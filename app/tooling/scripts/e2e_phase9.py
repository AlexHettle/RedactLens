"""Run Phase 9's production Windows UI against a live API and temporary filesystem.

No browser automation package is required. The runner launches an installed
Chromium browser (Edge or Chrome) in headless mode and drives it through the
browser's stable DevTools protocol with a dependency-free Node transport.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from urllib.error import URLError
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parents[2]
API_PORTS = range(8000, 8011)
STARTUP_TIMEOUT_SECONDS = 20.0
PROCESS_TIMEOUT_SECONDS = 120.0


def _creation_flags() -> int:
    return subprocess.CREATE_NO_WINDOW


def _browser_candidates() -> list[Path]:
    configured = os.environ.get("REDACTLENS_E2E_BROWSER", "").strip()
    if configured:
        configured_path = Path(shutil.which(configured) or configured).expanduser()
        if not configured_path.is_file():
            raise RuntimeError(
                f"REDACTLENS_E2E_BROWSER does not identify an executable file: {configured_path}"
            )
        return [configured_path]

    candidates: list[str | None] = []
    for executable in ("msedge", "chrome"):
        candidates.append(shutil.which(executable))

    program_files = os.environ.get("PROGRAMFILES")
    program_files_x86 = os.environ.get("PROGRAMFILES(X86)")
    for base in (program_files, program_files_x86):
        if base:
            candidates.extend(
                [
                    str(Path(base) / "Microsoft" / "Edge" / "Application" / "msedge.exe"),
                    str(Path(base) / "Google" / "Chrome" / "Application" / "chrome.exe"),
                ]
            )

    found: list[Path] = []
    identities: set[str] = set()
    for candidate in candidates:
        if not candidate:
            continue
        path = Path(candidate).expanduser()
        identity = os.path.normcase(str(path.resolve()))
        if path.is_file() and identity not in identities:
            found.append(path)
            identities.add(identity)
    return found


def _free_api_port() -> int:
    for port in API_PORTS:
        with socket.socket() as probe:
            try:
                probe.bind(("127.0.0.1", port))
            except OSError:
                continue
        return port
    raise RuntimeError("No free RedactLens API port is available between 8000 and 8010.")


def _wait_for_server(port: int, process: subprocess.Popen[bytes]) -> None:
    deadline = time.monotonic() + STARTUP_TIMEOUT_SECONDS
    url = f"http://127.0.0.1:{port}/detectors"
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(
                f"The live API exited during startup with code {process.returncode}."
            )
        try:
            with urlopen(url, timeout=0.5) as response:
                if response.status == 200 and b"risk_lesson" in response.read():
                    return
        except (OSError, URLError):
            time.sleep(0.1)
    raise RuntimeError("Timed out waiting for the live FastAPI server.")


def _wait_for_devtools(profile: Path, process: subprocess.Popen[bytes]) -> str:
    active_port = profile / "DevToolsActivePort"
    deadline = time.monotonic() + STARTUP_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"The browser exited during startup with code {process.returncode}.")
        try:
            lines = active_port.read_text(encoding="utf-8").splitlines()
        except OSError:
            lines = []
        if len(lines) >= 2 and lines[0].isdigit() and lines[1].startswith("/devtools/browser/"):
            browser_port = int(lines[0])
            try:
                with urlopen(f"http://127.0.0.1:{browser_port}/json/list", timeout=1) as response:
                    targets = json.load(response)
            except (OSError, URLError, json.JSONDecodeError):
                time.sleep(0.1)
                continue
            page = next((target for target in targets if target.get("type") == "page"), None)
            if page and page.get("webSocketDebuggerUrl"):
                return str(page["webSocketDebuggerUrl"]).replace(
                    "ws://localhost:", "ws://127.0.0.1:"
                )
        time.sleep(0.1)
    raise RuntimeError("Timed out waiting for the browser DevTools endpoint.")


def _terminate(process: subprocess.Popen[bytes] | None) -> None:
    if process is None or process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def _browser_command(browser: Path, profile: Path) -> list[str]:
    return [
        str(browser),
        "--headless=new",
        "--disable-background-networking",
        "--disable-breakpad",
        "--disable-component-update",
        "--disable-crash-reporter",
        "--disable-default-apps",
        "--disable-dev-shm-usage",
        "--disable-features=msEdgeFirstRunExperience",
        "--disable-gpu",
        "--disable-sync",
        "--metrics-recording-only",
        "--no-default-browser-check",
        "--no-first-run",
        # The verification browser opens only this test's loopback server and
        # disposable profile. Disabling the browser sandbox avoids Windows
        # application-container failures in locked-down CI/service accounts.
        "--no-sandbox",
        "--remote-allow-origins=*",
        "--remote-debugging-port=0",
        f"--user-data-dir={profile}",
        "about:blank",
    ]


def _log_tail(path: Path, limit: int = 1200) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")[-limit:].strip()
    except OSError:
        return ""


def _launch_browser(
    browsers: list[Path], workspace: Path, *, explicit: bool
) -> tuple[subprocess.Popen[bytes], str, Path]:
    failures: list[str] = []
    for index, candidate in enumerate(browsers, start=1):
        profile = workspace / f"browser-profile-{index}"
        browser_log = workspace / f"browser-{index}.log"
        profile.mkdir()
        process: subprocess.Popen[bytes] | None = None
        try:
            with browser_log.open("wb") as log:
                process = subprocess.Popen(
                    _browser_command(candidate, profile),
                    cwd=ROOT,
                    stdout=log,
                    stderr=subprocess.STDOUT,
                    creationflags=_creation_flags(),
                )
            web_socket_url = _wait_for_devtools(profile, process)
            if failures:
                print(
                    "Live browser startup fallback succeeded after: " + " | ".join(failures),
                    file=sys.stderr,
                )
            return process, web_socket_url, candidate
        except Exception as error:
            _terminate(process)
            detail = f"{candidate}: {error}"
            output = _log_tail(browser_log)
            if output:
                detail += f"; browser output: {output}"
            failures.append(detail)
            if explicit:
                raise RuntimeError(
                    "The browser configured by REDACTLENS_E2E_BROWSER failed to start: " + detail
                ) from error

    attempts = "\n".join(f"  - {failure}" for failure in failures)
    raise RuntimeError(
        "No auto-discovered Chromium browser could start with DevTools enabled. Attempts:\n"
        + attempts
    )


def _tree_digest(root: Path) -> str:
    digest = hashlib.sha256()
    for file_path in sorted(path for path in root.rglob("*") if path.is_file()):
        digest.update(file_path.relative_to(root).as_posix().encode("utf-8"))
        digest.update(b"\0")
        digest.update(file_path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def _verify_open_log(open_log: Path, target: Path) -> None:
    try:
        entries = [line for line in open_log.read_text(encoding="utf-8").splitlines() if line]
    except OSError as error:
        raise RuntimeError(
            "The live workflow did not record its native reveal boundaries."
        ) from error

    if len(entries) != 2:
        raise RuntimeError(
            "The live workflow must reveal exactly one source and one redacted output; "
            f"recorded {len(entries)} paths."
        )

    target_root = target.resolve(strict=True)
    # The test server strictly resolves each path and proves it exists inside
    # target_root at reveal time before writing the log. Compare those recorded
    # identities without adding a second, later existence requirement.
    opened = [Path(item).resolve(strict=False) for item in entries]
    if any(not item.is_relative_to(target_root) for item in opened):
        raise RuntimeError("The live workflow attempted to reveal a file outside its target.")

    expected = [
        (target / "config.py").resolve(strict=False),
        (target / "config-auto-redacted-copy.py").resolve(strict=False),
    ]
    if opened != expected:
        relative = [item.relative_to(target_root).as_posix() for item in opened]
        raise RuntimeError(
            "The live workflow revealed unexpected session paths; expected "
            "config.py followed by config-auto-redacted-copy.py, received "
            f"{relative}."
        )


def _run() -> int:
    if sys.platform != "win32":
        raise RuntimeError("The live browser workflow supports Microsoft Windows only.")

    if not (ROOT / "packages" / "frontend" / "dist" / "index.html").is_file():
        raise RuntimeError("The production frontend is missing. Run `npm run build` first.")
    node = shutil.which("node")
    if node is None:
        raise RuntimeError("Node.js is required for the dependency-free DevTools client.")
    explicit_browser = bool(os.environ.get("REDACTLENS_E2E_BROWSER", "").strip())
    browsers = _browser_candidates()
    if not browsers:
        raise RuntimeError(
            "No Chromium browser was found. Install Edge/Chrome/Chromium or set "
            "REDACTLENS_E2E_BROWSER to its executable."
        )

    original_demo_digest = _tree_digest(ROOT / "examples" / "demo")
    server: subprocess.Popen[bytes] | None = None
    browser: subprocess.Popen[bytes] | None = None
    server_log_text = ""

    with tempfile.TemporaryDirectory(
        prefix="redactlens-phase9-e2e-", ignore_cleanup_errors=True
    ) as temporary:
        workspace = Path(temporary)
        target = workspace / "target"
        downloads = workspace / "downloads"
        open_log = workspace / "opened-files.txt"
        server_log = workspace / "server.log"
        shutil.copytree(ROOT / "examples" / "demo", target)
        downloads.mkdir()

        port = _free_api_port()
        environment = os.environ.copy()
        environment.update(
            {
                "REDACTLENS_E2E_TARGET_ROOT": str(target),
                "REDACTLENS_E2E_OPEN_LOG": str(open_log),
                "REDACTLENS_IDLE_EXIT_MINUTES": "0",
            }
        )

        try:
            with server_log.open("wb") as log:
                server = subprocess.Popen(
                    [
                        sys.executable,
                        "-m",
                        "uvicorn",
                        "tooling.scripts.e2e_phase9_server:app",
                        "--host",
                        "127.0.0.1",
                        "--port",
                        str(port),
                        "--log-level",
                        "warning",
                        "--no-access-log",
                    ],
                    cwd=ROOT,
                    env=environment,
                    stdout=log,
                    stderr=subprocess.STDOUT,
                    creationflags=_creation_flags(),
                )
            _wait_for_server(port, server)

            browser, web_socket_url, selected_browser = _launch_browser(
                browsers,
                workspace,
                explicit=explicit_browser,
            )
            print(f"Live browser E2E using {selected_browser}.")

            completed = subprocess.run(
                [
                    node,
                    str(ROOT / "tooling" / "scripts" / "e2e_phase9_browser.mjs"),
                    web_socket_url,
                    f"http://127.0.0.1:{port}/",
                    str(target),
                    str(downloads),
                ],
                cwd=ROOT,
                check=False,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=PROCESS_TIMEOUT_SECONDS,
                creationflags=_creation_flags(),
            )
            if completed.stdout:
                print(completed.stdout.rstrip())
            if completed.returncode != 0:
                if completed.stderr:
                    print(completed.stderr.rstrip(), file=sys.stderr)
                return completed.returncode

            _verify_open_log(open_log, target)
            return 0
        finally:
            _terminate(browser)
            _terminate(server)
            try:
                server_log_text = server_log.read_text(encoding="utf-8", errors="replace")
            except OSError:
                pass
            if server is not None and server.returncode not in {None, 0, -15, 1}:
                print(server_log_text[-2000:], file=sys.stderr)
            if _tree_digest(ROOT / "examples" / "demo") != original_demo_digest:
                raise RuntimeError("The E2E workflow modified the committed demo fixture.")


def main() -> int:
    try:
        return _run()
    except subprocess.TimeoutExpired:
        print("The live browser workflow exceeded its 120-second budget.", file=sys.stderr)
        return 1
    except Exception as error:
        print(f"Live browser E2E failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
