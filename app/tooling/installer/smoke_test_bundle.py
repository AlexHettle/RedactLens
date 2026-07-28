"""Start a bundled RedactLens executable and probe its local UI/API."""

from __future__ import annotations

import argparse
import json
import os
import socket
import subprocess
import sys
import time
from pathlib import Path
from urllib.request import urlopen

PORTS = range(8000, 8011)
PICKER_CHILD_FLAG = "--redactlens-picker"


def _listening(port: int) -> bool:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=0.1):
            return True
    except OSError:
        return False


def _probe(port: int) -> bool:
    try:
        with urlopen(f"http://127.0.0.1:{port}/detectors", timeout=1) as response:
            detectors = json.load(response)
        with urlopen(f"http://127.0.0.1:{port}/", timeout=1) as response:
            index = response.read().decode("utf-8", errors="replace")
    except (OSError, ValueError):
        return False
    return (
        isinstance(detectors, list)
        and len(detectors) >= 3
        and all(isinstance(item, dict) and "risk_lesson" in item for item in detectors)
        and 'id="root"' in index
    )


def _log_tail() -> str:
    local = os.environ.get("LOCALAPPDATA")
    if not local:
        return ""
    path = Path(local) / "RedactLens" / "redactlens-launcher.log"
    try:
        return path.read_text(encoding="utf-8", errors="replace")[-2_000:].strip()
    except OSError:
        return ""


def _probe_picker_runtime(executable: Path, environment: dict[str, str]) -> bool:
    """Prove the bundle can dispatch and load its native picker runtime."""

    try:
        completed = subprocess.run(
            [str(executable), PICKER_CHILD_FLAG, "probe"],
            cwd=executable.parent,
            env=environment,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=5,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return completed.returncode == 0


def smoke_test(executable: Path, timeout_seconds: float) -> int:
    if sys.platform != "win32":
        print("The packaged executable smoke test requires Windows.", file=sys.stderr)
        return 2
    executable = executable.resolve()
    if not executable.is_file():
        print(f"Bundled executable not found: {executable}", file=sys.stderr)
        return 2

    environment = os.environ.copy()
    environment.update(
        {
            "REDACTLENS_NO_BROWSER": "1",
            "REDACTLENS_IDLE_EXIT_MINUTES": "0",
            "PYINSTALLER_SUPPRESS_SPLASH_SCREEN": "1",
            "PYTHONUTF8": "1",
        }
    )
    process = subprocess.Popen(
        [str(executable)],
        cwd=executable.parent,
        env=environment,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        creationflags=subprocess.CREATE_NO_WINDOW,
    )
    deadline = time.monotonic() + timeout_seconds
    try:
        while time.monotonic() < deadline:
            if process.poll() is not None:
                detail = _log_tail()
                suffix = f"\nLauncher log:\n{detail}" if detail else ""
                message = (
                    "Bundled executable exited during startup with code "
                    f"{process.returncode}.{suffix}"
                )
                print(
                    message,
                    file=sys.stderr,
                )
                return 1
            for port in PORTS:
                if _listening(port) and _probe(port):
                    if not _probe_picker_runtime(executable, environment):
                        print(
                            "Bundled native picker runtime probe failed.",
                            file=sys.stderr,
                        )
                        return 1
                    print(f"Bundled UI/API smoke test passed on 127.0.0.1:{port}.")
                    return 0
            time.sleep(0.1)
        detail = _log_tail()
        suffix = f"\nLauncher log:\n{detail}" if detail else ""
        print(f"Timed out waiting for the bundled UI/API.{suffix}", file=sys.stderr)
        return 1
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=10)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("executable", type=Path)
    parser.add_argument("--timeout", type=float, default=45.0)
    args = parser.parse_args()
    return smoke_test(args.executable, args.timeout)


if __name__ == "__main__":
    raise SystemExit(main())
