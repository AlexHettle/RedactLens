import shutil
import subprocess
from io import BytesIO
from pathlib import Path

from tooling.scripts import e2e_phase9

ROOT = Path(__file__).resolve().parents[1]
BROWSER_DRIVER = ROOT / "tooling" / "scripts" / "e2e_phase9_browser.mjs"
BROWSER_ERROR_TEST = ROOT / "tooling" / "scripts" / "e2e_phase9_browser_errors.test.mjs"


class _RunningBrowser:
    returncode = None

    def poll(self) -> None:
        return None


class _JsonResponse(BytesIO):
    def __enter__(self) -> "_JsonResponse":
        return self

    def __exit__(self, *args: object) -> None:
        self.close()


def test_browser_command_uses_an_explicit_loopback_devtools_port(tmp_path: Path) -> None:
    command = e2e_phase9._browser_command(
        Path(r"C:\Program Files\Browser\browser.exe"), tmp_path, 43123
    )

    assert "--remote-debugging-address=127.0.0.1" in command
    assert "--remote-debugging-port=43123" in command
    assert "--remote-debugging-port=0" not in command


def test_devtools_discovery_polls_the_explicit_port_without_a_profile_file(
    monkeypatch,
) -> None:
    requested: list[str] = []

    def fake_urlopen(url: str, *, timeout: float) -> _JsonResponse:
        requested.append(url)
        assert timeout == 1
        return _JsonResponse(
            b'[{"type":"page","webSocketDebuggerUrl":'
            b'"ws://localhost:43123/devtools/page/redactlens"}]'
        )

    monkeypatch.setattr(e2e_phase9, "urlopen", fake_urlopen)

    endpoint = e2e_phase9._wait_for_devtools(43123, _RunningBrowser())

    assert requested == ["http://127.0.0.1:43123/json/list"]
    assert endpoint == "ws://127.0.0.1:43123/devtools/page/redactlens"


def test_negative_open_probes_reach_route_authorization_without_exposing_token() -> None:
    source = BROWSER_DRIVER.read_text(encoding="utf-8")
    helper = source.split("async function assertRejectedOpen(", maxsplit=1)[1].split(
        "\n}\n\ntry {", maxsplit=1
    )[0]

    assert 'new URL("/launch-session", appUrl).href' in helper
    assert "'X-RedactLens-Token': token" in helper
    assert "status: response.status" in helper
    assert "text: await response.text()" in helper
    assert "console." not in helper
    assert "return { token" not in helper


def test_expected_denial_logs_are_filtered_without_hiding_other_browser_errors() -> None:
    node = shutil.which("node")
    assert node is not None, "Node.js is required by the live browser quality gate."

    completed = subprocess.run(
        [node, "--test", str(BROWSER_ERROR_TEST)],
        cwd=ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=30,
        check=False,
    )

    assert completed.returncode == 0, completed.stdout + completed.stderr

    source = BROWSER_DRIVER.read_text(encoding="utf-8")
    assert 'client.on("Runtime.exceptionThrown"' in source
    assert 'client.on("Runtime.consoleAPICalled"' in source
    assert '"Network.loadingFailed"' in source
