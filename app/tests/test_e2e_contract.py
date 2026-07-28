import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BROWSER_DRIVER = ROOT / "tooling" / "scripts" / "e2e_phase9_browser.mjs"
BROWSER_ERROR_TEST = ROOT / "tooling" / "scripts" / "e2e_phase9_browser_errors.test.mjs"


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
