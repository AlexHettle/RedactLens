"""Direct tests for the safe desktop reveal helper."""

from pathlib import Path

import pytest
from redactlens_api import open_file as open_file_module


@pytest.mark.parametrize("extension", [".bat", ".cmd", ".py", ".html", ".docm"])
def test_windows_reveals_active_content_in_explorer_without_launching(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    extension: str,
) -> None:
    target = tmp_path / f"untrusted & active{extension}"
    target.write_text("untrusted", encoding="utf-8")
    spawned: list[tuple[str, bool]] = []
    monkeypatch.setattr(open_file_module.sys, "platform", "win32")

    def capture(command: str, *, shell: bool) -> None:
        spawned.append((command, shell))

    monkeypatch.setattr(open_file_module.subprocess, "Popen", capture)

    open_file_module.open_file(str(target))

    assert spawned == [(f'explorer.exe /select,"{target}"', False)]


def test_non_windows_platform_is_rejected_without_starting_a_process(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    target = tmp_path / "active.html"
    target.write_text("<script>bad()</script>", encoding="utf-8")
    monkeypatch.setattr(open_file_module.sys, "platform", "unsupported")
    monkeypatch.setattr(open_file_module.subprocess, "Popen", pytest.fail)

    with pytest.raises(OSError, match="only supported on Microsoft Windows"):
        open_file_module.open_file(str(target))


def test_windows_propagates_explorer_start_failure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    target = tmp_path / "active.py"
    target.write_text("raise SystemExit", encoding="utf-8")
    monkeypatch.setattr(open_file_module.sys, "platform", "win32")

    def unavailable(_command: str, *, shell: bool) -> None:
        assert shell is False
        raise OSError("Explorer unavailable")

    monkeypatch.setattr(open_file_module.subprocess, "Popen", unavailable)

    with pytest.raises(OSError, match="Explorer unavailable"):
        open_file_module.open_file(str(target))


def test_missing_file_does_not_start_a_process(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    spawn = pytest.fail
    monkeypatch.setattr(open_file_module.subprocess, "Popen", spawn)

    with pytest.raises(FileNotFoundError):
        open_file_module.open_file(str(tmp_path / "missing.cmd"))
