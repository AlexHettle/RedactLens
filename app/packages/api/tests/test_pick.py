import subprocess
from pathlib import Path
from types import SimpleNamespace

import redactlens_api._pick_dialog as dialog_module
import redactlens_api.pick as pick_module


def test_source_picker_uses_python_module_and_private_result_file(monkeypatch):
    command: list[str] = []
    result_path: Path | None = None

    def run(arguments, **_kwargs):
        nonlocal command, result_path
        command = arguments
        result_path = Path(arguments[-2])
        assert result_path.is_file()
        result_path.write_text("C:\\chosen\\folder", encoding="utf-8")
        return SimpleNamespace(returncode=0, stderr="")

    monkeypatch.delattr(pick_module.sys, "frozen", raising=False)
    monkeypatch.setattr(pick_module.sys, "platform", "win32")
    monkeypatch.setattr(pick_module.sys, "executable", "python.exe")
    monkeypatch.setattr(pick_module.subprocess, "run", run)

    assert pick_module.pick_path("folder") == "C:\\chosen\\folder"
    assert command[:4] == [
        "python.exe",
        "-m",
        "redactlens_api._pick_dialog",
        "folder",
    ]
    assert command[-1] == "300.0"
    assert result_path is not None and not result_path.exists()


def test_frozen_picker_uses_internal_child_dispatch_and_cleans_up_on_timeout(monkeypatch):
    command: list[str] = []
    environment: dict[str, str] = {}
    result_path: Path | None = None

    def run(arguments, **kwargs):
        nonlocal command, result_path
        command = arguments
        environment.update(kwargs["env"])
        result_path = Path(arguments[-2])
        raise subprocess.TimeoutExpired(arguments, 0.01)

    monkeypatch.setattr(pick_module.sys, "frozen", True, raising=False)
    monkeypatch.setattr(pick_module.sys, "platform", "win32")
    monkeypatch.setattr(pick_module.sys, "executable", "RedactLens.exe")
    monkeypatch.setattr(pick_module.subprocess, "run", run)

    assert pick_module.pick_path("file", timeout=0.01) == ""
    assert command[:3] == ["RedactLens.exe", pick_module.PICKER_CHILD_FLAG, "file"]
    assert environment["PYINSTALLER_SUPPRESS_SPLASH_SCREEN"] == "1"
    assert result_path is not None and not result_path.exists()


def test_picker_child_uses_sta_winforms_and_writes_selection_to_handoff_file(monkeypatch, tmp_path):
    result_path = tmp_path / "result.txt"
    result_path.touch()
    invocation: dict[str, object] = {}

    def run(arguments, **kwargs):
        invocation["arguments"] = arguments
        invocation["environment"] = kwargs["env"]
        Path(kwargs["env"]["REDACTLENS_PICKER_RESULT"]).write_text(
            "C:\\chosen\\folder", encoding="utf-8"
        )
        return SimpleNamespace(returncode=0, stderr="")

    monkeypatch.setattr(dialog_module.sys, "platform", "win32")
    monkeypatch.setattr(dialog_module, "_result_path", lambda _value: result_path)
    monkeypatch.setattr(dialog_module, "_powershell_executable", lambda: "powershell.exe")
    monkeypatch.setattr(dialog_module.subprocess, "run", run)

    assert dialog_module.main(["folder", "private-handoff", "12"]) == 0
    assert result_path.read_text(encoding="utf-8") == "C:\\chosen\\folder"
    assert "-STA" in invocation["arguments"]
    assert "-EncodedCommand" in invocation["arguments"]
    assert invocation["environment"]["REDACTLENS_PICKER_KIND"] == "folder"


def test_folder_picker_uses_modern_explorer_dialog_in_folder_only_mode():
    script = dialog_module._POWERSHELL_PICKER

    assert "FileOpenDialog" in script
    assert "FileOpenOptions.PickFolders" in script
    assert "[RedactLens.NativeFolderPicker]::Show" in script
    assert "FolderBrowserDialog" not in script


def test_picker_probe_loads_native_runtime_without_result_file(monkeypatch):
    environment: dict[str, str] = {}

    def run(_arguments, **kwargs):
        environment.update(kwargs["env"])
        return SimpleNamespace(returncode=0, stderr="")

    monkeypatch.setattr(dialog_module.sys, "platform", "win32")
    monkeypatch.setattr(dialog_module, "_powershell_executable", lambda: "powershell.exe")
    monkeypatch.setattr(dialog_module.subprocess, "run", run)

    assert dialog_module.main(["probe"]) == 0
    assert environment["REDACTLENS_PICKER_KIND"] == "probe"
    assert "REDACTLENS_PICKER_RESULT" not in environment
