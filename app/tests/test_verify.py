from __future__ import annotations

import subprocess
from pathlib import Path

from tooling import verify


def test_every_check_has_a_timeout_and_ruff_owns_python_formatting(monkeypatch) -> None:
    monkeypatch.setattr(verify, "_npm_executable", lambda: "npm")

    checks = verify._checks()

    assert all(check.timeout_seconds > 0 for check in checks)
    formatting = next(check for check in checks if check.name == "Python formatting (Ruff)")
    assert formatting.command[1:] == ["-m", "ruff", "format", "--check", "."]
    assert all("black" not in argument.lower() for check in checks for argument in check.command)


def test_timeout_is_reported_and_does_not_stop_later_checks(
    monkeypatch, tmp_path: Path, capsys
) -> None:
    (tmp_path / "packages" / "frontend" / "node_modules").mkdir(parents=True)
    checks = [
        verify.Check("Slow check", ["slow-command"], 7),
        verify.Check("Later check", ["later-command"], 11),
    ]
    calls: list[tuple[list[str], Path, bool, int]] = []

    def fake_run(
        command: list[str], *, cwd: Path, check: bool, timeout: int
    ) -> subprocess.CompletedProcess[str]:
        calls.append((command, cwd, check, timeout))
        if command == ["slow-command"]:
            raise subprocess.TimeoutExpired(command, timeout)
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(verify, "ROOT", tmp_path)
    monkeypatch.setattr(verify, "_checks", lambda: checks)
    monkeypatch.setattr(verify.subprocess, "run", fake_run)

    assert verify.main() == 1
    assert calls == [
        (["slow-command"], tmp_path, False, 7),
        (["later-command"], tmp_path, False, 11),
    ]
    output = capsys.readouterr().out
    assert "Check timed out after 7 seconds." in output
    assert "Slow check" in output and "TIMED OUT" in output
    assert "Later check" in output and "passed" in output


def test_start_failure_is_reported_and_does_not_stop_later_checks(
    monkeypatch, tmp_path: Path, capsys
) -> None:
    (tmp_path / "packages" / "frontend" / "node_modules").mkdir(parents=True)
    checks = [
        verify.Check("Missing check", ["missing-command"], 7),
        verify.Check("Later check", ["later-command"], 11),
    ]
    calls: list[list[str]] = []

    def fake_run(
        command: list[str], *, cwd: Path, check: bool, timeout: int
    ) -> subprocess.CompletedProcess[str]:
        calls.append(command)
        if command == ["missing-command"]:
            raise OSError("not found")
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(verify, "ROOT", tmp_path)
    monkeypatch.setattr(verify, "_checks", lambda: checks)
    monkeypatch.setattr(verify.subprocess, "run", fake_run)

    assert verify.main() == 1
    assert calls == [["missing-command"], ["later-command"]]
    output = capsys.readouterr().out
    assert "Could not start check: not found" in output
    assert "Missing check" in output and "FAILED TO START" in output
    assert "Later check" in output and "passed" in output
