from __future__ import annotations

import json
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WINDOWS_CLASSIFIER = "Operating System :: Microsoft :: Windows"


def test_distribution_manifests_declare_windows_only() -> None:
    frontend_manifest = json.loads(
        (ROOT / "packages" / "frontend" / "package.json").read_text(encoding="utf-8")
    )
    frontend_lock = json.loads(
        (ROOT / "packages" / "frontend" / "package-lock.json").read_text(encoding="utf-8")
    )

    assert frontend_manifest["os"] == ["win32"]
    assert frontend_lock["packages"][""]["os"] == ["win32"]

    for relative_path in (
        "packages/redactlens-core/pyproject.toml",
        "packages/api/pyproject.toml",
        "packages/cli/pyproject.toml",
        "tooling/eval/pyproject.toml",
    ):
        metadata = tomllib.loads((ROOT / relative_path).read_text(encoding="utf-8"))["project"]
        assert metadata["classifiers"] == [WINDOWS_CLASSIFIER]

    assert not any(ROOT.glob("*.app"))
