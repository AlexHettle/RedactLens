"""Deterministic names for non-destructive remediation outputs."""

from __future__ import annotations

from pathlib import Path


def redacted_copy_path(file_path: str | Path) -> Path:
    """Place ``-auto-redacted-copy`` before the source's final extension."""

    path = Path(file_path)
    if path.suffix:
        return path.with_name(f"{path.stem}-auto-redacted-copy{path.suffix}")
    return path.with_name(f"{path.name}-auto-redacted-copy")
