"""Test-only live server adapter for the Phase 9 browser workflow.

The application and every HTTP route are the production FastAPI app. Only the
last native integration is replaced: revealing a source or redacted copy
records the verified path instead of starting a GUI program during an
unattended quality run.
"""

from __future__ import annotations

import os
from pathlib import Path

from redactlens_api import main as api_main


def _record_open(path: str | Path) -> None:
    target_root = Path(os.environ["REDACTLENS_E2E_TARGET_ROOT"]).resolve(strict=True)
    resolved = Path(path).resolve(strict=True)
    if not resolved.is_relative_to(target_root):
        raise OSError("The E2E workflow may only reveal files inside its temporary target.")

    log_path = Path(os.environ["REDACTLENS_E2E_OPEN_LOG"])
    with log_path.open("a", encoding="utf-8") as log:
        log.write(f"{resolved}\n")


api_main.open_file = _record_open
app = api_main.app
