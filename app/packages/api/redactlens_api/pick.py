"""Native Windows file/folder picker for the setup screen's "Browse" buttons.

This is deliberately in the API layer, not redactlens-core: opening a desktop
dialog is UI orchestration, and the core stays free of any UI concern. A
browser ``<input type="file">`` can't help here -- browsers hide the real
absolute path (``C:\\fakepath\\...``), but the scanner needs the true path on
disk, so we ask Windows directly via a local subprocess (see ``_pick_dialog``).
"""

import os
import subprocess
import sys
import tempfile
from pathlib import Path

from ._pick_dialog import PICKER_RESULT_PREFIX, PICKER_RESULT_SUFFIX

PICKER_CHILD_FLAG = "--redactlens-picker"


class PickerUnavailable(RuntimeError):
    """The native Windows picker couldn't be shown."""


def pick_path(kind: str = "folder", timeout: float = 300.0) -> str:
    """Open a native picker and return the chosen absolute path.

    Returns an empty string if the user cancels (or takes longer than
    ``timeout``). Raises :class:`PickerUnavailable` if no dialog could be
    shown at all, so the caller can fall back to manual path entry.
    """
    if sys.platform != "win32":
        raise PickerUnavailable("the native picker is only supported on Microsoft Windows")

    if kind not in ("folder", "file"):
        kind = "folder"

    descriptor, result_name = tempfile.mkstemp(
        prefix=PICKER_RESULT_PREFIX,
        suffix=PICKER_RESULT_SUFFIX,
    )
    os.close(descriptor)
    result_path = Path(result_name)
    child_command = (
        [sys.executable, PICKER_CHILD_FLAG, kind, str(result_path), str(timeout)]
        if getattr(sys, "frozen", False)
        else [
            sys.executable,
            "-m",
            "redactlens_api._pick_dialog",
            kind,
            str(result_path),
            str(timeout),
        ]
    )
    child_environment = os.environ.copy()
    if getattr(sys, "frozen", False):
        # The bundled executable normally opens the startup splash. Picker
        # helpers are intentionally invisible until the native dialog appears.
        child_environment["PYINSTALLER_SUPPRESS_SPLASH_SCREEN"] = "1"
    try:
        try:
            completed = subprocess.run(
                child_command,
                capture_output=True,
                text=True,
                timeout=timeout + 2.0,
                env=child_environment,
            )
        except subprocess.TimeoutExpired:
            return ""
        if completed.returncode != 0:
            detail = completed.stderr.strip() or "the native file picker isn't available here"
            raise PickerUnavailable(detail)
        try:
            return result_path.read_text(encoding="utf-8").strip()
        except OSError as error:
            raise PickerUnavailable("the native file picker did not return a result") from error
    finally:
        result_path.unlink(missing_ok=True)
