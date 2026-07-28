"""Reveal a file in Windows Explorer for results-screen actions.

Like :mod:`.pick`, this is deliberately in the API layer, not redactlens-core:
desktop integration is UI orchestration.  Scanned content is never passed to
its associated application: even an executable or active-content document is
only selected in Explorer.
"""

import subprocess
import sys
from pathlib import Path


def open_file(path: str) -> None:
    """Reveal *path* without launching or rendering the file itself.

    Raises :class:`FileNotFoundError` when the path isn't an existing file,
    or :class:`OSError` when the file manager could not be started.

    The historic name is retained because the local API route is already
    versioned around ``open-file``.  Its behavior is intentionally narrower.
    """
    file = Path(path)
    if not file.is_file():
        raise FileNotFoundError(f"not a file: {path}")

    if sys.platform != "win32":
        raise OSError("file reveal is only supported on Microsoft Windows")

    # Explorer parses this switch from the raw Windows command line rather
    # than with the usual argv rules. Keeping the comma outside the quoted
    # path is important: quoting the combined "/select,<path>" argument can
    # make Explorer ignore /select when the path contains spaces and open a
    # parent folder instead. shell=False keeps filename metacharacters inert.
    subprocess.Popen(f'explorer.exe /select,"{file}"', shell=False)
