"""Shared helpers for turning a text offset into a Finding's identity/location.

Split out from scanner.py so both scanner.py and llm/description_targets.py
can use them without an import cycle.
"""

import hashlib


def stable_id(file_path: str, start_offset: int, detector_id: str) -> str:
    digest = hashlib.sha256(f"{file_path}:{start_offset}:{detector_id}".encode()).hexdigest()
    return digest[:16]


def line_col(text: str, offset: int) -> tuple[int, int]:
    line = text.count("\n", 0, offset) + 1
    last_newline = text.rfind("\n", 0, offset)
    column = offset - last_newline
    return line, column
