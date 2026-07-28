"""Stable workflow errors shared by API session modules."""

from __future__ import annotations

from typing import Literal

ErrorCode = Literal[
    "scan_expired",
    "finding_not_found",
    "finding_not_anonymizable",
    "file_changed",
    "output_conflict",
    "file_unavailable",
    "session_capacity",
    "invalid_remediation_plan",
    "no_findings_selected",
    "verification_failed",
    "scan_incomplete",
    "scan_failed",
    "picker_unavailable",
]


class SessionProblem(Exception):
    """Expected workflow failure rendered as a stable structured API error."""

    def __init__(self, code: ErrorCode, message: str, status_code: int) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code
