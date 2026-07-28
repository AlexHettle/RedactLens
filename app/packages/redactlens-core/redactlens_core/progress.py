"""Observable and cooperatively cancellable scan execution primitives."""

from __future__ import annotations

import time
from collections.abc import Callable
from contextlib import AbstractContextManager, nullcontext
from dataclasses import dataclass, field
from typing import Literal, TypeVar

from pydantic import BaseModel

from redactlens_core.models import Finding, ScanResult, SkippedFile

_AdmittedValue = TypeVar("_AdmittedValue")

ScanEventType = Literal[
    "scan_started",
    "discovery_complete",
    "file_started",
    "file_completed",
    "finding_added",
    "finding_updated",
    "file_skipped",
    "ai_refinement_started",
    "scan_finalizing",
    "scan_completed",
    "scan_cancelled",
    "scan_failed",
]
ScanStage = Literal[
    "pending",
    "discovery",
    "extraction",
    "detection",
    "consolidation",
    "ai_refinement",
    "finalizing",
    "complete",
    "cancelled",
    "failed",
    "timed_out",
]


class ScanEvent(BaseModel):
    """Internal event; API consumers must project ``finding`` before transport."""

    type: ScanEventType
    stage: ScanStage
    file_path: str | None = None
    completed_files: int = 0
    total_files: int | None = None
    findings_so_far: int = 0
    skipped_files: int = 0
    finding: Finding | None = None
    skipped_file: SkippedFile | None = None
    message: str | None = None


class ScanInterrupted(Exception):
    """Base class carrying the safe partial result accumulated so far."""

    def __init__(self, message: str, partial_result: ScanResult) -> None:
        super().__init__(message)
        self.partial_result = partial_result


class ScanCancelled(ScanInterrupted):
    pass


class ScanTimedOut(ScanInterrupted):
    pass


class _CancellationRequested(Exception):
    pass


class _DeadlineExceeded(Exception):
    pass


@dataclass
class ScanExecution:
    """Optional controls for an observable scan; defaults preserve sync callers."""

    event_sink: Callable[[ScanEvent], None] | None = None
    cancel_requested: Callable[[], bool] | None = None
    job_timeout_seconds: float | None = None
    extraction_timeout_seconds: float | None = None
    clock: Callable[[], float] = time.monotonic
    submission_guard: Callable[[], AbstractContextManager[object]] | None = field(
        default=None,
        repr=False,
    )
    _started_at: float | None = field(default=None, init=False, repr=False)

    def start(self) -> None:
        self._started_at = self.clock()

    def checkpoint(self) -> None:
        if self.cancel_requested is not None and self.cancel_requested():
            raise _CancellationRequested
        if (
            self.job_timeout_seconds is not None
            and self._started_at is not None
            and self.clock() - self._started_at >= self.job_timeout_seconds
        ):
            raise _DeadlineExceeded

    def emit(self, event: ScanEvent) -> None:
        if self.event_sink is not None:
            self.event_sink(event)

    def admit(self, action: Callable[[], _AdmittedValue]) -> _AdmittedValue:
        """Linearize one submission with a host's cancellation acceptance lock."""

        guard = self.submission_guard() if self.submission_guard is not None else nullcontext()
        with guard:
            self.checkpoint()
            return action()

    def extraction_timed_out(self, started_at: float) -> bool:
        return (
            self.extraction_timeout_seconds is not None
            and self.clock() - started_at >= self.extraction_timeout_seconds
        )
