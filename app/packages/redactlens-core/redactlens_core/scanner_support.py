"""Internal state and adapters used by the scan coordinator."""

from __future__ import annotations

import re
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Literal

from redactlens_core.consolidation import ConsolidationResult, ScoredDetection
from redactlens_core.files import FileIssue
from redactlens_core.llm.adapter import OllamaAdapter
from redactlens_core.llm.description_targets import MAX_DESCRIPTION_LINE_CHARS, MAX_LINES_PER_FILE
from redactlens_core.methods import MatchCandidate
from redactlens_core.models import RawDetectorOpinion
from redactlens_core.progress import ScanExecution
from redactlens_core.registry import DetectorDef

_NON_WHITESPACE = re.compile(r"\S")
_DetectionOrigin = Literal["built_in", "user_target"]


@dataclass(frozen=True)
class _ConfiguredDetector:
    detector: DetectorDef
    origin: _DetectionOrigin
    category_selected: bool
    required: bool


class _FileDetectionLimitExceeded(RuntimeError):
    """One file exceeded the shared candidate budget across all detectors."""

    code = "detection_limit"
    reason = "file produced too many candidate detections"


@dataclass
class _CandidateBudget:
    limit: int
    consumed: int = 0

    @property
    def remaining(self) -> int:
        return max(0, self.limit - self.consumed)

    def consume(self) -> None:
        if self.consumed >= self.limit:
            raise _FileDetectionLimitExceeded
        self.consumed += 1


@dataclass(frozen=True)
class _DetectionWork:
    detector: DetectorDef
    candidate: MatchCandidate
    origin: _DetectionOrigin
    category_selected: bool
    required: bool


@dataclass(frozen=True)
class _PreparedDetection:
    detection: ScoredDetection
    prompt: str | None = None


@dataclass(frozen=True)
class _PreparedDescriptionLine:
    text: str
    start_offset: int
    line: int
    location: str | None = None


@dataclass
class _RefinementPlan:
    file_path: str
    detections: list[_PreparedDetection]
    description_lines: list[_PreparedDescriptionLine]
    can_anonymize: bool

    def clear(self) -> None:
        self.file_path = ""
        self.detections.clear()
        self.description_lines.clear()


@dataclass(frozen=True)
class _FileOutcome:
    path: str
    heuristic: ConsolidationResult | None = None
    refinement: _RefinementPlan | None = None
    issue: FileIssue | None = None
    bytes_scanned: int = 0
    extraction_seconds: float = 0.0
    detection_seconds: float = 0.0
    raw_detector_hits_by_detector: tuple[tuple[str, int], ...] = ()
    raw_detector_opinions: tuple[RawDetectorOpinion, ...] | None = None

    def clear_sensitive(self) -> None:
        if self.heuristic is not None:
            self.heuristic.findings.clear()
        if self.refinement is not None:
            self.refinement.clear()
        object.__setattr__(self, "heuristic", None)
        object.__setattr__(self, "refinement", None)
        object.__setattr__(self, "raw_detector_opinions", None)


@dataclass(frozen=True)
class _RefinementOutcome:
    result: ConsolidationResult
    detection_seconds: float
    raw_detector_hits_by_detector: tuple[tuple[str, int], ...]
    raw_detector_opinions: tuple[RawDetectorOpinion, ...] | None

    def clear_sensitive(self) -> None:
        self.result.findings.clear()
        object.__setattr__(self, "raw_detector_opinions", None)


@dataclass(frozen=True)
class _DetectionProjection:
    result: ConsolidationResult
    retained_detections: list[ScoredDetection]
    raw_detector_hits_by_detector: tuple[tuple[str, int], ...]


def _release_detection_projection(
    projection: _DetectionProjection | None,
    *,
    clear_findings: bool,
) -> None:
    """Drop raw detector opinions retained by an intermediate projection."""

    if projection is None:
        return
    projection.retained_detections.clear()
    if clear_findings:
        projection.result.findings.clear()


def _clear_exception_tracebacks(error: BaseException) -> None:
    """Release exited frames retained by an abandoned future or interruption."""

    pending: list[BaseException] = [error]
    seen: set[int] = set()
    while pending:
        current = pending.pop()
        if id(current) in seen:
            continue
        seen.add(id(current))
        if current.__cause__ is not None:
            pending.append(current.__cause__)
        if current.__context__ is not None:
            pending.append(current.__context__)
        if isinstance(current, BaseExceptionGroup):
            pending.extend(current.exceptions)

        traceback = current.__traceback__
        current.__traceback__ = None
        while traceback is not None:
            try:
                traceback.tb_frame.clear()
            except RuntimeError:
                # The coordinating scan frame is still executing while it
                # translates a private interruption into its public error.
                pass
            traceback = traceback.tb_next


class _StreamingExtractionTimedOut(Exception):
    """The cumulative streaming I/O/decoding budget was exhausted."""


@dataclass
class _ScanMetrics:
    bytes_scanned: int = 0
    extraction_seconds: float = 0.0
    detection_seconds: float = 0.0


_PROCESS_MODEL_CALL_GATE = threading.Lock()


class _TimedSerialAdapter:
    """Serialize process-wide model calls and record time inside the model boundary."""

    def __init__(self, delegate: OllamaAdapter, control: ScanExecution | None = None) -> None:
        self._delegate = delegate
        self._control = control or ScanExecution()
        # A scan owns its metrics, but every scan in this process shares one
        # local Ollama execution slot. The API can retain several concurrent
        # sessions, so an instance-local lock would still overload one model.
        self._lock = _PROCESS_MODEL_CALL_GATE
        self.elapsed_seconds = 0.0
        self.attempts = 0
        self.successes = 0
        self.failures = 0

    def judge(self, question: str):
        while True:
            self._control.checkpoint()
            if self._lock.acquire(timeout=0.05):
                break
        try:
            # A caller can spend meaningful time queued behind another model
            # request. Recheck after acquiring the lock so cancellation or a
            # deadline never permits one more request to begin.
            self._control.checkpoint()
            started = time.perf_counter()
            self.attempts += 1
            try:
                verdict = self._delegate.judge(question)
            except Exception:
                self.failures += 1
                raise
            else:
                if verdict is None:
                    self.failures += 1
                else:
                    self.successes += 1
                return verdict
            finally:
                self.elapsed_seconds += time.perf_counter() - started
        finally:
            self._lock.release()


class _PromptCaptureAdapter:
    """Capture the exact gray-zone prompt without making a model request."""

    def __init__(self) -> None:
        self.prompt: str | None = None

    def judge(self, question: str):
        self.prompt = question
        return None


class _DescriptionLineAccumulator:
    """Collect bounded physical lines without starting model refinement."""

    def __init__(
        self,
        control: ScanExecution,
        location_at: Callable[[int], str | None] | None = None,
    ) -> None:
        self._control = control
        self._location_at = location_at
        self._parts: list[str] = []
        self._line_length = 0
        self._line_has_content = False
        self._line_overflowed = False
        self._global_offset = 0
        self._line_start_offset = 0
        self._line_number = 1
        self._checked_lines = 0
        self._done = False

    def feed(self, text: str) -> list[_PreparedDescriptionLine]:
        """Consume the next disjoint core and return bounded completed lines."""
        if self._done or not text:
            return []
        lines: list[_PreparedDescriptionLine] = []
        cursor = 0
        while cursor < len(text) and not self._done:
            self._control.checkpoint()
            newline = text.find("\n", cursor)
            segment_end = len(text) if newline < 0 else newline
            self._append_segment(text, cursor, segment_end)
            self._global_offset += segment_end - cursor
            if newline < 0:
                break
            lines.extend(self._finish_line())
            self._global_offset += 1
            self._line_start_offset = self._global_offset
            self._line_number += 1
            cursor = newline + 1
        return lines

    def finish(self) -> list[_PreparedDescriptionLine]:
        """Flush one final unterminated physical line at EOF."""
        if self._done or self._line_length == 0:
            return []
        return self._finish_line()

    def clear(self) -> None:
        self._parts.clear()
        self._location_at = None

    def _append_segment(self, text: str, start: int, end: int) -> None:
        if start == end:
            return
        if not self._line_has_content and _NON_WHITESPACE.search(text, start, end):
            self._line_has_content = True
        self._line_length += end - start
        if self._line_length > MAX_DESCRIPTION_LINE_CHARS:
            self._line_overflowed = True
            self._parts.clear()
        elif not self._line_overflowed:
            self._parts.append(text[start:end])

    def _finish_line(self) -> list[_PreparedDescriptionLine]:
        lines: list[_PreparedDescriptionLine] = []
        if self._line_has_content:
            self._checked_lines += 1
            if not self._line_overflowed:
                line_text = "".join(self._parts)
                first_content = _NON_WHITESPACE.search(line_text)
                content_offset = first_content.start() if first_content is not None else 0
                global_content_offset = self._line_start_offset + content_offset
                lines.append(
                    _PreparedDescriptionLine(
                        text=line_text,
                        start_offset=self._line_start_offset,
                        line=self._line_number,
                        location=(
                            self._location_at(global_content_offset)
                            if self._location_at is not None
                            else None
                        ),
                    )
                )
            if self._checked_lines >= MAX_LINES_PER_FILE:
                self._done = True
        self._parts.clear()
        self._line_length = 0
        self._line_has_content = False
        self._line_overflowed = False
        return lines
