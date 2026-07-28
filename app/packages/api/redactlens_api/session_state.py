"""In-memory scan-session state, privacy projection, and retention sizing."""

from __future__ import annotations

import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from redactlens_core.models import (
    DEFAULT_TIER_THRESHOLD,
    Finding,
    ScanOptions,
    ScanRequest,
    ScanResult,
)
from redactlens_core.progress import ScanEvent

from .contracts import (
    PublicFinding,
    PublicRedactor,
    PublicScanError,
    PublicScanEvent,
    PublicScanMetadata,
    PublicScanProgress,
    PublicScanResult,
    RemediationState,
    ScanState,
    _public_skipped_file,
)
from .session_errors import SessionProblem
from .session_files import (
    FileFingerprint,
    GeneratedOutput,
    _redacted_output_path_no_follow,
)

DEFAULT_MAX_EVENTS = 2_000


class EventReplayGap(Exception):
    """The requested SSE cursor predates the bounded retained event window."""


@dataclass(frozen=True)
class _TerminalUpdate:
    """One fully materialized terminal state, sized before it is published."""

    state: ScanState
    error: PublicScanError | None
    public_result: PublicScanResult
    progress: PublicScanProgress
    internal_findings: dict[str, Finding]
    file_fingerprints: dict[str, FileFingerprint]
    remediation_states: dict[str, RemediationState]
    generated_outputs: dict[str, GeneratedOutput]
    retained_remediation_artifacts: set[str]
    public_redactor: PublicRedactor
    event: PublicScanEvent


@dataclass
class ScanSession:
    scan_id: str
    created_at: datetime
    last_accessed_at: datetime
    created_clock: float
    last_accessed_clock: float
    idle_timeout_seconds: float
    selected_roots: tuple[str, ...]
    internal_findings: dict[str, Finding]
    public_result: PublicScanResult
    file_fingerprints: dict[str, FileFingerprint]
    scan_state: ScanState = "complete"
    progress: PublicScanProgress = field(
        default_factory=lambda: PublicScanProgress(stage="complete", percent=100.0)
    )
    request: ScanRequest | None = None
    error: PublicScanError | None = None
    duration_ms: int | None = None
    detector_count: int = 0
    ai_model: str | None = None
    rescan_categories: tuple[str, ...] = ()
    rescan_tier_threshold: float = DEFAULT_TIER_THRESHOLD
    rescan_options: ScanOptions = field(default_factory=ScanOptions)
    rescan_scope_requires_ai: bool = False
    remediation_states: dict[str, RemediationState] = field(default_factory=dict)
    remediation_revision: int = 0
    generated_outputs: dict[str, GeneratedOutput] = field(default_factory=dict)
    retained_remediation_artifacts: set[str] = field(default_factory=set)
    public_redactor: PublicRedactor = field(default_factory=PublicRedactor, repr=False)
    public_live_paths: dict[str, str] = field(default_factory=dict)
    events: list[PublicScanEvent] = field(default_factory=list)
    next_event_sequence: int = 1
    max_events: int = DEFAULT_MAX_EVENTS
    estimated_bytes: int = 0
    discarded: bool = False
    cancel_signal: threading.Event = field(default_factory=threading.Event, repr=False)
    worker_thread: threading.Thread | None = field(default=None, repr=False)
    active_retention_deadline_clock: float | None = field(default=None, repr=False)
    capacity_callback: Callable[[ScanSession], None] | None = field(default=None, repr=False)
    workflow_lock: threading.RLock = field(default_factory=threading.RLock, repr=False)
    event_condition: threading.Condition = field(init=False, repr=False)

    def __post_init__(self) -> None:
        self.event_condition = threading.Condition(self.workflow_lock)

    @property
    def expires_at(self) -> datetime:
        return self.last_accessed_at + timedelta(seconds=self.idle_timeout_seconds)

    def touch(self, now: float, wall_now: float | None = None) -> None:
        """Refresh access without allowing concurrent or wall-clock rollback."""

        self.last_accessed_clock = max(self.last_accessed_clock, now)
        accessed_at = datetime.fromtimestamp(wall_now if wall_now is not None else now, tz=UTC)
        self.last_accessed_at = max(self.last_accessed_at, accessed_at)

    def response(self) -> PublicScanResult:
        with self.workflow_lock:
            self._raise_if_discarded_locked()
            redactor = session_public_redactor(self)
            return self.public_result.redacted(redactor).model_copy(
                update={
                    "expires_at": self.expires_at,
                    "event_cursor": self.next_event_sequence - 1,
                    "state": self.scan_state,
                    "progress": self.progress.redacted(redactor),
                    "error": (self.error.redacted(redactor) if self.error is not None else None),
                    "metadata": public_metadata(self, redactor),
                },
                deep=True,
            )

    @property
    def terminal(self) -> bool:
        return self.discarded or self.scan_state in {
            "complete",
            "cancelled",
            "failed",
            "timed_out",
        }

    @property
    def active(self) -> bool:
        return not self.terminal

    def request_cancel(self) -> None:
        with self.workflow_lock:
            if not self.active:
                return
            self.scan_state = "cancelling"
            self.cancel_signal.set()

    def cancellation_requested(self) -> bool:
        return self.cancel_signal.is_set() or self.discarded

    def require_complete(self) -> None:
        with self.workflow_lock:
            self._raise_if_discarded_locked()
            if self.scan_state != "complete":
                raise SessionProblem(
                    "scan_incomplete",
                    "This scan is incomplete. Run it to completion before taking file actions.",
                    409,
                )

    def _raise_if_discarded_locked(self) -> None:
        if self.discarded:
            raise SessionProblem(
                "scan_expired",
                "This scan has expired. Run it again before taking further action.",
                410,
            )

    def apply_core_event(self, event: ScanEvent) -> None:
        if event.type in {"scan_completed", "scan_cancelled", "scan_failed"}:
            return
        with self.event_condition:
            if self.discarded:
                return
            previous_redactor = session_public_redactor(self)
            if event.finding is not None:
                register_public_live_path(self, event.finding.file_path)
            if event.file_path is not None:
                register_public_live_path(self, event.file_path)
            if event.skipped_file is not None:
                register_public_live_path(self, event.skipped_file.path)
            if event.type == "scan_started":
                self.scan_state = "discovering"
            elif event.type == "ai_refinement_started":
                self.scan_state = "refining"
            elif event.type in {
                "file_started",
                "file_completed",
                "finding_added",
                "finding_updated",
                "file_skipped",
                "scan_finalizing",
            }:
                self.scan_state = "scanning" if event.stage != "ai_refinement" else "refining"

            if event.finding is not None:
                self.internal_findings[event.finding.id] = event.finding
            redactor = session_public_redactor(self)
            if redactor != previous_redactor:
                # A newly discovered value can already exist in an earlier
                # file label, structured location, skip reason, or retained
                # SSE event. Reapply the now scan-wide boundary before any
                # later browser read or replay.
                self.public_result = self.public_result.redacted(redactor)
                self.progress = self.progress.redacted(redactor)
                self.events = [retained.redacted(redactor) for retained in self.events]

            if event.finding is not None:
                public = PublicFinding.from_internal(
                    event.finding,
                    redactor=redactor,
                    live=True,
                )
                public_findings = list(self.public_result.findings)
                for index, existing in enumerate(public_findings):
                    if existing.id == public.id:
                        public_findings[index] = public
                        break
                else:
                    public_findings.append(public)
                self.public_result = self.public_result.model_copy(
                    update={"findings": public_findings}
                )

            if event.type == "file_completed" and event.file_path is not None:
                scanned = list(self.public_result.scanned_files)
                public_path = redactor.live_path(event.file_path)
                if public_path not in scanned:
                    scanned.append(public_path)
                    self.public_result = self.public_result.model_copy(
                        update={"scanned_files": scanned}
                    )
            if event.skipped_file is not None:
                public_skipped = _public_skipped_file(event.skipped_file, redactor, live=True)
                skipped = list(self.public_result.skipped_files)
                if not any(item.path == public_skipped.path for item in skipped):
                    skipped.append(public_skipped)
                    self.public_result = self.public_result.model_copy(
                        update={"skipped_files": skipped}
                    )

            self.progress = public_progress(event, redactor, live=True)
            self._append_event_locked(
                event.type,
                finding=(
                    PublicFinding.from_internal(
                        event.finding,
                        redactor=redactor,
                        live=True,
                    )
                    if event.finding is not None
                    else None
                ),
                skipped_file=(
                    _public_skipped_file(event.skipped_file, redactor, live=True)
                    if event.skipped_file is not None
                    else None
                ),
            )

    def finish(
        self,
        result: ScanResult,
        *,
        state: ScanState,
        fingerprints: dict[str, FileFingerprint] | None = None,
        error: PublicScanError | None = None,
        public_partial: PublicScanResult | None = None,
    ) -> None:
        with self.event_condition:
            if self.discarded:
                return
            update = self._prepare_terminal_update_locked(
                result,
                state=state,
                fingerprints=fingerprints,
                error=error,
                public_partial=public_partial,
            )
            self._apply_terminal_update_locked(update)

    def _prepare_terminal_update_locked(
        self,
        result: ScanResult,
        *,
        state: ScanState,
        fingerprints: dict[str, FileFingerprint] | None = None,
        error: PublicScanError | None = None,
        public_partial: PublicScanResult | None = None,
    ) -> _TerminalUpdate:
        """Build the exact terminal snapshot and event without mutating the session."""

        result = normalize_terminal_result(result, state)
        redactor = PublicRedactor.from_findings(
            [*self.internal_findings.values(), *result.findings],
            reserved_paths=[
                *self.selected_roots,
                *(finding.file_path for finding in self.internal_findings.values()),
                *(finding.file_path for finding in result.findings),
                *(
                    str(_redacted_output_path_no_follow(path))
                    for path in dict.fromkeys(
                        finding.file_path
                        for finding in [*self.internal_findings.values(), *result.findings]
                        if state == "complete" and finding.can_anonymize
                    )
                ),
                *result.scanned_files,
                *(skipped.path for skipped in result.skipped_files),
                *(fingerprints or {}),
                *(fingerprint.resolved_path for fingerprint in (fingerprints or {}).values()),
                *self.generated_outputs,
                *(output.output_path for output in self.generated_outputs.values()),
                *self.retained_remediation_artifacts,
            ],
        )
        event_type = {
            "complete": "scan_completed",
            "cancelled": "scan_cancelled",
            "timed_out": "scan_failed",
            "failed": "scan_failed",
        }[state]
        stage = {
            "complete": "complete",
            "cancelled": "cancelled",
            "timed_out": "timed_out",
            "failed": "failed",
        }[state]

        if public_partial is None:
            public_result = PublicScanResult.from_internal(
                scan_id=self.scan_id,
                created_at=self.created_at,
                expires_at=self.expires_at,
                result=result,
                state=state,
                error=error,
                redactor=redactor,
            )
            completed = int(result.summary.get("completed_files", 0))
            total_value = result.summary.get("total_files")
            total = int(total_value) if total_value is not None else None
        else:
            # Core progress events have already crossed the privacy projection.
            # Keep that redacted public work if the scanner fails before it can
            # return a ScanResult; never reconstruct it from retained raw data.
            completed = self.progress.completed_files
            total = self.progress.total_files
            # A scanner may have returned successfully before a later API
            # bookkeeping step fails. In that case its aggregate summary and
            # LLM-use flag are authoritative, while event-projected findings
            # remain the privacy-safe source of partial finding details.
            summary = {**public_partial.summary, **result.summary}
            summary.update(
                {
                    "status": state,
                    "incomplete": state != "complete",
                    "completed_files": completed,
                    "total_files": total,
                }
            )
            public_result = public_partial.model_copy(
                update={
                    "summary": summary,
                    "llm_used": result.llm_used,
                },
                deep=True,
            ).redacted(redactor)

        progress = PublicScanProgress(
            stage=stage,
            completed_files=completed,
            total_files=total,
            percent=100.0 if state == "complete" else percent(completed, total),
            current_file=None,
            findings_so_far=len(public_result.findings),
            skipped_files=len(public_result.skipped_files),
        )
        actionable = state == "complete"
        active_fingerprints = dict(fingerprints or {}) if actionable else {}
        internal_findings = (
            {finding.id: finding for finding in result.findings} if actionable else {}
        )
        remediation_states = (
            {
                finding.id: "pending" if finding.can_anonymize else "read_only"
                for finding in result.findings
            }
            if actionable
            else {}
        )
        metadata = PublicScanMetadata(
            selected_roots=list(self.selected_roots),
            duration_ms=self.duration_ms,
            data_scanned_bytes=sum(
                fingerprint.size for fingerprint in active_fingerprints.values()
            ),
            detector_count=self.detector_count,
            ai_model=self.ai_model,
        ).redacted(redactor)
        public_error = error.redacted(redactor) if error is not None else None
        public_result = public_result.model_copy(
            update={
                "expires_at": self.expires_at,
                "event_cursor": self.next_event_sequence,
                "state": state,
                "progress": progress,
                "error": public_error,
                "metadata": metadata,
            },
            deep=True,
        )
        event = PublicScanEvent(
            sequence=self.next_event_sequence,
            type=event_type,
            emitted_at=datetime.now(UTC),
            scan_id=self.scan_id,
            state=state,
            progress=progress.model_copy(deep=True),
            error=public_error,
        )
        return _TerminalUpdate(
            state=state,
            error=public_error,
            public_result=public_result,
            progress=progress,
            internal_findings=internal_findings,
            file_fingerprints=active_fingerprints,
            remediation_states=remediation_states,
            generated_outputs=dict(self.generated_outputs) if actionable else {},
            retained_remediation_artifacts=(
                set(self.retained_remediation_artifacts) if actionable else set()
            ),
            public_redactor=redactor if actionable else PublicRedactor(),
            event=event,
        )

    def _apply_terminal_update_locked(self, update: _TerminalUpdate) -> None:
        """Commit a previously sized terminal snapshot while workflow_lock is held."""

        self.scan_state = update.state
        self.error = update.error
        self.internal_findings = update.internal_findings
        self.file_fingerprints = update.file_fingerprints
        self.remediation_states = update.remediation_states
        self.remediation_revision = 0
        self.generated_outputs = update.generated_outputs
        self.retained_remediation_artifacts = update.retained_remediation_artifacts
        self.public_redactor = update.public_redactor
        self.public_live_paths.clear()
        self.public_result = update.public_result
        self.progress = update.progress
        self.request = None
        self.next_event_sequence = update.event.sequence + 1
        self.events.append(update.event)
        if len(self.events) > self.max_events:
            del self.events[: len(self.events) - self.max_events]
        self.estimated_bytes = estimate_session_bytes(self)
        self.event_condition.notify_all()

    def wait_for_events(self, after: int, timeout: float) -> list[PublicScanEvent]:
        with self.event_condition:
            self._raise_for_replay_gap_locked(after)
            if not any(event.sequence > after for event in self.events) and not self.terminal:
                self.event_condition.wait(timeout)
            self._raise_for_replay_gap_locked(after)
            return [event.model_copy(deep=True) for event in self.events if event.sequence > after]

    def _raise_for_replay_gap_locked(self, after: int) -> None:
        if self.events and after < self.events[0].sequence - 1:
            raise EventReplayGap

    def refresh_retained_size(self) -> None:
        """Recount variable retained data and enforce the owning store's limit."""
        callback = self.capacity_callback
        if callback is not None:
            callback(self)
            return
        with self.workflow_lock:
            self.estimated_bytes = estimate_session_bytes(self)

    def _append_event_locked(
        self,
        event_type: str,
        *,
        finding: PublicFinding | None = None,
        skipped_file=None,
        error: PublicScanError | None = None,
    ) -> None:
        event = PublicScanEvent(
            sequence=self.next_event_sequence,
            type=event_type,
            emitted_at=datetime.now(UTC),
            scan_id=self.scan_id,
            state=self.scan_state,
            progress=self.progress.model_copy(deep=True),
            finding=finding,
            skipped_file=skipped_file,
            error=error,
        )
        self.next_event_sequence += 1
        self.events.append(event)
        if len(self.events) > self.max_events:
            del self.events[: len(self.events) - self.max_events]
        self.event_condition.notify_all()

    def finding(self, finding_id: str) -> Finding:
        with self.workflow_lock:
            self.require_complete()
            finding = self.internal_findings.get(finding_id)
            if finding is None:
                raise SessionProblem(
                    "finding_not_found",
                    "That finding does not belong to this scan.",
                    404,
                )
            return finding

    def findings(self, finding_ids: list[str]) -> list[Finding]:
        with self.workflow_lock:
            self.require_complete()
            # Deduplicate IDs without changing the user's selection order.
            return [self.finding(finding_id) for finding_id in dict.fromkeys(finding_ids)]

    def clear(self) -> None:
        """Release every server-side reference retained by this session."""
        with self.event_condition:
            self.discarded = True
            self.cancel_signal.set()
            self.request = None
            self.internal_findings.clear()
            self.file_fingerprints.clear()
            self.remediation_states.clear()
            self.remediation_revision = 0
            self.generated_outputs.clear()
            self.retained_remediation_artifacts.clear()
            self.public_redactor = PublicRedactor()
            self.public_live_paths.clear()
            self.events.clear()
            self.selected_roots = ()
            self.active_retention_deadline_clock = None
            self.capacity_callback = None
            self.error = None
            self.duration_ms = None
            self.detector_count = 0
            self.ai_model = None
            self.rescan_categories = ()
            self.rescan_tier_threshold = DEFAULT_TIER_THRESHOLD
            self.rescan_options = ScanOptions()
            self.rescan_scope_requires_ai = False
            self.progress = PublicScanProgress(stage="failed")
            self.public_result = self.public_result.model_copy(
                update={
                    "findings": [],
                    "summary": {},
                    "scanned_files": [],
                    "skipped_files": [],
                    "llm_used": False,
                    "progress": self.progress,
                    "error": None,
                    "metadata": PublicScanMetadata(),
                }
            )
            self.estimated_bytes = 0
            self.event_condition.notify_all()


def normalize_terminal_result(result: ScanResult, state: ScanState) -> ScanResult:
    """Make every non-actionable terminal snapshot explicit and consistent."""

    if state == "complete":
        return result
    summary = dict(result.summary)
    summary.update({"status": state, "incomplete": True})
    return result.model_copy(update={"summary": summary})


def session_public_redactor(session: ScanSession) -> PublicRedactor:
    reserved_paths = [
        *session.selected_roots,
        *(session.request.paths if session.request is not None else []),
        *(finding.file_path for finding in session.internal_findings.values()),
        *session.file_fingerprints,
        *(fingerprint.resolved_path for fingerprint in session.file_fingerprints.values()),
        *session.generated_outputs,
        *(output.output_path for output in session.generated_outputs.values()),
        *session.retained_remediation_artifacts,
    ]
    if session.public_redactor != PublicRedactor():
        session.public_redactor = session.public_redactor.with_reserved_paths(reserved_paths)
        return session.public_redactor.with_live_paths(session.public_live_paths)
    return PublicRedactor.from_findings(
        session.internal_findings.values(),
        reserved_paths=reserved_paths,
    ).with_live_paths(
        session.public_live_paths,
    )


def register_public_live_path(session: ScanSession, path: str) -> None:
    if path not in session.public_live_paths:
        session.public_live_paths[path] = f"Scan file {len(session.public_live_paths) + 1}"


def public_metadata(
    session: ScanSession,
    redactor: PublicRedactor | None = None,
) -> PublicScanMetadata:
    active_redactor = redactor or session_public_redactor(session)
    if session.terminal and session.scan_state != "complete":
        # Non-actionable terminal sessions deliberately drop internal matches.
        # Keep the already scan-wide-redacted terminal projection instead of
        # reconstructing selected roots after that sensitive context is gone.
        return session.public_result.metadata.redacted(active_redactor)
    selected_roots = (
        list(session.selected_roots)
        if session.scan_state == "complete"
        else [f"Scan root {index}" for index, _root in enumerate(session.selected_roots, 1)]
    )
    return PublicScanMetadata(
        selected_roots=selected_roots,
        duration_ms=session.duration_ms,
        data_scanned_bytes=sum(
            fingerprint.size for fingerprint in session.file_fingerprints.values()
        ),
        detector_count=session.detector_count,
        ai_model=session.ai_model,
    ).redacted(active_redactor)


def _fingerprint_estimate(key: str, fingerprint: FileFingerprint) -> int:
    return (
        sum(
            len(value.encode("utf-8"))
            for value in (key, fingerprint.resolved_path, fingerprint.sha256)
        )
        + 32
    )


def _generated_output_estimate(source_path: str, generated: GeneratedOutput) -> int:
    return (
        len(source_path.encode("utf-8"))
        + len(generated.output_path.encode("utf-8"))
        + sum(len(finding_id.encode("utf-8")) for finding_id in generated.finding_ids)
        + sum(len(warning.encode("utf-8")) for warning in generated.warnings)
        + _fingerprint_estimate(source_path, generated.source_fingerprint)
        + _fingerprint_estimate(generated.output_path, generated.output_fingerprint)
        + len(generated.created_at.isoformat().encode("utf-8"))
        + len(generated.verification_status.encode("utf-8"))
        + len(generated.rescan_status.encode("utf-8"))
        + 32
    )


def _output_metadata_budget(
    fingerprints: dict[str, FileFingerprint],
    findings: list[Finding],
    generated_outputs: dict[str, GeneratedOutput],
) -> int:
    """Reserve enough retained space for output metadata before files are written."""

    finding_ids_by_file: dict[str, list[str]] = {}
    for finding in findings:
        if finding.can_anonymize:
            finding_ids_by_file.setdefault(finding.file_path, []).append(finding.id)

    total = 0
    for source_path in dict.fromkeys([*finding_ids_by_file, *generated_outputs]):
        if source_path not in fingerprints and source_path not in generated_outputs:
            continue
        path_bytes = len(source_path.encode("utf-8"))
        finding_id_bytes = sum(
            len(finding_id.encode("utf-8"))
            for finding_id in finding_ids_by_file.get(source_path, [])
        )
        # GeneratedOutput retains source/output paths, two fingerprints,
        # selected IDs, timestamps, verification counters, and bounded warning
        # copy. Reserve conservatively so a successful write cannot push an
        # already accepted session over its byte ceiling afterward.
        reserved = path_bytes * 8 + finding_id_bytes + 2_048
        generated = generated_outputs.get(source_path)
        actual = _generated_output_estimate(source_path, generated) if generated else 0
        total += max(reserved, actual)
    return total


def _estimate_retained_bytes(
    *,
    internal_findings: dict[str, Finding],
    public_result: PublicScanResult,
    request: ScanRequest | None,
    file_fingerprints: dict[str, FileFingerprint],
    selected_roots: tuple[str, ...],
    events: list[PublicScanEvent],
    remediation_states: dict[str, RemediationState],
    generated_outputs: dict[str, GeneratedOutput],
    progress: PublicScanProgress,
    ai_model: str | None,
    retained_remediation_artifacts: set[str],
    public_redactor: PublicRedactor,
    public_live_paths: dict[str, str],
    rescan_categories: tuple[str, ...],
    rescan_options: ScanOptions,
) -> int:
    internal = sum(
        len(finding.model_dump_json().encode("utf-8")) for finding in internal_findings.values()
    )
    public = len(public_result.model_dump_json().encode("utf-8"))
    request_bytes = len(request.model_dump_json().encode("utf-8")) if request is not None else 0
    fingerprints = sum(
        _fingerprint_estimate(path, fingerprint) for path, fingerprint in file_fingerprints.items()
    )
    roots = sum(len(root.encode("utf-8")) for root in selected_roots)
    event_bytes = sum(len(event.model_dump_json().encode("utf-8")) for event in events)
    remediation = sum(
        len(finding_id.encode("utf-8")) + len(state.encode("utf-8"))
        for finding_id, state in remediation_states.items()
    )
    outputs = _output_metadata_budget(
        file_fingerprints,
        list(internal_findings.values()),
        generated_outputs,
    )
    progress_bytes = len(progress.model_dump_json().encode("utf-8"))
    model = len(ai_model.encode("utf-8")) if ai_model is not None else 0
    retained_artifacts = sum(len(path.encode("utf-8")) for path in retained_remediation_artifacts)
    redactor_bytes = sum(
        len(internal.encode("utf-8")) + len(public.encode("utf-8"))
        for mapping in (
            public_redactor.replacements,
            public_redactor.path_replacements,
            public_redactor.public_paths,
            public_redactor.live_paths,
        )
        for internal, public in mapping
    )
    live_paths = sum(
        len(path.encode("utf-8")) + len(label.encode("utf-8"))
        for path, label in public_live_paths.items()
    )
    rescan_profile = (
        sum(len(category.encode("utf-8")) for category in rescan_categories)
        + len(rescan_options.model_dump_json().encode("utf-8"))
        + 9
    )
    return (
        internal
        + public
        + request_bytes
        + fingerprints
        + roots
        + event_bytes
        + remediation
        + 8  # remediation revision
        + outputs
        + progress_bytes
        + model
        + retained_artifacts
        + redactor_bytes
        + live_paths
        + rescan_profile
    )


def estimate_session_bytes(session: ScanSession) -> int:
    return _estimate_retained_bytes(
        internal_findings=session.internal_findings,
        public_result=session.public_result,
        request=session.request,
        file_fingerprints=session.file_fingerprints,
        selected_roots=session.selected_roots,
        events=session.events,
        remediation_states=session.remediation_states,
        generated_outputs=session.generated_outputs,
        progress=session.progress,
        ai_model=session.ai_model,
        retained_remediation_artifacts=session.retained_remediation_artifacts,
        public_redactor=session.public_redactor,
        public_live_paths=session.public_live_paths,
        rescan_categories=session.rescan_categories,
        rescan_options=session.rescan_options,
    )


def estimate_terminal_update_bytes(session: ScanSession, update: _TerminalUpdate) -> int:
    events = [*session.events, update.event]
    if len(events) > session.max_events:
        events = events[-session.max_events :]
    return _estimate_retained_bytes(
        internal_findings=update.internal_findings,
        public_result=update.public_result,
        request=None,
        file_fingerprints=update.file_fingerprints,
        selected_roots=session.selected_roots,
        events=events,
        remediation_states=update.remediation_states,
        generated_outputs=update.generated_outputs,
        progress=update.progress,
        ai_model=session.ai_model,
        retained_remediation_artifacts=update.retained_remediation_artifacts,
        public_redactor=update.public_redactor,
        public_live_paths=session.public_live_paths,
        rescan_categories=session.rescan_categories,
        rescan_options=session.rescan_options,
    )


def percent(completed: int, total: int | None) -> float:
    if total is None or total <= 0:
        return 0.0
    return min(100.0, completed / total * 100)


def public_progress(
    event: ScanEvent,
    redactor: PublicRedactor | None = None,
    *,
    live: bool = False,
) -> PublicScanProgress:
    active_redactor = redactor or PublicRedactor()
    progress = PublicScanProgress(
        stage=event.stage,
        completed_files=event.completed_files,
        total_files=event.total_files,
        percent=percent(event.completed_files, event.total_files),
        current_file=(
            active_redactor.live_path(event.file_path)
            if live and event.file_path is not None
            else event.file_path
        ),
        findings_so_far=event.findings_so_far,
        skipped_files=event.skipped_files,
    )
    return progress.redacted(active_redactor)
