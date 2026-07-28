"""Bounded, ephemeral server-side storage for browser scan workflows."""

from __future__ import annotations

import hashlib
import os
import secrets
import threading
import time
from collections.abc import Callable
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Literal

from redactlens_core.anonymize import (
    SourceChangedError,
    prepare_anonymized_file,
    verify_anonymized_bytes,
)
from redactlens_core.atomic import (
    AtomicCleanupError,
    AtomicFileSignature,
    AtomicOutputChangedError,
    AtomicRollbackError,
    capture_file_signature,
    write_many_bytes_atomically,
)
from redactlens_core.document_anonymize import DocumentChangedError
from redactlens_core.files import discover_files
from redactlens_core.llm.adapter import DEFAULT_MODEL, DEFAULT_TIMEOUT, OllamaAdapter
from redactlens_core.models import (
    DEFAULT_TIER_THRESHOLD,
    Finding,
    ScanOptions,
    ScanRequest,
    ScanResult,
    UserTarget,
)
from redactlens_core.progress import ScanCancelled, ScanEvent, ScanExecution, ScanTimedOut
from redactlens_core.registry import load_default_registry
from redactlens_core.scanner import scan as core_scan

from . import session_files as _session_files
from . import session_state as _session_state
from .contracts import (
    GeneratedOutputDetails,
    PublicFileFingerprint,
    PublicRedactor,
    PublicScanError,
    PublicScanMetadata,
    PublicScanProgress,
    PublicScanResult,
    RemediationFilePlan,
    RemediationFindingState,
    RemediationGenerationResponse,
    RemediationOutputMode,
    RemediationPlan,
    ScanState,
)
from .session_errors import ErrorCode as ErrorCode
from .session_errors import SessionProblem
from .session_files import (
    FileFingerprint,
    GeneratedOutput,
    _absolute_path_no_follow,
    _assert_no_redirect_ancestors,
    _filesystem_entry_may_exist,
    _read_regular_bytes_no_follow,
    _redacted_output_path_no_follow,
)
from .session_state import DEFAULT_MAX_EVENTS, ScanSession

EventReplayGap = _session_state.EventReplayGap
_estimate_session_bytes = _session_state.estimate_session_bytes
_estimate_terminal_update_bytes = _session_state.estimate_terminal_update_bytes
_session_public_redactor = _session_state.session_public_redactor

DEFAULT_IDLE_TIMEOUT_SECONDS = 15 * 60
DEFAULT_MAX_SESSIONS = 8
DEFAULT_MAX_RETAINED_BYTES = 64 * 1024 * 1024
DEFAULT_JOB_TIMEOUT_SECONDS = 30 * 60
DEFAULT_EXTRACTION_TIMEOUT_SECONDS = 30.0


def _output_rescan_options(options: ScanOptions) -> ScanOptions:
    """Keep the original resource bounds but scan the exact generated path.

    Directory and extension filters describe discovery of the original roots.
    Applying them to a deterministic ``*-auto-redacted-copy.*`` path can silently skip the
    output, so they are intentionally cleared for this one-file follow-up scan.
    """

    return options.model_copy(
        deep=True,
        update={
            "ignored_directories": [],
            "included_extensions": [],
            "excluded_extensions": [],
            "use_redactlensignore": False,
        },
    )


def _output_rescan_requires_ai(request: ScanRequest) -> bool:
    """Remember whether the requested detector scope needs nondeterministic AI."""

    return request.use_llm or any(target.kind == "description" for target in request.user_targets)


class ScanSessionStore:
    """Thread-safe LRU store bounded by idle time, count, and retained bytes."""

    def __init__(
        self,
        *,
        idle_timeout_seconds: float = DEFAULT_IDLE_TIMEOUT_SECONDS,
        max_sessions: int = DEFAULT_MAX_SESSIONS,
        max_retained_bytes: int = DEFAULT_MAX_RETAINED_BYTES,
        clock: Callable[[], float] | None = None,
        wall_clock: Callable[[], float] | None = None,
        id_factory: Callable[[], str] | None = None,
        job_timeout_seconds: float = DEFAULT_JOB_TIMEOUT_SECONDS,
        extraction_timeout_seconds: float = DEFAULT_EXTRACTION_TIMEOUT_SECONDS,
        llm_call_timeout_seconds: float = DEFAULT_TIMEOUT,
        max_events: int = DEFAULT_MAX_EVENTS,
    ) -> None:
        if idle_timeout_seconds <= 0:
            raise ValueError("idle_timeout_seconds must be positive")
        if max_sessions <= 0:
            raise ValueError("max_sessions must be positive")
        if max_retained_bytes <= 0:
            raise ValueError("max_retained_bytes must be positive")
        if job_timeout_seconds <= 0 or extraction_timeout_seconds <= 0:
            raise ValueError("scan timeouts must be positive")
        if llm_call_timeout_seconds <= 0 or max_events <= 0:
            raise ValueError("LLM timeout and max_events must be positive")
        self.idle_timeout_seconds = idle_timeout_seconds
        self.max_sessions = max_sessions
        self.max_retained_bytes = max_retained_bytes
        self.job_timeout_seconds = job_timeout_seconds
        self.extraction_timeout_seconds = extraction_timeout_seconds
        self.llm_call_timeout_seconds = llm_call_timeout_seconds
        self.max_events = max_events
        # Retention and LRU ages must never depend on an adjustable wall
        # clock. ``clock`` remains injectable for deterministic tests; when a
        # legacy caller supplies only that clock, reuse it for presentation
        # timestamps too. Production defaults stay strictly separated.
        self._clock = clock if clock is not None else time.monotonic
        self._wall_clock = (
            wall_clock if wall_clock is not None else (clock if clock is not None else time.time)
        )
        self._id_factory = id_factory or (lambda: secrets.token_urlsafe(24))
        self._sessions: dict[str, ScanSession] = {}
        # Pending background jobs reserve a slot before ``start_job`` can race
        # with another admission. Once started, the slot retains the worker
        # even if its session reaches the hard retention deadline and is
        # cleared. Python cannot safely terminate a non-cooperative thread, so
        # forgetting that still-alive worker here would let repeated expiry
        # cycles exceed the configured background-job bound.
        self._worker_slots: dict[str, threading.Thread | None] = {}
        self._lock = threading.RLock()
        self._cleanup_stop = threading.Event()
        self._cleanup_thread: threading.Thread | None = None

    @classmethod
    def from_environment(cls) -> ScanSessionStore:
        return cls(
            idle_timeout_seconds=_positive_env_float(
                "REDACTLENS_SESSION_IDLE_SECONDS", DEFAULT_IDLE_TIMEOUT_SECONDS
            ),
            max_sessions=_positive_env_int("REDACTLENS_MAX_SESSIONS", DEFAULT_MAX_SESSIONS),
            max_retained_bytes=_positive_env_int(
                "REDACTLENS_MAX_SESSION_BYTES", DEFAULT_MAX_RETAINED_BYTES
            ),
            job_timeout_seconds=_positive_env_float(
                "REDACTLENS_SCAN_TIMEOUT_SECONDS", DEFAULT_JOB_TIMEOUT_SECONDS
            ),
            extraction_timeout_seconds=_positive_env_float(
                "REDACTLENS_EXTRACTION_TIMEOUT_SECONDS",
                DEFAULT_EXTRACTION_TIMEOUT_SECONDS,
            ),
            llm_call_timeout_seconds=_positive_env_float(
                "REDACTLENS_LLM_CALL_TIMEOUT_SECONDS", DEFAULT_TIMEOUT
            ),
            max_events=_positive_env_int("REDACTLENS_MAX_SCAN_EVENTS", DEFAULT_MAX_EVENTS),
        )

    def create_pending(self, request: ScanRequest) -> ScanSession:
        progress = PublicScanProgress(stage="pending")
        empty_result = ScanResult(
            summary={
                "status": "pending",
                "incomplete": True,
                "completed_files": 0,
                "total_files": None,
            }
        )
        with self._lock:
            now = self._clock()
            created_at = datetime.fromtimestamp(self._wall_clock(), tz=UTC)
            self._prune_expired_locked(now)
            self._ensure_worker_slot_capacity_locked()
            scan_id = self._new_id_locked()
            expires_at = created_at + timedelta(seconds=self.idle_timeout_seconds)
            selected_roots = tuple(_absolute_path_no_follow(path) for path in request.paths)
            public_result = PublicScanResult.from_internal(
                scan_id=scan_id,
                created_at=created_at,
                expires_at=expires_at,
                result=empty_result,
                state="pending",
                progress=progress,
            )
            session = ScanSession(
                scan_id=scan_id,
                created_at=created_at,
                last_accessed_at=created_at,
                created_clock=now,
                last_accessed_clock=now,
                idle_timeout_seconds=self.idle_timeout_seconds,
                selected_roots=selected_roots,
                internal_findings={},
                public_result=public_result,
                file_fingerprints={},
                scan_state="pending",
                progress=progress,
                request=request.model_copy(deep=True),
                rescan_categories=tuple(request.categories),
                rescan_tier_threshold=request.tier_threshold,
                rescan_options=_output_rescan_options(request.options),
                rescan_scope_requires_ai=_output_rescan_requires_ai(request),
                max_events=self.max_events,
                capacity_callback=self._enforce_session_capacity,
            )
            session.estimated_bytes = _estimate_session_bytes(session)
            if session.estimated_bytes > self.max_retained_bytes:
                self._worker_slots.pop(scan_id, None)
                session.clear()
                raise _session_capacity_problem()
            try:
                self._make_capacity_locked(session.estimated_bytes)
            except SessionProblem:
                self._worker_slots.pop(scan_id, None)
                session.clear()
                raise
            self._worker_slots[scan_id] = None
            self._sessions[session.scan_id] = session
        return session

    def start_job(
        self,
        session: ScanSession,
        *,
        scanner: Callable = core_scan,
    ) -> None:
        with self._lock:
            if self._sessions.get(session.scan_id) is not session or session.discarded:
                raise SessionProblem(
                    "scan_expired",
                    "This scan expired before its background job could start. Run it again.",
                    410,
                )
            with session.workflow_lock:
                if session.worker_thread is not None:
                    raise RuntimeError("scan job already started")
                if session.scan_id not in self._worker_slots:
                    raise SessionProblem(
                        "scan_expired",
                        "This scan expired before its background job could start. Run it again.",
                        410,
                    )
                if self._worker_slots[session.scan_id] is not None:
                    raise RuntimeError("scan job already started")
                worker = threading.Thread(
                    target=self._run_registered_job,
                    args=(session, scanner),
                    name=f"redactlens-scan-{session.scan_id[:8]}",
                    daemon=True,
                )
                session.worker_thread = worker
                self._worker_slots[session.scan_id] = worker
                session.active_retention_deadline_clock = self._clock() + (
                    self.job_timeout_seconds
                    + max(self.extraction_timeout_seconds, self.llm_call_timeout_seconds)
                )
                try:
                    worker.start()
                except Exception as error:
                    self._sessions.pop(session.scan_id, None)
                    if not worker.is_alive():
                        self._worker_slots.pop(session.scan_id, None)
                    session.clear()
                    raise SessionProblem(
                        "scan_failed",
                        "The scan could not start. Try it again.",
                        503,
                    ) from error

    def create(
        self,
        request: ScanRequest,
        result: ScanResult,
        *,
        initial_fingerprints: dict[str, FileFingerprint] | None = None,
    ) -> ScanSession:
        fingerprints: dict[str, FileFingerprint] = {}
        for file_path in result.scanned_files:
            try:
                current = FileFingerprint.capture(file_path)
            except SessionProblem:
                raise
            except OSError as error:
                raise SessionProblem(
                    "file_unavailable",
                    "A scanned source could not be retained for follow-up actions.",
                    410,
                ) from error
            if initial_fingerprints is not None:
                expected = initial_fingerprints.get(current.resolved_path)
                if expected != current:
                    raise SessionProblem(
                        "file_changed",
                        "A source changed during the scan. Scan it again.",
                        409,
                    )
            fingerprints[file_path] = current

        internal_findings = {finding.id: finding for finding in result.findings}
        with self._lock:
            now = self._clock()
            created_at = datetime.fromtimestamp(self._wall_clock(), tz=UTC)
            self._prune_expired_locked(now)
            scan_id = self._new_id_locked()
            expires_at = created_at + timedelta(seconds=self.idle_timeout_seconds)
            selected_roots = tuple(_absolute_path_no_follow(path) for path in request.paths)
            public_redactor = PublicRedactor.from_findings(
                result.findings,
                reserved_paths=[
                    *selected_roots,
                    *(finding.file_path for finding in result.findings),
                    *(
                        str(_redacted_output_path_no_follow(path))
                        for path in dict.fromkeys(
                            finding.file_path
                            for finding in result.findings
                            if finding.can_anonymize
                        )
                    ),
                    *result.scanned_files,
                    *(skipped.path for skipped in result.skipped_files),
                    *fingerprints,
                    *(fingerprint.resolved_path for fingerprint in fingerprints.values()),
                ],
            )
            public_result = PublicScanResult.from_internal(
                scan_id=scan_id,
                created_at=created_at,
                expires_at=expires_at,
                result=result,
                redactor=public_redactor,
            )
            session = ScanSession(
                scan_id=scan_id,
                created_at=created_at,
                last_accessed_at=created_at,
                created_clock=now,
                last_accessed_clock=now,
                idle_timeout_seconds=self.idle_timeout_seconds,
                selected_roots=selected_roots,
                internal_findings=internal_findings,
                public_result=public_result,
                file_fingerprints=fingerprints,
                detector_count=len(load_default_registry().get_by_categories(request.categories))
                + len(request.user_targets),
                ai_model=(request.ollama_model or DEFAULT_MODEL) if result.llm_used else None,
                rescan_categories=tuple(request.categories),
                rescan_tier_threshold=request.tier_threshold,
                rescan_options=_output_rescan_options(request.options),
                rescan_scope_requires_ai=_output_rescan_requires_ai(request),
                remediation_states={
                    finding.id: "pending" if finding.can_anonymize else "read_only"
                    for finding in result.findings
                },
                public_redactor=public_redactor,
                max_events=self.max_events,
                capacity_callback=self._enforce_session_capacity,
            )
            session.estimated_bytes = _estimate_session_bytes(session)
            if session.estimated_bytes > self.max_retained_bytes:
                session.clear()
                raise _session_capacity_problem()
            try:
                self._make_capacity_locked(session.estimated_bytes)
            except SessionProblem:
                session.clear()
                raise
            self._sessions[session.scan_id] = session
        return session

    def get(self, scan_id: str) -> ScanSession:
        with self._lock:
            now = self._clock()
            self._prune_expired_locked(now)
            session = self._sessions.get(scan_id)
            if session is None:
                raise SessionProblem(
                    "scan_expired",
                    "This scan has expired. Run it again before taking further action.",
                    410,
                )
            session.touch(now, self._wall_clock())
            return session

    def touch(self, session: ScanSession) -> bool:
        """Refresh an existing session without raising inside a streaming response."""
        with self._lock:
            if self._sessions.get(session.scan_id) is not session or session.discarded:
                return False
            session.touch(self._clock(), self._wall_clock())
            return True

    def delete(self, scan_id: str) -> bool:
        with self._lock:
            session = self._sessions.get(scan_id)
            if session is None:
                return False
            if session.active:
                session.request_cancel()
                return True

        # File workflows intentionally hold workflow_lock for their complete
        # transaction. Never wait for that lock while retaining the store lock:
        # the workflow may need the store lock to publish its final retained
        # size. Waiting in workflow -> store order avoids that inversion.
        with session.workflow_lock:
            with self._lock:
                if self._sessions.get(scan_id) is not session:
                    return False
                self._sessions.pop(scan_id)
                self._release_worker_slot_locked(session)
            session.clear()
        return True

    def clear(self) -> None:
        with self._lock:
            sessions = list(self._sessions.values())
            self._sessions.clear()
            for session in sessions:
                self._release_worker_slot_locked(session)
        for session in sessions:
            session.clear()

    def start_cleanup_worker(self, interval_seconds: float | None = None) -> None:
        """Continuously purge expired sessions even when no requests arrive."""
        interval = interval_seconds or min(60.0, max(1.0, self.idle_timeout_seconds / 2))
        if interval <= 0:
            raise ValueError("interval_seconds must be positive")
        with self._lock:
            if self._cleanup_thread is not None and self._cleanup_thread.is_alive():
                return
            self._cleanup_stop.clear()
            self._cleanup_thread = threading.Thread(
                target=self._cleanup_loop,
                args=(interval,),
                name="redactlens-session-cleanup",
                daemon=True,
            )
            self._cleanup_thread.start()

    def close(self) -> None:
        self._cleanup_stop.set()
        worker = self._cleanup_thread
        if worker is not None and worker is not threading.current_thread():
            worker.join(timeout=1.0)
        self.clear()

    def prune_expired(self) -> int:
        with self._lock:
            return self._prune_expired_locked(self._clock())

    @property
    def session_count(self) -> int:
        with self._lock:
            return len(self._sessions)

    @property
    def retained_bytes(self) -> int:
        with self._lock:
            return sum(session.estimated_bytes for session in self._sessions.values())

    @property
    def worker_slot_count(self) -> int:
        """Pending reservations plus workers that have not actually exited."""
        with self._lock:
            self._prune_worker_slots_locked()
            return len(self._worker_slots)

    @property
    def live_worker_count(self) -> int:
        with self._lock:
            self._prune_worker_slots_locked()
            return sum(worker is not None for worker in self._worker_slots.values())

    def _new_id_locked(self) -> str:
        for _ in range(10):
            candidate = self._id_factory()
            if (
                candidate
                and candidate not in self._sessions
                and candidate not in self._worker_slots
            ):
                return candidate
        raise RuntimeError("could not generate a unique scan id")

    def _ensure_worker_slot_capacity_locked(self) -> None:
        self._prune_worker_slots_locked()
        if len(self._worker_slots) >= self.max_sessions:
            raise _session_capacity_problem()

    def _prune_worker_slots_locked(self) -> None:
        for scan_id, worker in list(self._worker_slots.items()):
            if worker is None:
                session = self._sessions.get(scan_id)
                if session is None or session.terminal:
                    self._worker_slots.pop(scan_id, None)
            elif not worker.is_alive():
                self._worker_slots.pop(scan_id, None)

    def _release_worker_slot_locked(self, session: ScanSession) -> None:
        worker = self._worker_slots.get(session.scan_id)
        if worker is None or not worker.is_alive():
            self._worker_slots.pop(session.scan_id, None)

    def _make_capacity_locked(self, incoming_bytes: int) -> None:
        if incoming_bytes > self.max_retained_bytes:
            raise _session_capacity_problem()
        while self._sessions and (
            len(self._sessions) >= self.max_sessions
            or self.retained_bytes + incoming_bytes > self.max_retained_bytes
        ):
            candidates = sorted(
                (
                    (scan_id, session)
                    for scan_id, session in self._sessions.items()
                    if session.terminal
                ),
                key=lambda item: item[1].last_accessed_clock,
            )
            if not any(
                self._evict_session_locked(scan_id, session) for scan_id, session in candidates
            ):
                # Reject the incoming session rather than waiting for a file
                # transaction that may itself need the store lock to finish.
                raise _session_capacity_problem()

    def _prune_expired_locked(self, now: float) -> int:
        # A worker cannot observe its own Thread as stopped while its target is
        # returning. Reap completed slots only from another thread after
        # ``is_alive()`` has become false.
        self._prune_worker_slots_locked()
        expired_ids = [
            scan_id
            for scan_id, session in self._sessions.items()
            if self._session_expired_locked(session, now)
        ]
        removed = 0
        for scan_id in expired_ids:
            session = self._sessions.get(scan_id)
            if session is not None and self._evict_session_locked(scan_id, session):
                removed += 1
        return removed

    def _evict_session_locked(self, scan_id: str, session: ScanSession) -> bool:
        """Clear one retained session without ever waiting under the store lock.

        The caller holds ``self._lock``. Acquiring ``workflow_lock``
        nonblocking makes clearing safe while preserving the global lock order:
        a remediation transaction that already owns the workflow lock remains
        responsible for finishing (or failing) instead of deadlocking while it
        tries to refresh store capacity.
        """
        if self._sessions.get(scan_id) is not session:
            return False
        if not session.workflow_lock.acquire(blocking=False):
            return False
        try:
            if self._sessions.get(scan_id) is not session:
                return False
            self._sessions.pop(scan_id)
            self._release_worker_slot_locked(session)
            session.clear()
            return True
        finally:
            session.workflow_lock.release()

    def _session_expired_locked(self, session: ScanSession, now: float) -> bool:
        # File workflows hold this lock for their whole transaction. A cleanup
        # pass must not clear trusted findings/metadata while one is active.
        if not session.workflow_lock.acquire(blocking=False):
            return False
        session.workflow_lock.release()
        if not session.active:
            return now - session.last_accessed_clock >= self.idle_timeout_seconds

        worker = session.worker_thread
        if worker is None:
            # A pending session that never reached start_job must not retain
            # its request (including literal targets) forever, even if an SSE
            # client keeps touching it.
            return now - session.created_clock >= self.idle_timeout_seconds
        if not worker.is_alive():
            # Normal workers make the session terminal before exiting. An
            # active session with a dead worker is therefore orphaned.
            return True
        deadline = session.active_retention_deadline_clock
        return deadline is not None and now >= deadline

    def _cleanup_loop(self, interval_seconds: float) -> None:
        while not self._cleanup_stop.wait(interval_seconds):
            self.prune_expired()

    def _record_core_event(self, session: ScanSession, event: ScanEvent) -> None:
        session.apply_core_event(event)
        with self._lock:
            if self._sessions.get(session.scan_id) is not session or session.discarded:
                return
            session.touch(self._clock(), self._wall_clock())
            with session.workflow_lock:
                session.estimated_bytes = _estimate_session_bytes(session)
                estimate = session.estimated_bytes
            if estimate > self.max_retained_bytes:
                _strip_for_capacity_failure(session)
                session.estimated_bytes = _estimate_session_bytes(session)
                raise _session_capacity_problem()
            try:
                self._make_capacity_for_existing_locked(session, estimate)
            except SessionProblem:
                # The event may have made this live job exceed the aggregate
                # store budget while every other retained session is active.
                # Keep the worker/session relationship intact so the raised
                # problem can terminate the job normally, but immediately
                # discard its variable sensitive state to restore the bound.
                _strip_for_capacity_failure(session)
                session.estimated_bytes = _estimate_session_bytes(session)
                raise

    def _enforce_session_capacity(self, session: ScanSession) -> None:
        """Recount a retained session after workflow metadata changes."""
        with self._lock:
            if self._sessions.get(session.scan_id) is not session or session.discarded:
                raise SessionProblem(
                    "scan_expired",
                    "This scan has expired. Run it again before taking further action.",
                    410,
                )
            with session.workflow_lock:
                session.estimated_bytes = _estimate_session_bytes(session)
                estimate = session.estimated_bytes
                session.touch(self._clock(), self._wall_clock())
            if estimate > self.max_retained_bytes:
                self._evict_session_locked(session.scan_id, session)
                raise _session_capacity_problem()
            self._make_capacity_for_existing_locked(session, estimate)

    def _finish_job(
        self,
        session: ScanSession,
        result: ScanResult,
        *,
        state: ScanState,
        fingerprints: dict[str, FileFingerprint] | None = None,
        error: PublicScanError | None = None,
        duration_ms: int,
        ai_model: str | None,
        public_partial: PublicScanResult | None = None,
    ) -> None:
        active_result = result
        active_state = state
        active_fingerprints = fingerprints or {}
        active_error = error

        with self._lock:
            if self._sessions.get(session.scan_id) is not session or session.discarded:
                return
            # DELETE and terminal publication share this store -> workflow lock
            # boundary. If DELETE linearized first, completion must honor the
            # accepted cancellation; if completion linearized first, DELETE
            # observes a terminal session and follows the normal delete path.
            with session.event_condition:
                if active_state == "complete" and session.cancellation_requested():
                    active_state = "cancelled"
                    active_fingerprints = {}
                    active_error = PublicScanError(
                        code="scan_cancelled",
                        message="Scan cancelled by request.",
                    )
                session.duration_ms = duration_ms
                session.ai_model = ai_model
                session.touch(self._clock(), self._wall_clock())
                update = session._prepare_terminal_update_locked(
                    active_result,
                    state=active_state,
                    fingerprints=active_fingerprints,
                    error=active_error,
                    public_partial=public_partial,
                )
                estimate = _estimate_terminal_update_bytes(session, update)

                try:
                    if estimate > self.max_retained_bytes:
                        raise _session_capacity_problem()
                    self._make_capacity_for_existing_locked(session, estimate)
                except SessionProblem as capacity_error:
                    if capacity_error.code != "session_capacity":
                        raise
                    # Do not publish one terminal event and then reverse it.
                    # Strip the active projection first, prepare the exact
                    # minimal failure (including its event), and size that.
                    _strip_for_capacity_failure(session)
                    capacity = _session_capacity_problem()
                    update = session._prepare_terminal_update_locked(
                        _capacity_failure_result(),
                        state="failed",
                        error=PublicScanError(
                            code=capacity.code,
                            message=capacity.message,
                        ),
                    )
                    estimate = _estimate_terminal_update_bytes(session, update)
                    try:
                        if estimate > self.max_retained_bytes:
                            raise capacity
                        self._make_capacity_for_existing_locked(session, estimate)
                    except SessionProblem:
                        self._sessions.pop(session.scan_id, None)
                        session.clear()
                        return

                session._apply_terminal_update_locked(update)
                session.active_retention_deadline_clock = None

    def _run_registered_job(self, session: ScanSession, scanner: Callable) -> None:
        # Keep the slot registered through actual Thread exit. Admission and
        # cleanup lazily reap it once ``worker.is_alive()`` is false; removing
        # it from this target's ``finally`` leaves a race while Thread.run is
        # still unwinding.
        self._run_job(session, scanner)

    def _run_job(self, session: ScanSession, scanner: Callable) -> None:
        request = session.request
        if request is None or session.discarded:
            return
        partial = ScanResult(
            summary={
                "status": "failed",
                "incomplete": True,
                "completed_files": 0,
                "total_files": None,
            }
        )
        job_started = time.monotonic()
        deadline = job_started + self.job_timeout_seconds
        adapter: OllamaAdapter | None = None

        def finish_job(
            result: ScanResult,
            *,
            state: ScanState,
            fingerprints: dict[str, FileFingerprint] | None = None,
            error: PublicScanError | None = None,
            public_partial: PublicScanResult | None = None,
        ) -> None:
            self._finish_job(
                session,
                result,
                state=state,
                fingerprints=fingerprints,
                error=error,
                duration_ms=max(0, round((time.monotonic() - job_started) * 1000)),
                ai_model=adapter.model if result.llm_used and adapter is not None else None,
                public_partial=public_partial,
            )

        checkpoint = _cancellation_checkpoint(
            session,
            deadline=deadline,
            partial_result=lambda: partial,
        )
        try:
            # Browser metadata records lexical absolute selected roots. Scan
            # those same paths without resolving a user-selected link before
            # discovery has applied the link/reparse policy.
            scan_request = request.model_copy(
                update={"paths": [_absolute_path_no_follow(path) for path in request.paths]}
            )
            initial_fingerprints = capture_scan_input_fingerprints(
                scan_request.paths,
                checkpoint=checkpoint,
                options=scan_request.options,
            )
            checkpoint()
            registry = load_default_registry()
            with session.workflow_lock:
                session.detector_count = len(
                    registry.get_by_categories(scan_request.categories)
                ) + len(scan_request.user_targets)
            adapter = OllamaAdapter(
                model=scan_request.ollama_model or DEFAULT_MODEL,
                timeout=min(
                    self.llm_call_timeout_seconds,
                    scan_request.options.ai_timeout_seconds,
                ),
            )
            execution = ScanExecution(
                event_sink=lambda event: self._record_core_event(session, event),
                cancel_requested=session.cancellation_requested,
                job_timeout_seconds=max(0.001, deadline - time.monotonic()),
                extraction_timeout_seconds=self.extraction_timeout_seconds,
                # DELETE accepts cancellation while holding this same lock.
                # Core therefore checks and submits under one linearization
                # boundary without holding it across synchronous event sinks.
                submission_guard=lambda: session.workflow_lock,
            )
            result = scanner(
                scan_request,
                registry,
                llm_adapter=adapter,
                execution=execution,
            )
            partial = result
            checkpoint()
            fingerprints = _capture_result_fingerprints(
                result,
                initial_fingerprints,
                checkpoint=checkpoint,
            )
            checkpoint()
            finish_job(result, state="complete", fingerprints=fingerprints)
        except ScanCancelled as error:
            finish_job(
                error.partial_result,
                state="cancelled",
                error=PublicScanError(code="scan_cancelled", message=str(error)),
            )
        except ScanTimedOut as error:
            finish_job(
                error.partial_result,
                state="timed_out",
                error=PublicScanError(code="scan_timed_out", message=str(error)),
            )
        except SessionProblem as error:
            finish_job(
                _capacity_failure_result() if error.code == "session_capacity" else partial,
                state="failed",
                error=PublicScanError(code=error.code, message=error.message),
            )
        except Exception:
            with session.workflow_lock:
                public_partial = session.public_result.model_copy(deep=True)
            finish_job(
                partial,
                state="failed",
                error=PublicScanError(
                    code="scan_failed",
                    message="The scan failed unexpectedly. Try the scan again.",
                ),
                public_partial=public_partial,
            )

    def _make_capacity_for_existing_locked(
        self,
        current: ScanSession,
        final_bytes: int,
    ) -> None:
        while True:
            all_others = [
                (scan_id, session)
                for scan_id, session in self._sessions.items()
                if session is not current
            ]
            other_bytes = sum(session.estimated_bytes for _, session in all_others)
            if other_bytes + final_bytes <= self.max_retained_bytes:
                return
            candidates = [(scan_id, session) for scan_id, session in all_others if session.terminal]
            if not candidates:
                if current.active:
                    raise _session_capacity_problem()
                self._evict_session_locked(current.scan_id, current)
                raise _session_capacity_problem()
            candidates.sort(key=lambda item: item[1].last_accessed_clock)
            if any(self._evict_session_locked(scan_id, session) for scan_id, session in candidates):
                continue

            # Active jobs must remain attached to their session until their
            # worker records a terminal failure. The event-recording caller
            # strips the current job's variable state before propagating this
            # capacity failure. Terminal workflow growth may safely discard
            # the terminal current session instead.
            if current.active:
                raise _session_capacity_problem()
            self._evict_session_locked(current.scan_id, current)
            raise _session_capacity_problem()


def verify_source_files(
    session: ScanSession,
    file_paths: list[str],
    *,
    before_action: str = "creating redacted copies",
) -> None:
    with session.workflow_lock:
        session.require_complete()
        _verify_source_files_locked(session, file_paths, before_action=before_action)


def _verify_source_files_locked(
    session: ScanSession,
    file_paths: list[str],
    *,
    before_action: str,
) -> None:
    _session_files.verify_source_files_locked(session, file_paths, before_action=before_action)


def capture_scan_input_fingerprints(
    paths: list[str],
    checkpoint: Callable[[], None] | None = None,
    options: ScanOptions | None = None,
) -> dict[str, FileFingerprint]:
    """Hash eligible inputs before scanning to detect mid-scan changes."""
    return _session_files.capture_scan_input_fingerprints(
        paths,
        checkpoint=checkpoint,
        options=options,
        discover=discover_files,
    )


def remediation_plan(session: ScanSession) -> RemediationPlan:
    """Project the server-owned workflow state into a privacy-safe review model."""
    with session.workflow_lock:
        session.require_complete()
        return _remediation_plan_locked(session)


def _remediation_plan_locked(session: ScanSession) -> RemediationPlan:
    redactor = _session_public_redactor(session)
    session.retained_remediation_artifacts = {
        path for path in session.retained_remediation_artifacts if _filesystem_entry_may_exist(path)
    }
    retained_artifact_paths = [
        redactor.path(path) for path in sorted(session.retained_remediation_artifacts)
    ]
    included = [
        finding
        for finding in session.internal_findings.values()
        if session.remediation_states.get(finding.id) == "included"
    ]
    included_by_file: dict[str, list[str]] = {}
    for finding in included:
        included_by_file.setdefault(finding.file_path, []).append(finding.id)

    source_paths = list(dict.fromkeys([*included_by_file, *session.generated_outputs]))
    files: list[RemediationFilePlan] = []
    for source_path in source_paths:
        selected_ids = included_by_file.get(source_path, [])
        generated = session.generated_outputs.get(source_path)
        if generated is None:
            proposed_output = _redacted_output_path_no_follow(source_path)
            try:
                _assert_no_redirect_ancestors(proposed_output)
            except OSError:
                output_state = "conflict"
            else:
                output_state = (
                    "conflict" if _filesystem_entry_may_exist(proposed_output) else "not_created"
                )
        elif not selected_ids:
            # A prior copy remains on disk, but generating a zero-selection
            # copy would merely duplicate the unredacted original. Keep the
            # artifact visible as a manual-cleanup concern instead.
            output_state = "obsolete"
        else:
            try:
                current_output = FileFingerprint.capture(generated.output_path)
            except (OSError, SessionProblem):
                # A missing prior output can be recreated safely. An existing
                # entry that is unreadable, redirected, non-regular, or no
                # longer fingerprinted belongs to the user and must not be
                # presented as a regenerable RedactLens-owned destination.
                output_state = (
                    "conflict"
                    if _filesystem_entry_may_exist(generated.output_path)
                    else "regeneration_required"
                )
            else:
                if current_output != generated.output_fingerprint:
                    output_state = "conflict"
                elif tuple(selected_ids) == generated.finding_ids:
                    output_state = "current"
                else:
                    output_state = "regeneration_required"
        files.append(
            RemediationFilePlan(
                source_path=redactor.path(source_path),
                output_path=(
                    redactor.path(generated.output_path)
                    if generated is not None
                    else redactor.path(str(_redacted_output_path_no_follow(source_path)))
                ),
                included_finding_ids=selected_ids,
                output_state=output_state,
            )
        )

    states = [
        RemediationFindingState(
            finding_id=finding.id,
            state=session.remediation_states.get(
                finding.id,
                "pending" if finding.can_anonymize else "read_only",
            ),
        )
        for finding in session.internal_findings.values()
    ]
    source_was_replaced = any(
        Path(_absolute_path_no_follow(source_path))
        == Path(_absolute_path_no_follow(generated.output_path))
        for source_path, generated in session.generated_outputs.items()
    )
    return RemediationPlan(
        plan_revision=session.remediation_revision,
        findings=states,
        files=files,
        selected_finding_count=len(included),
        affected_file_count=len(included_by_file),
        read_only_finding_count=sum(
            1 for finding in session.internal_findings.values() if not finding.can_anonymize
        ),
        retained_artifact_paths=retained_artifact_paths,
        can_review=bool(files or retained_artifact_paths),
        can_generate=(
            bool(included)
            and not source_was_replaced
            and not any(file.output_state == "conflict" for file in files)
        ),
    )


def update_remediation_plan(
    session: ScanSession,
    included_finding_ids: list[str],
    ignored_finding_ids: list[str],
    expected_revision: int | None = None,
) -> RemediationPlan:
    included_ids = list(dict.fromkeys(included_finding_ids))
    ignored_ids = list(dict.fromkeys(ignored_finding_ids))
    if set(included_ids) & set(ignored_ids):
        raise SessionProblem(
            "invalid_remediation_plan",
            "A finding cannot be both included and ignored.",
            400,
        )

    with session.workflow_lock:
        session.require_complete()
        if expected_revision is not None and expected_revision != session.remediation_revision:
            raise SessionProblem(
                "invalid_remediation_plan",
                "The remediation plan changed. Review the latest plan before continuing.",
                409,
            )
        chosen = session.findings([*included_ids, *ignored_ids])
        if any(not finding.can_anonymize for finding in chosen):
            raise SessionProblem(
                "finding_not_anonymizable",
                "Read-only findings cannot be included in an automatic remediation plan.",
                400,
            )
        for finding in session.internal_findings.values():
            session.remediation_states[finding.id] = (
                "pending" if finding.can_anonymize else "read_only"
            )
        for finding_id in ignored_ids:
            session.remediation_states[finding_id] = "ignored"
        for finding_id in included_ids:
            session.remediation_states[finding_id] = "included"
        session.remediation_revision += 1
        plan = remediation_plan(session)
        session.refresh_retained_size()
    return plan


class _OutputRescanScopeUnavailable(Exception):
    """The original detector scope cannot be reproduced without fresh AI."""


class _OutputRescanIncomplete(Exception):
    """The generated output was not completely processed by the advisory scan."""


def _output_rescan_completed(rescan: ScanResult, output_path: Path) -> bool:
    expected_path = _absolute_path_no_follow(str(output_path))
    scanned_paths = {
        _absolute_path_no_follow(scanned_path) for scanned_path in rescan.scanned_files
    }
    return (
        expected_path in scanned_paths
        and not rescan.skipped_files
        and rescan.summary.get("status") == "complete"
        and rescan.summary.get("incomplete") is False
    )


def _enforce_failed_workflow_capacity(session: ScanSession) -> None:
    """Account for recovery paths before propagating the file-operation error.

    If those final path strings exceed the configured session budget, the
    store may evict this terminal session. The imminent workflow error still
    carries every recovery path, so capacity enforcement must not replace it
    with a less actionable capacity error.
    """

    try:
        session.refresh_retained_size()
    except SessionProblem as error:
        if error.code != "session_capacity":
            raise


def _output_rescan_request(session: ScanSession, output_path: Path) -> ScanRequest:
    """Rebuild the deterministic portion of the original scan scope.

    Terminal sessions intentionally release the original request, including
    unmatched user-provided values. Literal targets that actually contributed
    to retained findings can be reconstructed from trusted internal findings;
    description targets and AI-refined results cannot be reproduced
    deterministically, so those rescans are reported as unavailable instead of
    returning deceptively precise counts.
    """

    if session.rescan_scope_requires_ai or session.ai_model is not None:
        raise _OutputRescanScopeUnavailable

    literal_targets: list[UserTarget] = []
    seen_targets: set[tuple[str, str]] = set()
    for finding in session.internal_findings.values():
        detector_ids = {
            finding.detector_id,
            *(supporting.detector_id for supporting in finding.supporting_detections),
        }
        if any(detector_id.startswith("user_target_desc_") for detector_id in detector_ids):
            raise _OutputRescanScopeUnavailable
        if not any(detector_id.startswith("user_target_") for detector_id in detector_ids):
            continue
        key = (finding.matched_text, finding.category)
        if key in seen_targets:
            continue
        seen_targets.add(key)
        literal_targets.append(
            UserTarget(kind="literal", value=finding.matched_text, category=finding.category)
        )

    return ScanRequest(
        paths=[str(output_path)],
        categories=list(session.rescan_categories),
        user_targets=literal_targets,
        use_llm=False,
        tier_threshold=session.rescan_tier_threshold,
        options=session.rescan_options.model_copy(deep=True),
    )


def _adopt_atomic_restoration_identities(
    session: ScanSession,
    error: BaseException,
) -> None:
    """Trust new identities only when the atomic layer verified its rollback."""

    restored = getattr(error, "restored_signatures", None)
    if not isinstance(restored, dict):
        return
    by_path = {
        Path(_absolute_path_no_follow(os.fspath(path))): signature
        for path, signature in restored.items()
        if isinstance(signature, AtomicFileSignature)
    }
    for source_path, generated in list(session.generated_outputs.items()):
        output_path = Path(_absolute_path_no_follow(generated.output_path))
        signature = by_path.get(output_path)
        if signature is None:
            continue
        session.generated_outputs[source_path] = replace(
            generated,
            output_fingerprint=FileFingerprint(
                resolved_path=str(output_path),
                device=signature.device,
                inode=signature.inode,
                size=signature.size,
                modified_ns=signature.modified_ns,
                changed_ns=signature.changed_ns,
                sha256=signature.sha256,
            ),
        )


def generate_remediation_outputs(
    session: ScanSession,
    expected_revision: int | None = None,
    output_mode: RemediationOutputMode = "copy",
) -> RemediationGenerationResponse:
    """Render from verified originals and publish one recoverable transaction."""
    replacing_originals = output_mode == "replace_original"
    output_label = "original files" if replacing_originals else "redacted copies"
    write_operation = "original-file replacement" if replacing_originals else "redacted-copy write"
    with session.workflow_lock:
        session.require_complete()
        if expected_revision is not None and expected_revision != session.remediation_revision:
            raise SessionProblem(
                "invalid_remediation_plan",
                "The remediation plan changed. Review the latest plan before creating files.",
                409,
            )
        findings = [
            finding
            for finding in session.internal_findings.values()
            if session.remediation_states.get(finding.id) == "included"
        ]
        if not findings:
            raise SessionProblem(
                "no_findings_selected",
                f"Include at least one finding before writing {output_label}.",
                400,
            )

        by_file: dict[str, list[Finding]] = {}
        for finding in findings:
            by_file.setdefault(finding.file_path, []).append(finding)
        verify_source_files(
            session,
            list(by_file),
            before_action=(
                "replacing the original files"
                if replacing_originals
                else "creating redacted copies"
            ),
        )

        rendered: dict[Path, bytes] = {}
        source_contents: dict[str, bytes] = {}
        expected_existing_signatures: dict[Path, AtomicFileSignature] = {}
        for source_path, file_findings in by_file.items():
            output_path = (
                Path(_absolute_path_no_follow(source_path))
                if replacing_originals
                else _redacted_output_path_no_follow(source_path)
            )
            previous = session.generated_outputs.get(source_path)
            try:
                _assert_no_redirect_ancestors(output_path)
            except OSError as error:
                raise SessionProblem(
                    "file_changed" if replacing_originals else "output_conflict",
                    (
                        "An original file is no longer safe to replace."
                        if replacing_originals
                        else "A redacted-copy destination is no longer safe to use."
                    ),
                    409,
                ) from error
            if not replacing_originals and os.path.lexists(output_path):
                if (
                    previous is None
                    or Path(_absolute_path_no_follow(previous.output_path)) != output_path
                ):
                    raise SessionProblem(
                        "output_conflict",
                        "A redacted-copy destination already exists and was not created by "
                        "this scan.",
                        409,
                    )
                try:
                    output_signature = capture_file_signature(output_path)
                except (AtomicOutputChangedError, OSError) as error:
                    raise SessionProblem(
                        "output_conflict",
                        "An existing redacted-copy destination could not be verified before "
                        "regeneration.",
                        409,
                    ) from error
                try:
                    current_output = FileFingerprint.capture(str(output_path))
                except (OSError, SessionProblem) as error:
                    raise SessionProblem(
                        "output_conflict",
                        "An existing redacted-copy destination could not be verified before "
                        "regeneration.",
                        409,
                    ) from error
                if current_output != previous.output_fingerprint:
                    raise SessionProblem(
                        "output_conflict",
                        "A redacted copy changed outside RedactLens and will not be overwritten.",
                        409,
                    )
                expected_existing_signatures[output_path] = output_signature
            try:
                expected_source = session.file_fingerprints[source_path]
                source_bytes = _read_regular_bytes_no_follow(
                    source_path,
                    max_bytes=expected_source.size,
                    expected_fingerprint=expected_source,
                )
            except OSError as error:
                raise SessionProblem(
                    "file_changed",
                    "A source changed after the scan. Scan it again before creating outputs.",
                    409,
                ) from error
            if replacing_originals:
                expected_existing_signatures[output_path] = AtomicFileSignature(
                    device=expected_source.device,
                    inode=expected_source.inode,
                    size=expected_source.size,
                    modified_ns=expected_source.modified_ns,
                    changed_ns=expected_source.changed_ns,
                    sha256=expected_source.sha256,
                )
            try:
                contents = prepare_anonymized_file(
                    source_path,
                    file_findings,
                    source_bytes=source_bytes,
                )
                verify_anonymized_bytes(
                    source_path,
                    contents,
                    file_findings,
                    source_bytes=source_bytes,
                )
            except (DocumentChangedError, SourceChangedError) as error:
                raise SessionProblem(
                    "file_changed",
                    "A source changed after the scan. Scan it again before creating outputs.",
                    409,
                ) from error
            except ValueError as error:
                raise SessionProblem(
                    "verification_failed",
                    "RedactLens could not verify a selected source file.",
                    422,
                ) from error
            if output_path in rendered:
                raise SessionProblem(
                    "output_conflict",
                    "Two selected sources map to the same redacted-copy destination.",
                    409,
                )
            rendered[output_path] = contents
            source_contents[source_path] = source_bytes

        # Detect a source mutation that happened while outputs were rendered.
        verify_source_files(
            session,
            list(by_file),
            before_action=(
                "replacing the original files"
                if replacing_originals
                else "creating redacted copies"
            ),
        )

        output_fingerprints: dict[str, FileFingerprint] = {}

        def validate_committed_outputs() -> None:
            """Verify the actual final files while atomic backups still exist."""

            if not replacing_originals:
                verify_source_files(session, list(by_file))
            for source_path, file_findings in by_file.items():
                output_path = (
                    Path(_absolute_path_no_follow(source_path))
                    if replacing_originals
                    else _redacted_output_path_no_follow(source_path)
                )
                expected_contents = rendered[output_path]
                actual_contents = _read_regular_bytes_no_follow(output_path)
                if actual_contents != expected_contents:
                    raise ValueError(
                        f"committed output '{output_path.name}' differs from its verified render"
                    )
                verify_anonymized_bytes(
                    source_path,
                    actual_contents,
                    file_findings,
                    source_bytes=source_contents[source_path],
                )
                fingerprint = FileFingerprint.capture(str(output_path))
                if (
                    fingerprint.size != len(expected_contents)
                    or fingerprint.sha256 != hashlib.sha256(expected_contents).hexdigest()
                ):
                    raise ValueError(
                        f"committed output '{output_path.name}' changed during verification"
                    )
                output_fingerprints[source_path] = fingerprint

        try:
            try:
                write_many_bytes_atomically(
                    rendered,
                    expected_existing_signatures=expected_existing_signatures,
                    validate_committed=validate_committed_outputs,
                )
            except BaseException as error:
                _adopt_atomic_restoration_identities(session, error)
                raise
        except FileExistsError as error:
            raise SessionProblem(
                "file_changed" if replacing_originals else "output_conflict",
                (
                    "An original file changed during replacement; RedactLens did not replace "
                    "the files."
                    if replacing_originals
                    else "A proposed output appeared during generation; RedactLens did not "
                    "overwrite it."
                ),
                409,
            ) from error
        except AtomicCleanupError as error:
            retained = set(error.retained_artifacts)
            if isinstance(error.original_error, AtomicRollbackError):
                retained.update(error.original_error.recovery_backups.values())
            session.retained_remediation_artifacts.update(str(path) for path in retained)
            session.public_redactor = session.public_redactor.with_reserved_paths(
                str(path) for path in retained
            )
            session.estimated_bytes = _estimate_session_bytes(session)
            if not error.write_committed:
                _enforce_failed_workflow_capacity(session)
                recovery = (
                    " Recovery artifacts may remain in the source folder; review the "
                    "remediation panel."
                    if retained
                    else " No recovery artifact could be preserved."
                )
                raise SessionProblem(
                    "file_unavailable",
                    f"The {write_operation} failed and temporary artifact cleanup did not "
                    f"finish.{recovery}",
                    500,
                ) from error
        except AtomicRollbackError as error:
            session.retained_remediation_artifacts.update(
                str(path) for path in error.recovery_backups.values()
            )
            session.public_redactor = session.public_redactor.with_reserved_paths(
                [
                    *(str(path) for path in error.recovery_backups.values()),
                    *(str(path) for path in error.rollback_errors),
                ]
            )
            session.estimated_bytes = _estimate_session_bytes(session)
            _enforce_failed_workflow_capacity(session)
            retained_outputs = any(
                _filesystem_entry_may_exist(path) for path in error.rollback_errors
            )
            output_recovery = (
                " Outputs requiring manual review may remain in the source folder."
                if retained_outputs
                else ""
            )
            recovery = (
                " Recovery backups may remain in the source folder; review the remediation panel."
                if error.recovery_backups
                else " No recovery backup could be preserved."
            )
            raise SessionProblem(
                "file_unavailable",
                f"The {write_operation} failed and could not be fully rolled back."
                f"{output_recovery}{recovery}",
                500,
            ) from error
        except AtomicOutputChangedError as error:
            raise SessionProblem(
                "file_changed" if replacing_originals else "output_conflict",
                (
                    "An original file changed during replacement; RedactLens did not overwrite it."
                    if replacing_originals
                    else "A redacted-copy destination changed during generation; RedactLens "
                    "did not overwrite it."
                ),
                409,
            ) from error
        except OSError as error:
            raise SessionProblem(
                "file_unavailable",
                (
                    "Could not replace the original files. Check that they are closed and writable."
                    if replacing_originals
                    else "Could not create the redacted copies. Check the destination permissions."
                ),
                410,
            ) from error
        except (DocumentChangedError, SourceChangedError) as error:
            raise SessionProblem(
                "file_changed",
                "A source changed while outputs were being committed. Scan it again.",
                409,
            ) from error
        except ValueError as error:
            raise SessionProblem(
                "verification_failed",
                f"RedactLens could not verify the committed {output_label}.",
                422,
            ) from error

        session.retained_remediation_artifacts = {
            path
            for path in session.retained_remediation_artifacts
            if _filesystem_entry_may_exist(path)
        }
        cleanup_warnings = (
            [
                "Temporary remediation artifacts remain after verification. Delete them "
                "manually: " + ", ".join(sorted(session.retained_remediation_artifacts)) + "."
            ]
            if session.retained_remediation_artifacts
            else []
        )

        now = datetime.now(tz=UTC)
        details: list[GeneratedOutputDetails] = []
        generated_outputs: dict[str, GeneratedOutput] = {}
        for source_path, file_findings in by_file.items():
            output_path = (
                Path(_absolute_path_no_follow(source_path))
                if replacing_originals
                else _redacted_output_path_no_follow(source_path)
            )
            source_fingerprint = session.file_fingerprints[source_path]
            output_fingerprint = output_fingerprints[source_path]
            applied_ids = tuple(finding.id for finding in file_findings)
            warnings = [
                "Verification covers selected values only; it does not guarantee the file "
                "contains no other sensitive data.",
                *(
                    [
                        "The original file was replaced. Run a new scan before making "
                        "additional changes."
                    ]
                    if replacing_originals
                    else []
                ),
                *cleanup_warnings,
            ]
            rescan_status: Literal["completed", "failed"] = "completed"
            remaining_count: int | None = None
            remaining_tier_a_count: int | None = None
            try:
                rescan_request = _output_rescan_request(session, output_path)
                rescan = core_scan(
                    rescan_request,
                    load_default_registry(),
                )
                if not _output_rescan_completed(rescan, output_path):
                    raise _OutputRescanIncomplete
            except _OutputRescanScopeUnavailable:
                rescan_status = "failed"
                warnings.append(
                    "The optional output rescan could not reproduce the original AI or "
                    "description-target scope; remaining counts are unavailable."
                )
            except _OutputRescanIncomplete:
                rescan_status = "failed"
                warnings.append(
                    "The optional output rescan did not completely process the generated file; "
                    "remaining counts are unavailable."
                )
            except Exception:  # pragma: no cover - scanner is defensive by contract
                rescan_status = "failed"
                warnings.append(
                    "The optional output rescan could not finish; review the output manually."
                )
            else:
                remaining_count = len(rescan.findings)
                remaining_tier_a_count = sum(
                    1 for finding in rescan.findings if finding.tier == "A"
                )
                if remaining_count:
                    warnings.append(
                        f"The output rescan reported {remaining_count} remaining "
                        "finding(s) for review."
                    )
            generated = GeneratedOutput(
                output_path=str(output_path),
                finding_ids=applied_ids,
                created_at=now,
                verification_status="verified",
                warnings=tuple(warnings),
                source_fingerprint=source_fingerprint,
                output_fingerprint=output_fingerprint,
                rescan_status=rescan_status,
                remaining_finding_count=remaining_count,
                remaining_tier_a_count=remaining_tier_a_count,
            )
            generated_outputs[source_path] = generated
            details.append(
                _public_output(source_path, generated, _session_public_redactor(session))
            )
        session.generated_outputs.update(generated_outputs)
        response = RemediationGenerationResponse(plan=remediation_plan(session), outputs=details)
        session.refresh_retained_size()
    return response


def session_redacted_output_for_finding(session: ScanSession, finding_id: str) -> str:
    with session.workflow_lock:
        session.require_complete()
        finding = session.finding(finding_id)
        generated = session.generated_outputs.get(finding.file_path)
        selected_ids = tuple(
            candidate.id
            for candidate in session.internal_findings.values()
            if candidate.file_path == finding.file_path
            and session.remediation_states.get(candidate.id) == "included"
        )
        if generated is None or generated.finding_ids != selected_ids:
            raise SessionProblem(
                "invalid_remediation_plan",
                "Regenerate this redacted copy before showing it in its folder.",
                409,
            )
        try:
            current = FileFingerprint.capture(generated.output_path)
        except (OSError, SessionProblem) as error:
            raise SessionProblem(
                "file_unavailable",
                "The redacted copy is no longer available.",
                410,
            ) from error
        if current != generated.output_fingerprint:
            raise SessionProblem(
                "output_conflict",
                "The redacted copy changed outside RedactLens and will not be shown as verified.",
                409,
            )
        return generated.output_path


def _public_output(
    source_path: str,
    generated: GeneratedOutput,
    redactor: PublicRedactor,
) -> GeneratedOutputDetails:
    fingerprint = generated.source_fingerprint
    return GeneratedOutputDetails(
        source_path=redactor.path(source_path),
        output_path=redactor.path(generated.output_path),
        applied_finding_ids=list(generated.finding_ids),
        verification_status=generated.verification_status,
        warnings=[redactor.text(warning) for warning in generated.warnings],
        source_fingerprint=PublicFileFingerprint(
            resolved_path=redactor.path(fingerprint.resolved_path),
            size=fingerprint.size,
            modified_ns=fingerprint.modified_ns,
            sha256=fingerprint.sha256,
        ),
        rescan_status=generated.rescan_status,
        remaining_finding_count=generated.remaining_finding_count,
        remaining_tier_a_count=generated.remaining_tier_a_count,
    )


def session_file_for_finding(session: ScanSession, finding_id: str) -> str:
    with session.workflow_lock:
        session.require_complete()
        finding = session.finding(finding_id)
        verify_source_files(
            session,
            [finding.file_path],
            before_action="showing it in its folder",
        )
        return finding.file_path


_SESSION_CAPACITY_MESSAGE = "This scan is too large to retain safely for browser actions."


def _session_capacity_problem() -> SessionProblem:
    return SessionProblem("session_capacity", _SESSION_CAPACITY_MESSAGE, 503)


def _capacity_failure_result() -> ScanResult:
    return ScanResult(
        summary={
            "status": "failed",
            "incomplete": True,
            "completed_files": 0,
            "total_files": None,
        }
    )


def _strip_for_capacity_failure(session: ScanSession) -> None:
    """Drop variable workflow data before retaining a minimal capacity error."""
    with session.event_condition:
        session.request = None
        session.internal_findings.clear()
        session.file_fingerprints.clear()
        session.remediation_states.clear()
        session.remediation_revision = 0
        session.generated_outputs.clear()
        session.retained_remediation_artifacts.clear()
        session.public_redactor = PublicRedactor()
        session.public_live_paths.clear()
        session.events.clear()
        session.selected_roots = ()
        session.detector_count = 0
        session.ai_model = None
        session.rescan_categories = ()
        session.rescan_tier_threshold = DEFAULT_TIER_THRESHOLD
        session.rescan_options = ScanOptions()
        session.rescan_scope_requires_ai = False
        session.progress = PublicScanProgress(stage="failed")
        session.public_result = session.public_result.model_copy(
            update={
                "findings": [],
                "summary": {},
                "scanned_files": [],
                "skipped_files": [],
                "llm_used": False,
                "progress": session.progress,
                "metadata": PublicScanMetadata(),
            }
        )
        session.estimated_bytes = _estimate_session_bytes(session)


def _capture_result_fingerprints(
    result: ScanResult,
    initial_fingerprints: dict[str, FileFingerprint],
    checkpoint: Callable[[], None] | None = None,
) -> dict[str, FileFingerprint]:
    fingerprints: dict[str, FileFingerprint] = {}
    for file_path in result.scanned_files:
        if checkpoint is not None:
            checkpoint()
        try:
            current = FileFingerprint.capture(file_path, checkpoint=checkpoint)
        except SessionProblem:
            raise
        except OSError as error:
            raise SessionProblem(
                "file_unavailable",
                "A scanned source could not be retained for follow-up actions.",
                410,
            ) from error
        expected = initial_fingerprints.get(current.resolved_path)
        if expected != current:
            raise SessionProblem(
                "file_changed",
                "A source changed during the scan. Scan it again.",
                409,
            )
        fingerprints[file_path] = current
    return fingerprints


def _cancellation_checkpoint(
    session: ScanSession,
    *,
    deadline: float | None = None,
    partial_result: Callable[[], ScanResult] | None = None,
) -> Callable[[], None]:
    def current_partial(status: str) -> ScanResult:
        if partial_result is not None:
            result = partial_result()
            return result.model_copy(
                update={
                    "summary": {
                        **result.summary,
                        "status": status,
                        "incomplete": True,
                    }
                },
                deep=True,
            )
        return ScanResult(
            summary={
                "status": status,
                "incomplete": True,
                "completed_files": 0,
                "total_files": None,
            }
        )

    def checkpoint() -> None:
        if session.cancellation_requested():
            raise ScanCancelled(
                "Scan cancelled by request.",
                current_partial("cancelled"),
            )
        if deadline is not None and time.monotonic() >= deadline:
            raise ScanTimedOut(
                "Scan exceeded its whole-job time limit.",
                current_partial("timed_out"),
            )

    return checkpoint


def _positive_env_int(name: str, default: int) -> int:
    try:
        value = int(os.environ.get(name, str(default)))
    except ValueError:
        return default
    return value if value > 0 else default


def _positive_env_float(name: str, default: float) -> float:
    try:
        value = float(os.environ.get(name, str(default)))
    except ValueError:
        return default
    return value if value > 0 else default
