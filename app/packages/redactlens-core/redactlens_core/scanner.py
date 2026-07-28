"""Bounded, deterministic scan orchestration with isolated file failures."""

from __future__ import annotations

import threading
import time
from collections import Counter
from collections.abc import Callable, Iterable
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path

from redactlens_core.consolidation import (
    ConsolidationResult,
    ScoredDetection,
    consolidate_detection_groups,
)
from redactlens_core.files import (
    DiscoveredFile,
    FileIssue,
    FileSnapshot,
    Scannable,
    StreamFileChanged,
    StreamFileTooLarge,
    StreamReadStats,
    TextChunk,
    discover_files,
    is_structured_document,
    iter_text_chunks,
    probe_text_file,
    read_scannable_detailed,
)
from redactlens_core.llm.adapter import DEFAULT_MODEL, OllamaAdapter
from redactlens_core.methods import MatchCandidate, entropy, keyword, regex
from redactlens_core.models import (
    Finding,
    RawDetectorOpinion,
    ScanRequest,
    ScanResult,
    SkippedFile,
)
from redactlens_core.progress import (
    ScanCancelled,
    ScanEvent,
    ScanExecution,
    ScanTimedOut,
    _CancellationRequested,
    _DeadlineExceeded,
)
from redactlens_core.registry import DetectorDef, DetectorRegistry
from redactlens_core.scan_results import (
    _finding_sort_key,
    _path_sort_key,
    _raw_detector_opinions,
    _result,
    _skipped_file,
)
from redactlens_core.scanner_consolidation import (
    MAX_DESCRIPTION_CONFIRMATION_CANDIDATES as MAX_DESCRIPTION_CONFIRMATION_CANDIDATES,
)
from redactlens_core.scanner_consolidation import (
    _project_detection_groups,
)
from redactlens_core.scanner_detection import _build_detection
from redactlens_core.scanner_refinement import (
    _clear_file_outcome,
    _prepare_work,
    _refine_file,
)
from redactlens_core.scanner_support import (
    _CandidateBudget,
    _clear_exception_tracebacks,
    _ConfiguredDetector,
    _DescriptionLineAccumulator,
    _DetectionProjection,
    _DetectionWork,
    _FileDetectionLimitExceeded,
    _FileOutcome,
    _PreparedDescriptionLine,
    _PreparedDetection,
    _RefinementOutcome,
    _RefinementPlan,
    _release_detection_projection,
    _ScanMetrics,
    _StreamingExtractionTimedOut,
    _TimedSerialAdapter,
)
from redactlens_core.scoring import DEFAULT_CONTEXT_WINDOW
from redactlens_core.user_targets import user_target_detectors

MAX_FILE_DETECTION_CANDIDATES = 100_000
MAX_WINDOW_DETECTION_CANDIDATES = 100_000


def _consolidate_requested_detections(
    detections: list[ScoredDetection],
    *,
    checkpoint: Callable[[], None] | None = None,
) -> _DetectionProjection:
    """Consolidate every opinion, then publish only request-eligible groups."""
    groups = consolidate_detection_groups(detections, checkpoint=checkpoint)
    return _project_detection_groups(groups, checkpoint=checkpoint)


def _configured_match_length(configured: _ConfiguredDetector) -> int:
    """Return the detector's validated bound used for matching and chunk overlap."""
    return configured.detector.max_match_length


def _configured_streaming_extent(configured: _ConfiguredDetector) -> int:
    """Return the matched span plus the declared external regex dependency."""

    detector = configured.detector
    return detector.max_match_length + detector.max_lookaround_length


def scan(
    request: ScanRequest,
    registry: DetectorRegistry,
    llm_adapter: OllamaAdapter | None = None,
    *,
    execution: ScanExecution | None = None,
    capture_raw_detector_opinions: bool = False,
) -> ScanResult:
    """Run one resource-bounded scan while preserving stable result ordering."""
    control = execution or ScanExecution()
    control.start()
    started_at = time.perf_counter()
    options = request.options
    description_targets = tuple(
        target for target in request.user_targets if target.kind == "description"
    )
    built_in_detectors = registry.get_all()
    selected_builtins = registry.get_by_categories(request.categories)
    selected_builtin_object_ids = {id(detector) for detector in selected_builtins}
    literal_detectors = user_target_detectors(request.user_targets)
    scanned_files: list[str] = []
    skipped_files: list[SkippedFile] = []
    findings: list[Finding] = []
    raw_detection_count = 0
    consolidated_detection_count = 0
    suppressed_detection_count = 0
    raw_detector_hits_by_detector: Counter[str] = Counter()
    raw_detector_opinions: list[RawDetectorOpinion] | None = (
        [] if capture_raw_detector_opinions else None
    )
    completed_files = 0
    total_files: int | None = None
    current_file: str | None = None
    metrics = _ScanMetrics()
    timed_adapter: _TimedSerialAdapter | None = None

    def emit(event_type: str, stage: str, **updates: object) -> None:
        control.emit(
            ScanEvent(
                type=event_type,
                stage=stage,
                file_path=current_file,
                completed_files=completed_files,
                total_files=total_files,
                findings_so_far=len(findings),
                skipped_files=len(skipped_files),
                **updates,
            )
        )

    def publish_heuristic_findings(batch: list[Finding]) -> None:
        finding: Finding | None = None
        try:
            for finding in batch:
                findings.append(finding)
                emit("finding_added", "consolidation", finding=finding)
        finally:
            finding = None

    def publish_refined_findings(
        file_start: int,
        heuristic: ConsolidationResult,
        refined: ConsolidationResult,
    ) -> None:
        old_by_id = {finding.id: finding for finding in heuristic.findings}
        positions_by_id = {
            finding.id: index
            for index, finding in enumerate(findings[file_start:], start=file_start)
        }
        finding: Finding | None = None
        prior: Finding | None = None
        try:
            for finding in refined.findings:
                prior = old_by_id.get(finding.id)
                if prior is None:
                    positions_by_id[finding.id] = len(findings)
                    findings.append(finding)
                    emit("finding_added", "ai_refinement", finding=finding)
                    continue

                position = positions_by_id[finding.id]
                findings[position] = finding
                if prior.model_dump() != finding.model_dump():
                    emit("finding_updated", "ai_refinement", finding=finding)

            # Restore the exact deterministic file-local ordering after every
            # observable change has been incorporated one at a time.
            findings[file_start:] = refined.findings
        finally:
            old_by_id.clear()
            positions_by_id.clear()
            finding = None
            prior = None

    def partial_result(status: str) -> ScanResult:
        return _result(
            findings,
            scanned_files,
            skipped_files,
            raw_detection_count,
            consolidated_detection_count,
            suppressed_detection_count,
            # Availability is not use.  A clean scan can have a reachable
            # adapter without ever crossing the model boundary, so only
            # report AI use after at least one recorded inference attempt.
            llm_used=timed_adapter is not None and timed_adapter.attempts > 0,
            status=status,
            completed_files=completed_files,
            total_files=total_files,
            duration_seconds=time.perf_counter() - started_at,
            metrics=metrics,
            llm_seconds=timed_adapter.elapsed_seconds if timed_adapter is not None else 0.0,
            llm_attempts=timed_adapter.attempts if timed_adapter is not None else 0,
            llm_successes=timed_adapter.successes if timed_adapter is not None else 0,
            llm_failures=timed_adapter.failures if timed_adapter is not None else 0,
            raw_detector_hits_by_detector=raw_detector_hits_by_detector,
            raw_detector_opinions=raw_detector_opinions,
        )

    executor: ThreadPoolExecutor | None = None
    pending: dict[int, Future[_FileOutcome]] = {}
    executor_shutdown = False

    def shutdown_executor() -> None:
        nonlocal executor_shutdown
        if executor is None or executor_shutdown:
            return
        executor_shutdown = True
        for future in pending.values():
            future.add_done_callback(_clear_file_outcome)
        # Cancel work that has not started, but retain ownership of every
        # already-running file task until it actually returns. Letting an
        # interrupted coordinator exit with wait=False would release the
        # API's registered top-level worker slot while a nested
        # ``redactlens-file`` thread could still be blocked, allowing repeated
        # replacement scans to escape the live-worker bound.
        executor.shutdown(wait=True, cancel_futures=True)

    try:
        emit("scan_started", "discovery")
        discovered: list[DiscoveredFile] = []
        for entry in discover_files(
            request.paths,
            options,
            checkpoint=control.checkpoint,
        ):
            control.checkpoint()
            discovered.append(entry)
        total_files = len(discovered)
        emit("discovery_complete", "discovery")

        active_adapter: _TimedSerialAdapter | None = None
        if request.use_llm:
            control.checkpoint()
            adapter = llm_adapter or OllamaAdapter(
                model=request.ollama_model or DEFAULT_MODEL,
                timeout=options.ai_timeout_seconds,
            )
            if adapter.available():
                timed_adapter = _TimedSerialAdapter(adapter, control)
                active_adapter = timed_adapter

        needs_detection_context = bool(
            selected_builtins
            or literal_detectors
            or (description_targets and active_adapter is not None)
        )
        # Hidden built-ins must still run at their full validated bounds. Arbitrary
        # same-span hits and transitive suppression chains cannot be inferred from
        # registry metadata alone without changing the canonical group. Because
        # each configured opinion can therefore affect visibility, every one is
        # classification-essential and fails the file closed on a safety error.
        detectors = [
            _ConfiguredDetector(
                detector=detector,
                origin="built_in",
                category_selected=id(detector) in selected_builtin_object_ids,
                required=True,
            )
            for detector in built_in_detectors
            if needs_detection_context
        ]
        detectors.extend(
            _ConfiguredDetector(
                detector=detector,
                origin="user_target",
                category_selected=True,
                required=True,
            )
            for detector in literal_detectors
        )

        document_gate = threading.Semaphore(options.document_workers)
        executor = ThreadPoolExecutor(
            max_workers=options.max_workers,
            thread_name_prefix="redactlens-file",
        )
        submit_cursor = 0
        ai_announced = False

        def fill_pending() -> None:
            nonlocal current_file, submit_cursor
            while submit_cursor < len(discovered) and len(pending) < options.max_workers:
                control.checkpoint()
                entry = discovered[submit_cursor]
                index = submit_cursor
                submit_cursor += 1
                if entry.issue is not None:
                    continue
                current_file = entry.path
                emit("file_started", "extraction")

                # The sink can synchronously accept a cancellation request or
                # advance a test/host clock across the deadline. Never submit
                # the file announced by that event until the new state is
                # observed.
                def submit_entry(file_path: str = entry.path) -> Future[_FileOutcome]:
                    return executor.submit(
                        _run_file_task,
                        file_path,
                        detectors,
                        description_targets,
                        request,
                        active_adapter,
                        control,
                        document_gate,
                        capture_raw_detector_opinions,
                    )

                pending[index] = control.admit(submit_entry)

        fill_pending()
        for index, entry in enumerate(discovered):
            control.checkpoint()
            current_file = entry.path
            if entry.issue is not None:
                skipped = _skipped_file(entry.path, entry.issue)
                skipped_files.append(skipped)
                completed_files += 1
                emit("file_skipped", entry.issue.stage, skipped_file=skipped)
                fill_pending()
                continue

            future = pending.pop(index)
            try:
                outcome = future.result()
            except BaseException as error:
                _clear_exception_tracebacks(error)
                raise
            finally:
                future = None
            try:
                # A file future can finish after cancellation was requested.
                # Check before publishing or beginning any queued refinement.
                control.checkpoint()
                metrics.bytes_scanned += outcome.bytes_scanned
                metrics.extraction_seconds += outcome.extraction_seconds
                metrics.detection_seconds += outcome.detection_seconds
                if outcome.issue is not None or outcome.heuristic is None:
                    issue = outcome.issue or FileIssue(
                        "unreadable_file", "extraction", "file could not be scanned"
                    )
                    skipped = _skipped_file(entry.path, issue)
                    skipped_files.append(skipped)
                    completed_files += 1
                    emit("file_skipped", issue.stage, skipped_file=skipped)
                else:
                    scanned_files.append(entry.path)
                    heuristic = outcome.heuristic
                    heuristic_counts = Counter(dict(outcome.raw_detector_hits_by_detector))
                    raw_detector_hits_by_detector.update(heuristic_counts)
                    opinion_start = (
                        len(raw_detector_opinions) if raw_detector_opinions is not None else None
                    )
                    if raw_detector_opinions is not None:
                        if outcome.raw_detector_opinions is None:
                            raise RuntimeError("captured detector opinion geometry is missing")
                        raw_detector_opinions.extend(outcome.raw_detector_opinions)
                    file_start = len(findings)
                    raw_detection_count += heuristic.raw_detection_count
                    consolidated_detection_count += heuristic.consolidated_detection_count
                    suppressed_detection_count += heuristic.suppressed_detection_count
                    publish_heuristic_findings(heuristic.findings)

                    if outcome.refinement is not None and active_adapter is not None:
                        refined_outcome: _RefinementOutcome | None = None
                        control.checkpoint()
                        if not ai_announced:
                            # This event is immediately adjacent to the first
                            # refinement call, after heuristic findings are
                            # already observable.
                            emit("ai_refinement_started", "ai_refinement")
                            ai_announced = True
                        try:
                            refined_outcome = _refine_file(
                                outcome.refinement,
                                heuristic,
                                description_targets,
                                request.tier_threshold,
                                active_adapter,
                                control,
                                capture_raw_detector_opinions,
                            )
                            control.checkpoint()
                            metrics.detection_seconds += refined_outcome.detection_seconds
                            refined = refined_outcome.result
                            refined_counts = Counter(
                                dict(refined_outcome.raw_detector_hits_by_detector)
                            )
                            raw_detector_hits_by_detector.subtract(heuristic_counts)
                            raw_detector_hits_by_detector.update(refined_counts)
                            raw_detector_hits_by_detector += Counter()
                            if raw_detector_opinions is not None:
                                if (
                                    opinion_start is None
                                    or refined_outcome.raw_detector_opinions is None
                                ):
                                    raise RuntimeError(
                                        "refined detector opinion geometry is missing"
                                    )
                                raw_detector_opinions[opinion_start:] = (
                                    refined_outcome.raw_detector_opinions
                                )
                            raw_detection_count += (
                                refined.raw_detection_count - heuristic.raw_detection_count
                            )
                            consolidated_detection_count += (
                                refined.consolidated_detection_count
                                - heuristic.consolidated_detection_count
                            )
                            suppressed_detection_count += (
                                refined.suppressed_detection_count
                                - heuristic.suppressed_detection_count
                            )
                            publish_refined_findings(file_start, heuristic, refined)
                        finally:
                            if refined_outcome is not None:
                                refined_outcome.clear_sensitive()

                    control.checkpoint()
                    completed_files += 1
                    emit("file_completed", "detection")
            finally:
                outcome.clear_sensitive()

            # Do not refill until the just-consumed refinement plan has been
            # cleared. Completed/running futures plus the current file are
            # therefore bounded by max_workers sensitive contexts.
            control.checkpoint()
            fill_pending()

        control.checkpoint()
        current_file = None
        emit("scan_finalizing", "finalizing")
        control.checkpoint()
        findings.sort(key=_finding_sort_key)
        scanned_files.sort(key=_path_sort_key)
        skipped_files.sort(key=lambda item: (_path_sort_key(item.path), item.code, item.reason))
        control.checkpoint()
        emit("scan_completed", "complete")
        return partial_result("complete")
    except _CancellationRequested as interruption:
        result = partial_result("cancelled")
        # A terminal event means all backend work for this scan has stopped.
        # Drain already-running file tasks before announcing that transition.
        shutdown_executor()
        emit("scan_cancelled", "cancelled", message="Scan cancelled by request.")
        _clear_exception_tracebacks(interruption)
        raise ScanCancelled("Scan cancelled by request.", result) from None
    except _DeadlineExceeded as interruption:
        result = partial_result("timed_out")
        shutdown_executor()
        emit("scan_failed", "timed_out", message="Scan exceeded the configured time limit.")
        _clear_exception_tracebacks(interruption)
        raise ScanTimedOut("Scan exceeded the configured time limit.", result) from None
    finally:
        shutdown_executor()


def _run_file_task(
    file_path: str,
    detectors: list[_ConfiguredDetector],
    description_targets: tuple,
    request: ScanRequest,
    active_adapter: _TimedSerialAdapter | None,
    control: ScanExecution,
    document_gate: threading.Semaphore,
    capture_raw_detector_opinions: bool,
) -> _FileOutcome:
    """Recheck interruption when a queued task actually acquires a worker."""

    control.checkpoint()
    return _process_file(
        file_path,
        detectors,
        description_targets,
        request,
        active_adapter,
        control,
        document_gate,
        capture_raw_detector_opinions,
    )


def _process_file(
    file_path: str,
    detectors: list[_ConfiguredDetector],
    description_targets: tuple,
    request: ScanRequest,
    active_adapter: _TimedSerialAdapter | None,
    control: ScanExecution,
    document_gate: threading.Semaphore,
    capture_raw_detector_opinions: bool,
) -> _FileOutcome:
    options = request.options
    processing_stage = "extraction"
    detection_budget = _CandidateBudget(MAX_FILE_DETECTION_CANDIDATES)
    try:
        try:
            size = Path(file_path).stat().st_size
        except OSError:
            size = 0
        extraction_started = control.clock()
        extraction_perf = time.perf_counter()

        if is_structured_document(file_path):
            with document_gate:
                scannable, issue = read_scannable_detailed(
                    file_path,
                    options.max_file_size,
                    control.checkpoint,
                    max_structured_size=options.max_structured_file_size,
                    archive_depth=options.archive_depth,
                    extraction_timed_out=lambda: control.extraction_timed_out(extraction_started),
                )
            extraction_seconds = time.perf_counter() - extraction_perf
            processing_stage = "detection"
            return _materialized_outcome(
                file_path,
                scannable,
                issue,
                size,
                extraction_started,
                extraction_seconds,
                detectors,
                description_targets,
                request,
                active_adapter,
                control,
                detection_budget,
                capture_raw_detector_opinions,
            )

        if size <= options.chunk_size:
            scannable, issue = read_scannable_detailed(
                file_path,
                max_size=options.max_file_size,
                checkpoint=control.checkpoint,
                max_structured_size=options.max_structured_file_size,
                archive_depth=options.archive_depth,
                extraction_timed_out=lambda: control.extraction_timed_out(extraction_started),
            )
            extraction_seconds = time.perf_counter() - extraction_perf
            processing_stage = "detection"
            return _materialized_outcome(
                file_path,
                scannable,
                issue,
                size,
                extraction_started,
                extraction_seconds,
                detectors,
                description_targets,
                request,
                active_adapter,
                control,
                detection_budget,
                capture_raw_detector_opinions,
            )

        probe = probe_text_file(
            file_path,
            max_size=options.max_file_size,
            checkpoint=control.checkpoint,
            extraction_timed_out=lambda: control.extraction_timed_out(extraction_started),
        )
        codec, measured_size, issue = probe
        extraction_seconds = time.perf_counter() - extraction_perf
        if control.extraction_timed_out(extraction_started):
            issue = FileIssue(
                "extraction_timeout",
                "extraction",
                "text extraction exceeded the configured time limit",
            )
        if issue is not None or codec is None:
            return _FileOutcome(
                file_path,
                issue=issue or FileIssue("unsupported_encoding", "extraction", "unreadable file"),
                extraction_seconds=extraction_seconds,
            )
        processing_stage = "detection"
        return _chunked_outcome(
            file_path,
            codec,
            measured_size,
            probe.snapshot,
            extraction_started,
            extraction_seconds,
            detectors,
            description_targets,
            request,
            active_adapter,
            control,
            detection_budget,
            capture_raw_detector_opinions,
        )
    except (_CancellationRequested, _DeadlineExceeded):
        raise
    except regex.RegexSafetyError as error:
        return _FileOutcome(
            file_path,
            issue=FileIssue(error.code, "detection", error.reason),
        )
    except _FileDetectionLimitExceeded as error:
        return _FileOutcome(
            file_path,
            issue=FileIssue(error.code, "detection", error.reason),
        )
    except Exception as error:
        return _FileOutcome(
            file_path,
            issue=FileIssue(
                "file_processing_failed",
                processing_stage,
                f"file failed in isolation during scanning ({type(error).__name__})",
            ),
        )


def _materialized_outcome(
    file_path: str,
    scannable: Scannable | None,
    issue: FileIssue | None,
    size: int,
    extraction_started: float,
    extraction_seconds: float,
    detectors: list[_ConfiguredDetector],
    description_targets: tuple,
    request: ScanRequest,
    active_adapter: _TimedSerialAdapter | None,
    control: ScanExecution,
    detection_budget: _CandidateBudget,
    capture_raw_detector_opinions: bool,
) -> _FileOutcome:
    if scannable is not None and control.extraction_timed_out(extraction_started):
        scannable = None
        issue = FileIssue(
            "extraction_timeout",
            "extraction",
            "text extraction exceeded the configured time limit",
        )
    if issue is not None or scannable is None:
        return _FileOutcome(
            file_path,
            issue=issue or FileIssue("unreadable_file", "extraction", "unreadable file"),
            extraction_seconds=extraction_seconds,
        )

    detection_started = time.perf_counter()
    work: list[_DetectionWork] = []
    heuristic_detections: list[ScoredDetection] = []
    prepared: list[_PreparedDetection] = []
    description_lines: list[_PreparedDescriptionLine] = []
    retained_plan = False
    collector: _DescriptionLineAccumulator | None = None
    projection: _DetectionProjection | None = None
    outcome: _FileOutcome | None = None
    refinement: _RefinementPlan | None = None
    try:
        work = _find_work(
            detectors,
            scannable.text,
            control,
            detection_budget=detection_budget,
        )
        if active_adapter is None:
            heuristic_detections = _score_work(
                work, scannable, file_path, request.tier_threshold, None, control
            )
        else:
            prepared = _prepare_work(
                work,
                scannable,
                file_path,
                request.tier_threshold,
                control,
            )
            heuristic_detections = [item.detection for item in prepared]
            if description_targets:
                collector = _DescriptionLineAccumulator(control, scannable.location_at)
                description_lines.extend(collector.feed(scannable.text))
                description_lines.extend(collector.finish())

        projection = _consolidate_requested_detections(
            heuristic_detections,
            checkpoint=control.checkpoint,
        )
        heuristic = projection.result
        raw_counts = projection.raw_detector_hits_by_detector
        retained_detection_ids = {id(detection) for detection in projection.retained_detections}
        if description_lines:
            prepared[:] = [
                (
                    item
                    if id(item.detection) in retained_detection_ids
                    else replace(item, prompt=None)
                )
                for item in prepared
            ]
        else:
            prepared[:] = [
                item for item in prepared if id(item.detection) in retained_detection_ids
            ]
        if active_adapter is not None and (
            any(item.prompt is not None for item in prepared) or description_lines
        ):
            refinement = _RefinementPlan(
                file_path=file_path,
                detections=prepared,
                description_lines=description_lines,
                can_anonymize=scannable.can_anonymize,
            )
        outcome = _FileOutcome(
            file_path,
            heuristic=heuristic,
            refinement=refinement,
            bytes_scanned=size,
            extraction_seconds=extraction_seconds,
            detection_seconds=time.perf_counter() - detection_started,
            raw_detector_hits_by_detector=raw_counts,
            raw_detector_opinions=(
                _raw_detector_opinions(projection.retained_detections)
                if capture_raw_detector_opinions
                else None
            ),
        )
        retained_plan = refinement is not None
        return outcome
    finally:
        work.clear()
        heuristic_detections.clear()
        scannable.text = ""
        if collector is not None:
            collector.clear()
        _release_detection_projection(projection, clear_findings=outcome is None)
        if not retained_plan:
            if refinement is not None:
                refinement.clear()
            else:
                prepared.clear()
                description_lines.clear()


def _chunked_outcome(
    file_path: str,
    codec,
    expected_size: int,
    expected_snapshot: FileSnapshot | None,
    extraction_started: float,
    extraction_seconds: float,
    detectors: list[_ConfiguredDetector],
    description_targets: tuple,
    request: ScanRequest,
    active_adapter: _TimedSerialAdapter | None,
    control: ScanExecution,
    detection_budget: _CandidateBudget,
    capture_raw_detector_opinions: bool,
) -> _FileOutcome:
    detection_seconds = 0.0
    heuristic_detections: list[ScoredDetection] = []
    prepared: list[_PreparedDetection] = []
    description_lines: list[_PreparedDescriptionLine] = []
    seen: set[tuple[int, int, int]] = set()
    failed_optional_detectors: set[int] = set()
    stream_stats = StreamReadStats()
    description_accumulator = (
        _DescriptionLineAccumulator(control)
        if active_adapter is not None and description_targets
        else None
    )
    maximum_streaming_extent = max(
        (_configured_streaming_extent(configured) for configured in detectors),
        default=1,
    )
    overlap = maximum_streaming_extent + DEFAULT_CONTEXT_WINDOW + 1
    # A smaller owned core repeats the same large overlap across too many
    # windows (for example a 64 KiB request beside a 1 MiB private-key bound).
    # Keeping the core at least as large as the overlap preserves exact spans
    # while bounding total streamed detector input to a small multiple of the
    # source size.
    stream_chunk_size = max(request.options.chunk_size, overlap)
    retained_plan = False
    iterator = None
    projection: _DetectionProjection | None = None
    outcome: _FileOutcome | None = None
    refinement: _RefinementPlan | None = None
    extraction_budget_elapsed = max(0.0, control.clock() - extraction_started)
    active_read_started: float | None = None

    def extraction_budget_exhausted(elapsed: float) -> bool:
        return (
            control.extraction_timeout_seconds is not None
            and elapsed >= control.extraction_timeout_seconds
        )

    def streaming_checkpoint() -> None:
        control.checkpoint()
        if active_read_started is None:
            return
        active_elapsed = max(0.0, control.clock() - active_read_started)
        if extraction_budget_exhausted(extraction_budget_elapsed + active_elapsed):
            raise _StreamingExtractionTimedOut

    def next_chunk():
        nonlocal active_read_started, extraction_budget_elapsed, extraction_seconds
        assert iterator is not None
        active_read_started = control.clock()
        read_started = time.perf_counter()
        try:
            return next(iterator)
        finally:
            extraction_seconds += time.perf_counter() - read_started
            extraction_budget_elapsed += max(0.0, control.clock() - active_read_started)
            active_read_started = None

    try:
        iterator = iter_text_chunks(
            file_path,
            codec,
            chunk_size=stream_chunk_size,
            overlap=overlap,
            max_size=request.options.max_file_size,
            expected_size=expected_size,
            expected_snapshot=expected_snapshot,
            checkpoint=streaming_checkpoint,
            stats=stream_stats,
        )
        while True:
            try:
                chunk = next_chunk()
            except StopIteration:
                break
            if extraction_budget_exhausted(extraction_budget_elapsed):
                raise _StreamingExtractionTimedOut

            chunk_detection_started = time.perf_counter()
            scannable = Scannable(chunk.text)
            work: list[_DetectionWork] = []
            unique_work: list[_DetectionWork] = []
            try:
                work = _find_work(
                    detectors,
                    chunk.text,
                    control,
                    owned_start=chunk.owned_start,
                    owned_end=chunk.owned_end,
                    failed_optional_detectors=failed_optional_detectors,
                    detection_budget=detection_budget,
                )
                for item in work:
                    key = (
                        id(item.detector),
                        chunk.start_offset + item.candidate.start,
                        chunk.start_offset + item.candidate.end,
                    )
                    if key not in seen:
                        seen.add(key)
                        unique_work.append(item)
                if active_adapter is None:
                    heuristic_detections.extend(
                        _score_work(
                            unique_work,
                            scannable,
                            file_path,
                            request.tier_threshold,
                            None,
                            control,
                            chunk=chunk,
                            failed_optional_detectors=failed_optional_detectors,
                        )
                    )
                else:
                    chunk_prepared = _prepare_work(
                        unique_work,
                        scannable,
                        file_path,
                        request.tier_threshold,
                        control,
                        chunk=chunk,
                        failed_optional_detectors=failed_optional_detectors,
                    )
                    prepared.extend(chunk_prepared)
                    heuristic_detections.extend(item.detection for item in chunk_prepared)
                    if description_accumulator is not None:
                        description_lines.extend(
                            description_accumulator.feed(
                                chunk.text[chunk.owned_start : chunk.owned_end]
                            )
                        )
                if failed_optional_detectors:
                    heuristic_detections[:] = [
                        detection
                        for detection in heuristic_detections
                        if id(detection.detector) not in failed_optional_detectors
                    ]
                    prepared[:] = [
                        item
                        for item in prepared
                        if id(item.detection.detector) not in failed_optional_detectors
                    ]
            finally:
                work.clear()
                unique_work.clear()
                scannable.text = ""
                detection_seconds += time.perf_counter() - chunk_detection_started

        final_detection_started = time.perf_counter()
        if description_accumulator is not None:
            description_lines.extend(description_accumulator.finish())

        projection = _consolidate_requested_detections(
            heuristic_detections,
            checkpoint=control.checkpoint,
        )
        heuristic = projection.result
        raw_counts = projection.raw_detector_hits_by_detector
        retained_detection_ids = {id(detection) for detection in projection.retained_detections}
        if description_lines:
            prepared[:] = [
                (
                    item
                    if id(item.detection) in retained_detection_ids
                    else replace(item, prompt=None)
                )
                for item in prepared
            ]
        else:
            prepared[:] = [
                item for item in prepared if id(item.detection) in retained_detection_ids
            ]
        if active_adapter is not None and (
            any(item.prompt is not None for item in prepared) or description_lines
        ):
            refinement = _RefinementPlan(
                file_path=file_path,
                detections=prepared,
                description_lines=description_lines,
                can_anonymize=True,
            )
        detection_seconds += time.perf_counter() - final_detection_started
        outcome = _FileOutcome(
            file_path,
            heuristic=heuristic,
            refinement=refinement,
            bytes_scanned=stream_stats.bytes_read,
            extraction_seconds=extraction_seconds,
            detection_seconds=detection_seconds,
            raw_detector_hits_by_detector=raw_counts,
            raw_detector_opinions=(
                _raw_detector_opinions(projection.retained_detections)
                if capture_raw_detector_opinions
                else None
            ),
        )
        retained_plan = refinement is not None
        return outcome
    except StreamFileTooLarge as error:
        observed = (
            f"{error.observed_size} > {error.max_size}"
            if error.observed_size is not None
            else f"> {error.max_size}"
        )
        return _FileOutcome(
            file_path,
            issue=FileIssue(
                "file_too_large",
                "extraction",
                f"file exceeds max scan size ({observed} bytes)",
            ),
            extraction_seconds=extraction_seconds,
            detection_seconds=detection_seconds,
        )
    except _StreamingExtractionTimedOut:
        return _FileOutcome(
            file_path,
            issue=FileIssue(
                "extraction_timeout",
                "extraction",
                "text extraction exceeded the configured time limit",
            ),
            extraction_seconds=extraction_seconds,
            detection_seconds=detection_seconds,
        )
    except StreamFileChanged:
        return _FileOutcome(
            file_path,
            issue=FileIssue(
                "read_failed",
                "extraction",
                "file changed while it was being scanned",
            ),
            extraction_seconds=extraction_seconds,
            detection_seconds=detection_seconds,
        )
    except UnicodeDecodeError:
        return _FileOutcome(
            file_path,
            issue=FileIssue(
                "invalid_encoding",
                "extraction",
                "file encoding changed while it was being scanned",
            ),
            extraction_seconds=extraction_seconds,
            detection_seconds=detection_seconds,
        )
    except OSError:
        return _FileOutcome(
            file_path,
            issue=FileIssue("read_failed", "extraction", "file could not be read"),
            extraction_seconds=extraction_seconds,
            detection_seconds=detection_seconds,
        )
    finally:
        if iterator is not None:
            iterator.close()
        seen.clear()
        heuristic_detections.clear()
        if description_accumulator is not None:
            description_accumulator.clear()
        _release_detection_projection(projection, clear_findings=outcome is None)
        if not retained_plan:
            if refinement is not None:
                refinement.clear()
            else:
                prepared.clear()
                description_lines.clear()


def _find_work(
    detectors: list[_ConfiguredDetector],
    text: str,
    control: ScanExecution,
    *,
    owned_start: int = 0,
    owned_end: int | None = None,
    failed_optional_detectors: set[int] | None = None,
    detection_budget: _CandidateBudget,
) -> list[_DetectionWork]:
    work: list[_DetectionWork] = []
    window_budget = _CandidateBudget(MAX_WINDOW_DETECTION_CANDIDATES)
    failed_detectors = failed_optional_detectors if failed_optional_detectors is not None else set()
    end = len(text) if owned_end is None else owned_end
    for configured in detectors:
        control.checkpoint()
        detector = configured.detector
        detector_object_id = id(detector)
        if detector_object_id in failed_detectors:
            continue
        detector_work_start = len(work)
        try:
            for candidate in _find_candidates(
                detector,
                text,
                max_matches=window_budget.remaining + 1,
            ):
                window_budget.consume()
                control.checkpoint()
                if not (owned_start <= candidate.start < end):
                    continue
                if candidate.end - candidate.start > _configured_match_length(configured):
                    continue
                detection_budget.consume()
                work.append(
                    _DetectionWork(
                        detector,
                        candidate,
                        configured.origin,
                        configured.category_selected,
                        configured.required,
                    )
                )
        except regex.RegexSafetyError:
            del work[detector_work_start:]
            if configured.required:
                raise
            failed_detectors.add(detector_object_id)
    return work


def _score_work(
    work: list[_DetectionWork],
    scannable: Scannable,
    file_path: str,
    tier_threshold: float,
    llm_adapter,
    control: ScanExecution,
    *,
    chunk: TextChunk | None = None,
    failed_optional_detectors: set[int] | None = None,
) -> list[ScoredDetection]:
    detections: list[ScoredDetection] = []
    failed_detectors = failed_optional_detectors if failed_optional_detectors is not None else set()
    for item in work:
        control.checkpoint()
        detector_object_id = id(item.detector)
        if detector_object_id in failed_detectors:
            continue
        try:
            detection = _build_detection(
                item.detector,
                item.candidate,
                scannable,
                file_path,
                tier_threshold,
                llm_adapter,
                origin=item.origin,
                category_selected=item.category_selected,
                chunk=chunk,
            )
        except regex.RegexSafetyError:
            if item.required:
                raise
            failed_detectors.add(detector_object_id)
            detections[:] = [prior for prior in detections if prior.detector is not item.detector]
            continue
        detections.append(detection)
    control.checkpoint()
    return detections


def _find_candidates(
    detector: DetectorDef,
    text: str,
    *,
    max_matches: int | None = None,
) -> Iterable[MatchCandidate]:
    if detector.method == "regex":
        return regex.find_matches(detector.pattern, text, max_matches=max_matches)
    if detector.method == "keyword":
        return keyword.find_matches(detector.pattern, text)
    if detector.method == "entropy":
        return entropy.find_matches(
            detector.pattern,
            text,
            detector.entropy_threshold,
            max_matches=max_matches,
        )
    raise NotImplementedError(f"detector method '{detector.method}' is not implemented yet")
