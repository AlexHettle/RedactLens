"""Deferred local-model refinement for completed file scans."""

from __future__ import annotations

import time
from concurrent.futures import Future
from dataclasses import replace

from redactlens_core.consolidation import ConsolidationResult, ScoredDetection
from redactlens_core.files import Scannable, TextChunk
from redactlens_core.llm.description_targets import scan_description_detections
from redactlens_core.methods import regex
from redactlens_core.progress import ScanExecution
from redactlens_core.scan_results import _raw_detector_opinions
from redactlens_core.scanner_consolidation import (
    _consolidate_descriptions,
    _preserve_canonical_ids,
)
from redactlens_core.scanner_detection import _build_detection
from redactlens_core.scanner_support import (
    _clear_exception_tracebacks,
    _DetectionProjection,
    _DetectionWork,
    _FileOutcome,
    _PreparedDetection,
    _PromptCaptureAdapter,
    _RefinementOutcome,
    _RefinementPlan,
    _release_detection_projection,
    _TimedSerialAdapter,
)


def _prepare_work(
    work: list[_DetectionWork],
    scannable: Scannable,
    file_path: str,
    tier_threshold: float,
    control: ScanExecution,
    *,
    chunk: TextChunk | None = None,
    failed_optional_detectors: set[int] | None = None,
) -> list[_PreparedDetection]:
    """Score heuristically and retain only bounded prompts needed later."""
    prepared: list[_PreparedDetection] = []
    failed_detectors = failed_optional_detectors if failed_optional_detectors is not None else set()
    try:
        for item in work:
            control.checkpoint()
            detector_object_id = id(item.detector)
            if detector_object_id in failed_detectors:
                continue
            capture = _PromptCaptureAdapter()
            try:
                detection = _build_detection(
                    item.detector,
                    item.candidate,
                    scannable,
                    file_path,
                    tier_threshold,
                    capture,
                    origin=item.origin,
                    category_selected=item.category_selected,
                    chunk=chunk,
                )
            except regex.RegexSafetyError:
                if item.required:
                    raise
                failed_detectors.add(detector_object_id)
                prepared[:] = [
                    prior for prior in prepared if prior.detection.detector is not item.detector
                ]
                continue
            prepared.append(_PreparedDetection(detection=detection, prompt=capture.prompt))
        control.checkpoint()
        return prepared
    except BaseException:
        prepared.clear()
        raise


def _refine_file(
    plan: _RefinementPlan,
    heuristic: ConsolidationResult,
    description_targets: tuple,
    tier_threshold: float,
    adapter: _TimedSerialAdapter,
    control: ScanExecution,
    capture_raw_detector_opinions: bool,
) -> _RefinementOutcome:
    """Refine one published heuristic result without rereading its source."""
    started = time.perf_counter()
    refined_detections: list[ScoredDetection] = []
    description_detections: list[ScoredDetection] = []
    local_detections: list[ScoredDetection] = []
    projection: _DetectionProjection | None = None
    outcome: _RefinementOutcome | None = None
    try:
        control.checkpoint()
        for item in plan.detections:
            control.checkpoint()
            detection = item.detection
            if item.prompt is not None:
                verdict = adapter.judge(item.prompt)
                control.checkpoint()
                if verdict is not None:
                    confidence = (detection.confidence + verdict.confidence) / 2
                    evidence = dict(detection.evidence)
                    signals = list(evidence.get("signals", []))
                    signals.append(
                        {
                            "kind": "llm",
                            "condition": verdict.reason,
                            "llm_confidence": verdict.confidence,
                        }
                    )
                    evidence["signals"] = signals
                    evidence["raw_confidence"] = confidence
                    detection = replace(
                        detection,
                        confidence=confidence,
                        tier="A" if confidence >= tier_threshold else "B",
                        evidence=evidence,
                    )
            refined_detections.append(detection)

        targets = list(description_targets)
        for line in plan.description_lines:
            control.checkpoint()
            local_detections = scan_description_detections(
                line.text,
                plan.file_path,
                targets,
                adapter,
                tier_threshold,
                checkpoint=control.checkpoint,
                can_anonymize=plan.can_anonymize,
            )
            description_detections.extend(
                replace(
                    detection,
                    line=line.line,
                    start_offset=line.start_offset + detection.start_offset,
                    end_offset=line.start_offset + detection.end_offset,
                    location=line.location,
                )
                for detection in local_detections
            )
            local_detections.clear()

        projection = _consolidate_descriptions(
            refined_detections,
            description_detections,
            adapter,
            tier_threshold,
            control,
        )
        refined = _preserve_canonical_ids(heuristic, projection.result)
        control.checkpoint()
        outcome = _RefinementOutcome(
            result=refined,
            detection_seconds=time.perf_counter() - started,
            raw_detector_hits_by_detector=projection.raw_detector_hits_by_detector,
            raw_detector_opinions=(
                _raw_detector_opinions(projection.retained_detections)
                if capture_raw_detector_opinions
                else None
            ),
        )
        return outcome
    finally:
        refined_detections.clear()
        description_detections.clear()
        local_detections.clear()
        _release_detection_projection(projection, clear_findings=outcome is None)
        plan.clear()


def _clear_file_outcome(future: Future[_FileOutcome]) -> None:
    """Release a prepared context from an interrupted coordinator."""
    if future.cancelled():
        return
    try:
        outcome = future.result()
    except BaseException as error:
        _clear_exception_tracebacks(error)
        return
    outcome.clear_sensitive()
