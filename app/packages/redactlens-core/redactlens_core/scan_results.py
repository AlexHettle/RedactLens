"""Deterministic result ordering, summaries, and public scan metrics."""

from __future__ import annotations

import os
from collections import Counter

from redactlens_core.consolidation import ScoredDetection
from redactlens_core.files import FileIssue, TextChunk
from redactlens_core.models import Finding, RawDetectorOpinion, ScanResult, SkippedFile
from redactlens_core.performance import peak_memory_bytes
from redactlens_core.scanner_support import _ScanMetrics
from redactlens_core.text_position import line_col


def _global_line_col(chunk: TextChunk, local_offset: int) -> tuple[int, int]:
    local_line, local_column = line_col(chunk.text, local_offset)
    line = chunk.start_line + local_line - 1
    column = chunk.start_column + local_column - 1 if local_line == 1 else local_column
    return line, column


def _skipped_file(path: str, issue: FileIssue) -> SkippedFile:
    return SkippedFile(
        path=path,
        reason=issue.reason,
        code=issue.code,
        stage=issue.stage,
        rule=issue.rule,
    )


def _path_sort_key(path: str) -> str:
    return os.path.normcase(os.path.abspath(path))


def _finding_sort_key(finding: Finding) -> tuple:
    return (
        _path_sort_key(finding.file_path),
        finding.start_offset,
        finding.end_offset,
        finding.detector_id,
        finding.id,
    )


def _raw_detector_opinions(
    detections: list[ScoredDetection],
) -> tuple[RawDetectorOpinion, ...]:
    """Discard matched text while retaining exact detector-level geometry."""

    return tuple(
        RawDetectorOpinion(
            file_path=detection.file_path,
            start_offset=detection.start_offset,
            end_offset=detection.end_offset,
            detector_id=detection.detector.id,
            category=detection.detector.category,
            confidence=detection.confidence,
            tier=detection.tier,
        )
        for detection in detections
    )


def _raw_detector_opinion_sort_key(opinion: RawDetectorOpinion) -> tuple:
    return (
        _path_sort_key(opinion.file_path),
        opinion.start_offset,
        opinion.end_offset,
        opinion.detector_id,
        opinion.category,
        opinion.confidence,
        opinion.tier,
    )


def _result(
    findings: list[Finding],
    scanned_files: list[str],
    skipped_files: list[SkippedFile],
    raw_detection_count: int,
    consolidated_detection_count: int,
    suppressed_detection_count: int,
    *,
    llm_used: bool,
    status: str,
    completed_files: int,
    total_files: int | None,
    duration_seconds: float,
    metrics: _ScanMetrics,
    llm_seconds: float,
    llm_attempts: int,
    llm_successes: int,
    llm_failures: int,
    raw_detector_hits_by_detector: Counter[str],
    raw_detector_opinions: list[RawDetectorOpinion] | None,
) -> ScanResult:
    ordered_findings = sorted(findings, key=_finding_sort_key)
    ordered_opinions = (
        sorted(raw_detector_opinions, key=_raw_detector_opinion_sort_key)
        if raw_detector_opinions is not None
        else None
    )
    ordered_scanned = sorted(scanned_files, key=_path_sort_key)
    ordered_skipped = sorted(
        skipped_files,
        key=lambda item: (_path_sort_key(item.path), item.code, item.reason),
    )
    return ScanResult(
        findings=ordered_findings,
        summary=_build_summary(
            ordered_findings,
            ordered_scanned,
            ordered_skipped,
            raw_detection_count,
            consolidated_detection_count,
            suppressed_detection_count,
            status=status,
            completed_files=completed_files,
            total_files=total_files,
            duration_seconds=duration_seconds,
            metrics=metrics,
            llm_seconds=llm_seconds,
            llm_attempts=llm_attempts,
            llm_successes=llm_successes,
            llm_failures=llm_failures,
            raw_detector_hits_by_detector=raw_detector_hits_by_detector,
        ),
        scanned_files=ordered_scanned,
        skipped_files=ordered_skipped,
        llm_used=llm_used,
        raw_detector_opinions=ordered_opinions,
    )


def _build_summary(
    findings: list[Finding],
    scanned_files: list[str],
    skipped_files: list[SkippedFile],
    raw_detection_count: int,
    consolidated_detection_count: int,
    suppressed_detection_count: int,
    *,
    status: str = "complete",
    completed_files: int | None = None,
    total_files: int | None = None,
    duration_seconds: float = 0.0,
    metrics: _ScanMetrics | None = None,
    llm_seconds: float = 0.0,
    llm_attempts: int = 0,
    llm_successes: int = 0,
    llm_failures: int = 0,
    raw_detector_hits_by_detector: Counter[str] | None = None,
) -> dict:
    completed = (
        len(scanned_files) + len(skipped_files) if completed_files is None else completed_files
    )
    total = completed if total_files is None else total_files
    measured = metrics or _ScanMetrics()
    elapsed = max(0.0, duration_seconds)
    throughput_denominator = max(elapsed, 1e-9)
    tier_counts = Counter(finding.tier for finding in findings)
    category_counts = Counter(finding.category for finding in findings)
    return {
        "total_findings": len(findings),
        "canonical_findings": len(findings),
        "raw_detector_hits": raw_detection_count,
        "consolidated_hits": consolidated_detection_count,
        "suppressed_hits": suppressed_detection_count,
        "raw_detector_hits_by_detector": {
            detector_id: count
            for detector_id, count in sorted((raw_detector_hits_by_detector or Counter()).items())
        },
        "tier_counts": {key: tier_counts[key] for key in sorted(tier_counts)},
        "category_counts": {key: category_counts[key] for key in sorted(category_counts)},
        "files_scanned": len(scanned_files),
        "files_skipped": len(skipped_files),
        "completed_files": completed,
        "total_files": total,
        "status": status,
        "incomplete": status != "complete",
        "duration_ms": round(elapsed * 1_000),
        "peak_memory_bytes": peak_memory_bytes(),
        "bytes_scanned": measured.bytes_scanned,
        "files_per_second": round(completed / throughput_denominator, 3),
        "megabytes_per_second": round(
            measured.bytes_scanned / 1_000_000 / throughput_denominator,
            3,
        ),
        "extraction_seconds": round(measured.extraction_seconds, 6),
        "detection_seconds": round(measured.detection_seconds, 6),
        "llm_seconds": round(llm_seconds, 6),
        "llm_attempts": llm_attempts,
        "llm_successes": llm_successes,
        "llm_failures": llm_failures,
    }
