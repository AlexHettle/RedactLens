"""Finding projection and description-target consolidation for scans."""

from __future__ import annotations

from collections import Counter
from collections.abc import Callable
from dataclasses import replace

from redactlens_core.consolidation import (
    ConsolidatedGroup,
    ConsolidationResult,
    ScoredDetection,
    consolidate_detection_groups,
)
from redactlens_core.llm.description_targets import confirm_description_match, standalone_finding
from redactlens_core.models import Finding
from redactlens_core.progress import ScanExecution
from redactlens_core.scan_results import _finding_sort_key
from redactlens_core.scanner_support import _DetectionProjection, _TimedSerialAdapter

MAX_DESCRIPTION_CONFIRMATION_CANDIDATES = 8


def _project_detection_groups(
    groups: list[ConsolidatedGroup],
    *,
    checkpoint: Callable[[], None] | None = None,
    finding_transform: Callable[[Finding], Finding] | None = None,
) -> _DetectionProjection:
    """Project complete canonical groups onto the categories a request selected.

    A built-in group is visible only when its canonical primary belongs to a
    selected category. User-target provenance overrides that filter even when
    an unselected built-in remains the more specific primary. Keeping every
    member of a retained group preserves canonical IDs, supporting evidence,
    and raw/consolidated accounting across filtered and unfiltered scans.
    """
    retained_groups: list[ConsolidatedGroup] = []
    for group in groups:
        if checkpoint is not None:
            checkpoint()
        if group.primary.category_selected or any(
            member.origin == "user_target" for member in group.members
        ):
            retained_groups.append(group)

    findings = [
        finding_transform(group.finding) if finding_transform is not None else group.finding
        for group in retained_groups
    ]
    retained = [member for group in retained_groups for member in group.members]
    raw_counts = Counter(detection.detector.id for detection in retained)
    raw_count = len(retained)
    return _DetectionProjection(
        result=ConsolidationResult(
            findings=findings,
            raw_detection_count=raw_count,
            consolidated_detection_count=raw_count - len(findings),
            suppressed_detection_count=sum(
                group.suppressed_detection_count for group in retained_groups
            ),
        ),
        retained_detections=retained,
        raw_detector_hits_by_detector=tuple(sorted(raw_counts.items())),
    )


def _combine_detection_projections(
    projections: list[_DetectionProjection],
) -> _DetectionProjection:
    """Combine disjoint projected group sets into one deterministic result."""
    findings = [finding for projection in projections for finding in projection.result.findings]
    findings.sort(key=_finding_sort_key)
    retained = [
        detection for projection in projections for detection in projection.retained_detections
    ]
    raw_counts = Counter(detection.detector.id for detection in retained)
    raw_count = sum(projection.result.raw_detection_count for projection in projections)
    return _DetectionProjection(
        result=ConsolidationResult(
            findings=findings,
            raw_detection_count=raw_count,
            consolidated_detection_count=raw_count - len(findings),
            suppressed_detection_count=sum(
                projection.result.suppressed_detection_count for projection in projections
            ),
        ),
        retained_detections=retained,
        raw_detector_hits_by_detector=tuple(sorted(raw_counts.items())),
    )


def _consolidate_descriptions(
    base_detections: list[ScoredDetection],
    description_detections: list[ScoredDetection],
    adapter: _TimedSerialAdapter,
    tier_threshold: float,
    control: ScanExecution,
) -> _DetectionProjection:
    """Reconcile unbounded line opinions with deterministic canonical spans.

    A description target reports the complete non-blank passage shown to the
    local model. Re-check every canonical span contained by that passage and
    merge the opinion only when exactly one span matches the same description.
    Zero or multiple semantic matches stay independently visible and can mask
    that complete passage when its source format supports rewriting.
    """
    base_groups = consolidate_detection_groups(
        base_detections,
        checkpoint=control.checkpoint,
    )
    if not description_detections:
        return _project_detection_groups(base_groups, checkpoint=control.checkpoint)

    mergeable: list[ScoredDetection] = []
    standalone: list[ScoredDetection] = []
    evidence_by_primary: dict[tuple[str, int, int, str], list[dict[str, object]]] = {}

    for description in description_detections:
        control.checkpoint()
        contained = [
            finding
            for finding in (group.finding for group in base_groups)
            if finding.file_path == description.file_path
            and description.start_offset <= finding.start_offset
            and description.end_offset >= finding.end_offset
        ]
        if len(contained) > MAX_DESCRIPTION_CONFIRMATION_CANDIDATES:
            standalone.append(description)
            continue
        confirmed = []
        for candidate in contained:
            confirmation = confirm_description_match(
                description,
                candidate.matched_text,
                adapter,
                checkpoint=control.checkpoint,
            )
            if confirmation is not None:
                confirmed.append((candidate, confirmation))
        if len(confirmed) != 1:
            standalone.append(description)
            continue

        canonical, confirmation = confirmed[0]
        projected_confidence = min(description.confidence, confirmation.confidence)
        projected_tier = "A" if projected_confidence >= tier_threshold else "B"

        mergeable.append(
            replace(
                description,
                line=canonical.line,
                column=canonical.column,
                start_offset=canonical.start_offset,
                end_offset=canonical.end_offset,
                location=canonical.location,
                can_anonymize=canonical.can_anonymize,
                matched_text=canonical.matched_text,
                redacted_preview=canonical.redacted_preview,
                confidence=projected_confidence,
                tier=projected_tier,
            )
        )
        primary_key = _canonical_key(canonical)
        evidence_by_primary.setdefault(primary_key, []).append(
            {
                "detector_id": description.detector.id,
                "target": description.detector.pattern,
                "line_confidence": description.confidence,
                "line_reason": description.evidence.get("llm_reason"),
                "span_confidence": confirmation.confidence,
                "span_reason": confirmation.reason,
                "projected_confidence": projected_confidence,
                "projected_tier": projected_tier,
            }
        )

    enriched_base: list[ScoredDetection] = []
    for detection in base_detections:
        key = _detection_key(detection)
        additions = evidence_by_primary.get(key)
        if additions is None:
            enriched_base.append(detection)
            continue
        evidence = dict(detection.evidence)
        existing = evidence.get("description_targets")
        description_evidence = list(existing) if isinstance(existing, list) else []
        description_evidence.extend(additions)
        description_evidence.sort(
            key=lambda item: (
                str(item.get("detector_id", "")),
                str(item.get("target", "")),
            )
        )
        evidence["description_targets"] = description_evidence
        enriched_base.append(replace(detection, evidence=evidence))

    combined_groups = consolidate_detection_groups(
        [*enriched_base, *mergeable],
        checkpoint=control.checkpoint,
    )
    combined_projection = _project_detection_groups(
        combined_groups,
        checkpoint=control.checkpoint,
    )
    standalone_groups: list[ConsolidatedGroup] = []
    by_span: dict[tuple[str, int, int], list[ScoredDetection]] = {}
    for detection in standalone:
        by_span.setdefault(
            (detection.file_path, detection.start_offset, detection.end_offset), []
        ).append(detection)
    for span_detections in by_span.values():
        groups = consolidate_detection_groups(
            span_detections,
            checkpoint=control.checkpoint,
        )
        if len(span_detections) == 1:
            groups = [replace(groups[0], finding=standalone_finding(span_detections[0]))]
        standalone_groups.extend(groups)

    standalone_projection = _project_detection_groups(
        standalone_groups,
        checkpoint=control.checkpoint,
    )
    return _combine_detection_projections([combined_projection, standalone_projection])


def _preserve_canonical_ids(
    heuristic: ConsolidationResult,
    refined: ConsolidationResult,
) -> ConsolidationResult:
    """Keep the actionable concept id stable while adding AI evidence."""
    heuristic_ids = {_canonical_key(finding): finding.id for finding in heuristic.findings}
    findings = [
        (
            finding.model_copy(update={"id": heuristic_ids[_canonical_key(finding)]})
            if _canonical_key(finding) in heuristic_ids
            else finding
        )
        for finding in refined.findings
    ]
    return ConsolidationResult(
        findings=findings,
        raw_detection_count=refined.raw_detection_count,
        consolidated_detection_count=refined.consolidated_detection_count,
        suppressed_detection_count=refined.suppressed_detection_count,
    )


def _canonical_key(finding: Finding) -> tuple[str, int, int, str]:
    return (
        finding.file_path,
        finding.start_offset,
        finding.end_offset,
        finding.detector_id,
    )


def _detection_key(detection: ScoredDetection) -> tuple[str, int, int, str]:
    return (
        detection.file_path,
        detection.start_offset,
        detection.end_offset,
        detection.detector.id,
    )
