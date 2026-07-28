"""Turn raw scored detector hits into stable, user-visible findings.

Detection methods are intentionally allowed to overlap: a known AWS key is
also high-entropy, and a credential-bearing connection string contains text
that resembles an email address. Those extra signals are useful evidence,
but presenting each implementation-level hit as a separate problem inflates
counts and makes remediation confusing.

This module keeps raw scoring separate from presentation. It groups only
relationships we can explain deterministically: identical spans, or a
contained detection explicitly suppressed by a more specific detector.
Unrelated partial overlaps remain separate rather than being guessed away.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Literal

from redactlens_core.models import Finding, SupportingDetection, Tier
from redactlens_core.registry import DetectorDef
from redactlens_core.text_position import stable_id


@dataclass(frozen=True)
class ScoredDetection:
    """One detector's scored opinion before canonical consolidation."""

    file_path: str
    line: int
    column: int
    start_offset: int
    end_offset: int
    location: str | None
    can_anonymize: bool
    matched_text: str
    redacted_preview: str
    detector: DetectorDef
    confidence: float
    tier: Tier
    evidence: dict[str, Any]
    origin: Literal["built_in", "user_target"] = "built_in"
    category_selected: bool = True
    # Tie-break equal-specificity opinions without relying on confidence or
    # implementation-level detector IDs. Literal targets use 1, built-ins 0,
    # and localized description opinions -1 so an exact deterministic anchor
    # remains the canonical primary when AI evidence is added.
    primary_priority: int = 0


@dataclass(frozen=True)
class ConsolidatedGroup:
    """One canonical finding plus the detector opinions that produced it."""

    primary: ScoredDetection
    members: tuple[ScoredDetection, ...]
    finding: Finding
    suppressed_detection_count: int


@dataclass(frozen=True)
class ConsolidationResult:
    findings: list[Finding]
    raw_detection_count: int
    consolidated_detection_count: int
    suppressed_detection_count: int


def consolidate_detections(
    detections: list[ScoredDetection],
    checkpoint: Callable[[], None] | None = None,
) -> ConsolidationResult:
    """Build canonical findings from one file's raw scored detections."""
    groups = consolidate_detection_groups(detections, checkpoint)
    raw_detection_count = sum(len(group.members) for group in groups)
    findings = [group.finding for group in groups]
    return ConsolidationResult(
        findings=findings,
        raw_detection_count=raw_detection_count,
        consolidated_detection_count=raw_detection_count - len(findings),
        suppressed_detection_count=sum(group.suppressed_detection_count for group in groups),
    )


def consolidate_detection_groups(
    detections: list[ScoredDetection],
    checkpoint: Callable[[], None] | None = None,
) -> list[ConsolidatedGroup]:
    """Build inspectable canonical groups before aggregate result projection."""
    if checkpoint is not None:
        checkpoint()
    if not detections:
        return []

    member_groups = _groups(detections, checkpoint)
    groups: list[ConsolidatedGroup] = []

    for members in member_groups:
        if checkpoint is not None:
            checkpoint()
        primary = sorted(
            members,
            key=lambda detection: _group_primary_sort_key(detection, members),
        )[0]
        relationships = {
            id(member): _supporting_relationship(primary, member, members)
            for member in members
            if member is not primary
        }
        suppressed_count = sum(reason == "suppressed" for reason in relationships.values())
        supporting = _supporting_detections(primary, members, relationships)
        evidence = dict(primary.evidence)
        if supporting:
            evidence["consolidation"] = {
                "raw_detection_count": len(members),
                "supporting_detector_ids": [item.detector_id for item in supporting],
            }
        groups.append(
            ConsolidatedGroup(
                primary=primary,
                members=tuple(members),
                finding=_to_finding(primary, members, evidence, supporting),
                suppressed_detection_count=suppressed_count,
            )
        )

    groups.sort(
        key=lambda group: (
            group.finding.start_offset,
            group.finding.end_offset,
            group.finding.id,
        )
    )
    if checkpoint is not None:
        checkpoint()
    return groups


def _groups(
    detections: list[ScoredDetection],
    checkpoint: Callable[[], None] | None,
) -> list[list[ScoredDetection]]:
    """Connected components under the explicit consolidation relation."""
    parents = list(range(len(detections)))

    def find(index: int) -> int:
        while parents[index] != index:
            parents[index] = parents[parents[index]]
            index = parents[index]
        return index

    def union(left: int, right: int) -> None:
        left_root = find(left)
        right_root = find(right)
        if left_root != right_root:
            parents[right_root] = left_root

    for left_index, left in enumerate(detections):
        if checkpoint is not None:
            checkpoint()
        for right_index in range(left_index + 1, len(detections)):
            # Grouping is quadratic. Check periodically inside the inner loop,
            # not merely once per detector, so a dense file remains
            # cooperatively cancellable and deadline-aware.
            if checkpoint is not None and (right_index - left_index) % 256 == 0:
                checkpoint()
            if _relationship(left, detections[right_index]) is not None:
                union(left_index, right_index)

    by_root: dict[int, list[ScoredDetection]] = {}
    for index, detection in enumerate(detections):
        if checkpoint is not None and index % 256 == 0:
            checkpoint()
        by_root.setdefault(find(index), []).append(detection)
    return list(by_root.values())


def _relationship(primary: ScoredDetection, other: ScoredDetection) -> str | None:
    if primary.file_path != other.file_path:
        return None
    if suppresses_detection(primary, other) or suppresses_detection(other, primary):
        return "suppressed"
    if primary.start_offset == other.start_offset and primary.end_offset == other.end_offset:
        return "same_span"
    return None


def _supporting_relationship(
    primary: ScoredDetection,
    member: ScoredDetection,
    members: list[ScoredDetection],
) -> str:
    """Describe why a non-primary detection belongs to its canonical group.

    Connected components can contain a suppression edge that does not touch
    the selected primary. Classify the suppressed detection from every
    directional edge in the group so transitive grouping does not hide that
    explicit detector relationship.
    """
    if any(
        suppresses_detection(candidate, member) for candidate in members if candidate is not member
    ):
        return "suppressed"
    if (
        primary.file_path == member.file_path
        and primary.start_offset == member.start_offset
        and primary.end_offset == member.end_offset
    ):
        return "same_span"
    return "overlap_chain"


def suppresses_detection(
    suppressor: ScoredDetection,
    suppressed: ScoredDetection,
) -> bool:
    """Return whether explicit metadata makes one contained hit supporting evidence.

    Scanner category filters use the same relation to retain cross-category
    suppressors as hidden context. Keeping the predicate here prevents the
    filtered and unfiltered consolidation paths from drifting apart.
    """
    return (
        suppressor.file_path == suppressed.file_path
        and _contains(suppressor, suppressed)
        and suppressed.detector.id in suppressor.detector.suppresses
    )


def _contains(container: ScoredDetection, contained: ScoredDetection) -> bool:
    return (
        container.start_offset <= contained.start_offset
        and container.end_offset >= contained.end_offset
    )


def _primary_sort_key(detection: ScoredDetection) -> tuple:
    span_length = detection.end_offset - detection.start_offset
    return (
        -detection.detector.specificity,
        -detection.primary_priority,
        -span_length,
        detection.detector.id,
        detection.start_offset,
        detection.end_offset,
    )


def _group_primary_sort_key(
    detection: ScoredDetection,
    members: list[ScoredDetection],
) -> tuple:
    """Keep malformed, unvalidated suppression metadata internally coherent.

    Frozen registries require a suppressor to have greater specificity than
    its target, so the ordinary primary key already chooses it. Direct users
    of consolidation can bypass a registry, though; in that case an explicit
    suppressor must not become evidence beneath the detection it suppresses.
    """
    is_suppressed = any(
        suppresses_detection(candidate, detection)
        for candidate in members
        if candidate is not detection
    )
    return (is_suppressed, *_primary_sort_key(detection))


def _supporting_detections(
    primary: ScoredDetection,
    members: list[ScoredDetection],
    relationships: dict[int, str],
) -> list[SupportingDetection]:
    # Several spans from the same generic detector (for example JWT
    # segments) should produce one supporting-detector label, while raw hit
    # counts still retain every absorbed span.
    by_detector: dict[str, SupportingDetection] = {}
    for member in sorted(members, key=_primary_sort_key):
        if member is primary:
            continue
        candidate = SupportingDetection(
            detector_id=member.detector.id,
            description=member.detector.description,
            confidence=member.confidence,
            relationship=relationships[id(member)],
        )
        current = by_detector.get(candidate.detector_id)
        if current is None or candidate.confidence > current.confidence:
            by_detector[candidate.detector_id] = candidate
    return [by_detector[detector_id] for detector_id in sorted(by_detector)]


def _to_finding(
    primary: ScoredDetection,
    members: list[ScoredDetection],
    evidence: dict[str, Any],
    supporting: list[SupportingDetection],
) -> Finding:
    signature = "|".join(
        f"{member.detector.id}:{member.start_offset}:{member.end_offset}"
        for member in sorted(
            members,
            key=lambda item: (item.start_offset, item.end_offset, item.detector.id),
        )
    )
    group_start = min(member.start_offset for member in members)
    group_end = max(member.end_offset for member in members)
    canonical_id = stable_id(
        primary.file_path,
        group_start,
        f"canonical:{group_end}:{signature}",
    )
    return Finding(
        id=canonical_id,
        file_path=primary.file_path,
        line=primary.line,
        column=primary.column,
        start_offset=primary.start_offset,
        end_offset=primary.end_offset,
        location=primary.location,
        can_anonymize=primary.can_anonymize,
        matched_text=primary.matched_text,
        redacted_preview=primary.redacted_preview,
        detector_id=primary.detector.id,
        category=primary.detector.category,
        confidence=primary.confidence,
        tier=primary.tier,
        explanation=primary.detector.description,
        risk_lesson=primary.detector.risk_lesson,
        suggested_action=(
            "anonymize" if primary.can_anonymize and primary.tier == "A" else "review"
        ),
        evidence=evidence,
        supporting_detections=supporting,
    )
