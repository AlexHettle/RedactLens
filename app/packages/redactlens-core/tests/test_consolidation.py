import hashlib
import random
from dataclasses import FrozenInstanceError

import pytest
from redactlens_core.consolidation import (
    ScoredDetection,
    consolidate_detection_groups,
    consolidate_detections,
)
from redactlens_core.registry import DetectorDef


def _detector(
    detector_id: str,
    *,
    specificity: int = 50,
    suppresses: list[str] | None = None,
    category: str = "credential",
) -> DetectorDef:
    return DetectorDef(
        id=detector_id,
        category=category,
        description=f"Detector {detector_id}",
        risk_lesson="Test risk lesson.",
        method="regex",
        pattern="x+",
        base_confidence=0.5,
        specificity=specificity,
        suppresses=suppresses or [],
    )


def _detection(
    detector: DetectorDef,
    *,
    file_path: str = "example.txt",
    start: int = 0,
    end: int = 4,
    line: int = 1,
    column: int | None = None,
    location: str | None = None,
    can_anonymize: bool = True,
    matched_text: str | None = None,
    preview: str | None = None,
    confidence: float = 0.8,
    tier: str = "A",
    evidence: dict | None = None,
    origin: str = "built_in",
    category_selected: bool = True,
    primary_priority: int = 0,
) -> ScoredDetection:
    return ScoredDetection(
        file_path=file_path,
        line=line,
        column=start + 1 if column is None else column,
        start_offset=start,
        end_offset=end,
        location=location,
        can_anonymize=can_anonymize,
        matched_text="x" * (end - start) if matched_text is None else matched_text,
        redacted_preview="*" * (end - start) if preview is None else preview,
        detector=detector,
        confidence=confidence,
        tier=tier,
        evidence={"base_confidence": confidence} if evidence is None else evidence,
        origin=origin,
        category_selected=category_selected,
        primary_priority=primary_priority,
    )


def test_quadratic_grouping_honors_checkpoints_inside_consolidation():
    detector = _detector("dense")
    detections = [_detection(detector, start=index * 5, end=index * 5 + 4) for index in range(600)]
    checks = 0

    class StopConsolidation(Exception):
        pass

    def checkpoint():
        nonlocal checks
        checks += 1
        if checks == 5:
            raise StopConsolidation

    with pytest.raises(StopConsolidation):
        consolidate_detections(detections, checkpoint=checkpoint)

    assert checks == 5


def test_identical_spans_merge_with_deterministic_primary():
    alpha = _detection(_detector("alpha"))
    beta = _detection(_detector("beta"))

    result = consolidate_detections([beta, alpha])

    assert len(result.findings) == 1
    assert result.findings[0].detector_id == "alpha"
    assert [item.detector_id for item in result.findings[0].supporting_detections] == ["beta"]
    assert result.findings[0].supporting_detections[0].relationship == "same_span"
    assert result.raw_detection_count == 2
    assert result.consolidated_detection_count == 1
    assert result.suppressed_detection_count == 0


def test_detection_provenance_defaults_to_selected_builtin():
    detection = ScoredDetection(
        file_path="example.txt",
        line=1,
        column=1,
        start_offset=0,
        end_offset=4,
        location=None,
        can_anonymize=True,
        matched_text="xxxx",
        redacted_preview="****",
        detector=_detector("default-origin"),
        confidence=0.8,
        tier="A",
        evidence={},
    )

    assert detection.origin == "built_in"
    assert detection.category_selected is True


def test_group_projection_preserves_provenance_and_aggregate_results():
    primary = _detection(
        _detector("primary", specificity=100, suppresses=["requested-target"]),
        start=0,
        end=20,
        category_selected=False,
    )
    requested_target = _detection(
        _detector("requested-target", specificity=10),
        start=5,
        end=15,
        origin="user_target",
        category_selected=False,
    )
    separate = _detection(_detector("separate"), start=30, end=34)

    groups = consolidate_detection_groups([separate, requested_target, primary])
    aggregate = consolidate_detections([separate, requested_target, primary])

    assert [group.finding for group in groups] == aggregate.findings
    assert [group.finding.detector_id for group in groups] == ["primary", "separate"]
    assert groups[0].primary is primary
    assert groups[0].members == (requested_target, primary)
    assert groups[0].suppressed_detection_count == 1
    assert {member.origin for member in groups[0].members} == {"built_in", "user_target"}
    assert aggregate.raw_detection_count == sum(len(group.members) for group in groups) == 3
    assert aggregate.consolidated_detection_count == 1
    assert (
        aggregate.suppressed_detection_count
        == sum(group.suppressed_detection_count for group in groups)
        == 1
    )
    with pytest.raises(FrozenInstanceError):
        groups[0].suppressed_detection_count = 0


def test_specificity_outranks_higher_generic_confidence():
    structured = _detection(_detector("structured", specificity=100), confidence=0.7)
    generic = _detection(_detector("generic", specificity=10), confidence=0.99)

    result = consolidate_detections([generic, structured])

    assert result.findings[0].detector_id == "structured"


def test_explicit_suppression_merges_contained_detection():
    container = _detection(
        _detector("connection", specificity=100, suppresses=["email"]),
        start=0,
        end=20,
    )
    contained = _detection(_detector("email"), start=8, end=18)

    result = consolidate_detections([contained, container])

    assert len(result.findings) == 1
    assert result.findings[0].detector_id == "connection"
    assert result.findings[0].supporting_detections[0].relationship == "suppressed"
    assert result.suppressed_detection_count == 1


def test_unvalidated_lower_specificity_suppressor_is_defensively_primary():
    suppressor = _detection(
        _detector("suppressor", specificity=10, suppresses=["target"]),
        start=0,
        end=20,
    )
    target = _detection(_detector("target", specificity=100), start=5, end=15)

    result = consolidate_detections([target, suppressor])

    assert len(result.findings) == 1
    assert result.findings[0].detector_id == "suppressor"
    assert result.findings[0].supporting_detections[0].detector_id == "target"
    assert result.findings[0].supporting_detections[0].relationship == "suppressed"
    assert result.suppressed_detection_count == 1


def test_suppression_through_same_span_bridge_is_counted_and_order_independent():
    primary = _detection(_detector("primary", specificity=100), start=0, end=20)
    bridge = _detection(
        _detector("bridge", specificity=90, suppresses=["nested"]),
        start=0,
        end=20,
    )
    nested = _detection(_detector("nested", specificity=10), start=5, end=15)

    forward = consolidate_detections([primary, bridge, nested])
    reverse = consolidate_detections([nested, bridge, primary])

    assert forward == reverse
    assert len(forward.findings) == 1
    assert forward.findings[0].detector_id == "primary"
    assert {
        item.detector_id: item.relationship for item in forward.findings[0].supporting_detections
    } == {"bridge": "same_span", "nested": "suppressed"}
    assert forward.raw_detection_count == 3
    assert forward.consolidated_detection_count == 2
    assert forward.suppressed_detection_count == 1


def test_unrelated_partial_overlaps_remain_separate():
    left = _detection(_detector("left"), start=0, end=4)
    right = _detection(_detector("right"), start=2, end=6)

    result = consolidate_detections([left, right])

    assert [finding.detector_id for finding in result.findings] == ["left", "right"]
    assert result.consolidated_detection_count == 0


def test_disjoint_detections_on_separate_lines_remain_distinct_findings():
    first = _detection(_detector("first"), start=0, end=4, line=1)
    second = _detection(_detector("second"), start=12, end=16, line=2)

    result = consolidate_detections([second, first])

    assert [
        (finding.detector_id, finding.line, finding.start_offset, finding.end_offset)
        for finding in result.findings
    ] == [("first", 1, 0, 4), ("second", 2, 12, 16)]
    assert len({finding.id for finding in result.findings}) == 2
    assert result.raw_detection_count == 2
    assert result.consolidated_detection_count == 0
    assert result.suppressed_detection_count == 0


def test_input_order_does_not_change_finding_or_stable_id():
    primary = _detection(
        _detector("primary", specificity=100, suppresses=["generic"]),
        start=0,
        end=10,
    )
    generic = _detection(_detector("generic", specificity=10), start=2, end=8)

    forward = consolidate_detections([primary, generic])
    reverse = consolidate_detections([generic, primary])

    assert forward.findings == reverse.findings


def _oracle_consolidation(detections: list[ScoredDetection]) -> tuple[list[tuple], int]:
    """Derive the documented grouping and precedence rules without production helpers."""

    def suppresses(suppressor: ScoredDetection, target: ScoredDetection) -> bool:
        return (
            suppressor.file_path == target.file_path
            and suppressor.start_offset <= target.start_offset
            and suppressor.end_offset >= target.end_offset
            and target.detector.id in suppressor.detector.suppresses
        )

    def related(left: ScoredDetection, right: ScoredDetection) -> bool:
        return left.file_path == right.file_path and (
            suppresses(left, right)
            or suppresses(right, left)
            or (left.start_offset == right.start_offset and left.end_offset == right.end_offset)
        )

    parents = list(range(len(detections)))

    def root(index: int) -> int:
        while parents[index] != index:
            index = parents[index]
        return index

    for left_index, left in enumerate(detections):
        for right_index in range(left_index + 1, len(detections)):
            if related(left, detections[right_index]):
                left_root = root(left_index)
                right_root = root(right_index)
                parents[right_root] = left_root

    groups: dict[int, list[ScoredDetection]] = {}
    for index, detection in enumerate(detections):
        groups.setdefault(root(index), []).append(detection)

    expected: list[tuple] = []
    suppressed_count = 0
    for members in groups.values():
        group_members = tuple(members)

        def primary_key(
            detection: ScoredDetection,
            candidates: tuple[ScoredDetection, ...] = group_members,
        ) -> tuple:
            is_suppressed = any(
                suppresses(candidate, detection)
                for candidate in candidates
                if candidate is not detection
            )
            return (
                is_suppressed,
                -detection.detector.specificity,
                -detection.primary_priority,
                -(detection.end_offset - detection.start_offset),
                detection.detector.id,
                detection.start_offset,
                detection.end_offset,
            )

        primary = min(members, key=primary_key)
        supporting = []
        for member in members:
            if member is primary:
                continue
            if any(
                suppresses(candidate, member) for candidate in members if candidate is not member
            ):
                relationship = "suppressed"
                suppressed_count += 1
            elif (
                member.start_offset == primary.start_offset
                and member.end_offset == primary.end_offset
            ):
                relationship = "same_span"
            else:
                relationship = "overlap_chain"
            supporting.append(
                (
                    member.detector.id,
                    member.detector.description,
                    relationship,
                    member.confidence,
                )
            )
        supporting.sort()
        signature = "|".join(
            f"{member.detector.id}:{member.start_offset}:{member.end_offset}"
            for member in sorted(
                members,
                key=lambda item: (item.start_offset, item.end_offset, item.detector.id),
            )
        )
        group_start = min(member.start_offset for member in members)
        group_end = max(member.end_offset for member in members)
        canonical_id = hashlib.sha256(
            f"{primary.file_path}:{group_start}:canonical:{group_end}:{signature}".encode()
        ).hexdigest()[:16]
        evidence = dict(primary.evidence)
        if supporting:
            evidence["consolidation"] = {
                "raw_detection_count": len(members),
                "supporting_detector_ids": [item[0] for item in supporting],
            }
        expected.append(
            (
                canonical_id,
                primary.file_path,
                primary.line,
                primary.column,
                primary.start_offset,
                primary.end_offset,
                primary.location,
                primary.can_anonymize,
                primary.matched_text,
                primary.redacted_preview,
                primary.detector.id,
                primary.detector.category,
                primary.confidence,
                primary.tier,
                primary.detector.description,
                primary.detector.risk_lesson,
                ("anonymize" if primary.can_anonymize and primary.tier == "A" else "review"),
                evidence,
                tuple(supporting),
                len(members),
            )
        )

    expected.sort(key=lambda item: (item[4], item[5], item[0]))
    return expected, suppressed_count


def _public_consolidation_signature(result) -> list[tuple]:
    return [
        (
            finding.id,
            finding.file_path,
            finding.line,
            finding.column,
            finding.start_offset,
            finding.end_offset,
            finding.location,
            finding.can_anonymize,
            finding.matched_text,
            finding.redacted_preview,
            finding.detector_id,
            finding.category,
            finding.confidence,
            finding.tier,
            finding.explanation,
            finding.risk_lesson,
            finding.suggested_action,
            finding.evidence,
            tuple(
                (
                    supporting.detector_id,
                    supporting.description,
                    supporting.relationship,
                    supporting.confidence,
                )
                for supporting in finding.supporting_detections
            ),
            finding.evidence.get("consolidation", {}).get("raw_detection_count", 1),
        )
        for finding in result.findings
    ]


def test_arbitrary_overlap_arrangements_are_order_independent():
    """Property-style coverage for connected, partial, and disjoint spans.

    The generated cases deliberately mix exact spans, containment chains,
    unrelated partial overlaps, and disjoint values.  Every permutation must
    preserve the same canonical findings and accounting totals.
    """

    randomizer = random.Random(20260716)
    for case in range(75):
        detectors = [
            _detector(
                f"detector-{index}",
                specificity=randomizer.randint(1, 150),
                suppresses=[f"detector-{index + 1}"] if index < 5 and case % 2 == 0 else [],
                category=randomizer.choice(["credential", "financial", "personal_id"]),
            )
            for index in range(6)
        ]
        spans: list[tuple[int, int]] = []
        for index in range(6):
            start = randomizer.randint(0, 24)
            length = randomizer.randint(1, 12)
            if index and randomizer.random() < 0.3:
                start, prior_end = randomizer.choice(spans)
                length = prior_end - start
            spans.append((start, start + length))
        detections = []
        for index, (detector, (start, end)) in enumerate(zip(detectors, spans, strict=True)):
            confidence = randomizer.uniform(0.45, 0.99)
            detections.append(
                _detection(
                    detector,
                    file_path=f"example-{randomizer.randint(0, 1)}.txt",
                    start=start,
                    end=end,
                    line=randomizer.randint(1, 12),
                    column=randomizer.randint(1, 80),
                    location=randomizer.choice([None, f"Sheet{index}!A{index + 1}"]),
                    can_anonymize=randomizer.choice([True, False]),
                    matched_text=f"raw-{case}-{index}",
                    preview=f"preview-{case}-{index}",
                    confidence=confidence,
                    tier=randomizer.choice(["A", "B"]),
                    evidence={
                        "base_confidence": confidence,
                        "case": case,
                        "member": index,
                    },
                    primary_priority=randomizer.choice([-1, 0, 1]),
                )
            )

        baseline = consolidate_detections(detections)
        expected, expected_suppressed = _oracle_consolidation(detections)
        assert _public_consolidation_signature(baseline) == expected
        assert baseline.suppressed_detection_count == expected_suppressed
        assert baseline.raw_detection_count == len(detections)
        assert baseline.consolidated_detection_count == len(detections) - len(expected)
        for _ in range(8):
            shuffled = detections.copy()
            randomizer.shuffle(shuffled)
            candidate = consolidate_detections(shuffled)

            assert candidate == baseline
            assert _public_consolidation_signature(candidate) == expected
