from itertools import combinations, permutations

import pytest

from metrics import (
    FindingLike,
    Plant,
    _one_to_one_matches,
    category_breakdown,
    confidence_calibration,
    detector_breakdown,
    evaluate,
    f1_score,
    finding_is_true_positive,
    finding_precision,
    plant_is_recalled,
    plant_recall,
    select_threshold,
    threshold_sweep,
    user_impact_metrics,
)


def _plant(
    file="a.txt",
    start=0,
    end=5,
    category="credential",
    is_positive=True,
    detector_id="password_assignment",
    case_id="unlabeled",
):
    return Plant(file, start, end, category, is_positive, detector_id, case_id)


def _finding(
    file="a.txt",
    start=0,
    end=5,
    tier="A",
    confidence=0.9,
    detector_id="password_assignment",
    category="credential",
    supporting_detector_ids=(),
):
    return FindingLike(
        file,
        start,
        end,
        tier,
        confidence,
        detector_id,
        category,
        supporting_detector_ids,
    )


def test_finding_is_true_positive_requires_same_file_category_and_meaningful_overlap():
    positives = [_plant(file="a.txt", start=10, end=20)]
    assert finding_is_true_positive(_finding(file="a.txt", start=8, end=22), positives)
    assert not finding_is_true_positive(_finding(file="b.txt", start=8, end=22), positives)
    assert not finding_is_true_positive(_finding(file="a.txt", start=30, end=40), positives)
    assert not finding_is_true_positive(
        _finding(file="a.txt", start=10, end=20, category="financial"),
        positives,
    )
    assert not finding_is_true_positive(_finding(file="a.txt", start=19, end=29), positives)


def test_finding_is_true_positive_accepts_containing_span():
    positives = [_plant(start=0, end=10)]
    assert finding_is_true_positive(_finding(start=0, end=20), positives)


def test_finding_is_true_positive_rejects_half_span():
    positives = [_plant(start=0, end=10)]
    assert not finding_is_true_positive(_finding(start=0, end=5), positives)


def test_plant_is_recalled_respects_require_tier():
    findings = [_finding(start=0, end=5, tier="B")]
    plant = _plant(start=0, end=5)
    assert plant_is_recalled(plant, findings, require_tier=None)
    assert not plant_is_recalled(plant, findings, require_tier="A")


def test_finding_precision_empty_findings_has_no_support():
    assert finding_precision([], [_plant()]) == 0.0


def test_finding_precision_counts_only_true_positives():
    positives = [_plant(start=0, end=5)]
    findings = [_finding(start=0, end=5), _finding(start=100, end=105)]
    assert finding_precision(findings, positives) == 0.5


def test_duplicate_findings_receive_only_one_true_positive_credit():
    positives = [_plant(start=0, end=10)]
    findings = [
        _finding(start=0, end=10, detector_id="password_assignment"),
        _finding(start=0, end=10, detector_id="high_entropy_secret"),
    ]

    result = evaluate(findings, positives)

    assert result["true_positive_findings"] == 1
    assert result["false_positive_findings"] == 1
    assert result["recalled_plants"] == 1
    assert result["overall_precision"] == 0.5
    assert result["overall_recall"] == 1.0


def test_broad_duplicate_findings_cannot_recall_multiple_contained_plants():
    positives = [
        _plant(start=2, end=4, case_id="left"),
        _plant(start=6, end=8, case_id="right"),
    ]
    findings = [
        _finding(start=0, end=10, confidence=0.9, detector_id="broad_primary"),
        _finding(start=0, end=10, confidence=0.8, detector_id="broad_duplicate"),
    ]

    result = evaluate(findings, positives)

    assert result["true_positive_findings"] == 1
    assert result["false_positive_findings"] == 1
    assert result["recalled_plants"] == 1
    assert result["false_negative_plants"] == 1
    assert result["overall_precision"] == 0.5
    assert result["overall_recall"] == 0.5


def test_identical_duplicate_credits_higher_confidence_before_stable_tie_break():
    plants = [_plant(start=0, end=5, detector_id="d")]
    findings = [
        _finding(start=0, end=5, confidence=0.1, detector_id="d"),
        _finding(start=0, end=5, confidence=0.9, detector_id="d"),
    ]

    matches = _one_to_one_matches(findings, plants)
    calibration = confidence_calibration(findings, plants)

    assert [findings[index].confidence for index, _ in matches] == [0.9]
    assert calibration["brier_score"] == pytest.approx(0.01)
    assert calibration["expected_calibration_error"] == pytest.approx(0.1)

    reversed_findings = list(reversed(findings))
    reversed_matches = _one_to_one_matches(reversed_findings, plants)
    assert [reversed_findings[index].confidence for index, _ in reversed_matches] == [0.9]
    assert confidence_calibration(reversed_findings, plants) == calibration


def test_matching_maximizes_cardinality_independently_of_input_order():
    plants = [
        _plant(start=0, end=10, case_id="left"),
        _plant(start=10, end=20, case_id="right"),
    ]
    findings = [
        _finding(start=0, end=20, detector_id="broad"),
        _finding(start=0, end=10, detector_id="password_assignment"),
    ]

    expected = evaluate(findings, plants)
    reversed_inputs = evaluate(list(reversed(findings)), list(reversed(plants)))

    assert expected["true_positive_findings"] == 2
    assert expected["overall_precision"] == 1.0
    assert expected["overall_recall"] == 1.0
    assert reversed_inputs == expected


def test_matching_globally_minimizes_overhang_before_assigning_true_positives():
    plants = [
        _plant(start=13, end=18, category="c", detector_id="d", case_id="p0"),
        _plant(start=15, end=16, category="c", detector_id="d", case_id="p1"),
        _plant(start=5, end=8, category="c", detector_id="d", case_id="p2"),
    ]
    findings = [
        _finding(start=12, end=13, confidence=0.637077, category="c", detector_id="d"),
        _finding(start=7, end=21, confidence=0.227582, category="c", detector_id="d"),
        _finding(start=4, end=14, confidence=0.563982, category="c", detector_id="d"),
        _finding(start=4, end=12, confidence=0.134931, category="c", detector_id="d"),
        _finding(start=12, end=19, confidence=0.878350, category="c", detector_id="d"),
        _finding(start=14, end=25, confidence=0.419197, category="c", detector_id="d"),
    ]

    matches = _one_to_one_matches(findings, plants)
    matched_confidences = {findings[index].confidence for index, _ in matches}
    total_overhang = sum(
        (plants[plant_index].start - findings[finding_index].start)
        + (findings[finding_index].end - plants[plant_index].end)
        for finding_index, plant_index in matches
    )
    total_length = sum(findings[index].end - findings[index].start for index, _ in matches)
    detector_disagreements = sum(
        findings[finding_index].detector_id != plants[plant_index].detector_id
        for finding_index, plant_index in matches
    )

    brute_force_objectives = []
    for size in range(min(len(findings), len(plants)), -1, -1):
        for finding_indices in combinations(range(len(findings)), size):
            for plant_indices in permutations(range(len(plants)), size):
                pairs = list(zip(finding_indices, plant_indices, strict=True))
                if not all(
                    findings[finding_index].file == plants[plant_index].file
                    and findings[finding_index].category == plants[plant_index].category
                    and findings[finding_index].start <= plants[plant_index].start
                    and findings[finding_index].end >= plants[plant_index].end
                    for finding_index, plant_index in pairs
                ):
                    continue
                brute_force_objectives.append(
                    (
                        -size,
                        sum(
                            (plants[plant_index].start - findings[finding_index].start)
                            + (findings[finding_index].end - plants[plant_index].end)
                            for finding_index, plant_index in pairs
                        ),
                        sum(
                            findings[finding_index].end - findings[finding_index].start
                            for finding_index, _ in pairs
                        ),
                        sum(
                            findings[finding_index].detector_id != plants[plant_index].detector_id
                            for finding_index, plant_index in pairs
                        ),
                    )
                )
        if brute_force_objectives:
            break

    assert len(matches) == 3
    assert matched_confidences == {0.134931, 0.878350, 0.419197}
    assert total_overhang == 17
    assert (-len(matches), total_overhang, total_length, detector_disagreements) == min(
        brute_force_objectives
    )

    reversed_findings = list(reversed(findings))
    reversed_plants = list(reversed(plants))
    reversed_matches = _one_to_one_matches(reversed_findings, reversed_plants)
    assert {reversed_findings[index].confidence for index, _ in reversed_matches} == (
        matched_confidences
    )
    assert confidence_calibration(reversed_findings, reversed_plants) == confidence_calibration(
        findings,
        plants,
    )


def test_plant_recall_no_positives_is_vacuously_perfect():
    assert plant_recall([], [_finding()]) == 1.0


def test_plant_recall_counts_covered_plants():
    positives = [_plant(start=0, end=5), _plant(start=100, end=105)]
    findings = [_finding(start=0, end=5)]
    assert plant_recall(positives, findings) == 0.5


def test_f1_score_harmonic_mean():
    assert abs(f1_score(1.0, 1.0) - 1.0) < 1e-9
    assert f1_score(0.0, 0.0) == 0.0
    assert abs(f1_score(0.5, 0.5) - 0.5) < 1e-9


def test_evaluate_reports_tier_a_precision_and_rescue_recall():
    plants = [
        _plant(file="a.txt", start=0, end=5, is_positive=True),  # caught at Tier A
        _plant(file="a.txt", start=50, end=55, is_positive=True),  # only caught at Tier B
        _plant(file="a.txt", start=90, end=95, is_positive=False),  # decoy, wrongly Tier A
    ]
    findings = [
        _finding(file="a.txt", start=0, end=5, tier="A", confidence=0.95),
        _finding(file="a.txt", start=50, end=55, tier="B", confidence=0.5),
        _finding(file="a.txt", start=90, end=95, tier="A", confidence=0.8),
    ]
    result = evaluate(findings, plants)
    assert result["num_positive_plants"] == 2
    assert result["num_decoy_plants"] == 1
    assert abs(result["tier_a_precision"] - 0.5) < 1e-9  # 1 of 2 Tier A findings is real
    assert abs(result["tier_a_recall"] - 0.5) < 1e-9  # 1 of 2 positives caught at Tier A
    assert result["any_tier_recall"] == 1.0  # both positives caught somewhere
    assert abs(result["tier_b_rescue_recall"] - 0.5) < 1e-9


def test_threshold_sweep_uses_confidence_not_precomputed_tier():
    plants = [_plant(file="a.txt", start=0, end=5, is_positive=True)]
    # tier says "B" but confidence is high -- sweep must trust confidence.
    findings = [_finding(file="a.txt", start=0, end=5, tier="B", confidence=0.9)]
    rows = threshold_sweep(findings, plants, [0.5, 0.95])
    assert rows[0]["recall"] == 1.0  # 0.9 >= 0.5
    assert rows[1]["recall"] == 0.0  # 0.9 < 0.95


def test_threshold_sweep_keeps_broad_duplicates_in_denominator_without_extra_recall():
    positives = [
        _plant(start=2, end=4, case_id="left"),
        _plant(start=6, end=8, case_id="right"),
    ]
    findings = [
        _finding(start=0, end=10, confidence=0.9, detector_id="broad_primary"),
        _finding(start=0, end=10, confidence=0.8, detector_id="broad_duplicate"),
    ]

    rows = threshold_sweep(findings, positives, [0.5, 0.85])

    assert rows[0]["num_findings_at_or_above"] == 2
    assert rows[0]["true_positive_findings"] == 1
    assert rows[0]["false_positive_findings"] == 1
    assert rows[0]["precision"] == 0.5
    assert rows[0]["recall"] == 0.5
    assert rows[1]["num_findings_at_or_above"] == 1
    assert rows[1]["precision"] == 1.0
    assert rows[1]["recall"] == 0.5


def test_select_threshold_uses_only_precision_eligible_calibration_rows():
    rows = [
        {"threshold": 0.5, "precision": 0.7, "recall": 1.0},
        {"threshold": 0.75, "precision": 0.95, "recall": 0.9},
        {"threshold": 0.9, "precision": 1.0, "recall": 0.6},
    ]

    assert select_threshold(rows, minimum_precision=0.9) == 0.75


def test_select_threshold_fails_when_no_row_meets_the_precision_gate():
    rows = [
        {"threshold": 0.5, "precision": 0.5, "recall": 1.0},
        {"threshold": 0.9, "precision": 0.8, "recall": 0.5},
    ]

    with pytest.raises(ValueError, match="no calibration threshold"):
        select_threshold(rows, minimum_precision=0.9)


def test_select_threshold_fails_for_an_empty_sweep():
    with pytest.raises(ValueError, match="empty calibration sweep"):
        select_threshold([], minimum_precision=0.9)


def test_detector_breakdown_reports_supporting_signal_consolidation():
    plants = [
        _plant(detector_id="high_entropy_secret"),
        _plant(start=20, end=25, detector_id="password_assignment"),
    ]
    findings = [
        _finding(
            detector_id="aws_access_key",
            supporting_detector_ids=("high_entropy_secret",),
        ),
        _finding(start=100, end=105, detector_id="high_entropy_secret"),
    ]
    raw_opinions = [
        _finding(detector_id="aws_access_key"),
        _finding(detector_id="high_entropy_secret", confidence=0.9),
        _finding(detector_id="high_entropy_secret", confidence=0.8),
        _finding(start=100, end=105, detector_id="high_entropy_secret"),
    ]

    result = detector_breakdown(
        findings,
        plants,
        raw_opinion_counts={
            "aws_access_key": 1,
            "high_entropy_secret": 3,
            "password_assignment": 0,
        },
        raw_opinions=raw_opinions,
    )

    assert result["aws_access_key"]["emitted_findings"] == 1
    assert result["aws_access_key"]["canonical_contributions"] == 1
    assert result["aws_access_key"]["precision"] == 1.0
    assert result["high_entropy_secret"]["recall"] == 1.0
    assert result["high_entropy_secret"]["precision"] == pytest.approx(1 / 3)
    assert result["high_entropy_secret"]["false_positives"] == 2
    assert result["high_entropy_secret"]["canonical_contributions"] == 2
    assert result["high_entropy_secret"]["canonical_precision"] == 0.5
    assert result["high_entropy_secret"]["canonical_false_positives"] == 1
    assert result["password_assignment"]["false_negatives"] == 1
    assert result["high_entropy_secret"]["raw_opinions"] == 3
    assert result["high_entropy_secret"]["raw_opinions_complete"] is True
    assert result["high_entropy_secret"]["consolidated_opinions"] == 2
    assert result["high_entropy_secret"]["unrepresented_raw_opinions"] == 1
    assert result["high_entropy_secret"]["consolidation_rate"] == pytest.approx(2 / 3)


def test_detector_breakdown_uses_raw_category_instead_of_canonical_support_geometry():
    plants = [
        _plant(
            start=10,
            end=20,
            category="credential",
            detector_id="connection_string",
        )
    ]
    findings = [
        _finding(
            start=0,
            end=30,
            detector_id="connection_string",
            category="credential",
            supporting_detector_ids=("email",),
        )
    ]
    raw_opinions = [
        _finding(
            start=0,
            end=30,
            detector_id="connection_string",
            category="credential",
        ),
        _finding(
            start=5,
            end=25,
            detector_id="email",
            category="personal_id",
        ),
    ]

    result = detector_breakdown(
        findings,
        plants,
        {"connection_string": 1, "email": 1},
        raw_opinions=raw_opinions,
    )

    assert result["email"]["precision"] == 0.0
    assert result["email"]["false_positives"] == 1
    assert result["email"]["canonical_precision"] == 1.0
    assert result["email"]["canonical_false_positives"] == 0
    assert result["email"]["emitted_findings"] == 0
    assert result["email"]["canonical_contributions"] == 1
    assert result["email"]["consolidated_opinions"] == 1
    assert result["email"]["unrepresented_raw_opinions"] == 0
    assert result["email"]["consolidation_rate"] == 1.0


def test_detector_breakdown_labels_observable_raw_fallback_incomplete():
    findings = [
        _finding(
            detector_id="aws_access_key",
            supporting_detector_ids=("high_entropy_secret",),
        )
    ]

    result = detector_breakdown(findings, [_plant(detector_id="aws_access_key")])

    assert result["high_entropy_secret"]["raw_opinions"] == 1
    assert result["high_entropy_secret"]["raw_opinions_complete"] is False
    assert result["high_entropy_secret"]["canonical_contributions"] == 1


def test_detector_breakdown_keeps_known_zero_activity_detectors_visible():
    result = detector_breakdown(
        [_finding(detector_id="aws_access_key")],
        [_plant(detector_id="aws_access_key")],
        detector_ids={"aws_access_key", "never_emitted"},
    )

    assert set(result) == {"aws_access_key", "never_emitted"}
    assert result["never_emitted"]["raw_opinions"] == 0
    assert result["never_emitted"]["emitted_findings"] == 0
    assert result["never_emitted"]["expected_plants"] == 0


def test_detector_breakdown_rejects_impossible_raw_counts():
    finding = _finding(
        detector_id="aws_access_key",
        supporting_detector_ids=("high_entropy_secret",),
    )

    with pytest.raises(ValueError, match="below its observable opinions"):
        detector_breakdown(
            [finding],
            [_plant(detector_id="aws_access_key")],
            raw_opinion_counts={"aws_access_key": 1, "high_entropy_secret": 0},
        )


def test_category_breakdown_separates_quality_by_expected_category():
    plants = [
        _plant(category="credential"),
        _plant(start=20, end=25, category="personal_id", detector_id="us_ssn"),
    ]
    findings = [_finding(category="credential")]

    result = category_breakdown(findings, plants)

    assert result["credential"]["recall"] == 1.0
    assert result["personal_id"]["recall"] == 0.0


def test_category_breakdown_does_not_credit_an_overlapping_wrong_category():
    plants = [_plant(category="personal_id", detector_id="us_ssn")]
    findings = [_finding(category="credential", detector_id="password_assignment")]

    result = category_breakdown(findings, plants)

    assert result["credential"]["precision"] == 0.0
    assert result["credential"]["false_positives"] == 1
    assert result["personal_id"]["recall"] == 0.0
    assert result["personal_id"]["false_negatives"] == 1


def test_confidence_calibration_reports_brier_ece_and_buckets():
    plants = [_plant(start=0, end=5)]
    findings = [
        _finding(start=0, end=5, confidence=0.9),
        _finding(start=20, end=25, confidence=0.8),
    ]

    result = confidence_calibration(findings, plants)

    assert abs(result["brier_score"] - 0.325) < 1e-9
    assert abs(result["expected_calibration_error"] - 0.45) < 1e-9
    assert sum(bucket["count"] for bucket in result["buckets"]) == 2


def test_confidence_calibration_penalizes_duplicate_predictions():
    plants = [_plant(start=0, end=5)]
    findings = [
        _finding(start=0, end=5, confidence=0.9, detector_id="password_assignment"),
        _finding(start=0, end=5, confidence=0.8, detector_id="high_entropy_secret"),
    ]

    result = confidence_calibration(findings, plants)

    assert result["brier_score"] == pytest.approx(0.325)
    assert sum(bucket["accuracy"] * bucket["count"] for bucket in result["buckets"]) == 1.0


def test_confidence_calibration_penalizes_broad_duplicates_across_multiple_plants():
    plants = [
        _plant(start=2, end=4, case_id="left"),
        _plant(start=6, end=8, case_id="right"),
    ]
    findings = [
        _finding(start=0, end=10, confidence=0.9, detector_id="broad_primary"),
        _finding(start=0, end=10, confidence=0.8, detector_id="broad_duplicate"),
    ]

    result = confidence_calibration(findings, plants)

    assert result["brier_score"] == pytest.approx(0.325)
    assert sum(bucket["count"] for bucket in result["buckets"]) == 2
    assert sum(bucket["accuracy"] * bucket["count"] for bucket in result["buckets"]) == 1.0


def test_user_impact_metrics_normalize_false_positives_by_all_files():
    plants = [_plant()]
    findings = [_finding(), _finding(start=20, end=25)]

    result = user_impact_metrics(findings, plants, num_files=100)

    assert result["false_positives_per_1000_files"] == 10.0
    assert result["canonical_findings_per_planted_value"] == 2.0
