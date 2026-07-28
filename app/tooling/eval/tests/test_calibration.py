from types import SimpleNamespace

import pytest
from redactlens_core.registry import ConfidenceWeightProfile

from calibration import confidence_profile_data, select_weight_profile, threshold_candidates
from metrics import FindingLike, Plant, threshold_sweep


def test_threshold_candidates_cover_all_observed_boundaries_and_endpoints():
    findings = [
        SimpleNamespace(confidence=0.97),
        SimpleNamespace(confidence=1.0),
        SimpleNamespace(confidence=0.42),
        SimpleNamespace(confidence=0.9500000000000001),
    ]

    assert threshold_candidates(findings, preferred_threshold=0.85) == [
        0.0,
        0.42,
        0.85,
        0.9500000000000001,
        0.97,
        1.0,
    ]


@pytest.mark.parametrize("confidence", [float("nan"), float("inf"), -0.1, 1.1])
def test_threshold_candidates_reject_invalid_confidence(confidence):
    with pytest.raises(ValueError, match="finite confidence"):
        threshold_candidates(
            [SimpleNamespace(confidence=confidence)],
            preferred_threshold=0.85,
        )


@pytest.mark.parametrize("preferred_threshold", [float("nan"), float("inf"), -0.1, 1.1])
def test_threshold_candidates_reject_invalid_preferred_threshold(preferred_threshold):
    with pytest.raises(ValueError, match="preferred threshold"):
        threshold_candidates([], preferred_threshold=preferred_threshold)


def test_threshold_candidates_preserve_an_upward_rounded_inclusive_boundary():
    confidence = 0.3 + 0.6
    finding = FindingLike("a.txt", 0, 5, "A", confidence, category="credential")
    plant = Plant("a.txt", 0, 5, "credential", True)

    candidates = threshold_candidates([finding], preferred_threshold=0.85)
    exact_row = threshold_sweep([finding], [plant], [confidence])[0]
    rounded_row = threshold_sweep([finding], [plant], [round(confidence, 12)])[0]

    assert confidence in candidates
    assert exact_row["num_findings_at_or_above"] == 1
    assert rounded_row["num_findings_at_or_above"] == 0


def test_weight_selection_uses_calibration_loss_then_quality_and_deployed_tie_break():
    def row(profile_id, brier, ece, recall=0.8, precision=0.9, eligible=True):
        return {
            "profile": {
                "profile_id": profile_id,
                "base_offset": 0.0,
                "context_scale": 1.0,
            },
            "eligible": eligible,
            "selected_threshold": 0.85,
            "threshold_precision": precision,
            "threshold_recall": recall,
            "brier_score": brier,
            "expected_calibration_error": ece,
        }

    selected = select_weight_profile(
        [
            row("worse-loss", 0.20, 0.10, recall=1.0, precision=1.0),
            row("challenger", 0.10, 0.10),
            row("deployed", 0.10, 0.10),
            row("ineligible", 0.0, 0.0, eligible=False),
        ],
        deployed_profile_id="deployed",
    )

    assert selected["profile"]["profile_id"] == "deployed"


def test_weight_selection_does_not_round_away_a_strictly_better_loss():
    def row(profile_id, loss):
        return {
            "profile": {
                "profile_id": profile_id,
                "base_offset": 0.0,
                "context_scale": 1.0,
            },
            "eligible": True,
            "selected_threshold": 0.85,
            "threshold_precision": 1.0,
            "threshold_recall": 1.0,
            "brier_score": loss,
            "expected_calibration_error": 0.0,
        }

    selected = select_weight_profile(
        [row("deployed", 0.2 + 4e-16), row("strictly-better", 0.2)],
        deployed_profile_id="deployed",
    )

    assert selected["profile"]["profile_id"] == "strictly-better"


def test_weight_selection_fails_without_an_eligible_profile():
    with pytest.raises(ValueError, match="no confidence-weight profile"):
        select_weight_profile(
            [{"eligible": False}],
            deployed_profile_id="deployed",
        )


def test_confidence_profile_data_is_closed_and_serializable():
    profile = ConfidenceWeightProfile("example", base_offset=-0.05, context_scale=1.25)

    assert confidence_profile_data(profile) == {
        "profile_id": "example",
        "base_offset": -0.05,
        "context_scale": 1.25,
    }
