"""Pure, deterministic calibration policy for Phase 4 evaluation."""

from __future__ import annotations

import math
from typing import Any, Protocol

from redactlens_core.registry import ConfidenceWeightProfile


class FindingConfidence(Protocol):
    confidence: float


CALIBRATION_WEIGHT_PROFILES = tuple(
    ConfidenceWeightProfile(
        profile_id=f"base{base_offset:+.2f}-contextx{context_scale:.2f}-v1",
        base_offset=base_offset,
        context_scale=context_scale,
    )
    for base_offset in (-0.05, 0.0, 0.05)
    for context_scale in (0.75, 1.0, 1.25)
)


def threshold_candidates(
    findings: list[FindingConfidence],
    *,
    preferred_threshold: float,
) -> list[float]:
    """Return every cutoff that can produce a distinct prediction set.

    With the evaluator's inclusive ``confidence >= threshold`` rule, each
    distinct observed confidence is a decision boundary.  Zero, one, and the
    deployed preference are retained explicitly so empty/full boundary
    behavior and deployment consistency remain visible.
    """

    values = {0.0, 1.0, preferred_threshold}
    if not math.isfinite(preferred_threshold) or not 0.0 <= preferred_threshold <= 1.0:
        raise ValueError("preferred threshold must be finite and in [0, 1]")
    for finding in findings:
        confidence = float(finding.confidence)
        if not math.isfinite(confidence) or not 0.0 <= confidence <= 1.0:
            raise ValueError("calibration findings must have finite confidence in [0, 1]")
        # Keep the exact evaluated float. Rounding only the cutoff can move it
        # above an inclusive finding boundary and silently omit a prediction
        # set (for example, 0.3 + 0.6 is below the rounded value 0.9).
        values.add(confidence)
    return sorted(values)


def confidence_profile_data(profile: ConfidenceWeightProfile) -> dict[str, Any]:
    return {
        "profile_id": profile.profile_id,
        "base_offset": profile.base_offset,
        "context_scale": profile.context_scale,
    }


def select_weight_profile(
    rows: list[dict[str, Any]],
    *,
    deployed_profile_id: str,
) -> dict[str, Any]:
    """Select weights using calibration outcomes only.

    Brier score and expected calibration error measure complementary aspects
    of confidence quality, so their sum is the primary loss.  Threshold recall
    and precision break quality-loss ties.  The deployed profile is retained
    only on a genuinely identical best plateau, followed by a stable profile
    id tie-break.
    """

    eligible = [row for row in rows if row.get("eligible") is True]
    if not eligible:
        raise ValueError("no confidence-weight profile has an eligible calibration threshold")

    def key(row: dict[str, Any]) -> tuple[float, float, float, int, str]:
        loss = float(row["brier_score"]) + float(row["expected_calibration_error"])
        return (
            loss,
            -float(row["threshold_recall"]),
            -float(row["threshold_precision"]),
            0 if row["profile"]["profile_id"] == deployed_profile_id else 1,
            str(row["profile"]["profile_id"]),
        )

    return min(eligible, key=key)
