"""Turns ScanRequest.user_targets into detectors, injected at scan time.

A user-defined target is just another detector — the same scoring/tiering
path handles it, no special-casing downstream. It is never added to a shared
DetectorRegistry (that would leak state across scans on a long-lived
registry, e.g. in the API server); scanner.py builds this list fresh per
request instead.
"""

from redactlens_core.models import UserTarget
from redactlens_core.registry import DetectorDef

# The user explicitly told us this value matters to them, so it starts high
# confidence regardless of surrounding context (no boosters/suppressors).
USER_TARGET_BASE_CONFIDENCE = 0.95


def user_target_detectors(user_targets: list[UserTarget]) -> list[DetectorDef]:
    detectors = []
    for i, target in enumerate(user_targets):
        if target.kind != "literal":
            continue  # "description" targets need the LLM adapter — see Phase 5
        detectors.append(
            DetectorDef(
                id=f"user_target_{i}",
                category=target.category,
                description="A value you told RedactLens to watch for.",
                risk_lesson=(
                    "You flagged this value yourself, so RedactLens treats any match as "
                    "high-confidence."
                ),
                method="keyword",
                pattern=target.value,
                base_confidence=USER_TARGET_BASE_CONFIDENCE,
                specificity=200,
                max_match_length=len(target.value),
            )
        )
    return detectors
