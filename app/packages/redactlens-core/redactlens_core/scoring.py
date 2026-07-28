"""The confidence model: continuous score in, evidence trail out.

Tiering itself (the A/B split) is a thin presentation step on top of this —
see scanner.py, where `tier = "A" if confidence >= tier_threshold else "B"`.
Keep that one-liner there rather than here, so this module only ever has to
reason about the continuous score.
"""

from redactlens_core.llm.adapter import OllamaAdapter
from redactlens_core.methods.regex import search_pattern
from redactlens_core.registry import ContextAdjustment, DetectorDef
from redactlens_core.validators import VALIDATORS

DEFAULT_CONTEXT_WINDOW = 100

# Only candidates already this ambiguous get sent to the LLM -- it's a
# confidence adjuster for the gray zone, not a second pass over everything.
LLM_BAND_LOW = 0.45
LLM_BAND_HIGH = 0.80


def score_match(
    detector: DetectorDef,
    matched_text: str,
    file_text: str,
    file_path: str,
    start: int,
    end: int,
    context_window: int = DEFAULT_CONTEXT_WINDOW,
    llm_adapter: OllamaAdapter | None = None,
) -> tuple[float, dict]:
    """Score one candidate match. Returns (confidence, evidence)."""
    window_start = max(0, start - context_window)
    window_end = min(len(file_text), end + context_window)
    context_text = file_text[window_start:window_end]

    confidence = detector.base_confidence
    evidence: dict = {"base_confidence": detector.base_confidence, "signals": []}

    for label, adjustments in (
        ("booster", detector.context.boosters),
        ("suppressor", detector.context.suppressors),
    ):
        for adj in adjustments:
            if not _adjustment_applies(adj, context_text, file_path, matched_text):
                continue
            confidence += adj.weight
            evidence["signals"].append(
                {
                    "kind": label,
                    "condition": _describe(adj),
                    "weight": adj.weight,
                }
            )

    confidence = max(0.0, min(1.0, confidence))

    if llm_adapter is not None and LLM_BAND_LOW <= confidence <= LLM_BAND_HIGH:
        verdict = llm_adapter.judge(_llm_prompt(detector, matched_text, context_text, file_path))
        if verdict is not None:
            confidence = (confidence + verdict.confidence) / 2
            evidence["signals"].append(
                {
                    "kind": "llm",
                    "condition": verdict.reason,
                    "llm_confidence": verdict.confidence,
                }
            )

    clamped = max(0.0, min(1.0, confidence))
    evidence["raw_confidence"] = confidence
    return clamped, evidence


def _llm_prompt(detector: DetectorDef, matched_text: str, context_text: str, file_path: str) -> str:
    return (
        f"File path: {file_path}\n"
        f"Surrounding text:\n{context_text}\n\n"
        f'The exact candidate value found: "{matched_text}"\n'
        f'This was flagged as a possible "{detector.description}" ({detector.category}). '
        "Considering the surrounding context -- does it look like a real value, or a "
        "placeholder/test/example value -- is this genuinely sensitive?"
    )


def _adjustment_applies(
    adj: ContextAdjustment, context_text: str, file_path: str, matched_text: str
) -> bool:
    if adj.pattern is not None:
        result = search_pattern(adj.pattern, context_text)
    elif adj.in_path is not None:
        result = search_pattern(adj.in_path, file_path)
    else:
        result = VALIDATORS[adj.validator](matched_text)
    return (not result) if adj.invert else result


def _describe(adj: ContextAdjustment) -> str:
    if adj.pattern is not None:
        return f"pattern:{adj.pattern}" + (" (inverted)" if adj.invert else "")
    if adj.in_path is not None:
        return f"in_path:{adj.in_path}" + (" (inverted)" if adj.invert else "")
    return f"validator:{adj.validator}" + (" (inverted)" if adj.invert else "")
