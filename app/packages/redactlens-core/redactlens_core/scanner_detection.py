"""Construction of scored detector opinions from raw match candidates."""

from __future__ import annotations

from redactlens_core.consolidation import ScoredDetection
from redactlens_core.files import Scannable, TextChunk
from redactlens_core.methods import MatchCandidate
from redactlens_core.redact import redacted_preview
from redactlens_core.registry import DetectorDef
from redactlens_core.scan_results import _global_line_col
from redactlens_core.scanner_support import _DetectionOrigin
from redactlens_core.scoring import score_match
from redactlens_core.text_position import line_col


def _build_detection(
    detector: DetectorDef,
    candidate: MatchCandidate,
    scannable: Scannable,
    file_path: str,
    tier_threshold: float,
    llm_adapter,
    *,
    origin: _DetectionOrigin,
    category_selected: bool,
    chunk: TextChunk | None = None,
) -> ScoredDetection:
    text = scannable.text
    confidence, evidence = score_match(
        detector,
        candidate.text,
        text,
        file_path,
        candidate.start,
        candidate.end,
        llm_adapter=llm_adapter,
    )
    tier = "A" if confidence >= tier_threshold else "B"
    if chunk is None:
        line, column = line_col(text, candidate.start)
        start_offset = candidate.start
        end_offset = candidate.end
    else:
        line, column = _global_line_col(chunk, candidate.start)
        start_offset = chunk.start_offset + candidate.start
        end_offset = chunk.start_offset + candidate.end

    return ScoredDetection(
        file_path=file_path,
        line=line,
        column=column,
        start_offset=start_offset,
        end_offset=end_offset,
        location=scannable.location_at(candidate.start),
        can_anonymize=scannable.can_anonymize,
        matched_text=candidate.text,
        redacted_preview=redacted_preview(candidate.text),
        detector=detector,
        confidence=confidence,
        tier=tier,
        evidence=evidence,
        origin=origin,
        category_selected=category_selected,
        primary_priority=1 if origin == "user_target" else 0,
    )
