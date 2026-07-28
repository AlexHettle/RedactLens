"""LLM-only scan path for user-defined "description" targets -- plain-English
criteria ("anything that looks like an employee ID") interpreted per-line by
the local model, since there's no regex/entropy method for free text.

Bounded to the first MAX_LINES_PER_FILE non-blank lines per file, with each
physical line capped at MAX_DESCRIPTION_LINE_CHARS: deliberate, disclosed v1
scope trims rather than silent unbounded model inputs. Real-time per-line LLM
calls against a local model don't scale to arbitrarily large files, and this
feature is explicitly a demo-oriented differentiator, not a bulk-scan path.
"""

from collections.abc import Callable

from redactlens_core.consolidation import ScoredDetection
from redactlens_core.llm.adapter import LLMVerdict, OllamaAdapter
from redactlens_core.models import Finding, UserTarget
from redactlens_core.redact import redacted_preview
from redactlens_core.registry import DetectorDef
from redactlens_core.text_position import line_col, stable_id

MAX_LINES_PER_FILE = 40
MAX_DESCRIPTION_LINE_CHARS = 16_384
DESCRIPTION_TARGET_SPECIFICITY = 0
DESCRIPTION_TARGET_EXPLANATION = "A local AI model matched this against a description you provided."
DESCRIPTION_TARGET_RISK_LESSON = (
    "This matched a user-defined description and may need careful review."
)


def scan_description_targets(
    text: str,
    file_path: str,
    targets: list[UserTarget],
    adapter: OllamaAdapter,
    tier_threshold: float,
    checkpoint: Callable[[], None] | None = None,
) -> list[Finding]:
    """Return standalone findings for the legacy description-target API.

    Scan orchestration uses :func:`scan_description_detections` so these
    model opinions can participate in per-file canonical consolidation. This
    wrapper preserves the public ``Finding`` return type and stable-id scheme
    for direct callers. Unlocalized whole-line opinions are review-only.
    """
    return [
        _standalone_finding(detection)
        for detection in scan_description_detections(
            text,
            file_path,
            targets,
            adapter,
            tier_threshold,
            checkpoint,
        )
    ]


def scan_description_detections(
    text: str,
    file_path: str,
    targets: list[UserTarget],
    adapter: OllamaAdapter,
    tier_threshold: float,
    checkpoint: Callable[[], None] | None = None,
    *,
    can_anonymize: bool = False,
) -> list[ScoredDetection]:
    """Return description-target model opinions before consolidation.

    Scanner orchestration opts rewriteable sources into remediation. Direct
    legacy callers remain review-only unless they explicitly provide that
    source capability.
    """
    detections = []
    offset = 0
    checked = 0
    for line in text.split("\n"):
        if checkpoint is not None:
            checkpoint()
        stripped = line.strip()
        if stripped and checked < MAX_LINES_PER_FILE:
            checked += 1
            if len(line) > MAX_DESCRIPTION_LINE_CHARS:
                offset += len(line) + 1
                continue
            local_start = line.find(stripped)
            start = offset + local_start
            end = start + len(stripped)
            detections.extend(
                _judge_span(
                    text,
                    file_path,
                    start,
                    end,
                    stripped,
                    targets,
                    adapter,
                    tier_threshold,
                    checkpoint,
                    can_anonymize,
                )
            )
        offset += len(line) + 1
    return detections


def _judge_span(
    text: str,
    file_path: str,
    start: int,
    end: int,
    snippet: str,
    targets: list[UserTarget],
    adapter: OllamaAdapter,
    tier_threshold: float,
    checkpoint: Callable[[], None] | None,
    can_anonymize: bool,
) -> list[ScoredDetection]:
    detections = []
    line_no, column = line_col(text, start)

    for i, target in enumerate(targets):
        if checkpoint is not None:
            checkpoint()
        verdict = adapter.judge(_prompt(snippet, target.value))
        if verdict is None or not verdict.is_sensitive:
            continue
        tier = "A" if verdict.confidence >= tier_threshold else "B"
        detector_id = f"user_target_desc_{i}"
        detector = DetectorDef(
            id=detector_id,
            category=target.category,
            # The free-form target remains internal in ``pattern`` and in the
            # model prompt. It must not be repeated in public explanatory copy:
            # users commonly include a real example in a description, and that
            # example can be the exact source value the finding is masking.
            description=DESCRIPTION_TARGET_EXPLANATION,
            # Model explanations are untrusted and may repeat the raw source
            # snippet. Keep them in internal evidence only; risk_lesson is
            # projected into browser-facing findings and must be fixed copy.
            risk_lesson=DESCRIPTION_TARGET_RISK_LESSON,
            # Description targets are model-generated opinions, not keyword
            # matches. DetectorDef has no LLM method because it is declarative
            # detector metadata, so use an inert valid method/pattern here;
            # scanner.py never dispatches it through a detection method.
            method="keyword",
            pattern=target.value,
            base_confidence=verdict.confidence,
            specificity=DESCRIPTION_TARGET_SPECIFICITY,
            max_match_length=max(1, min(len(snippet), 1_048_576)),
        )
        detections.append(
            ScoredDetection(
                file_path=file_path,
                line=line_no,
                column=column,
                start_offset=start,
                end_offset=end,
                matched_text=snippet,
                redacted_preview=redacted_preview(snippet),
                location=None,
                # Description matching returns the exact non-blank passage
                # shown to the model. On rewriteable sources the user may
                # intentionally redact that complete passage; read-only
                # source formats remain ineligible.
                can_anonymize=can_anonymize,
                detector=detector,
                confidence=verdict.confidence,
                tier=tier,
                evidence={"llm_reason": verdict.reason, "llm_confidence": verdict.confidence},
                origin="user_target",
                category_selected=True,
                primary_priority=-1,
            )
        )
    return detections


def standalone_finding(detection: ScoredDetection) -> Finding:
    """Project one unreconciled description opinion to its legacy finding."""
    return _standalone_finding(detection)


def confirm_description_match(
    detection: ScoredDetection,
    snippet: str,
    adapter: OllamaAdapter,
    checkpoint: Callable[[], None] | None = None,
) -> LLMVerdict | None:
    """Confirm that a narrower deterministic match is the described concept.

    A description opinion covers an entire line. Before it supports the only
    canonical detector found inside that line, ask the model about that exact
    actionable span so an unrelated email (for example) is not absorbed into
    an employee-ID opinion merely because both occur on the same line.
    """
    if checkpoint is not None:
        checkpoint()
    description = detection.detector.pattern
    if not description:
        return None
    verdict = adapter.judge(_prompt(snippet, description))
    if verdict is None or not verdict.is_sensitive:
        return None
    return verdict


def _standalone_finding(detection: ScoredDetection) -> Finding:
    return Finding(
        id=stable_id(detection.file_path, detection.start_offset, detection.detector.id),
        file_path=detection.file_path,
        line=detection.line,
        column=detection.column,
        start_offset=detection.start_offset,
        end_offset=detection.end_offset,
        location=detection.location,
        can_anonymize=detection.can_anonymize,
        matched_text=detection.matched_text,
        redacted_preview=detection.redacted_preview,
        detector_id=detection.detector.id,
        category=detection.detector.category,
        confidence=detection.confidence,
        tier=detection.tier,
        explanation=detection.detector.description,
        risk_lesson=detection.detector.risk_lesson,
        suggested_action=(
            "anonymize" if detection.can_anonymize and detection.tier == "A" else "review"
        ),
        evidence=detection.evidence,
    )


def _prompt(snippet: str, description: str) -> str:
    # The adapter's system prompt frames every judge() call as an
    # independent "is this sensitive" assessment, which is right for the
    # mid-band confidence adjuster but wrong here: the user already told us
    # this description matters to them (same principle as literal targets,
    # which skip a sensitivity gate entirely). Without this framing the
    # model correctly recognizes a match ("contains a numerical value") but
    # still says is_sensitive=false because the match itself isn't
    # inherently sensitive -- so we have to explicitly override that.
    return (
        f'The user told RedactLens to watch for: "{description}". They already consider '
        "anything matching that description worth flagging -- this is NOT an independent "
        "judgment about whether it's generally sensitive.\n"
        f'Text: "{snippet}"\n'
        "Set is_sensitive=true if the text matches what the user described, even if you "
        "wouldn't otherwise consider it sensitive on its own. Set is_sensitive=false only "
        "if the text does not match the description at all."
    )
