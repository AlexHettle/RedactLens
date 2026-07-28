from fakes import FakeAdapter
from redactlens_core.llm.adapter import LLMVerdict
from redactlens_core.llm.description_targets import (
    DESCRIPTION_TARGET_RISK_LESSON,
    MAX_LINES_PER_FILE,
    _prompt,
    scan_description_targets,
)
from redactlens_core.models import UserTarget


def test_matching_line_produces_a_finding():
    text = "employee id: EMP-99213\nunrelated line here\n"
    targets = [UserTarget(kind="description", value="an employee ID", category="custom")]
    adapter = FakeAdapter(
        verdict=lambda q: LLMVerdict(
            is_sensitive="EMP-99213" in q,
            confidence=0.9,
            reason="Matched raw value EMP-99213",
        )
    )

    findings = scan_description_targets(text, "notes.txt", targets, adapter, tier_threshold=0.75)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.tier == "A"
    assert finding.category == "custom"
    assert finding.matched_text == "employee id: EMP-99213"
    assert finding.detector_id == "user_target_desc_0"
    assert finding.risk_lesson == DESCRIPTION_TARGET_RISK_LESSON
    assert finding.evidence["llm_reason"] == "Matched raw value EMP-99213"


def test_non_matching_lines_produce_no_findings():
    text = "just a normal sentence\nanother normal one\n"
    targets = [UserTarget(kind="description", value="an employee ID")]
    adapter = FakeAdapter(verdict=LLMVerdict(is_sensitive=False, confidence=0.1, reason="no match"))

    findings = scan_description_targets(text, "notes.txt", targets, adapter, tier_threshold=0.75)

    assert findings == []


def test_low_confidence_match_lands_tier_b():
    text = "maybe an id: XJ-1\n"
    targets = [UserTarget(kind="description", value="an employee ID")]
    adapter = FakeAdapter(verdict=LLMVerdict(is_sensitive=True, confidence=0.5, reason="uncertain"))

    findings = scan_description_targets(text, "notes.txt", targets, adapter, tier_threshold=0.75)

    assert len(findings) == 1
    assert findings[0].tier == "B"


def test_respects_max_lines_per_file_cap():
    text = "\n".join(f"line {i} with content" for i in range(MAX_LINES_PER_FILE + 20))
    targets = [UserTarget(kind="description", value="anything")]
    adapter = FakeAdapter(verdict=LLMVerdict(is_sensitive=True, confidence=0.9, reason="match"))

    scan_description_targets(text, "notes.txt", targets, adapter, tier_threshold=0.75)

    assert len(adapter.calls) == MAX_LINES_PER_FILE


def test_blank_lines_are_skipped_without_calling_the_adapter():
    text = "\n\n   \n"
    targets = [UserTarget(kind="description", value="anything")]
    adapter = FakeAdapter(verdict=LLMVerdict(is_sensitive=True, confidence=0.9, reason="match"))

    findings = scan_description_targets(text, "notes.txt", targets, adapter, tier_threshold=0.75)

    assert findings == []
    assert adapter.calls == []


def test_prompt_overrides_the_independent_sensitivity_framing():
    """Regression test: a real model given the adapter's default system
    prompt ("you are a sensitive-data reviewer") will correctly recognize a
    match (e.g. "contains a numerical value") but still answer
    is_sensitive=false, because the match itself isn't inherently sensitive
    on its own. Description targets must override that -- the user already
    told us this description matters to them, same as literal targets
    skipping a sensitivity gate entirely. This can't be caught by a
    FakeAdapter test (it doesn't run a real model), so pin the prompt
    wording that fixes it instead.
    """
    prompt = _prompt("#36", "any numerical value")
    assert "even if you wouldn't otherwise consider it sensitive on its own" in prompt
    assert "any numerical value" in prompt
    assert "#36" in prompt
