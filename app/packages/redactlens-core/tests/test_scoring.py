from fakes import FakeAdapter
from redactlens_core.llm.adapter import LLMVerdict
from redactlens_core.registry import DetectorDef, load_default_registry
from redactlens_core.scoring import score_match


def _detector(**overrides) -> DetectorDef:
    base = dict(
        id="test_detector",
        category="custom",
        description="desc",
        risk_lesson="risk",
        method="regex",
        pattern=r"\d+",
        base_confidence=0.5,
        context={},
    )
    base.update(overrides)
    return DetectorDef.model_validate(base)


def test_booster_pattern_raises_confidence():
    detector = _detector(
        base_confidence=0.5,
        context={"boosters": [{"pattern": "ssn", "weight": 0.2}]},
    )
    confidence, evidence = score_match(detector, "123", "my ssn is 123", "f.txt", 10, 13)
    assert confidence == 0.7
    assert evidence["signals"][0]["kind"] == "booster"


def test_suppressor_in_path_lowers_confidence():
    detector = _detector(
        base_confidence=0.8,
        context={"suppressors": [{"in_path": r"\btest\b", "weight": -0.3}]},
    )
    confidence, _ = score_match(detector, "123", "value 123", "project/test/file.txt", 6, 9)
    assert abs(confidence - 0.5) < 1e-9


def test_calibrated_placeholder_and_migration_contexts_stay_below_tier_a():
    registry = load_default_registry()
    cases = [
        (
            "password_assignment",
            "replace-before-use-AbCdEf123456",
            "ADMIN_PASSWORD=replace-before-use-AbCdEf123456 # documentation placeholder",
            0.30,
        ),
        (
            "us_ssn",
            "321-45-6789",
            "migration_reference = 321-45-6789 # legacy report identifier, not a person",
            0.35,
        ),
    ]

    for detector_id, matched_text, file_text, expected in cases:
        start = file_text.index(matched_text)
        confidence, _ = score_match(
            registry.get(detector_id),
            matched_text,
            file_text,
            "project/config.txt",
            start,
            start + len(matched_text),
        )
        assert abs(confidence - expected) < 1e-9


def test_validator_suppressor_with_invert_fires_on_failure():
    detector = _detector(
        base_confidence=0.6,
        context={"suppressors": [{"validator": "luhn", "invert": True, "weight": -0.4}]},
    )
    confidence, _ = score_match(detector, "1234", "1234", "f.txt", 0, 4)
    assert abs(confidence - 0.2) < 1e-9


def test_confidence_clamped_to_unit_interval():
    detector = _detector(
        base_confidence=0.95,
        context={"boosters": [{"pattern": "x", "weight": 0.5}]},
    )
    confidence, _ = score_match(detector, "123x", "123x", "f.txt", 0, 4)
    assert confidence == 1.0

    detector = _detector(
        base_confidence=0.1,
        context={"suppressors": [{"pattern": "x", "weight": -0.5}]},
    )
    confidence, _ = score_match(detector, "123x", "123x", "f.txt", 0, 4)
    assert confidence == 0.0


def test_llm_adjusts_mid_band_confidence():
    detector = _detector(base_confidence=0.6)  # inside the 0.45-0.80 LLM band
    adapter = FakeAdapter(
        verdict=LLMVerdict(is_sensitive=True, confidence=0.9, reason="real value")
    )

    confidence, evidence = score_match(
        detector, "123", "value 123", "f.txt", 6, 9, llm_adapter=adapter
    )

    assert abs(confidence - 0.75) < 1e-9  # (0.6 + 0.9) / 2
    assert any(s["kind"] == "llm" for s in evidence["signals"])
    assert len(adapter.calls) == 1


def test_llm_not_consulted_outside_the_mid_band():
    detector = _detector(base_confidence=0.95)  # already clearly Tier A
    adapter = FakeAdapter(verdict=LLMVerdict(is_sensitive=False, confidence=0.0, reason="n/a"))

    confidence, _ = score_match(detector, "123", "value 123", "f.txt", 6, 9, llm_adapter=adapter)

    assert confidence == 0.95  # untouched
    assert adapter.calls == []


def test_llm_none_verdict_leaves_confidence_unchanged():
    detector = _detector(base_confidence=0.6)
    adapter = FakeAdapter(verdict=None, available=False)  # simulates Ollama being unreachable

    confidence, evidence = score_match(
        detector, "123", "value 123", "f.txt", 6, 9, llm_adapter=adapter
    )

    assert confidence == 0.6
    assert not any(s["kind"] == "llm" for s in evidence["signals"])
