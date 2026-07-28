import sys
import time

import pytest
from redactlens_core.methods import regex
from redactlens_core.models import ScanOptions, ScanRequest
from redactlens_core.registry import (
    ContextAdjustment,
    DetectorContext,
    DetectorDef,
    DetectorRegistry,
    load_default_registry,
)
from redactlens_core.scanner import scan
from redactlens_core.scoring import score_match
from tooling.scripts import profile_detectors

_CATASTROPHIC_PATTERN = r"(a+)+$"
_CATASTROPHIC_TEXT = ("a" * 20_000) + "!"


def test_regex_deadline_preempts_catastrophic_candidate_search():
    started = time.perf_counter()

    with pytest.raises(regex.RegexEvaluationTimedOut):
        list(
            regex.find_matches(
                _CATASTROPHIC_PATTERN,
                _CATASTROPHIC_TEXT,
                timeout_seconds=0.01,
            )
        )

    assert time.perf_counter() - started < 0.5


def test_context_search_uses_the_same_regex_deadline(monkeypatch):
    monkeypatch.setattr(regex, "DEFAULT_REGEX_TIMEOUT_SECONDS", 0.01)
    matched_text = "a" * 20_000
    detector = DetectorDef(
        id="context_timeout",
        category="custom",
        description="context timeout",
        risk_lesson="test",
        method="regex",
        pattern="a+",
        base_confidence=0.5,
        max_match_length=len(matched_text),
        context=DetectorContext(
            boosters=(ContextAdjustment(pattern=_CATASTROPHIC_PATTERN, weight=0.1),)
        ),
    )

    with pytest.raises(regex.RegexEvaluationTimedOut):
        score_match(
            detector,
            matched_text,
            matched_text + "!",
            "input.txt",
            0,
            len(matched_text),
        )


def test_regex_candidate_count_is_bounded():
    with pytest.raises(regex.RegexMatchLimitExceeded):
        list(regex.find_matches(r".", "x" * 20, max_matches=10))


def test_regex_timeout_isolated_as_a_structured_file_skip(monkeypatch, tmp_path):
    monkeypatch.setattr(regex, "DEFAULT_REGEX_TIMEOUT_SECONDS", 0.01)
    bad = tmp_path / "bad.txt"
    good = tmp_path / "good.txt"
    bad.write_text(_CATASTROPHIC_TEXT)
    good.write_text("SAFE-TARGET")

    registry = DetectorRegistry()
    registry.add(
        DetectorDef(
            id="catastrophic",
            category="custom",
            description="catastrophic test expression",
            risk_lesson="test",
            method="regex",
            pattern=_CATASTROPHIC_PATTERN,
            base_confidence=0.5,
        )
    )
    registry.add(
        DetectorDef(
            id="safe_keyword",
            category="custom",
            description="safe keyword",
            risk_lesson="test",
            method="keyword",
            pattern="SAFE-TARGET",
            base_confidence=0.9,
        )
    )

    result = scan(
        ScanRequest(
            paths=[str(tmp_path)],
            options=ScanOptions(max_workers=1),
        ),
        registry,
    )

    assert result.scanned_files == [str(good)]
    assert [finding.detector_id for finding in result.findings] == ["safe_keyword"]
    assert len(result.skipped_files) == 1
    assert result.skipped_files[0].path == str(bad)
    assert result.skipped_files[0].code == "regex_timeout"
    assert result.skipped_files[0].stage == "detection"
    assert result.skipped_files[0].reason == (
        "regex evaluation exceeded the configured safety deadline"
    )


def test_builtin_patterns_keep_representative_matching_behavior():
    registry = load_default_registry()
    for detector in registry.get_all():
        if detector.method in {"regex", "entropy"}:
            regex.compile_pattern(detector.pattern)

    email = registry.get("email")
    candidates = list(regex.find_matches(email.pattern, "contact person@example.com"))
    assert [candidate.text for candidate in candidates] == ["person@example.com"]


def test_connection_string_delimiter_lookahead_has_a_bounded_adversarial_cost():
    detector = load_default_registry().get("connection_string")
    connection = "postgres://admin:secret@db.internal/app"
    adversarial_next_key = "a" * 1_000_000

    started = time.perf_counter()
    list(
        regex.find_matches(
            detector.pattern,
            f"{connection},{adversarial_next_key}:",
            timeout_seconds=0.25,
        )
    )

    assert detector.max_lookaround_length == 300
    assert time.perf_counter() - started < 0.5


def test_profiler_applies_real_deadline_to_configurable_detector_directory(
    monkeypatch, tmp_path, capsys
):
    (tmp_path / "catastrophic.yaml").write_text(
        "id: catastrophic\n"
        "category: custom\n"
        "description: catastrophic test expression\n"
        "risk_lesson: test\n"
        "method: regex\n"
        "pattern: '(a+)+$'\n"
        "base_confidence: 0.5\n"
    )
    monkeypatch.setattr(
        profile_detectors,
        "ADVERSARIAL_INPUTS",
        {"catastrophic": _CATASTROPHIC_TEXT},
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "profile_detectors.py",
            "--max-ms",
            "10",
            "--detectors-dir",
            str(tmp_path),
        ],
    )

    started = time.perf_counter()
    exit_code = profile_detectors.main()

    assert exit_code == 1
    assert time.perf_counter() - started < 0.5
    assert "regex_timeout" in capsys.readouterr().out
