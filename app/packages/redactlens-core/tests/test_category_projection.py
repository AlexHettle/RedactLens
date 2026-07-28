import pytest
import redactlens_core.scanner as scanner_module
from fakes import FakeAdapter
from redactlens_core.llm.adapter import LLMVerdict
from redactlens_core.models import ScanOptions, ScanRequest, UserTarget
from redactlens_core.progress import ScanExecution
from redactlens_core.registry import DetectorDef, DetectorRegistry, load_default_registry
from redactlens_core.scanner import scan

CONNECTION = "postgres://admin:CorrectHorseBattery9@prod-db.internal:5432/appdb"
CONTACT_EMAIL = "jane.doe@redactlensteam.io"


def _connection_source() -> str:
    return f'DATABASE_URL = "{CONNECTION}"\ncontact = "{CONTACT_EMAIL}"\n'


def _assert_summary_invariants(result) -> None:
    summary = result.summary
    assert summary["canonical_findings"] == len(result.findings)
    assert summary["consolidated_hits"] == (
        summary["raw_detector_hits"] - summary["canonical_findings"]
    )
    assert summary["suppressed_hits"] <= summary["consolidated_hits"]
    assert sum(summary["raw_detector_hits_by_detector"].values()) == summary["raw_detector_hits"]


@pytest.mark.parametrize("chunked", [False, True], ids=["materialized", "chunked"])
def test_personal_id_projection_drops_connection_group_but_retains_real_email(
    tmp_path,
    chunked,
):
    path = tmp_path / "config.py"
    source = _connection_source()
    options = ScanOptions()
    if chunked:
        source += "x" * 70_000
        options = ScanOptions(chunk_size=65_536)
    path.write_text(source)

    result = scan(
        ScanRequest(paths=[str(path)], categories=["personal_id"], options=options),
        load_default_registry(),
    )

    assert [(finding.detector_id, finding.matched_text) for finding in result.findings] == [
        ("email", CONTACT_EMAIL)
    ]
    assert result.summary["raw_detector_hits"] == 1
    assert result.summary["canonical_findings"] == 1
    assert result.summary["consolidated_hits"] == 0
    assert result.summary["suppressed_hits"] == 0
    assert result.summary["raw_detector_hits_by_detector"] == {"email": 1}
    _assert_summary_invariants(result)


def test_credential_projection_retains_complete_group_and_stable_identity(tmp_path):
    path = tmp_path / "config.py"
    path.write_text(_connection_source())
    registry = load_default_registry()

    unfiltered = scan(ScanRequest(paths=[str(path)]), registry)
    credential_only = scan(
        ScanRequest(paths=[str(path)], categories=["credential"]),
        registry,
    )

    unfiltered_connection = next(
        finding for finding in unfiltered.findings if finding.detector_id == "connection_string"
    )
    filtered_connection = next(
        finding
        for finding in credential_only.findings
        if finding.detector_id == "connection_string"
    )
    assert filtered_connection.id == unfiltered_connection.id
    assert filtered_connection.supporting_detections == unfiltered_connection.supporting_detections
    assert [
        (support.detector_id, support.relationship)
        for support in filtered_connection.supporting_detections
    ] == [("email", "suppressed")]
    assert credential_only.findings == [filtered_connection]
    assert credential_only.summary["raw_detector_hits"] == 2
    assert credential_only.summary["canonical_findings"] == 1
    assert credential_only.summary["consolidated_hits"] == 1
    assert credential_only.summary["suppressed_hits"] == 1
    assert credential_only.summary["raw_detector_hits_by_detector"] == {
        "connection_string": 1,
        "email": 1,
    }
    _assert_summary_invariants(credential_only)


def test_filtered_scan_retains_unselected_same_span_support_and_identity(tmp_path):
    path = tmp_path / "same-span.txt"
    path.write_text("value = SAME-SPAN\n")
    registry = DetectorRegistry()
    for detector_id, category in [
        ("a_selected", "financial"),
        ("b_hidden", "credential"),
    ]:
        registry.add(
            DetectorDef(
                id=detector_id,
                category=category,
                description=f"{category} same-span detector",
                risk_lesson="test",
                method="keyword",
                pattern="SAME-SPAN",
                base_confidence=0.95,
                specificity=100,
                max_match_length=9,
            )
        )

    unfiltered = scan(ScanRequest(paths=[str(path)]), registry)
    filtered = scan(
        ScanRequest(paths=[str(path)], categories=["financial"]),
        registry,
    )

    assert filtered.findings == unfiltered.findings
    assert filtered.findings[0].detector_id == "a_selected"
    assert [
        (support.detector_id, support.relationship)
        for support in filtered.findings[0].supporting_detections
    ] == [("b_hidden", "same_span")]
    assert filtered.summary["raw_detector_hits"] == 2
    assert filtered.summary["consolidated_hits"] == 1
    assert filtered.summary["raw_detector_hits_by_detector"] == {
        "a_selected": 1,
        "b_hidden": 1,
    }
    _assert_summary_invariants(filtered)


def test_filtered_scan_uses_complete_transitive_suppression_group(monkeypatch, tmp_path):
    path = tmp_path / "transitive.txt"
    path.write_text("C-A-CORE-A-C\n")
    registry = DetectorRegistry()
    registry.add(
        DetectorDef(
            id="a_selected",
            category="financial",
            description="Selected inner value",
            risk_lesson="test",
            method="keyword",
            pattern="A-CORE-A",
            base_confidence=0.95,
            specificity=100,
            suppresses=("b_bridge",),
            max_match_length=8,
        )
    )
    registry.add(
        DetectorDef(
            id="b_bridge",
            category="generic",
            description="Contained bridge",
            risk_lesson="test",
            method="keyword",
            pattern="CORE",
            base_confidence=0.95,
            specificity=10,
            max_match_length=4,
        )
    )
    registry.add(
        DetectorDef(
            id="c_hidden_outer",
            category="credential",
            description="Hidden outer value",
            risk_lesson="test",
            method="keyword",
            pattern="C-A-CORE-A-C",
            base_confidence=0.95,
            specificity=200,
            suppresses=("b_bridge",),
            max_match_length=12,
        )
    )
    registry.freeze()

    unfiltered = scan(ScanRequest(paths=[str(path)]), registry)
    filtered = scan(
        ScanRequest(paths=[str(path)], categories=["financial"]),
        registry,
    )

    assert len(unfiltered.findings) == 1
    assert unfiltered.findings[0].detector_id == "c_hidden_outer"
    assert unfiltered.summary["raw_detector_hits"] == 3
    assert filtered.findings == []
    assert filtered.summary["raw_detector_hits"] == 0
    assert filtered.summary["canonical_findings"] == 0
    assert filtered.summary["raw_detector_hits_by_detector"] == {}
    _assert_summary_invariants(filtered)

    real_find_candidates = scanner_module._find_candidates

    def fail_hidden_outer(detector, text, **kwargs):
        if detector.id == "c_hidden_outer":
            raise scanner_module.regex.RegexEvaluationTimedOut
        return real_find_candidates(detector, text, **kwargs)

    monkeypatch.setattr(scanner_module, "_find_candidates", fail_hidden_outer)
    failed = scan(
        ScanRequest(paths=[str(path)], categories=["financial"]),
        registry,
    )
    assert failed.findings == []
    assert [item.code for item in failed.skipped_files] == ["regex_timeout"]


def test_category_projection_always_retains_explicit_literal_target(tmp_path):
    path = tmp_path / "notes.txt"
    literal = "ACME-1234-XYZ"
    path.write_text(f"account = {literal}\nssn = 123-45-6789\n")
    target = UserTarget(kind="literal", value=literal, category="arbitrary_target_category")
    registry = load_default_registry()

    unfiltered = scan(
        ScanRequest(paths=[str(path)], user_targets=[target]),
        registry,
    )
    filtered = scan(
        ScanRequest(paths=[str(path)], categories=["financial"], user_targets=[target]),
        registry,
    )

    target_finding = next(
        finding for finding in unfiltered.findings if finding.detector_id == "user_target_0"
    )
    assert [(finding.detector_id, finding.category) for finding in filtered.findings] == [
        ("user_target_0", "arbitrary_target_category")
    ]
    assert filtered.findings[0].id == target_finding.id
    assert filtered.summary["raw_detector_hits"] == 1
    assert filtered.summary["canonical_findings"] == 1
    assert filtered.summary["consolidated_hits"] == 0
    assert filtered.summary["suppressed_hits"] == 0
    assert filtered.summary["raw_detector_hits_by_detector"] == {"user_target_0": 1}
    _assert_summary_invariants(filtered)


def test_literal_target_retains_same_span_hidden_builtin_support(tmp_path):
    path = tmp_path / "record.txt"
    literal = "123-45-6789"
    path.write_text(f"identifier = {literal}\n")
    target = UserTarget(kind="literal", value=literal, category="custom")
    registry = load_default_registry()

    unfiltered = scan(
        ScanRequest(paths=[str(path)], user_targets=[target]),
        registry,
    )
    filtered = scan(
        ScanRequest(
            paths=[str(path)],
            categories=["financial"],
            user_targets=[target],
        ),
        registry,
    )

    unfiltered_target = next(
        finding for finding in unfiltered.findings if finding.detector_id == "user_target_0"
    )
    assert filtered.findings == [unfiltered_target]
    assert [
        (support.detector_id, support.relationship)
        for support in filtered.findings[0].supporting_detections
    ] == [("us_ssn", "same_span")]
    assert filtered.summary["raw_detector_hits"] == 2
    assert filtered.summary["consolidated_hits"] == 1
    assert filtered.summary["raw_detector_hits_by_detector"] == {
        "us_ssn": 1,
        "user_target_0": 1,
    }
    _assert_summary_invariants(filtered)


def test_description_target_can_project_onto_hidden_builtin_without_event_leakage(tmp_path):
    path = tmp_path / "record.txt"
    path.write_text("ssn = 123-45-6789\n")

    def verdict(prompt: str) -> LLMVerdict:
        if "The user told RedactLens to watch for:" not in prompt:
            return LLMVerdict(
                is_sensitive=True,
                confidence=0.9,
                reason="deterministic candidate looks real",
            )
        snippet = prompt.split('Text: "', 1)[1].split('"\n', 1)[0]
        matches = "123-45-6789" in snippet
        return LLMVerdict(
            is_sensitive=matches,
            confidence=0.92 if matches else 0.08,
            reason="matches the requested concept" if matches else "different concept",
        )

    target = UserTarget(
        kind="description",
        value="a Social Security number",
        category="arbitrary_target_category",
    )
    request = ScanRequest(
        paths=[str(path)],
        categories=["financial"],
        user_targets=[target],
        use_llm=True,
    )
    events = []

    result = scan(
        request,
        load_default_registry(),
        llm_adapter=FakeAdapter(verdict=verdict),
        execution=ScanExecution(event_sink=events.append),
    )

    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.detector_id == "us_ssn"
    assert finding.matched_text == "123-45-6789"
    assert [support.detector_id for support in finding.supporting_detections] == [
        "user_target_desc_0"
    ]
    assert finding.supporting_detections[0].relationship == "same_span"
    assert result.summary["raw_detector_hits"] == 2
    assert result.summary["canonical_findings"] == 1
    assert result.summary["consolidated_hits"] == 1
    assert result.summary["suppressed_hits"] == 0
    assert result.summary["raw_detector_hits_by_detector"] == {
        "us_ssn": 1,
        "user_target_desc_0": 1,
    }
    _assert_summary_invariants(result)

    finding_events = [event for event in events if event.finding is not None]
    assert [(event.type, event.stage) for event in finding_events] == [
        ("finding_added", "ai_refinement")
    ]
    event_types = [event.type for event in events]
    assert event_types.index("ai_refinement_started") < event_types.index("finding_added")
    assert finding_events[0].finding.id == finding.id

    repeated = scan(
        request,
        load_default_registry(),
        llm_adapter=FakeAdapter(verdict=verdict),
    )
    assert repeated.findings[0].id == finding.id


def test_description_target_cannot_displace_zero_specificity_builtin_or_duplicate_event(
    tmp_path,
):
    path = tmp_path / "zero-specificity.txt"
    path.write_text("value = ZERO-SPAN\n")
    registry = DetectorRegistry()
    registry.add(
        DetectorDef(
            id="z_builtin",
            category="financial",
            description="Zero-specificity deterministic detector",
            risk_lesson="test",
            method="keyword",
            pattern="ZERO-SPAN",
            base_confidence=0.95,
            specificity=0,
            max_match_length=9,
        )
    )
    events = []

    result = scan(
        ScanRequest(
            paths=[str(path)],
            categories=["financial"],
            user_targets=[
                UserTarget(
                    kind="description",
                    value="the ZERO-SPAN token",
                    category="custom",
                )
            ],
            use_llm=True,
        ),
        registry,
        llm_adapter=FakeAdapter(
            verdict=LLMVerdict(
                is_sensitive=True,
                confidence=0.92,
                reason="matches the requested token",
            )
        ),
        execution=ScanExecution(event_sink=events.append),
    )

    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.detector_id == "z_builtin"
    assert [support.detector_id for support in finding.supporting_detections] == [
        "user_target_desc_0"
    ]
    finding_events = [event for event in events if event.finding is not None]
    assert [event.type for event in finding_events] == ["finding_added", "finding_updated"]
    assert {event.finding.id for event in finding_events} == {finding.id}


@pytest.mark.parametrize("with_description_target", [False, True])
def test_ai_confidence_cannot_change_cross_category_primary_or_event_identity(
    tmp_path,
    with_description_target,
):
    path = tmp_path / "same-span.txt"
    path.write_text("value = SAME-SPAN\n")
    registry = DetectorRegistry()
    registry.add(
        DetectorDef(
            id="a_selected",
            category="financial",
            description="Selected detector",
            risk_lesson="test",
            method="keyword",
            pattern="SAME-SPAN",
            base_confidence=0.7,
            specificity=100,
            max_match_length=9,
        )
    )
    registry.add(
        DetectorDef(
            id="b_hidden",
            category="credential",
            description="Hidden detector",
            risk_lesson="test",
            method="keyword",
            pattern="SAME-SPAN",
            base_confidence=0.6,
            specificity=100,
            max_match_length=9,
        )
    )

    def verdict(prompt: str) -> LLMVerdict:
        if "The user told RedactLens to watch for:" in prompt:
            return LLMVerdict(is_sensitive=True, confidence=0.9, reason="matches target")
        if "Selected detector" in prompt:
            return LLMVerdict(is_sensitive=True, confidence=0.1, reason="weak selected signal")
        return LLMVerdict(is_sensitive=True, confidence=0.99, reason="strong hidden signal")

    events = []
    targets = (
        [
            UserTarget(
                kind="description",
                value="the SAME-SPAN token",
                category="custom",
            )
        ]
        if with_description_target
        else []
    )
    result = scan(
        ScanRequest(
            paths=[str(path)],
            categories=(["financial"] if with_description_target else ["financial", "credential"]),
            user_targets=targets,
            use_llm=True,
        ),
        registry,
        llm_adapter=FakeAdapter(verdict=verdict),
        execution=ScanExecution(event_sink=events.append),
    )

    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.detector_id == "a_selected"
    assert finding.category == "financial"
    expected_support = ["b_hidden"]
    if with_description_target:
        expected_support.append("user_target_desc_0")
    assert [support.detector_id for support in finding.supporting_detections] == expected_support
    finding_events = [event for event in events if event.finding is not None]
    assert [event.type for event in finding_events] == ["finding_added", "finding_updated"]
    assert {event.finding.id for event in finding_events} == {finding.id}


def test_hidden_only_groups_do_not_consume_model_calls(tmp_path):
    path = tmp_path / "hidden.txt"
    path.write_text("value = HIDDEN-123\n")
    registry = DetectorRegistry()
    registry.add(
        DetectorDef(
            id="hidden_midband",
            category="credential",
            description="Hidden gray-zone value",
            risk_lesson="test",
            method="keyword",
            pattern="HIDDEN-123",
            base_confidence=0.6,
            specificity=100,
            max_match_length=10,
        )
    )
    adapter = FakeAdapter(
        verdict=LLMVerdict(is_sensitive=True, confidence=0.9, reason="looks real")
    )

    result = scan(
        ScanRequest(
            paths=[str(path)],
            categories=["financial"],
            use_llm=True,
        ),
        registry,
        llm_adapter=adapter,
    )

    assert result.findings == []
    assert result.summary["raw_detector_hits"] == 0
    assert result.llm_used is False
    assert adapter.calls == []


@pytest.mark.parametrize(
    "hidden_suppresses_selected",
    [False, True],
    ids=["selected-support-member", "hidden-suppressor"],
)
def test_hidden_detector_safety_failures_are_fail_closed_for_complete_groups(
    monkeypatch,
    tmp_path,
    hidden_suppresses_selected,
):
    path = tmp_path / "selected.txt"
    path.write_text("value = SAFE-TARGET\n")
    selected_id = "selected_financial"
    hidden_id = "hidden_credential"
    registry = DetectorRegistry()
    registry.add(
        DetectorDef(
            id=selected_id,
            category="financial",
            description="Selected safe target",
            risk_lesson="test",
            method="keyword",
            pattern="SAFE-TARGET",
            base_confidence=0.95,
            specificity=100 if hidden_suppresses_selected else 200,
            suppresses=() if hidden_suppresses_selected else (hidden_id,),
            max_match_length=11,
        )
    )
    registry.add(
        DetectorDef(
            id=hidden_id,
            category="credential",
            description="Hidden detector",
            risk_lesson="test",
            method="keyword",
            pattern="UNUSED",
            base_confidence=0.95,
            specificity=200 if hidden_suppresses_selected else 100,
            suppresses=(selected_id,) if hidden_suppresses_selected else (),
            max_match_length=6,
        )
    )
    real_find_candidates = scanner_module._find_candidates

    def fail_hidden_detector(detector, text, **kwargs):
        if detector.id == hidden_id:
            raise scanner_module.regex.RegexEvaluationTimedOut
        return real_find_candidates(detector, text, **kwargs)

    monkeypatch.setattr(scanner_module, "_find_candidates", fail_hidden_detector)

    result = scan(
        ScanRequest(paths=[str(path)], categories=["financial"]),
        registry,
    )

    assert result.findings == []
    assert [item.code for item in result.skipped_files] == ["regex_timeout"]


def test_unmatched_category_skips_detector_execution(monkeypatch, tmp_path):
    path = tmp_path / "unmatched.txt"
    path.write_text("value = SAFE-TARGET\n")
    registry = DetectorRegistry()
    registry.add(
        DetectorDef(
            id="credential_only",
            category="credential",
            description="Credential detector",
            risk_lesson="test",
            method="keyword",
            pattern="SAFE-TARGET",
            base_confidence=0.95,
            max_match_length=11,
        )
    )

    def unexpected_detection(*_args, **_kwargs):
        raise AssertionError("detectors should not run without an eligible finding source")

    monkeypatch.setattr(scanner_module, "_find_candidates", unexpected_detection)
    result = scan(
        ScanRequest(paths=[str(path)], categories=["financial"]),
        registry,
    )

    assert result.scanned_files == [str(path)]
    assert result.skipped_files == []
    assert result.findings == []
    assert result.summary["raw_detector_hits"] == 0

    unavailable_description = scan(
        ScanRequest(
            paths=[str(path)],
            categories=["financial"],
            user_targets=[
                UserTarget(
                    kind="description",
                    value="the SAFE-TARGET value",
                    category="custom",
                )
            ],
            use_llm=False,
        ),
        registry,
    )
    assert unavailable_description.scanned_files == [str(path)]
    assert unavailable_description.skipped_files == []
    assert unavailable_description.findings == []
    assert unavailable_description.summary["raw_detector_hits"] == 0
