import threading
import time
from pathlib import Path

import pytest
import redactlens_core.scanner as scanner_module
from fakes import FakeAdapter
from redactlens_core.anonymize import anonymize_files
from redactlens_core.llm.adapter import LLMVerdict, OllamaAdapter
from redactlens_core.models import ScanOptions, ScanRequest, UserTarget
from redactlens_core.progress import ScanCancelled, ScanExecution, ScanTimedOut
from redactlens_core.registry import DetectorRegistry, load_default_registry
from redactlens_core.scanner import scan
from test_extractors import make_docx, make_pdf, make_xlsx

FIXTURES = Path(__file__).parent / "scan_targets"

# (detector_id, filename substring) for secrets that must be confidently
# detected (Tier A) when there is no decoy context around them.
HIGH_SIGNAL = [
    ("password_assignment", "secrets.py"),
    ("aws_access_key", "secrets.py"),
    ("us_ssn", "secrets.py"),
    ("credit_card", "secrets.py"),
    ("private_key_header", "private_key.pem"),
    ("jwt", "tokens.txt"),
    ("connection_string", "tokens.txt"),
    ("high_entropy_secret", "api_key.txt"),
]


def _run_scan(tier_threshold: float = 0.75):
    registry = load_default_registry()
    request = ScanRequest(paths=[str(FIXTURES)], tier_threshold=tier_threshold)
    return scan(request, registry)


def test_high_signal_secrets_are_detected_at_tier_a():
    result = _run_scan()
    for detector_id, filename in HIGH_SIGNAL:
        matches = [
            f
            for f in result.findings
            if f.detector_id == detector_id and f.file_path.endswith(filename)
        ]
        assert matches, f"expected a {detector_id} finding in {filename}"
        assert any(f.tier == "A" for f in matches), (
            f"expected a Tier A {detector_id} finding in {filename}, "
            f"got tiers {[f.tier for f in matches]}"
        )


def test_findings_carry_correct_category_and_location():
    result = _run_scan()
    ssn_findings = [f for f in result.findings if f.detector_id == "us_ssn"]
    assert ssn_findings
    finding = ssn_findings[0]
    assert finding.category == "personal_id"
    assert finding.line >= 1
    assert finding.column >= 1
    assert finding.matched_text == "123-45-6789"
    assert "12" in finding.redacted_preview
    assert "123-45-6789" not in finding.redacted_preview


def test_decoys_in_test_path_are_suppressed_below_threshold():
    result = _run_scan()
    decoy_findings = [f for f in result.findings if f.file_path.endswith("decoys.py")]
    assert decoy_findings, "expected the decoy file to still produce findings"
    assert all(f.tier == "B" for f in decoy_findings), (
        f"expected all decoy findings to land in Tier B, got {[f.tier for f in decoy_findings]}"
    )


def test_lower_signal_pii_is_still_reported_even_if_tier_b():
    result = _run_scan()
    email_findings = [f for f in result.findings if f.detector_id == "email"]
    phone_findings = [f for f in result.findings if f.detector_id == "phone"]
    assert email_findings and phone_findings


def test_scan_result_summary_counts_match_findings():
    result = _run_scan()
    assert result.summary["total_findings"] == len(result.findings)
    assert sum(result.summary["tier_counts"].values()) == len(result.findings)
    assert result.summary["files_scanned"] == len(result.scanned_files)
    assert (
        sum(result.summary["raw_detector_hits_by_detector"].values())
        == result.summary["raw_detector_hits"]
    )


def test_entropy_detector_has_low_false_positive_rate_on_prose():
    result = _run_scan()
    prose_entropy_findings = [
        f
        for f in result.findings
        if f.detector_id == "high_entropy_secret" and f.file_path.endswith("prose.txt")
    ]
    assert prose_entropy_findings == []


def test_password_assignment_catches_compound_identifiers(tmp_path):
    (tmp_path / "config.py").write_text('SECRET_KEY: "2E2@gVlXv7ccu@"\n')
    registry = load_default_registry()
    result = scan(ScanRequest(paths=[str(tmp_path)]), registry)
    matches = [f for f in result.findings if f.detector_id == "password_assignment"]
    assert matches, "expected SECRET_KEY: ... to be caught despite 'secret' not being the whole key"
    assert matches[0].matched_text == "2E2@gVlXv7ccu@"


@pytest.mark.parametrize(
    ("source", "primary_detector", "generic_detector", "value"),
    [
        (
            'AWS_ACCESS_KEY_ID = "AKIAV3XZJH2QK7RSTUV1"\n',
            "aws_access_key",
            "high_entropy_secret",
            "AKIAV3XZJH2QK7RSTUV1",
        ),
        (
            'SECRET_KEY = "n4Kp9xQzT2vBmR7wYsLd3aEf"\n',
            "password_assignment",
            "high_entropy_secret",
            "n4Kp9xQzT2vBmR7wYsLd3aEf",
        ),
    ],
)
def test_scan_consolidates_specific_and_generic_hits(
    tmp_path, source, primary_detector, generic_detector, value
):
    """One sensitive value should produce one actionable finding.

    The canonical finding should prefer the structured/contextual detector;
    the generic detector can remain supporting evidence in the future result
    model, but it must not inflate the visible finding count.
    """
    (tmp_path / "config.py").write_text(source)

    result = scan(ScanRequest(paths=[str(tmp_path)]), load_default_registry())
    matching = [finding for finding in result.findings if finding.matched_text == value]

    assert [finding.detector_id for finding in matching] == [primary_detector]
    assert generic_detector not in {finding.detector_id for finding in matching}
    assert [item.detector_id for item in matching[0].supporting_detections] == [generic_detector]
    assert matching[0].supporting_detections[0].relationship == "suppressed"


def test_scan_does_not_report_connection_string_credentials_as_contact_email(tmp_path):
    connection = "postgres://admin:CorrectHorseBattery9@prod-db.internal:5432/appdb"
    source = f'DATABASE_URL = "{connection}"\n'
    (tmp_path / "config.py").write_text(source)

    result = scan(
        ScanRequest(paths=[str(tmp_path)]),
        load_default_registry(),
        capture_raw_detector_opinions=True,
    )

    connection_finding = next(f for f in result.findings if f.detector_id == "connection_string")
    assert not any(
        f.detector_id == "email"
        and f.start_offset >= connection_finding.start_offset
        and f.end_offset <= connection_finding.end_offset
        for f in result.findings
    )
    assert [item.detector_id for item in connection_finding.supporting_detections] == ["email"]
    assert result.raw_detector_opinions is not None
    email_opinion = next(
        opinion for opinion in result.raw_detector_opinions if opinion.detector_id == "email"
    )
    assert email_opinion.category == "personal_id"
    assert connection_finding.start_offset <= email_opinion.start_offset
    assert email_opinion.end_offset <= connection_finding.end_offset
    assert (email_opinion.start_offset, email_opinion.end_offset) != (
        connection_finding.start_offset,
        connection_finding.end_offset,
    )
    assert "@" in source[email_opinion.start_offset : email_opinion.end_offset]
    assert len(result.raw_detector_opinions) == result.summary["raw_detector_hits"]
    assert "raw_detector_opinions" not in result.model_dump()
    assert "raw_detector_opinions" not in result.model_json_schema()["properties"]


def test_scan_summary_preserves_raw_and_canonical_counts(tmp_path):
    (tmp_path / "config.py").write_text('AWS_ACCESS_KEY_ID = "AKIAV3XZJH2QK7RSTUV1"\n')

    result = scan(ScanRequest(paths=[str(tmp_path)]), load_default_registry())

    assert result.summary["raw_detector_hits"] == 2
    assert result.summary["canonical_findings"] == 1
    assert result.summary["consolidated_hits"] == 1
    assert result.summary["suppressed_hits"] == 1
    assert result.raw_detector_opinions is None


def test_private_key_block_and_entropy_hits_become_one_actionable_finding(tmp_path):
    private_key = (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFqVnxK2tlSyVKLAfn3CzAaCa1SwoC\n"
        "ATBOhdCYqK+wzuB5wQv6gtWZQqd6c8B3VAgMBAAECQQCBz2dDtViNcHQH9Mx0\n"
        "-----END RSA PRIVATE KEY-----\n"
    )
    key_path = tmp_path / "id_rsa"
    key_path.write_text(private_key)

    result = scan(ScanRequest(paths=[str(key_path)]), load_default_registry())

    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.detector_id == "private_key_header"
    assert finding.matched_text.replace("\r\n", "\n") == private_key.rstrip("\n")
    assert [support.detector_id for support in finding.supporting_detections] == [
        "high_entropy_secret"
    ]
    assert finding.evidence["consolidation"]["raw_detection_count"] == 3
    assert result.summary["raw_detector_hits"] == 3
    assert result.summary["canonical_findings"] == 1

    outputs = anonymize_files(result.findings)
    redacted = Path(outputs[str(key_path)]).read_text()
    assert "BEGIN RSA PRIVATE KEY" not in redacted
    assert "MIIBOgIB" not in redacted


def test_canonical_finding_id_is_stable_across_llm_refinement(tmp_path):
    (tmp_path / "config.py").write_text('AWS_ACCESS_KEY_ID = "AKIAV3XZJH2QK7RSTUV1"\n')
    registry = load_default_registry()
    baseline = scan(ScanRequest(paths=[str(tmp_path)]), registry)
    fake = FakeAdapter(verdict=LLMVerdict(is_sensitive=True, confidence=0.99, reason="confirmed"))

    refined = scan(
        ScanRequest(paths=[str(tmp_path)], use_llm=True),
        registry,
        llm_adapter=fake,
    )

    assert len(baseline.findings) == len(refined.findings) == 1
    assert baseline.findings[0].id == refined.findings[0].id
    assert baseline.findings[0].detector_id == refined.findings[0].detector_id == "aws_access_key"


def test_detector_registry_order_does_not_change_canonical_findings(tmp_path):
    (tmp_path / "config.py").write_text(
        'AWS_ACCESS_KEY_ID = "AKIAV3XZJH2QK7RSTUV1"\nSECRET_KEY = "n4Kp9xQzT2vBmR7wYsLd3aEf"\n'
    )
    forward_registry = load_default_registry()
    reverse_registry = DetectorRegistry()
    for detector in reversed(forward_registry.get_all()):
        reverse_registry.add(detector)

    forward = scan(ScanRequest(paths=[str(tmp_path)]), forward_registry)
    reverse = scan(ScanRequest(paths=[str(tmp_path)]), reverse_registry)

    def signature(result):
        return [
            (
                finding.id,
                finding.detector_id,
                [support.detector_id for support in finding.supporting_detections],
            )
            for finding in result.findings
        ]

    assert signature(forward) == signature(reverse)


def test_scan_finds_secrets_inside_docx_with_location_and_anonymize_enabled(tmp_path):
    path = tmp_path / "notes.docx"
    path.write_bytes(make_docx(["meeting notes", 'my ssn is "123-45-6789" ok']))

    result = scan(ScanRequest(paths=[str(tmp_path)]), load_default_registry())

    assert str(path) in result.scanned_files
    matches = [f for f in result.findings if f.detector_id == "us_ssn"]
    assert matches, "expected the SSN inside the Word document to be found"
    finding = matches[0]
    assert finding.location == "paragraph 2"
    assert finding.can_anonymize is True  # docx write-back is supported


def test_scan_finds_secrets_inside_xlsx_cells(tmp_path):
    path = tmp_path / "payroll.xlsx"
    path.write_bytes(make_xlsx({"A1": "employee ssn", "B2": "123-45-6789"}))

    result = scan(ScanRequest(paths=[str(tmp_path)]), load_default_registry())

    matches = [f for f in result.findings if f.detector_id == "us_ssn"]
    assert matches
    assert matches[0].location == "Payroll!B2"
    assert matches[0].can_anonymize is True  # xlsx write-back is supported


def test_pdf_findings_stay_read_only(tmp_path):
    (tmp_path / "notes.pdf").write_bytes(make_pdf("ssn 123-45-6789"))

    result = scan(ScanRequest(paths=[str(tmp_path)]), load_default_registry())

    matches = [f for f in result.findings if f.detector_id == "us_ssn"]
    assert matches
    assert matches[0].location == "page 1"
    assert matches[0].can_anonymize is False  # PDF rewriting is a non-goal


def test_plain_text_findings_keep_anonymize_and_have_no_location(tmp_path):
    (tmp_path / "secrets.py").write_text('ssn = "123-45-6789"\n')

    result = scan(ScanRequest(paths=[str(tmp_path)]), load_default_registry())

    finding = next(f for f in result.findings if f.detector_id == "us_ssn")
    assert finding.can_anonymize is True
    assert finding.location is None


def test_category_filter_restricts_findings():
    registry = load_default_registry()
    request = ScanRequest(paths=[str(FIXTURES)], categories=["financial"])
    result = scan(request, registry)
    assert result.findings
    assert all(f.category == "financial" for f in result.findings)


def test_scan_degrades_gracefully_when_ollama_is_unreachable(tmp_path):
    """Phase 5 acceptance: scans must succeed with Ollama stopped, verified
    against a real dead endpoint (port 1 refuses connections)."""
    (tmp_path / "secrets.py").write_text('ssn = "123-45-6789"\n')
    dead_adapter = OllamaAdapter(host="http://127.0.0.1:1", timeout=2)

    request = ScanRequest(paths=[str(tmp_path)], use_llm=True)
    result = scan(request, load_default_registry(), llm_adapter=dead_adapter)

    assert result.llm_used is False
    assert any(f.detector_id == "us_ssn" for f in result.findings)


def test_scan_succeeds_with_llm_available_too(tmp_path):
    (tmp_path / "secrets.py").write_text('ssn = "123-45-6789"\nemail = "person@company.example"\n')
    fake = FakeAdapter(verdict=LLMVerdict(is_sensitive=True, confidence=0.8, reason="looks real"))

    request = ScanRequest(paths=[str(tmp_path)], use_llm=True)
    result = scan(request, load_default_registry(), llm_adapter=fake)

    assert result.llm_used is True
    assert result.summary["llm_attempts"] > 0
    assert result.summary["llm_successes"] == result.summary["llm_attempts"]
    assert result.summary["llm_failures"] == 0
    assert any(f.detector_id == "us_ssn" for f in result.findings)


def test_available_llm_without_an_inference_attempt_is_not_reported_as_used(tmp_path):
    (tmp_path / "ordinary.txt").write_text("ordinary public documentation\n")
    fake = FakeAdapter(verdict=LLMVerdict(is_sensitive=False, confidence=0.0, reason="not used"))

    result = scan(
        ScanRequest(paths=[str(tmp_path)], use_llm=True),
        load_default_registry(),
        llm_adapter=fake,
    )

    assert result.llm_used is False
    assert result.summary["llm_attempts"] == 0
    assert result.summary["llm_successes"] == 0
    assert result.summary["llm_failures"] == 0


def test_scan_reports_failed_llm_inference_attempts(tmp_path):
    (tmp_path / "secrets.py").write_text('email = "person@company.com"\n')
    fake = FakeAdapter(verdict=None)

    result = scan(
        ScanRequest(paths=[str(tmp_path)], use_llm=True),
        load_default_registry(),
        llm_adapter=fake,
    )

    assert result.llm_used is True
    assert result.summary["llm_attempts"] > 0
    assert result.summary["llm_successes"] == 0
    assert result.summary["llm_failures"] == result.summary["llm_attempts"]


def test_description_target_produces_matches_via_the_llm_path(tmp_path):
    (tmp_path / "notes.txt").write_text("employee id: EMP-99213\nunrelated content here\n")
    fake = FakeAdapter(
        verdict=lambda q: LLMVerdict(is_sensitive="EMP-99213" in q, confidence=0.9, reason="match")
    )

    request = ScanRequest(
        paths=[str(tmp_path)],
        use_llm=True,
        user_targets=[UserTarget(kind="description", value="an employee ID", category="custom")],
    )
    result = scan(request, load_default_registry(), llm_adapter=fake)

    matches = [f for f in result.findings if f.detector_id == "user_target_desc_0"]
    assert matches
    assert matches[0].tier == "A"
    assert matches[0].category == "custom"
    assert matches[0].can_anonymize is True


def test_description_target_in_a_read_only_pdf_stays_ineligible_for_redaction(tmp_path):
    (tmp_path / "notes.pdf").write_bytes(make_pdf("employee id: EMP-99213"))
    fake = FakeAdapter(
        verdict=lambda q: LLMVerdict(is_sensitive="EMP-99213" in q, confidence=0.9, reason="match")
    )

    result = scan(
        ScanRequest(
            paths=[str(tmp_path)],
            use_llm=True,
            user_targets=[
                UserTarget(kind="description", value="an employee ID", category="custom")
            ],
        ),
        load_default_registry(),
        llm_adapter=fake,
    )

    match = next(
        finding for finding in result.findings if finding.detector_id == "user_target_desc_0"
    )
    assert match.location == "page 1"
    assert match.can_anonymize is False
    assert match.suggested_action == "review"


def test_scan_events_report_real_file_progress_and_partial_findings(tmp_path):
    (tmp_path / "secret.py").write_text('ssn = "123-45-6789"\n')
    (tmp_path / "binary.bin").write_bytes(b"\x00\x01\x02")
    events = []

    result = scan(
        ScanRequest(paths=[str(tmp_path)]),
        load_default_registry(),
        execution=ScanExecution(event_sink=events.append),
    )

    event_types = [event.type for event in events]
    discovery = next(event for event in events if event.type == "discovery_complete")
    terminal = events[-1]
    assert event_types[0] == "scan_started"
    assert "finding_added" in event_types
    assert "file_completed" in event_types
    assert "file_skipped" in event_types
    assert discovery.total_files == 2
    assert events[-2].type == "scan_finalizing"
    assert events[-2].stage == "finalizing"
    assert terminal.type == "scan_completed"
    assert terminal.stage == "complete"
    assert terminal.completed_files == 2
    assert result.summary["completed_files"] == 2
    assert result.summary["incomplete"] is False


def test_progress_events_follow_the_per_file_protocol_and_never_regress(tmp_path):
    for index in range(3):
        (tmp_path / f"secret-{index}.py").write_text(f'ssn = "123-45-67{index:02d}"\n')
    events = []

    result = scan(
        ScanRequest(paths=[str(tmp_path)]),
        load_default_registry(),
        execution=ScanExecution(event_sink=events.append),
    )

    event_types = [event.type for event in events]
    assert event_types[:2] == ["scan_started", "discovery_complete"]
    assert event_types[-2:] == ["scan_finalizing", "scan_completed"]
    assert len(events) == 13
    assert {event_type: event_types.count(event_type) for event_type in set(event_types)} == {
        "scan_started": 1,
        "discovery_complete": 1,
        "file_started": 3,
        "finding_added": 3,
        "file_completed": 3,
        "scan_finalizing": 1,
        "scan_completed": 1,
    }
    completed_counts = [event.completed_files for event in events]
    assert completed_counts == sorted(completed_counts)
    assert [event.completed_files for event in events if event.type == "file_completed"] == [
        1,
        2,
        3,
    ]
    finding_events = [event for event in events if event.type == "finding_added"]
    assert [event.findings_so_far for event in finding_events] == [1, 2, 3]
    assert [event.finding.id for event in finding_events if event.finding is not None] == [
        finding.id for finding in result.findings
    ]
    assert len({event.finding.id for event in finding_events if event.finding is not None}) == 3
    for path in sorted(str(path) for path in tmp_path.glob("*.py")):
        relevant = [event.type for event in events if event.file_path == path]
        assert relevant == ["file_started", "finding_added", "file_completed"]


def test_progress_protocol_accounts_for_discovery_and_processing_skips(tmp_path):
    secret = tmp_path / "secret.py"
    binary = tmp_path / "binary.bin"
    excluded = tmp_path / "excluded.txt"
    secret.write_text('ssn = "123-45-6789"\n')
    binary.write_bytes(b"\x00\x01\x02")
    excluded.write_text('ssn = "987-65-4321"\n')
    events = []

    result = scan(
        ScanRequest(
            paths=[str(tmp_path)],
            options=ScanOptions(
                included_extensions=[".py", ".bin"],
                max_workers=1,
            ),
        ),
        load_default_registry(),
        execution=ScanExecution(event_sink=events.append),
    )

    event_types = [event.type for event in events]
    assert event_types == [
        "scan_started",
        "discovery_complete",
        "file_started",
        "file_skipped",
        "file_started",
        "file_skipped",
        "finding_added",
        "file_completed",
        "scan_finalizing",
        "scan_completed",
    ]
    assert [event.completed_files for event in events] == [0, 0, 0, 1, 1, 2, 2, 3, 3, 3]
    assert [event.skipped_files for event in events] == [0, 0, 0, 1, 1, 2, 2, 2, 2, 2]
    assert all(event.total_files == 3 for event in events[1:])
    assert [event.type for event in events if event.file_path == str(binary)] == [
        "file_started",
        "file_skipped",
    ]
    assert [event.type for event in events if event.file_path == str(excluded)] == ["file_skipped"]
    assert [event.type for event in events if event.file_path == str(secret)] == [
        "file_started",
        "finding_added",
        "file_completed",
    ]
    skipped_by_path = {item.path: item for item in result.skipped_files}
    assert skipped_by_path[str(binary)].stage == "extraction"
    assert skipped_by_path[str(excluded)].stage == "discovery"
    assert result.summary["completed_files"] == 3
    assert len(result.skipped_files) == 2


def test_finding_progress_is_cursor_exact_for_multiple_findings_in_one_file(tmp_path):
    target = tmp_path / "secrets.py"
    target.write_text('first = "123-45-6789"\nsecond = "987-65-4321"\n')
    events = []

    result = scan(
        ScanRequest(paths=[str(target)]),
        load_default_registry(),
        execution=ScanExecution(event_sink=events.append),
    )

    observed = {}
    finding_events = [event for event in events if event.finding is not None]
    assert len(finding_events) > 1
    for event in finding_events:
        observed[event.finding.id] = event.finding
        assert event.findings_so_far == len(observed)
    assert set(observed) == {finding.id for finding in result.findings}


def test_refinement_additions_report_each_incremental_finding_count(tmp_path):
    target = tmp_path / "employees.txt"
    target.write_text("employee id EMP-1001\nemployee id EMP-2002\n")
    events = []

    def verdict(prompt):
        matches = "EMP-" in prompt
        return LLMVerdict(
            is_sensitive=matches,
            confidence=0.95 if matches else 0.05,
            reason="employee identifier" if matches else "not an employee identifier",
        )

    result = scan(
        ScanRequest(
            paths=[str(target)],
            categories=["financial"],
            user_targets=[
                UserTarget(kind="description", value="an employee ID", category="custom")
            ],
            use_llm=True,
        ),
        load_default_registry(),
        llm_adapter=FakeAdapter(verdict=verdict),
        execution=ScanExecution(event_sink=events.append),
    )

    additions = [
        event
        for event in events
        if event.type == "finding_added" and event.stage == "ai_refinement"
    ]
    assert len(result.findings) == 2
    assert len(additions) == 2
    assert [event.findings_so_far for event in additions] == [1, 2]


@pytest.mark.parametrize(
    ("interruption", "error_type"),
    [("cancel", ScanCancelled), ("deadline", ScanTimedOut)],
)
def test_file_started_sink_interruption_prevents_submission(
    monkeypatch,
    tmp_path,
    interruption,
    error_type,
):
    for index in range(3):
        (tmp_path / f"secret-{index}.py").write_text(f'ssn = "123-45-67{index:02d}"\n')
    cancel = threading.Event()
    now = [0.0]
    events = []
    submitted = []

    def process_file(file_path, *_args, **_kwargs):
        submitted.append(file_path)
        return scanner_module._FileOutcome(
            file_path,
            issue=scanner_module.FileIssue("read_failed", "extraction", "test"),
        )

    def receive(event):
        events.append(event)
        if event.type != "file_started":
            return
        if interruption == "cancel":
            cancel.set()
        else:
            now[0] = 2.0

    monkeypatch.setattr(scanner_module, "_process_file", process_file)

    with pytest.raises(error_type):
        scan(
            ScanRequest(paths=[str(tmp_path)], options={"max_workers": 3}),
            load_default_registry(),
            execution=ScanExecution(
                event_sink=receive,
                cancel_requested=cancel.is_set,
                job_timeout_seconds=1.0,
                clock=lambda: now[0],
            ),
        )

    assert [event.type for event in events].count("file_started") == 1
    assert submitted == []


def test_concurrent_cancellation_linearizes_before_file_submission(monkeypatch, tmp_path):
    target = tmp_path / "secret.py"
    target.write_text('ssn = "123-45-6789"\n')
    admission_lock = threading.Lock()
    at_boundary = threading.Event()
    allow_admission = threading.Event()
    cancellation_accepted = threading.Event()
    cancel = threading.Event()
    submitted = []

    class PausingGuard:
        def __enter__(self):
            at_boundary.set()
            assert allow_admission.wait(timeout=2)
            admission_lock.acquire()
            return self

        def __exit__(self, *_args):
            admission_lock.release()
            return False

    def accept_cancellation():
        assert at_boundary.wait(timeout=2)
        with admission_lock:
            cancel.set()
            cancellation_accepted.set()
        allow_admission.set()

    def process_file(file_path, *_args, **_kwargs):
        submitted.append(file_path)
        raise AssertionError("accepted cancellation must prevent file work")

    monkeypatch.setattr(scanner_module, "_process_file", process_file)
    canceller = threading.Thread(target=accept_cancellation)
    canceller.start()
    try:
        with pytest.raises(ScanCancelled):
            scan(
                ScanRequest(paths=[str(target)]),
                load_default_registry(),
                execution=ScanExecution(
                    cancel_requested=cancel.is_set,
                    submission_guard=PausingGuard,
                ),
            )
    finally:
        allow_admission.set()
        canceller.join(timeout=2)

    assert not canceller.is_alive()
    assert cancellation_accepted.is_set()
    assert submitted == []


def test_cooperative_cancellation_stops_between_files_and_returns_partial_result(tmp_path):
    for index in range(3):
        (tmp_path / f"secret-{index}.py").write_text(f'ssn = "123-45-67{index:02d}"\n')
    cancel = False
    events = []

    def receive(event):
        nonlocal cancel
        events.append(event)
        if event.type == "file_completed":
            cancel = True

    with pytest.raises(ScanCancelled) as raised:
        scan(
            ScanRequest(paths=[str(tmp_path)]),
            load_default_registry(),
            execution=ScanExecution(
                event_sink=receive,
                cancel_requested=lambda: cancel,
            ),
        )

    partial = raised.value.partial_result
    assert partial.summary["status"] == "cancelled"
    assert partial.summary["incomplete"] is True
    assert partial.summary["completed_files"] == 1
    assert events[-1].type == "scan_cancelled"


def test_interruption_scrubs_consumed_and_abandoned_file_outcomes(monkeypatch, tmp_path):
    first = tmp_path / "a.txt"
    second = tmp_path / "b.txt"
    first.write_text("employee id EMP-1001 contact first@example.com\n")
    second.write_text("employee id EMP-2002 contact second@example.com\n")
    cancel = threading.Event()
    second_ready = threading.Event()
    captured = []
    plans = []
    had_sensitive_state = []
    real_process_file = scanner_module._process_file

    def controlled_process(file_path, *args, **kwargs):
        if Path(file_path) == first:
            assert second_ready.wait(timeout=2)
        outcome = real_process_file(file_path, *args, **kwargs)
        captured.append(outcome)
        plans.append(outcome.refinement)
        had_sensitive_state.append(
            outcome.heuristic is not None and outcome.raw_detector_opinions is not None
        )
        if Path(file_path) == second:
            second_ready.set()
        else:
            cancel.set()
        return outcome

    monkeypatch.setattr(scanner_module, "_process_file", controlled_process)

    with pytest.raises(ScanCancelled) as raised:
        scan(
            ScanRequest(
                paths=[str(tmp_path)],
                use_llm=True,
                user_targets=[
                    UserTarget(kind="description", value="an employee ID", category="custom")
                ],
                options={"max_workers": 2},
            ),
            load_default_registry(),
            llm_adapter=FakeAdapter(
                verdict=LLMVerdict(
                    is_sensitive=True,
                    confidence=0.95,
                    reason="employee identifier",
                )
            ),
            execution=ScanExecution(cancel_requested=cancel.is_set),
            capture_raw_detector_opinions=True,
        )

    assert raised.value.partial_result.findings == []
    assert len(captured) == 2
    assert all(had_sensitive_state)
    assert all(plan is not None for plan in plans)
    assert all(
        not plan.file_path and not plan.detections and not plan.description_lines for plan in plans
    )
    assert all(outcome.heuristic is None for outcome in captured)
    assert all(outcome.refinement is None for outcome in captured)
    assert all(outcome.raw_detector_opinions is None for outcome in captured)


def test_consumed_outcome_scrub_preserves_published_finding(monkeypatch, tmp_path):
    target = tmp_path / "secret.py"
    target.write_text('ssn = "123-45-6789"\n')
    captured = []
    real_process_file = scanner_module._process_file

    def capture_outcome(*args, **kwargs):
        outcome = real_process_file(*args, **kwargs)
        captured.append(outcome)
        return outcome

    monkeypatch.setattr(scanner_module, "_process_file", capture_outcome)
    result = scan(
        ScanRequest(paths=[str(target)]),
        load_default_registry(),
        capture_raw_detector_opinions=True,
    )

    assert any(finding.matched_text == "123-45-6789" for finding in result.findings)
    assert captured[0].heuristic is None
    assert captured[0].raw_detector_opinions is None


def test_abandoned_future_exception_drops_retained_traceback():
    future = scanner_module.Future()
    errors = []

    def fail_with_sensitive_local():
        raw_sensitive_local = "123-45-6789"
        assert raw_sensitive_local
        raise RuntimeError("worker failed")

    try:
        fail_with_sensitive_local()
    except RuntimeError as error:
        errors.append(error)
        future.set_exception(error)

    retained = errors[0].__traceback__
    assert retained is not None
    retained_frames = []
    while retained is not None:
        retained_frames.append(retained.tb_frame)
        retained = retained.tb_next
    assert any(
        frame.f_locals.get("raw_sensitive_local") == "123-45-6789" for frame in retained_frames
    )
    scanner_module._clear_file_outcome(future)
    assert errors[0].__traceback__ is None
    assert all("raw_sensitive_local" not in frame.f_locals for frame in retained_frames)


def test_abandoned_exception_group_drops_nested_tracebacks():
    future = scanner_module.Future()
    retained_frames = []

    def captured_error(secret):
        try:
            raw_sensitive_local = secret
            assert raw_sensitive_local
            raise RuntimeError("worker failed")
        except RuntimeError as error:
            traceback = error.__traceback__
            while traceback is not None:
                retained_frames.append(traceback.tb_frame)
                traceback = traceback.tb_next
            return error

    first = captured_error("123-45-6789")
    second = captured_error("987-65-4321")
    nested = ExceptionGroup("nested", [second])
    grouped = ExceptionGroup("workers failed", [first, nested])
    future.set_exception(grouped)

    scanner_module._clear_file_outcome(future)

    assert grouped.__traceback__ is None
    assert first.__traceback__ is None
    assert nested.__traceback__ is None
    assert second.__traceback__ is None
    assert all("raw_sensitive_local" not in frame.f_locals for frame in retained_frames)


@pytest.mark.parametrize(
    ("interruption", "terminal_type", "error_type"),
    [
        ("cancel", "scan_cancelled", ScanCancelled),
        ("timeout", "scan_failed", ScanTimedOut),
    ],
)
def test_interrupted_scan_drains_running_file_workers_before_terminal_event(
    monkeypatch,
    tmp_path,
    interruption,
    terminal_type,
    error_type,
):
    first = tmp_path / "a.py"
    later = tmp_path / "b.py"
    first.write_text('ssn = "123-45-6789"\n')
    later.write_text('ssn = "987-65-4321"\n')
    later_started = threading.Event()
    later_release = threading.Event()
    later_returned = threading.Event()
    cancel = threading.Event()
    interruption_requested = threading.Event()
    terminal_emitted = threading.Event()
    now = [0.0]
    events = []
    outcome = {}
    real_process_file = scanner_module._process_file

    def controlled_process(file_path, *args, **kwargs):
        if Path(file_path) == later:
            later_started.set()
            try:
                later_release.wait()
                return real_process_file(file_path, *args, **kwargs)
            finally:
                later_returned.set()
        later_started.wait()
        return real_process_file(file_path, *args, **kwargs)

    def receive(event):
        events.append(event)
        if event.type == "file_completed" and event.file_path == str(first):
            if interruption == "cancel":
                cancel.set()
            else:
                now[0] = 2.0
            interruption_requested.set()
        elif event.type == terminal_type:
            terminal_emitted.set()

    def run_scan():
        try:
            outcome["result"] = scan(
                ScanRequest(paths=[str(tmp_path)], options={"max_workers": 2}),
                load_default_registry(),
                execution=ScanExecution(
                    event_sink=receive,
                    cancel_requested=cancel.is_set,
                    job_timeout_seconds=1.0,
                    clock=lambda: now[0],
                ),
            )
        except BaseException as error:
            outcome["error"] = error

    monkeypatch.setattr(scanner_module, "_process_file", controlled_process)
    worker = threading.Thread(target=run_scan)
    worker.start()
    try:
        assert later_started.wait(timeout=1)
        assert interruption_requested.wait(timeout=1)
        worker.join(timeout=0.1)
        assert worker.is_alive(), "scan returned while a nested file worker was still running"
        assert later_returned.is_set() is False
        assert terminal_emitted.is_set() is False
        assert not any(event.type == terminal_type for event in events)
    finally:
        later_release.set()
        worker.join(timeout=2)

    assert not worker.is_alive()
    assert later_returned.is_set()
    assert isinstance(outcome.get("error"), error_type)
    assert terminal_emitted.is_set()
    assert events[-1].type == terminal_type


def test_whole_job_timeout_returns_partial_result(tmp_path):
    (tmp_path / "secret.py").write_text('ssn = "123-45-6789"\n')
    ticks = iter([0.0, 0.1, 0.4, 0.5])

    with pytest.raises(ScanTimedOut) as raised:
        scan(
            ScanRequest(paths=[str(tmp_path)]),
            load_default_registry(),
            execution=ScanExecution(
                job_timeout_seconds=0.25,
                clock=lambda: next(ticks, 1.0),
            ),
        )

    assert raised.value.partial_result.summary["status"] == "timed_out"
    assert raised.value.partial_result.summary["incomplete"] is True


def test_extraction_time_limit_skips_slow_file_with_visible_reason(tmp_path):
    target = tmp_path / "secret.py"
    target.write_text('ssn = "123-45-6789"\n')
    ticks = iter([0.0, 0.0, 1.0])

    result = scan(
        ScanRequest(paths=[str(target)]),
        load_default_registry(),
        execution=ScanExecution(
            extraction_timeout_seconds=0.5,
            clock=lambda: next(ticks, 1.0),
        ),
    )

    assert result.findings == []
    assert result.skipped_files[0].reason == "text extraction exceeded the configured time limit"


def test_ai_refines_stable_findings_without_rereading_file(monkeypatch, tmp_path):
    target = tmp_path / "contact.txt"
    target.write_text("contact person@acme.invalid\n")
    fake = FakeAdapter(
        verdict=LLMVerdict(is_sensitive=True, confidence=0.99, reason="private contact")
    )
    events = []
    from redactlens_core import scanner as scanner_module

    real_read = scanner_module.read_scannable_detailed
    reads = 0

    def counted_read(*args, **kwargs):
        nonlocal reads
        reads += 1
        return real_read(*args, **kwargs)

    monkeypatch.setattr(scanner_module, "read_scannable_detailed", counted_read)
    result = scan(
        # Keep this transition-focused test below the calibrated production
        # cutoff so the successful refinement crosses from Tier B to Tier A.
        ScanRequest(paths=[str(target)], use_llm=True, tier_threshold=0.75),
        load_default_registry(),
        llm_adapter=fake,
        execution=ScanExecution(event_sink=events.append),
    )

    added = next(event for event in events if event.type == "finding_added")
    updated = next(event for event in events if event.type == "finding_updated")
    assert reads == 1
    assert added.finding is not None and updated.finding is not None
    assert added.finding.id == updated.finding.id == result.findings[0].id
    assert added.finding.tier == "B"
    assert updated.finding.tier == "A"


def test_heuristic_finding_is_observable_before_blocking_ai_refinement(tmp_path):
    target = tmp_path / "contact.txt"
    target.write_text("contact person@acme.invalid\n")
    entered_model = threading.Event()
    release_model = threading.Event()
    events = []
    outcome = {}

    class BlockingAdapter:
        def available(self):
            return True

        def judge(self, _question):
            entered_model.set()
            release_model.wait(timeout=2)
            return LLMVerdict(is_sensitive=True, confidence=0.99, reason="private contact")

    def run_scan():
        try:
            outcome["result"] = scan(
                ScanRequest(paths=[str(target)], use_llm=True, tier_threshold=0.75),
                load_default_registry(),
                llm_adapter=BlockingAdapter(),
                execution=ScanExecution(event_sink=events.append),
            )
        except BaseException as error:  # pragma: no cover - assertion reports it
            outcome["error"] = error

    worker = threading.Thread(target=run_scan)
    worker.start()
    try:
        assert entered_model.wait(timeout=1)
        blocked_types = [event.type for event in events]
        assert blocked_types[-2:] == ["finding_added", "ai_refinement_started"]
        added = next(event for event in events if event.type == "finding_added")
        assert added.finding is not None
    finally:
        release_model.set()
        worker.join(timeout=2)

    assert not worker.is_alive()
    assert "error" not in outcome
    result = outcome["result"]
    updated = next(event for event in events if event.type == "finding_updated")
    assert updated.finding is not None
    assert added.finding.id == updated.finding.id == result.findings[0].id
    event_types = [event.type for event in events]
    assert event_types.index("finding_added") < event_types.index("ai_refinement_started")
    assert event_types.index("ai_refinement_started") < event_types.index("finding_updated")
    assert event_types.index("finding_updated") < event_types.index("file_completed")


def test_cancellation_during_blocking_ai_retains_published_heuristic_and_clears_plan(
    monkeypatch,
    tmp_path,
):
    target = tmp_path / "contact.txt"
    target.write_text("contact person@acme.invalid\n")
    entered_model = threading.Event()
    release_model = threading.Event()
    cancel = threading.Event()
    events = []
    outcome = {}
    plans = []
    real_refine = scanner_module._refine_file

    class BlockingAdapter:
        def available(self):
            return True

        def judge(self, _question):
            entered_model.set()
            release_model.wait(timeout=2)
            return LLMVerdict(is_sensitive=True, confidence=0.99, reason="private contact")

    def capture_plan(plan, *args, **kwargs):
        plans.append(plan)
        return real_refine(plan, *args, **kwargs)

    monkeypatch.setattr(scanner_module, "_refine_file", capture_plan)

    def run_scan():
        try:
            scan(
                ScanRequest(paths=[str(target)], use_llm=True),
                load_default_registry(),
                llm_adapter=BlockingAdapter(),
                execution=ScanExecution(
                    event_sink=events.append,
                    cancel_requested=cancel.is_set,
                ),
            )
        except BaseException as error:
            outcome["error"] = error

    worker = threading.Thread(target=run_scan)
    worker.start()
    try:
        assert entered_model.wait(timeout=1)
        cancel.set()
    finally:
        release_model.set()
        worker.join(timeout=2)

    assert isinstance(outcome.get("error"), ScanCancelled)
    partial = outcome["error"].partial_result
    assert len(partial.findings) == 1
    assert partial.scanned_files == [str(target)]
    assert [event.type for event in events][-1] == "scan_cancelled"
    assert plans and all(not plan.detections and not plan.description_lines for plan in plans)


def test_serial_adapter_gate_is_shared_across_scan_instances():
    active = 0
    maximum = 0
    state_lock = threading.Lock()
    start = threading.Barrier(3)

    class ObservedDelegate:
        def judge(self, _question):
            nonlocal active, maximum
            with state_lock:
                active += 1
                maximum = max(maximum, active)
            try:
                time.sleep(0.05)
                return LLMVerdict(is_sensitive=True, confidence=0.9, reason="done")
            finally:
                with state_lock:
                    active -= 1

    adapters = [
        scanner_module._TimedSerialAdapter(ObservedDelegate()),
        scanner_module._TimedSerialAdapter(ObservedDelegate()),
    ]

    def call(adapter):
        start.wait()
        adapter.judge("question")

    workers = [threading.Thread(target=call, args=(adapter,)) for adapter in adapters]
    for worker in workers:
        worker.start()
    start.wait()
    for worker in workers:
        worker.join(timeout=2)

    assert all(not worker.is_alive() for worker in workers)
    assert maximum == 1


def test_serial_adapter_does_not_start_queued_call_after_cancellation():
    entered_first = threading.Event()
    release_first = threading.Event()
    cancel = threading.Event()
    calls = []
    errors = []

    class BlockingDelegate:
        def judge(self, question):
            calls.append(question)
            entered_first.set()
            release_first.wait(timeout=2)
            return LLMVerdict(is_sensitive=True, confidence=0.9, reason="done")

    control = ScanExecution(cancel_requested=cancel.is_set)
    control.start()
    adapter = scanner_module._TimedSerialAdapter(BlockingDelegate(), control)

    first = threading.Thread(target=lambda: adapter.judge("first"))

    def call_second():
        try:
            adapter.judge("second")
        except BaseException as error:
            errors.append(error)

    second = threading.Thread(target=call_second)
    first.start()
    assert entered_first.wait(timeout=1)
    second.start()
    time.sleep(0.06)
    cancel.set()
    release_first.set()
    first.join(timeout=2)
    second.join(timeout=2)

    assert calls == ["first"]
    assert len(errors) == 1
    assert isinstance(errors[0], scanner_module._CancellationRequested)


def test_serial_adapter_does_not_start_queued_call_after_deadline():
    entered_first = threading.Event()
    release_first = threading.Event()
    now = [0.0]
    calls = []
    errors = []

    class BlockingDelegate:
        def judge(self, question):
            calls.append(question)
            entered_first.set()
            release_first.wait(timeout=2)
            return LLMVerdict(is_sensitive=True, confidence=0.9, reason="done")

    control = ScanExecution(job_timeout_seconds=1.0, clock=lambda: now[0])
    control.start()
    adapter = scanner_module._TimedSerialAdapter(BlockingDelegate(), control)
    first = threading.Thread(target=lambda: adapter.judge("first"))

    def call_second():
        try:
            adapter.judge("second")
        except BaseException as error:
            errors.append(error)

    second = threading.Thread(target=call_second)
    first.start()
    assert entered_first.wait(timeout=1)
    second.start()
    time.sleep(0.06)
    now[0] = 2.0
    release_first.set()
    first.join(timeout=2)
    second.join(timeout=2)

    assert calls == ["first"]
    assert len(errors) == 1
    assert isinstance(errors[0], scanner_module._DeadlineExceeded)


def test_cancellation_during_final_file_consolidation_cannot_complete(monkeypatch, tmp_path):
    target = tmp_path / "contact.txt"
    target.write_text("contact person@acme.invalid\n")
    cancel = threading.Event()
    events = []
    real_consolidate = scanner_module.consolidate_detection_groups

    def request_cancel(detections, checkpoint=None):
        cancel.set()
        return real_consolidate(detections, checkpoint=checkpoint)

    monkeypatch.setattr(scanner_module, "consolidate_detection_groups", request_cancel)

    with pytest.raises(ScanCancelled):
        scan(
            ScanRequest(paths=[str(target)]),
            load_default_registry(),
            execution=ScanExecution(
                event_sink=events.append,
                cancel_requested=cancel.is_set,
            ),
        )

    assert events[-1].type == "scan_cancelled"
    assert not any(event.type == "scan_completed" for event in events)


def test_timeout_during_final_file_consolidation_cannot_complete(monkeypatch, tmp_path):
    target = tmp_path / "contact.txt"
    target.write_text("contact person@acme.invalid\n")
    now = [0.0]
    events = []
    real_consolidate = scanner_module.consolidate_detection_groups

    def cross_deadline(detections, checkpoint=None):
        now[0] = 2.0
        return real_consolidate(detections, checkpoint=checkpoint)

    monkeypatch.setattr(scanner_module, "consolidate_detection_groups", cross_deadline)

    with pytest.raises(ScanTimedOut):
        scan(
            ScanRequest(paths=[str(target)]),
            load_default_registry(),
            execution=ScanExecution(
                event_sink=events.append,
                job_timeout_seconds=1.0,
                clock=lambda: now[0],
            ),
        )

    assert events[-1].type == "scan_failed"
    assert not any(event.type == "scan_completed" for event in events)
