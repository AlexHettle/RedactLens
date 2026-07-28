from fakes import FakeAdapter
from redactlens_core.anonymize import anonymize_text
from redactlens_core.llm.adapter import LLMVerdict
from redactlens_core.llm.description_targets import (
    MAX_DESCRIPTION_LINE_CHARS,
    scan_description_targets,
)
from redactlens_core.models import ScanOptions, ScanRequest, UserTarget
from redactlens_core.progress import ScanExecution
from redactlens_core.registry import load_default_registry
from redactlens_core.scanner import MAX_DESCRIPTION_CONFIRMATION_CANDIDATES, scan


def _adapter_for_description(match_text):
    def verdict(prompt: str) -> LLMVerdict:
        if "The user told RedactLens to watch for:" not in prompt:
            return LLMVerdict(
                is_sensitive=True,
                confidence=0.9,
                reason="deterministic candidate looks real",
            )
        snippet = prompt.split('Text: "', 1)[1].split('"\n', 1)[0]
        matches = match_text(snippet)
        return LLMVerdict(
            is_sensitive=matches,
            confidence=0.92 if matches else 0.08,
            reason="matches the requested concept" if matches else "different concept",
        )

    return FakeAdapter(verdict=verdict)


def _request(path, *, chunk_size: int | None = None) -> ScanRequest:
    options = ScanOptions(chunk_size=chunk_size) if chunk_size is not None else ScanOptions()
    return ScanRequest(
        paths=[str(path)],
        use_llm=True,
        user_targets=[
            UserTarget(
                kind="description",
                value="a Social Security number",
                category="custom",
            )
        ],
        options=options,
    )


def test_standalone_ai_description_passage_can_be_redacted_without_touching_other_lines(
    tmp_path,
):
    path = tmp_path / "record.txt"
    sensitive_passage = "employee id: EMP-99213"
    source = f"{sensitive_passage}\nunrelated line stays intact\n"
    path.write_text(source)

    result = scan(
        _request(path),
        load_default_registry(),
        llm_adapter=_adapter_for_description(lambda text: "EMP-99213" in text),
    )

    finding = next(
        finding for finding in result.findings if finding.detector_id == "user_target_desc_0"
    )
    redacted = anonymize_text(source, [finding])

    assert finding.can_anonymize is True
    assert sensitive_passage not in redacted
    assert redacted == ("*" * len(sensitive_passage)) + "\nunrelated line stays intact\n"


def test_confirmed_description_becomes_support_for_one_actionable_finding(tmp_path):
    path = tmp_path / "record.txt"
    source = "ssn = 123-45-6789\n"
    path.write_text(source)
    events = []

    result = scan(
        _request(path),
        load_default_registry(),
        llm_adapter=_adapter_for_description(lambda text: "123-45-6789" in text),
        execution=ScanExecution(event_sink=events.append),
    )

    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.detector_id == "us_ssn"
    assert finding.matched_text == "123-45-6789"
    assert source[finding.start_offset : finding.end_offset] == finding.matched_text
    assert [support.detector_id for support in finding.supporting_detections] == [
        "user_target_desc_0"
    ]
    assert finding.supporting_detections[0].relationship == "same_span"
    description_evidence = finding.evidence["description_targets"]
    assert description_evidence[0]["target"] == "a Social Security number"
    assert description_evidence[0]["span_reason"] == "matches the requested concept"
    assert result.summary["raw_detector_hits"] == 2
    assert result.summary["canonical_findings"] == 1
    assert result.summary["consolidated_hits"] == 1
    assert result.summary["suppressed_hits"] == 0

    finding_events = [event for event in events if event.finding is not None]
    assert [event.type for event in finding_events] == ["finding_added", "finding_updated"]
    assert {event.finding.id for event in finding_events} == {finding.id}
    assert "123-45-6789" not in anonymize_text(source, result.findings)

    repeated = scan(
        _request(path),
        load_default_registry(),
        llm_adapter=_adapter_for_description(lambda text: "123-45-6789" in text),
    )
    assert repeated.findings[0].id == finding.id


def test_unrelated_single_contained_finding_does_not_absorb_description(tmp_path):
    path = tmp_path / "record.txt"
    path.write_text("employee id: EMP-1 contact jane@example.com\n")

    def matches_employee_id(text: str) -> bool:
        return "EMP-1" in text

    request = ScanRequest(
        paths=[str(path)],
        use_llm=True,
        user_targets=[UserTarget(kind="description", value="an employee ID", category="custom")],
    )
    result = scan(
        request,
        load_default_registry(),
        llm_adapter=_adapter_for_description(matches_employee_id),
    )

    assert [finding.detector_id for finding in result.findings] == [
        "user_target_desc_0",
        "email",
    ]
    email = next(finding for finding in result.findings if finding.detector_id == "email")
    description = next(
        finding for finding in result.findings if finding.detector_id == "user_target_desc_0"
    )
    assert email.matched_text == "jane@example.com"
    assert email.supporting_detections == []
    assert email.can_anonymize is True
    assert description.matched_text == "employee id: EMP-1 contact jane@example.com"
    assert description.can_anonymize is True
    assert description.suggested_action == "anonymize"
    assert [finding.detector_id for finding in result.findings if finding.can_anonymize] == [
        "user_target_desc_0",
        "email",
    ]
    assert result.summary["raw_detector_hits"] == 2
    assert result.summary["canonical_findings"] == 2
    assert result.summary["consolidated_hits"] == 0


def test_description_selects_one_matching_concept_from_a_multi_concept_line(tmp_path):
    path = tmp_path / "record.txt"
    path.write_text("ssn 123-45-6789 contact jane@example.com\n")

    result = scan(
        _request(path),
        load_default_registry(),
        llm_adapter=_adapter_for_description(lambda text: "123-45-6789" in text),
    )

    assert [finding.detector_id for finding in result.findings] == ["us_ssn", "email"]
    ssn = result.findings[0]
    email = result.findings[1]
    assert [support.detector_id for support in ssn.supporting_detections] == ["user_target_desc_0"]
    assert ssn.supporting_detections[0].relationship == "same_span"
    assert email.supporting_detections == []
    assert result.summary["raw_detector_hits"] == 3
    assert result.summary["canonical_findings"] == 2
    assert result.summary["consolidated_hits"] == 1


def test_projected_support_uses_conservative_confirmation_confidence(tmp_path):
    path = tmp_path / "record.txt"
    path.write_text("ssn = 123-45-6789\n")

    def verdict(prompt: str) -> LLMVerdict:
        if "The user told RedactLens to watch for:" not in prompt:
            return LLMVerdict(is_sensitive=True, confidence=0.9, reason="looks real")
        snippet = prompt.split('Text: "', 1)[1].split('"\n', 1)[0]
        confidence = 0.6 if snippet == "123-45-6789" else 0.95
        return LLMVerdict(is_sensitive=True, confidence=confidence, reason="matches")

    result = scan(
        _request(path),
        load_default_registry(),
        llm_adapter=FakeAdapter(verdict=verdict),
    )

    finding = result.findings[0]
    support = finding.supporting_detections[0]
    assert support.detector_id == "user_target_desc_0"
    assert support.confidence == 0.6
    assert finding.evidence["description_targets"][0]["projected_confidence"] == 0.6
    assert finding.evidence["description_targets"][0]["projected_tier"] == "B"
    assert finding.can_anonymize is True


def test_description_confirmation_candidates_are_bounded(tmp_path):
    path = tmp_path / "many-emails.txt"
    email_count = MAX_DESCRIPTION_CONFIRMATION_CANDIDATES + 1
    line = " ".join(f"person{index}@example.com" for index in range(email_count))
    path.write_text(line + "\n")
    adapter = _adapter_for_description(lambda text: "person0@example.com" in text)
    request = ScanRequest(
        paths=[str(path)],
        use_llm=True,
        user_targets=[
            UserTarget(kind="description", value="the first email address", category="custom")
        ],
    )

    result = scan(request, load_default_registry(), llm_adapter=adapter)

    description_prompts = [
        prompt for prompt in adapter.calls if "The user told RedactLens to watch for:" in prompt
    ]
    description = next(
        finding for finding in result.findings if finding.detector_id == "user_target_desc_0"
    )
    assert len(description_prompts) == 1
    assert len(result.findings) == email_count + 1
    assert description.can_anonymize is True
    assert description.suggested_action == "anonymize"
    assert result.summary["raw_detector_hits"] == email_count + 1
    assert result.summary["consolidated_hits"] == 0


def test_standalone_description_opinions_on_the_same_span_are_canonicalized(tmp_path):
    path = tmp_path / "record.txt"
    path.write_text("employee id: EMP-1\n")
    request = ScanRequest(
        paths=[str(path)],
        use_llm=True,
        user_targets=[
            UserTarget(kind="description", value="an employee ID", category="custom"),
            UserTarget(
                kind="description",
                value="an internal staff identifier",
                category="custom",
            ),
        ],
    )

    result = scan(
        request,
        load_default_registry(),
        llm_adapter=_adapter_for_description(lambda text: "EMP-1" in text),
    )

    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.detector_id == "user_target_desc_0"
    assert finding.matched_text == "employee id: EMP-1"
    assert [support.detector_id for support in finding.supporting_detections] == [
        "user_target_desc_1"
    ]
    assert finding.supporting_detections[0].relationship == "same_span"
    assert result.summary["raw_detector_hits"] == 2
    assert result.summary["canonical_findings"] == 1
    assert result.summary["consolidated_hits"] == 1


def test_chunked_scan_uses_the_same_description_consolidation(tmp_path):
    path = tmp_path / "large-record.txt"
    prefix = "ssn = 123-45-6789\n"
    path.write_text(prefix + ("x" * 70_000))

    result = scan(
        _request(path, chunk_size=65_536),
        load_default_registry(),
        llm_adapter=_adapter_for_description(lambda text: "123-45-6789" in text),
    )

    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.detector_id == "us_ssn"
    assert finding.start_offset == prefix.index("123-45-6789")
    assert finding.end_offset == finding.start_offset + len("123-45-6789")
    assert [support.detector_id for support in finding.supporting_detections] == [
        "user_target_desc_0"
    ]
    assert finding.supporting_detections[0].relationship == "same_span"
    assert result.summary["raw_detector_hits"] == 2
    assert result.summary["canonical_findings"] == 1
    assert result.summary["consolidated_hits"] == 1


def test_chunked_scan_checks_unterminated_line_that_ends_in_right_overlap(tmp_path):
    path = tmp_path / "boundary-record.txt"
    prefix = ("x" * 65_530) + "\n"
    sensitive_line = "employee id: EMP-1"
    path.write_bytes((prefix + sensitive_line).encode())
    request = ScanRequest(
        paths=[str(path)],
        use_llm=True,
        user_targets=[UserTarget(kind="description", value="an employee ID", category="custom")],
        options=ScanOptions(chunk_size=65_536),
    )

    result = scan(
        request,
        load_default_registry(),
        llm_adapter=_adapter_for_description(lambda text: "EMP-1" in text),
    )

    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.detector_id == "user_target_desc_0"
    assert finding.matched_text == sensitive_line
    assert finding.start_offset == len(prefix)
    assert finding.end_offset == len(prefix) + len(sensitive_line)
    assert finding.line == 2
    assert finding.column == 1
    assert result.summary["raw_detector_hits"] == 1
    assert result.summary["canonical_findings"] == 1


def test_chunked_accumulator_reassembles_line_longer_than_detector_overlap(tmp_path):
    path = tmp_path / "long-line-record.txt"
    prefix = ("p" * 60_000) + "\n"
    sensitive_line = ("x" * 9_000) + " employee id: EMP-1"
    assert len(sensitive_line) < MAX_DESCRIPTION_LINE_CHARS
    path.write_bytes((prefix + sensitive_line).encode())
    adapter = _adapter_for_description(lambda text: "EMP-1" in text)
    request = ScanRequest(
        paths=[str(path)],
        use_llm=True,
        user_targets=[UserTarget(kind="description", value="an employee ID", category="custom")],
        options=ScanOptions(chunk_size=65_536),
    )

    result = scan(request, load_default_registry(), llm_adapter=adapter)

    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.detector_id == "user_target_desc_0"
    assert finding.matched_text == sensitive_line
    assert finding.start_offset == len(prefix)
    assert finding.end_offset == len(prefix) + len(sensitive_line)
    assert finding.line == 2
    assert finding.can_anonymize is True
    description_prompts = [
        prompt for prompt in adapter.calls if "The user told RedactLens to watch for:" in prompt
    ]
    assert len(description_prompts) == 1


def test_overlong_description_lines_are_skipped_without_model_prompts(tmp_path):
    target = UserTarget(kind="description", value="an employee ID", category="custom")
    overlong_line = ("x" * MAX_DESCRIPTION_LINE_CHARS) + " employee id: EMP-1"
    direct_adapter = _adapter_for_description(lambda text: "EMP-1" in text)

    direct = scan_description_targets(
        overlong_line,
        "notes.txt",
        [target],
        direct_adapter,
        tier_threshold=0.75,
    )

    assert direct == []
    assert direct_adapter.calls == []

    path = tmp_path / "overlong-streamed-record.txt"
    prefix = ("p" * 60_000) + "\n"
    path.write_bytes((prefix + overlong_line).encode())
    streamed_adapter = _adapter_for_description(lambda text: "EMP-1" in text)
    result = scan(
        ScanRequest(
            paths=[str(path)],
            use_llm=True,
            user_targets=[target],
            options=ScanOptions(chunk_size=65_536),
        ),
        load_default_registry(),
        llm_adapter=streamed_adapter,
    )

    assert result.findings == []
    assert streamed_adapter.calls == []
    assert result.summary["raw_detector_hits"] == 0
