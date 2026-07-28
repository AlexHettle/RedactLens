"""Focused tests for the browser-facing privacy projection."""

import io
import zipfile
from datetime import UTC, datetime, timedelta

from redactlens_api.contracts import (
    MAX_PUBLIC_LOCATION_LENGTH,
    PublicFinding,
    PublicRedactor,
    PublicScanError,
    PublicScanEvent,
    PublicScanMetadata,
    PublicScanProgress,
    PublicScanResult,
)
from redactlens_core.llm.adapter import LLMVerdict
from redactlens_core.llm.description_targets import (
    DESCRIPTION_TARGET_EXPLANATION,
    DESCRIPTION_TARGET_RISK_LESSON,
    scan_description_targets,
)
from redactlens_core.models import (
    ScanRequest,
    ScanResult,
    SkippedFile,
    SupportingDetection,
    UserTarget,
)
from redactlens_core.registry import load_default_registry
from redactlens_core.scanner import scan

_S_NS = 'xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"'


def _xlsx_with_sheet_and_cell(sheet_name: str, value: str) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("xl/sharedStrings.xml", f"<sst {_S_NS}><si><t>{value}</t></si></sst>")
        archive.writestr(
            "xl/workbook.xml",
            f'<workbook {_S_NS}><sheets><sheet name="{sheet_name}" sheetId="1"/></sheets>'
            "</workbook>",
        )
        archive.writestr(
            "xl/worksheets/sheet1.xml",
            f'<worksheet {_S_NS}><sheetData><row><c r="A1" t="s"><v>0</v></c></row>'
            "</sheetData></worksheet>",
        )
    return buffer.getvalue()


class EchoingAdapter:
    """Simulate a local model that repeats sensitive source text in its reason."""

    def __init__(self, raw_value: str) -> None:
        self.raw_value = raw_value

    def available(self) -> bool:
        return True

    def judge(self, _question: str) -> LLMVerdict:
        return LLMVerdict(
            is_sensitive=True,
            confidence=0.9,
            reason=f"Matched raw value {self.raw_value}",
        )


def _internal_description_finding(raw_value: str):
    return scan_description_targets(
        f"employee id: {raw_value}\n",
        "notes.txt",
        [UserTarget(kind="description", value="an employee ID", category="custom")],
        EchoingAdapter(raw_value),
        tier_threshold=0.75,
    )[0]


def _exact_description_finding(raw_value: str):
    return scan_description_targets(
        f"{raw_value}\n",
        "notes.txt",
        [UserTarget(kind="description", value=raw_value, category="custom")],
        EchoingAdapter(raw_value),
        tier_threshold=0.75,
    )[0]


def test_description_model_reason_is_absent_from_public_snapshot():
    raw_value = "EMP-99213"
    internal = _internal_description_finding(raw_value)
    now = datetime.now(UTC)

    snapshot = PublicScanResult.from_internal(
        scan_id="scan-1",
        created_at=now,
        expires_at=now + timedelta(minutes=15),
        result=ScanResult(findings=[internal], llm_used=True),
    )
    serialized = snapshot.model_dump_json()

    assert raw_value in internal.evidence["llm_reason"]
    assert snapshot.findings[0].risk_lesson == DESCRIPTION_TARGET_RISK_LESSON
    assert raw_value not in serialized


def test_description_model_reason_is_absent_from_public_scan_event():
    raw_value = "EMP-99213"
    internal = _internal_description_finding(raw_value)
    progress = PublicScanProgress(
        stage="detection",
        completed_files=0,
        total_files=1,
        percent=50,
        current_file="notes.txt",
        findings_so_far=1,
    )

    event = PublicScanEvent(
        sequence=1,
        type="finding_added",
        emitted_at=datetime.now(UTC),
        scan_id="scan-1",
        state="scanning",
        progress=progress,
        finding=PublicFinding.from_internal(internal),
    )
    serialized = f"data: {event.model_dump_json()}\n\n"

    assert event.finding is not None
    assert event.finding.risk_lesson == DESCRIPTION_TARGET_RISK_LESSON
    assert raw_value not in serialized


def test_exact_description_target_is_absent_from_public_snapshot_and_event():
    raw_value = "EMP-99213"
    internal = _exact_description_finding(raw_value)
    now = datetime.now(UTC)
    snapshot = PublicScanResult.from_internal(
        scan_id="scan-1",
        created_at=now,
        expires_at=now + timedelta(minutes=15),
        result=ScanResult(findings=[internal], llm_used=True),
    )
    event = PublicScanEvent(
        sequence=1,
        type="finding_added",
        emitted_at=now,
        scan_id="scan-1",
        state="scanning",
        progress=PublicScanProgress(
            stage="detection",
            completed_files=0,
            total_files=1,
            findings_so_far=1,
        ),
        finding=PublicFinding.from_internal(internal),
    )

    assert internal.matched_text == raw_value
    assert internal.explanation == DESCRIPTION_TARGET_EXPLANATION
    assert raw_value not in snapshot.model_dump_json()
    assert raw_value not in event.model_dump_json()


def test_public_projection_scrubs_raw_match_from_every_explanatory_field():
    raw_value = "EMP-99213"
    internal = _exact_description_finding(raw_value).model_copy(
        update={
            "explanation": f"A detector repeated {raw_value}.",
            "risk_lesson": f"Do not expose {raw_value}.",
            "supporting_detections": [
                SupportingDetection(
                    detector_id="support",
                    description=f"Supporting evidence repeated {raw_value}.",
                    confidence=0.8,
                    relationship="same_span",
                )
            ],
        }
    )

    public = PublicFinding.from_internal(internal)
    serialized = public.model_dump_json()

    assert raw_value not in serialized
    assert internal.redacted_preview in public.explanation
    assert internal.redacted_preview in public.risk_lesson
    assert internal.redacted_preview in public.supporting_detections[0].description


def test_consolidated_description_target_is_absent_from_snapshot_and_event(tmp_path):
    raw_value = "123-45-6789"
    target = tmp_path / "personal-id.txt"
    target.write_text(f"{raw_value}\n")
    result = scan(
        ScanRequest(
            paths=[str(target)],
            categories=["personal_id"],
            user_targets=[UserTarget(kind="description", value=raw_value, category="custom")],
            use_llm=True,
        ),
        load_default_registry(),
        llm_adapter=EchoingAdapter(raw_value),
    )
    internal = next(finding for finding in result.findings if finding.detector_id == "us_ssn")
    now = datetime.now(UTC)
    snapshot = PublicScanResult.from_internal(
        scan_id="scan-1",
        created_at=now,
        expires_at=now + timedelta(minutes=15),
        result=result,
    )
    event = PublicScanEvent(
        sequence=2,
        type="finding_updated",
        emitted_at=now,
        scan_id="scan-1",
        state="refining",
        progress=PublicScanProgress(
            stage="ai_refinement",
            completed_files=0,
            total_files=1,
            findings_so_far=1,
        ),
        finding=PublicFinding.from_internal(internal),
    )

    description_support = next(
        supporting
        for supporting in internal.supporting_detections
        if supporting.detector_id == "user_target_desc_0"
    )
    assert internal.matched_text == raw_value
    assert description_support.description == DESCRIPTION_TARGET_EXPLANATION
    assert raw_value not in snapshot.model_dump_json()
    assert raw_value not in event.model_dump_json()


def test_xlsx_location_cannot_reintroduce_the_raw_match(tmp_path):
    raw_value = "123-45-6789"
    workbook = tmp_path / "sensitive-location.xlsx"
    workbook.write_bytes(_xlsx_with_sheet_and_cell(raw_value, raw_value))
    result = scan(ScanRequest(paths=[str(workbook)]), load_default_registry())
    internal = next(finding for finding in result.findings if finding.detector_id == "us_ssn")
    now = datetime.now(UTC)

    snapshot = PublicScanResult.from_internal(
        scan_id="scan-1",
        created_at=now,
        expires_at=now + timedelta(minutes=15),
        result=result,
    )
    public = next(finding for finding in snapshot.findings if finding.id == internal.id)

    assert internal.matched_text == raw_value
    assert internal.location == f"{raw_value}!A1"
    assert public.location == f"{internal.redacted_preview}!A1"
    assert raw_value not in snapshot.model_dump_json()


def test_scan_wide_projection_redacts_a_raw_match_repeated_in_every_path_field(tmp_path):
    raw_value = "123-45-6789"
    selected_root = tmp_path / f"records-{raw_value}"
    selected_root.mkdir()
    target = selected_root / f"employee-{raw_value}.txt"
    target.write_text(f"{raw_value}\n")
    result = scan(ScanRequest(paths=[str(target)]), load_default_registry())
    internal = next(finding for finding in result.findings if finding.detector_id == "us_ssn")
    skipped = SkippedFile(
        path=str(selected_root / f"skipped-{raw_value}.txt"),
        reason=f"Could not inspect the file named {raw_value}.",
        rule=f"ignore-{raw_value}",
    )
    result = result.model_copy(
        update={
            "summary": {**result.summary, "diagnostic": f"processed {raw_value}"},
            "skipped_files": [skipped],
        },
        deep=True,
    )
    now = datetime.now(UTC)

    snapshot = PublicScanResult.from_internal(
        scan_id="scan-path-redaction",
        created_at=now,
        expires_at=now + timedelta(minutes=15),
        result=result,
        progress=PublicScanProgress(current_file=str(target)),
        error=PublicScanError(code="test", message=f"Could not open {target}"),
        metadata=PublicScanMetadata(selected_roots=[str(selected_root)]),
    )
    serialized = snapshot.model_dump_json()

    assert raw_value in internal.file_path
    assert raw_value in result.scanned_files[0]
    assert raw_value not in serialized
    assert "<sensitive-path-1>" in snapshot.findings[0].file_path
    assert "<sensitive-path-1>" in snapshot.scanned_files[0]
    assert "<sensitive-path-1>" in snapshot.metadata.selected_roots[0]


def test_scan_wide_projection_redacts_another_findings_match_from_location():
    first_raw = "EMP-11111"
    second_raw = "EMP-22222"
    first = _exact_description_finding(first_raw).model_copy(
        update={"location": f"archive-{second_raw}.xlsx · {second_raw}!B7"}
    )
    second = _exact_description_finding(second_raw)
    now = datetime.now(UTC)

    snapshot = PublicScanResult.from_internal(
        scan_id="scan-cross-location",
        created_at=now,
        expires_at=now + timedelta(minutes=15),
        result=ScanResult(findings=[first, second]),
    )
    projected_first = next(finding for finding in snapshot.findings if finding.id == first.id)

    assert projected_first.location is not None
    assert second_raw not in projected_first.location
    assert second.redacted_preview in projected_first.location
    assert second_raw not in snapshot.model_dump_json()


def test_path_redaction_keeps_distinct_files_when_matches_share_a_preview():
    first_raw = "EMP-11111"
    second_raw = "EMP-22222"
    shared_preview = "EM*******22"
    first_path = f"/records/{first_raw}.txt"
    second_path = f"/records/{second_raw}.txt"
    first = _exact_description_finding(first_raw).model_copy(
        update={"file_path": first_path, "redacted_preview": shared_preview}
    )
    second = _exact_description_finding(second_raw).model_copy(
        update={"file_path": second_path, "redacted_preview": shared_preview}
    )
    now = datetime.now(UTC)

    snapshot = PublicScanResult.from_internal(
        scan_id="scan-distinct-paths",
        created_at=now,
        expires_at=now + timedelta(minutes=15),
        result=ScanResult(
            findings=[first, second],
            scanned_files=[first_path, second_path],
        ),
    )
    finding_paths = {finding.file_path for finding in snapshot.findings}

    assert len(finding_paths) == 2
    assert len(set(snapshot.scanned_files)) == 2
    assert any("<sensitive-path-1>" in path for path in finding_paths)
    assert any("<sensitive-path-2>" in path for path in finding_paths)
    assert first_raw not in snapshot.model_dump_json()
    assert second_raw not in snapshot.model_dump_json()


def test_path_marker_cannot_collide_with_a_literal_filename():
    raw_value = "EMP-11111"
    sensitive_path = f"/records/{raw_value}.txt"
    literal_marker_path = "/records/<sensitive-path-1>.txt"
    internal = _exact_description_finding(raw_value).model_copy(
        update={"file_path": sensitive_path}
    )
    now = datetime.now(UTC)

    snapshot = PublicScanResult.from_internal(
        scan_id="scan-marker-paths",
        created_at=now,
        expires_at=now + timedelta(minutes=15),
        result=ScanResult(
            findings=[internal],
            scanned_files=[sensitive_path, literal_marker_path],
        ),
    )

    assert len(set(snapshot.scanned_files)) == 2
    assert snapshot.findings[0].file_path != literal_marker_path
    assert literal_marker_path in snapshot.scanned_files
    assert raw_value not in snapshot.model_dump_json()


def test_path_projection_disambiguates_control_and_unicode_normalization_collisions():
    paths = [
        "/records/a\tb.txt",
        "/records/a b.txt",
        "/records/café.txt",
        "/records/cafe\u0301.txt",
    ]
    now = datetime.now(UTC)

    snapshot = PublicScanResult.from_internal(
        scan_id="scan-normalized-paths",
        created_at=now,
        expires_at=now + timedelta(minutes=15),
        result=ScanResult(scanned_files=paths),
    )

    assert len(snapshot.scanned_files) == len(paths)
    assert len(set(snapshot.scanned_files)) == len(paths)
    assert all("\t" not in path for path in snapshot.scanned_files)


def test_new_derived_paths_extend_identity_mapping_without_collapsing():
    sources = ["/records/a\tb.txt", "/records/a b.txt"]
    outputs = [f"{source.removesuffix('.txt')}-auto-redacted-copy.txt" for source in sources]
    redactor = PublicRedactor.from_findings([], reserved_paths=sources)
    source_labels = [redactor.path(path) for path in sources]

    extended = redactor.with_reserved_paths(outputs)
    output_labels = [extended.path(path) for path in outputs]

    assert [extended.path(path) for path in sources] == source_labels
    assert len(set(source_labels)) == 2
    assert len(set(output_labels)) == 2


def test_path_redaction_matches_control_normalization_without_collapsing_spaces():
    raw_value = "EMP\t\t123"
    normalized_path_value = "EMP  123"
    internal = _exact_description_finding("EMP-00123").model_copy(
        update={
            "matched_text": raw_value,
            "redacted_preview": "EM*****23",
            "file_path": f"/records/{raw_value}.txt",
        }
    )
    now = datetime.now(UTC)

    snapshot = PublicScanResult.from_internal(
        scan_id="scan-control-path",
        created_at=now,
        expires_at=now + timedelta(minutes=15),
        result=ScanResult(
            findings=[internal],
            scanned_files=[internal.file_path],
        ),
    )
    serialized = snapshot.model_dump_json()

    assert raw_value not in serialized
    assert normalized_path_value not in serialized
    assert "<sensitive-path-1>" in snapshot.findings[0].file_path
    assert "<sensitive-path-1>" in snapshot.scanned_files[0]


def test_user_category_and_summary_key_cannot_repeat_the_raw_match():
    raw_value = "EMP-44556"
    category = f"employee-{raw_value}"
    internal = _exact_description_finding(raw_value).model_copy(update={"category": category})
    now = datetime.now(UTC)

    snapshot = PublicScanResult.from_internal(
        scan_id="scan-category",
        created_at=now,
        expires_at=now + timedelta(minutes=15),
        result=ScanResult(
            findings=[internal],
            summary={"category_counts": {category: 1}},
        ),
    )

    assert raw_value not in snapshot.model_dump_json()
    assert snapshot.findings[0].category != category
    assert list(snapshot.summary["category_counts"]) == [snapshot.findings[0].category]


def test_public_location_is_control_free_bounded_and_keeps_its_coordinate(tmp_path):
    raw_value = "123-45-6789"
    workbook = tmp_path / "bounded-location.xlsx"
    workbook.write_bytes(_xlsx_with_sheet_and_cell("Sheet", raw_value))
    result = scan(ScanRequest(paths=[str(workbook)]), load_default_registry())
    internal = next(finding for finding in result.findings if finding.detector_id == "us_ssn")
    internal = internal.model_copy(
        update={
            "location": f"archive\n\x00{raw_value}{'x' * 700} · Sheet!B7",
        }
    )

    public = PublicFinding.from_internal(internal)

    assert public.location is not None
    assert raw_value not in public.location
    assert "\n" not in public.location
    assert "\x00" not in public.location
    assert len(public.location) <= MAX_PUBLIC_LOCATION_LENGTH
    assert public.location.endswith("Sheet!B7")
    assert internal.redacted_preview in public.location
