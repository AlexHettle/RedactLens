"""OpenDocument (odt/ods/odp) extraction and write-back. Fixtures are
minimal in-memory ODF zips; roundtrips run scan → anonymize → re-extract."""

import io
import zipfile
from pathlib import Path

import pytest
from redactlens_core.anonymize import anonymize_files
from redactlens_core.extractors import extract_document
from redactlens_core.models import ScanRequest
from redactlens_core.registry import load_default_registry
from redactlens_core.scanner import scan

SSN = "123-45-6789"
MASKED_SSN = "*******6789"

_DECL = (
    'xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" '
    'xmlns:text="urn:oasis:names:tc:opendocument:xmlns:text:1.0" '
    'xmlns:table="urn:oasis:names:tc:opendocument:xmlns:table:1.0" '
    'xmlns:draw="urn:oasis:names:tc:opendocument:xmlns:drawing:1.0" '
    'xmlns:presentation="urn:oasis:names:tc:opendocument:xmlns:presentation:1.0" '
    'xmlns:style="urn:oasis:names:tc:opendocument:xmlns:style:1.0"'
)


def _odf_zip(mimetype: str, content_body: str, styles_body: str | None = None) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as zf:
        zf.writestr("mimetype", mimetype)
        zf.writestr(
            "content.xml",
            f"<office:document-content {_DECL}><office:body>{content_body}</office:body>"
            "</office:document-content>",
        )
        if styles_body is not None:
            zf.writestr(
                "styles.xml",
                f"<office:document-styles {_DECL}>{styles_body}</office:document-styles>",
            )
    return buffer.getvalue()


def make_odt(paragraphs: list[str], header: str | None = None) -> bytes:
    body = "<office:text>" + "".join(f"<text:p>{p}</text:p>" for p in paragraphs) + "</office:text>"
    styles = None
    if header is not None:
        styles = (
            '<office:master-styles><style:master-page style:name="Standard">'
            f"<style:header><text:p>{header}</text:p></style:header>"
            "</style:master-page></office:master-styles>"
        )
    return _odf_zip("application/vnd.oasis.opendocument.text", body, styles)


def make_ods(rows_xml: str, sheet_name: str = "Pay") -> bytes:
    body = (
        f'<office:spreadsheet><table:table table:name="{sheet_name}">{rows_xml}</table:table>'
        "</office:spreadsheet>"
    )
    return _odf_zip("application/vnd.oasis.opendocument.spreadsheet", body)


def make_odp(slide_text: str, notes_text: str | None = None) -> bytes:
    notes = ""
    if notes_text is not None:
        notes = (
            "<presentation:notes><draw:frame><draw:text-box>"
            f"<text:p>{notes_text}</text:p>"
            "</draw:text-box></draw:frame></presentation:notes>"
        )
    body = (
        "<office:presentation><draw:page>"
        f"<draw:frame><draw:text-box><text:p>{slide_text}</text:p></draw:text-box></draw:frame>"
        f"{notes}"
        "</draw:page></office:presentation>"
    )
    return _odf_zip("application/vnd.oasis.opendocument.presentation", body)


def _scan(folder) -> list:
    return scan(ScanRequest(paths=[str(folder)]), load_default_registry()).findings


def _extracted_text(path: Path) -> str:
    return extract_document(path.suffix.lower(), path.read_bytes()).text


def test_odt_extracts_paragraphs_with_locations():
    raw = make_odt(["intro", f"my ssn is {SSN}"])

    doc = extract_document(".odt", raw)

    assert doc.format == "odt"
    assert doc.location_at(doc.text.index(SSN)) == "paragraph 2"


def test_odt_value_split_by_inline_span_is_detected_and_anonymized(tmp_path):
    # Mixed content: the value straddles a span boundary (text/tail pieces).
    raw = make_odt(["ssn 123-<text:span>45-67</text:span>89 end"])
    original = tmp_path / "notes.odt"
    original.write_bytes(raw)
    findings = [f for f in _scan(tmp_path) if f.detector_id == "us_ssn"]
    assert findings and findings[0].can_anonymize is True

    outputs = anonymize_files(findings)

    redacted = Path(outputs[str(original)])
    assert redacted.name == "notes-auto-redacted-copy.odt"
    text = _extracted_text(redacted)
    assert SSN not in text
    assert text.startswith("ssn ") and text.endswith(" end")
    assert MASKED_SSN in text
    assert SSN in _extracted_text(original)  # original untouched


def test_odt_header_in_styles_xml_is_extracted_and_anonymized(tmp_path):
    original = tmp_path / "letter.odt"
    original.write_bytes(make_odt(["body"], header=f"case ssn {SSN}"))
    findings = [f for f in _scan(tmp_path) if f.detector_id == "us_ssn"]
    assert findings and findings[0].location == "header 1"

    outputs = anonymize_files(findings)

    with zipfile.ZipFile(Path(outputs[str(original)])) as zf:
        styles = zf.read("styles.xml").decode()
        assert SSN not in styles
        assert MASKED_SSN in styles
        assert zf.read("mimetype") == b"application/vnd.oasis.opendocument.text"


def test_odt_variable_field_is_flattened_with_its_backing_value(tmp_path):
    field = (
        f'<text:variable-set text:name="claim" office:value-type="string" '
        f'office:string-value="{SSN}">{SSN}</text:variable-set>'
    )
    original = tmp_path / "variable.odt"
    original.write_bytes(make_odt([field]))
    findings = [f for f in _scan(tmp_path) if f.detector_id == "us_ssn"]
    assert findings

    outputs = anonymize_files(findings)

    redacted = Path(outputs[str(original)])
    with zipfile.ZipFile(redacted) as zf:
        content = zf.read("content.xml").decode()
    assert SSN not in content
    assert MASKED_SSN in content
    assert "variable-set" not in content
    assert _extracted_text(redacted) == MASKED_SSN


def test_odt_orphaned_user_field_backing_value_is_scrubbed(tmp_path):
    body = (
        "<office:text>"
        "<text:user-field-decls>"
        f'<text:user-field-decl text:name="claim" office:value-type="string" '
        f'office:string-value="{SSN}"/>'
        "</text:user-field-decls>"
        f'<text:p><text:user-field-get text:name="claim">{SSN}</text:user-field-get></text:p>'
        "</office:text>"
    )
    original = tmp_path / "user-field.odt"
    original.write_bytes(_odf_zip("application/vnd.oasis.opendocument.text", body))
    findings = [f for f in _scan(tmp_path) if f.detector_id == "us_ssn"]
    assert findings

    outputs = anonymize_files(findings)

    redacted = Path(outputs[str(original)])
    with zipfile.ZipFile(redacted) as zf:
        content = zf.read("content.xml").decode()
    assert SSN not in content
    assert MASKED_SSN in content
    assert "user-field-get" not in content
    assert "string-value" not in content
    assert _extracted_text(redacted) == MASKED_SSN


def test_odt_user_field_backing_is_kept_for_an_ignored_reference(tmp_path):
    body = (
        "<office:text>"
        "<text:user-field-decls>"
        f'<text:user-field-decl text:name="claim" office:value-type="string" '
        f'office:string-value="{SSN}"/>'
        "</text:user-field-decls>"
        f'<text:p><text:user-field-get text:name="claim">{SSN}</text:user-field-get></text:p>'
        f'<text:p><text:user-field-get text:name="claim">{SSN}</text:user-field-get></text:p>'
        "</office:text>"
    )
    original = tmp_path / "shared-user-field.odt"
    original.write_bytes(_odf_zip("application/vnd.oasis.opendocument.text", body))
    findings = sorted(
        (finding for finding in _scan(tmp_path) if finding.detector_id == "us_ssn"),
        key=lambda finding: finding.start_offset,
    )
    assert len(findings) == 2

    outputs = anonymize_files([findings[0]])

    redacted = Path(outputs[str(original)])
    with zipfile.ZipFile(redacted) as zf:
        content = zf.read("content.xml").decode()
    assert _extracted_text(redacted) == f"{MASKED_SSN}\n{SSN}"
    assert content.count("<text:user-field-get") == 1
    assert f'office:string-value="{SSN}"' in content


def test_ods_cell_addressing_respects_repeated_columns():
    rows = (
        "<table:table-row>"
        '<table:table-cell table:number-columns-repeated="2"/>'
        f"<table:table-cell><text:p>{SSN}</text:p></table:table-cell>"
        "</table:table-row>"
    )
    doc = extract_document(".ods", make_ods(rows))

    # Two repeated empty cells occupy A1:B1, so the value sits in C1.
    assert doc.location_at(doc.text.index(SSN)) == "Pay!C1"


def test_ods_anonymize_scrubs_office_value_attribute(tmp_path):
    card = "4111111111111111"
    rows = (
        "<table:table-row>"
        f'<table:table-cell office:value-type="float" office:value="{card}">'
        f"<text:p>{card}</text:p></table:table-cell>"
        "</table:table-row>"
    )
    original = tmp_path / "cards.ods"
    original.write_bytes(make_ods(rows, sheet_name="Cards"))
    findings = [f for f in _scan(tmp_path) if f.detector_id == "credit_card"]
    assert findings and findings[0].location == "Cards!A1"

    outputs = anonymize_files(findings)

    with zipfile.ZipFile(Path(outputs[str(original)])) as zf:
        content = zf.read("content.xml").decode()
    # Neither the display text NOR the office:value attribute may leak it.
    assert card not in content
    assert "************1111" in content


def test_ods_anonymize_removes_formula_that_can_restore_the_secret(tmp_path):
    card = "4111111111111111"
    rows = (
        "<table:table-row>"
        f'<table:table-cell office:value-type="string" office:string-value="{card}" '
        f'table:formula="of:=&quot;{card}&quot;">'
        f"<text:p>{card}</text:p></table:table-cell>"
        "</table:table-row>"
    )
    original = tmp_path / "formula.ods"
    original.write_bytes(make_ods(rows, sheet_name="Cards"))
    findings = [f for f in _scan(tmp_path) if f.detector_id == "credit_card"]
    assert findings

    outputs = anonymize_files(findings)

    redacted = Path(outputs[str(original)])
    with zipfile.ZipFile(redacted) as zf:
        content = zf.read("content.xml").decode()
    assert card not in content
    assert "************1111" in content
    assert "table:formula" not in content
    assert _extracted_text(redacted) == "************1111"


def test_odp_slide_and_notes_are_extracted_and_anonymized(tmp_path):
    original = tmp_path / "deck.odp"
    original.write_bytes(make_odp(f"slide ssn {SSN}", notes_text="note ssn 987-65-4321"))
    findings = [f for f in _scan(tmp_path) if f.detector_id == "us_ssn"]
    assert {f.location for f in findings} == {"slide 1", "slide 1 notes"}
    assert all(f.can_anonymize for f in findings)

    outputs = anonymize_files(findings)

    text = _extracted_text(Path(outputs[str(original)]))
    assert SSN not in text and "987-65-4321" not in text
    assert MASKED_SSN in text and "*******4321" in text


def test_odf_changed_since_scan_is_refused(tmp_path):
    original = tmp_path / "notes.odt"
    original.write_bytes(make_odt([f"ssn {SSN}"]))
    findings = [f for f in _scan(tmp_path) if f.detector_id == "us_ssn"]

    original.write_bytes(make_odt(["different content now"]))

    with pytest.raises(ValueError, match="changed since it was scanned"):
        anonymize_files(findings)
