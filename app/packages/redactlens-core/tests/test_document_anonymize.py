"""Write-back anonymization for docx/xlsx (Phase B). Fixtures are built
in memory like the extractor tests; every test round-trips through the real
scan → anonymize → re-extract pipeline."""

import io
import zipfile
from pathlib import Path

import pytest
from redactlens_core.anonymize import anonymize_files
from redactlens_core.document_anonymize import render_anonymized_document
from redactlens_core.extractors import extract_document
from redactlens_core.models import ScanRequest
from redactlens_core.registry import load_default_registry
from redactlens_core.scanner import scan
from test_extractors import (
    _A_NS,
    _P_NS,
    _S_NS,
    _W_NS,
    make_docx,
    make_docx_parts,
    make_pptx,
    make_xlsx,
)

SSN = "123-45-6789"
MASKED_SSN = "*******6789"  # us_ssn uses PARTIAL_MASK, last 4 kept


def make_docx_runs(paragraphs: list[list[str]], extra_members: dict[str, str] | None = None):
    """Like make_docx but each paragraph is a list of separate <w:t> runs,
    the way Word fragments real documents."""
    body = "".join(
        "<w:p>" + "".join(f"<w:r><w:t>{run}</w:t></w:r>" for run in runs) + "</w:p>"
        for runs in paragraphs
    )
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as zf:
        zf.writestr(
            "word/document.xml", f"<w:document {_W_NS}><w:body>{body}</w:body></w:document>"
        )
        for name, content in (extra_members or {}).items():
            zf.writestr(name, content)
    return buffer.getvalue()


def make_docx_xml(document: str) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as zf:
        zf.writestr("word/document.xml", document)
    return buffer.getvalue()


def _scan(folder) -> list:
    return scan(ScanRequest(paths=[str(folder)]), load_default_registry()).findings


def _extracted_text(path: Path) -> str:
    return extract_document(path.suffix.lower(), path.read_bytes()).text


def test_document_renderer_rejects_a_static_symbolic_link_source(tmp_path):
    target = tmp_path / "actual.docx"
    target.write_bytes(make_docx([f"my ssn is {SSN}"]))
    redirected = tmp_path / "redirected.docx"
    try:
        redirected.symlink_to(target)
    except OSError as error:
        pytest.skip(f"file symlinks are unavailable in this environment: {error}")

    with pytest.raises(OSError, match="symbolic link"):
        render_anonymized_document(str(redirected), [])


def test_docx_findings_are_anonymizable_and_write_a_redacted_copy(tmp_path):
    original = tmp_path / "notes.docx"
    original.write_bytes(make_docx(["meeting notes", f"my ssn is {SSN} ok", "wrap-up"]))
    findings = [f for f in _scan(tmp_path) if f.detector_id == "us_ssn"]
    assert findings and findings[0].can_anonymize is True

    outputs = anonymize_files(findings)

    redacted = Path(outputs[str(original)])
    assert redacted.name == "notes-auto-redacted-copy.docx"  # extension kept → still opens in Word
    text = _extracted_text(redacted)
    assert SSN not in text
    assert f"my ssn is {MASKED_SSN} ok" in text
    assert "meeting notes" in text and "wrap-up" in text  # untouched content intact
    assert SSN in _extracted_text(original)  # original untouched


def test_docx_value_split_across_runs_is_replaced(tmp_path):
    original = tmp_path / "split.docx"
    original.write_bytes(make_docx_runs([["ssn: 123-45", "-6789 end"]]))
    findings = [f for f in _scan(tmp_path) if f.detector_id == "us_ssn"]
    assert findings, "the split SSN must still be detected via concatenated runs"

    outputs = anonymize_files(findings)

    text = _extracted_text(Path(outputs[str(original)]))
    assert SSN not in text
    assert MASKED_SSN in text
    assert text.startswith("ssn: ") and text.endswith(" end")


def test_docx_simple_field_is_flattened_with_its_backing_instruction(tmp_path):
    document = (
        f"<w:document {_W_NS}><w:body><w:p>"
        f'<w:fldSimple w:instr=" MERGEFIELD &quot;{SSN}&quot; ">'
        f"<w:r><w:t>{SSN}</w:t></w:r>"
        "</w:fldSimple>"
        "</w:p></w:body></w:document>"
    )
    original = tmp_path / "simple-field.docx"
    original.write_bytes(make_docx_xml(document))
    findings = [f for f in _scan(tmp_path) if f.detector_id == "us_ssn"]
    assert findings

    outputs = anonymize_files(findings)

    redacted = Path(outputs[str(original)])
    with zipfile.ZipFile(redacted) as zf:
        xml = zf.read("word/document.xml").decode()
    assert SSN not in xml
    assert MASKED_SSN in xml
    assert "fldSimple" not in xml
    assert _extracted_text(redacted) == MASKED_SSN


def test_docx_complex_field_is_flattened_with_its_instruction_runs(tmp_path):
    document = (
        f"<w:document {_W_NS}><w:body><w:p>"
        '<w:r><w:fldChar w:fldCharType="begin"/></w:r>'
        f"<w:r><w:instrText> MERGEFIELD &quot;{SSN}&quot; </w:instrText></w:r>"
        '<w:r><w:fldChar w:fldCharType="separate"/></w:r>'
        f"<w:r><w:t>{SSN}</w:t></w:r>"
        '<w:r><w:fldChar w:fldCharType="end"/></w:r>'
        "</w:p></w:body></w:document>"
    )
    original = tmp_path / "complex-field.docx"
    original.write_bytes(make_docx_xml(document))
    findings = [f for f in _scan(tmp_path) if f.detector_id == "us_ssn"]
    assert findings

    outputs = anonymize_files(findings)

    redacted = Path(outputs[str(original)])
    with zipfile.ZipFile(redacted) as zf:
        xml = zf.read("word/document.xml").decode()
    assert SSN not in xml
    assert MASKED_SSN in xml
    assert "instrText" not in xml
    assert "fldChar" not in xml
    assert _extracted_text(redacted) == MASKED_SSN


def test_docx_malformed_complex_field_is_refused_instead_of_leaking_instruction(tmp_path):
    document = (
        f"<w:document {_W_NS}><w:body><w:p>"
        '<w:r><w:fldChar w:fldCharType="begin"/></w:r>'
        f"<w:r><w:instrText> MERGEFIELD &quot;{SSN}&quot; </w:instrText></w:r>"
        '<w:r><w:fldChar w:fldCharType="separate"/></w:r>'
        f"<w:r><w:t>{SSN}</w:t></w:r>"
        "</w:p></w:body></w:document>"
    )
    original = tmp_path / "malformed-field.docx"
    original.write_bytes(make_docx_xml(document))
    findings = [f for f in _scan(tmp_path) if f.detector_id == "us_ssn"]
    assert findings

    with pytest.raises(ValueError, match="safely flatten malformed Word field"):
        anonymize_files(findings)

    assert not original.with_name("malformed-field-auto-redacted-copy.docx").exists()


def test_docx_untouched_zip_members_are_preserved_verbatim(tmp_path):
    original = tmp_path / "notes.docx"
    original.write_bytes(
        make_docx_runs([[f"ssn {SSN}"]], extra_members={"docProps/app.xml": "<Properties/>"})
    )
    findings = [f for f in _scan(tmp_path) if f.detector_id == "us_ssn"]

    outputs = anonymize_files(findings)

    with zipfile.ZipFile(Path(outputs[str(original)])) as zf:
        assert set(zf.namelist()) == {"word/document.xml", "docProps/app.xml"}
        assert zf.read("docProps/app.xml") == b"<Properties/>"


def test_xlsx_cell_is_redacted_without_touching_shared_string_siblings(tmp_path):
    # B2 and C3 reference the SAME shared string. Anonymizing only B2 must
    # not rewrite C3 — the classic shared-strings corruption bug.
    row = '<c r="B2" t="s"><v>0</v></c><c r="C3" t="s"><v>0</v></c>'
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as zf:
        zf.writestr("xl/sharedStrings.xml", f"<sst {_S_NS}><si><t>{SSN}</t></si></sst>")
        zf.writestr(
            "xl/workbook.xml",
            f'<workbook {_S_NS}><sheets><sheet name="People" sheetId="1"/></sheets></workbook>',
        )
        zf.writestr(
            "xl/worksheets/sheet1.xml",
            f"<worksheet {_S_NS}><sheetData><row>{row}</row></sheetData></worksheet>",
        )
    original = tmp_path / "people.xlsx"
    original.write_bytes(buffer.getvalue())

    findings = [f for f in _scan(tmp_path) if f.detector_id == "us_ssn"]
    b2 = [f for f in findings if f.location == "People!B2"]
    assert b2, f"expected a finding located at People!B2, got {[f.location for f in findings]}"

    outputs = anonymize_files(b2)

    redacted = Path(outputs[str(original)])
    doc = extract_document(".xlsx", redacted.read_bytes())
    assert doc.location_at(doc.text.index(MASKED_SSN)) == "People!B2"
    assert doc.location_at(doc.text.index(SSN)) == "People!C3"  # sibling untouched


def test_xlsx_orphaned_shared_string_is_scrubbed_from_raw_xml(tmp_path):
    # Only ONE cell references the secret's shared string. After anonymizing
    # it, the raw sharedStrings.xml must not still carry the secret bytes —
    # "redacted" must hold up against someone unzipping the file.
    original = tmp_path / "single.xlsx"
    original.write_bytes(make_xlsx({"B2": SSN}, sheet_name="People"))
    findings = [f for f in _scan(tmp_path) if f.detector_id == "us_ssn"]
    assert findings

    outputs = anonymize_files(findings)

    with zipfile.ZipFile(Path(outputs[str(original)])) as zf:
        shared_xml = zf.read("xl/sharedStrings.xml").decode()
        sheet_xml = zf.read("xl/worksheets/sheet1.xml").decode()
    assert SSN not in shared_xml
    assert SSN not in sheet_xml
    assert MASKED_SSN in sheet_xml


def test_xlsx_shared_string_still_referenced_elsewhere_is_kept(tmp_path):
    # Sibling reference intact ⇒ the shared entry must NOT be scrubbed,
    # or the untouched C3 cell would silently lose its value.
    row = '<c r="B2" t="s"><v>0</v></c><c r="C3" t="s"><v>0</v></c>'
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as zf:
        zf.writestr("xl/sharedStrings.xml", f"<sst {_S_NS}><si><t>{SSN}</t></si></sst>")
        zf.writestr(
            "xl/workbook.xml",
            f'<workbook {_S_NS}><sheets><sheet name="People" sheetId="1"/></sheets></workbook>',
        )
        zf.writestr(
            "xl/worksheets/sheet1.xml",
            f"<worksheet {_S_NS}><sheetData><row>{row}</row></sheetData></worksheet>",
        )
    original = tmp_path / "pair.xlsx"
    original.write_bytes(buffer.getvalue())
    b2 = [f for f in _scan(tmp_path) if f.location == "People!B2"]

    outputs = anonymize_files(b2)

    with zipfile.ZipFile(Path(outputs[str(original)])) as zf:
        assert SSN in zf.read("xl/sharedStrings.xml").decode()  # C3 still needs it


def test_xlsx_numeric_cell_is_redacted(tmp_path):
    card = "4111111111111111"
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as zf:
        zf.writestr(
            "xl/workbook.xml",
            f'<workbook {_S_NS}><sheets><sheet name="Cards" sheetId="1"/></sheets></workbook>',
        )
        zf.writestr(
            "xl/worksheets/sheet1.xml",
            f'<worksheet {_S_NS}><sheetData><row><c r="A1"><v>{card}</v></c></row></sheetData>'
            "</worksheet>",
        )
    original = tmp_path / "cards.xlsx"
    original.write_bytes(buffer.getvalue())
    findings = [f for f in _scan(tmp_path) if f.detector_id == "credit_card"]
    assert findings

    outputs = anonymize_files(findings)

    text = _extracted_text(Path(outputs[str(original)]))
    assert card not in text
    assert "************1111" in text


def test_docx_header_finding_is_anonymized(tmp_path):
    original = tmp_path / "letter.docx"
    original.write_bytes(make_docx_parts(body=["dear reader"], headers=[f"ref ssn {SSN}"]))
    findings = [f for f in _scan(tmp_path) if f.detector_id == "us_ssn"]
    assert findings and findings[0].location == "header 1"
    assert findings[0].can_anonymize is True

    outputs = anonymize_files(findings)

    redacted = Path(outputs[str(original)])
    text = _extracted_text(redacted)
    assert SSN not in text
    assert f"ref ssn {MASKED_SSN}" in text
    assert "dear reader" in text
    with zipfile.ZipFile(redacted) as zf:
        assert SSN not in zf.read("word/header1.xml").decode()


def test_docx_text_box_finding_is_anonymized(tmp_path):
    document = (
        f"<w:document {_W_NS}><w:body>"
        "<w:p><w:r><w:t>outer text</w:t></w:r>"
        f"<w:txbxContent><w:p><w:r><w:t>boxed {SSN}</w:t></w:r></w:p></w:txbxContent>"
        "</w:p></w:body></w:document>"
    )
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as zf:
        zf.writestr("word/document.xml", document)
    original = tmp_path / "boxed.docx"
    original.write_bytes(buffer.getvalue())
    findings = [f for f in _scan(tmp_path) if f.detector_id == "us_ssn"]
    assert findings and findings[0].location == "paragraph 1 (text box)"

    outputs = anonymize_files(findings)

    text = _extracted_text(Path(outputs[str(original)]))
    assert SSN not in text
    assert f"boxed {MASKED_SSN}" in text
    assert "outer text" in text


def test_pptx_slide_and_notes_findings_are_anonymized(tmp_path):
    original = tmp_path / "deck.pptx"
    original.write_bytes(make_pptx([f"slide ssn {SSN}"], notes=["note ssn 987-65-4321"]))
    findings = [f for f in _scan(tmp_path) if f.detector_id == "us_ssn"]
    locations = {f.location for f in findings}
    assert locations == {"slide 1", "slide 1 notes"}
    assert all(f.can_anonymize for f in findings)

    outputs = anonymize_files(findings)

    redacted = Path(outputs[str(original)])
    assert redacted.name == "deck-auto-redacted-copy.pptx"
    text = _extracted_text(redacted)
    assert SSN not in text and "987-65-4321" not in text
    assert f"slide ssn {MASKED_SSN}" in text
    assert "note ssn *******4321" in text
    assert SSN in _extracted_text(original)  # original untouched


def test_pptx_can_ignore_an_identical_value_in_another_paragraph(tmp_path):
    """Paragraphs on one slide share a location label, but remain distinct choices."""
    slide = (
        f"<p:sld {_P_NS} {_A_NS}>"
        f"<a:p><a:r><a:t>selected ssn {SSN}</a:t></a:r></a:p>"
        f"<a:p><a:r><a:t>ignored ssn {SSN}</a:t></a:r></a:p>"
        "</p:sld>"
    )
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as zf:
        zf.writestr("ppt/slides/slide1.xml", slide)
    original = tmp_path / "duplicate.pptx"
    original.write_bytes(buffer.getvalue())
    findings = [f for f in _scan(tmp_path) if f.detector_id == "us_ssn"]

    assert len(findings) == 2
    assert {finding.location for finding in findings} == {"slide 1"}
    selected = min(findings, key=lambda finding: finding.start_offset)

    outputs = anonymize_files([selected])

    assert _extracted_text(Path(outputs[str(original)])) == (
        f"selected ssn {MASKED_SSN}\nignored ssn {SSN}"
    )


def test_xlsx_write_back_respects_relationship_sheet_order(tmp_path):
    # Alpha maps to sheet2.xml via rels. Write-back must edit the SAME file
    # extraction labeled, or the mask would land in the wrong sheet.
    rels = (
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" Target="worksheets/sheet2.xml"/>'
        '<Relationship Id="rId2" Target="worksheets/sheet1.xml"/>'
        "</Relationships>"
    )
    r_ns = 'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"'
    workbook = (
        f"<workbook {_S_NS} {r_ns}><sheets>"
        '<sheet name="Alpha" sheetId="1" r:id="rId1"/>'
        '<sheet name="Beta" sheetId="2" r:id="rId2"/>'
        "</sheets></workbook>"
    )

    def sheet_xml(value: str) -> str:
        return (
            f'<worksheet {_S_NS}><sheetData><row><c r="A1" t="inlineStr"><is><t>{value}</t></is>'
            "</c></row></sheetData></worksheet>"
        )

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as zf:
        zf.writestr("xl/_rels/workbook.xml.rels", rels)
        zf.writestr("xl/workbook.xml", workbook)
        zf.writestr("xl/worksheets/sheet1.xml", sheet_xml("beta keeps 111-22-3333"))
        zf.writestr("xl/worksheets/sheet2.xml", sheet_xml(f"alpha ssn {SSN}"))
    original = tmp_path / "books.xlsx"
    original.write_bytes(buffer.getvalue())

    alpha = [f for f in _scan(tmp_path) if f.location == "Alpha!A1"]
    assert alpha and alpha[0].matched_text == SSN

    outputs = anonymize_files(alpha)

    with zipfile.ZipFile(Path(outputs[str(original)])) as zf:
        assert MASKED_SSN in zf.read("xl/worksheets/sheet2.xml").decode()
        assert SSN not in zf.read("xl/worksheets/sheet2.xml").decode()
        assert "111-22-3333" in zf.read("xl/worksheets/sheet1.xml").decode()  # untouched


def test_document_changed_since_scan_is_refused(tmp_path):
    original = tmp_path / "notes.docx"
    original.write_bytes(make_docx([f"ssn {SSN}"]))
    findings = [f for f in _scan(tmp_path) if f.detector_id == "us_ssn"]

    original.write_bytes(make_docx(["completely different content now"]))

    with pytest.raises(ValueError, match="changed since it was scanned"):
        anonymize_files(findings)
    assert not original.with_name("notes-auto-redacted-copy.docx").exists()


def test_in_place_overwrites_the_original_document(tmp_path):
    original = tmp_path / "notes.docx"
    original.write_bytes(make_docx([f"ssn {SSN}"]))
    findings = [f for f in _scan(tmp_path) if f.detector_id == "us_ssn"]

    outputs = anonymize_files(findings, in_place=True)

    assert outputs[str(original)] == str(original)
    assert SSN not in _extracted_text(original)


def test_plain_text_file_with_docx_extension_uses_the_text_path(tmp_path):
    # Mislabeled file: .docx extension but plain text content. It scans via
    # the text path (real file offsets), so anonymization must too.
    fake = tmp_path / "fake.docx"
    fake.write_text(f'ssn = "{SSN}"\n')
    findings = [f for f in _scan(tmp_path) if f.detector_id == "us_ssn"]
    assert findings and findings[0].location is None

    outputs = anonymize_files(findings)

    redacted = Path(outputs[str(fake)])
    assert redacted.name == "fake-auto-redacted-copy.docx"
    assert SSN not in redacted.read_text()
    assert MASKED_SSN in redacted.read_text()
