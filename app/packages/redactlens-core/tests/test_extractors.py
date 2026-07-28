"""Extractor tests build tiny real documents in memory — no binary fixtures
checked into the repo, and the OOXML each helper writes is the minimal
subset our extractors actually parse."""

import io
import warnings
import zipfile

import pytest
from redactlens_core import extractors
from redactlens_core.extractors import (
    DocumentLimitExceeded,
    ExtractedTextLimitExceeded,
    ExtractionError,
    NoExtractableTextError,
    extract_document,
)
from redactlens_core.files import read_scannable, read_scannable_detailed

_W_NS = 'xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"'
_S_NS = 'xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"'
_A_NS = 'xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"'


def make_docx(paragraphs: list[str]) -> bytes:
    body = "".join(f"<w:p><w:r><w:t>{p}</w:t></w:r></w:p>" for p in paragraphs)
    document = f"<w:document {_W_NS}><w:body>{body}</w:body></w:document>"
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as zf:
        zf.writestr("word/document.xml", document)
    return buffer.getvalue()


def make_xlsx(cells: dict[str, str], sheet_name: str = "Payroll") -> bytes:
    values = list(cells.values())
    shared = "".join(f"<si><t>{v}</t></si>" for v in values)
    row = "".join(f'<c r="{ref}" t="s"><v>{i}</v></c>' for i, ref in enumerate(cells))
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as zf:
        zf.writestr("xl/sharedStrings.xml", f"<sst {_S_NS}>{shared}</sst>")
        zf.writestr(
            "xl/workbook.xml",
            f'<workbook {_S_NS}><sheets><sheet name="{sheet_name}" sheetId="1"/></sheets>'
            "</workbook>",
        )
        zf.writestr(
            "xl/worksheets/sheet1.xml",
            f"<worksheet {_S_NS}><sheetData><row>{row}</row></sheetData></worksheet>",
        )
    return buffer.getvalue()


_P_NS = 'xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main"'


def _slide_xml(text: str) -> str:
    return f"<p:sld {_P_NS} {_A_NS}><a:p><a:r><a:t>{text}</a:t></a:r></a:p></p:sld>"


def make_pptx(slides: list[str], notes: list[str] | None = None) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as zf:
        for number, text in enumerate(slides, start=1):
            zf.writestr(f"ppt/slides/slide{number}.xml", _slide_xml(text))
        for number, text in enumerate(notes or [], start=1):
            zf.writestr(f"ppt/notesSlides/notesSlide{number}.xml", _slide_xml(text))
    return buffer.getvalue()


def _w_para(text: str) -> str:
    return f"<w:p><w:r><w:t>{text}</w:t></w:r></w:p>"


def make_docx_parts(
    body: list[str],
    headers: list[str] | None = None,
    footers: list[str] | None = None,
    footnotes: dict[str, str] | None = None,
    comments: dict[str, str] | None = None,
) -> bytes:
    """A docx with the auxiliary parts Phase C extraction covers.
    footnotes/comments map id -> text (ids mirror Word's w:id attributes)."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as zf:
        paragraphs = "".join(_w_para(p) for p in body)
        zf.writestr(
            "word/document.xml",
            f"<w:document {_W_NS}><w:body>{paragraphs}</w:body></w:document>",
        )
        for number, text in enumerate(headers or [], start=1):
            zf.writestr(f"word/header{number}.xml", f"<w:hdr {_W_NS}>{_w_para(text)}</w:hdr>")
        for number, text in enumerate(footers or [], start=1):
            zf.writestr(f"word/footer{number}.xml", f"<w:ftr {_W_NS}>{_w_para(text)}</w:ftr>")
        if footnotes:
            notes = "".join(
                f'<w:footnote w:id="{i}">{_w_para(t)}</w:footnote>' for i, t in footnotes.items()
            )
            zf.writestr("word/footnotes.xml", f"<w:footnotes {_W_NS}>{notes}</w:footnotes>")
        if comments:
            entries = "".join(
                f'<w:comment w:id="{i}">{_w_para(t)}</w:comment>' for i, t in comments.items()
            )
            zf.writestr("word/comments.xml", f"<w:comments {_W_NS}>{entries}</w:comments>")
    return buffer.getvalue()


def make_pdf(text: str) -> bytes:
    """A minimal one-page digital PDF with a correct xref table."""
    content = f"BT /F1 12 Tf 72 720 Td ({text}) Tj ET".encode()
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R "
        b"/Resources << /Font << /F1 5 0 R >> >> >>",
        b"<< /Length %d >>\nstream\n%s\nendstream" % (len(content), content),
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ]
    out = io.BytesIO()
    out.write(b"%PDF-1.4\n")
    offsets = []
    for number, obj in enumerate(objects, start=1):
        offsets.append(out.tell())
        out.write(b"%d 0 obj\n%s\nendobj\n" % (number, obj))
    xref_at = out.tell()
    out.write(b"xref\n0 %d\n0000000000 65535 f \n" % (len(objects) + 1))
    for offset in offsets:
        out.write(b"%010d 00000 n \n" % offset)
    out.write(
        b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n"
        % (len(objects) + 1, xref_at)
    )
    return out.getvalue()


def test_docx_extracts_paragraphs_with_locations():
    raw = make_docx(["Meeting notes", "ssn is 123-45-6789", "wrap-up"])

    doc = extract_document(".docx", raw)

    assert doc is not None and doc.format == "docx"
    assert "123-45-6789" in doc.text
    assert doc.location_at(doc.text.index("123-45-6789")) == "paragraph 2"


def test_xlsx_extracts_cells_with_sheet_and_cell_locations():
    raw = make_xlsx({"A1": "employee", "B2": "123-45-6789"})

    doc = extract_document(".xlsx", raw)

    assert "123-45-6789" in doc.text
    assert doc.location_at(doc.text.index("123-45-6789")) == "Payroll!B2"


def test_pptx_extracts_slides_with_locations():
    raw = make_pptx(["title slide", "the ssn 123-45-6789 slide"])

    doc = extract_document(".pptx", raw)

    assert "123-45-6789" in doc.text
    assert doc.location_at(doc.text.index("123-45-6789")) == "slide 2"


def test_pdf_extracts_pages_with_locations():
    raw = make_pdf("ssn 123-45-6789")

    doc = extract_document(".pdf", raw)

    assert "123-45-6789" in doc.text
    assert doc.location_at(doc.text.index("123-45-6789")) == "page 1"


def test_image_only_pdf_requires_ocr_instead_of_appearing_scanned(tmp_path):
    raw = make_pdf("")

    with pytest.raises(NoExtractableTextError, match="OCR is required"):
        extract_document(".pdf", raw)

    path = tmp_path / "image-only.pdf"
    path.write_bytes(raw)
    scannable, issue = read_scannable_detailed(str(path))

    assert scannable is None
    assert issue is not None
    assert issue.code == "no_extractable_text"
    assert issue.stage == "extraction"
    assert "OCR is required" in issue.reason


def test_extracted_text_limit_is_enforced_while_segments_are_added(tmp_path):
    raw = make_docx(["first", "second segment exceeds the cap"])

    with pytest.raises(ExtractedTextLimitExceeded, match="limit of 10 characters"):
        extract_document(".docx", raw, max_extracted_chars=10)

    path = tmp_path / "oversized.docx"
    path.write_bytes(raw)
    scannable, issue = read_scannable_detailed(str(path), max_extracted_chars=10)

    assert scannable is None
    assert issue is not None
    assert issue.code == "extracted_text_too_large"
    assert issue.stage == "extraction"


def test_pdf_visitor_aborts_before_retaining_text_over_the_limit(monkeypatch):
    import pypdf

    class OversizedPage:
        def extract_text(self, *, visitor_text):
            visitor_text("x" * 11, None, None, None, None)
            raise AssertionError("the extraction limit should stop the page visitor")

    class FakeReader:
        is_encrypted = False
        pages = [OversizedPage()]

        def __init__(self, _stream):
            pass

    monkeypatch.setattr(pypdf, "PdfReader", FakeReader)

    with pytest.raises(ExtractedTextLimitExceeded, match="limit of 10 characters"):
        extract_document(".pdf", b"%PDF fake", max_extracted_chars=10)


def test_pdf_page_limit_stops_before_extracting_the_next_page(monkeypatch, tmp_path):
    import pypdf

    extracted_pages: list[int] = []

    class Page:
        def __init__(self, number: int) -> None:
            self.number = number

        def extract_text(self, *, visitor_text):
            extracted_pages.append(self.number)
            visitor_text("text", None, None, None, None)
            return "text"

    class FakeReader:
        is_encrypted = False
        pages = [Page(1), Page(2), Page(3)]

        def __init__(self, _stream):
            pass

    monkeypatch.setattr(extractors, "MAX_PDF_PAGES", 2)
    monkeypatch.setattr(pypdf, "PdfReader", FakeReader)

    with pytest.raises(DocumentLimitExceeded, match="maximum page limit of 2"):
        extract_document(".pdf", b"%PDF fake")
    assert extracted_pages == [1, 2]

    path = tmp_path / "too-many-pages.pdf"
    path.write_bytes(b"%PDF fake")
    scannable, issue = read_scannable_detailed(str(path))

    assert scannable is None
    assert issue is not None
    assert issue.code == "document_limit"
    assert issue.stage == "extraction"


def test_pdf_extraction_timeout_is_checked_between_pages(monkeypatch, tmp_path):
    import pypdf

    extracted_pages: list[int] = []

    class Page:
        def extract_text(self, *, visitor_text):
            extracted_pages.append(1)
            visitor_text("text", None, None, None, None)
            return "text"

    class FakeReader:
        is_encrypted = False
        pages = [Page()]

        def __init__(self, _stream):
            pass

    monkeypatch.setattr(pypdf, "PdfReader", FakeReader)
    checks = 0

    def timed_out() -> bool:
        nonlocal checks
        checks += 1
        return checks >= 4

    path = tmp_path / "slow.pdf"
    path.write_bytes(b"%PDF fake")
    scannable, issue = read_scannable_detailed(str(path), extraction_timed_out=timed_out)

    assert extracted_pages == [1]
    assert scannable is None
    assert issue is not None
    assert issue.code == "extraction_timeout"
    assert issue.stage == "extraction"


def test_structured_extraction_propagates_checkpoint_exception_unchanged(tmp_path):
    class StopNow(Exception):
        pass

    path = tmp_path / "controlled.docx"
    path.write_bytes(make_docx(["one", "two"]))
    signal = StopNow("cancel")
    checks = 0

    def checkpoint() -> None:
        nonlocal checks
        checks += 1
        if checks == 3:
            raise signal

    with pytest.raises(StopNow) as caught:
        read_scannable_detailed(str(path), checkpoint=checkpoint)

    assert caught.value is signal


def test_docx_extracts_headers_footers_footnotes_and_comments():
    raw = make_docx_parts(
        body=["body text"],
        headers=["header ssn 123-45-6789"],
        footers=["footer card 4111 1111 1111 1111"],
        footnotes={"2": "footnote secret 987-65-4321"},
        comments={"1": "comment: check this ssn 111-22-3333"},
    )

    doc = extract_document(".docx", raw)

    assert doc.location_at(doc.text.index("123-45-6789")) == "header 1"
    assert doc.location_at(doc.text.index("4111 1111")) == "footer 1"
    assert doc.location_at(doc.text.index("987-65-4321")) == "footnote 2"
    assert doc.location_at(doc.text.index("111-22-3333")) == "comment 1"
    assert doc.location_at(doc.text.index("body text")) == "paragraph 1"


def test_docx_text_boxes_are_extracted_once_with_their_own_label():
    # A text box nests a whole paragraph inside another paragraph. Its text
    # must appear exactly once (not through both paragraphs) and carry a
    # "(text box)" label.
    document = (
        f"<w:document {_W_NS}><w:body>"
        "<w:p><w:r><w:t>outer text</w:t></w:r>"
        "<w:txbxContent><w:p><w:r><w:t>boxed 123-45-6789</w:t></w:r></w:p></w:txbxContent>"
        "</w:p></w:body></w:document>"
    )
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as zf:
        zf.writestr("word/document.xml", document)

    doc = extract_document(".docx", buffer.getvalue())

    assert doc.text.count("boxed 123-45-6789") == 1
    assert doc.text.count("outer text") == 1
    assert doc.location_at(doc.text.index("boxed")) == "paragraph 1 (text box)"
    assert doc.location_at(doc.text.index("outer")) == "paragraph 1"


def test_pptx_extracts_speaker_notes_with_locations():
    raw = make_pptx(["visible slide text"], notes=["note to self: ssn 123-45-6789"])

    doc = extract_document(".pptx", raw)

    assert doc.location_at(doc.text.index("123-45-6789")) == "slide 1 notes"
    assert doc.location_at(doc.text.index("visible")) == "slide 1"


def test_xlsx_sheet_names_resolve_through_workbook_relationships():
    # Workbook order says Alpha then Beta, but the relationships point Alpha
    # at sheet2.xml — filename order alone would mislabel every cell.
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
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as zf:
        zf.writestr("xl/_rels/workbook.xml.rels", rels)
        zf.writestr("xl/workbook.xml", workbook)
        zf.writestr(
            "xl/worksheets/sheet1.xml",
            f'<worksheet {_S_NS}><sheetData><row><c r="A1" t="inlineStr"><is><t>in beta</t></is>'
            "</c></row></sheetData></worksheet>",
        )
        zf.writestr(
            "xl/worksheets/sheet2.xml",
            f'<worksheet {_S_NS}><sheetData><row><c r="A1" t="inlineStr"><is><t>in alpha</t></is>'
            "</c></row></sheetData></worksheet>",
        )

    doc = extract_document(".xlsx", buffer.getvalue())

    assert doc.location_at(doc.text.index("in alpha")) == "Alpha!A1"
    assert doc.location_at(doc.text.index("in beta")) == "Beta!A1"


def make_eml(body: str, cte: str = "base64", attachment: tuple[str, str] | None = None) -> bytes:
    from email.message import EmailMessage

    message = EmailMessage()
    message["From"] = "alice.smith@example.com"
    message["To"] = "bob@example.com"
    message["Subject"] = "quarterly numbers"
    message.set_content(body, cte=cte)
    if attachment is not None:
        name, content = attachment
        message.add_attachment(content, filename=name)
    return bytes(message)


def test_eml_decodes_base64_body_that_raw_text_scanning_cannot_see():
    raw = make_eml("my ssn is 123-45-6789", cte="base64")
    assert b"123-45-6789" not in raw  # invisible to a plain-text scan

    doc = extract_document(".eml", raw)

    assert doc.format == "eml"
    assert doc.location_at(doc.text.index("123-45-6789")) == "body (text/plain)"


def test_eml_extracts_headers_and_text_attachments():
    raw = make_eml("hello", cte="quoted-printable", attachment=("keys.txt", "token 123-45-6789"))

    doc = extract_document(".eml", raw)

    assert doc.location_at(doc.text.index("alice.smith@example.com")) == "headers"
    assert doc.location_at(doc.text.index("123-45-6789")) == "attachment 'keys.txt'"


def test_eml_findings_are_read_only(tmp_path):
    from redactlens_core.models import ScanRequest
    from redactlens_core.registry import load_default_registry
    from redactlens_core.scanner import scan

    (tmp_path / "mail.eml").write_bytes(make_eml("ssn 123-45-6789"))

    result = scan(ScanRequest(paths=[str(tmp_path)]), load_default_registry())

    matches = [f for f in result.findings if f.detector_id == "us_ssn"]
    assert matches
    assert matches[0].can_anonymize is False  # MIME write-back is unsupported


def test_msg_files_get_an_email_specific_skip_reason(tmp_path):
    outlook = tmp_path / "mail.msg"
    outlook.write_bytes(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 64)

    _, reason = read_scannable(str(outlook))

    assert "save the email as .eml" in reason


def _zip_bytes(
    members: dict[str, bytes],
    compression: int = zipfile.ZIP_STORED,
) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=compression) as zf:
        for name, content in members.items():
            zf.writestr(name, content)
    return buffer.getvalue()


def test_zip_scans_text_members_including_utf16_and_documents():
    raw = _zip_bytes(
        {
            "notes.txt": "ssn 123-45-6789".encode("utf-16"),
            "docs/report.docx": make_docx(["card 4111 1111 1111 1111"]),
            "logo.png": b"\x89PNG\r\n\x1a\n\x00\x00",  # not scannable: skipped
        }
    )

    doc = extract_document(".zip", raw)

    assert doc.format == "zip"
    assert doc.location_at(doc.text.index("123-45-6789")) == "notes.txt"
    assert doc.location_at(doc.text.index("4111 1111")) == "docs/report.docx · paragraph 1"


def test_zip_reads_nested_archives_to_depth_two():
    inner = _zip_bytes({"secret.txt": b"ssn 123-45-6789"})
    raw = _zip_bytes({"inner.zip": inner})

    doc = extract_document(".zip", raw)

    assert doc.location_at(doc.text.index("123-45-6789")) == "inner.zip · secret.txt"


def test_zip_rejects_nesting_beyond_the_configured_depth():
    third_level = _zip_bytes({"too-deep.txt": b"ssn 987-65-4321"})
    second_level = _zip_bytes({"deep.zip": third_level})
    raw = _zip_bytes({"nested.zip": second_level})

    with pytest.raises(ExtractionError, match="nesting exceeds the maximum depth"):
        extract_document(".zip", raw)


def test_zip_rejects_more_entries_than_the_member_count_cap(monkeypatch):
    monkeypatch.setattr(extractors, "MAX_ZIP_MEMBERS", 2)
    raw = _zip_bytes(
        {
            "first.txt": b"first",
            "second.txt": b"second",
            "third.txt": b"third",
        }
    )

    with pytest.raises(ExtractionError, match="too many entries"):
        extract_document(".zip", raw)


def test_zip_rejects_member_over_the_decompressed_size_cap(monkeypatch):
    monkeypatch.setattr(extractors, "MAX_ARCHIVE_MEMBER_BYTES", 10)
    raw = _zip_bytes({"large.txt": b"x" * 11})

    with pytest.raises(ExtractionError, match="per-member decompression limit"):
        extract_document(".zip", raw)


def test_zip_rejects_extreme_compression_ratio(monkeypatch):
    monkeypatch.setattr(extractors, "MAX_ARCHIVE_COMPRESSION_RATIO", 2.0)
    raw = _zip_bytes({"compressed.txt": b"x" * 2_000}, compression=zipfile.ZIP_DEFLATED)

    with pytest.raises(ExtractionError, match="compression-ratio limit"):
        extract_document(".zip", raw)


def test_nested_archives_share_one_total_decompression_budget(monkeypatch):
    monkeypatch.setattr(extractors, "MAX_DECOMPRESSED_BYTES", 500)
    inner_a = _zip_bytes({"a.txt": b"a" * 300}, compression=zipfile.ZIP_DEFLATED)
    inner_b = _zip_bytes({"b.txt": b"b" * 300}, compression=zipfile.ZIP_DEFLATED)
    raw = _zip_bytes(
        {"a.zip": inner_a, "b.zip": inner_b},
        compression=zipfile.ZIP_DEFLATED,
    )

    with pytest.raises(ExtractionError, match="total decompression limit"):
        extract_document(".zip", raw)


def test_zip_rejects_duplicate_member_paths():
    buffer = io.BytesIO()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr("duplicate.txt", b"first")
            archive.writestr("duplicate.txt", b"second")

    with pytest.raises(ExtractionError, match="duplicate member paths"):
        extract_document(".zip", buffer.getvalue())


@pytest.mark.parametrize(
    ("first_name", "second_name"),
    [
        ("Secret.txt", "secret.TXT"),
    ],
    ids=["case-folded-alias"],
)
def test_zip_rejects_distinct_names_that_resolve_to_the_same_member_path(
    first_name,
    second_name,
):
    raw = _zip_bytes({first_name: b"first", second_name: b"second"})

    with pytest.raises(ExtractionError, match="duplicate member paths"):
        extract_document(".zip", raw)


def test_zip_rejects_encrypted_members_before_reading(tmp_path):
    raw = bytearray(_zip_bytes({"secret.txt": b"ssn 123-45-6789"}))
    local = raw.find(b"PK\x03\x04")
    central = raw.find(b"PK\x01\x02")
    assert local >= 0 and central >= 0
    raw[local + 6 : local + 8] = (1).to_bytes(2, "little")
    raw[central + 8 : central + 10] = (1).to_bytes(2, "little")

    with pytest.raises(ExtractionError, match="encrypted archive member"):
        extract_document(".zip", bytes(raw))

    archive_path = tmp_path / "encrypted.zip"
    archive_path.write_bytes(raw)
    scannable, reason = read_scannable(str(archive_path))
    assert scannable is None
    assert reason == "encrypted archive member — decrypt the archive locally and rescan"


@pytest.mark.parametrize(
    "member_name",
    [
        "../outside.txt",
        "/absolute.txt",
        r"\absolute.txt",
        r"C:\outside.txt",
        "folder/../secret.txt",
        r"folder\..\secret.txt",
        r"folder\..\..\outside.txt",
    ],
    ids=[
        "parent-traversal",
        "posix-absolute",
        "backslash-absolute",
        "drive-qualified",
        "internal-parent-traversal",
        "internal-backslash-parent-traversal",
        "backslash-traversal",
    ],
)
def test_zip_rejects_unsafe_member_paths(member_name):
    raw = _zip_bytes({member_name: b"not extracted, but still rejected"})

    with pytest.raises(ExtractionError, match="unsafe member path"):
        extract_document(".zip", raw)


def test_zip_findings_are_read_only(tmp_path):
    from redactlens_core.models import ScanRequest
    from redactlens_core.registry import load_default_registry
    from redactlens_core.scanner import scan

    (tmp_path / "backup.zip").write_bytes(_zip_bytes({"creds.txt": b'password = "hunter2xyz!"'}))

    result = scan(ScanRequest(paths=[str(tmp_path)]), load_default_registry())

    matches = [f for f in result.findings if f.file_path.endswith("backup.zip")]
    assert matches
    assert matches[0].location == "creds.txt"
    assert matches[0].can_anonymize is False


def test_unknown_extension_returns_none():
    assert extract_document(".txt", b"plain text") is None


def test_wrong_magic_returns_none():
    # Right extension, wrong content: not treated as a document.
    assert extract_document(".docx", b"not actually a zip") is None


def test_corrupt_zip_raises_extraction_error():
    with pytest.raises(ExtractionError, match="corrupt document container"):
        extract_document(".docx", b"PK\x03\x04garbage-that-is-not-a-zip")


def test_zip_declaring_huge_decompressed_size_is_refused(monkeypatch):
    monkeypatch.setattr(extractors, "MAX_DECOMPRESSED_BYTES", 100)
    raw = make_docx(["x" * 500])

    with pytest.raises(ExtractionError, match="too large to scan safely"):
        extract_document(".docx", raw)


def test_read_scannable_extracts_docx(tmp_path):
    path = tmp_path / "notes.docx"
    path.write_bytes(make_docx(["ssn is 123-45-6789"]))

    scannable, reason = read_scannable(str(path))

    assert reason is None
    assert scannable.extracted
    assert "123-45-6789" in scannable.text
    assert scannable.location_at(scannable.text.index("123-45-6789")) == "paragraph 1"


def test_read_scannable_plain_text_is_not_extracted(tmp_path):
    path = tmp_path / "notes.txt"
    path.write_text("hello")

    scannable, reason = read_scannable(str(path))

    assert reason is None
    assert not scannable.extracted
    assert scannable.location_at(0) is None


def test_read_scannable_gives_actionable_reasons_for_recognized_binaries(tmp_path):
    legacy = tmp_path / "old.doc"
    legacy.write_bytes(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 64)
    image = tmp_path / "scan.png"
    image.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 64)

    _, legacy_reason = read_scannable(str(legacy))
    _, image_reason = read_scannable(str(image))

    assert "save it as .docx" in legacy_reason
    assert "OCR" in image_reason


def test_read_scannable_reports_broken_documents_as_skips(tmp_path):
    path = tmp_path / "broken.docx"
    path.write_bytes(b"PK\x03\x04this is not a real zip archive")

    scannable, reason = read_scannable(str(path))

    assert scannable is None
    assert "corrupt document container" in reason
