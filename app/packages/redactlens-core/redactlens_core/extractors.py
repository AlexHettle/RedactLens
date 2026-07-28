"""Text extraction from binary document formats (docx/xlsx/pptx/pdf).

Extraction feeds the normal detector pipeline. Offsets in the resulting
findings refer to the *extracted* text, not bytes on disk, so each finding
carries a human `location` label ("Sheet1!B7", "page 3", "header 1")
instead of a meaningful line number. Writing findings back is a separate
capability: document_anonymize handles docx/xlsx/pptx; pdf findings are
read-only (`can_anonymize=False`).

Coverage per format:
  - docx: body paragraphs, headers, footers, footnotes, endnotes, comments,
    and text boxes (paragraphs nested inside other paragraphs).
  - xlsx: every cell of every sheet; sheet names resolved through the
    workbook relationships (falling back to filename order).
  - pptx: slide paragraphs and speaker notes.
  - odt/ods/odp (OpenDocument): paragraphs incl. text boxes, odt
    headers/footers, ods cells, odp slides and presenter notes.
  - pdf: per-page text of digital PDFs (scanned pages come out empty; OCR
    is out of scope).

The iter_*_units walkers below are shared with document_anonymize: both
sides must traverse a document in the exact same order for write-back
offsets to be valid, so that order is defined once, here. The walkers work
with any ElementTree-compatible elements (defusedxml here, lxml there).

Safety over untrusted inputs, per the spec's never-crash rule:
  - XML is parsed with defusedxml (no entity-expansion bombs).
  - Zip containers are capped on member count and declared decompressed
    size before anything is read.
  - Every failure raises ExtractionError whose message is a user-facing
    skip reason; callers convert it to a SkippedFile, never a crash.
"""

import io
import posixpath
import re
import zipfile
from bisect import bisect_right
from collections.abc import Callable, Iterator
from contextvars import ContextVar
from dataclasses import dataclass, field
from typing import Any

from defusedxml.ElementTree import fromstring as _safe_fromstring

from redactlens_core.textcodec import decode_text

MAX_ZIP_MEMBERS = 10_000
MAX_DECOMPRESSED_BYTES = 50_000_000
MAX_ARCHIVE_MEMBER_BYTES = 10_000_000
MAX_ARCHIVE_COMPRESSION_RATIO = 200.0
MAX_ARCHIVE_DEPTH = 2
MAX_EXTRACTED_TEXT_CHARS = 50_000_000
MAX_PDF_PAGES = 10_000

_W = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"
_S = "{http://schemas.openxmlformats.org/spreadsheetml/2006/main}"
_A = "{http://schemas.openxmlformats.org/drawingml/2006/main}"
_PKG_REL = "{http://schemas.openxmlformats.org/package/2006/relationships}"
_DOC_REL = "{http://schemas.openxmlformats.org/officeDocument/2006/relationships}"


class ExtractionError(Exception):
    """Extraction failed. str(exc) is a user-facing skip reason."""


class ArchiveSafetyError(ExtractionError):
    """An archive exceeded a declared safety boundary."""


class ExtractedTextLimitExceeded(ExtractionError):
    """Document extraction exceeded its in-memory text boundary."""

    def __init__(self, limit: int) -> None:
        self.limit = limit
        super().__init__(f"extracted text exceeds the configured limit of {limit} characters")


class NoExtractableTextError(ExtractionError):
    """A recognized document contains no text the scanner can inspect."""


class DocumentLimitExceeded(ExtractionError):
    """A structured document exceeded a format-specific traversal boundary."""


class ExtractionTimedOut(Exception):
    """Cooperative structured extraction exceeded its per-file time budget."""

    def __init__(self) -> None:
        super().__init__("text extraction exceeded the configured time limit")


@dataclass
class _ArchiveBudget:
    consumed: int = 0

    def charge(self, size: int) -> None:
        self.consumed += size
        if self.consumed > MAX_DECOMPRESSED_BYTES:
            raise ArchiveSafetyError(
                "archive content exceeded the total decompression limit while scanning nested files"
            )


_ARCHIVE_BUDGET: ContextVar[_ArchiveBudget | None] = ContextVar(
    "redactlens_archive_budget",
    default=None,
)
_ARCHIVE_DEPTH_LIMIT: ContextVar[int] = ContextVar(
    "redactlens_archive_depth_limit",
    default=MAX_ARCHIVE_DEPTH,
)
_EXTRACTED_TEXT_LIMIT: ContextVar[int] = ContextVar(
    "redactlens_extracted_text_limit",
    default=MAX_EXTRACTED_TEXT_CHARS,
)
_EXTRACTION_CHECKPOINT: ContextVar[Callable[[], None] | None] = ContextVar(
    "redactlens_extraction_checkpoint",
    default=None,
)
_EXTRACTION_TIMED_OUT: ContextVar[Callable[[], bool] | None] = ContextVar(
    "redactlens_extraction_timed_out",
    default=None,
)


def _check_extraction_control() -> None:
    """Observe job control only at boundaries outside third-party catch scopes."""
    checkpoint = _EXTRACTION_CHECKPOINT.get()
    if checkpoint is not None:
        checkpoint()
    extraction_timed_out = _EXTRACTION_TIMED_OUT.get()
    if extraction_timed_out is not None and extraction_timed_out():
        raise ExtractionTimedOut


@dataclass
class ExtractedDoc:
    """Extracted text plus a map from text offsets to human locations."""

    format: str  # "docx" | "xlsx" | "pptx" | "pdf"
    text: str
    # (start offset into text, label) per segment, sorted by offset.
    segments: list[tuple[int, str]] = field(default_factory=list)

    def location_at(self, offset: int) -> str | None:
        """Human-readable location ("Sheet1!B7") for an offset into text."""
        if not self.segments:
            return None
        index = bisect_right(self.segments, (offset, "￿")) - 1
        return self.segments[max(index, 0)][1]

    def iter_segments(self) -> Iterator[tuple[str, str]]:
        """(label, segment_text) pairs — used to fold one extraction into
        another (archive members that are themselves documents)."""
        for index, (start, label) in enumerate(self.segments):
            if index + 1 < len(self.segments):
                end = self.segments[index + 1][0] - 1  # strip the joining newline
            else:
                end = len(self.text)
            yield label, self.text[start:end]


class _SegmentBuilder:
    """Accumulates labeled text chunks; chunks are joined with newlines."""

    def __init__(self) -> None:
        self._parts: list[str] = []
        self._segments: list[tuple[int, str]] = []
        self._length = 0
        self._limit = _EXTRACTED_TEXT_LIMIT.get()

    def check_next_segment_length(self, length: int) -> None:
        """Reject a segment before retaining text beyond the extraction cap."""
        if length < 0:
            raise ValueError("segment length cannot be negative")
        if self._length + length > self._limit:
            raise ExtractedTextLimitExceeded(self._limit)

    def add(self, label: str, text: str) -> None:
        _check_extraction_control()
        self.check_next_segment_length(len(text))
        if not text.strip():
            return
        self._segments.append((self._length, label))
        self._parts.append(text)
        self._length += len(text) + 1  # +1 for the joining newline

    def build(self, fmt: str) -> ExtractedDoc:
        _check_extraction_control()
        return ExtractedDoc(format=fmt, text="\n".join(self._parts), segments=self._segments)


def _parse_xml(data: bytes, member: str) -> Any:
    try:
        return _safe_fromstring(data)
    except Exception as e:  # ParseError or a defusedxml refusal
        raise ExtractionError(f"malformed XML in document part '{member}'") from e


def _open_zip(raw: bytes) -> zipfile.ZipFile:
    try:
        zf = zipfile.ZipFile(io.BytesIO(raw))
    except zipfile.BadZipFile as e:
        raise ExtractionError("corrupt document container") from e
    infos = zf.infolist()
    try:
        if len(infos) > MAX_ZIP_MEMBERS:
            raise ArchiveSafetyError("archive has too many entries to scan safely")
        if sum(info.file_size for info in infos) > MAX_DECOMPRESSED_BYTES:
            raise ArchiveSafetyError(
                "archive content is too large to scan safely once decompressed"
            )

        normalized_names: set[str] = set()
        for info in infos:
            name = info.filename.replace("\\", "/")
            # Validate the original component sequence before normalizing it.
            # Otherwise ``folder/../secret.txt`` is silently accepted as
            # ``secret.txt`` whenever no second member exposes the alias.
            has_parent_component = any(part == ".." for part in name.split("/"))
            normalized = posixpath.normpath(name)
            if (
                name.startswith("/")
                or has_parent_component
                or normalized in {"", ".", ".."}
                or normalized.startswith("../")
                or re.match(r"^[A-Za-z]:", normalized)
            ):
                raise ArchiveSafetyError("archive contains an unsafe member path")
            identity = normalized.casefold()
            if identity in normalized_names:
                raise ArchiveSafetyError("archive contains duplicate member paths")
            normalized_names.add(identity)

            if info.flag_bits & 0x1:
                raise ArchiveSafetyError(
                    "encrypted archive member — decrypt the archive locally and rescan"
                )
            if info.is_dir():
                continue
            if info.file_size > MAX_ARCHIVE_MEMBER_BYTES:
                raise ArchiveSafetyError(
                    "archive member exceeds the per-member decompression limit"
                )
            if info.file_size > 0:
                ratio = info.file_size / max(info.compress_size, 1)
                if ratio > MAX_ARCHIVE_COMPRESSION_RATIO:
                    raise ArchiveSafetyError(
                        "archive member exceeds the safe compression-ratio limit"
                    )
    except Exception:
        zf.close()
        raise
    return zf


def _read_member(zf: zipfile.ZipFile, member: str) -> bytes:
    try:
        info = zf.getinfo(member)
        budget = _ARCHIVE_BUDGET.get()
        if budget is not None:
            budget.charge(info.file_size)
        return zf.read(info)
    except ArchiveSafetyError:
        raise
    except (KeyError, zipfile.BadZipFile, RuntimeError, NotImplementedError) as error:
        raise ExtractionError(f"could not read document part '{member}'") from error


def unit_text(t_nodes: list[Any]) -> str:
    """The text one unit contributes: its text nodes concatenated."""
    return "".join(node.text or "" for node in t_nodes)


# ---- docx ------------------------------------------------------------------
#
# A "unit" is one paragraph's worth of <w:t> nodes. Text boxes nest whole
# paragraphs inside other paragraphs, so each paragraph only owns the text
# nodes whose NEAREST paragraph ancestor it is — otherwise text-box content
# would be extracted twice (once through the outer paragraph, once through
# its own).


def docx_part_names(names: set[str]) -> list[str]:
    """The docx parts we extract, in the fixed order shared with write-back."""
    ordered = []
    if "word/document.xml" in names:
        ordered.append("word/document.xml")
    for kind in ("header", "footer"):
        numbered = sorted(
            (int(m.group(1)), name)
            for name in names
            if (m := re.fullmatch(rf"word/{kind}(\d+)\.xml", name))
        )
        ordered.extend(name for _, name in numbered)
    for single in ("word/footnotes.xml", "word/endnotes.xml", "word/comments.xml"):
        if single in names:
            ordered.append(single)
    return ordered


def _parent_map(root: Any) -> dict[Any, Any]:
    return {child: parent for parent in root.iter() for child in parent}


def _nearest_paragraph(node: Any, parents: dict[Any, Any]) -> Any | None:
    current = parents.get(node)
    while current is not None:
        if current.tag == f"{_W}p":
            return current
        current = parents.get(current)
    return None


def _paragraph_units(scope: Any, parents: dict[Any, Any], label: str) -> Iterator[tuple[str, list]]:
    """(label, t_nodes) for every paragraph under ``scope``: top-level
    paragraphs first get their own text nodes, then any text-box paragraphs
    nested inside them, labeled with a "(text box)" suffix."""
    top_level = [p for p in scope.iter(f"{_W}p") if _nearest_paragraph(p, parents) is None]
    for paragraph in top_level:
        own = [t for t in paragraph.iter(f"{_W}t") if _nearest_paragraph(t, parents) is paragraph]
        yield label, own
        for nested in paragraph.iter(f"{_W}p"):
            if nested is paragraph:
                continue
            nested_own = [
                t for t in nested.iter(f"{_W}t") if _nearest_paragraph(t, parents) is nested
            ]
            yield f"{label} (text box)", nested_own


def iter_docx_units(parts: list[tuple[str, Any]]) -> Iterator[tuple[str, str, list]]:
    """(part_name, label, t_nodes) per unit across all docx parts, in the
    canonical order. ``parts`` is [(part_name, parsed_root)] as returned by
    docx_part_names — stdlib or lxml elements both work."""
    for part_name, root in parts:
        parents = _parent_map(root)
        if part_name == "word/document.xml":
            top_level = [p for p in root.iter(f"{_W}p") if _nearest_paragraph(p, parents) is None]
            for number, paragraph in enumerate(top_level, start=1):
                for label, nodes in _paragraph_units(paragraph, parents, f"paragraph {number}"):
                    yield part_name, label, nodes
            continue
        match = re.fullmatch(r"word/(header|footer)(\d+)\.xml", part_name)
        if match:
            label = f"{match.group(1)} {match.group(2)}"
            for unit_label, nodes in _paragraph_units(root, parents, label):
                yield part_name, unit_label, nodes
            continue
        kind = {"word/footnotes.xml": "footnote", "word/endnotes.xml": "endnote"}.get(part_name)
        if kind is not None:
            for index, note in enumerate(root.iter(f"{_W}{kind}"), start=1):
                ident = note.get(f"{_W}id") or str(index)
                for unit_label, nodes in _paragraph_units(note, parents, f"{kind} {ident}"):
                    yield part_name, unit_label, nodes
            continue
        if part_name == "word/comments.xml":
            for index, comment in enumerate(root.iter(f"{_W}comment"), start=1):
                ident = comment.get(f"{_W}id") or str(index)
                for unit_label, nodes in _paragraph_units(comment, parents, f"comment {ident}"):
                    yield part_name, unit_label, nodes


def extract_docx(raw: bytes) -> ExtractedDoc:
    """Word: one segment per paragraph across body, headers, footers,
    footnotes, endnotes, comments, and text boxes."""
    with _open_zip(raw) as zf:
        names = set(zf.namelist())
        if "word/document.xml" not in names:
            raise ExtractionError("no word/document.xml inside — not a Word document?")
        parts = [
            (name, _parse_xml(_read_member(zf, name), name)) for name in docx_part_names(names)
        ]
    builder = _SegmentBuilder()
    for _, label, nodes in iter_docx_units(parts):
        builder.add(label, unit_text(nodes))
    return builder.build("docx")


# ---- pptx ------------------------------------------------------------------
#
# A unit is one <a:p> paragraph (runs concatenated — a value split across
# runs still forms one detectable string). Speaker notes follow their slide.


def pptx_part_names(names: set[str]) -> list[tuple[str, str]]:
    """[(part_name, base_label)] for slides and speaker notes, interleaved
    so each slide's notes follow it. The fixed order shared with write-back."""
    slides = {
        int(m.group(1)): name
        for name in names
        if (m := re.fullmatch(r"ppt/slides/slide(\d+)\.xml", name))
    }
    notes = {
        int(m.group(1)): name
        for name in names
        if (m := re.fullmatch(r"ppt/notesSlides/notesSlide(\d+)\.xml", name))
    }
    ordered = []
    for number in sorted(slides | notes):
        if number in slides:
            ordered.append((slides[number], f"slide {number}"))
        if number in notes:
            ordered.append((notes[number], f"slide {number} notes"))
    return ordered


def iter_pptx_units(parts: list[tuple[str, str, Any]]) -> Iterator[tuple[str, str, list]]:
    """(part_name, label, t_nodes) per <a:p> paragraph. ``parts`` is
    [(part_name, base_label, parsed_root)]."""
    for part_name, base_label, root in parts:
        for paragraph in root.iter(f"{_A}p"):
            yield part_name, base_label, list(paragraph.iter(f"{_A}t"))


def extract_pptx(raw: bytes) -> ExtractedDoc:
    """PowerPoint: one segment per paragraph, slides then their notes."""
    with _open_zip(raw) as zf:
        parts = [
            (name, label, _parse_xml(_read_member(zf, name), name))
            for name, label in pptx_part_names(set(zf.namelist()))
        ]
        builder = _SegmentBuilder()
        for _, label, nodes in iter_pptx_units(parts):
            builder.add(label, unit_text(nodes))
    return builder.build("pptx")


# ---- xlsx ------------------------------------------------------------------


def xlsx_shared_strings(zf: zipfile.ZipFile, parse=None) -> tuple[list[str], Any]:
    """(values, parsed_root_or_None) for xl/sharedStrings.xml."""
    if "xl/sharedStrings.xml" not in zf.namelist():
        return [], None
    parse = parse or (lambda data, member: _parse_xml(data, member))
    root = parse(_read_member(zf, "xl/sharedStrings.xml"), "xl/sharedStrings.xml")
    values = ["".join(t.text or "" for t in si.iter(f"{_S}t")) for si in root.iter(f"{_S}si")]
    return values, root


def xlsx_sheet_parts(zf: zipfile.ZipFile, parse=None) -> list[tuple[str, str]]:
    """[(part_name, sheet_label)] in workbook order, resolved through the
    workbook relationships; sheets that can't be resolved fall back to
    filename order. The fixed order shared with write-back."""
    parse = parse or (lambda data, member: _parse_xml(data, member))
    names = set(zf.namelist())

    relationships: dict[str, str] = {}
    if "xl/_rels/workbook.xml.rels" in names:
        rels_root = parse(
            _read_member(zf, "xl/_rels/workbook.xml.rels"), "xl/_rels/workbook.xml.rels"
        )
        for rel in rels_root.iter(f"{_PKG_REL}Relationship"):
            if rel.get("Id") and rel.get("Target"):
                relationships[rel.get("Id")] = rel.get("Target")

    numbered = sorted(
        (int(m.group(1)), name)
        for name in names
        if (m := re.fullmatch(r"xl/worksheets/sheet(\d+)\.xml", name))
    )
    worksheet_parts = [name for _, name in numbered]

    resolved: list[tuple[str | None, str]] = []
    if "xl/workbook.xml" in names:
        workbook = parse(_read_member(zf, "xl/workbook.xml"), "xl/workbook.xml")
        for index, sheet in enumerate(workbook.iter(f"{_S}sheet"), start=1):
            label = sheet.get("name") or f"sheet {index}"
            target = relationships.get(sheet.get(f"{_DOC_REL}id") or "")
            part = None
            if target:
                candidate = target.lstrip("/")
                candidate = candidate if candidate.startswith("xl/") else f"xl/{candidate}"
                if candidate in names:
                    part = candidate
            resolved.append((part, label))

    # Pair any unresolved workbook entries with unclaimed worksheet files in
    # order, then append worksheet files no workbook entry claimed at all.
    claimed = {part for part, _ in resolved if part}
    unclaimed = [name for name in worksheet_parts if name not in claimed]
    result: list[tuple[str, str]] = []
    for part, label in resolved:
        if part is None and unclaimed:
            part = unclaimed.pop(0)
        if part is not None:
            result.append((part, label))
    for index, name in enumerate(unclaimed, start=1):
        result.append((name, f"sheet {index}"))
    return result


def xlsx_cell_value(cell: Any, shared: list[str]) -> str:
    cell_type = cell.get("t")
    if cell_type == "s":  # shared-string reference
        v = cell.find(f"{_S}v")
        if v is not None and v.text and v.text.strip().isdigit():
            index = int(v.text)
            if index < len(shared):
                return shared[index]
        return ""
    if cell_type == "inlineStr":
        inline = cell.find(f"{_S}is")
        return "".join(t.text or "" for t in inline.iter(f"{_S}t")) if inline is not None else ""
    v = cell.find(f"{_S}v")  # numbers, booleans, formula results
    return (v.text or "") if v is not None else ""


def extract_xlsx(raw: bytes) -> ExtractedDoc:
    """Excel: one segment per non-empty cell, labeled "SheetName!B7"."""
    with _open_zip(raw) as zf:
        shared, _ = xlsx_shared_strings(zf)
        builder = _SegmentBuilder()
        for part_name, label in xlsx_sheet_parts(zf):
            root = _parse_xml(_read_member(zf, part_name), part_name)
            for cell in root.iter(f"{_S}c"):
                builder.add(f"{label}!{cell.get('r', '?')}", xlsx_cell_value(cell, shared))
    return builder.build("xlsx")


# ---- OpenDocument (odt/ods/odp) ---------------------------------------------
#
# Unlike OOXML, ODF text is mixed content: it lives in the .text and .tail
# of arbitrary elements inside a paragraph, not in dedicated text nodes. A
# unit is one paragraph; its "pieces" are (element, "text"|"tail") pairs
# owned by that paragraph — ownership by nearest paragraph ancestor, so a
# paragraph nested in a frame (text box) contributes to its own unit, never
# twice. Whitespace elements (text:s, text:tab) are not expanded; a value
# split by one won't be detected — an accepted v1 limit.

_T = "{urn:oasis:names:tc:opendocument:xmlns:text:1.0}"
_TBL = "{urn:oasis:names:tc:opendocument:xmlns:table:1.0}"
_OFF = "{urn:oasis:names:tc:opendocument:xmlns:office:1.0}"
_DR = "{urn:oasis:names:tc:opendocument:xmlns:drawing:1.0}"
_PR = "{urn:oasis:names:tc:opendocument:xmlns:presentation:1.0}"
_ST = "{urn:oasis:names:tc:opendocument:xmlns:style:1.0}"

_ODF_P_TAGS = frozenset({f"{_T}p", f"{_T}h"})

ODF_FORMATS = frozenset({"odt", "ods", "odp"})


def odf_part_names(fmt: str, names: set[str]) -> list[str]:
    """The ODF parts we extract, in the fixed order shared with write-back.
    odt headers/footers live in styles.xml; everything else in content.xml."""
    parts = [name for name in ("content.xml",) if name in names]
    if fmt == "odt" and "styles.xml" in names:
        parts.append("styles.xml")
    return parts


def _nearest_odf_paragraph(node: Any, parents: dict[Any, Any]) -> Any | None:
    current = parents.get(node)
    while current is not None:
        if current.tag in _ODF_P_TAGS:
            return current
        current = parents.get(current)
    return None


def _subtree_pieces(element: Any) -> Iterator[tuple[Any, str]]:
    """(node, "text"|"tail") pairs of a subtree in document order. The
    root's own tail is excluded — it belongs to the parent's content."""
    yield element, "text"
    for child in element:
        yield from _subtree_pieces(child)
        yield child, "tail"


def piece_text(pieces: list[tuple[Any, str]]) -> str:
    """The text one ODF unit contributes: its pieces concatenated."""
    return "".join(getattr(node, attr) or "" for node, attr in pieces)


def _odf_paragraph_pieces(paragraph: Any, parents: dict[Any, Any]) -> list[tuple[Any, str]]:
    """The mixed-content pieces owned by exactly this paragraph."""

    def owner(node: Any, attr: str) -> Any | None:
        if attr == "text" and node.tag in _ODF_P_TAGS:
            return node
        return _nearest_odf_paragraph(node, parents)

    return [(n, a) for n, a in _subtree_pieces(paragraph) if owner(n, a) is paragraph]


def _odf_paragraphs(scope: Any) -> list[Any]:
    return [el for el in scope.iter() if el.tag in _ODF_P_TAGS]


def _col_letters(index: int) -> str:
    """1 -> A, 27 -> AA (spreadsheet column naming)."""
    letters = ""
    while index > 0:
        index, remainder = divmod(index - 1, 26)
        letters = chr(ord("A") + remainder) + letters
    return letters


def _ods_units(root: Any, parents: dict[Any, Any], part_name: str) -> Iterator:
    for table in root.iter(f"{_TBL}table"):
        sheet = table.get(f"{_TBL}name") or "sheet"
        row_index = 0
        for row in table.iter(f"{_TBL}table-row"):
            row_repeat = int(row.get(f"{_TBL}number-rows-repeated") or 1)
            row_index += 1
            column_index = 0
            for cell in row:
                if cell.tag not in (f"{_TBL}table-cell", f"{_TBL}covered-table-cell"):
                    continue
                column_repeat = int(cell.get(f"{_TBL}number-columns-repeated") or 1)
                column_index += 1
                label = f"{sheet}!{_col_letters(column_index)}{row_index}"
                for paragraph in _odf_paragraphs(cell):
                    yield part_name, label, _odf_paragraph_pieces(paragraph, parents), cell
                column_index += column_repeat - 1
            row_index += row_repeat - 1


def _odp_units(root: Any, parents: dict[Any, Any], part_name: str) -> Iterator:
    for number, page in enumerate(root.iter(f"{_DR}page"), start=1):
        notes_paragraphs = set()
        for notes in page.iter(f"{_PR}notes"):
            notes_paragraphs.update(_odf_paragraphs(notes))
        for paragraph in _odf_paragraphs(page):
            label = f"slide {number} notes" if paragraph in notes_paragraphs else f"slide {number}"
            yield part_name, label, _odf_paragraph_pieces(paragraph, parents), None


def iter_odf_units(fmt: str, parts: list[tuple[str, Any]]) -> Iterator:
    """(part_name, label, pieces, cell) per paragraph unit across the ODF
    parts, in the canonical order shared between extraction and write-back.
    ``cell`` is the owning spreadsheet cell (for office:value scrubbing on
    edit) or None."""
    for part_name, root in parts:
        parents = _parent_map(root)
        if part_name == "styles.xml":  # odt headers/footers
            for kind in ("header", "footer"):
                for number, container in enumerate(root.iter(f"{_ST}{kind}"), start=1):
                    for paragraph in _odf_paragraphs(container):
                        pieces = _odf_paragraph_pieces(paragraph, parents)
                        yield part_name, f"{kind} {number}", pieces, None
            continue
        if fmt == "ods":
            yield from _ods_units(root, parents, part_name)
        elif fmt == "odp":
            yield from _odp_units(root, parents, part_name)
        else:  # odt content.xml — every paragraph in document order
            for number, paragraph in enumerate(_odf_paragraphs(root), start=1):
                pieces = _odf_paragraph_pieces(paragraph, parents)
                yield part_name, f"paragraph {number}", pieces, None


def _extract_odf(fmt: str):
    def extract(raw: bytes) -> ExtractedDoc:
        with _open_zip(raw) as zf:
            names = set(zf.namelist())
            if "content.xml" not in names:
                raise ExtractionError("no content.xml inside — not an OpenDocument file?")
            parts = [
                (name, _parse_xml(_read_member(zf, name), name))
                for name in odf_part_names(fmt, names)
            ]
        builder = _SegmentBuilder()
        for _, label, pieces, _cell in iter_odf_units(fmt, parts):
            builder.add(label, piece_text(pieces))
        return builder.build(fmt)

    return extract


extract_odt = _extract_odf("odt")
extract_ods = _extract_odf("ods")
extract_odp = _extract_odf("odp")


# ---- eml -------------------------------------------------------------------


def extract_eml(raw: bytes) -> ExtractedDoc:
    """RFC-822/MIME email: sensitive headers plus every text part, decoded —
    base64/quoted-printable bodies become scannable instead of opaque.

    Read-only (never in REWRITABLE_FORMATS): re-serializing MIME rewrites
    transfer encodings and boundaries, which is too lossy to write back
    safely. Non-text attachments aren't decoded (v1)."""
    import email
    from email import policy

    try:
        message = email.message_from_bytes(raw, policy=policy.default)
    except Exception as e:  # the parser is lenient; only hard failures land here
        raise ExtractionError("could not parse email safely") from e

    builder = _SegmentBuilder()
    headers = "\n".join(
        f"{name}: {value}"
        for name in ("From", "To", "Cc", "Bcc", "Reply-To", "Subject")
        if (value := message.get(name))
    )
    builder.add("headers", headers)

    for part in message.walk():
        if part.is_multipart() or not part.get_content_type().startswith("text/"):
            continue
        try:
            content = part.get_content()
        except Exception:
            continue  # undecodable part: skip it, keep scanning the rest
        filename = part.get_filename()
        label = f"attachment '{filename}'" if filename else f"body ({part.get_content_type()})"
        builder.add(label, content)
    return builder.build("eml")


# ---- pdf -------------------------------------------------------------------


def extract_pdf(raw: bytes) -> ExtractedDoc:
    """Digital PDFs: at most ``MAX_PDF_PAGES``, one segment per page."""
    from pypdf import PdfReader  # deferred: pypdf import is not free

    try:
        reader = PdfReader(io.BytesIO(raw))
        if reader.is_encrypted:
            raise ExtractionError("password-protected PDF — remove the password and rescan")
    except ExtractionError:
        raise
    except Exception as e:  # pypdf raises a small zoo of exception types
        raise ExtractionError("could not read PDF safely") from e

    _check_extraction_control()
    try:
        pages = iter(reader.pages)
    except Exception as e:
        raise ExtractionError("could not read PDF safely") from e

    builder = _SegmentBuilder()
    number = 0
    while True:
        _check_extraction_control()
        try:
            page = next(pages)
        except StopIteration:
            break
        except Exception as e:
            raise ExtractionError("could not read PDF safely") from e

        number += 1
        if number > MAX_PDF_PAGES:
            raise DocumentLimitExceeded(
                f"PDF exceeds the maximum page limit of {MAX_PDF_PAGES} pages"
            )

        observed_chars = 0

        def enforce_page_budget(text: str, *_args: Any) -> None:
            nonlocal observed_chars
            observed_chars += len(text)
            builder.check_next_segment_length(observed_chars)

        try:
            page_text = page.extract_text(visitor_text=enforce_page_budget) or ""
        except ExtractionError:
            raise
        except Exception as e:
            raise ExtractionError("could not read PDF safely") from e

        _check_extraction_control()
        builder.add(f"page {number}", page_text)

    _check_extraction_control()
    document = builder.build("pdf")
    if not document.text.strip():
        raise NoExtractableTextError(
            "PDF contains no extractable text; OCR is required before scanning"
        )
    return document


# ---- zip archives ------------------------------------------------------------


def extract_zip(raw: bytes, _depth: int = 1) -> ExtractedDoc:
    """Zip archives: every text member decoded, document members (docx/pdf/
    odt/…) extracted with member-prefixed locations, nested zips to depth
    2. Members that are neither (images, executables, …) are silently not
    scanned — the archive counts as one scanned file. Read-only: findings
    inside archives can't be written back (v1)."""
    budget_token = None
    if _ARCHIVE_BUDGET.get() is None:
        budget_token = _ARCHIVE_BUDGET.set(_ArchiveBudget())
    try:
        with _open_zip(raw) as zf:
            builder = _SegmentBuilder()
            for info in zf.infolist():
                if info.is_dir():
                    continue
                name = info.filename
                member_raw = _read_member(zf, name)
                suffix = ("." + name.rsplit(".", 1)[-1].lower()) if "." in name else ""

                if suffix == ".zip":
                    depth_limit = _ARCHIVE_DEPTH_LIMIT.get()
                    if _depth >= depth_limit:
                        raise ArchiveSafetyError(
                            f"archive nesting exceeds the maximum depth of {depth_limit}"
                        )
                    try:
                        nested = extract_zip(member_raw, _depth + 1)
                    except (ArchiveSafetyError, DocumentLimitExceeded):
                        raise
                    except ExtractionError:
                        continue  # corrupt nested archive: skip, keep scanning
                    for label, segment_text in nested.iter_segments():
                        builder.add(f"{name} · {label}", segment_text)
                    continue

                if suffix in _EXTRACTORS and suffix != ".zip":
                    try:
                        doc = extract_document(suffix, member_raw)
                    except (ArchiveSafetyError, DocumentLimitExceeded):
                        raise
                    except ExtractionError:
                        continue  # corrupt member document: skip, keep scanning
                    if doc is not None:
                        for label, segment_text in doc.iter_segments():
                            builder.add(f"{name} · {label}", segment_text)
                        continue
                    # wrong magic for its extension: fall through to text decode

                decoded = decode_text(member_raw)
                if decoded is not None:
                    builder.add(name, decoded[0])
        return builder.build("zip")
    finally:
        if budget_token is not None:
            _ARCHIVE_BUDGET.reset(budget_token)


# ---- Dispatch ----------------------------------------------------------------

_ZIP_MAGIC = b"PK\x03\x04"
_PDF_MAGIC = b"%PDF"

# extension -> (required magic bytes, extractor)
_EXTRACTORS = {
    ".docx": (_ZIP_MAGIC, extract_docx),
    ".xlsx": (_ZIP_MAGIC, extract_xlsx),
    ".pptx": (_ZIP_MAGIC, extract_pptx),
    ".odt": (_ZIP_MAGIC, extract_odt),
    ".ods": (_ZIP_MAGIC, extract_ods),
    ".odp": (_ZIP_MAGIC, extract_odp),
    ".pdf": (_PDF_MAGIC, extract_pdf),
    ".eml": (b"", extract_eml),  # no magic — RFC-822 is just structured text
    ".zip": (_ZIP_MAGIC, extract_zip),
}

SUPPORTED_DOCUMENT_EXTENSIONS = frozenset(_EXTRACTORS)


def extract_document(
    suffix: str,
    raw: bytes,
    *,
    max_archive_depth: int | None = None,
    max_extracted_chars: int | None = None,
    checkpoint: Callable[[], None] | None = None,
    extraction_timed_out: Callable[[], bool] | None = None,
) -> ExtractedDoc | None:
    """Extracts text when ``suffix`` (lowercase, with dot) is a supported
    document format whose magic bytes match; returns None otherwise.

    Raises ExtractionError when the format is right but extraction fails.
    """
    entry = _EXTRACTORS.get(suffix)
    if entry is None:
        return None
    magic, extractor = entry
    if not raw.startswith(magic):
        return None
    budget_token = None
    depth_token = None
    text_limit_token = None
    checkpoint_token = None
    timeout_token = None
    if max_archive_depth is not None:
        depth_token = _ARCHIVE_DEPTH_LIMIT.set(max_archive_depth)
    if max_extracted_chars is not None:
        if max_extracted_chars <= 0:
            raise ValueError("max_extracted_chars must be positive")
        text_limit_token = _EXTRACTED_TEXT_LIMIT.set(max_extracted_chars)
    if checkpoint is not None:
        checkpoint_token = _EXTRACTION_CHECKPOINT.set(checkpoint)
    if extraction_timed_out is not None:
        timeout_token = _EXTRACTION_TIMED_OUT.set(extraction_timed_out)
    if magic == _ZIP_MAGIC and _ARCHIVE_BUDGET.get() is None:
        budget_token = _ARCHIVE_BUDGET.set(_ArchiveBudget())
    try:
        _check_extraction_control()
        document = extractor(raw)
        _check_extraction_control()
        return document
    finally:
        if timeout_token is not None:
            _EXTRACTION_TIMED_OUT.reset(timeout_token)
        if checkpoint_token is not None:
            _EXTRACTION_CHECKPOINT.reset(checkpoint_token)
        if budget_token is not None:
            _ARCHIVE_BUDGET.reset(budget_token)
        if depth_token is not None:
            _ARCHIVE_DEPTH_LIMIT.reset(depth_token)
        if text_limit_token is not None:
            _EXTRACTED_TEXT_LIMIT.reset(text_limit_token)
