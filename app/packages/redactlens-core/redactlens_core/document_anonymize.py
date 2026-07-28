"""Write-back anonymization for rewritable document formats: docx, xlsx,
pptx, and the OpenDocument family (odt/ods/odp).

Findings in extracted documents carry offsets into the *extracted* text, so
writing them back means mapping those offsets to the XML text nodes that
produced them: this module rebuilds the extraction (using the same unit
walkers as extractors.py, so the traversal order can never drift), verifies
each finding still matches the document, edits the text nodes, and rewrites
the zip container with every other member byte-identical.

Format notes:
  - docx: covers everything extraction covers — body, headers, footers,
    footnotes, endnotes, comments, text boxes. A matched value can be split
    across several ``<w:t>`` runs (Word fragments text arbitrarily); the
    replacement lands in the first run and the covered parts of later runs
    are removed.
  - xlsx: an edited cell is converted to an inline string. Editing the
    shared-strings table instead would silently rewrite every OTHER cell
    that references the same string — the classic xlsx corruption bug.
    Shared-string entries orphaned by the edit are blanked so the secret
    bytes don't survive inside the "redacted" file.
  - pptx: slide and speaker-note paragraphs, same run mechanics as docx.
  - PDF is deliberately NOT here. PDF redaction is unsafe to automate
    (text survives in content streams/metadata even when it stops
    rendering), so RedactLens never claims it.

XML is parsed and re-serialized with lxml because it preserves the original
namespace prefixes; stdlib ElementTree renames them (ns0:), which breaks
Word documents whose ``mc:Ignorable`` attribute lists the original prefixes.
"""

import io
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from lxml import etree

from redactlens_core.atomic import write_bytes_atomically
from redactlens_core.extractors import (
    ExtractionError,
    _open_zip,
    docx_part_names,
    iter_docx_units,
    iter_odf_units,
    iter_pptx_units,
    odf_part_names,
    piece_text,
    pptx_part_names,
    unit_text,
    xlsx_cell_value,
    xlsx_shared_strings,
    xlsx_sheet_parts,
)
from redactlens_core.output_paths import redacted_copy_path

# Formats scan findings can be written back into. pdf stays read-only.
REWRITABLE_FORMATS = frozenset({"docx", "xlsx", "pptx", "odt", "ods", "odp"})
REWRITABLE_SUFFIXES = frozenset({".docx", ".xlsx", ".pptx", ".odt", ".ods", ".odp"})

_S = "{http://schemas.openxmlformats.org/spreadsheetml/2006/main}"
_W = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"
_ODF_OFFICE = "{urn:oasis:names:tc:opendocument:xmlns:office:1.0}"
_ODF_TABLE = "{urn:oasis:names:tc:opendocument:xmlns:table:1.0}"
_ODF_TEXT = "{urn:oasis:names:tc:opendocument:xmlns:text:1.0}"
_XML_SPACE = "{http://www.w3.org/XML/1998/namespace}space"

_ODF_DYNAMIC_FIELD_TAGS = frozenset(
    f"{_ODF_TEXT}{name}"
    for name in (
        "expression",
        "sequence",
        "user-field-get",
        "user-field-input",
        "variable-get",
        "variable-input",
        "variable-set",
    )
)
_ODF_USER_FIELD_REFERENCES = frozenset(
    {f"{_ODF_TEXT}user-field-get", f"{_ODF_TEXT}user-field-input"}
)
_ODF_VARIABLE_REFERENCES = frozenset({f"{_ODF_TEXT}variable-get", f"{_ODF_TEXT}variable-input"})

# Hardened: no entity resolution, no fetching anything external.
_PARSER = etree.XMLParser(resolve_entities=False, no_network=True)

# (start, end, replacement) in extracted-text offsets, plus the text the
# scan matched there — re-verified against the document before any edit.
Span = tuple[int, int, str, str]


@dataclass
class _Carrier:
    """One XML-backed piece of extracted text and its global offsets."""

    node: Any  # lxml element: <w:t>/<a:t> run for docx/pptx, <c> for xlsx
    start: int
    end: int
    text: str
    part: str  # zip member this node lives in
    attr: str = "text"  # which element attribute carries the text (ODF: tail too)
    cell: Any = None  # owning ODF spreadsheet cell, for office:value scrubbing
    modified: bool = field(default=False)


class DocumentChangedError(ValueError):
    """The document no longer matches the scan the findings came from."""


def anonymize_document(file_path: str, spans: list[Span], in_place: bool = False) -> str:
    """Applies replacement spans to a docx/xlsx/pptx file. Returns the path
    written to: ``<name>-auto-redacted-copy.<ext>`` (extension preserved so the
    redacted copy still opens in Word/Excel/PowerPoint), or the original
    when ``in_place`` is explicitly True.
    """
    path = Path(file_path)
    from redactlens_core.files import read_regular_bytes_no_follow

    source_bytes = read_regular_bytes_no_follow(path)
    new_raw = render_anonymized_document(file_path, spans, source_bytes=source_bytes)
    output = path if in_place else redacted_copy_path(path)
    write_bytes_atomically(output, new_raw, replace_existing=in_place)
    return str(output)


def render_anonymized_document(
    file_path: str,
    spans: list[Span],
    *,
    source_bytes: bytes | None = None,
) -> bytes:
    """Render a rewritten structured document without touching the filesystem."""
    path = Path(file_path)
    suffix = path.suffix.lower()
    if source_bytes is None:
        # Local import avoids a module-import cycle: files owns the shared
        # no-follow reader and imports the rewritable-format constants above.
        from redactlens_core.files import read_regular_bytes_no_follow

        raw = read_regular_bytes_no_follow(path)
    else:
        raw = source_bytes
    builders = {
        ".docx": _docx_carriers,
        ".xlsx": _xlsx_carriers,
        ".pptx": _pptx_carriers,
        ".odt": _odf_carriers("odt"),
        ".ods": _odf_carriers("ods"),
        ".odp": _odf_carriers("odp"),
    }
    if suffix not in builders:
        raise ValueError(f"'{suffix}' is not a rewritable document format")
    try:
        return _rewrite(raw, builders[suffix], spans)
    except ExtractionError as error:
        raise ValueError(f"could not rewrite '{path.name}': {error}") from error


def _rewrite(raw: bytes, build_carriers, spans: list[Span]) -> bytes:
    zf = _open_zip(raw)  # same member-count / decompressed-size caps as scanning
    with zf:
        carriers, finalize = build_carriers(zf)
        _verify_spans(carriers, spans)
        _apply_spans(carriers, spans)
        replaced = finalize(spans)
    return _rebuild_zip(raw, replaced) if replaced else raw


def _lxml_parse(data: bytes, member: str):
    try:
        return etree.fromstring(data, _PARSER)
    except etree.XMLSyntaxError as e:
        raise ExtractionError(f"malformed XML in document part '{member}': {e}") from e


# ---- Offset mapping -----------------------------------------------------------
#
# Carrier construction reuses the same unit walkers extraction runs on, and
# mirrors _SegmentBuilder: non-empty units joined by single newlines.
# _verify_spans backstops any drift — a mismatch turns into a clean
# "rescan" error, never a wrong edit.


def _run_carriers(units, trees: dict[str, Any]):
    """Carriers for run-based formats (docx/pptx): one per text node."""
    carriers: list[_Carrier] = []
    position = 0
    first = True
    for part_name, _label, nodes in units:
        text = unit_text(nodes)
        if not text.strip():
            continue  # skipped by the extractor too
        if not first:
            position += 1  # the joining newline
        first = False
        local = 0
        for node in nodes:
            node_text = node.text or ""
            carriers.append(
                _Carrier(
                    node=node,
                    start=position + local,
                    end=position + local + len(node_text),
                    text=node_text,
                    part=part_name,
                )
            )
            local += len(node_text)
        position += len(text)

    def finalize(_spans: list[Span]) -> dict[str, bytes]:
        changed_parts = set()
        for carrier in carriers:
            if carrier.modified:
                carrier.node.text = carrier.text
                if carrier.text != carrier.text.strip():
                    carrier.node.set(_XML_SPACE, "preserve")
                changed_parts.add(carrier.part)
        return {part: _serialize(trees[part]) for part in changed_parts}

    return carriers, finalize


def _docx_carriers(zf: zipfile.ZipFile):
    part_names = docx_part_names(set(zf.namelist()))
    trees = {name: _lxml_parse(zf.read(name), name) for name in part_names}
    units = iter_docx_units([(name, trees[name]) for name in part_names])
    carriers, finalize_text = _run_carriers(units, trees)

    def finalize(spans: list[Span]) -> dict[str, bytes]:
        replaced = finalize_text(spans)
        changed_parts = _flatten_touched_docx_fields(carriers)
        for part in changed_parts:
            replaced[part] = _serialize(trees[part])
        return replaced

    return carriers, finalize


@dataclass
class _ComplexWordField:
    """The control and instruction nodes for one complex Word field."""

    controls: list[Any] = field(default_factory=list)
    instructions: list[Any] = field(default_factory=list)
    touched: bool = False
    complete: bool = False
    separated: bool = False


def _flatten_touched_docx_fields(carriers: list[_Carrier]) -> set[str]:
    """Turn touched Word fields into ordinary result text.

    Word stores simple-field instructions in ``w:fldSimple/@w:instr`` and
    complex-field instructions in separate ``w:instrText`` runs. Merely
    changing the displayed ``w:t`` leaves those instructions able to restore
    the original value when fields update. Flatten only fields containing an
    edited carrier; unrelated fields remain live.
    """
    touched_paragraphs: dict[Any, tuple[str, set[Any]]] = {}
    simple_fields: set[Any] = set()

    for carrier in carriers:
        if not carrier.modified:
            continue
        paragraph = _nearest_word_paragraph(carrier.node)
        if paragraph is None:
            raise ValueError("could not safely flatten a Word field outside a paragraph")
        entry = touched_paragraphs.setdefault(paragraph, (carrier.part, set()))
        entry[1].add(carrier.node)
        for ancestor in carrier.node.iterancestors():
            if ancestor is paragraph:
                break
            if ancestor.tag == f"{_W}fldSimple":
                simple_fields.add(ancestor)

    touched_complex: list[_ComplexWordField] = []
    for paragraph, (_part, touched_nodes) in touched_paragraphs.items():
        stack: list[_ComplexWordField] = []
        malformed = False
        has_complex_markup = False

        for element in paragraph.iter():
            if element is not paragraph and _nearest_word_paragraph(element) is not paragraph:
                continue  # belongs to a nested text-box paragraph
            if element.tag == f"{_W}fldChar":
                has_complex_markup = True
                kind = element.get(f"{_W}fldCharType")
                if kind == "begin":
                    record = _ComplexWordField(controls=[element])
                    stack.append(record)
                elif kind == "separate" and stack and not stack[-1].separated:
                    stack[-1].controls.append(element)
                    stack[-1].separated = True
                elif kind == "end" and stack:
                    record = stack.pop()
                    record.controls.append(element)
                    record.complete = True
                    if record.touched:
                        touched_complex.append(record)
                else:
                    malformed = True
            elif element.tag == f"{_W}instrText":
                has_complex_markup = True
                if stack:
                    stack[-1].instructions.append(element)
                else:
                    malformed = True
            elif element.tag == f"{_W}t" and element in touched_nodes:
                # Nested fields can each regenerate the selected result, so
                # every open field containing the carrier must be flattened.
                for record in stack:
                    record.touched = True

        if stack:
            malformed = True
        if malformed and has_complex_markup:
            raise ValueError(
                "could not safely flatten malformed Word field markup in a touched paragraph"
            )

    for record in touched_complex:
        if not record.complete:
            raise ValueError("could not safely flatten an incomplete Word field")
        for node in record.instructions + record.controls:
            _drop_element(node)

    # Work inside-out so nested simple fields are flattened without losing
    # their result children or changing their order in the paragraph.
    for element in sorted(simple_fields, key=_element_depth, reverse=True):
        _unwrap_element(element)

    return {part for part, _nodes in touched_paragraphs.values()}


def _pptx_carriers(zf: zipfile.ZipFile):
    part_list = pptx_part_names(set(zf.namelist()))
    trees = {name: _lxml_parse(zf.read(name), name) for name, _ in part_list}
    units = iter_pptx_units([(name, label, trees[name]) for name, label in part_list])
    return _run_carriers(units, trees)


def _flatten_touched_odf_fields(
    carriers: list[_Carrier], trees: dict[str, Any], spans: list[Span]
) -> set[str]:
    """Flatten touched ODF fields and scrub orphaned backing values.

    Dynamic ODF fields keep their calculation/value in attributes that the
    canonical visible-text extractor intentionally does not emit. Flattening
    the selected field prevents recalculation from restoring it. User/variable
    backing values are also removed when no unflattened reference still needs
    them (the same preservation rule used for shared XLSX strings).
    """
    fields: set[Any] = set()
    changed_parts: set[str] = set()
    references: set[tuple[str, str]] = set()

    for carrier in carriers:
        if not carrier.modified:
            continue
        current = carrier.node if carrier.attr == "text" else carrier.node.getparent()
        while current is not None:
            if current.tag in _ODF_DYNAMIC_FIELD_TAGS:
                fields.add(current)
                name = current.get(f"{_ODF_TEXT}name")
                if name and current.tag in _ODF_USER_FIELD_REFERENCES:
                    references.add(("user", name))
                elif name and current.tag in _ODF_VARIABLE_REFERENCES:
                    references.add(("variable", name))
            current = current.getparent()
        changed_parts.add(carrier.part)

    for element in sorted(fields, key=_element_depth, reverse=True):
        _unwrap_element(element)

    selected_values = tuple(matched for _start, _end, _replacement, matched in spans if matched)
    for family, name in references:
        reference_tags = (
            _ODF_USER_FIELD_REFERENCES if family == "user" else _ODF_VARIABLE_REFERENCES
        )
        if any(
            element.get(f"{_ODF_TEXT}name") == name
            for tree in trees.values()
            for tag in reference_tags
            for element in tree.iter(tag)
        ):
            continue  # an ignored occurrence still relies on the backing value

        backing_tag = (
            f"{_ODF_TEXT}user-field-decl" if family == "user" else f"{_ODF_TEXT}variable-set"
        )
        for part, tree in trees.items():
            for backing in tree.iter(backing_tag):
                if backing.get(f"{_ODF_TEXT}name") != name:
                    continue
                for attribute, value in list(backing.attrib.items()):
                    if _is_odf_backing_value(attribute) and any(
                        selected in value for selected in selected_values
                    ):
                        del backing.attrib[attribute]
                        changed_parts.add(part)

    return changed_parts


def _odf_carriers(fmt: str):
    """Carrier builder for OpenDocument formats. ODF text is mixed content
    ((node, text|tail) pieces), and edited spreadsheet cells must have their
    office:value* attributes scrubbed — the display text may be masked, but
    the raw number would otherwise survive in the attribute."""

    def build(zf: zipfile.ZipFile):
        part_names = odf_part_names(fmt, set(zf.namelist()))
        trees = {name: _lxml_parse(zf.read(name), name) for name in part_names}
        parts = [(name, trees[name]) for name in part_names]

        carriers: list[_Carrier] = []
        position = 0
        first = True
        for part_name, _label, pieces, cell in iter_odf_units(fmt, parts):
            text = piece_text(pieces)
            if not text.strip():
                continue  # skipped by the extractor too
            if not first:
                position += 1  # the joining newline
            first = False
            local = 0
            for node, attr in pieces:
                node_text = getattr(node, attr) or ""
                carriers.append(
                    _Carrier(
                        node=node,
                        start=position + local,
                        end=position + local + len(node_text),
                        text=node_text,
                        part=part_name,
                        attr=attr,
                        cell=cell,
                    )
                )
                local += len(node_text)
            position += len(text)

        def finalize(spans: list[Span]) -> dict[str, bytes]:
            changed_parts = set()
            touched_cells = []
            for carrier in carriers:
                if carrier.modified:
                    setattr(carrier.node, carrier.attr, carrier.text)
                    changed_parts.add(carrier.part)
                    if carrier.cell is not None and carrier.cell not in touched_cells:
                        touched_cells.append(carrier.cell)
            for cell in touched_cells:
                for name in list(cell.attrib):
                    if name.startswith(_ODF_OFFICE) and "value" in name:
                        del cell.attrib[name]
                cell.attrib.pop(f"{_ODF_TABLE}formula", None)
                cell.set(f"{_ODF_OFFICE}value-type", "string")
            changed_parts.update(_flatten_touched_odf_fields(carriers, trees, spans))
            return {part: _serialize(trees[part]) for part in changed_parts}

        return carriers, finalize

    return build


def _xlsx_carriers(zf: zipfile.ZipFile):
    shared, shared_tree = xlsx_shared_strings(zf, parse=_lxml_parse)

    carriers: list[_Carrier] = []
    trees: dict[str, Any] = {}
    position = 0
    first = True
    for part, _label in xlsx_sheet_parts(zf, parse=_lxml_parse):
        tree = _lxml_parse(zf.read(part), part)
        trees[part] = tree
        for cell in tree.iter(f"{_S}c"):
            value = xlsx_cell_value(cell, shared)
            if not value.strip():
                continue
            if not first:
                position += 1
            first = False
            carriers.append(
                _Carrier(
                    node=cell,
                    start=position,
                    end=position + len(value),
                    text=value,
                    part=part,
                )
            )
            position += len(value)

    def finalize(_spans: list[Span]) -> dict[str, bytes]:
        changed_parts = set()
        freed_shared: set[int] = set()
        for carrier in carriers:
            if carrier.modified:
                index = _shared_index(carrier.node)
                if index is not None:
                    freed_shared.add(index)
                _set_inline_string(carrier.node, carrier.text)
                changed_parts.add(carrier.part)
        replaced = {part: _serialize(trees[part]) for part in changed_parts}

        # Converting a cell to an inline string orphans its shared-string
        # entry — but the secret bytes would still sit in sharedStrings.xml,
        # recoverable by unzipping the "redacted" file. Blank every freed
        # entry that no remaining cell references (entries are blanked in
        # place, never removed: removal would shift every later index).
        if shared_tree is not None and freed_shared:
            still_referenced = {
                index
                for tree in trees.values()
                for cell in tree.iter(f"{_S}c")
                if (index := _shared_index(cell)) is not None
            }
            orphaned = freed_shared - still_referenced
            if orphaned:
                for index, si in enumerate(shared_tree.iter(f"{_S}si")):
                    if index in orphaned:
                        for child in list(si):
                            si.remove(child)
                        etree.SubElement(si, f"{_S}t").text = ""
                replaced["xl/sharedStrings.xml"] = _serialize(shared_tree)
        return replaced

    return carriers, finalize


def _shared_index(cell) -> int | None:
    """The shared-strings index a cell references, or None."""
    if cell.get("t") != "s":
        return None
    v = cell.find(f"{_S}v")
    if v is not None and v.text and v.text.strip().isdigit():
        return int(v.text)
    return None


def _set_inline_string(cell, value: str) -> None:
    """Replaces a cell's content with an inline string, leaving the shared-
    strings table untouched (other cells may reference the same entry)."""
    for child in list(cell):
        cell.remove(child)
    cell.set("t", "inlineStr")
    inline = etree.SubElement(cell, f"{_S}is")
    t = etree.SubElement(inline, f"{_S}t")
    t.text = value
    if value != value.strip():
        t.set(_XML_SPACE, "preserve")


# ---- Span application ----------------------------------------------------------


def _overlapping(carriers: list[_Carrier], start: int, end: int) -> list[_Carrier]:
    return [c for c in carriers if c.end > start and c.start < end]


def _verify_spans(carriers: list[_Carrier], spans: list[Span]) -> None:
    for start, end, _, matched_text in spans:
        if _span_text(carriers, start, end) != matched_text:
            raise DocumentChangedError(
                "the document changed since it was scanned — rescan it and try again"
            )


def _span_text(carriers: list[_Carrier], start: int, end: int) -> str:
    """Reconstructs the extracted text covered by [start, end): carrier
    slices plus the virtual newlines that join carriers in the extraction."""
    pieces: list[str] = []
    previous_end = start
    for carrier in _overlapping(carriers, start, end):
        if carrier.start > previous_end:
            pieces.append("\n" * (carrier.start - previous_end))
        piece_start = max(start - carrier.start, 0)
        piece_end = min(end, carrier.end) - carrier.start
        pieces.append(carrier.text[piece_start:piece_end])
        previous_end = carrier.end
    if end > previous_end:
        pieces.append("\n" * (end - previous_end))
    return "".join(pieces)


def _apply_spans(carriers: list[_Carrier], spans: list[Span]) -> None:
    """Edits carrier texts back-to-front so earlier offsets stay valid.

    The replacement lands where the span begins; parts of the span covered
    by later carriers are removed from them. Spans must be non-overlapping
    (anonymize.py drops overlaps before calling in).
    """
    for start, end, replacement, _ in sorted(spans, reverse=True):
        hit = _overlapping(carriers, start, end)
        if not hit:
            raise DocumentChangedError(
                "the document changed since it was scanned — rescan it and try again"
            )
        for i, carrier in enumerate(hit):
            local_start = max(start - carrier.start, 0)
            local_end = min(end, carrier.end) - carrier.start
            head, tail = carrier.text[:local_start], carrier.text[local_end:]
            carrier.text = head + (replacement if i == 0 else "") + tail
            carrier.modified = True


# ---- Field/backing-store cleanup ----------------------------------------------


def _nearest_word_paragraph(element: Any) -> Any | None:
    if element.tag == f"{_W}p":
        return element
    return next(
        (ancestor for ancestor in element.iterancestors() if ancestor.tag == f"{_W}p"), None
    )


def _element_depth(element: Any) -> int:
    return sum(1 for _ in element.iterancestors())


def _append_unwrapped_text(parent: Any, index: int, text: str | None) -> None:
    if not text:
        return
    if index == 0:
        parent.text = (parent.text or "") + text
    else:
        previous = parent[index - 1]
        previous.tail = (previous.tail or "") + text


def _drop_element(element: Any) -> None:
    """Remove an XML element and its content, preserving only its tail."""
    parent = element.getparent()
    if parent is None:
        raise ValueError("could not safely remove detached field markup")
    index = parent.index(element)
    tail = element.tail
    parent.remove(element)
    _append_unwrapped_text(parent, index, tail)


def _unwrap_element(element: Any) -> None:
    """Remove a field wrapper while preserving its visible mixed content."""
    parent = element.getparent()
    if parent is None:
        raise ValueError("could not safely flatten detached field markup")
    index = parent.index(element)
    _append_unwrapped_text(parent, index, element.text)
    children = list(element)
    for child in children:
        element.remove(child)
        parent.insert(index, child)
        index += 1
    tail = element.tail
    parent.remove(element)
    _append_unwrapped_text(parent, index, tail)


def _is_odf_backing_value(attribute: str) -> bool:
    if attribute in {f"{_ODF_TABLE}formula", f"{_ODF_TEXT}formula"}:
        return True
    if not attribute.startswith(_ODF_OFFICE):
        return False
    local_name = attribute[len(_ODF_OFFICE) :]
    return local_name == "value" or local_name.endswith("-value")


# ---- Container plumbing ---------------------------------------------------------


def _serialize(tree) -> bytes:
    return etree.tostring(tree, xml_declaration=True, encoding="UTF-8", standalone=True)


def _rebuild_zip(raw: bytes, replaced: dict[str, bytes]) -> bytes:
    """A new zip with ``replaced`` members swapped in and everything else
    copied verbatim (metadata included, so Office doesn't see a difference)."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(raw)) as source, zipfile.ZipFile(buffer, "w") as out:
        for info in source.infolist():
            out.writestr(info, replaced.get(info.filename, source.read(info.filename)))
    return buffer.getvalue()
