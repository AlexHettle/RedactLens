"""Turns a complete remediation selection into verified redacted copies."""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path

from redactlens_core.atomic import write_many_bytes_atomically
from redactlens_core.document_anonymize import REWRITABLE_SUFFIXES, render_anonymized_document
from redactlens_core.extractors import ExtractionError, extract_document
from redactlens_core.files import (
    decode_text,
    read_regular_bytes_no_follow,
)
from redactlens_core.models import Finding
from redactlens_core.output_paths import redacted_copy_path
from redactlens_core.redact import MASK_CHAR

_ZIP_MAGIC = b"PK\x03\x04"


class Strategy(StrEnum):
    FULL_MASK = "full_mask"
    PARTIAL_MASK = "partial_mask"
    SYNTHETIC = "synthetic"


STRATEGY_BY_DETECTOR: dict[str, Strategy] = {
    "credit_card": Strategy.PARTIAL_MASK,
    "us_ssn": Strategy.PARTIAL_MASK,
    "email": Strategy.SYNTHETIC,
    "phone": Strategy.SYNTHETIC,
}

STRATEGY_BY_CATEGORY: dict[str, Strategy] = {
    "credential": Strategy.FULL_MASK,
    "financial": Strategy.PARTIAL_MASK,
    "personal_id": Strategy.SYNTHETIC,
}

DEFAULT_STRATEGY = Strategy.FULL_MASK

_SYNTHETIC_REPLACEMENTS = {
    "email": "redacted.user@example.invalid",
    "phone": "000-000-0000",
}
_ALTERNATE_MASK_CHAR = "#"


class SourceChangedError(ValueError):
    """A finding no longer addresses the source content that was scanned."""


def _full_mask(value: str) -> str:
    """Return an ASCII mask that cannot preserve the complete input value."""
    replacement = MASK_CHAR * len(value)
    if value and value.casefold() in replacement.casefold():
        return _ALTERNATE_MASK_CHAR * len(value)
    return replacement


def strategy_for(finding: Finding) -> Strategy:
    if finding.detector_id in STRATEGY_BY_DETECTOR:
        return STRATEGY_BY_DETECTOR[finding.detector_id]
    return STRATEGY_BY_CATEGORY.get(finding.category, DEFAULT_STRATEGY)


def anonymized_value(finding: Finding, keep_end: int = 4) -> str:
    strategy = strategy_for(finding)
    value = finding.matched_text

    if strategy is Strategy.FULL_MASK:
        return _full_mask(value)
    if strategy is Strategy.PARTIAL_MASK:
        if len(value) <= keep_end:
            return _full_mask(value)
        replacement = MASK_CHAR * (len(value) - keep_end) + value[-keep_end:]
        return _full_mask(value) if value.casefold() in replacement.casefold() else replacement
    if strategy is Strategy.SYNTHETIC:
        replacement = _SYNTHETIC_REPLACEMENTS.get(
            finding.detector_id,
            _full_mask(value),
        )
        # A fixed placeholder can itself contain a valid detected value. For
        # example, replacing ``user@example.invalid`` with
        # ``redacted.user@example.invalid`` would preserve the complete raw
        # selection while still matching the canonical expected output. Fall
        # back to a full mask whenever that would happen, including casing
        # variants accepted by the email detector.
        if value.casefold() in replacement.casefold():
            return _full_mask(value)
        return replacement
    raise ValueError(f"unknown strategy: {strategy}")  # pragma: no cover


RemediationSpan = tuple[int, int, str, str]


def _remediation_spans(findings: list[Finding]) -> list[RemediationSpan]:
    """Build deterministic, non-overlapping spans for the complete selection.

    Two detectors can legitimately select partially overlapping values. Dropping
    either finding would leave the non-overlapping tail of that selection in the
    output while still reporting it as applied. A true overlap group is therefore
    treated as one privacy boundary and fully masked across its union. Identical
    and contained detections naturally collapse into that same safe span.
    """
    ordered = sorted(
        findings,
        key=lambda finding: (finding.start_offset, -finding.end_offset, finding.id),
    )
    groups: list[list[Finding]] = []
    group_end = -1
    for finding in ordered:
        if groups and finding.start_offset < group_end:
            groups[-1].append(finding)
            group_end = max(group_end, finding.end_offset)
        else:
            groups.append([finding])
            group_end = finding.end_offset

    spans: list[RemediationSpan] = []
    for group in groups:
        if len(group) == 1:
            finding = group[0]
            spans.append(
                (
                    finding.start_offset,
                    finding.end_offset,
                    anonymized_value(finding),
                    finding.matched_text,
                )
            )
            continue

        start = min(finding.start_offset for finding in group)
        end = max(finding.end_offset for finding in group)
        matched: list[str | None] = [None] * (end - start)
        for finding in group:
            if finding.end_offset - finding.start_offset != len(finding.matched_text):
                raise SourceChangedError(f"finding '{finding.id}' has inconsistent source offsets")
            relative_start = finding.start_offset - start
            for index, character in enumerate(finding.matched_text, start=relative_start):
                previous = matched[index]
                if previous is not None and previous != character:
                    raise SourceChangedError(
                        "overlapping findings no longer agree on their scanned source text"
                    )
                matched[index] = character

        if any(character is None for character in matched):  # pragma: no cover - overlap invariant
            raise SourceChangedError("overlapping findings do not form a complete source span")
        matched_text = "".join(character for character in matched if character is not None)
        spans.append((start, end, _full_mask(matched_text), matched_text))
    return spans


def anonymize_text(text: str, findings: list[Finding]) -> str:
    """Apply selected findings back-to-front after rechecking their spans."""
    for finding in findings:
        if text[finding.start_offset : finding.end_offset] != finding.matched_text:
            raise SourceChangedError(
                f"finding '{finding.id}' no longer matches its scanned source span"
            )

    result = text
    spans = _remediation_spans(findings)
    for start, end, replacement, _ in sorted(spans, reverse=True):
        result = result[:start] + replacement + result[end:]
    return result


def redacted_output_path(file_path: str, *, source_bytes: bytes | None = None) -> Path:
    """Return the extension-preserving, non-destructive output path."""

    del source_bytes  # Kept for API compatibility with existing callers.
    return redacted_copy_path(file_path)


def prepare_anonymized_file(
    file_path: str,
    findings: list[Finding],
    *,
    source_bytes: bytes | None = None,
) -> bytes:
    """Build one complete redacted file in memory without writing it."""
    path = Path(file_path)
    file_findings = [finding for finding in findings if finding.file_path == file_path]
    if not file_findings:
        raise ValueError(f"no findings selected for '{path.name}'")
    if any(not finding.can_anonymize for finding in file_findings):
        raise ValueError(f"can't rewrite this file type safely: '{path.name}'")

    contents = source_bytes if source_bytes is not None else read_regular_bytes_no_follow(path)
    if path.suffix.lower() in REWRITABLE_SUFFIXES and contents.startswith(_ZIP_MAGIC):
        spans = _remediation_spans(file_findings)
        return render_anonymized_document(file_path, spans, source_bytes=contents)

    decoded = decode_text(contents)
    if decoded is None:
        raise ValueError(f"'{path.name}' is not a text file RedactLens can rewrite")
    original_text, codec = decoded
    return codec.encode(anonymize_text(original_text, file_findings))


def verify_anonymized_bytes(
    source_path: str,
    contents: bytes,
    findings: list[Finding],
    *,
    source_bytes: bytes | None = None,
) -> None:
    """Reopen rendered output and prove it matches the complete selected plan."""
    path = Path(source_path)
    original = source_bytes if source_bytes is not None else read_regular_bytes_no_follow(path)
    structured = path.suffix.lower() in REWRITABLE_SUFFIXES and contents.startswith(_ZIP_MAGIC)
    if structured:
        try:
            document = extract_document(path.suffix.lower(), contents)
            if document is None:
                raise ValueError("unsupported structured document")
        except (ExtractionError, OSError) as error:
            raise ValueError(f"could not reopen generated '{path.name}': {error}") from error
        try:
            source = extract_document(path.suffix.lower(), original)
            if source is None:
                raise ValueError("unsupported structured document")
        except (ExtractionError, OSError) as error:
            raise ValueError(f"could not reopen source '{path.name}': {error}") from error
        expected = anonymize_text(source.text, findings)
        if document.text != expected:
            raise ValueError(f"generated '{path.name}' does not match the remediation plan")
    else:
        decoded = decode_text(contents)
        if decoded is None:
            raise ValueError(f"generated '{path.name}' is not readable text")
        source = decode_text(original)
        if source is None:
            raise ValueError(f"source '{path.name}' is no longer readable text")
        expected = anonymize_text(source[0], findings)
        if decoded[0] != expected:
            raise ValueError(f"generated '{path.name}' does not match the remediation plan")


def anonymize_file(file_path: str, findings: list[Finding], in_place: bool = False) -> str:
    """Create one atomic redacted copy from the complete supplied selection."""
    path = Path(file_path)
    file_findings = [finding for finding in findings if finding.file_path == file_path]
    source_bytes = read_regular_bytes_no_follow(path)
    output_path = path if in_place else redacted_output_path(file_path, source_bytes=source_bytes)
    contents = prepare_anonymized_file(
        file_path,
        file_findings,
        source_bytes=source_bytes,
    )
    verify_anonymized_bytes(
        file_path,
        contents,
        file_findings,
        source_bytes=source_bytes,
    )

    def validate_committed() -> None:
        actual = read_regular_bytes_no_follow(output_path, max_bytes=len(contents))
        if actual != contents:
            raise ValueError(f"committed output '{output_path.name}' differs from verified bytes")
        if not in_place:
            verify_anonymized_bytes(
                file_path,
                actual,
                file_findings,
                source_bytes=source_bytes,
            )

    write_many_bytes_atomically(
        {output_path: contents},
        replace_existing=in_place,
        validate_committed=validate_committed,
    )
    return str(output_path)


def anonymize_files(findings: list[Finding], in_place: bool = False) -> dict[str, str]:
    """Render, verify, and atomically commit every selected source once."""
    by_file: dict[str, list[Finding]] = {}
    for finding in findings:
        by_file.setdefault(finding.file_path, []).append(finding)

    source_bytes = {path: read_regular_bytes_no_follow(path) for path in by_file}
    output_paths = {
        path: (
            Path(path) if in_place else redacted_output_path(path, source_bytes=source_bytes[path])
        )
        for path in by_file
    }
    rendered = {
        output_paths[path]: prepare_anonymized_file(
            path,
            file_findings,
            source_bytes=source_bytes[path],
        )
        for path, file_findings in by_file.items()
    }
    for path, file_findings in by_file.items():
        verify_anonymized_bytes(
            path,
            rendered[output_paths[path]],
            file_findings,
            source_bytes=source_bytes[path],
        )

    def validate_committed() -> None:
        for path, file_findings in by_file.items():
            output_path = output_paths[path]
            actual = read_regular_bytes_no_follow(
                output_path,
                max_bytes=len(rendered[output_path]),
            )
            if actual != rendered[output_path]:
                raise ValueError(
                    f"committed output '{output_path.name}' differs from verified bytes"
                )
            if not in_place:
                verify_anonymized_bytes(
                    path,
                    actual,
                    file_findings,
                    source_bytes=source_bytes[path],
                )

    write_many_bytes_atomically(
        rendered,
        replace_existing=in_place,
        validate_committed=validate_committed,
    )
    return {path: str(output) for path, output in output_paths.items()}
