import codecs
from pathlib import Path

import pytest
import redactlens_core.anonymize as anonymize_module
from redactlens_core.anonymize import (
    Strategy,
    anonymize_file,
    anonymize_files,
    anonymize_text,
    anonymized_value,
    strategy_for,
)
from redactlens_core.models import Finding


def _finding(**overrides) -> Finding:
    base = dict(
        id="abc123",
        file_path="f.txt",
        line=1,
        column=1,
        start_offset=0,
        end_offset=0,
        matched_text="",
        redacted_preview="",
        detector_id="password_assignment",
        category="credential",
        confidence=0.9,
        tier="A",
        explanation="e",
        risk_lesson="r",
        suggested_action="anonymize",
        evidence={},
    )
    base.update(overrides)
    base["end_offset"] = base["start_offset"] + len(base["matched_text"])
    return Finding.model_validate(base)


def test_strategy_for_uses_detector_specific_mapping_first():
    finding = _finding(detector_id="credit_card", category="financial")
    assert strategy_for(finding) is Strategy.PARTIAL_MASK


def test_strategy_for_falls_back_to_category():
    finding = _finding(detector_id="high_entropy_secret", category="credential")
    assert strategy_for(finding) is Strategy.FULL_MASK


def test_strategy_for_falls_back_to_default_for_unknown_category():
    finding = _finding(detector_id="user_target_0", category="custom")
    assert strategy_for(finding) is Strategy.FULL_MASK


def test_full_mask_hides_every_character():
    finding = _finding(detector_id="password_assignment", matched_text="Sup3rSecret!")
    assert anonymized_value(finding) == "*" * len("Sup3rSecret!")


def test_full_mask_changes_a_custom_target_made_of_mask_characters():
    finding = _finding(detector_id="user_target_0", category="custom", matched_text="*****")

    replacement = anonymized_value(finding)

    assert replacement == "#####"
    assert finding.matched_text not in replacement


def test_partial_mask_keeps_last_four_characters():
    finding = _finding(detector_id="credit_card", matched_text="4111111111111111")
    assert anonymized_value(finding) == "*" * 12 + "1111"


def test_partial_mask_fully_masks_short_values():
    finding = _finding(detector_id="us_ssn", matched_text="123")
    assert anonymized_value(finding) == "***"


def test_partial_mask_falls_back_when_the_normal_mask_would_preserve_source():
    finding = _finding(detector_id="credit_card", matched_text="****1111")

    replacement = anonymized_value(finding)

    assert replacement == "********"
    assert finding.matched_text not in replacement


def test_synthetic_replaces_email_and_phone():
    email = _finding(detector_id="email", matched_text="jane.doe@redactlensteam.io")
    phone = _finding(detector_id="phone", matched_text="415-555-2671")
    assert anonymized_value(email) == "redacted.user@example.invalid"
    assert anonymized_value(phone) == "000-000-0000"


@pytest.mark.parametrize(
    ("detector_id", "matched_text"),
    [
        ("email", "user@example.invalid"),
        ("email", "USER@example.invalid"),
        ("email", "redacted.user@example.invalid"),
        ("phone", "000-000-0000"),
    ],
)
def test_synthetic_falls_back_to_full_mask_when_placeholder_contains_source(
    detector_id,
    matched_text,
):
    finding = _finding(detector_id=detector_id, matched_text=matched_text)

    replacement = anonymized_value(finding)

    assert replacement == "*" * len(matched_text)
    assert matched_text.casefold() not in replacement.casefold()


def test_anonymize_text_replaces_multiple_findings_back_to_front():
    text = "ssn = 123-45-6789 and email = jane.doe@redactlensteam.io"
    ssn = _finding(detector_id="us_ssn", start_offset=6, matched_text="123-45-6789")
    email = _finding(
        detector_id="email",
        start_offset=text.index("jane.doe@redactlensteam.io"),
        matched_text="jane.doe@redactlensteam.io",
    )

    result = anonymize_text(text, [ssn, email])

    assert "123-45-6789" not in result
    assert "jane.doe@redactlensteam.io" not in result
    assert result.startswith("ssn = ")
    assert "6789" in result  # partial mask keeps the last 4 digits


def test_anonymize_text_collapses_identical_overlapping_findings():
    text = "AKIAABCDEFGHIJKLMNOP"
    aws = _finding(detector_id="aws_access_key", start_offset=0, matched_text=text)
    entropy = _finding(detector_id="high_entropy_secret", start_offset=0, matched_text=text)

    result = anonymize_text(text, [aws, entropy])

    assert result == "*" * len(text)  # not double-substituted or corrupted


def test_anonymize_text_masks_the_union_of_partially_overlapping_findings():
    text = "ABCDEFG"
    first = _finding(id="first", start_offset=0, matched_text="ABCD")
    second = _finding(id="second", start_offset=2, matched_text="CDEFG")

    result = anonymize_text(text, [second, first])

    assert result == "*" * len(text)
    assert "EFG" not in result


def test_anonymize_text_changes_overlapping_mask_character_targets():
    text = "*****"
    first = _finding(id="first", detector_id="user_target_0", matched_text=text)
    second = _finding(id="second", detector_id="user_target_1", matched_text=text)

    result = anonymize_text(text, [first, second])

    assert result == "#####"
    assert text not in result


def test_anonymize_file_writes_redacted_copy_by_default(tmp_path):
    original = tmp_path / "secrets.py"
    original.write_text('ssn = "123-45-6789"\n')
    finding = _finding(
        file_path=str(original), detector_id="us_ssn", start_offset=6, matched_text='"123-45-6789"'
    )

    output_path = anonymize_file(str(original), [finding])

    assert output_path == str(tmp_path / "secrets-auto-redacted-copy.py")
    assert original.read_text() == 'ssn = "123-45-6789"\n'  # untouched
    assert "123-45-6789" not in Path(output_path).read_text()


@pytest.mark.parametrize("batch", [False, True])
def test_committed_output_validation_uses_the_no_follow_reader(monkeypatch, tmp_path, batch):
    original = tmp_path / "secrets.py"
    source = 'ssn = "123-45-6789"\n'
    original.write_text(source)
    finding = _finding(
        file_path=str(original),
        detector_id="us_ssn",
        start_offset=source.index("123-45-6789"),
        matched_text="123-45-6789",
    )
    real_reader = anonymize_module.read_regular_bytes_no_follow
    reads: list[Path] = []

    def recording_reader(path, **kwargs):
        reads.append(Path(path))
        return real_reader(path, **kwargs)

    def commit_and_validate(outputs, *, validate_committed, **_kwargs):
        for output, contents in outputs.items():
            output.write_bytes(contents)
        validate_committed()

    monkeypatch.setattr(anonymize_module, "read_regular_bytes_no_follow", recording_reader)
    monkeypatch.setattr(anonymize_module, "write_many_bytes_atomically", commit_and_validate)

    if batch:
        output_path = Path(anonymize_files([finding])[str(original)])
    else:
        output_path = Path(anonymize_file(str(original), [finding]))

    assert reads == [original, output_path]


@pytest.mark.parametrize(
    ("source_name", "output_name"),
    [
        ("notes.txt", "notes-auto-redacted-copy.txt"),
        ("large.docx", "large-auto-redacted-copy.docx"),
        ("archive.tar.gz", "archive.tar-auto-redacted-copy.gz"),
        ("LICENSE", "LICENSE-auto-redacted-copy"),
        (".env", ".env-auto-redacted-copy"),
    ],
)
def test_redacted_output_naming_preserves_the_final_extension(tmp_path, source_name, output_name):
    output = anonymize_module.redacted_output_path(str(tmp_path / source_name))

    assert output == tmp_path / output_name


def test_anonymize_file_rejects_a_static_symbolic_link_source(tmp_path):
    target = tmp_path / "actual-secrets.py"
    source = 'ssn = "123-45-6789"\n'
    target.write_text(source)
    redirected = tmp_path / "redirected-secrets.py"
    try:
        redirected.symlink_to(target)
    except OSError as error:
        pytest.skip(f"file symlinks are unavailable in this environment: {error}")
    finding = _finding(
        file_path=str(redirected),
        detector_id="us_ssn",
        start_offset=7,
        matched_text="123-45-6789",
    )

    with pytest.raises(OSError, match="symbolic link"):
        anonymize_file(str(redirected), [finding])

    assert target.read_text() == source
    assert not redirected.with_name("redirected-secrets-auto-redacted-copy.py").exists()


def test_anonymize_file_never_preserves_email_inside_synthetic_placeholder(tmp_path):
    original = tmp_path / "contact.txt"
    matched_text = "user@example.invalid"
    source = f"contact = {matched_text}\n"
    original.write_text(source)
    finding = _finding(
        file_path=str(original),
        detector_id="email",
        category="personal_id",
        start_offset=source.index(matched_text),
        matched_text=matched_text,
    )

    output_path = anonymize_file(str(original), [finding])

    redacted = Path(output_path).read_text()
    assert matched_text not in redacted
    assert "*" * len(matched_text) in redacted


def test_incomplete_second_write_cannot_replace_an_existing_redacted_copy(tmp_path):
    """Low-level callers cannot silently restore an earlier redaction."""
    original = tmp_path / "secrets.txt"
    text = "password = FirstSecret123!\nssn = 123-45-6789\n"
    original.write_bytes(text.encode())
    password = _finding(
        id="password",
        file_path=str(original),
        detector_id="password_assignment",
        start_offset=text.index("FirstSecret123!"),
        matched_text="FirstSecret123!",
    )
    ssn = _finding(
        id="ssn",
        file_path=str(original),
        detector_id="us_ssn",
        category="personal_id",
        start_offset=text.index("123-45-6789"),
        matched_text="123-45-6789",
    )

    first_output = anonymize_file(str(original), [password])
    with pytest.raises(FileExistsError, match="output already exists"):
        anonymize_file(str(original), [ssn])
    redacted = Path(first_output).read_text()

    assert "FirstSecret123!" not in redacted
    assert "123-45-6789" in redacted


def test_anonymize_file_in_place_requires_explicit_opt_in(tmp_path):
    original = tmp_path / "secrets.py"
    original.write_text('ssn = "123-45-6789"\n')
    finding = _finding(
        file_path=str(original), detector_id="us_ssn", start_offset=6, matched_text='"123-45-6789"'
    )

    output_path = anonymize_file(str(original), [finding], in_place=True)

    assert output_path == str(original)
    assert "123-45-6789" not in original.read_text()


def test_anonymize_refuses_non_rewritable_document_findings(tmp_path):
    """pdf findings carry offsets into the *extracted* text and the format
    can't be rewritten; writing back would corrupt the document."""
    doc = tmp_path / "report.pdf"
    doc.write_bytes(b"%PDF-1.4 pretend pdf")
    finding = _finding(
        file_path=str(doc),
        detector_id="us_ssn",
        matched_text="123-45-6789",
        location="page 2",
        can_anonymize=False,
    )

    with pytest.raises(ValueError, match="can't rewrite this file type"):
        anonymize_files([finding])

    assert doc.read_bytes() == b"%PDF-1.4 pretend pdf"  # untouched
    assert not doc.with_name("report-auto-redacted-copy.pdf").exists()


def test_anonymize_utf16_file_stays_utf16(tmp_path):
    """Scan offsets address the DECODED text, so the writer must decode the
    same way — and the redacted copy must keep the original encoding+BOM."""
    import codecs

    from redactlens_core.models import ScanRequest
    from redactlens_core.registry import load_default_registry
    from redactlens_core.scanner import scan

    original = tmp_path / "log.txt"
    original.write_bytes('user ssn = "123-45-6789" end\n'.encode("utf-16"))
    findings = [
        f
        for f in scan(ScanRequest(paths=[str(tmp_path)]), load_default_registry()).findings
        if f.detector_id == "us_ssn"
    ]
    assert findings

    outputs = anonymize_files(findings)

    redacted = Path(outputs[str(original)]).read_bytes()
    assert redacted.startswith(codecs.BOM_UTF16_LE)  # still UTF-16
    text = redacted.decode("utf-16")
    assert "123-45-6789" not in text
    assert "*******6789" in text
    assert text.startswith("user ssn = ") and text.endswith(" end\n")


def test_anonymize_cp1252_file_preserves_non_ascii_bytes(tmp_path):
    from redactlens_core.models import ScanRequest
    from redactlens_core.registry import load_default_registry
    from redactlens_core.scanner import scan

    original = tmp_path / "notes.txt"
    original.write_bytes('café ssn = "123-45-6789"\n'.encode("cp1252"))
    findings = [
        f
        for f in scan(ScanRequest(paths=[str(tmp_path)]), load_default_registry()).findings
        if f.detector_id == "us_ssn"
    ]
    assert findings

    outputs = anonymize_files(findings)

    redacted = Path(outputs[str(original)]).read_bytes()
    assert "café".encode("cp1252") in redacted  # é stays the same single byte
    assert b"123-45-6789" not in redacted


@pytest.mark.parametrize(
    ("codec_name", "bom", "prefix"),
    [
        ("utf-8", b"", "café"),
        ("utf-8", codecs.BOM_UTF8, "café"),
        ("utf-16-le", codecs.BOM_UTF16_LE, "snowman ☃"),
        ("utf-16-be", codecs.BOM_UTF16_BE, "snowman ☃"),
        ("utf-32-le", codecs.BOM_UTF32_LE, "snowman ☃"),
        ("utf-32-be", codecs.BOM_UTF32_BE, "snowman ☃"),
        ("cp1252", b"", "café"),
    ],
)
def test_scan_to_remediation_round_trip_preserves_encoding_and_newlines(
    tmp_path,
    codec_name,
    bom,
    prefix,
):
    from redactlens_core.models import ScanRequest
    from redactlens_core.registry import load_default_registry
    from redactlens_core.scanner import scan
    from redactlens_core.textcodec import decode_text

    original = tmp_path / "encoded.txt"
    source = f"{prefix}\r\nssn = 123-45-6789\r\nfinal line\r\n"
    original.write_bytes(bom + source.encode(codec_name))
    result = scan(ScanRequest(paths=[str(original)]), load_default_registry())
    selected = [finding for finding in result.findings if finding.detector_id == "us_ssn"]

    outputs = anonymize_files(selected)
    raw_output = Path(outputs[str(original)]).read_bytes()
    decoded = decode_text(raw_output)

    assert selected
    assert raw_output.startswith(bom) if bom else not raw_output.startswith(codecs.BOM_UTF8)
    assert decoded is not None
    assert decoded[1].name == codec_name
    assert decoded[0] == f"{prefix}\r\nssn = *******6789\r\nfinal line\r\n"


def test_anonymize_files_groups_by_file_and_only_touches_selected_findings(tmp_path):
    a = tmp_path / "a.txt"
    b = tmp_path / "b.txt"
    a.write_text("ssn = 123-45-6789\n")
    b.write_text("ssn = 987-65-4321\n")
    finding_a = _finding(
        file_path=str(a), detector_id="us_ssn", start_offset=6, matched_text="123-45-6789"
    )
    finding_b = _finding(
        file_path=str(b), detector_id="us_ssn", start_offset=6, matched_text="987-65-4321"
    )

    outputs = anonymize_files([finding_a, finding_b])

    assert set(outputs) == {str(a), str(b)}
    assert "123-45-6789" not in Path(outputs[str(a)]).read_text()
    assert "987-65-4321" not in Path(outputs[str(b)]).read_text()
