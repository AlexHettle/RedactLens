import io
import os
import threading
import time
import zipfile
from contextlib import contextmanager
from pathlib import Path

import pytest
from pydantic import ValidationError
from redactlens_core.files import (
    FileIssue,
    Scannable,
    StreamReadStats,
    iter_text_chunks,
    probe_text_file,
)
from redactlens_core.models import ScanOptions, ScanRequest, UserTarget
from redactlens_core.registry import (
    DetectorDef,
    DetectorLoadError,
    DetectorRegistry,
    load_default_registry,
)
from redactlens_core.scanner import scan


def _ssn_registry() -> DetectorRegistry:
    registry = DetectorRegistry()
    registry.add(
        DetectorDef(
            id="bounded_ssn",
            category="personal_id",
            description="Bounded SSN",
            risk_lesson="Test detector",
            method="regex",
            pattern=r"\b\d{3}-\d{2}-\d{4}\b",
            base_confidence=0.9,
            max_match_length=11,
        )
    )
    return registry


def _zip_bytes(entries: dict[str, bytes]) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data in entries.items():
            archive.writestr(name, data)
    return output.getvalue()


def test_chunk_boundary_detection_is_unique_and_preserves_global_location(tmp_path):
    chunk_size = 65_536
    prefix = "row one\n" + ("x" * (chunk_size - 14)) + " "
    assert len(prefix) == chunk_size - 5
    secret = "123-45-6789"
    target = tmp_path / "large.txt"
    target.write_bytes((prefix + secret + "\n").encode())

    result = scan(
        ScanRequest(
            paths=[str(target)],
            options=ScanOptions(chunk_size=chunk_size, max_workers=1),
        ),
        _ssn_registry(),
    )

    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.start_offset == len(prefix)
    assert finding.end_offset == len(prefix) + len(secret)
    assert finding.line == 2
    assert finding.column == len(prefix) - prefix.rfind("\n")
    assert finding.matched_text == secret


def test_declared_lookbehind_context_preserves_materialized_streaming_parity(tmp_path):
    chunk_size = 65_536
    secret = "SECRET"
    target = tmp_path / "lookbehind-boundary.txt"
    target.write_text(("A" * (chunk_size + 50)) + secret)
    registry = DetectorRegistry()
    registry.add(
        DetectorDef(
            id="lookbehind_secret",
            category="custom",
            description="Secret after a fixed prefix",
            risk_lesson="Test detector",
            method="regex",
            pattern=r"(?<=A{200})SECRET",
            base_confidence=0.9,
            max_match_length=len(secret),
            max_lookaround_length=200,
        )
    )

    materialized = scan(
        ScanRequest(
            paths=[str(target)],
            options=ScanOptions(chunk_size=8_388_608, max_workers=1),
        ),
        registry,
    )
    streamed = scan(
        ScanRequest(
            paths=[str(target)],
            options=ScanOptions(chunk_size=chunk_size, max_workers=1),
        ),
        registry,
    )

    assert len(materialized.findings) == len(streamed.findings) == 1
    expected_offset = chunk_size + 50
    assert materialized.findings[0].start_offset == expected_offset
    assert streamed.findings[0].start_offset == expected_offset
    assert materialized.findings[0].model_dump() == streamed.findings[0].model_dump()


def test_detection_budget_is_shared_across_regex_entropy_and_literal_methods(
    monkeypatch,
    tmp_path,
):
    from redactlens_core import scanner as scanner_module

    monkeypatch.setattr(scanner_module, "MAX_FILE_DETECTION_CANDIDATES", 2)
    target = tmp_path / "mixed-methods.txt"
    target.write_text("REG ENTR KEY")
    registry = DetectorRegistry()
    registry.add(
        DetectorDef(
            id="regex_candidate",
            category="custom",
            description="Regex candidate",
            risk_lesson="Test detector",
            method="regex",
            pattern="REG",
            base_confidence=0.9,
            max_match_length=3,
        )
    )
    registry.add(
        DetectorDef(
            id="entropy_candidate",
            category="custom",
            description="Entropy candidate",
            risk_lesson="Test detector",
            method="entropy",
            pattern="ENTR",
            entropy_threshold=0.0,
            base_confidence=0.9,
            max_match_length=4,
        )
    )

    result = scan(
        ScanRequest(
            paths=[str(target)],
            user_targets=[UserTarget(kind="literal", value="KEY", category="custom")],
            options=ScanOptions(max_workers=1),
        ),
        registry,
    )

    assert result.findings == []
    assert result.scanned_files == []
    assert len(result.skipped_files) == 1
    assert result.skipped_files[0].code == "detection_limit"
    assert result.skipped_files[0].stage == "detection"
    assert result.skipped_files[0].reason == "file produced too many candidate detections"


def test_detection_budget_cannot_reset_between_streamed_chunks(monkeypatch, tmp_path):
    from redactlens_core import scanner as scanner_module

    monkeypatch.setattr(scanner_module, "MAX_FILE_DETECTION_CANDIDATES", 3)
    chunk_size = 65_536
    contents = ["x"] * (chunk_size * 2)
    for offset in (10, 1_000, chunk_size + 500, chunk_size + 1_500):
        contents[offset : offset + 3] = "HIT"
    target = tmp_path / "dense-across-chunks.txt"
    target.write_text("".join(contents))
    registry = DetectorRegistry()
    registry.add(
        DetectorDef(
            id="chunk_candidate",
            category="custom",
            description="Chunk candidate",
            risk_lesson="Test detector",
            method="regex",
            pattern="HIT",
            base_confidence=0.9,
            max_match_length=3,
        )
    )

    result = scan(
        ScanRequest(
            paths=[str(target)],
            options=ScanOptions(chunk_size=chunk_size, max_workers=1),
        ),
        registry,
    )

    assert result.findings == []
    assert result.scanned_files == []
    assert len(result.skipped_files) == 1
    assert result.skipped_files[0].code == "detection_limit"


def test_overlap_candidates_do_not_consume_the_file_detection_budget(monkeypatch, tmp_path):
    from redactlens_core import scanner as scanner_module

    monkeypatch.setattr(scanner_module, "MAX_FILE_DETECTION_CANDIDATES", 1)
    chunk_size = 65_536
    target = tmp_path / "one-owned-hit.txt"
    target.write_text(("x" * (chunk_size + 50)) + "HIT")
    registry = DetectorRegistry()
    registry.add(
        DetectorDef(
            id="overlap_candidate",
            category="custom",
            description="Overlap candidate",
            risk_lesson="Test detector",
            method="regex",
            pattern="HIT",
            base_confidence=0.9,
            max_match_length=3,
        )
    )

    result = scan(
        ScanRequest(
            paths=[str(target)],
            options=ScanOptions(chunk_size=chunk_size, max_workers=1),
        ),
        registry,
    )

    assert len(result.findings) == 1
    assert result.findings[0].start_offset == chunk_size + 50
    assert result.skipped_files == []


def test_literal_candidates_observe_the_per_window_engine_budget(monkeypatch, tmp_path):
    from redactlens_core import scanner as scanner_module

    monkeypatch.setattr(scanner_module, "MAX_WINDOW_DETECTION_CANDIDATES", 2)
    target = tmp_path / "dense-literal.txt"
    target.write_text("aaa")

    result = scan(
        ScanRequest(
            paths=[str(target)],
            user_targets=[UserTarget(kind="literal", value="a", category="custom")],
            options=ScanOptions(max_workers=1),
        ),
        DetectorRegistry(),
    )

    assert result.findings == []
    assert result.scanned_files == []
    assert len(result.skipped_files) == 1
    assert result.skipped_files[0].code == "detection_limit"


def test_text_larger_than_five_megabytes_is_streamed_instead_of_skipped(tmp_path):
    target = tmp_path / "large.txt"
    target.write_text(("x" * 5_100_000) + "\n123-45-6789\n")

    result = scan(
        ScanRequest(paths=[str(target)], options=ScanOptions(max_workers=1)),
        _ssn_registry(),
    )

    assert result.scanned_files == [str(target)]
    assert result.skipped_files == []
    assert [finding.matched_text for finding in result.findings] == ["123-45-6789"]
    assert result.summary["bytes_scanned"] == target.stat().st_size


def test_streaming_windows_stay_bounded_independent_of_total_file_size(tmp_path):
    target = tmp_path / "many-chunks.txt"
    target.write_text("a" * 400_000)
    codec, _, issue = probe_text_file(str(target))
    assert issue is None and codec is not None

    stats = StreamReadStats()
    chunks = list(
        iter_text_chunks(
            str(target),
            codec,
            chunk_size=65_536,
            overlap=128,
            stats=stats,
        )
    )

    assert len(chunks) > 5
    assert max(len(chunk.text) for chunk in chunks) <= 65_536 + (2 * 128)
    assert sum(chunk.owned_end - chunk.owned_start for chunk in chunks) == 400_000
    assert stats.bytes_read == target.stat().st_size


def test_default_registry_streaming_core_is_at_least_the_detector_overlap(
    monkeypatch,
    tmp_path,
):
    from redactlens_core import scanner as scanner_module

    target = tmp_path / "default-registry-large.txt"
    target.write_text("x" * 3_300_000)
    real_iter_text_chunks = scanner_module.iter_text_chunks
    iterator_arguments = []
    total_window_characters = 0

    def recording_chunks(*args, **kwargs):
        nonlocal total_window_characters
        iterator_arguments.append((kwargs["chunk_size"], kwargs["overlap"]))
        for chunk in real_iter_text_chunks(*args, **kwargs):
            total_window_characters += len(chunk.text)
            yield chunk

    monkeypatch.setattr(scanner_module, "iter_text_chunks", recording_chunks)
    monkeypatch.setattr(
        scanner_module,
        "_find_candidates",
        lambda _detector, _text, **_kwargs: [],
    )

    result = scan(
        ScanRequest(
            paths=[str(target)],
            categories=["personal_id"],
            options=ScanOptions(chunk_size=65_536, max_workers=1),
        ),
        load_default_registry(),
    )

    assert result.scanned_files == [str(target)]
    assert iterator_arguments
    assert all(chunk_size >= overlap for chunk_size, overlap in iterator_arguments)
    assert total_window_characters <= target.stat().st_size * 4


def test_streaming_second_pass_rejects_growth_beyond_max_file_size(monkeypatch, tmp_path):
    from redactlens_core import scanner as scanner_module

    target = tmp_path / "growing.txt"
    target.write_text("x" * 66_000)
    real_probe = scanner_module.probe_text_file

    def probe_then_grow(path, *args, **kwargs):
        result = real_probe(path, *args, **kwargs)
        with Path(path).open("a", encoding="utf-8") as stream:
            stream.write(("y" * 100_000) + " 123-45-6789")
        return result

    monkeypatch.setattr(scanner_module, "probe_text_file", probe_then_grow)
    result = scan(
        ScanRequest(
            paths=[str(target)],
            options=ScanOptions(
                chunk_size=65_536,
                max_file_size=70_000,
                max_workers=1,
            ),
        ),
        _ssn_registry(),
    )

    assert result.findings == []
    assert result.scanned_files == []
    assert result.summary["bytes_scanned"] == 0
    assert len(result.skipped_files) == 1
    assert result.skipped_files[0].code == "file_too_large"
    assert "70,000" not in result.skipped_files[0].reason  # stable machine-readable number
    assert "70000" in result.skipped_files[0].reason


def test_streaming_validation_pass_bounds_a_growing_file(monkeypatch, tmp_path):
    from redactlens_core import files as files_module

    target = tmp_path / "growing-during-validation.txt"
    target.write_text("x" * 66_000)
    real_open = files_module._open_regular_binary_no_follow
    open_count = 0
    validation_bytes = 0

    @contextmanager
    def grow_during_validation(path, *args, **kwargs):
        nonlocal open_count, validation_bytes
        with real_open(path, *args, **kwargs) as stream:
            open_count += 1
            if open_count != 2:
                yield stream
                return

            class GrowingStream:
                def read(self, amount=-1):
                    nonlocal validation_bytes
                    raw = stream.read(amount)
                    validation_bytes += len(raw)
                    if validation_bytes == len(raw):
                        with Path(path).open("ab") as writer:
                            writer.write(b"y" * 100_000)
                    return raw

                def __getattr__(self, name):
                    return getattr(stream, name)

            yield GrowingStream()

    monkeypatch.setattr(files_module, "_open_regular_binary_no_follow", grow_during_validation)
    result = scan(
        ScanRequest(
            paths=[str(target)],
            options=ScanOptions(chunk_size=65_536, max_file_size=70_000, max_workers=1),
        ),
        _ssn_registry(),
    )

    assert result.scanned_files == []
    assert result.skipped_files[0].code == "file_too_large"
    assert result.skipped_files[0].stage == "extraction"
    assert validation_bytes == 70_001


def test_streaming_validation_pass_observes_extraction_timeout(monkeypatch, tmp_path):
    from redactlens_core import files as files_module
    from redactlens_core.progress import ScanExecution

    target = tmp_path / "slow-validation.txt"
    target.write_text("x" * 70_000)
    real_open = files_module._open_regular_binary_no_follow
    open_count = 0
    now = [0.0]

    @contextmanager
    def delay_validation(path, *args, **kwargs):
        nonlocal open_count
        with real_open(path, *args, **kwargs) as stream:
            open_count += 1
            if open_count != 2:
                yield stream
                return

            class DelayedStream:
                def read(self, amount=-1):
                    raw = stream.read(amount)
                    now[0] = 2.0
                    return raw

                def __getattr__(self, name):
                    return getattr(stream, name)

            yield DelayedStream()

    monkeypatch.setattr(files_module, "_open_regular_binary_no_follow", delay_validation)
    result = scan(
        ScanRequest(
            paths=[str(target)],
            options=ScanOptions(chunk_size=65_536, max_workers=1),
        ),
        _ssn_registry(),
        execution=ScanExecution(extraction_timeout_seconds=1.0, clock=lambda: now[0]),
    )

    assert result.scanned_files == []
    assert result.skipped_files[0].code == "extraction_timeout"
    assert result.skipped_files[0].stage == "extraction"


def test_streaming_validation_pass_distinguishes_source_change(monkeypatch, tmp_path):
    from redactlens_core import files as files_module

    target = tmp_path / "changed-during-validation.txt"
    target.write_text("x" * 66_000)
    real_open = files_module._open_regular_binary_no_follow
    open_count = 0
    changed = False

    @contextmanager
    def change_during_validation(path, *args, **kwargs):
        nonlocal open_count, changed
        with real_open(path, *args, **kwargs) as stream:
            open_count += 1
            if open_count != 2:
                yield stream
                return

            class ChangedStream:
                def read(self, amount=-1):
                    nonlocal changed
                    raw = stream.read(amount)
                    if not changed:
                        changed = True
                        with Path(path).open("ab") as writer:
                            writer.write(b"still within the configured ceiling")
                    return raw

                def __getattr__(self, name):
                    return getattr(stream, name)

            yield ChangedStream()

    monkeypatch.setattr(files_module, "_open_regular_binary_no_follow", change_during_validation)
    result = scan(
        ScanRequest(
            paths=[str(target)],
            options=ScanOptions(chunk_size=65_536, max_file_size=100_000, max_workers=1),
        ),
        _ssn_registry(),
    )

    assert result.scanned_files == []
    assert result.skipped_files[0].code == "read_failed"
    assert result.skipped_files[0].reason == "file changed while it was being scanned"


def test_streaming_validation_pass_keeps_invalid_encoding_distinct(tmp_path):
    target = tmp_path / "invalid-utf16.txt"
    target.write_bytes(b"\xff\xfe" + (b"A\x00" * 33_000) + b"A")

    result = scan(
        ScanRequest(
            paths=[str(target)],
            options=ScanOptions(chunk_size=65_536, max_workers=1),
        ),
        _ssn_registry(),
    )

    assert result.scanned_files == []
    assert result.skipped_files[0].code == "invalid_encoding"
    assert result.skipped_files[0].stage == "extraction"


def test_streaming_second_pass_rejects_bounded_source_change(monkeypatch, tmp_path):
    from redactlens_core import scanner as scanner_module

    target = tmp_path / "changed.txt"
    target.write_text("x" * 66_000)
    real_probe = scanner_module.probe_text_file

    def probe_then_change(path, *args, **kwargs):
        result = real_probe(path, *args, **kwargs)
        with Path(path).open("a", encoding="utf-8") as stream:
            stream.write("still below the configured ceiling")
        return result

    monkeypatch.setattr(scanner_module, "probe_text_file", probe_then_change)
    result = scan(
        ScanRequest(
            paths=[str(target)],
            options=ScanOptions(
                chunk_size=65_536,
                max_file_size=100_000,
                max_workers=1,
            ),
        ),
        _ssn_registry(),
    )

    assert result.scanned_files == []
    assert result.summary["bytes_scanned"] == 0
    assert result.skipped_files[0].code == "read_failed"
    assert result.skipped_files[0].reason == "file changed while it was being scanned"


def test_streaming_second_pass_rejects_same_size_entry_replacement(monkeypatch, tmp_path):
    from redactlens_core import scanner as scanner_module

    target = tmp_path / "replaced.txt"
    original = "x" * 66_000
    replacement = ("y" * (len(original) - 12)) + " 123-45-6789"
    assert len(replacement.encode()) == len(original.encode())
    target.write_text(original)
    real_probe = scanner_module.probe_text_file

    def probe_then_replace(path, *args, **kwargs):
        probe = real_probe(path, *args, **kwargs)
        substitute = tmp_path / "substitute.txt"
        substitute.write_text(replacement)
        os.replace(substitute, target)
        return probe

    monkeypatch.setattr(scanner_module, "probe_text_file", probe_then_replace)

    result = scan(
        ScanRequest(
            paths=[str(target)],
            options=ScanOptions(chunk_size=65_536, max_workers=1),
        ),
        _ssn_registry(),
    )

    assert result.findings == []
    assert result.scanned_files == []
    assert result.summary["bytes_scanned"] == 0
    assert result.skipped_files[0].code == "read_failed"
    assert result.skipped_files[0].reason == "file changed while it was being scanned"


def test_streaming_extraction_timeout_applies_before_chunk_detection(monkeypatch, tmp_path):
    from redactlens_core import scanner as scanner_module
    from redactlens_core.progress import ScanExecution

    target = tmp_path / "slow-stream.txt"
    target.write_text(("x" * 70_000) + " 123-45-6789")
    now = [0.0]
    real_iter = scanner_module.iter_text_chunks

    def delayed_iter(*args, **kwargs):
        for chunk in real_iter(*args, **kwargs):
            now[0] = 2.0
            yield chunk

    monkeypatch.setattr(scanner_module, "iter_text_chunks", delayed_iter)
    result = scan(
        ScanRequest(
            paths=[str(target)],
            options=ScanOptions(chunk_size=65_536, max_workers=1),
        ),
        _ssn_registry(),
        execution=ScanExecution(
            extraction_timeout_seconds=1.0,
            clock=lambda: now[0],
        ),
    )

    assert result.findings == []
    assert result.scanned_files == []
    assert result.skipped_files[0].code == "extraction_timeout"
    assert result.summary["detection_seconds"] == 0


def test_streaming_io_time_is_accounted_as_extraction_not_detection(monkeypatch, tmp_path):
    from redactlens_core import scanner as scanner_module

    target = tmp_path / "timed-stream.txt"
    target.write_text("x" * 70_000)
    real_iter = scanner_module.iter_text_chunks

    def delayed_iter(*args, **kwargs):
        for chunk in real_iter(*args, **kwargs):
            time.sleep(0.02)
            yield chunk

    monkeypatch.setattr(scanner_module, "iter_text_chunks", delayed_iter)
    result = scan(
        ScanRequest(
            paths=[str(target)],
            options=ScanOptions(chunk_size=65_536, max_workers=1),
        ),
        _ssn_registry(),
    )

    assert result.scanned_files == [str(target)]
    assert result.summary["extraction_seconds"] >= 0.035
    assert result.summary["detection_seconds"] < result.summary["extraction_seconds"]


def test_parallel_completion_cannot_change_result_order(monkeypatch, tmp_path):
    from redactlens_core import scanner as scanner_module

    samples = (("z.txt", "111-22-3333"), ("a.txt", "222-33-4444"))
    for name, secret in samples:
        (tmp_path / name).write_text(secret)
    (tmp_path / "binary.bin").write_bytes(b"\x00\x01\x02")
    real_process_file = scanner_module._process_file
    condition = threading.Condition()
    schedules = [
        ["z.txt", "binary.bin", "a.txt"],
        ["a.txt", "binary.bin", "z.txt"],
    ]
    active_schedule = schedules[0]
    next_completion = 0
    observed_completions: list[str] = []

    def scheduled_process(path, *args, **kwargs):
        nonlocal next_completion
        outcome = real_process_file(path, *args, **kwargs)
        name = Path(path).name
        with condition:
            assert condition.wait_for(
                lambda: active_schedule[next_completion] == name,
                timeout=2,
            )
            observed_completions.append(name)
            next_completion += 1
            condition.notify_all()
        return outcome

    monkeypatch.setattr(scanner_module, "_process_file", scheduled_process)
    request = ScanRequest(paths=[str(tmp_path)], options=ScanOptions(max_workers=3))

    first = scan(request, _ssn_registry())
    assert observed_completions == schedules[0]
    active_schedule = schedules[1]
    next_completion = 0
    observed_completions.clear()
    second = scan(request, _ssn_registry())
    assert observed_completions == schedules[1]

    expected_scanned = [str(tmp_path / "a.txt"), str(tmp_path / "z.txt")]
    expected_skipped = [str(tmp_path / "binary.bin")]
    assert first.scanned_files == second.scanned_files == expected_scanned
    assert [item.path for item in first.skipped_files] == expected_skipped
    assert [item.model_dump() for item in first.skipped_files] == [
        item.model_dump() for item in second.skipped_files
    ]
    assert [finding.file_path for finding in first.findings] == expected_scanned
    assert [finding.model_dump() for finding in first.findings] == [
        finding.model_dump() for finding in second.findings
    ]
    for key in (
        "files_scanned",
        "files_skipped",
        "total_findings",
        "raw_detector_hits",
        "canonical_findings",
    ):
        assert first.summary[key] == second.summary[key]


def test_file_worker_parallelism_is_bounded(monkeypatch, tmp_path):
    from redactlens_core import scanner as scanner_module

    for index in range(6):
        (tmp_path / f"{index}.txt").write_text(f"123-45-67{index:02d}")
    real_read = scanner_module.read_scannable_detailed
    lock = threading.Lock()
    active = 0
    maximum = 0

    def observed_read(path, *args, **kwargs):
        nonlocal active, maximum
        with lock:
            active += 1
            maximum = max(maximum, active)
        try:
            time.sleep(0.03)
            return real_read(path, *args, **kwargs)
        finally:
            with lock:
                active -= 1

    monkeypatch.setattr(scanner_module, "read_scannable_detailed", observed_read)
    scan(
        ScanRequest(paths=[str(tmp_path)], options=ScanOptions(max_workers=2)),
        _ssn_registry(),
    )

    assert maximum == 2


def test_document_extraction_has_its_own_lower_concurrency_limit(monkeypatch, tmp_path):
    from redactlens_core import scanner as scanner_module

    for index in range(4):
        (tmp_path / f"{index}.pdf").write_bytes(b"%PDF fake")
    lock = threading.Lock()
    active = 0
    maximum = 0

    def fake_extract(*_args, **_kwargs):
        nonlocal active, maximum
        with lock:
            active += 1
            maximum = max(maximum, active)
        try:
            time.sleep(0.03)
            return Scannable("123-45-6789"), None
        finally:
            with lock:
                active -= 1

    monkeypatch.setattr(scanner_module, "read_scannable_detailed", fake_extract)
    scan(
        ScanRequest(
            paths=[str(tmp_path)],
            options=ScanOptions(max_workers=4, document_workers=1),
        ),
        _ssn_registry(),
    )

    assert maximum == 1


def test_one_unexpected_file_failure_is_isolated_and_structured(monkeypatch, tmp_path):
    from redactlens_core import scanner as scanner_module

    good = tmp_path / "good.txt"
    bad = tmp_path / "bad.txt"
    good.write_text("123-45-6789")
    bad.write_text("broken")
    real_read = scanner_module.read_scannable_detailed

    def sometimes_broken(path, *args, **kwargs):
        if Path(path).name == "bad.txt":
            raise RuntimeError("simulated parser bug")
        return real_read(path, *args, **kwargs)

    monkeypatch.setattr(scanner_module, "read_scannable_detailed", sometimes_broken)
    result = scan(ScanRequest(paths=[str(tmp_path)]), _ssn_registry())

    assert result.scanned_files == [str(good)]
    assert len(result.findings) == 1
    assert len(result.skipped_files) == 1
    skipped = result.skipped_files[0]
    assert skipped.path == str(bad)
    assert skipped.code == "file_processing_failed"
    assert skipped.stage == "extraction"


@pytest.mark.parametrize(
    ("reason", "expected_code"),
    [
        (
            "filesystem redirect skipped — scan the real target explicitly if you trust it",
            "filesystem_redirect",
        ),
        ("non-regular filesystem entry skipped", "non_regular_file"),
    ],
)
def test_entry_type_changes_remain_structured_during_file_processing(
    monkeypatch, tmp_path, reason, expected_code
):
    from redactlens_core import scanner as scanner_module

    target = tmp_path / "changed-entry.txt"
    target.write_text("ordinary")
    monkeypatch.setattr(
        scanner_module,
        "read_scannable_detailed",
        lambda *_args, **_kwargs: (
            None,
            FileIssue(expected_code, "extraction", reason),
        ),
    )

    result = scan(ScanRequest(paths=[str(target)]), _ssn_registry())

    assert result.scanned_files == []
    assert len(result.skipped_files) == 1
    assert result.skipped_files[0].code == expected_code
    assert result.skipped_files[0].stage == "extraction"


@pytest.mark.parametrize("payload_size", [64, 70_000])
def test_unsupported_binary_code_is_stable_across_small_and_streamed_files(tmp_path, payload_size):
    target = tmp_path / f"legacy-{payload_size}.doc"
    magic = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
    target.write_bytes(magic + (b"\x00" * (payload_size - len(magic))))

    result = scan(
        ScanRequest(
            paths=[str(target)],
            options=ScanOptions(chunk_size=65_536, max_workers=1),
        ),
        _ssn_registry(),
    )

    assert result.scanned_files == []
    assert result.skipped_files[0].code == "unsupported_binary"
    assert result.skipped_files[0].stage == "extraction"


def test_redactlensignore_supports_negation_and_explains_the_matching_rule(tmp_path):
    (tmp_path / ".redactlensignore").write_text("*.log\n!important.log\ncache/\n")
    (tmp_path / "debug.log").write_text("123-45-6789")
    (tmp_path / "important.log").write_text("123-45-6789")
    cache = tmp_path / "cache"
    cache.mkdir()
    (cache / "secret.txt").write_text("123-45-6789")

    result = scan(ScanRequest(paths=[str(tmp_path)]), _ssn_registry())

    assert result.scanned_files == [str(tmp_path / "important.log")]
    ignored = {Path(item.path).name: item for item in result.skipped_files}
    assert ignored["debug.log"].code == "ignored_by_rule"
    assert ignored["debug.log"].stage == "discovery"
    assert ignored["debug.log"].rule.endswith(".redactlensignore:1: *.log")
    assert ignored["secret.txt"].rule.endswith(".redactlensignore:3: cache/")


def test_extension_filters_and_archive_depth_are_request_configurable(tmp_path):
    (tmp_path / "ignored.py").write_text("123-45-6789")
    nested = _zip_bytes({"inside.txt": b"123-45-6789"})
    archive = tmp_path / "outer.zip"
    archive.write_bytes(_zip_bytes({"nested.zip": nested}))

    shallow = scan(
        ScanRequest(
            paths=[str(tmp_path)],
            options=ScanOptions(included_extensions=["zip"], archive_depth=1),
        ),
        _ssn_registry(),
    )
    deep = scan(
        ScanRequest(
            paths=[str(tmp_path)],
            options=ScanOptions(included_extensions=[".zip"], archive_depth=2),
        ),
        _ssn_registry(),
    )

    assert any(item.code == "extension_not_included" for item in shallow.skipped_files)
    assert any(item.code == "archive_limit" for item in shallow.skipped_files)
    assert deep.scanned_files == [str(archive)]
    assert len(deep.findings) == 1


def test_multi_dot_extension_filters_match_the_full_filename(tmp_path):
    target = tmp_path / "bundle.min.js"
    target.write_text("123-45-6789")

    excluded = scan(
        ScanRequest(
            paths=[str(target)],
            options=ScanOptions(excluded_extensions=[".min.js"]),
        ),
        _ssn_registry(),
    )
    included = scan(
        ScanRequest(
            paths=[str(target)],
            options=ScanOptions(included_extensions=[".min.js"]),
        ),
        _ssn_registry(),
    )

    assert excluded.scanned_files == []
    assert excluded.skipped_files[0].code == "excluded_extension"
    assert excluded.skipped_files[0].rule == "excluded_extensions:.min.js"
    assert included.scanned_files == [str(target)]
    assert len(included.findings) == 1


def test_scan_summary_contains_local_performance_regression_metrics(tmp_path):
    target = tmp_path / "data.txt"
    target.write_text("123-45-6789")
    summary = scan(ScanRequest(paths=[str(target)]), _ssn_registry()).summary

    assert summary["duration_ms"] >= 0
    assert summary["bytes_scanned"] == target.stat().st_size
    assert summary["files_per_second"] > 0
    assert summary["megabytes_per_second"] > 0
    assert summary["extraction_seconds"] >= 0
    assert summary["detection_seconds"] >= 0
    assert summary["llm_seconds"] == 0
    assert summary["peak_memory_bytes"] is None or summary["peak_memory_bytes"] > 0


def test_scan_options_normalize_scope_values_and_reject_conflicts():
    options = ScanOptions(
        ignored_directories=["vendor", "vendor"],
        included_extensions=["TXT", ".md"],
    )
    assert options.ignored_directories == ["vendor"]
    assert options.included_extensions == [".md", ".txt"]

    with pytest.raises(ValidationError, match="both included and excluded"):
        ScanOptions(included_extensions=["txt"], excluded_extensions=[".txt"])
    with pytest.raises(ValidationError, match="cannot exceed"):
        ScanOptions(max_workers=1, document_workers=2)


def test_default_registry_is_cached_validated_and_immutable():
    first = load_default_registry()
    second = load_default_registry()
    assert first is second
    assert first.frozen is True
    with pytest.raises(DetectorLoadError, match="immutable"):
        first.add(
            DetectorDef(
                id="late",
                category="custom",
                description="late",
                risk_lesson="late",
                method="keyword",
                pattern="late",
                base_confidence=0.5,
            )
        )


def test_builtin_detectors_have_a_local_adversarial_performance_budget(tmp_path):
    target = tmp_path / "adversarial.txt"
    target.write_text(("A" * 1_000_000) + "!")

    started = time.perf_counter()
    scan(
        ScanRequest(paths=[str(target)], options=ScanOptions(max_workers=1)),
        load_default_registry(),
    )
    elapsed = time.perf_counter() - started

    assert elapsed < 5.0
