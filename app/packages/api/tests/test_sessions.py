import os
import threading
import time
from dataclasses import replace
from pathlib import Path

import pytest
import redactlens_api.session_files as session_files_module
import redactlens_api.sessions as sessions_module
import redactlens_core.scanner as scanner_module
from redactlens_api.sessions import (
    FileFingerprint,
    ScanSessionStore,
    SessionProblem,
    generate_remediation_outputs,
    remediation_plan,
    session_file_for_finding,
    session_redacted_output_for_finding,
    update_remediation_plan,
    verify_source_files,
)
from redactlens_core import atomic
from redactlens_core.llm.adapter import LLMVerdict
from redactlens_core.models import ScanOptions, ScanRequest, ScanResult, SkippedFile, UserTarget
from redactlens_core.progress import ScanEvent
from redactlens_core.registry import load_default_registry
from redactlens_core.scanner import scan


class FakeClock:
    def __init__(self, value: float = 1_700_000_000.0) -> None:
        self.value = value

    def __call__(self) -> float:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += seconds


def test_background_job_scans_absolute_paths_for_relative_browser_input(monkeypatch, tmp_path):
    target = tmp_path / "scan-root"
    target.mkdir()
    (target / "ordinary.txt").write_text("ordinary text\n")
    monkeypatch.chdir(tmp_path)
    observed_paths: list[str] = []

    def scanner(request, _registry, **_kwargs):
        observed_paths.extend(request.paths)
        return ScanResult()

    store = ScanSessionStore(id_factory=lambda: "scan-id")
    session = store.create_pending(ScanRequest(paths=[target.name]))
    store.start_job(session, scanner=scanner)
    assert session.worker_thread is not None
    session.worker_thread.join(timeout=2)

    assert observed_paths == [os.path.abspath(target.name)]
    assert session.selected_roots == (os.path.abspath(target.name),)


def test_background_job_shares_cancellation_lock_with_core_submission(tmp_path):
    target = tmp_path / "ordinary.txt"
    target.write_text("ordinary text\n")
    observed_guards = []

    def scanner(_request, _registry, *, execution, **_kwargs):
        assert execution.submission_guard is not None
        observed_guards.append(execution.submission_guard())
        return ScanResult()

    store = ScanSessionStore(id_factory=lambda: "scan-id")
    session = store.create_pending(ScanRequest(paths=[str(target)]))
    store.start_job(session, scanner=scanner)
    assert session.worker_thread is not None
    session.worker_thread.join(timeout=2)

    assert observed_guards == [session.workflow_lock]


def test_background_job_does_not_resolve_a_selected_filesystem_link(monkeypatch, tmp_path):
    target = tmp_path / "target.txt"
    target.write_text("outside selection")
    selected = tmp_path / "selected-link.txt"
    try:
        selected.symlink_to(target)
    except (NotImplementedError, OSError) as error:
        pytest.skip(f"symlinks are unavailable in this environment: {error}")
    monkeypatch.chdir(tmp_path)
    observed_paths: list[str] = []

    def scanner(request, _registry, **_kwargs):
        observed_paths.extend(request.paths)
        return ScanResult()

    store = ScanSessionStore(id_factory=lambda: "scan-id")
    session = store.create_pending(ScanRequest(paths=[selected.name]))
    store.start_job(session, scanner=scanner)
    assert session.worker_thread is not None
    session.worker_thread.join(timeout=2)

    assert observed_paths == [os.path.abspath(selected.name)]
    assert observed_paths != [str(target.resolve())]
    assert session.selected_roots == (os.path.abspath(selected.name),)


def test_background_path_normalization_never_calls_path_resolve(monkeypatch, tmp_path):
    selected = tmp_path / "selected-entry"
    monkeypatch.chdir(tmp_path)
    observed_paths: list[str] = []

    def forbidden_resolve(_path, *_args, **_kwargs):
        raise AssertionError("selected paths must not be dereferenced")

    def scanner(request, _registry, **_kwargs):
        observed_paths.extend(request.paths)
        return ScanResult()

    monkeypatch.setattr(Path, "resolve", forbidden_resolve)
    store = ScanSessionStore(id_factory=lambda: "scan-id")
    session = store.create_pending(ScanRequest(paths=[selected.name]))
    store.start_job(session, scanner=scanner)
    assert session.worker_thread is not None
    session.worker_thread.join(timeout=2)

    assert observed_paths == [os.path.abspath(selected.name)]
    assert session.selected_roots == (os.path.abspath(selected.name),)


def test_input_fingerprint_discovery_receives_cancellation_checkpoint(monkeypatch, tmp_path):
    checkpoints = 0

    def checkpoint() -> None:
        nonlocal checkpoints
        checkpoints += 1

    def discover(_paths, _options, *, checkpoint):
        assert checkpoint is not None
        checkpoint()
        return iter(())

    monkeypatch.setattr(sessions_module, "discover_files", discover)

    assert (
        sessions_module.capture_scan_input_fingerprints(
            [str(tmp_path)],
            checkpoint=checkpoint,
        )
        == {}
    )
    assert checkpoints == 1


def test_available_ai_with_zero_inference_attempts_is_not_published_as_used(monkeypatch, tmp_path):
    target = tmp_path / "ordinary.txt"
    target.write_text("ordinary public documentation\n")

    class AvailableAdapter:
        model = "local-test-model"

        def __init__(self, **_kwargs):
            pass

        def available(self):
            return True

        def judge(self, _question):  # pragma: no cover - a call fails the test directly
            raise AssertionError("clean scan should not cross the model boundary")

    monkeypatch.setattr(sessions_module, "OllamaAdapter", AvailableAdapter)
    store = ScanSessionStore(id_factory=lambda: "scan-id")
    session = store.create_pending(ScanRequest(paths=[str(target)], use_llm=True))
    store.start_job(session)
    assert session.worker_thread is not None
    session.worker_thread.join(timeout=2)

    snapshot = session.response()
    assert snapshot.state == "complete"
    assert snapshot.llm_used is False
    assert snapshot.summary["llm_attempts"] == 0
    assert snapshot.metadata.ai_model is None


def test_ai_description_finding_can_generate_a_verified_redacted_copy(monkeypatch, tmp_path):
    target = tmp_path / "record.txt"
    sensitive_passage = "employee id: EMP-99213"
    target.write_text(f"{sensitive_passage}\nunrelated line stays intact\n")

    class DescriptionAdapter:
        model = "local-test-model"

        def __init__(self, **_kwargs):
            pass

        def available(self):
            return True

        def judge(self, question):
            matched = (
                "The user told RedactLens to watch for:" in question
                and sensitive_passage in question
            )
            return LLMVerdict(
                is_sensitive=matched,
                confidence=0.95 if matched else 0.05,
                reason="matches the requested employee identifier" if matched else "not a match",
            )

    monkeypatch.setattr(sessions_module, "OllamaAdapter", DescriptionAdapter)
    store = ScanSessionStore(id_factory=lambda: "scan-id")
    session = store.create_pending(
        ScanRequest(
            paths=[str(target)],
            use_llm=True,
            user_targets=[
                UserTarget(kind="description", value="an employee identifier", category="custom")
            ],
        )
    )
    store.start_job(session)
    assert session.worker_thread is not None
    session.worker_thread.join(timeout=2)

    snapshot = session.response()
    finding = next(item for item in snapshot.findings if item.detector_id == "user_target_desc_0")
    assert snapshot.state == "complete"
    assert finding.can_anonymize is True

    update_remediation_plan(session, [finding.id], [])
    generated = generate_remediation_outputs(session)
    output_path = Path(generated.outputs[0].output_path)

    assert generated.outputs[0].verification_status == "verified"
    assert sensitive_passage in target.read_text()
    assert sensitive_passage not in output_path.read_text()
    assert "unrelated line stays intact" in output_path.read_text()


@pytest.mark.parametrize(
    ("requested_timeout", "server_timeout", "expected_timeout"),
    [(1.5, 3.0, 1.5), (10.0, 3.0, 3.0)],
)
def test_background_job_applies_request_ai_timeout_with_server_ceiling(
    monkeypatch, tmp_path, requested_timeout, server_timeout, expected_timeout
):
    target = tmp_path / "ordinary.txt"
    target.write_text("ordinary public documentation\n")
    observed_timeouts: list[float] = []
    observed_models: list[str] = []

    class CapturingAdapter:
        model = "local-test-model"

        def __init__(self, *, model, timeout, **_kwargs):
            observed_models.append(model)
            observed_timeouts.append(timeout)

    monkeypatch.setattr(sessions_module, "OllamaAdapter", CapturingAdapter)
    store = ScanSessionStore(
        id_factory=lambda: "scan-id",
        llm_call_timeout_seconds=server_timeout,
    )
    session = store.create_pending(
        ScanRequest(
            paths=[str(target)],
            ollama_model="selected-local-model:7b",
            options=ScanOptions(ai_timeout_seconds=requested_timeout),
        )
    )
    store.start_job(session, scanner=lambda *_args, **_kwargs: ScanResult())
    assert session.worker_thread is not None
    session.worker_thread.join(timeout=2)

    assert observed_timeouts == [expected_timeout]
    assert observed_models == ["selected-local-model:7b"]


def test_active_session_bounds_events_and_releases_request_on_finish(tmp_path):
    request = ScanRequest(paths=[str(tmp_path)])
    store = ScanSessionStore(max_events=2, id_factory=lambda: "scan-id")
    session = store.create_pending(request)

    session.apply_core_event(ScanEvent(type="scan_started", stage="discovery"))
    session.apply_core_event(ScanEvent(type="discovery_complete", stage="discovery", total_files=1))
    session.apply_core_event(
        ScanEvent(type="file_started", stage="extraction", file_path="example.py", total_files=1)
    )

    assert [event.sequence for event in session.events] == [2, 3]
    assert session.response().event_cursor == 3
    assert session.request is not None

    session.finish(
        ScanResult(
            summary={
                "status": "complete",
                "incomplete": False,
                "completed_files": 1,
                "total_files": 1,
            }
        ),
        state="complete",
    )

    assert [event.sequence for event in session.events] == [3, 4]
    assert session.events[-1].type == "scan_completed"
    assert session.response().event_cursor == 4
    assert session.request is None


def test_accepted_cancellation_cannot_be_overwritten_by_late_completion(monkeypatch, tmp_path):
    finish_entered = threading.Event()
    release_finish = threading.Event()
    store = ScanSessionStore(id_factory=lambda: "scan-id")
    session = store.create_pending(ScanRequest(paths=[str(tmp_path)]))
    original_finish = store._finish_job

    def delayed_finish(active_session, result, **kwargs):
        finish_entered.set()
        release_finish.wait(timeout=5)
        original_finish(active_session, result, **kwargs)

    monkeypatch.setattr(store, "_finish_job", delayed_finish)
    completed = ScanResult(
        summary={
            "status": "complete",
            "incomplete": False,
            "completed_files": 0,
            "total_files": 0,
        }
    )
    store.start_job(session, scanner=lambda *_args, **_kwargs: completed)
    assert finish_entered.wait(timeout=2)

    try:
        assert store.delete(session.scan_id) is True
        assert session.scan_state == "cancelling"
    finally:
        release_finish.set()
        assert session.worker_thread is not None
        session.worker_thread.join(timeout=2)

    snapshot = session.response()
    assert snapshot.state == "cancelled"
    assert snapshot.summary["status"] == "cancelled"
    assert snapshot.summary["incomplete"] is True
    assert snapshot.error is not None
    assert snapshot.error.code == "scan_cancelled"
    assert session.events[-1].type == "scan_cancelled"
    assert all(event.type != "scan_completed" for event in session.events)


def test_finalizing_event_remains_nonterminal_and_visible_in_progress(tmp_path):
    session = ScanSessionStore(id_factory=lambda: "scan-id").create_pending(
        ScanRequest(paths=[str(tmp_path)])
    )

    session.apply_core_event(
        ScanEvent(
            type="scan_finalizing",
            stage="finalizing",
            completed_files=1,
            total_files=1,
        )
    )

    assert session.scan_state == "scanning"
    assert session.terminal is False
    assert session.progress.stage == "finalizing"
    assert session.events[-1].type == "scan_finalizing"


@pytest.mark.parametrize("state", ["cancelled", "timed_out", "failed"])
def test_non_complete_finish_normalizes_summary_and_drops_raw_action_state(tmp_path, state):
    path = tmp_path / "secrets.py"
    raw_secret = "123-45-6789"
    path.write_text(f'ssn = "{raw_secret}"\n')
    request, result = _scan_file(path)
    store = ScanSessionStore(id_factory=lambda: "scan-id")
    session = store.create_pending(request)
    fingerprint = FileFingerprint.capture(str(path))

    session.finish(result, state=state, fingerprints={str(path): fingerprint})
    snapshot = session.response()

    assert snapshot.state == state
    assert snapshot.summary["status"] == state
    assert snapshot.summary["incomplete"] is True
    assert snapshot.findings
    assert raw_secret not in snapshot.model_dump_json()
    assert session.internal_findings == {}
    assert session.file_fingerprints == {}
    assert session.remediation_states == {}
    assert session.request is None


def test_unexpected_scanner_failure_keeps_redacted_event_partial(tmp_path):
    path = tmp_path / "secrets.py"
    raw_secret = "123-45-6789"
    path.write_text(f'ssn = "{raw_secret}"\n')
    request, result = _scan_file(path)
    skipped = SkippedFile(
        path=str(tmp_path / "unreadable.txt"),
        reason="simulated extraction failure",
        code="extraction_failed",
    )
    store = ScanSessionStore(id_factory=lambda: "scan-id")
    session = store.create_pending(request)

    def scanner(*_args, execution, **_kwargs):
        execution.emit(
            ScanEvent(
                type="finding_added",
                stage="consolidation",
                finding=result.findings[0],
                completed_files=0,
                total_files=2,
                findings_so_far=1,
            )
        )
        execution.emit(
            ScanEvent(
                type="file_completed",
                stage="extraction",
                file_path=str(path),
                completed_files=1,
                total_files=2,
                findings_so_far=1,
            )
        )
        execution.emit(
            ScanEvent(
                type="file_skipped",
                stage="extraction",
                skipped_file=skipped,
                completed_files=2,
                total_files=2,
                findings_so_far=1,
                skipped_files=1,
            )
        )
        raise RuntimeError(f"failure containing {raw_secret}")

    store.start_job(session, scanner=scanner)
    assert session.worker_thread is not None
    session.worker_thread.join(timeout=2)

    snapshot = session.response()
    assert snapshot.state == "failed"
    assert snapshot.summary == {
        "status": "failed",
        "incomplete": True,
        "completed_files": 2,
        "total_files": 2,
    }
    assert [finding.id for finding in snapshot.findings] == [result.findings[0].id]
    assert len(snapshot.scanned_files) == 1
    assert snapshot.scanned_files[0].startswith("Scan file ")
    assert len(snapshot.skipped_files) == 1
    assert snapshot.skipped_files[0].path.startswith("Scan file ")
    assert snapshot.skipped_files[0].reason == skipped.reason
    assert snapshot.progress.stage == "failed"
    assert snapshot.progress.completed_files == 2
    assert snapshot.progress.findings_so_far == 1
    assert snapshot.error is not None
    assert snapshot.error.code == "scan_failed"
    assert snapshot.event_cursor == session.events[-1].sequence
    assert session.events[-1].type == "scan_failed"
    assert session.internal_findings == {}
    assert session.file_fingerprints == {}
    assert session.remediation_states == {}
    assert session.request is None
    assert raw_secret not in snapshot.model_dump_json()
    assert raw_secret not in session.public_result.model_dump_json()


def test_post_scan_failure_preserves_llm_used_partial_metadata(monkeypatch, tmp_path):
    path = tmp_path / "secrets.py"
    raw_secret = "123-45-6789"
    path.write_text(f'ssn = "{raw_secret}"\n')
    request, result = _scan_file(path)
    summary = {
        **result.summary,
        "status": "complete",
        "incomplete": False,
        "completed_files": 1,
        "total_files": 1,
        "llm_attempts": 2,
    }
    llm_result = result.model_copy(
        update={
            "summary": summary,
            "llm_used": True,
        },
        deep=True,
    )

    class LocalAdapter:
        model = "local-test-model"

        def __init__(self, **_kwargs):
            pass

    def fail_post_scan_fingerprinting(*_args, **_kwargs):
        raise RuntimeError("simulated post-scan bookkeeping failure")

    def scanner(*_args, execution, **_kwargs):
        execution.emit(
            ScanEvent(
                type="finding_added",
                stage="consolidation",
                finding=llm_result.findings[0],
                completed_files=1,
                total_files=1,
                findings_so_far=1,
            )
        )
        return llm_result

    monkeypatch.setattr(sessions_module, "OllamaAdapter", LocalAdapter)
    monkeypatch.setattr(
        sessions_module,
        "_capture_result_fingerprints",
        fail_post_scan_fingerprinting,
    )
    store = ScanSessionStore(id_factory=lambda: "scan-id")
    session = store.create_pending(request)
    store.start_job(session, scanner=scanner)
    assert session.worker_thread is not None
    session.worker_thread.join(timeout=2)

    snapshot = session.response()
    assert snapshot.state == "failed"
    assert snapshot.summary["status"] == "failed"
    assert snapshot.summary["incomplete"] is True
    assert snapshot.summary["llm_attempts"] == 2
    assert snapshot.llm_used is True
    assert snapshot.metadata.ai_model == "local-test-model"
    assert [finding.id for finding in snapshot.findings] == [llm_result.findings[0].id]
    assert session.internal_findings == {}
    assert raw_secret not in snapshot.model_dump_json()
    assert session.events[-1].type == "scan_failed"


def _scan_file(path: Path):
    request = ScanRequest(paths=[str(path)])
    result = scan(request, load_default_registry())
    assert result.findings
    return request, result


def test_session_separates_internal_raw_finding_from_public_contract(tmp_path):
    path = tmp_path / "secrets.py"
    raw_secret = "123-45-6789"
    path.write_text(f'ssn = "{raw_secret}"\n')
    request, result = _scan_file(path)
    store = ScanSessionStore(id_factory=lambda: "scan-id")

    session = store.create(request, result)

    internal = next(iter(session.internal_findings.values()))
    public = session.public_result.findings[0].model_dump()
    assert internal.matched_text == raw_secret
    assert {"matched_text", "start_offset", "end_offset", "evidence"}.isdisjoint(public)
    assert raw_secret not in session.public_result.model_dump_json()


def test_live_events_keep_future_cross_finding_path_and_location_values_opaque(tmp_path):
    first_raw = "123-45-6789"
    second_raw = "987-65-4321"
    source = tmp_path / "two-findings.txt"
    source.write_text(f"{first_raw}\n{second_raw}\n")
    _request, result = _scan_file(source)
    by_match = {finding.matched_text: finding for finding in result.findings}
    first = by_match[first_raw].model_copy(
        update={
            "file_path": str(tmp_path / f"archive-{second_raw}.xlsx"),
            "location": f"sheet-{second_raw}!A1",
        }
    )
    second = by_match[second_raw]
    future_sensitive_root = tmp_path / f"root-{second_raw}"
    session = ScanSessionStore(id_factory=lambda: "scan-id").create_pending(
        ScanRequest(paths=[str(future_sensitive_root)])
    )

    pending_json = session.response().model_dump_json()
    assert second_raw not in pending_json
    assert session.response().metadata.selected_roots == ["Scan root 1"]

    session.apply_core_event(
        ScanEvent(
            type="finding_added",
            stage="consolidation",
            finding=first,
            findings_so_far=1,
        )
    )
    first_event_json = session.events[-1].model_dump_json()

    assert second_raw not in first_event_json
    assert session.events[-1].finding is not None
    assert session.events[-1].finding.file_path.startswith("Scan file ")
    assert session.events[-1].finding.location is None

    session.apply_core_event(
        ScanEvent(
            type="finding_added",
            stage="consolidation",
            finding=second,
            findings_so_far=2,
        )
    )

    assert second_raw not in session.response().model_dump_json()
    assert all(second_raw not in event.model_dump_json() for event in session.events)

    session.finish(
        ScanResult(),
        state="failed",
        public_partial=session.public_result,
    )
    failed_snapshot = session.response()

    assert second_raw not in failed_snapshot.model_dump_json()
    assert failed_snapshot.metadata.selected_roots != [str(future_sensitive_root)]


def test_raw_match_in_filename_is_redacted_from_remediation_responses(tmp_path):
    raw_secret = "123-45-6789"
    path = tmp_path / f"employee-{raw_secret}.txt"
    path.write_text(f"ssn = {raw_secret}\n")
    request, result = _scan_file(path)
    finding = next(item for item in result.findings if item.detector_id == "us_ssn")
    session = ScanSessionStore(id_factory=lambda: "scan-id").create(request, result)

    plan = update_remediation_plan(session, [finding.id], [])
    generated = generate_remediation_outputs(session)

    assert raw_secret not in session.response().model_dump_json()
    assert raw_secret not in plan.model_dump_json()
    assert raw_secret not in generated.model_dump_json()
    assert session.generated_outputs[str(path)].output_path.endswith("-auto-redacted-copy.txt")
    assert Path(session.generated_outputs[str(path)].output_path).is_file()


def test_path_identity_stays_equal_from_snapshot_through_generation_with_marker_collision(
    tmp_path,
):
    raw_secret = "123-45-6789"
    path = tmp_path / f"employee-{raw_secret}.txt"
    path.write_text(f"ssn = {raw_secret}\n")
    request, result = _scan_file(path)
    finding = next(item for item in result.findings if item.detector_id == "us_ssn")
    literal_marker_path = str(tmp_path / "<sensitive-path-1>.txt")
    result = result.model_copy(
        update={
            "skipped_files": [
                SkippedFile(
                    path=literal_marker_path,
                    reason="simulated skipped marker filename",
                )
            ]
        },
        deep=True,
    )
    session = ScanSessionStore(id_factory=lambda: "scan-id").create(request, result)
    snapshot_path = next(
        item.file_path for item in session.response().findings if item.id == finding.id
    )

    plan = update_remediation_plan(session, [finding.id], [])
    generated = generate_remediation_outputs(session)

    assert snapshot_path != str(path)
    assert snapshot_path == plan.files[0].source_path
    assert snapshot_path == generated.plan.files[0].source_path
    assert snapshot_path == generated.outputs[0].source_path
    assert raw_secret not in generated.model_dump_json()


def test_normalization_colliding_sources_keep_distinct_plan_and_generated_output_paths(
    tmp_path,
):
    sources = [tmp_path / "caf\u00e9.py", tmp_path / "cafe\u0301.py"]
    secrets = ["123-45-6789", "987-65-4321"]
    for source, secret in zip(sources, secrets, strict=True):
        source.write_text(f'ssn = "{secret}"\n')
    request = ScanRequest(paths=[str(tmp_path)])
    result = scan(request, load_default_registry())
    findings = [finding for finding in result.findings if finding.detector_id == "us_ssn"]
    assert len(findings) == 2
    session = ScanSessionStore(id_factory=lambda: "scan-id").create(request, result)
    snapshot_paths = {
        finding.file_path
        for finding in session.response().findings
        if finding.detector_id == "us_ssn"
    }

    plan = update_remediation_plan(session, [finding.id for finding in findings], [])
    generated = generate_remediation_outputs(session)

    assert len(snapshot_paths) == 2
    assert {file.source_path for file in plan.files} == snapshot_paths
    assert len({file.output_path for file in plan.files}) == 2
    assert {output.source_path for output in generated.outputs} == snapshot_paths
    assert len({output.output_path for output in generated.outputs}) == 2
    assert all(Path(output.output_path).is_file() for output in session.generated_outputs.values())


def test_idle_expiration_clears_retained_internal_data(tmp_path):
    path = tmp_path / "secrets.py"
    path.write_text('ssn = "123-45-6789"\n')
    request, result = _scan_file(path)
    clock = FakeClock()
    store = ScanSessionStore(idle_timeout_seconds=30, clock=clock)
    session = store.create(request, result)

    clock.advance(30)
    assert store.prune_expired() == 1

    assert session.internal_findings == {}
    assert session.file_fingerprints == {}
    assert session.selected_roots == ()
    assert session.public_result.findings == []
    assert store.session_count == 0


def test_wall_clock_rollback_does_not_extend_idle_or_active_retention(tmp_path):
    elapsed = FakeClock(100.0)
    wall = FakeClock(1_700_000_000.0)
    idle_store = ScanSessionStore(
        idle_timeout_seconds=30,
        clock=elapsed,
        wall_clock=wall,
    )
    idle = idle_store.create(ScanRequest(paths=[str(tmp_path)]), ScanResult())

    wall.advance(-3_600)
    elapsed.advance(30)

    assert idle_store.prune_expired() == 1
    assert idle.discarded is True

    active_elapsed = FakeClock(200.0)
    active_wall = FakeClock(1_700_000_000.0)
    started = threading.Event()
    release = threading.Event()
    active_store = ScanSessionStore(
        idle_timeout_seconds=5,
        max_sessions=1,
        job_timeout_seconds=10,
        extraction_timeout_seconds=2,
        llm_call_timeout_seconds=3,
        clock=active_elapsed,
        wall_clock=active_wall,
    )
    active = active_store.create_pending(ScanRequest(paths=[str(tmp_path)]))

    def blocked_scanner(*_args, **_kwargs):
        started.set()
        release.wait(timeout=5)
        return ScanResult()

    active_store.start_job(active, scanner=blocked_scanner)
    assert started.wait(timeout=1)
    assert active.worker_thread is not None
    try:
        active_wall.advance(-3_600)
        active_elapsed.advance(13)

        assert active_store.prune_expired() == 1
        assert active.discarded is True
        assert active_store.worker_slot_count == 1
    finally:
        release.set()
        active.worker_thread.join(timeout=2)

    assert not active.worker_thread.is_alive()
    assert active_store.worker_slot_count == 0


def test_overlapping_get_cannot_move_last_access_backward(tmp_path):
    entered_store = threading.Event()
    release_store = threading.Event()

    class PerThreadClock:
        value = 0.0

        def __call__(self) -> float:
            if threading.current_thread().name == "stale-get":
                return 100.0
            return self.value

    class DelayedStoreLock:
        def __init__(self, lock) -> None:
            self._lock = lock
            self._delayed_threads: set[int] = set()

        def __enter__(self):
            thread_id = threading.get_ident()
            if (
                threading.current_thread().name == "stale-get"
                and thread_id not in self._delayed_threads
            ):
                self._delayed_threads.add(thread_id)
                entered_store.set()
                release_store.wait(timeout=5)
            self._lock.acquire()
            return self

        def __exit__(self, exc_type, exc_value, traceback) -> None:
            self._lock.release()

    elapsed = PerThreadClock()
    wall = FakeClock()
    store = ScanSessionStore(
        idle_timeout_seconds=30,
        clock=elapsed,
        wall_clock=wall,
        id_factory=lambda: "scan-id",
    )
    session = store.create(ScanRequest(paths=[str(tmp_path)]), ScanResult())
    store._lock = DelayedStoreLock(store._lock)
    elapsed.value = 200.0
    errors: list[BaseException] = []

    def stale_get() -> None:
        try:
            store.get(session.scan_id)
        except BaseException as error:
            errors.append(error)

    reader = threading.Thread(target=stale_get, name="stale-get")
    reader.start()
    assert entered_store.wait(timeout=1)
    assert store.touch(session) is True
    assert session.last_accessed_clock == 200.0
    release_store.set()
    reader.join(timeout=2)

    assert errors == []
    assert not reader.is_alive()
    assert session.last_accessed_clock == 200.0
    elapsed.value = 201.0
    assert store.prune_expired() == 0
    assert session.discarded is False


def test_cleanup_worker_purges_expired_sessions_without_another_request(tmp_path):
    path = tmp_path / "secrets.py"
    path.write_text('ssn = "123-45-6789"\n')
    request, result = _scan_file(path)
    clock = FakeClock()
    store = ScanSessionStore(idle_timeout_seconds=30, clock=clock)
    session = store.create(request, result)
    store.start_cleanup_worker(interval_seconds=0.01)

    try:
        clock.advance(30)
        deadline = time.monotonic() + 1
        while store.session_count and time.monotonic() < deadline:
            time.sleep(0.01)

        assert store.session_count == 0
        assert session.internal_findings == {}
    finally:
        store.close()


def test_explicit_delete_clears_session_references(tmp_path):
    path = tmp_path / "secrets.py"
    path.write_text('ssn = "123-45-6789"\n')
    request, result = _scan_file(path)
    store = ScanSessionStore()
    session = store.create(request, result)

    assert store.delete(session.scan_id) is True

    assert session.internal_findings == {}
    assert session.estimated_bytes == 0
    assert store.delete(session.scan_id) is False


def test_discarded_session_rejects_snapshots_and_every_trusted_helper(tmp_path):
    path = tmp_path / "secrets.py"
    path.write_text('ssn = "123-45-6789"\n')
    request, result = _scan_file(path)
    finding_id = result.findings[0].id
    store = ScanSessionStore()
    session = store.create(request, result)

    assert store.delete(session.scan_id) is True
    assert session.discarded is True

    trusted_calls = [
        session.response,
        session.require_complete,
        lambda: remediation_plan(session),
        lambda: update_remediation_plan(session, [], []),
        lambda: generate_remediation_outputs(session),
        lambda: verify_source_files(session, [str(path)]),
        lambda: session_file_for_finding(session, finding_id),
        lambda: session_redacted_output_for_finding(session, finding_id),
    ]
    for trusted_call in trusted_calls:
        with pytest.raises(SessionProblem) as error:
            trusted_call()
        assert error.value.code == "scan_expired"


def test_terminal_delete_never_holds_store_lock_while_workflow_is_locked(tmp_path):
    first_path = tmp_path / "first.py"
    second_path = tmp_path / "second.py"
    first_path.write_text('ssn = "123-45-6789"\n')
    second_path.write_text('ssn = "987-65-4321"\n')
    first_request, first_result = _scan_file(first_path)
    second_request, second_result = _scan_file(second_path)
    ids = iter(["first-session", "second-session"])
    store = ScanSessionStore(max_sessions=1, id_factory=lambda: next(ids))
    first = store.create(first_request, first_result)
    entered = threading.Event()
    release = threading.Event()
    delete_finished = threading.Event()
    creation_finished = threading.Event()
    delete_results: list[bool] = []
    creation_errors: list[BaseException] = []

    def hold_workflow() -> None:
        with first.workflow_lock:
            entered.set()
            release.wait(timeout=2)

    def delete_first() -> None:
        delete_results.append(store.delete(first.scan_id))
        delete_finished.set()

    def create_second() -> None:
        try:
            store.create(second_request, second_result)
        except BaseException as error:
            creation_errors.append(error)
        finally:
            creation_finished.set()

    holder = threading.Thread(target=hold_workflow)
    deleter = threading.Thread(target=delete_first)
    creator = threading.Thread(target=create_second)
    holder.start()
    assert entered.wait(timeout=1)
    deleter.start()
    creator.start()
    try:
        assert creation_finished.wait(timeout=1), "terminal delete retained the store lock"
        assert len(creation_errors) == 1
        assert isinstance(creation_errors[0], SessionProblem)
        assert creation_errors[0].code == "session_capacity"
        assert delete_finished.is_set() is False
    finally:
        release.set()
        holder.join(timeout=2)
        deleter.join(timeout=2)
        creator.join(timeout=2)

    assert delete_results == [True]
    assert first.discarded is True


def test_trusted_file_lookup_linearizes_with_terminal_deletion(monkeypatch, tmp_path):
    path = tmp_path / "secrets.py"
    path.write_text('ssn = "123-45-6789"\n')
    request, result = _scan_file(path)
    store = ScanSessionStore()
    session = store.create(request, result)
    finding_id = result.findings[0].id
    expected = session.file_fingerprints[str(path)]
    capture_started = threading.Event()
    release_capture = threading.Event()
    deletion_finished = threading.Event()
    opened_paths: list[str] = []
    action_errors: list[BaseException] = []

    def blocked_capture(cls, file_path, checkpoint=None):
        capture_started.set()
        release_capture.wait(timeout=5)
        return expected

    monkeypatch.setattr(FileFingerprint, "capture", classmethod(blocked_capture))

    def trusted_lookup() -> None:
        try:
            opened_paths.append(session_file_for_finding(session, finding_id))
        except BaseException as error:
            action_errors.append(error)

    def delete_session() -> None:
        store.delete(session.scan_id)
        deletion_finished.set()

    lookup = threading.Thread(target=trusted_lookup)
    deletion = threading.Thread(target=delete_session)
    lookup.start()
    assert capture_started.wait(timeout=1)
    deletion.start()
    try:
        assert not deletion_finished.wait(timeout=0.1)
    finally:
        release_capture.set()
        lookup.join(timeout=2)
        deletion.join(timeout=2)

    assert action_errors == []
    assert opened_paths == [str(path)]
    assert deletion_finished.is_set()
    assert session.discarded is True


def test_store_evicts_least_recently_used_session_at_count_limit(tmp_path):
    first_path = tmp_path / "first.py"
    second_path = tmp_path / "second.py"
    first_path.write_text('ssn = "123-45-6789"\n')
    second_path.write_text('ssn = "987-65-4321"\n')
    first_request, first_result = _scan_file(first_path)
    second_request, second_result = _scan_file(second_path)
    ids = iter(["first-session", "second-session"])
    store = ScanSessionStore(max_sessions=1, id_factory=lambda: next(ids))
    first = store.create(first_request, first_result)

    second = store.create(second_request, second_result)

    assert store.session_count == 1
    assert store.get(second.scan_id) is second
    assert first.internal_findings == {}
    with pytest.raises(SessionProblem, match="expired") as error:
        store.get(first.scan_id)
    assert error.value.code == "scan_expired"


def test_capacity_rejects_new_session_without_waiting_for_locked_workflow(tmp_path):
    first_path = tmp_path / "first.py"
    second_path = tmp_path / "second.py"
    first_path.write_text('ssn = "123-45-6789"\n')
    second_path.write_text('ssn = "987-65-4321"\n')
    first_request, first_result = _scan_file(first_path)
    second_request, second_result = _scan_file(second_path)
    ids = iter(["first-session", "second-session"])
    store = ScanSessionStore(max_sessions=1, id_factory=lambda: next(ids))
    first = store.create(first_request, first_result)
    entered = threading.Event()
    release = threading.Event()
    creation_finished = threading.Event()
    errors: list[BaseException] = []

    def hold_workflow() -> None:
        with first.workflow_lock:
            entered.set()
            release.wait(timeout=2)

    def create_second() -> None:
        try:
            store.create(second_request, second_result)
        except BaseException as error:
            errors.append(error)
        finally:
            creation_finished.set()

    holder = threading.Thread(target=hold_workflow)
    creator = threading.Thread(target=create_second)
    holder.start()
    assert entered.wait(timeout=1)
    creator.start()
    try:
        assert creation_finished.wait(timeout=1), "capacity eviction waited on a workflow lock"
        assert len(errors) == 1
        assert isinstance(errors[0], SessionProblem)
        assert errors[0].code == "session_capacity"
        assert store.get(first.scan_id) is first
        assert first.internal_findings
    finally:
        release.set()
        holder.join(timeout=2)
        creator.join(timeout=2)


def test_capacity_growth_discards_current_instead_of_waiting_for_locked_lru(tmp_path):
    first_path = tmp_path / "first.py"
    second_path = tmp_path / "second.py"
    first_path.write_text('ssn = "123-45-6789"\n')
    second_path.write_text('ssn = "987-65-4321"\n')
    first_request, first_result = _scan_file(first_path)
    second_request, second_result = _scan_file(second_path)
    store = ScanSessionStore()
    first = store.create(first_request, first_result)
    second = store.create(second_request, second_result)
    store.max_retained_bytes = max(first.estimated_bytes, second.estimated_bytes)
    entered = threading.Event()
    release = threading.Event()
    refresh_finished = threading.Event()
    errors: list[BaseException] = []

    def hold_first_workflow() -> None:
        with first.workflow_lock:
            entered.set()
            release.wait(timeout=2)

    def refresh_second() -> None:
        try:
            with second.workflow_lock:
                second.refresh_retained_size()
        except BaseException as error:
            errors.append(error)
        finally:
            refresh_finished.set()

    holder = threading.Thread(target=hold_first_workflow)
    refresher = threading.Thread(target=refresh_second)
    holder.start()
    assert entered.wait(timeout=1)
    refresher.start()
    try:
        assert refresh_finished.wait(timeout=1), "capacity refresh waited on a workflow lock"
        assert len(errors) == 1
        assert isinstance(errors[0], SessionProblem)
        assert errors[0].code == "session_capacity"
        assert second.discarded is True
        assert store.get(first.scan_id) is first
        assert store.retained_bytes <= store.max_retained_bytes
    finally:
        release.set()
        holder.join(timeout=2)
        refresher.join(timeout=2)


def test_store_rejects_one_session_larger_than_memory_limit(tmp_path):
    path = tmp_path / "secrets.py"
    path.write_text('ssn = "123-45-6789"\n')
    request, result = _scan_file(path)
    store = ScanSessionStore(max_retained_bytes=1)

    with pytest.raises(SessionProblem) as error:
        store.create(request, result)

    assert error.value.code == "session_capacity"
    assert store.session_count == 0
    assert store.retained_bytes == 0


def test_store_rejects_pending_session_larger_than_memory_limit(tmp_path):
    store = ScanSessionStore(max_retained_bytes=1)

    with pytest.raises(SessionProblem) as error:
        store.create_pending(ScanRequest(paths=[str(tmp_path)]))

    assert error.value.code == "session_capacity"
    assert store.session_count == 0
    assert store.retained_bytes == 0


def test_async_capacity_failure_drops_internal_results_and_stays_bounded(tmp_path):
    path = tmp_path / "secrets.py"
    path.write_text('ssn = "123-45-6789"\n')
    request, result = _scan_file(path)

    sizing_store = ScanSessionStore()
    pending_size = sizing_store.create_pending(request).estimated_bytes
    sizing_store.clear()
    finished_size = sizing_store.create(request, result).estimated_bytes
    sizing_store.clear()
    limit = (pending_size + finished_size) // 2
    store = ScanSessionStore(max_retained_bytes=limit, id_factory=lambda: "scan-id")
    session = store.create_pending(request)

    def scanner(*_args, **_kwargs):
        return result

    store.start_job(session, scanner=scanner)
    session.worker_thread.join(timeout=2)

    assert session.scan_state == "failed"
    assert session.error is not None
    assert session.error.code == "session_capacity"
    assert session.internal_findings == {}
    assert session.public_result.findings == []
    assert store.retained_bytes <= limit


def test_non_complete_terminal_capacity_omits_raw_and_action_only_state(tmp_path):
    path = tmp_path / "secrets.py"
    path.write_text('ssn = "123-45-6789"\n')
    request, result = _scan_file(path)
    large_result = result.model_copy(deep=True)
    large_result.findings[0] = large_result.findings[0].model_copy(
        update={"matched_text": "sensitive" * 20_000}
    )
    store = ScanSessionStore(id_factory=lambda: "scan-id")
    session = store.create_pending(request)
    failure = sessions_module.PublicScanError(
        code="scan_failed",
        message="The scan failed unexpectedly. Try the scan again.",
    )

    with session.event_condition:
        session.duration_ms = 5
        failed_update = session._prepare_terminal_update_locked(
            large_result,
            state="failed",
            error=failure,
        )
        complete_update = session._prepare_terminal_update_locked(
            large_result,
            state="complete",
            fingerprints={str(path): FileFingerprint.capture(str(path))},
        )
        failed_size = sessions_module._estimate_terminal_update_bytes(session, failed_update)
        complete_size = sessions_module._estimate_terminal_update_bytes(session, complete_update)

    assert complete_size > failed_size
    store.max_retained_bytes = failed_size + (complete_size - failed_size) // 2
    store._finish_job(
        session,
        large_result,
        state="failed",
        error=failure,
        duration_ms=5,
        ai_model=None,
    )

    snapshot = session.response()
    assert snapshot.state == "failed"
    assert snapshot.error is not None
    assert snapshot.error.code == "scan_failed"
    assert len(snapshot.findings) == 1
    assert session.internal_findings == {}
    assert session.file_fingerprints == {}
    assert session.remediation_states == {}
    assert store.retained_bytes <= store.max_retained_bytes


def test_terminal_capacity_preflight_matches_exact_committed_snapshot(monkeypatch, tmp_path):
    path = tmp_path / "secrets.py"
    path.write_text('ssn = "123-45-6789"\n')
    request, result = _scan_file(path)
    result = result.model_copy(update={"llm_used": True}, deep=True)
    fingerprint = FileFingerprint.capture(str(path))
    store = ScanSessionStore(id_factory=lambda: "scan-id")
    session = store.create_pending(request)
    session.detector_count = 3
    real_estimate = sessions_module._estimate_terminal_update_bytes
    estimates: list[int] = []

    def set_exact_boundary(active_session, update):
        estimate = real_estimate(active_session, update)
        if not estimates:
            store.max_retained_bytes = estimate
        estimates.append(estimate)
        return estimate

    monkeypatch.setattr(sessions_module, "_estimate_terminal_update_bytes", set_exact_boundary)
    store._finish_job(
        session,
        result,
        state="complete",
        fingerprints={str(path): fingerprint},
        duration_ms=123,
        ai_model="local-test-model",
    )

    snapshot = session.response()
    assert estimates == [session.estimated_bytes]
    assert store.max_retained_bytes == session.estimated_bytes
    assert snapshot.state == "complete"
    assert snapshot.event_cursor == session.events[-1].sequence
    assert snapshot.progress.stage == "complete"
    assert snapshot.error is None
    assert snapshot.metadata.duration_ms == 123
    assert snapshot.metadata.data_scanned_bytes == fingerprint.size
    assert snapshot.metadata.detector_count == 3
    assert snapshot.metadata.ai_model == "local-test-model"
    assert session.events[-1].type == "scan_completed"


def test_terminal_capacity_rejection_never_publishes_then_reverses_completion(
    monkeypatch, tmp_path
):
    path = tmp_path / "secrets.py"
    path.write_text('ssn = "123-45-6789"\n')
    request, result = _scan_file(path)
    fingerprint = FileFingerprint.capture(str(path))
    store = ScanSessionStore(id_factory=lambda: "scan-id")
    session = store.create_pending(request)
    real_estimate = sessions_module._estimate_terminal_update_bytes
    prepared_event_types: list[str] = []

    def set_undersized_boundary(active_session, update):
        estimate = real_estimate(active_session, update)
        prepared_event_types.append(update.event.type)
        if len(prepared_event_types) == 1:
            store.max_retained_bytes = estimate - 1
        return estimate

    monkeypatch.setattr(
        sessions_module,
        "_estimate_terminal_update_bytes",
        set_undersized_boundary,
    )
    store._finish_job(
        session,
        result,
        state="complete",
        fingerprints={str(path): fingerprint},
        duration_ms=9,
        ai_model=None,
    )

    snapshot = session.response()
    assert prepared_event_types == ["scan_completed", "scan_failed"]
    assert snapshot.state == "failed"
    assert snapshot.error is not None
    assert snapshot.error.code == "session_capacity"
    assert [event.type for event in session.events] == ["scan_failed"]
    assert snapshot.event_cursor == session.events[-1].sequence
    assert session.internal_findings == {}
    assert session.file_fingerprints == {}
    assert store.retained_bytes <= store.max_retained_bytes


def test_active_event_growth_is_stopped_at_memory_limit(tmp_path):
    path = tmp_path / "secrets.py"
    path.write_text('ssn = "123-45-6789"\n')
    request, result = _scan_file(path)

    sizing_store = ScanSessionStore()
    pending_size = sizing_store.create_pending(request).estimated_bytes
    sizing_store.clear()
    finished_size = sizing_store.create(request, result).estimated_bytes
    sizing_store.clear()
    limit = (pending_size + finished_size) // 2
    store = ScanSessionStore(max_retained_bytes=limit, id_factory=lambda: "scan-id")
    session = store.create_pending(request)

    def scanner(*_args, execution, **_kwargs):
        execution.emit(
            ScanEvent(
                type="finding_added",
                stage="consolidation",
                finding=result.findings[0],
            )
        )
        return result

    store.start_job(session, scanner=scanner)
    session.worker_thread.join(timeout=2)

    assert session.scan_state == "failed"
    assert session.error is not None
    assert session.error.code == "session_capacity"
    assert session.internal_findings == {}
    assert session.events[-1].type == "scan_failed"
    assert store.retained_bytes <= limit


def test_aggregate_growth_with_two_active_sessions_fails_current_without_eviction(tmp_path):
    path = tmp_path / "secrets.py"
    path.write_text('ssn = "123-45-6789"\n')
    request, result = _scan_file(path)
    event = ScanEvent(
        type="finding_added",
        stage="consolidation",
        finding=result.findings[0],
    )

    sizing = ScanSessionStore(id_factory=lambda: "sizing")
    projected = sizing.create_pending(request)
    projected.apply_core_event(event)
    projected_size = sessions_module._estimate_session_bytes(projected)
    sizing.clear()

    ids = iter(["first-", "second"])
    store = ScanSessionStore(max_sessions=2, id_factory=lambda: next(ids))
    first = store.create_pending(request)
    second = store.create_pending(request)
    store.max_retained_bytes = max(store.retained_bytes, projected_size)

    with pytest.raises(SessionProblem) as error:
        store._record_core_event(second, event)

    assert error.value.code == "session_capacity"
    assert store.get(first.scan_id) is first
    assert store.get(second.scan_id) is second
    assert first.discarded is False
    assert second.discarded is False
    assert first.request is not None
    assert second.request is None
    assert second.internal_findings == {}
    assert store.retained_bytes <= store.max_retained_bytes


def test_active_session_is_not_idle_expired_mid_job(tmp_path):
    clock = FakeClock()
    release = threading.Event()
    store = ScanSessionStore(
        idle_timeout_seconds=30,
        job_timeout_seconds=60,
        clock=clock,
    )
    session = store.create_pending(ScanRequest(paths=[str(tmp_path)]))

    def scanner(*_args, **_kwargs):
        release.wait(timeout=2)
        return ScanResult(
            summary={
                "status": "complete",
                "incomplete": False,
                "completed_files": 0,
                "total_files": 0,
            }
        )

    store.start_job(session, scanner=scanner)

    try:
        clock.advance(30)

        assert store.prune_expired() == 0
        assert store.get(session.scan_id) is session
        assert session.active is True
        assert session.worker_thread is not None
        assert session.worker_thread.is_alive()
    finally:
        release.set()
        session.worker_thread.join(timeout=2)


def test_pending_session_without_a_worker_expires_despite_stream_touches(tmp_path):
    clock = FakeClock()
    store = ScanSessionStore(idle_timeout_seconds=30, clock=clock)
    session = store.create_pending(ScanRequest(paths=[str(tmp_path)]))

    clock.advance(29)
    assert store.touch(session) is True
    clock.advance(1)

    assert store.prune_expired() == 1
    assert session.discarded is True
    assert session.request is None
    assert store.session_count == 0


def test_worker_start_failure_removes_and_clears_pending_session(monkeypatch, tmp_path):
    store = ScanSessionStore()
    session = store.create_pending(ScanRequest(paths=[str(tmp_path)]))

    def fail_start(_worker):
        raise RuntimeError("thread unavailable")

    monkeypatch.setattr(threading.Thread, "start", fail_start)

    with pytest.raises(SessionProblem) as error:
        store.start_job(session)

    assert error.value.code == "scan_failed"
    assert session.discarded is True
    assert session.request is None
    assert store.session_count == 0
    assert store.worker_slot_count == 0

    replacement = store.create_pending(ScanRequest(paths=[str(tmp_path)]))
    assert store.worker_slot_count == 1
    store.clear()
    assert replacement.discarded is True
    assert store.worker_slot_count == 0


def test_non_cooperative_worker_has_a_hard_retention_deadline(tmp_path):
    clock = FakeClock()
    started = threading.Event()
    release = threading.Event()
    ids = iter(["stuck-worker", "replacement"])
    store = ScanSessionStore(
        idle_timeout_seconds=5,
        max_sessions=1,
        job_timeout_seconds=10,
        extraction_timeout_seconds=2,
        llm_call_timeout_seconds=3,
        clock=clock,
        id_factory=lambda: next(ids),
    )
    session = store.create_pending(ScanRequest(paths=[str(tmp_path)]))

    def scanner(*_args, **_kwargs):
        started.set()
        release.wait()
        return ScanResult()

    store.start_job(session, scanner=scanner)
    assert started.wait(timeout=1)

    try:
        clock.advance(12)
        assert store.touch(session) is True
        assert store.prune_expired() == 0
        clock.advance(1)

        assert store.prune_expired() == 1
        assert session.discarded is True
        assert session.request is None
        assert store.session_count == 0
        assert store.live_worker_count == 1
        assert store.worker_slot_count == 1

        with pytest.raises(SessionProblem) as error:
            store.create_pending(ScanRequest(paths=[str(tmp_path)]))

        assert error.value.code == "session_capacity"
        assert store.session_count == 0
        assert store.live_worker_count == 1
    finally:
        release.set()
        assert session.worker_thread is not None
        session.worker_thread.join(timeout=2)

    assert not session.worker_thread.is_alive()
    assert store.worker_slot_count == 0
    replacement = store.create_pending(ScanRequest(paths=[str(tmp_path)]))
    assert replacement.scan_id == "replacement"
    assert store.worker_slot_count == 1
    store.clear()
    assert store.worker_slot_count == 0


def test_pending_worker_slot_closes_admission_race_before_and_after_start(tmp_path):
    clock = FakeClock()
    first_started = threading.Event()
    second_started = threading.Event()
    first_release = threading.Event()
    second_release = threading.Event()
    ids = iter(["first", "second", "third"])
    store = ScanSessionStore(
        idle_timeout_seconds=5,
        max_sessions=2,
        job_timeout_seconds=10,
        extraction_timeout_seconds=2,
        llm_call_timeout_seconds=3,
        clock=clock,
        id_factory=lambda: next(ids),
    )
    request = ScanRequest(paths=[str(tmp_path)])
    first = store.create_pending(request)

    def first_scanner(*_args, **_kwargs):
        first_started.set()
        first_release.wait()
        return ScanResult()

    def second_scanner(*_args, **_kwargs):
        second_started.set()
        second_release.wait()
        return ScanResult()

    store.start_job(first, scanner=first_scanner)
    assert first_started.wait(timeout=1)
    clock.advance(13)
    assert store.prune_expired() == 1
    assert store.session_count == 0
    assert store.live_worker_count == 1

    second = store.create_pending(request)
    assert store.worker_slot_count == 2
    assert store.live_worker_count == 1

    # A pending job owns its eventual worker slot. Admission cannot slip into
    # the interval between create_pending and start_job.
    with pytest.raises(SessionProblem) as before_start:
        store.create_pending(request)
    assert before_start.value.code == "session_capacity"

    store.start_job(second, scanner=second_scanner)
    assert second_started.wait(timeout=1)
    assert store.worker_slot_count == store.max_sessions
    assert store.live_worker_count == store.max_sessions

    with pytest.raises(SessionProblem) as after_start:
        store.create_pending(request)
    assert after_start.value.code == "session_capacity"
    assert store.live_worker_count <= store.max_sessions

    first_release.set()
    second_release.set()
    assert first.worker_thread is not None
    assert second.worker_thread is not None
    first.worker_thread.join(timeout=2)
    second.worker_thread.join(timeout=2)

    assert not first.worker_thread.is_alive()
    assert not second.worker_thread.is_alive()
    assert store.worker_slot_count == 0
    third = store.create_pending(request)
    assert third.scan_id == "third"
    store.clear()


def test_worker_slot_is_retained_until_the_thread_is_not_alive(monkeypatch, tmp_path):
    after_target = threading.Event()
    release_thread = threading.Event()
    original_run = threading.Thread.run
    ids = iter(["first", "replacement"])
    store = ScanSessionStore(max_sessions=1, id_factory=lambda: next(ids))
    request = ScanRequest(paths=[str(tmp_path)])
    first = store.create_pending(request)

    def delayed_thread_exit(worker) -> None:
        original_run(worker)
        if worker is first.worker_thread:
            after_target.set()
            release_thread.wait(timeout=5)

    monkeypatch.setattr(threading.Thread, "run", delayed_thread_exit)
    store.start_job(first, scanner=lambda *_args, **_kwargs: ScanResult())
    assert first.worker_thread is not None
    assert after_target.wait(timeout=2)
    try:
        assert first.worker_thread.is_alive()
        assert store.worker_slot_count == 1
        with pytest.raises(SessionProblem) as error:
            store.create_pending(request)
        assert error.value.code == "session_capacity"
    finally:
        release_thread.set()
        first.worker_thread.join(timeout=2)

    assert not first.worker_thread.is_alive()
    assert store.worker_slot_count == 0
    replacement = store.create_pending(request)
    assert replacement.scan_id == "replacement"
    store.clear()


def test_nested_file_worker_keeps_expired_scan_slot_until_it_returns(monkeypatch, tmp_path):
    first_path = tmp_path / "a.py"
    later_path = tmp_path / "b.py"
    first_path.write_text('ssn = "123-45-6789"\n')
    later_path.write_text('ssn = "987-65-4321"\n')
    clock = FakeClock()
    ids = iter(["blocked-scan", "replacement"])
    store = ScanSessionStore(
        idle_timeout_seconds=5,
        max_sessions=1,
        job_timeout_seconds=10,
        extraction_timeout_seconds=2,
        llm_call_timeout_seconds=3,
        clock=clock,
        id_factory=lambda: next(ids),
    )
    request = ScanRequest(paths=[str(tmp_path)], options={"max_workers": 2})
    later_started = threading.Event()
    later_release = threading.Event()
    cancel_requested = threading.Event()
    cancel_emitted = threading.Event()
    real_process_file = scanner_module._process_file
    real_record_core_event = store._record_core_event

    def controlled_process(file_path, *args, **kwargs):
        if Path(file_path) == later_path:
            later_started.set()
            later_release.wait()
        else:
            later_started.wait()
        return real_process_file(file_path, *args, **kwargs)

    def record_and_cancel(active_session, event):
        real_record_core_event(active_session, event)
        if event.type == "file_completed" and event.file_path == str(first_path):
            active_session.request_cancel()
            cancel_requested.set()
        elif event.type == "scan_cancelled":
            cancel_emitted.set()

    monkeypatch.setattr(scanner_module, "_process_file", controlled_process)
    monkeypatch.setattr(store, "_record_core_event", record_and_cancel)
    session = store.create_pending(request)
    store.start_job(session)
    assert session.worker_thread is not None

    try:
        assert later_started.wait(timeout=1)
        assert cancel_requested.wait(timeout=1)
        session.worker_thread.join(timeout=0.1)
        assert session.worker_thread.is_alive()
        assert store.live_worker_count == 1
        assert cancel_emitted.is_set() is False

        clock.advance(13)
        assert store.prune_expired() == 1
        assert session.discarded is True
        assert store.session_count == 0
        assert store.live_worker_count == 1
        assert store.worker_slot_count == 1

        with pytest.raises(SessionProblem) as error:
            store.create_pending(request)
        assert error.value.code == "session_capacity"
        assert store.live_worker_count == 1
    finally:
        later_release.set()
        session.worker_thread.join(timeout=2)

    assert not session.worker_thread.is_alive()
    assert cancel_emitted.is_set()
    assert store.worker_slot_count == 0
    replacement = store.create_pending(request)
    assert replacement.scan_id == "replacement"
    store.clear()


def test_finished_job_receives_a_full_idle_window(tmp_path):
    clock = FakeClock()
    store = ScanSessionStore(
        idle_timeout_seconds=30,
        job_timeout_seconds=60,
        clock=clock,
        id_factory=lambda: "scan-id",
    )
    session = store.create_pending(ScanRequest(paths=[str(tmp_path)]))
    clock.advance(100)

    def scanner(*_args, **_kwargs):
        return ScanResult(
            summary={
                "status": "complete",
                "incomplete": False,
                "completed_files": 0,
                "total_files": 0,
            }
        )

    store.start_job(session, scanner=scanner)
    session.worker_thread.join(timeout=2)

    assert session.scan_state == "complete"
    assert session.last_accessed_clock == clock()
    clock.advance(29)
    assert store.prune_expired() == 0
    clock.advance(1)
    assert store.prune_expired() == 1


def test_new_session_is_rejected_instead_of_evicting_active_sessions(tmp_path):
    clock = FakeClock()
    ids = iter(["first", "second", "third"])
    store = ScanSessionStore(max_sessions=2, clock=clock, id_factory=lambda: next(ids))
    request = ScanRequest(paths=[str(tmp_path)])
    first = store.create_pending(request)
    clock.advance(1)
    second = store.create_pending(request)
    clock.advance(1)

    assert store.touch(first) is True
    clock.advance(1)
    with pytest.raises(SessionProblem) as error:
        store.create_pending(request)

    assert error.value.code == "session_capacity"
    assert store.get(first.scan_id) is first
    assert store.get(second.scan_id) is second
    assert first.discarded is False
    assert second.discarded is False


def test_content_hash_detects_change_even_if_size_and_timestamp_are_restored(tmp_path):
    path = tmp_path / "secrets.py"
    path.write_text('ssn = "123-45-6789"\n')
    request, result = _scan_file(path)
    store = ScanSessionStore()
    session = store.create(request, result)
    original_stat = path.stat()

    path.write_text('ssn = "987-65-4321"\n')
    os.utime(path, ns=(original_stat.st_atime_ns, original_stat.st_mtime_ns))

    with pytest.raises(SessionProblem) as error:
        verify_source_files(session, [str(path)])
    assert error.value.code == "file_changed"


def test_fingerprint_rejects_identical_content_entry_replacement(tmp_path):
    path = tmp_path / "secrets.py"
    contents = 'ssn = "123-45-6789"\n'
    path.write_text(contents)
    original = FileFingerprint.capture(str(path))

    replacement = tmp_path / "replacement.py"
    replacement.write_text(contents)
    os.utime(
        replacement,
        ns=(replacement.stat().st_atime_ns, original.modified_ns),
    )
    os.replace(replacement, path)

    current = FileFingerprint.capture(str(path))

    assert current.size == original.size
    assert current.modified_ns == original.modified_ns
    assert current.sha256 == original.sha256
    assert current != original
    assert (current.device, current.inode, current.changed_ns) != (
        original.device,
        original.inode,
        original.changed_ns,
    )


def test_identity_bound_source_read_enforces_retained_digest(tmp_path):
    path = tmp_path / "secrets.py"
    path.write_text('ssn = "123-45-6789"\n')
    fingerprint = FileFingerprint.capture(str(path))
    wrong_digest = replace(fingerprint, sha256="0" * 64)

    with pytest.raises(OSError, match="retained fingerprint"):
        sessions_module._read_regular_bytes_no_follow(
            path,
            max_bytes=fingerprint.size,
            expected_fingerprint=wrong_digest,
        )


def test_fingerprint_rejects_a_file_beneath_a_symbolic_link_parent(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_text("private")
    redirected = tmp_path / "redirected"
    try:
        redirected.symlink_to(outside, target_is_directory=True)
    except OSError as error:
        pytest.skip(f"directory symlinks are unavailable in this environment: {error}")

    with pytest.raises(OSError, match="filesystem redirect"):
        FileFingerprint.capture(str(redirected / "secret.txt"))


def test_fingerprint_rejects_a_detected_junction_ancestor(monkeypatch, tmp_path):
    redirected = tmp_path / "redirected"
    redirected.mkdir()
    target = redirected / "secret.txt"
    target.write_text("private")
    real_is_junction = getattr(Path, "is_junction", None)

    def fake_is_junction(path):
        if path == redirected:
            return True
        return real_is_junction(path) if real_is_junction is not None else False

    monkeypatch.setattr(Path, "is_junction", fake_is_junction, raising=False)

    with pytest.raises(OSError, match="filesystem redirect"):
        FileFingerprint.capture(str(target))


def test_fingerprint_treats_a_detected_final_reparse_entry_as_changed(monkeypatch, tmp_path):
    target = tmp_path / "secret.txt"
    target.write_text("private")
    real_redirect_check = session_files_module._is_filesystem_redirect

    def detect_final_redirect(path, metadata):
        return path == target or real_redirect_check(path, metadata)

    monkeypatch.setattr(
        session_files_module,
        "_is_filesystem_redirect",
        detect_final_redirect,
    )

    with pytest.raises(SessionProblem) as error:
        FileFingerprint.capture(str(target))
    assert error.value.code == "file_changed"


def test_redacted_output_naming_preserves_the_final_extension(tmp_path):
    plain = tmp_path / "plain.docx"
    plain.write_text('ssn = "123-45-6789"\n')
    packaged = tmp_path / "packaged.docx"
    packaged.write_bytes(b"PK\x03\x04package bytes")

    assert sessions_module._redacted_output_path_no_follow(str(plain)) == (
        tmp_path / "plain-auto-redacted-copy.docx"
    )
    assert sessions_module._redacted_output_path_no_follow(str(packaged)) == (
        tmp_path / "packaged-auto-redacted-copy.docx"
    )


def test_output_naming_does_not_open_the_source(monkeypatch, tmp_path):
    def forbidden_open(*_args, **_kwargs):
        raise AssertionError("output naming must not open the source")

    monkeypatch.setattr(sessions_module.os, "open", forbidden_open)

    assert sessions_module._redacted_output_path_no_follow(str(tmp_path / "redirect.docx")) == (
        tmp_path / "redirect-auto-redacted-copy.docx"
    )


def test_fingerprint_rejects_mutation_after_final_descriptor_stat(monkeypatch, tmp_path):
    target = tmp_path / "data.txt"
    target.write_text("hello")
    real_lstat = Path.lstat
    target_lstat_calls = 0

    def mutate_before_final_path_stat(path, *args, **kwargs):
        nonlocal target_lstat_calls
        if path == target:
            target_lstat_calls += 1
            if target_lstat_calls == 3:
                target.write_text("changed after descriptor stat")
        return real_lstat(path, *args, **kwargs)

    monkeypatch.setattr(Path, "lstat", mutate_before_final_path_stat)

    with pytest.raises(SessionProblem) as error:
        FileFingerprint.capture(str(target))

    assert error.value.code == "file_changed"


def test_remediation_rejects_a_redirected_source_parent(monkeypatch, tmp_path):
    root = tmp_path / "scan-root"
    root.mkdir()
    path = root / "secrets.py"
    path.write_text('ssn = "123-45-6789"\n')
    request, result = _scan_file(path)
    store = ScanSessionStore()
    session = store.create(request, result)
    update_remediation_plan(session, [result.findings[0].id], [])
    real_is_junction = getattr(Path, "is_junction", None)

    def fake_is_junction(candidate):
        if candidate == root:
            return True
        return real_is_junction(candidate) if real_is_junction is not None else False

    monkeypatch.setattr(Path, "is_junction", fake_is_junction, raising=False)

    with pytest.raises(SessionProblem) as error:
        generate_remediation_outputs(session)

    assert error.value.code == "file_unavailable"
    assert not (root / "secrets-auto-redacted-copy.py").exists()


def test_generation_rejects_oversized_swap_before_materializing_source(monkeypatch, tmp_path):
    path = tmp_path / "secrets.py"
    path.write_text('ssn = "123-45-6789"\n')
    request, result = _scan_file(path)
    session = ScanSessionStore().create(request, result)
    update_remediation_plan(session, [result.findings[0].id], [])
    real_verify = sessions_module.verify_source_files
    real_open = sessions_module.os.open
    replacement_installed = False

    def verify_then_replace(*args, **kwargs):
        nonlocal replacement_installed
        result = real_verify(*args, **kwargs)
        if not replacement_installed:
            replacement = tmp_path / "oversized-replacement.py"
            replacement.write_bytes(b"x" * 1_000_000)
            os.replace(replacement, path)
            replacement_installed = True
        return result

    def reject_replacement_open(candidate, *args, **kwargs):
        if replacement_installed and Path(candidate) == path:
            raise AssertionError("the rejected oversized replacement must not be opened")
        return real_open(candidate, *args, **kwargs)

    monkeypatch.setattr(sessions_module, "verify_source_files", verify_then_replace)
    monkeypatch.setattr(sessions_module.os, "open", reject_replacement_open)

    with pytest.raises(SessionProblem) as error:
        generate_remediation_outputs(session)

    assert error.value.code == "file_changed"
    assert not (tmp_path / "secrets-auto-redacted-copy.py").exists()


def test_session_generation_records_verified_output_metadata(tmp_path):
    path = tmp_path / "secrets.py"
    path.write_text('ssn = "123-45-6789"\n')
    request, result = _scan_file(path)
    store = ScanSessionStore()
    session = store.create(request, result)
    finding_id = result.findings[0].id

    update_remediation_plan(session, [finding_id], [])
    before_generation = session.estimated_bytes
    response = generate_remediation_outputs(session)

    metadata = session.generated_outputs[str(path)]
    assert metadata.output_path == response.outputs[0].output_path
    assert metadata.finding_ids == (finding_id,)
    assert metadata.verification_status == "verified"
    assert metadata.source_fingerprint == session.file_fingerprints[str(path)]
    assert set(response.outputs[0].source_fingerprint.model_dump()) == {
        "resolved_path",
        "size",
        "modified_ns",
        "sha256",
    }
    assert response.plan.files[0].output_state == "current"
    assert session.estimated_bytes <= before_generation
    assert store.retained_bytes == session.estimated_bytes


def test_plan_revision_rejects_stale_update_and_generation(tmp_path):
    path = tmp_path / "secrets.py"
    path.write_text('ssn = "123-45-6789"\n')
    request, result = _scan_file(path)
    session = ScanSessionStore().create(request, result)
    finding_id = result.findings[0].id
    initial = remediation_plan(session)

    updated = update_remediation_plan(
        session,
        [finding_id],
        [],
        expected_revision=initial.plan_revision,
    )

    assert updated.plan_revision == initial.plan_revision + 1
    with pytest.raises(SessionProblem) as stale_update:
        update_remediation_plan(
            session,
            [],
            [],
            expected_revision=initial.plan_revision,
        )
    assert stale_update.value.code == "invalid_remediation_plan"
    with pytest.raises(SessionProblem) as stale_generation:
        generate_remediation_outputs(session, expected_revision=initial.plan_revision)
    assert stale_generation.value.code == "invalid_remediation_plan"
    assert not (tmp_path / "secrets-auto-redacted-copy.py").exists()


def test_post_commit_verification_failure_rolls_back_new_output(monkeypatch, tmp_path):
    path = tmp_path / "secrets.py"
    path.write_text('ssn = "123-45-6789"\n')
    request, result = _scan_file(path)
    session = ScanSessionStore().create(request, result)
    update_remediation_plan(session, [result.findings[0].id], [])
    real_link = atomic.os.link

    def publish_wrong_bytes(source, target):
        real_link(source, target)
        Path(target).write_text('ssn = "123-45-6789"\n')

    monkeypatch.setattr(atomic.os, "link", publish_wrong_bytes)

    with pytest.raises(SessionProblem) as error:
        generate_remediation_outputs(session)

    assert error.value.code == "verification_failed"
    assert not (tmp_path / "secrets-auto-redacted-copy.py").exists()
    assert session.generated_outputs == {}


def test_post_commit_fingerprint_failure_rolls_back_new_output(monkeypatch, tmp_path):
    path = tmp_path / "secrets.py"
    path.write_text('ssn = "123-45-6789"\n')
    request, result = _scan_file(path)
    session = ScanSessionStore().create(request, result)
    update_remediation_plan(session, [result.findings[0].id], [])
    real_capture = FileFingerprint.capture

    def fail_output_capture(cls, file_path, checkpoint=None):
        if str(file_path).endswith("-auto-redacted-copy.py"):
            raise OSError("simulated final fingerprint failure")
        return real_capture(file_path, checkpoint=checkpoint)

    monkeypatch.setattr(FileFingerprint, "capture", classmethod(fail_output_capture))

    with pytest.raises(SessionProblem) as error:
        generate_remediation_outputs(session)

    assert error.value.code == "file_unavailable"
    assert not (tmp_path / "secrets-auto-redacted-copy.py").exists()
    assert session.generated_outputs == {}


def test_failed_regeneration_adopts_verified_rollback_fingerprints(monkeypatch, tmp_path):
    paths = [tmp_path / "first.py", tmp_path / "second.py"]
    for path, value in zip(paths, ("123-45-6789", "987-65-4321"), strict=True):
        path.write_text(f'ssn = "{value}"\n')
    request = ScanRequest(paths=[str(path) for path in paths])
    result = scan(request, load_default_registry())
    session = ScanSessionStore().create(request, result)
    update_remediation_plan(session, [finding.id for finding in result.findings], [])
    first_generation = generate_remediation_outputs(session)
    output_by_source = {
        output.source_path: Path(output.output_path) for output in first_generation.outputs
    }
    original_fingerprints = {
        source: session.generated_outputs[source].output_fingerprint for source in output_by_source
    }
    second_output = output_by_source[str(paths[1])]
    real_replace = atomic.os.replace

    def fail_second_commit(source, target):
        if Path(target) == second_output and str(source).endswith(".tmp"):
            raise OSError("simulated second regeneration failure")
        return real_replace(source, target)

    monkeypatch.setattr(atomic.os, "replace", fail_second_commit)

    with pytest.raises(SessionProblem) as caught:
        generate_remediation_outputs(session)

    assert caught.value.code == "file_unavailable"
    plan = remediation_plan(session)
    assert {file.output_state for file in plan.files} == {"current"}
    for finding in result.findings:
        assert session_redacted_output_for_finding(session, finding.id) == str(
            output_by_source[finding.file_path]
        )
        retained = session.generated_outputs[finding.file_path].output_fingerprint
        original = original_fingerprints[finding.file_path]
        assert retained == FileFingerprint.capture(str(output_by_source[finding.file_path]))
        assert (retained.size, retained.modified_ns, retained.sha256) == (
            original.size,
            original.modified_ns,
            original.sha256,
        )


def test_successful_regeneration_reports_retained_backup_cleanup(monkeypatch, tmp_path):
    path = tmp_path / "secrets.txt"
    path.write_text("password = FirstSecret123!\nssn = 123-45-6789\n")
    request, result = _scan_file(path)
    findings = {finding.detector_id: finding for finding in result.findings}
    session = ScanSessionStore().create(request, result)
    update_remediation_plan(session, [findings["password_assignment"].id], [])
    first = generate_remediation_outputs(session)
    assert "123-45-6789" in Path(first.outputs[0].output_path).read_text()
    update_remediation_plan(session, [finding.id for finding in result.findings], [])
    real_unlink = Path.unlink

    def retain_backup(artifact, *args, **kwargs):
        if artifact.name.endswith(".backup"):
            raise PermissionError("backup is locked")
        return real_unlink(artifact, *args, **kwargs)

    monkeypatch.setattr(Path, "unlink", retain_backup)

    regenerated = generate_remediation_outputs(session)

    backups = list(tmp_path.glob(".*.backup"))
    assert len(backups) == 1
    assert "123-45-6789" in backups[0].read_text()
    assert "123-45-6789" not in Path(regenerated.outputs[0].output_path).read_text()
    assert regenerated.plan.files[0].output_state == "current"
    assert regenerated.plan.retained_artifact_paths == [str(backups[0])]
    assert any(
        str(backups[0]) in warning and "Delete" in warning
        for warning in regenerated.outputs[0].warnings
    )

    monkeypatch.setattr(Path, "unlink", real_unlink)
    repeated = generate_remediation_outputs(session)
    assert backups[0].exists()
    assert repeated.plan.retained_artifact_paths == [str(backups[0])]
    assert any(str(backups[0]) in warning for warning in repeated.outputs[0].warnings)

    backups[0].unlink()
    cleaned = generate_remediation_outputs(session)
    assert cleaned.plan.retained_artifact_paths == []
    assert not any(
        "Temporary remediation artifacts" in warning for warning in cleaned.outputs[0].warnings
    )


def test_failed_generation_keeps_retained_staging_artifact_visible(monkeypatch, tmp_path):
    path = tmp_path / "secrets.py"
    path.write_text('ssn = "123-45-6789"\n')
    request, result = _scan_file(path)
    store = ScanSessionStore()
    session = store.create(request, result)
    update_remediation_plan(session, [result.findings[0].id], [])
    real_unlink = Path.unlink

    def refuse_staging_cleanup(artifact, *args, **kwargs):
        if artifact.name.endswith(".tmp"):
            raise PermissionError("staging file is locked")
        return real_unlink(artifact, *args, **kwargs)

    monkeypatch.setattr(Path, "unlink", refuse_staging_cleanup)

    with pytest.raises(SessionProblem) as caught:
        generate_remediation_outputs(session)

    staging = list(tmp_path.glob(".*.tmp"))
    assert caught.value.code == "file_unavailable"
    assert len(staging) == 1
    assert str(staging[0]) not in caught.value.message
    assert "remediation panel" in caught.value.message
    assert not (tmp_path / "secrets-auto-redacted-copy.py").exists()
    assert session.generated_outputs == {}
    assert remediation_plan(session).retained_artifact_paths == [str(staging[0])]
    assert session.estimated_bytes == sessions_module._estimate_session_bytes(session)
    assert store.retained_bytes == session.estimated_bytes

    monkeypatch.setattr(Path, "unlink", real_unlink)
    staging[0].unlink()
    assert remediation_plan(session).retained_artifact_paths == []


def test_failed_cleanup_enforces_capacity_without_hiding_recovery_path(monkeypatch, tmp_path):
    path = tmp_path / "secrets.py"
    path.write_text('ssn = "123-45-6789"\n')
    request, result = _scan_file(path)
    store = ScanSessionStore()
    session = store.create(request, result)
    update_remediation_plan(session, [result.findings[0].id], [])
    store.max_retained_bytes = session.estimated_bytes
    real_unlink = Path.unlink

    def refuse_staging_cleanup(artifact, *args, **kwargs):
        if artifact.name.endswith(".tmp"):
            raise PermissionError("staging file is locked")
        return real_unlink(artifact, *args, **kwargs)

    monkeypatch.setattr(Path, "unlink", refuse_staging_cleanup)

    with pytest.raises(SessionProblem) as caught:
        generate_remediation_outputs(session)

    staging = list(tmp_path.glob(".*.tmp"))
    assert caught.value.code == "file_unavailable"
    assert len(staging) == 1
    assert str(staging[0]) not in caught.value.message
    assert "source folder" in caught.value.message
    assert session.discarded is True
    assert store.session_count == 0
    assert store.retained_bytes <= store.max_retained_bytes

    monkeypatch.setattr(Path, "unlink", real_unlink)
    staging[0].unlink()


def test_unreadable_retained_artifact_is_not_silently_forgotten(monkeypatch, tmp_path):
    path = tmp_path / "secrets.py"
    path.write_text('ssn = "123-45-6789"\n')
    artifact = tmp_path / ".secrets.py.recovery.backup"
    artifact.write_text("recovery bytes")
    request, result = _scan_file(path)
    session = ScanSessionStore().create(request, result)
    session.retained_remediation_artifacts.add(str(artifact))
    real_lstat = os.lstat

    def deny_artifact_lstat(candidate, *args, **kwargs):
        if os.path.abspath(os.fspath(candidate)) == os.path.abspath(artifact):
            raise PermissionError("recovery artifact is temporarily locked")
        return real_lstat(candidate, *args, **kwargs)

    monkeypatch.setattr(os, "lstat", deny_artifact_lstat)

    plan = remediation_plan(session)

    assert plan.retained_artifact_paths == [str(artifact)]
    assert plan.can_review is True


def test_existing_output_change_during_atomic_write_is_output_conflict(
    monkeypatch,
    tmp_path,
):
    path = tmp_path / "secrets.py"
    path.write_text('ssn = "123-45-6789"\n')
    request, result = _scan_file(path)
    session = ScanSessionStore().create(request, result)
    update_remediation_plan(session, [result.findings[0].id], [])
    first = generate_remediation_outputs(session)
    output = Path(first.outputs[0].output_path)
    real_stage = atomic._stage_bytes

    def mutate_after_staging(target, contents, *, label="tmp"):
        staged = real_stage(target, contents, label=label)
        output.write_text("changed during generation\n")
        return staged

    monkeypatch.setattr(atomic, "_stage_bytes", mutate_after_staging)

    with pytest.raises(SessionProblem) as caught:
        generate_remediation_outputs(session)

    assert caught.value.code == "output_conflict"
    assert output.read_text() == "changed during generation\n"


def test_existing_output_change_after_session_validation_is_not_overwritten(
    monkeypatch,
    tmp_path,
):
    path = tmp_path / "secrets.py"
    path.write_text('ssn = "123-45-6789"\n')
    request, result = _scan_file(path)
    session = ScanSessionStore().create(request, result)
    update_remediation_plan(session, [result.findings[0].id], [])
    first = generate_remediation_outputs(session)
    output = Path(first.outputs[0].output_path)
    published = session.generated_outputs[str(path)]
    real_prepare = sessions_module.prepare_anonymized_file

    def prepare_then_change_output(source_path, findings, **kwargs):
        contents = real_prepare(source_path, findings, **kwargs)
        output.write_text("external change after validation\n")
        return contents

    monkeypatch.setattr(
        sessions_module,
        "prepare_anonymized_file",
        prepare_then_change_output,
    )

    with pytest.raises(SessionProblem) as caught:
        generate_remediation_outputs(session)

    assert caught.value.code == "output_conflict"
    assert output.read_text() == "external change after validation\n"
    assert session.generated_outputs[str(path)] == published


def test_rollback_failure_reports_backup_and_does_not_publish_new_metadata(
    monkeypatch,
    tmp_path,
):
    path = tmp_path / "secrets.txt"
    path.write_text("password = FirstSecret123!\nssn = 123-45-6789\n")
    request, result = _scan_file(path)
    findings = {finding.detector_id: finding for finding in result.findings}
    session = ScanSessionStore().create(request, result)
    first_id = findings["password_assignment"].id
    update_remediation_plan(session, [first_id], [])
    first = generate_remediation_outputs(session)
    output = Path(first.outputs[0].output_path)
    previous_bytes = output.read_bytes()
    update_remediation_plan(session, [finding.id for finding in result.findings], [])
    real_verify = sessions_module.verify_anonymized_bytes
    verify_calls = 0

    def fail_committed_verification(source_path, contents, selected, **kwargs):
        nonlocal verify_calls
        verify_calls += 1
        real_verify(source_path, contents, selected, **kwargs)
        if verify_calls == 2:
            raise ValueError("simulated committed verification failure")

    real_replace = atomic.os.replace

    def fail_backup_restore(source, target):
        if str(source).endswith(".backup") and Path(target) == output:
            raise OSError("simulated rollback restoration failure")
        return real_replace(source, target)

    monkeypatch.setattr(sessions_module, "verify_anonymized_bytes", fail_committed_verification)
    monkeypatch.setattr(atomic.os, "replace", fail_backup_restore)

    with pytest.raises(SessionProblem) as caught:
        generate_remediation_outputs(session)

    backups = list(tmp_path.glob(".*.backup"))
    assert caught.value.code == "file_unavailable"
    assert len(backups) == 1
    assert str(backups[0]) not in caught.value.message
    assert "remediation panel" in caught.value.message
    assert backups[0].read_bytes() == previous_bytes
    assert session.generated_outputs[str(path)].finding_ids == (first_id,)
    assert remediation_plan(session).retained_artifact_paths == [str(backups[0])]


def test_rollback_refuses_to_delete_externally_changed_new_output(monkeypatch, tmp_path):
    path = tmp_path / "secrets.py"
    path.write_text('ssn = "123-45-6789"\n')
    request, result = _scan_file(path)
    session = ScanSessionStore().create(request, result)
    update_remediation_plan(session, [result.findings[0].id], [])
    output = tmp_path / "secrets-auto-redacted-copy.py"
    real_verify = sessions_module.verify_anonymized_bytes
    verify_calls = 0
    external_bytes: bytes | None = None

    def change_published_output_before_failure(source_path, contents, findings, **kwargs):
        nonlocal verify_calls, external_bytes
        verify_calls += 1
        if verify_calls == 2:
            published = atomic.capture_file_signature(output)
            external_bytes = b"X" * len(contents)
            output.write_bytes(external_bytes)
            os.utime(output, ns=(published.modified_ns, published.modified_ns))
            raise ValueError("simulated committed verification failure")
        real_verify(source_path, contents, findings, **kwargs)

    monkeypatch.setattr(
        sessions_module,
        "verify_anonymized_bytes",
        change_published_output_before_failure,
    )

    with pytest.raises(SessionProblem) as caught:
        generate_remediation_outputs(session)

    assert caught.value.code == "file_unavailable"
    assert str(output) not in caught.value.message
    assert "source folder" in caught.value.message
    assert external_bytes is not None
    assert output.read_bytes() == external_bytes
    assert session.generated_outputs == {}
    plan = remediation_plan(session)
    assert plan.files[0].output_state == "conflict"
    assert plan.can_generate is False


def test_failed_optional_rescan_is_not_reported_as_zero_findings(monkeypatch, tmp_path):
    path = tmp_path / "secrets.py"
    path.write_text('ssn = "123-45-6789"\n')
    request, result = _scan_file(path)
    session = ScanSessionStore().create(request, result)
    update_remediation_plan(session, [result.findings[0].id], [])

    def fail_rescan(*_args, **_kwargs):
        raise RuntimeError("simulated advisory rescan failure")

    monkeypatch.setattr(sessions_module, "core_scan", fail_rescan)

    response = generate_remediation_outputs(session)

    assert response.outputs[0].rescan_status == "failed"
    assert response.outputs[0].remaining_finding_count is None
    assert response.outputs[0].remaining_tier_a_count is None
    assert any("could not finish" in warning for warning in response.outputs[0].warnings)


def test_ai_refined_scope_reports_rescan_counts_unavailable(tmp_path):
    path = tmp_path / "secrets.py"
    path.write_text('ssn = "123-45-6789"\n')
    request, result = _scan_file(path)
    session = ScanSessionStore().create(request, result)
    session.ai_model = "local-test-model"
    update_remediation_plan(session, [result.findings[0].id], [])

    response = generate_remediation_outputs(session)
    output = response.outputs[0]

    assert output.rescan_status == "failed"
    assert output.remaining_finding_count is None
    assert output.remaining_tier_a_count is None
    assert any("could not reproduce" in warning for warning in output.warnings)


def test_requested_description_scope_stays_unavailable_without_retained_ai_result(tmp_path):
    path = tmp_path / "secrets.py"
    path.write_text('ssn = "123-45-6789"\ncodename = "RAVEN"\n')
    _, result = _scan_file(path)
    request = ScanRequest(
        paths=[str(path)],
        use_llm=True,
        user_targets=[UserTarget(kind="description", value="project codenames", category="custom")],
    )
    session = ScanSessionStore().create(request, result)
    update_remediation_plan(session, [result.findings[0].id], [])

    response = generate_remediation_outputs(session)
    output = response.outputs[0]

    assert "RAVEN" in Path(output.output_path).read_text()
    assert output.rescan_status == "failed"
    assert output.remaining_finding_count is None
    assert output.remaining_tier_a_count is None
    assert any("could not reproduce" in warning for warning in output.warnings)


def test_skipped_output_rescan_is_not_reported_as_zero(monkeypatch, tmp_path):
    path = tmp_path / "secrets.py"
    path.write_text('ssn = "123-45-6789"\n')
    request, result = _scan_file(path)
    session = ScanSessionStore().create(request, result)
    update_remediation_plan(session, [result.findings[0].id], [])

    def skip_rescan(rescan_request, *_args, **_kwargs):
        output_path = rescan_request.paths[0]
        return ScanResult(
            summary={"status": "complete", "incomplete": False},
            skipped_files=[
                SkippedFile(
                    path=output_path,
                    reason="simulated extraction failure",
                    code="extraction_failed",
                )
            ],
        )

    monkeypatch.setattr(sessions_module, "core_scan", skip_rescan)

    response = generate_remediation_outputs(session)
    output = response.outputs[0]

    assert output.rescan_status == "failed"
    assert output.remaining_finding_count is None
    assert output.remaining_tier_a_count is None
    assert any("did not completely process" in warning for warning in output.warnings)


def test_expiration_does_not_clear_a_locked_file_workflow(tmp_path):
    path = tmp_path / "secrets.py"
    path.write_text('ssn = "123-45-6789"\n')
    request, result = _scan_file(path)
    clock = FakeClock()
    store = ScanSessionStore(idle_timeout_seconds=1, clock=clock)
    session = store.create(request, result)
    clock.advance(2)
    entered = threading.Event()
    release = threading.Event()

    def hold_workflow_lock():
        with session.workflow_lock:
            entered.set()
            release.wait(timeout=2)

    worker = threading.Thread(target=hold_workflow_lock)
    worker.start()
    assert entered.wait(timeout=1)
    try:
        assert store.prune_expired() == 0
        assert session.internal_findings
    finally:
        release.set()
        worker.join(timeout=1)

    assert store.touch(session) is True
    assert store.session_count == 1


def test_remediation_state_growth_cannot_exceed_store_limit(tmp_path):
    path = tmp_path / "secrets.py"
    path.write_text('ssn = "123-45-6789"\n')
    request, result = _scan_file(path)
    store = ScanSessionStore()
    session = store.create(request, result)
    finding_id = result.findings[0].id
    store.max_retained_bytes = session.estimated_bytes

    with pytest.raises(SessionProblem) as error:
        update_remediation_plan(session, [finding_id], [])

    assert error.value.code == "session_capacity"
    assert store.session_count == 0
    assert store.retained_bytes == 0
    assert session.internal_findings == {}


def test_generated_output_metadata_fits_pre_reserved_store_limit(tmp_path):
    path = tmp_path / "secrets.py"
    path.write_text('ssn = "123-45-6789"\n')
    request, result = _scan_file(path)
    store = ScanSessionStore()
    session = store.create(request, result)
    finding_id = result.findings[0].id
    update_remediation_plan(session, [finding_id], [])
    store.max_retained_bytes = session.estimated_bytes

    response = generate_remediation_outputs(session)

    assert response.outputs
    assert store.session_count == 1
    assert store.retained_bytes <= store.max_retained_bytes
    assert session.generated_outputs


def test_generated_output_metadata_tracks_only_findings_for_each_file(tmp_path):
    first_path = tmp_path / "first.py"
    second_path = tmp_path / "second.py"
    first_path.write_text('ssn = "123-45-6789"\n')
    second_path.write_text('ssn = "987-65-4321"\n')
    request = ScanRequest(paths=[str(tmp_path)])
    result = scan(request, load_default_registry())
    store = ScanSessionStore()
    session = store.create(request, result)

    update_remediation_plan(session, [finding.id for finding in result.findings], [])
    generate_remediation_outputs(session)

    for finding in result.findings:
        assert session.generated_outputs[finding.file_path].finding_ids == (finding.id,)


def test_selection_changes_require_one_complete_regeneration_from_original(tmp_path):
    path = tmp_path / "secrets.txt"
    path.write_text("password = FirstSecret123!\nssn = 123-45-6789\n")
    request, result = _scan_file(path)
    findings = {finding.detector_id: finding for finding in result.findings}
    password = findings["password_assignment"]
    ssn = findings["us_ssn"]
    session = ScanSessionStore().create(request, result)

    update_remediation_plan(session, [password.id], [])
    first = generate_remediation_outputs(session)
    assert "FirstSecret123!" not in Path(first.outputs[0].output_path).read_text()

    changed = update_remediation_plan(session, [password.id, ssn.id], [])
    assert changed.files[0].output_state == "regeneration_required"
    second = generate_remediation_outputs(session)
    redacted = Path(second.outputs[0].output_path).read_text()

    assert "FirstSecret123!" not in redacted
    assert "123-45-6789" not in redacted
    assert second.plan.files[0].output_state == "current"
    assert session.generated_outputs[str(path)].finding_ids == (password.id, ssn.id)


def test_removing_a_selection_regenerates_from_the_original(tmp_path):
    path = tmp_path / "secrets.txt"
    path.write_text("password = FirstSecret123!\nssn = 123-45-6789\n")
    request, result = _scan_file(path)
    findings = {finding.detector_id: finding for finding in result.findings}
    password = findings["password_assignment"]
    ssn = findings["us_ssn"]
    session = ScanSessionStore().create(request, result)

    update_remediation_plan(session, [password.id, ssn.id], [])
    first = generate_remediation_outputs(session)
    first_contents = Path(first.outputs[0].output_path).read_text()
    assert "FirstSecret123!" not in first_contents
    assert "123-45-6789" not in first_contents

    changed = update_remediation_plan(session, [ssn.id], [])
    assert changed.files[0].output_state == "regeneration_required"
    second = generate_remediation_outputs(session)
    redacted = Path(second.outputs[0].output_path).read_text()

    assert "FirstSecret123!" in redacted
    assert "123-45-6789" not in redacted
    assert second.plan.files[0].output_state == "current"
    assert session.generated_outputs[str(path)].finding_ids == (ssn.id,)


def test_fully_deselected_generated_file_is_obsolete_not_endlessly_regenerable(tmp_path):
    first_path = tmp_path / "first.txt"
    second_path = tmp_path / "second.txt"
    first_path.write_text("ssn = 123-45-6789\n")
    second_path.write_text("ssn = 987-65-4321\n")
    request = ScanRequest(paths=[str(first_path), str(second_path)])
    result = scan(request, load_default_registry())
    findings = {finding.file_path: finding for finding in result.findings}
    session = ScanSessionStore().create(request, result)

    update_remediation_plan(session, [finding.id for finding in findings.values()], [])
    generate_remediation_outputs(session)

    update_remediation_plan(session, [findings[str(second_path)].id], [])
    regenerated = generate_remediation_outputs(session)
    states = {Path(file.source_path).name: file.output_state for file in regenerated.plan.files}

    assert states == {"second.txt": "current", "first.txt": "obsolete"}
    assert regenerated.plan.can_review is True
    assert regenerated.plan.can_generate is True


def test_externally_changed_output_has_conflict_state(tmp_path):
    path = tmp_path / "secrets.txt"
    path.write_text("ssn = 123-45-6789\n")
    request, result = _scan_file(path)
    session = ScanSessionStore().create(request, result)
    update_remediation_plan(session, [result.findings[0].id], [])
    generated = generate_remediation_outputs(session)
    Path(generated.outputs[0].output_path).write_text("changed outside RedactLens\n")

    plan = remediation_plan(session)

    assert plan.files[0].output_state == "conflict"
    assert plan.can_review is True
    assert plan.can_generate is False


def test_preexisting_unowned_output_projects_conflict_before_generation(tmp_path):
    path = tmp_path / "secrets.py"
    path.write_text('ssn = "123-45-6789"\n')
    output = tmp_path / "secrets-auto-redacted-copy.py"
    output.write_text("belongs to another process\n")
    request, result = _scan_file(path)
    session = ScanSessionStore().create(request, result)
    update_remediation_plan(session, [result.findings[0].id], [])

    plan = remediation_plan(session)

    assert plan.files[0].output_path == str(output)
    assert plan.files[0].output_state == "conflict"
    assert plan.can_review is True
    assert plan.can_generate is False


def test_output_rescan_reuses_original_literal_target_scope(tmp_path):
    target = "ACME-PRIVATE-VALUE"
    path = tmp_path / "custom.txt"
    path.write_text(f"{target}\n{target}\n")
    request = ScanRequest(
        paths=[str(path)],
        user_targets=[UserTarget(kind="literal", value=target, category="custom")],
    )
    result = scan(request, load_default_registry())
    findings = [finding for finding in result.findings if finding.detector_id == "user_target_0"]
    assert len(findings) == 2
    session = ScanSessionStore().create(request, result)
    update_remediation_plan(session, [findings[0].id], [findings[1].id])

    generated = generate_remediation_outputs(session)
    output = generated.outputs[0]

    assert target in Path(output.output_path).read_text()
    assert output.rescan_status == "completed"
    assert output.remaining_finding_count == 1
    assert output.remaining_tier_a_count == 1


def test_source_change_after_render_is_rejected_before_commit(monkeypatch, tmp_path):
    path = tmp_path / "secrets.py"
    path.write_text('ssn = "123-45-6789"\n')
    request, result = _scan_file(path)
    session = ScanSessionStore().create(request, result)
    update_remediation_plan(session, [result.findings[0].id], [])
    real_verify = sessions_module.verify_anonymized_bytes
    changed = False

    def verify_then_change_source(source_path, contents, findings, **kwargs):
        nonlocal changed
        real_verify(source_path, contents, findings, **kwargs)
        if not changed:
            changed = True
            path.write_text('ssn = "987-65-4321"\n')

    monkeypatch.setattr(sessions_module, "verify_anonymized_bytes", verify_then_change_source)

    with pytest.raises(SessionProblem) as error:
        generate_remediation_outputs(session)

    assert error.value.code == "file_changed"
    assert not (tmp_path / "secrets-auto-redacted-copy.py").exists()
    assert session.generated_outputs == {}


def test_exclude_and_ignore_have_distinct_plan_states(tmp_path):
    path = tmp_path / "secrets.txt"
    path.write_text("password = FirstSecret123!\nssn = 123-45-6789\n")
    request, result = _scan_file(path)
    first, second = result.findings[:2]
    store = ScanSessionStore()
    session = store.create(request, result)

    plan = update_remediation_plan(session, [first.id], [second.id])
    states = {item.finding_id: item.state for item in plan.findings}
    assert states[first.id] == "included"
    assert states[second.id] == "ignored"

    plan = update_remediation_plan(session, [], [second.id])
    states = {item.finding_id: item.state for item in plan.findings}
    assert states[first.id] == "pending"
    assert states[second.id] == "ignored"


def test_initial_plan_marks_non_rewritable_findings_read_only(tmp_path):
    path = tmp_path / "secrets.txt"
    path.write_text('ssn = "123-45-6789"\n')
    request, result = _scan_file(path)
    result.findings[0].can_anonymize = False
    store = ScanSessionStore()
    session = store.create(request, result)

    plan = remediation_plan(session)

    assert plan.findings[0].state == "read_only"
    assert plan.read_only_finding_count == 1
    assert plan.can_generate is False


def test_fingerprint_contains_resolved_path_size_timestamp_and_hash(tmp_path):
    path = tmp_path / "data.txt"
    path.write_text("hello")

    fingerprint = FileFingerprint.capture(str(path))

    assert fingerprint.resolved_path == str(path.resolve())
    assert fingerprint.device == path.stat().st_dev
    assert fingerprint.inode == path.stat().st_ino
    assert fingerprint.size == 5
    assert fingerprint.modified_ns == path.stat().st_mtime_ns
    assert fingerprint.changed_ns == path.stat().st_ctime_ns
    assert len(fingerprint.sha256) == 64
