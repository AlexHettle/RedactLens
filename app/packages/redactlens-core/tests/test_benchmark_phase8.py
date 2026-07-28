from __future__ import annotations

import copy
import json
import subprocess
import sys

import pytest
from tooling.scripts import benchmark_phase8 as benchmark


def _changed_large_text_recipe(root, sizes_mb):
    """Test-only generator body whose source represents recipe drift."""

    return root / f"changed-large-text-{len(sizes_mb)}"


def _environment() -> dict:
    return {
        "python_version": "3.12.0",
        "python_implementation": "CPython",
        "platform": "TestOS-1",
        "machine": "test-machine",
        "processor": "test-processor",
        "logical_cpu_count": 4,
        "dependencies": {
            "defusedxml": "0.7.1",
            "lxml": "6.0.0",
            "ollama": "0.6.0",
            "pydantic": "2.13.0",
            "pypdf": "6.0.0",
            "PyYAML": "6.0.0",
            "regex": "2026.1.1",
        },
    }


def _measurements(
    profile: str,
    *,
    wall_ms: int = 100,
    peak_memory_bytes: int | None = 1_000,
) -> dict:
    measurements = {}
    for name, spec in benchmark.workload_manifest(profile).items():
        memory_samples = (
            [peak_memory_bytes - 2, peak_memory_bytes, peak_memory_bytes - 1]
            if peak_memory_bytes is not None
            else [None, None, None]
        )
        measurements[name] = {
            "wall_ms": wall_ms,
            "wall_samples_ms": [wall_ms + 1, wall_ms - 1, wall_ms],
            "peak_memory_bytes": peak_memory_bytes,
            "peak_memory_samples_bytes": memory_samples,
            "findings": spec["expected_findings"],
            "summary": {
                "total_files": spec["expected_total_files"],
                "completed_files": spec["expected_total_files"],
                "files_scanned": spec["expected_scanned_files"],
                "files_skipped": spec["expected_skipped_files"],
                "total_findings": spec["expected_findings"],
                "canonical_findings": spec["expected_findings"],
                "raw_detector_hits": spec["expected_findings"],
                "consolidated_hits": 0,
                "suppressed_hits": 0,
                "raw_detector_hits_by_detector": {"test_detector": spec["expected_findings"]},
                "tier_counts": {"A": spec["expected_findings"]},
                "category_counts": {"test": spec["expected_findings"]},
                "status": "complete",
                "incomplete": False,
                "duration_ms": wall_ms,
                "peak_memory_bytes": peak_memory_bytes,
                "bytes_scanned": spec["expected_scanned_files"] * 10,
                "files_per_second": round(spec["expected_total_files"] / (wall_ms / 1_000), 3),
                "megabytes_per_second": round(
                    (spec["expected_scanned_files"] * 10) / 1_000_000 / (wall_ms / 1_000),
                    3,
                ),
                "extraction_seconds": 0.01,
                "detection_seconds": 0.02,
                "llm_seconds": 0.0,
                "llm_attempts": 0,
                "llm_successes": 0,
                "llm_failures": 0,
            },
        }
    return measurements


def _report(
    profile: str = "quick",
    *,
    wall_ms: int = 100,
    peak_memory_bytes: int | None = 1_000,
) -> dict:
    return benchmark.build_report(
        profile,
        3,
        _measurements(
            profile,
            wall_ms=wall_ms,
            peak_memory_bytes=peak_memory_bytes,
        ),
        generated_at="2026-07-17T12:00:00Z",
        environment=_environment(),
    )


def test_report_schema_records_reproducibility_metadata_and_exact_workloads():
    report = _report("full")

    assert report["schema_version"] == 2
    assert report["generated_at"].endswith("Z")
    assert len(report["source_digest"]) == 64
    assert report["fixture_digest"] == benchmark.fixture_digest("full")
    assert report["environment"] == _environment()
    assert report["repetitions"] == 3
    assert set(report["measurements"]) == set(report["workloads"])
    assert benchmark.validate_report(report) is report


def test_environment_metadata_tracks_regex_engine_version():
    metadata = benchmark.environment_metadata()

    assert metadata["dependencies"]["regex"] != "unavailable"


def test_report_validation_rejects_missing_or_extra_workloads():
    missing = _report()
    missing["measurements"].pop(next(iter(missing["measurements"])))
    extra = _report()
    extra["measurements"]["unplanned"] = copy.deepcopy(next(iter(extra["measurements"].values())))

    with pytest.raises(benchmark.BenchmarkReportError, match="every workload exactly once"):
        benchmark.validate_report(missing)
    with pytest.raises(benchmark.BenchmarkReportError, match="every workload exactly once"):
        benchmark.validate_report(extra)


def test_comparison_rejects_profile_and_environment_mismatch():
    with pytest.raises(benchmark.BenchmarkReportError, match="incompatible profile"):
        benchmark.compare_reports(
            _report("quick"),
            _report("full"),
            max_regression_percent=20,
            max_memory_regression_percent=20,
        )

    current = _report()
    baseline = _report()
    current["environment"]["python_version"] = "3.13.0"
    with pytest.raises(benchmark.BenchmarkReportError, match="incompatible environment"):
        benchmark.compare_reports(
            current,
            baseline,
            max_regression_percent=20,
            max_memory_regression_percent=20,
        )


def test_comparison_gates_median_wall_time_and_peak_memory():
    failures = benchmark.compare_reports(
        _report(wall_ms=126, peak_memory_bytes=1_201),
        _report(wall_ms=100, peak_memory_bytes=1_000),
        max_regression_percent=20,
        max_memory_regression_percent=20,
    )

    assert any("median wall time" in failure for failure in failures)
    assert any("peak memory" in failure for failure in failures)


def test_comparison_uses_absolute_noise_allowance_for_tiny_workloads():
    baseline = _report(wall_ms=9)

    within_noise = benchmark.compare_reports(
        _report(wall_ms=34),
        baseline,
        max_regression_percent=20,
        max_memory_regression_percent=20,
    )
    beyond_noise = benchmark.compare_reports(
        _report(wall_ms=35),
        baseline,
        max_regression_percent=20,
        max_memory_regression_percent=20,
    )

    assert not any("median wall time" in failure for failure in within_noise)
    assert all("25 ms noise budget" in failure for failure in beyond_noise)


def test_comparison_rejects_memory_availability_drift():
    failures = benchmark.compare_reports(
        _report(peak_memory_bytes=None),
        _report(peak_memory_bytes=1_000),
        max_regression_percent=20,
        max_memory_regression_percent=20,
    )

    assert failures == [
        f"{name}: peak-memory availability differs from the baseline"
        for name in benchmark.workload_manifest("quick")
    ]


def test_measurement_uses_isolated_repetitions_median_and_maximum_memory(monkeypatch, tmp_path):
    manifest = benchmark.workload_manifest("quick")
    name = next(iter(manifest))
    spec = manifest[name]
    responses = iter(
        [
            (300, 1_000),
            (100, 1_200),
            (200, 1_100),
        ]
    )

    def isolated(_fixture, workload_name, profile):
        wall_ms, memory = next(responses)
        assert workload_name == name
        assert profile == "quick"
        return {
            "wall_ms": wall_ms,
            "peak_memory_bytes": memory,
            "findings": spec["expected_findings"],
            "summary": {
                "total_files": spec["expected_total_files"],
                "completed_files": spec["expected_total_files"],
                "files_scanned": spec["expected_scanned_files"],
                "files_skipped": spec["expected_skipped_files"],
                "total_findings": spec["expected_findings"],
                "status": "complete",
                "incomplete": False,
            },
            "functional_digest": "a" * 64,
        }

    monkeypatch.setattr(benchmark, "_run_isolated_measurement", isolated)

    measured = benchmark.measure(
        {name: tmp_path / name},
        manifest,
        profile="quick",
        repetitions=3,
    )[name]

    assert measured["wall_ms"] == 200
    assert measured["wall_samples_ms"] == [300, 100, 200]
    assert measured["peak_memory_bytes"] == 1_200
    assert measured["peak_memory_samples_bytes"] == [1_000, 1_200, 1_100]


def test_isolated_measurement_invokes_worker_subprocess(monkeypatch, tmp_path):
    fixture = tmp_path / "small_100"
    fixture.mkdir()
    payload = {
        "wall_ms": 10,
        "peak_memory_bytes": 1_000,
        "findings": 1,
        "summary": {},
        "functional_digest": "b" * 64,
    }
    observed_command: list[str] = []

    def completed(command, **kwargs):
        observed_command.extend(command)
        assert kwargs["timeout"] == benchmark.WORKER_TIMEOUT_SECONDS
        assert kwargs["capture_output"] is True
        return subprocess.CompletedProcess(command, 0, json.dumps(payload), "")

    monkeypatch.setattr(benchmark.subprocess, "run", completed)

    assert benchmark._run_isolated_measurement(fixture, "small_100", "quick") == payload
    assert observed_command[1:3] == ["-m", "tooling.scripts.benchmark_phase8"]
    assert "--worker" in observed_command
    assert str(fixture) in observed_command


def test_output_and_baseline_alias_is_rejected_before_any_benchmark_run(monkeypatch, tmp_path):
    baseline = tmp_path / "baseline.json"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "benchmark_phase8.py",
            "--output",
            str(baseline),
            "--baseline",
            str(baseline),
        ],
    )

    with pytest.raises(SystemExit) as error:
        benchmark.main()

    assert error.value.code == 2
    assert not baseline.exists()


def test_freshness_accepts_current_evidence_and_rejects_source_drift(tmp_path):
    path = tmp_path / "benchmark.json"
    report = _report("full")
    path.write_text(json.dumps(report), encoding="utf-8")

    fresh, message = benchmark.check_report_fresh(path)

    assert fresh, message

    report["source_digest"] = "0" * 64
    path.write_text(json.dumps(report), encoding="utf-8")
    fresh, message = benchmark.check_report_fresh(path)

    assert fresh is False
    assert "source digest is stale" in message


def test_freshness_rejects_fixture_drift_and_non_full_evidence(tmp_path):
    path = tmp_path / "benchmark.json"
    report = _report("full")
    report["fixture_digest"] = "0" * 64
    path.write_text(json.dumps(report), encoding="utf-8")

    fresh, message = benchmark.check_report_fresh(path)

    assert fresh is False
    assert "fixture digest" in message

    path.write_text(json.dumps(_report("quick")), encoding="utf-8")
    fresh, message = benchmark.check_report_fresh(path)

    assert fresh is False
    assert "must use the 'full' profile" in message


def test_report_validation_rejects_non_median_samples_and_legacy_schema():
    report = _report()
    measurement = next(iter(report["measurements"].values()))
    measurement["wall_ms"] = 999

    with pytest.raises(benchmark.BenchmarkReportError, match="wall median is inconsistent"):
        benchmark.validate_report(report)
    with pytest.raises(benchmark.BenchmarkReportError, match="schema version 2"):
        benchmark.validate_report({"profile": "full", "measurements": {}})


@pytest.mark.parametrize("value", [float("nan"), float("inf"), -1.0, None, True, "20"])
def test_comparison_rejects_invalid_regression_percentages(value):
    with pytest.raises(benchmark.BenchmarkReportError, match="finite and non-negative"):
        benchmark.compare_reports(
            _report(),
            _report(),
            max_regression_percent=value,
            max_memory_regression_percent=20,
        )


@pytest.mark.parametrize("value", [float("nan"), float("inf"), -1.0, None, True, "20"])
def test_comparison_rejects_invalid_wall_time_noise_allowance(value):
    with pytest.raises(benchmark.BenchmarkReportError, match="finite and non-negative"):
        benchmark.compare_reports(
            _report(),
            _report(),
            max_regression_percent=20,
            max_memory_regression_percent=20,
            wall_time_noise_ms=value,
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("total_findings", -1),
        ("canonical_findings", True),
        ("raw_detector_hits", "1"),
        ("consolidated_hits", 0.5),
        ("suppressed_hits", -1),
        ("files_scanned", False),
        ("files_skipped", -1),
        ("completed_files", 1.5),
        ("total_files", "100"),
        ("duration_ms", True),
        ("bytes_scanned", "incorrect"),
        ("files_per_second", "not-a-number"),
        ("megabytes_per_second", -999),
        ("extraction_seconds", None),
        ("detection_seconds", float("nan")),
        ("llm_seconds", float("inf")),
        ("llm_attempts", 0.5),
        ("llm_successes", -1),
        ("llm_failures", False),
    ],
)
def test_report_validation_rejects_malformed_summary_metrics(field, value):
    report = _report()
    summary = next(iter(report["measurements"].values()))["summary"]
    summary[field] = value

    with pytest.raises(benchmark.BenchmarkReportError):
        benchmark.validate_report(report)


def test_report_validation_requires_every_summary_metric_exactly_once():
    missing = _report()
    next(iter(missing["measurements"].values()))["summary"].pop("duration_ms")
    extra = _report()
    next(iter(extra["measurements"].values()))["summary"]["unplanned_metric"] = 1

    for report in (missing, extra):
        with pytest.raises(benchmark.BenchmarkReportError, match="summary fields"):
            benchmark.validate_report(report)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("raw_detector_hits_by_detector", []),
        ("raw_detector_hits_by_detector", {"test_detector": True}),
        ("tier_counts", {"": 1}),
        ("category_counts", {"test": -1}),
    ],
)
def test_report_validation_rejects_malformed_counter_maps(field, value):
    report = _report()
    summary = next(iter(report["measurements"].values()))["summary"]
    summary[field] = value

    with pytest.raises(benchmark.BenchmarkReportError):
        benchmark.validate_report(report)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("wall_ms", True),
        ("findings", True),
        ("peak_memory_bytes", True),
    ],
)
def test_report_validation_rejects_non_integer_measurement_metrics(field, value):
    report = _report()
    measurement = next(iter(report["measurements"].values()))
    measurement[field] = value

    with pytest.raises(benchmark.BenchmarkReportError):
        benchmark.validate_report(report)


def test_report_validation_rejects_invalid_wall_and_memory_samples():
    invalid_wall = _report()
    next(iter(invalid_wall["measurements"].values()))["wall_samples_ms"][0] = -1
    invalid_memory = _report()
    next(iter(invalid_memory["measurements"].values()))["peak_memory_samples_bytes"][0] = False

    with pytest.raises(benchmark.BenchmarkReportError, match="wall sample"):
        benchmark.validate_report(invalid_wall)
    with pytest.raises(benchmark.BenchmarkReportError, match="memory sample"):
        benchmark.validate_report(invalid_memory)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("incomplete", 0, "must be a boolean"),
        ("status", 1, "must be a string"),
        ("peak_memory_bytes", None, "not a recorded sample"),
    ],
)
def test_report_validation_rejects_deceptively_equal_or_unrecorded_values(field, value, message):
    report = _report()
    summary = next(iter(report["measurements"].values()))["summary"]
    summary[field] = value

    with pytest.raises(benchmark.BenchmarkReportError, match=message):
        benchmark.validate_report(report)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("canonical_findings", 2, "canonical finding count"),
        ("raw_detector_hits", 2, "raw detector count"),
        ("suppressed_hits", 1, "suppressed finding count"),
        ("raw_detector_hits_by_detector", {"test_detector": 2}, "detector counter"),
        ("tier_counts", {"A": 2}, "tier counter"),
        ("category_counts", {"test": 2}, "category counter"),
        ("llm_attempts", 1, "LLM attempt counts"),
        ("duration_ms", 101, "exceeds measured wall time"),
        ("files_per_second", 0, "throughput must be positive"),
    ],
)
def test_report_validation_rejects_summary_invariant_drift(field, value, message):
    report = _report()
    summary = next(iter(report["measurements"].values()))["summary"]
    summary[field] = value

    with pytest.raises(benchmark.BenchmarkReportError, match=message):
        benchmark.validate_report(report)


def test_report_validation_requires_exact_dependency_metadata():
    missing = _report()
    missing["environment"]["dependencies"] = {}
    extra = _report()
    extra["environment"]["dependencies"]["unexpected"] = "1.0"
    invalid_version = _report()
    invalid_version["environment"]["dependencies"]["regex"] = ""

    for report in (missing, extra):
        with pytest.raises(benchmark.BenchmarkReportError, match="metadata is incomplete"):
            benchmark.validate_report(report)
    with pytest.raises(benchmark.BenchmarkReportError, match="metadata is invalid"):
        benchmark.validate_report(invalid_version)


@pytest.mark.parametrize("value", [True, False, 0, -1, 1.5, "4"])
def test_report_validation_requires_positive_non_boolean_cpu_count(value):
    report = _report()
    report["environment"]["logical_cpu_count"] = value

    with pytest.raises(benchmark.BenchmarkReportError, match="positive integer"):
        benchmark.validate_report(report)


def test_fixture_digest_tracks_generator_drift_but_not_validator_changes(monkeypatch):
    baseline = _report()
    original_digest = baseline["fixture_digest"]

    monkeypatch.setattr(benchmark, "_validate_timestamp", lambda _value: None)
    assert benchmark.fixture_digest("quick") == original_digest

    monkeypatch.setattr(benchmark, "_large_text", _changed_large_text_recipe)
    changed_digest = benchmark.fixture_digest("quick")
    assert changed_digest != original_digest
    current = _report()

    with pytest.raises(benchmark.BenchmarkReportError, match="fixture digest"):
        benchmark.compare_reports(
            current,
            baseline,
            max_regression_percent=20,
            max_memory_regression_percent=20,
        )
