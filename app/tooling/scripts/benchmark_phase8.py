"""Generate, validate, and compare the Phase 8 performance workloads.

Normal verification uses ``--check-baseline`` to validate the checked-in
evidence without rerunning the full benchmark. Performance runs use an odd
number of repetitions and compare only reports with identical fixture and
environment metadata.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import inspect
import io
import json
import math
import os
import platform
import re
import statistics
import subprocess
import sys
import tempfile
import time
import zipfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from redactlens_core.models import ScanOptions, ScanRequest, ScanResult
from redactlens_core.registry import load_default_registry
from redactlens_core.scanner import scan

SCHEMA_VERSION = 2
DEFAULT_REPETITIONS = 3
DEFAULT_REGRESSION_PERCENT = 20.0
DEFAULT_WALL_TIME_NOISE_MS = 25.0
WORKER_TIMEOUT_SECONDS = 10 * 60
PROJECT_ROOT = Path(__file__).resolve().parents[2]
CHECKED_BASELINE = PROJECT_ROOT / "docs" / "phase-8-benchmark.json"
_DIGEST = re.compile(r"[0-9a-f]{64}")
_SUMMARY_TIMING_KEYS = {
    "duration_ms",
    "peak_memory_bytes",
    "files_per_second",
    "megabytes_per_second",
    "extraction_seconds",
    "detection_seconds",
    "llm_seconds",
}
_SUMMARY_KEYS = {
    "total_findings",
    "canonical_findings",
    "raw_detector_hits",
    "consolidated_hits",
    "suppressed_hits",
    "raw_detector_hits_by_detector",
    "tier_counts",
    "category_counts",
    "files_scanned",
    "files_skipped",
    "completed_files",
    "total_files",
    "status",
    "incomplete",
    "duration_ms",
    "peak_memory_bytes",
    "bytes_scanned",
    "files_per_second",
    "megabytes_per_second",
    "extraction_seconds",
    "detection_seconds",
    "llm_seconds",
    "llm_attempts",
    "llm_successes",
    "llm_failures",
}
_DEPENDENCY_NAMES = {
    "defusedxml",
    "lxml",
    "ollama",
    "pydantic",
    "pypdf",
    "PyYAML",
    "regex",
}
_ENVIRONMENT_KEYS = {
    "python_version",
    "python_implementation",
    "platform",
    "machine",
    "processor",
    "logical_cpu_count",
    "dependencies",
}
_FIXTURE_RECIPE_FUNCTIONS = (
    "_small_files",
    "_large_text",
    "_large_docx",
    "_zip_bytes",
    "_nested_archives",
    "_binary_directory",
    "generate",
)


class BenchmarkReportError(ValueError):
    """A benchmark report is malformed, stale, or incompatible."""


def workload_manifest(profile: str) -> dict[str, dict[str, Any]]:
    """Return the canonical, JSON-serializable workload definition."""

    if profile not in {"quick", "full"}:
        raise BenchmarkReportError(f"unknown benchmark profile: {profile}")
    full = profile == "full"
    manifest: dict[str, dict[str, Any]] = {}
    small_counts = (1_000, 10_000) if full else (100,)
    for count in small_counts:
        manifest[f"small_{count}"] = {
            "kind": "small_files",
            "count": count,
            "expected_total_files": count,
            "expected_scanned_files": count,
            "expected_skipped_files": 0,
            "expected_findings": (count + 499) // 500,
        }
    text_sizes = [5, 10, 50] if full else [5]
    manifest["large_text"] = {
        "kind": "large_text",
        "sizes_mb": text_sizes,
        "expected_total_files": len(text_sizes),
        "expected_scanned_files": len(text_sizes),
        "expected_skipped_files": 0,
        "expected_findings": len(text_sizes),
    }
    paragraphs = 80_000 if full else 5_000
    manifest["large_office"] = {
        "kind": "large_docx",
        "paragraphs": paragraphs,
        "expected_total_files": 1,
        "expected_scanned_files": 1,
        "expected_skipped_files": 0,
        "expected_findings": 1,
    }
    manifest["nested_archives"] = {
        "kind": "nested_archives",
        "depth": 2,
        "expected_total_files": 1,
        "expected_scanned_files": 1,
        "expected_skipped_files": 0,
        "expected_findings": 1,
    }
    binary_count = 500 if full else 50
    manifest["mostly_binary"] = {
        "kind": "mostly_binary",
        "binary_files": binary_count,
        "bytes_per_binary": 65_536,
        "expected_total_files": binary_count + 1,
        "expected_scanned_files": 1,
        "expected_skipped_files": binary_count,
        "expected_findings": 1,
    }
    return manifest


def _canonical_digest(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def fixture_digest(profile: str) -> str:
    """Hash the workload declaration and deterministic fixture recipe.

    Scanner and report-validation changes belong to ``source_digest`` but do
    not change fixture compatibility. Hashing only these generator functions
    lets report comparisons reject actual recipe drift without treating an
    unrelated validator refactor as a different workload.
    """

    recipe: dict[str, str] = {}
    for name in _FIXTURE_RECIPE_FUNCTIONS:
        function = globals().get(name)
        if not callable(function):
            raise BenchmarkReportError(f"fixture generator is missing: {name}")
        try:
            source = inspect.getsource(function)
        except (OSError, TypeError) as error:
            raise BenchmarkReportError(
                f"fixture generator source is unavailable: {name}"
            ) from error
        recipe[name] = source.replace("\r\n", "\n").replace("\r", "\n")
    return _canonical_digest(
        {
            "workloads": workload_manifest(profile),
            "recipe": recipe,
        }
    )


def source_digest(project_root: Path = PROJECT_ROOT) -> str:
    """Hash the benchmark driver and all core scan/detector sources."""

    candidates = {
        project_root / "tooling" / "scripts" / "benchmark_phase8.py",
        project_root / "pyproject.toml",
        project_root / "packages" / "redactlens-core" / "pyproject.toml",
    }
    core = project_root / "packages" / "redactlens-core" / "redactlens_core"
    for suffix in ("*.py", "*.yaml", "*.yml"):
        candidates.update(core.rglob(suffix))

    digest = hashlib.sha256()
    for path in sorted(candidates, key=lambda item: item.as_posix()):
        if not path.is_file():
            raise BenchmarkReportError(f"benchmark source is missing: {path}")
        relative = path.relative_to(project_root).as_posix().encode("utf-8")
        contents = path.read_bytes()
        digest.update(len(relative).to_bytes(4, "big"))
        digest.update(relative)
        digest.update(len(contents).to_bytes(8, "big"))
        digest.update(contents)
    return digest.hexdigest()


def environment_metadata() -> dict[str, Any]:
    dependencies: dict[str, str] = {}
    for distribution in sorted(_DEPENDENCY_NAMES, key=str.casefold):
        try:
            dependencies[distribution] = importlib.metadata.version(distribution)
        except importlib.metadata.PackageNotFoundError:
            dependencies[distribution] = "unavailable"
    return {
        "python_version": platform.python_version(),
        "python_implementation": platform.python_implementation(),
        "platform": platform.platform(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "logical_cpu_count": max(1, os.cpu_count() or 1),
        "dependencies": dependencies,
    }


def _small_files(root: Path, count: int) -> Path:
    target = root / f"small_{count}"
    target.mkdir()
    for index in range(count):
        content = f"record={index}\nstatus=clean\n"
        if index % 500 == 0:
            content += f"ssn = 123-45-{index % 10_000:04d}\n"
        (target / f"record_{index:05d}.txt").write_text(content, encoding="utf-8")
    return target


def _large_text(root: Path, sizes_mb: list[int]) -> Path:
    target = root / "large_text"
    target.mkdir()
    block = ("ordinary application log line without sensitive values\n" * 2_000).encode()
    for size_mb in sizes_mb:
        path = target / f"log_{size_mb}mb.txt"
        remaining = size_mb * 1_000_000
        with path.open("wb") as stream:
            while remaining > 0:
                piece = block[:remaining]
                stream.write(piece)
                remaining -= len(piece)
            stream.write(b"\nssn = 123-45-6789\n")
    return target


def _large_docx(root: Path, paragraphs: int) -> Path:
    target = root / "large_office"
    target.mkdir()
    paragraph = (
        "<w:p><w:r><w:t>Quarterly operational record %08d without private data</w:t></w:r></w:p>"
    )
    body = "".join(paragraph % index for index in range(paragraphs))
    body += "<w:p><w:r><w:t>ssn = 123-45-6789</w:t></w:r></w:p>"
    document = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
        f"<w:body>{body}</w:body></w:document>"
    ).encode()
    path = target / "large-report.docx"
    with zipfile.ZipFile(path, "w", zipfile.ZIP_STORED) as archive:
        archive.writestr("word/document.xml", document)
    return target


def _zip_bytes(entries: dict[str, bytes]) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data in entries.items():
            archive.writestr(name, data)
    return output.getvalue()


def _nested_archives(root: Path) -> Path:
    target = root / "nested_archives"
    target.mkdir()
    inner = _zip_bytes({"records/private.txt": b"ssn = 123-45-6789\n"})
    (target / "two-level.zip").write_bytes(_zip_bytes({"bundle/inner.zip": inner}))
    return target


def _binary_directory(root: Path, count: int) -> Path:
    target = root / "mostly_binary"
    target.mkdir()
    payload = bytes(range(256)) * 256
    for index in range(count):
        (target / f"asset_{index:04d}.bin").write_bytes(payload)
    (target / "readme.txt").write_text("ssn = 123-45-6789\n", encoding="utf-8")
    return target


def generate(root: Path, *, profile: str) -> dict[str, Path]:
    fixtures: dict[str, Path] = {}
    for name, spec in workload_manifest(profile).items():
        kind = spec["kind"]
        if kind == "small_files":
            fixture = _small_files(root, spec["count"])
        elif kind == "large_text":
            fixture = _large_text(root, spec["sizes_mb"])
        elif kind == "large_docx":
            fixture = _large_docx(root, spec["paragraphs"])
        elif kind == "nested_archives":
            fixture = _nested_archives(root)
        elif kind == "mostly_binary":
            fixture = _binary_directory(root, spec["binary_files"])
        else:  # pragma: no cover - the manifest is declared above
            raise BenchmarkReportError(f"unsupported workload kind: {kind}")
        if fixture.name != name:
            raise BenchmarkReportError(
                f"workload '{name}' generated unexpected directory '{fixture.name}'"
            )
        fixtures[name] = fixture
    return fixtures


def _functional_result(result: ScanResult) -> dict[str, Any]:
    summary = {
        key: value for key, value in result.summary.items() if key not in _SUMMARY_TIMING_KEYS
    }
    return {
        "findings": [finding.model_dump(mode="json") for finding in result.findings],
        "scanned_files": result.scanned_files,
        "skipped_files": [item.model_dump(mode="json") for item in result.skipped_files],
        "llm_used": result.llm_used,
        "summary": summary,
    }


def _validate_result(name: str, spec: dict[str, Any], result: ScanResult) -> None:
    summary = result.summary
    expected = {
        "total_files": spec["expected_total_files"],
        "completed_files": spec["expected_total_files"],
        "files_scanned": spec["expected_scanned_files"],
        "files_skipped": spec["expected_skipped_files"],
        "total_findings": spec["expected_findings"],
    }
    for field, value in expected.items():
        if summary.get(field) != value:
            raise BenchmarkReportError(
                f"workload '{name}' produced {field}={summary.get(field)!r}; expected {value}"
            )
    if summary.get("status") != "complete" or summary.get("incomplete") is not False:
        raise BenchmarkReportError(f"workload '{name}' did not complete")
    if len(result.findings) != spec["expected_findings"]:
        raise BenchmarkReportError(f"workload '{name}' produced an unexpected finding count")


def _worker_payload(fixture: Path, name: str, profile: str) -> dict[str, Any]:
    manifest = workload_manifest(profile)
    if name not in manifest:
        raise BenchmarkReportError(f"worker received unknown workload '{name}'")
    registry = load_default_registry()
    started = time.perf_counter()
    result = scan(
        ScanRequest(
            paths=[str(fixture)],
            options=ScanOptions(max_workers=4, document_workers=1),
        ),
        registry,
    )
    wall_ms = round((time.perf_counter() - started) * 1_000)
    _validate_result(name, manifest[name], result)
    peak = result.summary.get("peak_memory_bytes")
    memory = peak if isinstance(peak, int) and not isinstance(peak, bool) else None
    return {
        "wall_ms": wall_ms,
        "peak_memory_bytes": memory,
        "findings": len(result.findings),
        "summary": result.summary,
        "functional_digest": _canonical_digest(_functional_result(result)),
    }


def _isolated_worker_environment() -> dict[str, str]:
    environment = os.environ.copy()
    workspace_paths = [
        PROJECT_ROOT,
        PROJECT_ROOT.parent / ".venv" / "Lib" / "site-packages",
        PROJECT_ROOT / "packages" / "redactlens-core",
    ]
    existing = environment.get("PYTHONPATH")
    values = [str(path) for path in workspace_paths if path.exists()]
    if existing:
        values.append(existing)
    environment["PYTHONPATH"] = os.pathsep.join(values)
    return environment


def _run_isolated_measurement(fixture: Path, name: str, profile: str) -> dict[str, Any]:
    command = [
        sys.executable,
        "-m",
        "tooling.scripts.benchmark_phase8",
        "--worker",
        "--fixture",
        str(fixture),
        "--workload-name",
        name,
        "--profile",
        profile,
    ]
    try:
        completed = subprocess.run(
            command,
            cwd=PROJECT_ROOT,
            env=_isolated_worker_environment(),
            capture_output=True,
            text=True,
            timeout=WORKER_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise BenchmarkReportError(f"isolated workload '{name}' could not finish") from error
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip() or "no worker diagnostic"
        if len(detail) > 2_000:
            detail = detail[-2_000:]
        raise BenchmarkReportError(
            f"isolated workload '{name}' failed with exit code {completed.returncode}: {detail}"
        )
    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise BenchmarkReportError(
            f"isolated workload '{name}' returned invalid measurement data"
        ) from error
    expected_fields = {
        "wall_ms",
        "peak_memory_bytes",
        "findings",
        "summary",
        "functional_digest",
    }
    if not isinstance(payload, dict) or set(payload) != expected_fields:
        raise BenchmarkReportError(f"isolated workload '{name}' returned invalid fields")
    _require_number(payload["wall_ms"], f"isolated workload '{name}' wall time")
    memory = payload["peak_memory_bytes"]
    if memory is not None and (not isinstance(memory, int) or isinstance(memory, bool)):
        raise BenchmarkReportError(f"isolated workload '{name}' returned invalid peak memory")
    functional_digest = payload["functional_digest"]
    if not isinstance(functional_digest, str) or _DIGEST.fullmatch(functional_digest) is None:
        raise BenchmarkReportError(f"isolated workload '{name}' returned invalid result digest")
    return payload


def measure(
    fixtures: dict[str, Path],
    manifest: dict[str, dict[str, Any]],
    *,
    profile: str,
    repetitions: int,
) -> dict[str, dict[str, Any]]:
    measurements: dict[str, dict[str, Any]] = {}
    for name, fixture in fixtures.items():
        wall_samples: list[int] = []
        memory_samples: list[int | None] = []
        runs: list[dict[str, Any]] = []
        stable_digest: str | None = None
        for repetition in range(1, repetitions + 1):
            payload = _run_isolated_measurement(fixture, name, profile)
            functional_digest = payload["functional_digest"]
            if stable_digest is None:
                stable_digest = functional_digest
            elif functional_digest != stable_digest:
                raise BenchmarkReportError(
                    f"workload '{name}' produced non-deterministic results across repetitions"
                )
            wall_samples.append(payload["wall_ms"])
            memory_samples.append(payload["peak_memory_bytes"])
            runs.append(payload)
            print(
                f"{name} [{repetition}/{repetitions}]: {payload['wall_ms']} ms, "
                f"{payload['summary']['files_scanned']} scanned, "
                f"{payload['summary']['files_skipped']} skipped, "
                f"{payload['findings']} findings"
            )

        ordered_runs = sorted(runs, key=lambda item: item["wall_ms"])
        median_result = ordered_runs[len(ordered_runs) // 2]
        measured_memory = [value for value in memory_samples if value is not None]
        measurements[name] = {
            "wall_ms": round(statistics.median(wall_samples)),
            "wall_samples_ms": wall_samples,
            "peak_memory_bytes": max(measured_memory) if measured_memory else None,
            "peak_memory_samples_bytes": memory_samples,
            "findings": median_result["findings"],
            "summary": median_result["summary"],
        }
    return measurements


def build_report(
    profile: str,
    repetitions: int,
    measurements: dict[str, dict[str, Any]],
    *,
    project_root: Path = PROJECT_ROOT,
    generated_at: str | None = None,
    environment: dict[str, Any] | None = None,
) -> dict[str, Any]:
    report = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": (
            generated_at
            if generated_at is not None
            else datetime.now(UTC).isoformat().replace("+00:00", "Z")
        ),
        "source_digest": source_digest(project_root),
        "fixture_digest": fixture_digest(profile),
        "environment": environment if environment is not None else environment_metadata(),
        "profile": profile,
        "repetitions": repetitions,
        "workloads": workload_manifest(profile),
        "measurements": measurements,
    }
    validate_report(report)
    return report


def _require_number(value: Any, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise BenchmarkReportError(f"{label} must be a number")
    measured = float(value)
    if not math.isfinite(measured) or measured < 0:
        raise BenchmarkReportError(f"{label} must be finite and non-negative")
    return measured


def _require_nonnegative_int(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise BenchmarkReportError(f"{label} must be a non-negative integer")
    return value


def _validate_counter_map(value: Any, label: str) -> dict[str, int]:
    if not isinstance(value, dict):
        raise BenchmarkReportError(f"{label} must be an object")
    for name, count in value.items():
        if not isinstance(name, str) or not name:
            raise BenchmarkReportError(f"{label} keys must be non-empty strings")
        _require_nonnegative_int(count, f"{label} count for '{name}'")
    return value


def _validate_summary(
    workload_name: str,
    spec: dict[str, Any],
    measurement: dict[str, Any],
) -> None:
    summary = measurement["summary"]
    if not isinstance(summary, dict) or set(summary) != _SUMMARY_KEYS:
        raise BenchmarkReportError(
            f"measurement '{workload_name}' summary fields do not match the schema"
        )

    integer_fields = {
        "total_findings",
        "canonical_findings",
        "raw_detector_hits",
        "consolidated_hits",
        "suppressed_hits",
        "files_scanned",
        "files_skipped",
        "completed_files",
        "total_files",
        "duration_ms",
        "bytes_scanned",
        "llm_attempts",
        "llm_successes",
        "llm_failures",
    }
    for field in integer_fields:
        _require_nonnegative_int(
            summary[field],
            f"measurement '{workload_name}' summary field '{field}'",
        )

    for field in (
        "files_per_second",
        "megabytes_per_second",
        "extraction_seconds",
        "detection_seconds",
        "llm_seconds",
    ):
        _require_number(
            summary[field],
            f"measurement '{workload_name}' summary field '{field}'",
        )

    summary_memory = summary["peak_memory_bytes"]
    if summary_memory not in measurement["peak_memory_samples_bytes"]:
        raise BenchmarkReportError(
            f"measurement '{workload_name}' summary peak memory is not a recorded sample"
        )
    if summary_memory is not None:
        _require_nonnegative_int(
            summary_memory,
            f"measurement '{workload_name}' summary field 'peak_memory_bytes'",
        )

    detector_counts = _validate_counter_map(
        summary["raw_detector_hits_by_detector"],
        f"measurement '{workload_name}' raw detector counts",
    )
    tier_counts = _validate_counter_map(
        summary["tier_counts"],
        f"measurement '{workload_name}' tier counts",
    )
    category_counts = _validate_counter_map(
        summary["category_counts"],
        f"measurement '{workload_name}' category counts",
    )

    if not isinstance(summary["status"], str):
        raise BenchmarkReportError(
            f"measurement '{workload_name}' summary field 'status' must be a string"
        )
    if not isinstance(summary["incomplete"], bool):
        raise BenchmarkReportError(
            f"measurement '{workload_name}' summary field 'incomplete' must be a boolean"
        )

    expected_summary = {
        "total_files": spec["expected_total_files"],
        "completed_files": spec["expected_total_files"],
        "files_scanned": spec["expected_scanned_files"],
        "files_skipped": spec["expected_skipped_files"],
        "total_findings": spec["expected_findings"],
        "status": "complete",
        "incomplete": False,
    }
    for field, expected in expected_summary.items():
        if summary[field] != expected:
            raise BenchmarkReportError(
                f"measurement '{workload_name}' summary field '{field}' is inconsistent"
            )

    if summary["canonical_findings"] != summary["total_findings"]:
        raise BenchmarkReportError(
            f"measurement '{workload_name}' canonical finding count is inconsistent"
        )
    if summary["raw_detector_hits"] != (
        summary["canonical_findings"] + summary["consolidated_hits"]
    ):
        raise BenchmarkReportError(
            f"measurement '{workload_name}' raw detector count is inconsistent"
        )
    if summary["suppressed_hits"] > summary["consolidated_hits"]:
        raise BenchmarkReportError(
            f"measurement '{workload_name}' suppressed finding count is inconsistent"
        )
    if sum(detector_counts.values()) != summary["raw_detector_hits"]:
        raise BenchmarkReportError(
            f"measurement '{workload_name}' detector counter total is inconsistent"
        )
    if sum(tier_counts.values()) != summary["total_findings"]:
        raise BenchmarkReportError(
            f"measurement '{workload_name}' tier counter total is inconsistent"
        )
    if sum(category_counts.values()) != summary["total_findings"]:
        raise BenchmarkReportError(
            f"measurement '{workload_name}' category counter total is inconsistent"
        )
    if summary["files_scanned"] + summary["files_skipped"] != summary["completed_files"]:
        raise BenchmarkReportError(
            f"measurement '{workload_name}' completed file count is inconsistent"
        )
    if summary["llm_successes"] + summary["llm_failures"] != summary["llm_attempts"]:
        raise BenchmarkReportError(
            f"measurement '{workload_name}' LLM attempt counts are inconsistent"
        )
    if summary["duration_ms"] > measurement["wall_ms"]:
        raise BenchmarkReportError(
            f"measurement '{workload_name}' scan duration exceeds measured wall time"
        )
    if summary["completed_files"] > 0 and summary["files_per_second"] <= 0:
        raise BenchmarkReportError(
            f"measurement '{workload_name}' file throughput must be positive"
        )


def _validate_timestamp(value: Any) -> None:
    if not isinstance(value, str):
        raise BenchmarkReportError("generated_at must be an ISO-8601 string")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise BenchmarkReportError("generated_at is not valid ISO-8601") from error
    if parsed.tzinfo is None:
        raise BenchmarkReportError("generated_at must include a timezone")


def validate_report(report: Any) -> dict[str, Any]:
    if not isinstance(report, dict):
        raise BenchmarkReportError("benchmark report must be a JSON object")
    expected_keys = {
        "schema_version",
        "generated_at",
        "source_digest",
        "fixture_digest",
        "environment",
        "profile",
        "repetitions",
        "workloads",
        "measurements",
    }
    if set(report) != expected_keys:
        raise BenchmarkReportError("benchmark report fields do not match schema version 2")
    if report["schema_version"] != SCHEMA_VERSION:
        raise BenchmarkReportError(
            f"unsupported benchmark schema version: {report['schema_version']!r}"
        )
    _validate_timestamp(report["generated_at"])
    for name in ("source_digest", "fixture_digest"):
        value = report[name]
        if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
            raise BenchmarkReportError(f"{name} must be a lowercase SHA-256 digest")

    profile = report["profile"]
    manifest = workload_manifest(profile)
    if report["workloads"] != manifest:
        raise BenchmarkReportError("workload manifest does not match the declared profile")
    if report["fixture_digest"] != fixture_digest(profile):
        raise BenchmarkReportError(
            "fixture digest does not match the workload manifest and generator recipe"
        )

    repetitions = report["repetitions"]
    if (
        isinstance(repetitions, bool)
        or not isinstance(repetitions, int)
        or repetitions < 3
        or repetitions % 2 == 0
    ):
        raise BenchmarkReportError("repetitions must be an odd integer of at least 3")

    environment = report["environment"]
    if not isinstance(environment, dict) or set(environment) != _ENVIRONMENT_KEYS:
        raise BenchmarkReportError("environment metadata is incomplete")
    dependencies = environment["dependencies"]
    if not isinstance(dependencies, dict) or set(dependencies) != _DEPENDENCY_NAMES:
        raise BenchmarkReportError("environment dependency metadata is incomplete")
    if not all(isinstance(version, str) and version for version in dependencies.values()):
        raise BenchmarkReportError("environment dependency metadata is invalid")
    logical_cpu_count = environment["logical_cpu_count"]
    if (
        isinstance(logical_cpu_count, bool)
        or not isinstance(logical_cpu_count, int)
        or logical_cpu_count <= 0
    ):
        raise BenchmarkReportError("logical_cpu_count must be a positive integer")
    for name in _ENVIRONMENT_KEYS - {"dependencies", "logical_cpu_count"}:
        if not isinstance(environment[name], str):
            raise BenchmarkReportError(f"environment field '{name}' must be a string")

    measurements = report["measurements"]
    if not isinstance(measurements, dict) or set(measurements) != set(manifest):
        raise BenchmarkReportError("measurements must cover every workload exactly once")
    for name, spec in manifest.items():
        measurement = measurements[name]
        required = {
            "wall_ms",
            "wall_samples_ms",
            "peak_memory_bytes",
            "peak_memory_samples_bytes",
            "findings",
            "summary",
        }
        if not isinstance(measurement, dict) or set(measurement) != required:
            raise BenchmarkReportError(f"measurement '{name}' has invalid fields")
        wall_samples = measurement["wall_samples_ms"]
        if not isinstance(wall_samples, list) or len(wall_samples) != repetitions:
            raise BenchmarkReportError(f"measurement '{name}' has invalid wall samples")
        for index, sample in enumerate(wall_samples):
            _require_nonnegative_int(sample, f"measurement '{name}' wall sample {index}")
        wall_ms = _require_nonnegative_int(measurement["wall_ms"], f"measurement '{name}' wall_ms")
        if wall_ms != round(statistics.median(wall_samples)):
            raise BenchmarkReportError(f"measurement '{name}' wall median is inconsistent")

        memory_samples = measurement["peak_memory_samples_bytes"]
        if not isinstance(memory_samples, list) or len(memory_samples) != repetitions:
            raise BenchmarkReportError(f"measurement '{name}' has invalid memory samples")
        available_memory: list[int] = []
        for sample in memory_samples:
            if sample is None:
                continue
            _require_nonnegative_int(sample, f"measurement '{name}' memory sample")
            available_memory.append(sample)
        expected_peak = max(available_memory) if available_memory else None
        measured_peak = measurement["peak_memory_bytes"]
        if measured_peak is not None:
            _require_nonnegative_int(measured_peak, f"measurement '{name}' peak memory")
        if measured_peak != expected_peak:
            raise BenchmarkReportError(f"measurement '{name}' peak memory is inconsistent")

        findings = _require_nonnegative_int(
            measurement["findings"], f"measurement '{name}' finding count"
        )
        if findings != spec["expected_findings"]:
            raise BenchmarkReportError(f"measurement '{name}' finding count is inconsistent")
        _validate_summary(name, spec, measurement)
    return report


def load_report(path: Path) -> dict[str, Any]:
    try:
        report = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise BenchmarkReportError(f"could not read benchmark report '{path}'") from error
    return validate_report(report)


def check_report_fresh(
    path: Path,
    *,
    project_root: Path = PROJECT_ROOT,
    required_profile: str = "full",
) -> tuple[bool, str]:
    try:
        report = load_report(path)
        if report["profile"] != required_profile:
            raise BenchmarkReportError(
                f"checked benchmark must use the '{required_profile}' profile"
            )
        if report["source_digest"] != source_digest(project_root):
            raise BenchmarkReportError("benchmark source digest is stale")
        if report["fixture_digest"] != fixture_digest(required_profile):
            raise BenchmarkReportError("benchmark fixture digest is stale")
    except BenchmarkReportError as error:
        return False, str(error)
    return True, "Phase 8 benchmark evidence is fresh."


def _validate_percentage(value: float, label: str) -> None:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(value)
        or value < 0
    ):
        raise BenchmarkReportError(f"{label} must be finite and non-negative")


def compare_reports(
    current: dict[str, Any],
    baseline: dict[str, Any],
    *,
    max_regression_percent: float,
    max_memory_regression_percent: float,
    wall_time_noise_ms: float = DEFAULT_WALL_TIME_NOISE_MS,
) -> list[str]:
    current = validate_report(current)
    baseline = validate_report(baseline)
    _validate_percentage(max_regression_percent, "max regression percent")
    _validate_percentage(max_memory_regression_percent, "max memory regression percent")
    _validate_percentage(wall_time_noise_ms, "wall-time noise allowance")

    compatibility_fields = ("profile", "repetitions", "fixture_digest", "workloads", "environment")
    for field in compatibility_fields:
        if current[field] != baseline[field]:
            raise BenchmarkReportError(
                f"current and baseline reports have incompatible {field} metadata"
            )
    if set(current["measurements"]) != set(baseline["measurements"]):
        raise BenchmarkReportError("current and baseline workload sets do not match")

    failures: list[str] = []
    for name in current["workloads"]:
        measured = current["measurements"][name]
        prior = baseline["measurements"][name]
        percentage_budget = prior["wall_ms"] * max_regression_percent / 100
        wall_budget = max(percentage_budget, wall_time_noise_ms)
        wall_allowed = prior["wall_ms"] + wall_budget
        if measured["wall_ms"] > wall_allowed:
            failures.append(
                f"{name}: median wall time {measured['wall_ms']} ms exceeds "
                f"{wall_allowed:.0f} ms ({max_regression_percent:.0f}% or "
                f"{wall_time_noise_ms:g} ms noise budget)"
            )

        current_memory = measured["peak_memory_bytes"]
        baseline_memory = prior["peak_memory_bytes"]
        if (current_memory is None) != (baseline_memory is None):
            failures.append(f"{name}: peak-memory availability differs from the baseline")
        elif current_memory is not None and baseline_memory is not None:
            memory_allowed = baseline_memory * (1 + max_memory_regression_percent / 100)
            if current_memory > memory_allowed:
                failures.append(
                    f"{name}: peak memory {current_memory} bytes exceeds "
                    f"{memory_allowed:.0f} bytes "
                    f"({max_memory_regression_percent:.0f}% budget)"
                )
    return failures


def paths_alias(left: Path | None, right: Path | None) -> bool:
    if left is None or right is None:
        return False
    normalized_left = os.path.normcase(os.path.abspath(left))
    normalized_right = os.path.normcase(os.path.abspath(right))
    if normalized_left == normalized_right:
        return True
    try:
        return os.path.samefile(left, right)
    except OSError:
        return False


def _write_report(path: Path, report: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")


def _run_benchmark(args: argparse.Namespace, root: Path) -> int:
    profile = "full" if args.full else "quick"
    manifest = workload_manifest(profile)
    fixtures = generate(root, profile=profile)
    measurements = measure(
        fixtures,
        manifest,
        profile=profile,
        repetitions=args.repetitions,
    )
    report = build_report(profile, args.repetitions, measurements)
    failures: list[str] = []
    if args.baseline is not None:
        baseline = load_report(args.baseline)
        failures = compare_reports(
            report,
            baseline,
            max_regression_percent=args.max_regression_percent,
            max_memory_regression_percent=args.max_memory_regression_percent,
            wall_time_noise_ms=args.wall_time_noise_ms,
        )
    if args.output is not None:
        _write_report(args.output, report)
        print(f"Wrote {args.output}")
    if failures:
        print("\nPerformance regressions:")
        for failure in failures:
            print(f"- {failure}")
        return 1
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--full", action="store_true", help="Generate every full-size workload.")
    parser.add_argument("--work-dir", type=Path, help="Use an empty persistent fixture directory.")
    parser.add_argument("--output", type=Path, help="Write the measurement JSON here.")
    parser.add_argument("--baseline", type=Path, help="Compare with a compatible prior report.")
    parser.add_argument(
        "--check-baseline",
        type=Path,
        help="Validate checked evidence freshness without running benchmark fixtures.",
    )
    parser.add_argument("--repetitions", type=int, default=DEFAULT_REPETITIONS)
    parser.add_argument(
        "--max-regression-percent",
        type=float,
        default=DEFAULT_REGRESSION_PERCENT,
    )
    parser.add_argument(
        "--max-memory-regression-percent",
        type=float,
        default=DEFAULT_REGRESSION_PERCENT,
    )
    parser.add_argument(
        "--wall-time-noise-ms",
        type=float,
        default=DEFAULT_WALL_TIME_NOISE_MS,
        help=(
            "Absolute timing jitter allowance; each workload gets the larger of this "
            "value or its percentage budget (default: 25 ms)."
        ),
    )
    parser.add_argument("--worker", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--fixture", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--workload-name", help=argparse.SUPPRESS)
    parser.add_argument("--profile", choices=("quick", "full"), help=argparse.SUPPRESS)
    args = parser.parse_args()

    if args.worker:
        if args.fixture is None or args.workload_name is None or args.profile is None:
            parser.error("worker mode requires fixture, workload name, and profile")
        payload = _worker_payload(args.fixture, args.workload_name, args.profile)
        print(json.dumps(payload, separators=(",", ":")))
        return 0

    if args.check_baseline is not None:
        if (
            args.full
            or args.work_dir is not None
            or args.output is not None
            or args.baseline is not None
        ):
            parser.error("--check-baseline cannot be combined with benchmark-run options")
        fresh, message = check_report_fresh(args.check_baseline)
        print(message)
        return 0 if fresh else 1

    if args.repetitions < 3 or args.repetitions % 2 == 0:
        parser.error("--repetitions must be an odd integer of at least 3")
    try:
        _validate_percentage(args.max_regression_percent, "--max-regression-percent")
        _validate_percentage(
            args.max_memory_regression_percent,
            "--max-memory-regression-percent",
        )
        _validate_percentage(args.wall_time_noise_ms, "--wall-time-noise-ms")
    except BenchmarkReportError as error:
        parser.error(str(error))
    if paths_alias(args.output, args.baseline):
        parser.error("--output and --baseline must identify different files")

    if args.baseline is not None:
        try:
            load_report(args.baseline)
        except BenchmarkReportError as error:
            parser.error(str(error))

    if args.work_dir is None:
        try:
            with tempfile.TemporaryDirectory(prefix="redactlens-phase8-") as temporary:
                return _run_benchmark(args, Path(temporary))
        except BenchmarkReportError as error:
            print(f"Benchmark failed: {error}", file=sys.stderr)
            return 1

    root = args.work_dir.resolve()
    root.mkdir(parents=True, exist_ok=True)
    if any(root.iterdir()):
        parser.error("--work-dir must be empty so benchmark fixtures are never overwritten")
    try:
        return _run_benchmark(args, root)
    except BenchmarkReportError as error:
        print(f"Benchmark failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
