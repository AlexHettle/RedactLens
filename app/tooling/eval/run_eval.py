"""Build RedactLens's reproducible calibration and holdout evaluation report.

The calibration corpus selects the built-in confidence-weight profile and tier
threshold. Only the separate holdout corpus supplies the headline quality
claims. Both corpora are generated into a temporary directory, so a clean clone
can reproduce the report without checked-in generated fixtures.

Usage:
    python tooling/eval/run_eval.py
    python tooling/eval/run_eval.py --check
    python tooling/eval/run_eval.py --no-llm
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import tempfile
import time
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from redactlens_core.llm.adapter import (
    DEFAULT_HOST,
    DEFAULT_MODEL,
    DEFAULT_TIMEOUT,
    OllamaAdapter,
    OllamaModelInfo,
)
from redactlens_core.models import ScanRequest
from redactlens_core.registry import (
    DEPLOYED_CONFIDENCE_WEIGHT_PROFILE,
    ConfidenceWeightProfile,
    default_detectors_dir,
    load_default_registry,
    load_default_registry_for_profile,
)
from redactlens_core.scanner import scan

import generate_corpus
from calibration import (
    CALIBRATION_WEIGHT_PROFILES,
    confidence_profile_data,
    select_weight_profile,
    threshold_candidates,
)
from evidence_validation import (
    EVALUATION_SCHEMA_VERSION,
    LLM_COMPARISON_METRICS,
    LLM_METRIC_DIRECTIONS,
    TARGETS,
)
from evidence_validation import (
    llm_metric_values as _llm_metric_values,
)
from evidence_validation import (
    llm_scan_completed as _llm_scan_completed,
)
from evidence_validation import (
    normalize_model_digest as _normalize_model_digest,
)
from evidence_validation import (
    validate_runtime_performance as _validate_runtime_performance,
)
from evidence_validation import (
    validate_stored_evidence_shape as _validate_stored_evidence_shape,
)
from evidence_validation import (
    validate_stored_llm as _validate_stored_llm,
)
from metrics import (
    FindingLike,
    Plant,
    category_breakdown,
    confidence_calibration,
    detector_breakdown,
    evaluate,
    select_threshold,
    threshold_sweep,
    user_impact_metrics,
)
from report_rendering import render_report

EVAL_DIR = Path(__file__).resolve().parent
ROOT = EVAL_DIR.parents[1]
REPORT_PATH = EVAL_DIR / "report.md"
REPORT_DATA_PATH = EVAL_DIR / "report.json"

DEFAULT_TIER_THRESHOLD = float(ScanRequest.model_fields["tier_threshold"].default)
CALIBRATION_MINIMUM_PRECISION = 0.90
LLM_EVALUATION_OPTIONS = {"temperature": 0, "seed": 91973}
_RUNTIME_MODEL_FIELDS = {
    "resolved_model",
    "resolved_model_digest",
}


def _source_digest(paths: list[Path]) -> str:
    """Hash project-relative names and bytes for a complete source set."""
    digest = hashlib.sha256()
    for path in sorted(set(paths), key=lambda item: item.relative_to(ROOT).as_posix()):
        digest.update(path.relative_to(ROOT).as_posix().encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def _detector_configuration_digest() -> str:
    """Hash all first-party core sources that can affect scanner output."""
    return _source_digest(_detector_configuration_paths())


def _detector_configuration_paths() -> list[Path]:
    core_dir = ROOT / "packages" / "redactlens-core" / "redactlens_core"
    return [
        *core_dir.rglob("*.py"),
        *default_detectors_dir().glob("*.yaml"),
        ROOT / "packages" / "redactlens-core" / "pyproject.toml",
        ROOT / "pyproject.toml",
    ]


def _evaluation_source_digest() -> str:
    """Hash every evaluation implementation module, excluding generated artifacts."""
    return _source_digest(_evaluation_source_paths())


def _evaluation_source_paths() -> list[Path]:
    return [
        EVAL_DIR / "calibration.py",
        EVAL_DIR / "evidence_validation.py",
        EVAL_DIR / "generate_corpus.py",
        EVAL_DIR / "metrics.py",
        EVAL_DIR / "report_rendering.py",
        EVAL_DIR / "run_eval.py",
        EVAL_DIR / "pyproject.toml",
        ROOT / "pyproject.toml",
    ]


def _prompt_source_digest() -> str:
    """Fingerprint system, scoring, and description-target prompt implementations."""
    return _source_digest(_prompt_source_paths())


def _prompt_source_paths() -> list[Path]:
    core_dir = ROOT / "packages" / "redactlens-core" / "redactlens_core"
    return [
        core_dir / "llm" / "adapter.py",
        core_dir / "llm" / "description_targets.py",
        core_dir / "scoring.py",
    ]


def _to_plants(bundle: generate_corpus.CorpusBundle) -> list[Plant]:
    return [Plant(**vars(plant)) for plant in bundle.plants]


def _to_finding_like(findings: list[Any], documents_dir: Path) -> list[FindingLike]:
    root = documents_dir.resolve()
    return [
        FindingLike(
            file=Path(finding.file_path).resolve().relative_to(root).as_posix(),
            start=finding.start_offset,
            end=finding.end_offset,
            tier=finding.tier,
            confidence=finding.confidence,
            detector_id=finding.detector_id,
            category=finding.category,
            supporting_detector_ids=tuple(
                supporting.detector_id for supporting in finding.supporting_detections
            ),
        )
        for finding in findings
    ]


def _to_raw_opinion_like(opinions: list[Any], documents_dir: Path) -> list[FindingLike]:
    root = documents_dir.resolve()
    return [
        FindingLike(
            file=Path(opinion.file_path).resolve().relative_to(root).as_posix(),
            start=opinion.start_offset,
            end=opinion.end_offset,
            tier=opinion.tier,
            confidence=opinion.confidence,
            detector_id=opinion.detector_id,
            category=opinion.category,
        )
        for opinion in opinions
    ]


def _run_scan(
    documents_dir: Path,
    tier_threshold: float,
    *,
    registry: Any | None = None,
    use_llm: bool = False,
    llm_adapter: OllamaAdapter | None = None,
) -> tuple[Any, dict[str, float]]:
    byte_count = sum(path.stat().st_size for path in documents_dir.rglob("*") if path.is_file())
    started = time.perf_counter()
    effective_adapter = (
        _CorpusRelativeAdapter(llm_adapter, documents_dir)
        if use_llm and llm_adapter is not None
        else llm_adapter
    )
    result = scan(
        ScanRequest(
            paths=[str(documents_dir)],
            tier_threshold=tier_threshold,
            use_llm=use_llm,
        ),
        registry or load_default_registry(),
        llm_adapter=effective_adapter,
        capture_raw_detector_opinions=True,
    )
    elapsed = max(time.perf_counter() - started, 1e-9)
    megabytes = byte_count / 1_000_000
    return result, {
        "elapsed_seconds": elapsed,
        "files_per_second": len(result.scanned_files) / elapsed,
        "megabytes_scanned": megabytes,
        "megabytes_per_second": megabytes / elapsed,
    }


class _CorpusRelativeAdapter:
    """Remove random temporary roots from evaluation prompts."""

    def __init__(self, delegate: OllamaAdapter, documents_dir: Path) -> None:
        self._delegate = delegate
        resolved = documents_dir.resolve()
        self._root_variants = {str(resolved), resolved.as_posix()}

    def available(self) -> bool:
        return self._delegate.available()

    def judge(self, question: str):
        normalized = question
        for root in sorted(self._root_variants, key=len, reverse=True):
            normalized = normalized.replace(root, "<EVAL_CORPUS>")
        first_line, separator, remainder = normalized.partition("\n")
        if first_line.startswith("File path: <EVAL_CORPUS>"):
            first_line = first_line.replace("\\", "/")
            normalized = first_line + separator + remainder
        return self._delegate.judge(normalized)


def _role_metrics(
    result: Any,
    findings: list[FindingLike],
    raw_opinions: list[FindingLike],
    plants: list[Plant],
    document_count: int,
    performance: dict[str, float],
    detector_ids: set[str],
) -> dict[str, Any]:
    raw_opinion_counts = result.summary["raw_detector_hits_by_detector"]
    if sum(raw_opinion_counts.values()) != result.summary["raw_detector_hits"]:
        raise RuntimeError("per-detector raw opinion counts do not match the aggregate")
    geometry_counts = Counter(opinion.detector_id for opinion in raw_opinions)
    if len(raw_opinions) != result.summary["raw_detector_hits"]:
        raise RuntimeError("raw detector opinion geometry does not match the aggregate")
    if dict(geometry_counts) != raw_opinion_counts:
        raise RuntimeError("raw detector opinion geometry does not match per-detector counts")
    per_detector = detector_breakdown(
        findings,
        plants,
        raw_opinion_counts,
        raw_opinions=raw_opinions,
        detector_ids=detector_ids,
    )
    if set(per_detector) != detector_ids:
        raise RuntimeError("per-detector evaluation rows do not cover the selected registry")
    uncovered_detectors = sorted(
        detector_id for detector_id, item in per_detector.items() if item["expected_plants"] == 0
    )
    if uncovered_detectors:
        raise RuntimeError(
            "evaluation corpus has no positive plant for built-in detector(s): "
            + ", ".join(uncovered_detectors)
        )
    if sum(item["emitted_findings"] for item in per_detector.values()) != len(findings):
        raise RuntimeError("per-detector primary findings do not match the aggregate")
    if (
        sum(item["consolidated_opinions"] for item in per_detector.values())
        != result.summary["consolidated_hits"]
    ):
        raise RuntimeError("per-detector consolidation does not match the aggregate")
    metrics = evaluate(findings, plants)
    metrics.update(
        raw_detector_hits=result.summary["raw_detector_hits"],
        canonical_findings=result.summary["canonical_findings"],
        consolidated_hits=result.summary["consolidated_hits"],
        suppressed_hits=result.summary["suppressed_hits"],
        scanned_files=result.summary["files_scanned"],
        skipped_files=result.summary["files_skipped"],
        per_detector=per_detector,
        per_category=category_breakdown(findings, plants),
        confidence_calibration=confidence_calibration(findings, plants),
        user_impact=user_impact_metrics(findings, plants, document_count),
        performance=performance,
    )
    return metrics


def _evaluate_bundle(
    bundle: generate_corpus.CorpusBundle,
    destination: Path,
    tier_threshold: float,
    *,
    registry: Any | None = None,
    use_llm: bool = False,
    llm_adapter: OllamaAdapter | None = None,
) -> tuple[dict[str, Any], Any, list[FindingLike]]:
    selected_registry = registry or load_default_registry()
    generate_corpus.write_bundle(bundle, destination)
    documents_dir = destination / "documents"
    result, performance = _run_scan(
        documents_dir,
        tier_threshold,
        registry=selected_registry,
        use_llm=use_llm,
        llm_adapter=llm_adapter,
    )
    findings = _to_finding_like(result.findings, documents_dir)
    if result.raw_detector_opinions is None:
        raise RuntimeError("evaluation scan did not capture raw detector opinion geometry")
    raw_opinions = _to_raw_opinion_like(result.raw_detector_opinions, documents_dir)
    manifest = generate_corpus.manifest_for(bundle)
    metrics = _role_metrics(
        result,
        findings,
        raw_opinions,
        _to_plants(bundle),
        manifest["document_count"],
        performance,
        {detector.id for detector in selected_registry.get_all()},
    )
    return metrics, result, findings


def _semantic_finding_key(finding: Any) -> tuple[str, int, int, str]:
    """Identify a finding without temporary-root-dependent canonical IDs."""
    relative_file = getattr(finding, "file", None)
    if relative_file is None:
        raise TypeError("tier-shift inputs must expose a corpus-relative 'file' field")
    return (
        Path(relative_file).as_posix(),
        int(finding.start),
        int(finding.end),
        str(finding.category),
    )


def _semantic_finding_id(key: tuple[str, int, int, str]) -> str:
    encoded = json.dumps(key, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()[:20]


def _tier_shifts(baseline_findings: list[Any], llm_findings: list[Any]) -> list[dict[str, str]]:
    """Compare tiers by path-independent corpus-relative finding identity."""
    baseline_by_key = {
        _semantic_finding_key(finding): finding.tier for finding in baseline_findings
    }
    shifts = []
    for finding in llm_findings:
        key = _semantic_finding_key(finding)
        prior_tier = baseline_by_key.get(key)
        if prior_tier is not None and prior_tier != finding.tier:
            shifts.append(
                {
                    "finding_id": _semantic_finding_id(key),
                    "before": prior_tier,
                    "after": finding.tier,
                }
            )
    return sorted(shifts, key=lambda item: item["finding_id"])


def _llm_comparison(
    baseline: dict[str, Any],
    with_llm: dict[str, Any],
    shifts: list[dict[str, str]],
) -> dict[str, Any]:
    baseline_values = _llm_metric_values(baseline)
    llm_values = _llm_metric_values(with_llm)
    comparisons = {}
    for name in LLM_COMPARISON_METRICS:
        before = baseline_values[name]
        after = llm_values[name]
        direction = LLM_METRIC_DIRECTIONS[name]
        delta = after - before
        benefit = delta * direction
        status = (
            "improvement" if benefit > 1e-12 else "regression" if benefit < -1e-12 else "unchanged"
        )
        comparisons[name] = {
            "baseline": before,
            "with_llm": after,
            "delta": delta,
            "status": status,
        }
    return {
        "metrics": comparisons,
        "tier_shifts": shifts,
        "improvements": sorted(
            name for name, values in comparisons.items() if values["status"] == "improvement"
        ),
        "regressions": sorted(
            name for name, values in comparisons.items() if values["status"] == "regression"
        ),
    }


def _llm_configuration(model_info: OllamaModelInfo | None = None) -> dict[str, Any]:
    options_json = json.dumps(
        LLM_EVALUATION_OPTIONS,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return {
        "provider": "Ollama",
        "configured_model": DEFAULT_MODEL,
        "resolved_model": model_info.name if model_info is not None else None,
        "resolved_model_digest": (
            _normalize_model_digest(model_info.digest) if model_info is not None else None
        ),
        "host": DEFAULT_HOST,
        "timeout_seconds": DEFAULT_TIMEOUT,
        "options": dict(LLM_EVALUATION_OPTIONS),
        "options_sha256": hashlib.sha256(options_json).hexdigest(),
        "prompt_source_sha256": _prompt_source_digest(),
        "prompt_path_normalization": "temporary corpus root -> <EVAL_CORPUS>",
    }


def _canonical_model_info(model_info: OllamaModelInfo | None) -> OllamaModelInfo | None:
    if model_info is None:
        return None
    digest = _normalize_model_digest(model_info.digest)
    if digest is None:
        return None
    return OllamaModelInfo(name=model_info.name, digest=digest)


def _llm_inference_counts(result: Any | None = None) -> dict[str, int]:
    summary = result.summary if result is not None else {}
    return {
        "attempts": int(summary.get("llm_attempts", 0)),
        "successes": int(summary.get("llm_successes", 0)),
        "failures": int(summary.get("llm_failures", 0)),
    }


def _calibrate_confidence_weights_and_threshold(
    bundle: generate_corpus.CorpusBundle,
    destination: Path,
) -> tuple[
    ConfidenceWeightProfile,
    float,
    dict[str, Any],
    list[dict[str, Any]],
    list[dict[str, Any]],
]:
    """Select the weight profile and threshold from calibration data only."""

    plants = _to_plants(bundle)
    profile_runs: dict[
        str,
        tuple[dict[str, Any], list[FindingLike], list[dict[str, Any]]],
    ] = {}
    profile_rows: list[dict[str, Any]] = []

    for index, profile in enumerate(CALIBRATION_WEIGHT_PROFILES):
        metrics, _, findings = _evaluate_bundle(
            bundle,
            destination / f"profile-{index:02d}",
            DEFAULT_TIER_THRESHOLD,
            registry=load_default_registry_for_profile(profile),
        )
        sweep = threshold_sweep(
            findings,
            plants,
            threshold_candidates(
                findings,
                preferred_threshold=DEFAULT_TIER_THRESHOLD,
            ),
        )
        try:
            selected_threshold = select_threshold(
                sweep,
                CALIBRATION_MINIMUM_PRECISION,
                preferred_threshold=DEFAULT_TIER_THRESHOLD,
            )
        except ValueError:
            selected_threshold = None
            selected_row = None
        else:
            selected_row = next(row for row in sweep if row["threshold"] == selected_threshold)

        confidence = metrics["confidence_calibration"]
        profile_row = {
            "profile": confidence_profile_data(profile),
            "eligible": selected_row is not None,
            "selected_threshold": selected_threshold,
            "threshold_precision": (
                selected_row["precision"] if selected_row is not None else None
            ),
            "threshold_recall": selected_row["recall"] if selected_row is not None else None,
            "brier_score": confidence["brier_score"],
            "expected_calibration_error": confidence["expected_calibration_error"],
        }
        profile_rows.append(profile_row)
        profile_runs[profile.profile_id] = (metrics, findings, sweep)

    selected_row = select_weight_profile(
        profile_rows,
        deployed_profile_id=DEPLOYED_CONFIDENCE_WEIGHT_PROFILE.profile_id,
    )
    selected_profile_id = selected_row["profile"]["profile_id"]
    selected_profile = next(
        profile
        for profile in CALIBRATION_WEIGHT_PROFILES
        if profile.profile_id == selected_profile_id
    )
    selected_threshold = float(selected_row["selected_threshold"])
    _, _, selected_sweep = profile_runs[selected_profile_id]
    selected_metrics, _, _ = _evaluate_bundle(
        bundle,
        destination / "selected",
        selected_threshold,
        registry=load_default_registry_for_profile(selected_profile),
    )
    selected_sweep_row = next(
        row for row in selected_sweep if row["threshold"] == selected_threshold
    )
    selected_metric_pairs = (
        ("tier_a_findings", "num_findings_at_or_above"),
        ("tier_a_true_positive_findings", "true_positive_findings"),
        ("tier_a_precision", "precision"),
        ("tier_a_recall", "recall"),
    )
    if any(
        selected_metrics[metric_name] != selected_sweep_row[sweep_name]
        for metric_name, sweep_name in selected_metric_pairs
    ):
        raise RuntimeError("selected calibration metrics do not match the threshold sweep")
    return (
        selected_profile,
        selected_threshold,
        selected_metrics,
        selected_sweep,
        profile_rows,
    )


def build_evaluation(*, include_llm: bool = True) -> dict[str, Any]:
    bundles = generate_corpus.generate_all()
    manifests = {role: generate_corpus.manifest_for(bundle) for role, bundle in bundles.items()}

    with tempfile.TemporaryDirectory(prefix="redactlens-eval-") as temp:
        temp_root = Path(temp)
        (
            selected_weight_profile,
            selected_threshold,
            calibration_metrics,
            sweep,
            weight_profile_sweep,
        ) = _calibrate_confidence_weights_and_threshold(
            bundles["calibration"],
            temp_root / "calibration",
        )
        selected_registry = load_default_registry_for_profile(selected_weight_profile)

        holdout_metrics, _, holdout_findings = _evaluate_bundle(
            bundles["holdout"],
            temp_root / "holdout",
            selected_threshold,
            registry=selected_registry,
        )

        llm = {
            "status": "not_requested",
            "configuration": _llm_configuration(),
            "inference": _llm_inference_counts(),
            "comparison": None,
        }
        if include_llm:
            adapter = OllamaAdapter(options=LLM_EVALUATION_OPTIONS)
            reported_model_info = adapter.available_model_info()
            model_info = _canonical_model_info(reported_model_info)
            if reported_model_info is not None and model_info is None:
                llm = {
                    "status": "failed_model_identity",
                    "configuration": _llm_configuration(reported_model_info),
                    "inference": _llm_inference_counts(),
                    "comparison": None,
                    "reason": (
                        "Ollama reported a matching model tag without the immutable digest "
                        "required for reproducible evaluation."
                    ),
                }
            elif model_info is not None:
                # Pin generation to the exact tag whose immutable digest is recorded.
                adapter.model = model_info.name
                llm_metrics, llm_result, llm_findings = _evaluate_bundle(
                    bundles["holdout"],
                    temp_root / "holdout-llm",
                    selected_threshold,
                    registry=selected_registry,
                    use_llm=True,
                    llm_adapter=adapter,
                )
                inference = _llm_inference_counts(llm_result)
                identity_after_scan = _canonical_model_info(adapter.available_model_info())
                if identity_after_scan != model_info:
                    llm = {
                        "status": "failed_model_identity",
                        "configuration": _llm_configuration(model_info),
                        "inference": inference,
                        "comparison": None,
                        "reason": (
                            "The resolved Ollama model tag or digest changed during the "
                            "measured holdout scan."
                        ),
                    }
                elif _llm_scan_completed(inference):
                    llm = {
                        "status": "completed",
                        "configuration": _llm_configuration(model_info),
                        "inference": inference,
                        "comparison": _llm_comparison(
                            holdout_metrics,
                            llm_metrics,
                            _tier_shifts(holdout_findings, llm_findings),
                        ),
                    }
                else:
                    llm = {
                        "status": "failed_inference",
                        "configuration": _llm_configuration(model_info),
                        "inference": inference,
                        "comparison": None,
                        "reason": (
                            "The model was present, but the holdout comparison did not "
                            "complete with at least one successful inference and zero "
                            "failed inferences."
                        ),
                    }
            else:
                llm["status"] = "skipped_unavailable"
                llm["reason"] = "Ollama or the configured model was not available."

    gate_support = {
        "tier_a_precision": holdout_metrics["tier_a_findings"],
        "tier_a_recall": holdout_metrics["num_positive_plants"],
        "any_tier_recall": holdout_metrics["num_positive_plants"],
    }
    quality_gates = {}
    for name, target in TARGETS.items():
        support = gate_support[name]
        quality_gates[name] = {
            "value": holdout_metrics[name],
            "target": target,
            "support": support,
            "passed": support > 0 and holdout_metrics[name] >= target,
        }
    quality_gates["selected_threshold_deployed"] = {
        "value": selected_threshold,
        "target": DEFAULT_TIER_THRESHOLD,
        "support": 1,
        "passed": selected_threshold == DEFAULT_TIER_THRESHOLD,
    }
    quality_gates["selected_confidence_weights_deployed"] = {
        "value": selected_weight_profile.profile_id,
        "target": DEPLOYED_CONFIDENCE_WEIGHT_PROFILE.profile_id,
        "support": 1,
        "passed": selected_weight_profile == DEPLOYED_CONFIDENCE_WEIGHT_PROFILE,
    }
    return {
        "schema_version": EVALUATION_SCHEMA_VERSION,
        "metadata": {
            "generated_at_utc": datetime.now(UTC).replace(microsecond=0).isoformat(),
            "corpus_version": generate_corpus.CORPUS_VERSION,
            "detector_configuration_sha256": _detector_configuration_digest(),
            "evaluation_source_sha256": _evaluation_source_digest(),
            "calibration_minimum_precision": CALIBRATION_MINIMUM_PRECISION,
            "deployed_confidence_weight_profile_before_calibration": confidence_profile_data(
                DEPLOYED_CONFIDENCE_WEIGHT_PROFILE
            ),
            "selected_confidence_weight_profile": confidence_profile_data(selected_weight_profile),
            "confidence_weight_selection_policy": (
                "Minimize calibration Brier score plus expected calibration error; then "
                "maximize eligible-threshold recall and precision; preserve the deployed "
                "profile only on an identical best plateau."
            ),
            "deployed_threshold_before_calibration": DEFAULT_TIER_THRESHOLD,
            "selected_tier_threshold": selected_threshold,
            "threshold_selection_policy": (
                "Across every distinct calibration confidence boundary, maximize recall "
                "subject to minimum precision; then maximize precision; preserve the deployed "
                "threshold when it lies on the best plateau."
            ),
            "corpora": manifests,
        },
        "calibration": {
            "metrics": calibration_metrics,
            "weight_profile_sweep": weight_profile_sweep,
            "threshold_sweep": sweep,
        },
        "holdout": {"metrics": holdout_metrics},
        "quality_gates": quality_gates,
        "llm": llm,
    }


def _without_performance(section: dict[str, Any]) -> dict[str, Any]:
    copied = json.loads(json.dumps(section))
    copied.get("metrics", {}).pop("performance", None)
    return copied


def stable_projection(data: dict[str, Any]) -> dict[str, Any]:
    """Return deterministic evidence reproducible without a live model server.

    Runtime Ollama results remain linked to the report JSON and exact rendered
    Markdown, but freshness must not turn a completed report stale merely
    because Ollama is unavailable during a later ``--check``. Resolved model
    identity is therefore retained in the artifact but excluded from this
    no-network projection. The configured model remains deterministic input
    and is compared against the current configuration.
    """
    metadata = dict(data["metadata"])
    metadata.pop("generated_at_utc", None)
    llm_configuration = {
        key: value
        for key, value in data["llm"]["configuration"].items()
        if key not in _RUNTIME_MODEL_FIELDS
    }
    return {
        "schema_version": data["schema_version"],
        "metadata": metadata,
        "calibration": _without_performance(data["calibration"]),
        "holdout": _without_performance(data["holdout"]),
        "quality_gates": data["quality_gates"],
        "llm_configuration": llm_configuration,
    }


def write_artifacts(
    data: dict[str, Any],
    *,
    report_path: Path = REPORT_PATH,
    data_path: Path = REPORT_DATA_PATH,
) -> str:
    report = _canonical_lf(render_report(data))
    report_bytes = report.encode("utf-8")
    _write_lf_text(report_path, report)
    artifact = data.setdefault("artifact", {})
    artifact["report_sha256"] = hashlib.sha256(report_bytes).hexdigest()
    _write_lf_text(data_path, json.dumps(data, indent=2, sort_keys=True) + "\n")
    return report


def _canonical_lf(text: str) -> str:
    return text.replace("\r\n", "\n").replace("\r", "\n")


def _write_lf_text(path: Path, text: str) -> None:
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(_canonical_lf(text))


def _current_render_data(current: dict[str, Any], stored: dict[str, Any]) -> dict[str, Any]:
    """Combine reproducible current evidence with validated runtime measurements."""
    expected = json.loads(json.dumps(current))
    expected["metadata"]["generated_at_utc"] = stored["metadata"]["generated_at_utc"]
    for role in ("calibration", "holdout"):
        expected[role]["metrics"]["performance"] = stored[role]["metrics"]["performance"]
    expected["llm"] = stored["llm"]
    return expected


def _linked_entry_kind(path: Path) -> str | None:
    if path.is_symlink():
        return "symlink"
    is_junction = getattr(os.path, "isjunction", None)
    if is_junction is not None and is_junction(path):
        return "junction"
    try:
        metadata = path.lstat()
    except OSError:
        return None
    attributes = getattr(metadata, "st_file_attributes", 0)
    if attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0):
        return "reparse-point"
    if path.is_file() and metadata.st_nlink > 1:
        return "hardlink"
    return None


def _corpus_tree_snapshot(root: Path) -> dict[str, tuple[str, bytes | None]]:
    entries: dict[str, tuple[str, bytes | None]] = {}
    for path in root.rglob("*"):
        relative = path.relative_to(root).as_posix()
        if relative == ".gitkeep":
            continue
        if linked_kind := _linked_entry_kind(path):
            entries[relative] = (linked_kind, None)
        elif path.is_dir():
            entries[relative] = ("directory", None)
        elif path.is_file():
            entries[relative] = ("file", path.read_bytes())
        else:
            entries[relative] = ("other", None)
    return entries


def _validate_checked_in_corpus(corpus_dir: Path) -> str | None:
    """Validate optional materialized corpus artifacts against seeded generation."""
    if linked_kind := _linked_entry_kind(corpus_dir):
        return (
            "Optional evaluation corpus root must not be linked or redirected "
            f"({linked_kind}); regenerate tooling/eval/corpus as ordinary files."
        )
    if not corpus_dir.exists():
        return None
    if not corpus_dir.is_dir():
        return "Optional evaluation corpus path is not a directory; regenerate tooling/eval/corpus."
    calibration_present = (corpus_dir / "calibration").exists()
    holdout_present = (corpus_dir / "holdout").exists()
    try:
        actual = _corpus_tree_snapshot(corpus_dir)
        if not calibration_present and not holdout_present:
            if actual:
                unexpected = sorted(actual)[0]
                return (
                    "Optional evaluation corpus contains unexpected or legacy materialized "
                    f"artifact {unexpected!r}; regenerate or remove tooling/eval/corpus outputs."
                )
            return None
        if calibration_present != holdout_present:
            return (
                "Optional evaluation corpus must contain both calibration and holdout roles; "
                "regenerate or remove tooling/eval/corpus outputs."
            )
        with tempfile.TemporaryDirectory(prefix="redactlens-corpus-check-") as temp:
            expected_root = Path(temp)
            for role, bundle in generate_corpus.generate_all().items():
                generate_corpus.write_bundle(bundle, expected_root / role)
            expected = _corpus_tree_snapshot(expected_root)
    except OSError as error:
        return f"Could not verify the checked-in evaluation corpus: {error}"

    missing = sorted(set(expected) - set(actual))
    unexpected = sorted(set(actual) - set(expected))
    changed = sorted(
        relative
        for relative in set(expected) & set(actual)
        if expected[relative] != actual[relative]
    )
    if missing or unexpected or changed:
        details = []
        if missing:
            details.append(f"missing {missing[0]!r}")
        if unexpected:
            details.append(f"unexpected {unexpected[0]!r}")
        if changed:
            details.append(f"modified {changed[0]!r}")
        return (
            "Checked-in evaluation corpus differs from canonical generation "
            f"({'; '.join(details)}); regenerate tooling/eval/corpus."
        )
    return None


def check_report_fresh(
    *,
    report_path: Path = REPORT_PATH,
    data_path: Path = REPORT_DATA_PATH,
    corpus_path: Path = generate_corpus.CORPUS_DIR,
) -> tuple[bool, str]:
    if not report_path.is_file() or not data_path.is_file():
        return False, (
            "Evaluation report artifacts are missing; run `python tooling/eval/run_eval.py`."
        )
    try:
        stored_data_bytes = data_path.read_bytes()
        stored = json.loads(stored_data_bytes.decode("utf-8"))
        canonical_json = (json.dumps(stored, indent=2, sort_keys=True) + "\n").encode("utf-8")
    except (ValueError, OSError, RecursionError, UnicodeDecodeError) as error:
        return False, f"Could not read evaluation evidence: {error}"
    if stored_data_bytes != canonical_json or b"\r" in stored_data_bytes:
        return False, (
            "tooling/eval/report.json is not canonical UTF-8/LF JSON; regenerate the report."
        )
    shape_error = _validate_stored_evidence_shape(stored)
    if shape_error is not None:
        return False, shape_error
    corpus_error = _validate_checked_in_corpus(corpus_path)
    if corpus_error is not None:
        return False, corpus_error

    current = build_evaluation(include_llm=False)
    llm_error = _validate_stored_llm(stored.get("llm"), current["holdout"]["metrics"])
    if llm_error is not None:
        return False, llm_error
    try:
        projections_match = stable_projection(stored) == stable_projection(current)
    except (AttributeError, KeyError, TypeError, ValueError) as error:
        return False, f"Stored evaluation evidence is malformed: {error}"
    if not projections_match:
        return False, (
            "Stored evaluation evidence is stale; run `python tooling/eval/run_eval.py`."
        )
    performance_error = _validate_runtime_performance(stored, current)
    if performance_error is not None:
        return False, performance_error

    try:
        actual_report_bytes = report_path.read_bytes()
        actual_report = actual_report_bytes.decode("utf-8")
    except (OSError, UnicodeDecodeError) as error:
        return False, f"Could not read evaluation report: {error}"
    try:
        expected_data = _current_render_data(current, stored)
        expected_report = _canonical_lf(render_report(expected_data))
    except (KeyError, TypeError) as error:
        return False, f"Stored evaluation evidence is incomplete: {error}"
    if actual_report != expected_report or b"\r" in actual_report_bytes:
        return (
            False,
            "tooling/eval/report.md is not the current canonical LF rendering of "
            "tooling/eval/report.json; regenerate the report.",
        )
    actual_report_digest = hashlib.sha256(actual_report_bytes).hexdigest()
    if stored.get("artifact", {}).get("report_sha256") != actual_report_digest:
        return False, (
            "tooling/eval/report.md does not match tooling/eval/report.json; regenerate the report."
        )
    failed_gates = sorted(
        name for name, gate in current["quality_gates"].items() if not gate["passed"]
    )
    if failed_gates:
        return (
            False,
            "Evaluation report is fresh but current quality gates failed: "
            + ", ".join(failed_gates),
        )
    return True, "Evaluation report matches the current code and corpus configuration."


def _quality_passes(data: dict[str, Any]) -> bool:
    return all(gate["passed"] for gate in data["quality_gates"].values())


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="fail if the stored report differs from current deterministic evidence",
    )
    parser.add_argument(
        "--no-llm",
        action="store_true",
        help="do not probe or evaluate the optional Ollama layer",
    )
    args = parser.parse_args(argv)

    if args.check:
        fresh, message = check_report_fresh()
        print(message)
        return 0 if fresh else 1

    data = build_evaluation(include_llm=not args.no_llm)
    report = write_artifacts(data)
    print(report)
    print(f"Report written to {REPORT_PATH}")
    print(f"Machine-readable evidence written to {REPORT_DATA_PATH}")
    return 0 if _quality_passes(data) else 1


if __name__ == "__main__":
    raise SystemExit(main())
