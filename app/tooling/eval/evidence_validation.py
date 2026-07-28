"""Validation primitives for checked-in RedactLens evaluation evidence."""

from __future__ import annotations

import math
from datetime import UTC, datetime
from typing import Any

from redactlens_core.llm.adapter import _model_matches

EVALUATION_SCHEMA_VERSION = 3
TARGETS = {
    "tier_a_precision": 0.90,
    "tier_a_recall": 0.50,
    "any_tier_recall": 0.95,
}
LLM_COMPARISON_METRICS = (
    "tier_a_precision",
    "tier_a_recall",
    "overall_precision",
    "overall_recall",
    "false_positives_per_1000_files",
    "brier_score",
    "expected_calibration_error",
)
LLM_METRIC_DIRECTIONS = {
    "tier_a_precision": 1,
    "tier_a_recall": 1,
    "overall_precision": 1,
    "overall_recall": 1,
    "false_positives_per_1000_files": -1,
    "brier_score": -1,
    "expected_calibration_error": -1,
}
PERFORMANCE_FIELDS = {
    "elapsed_seconds",
    "files_per_second",
    "megabytes_scanned",
    "megabytes_per_second",
}


def llm_metric_values(metrics: dict[str, Any]) -> dict[str, float]:
    return {
        "tier_a_precision": metrics["tier_a_precision"],
        "tier_a_recall": metrics["tier_a_recall"],
        "overall_precision": metrics["overall_precision"],
        "overall_recall": metrics["overall_recall"],
        "false_positives_per_1000_files": metrics["user_impact"]["false_positives_per_1000_files"],
        "brier_score": metrics["confidence_calibration"]["brier_score"],
        "expected_calibration_error": metrics["confidence_calibration"][
            "expected_calibration_error"
        ],
    }


def normalize_model_digest(digest: str | None) -> str | None:
    if not isinstance(digest, str):
        return None
    algorithm, separator, payload = digest.partition(":")
    if not separator:
        algorithm = "sha256"
        payload = digest
    if (
        algorithm.lower() != "sha256"
        or len(payload) != 64
        or any(character not in "0123456789abcdefABCDEF" for character in payload)
    ):
        return None
    return f"sha256:{payload.lower()}"


def llm_scan_completed(counts: dict[str, int]) -> bool:
    return (
        counts["attempts"] > 0
        and counts["successes"] == counts["attempts"]
        and counts["failures"] == 0
    )


def finite_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)


def validate_stored_evidence_shape(stored: Any) -> str | None:
    if not isinstance(stored, dict):
        return "Stored evaluation evidence must be a JSON object."
    root_fields = {
        "schema_version",
        "metadata",
        "calibration",
        "holdout",
        "quality_gates",
        "llm",
        "artifact",
    }
    if set(stored) != root_fields:
        return "Stored evaluation evidence has unexpected or missing top-level fields."
    schema_version = stored.get("schema_version")
    if (
        not isinstance(schema_version, int)
        or isinstance(schema_version, bool)
        or schema_version != EVALUATION_SCHEMA_VERSION
    ):
        return (
            "Stored evaluation evidence has an unsupported or missing schema_version; "
            "regenerate the report."
        )
    for key in ("metadata", "calibration", "holdout", "quality_gates", "llm", "artifact"):
        if not isinstance(stored.get(key), dict):
            return f"Stored evaluation evidence field {key!r} is missing or malformed."
    artifact = stored["artifact"]
    if set(artifact) != {"report_sha256"} or not isinstance(artifact.get("report_sha256"), str):
        return "Stored evaluation artifact wrapper has unexpected or missing fields."
    metadata = stored["metadata"]
    metadata_fields = {
        "generated_at_utc",
        "corpus_version",
        "detector_configuration_sha256",
        "evaluation_source_sha256",
        "calibration_minimum_precision",
        "deployed_confidence_weight_profile_before_calibration",
        "selected_confidence_weight_profile",
        "confidence_weight_selection_policy",
        "deployed_threshold_before_calibration",
        "selected_tier_threshold",
        "threshold_selection_policy",
        "corpora",
    }
    if set(metadata) != metadata_fields:
        return "Stored evaluation metadata has unexpected or missing fields."
    generated_at = metadata.get("generated_at_utc")
    if not isinstance(generated_at, str):
        return "Stored evaluation metadata is missing generated_at_utc."
    try:
        generated_datetime = datetime.fromisoformat(generated_at)
    except ValueError:
        return "Stored evaluation generated_at_utc is not a valid ISO timestamp."
    if generated_datetime.tzinfo is None or generated_datetime.utcoffset() != UTC.utcoffset(None):
        return "Stored evaluation generated_at_utc must be timezone-aware UTC."
    profile_fields = {"profile_id", "base_offset", "context_scale"}
    for profile_name in (
        "deployed_confidence_weight_profile_before_calibration",
        "selected_confidence_weight_profile",
    ):
        profile = metadata.get(profile_name)
        if not isinstance(profile, dict) or set(profile) != profile_fields:
            return f"Stored evaluation metadata field {profile_name!r} is malformed."
        if not isinstance(profile["profile_id"], str) or not profile["profile_id"].strip():
            return f"Stored evaluation metadata field {profile_name!r} lacks a profile id."
        if not finite_number(profile["base_offset"]) or not finite_number(profile["context_scale"]):
            return f"Stored evaluation metadata field {profile_name!r} has invalid weights."
    if set(stored["calibration"]) != {
        "metrics",
        "weight_profile_sweep",
        "threshold_sweep",
    }:
        return "Stored calibration wrapper has unexpected or missing fields."
    if set(stored["holdout"]) != {"metrics"}:
        return "Stored holdout wrapper has unexpected or missing fields."
    corpora = metadata.get("corpora")
    if not isinstance(corpora, dict) or set(corpora) != {"calibration", "holdout"}:
        return "Stored corpus metadata wrapper has unexpected or missing roles."
    manifest_fields = {
        "corpus_version",
        "role",
        "seed",
        "template_family",
        "structure_signature_version",
        "fabrication_policy",
        "document_count",
        "positive_plant_count",
        "decoy_plant_count",
        "sha256",
    }
    for role in ("calibration", "holdout"):
        if not isinstance(corpora.get(role), dict) or set(corpora[role]) != manifest_fields:
            return f"Stored {role} corpus manifest has unexpected or missing fields."
        metrics = stored[role].get("metrics")
        if not isinstance(metrics, dict) or not isinstance(metrics.get("performance"), dict):
            return f"Stored {role} metrics or performance evidence is malformed."
        performance = metrics["performance"]
        if set(performance) != PERFORMANCE_FIELDS:
            return f"Stored {role} performance evidence has unexpected or missing fields."
        if any(
            not finite_number(performance[field]) or performance[field] < 0.0
            for field in PERFORMANCE_FIELDS
        ):
            return f"Stored {role} performance evidence must contain finite nonnegative numbers."
        if performance["elapsed_seconds"] <= 0.0:
            return f"Stored {role} performance elapsed_seconds must be positive."
        scanned_files = metrics.get("scanned_files")
        if (
            isinstance(scanned_files, int)
            and not isinstance(scanned_files, bool)
            and scanned_files > 0
            and performance["files_per_second"] <= 0.0
        ):
            return f"Stored {role} files_per_second must be positive for a nonempty scan."
        if performance["megabytes_scanned"] > 0.0 and performance["megabytes_per_second"] <= 0.0:
            return f"Stored {role} megabytes_per_second must be positive when bytes were scanned."
    expected_gates = {
        *TARGETS,
        "selected_threshold_deployed",
        "selected_confidence_weights_deployed",
    }
    quality_gates = stored["quality_gates"]
    if set(quality_gates) != expected_gates:
        return "Stored quality-gate wrapper has unexpected or missing gates."
    for gate_name, gate in quality_gates.items():
        if not isinstance(gate, dict) or set(gate) != {"value", "target", "support", "passed"}:
            return f"Stored quality gate {gate_name!r} has unexpected or missing fields."
    if not isinstance(stored["calibration"].get("threshold_sweep"), list):
        return "Stored calibration threshold sweep is missing or malformed."
    weight_rows = stored["calibration"].get("weight_profile_sweep")
    weight_row_fields = {
        "profile",
        "eligible",
        "selected_threshold",
        "threshold_precision",
        "threshold_recall",
        "brier_score",
        "expected_calibration_error",
    }
    if not isinstance(weight_rows, list) or not weight_rows:
        return "Stored calibration confidence-weight sweep is missing or malformed."
    for row in weight_rows:
        if not isinstance(row, dict) or set(row) != weight_row_fields:
            return "Stored calibration confidence-weight row is malformed."
        if not isinstance(row.get("profile"), dict) or set(row["profile"]) != profile_fields:
            return "Stored calibration confidence-weight profile is malformed."
        if not isinstance(row.get("eligible"), bool):
            return "Stored calibration confidence-weight eligibility is malformed."
        for field in ("brier_score", "expected_calibration_error"):
            if not finite_number(row.get(field)) or not 0.0 <= row[field] <= 1.0:
                return "Stored calibration confidence-weight score is malformed."
        threshold_fields = (
            "selected_threshold",
            "threshold_precision",
            "threshold_recall",
        )
        if row["eligible"]:
            if any(
                not finite_number(row.get(field)) or not 0.0 <= row[field] <= 1.0
                for field in threshold_fields
            ):
                return "Stored eligible confidence-weight row lacks valid threshold evidence."
        elif any(row.get(field) is not None for field in threshold_fields):
            return "Stored ineligible confidence-weight row claims threshold evidence."
    if not isinstance(stored["llm"].get("configuration"), dict):
        return "Stored Ollama configuration is missing or malformed."
    return None


def validate_llm_comparison(comparison: Any, current_holdout: dict[str, Any]) -> str | None:
    if not isinstance(comparison, dict):
        return "Completed Ollama evidence is missing its measured comparison."
    if set(comparison) != {"metrics", "tier_shifts", "improvements", "regressions"}:
        return "Completed Ollama comparison wrapper has unexpected or missing fields."
    metric_rows = comparison.get("metrics")
    if not isinstance(metric_rows, dict) or set(metric_rows) != set(LLM_COMPARISON_METRICS):
        return "Completed Ollama comparison does not contain the exact required metrics."
    try:
        current_values = llm_metric_values(current_holdout)
    except (KeyError, TypeError):
        return "Current deterministic holdout metrics are incomplete."

    expected_improvements = []
    expected_regressions = []
    bounded_metrics = {
        "tier_a_precision",
        "tier_a_recall",
        "overall_precision",
        "overall_recall",
        "brier_score",
        "expected_calibration_error",
    }
    for name in LLM_COMPARISON_METRICS:
        row = metric_rows[name]
        if not isinstance(row, dict) or set(row) != {
            "baseline",
            "with_llm",
            "delta",
            "status",
        }:
            return f"Completed Ollama comparison row {name!r} is malformed."
        before = row["baseline"]
        after = row["with_llm"]
        delta = row["delta"]
        if not all(finite_number(value) for value in (before, after, delta)):
            return f"Completed Ollama comparison row {name!r} contains a non-finite value."
        if not math.isclose(before, current_values[name], rel_tol=0.0, abs_tol=1e-12):
            return f"Completed Ollama comparison baseline {name!r} is stale or inconsistent."
        if not math.isclose(delta, after - before, rel_tol=0.0, abs_tol=1e-12):
            return f"Completed Ollama comparison delta {name!r} is inconsistent."
        if name in bounded_metrics and not 0.0 <= after <= 1.0:
            return f"Completed Ollama comparison value {name!r} is outside its valid range."
        if name == "false_positives_per_1000_files" and after < 0.0:
            return "Completed Ollama comparison false-positive rate cannot be negative."

        benefit = (after - before) * LLM_METRIC_DIRECTIONS[name]
        expected_status = (
            "improvement" if benefit > 1e-12 else "regression" if benefit < -1e-12 else "unchanged"
        )
        if row["status"] != expected_status:
            return f"Completed Ollama comparison status {name!r} is inconsistent."
        if expected_status == "improvement":
            expected_improvements.append(name)
        elif expected_status == "regression":
            expected_regressions.append(name)

    if comparison.get("improvements") != sorted(expected_improvements):
        return "Completed Ollama comparison improvement list is inconsistent."
    if comparison.get("regressions") != sorted(expected_regressions):
        return "Completed Ollama comparison regression list is inconsistent."

    shifts = comparison.get("tier_shifts")
    if not isinstance(shifts, list):
        return "Completed Ollama comparison tier shifts are malformed."
    shift_ids = []
    for shift in shifts:
        if not isinstance(shift, dict) or set(shift) != {"finding_id", "before", "after"}:
            return "Completed Ollama comparison contains a malformed tier shift."
        finding_id = shift["finding_id"]
        if (
            not isinstance(finding_id, str)
            or len(finding_id) != 20
            or any(character not in "0123456789abcdef" for character in finding_id)
        ):
            return "Completed Ollama comparison contains an invalid tier-shift identity."
        if shift["before"] not in {"A", "B"} or shift["after"] not in {"A", "B"}:
            return "Completed Ollama comparison contains an invalid tier."
        if shift["before"] == shift["after"]:
            return "Completed Ollama comparison contains a tier shift that did not change."
        shift_ids.append(finding_id)
    if shift_ids != sorted(set(shift_ids)):
        return "Completed Ollama comparison tier shifts must be unique and sorted."
    return None


def validate_runtime_performance(stored: dict[str, Any], current: dict[str, Any]) -> str | None:
    for role in ("calibration", "holdout"):
        stored_metrics = stored[role]["metrics"]
        performance = stored_metrics["performance"]
        current_performance = current[role]["metrics"]["performance"]
        if not math.isclose(
            performance["megabytes_scanned"],
            current_performance["megabytes_scanned"],
            rel_tol=0.0,
            abs_tol=1e-12,
        ):
            return f"Stored {role} megabytes_scanned does not match the generated corpus bytes."

        elapsed = performance["elapsed_seconds"]
        expected_files_per_second = stored_metrics["scanned_files"] / elapsed
        if not math.isclose(
            performance["files_per_second"],
            expected_files_per_second,
            rel_tol=1e-12,
            abs_tol=1e-12,
        ):
            return f"Stored {role} files_per_second is inconsistent with elapsed_seconds."
        expected_megabytes_per_second = performance["megabytes_scanned"] / elapsed
        if not math.isclose(
            performance["megabytes_per_second"],
            expected_megabytes_per_second,
            rel_tol=1e-12,
            abs_tol=1e-12,
        ):
            return f"Stored {role} megabytes_per_second is inconsistent with elapsed_seconds."
    return None


def validate_stored_llm(llm: Any, current_holdout: dict[str, Any] | None = None) -> str | None:
    if not isinstance(llm, dict):
        return "Stored Ollama evidence is missing or malformed."
    status = llm.get("status")
    statuses_with_reason = {
        "skipped_unavailable",
        "failed_model_identity",
        "failed_inference",
    }
    statuses_without_reason = {"not_requested", "completed"}
    if not isinstance(status, str) or status not in statuses_with_reason | statuses_without_reason:
        return f"Stored Ollama status is unsupported: {status!r}."
    expected_llm_fields = {"status", "configuration", "inference", "comparison"}
    if status in statuses_with_reason:
        expected_llm_fields.add("reason")
    if set(llm) != expected_llm_fields:
        return "Stored Ollama wrapper has unexpected or status-inappropriate fields."
    if status in statuses_with_reason and (
        not isinstance(llm.get("reason"), str) or not llm["reason"].strip()
    ):
        return "Stored Ollama failure/skip reason is missing or malformed."
    configuration = llm.get("configuration")
    inference = llm.get("inference")
    if not isinstance(configuration, dict) or not isinstance(inference, dict):
        return "Stored Ollama configuration or inference telemetry is malformed."
    configuration_fields = {
        "provider",
        "configured_model",
        "resolved_model",
        "resolved_model_digest",
        "host",
        "timeout_seconds",
        "options",
        "options_sha256",
        "prompt_source_sha256",
        "prompt_path_normalization",
    }
    if set(configuration) != configuration_fields:
        return "Stored Ollama configuration has unexpected or missing fields."
    if not isinstance(configuration.get("options"), dict) or set(configuration["options"]) != {
        "temperature",
        "seed",
    }:
        return "Stored Ollama inference options have unexpected or missing fields."
    if (
        not isinstance(configuration.get("configured_model"), str)
        or not configuration["configured_model"].strip()
    ):
        return "Stored Ollama configured_model must be a nonempty string."
    if set(inference) != {"attempts", "successes", "failures"}:
        return "Stored Ollama inference telemetry has unexpected or missing fields."
    counts = [inference.get(key) for key in ("attempts", "successes", "failures")]
    if any(not isinstance(value, int) or isinstance(value, bool) for value in counts):
        return "Stored Ollama inference telemetry is malformed."
    attempts, successes, failures = counts
    if min(attempts, successes, failures) < 0 or successes + failures != attempts:
        return "Stored Ollama inference telemetry is internally inconsistent."

    comparison = llm.get("comparison")
    if status == "completed":
        identity_error = validate_resolved_model_identity(configuration, "Completed")
        if identity_error is not None:
            return identity_error
        if attempts <= 0 or successes != attempts or failures != 0:
            return "Completed Ollama evidence lacks a fully successful measured inference run."
        if current_holdout is not None:
            comparison_error = validate_llm_comparison(comparison, current_holdout)
            if comparison_error is not None:
                return comparison_error
        elif not isinstance(comparison, dict):
            return "Completed Ollama evidence is missing its measured comparison."
    elif status == "skipped_unavailable":
        if attempts != 0 or comparison is not None:
            return "Unavailable Ollama evidence must not claim inference or a comparison."
        if (
            configuration.get("resolved_model") is not None
            or configuration.get("resolved_model_digest") is not None
        ):
            return "Unavailable Ollama evidence must not claim a resolved model identity."
    elif status in {"not_requested", "failed_model_identity", "failed_inference"}:
        if comparison is not None:
            return "Incomplete Ollama evidence must not claim a completed comparison."
        if status == "not_requested":
            if attempts != 0:
                return "Not-requested Ollama evidence must not claim inference attempts."
            if (
                configuration.get("resolved_model") is not None
                or configuration.get("resolved_model_digest") is not None
            ):
                return "Not-requested Ollama evidence must not claim a resolved model identity."
        elif status == "failed_inference":
            identity_error = validate_resolved_model_identity(configuration, "Failed-inference")
            if identity_error is not None:
                return identity_error
            if llm_scan_completed(
                {"attempts": attempts, "successes": successes, "failures": failures}
            ):
                return "Failed-inference Ollama evidence contradicts fully successful telemetry."
        else:
            resolved_model = configuration.get("resolved_model")
            resolved_digest = configuration.get("resolved_model_digest")
            configured_model = configuration.get("configured_model")
            if (
                not isinstance(resolved_model, str)
                or ":" not in resolved_model
                or not isinstance(configured_model, str)
                or not _model_matches(configured_model, resolved_model)
            ):
                return "Failed-model-identity Ollama evidence lacks the reported exact model tag."
            if resolved_digest is None:
                if attempts != 0:
                    return (
                        "Failed-model-identity Ollama evidence with no valid digest must not "
                        "claim inference attempts."
                    )
            elif normalize_model_digest(resolved_digest) != resolved_digest:
                return "Failed-model-identity Ollama evidence contains a malformed model digest."
    return None


def validate_resolved_model_identity(
    configuration: dict[str, Any], status_label: str
) -> str | None:
    resolved_model = configuration.get("resolved_model")
    resolved_digest = configuration.get("resolved_model_digest")
    if not isinstance(resolved_model, str) or ":" not in resolved_model:
        return f"{status_label} Ollama evidence does not identify an exact model tag."
    configured_model = configuration.get("configured_model")
    if not isinstance(configured_model, str) or not _model_matches(
        configured_model, resolved_model
    ):
        return f"{status_label} Ollama evidence has inconsistent configured and resolved models."
    normalized_digest = normalize_model_digest(resolved_digest)
    if normalized_digest is None or normalized_digest != resolved_digest:
        return (
            f"{status_label} Ollama evidence does not identify a normalized SHA-256 model digest."
        )
    return None
