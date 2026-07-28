"""Markdown rendering for RedactLens evaluation evidence."""

from __future__ import annotations

import json
from typing import Any

from evidence_validation import LLM_COMPARISON_METRICS


def _bar(value: float, width: int = 24) -> str:
    filled = round(max(0.0, min(1.0, value)) * width)
    return "#" * filled + "." * (width - filled)


def _pass_label(passed: bool) -> str:
    return "PASS" if passed else "FAIL"


def render_report(data: dict[str, Any]) -> str:
    metadata = data["metadata"]
    calibration = data["calibration"]
    holdout = data["holdout"]["metrics"]
    calibration_manifest = metadata["corpora"]["calibration"]
    holdout_manifest = metadata["corpora"]["holdout"]
    lines = [
        "# RedactLens evaluation report",
        "",
        "> Headline metrics below come only from the selection-isolated holdout corpus. The",
        "> separate calibration corpus chooses confidence weights and the Tier A threshold.",
        "> Findings and plants use duplicate-safe one-to-one matching; gates require support.",
        "",
        "## Reproducibility metadata",
        "",
        f"- Generated (UTC): `{metadata['generated_at_utc']}`",
        f"- Corpus version: `{metadata['corpus_version']}`",
        f"- Detector configuration SHA-256: `{metadata['detector_configuration_sha256']}`",
        f"- Evaluation source SHA-256: `{metadata['evaluation_source_sha256']}`",
        f"- Selected confidence-weight profile: "
        f"`{metadata['selected_confidence_weight_profile']['profile_id']}` "
        f"(base offset {metadata['selected_confidence_weight_profile']['base_offset']:+.2f}, "
        f"context scale {metadata['selected_confidence_weight_profile']['context_scale']:.2f})",
        f"- Confidence-weight policy: {metadata['confidence_weight_selection_policy']}",
        f"- Selected Tier A threshold: `{metadata['selected_tier_threshold']:.4f}`",
        f"- Threshold policy: {metadata['threshold_selection_policy']}",
        f"- Calibration: seed `{calibration_manifest['seed']}`, "
        f"{calibration_manifest['document_count']} documents, digest "
        f"`{calibration_manifest['sha256']}`",
        f"- Holdout: seed `{holdout_manifest['seed']}`, "
        f"{holdout_manifest['document_count']} documents, digest "
        f"`{holdout_manifest['sha256']}`",
        "",
        "## Holdout headline results",
        "",
        "| quality gate | value | target | eligible support | result |",
        "|---|---:|---:|---:|---|",
    ]
    for name, label in [
        ("tier_a_precision", "Tier A precision"),
        ("tier_a_recall", "Tier A recall"),
        ("any_tier_recall", "Any-tier recall"),
    ]:
        gate = data["quality_gates"][name]
        lines.append(
            f"| {label} | {gate['value']:.3f} | >= {gate['target']:.2f} | "
            f"{gate['support']} | "
            f"{_pass_label(gate['passed'])} |"
        )
    deployment_gate = data["quality_gates"]["selected_threshold_deployed"]
    lines.append(
        f"| Selected threshold is deployed | {deployment_gate['value']:.4f} | "
        f"== {deployment_gate['target']:.4f} | 1 | "
        f"{_pass_label(deployment_gate['passed'])} |"
    )
    weight_gate = data["quality_gates"]["selected_confidence_weights_deployed"]
    lines.append(
        f"| Selected confidence weights are deployed | `{weight_gate['value']}` | "
        f"== `{weight_gate['target']}` | 1 | {_pass_label(weight_gate['passed'])} |"
    )

    user_impact = holdout["user_impact"]
    performance = holdout["performance"]
    lines.extend(
        [
            "",
            f"Holdout emitted {holdout['canonical_findings']} canonical findings from "
            f"{holdout['raw_detector_hits']} raw detector opinions across "
            f"{holdout_manifest['document_count']} documents. Consolidation absorbed "
            f"{holdout['consolidated_hits']} opinions; {holdout['suppressed_hits']} of those "
            "were explicit suppressions.",
            "",
            "| user-impact metric | value |",
            "|---|---:|",
            f"| Overall precision | {holdout['overall_precision']:.3f} |",
            f"| Overall recall | {holdout['overall_recall']:.3f} |",
            f"| Overall F1 | {holdout['overall_f1']:.3f} |",
            f"| Tier A recall | {holdout['tier_a_recall']:.3f} |",
            f"| Tier B rescue recall | {holdout['tier_b_rescue_recall']:.3f} |",
            f"| False positives / 1,000 files | "
            f"{user_impact['false_positives_per_1000_files']:.2f} |",
            f"| Canonical findings / planted value | "
            f"{user_impact['canonical_findings_per_planted_value']:.3f} |",
            f"| Files / second (single local run) | {performance['files_per_second']:.1f} |",
            f"| MB / second (single local run) | {performance['megabytes_per_second']:.2f} |",
            "",
            "## Calibration-only confidence-weight selection",
            "",
            "Every profile below is evaluated only against calibration labels. Selection "
            "minimizes Brier score plus expected calibration error; threshold quality and "
            "deployment stability are deterministic tie-breaks.",
            "",
            "| profile | base offset | context scale | Brier | ECE | threshold | precision | "
            "recall | eligible |",
            "|---|---:|---:|---:|---:|---:|---:|---:|---|",
        ]
    )
    selected_profile_id = metadata["selected_confidence_weight_profile"]["profile_id"]
    for row in calibration["weight_profile_sweep"]:
        profile = row["profile"]
        marker = " **selected**" if profile["profile_id"] == selected_profile_id else ""
        threshold = (
            f"{row['selected_threshold']:.4f}"
            if row["selected_threshold"] is not None
            else "unavailable"
        )
        precision = (
            f"{row['threshold_precision']:.3f}"
            if row["threshold_precision"] is not None
            else "unavailable"
        )
        recall = (
            f"{row['threshold_recall']:.3f}"
            if row["threshold_recall"] is not None
            else "unavailable"
        )
        lines.append(
            f"| `{profile['profile_id']}`{marker} | {profile['base_offset']:+.2f} | "
            f"{profile['context_scale']:.2f} | {row['brier_score']:.4f} | "
            f"{row['expected_calibration_error']:.4f} | {threshold} | {precision} | "
            f"{recall} | {'yes' if row['eligible'] else 'no'} |"
        )
    lines.extend(
        [
            "",
            "## Calibration-only threshold selection",
            "",
            f"Minimum acceptable calibration precision: "
            f"`{metadata['calibration_minimum_precision']:.2f}`. The selected threshold is "
            "marked; no holdout labels participate in this choice.",
            "",
            "| threshold | precision | recall | F1 | findings |",
            "|---:|---:|---:|---:|---:|",
        ]
    )
    for row in calibration["threshold_sweep"]:
        marker = " **selected**" if row["threshold"] == metadata["selected_tier_threshold"] else ""
        lines.append(
            f"| {row['threshold']:.4f}{marker} | {row['precision']:.3f} | "
            f"{row['recall']:.3f} | {row['f1']:.3f} | "
            f"{row['num_findings_at_or_above']} |"
        )
    lines.extend(["", "```text"])
    for row in calibration["threshold_sweep"]:
        lines.append(f"{row['threshold']:.4f}  P {_bar(row['precision'])} {row['precision']:.2f}")
        lines.append(f"      R {_bar(row['recall'])} {row['recall']:.2f}")
    lines.extend(["```", "", "## Holdout results by detector", ""])
    lines.extend(
        [
            "| detector | raw precision | raw recall | expected plants | raw FP | raw FN | "
            "primary findings | "
            "canonical contributions | raw opinions | consolidated opinions | "
            "consolidation rate |",
            "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
        ]
    )
    for detector_id, values in holdout["per_detector"].items():
        lines.append(
            f"| `{detector_id}` | {values['precision']:.3f} | {values['recall']:.3f} | "
            f"{values['expected_plants']} | "
            f"{values['false_positives']} | {values['false_negatives']} | "
            f"{values['emitted_findings']} | "
            f"{values.get('canonical_contributions', values['emitted_findings'])} | "
            f"{values['raw_opinions']} | "
            f"{values.get('consolidated_opinions', 0)} | "
            f"{values['consolidation_rate']:.1%} |"
        )
    lines.extend(
        [
            "",
            "## Holdout results by category",
            "",
            "| category | precision | recall | expected plants | F1 | FP | FN |",
            "|---|---:|---:|---:|---:|---:|---:|",
        ]
    )
    for category, values in holdout["per_category"].items():
        lines.append(
            f"| `{category}` | {values['precision']:.3f} | {values['recall']:.3f} | "
            f"{values['expected_plants']} | {values['f1']:.3f} | "
            f"{values['false_positives']} | "
            f"{values['false_negatives']} |"
        )

    confidence = holdout["confidence_calibration"]
    lines.extend(
        [
            "",
            "## Confidence calibration",
            "",
            f"- Brier score: `{confidence['brier_score']:.4f}` (lower is better)",
            f"- Expected calibration error: "
            f"`{confidence['expected_calibration_error']:.4f}` (lower is better)",
            "",
            "| confidence bucket | findings | average confidence | observed precision |",
            "|---|---:|---:|---:|",
        ]
    )
    for bucket in confidence["buckets"]:
        closing = "]" if bucket["upper"] == 1.0 else ")"
        lines.append(
            f"| [{bucket['lower']:.1f}, {bucket['upper']:.1f}{closing} | "
            f"{bucket['count']} | "
            f"{bucket['average_confidence']:.3f} | {bucket['accuracy']:.3f} |"
        )

    llm = data["llm"]
    configuration = llm["configuration"]
    lines.extend(
        [
            "",
            "## Ollama comparison",
            "",
            f"Configuration: provider `{configuration['provider']}`, configured model "
            f"`{configuration['configured_model']}`, resolved server model "
            f"`{configuration['resolved_model'] or 'unavailable'}`, host "
            f"`{configuration['host']}`, timeout "
            f"`{configuration['timeout_seconds']}` seconds.",
            f"Resolved model digest: `{configuration['resolved_model_digest'] or 'unavailable'}`.",
            f"Inference options: `{json.dumps(configuration['options'], sort_keys=True)}`; "
            f"options SHA-256 `{configuration['options_sha256']}`.",
            f"Prompt source SHA-256: `{configuration['prompt_source_sha256']}`.",
            f"Prompt path normalization: `{configuration['prompt_path_normalization']}`.",
            f"Inference telemetry: {llm['inference']['attempts']} attempts, "
            f"{llm['inference']['successes']} successes, "
            f"{llm['inference']['failures']} failures.",
            "",
        ]
    )
    if llm["status"] == "completed":
        comparison = llm["comparison"]
        lines.extend(
            [
                "Status: completed against the same holdout corpus.",
                "",
                "| metric | baseline | with LLM | delta | assessment |",
                "|---|---:|---:|---:|---|",
            ]
        )
        for name in LLM_COMPARISON_METRICS:
            values = comparison["metrics"][name]
            lines.append(
                f"| `{name}` | {values['baseline']:.4f} | {values['with_llm']:.4f} | "
                f"{values['delta']:+.4f} | {values['status']} |"
            )
        lines.extend(
            [
                "",
                f"Tier shifts: {len(comparison['tier_shifts'])}. Improvements: "
                f"{', '.join(comparison['improvements']) or 'none'}. Regressions: "
                f"{', '.join(comparison['regressions']) or 'none'}.",
            ]
        )
    else:
        lines.append(f"Status: `{llm['status']}`. {llm.get('reason', '')}".rstrip())

    lines.extend(
        [
            "",
            "## Interpretation and limits",
            "",
            "- All planted values are fabricated; no real credentials or personal data are used.",
            "- The public holdout is deterministic, structurally role-separated, and excluded "
            "from automated weight/threshold selection. It is regression evidence, not a "
            "blinded external test set or a claim about all real-world repositories.",
            "- This is a hard-negative-enriched stress corpus. False positives per 1,000 files "
            "are not an estimate of a typical production repository's incident rate.",
            "- Per-detector rows make weak detectors and duplicate consolidation visible instead "
            "of allowing aggregate scores to hide them.",
            "- Throughput is an indicative single-run measurement and is excluded from the "
            "deterministic stale-report comparison.",
            "",
            "Reproduce with `python tooling/eval/run_eval.py`; verify freshness with "
            "`python tooling/eval/run_eval.py --check`.",
            "",
        ]
    )
    return "\n".join(lines)
