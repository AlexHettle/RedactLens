import copy
import hashlib
import json
import os
import subprocess
from types import SimpleNamespace

import pytest
from redactlens_core.llm.adapter import LLMVerdict, OllamaModelInfo

import run_eval

TEST_MODEL_DIGEST = "sha256:" + "a" * 64


def test_git_attributes_pin_all_raw_digest_inputs_and_reports_to_lf():
    repository_root = run_eval.ROOT.parent
    if not (repository_root / ".git").exists():
        pytest.skip("Git checkout metadata is required to inspect attributes")
    paths = sorted(
        {
            *run_eval._detector_configuration_paths(),
            *run_eval._evaluation_source_paths(),
            *run_eval._prompt_source_paths(),
            run_eval.REPORT_PATH,
            run_eval.REPORT_DATA_PATH,
        },
        key=lambda path: path.as_posix(),
    )
    relative_paths = [path.relative_to(repository_root).as_posix() for path in paths]

    result = subprocess.run(
        [
            "git",
            "-c",
            f"safe.directory={repository_root.as_posix()}",
            "check-attr",
            "eol",
            "--",
            *relative_paths,
        ],
        cwd=repository_root,
        check=True,
        capture_output=True,
        text=True,
    )
    attribute_lines = [line for line in result.stdout.splitlines() if line]

    assert len(attribute_lines) == len(relative_paths)
    assert all(line.endswith(": eol: lf") for line in attribute_lines)


def test_calibration_selects_threshold_and_holdout_meets_quality_gates():
    data = run_eval.build_evaluation(include_llm=False)

    selected = data["metadata"]["selected_tier_threshold"]
    assert selected in {row["threshold"] for row in data["calibration"]["threshold_sweep"]}
    assert all(gate["passed"] for gate in data["quality_gates"].values())
    assert all(gate["support"] > 0 for gate in data["quality_gates"].values())
    deployment_gate = data["quality_gates"]["selected_threshold_deployed"]
    assert deployment_gate["value"] == run_eval.DEFAULT_TIER_THRESHOLD
    assert deployment_gate["passed"]
    weight_gate = data["quality_gates"]["selected_confidence_weights_deployed"]
    selected_weights = data["metadata"]["selected_confidence_weight_profile"]
    deployed_weights = data["metadata"]["deployed_confidence_weight_profile_before_calibration"]
    assert selected_weights == deployed_weights
    assert weight_gate["value"] == selected_weights["profile_id"]
    assert weight_gate["passed"]
    assert len(data["calibration"]["weight_profile_sweep"]) == len(
        run_eval.CALIBRATION_WEIGHT_PROFILES
    )
    assert data["holdout"]["metrics"]["tier_a_precision"] >= 0.90
    assert data["holdout"]["metrics"]["any_tier_recall"] >= 0.95


def test_report_counts_all_documents_and_exposes_detailed_holdout_metrics():
    data = run_eval.build_evaluation(include_llm=False)
    holdout_manifest = data["metadata"]["corpora"]["holdout"]
    holdout = data["holdout"]["metrics"]

    assert holdout_manifest["document_count"] == holdout["scanned_files"]
    assert holdout_manifest["document_count"] > holdout_manifest["positive_plant_count"] / 2
    assert "aws_access_key" in holdout["per_detector"]
    assert "credential" in holdout["per_category"]
    assert holdout["confidence_calibration"]["buckets"]
    assert holdout["performance"]["files_per_second"] > 0
    detector_ids = {detector.id for detector in run_eval.load_default_registry().get_all()}
    assert set(holdout["per_detector"]) == detector_ids
    assert all(item["expected_plants"] > 0 for item in holdout["per_detector"].values())
    calibration = data["calibration"]["metrics"]
    assert set(calibration["per_detector"]) == detector_ids
    assert all(item["expected_plants"] > 0 for item in calibration["per_detector"].values())
    assert (
        sum(item["raw_opinions"] for item in holdout["per_detector"].values())
        == holdout["raw_detector_hits"]
    )
    assert (
        sum(item["emitted_findings"] for item in holdout["per_detector"].values())
        == holdout["canonical_findings"]
    )
    assert (
        sum(item["consolidated_opinions"] for item in holdout["per_detector"].values())
        == holdout["consolidated_hits"]
    )
    assert all(item["raw_opinions_complete"] for item in holdout["per_detector"].values())
    email = holdout["per_detector"]["email"]
    assert email["precision"] < email["canonical_precision"]
    assert email["false_positives"] > email["canonical_false_positives"]
    assert data["schema_version"] == 3
    assert len(data["metadata"]["detector_configuration_sha256"]) == 64
    assert len(data["metadata"]["evaluation_source_sha256"]) == 64
    llm_configuration = data["llm"]["configuration"]
    assert llm_configuration["options"] == run_eval.LLM_EVALUATION_OPTIONS
    assert len(llm_configuration["options_sha256"]) == 64
    assert len(llm_configuration["prompt_source_sha256"]) == 64


def test_threshold_selection_preserves_deployed_value_on_best_plateau():
    rows = [
        {"threshold": 0.70, "precision": 0.95, "recall": 0.80},
        {"threshold": 0.75, "precision": 0.95, "recall": 0.80},
        {"threshold": 0.80, "precision": 0.95, "recall": 0.80},
    ]

    selected = run_eval.select_threshold(
        rows,
        minimum_precision=0.90,
        preferred_threshold=0.75,
    )

    assert selected == 0.75


def test_calibration_metrics_are_recomputed_at_a_nondefault_selected_threshold(
    tmp_path,
    monkeypatch,
):
    def force_one(selected_rows, *, deployed_profile_id):
        forced = copy.deepcopy(selected_rows[0])
        forced["selected_threshold"] = 1.0
        return forced

    monkeypatch.setattr(run_eval, "select_weight_profile", force_one)
    bundle = run_eval.generate_corpus.generate_all()["calibration"]

    _, selected_threshold, metrics, sweep, _ = run_eval._calibrate_confidence_weights_and_threshold(
        bundle, tmp_path
    )
    selected_row = next(row for row in sweep if row["threshold"] == selected_threshold)

    assert selected_threshold == 1.0
    assert metrics["tier_a_findings"] == selected_row["num_findings_at_or_above"]
    assert metrics["tier_a_true_positive_findings"] == selected_row["true_positive_findings"]
    assert metrics["tier_a_precision"] == selected_row["precision"]
    assert metrics["tier_a_recall"] == selected_row["recall"]


def test_tier_shifts_use_corpus_relative_semantic_identity():
    def finding(file, start, tier, detector_id="email"):
        return SimpleNamespace(
            file=file,
            start=start,
            end=start + 5,
            detector_id=detector_id,
            category="personal_id",
            tier=tier,
        )

    baseline = [finding("nested/a.txt", 10, "B"), finding("b.txt", 20, "A")]
    with_llm = [
        finding("nested/a.txt", 10, "A", detector_id="phone"),
        finding("b.txt", 20, "A"),
        finding("c.txt", 30, "B"),
    ]

    shifts = run_eval._tier_shifts(baseline, with_llm)

    assert len(shifts) == 1
    assert shifts[0]["before"] == "B"
    assert shifts[0]["after"] == "A"
    assert shifts[0]["finding_id"] == run_eval._semantic_finding_id(
        ("nested/a.txt", 10, 15, "personal_id")
    )


def test_evaluation_adapter_normalizes_only_the_temporary_file_path(tmp_path):
    class Delegate:
        prompt = None

        def available(self):
            return True

        def judge(self, question):
            self.prompt = question
            return None

    documents = tmp_path / "documents"
    delegate = Delegate()
    adapter = run_eval._CorpusRelativeAdapter(delegate, documents)
    source_path = f"{documents.resolve()}\\nested\\sample.py"

    adapter.judge(f"File path: {source_path}\nSurrounding text:\nC:\\keep\\content")

    assert delegate.prompt == (
        "File path: <EVAL_CORPUS>/nested/sample.py\nSurrounding text:\nC:\\keep\\content"
    )


def _comparison_metrics(**overrides):
    result = {
        "tier_a_precision": 0.90,
        "tier_a_recall": 0.80,
        "overall_precision": 0.80,
        "overall_recall": 1.00,
        "user_impact": {"false_positives_per_1000_files": 10.0},
        "confidence_calibration": {
            "brier_score": 0.20,
            "expected_calibration_error": 0.10,
        },
    }
    result.update(overrides)
    return result


def test_llm_comparison_reports_regressions_as_well_as_improvements():
    baseline = _comparison_metrics()
    with_llm = _comparison_metrics(
        tier_a_precision=0.85,
        tier_a_recall=0.90,
        user_impact={"false_positives_per_1000_files": 5.0},
        confidence_calibration={
            "brier_score": 0.25,
            "expected_calibration_error": 0.05,
        },
    )

    comparison = run_eval._llm_comparison(baseline, with_llm, [])

    assert "tier_a_recall" in comparison["improvements"]
    assert "false_positives_per_1000_files" in comparison["improvements"]
    assert "tier_a_precision" in comparison["regressions"]
    assert "brier_score" in comparison["regressions"]


def test_stable_projection_excludes_runtime_only_measurements():
    data = run_eval.build_evaluation(include_llm=False)
    changed = copy.deepcopy(data)
    changed["metadata"]["generated_at_utc"] = "2099-01-01T00:00:00+00:00"
    changed["holdout"]["metrics"]["performance"]["files_per_second"] = -1
    changed["llm"]["status"] = "completed"
    changed["llm"]["configuration"]["resolved_model"] = "llama3.2:latest"
    changed["llm"]["configuration"]["resolved_model_digest"] = TEST_MODEL_DIGEST

    assert run_eval.stable_projection(data) == run_eval.stable_projection(changed)

    changed["llm"]["configuration"]["configured_model"] = "runtime-model:tag"
    assert run_eval.stable_projection(data) != run_eval.stable_projection(changed)

    changed = copy.deepcopy(data)
    changed["llm"]["configuration"]["options"]["seed"] += 1
    assert run_eval.stable_projection(data) != run_eval.stable_projection(changed)


def test_written_artifacts_are_linked_and_tampering_is_detected(tmp_path):
    report_path = tmp_path / "report.md"
    data_path = tmp_path / "report.json"
    data = run_eval.build_evaluation(include_llm=False)

    report = run_eval.write_artifacts(
        data,
        report_path=report_path,
        data_path=data_path,
    )
    stored = json.loads(data_path.read_text(encoding="utf-8"))

    assert "Headline metrics below come only from the selection-isolated holdout corpus" in report
    assert "Calibration-only confidence-weight selection" in report
    assert stored["artifact"]["report_sha256"]
    assert "consolidation rate" in report
    assert "| detector | raw precision | raw recall | expected plants |" in report
    assert "| category | precision | recall | expected plants |" in report
    assert report.count("expected plants") >= 2
    assert "of those were explicit suppressions" in report
    assert b"\r" not in report_path.read_bytes()
    assert b"\r" not in data_path.read_bytes()

    tampered_report = report + "tampered but self-consistently re-hashed\n"
    stored["artifact"]["report_sha256"] = hashlib.sha256(
        tampered_report.encode("utf-8")
    ).hexdigest()
    run_eval._write_lf_text(report_path, tampered_report)
    run_eval._write_lf_text(data_path, json.dumps(stored, indent=2, sort_keys=True) + "\n")
    fresh, message = run_eval.check_report_fresh(
        report_path=report_path,
        data_path=data_path,
    )

    assert not fresh
    assert "canonical" in message or "does not match" in message


def test_freshness_compares_against_the_current_renderer(tmp_path, monkeypatch):
    report_path = tmp_path / "report.md"
    data_path = tmp_path / "report.json"
    data = run_eval.build_evaluation(include_llm=False)
    run_eval.write_artifacts(data, report_path=report_path, data_path=data_path)
    original_renderer = run_eval.render_report
    monkeypatch.setattr(
        run_eval,
        "render_report",
        lambda evidence: original_renderer(evidence) + "renderer semantics changed\n",
    )

    fresh, message = run_eval.check_report_fresh(
        report_path=report_path,
        data_path=data_path,
    )

    assert not fresh
    assert "current canonical LF rendering" in message


def test_freshness_rejects_a_current_report_with_failed_quality_gates(tmp_path, monkeypatch):
    current = run_eval.build_evaluation(include_llm=False)
    current["quality_gates"]["tier_a_precision"] = {
        "value": 0.0,
        "target": 0.90,
        "support": 1,
        "passed": False,
    }
    report_path = tmp_path / "report.md"
    data_path = tmp_path / "report.json"
    run_eval.write_artifacts(current, report_path=report_path, data_path=data_path)
    monkeypatch.setattr(
        run_eval,
        "build_evaluation",
        lambda *, include_llm: copy.deepcopy(current),
    )

    fresh, message = run_eval.check_report_fresh(
        report_path=report_path,
        data_path=data_path,
        corpus_path=tmp_path / "not-materialized",
    )

    assert not fresh
    assert "quality gates failed" in message
    assert "tier_a_precision" in message


def test_freshness_rejects_canonical_but_malformed_json_without_raising(tmp_path):
    report_path = tmp_path / "report.md"
    data_path = tmp_path / "report.json"
    run_eval._write_lf_text(report_path, "# invented report\n")
    run_eval._write_lf_text(data_path, "{}\n")

    fresh, message = run_eval.check_report_fresh(
        report_path=report_path,
        data_path=data_path,
    )

    assert not fresh
    assert "top-level fields" in message or "schema_version" in message


def test_freshness_rejects_oversized_json_integer_without_raising(tmp_path):
    report_path = tmp_path / "report.md"
    data_path = tmp_path / "report.json"
    run_eval._write_lf_text(report_path, "# invented report\n")
    run_eval._write_lf_text(data_path, '{"oversized": ' + ("9" * 5_000) + "}\n")

    fresh, message = run_eval.check_report_fresh(
        report_path=report_path,
        data_path=data_path,
    )

    assert not fresh
    assert "could not read evaluation evidence" in message.lower()


def test_freshness_rejects_excessively_nested_json_without_raising(tmp_path):
    report_path = tmp_path / "report.md"
    data_path = tmp_path / "report.json"
    run_eval._write_lf_text(report_path, "# invented report\n")
    run_eval._write_lf_text(data_path, ("[" * 2_000) + "0" + ("]" * 2_000) + "\n")

    fresh, message = run_eval.check_report_fresh(
        report_path=report_path,
        data_path=data_path,
    )

    assert not fresh
    assert "could not read evaluation evidence" in message.lower()


def test_freshness_rejects_impossible_or_malformed_runtime_performance(
    tmp_path,
    monkeypatch,
):
    current = run_eval.build_evaluation(include_llm=False)
    monkeypatch.setattr(
        run_eval,
        "build_evaluation",
        lambda *, include_llm: copy.deepcopy(current),
    )

    for case in ("negative", "nan", "infinite", "missing"):
        stored = copy.deepcopy(current)
        performance = stored["holdout"]["metrics"]["performance"]
        if case == "negative":
            performance["files_per_second"] = -99.0
        elif case == "nan":
            performance["elapsed_seconds"] = float("nan")
        elif case == "infinite":
            performance["megabytes_per_second"] = float("inf")
        else:
            performance.pop("elapsed_seconds")
        case_dir = tmp_path / case
        case_dir.mkdir()
        report_path = case_dir / "report.md"
        data_path = case_dir / "report.json"
        run_eval.write_artifacts(stored, report_path=report_path, data_path=data_path)

        fresh, message = run_eval.check_report_fresh(
            report_path=report_path,
            data_path=data_path,
        )

        assert not fresh, case
        assert "performance" in message.lower(), (case, message)


def test_freshness_rejects_deterministic_byte_or_derived_throughput_tampering(
    tmp_path,
    monkeypatch,
):
    current = run_eval.build_evaluation(include_llm=False)
    monkeypatch.setattr(
        run_eval,
        "build_evaluation",
        lambda *, include_llm: copy.deepcopy(current),
    )

    for case in ("megabytes_scanned", "files_per_second", "megabytes_per_second"):
        stored = copy.deepcopy(current)
        performance = stored["holdout"]["metrics"]["performance"]
        if case == "megabytes_scanned":
            performance["megabytes_scanned"] += 1.0
            performance["megabytes_per_second"] = (
                performance["megabytes_scanned"] / performance["elapsed_seconds"]
            )
        else:
            performance[case] += 1.0
        case_dir = tmp_path / case
        case_dir.mkdir()
        report_path = case_dir / "report.md"
        data_path = case_dir / "report.json"
        run_eval.write_artifacts(stored, report_path=report_path, data_path=data_path)

        fresh, message = run_eval.check_report_fresh(
            report_path=report_path,
            data_path=data_path,
        )

        assert not fresh, case
        assert case in message, (case, message)


def test_freshness_rejects_an_unparseable_generated_timestamp(tmp_path):
    stored = run_eval.build_evaluation(include_llm=False)
    stored["metadata"]["generated_at_utc"] = "invented"
    report_path = tmp_path / "report.md"
    data_path = tmp_path / "report.json"
    run_eval.write_artifacts(stored, report_path=report_path, data_path=data_path)

    fresh, message = run_eval.check_report_fresh(
        report_path=report_path,
        data_path=data_path,
    )

    assert not fresh
    assert "generated_at_utc" in message


def _materialize_corpus(destination):
    for role, bundle in run_eval.generate_corpus.generate_all().items():
        run_eval.generate_corpus.write_bundle(bundle, destination / role)


def test_freshness_allows_an_unmaterialized_optional_corpus(tmp_path, monkeypatch):
    current = run_eval.build_evaluation(include_llm=False)
    report_path = tmp_path / "report.md"
    data_path = tmp_path / "report.json"
    run_eval.write_artifacts(current, report_path=report_path, data_path=data_path)
    monkeypatch.setattr(
        run_eval,
        "build_evaluation",
        lambda *, include_llm: copy.deepcopy(current),
    )

    missing_fresh, missing_message = run_eval.check_report_fresh(
        report_path=report_path,
        data_path=data_path,
        corpus_path=tmp_path / "not-materialized",
    )
    empty_corpus = tmp_path / "empty-corpus"
    empty_corpus.mkdir()
    (empty_corpus / ".gitkeep").write_text("", encoding="utf-8")
    empty_fresh, empty_message = run_eval.check_report_fresh(
        report_path=report_path,
        data_path=data_path,
        corpus_path=empty_corpus,
    )
    materialized_corpus = tmp_path / "materialized-corpus"
    _materialize_corpus(materialized_corpus)
    materialized_fresh, materialized_message = run_eval.check_report_fresh(
        report_path=report_path,
        data_path=data_path,
        corpus_path=materialized_corpus,
    )

    assert missing_fresh, missing_message
    assert empty_fresh, empty_message
    assert materialized_fresh, materialized_message


def test_materialized_corpus_rejects_linked_root_and_hardlinked_files(tmp_path, monkeypatch):
    corpus_root = tmp_path / "corpus-root"
    corpus_root.mkdir()
    original_link_kind = run_eval._linked_entry_kind
    monkeypatch.setattr(
        run_eval,
        "_linked_entry_kind",
        lambda path: "junction" if path == corpus_root else original_link_kind(path),
    )

    root_error = run_eval._validate_checked_in_corpus(corpus_root)

    assert root_error is not None
    assert "linked or redirected" in root_error
    monkeypatch.setattr(run_eval, "_linked_entry_kind", original_link_kind)

    materialized = tmp_path / "hardlinked-corpus"
    _materialize_corpus(materialized)
    labels = materialized / "calibration" / "labels.json"
    external = tmp_path / "external-labels.json"
    external.write_bytes(labels.read_bytes())
    labels.unlink()
    try:
        os.link(external, labels)
    except OSError as error:
        pytest.skip(f"hardlinks are unavailable on this filesystem: {error}")

    hardlink_error = run_eval._validate_checked_in_corpus(materialized)

    assert hardlink_error is not None
    assert "differs from canonical generation" in hardlink_error


def test_freshness_rejects_drifted_or_partial_materialized_corpus(
    tmp_path,
    monkeypatch,
):
    current = run_eval.build_evaluation(include_llm=False)
    report_path = tmp_path / "report.md"
    data_path = tmp_path / "report.json"
    run_eval.write_artifacts(current, report_path=report_path, data_path=data_path)
    monkeypatch.setattr(
        run_eval,
        "build_evaluation",
        lambda *, include_llm: copy.deepcopy(current),
    )

    for case in ("changed", "missing", "extra", "one_role", "legacy"):
        corpus_path = tmp_path / f"corpus-{case}"
        if case == "one_role":
            bundles = run_eval.generate_corpus.generate_all()
            run_eval.generate_corpus.write_bundle(
                bundles["calibration"],
                corpus_path / "calibration",
            )
        elif case == "legacy":
            (corpus_path / "documents").mkdir(parents=True)
            (corpus_path / "labels.json").write_text("[]\n", encoding="utf-8")
        else:
            _materialize_corpus(corpus_path)
            if case == "changed":
                labels = corpus_path / "calibration" / "labels.json"
                labels.write_bytes(labels.read_bytes() + b"tampered\n")
            elif case == "missing":
                (corpus_path / "holdout" / "manifest.json").unlink()
            else:
                (corpus_path / "holdout" / "documents" / "unexpected.txt").write_text(
                    "extra\n",
                    encoding="utf-8",
                )

        fresh, message = run_eval.check_report_fresh(
            report_path=report_path,
            data_path=data_path,
            corpus_path=corpus_path,
        )

        assert not fresh, case
        assert "corpus" in message.lower(), (case, message)
        assert "regenerate" in message.lower() or "remove" in message.lower(), (
            case,
            message,
        )


def _llm_artifact(data, status):
    artifact = copy.deepcopy(data)
    artifact["llm"]["status"] = status
    artifact["llm"]["comparison"] = None
    artifact["llm"]["inference"] = {"attempts": 0, "successes": 0, "failures": 0}
    if status in {"completed", "failed_inference", "failed_model_identity"}:
        artifact["llm"]["configuration"]["resolved_model"] = "llama3.2:latest"
        artifact["llm"]["configuration"]["resolved_model_digest"] = TEST_MODEL_DIGEST
    if status == "completed":
        artifact["llm"]["inference"] = {"attempts": 3, "successes": 3, "failures": 0}
        metrics = artifact["holdout"]["metrics"]
        artifact["llm"]["comparison"] = run_eval._llm_comparison(metrics, metrics, [])
    elif status == "failed_inference":
        artifact["llm"]["inference"] = {"attempts": 3, "successes": 0, "failures": 3}
        artifact["llm"]["reason"] = "Every measured inference failed."
    elif status == "failed_model_identity":
        artifact["llm"]["reason"] = "The model identity changed during evaluation."
    elif status == "skipped_unavailable":
        artifact["llm"]["reason"] = "The configured model was unavailable."
    return artifact


@pytest.mark.parametrize("status", ["completed", "skipped_unavailable", "failed_inference"])
def test_completed_unavailable_and_failed_llm_artifacts_have_coherent_freshness(
    status,
    tmp_path,
    monkeypatch,
):
    current = run_eval.build_evaluation(include_llm=False)
    stored = _llm_artifact(current, status)
    report_path = tmp_path / "report.md"
    data_path = tmp_path / "report.json"
    run_eval.write_artifacts(stored, report_path=report_path, data_path=data_path)
    monkeypatch.setattr(
        run_eval,
        "build_evaluation",
        lambda *, include_llm: copy.deepcopy(current),
    )

    fresh, message = run_eval.check_report_fresh(
        report_path=report_path,
        data_path=data_path,
    )

    assert fresh, message


def test_freshness_rejects_a_different_configured_ollama_model(tmp_path, monkeypatch):
    current = run_eval.build_evaluation(include_llm=False)
    stored = copy.deepcopy(current)
    stored["llm"]["configuration"]["configured_model"] = "different-model:tag"
    report_path = tmp_path / "report.md"
    data_path = tmp_path / "report.json"
    run_eval.write_artifacts(stored, report_path=report_path, data_path=data_path)
    monkeypatch.setattr(
        run_eval,
        "build_evaluation",
        lambda *, include_llm: copy.deepcopy(current),
    )

    fresh, message = run_eval.check_report_fresh(
        report_path=report_path,
        data_path=data_path,
    )

    assert not fresh
    assert "stale" in message.lower()


def test_freshness_rejects_self_consistent_but_tampered_llm_comparisons(
    tmp_path,
    monkeypatch,
):
    current = run_eval.build_evaluation(include_llm=False)
    monkeypatch.setattr(
        run_eval,
        "build_evaluation",
        lambda *, include_llm: copy.deepcopy(current),
    )

    for case in (
        "baseline",
        "delta",
        "status",
        "improvements",
        "missing_metric",
        "tier_shift",
    ):
        stored = _llm_artifact(current, "completed")
        comparison = stored["llm"]["comparison"]
        if case == "baseline":
            comparison["metrics"]["tier_a_precision"]["baseline"] -= 0.1
        elif case == "delta":
            comparison["metrics"]["tier_a_precision"]["delta"] = 0.5
        elif case == "status":
            comparison["metrics"]["tier_a_precision"]["status"] = "improvement"
        elif case == "improvements":
            comparison["improvements"] = ["tier_a_precision"]
        elif case == "missing_metric":
            comparison["metrics"].pop("brier_score")
        else:
            comparison["tier_shifts"] = [{"finding_id": "invented", "before": "A", "after": "A"}]

        case_dir = tmp_path / case
        case_dir.mkdir()
        report_path = case_dir / "report.md"
        data_path = case_dir / "report.json"
        if case == "missing_metric":
            malformed_report = "# self-consistent comparison missing a required metric\n"
            stored["artifact"] = {
                "report_sha256": hashlib.sha256(malformed_report.encode("utf-8")).hexdigest()
            }
            run_eval._write_lf_text(report_path, malformed_report)
            run_eval._write_lf_text(
                data_path,
                json.dumps(stored, indent=2, sort_keys=True) + "\n",
            )
        else:
            run_eval.write_artifacts(stored, report_path=report_path, data_path=data_path)

        fresh, message = run_eval.check_report_fresh(
            report_path=report_path,
            data_path=data_path,
        )

        assert not fresh, case
        assert "comparison" in message.lower(), (case, message)


def test_freshness_rejects_unknown_or_status_inappropriate_schema_claims(
    tmp_path,
    monkeypatch,
):
    current = run_eval.build_evaluation(include_llm=False)
    monkeypatch.setattr(
        run_eval,
        "build_evaluation",
        lambda *, include_llm: copy.deepcopy(current),
    )

    for case in (
        "top_level",
        "artifact",
        "llm_wrapper",
        "inference",
        "comparison_wrapper",
        "completed_reason",
        "non_string_status",
    ):
        stored = (
            _llm_artifact(current, "completed")
            if case in {"comparison_wrapper", "completed_reason"}
            else copy.deepcopy(current)
        )
        if case == "top_level":
            stored["invented_quality_claim"] = {"passed": True}
        elif case == "artifact":
            stored["artifact"] = {"invented_quality_claim": True}
        elif case == "llm_wrapper":
            stored["llm"]["invented_quality_claim"] = True
        elif case == "inference":
            stored["llm"]["inference"]["invented_successes"] = 999
        elif case == "comparison_wrapper":
            stored["llm"]["comparison"]["invented_quality_claim"] = True
        elif case == "non_string_status":
            stored["llm"]["status"] = []
        else:
            stored["llm"]["reason"] = "Completed, allegedly."
        case_dir = tmp_path / case
        case_dir.mkdir()
        report_path = case_dir / "report.md"
        data_path = case_dir / "report.json"
        run_eval.write_artifacts(stored, report_path=report_path, data_path=data_path)

        fresh, message = run_eval.check_report_fresh(
            report_path=report_path,
            data_path=data_path,
        )

        assert not fresh, case
        assert any(
            term in message.lower() for term in ("unexpected", "inappropriate", "unsupported")
        ), (
            case,
            message,
        )


def test_freshness_rejects_status_identity_and_telemetry_contradictions(
    tmp_path,
    monkeypatch,
):
    current = run_eval.build_evaluation(include_llm=False)
    monkeypatch.setattr(
        run_eval,
        "build_evaluation",
        lambda *, include_llm: copy.deepcopy(current),
    )

    cases = {
        "completed_empty_tag": "completed",
        "completed_empty_base": "completed",
        "completed_leading_space": "completed",
        "completed_tag_space": "completed",
        "empty_configured": "not_requested",
        "skipped_resolved": "skipped_unavailable",
        "failed_fully_successful": "failed_inference",
        "failed_unrelated": "failed_inference",
        "failed_missing_digest": "failed_inference",
        "failed_garbage_digest": "failed_inference",
        "identity_unrelated": "failed_model_identity",
        "identity_garbage_digest": "failed_model_identity",
        "identity_attempts_without_digest": "failed_model_identity",
    }
    for case, status in cases.items():
        stored = _llm_artifact(current, status)
        configuration = stored["llm"]["configuration"]
        inference = stored["llm"]["inference"]
        if case.startswith("completed_"):
            malformed = {
                "completed_empty_tag": "llama3.2:",
                "completed_empty_base": ":latest",
                "completed_leading_space": " :latest",
                "completed_tag_space": "llama3.2: latest",
            }[case]
            configuration["configured_model"] = malformed
            configuration["resolved_model"] = malformed
        elif case == "empty_configured":
            configuration["configured_model"] = ""
        elif case == "skipped_resolved":
            configuration["resolved_model"] = "llama3.2:latest"
            configuration["resolved_model_digest"] = TEST_MODEL_DIGEST
        elif case == "failed_fully_successful":
            stored["llm"]["inference"] = {"attempts": 2, "successes": 2, "failures": 0}
        elif case.endswith("unrelated"):
            configuration["resolved_model"] = "unrelated:wrong"
        elif case.endswith("missing_digest"):
            configuration["resolved_model_digest"] = None
        elif case.endswith("garbage_digest"):
            configuration["resolved_model_digest"] = "garbage"
        else:
            configuration["resolved_model_digest"] = None
            inference.update(attempts=1, successes=0, failures=1)

        case_dir = tmp_path / case
        case_dir.mkdir()
        report_path = case_dir / "report.md"
        data_path = case_dir / "report.json"
        run_eval.write_artifacts(stored, report_path=report_path, data_path=data_path)

        fresh, message = run_eval.check_report_fresh(
            report_path=report_path,
            data_path=data_path,
        )

        assert not fresh, case
        assert "ollama" in message.lower(), (case, message)


def test_freshness_rejects_inconsistent_or_fabricated_model_identity(
    tmp_path,
    monkeypatch,
):
    current = run_eval.build_evaluation(include_llm=False)
    monkeypatch.setattr(
        run_eval,
        "build_evaluation",
        lambda *, include_llm: copy.deepcopy(current),
    )

    for case in ("unrelated_model", "invalid_digest"):
        stored = _llm_artifact(current, "completed")
        if case == "unrelated_model":
            stored["llm"]["configuration"]["resolved_model"] = "unrelated:wrong"
        else:
            stored["llm"]["configuration"]["resolved_model_digest"] = "not-even-a-sha256"
        case_dir = tmp_path / case
        case_dir.mkdir()
        report_path = case_dir / "report.md"
        data_path = case_dir / "report.json"
        run_eval.write_artifacts(stored, report_path=report_path, data_path=data_path)

        fresh, message = run_eval.check_report_fresh(
            report_path=report_path,
            data_path=data_path,
        )

        assert not fresh, case
        assert "model" in message.lower(), (case, message)


def _fake_ollama_type(verdict):
    class FakeOllama:
        def __init__(self, *, options):
            self.model = "llama3.2"
            self.options = options

        def available_model_info(self):
            return OllamaModelInfo("llama3.2:latest", TEST_MODEL_DIGEST)

        def available(self):
            return True

        def judge(self, question):
            del question
            return verdict

    return FakeOllama


def test_build_evaluation_marks_an_unavailable_model_without_inference(monkeypatch):
    class UnavailableOllama:
        def __init__(self, *, options):
            self.options = options

        def available_model_info(self):
            return None

    monkeypatch.setattr(run_eval, "OllamaAdapter", UnavailableOllama)

    data = run_eval.build_evaluation(include_llm=True)

    assert data["llm"]["status"] == "skipped_unavailable"
    assert data["llm"]["inference"] == {"attempts": 0, "successes": 0, "failures": 0}
    assert data["llm"]["comparison"] is None


@pytest.mark.parametrize("reported_digest", ["A" * 64, "a" * 64])
def test_generated_llm_artifact_canonicalizes_digest_and_passes_freshness(
    reported_digest,
    tmp_path,
    monkeypatch,
):
    class DigestVariantOllama:
        def __init__(self, *, options):
            self.model = "llama3.2"
            self.options = options
            self.info_calls = 0

        def available_model_info(self):
            self.info_calls += 1
            digest = reported_digest if self.info_calls == 1 else TEST_MODEL_DIGEST
            return OllamaModelInfo("llama3.2:latest", digest)

        def available(self):
            return True

        def judge(self, question):
            del question
            return LLMVerdict(True, 0.8, "measured")

    monkeypatch.setattr(run_eval, "OllamaAdapter", DigestVariantOllama)
    data = run_eval.build_evaluation(include_llm=True)
    report_path = tmp_path / "report.md"
    data_path = tmp_path / "report.json"
    run_eval.write_artifacts(data, report_path=report_path, data_path=data_path)

    fresh, message = run_eval.check_report_fresh(
        report_path=report_path,
        data_path=data_path,
    )

    assert data["llm"]["status"] == "completed"
    assert data["llm"]["configuration"]["resolved_model_digest"] == TEST_MODEL_DIGEST
    assert fresh, message


def test_completed_llm_evidence_requires_exact_identity_and_successful_telemetry():
    configuration = run_eval._llm_configuration()
    configuration["resolved_model"] = "llama3.2"
    configuration["resolved_model_digest"] = None
    evidence = {
        "status": "completed",
        "configuration": configuration,
        "inference": {"attempts": 1, "successes": 0, "failures": 1},
        "comparison": {},
    }

    error = run_eval._validate_stored_llm(evidence)

    assert error is not None
    assert "exact model tag" in error


@pytest.mark.parametrize(
    ("verdict", "expected_status"),
    [
        (LLMVerdict(True, 0.8, "measured"), "completed"),
        (None, "failed_inference"),
    ],
)
def test_build_evaluation_requires_successful_measured_inference(
    verdict,
    expected_status,
    monkeypatch,
):
    monkeypatch.setattr(run_eval, "OllamaAdapter", _fake_ollama_type(verdict))

    data = run_eval.build_evaluation(include_llm=True)

    assert data["llm"]["status"] == expected_status
    assert data["llm"]["inference"]["attempts"] > 0
    if expected_status == "completed":
        assert data["llm"]["inference"]["successes"] == data["llm"]["inference"]["attempts"]
        assert data["llm"]["configuration"]["resolved_model"] == "llama3.2:latest"
        assert data["llm"]["configuration"]["resolved_model_digest"] == TEST_MODEL_DIGEST
        assert data["llm"]["comparison"] is not None
    else:
        assert data["llm"]["inference"]["successes"] == 0
        assert data["llm"]["comparison"] is None
