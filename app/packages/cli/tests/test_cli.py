import json

from redactlens_cli.main import app
from typer.testing import CliRunner

runner = CliRunner()


def parse_json_output(result):
    assert result.exit_code == 0
    return json.loads(result.stdout)


def test_scan_human_output_groups_by_tier(tmp_path):
    (tmp_path / "secrets.py").write_text('ssn = "123-45-6789"\n')

    result = runner.invoke(app, ["scan", str(tmp_path)])

    assert result.exit_code == 0
    assert "Tier A" in result.stdout
    assert "Tier B" in result.stdout
    assert "12*******89" in result.stdout  # redacted preview
    assert "123-45-6789" not in result.stdout  # raw secret never printed
    assert "skipped 0." in result.stdout  # "scan" itself must not be treated as a path


def test_scan_human_output_scrubs_matches_from_paths_and_skip_details(tmp_path):
    raw_secret = "123-45-6789"
    matched_path = tmp_path / f"{raw_secret}.py"
    matched_path.write_text(f'ssn = "{raw_secret}"\n')
    skipped_path = tmp_path / f"{raw_secret}.bin"
    skipped_path.write_bytes(b"not text")

    result = runner.invoke(
        app,
        ["scan", str(tmp_path), "--target", raw_secret, "--exclude-ext", ".bin"],
    )

    assert result.exit_code == 0
    assert raw_secret not in result.stdout
    assert "<redacted-value-1>" in result.stdout


def test_scan_human_output_shows_supporting_detector_without_duplicate_finding(tmp_path):
    (tmp_path / "config.py").write_text('AWS_ACCESS_KEY_ID = "AKIAV3XZJH2QK7RSTUV1"\n')

    result = runner.invoke(app, ["scan", str(tmp_path)])

    assert result.exit_code == 0
    assert "Tier A -- Confirmed sensitive (recommended: anonymize) (1)" in result.stdout
    assert "AWS access key ID" in result.stdout
    assert "Also detected by: high_entropy_secret" in result.stdout


def test_scan_json_output_is_allowlisted_and_excludes_raw_secret(tmp_path):
    raw_secret = "123-45-6789"
    secret_path = tmp_path / f"{raw_secret}.py"
    secret_path.write_text(f'ssn = "{raw_secret}"\n')

    result = runner.invoke(app, ["scan", str(tmp_path), "--json"])

    parsed = parse_json_output(result)
    finding = next(item for item in parsed["findings"] if item["detector_id"] == "us_ssn")
    assert finding["redacted_preview"] == "12*******89"
    assert {"matched_text", "start_offset", "end_offset", "evidence"}.isdisjoint(finding)
    assert raw_secret not in result.stdout


def test_scan_respects_categories_filter(tmp_path):
    (tmp_path / "secrets.py").write_text('ssn = "123-45-6789"\ncard = "4111111111111111"\n')

    result = runner.invoke(app, ["scan", str(tmp_path), "--categories", "financial", "--json"])

    parsed = parse_json_output(result)
    assert parsed["findings"]
    assert all(finding["category"] == "financial" for finding in parsed["findings"])


def test_personal_id_filter_does_not_surface_connection_credentials_as_email(tmp_path):
    connection = "postgres://admin:CorrectHorseBattery9@prod-db.internal:5432/appdb"
    contact = "jane.doe@redactlensteam.io"
    (tmp_path / "config.py").write_text(f'DATABASE_URL = "{connection}"\ncontact = "{contact}"\n')

    unfiltered_result = runner.invoke(app, ["scan", str(tmp_path), "--json"])
    filtered_result = runner.invoke(
        app,
        ["scan", str(tmp_path), "--categories", "personal_id", "--json"],
    )

    assert unfiltered_result.exit_code == filtered_result.exit_code == 0
    unfiltered = parse_json_output(unfiltered_result)
    filtered = parse_json_output(filtered_result)
    unfiltered_contact = next(
        finding for finding in unfiltered["findings"] if finding["detector_id"] == "email"
    )
    assert [finding["detector_id"] for finding in filtered["findings"]] == ["email"]
    assert filtered["findings"][0]["id"] == unfiltered_contact["id"]
    assert contact not in filtered_result.stdout
    assert filtered["summary"]["raw_detector_hits"] == 1
    assert filtered["summary"]["canonical_findings"] == 1
    assert filtered["summary"]["consolidated_hits"] == 0
    assert filtered["summary"]["suppressed_hits"] == 0
    assert filtered["summary"]["raw_detector_hits_by_detector"] == {"email": 1}


def test_scan_user_defined_target_lands_tier_a(tmp_path):
    (tmp_path / "notes.txt").write_text("account: ACME-1234-XYZ\n")

    result = runner.invoke(app, ["scan", str(tmp_path), "--target", "ACME-1234-XYZ", "--json"])

    parsed = parse_json_output(result)
    matches = [f for f in parsed["findings"] if f["detector_id"] == "user_target_0"]
    assert matches
    assert matches[0]["tier"] == "A"
    assert "ACME-1234-XYZ" not in result.stdout


def test_scan_threshold_is_configurable(tmp_path):
    (tmp_path / "secrets.py").write_text('ssn = "123-45-6789"\n')

    result = runner.invoke(app, ["scan", str(tmp_path), "--threshold", "0.99", "--json"])

    parsed = parse_json_output(result)
    ssn_finding = next(f for f in parsed["findings"] if f["detector_id"] == "us_ssn")
    assert ssn_finding["tier"] == "B"  # confidence 0.95 < threshold 0.99


def test_scan_without_use_llm_flag_never_engages_the_llm(tmp_path):
    (tmp_path / "secrets.py").write_text('ssn = "123-45-6789"\n')

    result = runner.invoke(app, ["scan", str(tmp_path), "--json"])

    parsed = parse_json_output(result)
    assert parsed["llm_used"] is False


def test_scan_use_llm_flag_degrades_gracefully_when_unavailable(tmp_path):
    """Doesn't assert llm_used is True -- whether a local Ollama with the
    right model is actually reachable varies by machine/CI. Just proves the
    flag is accepted and the scan still completes correctly either way."""
    (tmp_path / "secrets.py").write_text('ssn = "123-45-6789"\n')

    result = runner.invoke(app, ["scan", str(tmp_path), "--use-llm", "--json"])

    parsed = parse_json_output(result)
    assert any(finding["detector_id"] == "us_ssn" for finding in parsed["findings"])


def test_scan_resource_and_scope_options_are_exposed_by_the_cli(tmp_path):
    (tmp_path / "included.txt").write_text("123-45-6789\n")
    (tmp_path / "excluded.py").write_text("987-65-4321\n")

    result = runner.invoke(
        app,
        [
            "scan",
            str(tmp_path),
            "--include-ext",
            "txt",
            "--workers",
            "1",
            "--chunk-size-kb",
            "64",
            "--json",
        ],
    )

    parsed = parse_json_output(result)
    assert parsed["scanned_files"] == [str(tmp_path / "included.txt")]
    assert parsed["skipped_files"][0]["code"] == "extension_not_included"


def test_scan_can_clear_default_ignored_directories_and_keep_custom_ignores(tmp_path):
    default_ignored = tmp_path / "node_modules"
    default_ignored.mkdir()
    (default_ignored / "secret.txt").write_text("123-45-6789\n")
    custom_ignored = tmp_path / "vendor"
    custom_ignored.mkdir()
    (custom_ignored / "secret.txt").write_text("987-65-4321\n")

    result = runner.invoke(
        app,
        [
            "scan",
            str(tmp_path),
            "--no-default-ignore-dirs",
            "--ignore-dir",
            "vendor",
            "--json",
        ],
    )

    parsed = parse_json_output(result)
    assert parsed["scanned_files"] == [str(default_ignored / "secret.txt")]
    assert [(item["path"], item["code"]) for item in parsed["skipped_files"]] == [
        (str(custom_ignored), "ignored_directory")
    ]


def test_scan_structured_file_limit_is_exposed_by_the_cli(tmp_path):
    document = tmp_path / "oversized.pdf"
    document.write_bytes(b"%PDF" + (b"x" * 2_000))

    result = runner.invoke(
        app,
        [
            "scan",
            str(document),
            "--max-structured-file-size-mb",
            "0.001",
            "--json",
        ],
    )

    parsed = parse_json_output(result)
    assert parsed["scanned_files"] == []
    assert [item["code"] for item in parsed["skipped_files"]] == ["structured_file_too_large"]
