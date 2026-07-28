"""Run the documented CLI demo and enforce its stable public result contract."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

EXPECTED_SCANNED_FILES = (
    "examples/demo/config.py",
    "examples/demo/id_rsa",
    "examples/demo/notes.txt",
    "examples/demo/test/decoy_notes.py",
)
EXPECTED_FINDING_SIGNATURE = (
    (
        "examples/demo/config.py",
        1,
        17,
        "connection_string",
        "credential",
        "A",
        0.9125,
        "anonymize",
        True,
        "po****************************db",
        (("email", "suppressed"),),
    ),
    (
        "examples/demo/config.py",
        2,
        22,
        "aws_access_key",
        "credential",
        "A",
        0.9625,
        "anonymize",
        True,
        "AK****************V1",
        (("high_entropy_secret", "suppressed"),),
    ),
    (
        "examples/demo/config.py",
        3,
        15,
        "password_assignment",
        "credential",
        "A",
        0.9875,
        "anonymize",
        True,
        "n4********************Ef",
        (("high_entropy_secret", "suppressed"),),
    ),
    (
        "examples/demo/id_rsa",
        1,
        1,
        "private_key_header",
        "credential",
        "A",
        0.97,
        "anonymize",
        True,
        "--****************************--",
        (("high_entropy_secret", "suppressed"),),
    ),
    (
        "examples/demo/notes.txt",
        3,
        14,
        "us_ssn",
        "personal_id",
        "A",
        0.975,
        "anonymize",
        True,
        "51*******49",
        (),
    ),
    (
        "examples/demo/notes.txt",
        4,
        21,
        "email",
        "personal_id",
        "B",
        0.675,
        "review",
        True,
        "mo***********************om",
        (),
    ),
    (
        "examples/demo/notes.txt",
        5,
        18,
        "phone",
        "personal_id",
        "B",
        0.6875,
        "review",
        True,
        "41********71",
        (),
    ),
    (
        "examples/demo/test/decoy_notes.py",
        2,
        15,
        "us_ssn",
        "personal_id",
        "B",
        0.1,
        "review",
        True,
        "00*******00",
        (),
    ),
    (
        "examples/demo/test/decoy_notes.py",
        5,
        13,
        "password_assignment",
        "credential",
        "B",
        0.0,
        "review",
        True,
        "hu***r2",
        (),
    ),
)
EXPECTED_SUMMARY = {
    "total_findings": 9,
    "canonical_findings": 9,
    "raw_detector_hits": 14,
    "consolidated_hits": 5,
    "suppressed_hits": 5,
    "raw_detector_hits_by_detector": {
        "aws_access_key": 1,
        "connection_string": 1,
        "email": 2,
        "high_entropy_secret": 4,
        "password_assignment": 2,
        "phone": 1,
        "private_key_header": 1,
        "us_ssn": 2,
    },
    "tier_counts": {"A": 5, "B": 4},
    "category_counts": {"credential": 5, "personal_id": 4},
    "files_scanned": 4,
    "files_skipped": 0,
    "completed_files": 4,
    "total_files": 4,
    "status": "complete",
    "incomplete": False,
}


def _portable_path(value: object) -> str:
    return str(value).replace("\\", "/").removeprefix("./")


def _finding_signature(item: dict[str, object]) -> tuple[object, ...]:
    supporting = item.get("supporting_detections")
    if not isinstance(supporting, list):
        supporting = []
    return (
        _portable_path(item.get("file_path")),
        item.get("line"),
        item.get("column"),
        item.get("detector_id"),
        item.get("category"),
        item.get("tier"),
        round(float(item.get("confidence", -1)), 4),
        item.get("suggested_action"),
        item.get("can_anonymize"),
        item.get("redacted_preview"),
        tuple(
            (support.get("detector_id"), support.get("relationship"))
            for support in supporting
            if isinstance(support, dict)
        ),
    )


def _contract_mismatch(label: str, expected: object, received: object) -> int:
    print(
        f"CLI demo {label} changed:\n  expected: {expected!r}\n  received: {received!r}",
        file=sys.stderr,
    )
    return 1


def main() -> int:
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "redactlens_cli.main",
            "scan",
            "examples/demo",
            "--json",
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        print(completed.stdout)
        print(completed.stderr, file=sys.stderr)
        return completed.returncode

    try:
        result = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        print(f"CLI demo did not return valid JSON: {error}", file=sys.stderr)
        return 1

    if not isinstance(result, dict):
        return _contract_mismatch("top-level shape", "a JSON object", type(result).__name__)

    scanned_files = result.get("scanned_files")
    if not isinstance(scanned_files, list):
        return _contract_mismatch("scanned-files shape", "a list", type(scanned_files).__name__)
    portable_files = tuple(_portable_path(item) for item in scanned_files)
    if portable_files != EXPECTED_SCANNED_FILES:
        return _contract_mismatch("scanned-file order", EXPECTED_SCANNED_FILES, portable_files)

    findings = result.get("findings")
    if not isinstance(findings, list) or not all(isinstance(item, dict) for item in findings):
        return _contract_mismatch("findings shape", "a list of objects", findings)
    signature = tuple(_finding_signature(item) for item in findings)
    if signature != EXPECTED_FINDING_SIGNATURE:
        return _contract_mismatch(
            "ordered finding signature", EXPECTED_FINDING_SIGNATURE, signature
        )

    summary = result.get("summary")
    if not isinstance(summary, dict):
        return _contract_mismatch("summary shape", "an object", type(summary).__name__)
    stable_summary = {key: summary.get(key) for key in EXPECTED_SUMMARY}
    if stable_summary != EXPECTED_SUMMARY:
        return _contract_mismatch("stable summary", EXPECTED_SUMMARY, stable_summary)

    if result.get("skipped_files") != []:
        return _contract_mismatch("skipped files", [], result.get("skipped_files"))
    if result.get("llm_used") is not False:
        print("The default CLI demo unexpectedly used an AI model.", file=sys.stderr)
        return 1

    print(
        "CLI demo: exact 4-file/9-finding ordered signature and stable summary passed "
        "(5 Tier A, 4 Tier B), heuristics-only."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
