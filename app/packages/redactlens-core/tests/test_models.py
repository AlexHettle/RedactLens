from redactlens_core.models import Finding, ScanOptions, SupportingDetection


def test_finding_round_trips_through_json():
    finding = Finding(
        id="abc123",
        file_path="example.txt",
        line=1,
        column=5,
        start_offset=4,
        end_offset=15,
        matched_text="123-45-6789",
        redacted_preview="123-**-6789",
        detector_id="us_ssn",
        category="personal_id",
        confidence=0.9,
        tier="A",
        explanation="Looks like a U.S. Social Security Number.",
        risk_lesson="An SSN can be used for identity theft.",
        suggested_action="anonymize",
        evidence={"booster": "ssn keyword nearby"},
        supporting_detections=[
            SupportingDetection(
                detector_id="high_entropy_secret",
                description="High-entropy token",
                confidence=0.8,
                relationship="suppressed",
            )
        ],
    )

    restored = Finding.model_validate_json(finding.model_dump_json())

    assert restored == finding


def test_scan_options_deduplicate_ignored_directories_case_insensitively():
    options = ScanOptions(ignored_directories=["Vendor", "vendor", "VENDOR"])

    assert options.ignored_directories == ["Vendor"]
