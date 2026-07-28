from redactlens_core.models import ScanRequest, UserTarget
from redactlens_core.registry import DetectorRegistry
from redactlens_core.scanner import scan
from redactlens_core.user_targets import USER_TARGET_BASE_CONFIDENCE, user_target_detectors


def test_literal_target_becomes_high_confidence_keyword_detector():
    detectors = user_target_detectors([UserTarget(kind="literal", value="ACME-1234-XYZ")])
    assert len(detectors) == 1
    detector = detectors[0]
    assert detector.method == "keyword"
    assert detector.pattern == "ACME-1234-XYZ"
    assert detector.base_confidence == USER_TARGET_BASE_CONFIDENCE


def test_description_target_produces_no_detector_yet():
    detectors = user_target_detectors([UserTarget(kind="description", value="employee IDs")])
    assert detectors == []


def test_literal_target_is_found_and_lands_tier_a_even_in_example_context(tmp_path):
    test_dir = tmp_path / "test"
    test_dir.mkdir()
    (test_dir / "example.txt").write_text(
        "This is just an example file. My account number is ACME-1234-XYZ, ok?"
    )

    request = ScanRequest(
        paths=[str(tmp_path)],
        user_targets=[UserTarget(kind="literal", value="ACME-1234-XYZ", category="custom")],
    )
    result = scan(request, DetectorRegistry())  # empty registry: only the user target applies

    matches = [f for f in result.findings if f.detector_id == "user_target_0"]
    assert len(matches) == 1
    assert matches[0].tier == "A"
    assert matches[0].category == "custom"
    assert matches[0].matched_text == "ACME-1234-XYZ"


def test_user_targets_are_not_filtered_out_by_categories():
    registry = DetectorRegistry()
    request = ScanRequest(
        paths=[],
        categories=["financial"],
        user_targets=[UserTarget(kind="literal", value="whatever", category="custom")],
    )
    detectors = registry.get_by_categories(request.categories) + user_target_detectors(
        request.user_targets
    )
    assert any(d.id == "user_target_0" for d in detectors)
