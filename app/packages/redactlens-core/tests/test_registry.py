import pytest
from redactlens_core.registry import (
    DEPLOYED_CONFIDENCE_WEIGHT_PROFILE,
    ConfidenceWeightProfile,
    DetectorDef,
    DetectorLoadError,
    DetectorRegistry,
    load_default_registry,
    load_default_registry_for_profile,
)

EXPECTED_BUILTIN_IDS = {
    "us_ssn",
    "credit_card",
    "email",
    "phone",
    "aws_access_key",
    "private_key_header",
    "password_assignment",
    "jwt",
    "connection_string",
    "high_entropy_secret",
}


def test_default_registry_loads_all_builtin_detectors():
    registry = load_default_registry()
    ids = {d.id for d in registry.get_all()}
    assert ids == EXPECTED_BUILTIN_IDS


def test_default_registry_applies_the_deployed_confidence_weight_profile():
    identity = load_default_registry_for_profile(ConfidenceWeightProfile("identity"))
    deployed = load_default_registry()

    identity_booster = identity.get("email").context.boosters[0].weight
    deployed_booster = deployed.get("email").context.boosters[0].weight

    assert DEPLOYED_CONFIDENCE_WEIGHT_PROFILE.context_scale == 1.25
    assert deployed.get("email").base_confidence == identity.get("email").base_confidence
    assert deployed_booster == pytest.approx(identity_booster * 1.25)


@pytest.mark.parametrize(
    "kwargs",
    [
        {"profile_id": ""},
        {"profile_id": "bad", "base_offset": 1.1},
        {"profile_id": "bad", "context_scale": -0.1},
    ],
)
def test_confidence_weight_profile_rejects_invalid_configuration(kwargs):
    with pytest.raises(ValueError, match="confidence-weight"):
        ConfidenceWeightProfile(**kwargs)


def test_get_by_categories_filters():
    registry = load_default_registry()
    credential_only = registry.get_by_categories(["credential"])
    assert credential_only
    assert all(d.category == "credential" for d in credential_only)


def test_get_by_categories_empty_returns_all():
    registry = load_default_registry()
    assert len(registry.get_by_categories([])) == len(registry.get_all())


def test_specific_detectors_outrank_and_suppress_generic_hits():
    registry = load_default_registry()
    entropy = registry.get("high_entropy_secret")
    aws = registry.get("aws_access_key")
    connection = registry.get("connection_string")

    assert aws.specificity > entropy.specificity
    assert "high_entropy_secret" in aws.suppresses
    assert "email" in connection.suppresses


def test_detector_cannot_suppress_itself():
    with pytest.raises(ValueError, match="cannot suppress itself"):
        DetectorDef(
            id="recursive",
            category="custom",
            description="d",
            risk_lesson="r",
            method="keyword",
            pattern="secret",
            base_confidence=0.5,
            suppresses=["recursive"],
        )


def test_freeze_rejects_unknown_suppression_target():
    registry = DetectorRegistry()
    registry.add(
        DetectorDef(
            id="specific",
            category="custom",
            description="d",
            risk_lesson="r",
            method="keyword",
            pattern="secret",
            base_confidence=0.5,
            specificity=100,
            suppresses=["missing"],
        )
    )

    with pytest.raises(DetectorLoadError, match="suppresses unknown detector 'missing'"):
        registry.freeze()

    assert registry.frozen is False


@pytest.mark.parametrize(("suppressor_specificity", "target_specificity"), [(50, 50), (49, 50)])
def test_freeze_requires_suppressor_to_have_greater_specificity(
    suppressor_specificity, target_specificity
):
    registry = DetectorRegistry()
    registry.add(
        DetectorDef(
            id="suppressor",
            category="custom",
            description="d",
            risk_lesson="r",
            method="keyword",
            pattern="secret",
            base_confidence=0.5,
            specificity=suppressor_specificity,
            suppresses=["target"],
        )
    )
    registry.add(
        DetectorDef(
            id="target",
            category="custom",
            description="d",
            risk_lesson="r",
            method="keyword",
            pattern="secret",
            base_confidence=0.5,
            specificity=target_specificity,
        )
    )

    with pytest.raises(DetectorLoadError, match="must have greater specificity"):
        registry.freeze()

    assert registry.frozen is False


def test_invalid_regex_raises_clear_error(tmp_path):
    (tmp_path / "bad.yaml").write_text(
        "id: bad\n"
        "category: custom\n"
        "description: d\n"
        "risk_lesson: r\n"
        "method: regex\n"
        "pattern: '[unclosed'\n"
        "base_confidence: 0.5\n"
    )
    registry = DetectorRegistry()
    with pytest.raises(DetectorLoadError, match="invalid regex"):
        registry.load_dir(tmp_path)


@pytest.mark.parametrize(
    "pattern", [r"value(?=suffix)", r"value(?!suffix)", r"(?<=prefix)value", r"(?<!prefix)value"]
)
def test_regex_lookaround_requires_declared_streaming_context(pattern):
    with pytest.raises(ValueError, match="positive max_lookaround_length"):
        DetectorDef(
            id="boundary_sensitive",
            category="custom",
            description="d",
            risk_lesson="r",
            method="regex",
            pattern=pattern,
            base_confidence=0.5,
            max_match_length=16,
        )


def test_literal_lookaround_text_does_not_require_streaming_context():
    detector = DetectorDef(
        id="literal_syntax",
        category="custom",
        description="d",
        risk_lesson="r",
        method="regex",
        pattern=r"\(\?=literal\)",
        base_confidence=0.5,
        max_match_length=11,
    )

    assert detector.max_lookaround_length == 0


def test_missing_pattern_for_regex_method_raises_clear_error(tmp_path):
    (tmp_path / "bad.yaml").write_text(
        "id: bad\n"
        "category: custom\n"
        "description: d\n"
        "risk_lesson: r\n"
        "method: regex\n"
        "base_confidence: 0.5\n"
    )
    registry = DetectorRegistry()
    with pytest.raises(DetectorLoadError, match="requires a non-empty 'pattern'"):
        registry.load_dir(tmp_path)


def test_duplicate_detector_id_raises_clear_error(tmp_path):
    content = (
        "id: dup\n"
        "category: custom\n"
        "description: d\n"
        "risk_lesson: r\n"
        "method: keyword\n"
        "pattern: foo\n"
        "base_confidence: 0.5\n"
    )
    (tmp_path / "a.yaml").write_text(content)
    (tmp_path / "b.yaml").write_text(content)
    registry = DetectorRegistry()
    with pytest.raises(DetectorLoadError, match="duplicate detector id"):
        registry.load_dir(tmp_path)


def test_malformed_yaml_raises_clear_error(tmp_path):
    (tmp_path / "bad.yaml").write_text("id: [this is not, valid: yaml")
    registry = DetectorRegistry()
    with pytest.raises(DetectorLoadError):
        registry.load_dir(tmp_path)
