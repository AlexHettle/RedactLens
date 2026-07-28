"""Detector registry: loads declarative YAML detector definitions.

Detectors are data, not code. Adding a built-in detector means dropping a
YAML file in redactlens_core/detectors/ — never adding a branch here. A
user-defined target (Phase 2) is just a DetectorDef constructed at runtime
and added to the registry the same way.
"""

from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Literal

import regex as regex_engine
import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator

from redactlens_core.validators import VALIDATORS


@dataclass(frozen=True)
class ConfidenceWeightProfile:
    """Global calibration applied to built-in declarative detector weights.

    Detector YAML remains the human-readable source of the individual base
    and context weights.  A small, versioned global profile lets the
    evaluation harness calibrate those weights reproducibly without changing
    custom/user detectors or introducing request-specific scoring behavior.
    """

    profile_id: str
    base_offset: float = 0.0
    context_scale: float = 1.0

    def __post_init__(self) -> None:
        if not self.profile_id.strip():
            raise ValueError("confidence-weight profile_id must be nonempty")
        if not -1.0 <= self.base_offset <= 1.0:
            raise ValueError("confidence-weight base_offset must be between -1 and 1")
        if not 0.0 <= self.context_scale <= 4.0:
            raise ValueError("confidence-weight context_scale must be between 0 and 4")


# Selected exclusively from the Phase 4 calibration corpus.  The evaluation
# harness contains the candidate set, objective, evidence, and a deployment
# consistency gate.  Product scans consume this same profile through the
# default registry; custom registries are intentionally left unchanged.
DEPLOYED_CONFIDENCE_WEIGHT_PROFILE = ConfidenceWeightProfile(
    profile_id="base+0.00-contextx1.25-v1",
    base_offset=0.0,
    context_scale=1.25,
)


class DetectorLoadError(Exception):
    """Raised when a detector file is malformed. Never failed silently."""


class ContextAdjustment(BaseModel):
    model_config = ConfigDict(frozen=True)

    pattern: str | None = None
    in_path: str | None = None
    validator: str | None = None
    weight: float
    invert: bool = False

    @model_validator(mode="after")
    def _exactly_one_condition(self) -> "ContextAdjustment":
        set_fields = [f for f in (self.pattern, self.in_path, self.validator) if f is not None]
        if len(set_fields) != 1:
            raise ValueError(
                "a context adjustment must set exactly one of: pattern, in_path, validator"
            )
        if self.validator is not None and self.validator not in VALIDATORS:
            available = ", ".join(sorted(VALIDATORS))
            raise ValueError(f"unknown validator '{self.validator}' (available: {available})")
        if self.pattern is not None:
            _compile_or_raise(self.pattern)
        if self.in_path is not None:
            _compile_or_raise(self.in_path)
        return self


class DetectorContext(BaseModel):
    model_config = ConfigDict(frozen=True)

    boosters: tuple[ContextAdjustment, ...] = ()
    suppressors: tuple[ContextAdjustment, ...] = ()


class DetectorDef(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: str
    category: str
    description: str
    risk_lesson: str
    method: Literal["regex", "entropy", "keyword"]
    pattern: str | None = None
    base_confidence: float = Field(ge=0.0, le=1.0)
    context: DetectorContext = Field(default_factory=DetectorContext)
    entropy_threshold: float = 4.0  # only used when method == "entropy"
    # Higher values win when overlapping detections are consolidated into
    # one canonical finding. Known formats outrank contextual detectors,
    # which outrank generic entropy analysis.
    specificity: int = Field(default=50, ge=0, le=1000)
    # Detector ids whose contained matches are supporting evidence rather
    # than separate user-visible findings.
    suppresses: tuple[str, ...] = ()
    # Streaming scans promise to retain this many characters to the right of
    # every chunk boundary. Configurable detectors must therefore declare a
    # finite match bound even when their regex contains open-ended quantifiers.
    max_match_length: int = Field(default=8_192, ge=1, le=1_048_576)
    # Lookaround can inspect characters that are not part of the returned
    # match span. Boundary-sensitive patterns must declare that external
    # dependency so streaming can retain enough context on both sides.
    max_lookaround_length: int = Field(default=0, ge=0, le=1_048_576)

    @model_validator(mode="after")
    def _pattern_required_for_method(self) -> "DetectorDef":
        if self.method in ("regex", "keyword", "entropy") and not self.pattern:
            raise ValueError(f"method '{self.method}' requires a non-empty 'pattern'")
        if self.method in ("regex", "entropy"):
            _compile_or_raise(self.pattern)
            if _contains_lookaround(self.pattern) and self.max_lookaround_length == 0:
                raise ValueError(
                    "regex lookaround requires a positive max_lookaround_length for streaming scans"
                )
        if self.id in self.suppresses:
            raise ValueError("a detector cannot suppress itself")
        return self


def _compile_or_raise(pattern: str) -> None:
    try:
        regex_engine.compile(pattern, regex_engine.VERSION0)
    except regex_engine.error as e:
        raise ValueError(f"invalid regex {pattern!r}: {e}") from e


def _contains_lookaround(pattern: str) -> bool:
    """Detect active lookaround operators without mistaking literals for syntax."""

    escaped = False
    in_character_class = False
    for index, character in enumerate(pattern):
        if escaped:
            escaped = False
            continue
        if character == "\\":
            escaped = True
            continue
        if character == "[" and not in_character_class:
            in_character_class = True
            continue
        if character == "]" and in_character_class:
            in_character_class = False
            continue
        if in_character_class or character != "(":
            continue
        if pattern.startswith(("(?=", "(?!", "(?<=", "(?<!"), index):
            return True
    return False


class DetectorRegistry:
    def __init__(self) -> None:
        self._detectors: dict[str, DetectorDef] = {}
        self._frozen = False

    def add(self, detector: DetectorDef) -> None:
        if self._frozen:
            raise DetectorLoadError("detector registry is immutable after validation")
        if detector.id in self._detectors:
            raise DetectorLoadError(f"duplicate detector id '{detector.id}'")
        self._detectors[detector.id] = detector

    def load_dir(self, directory: Path) -> None:
        paths = sorted(directory.glob("*.yaml")) + sorted(directory.glob("*.yml"))
        for path in paths:
            self._load_file(path)

    def _load_file(self, path: Path) -> None:
        try:
            raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        except yaml.YAMLError as e:
            raise DetectorLoadError(f"could not parse {path}: {e}") from e
        if not isinstance(raw, dict):
            raise DetectorLoadError(f"{path}: detector file must contain a YAML mapping")
        try:
            detector = DetectorDef.model_validate(raw)
        except ValueError as e:
            raise DetectorLoadError(f"{path}: {e}") from e
        try:
            self.add(detector)
        except DetectorLoadError as e:
            raise DetectorLoadError(f"{path}: {e}") from e

    def get_all(self) -> list[DetectorDef]:
        return list(self._detectors.values())

    def get(self, detector_id: str) -> DetectorDef:
        return self._detectors[detector_id]

    def get_by_categories(self, categories: list[str]) -> list[DetectorDef]:
        if not categories:
            return self.get_all()
        wanted = set(categories)
        return [d for d in self._detectors.values() if d.category in wanted]

    def freeze(self) -> "DetectorRegistry":
        """Prevent mutation so one validated registry can be shared safely."""
        self._validate_suppression_metadata()
        self._frozen = True
        return self

    def _validate_suppression_metadata(self) -> None:
        for detector in self._detectors.values():
            for suppressed_id in detector.suppresses:
                suppressed = self._detectors.get(suppressed_id)
                if suppressed is None:
                    raise DetectorLoadError(
                        f"detector '{detector.id}' suppresses unknown detector '{suppressed_id}'"
                    )
                if detector.specificity <= suppressed.specificity:
                    raise DetectorLoadError(
                        f"detector '{detector.id}' must have greater specificity than "
                        f"suppressed detector '{suppressed_id}' "
                        f"({detector.specificity} <= {suppressed.specificity})"
                    )

    @property
    def frozen(self) -> bool:
        return self._frozen


def default_detectors_dir() -> Path:
    return Path(__file__).parent / "detectors"


def _apply_confidence_weight_profile(
    detector: DetectorDef,
    profile: ConfidenceWeightProfile,
) -> DetectorDef:
    def adjusted(items: tuple[ContextAdjustment, ...]) -> tuple[ContextAdjustment, ...]:
        return tuple(
            item.model_copy(update={"weight": round(item.weight * profile.context_scale, 12)})
            for item in items
        )

    context = detector.context.model_copy(
        update={
            "boosters": adjusted(detector.context.boosters),
            "suppressors": adjusted(detector.context.suppressors),
        }
    )
    base_confidence = round(
        max(0.0, min(1.0, detector.base_confidence + profile.base_offset)),
        12,
    )
    return detector.model_copy(
        update={
            "base_confidence": base_confidence,
            "context": context,
        }
    )


@lru_cache(maxsize=16)
def load_default_registry_for_profile(
    profile: ConfidenceWeightProfile,
) -> DetectorRegistry:
    registry = DetectorRegistry()
    registry.load_dir(default_detectors_dir())
    calibrated = DetectorRegistry()
    for detector in registry.get_all():
        calibrated.add(_apply_confidence_weight_profile(detector, profile))
    return calibrated.freeze()


@lru_cache(maxsize=1)
def load_default_registry() -> DetectorRegistry:
    return load_default_registry_for_profile(DEPLOYED_CONFIDENCE_WEIGHT_PROFILE)
