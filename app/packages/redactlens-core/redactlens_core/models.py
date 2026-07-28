"""Core data model for RedactLens.

These types are the contract every consumer of redactlens-core (CLI, API, eval
harness) shares. Detection logic lives elsewhere; this module only defines
the shared request, finding, and result shapes.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator, model_validator
from pydantic.json_schema import SkipJsonSchema

DEFAULT_TIER_THRESHOLD = 0.85

Tier = Literal["A", "B"]
SuggestedAction = Literal["anonymize", "review"]
TargetKind = Literal["literal", "description"]
ConsolidationReason = Literal["same_span", "suppressed", "overlap_chain"]
SkipStage = Literal["discovery", "extraction", "detection", "ai_refinement"]


class SupportingDetection(BaseModel):
    """A non-primary detector that supports one canonical finding."""

    detector_id: str
    description: str
    confidence: float = Field(ge=0.0, le=1.0)
    relationship: ConsolidationReason


class Finding(BaseModel):
    id: str  # stable hash of the file, canonical span, and detector-group signature
    file_path: str
    line: int
    column: int
    start_offset: int
    end_offset: int
    # For findings inside extracted documents (docx/xlsx/pptx/pdf):
    # line/column/offsets address the *extracted* text, so `location` carries
    # the human-readable place ("Sheet1!B7", "page 3"). `can_anonymize` is
    # False only for formats RedactLens can't rewrite (pdf); docx/xlsx/pptx
    # write-back goes through document_anonymize.
    location: str | None = None
    can_anonymize: bool = True
    matched_text: str  # raw match; never log this directly, use redacted_preview
    redacted_preview: str
    detector_id: str
    category: str  # e.g. "credential", "financial", "personal_id", "health", "custom"
    confidence: float = Field(ge=0.0, le=1.0)  # continuous, kept internally
    tier: Tier  # derived from confidence via threshold
    explanation: str
    risk_lesson: str
    suggested_action: SuggestedAction
    evidence: dict[str, Any] = Field(default_factory=dict)
    supporting_detections: list[SupportingDetection] = Field(default_factory=list)


class UserTarget(BaseModel):
    kind: TargetKind
    value: str = Field(min_length=1, max_length=8_192)
    category: str = "custom"


class ScanOptions(BaseModel):
    """Resource and scope controls shared by the CLI, API, and core engine."""

    max_file_size: int = Field(default=100_000_000, ge=1, le=2_000_000_000)
    max_structured_file_size: int = Field(default=50_000_000, ge=1, le=250_000_000)
    ignored_directories: list[str] = Field(
        default_factory=lambda: [
            ".git",
            ".venv",
            "__pycache__",
            "build",
            "dist",
            "node_modules",
            "venv",
        ],
        max_length=256,
    )
    included_extensions: list[str] = Field(default_factory=list, max_length=256)
    excluded_extensions: list[str] = Field(default_factory=list, max_length=256)
    archive_depth: int = Field(default=2, ge=1, le=8)
    ai_timeout_seconds: float = Field(default=60.0, gt=0, le=600.0)
    max_workers: int = Field(default=4, ge=1, le=32)
    document_workers: int = Field(default=1, ge=1, le=4)
    chunk_size: int = Field(default=1_048_576, ge=65_536, le=8_388_608)
    use_redactlensignore: bool = True

    @field_validator("ignored_directories")
    @classmethod
    def _normalize_directories(cls, values: list[str]) -> list[str]:
        normalized: list[str] = []
        identities: set[str] = set()
        for value in values:
            name = value.strip().strip("/\\")
            if not name or "/" in name or "\\" in name or name in {".", ".."}:
                raise ValueError("ignored directory entries must be individual directory names")
            identity = name.casefold()
            if identity not in identities:
                normalized.append(name)
                identities.add(identity)
        return sorted(normalized, key=str.casefold)

    @field_validator("included_extensions", "excluded_extensions")
    @classmethod
    def _normalize_extensions(cls, values: list[str]) -> list[str]:
        normalized: list[str] = []
        for value in values:
            extension = value.strip().lower()
            if extension and not extension.startswith("."):
                extension = f".{extension}"
            if not extension or extension in {".", ".."} or "/" in extension or "\\" in extension:
                raise ValueError("extensions must be values such as '.py' or 'txt'")
            if extension not in normalized:
                normalized.append(extension)
        return sorted(normalized)

    @model_validator(mode="after")
    def _validate_worker_limits(self) -> ScanOptions:
        if self.document_workers > self.max_workers:
            raise ValueError("document_workers cannot exceed max_workers")
        overlap = set(self.included_extensions) & set(self.excluded_extensions)
        if overlap:
            names = ", ".join(sorted(overlap))
            raise ValueError(f"extensions cannot be both included and excluded: {names}")
        return self


class ScanRequest(BaseModel):
    paths: list[str]
    categories: list[str] = Field(default_factory=list)
    user_targets: list[UserTarget] = Field(default_factory=list)
    use_llm: bool = False
    ollama_model: str | None = None
    tier_threshold: float = Field(default=DEFAULT_TIER_THRESHOLD, ge=0.0, le=1.0)
    options: ScanOptions = Field(default_factory=ScanOptions)


class SkippedFile(BaseModel):
    path: str
    reason: str
    code: str = "unspecified"
    stage: SkipStage = "extraction"
    rule: str | None = None


class RawDetectorOpinion(BaseModel):
    """Privacy-internal geometry for one pre-consolidation detector opinion.

    The matched value and detector evidence are deliberately omitted. Evaluation
    can score the detector's own span and category without retaining another copy
    of sensitive source text.
    """

    file_path: str
    start_offset: int = Field(ge=0)
    end_offset: int = Field(gt=0)
    detector_id: str
    category: str
    confidence: float = Field(ge=0.0, le=1.0)
    tier: Tier

    @model_validator(mode="after")
    def _validate_span(self) -> RawDetectorOpinion:
        if self.end_offset <= self.start_offset:
            raise ValueError("detector opinion end_offset must be greater than start_offset")
        return self


class ScanResult(BaseModel):
    findings: list[Finding] = Field(default_factory=list)
    summary: dict[str, Any] = Field(default_factory=dict)
    scanned_files: list[str] = Field(default_factory=list)
    skipped_files: list[SkippedFile] = Field(default_factory=list)
    llm_used: bool = False
    # Evaluation opts into this geometry at the scanner boundary. It is never
    # serialized into CLI JSON or browser-facing API state.
    raw_detector_opinions: SkipJsonSchema[list[RawDetectorOpinion] | None] = Field(
        default=None,
        exclude=True,
        repr=False,
    )
