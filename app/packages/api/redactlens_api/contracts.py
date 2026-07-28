"""Privacy-safe HTTP contracts for RedactLens's browser-facing API.

The core ``Finding`` intentionally contains raw matched text and trusted
rewrite offsets because the CLI and remediation engine need them. Normal
scan state never exposes those fields. An explicit, authenticated reveal
request can return only the raw values for server-owned finding IDs; trusted
offsets and source context always remain behind the browser boundary.
"""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator
from redactlens_core.models import (
    DEFAULT_TIER_THRESHOLD,
    ConsolidationReason,
    Finding,
    ScanOptions,
    ScanRequest,
    ScanResult,
    SkippedFile,
    SuggestedAction,
    Tier,
)
from redactlens_core.progress import ScanEventType, ScanStage


class StrictRequest(BaseModel):
    """Reject undeclared client fields instead of silently ignoring them."""

    model_config = ConfigDict(extra="forbid")


MAX_SCAN_PATHS = 64
MAX_SCAN_CATEGORIES = 32
MAX_USER_TARGETS = 100
MAX_REMEDIATION_FINDINGS = 5_000
MAX_REVEAL_FINDINGS = 250
MAX_PUBLIC_LOCATION_LENGTH = 512

PathValue = Annotated[str, Field(min_length=1, max_length=4_096)]
CategoryValue = Annotated[str, Field(min_length=1, max_length=64)]
FindingId = Annotated[str, Field(min_length=1, max_length=128)]
OllamaModelValue = Annotated[
    str,
    Field(
        min_length=1,
        max_length=256,
        pattern=r"^[^\s\x00-\x1f\x7f]+$",
    ),
]


def _plain_public_label(value: str) -> str:
    """Normalize untrusted document labels into one control-free line."""

    normalized = unicodedata.normalize("NFC", value)
    without_controls = "".join(
        " " if unicodedata.category(character).startswith("C") else character
        for character in normalized
    )
    return " ".join(without_controls.split())


def _plain_public_path(value: str) -> str:
    """Keep path separators and spacing while removing browser-hostile controls."""

    normalized = unicodedata.normalize("NFC", value)
    return "".join(
        " " if unicodedata.category(character).startswith("C") else character
        for character in normalized
    )


def _safe_public_marker(
    raw_identities: tuple[str, ...],
    *,
    path_ordinal: int | None = None,
    reserved_identities: tuple[str, ...] = (),
) -> str:
    """Build a deterministic marker that cannot itself contain a scan match."""

    candidates = (
        (f"<sensitive-path-{path_ordinal}>", f"⟦file-value-{path_ordinal}⟧")
        if path_ordinal is not None
        else ("<redacted>", "⟦sensitive value⟧")
    )
    for candidate in candidates:
        candidate_identity = candidate.casefold()
        if not any(
            raw_identity in candidate_identity for raw_identity in raw_identities
        ) and not any(candidate_identity in reserved for reserved in reserved_identities):
            return candidate

    # Very short user targets can overlap every readable marker (for example,
    # a literal target of "e").  Encode the ordinal with private-use code
    # points in that exceptional case, trying deterministic blocks until the
    # marker is disjoint from every raw value.
    number = path_ordinal or 0
    for block in range(0xE000, 0xF800, 32):
        encoded: list[str] = []
        remainder = number
        while True:
            encoded.append(chr(block + remainder % 16))
            remainder //= 16
            if remainder == 0:
                break
        candidate = chr(block + 16) + "".join(reversed(encoded)) + chr(block + 17)
        candidate_identity = candidate.casefold()
        if not any(
            raw_identity in candidate_identity for raw_identity in raw_identities
        ) and not any(candidate_identity in reserved for reserved in reserved_identities):
            return candidate

    # A match containing the entire Unicode private-use range would already
    # exceed normal detector and request bounds.  Refuse to create a marker
    # that would make the privacy guarantee ambiguous if one is ever supplied.
    raise ValueError("could not construct a privacy-safe public redaction marker")


@dataclass(frozen=True)
class PublicRedactor:
    """Scan-wide raw-value redaction for every browser-facing string.

    A finding can safely redact its own explanatory fields, but paths and
    structured-document labels can repeat a *different* finding's match.  The
    browser boundary therefore projects complete scans with one redactor built
    from every internal finding.  Internal paths and matches remain unchanged
    for remediation and native file actions.
    """

    replacements: tuple[tuple[str, str], ...] = ()
    path_replacements: tuple[tuple[str, str], ...] = ()
    public_paths: tuple[tuple[str, str], ...] = ()
    live_paths: tuple[tuple[str, str], ...] = ()

    @classmethod
    def from_findings(
        cls,
        findings: Iterable[Finding],
        *,
        reserved_paths: Iterable[str] = (),
    ) -> PublicRedactor:
        reserved_path_values = tuple(dict.fromkeys(reserved_paths))
        candidates: dict[str, tuple[str, str]] = {}
        path_candidates: dict[str, str] = {}
        conflicting: set[str] = set()
        for finding in findings:
            raw_value = _plain_public_label(finding.matched_text)
            if raw_value:
                preview = _plain_public_label(finding.redacted_preview) or "<redacted>"
                identity = raw_value.casefold()
                existing = candidates.get(identity)
                if existing is not None and existing[1] != preview:
                    conflicting.add(identity)
                else:
                    candidates.setdefault(identity, (raw_value, preview))

            # Path normalization intentionally differs from explanatory text:
            # preserve repeated spacing so the exact filename occurrence is
            # still recognized after controls such as tabs become spaces.
            path_raw_value = _plain_public_path(finding.matched_text)
            if path_raw_value:
                path_candidates.setdefault(path_raw_value, path_raw_value)

        raw_identities = tuple(
            dict.fromkeys([*candidates, *(identity.casefold() for identity in path_candidates)])
        )
        reserved_identities = tuple(
            _plain_public_path(path).casefold() for path in reserved_path_values
        )
        replacements: list[tuple[str, str]] = []
        path_replacements: list[tuple[str, str]] = []
        ordered_candidates = sorted(
            candidates.items(),
            key=lambda item: item[0],
        )
        for identity, (raw_value, preview) in ordered_candidates:
            # A preview must not introduce this or another scan match after the
            # replacement pass.  Fall back to an unambiguous constant if it
            # does, or if duplicate findings supplied inconsistent previews.
            safe_preview = preview
            preview_identity = preview.casefold()
            if identity in conflicting or any(
                raw_identity in preview_identity for raw_identity in raw_identities
            ):
                safe_preview = _safe_public_marker(raw_identities)
            replacements.append((raw_value, safe_preview))

        for ordinal, (_identity, raw_value) in enumerate(
            sorted(path_candidates.items(), key=lambda item: (item[0].casefold(), item[0])),
            start=1,
        ):
            path_replacements.append(
                (
                    raw_value,
                    _safe_public_marker(
                        raw_identities,
                        path_ordinal=ordinal,
                        reserved_identities=reserved_identities,
                    ),
                )
            )

        # Longer values first avoids a shorter overlapping match partially
        # rewriting a longer one before it can be recognized.
        replacements.sort(key=lambda item: (-len(item[0]), item[0].casefold()))
        path_replacements.sort(key=lambda item: (-len(item[0]), item[0].casefold()))
        return cls(
            replacements=tuple(replacements),
            path_replacements=tuple(path_replacements),
        ).with_reserved_paths(reserved_path_values)

    def with_reserved_paths(self, paths: Iterable[str]) -> PublicRedactor:
        """Allocate stable unique labels for newly public path identities."""

        existing_internal = {path for path, _label in self.public_paths}
        additions = sorted(
            (path for path in dict.fromkeys(paths) if path not in existing_internal),
            key=lambda path: (path.casefold(), path),
        )
        if not additions:
            return self

        raw_identities = tuple(
            dict.fromkeys(
                raw.casefold()
                for mapping in (self.replacements, self.path_replacements)
                for raw, _replacement in mapping
            )
        )
        reserved_identities = tuple(
            _plain_public_path(path).casefold()
            for path in [*(path for path, _label in self.public_paths), *additions]
        )
        public_paths = list(self.public_paths)
        used_public_paths = {label for _path, label in public_paths}
        reserved_internal_paths = {path for path, _label in self.public_paths} | set(additions)
        collision_ordinal = len(self.path_replacements) + len(public_paths) + 1

        for internal_path in additions:
            base_path = self._redact(
                _plain_public_path(internal_path),
                self.path_replacements,
                ignore_case=False,
            )
            public_path = base_path
            while public_path in used_public_paths or (
                public_path in reserved_internal_paths and public_path != internal_path
            ):
                marker = _safe_public_marker(
                    raw_identities,
                    path_ordinal=collision_ordinal,
                    reserved_identities=reserved_identities,
                )
                collision_ordinal += 1
                public_path = f"{base_path} {marker}"
            public_paths.append((internal_path, public_path))
            used_public_paths.add(public_path)

        return PublicRedactor(
            replacements=self.replacements,
            path_replacements=self.path_replacements,
            public_paths=tuple(public_paths),
            live_paths=self.live_paths,
        )

    def with_live_paths(self, paths: Mapping[str, str]) -> PublicRedactor:
        return PublicRedactor(
            replacements=self.replacements,
            path_replacements=self.path_replacements,
            public_paths=self.public_paths,
            live_paths=tuple(paths.items()),
        )

    def text(self, value: str) -> str:
        return self._redact(
            _plain_public_label(value),
            self.replacements,
            ignore_case=True,
        )

    def path(self, value: str) -> str:
        for internal_path, public_path in self.public_paths:
            if internal_path == value:
                return public_path
        return self._redact(
            _plain_public_path(value),
            self.path_replacements,
            ignore_case=False,
        )

    def identifier(self, value: str) -> str:
        """Redact user-controlled labels while retaining distinct identities."""

        return self._redact(
            _plain_public_path(value),
            self.path_replacements,
            ignore_case=False,
        )

    def live_path(self, value: str) -> str:
        """Return a stable opaque label before every scan match is known.

        A progress event can precede a later finding whose raw value appears
        in this path.  Session-local ordinal labels keep those early events
        useful for file identity without publishing source metadata that
        cannot yet be redacted scan-wide.
        """

        for internal_path, public_label in self.live_paths:
            if internal_path == value:
                return public_label
        return "Scan file"

    def _redact(
        self,
        value: str,
        replacements: tuple[tuple[str, str], ...],
        *,
        ignore_case: bool,
    ) -> str:
        redacted = value
        for raw_value, preview in replacements:
            if (
                raw_value.casefold() not in redacted.casefold()
                if ignore_case
                else raw_value not in redacted
            ):
                continue
            redacted = re.sub(
                re.escape(raw_value),
                lambda _match, replacement=preview: replacement,
                redacted,
                flags=re.I if ignore_case else 0,
            )

        # Defensive second pass: a future preview format must not be able to
        # reintroduce any sensitive value that was processed earlier.
        raw_identities = tuple(raw.casefold() for raw, _replacement in replacements)
        safe_fallback = _safe_public_marker(raw_identities)
        for raw_value, _preview in replacements:
            if (
                raw_value.casefold() not in redacted.casefold()
                if ignore_case
                else raw_value not in redacted
            ):
                continue
            redacted = re.sub(
                re.escape(raw_value),
                safe_fallback,
                redacted,
                flags=re.I if ignore_case else 0,
            )
        return redacted


def _public_location(finding: Finding, redactor: PublicRedactor) -> str | None:
    """Keep useful document coordinates without re-exposing matched text.

    Structured formats derive locations from untrusted metadata such as a
    workbook sheet name, archive member name, or email attachment filename.
    That metadata can repeat the value found in the document, so it must be
    projected through the same privacy boundary as the match itself.
    """

    if finding.location is None:
        return None
    location = redactor.text(finding.location)
    if not location:
        return None
    if len(location) <= MAX_PUBLIC_LOCATION_LENGTH:
        return location

    # Location coordinates are conventionally at the end (for example
    # ``Sheet!B7`` or ``member.zip · page 3``), so preserve both ends.
    tail_length = MAX_PUBLIC_LOCATION_LENGTH // 3
    head_length = MAX_PUBLIC_LOCATION_LENGTH - tail_length - 1
    return f"{location[:head_length]}…{location[-tail_length:]}"


def _public_explanatory_text(
    value: str,
    finding: Finding,
    redactor: PublicRedactor | None = None,
) -> str:
    """Normalize public copy and mask any complete occurrence of the raw match."""

    active_redactor = redactor or PublicRedactor.from_findings([finding])
    return active_redactor.text(value)


def _redact_public_value(value: Any, redactor: PublicRedactor) -> Any:
    """Recursively redact strings retained in loosely typed public summaries."""

    if isinstance(value, str):
        return redactor.text(value)
    if isinstance(value, Mapping):
        redacted_mapping: dict[Any, Any] = {}
        for key, item in value.items():
            public_key = redactor.identifier(key) if isinstance(key, str) else key
            public_item = _redact_public_value(item, redactor)
            if (
                public_key in redacted_mapping
                and isinstance(redacted_mapping[public_key], (int, float))
                and not isinstance(redacted_mapping[public_key], bool)
                and isinstance(public_item, (int, float))
                and not isinstance(public_item, bool)
            ):
                # Category-count keys differing only in case can normalize to
                # the same public identity.  Preserve the total rather than
                # silently dropping one count.
                redacted_mapping[public_key] += public_item
            else:
                redacted_mapping[public_key] = public_item
        return redacted_mapping
    if isinstance(value, list):
        return [_redact_public_value(item, redactor) for item in value]
    if isinstance(value, tuple):
        return tuple(_redact_public_value(item, redactor) for item in value)
    return value


def _public_skipped_file(
    skipped: SkippedFile,
    redactor: PublicRedactor,
    *,
    live: bool = False,
) -> SkippedFile:
    return skipped.model_copy(
        update={
            "path": redactor.live_path(skipped.path) if live else redactor.path(skipped.path),
            "reason": redactor.text(skipped.reason),
            "rule": redactor.text(skipped.rule) if skipped.rule is not None else None,
        },
        deep=True,
    )


class BrowserUserTarget(StrictRequest):
    kind: Literal["literal", "description"]
    value: str = Field(min_length=1, max_length=8_192)
    category: CategoryValue = "custom"


class BrowserScanOptions(StrictRequest):
    max_file_size: int = Field(default=100_000_000, ge=1, le=1_000_000_000)
    max_structured_file_size: int = Field(default=50_000_000, ge=1, le=250_000_000)
    ignored_directories: list[Annotated[str, Field(min_length=1, max_length=255)]] = Field(
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
    included_extensions: list[Annotated[str, Field(min_length=1, max_length=32)]] = Field(
        default_factory=list,
        max_length=256,
    )
    excluded_extensions: list[Annotated[str, Field(min_length=1, max_length=32)]] = Field(
        default_factory=list,
        max_length=256,
    )
    archive_depth: int = Field(default=2, ge=1, le=8)
    ai_timeout_seconds: float = Field(default=60.0, gt=0, le=600.0)
    max_workers: int = Field(default=4, ge=1, le=16)
    document_workers: int = Field(default=1, ge=1, le=4)
    chunk_size: int = Field(default=1_048_576, ge=65_536, le=8_388_608)
    use_redactlensignore: bool = True

    @model_validator(mode="after")
    def validate_internal_limits(self) -> BrowserScanOptions:
        ScanOptions.model_validate(self.model_dump())
        return self


class BrowserScanRequest(StrictRequest):
    """Resource-bounded browser contract projected into the unrestricted core model."""

    paths: list[PathValue] = Field(min_length=1, max_length=MAX_SCAN_PATHS)
    categories: list[CategoryValue] = Field(default_factory=list, max_length=MAX_SCAN_CATEGORIES)
    user_targets: list[BrowserUserTarget] = Field(
        default_factory=list,
        max_length=MAX_USER_TARGETS,
    )
    use_llm: bool = False
    ollama_model: OllamaModelValue | None = None
    tier_threshold: float = Field(default=DEFAULT_TIER_THRESHOLD, ge=0.0, le=1.0)
    options: BrowserScanOptions = Field(default_factory=BrowserScanOptions)

    def to_internal(self) -> ScanRequest:
        return ScanRequest.model_validate(self.model_dump())


class LaunchSessionResponse(BaseModel):
    token: str


class PublicSupportingDetection(BaseModel):
    """Consolidation evidence safe to retain in browser state."""

    detector_id: str
    description: str
    confidence: float = Field(ge=0.0, le=1.0)
    relationship: ConsolidationReason


class PublicFinding(BaseModel):
    """Finding fields that are safe and useful in browser state."""

    id: str
    file_path: str
    line: int
    column: int
    location: str | None = Field(default=None, max_length=MAX_PUBLIC_LOCATION_LENGTH)
    can_anonymize: bool = True
    redacted_preview: str
    detector_id: str
    category: str
    confidence: float = Field(ge=0.0, le=1.0)
    tier: Tier
    explanation: str
    risk_lesson: str
    suggested_action: SuggestedAction
    supporting_detections: list[PublicSupportingDetection] = Field(default_factory=list)

    @classmethod
    def from_internal(
        cls,
        finding: Finding,
        *,
        redactor: PublicRedactor | None = None,
        live: bool = False,
    ) -> PublicFinding:
        active_redactor = redactor or PublicRedactor.from_findings([finding])
        return cls(
            id=finding.id,
            file_path=(
                active_redactor.live_path(finding.file_path)
                if live
                else active_redactor.path(finding.file_path)
            ),
            line=finding.line,
            column=finding.column,
            # Structured labels and archive member names are untrusted source
            # metadata.  A live event cannot know whether they repeat a match
            # that will be discovered later in the scan, so publish them only
            # in the complete scan-wide projection.
            location=None if live else _public_location(finding, active_redactor),
            can_anonymize=finding.can_anonymize,
            redacted_preview=active_redactor.text(finding.redacted_preview),
            detector_id=finding.detector_id,
            category=active_redactor.identifier(finding.category),
            confidence=finding.confidence,
            tier=finding.tier,
            explanation=_public_explanatory_text(
                finding.explanation,
                finding,
                active_redactor,
            ),
            risk_lesson=_public_explanatory_text(
                finding.risk_lesson,
                finding,
                active_redactor,
            ),
            suggested_action=finding.suggested_action,
            supporting_detections=[
                PublicSupportingDetection(
                    detector_id=supporting.detector_id,
                    description=_public_explanatory_text(
                        supporting.description,
                        finding,
                        active_redactor,
                    ),
                    confidence=supporting.confidence,
                    relationship=supporting.relationship,
                )
                for supporting in finding.supporting_detections
            ],
        )

    def redacted(self, redactor: PublicRedactor) -> PublicFinding:
        location = redactor.text(self.location) if self.location is not None else None
        if location is not None and len(location) > MAX_PUBLIC_LOCATION_LENGTH:
            tail_length = MAX_PUBLIC_LOCATION_LENGTH // 3
            head_length = MAX_PUBLIC_LOCATION_LENGTH - tail_length - 1
            location = f"{location[:head_length]}…{location[-tail_length:]}"
        return self.model_copy(
            update={
                "file_path": redactor.path(self.file_path),
                "location": location,
                "redacted_preview": redactor.text(self.redacted_preview),
                "category": redactor.identifier(self.category),
                "explanation": redactor.text(self.explanation),
                "risk_lesson": redactor.text(self.risk_lesson),
                "supporting_detections": [
                    supporting.model_copy(
                        update={"description": redactor.text(supporting.description)},
                        deep=True,
                    )
                    for supporting in self.supporting_detections
                ],
            },
            deep=True,
        )


ScanState = Literal[
    "pending",
    "discovering",
    "scanning",
    "refining",
    "cancelling",
    "complete",
    "cancelled",
    "failed",
    "timed_out",
]


class PublicScanProgress(BaseModel):
    stage: ScanStage = "pending"
    completed_files: int = 0
    total_files: int | None = None
    percent: float = Field(default=0.0, ge=0.0, le=100.0)
    current_file: str | None = None
    findings_so_far: int = 0
    skipped_files: int = 0

    def redacted(self, redactor: PublicRedactor) -> PublicScanProgress:
        return self.model_copy(
            update={
                "current_file": (
                    redactor.path(self.current_file) if self.current_file is not None else None
                )
            },
            deep=True,
        )


class PublicScanError(BaseModel):
    code: str
    message: str

    def redacted(self, redactor: PublicRedactor) -> PublicScanError:
        return self.model_copy(
            update={"message": redactor.text(self.message)},
            deep=True,
        )


class PublicScanMetadata(BaseModel):
    selected_roots: list[str] = Field(default_factory=list)
    duration_ms: int | None = Field(default=None, ge=0)
    data_scanned_bytes: int = Field(default=0, ge=0)
    detector_count: int = Field(default=0, ge=0)
    ai_model: str | None = None

    def redacted(self, redactor: PublicRedactor) -> PublicScanMetadata:
        return self.model_copy(
            update={
                "selected_roots": [redactor.path(path) for path in self.selected_roots],
                "ai_model": redactor.text(self.ai_model) if self.ai_model is not None else None,
            },
            deep=True,
        )


class PublicScanResult(BaseModel):
    scan_id: str
    created_at: datetime
    expires_at: datetime
    event_cursor: int = Field(default=0, ge=0)
    findings: list[PublicFinding] = Field(default_factory=list)
    summary: dict[str, Any] = Field(default_factory=dict)
    scanned_files: list[str] = Field(default_factory=list)
    skipped_files: list[SkippedFile] = Field(default_factory=list)
    llm_used: bool = False
    state: ScanState = "complete"
    progress: PublicScanProgress = Field(default_factory=PublicScanProgress)
    error: PublicScanError | None = None
    metadata: PublicScanMetadata = Field(default_factory=PublicScanMetadata)

    @classmethod
    def from_internal(
        cls,
        *,
        scan_id: str,
        created_at: datetime,
        expires_at: datetime,
        result: ScanResult,
        state: ScanState = "complete",
        progress: PublicScanProgress | None = None,
        error: PublicScanError | None = None,
        metadata: PublicScanMetadata | None = None,
        redactor: PublicRedactor | None = None,
    ) -> PublicScanResult:
        active_redactor = redactor or PublicRedactor.from_findings(
            result.findings,
            reserved_paths=[
                *(finding.file_path for finding in result.findings),
                *result.scanned_files,
                *(skipped.path for skipped in result.skipped_files),
                *(metadata.selected_roots if metadata is not None else []),
                *(
                    [progress.current_file]
                    if progress is not None and progress.current_file is not None
                    else []
                ),
            ],
        )
        return cls(
            scan_id=scan_id,
            created_at=created_at,
            expires_at=expires_at,
            findings=[
                PublicFinding.from_internal(finding, redactor=active_redactor)
                for finding in result.findings
            ],
            summary=_redact_public_value(result.summary, active_redactor),
            scanned_files=[active_redactor.path(path) for path in result.scanned_files],
            skipped_files=[
                _public_skipped_file(skipped, active_redactor) for skipped in result.skipped_files
            ],
            llm_used=result.llm_used,
            state=state,
            progress=(
                progress
                or PublicScanProgress(
                    stage="complete" if state == "complete" else "pending",
                    completed_files=len(result.scanned_files) + len(result.skipped_files),
                    total_files=len(result.scanned_files) + len(result.skipped_files),
                    percent=100.0 if state == "complete" else 0.0,
                    findings_so_far=len(result.findings),
                    skipped_files=len(result.skipped_files),
                )
            ).redacted(active_redactor),
            error=error.redacted(active_redactor) if error is not None else None,
            metadata=(metadata or PublicScanMetadata()).redacted(active_redactor),
        )

    def redacted(self, redactor: PublicRedactor) -> PublicScanResult:
        return self.model_copy(
            update={
                "findings": [finding.redacted(redactor) for finding in self.findings],
                "summary": _redact_public_value(self.summary, redactor),
                "scanned_files": [redactor.path(path) for path in self.scanned_files],
                "skipped_files": [
                    _public_skipped_file(skipped, redactor) for skipped in self.skipped_files
                ],
                "progress": self.progress.redacted(redactor),
                "error": self.error.redacted(redactor) if self.error is not None else None,
                "metadata": self.metadata.redacted(redactor),
            },
            deep=True,
        )


class PublicScanEvent(BaseModel):
    sequence: int
    type: ScanEventType
    emitted_at: datetime
    scan_id: str
    state: ScanState
    progress: PublicScanProgress
    finding: PublicFinding | None = None
    skipped_file: SkippedFile | None = None
    error: PublicScanError | None = None

    def redacted(self, redactor: PublicRedactor) -> PublicScanEvent:
        return self.model_copy(
            update={
                "progress": self.progress.redacted(redactor),
                "finding": self.finding.redacted(redactor) if self.finding is not None else None,
                "skipped_file": (
                    _public_skipped_file(self.skipped_file, redactor)
                    if self.skipped_file is not None
                    else None
                ),
                "error": self.error.redacted(redactor) if self.error is not None else None,
            },
            deep=True,
        )


RemediationState = Literal["pending", "included", "ignored", "read_only"]
OutputState = Literal[
    "not_created",
    "current",
    "regeneration_required",
    "obsolete",
    "conflict",
]
VerificationStatus = Literal["verified"]
RescanStatus = Literal["completed", "failed"]
RemediationOutputMode = Literal["copy", "replace_original"]


class RemediationFindingState(BaseModel):
    finding_id: str
    state: RemediationState


class RemediationFilePlan(BaseModel):
    source_path: str
    output_path: str
    included_finding_ids: list[str]
    output_state: OutputState


class RemediationPlan(BaseModel):
    plan_revision: int
    findings: list[RemediationFindingState]
    files: list[RemediationFilePlan]
    selected_finding_count: int
    affected_file_count: int
    read_only_finding_count: int
    retained_artifact_paths: list[str]
    can_review: bool
    can_generate: bool


class UpdateRemediationRequest(StrictRequest):
    plan_revision: int = Field(ge=0)
    included_finding_ids: list[FindingId] = Field(
        default_factory=list,
        max_length=MAX_REMEDIATION_FINDINGS,
    )
    ignored_finding_ids: list[FindingId] = Field(
        default_factory=list,
        max_length=MAX_REMEDIATION_FINDINGS,
    )

    @model_validator(mode="after")
    def bound_total_findings(self) -> UpdateRemediationRequest:
        if (
            len(self.included_finding_ids) + len(self.ignored_finding_ids)
            > MAX_REMEDIATION_FINDINGS
        ):
            raise ValueError("too many remediation finding IDs")
        return self


class GenerateRemediationRequest(StrictRequest):
    plan_revision: int = Field(ge=0)
    output_mode: RemediationOutputMode = "copy"


class PublicFileFingerprint(BaseModel):
    resolved_path: str
    size: int
    modified_ns: int
    sha256: str


class GeneratedOutputDetails(BaseModel):
    source_path: str
    output_path: str
    applied_finding_ids: list[str]
    verification_status: VerificationStatus
    warnings: list[str]
    source_fingerprint: PublicFileFingerprint
    rescan_status: RescanStatus
    remaining_finding_count: int | None
    remaining_tier_a_count: int | None


class RemediationGenerationResponse(BaseModel):
    plan: RemediationPlan
    outputs: list[GeneratedOutputDetails]


class SessionOpenFileRequest(StrictRequest):
    finding_id: FindingId


class RevealFindingsRequest(StrictRequest):
    """Bounded IDs for a deliberate, transient raw-value reveal."""

    finding_ids: list[FindingId] = Field(min_length=1, max_length=MAX_REVEAL_FINDINGS)


class RevealedFindingValue(BaseModel):
    finding_id: str
    value: str


class RevealFindingsResponse(BaseModel):
    values: list[RevealedFindingValue]


class OpenFileResponse(BaseModel):
    status: str


class OpenRedactedCopyRequest(StrictRequest):
    finding_id: FindingId


class ErrorBody(BaseModel):
    code: str
    message: str


class ErrorResponse(BaseModel):
    error: ErrorBody
