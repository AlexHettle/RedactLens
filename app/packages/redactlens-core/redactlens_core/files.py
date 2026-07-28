"""Deterministic discovery, ignore rules, and bounded file reading."""

from __future__ import annotations

import codecs
import os
import re
import stat
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path

from redactlens_core.document_anonymize import REWRITABLE_FORMATS
from redactlens_core.extractors import (
    SUPPORTED_DOCUMENT_EXTENSIONS,
    ArchiveSafetyError,
    DocumentLimitExceeded,
    ExtractedDoc,
    ExtractedTextLimitExceeded,
    ExtractionError,
    ExtractionTimedOut,
    NoExtractableTextError,
    extract_document,
)
from redactlens_core.models import ScanOptions
from redactlens_core.textcodec import (
    BINARY_SNIFF_BYTES,
    TextCodec,
    codec_from_bom,
    decode_text,
    mostly_printable,
)

__all__ = [
    "DEFAULT_IGNORE_DIRS",
    "DEFAULT_MAX_FILE_SIZE",
    "DEFAULT_MAX_STRUCTURED_FILE_SIZE",
    "BINARY_SNIFF_BYTES",
    "TextCodec",
    "decode_text",
    "DiscoveredFile",
    "FileIssue",
    "FileSnapshot",
    "Scannable",
    "StreamFileChanged",
    "StreamFileTooLarge",
    "StreamReadStats",
    "TextChunk",
    "TextFileProbe",
    "discover_files",
    "is_structured_document",
    "iter_files",
    "iter_text_chunks",
    "probe_text_file",
    "read_regular_bytes_no_follow",
    "read_regular_prefix_no_follow",
    "regular_file_issue",
    "read_scannable",
    "read_scannable_detailed",
]

DEFAULT_IGNORE_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build"}
DEFAULT_MAX_FILE_SIZE = 100_000_000
DEFAULT_MAX_STRUCTURED_FILE_SIZE = 50_000_000
DEFAULT_MAX_EXTRACTED_CHARS = 50_000_000


def _directory_name_identity(name: str) -> str:
    """Match configured directory names with Windows' case-insensitive semantics."""

    return name.casefold()


class _ExtractionControlSignal(BaseException):
    """Carry a caller control exception past extraction's isolation catch."""

    def __init__(self, error: BaseException) -> None:
        self.error = error


_OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
_IMAGE_MAGICS = (b"\x89PNG", b"\xff\xd8\xff", b"GIF87a", b"GIF89a", b"BM")
_ZIP_MAGIC = b"PK\x03\x04"
_MAX_IGNORE_FILE_BYTES = 1_000_000
_MAX_IGNORE_RULES = 1_024
_MAX_IGNORE_PATTERN_CHARS = 1_024
_MAX_IGNORE_PATTERN_TOTAL_CHARS = 65_536
_IGNORE_FILE_NAME = ".redactlensignore"
_LEGACY_IGNORE_FILE_NAME = ".redactscoutignore"
_IGNORE_FILE_NAMES = frozenset({_IGNORE_FILE_NAME, _LEGACY_IGNORE_FILE_NAME})

_ENTRY_DIRECTORY = "directory"
_ENTRY_FILE = "file"
_ENTRY_ANCESTOR_REDIRECT = "ancestor_redirect"
_ENTRY_MISSING = "missing"
_ENTRY_NON_REGULAR = "non_regular"
_ENTRY_REPARSE = "reparse"
_ENTRY_SYMLINK = "symlink"
_ENTRY_UNAVAILABLE = "unavailable"


@dataclass(frozen=True)
class FileIssue:
    code: str
    stage: str
    reason: str
    rule: str | None = None


@dataclass(frozen=True)
class DiscoveredFile:
    path: str
    issue: FileIssue | None = None


@dataclass(frozen=True)
class FileSnapshot:
    """Internal entry identity and mutation-sensitive metadata for one read."""

    device: int
    inode: int
    size: int
    modified_ns: int
    changed_ns: int

    @classmethod
    def from_stat(cls, details: os.stat_result) -> FileSnapshot:
        return cls(
            device=details.st_dev,
            inode=details.st_ino,
            size=details.st_size,
            modified_ns=details.st_mtime_ns,
            # Lightweight test doubles and a few older stat providers omit
            # nanosecond ctime. Falling back to mtime remains fail-closed when
            # compared with a retained full platform snapshot.
            changed_ns=getattr(details, "st_ctime_ns", details.st_mtime_ns),
        )

    def matches(self, details: os.stat_result, *, include_changed: bool = True) -> bool:
        observed = FileSnapshot.from_stat(details)
        if include_changed:
            return self == observed
        return (
            self.device,
            self.inode,
            self.size,
            self.modified_ns,
        ) == (
            observed.device,
            observed.inode,
            observed.size,
            observed.modified_ns,
        )


@dataclass(frozen=True)
class TextFileProbe:
    """Plain-text probe result with an internal snapshot for the stream pass.

    Iteration deliberately preserves the historical three-value unpacking
    contract used by lower-level callers. The scanner additionally consumes
    ``snapshot`` so a same-size replacement cannot become a new baseline.
    """

    codec: TextCodec | None
    size: int
    issue: FileIssue | None
    snapshot: FileSnapshot | None

    def __iter__(self):
        yield self.codec
        yield self.size
        yield self.issue


@dataclass(frozen=True)
class TextChunk:
    """A text window plus the subrange whose candidate starts it owns."""

    text: str
    start_offset: int
    start_line: int
    start_column: int
    owned_start: int
    owned_end: int
    is_final: bool


@dataclass
class StreamReadStats:
    """Mutable physical-I/O accounting for one streaming text pass."""

    bytes_read: int = 0


class StreamFileTooLarge(Exception):
    """The streaming pass observed bytes beyond its configured ceiling."""

    def __init__(self, max_size: int, observed_size: int | None = None) -> None:
        self.max_size = max_size
        self.observed_size = observed_size
        super().__init__("streamed file exceeds its configured byte limit")


class StreamFileChanged(Exception):
    """The streaming source changed identity or metadata during the pass."""


@dataclass
class Scannable:
    """One file's materialized text, used for bounded structured documents."""

    text: str
    doc: ExtractedDoc | None = None

    @property
    def extracted(self) -> bool:
        return self.doc is not None

    @property
    def can_anonymize(self) -> bool:
        return self.doc is None or self.doc.format in REWRITABLE_FORMATS

    def location_at(self, offset: int) -> str | None:
        return self.doc.location_at(offset) if self.doc is not None else None


@dataclass(frozen=True)
class _IgnoreRule:
    raw: str
    source: str
    line: int
    negated: bool
    expression: _CompiledIgnorePattern

    @property
    def label(self) -> str:
        return f"{self.source}:{self.line}: {self.raw}"


class _IgnoreMatcher:
    def __init__(self, root: Path, rules: list[_IgnoreRule]) -> None:
        self.root = root
        self.rules = rules
        self.has_negations = any(rule.negated for rule in rules)

    def matching_rule(
        self,
        path: Path,
        *,
        is_directory: bool = False,
        checkpoint: Callable[[], None] | None = None,
    ) -> _IgnoreRule | None:
        if checkpoint is not None:
            checkpoint()
        try:
            relative = _absolute_no_follow(path).relative_to(self.root).as_posix()
        except ValueError:
            return None
        selected: _IgnoreRule | None = None
        ignored = False
        for rule in self.rules:
            if checkpoint is not None:
                checkpoint()
            if rule.expression.fullmatch(relative, is_directory=is_directory):
                ignored = not rule.negated
                selected = rule if ignored else None
        return selected


@dataclass(frozen=True)
class _CompiledIgnoreSegment:
    """One path segment compiled to a non-backtracking wildcard expression."""

    expression: re.Pattern[str]
    minimum_length: int

    def fullmatch(self, value: str) -> bool:
        return len(value) >= self.minimum_length and self.expression.fullmatch(value) is not None


@dataclass(frozen=True)
class _CompiledIgnorePattern:
    """A bounded Gitignore-style wildcard program for one ignore rule."""

    segments: tuple[_CompiledIgnoreSegment | None, ...]
    anchored: bool
    directory_only: bool
    descendants_only: bool

    def fullmatch(self, value: str, *, is_directory: bool = False) -> bool:
        components = value.split("/") if value else []

        if not self.anchored:
            segment = self.segments[0]
            assert segment is not None
            for index, component in enumerate(components):
                if not segment.fullmatch(component):
                    continue
                if index < len(components) - 1 or not self.directory_only or is_directory:
                    return True
            return False

        pattern = self.segments[:-1] if self.descendants_only else self.segments
        endpoint = _match_path_prefix(pattern, components)
        if endpoint is None:
            return False
        if self.descendants_only:
            # A trailing ``/**`` means entries *inside* the matched directory,
            # not the directory itself.
            return endpoint < len(components)
        if endpoint < len(components):
            return True
        return not self.directory_only or is_directory


def _match_path_prefix(
    pattern: tuple[_CompiledIgnoreSegment | None, ...],
    components: list[str],
) -> int | None:
    """Return the earliest component boundary matched by an anchored pattern."""

    pattern_index = 0
    component_index = 0
    globstar_index: int | None = None
    globstar_component = 0

    while True:
        while pattern_index < len(pattern) and pattern[pattern_index] is None:
            globstar_index = pattern_index
            globstar_component = component_index
            pattern_index += 1

        if pattern_index == len(pattern):
            return component_index

        segment = pattern[pattern_index]
        assert segment is not None
        if component_index < len(components) and segment.fullmatch(components[component_index]):
            pattern_index += 1
            component_index += 1
            continue

        if globstar_index is None or globstar_component >= len(components):
            return None
        globstar_component += 1
        component_index = globstar_component
        pattern_index = globstar_index + 1


def _compile_ignore_segment(pattern: str) -> _CompiledIgnoreSegment:
    """Compile ``*``/``?`` without exposing regex backtracking amplification."""

    star = object()
    translated: list[str | object] = []
    minimum_length = 0
    for char in pattern:
        if char == "*":
            if not translated or translated[-1] is not star:
                translated.append(star)
        elif char == "?":
            translated.append(".")
            minimum_length += 1
        else:
            translated.append(re.escape(char))
            minimum_length += 1

    # Pair each interior star with the following fixed piece in an atomic
    # non-greedy group. This is the same bounded construction used by modern
    # Python fnmatch: once a piece is selected, the engine cannot revisit an
    # exponential number of earlier wildcard partitions.
    expression: list[str] = []
    index = 0
    while index < len(translated) and translated[index] is not star:
        expression.append(str(translated[index]))
        index += 1
    while index < len(translated):
        assert translated[index] is star
        index += 1
        if index == len(translated):
            expression.append(".*")
            break
        fixed: list[str] = []
        while index < len(translated) and translated[index] is not star:
            fixed.append(str(translated[index]))
            index += 1
        fixed_expression = "".join(fixed)
        if index == len(translated):
            expression.extend((".*", fixed_expression))
        else:
            expression.append(f"(?>.*?{fixed_expression})")

    return _CompiledIgnoreSegment(
        re.compile(f"(?s:{''.join(expression)})\\Z"),
        minimum_length,
    )


def is_structured_document(path: str | Path) -> bool:
    return Path(path).suffix.lower() in SUPPORTED_DOCUMENT_EXTENSIONS


def _absolute_no_follow(path: str | Path) -> Path:
    """Return a lexical absolute path without resolving filesystem links."""

    return Path(os.path.abspath(os.fspath(path)))


def _entry_kind_no_follow(path: Path) -> tuple[str, OSError | None]:
    """Classify one directory entry without following redirects."""

    kind, _metadata, error = _entry_snapshot_no_follow(path)
    return kind, error


def _entry_snapshot_no_follow(
    path: Path,
) -> tuple[str, os.stat_result | None, OSError | None]:
    """Classify an entry and retain the metadata validated by that check."""

    ancestor_kind, ancestor_error = _redirect_ancestor_kind(path)
    if ancestor_kind is not None:
        return ancestor_kind, None, ancestor_error

    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return _ENTRY_MISSING, None, None
    except OSError as error:
        return _ENTRY_UNAVAILABLE, None, error

    try:
        if _is_filesystem_redirect(path, metadata):
            if stat.S_ISLNK(metadata.st_mode):
                return _ENTRY_SYMLINK, metadata, None
            return _ENTRY_REPARSE, metadata, None
    except OSError:
        return _ENTRY_UNAVAILABLE, None, None

    if stat.S_ISREG(metadata.st_mode):
        return _ENTRY_FILE, metadata, None
    if stat.S_ISDIR(metadata.st_mode):
        return _ENTRY_DIRECTORY, metadata, None
    return _ENTRY_NON_REGULAR, metadata, None


def _redirect_ancestor_kind(path: Path) -> tuple[str | None, OSError | None]:
    """Classify an unsafe lexical ancestor without dereferencing the final entry."""

    for directory in reversed(_absolute_no_follow(path).parents):
        try:
            metadata = directory.lstat()
            if _is_filesystem_redirect(directory, metadata):
                return _ENTRY_ANCESTOR_REDIRECT, None
            if not stat.S_ISDIR(metadata.st_mode):
                return _ENTRY_NON_REGULAR, None
        except OSError as error:
            return _ENTRY_UNAVAILABLE, error
    return None, None


def _is_filesystem_redirect(path: Path, metadata: os.stat_result) -> bool:
    """Recognize POSIX links plus Windows junction and reparse redirects."""

    if stat.S_ISLNK(metadata.st_mode):
        return True
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    file_attributes = getattr(metadata, "st_file_attributes", None)
    if reparse_flag and file_attributes is not None:
        return bool(file_attributes & reparse_flag)

    # Older/non-Windows stat results cannot expose reparse attributes. Only
    # then use pathlib's junction probe, which performs another metadata call.
    is_junction = getattr(path, "is_junction", None)
    if callable(is_junction) and is_junction():
        return True
    return False


def _unsafe_entry_issue(kind: str, stage: str) -> FileIssue | None:
    if kind == _ENTRY_SYMLINK:
        return FileIssue(
            "symbolic_link",
            stage,
            "symbolic link skipped — scan the real target explicitly if you trust it",
        )
    if kind == _ENTRY_REPARSE:
        return FileIssue(
            "filesystem_redirect",
            stage,
            "filesystem redirect skipped — scan the real target explicitly if you trust it",
        )
    if kind == _ENTRY_ANCESTOR_REDIRECT:
        return FileIssue(
            "filesystem_redirect",
            stage,
            "filesystem redirect in parent path skipped — select the real path explicitly",
        )
    if kind == _ENTRY_NON_REGULAR:
        return FileIssue(
            "non_regular_file",
            stage,
            "non-regular filesystem entry skipped",
        )
    if kind == _ENTRY_MISSING:
        return FileIssue("stat_failed", stage, "file is no longer available")
    if kind == _ENTRY_UNAVAILABLE:
        return FileIssue("stat_failed", stage, "file metadata is unavailable")
    return None


def regular_file_issue(path: str | Path, *, stage: str = "extraction") -> FileIssue | None:
    """Return a curated issue unless ``path`` is a no-follow regular file."""

    _metadata, issue = _regular_file_snapshot_no_follow(Path(path), stage=stage)
    return issue


def _regular_file_snapshot_no_follow(
    path: Path,
    *,
    stage: str,
) -> tuple[os.stat_result | None, FileIssue | None]:
    kind, metadata, _error = _entry_snapshot_no_follow(path)
    if kind == _ENTRY_FILE:
        assert metadata is not None
        return metadata, None
    if kind == _ENTRY_DIRECTORY:
        return None, FileIssue(
            "non_regular_file",
            stage,
            "directory cannot be scanned as a file",
        )
    return None, _unsafe_entry_issue(kind, stage)


def _walk_directory_checkpointed(
    path: Path,
    *,
    checkpoint: Callable[[], None] | None,
    onerror: Callable[[OSError], None],
    onchanged: Callable[[Path, FileIssue], None],
) -> Iterator[tuple[str, list[str], list[str]]]:
    """Yield a top-down walk while remaining interruptible inside wide directories."""

    def check() -> None:
        if checkpoint is not None:
            checkpoint()

    pending = [str(path)]
    while pending:
        check()
        root = pending.pop()
        root_path = Path(root)
        root_kind, _error = _entry_kind_no_follow(root_path)
        if root_kind != _ENTRY_DIRECTORY:
            onchanged(root_path, _directory_descent_issue(root_kind))
            continue
        directories: list[str] = []
        files: list[str] = []
        enumeration_failed = False
        try:
            entries = os.scandir(root)
        except OSError as error:
            onerror(error)
            continue

        with entries:
            # Close an iterator opened during a path-swap race before asking
            # it for even one entry. If the path changes after this check, the
            # already-open iterator still addresses the approved directory;
            # descendant path classification independently checks ancestors.
            check()
            root_kind, _error = _entry_kind_no_follow(root_path)
            if root_kind != _ENTRY_DIRECTORY:
                onchanged(root_path, _directory_descent_issue(root_kind))
                continue
            while True:
                check()
                try:
                    entry = next(entries)
                except StopIteration:
                    break
                except OSError as error:
                    onerror(error)
                    enumeration_failed = True
                    break
                check()
                try:
                    # Classify without dereferencing the entry. Symlinks stay
                    # on the directory side only so configured ignored names
                    # retain os.walk's outcome; the caller's no-follow
                    # snapshot always reports and prunes them before descent.
                    is_directory = entry.is_dir(follow_symlinks=False) or entry.is_symlink()
                except OSError:
                    # Match os.walk: an entry whose directory classification
                    # fails is still surfaced for ordinary file classification.
                    is_directory = False
                (directories if is_directory else files).append(entry.name)

        if enumeration_failed:
            continue

        # The caller mutates ``directories`` in place to prune ignored and
        # unsafe entries. Resume only after that mutation, like top-down
        # os.walk, and reverse the stack insertion to preserve its ordering.
        yield root, directories, files
        for name in reversed(directories):
            check()
            pending.append(str(Path(root) / name))


def _directory_descent_issue(kind: str) -> FileIssue:
    issue = _unsafe_entry_issue(kind, "discovery")
    if issue is not None:
        return issue
    return FileIssue(
        "directory_unreadable",
        "discovery",
        "directory entry changed before it could be safely traversed",
    )


def discover_files(
    paths: list[str],
    options: ScanOptions,
    checkpoint: Callable[[], None] | None = None,
) -> Iterator[DiscoveredFile]:
    """Yield stable, unique discovery entries including explained exclusions."""

    def check() -> None:
        if checkpoint is not None:
            checkpoint()

    def name_sort_key(name: str) -> str:
        check()
        return name.casefold()

    def entry_sort_key(item: DiscoveredFile) -> tuple[str, bool]:
        check()
        return os.path.normcase(os.path.abspath(item.path)), item.issue is not None

    entries: list[DiscoveredFile] = []

    def capture_walk_error(error: OSError) -> None:
        check()
        walk_errors.append(error)

    def capture_changed_directory(path: Path, issue: FileIssue) -> None:
        check()
        entries.append(DiscoveredFile(str(path), issue))

    check()
    ignored_directories = {_directory_name_identity(name) for name in options.ignored_directories}
    for raw_path in paths:
        check()
        path = Path(raw_path)
        path_kind, _error = _entry_kind_no_follow(path)
        matcher = _load_ignore_matcher(
            path if path_kind == _ENTRY_DIRECTORY else path.parent,
            options,
            checkpoint=checkpoint,
        )
        check()
        if path_kind != _ENTRY_DIRECTORY:
            entry = _classify_discovered(
                path,
                matcher,
                options,
                explicit=True,
                checkpoint=checkpoint,
            )
            if entry is not None:
                entries.append(entry)
            continue

        walk_errors: list[OSError] = []
        for root, dirs, files in _walk_directory_checkpointed(
            path,
            checkpoint=checkpoint,
            onerror=capture_walk_error,
            onchanged=capture_changed_directory,
        ):
            check()
            root_path = Path(root)
            retained: list[str] = []
            for name in sorted(dirs, key=name_sort_key):
                check()
                candidate = root_path / name
                if _directory_name_identity(name) in ignored_directories:
                    entries.append(
                        DiscoveredFile(
                            str(candidate),
                            FileIssue(
                                "ignored_directory",
                                "discovery",
                                f"directory excluded by configured ignore name '{name}'",
                                f"ignored_directories:{name}",
                            ),
                        )
                    )
                    continue
                candidate_kind, _error = _entry_kind_no_follow(candidate)
                unsafe_issue = _unsafe_entry_issue(candidate_kind, "discovery")
                if unsafe_issue is not None:
                    entries.append(DiscoveredFile(str(candidate), unsafe_issue))
                    continue
                if candidate_kind != _ENTRY_DIRECTORY:
                    entries.append(
                        DiscoveredFile(
                            str(candidate),
                            FileIssue(
                                "directory_unreadable",
                                "discovery",
                                "directory entry could not be safely traversed",
                            ),
                        )
                    )
                    continue
                rule = (
                    matcher.matching_rule(
                        candidate,
                        is_directory=True,
                        checkpoint=checkpoint,
                    )
                    if matcher is not None
                    else None
                )
                if rule is not None and (matcher is None or not matcher.has_negations):
                    entries.append(_ignored_entry(candidate, rule))
                    continue
                retained.append(name)
            dirs[:] = retained

            for name in sorted(files, key=name_sort_key):
                check()
                candidate = root_path / name
                if candidate.name in _IGNORE_FILE_NAMES:
                    continue
                entry = _classify_discovered(
                    candidate,
                    matcher,
                    options,
                    explicit=False,
                    checkpoint=checkpoint,
                )
                if entry is not None:
                    entries.append(entry)

        for error in walk_errors:
            check()
            failed_path = error.filename or str(path)
            entries.append(
                DiscoveredFile(
                    str(failed_path),
                    FileIssue(
                        "directory_unreadable",
                        "discovery",
                        "directory could not be read",
                    ),
                )
            )

    unique: dict[str, DiscoveredFile] = {}
    for entry in entries:
        check()
        key = os.path.normcase(os.path.abspath(entry.path))
        unique.setdefault(key, entry)
    for entry in sorted(unique.values(), key=entry_sort_key):
        check()
        yield entry


def iter_files(paths: list[str], ignore_dirs: set[str] | None = None) -> Iterator[str]:
    """Backwards-compatible deterministic walker used by lower-level callers."""
    ignored = ignore_dirs if ignore_dirs is not None else DEFAULT_IGNORE_DIRS
    ignored_identities = {_directory_name_identity(name) for name in ignored}
    for raw_path in paths:
        path = Path(raw_path)
        path_kind, _error = _entry_kind_no_follow(path)
        if path_kind != _ENTRY_DIRECTORY:
            yield str(path)
        else:
            for root, dirs, files in os.walk(path, followlinks=False):
                linked_dirs: list[str] = []
                retained_dirs: list[str] = []
                for name in sorted(dirs, key=str.casefold):
                    if _directory_name_identity(name) in ignored_identities:
                        continue
                    candidate = Path(root) / name
                    candidate_kind, _error = _entry_kind_no_follow(candidate)
                    if candidate_kind != _ENTRY_DIRECTORY:
                        linked_dirs.append(str(candidate))
                    else:
                        retained_dirs.append(name)
                dirs[:] = retained_dirs
                yield from linked_dirs
                for name in sorted(files, key=str.casefold):
                    yield str(Path(root) / name)


def _classify_discovered(
    path: Path,
    matcher: _IgnoreMatcher | None,
    options: ScanOptions,
    *,
    explicit: bool,
    checkpoint: Callable[[], None] | None = None,
) -> DiscoveredFile | None:
    if checkpoint is not None:
        checkpoint()
    kind, _error = _entry_kind_no_follow(path)
    unsafe_issue = _unsafe_entry_issue(kind, "discovery")
    if unsafe_issue is not None:
        return DiscoveredFile(str(path), unsafe_issue)
    if kind != _ENTRY_FILE:
        return DiscoveredFile(
            str(path),
            FileIssue(
                "non_regular_file",
                "discovery",
                "filesystem entry cannot be scanned as a regular file",
            ),
        )
    if not explicit and path.name in _IGNORE_FILE_NAMES:
        return None
    rule = matcher.matching_rule(path, checkpoint=checkpoint) if matcher is not None else None
    if rule is not None:
        return _ignored_entry(path, rule)

    suffix = path.suffix.lower()
    excluded_extension = _matching_configured_extension(path, options.excluded_extensions)
    if excluded_extension is not None:
        return DiscoveredFile(
            str(path),
            FileIssue(
                "excluded_extension",
                "discovery",
                f"extension '{excluded_extension}' is excluded by scan options",
                f"excluded_extensions:{excluded_extension}",
            ),
        )
    included_extension = _matching_configured_extension(path, options.included_extensions)
    if options.included_extensions and included_extension is None:
        allowed = ", ".join(options.included_extensions)
        return DiscoveredFile(
            str(path),
            FileIssue(
                "extension_not_included",
                "discovery",
                f"extension '{suffix or '(none)'}' is not in the included set ({allowed})",
                f"included_extensions:{allowed}",
            ),
        )
    return DiscoveredFile(str(path))


def _matching_configured_extension(path: Path, extensions: list[str]) -> str | None:
    """Return the most specific configured suffix matching the full filename."""

    filename = path.name.lower()
    matches = (extension for extension in extensions if filename.endswith(extension))
    return max(matches, key=lambda extension: (len(extension), extension), default=None)


def _ignored_entry(path: Path, rule: _IgnoreRule) -> DiscoveredFile:
    return DiscoveredFile(
        str(path),
        FileIssue(
            "ignored_by_rule",
            "discovery",
            f"excluded by {Path(rule.source).name} rule '{rule.raw}'",
            rule.label,
        ),
    )


def _load_ignore_matcher(
    root: Path,
    options: ScanOptions,
    *,
    checkpoint: Callable[[], None] | None = None,
) -> _IgnoreMatcher | None:
    if checkpoint is not None:
        checkpoint()
    if not options.use_redactlensignore:
        return None
    ignore_path = root / _IGNORE_FILE_NAME
    try:
        raw = _read_regular_bytes_no_follow(ignore_path, _MAX_IGNORE_FILE_BYTES)
        if checkpoint is not None:
            checkpoint()
        if raw is None:
            current_kind, _error = _entry_kind_no_follow(ignore_path)
            if current_kind != _ENTRY_MISSING:
                return None
            ignore_path = root / _LEGACY_IGNORE_FILE_NAME
            raw = _read_regular_bytes_no_follow(ignore_path, _MAX_IGNORE_FILE_BYTES)
            if checkpoint is not None:
                checkpoint()
            if raw is None:
                return None
        lines = raw.decode("utf-8").splitlines()
    except UnicodeError:
        return None

    rules: list[_IgnoreRule] = []
    pattern_chars = 0
    for line_number, raw_line in enumerate(lines, start=1):
        if checkpoint is not None:
            checkpoint()
        value = raw_line.strip()
        if not value or value.startswith("#"):
            continue
        negated = value.startswith("!")
        pattern = value[1:] if negated else value
        if not pattern:
            continue
        if (
            len(rules) >= _MAX_IGNORE_RULES
            or len(pattern) > _MAX_IGNORE_PATTERN_CHARS
            or pattern_chars + len(pattern) > _MAX_IGNORE_PATTERN_TOTAL_CHARS
        ):
            # Never retain a partial ruleset. In particular, dropping a late
            # negation while keeping an earlier broad exclusion could hide a
            # file the user explicitly re-included. A cap violation therefore
            # disables this ignore file and safely scans everything.
            return None
        pattern_chars += len(pattern)
        rules.append(
            _IgnoreRule(
                raw=value,
                source=str(ignore_path),
                line=line_number,
                negated=negated,
                expression=_compile_ignore_pattern(pattern),
            )
        )
    if checkpoint is not None:
        checkpoint()
    return _IgnoreMatcher(_absolute_no_follow(root), rules)


def _read_regular_bytes_no_follow(
    path: Path,
    max_bytes: int,
    *,
    validated_metadata: os.stat_result | None = None,
) -> bytes | None:
    """Read a stable regular file while refusing link/reparse traversal.

    ``validated_metadata`` lets a caller reuse the exact no-follow snapshot it
    just classified. The descriptor and path are still checked before and
    after I/O so the optimization does not turn that snapshot into trust.
    """

    before = validated_metadata
    if before is None:
        before, issue = _regular_file_snapshot_no_follow(path, stage="extraction")
        if issue is not None:
            return None
    assert before is not None
    expected = FileSnapshot.from_stat(before)
    try:
        return read_regular_bytes_no_follow(
            path,
            max_bytes=max_bytes,
            expected=expected,
            _validated_metadata=before,
        )
    except OSError:
        return None


def read_regular_bytes_no_follow(
    path: str | Path,
    *,
    max_bytes: int | None = None,
    expected: FileSnapshot | None = None,
    _validated_metadata: os.stat_result | None = None,
) -> bytes:
    """Read stable bytes through one no-follow descriptor.

    When ``expected`` is supplied, entry identity, size, mtime, and ctime must
    match before, during, and after the read. The size ceiling is checked from
    descriptor metadata before allocating and again while reading.
    """

    candidate = Path(path)
    before = _validated_metadata
    if before is None:
        before, issue = _regular_file_snapshot_no_follow(candidate, stage="verification")
        if issue is not None or before is None:
            raise OSError(issue.reason if issue is not None else "file metadata is unavailable")
    baseline = FileSnapshot.from_stat(before)
    if expected is not None and baseline != expected:
        raise OSError("file changed before it could be read")
    if max_bytes is not None and baseline.size > max_bytes:
        raise OSError("file exceeds the configured read limit")

    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(candidate, flags)
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or not baseline.matches(opened, include_changed=False):
            raise OSError("file changed before it could be opened")
        ancestor_kind, _error = _redirect_ancestor_kind(candidate)
        if ancestor_kind is not None:
            raise OSError("file parent is a filesystem redirect")
        chunks: list[bytes] = []
        remaining = None if max_bytes is None else max_bytes + 1
        while remaining is None or remaining > 0:
            amount = 65_536 if remaining is None else min(65_536, remaining)
            chunk = os.read(descriptor, amount)
            if not chunk:
                break
            chunks.append(chunk)
            if remaining is not None:
                remaining -= len(chunk)
        raw = b"".join(chunks)
        if max_bytes is not None and len(raw) > max_bytes:
            raise OSError("file exceeds the configured read limit")
        after_opened = os.fstat(descriptor)
    finally:
        os.close(descriptor)

    try:
        after_path = candidate.lstat()
    except OSError as error:
        raise OSError("file changed while it was being read") from error
    ancestor_kind, _error = _redirect_ancestor_kind(candidate)
    if (
        ancestor_kind is not None
        or _is_filesystem_redirect(candidate, after_path)
        or not stat.S_ISREG(after_path.st_mode)
        or not baseline.matches(after_opened, include_changed=False)
        or not baseline.matches(after_path)
    ):
        raise OSError("file changed while it was being read")
    return raw


def read_regular_prefix_no_follow(path: str | Path, length: int) -> bytes:
    """Read at most *length* bytes without materializing the complete file.

    The entry, descriptor, final path, and lexical ancestors must describe the
    same stable ordinary file before and after the bounded read.
    """

    if length < 0:
        raise ValueError("prefix length must be nonnegative")
    candidate = Path(path)
    before, issue = _regular_file_snapshot_no_follow(candidate, stage="verification")
    if issue is not None or before is None:
        raise OSError(issue.reason if issue is not None else "file metadata is unavailable")
    baseline = FileSnapshot.from_stat(before)
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(candidate, flags)
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or not baseline.matches(
            opened,
            include_changed=False,
        ):
            raise OSError("file changed before it could be opened")
        ancestor_kind, _error = _redirect_ancestor_kind(candidate)
        if ancestor_kind is not None:
            raise OSError("file parent is a filesystem redirect")
        prefix = os.read(descriptor, length)
        after_opened = os.fstat(descriptor)
    finally:
        os.close(descriptor)

    try:
        after_path = candidate.lstat()
    except OSError as error:
        raise OSError("file changed while its prefix was being read") from error
    ancestor_kind, _error = _redirect_ancestor_kind(candidate)
    if (
        ancestor_kind is not None
        or _is_filesystem_redirect(candidate, after_path)
        or not stat.S_ISREG(after_path.st_mode)
        or not baseline.matches(after_opened, include_changed=False)
        or not baseline.matches(after_path)
    ):
        raise OSError("file changed while its prefix was being read")
    return prefix


def _open_regular_binary_no_follow(
    path: Path,
    *,
    expected: FileSnapshot | None = None,
):
    """Open a regular file descriptor without following a redirect."""

    kind, _error = _entry_kind_no_follow(path)
    if kind != _ENTRY_FILE:
        raise OSError("filesystem entry is not a regular file")
    before = path.lstat()
    baseline = FileSnapshot.from_stat(before)
    if expected is not None and baseline != expected:
        raise OSError("filesystem entry changed before it could be opened")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or not baseline.matches(opened, include_changed=False):
            raise OSError("filesystem entry changed before it could be opened")
        ancestor_kind, _error = _redirect_ancestor_kind(path)
        if ancestor_kind is not None:
            raise OSError("filesystem entry parent changed before it could be opened")
        return os.fdopen(descriptor, "rb")
    except Exception:
        os.close(descriptor)
        raise


def _same_entry(left: os.stat_result, right: os.stat_result) -> bool:
    """Compare stable entry identity where the platform exposes it."""

    if (left.st_dev, left.st_ino) != (right.st_dev, right.st_ino):
        return False
    return True


def _same_file_snapshot(left: os.stat_result, right: os.stat_result) -> bool:
    """Compare the identity and mutation-sensitive metadata used by reads."""

    return _same_entry(left, right) and (left.st_size, left.st_mtime_ns) == (
        right.st_size,
        right.st_mtime_ns,
    )


def _compile_ignore_pattern(pattern: str) -> _CompiledIgnorePattern:
    anchored = pattern.startswith("/")
    if anchored:
        pattern = pattern[1:]
    directory_only = pattern.endswith("/")
    descendants_only = pattern.endswith("/**")
    if directory_only:
        pattern = pattern[:-1]
    has_slash = "/" in pattern
    path_anchored = anchored or has_slash

    segments: list[_CompiledIgnoreSegment | None] = []
    for segment in pattern.split("/"):
        compiled: _CompiledIgnoreSegment | None
        if path_anchored and segment == "**":
            compiled = None
        else:
            compiled = _compile_ignore_segment(segment)
        if compiled is None and segments and segments[-1] is None:
            continue
        segments.append(compiled)

    return _CompiledIgnorePattern(
        tuple(segments),
        path_anchored,
        directory_only,
        descendants_only,
    )


def probe_text_file(
    path: str,
    *,
    max_size: int = DEFAULT_MAX_FILE_SIZE,
    checkpoint: Callable[[], None] | None = None,
    extraction_timed_out: Callable[[], bool] | None = None,
) -> TextFileProbe:
    """Validate a plain-text encoding without materializing the file."""
    if checkpoint is not None:
        checkpoint()
    candidate = Path(path)
    metadata, issue = _regular_file_snapshot_no_follow(candidate, stage="extraction")
    if issue is not None or metadata is None:
        return TextFileProbe(None, 0, issue, None)
    snapshot = FileSnapshot.from_stat(metadata)
    size = snapshot.size
    if size > max_size:
        return TextFileProbe(
            None,
            size,
            FileIssue(
                "file_too_large",
                "extraction",
                f"file exceeds max scan size ({size} > {max_size} bytes)",
            ),
            snapshot,
        )
    try:
        prefix = _read_stable_prefix(candidate, BINARY_SNIFF_BYTES, snapshot)
    except OSError:
        return TextFileProbe(
            None,
            size,
            FileIssue("read_failed", "extraction", "file could not be read"),
            None,
        )
    if checkpoint is not None:
        checkpoint()

    announced = codec_from_bom(prefix)
    if announced is not None:
        valid, validation_issue = _validate_stream_encoding(
            candidate,
            announced,
            checkpoint,
            snapshot,
            max_size=max_size,
            extraction_timed_out=extraction_timed_out,
        )
        if validation_issue is not None:
            return TextFileProbe(None, size, validation_issue, None)
        if valid:
            return TextFileProbe(announced, size, None, snapshot)
        return TextFileProbe(
            None,
            size,
            FileIssue(
                "invalid_encoding",
                "extraction",
                "encoding marker does not match the file contents",
            ),
            None,
        )
    unsupported_reason = _unsupported_binary_reason(prefix, candidate.suffix.lower())
    if unsupported_reason is not None:
        return TextFileProbe(
            None,
            size,
            FileIssue("unsupported_binary", "extraction", unsupported_reason),
            snapshot,
        )
    if b"\x00" in prefix:
        return TextFileProbe(
            None,
            size,
            FileIssue(
                "binary_file",
                "extraction",
                "binary file (null byte detected)",
            ),
            snapshot,
        )

    utf8 = TextCodec("utf-8")
    valid_utf8, validation_issue = _validate_stream_encoding(
        candidate,
        utf8,
        checkpoint,
        snapshot,
        max_size=max_size,
        extraction_timed_out=extraction_timed_out,
    )
    if validation_issue is not None:
        return TextFileProbe(None, size, validation_issue, None)
    if valid_utf8:
        return TextFileProbe(utf8, size, None, snapshot)
    try:
        sample = prefix.decode("cp1252")
    except UnicodeDecodeError:
        sample = ""
    cp1252 = TextCodec("cp1252")
    if sample and mostly_printable(sample):
        valid_cp1252, validation_issue = _validate_stream_encoding(
            candidate,
            cp1252,
            checkpoint,
            snapshot,
            max_size=max_size,
            extraction_timed_out=extraction_timed_out,
        )
        if validation_issue is not None:
            return TextFileProbe(None, size, validation_issue, None)
        if valid_cp1252:
            return TextFileProbe(cp1252, size, None, snapshot)
    return TextFileProbe(
        None,
        size,
        FileIssue(
            "unsupported_encoding",
            "extraction",
            "could not decode as text — unknown or unsupported encoding",
        ),
        None,
    )


def _read_stable_prefix(path: Path, length: int, expected: FileSnapshot) -> bytes:
    with _open_regular_binary_no_follow(path, expected=expected) as stream:
        prefix = stream.read(length)
        after_opened = os.fstat(stream.fileno())
    try:
        after_path = path.lstat()
    except OSError as error:
        raise OSError("file changed while it was being probed") from error
    ancestor_kind, _error = _redirect_ancestor_kind(path)
    if (
        ancestor_kind is not None
        or _is_filesystem_redirect(path, after_path)
        or not expected.matches(after_opened, include_changed=False)
        or not expected.matches(after_path)
    ):
        raise OSError("file changed while it was being probed")
    return prefix


def _validate_stream_encoding(
    path: Path,
    codec: TextCodec,
    checkpoint: Callable[[], None] | None,
    expected: FileSnapshot,
    *,
    max_size: int,
    extraction_timed_out: Callable[[], bool] | None,
) -> tuple[bool, FileIssue | None]:
    """Validate one codec without letting a growing source escape its bounds."""

    decoder = codecs.getincrementaldecoder(codec.name)(errors="strict")
    bytes_read = 0

    def check() -> FileIssue | None:
        if checkpoint is not None:
            checkpoint()
        if extraction_timed_out is not None and extraction_timed_out():
            return FileIssue(
                "extraction_timeout",
                "extraction",
                "text extraction exceeded the configured time limit",
            )
        return None

    try:
        with _open_regular_binary_no_follow(path, expected=expected) as stream:
            if codec.bom:
                stream.seek(len(codec.bom))
                bytes_read = len(codec.bom)
            while True:
                issue = check()
                if issue is not None:
                    return False, issue
                remaining = max_size - bytes_read
                raw = stream.read(min(1_048_576, remaining + 1))
                bytes_read += len(raw)
                issue = check()
                if issue is not None:
                    return False, issue
                if bytes_read > max_size:
                    return (
                        False,
                        FileIssue(
                            "file_too_large",
                            "extraction",
                            f"file exceeds max scan size ({bytes_read} > {max_size} bytes)",
                        ),
                    )
                if not raw:
                    break
                try:
                    decoder.decode(raw, final=False)
                except UnicodeDecodeError:
                    if _stream_source_changed(path, stream, expected):
                        return False, _stream_source_changed_issue()
                    return False, None
            try:
                decoder.decode(b"", final=True)
            except UnicodeDecodeError:
                if _stream_source_changed(path, stream, expected):
                    return False, _stream_source_changed_issue()
                return False, None
            if _stream_source_changed(path, stream, expected):
                return False, _stream_source_changed_issue()
        return True, None
    except OSError:
        return False, _stream_read_issue(path, expected)


def _stream_source_changed(path: Path, stream, expected: FileSnapshot) -> bool:
    try:
        after_opened = os.fstat(stream.fileno())
        after_path = path.lstat()
        ancestor_kind, _error = _redirect_ancestor_kind(path)
        return (
            ancestor_kind is not None
            or _is_filesystem_redirect(path, after_path)
            or not expected.matches(after_opened, include_changed=False)
            or not expected.matches(after_path)
        )
    except OSError:
        return True


def _stream_source_changed_issue() -> FileIssue:
    return FileIssue("read_failed", "extraction", "file changed while it was being scanned")


def _stream_read_issue(path: Path, expected: FileSnapshot) -> FileIssue:
    metadata, issue = _regular_file_snapshot_no_follow(path, stage="extraction")
    if metadata is None or issue is not None or FileSnapshot.from_stat(metadata) != expected:
        return _stream_source_changed_issue()
    return FileIssue("read_failed", "extraction", "file could not be read")


def iter_text_chunks(
    path: str,
    codec: TextCodec,
    *,
    chunk_size: int,
    overlap: int,
    max_size: int = DEFAULT_MAX_FILE_SIZE,
    expected_size: int | None = None,
    expected_snapshot: FileSnapshot | None = None,
    checkpoint: Callable[[], None] | None = None,
    stats: StreamReadStats | None = None,
) -> Iterator[TextChunk]:
    """Read byte-bounded overlapping text windows with global positions."""
    left = ""
    future = ""
    core_offset = 0
    window_line = 1
    window_column = 1
    reached_eof = False
    read_stats = stats if stats is not None else StreamReadStats()
    read_stats.bytes_read = 0
    candidate = Path(path)
    try:
        before = candidate.lstat()
    except OSError as error:
        raise StreamFileChanged from error
    baseline = FileSnapshot.from_stat(before)
    if baseline.size > max_size:
        raise StreamFileTooLarge(max_size, baseline.size)
    if expected_snapshot is not None and baseline != expected_snapshot:
        raise StreamFileChanged

    with _open_regular_binary_no_follow(candidate, expected=expected_snapshot) as binary:
        opened = os.fstat(binary.fileno())
        if opened.st_size > max_size:
            raise StreamFileTooLarge(max_size, opened.st_size)
        if expected_size is not None and opened.st_size != expected_size:
            raise StreamFileChanged
        if not baseline.matches(opened, include_changed=False):
            raise StreamFileChanged

        decoder = codecs.getincrementaldecoder(codec.name)(errors="strict")
        if codec.bom:
            announced = binary.read(len(codec.bom))
            read_stats.bytes_read += len(announced)
            if checkpoint is not None:
                checkpoint()
            if read_stats.bytes_read > max_size:
                raise StreamFileTooLarge(max_size, read_stats.bytes_read)
            if announced != codec.bom:
                raise UnicodeDecodeError(
                    codec.name,
                    announced,
                    0,
                    len(announced),
                    "encoding marker changed before streaming",
                )

        def fill(target: int) -> None:
            nonlocal future, reached_eof
            while len(future) < target and not reached_eof:
                if checkpoint is not None:
                    checkpoint()
                remaining = max_size - read_stats.bytes_read
                raw = binary.read(min(65_536, remaining + 1))
                read_stats.bytes_read += len(raw)
                if checkpoint is not None:
                    checkpoint()
                if read_stats.bytes_read > max_size:
                    raise StreamFileTooLarge(max_size, read_stats.bytes_read)
                if raw:
                    future += decoder.decode(raw, final=False)
                    continue
                future += decoder.decode(b"", final=True)
                reached_eof = True

        fill(chunk_size + overlap)
        while future:
            core = future[:chunk_size]
            right = future[len(core) : len(core) + overlap]
            window = left + core + right
            yield TextChunk(
                text=window,
                start_offset=core_offset - len(left),
                start_line=window_line,
                start_column=window_column,
                owned_start=len(left),
                owned_end=len(left) + len(core),
                is_final=reached_eof and len(future) <= len(core),
            )

            combined = left + core
            new_left = combined[-overlap:] if overlap else ""
            discarded = combined[: len(combined) - len(new_left)]
            window_line, window_column = _advance_position(
                window_line,
                window_column,
                discarded,
            )
            left = new_left
            core_offset += len(core)
            future = future[len(core) :]
            fill(chunk_size + overlap)

        after_opened = os.fstat(binary.fileno())

    try:
        after_path = candidate.lstat()
    except OSError as error:
        raise StreamFileChanged from error
    ancestor_kind, _error = _redirect_ancestor_kind(candidate)
    if ancestor_kind is not None:
        raise StreamFileChanged
    if not baseline.matches(after_path) or not baseline.matches(
        after_opened, include_changed=False
    ):
        raise StreamFileChanged


def _advance_position(line: int, column: int, text: str) -> tuple[int, int]:
    newline_count = text.count("\n")
    if newline_count == 0:
        return line, column + len(text)
    return line + newline_count, len(text) - text.rfind("\n")


def read_scannable_detailed(
    path: str,
    max_size: int = DEFAULT_MAX_FILE_SIZE,
    checkpoint: Callable[[], None] | None = None,
    *,
    max_structured_size: int = DEFAULT_MAX_STRUCTURED_FILE_SIZE,
    max_extracted_chars: int = DEFAULT_MAX_EXTRACTED_CHARS,
    archive_depth: int = 2,
    extraction_timed_out: Callable[[], bool] | None = None,
) -> tuple[Scannable | None, FileIssue | None]:
    if checkpoint is not None:
        checkpoint()
    candidate = Path(path)
    metadata, issue = _regular_file_snapshot_no_follow(candidate, stage="extraction")
    if issue is not None:
        return None, issue
    assert metadata is not None
    size = metadata.st_size
    structured = is_structured_document(candidate)
    effective_limit = min(max_size, max_structured_size) if structured else max_size
    if size > effective_limit:
        code = "structured_file_too_large" if structured else "file_too_large"
        return None, FileIssue(
            code,
            "extraction",
            f"file exceeds max scan size ({size} > {effective_limit} bytes)",
        )
    raw = _read_regular_bytes_no_follow(
        candidate,
        effective_limit,
        validated_metadata=metadata,
    )
    if raw is None:
        return None, FileIssue("read_failed", "extraction", "file could not be read")
    if checkpoint is not None:
        checkpoint()

    suffix = candidate.suffix.lower()

    def extraction_checkpoint() -> None:
        if checkpoint is None:
            return
        try:
            checkpoint()
        except BaseException as error:
            raise _ExtractionControlSignal(error) from None

    def extraction_timeout_check() -> bool:
        if extraction_timed_out is None:
            return False
        try:
            return extraction_timed_out()
        except BaseException as error:
            raise _ExtractionControlSignal(error) from None

    try:
        doc = extract_document(
            suffix,
            raw,
            max_archive_depth=archive_depth,
            max_extracted_chars=max_extracted_chars,
            checkpoint=extraction_checkpoint if checkpoint is not None else None,
            extraction_timed_out=(
                extraction_timeout_check if extraction_timed_out is not None else None
            ),
        )
    except _ExtractionControlSignal as signal:
        raise signal.error from None
    except ArchiveSafetyError as error:
        return None, FileIssue("archive_limit", "extraction", str(error))
    except DocumentLimitExceeded as error:
        return None, FileIssue("document_limit", "extraction", str(error))
    except ExtractedTextLimitExceeded as error:
        return None, FileIssue("extracted_text_too_large", "extraction", str(error))
    except ExtractionTimedOut as error:
        return None, FileIssue("extraction_timeout", "extraction", str(error))
    except NoExtractableTextError as error:
        return None, FileIssue("no_extractable_text", "extraction", str(error))
    except ExtractionError as error:
        return None, FileIssue("document_extraction_failed", "extraction", str(error))
    except Exception:
        return None, FileIssue(
            "document_extraction_failed",
            "extraction",
            "document extraction failed unexpectedly",
        )
    if doc is not None:
        if len(doc.text) > max_extracted_chars:
            return None, FileIssue(
                "extracted_text_too_large",
                "extraction",
                f"extracted text exceeds the configured limit ({len(doc.text)} > "
                f"{max_extracted_chars} characters)",
            )
        if checkpoint is not None:
            checkpoint()
        return Scannable(text=doc.text, doc=doc), None

    decoded = decode_text(raw)
    if checkpoint is not None:
        checkpoint()
    if decoded is not None:
        return Scannable(text=decoded[0]), None

    reason = _unsupported_binary_reason(raw, suffix)
    if reason is not None:
        return None, FileIssue("unsupported_binary", "extraction", reason)
    if b"\x00" in raw[:BINARY_SNIFF_BYTES]:
        return None, FileIssue("binary_file", "extraction", "binary file (null byte detected)")
    return None, FileIssue(
        "unsupported_encoding",
        "extraction",
        "could not decode as text — unknown or unsupported encoding",
    )


def read_scannable(
    path: str,
    max_size: int = DEFAULT_MAX_FILE_SIZE,
    checkpoint: Callable[[], None] | None = None,
) -> tuple[Scannable | None, str | None]:
    """Compatibility wrapper returning the original string skip reason."""
    scannable, issue = read_scannable_detailed(path, max_size, checkpoint)
    return scannable, issue.reason if issue is not None else None


def _unsupported_binary_reason(raw: bytes, suffix: str = "") -> str | None:
    if raw.startswith(_OLE_MAGIC):
        if suffix == ".msg":
            return "Outlook .msg format isn't supported — save the email as .eml and rescan"
        return (
            "legacy Office format (.doc/.xls/.ppt) isn't supported — "
            "save it as .docx/.xlsx/.pptx and rescan"
        )
    if any(raw.startswith(magic) for magic in _IMAGE_MAGICS):
        return "image file — reading text in images needs OCR, which RedactLens doesn't include"
    if raw.startswith(_ZIP_MAGIC):
        return "archive — unpack it and scan the extracted folder instead"
    return None
