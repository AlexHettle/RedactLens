"""Trusted filesystem access and retained file state for API scan sessions."""

from __future__ import annotations

import hashlib
import os
import stat
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Literal, Protocol

from redactlens_core.files import DiscoveredFile, is_structured_document, regular_file_issue
from redactlens_core.models import ScanOptions
from redactlens_core.output_paths import redacted_copy_path

from .session_errors import SessionProblem

_HASH_CHUNK_BYTES = 1024 * 1024


def _absolute_path_no_follow(file_path: str) -> str:
    """Normalize presentation without dereferencing a selected filesystem link."""

    return os.path.abspath(file_path)


def _filesystem_entry_may_exist(file_path: str | Path) -> bool:
    """Return false only when a directory entry's absence can be confirmed."""

    try:
        os.lstat(file_path)
    except FileNotFoundError:
        return False
    except OSError:
        return True
    return True


def _redacted_output_path_no_follow(source_path: str) -> Path:
    return redacted_copy_path(_absolute_path_no_follow(source_path))


def _same_entry(left: os.stat_result, right: os.stat_result) -> bool:
    return (left.st_dev, left.st_ino) == (right.st_dev, right.st_ino)


def _same_opened_snapshot(left: os.stat_result, right: os.stat_result) -> bool:
    """Compare fields represented consistently by path and handles on Windows."""

    return _same_entry(left, right) and (left.st_size, left.st_mtime_ns) == (
        right.st_size,
        right.st_mtime_ns,
    )


@dataclass(frozen=True)
class FileFingerprint:
    resolved_path: str
    device: int
    inode: int
    size: int
    modified_ns: int
    changed_ns: int
    sha256: str

    @classmethod
    def capture(
        cls,
        file_path: str,
        checkpoint: Callable[[], None] | None = None,
    ) -> FileFingerprint:
        path = Path(_absolute_path_no_follow(file_path))
        if checkpoint is not None:
            checkpoint()
        _assert_no_redirect_ancestors(path)
        issue = regular_file_issue(path, stage="verification")
        if issue is not None:
            raise OSError(issue.reason)
        before = path.lstat()
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        digest = hashlib.sha256()
        try:
            opened = os.fstat(descriptor)
            if not stat.S_ISREG(opened.st_mode) or not _same_opened_snapshot(before, opened):
                raise OSError("file changed before it could be opened")
            while chunk := os.read(descriptor, _HASH_CHUNK_BYTES):
                if checkpoint is not None:
                    checkpoint()
                digest.update(chunk)
            if checkpoint is not None:
                checkpoint()
            after = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        try:
            final_entry = path.lstat()
            _assert_no_redirect_ancestors(path)
            final_is_redirect = _is_filesystem_redirect(path, final_entry)
        except OSError as error:
            raise SessionProblem(
                "file_changed",
                "A source changed while RedactLens was recording the scan; scan it again.",
                409,
            ) from error
        if (
            final_is_redirect
            or not stat.S_ISREG(final_entry.st_mode)
            or (
                before.st_dev,
                before.st_ino,
                before.st_size,
                before.st_mtime_ns,
                before.st_ctime_ns,
            )
            != (
                final_entry.st_dev,
                final_entry.st_ino,
                final_entry.st_size,
                final_entry.st_mtime_ns,
                final_entry.st_ctime_ns,
            )
            or not _same_opened_snapshot(opened, after)
            or not _same_opened_snapshot(after, final_entry)
        ):
            raise SessionProblem(
                "file_changed",
                "A source changed while RedactLens was recording the scan; scan it again.",
                409,
            )
        return cls(
            resolved_path=str(path),
            device=final_entry.st_dev,
            inode=final_entry.st_ino,
            size=final_entry.st_size,
            modified_ns=final_entry.st_mtime_ns,
            changed_ns=final_entry.st_ctime_ns,
            sha256=digest.hexdigest(),
        )


def _matches_fingerprint_snapshot(
    expected: FileFingerprint,
    details: os.stat_result,
    *,
    include_changed: bool,
) -> bool:
    if (
        expected.device,
        expected.inode,
        expected.size,
        expected.modified_ns,
    ) != (
        details.st_dev,
        details.st_ino,
        details.st_size,
        details.st_mtime_ns,
    ):
        return False
    return not include_changed or expected.changed_ns == details.st_ctime_ns


def _is_filesystem_redirect(path: Path, details: os.stat_result) -> bool:
    if stat.S_ISLNK(details.st_mode):
        return True
    is_junction = getattr(path, "is_junction", None)
    if callable(is_junction) and is_junction():
        return True
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    return bool(reparse_flag and getattr(details, "st_file_attributes", 0) & reparse_flag)


def _assert_no_redirect_ancestors(path: Path) -> None:
    """Reject links, reparse points, and non-directories above one file path."""

    current = path.parent
    ancestors = [current]
    while current != current.parent:
        current = current.parent
        ancestors.append(current)
    for directory in reversed(ancestors):
        try:
            details = directory.lstat()
        except OSError as error:
            raise OSError("file parent metadata is unavailable") from error
        if _is_filesystem_redirect(directory, details):
            raise OSError("file parent is a filesystem redirect")
        if not stat.S_ISDIR(details.st_mode):
            raise OSError("file parent is not a directory")


def _read_regular_bytes_no_follow(
    file_path: str | Path,
    *,
    max_bytes: int | None = None,
    expected_fingerprint: FileFingerprint | None = None,
) -> bytes:
    """Read a stable regular file without accepting redirect entries."""

    path = Path(_absolute_path_no_follow(os.fspath(file_path)))
    _assert_no_redirect_ancestors(path)
    issue = regular_file_issue(path, stage="verification")
    if issue is not None:
        raise OSError(issue.reason)
    before = path.lstat()
    if expected_fingerprint is not None:
        if not _matches_fingerprint_snapshot(
            expected_fingerprint,
            before,
            include_changed=True,
        ):
            raise OSError("file changed before it could be read")
        if max_bytes is None:
            max_bytes = expected_fingerprint.size
    if expected_fingerprint is not None and max_bytes is not None and before.st_size > max_bytes:
        raise OSError("file exceeds the configured read limit")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    chunks: list[bytes] = []
    digest = hashlib.sha256() if expected_fingerprint is not None else None
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or not _same_opened_snapshot(before, opened):
            raise OSError("file changed before it could be opened")
        remaining = max_bytes
        while remaining is None or remaining > 0:
            chunk = os.read(
                descriptor,
                _HASH_CHUNK_BYTES if remaining is None else min(_HASH_CHUNK_BYTES, remaining),
            )
            if not chunk:
                break
            chunks.append(chunk)
            if digest is not None:
                digest.update(chunk)
            if remaining is not None:
                remaining -= len(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    final_entry = path.lstat()
    _assert_no_redirect_ancestors(path)
    if (
        _is_filesystem_redirect(path, final_entry)
        or not stat.S_ISREG(final_entry.st_mode)
        or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
        != (
            final_entry.st_dev,
            final_entry.st_ino,
            final_entry.st_size,
            final_entry.st_mtime_ns,
            final_entry.st_ctime_ns,
        )
        or not _same_opened_snapshot(opened, after)
        or not _same_opened_snapshot(after, final_entry)
    ):
        raise OSError("file changed while it was being read")
    if expected_fingerprint is not None and (
        not _matches_fingerprint_snapshot(
            expected_fingerprint,
            final_entry,
            include_changed=True,
        )
        or digest is None
        or digest.hexdigest() != expected_fingerprint.sha256
    ):
        raise OSError("file content no longer matches the retained fingerprint")
    return b"".join(chunks)


@dataclass(frozen=True)
class GeneratedOutput:
    output_path: str
    finding_ids: tuple[str, ...]
    created_at: datetime
    verification_status: Literal["verified"]
    warnings: tuple[str, ...]
    source_fingerprint: FileFingerprint
    output_fingerprint: FileFingerprint
    rescan_status: Literal["completed", "failed"]
    remaining_finding_count: int | None
    remaining_tier_a_count: int | None


class _FingerprintSession(Protocol):
    file_fingerprints: dict[str, FileFingerprint]


def verify_source_files_locked(
    session: _FingerprintSession,
    file_paths: list[str],
    *,
    before_action: str,
) -> None:
    """Validate retained fingerprints while the caller holds the workflow lock."""

    for file_path in dict.fromkeys(file_paths):
        expected = session.file_fingerprints.get(file_path)
        if expected is None:
            raise SessionProblem(
                "file_unavailable",
                "A source file is no longer available from this scan.",
                410,
            )
        try:
            current = FileFingerprint.capture(file_path)
        except SessionProblem:
            raise
        except OSError as error:
            raise SessionProblem(
                "file_unavailable",
                "A source file is no longer available.",
                410,
            ) from error
        if current != expected:
            raise SessionProblem(
                "file_changed",
                f"A source file changed after the scan. Scan it again before {before_action}.",
                409,
            )


def capture_scan_input_fingerprints(
    paths: list[str],
    *,
    checkpoint: Callable[[], None] | None,
    options: ScanOptions | None,
    discover: Callable[..., Iterable[DiscoveredFile]],
) -> dict[str, FileFingerprint]:
    """Hash eligible inputs before scanning to detect mid-scan changes."""

    active_options = options or ScanOptions()
    fingerprints: dict[str, FileFingerprint] = {}
    for entry in discover(paths, active_options, checkpoint=checkpoint):
        if checkpoint is not None:
            checkpoint()
        if entry.issue is not None:
            continue
        file_path = entry.path
        try:
            if regular_file_issue(file_path, stage="verification") is not None:
                continue
            size = Path(file_path).lstat().st_size
            if size > active_options.max_file_size:
                continue
            if is_structured_document(file_path) and size > min(
                active_options.max_file_size,
                active_options.max_structured_file_size,
            ):
                continue
            fingerprint = FileFingerprint.capture(file_path, checkpoint=checkpoint)
        except (OSError, SessionProblem):
            # The scanner will report unavailable, oversized, or unstable
            # inputs through its normal skipped-file/result behavior.
            continue
        fingerprints[fingerprint.resolved_path] = fingerprint
    return fingerprints
