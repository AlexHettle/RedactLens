"""Atomic sibling-file writes used by remediation output generation."""

from __future__ import annotations

import hashlib
import os
import shutil
import stat
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

_HASH_CHUNK_BYTES = 1024 * 1024


class AtomicRollbackError(OSError):
    """A write failed and at least one committed target could not be restored.

    ``recovery_backups`` identifies backup files intentionally retained for
    manual recovery. Callers should surface this exception rather than retrying
    blindly: retrying could overwrite either the committed file or its backup.
    """

    def __init__(
        self,
        original_error: BaseException,
        rollback_errors: dict[Path, BaseException],
        recovery_backups: dict[Path, Path],
    ) -> None:
        self.original_error = original_error
        self.rollback_errors = rollback_errors
        self.recovery_backups = recovery_backups
        affected = ", ".join(str(path) for path in rollback_errors)
        backup_details = ", ".join(
            f"{target} -> {backup}" for target, backup in recovery_backups.items()
        )
        message = f"atomic write failed ({original_error}); rollback also failed for: {affected}"
        if backup_details:
            message += f"; recovery backups retained: {backup_details}"
        super().__init__(message)


class AtomicCleanupError(OSError):
    """Temporary artifacts could not be removed after an atomic write attempt.

    ``retained_artifacts`` maps each path that still exists to either
    ``"staging"`` or ``"backup"``. ``write_committed`` is true only when the
    whole write and its optional validation completed successfully; callers
    must not infer that a write was rolled back merely because cleanup failed.
    If the cleanup followed another failure, ``original_error`` preserves it.
    """

    def __init__(
        self,
        original_error: BaseException | None,
        cleanup_errors: dict[Path, BaseException],
        retained_artifacts: dict[Path, str],
        *,
        write_committed: bool,
    ) -> None:
        self.original_error = original_error
        self.cleanup_errors = cleanup_errors
        self.retained_artifacts = retained_artifacts
        self.write_committed = write_committed
        retained = ", ".join(f"{kind}: {path}" for path, kind in retained_artifacts.items())
        if write_committed:
            message = "atomic write committed, but temporary artifact cleanup failed"
        elif original_error is not None:
            message = f"atomic write failed ({original_error}); artifact cleanup also failed"
        else:
            message = "temporary artifact cleanup failed"
        if retained:
            message += f"; retained artifacts: {retained}"
        super().__init__(message)


class AtomicOutputChangedError(RuntimeError):
    """An explicitly allowed existing output changed before replacement."""

    def __init__(self, output_path: Path, phase: str) -> None:
        self.output_path = output_path
        self.phase = phase
        super().__init__(f"existing output changed during atomic write ({phase}): {output_path}")


@dataclass(frozen=True)
class AtomicFileSignature:
    """Stable content and entry identity for an existing output.

    Callers that authorize replacement should capture this signature before
    validating it against their own stored fingerprint, then pass the exact
    object to :func:`write_many_bytes_atomically`. The atomic transaction will
    reject a different entry or content instead of accepting a new baseline.
    """

    device: int
    inode: int
    size: int
    modified_ns: int
    changed_ns: int
    sha256: str

    @property
    def identity(self) -> tuple[int, int, int, int, int]:
        return (
            self.device,
            self.inode,
            self.size,
            self.modified_ns,
            self.changed_ns,
        )

    @property
    def content(self) -> tuple[int, int, str]:
        """Return the fields that must survive copying to a new entry."""

        return (self.size, self.modified_ns, self.sha256)


def _normalize_target(path: Path) -> Path:
    """Return a lexical absolute target without dereferencing any entry."""

    return Path(os.path.abspath(os.fspath(path)))


def _is_filesystem_redirect(path: Path, details: os.stat_result) -> bool:
    """Identify links and Windows reparse-point redirects without following them."""

    if stat.S_ISLNK(details.st_mode):
        return True
    is_junction = getattr(path, "is_junction", None)
    if callable(is_junction) and is_junction():
        return True
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    return bool(reparse_flag and getattr(details, "st_file_attributes", 0) & reparse_flag)


def _parent_chain(target: Path) -> list[Path]:
    """Return the target's ancestor directories from the anchor downward."""

    chain = [target.parent]
    while chain[-1] != chain[-1].parent:
        chain.append(chain[-1].parent)
    chain.reverse()
    return chain


def _assert_safe_parent(target: Path, *, create: bool) -> None:
    """Reject redirected ancestors and optionally create missing directories."""

    chain = _parent_chain(target)
    for directory in chain:
        try:
            details = directory.lstat()
        except FileNotFoundError:
            continue
        if _is_filesystem_redirect(directory, details):
            raise FileExistsError(f"output parent is a filesystem redirect: {directory}")
        if not stat.S_ISDIR(details.st_mode):
            raise NotADirectoryError(f"output parent is not a directory: {directory}")

    if create:
        target.parent.mkdir(parents=True, exist_ok=True)

    # Recheck after directory creation. This catches ordinary changes between
    # the first validation and mkdir; a malicious same-user process racing the
    # remaining OS calls stays inside the documented local-process boundary.
    for directory in chain:
        try:
            details = directory.lstat()
        except FileNotFoundError:
            if create:
                raise
            continue
        if _is_filesystem_redirect(directory, details):
            raise FileExistsError(f"output parent is a filesystem redirect: {directory}")
        if not stat.S_ISDIR(details.st_mode):
            raise NotADirectoryError(f"output parent is not a directory: {directory}")


def _entry_exists(path: Path) -> bool:
    """Return true for every directory entry, including dangling symlinks."""
    return os.path.lexists(path)


def _stat_signature(details: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        details.st_dev,
        details.st_ino,
        details.st_size,
        details.st_mtime_ns,
        details.st_ctime_ns,
    )


def _opened_file_signature(details: os.stat_result) -> tuple[int, int, int, int]:
    """Return fields represented consistently by path and handle stats on Windows."""

    return (
        details.st_dev,
        details.st_ino,
        details.st_size,
        details.st_mtime_ns,
    )


def _regular_file_signature(path: Path) -> tuple[int, int, int, int, int]:
    """Return a cheap identity/change signature without following symlinks."""
    _assert_safe_parent(path, create=False)
    details = path.lstat()
    if _is_filesystem_redirect(path, details):
        raise FileExistsError(f"output path is a filesystem redirect: {path}")
    if not stat.S_ISREG(details.st_mode):
        raise FileExistsError(f"output path is not a regular file: {path}")
    return _stat_signature(details)


def capture_file_signature(path: Path) -> AtomicFileSignature:
    """Hash a stable regular file without following filesystem redirects."""

    normalized = _normalize_target(path)
    before = _regular_file_signature(normalized)
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(normalized, flags)
    digest = hashlib.sha256()
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or _opened_file_signature(opened) != before[:4]:
            raise AtomicOutputChangedError(normalized, "signature_capture")
        while chunk := os.read(descriptor, _HASH_CHUNK_BYTES):
            digest.update(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)

    try:
        final = _regular_file_signature(normalized)
    except OSError as error:
        raise AtomicOutputChangedError(normalized, "signature_capture") from error
    if _opened_file_signature(after) != before[:4] or final != before:
        raise AtomicOutputChangedError(normalized, "signature_capture")
    return AtomicFileSignature(
        device=before[0],
        inode=before[1],
        size=before[2],
        modified_ns=before[3],
        changed_ns=before[4],
        sha256=digest.hexdigest(),
    )


def _assert_unchanged(
    path: Path,
    expected: tuple[int, int, int, int, int],
    *,
    phase: str,
) -> None:
    try:
        if not _entry_exists(path) or _regular_file_signature(path) != expected:
            raise AtomicOutputChangedError(path, phase)
    except AtomicOutputChangedError:
        raise
    except OSError as error:
        raise AtomicOutputChangedError(path, phase) from error


def _assert_expected_signature(
    path: Path,
    expected: AtomicFileSignature,
    *,
    phase: str,
) -> AtomicFileSignature:
    try:
        current = capture_file_signature(path)
    except (AtomicOutputChangedError, OSError) as error:
        raise AtomicOutputChangedError(path, phase) from error
    if current != expected:
        raise AtomicOutputChangedError(path, phase)
    return current


def _capture_expected_identity(
    path: Path,
    expected: tuple[int, int, int, int, int],
    *,
    phase: str,
) -> AtomicFileSignature:
    try:
        current = capture_file_signature(path)
    except (AtomicOutputChangedError, OSError) as error:
        raise AtomicOutputChangedError(path, phase) from error
    if current.identity != expected:
        raise AtomicOutputChangedError(path, phase)
    return current


def _signature_for_contents(path: Path, contents: bytes) -> AtomicFileSignature:
    """Combine the published entry identity with the bytes meant to be visible."""

    identity = _regular_file_signature(path)
    if identity[2] != len(contents):
        raise AtomicOutputChangedError(path, "after_publish")
    return AtomicFileSignature(
        device=identity[0],
        inode=identity[1],
        size=identity[2],
        modified_ns=identity[3],
        changed_ns=identity[4],
        sha256=hashlib.sha256(contents).hexdigest(),
    )


def _cleanup_artifact(path: Path) -> BaseException | None:
    """Remove an internal artifact, returning a persistent cleanup error."""

    try:
        _assert_safe_parent(path, create=False)
        path.unlink(missing_ok=True)
    except OSError as error:
        # An unlink implementation may report an error after removing the
        # entry. Only an artifact that remains (or cannot be checked) is a
        # persistent cleanup failure that callers need to recover from.
        try:
            retained = _entry_exists(path)
        except OSError:
            retained = True
        if retained:
            return error
    return None


def _raise_if_artifact_retained(
    path: Path,
    *,
    kind: str,
    original_error: BaseException,
) -> None:
    cleanup_error = _cleanup_artifact(path)
    if cleanup_error is not None:
        raise AtomicCleanupError(
            original_error,
            {path: cleanup_error},
            {path: kind},
            write_committed=False,
        ) from original_error


def _stage_bytes(target: Path, contents: bytes, *, label: str = "tmp") -> Path:
    _assert_safe_parent(target, create=True)
    descriptor, temporary_name = tempfile.mkstemp(
        dir=target.parent,
        prefix=f".{target.name}.",
        suffix=f".{label}",
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(contents)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException as error:
        _raise_if_artifact_retained(
            temporary,
            kind="staging",
            original_error=error,
        )
        raise
    return temporary


def _backup_file(
    target: Path,
    expected: tuple[int, int, int, int, int],
    *,
    strict_expected: AtomicFileSignature | None = None,
) -> tuple[Path, AtomicFileSignature, AtomicFileSignature]:
    """Copy metadata and bytes from a stable target to a sibling backup."""
    if strict_expected is not None:
        source_before = _assert_expected_signature(
            target,
            strict_expected,
            phase="before_backup",
        )
        if source_before.identity != expected:
            raise AtomicOutputChangedError(target, "before_backup")
    else:
        source_before = _capture_expected_identity(
            target,
            expected,
            phase="before_backup",
        )
    descriptor, backup_name = tempfile.mkstemp(
        dir=target.parent,
        prefix=f".{target.name}.",
        suffix=".backup",
    )
    os.close(descriptor)
    backup = Path(backup_name)
    try:
        # copy2 preserves st_mtime_ns. That timestamp is part of the API's
        # verified-output fingerprint and must survive a rollback.
        shutil.copy2(target, backup)
        with backup.open("rb+") as handle:
            os.fsync(handle.fileno())
        source_after = _assert_expected_signature(
            target,
            source_before,
            phase="during_backup",
        )
        backup_signature = capture_file_signature(backup)
        if backup_signature.content != source_after.content:
            raise OSError(f"backup did not preserve output metadata: {target}")
    except BaseException as error:
        _raise_if_artifact_retained(
            backup,
            kind="backup",
            original_error=error,
        )
        raise
    return backup, source_after, backup_signature


def write_many_bytes_atomically(
    outputs: dict[Path, bytes],
    *,
    replace_existing: bool = False,
    allowed_existing: set[Path] | None = None,
    expected_existing_signatures: dict[Path, AtomicFileSignature] | None = None,
    validate_committed: Callable[[], None] | None = None,
) -> None:
    """Stage and publish a batch, rolling it back on commit or validation failure.

    New targets are published with a same-directory hard link, which provides
    create-if-absent semantics on supported filesystems and cannot silently
    overwrite an entry introduced by a race. Existing regular files are only
    replaced when explicitly trusted by the caller, and sibling backups remain
    available until optional post-commit validation succeeds.

    ``expected_existing_signatures`` is the strict replacement API. Its keys
    are the only replaceable destinations, and every file must still match the
    exact signature captured and validated by the caller. ``allowed_existing``
    retains the legacy behavior of establishing a baseline at atomic entry.

    If rollback restoration itself fails, :class:`AtomicRollbackError` exposes
    the rollback errors and retains any usable backup paths for recovery.
    :class:`AtomicCleanupError` reports staging or backup artifacts that could
    not be removed, including whether the requested write was fully committed.
    """
    if not outputs:
        return

    normalized = {_normalize_target(path): contents for path, contents in outputs.items()}
    if len(normalized) != len(outputs):
        raise ValueError("duplicate output paths are not allowed")
    if replace_existing and (
        allowed_existing is not None or expected_existing_signatures is not None
    ):
        raise ValueError(
            "choose replace_existing, allowed_existing, or expected_existing_signatures"
        )
    if allowed_existing is not None and expected_existing_signatures is not None:
        raise ValueError("choose allowed_existing or expected_existing_signatures, not both")
    strict_expected = {
        _normalize_target(path): signature
        for path, signature in (expected_existing_signatures or {}).items()
    }
    if expected_existing_signatures is not None and len(strict_expected) != len(
        expected_existing_signatures
    ):
        raise ValueError("duplicate expected-existing paths are not allowed")
    if any(
        not isinstance(signature, AtomicFileSignature) for signature in strict_expected.values()
    ):
        raise TypeError("expected existing signatures must be AtomicFileSignature values")
    unknown_expected = set(strict_expected) - set(normalized)
    if unknown_expected:
        raise ValueError("expected-existing paths must also be output paths")
    replaceable = (
        set(normalized)
        if replace_existing
        else (
            set(strict_expected)
            if expected_existing_signatures is not None
            else {_normalize_target(path) for path in (allowed_existing or set())}
        )
    )

    for path in normalized:
        _assert_safe_parent(path, create=False)

    originals: dict[Path, tuple[int, int, int, int, int]] = {}
    for path in normalized:
        if path in strict_expected:
            current = _assert_expected_signature(
                path,
                strict_expected[path],
                phase="at_entry",
            )
            originals[path] = current.identity
            continue
        if not _entry_exists(path):
            continue
        if path not in replaceable:
            raise FileExistsError(f"output already exists: {path}")
        originals[path] = _regular_file_signature(path)

    staged: dict[Path, Path] = {}
    backups: dict[Path, Path] = {}
    original_signatures: dict[Path, AtomicFileSignature] = {}
    backup_signatures: dict[Path, AtomicFileSignature] = {}
    committed: list[Path] = []
    committed_signatures: dict[Path, AtomicFileSignature] = {}
    restored_signatures: dict[Path, AtomicFileSignature] = {}
    preserved_backups: set[Path] = set()
    operation_error: BaseException | None = None
    write_committed = False
    try:
        for target, contents in normalized.items():
            staged[target] = _stage_bytes(target, contents)

        # Recheck after all staging. A path that appeared after the initial
        # snapshot is a collision even if its name was in allowed_existing.
        for target in normalized:
            original = originals.get(target)
            if original is None:
                if _entry_exists(target):
                    raise FileExistsError(f"output already exists: {target}")
                continue
            strict_signature = strict_expected.get(target)
            if strict_signature is not None:
                _assert_expected_signature(
                    target,
                    strict_signature,
                    phase="after_staging",
                )
            else:
                _assert_unchanged(target, original, phase="after_staging")

        for target, original in originals.items():
            backup, current, backup_signature = _backup_file(
                target,
                original,
                strict_expected=strict_expected.get(target),
            )
            backups[target] = backup
            original_signatures[target] = current
            backup_signatures[target] = backup_signature
            originals[target] = current.identity

        for target, temporary in staged.items():
            if target in originals:
                if target in strict_expected:
                    _assert_expected_signature(
                        target,
                        original_signatures[target],
                        phase="before_replace",
                    )
                else:
                    _assert_unchanged(
                        target,
                        originals[target],
                        phase="before_replace",
                    )
                os.replace(temporary, target)
                committed.append(target)
                committed_signature = _signature_for_contents(
                    target,
                    normalized[target],
                )
                committed_signatures[target] = committed_signature
                _assert_expected_signature(
                    target,
                    committed_signature,
                    phase="after_publish",
                )
            else:
                # Unlike os.replace/os.rename, hard-link creation never
                # overwrites a final entry that appears between checks.
                try:
                    _assert_safe_parent(target, create=False)
                    os.link(temporary, target)
                except OSError as error:
                    if _entry_exists(target):
                        raise FileExistsError(f"output already exists: {target}") from error
                    raise
                # Publication has succeeded at this point. Record it before
                # unlinking the staging name so even a cleanup failure rolls
                # the newly visible target back.
                committed.append(target)
                try:
                    temporary.unlink()
                except BaseException:
                    # The create-if-absent link established ownership of this
                    # new entry. Preserve its exact visible signature so a
                    # rollback may remove it only while it remains unchanged.
                    committed_signatures[target] = capture_file_signature(target)
                    raise
                committed_signature = capture_file_signature(target)
                committed_signatures[target] = committed_signature
                if (
                    committed_signature.size != len(normalized[target])
                    or committed_signature.sha256 != hashlib.sha256(normalized[target]).hexdigest()
                ):
                    raise ValueError(f"published output differs from staged contents: {target}")
                continue

        if validate_committed is not None:
            validate_committed()
        write_committed = True
    except BaseException as error:
        rollback_errors: dict[Path, BaseException] = {}
        recovery_backups: dict[Path, Path] = {}
        for target in reversed(committed):
            backup = backups.get(target)
            try:
                _assert_safe_parent(target, create=False)
                committed_signature = committed_signatures.get(target)
                if committed_signature is None:
                    raise AtomicOutputChangedError(target, "during_rollback")
                _assert_expected_signature(
                    target,
                    committed_signature,
                    phase="during_rollback",
                )
                if backup is not None:
                    if not _entry_exists(backup):
                        raise FileNotFoundError(
                            f"recovery backup disappeared during rollback: {backup}"
                        )
                    expected_backup = backup_signatures.get(target)
                    if expected_backup is None:
                        raise FileNotFoundError(
                            f"recovery backup was not verified for rollback: {backup}"
                        )
                    _assert_expected_signature(
                        backup,
                        expected_backup,
                        phase="before_restore",
                    )
                    os.replace(backup, target)
                    restored = capture_file_signature(target)
                    if restored.content != original_signatures[target].content:
                        raise OSError(
                            f"rollback did not restore output content and metadata: {target}"
                        )
                    restored_signatures[target] = restored
                else:
                    target.unlink()
            except BaseException as rollback_error:
                rollback_errors[target] = rollback_error
                if backup is not None and _entry_exists(backup):
                    recovery_backups[target] = backup
                    preserved_backups.add(backup)
        if rollback_errors:
            operation_error = AtomicRollbackError(
                error,
                rollback_errors,
                recovery_backups,
            )
        else:
            operation_error = error

    cleanup_errors: dict[Path, BaseException] = {}
    retained_artifacts: dict[Path, str] = {}
    cleanup_candidates = [(path, "staging") for path in staged.values()]
    cleanup_candidates.extend(
        (path, "backup") for path in backups.values() if path not in preserved_backups
    )
    for artifact, kind in cleanup_candidates:
        cleanup_error = _cleanup_artifact(artifact)
        if cleanup_error is not None:
            cleanup_errors[artifact] = cleanup_error
            retained_artifacts[artifact] = kind

    if cleanup_errors:
        cleanup_failure = AtomicCleanupError(
            operation_error,
            cleanup_errors,
            retained_artifacts,
            write_committed=write_committed,
        )
        cleanup_failure.restored_signatures = restored_signatures
        if operation_error is not None:
            raise cleanup_failure from operation_error
        raise cleanup_failure
    if isinstance(operation_error, AtomicRollbackError):
        operation_error.restored_signatures = restored_signatures
        raise operation_error from operation_error.original_error
    if operation_error is not None:
        operation_error.restored_signatures = restored_signatures
        raise operation_error


def write_bytes_atomically(
    output_path: Path,
    contents: bytes,
    *,
    replace_existing: bool = False,
    expected_existing_signature: AtomicFileSignature | None = None,
    validate_committed: Callable[[], None] | None = None,
) -> None:
    write_many_bytes_atomically(
        {output_path: contents},
        replace_existing=replace_existing,
        expected_existing_signatures=(
            {output_path: expected_existing_signature}
            if expected_existing_signature is not None
            else None
        ),
        validate_committed=validate_committed,
    )
