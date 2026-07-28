import os
from pathlib import Path

import pytest
from redactlens_core import atomic


def test_staging_failure_leaves_no_partial_final_outputs(monkeypatch, tmp_path):
    first = tmp_path / "first.redacted"
    second = tmp_path / "second.redacted"
    real_stage = atomic._stage_bytes
    calls = 0

    def fail_second_stage(target: Path, contents: bytes, *, label: str = "tmp") -> Path:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("simulated temporary write failure")
        return real_stage(target, contents, label=label)

    monkeypatch.setattr(atomic, "_stage_bytes", fail_second_stage)

    with pytest.raises(OSError, match="temporary write failure"):
        atomic.write_many_bytes_atomically({first: b"first", second: b"second"})

    assert not first.exists()
    assert not second.exists()
    assert list(tmp_path.glob(".*.tmp")) == []


def test_commit_failure_rolls_back_already_committed_outputs(monkeypatch, tmp_path):
    first = tmp_path / "first.redacted"
    second = tmp_path / "second.redacted"
    real_link = atomic.os.link
    failed = False

    def fail_second_commit(source, target):
        nonlocal failed
        if Path(target) == second and not failed:
            failed = True
            raise OSError("simulated publication failure")
        return real_link(source, target)

    monkeypatch.setattr(atomic.os, "link", fail_second_commit)

    with pytest.raises(OSError, match="publication failure"):
        atomic.write_many_bytes_atomically({first: b"first", second: b"second"})

    assert not first.exists()
    assert not second.exists()


def test_staging_name_cleanup_failure_rolls_back_published_output(monkeypatch, tmp_path):
    output = tmp_path / "output.redacted"
    real_unlink = Path.unlink
    failed = False

    def fail_first_staging_unlink(path, *args, **kwargs):
        nonlocal failed
        if path.name.endswith(".tmp") and not failed:
            failed = True
            raise OSError("simulated staging cleanup failure")
        return real_unlink(path, *args, **kwargs)

    monkeypatch.setattr(Path, "unlink", fail_first_staging_unlink)

    with pytest.raises(OSError, match="staging cleanup failure"):
        atomic.write_many_bytes_atomically({output: b"private"})

    assert not output.exists()
    assert list(tmp_path.glob(".*.tmp")) == []


def test_persistent_staging_cleanup_failure_reports_retained_artifact(
    monkeypatch,
    tmp_path,
):
    output = tmp_path / "output.redacted"
    real_unlink = Path.unlink

    def refuse_staging_cleanup(path, *args, **kwargs):
        if path.name.endswith(".tmp"):
            raise OSError("staging file is locked")
        return real_unlink(path, *args, **kwargs)

    monkeypatch.setattr(Path, "unlink", refuse_staging_cleanup)

    with pytest.raises(atomic.AtomicCleanupError) as caught:
        atomic.write_many_bytes_atomically({output: b"private"})

    error = caught.value
    assert not error.write_committed
    assert isinstance(error.original_error, OSError)
    assert len(error.retained_artifacts) == 1
    staging = next(iter(error.retained_artifacts))
    assert error.retained_artifacts[staging] == "staging"
    assert staging.exists()
    assert not output.exists()


def test_failed_regeneration_restores_the_previous_complete_output(monkeypatch, tmp_path):
    first = tmp_path / "first.redacted"
    second = tmp_path / "second.redacted"
    first.write_bytes(b"previous first")
    second.write_bytes(b"previous second")
    real_replace = atomic.os.replace
    failed = False

    def fail_second_commit(source, target):
        nonlocal failed
        if Path(target) == second and str(source).endswith(".tmp") and not failed:
            failed = True
            raise OSError("simulated regeneration failure")
        return real_replace(source, target)

    monkeypatch.setattr(atomic.os, "replace", fail_second_commit)

    with pytest.raises(OSError, match="regeneration failure"):
        atomic.write_many_bytes_atomically(
            {first: b"new first", second: b"new second"},
            allowed_existing={first, second},
        )

    assert first.read_bytes() == b"previous first"
    assert second.read_bytes() == b"previous second"


def test_failed_regeneration_restores_previous_mtime(tmp_path):
    output = tmp_path / "output.redacted"
    output.write_bytes(b"previous")
    restored_timestamp = 1_650_000_000_123_456_700
    os.utime(output, ns=(restored_timestamp, restored_timestamp))
    original_mtime = output.stat().st_mtime_ns

    def reject() -> None:
        raise ValueError("verification failed")

    with pytest.raises(ValueError, match="verification failed"):
        atomic.write_many_bytes_atomically(
            {output: b"replacement"},
            allowed_existing={output},
            validate_committed=reject,
        )

    assert output.read_bytes() == b"previous"
    assert output.stat().st_mtime_ns == original_mtime


def test_existing_output_change_after_staging_has_dedicated_error(
    monkeypatch,
    tmp_path,
):
    output = tmp_path / "output.redacted"
    output.write_bytes(b"previous")
    expected = atomic.capture_file_signature(output)
    real_stage = atomic._stage_bytes

    def mutate_after_staging(target, contents, *, label="tmp"):
        staged = real_stage(target, contents, label=label)
        output.write_bytes(b"external")
        os.utime(output, ns=(expected.modified_ns, expected.modified_ns))
        return staged

    monkeypatch.setattr(atomic, "_stage_bytes", mutate_after_staging)

    with pytest.raises(atomic.AtomicOutputChangedError) as caught:
        atomic.write_many_bytes_atomically(
            {output: b"replacement"},
            expected_existing_signatures={output: expected},
        )

    assert caught.value.output_path == output
    assert caught.value.phase == "after_staging"
    assert output.read_bytes() == b"external"
    assert list(tmp_path.glob(".*.tmp")) == []


def test_existing_output_change_during_backup_has_dedicated_error(
    monkeypatch,
    tmp_path,
):
    output = tmp_path / "output.redacted"
    output.write_bytes(b"previous")
    expected = atomic.capture_file_signature(output)
    real_copy = atomic.shutil.copy2

    def mutate_during_backup(source, destination, *args, **kwargs):
        result = real_copy(source, destination, *args, **kwargs)
        output.write_bytes(b"external")
        os.utime(output, ns=(expected.modified_ns, expected.modified_ns))
        return result

    monkeypatch.setattr(atomic.shutil, "copy2", mutate_during_backup)

    with pytest.raises(atomic.AtomicOutputChangedError) as caught:
        atomic.write_many_bytes_atomically(
            {output: b"replacement"},
            expected_existing_signatures={output: expected},
        )

    assert caught.value.output_path == output
    assert caught.value.phase == "during_backup"
    assert output.read_bytes() == b"external"
    assert list(tmp_path.glob(".*.backup")) == []


def test_existing_output_change_before_replace_has_dedicated_error(
    monkeypatch,
    tmp_path,
):
    output = tmp_path / "output.redacted"
    output.write_bytes(b"previous")
    expected = atomic.capture_file_signature(output)
    real_backup = atomic._backup_file

    def mutate_after_backup(target, identity, *, strict_expected=None):
        result = real_backup(
            target,
            identity,
            strict_expected=strict_expected,
        )
        output.write_bytes(b"external")
        os.utime(output, ns=(expected.modified_ns, expected.modified_ns))
        return result

    monkeypatch.setattr(atomic, "_backup_file", mutate_after_backup)

    with pytest.raises(atomic.AtomicOutputChangedError) as caught:
        atomic.write_many_bytes_atomically(
            {output: b"replacement"},
            expected_existing_signatures={output: expected},
        )

    assert caught.value.output_path == output
    assert caught.value.phase == "before_replace"
    assert output.read_bytes() == b"external"
    assert list(tmp_path.glob(".*.backup")) == []


def test_backup_content_change_with_restored_mtime_is_rejected(monkeypatch, tmp_path):
    output = tmp_path / "output.redacted"
    output.write_bytes(b"previous")
    expected = atomic.capture_file_signature(output)
    real_copy = atomic.shutil.copy2

    def corrupt_backup(source, destination, *args, **kwargs):
        result = real_copy(source, destination, *args, **kwargs)
        backup = Path(destination)
        backup.write_bytes(b"external")
        os.utime(backup, ns=(expected.modified_ns, expected.modified_ns))
        return result

    monkeypatch.setattr(atomic.shutil, "copy2", corrupt_backup)

    with pytest.raises(OSError, match="backup did not preserve"):
        atomic.write_many_bytes_atomically(
            {output: b"rendered"},
            expected_existing_signatures={output: expected},
        )

    assert output.read_bytes() == b"previous"
    assert list(tmp_path.glob(".*.backup")) == []


def test_expected_existing_signature_rejects_change_before_atomic_entry(tmp_path):
    output = tmp_path / "output.redacted"
    output.write_bytes(b"previous")
    expected = atomic.capture_file_signature(output)

    # Preserve the fingerprint's cheap size/mtime fields. The content digest
    # in AtomicFileSignature must still prevent this new baseline from being
    # trusted at atomic entry.
    output.write_bytes(b"external")
    os.utime(output, ns=(expected.modified_ns, expected.modified_ns))

    with pytest.raises(atomic.AtomicOutputChangedError) as caught:
        atomic.write_many_bytes_atomically(
            {output: b"replacement"},
            expected_existing_signatures={output: expected},
        )

    assert caught.value.output_path == output
    assert caught.value.phase == "at_entry"
    assert output.read_bytes() == b"external"
    assert list(tmp_path.glob(".*.tmp")) == []
    assert list(tmp_path.glob(".*.backup")) == []


def test_expected_existing_signature_rejects_disappearance_before_entry(tmp_path):
    output = tmp_path / "output.redacted"
    output.write_bytes(b"previous")
    expected = atomic.capture_file_signature(output)
    output.unlink()

    with pytest.raises(atomic.AtomicOutputChangedError) as caught:
        atomic.write_many_bytes_atomically(
            {output: b"replacement"},
            expected_existing_signatures={output: expected},
        )

    assert caught.value.phase == "at_entry"
    assert not output.exists()


def test_dangling_symlink_is_a_collision(tmp_path):
    output = tmp_path / "output.redacted"
    missing = tmp_path / "missing-target"
    try:
        output.symlink_to(missing)
    except OSError as error:
        pytest.skip(f"symlinks are unavailable in this environment: {error}")

    with pytest.raises(FileExistsError, match="already exists"):
        atomic.write_many_bytes_atomically({output: b"private"})

    assert output.is_symlink()
    assert not missing.exists()


def test_allowed_dangling_symlink_is_never_replaced(tmp_path):
    output = tmp_path / "output.redacted"
    missing = tmp_path / "missing-target"
    try:
        output.symlink_to(missing)
    except OSError as error:
        pytest.skip(f"symlinks are unavailable in this environment: {error}")

    with pytest.raises(FileExistsError, match="filesystem redirect"):
        atomic.write_many_bytes_atomically(
            {output: b"private"},
            allowed_existing={output},
        )

    assert output.is_symlink()
    assert not missing.exists()


def test_redirected_output_parent_is_rejected_without_writing_target(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    redirected = tmp_path / "redirected"
    try:
        redirected.symlink_to(outside, target_is_directory=True)
    except OSError as error:
        pytest.skip(f"directory symlinks are unavailable in this environment: {error}")

    with pytest.raises(FileExistsError, match="filesystem redirect"):
        atomic.write_many_bytes_atomically({redirected / "private.redacted": b"private"})

    assert not (outside / "private.redacted").exists()


def test_detected_junction_parent_is_rejected_before_staging(monkeypatch, tmp_path):
    redirected = tmp_path / "redirected"
    redirected.mkdir()
    output = redirected / "private.redacted"
    real_is_junction = getattr(Path, "is_junction", None)

    def fake_is_junction(path):
        if path == redirected:
            return True
        return real_is_junction(path) if real_is_junction is not None else False

    monkeypatch.setattr(Path, "is_junction", fake_is_junction, raising=False)

    with pytest.raises(FileExistsError, match="filesystem redirect"):
        atomic.write_many_bytes_atomically({output: b"private"})

    assert not output.exists()


def test_detected_reparse_output_is_never_replaced(monkeypatch, tmp_path):
    output = tmp_path / "private.redacted"
    output.write_bytes(b"outside data")
    real_is_junction = getattr(Path, "is_junction", None)

    def fake_is_junction(path):
        if path == output:
            return True
        return real_is_junction(path) if real_is_junction is not None else False

    monkeypatch.setattr(Path, "is_junction", fake_is_junction, raising=False)

    with pytest.raises(FileExistsError, match="filesystem redirect"):
        atomic.write_many_bytes_atomically(
            {output: b"private"},
            allowed_existing={output},
        )

    assert output.read_bytes() == b"outside data"


def test_atomic_target_normalization_never_resolves_filesystem_entries(monkeypatch, tmp_path):
    output = tmp_path / "private.redacted"

    def forbidden_resolve(_path, *_args, **_kwargs):
        raise AssertionError("atomic target normalization must not dereference paths")

    monkeypatch.setattr(Path, "resolve", forbidden_resolve)

    atomic.write_many_bytes_atomically({output: b"private"})

    assert output.read_bytes() == b"private"


def test_lexical_output_aliases_are_rejected(tmp_path):
    output = tmp_path / "private.redacted"
    alias = tmp_path / "unused" / ".." / output.name

    with pytest.raises(ValueError, match="duplicate output paths"):
        atomic.write_many_bytes_atomically({output: b"first", alias: b"second"})

    assert not output.exists()


def test_entry_created_during_publish_is_not_overwritten(monkeypatch, tmp_path):
    output = tmp_path / "output.redacted"
    real_link = atomic.os.link
    raced = False

    def create_collision_before_publish(source, target):
        nonlocal raced
        if not raced:
            raced = True
            Path(target).write_bytes(b"other process")
        return real_link(source, target)

    monkeypatch.setattr(atomic.os, "link", create_collision_before_publish)

    with pytest.raises(FileExistsError, match="already exists"):
        atomic.write_many_bytes_atomically({output: b"private"})

    assert output.read_bytes() == b"other process"


def test_post_commit_validation_runs_before_backup_cleanup(tmp_path):
    output = tmp_path / "output.redacted"
    output.write_bytes(b"previous")
    observed_backups: list[Path] = []

    def validate() -> None:
        assert output.read_bytes() == b"replacement"
        observed_backups.extend(tmp_path.glob(".*.backup"))

    atomic.write_many_bytes_atomically(
        {output: b"replacement"},
        allowed_existing={output},
        validate_committed=validate,
    )

    assert observed_backups
    assert output.read_bytes() == b"replacement"
    assert list(tmp_path.glob(".*.backup")) == []


def test_persistent_backup_cleanup_failure_reports_committed_write(
    monkeypatch,
    tmp_path,
):
    output = tmp_path / "output.redacted"
    output.write_bytes(b"previous")
    real_unlink = Path.unlink

    def refuse_backup_cleanup(path, *args, **kwargs):
        if path.name.endswith(".backup"):
            raise OSError("backup file is locked")
        return real_unlink(path, *args, **kwargs)

    monkeypatch.setattr(Path, "unlink", refuse_backup_cleanup)

    with pytest.raises(atomic.AtomicCleanupError) as caught:
        atomic.write_many_bytes_atomically(
            {output: b"replacement"},
            allowed_existing={output},
        )

    error = caught.value
    assert error.write_committed
    assert error.original_error is None
    assert len(error.retained_artifacts) == 1
    backup = next(iter(error.retained_artifacts))
    assert error.retained_artifacts[backup] == "backup"
    assert backup.exists()
    assert backup.read_bytes() == b"previous"
    assert output.read_bytes() == b"replacement"


def test_post_commit_validation_failure_rolls_back_entire_batch(tmp_path):
    existing = tmp_path / "existing.redacted"
    created = tmp_path / "created.redacted"
    existing.write_bytes(b"previous")

    def reject() -> None:
        assert existing.read_bytes() == b"replacement"
        assert created.read_bytes() == b"created"
        raise ValueError("verification failed")

    with pytest.raises(ValueError, match="verification failed"):
        atomic.write_many_bytes_atomically(
            {existing: b"replacement", created: b"created"},
            allowed_existing={existing},
            validate_committed=reject,
        )

    assert existing.read_bytes() == b"previous"
    assert not created.exists()
    assert list(tmp_path.glob(".*.backup")) == []


def test_rollback_does_not_overwrite_same_metadata_external_edit(tmp_path):
    output = tmp_path / "output.redacted"
    output.write_bytes(b"previous")
    expected = atomic.capture_file_signature(output)

    def change_then_reject() -> None:
        published = atomic.capture_file_signature(output)
        output.write_bytes(b"external")
        os.utime(output, ns=(published.modified_ns, published.modified_ns))
        raise ValueError("verification failed")

    with pytest.raises(atomic.AtomicRollbackError) as caught:
        atomic.write_many_bytes_atomically(
            {output: b"rendered"},
            expected_existing_signatures={output: expected},
            validate_committed=change_then_reject,
        )

    error = caught.value
    assert isinstance(error.original_error, ValueError)
    assert isinstance(error.rollback_errors[output], atomic.AtomicOutputChangedError)
    backup = error.recovery_backups[output]
    assert backup.read_bytes() == b"previous"
    assert output.read_bytes() == b"external"


def test_new_output_rollback_does_not_delete_same_metadata_external_edit(tmp_path):
    output = tmp_path / "output.redacted"

    def change_then_reject() -> None:
        published = atomic.capture_file_signature(output)
        output.write_bytes(b"external")
        os.utime(output, ns=(published.modified_ns, published.modified_ns))
        raise ValueError("verification failed")

    with pytest.raises(atomic.AtomicRollbackError) as caught:
        atomic.write_many_bytes_atomically(
            {output: b"rendered"},
            validate_committed=change_then_reject,
        )

    assert isinstance(caught.value.original_error, ValueError)
    assert isinstance(
        caught.value.rollback_errors[output],
        atomic.AtomicOutputChangedError,
    )
    assert caught.value.recovery_backups == {}
    assert output.read_bytes() == b"external"


def test_tampered_backup_is_not_used_for_rollback(tmp_path):
    output = tmp_path / "output.redacted"
    output.write_bytes(b"previous")
    expected = atomic.capture_file_signature(output)

    def tamper_then_reject() -> None:
        backup = next(tmp_path.glob(".*.backup"))
        backup_signature = atomic.capture_file_signature(backup)
        backup.write_bytes(b"tampered")
        os.utime(
            backup,
            ns=(backup_signature.modified_ns, backup_signature.modified_ns),
        )
        raise ValueError("verification failed")

    with pytest.raises(atomic.AtomicRollbackError) as caught:
        atomic.write_many_bytes_atomically(
            {output: b"rendered"},
            expected_existing_signatures={output: expected},
            validate_committed=tamper_then_reject,
        )

    error = caught.value
    backup = error.recovery_backups[output]
    assert isinstance(error.rollback_errors[output], atomic.AtomicOutputChangedError)
    assert backup.read_bytes() == b"tampered"
    assert output.read_bytes() == b"rendered"


def test_rollback_detects_content_change_after_backup_restore(monkeypatch, tmp_path):
    output = tmp_path / "output.redacted"
    output.write_bytes(b"previous")
    expected = atomic.capture_file_signature(output)
    real_replace = atomic.os.replace

    def corrupt_after_restore(source, target):
        result = real_replace(source, target)
        if Path(source).name.endswith(".backup") and Path(target) == output:
            output.write_bytes(b"corrupt!")
            os.utime(output, ns=(expected.modified_ns, expected.modified_ns))
        return result

    monkeypatch.setattr(atomic.os, "replace", corrupt_after_restore)

    def reject() -> None:
        raise ValueError("verification failed")

    with pytest.raises(atomic.AtomicRollbackError) as caught:
        atomic.write_many_bytes_atomically(
            {output: b"rendered"},
            expected_existing_signatures={output: expected},
            validate_committed=reject,
        )

    assert "did not restore output content" in str(caught.value.rollback_errors[output])
    assert caught.value.recovery_backups == {}
    assert output.read_bytes() == b"corrupt!"


def test_rollback_failure_retains_recovery_backup(monkeypatch, tmp_path):
    first = tmp_path / "first.redacted"
    second = tmp_path / "second.redacted"
    first.write_bytes(b"previous first")
    second.write_bytes(b"previous second")
    real_replace = atomic.os.replace
    commit_failed = False

    def fail_commit_and_restore(source, target):
        nonlocal commit_failed
        source_path = Path(source)
        target_path = Path(target)
        if target_path == second and source_path.name.endswith(".tmp") and not commit_failed:
            commit_failed = True
            raise OSError("simulated commit failure")
        if target_path == first and source_path.name.endswith(".backup"):
            raise OSError("simulated restoration failure")
        return real_replace(source, target)

    monkeypatch.setattr(atomic.os, "replace", fail_commit_and_restore)

    with pytest.raises(atomic.AtomicRollbackError, match="recovery backups retained") as caught:
        atomic.write_many_bytes_atomically(
            {first: b"new first", second: b"new second"},
            allowed_existing={first, second},
        )

    error = caught.value
    assert isinstance(error.original_error, OSError)
    assert first in error.rollback_errors
    backup = error.recovery_backups[first]
    assert backup.exists()
    assert backup.read_bytes() == b"previous first"
    assert first.read_bytes() == b"new first"
    assert second.read_bytes() == b"previous second"
    assert list(tmp_path.glob(".*.backup")) == [backup]
