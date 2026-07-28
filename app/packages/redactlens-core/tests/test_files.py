import codecs
import os
import stat
import time
from pathlib import Path
from types import SimpleNamespace

import pytest
from redactlens_core import files as files_module
from redactlens_core.files import (
    _compile_ignore_pattern,
    decode_text,
    discover_files,
    iter_files,
    probe_text_file,
    read_scannable,
    regular_file_issue,
)
from redactlens_core.models import ScanOptions


def test_iter_files_walks_directory_and_skips_ignored_dirs(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "a.txt").write_text("hello")
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "config").write_text("ignored")

    found = set(iter_files([str(tmp_path)]))
    assert str(tmp_path / "src" / "a.txt") in found
    assert not any(".git" in f for f in found)


def test_iter_files_yields_single_file_path(tmp_path):
    f = tmp_path / "a.txt"
    f.write_text("hello")
    assert list(iter_files([str(f)])) == [str(f)]


def test_configured_directory_ignores_are_case_insensitive(tmp_path):
    ignored = tmp_path / "Vendor"
    ignored.mkdir()
    secret = ignored / "secret.txt"
    secret.write_text("123-45-6789")

    entries = list(
        discover_files(
            [str(tmp_path)],
            ScanOptions(ignored_directories=["vendor"]),
        )
    )

    assert [(entry.path, entry.issue.code) for entry in entries] == [
        (str(ignored), "ignored_directory")
    ]
    assert str(secret) not in set(iter_files([str(tmp_path)], {"vendor"}))


def _make_symlink_or_skip(link, target, *, directory: bool = False):
    try:
        link.symlink_to(target, target_is_directory=directory)
    except (NotImplementedError, OSError) as error:
        pytest.skip(f"symlinks are unavailable in this test environment: {error}")


def test_iter_files_reports_directory_symlink_without_following_it(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_text("should not be reached through the link")
    link = root / "linked-folder"
    _make_symlink_or_skip(link, outside, directory=True)

    found = list(iter_files([str(root)]))

    assert str(link) in found
    assert str(link / "secret.txt") not in found
    scannable, reason = read_scannable(str(link))
    assert scannable is None
    assert "symbolic link skipped" in reason


def test_file_symlink_is_reported_instead_of_read(tmp_path):
    target = tmp_path / "secret.txt"
    target.write_text('ssn = "123-45-6789"')
    link = tmp_path / "linked-secret.txt"
    _make_symlink_or_skip(link, target)

    assert list(iter_files([str(link)])) == [str(link)]
    scannable, reason = read_scannable(str(link))

    assert scannable is None
    assert reason == "symbolic link skipped — scan the real target explicitly if you trust it"


def test_iter_files_removes_detected_directory_links_before_descent(monkeypatch, tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    walked_dirs = ["linked", "regular"]

    def fake_walk(_path, *, followlinks):
        assert followlinks is False
        yield str(root), walked_dirs, []

    monkeypatch.setattr(os, "walk", fake_walk)
    monkeypatch.setattr(
        files_module,
        "_entry_kind_no_follow",
        lambda path: (
            (files_module._ENTRY_SYMLINK, None)
            if path.name == "linked"
            else (files_module._ENTRY_DIRECTORY, None)
        ),
    )

    assert list(iter_files([str(root)])) == [str(root / "linked")]
    assert walked_dirs == ["regular"]


def test_read_scannable_rejects_detected_link_before_any_file_io(monkeypatch, tmp_path):
    nonexistent = tmp_path / "link"
    monkeypatch.setattr(
        files_module,
        "_entry_snapshot_no_follow",
        lambda _path: (files_module._ENTRY_SYMLINK, None, None),
    )

    scannable, reason = read_scannable(str(nonexistent))

    assert scannable is None
    assert "symbolic link skipped" in reason


def test_discovery_prunes_a_detected_junction_before_descent(monkeypatch, tmp_path):
    root = tmp_path / "root"
    linked = root / "linked"
    regular = root / "regular"
    linked.mkdir(parents=True)
    regular.mkdir()
    (linked / "outside.txt").write_text("must not be discovered")
    (regular / "inside.txt").write_text("safe")

    real_is_junction = getattr(Path, "is_junction", None)

    def fake_is_junction(path):
        if path == linked:
            return True
        return real_is_junction(path) if real_is_junction is not None else False

    # Exercise the compatibility fallback used when stat metadata cannot
    # expose Windows reparse attributes.
    monkeypatch.setattr(files_module.stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    monkeypatch.setattr(Path, "is_junction", fake_is_junction, raising=False)

    entries = list(discover_files([str(root)], ScanOptions()))

    by_path = {entry.path: entry for entry in entries}
    assert by_path[str(linked)].issue.code == "filesystem_redirect"
    assert str(linked / "outside.txt") not in by_path
    assert by_path[str(regular / "inside.txt")].issue is None


def test_discovery_checkpoint_preserves_order_and_interrupts_mid_walk(monkeypatch, tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    for name in ["z.txt", "A.txt", "m.txt", "b.txt"]:
        (root / name).write_text(name)

    expected = list(discover_files([str(root)], ScanOptions()))
    checkpoints = 0

    def observe() -> None:
        nonlocal checkpoints
        checkpoints += 1

    actual = list(discover_files([str(root)], ScanOptions(), checkpoint=observe))
    assert actual == expected
    assert checkpoints > len(actual)

    class DiscoveryStopped(Exception):
        pass

    classified = 0
    real_classify = files_module._classify_discovered

    def counted_classify(*args, **kwargs):
        nonlocal classified
        classified += 1
        return real_classify(*args, **kwargs)

    def stop_during_classification() -> None:
        if classified >= 2:
            raise DiscoveryStopped

    monkeypatch.setattr(files_module, "_classify_discovered", counted_classify)

    with pytest.raises(DiscoveryStopped):
        list(
            discover_files(
                [str(root)],
                ScanOptions(),
                checkpoint=stop_during_classification,
            )
        )

    assert classified == 2
    assert classified < len(expected)


def test_discovery_interrupts_while_scandir_enumerates_a_wide_directory(
    monkeypatch,
    tmp_path,
):
    root = tmp_path / "wide"
    root.mkdir()
    enumerated = 0
    classified = 0

    class FakeEntry:
        def __init__(self, name):
            self.name = name

        def is_dir(self, *, follow_symlinks=True):
            return False

        def is_symlink(self):
            return False

    class FakeScandir:
        def __init__(self):
            self.index = 0

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def __iter__(self):
            return self

        def __next__(self):
            nonlocal enumerated
            if self.index >= 100:
                raise StopIteration
            entry = FakeEntry(f"entry-{self.index:03d}.txt")
            self.index += 1
            enumerated += 1
            return entry

    class DiscoveryStopped(Exception):
        pass

    def stop_during_enumeration():
        if enumerated >= 4:
            raise DiscoveryStopped

    def classify(*_args, **_kwargs):
        nonlocal classified
        classified += 1
        raise AssertionError("classification must wait for directory enumeration")

    monkeypatch.setattr(files_module.os, "scandir", lambda path: FakeScandir())
    monkeypatch.setattr(files_module, "_classify_discovered", classify)

    with pytest.raises(DiscoveryStopped):
        list(
            discover_files(
                [str(root)],
                ScanOptions(),
                checkpoint=stop_during_enumeration,
            )
        )

    assert enumerated == 4
    assert classified == 0


def test_checkpointed_scandir_reports_errors_without_partial_directory_results(
    monkeypatch,
    tmp_path,
):
    root = tmp_path / "unreadable"
    root.mkdir()

    class FakeEntry:
        name = "partial.txt"

        def is_dir(self, *, follow_symlinks=True):
            return False

        def is_symlink(self):
            return False

    class BrokenScandir:
        def __init__(self):
            self.returned_entry = False

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def __iter__(self):
            return self

        def __next__(self):
            if not self.returned_entry:
                self.returned_entry = True
                return FakeEntry()
            raise OSError(5, "directory read failed", str(root))

    monkeypatch.setattr(files_module.os, "scandir", lambda path: BrokenScandir())

    entries = list(discover_files([str(root)], ScanOptions()))

    assert len(entries) == 1
    assert entries[0].path == str(root)
    assert entries[0].issue.code == "directory_unreadable"
    assert str(root / "partial.txt") not in {entry.path for entry in entries}


def test_discovery_rechecks_retained_directory_before_descent(monkeypatch, tmp_path):
    root = tmp_path / "root"
    child = root / "approved-then-replaced"
    child.mkdir(parents=True)
    external_descendant = child / "must-not-be-enumerated.txt"
    external_descendant.write_text("outside the approved tree")
    child_checks = 0
    scanned_paths = []
    real_entry_kind = files_module._entry_kind_no_follow
    real_scandir = files_module.os.scandir

    def changing_entry_kind(path):
        nonlocal child_checks
        if Path(path) != child:
            return real_entry_kind(path)
        child_checks += 1
        if child_checks == 1:
            return files_module._ENTRY_DIRECTORY, None
        return files_module._ENTRY_SYMLINK, None

    def guarded_scandir(path):
        scanned_paths.append(Path(path))
        if Path(path) == child:
            raise AssertionError("changed directory must not be enumerated")
        return real_scandir(path)

    monkeypatch.setattr(files_module, "_entry_kind_no_follow", changing_entry_kind)
    monkeypatch.setattr(files_module.os, "scandir", guarded_scandir)

    entries = list(discover_files([str(root)], ScanOptions()))
    by_path = {entry.path: entry for entry in entries}

    assert child_checks == 2
    assert child not in scanned_paths
    assert by_path[str(child)].issue.code == "symbolic_link"
    assert str(external_descendant) not in by_path


def test_redirect_check_prefers_existing_reparse_metadata_over_junction_probe(
    monkeypatch, tmp_path
):
    calls = 0

    def counted_junction(_path):
        nonlocal calls
        calls += 1
        return True

    reparse_flag = 0x400
    metadata = SimpleNamespace(st_mode=stat.S_IFDIR, st_file_attributes=0)
    monkeypatch.setattr(files_module.stat, "FILE_ATTRIBUTE_REPARSE_POINT", reparse_flag)
    monkeypatch.setattr(Path, "is_junction", counted_junction, raising=False)

    assert files_module._is_filesystem_redirect(tmp_path, metadata) is False
    assert calls == 0

    metadata.st_file_attributes = reparse_flag
    assert files_module._is_filesystem_redirect(tmp_path, metadata) is True
    assert calls == 0


def test_discovery_rejects_a_selected_tree_below_a_redirect_ancestor(monkeypatch, tmp_path):
    redirect = tmp_path / "redirect"
    selected = redirect / "selected"
    selected.mkdir(parents=True)
    child = selected / "must-not-be-discovered.txt"
    child.write_text("secret")
    real_redirect_check = files_module._is_filesystem_redirect

    monkeypatch.setattr(
        files_module,
        "_is_filesystem_redirect",
        lambda path, metadata: path == redirect or real_redirect_check(path, metadata),
    )

    entries = list(discover_files([str(selected)], ScanOptions()))

    assert len(entries) == 1
    assert entries[0].path == str(selected)
    assert entries[0].issue.code == "filesystem_redirect"
    assert str(child) not in {entry.path for entry in entries}


def test_read_rejects_a_regular_file_below_a_redirect_ancestor(monkeypatch, tmp_path):
    redirect = tmp_path / "redirect"
    redirect.mkdir()
    candidate = redirect / "secret.txt"
    candidate.write_text("secret")
    real_redirect_check = files_module._is_filesystem_redirect

    monkeypatch.setattr(
        files_module,
        "_is_filesystem_redirect",
        lambda path, metadata: path == redirect or real_redirect_check(path, metadata),
    )
    monkeypatch.setattr(
        os,
        "open",
        lambda *_args, **_kwargs: pytest.fail("unsafe file must not be opened"),
    )

    issue = regular_file_issue(candidate)
    scannable, reason = read_scannable(str(candidate))

    assert issue.code == "filesystem_redirect"
    assert scannable is None
    assert reason == "filesystem redirect in parent path skipped — select the real path explicitly"


def test_selected_file_below_a_real_directory_symlink_is_rejected(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    (target / "secret.txt").write_text("secret")
    link = tmp_path / "linked-parent"
    _make_symlink_or_skip(link, target, directory=True)

    entries = list(discover_files([str(link / "secret.txt")], ScanOptions()))

    assert len(entries) == 1
    assert entries[0].issue.code == "filesystem_redirect"


def test_non_regular_entry_is_rejected_before_read(monkeypatch, tmp_path):
    candidate = tmp_path / "pipe"
    monkeypatch.setattr(
        files_module,
        "_entry_snapshot_no_follow",
        lambda _path: (files_module._ENTRY_NON_REGULAR, None, None),
    )

    issue = regular_file_issue(candidate)
    scannable, reason = read_scannable(str(candidate))

    assert issue.code == "non_regular_file"
    assert scannable is None
    assert reason == "non-regular filesystem entry skipped"


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFOs are unavailable on this platform")
def test_fifo_is_classified_without_opening_it(tmp_path):
    candidate = tmp_path / "named-pipe"
    os.mkfifo(candidate)

    started = time.perf_counter()
    entries = list(discover_files([str(candidate)], ScanOptions()))
    _codec, _size, issue = probe_text_file(str(candidate))

    assert time.perf_counter() - started < 0.5
    assert entries[0].issue.code == "non_regular_file"
    assert issue.code == "non_regular_file"


def test_ignore_glob_matching_is_bounded_for_adversarial_wildcards():
    expression = _compile_ignore_pattern(("*a" * 96) + "*b")
    candidate = ("a" * 512) + "c"

    started = time.perf_counter()
    assert expression.fullmatch(candidate) is False

    assert time.perf_counter() - started < 0.5


def test_ignore_matching_is_fast_at_the_declared_aggregate_pattern_cap():
    rule = ("*a" * 30) + "*b"
    assert len(rule) * files_module._MAX_IGNORE_RULES <= (
        files_module._MAX_IGNORE_PATTERN_TOTAL_CHARS
    )
    expressions = [
        _compile_ignore_pattern(rule) for _index in range(files_module._MAX_IGNORE_RULES)
    ]
    candidate = ("a" * 4096) + "c"

    started = time.perf_counter()
    assert not any(expression.fullmatch(candidate) for expression in expressions)

    # This is deliberately generous for shared CI hosts while still catching
    # the former per-token full-path set expansion, which took many seconds at
    # the configured aggregate cap.
    assert time.perf_counter() - started < 2.0


@pytest.mark.parametrize(
    ("pattern", "matching", "not_matching"),
    [
        ("*.log", "nested/debug.log", "nested/debug.txt"),
        ("/root.txt", "root.txt", "nested/root.txt"),
        ("src/?ain.py", "src/main.py", "src/domain.py"),
        ("docs/**/secret.txt", "docs/a/b/secret.txt", "other/secret.txt"),
        ("**/cache/*.txt", "a/b/cache/key.txt", "a/b/cache/key.json"),
        ("docs/**/index.txt", "docs/index.txt", "docs/index.json"),
        ("prefix**suffix", "nested/prefix-middle-suffix", "prefix/a/suffix"),
        ("archive/**", "archive/deep/item.txt", "archive"),
    ],
)
def test_ignore_glob_program_preserves_documented_semantics(pattern, matching, not_matching):
    expression = _compile_ignore_pattern(pattern)

    assert expression.fullmatch(matching) is True
    assert expression.fullmatch(not_matching) is False


def test_trailing_slash_matches_only_directories_and_their_descendants():
    expression = _compile_ignore_pattern("cache/")

    assert expression.fullmatch("cache") is False
    assert expression.fullmatch("cache", is_directory=True) is True
    assert expression.fullmatch("cache/entry.txt") is True
    assert expression.fullmatch("nested/cache/entry.txt") is True


def test_directory_rule_does_not_hide_a_same_named_regular_file(tmp_path):
    (tmp_path / ".redactlensignore").write_text("cache/\n")
    same_named_file = tmp_path / "cache"
    same_named_file.write_text("must remain visible")
    nested_cache = tmp_path / "nested" / "cache"
    nested_cache.mkdir(parents=True)
    (nested_cache / "hidden.txt").write_text("ignored")

    entries = list(discover_files([str(tmp_path)], ScanOptions()))
    by_path = {entry.path: entry for entry in entries}

    assert by_path[str(same_named_file)].issue is None
    assert by_path[str(nested_cache)].issue.code == "ignored_by_rule"
    assert str(nested_cache / "hidden.txt") not in by_path


def test_legacy_ignore_file_remains_supported_after_product_rename(tmp_path):
    (tmp_path / ".redactscoutignore").write_text("*.txt\n")
    target = tmp_path / "hidden.txt"
    target.write_text("ignored")

    entries = list(discover_files([str(tmp_path)], ScanOptions()))
    by_path = {entry.path: entry for entry in entries}

    assert by_path[str(target)].issue is not None
    assert by_path[str(target)].issue.code == "ignored_by_rule"
    assert ".redactscoutignore:1: *.txt" in (by_path[str(target)].issue.rule or "")
    assert str(tmp_path / ".redactscoutignore") not in by_path


def test_current_ignore_file_takes_precedence_over_legacy_file(tmp_path):
    (tmp_path / ".redactlensignore").write_text("*.log\n")
    (tmp_path / ".redactscoutignore").write_text("*.txt\n")
    text_target = tmp_path / "visible.txt"
    log_target = tmp_path / "hidden.log"
    text_target.write_text("visible")
    log_target.write_text("ignored")

    entries = list(discover_files([str(tmp_path)], ScanOptions()))
    by_path = {entry.path: entry for entry in entries}

    assert by_path[str(text_target)].issue is None
    assert by_path[str(log_target)].issue is not None
    assert ".redactlensignore:1: *.log" in (by_path[str(log_target)].issue.rule or "")
    assert str(tmp_path / ".redactlensignore") not in by_path
    assert str(tmp_path / ".redactscoutignore") not in by_path


def test_ordered_negation_reincludes_a_file_below_an_ignored_directory(tmp_path):
    (tmp_path / ".redactlensignore").write_text("cache/\n!cache/keep.txt\n")
    cache = tmp_path / "cache"
    cache.mkdir()
    excluded = cache / "drop.txt"
    included = cache / "keep.txt"
    excluded.write_text("drop")
    included.write_text("keep")

    entries = list(discover_files([str(tmp_path)], ScanOptions()))
    by_path = {entry.path: entry for entry in entries}

    assert by_path[str(excluded)].issue.code == "ignored_by_rule"
    assert by_path[str(included)].issue is None


def test_linked_redactlensignore_is_not_followed(tmp_path):
    rules = tmp_path / "outside-ignore"
    rules.write_text("*.txt\n")
    root = tmp_path / "root"
    root.mkdir()
    target = root / "visible.txt"
    target.write_text("visible")
    _make_symlink_or_skip(root / ".redactlensignore", rules)

    entries = list(discover_files([str(root)], ScanOptions()))

    assert [entry.path for entry in entries] == [str(target)]
    assert entries[0].issue is None


@pytest.mark.parametrize("ignore_name", [".redactlensignore", ".redactscoutignore"])
def test_ignore_control_symlink_is_omitted_when_walked_as_a_directory(
    monkeypatch,
    tmp_path,
    ignore_name,
):
    root = tmp_path / "root"
    root.mkdir()
    target = root / "visible.txt"
    target.write_text("visible")

    def walk_with_linked_control_file(path, **_callbacks):
        assert path == root
        yield str(root), [ignore_name], [target.name]

    monkeypatch.setattr(
        files_module,
        "_walk_directory_checkpointed",
        walk_with_linked_control_file,
    )

    entries = list(discover_files([str(root)], ScanOptions()))

    assert [entry.path for entry in entries] == [str(target)]
    assert entries[0].issue is None


def test_ignore_rule_cap_does_not_keep_a_broad_rule_and_drop_late_negation(monkeypatch, tmp_path):
    monkeypatch.setattr(files_module, "_MAX_IGNORE_RULES", 1)
    (tmp_path / ".redactlensignore").write_text("*.txt\n!important.txt\n")
    ordinary = tmp_path / "ordinary.txt"
    important = tmp_path / "important.txt"
    ordinary.write_text("ordinary")
    important.write_text("important")

    entries = list(discover_files([str(tmp_path)], ScanOptions()))

    assert {entry.path for entry in entries} == {str(ordinary), str(important)}
    assert all(entry.issue is None for entry in entries)


@pytest.mark.parametrize(
    ("limit_name", "limit"),
    [
        ("_MAX_IGNORE_FILE_BYTES", 4),
        ("_MAX_IGNORE_PATTERN_CHARS", 3),
        ("_MAX_IGNORE_PATTERN_TOTAL_CHARS", 3),
    ],
)
def test_ignore_resource_caps_disable_the_whole_matcher(monkeypatch, tmp_path, limit_name, limit):
    monkeypatch.setattr(files_module, limit_name, limit)
    (tmp_path / ".redactlensignore").write_text("*.txt\n!important.txt\n")
    ordinary = tmp_path / "ordinary.txt"
    important = tmp_path / "important.txt"
    ordinary.write_text("ordinary")
    important.write_text("important")

    entries = list(discover_files([str(tmp_path)], ScanOptions()))

    assert {entry.path for entry in entries} == {str(ordinary), str(important)}
    assert all(entry.issue is None for entry in entries)


def test_ignore_file_read_rejects_a_final_path_metadata_change(monkeypatch, tmp_path):
    candidate = tmp_path / ".redactlensignore"
    candidate.write_text("*.txt\n")
    real_lstat = Path.lstat
    validated_metadata = candidate.lstat()

    def changed_final_metadata(path):
        metadata = real_lstat(path)
        if path == candidate:
            return SimpleNamespace(
                st_dev=metadata.st_dev,
                st_ino=metadata.st_ino,
                st_mode=metadata.st_mode,
                st_size=metadata.st_size + 1,
                st_mtime_ns=metadata.st_mtime_ns,
                st_file_attributes=getattr(metadata, "st_file_attributes", 0),
            )
        return metadata

    monkeypatch.setattr(Path, "lstat", changed_final_metadata)

    assert (
        files_module._read_regular_bytes_no_follow(
            candidate,
            100,
            validated_metadata=validated_metadata,
        )
        is None
    )


def test_regular_read_rechecks_ancestors_before_file_io(monkeypatch, tmp_path):
    candidate = tmp_path / "candidate.txt"
    candidate.write_text("safe")
    checks = 0

    def redirect_after_open(_path):
        nonlocal checks
        checks += 1
        if checks == 2:
            return files_module._ENTRY_ANCESTOR_REDIRECT, None
        return None, None

    monkeypatch.setattr(files_module, "_redirect_ancestor_kind", redirect_after_open)
    monkeypatch.setattr(
        os,
        "read",
        lambda *_args, **_kwargs: pytest.fail("file bytes must not be read"),
    )

    assert files_module._read_regular_bytes_no_follow(candidate, 100) is None
    assert checks == 2


def test_regular_read_rechecks_ancestors_after_file_io(monkeypatch, tmp_path):
    candidate = tmp_path / "candidate.txt"
    candidate.write_text("safe")
    checks = 0

    def redirect_after_read(_path):
        nonlocal checks
        checks += 1
        if checks == 3:
            return files_module._ENTRY_ANCESTOR_REDIRECT, None
        return None, None

    monkeypatch.setattr(files_module, "_redirect_ancestor_kind", redirect_after_read)

    assert files_module._read_regular_bytes_no_follow(candidate, 100) is None
    assert checks == 3


def test_read_scannable_reuses_the_validated_metadata_snapshot(monkeypatch, tmp_path):
    candidate = tmp_path / "candidate.txt"
    candidate.write_text("safe")
    real_lstat = Path.lstat
    candidate_lstat_calls = 0

    def counted_lstat(path):
        nonlocal candidate_lstat_calls
        if path == candidate:
            candidate_lstat_calls += 1
        return real_lstat(path)

    monkeypatch.setattr(Path, "lstat", counted_lstat)

    scannable, issue = files_module.read_scannable_detailed(str(candidate))

    assert issue is None
    assert scannable is not None
    assert scannable.text == "safe"
    assert candidate_lstat_calls == 2


def test_regular_read_rejects_a_change_between_snapshot_and_open(monkeypatch, tmp_path):
    candidate = tmp_path / "candidate.txt"
    candidate.write_text("safe")
    validated_metadata = candidate.lstat()
    real_open = os.open

    def change_then_open(path, flags):
        candidate.write_text("changed after validation")
        return real_open(path, flags)

    monkeypatch.setattr(os, "open", change_then_open)
    monkeypatch.setattr(
        os,
        "read",
        lambda *_args, **_kwargs: pytest.fail("changed file must not be read"),
    )

    assert (
        files_module._read_regular_bytes_no_follow(
            candidate,
            100,
            validated_metadata=validated_metadata,
        )
        is None
    )


def test_os_error_details_are_not_exposed_in_file_issues(monkeypatch, tmp_path):
    candidate = tmp_path / "private-name.txt"

    def denied(_path):
        return (
            files_module._ENTRY_UNAVAILABLE,
            None,
            OSError("C:/secret/private-name.txt denied"),
        )

    monkeypatch.setattr(files_module, "_entry_snapshot_no_follow", denied)

    _scannable, reason = read_scannable(str(candidate))

    assert reason == "file metadata is unavailable"
    assert "secret" not in reason


def test_read_scannable_returns_text_for_normal_file(tmp_path):
    f = tmp_path / "a.txt"
    f.write_text("hello world")
    scannable, reason = read_scannable(str(f))
    assert scannable.text == "hello world"
    assert reason is None


def test_read_scannable_skips_binary(tmp_path):
    f = tmp_path / "a.bin"
    f.write_bytes(b"\x00\x01\x02hello")
    scannable, reason = read_scannable(str(f))
    assert scannable is None
    assert "binary" in reason


def test_read_scannable_skips_oversized(tmp_path):
    f = tmp_path / "a.txt"
    f.write_text("x" * 100)
    scannable, reason = read_scannable(str(f), max_size=10)
    assert scannable is None
    assert "exceeds max scan size" in reason


def test_read_scannable_reports_missing_file(tmp_path):
    scannable, reason = read_scannable(str(tmp_path / "missing.txt"))
    assert scannable is None
    assert reason is not None


# ---- Text encodings ----------------------------------------------------------


def test_utf16_le_with_bom_is_scanned(tmp_path):
    # PowerShell's Out-File default on Windows: UTF-16 LE with BOM. Full of
    # null bytes, so the naive binary sniff used to reject it.
    f = tmp_path / "log.txt"
    f.write_bytes('ssn = "123-45-6789"\n'.encode("utf-16"))  # utf-16 writes an LE BOM

    scannable, reason = read_scannable(str(f))

    assert reason is None
    assert '"123-45-6789"' in scannable.text


def test_utf16_be_with_bom_is_scanned(tmp_path):
    f = tmp_path / "log.txt"
    f.write_bytes(codecs.BOM_UTF16_BE + "secret 123-45-6789".encode("utf-16-be"))

    scannable, reason = read_scannable(str(f))

    assert reason is None
    assert "123-45-6789" in scannable.text


def test_utf8_bom_is_stripped_not_leaked_into_text(tmp_path):
    f = tmp_path / "notes.txt"
    f.write_bytes(codecs.BOM_UTF8 + b"hello")

    scannable, reason = read_scannable(str(f))

    assert reason is None
    assert scannable.text == "hello"  # no ﻿ at the start


def test_cp1252_text_is_scanned(tmp_path):
    f = tmp_path / "notes.txt"
    f.write_bytes("café ssn 123-45-6789".encode("cp1252"))  # é = 0xE9, invalid UTF-8

    scannable, reason = read_scannable(str(f))

    assert reason is None
    assert "café" in scannable.text
    assert "123-45-6789" in scannable.text


def test_mostly_unprintable_bytes_are_still_skipped(tmp_path):
    # Not valid UTF-8 (lone 0xE9 tail), no null bytes, and CP-1252 happily
    # "decodes" it — but it's control-character soup, not text.
    f = tmp_path / "junk.dat"
    f.write_bytes(b"\x1b" * 800 + b"\xe9")

    scannable, reason = read_scannable(str(f))

    assert scannable is None
    assert "unknown or unsupported encoding" in reason


def test_bom_that_lies_about_its_encoding_is_skipped(tmp_path):
    f = tmp_path / "liar.txt"
    f.write_bytes(codecs.BOM_UTF16_LE + b"\x01")  # odd byte count can't be UTF-16

    scannable, reason = read_scannable(str(f))

    assert scannable is None
    assert reason is not None


def test_decode_text_reports_codec_for_roundtrips():
    text, codec = decode_text("hello".encode("utf-16"))
    assert text == "hello"
    assert codec.name == "utf-16-le"
    assert codec.encode("bye") == "bye".encode("utf-16")  # BOM preserved
