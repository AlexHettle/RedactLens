"""Fail locally when built-in or configurable regexes exceed a real deadline."""

from __future__ import annotations

import argparse
import math
import time
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

from redactlens_core.methods import entropy, keyword, regex
from redactlens_core.registry import (
    DetectorDef,
    DetectorLoadError,
    DetectorRegistry,
    load_default_registry,
)

ADVERSARIAL_INPUTS = {
    "long_word": ("A" * 250_000) + "!",
    "password_prefixes": ("not_a_password_name " * 12_500) + "end",
    "email_prefixes": ("person.example.invalid " * 12_500) + "end",
    "private_key_without_footer": "-----BEGIN RSA PRIVATE KEY-----\n" + ("A" * 250_000),
}


@dataclass(frozen=True)
class _ProfileTarget:
    label: str
    method: str
    pattern: str
    entropy_threshold: float = 0.0
    search_only: bool = False


def _profile_targets(detector: DetectorDef) -> Iterator[_ProfileTarget]:
    assert detector.pattern is not None
    yield _ProfileTarget(
        label=detector.id,
        method=detector.method,
        pattern=detector.pattern,
        entropy_threshold=detector.entropy_threshold,
    )
    for context_kind, adjustments in (
        ("booster", detector.context.boosters),
        ("suppressor", detector.context.suppressors),
    ):
        for index, adjustment in enumerate(adjustments):
            if adjustment.pattern is not None:
                yield _ProfileTarget(
                    label=f"{detector.id}.context.{context_kind}[{index}].pattern",
                    method="regex",
                    pattern=adjustment.pattern,
                    search_only=True,
                )
            elif adjustment.in_path is not None:
                yield _ProfileTarget(
                    label=f"{detector.id}.context.{context_kind}[{index}].in_path",
                    method="regex",
                    pattern=adjustment.in_path,
                    search_only=True,
                )


def _run(target: _ProfileTarget, text: str, *, timeout_seconds: float) -> int:
    if target.search_only:
        return int(regex.search_pattern(target.pattern, text, timeout_seconds=timeout_seconds))
    if target.method == "regex":
        return sum(
            1
            for _ in regex.find_matches(
                target.pattern,
                text,
                timeout_seconds=timeout_seconds,
            )
        )
    if target.method == "entropy":
        return sum(
            1
            for _ in entropy.find_matches(
                target.pattern,
                text,
                target.entropy_threshold,
                timeout_seconds=timeout_seconds,
            )
        )
    return sum(1 for _ in keyword.find_matches(target.pattern, text))


def _load_registry(detector_directories: list[Path]) -> DetectorRegistry:
    if not detector_directories:
        return load_default_registry()
    registry = DetectorRegistry()
    for directory in detector_directories:
        if not directory.is_dir():
            raise ValueError(f"detector directory does not exist: {directory}")
        registry.load_dir(directory)
    return registry.freeze()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--max-ms",
        type=float,
        default=750.0,
        help="Stop and fail when one detector definition/corpus pair reaches this deadline.",
    )
    parser.add_argument(
        "--detectors-dir",
        action="append",
        default=[],
        type=Path,
        help=(
            "Profile configurable detector YAML from this directory instead of built-ins; "
            "repeatable."
        ),
    )
    args = parser.parse_args()
    if not math.isfinite(args.max_ms) or args.max_ms <= 0:
        parser.error("--max-ms must be a finite number greater than zero")

    try:
        registry = _load_registry(args.detectors_dir)
    except (DetectorLoadError, OSError, ValueError) as error:
        parser.error(str(error))

    failures: list[str] = []
    timeout_seconds = args.max_ms / 1_000
    print("definition\tcorpus\tmatches\tduration_ms")
    for detector in registry.get_all():
        targets = tuple(_profile_targets(detector))
        for corpus_name, text in ADVERSARIAL_INPUTS.items():
            for target in targets:
                started = time.perf_counter()
                try:
                    matches: int | str = _run(
                        target,
                        text,
                        timeout_seconds=timeout_seconds,
                    )
                except regex.RegexSafetyError as error:
                    matches = error.code
                    failures.append(f"{target.label}/{corpus_name}: {error.reason}")
                duration_ms = (time.perf_counter() - started) * 1_000
                print(f"{target.label}\t{corpus_name}\t{matches}\t{duration_ms:.3f}")
                if duration_ms > args.max_ms and not isinstance(matches, str):
                    failures.append(f"{target.label}/{corpus_name}: {duration_ms:.1f} ms")

    if failures:
        print("\nDetector performance budget exceeded:")
        for failure in failures:
            print(f"- {failure}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
