"""Measure the heuristics-only core scan used for the Phase 0 baseline.

The measurement intentionally excludes interpreter/import startup and uses a
preloaded detector registry. It is a small repeatable reference, not a full
performance benchmark; Phase 8 owns broader workload and memory testing.
"""

from __future__ import annotations

import platform
import statistics
import time
from pathlib import Path

from redactlens_core.models import ScanRequest
from redactlens_core.registry import load_default_registry
from redactlens_core.scanner import scan

ROOT = Path(__file__).resolve().parents[2]
WARMUP_RUNS = 3
MEASURED_RUNS = 30


def main() -> None:
    registry = load_default_registry()
    request = ScanRequest(paths=[str(ROOT / "examples" / "demo")])

    for _ in range(WARMUP_RUNS):
        scan(request, registry)

    times_ms: list[float] = []
    result = None
    for _ in range(MEASURED_RUNS):
        start = time.perf_counter()
        result = scan(request, registry)
        times_ms.append((time.perf_counter() - start) * 1_000)

    assert result is not None
    tier_a = sum(finding.tier == "A" for finding in result.findings)
    tier_b = sum(finding.tier == "B" for finding in result.findings)
    print(f"Python: {platform.python_version()}")
    print(f"Warmups: {WARMUP_RUNS}; measured runs: {MEASURED_RUNS}")
    print(
        f"Result: {len(result.scanned_files)} files, {len(result.findings)} findings "
        f"({tier_a} Tier A, {tier_b} Tier B)"
    )
    print(f"Minimum: {min(times_ms):.3f} ms")
    print(f"Median: {statistics.median(times_ms):.3f} ms")
    print(f"Mean: {statistics.mean(times_ms):.3f} ms")
    print(f"Maximum: {max(times_ms):.3f} ms")


if __name__ == "__main__":
    main()
