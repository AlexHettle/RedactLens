"""Run RedactLens's complete local quality baseline without prompting.

Usage:
    .venv\\Scripts\\python.exe app\\tooling\\verify.py   # Windows, repository root

Every check has a bounded runtime and runs even if an earlier one fails or
times out. The process exits with zero only when the entire baseline passes,
which makes this suitable for local development tools as well as terminal
use. The double-click-oriented ``run_tests.bat`` delegates here and adds its
own final pause.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FRONTEND = "packages/frontend"


@dataclass(frozen=True)
class Check:
    name: str
    command: list[str]
    timeout_seconds: int


def _npm_executable() -> str:
    for candidate in ("npm.cmd", "npm.exe"):
        if executable := shutil.which(candidate):
            return executable
    return "npm.cmd"


def _checks() -> list[Check]:
    npm = _npm_executable()
    return [
        Check("Python tests", [sys.executable, "-m", "pytest", "-q"], 900),
        Check("Frontend tests", [npm, "test", "--prefix", FRONTEND], 600),
        Check(
            "Frontend production build",
            [npm, "run", "build", "--prefix", FRONTEND],
            300,
        ),
        Check(
            "Browser accessibility (Playwright + axe)",
            [npm, "run", "test:a11y:e2e", "--prefix", FRONTEND],
            600,
        ),
        Check(
            "Live browser workflow (Phase 9)",
            [sys.executable, "tooling/scripts/e2e_phase9.py"],
            300,
        ),
        Check(
            "CLI demo contract",
            [sys.executable, "tooling/scripts/check_demo_cli.py"],
            120,
        ),
        Check("Python lint (Ruff)", [sys.executable, "-m", "ruff", "check", "."], 180),
        Check(
            "Python formatting (Ruff)",
            [sys.executable, "-m", "ruff", "format", "--check", "."],
            180,
        ),
        Check(
            "Phase 8 benchmark freshness",
            [
                sys.executable,
                "tooling/scripts/benchmark_phase8.py",
                "--check-baseline",
                "docs/phase-8-benchmark.json",
            ],
            300,
        ),
        Check(
            "Detector performance budget",
            [sys.executable, "tooling/scripts/profile_detectors.py", "--max-ms", "750"],
            120,
        ),
        Check(
            "Frontend lint (ESLint)",
            [npm, "run", "lint", "--prefix", FRONTEND],
            300,
        ),
        Check(
            "Frontend formatting (Prettier)",
            [npm, "run", "format:check", "--prefix", FRONTEND],
            300,
        ),
        Check(
            "Evaluation report freshness",
            [sys.executable, "tooling/eval/run_eval.py", "--check"],
            300,
        ),
    ]


def main() -> int:
    if sys.platform != "win32":
        print("RedactLens's quality baseline supports Microsoft Windows only.")
        return 1

    if not (ROOT / FRONTEND / "node_modules").is_dir():
        print("Frontend dependencies are missing. Run `npm ci` in packages/frontend/ first.")
        return 1

    failures: dict[str, str] = {}
    checks = _checks()
    for index, check in enumerate(checks, start=1):
        print(f"\n[{index}/{len(checks)}] {check.name}", flush=True)
        print("=" * 72, flush=True)
        try:
            completed = subprocess.run(
                check.command,
                cwd=ROOT,
                check=False,
                timeout=check.timeout_seconds,
            )
        except subprocess.TimeoutExpired:
            print(f"Check timed out after {check.timeout_seconds} seconds.")
            failures[check.name] = "TIMED OUT"
            continue
        except OSError as error:
            print(f"Could not start check: {error}")
            failures[check.name] = "FAILED TO START"
            continue
        if completed.returncode != 0:
            failures[check.name] = "FAILED"

    print("\nQuality baseline summary")
    print("=" * 72)
    for check in checks:
        status = failures.get(check.name, "passed")
        print(f"{check.name:.<52} {status}")

    if failures:
        print(f"\n{len(failures)} check(s) failed.")
        return 1
    print("\nAll quality checks passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
