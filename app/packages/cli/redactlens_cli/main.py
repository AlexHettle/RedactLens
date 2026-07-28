"""Thin Typer CLI over redactlens-core. No detection logic lives here."""

import json
import re
import sys
from typing import Any

import typer
from redactlens_core import ScanOptions, ScanRequest, ScanResult, load_default_registry
from redactlens_core import scan as core_scan
from redactlens_core.models import DEFAULT_TIER_THRESHOLD, UserTarget

app = typer.Typer(help="RedactLens: local-first sensitive-data scanner.")

_PUBLIC_FINDING_FIELDS = (
    "id",
    "file_path",
    "line",
    "column",
    "location",
    "can_anonymize",
    "redacted_preview",
    "detector_id",
    "category",
    "confidence",
    "tier",
    "explanation",
    "risk_lesson",
    "suggested_action",
    "supporting_detections",
)


@app.callback()
def main() -> None:
    """RedactLens: local-first sensitive-data scanner.

    Kept as an explicit callback so `scan` stays a named subcommand (Typer
    would otherwise collapse a single-command app and silently swallow the
    word "scan" into the paths argument).
    """
    if sys.platform != "win32":
        typer.echo("RedactLens supports Microsoft Windows only.", err=True)
        raise typer.Exit(code=1)


@app.command()
def scan(
    paths: list[str] = typer.Argument(..., help="Files or folders to scan."),
    categories: list[str] = typer.Option(
        [],
        "--categories",
        "-c",
        help=(
            "Show findings from these built-in categories (repeatable); other detectors may "
            "provide consolidation context."
        ),
    ),
    target: list[str] = typer.Option(
        [], "--target", "-t", help="A literal value you want RedactLens to watch for (repeatable)."
    ),
    threshold: float = typer.Option(
        DEFAULT_TIER_THRESHOLD,
        "--threshold",
        help="Tier A/B confidence cutoff.",
    ),
    use_llm: bool = typer.Option(
        False,
        "--use-llm",
        help=(
            "Let a local Ollama model nudge ambiguous matches. Degrades gracefully "
            "(and silently) to heuristics-only if Ollama isn't reachable."
        ),
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
        help="Emit privacy-safe JSON without raw matches or rewrite offsets.",
    ),
    max_file_size_mb: float = typer.Option(
        100.0, "--max-file-size-mb", min=0.001, help="Maximum size of any input file."
    ),
    max_structured_file_size_mb: float = typer.Option(
        50.0,
        "--max-structured-file-size-mb",
        min=0.001,
        max=250.0,
        help="Maximum raw size of a structured document or archive.",
    ),
    ignore_dir: list[str] = typer.Option(
        [], "--ignore-dir", help="Additional directory name to ignore (repeatable)."
    ),
    default_ignore_dirs: bool = typer.Option(
        True,
        "--default-ignore-dirs/--no-default-ignore-dirs",
        help="Apply the built-in directory ignore list before any --ignore-dir values.",
    ),
    include_ext: list[str] = typer.Option(
        [], "--include-ext", help="Only scan this extension (repeatable)."
    ),
    exclude_ext: list[str] = typer.Option(
        [], "--exclude-ext", help="Do not scan this extension (repeatable)."
    ),
    archive_depth: int = typer.Option(
        2, "--archive-depth", min=1, max=8, help="Maximum nested archive depth."
    ),
    ai_timeout: float = typer.Option(
        60.0, "--ai-timeout", min=0.1, max=600.0, help="Per-call local AI timeout."
    ),
    workers: int = typer.Option(
        4, "--workers", min=1, max=32, help="Maximum concurrent file workers."
    ),
    document_workers: int = typer.Option(
        1, "--document-workers", min=1, max=4, help="Concurrent structured extractors."
    ),
    chunk_size_kb: int = typer.Option(
        1024, "--chunk-size-kb", min=64, max=8192, help="Streaming text chunk size."
    ),
    redactlensignore: bool = typer.Option(
        True,
        "--redactlensignore/--no-redactlensignore",
        help="Apply .redactlensignore rules at selected directory roots.",
    ),
) -> None:
    """Scan files/folders for sensitive data."""
    registry = load_default_registry()
    defaults = ScanOptions()
    options = ScanOptions(
        max_file_size=round(max_file_size_mb * 1_000_000),
        max_structured_file_size=round(max_structured_file_size_mb * 1_000_000),
        ignored_directories=sorted(
            {
                *(defaults.ignored_directories if default_ignore_dirs else []),
                *ignore_dir,
            },
            key=str.casefold,
        ),
        included_extensions=include_ext,
        excluded_extensions=exclude_ext,
        archive_depth=archive_depth,
        ai_timeout_seconds=ai_timeout,
        max_workers=workers,
        document_workers=document_workers,
        chunk_size=chunk_size_kb * 1024,
        use_redactlensignore=redactlensignore,
    )
    if len(target) > 100:
        raise typer.BadParameter(
            "At most 100 --target values may be supplied.",
            param_hint="--target",
        )
    if any(len(value) > 8_192 for value in target):
        raise typer.BadParameter(
            "Each --target value must be 8,192 characters or fewer.",
            param_hint="--target",
        )

    request = ScanRequest(
        paths=paths,
        categories=categories,
        user_targets=[UserTarget(kind="literal", value=v) for v in target],
        tier_threshold=threshold,
        use_llm=use_llm,
        options=options,
    )
    result = core_scan(request, registry)

    if json_output:
        typer.echo(_privacy_safe_json(result, target))
        return

    _print_human(result, target)


def _print_human(result: ScanResult, user_targets: list[str] | None = None) -> None:
    replacements = _privacy_replacements(result, user_targets)
    tier_a = [f for f in result.findings if f.tier == "A"]
    tier_b = [f for f in result.findings if f.tier == "B"]

    typer.echo(f"Scanned {len(result.scanned_files)} file(s), skipped {len(result.skipped_files)}.")
    typer.echo(f"Local AI assistance: {'used' if result.llm_used else 'not used'}.")
    typer.echo('Nothing here asserts you\'re "safe" -- review before you rely on it.\n')

    _print_tier("Tier A -- Confirmed sensitive (recommended: anonymize)", tier_a, replacements)
    _print_tier("Tier B -- Worth a double-check (your call)", tier_b, replacements)

    if result.skipped_files:
        typer.echo(f"Skipped {len(result.skipped_files)} file(s):")
        for skipped in result.skipped_files:
            path = _scrub_text(skipped.path, replacements)
            reason = _scrub_text(skipped.reason, replacements)
            typer.echo(f"  - {path}: {reason}")


def _print_tier(
    title: str,
    findings: list,
    replacements: tuple[tuple[str, str], ...] = (),
) -> None:
    typer.echo(f"{title} ({len(findings)})")
    if not findings:
        typer.echo("  (none)")
    for finding in findings:
        category = _scrub_text(finding.category, replacements)
        file_path = _scrub_text(finding.file_path, replacements)
        preview = _scrub_text(finding.redacted_preview, replacements)
        explanation = _scrub_text(finding.explanation, replacements)
        typer.echo(
            f"  [{category}] {file_path}:{finding.line}:{finding.column}  "
            f"{preview}  (confidence {finding.confidence:.2f})"
        )
        typer.echo(f"      {explanation}")
        if finding.supporting_detections:
            supporting = ", ".join(
                _scrub_text(item.detector_id, replacements)
                for item in finding.supporting_detections
            )
            typer.echo(f"      Also detected by: {supporting}")
    typer.echo("")


def _privacy_safe_json(result: ScanResult, user_targets: list[str] | None = None) -> str:
    """Serialize an allowlisted CLI report and scrub matches from every retained string."""

    payload: dict[str, Any] = {
        "report_version": "1.0",
        "findings": [
            {
                field: getattr(finding, field)
                if field != "supporting_detections"
                else [item.model_dump() for item in finding.supporting_detections]
                for field in _PUBLIC_FINDING_FIELDS
            }
            for finding in result.findings
        ],
        "summary": result.summary,
        "scanned_files": result.scanned_files,
        "skipped_files": [item.model_dump() for item in result.skipped_files],
        "llm_used": result.llm_used,
    }
    replacements = _privacy_replacements(result, user_targets)
    return json.dumps(_scrub_json_value(payload, replacements), indent=2, ensure_ascii=False)


def _privacy_replacements(
    result: ScanResult,
    user_targets: list[str] | None = None,
) -> tuple[tuple[str, str], ...]:
    """Build one scrub map for every CLI output surface.

    Explicit targets are included even when they produced no finding because a
    target can still occur in a scanned or skipped path.
    """

    raw_values = tuple(
        sorted(
            {
                value.casefold(): value
                for value in (
                    *(finding.matched_text for finding in result.findings),
                    *(user_targets or []),
                )
                if value
            }.values(),
            key=lambda value: (-len(value), value.casefold()),
        )
    )
    replacements = tuple(
        (raw_value, _safe_json_marker(raw_values, ordinal))
        for ordinal, raw_value in enumerate(raw_values, start=1)
    )
    return replacements


def _safe_json_marker(raw_values: tuple[str, ...], ordinal: int) -> str:
    identities = tuple(value.casefold() for value in raw_values)
    for candidate in (
        f"<redacted-value-{ordinal}>",
        f"[private-value-{ordinal}]",
    ):
        if all(identity not in candidate.casefold() for identity in identities):
            return candidate

    # A one-character private-use marker cannot contain any multi-character
    # match. At most 100 user targets exist, so this range always leaves ample
    # choices even when targets themselves are single private-use characters.
    for codepoint in range(0xE000, 0xF900):
        candidate = chr(codepoint)
        if all(identity not in candidate.casefold() for identity in identities):
            return candidate
    raise RuntimeError("A privacy-safe JSON marker could not be created.")


def _scrub_json_value(value: Any, replacements: tuple[tuple[str, str], ...]) -> Any:
    if isinstance(value, str):
        return _scrub_text(value, replacements)
    if isinstance(value, list):
        return [_scrub_json_value(item, replacements) for item in value]
    if isinstance(value, tuple):
        return [_scrub_json_value(item, replacements) for item in value]
    if isinstance(value, dict):
        return {key: _scrub_json_value(item, replacements) for key, item in value.items()}
    return value


def _scrub_text(value: str, replacements: tuple[tuple[str, str], ...]) -> str:
    scrubbed = value
    for raw_value, marker in replacements:
        scrubbed = re.sub(re.escape(raw_value), marker, scrubbed, flags=re.IGNORECASE)
    return scrubbed


if __name__ == "__main__":
    app()
