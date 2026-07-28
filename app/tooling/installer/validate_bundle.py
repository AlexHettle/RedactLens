"""Validate the structure and embedded assets of a RedactLens bundle."""

from __future__ import annotations

import argparse
from html.parser import HTMLParser
from pathlib import Path

LEGAL_DOCUMENTS = {
    "LICENSE": Path("LICENSE"),
    "THIRD_PARTY_NOTICES.md": Path("docs/legal/THIRD_PARTY_NOTICES.md"),
}
GENERATED_LEGAL_DOCUMENT = "THIRD_PARTY_LICENSES.txt"
REQUIRED_LICENSE_COMPONENTS = (
    "Python",
    "certifi",
    "numpy",
    "proxy-tools",
    "React",
    "react-dom",
    "scheduler",
    "Microsoft Edge WebView2 SDK redistributables",
    "Microsoft NETStandard.Library reference assemblies",
    "PyInstaller",
    "Inno Setup",
)


class _AssetReferences(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.references: list[str] = []

    def handle_starttag(self, _tag: str, attrs: list[tuple[str, str | None]]) -> None:
        for name, value in attrs:
            if name in {"href", "src"} and value:
                self.references.append(value)


def _content_root(bundle: Path) -> Path:
    internal = bundle / "_internal"
    return internal if internal.is_dir() else bundle


def validate_bundle(bundle: Path, source_root: Path) -> list[str]:
    errors: list[str] = []
    bundle = bundle.resolve()
    source_root = source_root.resolve()
    content = _content_root(bundle)
    executable = bundle / "RedactLens.exe"
    frontend = content / "frontend" / "dist"
    detector_dir = content / "redactlens_core" / "detectors"

    if not executable.is_file() or executable.stat().st_size == 0:
        errors.append("RedactLens.exe is missing or empty")

    repository_root = source_root.parent
    for bundle_name, source_relative in LEGAL_DOCUMENTS.items():
        source_document = repository_root / source_relative
        bundled_document = bundle / bundle_name
        if not source_document.is_file() or source_document.stat().st_size == 0:
            errors.append(f"the repository {bundle_name} is missing or empty")
        elif not bundled_document.is_file() or bundled_document.stat().st_size == 0:
            errors.append(f"the bundled {bundle_name} is missing or empty")
        elif bundled_document.read_bytes() != source_document.read_bytes():
            errors.append(f"the bundled {bundle_name} differs from the repository copy")

    generated_licenses = bundle / GENERATED_LEGAL_DOCUMENT
    if not generated_licenses.is_file() or generated_licenses.stat().st_size == 0:
        errors.append(f"the bundled {GENERATED_LEGAL_DOCUMENT} is missing or empty")
    else:
        license_text = generated_licenses.read_text(encoding="utf-8")
        if len(license_text) < 50_000:
            errors.append(f"the bundled {GENERATED_LEGAL_DOCUMENT} is unexpectedly short")
        for component in REQUIRED_LICENSE_COMPONENTS:
            if component.casefold() not in license_text.casefold():
                errors.append(f"the bundled {GENERATED_LEGAL_DOCUMENT} omits {component}")

    index = frontend / "index.html"
    if not index.is_file():
        errors.append("the bundled frontend index is missing")
    else:
        parser = _AssetReferences()
        parser.feed(index.read_text(encoding="utf-8"))
        for reference in parser.references:
            if reference.startswith(("data:", "http://", "https://", "#")):
                continue
            target = frontend / reference.lstrip("/")
            if not target.is_file():
                errors.append(f"frontend asset reference is missing: {reference}")

    source_detectors = {
        item.name
        for item in (
            source_root / "packages" / "redactlens-core" / "redactlens_core" / "detectors"
        ).glob("*.yaml")
    }
    bundled_detectors = {item.name for item in detector_dir.glob("*.yaml")}
    if not source_detectors:
        errors.append("the source detector set is empty")
    elif bundled_detectors != source_detectors:
        missing = sorted(source_detectors - bundled_detectors)
        extra = sorted(bundled_detectors - source_detectors)
        errors.append(f"bundled detector set differs (missing={missing}, extra={extra})")

    forbidden = sorted(path.name for path in bundle.rglob("*.app"))
    if forbidden:
        errors.append(f"non-Windows app bundles were included: {forbidden}")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("bundle", type=Path)
    parser.add_argument(
        "--source-root",
        type=Path,
        default=Path(__file__).resolve().parents[2],
    )
    args = parser.parse_args()

    errors = validate_bundle(args.bundle, args.source_root)
    if errors:
        for error in errors:
            print(f"ERROR: {error}")
        return 1
    print(f"Validated RedactLens bundle: {args.bundle.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
