"""Generate the third-party license-text bundle used by Windows releases."""

from __future__ import annotations

import argparse
import json
import sys
from importlib import metadata
from pathlib import Path

RUNTIME_DISTRIBUTIONS = (
    "annotated-doc",
    "annotated-types",
    "anyio",
    "bottle",
    "certifi",
    "cffi",
    "click",
    "clr-loader",
    "colorama",
    "defusedxml",
    "fastapi",
    "h11",
    "httpcore",
    "httpx",
    "idna",
    "lxml",
    "markdown-it-py",
    "mdurl",
    "numpy",
    "ollama",
    "packaging",
    "pillow",
    "pycparser",
    "pydantic",
    "pydantic-core",
    "pygments",
    "pypdf",
    "pythonnet",
    "pyyaml",
    "regex",
    "rich",
    "setuptools",
    "shellingham",
    "starlette",
    "typer",
    "typing-extensions",
    "typing-inspection",
    "uvicorn",
    "pywebview",
)

PACKAGING_DISTRIBUTIONS = (
    "altgraph",
    "pefile",
    "pyinstaller",
    "pyinstaller-hooks-contrib",
    "pywin32-ctypes",
)

FRONTEND_PACKAGES = ("react", "react-dom", "scheduler")

SEPARATOR = "=" * 80
SUBSEPARATOR = "-" * 80


class LicenseBundleError(RuntimeError):
    """Raised when a required license source cannot be found."""


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return path.read_text(encoding="utf-8", errors="replace")


def _python_license() -> tuple[str, str]:
    candidates = (
        Path(sys.base_prefix) / "LICENSE.txt",
        Path(sys.base_prefix) / "LICENSE",
        Path(sys.base_exec_prefix) / "LICENSE.txt",
        Path(sys.base_exec_prefix) / "LICENSE",
    )
    for candidate in candidates:
        if candidate.is_file():
            return sys.version.split()[0], _read_text(candidate)
    searched = ", ".join(str(path) for path in candidates)
    raise LicenseBundleError(f"Python license file was not found; searched: {searched}")


def _distribution_license_files(
    distribution_name: str,
) -> tuple[str, str, list[tuple[str, str]]]:
    try:
        distribution = metadata.distribution(distribution_name)
    except metadata.PackageNotFoundError as exc:
        raise LicenseBundleError(
            f"Required distribution is not installed: {distribution_name}"
        ) from exc

    located_paths: dict[str, Path] = {}
    for package_file in distribution.files or ():
        upper_name = package_file.name.upper()
        if not any(
            marker in upper_name
            for marker in (
                "LICENSE",
                "LICENCE",
                "COPYING",
                "NOTICE",
                "COPYRIGHT",
                "AUTHORS",
            )
        ):
            continue
        license_path = Path(distribution.locate_file(package_file))
        if license_path.is_file():
            located_paths[package_file.as_posix()] = license_path

    declared = distribution.metadata.get_all("License-File") or []
    for relative_name in declared:
        normalized = Path(relative_name).as_posix()
        if not any(
            label == normalized
            or label.endswith(f"/licenses/{normalized}")
            or label.endswith(f"/{normalized}")
            for label in located_paths
        ):
            raise LicenseBundleError(
                f"{distribution_name} declares a missing license file: {relative_name}"
            )

    located = [(label, _read_text(path)) for label, path in sorted(located_paths.items())]

    if not located:
        raise LicenseBundleError(
            f"No license text was found for required distribution: {distribution_name}"
        )

    package_name = distribution.metadata.get("Name", distribution_name)
    return package_name, distribution.version, located


def _frontend_license(
    frontend_root: Path, package_name: str
) -> tuple[str, str, list[tuple[str, str]]]:
    package_root = frontend_root / "node_modules" / package_name
    package_json = package_root / "package.json"
    if not package_json.is_file():
        raise LicenseBundleError(f"Required frontend package is not installed: {package_name}")
    package_metadata = json.loads(_read_text(package_json))
    license_files = sorted(
        path
        for path in package_root.iterdir()
        if path.is_file()
        and path.name.upper().startswith(("LICENSE", "LICENCE", "COPYING", "NOTICE"))
    )
    if not license_files:
        raise LicenseBundleError(f"No license text was found for frontend package: {package_name}")
    return (
        package_metadata.get("name", package_name),
        package_metadata["version"],
        [(path.name, _read_text(path)) for path in license_files],
    )


def _append_component(
    sections: list[str],
    name: str,
    version: str,
    license_files: list[tuple[str, str]],
) -> None:
    sections.extend((SEPARATOR, f"{name} {version}", SEPARATOR, ""))
    for index, (filename, contents) in enumerate(license_files):
        if index:
            sections.extend(("", SUBSEPARATOR, ""))
        sections.extend((f"License file: {filename}", "", contents.rstrip(), ""))


def generate_bundle(repository_root: Path) -> str:
    project_root = repository_root / "app"
    static_root = project_root / "tooling" / "installer" / "licenses"
    sections = [
        "REDACTLENS THIRD-PARTY LICENSES",
        "",
        "This file reproduces the license and copyright texts for third-party",
        "software included in, or used to produce, the RedactLens Windows release.",
        "Component versions are read from the release build environment.",
        "",
        "RedactLens itself is licensed separately under the repository LICENSE file.",
        "",
    ]

    python_version, python_text = _python_license()
    _append_component(
        sections,
        "Python",
        python_version,
        [("LICENSE.txt", python_text)],
    )

    for distribution_name in RUNTIME_DISTRIBUTIONS:
        name, version, files = _distribution_license_files(distribution_name)
        _append_component(sections, name, version, files)

    proxy_license = static_root / "proxy-tools-0.1.0-LICENSE.txt"
    if not proxy_license.is_file():
        raise LicenseBundleError(f"Required static license is missing: {proxy_license}")
    _append_component(
        sections,
        "proxy-tools",
        "0.1.0",
        [(proxy_license.name, _read_text(proxy_license))],
    )

    for package_name in FRONTEND_PACKAGES:
        name, version, files = _frontend_license(
            project_root / "packages" / "frontend", package_name
        )
        _append_component(sections, name, version, files)

    webview2_license = static_root / "MICROSOFT_WEBVIEW2_1.0.3856.49_LICENSE.txt"
    if not webview2_license.is_file():
        raise LicenseBundleError(f"Required static license is missing: {webview2_license}")
    _append_component(
        sections,
        "Microsoft Edge WebView2 SDK redistributables",
        "1.0.3856.49",
        [(webview2_license.name, _read_text(webview2_license))],
    )

    netstandard_license = static_root / "NETSTANDARD_LIBRARY_2.0.3_LICENSE.txt"
    if not netstandard_license.is_file():
        raise LicenseBundleError(f"Required static license is missing: {netstandard_license}")
    _append_component(
        sections,
        "Microsoft NETStandard.Library reference assemblies",
        "2.0.3",
        [(netstandard_license.name, _read_text(netstandard_license))],
    )

    for distribution_name in PACKAGING_DISTRIBUTIONS:
        name, version, files = _distribution_license_files(distribution_name)
        _append_component(sections, name, version, files)

    inno_license = static_root / "INNO_SETUP_LICENSE.txt"
    if not inno_license.is_file():
        raise LicenseBundleError(f"Required static license is missing: {inno_license}")
    _append_component(
        sections,
        "Inno Setup",
        "6.7.x",
        [(inno_license.name, _read_text(inno_license))],
    )
    return "\n".join(sections).rstrip() + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("output", type=Path)
    parser.add_argument(
        "--repository-root",
        type=Path,
        default=Path(__file__).resolve().parents[3],
    )
    args = parser.parse_args()

    try:
        bundle = generate_bundle(args.repository_root.resolve())
    except LicenseBundleError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(bundle, encoding="utf-8", newline="\n")
    print(f"Generated third-party license bundle: {args.output.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
