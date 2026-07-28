"""Generate deterministic PyInstaller Windows version metadata."""

from __future__ import annotations

import argparse
import re
from dataclasses import dataclass
from pathlib import Path

_VERSION = re.compile(
    r"^(?P<major>0|[1-9]\d*)\."
    r"(?P<minor>0|[1-9]\d*)\."
    r"(?P<patch>0|[1-9]\d*)"
    r"(?P<suffix>(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?)$"
)


@dataclass(frozen=True)
class ReleaseVersion:
    text: str
    numeric: tuple[int, int, int, int]


def parse_version(value: str) -> ReleaseVersion:
    match = _VERSION.fullmatch(value)
    if match is None:
        raise ValueError("version must be SemVer-like MAJOR.MINOR.PATCH[-PRERELEASE][+BUILD]")
    numeric = tuple(int(match.group(name)) for name in ("major", "minor", "patch")) + (0,)
    if any(part > 65_535 for part in numeric):
        raise ValueError("numeric version components must not exceed 65535")
    return ReleaseVersion(text=value, numeric=numeric)


def render_version_info(version: ReleaseVersion) -> str:
    numeric = ", ".join(str(part) for part in version.numeric)
    return f"""# UTF-8
VSVersionInfo(
  ffi=FixedFileInfo(
    filevers=({numeric}),
    prodvers=({numeric}),
    mask=0x3f,
    flags=0x0,
    OS=0x40004,
    fileType=0x1,
    subtype=0x0,
    date=(0, 0),
  ),
  kids=[
    StringFileInfo([
      StringTable(
        '040904B0',
        [
          StringStruct('CompanyName', 'RedactLens'),
          StringStruct('FileDescription', 'RedactLens local sensitive-data scanner'),
          StringStruct('FileVersion', '{version.text}'),
          StringStruct('InternalName', 'RedactLens'),
          StringStruct('OriginalFilename', 'RedactLens.exe'),
          StringStruct('ProductName', 'RedactLens'),
          StringStruct('ProductVersion', '{version.text}'),
        ],
      )
    ]),
    VarFileInfo([VarStruct('Translation', [1033, 1200])]),
  ],
)
"""


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("version")
    parser.add_argument("output", type=Path)
    args = parser.parse_args()

    try:
        version = parse_version(args.version)
    except ValueError as error:
        parser.error(str(error))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(render_version_info(version), encoding="utf-8", newline="\n")
    print(args.output.resolve())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
