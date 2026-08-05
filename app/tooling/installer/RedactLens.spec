# -*- mode: python ; coding: utf-8 -*-

import os
from pathlib import Path

from PyInstaller.utils.hooks import collect_submodules

project_root = Path(SPECPATH).resolve().parents[1]
frontend_dist = project_root / "packages" / "frontend" / "dist"
detectors = project_root / "packages" / "redactlens-core" / "redactlens_core" / "detectors"
version_file = Path(os.environ.get("REDACTLENS_VERSION_FILE", ""))

if not (frontend_dist / "index.html").is_file():
    raise SystemExit(
        "packages/frontend/dist is missing; run the frontend production build first"
    )
if not detectors.is_dir():
    raise SystemExit("the built-in detector directory is missing")
if not version_file.is_file():
    raise SystemExit("REDACTLENS_VERSION_FILE must identify generated version metadata")

hiddenimports = sorted(
    {
        *collect_submodules("ollama"),
        *collect_submodules("redactlens_api"),
        *collect_submodules("redactlens_core"),
        *collect_submodules("uvicorn"),
        *collect_submodules("webview"),
    }
)

a = Analysis(
    [str(project_root / "launch.py")],
    pathex=[
        str(project_root),
        str(project_root / "packages" / "api"),
        str(project_root / "packages" / "redactlens-core"),
    ],
    binaries=[],
    datas=[
        (str(frontend_dist), "frontend/dist"),
        (str(detectors), "redactlens_core/detectors"),
        (str(project_root / "assets" / "branding" / "redactlens.ico"), "branding"),
        (str(project_root / "assets" / "branding" / "redactlens-splash.bmp"), "branding"),
        (str(project_root / "assets" / "branding" / "redactlens-splash-dark.bmp"), "branding"),
        (
            str(project_root / "assets" / "branding" / "redactlens-splash-spinner.bmp"),
            "branding",
        ),
        (
            str(project_root / "assets" / "branding" / "redactlens-splash-spinner-dark.bmp"),
            "branding",
        ),
    ],
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["pytest", "ruff", "tkinter.test"],
    noarchive=False,
    optimize=1,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="RedactLens",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=str(project_root / "assets" / "branding" / "redactlens.ico"),
    version=str(version_file),
    contents_directory="_internal",
)
coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    name="RedactLens",
)
