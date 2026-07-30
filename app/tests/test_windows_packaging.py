from __future__ import annotations

import struct
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import launch
import pytest
from PIL import Image
from tooling.installer.generate_icon_assets import ACCENT_SOFT, DARK_ACCENT_SOFT
from tooling.installer.generate_version_info import parse_version, render_version_info
from tooling.installer.validate_bundle import (
    GENERATED_LEGAL_DOCUMENT,
    LEGAL_DOCUMENTS,
    REQUIRED_LICENSE_COMPONENTS,
    validate_bundle,
)

ROOT = Path(__file__).resolve().parents[1]
REPOSITORY_ROOT = ROOT.parent


def _bitmap_dimensions(path: Path) -> tuple[int, int]:
    return struct.unpack_from("<ii", path.read_bytes(), 18)


@pytest.mark.parametrize(
    ("value", "numeric"),
    [
        ("0.1.0", (0, 1, 0, 0)),
        ("12.34.56-rc.1+build.7", (12, 34, 56, 0)),
    ],
)
def test_release_version_metadata_is_deterministic(
    value: str,
    numeric: tuple[int, int, int, int],
) -> None:
    parsed = parse_version(value)

    assert parsed.numeric == numeric
    assert render_version_info(parsed) == render_version_info(parsed)
    assert f"StringStruct('ProductVersion', '{value}')" in render_version_info(parsed)


@pytest.mark.parametrize("value", ["v1.2.3", "1.2", "01.2.3", "1.2.3/unsafe", "65536.0.0"])
def test_release_version_rejects_unsafe_or_unrepresentable_values(value: str) -> None:
    with pytest.raises(ValueError):
        parse_version(value)


def test_frozen_launcher_uses_extracted_resources_and_writable_log(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    resource_root = tmp_path / "extracted"
    executable = tmp_path / "installed" / "RedactLens.exe"
    local_app_data = tmp_path / "local-app-data"
    monkeypatch.setattr(launch.sys, "frozen", True, raising=False)
    monkeypatch.setattr(launch.sys, "_MEIPASS", str(resource_root), raising=False)
    monkeypatch.setattr(launch.sys, "executable", str(executable))
    monkeypatch.setenv("LOCALAPPDATA", str(local_app_data))

    assert launch._resource_root() == resource_root.resolve()
    assert launch._application_root() == executable.parent.resolve()
    expected_log = local_app_data / "RedactLens" / "redactlens-launcher.log"
    assert launch._launcher_log_file() == expected_log


def test_frozen_launcher_migrates_legacy_preferences_once(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    legacy = tmp_path / "RedactScout"
    (legacy / "webview").mkdir(parents=True)
    (legacy / "appearance-theme").write_text("dark", encoding="ascii")
    (legacy / "webview" / "settings.db").write_bytes(b"legacy-preferences")
    monkeypatch.setattr(launch.sys, "frozen", True, raising=False)
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))

    launch._launcher_log_file()

    current = tmp_path / "RedactLens"
    assert (current / "appearance-theme").read_text(encoding="ascii") == "dark"
    assert (current / "webview" / "settings.db").read_bytes() == b"legacy-preferences"

    (legacy / "appearance-theme").write_text("light", encoding="ascii")
    launch._launcher_log_file()
    assert (current / "appearance-theme").read_text(encoding="ascii") == "dark"


def test_frozen_launcher_honors_reinstall_shutdown_signal(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(launch.sys, "frozen", True, raising=False)
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    signal_file = launch._reinstall_signal_file()
    assert signal_file == tmp_path / "RedactLens" / "reinstall.shutdown"
    signal_file.parent.mkdir(parents=True)
    signal_file.write_text("reinstall", encoding="utf-8")
    server = SimpleNamespace(should_exit=False)

    launch._watch_for_reinstall(server, signal_file, poll_seconds=0)

    assert server.should_exit is True
    assert signal_file.is_file()
    launch._remove_reinstall_signal(signal_file)
    assert not signal_file.exists()


def test_frozen_launcher_dispatches_picker_child_without_starting_the_app(monkeypatch) -> None:
    from redactlens_api import _pick_dialog

    picker_main = Mock(return_value=7)
    monkeypatch.setattr(_pick_dialog, "main", picker_main)

    assert launch._run_internal_child_mode(["ordinary-app-argument"]) is None
    assert (
        launch._run_internal_child_mode(
            [
                launch.PICKER_CHILD_FLAG,
                "file",
                "C:\\Temp\\redactlens-picker-result.txt",
                "300.0",
            ]
        )
        == 7
    )
    picker_main.assert_called_once_with(["file", "C:\\Temp\\redactlens-picker-result.txt", "300.0"])


def test_desktop_window_uses_brand_identity_and_persistent_storage(monkeypatch) -> None:
    class LoadedEvent:
        handler = None

        def __iadd__(self, handler):
            self.handler = handler
            return self

    loaded_event = LoadedEvent()
    created_window = SimpleNamespace(events=SimpleNamespace(loaded=loaded_event))
    desktop_window = SimpleNamespace(
        settings={},
        create_window=Mock(return_value=created_window),
        start=Mock(),
    )
    monkeypatch.setattr(launch.time, "time_ns", lambda: 1234567890)

    assert launch.show_desktop_window(desktop_window, "http://127.0.0.1:8000") is True
    desktop_window.create_window.assert_called_once_with(
        "RedactLens",
        "http://127.0.0.1:8000?launch=1234567890",
        width=1180,
        height=820,
        min_size=(760, 560),
        background_color="#f6f4ee",
        text_select=True,
    )
    assert desktop_window.settings["ALLOW_DOWNLOADS"] is True
    assert desktop_window.start.call_args.kwargs["gui"] == "edgechromium"
    assert desktop_window.start.call_args.kwargs["private_mode"] is False
    assert desktop_window.start.call_args.kwargs["icon"] == str(launch.BRAND_ICON)
    assert loaded_event.handler is launch._close_startup_splash


def test_packaged_splash_status_and_close_are_safe(monkeypatch) -> None:
    splash = SimpleNamespace(update=Mock(), close=Mock())
    monkeypatch.setattr(launch, "_startup_splash", splash)

    launch._update_startup_splash("Opening your workspace...")
    launch._close_startup_splash()

    splash.update.assert_called_once_with("Opening your workspace...")
    splash.close.assert_called_once_with()
    assert launch._startup_splash is None


def test_launcher_prefers_saved_theme_then_falls_back_to_windows(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    theme_file = tmp_path / "appearance-theme"
    monkeypatch.setattr(launch, "APPEARANCE_THEME_FILE", theme_file)
    monkeypatch.setattr(launch, "WEBVIEW_STORAGE", tmp_path / "empty-webview")
    monkeypatch.setattr(launch, "_windows_prefers_dark_theme", Mock(return_value=True))

    assert launch._preferred_theme() == "dark"
    theme_file.write_text("light", encoding="ascii")
    assert launch._preferred_theme() == "light"
    theme_file.write_text("invalid", encoding="ascii")
    assert launch._preferred_theme() == "dark"


def test_launcher_migrates_existing_webview_theme_before_first_splash(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    theme_file = tmp_path / "appearance-theme"
    webview_storage = tmp_path / "webview"
    leveldb = webview_storage / "EBWebView" / "Default" / "Local Storage" / "leveldb"
    leveldb.mkdir(parents=True)
    (leveldb / "000003.log").write_bytes(
        b"redactlens-theme\x06\x01light\x00newer-record\x00redactlens-theme\x05\x01dark"
    )
    windows_theme = Mock(return_value=False)
    monkeypatch.setattr(launch, "APPEARANCE_THEME_FILE", theme_file)
    monkeypatch.setattr(launch, "WEBVIEW_STORAGE", webview_storage)
    monkeypatch.setattr(launch, "_windows_prefers_dark_theme", windows_theme)

    assert launch._preferred_theme() == "dark"
    assert theme_file.read_text(encoding="ascii") == "dark"
    windows_theme.assert_not_called()


def test_launcher_reads_theme_from_legacy_webview_storage(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    theme_file = tmp_path / "appearance-theme"
    webview_storage = tmp_path / "webview"
    leveldb = webview_storage / "EBWebView" / "Default" / "Local Storage" / "leveldb"
    leveldb.mkdir(parents=True)
    (leveldb / "000003.log").write_bytes(b"redactscout-theme\x05\x01dark")
    monkeypatch.setattr(launch, "APPEARANCE_THEME_FILE", theme_file)
    monkeypatch.setattr(launch, "WEBVIEW_STORAGE", webview_storage)
    monkeypatch.setattr(launch, "_windows_prefers_dark_theme", Mock(return_value=False))

    assert launch._preferred_theme() == "dark"
    assert theme_file.read_text(encoding="ascii") == "dark"


def _fake_bundle(tmp_path: Path) -> tuple[Path, Path]:
    source_root = tmp_path / "source"
    legal_contents = {
        "LICENSE": "MIT License\n",
        "THIRD_PARTY_NOTICES.md": "# Third-party notices\n",
    }
    for bundle_name, source_relative in LEGAL_DOCUMENTS.items():
        source_document = source_root.parent / source_relative
        source_document.parent.mkdir(parents=True, exist_ok=True)
        source_document.write_text(legal_contents[bundle_name], encoding="utf-8")

    source_detectors = (
        source_root / "packages" / "redactlens-core" / "redactlens_core" / "detectors"
    )
    source_detectors.mkdir(parents=True)
    (source_detectors / "secrets.yaml").write_text("detectors: []\n", encoding="utf-8")

    bundle = tmp_path / "bundle"
    content = bundle / "_internal"
    frontend = content / "frontend" / "dist"
    frontend_assets = frontend / "assets"
    bundled_detectors = content / "redactlens_core" / "detectors"
    frontend_assets.mkdir(parents=True)
    bundled_detectors.mkdir(parents=True)
    (bundle / "RedactLens.exe").write_bytes(b"MZ")
    for name, contents in legal_contents.items():
        (bundle / name).write_text(contents, encoding="utf-8")
    generated_license_text = (
        "\n".join(REQUIRED_LICENSE_COMPONENTS) + "\n" + ("license text\n" * 5_000)
    )
    (bundle / GENERATED_LEGAL_DOCUMENT).write_text(
        generated_license_text,
        encoding="utf-8",
    )
    (frontend / "index.html").write_text(
        '<div id="root"></div><script src="/assets/app.js"></script>',
        encoding="utf-8",
    )
    (frontend_assets / "app.js").write_text("export {};\n", encoding="utf-8")
    (bundled_detectors / "secrets.yaml").write_text("detectors: []\n", encoding="utf-8")
    return bundle, source_root


def test_bundle_validation_covers_ui_assets_and_detector_data(tmp_path: Path) -> None:
    bundle, source_root = _fake_bundle(tmp_path)

    assert validate_bundle(bundle, source_root) == []

    (bundle / "_internal" / "frontend" / "dist" / "assets" / "app.js").unlink()
    assert validate_bundle(bundle, source_root) == [
        "frontend asset reference is missing: /assets/app.js"
    ]


def test_bundle_validation_requires_current_legal_documents(tmp_path: Path) -> None:
    bundle, source_root = _fake_bundle(tmp_path)

    (bundle / "LICENSE").unlink()
    assert validate_bundle(bundle, source_root) == ["the bundled LICENSE is missing or empty"]

    (bundle / "LICENSE").write_text("MIT License\n", encoding="utf-8")
    (bundle / "THIRD_PARTY_NOTICES.md").write_text("outdated\n", encoding="utf-8")
    assert validate_bundle(bundle, source_root) == [
        "the bundled THIRD_PARTY_NOTICES.md differs from the repository copy"
    ]

    (bundle / "THIRD_PARTY_NOTICES.md").write_text(
        "# Third-party notices\n",
        encoding="utf-8",
    )
    (bundle / GENERATED_LEGAL_DOCUMENT).unlink()
    assert validate_bundle(bundle, source_root) == [
        "the bundled THIRD_PARTY_LICENSES.txt is missing or empty"
    ]


def test_release_uses_redactlens_brand_icon() -> None:
    browser_mark = ROOT / "packages" / "frontend" / "public" / "redactlens-mark.svg"
    icon = ROOT / "assets" / "branding" / "redactlens.ico"
    small_wizard_mark = ROOT / "assets" / "branding" / "redactlens-icon.png"
    wizard_image = ROOT / "assets" / "branding" / "redactlens-installer-wizard.png"
    splash_image = ROOT / "assets" / "branding" / "redactlens-splash.png"
    splash_bitmap = ROOT / "assets" / "branding" / "redactlens-splash.bmp"
    dark_splash_image = ROOT / "assets" / "branding" / "redactlens-splash-dark.png"
    dark_splash_bitmap = ROOT / "assets" / "branding" / "redactlens-splash-dark.bmp"
    pyinstaller_spec = (ROOT / "tooling" / "installer" / "RedactLens.spec").read_text(
        encoding="utf-8"
    )
    inno_setup = (ROOT / "tooling" / "installer" / "RedactLens.iss").read_text(encoding="utf-8")

    assert "#356f4e" in browser_mark.read_text(encoding="utf-8")
    assert icon.is_file() and icon.stat().st_size > 0
    assert small_wizard_mark.is_file() and small_wizard_mark.stat().st_size > 0
    assert wizard_image.is_file() and wizard_image.stat().st_size > 0
    assert splash_image.is_file() and splash_image.stat().st_size > 0
    assert splash_bitmap.is_file() and splash_bitmap.stat().st_size > 0
    assert dark_splash_image.is_file() and dark_splash_image.stat().st_size > 0
    assert dark_splash_bitmap.is_file() and dark_splash_bitmap.stat().st_size > 0
    assert _bitmap_dimensions(splash_bitmap) == (1200, 720)
    assert _bitmap_dimensions(dark_splash_bitmap) == (1200, 720)
    assert 'assets" / "branding" / "redactlens.ico"' in pyinstaller_spec
    assert "SetupIconFile=..\\..\\assets\\branding\\redactlens.ico" in inno_setup
    assert "WizardImageFile=..\\..\\assets\\branding\\redactlens-installer-wizard.png" in inno_setup
    assert "WizardSmallImageFile=..\\..\\assets\\branding\\redactlens-icon.png" in inno_setup
    assert 'assets" / "branding" / "redactlens-splash.bmp"' in pyinstaller_spec
    assert 'assets" / "branding" / "redactlens-splash-dark.bmp"' in pyinstaller_spec
    assert 'IconFilename: "{app}\\RedactLens.ico"' in inno_setup
    assert 'AppUserModelID: "RedactLens.Desktop"' in inno_setup


def test_splash_footer_has_square_corners() -> None:
    splash_assets = (
        ("redactlens-splash.png", ACCENT_SOFT),
        ("redactlens-splash-dark.png", DARK_ACCENT_SOFT),
    )

    for filename, footer_color in splash_assets:
        with Image.open(ROOT / "assets" / "branding" / filename) as image:
            assert image.convert("RGBA").getpixel((image.width - 1, 288 * 2)) == footer_color


def test_installer_opens_with_a_welcome_page() -> None:
    inno_setup = (ROOT / "tooling" / "installer" / "RedactLens.iss").read_text(encoding="utf-8")

    assert "DisableWelcomePage=no" in inno_setup


def test_installer_supports_running_app_repair_and_prior_shortcut_choices() -> None:
    inno_setup = (ROOT / "tooling" / "installer" / "RedactLens.iss").read_text(encoding="utf-8")

    assert "CloseApplications=force" in inno_setup
    assert "CloseApplicationsFilter=RedactLens.exe,RedactScout.exe" in inno_setup
    assert "RestartApplications=no" in inno_setup
    assert "UsePreviousTasks=yes" in inno_setup
    assert "UsePreviousAppDir=no" in inno_setup
    assert "UsePreviousGroup=no" in inno_setup
    assert "function PrepareToInstall" in inno_setup
    assert "reinstall.shutdown" in inno_setup
    assert "procedure CleanupLegacyInstallation" in inno_setup
    assert '"{autodesktop}\\RedactScout.lnk"' in inno_setup


def test_windows_workflows_cover_verification_packaging_and_installer_smoke() -> None:
    ci = (REPOSITORY_ROOT / ".github" / "workflows" / "windows-ci.yml").read_text(encoding="utf-8")
    release_workflow = REPOSITORY_ROOT / ".github" / "workflows" / "windows-release.yml"
    release = release_workflow.read_text(encoding="utf-8")

    assert "runs-on: windows-latest" in ci
    assert "python tooling/verify.py" in ci
    assert "npm ci --prefix packages/frontend" in ci
    assert "tooling/installer/constraints-windows.txt" in ci

    assert "runs-on: windows-latest" in release
    assert "tooling/installer/requirements-build.txt" in release
    assert "build_windows.ps1" in release
    assert "smoke_test_installer.ps1" in release
    assert "actions/upload-artifact@v4" in release
    assert "innosetup" in release.lower()
    assert "WINDOWS_CODESIGN_PFX_BASE64" in release
    assert "WINDOWS_CODESIGN_PFX_PASSWORD" in release
    assert "Import-PfxCertificate" in release
    assert '-CodeSigningThumbprint "${{ steps.signing.outputs.thumbprint }}"' in release


def test_windows_build_signs_executables_before_archiving_and_checksumming() -> None:
    build = (ROOT / "tooling" / "installer" / "build_windows.ps1").read_text(encoding="utf-8")

    assert "Set-AuthenticodeSignature" in build
    assert "SignatureStatus]::Valid" in build
    app_signing = build.index('-Path (Join-Path $bundleRoot "RedactLens.exe")')
    archive_creation = build.index("Compress-Archive")
    installer_signing = build.index("-Path $installer `", archive_creation)
    root_copy = build.index("Copy-Item -LiteralPath $installer")
    checksum_creation = build.index("Get-FileHash -Algorithm SHA256")
    assert app_signing < archive_creation < installer_signing < root_copy < checksum_creation


def test_windows_build_includes_legal_documents_before_validation() -> None:
    build = (ROOT / "tooling" / "installer" / "build_windows.ps1").read_text(encoding="utf-8")

    legal_mapping = build.index('Source = "docs\\legal\\THIRD_PARTY_NOTICES.md"')
    legal_copy = build.index("foreach ($legalDocument in $legalDocuments)", legal_mapping)
    validation = build.index('"validate_bundle.py"')
    archive_creation = build.index("Compress-Archive")
    assert legal_mapping < legal_copy < validation < archive_creation
