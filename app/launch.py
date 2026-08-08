"""One-click, no-console launcher for RedactLens.

Windows entry point: double-click ``RedactLens.vbs``. It runs this module
under pythonw.exe, so no console window appears.

What it does:
  1. If a RedactLens server is already running, opens the desktop window to it.
  2. Rebuilds the frontend (hidden npm) only when the build is missing or
     older than the sources; a checkout that shipped with ``packages/frontend/dist``
     never needs npm at all.
  3. Starts the API server -- which also serves the built UI, so one process
     is the whole app -- and opens a branded native WebView window.

Closing that window also closes the server. If WebView2 is unavailable, the
launcher falls back to the default browser and the server exits after ~15
minutes with no requests. Errors surface as GUI dialogs, never a console.
"""

import os
import socket
import subprocess
import sys
import threading
import time
import webbrowser
from collections.abc import Callable
from pathlib import Path
from shutil import copy2, copytree, which
from typing import Any, Protocol
from urllib.request import urlopen


def _resource_root() -> Path:
    """Return the source root or PyInstaller's extracted resource root."""
    bundled = getattr(sys, "_MEIPASS", None)
    if getattr(sys, "frozen", False) and bundled:
        return Path(bundled).resolve()
    return Path(__file__).resolve().parent


def _application_root() -> Path:
    """Return the source checkout or installed executable directory."""
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent


def _migrate_legacy_user_data(base: Path, destination: Path) -> None:
    """Carry forward user preferences from installations using the former name."""
    legacy = base / "RedactScout"
    if not legacy.is_dir():
        return

    try:
        destination.mkdir(parents=True, exist_ok=True)
    except OSError:
        return

    legacy_theme = legacy / "appearance-theme"
    current_theme = destination / "appearance-theme"
    if legacy_theme.is_file() and not current_theme.exists():
        try:
            copy2(legacy_theme, current_theme)
        except OSError:
            pass

    legacy_webview = legacy / "webview"
    current_webview = destination / "webview"
    if legacy_webview.is_dir() and not current_webview.exists():
        try:
            copytree(legacy_webview, current_webview)
        except OSError:
            pass


def _launcher_log_file() -> Path:
    """Choose a user-writable log path for an installed windowed build."""
    if not getattr(sys, "frozen", False):
        return _application_root() / "redactlens-launcher.log"

    candidates = [os.environ.get("LOCALAPPDATA"), os.environ.get("TEMP")]
    for candidate in candidates:
        if not candidate:
            continue
        base = Path(candidate)
        directory = base / "RedactLens"
        try:
            directory.mkdir(parents=True, exist_ok=True)
        except OSError:
            continue
        _migrate_legacy_user_data(base, directory)
        return directory / "redactlens-launcher.log"
    return _application_root() / "redactlens-launcher.log"


RESOURCE_ROOT = _resource_root()
ROOT = _application_root()
FRONTEND_ROOT = (
    RESOURCE_ROOT / "frontend" if getattr(sys, "frozen", False) else ROOT / "packages" / "frontend"
)
DIST = FRONTEND_ROOT / "dist"
LOG_FILE = _launcher_log_file()
BRAND_ICON = (
    RESOURCE_ROOT / "branding" / "redactlens.ico"
    if getattr(sys, "frozen", False)
    else ROOT / "assets" / "branding" / "redactlens.ico"
)
SPLASH_IMAGE = (
    RESOURCE_ROOT / "branding" / "redactlens-splash.bmp"
    if getattr(sys, "frozen", False)
    else ROOT / "assets" / "branding" / "redactlens-splash.bmp"
)
SPLASH_DARK_IMAGE = (
    RESOURCE_ROOT / "branding" / "redactlens-splash-dark.bmp"
    if getattr(sys, "frozen", False)
    else ROOT / "assets" / "branding" / "redactlens-splash-dark.bmp"
)
WEBVIEW_STORAGE = (
    LOG_FILE.parent / "webview" if getattr(sys, "frozen", False) else ROOT / ".cache" / "webview"
)
APPEARANCE_THEME_FILE = (
    LOG_FILE.parent / "appearance-theme"
    if getattr(sys, "frozen", False)
    else ROOT / ".cache" / "appearance-theme"
)
# First free port wins; the UI is served same-origin, so any port works.
PORTS = range(8000, 8011)
IDLE_EXIT_MINUTES = "15"
# Matches run.bat: point RedactLens at the model that's actually pulled unless
# the user already chose one.
DEFAULT_OLLAMA_MODEL = "qwen3-coder:30b"
PICKER_CHILD_FLAG = "--redactlens-picker"
_startup_splash: Any | None = None
_startup_theme = "light"


class _StoppableServer(Protocol):
    should_exit: bool


def _reinstall_signal_file() -> Path | None:
    """Return the installer-to-app graceful shutdown signal for frozen builds."""
    if not getattr(sys, "frozen", False):
        return None
    base = os.environ.get("LOCALAPPDATA") or os.environ.get("TEMP")
    if not base:
        return None
    return Path(base) / "RedactLens" / "reinstall.shutdown"


def _remove_reinstall_signal(signal_file: Path) -> None:
    try:
        signal_file.unlink(missing_ok=True)
    except OSError:
        pass


def _watch_for_reinstall(
    server: _StoppableServer,
    signal_file: Path,
    *,
    poll_seconds: float = 0.2,
    on_signal: Callable[[], None] | None = None,
) -> None:
    """Ask Uvicorn to drain and exit when the installer requests a repair."""
    while not server.should_exit:
        if signal_file.is_file():
            server.should_exit = True
            if on_signal is not None:
                on_signal()
            return
        time.sleep(poll_seconds)


def ensure_streams() -> None:
    """Give a console-less process real stdout/stderr.

    Under pythonw there is no console, so sys.stdout and sys.stderr are None
    -- and uvicorn's logging setup calls .isatty() on them, which would crash
    the server before it ever binds. Point them at a log file instead:
    startup can't crash on logging, and there's somewhere to look when
    something goes wrong.
    """
    if sys.stdout is not None and sys.stderr is not None:
        return
    log = open(LOG_FILE, "a", buffering=1, encoding="utf-8", errors="replace")
    if sys.stdout is None:
        sys.stdout = log
    if sys.stderr is None:
        sys.stderr = log


def _windows_prefers_dark_theme() -> bool:
    """Match the browser's first-run color-scheme choice on Windows."""
    if sys.platform != "win32":
        return False
    try:
        import winreg

        key_path = r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize"
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path) as key:
            value, _value_type = winreg.QueryValueEx(key, "AppsUseLightTheme")
        return int(value) == 0
    except (OSError, TypeError, ValueError):
        return False


def _preferred_theme() -> str:
    """Return the last in-app choice, migrating older WebView-only storage."""
    try:
        saved = APPEARANCE_THEME_FILE.read_text(encoding="ascii").strip()
        if saved in {"light", "dark"}:
            return saved
    except OSError:
        pass

    legacy_theme = _legacy_webview_theme()
    if legacy_theme is not None:
        try:
            APPEARANCE_THEME_FILE.parent.mkdir(parents=True, exist_ok=True)
            APPEARANCE_THEME_FILE.write_text(legacy_theme, encoding="ascii")
        except OSError:
            pass
        return legacy_theme
    return "dark" if _windows_prefers_dark_theme() else "light"


def _legacy_webview_theme() -> str | None:
    """Recover the old localStorage theme before WebView starts.

    Chromium's local-storage LevelDB records ASCII keys and short string
    values together. The frontend wrote this value on every launch, so the
    newest matching record is the effective preference. This is a read-only
    migration fallback; all new builds use ``APPEARANCE_THEME_FILE``.
    """
    leveldb = WEBVIEW_STORAGE / "EBWebView" / "Default" / "Local Storage" / "leveldb"
    try:
        candidates = sorted(
            (
                path
                for path in leveldb.iterdir()
                if path.is_file() and path.suffix.lower() in {".log", ".ldb", ".sst"}
            ),
            key=lambda path: (path.stat().st_mtime_ns, path.name),
            reverse=True,
        )
    except OSError:
        return None

    encoded_values = {
        "light": (
            b"redactlens-theme\x06\x01light",
            b"redactscout-theme\x06\x01light",
        ),
        "dark": (
            b"redactlens-theme\x05\x01dark",
            b"redactscout-theme\x05\x01dark",
        ),
    }
    for candidate in candidates:
        try:
            content = candidate.read_bytes()
        except OSError:
            continue
        positions = {
            theme: max(content.rfind(value) for value in values)
            for theme, values in encoded_values.items()
        }
        theme, position = max(positions.items(), key=lambda item: item[1])
        if position >= 0:
            return theme
    return None


def _show_startup_splash() -> None:
    """Show the packaged native splash without delaying source or helper runs."""
    global _startup_splash, _startup_theme
    _startup_theme = _preferred_theme()
    image_path = SPLASH_DARK_IMAGE if _startup_theme == "dark" else SPLASH_IMAGE
    if (
        not getattr(sys, "frozen", False)
        or os.environ.get("PYINSTALLER_SUPPRESS_SPLASH_SCREEN") == "1"
        or not image_path.is_file()
    ):
        return
    try:
        from startup_splash import StartupSplash

        _startup_splash = StartupSplash(image_path, dark=_startup_theme == "dark")
        _startup_splash.show()
    except Exception:
        _startup_splash = None


def _update_startup_splash(message: str) -> None:
    """Update startup progress when the packaged splash is visible."""
    try:
        if _startup_splash is not None:
            _startup_splash.update(message)
    except Exception:
        pass


def _close_startup_splash(*_args: object) -> None:
    """Close the packaged splash once the real interface is ready."""
    global _startup_splash
    splash = _startup_splash
    _startup_splash = None
    try:
        if splash is not None:
            splash.close()
    except Exception:
        pass


def fail(message: str) -> None:
    """Report a fatal error without relying on optional GUI packages."""
    _close_startup_splash()
    try:
        import ctypes

        ctypes.windll.user32.MessageBoxW(None, message, "RedactLens", 0x10)
    except Exception:
        pass
    sys.exit(message)


def port_is_free(port: int) -> bool:
    with socket.socket() as probe:
        probe.settimeout(0.25)
        return probe.connect_ex(("127.0.0.1", port)) != 0


def is_redactlens(port: int) -> bool:
    """True if something answering like the RedactLens API is on this port."""
    # Cheap socket probe first: only pay for an HTTP round-trip on ports
    # that actually have a listener (a bare urlopen against a dead port can
    # eat its whole timeout, and we scan eleven ports at startup).
    if port_is_free(port):
        return False
    # Identify via /detectors, NOT /health: health round-trips to Ollama and
    # can exceed any sane probe timeout, which once made this launcher start
    # a duplicate server next to a perfectly healthy one.
    try:
        with urlopen(f"http://127.0.0.1:{port}/detectors", timeout=3) as response:
            return b"risk_lesson" in response.read()
    except OSError:
        return False


def newest_source_mtime() -> float:
    """Newest mtime among the frontend inputs that affect the build."""
    candidates = [FRONTEND_ROOT / "index.html", FRONTEND_ROOT / "package.json"]
    src = FRONTEND_ROOT / "src"
    if src.is_dir():
        candidates.extend(p for p in src.rglob("*") if p.is_file())
    return max((p.stat().st_mtime for p in candidates if p.exists()), default=0.0)


def ensure_frontend_build() -> None:
    index = DIST / "index.html"
    have_build = index.is_file()
    if have_build and index.stat().st_mtime >= newest_source_mtime():
        return

    if getattr(sys, "frozen", False):
        fail(
            "The RedactLens installation is incomplete because its bundled UI is missing.\n\n"
            "Reinstall RedactLens and try again."
        )

    npm = which("npm.cmd") or which("npm.exe")
    if npm is None:
        if have_build:
            return  # stale but usable beats a hard failure
        fail(
            "The RedactLens UI hasn't been built yet and npm wasn't found.\n\n"
            "Run 'npm install' then 'npm run build' inside packages/frontend/ "
            "folder once, and launch again."
        )

    result = subprocess.run(
        [npm, "run", "build"],
        cwd=FRONTEND_ROOT,
        capture_output=True,
        creationflags=subprocess.CREATE_NO_WINDOW,
    )
    if result.returncode != 0 and not have_build:
        detail = result.stderr.decode(errors="replace").strip()[-600:]
        fail(f"Building the RedactLens UI failed:\n\n{detail}")


def wait_until_ready(port: int, *, timeout_seconds: float = 20) -> bool:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if is_redactlens(port):
            return True
        time.sleep(0.2)
    return False


def open_browser_when_ready(port: int) -> None:
    if wait_until_ready(port):
        _update_startup_splash("Opening your browser...")
        _close_startup_splash()
        webbrowser.open(_fresh_ui_url(f"http://127.0.0.1:{port}"))


def _load_desktop_webview() -> Any | None:
    """Load the optional native host, retaining a browser fallback."""
    try:
        import webview
    except Exception as error:
        print(f"Native RedactLens window is unavailable; using the browser: {error}")
        return None
    return webview


def _close_desktop_windows(webview_module: Any) -> None:
    """Close native windows so a running installer can replace the bundle."""
    for window in tuple(getattr(webview_module, "windows", ())):
        try:
            window.destroy()
        except Exception:
            pass


def _set_windows_app_id() -> None:
    """Give the window its own taskbar identity instead of Edge's identity."""
    try:
        import ctypes

        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("RedactLens.Desktop")
    except Exception:
        pass


def _fresh_ui_url(url: str) -> str:
    """Force each app window to request the current installed frontend."""
    separator = "&" if "?" in url else "?"
    return f"{url}{separator}launch={time.time_ns()}"


def _run_internal_child_mode(arguments: list[str] | None = None) -> int | None:
    """Dispatch short-lived helpers when this module is a frozen executable."""

    args = list(sys.argv[1:] if arguments is None else arguments)
    if not args or args[0] != PICKER_CHILD_FLAG:
        return None
    _close_startup_splash()
    from redactlens_api._pick_dialog import main as picker_main

    return picker_main(args[1:])


def show_desktop_window(webview_module: Any, url: str) -> bool:
    """Show RedactLens in a native branded window; return False on fallback."""
    try:
        _set_windows_app_id()
        WEBVIEW_STORAGE.mkdir(parents=True, exist_ok=True)
        webview_module.settings["ALLOW_DOWNLOADS"] = True
        window = webview_module.create_window(
            "RedactLens",
            _fresh_ui_url(url),
            width=1180,
            height=820,
            min_size=(760, 560),
            background_color="#181c19" if _startup_theme == "dark" else "#f6f4ee",
            text_select=True,
            zoomable=True,
        )
        if window is not None:
            window.events.loaded += _close_startup_splash
        start_options: dict[str, str] = {}
        if BRAND_ICON.is_file():
            start_options["icon"] = str(BRAND_ICON)
        webview_module.start(
            gui="edgechromium",
            debug=False,
            private_mode=False,
            storage_path=str(WEBVIEW_STORAGE),
            **start_options,
        )
        return True
    except Exception:
        _close_startup_splash()
        import traceback

        traceback.print_exc()
        return False


def main() -> None:
    if sys.platform != "win32":
        raise SystemExit("RedactLens supports Microsoft Windows only.")

    os.environ["REDACTLENS_APPEARANCE_THEME_FILE"] = str(APPEARANCE_THEME_FILE)
    _show_startup_splash()
    ensure_streams()
    _update_startup_splash("Preparing your private workspace...")
    os.environ.setdefault("REDACTLENS_OLLAMA_MODEL", DEFAULT_OLLAMA_MODEL)
    os.environ.setdefault("REDACTLENS_IDLE_EXIT_MINUTES", IDLE_EXIT_MINUTES)

    # Rebuild (when stale) before the reuse check. Each window also opens a
    # cache-busted URL so WebView2 cannot retain an older installed UI.
    ensure_frontend_build()
    no_window = bool(os.environ.get("REDACTLENS_NO_BROWSER"))
    _update_startup_splash("Checking local services...")
    desktop_webview = None if no_window else _load_desktop_webview()

    # Already running (a previous click, or run.bat)? Reuse it.
    for port in PORTS:
        if is_redactlens(port):
            if not no_window:
                _update_startup_splash("Opening RedactLens...")
                url = f"http://127.0.0.1:{port}"
                if desktop_webview is None or not show_desktop_window(desktop_webview, url):
                    _close_startup_splash()
                    webbrowser.open(_fresh_ui_url(url))
            else:
                _close_startup_splash()
            return

    _update_startup_splash("Loading the scanner engine...")
    try:
        import redactlens_api.main  # noqa: F401  (fail fast if deps are missing)
        import uvicorn
    except ImportError as e:
        fail(
            "RedactLens's Python packages aren't installed in this environment "
            f"({e}).\n\nRun the dev-setup steps in README.md first."
        )
        return  # unreachable; keeps type-checkers happy

    port = next((p for p in PORTS if port_is_free(p)), None)
    if port is None:
        fail(f"No free port between {PORTS[0]} and {PORTS[-1]} to start RedactLens on.")
        return

    reinstall_signal = _reinstall_signal_file()
    if reinstall_signal is not None:
        # A forced shutdown from an older installer may leave a stale signal.
        # Clear it before listening for a new repair request.
        _remove_reinstall_signal(reinstall_signal)

    server = uvicorn.Server(
        uvicorn.Config(
            "redactlens_api.main:app",
            host="127.0.0.1",
            port=port,
            log_level="warning",
            access_log=False,
        )
    )
    _update_startup_splash("Starting the on-device service...")
    if reinstall_signal is not None:
        threading.Thread(
            target=_watch_for_reinstall,
            args=(server, reinstall_signal),
            kwargs={
                "on_signal": (
                    (lambda: _close_desktop_windows(desktop_webview))
                    if desktop_webview is not None
                    else None
                )
            },
            daemon=True,
        ).start()
    try:
        if desktop_webview is None:
            if no_window:
                _close_startup_splash()
            if not no_window:
                threading.Thread(
                    target=open_browser_when_ready,
                    args=(port,),
                    daemon=True,
                ).start()
            server.run()
        else:
            server_thread = threading.Thread(target=server.run, daemon=True)
            server_thread.start()
            if not wait_until_ready(port):
                server.should_exit = True
                server_thread.join(timeout=5)
                fail("RedactLens's local service did not become ready in time.")
            _update_startup_splash("Opening your workspace...")
            url = f"http://127.0.0.1:{port}"
            if show_desktop_window(desktop_webview, url):
                server.should_exit = True
            else:
                # A missing WebView2 runtime should not make the app unusable.
                _close_startup_splash()
                webbrowser.open(_fresh_ui_url(url))
            server_thread.join()
    finally:
        server.should_exit = True
        if reinstall_signal is not None:
            # Its disappearance tells Setup the graceful shutdown completed.
            _remove_reinstall_signal(reinstall_signal)


if __name__ == "__main__":
    child_exit = _run_internal_child_mode()
    if child_exit is not None:
        raise SystemExit(child_exit)
    try:
        main()
    except SystemExit:
        raise
    except Exception:
        import traceback

        try:
            with open(LOG_FILE, "a", encoding="utf-8", errors="replace") as log:
                traceback.print_exc(file=log)
        except OSError:
            pass
        fail(f"RedactLens failed to start. Details were written to:\n\n{LOG_FILE}")
