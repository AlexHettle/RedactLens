"""Dependency-free native Windows startup splash for the packaged app."""

from __future__ import annotations

import ctypes
import sys
import threading
from ctypes import wintypes
from pathlib import Path

_LOGICAL_WIDTH = 600
_LOGICAL_HEIGHT = 360
_STATUS_MESSAGE = 0x8001

_CS_DROPSHADOW = 0x00020000
_WS_POPUP = 0x80000000
_WS_EX_TOPMOST = 0x00000008
_WS_EX_TOOLWINDOW = 0x00000080
_WS_EX_NOACTIVATE = 0x08000000
_SW_SHOWNOACTIVATE = 4

_WM_CLOSE = 0x0010
_WM_DESTROY = 0x0002
_WM_ERASEBKGND = 0x0014
_WM_PAINT = 0x000F

_IMAGE_BITMAP = 0
_LR_LOADFROMFILE = 0x0010
_LR_CREATEDIBSECTION = 0x2000
_HALFTONE = 4
_SRCCOPY = 0x00CC0020
_TRANSPARENT = 1
_DT_LEFT = 0x0000
_DT_VCENTER = 0x0004
_DT_SINGLELINE = 0x0020
_DT_END_ELLIPSIS = 0x8000
_FW_SEMIBOLD = 600
_MONITOR_DEFAULTTONEAREST = 2

_LRESULT = ctypes.c_ssize_t
_WNDPROC = ctypes.WINFUNCTYPE(
    _LRESULT,
    wintypes.HWND,
    wintypes.UINT,
    wintypes.WPARAM,
    wintypes.LPARAM,
)


class _WndClass(ctypes.Structure):
    _fields_ = [
        ("style", wintypes.UINT),
        ("lpfnWndProc", _WNDPROC),
        ("cbClsExtra", ctypes.c_int),
        ("cbWndExtra", ctypes.c_int),
        ("hInstance", wintypes.HINSTANCE),
        ("hIcon", wintypes.HICON),
        ("hCursor", wintypes.HANDLE),
        ("hbrBackground", wintypes.HBRUSH),
        ("lpszMenuName", wintypes.LPCWSTR),
        ("lpszClassName", wintypes.LPCWSTR),
    ]


class _PaintStruct(ctypes.Structure):
    _fields_ = [
        ("hdc", wintypes.HDC),
        ("fErase", wintypes.BOOL),
        ("rcPaint", wintypes.RECT),
        ("fRestore", wintypes.BOOL),
        ("fIncUpdate", wintypes.BOOL),
        ("rgbReserved", wintypes.BYTE * 32),
    ]


class _Bitmap(ctypes.Structure):
    _fields_ = [
        ("bmType", wintypes.LONG),
        ("bmWidth", wintypes.LONG),
        ("bmHeight", wintypes.LONG),
        ("bmWidthBytes", wintypes.LONG),
        ("bmPlanes", wintypes.WORD),
        ("bmBitsPixel", wintypes.WORD),
        ("bmBits", wintypes.LPVOID),
    ]


class _MonitorInfo(ctypes.Structure):
    _fields_ = [
        ("cbSize", wintypes.DWORD),
        ("rcMonitor", wintypes.RECT),
        ("rcWork", wintypes.RECT),
        ("dwFlags", wintypes.DWORD),
    ]


def _rgb(red: int, green: int, blue: int) -> int:
    return red | (green << 8) | (blue << 16)


def _configure_apis(user32: object, gdi32: object, kernel32: object) -> None:
    """Declare pointer-sized Win32 signatures before passing 64-bit handles."""
    kernel32.GetModuleHandleW.argtypes = [wintypes.LPCWSTR]
    kernel32.GetModuleHandleW.restype = wintypes.HINSTANCE

    user32.LoadImageW.argtypes = [
        wintypes.HINSTANCE,
        wintypes.LPCWSTR,
        wintypes.UINT,
        ctypes.c_int,
        ctypes.c_int,
        wintypes.UINT,
    ]
    user32.LoadImageW.restype = wintypes.HANDLE
    user32.LoadCursorW.restype = wintypes.HANDLE
    user32.RegisterClassW.argtypes = [ctypes.POINTER(_WndClass)]
    user32.RegisterClassW.restype = wintypes.ATOM
    user32.CreateWindowExW.argtypes = [
        wintypes.DWORD,
        wintypes.LPCWSTR,
        wintypes.LPCWSTR,
        wintypes.DWORD,
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_int,
        wintypes.HWND,
        wintypes.HANDLE,
        wintypes.HINSTANCE,
        wintypes.LPVOID,
    ]
    user32.CreateWindowExW.restype = wintypes.HWND
    user32.GetCursorPos.argtypes = [ctypes.POINTER(wintypes.POINT)]
    user32.MonitorFromPoint.argtypes = [wintypes.POINT, wintypes.DWORD]
    user32.MonitorFromPoint.restype = wintypes.HANDLE
    user32.ShowWindow.argtypes = [wintypes.HWND, ctypes.c_int]
    user32.UpdateWindow.argtypes = [wintypes.HWND]
    user32.DestroyWindow.argtypes = [wintypes.HWND]
    user32.GetClientRect.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.RECT)]
    user32.GetMonitorInfoW.argtypes = [wintypes.HANDLE, ctypes.POINTER(_MonitorInfo)]
    user32.GetMessageW.argtypes = [
        ctypes.POINTER(wintypes.MSG),
        wintypes.HWND,
        wintypes.UINT,
        wintypes.UINT,
    ]
    user32.TranslateMessage.argtypes = [ctypes.POINTER(wintypes.MSG)]
    user32.DispatchMessageW.argtypes = [ctypes.POINTER(wintypes.MSG)]
    user32.DispatchMessageW.restype = _LRESULT
    user32.UnregisterClassW.argtypes = [wintypes.LPCWSTR, wintypes.HINSTANCE]
    user32.DefWindowProcW.argtypes = [
        wintypes.HWND,
        wintypes.UINT,
        wintypes.WPARAM,
        wintypes.LPARAM,
    ]
    user32.DefWindowProcW.restype = _LRESULT
    user32.BeginPaint.argtypes = [wintypes.HWND, ctypes.POINTER(_PaintStruct)]
    user32.BeginPaint.restype = wintypes.HDC
    user32.EndPaint.argtypes = [wintypes.HWND, ctypes.POINTER(_PaintStruct)]
    user32.PostMessageW.argtypes = [
        wintypes.HWND,
        wintypes.UINT,
        wintypes.WPARAM,
        wintypes.LPARAM,
    ]
    user32.InvalidateRect.argtypes = [
        wintypes.HWND,
        ctypes.POINTER(wintypes.RECT),
        wintypes.BOOL,
    ]
    user32.DrawTextW.argtypes = [
        wintypes.HDC,
        wintypes.LPCWSTR,
        ctypes.c_int,
        ctypes.POINTER(wintypes.RECT),
        wintypes.UINT,
    ]

    gdi32.GetObjectW.argtypes = [wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID]
    gdi32.CreateCompatibleDC.argtypes = [wintypes.HDC]
    gdi32.CreateCompatibleDC.restype = wintypes.HDC
    gdi32.SelectObject.argtypes = [wintypes.HDC, wintypes.HANDLE]
    gdi32.SelectObject.restype = wintypes.HANDLE
    gdi32.SetStretchBltMode.argtypes = [wintypes.HDC, ctypes.c_int]
    gdi32.StretchBlt.argtypes = [
        wintypes.HDC,
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_int,
        wintypes.HDC,
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_int,
        wintypes.DWORD,
    ]
    gdi32.CreateFontW.restype = wintypes.HANDLE
    gdi32.SetBkMode.argtypes = [wintypes.HDC, ctypes.c_int]
    gdi32.SetTextColor.argtypes = [wintypes.HDC, wintypes.DWORD]
    gdi32.DeleteObject.argtypes = [wintypes.HANDLE]
    gdi32.DeleteDC.argtypes = [wintypes.HDC]


class StartupSplash:
    """Own a small no-activation Win32 window on a dedicated UI thread."""

    def __init__(self, image_path: Path, *, dark: bool = False) -> None:
        self._image_path = image_path
        self._status_color = _rgb(130, 203, 157) if dark else _rgb(53, 111, 78)
        self._status = "Starting RedactLens..."
        self._status_lock = threading.Lock()
        self._ready = threading.Event()
        self._closed = threading.Event()
        self._window: int | None = None
        self._thread: threading.Thread | None = None
        self._wndproc: object | None = None

    def show(self) -> None:
        if sys.platform != "win32" or self._thread is not None:
            return
        self._thread = threading.Thread(
            target=self._run,
            name="RedactLens startup splash",
            daemon=True,
        )
        self._thread.start()
        # Do not let a cosmetic failure hold up application startup.
        self._ready.wait(timeout=1.5)

    def update(self, message: str) -> None:
        with self._status_lock:
            self._status = message
        window = self._window
        if window is not None:
            ctypes.windll.user32.PostMessageW(window, _STATUS_MESSAGE, 0, 0)

    def close(self) -> None:
        self._closed.set()
        window = self._window
        if window is not None:
            ctypes.windll.user32.PostMessageW(window, _WM_CLOSE, 0, 0)

    def _run(self) -> None:
        user32 = ctypes.windll.user32
        gdi32 = ctypes.windll.gdi32
        kernel32 = ctypes.windll.kernel32
        _configure_apis(user32, gdi32, kernel32)

        hbitmap = None
        class_name = "RedactLensStartupSplash"
        instance = kernel32.GetModuleHandleW(None)
        atom = 0
        try:
            user32.SetProcessDPIAware()
            hbitmap = user32.LoadImageW(
                None,
                str(self._image_path),
                _IMAGE_BITMAP,
                0,
                0,
                _LR_LOADFROMFILE | _LR_CREATEDIBSECTION,
            )
            if not hbitmap:
                return

            bitmap = _Bitmap()
            if not gdi32.GetObjectW(hbitmap, ctypes.sizeof(bitmap), ctypes.byref(bitmap)):
                return

            self._wndproc = _WNDPROC(self._window_proc)
            window_class = _WndClass(
                style=_CS_DROPSHADOW,
                lpfnWndProc=self._wndproc,
                cbClsExtra=0,
                cbWndExtra=0,
                hInstance=instance,
                hIcon=None,
                hCursor=user32.LoadCursorW(None, ctypes.c_void_p(32512)),
                hbrBackground=None,
                lpszMenuName=None,
                lpszClassName=class_name,
            )
            atom = user32.RegisterClassW(ctypes.byref(window_class))
            if not atom:
                return

            dpi = user32.GetDpiForSystem() if hasattr(user32, "GetDpiForSystem") else 96
            width = round(_LOGICAL_WIDTH * dpi / 96)
            height = round(_LOGICAL_HEIGHT * dpi / 96)
            left, top = self._centered_position(user32, width, height)

            window = user32.CreateWindowExW(
                _WS_EX_TOPMOST | _WS_EX_TOOLWINDOW | _WS_EX_NOACTIVATE,
                class_name,
                "Starting RedactLens",
                _WS_POPUP,
                left,
                top,
                width,
                height,
                None,
                None,
                instance,
                None,
            )
            if not window:
                return

            self._window = window
            self._bitmap = hbitmap
            self._bitmap_width = bitmap.bmWidth
            self._bitmap_height = bitmap.bmHeight
            self._dpi = dpi
            self._apply_rounded_corners(window)
            self._ready.set()
            if self._closed.is_set():
                user32.DestroyWindow(window)
            else:
                user32.ShowWindow(window, _SW_SHOWNOACTIVATE)
                user32.UpdateWindow(window)

            message = wintypes.MSG()
            while user32.GetMessageW(ctypes.byref(message), None, 0, 0) > 0:
                user32.TranslateMessage(ctypes.byref(message))
                user32.DispatchMessageW(ctypes.byref(message))
        except Exception:
            # The splash must never prevent RedactLens from starting.
            return
        finally:
            self._window = None
            self._ready.set()
            if hbitmap:
                gdi32.DeleteObject(hbitmap)
            if atom:
                user32.UnregisterClassW(class_name, instance)

    def _window_proc(
        self,
        window: wintypes.HWND,
        message: int,
        wparam: int,
        lparam: int,
    ) -> int:
        user32 = ctypes.windll.user32
        if message == _WM_ERASEBKGND:
            return 1
        if message == _WM_PAINT:
            self._paint(window)
            return 0
        if message == _STATUS_MESSAGE:
            user32.InvalidateRect(window, None, False)
            user32.UpdateWindow(window)
            return 0
        if message == _WM_CLOSE:
            user32.DestroyWindow(window)
            return 0
        if message == _WM_DESTROY:
            user32.PostQuitMessage(0)
            return 0
        return user32.DefWindowProcW(window, message, wparam, lparam)

    def _paint(self, window: wintypes.HWND) -> None:
        user32 = ctypes.windll.user32
        gdi32 = ctypes.windll.gdi32
        paint = _PaintStruct()
        hdc = user32.BeginPaint(window, ctypes.byref(paint))
        if not hdc:
            return
        memory_dc = None
        font = None
        try:
            client = wintypes.RECT()
            user32.GetClientRect(window, ctypes.byref(client))
            width = client.right - client.left
            height = client.bottom - client.top

            memory_dc = gdi32.CreateCompatibleDC(hdc)
            previous_bitmap = gdi32.SelectObject(memory_dc, self._bitmap)
            gdi32.SetStretchBltMode(hdc, _HALFTONE)
            gdi32.StretchBlt(
                hdc,
                0,
                0,
                width,
                height,
                memory_dc,
                0,
                0,
                self._bitmap_width,
                self._bitmap_height,
                _SRCCOPY,
            )
            gdi32.SelectObject(memory_dc, previous_bitmap)

            font_height = -round(11 * self._dpi / 72)
            gdi32.CreateFontW.restype = wintypes.HANDLE
            font = gdi32.CreateFontW(
                font_height,
                0,
                0,
                0,
                _FW_SEMIBOLD,
                False,
                False,
                False,
                1,
                0,
                0,
                5,
                0,
                "Segoe UI",
            )
            previous_font = gdi32.SelectObject(hdc, font)
            gdi32.SetBkMode(hdc, _TRANSPARENT)
            gdi32.SetTextColor(hdc, self._status_color)
            scale = self._dpi / 96
            text_rect = wintypes.RECT(
                round(70 * scale),
                round(296 * scale),
                round(440 * scale),
                round(350 * scale),
            )
            with self._status_lock:
                status = self._status
            user32.DrawTextW(
                hdc,
                status,
                -1,
                ctypes.byref(text_rect),
                _DT_LEFT | _DT_VCENTER | _DT_SINGLELINE | _DT_END_ELLIPSIS,
            )
            gdi32.SelectObject(hdc, previous_font)
        finally:
            if font:
                gdi32.DeleteObject(font)
            if memory_dc:
                gdi32.DeleteDC(memory_dc)
            user32.EndPaint(window, ctypes.byref(paint))

    @staticmethod
    def _centered_position(user32: object, width: int, height: int) -> tuple[int, int]:
        point = wintypes.POINT()
        user32.GetCursorPos(ctypes.byref(point))
        monitor = user32.MonitorFromPoint(point, _MONITOR_DEFAULTTONEAREST)
        info = _MonitorInfo(cbSize=ctypes.sizeof(_MonitorInfo))
        if monitor and user32.GetMonitorInfoW(monitor, ctypes.byref(info)):
            work = info.rcWork
            return (
                work.left + (work.right - work.left - width) // 2,
                work.top + (work.bottom - work.top - height) // 2,
            )
        return (
            (user32.GetSystemMetrics(0) - width) // 2,
            (user32.GetSystemMetrics(1) - height) // 2,
        )

    @staticmethod
    def _apply_rounded_corners(window: wintypes.HWND) -> None:
        try:
            preference = ctypes.c_int(2)
            dwmapi = ctypes.windll.dwmapi
            dwmapi.DwmSetWindowAttribute.argtypes = [
                wintypes.HWND,
                wintypes.DWORD,
                wintypes.LPCVOID,
                wintypes.DWORD,
            ]
            dwmapi.DwmSetWindowAttribute(
                window,
                33,
                ctypes.byref(preference),
                ctypes.sizeof(preference),
            )
        except Exception:
            pass
