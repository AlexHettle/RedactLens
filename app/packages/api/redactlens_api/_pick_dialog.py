"""Show a Windows file/folder dialog from a short-lived child process.

The packaged application deliberately avoids Tkinter: the embeddable Python
runtime used by the Windows bundle does not include Tcl/Tk. Windows PowerShell
and WinForms are part of the supported Windows environment, and ``-STA`` gives
the dialog the apartment state it requires.
"""

import base64
import os
import shutil
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path
from tempfile import gettempdir

PICKER_RESULT_PREFIX = "redactlens-picker-"
PICKER_RESULT_SUFFIX = ".txt"

_POWERSHELL_PICKER = r"""
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Windows.Forms

$folderPickerSource = @'
using System;
using System.Runtime.InteropServices;

namespace RedactLens
{
    [Flags]
    internal enum FileOpenOptions : uint
    {
        NoChangeDirectory = 0x00000008,
        PickFolders = 0x00000020,
        ForceFileSystem = 0x00000040,
        PathMustExist = 0x00000800,
        DontAddToRecent = 0x02000000
    }

    internal enum ShellItemDisplayName : uint
    {
        FileSystemPath = 0x80058000
    }

    [ComImport]
    [Guid("43826d1e-e718-42ee-bc55-a1e261c37bfe")]
    [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    internal interface IShellItem
    {
        void BindToHandler(
            IntPtr bindingContext,
            ref Guid handler,
            ref Guid interfaceId,
            out IntPtr value
        );
        void GetParent(out IShellItem parent);
        void GetDisplayName(ShellItemDisplayName displayName, out IntPtr name);
        void GetAttributes(uint mask, out uint attributes);
        void Compare(IShellItem item, uint hint, out int order);
    }

    [ComImport]
    [Guid("42f85136-db7e-439c-85f1-e4075d135fc8")]
    [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    internal interface IFileDialog
    {
        [PreserveSig]
        int Show(IntPtr owner);
        void SetFileTypes(uint count, IntPtr filterSpecifications);
        void SetFileTypeIndex(uint index);
        void GetFileTypeIndex(out uint index);
        void Advise(IntPtr events, out uint cookie);
        void Unadvise(uint cookie);
        void SetOptions(FileOpenOptions options);
        void GetOptions(out FileOpenOptions options);
        void SetDefaultFolder(IShellItem folder);
        void SetFolder(IShellItem folder);
        void GetFolder(out IShellItem folder);
        void GetCurrentSelection(out IShellItem item);
        void SetFileName([MarshalAs(UnmanagedType.LPWStr)] string name);
        void GetFileName([MarshalAs(UnmanagedType.LPWStr)] out string name);
        void SetTitle([MarshalAs(UnmanagedType.LPWStr)] string title);
        void SetOkButtonLabel([MarshalAs(UnmanagedType.LPWStr)] string text);
        void SetFileNameLabel([MarshalAs(UnmanagedType.LPWStr)] string label);
        void GetResult(out IShellItem item);
        void AddPlace(IShellItem item, uint alignment);
        void SetDefaultExtension([MarshalAs(UnmanagedType.LPWStr)] string extension);
        void Close(int result);
        void SetClientGuid(ref Guid clientGuid);
        void ClearClientData();
        void SetFilter(IntPtr filter);
    }

    public static class NativeFolderPicker
    {
        private static readonly Guid FileOpenDialogId =
            new Guid("dc1c5a9c-e88a-4dde-a5a1-60f82a20aef7");
        private const int Cancelled = unchecked((int)0x800704C7);

        public static void Probe()
        {
            IFileDialog dialog = null;
            try
            {
                dialog = CreateDialog();
                ApplyFolderOptions(dialog);
            }
            finally
            {
                if (dialog != null)
                {
                    Marshal.ReleaseComObject(dialog);
                }
            }
        }

        public static string Show(IntPtr owner, string title)
        {
            IFileDialog dialog = null;
            IShellItem selectedItem = null;
            IntPtr selectedPath = IntPtr.Zero;
            try
            {
                dialog = CreateDialog();
                ApplyFolderOptions(dialog);
                dialog.SetTitle(title);

                int result = dialog.Show(owner);
                if (result == Cancelled)
                {
                    return String.Empty;
                }
                Marshal.ThrowExceptionForHR(result);

                dialog.GetResult(out selectedItem);
                selectedItem.GetDisplayName(ShellItemDisplayName.FileSystemPath, out selectedPath);
                return Marshal.PtrToStringUni(selectedPath) ?? String.Empty;
            }
            finally
            {
                if (selectedPath != IntPtr.Zero)
                {
                    Marshal.FreeCoTaskMem(selectedPath);
                }
                if (selectedItem != null)
                {
                    Marshal.ReleaseComObject(selectedItem);
                }
                if (dialog != null)
                {
                    Marshal.ReleaseComObject(dialog);
                }
            }
        }

        private static IFileDialog CreateDialog()
        {
            Type dialogType = Type.GetTypeFromCLSID(FileOpenDialogId, true);
            return (IFileDialog)Activator.CreateInstance(dialogType);
        }

        private static void ApplyFolderOptions(IFileDialog dialog)
        {
            FileOpenOptions options;
            dialog.GetOptions(out options);
            dialog.SetOptions(
                options
                | FileOpenOptions.NoChangeDirectory
                | FileOpenOptions.PickFolders
                | FileOpenOptions.ForceFileSystem
                | FileOpenOptions.PathMustExist
                | FileOpenOptions.DontAddToRecent
            );
        }
    }
}
'@
Add-Type -TypeDefinition $folderPickerSource -Language CSharp

if ($env:REDACTLENS_PICKER_KIND -eq 'probe') {
    [RedactLens.NativeFolderPicker]::Probe()
    exit 0
}

[System.Windows.Forms.Application]::EnableVisualStyles()
$selected = ''
$owner = New-Object System.Windows.Forms.Form
$owner.ShowInTaskbar = $false
$owner.TopMost = $true
$owner.StartPosition = [System.Windows.Forms.FormStartPosition]::Manual
$owner.Location = New-Object System.Drawing.Point(-32000, -32000)
$owner.Size = New-Object System.Drawing.Size(1, 1)
$owner.Show()

try {
    if ($env:REDACTLENS_PICKER_KIND -eq 'file') {
        $dialog = New-Object System.Windows.Forms.OpenFileDialog
        $dialog.Title = 'Choose a file to scan'
        $dialog.CheckFileExists = $true
        $dialog.CheckPathExists = $true
        try {
            if ($dialog.ShowDialog($owner) -eq [System.Windows.Forms.DialogResult]::OK) {
                $selected = $dialog.FileName
            }
        } finally {
            $dialog.Dispose()
        }
    } else {
        $selected = [RedactLens.NativeFolderPicker]::Show(
            $owner.Handle,
            'Choose a folder to scan'
        )
    }
} finally {
    $owner.Close()
    $owner.Dispose()
}

$encoding = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText($env:REDACTLENS_PICKER_RESULT, $selected, $encoding)
"""
_ENCODED_PICKER = base64.b64encode(_POWERSHELL_PICKER.encode("utf-16-le")).decode("ascii")


def _result_path(value: str) -> Path | None:
    """Accept only the private temporary result files created by ``pick_path``."""

    path = Path(value)
    try:
        expected_parent = Path(gettempdir()).resolve()
        resolved_parent = path.resolve().parent
    except OSError:
        return None
    if (
        resolved_parent != expected_parent
        or not path.name.startswith(PICKER_RESULT_PREFIX)
        or path.suffix != PICKER_RESULT_SUFFIX
        or not path.is_file()
    ):
        return None
    return path


def _powershell_executable() -> str | None:
    """Locate the built-in 64-bit Windows PowerShell host."""

    system_root = os.environ.get("SystemRoot")
    if system_root:
        bundled = Path(system_root) / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
        if bundled.is_file():
            return str(bundled)
    return shutil.which("powershell.exe")


def main(argv: Sequence[str] | None = None) -> int:
    if sys.platform != "win32":
        return 2

    args = list(sys.argv[1:] if argv is None else argv)
    kind = args[0] if args else "folder"
    if kind not in {"folder", "file", "probe"}:
        return 2
    if kind == "probe":
        output_path = None
    else:
        output_path = _result_path(args[1]) if len(args) > 1 else None
    if kind != "probe" and output_path is None:
        return 2

    try:
        timeout = float(args[2]) if len(args) > 2 else 300.0
    except ValueError:
        return 2
    powershell = _powershell_executable()
    if powershell is None:
        return 2

    environment = os.environ.copy()
    environment["REDACTLENS_PICKER_KIND"] = kind
    if output_path is not None:
        environment["REDACTLENS_PICKER_RESULT"] = str(output_path)
    try:
        completed = subprocess.run(
            [
                powershell,
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-STA",
                "-EncodedCommand",
                _ENCODED_PICKER,
            ],
            capture_output=True,
            text=True,
            timeout=timeout,
            env=environment,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except subprocess.TimeoutExpired:
        return 0
    except OSError:
        return 2
    if completed.returncode != 0:
        if completed.stderr and sys.stderr is not None:
            sys.stderr.write(completed.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
