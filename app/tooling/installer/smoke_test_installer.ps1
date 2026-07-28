[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$InstallerPath,
    [string]$PythonExecutable = "python"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if ($env:OS -ne "Windows_NT") {
    throw "The installer smoke test requires Microsoft Windows."
}

$installer = (Resolve-Path -LiteralPath $InstallerPath).Path
$projectRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot "..\.."))
$temporaryRoot = if ($env:RUNNER_TEMP) { $env:RUNNER_TEMP } else { $env:TEMP }
if (-not $temporaryRoot) {
    throw "Neither RUNNER_TEMP nor TEMP identifies a temporary directory."
}
$temporaryPrefix = [IO.Path]::GetFullPath($temporaryRoot).TrimEnd('\') + '\'
$installRoot = [IO.Path]::GetFullPath((Join-Path $temporaryRoot "RedactLens-installer-smoke-$PID"))
if (-not $installRoot.StartsWith($temporaryPrefix, [StringComparison]::OrdinalIgnoreCase)) {
    throw "Refusing to use a smoke-test directory outside the temporary root: $installRoot"
}
$python = (Get-Command $PythonExecutable -ErrorAction Stop).Source
$defaultInstallRoot = [IO.Path]::GetFullPath(
    (Join-Path $env:LOCALAPPDATA "Programs\RedactLens")
)
$programsRoot = [Environment]::GetFolderPath([Environment+SpecialFolder]::Programs)
$shortcutDirectory = [IO.Path]::GetFullPath((Join-Path $programsRoot "RedactLens"))
$programsPrefix = [IO.Path]::GetFullPath($programsRoot).TrimEnd('\') + '\'
if (-not $shortcutDirectory.StartsWith($programsPrefix, [StringComparison]::OrdinalIgnoreCase)) {
    throw "Refusing to use a shortcut directory outside the current user's Programs folder."
}
$shortcut = Join-Path $shortcutDirectory "RedactLens.lnk"
$signalFile = Join-Path $env:LOCALAPPDATA "RedactLens\reinstall.shutdown"
$repairLog = Join-Path $temporaryRoot "RedactLens-installer-repair-$PID.log"
$appProcess = $null
$priorNoBrowser = $env:REDACTLENS_NO_BROWSER
$priorIdleExit = $env:REDACTLENS_IDLE_EXIT_MINUTES

$existingProcess = Get-Process -Name "RedactLens" -ErrorAction SilentlyContinue |
    Select-Object -First 1
if ($existingProcess) {
    throw "Refusing to disturb an existing RedactLens process (PID $($existingProcess.Id))."
}
if (Test-Path -LiteralPath $defaultInstallRoot) {
    throw "Refusing to disturb an existing RedactLens installation: $defaultInstallRoot"
}
if (Test-Path -LiteralPath $shortcutDirectory) {
    throw "Refusing to disturb an existing RedactLens Start Menu folder: $shortcutDirectory"
}

if (Test-Path -LiteralPath $installRoot) {
    Remove-Item -LiteralPath $installRoot -Recurse -Force
}

try {
    $installArguments = @(
        "/VERYSILENT",
        "/SUPPRESSMSGBOXES",
        "/NORESTART",
        "/CURRENTUSER",
        ('/DIR="' + $installRoot + '"')
    )
    $installProcess = Start-Process `
        -FilePath $installer `
        -ArgumentList $installArguments `
        -WindowStyle Hidden `
        -Wait `
        -PassThru
    if ($installProcess.ExitCode -ne 0) {
        throw "Installer exited with code $($installProcess.ExitCode)."
    }

    & $python (Join-Path $PSScriptRoot "validate_bundle.py") $installRoot "--source-root" $projectRoot
    if ($LASTEXITCODE -ne 0) {
        throw "Installed bundle validation failed with code $LASTEXITCODE."
    }
    & $python (Join-Path $PSScriptRoot "smoke_test_bundle.py") (Join-Path $installRoot "RedactLens.exe")
    if ($LASTEXITCODE -ne 0) {
        throw "Installed executable smoke test failed with code $LASTEXITCODE."
    }
    if (-not (Test-Path -LiteralPath $shortcut -PathType Leaf)) {
        throw "The initial install did not create the Start Menu shortcut."
    }

    # Reproduce a user repair: remove the shortcut while the hidden local
    # server is running, then install the same version again.
    Remove-Item -LiteralPath $shortcut -Force
    $env:REDACTLENS_NO_BROWSER = "1"
    $env:REDACTLENS_IDLE_EXIT_MINUTES = "0"
    $appProcess = Start-Process `
        -FilePath (Join-Path $installRoot "RedactLens.exe") `
        -WorkingDirectory $installRoot `
        -WindowStyle Hidden `
        -PassThru
    Start-Sleep -Seconds 2
    if ($appProcess.HasExited) {
        throw "Installed app exited before the repair-install test."
    }

    $repairArguments = @(
        $installArguments
        "/LOGCLOSEAPPLICATIONS"
        ('/LOG="' + $repairLog + '"')
    )
    $repairProcess = Start-Process `
        -FilePath $installer `
        -ArgumentList $repairArguments `
        -WindowStyle Hidden `
        -Wait `
        -PassThru
    if ($repairProcess.ExitCode -ne 0) {
        throw "Repair installer exited with code $($repairProcess.ExitCode). Log: $repairLog"
    }
    if (-not $appProcess.WaitForExit(10000)) {
        throw "Repair install did not stop the running RedactLens process. Log: $repairLog"
    }
    $appProcess = $null
    if (Test-Path -LiteralPath $signalFile) {
        throw "Repair install left a stale graceful-shutdown signal: $signalFile"
    }
    if (-not (Test-Path -LiteralPath $shortcut -PathType Leaf)) {
        throw "Repair install did not recreate the deleted Start Menu shortcut."
    }

    & $python (Join-Path $PSScriptRoot "validate_bundle.py") $installRoot "--source-root" $projectRoot
    if ($LASTEXITCODE -ne 0) {
        throw "Reinstalled bundle validation failed with code $LASTEXITCODE."
    }
    & $python (Join-Path $PSScriptRoot "smoke_test_bundle.py") (Join-Path $installRoot "RedactLens.exe")
    if ($LASTEXITCODE -ne 0) {
        throw "Reinstalled executable smoke test failed with code $LASTEXITCODE."
    }
}
finally {
    $env:REDACTLENS_NO_BROWSER = $priorNoBrowser
    $env:REDACTLENS_IDLE_EXIT_MINUTES = $priorIdleExit
    if ($appProcess -and -not $appProcess.HasExited) {
        Stop-Process -Id $appProcess.Id -Force -ErrorAction SilentlyContinue
        $appProcess.WaitForExit()
    }
    $uninstaller = Join-Path $installRoot "unins000.exe"
    if (Test-Path -LiteralPath $uninstaller) {
        $uninstallProcess = Start-Process `
            -FilePath $uninstaller `
            -ArgumentList @("/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART") `
            -WindowStyle Hidden `
            -Wait `
            -PassThru
        if ($uninstallProcess.ExitCode -ne 0) {
            Write-Warning "Uninstaller exited with code $($uninstallProcess.ExitCode)."
        }
    }
    if (Test-Path -LiteralPath $installRoot) {
        Remove-Item -LiteralPath $installRoot -Recurse -Force
    }
    if (Test-Path -LiteralPath $shortcutDirectory) {
        Remove-Item -LiteralPath $shortcutDirectory -Recurse -Force
    }
    Remove-Item -LiteralPath $signalFile,$repairLog -Force -ErrorAction SilentlyContinue
}
