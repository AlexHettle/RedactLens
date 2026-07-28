[CmdletBinding()]
param(
    [string]$Version = "0.1.0",
    [string]$PythonExecutable = "python",
    [string]$IsccPath = "",
    [string]$CodeSigningThumbprint = "",
    [string]$TimestampUrl = "http://timestamp.digicert.com",
    [switch]$SkipFrontendBuild,
    [switch]$SkipInstaller,
    [switch]$SkipBundleSmokeTest
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$installerRoot = [IO.Path]::GetFullPath($PSScriptRoot)
$projectRoot = [IO.Path]::GetFullPath((Join-Path $installerRoot "..\.."))
$repositoryRoot = [IO.Path]::GetFullPath((Join-Path $projectRoot ".."))
$artifactsRoot = Join-Path $projectRoot ".artifacts"
$buildRoot = Join-Path $artifactsRoot "build\windows-installer"
$pyinstallerWork = Join-Path $buildRoot "pyinstaller"
$versionFile = Join-Path $buildRoot "version_info.txt"
$distRoot = Join-Path $artifactsRoot "dist"
$bundleRoot = Join-Path $distRoot "RedactLens"
$releaseRoot = Join-Path $artifactsRoot "release"

function Invoke-External {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(Mandatory = $true)][string[]]$ArgumentList
    )
    & $FilePath @ArgumentList
    if ($LASTEXITCODE -ne 0) {
        throw "Command failed with exit code $LASTEXITCODE`: $FilePath $($ArgumentList -join ' ')"
    }
}

function Reset-ProjectDirectory {
    param([Parameter(Mandatory = $true)][string]$Path)
    $fullPath = [IO.Path]::GetFullPath($Path)
    $projectPrefix = $projectRoot.TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
    if (-not $fullPath.StartsWith($projectPrefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing to reset a directory outside the project: $fullPath"
    }
    if (Test-Path -LiteralPath $fullPath) {
        Remove-Item -LiteralPath $fullPath -Recurse -Force
    }
    New-Item -ItemType Directory -Path $fullPath -Force | Out-Null
}

function Invoke-CodeSigning {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        [Parameter(Mandatory = $true)][string]$TimestampServer
    )
    $signature = Set-AuthenticodeSignature `
        -LiteralPath $Path `
        -Certificate $Certificate `
        -HashAlgorithm SHA256 `
        -TimestampServer $TimestampServer
    if ($signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid) {
        throw "Authenticode signing failed for '$Path': $($signature.StatusMessage)"
    }
    Write-Host "Signed: $Path"
}

if ($env:OS -ne "Windows_NT") {
    throw "The RedactLens release build requires Microsoft Windows."
}

$versionMatch = [regex]::Match(
    $Version,
    '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$'
)
if (-not $versionMatch.Success) {
    throw "Version must be SemVer-like MAJOR.MINOR.PATCH[-PRERELEASE][+BUILD]."
}
$numericVersion = "$($versionMatch.Groups[1].Value).$($versionMatch.Groups[2].Value).$($versionMatch.Groups[3].Value).0"

$codeSigningCertificate = $null
if ($CodeSigningThumbprint) {
    $normalizedThumbprint = $CodeSigningThumbprint.Replace(" ", "").ToUpperInvariant()
    if ($normalizedThumbprint -notmatch '^[0-9A-F]{40}$') {
        throw "CodeSigningThumbprint must be a 40-character certificate thumbprint."
    }
    $certificatePath = "Cert:\CurrentUser\My\$normalizedThumbprint"
    $codeSigningCertificate = Get-Item -LiteralPath $certificatePath -ErrorAction Stop
    if (-not $codeSigningCertificate.HasPrivateKey) {
        throw "The code-signing certificate does not have an accessible private key."
    }
    $codeSigningUsage = $codeSigningCertificate.Extensions | Where-Object {
        $_ -is [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension] -and
        $_.EnhancedKeyUsages.Value -contains "1.3.6.1.5.5.7.3.3"
    }
    if (-not $codeSigningUsage) {
        throw "The selected certificate is not valid for code signing."
    }
    $timestampUri = $null
    if (
        -not [Uri]::TryCreate($TimestampUrl, [UriKind]::Absolute, [ref]$timestampUri) -or
        $timestampUri.Scheme -notin @("http", "https")
    ) {
        throw "TimestampUrl must be an absolute HTTP or HTTPS URL."
    }
}

$python = (Get-Command $PythonExecutable -ErrorAction Stop).Source
Push-Location $projectRoot
try {
    if (-not $SkipFrontendBuild) {
        $npm = (Get-Command "npm.cmd" -ErrorAction Stop).Source
        Invoke-External $npm @("run", "build", "--prefix", "packages/frontend")
    }

    Reset-ProjectDirectory $buildRoot
    if (Test-Path -LiteralPath $bundleRoot) {
        Remove-Item -LiteralPath $bundleRoot -Recurse -Force
    }
    Reset-ProjectDirectory $releaseRoot

    Invoke-External $python @(
        (Join-Path $installerRoot "generate_version_info.py"),
        $Version,
        $versionFile
    )

    $thirdPartyLicenseBundle = Join-Path $buildRoot "THIRD_PARTY_LICENSES.txt"
    Invoke-External $python @(
        (Join-Path $installerRoot "generate_third_party_licenses.py"),
        $thirdPartyLicenseBundle,
        "--repository-root", $repositoryRoot
    )

    $priorVersionFile = $env:REDACTLENS_VERSION_FILE
    $env:REDACTLENS_VERSION_FILE = $versionFile
    try {
        Invoke-External $python @(
            "-m", "PyInstaller",
            "--noconfirm",
            "--clean",
            "--distpath", $distRoot,
            "--workpath", $pyinstallerWork,
            (Join-Path $installerRoot "RedactLens.spec")
        )
    }
    finally {
        $env:REDACTLENS_VERSION_FILE = $priorVersionFile
    }

    $legalDocuments = @(
        @{ Source = "LICENSE"; Destination = "LICENSE" },
        @{
            Source = "docs\legal\THIRD_PARTY_NOTICES.md"
            Destination = "THIRD_PARTY_NOTICES.md"
        }
    )
    foreach ($legalDocument in $legalDocuments) {
        $sourceDocument = Join-Path $repositoryRoot $legalDocument.Source
        if (-not (Test-Path -LiteralPath $sourceDocument -PathType Leaf)) {
            throw "Required release document is missing: $sourceDocument"
        }
        Copy-Item `
            -LiteralPath $sourceDocument `
            -Destination (Join-Path $bundleRoot $legalDocument.Destination) `
            -Force
    }
    Copy-Item `
        -LiteralPath $thirdPartyLicenseBundle `
        -Destination (Join-Path $bundleRoot "THIRD_PARTY_LICENSES.txt") `
        -Force

    if ($codeSigningCertificate) {
        Invoke-CodeSigning `
            -Path (Join-Path $bundleRoot "RedactLens.exe") `
            -Certificate $codeSigningCertificate `
            -TimestampServer $TimestampUrl
    }

    Invoke-External $python @(
        (Join-Path $installerRoot "validate_bundle.py"),
        $bundleRoot,
        "--source-root", $projectRoot
    )
    if (-not $SkipBundleSmokeTest) {
        Invoke-External $python @(
            (Join-Path $installerRoot "smoke_test_bundle.py"),
            (Join-Path $bundleRoot "RedactLens.exe")
        )
    }

    $portableArchive = Join-Path $releaseRoot "RedactLens-$Version-windows-x64-portable.zip"
    Compress-Archive -Path (Join-Path $bundleRoot "*") -DestinationPath $portableArchive -CompressionLevel Optimal

    $artifacts = @($portableArchive)
    if (-not $SkipInstaller) {
        if (-not $IsccPath) {
            $isccCandidates = @(
                (Join-Path $env:LOCALAPPDATA "Programs\Inno Setup 6\ISCC.exe"),
                (Join-Path $env:LOCALAPPDATA "Programs\Inno Setup 7\ISCC.exe"),
                (Join-Path ${env:ProgramFiles(x86)} "Inno Setup 6\ISCC.exe"),
                (Join-Path $env:ProgramFiles "Inno Setup 6\ISCC.exe"),
                (Join-Path ${env:ProgramFiles(x86)} "Inno Setup 7\ISCC.exe"),
                (Join-Path $env:ProgramFiles "Inno Setup 7\ISCC.exe")
            )
            $IsccPath = $isccCandidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
        }
        if (-not $IsccPath -or -not (Test-Path -LiteralPath $IsccPath)) {
            throw "ISCC.exe was not found. Install Inno Setup or pass -IsccPath."
        }
        Invoke-External $IsccPath @(
            "/DMyAppVersion=$Version",
            "/DMyAppNumericVersion=$numericVersion",
            "/DMySourceDir=$bundleRoot",
            "/DMyOutputDir=$releaseRoot",
            (Join-Path $installerRoot "RedactLens.iss")
        )
        $installer = Join-Path $releaseRoot "RedactLens-Setup-$Version-windows-x64.exe"
        if (-not (Test-Path -LiteralPath $installer)) {
            throw "Inno Setup did not produce the expected installer: $installer"
        }
        if ($codeSigningCertificate) {
            Invoke-CodeSigning `
                -Path $installer `
                -Certificate $codeSigningCertificate `
                -TimestampServer $TimestampUrl
        }
        $artifacts += $installer

        $rootInstaller = Join-Path $repositoryRoot "Install RedactLens.exe"
        Copy-Item -LiteralPath $installer -Destination $rootInstaller -Force
        Write-Host "Root installer:"
        Write-Host "  $rootInstaller"
    }

    $checksumPath = Join-Path $releaseRoot "SHA256SUMS.txt"
    $checksumLines = $artifacts | Sort-Object | ForEach-Object {
        $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $_).Hash.ToLowerInvariant()
        "$hash  $([IO.Path]::GetFileName($_))"
    }
    [IO.File]::WriteAllLines($checksumPath, $checksumLines, [Text.UTF8Encoding]::new($false))

    Write-Host "RedactLens Windows release artifacts:"
    Get-ChildItem -LiteralPath $releaseRoot -File | ForEach-Object { Write-Host "  $($_.FullName)" }
}
finally {
    Pop-Location
}
