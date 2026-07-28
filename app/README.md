# RedactLens application workspace

This directory contains the RedactLens desktop application, its local API, scanner core, command
line interface, frontend, packaging tools, and engineering evidence.

For the product overview, installation guide, supported formats, privacy model, screenshots, and
user-facing workflow, start with the [project README](../README.md).

## Development requirements

- Windows 10 version 1809 (build 17763) or later, or Windows 11
- Python 3.11 or newer
- Node.js `^20.19` or `>=22.12`

The installed RedactLens application is self-contained. End users do not need these development
tools.

## Install dependencies

Run from the repository root:

```powershell
py -m venv .venv
Push-Location app
..\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
npm ci --prefix packages\frontend
Pop-Location
```

## Run the application

Launch the packaged-style desktop surface:

```powershell
.venv\Scripts\python.exe app\launch.py
```

Run the CLI against the fabricated demo fixture:

```powershell
.venv\Scripts\python.exe -m redactlens_cli.main scan app\examples\demo
```

For split frontend/API development, use two terminals:

```powershell
.venv\Scripts\python.exe -m redactlens_api
```

```powershell
npm run dev --prefix app\packages\frontend
```

The API binds to `127.0.0.1`. Vite uses `127.0.0.1:5173`; that strict development origin is part
of the API security policy.

## Verify a change

Run the complete repository baseline:

```powershell
.venv\Scripts\python.exe app\tooling\verify.py
```

The verifier runs twelve bounded gates:

1. Python tests
2. Frontend tests
3. Production frontend build
4. Live browser workflow
5. CLI demo contract
6. Ruff lint
7. Ruff format
8. Benchmark freshness
9. Detector performance
10. ESLint
11. Prettier
12. Evaluation-report freshness

The live browser gate requires Edge, Chrome, or Chromium. Set `REDACTLENS_E2E_BROWSER` to an
explicit executable path when automatic discovery is not suitable.

## Package map

```text
packages/
  redactlens-core/   Detection, extraction, scoring, consolidation, and redaction
  api/                Trusted scan sessions and the privacy-safe loopback API
  cli/                Thin Typer interface over the scanner core
  frontend/           React and TypeScript desktop interface
tooling/
  eval/               Deterministic detector evaluation and reports
  installer/          PyInstaller and Inno Setup release pipeline
  scripts/            Browser and release-contract checks
examples/demo/        Fabricated quick-demo fixture
docs/                 Security documentation
tests/                Cross-component and release-contract tests
```

## Build a Windows release

Install the pinned packaging requirements:

```powershell
Push-Location app
..\.venv\Scripts\python.exe -m pip install pip==26.1.2
$env:PIP_BUILD_CONSTRAINT = "tooling\installer\constraints-windows.txt"
..\.venv\Scripts\python.exe -m pip install `
  --constraint tooling\installer\constraints-windows.txt `
  --requirement requirements-dev.txt `
  --requirement tooling\installer\requirements-build.txt
Remove-Item Env:PIP_BUILD_CONSTRAINT
Pop-Location
```

Build and smoke-test the portable ZIP:

```powershell
.\app\tooling\installer\build_windows.ps1 -Version 0.1.8 -SkipInstaller
```

Install Inno Setup 6 and omit `-SkipInstaller` to build the installer and refresh the repository's
`Install RedactLens.exe`. Local artifacts are unsigned unless a trusted code-signing certificate
thumbprint is supplied. Official releases require signing and generate SHA-256 checksums.

## Engineering documentation

- [Threat model](docs/threat-model.md)
- [Evaluation report](tooling/eval/report.md)
- [Frontend responsibilities](packages/frontend/README.md)
