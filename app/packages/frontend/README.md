# RedactLens frontend

This directory contains the React and TypeScript interface for RedactLens's Windows-only local
application. The browser does not scan or rewrite files directly. It talks to the loopback FastAPI
service, receives privacy-safe scan events, and submits opaque finding IDs for trusted filesystem
actions.

## Responsibilities

- Configure file or folder scans, detector categories, custom targets, and bounded scan options.
- Render ordered progress and recover interrupted Server-Sent Events from an authoritative snapshot.
- Filter and group redacted findings without placing raw matches or rewrite offsets in browser state.
- Build explicit remediation plans, review generated copies, and export allowlisted reports.
- Preserve keyboard operation, focus management, live feedback, reduced-motion behavior, and
  forced-colors boundaries across setup, scanning, results, and remediation states.

The production build is served by the API on the same loopback origin. During development, Vite
runs on `http://127.0.0.1:5173` and uses the API at `http://127.0.0.1:8000` by default. Set
`VITE_API_BASE_URL` only when a different local development endpoint is required.

## Development

Install the repository dependencies from the application root (`app/`) as described in the
[application development guide](../../README.md), then start the API and Vite server in separate
terminals:

```powershell
..\.venv\Scripts\python.exe -m redactlens_api
npm run dev --prefix packages\frontend
```

The Vite development port is strict because it is part of the API's allowed-origin policy.

## Quality checks

Run these commands from the application root (`app/`):

```powershell
npm test --prefix packages\frontend
npm run test:a11y:e2e --prefix packages\frontend
npm run build --prefix packages\frontend
npm run lint --prefix packages\frontend
npm run format:check --prefix packages\frontend
```

Vitest and Testing Library cover component behavior, API recovery, keyboard workflows, privacy-safe
exports, large result sets, and accessibility states. Playwright with `@axe-core/playwright` adds a
real-Chrome accessibility gate for setup, scanning, results, revealed values, errors, remediation,
repeated action names, zoom/reflow, WCAG text spacing, forced colors, and reduced motion. It uses
deterministic loopback API fixtures and the installed Chrome channel, so no Playwright-managed browser
download is required. The repository-level `tooling/verify.py` command runs both browser suites as
required CI checks.

## Key files

- `src/App.tsx` owns the setup, scanning, recovery, and results workflow.
- `src/api/` contains the launch-capability client and runtime validation for scan events.
- `src/components/` contains setup, scanning, finding, and remediation views.
- `src/results/` contains deterministic triage, path projection, and report construction.
- `src/accessibility.test.tsx` verifies axe-covered states, contrast tokens, focus visibility,
  reduced motion, and forced-colors rules.
- `e2e/accessibility.spec.ts` verifies the same safeguards in a real Chrome accessibility tree and
  rendering engine.
- `vite.config.ts` fixes the development port and applies anti-framing headers in development and
  preview builds.
