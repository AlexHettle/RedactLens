import { cleanup, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import axe from 'axe-core'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import * as client from './api/client'
import ResultsScreen from './components/ResultsScreen'
import ScanningScreen from './components/ScanningScreen'
import SetupScreen from './components/SetupScreen'
import TitleBar from './components/TitleBar'
import type { PublicFinding, PublicScanResult, RemediationPlan } from './types'

vi.mock('./api/client')

function normalizeNewlines(source: string): string {
  return source.replace(/\r\n?/g, '\n')
}

const tokensCss = normalizeNewlines(readFileSync(resolve(process.cwd(), 'src/index.css'), 'utf8'))
const appCss = normalizeNewlines(readFileSync(resolve(process.cwd(), 'src/App.css'), 'utf8'))

const finding: PublicFinding = {
  id: 'finding-1',
  file_path: 'C:\\project\\secrets.txt',
  line: 1,
  column: 7,
  location: null,
  can_anonymize: true,
  redacted_preview: '12*******89',
  detector_id: 'us_ssn',
  category: 'personal_id',
  confidence: 0.95,
  tier: 'A',
  explanation: 'A U.S. Social Security number.',
  risk_lesson: 'It can enable identity theft.',
  suggested_action: 'anonymize',
  supporting_detections: [],
}

const result: PublicScanResult = {
  scan_id: 'scan-1',
  event_cursor: 1,
  created_at: '2026-07-16T00:00:00Z',
  expires_at: '2026-07-16T00:15:00Z',
  findings: [finding],
  summary: {},
  scanned_files: [finding.file_path],
  skipped_files: [],
  llm_used: false,
  state: 'complete',
  progress: {
    stage: 'complete',
    completed_files: 1,
    total_files: 1,
    percent: 100,
    current_file: null,
    findings_so_far: 1,
    skipped_files: 0,
  },
  error: null,
  metadata: {
    selected_roots: ['C:\\project'],
    duration_ms: 125,
    data_scanned_bytes: 42,
    detector_count: 10,
    ai_model: null,
  },
}

function remediationPlan(included: string[] = []): RemediationPlan {
  return {
    plan_revision: 1,
    findings: [{ finding_id: finding.id, state: included.length ? 'included' : 'pending' }],
    files: included.length
      ? [
          {
            source_path: finding.file_path,
            output_path: finding.file_path.replace(/(\.[^./\\]+)$/, '-auto-redacted-copy$1'),
            included_finding_ids: included,
            output_state: 'not_created',
          },
        ]
      : [],
    selected_finding_count: included.length,
    affected_file_count: included.length,
    read_only_finding_count: 0,
    retained_artifact_paths: [],
    can_review: included.length > 0,
    can_generate: included.length > 0,
  }
}

async function expectNoAutomatedViolations() {
  const report = await axe.run(document.body, {
    rules: {
      // jsdom has no layout engine; token contrast is tested separately below.
      'color-contrast': { enabled: false },
    },
  })
  expect(report.violations, report.violations.map((item) => item.id).join(', ')).toEqual([])
}

function tokenBlock(selector: string): Record<string, string> {
  const opening = tokensCss.indexOf(`${selector} {`)
  const closing = tokensCss.indexOf('}', opening)
  if (opening < 0 || closing < 0) throw new Error(`Missing CSS token block ${selector}`)
  const declarations = tokensCss.slice(opening, closing)
  const entries: Array<[string, string]> = []
  for (const item of declarations.matchAll(/--([\w-]+):\s*(#[0-9a-f]{6})/gi)) {
    entries.push([item[1], item[2]])
  }
  return Object.fromEntries(entries)
}

function ruleBlock(selector: string, source = appCss): string {
  const opening = source.indexOf(`${selector} {`)
  const closing = source.indexOf('}', opening)
  if (opening < 0 || closing < 0) throw new Error(`Missing CSS rule ${selector}`)
  return source.slice(opening, closing)
}

function luminance(hex: string): number {
  const channels = hex
    .slice(1)
    .match(/../g)!
    .map((channel) => Number.parseInt(channel, 16) / 255)
    .map((channel) => (channel <= 0.04045 ? channel / 12.92 : ((channel + 0.055) / 1.055) ** 2.4))
  return channels[0] * 0.2126 + channels[1] * 0.7152 + channels[2] * 0.0722
}

function contrast(foreground: string, background: string): number {
  const values = [luminance(foreground), luminance(background)].sort((left, right) => right - left)
  return (values[0] + 0.05) / (values[1] + 0.05)
}

beforeEach(() => {
  vi.clearAllMocks()
  vi.mocked(client.getDetectors).mockResolvedValue([
    {
      id: 'us_ssn',
      category: 'personal_id',
      description: 'SSN',
      risk_lesson: 'Identity risk',
    },
  ])
  vi.mocked(client.getHealth).mockResolvedValue({ status: 'ok', ollama_available: false })
  vi.mocked(client.postRevealFindingValues).mockResolvedValue({
    values: [{ finding_id: finding.id, value: '123-45-6789' }],
  })
  vi.mocked(client.putRemediationPlan).mockImplementation(
    async (_scanId, included, _ignored, planRevision) => ({
      ...remediationPlan(included),
      plan_revision: planRevision + 1,
    }),
  )
  vi.mocked(client.getRemediationPlan).mockResolvedValue(remediationPlan([finding.id]))
})

afterEach(() => {
  cleanup()
  delete document.documentElement.dataset.contrast
})

describe('automated accessibility checks', () => {
  it('exposes the persistent appearance controls without detectable violations', async () => {
    render(
      <TitleBar
        theme="light"
        highContrast={false}
        onToggleTheme={vi.fn()}
        onToggleHighContrast={vi.fn()}
      />,
    )
    expect(screen.getByRole('switch', { name: 'High contrast' })).toHaveAttribute(
      'aria-checked',
      'false',
    )
    await expectNoAutomatedViolations()
  })

  it('has no detectable WCAG A/AA violations on setup', async () => {
    const user = userEvent.setup()
    render(
      <main>
        <SetupScreen onSubmit={vi.fn()} />
      </main>,
    )
    await screen.findByRole('heading', { name: 'RedactLens' })
    await user.click(screen.getByText('Advanced scan options'))
    await user.type(screen.getByLabelText(/Include only extensions/i), '.txt')
    await user.type(screen.getByLabelText(/Excluded extensions/i), 'txt')
    expect(screen.getByRole('alert')).toHaveTextContent(/both included and excluded/i)
    await expectNoAutomatedViolations()
  })

  it('has no detectable WCAG A/AA violations on live scanning and recovery controls', async () => {
    render(
      <main>
        <ScanningScreen
          target="C:\\project"
          scan={{
            ...result,
            state: 'scanning',
            progress: {
              ...result.progress,
              stage: 'detection',
              completed_files: 1,
              total_files: 3,
              percent: 33.3,
            },
          }}
          connectionError="Live updates are temporarily unavailable."
          cancelError={null}
          isRecovering={false}
          isCancelling={false}
          onCancel={vi.fn()}
          onRetryConnection={vi.fn()}
        />
      </main>,
    )
    await expectNoAutomatedViolations()
  })

  it('has no detectable WCAG A/AA violations on results and the modal review', async () => {
    const user = userEvent.setup()
    render(
      <main>
        <ResultsScreen
          result={result}
          isRefining={false}
          refineError={null}
          onStartOver={vi.fn()}
          onSessionExpired={vi.fn()}
        />
      </main>,
    )
    await expectNoAutomatedViolations()
    await user.click(screen.getByRole('switch', { name: 'Full finding values' }))
    expect(await screen.findByText('123-45-6789')).toBeInTheDocument()
    await expectNoAutomatedViolations()
    await user.click(screen.getByRole('button', { name: /Include finding .* in redaction plan/i }))
    await user.click(await screen.findByRole('button', { name: 'Review remediation' }))
    await expectNoAutomatedViolations()
  })

  it('has no detectable structural violations on high-contrast results', async () => {
    document.documentElement.dataset.contrast = 'high'
    render(
      <main>
        <ResultsScreen
          result={result}
          isRefining={false}
          refineError={null}
          onStartOver={vi.fn()}
          onSessionExpired={vi.fn()}
        />
      </main>,
    )

    expect(screen.getByRole('button', { name: 'Export JSON' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Review remediation' })).toBeDisabled()
    await expectNoAutomatedViolations()
  })

  it('keeps normal-size theme text token pairs at WCAG AA contrast', () => {
    const light = tokenBlock(':root')
    const dark = tokenBlock(":root[data-theme='dark']")
    const highContrast = tokenBlock(":root[data-contrast='high']")
    const pairs: Array<[Record<string, string>, string, string]> = [
      [light, 'muted', 'bg'],
      [light, 'faint', 'bg'],
      [light, 'faint-2', 'bg'],
      [light, 'a-ink', 'a-soft'],
      [light, 'b-ink', 'b-soft'],
      [light, 'accent', 'accent-soft'],
      [light, 'success-ink', 'success-soft'],
      [light, 'ai', 'ai-soft'],
      [dark, 'muted', 'surface'],
      [dark, 'faint', 'surface'],
      [dark, 'faint-2', 'surface'],
      [dark, 'a-ink', 'a-soft'],
      [dark, 'b-ink', 'b-soft'],
      [dark, 'accent', 'accent-soft'],
      [dark, 'success-ink', 'success-soft'],
      [dark, 'ai', 'ai-soft'],
      [highContrast, 'muted', 'bg'],
      [highContrast, 'faint', 'bg'],
      [highContrast, 'faint-2', 'bg'],
      [highContrast, 'a-ink', 'a-soft'],
      [highContrast, 'b-ink', 'b-soft'],
      [highContrast, 'accent', 'accent-soft'],
      [highContrast, 'success-ink', 'success-soft'],
      [highContrast, 'ai', 'ai-soft'],
    ]

    for (const [theme, foreground, background] of pairs) {
      expect(
        contrast(theme[foreground], theme[background]),
        `${foreground}/${background}`,
      ).toBeGreaterThanOrEqual(4.5)
    }
  })

  it('animates the advanced-options disclosure while honoring reduced motion', () => {
    const collapsed = ruleBlock('.scan-options__content')
    const expanded = ruleBlock(".scan-options__content[data-open='true']")
    const chevron = ruleBlock('.scan-options__chevron')
    const reducedMotion = appCss.slice(appCss.indexOf('@media (prefers-reduced-motion: reduce)'))

    expect(collapsed).toContain('grid-template-rows: 0fr')
    expect(collapsed).toContain('grid-template-rows 360ms')
    expect(expanded).toContain('grid-template-rows: 1fr')
    expect(chevron).toContain('transition: transform 260ms')
    expect(reducedMotion).toContain('.scan-options__content')
    expect(reducedMotion).toContain('.scan-options__chevron')
    expect(reducedMotion).toContain('transition: none')
  })

  it('reserves scrollbar space so disclosures do not change the page width', () => {
    const frameBody = ruleBlock('.frame__body')
    expect(frameBody).toContain('overflow-y: scroll')
    expect(frameBody).toContain('scrollbar-gutter: stable')
  })

  it('keeps the finding file action in its own metadata row without overlap', () => {
    const desktopStart = appCss.indexOf('@media (min-width: 900px)')
    const desktopEnd = appCss.indexOf('@media (prefers-reduced-motion: reduce)')
    const desktopCss = appCss.slice(desktopStart, desktopEnd)
    const path = ruleBlock('.finding__path')
    const desktopMain = ruleBlock('.finding__main', desktopCss)
    const desktopOpen = ruleBlock('.finding__open', desktopCss)

    expect(path).toContain('flex: 1 1 auto')
    expect(path).toContain('min-width: 0')
    expect(desktopMain).not.toContain('padding-right')
    expect(desktopOpen).toContain('position: static')
    expect(desktopOpen).toContain('transform: none')
    expect(desktopOpen).not.toContain('position: absolute')
  })

  it('keeps finding geometry stable when a result becomes ignored', () => {
    const desktopStart = appCss.indexOf('@media (min-width: 900px)')
    const desktopEnd = appCss.indexOf('@media (prefers-reduced-motion: reduce)')
    const desktopCss = appCss.slice(desktopStart, desktopEnd)
    const desktopAside = ruleBlock('.finding__aside', desktopCss)

    expect(ruleBlock('.finding__select--placeholder')).toContain('width: 22px')
    expect(ruleBlock('.finding__select--placeholder')).toContain('height: 22px')
    expect(ruleBlock('.finding__aside')).toContain('min-height: 38px')
    expect(desktopAside).toContain('width: 300px')
    expect(desktopAside).toContain('justify-content: flex-end')
  })

  it('uses a thick sharpie mark only for values included in the redaction plan', () => {
    const redactedValue = ruleBlock('.finding__value--redacted')

    expect(redactedValue).toContain('text-decoration-line: line-through')
    expect(redactedValue).toContain('text-decoration-color: var(--redaction-mark)')
    expect(redactedValue).toContain('text-decoration-thickness: 0.52em')
    expect(redactedValue).toContain('text-decoration-skip-ink: none')
    expect(appCss).not.toContain('.finding--ignored .finding__value {')
    expect(ruleBlock('.finding')).not.toContain('background-color 180ms')
    expect(ruleBlock('.finding')).not.toContain('border-color 180ms')
  })

  it('keeps export colors stable during a single-finding plan update', () => {
    const quietExport = ruleBlock('.btn-export.btn-export--quiet-disabled:disabled')
    const quietReadableExport = ruleBlock(
      '.btn-export--secondary.btn-export--quiet-disabled:disabled',
    )

    expect(quietExport).toContain('background: var(--action-accent)')
    expect(quietExport).toContain('color: var(--on-action-accent)')
    expect(quietReadableExport).toContain('background: var(--accent-soft)')
    expect(quietReadableExport).toContain('color: var(--accent)')
  })

  it('keeps inactive category and ignored-finding states at WCAG AA without opacity compositing', () => {
    expect(ruleBlock('.cat-row')).not.toContain('opacity')
    expect(ruleBlock('.cat-row__desc')).toContain('color: var(--muted)')
    expect(ruleBlock('.finding--ignored')).not.toContain('opacity')
    expect(ruleBlock('.finding--ignored')).toContain('background: var(--surface-2)')
    expect(ruleBlock('.finding__evidence')).toContain('color: var(--muted)')
    expect(ruleBlock('.finding__path')).toContain('color: var(--muted)')
    expect(ruleBlock('.finding__undo')).toContain('color: var(--muted)')

    for (const theme of [
      tokenBlock(':root'),
      tokenBlock(":root[data-theme='dark']"),
      tokenBlock(":root[data-contrast='high']"),
    ]) {
      for (const foreground of ['ink', 'muted', 'accent']) {
        expect(
          contrast(theme[foreground], theme['surface-2']),
          `${foreground}/surface-2 in an inactive state`,
        ).toBeGreaterThanOrEqual(4.5)
      }
      expect(contrast(theme.muted, theme.surface), 'ignored badge text').toBeGreaterThanOrEqual(4.5)
    }
  })

  it('keeps every semantic action foreground/background pair at WCAG AA contrast', () => {
    const themes = [
      tokenBlock(':root'),
      tokenBlock(":root[data-theme='dark']"),
      tokenBlock(":root[data-contrast='high']"),
    ]
    const pairs = [
      ['on-action-accent', 'action-accent'],
      ['on-action-a', 'action-a'],
      ['on-tier-b-badge', 'tier-b-badge'],
    ]

    for (const theme of themes) {
      for (const [foreground, background] of pairs) {
        expect(
          contrast(theme[foreground], theme[background]),
          `${foreground}/${background}`,
        ).toBeGreaterThanOrEqual(4.5)
      }
    }

    const semanticRules: Array<[string, string, string]> = [
      ['.cta', 'action-accent', 'on-action-accent'],
      ['.bulk-plan-actions .bulk-plan-actions__primary', 'action-accent', 'on-action-accent'],
      [".bulk-actions button[aria-pressed='true']", 'action-accent', 'on-action-accent'],
      ['.tier__badge--a', 'action-a', 'on-action-a'],
      ['.tier__badge--b', 'tier-b-badge', 'on-tier-b-badge'],
      [
        '.finding--a .finding__anon,\n.finding--b .finding__anon',
        'action-accent',
        'on-action-accent',
      ],
      ['.review-btn,\n.generate-btn', 'action-accent', 'on-action-accent'],
      ['.btn-export', 'action-accent', 'on-action-accent'],
    ]
    for (const [selector, background, foreground] of semanticRules) {
      const declarations = ruleBlock(selector)
      expect(declarations).toContain(`background: var(--${background})`)
      expect(declarations).toContain(`color: var(--${foreground})`)
    }
  })

  it('keeps disabled result actions readable without opacity compositing', () => {
    for (const theme of [
      tokenBlock(':root'),
      tokenBlock(":root[data-theme='dark']"),
      tokenBlock(":root[data-contrast='high']"),
    ]) {
      expect(contrast(theme['disabled-ink'], theme['disabled-bg'])).toBeGreaterThanOrEqual(4.5)
      expect(contrast(theme['disabled-border'], theme['disabled-bg'])).toBeGreaterThanOrEqual(3)
    }

    for (const selector of [
      '.bulk-actions button:disabled,\n.bulk-plan-actions button:disabled',
      '.bulk-plan-actions .bulk-plan-actions__primary:disabled',
      '.bulk-btn:disabled',
      '.finding__anon:disabled',
      '.finding__ignore:disabled',
      '.review-btn:disabled,\n.generate-btn:disabled',
      '.btn-export:disabled',
    ]) {
      const declarations = ruleBlock(selector)
      expect(declarations).not.toContain('opacity')
      expect(declarations).toContain('var(--disabled-')
    }
  })

  it('uses system colors for result actions in Windows forced-color mode', () => {
    const forcedColors = appCss.slice(appCss.indexOf('@media (forced-colors: active)'))

    expect(forcedColors).toContain('.triage-controls')
    expect(forcedColors).toContain('.bulk-actions')
    expect(forcedColors).toContain('.bulk-plan-actions')
    expect(forcedColors).toContain('.remediation-summary')
    expect(forcedColors).toContain('background: Highlight')
    expect(forcedColors).toContain('color: HighlightText')
    expect(forcedColors).toContain('border-color: GrayText')
    expect(forcedColors).toContain('color: GrayText')
  })

  it('keeps form-control boundaries distinguishable in both themes', () => {
    for (const theme of [
      tokenBlock(':root'),
      tokenBlock(":root[data-theme='dark']"),
      tokenBlock(":root[data-contrast='high']"),
    ]) {
      for (const background of ['bg', 'surface', 'surface-2']) {
        expect(
          contrast(theme['control-border'], theme[background]),
          `control-border/${background}`,
        ).toBeGreaterThanOrEqual(3)
      }
    }

    for (const selector of [
      '.scan-options__grid input',
      '.path-input',
      '.target-box__input',
      '.triage-controls select',
    ]) {
      expect(ruleBlock(selector)).toContain('border: 1')
      expect(ruleBlock(selector)).toContain('var(--control-border)')
    }
  })

  it('keeps custom checkbox and enabled switch state indicators at non-text contrast', () => {
    const themes = [
      tokenBlock(':root'),
      tokenBlock(":root[data-theme='dark']"),
      tokenBlock(":root[data-contrast='high']"),
    ]

    for (const theme of themes) {
      const pairs = [
        ['control-border', 'surface-2'],
        ['control-selected', 'surface'],
        ['on-control-selected', 'control-selected'],
        ['switch-off', 'surface-2'],
        ['switch-knob', 'switch-off'],
        ['switch-on', 'ai-soft'],
        ['switch-knob', 'switch-on'],
      ]
      for (const [foreground, background] of pairs) {
        expect(
          contrast(theme[foreground], theme[background]),
          `${foreground}/${background}`,
        ).toBeGreaterThanOrEqual(3)
      }
    }

    expect(ruleBlock('.cat-row__mark')).toContain('border: 1.5px solid var(--control-border)')
    expect(ruleBlock('.cat-row__mark')).toContain('color: var(--on-control-selected)')
    expect(ruleBlock('.cat-row--on .cat-row__mark')).toContain(
      'background: var(--control-selected)',
    )
    const customCheckbox = ruleBlock(
      ".finding__select input,\n.scan-options__check input,\n.replacement-warning input[type='checkbox']",
    )
    expect(customCheckbox).toContain('appearance: none')
    expect(customCheckbox).toContain('margin: 0')
    expect(customCheckbox).toContain('width: 22px')
    expect(customCheckbox).toContain('border-radius: 7px')
    expect(customCheckbox).toContain('border: 1.5px solid var(--control-border)')
    expect(customCheckbox).toContain('transition:')
    const customCheckboxMark = ruleBlock(
      ".finding__select input::before,\n.scan-options__check input::before,\n.replacement-warning input[type='checkbox']::before",
    )
    expect(customCheckboxMark).toContain('clip-path:')
    expect(customCheckboxMark).toContain('transform: scale(0)')
    expect(ruleBlock('.cat-row__mark')).toContain('transition:')
    expect(ruleBlock('.cat-row--on .cat-row__mark svg')).toContain('animation: hv-check-pop')
    expect(
      ruleBlock(
        ".finding__select input:checked,\n.scan-options__check input:checked,\n.replacement-warning input[type='checkbox']:checked",
      ),
    ).toContain('background: var(--control-selected)')
    expect(ruleBlock('.switch')).toContain('background: var(--switch-off)')
    expect(ruleBlock('.switch--on')).toContain('background: var(--switch-on)')
    expect(ruleBlock('.switch__knob')).toContain('background: var(--switch-knob)')
  })

  it('uses yellow AI accents and black finding fills in app high-contrast mode', () => {
    const highContrast = tokenBlock(":root[data-contrast='high']")
    expect(highContrast.ai).toBe('#ffff00')
    expect(highContrast['ai-border']).toBe('#ffff00')
    expect(
      ruleBlock(
        ":root[data-contrast='high'] .finding--a,\n:root[data-contrast='high'] .finding--b,\n:root[data-contrast='high'] .finding--ignored",
      ),
    ).toContain('background: var(--surface)')
  })

  it('centers tier badges and replacement confirmation controls', () => {
    const badge = ruleBlock('.tier__badge')
    expect(badge).toContain('display: grid')
    expect(badge).toContain('place-items: center')
    expect(badge).toContain('line-height: 1')
    expect(ruleBlock('.replacement-warning label')).toContain('align-items: center')
    expect(appCss).toContain(
      ".replacement-warning input[type='checkbox'] {\n  flex: none;\n  margin: 0;",
    )
  })

  it('uses the green selection palette for the scanning emblem', () => {
    expect(ruleBlock('.scanning__ring')).toContain('border: 2px solid var(--success-border)')
    expect(ruleBlock('.scanning__shield')).toContain('background: var(--control-selected)')
    expect(ruleBlock('.scanning__shield')).toContain('color: var(--on-control-selected)')
  })

  it('stops the indeterminate progress animation when reduced motion is requested', () => {
    expect(appCss).toMatch(
      /@media \(prefers-reduced-motion: reduce\)[\s\S]*?\.progress__fill--indeterminate,[\s\S]*?animation: none;/,
    )
  })

  it('shows scripted focus destinations and lets notifications reflow', () => {
    const scriptedFocus = ruleBlock("[tabindex='-1']:focus")
    expect(scriptedFocus).toContain('outline: 2px solid var(--accent)')
    expect(scriptedFocus).toContain('outline-offset: 3px')

    const toastText = ruleBlock('.toast span')
    expect(toastText).toContain('overflow-wrap: anywhere')
    expect(toastText).toContain('white-space: normal')
    expect(toastText).not.toContain('text-overflow: ellipsis')
  })
})
