import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import * as client from '../api/client'
import type {
  GeneratedOutputDetails,
  PublicFinding,
  PublicScanResult,
  RemediationPlan,
  UserTarget,
} from '../types'
import ResultsScreen from './ResultsScreen'

vi.mock('../api/client')

const INCLUDE_ACTION_NAME = /Include finding .* in redaction plan/i
const IGNORE_ACTION_NAME = /Ignore finding /i
const RETURN_ACTION_NAME = /Return finding .* to pending/i
const EXCLUDE_ACTION_NAME = /Exclude finding .* from redaction plan/i
const OPEN_ACTION_NAME = /Show .* in folder for /i
const OPEN_OUTPUT_ACTION_NAME = /Show redacted copy .* in folder/i

beforeEach(() => {
  vi.clearAllMocks()
  vi.mocked(client.getRemediationPlan).mockReset()
  vi.mocked(client.postRevealFindingValues).mockResolvedValue({ values: [] })
  vi.mocked(client.putRemediationPlan).mockImplementation(
    async (_scanId, includedFindingIds, ignoredFindingIds, planRevision) =>
      makePlan(includedFindingIds, ignoredFindingIds, planRevision + 1),
  )
  vi.mocked(client.getRemediationPlan).mockImplementation(async () => {
    // Most component tests exercise a single in-memory workflow. Model the
    // GET as the authoritative value returned by its latest completed PUT;
    // freshness-specific tests override this response explicitly.
    const lastUpdate = vi.mocked(client.putRemediationPlan).mock.results.at(-1)
    return lastUpdate ? await lastUpdate.value : makePlan()
  })
})

function makePlan(
  included: string[] = [],
  ignored: string[] = [],
  planRevision = 1,
): RemediationPlan {
  const ids = [...new Set(['f1', 'f2', 'f3', 'doc1', ...included, ...ignored])]
  return {
    plan_revision: planRevision,
    findings: ids.map((findingId) => ({
      finding_id: findingId,
      state: included.includes(findingId)
        ? 'included'
        : ignored.includes(findingId)
          ? 'ignored'
          : findingId === 'doc1'
            ? 'read_only'
            : 'pending',
    })),
    files:
      included.length > 0
        ? [
            {
              source_path: 'C:\\project\\secrets.py',
              output_path: 'C:\\project\\secrets-auto-redacted-copy.py',
              included_finding_ids: included,
              output_state: 'not_created',
            },
          ]
        : [],
    selected_finding_count: included.length,
    affected_file_count: included.length > 0 ? 1 : 0,
    read_only_finding_count: 0,
    retained_artifact_paths: [],
    can_review: included.length > 0,
    can_generate: included.length > 0,
  }
}

function currentPlan(included: string[] = ['f1'], planRevision = 1): RemediationPlan {
  const plan = makePlan(included, [], planRevision)
  return {
    ...plan,
    files: plan.files.map((file) => ({ ...file, output_state: 'current' })),
  }
}

function generatedOutput(appliedFindingIds: string[] = ['f1']): GeneratedOutputDetails {
  return {
    source_path: 'C:\\project\\secrets.py',
    output_path: 'C:\\project\\secrets-auto-redacted-copy.py',
    applied_finding_ids: appliedFindingIds,
    verification_status: 'verified',
    warnings: ['Evidence retained while this output is current.'],
    source_fingerprint: {
      resolved_path: 'C:\\project\\secrets.py',
      size: 42,
      modified_ns: 123,
      sha256: 'c'.repeat(64),
    },
    rescan_status: 'completed',
    remaining_finding_count: 0,
    remaining_tier_a_count: 0,
  }
}

function deferred<Value>() {
  let resolve!: (value: Value) => void
  let reject!: (reason?: unknown) => void
  const promise = new Promise<Value>((done, fail) => {
    resolve = done
    reject = fail
  })
  return { promise, resolve, reject }
}

function installObjectUrlHarness() {
  const createObjectURL = vi.fn<(blob: Blob) => string>().mockReturnValue('blob:redactlens-report')
  const revokeObjectURL = vi.fn<(url: string) => void>()
  const originalCreate = Object.getOwnPropertyDescriptor(URL, 'createObjectURL')
  const originalRevoke = Object.getOwnPropertyDescriptor(URL, 'revokeObjectURL')
  const clickedAnchors: HTMLAnchorElement[] = []
  const click = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(function (
    this: HTMLAnchorElement,
  ) {
    clickedAnchors.push(this)
  })
  Object.defineProperty(URL, 'createObjectURL', { configurable: true, value: createObjectURL })
  Object.defineProperty(URL, 'revokeObjectURL', { configurable: true, value: revokeObjectURL })
  return {
    createObjectURL,
    revokeObjectURL,
    clickedAnchors,
    restore() {
      click.mockRestore()
      if (originalCreate) Object.defineProperty(URL, 'createObjectURL', originalCreate)
      else Reflect.deleteProperty(URL, 'createObjectURL')
      if (originalRevoke) Object.defineProperty(URL, 'revokeObjectURL', originalRevoke)
      else Reflect.deleteProperty(URL, 'revokeObjectURL')
    },
  }
}

function readBlob(blob: Blob) {
  return new Promise<string>((resolve, reject) => {
    const reader = new FileReader()
    reader.addEventListener('load', () => resolve(String(reader.result)))
    reader.addEventListener('error', () => reject(reader.error))
    reader.readAsText(blob)
  })
}

function makeFinding(overrides: Partial<PublicFinding> = {}): PublicFinding {
  return {
    id: 'f1',
    file_path: 'C:\\project\\secrets.py',
    line: 3,
    column: 5,
    location: null,
    can_anonymize: true,
    redacted_preview: '12*******89',
    detector_id: 'us_ssn',
    category: 'personal_id',
    confidence: 0.95,
    tier: 'A',
    explanation: 'A U.S. Social Security Number.',
    risk_lesson: 'Can be used for identity theft.',
    suggested_action: 'anonymize',
    supporting_detections: [],
    ...overrides,
  }
}

function makeResult(
  findings: PublicFinding[],
  overrides: Partial<PublicScanResult> = {},
): PublicScanResult {
  return {
    scan_id: 'scan-1',
    event_cursor: 1,
    created_at: '2026-07-15T00:00:00Z',
    expires_at: '2026-07-15T00:15:00Z',
    findings,
    summary: {},
    scanned_files: ['a.py'],
    skipped_files: [],
    llm_used: false,
    state: 'complete',
    progress: {
      stage: 'complete',
      completed_files: 1,
      total_files: 1,
      percent: 100,
      current_file: null,
      findings_so_far: findings.length,
      skipped_files: 0,
    },
    error: null,
    metadata: {
      selected_roots: ['C:\\project'],
      duration_ms: 1250,
      data_scanned_bytes: 42,
      detector_count: 12,
      ai_model: null,
    },
    ...overrides,
  }
}

function renderResults(
  result: PublicScanResult,
  overrides: {
    isRefining?: boolean
    refineError?: string | null
    onStartOver?: () => void
    onSessionExpired?: (message?: string) => void
    onToast?: (message: string) => void
    userTargets?: UserTarget[]
  } = {},
) {
  return render(
    <ResultsScreen
      result={result}
      isRefining={overrides.isRefining ?? false}
      refineError={overrides.refineError ?? null}
      userTargets={overrides.userTargets}
      onStartOver={overrides.onStartOver ?? vi.fn()}
      onSessionExpired={overrides.onSessionExpired ?? vi.fn()}
      onToast={overrides.onToast}
    />,
  )
}

describe('ResultsScreen', () => {
  it('names the custom rule that produced a finding and normalizes fallback masks', () => {
    renderResults(
      makeResult([
        makeFinding({
          detector_id: 'user_target_desc_0',
          redacted_preview: 'sc<redacted><redacted>29',
        }),
      ]),
      {
        userTargets: [
          { kind: 'description', value: 'credentials assigned in source code', category: 'custom' },
        ],
      },
    )

    expect(
      screen.getAllByText('Found with your custom rule "credentials assigned in source code"'),
    ).toHaveLength(2)
    expect(screen.getByText('sc**29')).toBeInTheDocument()
    expect(screen.queryByText(/<redacted>/i)).not.toBeInTheDocument()
  })

  it('keeps exact values masked until the user reveals them and clears them when hidden', async () => {
    const user = userEvent.setup()
    const rawValue = '123-45-6789'
    vi.mocked(client.postRevealFindingValues).mockResolvedValue({
      values: [{ finding_id: 'f1', value: rawValue }],
    })
    renderResults(makeResult([makeFinding()]))

    const visibility = screen.getByRole('switch', { name: 'Full finding values' })
    expect(visibility).toHaveAttribute('aria-checked', 'false')
    expect(screen.getByText('12*******89')).toBeInTheDocument()
    expect(screen.queryByText(rawValue)).not.toBeInTheDocument()

    await user.click(visibility)

    expect(await screen.findByText(rawValue)).toBeInTheDocument()
    expect(visibility).toHaveAttribute('aria-checked', 'true')
    expect(client.postRevealFindingValues).toHaveBeenCalledWith('scan-1', ['f1'])
    expect(screen.getByText(/Hide them before screen sharing/i)).toBeInTheDocument()
    expect(
      screen.getByRole('button', {
        name: 'Include finding 12*******89 from secrets.py in redaction plan',
      }),
    ).toBeInTheDocument()

    await user.click(visibility)

    expect(visibility).toHaveAttribute('aria-checked', 'false')
    expect(screen.queryByText(rawValue)).not.toBeInTheDocument()
    expect(screen.getByText('12*******89')).toBeInTheDocument()
  })

  it('reveals large result sets in bounded batches and never displays a partial response', async () => {
    const user = userEvent.setup()
    const findings = Array.from({ length: 251 }, (_, index) =>
      makeFinding({
        id: `f${index}`,
        redacted_preview: `masked-${index}`,
      }),
    )
    vi.mocked(client.postRevealFindingValues)
      .mockImplementationOnce(async (_scanId, findingIds) => ({
        values: findingIds.map((findingId) => ({
          finding_id: findingId,
          value: `raw-${findingId}`,
        })),
      }))
      .mockRejectedValueOnce(new Error('local service stopped'))
    renderResults(makeResult(findings))

    await user.click(screen.getByRole('switch', { name: 'Full finding values' }))

    expect(await screen.findByRole('alert')).toHaveTextContent(
      'Could not show full values. They remain hidden.',
    )
    expect(client.postRevealFindingValues).toHaveBeenCalledTimes(2)
    expect(vi.mocked(client.postRevealFindingValues).mock.calls[0][1]).toHaveLength(250)
    expect(vi.mocked(client.postRevealFindingValues).mock.calls[1][1]).toHaveLength(1)
    expect(screen.queryByText('raw-f0')).not.toBeInTheDocument()
    expect(screen.getByText('masked-0')).toBeInTheDocument()
    expect(screen.getByRole('switch', { name: 'Full finding values' })).toHaveAttribute(
      'aria-checked',
      'false',
    )
  })

  it('groups findings by tier and never claims the user is "safe" or "clean"', () => {
    renderResults(makeResult([makeFinding({ tier: 'A' }), makeFinding({ id: 'f2', tier: 'B' })]))

    expect(screen.getByRole('heading', { name: /Confirmed sensitive/i })).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: /Worth a double-check/i })).toBeInTheDocument()
    expect(screen.getByText('Strong match — still worth a review.')).toBeInTheDocument()
    expect(screen.getByText('Less certain — your call.')).toBeInTheDocument()
    expect(screen.queryByText(/you're safe/i)).not.toBeInTheDocument()
    expect(screen.queryByText(/\bclean\b/i)).not.toBeInTheDocument()
  })

  it('shows per-tier counts in the stat row', () => {
    renderResults(
      makeResult([
        makeFinding({ id: 'f1', tier: 'A' }),
        makeFinding({ id: 'f2', tier: 'A' }),
        makeFinding({ id: 'f3', tier: 'B', confidence: 0.6 }),
      ]),
    )

    expect(screen.getByText('Confirmed').previousElementSibling).toHaveTextContent('2')
    expect(screen.getByText('Double-check').previousElementSibling).toHaveTextContent('1')
    expect(screen.getByText('Decided').previousElementSibling).toHaveTextContent('0')
  })

  it('uses summary cards and filters to isolate results in one action', async () => {
    const user = userEvent.setup()
    renderResults(
      makeResult([
        makeFinding({ id: 'f1', tier: 'A', redacted_preview: 'tier-a-value' }),
        makeFinding({ id: 'f2', tier: 'B', confidence: 0.6, redacted_preview: 'tier-b-value' }),
      ]),
    )

    await user.click(screen.getByRole('button', { name: /1 confirmed findings/i }))

    expect(screen.getByText('tier-a-value')).toBeInTheDocument()
    expect(screen.queryByText('tier-b-value')).not.toBeInTheDocument()
    expect(screen.getByLabelText('Tier')).toHaveValue('A')
  })

  it('filters by category and can regroup the same results by file', async () => {
    const user = userEvent.setup()
    renderResults(
      makeResult([
        makeFinding({ id: 'f1', file_path: 'C:\\project\\src\\secrets.py' }),
        makeFinding({
          id: 'f2',
          file_path: 'C:\\project\\config\\db.env',
          category: 'credential',
          detector_id: 'password_assignment',
          redacted_preview: 'pa******rd',
        }),
      ]),
    )

    await user.selectOptions(screen.getByLabelText('Category'), 'credential')
    await user.selectOptions(screen.getByLabelText('Group by'), 'file')

    expect(screen.getByRole('heading', { name: /config\/db.env/i })).toBeInTheDocument()
    expect(screen.queryByText('12*******89')).not.toBeInTheDocument()
  })

  it('resets active triage filters with user-facing selection language', async () => {
    const user = userEvent.setup()
    renderResults(
      makeResult([
        makeFinding({ id: 'f1', category: 'personal_id' }),
        makeFinding({ id: 'f2', category: 'credential' }),
      ]),
    )

    await user.selectOptions(screen.getByLabelText('Category'), 'credential')

    const resetButton = screen.getByRole('button', { name: 'Reset filters (1)' })
    expect(resetButton).toBeEnabled()
    await user.click(resetButton)

    expect(screen.getByLabelText('Category')).toHaveValue('all')
    expect(screen.getByRole('button', { name: 'Reset filters' })).toBeDisabled()
  })

  it('filters by detector and by each individual remediation status', async () => {
    const user = userEvent.setup()
    renderResults(
      makeResult([
        makeFinding({ id: 'f1', redacted_preview: 'ssn-preview' }),
        makeFinding({
          id: 'f2',
          detector_id: 'aws_access_key',
          category: 'credential',
          redacted_preview: 'key-preview',
        }),
        makeFinding({
          id: 'doc1',
          detector_id: 'email',
          redacted_preview: 'mail-preview',
          can_anonymize: false,
        }),
        makeFinding({ id: 'f3', redacted_preview: 'pending-preview' }),
      ]),
    )

    await user.selectOptions(screen.getByLabelText('Detector'), 'aws_access_key')
    expect(screen.getByText('key-preview')).toBeInTheDocument()
    expect(screen.queryByText('ssn-preview')).not.toBeInTheDocument()

    await user.selectOptions(screen.getByLabelText('Detector'), 'all')
    await user.click(screen.getByRole('button', { name: /Ignore finding key-preview/i }))
    await user.click(screen.getByRole('button', { name: /Include finding ssn-preview/i }))

    await user.selectOptions(screen.getByLabelText('Remediation status'), 'included')
    expect(screen.getByText('ssn-preview')).toBeInTheDocument()
    expect(screen.queryByText('key-preview')).not.toBeInTheDocument()

    await user.selectOptions(screen.getByLabelText('Remediation status'), 'ignored')
    expect(screen.getByText('key-preview')).toBeInTheDocument()
    expect(screen.queryByText('ssn-preview')).not.toBeInTheDocument()

    await user.selectOptions(screen.getByLabelText('Remediation status'), 'read_only')
    expect(screen.getByText('mail-preview')).toBeInTheDocument()
    expect(screen.queryByText('key-preview')).not.toBeInTheDocument()

    await user.selectOptions(screen.getByLabelText('Remediation status'), 'pending')
    expect(screen.getByText('pending-preview')).toBeInTheDocument()
    expect(screen.queryByText('mail-preview')).not.toBeInTheDocument()
  })

  it('uses the Decided summary card to show included and ignored findings only', async () => {
    const user = userEvent.setup()
    renderResults(
      makeResult([
        makeFinding({ id: 'f1', redacted_preview: 'included-preview' }),
        makeFinding({ id: 'f2', redacted_preview: 'ignored-preview' }),
        makeFinding({ id: 'f3', redacted_preview: 'pending-preview' }),
      ]),
    )

    await user.click(screen.getByRole('button', { name: /Include finding included-preview/i }))
    await user.click(screen.getByRole('button', { name: /Ignore finding ignored-preview/i }))
    await user.click(screen.getByRole('button', { name: /2 decided findings/i }))

    expect(screen.getByLabelText('Remediation status')).toHaveValue('decided')
    expect(screen.getByText('included-preview')).toBeInTheDocument()
    expect(screen.getByText('ignored-preview')).toBeInTheDocument()
    expect(screen.queryByText('pending-preview')).not.toBeInTheDocument()
  })

  it('keeps identical relative paths under different Windows roots distinct', async () => {
    const user = userEvent.setup()
    renderResults(
      makeResult(
        [
          makeFinding({
            id: 'drive',
            file_path: 'c:\\CLIENT-ONE\\src\\same.py',
            redacted_preview: 'dr******ue',
          }),
          makeFinding({
            id: 'unc',
            file_path: '\\\\server\\share\\CLIENT-TWO\\src\\same.py',
            redacted_preview: 'un****ue',
          }),
        ],
        {
          metadata: {
            selected_roots: ['C:\\client-one', '\\\\SERVER\\Share\\client-two'],
            duration_ms: 1250,
            data_scanned_bytes: 42,
            detector_count: 12,
            ai_model: null,
          },
        },
      ),
    )

    await user.selectOptions(screen.getByLabelText('Group by'), 'file')
    expect(screen.getByRole('heading', { name: /Scan root 1: src\/same.py/i })).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: /Scan root 2: src\/same.py/i })).toBeInTheDocument()

    await user.selectOptions(
      screen.getByLabelText('File'),
      screen.getByRole('option', { name: 'Scan root 2: src/same.py' }),
    )
    expect(screen.queryByText('dr******ue')).not.toBeInTheDocument()
    expect(screen.getByText('un****ue')).toBeInTheDocument()
    expect(
      screen.queryByRole('heading', { name: /Scan root 1: src\/same.py/i }),
    ).not.toBeInTheDocument()
  })

  it('applies one exact-scope bulk inclusion to selected visible findings', async () => {
    const user = userEvent.setup()
    renderResults(
      makeResult([
        makeFinding({ id: 'f1' }),
        makeFinding({ id: 'f2', tier: 'B', confidence: 0.6, redacted_preview: 'se*******wo' }),
        makeFinding({ id: 'doc1', can_anonymize: false, redacted_preview: 're******ly' }),
      ]),
    )

    expect(
      screen.getByRole('button', {
        name: 'Include all pending writable Tier A findings across all results (1)',
      }),
    ).toBeInTheDocument()
    await user.click(
      screen.getByRole('button', { name: 'Select all visible actionable findings (2)' }),
    )
    expect(
      within(screen.getByRole('region', { name: 'Bulk finding selection' })).getByRole('status'),
    ).toHaveTextContent('2 actionable finding(s) selected')
    await user.click(
      screen.getByRole('button', { name: 'Include selected actionable findings (2)' }),
    )

    expect(client.putRemediationPlan).toHaveBeenCalledTimes(1)
    expect(client.putRemediationPlan).toHaveBeenCalledWith('scan-1', ['f1', 'f2'], [], 0)
    expect(
      screen.getByRole('button', { name: 'Include selected actionable findings (0)' }),
    ).toBeDisabled()
    expect(screen.getByRole('region', { name: 'Bulk finding selection' })).toHaveFocus()
  })

  it('provides separate visible Tier A and Tier B selection shortcuts', async () => {
    const user = userEvent.setup()
    renderResults(
      makeResult([
        makeFinding({ id: 'f1', tier: 'A' }),
        makeFinding({ id: 'f2', tier: 'B', confidence: 0.6, redacted_preview: 'tier-b' }),
      ]),
    )

    const selectionRegion = screen.getByRole('region', { name: 'Bulk finding selection' })
    const selectAllButton = within(selectionRegion).getByRole('button', {
      name: 'Select all visible actionable findings (2)',
    })
    const selectTierAButton = within(selectionRegion).getByRole('button', {
      name: 'Select visible actionable Tier A findings (1)',
    })
    const selectTierBButton = within(selectionRegion).getByRole('button', {
      name: 'Select visible actionable Tier B findings (1)',
    })
    expect(selectAllButton).toHaveAttribute('aria-pressed', 'false')
    expect(selectTierAButton).toHaveAttribute('aria-pressed', 'false')
    expect(selectTierBButton).toHaveAttribute('aria-pressed', 'false')
    expect(
      within(selectionRegion).queryByRole('button', {
        name: 'Include selected actionable findings (0)',
      }),
    ).not.toBeInTheDocument()
    expect(
      within(screen.getByRole('group', { name: 'Selected finding plan actions' })).getByRole(
        'button',
        { name: 'Include selected actionable findings (0)' },
      ),
    ).toBeDisabled()

    await user.click(selectTierAButton)
    expect(screen.getAllByRole('checkbox')[0]).toBeChecked()
    expect(screen.getAllByRole('checkbox')[1]).not.toBeChecked()
    expect(
      within(selectionRegion).getByRole('button', {
        name: 'Unselect visible actionable Tier A findings (1)',
      }),
    ).toHaveAttribute('aria-pressed', 'true')
    expect(
      within(screen.getByRole('region', { name: 'Bulk finding selection' })).getByRole('status'),
    ).toHaveTextContent('1 actionable finding(s) selected')

    await user.click(
      within(selectionRegion).getByRole('button', {
        name: 'Unselect visible actionable Tier A findings (1)',
      }),
    )
    for (const checkbox of screen.getAllByRole('checkbox')) expect(checkbox).not.toBeChecked()

    await user.click(selectAllButton)
    for (const checkbox of screen.getAllByRole('checkbox')) expect(checkbox).toBeChecked()
    expect(
      within(selectionRegion).getByRole('button', {
        name: 'Unselect all visible actionable findings (2)',
      }),
    ).toHaveAttribute('aria-pressed', 'true')
    expect(
      within(selectionRegion).getByRole('button', {
        name: 'Unselect visible actionable Tier A findings (1)',
      }),
    ).toHaveAttribute('aria-pressed', 'true')
    expect(
      within(selectionRegion).getByRole('button', {
        name: 'Unselect visible actionable Tier B findings (1)',
      }),
    ).toHaveAttribute('aria-pressed', 'true')

    await user.click(
      within(selectionRegion).getByRole('button', {
        name: 'Unselect visible actionable Tier B findings (1)',
      }),
    )
    expect(screen.getAllByRole('checkbox')[0]).toBeChecked()
    expect(screen.getAllByRole('checkbox')[1]).not.toBeChecked()
    expect(selectAllButton).toHaveAttribute('aria-pressed', 'false')
    expect(selectTierAButton).toHaveAttribute('aria-pressed', 'true')
    expect(selectTierBButton).toHaveAttribute('aria-pressed', 'false')
    expect(
      within(screen.getByRole('region', { name: 'Bulk finding selection' })).getByRole('status'),
    ).toHaveTextContent('1 actionable finding(s) selected')
  })

  it('bulk Exclude changes only selected included findings and preserves mixed states', async () => {
    const user = userEvent.setup()
    renderResults(
      makeResult([
        makeFinding({ id: 'f1', redacted_preview: 'included-preview' }),
        makeFinding({ id: 'f2', redacted_preview: 'ignored-preview' }),
        makeFinding({ id: 'f3', redacted_preview: 'pending-preview' }),
      ]),
    )

    await user.click(screen.getByRole('button', { name: /Include finding included-preview/i }))
    await user.click(screen.getByRole('button', { name: /Ignore finding ignored-preview/i }))
    expect(
      screen.queryByRole('checkbox', { name: /Select finding ignored-preview/i }),
    ).not.toBeInTheDocument()
    await user.click(
      screen.getByRole('button', { name: 'Select all visible actionable findings (2)' }),
    )
    await user.click(
      screen.getByRole('button', {
        name: 'Exclude selected included finding from redaction plan (1)',
      }),
    )

    expect(client.putRemediationPlan).toHaveBeenLastCalledWith('scan-1', [], ['f2'], 2)
    expect(screen.getByText('Ignored')).toBeInTheDocument()
    expect(
      screen.getByRole('button', {
        name: 'Exclude selected included findings from redaction plan (0)',
      }),
    ).toBeDisabled()
    expect(
      within(screen.getByRole('region', { name: 'Bulk finding selection' })).getByRole('status'),
    ).toHaveTextContent('1 actionable finding(s) selected')
    expect(screen.getByRole('region', { name: 'Bulk finding selection' })).toHaveFocus()
  })

  it('excludes ignored findings from all three mass-selection shortcuts', async () => {
    const user = userEvent.setup()
    renderResults(
      makeResult([
        makeFinding({ id: 'a-ignored', tier: 'A', redacted_preview: 'ignored-a' }),
        makeFinding({ id: 'a-pending', tier: 'A', redacted_preview: 'pending-a' }),
        makeFinding({
          id: 'b-ignored',
          tier: 'B',
          confidence: 0.6,
          redacted_preview: 'ignored-b',
        }),
        makeFinding({
          id: 'b-pending',
          tier: 'B',
          confidence: 0.6,
          redacted_preview: 'pending-b',
        }),
      ]),
    )

    await user.click(screen.getByRole('button', { name: /Ignore finding ignored-a/i }))
    await user.click(screen.getByRole('button', { name: /Ignore finding ignored-b/i }))

    const selectionRegion = screen.getByRole('region', { name: 'Bulk finding selection' })
    const selectAll = within(selectionRegion).getByRole('button', {
      name: 'Select all visible actionable findings (2)',
    })
    const selectTierA = within(selectionRegion).getByRole('button', {
      name: 'Select visible actionable Tier A findings (1)',
    })
    const selectTierB = within(selectionRegion).getByRole('button', {
      name: 'Select visible actionable Tier B findings (1)',
    })

    await user.click(selectAll)
    expect(screen.getByRole('checkbox', { name: /Select finding pending-a/i })).toBeChecked()
    expect(screen.getByRole('checkbox', { name: /Select finding pending-b/i })).toBeChecked()
    expect(screen.queryByRole('checkbox', { name: /Select finding ignored-a/i })).toBeNull()
    expect(screen.queryByRole('checkbox', { name: /Select finding ignored-b/i })).toBeNull()

    await user.click(
      within(selectionRegion).getByRole('button', {
        name: 'Unselect all visible actionable findings (2)',
      }),
    )
    await user.click(selectTierA)
    expect(screen.getByRole('checkbox', { name: /Select finding pending-a/i })).toBeChecked()
    expect(screen.getByRole('checkbox', { name: /Select finding pending-b/i })).not.toBeChecked()

    await user.click(selectTierB)
    expect(screen.getByRole('checkbox', { name: /Select finding pending-a/i })).toBeChecked()
    expect(screen.getByRole('checkbox', { name: /Select finding pending-b/i })).toBeChecked()
  })

  it('keeps skipped files collapsed, grouped, relative, and actionable', async () => {
    const user = userEvent.setup()
    renderResults(
      makeResult([makeFinding()], {
        skipped_files: [
          {
            path: 'C:\\project\\archives\\backup.zip',
            reason: 'archive — unpack it and scan the extracted folder instead',
            code: 'archive',
            stage: 'extraction',
            rule: null,
          },
        ],
      }),
    )

    const disclosure = screen.getByText('Review 1 skipped file')
    expect(screen.queryByText('Archives')).not.toBeInTheDocument()
    await user.click(disclosure)

    expect(screen.getByText('Archives')).toBeVisible()
    expect(screen.getByText(/Unpack each archive/i)).toBeVisible()
    expect(screen.getByText('archives/backup.zip')).toBeVisible()
  })

  it('lazily renders large skipped-file sets in focused batches', async () => {
    const user = userEvent.setup()
    const skippedFiles = Array.from({ length: 120 }, (_, index) => ({
      path: `C:\\project\\archives\\file-${String(index).padStart(3, '0')}.zip`,
      reason: 'archive — unpack it and scan the extracted folder instead',
      code: 'archive',
      stage: 'extraction' as const,
      rule: null,
    }))
    renderResults(makeResult([makeFinding()], { skipped_files: skippedFiles }))

    expect(screen.queryByText('archives/file-000.zip')).not.toBeInTheDocument()
    await user.click(screen.getByText('Review 120 skipped files'))

    expect(await screen.findByText('Showing 50 of 120 skipped files.')).toBeInTheDocument()
    expect(screen.getByText('archives/file-049.zip')).toBeInTheDocument()
    expect(screen.queryByText('archives/file-050.zip')).not.toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: 'Show up to 50 more skipped files' }))
    expect(screen.getByText('Showing 100 of 120 skipped files.')).toBeInTheDocument()
    expect(screen.getByText('archives/file-050.zip').closest('li')).toHaveFocus()
    expect(screen.queryByText('archives/file-100.zip')).not.toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: 'Show up to 20 more skipped files' }))
    expect(screen.getByText('Showing 120 of 120 skipped files.')).toBeInTheDocument()
    expect(screen.getByText('archives/file-100.zip').closest('li')).toHaveFocus()
    expect(
      screen.queryByRole('button', { name: /Show up to .* more skipped files/ }),
    ).not.toBeInTheDocument()
  })

  it('shows metadata, human detector labels, and full paths only inside disclosures', async () => {
    const user = userEvent.setup()
    renderResults(makeResult([makeFinding()]))

    expect(screen.getByRole('region', { name: 'Scan metadata' })).toHaveTextContent('1.3 s')
    expect(
      within(screen.getByRole('region', { name: 'Confirmed sensitive' })).getByText('US SSN'),
    ).toBeInTheDocument()
    expect(screen.getByRole('region', { name: 'Scan metadata' })).toHaveTextContent(
      'Configured detectors12',
    )
    expect(screen.getByText('C:\\project')).not.toBeVisible()
    await user.click(screen.getByText('Show full scan location'))
    expect(screen.getByText('C:\\project')).toBeVisible()
  })

  it('renders hundreds of results in bounded increments', async () => {
    const user = userEvent.setup()
    const findings = Array.from({ length: 300 }, (_, index) =>
      makeFinding({ id: `f${String(index).padStart(3, '0')}`, redacted_preview: `value-${index}` }),
    )
    renderResults(makeResult(findings))

    expect(screen.getByText('Showing 50 of 300 matching findings.')).toBeInTheDocument()
    expect(screen.getAllByRole('checkbox')).toHaveLength(50)
    await user.click(screen.getByRole('button', { name: 'Show up to 50 more' }))
    expect(screen.getByText('Showing 100 of 300 matching findings.')).toBeInTheDocument()
    expect(screen.getAllByRole('checkbox')).toHaveLength(100)
    expect(screen.getByText('value-50').closest('li')).toHaveFocus()
  })

  it('focuses the first newly revealed finding when the final Show more control disappears', async () => {
    const user = userEvent.setup()
    const findings = Array.from({ length: 51 }, (_, index) =>
      makeFinding({
        id: `f${String(index).padStart(3, '0')}`,
        redacted_preview: `last-batch-${index}`,
      }),
    )
    renderResults(makeResult(findings))

    await user.click(screen.getByRole('button', { name: 'Show up to 1 more' }))

    expect(screen.queryByRole('button', { name: /Show up to .* more/ })).not.toBeInTheDocument()
    expect(screen.getByText('last-batch-50').closest('li')).toHaveFocus()
  })

  it('shows the education content only once a finding is expanded', async () => {
    const user = userEvent.setup()
    renderResults(makeResult([makeFinding()]))

    // The <details> element hides non-summary content when closed; jsdom
    // doesn't apply that via CSS, but jest-dom's toBeVisible() special-cases
    // <details> so this still reflects real browser behavior.
    expect(screen.getByText(/identity theft/i)).not.toBeVisible()
    const expandIndicator = screen.getByText('Details')
    expect(expandIndicator).toBeVisible()
    expect(expandIndicator.closest('details')).not.toHaveAttribute('open')

    await user.click(expandIndicator)

    expect(expandIndicator.closest('details')).toHaveAttribute('open')
    expect(screen.getByText(/identity theft/i)).toBeVisible()
    expect(screen.queryByText(/95%|confidence/i)).not.toBeInTheDocument()
  })

  it('shows human-readable supporting evidence without another finding card', async () => {
    const user = userEvent.setup()
    renderResults(
      makeResult([
        makeFinding({
          detector_id: 'aws_access_key',
          explanation: 'AWS access key ID',
          supporting_detections: [
            {
              detector_id: 'high_entropy_secret',
              description: 'High-entropy token',
              confidence: 0.8,
              relationship: 'suppressed',
            },
          ],
        }),
      ]),
    )

    expect(screen.getByText('Confirmed').previousElementSibling).toHaveTextContent('1')
    await user.click(screen.getByText('12*******89'))
    const evidence = screen.getByText(/Supporting evidence:/i).closest('p')
    expect(evidence).toBeVisible()
    expect(evidence).toHaveTextContent('High-entropy token (covered by this finding).')
    expect(evidence).not.toHaveTextContent(/80%|confidence/i)
    expect(evidence).not.toHaveTextContent('high_entropy_secret')
  })

  it('including a finding updates the server-owned plan without writing', async () => {
    const user = userEvent.setup()
    renderResults(makeResult([makeFinding()]))

    await user.click(screen.getByRole('button', { name: /Include finding .* in redaction plan/i }))

    expect(await screen.findByText('Included')).toBeInTheDocument()
    expect(client.putRemediationPlan).toHaveBeenCalledWith('scan-1', ['f1'], [], 0)
    expect(client.postGenerateRemediation).not.toHaveBeenCalled()
  })

  it('moves focus to the stable finding card after every state action replaces its button', async () => {
    const user = userEvent.setup()
    renderResults(makeResult([makeFinding()]))

    await user.click(screen.getByRole('button', { name: INCLUDE_ACTION_NAME }))
    const includedStatus = await screen.findByText('Included')
    const findingCard = includedStatus.closest('li') as HTMLLIElement
    expect(findingCard).toHaveFocus()

    await user.click(screen.getByRole('button', { name: EXCLUDE_ACTION_NAME }))
    expect(await screen.findByRole('button', { name: INCLUDE_ACTION_NAME })).toBeInTheDocument()
    expect(findingCard).toHaveFocus()

    const cardFocus = vi.spyOn(findingCard, 'focus')
    await user.click(screen.getByRole('button', { name: IGNORE_ACTION_NAME }))
    expect(await screen.findByText('Ignored')).toBeInTheDocument()
    expect(findingCard).toHaveFocus()
    expect(cardFocus).toHaveBeenCalledTimes(1)
    expect(cardFocus).toHaveBeenCalledWith({ preventScroll: true })
    expect(findingCard.querySelector('.finding__select--placeholder')).toBeInTheDocument()
    expect(within(findingCard).queryByRole('checkbox')).not.toBeInTheDocument()
    cardFocus.mockRestore()

    await user.click(screen.getByRole('button', { name: RETURN_ACTION_NAME }))
    expect(await screen.findByRole('button', { name: INCLUDE_ACTION_NAME })).toBeInTheDocument()
    expect(findingCard).toHaveFocus()
  })

  it('does not visually disable unrelated results while one finding update is pending', async () => {
    const pendingUpdate = deferred<RemediationPlan>()
    vi.mocked(client.putRemediationPlan).mockReturnValueOnce(pendingUpdate.promise)
    const user = userEvent.setup()
    renderResults(
      makeResult([
        makeFinding({ id: 'f1', redacted_preview: 'first-preview' }),
        makeFinding({ id: 'f2', redacted_preview: 'second-preview' }),
      ]),
    )

    await user.click(screen.getByRole('button', { name: /Ignore finding first-preview/i }))

    expect(screen.getByRole('button', { name: /Ignore finding first-preview/i })).toBeDisabled()
    expect(screen.getByRole('button', { name: /Ignore finding second-preview/i })).toBeEnabled()
    expect(
      screen.getByRole('button', { name: 'Select all visible actionable findings (2)' }),
    ).toBeEnabled()
    expect(screen.getByRole('button', { name: 'Export JSON' })).toHaveClass(
      'btn-export--quiet-disabled',
    )
    expect(screen.getByRole('button', { name: 'Export JSON' })).toBeDisabled()

    pendingUpdate.resolve(makePlan([], ['f1'], 2))
    expect(await screen.findByText('Ignored')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Export JSON' })).not.toHaveClass(
      'btn-export--quiet-disabled',
    )
  })

  it('focuses the next visible card when pending-filter actions remove the acted card', async () => {
    const user = userEvent.setup()
    renderResults(
      makeResult([
        makeFinding({ id: 'f1', redacted_preview: 'pending-one' }),
        makeFinding({ id: 'f2', redacted_preview: 'pending-two' }),
        makeFinding({ id: 'f3', redacted_preview: 'pending-three' }),
      ]),
    )
    await user.selectOptions(screen.getByLabelText('Remediation status'), 'pending')

    await user.click(screen.getByRole('button', { name: /Include finding pending-one/i }))
    await waitFor(() => expect(screen.queryByText('pending-one')).not.toBeInTheDocument())
    expect(screen.getByText('pending-two').closest('li')).toHaveFocus()

    await user.click(screen.getByRole('button', { name: /Ignore finding pending-two/i }))
    await waitFor(() => expect(screen.queryByText('pending-two')).not.toBeInTheDocument())
    expect(screen.getByText('pending-three').closest('li')).toHaveFocus()
  })

  it('focuses the next included card when Exclude removes a card under the included filter', async () => {
    const user = userEvent.setup()
    renderResults(
      makeResult([
        makeFinding({ id: 'f1', redacted_preview: 'included-one' }),
        makeFinding({ id: 'f2', redacted_preview: 'included-two' }),
      ]),
    )
    await user.click(screen.getByRole('button', { name: /Include finding included-one/i }))
    await user.click(screen.getByRole('button', { name: /Include finding included-two/i }))
    await user.selectOptions(screen.getByLabelText('Remediation status'), 'included')

    await user.click(screen.getByRole('button', { name: /Exclude finding included-one/i }))

    await waitFor(() => expect(screen.queryByText('included-one')).not.toBeInTheDocument())
    expect(screen.getByText('included-two').closest('li')).toHaveFocus()
  })

  it('gives every repeated finding action file and redacted-value context', () => {
    renderResults(makeResult([makeFinding()]))

    expect(screen.getByRole('button', { name: OPEN_ACTION_NAME })).toHaveAccessibleName(
      'Show secrets.py in folder for 12*******89',
    )
    expect(screen.getByRole('button', { name: INCLUDE_ACTION_NAME })).toHaveAccessibleName(
      'Include finding 12*******89 from secrets.py in redaction plan',
    )
    expect(screen.getByRole('button', { name: IGNORE_ACTION_NAME })).toHaveAccessibleName(
      'Ignore finding 12*******89 from secrets.py',
    )
  })

  it('hands an expired session back to the setup workflow', async () => {
    const onSessionExpired = vi.fn()
    vi.mocked(client.putRemediationPlan).mockRejectedValue(
      Object.assign(new Error('This scan has expired.'), { code: 'scan_expired' }),
    )
    const user = userEvent.setup()
    renderResults(makeResult([makeFinding()]), { onSessionExpired })

    await user.click(screen.getByRole('button', { name: INCLUDE_ACTION_NAME }))

    expect(onSessionExpired).toHaveBeenCalledTimes(1)
  })

  it('ignoring a finding is distinct from excluding it from the plan', async () => {
    const user = userEvent.setup()
    renderResults(makeResult([makeFinding()]))

    await user.click(screen.getByRole('button', { name: IGNORE_ACTION_NAME }))

    expect(await screen.findByText('Ignored')).toBeInTheDocument()
    expect(client.putRemediationPlan).toHaveBeenCalledWith('scan-1', [], ['f1'], 0)
    expect(client.postGenerateRemediation).not.toHaveBeenCalled()
  })

  it('an ignored finding can explicitly return to pending', async () => {
    const user = userEvent.setup()
    renderResults(makeResult([makeFinding()]))

    await user.click(screen.getByRole('button', { name: IGNORE_ACTION_NAME }))
    expect(await screen.findByText('Ignored')).toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: RETURN_ACTION_NAME }))

    expect(screen.queryByText('Ignored')).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: INCLUDE_ACTION_NAME })).toBeInTheDocument()
  })

  it('moves focus to an action error so keyboard users receive it immediately', async () => {
    const user = userEvent.setup()
    vi.mocked(client.putRemediationPlan).mockRejectedValue(new Error('Plan update failed.'))
    renderResults(makeResult([makeFinding()]))

    await user.click(screen.getByRole('button', { name: INCLUDE_ACTION_NAME }))

    expect(await screen.findByRole('alert')).toHaveTextContent('Plan update failed.')
    expect(screen.getByRole('alert')).toHaveFocus()
  })

  it('includes every pending writable Tier A finding with an exact global scope label', async () => {
    const user = userEvent.setup()
    renderResults(
      makeResult([
        makeFinding({ id: 'f1' }),
        makeFinding({ id: 'f2' }),
        makeFinding({ id: 'f3', tier: 'B', confidence: 0.6 }),
      ]),
    )

    await user.click(
      screen.getByRole('button', {
        name: 'Include all pending writable Tier A findings across all results (2)',
      }),
    )

    expect(await screen.findAllByText('Included')).toHaveLength(2)
    expect(client.putRemediationPlan).toHaveBeenCalledTimes(1)
    expect(client.putRemediationPlan).toHaveBeenCalledWith('scan-1', ['f1', 'f2'], [], 0)
    expect(client.postGenerateRemediation).not.toHaveBeenCalled()
    // The Tier B finding is untouched and the bulk button is gone.
    expect(screen.getByRole('button', { name: INCLUDE_ACTION_NAME })).toBeInTheDocument()
    expect(
      screen.queryByRole('button', {
        name: /pending writable Tier A findings across all results/i,
      }),
    ).not.toBeInTheDocument()
    expect(screen.getByRole('region', { name: 'Bulk finding selection' })).toHaveFocus()
  })

  it('includes every pending writable Tier B finding with an exact global scope label', async () => {
    const user = userEvent.setup()
    renderResults(
      makeResult([
        makeFinding({ id: 'f1', tier: 'A' }),
        makeFinding({ id: 'f2', tier: 'B', confidence: 0.6 }),
        makeFinding({
          id: 'doc1',
          tier: 'B',
          confidence: 0.6,
          can_anonymize: false,
          file_path: 'C:\\project\\manual.pdf',
        }),
      ]),
    )

    const tierBBulkButton = screen.getByRole('button', {
      name: 'Include all pending writable Tier B findings across all results (1)',
    })
    expect(tierBBulkButton).toHaveClass('bulk-btn--b')
    await user.click(tierBBulkButton)

    expect(await screen.findByText('Included')).toBeInTheDocument()
    expect(client.putRemediationPlan).toHaveBeenCalledTimes(1)
    expect(client.putRemediationPlan).toHaveBeenCalledWith('scan-1', ['f2'], [], 0)
    expect(
      screen.queryByRole('button', {
        name: /pending writable Tier B findings across all results/i,
      }),
    ).not.toBeInTheDocument()
    expect(
      screen.getByRole('button', {
        name: 'Include all pending writable Tier A findings across all results (1)',
      }),
    ).toBeEnabled()
    expect(screen.getByRole('region', { name: 'Bulk finding selection' })).toHaveFocus()
  })

  it('states that a filtered bulk shortcut includes hidden and not-yet-rendered Tier A findings', async () => {
    const findings = Array.from({ length: 60 }, (_, index) =>
      makeFinding({
        id: `bulk-${index}`,
        category: index === 59 ? 'credential' : 'personal_id',
        redacted_preview: `bulk-value-${index}`,
      }),
    )
    const user = userEvent.setup()
    renderResults(makeResult(findings))

    expect(screen.getByText('Showing 50 of 60 matching findings.')).toBeInTheDocument()
    await user.selectOptions(screen.getByLabelText('Category'), 'credential')
    expect(screen.getByText('Showing 1 of 1 matching findings.')).toBeInTheDocument()

    await user.click(
      screen.getByRole('button', {
        name: 'Include all pending writable Tier A findings across all results (60)',
      }),
    )

    expect(client.putRemediationPlan).toHaveBeenCalledTimes(1)
    expect(client.putRemediationPlan).toHaveBeenCalledWith(
      'scan-1',
      findings.map((finding) => finding.id),
      [],
      0,
    )
  })

  it('reviews proposed paths before one explicit verified generation', async () => {
    const generatedPlan = makePlan(['f1'])
    generatedPlan.files[0].output_state = 'current'
    vi.mocked(client.postGenerateRemediation).mockResolvedValue({
      plan: generatedPlan,
      outputs: [
        {
          source_path: 'C:\\project\\secrets.py',
          output_path: 'C:\\project\\secrets-auto-redacted-copy.py',
          applied_finding_ids: ['f1'],
          verification_status: 'verified',
          warnings: ['Review before sharing.'],
          source_fingerprint: {
            resolved_path: 'C:\\project\\secrets.py',
            size: 42,
            modified_ns: 123,
            sha256: 'a'.repeat(64),
          },
          rescan_status: 'completed',
          remaining_finding_count: 0,
          remaining_tier_a_count: 0,
        },
      ],
    })
    const user = userEvent.setup()
    renderResults(makeResult([makeFinding()]))

    await user.click(screen.getByRole('button', { name: INCLUDE_ACTION_NAME }))
    await user.click(await screen.findByRole('button', { name: 'Review remediation' }))

    const dialog = screen.getByRole('dialog')
    expect(dialog).toHaveFocus()
    expect(screen.getByText('C:\\project\\secrets-auto-redacted-copy.py')).toBeInTheDocument()
    expect(client.postGenerateRemediation).not.toHaveBeenCalled()
    await user.click(screen.getByRole('button', { name: 'Create redacted copies' }))

    expect(client.postGenerateRemediation).toHaveBeenCalledWith('scan-1', 1, 'copy')
    const completionStatus = await within(dialog).findByRole('status')
    expect(completionStatus).toHaveTextContent('Created and verified 1 redacted copy.')
    expect(completionStatus).not.toHaveClass('visually-hidden')
    expect(await screen.findByText(/selected values were removed/i)).toBeInTheDocument()
    expect(screen.getByText(/Output rescan completed/i).closest('p')).toHaveTextContent(
      '0 remaining',
    )
    expect(screen.getByText('Review before sharing.')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: OPEN_OUTPUT_ACTION_NAME })).toBeInTheDocument()
  })

  it('requires explicit confirmation before replacing original files', async () => {
    const generatedPlan = makePlan(['f1'])
    generatedPlan.files[0] = {
      ...generatedPlan.files[0],
      output_path: generatedPlan.files[0].source_path,
      output_state: 'current',
    }
    generatedPlan.can_generate = false
    vi.mocked(client.postGenerateRemediation).mockResolvedValue({
      plan: generatedPlan,
      outputs: [
        {
          ...generatedOutput(),
          output_path: 'C:\\project\\secrets.py',
          warnings: [
            'The original file was replaced. Run a new scan before making additional changes.',
          ],
        },
      ],
    })
    const user = userEvent.setup()
    renderResults(makeResult([makeFinding()]))

    await user.click(screen.getByRole('button', { name: INCLUDE_ACTION_NAME }))
    await user.click(await screen.findByRole('button', { name: 'Review remediation' }))

    expect(screen.getByRole('radio', { name: /Create redacted copies/i })).toBeChecked()
    await user.click(screen.getByRole('radio', { name: /Replace original files/i }))

    const replaceButton = screen.getByRole('button', { name: 'Replace 1 original file' })
    expect(replaceButton).toBeDisabled()
    expect(screen.getAllByText('C:\\project\\secrets.py')).not.toHaveLength(0)
    expect(screen.getByText(/This cannot be undone/i)).toBeInTheDocument()

    await user.click(
      screen.getByRole('checkbox', {
        name: /I understand that the original files will be permanently replaced/i,
      }),
    )
    expect(replaceButton).toBeEnabled()
    await user.click(replaceButton)

    expect(client.postGenerateRemediation).toHaveBeenCalledWith('scan-1', 1, 'replace_original')
    expect(await screen.findByText(/Replaced and verified 1 original file\./i)).toBeInTheDocument()
    expect(screen.getByText(/Verified replacement/i)).toBeInTheDocument()
    expect(
      screen.getAllByText(/Run a new scan before making additional changes/i),
    ).not.toHaveLength(0)
  })

  it('batches a 300-file remediation review and focuses each newly revealed section', async () => {
    const findings = Array.from({ length: 300 }, (_, index) => {
      const suffix = String(index).padStart(3, '0')
      return makeFinding({
        id: `review-${suffix}`,
        file_path: `C:\\project\\review\\file-${suffix}.txt`,
        redacted_preview: `review-value-${suffix}`,
      })
    })
    const planFiles = findings.map((finding) => ({
      source_path: finding.file_path,
      output_path: finding.file_path.replace(/(\.[^./\\]+)$/, '-auto-redacted-copy$1'),
      included_finding_ids: [finding.id],
      output_state: 'not_created' as const,
    }))
    const largePlan: RemediationPlan = {
      plan_revision: 1,
      findings: findings.map((finding) => ({
        finding_id: finding.id,
        state: 'included' as const,
      })),
      files: planFiles,
      selected_finding_count: findings.length,
      affected_file_count: findings.length,
      read_only_finding_count: 0,
      retained_artifact_paths: [],
      can_review: true,
      can_generate: true,
    }
    const generatedPlan: RemediationPlan = {
      ...largePlan,
      files: planFiles.map((file) => ({ ...file, output_state: 'current' as const })),
    }
    const generatedOutputs = findings.map((finding) => ({
      ...generatedOutput([finding.id]),
      source_path: finding.file_path,
      output_path: finding.file_path.replace(/(\.[^./\\]+)$/, '-auto-redacted-copy$1'),
      source_fingerprint: {
        ...generatedOutput([finding.id]).source_fingerprint,
        resolved_path: finding.file_path,
      },
      warnings: [],
    }))
    vi.mocked(client.putRemediationPlan).mockResolvedValueOnce(largePlan)
    vi.mocked(client.postGenerateRemediation).mockResolvedValueOnce({
      plan: generatedPlan,
      outputs: generatedOutputs,
    })
    const user = userEvent.setup()
    renderResults(makeResult(findings))

    await user.click(
      screen.getByRole('button', {
        name: 'Include all pending writable Tier A findings across all results (300)',
      }),
    )
    const reviewButton = screen.getByRole('button', { name: 'Review remediation' })
    await waitFor(() => expect(reviewButton).toBeEnabled())
    await user.click(reviewButton)

    const dialog = screen.getByRole('dialog')
    expect(within(dialog).getByText('Showing 50 of 300 proposed files.')).toBeInTheDocument()
    expect(dialog.querySelectorAll('[data-review-file]')).toHaveLength(50)
    await user.click(
      within(dialog).getByRole('button', { name: 'Show up to 50 more proposed files' }),
    )
    const expandedFileRows = dialog.querySelectorAll<HTMLElement>('[data-review-file]')
    expect(expandedFileRows).toHaveLength(100)
    expect(expandedFileRows[50]).toHaveFocus()

    await user.click(within(dialog).getByRole('button', { name: 'Create redacted copies' }))
    expect(
      await within(dialog).findByText('Showing 50 of 300 output evidence records.'),
    ).toBeInTheDocument()
    expect(dialog.querySelectorAll('[data-review-output]')).toHaveLength(50)
    await user.click(
      within(dialog).getByRole('button', {
        name: 'Show up to 50 more output evidence records',
      }),
    )
    const expandedOutputRows = dialog.querySelectorAll<HTMLElement>('[data-review-output]')
    expect(expandedOutputRows).toHaveLength(100)
    expect(expandedOutputRows[50]).toHaveFocus()
  })

  it('shows failed output rescans and their warnings without reporting zero remaining findings', async () => {
    const generatedPlan = makePlan(['f1'])
    generatedPlan.files[0].output_state = 'current'
    vi.mocked(client.postGenerateRemediation).mockResolvedValue({
      plan: generatedPlan,
      outputs: [
        {
          source_path: 'C:\\project\\secrets.py',
          output_path: 'C:\\project\\secrets-auto-redacted-copy.py',
          applied_finding_ids: ['f1'],
          verification_status: 'verified',
          warnings: ['The optional output rescan could not finish; review manually.'],
          source_fingerprint: {
            resolved_path: 'C:\\project\\secrets.py',
            size: 42,
            modified_ns: 123,
            sha256: 'b'.repeat(64),
          },
          rescan_status: 'failed',
          remaining_finding_count: null,
          remaining_tier_a_count: null,
        },
      ],
    })
    const user = userEvent.setup()
    renderResults(makeResult([makeFinding()]))

    await user.click(screen.getByRole('button', { name: INCLUDE_ACTION_NAME }))
    await user.click(await screen.findByRole('button', { name: 'Review remediation' }))
    await user.click(screen.getByRole('button', { name: 'Create redacted copies' }))

    expect((await screen.findByText(/Output rescan failed/i)).closest('p')).toHaveTextContent(
      /counts are unavailable/i,
    )
    expect(
      screen.getByText('The optional output rescan could not finish; review manually.'),
    ).toBeInTheDocument()
    expect(screen.queryByText(/0 remaining finding/i)).not.toBeInTheDocument()
  })

  it('disables review and generation while a plan mutation is pending', async () => {
    const user = userEvent.setup()
    const pendingUpdate = deferred<RemediationPlan>()
    renderResults(
      makeResult([
        makeFinding({ id: 'f1' }),
        makeFinding({ id: 'f2', redacted_preview: 'se*******wo' }),
      ]),
    )

    await user.click(screen.getAllByRole('button', { name: INCLUDE_ACTION_NAME })[0])
    const review = await screen.findByRole('button', { name: 'Review remediation' })
    await user.click(review)
    vi.mocked(client.putRemediationPlan).mockReturnValueOnce(pendingUpdate.promise)

    await user.click(screen.getByRole('button', { name: INCLUDE_ACTION_NAME }))

    expect(review).toBeDisabled()
    expect(screen.getByRole('button', { name: 'Create redacted copies' })).toBeDisabled()
    expect(screen.getByRole('button', { name: 'Export JSON' })).toBeDisabled()
    expect(screen.getByRole('button', { name: 'Export readable report' })).toBeDisabled()

    pendingUpdate.resolve(makePlan(['f1', 'f2'], [], 2))
    await waitFor(() => expect(screen.getAllByText('Included')).toHaveLength(2))
    expect(screen.getByRole('button', { name: 'Create redacted copies' })).toBeEnabled()
    expect(screen.getByRole('button', { name: 'Export JSON' })).toBeEnabled()
  })

  it('blocks plan mutations while a review freshness request is pending', async () => {
    const includedPlan = makePlan(['f1'], [], 1)
    const pendingRefresh = deferred<RemediationPlan>()
    vi.mocked(client.putRemediationPlan).mockResolvedValueOnce(includedPlan)
    const user = userEvent.setup()
    renderResults(makeResult([makeFinding()]))

    await user.click(screen.getByRole('button', { name: INCLUDE_ACTION_NAME }))
    vi.mocked(client.getRemediationPlan).mockReturnValueOnce(pendingRefresh.promise)
    await user.click(await screen.findByRole('button', { name: 'Review remediation' }))

    const exclude = screen.getByRole('button', { name: EXCLUDE_ACTION_NAME })
    expect(exclude).toBeDisabled()
    expect(screen.getByRole('checkbox', { name: /Select finding/i })).toBeDisabled()
    await user.click(exclude)
    expect(client.putRemediationPlan).toHaveBeenCalledTimes(1)

    pendingRefresh.resolve(includedPlan)
    expect(await screen.findByRole('dialog')).toBeInTheDocument()
    expect(client.putRemediationPlan).toHaveBeenCalledTimes(1)
  })

  it('blocks plan mutations while an export freshness request is pending', async () => {
    const pendingRefresh = deferred<RemediationPlan>()
    vi.mocked(client.getRemediationPlan).mockReturnValueOnce(pendingRefresh.promise)
    const urls = installObjectUrlHarness()
    const user = userEvent.setup()

    try {
      renderResults(makeResult([makeFinding()]))
      await user.click(screen.getByRole('button', { name: 'Export JSON' }))

      const include = screen.getByRole('button', { name: INCLUDE_ACTION_NAME })
      expect(include).toBeDisabled()
      expect(screen.getByRole('button', { name: IGNORE_ACTION_NAME })).toBeDisabled()
      expect(screen.getByRole('checkbox', { name: /Select finding/i })).toBeDisabled()
      await user.click(include)
      expect(client.putRemediationPlan).not.toHaveBeenCalled()

      pendingRefresh.resolve(makePlan())
      await waitFor(() => expect(include).toBeEnabled())
      expect(urls.createObjectURL).toHaveBeenCalledTimes(1)
      await user.click(include)
      expect(client.putRemediationPlan).toHaveBeenCalledTimes(1)
    } finally {
      urls.restore()
    }
  })

  it('disables report exports until generation settles with authoritative output evidence', async () => {
    const user = userEvent.setup()
    const pendingGeneration = deferred<{
      plan: RemediationPlan
      outputs: GeneratedOutputDetails[]
    }>()
    const generatedPlan = currentPlan(['f1'], 1)
    vi.mocked(client.postGenerateRemediation).mockReturnValueOnce(pendingGeneration.promise)
    renderResults(makeResult([makeFinding()]))

    await user.click(screen.getByRole('button', { name: INCLUDE_ACTION_NAME }))
    await user.click(await screen.findByRole('button', { name: 'Review remediation' }))
    await user.click(screen.getByRole('button', { name: 'Create redacted copies' }))

    expect(screen.getByRole('button', { name: 'Export JSON' })).toBeDisabled()
    expect(screen.getByRole('button', { name: 'Export readable report' })).toBeDisabled()

    pendingGeneration.resolve({ plan: generatedPlan, outputs: [generatedOutput()] })
    await waitFor(() => expect(screen.getByRole('button', { name: 'Export JSON' })).toBeEnabled())
  })

  it('reloads the latest plan after a revision conflict', async () => {
    const user = userEvent.setup()
    const latest = makePlan(['f1'], [], 4)
    vi.mocked(client.putRemediationPlan).mockRejectedValueOnce({
      code: 'invalid_remediation_plan',
      message: 'The remediation plan changed.',
    })
    vi.mocked(client.getRemediationPlan).mockResolvedValueOnce(latest)
    renderResults(makeResult([makeFinding()]))

    await user.click(screen.getByRole('button', { name: INCLUDE_ACTION_NAME }))

    await waitFor(() => expect(client.getRemediationPlan).toHaveBeenCalledWith('scan-1'))
    expect(await screen.findByRole('alert')).toHaveTextContent(/review the latest selections/i)
    expect(screen.getByText('Included')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Review remediation' })).toBeEnabled()
  })

  it('keeps evidence only for outputs the updated plan still marks current', async () => {
    const initialIncluded = makePlan(['f1'], [], 1)
    const generatedPlan = {
      ...initialIncluded,
      files: initialIncluded.files.map((file) => ({ ...file, output_state: 'current' as const })),
    }
    const currentAfterIgnore = {
      ...makePlan(['f1'], ['f2'], 2),
      files: generatedPlan.files,
    }
    const staleAfterExclude = {
      ...makePlan([], ['f2'], 3),
      files: generatedPlan.files.map((file) => ({
        ...file,
        included_finding_ids: [],
        output_state: 'regeneration_required' as const,
      })),
    }
    vi.mocked(client.putRemediationPlan)
      .mockResolvedValueOnce(initialIncluded)
      .mockResolvedValueOnce(currentAfterIgnore)
      .mockResolvedValueOnce(staleAfterExclude)
    vi.mocked(client.postGenerateRemediation).mockResolvedValue({
      plan: generatedPlan,
      outputs: [
        {
          source_path: 'C:\\project\\secrets.py',
          output_path: 'C:\\project\\secrets-auto-redacted-copy.py',
          applied_finding_ids: ['f1'],
          verification_status: 'verified',
          warnings: ['Evidence retained while this output is current.'],
          source_fingerprint: {
            resolved_path: 'C:\\project\\secrets.py',
            size: 42,
            modified_ns: 123,
            sha256: 'c'.repeat(64),
          },
          rescan_status: 'completed',
          remaining_finding_count: 0,
          remaining_tier_a_count: 0,
        },
      ],
    })
    const user = userEvent.setup()
    renderResults(
      makeResult([
        makeFinding({ id: 'f1' }),
        makeFinding({ id: 'f2', redacted_preview: 'se*******wo' }),
      ]),
    )

    await user.click(screen.getAllByRole('button', { name: INCLUDE_ACTION_NAME })[0])
    await user.click(await screen.findByRole('button', { name: 'Review remediation' }))
    await user.click(screen.getByRole('button', { name: 'Create redacted copies' }))
    expect(
      await screen.findByText('Evidence retained while this output is current.'),
    ).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Close review' }))

    await user.click(screen.getByRole('button', { name: IGNORE_ACTION_NAME }))
    await user.click(await screen.findByRole('button', { name: 'Review remediation' }))
    expect(screen.getByText('Evidence retained while this output is current.')).toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: EXCLUDE_ACTION_NAME }))
    expect(
      screen.queryByText('Evidence retained while this output is current.'),
    ).not.toBeInTheDocument()
  })

  it('drops same-path evidence when conflict recovery changes the applied finding IDs', async () => {
    const includedPlan = makePlan(['f1'], [], 1)
    const generatedPlan = currentPlan(['f1'], 1)
    const latestPlan = currentPlan(['f2'], 5)
    vi.mocked(client.putRemediationPlan).mockResolvedValueOnce(includedPlan).mockRejectedValueOnce({
      code: 'invalid_remediation_plan',
      message: 'The remediation plan changed.',
    })
    vi.mocked(client.postGenerateRemediation).mockResolvedValue({
      plan: generatedPlan,
      outputs: [generatedOutput(['f1'])],
    })
    vi.mocked(client.getRemediationPlan)
      .mockResolvedValueOnce(includedPlan)
      .mockResolvedValueOnce(latestPlan)
      .mockResolvedValueOnce(latestPlan)
    const user = userEvent.setup()
    renderResults(
      makeResult([
        makeFinding({ id: 'f1' }),
        makeFinding({ id: 'f2', redacted_preview: 'se*******wo' }),
      ]),
    )

    await user.click(screen.getAllByRole('button', { name: INCLUDE_ACTION_NAME })[0])
    await user.click(await screen.findByRole('button', { name: 'Review remediation' }))
    await user.click(screen.getByRole('button', { name: 'Create redacted copies' }))
    expect(
      await screen.findByText('Evidence retained while this output is current.'),
    ).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Close review' }))
    await user.click(screen.getByRole('button', { name: INCLUDE_ACTION_NAME }))

    const error = await screen.findByText(/review the latest selections/i)
    expect(error).toHaveFocus()
    await user.click(screen.getByRole('button', { name: 'Review remediation' }))
    expect(await screen.findByText(/verified copy is current/i)).toBeInTheDocument()
    expect(
      screen.queryByText('Evidence retained while this output is current.'),
    ).not.toBeInTheDocument()
  })

  it('refreshes a conflicting open, keeps its alert in review, and removes untrusted evidence', async () => {
    const includedPlan = makePlan(['f1'], [], 1)
    const generatedPlan = currentPlan(['f1'], 1)
    const conflictPlan: RemediationPlan = {
      ...makePlan(['f1'], [], 2),
      files: generatedPlan.files.map((file) => ({ ...file, output_state: 'conflict' })),
      can_review: true,
      can_generate: false,
    }
    vi.mocked(client.putRemediationPlan).mockResolvedValueOnce(includedPlan)
    vi.mocked(client.postGenerateRemediation).mockResolvedValueOnce({
      plan: generatedPlan,
      outputs: [generatedOutput()],
    })
    vi.mocked(client.postOpenOutput).mockRejectedValueOnce({
      code: 'output_conflict',
      message: 'The redacted copy changed outside RedactLens and will not be shown in its folder.',
    })
    const pendingRefresh = deferred<RemediationPlan>()
    vi.mocked(client.getRemediationPlan)
      .mockResolvedValueOnce(includedPlan)
      .mockReturnValueOnce(pendingRefresh.promise)
      .mockResolvedValueOnce(conflictPlan)
    const user = userEvent.setup()
    renderResults(makeResult([makeFinding()]))

    await user.click(screen.getByRole('button', { name: INCLUDE_ACTION_NAME }))
    await user.click(await screen.findByRole('button', { name: 'Review remediation' }))
    await user.click(screen.getByRole('button', { name: 'Create redacted copies' }))
    const dialog = screen.getByRole('dialog')
    await user.click(await within(dialog).findByRole('button', { name: OPEN_OUTPUT_ACTION_NAME }))

    await waitFor(() => expect(client.getRemediationPlan).toHaveBeenCalledWith('scan-1'))
    const initialAlert = await within(dialog).findByText(/will not be shown in its folder/i)
    expect(initialAlert).toHaveTextContent(/will not be shown in its folder/i)
    expect(initialAlert).toHaveAttribute('aria-live', 'assertive')
    expect(screen.getByRole('button', { name: 'Export JSON' })).toBeDisabled()
    expect(screen.getByRole('button', { name: 'Export readable report' })).toBeDisabled()
    pendingRefresh.resolve(conflictPlan)
    const error = await within(dialog).findByText(/remediation plan was refreshed/i)
    expect(error).toHaveTextContent(/will not be shown in its folder/i)
    expect(error).toHaveAttribute('role', 'alert')
    expect(screen.getByRole('dialog')).toBe(dialog)
    expect(
      await within(dialog).findByText(/conflict; changed or untrusted output/i),
    ).toBeInTheDocument()
    expect(
      within(dialog).queryByText('Evidence retained while this output is current.'),
    ).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Export JSON' })).toBeEnabled()
  })

  it('fails closed when conflict recovery cannot reload the latest plan', async () => {
    const includedPlan = makePlan(['f1'], [], 1)
    const generatedPlan = currentPlan(['f1'], 1)
    const conflictPlan: RemediationPlan = {
      ...includedPlan,
      files: generatedPlan.files.map((file) => ({ ...file, output_state: 'conflict' })),
      can_generate: false,
    }
    vi.mocked(client.putRemediationPlan).mockResolvedValueOnce(includedPlan)
    vi.mocked(client.postGenerateRemediation).mockResolvedValueOnce({
      plan: generatedPlan,
      outputs: [generatedOutput()],
    })
    vi.mocked(client.postOpenOutput).mockRejectedValueOnce({
      code: 'output_conflict',
      message: 'The redacted copy changed outside RedactLens.',
    })
    vi.mocked(client.getRemediationPlan)
      .mockResolvedValueOnce(includedPlan)
      .mockRejectedValueOnce(new Error('refresh failed'))
      .mockResolvedValueOnce(conflictPlan)
    const user = userEvent.setup()
    renderResults(makeResult([makeFinding()]))

    await user.click(screen.getByRole('button', { name: INCLUDE_ACTION_NAME }))
    await user.click(await screen.findByRole('button', { name: 'Review remediation' }))
    await user.click(screen.getByRole('button', { name: 'Create redacted copies' }))
    expect(
      await screen.findByText('Evidence retained while this output is current.'),
    ).toBeInTheDocument()
    const dialog = screen.getByRole('dialog')
    await user.click(within(dialog).getByRole('button', { name: OPEN_OUTPUT_ACTION_NAME }))

    const error = await within(dialog).findByText(/latest remediation plan could not be loaded/i)
    expect(error).toHaveAttribute('role', 'alert')
    expect(error).toHaveAttribute('aria-live', 'assertive')
    expect(screen.getByRole('dialog')).toBe(dialog)
    expect(
      within(dialog).queryByText('Evidence retained while this output is current.'),
    ).not.toBeInTheDocument()
    expect(
      await within(dialog).findByText(/conflict; changed or untrusted output/i),
    ).toBeInTheDocument()
    expect(within(dialog).getByRole('button', { name: 'Create redacted copies' })).toBeDisabled()
  })

  it('refreshes after generation becomes unavailable and focuses the visible error', async () => {
    const includedPlan = makePlan(['f1'], [], 1)
    const latestPlan = makePlan(['f1'], [], 2)
    vi.mocked(client.putRemediationPlan).mockResolvedValueOnce(includedPlan)
    vi.mocked(client.postGenerateRemediation).mockRejectedValueOnce({
      code: 'file_unavailable',
      message: 'The proposed output is no longer available.',
    })
    vi.mocked(client.getRemediationPlan)
      .mockResolvedValueOnce(includedPlan)
      .mockResolvedValueOnce(latestPlan)
    const user = userEvent.setup()
    renderResults(makeResult([makeFinding()]))

    await user.click(screen.getByRole('button', { name: INCLUDE_ACTION_NAME }))
    await user.click(await screen.findByRole('button', { name: 'Review remediation' }))
    await user.click(screen.getByRole('button', { name: 'Create redacted copies' }))

    await waitFor(() => expect(client.getRemediationPlan).toHaveBeenCalledWith('scan-1'))
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
    const error = screen.getByText(/remediation plan was refreshed/i)
    expect(error).toHaveTextContent(/no longer available/i)
    expect(error).toHaveFocus()
  })

  it('preserves a recovery artifact path when capacity eviction expires reconciliation', async () => {
    const retainedPath = 'C:\\project\\.secrets.py.abc.tmp'
    const onSessionExpired = vi.fn()
    vi.mocked(client.putRemediationPlan).mockResolvedValueOnce(makePlan(['f1'], [], 1))
    vi.mocked(client.postGenerateRemediation).mockRejectedValueOnce({
      code: 'file_unavailable',
      message: `Recovery artifact was preserved at: ${retainedPath}.`,
    })
    vi.mocked(client.getRemediationPlan)
      .mockResolvedValueOnce(makePlan(['f1'], [], 1))
      .mockRejectedValueOnce({
        code: 'scan_expired',
        message: 'This scan has expired.',
      })
    const user = userEvent.setup()
    renderResults(makeResult([makeFinding()]), { onSessionExpired })

    await user.click(screen.getByRole('button', { name: INCLUDE_ACTION_NAME }))
    await user.click(await screen.findByRole('button', { name: 'Review remediation' }))
    await user.click(screen.getByRole('button', { name: 'Create redacted copies' }))

    await waitFor(() =>
      expect(onSessionExpired).toHaveBeenCalledWith(expect.stringContaining(retainedPath)),
    )
  })

  it('returns focus to the remediation trigger when review closes', async () => {
    const user = userEvent.setup()
    renderResults(makeResult([makeFinding()]))
    await user.click(screen.getByRole('button', { name: INCLUDE_ACTION_NAME }))
    const trigger = await screen.findByRole('button', { name: 'Review remediation' })
    await user.click(trigger)
    await user.click(screen.getByRole('button', { name: 'Close review' }))

    expect(trigger).toHaveFocus()
  })

  it('traps Tab inside the modal review and closes it with Escape', async () => {
    const user = userEvent.setup()
    renderResults(makeResult([makeFinding()]))
    await user.click(screen.getByRole('button', { name: INCLUDE_ACTION_NAME }))
    const trigger = await screen.findByRole('button', { name: 'Review remediation' })
    await user.click(trigger)
    const dialog = screen.getByRole('dialog')

    expect(dialog).toHaveAttribute('aria-modal', 'true')
    expect(dialog).toHaveFocus()
    await user.tab()
    expect(screen.getByRole('button', { name: 'Close review' })).toHaveFocus()
    await user.tab({ shift: true })
    expect(screen.getByRole('button', { name: 'Create redacted copies' })).toHaveFocus()
    await user.tab()
    expect(screen.getByRole('button', { name: 'Close review' })).toHaveFocus()
    await user.keyboard('{Escape}')

    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
    expect(trigger).toHaveFocus()
  })

  it('marks a copy obsolete after its final selection is removed and keeps review available', async () => {
    const includedPlan = makePlan(['f1'])
    includedPlan.files[0].output_state = 'current'
    vi.mocked(client.putRemediationPlan)
      .mockResolvedValueOnce(includedPlan)
      .mockResolvedValueOnce({
        ...makePlan(),
        files: [
          {
            ...includedPlan.files[0],
            included_finding_ids: [],
            output_state: 'obsolete',
          },
        ],
        can_review: true,
      })
    const user = userEvent.setup()
    renderResults(makeResult([makeFinding()]))

    await user.click(screen.getByRole('button', { name: INCLUDE_ACTION_NAME }))
    await user.click(await screen.findByRole('button', { name: EXCLUDE_ACTION_NAME }))

    expect(screen.getByRole('button', { name: INCLUDE_ACTION_NAME })).toBeInTheDocument()
    expect(screen.getByText(/redacted copy is obsolete/i)).toHaveAttribute('role', 'status')
    const review = screen.getByRole('button', { name: 'Review remediation' })
    expect(review).toBeEnabled()
    await user.click(review)
    expect(screen.getByText(/obsolete; no findings are selected/i)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Create redacted copies' })).toBeDisabled()
    expect(screen.queryByText('Anonymized')).not.toBeInTheDocument()
  })

  it('lists retained recovery artifacts for manual deletion without output evidence', async () => {
    const retainedPath = 'C:\\project\\.redactlens-recovery\\secrets.py.backup'
    vi.mocked(client.putRemediationPlan).mockResolvedValueOnce({
      ...makePlan([], ['f1'], 2),
      retained_artifact_paths: [retainedPath],
      can_review: true,
    })
    const user = userEvent.setup()
    renderResults(makeResult([makeFinding()]))

    await user.click(screen.getByRole('button', { name: IGNORE_ACTION_NAME }))

    const warning = screen.getByText('Manual cleanup required.').closest('[role="alert"]')
    expect(warning).toBeInTheDocument()
    expect(warning).toHaveTextContent(/delete them manually/i)
    expect(screen.getByText(retainedPath)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Review remediation' })).toBeEnabled()
    expect(screen.queryByText(/Verified output:/i)).not.toBeInTheDocument()
  })

  it('the folder action reveals the file and fires a toast naming file and line', async () => {
    const onToast = vi.fn()
    const user = userEvent.setup()
    vi.mocked(client.postOpenFile).mockResolvedValue({ status: 'ok' })
    renderResults(makeResult([makeFinding()]), { onToast })

    await user.click(screen.getByRole('button', { name: OPEN_ACTION_NAME }))

    expect(client.postOpenFile).toHaveBeenCalledWith('scan-1', 'f1')
    expect(onToast).toHaveBeenCalledWith(expect.stringContaining('secrets.py'))
    expect(onToast).toHaveBeenCalledWith(expect.stringContaining('line 3'))
  })

  it('the folder action reports failure instead of pretending it worked', async () => {
    const onToast = vi.fn()
    const user = userEvent.setup()
    vi.mocked(client.postOpenFile).mockRejectedValue(new Error('404'))
    renderResults(makeResult([makeFinding()]), { onToast })

    await user.click(screen.getByRole('button', { name: OPEN_ACTION_NAME }))

    expect(onToast).toHaveBeenCalledWith(expect.stringContaining("Couldn't show"))
  })

  it('announces a successful redacted-output reveal inside the active review dialog', async () => {
    const includedPlan = makePlan(['f1'], [], 1)
    const generatedPlan = currentPlan(['f1'], 1)
    const onToast = vi.fn()
    vi.mocked(client.putRemediationPlan).mockResolvedValueOnce(includedPlan)
    vi.mocked(client.postGenerateRemediation).mockResolvedValueOnce({
      plan: generatedPlan,
      outputs: [generatedOutput()],
    })
    vi.mocked(client.postOpenOutput).mockResolvedValueOnce({ status: 'ok' })
    const user = userEvent.setup()
    renderResults(makeResult([makeFinding()]), { onToast })

    await user.click(screen.getByRole('button', { name: INCLUDE_ACTION_NAME }))
    await user.click(await screen.findByRole('button', { name: 'Review remediation' }))
    await user.click(screen.getByRole('button', { name: 'Create redacted copies' }))
    const dialog = screen.getByRole('dialog')
    await user.click(await within(dialog).findByRole('button', { name: OPEN_OUTPUT_ACTION_NAME }))

    const statusMessage = await within(dialog).findByText(
      'Showed secrets-auto-redacted-copy.py in its folder.',
    )
    expect(statusMessage).toHaveAttribute('role', 'status')
    expect(statusMessage).toHaveAttribute('aria-live', 'polite')
    expect(statusMessage).toHaveClass('generation-status')
    expect(onToast).not.toHaveBeenCalled()
  })

  it('announces a redacted-output reveal failure assertively inside active review', async () => {
    const includedPlan = makePlan(['f1'], [], 1)
    const generatedPlan = currentPlan(['f1'], 1)
    const onToast = vi.fn()
    vi.mocked(client.putRemediationPlan).mockResolvedValueOnce(includedPlan)
    vi.mocked(client.postGenerateRemediation).mockResolvedValueOnce({
      plan: generatedPlan,
      outputs: [generatedOutput()],
    })
    vi.mocked(client.postOpenOutput).mockRejectedValueOnce(
      new Error('Native folder reveal failed.'),
    )
    const user = userEvent.setup()
    renderResults(makeResult([makeFinding()]), { onToast })

    await user.click(screen.getByRole('button', { name: INCLUDE_ACTION_NAME }))
    await user.click(await screen.findByRole('button', { name: 'Review remediation' }))
    await user.click(screen.getByRole('button', { name: 'Create redacted copies' }))
    const dialog = screen.getByRole('dialog')
    expect(within(dialog).getByRole('alert')).toBeEmptyDOMElement()
    await user.click(within(dialog).getByRole('button', { name: OPEN_OUTPUT_ACTION_NAME }))

    const alert = await within(dialog).findByText('Native folder reveal failed.')
    expect(alert).toHaveTextContent('Native folder reveal failed.')
    expect(alert).toHaveAttribute('aria-live', 'assertive')
    expect(alert).toHaveAttribute('aria-atomic', 'true')
    expect(alert).toHaveClass('generation-status', 'generation-status--error')
    expect(screen.getByRole('dialog')).toBe(dialog)
    expect(onToast).not.toHaveBeenCalled()
  })

  it('uses the global notification if review closes while an output reveal is pending', async () => {
    const includedPlan = makePlan(['f1'], [], 1)
    const generatedPlan = currentPlan(['f1'], 1)
    const reveal = deferred<{ status: string }>()
    const onToast = vi.fn()
    vi.mocked(client.putRemediationPlan).mockResolvedValueOnce(includedPlan)
    vi.mocked(client.postGenerateRemediation).mockResolvedValueOnce({
      plan: generatedPlan,
      outputs: [generatedOutput()],
    })
    vi.mocked(client.postOpenOutput).mockReturnValueOnce(reveal.promise)
    const user = userEvent.setup()
    renderResults(makeResult([makeFinding()]), { onToast })

    await user.click(screen.getByRole('button', { name: INCLUDE_ACTION_NAME }))
    await user.click(await screen.findByRole('button', { name: 'Review remediation' }))
    await user.click(screen.getByRole('button', { name: 'Create redacted copies' }))
    const dialog = screen.getByRole('dialog')
    await user.click(within(dialog).getByRole('button', { name: OPEN_OUTPUT_ACTION_NAME }))
    await user.click(within(dialog).getByRole('button', { name: 'Close review' }))
    reveal.resolve({ status: 'ok' })

    await waitFor(() =>
      expect(onToast).toHaveBeenCalledWith('Showed secrets-auto-redacted-copy.py in its folder.'),
    )
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
  })

  it('uses the global alert if review closes while an output reveal failure is pending', async () => {
    const includedPlan = makePlan(['f1'], [], 1)
    const generatedPlan = currentPlan(['f1'], 1)
    const reveal = deferred<{ status: string }>()
    vi.mocked(client.putRemediationPlan).mockResolvedValueOnce(includedPlan)
    vi.mocked(client.postGenerateRemediation).mockResolvedValueOnce({
      plan: generatedPlan,
      outputs: [generatedOutput()],
    })
    vi.mocked(client.postOpenOutput).mockReturnValueOnce(reveal.promise)
    const user = userEvent.setup()
    renderResults(makeResult([makeFinding()]))

    await user.click(screen.getByRole('button', { name: INCLUDE_ACTION_NAME }))
    await user.click(await screen.findByRole('button', { name: 'Review remediation' }))
    await user.click(screen.getByRole('button', { name: 'Create redacted copies' }))
    const dialog = screen.getByRole('dialog')
    await user.click(within(dialog).getByRole('button', { name: OPEN_OUTPUT_ACTION_NAME }))
    await user.click(within(dialog).getByRole('button', { name: 'Close review' }))
    reveal.reject(new Error('Native folder reveal failed.'))

    const alert = await screen.findByRole('alert')
    expect(alert).toHaveTextContent('Native folder reveal failed.')
    await waitFor(() => expect(alert).toHaveFocus())
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
  })

  it('refreshes review after output tampering and blocks a report from the conflict', async () => {
    const includedPlan = makePlan(['f1'], [], 1)
    const generatedPlan = currentPlan(['f1'], 1)
    const conflictPlan: RemediationPlan = {
      ...generatedPlan,
      files: generatedPlan.files.map((file) => ({ ...file, output_state: 'conflict' })),
      can_generate: false,
    }
    vi.mocked(client.putRemediationPlan).mockResolvedValueOnce(includedPlan)
    vi.mocked(client.postGenerateRemediation).mockResolvedValueOnce({
      plan: generatedPlan,
      outputs: [generatedOutput()],
    })
    vi.mocked(client.getRemediationPlan)
      .mockResolvedValueOnce(includedPlan)
      .mockResolvedValueOnce(conflictPlan)
      .mockResolvedValueOnce(conflictPlan)
    const user = userEvent.setup()
    const urls = installObjectUrlHarness()

    try {
      renderResults(makeResult([makeFinding()]))
      await user.click(screen.getByRole('button', { name: INCLUDE_ACTION_NAME }))
      await user.click(await screen.findByRole('button', { name: 'Review remediation' }))
      await user.click(screen.getByRole('button', { name: 'Create redacted copies' }))
      expect(
        await screen.findByText('Evidence retained while this output is current.'),
      ).toBeInTheDocument()
      await user.click(screen.getByRole('button', { name: 'Close review' }))

      await user.click(screen.getByRole('button', { name: 'Review remediation' }))
      expect(await screen.findByText(/conflict; changed or untrusted output/i)).toBeInTheDocument()
      expect(
        screen.queryByText('Evidence retained while this output is current.'),
      ).not.toBeInTheDocument()
      await user.click(screen.getByRole('button', { name: 'Close review' }))
      await user.click(screen.getByRole('button', { name: 'Export JSON' }))

      expect(
        await screen.findByText(/report was not created because a redacted copy changed/i),
      ).toHaveAttribute('role', 'alert')
      expect(urls.createObjectURL).not.toHaveBeenCalled()
      expect(urls.clickedAnchors).toHaveLength(0)
    } finally {
      urls.restore()
    }
  })

  it('rejects stale report evidence after an output is deleted and opens refreshed review', async () => {
    const includedPlan = makePlan(['f1'], [], 1)
    const generatedPlan = currentPlan(['f1'], 1)
    const deletedPlan: RemediationPlan = {
      ...generatedPlan,
      files: generatedPlan.files.map((file) => ({
        ...file,
        output_state: 'regeneration_required',
      })),
    }
    vi.mocked(client.putRemediationPlan).mockResolvedValueOnce(includedPlan)
    vi.mocked(client.postGenerateRemediation).mockResolvedValueOnce({
      plan: generatedPlan,
      outputs: [generatedOutput()],
    })
    vi.mocked(client.getRemediationPlan)
      .mockResolvedValueOnce(includedPlan)
      .mockResolvedValueOnce(deletedPlan)
      .mockResolvedValueOnce(deletedPlan)
    const user = userEvent.setup()
    const urls = installObjectUrlHarness()

    try {
      renderResults(makeResult([makeFinding()]))
      await user.click(screen.getByRole('button', { name: INCLUDE_ACTION_NAME }))
      await user.click(await screen.findByRole('button', { name: 'Review remediation' }))
      await user.click(screen.getByRole('button', { name: 'Create redacted copies' }))
      await user.click(screen.getByRole('button', { name: 'Close review' }))

      await user.click(screen.getByRole('button', { name: 'Export readable report' }))
      expect(await screen.findByRole('alert')).toHaveTextContent(
        /prior output evidence.*no longer current/i,
      )
      expect(urls.createObjectURL).not.toHaveBeenCalled()

      await user.click(screen.getByRole('button', { name: 'Review remediation' }))
      expect(await screen.findByText(/regeneration required/i)).toBeInTheDocument()
      expect(screen.queryByText(/Verified output:/i)).not.toBeInTheDocument()
    } finally {
      urls.restore()
    }
  })

  it('creates no report when the freshness request expires', async () => {
    const includedPlan = makePlan(['f1'], [], 1)
    const generatedPlan = currentPlan(['f1'], 1)
    const onSessionExpired = vi.fn()
    vi.mocked(client.putRemediationPlan).mockResolvedValueOnce(includedPlan)
    vi.mocked(client.postGenerateRemediation).mockResolvedValueOnce({
      plan: generatedPlan,
      outputs: [generatedOutput()],
    })
    vi.mocked(client.getRemediationPlan)
      .mockResolvedValueOnce(includedPlan)
      .mockRejectedValueOnce({ code: 'scan_expired', message: 'Expired.' })
    const user = userEvent.setup()
    const urls = installObjectUrlHarness()

    try {
      renderResults(makeResult([makeFinding()]), { onSessionExpired })
      await user.click(screen.getByRole('button', { name: INCLUDE_ACTION_NAME }))
      await user.click(await screen.findByRole('button', { name: 'Review remediation' }))
      await user.click(screen.getByRole('button', { name: 'Create redacted copies' }))
      await user.click(screen.getByRole('button', { name: 'Close review' }))

      await user.click(screen.getByRole('button', { name: 'Export JSON' }))
      expect(onSessionExpired).toHaveBeenCalledTimes(1)
      expect(urls.createObjectURL).not.toHaveBeenCalled()
    } finally {
      urls.restore()
    }
  })

  it('creates no report when the freshness request fails', async () => {
    vi.mocked(client.getRemediationPlan).mockRejectedValueOnce(new Error('offline'))
    const user = userEvent.setup()
    const urls = installObjectUrlHarness()

    try {
      renderResults(makeResult([makeFinding()]))
      await user.click(screen.getByRole('button', { name: 'Export readable report' }))

      expect(await screen.findByRole('alert')).toHaveTextContent(/could not be refreshed/i)
      expect(urls.createObjectURL).not.toHaveBeenCalled()
    } finally {
      urls.restore()
    }
  })

  it('exports the exact concurrently updated plan returned by the freshness request', async () => {
    const localPlan = makePlan(['f1'], [], 1)
    const concurrentPlan = makePlan([], ['f1'], 9)
    vi.mocked(client.putRemediationPlan).mockResolvedValueOnce(localPlan)
    vi.mocked(client.getRemediationPlan).mockResolvedValueOnce(concurrentPlan)
    const user = userEvent.setup()
    const urls = installObjectUrlHarness()

    try {
      renderResults(makeResult([makeFinding()]))
      await user.click(screen.getByRole('button', { name: INCLUDE_ACTION_NAME }))
      expect(await screen.findByText('Included')).toBeInTheDocument()
      await user.click(screen.getByRole('button', { name: 'Export JSON' }))

      expect(urls.createObjectURL).toHaveBeenCalledTimes(1)
      const report = JSON.parse(await readBlob(urls.createObjectURL.mock.calls[0][0]))
      expect(report.remediation.plan_revision).toBe(9)
      expect(report.remediation.selected_finding_count).toBe(0)
      expect(report.findings).toEqual([expect.objectContaining({ id: 'f1', status: 'ignored' })])
      expect(screen.getByText('Ignored')).toBeInTheDocument()
    } finally {
      urls.restore()
    }
  })

  it('does not open review when its authoritative refresh expires', async () => {
    const includedPlan = makePlan(['f1'], [], 1)
    const onSessionExpired = vi.fn()
    vi.mocked(client.putRemediationPlan).mockResolvedValueOnce(includedPlan)
    vi.mocked(client.getRemediationPlan).mockRejectedValueOnce({
      code: 'scan_expired',
      message: 'Expired.',
    })
    const user = userEvent.setup()
    renderResults(makeResult([makeFinding()]), { onSessionExpired })

    await user.click(screen.getByRole('button', { name: INCLUDE_ACTION_NAME }))
    await user.click(await screen.findByRole('button', { name: 'Review remediation' }))

    expect(onSessionExpired).toHaveBeenCalledTimes(1)
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
  })

  it('downloads both report formats through short-lived object URLs', async () => {
    const user = userEvent.setup()
    const onToast = vi.fn()
    const createObjectURL = vi
      .fn<(blob: Blob) => string>()
      .mockReturnValueOnce('blob:redactlens-json')
      .mockReturnValueOnce('blob:redactlens-markdown')
    const revokeObjectURL = vi.fn<(url: string) => void>()
    const originalCreate = Object.getOwnPropertyDescriptor(URL, 'createObjectURL')
    const originalRevoke = Object.getOwnPropertyDescriptor(URL, 'revokeObjectURL')
    const clickedAnchors: HTMLAnchorElement[] = []
    const click = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(function (
      this: HTMLAnchorElement,
    ) {
      clickedAnchors.push(this)
    })
    Object.defineProperty(URL, 'createObjectURL', { configurable: true, value: createObjectURL })
    Object.defineProperty(URL, 'revokeObjectURL', { configurable: true, value: revokeObjectURL })

    try {
      renderResults(makeResult([makeFinding()]), { onToast })
      await user.click(screen.getByRole('button', { name: INCLUDE_ACTION_NAME }))
      expect(await screen.findByText('Included')).toBeInTheDocument()
      await user.click(screen.getByRole('button', { name: 'Export JSON' }))
      await user.click(screen.getByRole('button', { name: 'Export readable report' }))

      expect(createObjectURL).toHaveBeenCalledTimes(2)
      expect(createObjectURL.mock.calls[0][0]).toHaveProperty('type', 'application/json')
      expect(createObjectURL.mock.calls[1][0]).toHaveProperty('type', 'text/markdown')
      expect(clickedAnchors.map((anchor) => anchor.download)).toEqual([
        'redactlens-report.json',
        'redactlens-report.md',
      ])
      expect(revokeObjectURL.mock.calls).toEqual([
        ['blob:redactlens-json'],
        ['blob:redactlens-markdown'],
      ])
      const readBlob = (blob: Blob) =>
        new Promise<string>((resolve, reject) => {
          const reader = new FileReader()
          reader.addEventListener('load', () => resolve(String(reader.result)))
          reader.addEventListener('error', () => reject(reader.error))
          reader.readAsText(blob)
        })
      const jsonContents = JSON.parse(await readBlob(createObjectURL.mock.calls[0][0]))
      const markdownContents = await readBlob(createObjectURL.mock.calls[1][0])
      expect(jsonContents.remediation).toMatchObject({
        plan_revision: 1,
        selected_finding_count: 1,
      })
      expect(jsonContents.findings).toEqual([
        expect.objectContaining({ id: 'f1', status: 'included' }),
      ])
      expect(markdownContents).toContain('- Status: included')
      expect(markdownContents).toContain('- Plan revision: 1')
      expect(onToast).toHaveBeenCalledWith('Report saved as redactlens-report.json')
      expect(onToast).toHaveBeenCalledWith('Report saved as redactlens-report.md')
    } finally {
      click.mockRestore()
      if (originalCreate) Object.defineProperty(URL, 'createObjectURL', originalCreate)
      else Reflect.deleteProperty(URL, 'createObjectURL')
      if (originalRevoke) Object.defineProperty(URL, 'revokeObjectURL', originalRevoke)
      else Reflect.deleteProperty(URL, 'revokeObjectURL')
    }
  })

  it('extracted-document findings show a location and remain read-only', async () => {
    const user = userEvent.setup()
    renderResults(
      makeResult([
        makeFinding({
          id: 'doc1',
          tier: 'A',
          file_path: 'C:\\stuff\\report.pdf',
          location: 'page 3',
          can_anonymize: false,
        }),
      ]),
    )

    expect(screen.getByText('report.pdf · page 3')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: INCLUDE_ACTION_NAME })).not.toBeInTheDocument()
    expect(
      screen.queryByRole('button', {
        name: /pending writable Tier A findings across all results/i,
      }),
    ).not.toBeInTheDocument()
    expect(screen.getAllByText('Read-only')).toHaveLength(2)
    expect(screen.queryByRole('button', { name: IGNORE_ACTION_NAME })).not.toBeInTheDocument()
    await user.click(screen.getByText('12*******89'))
    expect(screen.getByText(/cannot safely rewrite/i)).toBeInTheDocument()
  })

  it('allows an AI description passage to be included and explains its full redaction scope', async () => {
    const user = userEvent.setup()
    const aiFinding = makeFinding({
      id: 'ai1',
      detector_id: 'user_target_desc_0',
      category: 'custom',
      redacted_preview: 'EM*****************13',
      file_path: 'C:\\project\\custom-rule-test-data.txt',
      can_anonymize: true,
    })
    vi.mocked(client.putRemediationPlan).mockResolvedValue({
      ...makePlan(['ai1']),
      findings: [{ finding_id: 'ai1', state: 'included' }],
    })
    renderResults(makeResult([aiFinding]))

    await user.click(screen.getByText('EM*****************13'))
    expect(screen.getByText(/AI description match covers the complete passage/i)).toHaveTextContent(
      /masks that entire passage/i,
    )
    await user.click(
      screen.getByRole('button', {
        name: /Include finding EM\*+13 .* in redaction plan/i,
      }),
    )

    expect(client.putRemediationPlan).toHaveBeenCalledWith('scan-1', ['ai1'], [], 0)
    expect(await screen.findByText('Included')).toBeInTheDocument()
  })

  it('shows a warning banner naming files it can identify but not anonymize', () => {
    renderResults(
      makeResult([
        makeFinding({ id: 'f1' }),
        makeFinding({
          id: 'doc1',
          file_path: 'C:\\stuff\\report.pdf',
          location: 'page 3',
          can_anonymize: false,
        }),
      ]),
    )

    const banner = screen.getByRole('note')
    expect(banner).toHaveTextContent(/read-only and excluded/i)
    expect(banner).toHaveTextContent('report.pdf')
    expect(banner).toHaveTextContent(/yourself/i)
  })

  it('describes mixed-capability files per finding without contradicting include actions', () => {
    const sharedPath = 'C:\\project\\custom-rule-test-data.txt'
    renderResults(
      makeResult([
        makeFinding({ id: 'f1', file_path: sharedPath }),
        makeFinding({
          id: 'doc1',
          file_path: sharedPath,
          location: 'embedded object',
          can_anonymize: false,
        }),
      ]),
    )

    const banner = screen.getByRole('note')
    expect(banner).toHaveTextContent(/One finding in custom-rule-test-data\.txt is read-only/i)
    expect(banner).toHaveTextContent(/applies only to results marked Read-only/i)
    expect(banner).toHaveTextContent(/Other findings in the same file can still be included/i)
    expect(screen.getByRole('button', { name: INCLUDE_ACTION_NAME })).toBeEnabled()
  })

  it('fails closed and refreshes when the backend says a visible finding became read-only', async () => {
    const user = userEvent.setup()
    vi.mocked(client.putRemediationPlan).mockRejectedValue({
      code: 'finding_not_anonymizable',
      message: 'This finding is now read-only.',
    })
    vi.mocked(client.getRemediationPlan).mockResolvedValue({
      ...makePlan(),
      findings: [{ finding_id: 'f1', state: 'read_only' }],
      read_only_finding_count: 1,
    })
    renderResults(makeResult([makeFinding({ id: 'f1' })]))

    await user.click(screen.getByRole('button', { name: INCLUDE_ACTION_NAME }))

    expect(await screen.findByRole('alert')).toHaveTextContent(/plan was refreshed/i)
    expect(screen.queryByRole('button', { name: INCLUDE_ACTION_NAME })).not.toBeInTheDocument()
    const card = screen.getByText('12*******89').closest('li')
    expect(card).not.toBeNull()
    expect(within(card!).getByText('Read-only')).toBeInTheDocument()
    expect(client.getRemediationPlan).toHaveBeenCalledWith('scan-1')
  })

  it('bounds the read-only warning while retaining the total file scope', () => {
    const findings = Array.from({ length: 80 }, (_, index) =>
      makeFinding({
        id: `doc-${index}`,
        file_path: `C:\\project\\manual-${index}.pdf`,
        redacted_preview: `manual-preview-${index}`,
        can_anonymize: false,
      }),
    )
    renderResults(makeResult(findings))

    const banner = screen.getByRole('note')
    expect(banner).toHaveTextContent('manual-0.pdf')
    expect(banner).toHaveTextContent('manual-4.pdf')
    expect(banner).toHaveTextContent('and 75 more files')
    expect(banner).not.toHaveTextContent('manual-79.pdf')
    expect(banner).toHaveTextContent(/Use the read-only filter to review them/i)
  })

  it('shows no read-only warning when every finding is anonymizable', () => {
    renderResults(makeResult([makeFinding()]))

    expect(screen.queryByRole('note')).not.toBeInTheDocument()
  })

  it('bulk inclusion only sends findings the backend can rewrite', async () => {
    const user = userEvent.setup()
    renderResults(
      makeResult([
        makeFinding({ id: 'f1', tier: 'A' }),
        makeFinding({ id: 'doc1', tier: 'A', location: 'page 2', can_anonymize: false }),
      ]),
    )

    await user.click(
      screen.getByRole('button', {
        name: 'Include all pending writable Tier A findings across all results (1)',
      }),
    )

    expect(client.putRemediationPlan).toHaveBeenCalledWith('scan-1', ['f1'], [], 0)
  })

  it('shows an honest empty state, never asserting safety', () => {
    renderResults(makeResult([]))

    expect(screen.getByText(/Nothing matched here/i)).toBeInTheDocument()
    expect(screen.queryByText(/\bsafe\b/i)).not.toBeInTheDocument()
  })

  it('warns when a completed scan inspected no files instead of reporting no matches', () => {
    renderResults(
      makeResult([], {
        scanned_files: [],
        skipped_files: [
          {
            path: 'C:\\project\\missing',
            reason: 'file is no longer available',
            code: 'stat_failed',
            stage: 'discovery',
            rule: null,
          },
        ],
      }),
    )

    expect(screen.getByRole('alert')).toHaveTextContent(/did not inspect any files/i)
    expect(screen.getByText(/No detection result is available/i)).toBeInTheDocument()
    expect(screen.queryByText(/Nothing matched here/i)).not.toBeInTheDocument()
    expect(screen.getByText(/Review 1 skipped file/i)).toBeInTheDocument()
  })

  it('distinguishes no filtered matches from no scan matches', async () => {
    const user = userEvent.setup()
    renderResults(makeResult([makeFinding()]))

    await user.selectOptions(screen.getByLabelText('Remediation capability'), 'read_only')

    expect(screen.getByText(/No findings match these filters/i)).toBeInTheDocument()
    expect(screen.queryByText(/Nothing matched here/i)).not.toBeInTheDocument()
  })

  it('identifies an all-read-only result set as a manual workflow', () => {
    renderResults(makeResult([makeFinding({ id: 'doc1', can_anonymize: false })]))

    expect(screen.getByText(/Only read-only findings were detected/i)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Review remediation' })).toBeDisabled()
  })

  it('gives accurate clear-filter guidance for filtered all-read-only results', async () => {
    const user = userEvent.setup()
    renderResults(
      makeResult([makeFinding({ id: 'doc1', tier: 'B', confidence: 0.6, can_anonymize: false })]),
    )

    await user.selectOptions(screen.getByLabelText('Tier'), 'A')

    expect(
      screen.getByText(/Only read-only findings are available, but none match these filters/i),
    ).toHaveTextContent(/Clear one or more filters to review them/i)
    expect(screen.queryByText(/Change the anonymizable filter/i)).not.toBeInTheDocument()
  })

  it('labels incomplete results and disables remediation actions', () => {
    renderResults(makeResult([makeFinding()], { state: 'timed_out' }))

    expect(screen.getByRole('alert')).toHaveTextContent(/scan is incomplete/i)
    expect(screen.getByRole('button', { name: INCLUDE_ACTION_NAME })).toBeDisabled()
    expect(screen.getByRole('button', { name: OPEN_ACTION_NAME })).toBeDisabled()
    expect(screen.queryByRole('button', { name: 'Review remediation' })).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Export JSON' })).toBeDisabled()
    expect(screen.getByRole('button', { name: 'Export readable report' })).toBeDisabled()
  })

  it('does not present an incomplete empty result as a completed no-match scan', () => {
    renderResults(makeResult([], { state: 'timed_out' }))

    expect(screen.getByRole('alert')).toHaveTextContent(/scan is incomplete/i)
    expect(
      screen.getByText(/No findings were retained before this scan stopped/i),
    ).toHaveTextContent(/run it again/i)
    expect(screen.queryByText(/Nothing matched here/i)).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Export JSON' })).toBeDisabled()
  })

  it('announces when every finding has a decision', async () => {
    const user = userEvent.setup()
    renderResults(makeResult([makeFinding()]))

    await user.click(screen.getByRole('button', { name: IGNORE_ACTION_NAME }))

    expect(await screen.findByText(/All findings have a decision/i)).toBeInTheDocument()
  })

  it('announces when every actionable finding is decided alongside read-only findings', async () => {
    const user = userEvent.setup()
    renderResults(
      makeResult([
        makeFinding({ id: 'f1' }),
        makeFinding({ id: 'doc1', can_anonymize: false, file_path: 'C:\\project\\manual.pdf' }),
      ]),
    )

    await user.click(screen.getByRole('button', { name: IGNORE_ACTION_NAME }))

    expect(await screen.findByText(/All actionable findings have a decision/i)).toHaveTextContent(
      /Read-only findings still require manual editing/i,
    )
  })

  it('does not show the empty state while still refining, even with zero findings so far', () => {
    renderResults(makeResult([]), { isRefining: true })

    expect(screen.queryByText(/Nothing matched here/i)).not.toBeInTheDocument()
    expect(screen.getByText(/Double-checking a few more with on-device AI/i)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Export JSON' })).toBeDisabled()
    expect(screen.getByRole('button', { name: 'Export readable report' })).toBeDisabled()
  })

  it('shows a refinement notice without hiding the results that already loaded', () => {
    renderResults(makeResult([makeFinding()]), { refineError: 'ollama unreachable' })

    expect(screen.getByText(/didn.t finish/i)).toHaveTextContent('ollama unreachable')
    expect(screen.getByText('12*******89')).toBeInTheDocument()
  })

  it('preserves per-finding status across a findings-array replace (same id)', async () => {
    const user = userEvent.setup()
    const { rerender } = renderResults(makeResult([makeFinding({ tier: 'B', confidence: 0.6 })]))

    // Simulate ignoring the finding while still on the heuristic-only result.
    await user.click(screen.getByRole('button', { name: IGNORE_ACTION_NAME }))
    expect(await screen.findByText('Ignored')).toBeInTheDocument()

    // Phase 2 replaces the whole result -- same id, but now Tier A (AI bumped it).
    rerender(
      <ResultsScreen
        result={makeResult([makeFinding({ tier: 'A', confidence: 0.9 })])}
        isRefining={false}
        refineError={null}
        onStartOver={vi.fn()}
        onSessionExpired={vi.fn()}
      />,
    )

    expect(screen.getByText('Ignored')).toBeInTheDocument()
    const tierASection = screen.getByRole('region', { name: /Confirmed sensitive/i })
    expect(within(tierASection).getByText('12*******89')).toBeInTheDocument()
  })
})
