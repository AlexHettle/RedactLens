import { act, fireEvent, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import * as client from './api/client'
import App from './App'
import type { PublicScanResult, RemediationPlan, ScanEvent, ScanProgress } from './types'

vi.mock('./api/client')

const PENDING_PROGRESS: ScanProgress = {
  stage: 'pending',
  completed_files: 0,
  total_files: null,
  percent: 0,
  current_file: null,
  findings_so_far: 0,
  skipped_files: 0,
}

const FINDING = {
  id: 'f1',
  file_path: 'C:\\some\\path\\a.txt',
  line: 1,
  column: 1,
  location: null,
  can_anonymize: true,
  redacted_preview: '12*******89',
  detector_id: 'us_ssn',
  category: 'personal_id',
  confidence: 0.95,
  tier: 'A' as const,
  explanation: 'A U.S. Social Security Number.',
  risk_lesson: 'Can be used for identity theft.',
  suggested_action: 'anonymize' as const,
  supporting_detections: [],
}

function scanResult(overrides: Partial<PublicScanResult> = {}): PublicScanResult {
  return {
    scan_id: 'scan-1',
    event_cursor: 1,
    created_at: '2026-07-15T00:00:00Z',
    expires_at: '2026-07-15T00:15:00Z',
    findings: [],
    summary: {},
    scanned_files: [],
    skipped_files: [],
    llm_used: false,
    state: 'pending',
    progress: PENDING_PROGRESS,
    error: null,
    metadata: {
      selected_roots: ['C:\\some\\path'],
      duration_ms: null,
      data_scanned_bytes: 0,
      detector_count: 0,
      ai_model: null,
    },
    ...overrides,
  }
}

function event(overrides: Partial<ScanEvent>): ScanEvent {
  return {
    sequence: 1,
    type: 'scan_started',
    emitted_at: '2026-07-15T00:00:01Z',
    scan_id: 'scan-1',
    state: 'discovering',
    progress: { ...PENDING_PROGRESS, stage: 'discovery' },
    finding: null,
    skipped_file: null,
    error: null,
    ...overrides,
  }
}

function deferred<T>() {
  let resolve!: (value: T | PromiseLike<T>) => void
  let reject!: (reason?: unknown) => void
  const promise = new Promise<T>((resolvePromise, rejectPromise) => {
    resolve = resolvePromise
    reject = rejectPromise
  })
  return { promise, resolve, reject }
}

let receiveEvent: ((event: ScanEvent) => void) | undefined
let disconnect: (() => void) | undefined
const closeStream = vi.fn()

beforeEach(() => {
  vi.clearAllMocks()
  vi.mocked(client.postScan).mockReset()
  vi.mocked(client.getScan).mockReset()
  vi.mocked(client.deleteScan).mockReset()
  vi.mocked(client.saveAppearanceTheme).mockReset()
  vi.mocked(client.postOpenFile).mockReset()
  vi.mocked(client.getRemediationPlan).mockReset()
  vi.mocked(client.putRemediationPlan).mockReset()
  vi.mocked(client.subscribeToScanEvents).mockReset()
  closeStream.mockReset()
  receiveEvent = undefined
  disconnect = undefined
  vi.mocked(client.deleteScan).mockResolvedValue()
  vi.mocked(client.saveAppearanceTheme).mockResolvedValue()
  vi.mocked(client.getDetectors).mockResolvedValue([
    {
      id: 'us_ssn',
      category: 'personal_id',
      description: 'SSN',
      risk_lesson: 'Identity risk',
    },
  ])
  vi.mocked(client.getHealth).mockResolvedValue({ status: 'ok', ollama_available: false })
  vi.mocked(client.subscribeToScanEvents).mockImplementation(
    (_id, _afterSequence, onEvent, onDisconnect) => {
      receiveEvent = onEvent
      disconnect = onDisconnect
      return closeStream
    },
  )
  localStorage.clear()
})

afterEach(() => {
  vi.useRealTimers()
})

async function startScan(user: ReturnType<typeof userEvent.setup>) {
  await user.type(await screen.findByLabelText(/Folder or file to scan/i), 'C:\\some\\path')
  await user.click(screen.getByRole('button', { name: /Scan this location/i }))
  await screen.findByRole('heading', { name: /Looking through your files/i })
  await waitFor(() => expect(client.subscribeToScanEvents).toHaveBeenCalled())
}

describe('App', () => {
  it('renders the Setup screen by default', async () => {
    render(<App />)
    expect(await screen.findByRole('heading', { name: 'RedactLens' })).toHaveFocus()
  })

  it('shows real progress and partial findings before the completed result', async () => {
    vi.mocked(client.postScan).mockResolvedValue(scanResult())
    vi.mocked(client.postOpenFile).mockResolvedValue({ status: 'ok' })
    vi.mocked(client.getScan).mockResolvedValue(
      scanResult({
        event_cursor: 3,
        state: 'complete',
        findings: [FINDING],
        scanned_files: [FINDING.file_path],
        progress: {
          ...PENDING_PROGRESS,
          stage: 'complete',
          completed_files: 1,
          total_files: 1,
          percent: 100,
          findings_so_far: 1,
        },
      }),
    )
    const user = userEvent.setup()
    render(<App />)
    await startScan(user)

    await act(async () => {
      receiveEvent?.(
        event({
          sequence: 2,
          type: 'finding_added',
          state: 'scanning',
          finding: FINDING,
          progress: {
            ...PENDING_PROGRESS,
            stage: 'consolidation',
            total_files: 1,
            findings_so_far: 1,
            current_file: FINDING.file_path,
          },
        }),
      )
    })
    expect(screen.getByRole('heading', { name: /Findings so far/i })).toBeInTheDocument()
    expect(screen.getByText(FINDING.redacted_preview)).toBeInTheDocument()
    expect(screen.getByText('US SSN')).toHaveClass(
      'partial-findings__type',
      'partial-findings__type--a',
    )

    await act(async () => {
      receiveEvent?.(
        event({
          sequence: 3,
          type: 'scan_completed',
          state: 'complete',
          progress: {
            ...PENDING_PROGRESS,
            stage: 'complete',
            completed_files: 1,
            total_files: 1,
            percent: 100,
            findings_so_far: 1,
          },
        }),
      )
    })

    expect(await screen.findByRole('heading', { name: /Here.s what I found/ })).toHaveFocus()
    expect(client.postScan).toHaveBeenCalledTimes(1)

    await user.click(screen.getByRole('button', { name: /Show .*a\.txt in folder for/i }))
    expect(await screen.findByText(/Showed a\.txt in its folder/i)).toHaveAttribute(
      'role',
      'status',
    )
    await user.click(screen.getByRole('button', { name: 'Dismiss notification' }))
    expect(screen.queryByText(/Showed a\.txt in its folder/i)).not.toBeInTheDocument()
  })

  it('applies AI refinement to a stable finding instead of duplicating it', async () => {
    vi.mocked(client.postScan).mockResolvedValue(scanResult())
    const user = userEvent.setup()
    render(<App />)
    await startScan(user)

    await act(async () => {
      receiveEvent?.(
        event({
          sequence: 2,
          type: 'finding_added',
          state: 'scanning',
          finding: { ...FINDING, confidence: 0.7, tier: 'B' },
        }),
      )
      receiveEvent?.(
        event({
          sequence: 3,
          type: 'finding_updated',
          state: 'refining',
          finding: FINDING,
          progress: { ...PENDING_PROGRESS, stage: 'ai_refinement', findings_so_far: 1 },
        }),
      )
    })

    expect(screen.getAllByText(FINDING.redacted_preview)).toHaveLength(1)
    expect(screen.getByText('A')).toBeInTheDocument()
  })

  it('renders the nonterminal final verification stage without completing early', async () => {
    vi.mocked(client.postScan).mockResolvedValue(scanResult())
    const user = userEvent.setup()
    render(<App />)
    await startScan(user)

    await act(async () => {
      receiveEvent?.(
        event({
          sequence: 2,
          type: 'scan_finalizing',
          state: 'scanning',
          progress: { ...PENDING_PROGRESS, stage: 'finalizing', total_files: 1 },
        }),
      )
    })

    expect(screen.getByText('Finalizing the scan summary…')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Cancel' })).toBeEnabled()
    expect(screen.queryByRole('heading', { name: /Here.s what I found/ })).not.toBeInTheDocument()
  })

  it('announces throttled file, finding, and skipped totals as one atomic status', async () => {
    vi.mocked(client.postScan).mockResolvedValue(scanResult())
    const user = userEvent.setup()
    render(<App />)
    await startScan(user)

    await act(async () => {
      receiveEvent?.(
        event({
          sequence: 2,
          type: 'finding_added',
          state: 'scanning',
          finding: FINDING,
          progress: {
            ...PENDING_PROGRESS,
            stage: 'consolidation',
            completed_files: 2,
            total_files: 4,
            percent: 50,
            findings_so_far: 1,
            skipped_files: 1,
            current_file: FINDING.file_path,
          },
        }),
      )
    })

    const status = screen.getByRole('status')
    await waitFor(() => expect(status).toHaveTextContent('2 of 4 files completed'), {
      timeout: 1200,
    })
    expect(status).toHaveTextContent('1 finding')
    expect(status).toHaveTextContent('1 skipped')
    expect(status).toHaveAttribute('aria-atomic', 'true')
  })

  it('shows a friendly error and returns to setup if job creation fails', async () => {
    vi.mocked(client.postScan).mockRejectedValue(new Error('backend down'))
    const user = userEvent.setup()
    render(<App />)
    await user.type(await screen.findByLabelText(/Folder or file to scan/i), 'C:\\some\\path')
    await user.click(screen.getByRole('button', { name: /Scan this location/i }))
    expect(await screen.findByRole('alert')).toHaveTextContent('backend down')
    expect(screen.getByRole('alert')).toHaveFocus()
    expect(screen.getByRole('heading', { name: 'RedactLens' })).toBeInTheDocument()

    const pathInput = screen.getByLabelText(/Folder or file to scan/i)
    await user.clear(pathInput)

    expect(screen.queryByText('backend down')).not.toBeInTheDocument()
    expect(pathInput).toHaveFocus()
  })

  it('waits for authoritative cancellation, preserves partial results, then returns explicitly', async () => {
    vi.mocked(client.postScan).mockResolvedValue(scanResult())
    vi.mocked(client.getScan).mockResolvedValue(
      scanResult({
        event_cursor: 2,
        state: 'cancelled',
        findings: [FINDING],
        error: { code: 'scan_cancelled', message: 'Scan cancelled by request.' },
        progress: {
          ...PENDING_PROGRESS,
          stage: 'cancelled',
          total_files: 3,
          completed_files: 1,
          percent: 33.3,
          findings_so_far: 1,
        },
      }),
    )
    const user = userEvent.setup()
    render(<App />)
    await startScan(user)
    expect(screen.getByRole('heading', { name: /Looking through your files/i })).toHaveFocus()
    await user.click(screen.getByRole('button', { name: 'Cancel' }))

    expect(client.deleteScan).toHaveBeenCalledWith('scan-1', expect.any(AbortSignal))
    expect(
      await screen.findByRole('heading', { name: /Scan stopped before finishing/i }),
    ).toHaveFocus()
    expect(screen.getByText(FINDING.redacted_preview)).toBeInTheDocument()
    expect(
      screen.getByRole('heading', { name: /Findings so far — incomplete/i }),
    ).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Back to setup' }))
    expect(await screen.findByRole('heading', { name: 'RedactLens' })).toBeInTheDocument()
    expect(screen.getByLabelText(/Folder or file to scan/i)).toHaveValue('C:\\some\\path')
  })

  it('focuses the first newly revealed terminal item after every finding and skip expansion', async () => {
    const retainedFindings = Array.from({ length: 103 }, (_, index) => ({
      ...FINDING,
      id: `retained-${index}`,
      file_path: `C:\\some\\path\\file-${index}.txt`,
      redacted_preview: `partial-${index}`,
      line: index + 1,
    }))
    const skippedFiles: PublicScanResult['skipped_files'] = [
      {
        path: 'C:\\some\\path\\skips\\archive.zip',
        reason: 'Archive content requires extraction before rescanning.',
        code: 'archive',
        stage: 'extraction',
        rule: null,
      },
      {
        path: 'C:\\some\\path\\skips\\photo.png',
        reason: 'Image file requires trusted local OCR before rescanning.',
        code: 'binary_file',
        stage: 'extraction',
        rule: null,
      },
      ...Array.from({ length: 101 }, (_, index) => ({
        path: `C:\\some\\path\\skips\\extra-${index}.zip`,
        reason: `Archive ${index} requires extraction before rescanning.`,
        code: 'archive',
        stage: 'extraction' as const,
        rule: null,
      })),
    ]
    vi.mocked(client.postScan).mockResolvedValue(scanResult())
    vi.mocked(client.getScan).mockResolvedValue(
      scanResult({
        event_cursor: 2,
        state: 'timed_out',
        findings: retainedFindings,
        skipped_files: skippedFiles,
        error: { code: 'scan_timed_out', message: 'Scan exceeded its time limit.' },
        progress: {
          ...PENDING_PROGRESS,
          stage: 'timed_out',
          completed_files: 40,
          total_files: 60,
          percent: 66.7,
          findings_so_far: retainedFindings.length,
          skipped_files: skippedFiles.length,
        },
      }),
    )
    const user = userEvent.setup()
    render(<App />)
    await startScan(user)

    await act(async () => {
      receiveEvent?.(event({ sequence: 2, type: 'scan_failed', state: 'timed_out' }))
    })

    const terminalHeading = await screen.findByRole('heading', {
      name: /Scan stopped before finishing/i,
    })
    expect(terminalHeading).toHaveFocus()
    expect(screen.getByText('partial-0')).toBeInTheDocument()
    expect(screen.getByText('partial-49')).toBeInTheDocument()
    expect(screen.queryByText('partial-50')).not.toBeInTheDocument()
    expect(screen.getByText('Showing 50 of 103 retained findings.')).toBeInTheDocument()

    const findingPath = screen.getByText('C:\\some\\path\\file-0.txt')
    expect(findingPath).not.toBeVisible()
    await user.click(screen.getByText('Show full path for file-0.txt'))
    expect(findingPath).toBeVisible()

    await user.click(screen.getByRole('button', { name: 'Show up to 50 more retained findings' }))
    expect(screen.getByText('partial-50').closest('li')).toHaveFocus()
    expect(screen.getByText('Showing 100 of 103 retained findings.')).toBeInTheDocument()
    expect(
      screen.getByRole('button', { name: 'Show up to 3 more retained findings' }),
    ).toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: 'Show up to 3 more retained findings' }))
    expect(screen.getByText('partial-100').closest('li')).toHaveFocus()
    expect(screen.getByText('partial-102')).toBeInTheDocument()
    expect(screen.getByText('Showing 103 of 103 retained findings.')).toBeInTheDocument()
    expect(
      screen.queryByRole('button', { name: /more retained findings/i }),
    ).not.toBeInTheDocument()

    const skippedDisclosure = screen.getByText('Review 103 skipped files from this incomplete scan')
    expect(screen.getByText(skippedFiles[0].reason)).not.toBeVisible()
    await user.click(skippedDisclosure)
    expect(screen.getByText(skippedFiles[0].reason)).toBeVisible()
    expect(screen.getByText('skips/archive.zip')).toBeVisible()

    const skippedPath = screen.getByText(skippedFiles[0].path)
    expect(skippedPath).not.toBeVisible()
    await user.click(screen.getByText('Show full path for archive.zip'))
    expect(skippedPath).toBeVisible()
    await user.click(screen.getByRole('button', { name: 'Show up to 50 more skipped files' }))
    expect(screen.getByText(skippedFiles[50].reason).closest('li')).toHaveFocus()
    expect(screen.getByText('Showing 100 of 103 skipped files.')).toBeVisible()
    expect(screen.getByRole('button', { name: 'Show up to 3 more skipped files' })).toBeVisible()

    await user.click(screen.getByRole('button', { name: 'Show up to 3 more skipped files' }))
    expect(screen.getByText(skippedFiles[100].reason).closest('li')).toHaveFocus()
    expect(screen.getByText(skippedFiles[102].reason)).toBeVisible()
    expect(screen.getByText('Showing 103 of 103 skipped files.')).toBeVisible()
    expect(screen.queryByRole('button', { name: /more skipped files/i })).not.toBeInTheDocument()
    expect(
      screen.queryByRole('button', { name: /Include finding .* in redaction plan/i }),
    ).not.toBeInTheDocument()
  })

  it('keeps the scan and partial findings visible while DELETE cancellation is pending', async () => {
    const cancellation = deferred<void>()
    vi.mocked(client.postScan).mockResolvedValue(
      scanResult({
        state: 'scanning',
        findings: [FINDING],
        progress: {
          ...PENDING_PROGRESS,
          stage: 'detection',
          total_files: 3,
          findings_so_far: 1,
        },
      }),
    )
    vi.mocked(client.deleteScan).mockReturnValue(cancellation.promise)
    vi.mocked(client.getScan).mockResolvedValue(
      scanResult({
        event_cursor: 2,
        state: 'cancelled',
        findings: [FINDING],
        error: { code: 'scan_cancelled', message: 'Scan cancelled by request.' },
        progress: {
          ...PENDING_PROGRESS,
          stage: 'cancelled',
          total_files: 3,
          findings_so_far: 1,
        },
      }),
    )
    const user = userEvent.setup()
    render(<App />)
    await startScan(user)

    await user.click(screen.getByRole('button', { name: 'Cancel' }))
    expect(screen.getByRole('button', { name: 'Cancelling…' })).toBeDisabled()
    expect(screen.getByText(FINDING.redacted_preview)).toBeInTheDocument()
    expect(screen.queryByRole('heading', { name: 'RedactLens' })).not.toBeInTheDocument()

    await act(async () => cancellation.resolve())
    expect(
      await screen.findByRole('heading', { name: /Scan stopped before finishing/i }),
    ).toBeInTheDocument()
  })

  it('does not repeat the current filename beneath the live file count', async () => {
    vi.mocked(client.postScan).mockResolvedValue(
      scanResult({
        state: 'scanning',
        progress: { ...PENDING_PROGRESS, stage: 'discovery' },
      }),
    )
    const user = userEvent.setup()
    render(<App />)
    await startScan(user)

    expect(screen.getByText('Scan target: path')).toBeInTheDocument()
    expect(screen.queryByText(/Current file:/i)).not.toBeInTheDocument()

    await act(async () => {
      receiveEvent?.(
        event({
          sequence: 2,
          type: 'file_started',
          state: 'scanning',
          progress: {
            ...PENDING_PROGRESS,
            stage: 'extraction',
            total_files: 1,
            current_file: 'C:\\some\\path\\document.txt',
          },
        }),
      )
    })

    expect(screen.queryByText(/Current file:/i)).not.toBeInTheDocument()
  })

  it('keeps connection retry isolated from an in-flight cancellation request', async () => {
    vi.mocked(client.postScan).mockResolvedValue(scanResult({ state: 'scanning' }))
    vi.mocked(client.getScan).mockRejectedValue(new Error('connection dropped'))
    const cancellation = deferred<void>()
    let cancellationSignal: AbortSignal | undefined
    const user = userEvent.setup()
    render(<App />)
    await startScan(user)

    vi.useFakeTimers()
    await act(async () => disconnect?.())
    await act(async () => {
      await vi.advanceTimersByTimeAsync(11_000)
    })
    vi.useRealTimers()
    expect(screen.getByRole('button', { name: 'Retry live connection' })).toBeEnabled()

    vi.mocked(client.deleteScan).mockImplementation((_scanId, signal) => {
      cancellationSignal = signal
      return cancellation.promise
    })
    await user.click(screen.getByRole('button', { name: 'Cancel' }))

    expect(screen.queryByRole('button', { name: 'Retry live connection' })).not.toBeInTheDocument()
    expect(cancellationSignal?.aborted).toBe(false)

    vi.mocked(client.getScan).mockResolvedValue(
      scanResult({
        event_cursor: 2,
        state: 'cancelled',
        error: { code: 'scan_cancelled', message: 'Scan cancelled by request.' },
        progress: { ...PENDING_PROGRESS, stage: 'cancelled' },
      }),
    )
    await act(async () => cancellation.resolve())
    expect(
      await screen.findByRole('heading', { name: /Scan stopped before finishing/i }),
    ).toBeInTheDocument()
  })

  it('stops announcing recovery when cancellation supersedes a pending snapshot request', async () => {
    vi.mocked(client.postScan).mockResolvedValue(
      scanResult({
        state: 'scanning',
        progress: { ...PENDING_PROGRESS, stage: 'detection', total_files: 2 },
      }),
    )
    let recoverySignal: AbortSignal | undefined
    vi.mocked(client.getScan).mockImplementation(
      (_scanId, signal) =>
        new Promise<PublicScanResult>((_resolve, reject) => {
          recoverySignal = signal
          signal?.addEventListener(
            'abort',
            () => reject(new DOMException('Aborted', 'AbortError')),
            { once: true },
          )
        }),
    )
    const cancellation = deferred<void>()
    vi.mocked(client.deleteScan).mockReturnValue(cancellation.promise)
    const user = userEvent.setup()
    render(<App />)
    await startScan(user)

    await act(async () => disconnect?.())
    await waitFor(() => expect(client.getScan).toHaveBeenCalledTimes(1))
    expect(recoverySignal?.aborted).toBe(false)

    await user.click(screen.getByRole('button', { name: 'Cancel' }))

    expect(recoverySignal?.aborted).toBe(true)
    await waitFor(
      () => {
        const liveStatus = screen.getByRole('status')
        expect(liveStatus).toHaveTextContent(/Cancellation requested/i)
        expect(liveStatus).not.toHaveTextContent(/Reconnecting to live scan updates/i)
      },
      { timeout: 1500 },
    )

    vi.mocked(client.getScan).mockResolvedValue(
      scanResult({
        event_cursor: 2,
        state: 'cancelled',
        error: { code: 'scan_cancelled', message: 'Scan cancelled by request.' },
        progress: { ...PENDING_PROGRESS, stage: 'cancelled' },
      }),
    )
    await act(async () => cancellation.resolve())
    expect(
      await screen.findByRole('heading', { name: /Scan stopped before finishing/i }),
    ).toBeInTheDocument()
  })

  it('retains the last authoritative state when cancellation and recovery both fail', async () => {
    vi.mocked(client.postScan).mockResolvedValue(
      scanResult({
        state: 'scanning',
        progress: { ...PENDING_PROGRESS, stage: 'detection', total_files: 2 },
      }),
    )
    vi.mocked(client.deleteScan).mockRejectedValue(new Error('connection dropped'))
    vi.mocked(client.getScan).mockRejectedValue(new Error('snapshot unavailable'))
    const user = userEvent.setup()
    render(<App />)
    await startScan(user)

    await user.click(screen.getByRole('button', { name: 'Cancel' }))

    expect(await screen.findByText('Checking the current file…')).toBeInTheDocument()
    expect(screen.queryByText(/Cancellation requested/i)).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Retry cancellation' })).toBeEnabled()
    await waitFor(() => expect(client.getScan).toHaveBeenCalledTimes(3), { timeout: 2500 })
    expect(await screen.findByText(/Live scan updates are temporarily unavailable/i)).toBeVisible()
  })

  it('shows a retryable cancellation error and succeeds when cancellation is retried', async () => {
    vi.mocked(client.postScan).mockResolvedValue(scanResult({ state: 'scanning' }))
    vi.mocked(client.deleteScan)
      .mockRejectedValueOnce(new Error('connection dropped'))
      .mockResolvedValueOnce()
    vi.mocked(client.getScan)
      .mockResolvedValueOnce(scanResult({ state: 'scanning' }))
      .mockResolvedValueOnce(
        scanResult({
          event_cursor: 2,
          state: 'cancelled',
          error: { code: 'scan_cancelled', message: 'Scan cancelled by request.' },
          progress: { ...PENDING_PROGRESS, stage: 'cancelled' },
        }),
      )
    const user = userEvent.setup()
    render(<App />)
    await startScan(user)

    await user.click(screen.getByRole('button', { name: 'Cancel' }))
    expect(await screen.findByRole('alert')).toHaveTextContent(
      'RedactLens could not confirm cancellation',
    )
    expect(screen.getByRole('button', { name: 'Retry cancellation' })).toBeEnabled()

    await user.click(screen.getByRole('button', { name: 'Retry cancellation' }))
    expect(client.deleteScan).toHaveBeenCalledTimes(2)
    expect(
      await screen.findByRole('heading', { name: /Scan stopped before finishing/i }),
    ).toBeInTheDocument()
  })

  it('completes scan and remediation using only keyboard input', async () => {
    const complete = scanResult({
      event_cursor: 2,
      state: 'complete',
      findings: [FINDING],
      scanned_files: [FINDING.file_path],
      progress: {
        ...PENDING_PROGRESS,
        stage: 'complete',
        completed_files: 1,
        total_files: 1,
        percent: 100,
        findings_so_far: 1,
      },
    })
    const includedPlan = {
      plan_revision: 1,
      findings: [{ finding_id: 'f1', state: 'included' as const }],
      files: [
        {
          source_path: FINDING.file_path,
          output_path: FINDING.file_path.replace(/(\.[^./\\]+)$/, '-auto-redacted-copy$1'),
          included_finding_ids: ['f1'],
          output_state: 'not_created' as const,
        },
      ],
      selected_finding_count: 1,
      affected_file_count: 1,
      read_only_finding_count: 0,
      retained_artifact_paths: [],
      can_review: true,
      can_generate: true,
    }
    vi.mocked(client.postScan).mockResolvedValue(scanResult())
    vi.mocked(client.getScan).mockResolvedValue(complete)
    vi.mocked(client.putRemediationPlan).mockResolvedValue(includedPlan)
    vi.mocked(client.getRemediationPlan).mockResolvedValue(includedPlan)
    vi.mocked(client.postGenerateRemediation).mockResolvedValue({
      plan: {
        ...includedPlan,
        files: includedPlan.files.map((file) => ({ ...file, output_state: 'current' })),
      },
      outputs: [
        {
          source_path: FINDING.file_path,
          output_path: FINDING.file_path.replace(/(\.[^./\\]+)$/, '-auto-redacted-copy$1'),
          applied_finding_ids: ['f1'],
          verification_status: 'verified',
          warnings: ['Review before sharing.'],
          source_fingerprint: {
            resolved_path: FINDING.file_path,
            size: 42,
            modified_ns: 1,
            sha256: 'a'.repeat(64),
          },
          rescan_status: 'completed' as const,
          remaining_finding_count: 0,
          remaining_tier_a_count: 0,
        },
      ],
    })
    const user = userEvent.setup()
    render(<App />)

    await screen.findByRole('heading', { name: 'RedactLens' })
    await user.tab()
    expect(screen.getByRole('button', { name: 'On device' })).toHaveFocus()
    await user.tab()
    expect(screen.getByLabelText(/Folder or file to scan/i)).toHaveFocus()
    await user.keyboard('C:\\some\\path{Enter}')
    await screen.findByRole('heading', { name: /Looking through your files/i })
    await act(async () => {
      receiveEvent?.(event({ sequence: 2, type: 'scan_completed', state: 'complete' }))
    })
    await screen.findByRole('heading', { name: /Here.s what I found/i })

    async function tabToButton(label: string) {
      for (let index = 0; index < 60; index += 1) {
        await user.tab()
        const active = document.activeElement
        if (active instanceof HTMLButtonElement && active.textContent?.trim() === label)
          return active
      }
      throw new Error(`Keyboard focus did not reach ${label}`)
    }

    expect(
      await tabToButton('Include all pending writable Tier A findings across all results (1)'),
    ).toHaveFocus()
    await user.keyboard('{Enter}')
    expect(await tabToButton('Review remediation')).toHaveFocus()
    await user.keyboard('{Enter}')
    expect(screen.getByRole('dialog')).toHaveFocus()
    await user.tab({ shift: true })
    expect(screen.getByRole('button', { name: 'Create redacted copies' })).toHaveFocus()
    await user.keyboard('{Enter}')

    expect(await screen.findByText(/selected values were removed/i)).toBeInTheDocument()
    expect(client.postGenerateRemediation).toHaveBeenCalledWith('scan-1', 1, 'copy')
  })

  it('sends the AI option in one scan instead of launching a second scan', async () => {
    vi.mocked(client.getHealth).mockResolvedValue({ status: 'ok', ollama_available: true })
    vi.mocked(client.postScan).mockResolvedValue(scanResult({ state: 'complete' }))
    const user = userEvent.setup()
    render(<App />)
    await user.type(await screen.findByLabelText(/Folder or file to scan/i), 'C:\\some\\path')
    await user.click(await screen.findByRole('switch', { name: /On-device AI/i }))
    await user.click(screen.getByRole('button', { name: /Scan this location/i }))

    expect(client.postScan).toHaveBeenCalledTimes(1)
    expect(client.postScan).toHaveBeenCalledWith(expect.objectContaining({ use_llm: true }))
  })

  it('recovers current state after an event-stream disconnect', async () => {
    vi.mocked(client.postScan).mockResolvedValue(scanResult())
    vi.mocked(client.getScan).mockResolvedValue(
      scanResult({ event_cursor: 2, state: 'complete', findings: [FINDING] }),
    )
    const user = userEvent.setup()
    render(<App />)
    await startScan(user)

    await act(async () => disconnect?.())

    expect(client.getScan).toHaveBeenCalledWith('scan-1', expect.any(AbortSignal))
    expect(await screen.findByRole('heading', { name: /Here.s what I found/ })).toBeInTheDocument()
  })

  it('recovers an active snapshot and reconnects after its authoritative cursor', async () => {
    vi.mocked(client.postScan).mockResolvedValue(scanResult())
    vi.mocked(client.getScan).mockResolvedValue(
      scanResult({
        event_cursor: 2,
        state: 'scanning',
        findings: [FINDING],
        progress: {
          ...PENDING_PROGRESS,
          stage: 'detection',
          completed_files: 1,
          total_files: 3,
          percent: 33.3,
          findings_so_far: 1,
        },
      }),
    )
    const user = userEvent.setup()
    render(<App />)
    await startScan(user)

    await act(async () => disconnect?.())

    expect(await screen.findByText(FINDING.redacted_preview)).toBeInTheDocument()
    await waitFor(() => expect(client.subscribeToScanEvents).toHaveBeenCalledTimes(2))
    expect(vi.mocked(client.subscribeToScanEvents).mock.calls[1][1]).toBe(2)
    expect(screen.getByRole('heading', { name: /Looking through your files/i })).toBeInTheDocument()
  })

  it('ignores duplicate and out-of-order events and recovers an event gap from a snapshot', async () => {
    const lowConfidence = { ...FINDING, confidence: 0.7, tier: 'B' as const }
    vi.mocked(client.postScan).mockResolvedValue(scanResult())
    vi.mocked(client.getScan).mockResolvedValue(
      scanResult({
        event_cursor: 4,
        state: 'scanning',
        findings: [FINDING],
        progress: {
          ...PENDING_PROGRESS,
          stage: 'detection',
          completed_files: 1,
          total_files: 2,
          percent: 50,
          findings_so_far: 1,
        },
      }),
    )
    const user = userEvent.setup()
    render(<App />)
    await startScan(user)

    await act(async () => {
      receiveEvent?.(
        event({ sequence: 2, type: 'finding_added', state: 'scanning', finding: lowConfidence }),
      )
      receiveEvent?.(
        event({ sequence: 2, type: 'finding_updated', state: 'refining', finding: FINDING }),
      )
      receiveEvent?.(
        event({ sequence: 1, type: 'finding_updated', state: 'refining', finding: FINDING }),
      )
    })
    expect(screen.getByText('B')).toBeInTheDocument()
    expect(screen.queryByText('A')).not.toBeInTheDocument()

    await act(async () => {
      receiveEvent?.(event({ sequence: 4, type: 'file_completed', state: 'scanning' }))
    })
    await waitFor(() => expect(client.getScan).toHaveBeenCalledTimes(1))
    expect(await screen.findByText('A')).toBeInTheDocument()
    await waitFor(() => expect(client.subscribeToScanEvents).toHaveBeenCalledTimes(2))
    expect(vi.mocked(client.subscribeToScanEvents).mock.calls[1][1]).toBe(4)
  })

  it('rejects a stale snapshot after a newer event and retries without regressing the finding', async () => {
    vi.mocked(client.postScan).mockResolvedValue(scanResult())
    vi.mocked(client.getScan)
      .mockResolvedValueOnce(
        scanResult({
          event_cursor: 1,
          state: 'scanning',
          findings: [{ ...FINDING, confidence: 0.7, tier: 'B' }],
        }),
      )
      .mockResolvedValueOnce(
        scanResult({ event_cursor: 2, state: 'refining', findings: [FINDING] }),
      )
    const user = userEvent.setup()
    render(<App />)
    await startScan(user)

    await act(async () => {
      receiveEvent?.(
        event({ sequence: 2, type: 'finding_updated', state: 'refining', finding: FINDING }),
      )
      disconnect?.()
    })

    await waitFor(() => expect(client.getScan).toHaveBeenCalledTimes(2), { timeout: 1200 })
    expect(screen.getByText('A')).toBeInTheDocument()
    expect(screen.queryByText('B')).not.toBeInTheDocument()
  })

  it('fences queued callbacks from the closed stream while a snapshot is delayed', async () => {
    const snapshot = deferred<PublicScanResult>()
    vi.mocked(client.postScan).mockResolvedValue(scanResult())
    vi.mocked(client.getScan).mockReturnValue(snapshot.promise)
    const user = userEvent.setup()
    render(<App />)
    await startScan(user)
    const staleEvent = receiveEvent

    await act(async () => disconnect?.())
    await act(async () => {
      staleEvent?.(
        event({ sequence: 2, type: 'finding_added', state: 'scanning', finding: FINDING }),
      )
      snapshot.resolve(scanResult({ state: 'scanning' }))
    })

    await waitFor(() => expect(client.subscribeToScanEvents).toHaveBeenCalledTimes(2))
    expect(screen.queryByText(FINDING.redacted_preview)).not.toBeInTheDocument()
    expect(vi.mocked(client.subscribeToScanEvents).mock.calls[1][1]).toBe(1)
  })

  it('bounds a hung snapshot recovery and leaves a manual retry without discarding state', async () => {
    vi.mocked(client.postScan).mockResolvedValue(scanResult())
    vi.mocked(client.getScan).mockImplementation(
      (_scanId, signal) =>
        new Promise<PublicScanResult>((_resolve, reject) => {
          signal?.addEventListener(
            'abort',
            () => reject(new DOMException('Aborted', 'AbortError')),
            {
              once: true,
            },
          )
        }),
    )
    const user = userEvent.setup()
    render(<App />)
    await startScan(user)
    vi.useFakeTimers()

    await act(async () => disconnect?.())
    await act(async () => {
      await vi.advanceTimersByTimeAsync(11_000)
    })

    expect(client.getScan).toHaveBeenCalledTimes(3)
    expect(screen.getByRole('alert')).toHaveTextContent(
      'Live scan updates are temporarily unavailable',
    )
    expect(screen.getByRole('button', { name: 'Retry live connection' })).toBeEnabled()
    expect(screen.getByRole('heading', { name: /Looking through your files/i })).toBeInTheDocument()
  })

  it('stops recovery and restores every setup field when the active scan has expired', async () => {
    vi.mocked(client.getDetectors).mockResolvedValue([
      {
        id: 'us_ssn',
        category: 'personal_id',
        description: 'SSN',
        risk_lesson: 'Identity risk',
      },
      {
        id: 'credit_card',
        category: 'financial',
        description: 'Credit card',
        risk_lesson: 'Financial risk',
      },
    ])
    vi.mocked(client.getHealth).mockResolvedValue({ status: 'ok', ollama_available: true })
    vi.mocked(client.postScan).mockResolvedValue(scanResult())
    vi.mocked(client.getScan).mockRejectedValue(
      Object.assign(new Error('This scan has expired.'), { code: 'scan_expired' }),
    )
    const user = userEvent.setup()
    render(<App />)

    const path = await screen.findByLabelText(/Folder or file to scan/i)
    await user.type(path, 'C:\\some\\path')
    await user.click(await screen.findByRole('checkbox', { name: /Financial/i }))
    const aiSwitch = screen.getByRole('switch', { name: /On-device AI/i })
    await waitFor(() => expect(aiSwitch).toBeEnabled())
    await user.click(aiSwitch)

    const target = screen.getByLabelText(/Value or description/i)
    await user.type(target, 'ACME-1234')
    await user.click(screen.getByRole('button', { name: 'Add' }))
    await user.click(screen.getByRole('radio', { name: /Plain-English description/i }))
    await user.type(target, 'employee payroll identifier')
    await user.click(screen.getByRole('button', { name: 'Add' }))

    await user.click(screen.getByText('Advanced scan options'))
    const replace = async (label: RegExp, value: string) => {
      const input = screen.getByLabelText(label)
      await user.clear(input)
      await user.type(input, value)
    }
    await replace(/Maximum file size/i, '75')
    await replace(/Structured file limit/i, '25')
    await replace(/Ignored directory names/i, '.git, vendor')
    await replace(/Include only extensions/i, '.txt, .min.js')
    await replace(/Excluded extensions/i, '.map')
    await replace(/Archive depth/i, '3')
    await replace(/Local AI timeout/i, '12.5')
    await replace(/File workers/i, '3')
    await replace(/Structured-document workers/i, '2')
    await replace(/Text chunk size/i, '128')
    await user.click(screen.getByRole('checkbox', { name: /Apply root-level/i }))
    await user.click(screen.getByRole('button', { name: /Scan this location/i }))
    await screen.findByRole('heading', { name: /Looking through your files/i })
    await waitFor(() => expect(client.subscribeToScanEvents).toHaveBeenCalled())

    expect(client.postScan).toHaveBeenCalledWith({
      paths: ['C:\\some\\path'],
      categories: ['personal_id'],
      user_targets: [
        { kind: 'literal', value: 'ACME-1234', category: 'custom' },
        { kind: 'description', value: 'employee payroll identifier', category: 'custom' },
      ],
      use_llm: true,
      ollama_model: 'qwen3-coder:30b',
      options: {
        max_file_size: 75_000_000,
        max_structured_file_size: 25_000_000,
        ignored_directories: ['.git', 'vendor'],
        included_extensions: ['.txt', '.min.js'],
        excluded_extensions: ['.map'],
        archive_depth: 3,
        ai_timeout_seconds: 12.5,
        max_workers: 3,
        document_workers: 2,
        chunk_size: 131_072,
        use_redactlensignore: false,
      },
    })

    await act(async () => disconnect?.())

    expect(client.getScan).toHaveBeenCalledTimes(1)
    expect(closeStream).toHaveBeenCalledTimes(1)
    expect(await screen.findByRole('heading', { name: 'RedactLens' })).toBeInTheDocument()
    expect(screen.getByRole('alert')).toHaveTextContent(
      'Its saved server-side session was cleared and any background work was asked to stop',
    )
    expect(screen.getByLabelText(/Folder or file to scan/i)).toHaveValue('C:\\some\\path')
    expect(await screen.findByRole('checkbox', { name: /Personal info/i })).toBeChecked()
    expect(screen.getByRole('checkbox', { name: /Financial/i })).not.toBeChecked()
    expect(screen.getByText('ACME-1234')).toBeInTheDocument()
    expect(screen.getByText('employee payroll identifier')).toBeInTheDocument()
    expect(screen.getByRole('switch', { name: /On-device AI/i })).toHaveAttribute(
      'aria-checked',
      'true',
    )

    await user.click(screen.getByText('Advanced scan options'))
    expect(screen.getByLabelText(/Maximum file size/i)).toHaveValue(75)
    expect(screen.getByLabelText(/Structured file limit/i)).toHaveValue(25)
    expect(screen.getByLabelText(/Ignored directory names/i)).toHaveValue('.git, vendor')
    expect(screen.getByLabelText(/Include only extensions/i)).toHaveValue('.txt, .min.js')
    expect(screen.getByLabelText(/Excluded extensions/i)).toHaveValue('.map')
    expect(screen.getByLabelText(/Archive depth/i)).toHaveValue(3)
    expect(screen.getByLabelText(/Local AI timeout/i)).toHaveValue(12.5)
    expect(screen.getByLabelText(/File workers/i)).toHaveValue(3)
    expect(screen.getByLabelText(/Structured-document workers/i)).toHaveValue(2)
    expect(screen.getByLabelText(/Text chunk size/i)).toHaveValue(128)
    expect(screen.getByRole('checkbox', { name: /Apply root-level/i })).not.toBeChecked()

    await act(async () => disconnect?.())
    expect(client.getScan).toHaveBeenCalledTimes(1)
  })

  it('clears a stale result toast when expiry resets the workflow', async () => {
    vi.mocked(client.postScan).mockResolvedValue(
      scanResult({
        state: 'complete',
        findings: [FINDING],
        scanned_files: [FINDING.file_path],
        progress: {
          ...PENDING_PROGRESS,
          stage: 'complete',
          completed_files: 1,
          total_files: 1,
          percent: 100,
          findings_so_far: 1,
        },
      }),
    )
    vi.mocked(client.postOpenFile).mockResolvedValue({ status: 'ok' })
    vi.mocked(client.putRemediationPlan).mockRejectedValue(
      Object.assign(new Error('This scan has expired.'), { code: 'scan_expired' }),
    )
    const user = userEvent.setup()
    render(<App />)

    await user.type(await screen.findByLabelText(/Folder or file to scan/i), 'C:\\some\\path')
    await user.click(screen.getByRole('button', { name: /Scan this location/i }))
    expect(await screen.findByRole('heading', { name: /Here.s what I found/ })).toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: /Show .*a\.txt in folder for/i }))
    expect(await screen.findByText(/Showed a\.txt in its folder/i)).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: /Include finding/i }))

    expect(await screen.findByRole('heading', { name: 'RedactLens' })).toBeInTheDocument()
    expect(screen.queryByText(/Showed a\.txt in its folder/i)).not.toBeInTheDocument()
    expect(screen.getByRole('alert')).toHaveTextContent(/saved server-side session was cleared/i)
  })

  it('fences old result requests after Start over and preserves the replacement scan', async () => {
    const oldResult = scanResult({
      state: 'complete',
      findings: [FINDING],
      scanned_files: [FINDING.file_path],
      progress: {
        ...PENDING_PROGRESS,
        stage: 'complete',
        completed_files: 1,
        total_files: 1,
        percent: 100,
        findings_so_far: 1,
      },
    })
    const newFinding = {
      ...FINDING,
      id: 'f2',
      file_path: 'C:\\new\\b.txt',
      redacted_preview: '98*******21',
    }
    const newResult = scanResult({
      scan_id: 'scan-2',
      state: 'complete',
      findings: [newFinding],
      scanned_files: [newFinding.file_path],
      progress: {
        ...PENDING_PROGRESS,
        stage: 'complete',
        completed_files: 1,
        total_files: 1,
        percent: 100,
        findings_so_far: 1,
      },
      metadata: {
        ...oldResult.metadata,
        selected_roots: ['C:\\new'],
      },
    })
    const revealSuccess = deferred<{ status: string }>()
    const revealExpiry = deferred<{ status: string }>()
    const reportRefresh = deferred<RemediationPlan>()
    vi.mocked(client.postScan).mockResolvedValueOnce(oldResult).mockResolvedValueOnce(newResult)
    vi.mocked(client.postOpenFile)
      .mockReturnValueOnce(revealSuccess.promise)
      .mockReturnValueOnce(revealExpiry.promise)
    vi.mocked(client.getRemediationPlan).mockReturnValueOnce(reportRefresh.promise)
    const createObjectURL = vi.fn<(blob: Blob) => string>().mockReturnValue('blob:old-report')
    const originalCreate = Object.getOwnPropertyDescriptor(URL, 'createObjectURL')
    const click = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {})
    Object.defineProperty(URL, 'createObjectURL', { configurable: true, value: createObjectURL })
    const user = userEvent.setup()

    try {
      render(<App />)
      await user.type(await screen.findByLabelText(/Folder or file to scan/i), 'C:\\old')
      await user.click(screen.getByRole('button', { name: /Scan this location/i }))
      expect(
        await screen.findByRole('heading', { name: /Here.s what I found/i }),
      ).toBeInTheDocument()

      const oldReveal = screen.getByRole('button', { name: /Show .*a\.txt in folder for/i })
      await user.click(oldReveal)
      await user.click(oldReveal)
      await user.click(screen.getByRole('button', { name: 'Export JSON' }))
      expect(client.postOpenFile).toHaveBeenCalledTimes(2)
      expect(client.getRemediationPlan).toHaveBeenCalledTimes(1)

      await user.click(screen.getByRole('button', { name: 'Scan something else' }))
      const target = await screen.findByLabelText(/Folder or file to scan/i)
      await user.clear(target)
      await user.type(target, 'C:\\new')
      await user.click(screen.getByRole('button', { name: /Scan this location/i }))
      expect(
        await screen.findByRole('button', { name: /Show .*b\.txt in folder for/i }),
      ).toBeInTheDocument()

      await act(async () => {
        revealSuccess.resolve({ status: 'ok' })
        revealExpiry.reject(Object.assign(new Error('Expired.'), { code: 'scan_expired' }))
        reportRefresh.resolve({
          plan_revision: 0,
          findings: [{ finding_id: FINDING.id, state: 'pending' }],
          files: [],
          selected_finding_count: 0,
          affected_file_count: 0,
          read_only_finding_count: 0,
          retained_artifact_paths: [],
          can_review: false,
          can_generate: false,
        })
        await Promise.resolve()
      })

      expect(
        screen.getByRole('button', { name: /Show .*b\.txt in folder for/i }),
      ).toBeInTheDocument()
      expect(screen.queryByRole('heading', { name: 'RedactLens' })).not.toBeInTheDocument()
      expect(screen.queryByText(/Showed a\.txt|Report saved/i)).not.toBeInTheDocument()
      expect(screen.queryByText(/saved server-side session was cleared/i)).not.toBeInTheDocument()
      expect(createObjectURL).not.toHaveBeenCalled()
      expect(click).not.toHaveBeenCalled()
      expect(client.deleteScan).toHaveBeenCalledTimes(1)
      expect(client.deleteScan).toHaveBeenCalledWith('scan-1')
      expect(client.deleteScan).not.toHaveBeenCalledWith('scan-2')
    } finally {
      click.mockRestore()
      if (originalCreate) Object.defineProperty(URL, 'createObjectURL', originalCreate)
      else Reflect.deleteProperty(URL, 'createObjectURL')
    }
  })

  it('preserves partial state and offers manual retry when snapshot recovery fails', async () => {
    vi.mocked(client.postScan).mockResolvedValue(scanResult())
    vi.mocked(client.getScan).mockRejectedValue(new Error('Could not recover this scan.'))
    const user = userEvent.setup()
    render(<App />)
    await startScan(user)

    await act(async () => disconnect?.())

    expect(closeStream).toHaveBeenCalledTimes(1)
    expect(await screen.findByRole('alert', {}, { timeout: 3000 })).toHaveTextContent(
      'Live scan updates are temporarily unavailable',
    )
    expect(screen.getByRole('heading', { name: /Looking through your files/i })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Retry live connection' })).toBeInTheDocument()
    expect(client.getScan).toHaveBeenCalledTimes(3)

    vi.mocked(client.getScan).mockResolvedValue(scanResult({ event_cursor: 2, state: 'scanning' }))
    await user.click(screen.getByRole('button', { name: 'Retry live connection' }))
    await waitFor(() => expect(client.subscribeToScanEvents).toHaveBeenCalledTimes(2))
    expect(
      screen.queryByText(/Live scan updates are temporarily unavailable/i),
    ).not.toBeInTheDocument()
  })

  it('labels timed-out partial findings as incomplete', async () => {
    vi.mocked(client.postScan).mockResolvedValue(scanResult())
    vi.mocked(client.getScan).mockResolvedValue(
      scanResult({
        event_cursor: 2,
        state: 'timed_out',
        findings: [FINDING],
        error: { code: 'scan_timed_out', message: 'Scan exceeded its time limit.' },
        progress: {
          ...PENDING_PROGRESS,
          stage: 'timed_out',
          completed_files: 1,
          total_files: 3,
          percent: 33.3,
          findings_so_far: 1,
        },
      }),
    )
    const user = userEvent.setup()
    render(<App />)
    await startScan(user)

    await act(async () => {
      receiveEvent?.(event({ sequence: 2, type: 'scan_failed', state: 'timed_out' }))
    })

    expect(
      await screen.findByRole('heading', { name: /Scan stopped before finishing/i }),
    ).toBeInTheDocument()
    expect(screen.getAllByText(/partial results/i).length).toBeGreaterThan(0)
    expect(
      screen.getByRole('heading', { name: /Findings so far — incomplete/i }),
    ).toBeInTheDocument()
  })

  it('keeps a zero-finding timed-out scan in the incomplete terminal view', async () => {
    vi.mocked(client.postScan).mockResolvedValue(scanResult())
    vi.mocked(client.getScan).mockResolvedValue(
      scanResult({
        event_cursor: 2,
        state: 'timed_out',
        findings: [],
        error: { code: 'scan_timed_out', message: 'Scan exceeded its time limit.' },
        progress: {
          ...PENDING_PROGRESS,
          stage: 'timed_out',
          completed_files: 0,
          total_files: 3,
          percent: 0,
          findings_so_far: 0,
        },
      }),
    )
    const user = userEvent.setup()
    render(<App />)
    await startScan(user)

    await act(async () => {
      receiveEvent?.(event({ sequence: 2, type: 'scan_failed', state: 'timed_out' }))
    })

    expect(
      await screen.findByRole('heading', { name: /Scan stopped before finishing/i }),
    ).toHaveFocus()
    expect(screen.getByRole('alert')).toHaveTextContent('Scan exceeded its time limit.')
    expect(screen.queryByRole('heading', { name: /Here’s what I found/i })).not.toBeInTheDocument()
    expect(screen.queryByText(/Nothing matched here/i)).not.toBeInTheDocument()
  })

  it('toggles and persists the theme', async () => {
    const user = userEvent.setup()
    render(<App />)
    expect(document.documentElement.dataset.theme).toBe('light')
    await user.click(screen.getByRole('button', { name: /Switch to dark theme/i }))
    expect(document.documentElement.dataset.theme).toBe('dark')
    expect(localStorage.getItem('redactlens-theme')).toBe('dark')
    await waitFor(() => expect(client.saveAppearanceTheme).toHaveBeenLastCalledWith('dark'))
    expect(document.documentElement).toHaveClass('theme-transition')
    await waitFor(() => expect(document.documentElement).not.toHaveClass('theme-transition'))
  })

  it('offers a persistent high contrast switch', async () => {
    const user = userEvent.setup()
    render(<App />)
    const highContrastSwitch = screen.getByRole('switch', { name: 'High contrast' })

    expect(highContrastSwitch).toHaveAttribute('aria-checked', 'false')
    expect(document.documentElement.dataset.contrast).toBeUndefined()

    await user.click(highContrastSwitch)
    expect(highContrastSwitch).toHaveAttribute('aria-checked', 'true')
    expect(document.documentElement.dataset.contrast).toBe('high')
    expect(localStorage.getItem('redactlens-high-contrast')).toBe('true')
    expect(document.documentElement).toHaveClass('theme-transition')

    await user.click(highContrastSwitch)
    expect(highContrastSwitch).toHaveAttribute('aria-checked', 'false')
    expect(document.documentElement.dataset.contrast).toBeUndefined()
    expect(localStorage.getItem('redactlens-high-contrast')).toBe('false')
    await waitFor(() => expect(document.documentElement).not.toHaveClass('theme-transition'))
  })

  it('offers visible zoom commands with persistent keyboard and wheel controls', async () => {
    const user = userEvent.setup()
    render(<App />)

    await screen.findByRole('heading', { name: 'RedactLens' })
    expect(screen.getByRole('group', { name: 'Page zoom' })).toBeInTheDocument()
    const zoomOut = screen.getByRole('button', { name: 'Zoom out' })
    const zoomIn = screen.getByRole('button', { name: 'Zoom in' })
    expect(zoomOut).toHaveAttribute('aria-keyshortcuts', 'Control+-')
    expect(zoomIn).toHaveAttribute('aria-keyshortcuts', 'Control++')
    expect(zoomOut).toBeEnabled()

    await user.click(zoomIn)
    expect(document.documentElement.dataset.zoom).toBe('125')
    expect(localStorage.getItem('redactlens-zoom')).toBe('125')

    fireEvent.keyDown(window, { key: '+', ctrlKey: true })
    expect(document.documentElement.dataset.zoom).toBe('150')
    fireEvent.keyDown(window, { key: '-', ctrlKey: true })
    expect(document.documentElement.dataset.zoom).toBe('125')
    fireEvent.wheel(window, { deltaY: -100, ctrlKey: true })
    expect(document.documentElement.dataset.zoom).toBe('150')

    fireEvent.keyDown(window, { key: '0', ctrlKey: true })
    expect(document.documentElement.dataset.zoom).toBe('100')
    expect(screen.getByRole('button', { name: /Reset zoom to 100%/i })).toBeDisabled()
  })

  it.each([
    [200, '2', '50%', '50svh'],
    [400, '4', '25%', '25svh'],
  ])(
    'restores %i%% zoom and its reflow viewport on every screen',
    async (savedZoom, scale, width, height) => {
      localStorage.setItem('redactlens-zoom', String(savedZoom))
      vi.mocked(client.postScan).mockResolvedValue(scanResult())
      vi.mocked(client.getScan).mockResolvedValue(
        scanResult({ event_cursor: 2, state: 'complete' }),
      )
      const user = userEvent.setup()
      render(<App />)

      const expectZoom = () => {
        expect(document.documentElement.dataset.zoom).toBe(String(savedZoom))
        expect(document.documentElement.style.getPropertyValue('--app-zoom')).toBe(scale)
        expect(document.documentElement.style.getPropertyValue('--app-layout-width')).toBe(width)
        expect(document.documentElement.style.getPropertyValue('--app-layout-height')).toBe(height)
        expect(localStorage.getItem('redactlens-zoom')).toBe(String(savedZoom))
      }

      expect(screen.getByRole('heading', { name: 'RedactLens' })).toBeInTheDocument()
      expectZoom()
      await startScan(user)
      expect(
        screen.getByRole('heading', { name: /Looking through your files/i }),
      ).toBeInTheDocument()
      expectZoom()

      await act(async () => {
        receiveEvent?.(
          event({
            sequence: 2,
            type: 'scan_completed',
            state: 'complete',
            progress: { ...PENDING_PROGRESS, stage: 'complete', percent: 100 },
          }),
        )
      })
      expect(
        await screen.findByRole('heading', { name: /Here.s what I found/i }),
      ).toBeInTheDocument()
      expectZoom()
    },
  )

  it('restores the saved high contrast preference', () => {
    localStorage.setItem('redactlens-high-contrast', 'true')
    render(<App />)

    expect(screen.getByRole('switch', { name: 'High contrast' })).toHaveAttribute(
      'aria-checked',
      'true',
    )
    expect(document.documentElement.dataset.contrast).toBe('high')
  })

  it('migrates appearance preferences saved under the former product name', () => {
    localStorage.setItem('redactscout-theme', 'dark')
    localStorage.setItem('redactscout-high-contrast', 'true')

    render(<App />)

    expect(document.documentElement.dataset.theme).toBe('dark')
    expect(document.documentElement.dataset.contrast).toBe('high')
    expect(localStorage.getItem('redactlens-theme')).toBe('dark')
    expect(localStorage.getItem('redactlens-high-contrast')).toBe('true')
  })
})
