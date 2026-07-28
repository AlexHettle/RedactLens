import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

const TOKEN_ONE = 'one-'.padEnd(43, 'a')
const TOKEN_TWO = 'two-'.padEnd(43, 'b')

const VALID_PROGRESS = {
  stage: 'detection',
  completed_files: 1,
  total_files: 3,
  percent: 33.3,
  current_file: 'C:\\project\\example.txt',
  findings_so_far: 1,
  skipped_files: 0,
}

const VALID_FINDING = {
  id: 'finding-1',
  file_path: 'C:\\project\\example.txt',
  line: 2,
  column: 4,
  location: null,
  can_anonymize: true,
  redacted_preview: 'se*****',
  detector_id: 'credential',
  category: 'credential',
  confidence: 0.92,
  tier: 'A',
  explanation: 'A credential-like value.',
  risk_lesson: 'Credentials can grant access.',
  suggested_action: 'anonymize',
  supporting_detections: [
    {
      detector_id: 'entropy',
      description: 'High-entropy text.',
      confidence: 0.81,
      relationship: 'same_span',
    },
  ],
}

function validEvent(overrides: Record<string, unknown> = {}) {
  return {
    sequence: 18,
    type: 'scan_finalizing',
    emitted_at: '2026-07-18T12:00:00Z',
    scan_id: 'scan/1',
    state: 'scanning',
    progress: VALID_PROGRESS,
    finding: null,
    skipped_file: null,
    error: null,
    ...overrides,
  }
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    statusText: status >= 400 ? 'Request failed' : 'OK',
    headers: { 'Content-Type': 'application/json' },
  })
}

beforeEach(() => {
  vi.resetModules()
})

afterEach(() => {
  vi.unstubAllGlobals()
})

describe('API launch authorization', () => {
  it('gives installed-app recovery guidance when the local service is unreachable', async () => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new TypeError('network error')))
    const client = await import('./client')

    await expect(client.getHealth()).rejects.toThrow(
      'Could not reach RedactLens. Close and reopen the app, then try again.',
    )
  })

  it('fetches one launch token and sends it only in mutation headers', async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(jsonResponse({ token: TOKEN_ONE }))
      .mockResolvedValueOnce(jsonResponse({ scan_id: 'scan-1' }, 201))
      .mockResolvedValueOnce(jsonResponse({ path: 'C:\\project' }))
    vi.stubGlobal('fetch', fetchMock)
    const client = await import('./client')

    await client.postScan({
      paths: ['C:\\project'],
      categories: [],
      user_targets: [],
      use_llm: false,
    })
    await client.pickPath('folder')

    expect(fetchMock).toHaveBeenCalledTimes(3)
    expect(String(fetchMock.mock.calls[0][0])).toMatch(/\/launch-session$/)
    for (const call of fetchMock.mock.calls.slice(1)) {
      const options = call[1] as RequestInit
      expect(options.method).toBe('POST')
      expect(new Headers(options.headers).get('X-RedactLens-Token')).toBe(TOKEN_ONE)
    }
    expect(String(fetchMock.mock.calls[2][0])).toContain('/pick-path?kind=folder')
  })

  it('refreshes a stale launch token once after the backend restarts', async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(jsonResponse({ token: TOKEN_ONE }))
      .mockResolvedValueOnce(
        jsonResponse(
          {
            error: {
              code: 'invalid_launch_token',
              message: 'Reload RedactLens to establish a valid local session.',
            },
          },
          403,
        ),
      )
      .mockResolvedValueOnce(jsonResponse({ token: TOKEN_TWO }))
      .mockResolvedValueOnce(jsonResponse({ scan_id: 'scan-2' }, 201))
    vi.stubGlobal('fetch', fetchMock)
    const client = await import('./client')

    await client.postScan({
      paths: ['C:\\project'],
      categories: [],
      user_targets: [],
      use_llm: false,
    })

    expect(fetchMock).toHaveBeenCalledTimes(4)
    expect(
      new Headers((fetchMock.mock.calls[1][1] as RequestInit).headers).get('X-RedactLens-Token'),
    ).toBe(TOKEN_ONE)
    expect(
      new Headers((fetchMock.mock.calls[3][1] as RequestInit).headers).get('X-RedactLens-Token'),
    ).toBe(TOKEN_TWO)
  })

  it('turns scan validation field paths into plain-language recovery guidance', async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(jsonResponse({ token: TOKEN_ONE }))
      .mockResolvedValueOnce(
        jsonResponse(
          {
            error: {
              code: 'invalid_request',
              message: 'The request is invalid. Check: options.included_extensions.',
            },
          },
          422,
        ),
      )
    vi.stubGlobal('fetch', fetchMock)
    const client = await import('./client')

    await expect(
      client.postScan({
        paths: ['C:\\project'],
        categories: [],
        user_targets: [],
        use_llm: false,
      }),
    ).rejects.toMatchObject({
      message:
        'Some scan settings are invalid. Review the scan location, custom targets, and advanced options, then try again.',
      status: 422,
      code: 'invalid_request',
    })
  })

  it('sends the server-issued plan revision with plan updates and generation', async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(jsonResponse({ token: TOKEN_ONE }))
      .mockResolvedValueOnce(jsonResponse({ plan_revision: 8 }))
      .mockResolvedValueOnce(jsonResponse({ plan: { plan_revision: 8 }, outputs: [] }))
    vi.stubGlobal('fetch', fetchMock)
    const client = await import('./client')

    await client.putRemediationPlan('scan/1', ['f1'], ['f2'], 7)
    await client.postGenerateRemediation('scan/1', 8)

    expect(String(fetchMock.mock.calls[1][0])).toContain('/scans/scan%2F1/remediation')
    expect(JSON.parse(String((fetchMock.mock.calls[1][1] as RequestInit).body))).toEqual({
      included_finding_ids: ['f1'],
      ignored_finding_ids: ['f2'],
      plan_revision: 7,
    })
    expect(String(fetchMock.mock.calls[2][0])).toContain('/scans/scan%2F1/remediation/generate')
    expect(JSON.parse(String((fetchMock.mock.calls[2][1] as RequestInit).body))).toEqual({
      plan_revision: 8,
      output_mode: 'copy',
    })
  })

  it('requests exact finding values with an authenticated body instead of URL data', async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(jsonResponse({ token: TOKEN_ONE }))
      .mockResolvedValueOnce(
        jsonResponse({ values: [{ finding_id: 'finding-1', value: '123-45-6789' }] }),
      )
    vi.stubGlobal('fetch', fetchMock)
    const client = await import('./client')

    await client.postRevealFindingValues('scan/1', ['finding-1'])

    const requestUrl = String(fetchMock.mock.calls[1][0])
    const request = fetchMock.mock.calls[1][1] as RequestInit
    expect(requestUrl).toContain('/scans/scan%2F1/reveal-findings')
    expect(requestUrl).not.toContain('finding-1')
    expect(request.method).toBe('POST')
    expect(new Headers(request.headers).get('X-RedactLens-Token')).toBe(TOKEN_ONE)
    expect(JSON.parse(String(request.body))).toEqual({ finding_ids: ['finding-1'] })
  })
})

describe('scan event transport', () => {
  it('starts after the authoritative cursor, validates events, reports corruption, and closes', async () => {
    const instances: FakeEventSource[] = []
    class FakeEventSource {
      readonly url: string
      onmessage: ((event: MessageEvent<string>) => void) | null = null
      onerror: (() => void) | null = null
      close = vi.fn()

      constructor(url: string | URL) {
        this.url = String(url)
        instances.push(this)
      }
    }
    vi.stubGlobal('EventSource', FakeEventSource)
    const client = await import('./client')
    const onEvent = vi.fn()
    const onDisconnect = vi.fn()

    const close = client.subscribeToScanEvents('scan/1', 17, onEvent, onDisconnect)
    const source = instances[0]
    expect(source.url).toContain('/scans/scan%2F1/events?after=17')

    const finalizing = validEvent()
    source.onmessage?.(new MessageEvent('message', { data: JSON.stringify(finalizing) }))
    expect(onEvent).toHaveBeenCalledWith(finalizing)

    const findingAdded = validEvent({
      sequence: 19,
      type: 'finding_added',
      finding: VALID_FINDING,
    })
    source.onmessage?.(new MessageEvent('message', { data: JSON.stringify(findingAdded) }))
    expect(onEvent).toHaveBeenLastCalledWith(findingAdded)

    source.onmessage?.(
      new MessageEvent('message', {
        data: JSON.stringify(validEvent({ progress: { ...VALID_PROGRESS, percent: '33.3' } })),
      }),
    )
    source.onmessage?.(
      new MessageEvent('message', {
        data: JSON.stringify(
          validEvent({
            type: 'finding_added',
            finding: {
              ...VALID_FINDING,
              supporting_detections: [
                { ...VALID_FINDING.supporting_detections[0], relationship: 'untrusted' },
              ],
            },
          }),
        ),
      }),
    )
    expect(onEvent).toHaveBeenCalledTimes(2)

    source.onmessage?.(new MessageEvent('message', { data: '{not-json' }))
    source.onerror?.()
    expect(onDisconnect).toHaveBeenCalledTimes(4)

    close()
    expect(source.close).toHaveBeenCalledTimes(1)
  })
})
