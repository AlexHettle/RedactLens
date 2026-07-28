import type {
  DetectorInfo,
  RemediationGenerationResponse,
  RemediationOutputMode,
  RemediationPlan,
  HealthResponse,
  PublicScanResult,
  RevealFindingsResponse,
  ScanEvent,
  ScanRequest,
} from '../types'
import { isScanEvent } from './scanEvent'

// In dev the UI runs on Vite (:5173) and the API on :8000, so the base must
// be absolute. Production builds are served BY the API process itself (see
// redactlens_api.main), so relative same-origin URLs are correct on any port.
const API_BASE =
  import.meta.env.VITE_API_BASE_URL ?? (import.meta.env.DEV ? 'http://127.0.0.1:8000' : '')
const AUTH_HEADER = 'X-RedactLens-Token'
const MUTATING_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE'])

let launchToken: string | null = null
let launchTokenPromise: Promise<string> | null = null

export class ApiError extends Error {
  readonly status: number
  readonly code?: string

  constructor(message: string, status: number, code?: string) {
    super(message)
    this.name = 'ApiError'
    this.status = status
    this.code = code
  }
}

async function responseError(response: Response): Promise<ApiError> {
  const body = await response.text()
  try {
    const parsed = JSON.parse(body) as {
      error?: { code?: string; message?: string }
    }
    return new ApiError(
      parsed.error?.message ?? response.statusText,
      response.status,
      parsed.error?.code,
    )
  } catch {
    return new ApiError(response.statusText || 'RedactLens rejected the request.', response.status)
  }
}

async function getLaunchToken(): Promise<string> {
  if (launchToken) return launchToken
  if (!launchTokenPromise) {
    launchTokenPromise = fetch(`${API_BASE}/launch-session`, {
      cache: 'no-store',
      headers: { Accept: 'application/json' },
    })
      .then(async (response) => {
        if (!response.ok) throw await responseError(response)
        const body = (await response.json()) as { token?: unknown }
        if (typeof body.token !== 'string' || body.token.length < 32) {
          throw new Error('RedactLens returned an invalid local session.')
        }
        launchToken = body.token
        return body.token
      })
      .finally(() => {
        launchTokenPromise = null
      })
  }
  return launchTokenPromise
}

function clearLaunchToken() {
  launchToken = null
  launchTokenPromise = null
}

async function request<T>(
  path: string,
  options: RequestInit = {},
  retryAuthorization = true,
): Promise<T> {
  const method = (options.method ?? 'GET').toUpperCase()
  const headers = new Headers(options.headers)
  if (options.body !== undefined) headers.set('Content-Type', 'application/json')
  if (MUTATING_METHODS.has(method)) headers.set(AUTH_HEADER, await getLaunchToken())

  let response: Response
  try {
    response = await fetch(`${API_BASE}${path}`, { ...options, headers })
  } catch {
    throw new Error('Could not reach RedactLens. Close and reopen the app, then try again.')
  }
  if (!response.ok) {
    const error = await responseError(response)
    if (
      retryAuthorization &&
      MUTATING_METHODS.has(method) &&
      error.code === 'invalid_launch_token'
    ) {
      clearLaunchToken()
      return request<T>(path, options, false)
    }
    throw error
  }
  if (response.status === 204) return undefined as T
  return response.json() as Promise<T>
}

export function getHealth(): Promise<HealthResponse> {
  return request<HealthResponse>('/health')
}

export function getDetectors(): Promise<DetectorInfo[]> {
  return request<DetectorInfo[]>('/detectors')
}

export function saveAppearanceTheme(theme: 'light' | 'dark'): Promise<void> {
  return request<void>('/appearance/theme', {
    method: 'PUT',
    body: JSON.stringify({ theme }),
    keepalive: true,
  })
}

/** Opens a native OS folder/file picker on this machine (the backend runs
 * locally) and resolves with the chosen absolute path, or '' if cancelled. */
export function pickPath(kind: 'folder' | 'file'): Promise<{ path: string }> {
  return request<{ path: string }>(`/pick-path?kind=${kind}`, { method: 'POST' })
}

/** Reveals the file in the local file manager without launching its content. */
export function postOpenFile(scanId: string, findingId: string): Promise<{ status: string }> {
  return request<{ status: string }>(`/scans/${encodeURIComponent(scanId)}/open-file`, {
    method: 'POST',
    body: JSON.stringify({ finding_id: findingId }),
  })
}

export async function postScan(body: ScanRequest): Promise<PublicScanResult> {
  try {
    return await request<PublicScanResult>('/scans', {
      method: 'POST',
      body: JSON.stringify(body),
    })
  } catch (error) {
    if (error instanceof ApiError && error.code === 'invalid_request') {
      throw new ApiError(
        'Some scan settings are invalid. Review the scan location, custom targets, and advanced options, then try again.',
        error.status,
        error.code,
      )
    }
    throw error
  }
}

export function getScan(scanId: string, signal?: AbortSignal): Promise<PublicScanResult> {
  return request<PublicScanResult>(`/scans/${encodeURIComponent(scanId)}`, { signal })
}

export function subscribeToScanEvents(
  scanId: string,
  afterSequence: number,
  onEvent: (event: ScanEvent) => void,
  onDisconnect: () => void,
): () => void {
  const source = new EventSource(
    `${API_BASE}/scans/${encodeURIComponent(scanId)}/events?after=${encodeURIComponent(afterSequence)}`,
  )
  source.onmessage = (message) => {
    try {
      const event: unknown = JSON.parse(message.data)
      if (!isScanEvent(event)) {
        onDisconnect()
        return
      }
      onEvent(event)
    } catch {
      onDisconnect()
    }
  }
  source.onerror = () => onDisconnect()
  return () => source.close()
}

export function getRemediationPlan(scanId: string): Promise<RemediationPlan> {
  return request<RemediationPlan>(`/scans/${encodeURIComponent(scanId)}/remediation`)
}

export function postRevealFindingValues(
  scanId: string,
  findingIds: string[],
): Promise<RevealFindingsResponse> {
  return request<RevealFindingsResponse>(`/scans/${encodeURIComponent(scanId)}/reveal-findings`, {
    method: 'POST',
    body: JSON.stringify({ finding_ids: findingIds }),
  })
}

export function putRemediationPlan(
  scanId: string,
  includedFindingIds: string[],
  ignoredFindingIds: string[],
  planRevision: number,
): Promise<RemediationPlan> {
  return request<RemediationPlan>(`/scans/${encodeURIComponent(scanId)}/remediation`, {
    method: 'PUT',
    body: JSON.stringify({
      included_finding_ids: includedFindingIds,
      ignored_finding_ids: ignoredFindingIds,
      plan_revision: planRevision,
    }),
  })
}

export function postGenerateRemediation(
  scanId: string,
  planRevision: number,
  outputMode: RemediationOutputMode = 'copy',
): Promise<RemediationGenerationResponse> {
  return request<RemediationGenerationResponse>(
    `/scans/${encodeURIComponent(scanId)}/remediation/generate`,
    {
      method: 'POST',
      body: JSON.stringify({ plan_revision: planRevision, output_mode: outputMode }),
    },
  )
}

export function postOpenOutput(scanId: string, findingId: string): Promise<{ status: string }> {
  return request<{ status: string }>(`/scans/${encodeURIComponent(scanId)}/open-output`, {
    method: 'POST',
    body: JSON.stringify({ finding_id: findingId }),
  })
}

export function deleteScan(scanId: string, signal?: AbortSignal): Promise<void> {
  return request<void>(`/scans/${encodeURIComponent(scanId)}`, { method: 'DELETE', signal })
}
