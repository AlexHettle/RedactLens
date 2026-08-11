import type { Page, Route } from '@playwright/test'
import type {
  DetectorInfo,
  PublicFinding,
  PublicScanResult,
  RemediationPlan,
  ScanProgress,
} from '../src/types'

export type ScanMode = 'complete' | 'pending' | 'start-error'

const SCAN_ID = 'accessibility-scan'
const ROOT_PATH = 'C:\\demo'

const DETECTORS: DetectorInfo[] = [
  {
    id: 'password_assignment',
    category: 'credentials',
    description: 'Password assignment',
    risk_lesson: 'Exposed passwords can allow unauthorized access.',
  },
  {
    id: 'email',
    category: 'personal_id',
    description: 'Email address',
    risk_lesson: 'Email addresses can identify and contact a person.',
  },
  {
    id: 'credit_card',
    category: 'financial',
    description: 'Credit card number',
    risk_lesson: 'Payment card details can enable financial fraud.',
  },
]

export const FINDINGS: PublicFinding[] = [
  {
    id: 'finding-password',
    file_path: 'C:\\demo\\config.py',
    line: 4,
    column: 12,
    location: null,
    can_anonymize: true,
    redacted_preview: 'su********et',
    detector_id: 'password_assignment',
    category: 'credentials',
    confidence: 0.98,
    tier: 'A',
    explanation: 'A password assigned in source code.',
    risk_lesson: 'Anyone with file access may be able to reuse this password.',
    suggested_action: 'anonymize',
    supporting_detections: [],
  },
  {
    id: 'finding-email',
    file_path: 'C:\\demo\\contacts.txt',
    line: 2,
    column: 1,
    location: null,
    can_anonymize: true,
    redacted_preview: 'al*************om',
    detector_id: 'email',
    category: 'personal_id',
    confidence: 0.78,
    tier: 'B',
    explanation: 'An email address.',
    risk_lesson: 'It can identify and expose contact information for a person.',
    suggested_action: 'anonymize',
    supporting_detections: [],
  },
  {
    id: 'finding-card',
    file_path: 'C:\\demo\\statement.pdf',
    line: 1,
    column: 1,
    location: 'page 1',
    can_anonymize: false,
    redacted_preview: '41**********11',
    detector_id: 'credit_card',
    category: 'financial',
    confidence: 0.74,
    tier: 'B',
    explanation: 'A payment card number in a read-only document.',
    risk_lesson: 'Payment card details can be used for fraudulent purchases.',
    suggested_action: 'review',
    supporting_detections: [],
  },
]

const ACTIVE_PROGRESS: ScanProgress = {
  stage: 'detection',
  completed_files: 1,
  total_files: null,
  percent: 35,
  current_file: FINDINGS[0].file_path,
  findings_so_far: 1,
  skipped_files: 0,
}

const COMPLETE_PROGRESS: ScanProgress = {
  stage: 'complete',
  completed_files: 3,
  total_files: 3,
  percent: 100,
  current_file: null,
  findings_so_far: FINDINGS.length,
  skipped_files: 0,
}

function scanResult(state: 'scanning' | 'complete'): PublicScanResult {
  const complete = state === 'complete'
  return {
    scan_id: SCAN_ID,
    event_cursor: complete ? 4 : 1,
    created_at: '2026-08-11T12:00:00Z',
    expires_at: '2026-08-11T12:30:00Z',
    findings: complete ? FINDINGS : [FINDINGS[0]],
    summary: {},
    scanned_files: complete ? FINDINGS.map((finding) => finding.file_path) : [],
    skipped_files: [],
    llm_used: false,
    state,
    progress: complete ? COMPLETE_PROGRESS : ACTIVE_PROGRESS,
    error: null,
    metadata: {
      selected_roots: [ROOT_PATH],
      duration_ms: complete ? 84 : null,
      data_scanned_bytes: complete ? 4_096 : 1_024,
      detector_count: DETECTORS.length,
      ai_model: null,
    },
  }
}

function remediationPlan(
  includedFindingIds: string[] = [],
  ignoredFindingIds: string[] = [],
  revision = 1,
): RemediationPlan {
  const included = new Set(includedFindingIds)
  const ignored = new Set(ignoredFindingIds)
  const files = FINDINGS.filter((finding) => included.has(finding.id)).map((finding) => ({
    source_path: finding.file_path,
    output_path: finding.file_path.replace(/(\.[^.]+)$/, '-auto-redacted-copy$1'),
    included_finding_ids: [finding.id],
    output_state: 'not_created' as const,
  }))
  return {
    plan_revision: revision,
    findings: FINDINGS.map((finding) => ({
      finding_id: finding.id,
      state: !finding.can_anonymize
        ? ('read_only' as const)
        : included.has(finding.id)
          ? ('included' as const)
          : ignored.has(finding.id)
            ? ('ignored' as const)
            : ('pending' as const),
    })),
    files,
    selected_finding_count: included.size,
    affected_file_count: files.length,
    read_only_finding_count: FINDINGS.filter((finding) => !finding.can_anonymize).length,
    retained_artifact_paths: [],
    can_review: included.size > 0,
    can_generate: included.size > 0,
  }
}

function fulfillJson(route: Route, payload: unknown, status = 200) {
  return route.fulfill({
    status,
    contentType: 'application/json',
    body: JSON.stringify(payload),
  })
}

export async function installMockApi(page: Page, scanMode: ScanMode = 'complete') {
  let plan = remediationPlan()
  const activeResult = scanResult('scanning')
  const completedResult = scanResult('complete')

  await page.route('**/*', async (route) => {
    const request = route.request()
    const method = request.method()
    const pathname = new URL(request.url()).pathname

    if (method === 'GET' && pathname === '/launch-session') {
      return fulfillJson(route, { token: 'accessibility-test-token-with-at-least-32-characters' })
    }
    if (method === 'PUT' && pathname === '/appearance/theme') {
      return route.fulfill({ status: 204 })
    }
    if (method === 'GET' && pathname === '/health') {
      return fulfillJson(route, {
        status: 'ok',
        ollama_available: false,
        ollama_status: 'unavailable',
      })
    }
    if (method === 'GET' && pathname === '/detectors') {
      return fulfillJson(route, DETECTORS)
    }
    if (method === 'POST' && pathname === '/scans') {
      if (scanMode === 'start-error') {
        return fulfillJson(
          route,
          {
            error: { code: 'scan_failed', message: 'The accessibility test scan could not start.' },
          },
          500,
        )
      }
      return fulfillJson(route, scanMode === 'pending' ? activeResult : completedResult, 201)
    }
    if (method === 'GET' && pathname.endsWith('/events')) {
      return route.fulfill({
        status: 200,
        headers: {
          'Cache-Control': 'no-cache',
          'Content-Type': 'text/event-stream',
        },
        body: 'retry: 60000\n\n',
      })
    }
    if (method === 'GET' && pathname === '/scans/' + SCAN_ID) {
      return fulfillJson(route, scanMode === 'pending' ? activeResult : completedResult)
    }
    if (method === 'DELETE' && pathname === '/scans/' + SCAN_ID) {
      return route.fulfill({ status: 204 })
    }
    if (method === 'GET' && pathname === '/scans/' + SCAN_ID + '/remediation') {
      return fulfillJson(route, plan)
    }
    if (method === 'PUT' && pathname === '/scans/' + SCAN_ID + '/remediation') {
      const body = request.postDataJSON() as {
        included_finding_ids: string[]
        ignored_finding_ids: string[]
        plan_revision: number
      }
      plan = remediationPlan(
        body.included_finding_ids,
        body.ignored_finding_ids,
        body.plan_revision + 1,
      )
      return fulfillJson(route, plan)
    }
    if (method === 'POST' && pathname === '/scans/' + SCAN_ID + '/reveal-findings') {
      const body = request.postDataJSON() as { finding_ids: string[] }
      const values = new Map([
        ['finding-password', 'super-secret'],
        ['finding-email', 'alex@example.com'],
        ['finding-card', '4111111111111111'],
      ])
      return fulfillJson(route, {
        values: body.finding_ids.map((findingId) => ({
          finding_id: findingId,
          value: values.get(findingId) ?? 'revealed-value',
        })),
      })
    }
    if (
      method === 'POST' &&
      (pathname.endsWith('/open-file') || pathname.endsWith('/open-output'))
    ) {
      return fulfillJson(route, { status: 'ok' })
    }

    return route.continue()
  })
}
