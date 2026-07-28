import { describe, expect, it } from 'vitest'
import type {
  GeneratedOutputDetails,
  PublicFinding,
  PublicScanResult,
  RemediationPlan,
} from '../types'
import { buildHumanReport, buildJsonReport } from './reports'

function finding(overrides: Partial<PublicFinding> = {}): PublicFinding {
  return {
    id: 'finding-1',
    file_path: 'C:\\project\\src\\secrets.py',
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

function result(item: PublicFinding): PublicScanResult {
  return {
    scan_id: 'scan-1',
    event_cursor: 1,
    created_at: '2026-07-16T00:00:00Z',
    expires_at: '2026-07-16T00:15:00Z',
    findings: [item],
    summary: {},
    scanned_files: [item.file_path],
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
      duration_ms: 1200,
      data_scanned_bytes: 42,
      detector_count: 12,
      ai_model: null,
    },
  }
}

function plan(item: PublicFinding): RemediationPlan {
  return {
    plan_revision: 1,
    findings: [{ finding_id: item.id, state: 'included' }],
    files: [
      {
        source_path: item.file_path,
        output_path: item.file_path.replace(/(\.[^./\\]+)$/, '-auto-redacted-copy$1'),
        included_finding_ids: [item.id],
        output_state: 'current',
      },
    ],
    selected_finding_count: 1,
    affected_file_count: 1,
    read_only_finding_count: 0,
    retained_artifact_paths: [],
    can_review: true,
    can_generate: true,
  }
}

describe('privacy-safe reports', () => {
  it('does not claim there were no matches when no files were inspected', () => {
    const item = finding()
    const scan = result(item)
    scan.findings = []
    scan.scanned_files = []
    scan.progress.completed_files = 0
    scan.progress.total_files = 0
    scan.progress.findings_so_far = 0

    const human = buildHumanReport(scan, plan(item), [], () => 'pending')

    expect(human).toContain('No detection result is available because no files were inspected.')
    expect(human).not.toContain('No values matched the configured detectors.')
  })

  it('keeps the no-match message when readable files were actually inspected', () => {
    const item = finding()
    const scan = result(item)
    scan.findings = []
    scan.progress.findings_so_far = 0

    const human = buildHumanReport(scan, plan(item), [], () => 'pending')

    expect(human).toContain('No values matched the configured detectors.')
  })

  it('keeps an exact description-target match out of JSON and Markdown exports', () => {
    const rawValue = 'EMP-99213'
    const item = {
      ...finding({
        file_path: `C:\\project\\${rawValue}.txt`,
        location: `Workbook ${rawValue}!A1`,
        redacted_preview: 'EM*****13',
        detector_id: 'user_target_desc_0',
        category: 'custom',
        explanation: 'A local AI model matched this against a description you provided.',
        risk_lesson: 'This matched a user-defined description and may need careful review.',
        supporting_detections: [
          {
            detector_id: 'employee_id',
            description: 'A possible employee identifier.',
            confidence: 0.9,
            relationship: 'same_span',
          },
        ],
      }),
      // Reports explicitly project their public allowlist, so an accidentally
      // retained internal field must not cross the export boundary either.
      matched_text: rawValue,
    } as unknown as PublicFinding
    const scan = result(item)
    const remediation = plan(item)
    remediation.retained_artifact_paths = [
      `C:\\project\\.redactlens-recovery\\${rawValue}.txt.backup`,
    ]
    const outputs: GeneratedOutputDetails[] = [
      {
        source_path: item.file_path,
        output_path: item.file_path.replace(/(\.[^./\\]+)$/, '-auto-redacted-copy$1'),
        applied_finding_ids: [item.id],
        verification_status: 'verified',
        warnings: [`Removed ${rawValue} from the output.`],
        source_fingerprint: {
          resolved_path: item.file_path,
          size: 42,
          modified_ns: 1,
          sha256: 'a'.repeat(64),
        },
        rescan_status: 'completed',
        remaining_finding_count: 0,
        remaining_tier_a_count: 0,
      },
    ]

    const json = buildJsonReport(scan, remediation, outputs, () => 'included')
    const human = buildHumanReport(scan, remediation, outputs, () => 'included')

    expect(JSON.stringify(json)).not.toContain(rawValue)
    expect(human).not.toContain(rawValue)
    expect(json.findings[0].file_path).toContain('<redacted-value-1>')
    expect(json.findings[0].location).toContain('<redacted-value-1>')
    expect(json.outputs[0].output_path).toContain('<redacted-value-1>')
    expect(json.findings[0].explanation).toBe(
      'A local AI model matched this against a description you provided.',
    )
  })

  it('redacts selected roots embedded in public location metadata', () => {
    const item = finding({
      location: "attachment 'C:\\project\\private\\payload.txt'",
    })

    const report = buildJsonReport(result(item), plan(item), [], () => 'included')

    expect(report.findings[0].location).toContain('<scan root>')
    expect(report.findings[0].location).not.toContain('C:\\project')
  })

  it("scrubs one finding's raw value from every other exported finding", () => {
    const rawValue = 'SECOND-SECRET'
    const first = finding({
      id: 'finding-1',
      location: `Workbook ${rawValue}!A1`,
      explanation: `The workbook label contains ${rawValue}.`,
    })
    const second = {
      ...finding({
        id: 'finding-2',
        file_path: 'C:\\project\\src\\other.txt',
        redacted_preview: 'SE*******ET',
      }),
      matched_text: rawValue,
    } as unknown as PublicFinding
    const scan = result(first)
    scan.findings = [first, second]
    scan.scanned_files.push(second.file_path)

    const json = buildJsonReport(scan, plan(first), [], () => 'pending')
    const human = buildHumanReport(scan, plan(first), [], () => 'pending')

    expect(JSON.stringify(json)).not.toContain(rawValue)
    expect(human).not.toContain(rawValue)
    expect(json.findings[0].location).toContain('<redacted-value-1>')
    expect(json.findings[0].explanation).toContain('<redacted-value-1>')
  })

  it('never reuses a raw value that collides with the default report marker', () => {
    const rawValue = '<redacted-value-1>'
    const item = {
      ...finding({
        file_path: `C:\\project\\${rawValue}.txt`,
        location: `Sheet ${rawValue}!A1`,
      }),
      matched_text: rawValue,
    } as unknown as PublicFinding

    const json = buildJsonReport(result(item), plan(item), [], () => 'included')
    const human = buildHumanReport(result(item), plan(item), [], () => 'included')

    expect(JSON.stringify(json)).not.toContain(rawValue)
    expect(human).not.toContain(rawValue)
    expect(json.findings[0].file_path).toContain('⟦sensitive-1⟧')
  })

  it('exports retained recovery artifacts through the relative-path projection', () => {
    const item = finding()
    const remediation = plan(item)
    const retainedPath = 'C:\\project\\.redactlens-recovery\\secrets.py.backup'
    remediation.retained_artifact_paths = [retainedPath]

    const json = buildJsonReport(result(item), remediation, [], () => 'included')
    const human = buildHumanReport(result(item), remediation, [], () => 'included')

    expect(json.remediation.retained_artifact_paths).toEqual([
      '.redactlens-recovery/secrets.py.backup',
    ])
    expect(JSON.stringify(json)).not.toContain('C:\\project')
    expect(human).toContain('Manual cleanup required')
    expect(human).toContain('secrets.py.backup')
    expect(human).toContain('delete them manually')
    expect(human).not.toContain('C:\\project')
  })

  it('renders every dynamic Markdown value as inert single-line text', () => {
    const attack = 'value\n# forged\u0000<script>alert(1)</script> `tick` [link](https://evil)'
    const item = finding({
      id: attack,
      file_path: `C:\\project\\${attack}.txt`,
      location: attack,
      redacted_preview: attack,
      detector_id: attack,
      risk_lesson: attack,
    })
    const scan = result(item)
    scan.metadata.ai_model = attack
    scan.skipped_files = [
      {
        path: `C:\\project\\${attack}.bin`,
        reason: attack,
        code: 'unreadable_file',
        stage: 'extraction',
        rule: attack,
      },
    ]
    const remediation = plan(item)
    const outputs: GeneratedOutputDetails[] = [
      {
        source_path: item.file_path,
        output_path: item.file_path.replace(/(\.[^./\\]+)$/, '-auto-redacted-copy$1'),
        applied_finding_ids: [attack],
        verification_status: 'verified',
        warnings: [attack],
        source_fingerprint: {
          resolved_path: item.file_path,
          size: 42,
          modified_ns: 1,
          sha256: attack,
        },
        rescan_status: 'completed',
        remaining_finding_count: 0,
        remaining_tier_a_count: 0,
      },
    ]

    const human = buildHumanReport(scan, remediation, outputs, () => 'included', attack)

    expect(human).toContain('Configured detectors: 12')
    expect(human).toContain('&lt;script&gt;alert&#40;1&#41;&lt;/script&gt;')
    expect(human).toContain('&#96;tick&#96;')
    expect(human).toContain('&#91;link&#93;&#40;https://evil&#41;')
    expect(human).not.toContain('<script>')
    expect(human).not.toContain('`tick`')
    expect(human).not.toContain('[link](https://evil)')
    expect(human).not.toContain('\u0000')
    expect(human).not.toMatch(/^# forged/gm)
  })
})
