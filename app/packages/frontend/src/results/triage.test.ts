import { describe, expect, it } from 'vitest'
import type {
  GeneratedOutputDetails,
  PublicFinding,
  PublicScanResult,
  RemediationPlan,
} from '../types'
import { buildHumanReport, buildJsonReport } from './reports'
import {
  buildFileOptions,
  detectorName,
  displayRedactedPreview,
  EMPTY_FILTERS,
  fileIdentity,
  filterFindings,
  formatDuration,
  groupFindings,
  groupSkippedFiles,
  relativePath,
  sortFindings,
} from './triage'

function finding(overrides: Partial<PublicFinding> = {}): PublicFinding {
  return {
    id: 'f1',
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

function result(findings: PublicFinding[]): PublicScanResult {
  return {
    scan_id: 'scan-1',
    event_cursor: 1,
    created_at: '2026-07-16T00:00:00Z',
    expires_at: '2026-07-16T00:15:00Z',
    findings,
    summary: {},
    scanned_files: ['C:\\project\\src\\secrets.py'],
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
      duration_ms: 1200,
      data_scanned_bytes: 42,
      detector_count: 12,
      ai_model: null,
    },
  }
}

const plan: RemediationPlan = {
  plan_revision: 0,
  findings: [{ finding_id: 'f1', state: 'pending' }],
  files: [],
  selected_finding_count: 0,
  affected_file_count: 0,
  read_only_finding_count: 0,
  retained_artifact_paths: [],
  can_review: false,
  can_generate: false,
}

describe('result triage utilities', () => {
  it('gives generated user-target detector IDs readable labels', () => {
    const targets = [
      { kind: 'literal' as const, value: 'ACME-1234-XYZ', category: 'custom' },
      { kind: 'description' as const, value: 'all employee names', category: 'custom' },
    ]

    expect(detectorName('user_target_0', targets)).toBe(
      'Found with your custom rule "ACME-1234-XYZ"',
    )
    expect(detectorName('user_target_desc_0', targets)).toBe(
      'Found with your custom rule "all employee names"',
    )
    expect(detectorName('user_target_0')).toBe('Found with your custom exact-value rule')
    expect(detectorName('user_target_desc_0')).toBe('Found with your custom description rule')
  })

  it('renders privacy fallback markers as ordinary mask characters', () => {
    expect(displayRedactedPreview('sc<redacted><redacted>29')).toBe('sc**29')
    expect(displayRedactedPreview('ab\u27e6sensitive value\u27e7cd')).toBe('ab*cd')
  })

  it('carries rounded duration seconds into minutes at the boundary', () => {
    expect(formatDuration(null)).toBe('Not recorded')
    expect(formatDuration(999)).toBe('999 ms')
    expect(formatDuration(59_949)).toBe('59.9 s')
    expect(formatDuration(59_950)).toBe('1m 0s')
    expect(formatDuration(119_999)).toBe('2m 0s')
  })

  it('shows paths relative to Windows drive and UNC scan roots', () => {
    expect(relativePath('C:\\project\\src\\secrets.py', ['C:\\project'])).toBe('src/secrets.py')
    expect(relativePath('C:\\src\\app.ts', ['C:\\'])).toBe('src/app.ts')
    expect(relativePath('c:\\PROJECT\\src\\app.ts', ['C:\\project'])).toBe('src/app.ts')
    expect(relativePath('\\\\server\\share\\ROOT\\src\\app.ts', ['\\\\SERVER\\SHARE\\root'])).toBe(
      'src/app.ts',
    )
    expect(fileIdentity('C:\\Project\\src\\app.ts')).toBe(fileIdentity('c:\\project\\SRC\\APP.TS'))
    expect(fileIdentity('\\\\SERVER\\Share\\Root\\app.ts')).toBe(
      fileIdentity('\\\\server\\share\\root\\APP.TS'),
    )
  })

  it('keeps duplicate relative file names independently filterable and grouped', () => {
    const roots = ['C:\\client-one', '\\\\SERVER\\Share\\client-two']
    const findings = [
      finding({ id: 'drive', file_path: 'c:\\CLIENT-ONE\\src\\same.py' }),
      finding({ id: 'unc', file_path: '\\\\server\\share\\CLIENT-TWO\\src\\same.py' }),
    ]
    const options = buildFileOptions(
      findings.map((item) => item.file_path),
      roots,
    )

    expect(options).toEqual([
      {
        value: fileIdentity('c:\\CLIENT-ONE\\src\\same.py'),
        label: 'Scan root 1: src/same.py',
      },
      {
        value: fileIdentity('\\\\server\\share\\CLIENT-TWO\\src\\same.py'),
        label: 'Scan root 2: src/same.py',
      },
    ])
    expect(options.map((option) => option.label).join(' ')).not.toMatch(/client-one|client-two/i)
    expect(
      filterFindings(findings, { ...EMPTY_FILTERS, file: options[1].value }, () => 'pending').map(
        (item) => item.id,
      ),
    ).toEqual(['unc'])
    expect(groupFindings(findings, 'file', roots, options).map((group) => group.title)).toEqual([
      'Scan root 1: src/same.py',
      'Scan root 2: src/same.py',
    ])
  })

  it('keeps duplicate root-relative paths distinct in both report formats', () => {
    const roots = ['C:\\client-one', 'C:\\client-two']
    const findings = [
      finding({ id: 'first', file_path: 'C:\\client-one\\src\\same.py' }),
      finding({ id: 'second', file_path: 'C:\\client-two\\src\\same.py' }),
    ]
    const scan = {
      ...result(findings),
      scanned_files: findings.map((item) => item.file_path),
      metadata: { ...result(findings).metadata, selected_roots: roots },
    }

    const json = buildJsonReport(scan, plan, [], () => 'pending')
    const human = buildHumanReport(scan, plan, [], () => 'pending')

    expect(json.scanned_files).toEqual(['Scan root 1: src/same.py', 'Scan root 2: src/same.py'])
    expect(json.findings.map((item) => item.file_path)).toEqual([
      'Scan root 1: src/same.py',
      'Scan root 2: src/same.py',
    ])
    expect(human).toContain('Scan root 1: src/same.py')
    expect(human).toContain('Scan root 2: src/same.py')
    expect(human).not.toMatch(/client-one|client-two/i)
  })

  it('sorts deterministically by tier, confidence, path, and position', () => {
    const findings = [
      finding({ id: 'b', tier: 'B', confidence: 0.99 }),
      finding({ id: 'a2', confidence: 0.8, file_path: 'C:\\project\\z.py' }),
      finding({ id: 'a1', confidence: 0.8, file_path: 'C:\\project\\a.py', line: 10 }),
      finding({ id: 'a0', confidence: 0.8, file_path: 'C:\\project\\a.py', line: 2 }),
      finding({ id: 'top', confidence: 0.99 }),
    ]

    expect(sortFindings(findings).map((item) => item.id)).toEqual(['top', 'a0', 'a1', 'a2', 'b'])
  })

  it('filters and groups one authoritative finding collection', () => {
    const findings = [
      finding(),
      finding({ id: 'f2', tier: 'B', category: 'credential', detector_id: 'password_assignment' }),
    ]
    const filtered = filterFindings(findings, { ...EMPTY_FILTERS, tier: 'B' }, () => 'pending')

    expect(filtered.map((item) => item.id)).toEqual(['f2'])
    expect(
      groupFindings(findings, 'category', ['C:\\project']).map((group) => group.title),
    ).toEqual(['Credentials', 'Personal identifiers'])
  })

  it('groups skips with actionable remediation guidance', () => {
    const groups = groupSkippedFiles([
      {
        path: 'large.bin',
        reason: 'file exceeds max scan size (9 > 5 bytes)',
        code: 'file_too_large',
        stage: 'extraction',
        rule: null,
      },
      {
        path: 'backup.zip',
        reason: 'archive — unpack it and scan the extracted folder instead',
        code: 'archive',
        stage: 'extraction',
        rule: null,
      },
      {
        path: 'linked',
        reason: 'symbolic link skipped — scan the real target explicitly',
        code: 'symbolic_link',
        stage: 'extraction',
        rule: null,
      },
      {
        path: 'junction',
        reason: 'filesystem redirect skipped',
        code: 'filesystem_redirect',
        stage: 'discovery',
        rule: null,
      },
      {
        path: 'named-pipe',
        reason: 'non-regular filesystem entry skipped',
        code: 'non_regular_file',
        stage: 'discovery',
        rule: null,
      },
    ])

    expect(groups.map((group) => group.title)).toEqual([
      'Archives',
      'Filesystem redirects',
      'Special filesystem entries',
      'Symbolic links',
      'Too large',
    ])
    expect(groups.every((group) => group.advice.length > 10)).toBe(true)
  })

  it('classifies unsupported encodings as unreadable text before generic unsupported formats', () => {
    const groups = groupSkippedFiles([
      {
        path: 'legacy.txt',
        reason: 'unsupported encoding cp500; text could not be decoded',
        code: 'extraction_failed',
        stage: 'extraction',
        rule: null,
      },
    ])

    expect(groups).toHaveLength(1)
    expect(groups[0].title).toBe('Unreadable text')
    expect(groups[0].advice).toMatch(/plain-text encoding/i)
  })

  it('exports only allowlisted public fields and relative paths', () => {
    const malformed = {
      ...finding(),
      matched_text: '123-45-6789',
      start_offset: 4,
      evidence: { context: 'raw context' },
      supporting_detections: [
        {
          detector_id: 'high_entropy',
          description: 'Entropy signal',
          confidence: 0.8,
          relationship: 'same_span',
          matched_text: 'nested raw match',
        },
      ],
    } as unknown as PublicFinding
    const scan = result([malformed])
    const malformedPlan = {
      ...plan,
      findings: [{ finding_id: 'f1', state: 'pending', matched_text: 'plan raw match' }],
      files: [
        {
          source_path: 'C:\\project\\src\\secrets.py',
          output_path: 'C:\\project\\src\\secrets-auto-redacted-copy.py',
          included_finding_ids: ['f1'],
          output_state: 'not_created',
          evidence: 'plan raw context',
        },
      ],
    } as unknown as RemediationPlan
    const malformedOutputs = [
      {
        source_path: 'C:\\project\\src\\secrets.py',
        output_path: 'C:\\project\\src\\secrets-auto-redacted-copy.py',
        applied_finding_ids: ['f1'],
        verification_status: 'verified',
        warnings: ['Review before sharing.'],
        source_fingerprint: {
          resolved_path: 'C:\\project\\src\\secrets.py',
          size: 42,
          modified_ns: 1,
          sha256: 'abc123',
          matched_text: 'fingerprint raw match',
        },
        rescan_status: 'completed',
        remaining_finding_count: 0,
        remaining_tier_a_count: 0,
        evidence: 'output raw context',
      },
    ] as unknown as GeneratedOutputDetails[]
    const json = JSON.stringify(
      buildJsonReport(scan, malformedPlan, malformedOutputs, () => 'pending'),
    )
    const human = buildHumanReport(scan, malformedPlan, malformedOutputs, () => 'pending')

    for (const exported of [json, human]) {
      expect(exported).not.toContain('123-45-6789')
      expect(exported).not.toContain('raw context')
      expect(exported).not.toContain('raw match')
      expect(exported).not.toContain('C:\\project')
      expect(exported).toContain('src/secrets.py')
    }
    expect(human).toContain('## Redacted output evidence')
    expect(human).toContain('Output: src/secrets-auto-redacted-copy.py')
    expect(human).toContain('Verification status: verified')
    expect(human).toContain('Source fingerprint: SHA-256 abc123')
    expect(human).toContain('Output rescan status: completed')
    expect(human).toContain('Remaining findings: 0')
    expect(human).toContain('Warning: Review before sharing.')
  })
})
