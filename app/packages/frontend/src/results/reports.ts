import type {
  GeneratedOutputDetails,
  PublicFinding,
  PublicScanResult,
  RemediationPlan,
  RemediationState,
} from '../types'
import {
  buildFileOptions,
  detectorName,
  fileIdentity,
  relativePath,
  relativizeText,
} from './triage'

/** Emit an untrusted value as one inert line of Markdown text. */
function markdownText(value: string): string {
  const oneLine = value
    .replace(/[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/gu, ' ')
    .replace(/\s+/gu, ' ')
    .trim()
  const htmlSafe = oneLine.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')

  // Numeric entities render as their original characters without being
  // interpreted as links, emphasis, headings, code spans, or other markup.
  return htmlSafe.replace(/[\\`*_[\]{}()#+!|~]/g, (character) => {
    return `&#${character.codePointAt(0)};`
  })
}

interface RuntimeFindingWithRawMatch extends PublicFinding {
  matched_text?: unknown
}

function escapeRegularExpression(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
}

function safeRuntimeMarker(
  rawIdentities: string[],
  ordinal: number,
  usedMarkers: Set<string>,
): string {
  const candidates = [
    `<redacted-value-${ordinal}>`,
    `⟦sensitive-${ordinal}⟧`,
    `[private-value-${ordinal}]`,
  ]
  for (const candidate of candidates) {
    const identity = candidate.toLowerCase()
    if (
      !usedMarkers.has(candidate) &&
      rawIdentities.every((rawValue) => !identity.includes(rawValue))
    ) {
      usedMarkers.add(candidate)
      return candidate
    }
  }

  // Short custom targets can overlap every readable marker. Private-use code points keep the
  // replacement inert and deterministic; fail closed if an intentionally pathological target set
  // consumes the whole range rather than risk reproducing a raw value.
  const privateUseSize = 0xf8ff - 0xe000 + 1
  for (let offset = 0; offset < privateUseSize; offset += 1) {
    const codePoint = 0xe000 + ((ordinal - 1 + offset) % privateUseSize)
    const candidate = String.fromCodePoint(codePoint)
    const identity = candidate.toLowerCase()
    if (
      !usedMarkers.has(candidate) &&
      rawIdentities.every((rawValue) => !identity.includes(rawValue))
    ) {
      usedMarkers.add(candidate)
      return candidate
    }
  }
  throw new Error('A privacy-safe report marker could not be created.')
}

/**
 * The public API deliberately omits raw matches. Keep the report boundary safe even if a future
 * projection regression accidentally restores that internal property: any such value is removed
 * from every exported string, including paths and structured-document locations.
 */
function runtimeRawReplacements(findings: PublicFinding[]): Array<[RegExp, string]> {
  const rawValues = new Map<string, string>()
  for (const finding of findings as RuntimeFindingWithRawMatch[]) {
    if (typeof finding.matched_text !== 'string' || finding.matched_text.length === 0) continue
    rawValues.set(finding.matched_text.toLowerCase(), finding.matched_text)
  }
  const orderedRawValues = [...rawValues.values()].sort(
    (left, right) => right.length - left.length || left.localeCompare(right),
  )
  const rawIdentities = orderedRawValues.map((rawValue) => rawValue.toLowerCase())
  const usedMarkers = new Set<string>()
  return orderedRawValues.map((rawValue, index) => [
    new RegExp(escapeRegularExpression(rawValue), 'gi'),
    safeRuntimeMarker(rawIdentities, index + 1, usedMarkers),
  ])
}

function scrubRuntimeRawValues<T>(value: T, replacements: Array<[RegExp, string]>): T {
  if (replacements.length === 0) return value
  if (typeof value === 'string') {
    let scrubbed: string = value
    for (const [rawValue, preview] of replacements) {
      scrubbed = scrubbed.replace(rawValue, () => preview)
    }
    return scrubbed as T
  }
  if (Array.isArray(value)) {
    return value.map((item) => scrubRuntimeRawValues(item, replacements)) as T
  }
  if (value && typeof value === 'object') {
    return Object.fromEntries(
      Object.entries(value).map(([key, item]) => [key, scrubRuntimeRawValues(item, replacements)]),
    ) as T
  }
  return value
}

export function buildJsonReport(
  result: PublicScanResult,
  plan: RemediationPlan,
  outputs: GeneratedOutputDetails[],
  stateOf: (finding: PublicFinding) => RemediationState,
  generatedAt = new Date().toISOString(),
) {
  const rawReplacements = runtimeRawReplacements(result.findings)
  const roots = result.metadata.selected_roots
  const allPaths = [
    ...result.scanned_files,
    ...result.skipped_files.map((file) => file.path),
    ...plan.files.flatMap((file) => [file.source_path, file.output_path]),
    ...plan.retained_artifact_paths,
    ...outputs.flatMap((output) => [output.source_path, output.output_path]),
    ...result.findings.map((finding) => finding.file_path),
  ]
  const pathLabels = new Map(
    buildFileOptions(allPaths, roots).map((option) => [option.value, option.label]),
  )
  const reportPath = (path: string) =>
    pathLabels.get(fileIdentity(path)) ?? relativePath(path, roots)
  const report = {
    report_version: '1.0',
    generated_at: generatedAt,
    notice: 'This report is a review aid, not a guarantee that every sensitive value was found.',
    scan: {
      state: result.state,
      duration_ms: result.metadata.duration_ms,
      data_scanned_bytes: result.metadata.data_scanned_bytes,
      files_scanned: result.scanned_files.length,
      files_skipped: result.skipped_files.length,
      detector_count: result.metadata.detector_count,
      ai_model: result.metadata.ai_model,
    },
    scanned_files: result.scanned_files.map(reportPath),
    skipped_files: result.skipped_files.map((file) => ({
      path: reportPath(file.path),
      reason: relativizeText(file.reason, roots),
      code: file.code,
      stage: file.stage,
      rule: file.rule ? relativizeText(file.rule, roots) : null,
    })),
    remediation: {
      plan_revision: plan.plan_revision,
      findings: plan.findings.map((finding) => ({
        finding_id: finding.finding_id,
        state: finding.state,
      })),
      files: plan.files.map((file) => ({
        source_path: reportPath(file.source_path),
        output_path: reportPath(file.output_path),
        included_finding_ids: file.included_finding_ids,
        output_state: file.output_state,
      })),
      selected_finding_count: plan.selected_finding_count,
      affected_file_count: plan.affected_file_count,
      read_only_finding_count: plan.read_only_finding_count,
      retained_artifact_paths: plan.retained_artifact_paths.map(reportPath),
      can_review: plan.can_review,
      can_generate: plan.can_generate,
    },
    outputs: outputs.map((output) => ({
      source_path: reportPath(output.source_path),
      output_path: reportPath(output.output_path),
      applied_finding_ids: output.applied_finding_ids,
      verification_status: output.verification_status,
      warnings: output.warnings.map((warning) => relativizeText(warning, roots)),
      source_fingerprint: {
        size: output.source_fingerprint.size,
        modified_ns: output.source_fingerprint.modified_ns,
        sha256: output.source_fingerprint.sha256,
      },
      rescan_status: output.rescan_status,
      remaining_finding_count: output.remaining_finding_count,
      remaining_tier_a_count: output.remaining_tier_a_count,
    })),
    findings: result.findings.map((finding) => ({
      id: finding.id,
      file_path: reportPath(finding.file_path),
      line: finding.line,
      column: finding.column,
      location: finding.location ? relativizeText(finding.location, roots) : null,
      can_anonymize: finding.can_anonymize,
      redacted_preview: finding.redacted_preview,
      detector_id: finding.detector_id,
      detector_name: detectorName(finding.detector_id),
      category: finding.category,
      confidence: finding.confidence,
      tier: finding.tier,
      explanation: finding.explanation,
      risk_lesson: finding.risk_lesson,
      suggested_action: finding.suggested_action,
      supporting_detections: finding.supporting_detections.map((supporting) => ({
        detector_id: supporting.detector_id,
        description: supporting.description,
        confidence: supporting.confidence,
        relationship: supporting.relationship,
      })),
      status: stateOf(finding),
    })),
  }
  return scrubRuntimeRawValues(report, rawReplacements)
}

export function buildHumanReport(
  result: PublicScanResult,
  plan: RemediationPlan,
  outputs: GeneratedOutputDetails[],
  stateOf: (finding: PublicFinding) => RemediationState,
  generatedAt = new Date().toISOString(),
): string {
  const report = buildJsonReport(result, plan, outputs, stateOf, generatedAt)
  const lines = [
    '# RedactLens scan report',
    '',
    `Generated: ${markdownText(report.generated_at)}`,
    '',
    `> ${markdownText(report.notice)}`,
    '',
    '## Scan summary',
    '',
    `- State: ${markdownText(report.scan.state)}`,
    `- Files scanned: ${report.scan.files_scanned}`,
    `- Files skipped: ${report.scan.files_skipped}`,
    `- Data scanned: ${report.scan.data_scanned_bytes} bytes`,
    `- Duration: ${report.scan.duration_ms ?? 'not recorded'} ms`,
    `- Configured detectors: ${report.scan.detector_count}`,
    `- On-device AI: ${markdownText(report.scan.ai_model ?? 'not used')}`,
    '',
    `## Findings (${report.findings.length})`,
    '',
  ]
  for (const finding of report.findings) {
    const place = finding.location ?? `line ${finding.line}, column ${finding.column}`
    lines.push(
      `### Tier ${markdownText(finding.tier)} — ${markdownText(finding.detector_name)}`,
      '',
      `- File: ${markdownText(finding.file_path)} (${markdownText(place)})`,
      `- Preview: ${markdownText(finding.redacted_preview)}`,
      `- Confidence: ${Math.round(finding.confidence * 100)}%`,
      `- Status: ${markdownText(finding.status)}`,
      `- Why it matters: ${markdownText(finding.risk_lesson)}`,
      '',
    )
  }
  if (report.findings.length === 0) {
    lines.push(
      report.scan.files_scanned === 0
        ? 'No detection result is available because no files were inspected. Review the skipped-file details and scan a readable file or folder.'
        : 'No values matched the configured detectors. Manual review is still recommended.',
      '',
    )
  }
  if (report.skipped_files.length > 0) {
    lines.push('## Skipped files', '')
    for (const file of report.skipped_files) {
      lines.push(`- ${markdownText(file.path)}: ${markdownText(file.reason)}`)
    }
    lines.push('')
  }
  lines.push(
    '## Remediation',
    '',
    `- Findings selected for redaction: ${plan.selected_finding_count}`,
    `- Affected files: ${plan.affected_file_count}`,
    `- Plan revision: ${plan.plan_revision}`,
    `- Verified outputs created: ${outputs.length}`,
    `- Retained remediation artifacts: ${report.remediation.retained_artifact_paths.length}`,
    '',
  )
  if (report.remediation.retained_artifact_paths.length > 0) {
    lines.push(
      '### Manual cleanup required',
      '',
      'RedactLens could not remove these temporary remediation artifacts after a file operation. They may contain sensitive content. Inspect or recover them if needed, then delete them manually:',
      '',
    )
    for (const artifactPath of report.remediation.retained_artifact_paths) {
      lines.push(`- ${markdownText(artifactPath)}`)
    }
    lines.push('')
  }
  if (report.outputs.length > 0) {
    lines.push('## Redacted output evidence', '')
    for (const output of report.outputs) {
      lines.push(
        `### ${markdownText(output.output_path)}`,
        '',
        `- Source: ${markdownText(output.source_path)}`,
        `- Output: ${markdownText(output.output_path)}`,
        `- Applied finding IDs: ${markdownText(output.applied_finding_ids.join(', ') || 'none')}`,
        `- Verification status: ${markdownText(output.verification_status)}`,
        `- Source fingerprint: SHA-256 ${markdownText(output.source_fingerprint.sha256)}; ${output.source_fingerprint.size} bytes; modified_ns ${output.source_fingerprint.modified_ns}`,
        `- Output rescan status: ${markdownText(output.rescan_status)}`,
      )
      if (output.rescan_status === 'completed') {
        lines.push(
          `- Remaining findings: ${output.remaining_finding_count ?? 'not reported'}`,
          `- Remaining Tier A findings: ${output.remaining_tier_a_count ?? 'not reported'}`,
        )
      } else {
        lines.push('- Remaining findings: unavailable because the output rescan failed')
      }
      for (const warning of output.warnings) {
        lines.push(`- Warning: ${markdownText(warning)}`)
      }
      lines.push('')
    }
  }
  return `${lines.join('\n')}\n`
}
