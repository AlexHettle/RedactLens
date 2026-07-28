import type { PublicFinding, RemediationState, SkippedFile, Tier, UserTarget } from '../types'

export type GroupMode = 'tier' | 'file' | 'category'
export type RewriteFilter = 'all' | 'anonymizable' | 'read_only'

export interface FindingFilters {
  tier: 'all' | Tier
  category: string
  detector: string
  file: string
  status: 'all' | RemediationState | 'decided'
  rewrite: RewriteFilter
}

/** Resolve one fail-closed state from the finding and server-owned plan. */
export function effectiveRemediationState(
  finding: PublicFinding,
  state?: RemediationState,
): RemediationState {
  if (!finding.can_anonymize || state === 'read_only') return 'read_only'
  return state ?? 'pending'
}

/**
 * Automatic redaction is available only when both the finding projection and
 * the server-owned remediation state agree. Any disagreement fails closed.
 */
export function findingSupportsAutomaticRedaction(
  finding: PublicFinding,
  state?: RemediationState,
): boolean {
  return effectiveRemediationState(finding, state) !== 'read_only'
}

export const EMPTY_FILTERS: FindingFilters = {
  tier: 'all',
  category: 'all',
  detector: 'all',
  file: 'all',
  status: 'all',
  rewrite: 'all',
}

const ACRONYMS: Record<string, string> = {
  api: 'API',
  aws: 'AWS',
  iban: 'IBAN',
  ip: 'IP',
  jwt: 'JWT',
  pii: 'PII',
  ssn: 'SSN',
  us: 'US',
  url: 'URL',
}

const CATEGORY_NAMES: Record<string, string> = {
  credential: 'Credentials',
  financial: 'Financial data',
  health: 'Health data',
  personal_id: 'Personal identifiers',
  custom: 'Custom targets',
}

function compareText(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0
}

function normalizedPath(path: string): string {
  let normalized = path.replace(/\\/g, '/')
  normalized = normalized.replace(/\/+$/, '')
  return normalized.toLowerCase()
}

export function fileName(path: string): string {
  const parts = path.replace(/\\/g, '/').split('/')
  return parts.at(-1) || path
}

interface PathProjection {
  relative: string
  rootIndex: number | null
}

function pathSegments(path: string): string[] {
  return path
    .replace(/\\/g, '/')
    .split('/')
    .filter((part) => part.length > 0)
}

function projectPath(path: string, roots: string[]): PathProjection {
  const normalized = normalizedPath(path)
  const candidates = roots.flatMap((root, rootIndex) => {
    const normalizedRoot = normalizedPath(root)
    const exactMatch = normalized === normalizedRoot
    const childMatch = normalized.startsWith(`${normalizedRoot}/`)
    if (!exactMatch && !childMatch) return []

    const rootParts = pathSegments(root)
    const fileParts = pathSegments(path)
    const relative = exactMatch ? fileName(path) : fileParts.slice(rootParts.length).join('/')
    return [
      {
        relative: relative || fileName(path),
        rootIndex,
        specificity: normalizedRoot.length,
      },
    ]
  })
  if (candidates.length === 0) return { relative: fileName(path), rootIndex: null }
  const best = candidates.sort(
    (left, right) => right.specificity - left.specificity || left.rootIndex - right.rootIndex,
  )[0]
  return { relative: best.relative, rootIndex: best.rootIndex }
}

export function relativePath(path: string, roots: string[]): string {
  return projectPath(path, roots).relative
}

/** Stable internal identity for a source file. Never use this as display text. */
export function fileIdentity(path: string): string {
  return normalizedPath(path)
}

export interface FileOption {
  value: string
  label: string
}

/**
 * Build independently selectable file identities while keeping labels relative to scan roots.
 * Duplicate relative names are disambiguated by the public root ordinal, never by revealing the
 * root itself.
 */
export function buildFileOptions(paths: string[], roots: string[]): FileOption[] {
  const uniquePaths = new Map<string, string>()
  for (const path of paths) {
    const identity = fileIdentity(path)
    if (!uniquePaths.has(identity)) uniquePaths.set(identity, path)
  }

  const records = [...uniquePaths.entries()].map(([value, path]) => ({
    value,
    path,
    projection: projectPath(path, roots),
  }))
  const collisionCounts = new Map<string, number>()
  for (const record of records) {
    const collisionKey = record.projection.relative.toLowerCase()
    collisionCounts.set(collisionKey, (collisionCounts.get(collisionKey) ?? 0) + 1)
  }

  const outsideRootOrdinals = new Map<string, number>()
  let nextOutsideRootOrdinal = 1
  const options = records
    .sort((left, right) => compareText(left.value, right.value))
    .map((record) => {
      const collisionKey = record.projection.relative.toLowerCase()
      let label = record.projection.relative
      if ((collisionCounts.get(collisionKey) ?? 0) > 1) {
        if (record.projection.rootIndex !== null) {
          label = `Scan root ${record.projection.rootIndex + 1}: ${record.projection.relative}`
        } else {
          let ordinal = outsideRootOrdinals.get(record.value)
          if (ordinal === undefined) {
            ordinal = nextOutsideRootOrdinal
            nextOutsideRootOrdinal += 1
            outsideRootOrdinals.set(record.value, ordinal)
          }
          label = `File ${ordinal}: ${record.projection.relative}`
        }
      }
      return { value: record.value, label }
    })

  return options.sort(
    (left, right) => compareText(left.label, right.label) || compareText(left.value, right.value),
  )
}

export function relativizeText(text: string, roots: string[]): string {
  return roots.reduce((current, root) => {
    const escaped = root.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
    return current
      .replace(new RegExp(escaped, 'gi'), '<scan root>')
      .replace(new RegExp(escaped.replace(/\\\\/g, '/'), 'gi'), '<scan root>')
  }, text)
}

const REDACTION_MARKERS = /<redacted>|\u27e6sensitive value\u27e7/gi

export function displayRedactedPreview(preview: string): string {
  return preview.replace(REDACTION_MARKERS, '*')
}

function indexedTarget(detectorId: string, userTargets: UserTarget[]): UserTarget | null {
  const descriptionMatch = /^(?:user_target_desc|custom_description)_(\d+)$/.exec(detectorId)
  if (descriptionMatch) {
    const target = userTargets.filter((candidate) => candidate.kind === 'description')[
      Number(descriptionMatch[1])
    ]
    return target ?? null
  }

  const userLiteralMatch = /^user_target_(\d+)$/.exec(detectorId)
  if (userLiteralMatch) {
    const target = userTargets[Number(userLiteralMatch[1])]
    return target?.kind === 'literal' ? target : null
  }

  const legacyLiteralMatch = /^custom_literal_(\d+)$/.exec(detectorId)
  if (legacyLiteralMatch) {
    const target = userTargets.filter((candidate) => candidate.kind === 'literal')[
      Number(legacyLiteralMatch[1])
    ]
    return target ?? null
  }
  return null
}

export function detectorName(detectorId: string, userTargets: UserTarget[] = []): string {
  const customTarget = indexedTarget(detectorId, userTargets)
  if (customTarget) {
    return `Found with your custom rule "${customTarget.value}"`
  }
  if (detectorId.startsWith('user_target_desc_') || detectorId.startsWith('custom_description')) {
    return 'Found with your custom description rule'
  }
  if (detectorId.startsWith('user_target_') || detectorId.startsWith('custom_literal')) {
    return 'Found with your custom exact-value rule'
  }
  return detectorId
    .split('_')
    .map(
      (token, index) =>
        ACRONYMS[token] ?? (index === 0 ? token[0]?.toUpperCase() + token.slice(1) : token),
    )
    .join(' ')
}

export function categoryName(category: string): string {
  return (
    CATEGORY_NAMES[category] ??
    category
      .split('_')
      .map((token) => token[0]?.toUpperCase() + token.slice(1))
      .join(' ')
  )
}

export function sortFindings(findings: PublicFinding[]): PublicFinding[] {
  return [...findings].sort(
    (left, right) =>
      (left.tier === right.tier ? 0 : left.tier === 'A' ? -1 : 1) ||
      right.confidence - left.confidence ||
      compareText(normalizedPath(left.file_path), normalizedPath(right.file_path)) ||
      left.line - right.line ||
      left.column - right.column ||
      compareText(left.id, right.id),
  )
}

export function filterFindings(
  findings: PublicFinding[],
  filters: FindingFilters,
  stateOf: (finding: PublicFinding) => RemediationState,
): PublicFinding[] {
  return sortFindings(
    findings.filter((finding) => {
      if (filters.tier !== 'all' && finding.tier !== filters.tier) return false
      if (filters.category !== 'all' && finding.category !== filters.category) return false
      if (filters.detector !== 'all' && finding.detector_id !== filters.detector) return false
      if (filters.file !== 'all' && fileIdentity(finding.file_path) !== filters.file) return false
      const status = effectiveRemediationState(finding, stateOf(finding))
      if (filters.status === 'decided' && !['included', 'ignored'].includes(status)) return false
      if (filters.status !== 'all' && filters.status !== 'decided' && status !== filters.status)
        return false
      const supportsRedaction = findingSupportsAutomaticRedaction(finding, status)
      if (filters.rewrite === 'anonymizable' && !supportsRedaction) return false
      if (filters.rewrite === 'read_only' && supportsRedaction) return false
      return true
    }),
  )
}

export interface FindingGroup {
  key: string
  title: string
  subtitle?: string
  tier?: Tier
  findings: PublicFinding[]
}

export function groupFindings(
  findings: PublicFinding[],
  mode: GroupMode,
  roots: string[],
  fileOptions: FileOption[] = buildFileOptions(
    findings.map((finding) => finding.file_path),
    roots,
  ),
): FindingGroup[] {
  const fileLabels = new Map(fileOptions.map((option) => [option.value, option.label]))
  const groups = new Map<string, PublicFinding[]>()
  for (const finding of findings) {
    const key =
      mode === 'tier'
        ? finding.tier
        : mode === 'file'
          ? fileIdentity(finding.file_path)
          : finding.category
    groups.set(key, [...(groups.get(key) ?? []), finding])
  }
  return [...groups.entries()]
    .sort(([left], [right]) => {
      if (mode === 'tier') return left === right ? 0 : left === 'A' ? -1 : 1
      if (mode === 'file') {
        return (
          compareText(fileLabels.get(left) ?? left, fileLabels.get(right) ?? right) ||
          compareText(left, right)
        )
      }
      return compareText(left, right)
    })
    .map(([key, group]) => ({
      key,
      title:
        mode === 'tier'
          ? key === 'A'
            ? 'Confirmed sensitive'
            : 'Worth a double-check'
          : mode === 'category'
            ? categoryName(key)
            : (fileLabels.get(key) ?? relativePath(group[0].file_path, roots)),
      subtitle:
        mode === 'tier'
          ? key === 'A'
            ? 'Strong match — still worth a review.'
            : 'Less certain — your call.'
          : undefined,
      tier: mode === 'tier' ? (key as Tier) : undefined,
      findings: group,
    }))
}

interface SkipGuidance {
  title: string
  advice: string
}

function skipGuidance(file: SkippedFile): SkipGuidance {
  if (file.code === 'ignored_by_rule' || file.code === 'ignored_directory') {
    return {
      title: 'Ignored by scope',
      advice:
        'Review the named option or .redactlensignore rule if this content should be scanned.',
    }
  }
  if (file.code === 'excluded_extension' || file.code === 'extension_not_included') {
    return {
      title: 'Filtered extensions',
      advice: 'Adjust the included or excluded extension list if these files should be scanned.',
    }
  }
  if (file.code === 'filesystem_redirect') {
    return {
      title: 'Filesystem redirects',
      advice: 'Scan the real target explicitly only after confirming that you trust its location.',
    }
  }
  if (file.code === 'non_regular_file') {
    return {
      title: 'Special filesystem entries',
      advice: 'Copy the content to a regular local file, then scan that trusted copy.',
    }
  }
  const value = file.reason.toLowerCase()
  if (value.includes('symbolic link') || value.includes('symlink')) {
    return {
      title: 'Symbolic links',
      advice: 'Scan the real target explicitly only after confirming that you trust its location.',
    }
  }
  if (value.includes('max scan size') || value.includes('too large')) {
    return {
      title: 'Too large',
      advice: 'Inspect these files manually or scan a smaller exported copy.',
    }
  }
  if (value.includes('archive')) {
    return { title: 'Archives', advice: 'Unpack each archive and scan the extracted folder.' }
  }
  if (value.includes('image') || value.includes('ocr')) {
    return {
      title: 'Images',
      advice: 'Use a trusted local OCR tool, then scan the extracted text.',
    }
  }
  if (value.includes('binary') || value.includes('decode') || value.includes('encoding')) {
    return {
      title: 'Unreadable text',
      advice: 'Inspect manually or convert to a supported plain-text encoding before rescanning.',
    }
  }
  if (value.includes('legacy office') || value.includes('.msg') || value.includes('supported')) {
    return {
      title: 'Unsupported format',
      advice: 'Convert to the supported format named in the reason, then rescan.',
    }
  }
  if (value.includes('time limit') || value.includes('timed out')) {
    return { title: 'Timed out', advice: 'Scan the file separately or reduce its complexity.' }
  }
  if (value.includes('stat') || value.includes('read file') || value.includes('available')) {
    return {
      title: 'Unavailable',
      advice: 'Check that the file still exists and that RedactLens can read it, then rescan.',
    }
  }
  return { title: 'Other skips', advice: 'Review the reason and inspect the file manually.' }
}

export interface SkippedGroup extends SkipGuidance {
  files: SkippedFile[]
}

export function groupSkippedFiles(files: SkippedFile[]): SkippedGroup[] {
  const groups = new Map<string, SkippedGroup>()
  for (const file of files) {
    const guidance = skipGuidance(file)
    const current = groups.get(guidance.title) ?? { ...guidance, files: [] }
    current.files.push(file)
    groups.set(guidance.title, current)
  }
  return [...groups.values()].sort((left, right) => left.title.localeCompare(right.title))
}

export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 ** 2) return `${(bytes / 1024).toFixed(1)} KB`
  if (bytes < 1024 ** 3) return `${(bytes / 1024 ** 2).toFixed(1)} MB`
  return `${(bytes / 1024 ** 3).toFixed(1)} GB`
}

export function formatDuration(durationMs: number | null): string {
  if (durationMs === null) return 'Not recorded'
  if (durationMs < 1000) return `${durationMs} ms`
  const secondsWithTenths = Math.round(durationMs / 100) / 10
  if (secondsWithTenths < 60) return `${secondsWithTenths.toFixed(1)} s`
  const totalSeconds = Math.round(durationMs / 1000)
  const minutes = Math.floor(totalSeconds / 60)
  const seconds = totalSeconds % 60
  return `${minutes}m ${seconds}s`
}
