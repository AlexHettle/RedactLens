import type {
  ConsolidationReason,
  PublicFinding,
  ScanError,
  ScanEvent,
  ScanEventType,
  ScanProgress,
  ScanStage,
  ScanState,
  SkippedFile,
  SuggestedAction,
  SupportingDetection,
  Tier,
} from '../types'

const EVENT_TYPES = new Set<ScanEventType>([
  'scan_started',
  'discovery_complete',
  'file_started',
  'file_completed',
  'finding_added',
  'finding_updated',
  'file_skipped',
  'ai_refinement_started',
  'scan_finalizing',
  'scan_completed',
  'scan_cancelled',
  'scan_failed',
])

const SCAN_STATES = new Set<ScanState>([
  'pending',
  'discovering',
  'scanning',
  'refining',
  'cancelling',
  'complete',
  'cancelled',
  'failed',
  'timed_out',
])

const SCAN_STAGES = new Set<ScanStage>([
  'pending',
  'discovery',
  'extraction',
  'detection',
  'consolidation',
  'ai_refinement',
  'finalizing',
  'complete',
  'cancelled',
  'failed',
  'timed_out',
])

const TIERS = new Set<Tier>(['A', 'B'])
const SUGGESTED_ACTIONS = new Set<SuggestedAction>(['anonymize', 'review'])
const CONSOLIDATION_REASONS = new Set<ConsolidationReason>([
  'same_span',
  'suppressed',
  'overlap_chain',
])
const SKIP_STAGES = new Set<SkippedFile['stage']>([
  'discovery',
  'extraction',
  'detection',
  'ai_refinement',
])

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function isMember<Value extends string>(
  value: unknown,
  allowed: ReadonlySet<Value>,
): value is Value {
  return typeof value === 'string' && allowed.has(value as Value)
}

function isFiniteNumber(value: unknown): value is number {
  return typeof value === 'number' && Number.isFinite(value)
}

function isSafeInteger(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value)
}

function isNonNegativeInteger(value: unknown): value is number {
  return isSafeInteger(value) && value >= 0
}

function isNullableString(value: unknown): value is string | null {
  return value === null || typeof value === 'string'
}

function isSupportingDetection(value: unknown): value is SupportingDetection {
  return (
    isRecord(value) &&
    typeof value.detector_id === 'string' &&
    typeof value.description === 'string' &&
    isFiniteNumber(value.confidence) &&
    value.confidence >= 0 &&
    value.confidence <= 1 &&
    isMember(value.relationship, CONSOLIDATION_REASONS)
  )
}

function isPublicFinding(value: unknown): value is PublicFinding {
  return (
    isRecord(value) &&
    typeof value.id === 'string' &&
    typeof value.file_path === 'string' &&
    isSafeInteger(value.line) &&
    isSafeInteger(value.column) &&
    isNullableString(value.location) &&
    typeof value.can_anonymize === 'boolean' &&
    typeof value.redacted_preview === 'string' &&
    typeof value.detector_id === 'string' &&
    typeof value.category === 'string' &&
    isFiniteNumber(value.confidence) &&
    value.confidence >= 0 &&
    value.confidence <= 1 &&
    isMember(value.tier, TIERS) &&
    typeof value.explanation === 'string' &&
    typeof value.risk_lesson === 'string' &&
    isMember(value.suggested_action, SUGGESTED_ACTIONS) &&
    Array.isArray(value.supporting_detections) &&
    value.supporting_detections.every(isSupportingDetection)
  )
}

function isScanProgress(value: unknown): value is ScanProgress {
  return (
    isRecord(value) &&
    isMember(value.stage, SCAN_STAGES) &&
    isNonNegativeInteger(value.completed_files) &&
    (value.total_files === null || isNonNegativeInteger(value.total_files)) &&
    isFiniteNumber(value.percent) &&
    value.percent >= 0 &&
    value.percent <= 100 &&
    isNullableString(value.current_file) &&
    isNonNegativeInteger(value.findings_so_far) &&
    isNonNegativeInteger(value.skipped_files)
  )
}

function isSkippedFile(value: unknown): value is SkippedFile {
  return (
    isRecord(value) &&
    typeof value.path === 'string' &&
    typeof value.reason === 'string' &&
    typeof value.code === 'string' &&
    isMember(value.stage, SKIP_STAGES) &&
    isNullableString(value.rule)
  )
}

function isScanError(value: unknown): value is ScanError {
  return isRecord(value) && typeof value.code === 'string' && typeof value.message === 'string'
}

/** Validate untrusted EventSource JSON before it can advance the cursor or enter React state. */
export function isScanEvent(value: unknown): value is ScanEvent {
  if (
    !isRecord(value) ||
    !isSafeInteger(value.sequence) ||
    value.sequence < 1 ||
    !isMember(value.type, EVENT_TYPES) ||
    typeof value.emitted_at !== 'string' ||
    typeof value.scan_id !== 'string' ||
    !isMember(value.state, SCAN_STATES) ||
    !isScanProgress(value.progress) ||
    !(value.finding === null || isPublicFinding(value.finding)) ||
    !(value.skipped_file === null || isSkippedFile(value.skipped_file)) ||
    !(value.error === null || isScanError(value.error))
  ) {
    return false
  }

  if (
    (value.type === 'finding_added' || value.type === 'finding_updated') &&
    value.finding === null
  ) {
    return false
  }
  if (value.type === 'file_skipped' && value.skipped_file === null) return false
  if ((value.type === 'scan_cancelled' || value.type === 'scan_failed') && value.error === null) {
    return false
  }
  return true
}
