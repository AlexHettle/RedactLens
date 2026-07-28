// Mirrors the browser-facing API contracts, intentionally not the larger
// redactlens_core.models types that retain raw matches and trusted offsets.
// Exact values are available only through the separate, transient reveal
// response below and never become part of PublicFinding or PublicScanResult.

export type Tier = 'A' | 'B'
export type SuggestedAction = 'anonymize' | 'review'
export type TargetKind = 'literal' | 'description'
export type ConsolidationReason = 'same_span' | 'suppressed' | 'overlap_chain'

export interface SupportingDetection {
  detector_id: string
  description: string
  confidence: number
  relationship: ConsolidationReason
}

export interface PublicFinding {
  id: string
  file_path: string
  line: number
  column: number
  // Set for findings inside extracted documents (docx/xlsx/pptx/pdf):
  // a human-readable place like "Sheet1!B7" or "page 3". line/column then
  // refer to the extracted text, not the file.
  location: string | null
  // False for read-only extracted formats such as PDF. Supported Office
  // documents can be rewritten and keep this true.
  can_anonymize: boolean
  redacted_preview: string
  detector_id: string
  category: string
  confidence: number
  tier: Tier
  explanation: string
  risk_lesson: string
  suggested_action: SuggestedAction
  supporting_detections: SupportingDetection[]
}

export interface RevealedFindingValue {
  finding_id: string
  value: string
}

export interface RevealFindingsResponse {
  values: RevealedFindingValue[]
}

export interface UserTarget {
  kind: TargetKind
  value: string
  category: string
}

export interface ScanRequest {
  paths: string[]
  categories: string[]
  user_targets: UserTarget[]
  use_llm: boolean
  ollama_model?: string
  tier_threshold?: number
  options?: ScanOptions
}

export interface ScanOptions {
  max_file_size?: number
  max_structured_file_size?: number
  ignored_directories?: string[]
  included_extensions?: string[]
  excluded_extensions?: string[]
  archive_depth?: number
  ai_timeout_seconds?: number
  max_workers?: number
  document_workers?: number
  chunk_size?: number
  use_redactlensignore?: boolean
}

export interface SkippedFile {
  path: string
  reason: string
  code: string
  stage: 'discovery' | 'extraction' | 'detection' | 'ai_refinement'
  rule: string | null
}

export type ScanState =
  | 'pending'
  | 'discovering'
  | 'scanning'
  | 'refining'
  | 'cancelling'
  | 'complete'
  | 'cancelled'
  | 'failed'
  | 'timed_out'

export type ScanStage =
  | 'pending'
  | 'discovery'
  | 'extraction'
  | 'detection'
  | 'consolidation'
  | 'ai_refinement'
  | 'finalizing'
  | 'complete'
  | 'cancelled'
  | 'failed'
  | 'timed_out'

export interface ScanProgress {
  stage: ScanStage
  completed_files: number
  total_files: number | null
  percent: number
  current_file: string | null
  findings_so_far: number
  skipped_files: number
}

export interface ScanError {
  code: string
  message: string
}

export interface ScanMetadata {
  selected_roots: string[]
  duration_ms: number | null
  data_scanned_bytes: number
  detector_count: number
  ai_model: string | null
}

export interface PublicScanResult {
  scan_id: string
  /** Sequence of the newest event already represented by this snapshot. */
  event_cursor: number
  created_at: string
  expires_at: string
  findings: PublicFinding[]
  summary: Record<string, unknown>
  scanned_files: string[]
  skipped_files: SkippedFile[]
  llm_used: boolean
  state: ScanState
  progress: ScanProgress
  error: ScanError | null
  metadata: ScanMetadata
}

export type ScanEventType =
  | 'scan_started'
  | 'discovery_complete'
  | 'file_started'
  | 'file_completed'
  | 'finding_added'
  | 'finding_updated'
  | 'file_skipped'
  | 'ai_refinement_started'
  | 'scan_finalizing'
  | 'scan_completed'
  | 'scan_cancelled'
  | 'scan_failed'

export interface ScanEvent {
  sequence: number
  type: ScanEventType
  emitted_at: string
  scan_id: string
  state: ScanState
  progress: ScanProgress
  finding: PublicFinding | null
  skipped_file: SkippedFile | null
  error: ScanError | null
}

export interface DetectorInfo {
  id: string
  category: string
  description: string
  risk_lesson: string
}

export interface OllamaModelSummary {
  name: string
  size_bytes: number | null
}

export interface HealthResponse {
  status: string
  ollama_available: boolean
  /** Optional for compatibility with an older local service during upgrades. */
  ollama_status?: 'unavailable' | 'model_missing' | 'ready'
  ollama_model?: string
  ollama_models?: OllamaModelSummary[]
}

export type RemediationState = 'pending' | 'included' | 'ignored' | 'read_only'
export type RemediationOutputMode = 'copy' | 'replace_original'
export type OutputState =
  'not_created' | 'current' | 'regeneration_required' | 'obsolete' | 'conflict'

export interface RemediationFindingState {
  finding_id: string
  state: RemediationState
}

export interface RemediationFilePlan {
  source_path: string
  output_path: string
  included_finding_ids: string[]
  output_state: OutputState
}

export interface RemediationPlan {
  plan_revision: number
  findings: RemediationFindingState[]
  files: RemediationFilePlan[]
  selected_finding_count: number
  affected_file_count: number
  read_only_finding_count: number
  retained_artifact_paths: string[]
  can_review: boolean
  can_generate: boolean
}

export interface PublicFileFingerprint {
  resolved_path: string
  size: number
  modified_ns: number
  sha256: string
}

export interface GeneratedOutputDetails {
  source_path: string
  output_path: string
  applied_finding_ids: string[]
  verification_status: 'verified'
  warnings: string[]
  source_fingerprint: PublicFileFingerprint
  rescan_status: 'completed' | 'failed'
  remaining_finding_count: number | null
  remaining_tier_a_count: number | null
}

export interface RemediationGenerationResponse {
  plan: RemediationPlan
  outputs: GeneratedOutputDetails[]
}
