import { useEffect, useRef, useState, type ReactNode, type RefObject } from 'react'
import {
  buildFileOptions,
  categoryName,
  detectorName,
  fileIdentity,
  formatBytes,
  formatDuration,
  effectiveRemediationState,
  groupSkippedFiles,
  relativePath,
  relativizeText,
  type FindingFilters,
  type FileOption,
  type GroupMode,
} from '../results/triage'
import type { PublicFinding, PublicScanResult, RemediationState, UserTarget } from '../types'
import FindingCard from './FindingCard'
import { IconEye, IconEyeOff } from './Icons'

const SKIPPED_FILE_PAGE_SIZE = 50

interface FindingValueControlProps {
  visible: boolean
  busy: boolean
  disabled: boolean
  error: string | null
  onToggle: () => void
}

export function FindingValueControl({
  visible,
  busy,
  disabled,
  error,
  onToggle,
}: FindingValueControlProps) {
  const description = busy
    ? 'Loading exact values from this local scan. Values will stay masked until every result is ready.'
    : visible
      ? 'Full sensitive values are visible. Hide them before screen sharing or stepping away.'
      : disabled
        ? 'Values stay masked until the scan and on-device AI checks finish.'
        : 'Values are masked by default. Reveal them temporarily to review exact matches.'

  return (
    <section
      className={`finding-values${visible ? ' finding-values--visible' : ''}`}
      aria-labelledby="finding-values-title"
      aria-busy={busy}
    >
      <div className="finding-values__copy">
        <span className="finding-values__icon" aria-hidden="true">
          {visible ? <IconEyeOff size={18} /> : <IconEye size={18} />}
        </span>
        <div>
          <h2 id="finding-values-title">Finding values</h2>
          <p id="finding-values-description">{description}</p>
        </div>
      </div>
      <button
        type="button"
        role="switch"
        aria-label="Full finding values"
        aria-checked={visible}
        aria-describedby="finding-values-description"
        disabled={disabled || busy}
        onClick={onToggle}
      >
        {busy ? 'Loading full values…' : visible ? 'Hide full values' : 'Show full values'}
      </button>
      {error && (
        <p className="finding-values__error" role="alert">
          {error}
        </p>
      )}
    </section>
  )
}

export function ScanMetadata({ result }: { result: PublicScanResult }) {
  const metadata = result.metadata
  return (
    <section className="scan-metadata" aria-label="Scan metadata">
      <dl>
        <div>
          <dt>Duration</dt>
          <dd>{formatDuration(metadata.duration_ms)}</dd>
        </div>
        <div>
          <dt>Files scanned</dt>
          <dd>{result.scanned_files.length}</dd>
        </div>
        <div>
          <dt>Data scanned</dt>
          <dd>{formatBytes(metadata.data_scanned_bytes)}</dd>
        </div>
        <div>
          <dt>Files skipped</dt>
          <dd>{result.skipped_files.length}</dd>
        </div>
        <div>
          <dt>Configured detectors</dt>
          <dd>{metadata.detector_count}</dd>
        </div>
        <div>
          <dt>On-device AI</dt>
          <dd>{metadata.ai_model ?? 'Not used'}</dd>
        </div>
      </dl>
      {metadata.selected_roots.length > 0 && (
        <details>
          <summary>
            Show full scan location{metadata.selected_roots.length === 1 ? '' : 's'}
          </summary>
          <ul>
            {metadata.selected_roots.map((root) => (
              <li key={root}>
                <code>{root}</code>
              </li>
            ))}
          </ul>
        </details>
      )}
    </section>
  )
}

interface TriageControlsProps {
  filters: FindingFilters
  groupMode: GroupMode
  categories: string[]
  detectors: string[]
  files: FileOption[]
  matchCount: number
  totalCount: number
  activeFilterCount: number
  userTargets?: UserTarget[]
  onFilter: <Key extends keyof FindingFilters>(key: Key, value: FindingFilters[Key]) => void
  onGroup: (mode: GroupMode) => void
  onReset: () => void
}

export function TriageControls({
  filters,
  groupMode,
  categories,
  detectors,
  files,
  matchCount,
  totalCount,
  activeFilterCount,
  userTargets = [],
  onFilter,
  onGroup,
  onReset,
}: TriageControlsProps) {
  return (
    <section className="triage-controls" aria-labelledby="triage-title">
      <div className="triage-controls__head">
        <div>
          <h2 id="triage-title">Triage results</h2>
          <p>
            {matchCount} of {totalCount} findings match
            {activeFilterCount ? ` ${activeFilterCount} active filter(s)` : ''}.
          </p>
        </div>
        <button type="button" disabled={activeFilterCount === 0} onClick={onReset}>
          Reset filters{activeFilterCount ? ` (${activeFilterCount})` : ''}
        </button>
      </div>
      <div className="triage-controls__grid">
        <label>
          Tier
          <select
            value={filters.tier}
            onChange={(event) => onFilter('tier', event.target.value as FindingFilters['tier'])}
          >
            <option value="all">All tiers</option>
            <option value="A">Tier A — Confirmed</option>
            <option value="B">Tier B — Double-check</option>
          </select>
        </label>
        <label>
          Category
          <select
            value={filters.category}
            onChange={(event) => onFilter('category', event.target.value)}
          >
            <option value="all">All categories</option>
            {categories.map((category) => (
              <option key={category} value={category}>
                {categoryName(category)}
              </option>
            ))}
          </select>
        </label>
        <label>
          Detector
          <select
            value={filters.detector}
            onChange={(event) => onFilter('detector', event.target.value)}
          >
            <option value="all">All detectors</option>
            {detectors.map((detector) => (
              <option key={detector} value={detector}>
                {detectorName(detector, userTargets)}
              </option>
            ))}
          </select>
        </label>
        <label>
          File
          <select value={filters.file} onChange={(event) => onFilter('file', event.target.value)}>
            <option value="all">All files</option>
            {files.map((file) => (
              <option key={file.value} value={file.value}>
                {file.label}
              </option>
            ))}
          </select>
        </label>
        <label>
          <span aria-hidden="true">Status</span>
          <select
            aria-label="Remediation status"
            value={filters.status}
            onChange={(event) => onFilter('status', event.target.value as FindingFilters['status'])}
          >
            <option value="all">All statuses</option>
            <option value="pending">Pending status</option>
            <option value="included">Included in plan</option>
            <option value="ignored">Ignored findings</option>
            <option value="read_only">Read-only status</option>
            <option value="decided">Decisions made</option>
          </select>
        </label>
        <label>
          <span aria-hidden="true">Capability</span>
          <select
            aria-label="Remediation capability"
            value={filters.rewrite}
            onChange={(event) =>
              onFilter('rewrite', event.target.value as FindingFilters['rewrite'])
            }
          >
            <option value="all">All findings</option>
            <option value="anonymizable">Anonymizable</option>
            <option value="read_only">Requires manual editing</option>
          </select>
        </label>
        <label>
          Group by
          <select value={groupMode} onChange={(event) => onGroup(event.target.value as GroupMode)}>
            <option value="tier">Tier</option>
            <option value="file">File</option>
            <option value="category">Category</option>
          </select>
        </label>
      </div>
    </section>
  )
}

interface BulkActionsProps {
  containerRef: RefObject<HTMLElement | null>
  selectedCount: number
  selectedIncludedCount: number
  visibleCount: number
  visibleTierACount: number
  visibleTierBCount: number
  allVisibleSelected: boolean
  allVisibleTierASelected: boolean
  allVisibleTierBSelected: boolean
  busy: boolean
  onToggleVisible: () => void
  onToggleTierA: () => void
  onToggleTierB: () => void
  onInclude: () => void
  onExclude: () => void
}

export function BulkActions({
  containerRef,
  selectedCount,
  selectedIncludedCount,
  visibleCount,
  visibleTierACount,
  visibleTierBCount,
  allVisibleSelected,
  allVisibleTierASelected,
  allVisibleTierBSelected,
  busy,
  onToggleVisible,
  onToggleTierA,
  onToggleTierB,
  onInclude,
  onExclude,
}: BulkActionsProps) {
  return (
    <div className="bulk-workflow">
      <section
        ref={containerRef}
        className="bulk-actions"
        aria-label="Bulk finding selection"
        tabIndex={-1}
      >
        <p role="status" aria-live="polite" aria-atomic="true">
          <span aria-hidden="true">
            <strong>{selectedCount}</strong> selected
          </span>
          <span className="visually-hidden">
            <strong>{selectedCount}</strong> actionable finding(s) selected across the result set.
          </span>
        </p>
        <div className="bulk-actions__buttons">
          <button
            type="button"
            aria-pressed={allVisibleSelected}
            aria-describedby="bulk-visible-selection-description"
            disabled={busy || visibleCount === 0}
            onClick={onToggleVisible}
          >
            Select all ({visibleCount})
          </button>
          <button
            type="button"
            aria-pressed={allVisibleTierASelected}
            aria-describedby="bulk-tier-a-selection-description"
            disabled={busy || visibleTierACount === 0}
            onClick={onToggleTierA}
          >
            Tier A ({visibleTierACount})
          </button>
          <button
            type="button"
            aria-pressed={allVisibleTierBSelected}
            aria-describedby="bulk-tier-b-selection-description"
            disabled={busy || visibleTierBCount === 0}
            onClick={onToggleTierB}
          >
            Tier B ({visibleTierBCount})
          </button>
        </div>
      </section>
      <div className="bulk-plan-actions" role="group" aria-label="Selected finding plan actions">
        <button
          type="button"
          className="bulk-plan-actions__primary"
          aria-describedby="bulk-include-description"
          disabled={busy || selectedCount === 0}
          onClick={onInclude}
        >
          Include ({selectedCount})
        </button>
        <button
          type="button"
          aria-describedby="bulk-exclude-description"
          disabled={busy || selectedIncludedCount === 0}
          onClick={onExclude}
        >
          Exclude ({selectedIncludedCount})
        </button>
      </div>
      <div className="visually-hidden">
        <span id="bulk-visible-selection-description">
          {allVisibleSelected ? 'Unselects' : 'Selects'} all visible actionable findings.
        </span>
        <span id="bulk-tier-a-selection-description">
          {allVisibleTierASelected ? 'Unselects' : 'Selects'} visible actionable Tier A findings.
        </span>
        <span id="bulk-tier-b-selection-description">
          {allVisibleTierBSelected ? 'Unselects' : 'Selects'} visible actionable Tier B findings.
        </span>
        <span id="bulk-include-description">
          Includes the selected actionable findings in the redaction plan.
        </span>
        <span id="bulk-exclude-description">
          Excludes the selected included {selectedIncludedCount === 1 ? 'finding' : 'findings'} from
          the redaction plan.
        </span>
      </div>
    </div>
  )
}

interface FindingSectionProps {
  title: string
  subtitle?: string
  tier?: 'A' | 'B'
  findings: PublicFinding[]
  roots: string[]
  fileLabels: Map<string, string>
  states: Record<string, RemediationState>
  revealedValues: Record<string, string>
  userTargets?: UserTarget[]
  selectedIds: Set<string>
  workflowBusy: boolean
  busyId: string | null
  onSelect: (finding: PublicFinding, selected: boolean) => void
  onInclude: (finding: PublicFinding) => void
  onExclude: (finding: PublicFinding) => void
  onIgnore: (finding: PublicFinding) => void
  onRestore: (finding: PublicFinding) => void
  onOpen: (finding: PublicFinding) => void
  action?: ReactNode
}

export function FindingSection({
  title,
  subtitle,
  tier,
  findings,
  roots,
  fileLabels,
  states,
  revealedValues,
  userTargets = [],
  selectedIds,
  workflowBusy,
  busyId,
  onSelect,
  onInclude,
  onExclude,
  onIgnore,
  onRestore,
  onOpen,
  action,
}: FindingSectionProps) {
  return (
    <section aria-label={title} className="tier">
      <div className="tier__head">
        <h2 className="tier__title">
          {tier && (
            <span className={`tier__badge tier__badge--${tier.toLowerCase()}`} aria-hidden="true">
              {tier}
            </span>
          )}
          {title}
          <span className="tier__count">{findings.length}</span>
        </h2>
        {action}
      </div>
      {subtitle && <p className="tier__sub">{subtitle}</p>}
      <ul className="findings">
        {findings.map((finding) => (
          <FindingCard
            key={finding.id}
            finding={finding}
            displayPath={
              fileLabels.get(fileIdentity(finding.file_path)) ??
              relativePath(finding.file_path, roots)
            }
            detectorLabel={detectorName(finding.detector_id, userTargets)}
            status={effectiveRemediationState(finding, states[finding.id])}
            revealedValue={revealedValues[finding.id]}
            selected={selectedIds.has(finding.id)}
            busy={busyId === finding.id}
            disabled={workflowBusy || busyId === finding.id}
            onSelect={onSelect}
            onInclude={onInclude}
            onExclude={onExclude}
            onIgnore={onIgnore}
            onRestore={onRestore}
            onOpen={onOpen}
          />
        ))}
      </ul>
    </section>
  )
}

export function SkippedFiles({ result }: { result: PublicScanResult }) {
  const [open, setOpen] = useState(false)
  const [visibleLimit, setVisibleLimit] = useState(SKIPPED_FILE_PAGE_SIZE)
  const countRef = useRef<HTMLParagraphElement>(null)
  const detailsRef = useRef<HTMLDetailsElement>(null)
  const focusSkippedPathAfterExpandRef = useRef<string | null>(null)
  const visibleSkippedFiles = result.skipped_files.slice(0, visibleLimit)
  const groups = open ? groupSkippedFiles(visibleSkippedFiles) : []
  const roots = result.metadata.selected_roots
  const fileLabels = new Map(
    buildFileOptions(
      result.skipped_files.map((file) => file.path),
      roots,
    ).map((option) => [option.value, option.label]),
  )

  useEffect(() => {
    const skippedPath = focusSkippedPathAfterExpandRef.current
    if (skippedPath === null) return
    const skippedItem = Array.from(
      detailsRef.current?.querySelectorAll<HTMLElement>('[data-skipped-path]') ?? [],
    ).find((element) => element.dataset.skippedPath === skippedPath)
    const focusDestination = skippedItem ?? countRef.current
    focusDestination?.focus()
    focusSkippedPathAfterExpandRef.current = null
  }, [visibleLimit])

  return (
    <details
      ref={detailsRef}
      className="skipped-files"
      onToggle={(event) => setOpen(event.currentTarget.open)}
    >
      <summary>
        Review {result.skipped_files.length} skipped file
        {result.skipped_files.length === 1 ? '' : 's'}
      </summary>
      {open && (
        <>
          <p>Skipped files were not inspected for sensitive data.</p>
          {groups.map((group) => (
            <section key={group.title}>
              <h2>
                {group.title} <span>{group.files.length}</span>
              </h2>
              <p>{group.advice}</p>
              <ul>
                {group.files.map((file) => (
                  <li key={file.path} data-skipped-path={file.path} tabIndex={-1}>
                    <details>
                      <summary>
                        {fileLabels.get(fileIdentity(file.path)) ?? relativePath(file.path, roots)}
                      </summary>
                      <code>{file.path}</code>
                    </details>
                    <span>{relativizeText(file.reason, roots)}</span>
                    <small>
                      Stage: {file.stage}
                      {file.rule ? ` · Rule: ${relativizeText(file.rule, roots)}` : ''}
                    </small>
                  </li>
                ))}
              </ul>
            </section>
          ))}
          <p ref={countRef} className="results-count" aria-live="polite" tabIndex={-1}>
            Showing {visibleSkippedFiles.length} of {result.skipped_files.length} skipped files.
          </p>
          {visibleSkippedFiles.length < result.skipped_files.length && (
            <button
              type="button"
              className="show-more-btn"
              onClick={() => {
                const nextLimit = Math.min(
                  visibleLimit + SKIPPED_FILE_PAGE_SIZE,
                  result.skipped_files.length,
                )
                focusSkippedPathAfterExpandRef.current =
                  result.skipped_files[visibleLimit]?.path ?? null
                setVisibleLimit(nextLimit)
              }}
            >
              Show up to{' '}
              {Math.min(SKIPPED_FILE_PAGE_SIZE, result.skipped_files.length - visibleLimit)} more
              skipped files
            </button>
          )}
        </>
      )}
    </details>
  )
}
