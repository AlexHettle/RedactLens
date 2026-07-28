import { useEffect, useRef, useState } from 'react'
import {
  buildFileOptions,
  detectorName,
  displayRedactedPreview,
  fileIdentity,
  fileName,
  relativePath,
  relativizeText,
} from '../results/triage'
import type { PublicScanResult, ScanStage, UserTarget } from '../types'
import { IconShield } from './Icons'

interface ScanningScreenProps {
  target: string
  scan: PublicScanResult | null
  connectionError: string | null
  cancelError: string | null
  isRecovering: boolean
  isCancelling: boolean
  userTargets?: UserTarget[]
  onCancel: () => void
  onRetryConnection: () => void
}

const STAGE_LABELS: Record<ScanStage, string> = {
  pending: 'Preparing the scan…',
  discovery: 'Discovering files…',
  extraction: 'Reading and extracting the current file…',
  detection: 'Checking the current file…',
  consolidation: 'Combining related findings…',
  ai_refinement: 'Refining findings with on-device AI…',
  finalizing: 'Finalizing the scan summary…',
  complete: 'Scan complete.',
  cancelled: 'Scan cancelled.',
  failed: 'Scan failed.',
  timed_out: 'Scan timed out.',
}

const LIVE_FINDING_LIMIT = 5
const TERMINAL_BATCH_SIZE = 50

function useThrottledStatus(value: string, urgent: boolean): string {
  const [announced, setAnnounced] = useState(value)
  const pendingRef = useRef(value)
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null)

  useEffect(() => {
    pendingRef.current = value
    if (urgent && timerRef.current) {
      clearTimeout(timerRef.current)
      timerRef.current = null
    }
    if (!timerRef.current) {
      timerRef.current = setTimeout(
        () => {
          timerRef.current = null
          setAnnounced(pendingRef.current)
        },
        urgent ? 0 : 750,
      )
    }
  }, [urgent, value])

  useEffect(
    () => () => {
      if (timerRef.current) clearTimeout(timerRef.current)
    },
    [],
  )

  return announced
}

export default function ScanningScreen({
  target,
  scan,
  connectionError,
  cancelError,
  isRecovering,
  isCancelling,
  userTargets = [],
  onCancel,
  onRetryConnection,
}: ScanningScreenProps) {
  const headingRef = useRef<HTMLHeadingElement>(null)
  const progress = scan?.progress
  const terminal = scan ? ['cancelled', 'failed', 'timed_out'].includes(scan.state) : false
  const wasTerminalRef = useRef(terminal)
  const terminalFindingListRef = useRef<HTMLUListElement>(null)
  const terminalSkipListRef = useRef<HTMLUListElement>(null)
  const pendingFindingFocusIndexRef = useRef<number | null>(null)
  const pendingSkipFocusIndexRef = useRef<number | null>(null)
  const [terminalFindingLimit, setTerminalFindingLimit] = useState(TERMINAL_BATCH_SIZE)
  const [terminalSkipLimit, setTerminalSkipLimit] = useState(TERMINAL_BATCH_SIZE)
  const cancellationPending = isCancelling || scan?.state === 'cancelling'
  const percent = progress?.percent ?? 0
  const total = progress?.total_files
  const completed = progress?.completed_files ?? 0
  const findings = scan?.findings.length ?? 0
  const skipped = progress?.skipped_files ?? 0
  const stageLabel = terminal
    ? 'These are partial results and must not be treated as a complete scan.'
    : cancellationPending
      ? 'Cancellation requested. Waiting for RedactLens to stop safely.'
      : STAGE_LABELS[progress?.stage ?? 'pending']
  const liveSummary = `${stageLabel} ${
    total === null || total === undefined
      ? 'Discovering files.'
      : `${completed} of ${total} files completed.`
  } ${findings} ${findings === 1 ? 'finding' : 'findings'}. ${skipped} skipped.${
    isRecovering ? ' Reconnecting to live scan updates.' : ''
  }`
  const announcedSummary = useThrottledStatus(
    liveSummary,
    terminal || Boolean(connectionError) || Boolean(cancelError),
  )
  const roots = scan?.metadata.selected_roots ?? []
  const displayedFindings = scan
    ? terminal
      ? scan.findings.slice(0, terminalFindingLimit)
      : scan.findings.slice(-LIVE_FINDING_LIMIT)
    : []
  const displayedSkips = terminal ? (scan?.skipped_files.slice(0, terminalSkipLimit) ?? []) : []
  const findingFileLabels = new Map(
    buildFileOptions(
      (terminal ? scan?.findings : displayedFindings)?.map((finding) => finding.file_path) ?? [],
      roots,
    ).map((option) => [option.value, option.label]),
  )
  const skippedFileLabels = new Map(
    buildFileOptions(
      terminal ? (scan?.skipped_files.map((file) => file.path) ?? []) : [],
      roots,
    ).map((option) => [option.value, option.label]),
  )

  useEffect(() => {
    if (terminal && !wasTerminalRef.current) headingRef.current?.focus()
    wasTerminalRef.current = terminal
  }, [terminal])

  useEffect(() => {
    const focusIndex = pendingFindingFocusIndexRef.current
    if (focusIndex === null || displayedFindings.length <= focusIndex) return
    const firstNewFinding = terminalFindingListRef.current?.children.item(focusIndex)
    if (firstNewFinding instanceof HTMLElement) firstNewFinding.focus()
    pendingFindingFocusIndexRef.current = null
  }, [displayedFindings.length])

  useEffect(() => {
    const focusIndex = pendingSkipFocusIndexRef.current
    if (focusIndex === null || displayedSkips.length <= focusIndex) return
    const firstNewSkip = terminalSkipListRef.current?.children.item(focusIndex)
    if (firstNewSkip instanceof HTMLElement) firstNewSkip.focus()
    pendingSkipFocusIndexRef.current = null
  }, [displayedSkips.length])

  function showMoreTerminalFindings() {
    if (!scan) return
    pendingFindingFocusIndexRef.current = displayedFindings.length
    const nextLimit = Math.min(scan.findings.length, terminalFindingLimit + TERMINAL_BATCH_SIZE)
    setTerminalFindingLimit(nextLimit)
  }

  function showMoreTerminalSkips() {
    if (!scan) return
    pendingSkipFocusIndexRef.current = displayedSkips.length
    const nextLimit = Math.min(scan.skipped_files.length, terminalSkipLimit + TERMINAL_BATCH_SIZE)
    setTerminalSkipLimit(nextLimit)
  }

  return (
    <section aria-labelledby="scanning-heading" className="scanning">
      <div className="scanning__emblem" aria-hidden="true">
        <span className="scanning__ring" />
        <span className="scanning__ring scanning__ring--delayed" />
        <div className="scanning__shield">
          <IconShield size={38} />
        </div>
      </div>
      <h1 ref={headingRef} id="scanning-heading" className="scanning__title" tabIndex={-1}>
        {terminal ? 'Scan stopped before finishing' : 'Looking through your files…'}
      </h1>
      <p className="scanning__sub">{stageLabel}</p>
      <p className="visually-hidden" role="status" aria-live="polite" aria-atomic="true">
        {announcedSummary}
      </p>
      {scan?.error && (
        <p role="alert" className="warning-banner">
          {scan.error.message}
        </p>
      )}
      {cancelError && (
        <p role="alert" className="warning-banner">
          {cancelError}
        </p>
      )}
      {connectionError && !cancellationPending && (
        <p role="alert" className="warning-banner">
          {connectionError}
        </p>
      )}
      <div
        className="progress"
        role="progressbar"
        aria-label="Scan progress"
        aria-valuenow={total === null || total === undefined ? undefined : Math.round(percent)}
        aria-valuemin={0}
        aria-valuemax={100}
        aria-valuetext={
          total === null || total === undefined
            ? 'Discovering files'
            : `${progress?.completed_files ?? 0} of ${total} files completed`
        }
      >
        <div
          className={`progress__fill ${total === null || total === undefined ? 'progress__fill--indeterminate' : ''}`}
          style={{ width: total === null || total === undefined ? '28%' : `${percent}%` }}
        />
      </div>
      <div className="scanning__stats" aria-label="Live scan totals">
        <span>
          <strong>{completed}</strong> / {total ?? '…'} files
        </span>
        <span>
          <strong>{findings}</strong> findings
        </span>
        <span>
          <strong>{skipped}</strong> skipped
        </span>
      </div>
      {target && (
        <p className="scanning__file">
          <span className="scanning__dot" aria-hidden="true" />
          <span className="scanning__file-name">Scan target: {fileName(target)}</span>
        </p>
      )}
      {scan && scan.findings.length > 0 && (
        <section className="partial-findings" aria-labelledby="partial-findings-title">
          <h2 id="partial-findings-title">Findings so far {terminal ? '— incomplete' : ''}</h2>
          <ul ref={terminalFindingListRef}>
            {displayedFindings.map((finding) => (
              <li key={finding.id} tabIndex={terminal ? -1 : undefined}>
                <span
                  className={`tier__badge tier__badge--${finding.tier.toLowerCase()}`}
                  aria-hidden="true"
                >
                  {finding.tier}
                </span>
                <div className="partial-findings__content">
                  <div className="partial-findings__summary">
                    <code>{displayRedactedPreview(finding.redacted_preview)}</code>
                    <span
                      className={`partial-findings__type partial-findings__type--${finding.tier.toLowerCase()}`}
                      title={detectorName(finding.detector_id, userTargets)}
                    >
                      {detectorName(finding.detector_id, userTargets)}
                    </span>
                  </div>
                  <span className="partial-findings__location">
                    {findingFileLabels.get(fileIdentity(finding.file_path)) ??
                      relativePath(finding.file_path, roots)}{' '}
                    · {finding.location ?? `line ${finding.line}`}
                  </span>
                  {terminal && (
                    <details>
                      <summary>Show full path for {fileName(finding.file_path)}</summary>
                      <code>{finding.file_path}</code>
                    </details>
                  )}
                </div>
              </li>
            ))}
          </ul>
          {terminal ? (
            <>
              <p aria-live="polite">
                Showing {displayedFindings.length} of {scan.findings.length} retained findings.
              </p>
              {displayedFindings.length < scan.findings.length && (
                <button type="button" className="show-more-btn" onClick={showMoreTerminalFindings}>
                  Show up to{' '}
                  {Math.min(TERMINAL_BATCH_SIZE, scan.findings.length - displayedFindings.length)}{' '}
                  more retained findings
                </button>
              )}
            </>
          ) : (
            scan.findings.length > LIVE_FINDING_LIMIT && (
              <p>Showing the {LIVE_FINDING_LIMIT} most recent findings.</p>
            )
          )}
        </section>
      )}

      {terminal && scan && scan.skipped_files.length > 0 && (
        <details className="partial-findings">
          <summary>
            Review {scan.skipped_files.length} skipped file
            {scan.skipped_files.length === 1 ? '' : 's'} from this incomplete scan
          </summary>
          <p>Skipped files were not inspected for sensitive data.</p>
          <ul ref={terminalSkipListRef}>
            {displayedSkips.map((skippedFile) => (
              <li
                key={`${skippedFile.path}:${skippedFile.code}:${skippedFile.stage}`}
                tabIndex={-1}
              >
                <strong>
                  {skippedFileLabels.get(fileIdentity(skippedFile.path)) ??
                    relativePath(skippedFile.path, roots)}
                </strong>
                <span>{relativizeText(skippedFile.reason, roots)}</span>
                <details>
                  <summary>Show full path for {fileName(skippedFile.path)}</summary>
                  <code>{skippedFile.path}</code>
                  <small>
                    Stage: {skippedFile.stage}
                    {skippedFile.rule ? ` · Rule: ${relativizeText(skippedFile.rule, roots)}` : ''}
                  </small>
                </details>
              </li>
            ))}
          </ul>
          <p aria-live="polite">
            Showing {displayedSkips.length} of {scan.skipped_files.length} skipped files.
          </p>
          {displayedSkips.length < scan.skipped_files.length && (
            <button type="button" className="show-more-btn" onClick={showMoreTerminalSkips}>
              Show up to{' '}
              {Math.min(TERMINAL_BATCH_SIZE, scan.skipped_files.length - displayedSkips.length)}{' '}
              more skipped files
            </button>
          )}
        </details>
      )}

      <p className="scanning__note">
        {terminal
          ? 'Run the scan again to obtain actionable results.'
          : 'Everything stays on this device.'}
      </p>
      <div className="scanning__actions">
        {connectionError && !terminal && !cancellationPending && (
          <button
            type="button"
            className="btn-outline"
            onClick={onRetryConnection}
            disabled={isRecovering}
          >
            {isRecovering ? 'Reconnecting…' : 'Retry live connection'}
          </button>
        )}
        <button
          type="button"
          className="btn-outline"
          onClick={onCancel}
          disabled={!terminal && cancellationPending && !cancelError}
        >
          {terminal
            ? 'Back to setup'
            : cancelError
              ? 'Retry cancellation'
              : cancellationPending
                ? 'Cancelling…'
                : 'Cancel'}
        </button>
      </div>
    </section>
  )
}
