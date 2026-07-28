import { useEffect, useRef, useState } from 'react'
import { relativePath, relativizeText } from '../results/triage'
import type { GeneratedOutputDetails, RemediationOutputMode, RemediationPlan } from '../types'

const REVIEW_PAGE_SIZE = 50

interface RemediationReviewProps {
  plan: RemediationPlan
  outputs: GeneratedOutputDetails[]
  roots: string[]
  generating: boolean
  generationMessage: string
  generationMessageRole: 'status' | 'alert'
  planMutationPending: boolean
  onClose: () => void
  onGenerate: (outputMode: RemediationOutputMode) => void
  onOpenOutput: (findingId: string, outputPath: string) => void
}

export default function RemediationReview({
  plan,
  outputs,
  roots,
  generating,
  generationMessage,
  generationMessageRole,
  planMutationPending,
  onClose,
  onGenerate,
  onOpenOutput,
}: RemediationReviewProps) {
  const [outputMode, setOutputMode] = useState<RemediationOutputMode>('copy')
  const [replacementConfirmed, setReplacementConfirmed] = useState(false)
  const replacingOriginals = outputMode === 'replace_original'
  const needsRegeneration = plan.files.some((file) => file.output_state === 'regeneration_required')
  const hasConflict =
    !replacingOriginals && plan.files.some((file) => file.output_state === 'conflict')
  const sourceWasAlreadyReplaced = plan.files.some(
    (file) => file.source_path === file.output_path && file.output_state === 'current',
  )
  const canGenerate = replacingOriginals
    ? plan.selected_finding_count > 0 && !sourceWasAlreadyReplaced
    : plan.can_generate
  const [fileLimit, setFileLimit] = useState(REVIEW_PAGE_SIZE)
  const [outputLimit, setOutputLimit] = useState(REVIEW_PAGE_SIZE)
  const dialogRef = useRef<HTMLDivElement>(null)
  const focusFileAfterExpandRef = useRef<string | null>(null)
  const focusOutputAfterExpandRef = useRef<string | null>(null)
  const visiblePlanFiles = plan.files.slice(0, fileLimit)
  const visibleOutputs = outputs.slice(0, outputLimit)
  const statusMessage = generationMessageRole === 'status' ? generationMessage : ''
  const alertMessage = generationMessageRole === 'alert' ? generationMessage : ''
  useEffect(() => dialogRef.current?.focus(), [])

  useEffect(() => {
    const sourcePath = focusFileAfterExpandRef.current
    if (sourcePath === null) return
    const fileRow = Array.from(
      dialogRef.current?.querySelectorAll<HTMLElement>('[data-review-file]') ?? [],
    ).find((element) => element.dataset.reviewFile === sourcePath)
    fileRow?.focus()
    focusFileAfterExpandRef.current = null
  }, [fileLimit])

  useEffect(() => {
    const sourcePath = focusOutputAfterExpandRef.current
    if (sourcePath === null) return
    const outputRow = Array.from(
      dialogRef.current?.querySelectorAll<HTMLElement>('[data-review-output]') ?? [],
    ).find((element) => element.dataset.reviewOutput === sourcePath)
    outputRow?.focus()
    focusOutputAfterExpandRef.current = null
  }, [outputLimit])

  useEffect(() => {
    const dialog = dialogRef.current
    if (!dialog) return
    function keepFocusInDialog(event: KeyboardEvent) {
      if (event.key === 'Escape') {
        event.preventDefault()
        onClose()
        return
      }
      if (event.key !== 'Tab') return
      const focusable = Array.from(
        dialog?.querySelectorAll<HTMLElement>(
          'button:not([disabled]), a[href], input:not([disabled]), select:not([disabled]), summary, [tabindex]:not([tabindex="-1"])',
        ) ?? [],
      ).filter((element) => !element.hasAttribute('hidden'))
      if (focusable.length === 0) {
        event.preventDefault()
        dialog?.focus()
        return
      }
      const first = focusable[0]
      const last = focusable[focusable.length - 1]
      if (document.activeElement === dialog) {
        event.preventDefault()
        const boundary = event.shiftKey ? last : first
        boundary.focus()
      } else if (event.shiftKey && document.activeElement === first) {
        event.preventDefault()
        last.focus()
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault()
        first.focus()
      }
    }
    dialog.addEventListener('keydown', keepFocusInDialog)
    return () => dialog.removeEventListener('keydown', keepFocusInDialog)
  }, [onClose])

  return (
    <div className="remediation-review-backdrop">
      <div
        ref={dialogRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby="remediation-review-title"
        aria-describedby="remediation-review-description"
        className="remediation-review"
        tabIndex={-1}
      >
        <div className="remediation-review__head">
          <div>
            <p className="remediation-review__eyebrow">Review before writing</p>
            <h2 id="remediation-review-title">Choose how to save redacted files</h2>
          </div>
          <button type="button" className="remediation-review__close" onClick={onClose}>
            Close review
          </button>
        </div>
        <p id="remediation-review-description">
          RedactLens rebuilds only files with selected findings, once each from their verified
          originals. Choose whether to preserve those originals or replace them.
        </p>
        <fieldset
          className="output-method"
          disabled={generating || planMutationPending || sourceWasAlreadyReplaced}
        >
          <legend>Output method</legend>
          <label
            htmlFor="remediation-output-copy"
            aria-label="Create redacted copies (recommended)"
            className={`output-method__option ${
              outputMode === 'copy' ? 'output-method__option--selected' : ''
            }`}
          >
            <input
              id="remediation-output-copy"
              type="radio"
              name="remediation-output-method"
              value="copy"
              checked={outputMode === 'copy'}
              onChange={() => {
                setOutputMode('copy')
                setReplacementConfirmed(false)
              }}
            />
            <span>
              <strong>Create redacted copies</strong>
              <small>Recommended · Keeps every original file unchanged.</small>
            </span>
          </label>
          <label
            htmlFor="remediation-output-replace"
            aria-label="Replace original files"
            className={`output-method__option ${
              replacingOriginals ? 'output-method__option--selected' : ''
            }`}
          >
            <input
              id="remediation-output-replace"
              type="radio"
              name="remediation-output-method"
              value="replace_original"
              checked={replacingOriginals}
              onChange={() => setOutputMode('replace_original')}
            />
            <span>
              <strong>Replace original files</strong>
              <small>Permanently replaces the selected originals after verification.</small>
            </span>
          </label>
        </fieldset>
        {sourceWasAlreadyReplaced ? (
          <p className="replacement-warning" role="status">
            The originals were replaced and verified. Run a new scan before making additional
            changes.
          </p>
        ) : (
          replacingOriginals && (
            <div className="replacement-warning">
              <strong>This cannot be undone.</strong>
              <p>
                Only selected findings will be anonymized. Close files in other apps before
                continuing.
              </p>
              <label>
                <input
                  type="checkbox"
                  checked={replacementConfirmed}
                  onChange={(event) => setReplacementConfirmed(event.target.checked)}
                />
                I understand that the original files will be permanently replaced.
              </label>
            </div>
          )
        )}
        <p
          className={statusMessage ? 'generation-status' : 'visually-hidden'}
          role="status"
          aria-live="polite"
          aria-atomic="true"
        >
          {statusMessage}
        </p>
        <p
          className={
            alertMessage ? 'generation-status generation-status--error' : 'visually-hidden'
          }
          role="alert"
          aria-live="assertive"
          aria-atomic="true"
        >
          {alertMessage}
        </p>
        <ul className="remediation-files">
          {visiblePlanFiles.map((file) => {
            const displayedPath = replacingOriginals ? file.source_path : file.output_path
            const originalWasReplaced =
              file.source_path === file.output_path && file.output_state === 'current'
            return (
              <li key={file.source_path} data-review-file={file.source_path} tabIndex={-1}>
                <code>{relativePath(displayedPath, roots)}</code>
                <details>
                  <summary>Show full {replacingOriginals ? 'original' : 'output'} path</summary>
                  <code>{displayedPath}</code>
                </details>
                <span>
                  {file.included_finding_ids.length} selected ·{' '}
                  {originalWasReplaced
                    ? 'original was replaced and verified'
                    : replacingOriginals
                      ? 'will replace the original after verification'
                      : file.output_state === 'current'
                        ? 'verified copy is current'
                        : file.output_state === 'regeneration_required'
                          ? 'regeneration required'
                          : file.output_state === 'obsolete'
                            ? 'obsolete; no findings are selected for this copy'
                            : file.output_state === 'conflict'
                              ? 'conflict; changed or untrusted output will not be overwritten'
                              : 'not created yet'}
                </span>
                {file.output_state === 'current' && file.included_finding_ids[0] && (
                  <button
                    type="button"
                    aria-label={`Show ${
                      originalWasReplaced ? 'replaced original' : 'redacted copy'
                    } ${relativePath(file.output_path, roots)} in folder`}
                    onClick={() => onOpenOutput(file.included_finding_ids[0], file.output_path)}
                  >
                    Show {originalWasReplaced ? 'replaced file' : 'redacted copy'} in folder
                  </button>
                )}
              </li>
            )
          })}
        </ul>
        <p className="results-count" aria-live="polite">
          Showing {visiblePlanFiles.length} of {plan.files.length} proposed files.
        </p>
        {visiblePlanFiles.length < plan.files.length && (
          <button
            type="button"
            className="show-more-btn"
            onClick={() => {
              focusFileAfterExpandRef.current = plan.files[fileLimit]?.source_path ?? null
              setFileLimit((limit) => Math.min(limit + REVIEW_PAGE_SIZE, plan.files.length))
            }}
          >
            Show up to {Math.min(REVIEW_PAGE_SIZE, plan.files.length - fileLimit)} more proposed
            files
          </button>
        )}
        {visibleOutputs.map((output) => (
          <section
            className="verification-note"
            key={output.source_path}
            data-review-output={output.source_path}
            tabIndex={-1}
          >
            <p>
              <strong>
                {output.source_path === output.output_path
                  ? 'Verified replacement:'
                  : 'Verified output:'}
              </strong>{' '}
              selected values were removed and the file was read back successfully.
            </p>
            <p>
              <strong>Output:</strong> <code>{relativePath(output.output_path, roots)}</code>
            </p>
            <p>
              <strong>Source fingerprint:</strong>{' '}
              <code>{output.source_fingerprint.sha256.slice(0, 12)}…</code>
            </p>
            {output.rescan_status === 'completed' ? (
              <p>
                <strong>Output rescan completed:</strong>{' '}
                {output.remaining_finding_count ?? 'unknown'} remaining finding(s), including{' '}
                {output.remaining_tier_a_count ?? 'unknown'} Tier A. This is review evidence, not a
                guarantee of safety.
              </p>
            ) : (
              <p role="alert">
                <strong>Output rescan failed:</strong> remaining finding counts are unavailable.
                Review the redacted copy manually before sharing it.
              </p>
            )}
            {output.warnings.length > 0 && (
              <>
                <p>
                  <strong>Warnings:</strong>
                </p>
                <ul>
                  {output.warnings.map((warning) => (
                    <li key={warning}>{relativizeText(warning, roots)}</li>
                  ))}
                </ul>
              </>
            )}
          </section>
        ))}
        {outputs.length > 0 && (
          <>
            <p className="results-count" aria-live="polite">
              Showing {visibleOutputs.length} of {outputs.length} output evidence records.
            </p>
            {visibleOutputs.length < outputs.length && (
              <button
                type="button"
                className="show-more-btn"
                onClick={() => {
                  focusOutputAfterExpandRef.current = outputs[outputLimit]?.source_path ?? null
                  setOutputLimit((limit) => Math.min(limit + REVIEW_PAGE_SIZE, outputs.length))
                }}
              >
                Show up to {Math.min(REVIEW_PAGE_SIZE, outputs.length - outputLimit)} more output
                evidence records
              </button>
            )}
          </>
        )}
        <button
          type="button"
          className={`generate-btn ${replacingOriginals ? 'generate-btn--danger' : ''}`}
          disabled={
            !canGenerate ||
            hasConflict ||
            generating ||
            planMutationPending ||
            (replacingOriginals && !replacementConfirmed)
          }
          onClick={() => onGenerate(outputMode)}
        >
          {generating
            ? replacingOriginals
              ? 'Replacing and verifying…'
              : 'Creating and verifying…'
            : replacingOriginals
              ? `Replace ${plan.affected_file_count} original ${
                  plan.affected_file_count === 1 ? 'file' : 'files'
                }`
              : needsRegeneration
                ? 'Regenerate redacted copies'
                : 'Create redacted copies'}
        </button>
      </div>
    </div>
  )
}
