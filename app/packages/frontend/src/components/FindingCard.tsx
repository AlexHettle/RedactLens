import { displayRedactedPreview, findingSupportsAutomaticRedaction } from '../results/triage'
import type { PublicFinding, RemediationState } from '../types'
import { IconChevronDown, IconFolder, IconRedact } from './Icons'

export type FindingStatus = RemediationState

const supportingRelationshipLabels = {
  same_span: 'same location as this finding',
  suppressed: 'covered by this finding',
  overlap_chain: 'related overlapping location',
} as const

interface FindingCardProps {
  finding: PublicFinding
  displayPath: string
  detectorLabel: string
  status: FindingStatus
  revealedValue?: string
  selected: boolean
  busy: boolean
  disabled: boolean
  onSelect: (finding: PublicFinding, selected: boolean) => void
  onInclude: (finding: PublicFinding) => void
  onExclude: (finding: PublicFinding) => void
  onIgnore: (finding: PublicFinding) => void
  onRestore: (finding: PublicFinding) => void
  onOpen: (finding: PublicFinding) => void
}

export default function FindingCard({
  finding,
  displayPath,
  detectorLabel,
  status,
  revealedValue,
  selected,
  busy,
  disabled,
  onSelect,
  onInclude,
  onExclude,
  onIgnore,
  onRestore,
  onOpen,
}: FindingCardProps) {
  const maskedPreview = displayRedactedPreview(finding.redacted_preview)
  const findingContext = `finding ${maskedPreview} from ${displayPath}`
  const supportsRedaction = findingSupportsAutomaticRedaction(finding, status)

  function requestStateChange(action: (target: PublicFinding) => void) {
    action(finding)
  }

  return (
    <li
      className={`finding finding--${finding.tier.toLowerCase()} finding--${status} ${selected ? 'finding--selected' : ''}`}
      data-finding-id={finding.id}
      tabIndex={-1}
    >
      {supportsRedaction && status !== 'ignored' && (
        <label className="finding__select">
          <input
            type="checkbox"
            checked={selected}
            disabled={disabled}
            onChange={(event) => onSelect(finding, event.target.checked)}
          />
          <span className="visually-hidden">Select {findingContext}</span>
        </label>
      )}
      {supportsRedaction && status === 'ignored' && (
        <span className="finding__select finding__select--placeholder" aria-hidden="true" />
      )}
      <div className="finding__main">
        <details className="finding__details">
          <summary>
            <span
              className={`finding__value${revealedValue !== undefined ? ' finding__value--revealed' : ''}`}
            >
              {revealedValue ?? maskedPreview}
            </span>
            <span className="finding__type" title={detectorLabel}>
              {detectorLabel}
            </span>
            <span className="finding__expand">
              Details
              <IconChevronDown size={11} />
            </span>
          </summary>
          <div className="finding__body">
            <p>
              <strong>What this is:</strong> {finding.explanation}
            </p>
            <p>
              <strong>Why it matters:</strong> {finding.risk_lesson}
            </p>
            <p className="finding__evidence">
              Detector ID <code>{finding.detector_id}</code>.
            </p>
            {finding.supporting_detections.length > 0 && (
              <p className="finding__evidence">
                <strong>Supporting evidence:</strong>{' '}
                {finding.supporting_detections.map((detection, index) => (
                  <span key={detection.detector_id}>
                    {index > 0 ? '; ' : ''}
                    {detection.description} ({supportingRelationshipLabels[detection.relationship]})
                  </span>
                ))}
                .
              </p>
            )}
            {supportsRedaction &&
              (finding.detector_id.startsWith('user_target_desc_') ||
                finding.detector_id.startsWith('custom_description')) && (
                <p>
                  <strong>Redaction scope:</strong> This AI description match covers the complete
                  passage shown. Including it masks that entire passage.
                </p>
              )}
            {!supportsRedaction && (
              <p>
                <strong>Why is this read-only?</strong>{' '}
                {finding.detector_id.startsWith('user_target_desc_') ||
                finding.detector_id.startsWith('custom_description')
                  ? 'This description rule identified a potentially sensitive passage, but its source format or location cannot be rewritten safely.'
                  : 'RedactLens can detect this value, but cannot safely rewrite its source format or location.'}{' '}
                Show the file in its folder, then edit it yourself.
              </p>
            )}
            <p className="finding__full-path">
              <strong>Full path:</strong> <code>{finding.file_path}</code>
            </p>
          </div>
        </details>
        <div className="finding__loc">
          <span className="finding__path">
            {finding.location
              ? `${displayPath} · ${finding.location}`
              : `${displayPath}:${finding.line}`}
          </span>
          <button
            type="button"
            className="finding__open"
            disabled={disabled}
            aria-label={`Show ${displayPath} in folder for ${maskedPreview}`}
            onClick={() => onOpen(finding)}
          >
            <IconFolder size={12} />
            Show in folder
          </button>
        </div>
      </div>

      {supportsRedaction && status === 'pending' ? (
        <div
          className="finding__aside finding__actions"
          role="group"
          aria-label={`Actions for ${findingContext}`}
        >
          <button
            type="button"
            className="finding__anon"
            disabled={disabled}
            aria-label={`Include ${findingContext} in redaction plan`}
            onClick={() => requestStateChange(onInclude)}
          >
            <IconRedact size={14} />
            {busy ? 'Updating…' : 'Include in redaction plan'}
          </button>
          <button
            type="button"
            className="finding__ignore"
            disabled={disabled}
            aria-label={`Ignore ${findingContext}`}
            onClick={() => requestStateChange(onIgnore)}
          >
            Ignore
          </button>
        </div>
      ) : supportsRedaction && status === 'included' ? (
        <div className="finding__aside">
          <span className="status-badge status-badge--included">
            <span aria-hidden="true">✓</span>
            <span>Included</span>
          </span>
          <button
            type="button"
            className="finding__undo"
            disabled={disabled}
            aria-label={`Exclude ${findingContext} from redaction plan`}
            onClick={() => requestStateChange(onExclude)}
          >
            Exclude
          </button>
        </div>
      ) : supportsRedaction && status === 'ignored' ? (
        <div className="finding__aside">
          <span className="status-badge status-badge--ignored">Ignored</span>
          <button
            type="button"
            className="finding__undo"
            disabled={disabled}
            aria-label={`Return ${findingContext} to pending`}
            onClick={() => requestStateChange(onRestore)}
          >
            Return to pending
          </button>
        </div>
      ) : (
        <div className="finding__aside">
          <span className="status-badge status-badge--read-only">Read-only</span>
        </div>
      )}
    </li>
  )
}
