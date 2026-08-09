import { EMPTY_FILTERS, relativePath } from '../results/triage'
import type { PublicScanResult, UserTarget } from '../types'
import { IconDownload } from './Icons'
import RemediationReview from './RemediationReview'
import {
  BulkActions,
  FindingSection,
  FindingValueControl,
  ScanMetadata,
  SkippedFiles,
  TriageControls,
} from './ResultsScreenSections'
import Spinner from './Spinner'
import { RESULTS_PAGE_SIZE, useResultsScreenController } from './useResultsScreenController'

const REFINING_BANNER_MESSAGE = 'Double-checking a few more with on-device AI…'

interface ResultsScreenProps {
  result: PublicScanResult
  isRefining: boolean
  refineError: string | null
  userTargets?: UserTarget[]
  onStartOver: () => void
  onSessionExpired: (message?: string) => void
  onToast?: (message: string) => void
}

export default function ResultsScreen({
  result,
  isRefining,
  refineError,
  userTargets = [],
  onStartOver,
  onSessionExpired,
  onToast,
}: ResultsScreenProps) {
  const {
    actionError,
    actionErrorRef,
    activeFilterCount,
    additionalReadOnlyFileCount,
    allHandled,
    bulkActionsRef,
    bulkBusy,
    busyId,
    categoryOptions,
    closeReview,
    conflictingOutputs,
    detectorOptions,
    downloadReport,
    fileLabels,
    fileOptions,
    filteredFindings,
    filters,
    fullValuesVisible,
    focusFindingAfterExpandRef,
    generating,
    generationMessage,
    generationMessageRole,
    groupedFindings,
    groupMode,
    handleGenerate,
    handleIncludeTier,
    handleOpen,
    handleOpenOutput,
    handleSelectedState,
    handledCount,
    hasMixedRemediationFiles,
    incomplete,
    leaveResults,
    liveMessage,
    obsoleteOutputs,
    onlyReadOnly,
    openFreshReview,
    outputs,
    pendingA,
    pendingB,
    plan,
    planMutationPending,
    readOnlyFilePreview,
    readOnlyFindingCount,
    readOnlyFiles,
    reconciling,
    revealedValues,
    revealValuesBusy,
    revealValuesError,
    refiningLiveRegionRef,
    regenerationRequired,
    reportBusy,
    retainedArtifactPaths,
    reviewButtonRef,
    reviewOpen,
    resultsCountRef,
    resultsHeadingRef,
    resultsSectionRef,
    roots,
    selectedActionable,
    selectedIds,
    selectedIncluded,
    setFilters,
    setFindingState,
    setGroupMode,
    setVisibleLimit,
    states,
    tierA,
    tierB,
    toggleFindings,
    toggleFinding,
    toggleFullValues,
    updateFilter,
    visibleActionable,
    visibleFindings,
    visibleLimit,
    visibleTierA,
    visibleTierB,
  } = useResultsScreenController({
    result,
    isRefining,
    onStartOver,
    onSessionExpired,
    onToast,
  })
  const noFilesInspected = !incomplete && result.scanned_files.length === 0
  const allVisibleSelected =
    visibleActionable.length > 0 &&
    visibleActionable.every((finding) => selectedIds.has(finding.id))
  const allVisibleTierASelected =
    visibleTierA.length > 0 && visibleTierA.every((finding) => selectedIds.has(finding.id))
  const allVisibleTierBSelected =
    visibleTierB.length > 0 && visibleTierB.every((finding) => selectedIds.has(finding.id))
  const resultListBusy = bulkBusy || generating || reconciling || isRefining || incomplete
  const quietExportLock =
    busyId !== null && !bulkBusy && !generating && !reconciling && !isRefining && !incomplete

  function tierBulkAction(tier: 'A' | 'B' | undefined) {
    if (groupMode !== 'tier' || tier === undefined) return null
    const pendingCount = tier === 'A' ? pendingA.length : pendingB.length
    if (pendingCount === 0) return null
    return (
      <button
        type="button"
        className={`bulk-btn bulk-btn--${tier.toLowerCase()}`}
        disabled={resultListBusy}
        aria-disabled={planMutationPending || undefined}
        onClick={() => void handleIncludeTier(tier)}
      >
        {bulkBusy ? 'Including' : 'Include'} all pending writable Tier {tier} findings across all
        results ({pendingCount}){bulkBusy ? '…' : ''}
      </button>
    )
  }

  return (
    <section ref={resultsSectionRef} aria-labelledby="results-heading">
      <h1 ref={resultsHeadingRef} id="results-heading" className="results__title" tabIndex={-1}>
        Here&rsquo;s what I found
      </h1>
      <p className="results__sub">
        A starting point, not a guarantee — detection can miss things, so give it a review.
      </p>

      <ScanMetadata result={result} />

      <div aria-live="polite" className="visually-hidden">
        {liveMessage}
      </div>
      <div ref={refiningLiveRegionRef} aria-live="polite" className="visually-hidden" />
      {actionError && (
        <p ref={actionErrorRef} role="alert" className="error-banner" tabIndex={-1}>
          {actionError}
        </p>
      )}

      <div className="results__layout">
        <aside className="results__side" aria-label="Scan summary and actions">
          <div className="stats">
            <button
              type="button"
              className="stat"
              aria-labelledby="tier-a-count tier-a-label"
              aria-describedby="tier-a-filter-description"
              aria-pressed={filters.tier === 'A'}
              onClick={() => updateFilter('tier', filters.tier === 'A' ? 'all' : 'A')}
            >
              <span id="tier-a-count" className="stat__num stat__num--a">
                {tierA.length}
              </span>
              <span id="tier-a-label" className="stat__label">
                Confirmed
              </span>
            </button>
            <button
              type="button"
              className="stat"
              aria-labelledby="tier-b-count tier-b-label"
              aria-describedby="tier-b-filter-description"
              aria-pressed={filters.tier === 'B'}
              onClick={() => updateFilter('tier', filters.tier === 'B' ? 'all' : 'B')}
            >
              <span id="tier-b-count" className="stat__num stat__num--b">
                {tierB.length}
              </span>
              <span id="tier-b-label" className="stat__label">
                Double-check
              </span>
            </button>
            <button
              type="button"
              className="stat"
              aria-labelledby="decided-count decided-label"
              aria-describedby="decided-filter-description"
              aria-pressed={filters.status === 'decided'}
              onClick={() =>
                updateFilter('status', filters.status === 'decided' ? 'all' : 'decided')
              }
            >
              <span id="decided-count" className="stat__num stat__num--handled">
                {handledCount}
              </span>
              <span id="decided-label" className="stat__label">
                Decided
              </span>
            </button>
            <div className="visually-hidden">
              <span id="tier-a-filter-description">
                {filters.tier === 'A' ? 'Clears the Tier A filter.' : 'Filters results to Tier A.'}
              </span>
              <span id="tier-b-filter-description">
                {filters.tier === 'B' ? 'Clears the Tier B filter.' : 'Filters results to Tier B.'}
              </span>
              <span id="decided-filter-description">
                {filters.status === 'decided'
                  ? 'Clears the decided findings filter.'
                  : 'Filters results to decided findings.'}
              </span>
            </div>
          </div>

          {result.findings.length > 0 && !incomplete && (
            <section className="remediation-summary" aria-labelledby="remediation-summary-title">
              <h2 id="remediation-summary-title">Redaction plan</h2>
              <dl>
                <div>
                  <dt>Selected</dt>
                  <dd>{plan.selected_finding_count}</dd>
                </div>
                <div>
                  <dt>Files</dt>
                  <dd>{plan.affected_file_count}</dd>
                </div>
                <div>
                  <dt>Read-only</dt>
                  <dd>{plan.read_only_finding_count}</dd>
                </div>
              </dl>
              {regenerationRequired && (
                <p
                  className="remediation-summary__warning"
                  role="status"
                  aria-live="polite"
                  aria-atomic="true"
                >
                  Existing redacted copies are out of date. Review and regenerate them before
                  sharing.
                </p>
              )}
              {obsoleteOutputs && (
                <p
                  className="remediation-summary__warning"
                  role="status"
                  aria-live="polite"
                  aria-atomic="true"
                >
                  An existing redacted copy is obsolete because no findings remain selected for it.
                  Review its path and remove it manually if it is no longer needed.
                </p>
              )}
              {conflictingOutputs && (
                <p
                  className="remediation-summary__warning"
                  role="alert"
                  aria-live="assertive"
                  aria-atomic="true"
                >
                  An existing redacted copy changed outside RedactLens or is no longer a trusted
                  regular file. RedactLens will not overwrite or reveal it as verified.
                </p>
              )}
              {retainedArtifactPaths.length > 0 && (
                <div
                  className="remediation-summary__warning"
                  role="alert"
                  aria-live="assertive"
                  aria-atomic="true"
                >
                  <p>
                    <strong>Manual cleanup required.</strong> RedactLens could not remove temporary
                    remediation artifacts after a file operation. They may contain sensitive
                    content. Inspect or recover them if needed, then delete them manually.
                  </p>
                  <ul>
                    {retainedArtifactPaths.map((artifactPath) => (
                      <li key={artifactPath}>
                        <code>{relativePath(artifactPath, roots)}</code>
                        <details>
                          <summary>Show full retained artifact path</summary>
                          <code>{artifactPath}</code>
                        </details>
                      </li>
                    ))}
                  </ul>
                </div>
              )}
              <button
                ref={reviewButtonRef}
                type="button"
                className="review-btn"
                disabled={!plan.can_review || planMutationPending || isRefining || reconciling}
                onClick={openFreshReview}
              >
                Review remediation
              </button>
            </section>
          )}

          <div className="results__footer">
            <button type="button" className="btn-again" onClick={leaveResults}>
              Scan something else
            </button>
            <button
              type="button"
              className={`btn-export ${quietExportLock ? 'btn-export--quiet-disabled' : ''}`}
              disabled={reportBusy}
              onClick={() => downloadReport('json')}
            >
              <IconDownload size={15} />
              Export JSON
            </button>
            <button
              type="button"
              className={`btn-export btn-export--secondary ${
                quietExportLock ? 'btn-export--quiet-disabled' : ''
              }`}
              disabled={reportBusy}
              onClick={() => downloadReport('markdown')}
            >
              <IconDownload size={15} />
              Export readable report
            </button>
          </div>
        </aside>

        <div className="results__main">
          {isRefining && (
            <div className="ai-banner" aria-hidden="true">
              <Spinner />
              <span>{REFINING_BANNER_MESSAGE}</span>
            </div>
          )}
          {refineError && (
            <p role="status" className="warning-banner">
              On-device AI refinement didn&rsquo;t finish: {refineError}. The results below are
              still accurate for everything found without it.
            </p>
          )}
          {incomplete && (
            <p role="alert" className="warning-banner">
              This scan is incomplete. Partial findings are shown for review only; remediation is
              disabled until a scan completes.
            </p>
          )}
          {noFilesInspected && (
            <p role="alert" className="warning-banner">
              RedactLens did not inspect any files.{' '}
              {result.skipped_files.length > 0
                ? 'Review the skipped-file details, then check the scan location, filters, permissions, and supported formats before trying again.'
                : 'Check that the scan location exists and contains files, then try again.'}
            </p>
          )}
          {readOnlyFiles.length > 0 && (
            <p role="note" className="warning-banner">
              {readOnlyFindingCount === 1 ? 'One finding' : `${readOnlyFindingCount} findings`} in{' '}
              <strong>{readOnlyFilePreview.join(', ')}</strong>
              {additionalReadOnlyFileCount > 0
                ? ` and ${additionalReadOnlyFileCount} more ${additionalReadOnlyFileCount === 1 ? 'file' : 'files'}`
                : ''}{' '}
              {readOnlyFindingCount === 1 ? 'is' : 'are'} read-only and excluded from automatic
              remediation. This applies only to results marked Read-only.
              {hasMixedRemediationFiles &&
                ' Other findings in the same file can still be included when an Include in redaction plan button is shown.'}{' '}
              Use the read-only filter to review them, then show those files in their folders and
              edit them yourself.
            </p>
          )}
          {allHandled && (
            <p role="status" className="success-banner">
              {readOnlyFiles.length > 0
                ? 'All actionable findings have a decision. Read-only findings still require manual editing.'
                : 'All findings have a decision. Review the remediation plan before creating files.'}
            </p>
          )}
          {onlyReadOnly && (
            <p className="empty-state">
              Only read-only findings were detected. They remain reviewable, but each file must be
              edited manually.
            </p>
          )}

          {reviewOpen && (
            <RemediationReview
              plan={plan}
              outputs={outputs}
              roots={roots}
              generating={generating}
              generationMessage={generationMessage}
              generationMessageRole={generationMessageRole}
              planMutationPending={planMutationPending || reconciling}
              onClose={closeReview}
              onGenerate={handleGenerate}
              onOpenOutput={handleOpenOutput}
            />
          )}

          {result.findings.length === 0 && !isRefining ? (
            <p className="empty-state">
              {incomplete
                ? 'No findings were retained before this scan stopped. Because the scan did not complete, run it again before reviewing or sharing these files.'
                : noFilesInspected
                  ? 'No detection result is available because no files were inspected.'
                  : 'Nothing matched here — but detection can miss things, so still take a look yourself before sharing.'}
            </p>
          ) : (
            result.findings.length > 0 && (
              <>
                <FindingValueControl
                  visible={fullValuesVisible}
                  busy={revealValuesBusy}
                  disabled={isRefining || incomplete}
                  error={revealValuesError}
                  onToggle={toggleFullValues}
                />

                <TriageControls
                  filters={filters}
                  groupMode={groupMode}
                  categories={categoryOptions}
                  detectors={detectorOptions}
                  files={fileOptions}
                  matchCount={filteredFindings.length}
                  totalCount={result.findings.length}
                  activeFilterCount={activeFilterCount}
                  userTargets={userTargets}
                  onFilter={updateFilter}
                  onGroup={(mode) => {
                    setGroupMode(mode)
                    setVisibleLimit(RESULTS_PAGE_SIZE)
                  }}
                  onReset={() => {
                    setFilters({ ...EMPTY_FILTERS })
                    setVisibleLimit(RESULTS_PAGE_SIZE)
                  }}
                />

                <BulkActions
                  containerRef={bulkActionsRef}
                  selectedCount={selectedActionable.length}
                  selectedIncludedCount={selectedIncluded.length}
                  visibleCount={visibleActionable.length}
                  visibleTierACount={visibleTierA.length}
                  visibleTierBCount={visibleTierB.length}
                  allVisibleSelected={allVisibleSelected}
                  allVisibleTierASelected={allVisibleTierASelected}
                  allVisibleTierBSelected={allVisibleTierBSelected}
                  busy={resultListBusy}
                  onToggleVisible={() => toggleFindings(visibleActionable)}
                  onToggleTierA={() => toggleFindings(visibleTierA)}
                  onToggleTierB={() => toggleFindings(visibleTierB)}
                  onInclude={() => handleSelectedState('included')}
                  onExclude={() => handleSelectedState('excluded')}
                />

                {filteredFindings.length === 0 ? (
                  <p className="empty-state">
                    {allHandled
                      ? readOnlyFiles.length > 0
                        ? 'All actionable findings are handled. Clear the current filters to review those decisions and the remaining read-only findings.'
                        : 'All findings are handled. Clear the current filters to review those decisions.'
                      : onlyReadOnly
                        ? 'Only read-only findings are available, but none match these filters. Clear one or more filters to review them.'
                        : 'No findings match these filters. Clear one or more filters to broaden the view.'}
                  </p>
                ) : (
                  <>
                    {groupedFindings.map((group) => (
                      <FindingSection
                        key={group.key}
                        title={group.title}
                        subtitle={group.subtitle}
                        tier={group.tier}
                        findings={group.findings}
                        roots={roots}
                        fileLabels={fileLabels}
                        states={states}
                        revealedValues={revealedValues}
                        userTargets={userTargets}
                        selectedIds={selectedIds}
                        workflowBusy={resultListBusy}
                        busyId={busyId}
                        onSelect={toggleFinding}
                        onInclude={(finding) => setFindingState(finding, 'included')}
                        onExclude={(finding) => setFindingState(finding, 'pending')}
                        onIgnore={(finding) => setFindingState(finding, 'ignored')}
                        onRestore={(finding) => setFindingState(finding, 'pending')}
                        onOpen={handleOpen}
                        action={tierBulkAction(group.tier)}
                      />
                    ))}
                    <p
                      ref={resultsCountRef}
                      className="results-count"
                      aria-live="polite"
                      tabIndex={-1}
                    >
                      Showing {visibleFindings.length} of {filteredFindings.length} matching
                      findings.
                    </p>
                    {visibleFindings.length < filteredFindings.length && (
                      <button
                        type="button"
                        className="show-more-btn"
                        onClick={() => {
                          const nextLimit = Math.min(
                            visibleLimit + RESULTS_PAGE_SIZE,
                            filteredFindings.length,
                          )
                          focusFindingAfterExpandRef.current =
                            filteredFindings[visibleLimit]?.id ?? null
                          setVisibleLimit(nextLimit)
                        }}
                      >
                        Show up to{' '}
                        {Math.min(RESULTS_PAGE_SIZE, filteredFindings.length - visibleLimit)} more
                      </button>
                    )}
                  </>
                )}
              </>
            )
          )}

          {result.skipped_files.length > 0 && <SkippedFiles result={result} />}
        </div>
      </div>
    </section>
  )
}
