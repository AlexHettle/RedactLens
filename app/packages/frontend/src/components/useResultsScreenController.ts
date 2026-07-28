import { useEffect, useMemo, useRef, useState } from 'react'
import {
  getRemediationPlan,
  postGenerateRemediation,
  postOpenFile,
  postOpenOutput,
  postRevealFindingValues,
  putRemediationPlan,
} from '../api/client'
import { buildHumanReport, buildJsonReport } from '../results/reports'
import {
  buildFileOptions,
  displayRedactedPreview,
  EMPTY_FILTERS,
  effectiveRemediationState,
  fileIdentity,
  fileName,
  filterFindings,
  findingSupportsAutomaticRedaction,
  groupFindings,
  relativePath,
  type FindingFilters,
  type GroupMode,
} from '../results/triage'
import type {
  GeneratedOutputDetails,
  PublicFinding,
  PublicScanResult,
  RemediationOutputMode,
  RemediationPlan,
  RemediationState,
  Tier,
} from '../types'

const STILL_REFINING_MESSAGE = 'Still checking some results with on-device AI.'
export const RESULTS_PAGE_SIZE = 50
const REVEAL_BATCH_SIZE = 250
const READ_ONLY_FILE_PREVIEW_LIMIT = 5

function hasErrorCode(error: unknown, code: string): boolean {
  return (
    typeof error === 'object' &&
    error !== null &&
    'code' in error &&
    (error as { code?: unknown }).code === code
  )
}

function actionErrorMessage(error: unknown, fallback: string): string {
  if (
    typeof error === 'object' &&
    error !== null &&
    'message' in error &&
    typeof (error as { message?: unknown }).message === 'string'
  ) {
    return (error as { message: string }).message
  }
  return error instanceof Error ? error.message : fallback
}

function outputRevealError(error: unknown): unknown {
  if (hasErrorCode(error, 'output_conflict')) {
    return {
      code: 'output_conflict',
      message: 'The redacted copy changed outside RedactLens and will not be shown in its folder.',
    }
  }
  if (hasErrorCode(error, 'file_unavailable')) {
    return {
      code: 'file_unavailable',
      message:
        'The redacted copy could not be shown in its folder. Check that it is still available.',
    }
  }
  return error
}

function initialPlan(result: PublicScanResult): RemediationPlan {
  const readOnly = result.findings.filter((finding) => !finding.can_anonymize).length
  return {
    plan_revision: 0,
    findings: result.findings.map((finding) => ({
      finding_id: finding.id,
      state: finding.can_anonymize ? 'pending' : 'read_only',
    })),
    files: [],
    selected_finding_count: 0,
    affected_file_count: 0,
    read_only_finding_count: readOnly,
    retained_artifact_paths: [],
    can_review: false,
    can_generate: false,
  }
}

function sameFindingIds(left: string[], right: string[]): boolean {
  if (left.length !== right.length) return false
  const expected = new Set(left)
  const actual = new Set(right)
  return (
    expected.size === left.length &&
    actual.size === right.length &&
    actual.size === expected.size &&
    [...actual].every((findingId) => expected.has(findingId))
  )
}

function outputMatchesCurrentPlan(output: GeneratedOutputDetails, plan: RemediationPlan): boolean {
  return plan.files.some(
    (file) =>
      file.output_state === 'current' &&
      file.source_path === output.source_path &&
      file.output_path === output.output_path &&
      sameFindingIds(file.included_finding_ids, output.applied_finding_ids),
  )
}

function stateFromPlan(plan: RemediationPlan, finding: PublicFinding): RemediationState {
  return effectiveRemediationState(
    finding,
    plan.findings.find((candidate) => candidate.finding_id === finding.id)?.state ??
      (finding.can_anonymize ? 'pending' : 'read_only'),
  )
}

interface ResultsControllerOptions {
  result: PublicScanResult
  isRefining: boolean
  onStartOver: () => void
  onSessionExpired: (message?: string) => void
  onToast?: (message: string) => void
}

export function useResultsScreenController({
  result,
  isRefining,
  onStartOver,
  onSessionExpired,
  onToast,
}: ResultsControllerOptions) {
  const [plan, setPlan] = useState<RemediationPlan>(() => initialPlan(result))
  const [outputs, setOutputs] = useState<GeneratedOutputDetails[]>([])
  const [reviewOpen, setReviewOpen] = useState(false)
  const [liveMessage, setLiveMessage] = useState('')
  const [generationMessage, setGenerationMessage] = useState('')
  const [generationMessageRole, setGenerationMessageRole] = useState<'status' | 'alert'>('status')
  const [busyId, setBusyId] = useState<string | null>(null)
  const [bulkBusy, setBulkBusy] = useState(false)
  const [generating, setGenerating] = useState(false)
  const [reconciling, setReconciling] = useState(false)
  const [actionError, setActionError] = useState<string | null>(null)
  const [fullValuesVisible, setFullValuesVisible] = useState(false)
  const [revealedValues, setRevealedValues] = useState<Record<string, string>>({})
  const [revealValuesBusy, setRevealValuesBusy] = useState(false)
  const [revealValuesError, setRevealValuesError] = useState<string | null>(null)
  const [filters, setFilters] = useState<FindingFilters>({ ...EMPTY_FILTERS })
  const [groupMode, setGroupMode] = useState<GroupMode>('tier')
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set())
  const [visibleLimit, setVisibleLimit] = useState(RESULTS_PAGE_SIZE)
  const activeRef = useRef(true)
  const refiningLiveRegionRef = useRef<HTMLDivElement>(null)
  const resultsHeadingRef = useRef<HTMLHeadingElement>(null)
  const actionErrorRef = useRef<HTMLParagraphElement>(null)
  const reviewButtonRef = useRef<HTMLButtonElement>(null)
  const bulkActionsRef = useRef<HTMLElement>(null)
  const resultsCountRef = useRef<HTMLParagraphElement>(null)
  const resultsSectionRef = useRef<HTMLElement>(null)
  const reviewWasOpenRef = useRef(false)
  const reviewOpenRef = useRef(false)
  const focusBulkActionsAfterUpdateRef = useRef(false)
  const focusFindingAfterExpandRef = useRef<string | null>(null)
  const focusAfterFindingUpdateRef = useRef<{
    actedFindingId: string
    successorFindingId: string | null
  } | null>(null)
  const planMutationInFlightRef = useRef(false)
  const revealRequestRef = useRef(0)

  useEffect(() => {
    activeRef.current = true
    return () => {
      activeRef.current = false
      revealRequestRef.current += 1
    }
  }, [])

  useEffect(() => {
    resultsHeadingRef.current?.focus()
  }, [])

  useEffect(() => {
    const liveRegion = refiningLiveRegionRef.current
    if (!liveRegion) return
    if (isRefining) liveRegion.textContent = STILL_REFINING_MESSAGE
    else if (liveRegion.textContent === STILL_REFINING_MESSAGE) {
      liveRegion.textContent = 'On-device AI refinement complete.'
    }
  }, [isRefining])

  useEffect(() => {
    if (reviewWasOpenRef.current && !reviewOpen) reviewButtonRef.current?.focus()
    reviewWasOpenRef.current = reviewOpen
  }, [reviewOpen])

  useEffect(() => {
    if (actionError && !reviewOpen) actionErrorRef.current?.focus()
  }, [actionError, reviewOpen])

  useEffect(() => {
    if (!focusBulkActionsAfterUpdateRef.current) return
    bulkActionsRef.current?.focus()
    focusBulkActionsAfterUpdateRef.current = false
  }, [plan.plan_revision])

  useEffect(() => {
    const request = focusAfterFindingUpdateRef.current
    if (request === null) return
    const findingCards = Array.from(
      resultsSectionRef.current?.querySelectorAll<HTMLElement>('[data-finding-id]') ?? [],
    )
    const actedFindingCard = findingCards.find(
      (element) => element.dataset.findingId === request.actedFindingId,
    )
    const successorFindingCard = findingCards.find(
      (element) => element.dataset.findingId === request.successorFindingId,
    )
    if (actedFindingCard) {
      actedFindingCard.focus({ preventScroll: true })
    } else {
      const focusDestination =
        successorFindingCard ?? resultsCountRef.current ?? bulkActionsRef.current
      focusDestination?.focus()
    }
    focusAfterFindingUpdateRef.current = null
  }, [plan.plan_revision])

  useEffect(() => {
    const findingId = focusFindingAfterExpandRef.current
    if (findingId === null) return
    const findingCard = Array.from(
      resultsSectionRef.current?.querySelectorAll<HTMLElement>('[data-finding-id]') ?? [],
    ).find((element) => element.dataset.findingId === findingId)
    const focusDestination = findingCard ?? resultsCountRef.current
    focusDestination?.focus()
    focusFindingAfterExpandRef.current = null
  }, [visibleLimit])

  const roots = result.metadata.selected_roots
  const states = Object.fromEntries(
    plan.findings.map((finding) => [finding.finding_id, finding.state]),
  ) as Record<string, RemediationState>
  const stateOf = (finding: PublicFinding): RemediationState =>
    effectiveRemediationState(finding, states[finding.id])
  const isActionable = (finding: PublicFinding): boolean =>
    findingSupportsAutomaticRedaction(finding, stateOf(finding))
  const isBulkSelectable = (finding: PublicFinding): boolean =>
    isActionable(finding) && stateOf(finding) !== 'ignored'
  const includedIds = plan.findings
    .filter((finding) => finding.state === 'included')
    .map((finding) => finding.finding_id)
  const ignoredIds = plan.findings
    .filter((finding) => finding.state === 'ignored')
    .map((finding) => finding.finding_id)

  const tierA = result.findings.filter((finding) => finding.tier === 'A')
  const tierB = result.findings.filter((finding) => finding.tier === 'B')
  const actionableFindings = result.findings.filter(isActionable)
  const handledCount = actionableFindings.filter((finding) =>
    ['included', 'ignored'].includes(stateOf(finding)),
  ).length
  const pendingA = tierA.filter(
    (finding) => isActionable(finding) && stateOf(finding) === 'pending',
  )
  const pendingB = tierB.filter(
    (finding) => isActionable(finding) && stateOf(finding) === 'pending',
  )
  const allHandled = actionableFindings.length > 0 && handledCount === actionableFindings.length
  const onlyReadOnly =
    result.findings.length > 0 && result.findings.every((finding) => !isActionable(finding))
  const incomplete = result.state !== 'complete'
  const planMutationPending = busyId !== null || bulkBusy
  const workflowBusy = planMutationPending || generating || reconciling || isRefining || incomplete
  const reportBusy = workflowBusy
  const regenerationRequired = plan.files.some(
    (file) => file.output_state === 'regeneration_required',
  )
  const obsoleteOutputs = plan.files.some((file) => file.output_state === 'obsolete')
  const conflictingOutputs = plan.files.some((file) => file.output_state === 'conflict')
  const retainedArtifactPaths = [...new Set(plan.retained_artifact_paths)]

  const categoryOptions = useMemo(
    () => [...new Set(result.findings.map((finding) => finding.category))].sort(),
    [result.findings],
  )
  const detectorOptions = useMemo(
    () => [...new Set(result.findings.map((finding) => finding.detector_id))].sort(),
    [result.findings],
  )
  const fileOptions = useMemo(
    () =>
      buildFileOptions(
        result.findings.map((finding) => finding.file_path),
        roots,
      ),
    [result.findings, roots],
  )
  const fileLabels = useMemo(
    () => new Map(fileOptions.map((option) => [option.value, option.label])),
    [fileOptions],
  )
  const readOnlyFindings = result.findings.filter((finding) => !isActionable(finding))
  const readOnlyFiles = [
    ...new Set(
      readOnlyFindings.map(
        (finding) =>
          fileLabels.get(fileIdentity(finding.file_path)) ?? relativePath(finding.file_path, roots),
      ),
    ),
  ]
  const actionableFileIdentities = new Set(
    actionableFindings.map((finding) => fileIdentity(finding.file_path)),
  )
  const hasMixedRemediationFiles = readOnlyFindings.some((finding) =>
    actionableFileIdentities.has(fileIdentity(finding.file_path)),
  )
  const readOnlyFindingCount = readOnlyFindings.length
  const readOnlyFilePreview = readOnlyFiles.slice(0, READ_ONLY_FILE_PREVIEW_LIMIT)
  const additionalReadOnlyFileCount = readOnlyFiles.length - readOnlyFilePreview.length
  const filteredFindings = filterFindings(result.findings, filters, stateOf)
  const visibleFindings = filteredFindings.slice(0, visibleLimit)
  const groupedFindings = groupFindings(visibleFindings, groupMode, roots, fileOptions)
  const visibleActionable = visibleFindings.filter(isBulkSelectable)
  const visibleTierA = visibleActionable.filter((finding) => finding.tier === 'A')
  const visibleTierB = visibleActionable.filter((finding) => finding.tier === 'B')
  const selectedActionable = result.findings.filter(
    (finding) => isActionable(finding) && selectedIds.has(finding.id),
  )
  const selectedIncluded = selectedActionable.filter((finding) => stateOf(finding) === 'included')
  const activeFilterCount = Object.entries(filters).filter(
    ([key, value]) => value !== EMPTY_FILTERS[key as keyof FindingFilters],
  ).length

  function leaveResults() {
    if (!activeRef.current) return
    // Fence already-running promises immediately; React's effect cleanup runs
    // after the parent processes this callback and is too late for this edge.
    activeRef.current = false
    onStartOver()
  }

  function expireSession(message?: string) {
    if (!activeRef.current) return
    activeRef.current = false
    onSessionExpired(message)
  }

  function publishToast(message: string) {
    if (activeRef.current) onToast?.(message)
  }

  async function toggleFullValues() {
    if (!activeRef.current || revealValuesBusy) return
    if (fullValuesVisible) {
      revealRequestRef.current += 1
      setFullValuesVisible(false)
      setRevealedValues({})
      setRevealValuesError(null)
      return
    }
    if (isRefining || incomplete) return

    const requestId = ++revealRequestRef.current
    const findingIds = [...new Set(result.findings.map((finding) => finding.id))]
    const collected: Record<string, string> = {}
    setRevealValuesBusy(true)
    setRevealValuesError(null)
    try {
      for (let start = 0; start < findingIds.length; start += REVEAL_BATCH_SIZE) {
        const batch = findingIds.slice(start, start + REVEAL_BATCH_SIZE)
        const response = await postRevealFindingValues(result.scan_id, batch)
        if (!activeRef.current || revealRequestRef.current !== requestId) return

        const expected = new Set(batch)
        const seen = new Set<string>()
        if (!Array.isArray(response.values)) throw new Error('Invalid reveal response')
        for (const item of response.values) {
          if (
            typeof item?.finding_id !== 'string' ||
            typeof item.value !== 'string' ||
            !expected.has(item.finding_id) ||
            seen.has(item.finding_id)
          ) {
            throw new Error('Invalid reveal response')
          }
          seen.add(item.finding_id)
          collected[item.finding_id] = item.value
        }
        if (seen.size !== expected.size) throw new Error('Incomplete reveal response')
      }
      if (!activeRef.current || revealRequestRef.current !== requestId) return
      setRevealedValues(collected)
      setFullValuesVisible(true)
    } catch (error) {
      if (!activeRef.current || revealRequestRef.current !== requestId) return
      setRevealedValues({})
      setFullValuesVisible(false)
      if (hasErrorCode(error, 'scan_expired')) {
        expireSession()
      } else {
        setRevealValuesError('Could not show full values. They remain hidden. Try again.')
      }
    } finally {
      if (activeRef.current && revealRequestRef.current === requestId) {
        setRevealValuesBusy(false)
      }
    }
  }

  function retainCurrentOutputEvidence(updated: RemediationPlan) {
    if (!activeRef.current) return
    setOutputs((current) => current.filter((output) => outputMatchesCurrentPlan(output, updated)))
  }

  function publishActionError(message: string, preferReview: boolean) {
    if (preferReview && reviewOpenRef.current) {
      setGenerationMessageRole('alert')
      setGenerationMessage(message)
      return
    }
    reviewOpenRef.current = false
    setReviewOpen(false)
    setActionError(message)
  }

  async function handleActionError(error: unknown, fallback: string, preferReview = false) {
    if (!activeRef.current) return
    if (hasErrorCode(error, 'scan_expired')) {
      expireSession()
      return
    }
    const keepInReview = preferReview && reviewOpenRef.current
    if (!keepInReview) {
      // An alert outside an aria-modal cannot be reached reliably. Close review
      // before publishing any global action error so focus and assistive
      // technology both land on visible content.
      reviewOpenRef.current = false
      setReviewOpen(false)
    }
    const reconcilePlan =
      hasErrorCode(error, 'invalid_remediation_plan') ||
      hasErrorCode(error, 'finding_not_anonymizable') ||
      hasErrorCode(error, 'output_conflict') ||
      hasErrorCode(error, 'file_unavailable')
    if (reconcilePlan) {
      if (keepInReview) publishActionError(actionErrorMessage(error, fallback), true)
      setReconciling(true)
      // The error itself proves the locally retained evidence may no longer
      // describe disk or the authoritative selection. Clear it before the
      // refresh so a failed/slow GET cannot leave exportable stale evidence.
      setOutputs([])
      setPlan((current) => ({
        ...current,
        can_generate: false,
        files: current.files.map((file) =>
          file.output_state === 'current' || file.output_state === 'regeneration_required'
            ? {
                ...file,
                output_state: hasErrorCode(error, 'invalid_remediation_plan')
                  ? 'regeneration_required'
                  : 'conflict',
              }
            : file,
        ),
      }))
      try {
        const latest = await getRemediationPlan(result.scan_id)
        if (!activeRef.current) return
        setPlan(latest)
        retainCurrentOutputEvidence(latest)
        publishActionError(
          hasErrorCode(error, 'invalid_remediation_plan')
            ? 'The remediation plan changed. Review the latest selections and try again.'
            : `${actionErrorMessage(error, fallback)} The remediation plan was refreshed.`,
          preferReview,
        )
      } catch (refreshError) {
        if (!activeRef.current) return
        if (hasErrorCode(refreshError, 'scan_expired')) {
          expireSession(
            `${actionErrorMessage(error, fallback)} The scan session is no longer available; run the scan again before continuing.`,
          )
        } else {
          publishActionError(
            `${fallback} The latest remediation plan could not be loaded.`,
            preferReview,
          )
        }
      } finally {
        if (activeRef.current) setReconciling(false)
      }
      return
    }
    publishActionError(actionErrorMessage(error, fallback), preferReview)
  }

  async function saveSelection(
    nextIncluded: string[],
    nextIgnored: string[],
    announcement: string,
    onSaved?: () => void,
  ): Promise<boolean> {
    if (!activeRef.current) return false
    setActionError(null)
    const updated = await putRemediationPlan(
      result.scan_id,
      nextIncluded,
      nextIgnored,
      plan.plan_revision,
    )
    if (!activeRef.current) return false
    setPlan(updated)
    retainCurrentOutputEvidence(updated)
    onSaved?.()
    setLiveMessage(announcement)
    return true
  }

  async function setFindingState(finding: PublicFinding, state: RemediationState) {
    if (!isActionable(finding) || planMutationInFlightRef.current) return
    planMutationInFlightRef.current = true
    const findingIndex = visibleFindings.findIndex((candidate) => candidate.id === finding.id)
    const successor =
      findingIndex < 0
        ? null
        : (visibleFindings[findingIndex + 1] ?? visibleFindings[findingIndex - 1] ?? null)
    focusAfterFindingUpdateRef.current = {
      actedFindingId: finding.id,
      successorFindingId: successor?.id ?? null,
    }
    setBusyId(finding.id)
    let busyCleared = false
    try {
      const nextIncluded = includedIds.filter((id) => id !== finding.id)
      const nextIgnored = ignoredIds.filter((id) => id !== finding.id)
      if (state === 'included') nextIncluded.push(finding.id)
      if (state === 'ignored') nextIgnored.push(finding.id)
      const action =
        state === 'included'
          ? 'Included in the redaction plan.'
          : state === 'ignored'
            ? 'Marked ignored.'
            : 'Returned to pending. Any existing copy may require regeneration.'
      await saveSelection(
        nextIncluded,
        nextIgnored,
        `${displayRedactedPreview(finding.redacted_preview)}: ${action}`,
        () => {
          if (state === 'ignored') {
            setSelectedIds((current) => {
              const next = new Set(current)
              next.delete(finding.id)
              return next
            })
          }
          setBusyId(null)
          busyCleared = true
        },
      )
    } catch (error) {
      if (!activeRef.current) return
      focusAfterFindingUpdateRef.current = null
      await handleActionError(error, 'Could not update the remediation plan.')
    } finally {
      planMutationInFlightRef.current = false
      if (activeRef.current && !busyCleared) setBusyId(null)
    }
  }

  async function handleIncludeTier(tier: Tier) {
    const pending = tier === 'A' ? pendingA : pendingB
    if (pending.length === 0 || planMutationInFlightRef.current) return
    planMutationInFlightRef.current = true
    setBulkBusy(true)
    focusBulkActionsAfterUpdateRef.current = true
    let busyCleared = false
    try {
      await saveSelection(
        [...includedIds, ...pending.map((finding) => finding.id)],
        ignoredIds,
        `Included ${pending.length} ${
          tier === 'A' ? 'confirmed' : 'double-check'
        } findings in the remediation plan.`,
        () => {
          setBulkBusy(false)
          busyCleared = true
        },
      )
    } catch (error) {
      if (!activeRef.current) return
      focusBulkActionsAfterUpdateRef.current = false
      await handleActionError(error, 'Could not update the remediation plan.')
    } finally {
      planMutationInFlightRef.current = false
      if (activeRef.current && !busyCleared) setBulkBusy(false)
    }
  }

  async function handleSelectedState(state: 'included' | 'excluded') {
    const affectedFindings = state === 'included' ? selectedActionable : selectedIncluded
    if (affectedFindings.length === 0 || planMutationInFlightRef.current) return
    planMutationInFlightRef.current = true
    setBulkBusy(true)
    focusBulkActionsAfterUpdateRef.current = true
    const selected = new Set(affectedFindings.map((finding) => finding.id))
    const nextIncluded = includedIds.filter((id) => !selected.has(id))
    const nextIgnored =
      state === 'included' ? ignoredIds.filter((id) => !selected.has(id)) : ignoredIds
    let busyCleared = false
    if (state === 'included') nextIncluded.push(...selected)
    try {
      const saved = await saveSelection(
        nextIncluded,
        nextIgnored,
        state === 'included'
          ? `Included ${selected.size} selected findings.`
          : `Excluded ${selected.size} selected included findings from the redaction plan.`,
        () => {
          setSelectedIds((current) => {
            const next = new Set(current)
            for (const findingId of selected) next.delete(findingId)
            return next
          })
          setBulkBusy(false)
          busyCleared = true
        },
      )
      if (!saved || !activeRef.current) return
    } catch (error) {
      if (!activeRef.current) return
      focusBulkActionsAfterUpdateRef.current = false
      await handleActionError(error, 'Could not update the selected findings.')
    } finally {
      planMutationInFlightRef.current = false
      if (activeRef.current && !busyCleared) setBulkBusy(false)
    }
  }

  function toggleFindings(findings: PublicFinding[]) {
    const findingIds = findings.filter(isBulkSelectable).map((finding) => finding.id)
    if (findingIds.length === 0) return
    setSelectedIds((current) => {
      const next = new Set(current)
      const allSelected = findingIds.every((findingId) => next.has(findingId))
      for (const findingId of findingIds) {
        if (allSelected) next.delete(findingId)
        else next.add(findingId)
      }
      return next
    })
  }

  function toggleFinding(finding: PublicFinding, selected: boolean) {
    setSelectedIds((current) => {
      const next = new Set(current)
      if (selected && isActionable(finding)) next.add(finding.id)
      else next.delete(finding.id)
      return next
    })
  }

  async function handleGenerate(outputMode: RemediationOutputMode) {
    if (!activeRef.current || planMutationInFlightRef.current) return
    setGenerating(true)
    setActionError(null)
    setGenerationMessageRole('status')
    setGenerationMessage('')
    try {
      const generated = await postGenerateRemediation(
        result.scan_id,
        plan.plan_revision,
        outputMode,
      )
      if (!activeRef.current) return
      setPlan(generated.plan)
      setOutputs(
        generated.outputs.filter((output) => outputMatchesCurrentPlan(output, generated.plan)),
      )
      setGenerationMessageRole('status')
      setGenerationMessage(
        outputMode === 'replace_original'
          ? `Replaced and verified ${generated.outputs.length} original ${
              generated.outputs.length === 1 ? 'file' : 'files'
            }. Run a new scan before making additional changes.`
          : `Created and verified ${generated.outputs.length} redacted ${
              generated.outputs.length === 1 ? 'copy' : 'copies'
            }.`,
      )
    } catch (error) {
      if (!activeRef.current) return
      await handleActionError(
        error,
        outputMode === 'replace_original'
          ? 'Could not replace the original files.'
          : 'Could not create the redacted copies.',
      )
    } finally {
      if (activeRef.current) setGenerating(false)
    }
  }

  async function handleOpen(finding: PublicFinding) {
    if (!activeRef.current) return
    const name = fileName(finding.file_path)
    try {
      await postOpenFile(result.scan_id, finding.id)
      if (!activeRef.current) return
      const place = finding.location ?? `line ${finding.line}`
      publishToast(`Showed ${name} in its folder — the finding is at ${place}.`)
    } catch (error) {
      if (!activeRef.current) return
      if (hasErrorCode(error, 'scan_expired')) return expireSession()
      publishToast(`Couldn't show ${name} in its folder.`)
    }
  }

  async function handleOpenOutput(findingId: string, outputPath: string) {
    if (!activeRef.current) return
    setActionError(null)
    if (reviewOpenRef.current) {
      setGenerationMessageRole('status')
      setGenerationMessage('')
    }
    try {
      await postOpenOutput(result.scan_id, findingId)
      if (!activeRef.current) return
      const message = `Showed ${fileName(outputPath)} in its folder.`
      // Keep modal feedback inside the active aria-modal so it remains
      // perceivable and reachable under the focus trap. If the user closes
      // review while the native reveal request is pending, fall back to the
      // app-level notification that is visible outside the dialog.
      if (reviewOpenRef.current) {
        setGenerationMessageRole('status')
        setGenerationMessage(message)
      } else publishToast(message)
    } catch (error) {
      if (!activeRef.current) return
      if (hasErrorCode(error, 'scan_expired')) return expireSession()
      await handleActionError(
        outputRevealError(error),
        'Could not show the redacted copy in its folder.',
        true,
      )
    }
  }

  function saveReport(
    format: 'json' | 'markdown',
    freshPlan: RemediationPlan,
    freshOutputs: GeneratedOutputDetails[],
  ) {
    if (!activeRef.current) return
    const freshStateOf = (finding: PublicFinding) => stateFromPlan(freshPlan, finding)
    const json = buildJsonReport(result, freshPlan, freshOutputs, freshStateOf)
    const contents =
      format === 'json'
        ? JSON.stringify(json, null, 2)
        : buildHumanReport(result, freshPlan, freshOutputs, freshStateOf)
    const blob = new Blob([contents], {
      type: format === 'json' ? 'application/json' : 'text/markdown',
    })
    const url = URL.createObjectURL(blob)
    const anchor = document.createElement('a')
    anchor.href = url
    anchor.download = format === 'json' ? 'redactlens-report.json' : 'redactlens-report.md'
    anchor.click()
    URL.revokeObjectURL(url)
    publishToast(`Report saved as ${anchor.download}`)
  }

  function reconcileFreshEvidence(freshPlan: RemediationPlan) {
    const freshOutputs = outputs.filter((output) => outputMatchesCurrentPlan(output, freshPlan))
    const evidenceInvalidated = freshOutputs.length !== outputs.length
    if (!activeRef.current) return { freshOutputs, evidenceInvalidated }
    setPlan(freshPlan)
    setOutputs(freshOutputs)
    return { freshOutputs, evidenceInvalidated }
  }

  async function openFreshReview() {
    if (!activeRef.current) return
    setReconciling(true)
    setActionError(null)
    try {
      const freshPlan = await getRemediationPlan(result.scan_id)
      if (!activeRef.current) return
      const { evidenceInvalidated } = reconcileFreshEvidence(freshPlan)
      if (!freshPlan.can_review) {
        setActionError('The remediation plan changed and no longer has anything to review.')
        return
      }
      if (evidenceInvalidated) {
        setLiveMessage(
          'The remediation evidence changed on disk. Stale verification evidence was removed.',
        )
      }
      setGenerationMessageRole('status')
      setGenerationMessage('')
      reviewOpenRef.current = true
      setReviewOpen(true)
    } catch (error) {
      if (!activeRef.current) return
      // A failed refresh cannot establish that cached verification evidence is
      // still current, so remove it before returning control to the user.
      setOutputs([])
      if (hasErrorCode(error, 'scan_expired')) {
        expireSession()
      } else {
        setActionError('Could not refresh the remediation plan. Review was not opened.')
      }
    } finally {
      if (activeRef.current) setReconciling(false)
    }
  }

  async function downloadReport(format: 'json' | 'markdown') {
    if (!activeRef.current) return
    setReconciling(true)
    setActionError(null)
    try {
      // Build from the values returned by this request. Waiting for setState
      // here would still leave the click handler with its previous render's
      // closures and could stamp stale evidence with a new generated_at time.
      const freshPlan = await getRemediationPlan(result.scan_id)
      if (!activeRef.current) return
      const { freshOutputs, evidenceInvalidated } = reconcileFreshEvidence(freshPlan)
      if (freshPlan.files.some((file) => file.output_state === 'conflict')) {
        setActionError(
          'The report was not created because a redacted copy changed or is no longer trusted. Review the refreshed remediation plan.',
        )
        return
      }
      if (evidenceInvalidated) {
        setActionError(
          'The report was not created because prior output evidence is no longer current. Review the refreshed remediation plan.',
        )
        return
      }
      saveReport(format, freshPlan, freshOutputs)
    } catch (error) {
      if (!activeRef.current) return
      setOutputs([])
      if (hasErrorCode(error, 'scan_expired')) {
        expireSession()
      } else {
        setActionError(
          'The report was not created because the remediation plan could not be refreshed.',
        )
      }
    } finally {
      if (activeRef.current) setReconciling(false)
    }
  }

  function updateFilter<Key extends keyof FindingFilters>(key: Key, value: FindingFilters[Key]) {
    setFilters((current) => ({ ...current, [key]: value }))
    setVisibleLimit(RESULTS_PAGE_SIZE)
  }

  function closeReview() {
    reviewOpenRef.current = false
    setReviewOpen(false)
  }

  return {
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
    workflowBusy,
  }
}
