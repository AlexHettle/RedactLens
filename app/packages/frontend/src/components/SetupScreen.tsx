import {
  useEffect,
  useRef,
  useState,
  type FormEvent,
  type KeyboardEvent,
  type ReactNode,
} from 'react'
import { getDetectors, getHealth } from '../api/client'
import type {
  DetectorInfo,
  HealthResponse,
  ScanOptions,
  ScanRequest,
  TargetKind,
  UserTarget,
} from '../types'
import BrowseButton from './BrowseButton'
import {
  IconAlertTriangle,
  IconCard,
  IconCheck,
  IconCpu,
  IconFolder,
  IconInfo,
  IconKey,
  IconLock,
  IconPencil,
  IconPerson,
  IconSearch,
} from './Icons'

interface SetupScreenProps {
  onSubmit: (request: ScanRequest) => void
  /** Clears any submission error once the user starts correcting the setup. */
  onRequestChange?: () => void
  /** The previously submitted request, if any — restores the user's setup
   * when they come back via Cancel or "Scan something else". */
  initial?: ScanRequest | null
}

interface CategoryMeta {
  title: string
  description: string
  icon: ReactNode
}

const DEFAULT_OLLAMA_MODEL = 'qwen3-coder:30b'
const OLLAMA_DOWNLOAD_URL = 'https://ollama.com/download/windows'
const OLLAMA_MODEL_URL = 'https://ollama.com/library/qwen3-coder/tags'
const OLLAMA_MODEL_STORAGE_KEY = 'redactlens-ollama-model'
const LEGACY_OLLAMA_MODEL_STORAGE_KEY = 'redactscout-ollama-model'
const OLLAMA_STARTUP_RETRY_INTERVAL_MS = 3_000
const OLLAMA_STARTUP_RETRY_WINDOW_MS = 120_000
const ON_DEVICE_HELP =
  'Your files and scan excerpts are processed locally on this computer. RedactLens does not upload them.'

const DEFAULT_SCAN_OPTIONS: Required<ScanOptions> = {
  max_file_size: 100_000_000,
  max_structured_file_size: 50_000_000,
  ignored_directories: ['.git', '.venv', '__pycache__', 'build', 'dist', 'node_modules', 'venv'],
  included_extensions: [],
  excluded_extensions: [],
  archive_depth: 2,
  ai_timeout_seconds: 60,
  max_workers: 4,
  document_workers: 1,
  chunk_size: 1_048_576,
  use_redactlensignore: true,
}

const MAX_USER_TARGETS = 100
const MAX_USER_TARGET_LENGTH = 8_192
const MAX_SCAN_REQUEST_BYTES = 256 * 1024
const MAX_PATH_LENGTH = 4_096
const MAX_OPTION_ENTRIES = 256
const MAX_IGNORED_DIRECTORY_LENGTH = 255
const MAX_EXTENSION_LENGTH = 32

function textLength(value: string): number {
  return Array.from(value).length
}

function requestBytes(request: ScanRequest): number {
  return new TextEncoder().encode(JSON.stringify(request)).byteLength
}

function storedOllamaModel(): string | null {
  try {
    const stored = localStorage.getItem(OLLAMA_MODEL_STORAGE_KEY)
    if (stored !== null) return stored
    const legacy = localStorage.getItem(LEGACY_OLLAMA_MODEL_STORAGE_KEY)
    if (legacy !== null) localStorage.setItem(OLLAMA_MODEL_STORAGE_KEY, legacy)
    return legacy
  } catch {
    return null
  }
}

function formatModelSize(sizeBytes: number | null): string {
  if (sizeBytes === null) return 'size unavailable'
  if (sizeBytes < 1_000_000_000) return `${(sizeBytes / 1_000_000).toFixed(0)} MB`
  return `${(sizeBytes / 1_000_000_000).toFixed(1)} GB`
}

function modelIsAvailable(health: HealthResponse, modelName: string): boolean {
  if (health.ollama_models !== undefined) {
    return health.ollama_models.some((model) => model.name === modelName)
  }
  return health.ollama_available && (health.ollama_model ?? DEFAULT_OLLAMA_MODEL) === modelName
}

function ollamaServiceIsUnavailable(health: HealthResponse): boolean {
  return (
    health.status === 'ok' &&
    (health.ollama_status === 'unavailable' ||
      (health.ollama_status === undefined &&
        health.ollama_models === undefined &&
        !health.ollama_available))
  )
}

function listValues(value: string): string[] {
  return Array.from(
    new Set(
      value
        .split(',')
        .map((item) => item.trim())
        .filter(Boolean),
    ),
  )
}

function normalizedExtension(value: string): string {
  const lowered = value.toLowerCase()
  return lowered.startsWith('.') ? lowered : `.${lowered}`
}

function isIndividualDirectoryName(value: string): boolean {
  const name = value.replace(/^[/\\]+/, '').replace(/[/\\]+$/, '')
  return (
    Boolean(name) && name !== '.' && name !== '..' && !name.includes('/') && !name.includes('\\')
  )
}

function isExtensionName(value: string): boolean {
  const extension = normalizedExtension(value)
  return (
    extension !== '.' && extension !== '..' && !extension.includes('/') && !extension.includes('\\')
  )
}

const CATEGORY_META: Record<string, CategoryMeta> = {
  credential: {
    title: 'Credentials & secrets',
    description: 'Passwords, API keys, private keys',
    icon: <IconKey size={13} />,
  },
  financial: {
    title: 'Financial',
    description: 'Card numbers, account details',
    icon: <IconCard size={13} />,
  },
  personal_id: {
    title: 'Personal info',
    description: 'SSNs, emails, phone numbers',
    icon: <IconPerson size={13} />,
  },
}

function categoryMeta(category: string): CategoryMeta {
  return (
    CATEGORY_META[category] ?? {
      title: category,
      description: 'Custom detector category',
      icon: <IconSearch size={13} />,
    }
  )
}

function descriptionTargetWarning(ollamaAvailable: boolean): string {
  return ollamaAvailable
    ? 'This plain-English target needs local AI turned on above, or it won’t match anything.'
    : 'This plain-English target needs local AI, but no local model was detected — it won’t match anything until one is available.'
}

function scanLabel(path: string): string {
  if (!path) return 'Choose a folder or file to scan'
  return 'Scan this location'
}

export default function SetupScreen({ onSubmit, onRequestChange, initial }: SetupScreenProps) {
  const restoredOptions = { ...DEFAULT_SCAN_OPTIONS, ...initial?.options }
  const [path, setPath] = useState(initial?.paths[0] ?? '')
  const [detectors, setDetectors] = useState<DetectorInfo[]>([])
  const [detectorsLoaded, setDetectorsLoaded] = useState(false)
  const [selectedCategories, setSelectedCategories] = useState<Set<string>>(
    new Set(initial?.categories ?? []),
  )
  const [targets, setTargets] = useState<UserTarget[]>(initial?.user_targets ?? [])
  const [targetValue, setTargetValue] = useState('')
  const [targetAnnouncement, setTargetAnnouncement] = useState('')
  const [targetActionError, setTargetActionError] = useState<string | null>(null)
  const targetInputRef = useRef<HTMLInputElement>(null)
  const [targetKind, setTargetKind] = useState<TargetKind>('literal')
  const [useLlm, setUseLlm] = useState(initial?.use_llm ?? false)
  const [ollamaModel, setOllamaModel] = useState(
    () => initial?.ollama_model ?? storedOllamaModel() ?? DEFAULT_OLLAMA_MODEL,
  )
  const [health, setHealth] = useState<HealthResponse | null>(null)
  const [healthCheckPending, setHealthCheckPending] = useState(false)
  const [healthCheckCycle, setHealthCheckCycle] = useState(0)
  const [ollamaStartupRetryActive, setOllamaStartupRetryActive] = useState(false)
  const [ollamaStartupRetryExpired, setOllamaStartupRetryExpired] = useState(false)
  const [loadError, setLoadError] = useState<string | null>(null)
  const [pickError, setPickError] = useState<string | null>(null)
  const [maxFileSizeMb, setMaxFileSizeMb] = useState(restoredOptions.max_file_size / 1_000_000)
  const [maxStructuredFileSizeMb, setMaxStructuredFileSizeMb] = useState(
    restoredOptions.max_structured_file_size / 1_000_000,
  )
  const [ignoredDirectories, setIgnoredDirectories] = useState(
    restoredOptions.ignored_directories.join(', '),
  )
  const [includedExtensions, setIncludedExtensions] = useState(
    restoredOptions.included_extensions.join(', '),
  )
  const [excludedExtensions, setExcludedExtensions] = useState(
    restoredOptions.excluded_extensions.join(', '),
  )
  const [archiveDepth, setArchiveDepth] = useState(restoredOptions.archive_depth)
  const [aiTimeoutSeconds, setAiTimeoutSeconds] = useState(restoredOptions.ai_timeout_seconds)
  const [maxWorkers, setMaxWorkers] = useState(restoredOptions.max_workers)
  const [documentWorkers, setDocumentWorkers] = useState(restoredOptions.document_workers)
  const [chunkSizeKb, setChunkSizeKb] = useState(restoredOptions.chunk_size / 1024)
  const [useRedactLensignore, setUseRedactLensignore] = useState(
    restoredOptions.use_redactlensignore,
  )
  const [advancedOptionsOpen, setAdvancedOptionsOpen] = useState(false)
  const [onDeviceHelpOpen, setOnDeviceHelpOpen] = useState(false)

  useEffect(() => {
    getDetectors()
      .then((list) => {
        setDetectors(list)
        // Default to everything selected, unless we're restoring a previous
        // setup — then the user's own selection wins.
        if (!initial || initial.categories.length === 0) {
          setSelectedCategories(new Set(list.map((d) => d.category)))
        }
        setDetectorsLoaded(true)
      })
      .catch((err: unknown) => {
        setLoadError(err instanceof Error ? err.message : 'Could not load detector list.')
      })
  }, [initial])

  useEffect(() => {
    let cancelled = false
    let retryTimer: number | undefined
    const retryDeadline = Date.now() + OLLAMA_STARTUP_RETRY_WINDOW_MS

    async function checkHealth(firstCheck = false) {
      if (cancelled) return
      setHealthCheckPending(true)
      if (firstCheck) {
        setOllamaStartupRetryActive(false)
        setOllamaStartupRetryExpired(false)
      }

      try {
        const nextHealth = await getHealth()
        if (cancelled) return

        setHealth(nextHealth)
        if (!modelIsAvailable(nextHealth, ollamaModel)) {
          setUseLlm(false)
        }

        if (ollamaServiceIsUnavailable(nextHealth)) {
          if (Date.now() < retryDeadline) {
            setOllamaStartupRetryActive(true)
            retryTimer = window.setTimeout(
              () => void checkHealth(),
              OLLAMA_STARTUP_RETRY_INTERVAL_MS,
            )
          } else {
            setOllamaStartupRetryActive(false)
            setOllamaStartupRetryExpired(true)
          }
        } else {
          setOllamaStartupRetryActive(false)
          setOllamaStartupRetryExpired(false)
        }
      } catch {
        if (cancelled) return
        setHealth({ status: 'unreachable', ollama_available: false })
        setUseLlm(false)
        setOllamaStartupRetryActive(false)
      } finally {
        if (!cancelled) {
          setHealthCheckPending(false)
        }
      }
    }

    void checkHealth(true)

    return () => {
      cancelled = true
      if (retryTimer !== undefined) {
        window.clearTimeout(retryTimer)
      }
    }
  }, [healthCheckCycle, initial, ollamaModel])

  useEffect(() => {
    try {
      localStorage.setItem(OLLAMA_MODEL_STORAGE_KEY, ollamaModel)
    } catch {
      // Storage can be unavailable in a locked-down browser. The in-memory
      // selection still works for the current app session.
    }
  }, [ollamaModel])

  const categories = Array.from(new Set(detectors.map((d) => d.category))).sort()
  const hasSelectedCategory = categories.some((category) => selectedCategories.has(category))
  const categorySelectionError =
    detectorsLoaded && !hasSelectedCategory
      ? categories.length > 0
        ? 'Select at least one category to scan.'
        : 'No scan categories are available. Reload RedactLens and try again.'
      : ''
  const detectorLoadPending = !detectorsLoaded && !loadError
  const categoryDescriptionId = categorySelectionError
    ? 'category-selection-error'
    : loadError
      ? 'detector-load-error'
      : detectorLoadPending
        ? 'category-loading-status'
        : undefined
  const hasDescriptionTargets = targets.some((t) => t.kind === 'description')
  const installedOllamaModels = health?.ollama_models ?? []
  const selectedModelAvailable = health !== null && modelIsAvailable(health, ollamaModel)
  const aiWillActuallyRun = useLlm && selectedModelAvailable
  const descriptionNeedsAiWarning =
    (targetKind === 'description' || hasDescriptionTargets) && !aiWillActuallyRun

  const trimmedPath = path.trim()
  const ignoredDirectoryList = listValues(ignoredDirectories)
  const includedExtensionList = listValues(includedExtensions)
  const excludedExtensionList = listValues(excludedExtensions)
  const pathError =
    textLength(trimmedPath) > MAX_PATH_LENGTH
      ? 'The folder or file path can be up to 4,096 characters. Shorten it before scanning.'
      : ''
  const ignoredDirectoriesError = [
    ignoredDirectoryList.length > MAX_OPTION_ENTRIES
      ? 'Use no more than 256 ignored directory names.'
      : null,
    ignoredDirectoryList.some((value) => textLength(value) > MAX_IGNORED_DIRECTORY_LENGTH)
      ? 'Each ignored directory name can be up to 255 characters.'
      : null,
    ignoredDirectoryList.some((value) => !isIndividualDirectoryName(value))
      ? 'Ignored directories must be individual names, not paths.'
      : null,
  ]
    .filter(Boolean)
    .join(' ')
  const includedExtensionsError = [
    includedExtensionList.length > MAX_OPTION_ENTRIES
      ? 'Use no more than 256 included extensions.'
      : null,
    includedExtensionList.some((value) => textLength(value) > MAX_EXTENSION_LENGTH)
      ? 'Each included extension can be up to 32 characters.'
      : null,
    includedExtensionList.some((value) => !isExtensionName(value))
      ? 'Included extensions must be names such as .txt, not paths.'
      : null,
  ]
    .filter(Boolean)
    .join(' ')
  const excludedExtensionsError = [
    excludedExtensionList.length > MAX_OPTION_ENTRIES
      ? 'Use no more than 256 excluded extensions.'
      : null,
    excludedExtensionList.some((value) => textLength(value) > MAX_EXTENSION_LENGTH)
      ? 'Each excluded extension can be up to 32 characters.'
      : null,
    excludedExtensionList.some((value) => !isExtensionName(value))
      ? 'Excluded extensions must be names such as .txt, not paths.'
      : null,
  ]
    .filter(Boolean)
    .join(' ')
  const extensionOverlap = includedExtensionList
    .map(normalizedExtension)
    .filter((extension) => excludedExtensionList.map(normalizedExtension).includes(extension))
  const workerOptionsError = documentWorkers > maxWorkers
  const extensionOptionsError = extensionOverlap.length > 0
  const optionsError = [
    ignoredDirectoriesError || null,
    includedExtensionsError || null,
    excludedExtensionsError || null,
    workerOptionsError ? 'Structured-document workers cannot exceed total file workers.' : null,
    extensionOptionsError
      ? `Extensions cannot be both included and excluded: ${extensionOverlap.join(', ')}`
      : null,
  ]
    .filter(Boolean)
    .join(' ')
  const targetDraftError =
    textLength(targetValue.trim()) > MAX_USER_TARGET_LENGTH
      ? 'Custom targets can be up to 8,192 characters. Shorten this value before adding it.'
      : ''
  const storedTargetError =
    targets.length > MAX_USER_TARGETS
      ? 'This setup has more than 100 custom targets. Remove targets before scanning.'
      : targets.some((target) => textLength(target.value) > MAX_USER_TARGET_LENGTH)
        ? 'This setup contains a custom target longer than 8,192 characters. Shorten or remove it before scanning.'
        : ''
  const targetLimitReached = targets.length >= MAX_USER_TARGETS

  function scanRequest(nextTargets: UserTarget[] = targets): ScanRequest {
    return {
      paths: [trimmedPath],
      categories: Array.from(selectedCategories),
      user_targets: nextTargets,
      use_llm: useLlm && selectedModelAvailable,
      ollama_model: ollamaModel,
      options: {
        max_file_size: Math.round(maxFileSizeMb * 1_000_000),
        max_structured_file_size: Math.round(maxStructuredFileSizeMb * 1_000_000),
        ignored_directories: ignoredDirectoryList,
        included_extensions: includedExtensionList,
        excluded_extensions: excludedExtensionList,
        archive_depth: archiveDepth,
        ai_timeout_seconds: aiTimeoutSeconds,
        max_workers: maxWorkers,
        document_workers: documentWorkers,
        chunk_size: Math.round(chunkSizeKb * 1024),
        use_redactlensignore: useRedactLensignore,
      },
    }
  }

  const requestSizeError =
    requestBytes(scanRequest()) > MAX_SCAN_REQUEST_BYTES
      ? 'This scan setup is too large to send. Shorten or remove custom targets and try again.'
      : ''
  const targetValidationError =
    targetDraftError || storedTargetError || requestSizeError || targetActionError || ''
  const submitDisabled =
    !trimmedPath ||
    Boolean(pathError) ||
    !detectorsLoaded ||
    Boolean(categorySelectionError) ||
    Boolean(optionsError) ||
    Boolean(storedTargetError) ||
    Boolean(requestSizeError)

  const aiHint =
    health === null || healthCheckPending
      ? 'Checking for a local AI model…'
      : health.status === 'unreachable'
        ? 'Couldn’t check local AI right now — RedactLens will keep using its built-in rules.'
        : selectedModelAvailable
          ? `${ollamaModel} is installed locally. Catches things patterns miss — source excerpts are sent only to your local Ollama service; RedactLens does not upload them.`
          : health.ollama_status === 'model_missing' || health.ollama_status === 'ready'
            ? `${ollamaModel} is not installed locally yet.`
            : 'Ollama isn’t running — RedactLens will still scan using its built-in rules.'
  const ollamaStatus =
    health?.status === 'ok' &&
    health.ollama_status !== 'unavailable' &&
    !(
      health.ollama_status === undefined &&
      health.ollama_models === undefined &&
      !health.ollama_available
    )
      ? selectedModelAvailable
        ? 'ready'
        : 'model_missing'
      : 'unavailable'
  const showOllamaSetup = health?.status === 'ok' && ollamaStatus !== 'ready'
  const showRecommendedModelSize = ollamaModel === DEFAULT_OLLAMA_MODEL
  const selectedModelIsListed = installedOllamaModels.some((model) => model.name === ollamaModel)

  function checkOllamaAgain() {
    setHealthCheckCycle((cycle) => cycle + 1)
  }

  function resetAdvancedScanOptions() {
    setOllamaModel(DEFAULT_OLLAMA_MODEL)
    setMaxFileSizeMb(DEFAULT_SCAN_OPTIONS.max_file_size / 1_000_000)
    setMaxStructuredFileSizeMb(DEFAULT_SCAN_OPTIONS.max_structured_file_size / 1_000_000)
    setIgnoredDirectories(DEFAULT_SCAN_OPTIONS.ignored_directories.join(', '))
    setIncludedExtensions(DEFAULT_SCAN_OPTIONS.included_extensions.join(', '))
    setExcludedExtensions(DEFAULT_SCAN_OPTIONS.excluded_extensions.join(', '))
    setArchiveDepth(DEFAULT_SCAN_OPTIONS.archive_depth)
    setAiTimeoutSeconds(DEFAULT_SCAN_OPTIONS.ai_timeout_seconds)
    setMaxWorkers(DEFAULT_SCAN_OPTIONS.max_workers)
    setDocumentWorkers(DEFAULT_SCAN_OPTIONS.document_workers)
    setChunkSizeKb(DEFAULT_SCAN_OPTIONS.chunk_size / 1024)
    setUseRedactLensignore(DEFAULT_SCAN_OPTIONS.use_redactlensignore)
    onRequestChange?.()
  }

  function toggleCategory(category: string) {
    setSelectedCategories((prev) => {
      const next = new Set(prev)
      if (next.has(category)) {
        next.delete(category)
      } else {
        next.add(category)
      }
      return next
    })
  }

  function addTarget() {
    const value = targetValue.trim()
    if (!value) {
      setTargetActionError('Enter an exact value or description before adding this rule.')
      targetInputRef.current?.focus()
      return
    }
    if (textLength(value) > MAX_USER_TARGET_LENGTH) {
      setTargetActionError(
        'Custom targets can be up to 8,192 characters. Shorten this value before adding it.',
      )
      return
    }
    if (targets.length >= MAX_USER_TARGETS) {
      setTargetActionError(
        'You can add up to 100 custom targets. Remove one before adding another.',
      )
      return
    }
    const nextTargets: UserTarget[] = [...targets, { kind: targetKind, value, category: 'custom' }]
    if (requestBytes(scanRequest(nextTargets)) > MAX_SCAN_REQUEST_BYTES) {
      setTargetActionError(
        'Adding this target would make the scan setup too large to send. Shorten it or remove another target.',
      )
      return
    }
    setTargets(nextTargets)
    onRequestChange?.()
    setTargetValue('')
    setTargetActionError(null)
    setTargetAnnouncement(
      `Added ${targetKind === 'literal' ? 'exact-value' : 'description'} target.`,
    )
  }

  function onTargetKeyDown(event: KeyboardEvent<HTMLInputElement>) {
    if (event.key === 'Enter') {
      event.preventDefault()
      addTarget()
    }
  }

  function removeTarget(index: number) {
    const removed = targets[index]
    targetInputRef.current?.focus()
    setTargets((prev) => prev.filter((_, i) => i !== index))
    onRequestChange?.()
    setTargetActionError(null)
    setTargetAnnouncement(
      `Removed ${removed?.kind === 'description' ? 'description' : 'exact-value'} target. Focus returned to the target field.`,
    )
  }

  function handleSubmit(event: FormEvent) {
    event.preventDefault()
    if (submitDisabled) return
    onSubmit(scanRequest())
  }

  return (
    <section aria-labelledby="setup-heading">
      <header className="setup__header">
        <div className="setup__logo" aria-hidden="true">
          <img src="/redactlens-mark.svg" alt="" />
        </div>
        <div>
          <h1 id="setup-heading" className="setup__title" tabIndex={-1}>
            RedactLens
          </h1>
          <p className="setup__tagline">Finds sensitive data before you share it.</p>
        </div>
        <button
          type="button"
          className="ondevice-help"
          aria-label="On device"
          aria-describedby="ondevice-tooltip"
          onMouseEnter={() => setOnDeviceHelpOpen(true)}
          onMouseLeave={(event) => {
            if (!event.currentTarget.contains(document.activeElement)) setOnDeviceHelpOpen(false)
          }}
          onFocus={() => setOnDeviceHelpOpen(true)}
          onBlur={() => setOnDeviceHelpOpen(false)}
          onClick={() => setOnDeviceHelpOpen(true)}
          onKeyDown={(event) => {
            if (event.key === 'Escape') {
              event.preventDefault()
              setOnDeviceHelpOpen(false)
            }
          }}
        >
          <span className="ondevice-pill" aria-hidden="true">
            <IconLock size={11} />
            On device
          </span>
          <span
            id="ondevice-tooltip"
            role="tooltip"
            aria-hidden={!onDeviceHelpOpen}
            className={`ondevice-tooltip${onDeviceHelpOpen ? ' ondevice-tooltip--open' : ''}`}
          >
            {ON_DEVICE_HELP}
          </span>
        </button>
      </header>

      <hr className="rule" />

      {loadError && (
        <p id="detector-load-error" role="alert" className="error-banner">
          {loadError}
        </p>
      )}

      <form onSubmit={handleSubmit} onChange={() => onRequestChange?.()}>
        <h2 className="section-title">Where should I look?</h2>
        <div className="path-row">
          <div className="path-input">
            <IconFolder size={17} />
            <input
              type="text"
              value={path}
              onChange={(e) => setPath(e.target.value)}
              placeholder="Drop a folder or paste a path…"
              aria-label="Folder or file to scan"
              aria-invalid={pathError ? true : undefined}
              aria-describedby={pathError ? 'scan-path-error' : undefined}
            />
          </div>
          <BrowseButton
            onPicked={(chosen) => {
              setPickError(null)
              setPath(chosen)
              onRequestChange?.()
            }}
            onError={() =>
              setPickError('Couldn’t open the file picker — type the path in instead.')
            }
          />
        </div>
        {pathError && (
          <p id="scan-path-error" role="alert" className="hint hint--error">
            {pathError}
          </p>
        )}
        <p className="hint">
          <IconInfo size={12} />
          Nothing is uploaded — the scan runs right here.
        </p>
        {pickError && (
          <p role="alert" className="hint hint--error">
            {pickError}
          </p>
        )}

        <div className="setup__grid">
          <div className="setup__col">
            <h2 id="category-heading" className="section-title section-title--spaced">
              What should I flag?
            </h2>
            <div
              className="cat-list"
              role="group"
              aria-labelledby="category-heading"
              aria-describedby={categoryDescriptionId}
              aria-busy={detectorLoadPending ? true : undefined}
            >
              {categories.map((category) => {
                const meta = categoryMeta(category)
                const on = selectedCategories.has(category)
                return (
                  <label key={category} className={`cat-row${on ? ' cat-row--on' : ''}`}>
                    <input
                      type="checkbox"
                      className="visually-hidden"
                      checked={on}
                      aria-invalid={categorySelectionError ? true : undefined}
                      aria-describedby={
                        categorySelectionError ? 'category-selection-error' : undefined
                      }
                      onChange={() => toggleCategory(category)}
                    />
                    <span className="cat-row__icon" aria-hidden="true">
                      {meta.icon}
                    </span>
                    <span>
                      <span className="cat-row__title">{meta.title}</span>
                      <span className="cat-row__desc">{meta.description}</span>
                    </span>
                    <span className="cat-row__mark" aria-hidden="true">
                      {on && <IconCheck size={14} />}
                    </span>
                  </label>
                )
              })}
            </div>
            {detectorLoadPending && (
              <p id="category-loading-status" role="status" className="hint">
                Loading scan categories...
              </p>
            )}
            {categorySelectionError && (
              <p id="category-selection-error" role="alert" className="hint hint--error">
                {categorySelectionError}
              </p>
            )}

            <button
              type="button"
              role="switch"
              aria-checked={useLlm}
              disabled={!selectedModelAvailable}
              className={`ai-card${useLlm ? ' ai-card--on' : ''}`}
              onClick={() => {
                setUseLlm((v) => !v)
                onRequestChange?.()
              }}
            >
              <span className="ai-card__lead">
                <span className="ai-card__chip" aria-hidden="true">
                  <IconCpu size={18} />
                </span>
                <span>
                  <span className="ai-card__title">On-device AI for fuzzier matches</span>
                  <span className="ai-card__desc">{aiHint}</span>
                </span>
              </span>
              <span className={`switch${useLlm ? ' switch--on' : ''}`} aria-hidden="true">
                <span className="switch__knob" />
              </span>
            </button>
            <span className="visually-hidden" aria-live="polite" aria-atomic="true">
              {aiHint}
            </span>
            {showOllamaSetup && (
              <aside className="ai-setup" aria-labelledby="ai-setup-heading">
                <h3 id="ai-setup-heading">
                  {ollamaStatus === 'model_missing'
                    ? 'Download the local AI model'
                    : 'Set up local AI'}
                </h3>
                {ollamaStatus === 'model_missing' ? (
                  <p>Ollama is running, but RedactLens&rsquo;s configured model is missing.</p>
                ) : (
                  <p>
                    Start Ollama from the Windows Start menu. If it isn&rsquo;t installed, follow
                    these steps:
                  </p>
                )}
                {ollamaStatus === 'unavailable' && ollamaStartupRetryActive && (
                  <p className="ai-setup__startup-status" aria-live="polite">
                    Ollama may still be starting with Windows. RedactLens is checking automatically
                    for up to two minutes—no repeated clicks needed.
                  </p>
                )}
                {ollamaStatus === 'unavailable' && ollamaStartupRetryExpired && (
                  <p
                    className="ai-setup__startup-status ai-setup__startup-status--expired"
                    aria-live="polite"
                  >
                    RedactLens still can&rsquo;t reach Ollama. Make sure Ollama is open, then choose
                    Check again. Built-in scanning remains available.
                  </p>
                )}
                <ol>
                  {ollamaStatus !== 'model_missing' && (
                    <li>
                      <a href={OLLAMA_DOWNLOAD_URL} target="_blank" rel="noreferrer">
                        Download Ollama for Windows
                        <span className="visually-hidden"> (opens in your browser)</span>
                      </a>{' '}
                      and run the installer.
                    </li>
                  )}
                  <li>
                    Open PowerShell and run <code>ollama pull {ollamaModel}</code>.
                  </li>
                  <li>When the download finishes, return here and choose Check again.</li>
                </ol>
                <p className="ai-setup__note">
                  {showRecommendedModelSize
                    ? 'The configured model download is about 19 GB. '
                    : 'Local model downloads can be large. '}
                  {showRecommendedModelSize && (
                    <a href={OLLAMA_MODEL_URL} target="_blank" rel="noreferrer">
                      View model details
                      <span className="visually-hidden"> (opens in your browser)</span>
                    </a>
                  )}
                </p>
                <button
                  type="button"
                  className="ai-setup__check"
                  onClick={checkOllamaAgain}
                  disabled={healthCheckPending}
                >
                  {healthCheckPending ? 'Checking…' : 'Check again'}
                </button>
              </aside>
            )}
          </div>

          <div className="setup__col">
            <h2 className="section-title section-title--spaced">
              Anything specific you&rsquo;re worried about?
            </h2>
            <p className="section-sub">Add your own values or a plain-English description.</p>
            {targets.length > 0 && (
              <ul className="target-chips">
                {targets.map((t, i) => (
                  <li key={`${t.kind}-${t.value}-${i}`} className="target-chip">
                    <span
                      className={`target-chip__tag ${
                        t.kind === 'literal' ? 'target-chip__tag--exact' : 'target-chip__tag--desc'
                      }`}
                    >
                      {t.kind === 'literal' ? 'EXACT' : 'DESC'}
                    </span>
                    <span className="target-chip__text">{t.value}</span>
                    <button
                      type="button"
                      className="target-chip__remove"
                      onClick={() => removeTarget(i)}
                      aria-label={`Remove ${t.value}`}
                    >
                      ×
                    </button>
                  </li>
                ))}
              </ul>
            )}
            <p className="visually-hidden" aria-live="polite" aria-atomic="true">
              {targetAnnouncement}
            </p>
            <div className="target-box">
              <div className="target-box__input">
                <IconPencil size={15} />
                <input
                  ref={targetInputRef}
                  type="text"
                  value={targetValue}
                  onChange={(e) => {
                    setTargetValue(e.target.value)
                    setTargetActionError(null)
                  }}
                  onKeyDown={onTargetKeyDown}
                  placeholder='e.g. "my account number 4471…" or "project codenames"'
                  aria-label="Value or description"
                  aria-invalid={targetValidationError ? true : undefined}
                  aria-describedby={
                    targetValidationError
                      ? 'target-validation-error'
                      : targetLimitReached
                        ? 'target-limit-status'
                        : undefined
                  }
                />
              </div>
              <div className="target-box__row">
                <div className={`seg seg--${targetKind}`}>
                  <label className={`seg__btn${targetKind === 'literal' ? ' seg__btn--on' : ''}`}>
                    <input
                      type="radio"
                      name="target-kind"
                      className="visually-hidden"
                      checked={targetKind === 'literal'}
                      onChange={() => setTargetKind('literal')}
                    />
                    <span className="seg__indicator" aria-hidden="true" />
                    Exact value
                  </label>
                  <label
                    className={`seg__btn${targetKind === 'description' ? ' seg__btn--on' : ''}`}
                  >
                    <input
                      type="radio"
                      name="target-kind"
                      className="visually-hidden"
                      checked={targetKind === 'description'}
                      onChange={() => setTargetKind('description')}
                      aria-label="Plain-English description (needs local AI)"
                    />
                    <span className="seg__indicator" aria-hidden="true" />
                    Description
                  </label>
                </div>
                <button
                  type="button"
                  className="setup-secondary-button btn-add"
                  onClick={addTarget}
                  disabled={Boolean(targetDraftError) || targetLimitReached}
                >
                  Add
                </button>
              </div>
              {targetValidationError && (
                <p id="target-validation-error" role="alert" className="target-box__warn">
                  <IconInfo size={12} />
                  {targetValidationError}
                </p>
              )}
              {!targetValidationError && targetLimitReached && (
                <p id="target-limit-status" role="status" className="target-box__warn">
                  <IconInfo size={12} />
                  You have reached the limit of 100 custom targets. Remove one to add another.
                </p>
              )}
              <div
                className="target-box__ai-warning"
                data-visible={descriptionNeedsAiWarning}
                aria-hidden={!descriptionNeedsAiWarning}
              >
                <div className="target-box__ai-warning-inner">
                  <p
                    role={descriptionNeedsAiWarning ? 'alert' : undefined}
                    className="target-box__warn"
                  >
                    <IconAlertTriangle size={13} />
                    {descriptionTargetWarning(selectedModelAvailable)}
                  </p>
                </div>
              </div>
            </div>
          </div>
        </div>

        <div className="scan-options" data-open={advancedOptionsOpen}>
          <button
            type="button"
            className="scan-options__summary"
            aria-expanded={advancedOptionsOpen}
            aria-controls="advanced-scan-options-content"
            onClick={() => setAdvancedOptionsOpen((open) => !open)}
          >
            <span className="scan-options__chevron" aria-hidden="true">
              ▸
            </span>
            Advanced scan options
          </button>
          <div
            id="advanced-scan-options-content"
            className="scan-options__content"
            data-open={advancedOptionsOpen}
            aria-hidden={!advancedOptionsOpen}
            inert={!advancedOptionsOpen}
          >
            <div className="scan-options__content-inner">
              <div className="scan-options__intro-row">
                <p className="scan-options__intro">
                  Choose an installed local AI model, bound resource use, and narrow the files
                  included in this scan. Comma-separate individual directory names or extensions.
                  Each list accepts up to 256 entries; directory names can be 255 characters and
                  extensions 32.
                </p>
                <button
                  type="button"
                  className="setup-secondary-button scan-options__reset"
                  onClick={resetAdvancedScanOptions}
                >
                  Reset to defaults
                </button>
              </div>
              <div className="scan-options__model">
                <label htmlFor="ollama-model">Local AI model</label>
                <div className="scan-options__model-row">
                  <select
                    id="ollama-model"
                    value={ollamaModel}
                    aria-describedby="ollama-model-help"
                    disabled={
                      health === null || healthCheckPending || installedOllamaModels.length === 0
                    }
                    onChange={(event) => {
                      setOllamaModel(event.target.value)
                      onRequestChange?.()
                    }}
                  >
                    {!selectedModelIsListed && (
                      <option value={ollamaModel} disabled>
                        {health === null || healthCheckPending
                          ? 'Checking installed models…'
                          : ollamaStatus === 'unavailable'
                            ? `${ollamaModel} — Ollama unavailable`
                            : `${ollamaModel} — not installed${
                                ollamaModel === DEFAULT_OLLAMA_MODEL ? ' — Recommended' : ''
                              }`}
                      </option>
                    )}
                    {installedOllamaModels.map((model) => (
                      <option key={model.name} value={model.name}>
                        {model.name} — {formatModelSize(model.size_bytes)}
                        {model.name === DEFAULT_OLLAMA_MODEL ? ' — Recommended' : ''}
                      </option>
                    ))}
                  </select>
                  <button
                    type="button"
                    className="setup-secondary-button"
                    onClick={checkOllamaAgain}
                    disabled={healthCheckPending}
                  >
                    {healthCheckPending ? 'Refreshing…' : 'Refresh models'}
                  </button>
                </div>
                <p id="ollama-model-help">
                  Only models backed by verified local weight files and identified by Ollama as
                  local are selectable; cloud models and renamed cloud references are excluded.
                  Changing models can affect scan speed and detection quality.
                </p>
              </div>
              <div className="scan-options__grid">
                <label>
                  Maximum file size (MB)
                  <input
                    type="number"
                    min="0.001"
                    max="1000"
                    step="0.001"
                    required
                    value={maxFileSizeMb}
                    onChange={(event) => setMaxFileSizeMb(Number(event.target.value))}
                  />
                </label>
                <label>
                  Structured file limit (MB)
                  <input
                    type="number"
                    min="0.001"
                    max="250"
                    step="0.001"
                    required
                    value={maxStructuredFileSizeMb}
                    onChange={(event) => setMaxStructuredFileSizeMb(Number(event.target.value))}
                  />
                </label>
                <label>
                  Ignored directory names
                  <input
                    type="text"
                    value={ignoredDirectories}
                    onChange={(event) => setIgnoredDirectories(event.target.value)}
                    aria-invalid={ignoredDirectoriesError ? true : undefined}
                    aria-describedby={ignoredDirectoriesError ? 'scan-options-error' : undefined}
                  />
                </label>
                <label>
                  Include only extensions
                  <input
                    type="text"
                    placeholder=".py, .txt"
                    aria-invalid={
                      includedExtensionsError || extensionOptionsError ? true : undefined
                    }
                    aria-describedby={
                      includedExtensionsError || extensionOptionsError
                        ? 'scan-options-error'
                        : undefined
                    }
                    value={includedExtensions}
                    onChange={(event) => setIncludedExtensions(event.target.value)}
                  />
                </label>
                <label>
                  Excluded extensions
                  <input
                    type="text"
                    placeholder=".min.js, .map"
                    aria-invalid={
                      excludedExtensionsError || extensionOptionsError ? true : undefined
                    }
                    aria-describedby={
                      excludedExtensionsError || extensionOptionsError
                        ? 'scan-options-error'
                        : undefined
                    }
                    value={excludedExtensions}
                    onChange={(event) => setExcludedExtensions(event.target.value)}
                  />
                </label>
                <label>
                  Archive depth
                  <input
                    type="number"
                    min="1"
                    max="8"
                    required
                    value={archiveDepth}
                    onChange={(event) => setArchiveDepth(Number(event.target.value))}
                  />
                </label>
                <label>
                  Local AI timeout (seconds)
                  <input
                    type="number"
                    min="0.1"
                    max="600"
                    step="0.1"
                    required
                    value={aiTimeoutSeconds}
                    onChange={(event) => setAiTimeoutSeconds(Number(event.target.value))}
                  />
                </label>
                <label>
                  File workers
                  <input
                    type="number"
                    min="1"
                    max="16"
                    required
                    aria-invalid={workerOptionsError}
                    aria-describedby={workerOptionsError ? 'scan-options-error' : undefined}
                    value={maxWorkers}
                    onChange={(event) => setMaxWorkers(Number(event.target.value))}
                  />
                </label>
                <label>
                  Structured-document workers
                  <input
                    type="number"
                    min="1"
                    max="4"
                    required
                    aria-invalid={workerOptionsError}
                    aria-describedby={workerOptionsError ? 'scan-options-error' : undefined}
                    value={documentWorkers}
                    onChange={(event) => setDocumentWorkers(Number(event.target.value))}
                  />
                </label>
                <label>
                  Text chunk size (KiB)
                  <input
                    type="number"
                    min="64"
                    max="8192"
                    required
                    value={chunkSizeKb}
                    onChange={(event) => setChunkSizeKb(Number(event.target.value))}
                  />
                </label>
              </div>
              <label className="scan-options__check">
                <input
                  type="checkbox"
                  checked={useRedactLensignore}
                  onChange={(event) => setUseRedactLensignore(event.target.checked)}
                />
                Apply root-level .redactlensignore rules
              </label>
              {optionsError && (
                <p id="scan-options-error" className="scan-options__error" role="alert">
                  {optionsError}
                </p>
              )}
            </div>
          </div>
        </div>

        <div className="setup__cta-row">
          <button type="submit" className="cta" disabled={submitDisabled}>
            <IconSearch size={19} />
            {scanLabel(trimmedPath)}
          </button>
        </div>
      </form>
    </section>
  )
}
