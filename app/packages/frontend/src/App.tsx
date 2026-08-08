import { useEffect, useRef, useState } from 'react'
import './App.css'
import {
  deleteScan,
  getHealth,
  getScan,
  postScan,
  saveAppearanceTheme,
  subscribeToScanEvents,
} from './api/client'
import ResultsScreen from './components/ResultsScreen'
import ScanningScreen from './components/ScanningScreen'
import SetupScreen from './components/SetupScreen'
import TitleBar, { type Theme } from './components/TitleBar'
import type { PublicScanResult, ScanEvent, ScanRequest } from './types'

type Screen = 'setup' | 'scanning' | 'results'

const THEME_KEY = 'redactlens-theme'
const HIGH_CONTRAST_KEY = 'redactlens-high-contrast'
const ZOOM_KEY = 'redactlens-zoom'
const LEGACY_THEME_KEY = 'redactscout-theme'
const LEGACY_HIGH_CONTRAST_KEY = 'redactscout-high-contrast'
const ZOOM_LEVELS = [75, 100, 125, 150, 175, 200, 250, 300, 400] as const
type ZoomLevel = (typeof ZOOM_LEVELS)[number]
const THEME_TRANSITION_MS = 240
const TERMINAL_STATES = new Set(['complete', 'cancelled', 'failed', 'timed_out'])
const TERMINAL_EVENTS = new Set(['scan_completed', 'scan_cancelled', 'scan_failed'])
const RECOVERY_DELAYS_MS = [0, 300, 1200] as const
const RECOVERY_REQUEST_TIMEOUT_MS = 3000
const CANCELLATION_REQUEST_TIMEOUT_MS = 5000
const CANCELLATION_POLL_MS = 750
const RECOVERY_ERROR_MESSAGE =
  'Live scan updates are temporarily unavailable. Your partial results are still here. Retry the connection to continue.'
const CANCELLATION_ERROR_MESSAGE =
  'RedactLens could not confirm cancellation. The scan may still be running; retry cancellation or reconnect to check its status.'
const SCAN_EXPIRED_MESSAGE =
  'This scan expired. Its saved server-side session was cleared and any background work was asked to stop. Your previous settings are ready—run the scan again to continue.'

function hasErrorCode(error: unknown, code: string): boolean {
  return (
    typeof error === 'object' &&
    error !== null &&
    'code' in error &&
    (error as { code?: unknown }).code === code
  )
}

function getInitialTheme(): Theme {
  try {
    let stored = localStorage.getItem(THEME_KEY)
    if (stored === null) {
      stored = localStorage.getItem(LEGACY_THEME_KEY)
      if (stored !== null) localStorage.setItem(THEME_KEY, stored)
    }
    if (stored === 'light' || stored === 'dark') return stored
  } catch {
    /* storage unavailable — fall through to the system preference */
  }
  return window.matchMedia?.('(prefers-color-scheme: dark)')?.matches ? 'dark' : 'light'
}

function getInitialHighContrast(): boolean {
  try {
    let stored = localStorage.getItem(HIGH_CONTRAST_KEY)
    if (stored === null) {
      stored = localStorage.getItem(LEGACY_HIGH_CONTRAST_KEY)
      if (stored !== null) localStorage.setItem(HIGH_CONTRAST_KEY, stored)
    }
    return stored === 'true'
  } catch {
    return false
  }
}

function isZoomLevel(value: number): value is ZoomLevel {
  return ZOOM_LEVELS.some((level) => level === value)
}

function getInitialZoom(): ZoomLevel {
  try {
    const stored = Number(localStorage.getItem(ZOOM_KEY))
    if (isZoomLevel(stored)) return stored
  } catch {
    /* storage unavailable — use the default zoom */
  }
  return 100
}

function stepZoom(current: ZoomLevel, direction: -1 | 1): ZoomLevel {
  const currentIndex = ZOOM_LEVELS.indexOf(current)
  const nextIndex = Math.min(ZOOM_LEVELS.length - 1, Math.max(0, currentIndex + direction))
  return ZOOM_LEVELS[nextIndex]
}

function formatZoomDimension(scale: number, unit: '%' | 'vw' | 'svh'): string {
  return `${Number((100 / scale).toFixed(4))}${unit}`
}

function applyZoomPreference(zoom: ZoomLevel): void {
  const root = document.documentElement
  const scale = zoom / 100
  root.dataset.zoom = String(zoom)
  root.style.setProperty('--app-zoom', String(scale))
  root.style.setProperty('--app-layout-width', formatZoomDimension(scale, '%'))
  root.style.setProperty('--app-layout-height', formatZoomDimension(scale, 'svh'))
  root.style.setProperty('--app-viewport-width', formatZoomDimension(scale, 'vw'))
  root.style.setProperty('--app-viewport-height', formatZoomDimension(scale, 'svh'))
}

function applyEvent(result: PublicScanResult, event: ScanEvent): PublicScanResult {
  const findings = [...result.findings]
  if (event.finding) {
    const index = findings.findIndex((finding) => finding.id === event.finding?.id)
    if (index >= 0) findings[index] = event.finding
    else findings.push(event.finding)
  }

  const skippedFiles = [...result.skipped_files]
  if (event.skipped_file && !skippedFiles.some((item) => item.path === event.skipped_file?.path)) {
    skippedFiles.push(event.skipped_file)
  }

  const scannedFiles = [...result.scanned_files]
  if (
    event.type === 'file_completed' &&
    event.progress.current_file &&
    !scannedFiles.includes(event.progress.current_file)
  ) {
    scannedFiles.push(event.progress.current_file)
  }

  return {
    ...result,
    event_cursor: event.sequence,
    state: event.state,
    progress: event.progress,
    error: event.error,
    findings,
    skipped_files: skippedFiles,
    scanned_files: scannedFiles,
  }
}

function App() {
  const [theme, setTheme] = useState<Theme>(getInitialTheme)
  const [highContrast, setHighContrast] = useState(getInitialHighContrast)
  const [zoom, setZoom] = useState<ZoomLevel>(getInitialZoom)
  const [screen, setScreen] = useState<Screen>('setup')
  const [scanTarget, setScanTarget] = useState('')
  const [lastRequest, setLastRequest] = useState<ScanRequest | null>(null)
  const [activeScan, setActiveScan] = useState<PublicScanResult | null>(null)
  const [result, setResult] = useState<PublicScanResult | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [toast, setToast] = useState<string | null>(null)
  const [connectionError, setConnectionError] = useState<string | null>(null)
  const [cancelError, setCancelError] = useState<string | null>(null)
  const [isRecovering, setIsRecovering] = useState(false)
  const [isCancelling, setIsCancelling] = useState(false)

  // Promise callbacks from a prior ResultsScreen retain the callback from
  // their render. Keep the current result identity outside that closure so an
  // expired old request cannot tear down a replacement scan.
  const resultRef = useRef<PublicScanResult | null>(result)
  resultRef.current = result
  const scanSeqRef = useRef(0)
  const eventCursorRef = useRef(0)
  const recoveryRunRef = useRef(0)
  const recoveryInFlightRef = useRef(false)
  const recoveryAbortRef = useRef<AbortController | null>(null)
  const cancellationPollRef = useRef<ReturnType<typeof setTimeout> | null>(null)
  const cancelRequestedSeqRef = useRef<number | null>(null)
  const cancelInFlightRef = useRef(false)
  const cancelAbortRef = useRef<AbortController | null>(null)
  const streamGenerationRef = useRef(0)
  const streamCleanupRef = useRef<(() => void) | null>(null)
  const themeTransitionTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null)
  const errorRef = useRef<HTMLParagraphElement>(null)
  const focusedScreenRef = useRef<Screen | null>(null)

  useEffect(() => {
    document.documentElement.dataset.theme = theme
    try {
      localStorage.setItem(THEME_KEY, theme)
    } catch {
      /* storage unavailable — theme just won't persist */
    }
    void saveAppearanceTheme(theme).catch(() => {
      /* Native splash sync is best-effort; localStorage remains authoritative. */
    })
  }, [theme])

  useEffect(() => {
    if (highContrast) document.documentElement.dataset.contrast = 'high'
    else delete document.documentElement.dataset.contrast
    try {
      localStorage.setItem(HIGH_CONTRAST_KEY, String(highContrast))
    } catch {
      /* storage unavailable — high contrast just won't persist */
    }
  }, [highContrast])

  useEffect(() => {
    applyZoomPreference(zoom)
    try {
      localStorage.setItem(ZOOM_KEY, String(zoom))
    } catch {
      /* storage unavailable — zoom just won't persist */
    }
  }, [zoom])

  useEffect(() => {
    function handleZoomShortcut(event: KeyboardEvent) {
      if (!event.ctrlKey || event.altKey || event.metaKey) return
      if (event.key === '+' || event.key === '=') {
        event.preventDefault()
        setZoom((current) => stepZoom(current, 1))
      } else if (event.key === '-' || event.key === '_') {
        event.preventDefault()
        setZoom((current) => stepZoom(current, -1))
      } else if (event.key === '0') {
        event.preventDefault()
        setZoom(100)
      }
    }

    function handleZoomWheel(event: WheelEvent) {
      if (!event.ctrlKey || event.deltaY === 0) return
      event.preventDefault()
      setZoom((current) => stepZoom(current, event.deltaY < 0 ? 1 : -1))
    }

    window.addEventListener('keydown', handleZoomShortcut)
    window.addEventListener('wheel', handleZoomWheel, { passive: false })
    return () => {
      window.removeEventListener('keydown', handleZoomShortcut)
      window.removeEventListener('wheel', handleZoomWheel)
    }
  }, [])

  useEffect(() => {
    if (error) errorRef.current?.focus()
  }, [error])

  useEffect(() => {
    if (focusedScreenRef.current === screen) return
    focusedScreenRef.current = screen
    if (!error) document.getElementById(`${screen}-heading`)?.focus()
  }, [screen, error])

  useEffect(() => {
    const recoveryRun = recoveryRunRef
    const recoveryAbort = recoveryAbortRef
    const cancelAbort = cancelAbortRef
    const cancellationPoll = cancellationPollRef
    const streamCleanup = streamCleanupRef
    const themeTransitionTimer = themeTransitionTimerRef
    return () => {
      streamCleanup.current?.()
      recoveryRun.current++
      recoveryAbort.current?.abort()
      cancelAbort.current?.abort()
      if (cancellationPoll.current) clearTimeout(cancellationPoll.current)
      if (themeTransitionTimer.current) clearTimeout(themeTransitionTimer.current)
      document.documentElement.classList.remove('theme-transition')
      delete document.documentElement.dataset.zoom
      document.documentElement.style.removeProperty('--app-zoom')
      document.documentElement.style.removeProperty('--app-layout-width')
      document.documentElement.style.removeProperty('--app-layout-height')
      document.documentElement.style.removeProperty('--app-viewport-width')
      document.documentElement.style.removeProperty('--app-viewport-height')
    }
  }, [])

  useEffect(() => {
    const id = setInterval(
      () => {
        getHealth().catch(() => {})
      },
      4 * 60 * 1000,
    )
    return () => clearInterval(id)
  }, [])

  function showToast(message: string) {
    setToast(message)
  }

  function beginThemeTransition() {
    const root = document.documentElement
    root.classList.add('theme-transition')
    if (themeTransitionTimerRef.current) clearTimeout(themeTransitionTimerRef.current)
    themeTransitionTimerRef.current = setTimeout(() => {
      root.classList.remove('theme-transition')
      themeTransitionTimerRef.current = null
    }, THEME_TRANSITION_MS)
  }

  function toggleTheme() {
    beginThemeTransition()
    setTheme((currentTheme) => (currentTheme === 'dark' ? 'light' : 'dark'))
  }

  function toggleHighContrast() {
    beginThemeTransition()
    setHighContrast((currentValue) => !currentValue)
  }

  function zoomIn() {
    setZoom((current) => stepZoom(current, 1))
  }

  function zoomOut() {
    setZoom((current) => stepZoom(current, -1))
  }

  function closeEventStream() {
    streamGenerationRef.current++
    streamCleanupRef.current?.()
    streamCleanupRef.current = null
  }

  function clearCancellationPoll() {
    if (cancellationPollRef.current) clearTimeout(cancellationPollRef.current)
    cancellationPollRef.current = null
  }

  function cancelRecoveryWork() {
    recoveryRunRef.current++
    recoveryInFlightRef.current = false
    recoveryAbortRef.current?.abort()
    recoveryAbortRef.current = null
    clearCancellationPoll()
    setIsRecovering(false)
  }

  function cancelCancellationWork() {
    cancelAbortRef.current?.abort()
    cancelAbortRef.current = null
    cancelInFlightRef.current = false
  }

  function resetScanUi(message: string) {
    scanSeqRef.current++
    cancelRecoveryWork()
    cancelCancellationWork()
    closeEventStream()
    eventCursorRef.current = 0
    cancelRequestedSeqRef.current = null
    cancelInFlightRef.current = false
    resultRef.current = null
    setResult(null)
    setActiveScan(null)
    setConnectionError(null)
    setCancelError(null)
    setIsRecovering(false)
    setIsCancelling(false)
    setToast(null)
    setError(message)
    setScreen('setup')
  }

  function acceptSnapshot(
    snapshot: PublicScanResult,
    scanId: string,
    seq: number,
  ): 'ignored' | 'active' | 'terminal' | 'complete' {
    if (
      seq !== scanSeqRef.current ||
      snapshot.scan_id !== scanId ||
      !Number.isSafeInteger(snapshot.event_cursor) ||
      snapshot.event_cursor < eventCursorRef.current
    ) {
      return 'ignored'
    }

    eventCursorRef.current = snapshot.event_cursor
    setActiveScan(snapshot)
    setIsCancelling(snapshot.state === 'cancelling' || cancelRequestedSeqRef.current === seq)
    if (snapshot.state === 'complete') {
      closeEventStream()
      clearCancellationPoll()
      cancelRequestedSeqRef.current = null
      setIsCancelling(false)
      setCancelError(null)
      resultRef.current = snapshot
      setResult(snapshot)
      setActiveScan(null)
      setScreen('results')
      return 'complete'
    }
    if (TERMINAL_STATES.has(snapshot.state)) {
      closeEventStream()
      clearCancellationPoll()
      cancelRequestedSeqRef.current = null
      setIsCancelling(false)
      setCancelError(null)
      setScreen('scanning')
      return 'terminal'
    }
    setScreen('scanning')
    return 'active'
  }

  async function getSnapshotWithTimeout(scanId: string): Promise<PublicScanResult> {
    const controller = new AbortController()
    recoveryAbortRef.current?.abort()
    recoveryAbortRef.current = controller
    let timeout: ReturnType<typeof setTimeout> | null = null
    try {
      const timedOut = new Promise<never>((_, reject) => {
        timeout = setTimeout(() => {
          controller.abort()
          reject(new Error('Timed out while reading the current scan state.'))
        }, RECOVERY_REQUEST_TIMEOUT_MS)
      })
      return await Promise.race([getScan(scanId, controller.signal), timedOut])
    } finally {
      if (timeout) clearTimeout(timeout)
      if (recoveryAbortRef.current === controller) recoveryAbortRef.current = null
    }
  }

  function scheduleCancellationPoll(scanId: string, seq: number) {
    clearCancellationPoll()
    cancellationPollRef.current = setTimeout(() => {
      cancellationPollRef.current = null
      requestRecovery(scanId, seq)
    }, CANCELLATION_POLL_MS)
  }

  function openEventStream(scanId: string, seq: number, afterSequence: number): boolean {
    if (seq !== scanSeqRef.current) return false
    closeEventStream()
    const streamGeneration = streamGenerationRef.current
    try {
      streamCleanupRef.current = subscribeToScanEvents(
        scanId,
        afterSequence,
        (event) => {
          if (seq !== scanSeqRef.current || streamGeneration !== streamGenerationRef.current) {
            return
          }
          if (
            event.scan_id !== scanId ||
            !Number.isSafeInteger(event.sequence) ||
            event.sequence < 1
          ) {
            requestRecovery(scanId, seq)
            return
          }

          const currentCursor = eventCursorRef.current
          if (event.sequence <= currentCursor) return
          if (event.sequence !== currentCursor + 1) {
            requestRecovery(scanId, seq)
            return
          }

          eventCursorRef.current = event.sequence
          setActiveScan((current) => {
            if (!current || current.scan_id !== scanId) return current
            return applyEvent(current, event)
          })
          if (TERMINAL_EVENTS.has(event.type)) requestRecovery(scanId, seq)
        },
        () => {
          if (streamGeneration === streamGenerationRef.current) requestRecovery(scanId, seq)
        },
      )
      return true
    } catch {
      setConnectionError(RECOVERY_ERROR_MESSAGE)
      return false
    }
  }

  function requestRecovery(scanId: string, seq: number) {
    if (seq !== scanSeqRef.current || recoveryInFlightRef.current) return
    void recoverSnapshot(scanId, seq)
  }

  async function recoverSnapshot(
    scanId: string,
    seq: number,
    { force = false, manual = false }: { force?: boolean; manual?: boolean } = {},
  ) {
    if (seq !== scanSeqRef.current) return
    if (force) cancelRecoveryWork()
    if (recoveryInFlightRef.current) return

    const run = ++recoveryRunRef.current
    recoveryInFlightRef.current = true
    clearCancellationPoll()
    closeEventStream()
    setIsRecovering(true)
    if (manual) setConnectionError(null)

    for (const delay of RECOVERY_DELAYS_MS) {
      if (delay > 0) await new Promise((resolve) => setTimeout(resolve, delay))
      if (seq !== scanSeqRef.current || run !== recoveryRunRef.current) return

      try {
        const snapshot = await getSnapshotWithTimeout(scanId)
        if (seq !== scanSeqRef.current || run !== recoveryRunRef.current) return
        const accepted = acceptSnapshot(snapshot, scanId, seq)
        if (accepted === 'ignored') continue

        recoveryInFlightRef.current = false
        setIsRecovering(false)
        setConnectionError(null)
        if (accepted === 'active') {
          openEventStream(scanId, seq, eventCursorRef.current)
          if (snapshot.state === 'cancelling' || cancelRequestedSeqRef.current === seq) {
            scheduleCancellationPoll(scanId, seq)
          }
        }
        return
      } catch (err) {
        if (seq !== scanSeqRef.current || run !== recoveryRunRef.current) return
        if (hasErrorCode(err, 'scan_expired')) {
          resetScanUi(SCAN_EXPIRED_MESSAGE)
          return
        }
      }
    }

    if (seq !== scanSeqRef.current || run !== recoveryRunRef.current) return
    recoveryInFlightRef.current = false
    setIsRecovering(false)
    setConnectionError(RECOVERY_ERROR_MESSAGE)
    if (cancelRequestedSeqRef.current === seq) scheduleCancellationPoll(scanId, seq)
  }

  async function handleScan(request: ScanRequest) {
    const seq = ++scanSeqRef.current
    cancelRecoveryWork()
    cancelCancellationWork()
    closeEventStream()
    eventCursorRef.current = 0
    cancelRequestedSeqRef.current = null
    cancelInFlightRef.current = false
    setScanTarget(request.paths[0] ?? '')
    setLastRequest(request)
    setActiveScan(null)
    resultRef.current = null
    setResult(null)
    setConnectionError(null)
    setCancelError(null)
    setIsRecovering(false)
    setIsCancelling(false)
    setScreen('scanning')
    setError(null)

    let created: PublicScanResult
    try {
      created = await postScan(request)
    } catch (err) {
      if (seq !== scanSeqRef.current) return
      cancelRequestedSeqRef.current = null
      cancelInFlightRef.current = false
      setIsCancelling(false)
      setError(err instanceof Error ? err.message : 'Something went wrong while starting the scan.')
      setScreen('setup')
      return
    }
    if (seq !== scanSeqRef.current) {
      void deleteScan(created.scan_id).catch(() => {})
      return
    }

    const accepted = acceptSnapshot(created, created.scan_id, seq)
    if (accepted === 'ignored') {
      setConnectionError(RECOVERY_ERROR_MESSAGE)
      return
    }
    if (TERMINAL_STATES.has(created.state)) return

    if (cancelRequestedSeqRef.current === seq) {
      void requestCancellation(created.scan_id, seq)
      return
    }
    openEventStream(created.scan_id, seq, eventCursorRef.current)
  }

  async function requestCancellation(scanId: string, seq: number) {
    if (seq !== scanSeqRef.current || cancelInFlightRef.current) return
    cancelRecoveryWork()
    cancelInFlightRef.current = true
    cancelRequestedSeqRef.current = seq
    closeEventStream()
    setConnectionError(null)
    setCancelError(null)
    setIsCancelling(true)
    const controller = new AbortController()
    cancelAbortRef.current = controller
    let timeout: ReturnType<typeof setTimeout> | null = null
    try {
      const timedOut = new Promise<never>((_, reject) => {
        timeout = setTimeout(() => {
          controller.abort()
          reject(new Error('Timed out while requesting scan cancellation.'))
        }, CANCELLATION_REQUEST_TIMEOUT_MS)
      })
      await Promise.race([deleteScan(scanId, controller.signal), timedOut])
    } catch {
      if (seq !== scanSeqRef.current) return
      cancelInFlightRef.current = false
      cancelRequestedSeqRef.current = null
      setIsCancelling(false)
      setCancelError(CANCELLATION_ERROR_MESSAGE)
      void recoverSnapshot(scanId, seq, { force: true, manual: true })
      return
    } finally {
      if (timeout) clearTimeout(timeout)
      if (cancelAbortRef.current === controller) cancelAbortRef.current = null
    }
    if (seq !== scanSeqRef.current) return
    cancelInFlightRef.current = false
    void recoverSnapshot(scanId, seq, { force: true, manual: true })
  }

  function handleCancel() {
    if (activeScan && TERMINAL_STATES.has(activeScan.state)) {
      scanSeqRef.current++
      cancelRecoveryWork()
      cancelCancellationWork()
      closeEventStream()
      void deleteScan(activeScan.scan_id).catch(() => {})
      eventCursorRef.current = 0
      cancelRequestedSeqRef.current = null
      setActiveScan(null)
      setConnectionError(null)
      setCancelError(null)
      setIsRecovering(false)
      setIsCancelling(false)
      setScreen('setup')
      return
    }

    const seq = scanSeqRef.current
    if (cancelInFlightRef.current) return
    cancelRequestedSeqRef.current = seq
    setCancelError(null)
    setIsCancelling(true)
    if (activeScan) void requestCancellation(activeScan.scan_id, seq)
  }

  function handleRetryConnection() {
    if (
      !activeScan ||
      cancelInFlightRef.current ||
      isCancelling ||
      activeScan.state === 'cancelling'
    ) {
      return
    }
    void recoverSnapshot(activeScan.scan_id, scanSeqRef.current, { force: true, manual: true })
  }

  function handleStartOver() {
    scanSeqRef.current++
    cancelRecoveryWork()
    cancelCancellationWork()
    closeEventStream()
    const previousResult = resultRef.current
    resultRef.current = null
    if (previousResult) void deleteScan(previousResult.scan_id).catch(() => {})
    eventCursorRef.current = 0
    cancelRequestedSeqRef.current = null
    cancelInFlightRef.current = false
    setResult(null)
    setActiveScan(null)
    setConnectionError(null)
    setCancelError(null)
    setIsRecovering(false)
    setIsCancelling(false)
    setToast(null)
    setScreen('setup')
  }

  function handleSessionExpired(expectedScanId: string, message: string = SCAN_EXPIRED_MESSAGE) {
    if (resultRef.current?.scan_id !== expectedScanId) return
    resultRef.current = null
    resetScanUi(message)
    void deleteScan(expectedScanId).catch(() => {})
  }

  return (
    <main className="frame">
      <TitleBar
        theme={theme}
        highContrast={highContrast}
        zoom={zoom}
        onToggleTheme={toggleTheme}
        onToggleHighContrast={toggleHighContrast}
        onZoomIn={zoomIn}
        onZoomOut={zoomOut}
        onResetZoom={() => setZoom(100)}
      />
      <div className="frame__body">
        {error && (
          <p ref={errorRef} role="alert" className="error-banner" tabIndex={-1}>
            {error}
          </p>
        )}
        {screen === 'setup' && (
          <SetupScreen
            onSubmit={handleScan}
            onRequestChange={() => setError(null)}
            initial={lastRequest}
          />
        )}
        {screen === 'scanning' && (
          <ScanningScreen
            target={scanTarget}
            scan={activeScan}
            connectionError={connectionError}
            cancelError={cancelError}
            isRecovering={isRecovering}
            isCancelling={isCancelling}
            userTargets={lastRequest?.user_targets}
            onCancel={handleCancel}
            onRetryConnection={handleRetryConnection}
          />
        )}
        {screen === 'results' && result && (
          <ResultsScreen
            key={result.scan_id}
            result={result}
            isRefining={false}
            refineError={null}
            userTargets={lastRequest?.user_targets}
            onStartOver={handleStartOver}
            onSessionExpired={(message) => handleSessionExpired(result.scan_id, message)}
            onToast={showToast}
          />
        )}
      </div>
      {toast && (
        <div className="toast">
          <span role="status">{toast}</span>
          <button
            type="button"
            className="toast__dismiss"
            aria-label="Dismiss notification"
            onClick={() => setToast(null)}
          >
            ×
          </button>
        </div>
      )}
    </main>
  )
}

export default App
