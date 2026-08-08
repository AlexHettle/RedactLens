import { IconMoon, IconSun } from './Icons'

export type Theme = 'light' | 'dark'

interface TitleBarProps {
  theme: Theme
  highContrast: boolean
  zoom: number
  onToggleTheme: () => void
  onToggleHighContrast: () => void
  onZoomIn: () => void
  onZoomOut: () => void
  onResetZoom: () => void
}

/** Persistent appearance controls, available from every app screen. */
export default function TitleBar({
  theme,
  highContrast,
  zoom,
  onToggleTheme,
  onToggleHighContrast,
  onZoomIn,
  onZoomOut,
  onResetZoom,
}: TitleBarProps) {
  const themeToggleLabel = theme === 'dark' ? 'Switch to light theme' : 'Switch to dark theme'

  return (
    <header className="titlebar">
      <div className="titlebar__zoom" role="group" aria-label="Page zoom">
        <span className="titlebar__zoom-label">Zoom</span>
        <button
          type="button"
          className="titlebar__zoom-action"
          onClick={onZoomOut}
          disabled={zoom <= 75}
          aria-label="Zoom out"
          aria-keyshortcuts="Control+-"
          title="Zoom out (Ctrl+-)"
        >
          <span aria-hidden="true">−</span>
        </button>
        <button
          type="button"
          className="titlebar__zoom-value"
          onClick={onResetZoom}
          disabled={zoom === 100}
          aria-label={`Reset zoom to 100% (current zoom ${zoom}%)`}
          aria-keyshortcuts="Control+0"
          title="Reset zoom to 100% (Ctrl+0)"
        >
          {zoom}%
        </button>
        <button
          type="button"
          className="titlebar__zoom-action"
          onClick={onZoomIn}
          disabled={zoom >= 400}
          aria-label="Zoom in"
          aria-keyshortcuts="Control++"
          title="Zoom in (Ctrl++)"
        >
          <span aria-hidden="true">+</span>
        </button>
        <span className="visually-hidden" aria-live="polite" aria-atomic="true">
          Zoom {zoom} percent
        </span>
      </div>
      <button
        type="button"
        role="switch"
        aria-checked={highContrast}
        className="titlebar__contrast"
        onClick={onToggleHighContrast}
        title={highContrast ? 'Turn off high contrast' : 'Turn on high contrast'}
      >
        <span>High contrast</span>
        <span
          className={`titlebar__contrast-track${highContrast ? ' titlebar__contrast-track--on' : ''}`}
          aria-hidden="true"
        >
          <span className="titlebar__contrast-knob" />
        </span>
      </button>
      <button
        type="button"
        className="titlebar__theme"
        data-current-theme={theme}
        onClick={onToggleTheme}
        aria-label={themeToggleLabel}
        title={themeToggleLabel}
      >
        {theme === 'dark' ? (
          <IconSun size={18} strokeWidth={2.2} />
        ) : (
          <IconMoon size={18} strokeWidth={2.2} />
        )}
      </button>
    </header>
  )
}
