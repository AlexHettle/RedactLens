import { IconMoon, IconSun } from './Icons'

export type Theme = 'light' | 'dark'

interface TitleBarProps {
  theme: Theme
  highContrast: boolean
  onToggleTheme: () => void
  onToggleHighContrast: () => void
}

/** Persistent appearance controls, available from every app screen. */
export default function TitleBar({
  theme,
  highContrast,
  onToggleTheme,
  onToggleHighContrast,
}: TitleBarProps) {
  return (
    <header className="titlebar">
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
        onClick={onToggleTheme}
        aria-label={theme === 'dark' ? 'Switch to light theme' : 'Switch to dark theme'}
        title="Toggle theme"
      >
        {theme === 'dark' ? <IconSun /> : <IconMoon />}
      </button>
    </header>
  )
}
