// Apply saved appearance preferences before first paint to avoid a flash.
try {
  var theme = localStorage.getItem('redactlens-theme')
  if (theme === null) {
    theme = localStorage.getItem('redactscout-theme')
    if (theme !== null) localStorage.setItem('redactlens-theme', theme)
  }
  if (theme !== 'light' && theme !== 'dark') {
    theme =
      window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches
        ? 'dark'
        : 'light'
  }
  document.documentElement.dataset.theme = theme

  var contrast = localStorage.getItem('redactlens-high-contrast')
  if (contrast === null) {
    contrast = localStorage.getItem('redactscout-high-contrast')
    if (contrast !== null) localStorage.setItem('redactlens-high-contrast', contrast)
  }
  if (contrast === 'true') {
    document.documentElement.dataset.contrast = 'high'
  }
} catch {
  // Default to light with standard contrast.
}
