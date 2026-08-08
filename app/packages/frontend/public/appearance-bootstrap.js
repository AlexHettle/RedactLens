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

  var allowedZoomLevels = [75, 100, 125, 150, 175, 200, 250, 300, 400]
  var savedZoom = Number(localStorage.getItem('redactlens-zoom'))
  var zoom = allowedZoomLevels.indexOf(savedZoom) >= 0 ? savedZoom : 100
  var zoomScale = zoom / 100
  var layoutSize = Number((100 / zoomScale).toFixed(4))
  document.documentElement.dataset.zoom = String(zoom)
  document.documentElement.style.setProperty('--app-zoom', String(zoomScale))
  document.documentElement.style.setProperty('--app-layout-width', layoutSize + '%')
  document.documentElement.style.setProperty('--app-layout-height', layoutSize + 'svh')
  document.documentElement.style.setProperty('--app-viewport-width', layoutSize + 'vw')
  document.documentElement.style.setProperty('--app-viewport-height', layoutSize + 'svh')
} catch {
  // Default to light with standard contrast.
}
