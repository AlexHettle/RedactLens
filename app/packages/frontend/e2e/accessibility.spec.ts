import AxeBuilder from '@axe-core/playwright'
import { expect, test, type Locator, type Page } from '@playwright/test'
import { FINDINGS, installMockApi, type ScanMode } from './accessibility-fixtures'

const WCAG_TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22a', 'wcag22aa']

async function expectNoAxeViolations(page: Page, state: string) {
  const results = await new AxeBuilder({ page }).withTags(WCAG_TAGS).analyze()
  const detail = results.violations
    .map((violation) => {
      const targets = violation.nodes.flatMap((node) => node.target).join(', ')
      return violation.id + ': ' + violation.help + ' (' + targets + ')'
    })
    .join('\n')
  expect(results.violations, state + ' axe violations:\n' + detail).toEqual([])
}

async function openSetup(page: Page, scanMode: ScanMode = 'complete') {
  await installMockApi(page, scanMode)
  await page.goto('/')
  await expect(page.getByRole('heading', { name: 'RedactLens' })).toBeFocused()
  await expect(page.getByRole('checkbox', { name: /Credentials/i })).toBeVisible()
}

async function startScan(page: Page) {
  await page.getByRole('textbox', { name: 'Folder or file to scan' }).fill('C:\\demo')
  await page.getByRole('button', { name: /Scan this location/i }).click()
}

async function openResults(page: Page) {
  await openSetup(page)
  await startScan(page)
  await expect(page.getByRole('heading', { name: /Here.s what I found/i })).toBeFocused()
  await expect(page.getByRole('button', { name: 'Review remediation' })).toBeVisible()
}

async function expectRepeatedAction(page: Page, name: string, expectedCount: number) {
  const actions = page.getByRole('button', { name, exact: true })
  await expect(actions).toHaveCount(expectedCount)
  const descriptionIds: string[] = []
  for (let index = 0; index < expectedCount; index += 1) {
    const action = actions.nth(index)
    await expect(action).toHaveAccessibleName(name)
    await expect(action).toHaveAccessibleDescription(/For finding .+ Full path: .+\./)
    descriptionIds.push((await action.getAttribute('aria-describedby')) ?? '')
  }
  expect(descriptionIds.every(Boolean)).toBe(true)
  expect(new Set(descriptionIds).size).toBe(expectedCount)
}

async function expectNoHorizontalOverflow(page: Page) {
  const dimensions = await page.evaluate(() => ({
    viewport: document.documentElement.clientWidth,
    content: document.documentElement.scrollWidth,
  }))
  expect(dimensions.content).toBeLessThanOrEqual(dimensions.viewport + 1)
}

async function expectNoClippedControls(page: Page) {
  const clipped = await page.locator('button, summary, label').evaluateAll((elements) =>
    elements
      .filter((element) => {
        const node = element as HTMLElement
        const style = getComputedStyle(node)
        const clipsX = ['hidden', 'clip'].includes(style.overflowX)
        const clipsY = ['hidden', 'clip'].includes(style.overflowY)
        return (
          (clipsX && node.scrollWidth > node.clientWidth + 1) ||
          (clipsY && node.scrollHeight > node.clientHeight + 1)
        )
      })
      .map((element) => (element.textContent ?? '').replace(/\s+/g, ' ').trim()),
  )
  expect(clipped).toEqual([])
}

async function setAppZoom(page: Page, target: string, clicks: number) {
  const root = page.locator('html')
  for (let index = 0; index < clicks; index += 1) {
    await page.getByRole('button', { name: 'Zoom in' }).click()
  }
  await expect(root).toHaveAttribute('data-zoom', target)
}

async function includeFirstFinding(page: Page): Promise<Locator> {
  const include = page
    .getByRole('button', { name: 'Include in redaction plan', exact: true })
    .first()
  await include.click()
  const review = page.getByRole('button', { name: 'Review remediation' })
  await expect(review).toBeEnabled()
  return review
}

test('axe scans setup and its empty-rule Add state', async ({ page }) => {
  await openSetup(page)
  await expectNoAxeViolations(page, 'setup')

  const add = page.getByRole('button', { name: 'Add' })
  const input = page.getByRole('textbox', { name: 'Value or description' })
  await expect(add).toBeDisabled()
  await input.fill('   ')
  await expect(add).toBeDisabled()
  await expect(page.getByRole('alert')).toHaveCount(0)
  await input.fill('passport number')
  await expect(add).toBeEnabled()
  await expectNoAxeViolations(page, 'setup Add states')
})

test('axe scans the active scanning state and honors reduced motion', async ({ page }) => {
  await page.emulateMedia({ reducedMotion: 'reduce' })
  await openSetup(page, 'pending')
  await startScan(page)

  await expect(page.getByRole('heading', { name: /Looking through your files/i })).toBeFocused()
  await expect(page.getByRole('progressbar', { name: 'Scan progress' })).toBeVisible()
  expect(await page.evaluate(() => matchMedia('(prefers-reduced-motion: reduce)').matches)).toBe(
    true,
  )
  await expect(page.locator('.scanning__ring').first()).toHaveCSS('display', 'none')
  await expect(page.locator('.progress__fill--indeterminate')).toHaveCSS('animation-name', 'none')
  await expectNoAxeViolations(page, 'active scanning with reduced motion')
})

test('axe scans results and full-value display with repeated action names', async ({ page }) => {
  await openResults(page)
  await expectNoAxeViolations(page, 'results')

  await expectRepeatedAction(page, 'Show in folder', FINDINGS.length)
  await expectRepeatedAction(page, 'Include in redaction plan', 2)
  await expectRepeatedAction(page, 'Ignore', 2)

  const selectors = page.getByRole('checkbox', { name: /^Select finding / })
  await expect(selectors).toHaveCount(2)
  const selectorNames = await selectors.evaluateAll((elements) =>
    elements.map(
      (element) => element.getAttribute('aria-label') ?? element.parentElement?.textContent ?? '',
    ),
  )
  expect(new Set(selectorNames).size).toBe(selectorNames.length)

  const fullValues = page.getByRole('switch', { name: 'Full finding values' })
  await expect(fullValues).toHaveText('Show full values')
  await fullValues.click()
  await expect(page.getByText('super-secret', { exact: true })).toBeVisible()
  await expect(page.getByText('alex@example.com', { exact: true })).toBeVisible()
  await expectNoAxeViolations(page, 'full-value results')
})

test('axe scans the remediation review dialog and its focus contract', async ({ page }) => {
  await openResults(page)
  const review = await includeFirstFinding(page)
  await review.click()

  const dialog = page.getByRole('dialog', { name: 'Choose how to save redacted files' })
  await expect(dialog).toBeFocused()
  await expect(dialog).toHaveAttribute('aria-modal', 'true')
  await expect(dialog.getByRole('radio', { name: /Create redacted copies/i })).toBeChecked()
  await expect(dialog.getByRole('radio', { name: 'Replace original files' })).not.toBeChecked()
  await expectNoAxeViolations(page, 'remediation review')
})

test('axe scans a backend error and verifies focus reaches it', async ({ page }) => {
  await openSetup(page, 'start-error')
  await startScan(page)

  const error = page.getByRole('alert').filter({
    hasText: 'The accessibility test scan could not start.',
  })
  await expect(error).toBeFocused()
  await expect(page.getByRole('heading', { name: 'RedactLens' })).toBeVisible()
  await expectNoAxeViolations(page, 'scan start error')
})

test('preserves results at 200%, 400%, and a 320 CSS-pixel viewport', async ({ page }) => {
  await page.setViewportSize({ width: 1280, height: 900 })
  await openResults(page)

  await setAppZoom(page, '200', 4)
  await expectNoHorizontalOverflow(page)
  await setAppZoom(page, '400', 3)
  await expect(page.getByRole('button', { name: 'Zoom in' })).toBeDisabled()
  await expectNoHorizontalOverflow(page)

  await page.keyboard.press('Control+0')
  await expect(page.locator('html')).toHaveAttribute('data-zoom', '100')
  await page.setViewportSize({ width: 320, height: 900 })
  await expect(page.getByRole('heading', { name: /Here.s what I found/i })).toBeVisible()
  await expect(page.getByRole('button', { name: 'Scan something else' })).toBeVisible()
  await expectNoHorizontalOverflow(page)
  await expectNoClippedControls(page)
  await expectNoAxeViolations(page, '320 CSS-pixel results reflow')
})

test('preserves content with WCAG text spacing overrides', async ({ page }) => {
  await openResults(page)
  await page.route('**/e2e-text-spacing.css', (route) =>
    route.fulfill({
      contentType: 'text/css',
      body: [
        '* { line-height: 1.5 !important; letter-spacing: 0.12em !important;',
        'word-spacing: 0.16em !important; }',
        'p { margin-bottom: 2em !important; }',
      ].join(' '),
    }),
  )
  await page.addStyleTag({
    url: '/e2e-text-spacing.css',
  })

  await expect(
    page.getByRole('button', { name: 'Include in redaction plan', exact: true }).first(),
  ).toBeVisible()
  await expectNoHorizontalOverflow(page)
  await expectNoClippedControls(page)
  await expectNoAxeViolations(page, 'WCAG text spacing')
})

test('preserves boundaries and focus in forced-colors mode', async ({ page }) => {
  await page.emulateMedia({ forcedColors: 'active' })
  await openSetup(page)

  expect(await page.evaluate(() => matchMedia('(forced-colors: active)').matches)).toBe(true)
  await expect(page.getByRole('button', { name: 'Add' })).toBeDisabled()
  const contrastSwitch = page.getByRole('switch', { name: 'High contrast' })
  await contrastSwitch.focus()
  const focusStyle = await contrastSwitch.evaluate((element) => {
    const style = getComputedStyle(element)
    return { outlineStyle: style.outlineStyle, outlineWidth: style.outlineWidth }
  })
  expect(focusStyle.outlineStyle).not.toBe('none')
  expect(focusStyle.outlineWidth).not.toBe('0px')
  await expect(page.locator('.cat-row').first()).toHaveCSS('border-top-style', 'solid')
  await expectNoAxeViolations(page, 'forced colors setup')
})
