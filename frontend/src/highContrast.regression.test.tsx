import React from 'react'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import App from './App'
import { useLiveRegion } from './hooks/useA11y'
import { safeLocalStorage } from './safeStorage'
import { expectNoA11yViolations, runAxe } from './test/axeA11y'

// jsdom externalises CSS imports, so read the canonical stylesheet from disk
// to assert on the OS-driven high-contrast overrides.
const appCss = readFileSync(join(process.cwd(), 'src', 'App.css'), 'utf8')

/**
 * High-contrast theme regression checks (Issue #318).
 *
 * Finding: the Harpocrates frontend has no JS theme system — no provider,
 * toggle, persisted theme state, or theme context. Contrast behavior is the
 * canonical dark token set in `App.css` plus OS-driven
 * `@media (prefers-contrast: more)` / `@media (forced-colors: active)`
 * overrides. These tests lock in that architecture:
 *
 * - high-contrast rendering follows the OS (CSS media queries), never app state
 * - key UI stays visible, named, and keyboard-operable when contrast is requested
 * - malformed/foreign theme values cannot create an invalid theme state
 * - failures stay privacy-safe (synthetic fixtures only; sanitised live regions)
 *
 * No protocol, artifact, contract, or storage behavior is covered here on
 * purpose: high-contrast handling is a frontend-only concern.
 */

vi.mock('./components/EvilEye', () => ({
  default: () => <div data-testid="evil-eye" />,
}))

// Offline/verify paths decode video in jsdom; stub the extractor like App.test.tsx.
vi.mock('./stego', () => ({
  extractMetadata: vi.fn().mockResolvedValue({
    protocol: 'harpocrates',
    version: 1,
    tier: 'silent',
    sourceHash: 'a'.repeat(64),
    proofId: 'b'.repeat(64),
    timestamp: '2026-01-01T00:00:00.000Z',
  }),
  MalformedEvidenceError: class MalformedEvidenceError extends Error {},
}))

const matchMediaOriginal = window.matchMedia

/** Simulate an OS contrast environment for code that reads matchMedia. */
function stubContrastEnvironment(options: { prefersContrastMore: boolean; forcedColors: boolean }) {
  const queryStates = new Map<string, boolean>([
    ['(prefers-contrast: more)', options.prefersContrastMore],
    ['(forced-colors: active)', options.forcedColors],
  ])
  Object.defineProperty(window, 'matchMedia', {
    configurable: true,
    value: (query: string) => ({
      matches: queryStates.get(query) ?? false,
      media: query,
      onchange: null,
      addListener: vi.fn(),
      removeListener: vi.fn(),
      addEventListener: vi.fn(),
      removeEventListener: vi.fn(),
      dispatchEvent: vi.fn().mockReturnValue(false),
    }),
  })
}

/** The app must never invent a JS-driven theme state. */
function expectNoJsThemeState() {
  expect(document.documentElement.getAttribute('data-theme')).toBeNull()
  expect(document.body.getAttribute('data-theme')).toBeNull()
  expect(document.documentElement.className).not.toMatch(/high-contrast|hc-theme/i)
  expect(document.body.className).not.toMatch(/high-contrast|hc-theme/i)
  expect(
    screen.queryByRole('button', { name: /theme|contrast mode|dark mode|light mode/i }),
  ).not.toBeInTheDocument()
}

function cssBlock(css: string, query: string): string {
  const start = css.indexOf(query)
  expect(start, `expected App.css to contain ${query}`).toBeGreaterThanOrEqual(0)
  let depth = 0
  let end = start
  for (let i = start; i < css.length; i += 1) {
    if (css[i] === '{') depth += 1
    if (css[i] === '}') {
      depth -= 1
      if (depth === 0) {
        end = i
        break
      }
    }
  }
  return css.slice(start, end + 1)
}

/** Drives the real sanitised live-region hook with synthetic fixture values. */
function AnnounceProbe({ message }: { message: string }) {
  const live = useLiveRegion()
  return (
    <>
      <div role="status" aria-live="polite" data-testid="probe-live">
        {live.message}
      </div>
      <button type="button" onClick={() => live.announce(message)}>
        announce failure
      </button>
    </>
  )
}

describe('high-contrast regression (Issue #318)', () => {
  beforeEach(() => {
    vi.restoreAllMocks()
    Object.defineProperty(window, 'scrollTo', {
      configurable: true,
      value: vi.fn(),
    })
    window.history.replaceState(null, '', '/')
    window.localStorage.clear()
    window.sessionStorage.clear()
  })

  afterEach(() => {
    if (matchMediaOriginal) {
      Object.defineProperty(window, 'matchMedia', {
        configurable: true,
        value: matchMediaOriginal,
      })
    }
    document.documentElement.removeAttribute('data-theme')
    document.body.removeAttribute('data-theme')
  })

  // ── Positive ──────────────────────────────────────────────────────────────

  it('drives high contrast through OS media queries, not a JS theme system', () => {
    render(<App />)

    // Stylesheet contract: jsdom has no layout engine and cannot evaluate
    // media queries, so the stylesheet source is the testable boundary for
    // these CSS-only overrides. Assert both OS signals exist and carry their
    // load-bearing declarations.
    const prefersMore = cssBlock(appCss, '@media (prefers-contrast: more)')
    expect(prefersMore).toMatch(/\.data-list\s+dd/)
    expect(prefersMore).toMatch(/redaction-preview__label/)
    expect(prefersMore).toMatch(/:focus-visible/)
    expect(prefersMore).toMatch(/outline-width:\s*3px/)
    // Selection state keeps a non-colour indicator when contrast is requested.
    expect(prefersMore).toMatch(/\.tier-tab\.active/)

    const forcedColors = cssBlock(appCss, '@media (forced-colors: active)')
    expect(forcedColors).toMatch(/CanvasText/)
    expect(forcedColors).toMatch(/:focus-visible/)
    expect(forcedColors).toMatch(/Highlight/)
    expect(forcedColors).toMatch(/\.tier-tab\.active/)
    // Decorative full-viewport layers must never cover content in WHCM.
    expect(forcedColors).toMatch(/\.signal-background/)
    expect(forcedColors).toMatch(/display:\s*none/)

    expectNoJsThemeState()
    expect(
      screen.getByRole('heading', { name: /evidence integrity for silent witnesses/i }),
    ).toBeInTheDocument()
  })

  it('keeps key UI visible and accessibly named when the OS requests more contrast', async () => {
    stubContrastEnvironment({ prefersContrastMore: true, forcedColors: false })
    const user = userEvent.setup()
    render(<App />)

    expect(screen.getByRole('link', { name: /skip to main content/i })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /^evidence$/i })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /^verify$/i })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /batch workspace/i })).toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: /begin evidence flow/i }))
    expect(screen.getByRole('heading', { name: /evidence studio/i })).toBeInTheDocument()
    // Tier state is conveyed by aria-pressed, never by colour alone.
    expect(screen.getByRole('button', { name: /silent witness/i })).toHaveAttribute('aria-pressed', 'true')

    await user.click(screen.getByRole('button', { name: /^verify$/i }))
    expect(screen.getByRole('heading', { name: /verify artifact/i })).toBeInTheDocument()
    expect(screen.getByLabelText(/drop or choose a received video/i)).toBeInTheDocument()
    expectNoJsThemeState()
  })

  it('stays axe-clean in every public view when high contrast is requested', async () => {
    stubContrastEnvironment({ prefersContrastMore: true, forcedColors: true })
    const user = userEvent.setup()

    const landing = render(<App />)
    expectNoA11yViolations(await runAxe(landing.container), 'landing (high contrast)')
    landing.unmount()

    const studio = render(<App />)
    await user.click(screen.getByRole('button', { name: /begin evidence flow/i }))
    expectNoA11yViolations(await runAxe(studio.container), 'evidence studio (high contrast)')
    studio.unmount()

    const verify = render(<App />)
    await user.click(screen.getByRole('button', { name: /^verify$/i }))
    expectNoA11yViolations(await runAxe(verify.container), 'verify (high contrast)')
    verify.unmount()

    const batch = render(<App />)
    await user.click(screen.getByRole('button', { name: /batch workspace/i }))
    expectNoA11yViolations(await runAxe(batch.container), 'batch workspace (high contrast)')
  })

  it('preserves existing UI state across view navigation while contrast is requested', async () => {
    stubContrastEnvironment({ prefersContrastMore: true, forcedColors: false })
    const user = userEvent.setup()
    render(<App />)

    await user.click(screen.getByRole('button', { name: /begin evidence flow/i }))
    await user.click(screen.getByRole('button', { name: /consistent source/i }))
    expect(screen.getByRole('button', { name: /consistent source/i })).toHaveAttribute('aria-pressed', 'true')

    await user.click(screen.getByRole('button', { name: /^verify$/i }))
    expect(screen.getByRole('heading', { name: /verify artifact/i })).toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: /^evidence$/i }))
    expect(screen.getByRole('button', { name: /consistent source/i })).toHaveAttribute('aria-pressed', 'true')
    expectNoJsThemeState()
  })

  // ── Negative ──────────────────────────────────────────────────────────────

  it('falls back safely on malformed or foreign stored values without creating theme state', () => {
    // safeStorage is the only sanctioned browser-storage boundary: malformed
    // JSON and unknown/foreign values must fall back to empty preferences
    // rather than throw or invent state.
    window.localStorage.setItem('harpocrates:ui-preferences', 'this is not valid json {{{')
    expect(safeLocalStorage.getUiPreferences()).toEqual({})
    window.localStorage.setItem(
      'harpocrates:ui-preferences',
      JSON.stringify({ currentView: 'nowhere', selectedTier: 'ultra-dark', theme: 'high-contrast' }),
    )
    expect(safeLocalStorage.getUiPreferences()).toEqual({})

    // Foreign theme keys are outside the storage schema and are never honoured.
    window.localStorage.setItem('harpocrates:theme', 'ultra-dark')
    window.localStorage.setItem('theme', '{"mode":"high-contrast"}')
    document.documentElement.setAttribute('data-theme', 'ultra-dark')

    render(<App />)

    // The app renders normally; the foreign attribute is not owned or honoured by it.
    expect(
      screen.getByRole('heading', { name: /evidence integrity for silent witnesses/i }),
    ).toBeInTheDocument()
    expect(document.body.getAttribute('data-theme')).toBeNull()
    expect(document.body.className).not.toMatch(/high-contrast|hc-theme/i)
  })

  it('keeps theme-adjacent failures privacy-safe: live regions never leak secrets', async () => {
    const user = userEvent.setup()
    // Synthetic fixtures only — no real media, evidence, witness, or wallet values.
    const syntheticHash = `deadbeef${'0123456789abcdef'.repeat(4)}`
    const syntheticAddress = `G${'A'.repeat(55)}`
    render(<AnnounceProbe message={`Theme failed for ${syntheticHash} ${syntheticAddress} /synthetic/fixtures/clip.mp4`} />)

    await user.click(screen.getByRole('button', { name: /announce failure/i }))

    const live = screen.getByTestId('probe-live')
    expect(live).toHaveTextContent('[redacted]')
    expect(live).toHaveTextContent('[address]')
    expect(live).toHaveTextContent('[path]')
    expect(live.textContent).not.toContain(syntheticHash)
    expect(live.textContent).not.toContain(syntheticAddress)
    expect(live.textContent).not.toContain('/synthetic/fixtures/clip.mp4')
  })

  it('does not corrupt UI state when an unrelated frontend failure occurs', async () => {
    const user = userEvent.setup()
    vi.spyOn(globalThis, 'fetch').mockRejectedValue(new Error('network unavailable'))
    render(<App />)

    await user.click(screen.getByRole('button', { name: /^verify$/i }))
    await user.upload(
      screen.getByLabelText(/drop or choose a received video/i),
      new File(['synthetic-bytes'], 'clip.mp4', { type: 'video/mp4' }),
    )

    expect(await screen.findByText(/verification services are unavailable/i)).toBeInTheDocument()
    // Navigation and view state still work; no theme state appears.
    await user.click(screen.getByRole('button', { name: /^evidence$/i }))
    expect(screen.getByRole('heading', { name: /evidence studio/i })).toBeInTheDocument()
    expectNoJsThemeState()
  })

  // ── Boundary / accessibility ──────────────────────────────────────────────

  it('keeps primary navigation keyboard-operable with visible focus semantics', async () => {
    stubContrastEnvironment({ prefersContrastMore: true, forcedColors: false })
    const user = userEvent.setup()
    render(<App />)

    const evidenceButton = screen.getByRole('button', { name: /^evidence$/i })
    evidenceButton.focus()
    expect(evidenceButton).toHaveFocus()
    // Keyboard activation (Enter) opens the studio; focus moves to its heading
    // after the app's short post-transition settle delay.
    await user.keyboard('{Enter}')
    const heading = await screen.findByRole('heading', { name: /evidence studio/i })
    await waitFor(() => expect(heading).toHaveFocus())

    // Skip link is the first focusable element and targets the main region.
    expect(screen.getByRole('link', { name: /skip to main content/i })).toHaveAttribute('href', '#main-content')
    expect(screen.getByRole('main')).toBeInTheDocument()
  })

  it('keeps core controls reachable at a mobile viewport while contrast is requested', async () => {
    stubContrastEnvironment({ prefersContrastMore: true, forcedColors: false })
    Object.defineProperty(window, 'innerWidth', { configurable: true, value: 390 })
    Object.defineProperty(window, 'innerHeight', { configurable: true, value: 844 })
    window.dispatchEvent(new Event('resize'))
    const user = userEvent.setup()
    render(<App />)

    expect(screen.getByRole('button', { name: /begin evidence flow/i })).toBeVisible()
    expect(screen.getByRole('button', { name: /verify an artifact/i })).toBeVisible()

    await user.click(screen.getByRole('button', { name: /begin evidence flow/i }))
    expect(screen.getByRole('heading', { name: /evidence studio/i })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /register proof/i })).toBeInTheDocument()
    expectNoJsThemeState()
  })

  it('creates no theme state across repeated view switching', async () => {
    stubContrastEnvironment({ prefersContrastMore: true, forcedColors: true })
    const user = userEvent.setup()
    render(<App />)

    for (let i = 0; i < 3; i += 1) {
      await user.click(screen.getByRole('button', { name: /^evidence$/i }))
      expect(screen.getByRole('heading', { name: /evidence studio/i })).toBeInTheDocument()
      await user.click(screen.getByRole('button', { name: /^verify$/i }))
      expect(screen.getByRole('heading', { name: /verify artifact/i })).toBeInTheDocument()
    }
    expectNoJsThemeState()
  })

  it('renders without crashing when matchMedia is unavailable', () => {
    Object.defineProperty(window, 'matchMedia', { configurable: true, value: undefined })

    render(<App />)
    expect(
      screen.getByRole('heading', { name: /evidence integrity for silent witnesses/i }),
    ).toBeInTheDocument()
    expectNoJsThemeState()
  })
})
