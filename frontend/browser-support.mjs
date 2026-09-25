/**
 * Canonical browser build/support floor for the Harpocrates frontend.
 *
 * These targets match Vite 8's Baseline Widely Available target. Keeping them
 * explicit prevents a future Vite upgrade from silently changing the browser
 * floor without a review of the privacy/proof boundaries documented in
 * BROWSER_SUPPORT.md.
 */
export const browserBuildTargets = Object.freeze([
  'chrome111',
  'edge111',
  'firefox114',
  'safari16.4',
  'ios16.4',
])

export const browserSupportMatrix = Object.freeze([
  Object.freeze({ browser: 'Chrome', platform: 'desktop', minimum: '111', tier: 'supported' }),
  Object.freeze({ browser: 'Edge', platform: 'desktop', minimum: '111', tier: 'supported' }),
  Object.freeze({ browser: 'Firefox', platform: 'desktop', minimum: '114', tier: 'supported' }),
  Object.freeze({ browser: 'Safari', platform: 'macOS', minimum: '16.4', tier: 'supported' }),
  Object.freeze({ browser: 'Safari', platform: 'iOS/iPadOS', minimum: '16.4', tier: 'best-effort' }),
])

export const requiredBrowserCapabilities = Object.freeze([
  'secure-context Web Crypto (SubtleCrypto)',
  'WebAssembly',
  'module Web Workers',
  'BigInt',
  'File/Blob/ArrayBuffer APIs',
  'localStorage',
])
