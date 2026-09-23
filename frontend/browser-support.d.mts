export interface BrowserSupportEntry {
  readonly browser: string
  readonly platform: string
  readonly minimum: string
  readonly tier: 'supported' | 'best-effort'
}

export const browserBuildTargets: readonly string[]
export const browserSupportMatrix: readonly BrowserSupportEntry[]
export const requiredBrowserCapabilities: readonly string[]
