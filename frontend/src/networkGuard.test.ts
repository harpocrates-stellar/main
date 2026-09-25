/**
 * Tests for the network mismatch detection utility.
 *
 * Covers the acceptance criteria:
 *  - Testnet passphrase matches contract passphrase → no mismatch (positive case)
 *  - Wallet on Mainnet while contract is on Testnet → blocked with guidance
 *  - Wallet returns empty string (locked / unsupported extension) → blocked with guidance
 *  - Wallet returns null or undefined → blocked with same guidance as empty string
 *  - Any future unknown passphrase falls back to raw passphrase in the message
 *  - assertNetworkMatch throws NetworkMismatchError on mismatch
 *  - assertNetworkMatch does not throw on match
 */

import { describe, it, expect } from 'vitest'
import { checkNetworkMatch, networkName, assertNetworkMatch, NetworkMismatchError } from './networkGuard'

// Network passphrases used by the Stellar SDK.
const TESTNET = 'Test SDF Network ; September 2015'
const MAINNET = 'Public Global Stellar Network ; September 2015'
const FUTURENET = 'Test SDF Future Network ; October 2022'
const SANDBOX = 'Local Sandbox Stellar Network ; September 2022'
const STANDALONE = 'Standalone Network ; February 2017'
const UNKNOWN = 'My Private Network ; January 2024'

// ── networkName ────────────────────────────────────────────────────────────

describe('networkName', () => {
  it('returns "Testnet" for the testnet passphrase', () => {
    expect(networkName(TESTNET)).toBe('Testnet')
  })

  it('returns "Mainnet" for the public network passphrase', () => {
    expect(networkName(MAINNET)).toBe('Mainnet')
  })

  it('returns "Futurenet" for the futurenet passphrase', () => {
    expect(networkName(FUTURENET)).toBe('Futurenet')
  })

  it('returns "Sandbox" for the sandbox passphrase', () => {
    expect(networkName(SANDBOX)).toBe('Sandbox')
  })

  it('returns "Standalone" for the standalone passphrase', () => {
    expect(networkName(STANDALONE)).toBe('Standalone')
  })

  it('returns the raw passphrase for unknown networks', () => {
    expect(networkName(UNKNOWN)).toBe(UNKNOWN)
  })
})

// ── checkNetworkMatch – positive (matching) cases ─────────────────────────

describe('checkNetworkMatch – matching passphrases', () => {
  it('returns ok:true when wallet and contract are both on Testnet', () => {
    const result = checkNetworkMatch(TESTNET, TESTNET)
    expect(result.ok).toBe(true)
  })

  it('returns ok:true when wallet and contract are both on Mainnet', () => {
    const result = checkNetworkMatch(MAINNET, MAINNET)
    expect(result.ok).toBe(true)
  })

  it('trims leading/trailing whitespace from the wallet passphrase before comparing', () => {
    const result = checkNetworkMatch(`  ${TESTNET}  `, TESTNET)
    expect(result.ok).toBe(true)
  })
})

// ── checkNetworkMatch – mismatch cases ────────────────────────────────────

describe('checkNetworkMatch – mismatched passphrases', () => {
  it('returns ok:false when wallet is on Mainnet but contract is on Testnet', () => {
    const result = checkNetworkMatch(MAINNET, TESTNET)
    expect(result.ok).toBe(false)
    if (result.ok) return // type-narrowing guard for TS

    expect(result.reason).toContain('Mainnet')
    expect(result.reason).toContain('Testnet')
    expect(result.remediation).toContain('Testnet')
  })

  it('includes a switch instruction in the remediation message', () => {
    const result = checkNetworkMatch(MAINNET, TESTNET)
    if (result.ok) throw new Error('expected mismatch')
    expect(result.remediation).toMatch(/switch|open freighter/i)
  })

  it('returns ok:false when wallet is on Futurenet but contract is on Testnet', () => {
    const result = checkNetworkMatch(FUTURENET, TESTNET)
    expect(result.ok).toBe(false)
    if (result.ok) return

    expect(result.reason).toContain('Futurenet')
    expect(result.reason).toContain('Testnet')
  })

  it('uses the raw passphrase in the message for unknown networks', () => {
    const result = checkNetworkMatch(UNKNOWN, TESTNET)
    expect(result.ok).toBe(false)
    if (result.ok) return

    // The unknown passphrase should appear verbatim in the reason.
    expect(result.reason).toContain(UNKNOWN)
  })
})

// ── checkNetworkMatch – unsupported / unavailable cases ───────────────────

describe('checkNetworkMatch – unsupported wallet network', () => {
  it('returns ok:false when wallet passphrase is an empty string', () => {
    const result = checkNetworkMatch('', TESTNET)
    expect(result.ok).toBe(false)
  })

  it('includes an unlock/reconnect instruction when passphrase is empty', () => {
    const result = checkNetworkMatch('', TESTNET)
    if (result.ok) throw new Error('expected failure')
    // Should guide the user to unlock Freighter or reconnect.
    expect(result.remediation).toMatch(/unlock|reconnect/i)
  })

  it('returns ok:false when wallet passphrase is only whitespace', () => {
    const result = checkNetworkMatch('   ', TESTNET)
    expect(result.ok).toBe(false)
  })

  // ── null / undefined passphrase — regression for missing null guard ───────

  it('returns ok:false when wallet passphrase is null', () => {
    const result = checkNetworkMatch(null, TESTNET)
    expect(result.ok).toBe(false)
  })

  it('includes an unlock/reconnect instruction when passphrase is null', () => {
    const result = checkNetworkMatch(null, TESTNET)
    if (result.ok) throw new Error('expected failure')
    expect(result.remediation).toMatch(/unlock|reconnect/i)
  })

  it('returns ok:false when wallet passphrase is undefined', () => {
    const result = checkNetworkMatch(undefined, TESTNET)
    expect(result.ok).toBe(false)
  })

  it('includes an unlock/reconnect instruction when passphrase is undefined', () => {
    const result = checkNetworkMatch(undefined, TESTNET)
    if (result.ok) throw new Error('expected failure')
    expect(result.remediation).toMatch(/unlock|reconnect/i)
  })

  it('does not leak private context in the reason when passphrase is null', () => {
    const result = checkNetworkMatch(null, TESTNET)
    if (result.ok) throw new Error('expected failure')
    // Reason must not contain the contract passphrase raw value.
    expect(result.reason).not.toContain(TESTNET)
  })
})

// ── assertNetworkMatch ─────────────────────────────────────────────────────

describe('assertNetworkMatch', () => {
  it('does not throw when wallet and contract are on the same network', () => {
    expect(() => assertNetworkMatch(TESTNET, TESTNET)).not.toThrow()
  })

  it('throws NetworkMismatchError when wallet is on a different network', () => {
    expect(() => assertNetworkMatch(MAINNET, TESTNET)).toThrowError(NetworkMismatchError)
  })

  it('thrown error message contains the wallet network name', () => {
    let caught: unknown
    try {
      assertNetworkMatch(MAINNET, TESTNET)
    } catch (err) {
      caught = err
    }
    expect(caught).toBeInstanceOf(NetworkMismatchError)
    expect((caught as NetworkMismatchError).message).toContain('Mainnet')
  })

  it('thrown error includes a remediation string', () => {
    let caught: unknown
    try {
      assertNetworkMatch(MAINNET, TESTNET)
    } catch (err) {
      caught = err
    }
    const err = caught as NetworkMismatchError
    expect(err.remediation).toBeTruthy()
    expect(err.remediation).toMatch(/switch|open freighter/i)
  })

  it('throws when wallet passphrase is null', () => {
    expect(() => assertNetworkMatch(null, TESTNET)).toThrowError(NetworkMismatchError)
  })

  it('throws when wallet passphrase is undefined', () => {
    expect(() => assertNetworkMatch(undefined, TESTNET)).toThrowError(NetworkMismatchError)
  })

  it('throws when wallet passphrase is only whitespace', () => {
    expect(() => assertNetworkMatch('   ', TESTNET)).toThrowError(NetworkMismatchError)
  })

  it('error name is "NetworkMismatchError"', () => {
    let caught: unknown
    try {
      assertNetworkMatch(MAINNET, TESTNET)
    } catch (err) {
      caught = err
    }
    expect((caught as Error).name).toBe('NetworkMismatchError')
  })
})
