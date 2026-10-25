import { describe, expect, it } from 'vitest'
import { Networks } from '@stellar/stellar-sdk'
import { DEFAULT_NETWORK_PASSPHRASE, resolveNetwork } from '../src/network.js'

describe('resolveNetwork', () => {
  it.each([
    ['testnet', Networks.TESTNET],
    ['mainnet', Networks.PUBLIC],
    ['public', Networks.PUBLIC],
    ['futurenet', Networks.FUTURENET],
  ])('maps %s to its SDK passphrase', (alias, passphrase) => {
    expect(resolveNetwork(alias)).toBe(passphrase)
  })

  it.each(['TESTNET', 'Testnet', 'MainNet', 'PUBLIC', 'FutureNet', '  testnet  '])(
    'matches %j case-insensitively',
    (alias) => {
      expect(Object.values(Networks)).toContain(resolveNetwork(alias))
    },
  )

  it.each([
    Networks.TESTNET,
    Networks.PUBLIC,
    Networks.FUTURENET,
    'Standalone Network ; February 2017',
    'My Custom Network ; 2026',
    'devnet',
  ])('passes %j through unchanged', (value) => {
    expect(resolveNetwork(value)).toBe(value)
  })

  it('defaults to testnet', () => {
    expect(DEFAULT_NETWORK_PASSPHRASE).toBe(Networks.TESTNET)
  })
})
