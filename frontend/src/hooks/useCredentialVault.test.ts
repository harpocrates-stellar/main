import { act, renderHook } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { useCredentialVault } from './useCredentialVault'
import { CredentialVault, VAULT_STORAGE_KEY } from '../credentialVault'

describe('useCredentialVault hook', () => {
  beforeEach(() => {
    window.localStorage.clear()
    vi.useFakeTimers()
  })

  afterEach(() => {
    vi.restoreAllMocks()
    window.localStorage.clear()
  })

  it('starts in locked status', () => {
    const { result } = renderHook(() => useCredentialVault())
    expect(result.current.status).toBe('locked')
    expect(result.current.isLocked).toBe(true)
    expect(result.current.isStale).toBe(false)
    expect(result.current.seeds).toBeNull()
  })

  it('reflects unlocked state after setup', async () => {
    const { result } = renderHook(() => useCredentialVault())
    const seeds = { credentialSeed: 'cred1', nullifierSeed: 'null1' }

    await act(async () => {
      await result.current.setup('password123', seeds)
    })

    expect(result.current.status).toBe('unlocked')
    expect(result.current.isLocked).toBe(false)
    expect(result.current.isStale).toBe(false)
    expect(result.current.seeds).toEqual(seeds)
  }, 15000)

  it('transitions to stale when another tab updates storage', async () => {
    const { result } = renderHook(() => useCredentialVault())
    const seeds = { credentialSeed: 'cred1', nullifierSeed: 'null1' }

    await act(async () => {
      await result.current.setup('password123', seeds)
    })
    expect(result.current.status).toBe('unlocked')

    // Simulate cross-tab update
    const otherVault = new CredentialVault()
    await otherVault.setup('pass2', { credentialSeed: 'c2', nullifierSeed: 'n2' })
    otherVault.dispose()

    act(() => {
      window.dispatchEvent(
        new StorageEvent('storage', {
          key: VAULT_STORAGE_KEY,
          newValue: window.localStorage.getItem(VAULT_STORAGE_KEY),
          storageArea: window.localStorage,
        })
      )
    })

    expect(result.current.status).toBe('stale')
    expect(result.current.isStale).toBe(true)
    expect(result.current.isLocked).toBe(true)
    expect(result.current.seeds).toBeNull() // fail-closed
    expect(result.current.preservedWork?.seeds).toEqual(seeds)
  }, 15000)

  it('executes recovery action via hook', async () => {
    const { result } = renderHook(() => useCredentialVault())
    const seeds = { credentialSeed: 'cred1', nullifierSeed: 'null1' }

    await act(async () => {
      await result.current.setup('password123', seeds)
    })

    // Invalidate
    act(() => {
      window.localStorage.setItem(VAULT_STORAGE_KEY, 'new-envelope')
      window.dispatchEvent(
        new StorageEvent('storage', {
          key: VAULT_STORAGE_KEY,
          newValue: 'new-envelope',
          storageArea: window.localStorage,
        })
      )
    })

    expect(result.current.status).toBe('stale')

    // Discard recovery action
    await act(async () => {
      await result.current.recover('discard')
    })

    expect(result.current.status).toBe('locked')
    expect(result.current.isStale).toBe(false)
    expect(result.current.preservedWork).toBeNull()
  }, 15000)
})
