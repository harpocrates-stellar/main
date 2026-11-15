import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { CredentialVault } from './credentialVault'
import { CrossTabVaultChangeBanner } from './components/CrossTabVaultChangeBanner'
import { expectNoA11yViolations, runAxe } from './test/axeA11y'

function dispatchCrossTabVaultEvent(oldValue: string | null, newValue: string | null, key: string | null = 'harpocrates:credential-vault') {
  if (key === null && newValue === null) {
    window.localStorage.clear()
  } else if (key !== null) {
    if (newValue === null) {
      window.localStorage.removeItem(key)
    } else {
      window.localStorage.setItem(key, newValue)
    }
  }

  window.dispatchEvent(
    new StorageEvent('storage', {
      key,
      oldValue,
      newValue,
      storageArea: window.localStorage,
    }),
  )
}

describe('Cross-tab vault change detection (#1149)', () => {
  const createdVaults: CredentialVault[] = []

  function createTrackedVault(): CredentialVault {
    const v = new CredentialVault()
    createdVaults.push(v)
    return v
  }

  beforeEach(() => {
    window.localStorage.clear()
  })

  afterEach(() => {
    for (const v of createdVaults.splice(0)) {
      v.dispose()
    }
    vi.restoreAllMocks()
    window.localStorage.clear()
  })

  it('invalidates an unlocked stale view when another tab updates the envelope while preserving active work', async () => {
    const tabAVault = createTrackedVault()
    await tabAVault.setup('TabAPass#2026!', {
      credentialSeed: 'tab-a-cred-seed',
      nullifierSeed: 'tab-a-null-seed',
    })
    const heldSeedRef = tabAVault.getSeeds()!
    expect(heldSeedRef.credentialSeed).toBe('tab-a-cred-seed')

    tabAVault.setActiveWork({
      selectedTier: 'silent',
      statementDigest: '0x1234abcd',
      draftTitle: 'field-report-alpha',
    })

    const oldRaw = window.localStorage.getItem('harpocrates:credential-vault')!

    // Simulate Tab B replacing the vault with new seeds and passphrase
    const tabBVault = createTrackedVault()
    await tabBVault.setup('TabBPass#2026!', {
      credentialSeed: 'tab-b-cred-seed',
      nullifierSeed: 'tab-b-null-seed',
    })
    const newRaw = window.localStorage.getItem('harpocrates:credential-vault')!

    dispatchCrossTabVaultEvent(oldRaw, newRaw)

    // Unlocked view in Tab A is immediately invalidated and zeroed
    expect(tabAVault.isLocked()).toBe(true)
    expect(tabAVault.getSeeds()).toBeNull()
    expect(heldSeedRef.credentialSeed).toBe('')
    expect(heldSeedRef.nullifierSeed).toBe('')

    // Active work remains preserved until user picks an explicit recovery action
    const state = tabAVault.getExternalChangeState()
    expect(state.stale).toBe(true)
    expect(state.recoveryRequired).toBe(true)
    expect(state.kind).toBe('updated')
    expect(state.activeWorkPreserved).toBe(true)
    expect(tabAVault.getActiveWork()).toEqual({
      selectedTier: 'silent',
      statementDigest: '0x1234abcd',
      draftTitle: 'field-report-alpha',
    })

    // Direct unlock without choosing a recovery action is rejected
    await expect(tabAVault.unlock('TabBPass#2026!')).rejects.toThrow(
      'Vault envelope changed in another tab: choose an explicit recovery action before unlocking',
    )

    // Wrong recovery passphrase keeps recovery pending and preserves active work
    const failedRecovery = await tabAVault.resolveExternalChange({
      type: 'reunlock-updated-vault',
      password: 'WrongPassword!',
    })
    expect(failedRecovery.resolved).toBe(false)
    expect(failedRecovery.unlocked).toBe(false)
    expect(tabAVault.getExternalChangeState().stale).toBe(true)
    expect(tabAVault.getActiveWork()?.draftTitle).toBe('field-report-alpha')

    // Valid recovery unlocks Tab B's updated credentials while keeping active work
    const recovered = await tabAVault.resolveExternalChange({
      type: 'reunlock-updated-vault',
      password: 'TabBPass#2026!',
    })
    expect(recovered.resolved).toBe(true)
    expect(recovered.unlocked).toBe(true)
    expect(tabAVault.isLocked()).toBe(false)
    expect(tabAVault.getSeeds()).toEqual({
      credentialSeed: 'tab-b-cred-seed',
      nullifierSeed: 'tab-b-null-seed',
    })
    expect(recovered.activeWork).toEqual({
      selectedTier: 'silent',
      statementDigest: '0x1234abcd',
      draftTitle: 'field-report-alpha',
    })
  })

  it('handles external vault deletion and supports both keeping or discarding active work', async () => {
    const tabAVault = createTrackedVault()
    await tabAVault.setup('TabAPass#1', {
      credentialSeed: 'seed-1',
      nullifierSeed: 'seed-2',
    })
    tabAVault.setActiveWork({
      selectedTier: 'source',
      pendingStep: 2,
    })

    const oldRaw = window.localStorage.getItem('harpocrates:credential-vault')
    dispatchCrossTabVaultEvent(oldRaw, null, null) // Simulate localStorage.clear() in another tab

    expect(tabAVault.isLocked()).toBe(true)
    expect(tabAVault.getExternalChangeState().kind).toBe('removed')
    expect(tabAVault.getActiveWork()).toEqual({
      selectedTier: 'source',
      pendingStep: 2,
    })

    const discarded = await tabAVault.resolveExternalChange({
      type: 'discard-active-work',
    })
    expect(discarded.resolved).toBe(true)
    expect(discarded.activeWork).toBeNull()
    expect(tabAVault.getExternalChangeState().stale).toBe(false)
  })

  it('does not invalidate unlocked state on unrelated storage keys or identical values and blocks private fields in activeWork', async () => {
    const vault = createTrackedVault()
    await vault.setup('Pass#123', {
      credentialSeed: 'secret-cred',
      nullifierSeed: 'secret-null',
    })
    const raw = window.localStorage.getItem('harpocrates:credential-vault')!

    // Unrelated key
    window.dispatchEvent(
      new StorageEvent('storage', {
        key: 'harpocrates:ui-preferences',
        oldValue: null,
        newValue: '{"currentView":"verify"}',
        storageArea: window.localStorage,
      }),
    )
    // Identical raw envelope value
    dispatchCrossTabVaultEvent(raw, raw)

    expect(vault.isLocked()).toBe(false)
    expect(vault.getExternalChangeState().stale).toBe(false)

    expect(() =>
      vault.setActiveWork({ credentialSeed: 'must-never-store' }),
    ).toThrow('Private vault field "credentialSeed" cannot be stored in active work state')
  })

  it('renders an accessible recovery banner (WCAG 2.2 AA) and completes user-chosen recovery', async () => {
    const tabAVault = createTrackedVault()
    await tabAVault.setup('InitialPass#1', {
      credentialSeed: 'initial-cred',
      nullifierSeed: 'initial-null',
    })
    tabAVault.setActiveWork({ draftName: 'witness-bundle-07' })
    const oldRaw = window.localStorage.getItem('harpocrates:credential-vault')!

    const tabBVault = createTrackedVault()
    await tabBVault.setup('UpdatedPass#2', {
      credentialSeed: 'updated-cred',
      nullifierSeed: 'updated-null',
    })
    const newRaw = window.localStorage.getItem('harpocrates:credential-vault')!

    const { container } = render(<CrossTabVaultChangeBanner vault={tabAVault} />)
    expect(screen.queryByRole('alert')).toBeNull()

    dispatchCrossTabVaultEvent(oldRaw, newRaw)

    const banner = await screen.findByRole('alert')
    expect(banner.textContent).toContain('Credential vault was updated in another tab')
    expect(banner.textContent).toContain('Your unsaved non-secret work is preserved')

    expectNoA11yViolations(await runAxe(container), 'cross-tab vault change banner')

    fireEvent.change(screen.getByLabelText('Updated vault passphrase'), {
      target: { value: 'UpdatedPass#2' },
    })
    fireEvent.click(screen.getByRole('button', { name: 'Unlock updated vault and keep work' }))

    await waitFor(() => {
      expect(screen.queryByRole('alert')).toBeNull()
    })
    expect(tabAVault.isLocked()).toBe(false)
    expect(tabAVault.getSeeds()?.credentialSeed).toBe('updated-cred')
    expect(tabAVault.getActiveWork()).toEqual({ draftName: 'witness-bundle-07' })
  })
})
