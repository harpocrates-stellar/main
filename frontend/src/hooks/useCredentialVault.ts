import { useCallback, useEffect, useState } from 'react'
import {
  CredentialVault,
  type PreservedActiveWork,
  type RecoveryAction,
  type RecoveryOptions,
  type StaleReason,
  type VaultStatus,
} from '../credentialVault'
import type { SeedPair } from '../seedVault'

export interface UseCredentialVaultReturn {
  vault: CredentialVault
  status: VaultStatus
  isLocked: boolean
  isStale: boolean
  staleReason: StaleReason | null
  preservedWork: PreservedActiveWork | null
  seeds: SeedPair | null
  setup: (password: string, seeds: SeedPair) => Promise<void>
  unlock: (password: string) => Promise<boolean>
  lock: () => void
  recover: (action: RecoveryAction, options?: RecoveryOptions) => Promise<boolean>
  setActiveWork: (data: unknown) => void
}

export function useCredentialVault(inactivityTimeoutMs?: number): UseCredentialVaultReturn {
  const [vault] = useState(() => new CredentialVault(inactivityTimeoutMs))

  const [status, setStatus] = useState<VaultStatus>(() => vault.getStatus())
  const [staleReason, setStaleReason] = useState<StaleReason | null>(() => vault.getStaleReason())
  const [preservedWork, setPreservedWork] = useState<PreservedActiveWork | null>(() => vault.getPreservedWork())
  const [seeds, setSeeds] = useState<SeedPair | null>(() => vault.getSeeds())

  const syncState = useCallback(() => {
    setStatus(vault.getStatus())
    setStaleReason(vault.getStaleReason())
    setPreservedWork(vault.getPreservedWork())
    setSeeds(vault.getSeeds())
  }, [vault])

  useEffect(() => {
    const unsubscribe = vault.subscribe(() => {
      syncState()
    })
    return () => {
      unsubscribe()
      vault.dispose()
    }
  }, [vault, syncState])

  const setup = useCallback(async (password: string, newSeeds: SeedPair) => {
    await vault.setup(password, newSeeds)
    syncState()
  }, [vault, syncState])

  const unlock = useCallback(async (password: string) => {
    const result = await vault.unlock(password)
    syncState()
    return result
  }, [vault, syncState])

  const lock = useCallback(() => {
    vault.lock()
    syncState()
  }, [vault, syncState])

  const recover = useCallback(async (action: RecoveryAction, options?: RecoveryOptions) => {
    const result = await vault.handleRecoveryAction(action, options)
    syncState()
    return result
  }, [vault, syncState])

  const setActiveWork = useCallback((data: unknown) => {
    vault.setActiveWork(data)
  }, [vault])

  return {
    vault,
    status,
    isLocked: status !== 'unlocked',
    isStale: status === 'stale',
    staleReason,
    preservedWork,
    seeds,
    setup,
    unlock,
    lock,
    recover,
    setActiveWork,
  }
}
