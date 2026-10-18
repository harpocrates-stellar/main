import { useEffect, useState } from 'react'
import type { ChainVerifierState } from '../stellarTypes'
import { getVerifierState } from '../stellar'
import { useWallet } from './useWallet'

const CONTRACT_ID = import.meta.env.VITE_HARPOCRATES_REGISTRY_ID ?? ''

export function useVerifierState() {
  const [verifierState, setVerifierState] = useState<ChainVerifierState | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<Error | null>(null)
  const { wallet } = useWallet()

  useEffect(() => {
    if (!CONTRACT_ID) {
      setLoading(false)
      return
    }

    let mounted = true
    setLoading(true)
    setError(null)

    getVerifierState(CONTRACT_ID, wallet || undefined)
      .then((state) => {
        if (mounted) {
          setVerifierState(state)
        }
      })
      .catch((err) => {
        if (mounted) {
          setError(err instanceof Error ? err : new Error(String(err)))
        }
      })
      .finally(() => {
        if (mounted) {
          setLoading(false)
        }
      })

    return () => {
      mounted = false
    }
  }, [wallet])

  return { verifierState, loading, error }
}
