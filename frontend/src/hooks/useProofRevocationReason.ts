import { useEffect, useState } from 'react'
import { getProofHistoryAt, getProofHistoryCount } from '../stellar'

const REGISTRY_CONTRACT_ID = import.meta.env.VITE_HARPOCRATES_REGISTRY_ID ?? ''
const REVOCATION_ACTION = 3

type SettledReason = {
  key: string
  reasonCode: number | null
}

const EMPTY_REASON: SettledReason = { key: '', reasonCode: null }

type Options = {
  proofId: string | null | undefined
  revoked: boolean
  sourceAddress?: string
  contractId?: string
}

export function useProofRevocationReason({
  proofId,
  revoked,
  sourceAddress,
  contractId = REGISTRY_CONTRACT_ID,
}: Options): string | null {
  const [settled, setSettled] = useState(EMPTY_REASON)
  const lookupKey = revoked && proofId && contractId
    ? `${contractId}|${proofId}|${sourceAddress ?? ''}`
    : ''

  useEffect(() => {
    if (!lookupKey || !proofId) return

    let cancelled = false
    void (async () => {
      let reasonCode: number | null = null
      try {
        const count = await getProofHistoryCount(contractId, proofId, sourceAddress)
        if (Number.isSafeInteger(count) && count > 0) {
          const latest = await getProofHistoryAt(contractId, proofId, sourceAddress, count)
          if (
            latest?.action === REVOCATION_ACTION &&
            Number.isInteger(latest.reasonCode) &&
            latest.reasonCode >= 0 &&
            latest.reasonCode <= 255
          ) {
            reasonCode = latest.reasonCode
          }
        }
      } catch {
        // RPC details are deliberately not surfaced to the UI.
      }

      if (!cancelled) setSettled({ key: lookupKey, reasonCode })
    })()

    return () => {
      cancelled = true
    }
  }, [lookupKey, proofId, contractId, sourceAddress])

  if (!revoked) return null
  if (!proofId || !contractId) return 'Revocation reason unavailable.'
  if (settled.key !== lookupKey) return 'Loading revocation reason…'
  if (settled.reasonCode === null) return 'Revocation reason unavailable.'
  return `Reason code ${settled.reasonCode}. The registry publishes no narrative reason.`
}