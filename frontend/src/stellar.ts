import { requestAccess } from '@stellar/freighter-api'

export type {
  ChainProofRecord,
  IdentityTier,
  RegisterProofInput,
  RegisterProofResult,
  TxState,
} from './stellarTypes'
export { describeTxState } from './stellarTypes'
export { getProofByVideoHash, registerProofOnStellar } from './harpocratesRegistry'

export async function connectFreighter() {
  const result = await requestAccess()
  if (result.error) {
    throw new Error(result.error.message)
  }
  return result.address
}
