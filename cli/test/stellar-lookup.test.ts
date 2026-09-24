import { describe, it, expect } from 'vitest'
import { StrKey } from '@stellar/stellar-sdk'
import { checkContractMatch } from '../src/stellar-lookup.js'

const contractBytes = Uint8Array.from({ length: 32 }, (_, index) => index)
const contractId = StrKey.encodeContract(contractBytes)

describe('checkContractMatch', () => {
  it('matches the decoded Stellar contract ID bytes', () => {
    const envelope = Uint8Array.from([255, ...contractBytes, 255])
    expect(checkContractMatch(envelope, contractId)).toBe(true)
  })

  it('rejects a different contract, malformed ID and empty envelope', () => {
    expect(checkContractMatch(new Uint8Array(32), contractId)).toBe(false)
    expect(checkContractMatch(contractBytes, '0x' + contractId)).toBe(false)
    expect(checkContractMatch(new Uint8Array(), contractId)).toBe(false)
  })
})
