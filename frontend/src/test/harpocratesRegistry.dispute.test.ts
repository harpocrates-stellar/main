import { describe, expect, it, vi } from 'vitest'
import {
  DisputeReason,
  isValidDisputeReason,
  isValidEvidenceHash,
  validateDisputeReason,
  validateEvidenceHash,
  openDispute,
  respondDispute,
} from '../harpocratesRegistry'
import { TransactionStateMachine } from '../transactionStateMachine'

describe('harpocratesRegistry dispute validation & builders', () => {
  it('validates dispute reason codes (1 to 6)', () => {
    expect(isValidDisputeReason(1)).toBe(true)
    expect(isValidDisputeReason(6)).toBe(true)
    expect(isValidDisputeReason(0)).toBe(false)
    expect(isValidDisputeReason(7)).toBe(false)
    expect(isValidDisputeReason(1.5)).toBe(false)

    expect(validateDisputeReason(DisputeReason.ContentError)).toBe(DisputeReason.ContentError)
    expect(() => validateDisputeReason(99)).toThrow(/dispute reason must be an integer between 1 and 6/i)
  })

  it('validates 32-byte (64 hex characters) evidence hash format', () => {
    const valid = 'a1'.repeat(32)
    expect(isValidEvidenceHash(valid)).toBe(true)
    expect(validateEvidenceHash(valid)).toBe(valid.toLowerCase())

    expect(isValidEvidenceHash('not-a-hash')).toBe(false)
    expect(isValidEvidenceHash('a1'.repeat(31))).toBe(false) // 62 chars
    expect(isValidEvidenceHash('a1'.repeat(33))).toBe(false) // 66 chars
    expect(() => validateEvidenceHash('bad')).toThrow(/must be a 64-character/i)
  })

  it('rejects openDispute with invalid reason before RPC or wallet call', async () => {
    const machine = new TransactionStateMachine()
    await expect(
      openDispute(
        {
          contractId: 'C123',
          publicKey: 'G123',
          proofId: '11'.repeat(32),
          reason: 0,
          evidenceHash: '22'.repeat(32),
        },
        machine,
      ),
    ).rejects.toThrow(/dispute reason/i)

    expect(machine.getState().status).toBe('idle')
  })

  it('rejects openDispute with invalid evidence hash before RPC or wallet call', async () => {
    const machine = new TransactionStateMachine()
    await expect(
      openDispute(
        {
          contractId: 'C123',
          publicKey: 'G123',
          proofId: '11'.repeat(32),
          reason: 1,
          evidenceHash: 'short-hash',
        },
        machine,
      ),
    ).rejects.toThrow(/evidencehash must be a 64-character/i)

    expect(machine.getState().status).toBe('idle')
  })

  it('rejects respondDispute with invalid disputeId or commitment before RPC', async () => {
    const machine = new TransactionStateMachine()
    await expect(
      respondDispute(
        {
          contractId: 'C123',
          publicKey: 'G123',
          disputeId: 'short',
          responseCommitment: '22'.repeat(32),
        },
        machine,
      ),
    ).rejects.toThrow(/disputeid must be a 32-byte hex string/i)

    await expect(
      respondDispute(
        {
          contractId: 'C123',
          publicKey: 'G123',
          disputeId: '11'.repeat(32),
          responseCommitment: 'short',
        },
        machine,
      ),
    ).rejects.toThrow(/responsecommitment must be a 64-character/i)

    expect(machine.getState().status).toBe('idle')
  })
})
