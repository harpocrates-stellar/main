import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { TransactionStateMachine } from '../transactionStateMachine'

describe('TransactionStateMachine', () => {
  beforeEach(() => {
    localStorage.clear()
    vi.useFakeTimers()
  })

  afterEach(() => {
    vi.useRealTimers()
  })

  it('starts in idle state', () => {
    const machine = new TransactionStateMachine()
    expect(machine.getState().status).toBe('idle')
  })

  it('transitions to submitting on SUBMIT event', () => {
    const machine = new TransactionStateMachine()
    machine.send({ type: 'SUBMIT' })
    expect(machine.getState().status).toBe('submitting')
  })

  it('transitions to awaiting_confirmation and persists when TX_HASH_RECEIVED', () => {
    const machine = new TransactionStateMachine()
    machine.send({ type: 'SUBMIT' })
    machine.send({ type: 'TX_HASH_RECEIVED', hash: 'abc' })
    
    expect(machine.getState().status).toBe('awaiting_confirmation')
    expect(machine.getState().hash).toBe('abc')
    
    // Check persistence
    const stored = localStorage.getItem('harpocrates_pending_tx')
    expect(stored).toBeTruthy()
    expect(JSON.parse(stored!).hash).toBe('abc')
  })

  it('recovers from localStorage if awaiting_confirmation', () => {
    localStorage.setItem(
      'harpocrates_pending_tx',
      JSON.stringify({ status: 'awaiting_confirmation', hash: 'def', error: null, updatedAt: Date.now() })
    )
    
    const machine = new TransactionStateMachine()
    expect(machine.getState().status).toBe('awaiting_confirmation')
    expect(machine.getState().hash).toBe('def')
  })

  it('clears localStorage when confirmed or failed', () => {
    const machine = new TransactionStateMachine()
    machine.send({ type: 'SUBMIT' })
    machine.send({ type: 'TX_HASH_RECEIVED', hash: 'abc' })
    expect(localStorage.getItem('harpocrates_pending_tx')).toBeTruthy()

    machine.send({ type: 'CONFIRMED' })
    expect(machine.getState().status).toBe('confirmed')
    expect(localStorage.getItem('harpocrates_pending_tx')).toBeNull()
  })
  
  it('times out old transactions when recovering', () => {
    localStorage.setItem(
      'harpocrates_pending_tx',
      JSON.stringify({ status: 'awaiting_confirmation', hash: 'def', error: null, updatedAt: Date.now() - 2 * 60 * 60 * 1000 })
    )
    
    const machine = new TransactionStateMachine()
    expect(machine.getState().status).toBe('idle') // It fell back to initial state because the old one timed out
    // and storage should be cleared by the persist logic since it timed out
    expect(localStorage.getItem('harpocrates_pending_tx')).toBeNull()
  })

  describe('dispute transaction flows', () => {
    it('handles open dispute happy path: idle -> submitting -> awaiting_confirmation -> confirmed', () => {
      const machine = new TransactionStateMachine()
      expect(machine.getState().status).toBe('idle')

      // 1. Submit open dispute
      machine.send({ type: 'SUBMIT' })
      expect(machine.getState().status).toBe('submitting')

      // 2. Tx hash received from Stellar RPC
      const disputeTxHash = '11'.repeat(32)
      machine.send({ type: 'TX_HASH_RECEIVED', hash: disputeTxHash })
      expect(machine.getState().status).toBe('awaiting_confirmation')
      expect(machine.getState().hash).toBe(disputeTxHash)

      // 3. Dispute confirmed on-chain
      machine.send({ type: 'CONFIRMED' })
      expect(machine.getState().status).toBe('confirmed')
      expect(localStorage.getItem('harpocrates_pending_tx')).toBeNull()
    })

    it('handles open dispute failure (cooldown or contract rejection)', () => {
      const machine = new TransactionStateMachine()
      machine.send({ type: 'SUBMIT' })
      expect(machine.getState().status).toBe('submitting')

      machine.send({
        type: 'FAILED',
        error: 'HostError: Error(Contract, #66)',
      })
      expect(machine.getState().status).toBe('failed')
      expect(machine.getState().error).toBe('HostError: Error(Contract, #66)')

      // Can reset after failure
      machine.send({ type: 'RESET' })
      expect(machine.getState().status).toBe('idle')
      expect(machine.getState().error).toBeNull()
    })

    it('handles respond dispute flow with confirmation', () => {
      const machine = new TransactionStateMachine()
      machine.send({ type: 'SUBMIT' })
      const respondTxHash = '22'.repeat(32)
      machine.send({ type: 'TX_HASH_RECEIVED', hash: respondTxHash })
      expect(machine.getState().status).toBe('awaiting_confirmation')

      machine.send({ type: 'CONFIRMED' })
      expect(machine.getState().status).toBe('confirmed')
    })

    it('handles timeout during awaiting confirmation', () => {
      const machine = new TransactionStateMachine()
      machine.send({ type: 'SUBMIT' })
      machine.send({ type: 'TX_HASH_RECEIVED', hash: 'abc' })
      expect(machine.getState().status).toBe('awaiting_confirmation')

      machine.send({ type: 'TIMEOUT' })
      expect(machine.getState().status).toBe('timeout')

      machine.send({ type: 'RESET' })
      expect(machine.getState().status).toBe('idle')
    })
  })
})
