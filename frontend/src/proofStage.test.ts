import { describe, expect, it } from 'vitest'
import {
  PROOF_STAGES,
  PROOF_STAGE_LABELS,
  PROOF_STAGE_SEQUENCE,
  isProofStage,
  proofStageIndex,
  proofStageLabel,
  proofStageStatus,
} from './proofStage'

describe('proofStage vocabulary', () => {
  it('exposes the canonical phases in execution order', () => {
    expect(PROOF_STAGE_SEQUENCE).toEqual([
      'loading_circuits',
      'executing_helper',
      'executing_main',
      'generating_proof',
    ])
    expect(PROOF_STAGE_SEQUENCE).toEqual([...PROOF_STAGES])
  })

  it('is frozen so consumers cannot mutate the shared sequence', () => {
    expect(Object.isFrozen(PROOF_STAGE_SEQUENCE)).toBe(true)
    expect(Object.isFrozen(PROOF_STAGE_LABELS)).toBe(true)
  })

  it('labels every phase with a non-empty, privacy-safe string', () => {
    for (const stage of PROOF_STAGE_SEQUENCE) {
      const label = proofStageLabel(stage)
      expect(label.length).toBeGreaterThan(0)
      // Phase labels must never leak hex hashes, addresses, or file paths.
      expect(label).not.toMatch(/[0-9a-f]{9,}/i)
      expect(label).not.toMatch(/[GC][A-Z2-7]{55}/)
    }
  })

  it('maps each phase to its sequence index', () => {
    expect(proofStageIndex('loading_circuits')).toBe(0)
    expect(proofStageIndex('generating_proof')).toBe(3)
  })

  it('rejects values outside the canonical union', () => {
    expect(isProofStage('loading_circuits')).toBe(true)
    expect(isProofStage('not_a_phase')).toBe(false)
    expect(isProofStage(undefined)).toBe(false)
    expect(isProofStage(42)).toBe(false)
  })
})

describe('proofStageStatus', () => {
  it('marks earlier phases complete, the current phase active, later pending', () => {
    expect(proofStageStatus('loading_circuits', 'executing_main')).toBe('complete')
    expect(proofStageStatus('executing_helper', 'executing_main')).toBe('complete')
    expect(proofStageStatus('executing_main', 'executing_main')).toBe('active')
    expect(proofStageStatus('generating_proof', 'executing_main')).toBe('pending')
  })

  it('leaves every phase pending when there is no active phase (boundary)', () => {
    for (const stage of PROOF_STAGE_SEQUENCE) {
      expect(proofStageStatus(stage, null)).toBe('pending')
    }
  })

  it('first and last phases behave at the boundaries', () => {
    expect(proofStageStatus('loading_circuits', 'loading_circuits')).toBe('active')
    expect(proofStageStatus('loading_circuits', 'generating_proof')).toBe('complete')
    expect(proofStageStatus('generating_proof', 'generating_proof')).toBe('active')
    expect(proofStageStatus('generating_proof', 'loading_circuits')).toBe('pending')
  })
})
