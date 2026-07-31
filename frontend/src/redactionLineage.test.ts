import { describe, expect, it } from 'vitest'

import { createTransformationManifest } from './lineageManifest'
import { redactionReplayBinding } from './redactionLineage'

const manifest = createTransformationManifest({
  parentProofIds: ['a'.repeat(64)],
  operationType: 'redact',
  parametersDigest: 'c'.repeat(64),
  toolIdentity: 'harpocrates-studio',
  toolVersion: '1.2.3',
  outputDigest: 'd'.repeat(64),
  network: 'testnet',
  actorAddress: 'GABC123',
})

describe('redaction replay binding', () => {
  it('is deterministic and changes with the claim', async () => {
    const first = await redactionReplayBinding(manifest)
    const second = await redactionReplayBinding(manifest)
    const changed = await redactionReplayBinding({ ...manifest, outputDigest: 'e'.repeat(64) })
    expect(first).toBe(second)
    expect(first).not.toBe(changed)
  })
})
