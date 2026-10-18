import { readFile } from 'node:fs/promises'
import { Noir } from '@noir-lang/noir_js'
import { UltraHonkBackend } from '@aztec/bb.js'

const helper = JSON.parse(
  await readFile(new URL('../public/noir/silent_witness_helper.json', import.meta.url), 'utf8'),
)
const main = JSON.parse(
  await readFile(new URL('../public/noir/silent_witness.json', import.meta.url), 'utf8'),
)

const videoHash = '1111111111111111111111111111111122222222222222222222222222222222'
const baseInputs = {
  credential_secret: '123456789',
  nullifier_secret: '987654321',
  video_hash_hi: BigInt(`0x${videoHash.slice(0, 32)}`).toString(10),
  video_hash_lo: BigInt(`0x${videoHash.slice(32)}`).toString(10),
}

const helperResult = await new Noir(helper).execute(baseInputs)
const [credentialRoot, nullifier] = helperResult.returnValue
const mainInputs = {
  ...baseInputs,
  credential_root: credentialRoot,
  nullifier,
}

const { witness } = await new Noir(main).execute(mainInputs)
const backend = new UltraHonkBackend(main.bytecode)
try {
  const proofData = await backend.generateProof(witness, { keccak: true })
  const verified = await backend.verifyProof(proofData, { keccak: true })
  if (proofData.publicInputs.length !== 4 || !verified) {
    throw new Error('Published browser artifact proof did not verify as a four-field statement')
  }

  console.log(
    JSON.stringify(
      {
        proofBytes: proofData.proof.length,
        publicInputBytes: proofData.publicInputs.length * 32,
        verified,
      },
      null,
      2,
    ),
  )
} finally {
  await backend.destroy()
}
