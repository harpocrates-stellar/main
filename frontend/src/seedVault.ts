const BN254_FIELD_MODULUS =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n

function hex(buffer: ArrayBuffer) {
  return [...new Uint8Array(buffer)]
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('')
}

async function sha256(input: ArrayBuffer | string) {
  const bytes = typeof input === 'string' ? new TextEncoder().encode(input) : input
  return hex(await crypto.subtle.digest('SHA-256', bytes))
}

export async function fieldSecret(label: string, seed: string) {
  const digest = await sha256(`harpocrates:${label}:${seed}`)
  const value = BigInt(`0x${digest}`) % BN254_FIELD_MODULUS
  return value === 0n ? '1' : value.toString(10)
}

export type SeedPair = {
  credentialSeed: string
  nullifierSeed: string
}

export function deriveSeeds(raw: SeedPair): SeedPair {
  return {
    credentialSeed: raw.credentialSeed.trim(),
    nullifierSeed: raw.nullifierSeed.trim(),
  }
}

export function hasSeeds(raw: SeedPair): boolean {
  return raw.credentialSeed.trim().length > 0 && raw.nullifierSeed.trim().length > 0
}

export function createClearSeeds(setter: (value: string) => void): () => void {
  return () => {
    setter('')
  }
}
