import { Barretenberg, Fr, UltraHonkBackend } from '@aztec/bb.js'
import { Noir } from '@noir-lang/noir_js'
import type { CompiledCircuit } from '@noir-lang/types'
import type {
  IntervalClause,
  Predicate,
  PredicateType,
  SelectiveDisclosureInput,
  SelectiveDisclosureProof,
} from './types/schema'
import { SCHEMA_CONSTANTS } from './types/schema'
import { encodePublicInputs } from './verifierInputs'

const U64_MAX = 0xffffffffffffffffn
const TWO_POW_64 = 1n << 64n
const TWO_POW_128 = 1n << 128n

export type CanonicalIntervalConjunction = {
  lower: bigint
  upper: bigint
  lowerInclusive: boolean
  upperInclusive: boolean
  canonicalFlags: bigint
  packedPublicValue: bigint
  isEmpty: boolean
  minValid: bigint | null
  maxValid: bigint | null
}

export type WitnessPredicate = {
  predicate_type: string
  attr_index: string
  public_value: string
  set_values: string[]
  set_len: string
  lower_bound: string
  upper_bound: string
}

let circuitPromise: Promise<CompiledCircuit> | null = null
let bbPromise: Promise<Barretenberg> | null = null

async function getBB(): Promise<Barretenberg> {
  bbPromise ??= Barretenberg.new()
  return bbPromise
}

async function pedersenHash(inputs: bigint[]): Promise<bigint> {
  const bb = await getBB()
  const result = await bb.pedersenHash(inputs.map((input) => new Fr(input)), 0)
  return BigInt(result.toString())
}

function parseU64Bound(raw: string, label: string): bigint {
  const trimmed = raw.trim()
  if (!/^(0x[0-9a-fA-F]+|\d+)$/.test(trimmed)) {
    throw new Error(`Invalid u64 interval bound in ${label}`)
  }
  const value = BigInt(trimmed)
  if (value < 0n || value > U64_MAX) {
    throw new Error(`Interval bound out of u64 range in ${label}`)
  }
  return value
}

export function packCanonicalIntervalConjunction(
  lower: bigint,
  upper: bigint,
  lowerInclusive: boolean,
  upperInclusive: boolean,
): bigint {
  if (lower < 0n || lower > U64_MAX || upper < 0n || upper > U64_MAX) {
    throw new Error('Canonical interval bounds must fit in u64')
  }
  const canonicalFlags = (lowerInclusive ? 1n : 0n) + (upperInclusive ? 2n : 0n)
  return lower + upper * TWO_POW_64 + canonicalFlags * TWO_POW_128
}

export function reduceIntervalIntersection(
  clauses: IntervalClause[],
): CanonicalIntervalConjunction {
  if (clauses.length < 1) {
    throw new Error('IntervalIntersection predicate requires at least 1 clause')
  }
  if (clauses.length > SCHEMA_CONSTANTS.MAX_INTERVAL_CLAUSES) {
    throw new Error(
      `IntervalIntersection predicate supports at most ${SCHEMA_CONSTANTS.MAX_INTERVAL_CLAUSES} clauses`,
    )
  }

  let effLo = parseU64Bound(clauses[0].lower, 'clauses[0].lower')
  let effIncLo = clauses[0].lowerInclusive ?? true
  let effHi = parseU64Bound(clauses[0].upper, 'clauses[0].upper')
  let effIncHi = clauses[0].upperInclusive ?? true

  for (let j = 1; j < clauses.length; j += 1) {
    const cLo = parseU64Bound(clauses[j].lower, `clauses[${j}].lower`)
    const cIncLo = clauses[j].lowerInclusive ?? true
    const cHi = parseU64Bound(clauses[j].upper, `clauses[${j}].upper`)
    const cIncHi = clauses[j].upperInclusive ?? true

    if (cLo > effLo) {
      effLo = cLo
      effIncLo = cIncLo
    } else if (cLo === effLo) {
      effIncLo = effIncLo && cIncLo
    }

    if (cHi < effHi) {
      effHi = cHi
      effIncHi = cIncHi
    } else if (cHi === effHi) {
      effIncHi = effIncHi && cIncHi
    }
  }

  const canonicalFlags = (effIncLo ? 1n : 0n) + (effIncHi ? 2n : 0n)
  const packedPublicValue = packCanonicalIntervalConjunction(effLo, effHi, effIncLo, effIncHi)

  const loOverflow = !effIncLo && effLo === U64_MAX
  const hiUnderflow = !effIncHi && effHi === 0n
  const minCandidate = effIncLo ? effLo : effLo < U64_MAX ? effLo + 1n : effLo
  const maxCandidate = effIncHi ? effHi : effHi > 0n ? effHi - 1n : 0n
  const nonEmpty = !loOverflow && !hiUnderflow && minCandidate <= maxCandidate

  return {
    lower: effLo,
    upper: effHi,
    lowerInclusive: effIncLo,
    upperInclusive: effIncHi,
    canonicalFlags,
    packedPublicValue,
    isEmpty: !nonEmpty,
    minValid: nonEmpty ? minCandidate : null,
    maxValid: nonEmpty ? maxCandidate : null,
  }
}

function predicateTypeCode(predicateType: PredicateType): bigint {
  switch (predicateType) {
    case 'Equality':
      return 0n
    case 'SetMembership':
      return 1n
    case 'Range':
      return 2n
    case 'IntervalIntersection':
      return 3n
  }
}

export function encodeWitnessPredicate(p: Predicate): WitnessPredicate {
  if (p.predicateType === 'IntervalIntersection') {
    const clauses = p.intervals ?? []
    const conjunction = reduceIntervalIntersection(clauses)
    if (conjunction.isEmpty) {
      throw new Error('IntervalIntersection predicate has an empty u64 intersection')
    }
    const setValues = Array<string>(SCHEMA_CONSTANTS.MAX_SET_MEMBERS).fill('0')
    let clauseMask = 0
    for (let j = 0; j < clauses.length; j += 1) {
      const lo = parseU64Bound(clauses[j].lower, `clauses[${j}].lower`)
      const hi = parseU64Bound(clauses[j].upper, `clauses[${j}].upper`)
      const loInc = clauses[j].lowerInclusive ?? true
      const hiInc = clauses[j].upperInclusive ?? true
      setValues[2 * j] = lo.toString(10)
      setValues[2 * j + 1] = hi.toString(10)
      if (loInc) {
        clauseMask |= 1 << (2 * j)
      }
      if (hiInc) {
        clauseMask |= 1 << (2 * j + 1)
      }
    }
    const packedSetLen = clauses.length | (clauseMask << 8)
    return {
      predicate_type: '3',
      attr_index: p.attrIndex.toString(),
      public_value: conjunction.packedPublicValue.toString(10),
      set_values: setValues,
      set_len: packedSetLen.toString(),
      lower_bound: conjunction.lower.toString(10),
      upper_bound: conjunction.upper.toString(10),
    }
  }

  return {
    predicate_type: predicateTypeCode(p.predicateType).toString(10),
    attr_index: p.attrIndex.toString(),
    public_value: toBigInt(p.publicValue ?? '0').toString(10),
    set_values: padArray(p.setValues ?? [], SCHEMA_CONSTANTS.MAX_SET_MEMBERS, '0').map((v) =>
      toBigInt(v).toString(10),
    ),
    set_len: (p.setLen ?? 0).toString(),
    lower_bound: toBigInt(p.lowerBound ?? '0').toString(10),
    upper_bound: toBigInt(p.upperBound ?? '0').toString(10),
  }
}

function padPredicates(predicates: Predicate[]): Predicate[] {
  const padded = [...predicates]
  while (padded.length < SCHEMA_CONSTANTS.MAX_PREDICATES) {
    padded.push({
      predicateType: 'Equality',
      attrIndex: 0,
      publicValue: '0',
      setValues: Array(SCHEMA_CONSTANTS.MAX_SET_MEMBERS).fill('0'),
      setLen: 0,
      lowerBound: '0',
      upperBound: '0',
    })
  }
  return padded
}

function padArray<T>(arr: T[], len: number, fill: T): T[] {
  const padded = [...arr]
  while (padded.length < len) {
    padded.push(fill)
  }
  return padded
}

async function computePredicateCommitment(predicates: Predicate[]): Promise<string> {
  // The circuit hashes exactly num_predicates entries and skips the padding
  // predicates, so the commitment must only fold real predicates.
  let current = BigInt(0)
  for (const p of predicates) {
    const predType = predicateTypeCode(p.predicateType)
    const attrIndex = BigInt(p.attrIndex ?? 0)
    let publicValue: bigint
    if (p.predicateType === 'IntervalIntersection') {
      const conjunction = reduceIntervalIntersection(p.intervals ?? [])
      if (conjunction.isEmpty) {
        throw new Error('IntervalIntersection predicate has an empty u64 intersection')
      }
      publicValue = conjunction.packedPublicValue
    } else {
      publicValue = BigInt(p.publicValue ?? '0')
    }
    current = await pedersenHash([current, predType, attrIndex, publicValue])
  }
  return current.toString()
}

function toBigInt(value: string): bigint {
  const hex = value.startsWith('0x') ? value : '0x' + value
  return BigInt(hex)
}

export async function computeNullifier(
  credentialRoot: string,
  videoHashHi: string,
  videoHashLo: string,
  evidenceDigest: string,
): Promise<string> {
  const result = await pedersenHash([
    toBigInt(credentialRoot),
    toBigInt(videoHashHi),
    toBigInt(videoHashLo),
    toBigInt(evidenceDigest),
  ])
  return result.toString()
}

export async function generateSelectiveDisclosureProof(
  input: SelectiveDisclosureInput,
): Promise<SelectiveDisclosureProof> {
  const circuit = await loadCircuit()

  const paddedAttrs = padArray(input.attrValues, SCHEMA_CONSTANTS.MAX_ATTRIBUTES, '0')
  const paddedBlindings = padArray(input.attrBlindings, SCHEMA_CONSTANTS.MAX_ATTRIBUTES, '0')
  const paddedPredicates = padPredicates(input.predicates)

  const witnessInputs = {
    schema_hash: toBigInt(input.schemaHash).toString(10),
    issuer_namespace: toBigInt(input.issuerNamespace).toString(10),
    schema_version: input.schemaVersion.toString(),
    credential_root: toBigInt(input.credentialRoot).toString(10),
    nullifier: toBigInt(input.nullifier).toString(10),
    video_hash_hi: toBigInt(input.videoHashHi).toString(10),
    video_hash_lo: toBigInt(input.videoHashLo).toString(10),
    verifier_digest: toBigInt(input.verifierDigest).toString(10),
    circuit_version: input.circuitVersion.toString(),
    evidence_digest: toBigInt(input.evidenceDigest).toString(10),
    predicate_commitment: toBigInt(await computePredicateCommitment(input.predicates)).toString(10),
    num_attributes: input.numAttributes.toString(),
    attr_values: paddedAttrs.map((v) => toBigInt(v).toString(10)),
    attr_blindings: paddedBlindings.map((v) => toBigInt(v).toString(10)),
    num_predicates: input.numPredicates.toString(),
    predicates: paddedPredicates.map((p) => encodeWitnessPredicate(p)),
  }

  const { witness } = await new Noir(circuit).execute(witnessInputs)

  const backend = new UltraHonkBackend(circuit.bytecode)
  try {
    const proofData = await backend.generateProof(witness, { keccak: true })
    const proofHex = bytesToHex(proofData.proof)
    const publicInputHex = encodePublicInputs(proofData.publicInputs)

    return {
      proof: proofHex,
      publicInputs: publicInputHex,
    }
  } finally {
    await backend.destroy()
  }
}

async function loadCircuit() {
  circuitPromise ??= fetchCircuit('/noir/selective_disclosure.json')
  return circuitPromise
}

async function fetchCircuit(path: string) {
  const response = await fetch(path)
  if (!response.ok) {
    throw new Error(`Unable to load Noir circuit artifact: ${path}`)
  }
  return (await response.json()) as CompiledCircuit
}

function bytesToHex(bytes: Uint8Array) {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('')
}
