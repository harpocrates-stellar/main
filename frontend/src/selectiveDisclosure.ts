import { Barretenberg, Fr, UltraHonkBackend } from '@aztec/bb.js'
import { Noir } from '@noir-lang/noir_js'
import type { CompiledCircuit } from '@noir-lang/types'
import type {
  Predicate,
  PredicateType,
  SelectiveDisclosureInput,
  SelectiveDisclosureProof,
} from './types/schema'
import { SCHEMA_CONSTANTS } from './types/schema'
import { encodePublicInputs } from './verifierInputs'

const BN254_SCALAR_MODULUS =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n

export const PREDICATE_TYPE_CODES: Readonly<Record<PredicateType, '0' | '1' | '2'>> = {
  Equality: '0',
  SetMembership: '1',
  Range: '2',
}

export class DisclosureWitnessError extends Error {
  readonly code: string
  readonly field: string

  constructor(code: string, field = 'predicates') {
    super(`${code}:${field}`)
    this.name = 'DisclosureWitnessError'
    this.code = code
    this.field = field
  }
}

export type PreparedNoirPredicate = {
  predicate_type: '0' | '1' | '2'
  attr_index: string
  public_value: string
  set_values: string[]
  set_len: string
  lower_bound: string
  upper_bound: string
}

export type PreparedSelectiveDisclosureWitness = {
  num_attributes: string
  attr_values: string[]
  attr_blindings: string[]
  num_predicates: string
  predicates: PreparedNoirPredicate[]
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

export function encodePredicateType(
  predicateType: PredicateType,
  field = 'predicateType',
): '0' | '1' | '2' {
  if (
    typeof predicateType === 'string' &&
    Object.prototype.hasOwnProperty.call(PREDICATE_TYPE_CODES, predicateType)
  ) {
    return PREDICATE_TYPE_CODES[predicateType]
  }
  throw new DisclosureWitnessError('unsupported_predicate_type', field)
}

function toBigInt(value: string, field = 'field'): bigint {
  if (typeof value !== 'string' || value.trim().length === 0) {
    throw new DisclosureWitnessError('malformed_field_element', field)
  }
  const trimmed = value.trim()
  const hex = trimmed.startsWith('0x') || trimmed.startsWith('0X') ? trimmed : '0x' + trimmed
  let parsed: bigint
  try {
    parsed = BigInt(hex)
  } catch {
    throw new DisclosureWitnessError('malformed_field_element', field)
  }
  if (parsed < 0n || parsed >= BN254_SCALAR_MODULUS) {
    throw new DisclosureWitnessError('field_element_out_of_range', field)
  }
  return parsed
}

function toCommitmentScalar(value: string, field: string): bigint {
  if (typeof value !== 'string' || value.trim().length === 0) {
    throw new DisclosureWitnessError('malformed_field_element', field)
  }
  const trimmed = value.trim()
  try {
    const scalar =
      trimmed.startsWith('0x') || trimmed.startsWith('0X') || /^[0-9]+$/.test(trimmed)
        ? BigInt(trimmed)
        : BigInt('0x' + trimmed)
    if (scalar < 0n || scalar >= BN254_SCALAR_MODULUS) {
      throw new DisclosureWitnessError('field_element_out_of_range', field)
    }
    return scalar
  } catch (err) {
    if (err instanceof DisclosureWitnessError) throw err
    throw new DisclosureWitnessError('malformed_field_element', field)
  }
}

export function padPredicates(predicates: Predicate[]): Predicate[] {
  if (!Array.isArray(predicates)) {
    throw new DisclosureWitnessError('malformed_predicates', 'predicates')
  }
  if (predicates.length > SCHEMA_CONSTANTS.MAX_PREDICATES) {
    throw new DisclosureWitnessError('predicates_oversize', 'predicates')
  }
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

function padArray<T>(arr: T[], len: number, fill: T, field: string): T[] {
  if (!Array.isArray(arr)) {
    throw new DisclosureWitnessError('malformed_array', field)
  }
  if (arr.length > len) {
    throw new DisclosureWitnessError('array_oversize', field)
  }
  const padded = [...arr]
  while (padded.length < len) {
    padded.push(fill)
  }
  return padded
}

/**
 * Validates selective-disclosure predicate, set-member, and attribute bounds
 * BEFORE allocating padded witness arrays, loading circuits, or invoking bb.js,
 * while preserving caller predicate order and canonical type codes (`0`, `1`, `2`).
 */
export function prepareSelectiveDisclosureWitness(
  input: Pick<
    SelectiveDisclosureInput,
    'numAttributes' | 'attrValues' | 'attrBlindings' | 'numPredicates' | 'predicates'
  >,
): PreparedSelectiveDisclosureWitness {
  if (!input || typeof input !== 'object') {
    throw new DisclosureWitnessError('malformed_input', 'input')
  }
  if (!Array.isArray(input.predicates)) {
    throw new DisclosureWitnessError('malformed_predicates', 'predicates')
  }
  if (input.predicates.length > SCHEMA_CONSTANTS.MAX_PREDICATES) {
    throw new DisclosureWitnessError('predicates_oversize', 'predicates')
  }
  if (!Number.isInteger(input.numPredicates)) {
    throw new DisclosureWitnessError('malformed_num_predicates', 'numPredicates')
  }
  if (input.numPredicates < 0) {
    throw new DisclosureWitnessError('predicates_undersize', 'numPredicates')
  }
  if (input.numPredicates > SCHEMA_CONSTANTS.MAX_PREDICATES) {
    throw new DisclosureWitnessError('predicates_oversize', 'numPredicates')
  }
  if (input.numPredicates !== input.predicates.length) {
    throw new DisclosureWitnessError('predicate_count_mismatch', 'numPredicates')
  }

  if (!Array.isArray(input.attrValues)) {
    throw new DisclosureWitnessError('malformed_attr_values', 'attrValues')
  }
  if (!Array.isArray(input.attrBlindings)) {
    throw new DisclosureWitnessError('malformed_attr_blindings', 'attrBlindings')
  }
  if (!Number.isInteger(input.numAttributes)) {
    throw new DisclosureWitnessError('malformed_num_attributes', 'numAttributes')
  }
  if (input.numAttributes < 1) {
    throw new DisclosureWitnessError('attributes_undersize', 'numAttributes')
  }
  if (
    input.numAttributes > SCHEMA_CONSTANTS.MAX_ATTRIBUTES ||
    input.attrValues.length > SCHEMA_CONSTANTS.MAX_ATTRIBUTES
  ) {
    throw new DisclosureWitnessError('attributes_oversize', 'attrValues')
  }
  if (input.attrBlindings.length > SCHEMA_CONSTANTS.MAX_ATTRIBUTES) {
    throw new DisclosureWitnessError('attributes_oversize', 'attrBlindings')
  }
  if (input.attrValues.length < input.numAttributes) {
    throw new DisclosureWitnessError('attribute_count_mismatch', 'attrValues')
  }
  if (
    input.attrBlindings.length < input.numAttributes ||
    input.attrBlindings.length !== input.attrValues.length
  ) {
    throw new DisclosureWitnessError('attribute_count_mismatch', 'attrBlindings')
  }

  // Validate active predicates in caller order BEFORE allocating padded arrays.
  const activePredicates: PreparedNoirPredicate[] = []
  for (let i = 0; i < input.predicates.length; i++) {
    const p = input.predicates[i]
    const prefix = `predicates[${i}]`
    if (!p || typeof p !== 'object') {
      throw new DisclosureWitnessError('malformed_predicate', prefix)
    }
    const predCode = encodePredicateType(p.predicateType, `${prefix}.predicateType`)
    if (!Number.isInteger(p.attrIndex) || p.attrIndex < 0 || p.attrIndex >= input.numAttributes) {
      throw new DisclosureWitnessError('predicate_attr_out_of_range', `${prefix}.attrIndex`)
    }

    const rawSet = p.setValues ?? []
    if (!Array.isArray(rawSet)) {
      throw new DisclosureWitnessError('malformed_set_values', `${prefix}.setValues`)
    }
    if (rawSet.length > SCHEMA_CONSTANTS.MAX_SET_MEMBERS) {
      throw new DisclosureWitnessError('set_members_oversize', `${prefix}.setValues`)
    }

    const rawSetLen = p.setLen ?? (predCode === '1' ? rawSet.length : 0)
    if (!Number.isInteger(rawSetLen)) {
      throw new DisclosureWitnessError('malformed_set_len', `${prefix}.setLen`)
    }
    if (rawSetLen < 0) {
      throw new DisclosureWitnessError('set_members_undersize', `${prefix}.setLen`)
    }
    if (rawSetLen > SCHEMA_CONSTANTS.MAX_SET_MEMBERS) {
      throw new DisclosureWitnessError('set_members_oversize', `${prefix}.setLen`)
    }
    if (predCode === '1') {
      if (rawSetLen < 1) {
        throw new DisclosureWitnessError('set_members_undersize', `${prefix}.setLen`)
      }
      if (rawSet.length < rawSetLen) {
        throw new DisclosureWitnessError('set_length_mismatch', `${prefix}.setValues`)
      }
    } else if (rawSetLen > rawSet.length && rawSet.length > 0) {
      throw new DisclosureWitnessError('set_length_mismatch', `${prefix}.setValues`)
    }

    const encodedSet = padArray(
      rawSet.map((v, j) => toBigInt(v, `${prefix}.setValues[${j}]`).toString(10)),
      SCHEMA_CONSTANTS.MAX_SET_MEMBERS,
      '0',
      `${prefix}.setValues`,
    )

    activePredicates.push({
      predicate_type: predCode,
      attr_index: p.attrIndex.toString(),
      public_value: toBigInt(p.publicValue ?? '0', `${prefix}.publicValue`).toString(10),
      set_values: encodedSet,
      set_len: rawSetLen.toString(),
      lower_bound: toBigInt(p.lowerBound ?? '0', `${prefix}.lowerBound`).toString(10),
      upper_bound: toBigInt(p.upperBound ?? '0', `${prefix}.upperBound`).toString(10),
    })
  }

  const encodedAttrs = padArray(
    input.attrValues.map((v, idx) => toBigInt(v, `attrValues[${idx}]`).toString(10)),
    SCHEMA_CONSTANTS.MAX_ATTRIBUTES,
    '0',
    'attrValues',
  )
  const encodedBlindings = padArray(
    input.attrBlindings.map((v, idx) => toBigInt(v, `attrBlindings[${idx}]`).toString(10)),
    SCHEMA_CONSTANTS.MAX_ATTRIBUTES,
    '0',
    'attrBlindings',
  )

  const paddedPredicates = [...activePredicates]
  while (paddedPredicates.length < SCHEMA_CONSTANTS.MAX_PREDICATES) {
    paddedPredicates.push({
      predicate_type: '0',
      attr_index: '0',
      public_value: '0',
      set_values: Array(SCHEMA_CONSTANTS.MAX_SET_MEMBERS).fill('0'),
      set_len: '0',
      lower_bound: '0',
      upper_bound: '0',
    })
  }

  return {
    num_attributes: input.numAttributes.toString(),
    attr_values: encodedAttrs,
    attr_blindings: encodedBlindings,
    num_predicates: input.numPredicates.toString(),
    predicates: paddedPredicates,
  }
}

async function computePredicateCommitment(predicates: Predicate[]): Promise<string> {
  if (!Array.isArray(predicates)) {
    throw new DisclosureWitnessError('malformed_predicates', 'predicates')
  }
  if (predicates.length > SCHEMA_CONSTANTS.MAX_PREDICATES) {
    throw new DisclosureWitnessError('predicates_oversize', 'predicates')
  }
  // The circuit hashes exactly num_predicates entries and skips the padding
  // predicates, so the commitment must only fold real predicates.
  let current = BigInt(0)
  for (let i = 0; i < predicates.length; i++) {
    const p = predicates[i]
    const predType = BigInt(encodePredicateType(p.predicateType, `predicates[${i}].predicateType`))
    const attrIndex = BigInt(p.attrIndex ?? 0)
    const publicValue = toCommitmentScalar(p.publicValue ?? '0', `predicates[${i}].publicValue`)
    current = await pedersenHash([current, predType, attrIndex, publicValue])
  }
  return current.toString()
}

export async function computeNullifier(
  credentialRoot: string,
  videoHashHi: string,
  videoHashLo: string,
  evidenceDigest: string,
): Promise<string> {
  const result = await pedersenHash([
    toBigInt(credentialRoot, 'credentialRoot'),
    toBigInt(videoHashHi, 'videoHashHi'),
    toBigInt(videoHashLo, 'videoHashLo'),
    toBigInt(evidenceDigest, 'evidenceDigest'),
  ])
  return result.toString()
}

export async function generateSelectiveDisclosureProof(
  input: SelectiveDisclosureInput,
): Promise<SelectiveDisclosureProof> {
  // Bound predicate, set-member, and attribute lists BEFORE circuit fetch or proving.
  const preparedWitness = prepareSelectiveDisclosureWitness(input)

  const witnessInputs = {
    schema_hash: toBigInt(input.schemaHash, 'schemaHash').toString(10),
    issuer_namespace: toBigInt(input.issuerNamespace, 'issuerNamespace').toString(10),
    schema_version: input.schemaVersion.toString(),
    credential_root: toBigInt(input.credentialRoot, 'credentialRoot').toString(10),
    nullifier: toBigInt(input.nullifier, 'nullifier').toString(10),
    video_hash_hi: toBigInt(input.videoHashHi, 'videoHashHi').toString(10),
    video_hash_lo: toBigInt(input.videoHashLo, 'videoHashLo').toString(10),
    verifier_digest: toBigInt(input.verifierDigest, 'verifierDigest').toString(10),
    circuit_version: input.circuitVersion.toString(),
    evidence_digest: toBigInt(input.evidenceDigest, 'evidenceDigest').toString(10),
    predicate_commitment: BigInt(await computePredicateCommitment(input.predicates)).toString(10),
    ...preparedWitness,
  }

  const circuit = await loadCircuit()
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
