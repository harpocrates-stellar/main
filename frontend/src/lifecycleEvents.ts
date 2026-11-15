/**
 * Independent browser-side Stellar ScVal XDR decoder and lifecycle event
 * schema validator (`hpx-ev/1`, #1201).
 *
 * Uses only standard ES2023 `Uint8Array` / `DataView` / `TextDecoder` primitives
 * so browser clients and indexers can verify Soroban lifecycle event topics and
 * payloads against the canonical interoperability corpus without Rust bindings.
 */

export const LIFECYCLE_EVENT_CODEC_ID = 'hpx-ev/1'

export type LifecycleEventRejectCode =
  | 'malformed_xdr'
  | 'trailing_xdr_bytes'
  | 'non_canonical_padding'
  | 'unknown_event_topic'
  | 'topic_arity_mismatch'
  | 'topic_type_mismatch'
  | 'payload_schema_mismatch'
  | 'non_canonical_map_order'

export class LifecycleEventError extends Error {
  readonly code: LifecycleEventRejectCode

  constructor(code: LifecycleEventRejectCode, message: string) {
    super(`${code}: ${message}`)
    this.name = 'LifecycleEventError'
    this.code = code
  }
}

export type StructuredEventAtom = {
  type: string
  value: boolean | number | string | null | StructuredEventAtom[]
}

export type StructuredPayloadEntry = StructuredEventAtom & {
  field: string
}

export type DecodedLifecycleEvent = {
  event_name: string
  topics: StructuredEventAtom[]
  payload: StructuredPayloadEntry[]
  topics_canonical: string
  payload_canonical: string
}

type InternalDecodedValue = {
  type: string
  value: unknown
  canonical: string
}

type EventSchemaDef = {
  topicPrefix: readonly string[]
  topicTypes: readonly string[]
  requiredFields: Readonly<Record<string, string>>
  optionalFields: Readonly<Record<string, string>>
}

export const LIFECYCLE_EVENT_SPECS: Readonly<Record<string, EventSchemaDef>> = {
  CredentialRootAdded: {
    topicPrefix: ['credroot', 'add'],
    topicTypes: ['symbol', 'symbol', 'bytes32'],
    requiredFields: { issued_at: 'u64', metadata_hash: 'bytes32' },
    optionalFields: {},
  },
  CredentialRootRevoked: {
    topicPrefix: ['credroot', 'revoke'],
    topicTypes: ['symbol', 'symbol', 'bytes32'],
    requiredFields: {},
    optionalFields: {},
  },
  IssuerAdded: {
    topicPrefix: ['issuer', 'add'],
    topicTypes: ['symbol', 'symbol', 'address_ed25519'],
    requiredFields: { metadata_hash: 'bytes32' },
    optionalFields: {},
  },
  IssuerRevoked: {
    topicPrefix: ['issuer', 'revoke'],
    topicTypes: ['symbol', 'symbol', 'address_ed25519'],
    requiredFields: {},
    optionalFields: {},
  },
  ProofRegistered: {
    topicPrefix: ['proof', 'reg'],
    topicTypes: ['symbol', 'symbol', 'bytes32'],
    requiredFields: {
      batch_size: 'u32',
      status: 'u32',
      tier: 'u32',
      video_hash: 'bytes32',
    },
    optionalFields: {},
  },
  ProofHistoryEvent: {
    topicPrefix: ['proof', 'history'],
    topicTypes: ['symbol', 'symbol', 'bytes32'],
    requiredFields: {
      action: 'u32',
      reason_code: 'u32',
      timestamp: 'u64',
    },
    optionalFields: { actor: 'address_ed25519' },
  },
  ProofRevoked: {
    topicPrefix: ['proof', 'revoke'],
    topicTypes: ['symbol', 'symbol', 'bytes32'],
    requiredFields: { status: 'u32' },
    optionalFields: {},
  },
  MetadataEnvelopeBound: {
    topicPrefix: ['metadata', 'envelope', 'bound'],
    topicTypes: ['symbol', 'symbol', 'symbol', 'bytes32'],
    requiredFields: {
      bound_at: 'u64',
      metadata_hash: 'bytes32',
      version: 'u32',
    },
    optionalFields: {},
  },
  MetadataEnvelopeUpgraded: {
    topicPrefix: ['metadata', 'envelope', 'upgraded'],
    topicTypes: ['symbol', 'symbol', 'symbol', 'bytes32'],
    requiredFields: {
      current: 'u32',
      metadata_hash: 'bytes32',
      previous: 'u32',
    },
    optionalFields: {},
  },
  TimestampClaimAnchored: {
    topicPrefix: ['timestamp', 'anchor'],
    topicTypes: ['symbol', 'symbol', 'bytes32'],
    requiredFields: {
      anchored_at: 'u64',
      assurance: 'u32',
      attestation_digest: 'bytes32',
      ledger_sequence: 'u32',
      sources: 'u32',
    },
    optionalFields: {},
  },
  LineageRegistered: {
    topicPrefix: ['lineage', 'reg'],
    topicTypes: ['symbol', 'symbol', 'bytes32'],
    requiredFields: {
      actor: 'address_ed25519',
      depth: 'u32',
      manifest_digest: 'bytes32',
      operation_type: 'symbol',
      parent_commitments: 'vec',
    },
    optionalFields: {},
  },
  DisputeOpened: {
    topicPrefix: ['dispute', 'open'],
    topicTypes: ['symbol', 'symbol', 'bytes32', 'bytes32'],
    requiredFields: {
      commitment_hash: 'bytes32',
      reason: 'u32',
      reporter_hash: 'bytes32',
      respond_deadline: 'u64',
    },
    optionalFields: {},
  },
  DisputeResponded: {
    topicPrefix: ['dispute', 'respond'],
    topicTypes: ['symbol', 'symbol', 'bytes32', 'bytes32'],
    requiredFields: {
      resolve_deadline: 'u64',
      response_commitment: 'bytes32',
    },
    optionalFields: {},
  },
  DisputeResolved: {
    topicPrefix: ['dispute', 'resolve'],
    topicTypes: ['symbol', 'symbol', 'bytes32', 'bytes32'],
    requiredFields: { resolved_at: 'u64' },
    optionalFields: {},
  },
  DisputeDismissed: {
    topicPrefix: ['dispute', 'dismiss'],
    topicTypes: ['symbol', 'symbol', 'bytes32', 'bytes32'],
    requiredFields: { resolved_at: 'u64' },
    optionalFields: {},
  },
  DisputeSuperseded: {
    topicPrefix: ['dispute', 'supersede'],
    topicTypes: ['symbol', 'symbol', 'bytes32', 'bytes32'],
    requiredFields: { resolved_at: 'u64', superseded_by: 'bytes32' },
    optionalFields: {},
  },
  SourceBatchRootRegistered: {
    topicPrefix: ['batch', 'root'],
    topicTypes: ['symbol', 'symbol', 'bytes32', 'address_ed25519'],
    requiredFields: {
      count: 'u32',
      metadata_hash: 'bytes32',
      registered_at: 'u64',
    },
    optionalFields: {},
  },
  SchemaAdded: {
    topicPrefix: ['schema', 'add'],
    topicTypes: ['symbol', 'symbol', 'bytes32'],
    requiredFields: {
      attribute_count: 'u32',
      issuer_namespace: 'bytes32',
      version: 'u32',
    },
    optionalFields: {},
  },
  SchemaDeprecated: {
    topicPrefix: ['schema', 'deprecate'],
    topicTypes: ['symbol', 'symbol', 'bytes32'],
    requiredFields: {},
    optionalFields: {},
  },
  SchemaReactivated: {
    topicPrefix: ['schema', 'reactivate'],
    topicTypes: ['symbol', 'symbol', 'bytes32'],
    requiredFields: {},
    optionalFields: {},
  },
  RevocationRootSet: {
    topicPrefix: ['revroot', 'set'],
    topicTypes: ['symbol', 'symbol', 'bytes32'],
    requiredFields: {},
    optionalFields: {},
  },
}

const ASCII_DECODER = new TextDecoder('utf-8', { fatal: true })

export function decodeXdrHex(hex: string): Uint8Array {
  if (hex.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(hex)) {
    throw new LifecycleEventError('malformed_xdr', 'invalid hex presentation')
  }
  const out = new Uint8Array(hex.length / 2)
  for (let i = 0; i < out.length; i += 1) {
    out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16)
  }
  return out
}

function encodeHex(bytes: Uint8Array): string {
  let out = ''
  for (const b of bytes) {
    out += b.toString(16).padStart(2, '0')
  }
  return out
}

class XdrCursor {
  private readonly bytes: Uint8Array
  private readonly view: DataView
  pos: number

  constructor(bytes: Uint8Array) {
    this.bytes = bytes
    this.view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength)
    this.pos = 0
  }

  readU32(): number {
    if (this.pos + 4 > this.bytes.length) {
      throw new LifecycleEventError('malformed_xdr', 'truncated u32')
    }
    const val = this.view.getUint32(this.pos, false)
    this.pos += 4
    return val
  }

  readU64(): bigint {
    if (this.pos + 8 > this.bytes.length) {
      throw new LifecycleEventError('malformed_xdr', 'truncated u64')
    }
    const val = this.view.getBigUint64(this.pos, false)
    this.pos += 8
    return val
  }

  readFixed32(): Uint8Array {
    if (this.pos + 32 > this.bytes.length) {
      throw new LifecycleEventError('malformed_xdr', 'truncated fixed32')
    }
    const slice = this.bytes.subarray(this.pos, this.pos + 32)
    this.pos += 32
    return slice
  }

  readVarOpaque(): Uint8Array {
    const len = this.readU32()
    const pad = (4 - (len % 4)) % 4
    if (this.pos + len + pad > this.bytes.length) {
      throw new LifecycleEventError('malformed_xdr', 'truncated variable opaque')
    }
    const slice = this.bytes.subarray(this.pos, this.pos + len)
    for (let i = 0; i < pad; i += 1) {
      if (this.bytes[this.pos + len + i] !== 0) {
        throw new LifecycleEventError('non_canonical_padding', 'non-zero XDR padding')
      }
    }
    this.pos += len + pad
    return slice
  }

  readScVal(): InternalDecodedValue {
    const disc = this.readU32()
    switch (disc) {
      case 0: {
        const flag = this.readU32()
        if (flag !== 0 && flag !== 1) {
          throw new LifecycleEventError('malformed_xdr', 'invalid bool flag')
        }
        const bVal = flag === 1
        return {
          type: 'bool',
          value: bVal,
          canonical: `bool:${bVal ? 'true' : 'false'}`,
        }
      }
      case 1:
        return { type: 'void', value: null, canonical: 'void:null' }
      case 3: {
        const u = this.readU32()
        return { type: 'u32', value: u, canonical: `u32:${u}` }
      }
      case 5: {
        const big = this.readU64()
        const jsonSafe =
          big <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(big) : big.toString()
        return { type: 'u64', value: jsonSafe, canonical: `u64:${big.toString()}` }
      }
      case 13: {
        const raw = this.readVarOpaque()
        const hx = encodeHex(raw)
        const ty = `bytes${raw.length}`
        return { type: ty, value: hx, canonical: `${ty}:${hx}` }
      }
      case 15: {
        const raw = this.readVarOpaque()
        if (raw.length === 0 || raw.length > 32) {
          throw new LifecycleEventError('malformed_xdr', 'invalid ScSymbol length')
        }
        for (const ch of raw) {
          const ok =
            (ch >= 48 && ch <= 57) ||
            (ch >= 65 && ch <= 90) ||
            (ch >= 97 && ch <= 122) ||
            ch === 95
          if (!ok) {
            throw new LifecycleEventError('malformed_xdr', 'invalid ScSymbol character')
          }
        }
        const sym = ASCII_DECODER.decode(raw)
        return { type: 'symbol', value: sym, canonical: `symbol:${sym}` }
      }
      case 16: {
        if (this.readU32() !== 1) {
          throw new LifecycleEventError('malformed_xdr', 'missing ScVec body')
        }
        const count = this.readU32()
        const items: InternalDecodedValue[] = []
        for (let i = 0; i < count; i += 1) {
          items.push(this.readScVal())
        }
        return {
          type: 'vec',
          value: items,
          canonical: `vec[${items.map((x) => x.canonical).join(',')}]`,
        }
      }
      case 17: {
        if (this.readU32() !== 1) {
          throw new LifecycleEventError('malformed_xdr', 'missing ScMap body')
        }
        const count = this.readU32()
        const entries: Array<[string, InternalDecodedValue]> = []
        let prevKey: string | null = null
        for (let i = 0; i < count; i += 1) {
          const keyVal = this.readScVal()
          if (keyVal.type !== 'symbol') {
            throw new LifecycleEventError('payload_schema_mismatch', 'non-symbol map key')
          }
          const keyStr = String(keyVal.value)
          if (prevKey !== null && keyStr <= prevKey) {
            throw new LifecycleEventError(
              'non_canonical_map_order',
              'ScMap keys not strictly ascending',
            )
          }
          prevKey = keyStr
          entries.push([keyStr, this.readScVal()])
        }
        const canonical =
          entries.length === 0
            ? 'empty_map'
            : entries.map(([k, v]) => `${k}=${v.canonical}`).join(';')
        return { type: 'map', value: entries, canonical }
      }
      case 18: {
        const addrKind = this.readU32()
        if (addrKind === 0) {
          if (this.readU32() !== 0) {
            throw new LifecycleEventError('malformed_xdr', 'unsupported PublicKeyType')
          }
          const hx = encodeHex(this.readFixed32())
          return {
            type: 'address_ed25519',
            value: hx,
            canonical: `address_ed25519:${hx}`,
          }
        }
        if (addrKind === 1) {
          const hx = encodeHex(this.readFixed32())
          return {
            type: 'address_contract',
            value: hx,
            canonical: `address_contract:${hx}`,
          }
        }
        throw new LifecycleEventError('malformed_xdr', 'unsupported ScAddress kind')
      }
      default:
        throw new LifecycleEventError('malformed_xdr', `unsupported ScVal discriminant ${disc}`)
    }
  }
}

export function decodeExactScVal(hex: string): InternalDecodedValue {
  const bytes = decodeXdrHex(hex)
  const cursor = new XdrCursor(bytes)
  const decoded = cursor.readScVal()
  if (cursor.pos !== bytes.length) {
    throw new LifecycleEventError('trailing_xdr_bytes', 'unconsumed trailing XDR bytes')
  }
  return decoded
}

function toStructuredAtom(val: InternalDecodedValue): StructuredEventAtom {
  if (val.type === 'vec') {
    const arr = val.value as InternalDecodedValue[]
    return { type: 'vec', value: arr.map(toStructuredAtom) }
  }
  return {
    type: val.type,
    value: val.value as boolean | number | string | null,
  }
}

export function decodeLifecycleEvent(
  topicsXdrHex: string,
  dataXdrHex: string,
): DecodedLifecycleEvent {
  const topicsVal = decodeExactScVal(topicsXdrHex)
  const dataVal = decodeExactScVal(dataXdrHex)

  if (topicsVal.type !== 'vec') {
    throw new LifecycleEventError('malformed_xdr', 'topics root must be ScVal::Vec')
  }
  const topics = topicsVal.value as InternalDecodedValue[]
  if (topics.length < 2) {
    throw new LifecycleEventError('topic_arity_mismatch', 'fewer than 2 topics')
  }

  let matchedName: string | null = null
  let matchedSpec: EventSchemaDef | null = null
  for (const [evName, spec] of Object.entries(LIFECYCLE_EVENT_SPECS)) {
    if (
      topics.length >= spec.topicPrefix.length &&
      spec.topicPrefix.every(
        (sym, idx) => topics[idx].type === 'symbol' && topics[idx].value === sym,
      )
    ) {
      matchedName = evName
      matchedSpec = spec
      break
    }
  }

  if (matchedName === null || matchedSpec === null) {
    throw new LifecycleEventError('unknown_event_topic', 'unrecognized topic prefix')
  }

  if (topics.length !== matchedSpec.topicTypes.length) {
    throw new LifecycleEventError('topic_arity_mismatch', 'unexpected topic count')
  }
  for (let i = 0; i < topics.length; i += 1) {
    if (topics[i].type !== matchedSpec.topicTypes[i]) {
      throw new LifecycleEventError('topic_type_mismatch', 'topic ScVal type mismatch')
    }
  }

  if (dataVal.type !== 'map') {
    throw new LifecycleEventError('payload_schema_mismatch', 'payload root must be ScVal::Map')
  }
  const entries = dataVal.value as Array<[string, InternalDecodedValue]>
  const entryMap = new Map<string, InternalDecodedValue>(entries)

  for (const [reqKey, reqType] of Object.entries(matchedSpec.requiredFields)) {
    const actual = entryMap.get(reqKey)
    if (actual === undefined || actual.type !== reqType) {
      throw new LifecycleEventError('payload_schema_mismatch', `invalid required field ${reqKey}`)
    }
  }

  for (const [key, val] of entries) {
    const expectedType =
      matchedSpec.requiredFields[key] ?? matchedSpec.optionalFields[key]
    if (expectedType === undefined || val.type !== expectedType) {
      throw new LifecycleEventError('payload_schema_mismatch', `unexpected field ${key}`)
    }
  }

  return {
    event_name: matchedName,
    topics: topics.map(toStructuredAtom),
    payload: entries.map(([field, val]) => ({
      field,
      ...toStructuredAtom(val),
    })),
    topics_canonical: topics.map((t) => t.canonical).join('|'),
    payload_canonical: dataVal.canonical,
  }
}
