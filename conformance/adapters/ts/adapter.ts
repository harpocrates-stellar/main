// Conformance adapter for the shipped TypeScript: cli/src (the CLI/SDK) or frontend/src (browser libraries).
//
//   HPX_IMPL=cli       npx tsx conformance/adapters/ts/adapter.ts
//   HPX_IMPL=frontend  npx tsx conformance/adapters/ts/adapter.ts
//
// It calls the *real* exported functions and translates their thrown messages / results into the suite's
// stable reason codes. It never re-implements protocol logic: where a function is not exported (e.g. the
// recursive canonicalizer), the op is routed through the public function that uses it, and where nothing
// public exists the op answers `unsupported_op` (contract-side and indexer-side operations belong to a
// contract adapter or a deployed harness, not to a TypeScript library).
//
// Protocol: hpx-conformance-adapter/1 (line-delimited JSON on stdio). Errors never echo input.
import { createInterface } from 'node:readline'
import { createHash } from 'node:crypto'
import { hash as sdkHash, StrKey } from '@stellar/stellar-sdk'

const IMPL = process.env.HPX_IMPL === 'frontend' ? 'frontend' : 'cli'
const ROOT = new URL('../../../', import.meta.url)
const load = (p: string) => import(new URL(p, ROOT).href)

const cliManifest = await load('cli/src/manifest.ts')
const cliMetadata = await load('cli/src/metadata.ts')
const cliNormalize = await load('cli/src/normalize.ts')
const cliHashing = await load('cli/src/hashing.ts')
const cliSigned = await load('cli/src/signed-receipt.ts')
const feManifest = await load('frontend/src/proofManifest.ts')
const feReceipt = await load('frontend/src/verificationReceipt.ts')
const feGuard = await load('frontend/src/networkGuard.ts')
const feLineage = await load('frontend/src/lineageManifest.ts')
const feEnc = await load('frontend/src/stellarEncoding.ts')
const feVI = await load('frontend/src/verifierInputs.ts')

const manifestLib = IMPL === 'cli' ? cliManifest : feManifest
const receiptLib = IMPL === 'cli' ? cliSigned : feReceipt

class Fail extends Error {
  code: string
  detail?: Record<string, unknown>
  constructor(code: string, detail?: Record<string, unknown>) {
    super(code)
    this.code = code
    this.detail = detail
  }
}
const sha = (s: string) => createHash('sha256').update(s, 'utf8').digest('hex')
const canonOut = (canonical: string) => ({ canonical, sha256: sha(canonical) })
const msg = (e: unknown) => (e instanceof Error ? e.message : String(e))

/** Map a thrown message onto a reason code via ordered [pattern, code] rules. Unmapped => `unmapped:<...>` (visible in the report). */
function mapErr(e: unknown, rules: Array<[RegExp, string | ((m: RegExpMatchArray) => Fail)]>): never {
  const m = msg(e)
  for (const [rx, out] of rules) {
    const hit = m.match(rx)
    if (hit) throw typeof out === 'string' ? new Fail(out) : out(hit)
  }
  throw new Fail('unmapped_error')
}

const ops: Record<string, (i: any) => unknown> = {
  // ---- canonical JSON: the only recursive canonicalizer is the receipt serializer
  canonicalize(i) {
    let v: unknown
    try {
      v = JSON.parse(i.json_text)
    } catch {
      throw new Fail('invalid_json')
    }
    return canonOut(receiptLib.serializeVerificationReceipt(v))
  },

  // ---- metadata (CLI/SDK is the only TS metadata implementation)
  metadata_validate(i) {
    try {
      cliMetadata.validateMetadata(i.metadata)
    } catch (e) {
      mapErr(e, [
        [/must be a JSON object/, 'not_object'],
        [/missing required field: (\w+)/, (m) => new Fail('missing_field', { field: m[1] })],
        [/protocol must/, 'bad_protocol'],
        [/version must/, 'bad_version'],
        [/tier must/, 'bad_tier'],
        [/sourceHash must/, 'bad_source_hash'],
        [/proofId must/, 'bad_proof_id'],
      ])
    }
    return { valid: true }
  },
  metadata_hash(i) {
    // canonicalMetadataHash returns only the digest; the canonical text is its (unexported) first line.
    const canonical = JSON.stringify(i.metadata, Object.keys(i.metadata).sort())
    const digest = cliMetadata.canonicalMetadataHash(i.metadata)
    if (digest !== sha(canonical)) throw new Fail('adapter_self_check_failed')
    return { canonical, sha256: digest }
  },

  // ---- manifests
  manifest_create(i) {
    return canonOut(manifestLib.serializeManifest(manifestLib.createProofManifest(i)))
  },
  manifest_parse(i) {
    let parsed
    try {
      parsed = cliManifest.parseManifest(i.text)
    } catch (e) {
      mapErr(e, [
        [/not valid JSON/, 'invalid_json'],
        [/must be a JSON object/, 'not_object'],
        [/unsupported fields/, 'unsupported_field'],
        [/protocol must/, 'bad_protocol'],
        [/unsupported manifest version/, 'unsupported_version'],
        [/tier must/, 'bad_tier'],
        [/manifest\.(\w+) must be a non-empty string/, (m) => new Fail('bad_string_field', { field: m[1] })],
        [/manifest\.(\w+) must be a 32-byte hex/, (m) => new Fail('bad_hex32', { field: m[1] })],
        [/timestamp must be a valid date/, 'bad_timestamp'],
        [/scope or epoch/, 'bad_scope_epoch'],
        [/scopeName/, 'bad_scope_name'],
        [/selectiveDisclosure/, 'bad_disclosure'],
      ])
    }
    return canonOut(cliManifest.serializeManifest(parsed))
  },
  lineage_manifest_create(i) {
    try {
      return canonOut(feLineage.serializeTransformationManifest(feLineage.createTransformationManifest(i)))
    } catch (e) {
      mapErr(e, [[/Unsupported lineage operation/, 'unsupported_operation']])
    }
  },

  // ---- receipts
  async receipt_verify(i) {
    const o = i.options ?? {}
    const r = await receiptLib.verifyVerificationReceipt(i.receipt, {
      keys: i.keys,
      expectedNetworkPassphrase: o.expectedNetworkPassphrase,
      expectedProofId: o.expectedProofId,
      now: o.now ? new Date(o.now) : undefined,
      keyValidity: o.keyValidity,
    })
    if (r.valid) return { valid: true }
    mapErr(new Error(r.reason), [
      [/size limit/, 'receipt_too_large'],
      [/unsupported receipt version/, 'receipt_unsupported_version'],
      [/result is invalid/, 'receipt_result_invalid'],
      [/digests must be/, 'receipt_digest_invalid'],
      [/tier is invalid/, 'receipt_tier_invalid'],
      [/metadata is incomplete/, 'receipt_metadata_incomplete'],
      [/signer is invalid/, 'receipt_signer_invalid'],
      [/ledger sequence/, 'receipt_ledger_invalid'],
      [/transaction hash/, 'receipt_txhash_invalid'],
      [/verification time is invalid/, 'receipt_time_invalid'],
      [/missing signature/, 'receipt_signature_missing'],
      [/network does not match/, 'receipt_network_mismatch'],
      [/proof does not match/, 'receipt_proof_mismatch'],
      [/stale or was not valid/, 'receipt_key_stale'],
      [/signer key is unknown/, 'receipt_key_unknown'],
      [/invalid base64url/, 'receipt_signature_malformed'],
      [/signature is invalid/, 'receipt_signature_invalid'],
    ])
  },
  receipt_qr_encode(i) {
    try {
      return { encoded: receiptLib.encodeReceiptForQr(i.receipt) }
    } catch (e) {
      mapErr(e, [[/QR payload size limit/, 'qr_too_large']])
    }
  },
  receipt_qr_decode(i) {
    try {
      const r = receiptLib.decodeReceiptFromQr(i.encoded)
      return canonOut(receiptLib.serializeVerificationReceipt(r))
    } catch (e) {
      mapErr(e, [
        [/QR payload size limit/, 'qr_too_large'],
        [/invalid receipt encoding/, 'qr_invalid_encoding'],
      ])
    }
  },

  // ---- encodings
  hex32_normalize(i) {
    try {
      return { hex: IMPL === 'cli' ? cliHashing.asHex32(i.value) : feEnc.asHex32(i.value) }
    } catch {
      throw new Fail('invalid_hex32')
    }
  },
  hex_bytes_normalize(i) {
    try {
      return { hex: IMPL === 'cli' ? cliHashing.asHexBytes(i.value) : feEnc.asHexBytes(i.value) }
    } catch {
      throw new Fail('invalid_hex_bytes')
    }
  },
  bytes_to_hex(i) {
    return { hex: (IMPL === 'cli' ? cliHashing.bytesToHex : feEnc.bytesToHex)(i.bytes) }
  },
  strkey_decode(i) {
    const s = i.strkey
    const ok = i.expect === 'contract' ? StrKey.isValidContract(s) : StrKey.isValidEd25519PublicKey(s)
    if (!ok) throw new Fail('strkey_invalid')
    const raw = i.expect === 'contract' ? StrKey.decodeContract(s) : StrKey.decodeEd25519PublicKey(s)
    return { type: i.expect, payload_hex: Buffer.from(raw).toString('hex') }
  },
  network_id(i) {
    return { network_id: Buffer.from(sdkHash(Buffer.from(i.passphrase, 'utf8'))).toString('hex') }
  },
  network_name(i) {
    return { name: (IMPL === 'cli' ? cliNormalize : feGuard).networkName(i.passphrase) }
  },
  scval_bytes_xdr(i) {
    try {
      return { xdr_hex: feEnc.scBytes(feEnc.asHexBytes(i.hex)).toXDR('hex') }
    } catch {
      throw new Fail('invalid_hex_bytes')
    }
  },
  network_check(i) {
    const r = feGuard.checkNetworkMatch(i.wallet, i.contract)
    if (r.ok) return { match: true }
    if (/^Freighter did not return/.test(r.reason)) throw new Fail('wallet_network_unavailable')
    const m = r.reason.match(/^Wallet is on ([\s\S]*) but the contract is deployed on ([\s\S]*)\.$/)
    if (!m) throw new Fail('unmapped_error')
    throw new Fail('network_mismatch', { wallet_network: m[1], contract_network: m[2] })
  },

  // ---- status
  verification_classify(i) {
    return { result: cliNormalize.classifyVerification(i.manifest, i.transaction, i.chain_record, i.now_seconds) }
  },

  // ---- public inputs (browser codec)
  classify_public_inputs(i) {
    const code = feVI.classify(i.schema, i.public_inputs_hex, i.proof_hex)
    if (code === null) return { accepted: true }
    throw new Fail(code)
  },
  decode_public_inputs_hex(i) {
    try {
      return { bytes: feVI.decodeHex(i.value, i.field).length }
    } catch (e) {
      throw new Fail((e as { code?: string }).code ?? 'malformed_hex')
    }
  },
}
// `cli` has no browser-only pieces and vice-versa; ops a layer does not ship simply are not advertised.
if (IMPL === 'cli') {
  for (const op of ['lineage_manifest_create', 'network_check', 'scval_bytes_xdr', 'classify_public_inputs', 'decode_public_inputs_hex'])
    delete ops[op]
} else {
  for (const op of ['metadata_validate', 'metadata_hash', 'manifest_parse', 'verification_classify']) delete ops[op]
}

const rl = createInterface({ input: process.stdin, crlfDelay: Infinity })
const out = (o: unknown) => process.stdout.write(JSON.stringify(o) + '\n')
for await (const line of rl) {
  let req: { id?: string; op?: string; input?: unknown }
  try {
    req = JSON.parse(line)
  } catch {
    out({ id: null, ok: false, code: 'bad_request' })
    continue
  }
  if (req.op === 'hello') {
    out({ id: req.id, ok: true, output: { protocol: 'hpx-conformance-adapter/1', ops: Object.keys(ops).sort(),
      implementation: { name: `harpocrates-${IMPL}`, version: '1.0.0', language: 'typescript' } } })
    continue
  }
  const fn = ops[req.op ?? '']
  if (!fn) {
    out({ id: req.id, ok: false, code: 'unsupported_op' })
    continue
  }
  try {
    out({ id: req.id, ok: true, output: await fn(req.input) })
  } catch (e) {
    if (e instanceof Fail) out({ id: req.id, ok: false, code: e.code, ...(e.detail ? { detail: e.detail } : {}) })
    else out({ id: req.id, ok: false, code: 'internal_error' })
  }
}
