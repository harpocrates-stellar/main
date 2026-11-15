//! Canonical lifecycle event interoperability corpus conformance (`hpx-ev/1`, #1201).
//!
//! Drives `contracts/vectors/lifecycle_events_v1.json` across two contract-side
//! checks:
//!   1. Live execution parity: invokes every covered `HarpocratesRegistry`
//!      lifecycle entry point in `Env::default()` and asserts that the emitted
//!      `ContractEvent` V0 topics and data XDR bytes match the published corpus
//!      byte-for-byte.
//!   2. Strict wire & schema classification: decodes every positive and negative
//!      corpus case, cross-checking accepted vectors against `stellar_xdr`'s
//!      `ScVal::from_xdr` and asserting rejected boundary cases fail closed with
//!      their exact `reject_code`.
//!
//! Independent client runners in Python (`backend/test_lifecycle_event_corpus.py`)
//! and TypeScript (`frontend/src/lifecycleEvents.conformance.test.ts`) verify
//! the exact same corpus file without depending on Rust or `soroban-sdk`.

use super::*;
use soroban_sdk::{
    testutils::{Events as _, Ledger},
    xdr::{
        AccountId, ContractEventBody, Limits, PublicKey, ReadXdr, ScAddress, ScVal, ScVec, Uint256,
        WriteXdr,
    },
    Address, Bytes, BytesN, Env, Symbol, TryFromVal, Val,
};
use std::format;
use std::string::{String, ToString};
use std::vec::Vec as StdVec;

const CORPUS_JSON: &str = include_str!("../../../vectors/lifecycle_events_v1.json");

#[derive(Clone, Debug)]
struct CorpusCase {
    id: String,
    event_name: String,
    entrypoint: String,
    topics_canonical: String,
    payload_canonical: String,
    topics_xdr_hex: String,
    data_xdr_hex: String,
    accept: bool,
    reject_code: Option<String>,
}

fn json_line_field(line: &str, key: &str) -> Option<String> {
    let trimmed = line.trim();
    let prefix = format!("\"{}\":", key);
    let rest = trimmed.strip_prefix(prefix.as_str())?.trim();
    let rest = rest.trim_end_matches(',').trim();
    if rest == "null" {
        return Some("null".to_string());
    }
    Some(rest.trim_matches('"').to_string())
}

fn parse_corpus_cases(raw: &str) -> StdVec<CorpusCase> {
    let mut out = StdVec::new();
    let mut in_cases = false;
    let mut id = None;
    let mut event_name = None;
    let mut entrypoint = None;
    let mut topics_canonical = None;
    let mut payload_canonical = None;
    let mut topics_xdr_hex = None;
    let mut data_xdr_hex = None;
    let mut accept = None;

    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed == "\"cases\": [" {
            in_cases = true;
            continue;
        }
        if !in_cases {
            continue;
        }
        if let Some(v) = json_line_field(line, "id") {
            id = Some(v);
        } else if let Some(v) = json_line_field(line, "event_name") {
            event_name = Some(v);
        } else if let Some(v) = json_line_field(line, "entrypoint") {
            entrypoint = Some(v);
        } else if let Some(v) = json_line_field(line, "topics_canonical") {
            topics_canonical = Some(v);
        } else if let Some(v) = json_line_field(line, "payload_canonical") {
            payload_canonical = Some(v);
        } else if let Some(v) = json_line_field(line, "topics_xdr_hex") {
            topics_xdr_hex = Some(v);
        } else if let Some(v) = json_line_field(line, "data_xdr_hex") {
            data_xdr_hex = Some(v);
        } else if let Some(v) = json_line_field(line, "accept") {
            accept = Some(v == "true");
        } else if let Some(v) = json_line_field(line, "reject_code") {
            let rc = if v == "null" { None } else { Some(v) };
            if let (Some(i), Some(en), Some(ep), Some(tc), Some(pc), Some(tx), Some(dx), Some(ac)) = (
                id.take(),
                event_name.take(),
                entrypoint.take(),
                topics_canonical.take(),
                payload_canonical.take(),
                topics_xdr_hex.take(),
                data_xdr_hex.take(),
                accept.take(),
            ) {
                out.push(CorpusCase {
                    id: i,
                    event_name: en,
                    entrypoint: ep,
                    topics_canonical: tc,
                    payload_canonical: pc,
                    topics_xdr_hex: tx,
                    data_xdr_hex: dx,
                    accept: ac,
                    reject_code: rc,
                });
            }
        }
    }
    out
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use core::fmt::Write;
        let _ = write!(&mut out, "{:02x}", b);
    }
    out
}

fn hex_decode(hex: &str) -> Result<StdVec<u8>, &'static str> {
    if hex.len() % 2 != 0 {
        return Err("malformed_xdr");
    }
    let mut out = StdVec::with_capacity(hex.len() / 2);
    let bytes = hex.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let hi = (bytes[i] as char).to_digit(16).ok_or("malformed_xdr")?;
        let lo = (bytes[i + 1] as char).to_digit(16).ok_or("malformed_xdr")?;
        out.push(((hi << 4) | lo) as u8);
        i += 2;
    }
    Ok(out)
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum WireVal {
    Bool(bool),
    Void,
    U32(u32),
    U64(u64),
    Bytes(StdVec<u8>),
    Symbol(String),
    AddressEd25519([u8; 32]),
    AddressContract([u8; 32]),
    Vec(StdVec<WireVal>),
    Map(StdVec<(String, WireVal)>),
}

impl WireVal {
    fn type_tag(&self) -> String {
        match self {
            WireVal::Bool(_) => "bool".to_string(),
            WireVal::Void => "void".to_string(),
            WireVal::U32(_) => "u32".to_string(),
            WireVal::U64(_) => "u64".to_string(),
            WireVal::Bytes(b) => format!("bytes{}", b.len()),
            WireVal::Symbol(_) => "symbol".to_string(),
            WireVal::AddressEd25519(_) => "address_ed25519".to_string(),
            WireVal::AddressContract(_) => "address_contract".to_string(),
            WireVal::Vec(_) => "vec".to_string(),
            WireVal::Map(_) => "map".to_string(),
        }
    }

    fn canonical(&self) -> String {
        match self {
            WireVal::Void => "void:null".to_string(),
            WireVal::Bool(b) => format!("bool:{}", if *b { "true" } else { "false" }),
            WireVal::U32(n) => format!("u32:{}", n),
            WireVal::U64(n) => format!("u64:{}", n),
            WireVal::Symbol(s) => format!("symbol:{}", s),
            WireVal::Bytes(b) => format!("bytes{}:{}", b.len(), hex_encode(b)),
            WireVal::AddressEd25519(pk) => format!("address_ed25519:{}", hex_encode(pk)),
            WireVal::AddressContract(h) => format!("address_contract:{}", hex_encode(h)),
            WireVal::Vec(items) => {
                let parts: StdVec<String> = items.iter().map(WireVal::canonical).collect();
                format!("vec[{}]", parts.join(","))
            }
            WireVal::Map(entries) => {
                if entries.is_empty() {
                    "empty_map".to_string()
                } else {
                    let parts: StdVec<String> = entries
                        .iter()
                        .map(|(k, v)| format!("{}={}", k, v.canonical()))
                        .collect();
                    parts.join(";")
                }
            }
        }
    }
}

struct XdrReader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> XdrReader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn read_u32(&mut self) -> Result<u32, &'static str> {
        if self.pos + 4 > self.buf.len() {
            return Err("malformed_xdr");
        }
        let mut arr = [0u8; 4];
        arr.copy_from_slice(&self.buf[self.pos..self.pos + 4]);
        self.pos += 4;
        Ok(u32::from_be_bytes(arr))
    }

    fn read_u64(&mut self) -> Result<u64, &'static str> {
        if self.pos + 8 > self.buf.len() {
            return Err("malformed_xdr");
        }
        let mut arr = [0u8; 8];
        arr.copy_from_slice(&self.buf[self.pos..self.pos + 8]);
        self.pos += 8;
        Ok(u64::from_be_bytes(arr))
    }

    fn read_fixed32(&mut self) -> Result<[u8; 32], &'static str> {
        if self.pos + 32 > self.buf.len() {
            return Err("malformed_xdr");
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&self.buf[self.pos..self.pos + 32]);
        self.pos += 32;
        Ok(arr)
    }

    fn read_var_opaque(&mut self) -> Result<StdVec<u8>, &'static str> {
        let len = self.read_u32()? as usize;
        let pad = (4 - (len % 4)) % 4;
        if self.pos + len + pad > self.buf.len() {
            return Err("malformed_xdr");
        }
        let data = self.buf[self.pos..self.pos + len].to_vec();
        let pad_bytes = &self.buf[self.pos + len..self.pos + len + pad];
        if pad_bytes.iter().any(|b| *b != 0) {
            return Err("non_canonical_padding");
        }
        self.pos += len + pad;
        Ok(data)
    }

    fn read_scval(&mut self) -> Result<WireVal, &'static str> {
        let disc = self.read_u32()?;
        match disc {
            0 => match self.read_u32()? {
                0 => Ok(WireVal::Bool(false)),
                1 => Ok(WireVal::Bool(true)),
                _ => Err("malformed_xdr"),
            },
            1 => Ok(WireVal::Void),
            3 => Ok(WireVal::U32(self.read_u32()?)),
            5 => Ok(WireVal::U64(self.read_u64()?)),
            13 => Ok(WireVal::Bytes(self.read_var_opaque()?)),
            15 => {
                let raw = self.read_var_opaque()?;
                if raw.is_empty()
                    || raw.len() > 32
                    || !raw.iter().all(|b| b.is_ascii_alphanumeric() || *b == b'_')
                {
                    return Err("malformed_xdr");
                }
                let sym = String::from_utf8(raw).map_err(|_| "malformed_xdr")?;
                Ok(WireVal::Symbol(sym))
            }
            16 => {
                let present = self.read_u32()?;
                if present != 1 {
                    return Err("malformed_xdr");
                }
                let count = self.read_u32()? as usize;
                let mut items = StdVec::with_capacity(count);
                for _ in 0..count {
                    items.push(self.read_scval()?);
                }
                Ok(WireVal::Vec(items))
            }
            17 => {
                let present = self.read_u32()?;
                if present != 1 {
                    return Err("malformed_xdr");
                }
                let count = self.read_u32()? as usize;
                let mut entries: StdVec<(String, WireVal)> = StdVec::with_capacity(count);
                for _ in 0..count {
                    let k = match self.read_scval()? {
                        WireVal::Symbol(s) => s,
                        _ => return Err("payload_schema_mismatch"),
                    };
                    if let Some((prev, _)) = entries.last() {
                        if k.as_bytes() <= prev.as_bytes() {
                            return Err("non_canonical_map_order");
                        }
                    }
                    let v = self.read_scval()?;
                    entries.push((k, v));
                }
                Ok(WireVal::Map(entries))
            }
            18 => {
                let addr_kind = self.read_u32()?;
                match addr_kind {
                    0 => {
                        let pk_type = self.read_u32()?;
                        if pk_type != 0 {
                            return Err("malformed_xdr");
                        }
                        Ok(WireVal::AddressEd25519(self.read_fixed32()?))
                    }
                    1 => Ok(WireVal::AddressContract(self.read_fixed32()?)),
                    _ => Err("malformed_xdr"),
                }
            }
            _ => Err("malformed_xdr"),
        }
    }
}

fn decode_exact_scval(hex: &str) -> Result<WireVal, &'static str> {
    let raw = hex_decode(hex)?;
    let mut r = XdrReader::new(&raw);
    let val = r.read_scval()?;
    if r.pos != raw.len() {
        return Err("trailing_xdr_bytes");
    }
    Ok(val)
}

struct EventSpec {
    name: &'static str,
    prefix: &'static [&'static str],
    topic_types: &'static [&'static str],
    required_fields: &'static [(&'static str, &'static str)],
    optional_fields: &'static [(&'static str, &'static str)],
}

const EVENT_SPECS: &[EventSpec] = &[
    EventSpec {
        name: "CredentialRootAdded",
        prefix: &["credroot", "add"],
        topic_types: &["symbol", "symbol", "bytes32"],
        required_fields: &[("issued_at", "u64"), ("metadata_hash", "bytes32")],
        optional_fields: &[],
    },
    EventSpec {
        name: "CredentialRootRevoked",
        prefix: &["credroot", "revoke"],
        topic_types: &["symbol", "symbol", "bytes32"],
        required_fields: &[],
        optional_fields: &[],
    },
    EventSpec {
        name: "IssuerAdded",
        prefix: &["issuer", "add"],
        topic_types: &["symbol", "symbol", "address_ed25519"],
        required_fields: &[("metadata_hash", "bytes32")],
        optional_fields: &[],
    },
    EventSpec {
        name: "IssuerRevoked",
        prefix: &["issuer", "revoke"],
        topic_types: &["symbol", "symbol", "address_ed25519"],
        required_fields: &[],
        optional_fields: &[],
    },
    EventSpec {
        name: "ProofRegistered",
        prefix: &["proof", "reg"],
        topic_types: &["symbol", "symbol", "bytes32"],
        required_fields: &[
            ("batch_size", "u32"),
            ("status", "u32"),
            ("tier", "u32"),
            ("video_hash", "bytes32"),
        ],
        optional_fields: &[],
    },
    EventSpec {
        name: "ProofHistoryEvent",
        prefix: &["proof", "history"],
        topic_types: &["symbol", "symbol", "bytes32"],
        required_fields: &[
            ("action", "u32"),
            ("reason_code", "u32"),
            ("timestamp", "u64"),
        ],
        optional_fields: &[("actor", "address_ed25519")],
    },
    EventSpec {
        name: "ProofRevoked",
        prefix: &["proof", "revoke"],
        topic_types: &["symbol", "symbol", "bytes32"],
        required_fields: &[("status", "u32")],
        optional_fields: &[],
    },
    EventSpec {
        name: "MetadataEnvelopeBound",
        prefix: &["metadata", "envelope", "bound"],
        topic_types: &["symbol", "symbol", "symbol", "bytes32"],
        required_fields: &[
            ("bound_at", "u64"),
            ("metadata_hash", "bytes32"),
            ("version", "u32"),
        ],
        optional_fields: &[],
    },
    EventSpec {
        name: "MetadataEnvelopeUpgraded",
        prefix: &["metadata", "envelope", "upgraded"],
        topic_types: &["symbol", "symbol", "symbol", "bytes32"],
        required_fields: &[
            ("current", "u32"),
            ("metadata_hash", "bytes32"),
            ("previous", "u32"),
        ],
        optional_fields: &[],
    },
    EventSpec {
        name: "TimestampClaimAnchored",
        prefix: &["timestamp", "anchor"],
        topic_types: &["symbol", "symbol", "bytes32"],
        required_fields: &[
            ("anchored_at", "u64"),
            ("assurance", "u32"),
            ("attestation_digest", "bytes32"),
            ("ledger_sequence", "u32"),
            ("sources", "u32"),
        ],
        optional_fields: &[],
    },
    EventSpec {
        name: "LineageRegistered",
        prefix: &["lineage", "reg"],
        topic_types: &["symbol", "symbol", "bytes32"],
        required_fields: &[
            ("actor", "address_ed25519"),
            ("depth", "u32"),
            ("manifest_digest", "bytes32"),
            ("operation_type", "symbol"),
            ("parent_commitments", "vec"),
        ],
        optional_fields: &[],
    },
    EventSpec {
        name: "DisputeOpened",
        prefix: &["dispute", "open"],
        topic_types: &["symbol", "symbol", "bytes32", "bytes32"],
        required_fields: &[
            ("commitment_hash", "bytes32"),
            ("reason", "u32"),
            ("reporter_hash", "bytes32"),
            ("respond_deadline", "u64"),
        ],
        optional_fields: &[],
    },
    EventSpec {
        name: "DisputeResponded",
        prefix: &["dispute", "respond"],
        topic_types: &["symbol", "symbol", "bytes32", "bytes32"],
        required_fields: &[
            ("resolve_deadline", "u64"),
            ("response_commitment", "bytes32"),
        ],
        optional_fields: &[],
    },
    EventSpec {
        name: "DisputeResolved",
        prefix: &["dispute", "resolve"],
        topic_types: &["symbol", "symbol", "bytes32", "bytes32"],
        required_fields: &[("resolved_at", "u64")],
        optional_fields: &[],
    },
    EventSpec {
        name: "DisputeDismissed",
        prefix: &["dispute", "dismiss"],
        topic_types: &["symbol", "symbol", "bytes32", "bytes32"],
        required_fields: &[("resolved_at", "u64")],
        optional_fields: &[],
    },
    EventSpec {
        name: "DisputeSuperseded",
        prefix: &["dispute", "supersede"],
        topic_types: &["symbol", "symbol", "bytes32", "bytes32"],
        required_fields: &[("resolved_at", "u64"), ("superseded_by", "bytes32")],
        optional_fields: &[],
    },
    EventSpec {
        name: "SourceBatchRootRegistered",
        prefix: &["batch", "root"],
        topic_types: &["symbol", "symbol", "bytes32", "address_ed25519"],
        required_fields: &[
            ("count", "u32"),
            ("metadata_hash", "bytes32"),
            ("registered_at", "u64"),
        ],
        optional_fields: &[],
    },
    EventSpec {
        name: "SchemaAdded",
        prefix: &["schema", "add"],
        topic_types: &["symbol", "symbol", "bytes32"],
        required_fields: &[
            ("attribute_count", "u32"),
            ("issuer_namespace", "bytes32"),
            ("version", "u32"),
        ],
        optional_fields: &[],
    },
    EventSpec {
        name: "SchemaDeprecated",
        prefix: &["schema", "deprecate"],
        topic_types: &["symbol", "symbol", "bytes32"],
        required_fields: &[],
        optional_fields: &[],
    },
    EventSpec {
        name: "SchemaReactivated",
        prefix: &["schema", "reactivate"],
        topic_types: &["symbol", "symbol", "bytes32"],
        required_fields: &[],
        optional_fields: &[],
    },
    EventSpec {
        name: "RevocationRootSet",
        prefix: &["revroot", "set"],
        topic_types: &["symbol", "symbol", "bytes32"],
        required_fields: &[],
        optional_fields: &[],
    },
];

fn classify_wire_event(
    topics_xdr_hex: &str,
    data_xdr_hex: &str,
) -> Result<(&'static str, String, String), &'static str> {
    let topics_val = decode_exact_scval(topics_xdr_hex)?;
    let data_val = decode_exact_scval(data_xdr_hex)?;

    let topics = match topics_val {
        WireVal::Vec(v) => v,
        _ => return Err("malformed_xdr"),
    };
    if topics.len() < 2 {
        return Err("topic_arity_mismatch");
    }

    let mut matched_spec: Option<&EventSpec> = None;
    for spec in EVENT_SPECS {
        let p_len = spec.prefix.len();
        if topics.len() >= p_len {
            let mut ok = true;
            for (idx, expected_sym) in spec.prefix.iter().enumerate() {
                match &topics[idx] {
                    WireVal::Symbol(s) if s == expected_sym => {}
                    _ => {
                        ok = false;
                        break;
                    }
                }
            }
            if ok {
                matched_spec = Some(spec);
                break;
            }
        }
    }

    let spec = matched_spec.ok_or("unknown_event_topic")?;
    if topics.len() != spec.topic_types.len() {
        return Err("topic_arity_mismatch");
    }
    for (topic, expected_ty) in topics.iter().zip(spec.topic_types.iter()) {
        if topic.type_tag().as_str() != *expected_ty {
            return Err("topic_type_mismatch");
        }
    }

    let entries = match &data_val {
        WireVal::Map(m) => m,
        _ => return Err("payload_schema_mismatch"),
    };

    for (req_key, req_ty) in spec.required_fields {
        let found = entries.iter().find(|(k, _)| k == req_key);
        match found {
            Some((_, v)) if v.type_tag().as_str() == *req_ty => {}
            _ => return Err("payload_schema_mismatch"),
        }
    }
    for (k, v) in entries {
        let allowed = spec
            .required_fields
            .iter()
            .chain(spec.optional_fields.iter())
            .find(|(ak, _)| ak == k);
        match allowed {
            Some((_, expected_ty)) if v.type_tag().as_str() == *expected_ty => {}
            _ => return Err("payload_schema_mismatch"),
        }
    }

    let topics_parts: StdVec<String> = topics.iter().map(WireVal::canonical).collect();
    Ok((spec.name, topics_parts.join("|"), data_val.canonical()))
}

fn account_address(env: &Env, fill: u8) -> Address {
    let sc_addr = ScAddress::Account(AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(
        [fill; 32],
    ))));
    let val = Val::try_from_val(env, &ScVal::Address(sc_addr)).expect("valid ScAddress");
    Address::try_from_val(env, &val).expect("valid Address")
}

fn b32(env: &Env, fill: u8) -> BytesN<32> {
    BytesN::from_array(env, &[fill; 32])
}

#[derive(Clone, Debug)]
struct LiveCapture {
    id: &'static str,
    event_name: &'static str,
    entrypoint: &'static str,
    topics_xdr_hex: String,
    data_xdr_hex: String,
}

fn capture_event(
    id: &'static str,
    event_name: &'static str,
    entrypoint: &'static str,
    ev: &soroban_sdk::xdr::ContractEvent,
) -> LiveCapture {
    let ContractEventBody::V0(v0) = &ev.body;
    let topics_vec = ScVal::Vec(Some(ScVec(v0.topics.clone())));
    let topics_xdr = WriteXdr::to_xdr(&topics_vec, Limits::none()).expect("topics XDR");
    let data_xdr = WriteXdr::to_xdr(&v0.data, Limits::none()).expect("data XDR");
    LiveCapture {
        id,
        event_name,
        entrypoint,
        topics_xdr_hex: hex_encode(&topics_xdr),
        data_xdr_hex: hex_encode(&data_xdr),
    }
}

fn build_live_transitions() -> StdVec<LiveCapture> {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    let admin = account_address(&env, 0xA1);
    let source = account_address(&env, 0xB2);
    let issuer = account_address(&env, 0xC3);
    let reporter = account_address(&env, 0xD4);

    env.ledger().set_timestamp(1_700_000_000);
    env.ledger().set_sequence_number(100);
    client.init(&admin);

    let mut out = StdVec::new();

    let cred_root = b32(&env, 0x11);
    client.add_credential_root(&admin, &cred_root, &b32(&env, 0x12));
    let evs = env.events().all();
    out.push(capture_event(
        "ev-001-credroot-added",
        "CredentialRootAdded",
        "add_credential_root",
        &evs.events()[0],
    ));

    client.add_issuer(&admin, &issuer, &b32(&env, 0x13));
    let evs = env.events().all();
    out.push(capture_event(
        "ev-002-issuer-added",
        "IssuerAdded",
        "add_issuer",
        &evs.events()[0],
    ));

    env.ledger().set_timestamp(1_700_000_100);
    let proof_t1 = b32(&env, 0x21);
    client.register_anonymous(
        &b32(&env, 0x22),
        &b32(&env, 0x23),
        &proof_t1,
        &b32(&env, 0x24),
        &cred_root,
        &Bytes::from_array(&env, &[0xDE, 0xAD, 0xBE, 0xEF]),
    );
    let evs = env.events().all();
    assert_eq!(evs.events().len(), 3);
    out.push(capture_event(
        "ev-003-tier1-proof-registered",
        "ProofRegistered",
        "register_anonymous",
        &evs.events()[0],
    ));
    out.push(capture_event(
        "ev-004-tier1-history-registered-anon",
        "ProofHistoryEvent",
        "register_anonymous",
        &evs.events()[1],
    ));
    out.push(capture_event(
        "ev-005-tier1-metadata-bound-v1",
        "MetadataEnvelopeBound",
        "register_anonymous",
        &evs.events()[2],
    ));

    env.ledger().set_timestamp(1_700_000_200);
    let proof_t2 = b32(&env, 0x31);
    let meta_t2 = b32(&env, 0x33);
    client.register_source(&source, &b32(&env, 0x32), &meta_t2, &proof_t2);
    let evs = env.events().all();
    assert_eq!(evs.events().len(), 3);
    out.push(capture_event(
        "ev-006-tier2-proof-registered",
        "ProofRegistered",
        "register_source",
        &evs.events()[0],
    ));
    out.push(capture_event(
        "ev-007-tier2-history-registered-source",
        "ProofHistoryEvent",
        "register_source",
        &evs.events()[1],
    ));

    env.ledger().set_timestamp(1_700_000_300);
    let proof_t3 = b32(&env, 0x41);
    client.register_seal(&issuer, &b32(&env, 0x42), &b32(&env, 0x43), &proof_t3);
    let evs = env.events().all();
    out.push(capture_event(
        "ev-008-tier3-proof-registered",
        "ProofRegistered",
        "register_seal",
        &evs.events()[0],
    ));

    env.ledger().set_timestamp(1_700_000_400);
    client.verify_proof(&admin, &proof_t2, &7);
    let evs = env.events().all();
    out.push(capture_event(
        "ev-009-history-verified",
        "ProofHistoryEvent",
        "verify_proof",
        &evs.events()[0],
    ));

    env.ledger().set_timestamp(1_700_000_500);
    client.bind_metadata_envelope(&source, &proof_t2, &2, &meta_t2);
    let evs = env.events().all();
    out.push(capture_event(
        "ev-010-metadata-envelope-upgraded-v2",
        "MetadataEnvelopeUpgraded",
        "bind_metadata_envelope",
        &evs.events()[0],
    ));

    env.ledger().set_timestamp(1_700_000_600);
    client.correct_proof(&admin, &proof_t2, &b32(&env, 0x34), &12);
    let evs = env.events().all();
    out.push(capture_event(
        "ev-011-history-corrected",
        "ProofHistoryEvent",
        "correct_proof",
        &evs.events()[0],
    ));

    env.ledger().set_timestamp(1_700_000_700);
    env.ledger().set_sequence_number(250);
    client.anchor_timestamp_claim(
        &source,
        &proof_t2,
        &b32(&env, 0x51),
        &1_700_000_690,
        &b32(&env, 0x52),
    );
    let evs = env.events().all();
    out.push(capture_event(
        "ev-012-timestamp-claim-anchored",
        "TimestampClaimAnchored",
        "anchor_timestamp_claim",
        &evs.events()[0],
    ));

    env.ledger().set_timestamp(1_700_000_800);
    let mut parents = soroban_sdk::Vec::new(&env);
    parents.push_back(proof_t2.clone());
    client.register_lineage(
        &source,
        &parents,
        &b32(&env, 0x61),
        &Symbol::new(&env, "trim"),
        &b32(&env, 0x62),
        &1,
    );
    let evs = env.events().all();
    out.push(capture_event(
        "ev-013-lineage-registered",
        "LineageRegistered",
        "register_lineage",
        &evs.events()[0],
    ));

    env.ledger().set_timestamp(1_700_000_900);
    let dispute_resolve_id = b32(&env, 0x71);
    client.open_dispute(
        &reporter,
        &b32(&env, 0x72),
        &dispute_resolve_id,
        &proof_t2,
        &DisputeReason::MetadataError,
        &b32(&env, 0x73),
    );
    let evs = env.events().all();
    out.push(capture_event(
        "ev-014-dispute-opened",
        "DisputeOpened",
        "open_dispute",
        &evs.events()[0],
    ));

    env.ledger().set_timestamp(1_700_001_000);
    client.respond_dispute(&source, &dispute_resolve_id, &b32(&env, 0x74));
    let evs = env.events().all();
    out.push(capture_event(
        "ev-015-dispute-responded",
        "DisputeResponded",
        "respond_dispute",
        &evs.events()[0],
    ));

    env.ledger().set_timestamp(1_700_001_100);
    client.resolve_dispute(&admin, &dispute_resolve_id);
    let evs = env.events().all();
    out.push(capture_event(
        "ev-016-dispute-resolved",
        "DisputeResolved",
        "resolve_dispute",
        &evs.events()[0],
    ));

    env.ledger().set_timestamp(1_700_100_000);
    let dispute_dismiss_id = b32(&env, 0x75);
    client.open_dispute(
        &reporter,
        &b32(&env, 0x76),
        &dispute_dismiss_id,
        &proof_t2,
        &DisputeReason::ContentError,
        &b32(&env, 0x77),
    );
    env.ledger().set_timestamp(1_700_100_100);
    client.dismiss_dispute(&admin, &dispute_dismiss_id);
    let evs = env.events().all();
    out.push(capture_event(
        "ev-017-dispute-dismissed",
        "DisputeDismissed",
        "dismiss_dispute",
        &evs.events()[0],
    ));

    env.ledger().set_timestamp(1_700_200_000);
    let dispute_sup_id = b32(&env, 0x78);
    client.open_dispute(
        &reporter,
        &b32(&env, 0x79),
        &dispute_sup_id,
        &proof_t2,
        &DisputeReason::Other,
        &b32(&env, 0x7A),
    );
    env.ledger().set_timestamp(1_700_200_100);
    client.supersede_dispute(&admin, &dispute_sup_id, &proof_t3);
    let evs = env.events().all();
    out.push(capture_event(
        "ev-018-dispute-superseded",
        "DisputeSuperseded",
        "supersede_dispute",
        &evs.events()[0],
    ));

    env.ledger().set_timestamp(1_700_200_200);
    client.expire_proof(&admin, &proof_t1, &9);
    let evs = env.events().all();
    out.push(capture_event(
        "ev-019-history-expired",
        "ProofHistoryEvent",
        "expire_proof",
        &evs.events()[0],
    ));

    env.ledger().set_timestamp(1_700_200_300);
    client.revoke_proof(&admin, &proof_t3);
    let evs = env.events().all();
    assert_eq!(evs.events().len(), 2);
    out.push(capture_event(
        "ev-020-proof-revoked",
        "ProofRevoked",
        "revoke_proof",
        &evs.events()[0],
    ));
    out.push(capture_event(
        "ev-021-history-revoked",
        "ProofHistoryEvent",
        "revoke_proof",
        &evs.events()[1],
    ));

    env.ledger().set_timestamp(1_700_200_400);
    client.register_source_batch_root(&source, &b32(&env, 0x81), &4, &b32(&env, 0x82));
    let evs = env.events().all();
    out.push(capture_event(
        "ev-022-source-batch-root-registered",
        "SourceBatchRootRegistered",
        "register_source_batch_root",
        &evs.events()[0],
    ));

    env.ledger().set_timestamp(1_700_200_500);
    let schema_hash = b32(&env, 0x91);
    client.add_schema(&admin, &schema_hash, &b32(&env, 0x92), &1, &3);
    let evs = env.events().all();
    out.push(capture_event(
        "ev-023-schema-added",
        "SchemaAdded",
        "add_schema",
        &evs.events()[0],
    ));

    env.ledger().set_timestamp(1_700_200_600);
    client.deprecate_schema(&admin, &schema_hash);
    let evs = env.events().all();
    out.push(capture_event(
        "ev-024-schema-deprecated",
        "SchemaDeprecated",
        "deprecate_schema",
        &evs.events()[0],
    ));

    env.ledger().set_timestamp(1_700_200_700);
    client.reactivate_schema(&admin, &schema_hash);
    let evs = env.events().all();
    out.push(capture_event(
        "ev-025-schema-reactivated",
        "SchemaReactivated",
        "reactivate_schema",
        &evs.events()[0],
    ));

    env.ledger().set_timestamp(1_700_200_800);
    client.set_revocation_root(&admin, &b32(&env, 0x95));
    let evs = env.events().all();
    out.push(capture_event(
        "ev-026-revocation-root-set",
        "RevocationRootSet",
        "set_revocation_root",
        &evs.events()[0],
    ));

    env.ledger().set_timestamp(1_700_200_900);
    client.revoke_credential_root(&admin, &cred_root);
    let evs = env.events().all();
    out.push(capture_event(
        "ev-027-credroot-revoked",
        "CredentialRootRevoked",
        "revoke_credential_root",
        &evs.events()[0],
    ));

    env.ledger().set_timestamp(1_700_201_000);
    client.revoke_issuer(&admin, &issuer);
    let evs = env.events().all();
    out.push(capture_event(
        "ev-028-issuer-revoked",
        "IssuerRevoked",
        "revoke_issuer",
        &evs.events()[0],
    ));

    out
}

#[test]
fn corpus_is_versioned_and_non_empty() {
    assert!(CORPUS_JSON.contains("\"format\": \"harpocrates.lifecycle-events\""));
    assert!(CORPUS_JSON.contains("\"version\": 1"));
    assert!(CORPUS_JSON.contains("\"codec\": \"hpx-ev/1\""));

    let cases = parse_corpus_cases(CORPUS_JSON);
    let pos_count = cases.iter().filter(|c| c.accept).count();
    let neg_count = cases.iter().filter(|c| !c.accept).count();
    assert_eq!(pos_count, 28);
    assert_eq!(neg_count, 8);
}

#[test]
fn live_contract_transitions_match_published_corpus_byte_for_byte() {
    let cases = parse_corpus_cases(CORPUS_JSON);
    let positive: StdVec<&CorpusCase> = cases.iter().filter(|c| c.accept).collect();
    let live = build_live_transitions();
    assert_eq!(live.len(), positive.len());

    for (actual, expected) in live.iter().zip(positive.iter()) {
        assert_eq!(actual.id, expected.id);
        assert_eq!(
            actual.event_name, expected.event_name,
            "case {}",
            expected.id
        );
        assert_eq!(
            actual.entrypoint, expected.entrypoint,
            "case {}",
            expected.id
        );
        assert_eq!(
            actual.topics_xdr_hex, expected.topics_xdr_hex,
            "topics XDR drifted for case {}",
            expected.id
        );
        assert_eq!(
            actual.data_xdr_hex, expected.data_xdr_hex,
            "data XDR drifted for case {}",
            expected.id
        );
    }
}

#[test]
fn wire_classifier_and_stellar_xdr_agree_across_all_corpus_cases() {
    let cases = parse_corpus_cases(CORPUS_JSON);
    assert_eq!(cases.len(), 36);

    for case in &cases {
        let verdict = classify_wire_event(&case.topics_xdr_hex, &case.data_xdr_hex);
        if case.accept {
            let (ev_name, topics_canon, payload_canon) =
                verdict.unwrap_or_else(|e| panic!("positive case {} rejected with {}", case.id, e));
            assert_eq!(ev_name, case.event_name, "case {}", case.id);
            assert_eq!(topics_canon, case.topics_canonical, "case {}", case.id);
            assert_eq!(payload_canon, case.payload_canonical, "case {}", case.id);

            // Cross-check round-trip canonicality with stellar_xdr::ScVal.
            let t_bytes = hex_decode(&case.topics_xdr_hex).unwrap();
            let d_bytes = hex_decode(&case.data_xdr_hex).unwrap();
            let t_scv = <ScVal as ReadXdr>::from_xdr(&t_bytes, Limits::none())
                .unwrap_or_else(|_| panic!("stellar_xdr failed topics on {}", case.id));
            let d_scv = <ScVal as ReadXdr>::from_xdr(&d_bytes, Limits::none())
                .unwrap_or_else(|_| panic!("stellar_xdr failed data on {}", case.id));
            assert_eq!(WriteXdr::to_xdr(&t_scv, Limits::none()).unwrap(), t_bytes);
            assert_eq!(WriteXdr::to_xdr(&d_scv, Limits::none()).unwrap(), d_bytes);
        } else {
            let expected_err = case
                .reject_code
                .as_deref()
                .expect("negative case must declare reject_code");
            assert_eq!(
                verdict,
                Err(expected_err),
                "negative case {} mismatch",
                case.id
            );
        }
    }
}
