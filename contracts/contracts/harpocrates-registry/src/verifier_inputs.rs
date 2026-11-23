//! Canonical verifier-input codecs for Harpocrates (`hpx-vi/1` and `hpx-vi/2`).
//!
//! `hpx-vi/1` covers `silent_witness/v1` and `revocation_witness/v1`.
//! `hpx-vi/2` covers `silent_witness/v2`, which appends the circuit version as a
//! trailing field so the wire format commits to the exact circuit that produced
//! the proof.
//!
//! Soroban/Rust side of a three-way codec that must agree byte for byte with:
//!
//! - `backend/verifier_inputs.py` (Python)
//! - `frontend/src/verifierInputs.ts` (browser / TypeScript)
//!
//! Agreement is enforced by the shared corpora in
//! `zk/vectors/verifier_conformance_v1.json` and
//! `zk/vectors/verifier_conformance_v2.json`; see
//! `docs/zk-conformance-vectors.md`.
//!
//! The module is deliberately `no_std`, allocation-free, and independent of the
//! Soroban SDK: it operates on fixed-size byte slices so the same code can be
//! exercised by host-side tests and by the contract itself. All work is O(1) in
//! the size of a frame, so a hostile caller cannot drive cost through it.

/// Codec identifier carried in signals and documentation.
pub const CODEC_ID: &str = "hpx-vi/1";

/// Codec identifier for the circuit-versioned silent-witness envelope.
pub const CODEC_ID_V2: &str = "hpx-vi/2";

/// Numeric verifier-input codec versions corresponding to `hpx-vi/1` and `hpx-vi/2`.
pub const VERIFIER_INPUT_VERSION_V1: u32 = 1;
pub const VERIFIER_INPUT_VERSION_V2: u32 = 2;
pub const MIN_VERIFIER_INPUT_VERSION: u32 = VERIFIER_INPUT_VERSION_V1;
pub const MAX_VERIFIER_INPUT_VERSION: u32 = VERIFIER_INPUT_VERSION_V2;

/// Version of the bounded proof statement compatibility descriptor format.
pub const COMPATIBILITY_DESCRIPTOR_VERSION: u32 = 1;

/// Hard upper bound on the number of schema entries in a compatibility descriptor.
pub const MAX_COMPATIBILITY_SCHEMAS: usize = 8;

/// Bitmask of critical proof-statement fields understood by the canonical codec.
///
/// Any bit outside a schema's supported mask (including future/unknown bits)
/// must fail closed with [`RejectCode::UnsupportedCriticalField`].
pub const CRITICAL_FIELD_VIDEO_HASH: u32 = 1 << 0;
pub const CRITICAL_FIELD_CREDENTIAL_ROOT: u32 = 1 << 1;
pub const CRITICAL_FIELD_NULLIFIER: u32 = 1 << 2;
pub const CRITICAL_FIELD_DOMAIN_TAG: u32 = 1 << 3;
pub const CRITICAL_FIELD_VERIFIER_SCOPE: u32 = 1 << 4;
pub const CRITICAL_FIELD_EPOCH: u32 = 1 << 5;
pub const CRITICAL_FIELD_CIRCUIT_VERSION: u32 = 1 << 6;
pub const CRITICAL_FIELD_REVOCATION_ROOT: u32 = 1 << 7;

/// Critical fields supported by `silent_witness/v1` (`hpx-vi/1`).
pub const CRITICAL_FIELDS_SILENT_WITNESS_V1: u32 = CRITICAL_FIELD_VIDEO_HASH
    | CRITICAL_FIELD_CREDENTIAL_ROOT
    | CRITICAL_FIELD_NULLIFIER
    | CRITICAL_FIELD_DOMAIN_TAG;

/// Critical fields supported by `revocation_witness/v1` (`hpx-vi/1`).
pub const CRITICAL_FIELDS_REVOCATION_WITNESS_V1: u32 = CRITICAL_FIELD_REVOCATION_ROOT
    | CRITICAL_FIELD_NULLIFIER
    | CRITICAL_FIELD_DOMAIN_TAG
    | CRITICAL_FIELD_CREDENTIAL_ROOT;

/// Critical fields supported by `silent_witness/v2` (`hpx-vi/2`).
pub const CRITICAL_FIELDS_SILENT_WITNESS_V2: u32 = CRITICAL_FIELDS_SILENT_WITNESS_V1
    | CRITICAL_FIELD_VERIFIER_SCOPE
    | CRITICAL_FIELD_EPOCH
    | CRITICAL_FIELD_CIRCUIT_VERSION;

/// Union of all critical fields supported by this codec build.
pub const CRITICAL_FIELDS_ALL_SUPPORTED: u32 =
    CRITICAL_FIELDS_SILENT_WITNESS_V2 | CRITICAL_FIELDS_REVOCATION_WITNESS_V1;

pub const FIELD_LEN: usize = 32;
pub const SILENT_WITNESS_FIELD_COUNT: usize = 5;
pub const SILENT_WITNESS_BROWSER_FIELD_COUNT: usize = 4;
pub const REVOCATION_FIELD_COUNT: usize = 4;
pub const PUBLIC_INPUTS_LEN: usize = FIELD_LEN * SILENT_WITNESS_FIELD_COUNT; // 160
pub const SILENT_WITNESS_PUBLIC_INPUTS_LEN: usize = 160;
pub const SILENT_WITNESS_BROWSER_PUBLIC_INPUTS_LEN: usize =
    FIELD_LEN * SILENT_WITNESS_BROWSER_FIELD_COUNT; // 128
pub const REVOCATION_PUBLIC_INPUTS_LEN: usize = 128;

/// `silent_witness/v2` is the scoped frame (7 fields) plus a trailing 8th field
/// that commits the circuit version (#368).
pub const SILENT_WITNESS_V2_FIELD_COUNT: usize = 8;
pub const SILENT_WITNESS_V2_PUBLIC_INPUTS_LEN: usize = FIELD_LEN * SILENT_WITNESS_V2_FIELD_COUNT; // 256

/// The only circuit version accepted by the `silent_witness/v2` codec. Must
/// match `CURRENT_CIRCUIT_VERSION` in `zk/noir/silent_witness/src/main.nr`.
pub const EXPECTED_CIRCUIT_VERSION: u32 = 2;

/// Accepted proof-blob size window. Matches the Python and TypeScript layers.
pub const MIN_PROOF_BYTES: u32 = 64;
pub const MAX_PROOF_BYTES: u32 = 65_536;

/// BN254 scalar field modulus, big-endian. A 32-byte encoding is canonical only
/// when the value it denotes is strictly below this.
pub const BN254_SCALAR_FIELD_MODULUS_BE: [u8; FIELD_LEN] = [
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
    0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91, 0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00, 0x00, 0x01,
];

/// Expected Silent Witness domain tag SHA-256 digest.
pub const SILENT_WITNESS_DOMAIN_TAG_BE: [u8; FIELD_LEN] = [
    0x4a, 0xa0, 0x38, 0xf0, 0xa2, 0x7b, 0x66, 0x75, 0xd7, 0x12, 0x2a, 0xe2, 0xd4, 0xe1, 0x97, 0xc2,
    0x1e, 0x83, 0xfb, 0xe3, 0x01, 0x43, 0xa5, 0xc8, 0x3f, 0xf3, 0x5c, 0x95, 0x14, 0xb9, 0x2c, 0x55,
];

/// Stable rejection codes shared across circuit, backend, browser, and chain.
///
/// The string form is the wire identity used by the conformance corpus; the
/// discriminants are stable and may only be appended to.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RejectCode {
    MalformedHex,
    Length,
    Padding,
    NonCanonicalField,
    ZeroField,
    DomainMismatch,
    ProofUndersize,
    ProofOversize,
    UnknownSchema,
    /// The envelope's declared circuit version is not the one this codec
    /// accepts (`hpx-vi/2` cases only).
    VersionMismatch,
    /// A requested proof statement requires a critical field not supported by
    /// the selected schema or this codec build (fail-closed).
    UnsupportedCriticalField,
}

/// Numeric result meaning "the material was accepted", returned by the
/// on-chain `classify_public_inputs` entry point.
pub const ACCEPTED_CODE: u32 = 0;

impl RejectCode {
    /// Stable numeric identity, used where a `&'static str` cannot cross the
    /// Soroban host boundary. Values are append-only.
    pub const fn as_code(self) -> u32 {
        match self {
            RejectCode::MalformedHex => 1,
            RejectCode::Length => 2,
            RejectCode::Padding => 3,
            RejectCode::NonCanonicalField => 4,
            RejectCode::ZeroField => 5,
            RejectCode::DomainMismatch => 6,
            RejectCode::ProofUndersize => 7,
            RejectCode::ProofOversize => 8,
            RejectCode::UnknownSchema => 9,
            RejectCode::VersionMismatch => 10,
            RejectCode::UnsupportedCriticalField => 11,
        }
    }

    /// Resolve a wire identity from the conformance corpus. Returns `None` for
    /// unrecognised codes so an out-of-date runner fails loudly.
    pub fn from_wire(value: &str) -> Option<RejectCode> {
        match value {
            "malformed_hex" => Some(RejectCode::MalformedHex),
            "length" => Some(RejectCode::Length),
            "padding" => Some(RejectCode::Padding),
            "non_canonical_field" => Some(RejectCode::NonCanonicalField),
            "zero_field" => Some(RejectCode::ZeroField),
            "domain_mismatch" => Some(RejectCode::DomainMismatch),
            "proof_undersize" => Some(RejectCode::ProofUndersize),
            "proof_oversize" => Some(RejectCode::ProofOversize),
            "unknown_schema" => Some(RejectCode::UnknownSchema),
            "version_mismatch" => Some(RejectCode::VersionMismatch),
            "unsupported_critical_field" => Some(RejectCode::UnsupportedCriticalField),
            _ => None,
        }
    }

    /// Wire identity of this code, as it appears in the conformance corpus.
    pub const fn as_str(self) -> &'static str {
        match self {
            RejectCode::MalformedHex => "malformed_hex",
            RejectCode::Length => "length",
            RejectCode::Padding => "padding",
            RejectCode::NonCanonicalField => "non_canonical_field",
            RejectCode::ZeroField => "zero_field",
            RejectCode::DomainMismatch => "domain_mismatch",
            RejectCode::ProofUndersize => "proof_undersize",
            RejectCode::ProofOversize => "proof_oversize",
            RejectCode::UnknownSchema => "unknown_schema",
            RejectCode::VersionMismatch => "version_mismatch",
            RejectCode::UnsupportedCriticalField => "unsupported_critical_field",
        }
    }
}

pub const SCHEMA_SILENT_WITNESS: &str = "silent_witness/v1";
pub const SCHEMA_REVOCATION_WITNESS: &str = "revocation_witness/v1";
pub const SCHEMA_SILENT_WITNESS_V2: &str = "silent_witness/v2";

/// Parsed `silent_witness/v1` public inputs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SilentWitnessFields {
    pub video_hash: [u8; FIELD_LEN],
    pub credential_root: [u8; FIELD_LEN],
    pub nullifier: [u8; FIELD_LEN],
    pub domain_tag: [u8; FIELD_LEN],
    /// Circuit version the frame was produced by. `silent_witness/v1` frames
    /// carry `1` implicitly because the v1 layout predates the commitment.
    pub circuit_version: u32,
}

/// Parsed `silent_witness/v2` public inputs: the scoped frame with the circuit
/// version committed as its rightmost field (#368).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScopedSilentWitnessFields {
    pub video_hash: [u8; FIELD_LEN],
    pub credential_root: [u8; FIELD_LEN],
    pub nullifier: [u8; FIELD_LEN],
    pub verifier_scope: [u8; FIELD_LEN],
    /// Raw 32-byte epoch field element. The registry narrows it to a `u64`;
    /// the codec stays a pure byte-level boundary and never interprets it.
    pub epoch: [u8; FIELD_LEN],
    pub domain_tag: [u8; FIELD_LEN],
    pub circuit_version: u32,
}

/// Parsed `silent_witness` 4-field browser v1 public inputs (128 bytes).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BrowserSilentWitnessFields {
    pub video_hash: [u8; FIELD_LEN],
    pub credential_root: [u8; FIELD_LEN],
    pub nullifier: [u8; FIELD_LEN],
    pub circuit_version: u32,
}

/// Parsed `revocation_witness/v1` public inputs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RevocationFields {
    pub revocation_root: [u8; FIELD_LEN],
    pub nullifier: [u8; FIELD_LEN],
    pub domain_separator: [u8; FIELD_LEN],
    pub credential_root: [u8; FIELD_LEN],
}

#[inline]
fn field_at(frame: &[u8], index: usize) -> [u8; FIELD_LEN] {
    let mut out = [0u8; FIELD_LEN];
    out.copy_from_slice(&frame[index * FIELD_LEN..(index + 1) * FIELD_LEN]);
    out
}

/// Is this 32-byte big-endian encoding strictly below the BN254 modulus?
pub fn is_canonical_field(element: &[u8; FIELD_LEN]) -> bool {
    for index in 0..FIELD_LEN {
        if element[index] < BN254_SCALAR_FIELD_MODULUS_BE[index] {
            return true;
        }
        if element[index] > BN254_SCALAR_FIELD_MODULUS_BE[index] {
            return false;
        }
    }
    // Exactly equal to the modulus is not a canonical encoding.
    false
}

fn is_zero(element: &[u8; FIELD_LEN]) -> bool {
    let mut acc = 0u8;
    for byte in element.iter() {
        acc |= *byte;
    }
    acc == 0
}

/// A 128-bit half is carried in the low 16 bytes; the high 16 must be zero.
fn has_half_padding(element: &[u8; FIELD_LEN]) -> bool {
    let mut acc = 0u8;
    for byte in element.iter().take(16) {
        acc |= *byte;
    }
    acc == 0
}

/// Compare two byte slices without an early exit on the first difference.
///
/// Every byte is folded into one accumulator, so the work done does not depend
/// on where (or whether) the inputs diverge. Slices of different lengths
/// compare unequal; length is public. Mirrors `constant_time_equals` in
/// `backend/verifier_inputs.py` and `constantTimeEquals` in
/// `frontend/src/verifierInputs.ts`.
pub fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0u8;
    for (a, b) in left.iter().zip(right.iter()) {
        difference |= *a ^ *b;
    }
    // `black_box` stops the optimiser from turning the fold back into an
    // early-exit comparison.
    core::hint::black_box(difference) == 0
}

/// Enforce the accepted proof-blob size window.
pub fn check_proof_bounds(proof_len: u32) -> Result<(), RejectCode> {
    if proof_len < MIN_PROOF_BYTES {
        return Err(RejectCode::ProofUndersize);
    }
    if proof_len > MAX_PROOF_BYTES {
        return Err(RejectCode::ProofOversize);
    }
    Ok(())
}

/// Parse `silent_witness/v1` public inputs in canonical check order.
pub fn parse_silent_witness(
    frame: &[u8],
    expected_domain: &[u8; FIELD_LEN],
) -> Result<SilentWitnessFields, RejectCode> {
    if frame.len() != SILENT_WITNESS_PUBLIC_INPUTS_LEN {
        return Err(RejectCode::Length);
    }

    let fields = [
        field_at(frame, 0),
        field_at(frame, 1),
        field_at(frame, 2),
        field_at(frame, 3),
        field_at(frame, 4),
    ];

    if !has_half_padding(&fields[0]) || !has_half_padding(&fields[1]) {
        return Err(RejectCode::Padding);
    }

    // The domain tag is an opaque protocol binding; compare it byte-for-byte
    // below instead of treating arbitrary SHA-256 output as a BN254 scalar.
    for element in fields[..4].iter() {
        if !is_canonical_field(element) {
            return Err(RejectCode::NonCanonicalField);
        }
    }

    if is_zero(&fields[2]) || is_zero(&fields[3]) || is_zero(&fields[4]) {
        return Err(RejectCode::ZeroField);
    }

    if !constant_time_eq(&fields[4], expected_domain) {
        return Err(RejectCode::DomainMismatch);
    }

    let mut video_hash = [0u8; FIELD_LEN];
    video_hash[..16].copy_from_slice(&fields[0][16..]);
    video_hash[16..].copy_from_slice(&fields[1][16..]);

    Ok(SilentWitnessFields {
        video_hash,
        credential_root: fields[2],
        nullifier: fields[3],
        domain_tag: fields[4],
        circuit_version: 1,
    })
}

/// Decode the circuit version carried in a 32-byte field element: a `u32` in
/// the low 4 bytes with the upper 28 zero.
///
/// Public so the registry can validate an envelope trailer through this codec
/// instead of re-deriving the encoding a second time.
pub fn circuit_version_of(field: &[u8; FIELD_LEN]) -> u32 {
    let mut acc = 0u8;
    for byte in field.iter().take(FIELD_LEN - 4) {
        acc |= *byte;
    }
    if acc != 0 {
        return u32::MAX;
    }
    u32::from_be_bytes([field[28], field[29], field[30], field[31]])
}

/// Parse `silent_witness/v2` public inputs in canonical check order (#368).
///
/// Layout (8 x BN254 field elements, 32 bytes each):
///   [  0.. 32)  video_hash_hi  (128-bit half in the low 16 bytes)
///   [ 32.. 64)  video_hash_lo  (128-bit half in the low 16 bytes)
///   [ 64.. 96)  credential_root
///   [ 96..128)  nullifier
///   [128..160)  verifier_scope
///   [160..192)  epoch
///   [192..224)  domain_tag
///   [224..256)  circuit_version (u32 in the low 4 bytes)
///
/// Check order (documented in `docs/zk-conformance-vectors.md`):
/// length → half padding → circuit version → canonicity → zero identity →
/// domain → (proof bounds applied by the caller).
pub fn parse_silent_witness_v2(
    frame: &[u8],
    expected_domain: &[u8; FIELD_LEN],
) -> Result<ScopedSilentWitnessFields, RejectCode> {
    if frame.len() != SILENT_WITNESS_V2_PUBLIC_INPUTS_LEN {
        return Err(RejectCode::Length);
    }

    let fields = [
        field_at(frame, 0),
        field_at(frame, 1),
        field_at(frame, 2),
        field_at(frame, 3),
        field_at(frame, 4),
        field_at(frame, 5),
        field_at(frame, 6),
        field_at(frame, 7),
    ];

    if !has_half_padding(&fields[0]) || !has_half_padding(&fields[1]) {
        return Err(RejectCode::Padding);
    }

    // The committed version is checked before the identity fields so a frame
    // produced by another circuit is reported as a version problem, never as a
    // malformed-identity problem.
    if circuit_version_of(&fields[7]) != EXPECTED_CIRCUIT_VERSION {
        return Err(RejectCode::VersionMismatch);
    }

    // The domain tag is an opaque protocol binding; compare it byte-for-byte
    // below instead of treating arbitrary SHA-256 output as a BN254 scalar.
    for element in fields[..6].iter() {
        if !is_canonical_field(element) {
            return Err(RejectCode::NonCanonicalField);
        }
    }

    if is_zero(&fields[2]) || is_zero(&fields[3]) || is_zero(&fields[6]) {
        return Err(RejectCode::ZeroField);
    }

    if !constant_time_eq(&fields[6], expected_domain) {
        return Err(RejectCode::DomainMismatch);
    }

    let mut video_hash = [0u8; FIELD_LEN];
    video_hash[..16].copy_from_slice(&fields[0][16..]);
    video_hash[16..].copy_from_slice(&fields[1][16..]);

    Ok(ScopedSilentWitnessFields {
        video_hash,
        credential_root: fields[2],
        nullifier: fields[3],
        verifier_scope: fields[4],
        epoch: fields[5],
        domain_tag: fields[6],
        circuit_version: EXPECTED_CIRCUIT_VERSION,
    })
}

/// Parse the 128-byte browser `silent_witness` v1 public inputs in canonical
/// check order (`length` -> `padding` -> `non_canonical_field` -> `zero_field`).
pub fn parse_browser_silent_witness(
    frame: &[u8],
) -> Result<BrowserSilentWitnessFields, RejectCode> {
    if frame.len() != SILENT_WITNESS_BROWSER_PUBLIC_INPUTS_LEN {
        return Err(RejectCode::Length);
    }

    let fields = [
        field_at(frame, 0),
        field_at(frame, 1),
        field_at(frame, 2),
        field_at(frame, 3),
    ];

    if !has_half_padding(&fields[0]) || !has_half_padding(&fields[1]) {
        return Err(RejectCode::Padding);
    }

    for element in fields.iter() {
        if !is_canonical_field(element) {
            return Err(RejectCode::NonCanonicalField);
        }
    }

    if is_zero(&fields[2]) || is_zero(&fields[3]) {
        return Err(RejectCode::ZeroField);
    }

    let mut video_hash = [0u8; FIELD_LEN];
    video_hash[..16].copy_from_slice(&fields[0][16..]);
    video_hash[16..].copy_from_slice(&fields[1][16..]);

    Ok(BrowserSilentWitnessFields {
        video_hash,
        credential_root: fields[2],
        nullifier: fields[3],
        circuit_version: 1,
    })
}

/// Parse `revocation_witness/v1` public inputs in canonical check order.
///
/// `expected_domain` is supplied by the caller so the contract's single
/// `REVOCATION_DOMAIN_SEPARATOR` constant remains the one authority for the
/// domain value.
pub fn parse_revocation_witness(
    frame: &[u8],
    expected_domain: &[u8; FIELD_LEN],
) -> Result<RevocationFields, RejectCode> {
    if frame.len() != REVOCATION_PUBLIC_INPUTS_LEN {
        return Err(RejectCode::Length);
    }

    let fields = [
        field_at(frame, 0),
        field_at(frame, 1),
        field_at(frame, 2),
        field_at(frame, 3),
    ];

    for element in fields.iter() {
        if !is_canonical_field(element) {
            return Err(RejectCode::NonCanonicalField);
        }
    }

    if is_zero(&fields[0]) || is_zero(&fields[1]) || is_zero(&fields[3]) {
        return Err(RejectCode::ZeroField);
    }

    if !constant_time_eq(&fields[2], expected_domain) {
        return Err(RejectCode::DomainMismatch);
    }

    Ok(RevocationFields {
        revocation_root: fields[0],
        nullifier: fields[1],
        domain_separator: fields[2],
        credential_root: fields[3],
    })
}

/// Classify one conformance case from already-decoded bytes.
///
/// Returns `Ok(())` when the material is accepted. The check order — public
/// inputs first, then the proof blob — is part of the codec contract and is
/// mirrored by every layer.
pub fn classify(
    schema: &str,
    public_inputs: &[u8],
    proof_len: u32,
    expected_domain: &[u8; FIELD_LEN],
) -> Result<(), RejectCode> {
    // Schema dispatch precedes the length check, matching the Python and
    // TypeScript layers: an unrecognised schema is reported as such even when
    // the frame is also the wrong length.
    if schema != SCHEMA_SILENT_WITNESS
        && schema != SCHEMA_SILENT_WITNESS_V2
        && schema != SCHEMA_REVOCATION_WITNESS
    {
        return Err(RejectCode::UnknownSchema);
    }

    if schema == SCHEMA_SILENT_WITNESS {
        parse_silent_witness(public_inputs, expected_domain)?;
    } else if schema == SCHEMA_SILENT_WITNESS_V2 {
        parse_silent_witness_v2(public_inputs, expected_domain)?;
    } else {
        parse_revocation_witness(public_inputs, expected_domain)?;
    }

    check_proof_bounds(proof_len)
}

/// Bounded description of one accepted proof-statement schema.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SchemaCompatibilityEntry {
    pub schema_id: u32,
    pub schema_name: &'static str,
    pub codec_id: &'static str,
    pub verifier_input_version: u32,
    pub circuit_version: u32,
    pub public_inputs_len: u32,
    pub supported_critical_fields: u32,
}

/// Fixed-size, bounded table of all accepted proof-statement schemas.
pub const SUPPORTED_SCHEMAS: [SchemaCompatibilityEntry; 3] = [
    SchemaCompatibilityEntry {
        schema_id: 1,
        schema_name: SCHEMA_SILENT_WITNESS,
        codec_id: CODEC_ID,
        verifier_input_version: VERIFIER_INPUT_VERSION_V1,
        circuit_version: 1,
        public_inputs_len: SILENT_WITNESS_PUBLIC_INPUTS_LEN as u32,
        supported_critical_fields: CRITICAL_FIELDS_SILENT_WITNESS_V1,
    },
    SchemaCompatibilityEntry {
        schema_id: 2,
        schema_name: SCHEMA_REVOCATION_WITNESS,
        codec_id: CODEC_ID,
        verifier_input_version: VERIFIER_INPUT_VERSION_V1,
        circuit_version: 1,
        public_inputs_len: REVOCATION_PUBLIC_INPUTS_LEN as u32,
        supported_critical_fields: CRITICAL_FIELDS_REVOCATION_WITNESS_V1,
    },
    SchemaCompatibilityEntry {
        schema_id: 3,
        schema_name: SCHEMA_SILENT_WITNESS_V2,
        codec_id: CODEC_ID_V2,
        verifier_input_version: VERIFIER_INPUT_VERSION_V2,
        circuit_version: EXPECTED_CIRCUIT_VERSION,
        public_inputs_len: SILENT_WITNESS_V2_PUBLIC_INPUTS_LEN as u32,
        supported_critical_fields: CRITICAL_FIELDS_SILENT_WITNESS_V2,
    },
];

const _: () = assert!(
    SUPPORTED_SCHEMAS.len() <= MAX_COMPATIBILITY_SCHEMAS,
    "SUPPORTED_SCHEMAS must stay within MAX_COMPATIBILITY_SCHEMAS"
);

/// Look up a supported schema entry by its numeric selector.
pub fn schema_entry_by_id(schema_id: u32) -> Option<&'static SchemaCompatibilityEntry> {
    let mut i = 0;
    while i < SUPPORTED_SCHEMAS.len() {
        if SUPPORTED_SCHEMAS[i].schema_id == schema_id {
            return Some(&SUPPORTED_SCHEMAS[i]);
        }
        i += 1;
    }
    None
}

/// Fail-closed compatibility check for a requested proof statement.
///
/// Check order:
/// 1. `schema_id` must be a known schema ([`RejectCode::UnknownSchema`]).
/// 2. `verifier_input_version` must match the schema's accepted codec version
///    ([`RejectCode::VersionMismatch`]).
/// 3. Every bit in `required_critical_fields` must be supported by that schema;
///    any unknown or unsupported critical field bit fails closed with
///    [`RejectCode::UnsupportedCriticalField`].
pub fn check_statement_compatibility(
    schema_id: u32,
    verifier_input_version: u32,
    required_critical_fields: u32,
) -> Result<&'static SchemaCompatibilityEntry, RejectCode> {
    let entry = schema_entry_by_id(schema_id).ok_or(RejectCode::UnknownSchema)?;
    if verifier_input_version != entry.verifier_input_version {
        return Err(RejectCode::VersionMismatch);
    }
    if (required_critical_fields & !entry.supported_critical_fields) != 0 {
        return Err(RejectCode::UnsupportedCriticalField);
    }
    Ok(entry)
}

#[cfg(test)]
mod constant_time_tests {
    use super::*;

    const REVOCATION_DOMAIN: [u8; FIELD_LEN] = {
        let mut out = [0u8; FIELD_LEN];
        let tag = b"HARPOCRATES_REVOCATION_V1";
        let mut i = 0;
        while i < tag.len() {
            out[7 + i] = tag[i];
            i += 1;
        }
        out
    };

    fn field(last: u8) -> [u8; FIELD_LEN] {
        let mut out = [0u8; FIELD_LEN];
        out[FIELD_LEN - 1] = last;
        out
    }

    fn half() -> [u8; FIELD_LEN] {
        let mut out = [0u8; FIELD_LEN];
        out[16..].fill(0x11);
        out
    }

    fn silent_frame(domain: &[u8; FIELD_LEN]) -> [u8; SILENT_WITNESS_PUBLIC_INPUTS_LEN] {
        let mut frame = [0u8; SILENT_WITNESS_PUBLIC_INPUTS_LEN];
        for (i, part) in [half(), half(), field(7), field(9), *domain]
            .iter()
            .enumerate()
        {
            frame[i * FIELD_LEN..(i + 1) * FIELD_LEN].copy_from_slice(part);
        }
        frame
    }

    /// Scope 4, epoch 5, version `EXPECTED_CIRCUIT_VERSION`.
    fn scoped_frame(domain: &[u8; FIELD_LEN]) -> [u8; SILENT_WITNESS_V2_PUBLIC_INPUTS_LEN] {
        let mut frame = [0u8; SILENT_WITNESS_V2_PUBLIC_INPUTS_LEN];
        let mut version = [0u8; FIELD_LEN];
        version[FIELD_LEN - 1] = EXPECTED_CIRCUIT_VERSION as u8;
        for (i, part) in [
            half(),
            half(),
            field(7),
            field(9),
            field(4),
            field(5),
            *domain,
            version,
        ]
        .iter()
        .enumerate()
        {
            frame[i * FIELD_LEN..(i + 1) * FIELD_LEN].copy_from_slice(part);
        }
        frame
    }

    fn revocation_frame(domain: &[u8; FIELD_LEN]) -> [u8; REVOCATION_PUBLIC_INPUTS_LEN] {
        let mut frame = [0u8; REVOCATION_PUBLIC_INPUTS_LEN];
        for (i, part) in [field(5), field(9), *domain, field(7)].iter().enumerate() {
            frame[i * FIELD_LEN..(i + 1) * FIELD_LEN].copy_from_slice(part);
        }
        frame
    }

    fn flipped(value: &[u8; FIELD_LEN], index: usize) -> [u8; FIELD_LEN] {
        let mut out = *value;
        out[index] ^= 0x01;
        out
    }

    #[test]
    fn constant_time_eq_matches_slice_equality() {
        assert!(constant_time_eq(&[], &[]));
        assert!(constant_time_eq(
            &SILENT_WITNESS_DOMAIN_TAG_BE,
            &SILENT_WITNESS_DOMAIN_TAG_BE
        ));
        assert!(!constant_time_eq(&[0u8; 31], &[0u8; 32]));
        assert!(!constant_time_eq(&[], &[0u8]));
    }

    #[test]
    fn constant_time_eq_rejects_a_flip_at_every_position() {
        for index in 0..FIELD_LEN {
            let tampered = flipped(&SILENT_WITNESS_DOMAIN_TAG_BE, index);
            assert!(
                !constant_time_eq(&SILENT_WITNESS_DOMAIN_TAG_BE, &tampered),
                "byte {index}"
            );
        }
    }

    #[test]
    fn baseline_frames_are_accepted() {
        assert!(parse_silent_witness(
            &silent_frame(&SILENT_WITNESS_DOMAIN_TAG_BE),
            &SILENT_WITNESS_DOMAIN_TAG_BE
        )
        .is_ok());
        assert!(parse_silent_witness_v2(
            &scoped_frame(&SILENT_WITNESS_DOMAIN_TAG_BE),
            &SILENT_WITNESS_DOMAIN_TAG_BE
        )
        .is_ok());
        assert!(parse_revocation_witness(
            &revocation_frame(&REVOCATION_DOMAIN),
            &REVOCATION_DOMAIN
        )
        .is_ok());
    }

    #[test]
    fn silent_witness_domain_flip_is_rejected_at_every_byte() {
        for index in 0..FIELD_LEN {
            let tampered = flipped(&SILENT_WITNESS_DOMAIN_TAG_BE, index);
            let result =
                parse_silent_witness(&silent_frame(&tampered), &SILENT_WITNESS_DOMAIN_TAG_BE);
            assert_eq!(
                result.err(),
                Some(RejectCode::DomainMismatch),
                "byte {index}"
            );
        }
    }

    #[test]
    fn scoped_v2_domain_flip_is_rejected_at_every_byte() {
        for index in 0..FIELD_LEN {
            let tampered = flipped(&SILENT_WITNESS_DOMAIN_TAG_BE, index);
            let result =
                parse_silent_witness_v2(&scoped_frame(&tampered), &SILENT_WITNESS_DOMAIN_TAG_BE);
            assert_eq!(
                result.err(),
                Some(RejectCode::DomainMismatch),
                "byte {index}"
            );
        }
    }

    #[test]
    fn revocation_domain_flip_is_rejected_at_every_byte() {
        for index in 0..FIELD_LEN {
            let tampered = flipped(&REVOCATION_DOMAIN, index);
            let result = parse_revocation_witness(&revocation_frame(&tampered), &REVOCATION_DOMAIN);
            assert_eq!(
                result.err(),
                Some(RejectCode::DomainMismatch),
                "byte {index}"
            );
        }
    }

    #[test]
    fn browser_silent_witness_enforces_canonical_field_structure() {
        let mut valid = [0u8; SILENT_WITNESS_BROWSER_PUBLIC_INPUTS_LEN];
        for (i, part) in [half(), half(), field(7), field(9)].iter().enumerate() {
            valid[i * FIELD_LEN..(i + 1) * FIELD_LEN].copy_from_slice(part);
        }

        let parsed = parse_browser_silent_witness(&valid).expect("valid 128-byte browser frame");
        assert_eq!(parsed.circuit_version, 1);
        assert_eq!(parsed.credential_root, field(7));
        assert_eq!(parsed.nullifier, field(9));

        assert_eq!(
            parse_browser_silent_witness(&valid[..96]).err(),
            Some(RejectCode::Length)
        );

        let mut bad_padding = valid;
        bad_padding[0] = 0x01;
        assert_eq!(
            parse_browser_silent_witness(&bad_padding).err(),
            Some(RejectCode::Padding)
        );

        let mut non_canonical = valid;
        non_canonical[64..96].copy_from_slice(&BN254_SCALAR_FIELD_MODULUS_BE);
        assert_eq!(
            parse_browser_silent_witness(&non_canonical).err(),
            Some(RejectCode::NonCanonicalField)
        );

        let mut zero_nullifier = valid;
        zero_nullifier[96..128].fill(0);
        assert_eq!(
            parse_browser_silent_witness(&zero_nullifier).err(),
            Some(RejectCode::ZeroField)
        );
    }
}


#[cfg(test)]
mod compatibility_descriptor_tests {
    use super::*;

    #[test]
    fn supported_schemas_table_is_bounded_and_canonical() {
        assert!(SUPPORTED_SCHEMAS.len() <= MAX_COMPATIBILITY_SCHEMAS);
        assert_eq!(SUPPORTED_SCHEMAS.len(), 3);

        let sw1 = schema_entry_by_id(1).expect("silent_witness/v1 must exist");
        assert_eq!(sw1.schema_name, SCHEMA_SILENT_WITNESS);
        assert_eq!(sw1.codec_id, CODEC_ID);
        assert_eq!(sw1.verifier_input_version, VERIFIER_INPUT_VERSION_V1);
        assert_eq!(sw1.circuit_version, 1);
        assert_eq!(sw1.public_inputs_len, SILENT_WITNESS_PUBLIC_INPUTS_LEN as u32);
        assert_eq!(sw1.supported_critical_fields, CRITICAL_FIELDS_SILENT_WITNESS_V1);

        let rv1 = schema_entry_by_id(2).expect("revocation_witness/v1 must exist");
        assert_eq!(rv1.schema_name, SCHEMA_REVOCATION_WITNESS);
        assert_eq!(rv1.codec_id, CODEC_ID);
        assert_eq!(rv1.verifier_input_version, VERIFIER_INPUT_VERSION_V1);
        assert_eq!(rv1.circuit_version, 1);
        assert_eq!(rv1.public_inputs_len, REVOCATION_PUBLIC_INPUTS_LEN as u32);
        assert_eq!(
            rv1.supported_critical_fields,
            CRITICAL_FIELDS_REVOCATION_WITNESS_V1
        );

        let sw2 = schema_entry_by_id(3).expect("silent_witness/v2 must exist");
        assert_eq!(sw2.schema_name, SCHEMA_SILENT_WITNESS_V2);
        assert_eq!(sw2.codec_id, CODEC_ID_V2);
        assert_eq!(sw2.verifier_input_version, VERIFIER_INPUT_VERSION_V2);
        assert_eq!(sw2.circuit_version, EXPECTED_CIRCUIT_VERSION);
        assert_eq!(
            sw2.public_inputs_len,
            SILENT_WITNESS_V2_PUBLIC_INPUTS_LEN as u32
        );
        assert_eq!(sw2.supported_critical_fields, CRITICAL_FIELDS_SILENT_WITNESS_V2);

        assert!(schema_entry_by_id(0).is_none());
        assert!(schema_entry_by_id(4).is_none());
    }

    #[test]
    fn check_statement_compatibility_accepts_supported_combinations() {
        for entry in SUPPORTED_SCHEMAS.iter() {
            assert_eq!(
                check_statement_compatibility(
                    entry.schema_id,
                    entry.verifier_input_version,
                    entry.supported_critical_fields,
                ),
                Ok(entry)
            );
            assert_eq!(
                check_statement_compatibility(entry.schema_id, entry.verifier_input_version, 0),
                Ok(entry)
            );
        }
    }

    #[test]
    fn check_statement_compatibility_fails_closed_on_unknown_schema_and_version_mismatch() {
        assert_eq!(
            check_statement_compatibility(0, VERIFIER_INPUT_VERSION_V1, 0),
            Err(RejectCode::UnknownSchema)
        );
        assert_eq!(
            check_statement_compatibility(99, VERIFIER_INPUT_VERSION_V2, 0),
            Err(RejectCode::UnknownSchema)
        );
        assert_eq!(
            check_statement_compatibility(
                1,
                VERIFIER_INPUT_VERSION_V2,
                CRITICAL_FIELDS_SILENT_WITNESS_V1
            ),
            Err(RejectCode::VersionMismatch)
        );
        assert_eq!(
            check_statement_compatibility(
                3,
                VERIFIER_INPUT_VERSION_V1,
                CRITICAL_FIELDS_SILENT_WITNESS_V2
            ),
            Err(RejectCode::VersionMismatch)
        );
    }

    #[test]
    fn check_statement_compatibility_fails_closed_on_unsupported_critical_fields() {
        // Unknown high bit must fail closed for every schema.
        let unknown_critical_bit: u32 = 1 << 31;
        for entry in SUPPORTED_SCHEMAS.iter() {
            assert_eq!(
                check_statement_compatibility(
                    entry.schema_id,
                    entry.verifier_input_version,
                    entry.supported_critical_fields | unknown_critical_bit,
                ),
                Err(RejectCode::UnsupportedCriticalField)
            );
        }

        // A v2-only critical field (verifier_scope) must fail closed on v1.
        assert_eq!(
            check_statement_compatibility(
                1,
                VERIFIER_INPUT_VERSION_V1,
                CRITICAL_FIELDS_SILENT_WITNESS_V1 | CRITICAL_FIELD_VERIFIER_SCOPE,
            ),
            Err(RejectCode::UnsupportedCriticalField)
        );

        // Revocation root is not a silent_witness/v2 critical field.
        assert_eq!(
            check_statement_compatibility(
                3,
                VERIFIER_INPUT_VERSION_V2,
                CRITICAL_FIELDS_SILENT_WITNESS_V2 | CRITICAL_FIELD_REVOCATION_ROOT,
            ),
            Err(RejectCode::UnsupportedCriticalField)
        );

        assert_eq!(RejectCode::UnsupportedCriticalField.as_code(), 11);
        assert_eq!(
            RejectCode::UnsupportedCriticalField.as_str(),
            "unsupported_critical_field"
        );
        assert_eq!(
            RejectCode::from_wire("unsupported_critical_field"),
            Some(RejectCode::UnsupportedCriticalField)
        );
    }
}
