"""Independent Stellar ScVal XDR decoder and lifecycle event validator (`hpx-ev/1`).

Decodes raw RFC-4506 big-endian Soroban event topic vectors and map payloads
without depending on Rust or ``soroban-sdk``, enforcing canonical XDR 4-byte
zero padding, trailing-byte rejection, lexicographically sorted ``ScMap`` keys,
and typed topic/payload schemas for ``HarpocratesRegistry`` lifecycle events.
"""

from __future__ import annotations

from dataclasses import dataclass
import struct
from typing import Any

CODEC_ID = "hpx-ev/1"


class LifecycleEventError(ValueError):
    """Fail-closed error raised when an XDR lifecycle event violates `hpx-ev/1`."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


@dataclass(frozen=True)
class DecodedValue:
    type: str
    value: Any
    canonical: str


@dataclass(frozen=True)
class DecodedLifecycleEvent:
    event_name: str
    topics: list[dict[str, Any]]
    payload: list[dict[str, Any]]
    topics_canonical: str
    payload_canonical: str


EVENT_SPECS: dict[str, dict[str, Any]] = {
    "CredentialRootAdded": {
        "topic_prefix": ("credroot", "add"),
        "topic_types": ("symbol", "symbol", "bytes32"),
        "required_fields": {"issued_at": "u64", "metadata_hash": "bytes32"},
        "optional_fields": {},
    },
    "CredentialRootRevoked": {
        "topic_prefix": ("credroot", "revoke"),
        "topic_types": ("symbol", "symbol", "bytes32"),
        "required_fields": {},
        "optional_fields": {},
    },
    "IssuerAdded": {
        "topic_prefix": ("issuer", "add"),
        "topic_types": ("symbol", "symbol", "address_ed25519"),
        "required_fields": {"metadata_hash": "bytes32"},
        "optional_fields": {},
    },
    "IssuerRevoked": {
        "topic_prefix": ("issuer", "revoke"),
        "topic_types": ("symbol", "symbol", "address_ed25519"),
        "required_fields": {},
        "optional_fields": {},
    },
    "ProofRegistered": {
        "topic_prefix": ("proof", "reg"),
        "topic_types": ("symbol", "symbol", "bytes32"),
        "required_fields": {
            "batch_size": "u32",
            "status": "u32",
            "tier": "u32",
            "video_hash": "bytes32",
        },
        "optional_fields": {},
    },
    "ProofHistoryEvent": {
        "topic_prefix": ("proof", "history"),
        "topic_types": ("symbol", "symbol", "bytes32"),
        "required_fields": {
            "action": "u32",
            "reason_code": "u32",
            "timestamp": "u64",
        },
        "optional_fields": {"actor": "address_ed25519"},
    },
    "ProofRevoked": {
        "topic_prefix": ("proof", "revoke"),
        "topic_types": ("symbol", "symbol", "bytes32"),
        "required_fields": {"status": "u32"},
        "optional_fields": {},
    },
    "MetadataEnvelopeBound": {
        "topic_prefix": ("metadata", "envelope", "bound"),
        "topic_types": ("symbol", "symbol", "symbol", "bytes32"),
        "required_fields": {
            "bound_at": "u64",
            "metadata_hash": "bytes32",
            "version": "u32",
        },
        "optional_fields": {},
    },
    "MetadataEnvelopeUpgraded": {
        "topic_prefix": ("metadata", "envelope", "upgraded"),
        "topic_types": ("symbol", "symbol", "symbol", "bytes32"),
        "required_fields": {
            "current": "u32",
            "metadata_hash": "bytes32",
            "previous": "u32",
        },
        "optional_fields": {},
    },
    "TimestampClaimAnchored": {
        "topic_prefix": ("timestamp", "anchor"),
        "topic_types": ("symbol", "symbol", "bytes32"),
        "required_fields": {
            "anchored_at": "u64",
            "assurance": "u32",
            "attestation_digest": "bytes32",
            "ledger_sequence": "u32",
            "sources": "u32",
        },
        "optional_fields": {},
    },
    "LineageRegistered": {
        "topic_prefix": ("lineage", "reg"),
        "topic_types": ("symbol", "symbol", "bytes32"),
        "required_fields": {
            "actor": "address_ed25519",
            "depth": "u32",
            "manifest_digest": "bytes32",
            "operation_type": "symbol",
            "parent_commitments": "vec",
        },
        "optional_fields": {},
    },
    "DisputeOpened": {
        "topic_prefix": ("dispute", "open"),
        "topic_types": ("symbol", "symbol", "bytes32", "bytes32"),
        "required_fields": {
            "commitment_hash": "bytes32",
            "reason": "u32",
            "reporter_hash": "bytes32",
            "respond_deadline": "u64",
        },
        "optional_fields": {},
    },
    "DisputeResponded": {
        "topic_prefix": ("dispute", "respond"),
        "topic_types": ("symbol", "symbol", "bytes32", "bytes32"),
        "required_fields": {
            "resolve_deadline": "u64",
            "response_commitment": "bytes32",
        },
        "optional_fields": {},
    },
    "DisputeResolved": {
        "topic_prefix": ("dispute", "resolve"),
        "topic_types": ("symbol", "symbol", "bytes32", "bytes32"),
        "required_fields": {"resolved_at": "u64"},
        "optional_fields": {},
    },
    "DisputeDismissed": {
        "topic_prefix": ("dispute", "dismiss"),
        "topic_types": ("symbol", "symbol", "bytes32", "bytes32"),
        "required_fields": {"resolved_at": "u64"},
        "optional_fields": {},
    },
    "DisputeSuperseded": {
        "topic_prefix": ("dispute", "supersede"),
        "topic_types": ("symbol", "symbol", "bytes32", "bytes32"),
        "required_fields": {"resolved_at": "u64", "superseded_by": "bytes32"},
        "optional_fields": {},
    },
    "SourceBatchRootRegistered": {
        "topic_prefix": ("batch", "root"),
        "topic_types": ("symbol", "symbol", "bytes32", "address_ed25519"),
        "required_fields": {
            "count": "u32",
            "metadata_hash": "bytes32",
            "registered_at": "u64",
        },
        "optional_fields": {},
    },
    "SchemaAdded": {
        "topic_prefix": ("schema", "add"),
        "topic_types": ("symbol", "symbol", "bytes32"),
        "required_fields": {
            "attribute_count": "u32",
            "issuer_namespace": "bytes32",
            "version": "u32",
        },
        "optional_fields": {},
    },
    "SchemaDeprecated": {
        "topic_prefix": ("schema", "deprecate"),
        "topic_types": ("symbol", "symbol", "bytes32"),
        "required_fields": {},
        "optional_fields": {},
    },
    "SchemaReactivated": {
        "topic_prefix": ("schema", "reactivate"),
        "topic_types": ("symbol", "symbol", "bytes32"),
        "required_fields": {},
        "optional_fields": {},
    },
    "RevocationRootSet": {
        "topic_prefix": ("revroot", "set"),
        "topic_types": ("symbol", "symbol", "bytes32"),
        "required_fields": {},
        "optional_fields": {},
    },
}


def decode_hex(hex_str: str) -> bytes:
    if len(hex_str) % 2 != 0:
        raise LifecycleEventError("malformed_xdr", "odd-length hex string")
    try:
        return bytes.fromhex(hex_str)
    except ValueError as exc:
        raise LifecycleEventError("malformed_xdr", "invalid hex string") from exc


class _XdrCursor:
    def __init__(self, buf: bytes) -> None:
        self.buf = buf
        self.pos = 0

    def read_u32(self) -> int:
        if self.pos + 4 > len(self.buf):
            raise LifecycleEventError("malformed_xdr", "truncated u32")
        (val,) = struct.unpack(">I", self.buf[self.pos : self.pos + 4])
        self.pos += 4
        return val

    def read_u64(self) -> int:
        if self.pos + 8 > len(self.buf):
            raise LifecycleEventError("malformed_xdr", "truncated u64")
        (val,) = struct.unpack(">Q", self.buf[self.pos : self.pos + 8])
        self.pos += 8
        return val

    def read_fixed32(self) -> bytes:
        if self.pos + 32 > len(self.buf):
            raise LifecycleEventError("malformed_xdr", "truncated 32-byte value")
        out = self.buf[self.pos : self.pos + 32]
        self.pos += 32
        return out

    def read_var_opaque(self) -> bytes:
        length = self.read_u32()
        pad = (4 - (length % 4)) % 4
        if self.pos + length + pad > len(self.buf):
            raise LifecycleEventError("malformed_xdr", "truncated variable opaque")
        raw = self.buf[self.pos : self.pos + length]
        padding = self.buf[self.pos + length : self.pos + length + pad]
        if any(b != 0 for b in padding):
            raise LifecycleEventError("non_canonical_padding", "non-zero XDR padding")
        self.pos += length + pad
        return raw

    def read_scval(self) -> DecodedValue:
        disc = self.read_u32()
        if disc == 0:
            flag = self.read_u32()
            if flag not in (0, 1):
                raise LifecycleEventError("malformed_xdr", "invalid bool flag")
            b_val = flag == 1
            return DecodedValue("bool", b_val, f"bool:{'true' if b_val else 'false'}")
        if disc == 1:
            return DecodedValue("void", None, "void:null")
        if disc == 3:
            u32_val = self.read_u32()
            return DecodedValue("u32", u32_val, f"u32:{u32_val}")
        if disc == 5:
            u64_val = self.read_u64()
            return DecodedValue("u64", u64_val, f"u64:{u64_val}")
        if disc == 13:
            raw = self.read_var_opaque()
            hx = raw.hex()
            ty = f"bytes{len(raw)}"
            return DecodedValue(ty, hx, f"{ty}:{hx}")
        if disc == 15:
            raw = self.read_var_opaque()
            if not (1 <= len(raw) <= 32) or not all(
                (48 <= b <= 57) or (65 <= b <= 90) or (97 <= b <= 122) or b == 95
                for b in raw
            ):
                raise LifecycleEventError("malformed_xdr", "invalid ScSymbol")
            sym = raw.decode("ascii")
            return DecodedValue("symbol", sym, f"symbol:{sym}")
        if disc == 16:
            if self.read_u32() != 1:
                raise LifecycleEventError("malformed_xdr", "missing ScVec body")
            count = self.read_u32()
            items = [self.read_scval() for _ in range(count)]
            canon = f"vec[{','.join(i.canonical for i in items)}]"
            return DecodedValue("vec", items, canon)
        if disc == 17:
            if self.read_u32() != 1:
                raise LifecycleEventError("malformed_xdr", "missing ScMap body")
            count = self.read_u32()
            entries: list[tuple[str, DecodedValue]] = []
            prev_key_bytes: bytes | None = None
            for _ in range(count):
                k_val = self.read_scval()
                if k_val.type != "symbol":
                    raise LifecycleEventError("payload_schema_mismatch", "non-symbol map key")
                k_bytes = str(k_val.value).encode("ascii")
                if prev_key_bytes is not None and k_bytes <= prev_key_bytes:
                    raise LifecycleEventError(
                        "non_canonical_map_order", "ScMap keys not strictly ascending"
                    )
                prev_key_bytes = k_bytes
                entries.append((str(k_val.value), self.read_scval()))
            canon = (
                "empty_map"
                if not entries
                else ";".join(f"{k}={v.canonical}" for k, v in entries)
            )
            return DecodedValue("map", entries, canon)
        if disc == 18:
            addr_kind = self.read_u32()
            if addr_kind == 0:
                if self.read_u32() != 0:
                    raise LifecycleEventError("malformed_xdr", "unsupported PublicKeyType")
                hx = self.read_fixed32().hex()
                return DecodedValue("address_ed25519", hx, f"address_ed25519:{hx}")
            if addr_kind == 1:
                hx = self.read_fixed32().hex()
                return DecodedValue("address_contract", hx, f"address_contract:{hx}")
            raise LifecycleEventError("malformed_xdr", "unsupported ScAddress kind")
        raise LifecycleEventError("malformed_xdr", f"unsupported ScVal discriminant {disc}")


def decode_exact_scval(hex_str: str) -> DecodedValue:
    raw = decode_hex(hex_str)
    cur = _XdrCursor(raw)
    val = cur.read_scval()
    if cur.pos != len(raw):
        raise LifecycleEventError("trailing_xdr_bytes", "unconsumed bytes after ScVal")
    return val


def _to_structured(val: DecodedValue) -> dict[str, Any]:
    if val.type == "vec":
        return {"type": "vec", "value": [_to_structured(item) for item in val.value]}
    return {"type": val.type, "value": val.value}


def decode_lifecycle_event(topics_xdr_hex: str, data_xdr_hex: str) -> DecodedLifecycleEvent:
    topics_scv = decode_exact_scval(topics_xdr_hex)
    data_scv = decode_exact_scval(data_xdr_hex)

    if topics_scv.type != "vec":
        raise LifecycleEventError("malformed_xdr", "topics root must be ScVal::Vec")
    topics: list[DecodedValue] = topics_scv.value
    if len(topics) < 2:
        raise LifecycleEventError("topic_arity_mismatch", "fewer than 2 event topics")

    matched_name: str | None = None
    matched_spec: dict[str, Any] | None = None
    for ev_name, spec in EVENT_SPECS.items():
        prefix: tuple[str, ...] = spec["topic_prefix"]
        if len(topics) >= len(prefix) and all(
            topics[i].type == "symbol" and topics[i].value == prefix[i]
            for i in range(len(prefix))
        ):
            matched_name = ev_name
            matched_spec = spec
            break

    if matched_name is None or matched_spec is None:
        raise LifecycleEventError("unknown_event_topic", "unrecognized topic prefix")

    expected_topic_types: tuple[str, ...] = matched_spec["topic_types"]
    if len(topics) != len(expected_topic_types):
        raise LifecycleEventError("topic_arity_mismatch", "unexpected topic count")

    for topic, expected_type in zip(topics, expected_topic_types):
        if topic.type != expected_type:
            raise LifecycleEventError("topic_type_mismatch", "topic ScVal type mismatch")

    if data_scv.type != "map":
        raise LifecycleEventError("payload_schema_mismatch", "payload root must be ScVal::Map")

    entries: list[tuple[str, DecodedValue]] = data_scv.value
    entry_map = dict(entries)
    req_fields: dict[str, str] = matched_spec["required_fields"]
    opt_fields: dict[str, str] = matched_spec["optional_fields"]

    for req_key, req_type in req_fields.items():
        if req_key not in entry_map or entry_map[req_key].type != req_type:
            raise LifecycleEventError("payload_schema_mismatch", f"invalid field {req_key}")

    allowed = {**req_fields, **opt_fields}
    for key, val in entries:
        if key not in allowed or val.type != allowed[key]:
            raise LifecycleEventError("payload_schema_mismatch", f"unexpected field {key}")

    topics_structured = [_to_structured(t) for t in topics]
    payload_structured = [
        {"field": k, **_to_structured(v)}
        for k, v in entries
    ]
    topics_canonical = "|".join(t.canonical for t in topics)
    return DecodedLifecycleEvent(
        event_name=matched_name,
        topics=topics_structured,
        payload=payload_structured,
        topics_canonical=topics_canonical,
        payload_canonical=data_scv.canonical,
    )
