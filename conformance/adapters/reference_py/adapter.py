#!/usr/bin/env python3
"""Reference adapter for the Harpocrates conformance suite (Python, stdlib only).

Protocol `hpx-conformance-adapter/1`: one JSON object per line on stdin,
    {"id": "...", "op": "...", "input": {...}}
one JSON object per line on stdout,
    {"id": "...", "ok": true,  "output": {...}}
    {"id": "...", "ok": false, "code": "<reason code>", "detail": {...}?}
`hello` returns {"protocol", "ops", "implementation"}. Unknown ops answer
code `unsupported_op`. Nothing is ever echoed from the input except a field NAME.

This is the *strict* reading of the spec: it also satisfies the advisory cases.
The error table is read from contracts/ERROR_ABI.md when this adapter runs inside
the Harpocrates repo (a third-party implementation embeds its own copy).
"""
import base64
import calendar
import hashlib
import json
import os
import re
import struct
import sys
from pathlib import Path

PROTOCOL = "hpx-conformance-adapter/1"
SAFE_INT = 2**53 - 1
U32, U64 = 2**32 - 1, 2**64 - 1
HEX32 = re.compile(r"[0-9a-fA-F]{64}")
HEX32_LOWER = re.compile(r"[0-9a-f]{64}")
HEXB = re.compile(r"(?:[0-9a-fA-F]{2})*")
DEC = re.compile(r"(?:0|[1-9][0-9]*)")
TIERS = ("silent", "source", "seal")
NET = {"Public Global Stellar Network ; September 2015": "Mainnet", "Test SDF Network ; September 2015": "Testnet",
       "Test SDF Future Network ; October 2022": "Futurenet", "Local Sandbox Stellar Network ; September 2022": "Sandbox",
       "Standalone Network ; February 2017": "Standalone"}


class Fail(Exception):
    def __init__(self, code, **detail):
        self.code, self.detail = code, detail


def is_int(v):
    return isinstance(v, int) and not isinstance(v, bool)


# ------------------------------------------------------------------ canonical JSON (hpx-cj/1)
def _no_dup(pairs):
    d = {}
    for k, v in pairs:
        if k in d:
            raise Fail("duplicate_key")
        d[k] = v
    return d


def _bad_const(_):
    raise Fail("invalid_json")


def _bad_float(_):
    raise Fail("unsupported_number")


def _check(v, depth=1):
    if depth > 64:
        raise Fail("nesting_too_deep")
    if isinstance(v, str):
        if any(0xD800 <= ord(ch) <= 0xDFFF for ch in v):
            raise Fail("invalid_unicode")
    elif is_int(v):
        if abs(v) > SAFE_INT:
            raise Fail("unsupported_number")
    elif isinstance(v, list):
        for x in v:
            _check(x, depth + 1)
    elif isinstance(v, dict):
        for k, x in v.items():
            _check(k, depth + 1)
            _check(x, depth + 1)


def parse_json(text):
    if not isinstance(text, str):
        raise Fail("invalid_json")
    try:
        v = json.loads(text, object_pairs_hook=_no_dup, parse_constant=_bad_const, parse_float=_bad_float)
    except Fail:
        raise
    except RecursionError:
        raise Fail("nesting_too_deep")
    except (ValueError, TypeError):
        raise Fail("invalid_json")
    return v


def canon(v):
    """Canonical JSON text of an already-parsed value (validates the number/unicode/depth rules)."""
    _check(v)
    return _emit(v)


def _emit(v):
    if v is None:
        return "null"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if is_int(v):
        return str(v)
    if isinstance(v, float):
        if v != int(v) or abs(v) > SAFE_INT:
            raise Fail("unsupported_number")
        return str(int(v))
    if isinstance(v, str):
        return json.dumps(v, ensure_ascii=False)
    if isinstance(v, list):
        return "[" + ",".join(_emit(x) for x in v) + "]"
    keys = sorted(v, key=lambda k: k.encode("utf-16-be"))
    return "{" + ",".join(json.dumps(k, ensure_ascii=False) + ":" + _emit(v[k]) for k in keys) + "}"


def sha(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def out_canon(v):
    c = canon(v)
    return {"canonical": c, "sha256": sha(c)}


# ------------------------------------------------------------------ time
_TS = re.compile(r"(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d+)?(Z|[+-]\d{2}:\d{2})")


def parse_time(s):
    """RFC 3339 -> integer seconds since epoch (UTC), else None."""
    if not isinstance(s, str):
        return None
    m = _TS.fullmatch(s)
    if not m:
        return None
    y, mo, d, h, mi, se = (int(x) for x in m.groups()[:6])
    if not (1 <= mo <= 12 and 1 <= d <= calendar.monthrange(y, mo)[1] and h < 24 and mi < 60 and se < 60):
        return None
    off = 0
    z = m.group(7)
    if z != "Z":
        if int(z[1:3]) > 23 or int(z[4:6]) > 59:
            return None
        off = (int(z[1:3]) * 3600 + int(z[4:6]) * 60) * (1 if z[0] == "+" else -1)
    return calendar.timegm((y, mo, d, h, mi, se)) - off


# ------------------------------------------------------------------ metadata
def op_canonicalize(i):
    return out_canon(parse_json(i["json_text"]))


def op_metadata_validate(i):
    m = i["metadata"]
    if not isinstance(m, dict):
        raise Fail("not_object")
    for f in ("protocol", "version", "tier", "sourceHash", "proofId", "timestamp"):
        if f not in m:
            raise Fail("missing_field", field=f)
    if m["protocol"] != "harpocrates":
        raise Fail("bad_protocol")
    v = m["version"]
    if not is_int(v) or v < 1:
        raise Fail("bad_version")
    if m["tier"] not in TIERS:
        raise Fail("bad_tier")
    if not (isinstance(m["sourceHash"], str) and HEX32.fullmatch(m["sourceHash"])):
        raise Fail("bad_source_hash")
    if not (isinstance(m["proofId"], str) and HEX32.fullmatch(m["proofId"])):
        raise Fail("bad_proof_id")
    if parse_time(m["timestamp"]) is None:
        raise Fail("bad_timestamp")
    return {"valid": True}


def op_metadata_hash(i):
    return out_canon(i["metadata"])


def _env_ok(v):
    return is_int(v) and 1 <= v <= 2


def op_envelope_version_check(i):
    if not _env_ok(i["version"]):
        raise Fail("unsupported_metadata_envelope_version")
    return {"supported": True}


def op_envelope_version_resolve(i):
    if i["stored_version"] is not None:
        return {"version": i["stored_version"]}
    return {"version": 1 if i["proof_exists"] else 0}


def op_envelope_bind(i):
    if not i["proof_exists"]:
        raise Fail("metadata_envelope_not_found")
    if not _env_ok(i["version"]):
        raise Fail("unsupported_metadata_envelope_version")
    if i["metadata_hash"] == "0" * 64:
        raise Fail("invalid_metadata_envelope")
    if i["metadata_hash"] != i["stored_hash"]:
        raise Fail("metadata_envelope_hash_mismatch")
    prev = i["current_version"]
    if prev is not None:
        if i["version"] < prev:
            raise Fail("unsupported_metadata_envelope_version")
        if i["version"] == prev:
            if i["metadata_hash"] == i["current_hash"]:
                return {"version": prev, "event": "none"}
            raise Fail("metadata_envelope_hash_mismatch")
        return {"version": i["version"], "event": "upgraded"}
    return {"version": i["version"], "event": "bound"}


# ------------------------------------------------------------------ manifest
MAN_FIELDS = {"contractId", "metadataHash", "network", "proofId", "protocol", "sourceHash", "tier", "timestamp",
              "transactionRef", "version", "videoHash", "verifierScope", "epoch", "scopeName", "selectiveDisclosure"}
BN254_R = 21888242871839275222246405745257275088548364400416034343698204186575808495617


def op_manifest_create(i):
    m = {"protocol": "harpocrates", "version": 2}
    for k in ("proofId", "tier", "network", "contractId", "transactionRef", "videoHash", "metadataHash", "sourceHash", "timestamp"):
        m[k] = i[k]
    m["verifierScope"] = i.get("verifierScope") if i.get("verifierScope") is not None else "0"
    m["epoch"] = i.get("epoch") if i.get("epoch") is not None else 0
    if i.get("scopeName"):
        m["scopeName"] = i["scopeName"]
    if i.get("selectiveDisclosure"):
        m["selectiveDisclosure"] = i["selectiveDisclosure"]
    return out_canon(m)


def op_manifest_parse(i):
    try:
        m = json.loads(i["text"])
    except (ValueError, RecursionError):
        raise Fail("invalid_json")
    if not isinstance(m, dict):
        raise Fail("not_object")
    if any(k not in MAN_FIELDS for k in m):
        raise Fail("unsupported_field")
    if m.get("protocol") != "harpocrates":
        raise Fail("bad_protocol")
    v = m.get("version")
    if not (is_int(v) and v in (1, 2)):
        raise Fail("unsupported_version")
    if m.get("tier") not in TIERS:
        raise Fail("bad_tier")
    for f in ("proofId", "network", "contractId", "transactionRef", "videoHash", "metadataHash", "sourceHash", "timestamp"):
        if not isinstance(m.get(f), str) or not m[f]:
            raise Fail("bad_string_field", field=f)
    for f in ("proofId", "videoHash", "metadataHash", "sourceHash", "transactionRef"):
        if not HEX32.fullmatch(m[f]):
            raise Fail("bad_hex32", field=f)
    if parse_time(m["timestamp"]) is None:
        raise Fail("bad_timestamp")
    if v == 2:
        s, e = m.get("verifierScope"), m.get("epoch")
        if not (isinstance(s, str) and DEC.fullmatch(s) and int(s) < BN254_R and is_int(e) and 0 <= e <= SAFE_INT):
            raise Fail("bad_scope_epoch")
    if "scopeName" in m:
        n = m["scopeName"]
        if not isinstance(n, str) or len(n.encode("utf-16-le", "surrogatepass")) // 2 > 128:
            raise Fail("bad_scope_name")
    if "selectiveDisclosure" in m:
        d = m["selectiveDisclosure"]
        ok = (isinstance(d, dict) and set(d) <= {"schemaHash", "publicInputs", "predicateCommitment", "circuitVersion"}
              and isinstance(d.get("schemaHash"), str) and HEX32.fullmatch(d["schemaHash"])
              and isinstance(d.get("predicateCommitment"), str) and HEX32.fullmatch(d["predicateCommitment"])
              and isinstance(d.get("publicInputs"), str) and HEXB.fullmatch(d["publicInputs"])
              and is_int(d.get("circuitVersion")))
        if not ok:
            raise Fail("bad_disclosure")
    return out_canon(m)


# ------------------------------------------------------------------ P-256 verification (pure Python)
_P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
_A = _P - 3
_B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
_G = (0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
      0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5)


def _add(p, q):
    if p is None:
        return q
    if q is None:
        return p
    if p[0] == q[0] and (p[1] + q[1]) % _P == 0:
        return None
    if p == q:
        lam = (3 * p[0] * p[0] + _A) * pow(2 * p[1], -1, _P) % _P
    else:
        lam = (q[1] - p[1]) * pow(q[0] - p[0], -1, _P) % _P
    x = (lam * lam - p[0] - q[0]) % _P
    return x, (lam * (p[0] - x) - p[1]) % _P


def _mul(k, p):
    r = None
    while k:
        if k & 1:
            r = _add(r, p)
        p = _add(p, p)
        k >>= 1
    return r


def ecdsa_verify(x, y, sig64, msg):
    if len(sig64) != 64:
        return False
    r, s = int.from_bytes(sig64[:32], "big"), int.from_bytes(sig64[32:], "big")
    if not (1 <= r < _N and 1 <= s < _N):
        return False
    if (y * y - (x * x * x + _A * x + _B)) % _P != 0:
        return False
    z = int.from_bytes(hashlib.sha256(msg).digest(), "big")
    w = pow(s, -1, _N)
    pt = _add(_mul(z * w % _N, _G), _mul(r * w % _N, (x, y)))
    return pt is not None and pt[0] % _N == r


B64U = re.compile(r"[A-Za-z0-9_-]+")


def b64u_decode(s):
    if not isinstance(s, str) or not B64U.fullmatch(s) or len(s) % 4 == 1:
        raise ValueError
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def b64u_encode(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


# ------------------------------------------------------------------ receipts
MAX_RECEIPT, MAX_QR = 8192, 4096


def _size(r):
    # Sizing must not depend on value validity (structure is checked after size), so use a lenient emitter.
    lenient = json.dumps(r, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    if len(lenient.encode("utf-8", "surrogatepass")) > MAX_RECEIPT:
        raise Fail("receipt_too_large")


def _nonempty(v):
    return isinstance(v, str) and v.strip() != ""


def _payload(p):
    if not isinstance(p, dict):
        raise Fail("receipt_unsupported_version")
    if p.get("protocol") != "harpocrates-verification-receipt" or p.get("version") != 1 or isinstance(p.get("version"), bool):
        raise Fail("receipt_unsupported_version")
    if p.get("result") not in ("verified", "unverified"):
        raise Fail("receipt_result_invalid")
    for f in ("proofId", "videoHash", "metadataHash"):
        if not (isinstance(p.get(f), str) and HEX32.fullmatch(p[f])):
            raise Fail("receipt_digest_invalid")
    if p.get("tier") not in TIERS:
        raise Fail("receipt_tier_invalid")
    if not all(_nonempty(p.get(f)) for f in ("networkPassphrase", "contractId", "circuitVersion", "verifierVersion")):
        raise Fail("receipt_metadata_incomplete")
    sg = p.get("signer")
    if not (isinstance(sg, dict) and _nonempty(sg.get("keyId")) and sg.get("algorithm") == "ECDSA_P256_SHA256"):
        raise Fail("receipt_signer_invalid")
    lg = p.get("ledgerSequence")
    if lg is not None and not (is_int(lg) and 0 <= lg <= U32):
        raise Fail("receipt_ledger_invalid")
    tx = p.get("transactionHash")
    if tx is not None and not (isinstance(tx, str) and HEX32.fullmatch(tx)):
        raise Fail("receipt_txhash_invalid")
    if not _nonempty(p.get("verifiedAt")) or parse_time(p["verifiedAt"]) is None:
        raise Fail("receipt_time_invalid")


def op_receipt_verify(i):
    r, keys, opt = i["receipt"], i["keys"], i.get("options") or {}
    _size(r)
    _payload(r)
    sig = r.get("signature")
    if not isinstance(sig, str) or not sig:
        raise Fail("receipt_signature_missing")
    if opt.get("expectedNetworkPassphrase") and r["networkPassphrase"] != opt["expectedNetworkPassphrase"]:
        raise Fail("receipt_network_mismatch")
    if opt.get("expectedProofId") and r["proofId"] != opt["expectedProofId"]:
        raise Fail("receipt_proof_mismatch")
    kid = r["signer"]["keyId"]
    win = (opt.get("keyValidity") or {}).get(kid)
    if win:
        va, now = parse_time(r["verifiedAt"]), parse_time(opt.get("now"))
        nb = parse_time(win["notBefore"]) if win.get("notBefore") else None
        na = parse_time(win["notAfter"]) if win.get("notAfter") else None
        if (nb is not None and va < nb) or (na is not None and (va > na or now > na)):
            raise Fail("receipt_key_stale")
    jwk = keys.get(kid)
    if not jwk:
        raise Fail("receipt_key_unknown")
    try:
        raw = b64u_decode(sig)
    except ValueError:
        raise Fail("receipt_signature_malformed")
    body = {k: v for k, v in r.items() if k != "signature"}
    x = int.from_bytes(b64u_decode(jwk["x"]), "big")
    y = int.from_bytes(b64u_decode(jwk["y"]), "big")
    if not ecdsa_verify(x, y, raw, canon(body).encode("utf-8")):
        raise Fail("receipt_signature_invalid")
    return {"valid": True}


def op_receipt_qr_encode(i):
    _size(i["receipt"])
    enc = b64u_encode(canon(i["receipt"]).encode("utf-8"))
    if len(enc) > MAX_QR:
        raise Fail("qr_too_large")
    return {"encoded": enc}


def op_receipt_qr_decode(i):
    enc = i["encoded"]
    if not isinstance(enc, str):
        raise Fail("qr_invalid_encoding")
    if len(enc) > MAX_QR:
        raise Fail("qr_too_large")
    try:
        text = b64u_decode(enc).decode("utf-8")
        r = json.loads(text)
    except (ValueError, UnicodeDecodeError):
        raise Fail("qr_invalid_encoding")
    _size(r)
    return out_canon(r)


# ------------------------------------------------------------------ stellar encodings
def op_hex32_normalize(i):
    v = i["value"]
    if not (isinstance(v, str) and HEX32.fullmatch(v)):
        raise Fail("invalid_hex32")
    return {"hex": v.lower()}


def op_hex_bytes_normalize(i):
    v = i["value"]
    if not (isinstance(v, str) and HEXB.fullmatch(v)):
        raise Fail("invalid_hex_bytes")
    return {"hex": v.lower()}


def op_bytes_to_hex(i):
    b = i["bytes"]
    if not all(is_int(x) and 0 <= x <= 255 for x in b):
        raise Fail("invalid_byte")
    return {"hex": bytes(b).hex()}


def crc16(data):
    crc = 0
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return crc


def op_strkey_decode(i):
    s, expect = i["strkey"], i["expect"]
    if not (isinstance(s, str) and len(s) == 56 and re.fullmatch(r"[A-Z2-7]{56}", s)):
        raise Fail("strkey_invalid")
    raw = base64.b32decode(s)
    if base64.b32encode(raw).decode() != s:
        raise Fail("strkey_invalid")
    kinds = {6 << 3: "account", 2 << 3: "contract"}
    if len(raw) != 35 or raw[0] not in kinds or kinds[raw[0]] != expect:
        raise Fail("strkey_invalid")
    if struct.unpack("<H", raw[33:])[0] != crc16(raw[:33]):
        raise Fail("strkey_invalid")
    return {"type": kinds[raw[0]], "payload_hex": raw[1:33].hex()}


def op_network_id(i):
    return {"network_id": sha(i["passphrase"])}


def op_network_name(i):
    return {"name": NET.get(i["passphrase"], i["passphrase"])}


def op_scval_bytes_xdr(i):
    v = i["hex"]
    if not (isinstance(v, str) and HEXB.fullmatch(v)):
        raise Fail("invalid_hex_bytes")
    d = bytes.fromhex(v)
    return {"xdr_hex": (struct.pack(">II", 13, len(d)) + d + b"\x00" * (-len(d) % 4)).hex()}


# ECMAScript WhiteSpace + LineTerminator (what JS String.prototype.trim removes).
_JSWS = set("\t\n\v\f\r \u00a0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a"
            "\u2028\u2029\u202f\u205f\u3000\ufeff")


def js_trim(s):
    a, b = 0, len(s)
    while a < b and s[a] in _JSWS:
        a += 1
    while b > a and s[b - 1] in _JSWS:
        b -= 1
    return s[a:b]


def op_network_check(i):
    w = i.get("wallet")
    w = js_trim(w) if isinstance(w, str) else ""
    if not w:
        raise Fail("wallet_network_unavailable")
    if w == i["contract"]:
        return {"match": True}
    raise Fail("network_mismatch", wallet_network=NET.get(w, w), contract_network=NET.get(i["contract"], i["contract"]))


# ------------------------------------------------------------------ status / verification
def op_proof_status(i):
    r, now = i["record"], i["now"]
    if r is None:
        return {"status": "not_found"}
    if r["status"] == 2:
        return {"status": "revoked"}
    if r["status"] == 3:
        return {"status": "expired"}
    if r["status"] != 1:
        raise Fail("unknown_status")
    if r["expires_at"] > 0 and now > r["expires_at"]:
        return {"status": "expired"}
    return {"status": "valid"}


EXIT = {"valid": 0, "expired": 1, "revoked": 2, "not_found": 3, "network_mismatch": 4, "contract_mismatch": 5,
        "pending": 6, "failed": 7, "error": 8}


def op_verification_classify(i):
    m, tx, rec, now = i["manifest"], i["transaction"], i["chain_record"], i["now_seconds"]
    if tx.get("contractMatch") is False:
        return {"result": "contract_mismatch"}
    if tx["status"] == "missing":
        res = "not_found"
    elif tx["status"] == "failed":
        res = "failed"
    elif tx["status"] == "pending":
        res = "pending"
    elif rec is None:
        res = "not_found"
    else:
        res = {1: "valid", 2: "revoked", 3: "expired"}.get(rec["status"], "error")
    if rec is None:
        return {"result": res}
    if (rec["videoHash"].lower() != m["videoHash"].lower() or rec["metadataHash"].lower() != m["metadataHash"].lower()
            or rec["tier"] != {"silent": 1, "source": 2, "seal": 3}[m["tier"]]):
        return {"result": "error"}
    if res == "valid" and rec.get("expiresAt") and int(rec["expiresAt"]) > 0 and int(rec["expiresAt"]) < now:
        res = "expired"
    return {"result": res}


def op_result_exit_code(i):
    return {"exit_code": EXIT.get(i["result"], 8)}


# ------------------------------------------------------------------ events
FORBIDDEN = {"nullifier", "witness", "proof_bytes", "public_inputs", "credential_secret", "private_key", "seed",
             "media", "raw_metadata", "envelope_bytes"}
EVENTS = {
    "proof_registered": (["proof", "reg"], [("video_hash", "hex32"), ("tier", "u32:1:3"), ("status", "u32:1:3"), ("batch_size", "u32")]),
    "proof_revoked": (["proof", "revoke"], [("status", "u32:2:2")]),
    "metadata_envelope_bound": (["metadata", "envelope", "bound"], [("version", "u32:1:2"), ("metadata_hash", "hex32"), ("bound_at", "u64")]),
    "metadata_envelope_upgraded": (["metadata", "envelope", "upgraded"], [("previous", "u32:1:2"), ("current", "u32:1:2"), ("metadata_hash", "hex32")]),
    "proof_history": (["proof", "history"], [("action", "u32"), ("timestamp", "u64"), ("actor", "address?"), ("reason_code", "u32:0:255")]),
    "lineage_registered": (["lineage", "reg"], [("manifest_digest", "hex32"), ("actor", "address"), ("operation_type", "string"),
                                              ("depth", "u32:1:4"), ("parent_commitments", "hex32[]")]),
}


def _scan(o):
    if isinstance(o, dict):
        for k, v in o.items():
            if k.lower() in FORBIDDEN:
                raise Fail("event_privacy_violation", field=k)
            _scan(v)
    elif isinstance(o, list):
        for v in o:
            _scan(v)


def _address(v):
    try:
        op_strkey_decode({"strkey": v, "expect": "account"})
        return True
    except Fail:
        try:
            op_strkey_decode({"strkey": v, "expect": "contract"})
            return True
        except Fail:
            return False


def _field(name, kind, v):
    def t():
        raise Fail("event_field_type", field=name)

    def r():
        raise Fail("event_value_out_of_range", field=name)

    if kind == "hex32":
        if not (isinstance(v, str) and HEX32_LOWER.fullmatch(v)):
            t()
    elif kind.startswith("u32"):
        if not is_int(v):
            t()
        lo, hi = 0, U32
        if ":" in kind:
            _, a, b = kind.split(":")
            lo, hi = int(a), int(b)
        if v < 0 or v > U32 or v < lo or v > hi:
            r()
    elif kind == "u64":
        if not (isinstance(v, str) and DEC.fullmatch(v)):
            t()
        if int(v) > U64:
            r()
    elif kind in ("address", "address?"):
        if v is None and kind == "address?":
            return
        if not (isinstance(v, str) and _address(v)):
            t()
    elif kind == "string":
        if not isinstance(v, str):
            t()
    elif kind == "hex32[]":
        if not isinstance(v, list) or not all(isinstance(x, str) and HEX32_LOWER.fullmatch(x) for x in v):
            t()
        if not 1 <= len(v) <= 4:
            r()


def op_event_validate(i):
    topics, data = i["topics"], i["data"]
    _scan(data)
    if not isinstance(topics, list):
        raise Fail("event_unknown")
    hit = next(((n, s) for n, s in EVENTS.items() if topics[: len(s[0])] == s[0] and len(topics) >= len(s[0])), None)
    if not hit:
        raise Fail("event_unknown")
    name, (prefix, fields) = hit
    if len(topics) != len(prefix) + 1 or not (isinstance(topics[-1], str) and HEX32_LOWER.fullmatch(topics[-1])):
        raise Fail("event_topics_invalid")
    if not isinstance(data, dict):
        raise Fail("event_field_type")
    for f, _ in fields:
        if f not in data:
            raise Fail("event_field_missing", field=f)
    for k in data:
        if k not in dict(fields):
            raise Fail("event_field_unexpected", field=k)
    for f, kind in fields:
        _field(f, kind, data[f])
    if name == "metadata_envelope_upgraded" and not data["current"] > data["previous"]:
        raise Fail("event_value_out_of_range", field="current")
    return {"event": name}


# ------------------------------------------------------------------ lineage
def op_lineage_validate(i):
    ps, out, depth = i["parents"], i["output_digest"], i["depth"]
    if len(ps) == 0:
        raise Fail("lineage_empty_parents")
    if len(ps) > 4:
        raise Fail("lineage_fan_out_exceeded")
    if depth > 4:
        raise Fail("lineage_too_deep")
    if depth == 0:
        raise Fail("invalid_lineage")
    for p in ps:
        if p["id"] == out:
            raise Fail("lineage_cycle")
        if p["kind"] == "proof":
            if p["status"] != "valid":
                raise Fail("lineage_parent_unavailable")
        elif p["kind"] != "lineage":
            raise Fail("invalid_lineage")
    if i["output_registered"]:
        raise Fail("duplicate_lineage")
    return {"valid": True}


OPS_OK = {"crop", "transcode", "blur", "redact", "compose"}


def op_lineage_manifest_create(i):
    if i["operationType"] not in OPS_OK:
        raise Fail("unsupported_operation")
    m = dict(i, protocol="harpocrates", version=2)
    return out_canon(m)


LIN_FIELDS = {"protocol", "version", "parentProofIds", "operationType", "parametersDigest", "toolIdentity", "toolVersion",
              "outputDigest", "network", "actorAddress"}


def op_lineage_manifest_parse(i):
    try:
        m = json.loads(i["text"])
    except (ValueError, RecursionError):
        raise Fail("invalid_json")
    if not isinstance(m, dict):
        raise Fail("not_object")
    if any(k not in LIN_FIELDS for k in m):
        raise Fail("unsupported_field")
    if m.get("protocol") != "harpocrates":
        raise Fail("bad_protocol")
    if not (is_int(m.get("version")) and m["version"] == 2):
        raise Fail("unsupported_version")
    ps = m.get("parentProofIds")
    if not isinstance(ps, list):
        raise Fail("bad_hex32")
    if not ps:
        raise Fail("lineage_empty_parents")
    if len(ps) > 4:
        raise Fail("lineage_fan_out_exceeded")
    if not all(isinstance(p, str) and HEX32.fullmatch(p) for p in ps):
        raise Fail("bad_hex32")
    if m.get("operationType") not in OPS_OK:
        raise Fail("unsupported_operation")
    for f in ("outputDigest", "parametersDigest"):
        if not (isinstance(m.get(f), str) and HEX32.fullmatch(m[f])):
            raise Fail("bad_hex32")
    c = canon(m)
    if len(c.encode("utf-8")) > 4096:
        raise Fail("payload_too_large")
    return {"canonical": c, "sha256": sha(c)}


# ------------------------------------------------------------------ error ABI
_ABI = None


def _abi():
    global _ABI
    if _ABI is None:
        p = Path(os.environ.get("HPX_ERROR_ABI", Path(__file__).resolve().parents[3] / "contracts" / "ERROR_ABI.md"))
        _ABI = {}
        if p.exists():
            for c, n, k, r in re.findall(r"^\|\s*(\d+)\s*\|\s*`(\w+)`\s*\|\s*(\w+)\s*\|\s*(yes|no)\s*\|", p.read_text(encoding="utf-8"), re.M):
                _ABI[int(c)] = (n, k, r == "yes")
    return _ABI


def op_classify_error(i):
    t = _abi()
    if not t:
        raise Fail("unsupported_op")
    c = i["code"]
    if not is_int(c) or c not in t:
        raise Fail("unknown_error_code")
    n, k, r = t[c]
    return {"name": n, "class": k, "retryable": r, "reason_code": re.sub(r"(?<!^)(?=[A-Z])", "_", n).lower()}


# ------------------------------------------------------------------ public inputs (hpx-vi/1)
SW_DOMAIN = bytes.fromhex("4aa038f0a27b6675d7122ae2d4e197c21e83fbe30143a5c83ff35c9514b92c55")
RV_DOMAIN = bytes.fromhex("00000000000000484152504f4352415445535f5245564f434154494f4e5f5631")


def _hex(v):
    if not (isinstance(v, str) and HEXB.fullmatch(v)):
        raise Fail("malformed_hex")
    return bytes.fromhex(v)


def op_decode_public_inputs_hex(i):
    return {"bytes": len(_hex(i["value"]))}


def op_classify_public_inputs(i):
    pi, proof = _hex(i["public_inputs_hex"]), _hex(i["proof_hex"])
    sch = i["schema"]
    if sch not in ("silent_witness/v1", "revocation_witness/v1"):
        raise Fail("unknown_schema")
    sw = sch == "silent_witness/v1"
    if len(pi) != (160 if sw else 128):
        raise Fail("length")
    f = [pi[k:k + 32] for k in range(0, len(pi), 32)]
    z = bytes(32)
    if sw:
        if f[0][:16] != z[:16] or f[1][:16] != z[:16]:
            raise Fail("padding")
        check = f[:4]
    else:
        check = f
    if any(int.from_bytes(x, "big") >= BN254_R for x in check):
        raise Fail("non_canonical_field")
    for idx in ((2, 3, 4) if sw else (0, 1, 3)):
        if f[idx] == z:
            raise Fail("zero_field")
    if sw and f[4] != SW_DOMAIN or (not sw and f[2] != RV_DOMAIN):
        raise Fail("domain_mismatch")
    if len(proof) < 64:
        raise Fail("proof_undersize")
    if len(proof) > 65536:
        raise Fail("proof_oversize")
    return {"accepted": True}


HANDLERS = {n[3:]: f for n, f in list(globals().items()) if n.startswith("op_")}


def handle(req):
    op = req.get("op")
    if op == "hello":
        return {"protocol": PROTOCOL, "ops": sorted(HANDLERS),
                "implementation": {"name": "reference-py", "version": "1.0.0", "language": "python"}}
    if op not in HANDLERS:
        raise Fail("unsupported_op")
    return HANDLERS[op](req["input"])


def main():
    for line in sys.stdin:
        try:
            req = json.loads(line)
            rid = req.get("id")
        except Exception:  # noqa: BLE001
            print(json.dumps({"id": None, "ok": False, "code": "bad_request"}), flush=True)
            continue
        try:
            resp = {"id": rid, "ok": True, "output": handle(req)}
        except Fail as f:
            resp = {"id": rid, "ok": False, "code": f.code}
            if f.detail:
                resp["detail"] = f.detail
        except Exception:  # noqa: BLE001 - never leak exception text (may contain input)
            resp = {"id": rid, "ok": False, "code": "internal_error"}
        print(json.dumps(resp, sort_keys=True, ensure_ascii=True), flush=True)


if __name__ == "__main__":
    main()
