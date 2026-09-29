"""Signed verification receipts (`harpocrates-verification-receipt` v1).

Signatures are ECDSA P-256 / SHA-256 in IEEE P1363 form (r || s, 64 bytes,
base64url without padding) -- what WebCrypto produces and verifies. DER is the
classic cross-language trap and is exercised as a negative case.

The signing keys are derived from public labels (a *test-only* construction,
never a literal secret), signatures use RFC 6979 deterministic nonces so a
regeneration is byte-identical, and only PUBLIC JWKs are written to fixtures.
"""
import base64
import hashlib
import json

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from .common import Area, syn, sha256_hex
from .metadata import canon

NET = "Test SDF Network ; September 2015"
NOW = "2026-02-01T00:00:00.000Z"
CONTRACT_ID = None  # set by gen.py

_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


def b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def make_key(label: str):
    d = int.from_bytes(hashlib.sha256(b"hpx-conformance/v1/test-key/" + label.encode()).digest(), "big") % (_N - 1) + 1
    key = ec.derive_private_key(d, ec.SECP256R1())
    n = key.public_key().public_numbers()
    jwk = {"kty": "EC", "crv": "P-256", "x": b64u(n.x.to_bytes(32, "big")), "y": b64u(n.y.to_bytes(32, "big"))}
    return key, jwk


def sign_p1363(key, message: str) -> str:
    der = key.sign(message.encode("utf-8"), ec.ECDSA(hashes.SHA256(), deterministic_signing=True))
    r, s = decode_dss_signature(der)
    return b64u(r.to_bytes(32, "big") + s.to_bytes(32, "big"))


def sign_der(key, message: str) -> str:
    der = key.sign(message.encode("utf-8"), ec.ECDSA(hashes.SHA256(), deterministic_signing=True))
    return b64u(der)


def payload(**over):
    p = {
        "protocol": "harpocrates-verification-receipt", "version": 1, "result": "verified",
        "verifiedAt": "2026-01-15T12:00:00.000Z", "proofId": syn("rcpt/proof"),
        "videoHash": syn("rcpt/video"), "metadataHash": syn("rcpt/meta"), "tier": "silent",
        "networkPassphrase": NET, "contractId": CONTRACT_ID, "ledgerSequence": 123456,
        "transactionHash": syn("rcpt/tx"), "circuitVersion": "1.0.0", "verifierVersion": "1.0.0",
        "signer": {"keyId": "conformance-key-1", "algorithm": "ECDSA_P256_SHA256"},
    }
    p.update(over)
    return p


def build() -> Area:
    a = Area("receipt", "Signed verification receipts: structure, signature, key validity, QR transport")
    k1, jwk1 = make_key("k1")
    k2, jwk2 = make_key("k2")
    keys = {"conformance-key-1": jwk1}

    def signed(p, key=k1):
        return dict(p, signature=sign_p1363(key, canon(p)))

    def verify(cid, receipt, desc, *, ok=False, code=None, opts=None, ks=None, tier="required", why=None):
        inp = {"receipt": receipt, "keys": keys if ks is None else ks, "options": dict({"now": NOW}, **(opts or {}))}
        if ok:
            a.add(cid, "receipt_verify", inp, ok={"valid": True}, desc=desc, tier=tier, why=why)
        else:
            a.add(cid, "receipt_verify", inp, code=code, desc=desc, tier=tier, why=why)

    good = signed(payload())
    verify("rc-pos-001-verified", good, "A well-formed, correctly signed receipt.", ok=True)
    verify("rc-pos-002-unverified-null-fields",
           signed(payload(result="unverified", ledgerSequence=None, transactionHash=None)),
           "An 'unverified' receipt may carry null ledger and transaction hash.", ok=True)
    verify("rc-pos-003-second-key-selected", signed(payload(signer={"keyId": "conformance-key-2", "algorithm": "ECDSA_P256_SHA256"}), k2),
           "The key is selected by signer.keyId.", ok=True, ks={"conformance-key-1": jwk1, "conformance-key-2": jwk2})
    verify("rc-pos-004-expected-network-match", good, "Expected network equals the receipt network.", ok=True,
           opts={"expectedNetworkPassphrase": NET})
    verify("rc-pos-005-expected-proof-match", good, "Expected proof id equals the receipt proof id.", ok=True,
           opts={"expectedProofId": syn("rcpt/proof")})
    verify("rc-pos-006-key-window-inclusive", good, "verifiedAt exactly on notBefore and notAfter (and now == notAfter) is valid.", ok=True,
           opts={"now": "2026-01-15T12:00:00.000Z",
                 "keyValidity": {"conformance-key-1": {"notBefore": "2026-01-15T12:00:00.000Z", "notAfter": "2026-01-15T12:00:00.000Z"}}})
    verify("rc-pos-007-unicode-contract-field", signed(payload(verifierVersion="v1-caf\u00e9-\U0001F600")),
           "Non-ASCII in a string field is signed as literal UTF-8.", ok=True)

    def neg(n, slug, receipt, code, desc, **kw):
        verify(f"rc-neg-{n:03d}-{slug}", receipt, desc, code=code, **kw)

    p = payload()
    flipped = dict(good, result="unverified")
    neg(1, "tampered-result", flipped, "receipt_signature_invalid", "Flipping result invalidates the signature.")
    tp = list(syn("rcpt/proof"))
    tp[0] = "0" if tp[0] != "0" else "1"
    neg(2, "tampered-proof-id", dict(good, proofId="".join(tp)), "receipt_signature_invalid", "One changed hex digit invalidates the signature.")
    neg(3, "der-signature", dict(p, signature=sign_der(k1, canon(p))), "receipt_signature_invalid",
        "An ASN.1 DER signature is not the IEEE P1363 r||s form WebCrypto verifies.")
    neg(4, "wrong-key", signed(p, k2), "receipt_signature_invalid", "Signed by a different key than the one registered under keyId.")
    neg(5, "unknown-key-id", signed(payload(signer={"keyId": "nobody", "algorithm": "ECDSA_P256_SHA256"})), "receipt_key_unknown",
        "signer.keyId has no registered key.")
    neg(6, "missing-signature", dict(p), "receipt_signature_missing", "No signature member.")
    neg(7, "empty-signature", dict(p, signature=""), "receipt_signature_missing", "Empty signature.")
    sig = good["signature"]
    neg(8, "padded-signature", dict(p, signature=sig + "=="), "receipt_signature_malformed", "base64url must be unpadded.")
    neg(9, "standard-base64-alphabet", dict(p, signature=sig[:10] + "+" + sig[11:]), "receipt_signature_malformed",
        "'+' and '/' belong to standard base64, not base64url.")
    neg(10, "protocol-wrong", signed(dict(p, protocol="something-else")), "receipt_unsupported_version", "Wrong protocol id.")
    neg(11, "version-2", signed(dict(p, version=2)), "receipt_unsupported_version", "Future receipt version fails closed.")
    neg(12, "result-pending", signed(dict(p, result="pending")), "receipt_result_invalid", "Only verified/unverified exist on signed receipts.")
    for i, f in enumerate(("proofId", "videoHash", "metadataHash")):
        neg(13 + i, f"digest-short-{f}", signed(dict(p, **{f: syn("x")[:-1]})), "receipt_digest_invalid", f"{f} is not 32-byte hex.")
    neg(16, "digest-trailing-newline", signed(dict(p, proofId=syn("rcpt/proof") + "\n")), "receipt_digest_invalid",
        "Trailing newline after 64 hex chars.")
    neg(17, "tier-unknown", signed(dict(p, tier="gold")), "receipt_tier_invalid", "Unknown tier.")
    neg(18, "circuit-version-empty", signed(dict(p, circuitVersion="")), "receipt_metadata_incomplete", "Empty circuitVersion.")
    neg(19, "verifier-version-blank", signed(dict(p, verifierVersion="   ")), "receipt_metadata_incomplete", "Whitespace-only verifierVersion.")
    neg(20, "network-empty", signed(dict(p, networkPassphrase="")), "receipt_metadata_incomplete", "Empty networkPassphrase.")
    neg(21, "signer-algorithm", signed(dict(p, signer={"keyId": "conformance-key-1", "algorithm": "ES256"})), "receipt_signer_invalid", "Algorithm id must be ECDSA_P256_SHA256.")
    neg(22, "signer-key-id-empty", signed(dict(p, signer={"keyId": "", "algorithm": "ECDSA_P256_SHA256"})), "receipt_signer_invalid", "Empty keyId.")
    neg(23, "ledger-fractional", signed(dict(p, ledgerSequence=1.5)), "receipt_ledger_invalid", "Fractional ledger sequence.")
    neg(24, "ledger-string", signed(dict(p, ledgerSequence="5")), "receipt_ledger_invalid", "String ledger sequence.")
    neg(25, "tx-hash-short", signed(dict(p, transactionHash="abc")), "receipt_txhash_invalid", "Malformed transaction hash.")
    neg(26, "verified-at-empty", signed(dict(p, verifiedAt="")), "receipt_time_invalid", "Empty verifiedAt.")
    neg(27, "verified-at-garbage", signed(dict(p, verifiedAt="yesterday-ish")), "receipt_time_invalid", "Unparseable verifiedAt.")
    neg(28, "network-mismatch", good, "receipt_network_mismatch", "Expected network differs from the receipt's.",
        opts={"expectedNetworkPassphrase": "Public Global Stellar Network ; September 2015"})
    neg(29, "proof-mismatch", good, "receipt_proof_mismatch", "Expected proof id differs.", opts={"expectedProofId": syn("other")})
    neg(30, "key-not-yet-valid", good, "receipt_key_stale", "verifiedAt is before the key's notBefore.",
        opts={"keyValidity": {"conformance-key-1": {"notBefore": "2026-01-16T00:00:00.000Z"}}})
    neg(31, "key-expired-before-signing", good, "receipt_key_stale", "verifiedAt is after the key's notAfter.",
        opts={"keyValidity": {"conformance-key-1": {"notAfter": "2026-01-14T00:00:00.000Z"}}})
    neg(32, "key-expired-now", good, "receipt_key_stale", "The key has expired as of `now`, even though it was valid at verifiedAt.",
        opts={"now": "2026-03-01T00:00:00.000Z", "keyValidity": {"conformance-key-1": {"notAfter": "2026-02-01T00:00:00.000Z"}}})
    neg(33, "order-network-before-key", signed(payload(signer={"keyId": "nobody", "algorithm": "ECDSA_P256_SHA256"})),
        "receipt_network_mismatch", "Check order: network is compared before the signer key is looked up.",
        opts={"expectedNetworkPassphrase": "Public Global Stellar Network ; September 2015"})
    neg(34, "order-structure-before-signature", dict(p, tier="gold", signature="!!not-base64!!"), "receipt_tier_invalid",
        "Check order: payload structure is validated before the signature is decoded.")
    neg(35, "order-signature-missing-before-network", dict(p), "receipt_signature_missing",
        "Check order: a missing signature is reported before an expected-network mismatch.",
        opts={"expectedNetworkPassphrase": "x"})

    # ---- size limit: 8192 UTF-8 bytes of canonical JSON, bytes not characters ----
    def sized(pad_char, target_bytes, extra=None):
        # Multi-byte padding can only reach targets of the right parity; try target, then target + 1.
        blen = len(pad_char.encode("utf-8"))
        for target in range(target_bytes, target_bytes + blen):
            pad = 0
            for _ in range(8):
                pp = payload(circuitVersion="1" + pad_char * pad, **(extra or {}))
                full = signed(pp)
                size = len(canon(full).encode("utf-8"))
                if size == target:
                    return full
                if (target - size) % blen:
                    break
                pad += (target - size) // blen
        raise AssertionError("could not size receipt")

    at_limit = sized("a", 8192)
    over = sized("a", 8193)
    verify("rc-pos-008-size-at-limit", at_limit, "Canonical receipt of exactly 8192 bytes is accepted.", ok=True)
    neg(36, "size-over-limit", over, "receipt_too_large", "8193 canonical bytes is rejected.")
    # 8192-byte budget measured in UTF-8 bytes, not characters: > 8192 bytes but < 8192 characters.
    mb = sized("\u00e9", 8300)
    assert len(canon(mb)) < 8192 < len(canon(mb).encode("utf-8"))
    neg(37, "size-counts-bytes-not-chars", mb, "receipt_too_large",
        "Fewer than 8192 characters but more than 8192 UTF-8 bytes: the limit is in bytes.")
    neg(38, "size-before-structure", dict(over, tier="golden"), "receipt_too_large", "Check order: size precedes structure.")

    # ---- advisory hardening ----
    verify("rc-adv-001-verified-at-year-only", signed(payload(verifiedAt="2026")),
           "Deployed code accepts anything `new Date()` parses; require RFC 3339.",
           code="receipt_time_invalid", tier="advisory", why="proposed_hardening")
    verify("rc-adv-002-ledger-negative", signed(payload(ledgerSequence=-1)),
           "A ledger sequence is a u32; deployed code accepts any integer.",
           code="receipt_ledger_invalid", tier="advisory", why="proposed_hardening")
    verify("rc-adv-003-ledger-above-u32", signed(payload(ledgerSequence=4294967296)),
           "Above u32::MAX.", code="receipt_ledger_invalid", tier="advisory", why="proposed_hardening")

    # ---- QR transport: base64url(canonical JSON), <= 4096 characters ----
    def qr_ok(cid, receipt, desc):
        c = canon(receipt)
        a.add(cid, "receipt_qr_decode", {"encoded": b64u(c.encode("utf-8"))},
              ok={"canonical": c, "sha256": sha256_hex(c)}, desc=desc)
        a.add(cid.replace("decode", "encode").replace("-qr-", "-qre-"), "receipt_qr_encode", {"receipt": receipt},
              ok={"encoded": b64u(c.encode("utf-8"))}, desc=desc + " (encode direction)")

    qr_ok("rc-qr-decode-001-roundtrip", good, "A signed receipt round-trips through the QR encoding.")
    qr_ok("rc-qr-decode-002-unicode", signed(payload(verifierVersion="caf\u00e9")), "Non-ASCII survives the QR round trip byte-exactly.")
    enc = b64u(canon(good).encode())

    def qr_bad(n, slug, encoded, code, desc):
        a.add(f"rc-qr-neg-{n:03d}-{slug}", "receipt_qr_decode", {"encoded": encoded}, code=code, desc=desc)

    qr_bad(1, "standard-alphabet", enc[:8] + "+/" + enc[10:], "qr_invalid_encoding", "'+' and '/' are not base64url.")
    qr_bad(2, "padded", enc + "=", "qr_invalid_encoding", "Padding is not allowed.")
    qr_bad(3, "length-mod-4-is-1", enc[: 4 * (len(enc) // 4 - 1) + 1], "qr_invalid_encoding", "A base64 length of 1 mod 4 is impossible.")
    qr_bad(4, "not-json", b64u(b"this is not json"), "qr_invalid_encoding", "Decodes, but is not JSON.")
    qr_bad(5, "empty", "", "qr_invalid_encoding", "Empty payload.")
    qr_bad(6, "whitespace", enc[:20] + "\n" + enc[20:], "qr_invalid_encoding", "Embedded newline.")
    qr_bad(7, "over-qr-limit", "A" * 4097, "qr_too_large", "4097 characters exceeds the QR budget.")
    qr_bad(8, "utf8-invalid", b64u(b"\xff\xfe{}"), "qr_invalid_encoding", "Not valid UTF-8 JSON.")
    big = sized("a", 3200)
    assert len(b64u(canon(big).encode())) > 4096
    a.add("rc-qr-neg-009-encode-over-limit", "receipt_qr_encode", {"receipt": big}, code="qr_too_large",
          desc="A 3200-byte receipt is a valid receipt but exceeds the 4096-character QR budget once base64url-encoded.")
    return a
