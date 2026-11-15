"""Focused tests for deterministic backend and CLI receipt interoperability (#1083)."""

from __future__ import annotations

import json
import shutil
import subprocess
from datetime import UTC, datetime
from pathlib import Path

from verification_receipt import (
    build_unsigned_receipt_payload,
    build_verification_receipt,
    canonicalize_receipt_json,
    decode_receipt_from_qr,
    encode_receipt_for_qr,
    serialize_signed_receipt,
    verify_signed_verification_receipt,
)

FIXTURE_PATH = Path(__file__).resolve().parent / "fixtures" / "verification_receipt_interop_vectors.json"
CLI_SIGNED_RECEIPT_TS = Path(__file__).resolve().parents[1] / "cli" / "src" / "signed-receipt.ts"


def _load_vectors() -> dict[str, object]:
    return json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))


def test_backend_matches_canonical_payload_qr_and_signature_vectors() -> None:
    doc = _load_vectors()
    keys = doc["keys"]
    assert isinstance(keys, dict)
    valid_vectors = doc["validVectors"]
    assert isinstance(valid_vectors, list) and len(valid_vectors) >= 2

    for vec in valid_vectors:
        assert isinstance(vec, dict)
        inp = vec["input"]
        assert isinstance(inp, dict)

        built_input = build_verification_receipt(inp, result=inp["result"])
        built_input["verifiedAt"] = inp["verifiedAt"]

        unsigned = build_unsigned_receipt_payload(built_input, key_id="verifier-interop-2026-07")
        assert unsigned == vec["unsignedPayload"]
        assert canonicalize_receipt_json(unsigned) == vec["expectedUnsignedCanonicalJson"]

        signed = vec["signedReceipt"]
        assert isinstance(signed, dict)
        assert serialize_signed_receipt(signed) == vec["expectedSignedCanonicalJson"]
        assert encode_receipt_for_qr(signed) == vec["expectedQrPayload"]
        assert decode_receipt_from_qr(vec["expectedQrPayload"]) == signed

        verdict = verify_signed_verification_receipt(
            signed,
            keys=keys,
            expected_network_passphrase=inp["networkPassphrase"],
            expected_proof_id=inp["proofId"],
            now=datetime(2026, 8, 2, tzinfo=UTC),
        )
        assert verdict["valid"] is True


def test_backend_explicitly_rejects_mutated_statements_and_stale_signers() -> None:
    doc = _load_vectors()
    keys = doc["keys"]
    assert isinstance(keys, dict)
    mutated_vectors = doc["mutatedVectors"]
    assert isinstance(mutated_vectors, list) and len(mutated_vectors) >= 6

    for mut in mutated_vectors:
        assert isinstance(mut, dict)
        verdict = verify_signed_verification_receipt(mut["receipt"], keys=keys)
        assert verdict["valid"] is False, f"expected {mut['id']} to fail"
        assert mut["expectedReasonSubstring"].lower() in str(verdict["reason"]).lower()

    valid_receipt = doc["validVectors"][0]["signedReceipt"]  # type: ignore[index]
    stale_verdict = verify_signed_verification_receipt(
        valid_receipt,
        keys=keys,
        key_validity={"verifier-interop-2026-07": {"notAfter": "2026-07-25T00:00:00.000Z"}},
        now=datetime(2026, 7, 26, 12, 0, tzinfo=UTC),
    )
    assert stale_verdict["valid"] is False
    assert "stale" in str(stale_verdict["reason"]).lower()

    extra_field_verdict = verify_signed_verification_receipt(
        {**valid_receipt, "unexpectedClaim": "injected"},
        keys=keys,
    )
    assert extra_field_verdict["valid"] is False


def test_cli_signed_receipt_runtime_agrees_on_shared_vectors() -> None:
    node_bin = shutil.which("node")
    if node_bin is None or not CLI_SIGNED_RECEIPT_TS.exists():
        return

    script = f"""
import {{ readFileSync }} from 'node:fs';
import {{ pathToFileURL }} from 'node:url';
const mod = await import(pathToFileURL({json.dumps(str(CLI_SIGNED_RECEIPT_TS))}).href);
const doc = JSON.parse(readFileSync({json.dumps(str(FIXTURE_PATH))}, 'utf8'));
for (const vec of doc.validVectors) {{
  if (mod.serializeVerificationReceipt(vec.signedReceipt) !== vec.expectedSignedCanonicalJson) {{
    throw new Error('canonical JSON mismatch for ' + vec.id);
  }}
  if (mod.encodeReceiptForQr(vec.signedReceipt) !== vec.expectedQrPayload) {{
    throw new Error('QR payload mismatch for ' + vec.id);
  }}
  const res = await mod.verifyVerificationReceipt(vec.signedReceipt, {{ keys: doc.keys }});
  if (!res.valid) throw new Error('valid vector rejected: ' + vec.id + ' ' + res.reason);
}}
for (const mut of doc.mutatedVectors) {{
  const res = await mod.verifyVerificationReceipt(mut.receipt, {{ keys: doc.keys }});
  if (res.valid) throw new Error('mutated vector accepted: ' + mut.id);
  if (!res.reason.toLowerCase().includes(mut.expectedReasonSubstring.toLowerCase())) {{
    throw new Error('unexpected reason for ' + mut.id + ': ' + res.reason);
  }}
}}
console.log('CLI_INTEROP_OK');
"""
    proc = subprocess.run(
        [node_bin, "--experimental-strip-types", "--input-type=module", "-e", script],
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    assert proc.returncode == 0, f"CLI interop failed: {proc.stderr}"
    assert "CLI_INTEROP_OK" in proc.stdout
