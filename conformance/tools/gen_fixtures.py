#!/usr/bin/env python3
"""Generate (or verify) the versioned conformance fixtures.

    python conformance/tools/gen_fixtures.py            # write fixtures + manifest.json
    python conformance/tools/gen_fixtures.py --check    # CI: regenerate in memory, fail on any drift

Policy ("prevent silent regeneration"): fixtures/v1 is APPEND-ONLY. A regeneration
may add case ids; it may not change or delete an existing case. Doing so requires
`--allow-breaking`, and that flag additionally requires bumping SUITE_VERSION in
tools/fx/common.py (and FIXTURE_VERSION for a new fixtures/vN directory), so a
breaking edit is always visible in review as a version change.

Only the generator needs the `cryptography` package (to produce deterministic
RFC 6979 receipt signatures). Running the suite does not.
"""
import argparse
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]          # conformance/
REPO = ROOT.parent
sys.path.insert(0, str(ROOT))

from tools.fx import common, canonical, events_lineage, manifest, metadata, receipt, status, stellar  # noqa: E402

REASON_DOCS = {
    # canonical json
    "invalid_json": "Input text is not valid JSON.",
    "unsupported_number": "Number is not an integer within +/-(2^53-1).",
    "duplicate_key": "An object repeats a key.",
    "invalid_unicode": "A string contains a lone surrogate.",
    "nesting_too_deep": "Nesting exceeds 64 levels.",
    # metadata
    "not_object": "The value is not a JSON object.",
    "missing_field": "A required member is absent.",
    "bad_protocol": "protocol is not the expected literal.",
    "bad_version": "version is not an acceptable number.",
    "bad_tier": "tier is not one of silent, source, seal.",
    "bad_source_hash": "sourceHash is not 32-byte hex.",
    "bad_proof_id": "proofId is not 32-byte hex.",
    "bad_timestamp": "timestamp is not a valid date-time.",
    "unsupported_metadata_envelope_version": "Envelope version is 0, above the supported maximum, or a downgrade (ABI #68).",
    "metadata_envelope_not_found": "No proof or envelope for the id (ABI #70).",
    "invalid_metadata_envelope": "Envelope hash is zero (ABI #69).",
    "metadata_envelope_hash_mismatch": "Envelope hash differs from the proof's metadata hash (ABI #71).",
    # manifest
    "unsupported_field": "A closed object contains an unknown member.",
    "unsupported_version": "Manifest version is not supported.",
    "bad_string_field": "A required string member is missing, non-string, or empty.",
    "bad_hex32": "A digest member is not 32-byte hex.",
    "bad_scope_epoch": "verifierScope or epoch is malformed.",
    "bad_scope_name": "scopeName is not a string of at most 128 UTF-16 code units.",
    "bad_disclosure": "selectiveDisclosure is malformed.",
    # receipt
    "receipt_too_large": "Canonical receipt exceeds 8192 UTF-8 bytes.",
    "receipt_unsupported_version": "Receipt protocol or version is not recognised.",
    "receipt_result_invalid": "result is not verified/unverified.",
    "receipt_digest_invalid": "A receipt digest is not 32-byte hex.",
    "receipt_tier_invalid": "Receipt tier is invalid.",
    "receipt_metadata_incomplete": "A required receipt string is empty.",
    "receipt_signer_invalid": "signer.keyId or signer.algorithm is invalid.",
    "receipt_ledger_invalid": "ledgerSequence is not an integer or null.",
    "receipt_txhash_invalid": "transactionHash is not 32-byte hex or null.",
    "receipt_time_invalid": "verifiedAt is not a valid date-time.",
    "receipt_signature_missing": "No signature present.",
    "receipt_signature_malformed": "Signature is not unpadded base64url.",
    "receipt_signature_invalid": "Signature does not verify.",
    "receipt_network_mismatch": "Receipt network differs from the expected network.",
    "receipt_proof_mismatch": "Receipt proof id differs from the expected proof id.",
    "receipt_key_stale": "Signer key was not valid at verification time or has expired.",
    "receipt_key_unknown": "No key is registered for signer.keyId.",
    "qr_too_large": "QR payload exceeds 4096 characters.",
    "qr_invalid_encoding": "QR payload is not base64url canonical JSON.",
    # stellar
    "invalid_hex32": "Not a 64-character hex string.",
    "invalid_hex_bytes": "Not an even-length hex string.",
    "invalid_byte": "A byte value is outside 0..255.",
    "strkey_invalid": "Not a valid strkey of the expected type.",
    "wallet_network_unavailable": "The wallet reported no network.",
    "network_mismatch": "Wallet and contract networks differ.",
    # status / events / lineage / abi
    "unknown_status": "Stored status is not 1, 2 or 3.",
    "event_privacy_violation": "An event carries a field that may hold private material.",
    "event_unknown": "Topics do not identify a known event.",
    "event_topics_invalid": "Topic list has the wrong shape.",
    "event_field_missing": "A schema field is absent.",
    "event_field_unexpected": "A field outside the schema is present.",
    "event_field_type": "A field has the wrong type or encoding.",
    "event_value_out_of_range": "A field is outside its allowed range.",
    "lineage_empty_parents": "Lineage has no parents (ABI #76).",
    "lineage_fan_out_exceeded": "More than 4 parents (ABI #60).",
    "lineage_too_deep": "Depth above 4 (ABI #59).",
    "invalid_lineage": "Depth 0 or an unknown parent (ABI #57).",
    "lineage_cycle": "Output equals a parent (ABI #58).",
    "lineage_parent_unavailable": "Parent proof is revoked or expired (ABI #77).",
    "duplicate_lineage": "Output digest already registered (ABI #78).",
    "unsupported_operation": "operationType is not in the supported set.",
    "payload_too_large": "Canonical manifest exceeds 4096 UTF-8 bytes.",
    "unknown_error_code": "The numeric error code is not assigned.",
}


def build_all():
    cid = stellar.contract_id("manifest-contract")
    manifest.CONTRACT_ID = cid
    receipt.CONTRACT_ID = cid
    areas = [
        canonical.build(), metadata.build_metadata(), manifest.build(), receipt.build(),
        stellar.build_encodings(), stellar.build_network_guard(), status.build_status(), status.build_verification(),
        events_lineage.build_events(), events_lineage.build_lineage(), events_lineage.build_errors(REPO),
    ]
    return areas


def case_digest(case) -> str:
    return hashlib.sha256(json.dumps(case, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()).hexdigest()


def external_corpora():
    entries = []
    for rel, role in (("zk/vectors/verifier_conformance_v1.json", "classify_public_inputs"),
                      ("zk/vectors/malformed_public_inputs_v1.json", "decode_public_inputs_hex")):
        p = REPO / rel
        entries.append({"path": rel, "role": role, "sha256": hashlib.sha256(p.read_bytes()).hexdigest()})
    return entries


def render(areas):
    files, cases, all_codes = {}, {}, {}
    for a in areas:
        doc = a.doc()
        files[f"fixtures/v{common.FIXTURE_VERSION}/{a.area}.json"] = common.dumps(doc)
        for c in a.cases:
            cases[c["id"]] = case_digest(c)
            if not c["expect"]["ok"]:
                all_codes.setdefault(c["expect"]["code"], a.area)
    missing = sorted(set(all_codes) - set(REASON_DOCS))
    assert not missing, f"reason codes without documentation: {missing}"
    codes = {k: {"first_area": all_codes[k], "meaning": REASON_DOCS[k]} for k in sorted(all_codes)}
    rc = {"format": "harpocrates.conformance.reason-codes", "suite_version": common.SUITE_VERSION, "codes": codes}
    files["reason-codes.json"] = common.dumps(rc)
    man = {
        "format": "harpocrates.conformance.manifest",
        "suite_version": common.SUITE_VERSION,
        "fixture_version": common.FIXTURE_VERSION,
        "adapter_protocol": "hpx-conformance-adapter/1",
        "policy": "fixtures/vN is append-only; changing or removing an existing case requires a version bump",
        "files": {p: hashlib.sha256(t.encode()).hexdigest() for p, t in sorted(files.items())},
        "cases": dict(sorted(cases.items())),
        "external_corpora": external_corpora(),
        "counts": {"cases": len(cases), "required": sum(1 for a in areas for c in a.cases if c["tier"] == "required"),
                   "advisory": sum(1 for a in areas for c in a.cases if c["tier"] == "advisory")},
    }
    files["manifest.json"] = common.dumps(man)
    return files, man


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true", help="verify on-disk fixtures equal a fresh regeneration")
    ap.add_argument("--allow-breaking", action="store_true", help="permit changing/removing existing cases (needs a version bump)")
    args = ap.parse_args()

    files, man = render(build_all())
    lock_path = ROOT / "manifest.json"
    old = json.loads(lock_path.read_text()) if lock_path.exists() else None

    if args.check:
        bad = [p for p, t in files.items() if not (ROOT / p).exists() or (ROOT / p).read_text(encoding="utf-8") != t]
        if bad:
            print("DRIFT: fixtures differ from a fresh regeneration:", *bad, sep="\n  ")
            return 1
        print(f"ok: {man['counts']['cases']} cases match a fresh regeneration")
        return 0

    if old:
        changed = sorted(i for i, d in old["cases"].items() if i in man["cases"] and man["cases"][i] != d)
        removed = sorted(i for i in old["cases"] if i not in man["cases"])
        if changed or removed:
            same_version = old["suite_version"] == man["suite_version"]
            if not args.allow_breaking or same_version:
                print("REFUSED: existing fixtures would change (fixtures are append-only).")
                for label, ids in (("changed", changed), ("removed", removed)):
                    if ids:
                        print(f"  {label}: {', '.join(ids[:10])}{' ...' if len(ids) > 10 else ''}")
                print("  To do this deliberately: bump SUITE_VERSION in tools/fx/common.py and pass --allow-breaking.")
                return 2
    for p, t in files.items():
        dest = ROOT / p
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(t, encoding="utf-8", newline="\n")
    added = len(man["cases"]) - (len(old["cases"]) if old else 0)
    print(f"wrote {len(files)} files, {man['counts']['cases']} cases ({man['counts']['required']} required, "
          f"{man['counts']['advisory']} advisory), +{added} new")
    return 0


if __name__ == "__main__":
    sys.exit(main())
