import json

from .common import Area, syn, sha256_hex

REQUIRED = ["protocol", "version", "tier", "sourceHash", "proofId", "timestamp"]


def base(**over):
    m = {
        "protocol": "harpocrates",
        "version": 1,
        "tier": "silent",
        "sourceHash": syn("meta/source"),
        "proofId": syn("meta/proof"),
        "timestamp": "2026-01-15T12:00:00.000Z",
    }
    m.update(over)
    return m


def canon(obj) -> str:
    """Independent (generator-local) canonical form; ASCII/BMP-only inputs."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def build_metadata() -> Area:
    a = Area("metadata-envelope", "Metadata validation, canonical hash, and envelope-version semantics")

    def ok(n, slug, meta, desc):
        a.add(f"me-pos-{n:03d}-{slug}", "metadata_validate", {"metadata": meta}, ok={"valid": True}, desc=desc)

    ok(1, "minimal", base(), "All six required fields, tier silent.")
    ok(2, "tier-source", base(tier="source"), "Tier source.")
    ok(3, "tier-seal", base(tier="seal"), "Tier seal.")
    ok(4, "uppercase-hex", base(sourceHash=syn("meta/source").upper(), proofId=syn("meta/proof").upper()),
       "Hex digests are case-insensitive on input.")
    ok(5, "extension-keys", base(extensions={"note": "synthetic", "n": 1}, x_extra=True),
       "Unknown keys are tolerated: metadata is the extension point.")
    ok(6, "version-2", base(version=2), "Layer-local validation accepts any numeric version; "
       "envelope support is a separate check (envelope_version_check).")

    def bad(n, slug, meta, code, desc, field=None, tier="required", why=None):
        a.add(f"me-neg-{n:03d}-{slug}", "metadata_validate", {"metadata": meta}, code=code,
              detail={"field": field} if field else None, desc=desc, tier=tier, why=why)

    bad(1, "null", None, "not_object", "null is not an object.")
    bad(2, "string", "harpocrates", "not_object", "A string is not an object.")
    bad(3, "number", 7, "not_object", "A number is not an object.")
    for i, f in enumerate(REQUIRED):
        m = base()
        del m[f]
        bad(10 + i, f"missing-{f}", m, "missing_field", f"Missing {f}.", field=f)
    bad(20, "protocol-case", base(protocol="Harpocrates"), "bad_protocol", "Protocol is case-sensitive.")
    bad(21, "protocol-other", base(protocol="other"), "bad_protocol", "Foreign protocol id.")
    bad(22, "version-string", base(version="1"), "bad_version", "Version must be a JSON number.")
    bad(23, "version-null", base(version=None), "bad_version", "null version.")
    bad(24, "tier-unknown", base(tier="gold"), "bad_tier", "Unknown tier.")
    bad(25, "tier-case", base(tier="Silent"), "bad_tier", "Tier is case-sensitive.")
    bad(26, "tier-numeric", base(tier=1), "bad_tier", "Numeric tier is not the wire form.")
    for field, code in (("sourceHash", "bad_source_hash"), ("proofId", "bad_proof_id")):
        v = syn("meta/" + field)
        bad(30 if field == "sourceHash" else 40, f"{field}-short", base(**{field: v[:-1]}), code, f"{field}: 63 hex chars.")
        bad(31 if field == "sourceHash" else 41, f"{field}-long", base(**{field: v + "0"}), code, f"{field}: 65 hex chars.")
        bad(32 if field == "sourceHash" else 42, f"{field}-non-hex", base(**{field: "g" + v[1:]}), code, f"{field}: non-hex char.")
        bad(33 if field == "sourceHash" else 43, f"{field}-trailing-newline", base(**{field: v + "\n"}), code,
            f"{field}: trailing newline. Python `re.match('^...$')` accepts this; JS does not. Use fullmatch.")
        bad(34 if field == "sourceHash" else 44, f"{field}-0x-prefix", base(**{field: "0x" + v[2:]}), code, f"{field}: 0x prefix.")
        bad(35 if field == "sourceHash" else 45, f"{field}-number", base(**{field: 5}), code, f"{field}: not a string.")
        bad(36 if field == "sourceHash" else 46, f"{field}-fullwidth", base(**{field: "\uff10" * 64}), code,
            f"{field}: fullwidth digits (U+FF10) are not hex; Python str.isdigit/int() would accept them.")
    # Check order is part of the contract: required-field scan, then protocol, version, tier, sourceHash, proofId.
    bad(50, "order-tier-before-hash", base(tier="gold", sourceHash="zz"), "bad_tier",
        "Two faults: tier is reported before sourceHash.")
    bad(51, "order-missing-before-protocol", {k: v for k, v in base(protocol="x").items() if k != "timestamp"},
        "missing_field", "Missing-field scan precedes value checks.", field="timestamp")
    # Advisory hardening: deployed validateMetadata never inspects timestamp or the value of version.
    bad(60, "timestamp-number", base(timestamp=12345), "bad_timestamp",
        "Deployed validation ignores timestamp entirely.", tier="advisory", why="proposed_hardening")
    bad(61, "version-zero", base(version=0), "bad_version",
        "Deployed validation accepts any number, including 0, -1 and 1.5.", tier="advisory", why="proposed_hardening")
    bad(62, "version-fractional", base(version=1.5), "bad_version", "Fractional version.",
        tier="advisory", why="proposed_hardening")
    bad(63, "array-input", [], "not_object",
        "Deployed code reports missing_field for arrays because typeof [] is 'object'.",
        tier="advisory", why="proposed_hardening")

    # ---- canonical metadata hash (flat objects: the deployed behaviour is unambiguous) ----
    def h(n, slug, meta, desc, tier="required", why=None, canonical=None):
        c = canonical if canonical is not None else canon(meta)
        a.add(f"me-hash-{n:03d}-{slug}", "metadata_hash", {"metadata": meta},
              ok={"canonical": c, "sha256": sha256_hex(c)}, desc=desc, tier=tier, why=why)

    h(1, "flat", base(), "Flat metadata: sorted keys, no whitespace, sha256 of the UTF-8 bytes.")
    h(2, "flat-extension-scalar", base(x_note="synthetic", x_n=3), "Scalar extension keys are hashed.")
    h(3, "non-ascii-value", base(x_label="caf\u00e9 \u2603"),
      "Non-ASCII stays literal UTF-8 in the hashed bytes (backend must not use ensure_ascii=True).")
    h(4, "key-order-independent", dict(reversed(list(base().items()))),
      "Insertion order of the input never changes the hash.")
    # Known defect: JSON.stringify(obj, Object.keys(obj).sort()) filters nested keys.
    h(10, "nested-extension-object", base(extensions={"note": "synthetic", "b": 1}),
      "Nested extension objects must contribute to the hash. The deployed TypeScript "
      "`canonicalMetadataHash` uses an array replacer that silently DROPS nested keys, "
      "so `extensions` hashes as {}.", tier="advisory", why="known_defect")
    h(11, "nested-key-collides-with-top-level", base(extensions={"tier": "shadow", "zeta": 1}),
      "Only nested keys that happen to equal a top-level key survive the deployed replacer.",
      tier="advisory", why="known_defect")

    # ---- envelope version semantics (contracts/METADATA_ENVELOPE.md, error #68/#70/#71) ----
    for n, v in ((1, 1), (2, 2)):
        a.add(f"me-env-pos-{n:03d}-supported-v{v}", "envelope_version_check", {"version": v},
              ok={"supported": True}, desc=f"Envelope version {v} is supported.")
    for n, v, slug in ((3, 0, "zero"), (4, 3, "above-max"), (5, 4294967295, "u32-max")):
        a.add(f"me-env-neg-{n:03d}-{slug}", "envelope_version_check", {"version": v},
              code="unsupported_metadata_envelope_version", desc=f"Version {v} fails closed (#68).")
    a.add("me-env-neg-006-negative", "envelope_version_check", {"version": -1},
          code="unsupported_metadata_envelope_version", desc="A negative version is not a u32 and fails closed.")
    a.add("me-env-neg-007-fractional", "envelope_version_check", {"version": 1.5},
          code="unsupported_metadata_envelope_version", desc="A fractional version fails closed.")

    def res(n, slug, inp, version, desc):
        a.add(f"me-res-{n:03d}-{slug}", "envelope_version_resolve", inp, ok={"version": version}, desc=desc)

    res(1, "stored-v2", {"proof_exists": True, "stored_version": 2}, 2, "Stored row wins.")
    res(2, "legacy-no-row", {"proof_exists": True, "stored_version": None}, 1, "Proof without a row is V1.")
    res(3, "unknown-proof", {"proof_exists": False, "stored_version": None}, 0, "0 means unknown proof.")

    def bind(n, slug, inp, ok=None, code=None, desc=""):
        a.add(f"me-bind-{n:03d}-{slug}", "envelope_bind", inp, ok=ok, code=code, desc=desc)

    zero = "0" * 64
    h1, h2 = syn("bind/hash1"), syn("bind/hash2")
    bind(1, "first-v2", {"proof_exists": True, "stored_hash": h1, "current_version": None, "current_hash": None,
                         "version": 2, "metadata_hash": h1}, ok={"version": 2, "event": "bound"}, desc="First bind may set any supported version.")
    bind(2, "upgrade", {"proof_exists": True, "stored_hash": h1, "current_version": 1, "current_hash": h1,
                        "version": 2, "metadata_hash": h1}, ok={"version": 2, "event": "upgraded"}, desc="v1 -> v2 upgrade emits one upgrade event.")
    bind(3, "idempotent", {"proof_exists": True, "stored_hash": h1, "current_version": 2, "current_hash": h1,
                           "version": 2, "metadata_hash": h1}, ok={"version": 2, "event": "none"}, desc="Re-bind of identical data is a no-op with no event.")
    bind(4, "downgrade", {"proof_exists": True, "stored_hash": h1, "current_version": 2, "current_hash": h1,
                          "version": 1, "metadata_hash": h1}, code="unsupported_metadata_envelope_version", desc="Downgrade fails closed (#68).")
    bind(5, "unknown-proof", {"proof_exists": False, "stored_hash": None, "current_version": None, "current_hash": None,
                              "version": 2, "metadata_hash": h1}, code="metadata_envelope_not_found", desc="Unknown proof (#70).")
    bind(6, "zero-hash", {"proof_exists": True, "stored_hash": h1, "current_version": None, "current_hash": None,
                          "version": 2, "metadata_hash": zero}, code="invalid_metadata_envelope", desc="All-zero hash (#69).")
    bind(7, "hash-mismatch", {"proof_exists": True, "stored_hash": h1, "current_version": None, "current_hash": None,
                              "version": 2, "metadata_hash": h2}, code="metadata_envelope_hash_mismatch", desc="Hash differs from the stored proof hash (#71).")
    bind(8, "unsupported-version", {"proof_exists": True, "stored_hash": h1, "current_version": None, "current_hash": None,
                                    "version": 9, "metadata_hash": h1}, code="unsupported_metadata_envelope_version", desc="Version above max (#68) is checked before the hash.")
    bind(9, "version-checked-before-zero-hash", {"proof_exists": True, "stored_hash": h1, "current_version": None, "current_hash": None,
                                                  "version": 0, "metadata_hash": zero}, code="unsupported_metadata_envelope_version",
         desc="Check order: proof exists, version supported, non-zero hash, hash matches, then downgrade rules.")
    bind(10, "same-version-different-row-hash", {"proof_exists": True, "stored_hash": h1, "current_version": 2, "current_hash": h2,
                                                  "version": 2, "metadata_hash": h1}, code="metadata_envelope_hash_mismatch",
         desc="Same-version hash edits go through correct_proof, never through bind (#71).")
    return a
