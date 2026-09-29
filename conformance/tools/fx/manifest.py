import copy
import json

from .common import Area, syn, sha256_hex
from .metadata import canon

BN254_R = 21888242871839275222246405745257275088548364400416034343698204186575808495617
NET = "Test SDF Network ; September 2015"
# A syntactically valid, synthetic contract id (filled in by stellar.py's strkey helper).
CONTRACT_ID = None  # set by gen.py before build() so both areas share one value


def m2(**over):
    m = {
        "protocol": "harpocrates", "version": 2, "proofId": syn("man/proof"), "tier": "silent",
        "network": NET, "contractId": CONTRACT_ID, "transactionRef": syn("man/tx"),
        "videoHash": syn("man/video"), "metadataHash": syn("man/meta"), "sourceHash": syn("man/source"),
        "timestamp": "2026-01-15T12:00:00.000Z", "verifierScope": "0", "epoch": 0,
    }
    m.update(over)
    return m


def build() -> Area:
    a = Area("proof-manifest", "Proof manifest creation, serialization, and strict parsing")

    def create(n, slug, inp, expected, desc, tier="required", why=None):
        c = canon(expected)
        a.add(f"pm-create-{n:03d}-{slug}", "manifest_create", inp,
              ok={"canonical": c, "sha256": sha256_hex(c)}, desc=desc, tier=tier, why=why)

    core = {k: m2()[k] for k in ("proofId", "tier", "network", "contractId", "transactionRef",
                                 "videoHash", "metadataHash", "sourceHash", "timestamp")}
    create(1, "defaults", dict(core), m2(),
           "Omitted verifierScope/epoch default to '0' and 0; version is always 2.")
    create(2, "explicit-scope", dict(core, verifierScope="12345", epoch=7), m2(verifierScope="12345", epoch=7),
           "Explicit scope and epoch are kept.")
    create(3, "scope-name", dict(core, scopeName="Example Verifier"), m2(scopeName="Example Verifier"),
           "scopeName is included when non-empty.")
    create(4, "empty-scope-name-omitted", dict(core, scopeName=""), m2(),
           "An empty scopeName is omitted, not serialized as an empty string.")
    create(5, "tier-seal", dict(core, tier="seal"), m2(tier="seal"), "Tier passes through.")
    sd = {"schemaHash": syn("sd/schema"), "publicInputs": "00ff", "predicateCommitment": syn("sd/pred"), "circuitVersion": 1}
    create(10, "selective-disclosure", dict(core, selectiveDisclosure=sd), m2(selectiveDisclosure=sd),
           "The nested disclosure object must survive serialization. The deployed `serializeManifest` "
           "(`JSON.stringify(m, Object.keys(m).sort())`) serializes it as {} because the array replacer "
           "also filters nested keys.", tier="advisory", why="known_defect")

    def ok(n, slug, m, desc, canonical=None, tier="required", why=None):
        c = canon(m) if canonical is None else canonical
        a.add(f"pm-pos-{n:03d}-{slug}", "manifest_parse", {"text": json.dumps(m)},
              ok={"canonical": c, "sha256": sha256_hex(c)}, desc=desc, tier=tier, why=why)

    ok(1, "v2-minimal", m2(), "A complete v2 manifest.")
    v1 = {k: v for k, v in m2().items() if k not in ("verifierScope", "epoch")}
    v1["version"] = 1
    ok(2, "v1-legacy", v1, "v1 manifests have no scope or epoch and stay valid.")
    ok(3, "uppercase-hex", m2(proofId=syn("man/proof").upper(), videoHash=syn("man/video").upper()),
       "Hex digests are case-insensitive on input and are NOT rewritten by parsing.")
    ok(4, "scope-and-epoch", m2(verifierScope="9" * 30, epoch=9007199254740991), "Largest safe epoch, long decimal scope.")
    ok(5, "scope-name-128", m2(scopeName="a" * 128), "scopeName of exactly 128 UTF-16 code units.")
    ok(6, "scope-name-64-emoji", m2(scopeName="\U0001F600" * 64),
       "64 emoji = 128 UTF-16 code units = 64 code points: accepted. Length is counted in UTF-16 code units.")
    ok(7, "disclosure", m2(selectiveDisclosure=sd),
       "Well-formed selective disclosure block; the canonical form must include it. Deployed `serializeManifest` "
       "drops the nested object (array replacer), so the parsed manifest re-serializes with `selectiveDisclosure: {}`.",
       tier="advisory", why="known_defect")
    ok(8, "disclosure-empty-public-inputs", m2(selectiveDisclosure=dict(sd, publicInputs="")),
       "Empty publicInputs hex is accepted (same canonicalization defect as pm-pos-007).",
       tier="advisory", why="known_defect")

    def bad(n, slug, text, code, desc, field=None, tier="required", why=None):
        a.add(f"pm-neg-{n:03d}-{slug}", "manifest_parse", {"text": text}, code=code,
              detail={"field": field} if field else None, desc=desc, tier=tier, why=why)

    def mut(**over):
        return json.dumps(m2(**over))

    def drop(*keys, **over):
        m = m2(**over)
        for k in keys:
            m.pop(k, None)
        return json.dumps(m)

    bad(1, "not-json", "{nope", "invalid_json", "Not JSON.")
    bad(2, "array", "[]", "not_object", "Top level must be an object.")
    bad(3, "null", "null", "not_object", "null.")
    bad(4, "string", '"harpocrates"', "not_object", "A JSON string.")
    bad(5, "unsupported-field", mut(extra=1), "unsupported_field", "Manifests are closed: unknown top-level fields are rejected.")
    bad(6, "signature-field", mut(signature="00"), "unsupported_field", "A smuggled signature field is rejected, not ignored.")
    bad(10, "protocol-case", mut(protocol="Harpocrates"), "bad_protocol", "Protocol is case-sensitive.")
    bad(11, "version-3", mut(version=3), "unsupported_version", "Future versions fail closed.")
    bad(12, "version-0", mut(version=0), "unsupported_version", "Version 0.")
    bad(13, "version-string", mut(version="2"), "unsupported_version", "Version must be the number 2 (or 1).")
    bad(14, "tier-unknown", mut(tier="gold"), "bad_tier", "Unknown tier.")
    bad(15, "tier-numeric", mut(tier=1), "bad_tier", "Numeric tier.")
    for i, f in enumerate(("proofId", "network", "contractId", "transactionRef", "videoHash", "metadataHash", "sourceHash", "timestamp")):
        bad(20 + i, f"empty-{f}", mut(**{f: ""}), "bad_string_field", f"{f} is empty.", field=f)
    bad(28, "missing-network", drop("network"), "bad_string_field", "Missing network.", field="network")
    bad(29, "contract-id-number", mut(contractId=5), "bad_string_field", "Non-string contractId.", field="contractId")
    for i, f in enumerate(("proofId", "videoHash", "metadataHash", "sourceHash", "transactionRef")):
        v = syn("man/" + f)
        bad(30 + i * 5, f"{f}-short", mut(**{f: v[:-1]}), "bad_hex32", f"{f}: 63 hex chars.", field=f)
        bad(31 + i * 5, f"{f}-non-hex", mut(**{f: "g" + v[1:]}), "bad_hex32", f"{f}: non-hex.", field=f)
        bad(32 + i * 5, f"{f}-trailing-newline", mut(**{f: v + "\n"}), "bad_hex32",
            f"{f}: trailing newline (Python `$` matches before it).", field=f)
        bad(33 + i * 5, f"{f}-0x", mut(**{f: "0x" + v[2:]}), "bad_hex32", f"{f}: 0x prefix.", field=f)
    bad(60, "order-string-before-hex", mut(network="", proofId="zz"), "bad_string_field",
        "Two faults: every string field is checked before any hex field.", field="network")
    bad(61, "order-tier-before-fields", mut(tier="gold", proofId=""), "bad_tier", "Tier is checked before field contents.")
    bad(70, "timestamp-garbage", mut(timestamp="not-a-date"), "bad_timestamp", "Unparseable timestamp.")
    bad(71, "timestamp-month-13", mut(timestamp="2026-13-45T00:00:00Z"), "bad_timestamp", "Impossible calendar date.")
    bad(72, "timestamp-year-only", mut(timestamp="2026"), "bad_timestamp",
        "Deployed `Date.parse` accepts many non-ISO strings ('2026', 'Jan 1 2026'); require RFC 3339.",
        tier="advisory", why="proposed_hardening")
    bad(80, "scope-leading-zero", mut(verifierScope="01"), "bad_scope_epoch", "Decimal scope must be canonical (no leading zero).")
    bad(81, "scope-negative", mut(verifierScope="-1"), "bad_scope_epoch", "Negative scope.")
    bad(82, "scope-number", mut(verifierScope=0), "bad_scope_epoch", "Scope must be a decimal string.")
    bad(83, "scope-missing", drop("verifierScope"), "bad_scope_epoch", "v2 requires verifierScope.")
    bad(84, "epoch-missing", drop("epoch"), "bad_scope_epoch", "v2 requires epoch.")
    bad(85, "epoch-negative", mut(epoch=-1), "bad_scope_epoch", "Negative epoch.")
    bad(86, "epoch-fractional", mut(epoch=1.5), "bad_scope_epoch", "Fractional epoch.")
    bad(87, "epoch-string", mut(epoch="0"), "bad_scope_epoch", "String epoch.")
    a.add("pm-neg-088-epoch-unsafe", "manifest_parse",
          {"text": json.dumps(m2()).replace('"epoch": 0', '"epoch": 9007199254740992')},
          code="bad_scope_epoch", desc="Epoch 2^53 is not a safe integer.")
    bad(89, "scope-at-modulus", mut(verifierScope=str(BN254_R)), "bad_scope_epoch",
        "The scope is a BN254 field element; a value >= the modulus is non-canonical. "
        "Deployed parsing only checks the decimal shape.", tier="advisory", why="proposed_hardening")
    bad(90, "scope-name-129", mut(scopeName="a" * 129), "bad_scope_name", "129 code units.")
    bad(91, "scope-name-65-emoji", mut(scopeName="\U0001F600" * 65), "bad_scope_name",
        "65 emoji = 130 UTF-16 code units but only 65 code points. Length is measured in UTF-16 code "
        "units (deployed JS `.length`); a code-point counter would wrongly accept this.")
    bad(92, "scope-name-number", mut(scopeName=5), "bad_scope_name", "Non-string scopeName.")
    bad(100, "disclosure-null", mut(selectiveDisclosure=None), "bad_disclosure", "null disclosure.")
    bad(101, "disclosure-array", mut(selectiveDisclosure=[]), "bad_disclosure", "Array disclosure.")
    sd = {"schemaHash": syn("sd/schema"), "publicInputs": "00ff", "predicateCommitment": syn("sd/pred"), "circuitVersion": 1}
    bad(102, "disclosure-extra-key", mut(selectiveDisclosure=dict(sd, extra=1)), "bad_disclosure", "Unknown disclosure key.")
    bad(103, "disclosure-missing-schema", mut(selectiveDisclosure={k: v for k, v in sd.items() if k != "schemaHash"}),
        "bad_disclosure", "Missing schemaHash.")
    bad(104, "disclosure-short-hash", mut(selectiveDisclosure=dict(sd, schemaHash=syn("x")[:-2])), "bad_disclosure", "Short schemaHash.")
    bad(105, "disclosure-non-hex-inputs", mut(selectiveDisclosure=dict(sd, publicInputs="0g")), "bad_disclosure", "Non-hex publicInputs.")
    bad(106, "disclosure-circuit-fractional", mut(selectiveDisclosure=dict(sd, circuitVersion=1.5)), "bad_disclosure", "Fractional circuitVersion.")
    bad(107, "disclosure-odd-public-inputs", mut(selectiveDisclosure=dict(sd, publicInputs="abc")), "bad_disclosure",
        "Odd-length hex is not a byte string; deployed parsing accepts it (regex only).",
        tier="advisory", why="proposed_hardening")
    return a
