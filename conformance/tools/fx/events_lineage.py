"""Events (indexer/decoder boundary), lineage rules, lineage manifests, and the frozen error ABI."""
import hashlib
import re

from .common import Area, syn, sha256_hex
from .metadata import canon
from .stellar import account_id, contract_id

U32_MAX = 2**32 - 1
U64_MAX = 2**64 - 1

# name -> (topic prefix incl. literal third topic, [(field, type)], notes)
EVENT_SCHEMAS = {
    "proof_registered": {"topics": ["proof", "reg", "$hex32"],
                         "fields": [["video_hash", "hex32"], ["tier", "u32:1..3"], ["status", "u32:1..3"], ["batch_size", "u32"]]},
    "proof_revoked": {"topics": ["proof", "revoke", "$hex32"], "fields": [["status", "u32:2..2"]]},
    "metadata_envelope_bound": {"topics": ["metadata", "envelope", "bound", "$hex32"],
                                "fields": [["version", "u32:1..2"], ["metadata_hash", "hex32"], ["bound_at", "u64"]]},
    "metadata_envelope_upgraded": {"topics": ["metadata", "envelope", "upgraded", "$hex32"],
                                   "fields": [["previous", "u32:1..2"], ["current", "u32:1..2"], ["metadata_hash", "hex32"]],
                                   "rule": "current > previous"},
    "proof_history": {"topics": ["proof", "history", "$hex32"],
                      "fields": [["action", "u32"], ["timestamp", "u64"], ["actor", "address|null"], ["reason_code", "u32:0..255"]]},
    "lineage_registered": {"topics": ["lineage", "reg", "$hex32"],
                           "fields": [["manifest_digest", "hex32"], ["actor", "address"], ["operation_type", "string"],
                                      ["depth", "u32:1..4"], ["parent_commitments", "hex32[1..4]"]]},
}
FORBIDDEN = ["nullifier", "witness", "proof_bytes", "public_inputs", "credential_secret", "private_key", "seed",
             "media", "raw_metadata", "envelope_bytes"]


def build_events() -> Area:
    a = Area("events", "Registry events: schema, encodings, and privacy (no secrets in any event)")
    a.extras["encoding"] = {
        "hex32": "64 lowercase hex characters", "u32": "JSON integer 0..4294967295 (booleans are not integers)",
        "u64": "base-10 string, canonical (no sign, no leading zeros), 0..18446744073709551615",
        "address": "strkey G... or C... with valid checksum, or JSON null where the schema allows",
    }
    a.extras["event_schemas"] = EVENT_SCHEMAS
    a.extras["forbidden_field_names"] = FORBIDDEN
    pid, vh, mh = syn("evt/proof"), syn("evt/video"), syn("evt/meta")
    actor = account_id("evt-actor")

    def ev(cid, topics, data, desc, name=None, code=None, detail=None, tier="required", why=None):
        if name:
            a.add(cid, "event_validate", {"topics": topics, "data": data}, ok={"event": name}, desc=desc, tier=tier, why=why)
        else:
            a.add(cid, "event_validate", {"topics": topics, "data": data}, code=code, detail=detail, desc=desc, tier=tier, why=why)

    reg_t = ["proof", "reg", pid]
    reg_d = {"video_hash": vh, "tier": 1, "status": 1, "batch_size": 0}
    ev("ev-pos-001-proof-registered", reg_t, reg_d, "Registration event.", name="proof_registered")
    ev("ev-pos-002-proof-revoked", ["proof", "revoke", pid], {"status": 2}, "Revocation event.", name="proof_revoked")
    ev("ev-pos-003-envelope-bound", ["metadata", "envelope", "bound", pid], {"version": 2, "metadata_hash": mh, "bound_at": "1800000000"},
       "Envelope bound.", name="metadata_envelope_bound")
    ev("ev-pos-004-envelope-upgraded", ["metadata", "envelope", "upgraded", pid], {"previous": 1, "current": 2, "metadata_hash": mh},
       "Envelope upgraded.", name="metadata_envelope_upgraded")
    ev("ev-pos-005-history-with-actor", ["proof", "history", pid], {"action": 3, "timestamp": "1800000000", "actor": actor, "reason_code": 255},
       "History with an actor.", name="proof_history")
    ev("ev-pos-006-history-null-actor", ["proof", "history", pid], {"action": 1, "timestamp": "0", "actor": None, "reason_code": 0},
       "History with no actor; u64 zero.", name="proof_history")
    ev("ev-pos-007-lineage", ["lineage", "reg", syn("evt/out")],
       {"manifest_digest": syn("evt/man"), "actor": contract_id("evt-actor"), "operation_type": "crop", "depth": 4,
        "parent_commitments": [syn("evt/pc1"), syn("evt/pc2")]}, "Lineage registration with a contract actor.", name="lineage_registered")
    ev("ev-pos-008-batch-size", reg_t, dict(reg_d, batch_size=U32_MAX, tier=3, status=3), "u32 maximum batch size; tier/status upper bounds.", name="proof_registered")
    ev("ev-pos-009-u64-max", ["metadata", "envelope", "bound", pid], {"version": 1, "metadata_hash": mh, "bound_at": str(U64_MAX)},
       "u64::MAX as a string: no float rounding.", name="metadata_envelope_bound")

    # -- privacy: any forbidden field is a hard failure, checked first --
    for i, f in enumerate(FORBIDDEN):
        ev(f"ev-neg-{i + 1:03d}-privacy-{f}", reg_t, dict(reg_d, **{f: syn("evt/secret/" + f)}),
           f"An event carrying `{f}` leaks private material and must be rejected.", code="event_privacy_violation", detail={"field": f})
    ev("ev-neg-011-privacy-case-insensitive", reg_t, dict(reg_d, Nullifier=syn("evt/secret/n")),
       "Field-name matching is case-insensitive.", code="event_privacy_violation", detail={"field": "Nullifier"})
    ev("ev-neg-012-privacy-on-unknown-event", ["totally", "unknown", pid], {"private_key": syn("evt/secret/k")},
       "Privacy is checked before the event is even recognised.", code="event_privacy_violation", detail={"field": "private_key"})
    ev("ev-neg-013-privacy-nested", reg_t, dict(reg_d, extra={"nullifier": syn("evt/secret/n2")}),
       "Forbidden names are found at any depth.", code="event_privacy_violation", detail={"field": "nullifier"})

    ev("ev-neg-020-unknown-event", ["proof", "explode", pid], {"status": 1}, "Unknown topic prefix.", code="event_unknown")
    ev("ev-neg-021-no-topics", [], {}, "No topics.", code="event_unknown")
    ev("ev-neg-022-topic-missing-id", ["proof", "reg"], reg_d, "The proof id topic is missing.", code="event_topics_invalid")
    ev("ev-neg-023-topic-extra", ["proof", "reg", pid, pid], reg_d, "One topic too many.", code="event_topics_invalid")
    ev("ev-neg-024-topic-short-id", ["proof", "reg", pid[:-2]], reg_d, "Short id topic.", code="event_topics_invalid")
    ev("ev-neg-025-topic-non-string", ["proof", "reg", 5], reg_d, "Non-string topic.", code="event_topics_invalid")
    ev("ev-neg-026-topic-trailing-newline", ["proof", "reg", pid + "\n"], reg_d, "Trailing newline in the id topic.", code="event_topics_invalid")
    ev("ev-neg-027-envelope-missing-verb", ["metadata", "envelope", pid], {"version": 1, "metadata_hash": mh, "bound_at": "1"},
       "The bound/upgraded literal topic is missing.", code="event_unknown")
    for i, f in enumerate(("video_hash", "tier", "status", "batch_size")):
        ev(f"ev-neg-{30 + i}-missing-{f}", reg_t, {k: v for k, v in reg_d.items() if k != f}, f"Missing `{f}`.",
           code="event_field_missing", detail={"field": f})
    ev("ev-neg-034-unexpected-field", reg_t, dict(reg_d, memo="x"), "Unknown data field.", code="event_field_unexpected", detail={"field": "memo"})
    ev("ev-neg-035-tier-string", reg_t, dict(reg_d, tier="1"), "u32 must be a JSON integer, not a string.", code="event_field_type", detail={"field": "tier"})
    ev("ev-neg-036-tier-bool", reg_t, dict(reg_d, tier=True), "A JSON boolean is not an integer (Python: isinstance(True, int)).", code="event_field_type", detail={"field": "tier"})
    ev("ev-neg-037-tier-float", reg_t, dict(reg_d, tier=1.5), "Fractional u32.", code="event_field_type", detail={"field": "tier"})
    ev("ev-neg-038-tier-zero", reg_t, dict(reg_d, tier=0), "Tier 0 is out of range.", code="event_value_out_of_range", detail={"field": "tier"})
    ev("ev-neg-039-tier-four", reg_t, dict(reg_d, tier=4), "Tier 4 is out of range.", code="event_value_out_of_range", detail={"field": "tier"})
    ev("ev-neg-040-status-zero", reg_t, dict(reg_d, status=0), "Status 0 is out of range.", code="event_value_out_of_range", detail={"field": "status"})
    ev("ev-neg-041-u32-overflow", reg_t, dict(reg_d, batch_size=U32_MAX + 1), "u32 overflow.", code="event_value_out_of_range", detail={"field": "batch_size"})
    ev("ev-neg-042-u32-negative", reg_t, dict(reg_d, batch_size=-1), "Negative u32.", code="event_value_out_of_range", detail={"field": "batch_size"})
    ev("ev-neg-043-hash-short", reg_t, dict(reg_d, video_hash=vh[:-1]), "Short hash.", code="event_field_type", detail={"field": "video_hash"})
    ev("ev-neg-044-revoke-wrong-status", ["proof", "revoke", pid], {"status": 1}, "A revoke event must carry status 2.", code="event_value_out_of_range", detail={"field": "status"})
    bound = ["metadata", "envelope", "bound", pid]
    bd = {"version": 2, "metadata_hash": mh, "bound_at": "1"}
    ev("ev-neg-045-u64-number", bound, dict(bd, bound_at=1), "u64 must be a decimal string, never a JSON number.", code="event_field_type", detail={"field": "bound_at"})
    ev("ev-neg-046-u64-leading-zero", bound, dict(bd, bound_at="01"), "Non-canonical decimal.", code="event_field_type", detail={"field": "bound_at"})
    ev("ev-neg-047-u64-negative", bound, dict(bd, bound_at="-1"), "Negative u64.", code="event_field_type", detail={"field": "bound_at"})
    ev("ev-neg-048-u64-overflow", bound, dict(bd, bound_at=str(U64_MAX + 1)), "u64 overflow.", code="event_value_out_of_range", detail={"field": "bound_at"})
    ev("ev-neg-049-u64-plus", bound, dict(bd, bound_at="+5"), "Explicit plus sign.", code="event_field_type", detail={"field": "bound_at"})
    ev("ev-neg-050-u64-fullwidth", bound, dict(bd, bound_at="\uff11"), "Fullwidth digit: Python int('\uff11') == 1.", code="event_field_type", detail={"field": "bound_at"})
    ev("ev-neg-051-version-three", bound, dict(bd, version=3), "Envelope version above max.", code="event_value_out_of_range", detail={"field": "version"})
    up = ["metadata", "envelope", "upgraded", pid]
    ev("ev-neg-052-upgrade-not-increasing", up, {"previous": 2, "current": 2, "metadata_hash": mh}, "An upgrade must strictly increase the version.",
       code="event_value_out_of_range", detail={"field": "current"})
    hist = ["proof", "history", pid]
    hd = {"action": 1, "timestamp": "1", "actor": actor, "reason_code": 0}
    ev("ev-neg-053-reason-256", hist, dict(hd, reason_code=256), "reason_code is bounded to 0..=255.", code="event_value_out_of_range", detail={"field": "reason_code"})
    ev("ev-neg-054-actor-bad-checksum", hist, dict(hd, actor=actor[:-1] + ("A" if actor[-1] != "A" else "B")), "Address with a bad checksum.",
       code="event_field_type", detail={"field": "actor"})
    ev("ev-neg-055-actor-missing", hist, {k: v for k, v in hd.items() if k != "actor"}, "`actor` must be present (null is allowed, absent is not).",
       code="event_field_missing", detail={"field": "actor"})
    lin = ["lineage", "reg", syn("evt/out")]
    ld = {"manifest_digest": syn("evt/man"), "actor": actor, "operation_type": "crop", "depth": 1, "parent_commitments": [syn("evt/pc")]}
    ev("ev-neg-056-lineage-null-actor", lin, dict(ld, actor=None), "Lineage actor is required.", code="event_field_type", detail={"field": "actor"})
    ev("ev-neg-057-lineage-no-parents", lin, dict(ld, parent_commitments=[]), "At least one parent commitment.", code="event_value_out_of_range", detail={"field": "parent_commitments"})
    ev("ev-neg-058-lineage-five-parents", lin, dict(ld, parent_commitments=[syn(f"evt/pc{i}") for i in range(5)]), "At most four parent commitments.",
       code="event_value_out_of_range", detail={"field": "parent_commitments"})
    ev("ev-neg-059-lineage-depth-five", lin, dict(ld, depth=5), "Depth above MAX_LINEAGE_DEPTH.", code="event_value_out_of_range", detail={"field": "depth"})
    ev("ev-neg-060-lineage-bad-commitment", lin, dict(ld, parent_commitments=["xyz"]), "Malformed commitment.", code="event_field_type", detail={"field": "parent_commitments"})
    ev("ev-adv-001-uppercase-hash", reg_t, dict(reg_d, video_hash=vh.upper()),
       "Registry events carry canonical lowercase hex; an uppercase digest signals a re-encoding bug upstream.",
       code="event_field_type", detail={"field": "video_hash"}, tier="advisory", why="proposed_hardening")
    return a


def build_lineage() -> Area:
    a = Area("lineage", "Lineage rules (contract), transformation manifests, and extension handling")
    a.extras["limits"] = {"max_depth": 4, "max_fanout": 4, "max_payload_bytes": 4096}
    out = syn("lin/out")

    def par(label, kind="proof", status="valid"):
        return {"id": syn("lin/" + label), "kind": kind, "status": status if kind == "proof" else None}

    def lv(n, slug, parents, depth, desc, *, output=out, dup=False, ok=None, code=None):
        inp = {"parents": parents, "output_digest": output, "depth": depth, "output_registered": dup}
        if code:
            a.add(f"ln-rule-{n:03d}-{slug}", "lineage_validate", inp, code=code, desc=desc)
        else:
            a.add(f"ln-rule-{n:03d}-{slug}", "lineage_validate", inp, ok={"valid": True}, desc=desc)

    lv(1, "one-valid-parent", [par("a")], 1, "One valid parent at depth 1.")
    lv(2, "four-parents", [par(c) for c in "abcd"], 4, "Fan-out and depth exactly at the limits.")
    lv(3, "lineage-parent", [par("a", "lineage")], 2, "A parent that is itself a lineage record needs no status.")
    lv(4, "empty-parents", [], 1, "Zero parents.", code="lineage_empty_parents")
    lv(5, "five-parents", [par(c) for c in "abcde"], 1, "Fan-out 5 > 4.", code="lineage_fan_out_exceeded")
    lv(6, "depth-five", [par("a")], 5, "Depth 5 > 4.", code="lineage_too_deep")
    lv(7, "depth-zero", [par("a")], 0, "Depth 0 is not a derivation.", code="invalid_lineage")
    lv(8, "self-parent", [{"id": out, "kind": "proof", "status": "valid"}], 1, "Output equal to a parent is a cycle.", code="lineage_cycle")
    lv(9, "revoked-parent", [par("a", status="revoked")], 1, "Revoked parent proof.", code="lineage_parent_unavailable")
    lv(10, "expired-parent", [par("a", status="expired")], 1, "Expired parent proof.", code="lineage_parent_unavailable")
    lv(11, "unknown-parent", [par("a", "unknown")], 1, "Parent that is neither a proof nor a lineage record.", code="invalid_lineage")
    lv(12, "duplicate-output", [par("a")], 1, "Output digest already registered.", dup=True, code="duplicate_lineage")
    lv(13, "order-empty-before-depth", [], 9, "Check order: empty parents before depth.", code="lineage_empty_parents")
    lv(14, "order-fanout-before-depth", [par(c) for c in "abcde"], 9, "Check order: fan-out before depth.", code="lineage_fan_out_exceeded")
    lv(15, "order-depth-before-parents", [par("a", status="revoked")], 5, "Check order: depth before per-parent checks.", code="lineage_too_deep")
    lv(16, "order-cycle-before-availability", [{"id": out, "kind": "proof", "status": "revoked"}], 1,
       "Per parent: cycle is checked before availability.", code="lineage_cycle")
    lv(17, "first-failing-parent-wins", [par("a", status="revoked"), par("b", "unknown")], 1,
       "Parents are examined in order; the first failure is reported.", code="lineage_parent_unavailable")
    lv(18, "duplicate-checked-last", [par("a", status="revoked")], 1, "Duplicate-output is only reached after every rule passes.",
       dup=True, code="lineage_parent_unavailable")

    ops = ("crop", "transcode", "blur", "redact", "compose")

    def man(**over):
        m = {"protocol": "harpocrates", "version": 2, "parentProofIds": [syn("lin/p1"), syn("lin/p2")], "operationType": "crop",
             "parametersDigest": syn("lin/params"), "toolIdentity": "example-tool", "toolVersion": "1.0.0",
             "outputDigest": syn("lin/output"), "network": "Test SDF Network ; September 2015", "actorAddress": account_id("lin-actor")}
        m.update(over)
        return m

    def create_input(m):
        return {k: v for k, v in m.items() if k not in ("protocol", "version")}

    for i, op in enumerate(ops, 1):
        m = man(operationType=op)
        c = canon(m)
        a.add(f"ln-man-pos-{i:03d}-{op}", "lineage_manifest_create", create_input(m), ok={"canonical": c, "sha256": sha256_hex(c)},
              desc=f"Operation '{op}' is supported; version is always 2.")
    m = man(parentProofIds=[syn("lin/p2"), syn("lin/p1")])
    c = canon(m)
    a.add("ln-man-pos-006-parent-order-preserved", "lineage_manifest_create", create_input(m), ok={"canonical": c, "sha256": sha256_hex(c)},
          desc="parentProofIds order is significant and is not sorted.")
    for i, op in enumerate(("Crop", "resize", "", "crop "), 1):
        a.add(f"ln-man-neg-{i:03d}-op-{['case', 'unknown', 'empty', 'space'][i - 1]}", "lineage_manifest_create", create_input(man(operationType=op)),
              code="unsupported_operation", desc=f"operationType {op!r} is not in the supported set (exact, case-sensitive).")

    def prs(n, slug, m, *, code=None, desc="", tier="advisory"):
        import json as _j
        text = _j.dumps(m)
        if code:
            a.add(f"ln-ext-{n:03d}-{slug}", "lineage_manifest_parse", {"text": text}, code=code, desc=desc, tier=tier, why="proposed_hardening")
        else:
            c = canon(m)
            a.add(f"ln-ext-{n:03d}-{slug}", "lineage_manifest_parse", {"text": text}, ok={"canonical": c, "sha256": sha256_hex(c)},
                  desc=desc, tier=tier, why="proposed_hardening")

    prs(1, "v2-accepted", man(), desc="A well-formed v2 transformation manifest parses.")
    prs(2, "version-3-fails-closed", man(version=3), code="unsupported_version", desc="Future manifest versions fail closed.")
    prs(3, "unknown-field-rejected", dict(man(), futureExtension={"x": 1}), code="unsupported_field",
        desc="Transformation manifests are closed like proof manifests: unknown members are rejected, never silently dropped.")
    prs(4, "empty-parents", man(parentProofIds=[]), code="lineage_empty_parents", desc="At least one parent.")
    prs(5, "five-parents", man(parentProofIds=[syn(f"lin/x{i}") for i in range(5)]), code="lineage_fan_out_exceeded", desc="At most four parents.")
    prs(6, "parent-not-hex", man(parentProofIds=["nope"]), code="bad_hex32", desc="Parent ids are 32-byte hex.")
    prs(7, "output-not-hex", man(outputDigest="nope"), code="bad_hex32", desc="outputDigest is 32-byte hex.")
    prs(8, "unsupported-operation", man(operationType="resize"), code="unsupported_operation", desc="Unsupported operation.")
    prs(9, "payload-too-large", man(toolIdentity="x" * 4100), code="payload_too_large", desc="Canonical manifest above 4096 bytes.")
    prs(10, "payload-at-limit-bytes-not-chars", man(toolIdentity="\u00e9" * 2100), code="payload_too_large",
        desc="~2100 characters but > 4096 UTF-8 bytes: the bound is in bytes.")
    return a


def build_errors(repo_root) -> Area:
    a = Area("error-abi", "Frozen numeric error ABI (hpx-err/1)")
    path = repo_root / "contracts" / "ERROR_ABI.md"
    text = path.read_text(encoding="utf-8")
    rows = re.findall(r"^\|\s*(\d+)\s*\|\s*`(\w+)`\s*\|\s*(\w+)\s*\|\s*(yes|no)\s*\|", text, flags=re.M)
    assert rows, "no error rows parsed"
    codes = [int(r[0]) for r in rows]
    assert codes == list(range(1, len(codes) + 1)), "ERROR_ABI.md codes must be contiguous from 1"

    def snake(name):
        return re.sub(r"(?<!^)(?=[A-Z])", "_", name).lower()

    a.extras["source"] = {"path": "contracts/ERROR_ABI.md", "sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
                          "rows": len(rows)}
    for code, name, klass, retry in rows:
        a.add(f"ea-{int(code):03d}-{snake(name)}", "classify_error", {"code": int(code)},
              ok={"name": name, "class": klass, "retryable": retry == "yes", "reason_code": snake(name)},
              desc=f"Code {code} is `{name}` ({klass}, retryable={retry}).")
    for i, c in enumerate((0, len(rows) + 1, 9999, U32_MAX), 1):
        a.add(f"ea-neg-{i:03d}-unknown-{c}", "classify_error", {"code": c}, code="unknown_error_code",
              desc=f"Code {c} is not assigned; readers must treat it as an opaque failure, not guess.")
    a.add("ea-neg-005-negative", "classify_error", {"code": -1}, code="unknown_error_code", desc="Negative codes are never assigned.")
    return a
