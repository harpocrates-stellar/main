"""Status semantics: contract `get_proof_status`, CLI verification classification, exit codes.

Sources of truth (read from the repo, not invented):
  * contracts/.../lib.rs `get_proof_status`: Revoked (status 2) > Expired (status 3) >
    Expired (expires_at > 0 && now > expires_at) > Valid; unknown proof -> NotFound.
  * cli/src/normalize.ts `computeResult` / `classifyVerification`.
  * cli/src/cli.ts exit-code table.
"""
from .common import Area, syn

TIER = {"silent": 1, "source": 2, "seal": 3}
NOW = 1_800_000_000


def build_status() -> Area:
    a = Area("status-semantics", "On-chain proof status: revocation, expiry, and boundary behaviour")

    def st(n, slug, record, now, status, desc, tier="required", why=None, code=None):
        inp = {"record": record, "now": now}
        if code:
            a.add(f"ss-{n:03d}-{slug}", "proof_status", inp, code=code, desc=desc, tier=tier, why=why)
        else:
            a.add(f"ss-{n:03d}-{slug}", "proof_status", inp, ok={"status": status}, desc=desc, tier=tier, why=why)

    st(1, "unknown-proof", None, NOW, "not_found", "No record: NotFound.")
    st(2, "registered-no-ttl", {"status": 1, "expires_at": 0}, NOW, "valid", "expires_at == 0 means the proof never expires.")
    st(3, "registered-far-future", {"status": 1, "expires_at": NOW + 10**9}, NOW, "valid", "Not yet expired.")
    st(4, "expiry-boundary-equal", {"status": 1, "expires_at": NOW}, NOW, "valid", "now == expires_at is still valid (strict >).")
    st(5, "expiry-boundary-plus-one", {"status": 1, "expires_at": NOW}, NOW + 1, "expired", "One second past expires_at is expired.")
    st(6, "stored-expired", {"status": 3, "expires_at": 0}, NOW, "expired", "Stored status 3 is expired regardless of expires_at.")
    st(7, "stored-revoked", {"status": 2, "expires_at": 0}, NOW, "revoked", "Stored status 2 is revoked.")
    st(8, "revoked-beats-expired-clock", {"status": 2, "expires_at": NOW - 5}, NOW, "revoked", "Revocation outranks clock expiry.")
    st(9, "revoked-beats-stored-expired-order", {"status": 2, "expires_at": 1}, NOW, "revoked", "Revocation is reported even when also past expiry.")
    st(10, "u64-max-expiry", {"status": 1, "expires_at": 2**64 - 1}, 2**64 - 1, "valid", "u64::MAX boundary: equal is valid; no overflow.")
    st(11, "u64-max-now", {"status": 1, "expires_at": 1}, 2**64 - 1, "expired", "Large clock values do not wrap.")
    st(12, "unknown-stored-status", {"status": 9, "expires_at": 0}, NOW, None,
       "Deployed `get_proof_status` treats an unrecognised stored status as Valid (fail-open) while the CLI "
       "classifier returns 'error' (fail-closed). Unreachable via current entry points, but the layers disagree.",
       tier="advisory", why="known_defect", code="unknown_status")
    st(13, "zero-stored-status", {"status": 0, "expires_at": 0}, NOW, None,
       "Status 0 is not defined; must not read as Valid.", tier="advisory", why="known_defect", code="unknown_status")
    return a


def build_verification() -> Area:
    a = Area("verification-result", "CLI verification classification and exit codes")

    man = {"videoHash": syn("vr/video"), "metadataHash": syn("vr/meta"), "tier": "silent"}

    def rec(**over):
        r = {"videoHash": syn("vr/video"), "metadataHash": syn("vr/meta"), "tier": 1, "status": 1, "expiresAt": None}
        r.update(over)
        return r

    def tx(status="confirmed", cm=None):
        return {"status": status, "contractMatch": cm}

    def vc(n, slug, transaction, record, result, desc, now=NOW, manifest=None, tier="required", why=None):
        a.add(f"vr-{n:03d}-{slug}", "verification_classify",
              {"manifest": manifest or man, "transaction": transaction, "chain_record": record, "now_seconds": now},
              ok={"result": result}, desc=desc, tier=tier, why=why)

    vc(1, "valid", tx(), rec(), "valid", "Confirmed tx, registered record, matching fields.")
    vc(2, "valid-contract-match-true", tx(cm=True), rec(), "valid", "contractMatch=true is fine.")
    vc(3, "contract-mismatch-wins", tx(cm=False), rec(), "contract_mismatch", "contractMatch=false overrides everything else.")
    vc(4, "contract-mismatch-beats-missing", tx("missing", False), None, "contract_mismatch", "Even with a missing transaction.")
    vc(5, "tx-missing", tx("missing"), None, "not_found", "Transaction not found on the network.")
    vc(6, "tx-failed", tx("failed"), rec(), "failed", "A failed transaction is never valid, even if a record exists.")
    vc(7, "tx-pending", tx("pending"), None, "pending", "Pending transaction.")
    vc(8, "tx-pending-with-record", tx("pending"), rec(), "pending", "Pending outranks a matching record.")
    vc(9, "confirmed-no-record", tx(), None, "not_found", "Confirmed tx but no registry record.")
    vc(10, "revoked", tx(), rec(status=2), "revoked", "Registry status 2.")
    vc(11, "expired-status", tx(), rec(status=3), "expired", "Registry status 3.")
    vc(12, "unknown-status", tx(), rec(status=9), "error", "Unrecognised registry status fails closed.")
    vc(13, "status-zero", tx(), rec(status=0), "error", "Status 0 fails closed.")
    vc(14, "expired-by-clock", tx(), rec(expiresAt=str(NOW - 1)), "expired", "expiresAt one second in the past.")
    vc(15, "expiry-boundary-equal", tx(), rec(expiresAt=str(NOW)), "valid", "expiresAt == now is still valid.")
    vc(16, "expires-zero-never", tx(), rec(expiresAt="0"), "valid", "expiresAt '0' means no expiry.")
    vc(17, "expires-u64-string", tx(), rec(expiresAt=str(2**64 - 1)), "valid", "u64::MAX as a decimal string: no float rounding.")
    vc(18, "expires-bigint-precision", tx(), rec(expiresAt="9007199254740995"), "expired",
       "9007199254740995 < 9007199254740996 exactly; as IEEE doubles both round to 9007199254740996 and the "
       "record would wrongly read as unexpired. Compare as integers (BigInt), never floats.", now=9007199254740996)
    vc(19, "video-hash-mismatch", tx(), rec(videoHash=syn("other")), "error", "Registry record is for a different video hash.")
    vc(20, "metadata-hash-mismatch", tx(), rec(metadataHash=syn("other")), "error", "Registry record has different metadata.")
    vc(21, "tier-mismatch", tx(), rec(tier=2), "error", "Manifest says silent (1) but the record says source (2).")
    vc(22, "hash-compare-case-insensitive", tx(), rec(videoHash=syn("vr/video").upper()), "valid", "Hex comparison ignores case.")
    vc(23, "mismatch-beats-revoked", tx(), rec(status=2, videoHash=syn("other")), "error",
       "Field disagreement is reported as error before revocation.")
    vc(24, "mismatch-beats-pending", tx("pending"), rec(videoHash=syn("other")), "error",
       "With a record present, a field mismatch outranks pending.")
    vc(25, "tier-seal", tx(), rec(tier=3), "valid", "Tier seal maps to 3.", manifest=dict(man, tier="seal"))

    for n, (res, code) in enumerate((("valid", 0), ("expired", 1), ("revoked", 2), ("not_found", 3), ("network_mismatch", 4),
                                     ("contract_mismatch", 5), ("pending", 6), ("failed", 7), ("error", 8)), 1):
        a.add(f"vr-exit-{n:03d}-{res}", "result_exit_code", {"result": res}, ok={"exit_code": code}, desc=f"'{res}' exits with {code}.")
    a.add("vr-exit-010-unknown-result", "result_exit_code", {"result": "bogus"}, ok={"exit_code": 8}, desc="Anything unrecognised exits 8 (error).")
    return a
