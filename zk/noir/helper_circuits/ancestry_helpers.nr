// Ancestry helper circuit: bounded depth and fan-out constants
// shared by the redacted derivative ancestry circuit and the canonical
// lineage manifest tooling. These values are pinned to the backend
// constants in backend/lineage.py so the circuit and the host validator
// agree on the trust boundary.

global MAX_ANCESTRY_DEPTH: u32 = 4;
global MAX_ANCESTRY_FANOUT: u32 = 4;

// Domain tags for domain-separated commitments. These must match the
// domain tags used by the host tooling when building the canonical
// lineage manifest digest.
global DOMAIN_LINEAGE_MANIFEST: u8 = 0x01;
global DOMAIN_OUTPUT_DIGEST: u8 = 0x02;
global DOMAIN_NONCE: u8 = 0x03;

// Returns true when the given depth is within the bounded ancestry
// depth and fan-out limits. This is the canonical check used by the
// redacted derivative ancestry circuit and by the host validator.
pub fn depth_in_bounds(depth: u32) -> bool {
    depth >= 1 && depth <= MAX_ANCESTRY_DEEPH
}

// Returns true when the given fan-out is within the bounded limit.
pub fn fanout_in_bounds(fanout: u32) -> bool {
    fanout >= 1 && fanout <= MAX_ANCESTRY_FANOUT
}

// Returns true when the given domain tag is a recognized commitment
// domain. Unknown domains are rejected so the circuit fails closed on
// unsupported inputs.
pub fn is_known_domain(domain: u8) -> bool {
    domain == DOMAIN_LINEAGE_MANIFEST
        || domain == DOMAIN_OUTPUT_DIGEST
        || domain == DOMAIN_NONCE
}
