"""
C2PA interoperability layer for Harpocrates.

This module provides:
- Bounded parsing and validation of C2PA-compatible manifests (JSON envelope).
- Export of a C2PA-compatible manifest that binds Harpocrates evidence digests.
- An explicit, separate trust status enum so C2PA trust is never conflated with
  on-chain or ZK verification status.

Design constraints
------------------
- A C2PA claim is NOT equivalent to a Harpocrates proof.  The ``C2paTrustStatus``
  enum makes that separation mandatory and machine-readable.
- The parser enforces strict size, depth, algorithm, and resource limits before
  touching any assertion content.
- Unknown assertions are preserved verbatim in ``unknown_assertions`` with an
  explicit ``unsupported_semantics`` flag; they do not affect the parsed binding.
- All errors return typed ``C2paParseError`` instances; no raw exceptions escape
  this module's public surface.
- Observability: only the reject *reason code* and optional field *name* are
  logged/returned.  No claim bytes, assertion values, or digest material appear
  in error payloads.

Versioning
----------
``C2PA_HARPOCRATES_MAPPING_VERSION = 1`` pins the canonical field mapping from
Harpocrates evidence/proof digests to C2PA claim/assertion names.  A bump
requires a new mapping entry, migration documentation, and updated fixtures.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

# ---------------------------------------------------------------------------
# Version and constants
# ---------------------------------------------------------------------------

C2PA_HARPOCRATES_MAPPING_VERSION: int = 1
"""Increment when the canonical field mapping changes (not just additions)."""

_MAPPING_LABEL = "harpocrates.binding/v1"
"""C2PA assertion label used to embed the Harpocrates binding."""

_C2PA_MANIFEST_CLAIM_GENERATOR = "harpocrates"
_C2PA_SPEC_VERSION = "1.3"  # Version we target for compatibility labelling.

# Hard limits applied before any semantic parsing.
_MAX_MANIFEST_BYTES: int = 256 * 1024          # 256 KiB single manifest cap
_MAX_CUMULATIVE_MANIFEST_BYTES: int = 256 * 1024  # 256 KiB whole-graph cumulative cap
_MAX_CUMULATIVE_GRAPH_NODES: int = 2048        # Whole-graph JSON + ingredient node cap
_MAX_NESTED_MANIFEST_COUNT: int = 32           # Whole-graph nested manifest count cap
_MAX_ASSERTION_COUNT: int = 64
_MAX_ASSERTION_LABEL_LEN: int = 256
_MAX_ASSERTION_DATA_BYTES: int = 32 * 1024     # 32 KiB per assertion
_MAX_JSON_DEPTH: int = 16

# Supported hash algorithms (lower-case names, SHA-256 only for now).
_SUPPORTED_ALGORITHMS: frozenset[str] = frozenset({"sha256"})

# Required top-level manifest keys.
_REQUIRED_MANIFEST_KEYS: frozenset[str] = frozenset(
    {"claim_generator", "assertions", "harpocrates_binding"}
)

# Required keys inside harpocrates_binding.
_REQUIRED_BINDING_KEYS: frozenset[str] = frozenset(
    {
        "mapping_version",
        "video_hash",
        "metadata_hash",
        "proof_id",
        "tier",
        "network",
        "contract_id",
    }
)

# Allowed identity tiers (mirrors envelope.ALLOWED_TIERS).
_ALLOWED_TIERS: frozenset[str] = frozenset({"silent", "source", "seal"})

#: Binding fields that carry 32-byte hex digests. Compared case-insensitively.
_BINDING_HASH_FIELDS: tuple[str, ...] = ("video_hash", "metadata_hash", "proof_id")

#: Binding fields that carry free text. Compared after stripping whitespace.
_BINDING_TEXT_FIELDS: tuple[str, ...] = ("tier", "network", "contract_id")

# Hex-32 pattern (64 lower-case hex chars).
_HEX32_RE = re.compile(r"^[0-9a-f]{64}$")

# ---------------------------------------------------------------------------
# Trust status — MUST be kept separate from on-chain / ZK status
# ---------------------------------------------------------------------------


class C2paTrustStatus(str, Enum):
    """
    Explicit trust verdict for a parsed C2PA manifest.

    This is a *C2PA-level* verdict only.  It is entirely independent of:
    - on-chain registration status (Soroban)
    - ZK proof verification status (Noir / UltraHonk)
    - NeonDB event presence

    Callers MUST NOT treat ``SIGNATURE_VALID`` as equivalent to
    ``confirmed`` in the Harpocrates verification flow.
    """

    SIGNATURE_VALID = "signature_valid"
    """The manifest's self-described digest binding is internally consistent.
    No cryptographic signature verification is performed (out of scope)."""

    SIGNATURE_NOT_CHECKED = "signature_not_checked"
    """Signature verification was not attempted (default for all imports)."""

    UNSUPPORTED_ALGORITHM = "unsupported_algorithm"
    """The manifest references a hash algorithm not supported by this version."""

    BINDING_MISMATCH = "binding_mismatch"
    """The extracted binding digests do not match the claimed hashes."""

    PARSE_FAILED = "parse_failed"
    """The manifest could not be parsed; no trust can be assigned."""


# ---------------------------------------------------------------------------
# Error types
# ---------------------------------------------------------------------------


class C2paParseError(Exception):
    """Raised when manifest parsing fails.  Never leaks raw manifest bytes."""

    def __init__(self, reason: str, field: str | None = None) -> None:
        self.reason = reason
        self.field = field
        super().__init__(reason if field is None else f"{reason}: {field}")

    def to_dict(self) -> dict[str, str | None]:
        """Privacy-safe error payload: only reason code and field name."""
        return {"reason": self.reason, "field": self.field}


# Reason codes — stable, machine-readable.
class _Reason:
    MANIFEST_TOO_LARGE = "manifest_too_large"
    NOT_JSON = "not_json"
    DEPTH_EXCEEDED = "depth_exceeded"
    NOT_OBJECT = "not_object"
    MISSING_KEY = "missing_key"
    INVALID_TYPE = "invalid_type"
    INVALID_VALUE = "invalid_value"
    ASSERTION_COUNT_EXCEEDED = "assertion_count_exceeded"
    ASSERTION_LABEL_TOO_LONG = "assertion_label_too_long"
    ASSERTION_DATA_TOO_LARGE = "assertion_data_too_large"
    UNSUPPORTED_ALGORITHM = "unsupported_algorithm"
    DIGEST_MISMATCH = "digest_mismatch"
    MAPPING_VERSION_MISMATCH = "mapping_version_mismatch"
    RECURSION_DETECTED = "recursion_detected"
    EMBEDDED_BINDING_MISMATCH = "embedded_binding_mismatch"
    EMBEDDED_BINDING_DUPLICATE = "embedded_binding_duplicate"
    CUMULATIVE_BYTES_EXCEEDED = "cumulative_bytes_exceeded"
    CUMULATIVE_NODES_EXCEEDED = "cumulative_nodes_exceeded"
    CUMULATIVE_MANIFESTS_EXCEEDED = "cumulative_manifests_exceeded"


# ---------------------------------------------------------------------------
# Parsed / exported data types
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class C2paHarpocratesBinding:
    """
    The Harpocrates-specific fields extracted from or written into a C2PA manifest.

    These are the canonical bindings between Harpocrates evidence digests and
    C2PA claim assertions.  See ``C2PA_HARPOCRATES_MAPPING_VERSION``.
    """

    mapping_version: int
    video_hash: str          # 32-byte hex (embedded video hash registered on-chain)
    metadata_hash: str       # 32-byte hex
    proof_id: str            # 32-byte hex
    tier: str                # 'silent' | 'source' | 'seal'
    network: str             # Stellar network passphrase
    contract_id: str         # Soroban registry contract ID


@dataclass
class C2paUnknownAssertion:
    """An assertion whose label or content is not recognised by this version."""

    label: str
    data: Any
    unsupported_semantics: bool = True


@dataclass
class C2paExpansionBudget:
    """Shared whole-graph resource accumulator across root and nested ingredients.

    Passed by reference into every nested manifest/ingredient expansion step so
    byte, node, and nested-manifest limits apply cumulatively across the entire
    graph rather than resetting per nested object.
    """

    max_bytes: int = _MAX_CUMULATIVE_MANIFEST_BYTES
    max_nodes: int = _MAX_CUMULATIVE_GRAPH_NODES
    max_manifests: int = _MAX_NESTED_MANIFEST_COUNT
    consumed_bytes: int = 0
    consumed_nodes: int = 0
    manifest_count: int = 0

    def charge_bytes(self, byte_count: int, *, field: str | None = None) -> None:
        self.consumed_bytes += max(0, int(byte_count))
        if self.consumed_bytes > self.max_bytes:
            raise C2paParseError(_Reason.CUMULATIVE_BYTES_EXCEEDED, field)

    def charge_node(self, *, field: str | None = None) -> None:
        self.consumed_nodes += 1
        if self.consumed_nodes > self.max_nodes:
            raise C2paParseError(_Reason.CUMULATIVE_NODES_EXCEEDED, field)

    def charge_manifest(self, *, field: str | None = None) -> None:
        self.manifest_count += 1
        if self.manifest_count > self.max_manifests:
            raise C2paParseError(_Reason.CUMULATIVE_MANIFESTS_EXCEEDED, field)

    def snapshot(self) -> dict[str, int]:
        return {
            "consumed_bytes": self.consumed_bytes,
            "consumed_nodes": self.consumed_nodes,
            "manifest_count": self.manifest_count,
        }


@dataclass
class C2paParsedManifest:
    """
    Result of a successful ``parse_c2pa_manifest`` call.

    ``trust_status`` is always ``SIGNATURE_NOT_CHECKED`` on import (signature
    verification is out of scope for this module).  The caller must not
    promote this to an on-chain or ZK trust level without additional checks.
    """

    claim_generator: str
    spec_version: str | None
    binding: C2paHarpocratesBinding
    unknown_assertions: list[C2paUnknownAssertion] = field(default_factory=list)
    trust_status: C2paTrustStatus = C2paTrustStatus.SIGNATURE_NOT_CHECKED
    nested_ingredients: list[C2paParsedManifest] = field(default_factory=list)
    expansion_stats: dict[str, int] = field(default_factory=dict)


@dataclass(frozen=True)
class C2paExportedManifest:
    """
    A serialisable C2PA-compatible manifest produced by ``export_c2pa_manifest``.

    The ``manifest`` field is the canonical JSON-serialisable dict.
    The ``digest`` field is the SHA-256 of the canonical JSON encoding, for
    round-trip integrity verification.
    """

    manifest: dict[str, Any]
    digest: str   # hex-encoded SHA-256 of canonical JSON


@dataclass(frozen=True)
class C2paHashCorroboration:
    """
    Result of comparing caller-submitted hashes against an embedded binding.

    ``compared_fields`` and ``mismatches`` carry field *names* only — never a
    hash value, digest byte, or manifest content — so the result is safe to log
    and safe to return to a caller.
    """

    ok: bool
    compared_fields: tuple[str, ...] = ()
    mismatches: tuple[str, ...] = ()


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def parse_c2pa_manifest(
    raw: bytes | str,
    *,
    max_cumulative_bytes: int = _MAX_CUMULATIVE_MANIFEST_BYTES,
    max_cumulative_nodes: int = _MAX_CUMULATIVE_GRAPH_NODES,
    max_nested_manifests: int = _MAX_NESTED_MANIFEST_COUNT,
    _budget: C2paExpansionBudget | None = None,
) -> C2paParsedManifest:
    """
    Parse and validate a C2PA-compatible manifest and any nested ingredients.

    Applies strict whole-graph byte, node, depth, algorithm, and resource limits
    before semantic processing. Limits are tracked in a single shared
    ``C2paExpansionBudget`` across the root manifest and all nested ingredient
    objects so limits never reset per nested manifest.
    """
    budget = (
        _budget
        if _budget is not None
        else C2paExpansionBudget(
            max_bytes=max_cumulative_bytes,
            max_nodes=max_cumulative_nodes,
            max_manifests=max_nested_manifests,
        )
    )
    return _parse_manifest_recursive(
        raw,
        budget=budget,
        base_depth=0,
        charge_bytes_and_nodes=True,
        field_prefix=None,
    )


def parse_c2pa_ingredient_graph(
    manifests: list[bytes | str | dict[str, Any]],
    *,
    max_cumulative_bytes: int = _MAX_CUMULATIVE_MANIFEST_BYTES,
    max_cumulative_nodes: int = _MAX_CUMULATIVE_GRAPH_NODES,
    max_nested_manifests: int = _MAX_NESTED_MANIFEST_COUNT,
) -> list[C2paParsedManifest]:
    """Parse a graph of C2PA manifests under a single shared expansion budget."""
    if not isinstance(manifests, list):
        raise C2paParseError(_Reason.INVALID_TYPE, "manifests")

    budget = C2paExpansionBudget(
        max_bytes=max_cumulative_bytes,
        max_nodes=max_cumulative_nodes,
        max_manifests=max_nested_manifests,
    )
    parsed_list: list[C2paParsedManifest] = []
    for idx, item in enumerate(manifests):
        if isinstance(item, dict):
            try:
                encoded: bytes | str = _canonical_json(item)
            except (TypeError, ValueError):
                raise C2paParseError(_Reason.INVALID_TYPE, f"manifests[{idx}]")
        elif isinstance(item, (bytes, str)):
            encoded = item
        else:
            raise C2paParseError(_Reason.INVALID_TYPE, f"manifests[{idx}]")

        parsed_list.append(
            _parse_manifest_recursive(
                encoded,
                budget=budget,
                base_depth=0,
                charge_bytes_and_nodes=True,
                field_prefix=f"manifests[{idx}]",
            )
        )
    return parsed_list


def _parse_manifest_recursive(
    raw: bytes | str | dict[str, Any],
    *,
    budget: C2paExpansionBudget,
    base_depth: int,
    charge_bytes_and_nodes: bool,
    field_prefix: str | None,
) -> C2paParsedManifest:
    budget.charge_manifest(field=field_prefix)

    if isinstance(raw, dict):
        data = raw
        if charge_bytes_and_nodes:
            encoded_bytes = _canonical_json(data)
            if len(encoded_bytes) > _MAX_MANIFEST_BYTES:
                raise C2paParseError(_Reason.MANIFEST_TOO_LARGE, field_prefix)
            budget.charge_bytes(len(encoded_bytes), field=field_prefix)
            _check_depth(
                data,
                limit=_MAX_JSON_DEPTH,
                _current=base_depth,
                budget=budget,
                field_prefix=field_prefix,
            )
    else:
        raw_bytes = raw.encode("utf-8") if isinstance(raw, str) else raw
        if len(raw_bytes) > _MAX_MANIFEST_BYTES:
            raise C2paParseError(_Reason.MANIFEST_TOO_LARGE, field_prefix)
        if charge_bytes_and_nodes:
            budget.charge_bytes(len(raw_bytes), field=field_prefix)
        try:
            data = json.loads(raw_bytes.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise C2paParseError(_Reason.NOT_JSON, field_prefix)
        if charge_bytes_and_nodes:
            _check_depth(
                data,
                limit=_MAX_JSON_DEPTH,
                _current=base_depth,
                budget=budget,
                field_prefix=field_prefix,
            )

    def _qualify(name: str) -> str:
        return f"{field_prefix}.{name}" if field_prefix else name

    # 4. Top-level must be an object.
    if not isinstance(data, dict):
        raise C2paParseError(_Reason.NOT_OBJECT, field_prefix)

    # 5. Required top-level keys.
    for key in _REQUIRED_MANIFEST_KEYS:
        if key not in data:
            raise C2paParseError(_Reason.MISSING_KEY, _qualify(key))

    # 6. claim_generator.
    claim_generator = data["claim_generator"]
    if not isinstance(claim_generator, str) or not claim_generator.strip():
        raise C2paParseError(_Reason.INVALID_TYPE, _qualify("claim_generator"))

    # 7. spec_version (optional).
    spec_version: str | None = None
    if "spec_version" in data:
        sv = data["spec_version"]
        if not isinstance(sv, str):
            raise C2paParseError(_Reason.INVALID_TYPE, _qualify("spec_version"))
        spec_version = sv

    # 8. assertions list.
    assertions_raw = data["assertions"]
    if not isinstance(assertions_raw, list):
        raise C2paParseError(_Reason.INVALID_TYPE, _qualify("assertions"))
    if len(assertions_raw) > _MAX_ASSERTION_COUNT:
        raise C2paParseError(_Reason.ASSERTION_COUNT_EXCEEDED, _qualify("assertions"))

    unknown: list[C2paUnknownAssertion] = []
    assertion_bindings: list[C2paHarpocratesBinding] = []
    nested_parsed: list[C2paParsedManifest] = []

    for idx, assertion in enumerate(assertions_raw):
        a_path = _qualify(f"assertions[{idx}]")
        if not isinstance(assertion, dict):
            raise C2paParseError(_Reason.INVALID_TYPE, a_path)
        label = assertion.get("label", "")
        if not isinstance(label, str):
            raise C2paParseError(_Reason.INVALID_TYPE, f"{a_path}.label")
        if len(label) > _MAX_ASSERTION_LABEL_LEN:
            raise C2paParseError(_Reason.ASSERTION_LABEL_TOO_LONG, f"{a_path}.label")
        # Measure assertion data size.
        try:
            assertion_bytes = json.dumps(assertion, separators=(",", ":")).encode("utf-8")
        except (TypeError, ValueError):
            raise C2paParseError(_Reason.INVALID_TYPE, a_path)
        if len(assertion_bytes) > _MAX_ASSERTION_DATA_BYTES:
            raise C2paParseError(_Reason.ASSERTION_DATA_TOO_LARGE, a_path)

        if label == _MAPPING_LABEL:
            assertion_bindings.append(
                _parse_binding(assertion.get("data"), prefix=f"{a_path}.data")
            )
            continue

        # Expand any nested ingredient manifests embedded inside ingredient assertions
        # under the SAME cumulative budget and depth.
        a_data = assertion.get("data")
        if isinstance(a_data, dict) and "ingredient" in label.lower():
            nested_parsed.extend(
                _expand_ingredient_entries(
                    [a_data],
                    budget=budget,
                    base_depth=base_depth + 3,
                    list_prefix=f"{a_path}.data",
                )
            )

        unknown.append(
            C2paUnknownAssertion(
                label=label,
                data=a_data,
                unsupported_semantics=True,
            )
        )

    # 9. algorithm check (optional field; only SHA-256 supported).
    if "alg" in data:
        alg = data["alg"]
        if not isinstance(alg, str):
            raise C2paParseError(_Reason.INVALID_TYPE, _qualify("alg"))
        if alg.lower() not in _SUPPORTED_ALGORITHMS:
            raise C2paParseError(_Reason.UNSUPPORTED_ALGORITHM, _qualify("alg"))

    # 10. harpocrates_binding.
    binding_raw = data["harpocrates_binding"]
    binding = _parse_binding(binding_raw, prefix=_qualify("harpocrates_binding"))

    # 11. Dual-copy binding agreement.
    if len(assertion_bindings) > 1:
        raise C2paParseError(_Reason.EMBEDDED_BINDING_DUPLICATE, _MAPPING_LABEL)
    if assertion_bindings:
        _require_consistent_embedded_binding(binding, assertion_bindings[0])

    # 12. Expand top-level nested ingredients using the SAME shared budget.
    if "ingredients" in data:
        ingredients_raw = data["ingredients"]
        if not isinstance(ingredients_raw, list):
            raise C2paParseError(_Reason.INVALID_TYPE, _qualify("ingredients"))
        if len(ingredients_raw) > _MAX_ASSERTION_COUNT:
            raise C2paParseError(_Reason.ASSERTION_COUNT_EXCEEDED, _qualify("ingredients"))
        nested_parsed.extend(
            _expand_ingredient_entries(
                ingredients_raw,
                budget=budget,
                base_depth=base_depth + 2,
                list_prefix=_qualify("ingredients"),
            )
        )

    return C2paParsedManifest(
        claim_generator=claim_generator.strip(),
        spec_version=spec_version,
        binding=binding,
        unknown_assertions=unknown,
        trust_status=C2paTrustStatus.SIGNATURE_NOT_CHECKED,
        nested_ingredients=nested_parsed,
        expansion_stats=budget.snapshot(),
    )


def _expand_ingredient_entries(
    entries: list[Any],
    *,
    budget: C2paExpansionBudget,
    base_depth: int,
    list_prefix: str,
) -> list[C2paParsedManifest]:
    """Recursively expand nested ingredient objects without resetting cumulative limits."""
    expanded: list[C2paParsedManifest] = []
    for idx, entry in enumerate(entries):
        item_path = f"{list_prefix}[{idx}]"
        if not isinstance(entry, dict):
            raise C2paParseError(_Reason.INVALID_TYPE, item_path)

        if "manifest" in entry:
            nested_m = entry["manifest"]
            m_path = f"{item_path}.manifest"
            if isinstance(nested_m, str):
                # String-encoded nested manifest: charge its expanded bytes & nodes
                # into the shared graph budget and continue cumulative depth!
                if _is_harpocrates_manifest_candidate_str(nested_m, budget=budget, field=m_path, base_depth=base_depth + 1):
                    expanded.append(
                        _parse_manifest_recursive(
                            nested_m,
                            budget=budget,
                            base_depth=base_depth + 1,
                            charge_bytes_and_nodes=False,
                            field_prefix=m_path,
                        )
                    )
            elif isinstance(nested_m, dict):
                if "harpocrates_binding" in nested_m or _has_mapping_assertion(nested_m):
                    expanded.append(
                        _parse_manifest_recursive(
                            nested_m,
                            budget=budget,
                            base_depth=base_depth + 1,
                            charge_bytes_and_nodes=False,
                            field_prefix=m_path,
                        )
                    )
                elif "ingredients" in nested_m:
                    sub_ings = nested_m["ingredients"]
                    if not isinstance(sub_ings, list):
                        raise C2paParseError(_Reason.INVALID_TYPE, f"{m_path}.ingredients")
                    if len(sub_ings) > _MAX_ASSERTION_COUNT:
                        raise C2paParseError(_Reason.ASSERTION_COUNT_EXCEEDED, f"{m_path}.ingredients")
                    expanded.extend(
                        _expand_ingredient_entries(
                            sub_ings,
                            budget=budget,
                            base_depth=base_depth + 2,
                            list_prefix=f"{m_path}.ingredients",
                        )
                    )
            else:
                raise C2paParseError(_Reason.INVALID_TYPE, m_path)
        elif "ingredients" in entry:
            sub_ings = entry["ingredients"]
            if not isinstance(sub_ings, list):
                raise C2paParseError(_Reason.INVALID_TYPE, f"{item_path}.ingredients")
            if len(sub_ings) > _MAX_ASSERTION_COUNT:
                raise C2paParseError(_Reason.ASSERTION_COUNT_EXCEEDED, f"{item_path}.ingredients")
            expanded.extend(
                _expand_ingredient_entries(
                    sub_ings,
                    budget=budget,
                    base_depth=base_depth + 1,
                    list_prefix=f"{item_path}.ingredients",
                )
            )
    return expanded


def _has_mapping_assertion(manifest_dict: dict[str, Any]) -> bool:
    assertions = manifest_dict.get("assertions")
    return isinstance(assertions, list) and any(
        isinstance(a, dict) and a.get("label") == _MAPPING_LABEL for a in assertions
    )


def _is_harpocrates_manifest_candidate_str(
    nested_str: str,
    *,
    budget: C2paExpansionBudget,
    field: str,
    base_depth: int,
) -> bool:
    raw_bytes = nested_str.encode("utf-8")
    if len(raw_bytes) > _MAX_MANIFEST_BYTES:
        raise C2paParseError(_Reason.MANIFEST_TOO_LARGE, field)
    budget.charge_bytes(len(raw_bytes), field=field)
    try:
        decoded = json.loads(nested_str)
    except json.JSONDecodeError:
        raise C2paParseError(_Reason.NOT_JSON, field)
    _check_depth(
        decoded,
        limit=_MAX_JSON_DEPTH,
        _current=base_depth,
        budget=budget,
        field_prefix=field,
    )
    if not isinstance(decoded, dict):
        raise C2paParseError(_Reason.NOT_OBJECT, field)
    if "harpocrates_binding" in decoded or _has_mapping_assertion(decoded):
        return True
    if "ingredients" in decoded:
        sub_ings = decoded["ingredients"]
        if not isinstance(sub_ings, list):
            raise C2paParseError(_Reason.INVALID_TYPE, f"{field}.ingredients")
        budget.charge_manifest(field=field)
        _expand_ingredient_entries(
            sub_ings,
            budget=budget,
            base_depth=base_depth + 1,
            list_prefix=f"{field}.ingredients",
        )
    else:
        budget.charge_manifest(field=field)
    return False


def export_c2pa_manifest(
    *,
    video_hash: str,
    metadata_hash: str,
    proof_id: str,
    tier: str,
    network: str,
    contract_id: str,
    claim_generator: str | None = None,
) -> C2paExportedManifest:
    """
    Export a C2PA-compatible manifest that binds Harpocrates evidence digests.

    The manifest is idempotent: identical inputs always produce byte-identical
    JSON (keys are sorted, separators are compact).

    The trust status of an exported manifest is always
    ``C2paTrustStatus.SIGNATURE_NOT_CHECKED``; the caller is responsible for
    any downstream cryptographic signing.

    Args:
        video_hash:     32-byte hex — the embedded video hash registered on-chain.
        metadata_hash:  32-byte hex — canonical metadata hash.
        proof_id:       32-byte hex — Harpocrates proof ID.
        tier:           Identity tier ('silent' | 'source' | 'seal').
        network:        Stellar network passphrase.
        contract_id:    Soroban registry contract ID.
        claim_generator: Optional override for the claim_generator field.

    Returns:
        A ``C2paExportedManifest`` containing the manifest dict and its SHA-256
        digest for round-trip verification.

    Raises:
        ValueError: If any required field fails validation.
    """
    _validate_hex32(video_hash, "video_hash")
    _validate_hex32(metadata_hash, "metadata_hash")
    _validate_hex32(proof_id, "proof_id")
    if tier not in _ALLOWED_TIERS:
        raise ValueError(f"tier must be one of {sorted(_ALLOWED_TIERS)}, got: {tier!r}")
    if not isinstance(network, str) or not network.strip():
        raise ValueError("network must be a non-empty string")
    if not isinstance(contract_id, str) or not contract_id.strip():
        raise ValueError("contract_id must be a non-empty string")

    manifest: dict[str, Any] = {
        "claim_generator": (claim_generator or _C2PA_MANIFEST_CLAIM_GENERATOR).strip(),
        "spec_version": _C2PA_SPEC_VERSION,
        "alg": "sha256",
        "assertions": [
            # The Harpocrates-specific binding assertion.
            {
                "label": _MAPPING_LABEL,
                "data": {
                    "mapping_version": C2PA_HARPOCRATES_MAPPING_VERSION,
                    "video_hash": video_hash.lower(),
                    "metadata_hash": metadata_hash.lower(),
                    "proof_id": proof_id.lower(),
                    "tier": tier,
                    "network": network.strip(),
                    "contract_id": contract_id.strip(),
                },
            }
        ],
        "harpocrates_binding": {
            "mapping_version": C2PA_HARPOCRATES_MAPPING_VERSION,
            "video_hash": video_hash.lower(),
            "metadata_hash": metadata_hash.lower(),
            "proof_id": proof_id.lower(),
            "tier": tier,
            "network": network.strip(),
            "contract_id": contract_id.strip(),
        },
    }

    canonical = _canonical_json(manifest)
    digest = hashlib.sha256(canonical).hexdigest()
    return C2paExportedManifest(manifest=manifest, digest=digest)


def verify_round_trip(exported: C2paExportedManifest) -> bool:
    """
    Verify that an exported manifest survives a parse round-trip intact.

    Returns True if and only if:
    1. The manifest parses without error.
    2. The re-serialised canonical JSON hashes to the same digest as the export.
    3. All binding fields are preserved byte-for-byte.

    This is a determinism check; it does not perform cryptographic signature
    verification.
    """
    try:
        raw = _canonical_json(exported.manifest)
        parsed = parse_c2pa_manifest(raw)
    except C2paParseError:
        return False

    # Re-export using the parsed binding fields and compare digests.
    try:
        re_exported = export_c2pa_manifest(
            video_hash=parsed.binding.video_hash,
            metadata_hash=parsed.binding.metadata_hash,
            proof_id=parsed.binding.proof_id,
            tier=parsed.binding.tier,
            network=parsed.binding.network,
            contract_id=parsed.binding.contract_id,
            claim_generator=parsed.claim_generator,
        )
    except ValueError:
        return False

    return re_exported.digest == exported.digest


def corroborate_binding(
    parsed: C2paParsedManifest,
    *,
    video_hash: str | None = None,
    metadata_hash: str | None = None,
    proof_id: str | None = None,
    tier: str | None = None,
    network: str | None = None,
    contract_id: str | None = None,
) -> C2paHashCorroboration:
    """Verify caller-submitted values against the binding embedded in *parsed*.

    This is the submitted-vs-embedded half of C2PA import: an ``export`` digest
    binds hashes *inside* the manifest, but nothing there ties them to the
    evidence a caller is asking about. Passing the hashes the caller claims
    (typically the registered ``video_hash``/``metadata_hash``/``proof_id``)
    makes the import reject a manifest whose embedded binding describes
    different evidence.

    Only the fields the caller supplies are compared, in a fixed order —
    ``video_hash``, ``metadata_hash``, ``proof_id``, ``tier``, ``network``,
    ``contract_id`` — so identical inputs always produce the same result.

    A mismatch is *reported*, not raised: the caller chooses the policy (the
    ``/api/c2pa/import`` endpoint rejects with a stable 400). Malformed
    submitted values raise :class:`ValueError` whose message contains the field
    name and static text only.

    Returns:
        A :class:`C2paHashCorroboration`. ``ok`` is True only when every
        supplied field matched the embedded binding.
    """
    submitted: dict[str, str | None] = {
        "video_hash": video_hash,
        "metadata_hash": metadata_hash,
        "proof_id": proof_id,
        "tier": tier,
        "network": network,
        "contract_id": contract_id,
    }

    compared: list[str] = []
    mismatches: list[str] = []

    for field_name in _BINDING_HASH_FIELDS + _BINDING_TEXT_FIELDS:
        supplied = submitted[field_name]
        if supplied is None:
            continue

        if field_name in _BINDING_HASH_FIELDS:
            _validate_hex32(supplied, field_name)  # raises ValueError on malformed hex
            normalised = supplied.lower()
        else:
            if not isinstance(supplied, str) or not supplied.strip():
                raise ValueError(f"{field_name} must be a non-empty string")
            normalised = supplied.strip()

        compared.append(field_name)
        if normalised != getattr(parsed.binding, field_name):
            mismatches.append(field_name)

    return C2paHashCorroboration(
        ok=not mismatches,
        compared_fields=tuple(compared),
        mismatches=tuple(mismatches),
    )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _parse_binding(
    raw: Any, *, prefix: str = "harpocrates_binding"
) -> C2paHarpocratesBinding:
    """Validate one embedded copy of the Harpocrates binding.

    ``prefix`` names the location of the copy in the manifest so error payloads
    point at the offending path (``harpocrates_binding`` or
    ``assertions[i].data``) without echoing any value.
    """
    if not isinstance(raw, dict):
        raise C2paParseError(_Reason.INVALID_TYPE, prefix)

    for key in _REQUIRED_BINDING_KEYS:
        if key not in raw:
            raise C2paParseError(_Reason.MISSING_KEY, f"{prefix}.{key}")

    mv = raw["mapping_version"]
    if not isinstance(mv, int) or mv < 1:
        raise C2paParseError(_Reason.INVALID_TYPE, f"{prefix}.mapping_version")
    if mv != C2PA_HARPOCRATES_MAPPING_VERSION:
        raise C2paParseError(
            _Reason.MAPPING_VERSION_MISMATCH,
            f"{prefix}.mapping_version",
        )

    for hex_field in _BINDING_HASH_FIELDS:
        val = raw[hex_field]
        if not isinstance(val, str):
            raise C2paParseError(_Reason.INVALID_TYPE, f"{prefix}.{hex_field}")
        if not _HEX32_RE.match(val.lower()):
            raise C2paParseError(_Reason.INVALID_VALUE, f"{prefix}.{hex_field}")

    tier = raw["tier"]
    if not isinstance(tier, str) or tier not in _ALLOWED_TIERS:
        raise C2paParseError(_Reason.INVALID_VALUE, f"{prefix}.tier")

    network = raw["network"]
    if not isinstance(network, str) or not network.strip():
        raise C2paParseError(_Reason.INVALID_VALUE, f"{prefix}.network")

    contract_id = raw["contract_id"]
    if not isinstance(contract_id, str) or not contract_id.strip():
        raise C2paParseError(_Reason.INVALID_VALUE, f"{prefix}.contract_id")

    return C2paHarpocratesBinding(
        mapping_version=mv,
        video_hash=raw["video_hash"].lower(),
        metadata_hash=raw["metadata_hash"].lower(),
        proof_id=raw["proof_id"].lower(),
        tier=tier,
        network=network.strip(),
        contract_id=contract_id.strip(),
    )


def _require_consistent_embedded_binding(
    top_level: C2paHarpocratesBinding,
    assertion: C2paHarpocratesBinding,
) -> None:
    """Reject a manifest whose two embedded copies of the binding disagree.

    The binding is embedded twice by design (named assertion plus top-level
    object) so that both assertion-based and direct consumers can read it. A
    manifest that carries contradictory hashes in the two copies must not be
    accepted: which copy a consumer reads would otherwise decide the verdict.
    Only the offending field *name* is reported.
    """
    if top_level.mapping_version != assertion.mapping_version:
        raise C2paParseError(_Reason.EMBEDDED_BINDING_MISMATCH, "mapping_version")

    for field_name in _BINDING_HASH_FIELDS + _BINDING_TEXT_FIELDS:
        if getattr(top_level, field_name) != getattr(assertion, field_name):
            raise C2paParseError(_Reason.EMBEDDED_BINDING_MISMATCH, field_name)


def _validate_hex32(value: Any, name: str) -> None:
    if not isinstance(value, str) or not _HEX32_RE.match(value.lower()):
        raise ValueError(f"{name} must be a 32-byte lower-case hex string (64 chars)")


def _canonical_json(obj: Any) -> bytes:
    """Deterministic, compact JSON encoding (keys sorted recursively)."""
    return json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("utf-8")


def _check_depth(
    obj: Any,
    limit: int,
    _current: int = 0,
    *,
    budget: C2paExpansionBudget | None = None,
    field_prefix: str | None = None,
) -> None:
    """Enforce nesting depth and cumulative graph node bounds across the structure."""
    if _current > limit:
        raise C2paParseError(_Reason.DEPTH_EXCEEDED, field_prefix)
    if budget is not None:
        budget.charge_node(field=field_prefix)
    if isinstance(obj, dict):
        for v in obj.values():
            _check_depth(
                v,
                limit,
                _current + 1,
                budget=budget,
                field_prefix=field_prefix,
            )
    elif isinstance(obj, list):
        for item in obj:
            _check_depth(
                item,
                limit,
                _current + 1,
                budget=budget,
                field_prefix=field_prefix,
            )
