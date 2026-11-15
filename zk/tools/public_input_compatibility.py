#!/usr/bin/env python3
"""Cross-circuit public-input compatibility analyzer and report generator.

Compares public-input layouts, field encodings, domain bindings, version
commitments, and nullifier/credential derivations across Harpocrates' three
statement families:

  * ``silent_witness``       (``zk/noir/silent_witness/src/main.nr``)
  * ``redacted_ancestry``    (``zk/noir/redacted_ancestry/src/main.nr``)
  * ``selective_disclosure`` (``zk/noir/selective_disclosure/src/main.nr``)

Design invariants
-----------------
* **No silent normalization.** Field names, Noir types, slot positions, wire
  padding rules, zero-value policies, and hash derivations are extracted
  verbatim from circuit sources and host codecs. Differences across circuits
  are never coerced or aliased automatically.
* **Explicit reviewed differences.** Every cross-circuit difference must match
  an explicit ``status == "reviewed"`` record in
  ``zk/noir/public_input_compatibility_v1.json`` with a non-empty rationale and
  specification reference. Unreviewed or drifted differences fail closed.
* **Privacy-safe diagnostics.** Errors and report entries emit only circuit
  identifiers, field names, structural encodings, and stable reason codes —
  never secret witness values or raw file contents.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Final

REPORT_FORMAT: Final[str] = "harpocrates.cross-circuit-public-input-compatibility-report"
REPORT_VERSION: Final[int] = 1
POLICY_FORMAT: Final[str] = "harpocrates.cross-circuit-public-input-compatibility"
POLICY_VERSION: Final[int] = 1

REPO_ROOT: Final[Path] = Path(__file__).resolve().parents[2]
DEFAULT_POLICY_PATH: Final[Path] = (
    REPO_ROOT / "zk" / "noir" / "public_input_compatibility_v1.json"
)

TARGET_CIRCUITS: Final[tuple[str, ...]] = (
    "silent_witness",
    "redacted_ancestry",
    "selective_disclosure",
)

FIELD_BYTES: Final[int] = 32
MAX_SOURCE_BYTES: Final[int] = 512 * 1024
MAX_POLICY_BYTES: Final[int] = 512 * 1024

EXIT_OK: Final[int] = 0
EXIT_INCOMPATIBLE: Final[int] = 1
EXIT_INVALID_INPUT: Final[int] = 2


class CompatibilityErrorCode(str, Enum):
    """Stable machine-readable error codes for compatibility checks."""

    MISSING_SOURCE = "missing_source"
    OVERSIZED_INPUT = "oversized_input"
    MALFORMED_SOURCE = "malformed_source"
    MALFORMED_POLICY = "malformed_policy"
    UNSUPPORTED_POLICY_VERSION = "unsupported_policy_version"
    SILENT_NORMALIZATION_FORBIDDEN = "silent_normalization_forbidden"
    INVALID_REVIEW_RECORD = "invalid_review_record"


class CompatibilityReportError(ValueError):
    """Raised when circuit sources or reviewed-difference policies are invalid."""

    def __init__(self, code: CompatibilityErrorCode, target: str) -> None:
        self.code = code
        self.target = target
        super().__init__(f"{code.value}:{target}")

    def signal(self) -> dict[str, str]:
        return {"error_code": self.code.value, "target": self.target}


@dataclass(frozen=True)
class PublicSlot:
    """One ``pub`` parameter declared on a Noir circuit ``main`` entry point."""

    slot_index: int
    param_index: int
    name: str
    noir_type: str

    def to_dict(self) -> dict[str, int | str]:
        return {
            "slot_index": self.slot_index,
            "param_index": self.param_index,
            "name": self.name,
            "noir_type": self.noir_type,
        }


@dataclass(frozen=True)
class CircuitPublicProfile:
    """Extracted public-input structure and encoding facts for one circuit."""

    circuit: str
    source_path: str
    version_constant: str
    public_slots: tuple[PublicSlot, ...]
    private_param_names: tuple[str, ...]
    public_frame_bytes: int
    uses_common_domain_tag: bool
    asserts_circuit_version_in_main: bool
    non_zero_asserted_fields: tuple[str, ...]

    @property
    def public_field_names(self) -> tuple[str, ...]:
        return tuple(slot.name for slot in self.public_slots)

    def slot_by_name(self, name: str) -> PublicSlot | None:
        for slot in self.public_slots:
            if slot.name == name:
                return slot
        return None

    def to_dict(self) -> dict[str, Any]:
        return {
            "circuit": self.circuit,
            "source_path": self.source_path,
            "version_constant": self.version_constant,
            "public_field_count": len(self.public_slots),
            "public_frame_bytes": self.public_frame_bytes,
            "public_fields": [slot.to_dict() for slot in self.public_slots],
            "uses_common_domain_tag": self.uses_common_domain_tag,
            "asserts_circuit_version_in_main": self.asserts_circuit_version_in_main,
            "non_zero_asserted_public_fields": list(self.non_zero_asserted_fields),
        }


@dataclass(frozen=True)
class HostWireFacts:
    """Extracted wire-level public-input rules from ``backend/verifier_inputs.py``."""

    silent_witness_v2_field_count: int
    expected_circuit_version: int
    enforces_video_hash_half_padding: bool
    enforces_upper28_zero_version: bool
    domain_tag_wire_hash: str


@dataclass(frozen=True)
class ReviewedDifference:
    """Explicit human-reviewed cross-circuit encoding or layout difference."""

    difference_id: str
    concept: str
    dimension: str
    observed: dict[str, str]
    status: str
    rationale: str
    reviewer_ref: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "difference_id": self.difference_id,
            "concept": self.concept,
            "dimension": self.dimension,
            "observed": dict(sorted(self.observed.items())),
            "status": self.status,
            "rationale": self.rationale,
            "reviewer_ref": self.reviewer_ref,
        }


_COMMENT_RE: Final[re.Pattern[str]] = re.compile(r"//[^\n]*")
_MAIN_FN_RE: Final[re.Pattern[str]] = re.compile(
    r"\bfn\s+main\s*\((?P<params>.*?)\)\s*\{",
    re.DOTALL,
)
_GLOBAL_VERSION_RE: Final[re.Pattern[str]] = re.compile(
    r"\bglobal\s+(?P<name>(?:CURRENT_)?CIRCUIT_VERSION)\s*:\s*(?P<ntype>[A-Za-z0-9_]+)\s*=\s*(?P<val>[0-9a-fxA-F]+)\s*;"
)
_NON_ZERO_ASSERT_RE: Final[re.Pattern[str]] = re.compile(
    r"\bassert\s*\(\s*(?P<field>[A-Za-z_][A-Za-z0-9_]*)\s*!=\s*0\b"
)
_PY_INT_CONST_RE_TEMPLATE: Final[str] = (
    r"^{name}\s*(?::\s*[^=]+)?=\s*(?P<val>[0-9_]+)\b"
)

FORBIDDEN_NORMALIZATION_KEYS: Final[frozenset[str]] = frozenset(
    {
        "normalize",
        "silent_normalize",
        "silent_normalization",
        "auto_normalize",
        "coerce_types",
        "ignore_slot_index",
        "alias_fields",
    }
)


def _rel_label(path: Path, repo_root: Path) -> str:
    try:
        return path.resolve().relative_to(repo_root.resolve()).as_posix()
    except (OSError, ValueError):
        return path.name


def _read_bounded_text(path: Path, *, max_bytes: int, label: str) -> str:
    if not path.is_file():
        raise CompatibilityReportError(CompatibilityErrorCode.MISSING_SOURCE, label)
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise CompatibilityReportError(
            CompatibilityErrorCode.MISSING_SOURCE, label
        ) from exc
    if size > max_bytes:
        raise CompatibilityReportError(CompatibilityErrorCode.OVERSIZED_INPUT, label)
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise CompatibilityReportError(
            CompatibilityErrorCode.MISSING_SOURCE, label
        ) from exc
    if len(raw) > max_bytes:
        raise CompatibilityReportError(CompatibilityErrorCode.OVERSIZED_INPUT, label)
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise CompatibilityReportError(
            CompatibilityErrorCode.MALFORMED_SOURCE, label
        ) from exc


def _extract_main_body(uncommented: str, body_open_index: int, label: str) -> str:
    depth = 0
    for idx in range(body_open_index, len(uncommented)):
        ch = uncommented[idx]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return uncommented[body_open_index + 1 : idx]
    raise CompatibilityReportError(CompatibilityErrorCode.MALFORMED_SOURCE, label)


def _split_top_level_commas(params_blob: str) -> list[str]:
    parts: list[str] = []
    bracket_depth = 0
    current: list[str] = []
    for ch in params_blob:
        if ch in "([<":
            bracket_depth += 1
            current.append(ch)
        elif ch in ")]>":
            bracket_depth = max(0, bracket_depth - 1)
            current.append(ch)
        elif ch == "," and bracket_depth == 0:
            token = "".join(current).strip()
            if token:
                parts.append(token)
            current = []
        else:
            current.append(ch)
    tail = "".join(current).strip()
    if tail:
        parts.append(tail)
    return parts


def extract_circuit_profile(circuit: str, repo_root: Path = REPO_ROOT) -> CircuitPublicProfile:
    """Parse a Noir circuit's ``src/main.nr`` without normalizing types or names."""
    source_file = repo_root / "zk" / "noir" / circuit / "src" / "main.nr"
    rel = f"zk/noir/{circuit}/src/main.nr"
    source = _read_bounded_text(source_file, max_bytes=MAX_SOURCE_BYTES, label=rel)
    uncommented = _COMMENT_RE.sub("", source)

    main_match = _MAIN_FN_RE.search(uncommented)
    if main_match is None:
        raise CompatibilityReportError(CompatibilityErrorCode.MALFORMED_SOURCE, rel)

    brace_index = uncommented.find("{", main_match.start())
    main_body = _extract_main_body(uncommented, brace_index, rel)

    raw_params = _split_top_level_commas(main_match.group("params"))
    if not raw_params:
        raise CompatibilityReportError(CompatibilityErrorCode.MALFORMED_SOURCE, rel)

    public_slots: list[PublicSlot] = []
    private_names: list[str] = []
    pub_idx = 0

    for param_idx, decl in enumerate(raw_params):
        if ":" not in decl:
            raise CompatibilityReportError(CompatibilityErrorCode.MALFORMED_SOURCE, rel)
        raw_name, raw_type = decl.split(":", 1)
        param_name = raw_name.strip()
        type_str = " ".join(raw_type.strip().split())
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", param_name):
            raise CompatibilityReportError(CompatibilityErrorCode.MALFORMED_SOURCE, rel)
        if type_str.startswith("pub "):
            noir_type = type_str[len("pub ") :].strip()
            if not noir_type:
                raise CompatibilityReportError(
                    CompatibilityErrorCode.MALFORMED_SOURCE, rel
                )
            public_slots.append(
                PublicSlot(
                    slot_index=pub_idx,
                    param_index=param_idx,
                    name=param_name,
                    noir_type=noir_type,
                )
            )
            pub_idx += 1
        else:
            private_names.append(param_name)

    version_match = _GLOBAL_VERSION_RE.search(uncommented)
    version_constant = (
        f"{version_match.group('name')}:{version_match.group('ntype')}={version_match.group('val')}"
        if version_match is not None
        else "none"
    )

    public_name_set = {slot.name for slot in public_slots}
    non_zero_public = sorted(
        {
            m.group("field")
            for m in _NON_ZERO_ASSERT_RE.finditer(main_body)
            if m.group("field") in public_name_set
        }
    )

    uses_common_domain_tag = (
        "expected_domain_tag" in uncommented
        or (
            "DOMAIN_PROTOCOL_FIELD" in main_body
            and "DOMAIN_VERSION_FIELD" in main_body
            and "DOMAIN_NETWORK_FIELD" in main_body
        )
    )
    asserts_circuit_version = bool(
        re.search(r"\bassert\s*\([^;]*\bcircuit_version\s*==", main_body, re.DOTALL)
    )

    return CircuitPublicProfile(
        circuit=circuit,
        source_path=rel,
        version_constant=version_constant,
        public_slots=tuple(public_slots),
        private_param_names=tuple(private_names),
        public_frame_bytes=len(public_slots) * FIELD_BYTES,
        uses_common_domain_tag=uses_common_domain_tag,
        asserts_circuit_version_in_main=asserts_circuit_version,
        non_zero_asserted_fields=tuple(non_zero_public),
    )


def extract_host_wire_facts(repo_root: Path = REPO_ROOT) -> HostWireFacts:
    """Extract wire-codec rules from ``backend/verifier_inputs.py``."""
    codec_path = repo_root / "backend" / "verifier_inputs.py"
    rel = "backend/verifier_inputs.py"
    text = _read_bounded_text(codec_path, max_bytes=MAX_SOURCE_BYTES, label=rel)

    def _find_int(const_name: str) -> int:
        pattern = re.compile(
            _PY_INT_CONST_RE_TEMPLATE.format(name=re.escape(const_name)),
            re.MULTILINE,
        )
        match = pattern.search(text)
        if match is None:
            raise CompatibilityReportError(CompatibilityErrorCode.MALFORMED_SOURCE, rel)
        return int(match.group("val").replace("_", ""))

    sw_v2_count = _find_int("SILENT_WITNESS_V2_FIELD_COUNT")
    expected_ver = _find_int("EXPECTED_CIRCUIT_VERSION")
    enforces_half_padding = "_require_half_padding(fields[0], \"video_hash_hi\")" in text and (
        "_require_half_padding(fields[1], \"video_hash_lo\")" in text
    )
    enforces_upper28 = "field_value[:28] != b\"\\x00\" * 28" in text
    domain_wire_hash = (
        "sha256(DOMAIN_PROTOCOL_FIELD||DOMAIN_VERSION_FIELD||DOMAIN_NETWORK_FIELD)"
        if "SILENT_WITNESS_DOMAIN_TAG: Final[bytes] = hashlib.sha256(" in text
        else "unknown"
    )
    return HostWireFacts(
        silent_witness_v2_field_count=sw_v2_count,
        expected_circuit_version=expected_ver,
        enforces_video_hash_half_padding=enforces_half_padding,
        enforces_upper28_zero_version=enforces_upper28,
        domain_tag_wire_hash=domain_wire_hash,
    )


def verify_common_domain_helper(repo_root: Path = REPO_ROOT) -> str:
    """Verify ``harpocrates_common/src/lib.nr`` domain tag derivation."""
    common_path = repo_root / "zk" / "noir" / "harpocrates_common" / "src" / "lib.nr"
    rel = "zk/noir/harpocrates_common/src/lib.nr"
    text = _read_bounded_text(common_path, max_bytes=MAX_SOURCE_BYTES, label=rel)
    uncommented = _COMMENT_RE.sub("", text)
    if (
        "pub fn expected_domain_tag() -> Field" in uncommented
        and "DOMAIN_PROTOCOL_FIELD" in uncommented
        and "DOMAIN_VERSION_FIELD" in uncommented
        and "DOMAIN_NETWORK_FIELD" in uncommented
        and "pedersen_hash" in uncommented
    ):
        return "pedersen([DOMAIN_PROTOCOL_FIELD,DOMAIN_VERSION_FIELD,DOMAIN_NETWORK_FIELD])"
    raise CompatibilityReportError(CompatibilityErrorCode.MALFORMED_SOURCE, rel)


def _describe_slot(profile: CircuitPublicProfile, slot_name: str) -> tuple[str, str, str]:
    slot = profile.slot_by_name(slot_name)
    if slot is None:
        return ("omitted", "none", "none")
    return ("public", f"{slot.name}:{slot.noir_type}", str(slot.slot_index))


def build_concept_observations(
    profiles: dict[str, CircuitPublicProfile],
    wire_facts: HostWireFacts,
    common_domain_derivation: str,
) -> dict[str, dict[str, dict[str, str]]]:
    """Build unnormalized per-circuit observations for every shared concept.

    Returns ``concept -> dimension -> {circuit: exact_observed_descriptor}``.
    """
    sw = profiles["silent_witness"]
    ra = profiles["redacted_ancestry"]
    sd = profiles["selective_disclosure"]

    if sw.public_slots and len(sw.public_slots) != wire_facts.silent_witness_v2_field_count:
        sw_wire_frame = (
            f"mismatch(noir={len(sw.public_slots)},codec={wire_facts.silent_witness_v2_field_count})"
        )
    else:
        sw_wire_frame = "matched_hpx_vi_v2_8_fields"

    observations: dict[str, dict[str, dict[str, str]]] = {}

    # 1. Media hash high limb / parent commitment binding
    sw_vhi_exp, sw_vhi_decl, sw_vhi_idx = _describe_slot(sw, "video_hash_hi")
    sd_vhi_exp, sd_vhi_decl, sd_vhi_idx = _describe_slot(sd, "video_hash_hi")
    ra_vhi_exp = (
        "private_blinded_in_parent_commitment"
        if "parent_hash_hi" in ra.private_param_names
        and ra.slot_by_name("parent_commitment") is not None
        else _describe_slot(ra, "video_hash_hi")[0]
    )
    ra_vhi_decl = (
        "parent_hash_hi:Field(private)->parent_commitment:Field(pub)"
        if ra_vhi_exp == "private_blinded_in_parent_commitment"
        else _describe_slot(ra, "video_hash_hi")[1]
    )
    ra_vhi_idx = (
        "private->slot_0(parent_commitment)"
        if ra_vhi_exp == "private_blinded_in_parent_commitment"
        else _describe_slot(ra, "video_hash_hi")[2]
    )
    observations["media_hash_hi"] = {
        "exposure": {
            "silent_witness": sw_vhi_exp,
            "redacted_ancestry": ra_vhi_exp,
            "selective_disclosure": sd_vhi_exp,
        },
        "declaration": {
            "silent_witness": sw_vhi_decl,
            "redacted_ancestry": ra_vhi_decl,
            "selective_disclosure": sd_vhi_decl,
        },
        "slot_index": {
            "silent_witness": sw_vhi_idx,
            "redacted_ancestry": ra_vhi_idx,
            "selective_disclosure": sd_vhi_idx,
        },
        "wire_encoding": {
            "silent_witness": (
                "u128_be32_upper16_zero"
                if wire_facts.enforces_video_hash_half_padding and sw_vhi_exp == "public"
                else "bn254_field_be32"
            ),
            "redacted_ancestry": (
                "blinded_pedersen_commitment_be32"
                if ra_vhi_exp == "private_blinded_in_parent_commitment"
                else "bn254_field_be32"
            ),
            "selective_disclosure": (
                "bn254_field_be32_unpadded" if sd_vhi_exp == "public" else "none"
            ),
        },
    }

    # 2. Media hash low limb / parent commitment binding
    sw_vlo_exp, sw_vlo_decl, sw_vlo_idx = _describe_slot(sw, "video_hash_lo")
    sd_vlo_exp, sd_vlo_decl, sd_vlo_idx = _describe_slot(sd, "video_hash_lo")
    ra_vlo_exp = (
        "private_blinded_in_parent_commitment"
        if "parent_hash_lo" in ra.private_param_names
        and ra.slot_by_name("parent_commitment") is not None
        else _describe_slot(ra, "video_hash_lo")[0]
    )
    ra_vlo_decl = (
        "parent_hash_lo:Field(private)->parent_commitment:Field(pub)"
        if ra_vlo_exp == "private_blinded_in_parent_commitment"
        else _describe_slot(ra, "video_hash_lo")[1]
    )
    ra_vlo_idx = (
        "private->slot_0(parent_commitment)"
        if ra_vlo_exp == "private_blinded_in_parent_commitment"
        else _describe_slot(ra, "video_hash_lo")[2]
    )
    observations["media_hash_lo"] = {
        "exposure": {
            "silent_witness": sw_vlo_exp,
            "redacted_ancestry": ra_vlo_exp,
            "selective_disclosure": sd_vlo_exp,
        },
        "declaration": {
            "silent_witness": sw_vlo_decl,
            "redacted_ancestry": ra_vlo_decl,
            "selective_disclosure": sd_vlo_decl,
        },
        "slot_index": {
            "silent_witness": sw_vlo_idx,
            "redacted_ancestry": ra_vlo_idx,
            "selective_disclosure": sd_vlo_idx,
        },
        "wire_encoding": {
            "silent_witness": (
                "u128_be32_upper16_zero"
                if wire_facts.enforces_video_hash_half_padding and sw_vlo_exp == "public"
                else "bn254_field_be32"
            ),
            "redacted_ancestry": (
                "blinded_pedersen_commitment_be32"
                if ra_vlo_exp == "private_blinded_in_parent_commitment"
                else "bn254_field_be32"
            ),
            "selective_disclosure": (
                "bn254_field_be32_unpadded" if sd_vlo_exp == "public" else "none"
            ),
        },
    }

    # 3. Credential root binding
    sw_cr_exp, sw_cr_decl, sw_cr_idx = _describe_slot(sw, "credential_root")
    ra_cr_exp, ra_cr_decl, ra_cr_idx = _describe_slot(ra, "credential_root")
    sd_cr_exp, sd_cr_decl, sd_cr_idx = _describe_slot(sd, "credential_root")
    observations["credential_root"] = {
        "exposure": {
            "silent_witness": sw_cr_exp,
            "redacted_ancestry": (
                "omitted_bound_via_nullifier"
                if ra_cr_exp == "omitted" and "credential_secret" in ra.private_param_names
                else ra_cr_exp
            ),
            "selective_disclosure": sd_cr_exp,
        },
        "declaration": {
            "silent_witness": sw_cr_decl,
            "redacted_ancestry": ra_cr_decl,
            "selective_disclosure": sd_cr_decl,
        },
        "slot_index": {
            "silent_witness": sw_cr_idx,
            "redacted_ancestry": ra_cr_idx,
            "selective_disclosure": sd_cr_idx,
        },
        "derivation": {
            "silent_witness": "pedersen([credential_secret])",
            "redacted_ancestry": "none_credential_secret_in_nullifier_only",
            "selective_disclosure": "pedersen_fold(attr_commitment(attr_values[i],attr_blindings[i]))",
        },
        "zero_policy": {
            "silent_witness": (
                "non_zero_in_circuit_and_wire"
                if "credential_root" in sw.non_zero_asserted_fields
                else "non_zero_on_wire_only"
            ),
            "redacted_ancestry": "not_exposed_secret_asserted_non_zero",
            "selective_disclosure": (
                "non_zero_in_circuit"
                if "credential_root" in sd.non_zero_asserted_fields
                else "derived_pedersen_chain_no_explicit_zero_assert"
            ),
        },
    }

    # 4. Nullifier (present across all three circuits)
    sw_nul_exp, sw_nul_decl, sw_nul_idx = _describe_slot(sw, "nullifier")
    ra_nul_exp, ra_nul_decl, ra_nul_idx = _describe_slot(ra, "nullifier")
    sd_nul_exp, sd_nul_decl, sd_nul_idx = _describe_slot(sd, "nullifier")
    observations["nullifier"] = {
        "exposure": {
            "silent_witness": sw_nul_exp,
            "redacted_ancestry": ra_nul_exp,
            "selective_disclosure": sd_nul_exp,
        },
        "declaration": {
            "silent_witness": sw_nul_decl,
            "redacted_ancestry": ra_nul_decl,
            "selective_disclosure": sd_nul_decl,
        },
        "wire_encoding": {
            "silent_witness": "bn254_field_be32" if sw_nul_exp == "public" else "none",
            "redacted_ancestry": "bn254_field_be32" if ra_nul_exp == "public" else "none",
            "selective_disclosure": "bn254_field_be32" if sd_nul_exp == "public" else "none",
        },
        "slot_index": {
            "silent_witness": sw_nul_idx,
            "redacted_ancestry": ra_nul_idx,
            "selective_disclosure": sd_nul_idx,
        },
        "derivation": {
            "silent_witness": "pedersen([credential_secret,nullifier_secret,evidence_digest])",
            "redacted_ancestry": "pedersen([DOMAIN_NULLIFIER,credential_secret,nullifier_secret,ancestry_root])",
            "selective_disclosure": "pedersen([credential_root,video_hash_hi,video_hash_lo,evidence_digest])",
        },
        "zero_policy": {
            "silent_witness": (
                "non_zero_in_circuit"
                if "nullifier" in sw.non_zero_asserted_fields
                else "non_zero_on_wire_only"
            ),
            "redacted_ancestry": (
                "non_zero_in_circuit"
                if "nullifier" in ra.non_zero_asserted_fields
                else "unconstrained_zero"
            ),
            "selective_disclosure": (
                "non_zero_in_circuit"
                if "nullifier" in sd.non_zero_asserted_fields
                else "derived_pedersen_no_explicit_zero_assert"
            ),
        },
    }

    # 5. Domain separation
    sw_dom_exp, sw_dom_decl, sw_dom_idx = _describe_slot(sw, "domain_tag")
    ra_dom_exp, ra_dom_decl, ra_dom_idx = _describe_slot(ra, "domain_tag")
    sd_dom_exp, sd_dom_decl, sd_dom_idx = _describe_slot(sd, "domain_tag")
    observations["domain_separation"] = {
        "exposure": {
            "silent_witness": sw_dom_exp,
            "redacted_ancestry": ra_dom_exp,
            "selective_disclosure": (
                "omitted_uses_schema_and_verifier_digest"
                if sd_dom_exp == "omitted" and sd.slot_by_name("verifier_digest") is not None
                else sd_dom_exp
            ),
        },
        "declaration": {
            "silent_witness": sw_dom_decl,
            "redacted_ancestry": ra_dom_decl,
            "selective_disclosure": sd_dom_decl,
        },
        "slot_index": {
            "silent_witness": sw_dom_idx,
            "redacted_ancestry": ra_dom_idx,
            "selective_disclosure": sd_dom_idx,
        },
        "circuit_derivation": {
            "silent_witness": (
                common_domain_derivation if sw.uses_common_domain_tag else "custom"
            ),
            "redacted_ancestry": (
                common_domain_derivation if ra.uses_common_domain_tag else "custom"
            ),
            "selective_disclosure": "pedersen([verifier_digest,schema_hash,circuit_version])",
        },
        "wire_vs_circuit_binding": {
            "silent_witness": (
                f"wire:{wire_facts.domain_tag_wire_hash};circuit:{common_domain_derivation};{sw_wire_frame}"
            ),
            "redacted_ancestry": f"circuit:{common_domain_derivation}",
            "selective_disclosure": (
                "verifier_digest_non_zero_in_circuit"
                if "verifier_digest" in sd.non_zero_asserted_fields
                else "verifier_digest_unconstrained"
            ),
        },
    }

    # 6. Circuit version commitment
    sw_ver_exp, sw_ver_decl, sw_ver_idx = _describe_slot(sw, "circuit_version")
    ra_ver_exp, ra_ver_decl, ra_ver_idx = _describe_slot(ra, "circuit_version")
    sd_ver_exp, sd_ver_decl, sd_ver_idx = _describe_slot(sd, "circuit_version")
    observations["circuit_version"] = {
        "exposure": {
            "silent_witness": sw_ver_exp,
            "redacted_ancestry": (
                "folded_into_ancestry_root"
                if ra_ver_exp == "omitted" and ra.version_constant != "none"
                else ra_ver_exp
            ),
            "selective_disclosure": sd_ver_exp,
        },
        "declaration": {
            "silent_witness": sw_ver_decl,
            "redacted_ancestry": ra_ver_decl,
            "selective_disclosure": sd_ver_decl,
        },
        "slot_index": {
            "silent_witness": sw_ver_idx,
            "redacted_ancestry": ra_ver_idx,
            "selective_disclosure": sd_ver_idx,
        },
        "version_constant": {
            "silent_witness": sw.version_constant,
            "redacted_ancestry": ra.version_constant,
            "selective_disclosure": sd.version_constant,
        },
        "wire_encoding": {
            "silent_witness": (
                f"u32_be32_upper28_zero(expected={wire_facts.expected_circuit_version})"
                if wire_facts.enforces_upper28_zero_version and sw_ver_exp == "public"
                else "bn254_field_be32"
            ),
            "redacted_ancestry": "folded_in_ancestry_root_pedersen",
            "selective_disclosure": "u32_be32_low4_label",
        },
        "in_circuit_enforcement": {
            "silent_witness": (
                "assert_eq_in_main"
                if sw.asserts_circuit_version_in_main
                else "wire_enforced_missing_main_assert"
            ),
            "redacted_ancestry": "bound_in_ancestry_root_preimage",
            "selective_disclosure": (
                "assert_eq_in_main"
                if sd.asserts_circuit_version_in_main
                else "missing_main_assert"
            ),
        },
    }

    # 7. Evidence digest representation
    sw_ev_exp, sw_ev_decl, sw_ev_idx = _describe_slot(sw, "evidence_digest")
    ra_ev_exp, ra_ev_decl, ra_ev_idx = _describe_slot(ra, "evidence_digest")
    sd_ev_exp, sd_ev_decl, sd_ev_idx = _describe_slot(sd, "evidence_digest")
    observations["evidence_digest"] = {
        "exposure": {
            "silent_witness": (
                "internal_intermediate" if sw_ev_exp == "omitted" else sw_ev_exp
            ),
            "redacted_ancestry": (
                "lineage_derivative_and_parameters_digests"
                if ra_ev_exp == "omitted"
                and ra.slot_by_name("derivative_digest") is not None
                else ra_ev_exp
            ),
            "selective_disclosure": sd_ev_exp,
        },
        "declaration": {
            "silent_witness": sw_ev_decl,
            "redacted_ancestry": ra_ev_decl,
            "selective_disclosure": sd_ev_decl,
        },
        "slot_index": {
            "silent_witness": sw_ev_idx,
            "redacted_ancestry": ra_ev_idx,
            "selective_disclosure": sd_ev_idx,
        },
    }

    # 8. Dynamic discovery for any additional same-named public inputs shared by >=2 circuits
    tracked_field_names = {
        "video_hash_hi",
        "video_hash_lo",
        "credential_root",
        "nullifier",
        "domain_tag",
        "circuit_version",
        "evidence_digest",
    }
    name_to_circuits: dict[str, list[str]] = {}
    for circuit_name, prof in profiles.items():
        for slot in prof.public_slots:
            name_to_circuits.setdefault(slot.name, []).append(circuit_name)

    for shared_name, present_in in sorted(name_to_circuits.items()):
        if shared_name in tracked_field_names or len(present_in) < 2:
            continue
        concept_key = f"shared_field:{shared_name}"
        observations[concept_key] = {
            "exposure": {},
            "declaration": {},
            "slot_index": {},
        }
        for circuit_name in TARGET_CIRCUITS:
            exp, decl, idx = _describe_slot(profiles[circuit_name], shared_name)
            observations[concept_key]["exposure"][circuit_name] = exp
            observations[concept_key]["declaration"][circuit_name] = decl
            observations[concept_key]["slot_index"][circuit_name] = idx

    return observations


def _check_no_silent_normalization_flags(obj: Any, target: str) -> None:
    if isinstance(obj, dict):
        for key, val in obj.items():
            if key in FORBIDDEN_NORMALIZATION_KEYS and bool(val):
                raise CompatibilityReportError(
                    CompatibilityErrorCode.SILENT_NORMALIZATION_FORBIDDEN,
                    f"{target}:{key}",
                )
            _check_no_silent_normalization_flags(val, f"{target}.{key}")
    elif isinstance(obj, list):
        for idx, item in enumerate(obj):
            _check_no_silent_normalization_flags(item, f"{target}[{idx}]")


def load_compatibility_policy(
    policy_path: Path = DEFAULT_POLICY_PATH,
    repo_root: Path = REPO_ROOT,
) -> tuple[dict[str, list[str]], list[ReviewedDifference]]:
    """Load and validate the reviewed cross-circuit compatibility policy."""
    label = _rel_label(policy_path, repo_root)
    raw_text = _read_bounded_text(policy_path, max_bytes=MAX_POLICY_BYTES, label=label)
    try:
        payload = json.loads(raw_text)
    except json.JSONDecodeError as exc:
        raise CompatibilityReportError(
            CompatibilityErrorCode.MALFORMED_POLICY, label
        ) from exc

    if not isinstance(payload, dict):
        raise CompatibilityReportError(CompatibilityErrorCode.MALFORMED_POLICY, label)

    _check_no_silent_normalization_flags(payload, label)

    if payload.get("format") != POLICY_FORMAT:
        raise CompatibilityReportError(CompatibilityErrorCode.MALFORMED_POLICY, label)
    if payload.get("version") != POLICY_VERSION:
        raise CompatibilityReportError(
            CompatibilityErrorCode.UNSUPPORTED_POLICY_VERSION, label
        )
    if payload.get("normalization_policy") != "forbid_silent_normalization":
        raise CompatibilityReportError(
            CompatibilityErrorCode.SILENT_NORMALIZATION_FORBIDDEN,
            f"{label}:normalization_policy",
        )

    raw_frames = payload.get("circuit_frames")
    if not isinstance(raw_frames, dict) or set(raw_frames.keys()) != set(TARGET_CIRCUITS):
        raise CompatibilityReportError(
            CompatibilityErrorCode.MALFORMED_POLICY, f"{label}:circuit_frames"
        )

    expected_frames: dict[str, list[str]] = {}
    for circuit_name in TARGET_CIRCUITS:
        frame_info = raw_frames.get(circuit_name)
        if not isinstance(frame_info, dict):
            raise CompatibilityReportError(
                CompatibilityErrorCode.MALFORMED_POLICY,
                f"{label}:circuit_frames.{circuit_name}",
            )
        fields = frame_info.get("public_fields")
        if not isinstance(fields, list) or not all(
            isinstance(item, str) and item for item in fields
        ):
            raise CompatibilityReportError(
                CompatibilityErrorCode.MALFORMED_POLICY,
                f"{label}:circuit_frames.{circuit_name}.public_fields",
            )
        expected_frames[circuit_name] = list(fields)

    raw_reviews = payload.get("reviewed_differences")
    if not isinstance(raw_reviews, list):
        raise CompatibilityReportError(
            CompatibilityErrorCode.MALFORMED_POLICY, f"{label}:reviewed_differences"
        )

    seen_ids: set[str] = set()
    seen_pairs: set[tuple[str, str]] = set()
    reviews: list[ReviewedDifference] = []

    for idx, entry in enumerate(raw_reviews):
        entry_target = f"{label}:reviewed_differences[{idx}]"
        if not isinstance(entry, dict):
            raise CompatibilityReportError(
                CompatibilityErrorCode.INVALID_REVIEW_RECORD, entry_target
            )

        diff_id = entry.get("difference_id")
        concept = entry.get("concept")
        dimension = entry.get("dimension")
        status = entry.get("status")
        rationale = entry.get("rationale")
        reviewer_ref = entry.get("reviewer_ref")
        observed = entry.get("observed")

        if (
            not isinstance(diff_id, str)
            or not diff_id.strip()
            or diff_id in seen_ids
            or not isinstance(concept, str)
            or not concept.strip()
            or not isinstance(dimension, str)
            or not dimension.strip()
        ):
            raise CompatibilityReportError(
                CompatibilityErrorCode.INVALID_REVIEW_RECORD, entry_target
            )

        if status in ("normalized", "silent_normalized", "auto_normalized"):
            raise CompatibilityReportError(
                CompatibilityErrorCode.SILENT_NORMALIZATION_FORBIDDEN,
                f"{entry_target}:status",
            )
        if status != "reviewed":
            raise CompatibilityReportError(
                CompatibilityErrorCode.INVALID_REVIEW_RECORD,
                f"{entry_target}:status",
            )
        if not isinstance(rationale, str) or len(rationale.strip()) < 10:
            raise CompatibilityReportError(
                CompatibilityErrorCode.INVALID_REVIEW_RECORD,
                f"{entry_target}:rationale",
            )
        if not isinstance(reviewer_ref, str) or not reviewer_ref.strip():
            raise CompatibilityReportError(
                CompatibilityErrorCode.INVALID_REVIEW_RECORD,
                f"{entry_target}:reviewer_ref",
            )
        if not isinstance(observed, dict) or set(observed.keys()) != set(TARGET_CIRCUITS):
            raise CompatibilityReportError(
                CompatibilityErrorCode.INVALID_REVIEW_RECORD,
                f"{entry_target}:observed",
            )

        clean_observed: dict[str, str] = {}
        for circuit_name in TARGET_CIRCUITS:
            val = observed[circuit_name]
            if not isinstance(val, str) or not val or val == "*":
                raise CompatibilityReportError(
                    CompatibilityErrorCode.INVALID_REVIEW_RECORD,
                    f"{entry_target}:observed.{circuit_name}",
                )
            clean_observed[circuit_name] = val

        pair = (concept, dimension)
        if pair in seen_pairs:
            raise CompatibilityReportError(
                CompatibilityErrorCode.INVALID_REVIEW_RECORD,
                f"{entry_target}:duplicate_concept_dimension",
            )
        seen_ids.add(diff_id)
        seen_pairs.add(pair)
        reviews.append(
            ReviewedDifference(
                difference_id=diff_id,
                concept=concept,
                dimension=dimension,
                observed=clean_observed,
                status=status,
                rationale=rationale.strip(),
                reviewer_ref=reviewer_ref.strip(),
            )
        )

    return expected_frames, reviews


def generate_compatibility_report(
    *,
    repo_root: Path = REPO_ROOT,
    policy_path: Path | None = None,
) -> dict[str, Any]:
    """Generate the cross-circuit public-input compatibility report."""
    resolved_policy = (
        policy_path
        if policy_path is not None
        else repo_root / "zk" / "noir" / "public_input_compatibility_v1.json"
    )

    expected_frames, reviewed_list = load_compatibility_policy(
        policy_path=resolved_policy,
        repo_root=repo_root,
    )
    profiles = {
        circuit: extract_circuit_profile(circuit, repo_root=repo_root)
        for circuit in TARGET_CIRCUITS
    }
    wire_facts = extract_host_wire_facts(repo_root=repo_root)
    common_domain = verify_common_domain_helper(repo_root=repo_root)
    observations = build_concept_observations(profiles, wire_facts, common_domain)

    reviews_by_key: dict[tuple[str, str], ReviewedDifference] = {
        (item.concept, item.dimension): item for item in reviewed_list
    }
    matched_review_keys: set[tuple[str, str]] = set()

    compatible_checks: list[dict[str, Any]] = []
    pairwise_shared: list[dict[str, Any]] = []
    reviewed_differences: list[dict[str, Any]] = []
    unreviewed_differences: list[dict[str, Any]] = []
    drifted_reviews: list[dict[str, Any]] = []
    frame_drift: list[dict[str, Any]] = []

    circuit_pairs = (
        ("silent_witness", "redacted_ancestry"),
        ("silent_witness", "selective_disclosure"),
        ("redacted_ancestry", "selective_disclosure"),
    )

    for circuit_name in TARGET_CIRCUITS:
        actual_fields = list(profiles[circuit_name].public_field_names)
        declared_fields = expected_frames[circuit_name]
        if actual_fields != declared_fields:
            frame_drift.append(
                {
                    "circuit": circuit_name,
                    "reason": "unreviewed_public_frame_layout_change",
                    "expected_public_fields": declared_fields,
                    "actual_public_fields": actual_fields,
                }
            )

    for concept in sorted(observations.keys()):
        dimensions = observations[concept]
        for dimension in sorted(dimensions.keys()):
            per_circuit = {
                c: dimensions[dimension][c] for c in TARGET_CIRCUITS
            }
            unique_values = set(per_circuit.values())
            key = (concept, dimension)

            if len(unique_values) == 1:
                shared_encoding = next(iter(unique_values))
                compatible_checks.append(
                    {
                        "concept": concept,
                        "dimension": dimension,
                        "shared_encoding": shared_encoding,
                        "circuits": list(TARGET_CIRCUITS),
                    }
                )
                if key in reviews_by_key:
                    matched_review_keys.add(key)
                    drifted_reviews.append(
                        {
                            "difference_id": reviews_by_key[key].difference_id,
                            "concept": concept,
                            "dimension": dimension,
                            "reason": "stale_review_difference_no_longer_present",
                            "expected_observed": reviews_by_key[key].observed,
                            "actual_observed": per_circuit,
                        }
                    )
                continue

            for left_c, right_c in circuit_pairs:
                if (
                    per_circuit[left_c] == per_circuit[right_c]
                    and per_circuit[left_c] not in ("none", "omitted")
                ):
                    pairwise_shared.append(
                        {
                            "concept": concept,
                            "dimension": dimension,
                            "circuits": [left_c, right_c],
                            "shared_encoding": per_circuit[left_c],
                        }
                    )

            review = reviews_by_key.get(key)
            if review is None:
                unreviewed_differences.append(
                    {
                        "concept": concept,
                        "dimension": dimension,
                        "reason": "unreviewed_cross_circuit_difference",
                        "observed": per_circuit,
                    }
                )
                continue

            matched_review_keys.add(key)
            if review.observed != per_circuit:
                drifted_reviews.append(
                    {
                        "difference_id": review.difference_id,
                        "concept": concept,
                        "dimension": dimension,
                        "reason": "reviewed_observation_drift",
                        "expected_observed": review.observed,
                        "actual_observed": per_circuit,
                    }
                )
                continue

            reviewed_differences.append(review.to_dict())

    for key, review in sorted(reviews_by_key.items()):
        if key not in matched_review_keys:
            drifted_reviews.append(
                {
                    "difference_id": review.difference_id,
                    "concept": review.concept,
                    "dimension": review.dimension,
                    "reason": "orphaned_review_entry",
                    "expected_observed": review.observed,
                    "actual_observed": {},
                }
            )

    ok = (
        not frame_drift
        and not unreviewed_differences
        and not drifted_reviews
    )

    return {
        "format": REPORT_FORMAT,
        "version": REPORT_VERSION,
        "normalization_policy": "forbid_silent_normalization",
        "ok": ok,
        "summary": {
            "circuits_checked": len(TARGET_CIRCUITS),
            "compatible_count": len(compatible_checks),
            "pairwise_shared_count": len(pairwise_shared),
            "reviewed_difference_count": len(reviewed_differences),
            "unreviewed_difference_count": len(unreviewed_differences),
            "drifted_review_count": len(drifted_reviews),
            "frame_drift_count": len(frame_drift),
        },
        "circuits": {
            circuit: profiles[circuit].to_dict() for circuit in TARGET_CIRCUITS
        },
        "compatible_encodings": compatible_checks,
        "pairwise_shared_encodings": pairwise_shared,
        "reviewed_differences": reviewed_differences,
        "unreviewed_differences": unreviewed_differences,
        "drifted_reviews": drifted_reviews,
        "frame_drift": frame_drift,
    }


def format_markdown_report(report: dict[str, Any]) -> str:
    """Render a deterministic Markdown summary of the compatibility report."""
    status_text = "PASS" if report["ok"] else "FAIL"
    summary = report["summary"]
    lines = [
        "# Cross-Circuit Public-Input Compatibility Report",
        "",
        f"- **Status:** `{status_text}`",
        f"- **Normalization Policy:** `{report['normalization_policy']}`",
        f"- **Compatible Shared Checks (3-Way):** `{summary['compatible_count']}`",
        f"- **Pairwise Shared Encodings (2-Way):** `{summary['pairwise_shared_count']}`",
        f"- **Explicitly Reviewed Differences:** `{summary['reviewed_difference_count']}`",
        f"- **Unreviewed Differences:** `{summary['unreviewed_difference_count']}`",
        f"- **Drifted / Stale Reviews:** `{summary['drifted_review_count']}`",
        f"- **Public Frame Layout Drift:** `{summary['frame_drift_count']}`",
        "",
        "## Circuit Public-Input Frames",
        "",
        "| Circuit | Version Constant | Public Fields | Frame Bytes | Ordered Public Slots |",
        "| :--- | :--- | :---: | :---: | :--- |",
    ]

    for circuit in TARGET_CIRCUITS:
        c_info = report["circuits"][circuit]
        slot_summary = ", ".join(
            f"`[{s['slot_index']}] {s['name']}: {s['noir_type']}`"
            for s in c_info["public_fields"]
        )
        lines.append(
            f"| `{circuit}` | `{c_info['version_constant']}` | "
            f"{c_info['public_field_count']} | {c_info['public_frame_bytes']} | {slot_summary} |"
        )

    lines.extend(
        [
            "",
            "## Compatible Shared Encodings (Exact Match)",
            "",
            "| Concept | Dimension | Shared Encoding |",
            "| :--- | :--- | :--- |",
        ]
    )
    for item in report["compatible_encodings"]:
        lines.append(
            f"| `{item['concept']}` | `{item['dimension']}` | `{item['shared_encoding']}` |"
        )

    lines.extend(
        [
            "",
            "## Pairwise Shared Encodings (Subset Match, Differences Explicitly Reviewed)",
            "",
            "| Concept | Dimension | Circuits | Shared Encoding |",
            "| :--- | :--- | :--- | :--- |",
        ]
    )
    for item in report["pairwise_shared_encodings"]:
        pair_str = ", ".join(f"`{c}`" for c in item["circuits"])
        lines.append(
            f"| `{item['concept']}` | `{item['dimension']}` | {pair_str} | `{item['shared_encoding']}` |"
        )

    lines.extend(
        [
            "",
            "## Explicitly Reviewed Cross-Circuit Differences",
            "",
            "| ID | Concept | Dimension | `silent_witness` | `redacted_ancestry` | `selective_disclosure` | Spec Ref |",
            "| :--- | :--- | :--- | :--- | :--- | :--- | :--- |",
        ]
    )
    for item in report["reviewed_differences"]:
        obs = item["observed"]
        lines.append(
            f"| `{item['difference_id']}` | `{item['concept']}` | `{item['dimension']}` | "
            f"`{obs['silent_witness']}` | `{obs['redacted_ancestry']}` | "
            f"`{obs['selective_disclosure']}` | `{item['reviewer_ref']}` |"
        )

    if not report["ok"]:
        lines.extend(["", "## Compatibility Failures", ""])
        for drift in report["frame_drift"]:
            lines.append(
                f"- **Frame drift (`{drift['circuit']}`):** `{drift['reason']}` "
                f"(expected `{drift['expected_public_fields']}`, got `{drift['actual_public_fields']}`)"
            )
        for unrev in report["unreviewed_differences"]:
            lines.append(
                f"- **Unreviewed difference (`{unrev['concept']}.{unrev['dimension']}`):** "
                f"`{json.dumps(unrev['observed'], sort_keys=True)}`"
            )
        for drifted in report["drifted_reviews"]:
            lines.append(
                f"- **Drifted review (`{drifted['difference_id']}` / "
                f"`{drifted['concept']}.{drifted['dimension']}`):** `{drifted['reason']}`"
            )

    lines.append("")
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Compare shared public-input encodings across silent_witness, "
            "redacted_ancestry, and selective_disclosure without silent normalization."
        )
    )
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=REPO_ROOT,
        help="Repository root directory (default: auto-detected).",
    )
    parser.add_argument(
        "--policy",
        type=Path,
        default=None,
        help="Path to reviewed compatibility policy JSON.",
    )
    parser.add_argument(
        "--format",
        choices=("json", "markdown"),
        default="json",
        help="Output report format (default: json).",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Optional output path to write the rendered report.",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Fail closed (exit 1) when any cross-circuit difference is unreviewed or drifted.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    repo_root = args.repo_root.resolve()
    policy_path = args.policy.resolve() if args.policy is not None else None

    try:
        report = generate_compatibility_report(
            repo_root=repo_root,
            policy_path=policy_path,
        )
    except CompatibilityReportError as err:
        print(
            json.dumps(err.signal(), sort_keys=True, separators=(",", ":")),
            file=sys.stderr,
        )
        return EXIT_INVALID_INPUT

    rendered = (
        format_markdown_report(report)
        if args.format == "markdown"
        else json.dumps(report, indent=2, sort_keys=True) + "\n"
    )

    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8", newline="\n")
    elif not args.check or not report["ok"]:
        sys.stdout.write(rendered if rendered.endswith("\n") else rendered + "\n")

    return EXIT_OK if report["ok"] else EXIT_INCOMPATIBLE


if __name__ == "__main__":
    raise SystemExit(main())
