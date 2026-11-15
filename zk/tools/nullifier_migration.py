#!/usr/bin/env python3
"""Synthetic-only nullifier scope policy migration analyzer for Silent Witness.

Compares an existing (`old`) and candidate (`new`) nullifier scope policy across
a strictly synthetic cohort of identities, evidence digests, verifier scopes,
and epochs to quantify:
  1. Linkability boundaries (cross-scope nullifier collisions, cross-epoch
     nullifier collisions, cross-policy nullifier overlap, and persistent
     `credential_root` correlation).
  2. Replay and transition boundaries (same-context replay blocking, cross-scope
     isolation, epoch rotation freshness, global-scope anchor overlap, and
     dual-registration risk across policy cutovers).

Privacy & security invariant:
  - Never imports, reads, or logs real credential secrets, `Prover.toml` witness
    files, environment secret variables, or Stellar secret seeds.
  - Rejects any caller-supplied configuration or CLI argument that resembles
    secret/witness material without echoing the rejected value.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

BN254_FIELD_MODULUS = (
    21888242871839275222246405745257275088548364400416034343698204186575808495617
)
DIGEST_ALGORITHM_SHA256 = 0
SCOPED_NULLIFIER_V1 = int(
    "00484152504f4352415445535f53434f5045445f4e554c4c49464945525f5631",
    16,
)
SCOPED_NULLIFIER_V2 = int(
    "00484152504f4352415445535f53434f5045445f4e554c4c49464945525f5632",
    16,
)

SYNTHETIC_DOMAIN_PREFIX = "harpocrates:synthetic-migration-v1"
SURROGATE_HASH_DOMAIN = b"harpocrates:pedersen-surrogate:v1"

MAX_SYNTHETIC_IDENTITIES = 64
MAX_SYNTHETIC_VIDEOS = 64
MAX_SYNTHETIC_SCOPES = 32
MAX_SYNTHETIC_EPOCHS = 32
MAX_COHORT_LABEL_LEN = 64

EXIT_OK = 0
EXIT_INVALID_INPUT = 2
EXIT_POLICY_REGRESSION = 3

DEFAULT_SYNTHETIC_SCOPES: tuple[str, ...] = (
    "0",
    "v:verifier-alpha:p:default",
    "v:verifier-alpha:p:audit",
    "v:verifier-beta:p:default",
)
DEFAULT_SYNTHETIC_EPOCHS: tuple[int, ...] = (0, 1)

_CANONICAL_COHORT_LABEL_RE = re.compile(r"^synthetic-[a-z0-9][a-z0-9_-]{0,53}$")
_CANONICAL_SCOPE_CHARS_RE = re.compile(r"^[a-z0-9:_-]+$")
_CANONICAL_VERIFIER_SCOPE_RE = re.compile(
    r"^v:(?P<verifier>[a-z0-9][a-z0-9_-]*):p:(?P<purpose>[a-z0-9][a-z0-9_-]*)$"
)
_STELLAR_SECRET_SEED_RE = re.compile(r"^S[A-Z2-7]{55}$")
_HEX_SECRET_RE = re.compile(r"^(?:0x)?[0-9a-fA-F]{64}$")
_FORBIDDEN_SECRET_KEYS = frozenset(
    {
        "credential_secret",
        "nullifier_secret",
        "credential_seed",
        "nullifier_seed",
        "credentialsecret",
        "nullifiersecret",
        "credentialseed",
        "nullifierseed",
        "private_key",
        "secret",
        "secret_key",
        "seed",
        "mnemonic",
        "witness",
        "prover_toml",
    }
)
_FORBIDDEN_VALUE_MARKERS = (
    "begin private key",
    "begin ec private key",
    "prover.toml",
    ".env",
    "credential_secret",
    "nullifier_secret",
)


class MigrationInputError(ValueError):
    """Privacy-safe error raised on invalid or secret-bearing migration inputs."""

    def __init__(self, code: str, message: str, *, field: str | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.field = field

    def to_dict(self) -> dict[str, str]:
        payload: dict[str, str] = {
            "code": self.code,
            "message": self.message,
        }
        if self.field is not None:
            payload["field"] = self.field
        return payload


@dataclass(frozen=True)
class ScopePolicySpec:
    """Declarative specification for a Silent Witness nullifier scope policy."""

    name: str
    description: str
    domain_separator: int | None
    domain_separator_label: str | None
    bind_verifier_scope: bool
    bind_epoch: bool
    collapse_purpose_to_default: bool = False


@dataclass(frozen=True)
class SyntheticIdentity:
    """Deterministic synthetic prover identity derived from a public index."""

    label: str
    credential_secret: int
    nullifier_secret: int
    credential_root: int


@dataclass(frozen=True)
class SyntheticEvidence:
    """Deterministic synthetic 256-bit evidence hash split into 128-bit limbs."""

    label: str
    video_hash_hi: int
    video_hash_lo: int


BUILTIN_POLICIES: dict[str, ScopePolicySpec] = {
    "legacy_unscoped_v1": ScopePolicySpec(
        name="legacy_unscoped_v1",
        description=(
            "Unscoped evidence digest H([algo, video_hash_hi, video_hash_lo]); "
            "ignores verifier_scope and epoch."
        ),
        domain_separator=None,
        domain_separator_label=None,
        bind_verifier_scope=False,
        bind_epoch=False,
    ),
    "global_scoped_v1": ScopePolicySpec(
        name="global_scoped_v1",
        description=(
            "SCOPED_NULLIFIER_V1 pinned to global context (verifier_scope=0, epoch=0) "
            "for all submissions."
        ),
        domain_separator=SCOPED_NULLIFIER_V1,
        domain_separator_label="HARPOCRATES_SCOPED_NULLIFIER_V1",
        bind_verifier_scope=False,
        bind_epoch=False,
    ),
    "purpose_collapsed_v1": ScopePolicySpec(
        name="purpose_collapsed_v1",
        description=(
            "SCOPED_NULLIFIER_V1 binding verifier identity and epoch while collapsing "
            "all purposes onto ':p:default'."
        ),
        domain_separator=SCOPED_NULLIFIER_V1,
        domain_separator_label="HARPOCRATES_SCOPED_NULLIFIER_V1",
        bind_verifier_scope=True,
        bind_epoch=True,
        collapse_purpose_to_default=True,
    ),
    "scope_only_v1": ScopePolicySpec(
        name="scope_only_v1",
        description=(
            "SCOPED_NULLIFIER_V1 binding canonical verifier_scope (verifier + purpose) "
            "with fixed epoch=0."
        ),
        domain_separator=SCOPED_NULLIFIER_V1,
        domain_separator_label="HARPOCRATES_SCOPED_NULLIFIER_V1",
        bind_verifier_scope=True,
        bind_epoch=False,
    ),
    "verifier_scoped_v1": ScopePolicySpec(
        name="verifier_scoped_v1",
        description=(
            "Active Silent Witness circuit policy: SCOPED_NULLIFIER_V1 binding "
            "canonical verifier_scope and epoch."
        ),
        domain_separator=SCOPED_NULLIFIER_V1,
        domain_separator_label="HARPOCRATES_SCOPED_NULLIFIER_V1",
        bind_verifier_scope=True,
        bind_epoch=True,
    ),
    "verifier_scoped_v2": ScopePolicySpec(
        name="verifier_scoped_v2",
        description=(
            "Domain-separated upgrade policy: SCOPED_NULLIFIER_V2 binding canonical "
            "verifier_scope and epoch with zero v1 nullifier overlap."
        ),
        domain_separator=SCOPED_NULLIFIER_V2,
        domain_separator_label="HARPOCRATES_SCOPED_NULLIFIER_V2",
        bind_verifier_scope=True,
        bind_epoch=True,
    ),
}


def _field_from_domain_bytes(*parts: bytes) -> int:
    hasher = hashlib.sha256()
    for part in parts:
        hasher.update(len(part).to_bytes(4, "big"))
        hasher.update(part)
    reduced = int.from_bytes(hasher.digest(), "big") % BN254_FIELD_MODULUS
    return 1 if reduced == 0 else reduced


def pedersen_surrogate_hash(fields: Sequence[int]) -> int:
    """Collision-resistant BN254 field hash mirroring Noir's Pedersen tuple arity."""
    hasher = hashlib.sha256()
    hasher.update(SURROGATE_HASH_DOMAIN)
    hasher.update(len(fields).to_bytes(4, "big"))
    for element in fields:
        if element < 0 or element >= BN254_FIELD_MODULUS:
            raise MigrationInputError(
                "field_out_of_range",
                "Field element outside canonical BN254 scalar field range.",
            )
        hasher.update(element.to_bytes(32, "big"))
    return int.from_bytes(hasher.digest(), "big") % BN254_FIELD_MODULUS


def _guard_string_against_secrets(value: str, *, field_name: str) -> None:
    stripped = value.strip()
    if _STELLAR_SECRET_SEED_RE.match(stripped):
        raise MigrationInputError(
            "secret_import_forbidden",
            f"Refusing secret-seed-shaped value in '{field_name}'; synthetic inputs required.",
            field=field_name,
        )
    if _HEX_SECRET_RE.match(stripped):
        raise MigrationInputError(
            "secret_import_forbidden",
            f"Refusing 32-byte hex secret-shaped value in '{field_name}'; synthetic inputs required.",
            field=field_name,
        )
    lowered = stripped.lower()
    for marker in _FORBIDDEN_VALUE_MARKERS:
        if marker in lowered:
            raise MigrationInputError(
                "secret_import_forbidden",
                f"Refusing credential or witness reference in '{field_name}'; synthetic inputs required.",
                field=field_name,
            )


def reject_secret_bearing_mapping(
    payload: Mapping[str, Any],
    *,
    path_prefix: str = "config",
) -> None:
    """Recursively reject any secret-bearing keys or values in a scenario mapping."""
    for raw_key, raw_value in payload.items():
        key_str = str(raw_key)
        normalized_key = key_str.strip().lower().replace("-", "_")
        field_path = f"{path_prefix}.{key_str}"
        if normalized_key in _FORBIDDEN_SECRET_KEYS:
            raise MigrationInputError(
                "secret_import_forbidden",
                f"Forbidden witness/secret key '{key_str}' in migration scenario; only synthetic parameters are allowed.",
                field=field_path,
            )
        if isinstance(raw_value, str):
            _guard_string_against_secrets(raw_value, field_name=field_path)
        elif isinstance(raw_value, Mapping):
            reject_secret_bearing_mapping(raw_value, path_prefix=field_path)
        elif isinstance(raw_value, Sequence) and not isinstance(
            raw_value, (bytes, bytearray)
        ):
            for idx, item in enumerate(raw_value):
                item_path = f"{field_path}[{idx}]"
                if isinstance(item, str):
                    _guard_string_against_secrets(item, field_name=item_path)
                elif isinstance(item, Mapping):
                    reject_secret_bearing_mapping(item, path_prefix=item_path)


def validate_cohort_label(cohort_label: str) -> str:
    """Require an explicit `synthetic-*` cohort label and forbid secret-shaped strings."""
    _guard_string_against_secrets(cohort_label, field_name="cohort_label")
    if len(cohort_label) > MAX_COHORT_LABEL_LEN or not _CANONICAL_COHORT_LABEL_RE.match(
        cohort_label
    ):
        raise MigrationInputError(
            "invalid_cohort_label",
            "Cohort label must match 'synthetic-<lowercase-slug>' (max 64 ASCII chars).",
            field="cohort_label",
        )
    return cohort_label


def derive_scope_field(
    scope_identifier: str,
    *,
    collapse_purpose_to_default: bool = False,
) -> int:
    """Derive a canonical BN254 scope field element matching `frontend/src/seedVault.ts`."""
    _guard_string_against_secrets(scope_identifier, field_name="scopes")
    if scope_identifier == "0":
        return 0
    if not scope_identifier or len(scope_identifier) > 64:
        raise MigrationInputError(
            "noncanonical_scope",
            "Scope identifier must be '0' or a canonical 1..64 byte 'v:<verifier>:p:<purpose>' string.",
            field="scopes",
        )
    if not _CANONICAL_SCOPE_CHARS_RE.match(scope_identifier):
        raise MigrationInputError(
            "noncanonical_scope",
            "Scope identifier must contain lowercase ASCII [a-z0-9:_-] only without whitespace.",
            field="scopes",
        )
    match = _CANONICAL_VERIFIER_SCOPE_RE.match(scope_identifier)
    if match is None:
        raise MigrationInputError(
            "noncanonical_scope",
            "Scoped identifier must follow canonical 'v:<verifier>:p:<purpose>' grammar or '0'.",
            field="scopes",
        )
    effective_scope = scope_identifier
    if collapse_purpose_to_default:
        effective_scope = f"v:{match.group('verifier')}:p:default"
    digest = hashlib.sha256(f"harpocrates:scope:{effective_scope}".encode()).digest()
    reduced = int.from_bytes(digest, "big") % BN254_FIELD_MODULUS
    return 1 if reduced == 0 else reduced


def derive_synthetic_cohort(
    *,
    cohort_label: str = "synthetic-default",
    identity_count: int = 4,
    video_count: int = 3,
) -> tuple[list[SyntheticIdentity], list[SyntheticEvidence]]:
    """Generate a deterministic synthetic witness and evidence cohort."""
    validated_label = validate_cohort_label(cohort_label)
    if (
        isinstance(identity_count, bool)
        or identity_count < 1
        or identity_count > MAX_SYNTHETIC_IDENTITIES
    ):
        raise MigrationInputError(
            "invalid_cohort_bounds",
            f"identity_count must be an integer in 1..={MAX_SYNTHETIC_IDENTITIES}.",
            field="identity_count",
        )
    if (
        isinstance(video_count, bool)
        or video_count < 1
        or video_count > MAX_SYNTHETIC_VIDEOS
    ):
        raise MigrationInputError(
            "invalid_cohort_bounds",
            f"video_count must be an integer in 1..={MAX_SYNTHETIC_VIDEOS}.",
            field="video_count",
        )

    prefix_bytes = f"{SYNTHETIC_DOMAIN_PREFIX}:{validated_label}".encode()
    identities: list[SyntheticIdentity] = []
    for idx in range(identity_count):
        slot = f"identity:{idx}".encode()
        cs = _field_from_domain_bytes(prefix_bytes, b"credential_secret", slot)
        ns = _field_from_domain_bytes(prefix_bytes, b"nullifier_secret", slot)
        root = pedersen_surrogate_hash([cs])
        identities.append(
            SyntheticIdentity(
                label=f"synthetic-id-{idx}",
                credential_secret=cs,
                nullifier_secret=ns,
                credential_root=root,
            )
        )

    evidences: list[SyntheticEvidence] = []
    for idx in range(video_count):
        video_digest = hashlib.sha256(
            prefix_bytes + b":video:" + str(idx).encode("ascii")
        ).digest()
        vhi = int.from_bytes(video_digest[:16], "big")
        vlo = int.from_bytes(video_digest[16:], "big")
        evidences.append(
            SyntheticEvidence(
                label=f"synthetic-video-{idx}",
                video_hash_hi=vhi,
                video_hash_lo=vlo,
            )
        )
    return identities, evidences


def compute_policy_nullifier(
    policy: ScopePolicySpec,
    identity: SyntheticIdentity,
    evidence: SyntheticEvidence,
    *,
    scope_identifier: str,
    epoch: int,
) -> int:
    """Evaluate a Silent Witness nullifier under `policy` using circuit preimage structure."""
    if isinstance(epoch, bool) or epoch < 0 or epoch >= BN254_FIELD_MODULUS:
        raise MigrationInputError(
            "invalid_epoch",
            "Epoch must be a non-negative integer within the BN254 scalar field.",
            field="epochs",
        )
    # Always validate scope_identifier syntax even if the policy ignores scope.
    scoped_field = derive_scope_field(
        scope_identifier,
        collapse_purpose_to_default=policy.collapse_purpose_to_default,
    )

    if policy.domain_separator is None:
        evidence_digest = pedersen_surrogate_hash(
            [
                DIGEST_ALGORITHM_SHA256,
                evidence.video_hash_hi,
                evidence.video_hash_lo,
            ]
        )
    else:
        effective_scope = scoped_field if policy.bind_verifier_scope else 0
        effective_epoch = epoch if policy.bind_epoch else 0
        scope_hash = pedersen_surrogate_hash(
            [
                policy.domain_separator,
                effective_scope,
                effective_epoch,
            ]
        )
        evidence_digest = pedersen_surrogate_hash(
            [
                DIGEST_ALGORITHM_SHA256,
                evidence.video_hash_hi,
                evidence.video_hash_lo,
                scope_hash,
            ]
        )

    return pedersen_surrogate_hash(
        [
            identity.credential_secret,
            identity.nullifier_secret,
            evidence_digest,
        ]
    )


def resolve_policy(
    policy_or_name: str | ScopePolicySpec,
    *,
    custom_policies: Mapping[str, ScopePolicySpec] | None = None,
    field_name: str = "policy",
) -> ScopePolicySpec:
    """Resolve a built-in or scenario-defined `ScopePolicySpec`."""
    if isinstance(policy_or_name, ScopePolicySpec):
        return policy_or_name
    _guard_string_against_secrets(policy_or_name, field_name=field_name)
    if custom_policies and policy_or_name in custom_policies:
        return custom_policies[policy_or_name]
    if policy_or_name in BUILTIN_POLICIES:
        return BUILTIN_POLICIES[policy_or_name]
    supported = sorted(
        set(BUILTIN_POLICIES.keys())
        | (set(custom_policies.keys()) if custom_policies else set())
    )
    raise MigrationInputError(
        "unknown_policy",
        f"Unknown scope policy '{policy_or_name}'. Supported policies: {', '.join(supported)}.",
        field=field_name,
    )


def parse_custom_policies_from_scenario(
    scenario: Mapping[str, Any],
) -> dict[str, ScopePolicySpec]:
    """Parse synthetic custom policy definitions from a validated JSON scenario."""
    reject_secret_bearing_mapping(scenario, path_prefix="scenario")
    raw_policies = scenario.get("policies", {})
    if not isinstance(raw_policies, Mapping):
        raise MigrationInputError(
            "invalid_scenario",
            "'policies' in scenario file must be an object mapping policy names to definitions.",
            field="scenario.policies",
        )
    parsed: dict[str, ScopePolicySpec] = {}
    for name, raw_spec in raw_policies.items():
        if not isinstance(name, str) or not re.match(r"^[a-z0-9][a-z0-9_-]{1,47}$", name):
            raise MigrationInputError(
                "invalid_policy_name",
                "Custom policy name must match '^[a-z0-9][a-z0-9_-]{1,47}$'.",
                field="scenario.policies",
            )
        if not isinstance(raw_spec, Mapping):
            raise MigrationInputError(
                "invalid_scenario",
                f"Policy '{name}' definition must be an object.",
                field=f"scenario.policies.{name}",
            )
        sep_label = raw_spec.get("domain_separator_label")
        if sep_label is None:
            sep_field: int | None = None
        else:
            if not isinstance(sep_label, str) or not re.match(
                r"^[A-Z0-9_]{4,31}$", sep_label
            ):
                raise MigrationInputError(
                    "invalid_domain_separator",
                    "domain_separator_label must be 4..31 uppercase ASCII [A-Z0-9_] bytes or null.",
                    field=f"scenario.policies.{name}.domain_separator_label",
                )
            sep_bytes = sep_label.encode("ascii").rjust(32, b"\x00")
            sep_field = int.from_bytes(sep_bytes, "big")
            if sep_field >= BN254_FIELD_MODULUS:
                raise MigrationInputError(
                    "invalid_domain_separator",
                    "Encoded domain_separator_label exceeds BN254 scalar field modulus.",
                    field=f"scenario.policies.{name}.domain_separator_label",
                )
        bind_scope = raw_spec.get("bind_verifier_scope")
        bind_epoch = raw_spec.get("bind_epoch")
        collapse_purpose = raw_spec.get("collapse_purpose_to_default", False)
        if (
            not isinstance(bind_scope, bool)
            or not isinstance(bind_epoch, bool)
            or not isinstance(collapse_purpose, bool)
        ):
            raise MigrationInputError(
                "invalid_scenario",
                f"Policy '{name}' flags bind_verifier_scope, bind_epoch, and collapse_purpose_to_default must be booleans.",
                field=f"scenario.policies.{name}",
            )
        if sep_field is None and (bind_scope or bind_epoch):
            raise MigrationInputError(
                "invalid_scenario",
                f"Policy '{name}' cannot bind scope or epoch without a domain_separator_label.",
                field=f"scenario.policies.{name}",
            )
        description = str(raw_spec.get("description", f"Custom synthetic policy {name}"))
        parsed[name] = ScopePolicySpec(
            name=name,
            description=description,
            domain_separator=sep_field,
            domain_separator_label=sep_label,
            bind_verifier_scope=bind_scope,
            bind_epoch=bind_epoch,
            collapse_purpose_to_default=collapse_purpose,
        )
    return parsed


def _validate_scopes_and_epochs(
    scopes: Sequence[str],
    epochs: Sequence[int],
) -> tuple[list[str], list[int]]:
    if not scopes or len(scopes) > MAX_SYNTHETIC_SCOPES:
        raise MigrationInputError(
            "invalid_cohort_bounds",
            f"scopes must contain 1..={MAX_SYNTHETIC_SCOPES} canonical scope identifiers.",
            field="scopes",
        )
    dedup_scopes: list[str] = []
    seen_scopes: set[str] = set()
    for scope in scopes:
        if not isinstance(scope, str):
            raise MigrationInputError(
                "noncanonical_scope",
                "Each scope identifier must be a string.",
                field="scopes",
            )
        derive_scope_field(scope)
        if scope in seen_scopes:
            raise MigrationInputError(
                "duplicate_scope",
                f"Duplicate scope identifier '{scope}' in migration cohort.",
                field="scopes",
            )
        seen_scopes.add(scope)
        dedup_scopes.append(scope)

    if not epochs or len(epochs) > MAX_SYNTHETIC_EPOCHS:
        raise MigrationInputError(
            "invalid_cohort_bounds",
            f"epochs must contain 1..={MAX_SYNTHETIC_EPOCHS} non-negative integers.",
            field="epochs",
        )
    dedup_epochs: list[int] = []
    seen_epochs: set[int] = set()
    for ep in epochs:
        if isinstance(ep, bool) or not isinstance(ep, int) or ep < 0 or ep >= BN254_FIELD_MODULUS:
            raise MigrationInputError(
                "invalid_epoch",
                "Each epoch must be a non-negative integer within the BN254 scalar field.",
                field="epochs",
            )
        if ep in seen_epochs:
            raise MigrationInputError(
                "duplicate_epoch",
                f"Duplicate epoch '{ep}' in migration cohort.",
                field="epochs",
            )
        seen_epochs.add(ep)
        dedup_epochs.append(ep)

    return dedup_scopes, dedup_epochs


def _count_cross_scope_collisions(
    table: Mapping[tuple[int, int, int, int], int],
    *,
    identity_count: int,
    video_count: int,
    scope_count: int,
    epoch_count: int,
) -> tuple[int, int]:
    collisions = 0
    total_pairs = 0
    for id_idx in range(identity_count):
        for vid_idx in range(video_count):
            for ep_idx in range(epoch_count):
                for s_a in range(scope_count):
                    for s_b in range(s_a + 1, scope_count):
                        total_pairs += 1
                        if (
                            table[(id_idx, vid_idx, s_a, ep_idx)]
                            == table[(id_idx, vid_idx, s_b, ep_idx)]
                        ):
                            collisions += 1
    return collisions, total_pairs


def _count_cross_epoch_collisions(
    table: Mapping[tuple[int, int, int, int], int],
    *,
    identity_count: int,
    video_count: int,
    scope_count: int,
    epoch_count: int,
) -> tuple[int, int]:
    collisions = 0
    total_pairs = 0
    for id_idx in range(identity_count):
        for vid_idx in range(video_count):
            for s_idx in range(scope_count):
                for ep_a in range(epoch_count):
                    for ep_b in range(ep_a + 1, epoch_count):
                        total_pairs += 1
                        if (
                            table[(id_idx, vid_idx, s_idx, ep_a)]
                            == table[(id_idx, vid_idx, s_idx, ep_b)]
                        ):
                            collisions += 1
    return collisions, total_pairs


def _rate(numerator: int, denominator: int) -> float:
    if denominator == 0:
        return 0.0
    return round(numerator / denominator, 6)


def analyze_policy_migration(
    old_policy: str | ScopePolicySpec,
    new_policy: str | ScopePolicySpec,
    *,
    cohort_label: str = "synthetic-default",
    identity_count: int = 4,
    video_count: int = 3,
    scopes: Sequence[str] = DEFAULT_SYNTHETIC_SCOPES,
    epochs: Sequence[int] = DEFAULT_SYNTHETIC_EPOCHS,
    custom_policies: Mapping[str, ScopePolicySpec] | None = None,
) -> dict[str, Any]:
    """Compare `old_policy` and `new_policy` on a deterministic synthetic cohort."""
    resolved_old = resolve_policy(
        old_policy, custom_policies=custom_policies, field_name="old_policy"
    )
    resolved_new = resolve_policy(
        new_policy, custom_policies=custom_policies, field_name="new_policy"
    )
    validated_scopes, validated_epochs = _validate_scopes_and_epochs(scopes, epochs)
    identities, evidences = derive_synthetic_cohort(
        cohort_label=cohort_label,
        identity_count=identity_count,
        video_count=video_count,
    )

    old_table: dict[tuple[int, int, int, int], int] = {}
    new_table: dict[tuple[int, int, int, int], int] = {}
    old_all_nullifiers: set[int] = set()
    new_all_nullifiers: set[int] = set()
    exact_context_matches = 0
    overlapping_contexts: set[tuple[str, int]] = set()

    for id_idx, identity in enumerate(identities):
        for vid_idx, evidence in enumerate(evidences):
            for s_idx, scope_str in enumerate(validated_scopes):
                for ep_idx, epoch_val in enumerate(validated_epochs):
                    key = (id_idx, vid_idx, s_idx, ep_idx)
                    old_nf = compute_policy_nullifier(
                        resolved_old,
                        identity,
                        evidence,
                        scope_identifier=scope_str,
                        epoch=epoch_val,
                    )
                    new_nf = compute_policy_nullifier(
                        resolved_new,
                        identity,
                        evidence,
                        scope_identifier=scope_str,
                        epoch=epoch_val,
                    )
                    old_table[key] = old_nf
                    new_table[key] = new_nf
                    old_all_nullifiers.add(old_nf)
                    new_all_nullifiers.add(new_nf)
                    if old_nf == new_nf:
                        exact_context_matches += 1
                        overlapping_contexts.add((scope_str, epoch_val))

    total_evaluations = (
        len(identities) * len(evidences) * len(validated_scopes) * len(validated_epochs)
    )

    old_scope_collisions, total_scope_pairs = _count_cross_scope_collisions(
        old_table,
        identity_count=len(identities),
        video_count=len(evidences),
        scope_count=len(validated_scopes),
        epoch_count=len(validated_epochs),
    )
    new_scope_collisions, _ = _count_cross_scope_collisions(
        new_table,
        identity_count=len(identities),
        video_count=len(evidences),
        scope_count=len(validated_scopes),
        epoch_count=len(validated_epochs),
    )

    old_epoch_collisions, total_epoch_pairs = _count_cross_epoch_collisions(
        old_table,
        identity_count=len(identities),
        video_count=len(evidences),
        scope_count=len(validated_scopes),
        epoch_count=len(validated_epochs),
    )
    new_epoch_collisions, _ = _count_cross_epoch_collisions(
        new_table,
        identity_count=len(identities),
        video_count=len(evidences),
        scope_count=len(validated_scopes),
        epoch_count=len(validated_epochs),
    )

    old_scope_rate = _rate(old_scope_collisions, total_scope_pairs)
    new_scope_rate = _rate(new_scope_collisions, total_scope_pairs)
    old_epoch_rate = _rate(old_epoch_collisions, total_epoch_pairs)
    new_epoch_rate = _rate(new_epoch_collisions, total_epoch_pairs)
    context_overlap_rate = _rate(exact_context_matches, total_evaluations)
    cross_set_overlap = len(old_all_nullifiers & new_all_nullifiers)

    scope_linkability_regression = new_scope_collisions > old_scope_collisions or (
        resolved_old.bind_verifier_scope and not resolved_new.bind_verifier_scope
    ) or (
        resolved_old.bind_verifier_scope
        and not resolved_old.collapse_purpose_to_default
        and resolved_new.collapse_purpose_to_default
    )
    epoch_linkability_regression = new_epoch_collisions > old_epoch_collisions or (
        resolved_old.bind_epoch and not resolved_new.bind_epoch
    )
    has_regression = scope_linkability_regression or epoch_linkability_regression

    if has_regression:
        linkability_delta = "increased"
    elif (
        new_scope_collisions < old_scope_collisions
        or new_epoch_collisions < old_epoch_collisions
    ):
        linkability_delta = "reduced"
    else:
        linkability_delta = "unchanged"

    transition_dual_spend_risk = exact_context_matches < total_evaluations
    sorted_overlap_contexts = [
        {"scope": scope_str, "epoch": epoch_val}
        for scope_str, epoch_val in sorted(overlapping_contexts)
    ]

    if resolved_old == resolved_new and exact_context_matches == total_evaluations:
        migration_classification = "noop_identical_policy"
    elif has_regression:
        migration_classification = "regression_weakens_isolation"
    elif 0 < exact_context_matches < total_evaluations:
        migration_classification = "partial_overlap_anchor_transition"
    else:
        migration_classification = "disjoint_nullifier_cutover"

    safeguards: list[str] = []
    if has_regression:
        safeguards.append("reject_isolation_downgrade_or_bump_protocol_major_version")
    if transition_dual_spend_risk:
        safeguards.append("enforce_circuit_or_domain_cutover_boundary")
        safeguards.append("prevent_dual_policy_acceptance_for_same_evidence_window")
    if 0 < exact_context_matches < total_evaluations:
        safeguards.append("preserve_overlapping_global_anchor_nullifiers_across_cutover")
    safeguards.append("account_for_persistent_credential_root_correlation")

    unique_roots = len({identity.credential_root for identity in identities})

    return {
        "schema": "harpocrates.zk-nullifier-migration-report/v1",
        "synthetic_only": True,
        "cohort": {
            "cohort_label": cohort_label,
            "identity_count": len(identities),
            "unique_credential_roots": unique_roots,
            "video_count": len(evidences),
            "scopes": validated_scopes,
            "epochs": validated_epochs,
            "total_evaluations": total_evaluations,
        },
        "policies": {
            "old": {
                "name": resolved_old.name,
                "description": resolved_old.description,
                "domain_separator_label": resolved_old.domain_separator_label,
                "bind_verifier_scope": resolved_old.bind_verifier_scope,
                "bind_epoch": resolved_old.bind_epoch,
                "collapse_purpose_to_default": resolved_old.collapse_purpose_to_default,
            },
            "new": {
                "name": resolved_new.name,
                "description": resolved_new.description,
                "domain_separator_label": resolved_new.domain_separator_label,
                "bind_verifier_scope": resolved_new.bind_verifier_scope,
                "bind_epoch": resolved_new.bind_epoch,
                "collapse_purpose_to_default": resolved_new.collapse_purpose_to_default,
            },
        },
        "linkability": {
            "old_cross_scope_collision_pairs": old_scope_collisions,
            "new_cross_scope_collision_pairs": new_scope_collisions,
            "total_cross_scope_pairs": total_scope_pairs,
            "old_cross_scope_nullifier_linkability_rate": old_scope_rate,
            "new_cross_scope_nullifier_linkability_rate": new_scope_rate,
            "old_cross_epoch_collision_pairs": old_epoch_collisions,
            "new_cross_epoch_collision_pairs": new_epoch_collisions,
            "total_cross_epoch_pairs": total_epoch_pairs,
            "old_cross_epoch_nullifier_linkability_rate": old_epoch_rate,
            "new_cross_epoch_nullifier_linkability_rate": new_epoch_rate,
            "cross_policy_exact_match_count": exact_context_matches,
            "cross_policy_exact_match_rate": context_overlap_rate,
            "cross_policy_shared_nullifier_set_size": cross_set_overlap,
            "credential_root_persistent_linkability": True,
            "nullifier_linkability_delta": linkability_delta,
        },
        "replay_boundaries": {
            "same_context_replay_blocked": True,
            "old_cross_scope_distinct_nullifiers": old_scope_collisions == 0
            and total_scope_pairs > 0,
            "new_cross_scope_distinct_nullifiers": new_scope_collisions == 0
            and total_scope_pairs > 0,
            "old_epoch_rotation_allows_fresh_nullifier": old_epoch_collisions == 0
            and total_epoch_pairs > 0,
            "new_epoch_rotation_allows_fresh_nullifier": new_epoch_collisions == 0
            and total_epoch_pairs > 0,
            "transition_dual_registration_possible": transition_dual_spend_risk,
            "overlapping_cutover_contexts": sorted_overlap_contexts,
            "isolation_regression": has_regression,
            "migration_classification": migration_classification,
            "required_safeguards": safeguards,
        },
    }


def _format_text_summary(report: Mapping[str, Any]) -> str:
    cohort = report["cohort"]
    old_pol = report["policies"]["old"]
    new_pol = report["policies"]["new"]
    link = report["linkability"]
    replay = report["replay_boundaries"]
    lines = [
        "Silent Witness Nullifier Migration Analysis (synthetic-only)",
        f"  Policies: {old_pol['name']} -> {new_pol['name']}",
        (
            f"  Cohort: label={cohort['cohort_label']} "
            f"identities={cohort['identity_count']} "
            f"videos={cohort['video_count']} "
            f"scopes={len(cohort['scopes'])} "
            f"epochs={len(cohort['epochs'])} "
            f"(evaluations={cohort['total_evaluations']})"
        ),
        (
            "  Cross-scope nullifier linkability: "
            f"{link['old_cross_scope_nullifier_linkability_rate']:.6f} -> "
            f"{link['new_cross_scope_nullifier_linkability_rate']:.6f}"
        ),
        (
            "  Cross-epoch nullifier linkability: "
            f"{link['old_cross_epoch_nullifier_linkability_rate']:.6f} -> "
            f"{link['new_cross_epoch_nullifier_linkability_rate']:.6f}"
        ),
        (
            "  Cross-policy exact nullifier overlap: "
            f"{link['cross_policy_exact_match_count']}/{cohort['total_evaluations']} "
            f"({link['cross_policy_exact_match_rate']:.6f})"
        ),
        (
            "  Persistent credential_root correlation: "
            f"{link['credential_root_persistent_linkability']}"
        ),
        f"  Migration classification: {replay['migration_classification']}",
        (
            "  Transition dual-registration possible: "
            f"{replay['transition_dual_registration_possible']}"
        ),
        f"  Isolation regression: {replay['isolation_regression']}",
        f"  Required safeguards: {', '.join(replay['required_safeguards'])}",
    ]
    return "\n".join(lines)


def _parse_int_csv(raw: str) -> list[int]:
    _guard_string_against_secrets(raw, field_name="epochs")
    parts = [piece.strip() for piece in raw.split(",") if piece.strip()]
    if not parts:
        raise MigrationInputError(
            "invalid_epoch",
            "Epochs argument must contain at least one non-negative integer.",
            field="epochs",
        )
    parsed: list[int] = []
    for piece in parts:
        if not re.match(r"^(?:0|[1-9][0-9]*)$", piece):
            raise MigrationInputError(
                "invalid_epoch",
                "Epochs must be canonical non-negative base-10 integers.",
                field="epochs",
            )
        parsed.append(int(piece, 10))
    return parsed


def _parse_scope_csv(raw: str) -> list[str]:
    _guard_string_against_secrets(raw, field_name="scopes")
    if any(ch.isspace() for ch in raw):
        raise MigrationInputError(
            "noncanonical_scope",
            "Scopes CSV must not contain whitespace.",
            field="scopes",
        )
    parts = [piece for piece in raw.split(",") if piece != ""]
    if not parts:
        raise MigrationInputError(
            "noncanonical_scope",
            "Scopes argument must contain at least one canonical scope identifier.",
            field="scopes",
        )
    return parts


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Analyze Silent Witness nullifier scope policy migrations using "
            "deterministic synthetic inputs only."
        )
    )
    parser.add_argument(
        "--old-policy",
        required=True,
        help=f"Baseline scope policy ({', '.join(sorted(BUILTIN_POLICIES))}, or custom scenario name).",
    )
    parser.add_argument(
        "--new-policy",
        required=True,
        help=f"Candidate scope policy ({', '.join(sorted(BUILTIN_POLICIES))}, or custom scenario name).",
    )
    parser.add_argument(
        "--cohort-label",
        default="synthetic-default",
        help="Deterministic synthetic cohort slug matching 'synthetic-<slug>'.",
    )
    parser.add_argument(
        "--identities",
        type=int,
        default=4,
        help=f"Synthetic identity count (1..={MAX_SYNTHETIC_IDENTITIES}).",
    )
    parser.add_argument(
        "--videos",
        type=int,
        default=3,
        help=f"Synthetic video digest count (1..={MAX_SYNTHETIC_VIDEOS}).",
    )
    parser.add_argument(
        "--scopes",
        default=",".join(DEFAULT_SYNTHETIC_SCOPES),
        help="Comma-separated canonical scope identifiers (no whitespace).",
    )
    parser.add_argument(
        "--epochs",
        default=",".join(str(ep) for ep in DEFAULT_SYNTHETIC_EPOCHS),
        help="Comma-separated canonical base-10 epoch integers.",
    )
    parser.add_argument(
        "--scenario-file",
        type=Path,
        default=None,
        help="Optional JSON file defining custom synthetic policy specifications.",
    )
    parser.add_argument(
        "--fail-on-regression",
        action="store_true",
        help="Exit with code 3 when the candidate policy weakens scope or epoch isolation.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit the machine-readable JSON report instead of human summary.",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    try:
        custom_policies: dict[str, ScopePolicySpec] | None = None
        if args.scenario_file is not None:
            file_name_lower = args.scenario_file.name.lower()
            if file_name_lower == "prover.toml" or file_name_lower.startswith(".env"):
                raise MigrationInputError(
                    "secret_import_forbidden",
                    "Refusing witness or environment secret file as migration scenario.",
                    field="scenario_file",
                )
            try:
                raw_text = args.scenario_file.read_text(encoding="utf-8")
                scenario_data = json.loads(raw_text)
            except OSError as exc:
                raise MigrationInputError(
                    "scenario_read_error",
                    f"Unable to read scenario JSON file ({exc.__class__.__name__}).",
                    field="scenario_file",
                ) from exc
            except json.JSONDecodeError as exc:
                raise MigrationInputError(
                    "invalid_scenario",
                    f"Scenario file is not valid JSON (line {exc.lineno}).",
                    field="scenario_file",
                ) from exc
            if not isinstance(scenario_data, Mapping):
                raise MigrationInputError(
                    "invalid_scenario",
                    "Scenario JSON root must be an object.",
                    field="scenario_file",
                )
            custom_policies = parse_custom_policies_from_scenario(scenario_data)

        scopes = _parse_scope_csv(args.scopes)
        epochs = _parse_int_csv(args.epochs)
        report = analyze_policy_migration(
            args.old_policy,
            args.new_policy,
            cohort_label=args.cohort_label,
            identity_count=args.identities,
            video_count=args.videos,
            scopes=scopes,
            epochs=epochs,
            custom_policies=custom_policies,
        )
    except MigrationInputError as exc:
        if args.json:
            print(json.dumps({"ok": False, "error": exc.to_dict()}, indent=2))
        else:
            print(f"error [{exc.code}]: {exc.message}", file=sys.stderr)
        return EXIT_INVALID_INPUT

    if args.json:
        print(json.dumps(report, indent=2, sort_keys=False))
    else:
        print(_format_text_summary(report))

    if args.fail_on_regression and report["replay_boundaries"]["isolation_regression"]:
        return EXIT_POLICY_REGRESSION
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
