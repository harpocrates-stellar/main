from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import threading
import time
from dataclasses import dataclass
from typing import Any, Dict, FrozenSet, Iterable, List, Mapping, Optional, Sequence, Tuple

try:
    from analytics.log_processor import LogEntry, LogProcessor, validate_log_export_safety
except Exception:
    try:
        from backend.analytics.log_processor import LogEntry, LogProcessor, validate_log_export_safety
    except Exception:
        LogEntry = None
        LogProcessor = None
        validate_log_export_safety = None

try:
    from analytics.consent import ConsentManager
except Exception:
    try:
        from backend.analytics.consent import ConsentManager
    except Exception:
        ConsentManager = None  # type: ignore[assignment]

try:
    from analytics.redaction import (
        CRYPTO_DOMAIN_VERSION,
        DEFAULT_CAP_BYTES,
        SENSITIVE_FIELD_CATEGORIES,
    )
except Exception:
    try:
        from backend.analytics.redaction import (
            CRYPTO_DOMAIN_VERSION,
            DEFAULT_CAP_BYTES,
            SENSITIVE_FIELD_CATEGORIES,
        )
    except Exception:
        CRYPTO_DOMAIN_VERSION = "harpocrates-redaction-v1"
        DEFAULT_CAP_BYTES = 256
        SENSITIVE_FIELD_CATEGORIES = {
            "secret": ["secret", "password", "token", "private_key"],
            "witness": ["witness"],
            "media": ["video", "media", "blob"],
            "proof": ["proof", "private_inputs", "nullifier"],
            "wallet_sig": ["signature", "xdr"],
            "wallet_id": ["wallet", "stellar_address"],
            "pii": ["email", "ip"],
        }


EXPORT_FORMAT_VERSION = "1.0.0"
TENANT_MANIFEST_SCHEMA_VERSION = "1.0.0"
TENANT_EXPORT_MANIFEST_DOMAIN_TAG = "harpocrates:tenant-export-manifest:v1"
TENANT_MANIFEST_POLICY_DOMAIN_TAG = "harpocrates:tenant-export-redaction-policy:v1"
TENANT_MANIFEST_CLASS_DOMAIN_TAG = "harpocrates:tenant-export-class:v1"
TENANT_MANIFEST_SUBJECT_DOMAIN_TAG = "harpocrates:tenant-export-subject:v1"

# Strict allowlists per exported record class: fields outside these sets are excluded by construction.
TENANT_CLASS_FIELD_ALLOWLISTS: Dict[str, FrozenSet[str]] = {
    "consent_posture": frozenset({
        "schema_version",
        "status",
        "source",
        "granted_scopes",
        "granted_at_epoch_seconds",
        "expires_at_epoch_seconds",
        "withdrawal_epoch_seconds",
    }),
    "operational_telemetry": frozenset({
        "schema_version",
        "event_name",
        "category",
        "severity",
        "timestamp_epoch_seconds",
        "endpoint_pattern",
        "method",
        "status_code",
        "operation_status",
        "lifecycle_state",
        "duration_seconds",
        "labels",
        "counters",
    }),
    "export_audit_metadata": frozenset({
        "artifact_id",
        "schema_version",
        "generated_at_epoch_seconds",
        "entry_count",
        "payload_bytes",
        "compress",
        "payload_type",
        "rollout_phase",
        "redaction_version",
        "checksum_sha256_prefix16",
    }),
}

ALLOWED_TENANT_EXPORT_CLASSES: FrozenSet[str] = frozenset(TENANT_CLASS_FIELD_ALLOWLISTS.keys())
DEFAULT_EXCLUDED_SENSITIVE_CATEGORIES: Tuple[str, ...] = tuple(sorted(SENSITIVE_FIELD_CATEGORIES.keys()))

_TENANT_TAG_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_POLICY_VERSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$")
_SHA256_HEX_RE = re.compile(r"^[0-9a-f]{64}$")

_FORBIDDEN_VALUE_PATTERNS = (
    re.compile(r"\b[GSM][A-Z2-7]{55,68}\b"),
    re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"),
    re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{8,}"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    re.compile(r"(?i)\bpostgres(?:ql)?://[^\s]+"),
    re.compile(r"\b(?:0x)?[0-9a-fA-F]{32,}\b"),
    re.compile(r"(?i)\b(?:cst-v1|sk_live|sk_test|rk_live)[:_][A-Za-z0-9_-]{6,}"),
    re.compile(
        r"(?i)(?:^|[\s/\\])[A-Za-z0-9_.-]{1,128}\."
        r"(?:mp4|mov|mkv|avi|webm|wav|mp3|png|jpg|jpeg|wtns|proof|acir|pem|key)(?:$|[\s?#])"
    ),
)

_FORBIDDEN_NESTED_KEY_TOKENS = frozenset({
    "secret",
    "credential",
    "password",
    "passwd",
    "token",
    "consent_token",
    "apikey",
    "private_key",
    "privkey",
    "mnemonic",
    "seed_phrase",
    "witness",
    "witness_data",
    "video",
    "media",
    "raw_bytes",
    "file_content",
    "proof",
    "proof_payload",
    "private_inputs",
    "nullifier",
    "signature",
    "wallet_signature",
    "xdr",
    "stellar_address",
    "account_id_tag",
    "exported_by_tag",
})


class ExportMaterialExclusionError(ValueError):
    """Raised when non-allowlisted, credential, or evidence material enters a tenant export."""


class ManifestVerificationError(ValueError):
    """Raised when a tenant export manifest fails cryptographic or structural verification."""


def _frame_digest(domain_tag: str, parts: Sequence[bytes]) -> str:
    hasher = hashlib.sha256()
    tag_bytes = domain_tag.encode("utf-8")
    hasher.update(f"{len(tag_bytes)}:".encode("ascii"))
    hasher.update(tag_bytes)
    for part in parts:
        hasher.update(f"|{len(part)}:".encode("ascii"))
        hasher.update(part)
    return hasher.hexdigest()


def _canonical_json_bytes(payload: Any) -> bytes:
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


def _hash_tenant_subject(tenant_tag: str) -> str:
    return _frame_digest(TENANT_MANIFEST_SUBJECT_DOMAIN_TAG, [tenant_tag.encode("utf-8")])


def _compute_allowlists_digest() -> str:
    canonical_map = {
        cls_name: sorted(fields)
        for cls_name, fields in sorted(TENANT_CLASS_FIELD_ALLOWLISTS.items())
    }
    return _frame_digest(
        TENANT_MANIFEST_POLICY_DOMAIN_TAG + ":allowlists",
        [_canonical_json_bytes(canonical_map)],
    )


def _inspect_value_for_forbidden_material(value: Any, *, field_context: str) -> None:
    if isinstance(value, (bytes, bytearray, memoryview)):
        raise ExportMaterialExclusionError(
            f"binary evidence material forbidden in {field_context}"
        )
    if isinstance(value, str):
        if value.startswith("[REDACTED"):
            raise ExportMaterialExclusionError(
                f"redaction placeholder indicates sensitive field presence in {field_context}"
            )
        for pattern in _FORBIDDEN_VALUE_PATTERNS:
            if pattern.search(value):
                raise ExportMaterialExclusionError(
                    f"credential or evidence-shaped value forbidden in {field_context}"
                )
        return
    if isinstance(value, Mapping):
        for nk, nv in value.items():
            if not isinstance(nk, str):
                raise ExportMaterialExclusionError("nested map keys must be strings")
            lowered = nk.strip().lower()
            if lowered in _FORBIDDEN_NESTED_KEY_TOKENS or any(
                tok in lowered for tok in ("secret", "password", "token", "witness", "private_key", "xdr")
            ):
                raise ExportMaterialExclusionError(
                    f"sensitive nested key forbidden in {field_context}"
                )
            _inspect_value_for_forbidden_material(nv, field_context=f"{field_context}.{nk}")
        return
    if isinstance(value, (list, tuple)):
        for idx, elem in enumerate(value):
            _inspect_value_for_forbidden_material(elem, field_context=f"{field_context}[{idx}]")
        return
    if value is None or isinstance(value, (bool, int, float)):
        return
    raise ExportMaterialExclusionError(f"unsupported value type in {field_context}")


def assert_class_records_safe_by_construction(
    class_name: str,
    records: Sequence[Mapping[str, Any]],
) -> List[Dict[str, Any]]:
    """Verify records belong to an allowed class, contain only allowlisted keys, and carry no secrets."""
    if not isinstance(class_name, str) or class_name not in TENANT_CLASS_FIELD_ALLOWLISTS:
        raise ExportMaterialExclusionError(f"disallowed tenant export record class: {class_name!r}")
    if not isinstance(records, Sequence) or isinstance(records, (str, bytes)):
        raise ExportMaterialExclusionError("class records must be a sequence of mappings")

    allowed_fields = TENANT_CLASS_FIELD_ALLOWLISTS[class_name]
    sanitized_records: List[Dict[str, Any]] = []

    for idx, rec in enumerate(records):
        if not isinstance(rec, Mapping):
            raise ExportMaterialExclusionError(f"{class_name}[{idx}] must be a mapping")
        projected: Dict[str, Any] = {}
        for key, val in rec.items():
            if not isinstance(key, str) or key not in allowed_fields:
                raise ExportMaterialExclusionError(
                    f"non-allowlisted field {key!r} forbidden in record class {class_name!r}"
                )
            _inspect_value_for_forbidden_material(val, field_context=f"{class_name}.{key}")
            projected[key] = val
        sanitized_records.append(projected)

    return sanitized_records


@dataclass(frozen=True)
class RedactionPolicyBinding:
    redaction_version: str
    excluded_categories: Tuple[str, ...]
    class_allowlists_digest: str
    cap_bytes: int
    policy_digest: str

    @classmethod
    def build(
        cls,
        *,
        redaction_version: str = CRYPTO_DOMAIN_VERSION,
        excluded_categories: Iterable[str] = DEFAULT_EXCLUDED_SENSITIVE_CATEGORIES,
        cap_bytes: int = DEFAULT_CAP_BYTES,
    ) -> RedactionPolicyBinding:
        if not isinstance(redaction_version, str) or not _POLICY_VERSION_RE.match(redaction_version):
            raise ValueError("invalid redaction_version")
        if isinstance(cap_bytes, bool) or not isinstance(cap_bytes, int) or cap_bytes <= 0:
            raise ValueError("cap_bytes must be a positive integer")
        cats = tuple(sorted({str(c) for c in excluded_categories if str(c)}))
        required = set(DEFAULT_EXCLUDED_SENSITIVE_CATEGORIES)
        if not required.issubset(set(cats)):
            raise ExportMaterialExclusionError(
                "redaction policy cannot omit mandatory sensitive exclusion categories"
            )
        allowlists_digest = _compute_allowlists_digest()
        digest = _frame_digest(
            TENANT_MANIFEST_POLICY_DOMAIN_TAG,
            [
                redaction_version.encode("utf-8"),
                ",".join(cats).encode("utf-8"),
                allowlists_digest.encode("ascii"),
                str(cap_bytes).encode("ascii"),
            ],
        )
        return cls(
            redaction_version=redaction_version,
            excluded_categories=cats,
            class_allowlists_digest=allowlists_digest,
            cap_bytes=cap_bytes,
            policy_digest=digest,
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "redaction_version": self.redaction_version,
            "excluded_categories": list(self.excluded_categories),
            "class_allowlists_digest": self.class_allowlists_digest,
            "cap_bytes": self.cap_bytes,
            "policy_digest": self.policy_digest,
        }


@dataclass(frozen=True)
class ExportedRecordClassBinding:
    class_name: str
    schema_allowlist: Tuple[str, ...]
    record_count: int
    payload_bytes: int
    records_sha256: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "class_name": self.class_name,
            "schema_allowlist": list(self.schema_allowlist),
            "record_count": self.record_count,
            "payload_bytes": self.payload_bytes,
            "records_sha256": self.records_sha256,
        }


def _build_class_binding(
    class_name: str,
    validated_records: List[Dict[str, Any]],
) -> Tuple[ExportedRecordClassBinding, bytes]:
    canonical_bytes = _canonical_json_bytes(validated_records)
    records_digest = _frame_digest(
        TENANT_MANIFEST_CLASS_DOMAIN_TAG,
        [class_name.encode("utf-8"), canonical_bytes],
    )
    allowlist_sorted = tuple(sorted(TENANT_CLASS_FIELD_ALLOWLISTS[class_name]))
    binding = ExportedRecordClassBinding(
        class_name=class_name,
        schema_allowlist=allowlist_sorted,
        record_count=len(validated_records),
        payload_bytes=len(canonical_bytes),
        records_sha256=records_digest,
    )
    return binding, canonical_bytes


def _compute_manifest_digest(
    *,
    schema_version: str,
    tenant_tag_digest: str,
    redaction_policy: RedactionPolicyBinding,
    record_classes: Sequence[ExportedRecordClassBinding],
) -> str:
    parts: List[bytes] = [
        schema_version.encode("utf-8"),
        tenant_tag_digest.encode("ascii"),
        redaction_policy.redaction_version.encode("utf-8"),
        redaction_policy.policy_digest.encode("ascii"),
        str(len(record_classes)).encode("ascii"),
    ]
    for rc in record_classes:
        parts.extend(
            [
                rc.class_name.encode("utf-8"),
                ",".join(rc.schema_allowlist).encode("utf-8"),
                str(rc.record_count).encode("ascii"),
                str(rc.payload_bytes).encode("ascii"),
                rc.records_sha256.encode("ascii"),
            ]
        )
    return _frame_digest(TENANT_EXPORT_MANIFEST_DOMAIN_TAG, parts)


@dataclass(frozen=True)
class TenantExportManifest:
    manifest_id: str
    schema_version: str
    domain_tag: str
    tenant_tag_digest: str
    generated_at_epoch_seconds: float
    redaction_policy: RedactionPolicyBinding
    record_classes: Tuple[ExportedRecordClassBinding, ...]
    manifest_digest: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "manifest_id": self.manifest_id,
            "schema_version": self.schema_version,
            "domain_tag": self.domain_tag,
            "tenant_tag_digest": self.tenant_tag_digest,
            "generated_at_epoch_seconds": self.generated_at_epoch_seconds,
            "redaction_policy": self.redaction_policy.to_dict(),
            "record_classes": [rc.to_dict() for rc in self.record_classes],
            "manifest_digest": self.manifest_digest,
        }


@dataclass(frozen=True)
class TenantExportBundle:
    manifest: TenantExportManifest
    records_by_class: Dict[str, List[Dict[str, Any]]]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "manifest": self.manifest.to_dict(),
            "records_by_class": {
                cls_name: list(items)
                for cls_name, items in sorted(self.records_by_class.items())
            },
        }


def build_tenant_export_manifest(
    authorized_tenant_tag: str,
    records_by_class: Mapping[str, Sequence[Mapping[str, Any]]],
    *,
    redaction_policy: Optional[RedactionPolicyBinding] = None,
    generated_at_epoch_seconds: Optional[float] = None,
) -> TenantExportBundle:
    """Validate exclusion-by-construction and bind exported record classes + policy to a digest."""
    if not isinstance(authorized_tenant_tag, str) or not _TENANT_TAG_RE.match(authorized_tenant_tag):
        raise ValueError("authorized_tenant_tag must be a valid non-empty tenant tag")
    if not isinstance(records_by_class, Mapping) or not records_by_class:
        raise ValueError("records_by_class must be a non-empty mapping")

    policy_binding = redaction_policy if redaction_policy is not None else RedactionPolicyBinding.build()
    rebuilt_policy = RedactionPolicyBinding.build(
        redaction_version=policy_binding.redaction_version,
        excluded_categories=policy_binding.excluded_categories,
        cap_bytes=policy_binding.cap_bytes,
    )
    if not hmac.compare_digest(rebuilt_policy.policy_digest, policy_binding.policy_digest):
        raise ManifestVerificationError("supplied redaction_policy has an invalid policy_digest")

    validated_map: Dict[str, List[Dict[str, Any]]] = {}
    class_bindings: List[ExportedRecordClassBinding] = []

    for class_name in sorted(records_by_class.keys()):
        clean_records = assert_class_records_safe_by_construction(
            class_name,
            records_by_class[class_name],
        )
        binding, _ = _build_class_binding(class_name, clean_records)
        validated_map[class_name] = clean_records
        class_bindings.append(binding)

    tenant_digest = _hash_tenant_subject(authorized_tenant_tag)
    now = float(generated_at_epoch_seconds) if generated_at_epoch_seconds is not None else time.time()
    bindings_tuple = tuple(class_bindings)
    manifest_digest = _compute_manifest_digest(
        schema_version=TENANT_MANIFEST_SCHEMA_VERSION,
        tenant_tag_digest=tenant_digest,
        redaction_policy=policy_binding,
        record_classes=bindings_tuple,
    )
    manifest_id = "tem-v1:" + hashlib.sha256(os.urandom(24) + manifest_digest.encode("ascii")).hexdigest()[:16]

    manifest = TenantExportManifest(
        manifest_id=manifest_id,
        schema_version=TENANT_MANIFEST_SCHEMA_VERSION,
        domain_tag=TENANT_EXPORT_MANIFEST_DOMAIN_TAG,
        tenant_tag_digest=tenant_digest,
        generated_at_epoch_seconds=now,
        redaction_policy=policy_binding,
        record_classes=bindings_tuple,
        manifest_digest=manifest_digest,
    )
    return TenantExportBundle(manifest=manifest, records_by_class=validated_map)


def verify_tenant_export_manifest(
    manifest: TenantExportManifest,
    records_by_class: Mapping[str, Sequence[Mapping[str, Any]]],
    *,
    expected_redaction_policy: Optional[RedactionPolicyBinding] = None,
    expected_tenant_tag: Optional[str] = None,
    raise_on_error: bool = False,
) -> bool:
    """Fail-closed verifier checking exclusion invariants, class digests, policy digest, and manifest digest."""

    def _fail(reason: str) -> bool:
        if raise_on_error:
            raise ManifestVerificationError(reason)
        return False

    if not isinstance(manifest, TenantExportManifest):
        return _fail("manifest must be a TenantExportManifest")
    if manifest.schema_version != TENANT_MANIFEST_SCHEMA_VERSION:
        return _fail("unsupported manifest schema_version")
    if manifest.domain_tag != TENANT_EXPORT_MANIFEST_DOMAIN_TAG:
        return _fail("unexpected manifest domain_tag")
    if not _SHA256_HEX_RE.match(manifest.tenant_tag_digest) or not _SHA256_HEX_RE.match(
        manifest.manifest_digest
    ):
        return _fail("malformed digest format on manifest")

    if expected_tenant_tag is not None:
        if not isinstance(expected_tenant_tag, str) or not _TENANT_TAG_RE.match(expected_tenant_tag):
            return _fail("invalid expected_tenant_tag")
        expected_sub_digest = _hash_tenant_subject(expected_tenant_tag)
        if not hmac.compare_digest(expected_sub_digest, manifest.tenant_tag_digest):
            return _fail("tenant_tag_digest mismatch")

    try:
        rebuilt_policy = RedactionPolicyBinding.build(
            redaction_version=manifest.redaction_policy.redaction_version,
            excluded_categories=manifest.redaction_policy.excluded_categories,
            cap_bytes=manifest.redaction_policy.cap_bytes,
        )
    except Exception as exc:
        return _fail(f"invalid redaction_policy binding: {type(exc).__name__}")

    if not hmac.compare_digest(
        rebuilt_policy.policy_digest, manifest.redaction_policy.policy_digest
    ) or not hmac.compare_digest(
        rebuilt_policy.class_allowlists_digest, manifest.redaction_policy.class_allowlists_digest
    ):
        return _fail("redaction policy digest verification failed")

    if expected_redaction_policy is not None:
        if not hmac.compare_digest(
            expected_redaction_policy.policy_digest, manifest.redaction_policy.policy_digest
        ):
            return _fail("manifest redaction policy does not match expected policy")

    if not isinstance(records_by_class, Mapping):
        return _fail("records_by_class must be a mapping")

    manifest_class_names = [rc.class_name for rc in manifest.record_classes]
    if manifest_class_names != sorted(manifest_class_names) or len(set(manifest_class_names)) != len(
        manifest_class_names
    ):
        return _fail("manifest record_classes must be uniquely sorted")

    if sorted(records_by_class.keys()) != manifest_class_names:
        return _fail("exported record classes do not match manifest class bindings")

    for rc in manifest.record_classes:
        try:
            clean_records = assert_class_records_safe_by_construction(
                rc.class_name,
                records_by_class[rc.class_name],
            )
        except ExportMaterialExclusionError as exc:
            return _fail(f"unsafe material in class {rc.class_name}: {exc}")

        recomputed_binding, _ = _build_class_binding(rc.class_name, clean_records)
        if rc.schema_allowlist != recomputed_binding.schema_allowlist:
            return _fail(f"schema allowlist mismatch for class {rc.class_name}")
        if rc.record_count != recomputed_binding.record_count:
            return _fail(f"record_count mismatch for class {rc.class_name}")
        if rc.payload_bytes != recomputed_binding.payload_bytes:
            return _fail(f"payload_bytes mismatch for class {rc.class_name}")
        if not hmac.compare_digest(rc.records_sha256, recomputed_binding.records_sha256):
            return _fail(f"records_sha256 mismatch for class {rc.class_name}")

    expected_manifest_digest = _compute_manifest_digest(
        schema_version=manifest.schema_version,
        tenant_tag_digest=manifest.tenant_tag_digest,
        redaction_policy=manifest.redaction_policy,
        record_classes=manifest.record_classes,
    )
    if not hmac.compare_digest(expected_manifest_digest, manifest.manifest_digest):
        return _fail("top-level manifest_digest mismatch")

    return True


def _project_safe_operational_telemetry(entry: LogEntry) -> Dict[str, Any]:
    safe_labels: Dict[str, str] = {}
    for lk, lv in sorted((entry.labels or {}).items()):
        if isinstance(lk, str) and isinstance(lv, str):
            try:
                _inspect_value_for_forbidden_material({lk: lv}, field_context="labels")
                safe_labels[lk] = lv
            except ExportMaterialExclusionError:
                continue
    safe_counters: Dict[str, int] = {}
    for ck, cv in sorted((entry.counters or {}).items()):
        if isinstance(ck, str) and not isinstance(cv, bool) and isinstance(cv, int):
            try:
                _inspect_value_for_forbidden_material({ck: cv}, field_context="counters")
                safe_counters[ck] = cv
            except ExportMaterialExclusionError:
                continue

    return {
        "schema_version": entry.schema_version,
        "event_name": entry.event_name,
        "category": entry.category,
        "severity": entry.severity,
        "timestamp_epoch_seconds": float(entry.timestamp_epoch_seconds),
        "endpoint_pattern": entry.endpoint_pattern,
        "method": entry.method,
        "status_code": entry.status_code,
        "operation_status": entry.operation_status,
        "lifecycle_state": entry.lifecycle_state,
        "duration_seconds": entry.duration_seconds,
        "labels": safe_labels,
        "counters": safe_counters,
    }


def _project_safe_export_audit(artifact: ExportArtifact) -> Dict[str, Any]:
    return {
        "artifact_id": artifact.artifact_id,
        "schema_version": artifact.schema_version,
        "generated_at_epoch_seconds": float(artifact.generated_at_epoch_seconds),
        "entry_count": int(artifact.entry_count),
        "payload_bytes": int(artifact.payload_bytes),
        "compress": bool(artifact.compress),
        "payload_type": artifact.payload_type,
        "rollout_phase": artifact.rollout_phase,
        "redaction_version": artifact.redaction_version,
        "checksum_sha256_prefix16": artifact.checksum_sha256_prefix16,
    }


@dataclass
class ExportPolicy:
    max_artifacts_per_export: int = 64
    max_artifact_bytes: int = 4_194_304
    compress_default: bool = False
    include_sampled_out_events: bool = False
    include_debug_fields: bool = False
    require_export_token: bool = True
    allow_unauthenticated_export_shadow_mode: bool = True
    export_id_prefix: str = "exp-v1:"
    require_safety_signature: bool = True
    safety_signature_prefix: str = "sig-v1:"
    redaction_version: str = CRYPTO_DOMAIN_VERSION


EXPORT_POLICY_DEFAULT: ExportPolicy = ExportPolicy()


@dataclass
class ExportArtifact:
    artifact_id: str
    schema_version: str = EXPORT_FORMAT_VERSION
    generated_at_epoch_seconds: float = 0.0
    entry_count: int = 0
    payload_bytes: int = 0
    compress: bool = False
    exported_by_tag: Optional[str] = None
    safety_signature: Optional[str] = None
    checksum_sha256_prefix16: Optional[str] = None
    payload_type: str = "application/json"
    rollout_phase: str = "shadow"
    redaction_version: str = "harpocrates-redaction-v1"
    encryption_at_rest: bool = False


class ExportManager:
    def __init__(
        self,
        policy: Optional[ExportPolicy] = None,
        processor: Optional[LogProcessor] = None,
        max_artifacts_memory: int = 1024,
        *,
        consent_manager: Optional[ConsentManager] = None,
    ) -> None:
        self._lock: threading.RLock = threading.RLock()
        self._artifacts: Dict[str, ExportArtifact] = {}
        self._artifact_queue: List[str] = []
        self._policy: ExportPolicy = policy if policy is not None else EXPORT_POLICY_DEFAULT
        if processor is not None:
            self._processor: LogProcessor = processor
        elif LogProcessor is not None:
            self._processor = LogProcessor()
        else:
            self._processor = None
        self._max_artifacts_memory: int = max_artifacts_memory
        self._consent_manager: Optional[ConsentManager] = consent_manager

    def create_tenant_export_bundle(
        self,
        authorized_tenant_tag: str,
        *,
        export_token_verified: bool = True,
        include_classes: Optional[Sequence[str]] = None,
        generated_at_epoch_seconds: Optional[float] = None,
    ) -> TenantExportBundle:
        """Construct a verifiable tenant export bundle excluding evidence and credentials by construction."""
        if not export_token_verified:
            raise PermissionError("export_token_verified=True is required for tenant data exports")
        if not isinstance(authorized_tenant_tag, str) or not _TENANT_TAG_RE.match(authorized_tenant_tag):
            raise ValueError("authorized_tenant_tag must be a valid non-empty tenant tag")

        selected = (
            sorted(set(include_classes))
            if include_classes is not None
            else sorted(ALLOWED_TENANT_EXPORT_CLASSES)
        )
        if not selected:
            raise ValueError("at least one record class must be selected")
        for cls_name in selected:
            if cls_name not in ALLOWED_TENANT_EXPORT_CLASSES:
                raise ExportMaterialExclusionError(f"disallowed tenant export record class: {cls_name!r}")

        records_by_class: Dict[str, List[Dict[str, Any]]] = {}

        if "consent_posture" in selected:
            if self._consent_manager is not None:
                records_by_class["consent_posture"] = (
                    self._consent_manager.project_safe_tenant_consent_records(authorized_tenant_tag)
                )
            else:
                records_by_class["consent_posture"] = []

        if "operational_telemetry" in selected:
            telemetry_rows: List[Dict[str, Any]] = []
            if self._processor is not None:
                with self._processor._lock:
                    raw_entries = list(self._processor._entries[:])
                for entry in sorted(raw_entries, key=lambda e: (e.timestamp_epoch_seconds, e.entry_id)):
                    if entry.account_id_tag is None:
                        continue
                    if not hmac.compare_digest(
                        entry.account_id_tag.encode("utf-8"),
                        authorized_tenant_tag.encode("utf-8"),
                    ):
                        continue
                    if not entry.export_safe:
                        continue
                    if validate_log_export_safety is not None and not validate_log_export_safety(entry)[0]:
                        continue
                    telemetry_rows.append(_project_safe_operational_telemetry(entry))
                    if len(telemetry_rows) >= self._policy.max_artifacts_per_export:
                        break
            records_by_class["operational_telemetry"] = telemetry_rows

        if "export_audit_metadata" in selected:
            audit_rows: List[Dict[str, Any]] = []
            with self._lock:
                for aid in self._artifact_queue:
                    art = self._artifacts.get(aid)
                    if art is None or art.exported_by_tag is None:
                        continue
                    if not hmac.compare_digest(
                        art.exported_by_tag.encode("utf-8"),
                        authorized_tenant_tag.encode("utf-8"),
                    ):
                        continue
                    audit_rows.append(_project_safe_export_audit(art))
            records_by_class["export_audit_metadata"] = audit_rows

        policy_binding = RedactionPolicyBinding.build(
            redaction_version=self._policy.redaction_version,
        )
        return build_tenant_export_manifest(
            authorized_tenant_tag,
            records_by_class,
            redaction_policy=policy_binding,
            generated_at_epoch_seconds=generated_at_epoch_seconds,
        )

    def generate_export_id(self) -> str:
        random_bytes = os.urandom(32)
        timestamp = str(time.time()).encode("utf-8")
        raw = random_bytes + timestamp
        digest = hashlib.sha256(raw).hexdigest()[:16]
        return self._policy.export_id_prefix + digest

    def compute_safety_signature(self, entries: List[LogEntry]) -> str:
        sorted_entries = sorted(entries, key=lambda x: x.entry_id)
        parts = []
        for e in sorted_entries:
            sig = e.export_signature or "0"
            parts.append(e.entry_id + ":" + sig)
        payload = "|".join(parts)
        digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:12]
        return self._policy.safety_signature_prefix + digest

    def create_export(
        self,
        entries: Optional[List[LogEntry]] = None,
        exported_by_tag: Optional[str] = None,
        compress: Optional[bool] = None,
        rollout_phase: str = "shadow",
        export_token_verified: bool = False,
    ) -> Tuple[Optional[ExportArtifact], str, int]:
        with self._lock:
            policy = self._policy
            if not export_token_verified and policy.require_export_token and not policy.allow_unauthenticated_export_shadow_mode:
                return None, "export_token_required", 0
            if entries is not None:
                entries_filtered = list(entries)
            elif self._processor is not None:
                entries_filtered = list(self._processor._entries[:])
            else:
                entries_filtered = []
            if not policy.include_sampled_out_events:
                entries_filtered = [e for e in entries_filtered if e.export_safe]
            if validate_log_export_safety is not None:
                entries_filtered = [e for e in entries_filtered if validate_log_export_safety(e)[0]]
            if policy.require_safety_signature:
                all_safe = all(e.export_safe for e in entries_filtered)
                if not all_safe:
                    safety_sig = None
                else:
                    safety_sig = self.compute_safety_signature(entries_filtered)
            else:
                safety_sig = None
            if not export_token_verified:
                entries_filtered = []
            entries_filtered = entries_filtered[:policy.max_artifacts_per_export]
            use_compress = compress if compress is not None else policy.compress_default
            if self._processor is not None:
                serialized, count = self._processor.export_json_logs(
                    entries=entries_filtered,
                    compress=use_compress,
                    max_entries=policy.max_artifacts_per_export,
                    max_bytes=policy.max_artifact_bytes,
                )
            else:
                serialized = "[]"
                count = 0
            payload_bytes = len(serialized.encode("utf-8"))
            checksum = hashlib.sha256(serialized.encode("utf-8")).hexdigest()[:16]
            artifact_id = self.generate_export_id()
            artifact = ExportArtifact(
                artifact_id=artifact_id,
                generated_at_epoch_seconds=time.time(),
                entry_count=count,
                payload_bytes=payload_bytes,
                compress=use_compress,
                exported_by_tag=exported_by_tag if export_token_verified else None,
                safety_signature=safety_sig,
                checksum_sha256_prefix16=checksum,
                rollout_phase=rollout_phase,
                redaction_version=policy.redaction_version,
                encryption_at_rest=False,
            )
            if len(self._artifacts) >= self._max_artifacts_memory:
                if self._artifact_queue:
                    oldest_id = self._artifact_queue.pop(0)
                    self._artifacts.pop(oldest_id, None)
            self._artifacts[artifact_id] = artifact
            self._artifact_queue.append(artifact_id)
            return artifact, serialized, count

    def get_artifact(self, artifact_id: str) -> Optional[ExportArtifact]:
        with self._lock:
            return self._artifacts.get(artifact_id)

    def list_artifacts(self, limit: int = 50) -> List[ExportArtifact]:
        with self._lock:
            result: List[ExportArtifact] = []
            for aid in reversed(self._artifact_queue):
                if len(result) >= limit:
                    break
                art = self._artifacts.get(aid)
                if art is not None:
                    result.append(art)
            return result

    def delete_artifact(self, artifact_id: str) -> bool:
        with self._lock:
            if artifact_id in self._artifacts:
                self._artifacts.pop(artifact_id, None)
                self._artifact_queue = [aid for aid in self._artifact_queue if aid != artifact_id]
                return True
            return False

    def reset(self) -> None:
        with self._lock:
            self._artifacts.clear()
            self._artifact_queue.clear()
