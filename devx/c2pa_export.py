#!/usr/bin/env python3
"""Export C2PA authenticity assertions from a Harpocrates proof manifest.

This is fail-closed developer-experience / release tooling.  It consumes the
exact public proof-manifest JSON emitted by ``harpocrates manifest`` (see
``cli/src/manifest.ts``) and produces a deterministic, C2PA (Content
Credentials) shaped manifest whose assertions are derived *only* from public
fields.

Privacy contract
----------------
The exporter never reads media, and never emits witnesses, nullifiers,
per-session device keys, credentials, API keys, or private keys.  Any input
that contains a field whose name looks like secret material is rejected
outright instead of being copied or logged, so a mistakenly supplied proof
package can never leak through this boundary.  Error messages are stable and
contain only an error code and a fixed description -- never input values.

The emitted object deliberately has ``signature: null``: exporting assertions
is not signing.  A C2PA claim signature is attached by a signer with a private
key, which is out of scope and must never happen in this repository.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any, Mapping

ROOT = Path(__file__).resolve().parents[1]

# ── Protocol / format constants ────────────────────────────────────────────

PROFILE_ID = "harpocrates-c2pa-export/v1"
EXPORT_VERSION = 1
CLAIM_GENERATOR = "harpocrates-devx/1.0.0"
CLAIM_GENERATOR_NAME = "Harpocrates"
CLAIM_GENERATOR_VERSION = "1.0.0"
C2PA_SPEC_VERSION = "2.1"

DIGITAL_CAPTURE_SOURCE_TYPE = (
    "http://cv.iptc.org/newscodes/digitalsourcetype/digitalCapture"
)

# Assertion labels.  ``c2pa.*`` labels use the standard namespace; everything
# Harpocrates-specific is namespaced under ``org.harpocrates.*`` so no custom
# assertion can shadow a future standard label.
LABEL_ACTIONS = "c2pa.actions"
LABEL_VERIFICATION = "org.harpocrates.verification"
LABEL_EVIDENCE_BINDING = "org.harpocrates.evidence-binding"
REQUIRED_ASSERTION_LABELS = (LABEL_ACTIONS, LABEL_VERIFICATION, LABEL_EVIDENCE_BINDING)

# ── Bounds ─────────────────────────────────────────────────────────────────

# Matches the release compatibility manifest cap so one bundle cannot become a
# memory or log amplification vector.
MAX_INPUT_BYTES = 256 * 1024
MAX_EXPORT_BYTES = 256 * 1024
MAX_TITLE_LENGTH = 256

ALLOWED_TIERS = frozenset({"silent", "source", "seal"})
SUPPORTED_MEDIA_TYPES = frozenset(
    {
        "application/octet-stream",
        "image/jpeg",
        "image/png",
        "image/webp",
        "video/mp4",
        "video/quicktime",
    }
)

# Verification states that permit a *positive* authenticity assertion.
AFFIRMATIVE_STATES = frozenset({"valid", "pending"})
# States that must fail closed rather than emit an authenticity claim.
NEGATIVE_STATES = frozenset({"expired", "revoked"})
# Any other known failure to bind to chain evidence is a dependency failure.
DEPENDENCY_STATES = frozenset(
    {"not_found", "failed", "error", "network_mismatch", "contract_mismatch"}
)

HEX_256 = re.compile(r"^[0-9a-fA-F]{64}$")
ISO_8601 = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$"
)

# Field names that must never enter, or be copied out of, the export boundary.
_SENSITIVE_KEY = re.compile(
    r"(seed|secret|private|witness|nullifier|credential|password|passphrase"
    r"|api[_-]?key|mnemonic|device[_-]?key|signing[_-]?key)",
    re.IGNORECASE,
)

REQUIRED_HEX_FIELDS = ("proofId", "sourceHash", "metadataHash", "transactionRef")
REQUIRED_STRING_FIELDS = ("network", "contractId", "timestamp", "tier", "protocol")


# ── Error taxonomy ─────────────────────────────────────────────────────────


class C2PAExportError(ValueError):
    """Stable, privacy-safe export failure.

    ``code`` is one of ``malformed``, ``oversized``, ``unsupported``,
    ``expired``, ``revoked`` or ``dependency_failure``.  The message never
    includes caller-supplied values.
    """

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(f"{code}: {message}")


def _fail(code: str, message: str) -> None:
    raise C2PAExportError(code, message)


# ── Canonicalisation helpers ───────────────────────────────────────────────


def canonical_json_bytes(value: Any) -> bytes:
    """Serialise a JSON value deterministically (sorted keys, compact)."""
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


def _digest(value: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


# ── Validation ─────────────────────────────────────────────────────────────


def _scan_for_sensitive_fields(value: Any, depth: int = 0) -> None:
    """Reject any input that carries secret-looking field names.

    Only key names are inspected; values are never read, logged, or copied.
    Depth is bounded so a hostile input cannot cause unbounded recursion.
    """
    if depth > 32:
        _fail("malformed", "input nesting exceeds the allowed depth")
    if isinstance(value, Mapping):
        for key, child in value.items():
            if isinstance(key, str) and _SENSITIVE_KEY.search(key):
                _fail("unsupported", "input contains a prohibited sensitive field")
            _scan_for_sensitive_fields(child, depth + 1)
    elif isinstance(value, (list, tuple)):
        for child in value:
            _scan_for_sensitive_fields(child, depth + 1)


def _validate_proof_manifest(manifest: Mapping[str, Any]) -> None:
    for field in REQUIRED_STRING_FIELDS:
        if not isinstance(manifest.get(field), str) or not manifest[field]:
            _fail("malformed", f"proof manifest requires a non-empty {field}")

    if manifest["protocol"] != "harpocrates":
        _fail("unsupported", "proof manifest protocol is not supported")

    version = manifest.get("version")
    if not isinstance(version, int) or isinstance(version, bool):
        _fail("malformed", "proof manifest version must be an integer")
    if version != 1:
        _fail("unsupported", "only proof manifest version 1 is supported")

    if manifest["tier"] not in ALLOWED_TIERS:
        _fail("unsupported", "proof manifest tier is not supported")

    for field in REQUIRED_HEX_FIELDS:
        value = manifest.get(field)
        if not isinstance(value, str) or not HEX_256.fullmatch(value):
            _fail("malformed", f"proof manifest {field} must be 32-byte hex")

    video_hash = manifest.get("videoHash")
    if video_hash not in (None, "") and (
        not isinstance(video_hash, str) or not HEX_256.fullmatch(video_hash)
    ):
        _fail("malformed", "proof manifest videoHash must be 32-byte hex")

    if not ISO_8601.fullmatch(manifest["timestamp"]):
        _fail("malformed", "proof manifest timestamp must be ISO-8601")


def _resolve_verification(verification: str) -> str:
    if not isinstance(verification, str):
        _fail("malformed", "verification status must be a string")
    if verification in NEGATIVE_STATES:
        # Fail closed: never assert authenticity for expired or revoked evidence.
        _fail(verification, f"evidence is {verification}")
    if verification in DEPENDENCY_STATES:
        _fail("dependency_failure", "chain evidence could not be bound")
    if verification not in AFFIRMATIVE_STATES:
        _fail("unsupported", "verification status is not supported")
    return verification


def _resolve_media_type(media_type: str | None) -> str:
    if media_type is None:
        return "application/octet-stream"
    if not isinstance(media_type, str) or media_type not in SUPPORTED_MEDIA_TYPES:
        _fail("unsupported", "media type is not supported")
    return media_type


def _resolve_title(title: str | None, proof_id: str) -> str:
    if title is None:
        return f"Harpocrates evidence {proof_id[:16]}"
    if not isinstance(title, str) or not title:
        _fail("malformed", "title must be a non-empty string")
    if len(title) > MAX_TITLE_LENGTH:
        _fail("oversized", "title exceeds the allowed length")
    return title


# ── Export ─────────────────────────────────────────────────────────────────


def build_actions_assertion(manifest: Mapping[str, Any], verification: str) -> dict[str, Any]:
    """Build the standard ``c2pa.actions`` assertion for the evidence."""
    action: dict[str, Any] = {
        "action": "c2pa.created",
        "when": manifest["timestamp"],
        "softwareAgent": CLAIM_GENERATOR,
    }
    if verification == "valid":
        action["digitalSourceType"] = DIGITAL_CAPTURE_SOURCE_TYPE
    return {"label": LABEL_ACTIONS, "data": {"actions": [action]}}


def build_verification_assertion(
    manifest: Mapping[str, Any], verification: str
) -> dict[str, Any]:
    """Build the ``org.harpocrates.verification`` assertion (public chain data)."""
    return {
        "label": LABEL_VERIFICATION,
        "data": {
            "status": verification,
            "authenticity": "asserted" if verification == "valid" else "pending",
            "protocol": manifest["protocol"],
            "protocolVersion": manifest["version"],
            "tier": manifest["tier"],
            "network": manifest["network"],
            "contractId": manifest["contractId"],
            "transactionRef": manifest["transactionRef"].lower(),
            "timestamp": manifest["timestamp"],
        },
    }


def build_evidence_binding_assertion(manifest: Mapping[str, Any]) -> dict[str, Any]:
    """Build the ``org.harpocrates.evidence-binding`` assertion (hashes only)."""
    video_hash = manifest.get("videoHash") or None
    return {
        "label": LABEL_EVIDENCE_BINDING,
        "data": {
            "algorithm": "sha256",
            "proofId": manifest["proofId"].lower(),
            "sourceHash": manifest["sourceHash"].lower(),
            "metadataHash": manifest["metadataHash"].lower(),
            "videoHash": video_hash.lower() if video_hash else None,
        },
    }


def export_manifest(
    proof_manifest: Mapping[str, Any],
    *,
    verification: str = "valid",
    title: str | None = None,
    media_type: str | None = None,
) -> dict[str, Any]:
    """Export a deterministic C2PA manifest of authenticity assertions.

    Raises :class:`C2PAExportError` with a stable ``code`` for malformed,
    oversized, unsupported, expired, revoked, or dependency-failure inputs.
    """
    if not isinstance(proof_manifest, Mapping):
        _fail("malformed", "proof manifest must be a JSON object")

    try:
        encoded_input = canonical_json_bytes(proof_manifest)
    except (TypeError, ValueError):
        _fail("malformed", "proof manifest is not JSON serialisable")
    if len(encoded_input) > MAX_INPUT_BYTES:
        _fail("oversized", "proof manifest exceeds the allowed size")

    _scan_for_sensitive_fields(proof_manifest)
    _validate_proof_manifest(proof_manifest)

    resolved_verification = _resolve_verification(verification)
    resolved_media_type = _resolve_media_type(media_type)
    resolved_title = _resolve_title(title, proof_manifest["proofId"])

    assertions = [
        build_actions_assertion(proof_manifest, resolved_verification),
        build_evidence_binding_assertion(proof_manifest),
        build_verification_assertion(proof_manifest, resolved_verification),
    ]

    instance_id = "xmp:iid:" + _digest(
        {"proofId": proof_manifest["proofId"].lower(), "contractId": proof_manifest["contractId"]}
    )

    exported: dict[str, Any] = {
        "claim_generator": CLAIM_GENERATOR,
        "claim_generator_info": [
            {"name": CLAIM_GENERATOR_NAME, "version": CLAIM_GENERATOR_VERSION}
        ],
        "dc:title": resolved_title,
        "format": resolved_media_type,
        "instance_id": instance_id,
        "profile": PROFILE_ID,
        "export_version": EXPORT_VERSION,
        "c2pa_spec_version": C2PA_SPEC_VERSION,
        "assertions": assertions,
        "assertions_digest": _digest(assertions),
        # Exporting assertions is not signing; no private key is ever touched.
        "signature": None,
        "signing": {
            "status": "unsigned",
            "note": "Import into a C2PA signer to attach a claim signature.",
        },
    }

    if len(canonical_json_bytes(exported)) > MAX_EXPORT_BYTES:
        _fail("oversized", "exported manifest exceeds the allowed size")

    return exported


def serialize_export(exported: Mapping[str, Any]) -> str:
    """Deterministically serialise an exported manifest to JSON text."""
    return canonical_json_bytes(exported).decode("utf-8")


def load_proof_manifest(source: str | Path | Mapping[str, Any]) -> Mapping[str, Any]:
    """Load a proof manifest from a path, JSON string, or mapping."""
    if isinstance(source, Mapping):
        return source
    if isinstance(source, Path):
        raw = source.read_text(encoding="utf-8")
    elif isinstance(source, str):
        candidate = Path(source)
        raw = candidate.read_text(encoding="utf-8") if candidate.exists() else source
    else:
        _fail("malformed", "proof manifest source is not supported")
    try:
        value = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        _fail("malformed", "proof manifest is not valid JSON")
    if not isinstance(value, Mapping):
        _fail("malformed", "proof manifest must be a JSON object")
    return value


def verify_export(exported: Mapping[str, Any]) -> None:
    """Re-validate an exported manifest and detect assertion tampering."""
    if not isinstance(exported, Mapping):
        _fail("malformed", "export must be a JSON object")
    if exported.get("profile") != PROFILE_ID:
        _fail("unsupported", "export profile is not supported")
    if exported.get("export_version") != EXPORT_VERSION:
        _fail("unsupported", "export version is not supported")

    assertions = exported.get("assertions")
    if not isinstance(assertions, list):
        _fail("malformed", "export assertions must be an array")

    labels = {
        assertion.get("label")
        for assertion in assertions
        if isinstance(assertion, Mapping)
    }
    for label in REQUIRED_ASSERTION_LABELS:
        if label not in labels:
            _fail("malformed", "export is missing a required assertion")

    if _digest(assertions) != exported.get("assertions_digest"):
        _fail("malformed", "export assertion digest mismatch")


# ── CLI ────────────────────────────────────────────────────────────────────


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="export C2PA authenticity assertions from a Harpocrates proof manifest"
    )
    parser.add_argument(
        "--manifest",
        required=True,
        help="path to a Harpocrates proof manifest JSON file",
    )
    parser.add_argument(
        "--result",
        default="valid",
        help="verification status: valid (default), pending, expired, revoked, ...",
    )
    parser.add_argument("--title", default=None, help="optional C2PA title")
    parser.add_argument(
        "--media-type",
        default=None,
        help="optional IANA media type (for example video/mp4)",
    )
    parser.add_argument(
        "--output", type=Path, default=None, help="write the export to a file"
    )
    parser.add_argument(
        "--verify",
        action="store_true",
        help="re-validate an existing export instead of producing one",
    )
    args = parser.parse_args(argv)

    try:
        source = Path(args.manifest)
        if args.verify:
            exported = load_proof_manifest(source)
            verify_export(exported)
            print("c2pa export verified: assertions and digest are intact")
            return 0

        proof_manifest = load_proof_manifest(source)
        exported = export_manifest(
            proof_manifest,
            verification=args.result,
            title=args.title,
            media_type=args.media_type,
        )
        rendered = serialize_export(exported)
    except C2PAExportError as exc:
        print(f"c2pa export failed: {exc}", file=sys.stderr)
        return 1
    except OSError:
        print("c2pa export failed: malformed: manifest could not be read", file=sys.stderr)
        return 1

    if args.output is not None:
        args.output.write_text(rendered + "\n", encoding="utf-8")
        print(f"c2pa export written to {args.output}")
    else:
        print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
