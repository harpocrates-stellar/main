"""Validation for the canonical verification-receipt input contract.

The frontend owns receipt versioning and signing. The backend only returns the
same unsigned input shape, so there is one protocol contract and no second
backend-specific receipt envelope.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal, Mapping, TypedDict

try:
    from time_attestation import (
        TimeAttestation,
        check_backdating_risk,
        decode_time_attestation,
        encode_time_attestation,
    )
except ImportError:  # pragma: no cover - package layout fallback
    from backend.time_attestation import (  # type: ignore[no-redef]
        TimeAttestation,
        check_backdating_risk,
        decode_time_attestation,
        encode_time_attestation,
    )


DiffCategory = Literal["evidence", "trust", "revocation", "chain", "presentation"]


class ReceiptDiffItem(TypedDict):
    """Single categorized difference between two verification runs."""

    field: str
    category: DiffCategory
    before: Any
    after: Any
    explanation: str


class ReceiptComparisonReport(TypedDict):
    """Structured comparison report for two verification runs."""

    identical: bool
    equivalentEvidence: bool
    presentationOnly: bool
    summary: str
    evidenceChanges: list[ReceiptDiffItem]
    trustChanges: list[ReceiptDiffItem]
    revocationChanges: list[ReceiptDiffItem]
    chainChanges: list[ReceiptDiffItem]
    presentationChanges: list[ReceiptDiffItem]
    explanations: list[str]


class VerificationReceiptInput(TypedDict):
    """Unsigned fields consumed by the frontend receipt signer."""

    result: Literal["verified", "unverified"]
    verifiedAt: str
    proofId: str
    videoHash: str
    metadataHash: str
    tier: Literal["silent", "source", "seal"]
    networkPassphrase: str
    contractId: str
    ledgerSequence: int | None
    transactionHash: str | None
    circuitVersion: str
    verifierVersion: str


# Receipt metadata extensions are keyed by name. A key prefixed with "critical:"
# marks an extension the verifier MUST understand; unknown critical extensions
# cause the receipt to be rejected (fail closed). Non-critical (optional)
# extensions are preserved verbatim so they survive round trips.
CRITICAL_EXTENSION_PREFIX = "critical:"

# Critical extensions this verifier implements. Empty today: any critical
# extension is unsupported and must be rejected.
SUPPORTED_CRITICAL_EXTENSIONS: frozenset[str] = frozenset()


def build_verification_receipt(
    context: Mapping[str, object],
    *,
    result: Literal["verified", "unverified"] = "unverified",
) -> VerificationReceiptInput:
    """Validate and build the canonical unsigned receipt input.

    A receipt is only emitted when the caller supplies the complete canonical
    evidence context. This prevents the selective-disclosure endpoint from
    inventing proof IDs or hashes from unrelated request fields.

    Any metadata extensions present in ``context['extensions']`` are checked:
    unknown critical extensions are rejected, while optional extensions are
    preserved in the returned mapping under ``extensions``.
    """

    receipt: VerificationReceiptInput = {
        "result": result,
        "verifiedAt": datetime.now(timezone.utc).isoformat(),
        "proofId": _hex32(context.get("proofId"), "proofId"),
        "videoHash": _hex32(context.get("videoHash"), "videoHash"),
        "metadataHash": _hex32(context.get("metadataHash"), "metadataHash"),
        "tier": _choice(context.get("tier"), "tier", ("silent", "source", "seal")),
        "networkPassphrase": _text(context.get("networkPassphrase"), "networkPassphrase"),
        "contractId": _text(context.get("contractId"), "contractId"),
        "ledgerSequence": _optional_int(context.get("ledgerSequence"), "ledgerSequence"),
        "transactionHash": _optional_hex32(context.get("transactionHash"), "transactionHash"),
        "circuitVersion": _text(context.get("circuitVersion"), "circuitVersion"),
        "verifierVersion": _text(context.get("verifierVersion"), "verifierVersion"),
    }
    extensions = _extensions(context.get("extensions"))
    if extensions:
        receipt["extensions"] = extensions  # type: ignore[typeddict-unknown-key]
    return receipt


def _extensions(value: object) -> dict[str, object]:
    """Validate receipt metadata extensions, failing closed on unknown critical ones."""

    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise ValueError("extensions must be a mapping or null")
    preserved: dict[str, object] = {}
    for key, item in value.items():
        if not isinstance(key, str) or not key.strip():
            raise ValueError("extension names must be non-empty strings")
        if key.startswith(CRITICAL_EXTENSION_PREFIX):
            if key not in SUPPORTED_CRITICAL_EXTENSIONS:
                raise ValueError(f"unsupported critical extension: {key}")
        preserved[key] = item
    return preserved


def _text(value: object, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be a non-empty string")
    return value


def _hex32(value: object, field: str) -> str:
    if not isinstance(value, str) or len(value) != 64:
        raise ValueError(f"{field} must be a 32-byte hex string")
    try:
        int(value, 16)
    except ValueError as exc:
        raise ValueError(f"{field} must be a 32-byte hex string") from exc
    return value.lower()


def _optional_hex32(value: object, field: str) -> str | None:
    if value is None:
        return None
    return _hex32(value, field)


def _optional_int(value: object, field: str) -> int | None:
    if value is None:
        return None
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ValueError(f"{field} must be a non-negative integer or null")
    return value


def _choice(value: object, field: str, choices: tuple[str, ...]) -> str:
    if value not in choices:
        raise ValueError(f"{field} must be one of: {', '.join(choices)}")
    return value


_PRESENTATION_ENVELOPE_FIELDS: tuple[str, ...] = (
    "protocol",
    "version",
    "signature",
    "signedAt",
    "format",
)

_HEX_FIELDS: tuple[str, ...] = (
    "proofId",
    "videoHash",
    "metadataHash",
    "transactionHash",
)


def _validate_receipt_for_comparison(
    receipt: Mapping[str, object],
    label: str,
) -> VerificationReceiptInput:
    """Fail-closed validation of canonical receipt fields prior to comparison."""

    if not isinstance(receipt, Mapping):
        raise ValueError(f"{label} receipt must be a mapping")

    try:
        return {
            "result": _choice(receipt.get("result"), "result", ("verified", "unverified")),
            "verifiedAt": _text(receipt.get("verifiedAt"), "verifiedAt"),
            "proofId": _hex32(receipt.get("proofId"), "proofId"),
            "videoHash": _hex32(receipt.get("videoHash"), "videoHash"),
            "metadataHash": _hex32(receipt.get("metadataHash"), "metadataHash"),
            "tier": _choice(receipt.get("tier"), "tier", ("silent", "source", "seal")),
            "networkPassphrase": _text(
                receipt.get("networkPassphrase"), "networkPassphrase"
            ),
            "contractId": _text(receipt.get("contractId"), "contractId"),
            "ledgerSequence": _optional_int(
                receipt.get("ledgerSequence"), "ledgerSequence"
            ),
            "transactionHash": _optional_hex32(
                receipt.get("transactionHash"), "transactionHash"
            ),
            "circuitVersion": _text(receipt.get("circuitVersion"), "circuitVersion"),
            "verifierVersion": _text(receipt.get("verifierVersion"), "verifierVersion"),
        }
    except ValueError as exc:
        raise ValueError(f"{label} receipt invalid: {exc}") from exc


def _optional_mapping(
    receipt: Mapping[str, object],
    field: str,
    label: str,
) -> Mapping[str, object] | None:
    value = receipt.get(field)
    if value is None:
        return None
    if not isinstance(value, Mapping):
        raise ValueError(f"{label} receipt invalid: {field} must be a mapping or null")
    return value


def _optional_time_attestation(
    receipt: Mapping[str, object],
    label: str,
) -> TimeAttestation | None:
    value = receipt.get("timeAttestation")
    if value is None:
        return None
    if isinstance(value, TimeAttestation):
        # Validate canonical encoding bounds fail-closed
        encode_time_attestation(value)
        return value
    if isinstance(value, Mapping):
        try:
            return decode_time_attestation(dict(value))
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError(
                f"{label} receipt invalid: timeAttestation malformed: {exc}"
            ) from exc
    raise ValueError(
        f"{label} receipt invalid: timeAttestation must be a TimeAttestation, mapping, or null"
    )


def _record_diff(
    buckets: dict[DiffCategory, list[ReceiptDiffItem]],
    *,
    field: str,
    category: DiffCategory,
    before: Any,
    after: Any,
    explanation: str,
) -> None:
    buckets[category].append(
        {
            "field": field,
            "category": category,
            "before": before,
            "after": after,
            "explanation": explanation,
        }
    )


def _compare_optional_section(
    buckets: dict[DiffCategory, list[ReceiptDiffItem]],
    *,
    section: str,
    category: DiffCategory,
    before: Mapping[str, object] | None,
    after: Mapping[str, object] | None,
) -> None:
    if before is None and after is None:
        return
    before_map = dict(before) if before is not None else {}
    after_map = dict(after) if after is not None else {}
    for key in sorted(set(before_map.keys()) | set(after_map.keys())):
        b_val = before_map.get(key)
        a_val = after_map.get(key)
        if b_val != a_val:
            _record_diff(
                buckets,
                field=f"{section}.{key}",
                category=category,
                before=b_val,
                after=a_val,
                explanation=(
                    f"{category.capitalize()} observation '{section}.{key}' "
                    f"changed from {b_val!r} to {a_val!r}."
                ),
            )


def _compare_time_attestations(
    buckets: dict[DiffCategory, list[ReceiptDiffItem]],
    before: TimeAttestation | None,
    after: TimeAttestation | None,
) -> None:
    if before is None and after is None:
        return

    if before is None or after is None:
        state = "added" if before is None else "removed"
        _record_diff(
            buckets,
            field="timeAttestation",
            category="trust",
            before=encode_time_attestation(before) if before else None,
            after=encode_time_attestation(after) if after else None,
            explanation=f"Time attestation was {state} between verification runs.",
        )
        return

    if before.evidence_digest != after.evidence_digest:
        _record_diff(
            buckets,
            field="timeAttestation.evidenceDigest",
            category="evidence",
            before=before.evidence_digest,
            after=after.evidence_digest,
            explanation=(
                "Time attestation evidence digest changed, indicating the "
                "attestations bind different evidence payloads."
            ),
        )

    before_stellar = [
        (a.network_passphrase, a.ledger_sequence, a.ledger_timestamp, a.transaction_hash)
        for a in before.stellar_anchors
    ]
    after_stellar = [
        (a.network_passphrase, a.ledger_sequence, a.ledger_timestamp, a.transaction_hash)
        for a in after.stellar_anchors
    ]
    if before_stellar != after_stellar:
        _record_diff(
            buckets,
            field="timeAttestation.stellarAnchors",
            category="chain",
            before=len(before.stellar_anchors),
            after=len(after.stellar_anchors),
            explanation=(
                "Stellar ledger time anchors changed "
                f"({len(before.stellar_anchors)} -> {len(after.stellar_anchors)})."
            ),
        )

    before_tsa = [
        (a.tsa_url, a.gen_time, a.verification_status, a.cert_fingerprint)
        for a in before.rfc3161_anchors
    ]
    after_tsa = [
        (a.tsa_url, a.gen_time, a.verification_status, a.cert_fingerprint)
        for a in after.rfc3161_anchors
    ]
    if before_tsa != after_tsa:
        _record_diff(
            buckets,
            field="timeAttestation.rfc3161Anchors",
            category="trust",
            before=[a.verification_status for a in before.rfc3161_anchors],
            after=[a.verification_status for a in after.rfc3161_anchors],
            explanation=(
                "RFC 3161 TSA time anchor trust or verification status changed."
            ),
        )

    before_risk = check_backdating_risk(before)["risk_level"]
    after_risk = check_backdating_risk(after)["risk_level"]
    if before_risk != after_risk:
        _record_diff(
            buckets,
            field="timeAttestation.backdatingRisk",
            category="trust",
            before=before_risk,
            after=after_risk,
            explanation=(
                f"Time attestation backdating risk changed from '{before_risk}' "
                f"to '{after_risk}'."
            ),
        )


def compare_verification_receipts(
    baseline: Mapping[str, object],
    candidate: Mapping[str, object],
) -> ReceiptComparisonReport:
    """Compare two verification runs and categorize every difference.

    Distinguishes evidence changes, trust/revocation/chain observations, and
    presentation-only differences while validating canonical fields fail-closed.
    """

    base_norm = _validate_receipt_for_comparison(baseline, "baseline")
    cand_norm = _validate_receipt_for_comparison(candidate, "candidate")

    base_trust = _optional_mapping(baseline, "trust", "baseline")
    cand_trust = _optional_mapping(candidate, "trust", "candidate")
    base_rev = _optional_mapping(baseline, "revocation", "baseline")
    cand_rev = _optional_mapping(candidate, "revocation", "candidate")
    base_ta = _optional_time_attestation(baseline, "baseline")
    cand_ta = _optional_time_attestation(candidate, "candidate")

    buckets: dict[DiffCategory, list[ReceiptDiffItem]] = {
        "evidence": [],
        "trust": [],
        "revocation": [],
        "chain": [],
        "presentation": [],
    }

    # 1. Evidence fields (canonicalized)
    evidence_explanations = {
        "videoHash": "Evidence media digest (videoHash) changed between runs.",
        "metadataHash": "Evidence metadata digest (metadataHash) changed between runs.",
        "proofId": "Proof identifier (proofId) changed between runs.",
        "tier": (
            f"Identity tier changed from '{base_norm['tier']}' to '{cand_norm['tier']}'."
        ),
        "circuitVersion": (
            f"ZK circuit version changed from '{base_norm['circuitVersion']}' "
            f"to '{cand_norm['circuitVersion']}'."
        ),
    }
    for field, explanation in evidence_explanations.items():
        if base_norm[field] != cand_norm[field]:  # type: ignore[literal-required]
            _record_diff(
                buckets,
                field=field,
                category="evidence",
                before=base_norm[field],  # type: ignore[literal-required]
                after=cand_norm[field],  # type: ignore[literal-required]
                explanation=explanation,
            )

    # 2. Trust outcome & optional trust observations
    if base_norm["result"] != cand_norm["result"]:
        _record_diff(
            buckets,
            field="result",
            category="trust",
            before=base_norm["result"],
            after=cand_norm["result"],
            explanation=(
                f"Verification outcome changed from '{base_norm['result']}' "
                f"to '{cand_norm['result']}'."
            ),
        )
    _compare_optional_section(
        buckets,
        section="trust",
        category="trust",
        before=base_trust,
        after=cand_trust,
    )

    # 3. Revocation observations
    _compare_optional_section(
        buckets,
        section="revocation",
        category="revocation",
        before=base_rev,
        after=cand_rev,
    )

    # 4. Chain observations
    chain_explanations = {
        "networkPassphrase": (
            f"Stellar network changed from '{base_norm['networkPassphrase']}' "
            f"to '{cand_norm['networkPassphrase']}'."
        ),
        "contractId": (
            f"Verifier contract changed from '{base_norm['contractId']}' "
            f"to '{cand_norm['contractId']}'."
        ),
        "ledgerSequence": (
            f"Observed ledger sequence changed from {base_norm['ledgerSequence']!r} "
            f"to {cand_norm['ledgerSequence']!r}."
        ),
        "transactionHash": (
            "Observed anchor transaction hash changed between runs."
        ),
    }
    for field, explanation in chain_explanations.items():
        if base_norm[field] != cand_norm[field]:  # type: ignore[literal-required]
            _record_diff(
                buckets,
                field=field,
                category="chain",
                before=base_norm[field],  # type: ignore[literal-required]
                after=cand_norm[field],  # type: ignore[literal-required]
                explanation=explanation,
            )

    # 5. Time attestation observations (evidence, chain, and trust)
    _compare_time_attestations(buckets, base_ta, cand_ta)

    # 6. Presentation-only differences
    if base_norm["verifiedAt"] != cand_norm["verifiedAt"]:
        _record_diff(
            buckets,
            field="verifiedAt",
            category="presentation",
            before=base_norm["verifiedAt"],
            after=cand_norm["verifiedAt"],
            explanation=(
                "Verification timestamp (verifiedAt) changed; evidence and "
                "verification observations are unaffected."
            ),
        )
    if base_norm["verifierVersion"] != cand_norm["verifierVersion"]:
        _record_diff(
            buckets,
            field="verifierVersion",
            category="presentation",
            before=base_norm["verifierVersion"],
            after=cand_norm["verifierVersion"],
            explanation=(
                f"Verifier software version changed from '{base_norm['verifierVersion']}' "
                f"to '{cand_norm['verifierVersion']}'."
            ),
        )

    # Detect non-canonical hex casing differences when canonical values match
    for field in _HEX_FIELDS:
        raw_base = baseline.get(field)
        raw_cand = candidate.get(field)
        if (
            base_norm[field] == cand_norm[field]  # type: ignore[literal-required]
            and raw_base != raw_cand
        ):
            _record_diff(
                buckets,
                field=f"{field}.casing",
                category="presentation",
                before=raw_base,
                after=raw_cand,
                explanation=(
                    f"Hex casing for '{field}' differed, but canonical lowercase "
                    "digests are identical."
                ),
            )

    # Optional presentation/envelope metadata fields
    for field in _PRESENTATION_ENVELOPE_FIELDS:
        if field in baseline or field in candidate:
            raw_base = baseline.get(field)
            raw_cand = candidate.get(field)
            if raw_base != raw_cand:
                _record_diff(
                    buckets,
                    field=field,
                    category="presentation",
                    before=raw_base,
                    after=raw_cand,
                    explanation=(
                        f"Presentation/envelope field '{field}' changed without "
                        "altering evidence or verification observations."
                    ),
                )

    substantive_categories = [
        cat
        for cat in ("evidence", "trust", "revocation", "chain")
        if buckets[cat]
    ]
    has_presentation = bool(buckets["presentation"])
    identical = not substantive_categories and not has_presentation
    equivalent_evidence = not buckets["evidence"]
    presentation_only = not substantive_categories and has_presentation

    if identical:
        summary = "Receipts are identical."
    elif presentation_only:
        fields = ", ".join(item["field"] for item in buckets["presentation"])
        summary = f"Only presentation differences detected ({fields})."
    else:
        cats = ", ".join(substantive_categories)
        summary = f"Substantive differences detected in: {cats}."

    explanations = [
        item["explanation"]
        for cat in ("evidence", "trust", "revocation", "chain", "presentation")
        for item in buckets[cat]
    ]

    return {
        "identical": identical,
        "equivalentEvidence": equivalent_evidence,
        "presentationOnly": presentation_only,
        "summary": summary,
        "evidenceChanges": buckets["evidence"],
        "trustChanges": buckets["trust"],
        "revocationChanges": buckets["revocation"],
        "chainChanges": buckets["chain"],
        "presentationChanges": buckets["presentation"],
        "explanations": explanations,
    }


TrustDependency = Literal["stellar_anchor", "rfc3161_anchor", "backdating_risk"]
TrustOutcome = Literal["trusted", "invalid_signature", "unavailable", "not_present"]


class TimestampChainDependency(TypedDict):
    """One time-attestation dependency and its bounded trust result."""

    dependency: TrustDependency
    source: str
    outcome: TrustOutcome
    explanation: str


class TimestampChainReport(TypedDict):
    """Offline timestamp-chain validation report for one receipt."""

    valid: bool
    dependencies: list[TimestampChainDependency]
    invalidSignatures: list[str]
    unavailableTrust: list[str]
    summary: str


def build_timestamp_chain_report(
    receipt: Mapping[str, object],
) -> TimestampChainReport:
    """Enumerate time-attestation dependencies with bounded, offline trust results.

    Invalid signatures (a TSA or anchor that reports a failed verification) are
    reported separately from unavailable trust material (a missing, unreachable
    or unknown verification status). Nothing is fetched over the network.
    """

    ta = _optional_time_attestation(receipt, "candidate")
    dependencies: list[TimestampChainDependency] = []
    invalid: list[str] = []
    unavailable: list[str] = []

    if ta is None:
        summary = "No time attestation present; no timestamp chain to validate."
        return {
            "valid": True,
            "dependencies": [],
            "invalidSignatures": [],
            "unavailableTrust": [],
            "summary": summary,
        }

    for anchor in ta.stellar_anchors:
        source = f"stellar:{anchor.network_passphrase}@{anchor.ledger_sequence}"
        dependencies.append(
            {
                "dependency": "stellar_anchor",
                "source": source,
                "outcome": "trusted",
                "explanation": "Stellar ledger anchor is present for offline cross-check.",
            }
        )

    for anchor in ta.rfc3161_anchors:
        status = anchor.verification_status
        source = f"rfc3161:{anchor.tsa_url}"
        if status == "verified":
            outcome: TrustOutcome = "trusted"
            explanation = "RFC 3161 token signature verified against held trust material."
        elif status in ("invalid", "failed", "bad_signature"):
            outcome = "invalid_signature"
            explanation = f"RFC 3161 token signature is invalid ({status})."
            invalid.append(source)
        else:
            outcome = "unavailable"
            explanation = (
                f"RFC 3161 trust material unavailable or unknown ({status!r})."
            )
            unavailable.append(source)
        dependencies.append(
            {
                "dependency": "rfc3161_anchor",
                "source": source,
                "outcome": outcome,
                "explanation": explanation,
            }
        )

    risk = check_backdating_risk(ta)["risk_level"]
    dependencies.append(
        {
            "dependency": "backdating_risk",
            "source": "time_attestation",
            "outcome": "trusted" if risk == "low" else "unavailable",
            "explanation": f"Backdating risk assessed as '{risk}' from local anchors.",
        }
    )
    if risk != "low":
        unavailable.append("time_attestation:backdating_risk")

    valid = not invalid and not unavailable
    if invalid:
        summary = f"Invalid signatures detected in {len(invalid)} anchor(s)."
    elif unavailable:
        summary = f"Trust material unavailable for {len(unavailable)} dependency(ies)."
    else:
        summary = "All time-attestation dependencies validated offline."

    return {
        "valid": valid,
        "dependencies": dependencies,
        "invalidSignatures": invalid,
        "unavailableTrust": unavailable,
        "summary": summary,
    }


def format_receipt_comparison_report(report: ReceiptComparisonReport) -> str:
    """Render a deterministic human-readable receipt comparison report."""

    lines = [
        "Verification Receipt Comparison Report",
        f"Summary: {report['summary']}",
        f"Equivalent evidence: {'yes' if report['equivalentEvidence'] else 'no'}",
        f"Presentation only: {'yes' if report['presentationOnly'] else 'no'}",
    ]
    sections: tuple[tuple[str, list[ReceiptDiffItem]], ...] = (
        ("Evidence Changes", report["evidenceChanges"]),
        ("Trust Observations", report["trustChanges"]),
        ("Revocation Observations", report["revocationChanges"]),
        ("Chain Observations", report["chainChanges"]),
        ("Presentation Differences", report["presentationChanges"]),
    )
    for title, items in sections:
        if not items:
            continue
        lines.append(f"\n{title}:")
        for item in items:
            lines.append(f"  - [{item['field']}] {item['explanation']}")
    return "\n".join(lines)
