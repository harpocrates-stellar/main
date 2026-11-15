"""Validation for the canonical verification-receipt input contract.

The frontend owns receipt versioning and signing. The backend only returns the
same unsigned input shape, so there is one protocol contract and no second
backend-specific receipt envelope.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Literal, Mapping, TypedDict


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


def build_verification_receipt(
    context: Mapping[str, object],
    *,
    result: Literal["verified", "unverified"] = "unverified",
) -> VerificationReceiptInput:
    """Validate and build the canonical unsigned receipt input.

    A receipt is only emitted when the caller supplies the complete canonical
    evidence context. This prevents the selective-disclosure endpoint from
    inventing proof IDs or hashes from unrelated request fields.
    """

    return {
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


# ── Receipt comparison report across two verification runs ─────────────────

RECEIPT_COMPARISON_REPORT_SCHEMA = "harpocrates-receipt-comparison-report/v1"

ReceiptDiffCategory = Literal[
    "evidence_change",
    "trust_or_revocation_change",
    "chain_observation_change",
    "verifier_environment_change",
    "presentation_only",
]

OverallReceiptComparisonStatus = Literal[
    "identical",
    "presentation_only_differences",
    "observation_or_trust_changed",
    "different_evidence",
]


@dataclass(frozen=True)
class RunObservationContext:
    """Optional trust, revocation, or time-attestation state observed during a run."""

    trust_status: str | None = None
    revocation_status: str | None = None
    tsa_verification_status: str | None = None
    stellar_anchor_count: int | None = None


@dataclass(frozen=True)
class ReceiptFieldDifference:
    """Single categorized difference between two verification receipts."""

    field: str
    category: ReceiptDiffCategory
    reason_code: str
    first_value: Any
    second_value: Any
    explanation: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "explanation": self.explanation,
            "field": self.field,
            "firstValue": self.first_value,
            "reasonCode": self.reason_code,
            "secondValue": self.second_value,
        }


@dataclass(frozen=True)
class ReceiptComparisonReport:
    """Structured explanation comparing two verification receipt runs."""

    overall_status: OverallReceiptComparisonStatus
    same_evidence: bool
    has_substantive_changes: bool
    has_presentation_differences: bool
    differences: tuple[ReceiptFieldDifference, ...]
    explanations: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "differences": [d.to_dict() for d in self.differences],
            "explanations": list(self.explanations),
            "hasPresentationDifferences": self.has_presentation_differences,
            "hasSubstantiveChanges": self.has_substantive_changes,
            "overallStatus": self.overall_status,
            "sameEvidence": self.same_evidence,
            "schema": RECEIPT_COMPARISON_REPORT_SCHEMA,
        }


def _parse_iso_for_compare(value: object, field: str) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be a valid ISO-8601 timestamp")
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        dt = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise ValueError(f"{field} must be a valid ISO-8601 timestamp") from exc
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _normalize_receipt_for_compare(raw: Mapping[str, object]) -> dict[str, Any]:
    if not isinstance(raw, Mapping):
        raise ValueError("receipt must be a mapping")

    signer = raw.get("signer")
    signer_key_id: str | None = None
    signer_alg: str | None = None
    if signer is not None:
        if not isinstance(signer, Mapping):
            raise ValueError("signer must be an object when present")
        signer_key_id = _text(signer.get("keyId"), "signer.keyId")
        signer_alg = _text(signer.get("algorithm"), "signer.algorithm")

    signature = raw.get("signature")
    if signature is not None and (not isinstance(signature, str) or not signature.strip()):
        raise ValueError("signature must be a non-empty string when present")

    verified_at_raw = _text(raw.get("verifiedAt"), "verifiedAt")
    verified_at_dt = _parse_iso_for_compare(verified_at_raw, "verifiedAt")

    raw_proof_id = str(raw.get("proofId", ""))
    raw_video_hash = str(raw.get("videoHash", ""))
    raw_meta_hash = str(raw.get("metadataHash", ""))
    raw_tx_hash = raw.get("transactionHash")

    return {
        "result": _choice(raw.get("result"), "result", ("verified", "unverified")),
        "verifiedAtRaw": verified_at_raw,
        "verifiedAtDt": verified_at_dt,
        "proofId": _hex32(raw.get("proofId"), "proofId"),
        "proofIdRaw": raw_proof_id,
        "videoHash": _hex32(raw.get("videoHash"), "videoHash"),
        "videoHashRaw": raw_video_hash,
        "metadataHash": _hex32(raw.get("metadataHash"), "metadataHash"),
        "metadataHashRaw": raw_meta_hash,
        "tier": _choice(raw.get("tier"), "tier", ("silent", "source", "seal")),
        "networkPassphrase": _text(raw.get("networkPassphrase"), "networkPassphrase").strip(),
        "networkPassphraseRaw": str(raw.get("networkPassphrase", "")),
        "contractId": _text(raw.get("contractId"), "contractId").strip(),
        "ledgerSequence": _optional_int(raw.get("ledgerSequence"), "ledgerSequence"),
        "transactionHash": _optional_hex32(raw_tx_hash, "transactionHash"),
        "transactionHashRaw": str(raw_tx_hash) if raw_tx_hash is not None else None,
        "circuitVersion": _text(raw.get("circuitVersion"), "circuitVersion").strip(),
        "verifierVersion": _text(raw.get("verifierVersion"), "verifierVersion").strip(),
        "signerKeyId": signer_key_id,
        "signerAlgorithm": signer_alg,
        "signature": signature,
    }


def compare_verification_receipts(
    first_receipt: Mapping[str, object],
    second_receipt: Mapping[str, object],
    *,
    first_observation: RunObservationContext | None = None,
    second_observation: RunObservationContext | None = None,
) -> ReceiptComparisonReport:
    """Compare two verification receipts and distinguish substantive vs. presentation diffs."""
    r1 = _normalize_receipt_for_compare(first_receipt)
    r2 = _normalize_receipt_for_compare(second_receipt)
    obs1 = first_observation or RunObservationContext()
    obs2 = second_observation or RunObservationContext()

    diffs: list[ReceiptFieldDifference] = []

    # 1. Evidence-binding fields
    for field_name, code, label in (
        ("proofId", "proof_id_changed", "Proof identifier changed across runs."),
        ("videoHash", "video_hash_changed", "Canonical video digest changed (different underlying media)."),
        ("metadataHash", "metadata_hash_changed", "Canonical metadata digest changed."),
        ("tier", "identity_tier_changed", "Evidence identity tier changed across runs."),
    ):
        if r1[field_name] != r2[field_name]:
            diffs.append(
                ReceiptFieldDifference(
                    field=field_name,
                    category="evidence_change",
                    reason_code=code,
                    first_value=r1[field_name],
                    second_value=r2[field_name],
                    explanation=label,
                )
            )

    # Hex-casing presentation-only differences when underlying digest is identical
    for field_name, raw_key in (
        ("proofId", "proofIdRaw"),
        ("videoHash", "videoHashRaw"),
        ("metadataHash", "metadataHashRaw"),
        ("transactionHash", "transactionHashRaw"),
    ):
        if r1[field_name] == r2[field_name] and r1[raw_key] != r2[raw_key]:
            diffs.append(
                ReceiptFieldDifference(
                    field=field_name,
                    category="presentation_only",
                    reason_code="hex_casing_format_difference",
                    first_value=r1[raw_key],
                    second_value=r2[raw_key],
                    explanation=f"{field_name} differs only in hex letter casing.",
                )
            )

    # 2. Trust, verification outcome, and revocation changes
    if r1["result"] != r2["result"]:
        diffs.append(
            ReceiptFieldDifference(
                field="result",
                category="trust_or_revocation_change",
                reason_code="verification_result_changed",
                first_value=r1["result"],
                second_value=r2["result"],
                explanation=f"Verification outcome changed from '{r1['result']}' to '{r2['result']}'.",
            )
        )

    if obs1.revocation_status != obs2.revocation_status:
        diffs.append(
            ReceiptFieldDifference(
                field="revocationStatus",
                category="trust_or_revocation_change",
                reason_code="revocation_status_changed",
                first_value=obs1.revocation_status,
                second_value=obs2.revocation_status,
                explanation=(
                    f"Revocation observation changed from '{obs1.revocation_status}' "
                    f"to '{obs2.revocation_status}'."
                ),
            )
        )

    if obs1.trust_status != obs2.trust_status:
        diffs.append(
            ReceiptFieldDifference(
                field="trustStatus",
                category="trust_or_revocation_change",
                reason_code="issuer_or_signer_trust_changed",
                first_value=obs1.trust_status,
                second_value=obs2.trust_status,
                explanation=(
                    f"Trust evaluation changed from '{obs1.trust_status}' "
                    f"to '{obs2.trust_status}'."
                ),
            )
        )

    if obs1.tsa_verification_status != obs2.tsa_verification_status:
        diffs.append(
            ReceiptFieldDifference(
                field="tsaVerificationStatus",
                category="trust_or_revocation_change",
                reason_code="tsa_chain_status_changed",
                first_value=obs1.tsa_verification_status,
                second_value=obs2.tsa_verification_status,
                explanation=(
                    f"Timestamp authority verification status changed from "
                    f"'{obs1.tsa_verification_status}' to '{obs2.tsa_verification_status}'."
                ),
            )
        )

    if r1["signerKeyId"] != r2["signerKeyId"]:
        diffs.append(
            ReceiptFieldDifference(
                field="signer.keyId",
                category="trust_or_revocation_change",
                reason_code="receipt_signer_key_changed",
                first_value=r1["signerKeyId"],
                second_value=r2["signerKeyId"],
                explanation="Receipt signer key identifier changed across runs.",
            )
        )

    # 3. Chain & ledger observation changes
    if r1["ledgerSequence"] != r2["ledgerSequence"]:
        if r1["ledgerSequence"] is None and r2["ledgerSequence"] is not None:
            ledger_expl = f"Proof gained on-chain ledger confirmation at sequence {r2['ledgerSequence']}."
            ledger_code = "chain_anchor_confirmed"
        elif r1["ledgerSequence"] is not None and r2["ledgerSequence"] is None:
            ledger_expl = "On-chain ledger sequence missing in second verification run (offline or unanchored view)."
            ledger_code = "chain_anchor_missing"
        else:
            ledger_expl = (
                f"Observed ledger sequence changed from {r1['ledgerSequence']} to {r2['ledgerSequence']}."
            )
            ledger_code = "ledger_sequence_changed"
        diffs.append(
            ReceiptFieldDifference(
                field="ledgerSequence",
                category="chain_observation_change",
                reason_code=ledger_code,
                first_value=r1["ledgerSequence"],
                second_value=r2["ledgerSequence"],
                explanation=ledger_expl,
            )
        )

    if r1["transactionHash"] != r2["transactionHash"]:
        diffs.append(
            ReceiptFieldDifference(
                field="transactionHash",
                category="chain_observation_change",
                reason_code="transaction_hash_changed",
                first_value=r1["transactionHash"],
                second_value=r2["transactionHash"],
                explanation="Observed registration transaction hash changed across runs.",
            )
        )

    if r1["networkPassphrase"] != r2["networkPassphrase"]:
        diffs.append(
            ReceiptFieldDifference(
                field="networkPassphrase",
                category="chain_observation_change",
                reason_code="network_changed",
                first_value=r1["networkPassphrase"],
                second_value=r2["networkPassphrase"],
                explanation="Stellar network passphrase differs between verification runs.",
            )
        )

    if r1["contractId"] != r2["contractId"]:
        diffs.append(
            ReceiptFieldDifference(
                field="contractId",
                category="chain_observation_change",
                reason_code="contract_id_changed",
                first_value=r1["contractId"],
                second_value=r2["contractId"],
                explanation="Registry contract identifier differs between verification runs.",
            )
        )

    if obs1.stellar_anchor_count != obs2.stellar_anchor_count:
        diffs.append(
            ReceiptFieldDifference(
                field="stellarAnchorCount",
                category="chain_observation_change",
                reason_code="stellar_anchor_count_changed",
                first_value=obs1.stellar_anchor_count,
                second_value=obs2.stellar_anchor_count,
                explanation="Observed Stellar timestamp anchor count changed across runs.",
            )
        )

    # 4. Verifier / circuit version differences
    if r1["circuitVersion"] != r2["circuitVersion"]:
        diffs.append(
            ReceiptFieldDifference(
                field="circuitVersion",
                category="verifier_environment_change",
                reason_code="circuit_version_changed",
                first_value=r1["circuitVersion"],
                second_value=r2["circuitVersion"],
                explanation="Circuit version changed between verification runs.",
            )
        )

    if r1["verifierVersion"] != r2["verifierVersion"]:
        diffs.append(
            ReceiptFieldDifference(
                field="verifierVersion",
                category="verifier_environment_change",
                reason_code="verifier_version_changed",
                first_value=r1["verifierVersion"],
                second_value=r2["verifierVersion"],
                explanation="Verifier version changed between verification runs.",
            )
        )

    # 5. Presentation-only differences (verifiedAt timestamp / timezone formatting / fresh signature bytes)
    if r1["verifiedAtRaw"] != r2["verifiedAtRaw"]:
        same_instant = r1["verifiedAtDt"] == r2["verifiedAtDt"]
        diffs.append(
            ReceiptFieldDifference(
                field="verifiedAt",
                category="presentation_only",
                reason_code="timestamp_format_difference" if same_instant else "reverification_timestamp_advanced",
                first_value=r1["verifiedAtRaw"],
                second_value=r2["verifiedAtRaw"],
                explanation=(
                    "verifiedAt represents the same UTC instant in a different ISO-8601 format."
                    if same_instant
                    else "Receipt was generated at a different verification run timestamp without altering evidence digests."
                ),
            )
        )

    has_non_presentation = any(d.category != "presentation_only" for d in diffs)
    if (
        r1["signature"] != r2["signature"]
        and not has_non_presentation
        and r1["signerKeyId"] == r2["signerKeyId"]
    ):
        diffs.append(
            ReceiptFieldDifference(
                field="signature",
                category="presentation_only",
                reason_code="re_signed_envelope_bytes",
                first_value="[present]" if r1["signature"] else None,
                second_value="[present]" if r2["signature"] else None,
                explanation="Receipt signature bytes differ due to re-signing/timestamping without substantive statement changes.",
            )
        )

    same_evidence = not any(d.category == "evidence_change" for d in diffs)
    has_substantive = any(d.category != "presentation_only" for d in diffs)
    has_presentation = any(d.category == "presentation_only" for d in diffs)

    overall: OverallReceiptComparisonStatus
    if not same_evidence:
        overall = "different_evidence"
    elif has_substantive:
        overall = "observation_or_trust_changed"
    elif has_presentation:
        overall = "presentation_only_differences"
    else:
        overall = "identical"

    explanations = (
        tuple(d.explanation for d in diffs)
        if diffs
        else ("Both verification receipts are semantically and presentationally identical.",)
    )
    return ReceiptComparisonReport(
        overall_status=overall,
        same_evidence=same_evidence,
        has_substantive_changes=has_substantive,
        has_presentation_differences=has_presentation,
        differences=tuple(diffs),
        explanations=explanations,
    )

