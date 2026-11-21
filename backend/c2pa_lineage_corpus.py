"""Offline C2PA and lineage interoperability corpus runner.

Loads deterministic synthetic fixtures (no network access, no real media) and
evaluates C2PA manifest parsing/corroboration alongside Harpocrates lineage
manifest canonicalization and DAG validation.
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from c2pa import (
    C2paParseError,
    C2paTrustStatus,
    corroborate_binding,
    export_c2pa_manifest,
    parse_c2pa_manifest,
    verify_round_trip,
)
from lineage import (
    LineageValidationError,
    canonical_lineage_manifest,
    lineage_manifest_digest,
    validate_lineage_graph,
)

DEFAULT_CORPUS_PATH = Path(__file__).resolve().parent / "fixtures" / "c2pa_lineage_corpus.json"
CORPUS_SCHEMA_VERSION = 1


class CorpusFormatError(ValueError):
    """Raised when the corpus fixture file itself is malformed."""


@dataclass(frozen=True)
class CorpusCaseResult:
    """Stable, privacy-safe evaluation result for a single corpus vector."""

    case_id: str
    kind: str
    passed: bool
    outcome: str
    details: tuple[str, ...] = ()


@dataclass(frozen=True)
class CorpusRunReport:
    """Aggregate report for an offline corpus run."""

    corpus_version: int
    total: int
    passed: int
    failed: int
    results: tuple[CorpusCaseResult, ...]

    @property
    def ok(self) -> bool:
        return self.failed == 0 and self.total > 0


def load_corpus(path: Path | str = DEFAULT_CORPUS_PATH) -> dict[str, Any]:
    """Load and structurally validate the offline corpus JSON file."""
    corpus_path = Path(path)
    try:
        raw = corpus_path.read_text(encoding="utf-8")
        data = json.loads(raw)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CorpusFormatError(f"failed to load corpus: {exc}") from exc

    if not isinstance(data, dict):
        raise CorpusFormatError("corpus root must be a JSON object")
    if data.get("corpus_version") != CORPUS_SCHEMA_VERSION:
        raise CorpusFormatError(
            f"unsupported corpus_version: expected {CORPUS_SCHEMA_VERSION}"
        )
    cases = data.get("cases")
    if not isinstance(cases, list) or not cases:
        raise CorpusFormatError("corpus must contain a non-empty 'cases' list")
    return data


def _evaluate_c2pa_case(case: dict[str, Any]) -> CorpusCaseResult:
    case_id = str(case["id"])
    expected = case["expected"]
    manifest = case["manifest"]
    raw_manifest = manifest if isinstance(manifest, str) else json.dumps(manifest, sort_keys=True)
    failures: list[str] = []

    if expected["status"] == "reject":
        try:
            parse_c2pa_manifest(raw_manifest)
        except C2paParseError as err:
            if err.reason != expected["reason"]:
                failures.append(f"reason={err.reason} expected={expected['reason']}")
            if "field" in expected and err.field != expected["field"]:
                failures.append(f"field={err.field} expected={expected['field']}")
            return CorpusCaseResult(
                case_id=case_id,
                kind="c2pa",
                passed=not failures,
                outcome="rejected" if not failures else "mismatch",
                details=tuple(failures),
            )
        return CorpusCaseResult(
            case_id=case_id,
            kind="c2pa",
            passed=False,
            outcome="unexpected_accept",
            details=("expected C2paParseError but manifest parsed",),
        )

    try:
        parsed = parse_c2pa_manifest(raw_manifest)
    except C2paParseError as err:
        return CorpusCaseResult(
            case_id=case_id,
            kind="c2pa",
            passed=False,
            outcome="unexpected_reject",
            details=(f"unexpected C2paParseError: {err.reason}",),
        )

    expected_trust = expected.get("trust_status", C2paTrustStatus.SIGNATURE_NOT_CHECKED.value)
    if parsed.trust_status.value != expected_trust:
        failures.append(f"trust_status={parsed.trust_status.value} expected={expected_trust}")

    if "tier" in expected and parsed.binding.tier != expected["tier"]:
        failures.append(f"tier={parsed.binding.tier} expected={expected['tier']}")

    unknown_labels = [a.label for a in parsed.unknown_assertions]
    if "unknown_assertion_labels" in expected:
        if unknown_labels != expected["unknown_assertion_labels"]:
            failures.append(
                f"unknown_labels={unknown_labels} expected={expected['unknown_assertion_labels']}"
            )
    if any(not a.unsupported_semantics for a in parsed.unknown_assertions):
        failures.append("unknown assertion missing unsupported_semantics=True")

    if expected.get("check_round_trip"):
        exported = export_c2pa_manifest(
            video_hash=parsed.binding.video_hash,
            metadata_hash=parsed.binding.metadata_hash,
            proof_id=parsed.binding.proof_id,
            tier=parsed.binding.tier,
            network=parsed.binding.network,
            contract_id=parsed.binding.contract_id,
            claim_generator=parsed.claim_generator,
        )
        if not verify_round_trip(exported):
            failures.append("verify_round_trip returned False")
        if "export_digest" in expected and exported.digest != expected["export_digest"]:
            failures.append("export_digest mismatch")

    if "corroborate" in case:
        corr = corroborate_binding(parsed, **case["corroborate"])
        if corr.ok != expected.get("corroboration_ok", True):
            failures.append(
                f"corroboration_ok={corr.ok} expected={expected.get('corroboration_ok', True)}"
            )
        expected_mismatches = tuple(expected.get("corroboration_mismatches", []))
        if corr.mismatches != expected_mismatches:
            failures.append(
                f"corroboration_mismatches={corr.mismatches} expected={expected_mismatches}"
            )

    return CorpusCaseResult(
        case_id=case_id,
        kind="c2pa",
        passed=not failures,
        outcome="accepted" if not failures else "mismatch",
        details=tuple(failures),
    )


def _evaluate_lineage_case(case: dict[str, Any]) -> CorpusCaseResult:
    case_id = str(case["id"])
    expected = case["expected"]
    manifest = case["lineage_manifest"]
    graph = case.get("graph")
    failures: list[str] = []

    def _run_lineage() -> tuple[str, str]:
        canonical = canonical_lineage_manifest(manifest)
        digest = lineage_manifest_digest(manifest)
        if graph is not None:
            ancestry = graph.get("ancestry", {})

            def _get_lineage(proof_id: str) -> dict[str, Any] | None:
                return ancestry.get(proof_id)

            validate_lineage_graph(
                parent_proof_ids=graph.get("parent_proof_ids", manifest.get("parentProofIds", [])),
                depth=graph["depth"],
                actor_address=graph.get("actor_address", manifest.get("actorAddress", "")),
                output_digest=graph.get("output_digest", manifest.get("outputDigest")),
                get_lineage_fn=_get_lineage if ancestry else None,
            )
        return canonical, digest

    if expected["status"] == "reject":
        try:
            _run_lineage()
        except LineageValidationError as err:
            substr = expected.get("error_contains", "")
            if substr and substr.lower() not in str(err).lower():
                failures.append(f"error='{err}' missing '{substr}'")
            return CorpusCaseResult(
                case_id=case_id,
                kind="lineage",
                passed=not failures,
                outcome="rejected" if not failures else "mismatch",
                details=tuple(failures),
            )
        return CorpusCaseResult(
            case_id=case_id,
            kind="lineage",
            passed=False,
            outcome="unexpected_accept",
            details=("expected LineageValidationError but lineage validated",),
        )

    try:
        canonical, digest = _run_lineage()
    except LineageValidationError as err:
        return CorpusCaseResult(
            case_id=case_id,
            kind="lineage",
            passed=False,
            outcome="unexpected_reject",
            details=(f"unexpected LineageValidationError: {err}",),
        )

    if "lineage_digest" in expected and digest != expected["lineage_digest"]:
        failures.append("lineage_digest mismatch")
    if "canonical_manifest" in expected and canonical != expected["canonical_manifest"]:
        failures.append("canonical_manifest mismatch")

    return CorpusCaseResult(
        case_id=case_id,
        kind="lineage",
        passed=not failures,
        outcome="accepted" if not failures else "mismatch",
        details=tuple(failures),
    )


def _evaluate_interop_case(case: dict[str, Any]) -> CorpusCaseResult:
    """Evaluate a combined C2PA + lineage interoperability vector."""
    case_id = str(case["id"])
    expected = case["expected"]
    failures: list[str] = []

    raw_manifest = json.dumps(case["c2pa_manifest"], sort_keys=True)
    c2pa_parsed = None
    c2pa_error: C2paParseError | None = None
    try:
        c2pa_parsed = parse_c2pa_manifest(raw_manifest)
    except C2paParseError as err:
        c2pa_error = err

    if expected.get("c2pa_status") == "reject":
        if c2pa_error is None:
            failures.append("expected C2PA rejection")
        elif c2pa_error.reason != expected.get("c2pa_reason"):
            failures.append(
                f"c2pa_reason={c2pa_error.reason} expected={expected.get('c2pa_reason')}"
            )
        return CorpusCaseResult(
            case_id=case_id,
            kind="interop",
            passed=not failures,
            outcome="rejected" if not failures else "mismatch",
            details=tuple(failures),
        )

    if c2pa_error is not None or c2pa_parsed is None:
        return CorpusCaseResult(
            case_id=case_id,
            kind="interop",
            passed=False,
            outcome="unexpected_reject",
            details=(f"unexpected C2PA error: {c2pa_error.reason if c2pa_error else 'unknown'}",),
        )

    if c2pa_parsed.trust_status != C2paTrustStatus.SIGNATURE_NOT_CHECKED:
        failures.append(f"trust_status={c2pa_parsed.trust_status.value}")

    unknown_labels = [a.label for a in c2pa_parsed.unknown_assertions]
    if "unknown_assertion_labels" in expected:
        if unknown_labels != expected["unknown_assertion_labels"]:
            failures.append(
                f"unknown_labels={unknown_labels} expected={expected['unknown_assertion_labels']}"
            )
    if any(not a.unsupported_semantics for a in c2pa_parsed.unknown_assertions):
        failures.append("unknown assertion missing unsupported_semantics=True")

    # Corroborate C2PA binding against the lineage outputDigest (or explicit expected fields).
    lineage_manifest = case["lineage_manifest"]
    corroborate_fields = case.get(
        "corroborate",
        {"video_hash": lineage_manifest.get("outputDigest")},
    )
    corr = corroborate_binding(c2pa_parsed, **corroborate_fields)
    if corr.ok != expected.get("corroboration_ok", True):
        failures.append(
            f"corroboration_ok={corr.ok} expected={expected.get('corroboration_ok', True)}"
        )
    expected_mismatches = tuple(expected.get("corroboration_mismatches", []))
    if corr.mismatches != expected_mismatches:
        failures.append(
            f"corroboration_mismatches={corr.mismatches} expected={expected_mismatches}"
        )

    # Evaluate the linked lineage manifest and graph.
    graph = case.get("graph")
    if expected.get("lineage_status") == "reject":
        try:
            canonical_lineage_manifest(lineage_manifest)
            if graph is not None:
                ancestry = graph.get("ancestry", {})
                validate_lineage_graph(
                    parent_proof_ids=graph.get(
                        "parent_proof_ids", lineage_manifest.get("parentProofIds", [])
                    ),
                    depth=graph["depth"],
                    actor_address=graph.get(
                        "actor_address", lineage_manifest.get("actorAddress", "")
                    ),
                    output_digest=graph.get(
                        "output_digest", lineage_manifest.get("outputDigest")
                    ),
                    get_lineage_fn=(lambda pid: ancestry.get(pid)) if ancestry else None,
                )
        except LineageValidationError as err:
            substr = expected.get("lineage_error_contains", "")
            if substr and substr.lower() not in str(err).lower():
                failures.append(f"lineage_error='{err}' missing '{substr}'")
        else:
            failures.append("expected LineageValidationError")
    else:
        try:
            digest = lineage_manifest_digest(lineage_manifest)
            if graph is not None:
                ancestry = graph.get("ancestry", {})
                validate_lineage_graph(
                    parent_proof_ids=graph.get(
                        "parent_proof_ids", lineage_manifest.get("parentProofIds", [])
                    ),
                    depth=graph["depth"],
                    actor_address=graph.get(
                        "actor_address", lineage_manifest.get("actorAddress", "")
                    ),
                    output_digest=graph.get(
                        "output_digest", lineage_manifest.get("outputDigest")
                    ),
                    get_lineage_fn=(lambda pid: ancestry.get(pid)) if ancestry else None,
                )
        except LineageValidationError as err:
            failures.append(f"unexpected LineageValidationError: {err}")
        else:
            if "lineage_digest" in expected and digest != expected["lineage_digest"]:
                failures.append("lineage_digest mismatch")

    return CorpusCaseResult(
        case_id=case_id,
        kind="interop",
        passed=not failures,
        outcome="accepted" if not failures else "mismatch",
        details=tuple(failures),
    )


def run_corpus(path: Path | str = DEFAULT_CORPUS_PATH) -> CorpusRunReport:
    """Execute all vectors in the offline interoperability corpus."""
    corpus = load_corpus(path)
    results: list[CorpusCaseResult] = []

    for case in corpus["cases"]:
        if not isinstance(case, dict) or "id" not in case or "kind" not in case:
            raise CorpusFormatError("each corpus case must have 'id' and 'kind'")
        kind = case["kind"]
        if kind == "c2pa":
            results.append(_evaluate_c2pa_case(case))
        elif kind == "lineage":
            results.append(_evaluate_lineage_case(case))
        elif kind == "interop":
            results.append(_evaluate_interop_case(case))
        else:
            raise CorpusFormatError(f"unsupported corpus case kind: {kind}")

    passed = sum(1 for r in results if r.passed)
    failed = len(results) - passed
    return CorpusRunReport(
        corpus_version=corpus["corpus_version"],
        total=len(results),
        passed=passed,
        failed=failed,
        results=tuple(results),
    )


def main(argv: list[str] | None = None) -> int:
    path = Path(argv[0]) if argv else DEFAULT_CORPUS_PATH
    report = run_corpus(path)
    print(
        f"C2PA/Lineage Offline Corpus v{report.corpus_version}: "
        f"{report.passed}/{report.total} passed, {report.failed} failed"
    )
    for res in report.results:
        status = "PASS" if res.passed else "FAIL"
        suffix = f" ({'; '.join(res.details)})" if res.details else ""
        print(f"  [{status}] {res.kind}:{res.case_id} -> {res.outcome}{suffix}")
    return 0 if report.ok else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
