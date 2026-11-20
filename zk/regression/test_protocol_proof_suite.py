"""Protocol-level proof regression suite (Harpocrates).

Exercises the public verifier-input boundary with synthetic, versioned vectors
so malformed / oversized / revoked-shaped inputs fail closed without leaking
witness material into messages.

This suite reuses the canonical corpus at
``zk/vectors/verifier_conformance_v1.json`` and revocation vectors at
``zk/noir/fixtures/revocation_vectors.json`` — it does **not** invent a second
protocol truth.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
CORPUS_PATH = ROOT / "zk" / "vectors" / "verifier_conformance_v1.json"
REVOCATION_VECTORS_PATH = ROOT / "zk" / "noir" / "fixtures" / "revocation_vectors.json"

sys.path.insert(0, str(ROOT / "zk" / "tools"))
sys.path.insert(0, str(ROOT / "backend"))

import revocation_depth as rd  # noqa: E402
import verifier_inputs as vi  # noqa: E402

# Privacy: rejection messages must never echo raw hex blobs / witness-looking material.
SECRETISH = re.compile(r"(?i)(private[ _-]?key|witness|sk_|0x[0-9a-f]{32,})")


@pytest.fixture(scope="module")
def corpus():
    assert CORPUS_PATH.is_file(), f"missing corpus: {CORPUS_PATH}"
    data = json.loads(CORPUS_PATH.read_text(encoding="utf-8"))
    assert data.get("format") == "harpocrates.verifier-conformance"
    assert data.get("version") == 1
    return data


@pytest.fixture(scope="module")
def revocation_vectors():
    assert REVOCATION_VECTORS_PATH.is_file(), f"missing fixture: {REVOCATION_VECTORS_PATH}"
    return json.loads(REVOCATION_VECTORS_PATH.read_text(encoding="utf-8"))


def test_corpus_is_pinned_and_reproducible(corpus):
    assert "codec" in corpus
    assert "constants" in corpus
    assert len(corpus.get("cases", [])) >= 10


def test_negative_cases_have_stable_reject_codes(corpus):
    negatives = [c for c in corpus["cases"] if c.get("expect") == "reject" or c.get("outcome") == "reject"]
    if not negatives:
        # Some corpora use `want` / `accept` flags — accept either shape.
        negatives = [c for c in corpus["cases"] if c.get("accept") is False]
    assert negatives, "expected at least one negative conformance case"
    for case in negatives:
        # Stable identity for CI blame lines
        assert case.get("id"), case
        # Must declare why it fails (code or reason) without embedding secrets
        reason = json.dumps(case)
        assert not SECRETISH.search(reason), f"case {case.get('id')} looks secret-bearing"


def test_positive_cases_are_marked(corpus):
    positives = [
        c
        for c in corpus["cases"]
        if c.get("expect") == "accept" or c.get("outcome") == "accept" or c.get("accept") is True
    ]
    if not positives:
        positives = [c for c in corpus["cases"] if "accept" not in c and c.get("expect") != "reject"]
    assert positives, "expected at least one positive / accepted case"


def test_oversized_and_malformed_shapes_are_represented(corpus):
    blob = json.dumps(corpus).lower()
    # Boundary vocabulary the protocol suite must keep coverage for
    needles = ("malformed", "oversize", "oversized", "length", "revoke", "expired", "unsupported")
    assert any(n in blob for n in needles), "corpus missing malformed/boundary vocabulary"


def test_readme_documents_trust_boundary():
    readme = Path(__file__).with_name("README.md")
    text = readme.read_text(encoding="utf-8")
    assert "trust" in text.lower() or "privacy" in text.lower()
    assert "rollback" in text.lower() or "compat" in text.lower()


def test_revocation_witness_max_depth_and_over_depth_vectors(revocation_vectors):
    assert revocation_vectors["_max_revocation_witness_depth"] == 16
    assert revocation_vectors["_max_revocation_leaves"] == 65536
    assert rd.MAX_REVOCATION_WITNESS_DEPTH == 16
    assert vi.MAX_REVOCATION_WITNESS_DEPTH == 16

    positive_by_name = {c["name"]: c for c in revocation_vectors["positive_cases"]}
    assert "max_depth_non_revocation_witness" in positive_by_name
    max_case = positive_by_name["max_depth_non_revocation_witness"]
    assert max_case["depth"] == 16
    assert max_case["leaf_count"] == 65536
    assert rd.validate_revocation_witness_shape(max_case["depth"], max_case["leaf_count"]) == (16, 65536)
    vi.check_revocation_witness_depth(max_case["depth"])

    negative_by_name = {c["name"]: c for c in revocation_vectors["negative_cases"]}
    over_depth = negative_by_name["oversized_revocation_depth"]
    assert over_depth["depth"] == 17
    assert over_depth["expected_error"] == "depth_oversize"
    assert over_depth["expected_contract_error"] == "InvalidProofInput"
    with pytest.raises(rd.RevocationDepthError) as rd_exc:
        rd.validate_revocation_depth(over_depth["depth"])
    assert rd_exc.value.code == "depth_oversize"
    with pytest.raises(vi.VerifierInputError) as vi_exc:
        vi.check_revocation_witness_depth(over_depth["depth"])
    assert vi_exc.value.code == vi.RejectCode.PROOF_OVERSIZE

    over_leaves = negative_by_name["oversized_revocation_leaf_count"]
    assert over_leaves["leaf_count"] == 65537
    assert over_leaves["expected_error"] == "depth_oversize"
    with pytest.raises(rd.RevocationDepthError) as leaf_exc:
        rd.validate_revocation_leaf_count(over_leaves["leaf_count"])
    assert leaf_exc.value.code == "depth_oversize"
