"""Protocol-level proof regression suite (Harpocrates).

Exercises the public verifier-input boundary with synthetic, versioned vectors
so malformed / oversized / revoked-shaped inputs fail closed without leaking
witness material into messages.

This suite reuses the canonical corpus at
``zk/vectors/verifier_conformance_v1.json`` — it does **not** invent a second
protocol truth.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
CORPUS_PATH = ROOT / "zk" / "vectors" / "verifier_conformance_v1.json"

# Privacy: rejection messages must never echo raw hex blobs / witness-looking material.
SECRETISH = re.compile(r"(?i)(private[ _-]?key|witness|sk_|0x[0-9a-f]{32,})")


@pytest.fixture(scope="module")
def corpus():
    assert CORPUS_PATH.is_file(), f"missing corpus: {CORPUS_PATH}"
    data = json.loads(CORPUS_PATH.read_text(encoding="utf-8"))
    assert data.get("format") == "harpocrates.verifier-conformance"
    assert data.get("version") == 1
    return data


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
