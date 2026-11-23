"""Focused tests for the offline C2PA and lineage interoperability corpus."""

from __future__ import annotations

import json
import socket
from pathlib import Path

import pytest

from c2pa_lineage_corpus import (
    CORPUS_SCHEMA_VERSION,
    DEFAULT_CORPUS_PATH,
    CorpusFormatError,
    load_corpus,
    main,
    run_corpus,
)


def test_default_corpus_passes_completely() -> None:
    report = run_corpus(DEFAULT_CORPUS_PATH)
    assert report.ok is True
    assert report.corpus_version == CORPUS_SCHEMA_VERSION
    assert report.failed == 0
    assert report.total == report.passed
    assert report.total >= 19
    assert all(r.passed for r in report.results)


def test_corpus_is_deterministic_across_runs() -> None:
    first = run_corpus(DEFAULT_CORPUS_PATH)
    second = run_corpus(DEFAULT_CORPUS_PATH)
    assert first == second


def test_corpus_runs_without_network_access(monkeypatch: pytest.MonkeyPatch) -> None:
    def _blocked(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("network access is forbidden during offline corpus run")

    monkeypatch.setattr(socket, "create_connection", _blocked)
    report = run_corpus(DEFAULT_CORPUS_PATH)
    assert report.ok is True


def test_corpus_covers_all_kinds_and_mixed_ingredients() -> None:
    report = run_corpus(DEFAULT_CORPUS_PATH)
    kinds = {r.kind for r in report.results}
    assert kinds == {"c2pa", "lineage", "interop"}

    ids = {r.case_id for r in report.results}
    assert "c2pa_mixed_supported_and_unsupported_ingredients" in ids
    assert "interop_mixed_ingredients_valid_lineage" in ids
    assert "interop_c2pa_lineage_digest_mismatch" in ids
    assert "interop_mixed_ingredients_unsupported_lineage_op" in ids
    assert "interop_reject_c2pa_unsupported_algorithm" in ids


def test_corpus_cli_main_returns_zero(capsys: pytest.CaptureFixture[str]) -> None:
    rc = main([str(DEFAULT_CORPUS_PATH)])
    captured = capsys.readouterr()
    assert rc == 0
    assert "0 failed" in captured.out


def test_load_corpus_rejects_malformed_file(tmp_path: Path) -> None:
    bad_file = tmp_path / "bad.json"
    bad_file.write_text("{not valid json", encoding="utf-8")
    with pytest.raises(CorpusFormatError):
        load_corpus(bad_file)


def test_load_corpus_rejects_unsupported_version(tmp_path: Path) -> None:
    bad_ver = tmp_path / "bad_version.json"
    bad_ver.write_text(json.dumps({"corpus_version": 999, "cases": [{}]}), encoding="utf-8")
    with pytest.raises(CorpusFormatError, match="unsupported corpus_version"):
        load_corpus(bad_ver)


def test_run_corpus_rejects_unknown_case_kind(tmp_path: Path) -> None:
    bad_kind = tmp_path / "bad_kind.json"
    bad_kind.write_text(
        json.dumps(
            {
                "corpus_version": CORPUS_SCHEMA_VERSION,
                "cases": [{"id": "unknown", "kind": "mystery", "expected": {}}],
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(CorpusFormatError, match="unsupported corpus case kind"):
        run_corpus(bad_kind)


def test_run_corpus_reports_failure_on_tampered_expected_digest(tmp_path: Path) -> None:
    corpus = load_corpus(DEFAULT_CORPUS_PATH)
    for case in corpus["cases"]:
        if case["id"] == "lineage_valid_compose_max_bounds":
            case["expected"]["lineage_digest"] = "0" * 64
            break

    tampered = tmp_path / "tampered.json"
    tampered.write_text(json.dumps(corpus), encoding="utf-8")
    report = run_corpus(tampered)
    assert report.ok is False
    assert report.failed == 1
    failed_cases = [r for r in report.results if not r.passed]
    assert len(failed_cases) == 1
    assert failed_cases[0].case_id == "lineage_valid_compose_max_bounds"
    assert "lineage_digest mismatch" in failed_cases[0].details
