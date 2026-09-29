"""Shared helpers for the conformance fixture generator.

Every digest in the fixtures is derived from a public label so the values are
reproducibly synthetic: sha256("hpx-conformance/v1/" + label). No real video,
witness, nullifier, credential secret, or key material is used anywhere.
"""
import hashlib
import json

SUITE_VERSION = "1.0.0"
FIXTURE_VERSION = 1


def syn(label: str) -> str:
    return hashlib.sha256(b"hpx-conformance/v1/" + label.encode()).hexdigest()


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class Area:
    """Collects cases for one fixture file and enforces unique ids."""

    def __init__(self, area: str, title: str):
        self.area, self.title, self.cases, self._ids = area, title, [], set()
        self.extras = {}

    def add(self, cid, op, inp, *, ok=None, code=None, detail=None, desc="",
            tier="required", why=None):
        assert cid not in self._ids, f"duplicate case id {cid}"
        self._ids.add(cid)
        if code is not None:
            expect = {"ok": False, "code": code}
            if detail:
                expect["detail"] = detail
        else:
            expect = {"ok": True, "output": ok if ok is not None else {}}
        case = {"id": cid, "op": op, "tier": tier, "description": desc,
                "input": inp, "expect": expect}
        if tier == "advisory":
            assert why in ("known_defect", "proposed_hardening"), cid
            case["advisory_reason"] = why
        self.cases.append(case)

    def doc(self):
        return {
            "format": "harpocrates.conformance",
            "suite_version": SUITE_VERSION,
            "fixture_version": FIXTURE_VERSION,
            "area": self.area,
            "title": self.title,
            "synthetic": True,
            "cases": self.cases,
            **self.extras,
        }


def dumps(doc) -> str:
    # ASCII-only, sorted, stable: file bytes are identical on every platform.
    return json.dumps(doc, indent=2, sort_keys=True, ensure_ascii=True) + "\n"
