"""Tests for the conformance suite itself (standard library only):  python -m unittest discover conformance/tests

They prove the *suite* is trustworthy, not just that an implementation passes it:
  * fixtures equal a fresh regeneration and the hash lock (no silent regeneration)
  * the lock refuses an edited case
  * seeded cross-language bugs are DETECTED (the suite fails, and names the right cases)
  * a hostile / broken adapter can neither hang the runner nor leak into a report
  * the runner and reference adapter import nothing outside the standard library
  * a bundle extracted outside the repository runs green with no repository access
"""
import ast
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import textwrap
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPO = ROOT.parent
RUNNER = ROOT / "runner" / "hpx_conformance.py"
REF = ROOT / "adapters" / "reference_py" / "adapter.py"
PY = sys.executable


def run(*args, cwd=None, timeout=300):
    return subprocess.run([PY, *map(str, args)], capture_output=True, text=True, cwd=cwd, timeout=timeout)


def run_suite(adapter_cmd, report, *extra, runner=RUNNER, cwd=None, timeout=300):
    return run(runner, "run", "--adapter", adapter_cmd, "--report", report, "--no-timestamp", *extra, cwd=cwd, timeout=timeout)


class Integrity(unittest.TestCase):
    def test_fixtures_match_fresh_regeneration(self):
        r = run(ROOT / "tools" / "gen_fixtures.py", "--check")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_lock_and_lint(self):
        for cmd in ("check-lock", "lint"):
            r = run(RUNNER, cmd)
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_lock_refuses_an_edited_case(self):
        with tempfile.TemporaryDirectory() as t:
            shutil.copytree(ROOT / "fixtures", Path(t) / "fixtures")
            shutil.copy(ROOT / "manifest.json", t)
            f = Path(t) / "fixtures" / "v1" / "status-semantics.json"
            doc = json.loads(f.read_text())
            doc["cases"][0]["expect"] = {"ok": True, "output": {"status": "valid"}}
            f.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n")
            # Run a copy of the runner rooted at the tampered tree.
            (Path(t) / "runner").mkdir()
            shutil.copy(RUNNER, Path(t) / "runner" / "hpx_conformance.py")
            r = run(Path(t) / "runner" / "hpx_conformance.py", "check-lock")
            self.assertEqual(r.returncode, 3, r.stdout)
            self.assertIn("ss-001", r.stdout)

    def test_generator_refuses_breaking_change_without_version_bump(self):
        # A regeneration that changes an existing case must be refused unless SUITE_VERSION is bumped.
        src = (ROOT / "tools" / "gen_fixtures.py").read_text()
        self.assertIn("REFUSED", src)
        self.assertIn("--allow-breaking", src)

    def test_case_ids_are_unique_and_reason_codes_documented(self):
        ids, codes = set(), set()
        for f in sorted((ROOT / "fixtures").glob("v*/*.json")):
            for c in json.loads(f.read_text())["cases"]:
                self.assertNotIn(c["id"], ids)
                ids.add(c["id"])
                if not c["expect"]["ok"]:
                    codes.add(c["expect"]["code"])
        documented = set(json.loads((ROOT / "reason-codes.json").read_text())["codes"])
        self.assertFalse(codes - documented, f"undocumented: {sorted(codes - documented)}")

    def test_advisory_cases_are_labelled(self):
        for f in sorted((ROOT / "fixtures").glob("v*/*.json")):
            for c in json.loads(f.read_text())["cases"]:
                if c["tier"] == "advisory":
                    self.assertIn(c["advisory_reason"], ("known_defect", "proposed_hardening"), c["id"])

    def test_every_area_has_required_accepting_cases_and_most_have_rejecting_ones(self):
        # status-semantics has no *required* rejection (its only rejections are advisory), error-abi is a lookup table.
        for f in sorted((ROOT / "fixtures").glob("v*/*.json")):
            doc = json.loads(f.read_text())
            oks = {c["expect"]["ok"] for c in doc["cases"] if c["tier"] == "required"}
            self.assertIn(True, oks, doc["area"])
            if doc["area"] not in ("error-abi", "status-semantics", "verification-result"):
                self.assertIn(False, oks, doc["area"])


class ReferenceAdapter(unittest.TestCase):
    def test_reference_adapter_is_fully_conformant(self):
        with tempfile.TemporaryDirectory() as t:
            r = run_suite(f"{PY} {REF}", f"{t}/r.json", "--show-advisory")
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            rep = json.loads(Path(f"{t}/r.json").read_text())
            self.assertEqual(rep["verdict"], "conformant")
            self.assertEqual(rep["totals"]["advisory"]["fail"], 0)
            self.assertEqual(rep["totals"]["required"]["not_implemented"], 0)


class Sensitivity(unittest.TestCase):
    """Seed real cross-language bugs into a copy of the reference adapter; the suite must catch each one."""

    MUTATIONS = {
        "code-point-key-order (Python sorted() default)": (
            'key=lambda k: k.encode("utf-16-be")', "key=lambda k: k", {"cj-pos-007-key-order-utf16"}),
        "ensure_ascii=True on output": (
            'return json.dumps(v, ensure_ascii=False)', 'return json.dumps(v, ensure_ascii=True)', {"cj-pos-005-utf8-literal"}),
        "regex `$` semantics (trailing newline accepted)": (
            'HEX32 = re.compile(r"[0-9a-fA-F]{64}")', 'HEX32 = re.compile(r"[0-9a-fA-F]{64}\\n?")',
            {"me-neg-033-sourceHash-trailing-newline", "pm-neg-032-proofId-trailing-newline"}),
        "scopeName length in code points, not UTF-16 units": (
            'len(n.encode("utf-16-le", "surrogatepass")) // 2 > 128', 'len(n) > 128', {"pm-neg-091-scope-name-65-emoji"}),
        "expiry compared as floats": (
            'int(rec["expiresAt"]) < now', 'float(rec["expiresAt"]) < float(now)', {"vr-018-expires-bigint-precision"}),
        "str.strip() instead of JS trim()": (
            'w = js_trim(w) if isinstance(w, str) else ""', 'w = w.strip() if isinstance(w, str) else ""',
            {"ng-pos-004-bom-trimmed", "ng-neg-016-nel-is-not-js-whitespace"}),
        "revoked outranks nothing (expiry before revocation)": (
            '    if r["status"] == 2:\n        return {"status": "revoked"}\n    if r["status"] == 3:',
            '    if r["expires_at"] > 0 and now > r["expires_at"]:\n        return {"status": "expired"}\n    if r["status"] == 2:\n        return {"status": "revoked"}\n    if r["status"] == 3:',
            {"ss-008-revoked-beats-expired-clock"}),
        "receipt size measured in characters": (
            'len(lenient.encode("utf-8", "surrogatepass")) > MAX_RECEIPT', 'len(lenient) > MAX_RECEIPT', {"rc-neg-037-size-counts-bytes-not-chars"}),
        "u64 event field accepted as JSON number": (
            'if not (isinstance(v, str) and DEC.fullmatch(v)):\n            t()\n        if int(v) > U64:',
            'if not ((isinstance(v, str) and DEC.fullmatch(v)) or is_int(v)):\n            t()\n        if int(v) > U64:', {"ev-neg-045-u64-number"}),
        "privacy scan skipped": (
            "    _scan(data)\n    if not isinstance(topics, list):", "    if not isinstance(topics, list):", {"ev-neg-001-privacy-nullifier"}),
    }

    def test_each_seeded_bug_is_detected(self):
        src = REF.read_text()
        with tempfile.TemporaryDirectory() as t:
            for name, (old, new, expect_ids) in self.MUTATIONS.items():
                with self.subTest(name):
                    self.assertIn(old, src, f"mutation target vanished from the adapter: {name}")
                    mutated = Path(t) / "mut_adapter.py"
                    mutated.write_text(src.replace(old, new))
                    rep = f"{t}/m.json"
                    r = run_suite(f"{PY} {mutated}", rep, "--repeat", "1", "--tier", "required")
                    self.assertEqual(r.returncode, 1, f"suite did not fail for: {name}\n{r.stdout}")
                    failed = {f["id"] for f in json.loads(Path(rep).read_text())["failures"]}
                    self.assertTrue(expect_ids <= failed, f"{name}: expected {sorted(expect_ids)} to fail, got {sorted(failed)[:8]}")


HANG = "import sys,time\nfor l in sys.stdin:\n    time.sleep(999)\n"
GARBAGE = 'import sys,json\nfor l in sys.stdin:\n    r=json.loads(l)\n    print("not json" if r["op"]!="hello" else json.dumps({"id":r["id"],"ok":True,"output":{"protocol":"hpx-conformance-adapter/1","ops":["canonicalize"]}}),flush=True)\n'
WRONG_ID = 'import sys,json\nfor l in sys.stdin:\n    r=json.loads(l)\n    print(json.dumps({"id":"x","ok":True,"output":{}}),flush=True)\n'
NOISY_LEAKY = textwrap.dedent('''
    import sys, json
    SECRET = "S3CR3T-MARKER-ZZZ"
    for l in sys.stdin:
        r = json.loads(l)
        if r["op"] == "hello":
            print(json.dumps({"id": r["id"], "ok": True, "output": {"protocol": "hpx-conformance-adapter/1", "ops": ["canonicalize"]}}), flush=True)
        else:
            sys.stderr.write(SECRET + "\\n")
            print(json.dumps({"id": r["id"], "ok": True, "output": {"leak": SECRET}, "extra": SECRET}), flush=True)
''')
NONDET = textwrap.dedent('''
    import sys, json, itertools
    n = itertools.count()
    for l in sys.stdin:
        r = json.loads(l)
        if r["op"] == "hello":
            print(json.dumps({"id": r["id"], "ok": True, "output": {"protocol": "hpx-conformance-adapter/1", "ops": ["canonicalize"]}}), flush=True)
        else:
            print(json.dumps({"id": r["id"], "ok": False, "code": "invalid_json" if next(n) % 2 else "other"}), flush=True)
''')


class HostileAdapters(unittest.TestCase):
    def _try(self, source, *extra):
        with tempfile.TemporaryDirectory() as t:
            p = Path(t) / "a.py"
            p.write_text(source)
            r = run_suite(f"{PY} {p}", f"{t}/r.json", "--areas", "canonical-json", "--timeout", "1", *extra, timeout=120)
            rep = Path(f"{t}/r.json")
            return r, (rep.read_text() if rep.exists() else "")

    def test_hanging_adapter_aborts_bounded(self):
        r, _ = self._try(HANG)
        self.assertEqual(r.returncode, 2, r.stdout + r.stderr)

    def test_garbage_output_is_an_error_not_a_pass(self):
        r, rep = self._try(GARBAGE)
        self.assertNotEqual(r.returncode, 0)

    def test_wrong_response_id_is_rejected(self):
        r, _ = self._try(WRONG_ID)
        self.assertNotEqual(r.returncode, 0)

    def test_adapter_that_does_not_speak_the_protocol_is_rejected(self):
        r, _ = self._try("print('hello world')")
        self.assertEqual(r.returncode, 2)

    def test_report_never_contains_raw_adapter_output_or_stderr(self):
        r, rep = self._try(NOISY_LEAKY)
        self.assertNotIn("S3CR3T-MARKER-ZZZ", rep)
        self.assertNotIn("S3CR3T-MARKER-ZZZ", r.stdout + r.stderr)

    def test_nondeterministic_adapter_fails(self):
        r, rep = self._try(NONDET, "--repeat", "2")
        self.assertEqual(r.returncode, 1)
        self.assertIn("nondeterministic", rep)

    def test_partial_adapter_is_incomplete_not_conformant(self):
        with tempfile.TemporaryDirectory() as t:
            r = run_suite(f"node {ROOT}/adapters/skeleton/adapter.js", f"{t}/r.json") if shutil.which("node") else None
            if r is None:
                self.skipTest("node not available")
            rep = json.loads(Path(f"{t}/r.json").read_text())
            self.assertEqual(rep["verdict"], "incomplete")
            self.assertEqual(r.returncode, 1)
            self.assertEqual(rep["totals"]["required"]["fail"], 0)
            # ...and the one op the skeleton implements really is checked.
            self.assertGreater(rep["totals"]["required"]["pass"], 0)
            r2 = run_suite(f"node {ROOT}/adapters/skeleton/adapter.js", f"{t}/r2.json", "--allow-missing-ops")
            self.assertEqual(r2.returncode, 0, r2.stdout)


class Independence(unittest.TestCase):
    def test_runner_and_reference_adapter_import_only_the_standard_library(self):
        for path in (RUNNER, REF):
            tree = ast.parse(path.read_text())
            mods = set()
            for n in ast.walk(tree):
                if isinstance(n, ast.Import):
                    mods |= {a.name.split(".")[0] for a in n.names}
                elif isinstance(n, ast.ImportFrom) and n.level == 0:
                    mods.add(n.module.split(".")[0])
            self.assertFalse(mods - set(sys.stdlib_module_names), f"{path.name} imports non-stdlib: {mods - set(sys.stdlib_module_names)}")

    def test_bundle_runs_green_outside_the_repository(self):
        with tempfile.TemporaryDirectory() as t:
            b1, b2 = Path(t) / "a.tgz", Path(t) / "b.tgz"
            self.assertEqual(run(ROOT / "tools" / "bundle.py", "--out", b1).returncode, 0)
            self.assertEqual(run(ROOT / "tools" / "bundle.py", "--out", b2).returncode, 0)
            self.assertEqual(b1.read_bytes(), b2.read_bytes(), "bundle must be byte-reproducible")
            with tarfile.open(b1) as tar:
                tar.extractall(Path(t) / "x", filter="data")
            root = next((Path(t) / "x").iterdir())
            names = {p.name for p in root.rglob("*") if p.is_file()}
            self.assertNotIn("adapter.ts", names, "the repo-bound TS adapter must not ship in the bundle")
            self.assertNotIn("gen_fixtures.py", names)
            env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
            r = subprocess.run([PY, str(root / "conformance/runner/hpx_conformance.py"), "run", "--adapter",
                                f"{PY} {root}/conformance/adapters/reference_py/adapter.py", "--report", f"{t}/o.json"],
                               capture_output=True, text=True, cwd=t, env=env, timeout=300)
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            self.assertIn("CONFORMANT", r.stdout)
            self.assertEqual(run(root / "conformance/runner/hpx_conformance.py", "check-lock", cwd=t).returncode, 0)

    def test_runner_refuses_a_tampered_external_corpus(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            shutil.copytree(ROOT, root / "conformance", ignore=shutil.ignore_patterns("__pycache__", "tools", "tests"))
            (root / "zk" / "vectors").mkdir(parents=True)
            for n in ("verifier_conformance_v1.json", "malformed_public_inputs_v1.json"):
                shutil.copy(REPO / "zk" / "vectors" / n, root / "zk" / "vectors" / n)
            f = root / "zk" / "vectors" / "verifier_conformance_v1.json"
            doc = json.loads(f.read_text())
            doc["cases"][0]["expect"]["accept"] = False           # weakening a shared corpus
            f.write_text(json.dumps(doc, indent=2) + "\n")
            (root / "contracts").mkdir()
            shutil.copy(REPO / "contracts" / "ERROR_ABI.md", root / "contracts" / "ERROR_ABI.md")
            r = run(root / "conformance/runner/hpx_conformance.py", "run", "--adapter",
                    f"{PY} {root}/conformance/adapters/reference_py/adapter.py")
            self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
            self.assertIn("pinned SHA-256", r.stderr)


if __name__ == "__main__":
    unittest.main()
