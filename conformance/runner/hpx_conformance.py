#!/usr/bin/env python3
"""Harpocrates black-box conformance runner.

Standard library only; no import from anywhere else in the repository. It reads
the fixtures as plain JSON and talks to the implementation under test through an
*adapter*: any executable that speaks line-delimited JSON on stdin/stdout
(protocol `hpx-conformance-adapter/1`, see conformance/README.md).

    hpx_conformance.py run --adapter "node adapter.js" [--areas a,b] [--report r.json]
    hpx_conformance.py check-lock          # fixtures still equal the committed hash lock
    hpx_conformance.py lint                # fixtures are synthetic and contain no secret-shaped values
    hpx_conformance.py matrix --reports DIR --out matrix.md

Exit codes: 0 conformant, 1 required case failed / missing, 2 harness or protocol error, 3 lock/lint failure.

Privacy: the report records case ids, machine codes and SHA-256 digests of
outputs. It never stores raw adapter output, so pointing the runner at a deployed
harness cannot copy secrets into CI artifacts. Adapter stderr is discarded.
"""
import argparse
import hashlib
import json
import os
import queue
import re
import shlex
import subprocess
import sys
import threading
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent                          # conformance/
PROTOCOL = "hpx-conformance-adapter/1"
MAX_LINE = 1 << 20                          # adapters may not answer with more than 1 MiB per case
MAX_RESTARTS = 5


# --------------------------------------------------------------------------- util
def cjson(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def digest(value) -> str:
    return hashlib.sha256(cjson(value).encode()).hexdigest()


def load(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def fixture_files(root: Path):
    return sorted((root / "fixtures").glob("v*/*.json"))


# --------------------------------------------------------------------------- adapter
class AdapterError(Exception):
    pass


class Adapter:
    def __init__(self, cmd: str, timeout: float, show_stderr: bool):
        self.cmd, self.timeout, self.show_stderr = shlex.split(cmd, posix=os.name != "nt"), timeout, show_stderr
        self.proc = None
        self.lines = None
        self.restarts = 0
        self.hello = None

    def start(self):
        self.proc = subprocess.Popen(self.cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                     stderr=None if self.show_stderr else subprocess.DEVNULL, bufsize=0)
        self.lines = queue.Queue()
        threading.Thread(target=self._pump, args=(self.proc, self.lines), daemon=True).start()
        self.hello = self.call({"id": "hello", "op": "hello", "input": {}})
        out = self.hello.get("output") if self.hello.get("ok") else None
        if not isinstance(out, dict) or out.get("protocol") != PROTOCOL or not isinstance(out.get("ops"), list):
            raise AdapterError(f"adapter did not answer hello with protocol {PROTOCOL}")

    @staticmethod
    def _pump(proc, q):
        try:
            while True:
                line = proc.stdout.readline(MAX_LINE + 2)
                if not line:
                    q.put(None)
                    return
                q.put(line if len(line) <= MAX_LINE + 1 else b"\x00TOOLONG")
        except Exception:  # noqa: BLE001 - reader thread must never raise into the interpreter
            q.put(None)

    def call(self, req: dict) -> dict:
        try:
            self.proc.stdin.write((cjson(req) + "\n").encode())
            self.proc.stdin.flush()
        except (BrokenPipeError, OSError) as e:
            raise AdapterError("adapter closed its input") from e
        try:
            raw = self.lines.get(timeout=self.timeout)
        except queue.Empty as e:
            self.kill()
            raise AdapterError(f"timeout after {self.timeout}s") from e
        if raw is None:
            raise AdapterError("adapter exited")
        if raw == b"\x00TOOLONG":
            self.kill()
            raise AdapterError("response exceeded 1 MiB")
        try:
            resp = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as e:
            raise AdapterError("response is not a JSON line") from e
        if not isinstance(resp, dict) or resp.get("id") != req["id"] or not isinstance(resp.get("ok"), bool):
            raise AdapterError("response has the wrong id or no boolean `ok`")
        return resp

    def kill(self):
        if self.proc and self.proc.poll() is None:
            self.proc.kill()

    def restart(self):
        self.kill()
        self.restarts += 1
        if self.restarts > MAX_RESTARTS:
            raise AdapterError("adapter restarted too many times")
        self.start()

    def close(self):
        try:
            if self.proc and self.proc.poll() is None:
                self.proc.stdin.close()
                self.proc.wait(timeout=2)
        except Exception:  # noqa: BLE001
            self.kill()


# --------------------------------------------------------------------------- cases
def load_cases(root: Path, areas, tier):
    cases = []
    for f in fixture_files(root):
        doc = load(f)
        if areas and doc["area"] not in areas:
            continue
        for c in doc["cases"]:
            if tier == "required" and c["tier"] != "required":
                continue
            cases.append(dict(c, area=doc["area"]))
    return cases


def corpus_cases(root: Path, corpus_root: Path, areas, notes):
    """Cases drawn from the existing zk/vectors corpora by reference (never copied)."""
    man = load(root / "manifest.json")
    out = []
    for entry in man["external_corpora"]:
        area = "public-inputs" if entry["role"] == "classify_public_inputs" else "malformed-hex"
        if areas and area not in areas:
            continue
        p = corpus_root / entry["path"]
        if not p.exists():
            notes.append(f"{area}: corpus {entry['path']} not found under {corpus_root}; area skipped")
            continue
        if hashlib.sha256(p.read_bytes()).hexdigest() != entry["sha256"]:
            raise AdapterError(f"corpus {entry['path']} does not match its pinned SHA-256; refusing to run")
        doc = load(p)
        for c in doc["cases"]:
            if entry["role"] == "classify_public_inputs":
                exp = ({"ok": True, "output": {"accepted": True}} if c["expect"]["accept"]
                       else {"ok": False, "code": c["expect"]["reject_code"]})
                inp = {"schema": c["schema"], "public_inputs_hex": c["public_inputs_hex"], "proof_hex": c["proof_hex"]}
                op = "classify_public_inputs"
            else:
                exp = {"ok": False, "code": c["expect"]["reject_code"]}
                inp = {"field": c["field"], "value": c["value"]}
                op = "decode_public_inputs_hex"
            out.append({"id": f"{area}/{c['id']}", "op": op, "tier": "required", "input": inp, "expect": exp,
                        "description": c.get("description", ""), "area": area})
    return out


def judge(case, resp):
    """Return (status, reason). Compares only machine-readable fields."""
    exp = case["expect"]
    if not resp["ok"] and resp.get("code") == "unsupported_op":
        return "not_implemented", "adapter reports unsupported_op"
    if exp["ok"]:
        if not resp["ok"]:
            return "fail", f"expected success, got code {resp.get('code')!r}"
        if cjson(resp.get("output")) != cjson(exp["output"]):
            return "fail", f"output differs (expected sha256 {digest(exp['output'])[:16]}, got {digest(resp.get('output'))[:16]})"
        return "pass", ""
    if resp["ok"]:
        return "fail", f"expected code {exp['code']!r}, got success (output sha256 {digest(resp.get('output'))[:16]})"
    if resp.get("code") != exp["code"]:
        return "fail", f"expected code {exp['code']!r}, got {resp.get('code')!r}"
    for k, v in (exp.get("detail") or {}).items():
        got = (resp.get("detail") or {}).get(k)
        if cjson(got) != cjson(v):
            return "fail", f"detail.{k} differs (expected sha256 {digest(v)[:16]}, got {digest(got)[:16]})"
    return "pass", ""


def run(args) -> int:
    root = ROOT
    areas = set(filter(None, (args.areas or "").split(",")))
    try:
        lock_problems = verify_lock(root, quiet=True)
        if lock_problems and not args.ignore_lock:
            print("fixtures do not match the committed lock (run `check-lock`):", *lock_problems[:5], sep="\n  ")
            return 3
        notes = []
        cases = load_cases(root, areas, args.tier)
        corpus_root = Path(args.corpus_root) if args.corpus_root else root.parent
        cases += corpus_cases(root, corpus_root, areas, notes)
        ad = Adapter(args.adapter, args.timeout, args.adapter_stderr)
        ad.start()
    except AdapterError as e:
        print(f"harness error: {e}", file=sys.stderr)
        return 2

    supported = set(ad.hello["output"]["ops"])
    impl = ad.hello["output"].get("implementation", {})
    results = []
    t0 = time.time()
    for c in cases:
        rec = {"id": c["id"], "area": c["area"], "tier": c["tier"], "op": c["op"]}
        if c["tier"] == "advisory":
            rec["advisory_reason"] = c.get("advisory_reason")
        if c["op"] not in supported:
            rec.update(status="not_implemented", reason="op not advertised in hello")
            results.append(rec)
            continue
        try:
            first = None
            for i in range(max(1, args.repeat)):
                resp = ad.call({"id": f"{c['id']}#{i}", "op": c["op"], "input": c["input"]})
                resp_cmp = {k: v for k, v in resp.items() if k != "id"}
                if first is None:
                    first, first_resp = resp_cmp, resp
                elif cjson(first) != cjson(resp_cmp):
                    raise ValueError("nondeterministic: repeated identical request returned a different response")
            status, reason = judge(c, first_resp)
        except ValueError as e:
            status, reason = "fail", str(e)
        except AdapterError as e:
            status, reason = "error", str(e)
            try:
                ad.restart()
            except AdapterError as e2:
                rec.update(status="error", reason=str(e2))
                results.append(rec)
                print(f"harness error: {e2}", file=sys.stderr)
                return finish(args, results, impl, notes, t0, aborted=True)
        rec["status"] = status
        if reason:
            rec["reason"] = reason
        results.append(rec)
    ad.close()
    return finish(args, results, impl, notes, t0)


def summarize(results):
    areas = {}
    for r in results:
        s = areas.setdefault(r["area"], {"required": dict(pass_=0, fail=0, not_implemented=0, error=0),
                                          "advisory": dict(pass_=0, fail=0, not_implemented=0, error=0)})
        s["required" if r["tier"] == "required" else "advisory"]["pass_" if r["status"] == "pass" else r["status"]] += 1
    for s in areas.values():
        for t in s.values():
            t["pass"] = t.pop("pass_")
    return areas


def finish(args, results, impl, notes, t0, aborted=False) -> int:
    man = load(ROOT / "manifest.json")
    areas = summarize(results)
    req = [r for r in results if r["tier"] == "required"]
    failed = [r for r in req if r["status"] in ("fail", "error")]
    missing = [r for r in req if r["status"] == "not_implemented"]
    if aborted:
        verdict = "aborted"
    elif failed:
        verdict = "non-conformant"
    elif missing and not args.allow_missing_ops:
        verdict = "incomplete"
    elif missing:
        verdict = "partial"        # every implemented op passes; some required ops were not implemented (explicitly allowed)
    else:
        verdict = "conformant"
    report = {
        "format": "harpocrates.conformance.report", "suite_version": man["suite_version"], "fixture_version": man["fixture_version"],
        "implementation": {k: impl.get(k) for k in ("name", "version", "language")},
        "verdict": verdict, "allow_missing_ops": bool(args.allow_missing_ops), "notes": notes,
        "totals": {"required": {s: sum(1 for r in req if r["status"] == s) for s in ("pass", "fail", "not_implemented", "error")},
                   "advisory": {s: sum(1 for r in results if r["tier"] == "advisory" and r["status"] == s)
                                for s in ("pass", "fail", "not_implemented", "error")}},
        "areas": areas,
        "failures": [r for r in results if r["status"] in ("fail", "error") ],
    }
    if not args.no_timestamp:
        report["generated_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        report["duration_s"] = round(time.time() - t0, 2)
    if args.report:
        Path(args.report).parent.mkdir(parents=True, exist_ok=True)
        Path(args.report).write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    t = report["totals"]
    print(f"{impl.get('name', '?')} {impl.get('version', '')}: {verdict.upper()}  "
          f"required pass={t['required']['pass']} fail={t['required']['fail']} n/i={t['required']['not_implemented']} err={t['required']['error']}  "
          f"| advisory pass={t['advisory']['pass']} fail={t['advisory']['fail']} n/i={t['advisory']['not_implemented']}")
    for n in notes:
        print("  note:", n)
    shown = 0
    for r in failed:
        if shown < args.show:
            print(f"  FAIL {r['id']}: {r.get('reason', '')}")
            shown += 1
    if len(failed) > shown:
        print(f"  ... {len(failed) - shown} more (see report)")
    if args.show_advisory:
        for r in results:
            if r["tier"] == "advisory" and r["status"] == "fail":
                print(f"  ADVISORY[{r.get('advisory_reason')}] {r['id']}: {r.get('reason', '')}")
    return {"conformant": 0, "partial": 0, "non-conformant": 1, "incomplete": 1, "aborted": 2}[verdict]


# --------------------------------------------------------------------------- lock + lint
def verify_lock(root: Path, quiet=False):
    man = load(root / "manifest.json")
    problems = []
    for rel, sha in man["files"].items():
        p = root / rel
        if not p.exists():
            problems.append(f"missing file {rel}")
        elif hashlib.sha256(p.read_bytes()).hexdigest() != sha:
            problems.append(f"file changed: {rel}")
    seen = {}
    for f in fixture_files(root):
        for c in load(f)["cases"]:
            c2 = dict(c)
            seen[c["id"]] = hashlib.sha256(json.dumps(c2, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()).hexdigest()
    for cid, d in man["cases"].items():
        if cid not in seen:
            problems.append(f"case removed: {cid}")
        elif seen[cid] != d:
            problems.append(f"case changed: {cid}")
    for cid in seen:
        if cid not in man["cases"]:
            problems.append(f"case not in lock: {cid}")
    return problems


def cmd_check_lock(args) -> int:
    problems = verify_lock(ROOT)
    man = load(ROOT / "manifest.json")
    corpus_root = Path(args.corpus_root) if args.corpus_root else ROOT.parent
    for e in man["external_corpora"]:
        p = corpus_root / e["path"]
        if p.exists() and hashlib.sha256(p.read_bytes()).hexdigest() != e["sha256"]:
            problems.append(f"external corpus changed: {e['path']} (bump the suite or re-pin deliberately)")
    if problems:
        print("LOCK FAILURE:", *problems[:20], sep="\n  ")
        return 3
    print(f"ok: {len(man['cases'])} cases, {len(man['files'])} files match the lock")
    return 0


SECRET_SHAPES = [re.compile(r"\bS[A-Z2-7]{55}\b"), re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), re.compile(r'"d"\s*:\s*"[A-Za-z0-9_-]{40,}"'),
                 re.compile(r"\bAKIA[0-9A-Z]{16}\b"), re.compile(r"\b(?:ghp|gho|ghs|xox[abp])_?[A-Za-z0-9-]{20,}\b")]


def cmd_lint(_args) -> int:
    problems = []
    for f in fixture_files(ROOT):
        text = f.read_text(encoding="utf-8")
        doc = json.loads(text)
        if doc.get("synthetic") is not True:
            problems.append(f"{f.name}: missing synthetic=true")
        for rx in SECRET_SHAPES:
            if rx.search(text):
                problems.append(f"{f.name}: secret-shaped value matches {rx.pattern[:24]}")
        if doc["area"] != "events":
            forbidden = set(load(next(p for p in fixture_files(ROOT) if p.name == "events.json"))["forbidden_field_names"])

            def walk(o, path=""):
                if isinstance(o, dict):
                    for k, v in o.items():
                        if k.lower() in forbidden:
                            problems.append(f"{f.name}:{path}/{k}: forbidden field name outside the events area")
                        walk(v, f"{path}/{k}")
                elif isinstance(o, list):
                    for i, v in enumerate(o):
                        walk(v, f"{path}[{i}]")
            for c in doc["cases"]:
                walk(c["input"], c["id"])
    if problems:
        print("LINT FAILURE:", *problems[:20], sep="\n  ")
        return 3
    print("ok: fixtures are marked synthetic and contain no secret-shaped values")
    return 0


# --------------------------------------------------------------------------- matrix
def cmd_matrix(args) -> int:
    reports = [load(p) for p in sorted(Path(args.reports).glob("*.json"))]
    reports = [r for r in reports if r.get("format") == "harpocrates.conformance.report"]
    if not reports:
        print("no reports found", file=sys.stderr)
        return 2
    names = [f"{r['implementation'].get('name')} {r['implementation'].get('version') or ''}".strip() for r in reports]
    areas = sorted({a for r in reports for a in r["areas"]})

    def cell(r, a):
        s = r["areas"].get(a)
        if not s:
            return "n/a"
        q, v = s["required"], s["advisory"]
        total = sum(q.values())
        if total and q["not_implemented"] == total:
            txt = "not implemented"
        elif q["fail"] or q["error"]:
            txt = f"FAIL {q['pass']}/{total}"
        elif q["not_implemented"]:
            txt = f"partial {q['pass']}/{total}"
        else:
            txt = f"pass {q['pass']}/{total}"
        vt = sum(v.values())
        if vt:
            txt += f" (adv {v['pass']}/{vt})"
        return txt

    lines = [f"# Harpocrates conformance compatibility matrix", "",
             f"Suite {reports[0]['suite_version']}, fixtures v{reports[0]['fixture_version']}. "
             "`adv` = advisory cases (known defects / proposed hardening); they never gate.", "",
             "| Area | " + " | ".join(names) + " |", "|---|" + "---|" * len(names)]
    for a in areas:
        lines.append(f"| {a} | " + " | ".join(cell(r, a) for r in reports) + " |")
    lines.append("| **verdict** | " + " | ".join(f"**{r['verdict']}**" for r in reports) + " |")
    Path(args.out).write_text("\n".join(lines) + "\n", encoding="utf-8")
    Path(args.out).with_suffix(".json").write_text(json.dumps(
        {"suite_version": reports[0]["suite_version"], "implementations": names,
         "areas": {a: {n: r["areas"].get(a) for n, r in zip(names, reports)} for a in areas},
         "verdicts": dict(zip(names, (r["verdict"] for r in reports)))}, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print("\n".join(lines))
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run")
    r.add_argument("--adapter", required=True, help="command that starts the adapter (line-delimited JSON on stdio)")
    r.add_argument("--areas", help="comma-separated area names (default: all)")
    r.add_argument("--tier", choices=["required", "all"], default="all", help="which cases to execute (advisory never gates)")
    r.add_argument("--corpus-root", help="directory containing zk/vectors/*.json (default: parent of conformance/)")
    r.add_argument("--report", help="write the JSON report here")
    r.add_argument("--repeat", type=int, default=2, help="send each request N times and require identical answers")
    r.add_argument("--timeout", type=float, default=10.0, help="per-request timeout in seconds")
    r.add_argument("--allow-missing-ops", action="store_true", help="operations the adapter does not implement do not fail the run")
    r.add_argument("--ignore-lock", action="store_true")
    r.add_argument("--no-timestamp", action="store_true")
    r.add_argument("--show", type=int, default=10)
    r.add_argument("--show-advisory", action="store_true")
    r.add_argument("--adapter-stderr", action="store_true", help="pass adapter stderr through (debugging only)")
    for name in ("check-lock", "lint"):
        p = sub.add_parser(name)
        p.add_argument("--corpus-root")
    m = sub.add_parser("matrix")
    m.add_argument("--reports", required=True)
    m.add_argument("--out", required=True)
    a = ap.parse_args()
    return {"run": run, "check-lock": cmd_check_lock, "lint": cmd_lint, "matrix": cmd_matrix}[a.cmd](a)


if __name__ == "__main__":
    sys.exit(main())
