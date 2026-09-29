#!/usr/bin/env python3
"""Build the self-contained, deterministic third-party bundle.

    python conformance/tools/bundle.py --out dist/harpocrates-conformance-1.0.0.tar.gz

The bundle keeps repository-relative paths, so `conformance/runner/hpx_conformance.py` finds the two
pinned zk/vectors corpora (and the reference adapter finds contracts/ERROR_ABI.md) with no flags.
It contains no TypeScript adapter (that one is bound to this repository's sources) and no generator
(it needs the `cryptography` package; consumers only need Python's standard library).
"""
import argparse
import gzip
import io
import json
import sys
import tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPO = ROOT.parent
INCLUDE_DIRS = ["conformance/fixtures", "conformance/runner", "conformance/adapters/reference_py", "conformance/adapters/skeleton"]
INCLUDE_FILES = ["conformance/README.md", "conformance/manifest.json", "conformance/reason-codes.json",
                 "zk/vectors/verifier_conformance_v1.json", "zk/vectors/malformed_public_inputs_v1.json", "contracts/ERROR_ABI.md"]


def files():
    out = set(INCLUDE_FILES)
    for d in INCLUDE_DIRS:
        out |= {str(p.relative_to(REPO)).replace("\\", "/") for p in (REPO / d).rglob("*") if p.is_file() and "__pycache__" not in p.parts}
    return sorted(out)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    version = json.loads((ROOT / "manifest.json").read_text())["suite_version"]
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        for rel in files():
            data = (REPO / rel).read_bytes()
            ti = tarfile.TarInfo(f"harpocrates-conformance-{version}/{rel}")
            ti.size, ti.mtime, ti.uid, ti.gid, ti.uname, ti.gname = len(data), 0, 0, 0, "", ""
            ti.mode = 0o755 if rel.endswith((".py", ".js")) and "/adapters/" in rel or rel.endswith("hpx_conformance.py") else 0o644
            tar.addfile(ti, io.BytesIO(data))
    Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    with open(a.out, "wb") as f, gzip.GzipFile(filename="", fileobj=f, mode="wb", mtime=0) as gz:
        gz.write(buf.getvalue())
    print(f"wrote {a.out} ({len(files())} files)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
