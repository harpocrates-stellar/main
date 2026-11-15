"""Focused devx coverage for the circuit build dependency graph (#1215)."""

from __future__ import annotations

import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stderr
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
ZK_TOOLS = REPO_ROOT / "zk" / "tools"
for candidate in (str(REPO_ROOT), str(ZK_TOOLS)):
    if candidate not in sys.path:
        sys.path.insert(0, candidate)

import artifact_manifest as am
import build_circuits as bc


class CircuitDependencyGraphTest(unittest.TestCase):
    def _build_fixture_tree(self, root: Path) -> Path:
        common = root / "zk" / "noir" / "harpocrates_common"
        (common / "src").mkdir(parents=True)
        (common / "Nargo.toml").write_text(
            '[package]\nname = "harpocrates_common"\ntype = "lib"\n',
            encoding="utf-8",
        )
        (common / "src" / "lib.nr").write_text(
            "pub fn domain_tag() -> Field { 7 }\n",
            encoding="utf-8",
        )

        helper = root / "zk" / "noir" / "silent_witness_helper"
        (helper / "src").mkdir(parents=True)
        (helper / "Nargo.toml").write_text(
            '[package]\nname = "silent_witness_helper"\ntype = "bin"\n\n'
            '[dependencies]\nharpocrates_common = { path = "../harpocrates_common" }\n',
            encoding="utf-8",
        )
        (helper / "src" / "main.nr").write_text("fn main() {}\n", encoding="utf-8")

        sw = root / "zk" / "noir" / "silent_witness"
        (sw / "src").mkdir(parents=True)
        (sw / "Nargo.toml").write_text(
            '[package]\nname = "silent_witness"\ntype = "bin"\n\n'
            '[dependencies]\nharpocrates_common = { path = "../harpocrates_common" }\n',
            encoding="utf-8",
        )
        (sw / "src" / "main.nr").write_text("fn main() {}\n", encoding="utf-8")

        raw_lock = json.loads((REPO_ROOT / "zk" / "toolchain.lock.json").read_text(encoding="utf-8"))
        raw_lock["artifacts"] = [
            {
                "path": "zk/noir/silent_witness/target/silent_witness.json",
                "kind": "json",
                "role": "acir",
                "required": True,
            },
            {
                "path": "zk/noir/silent_witness/target/vk",
                "kind": "binary",
                "role": "verification_key",
                "required": True,
            },
            {
                "path": "zk/noir/silent_witness/target/vk_fields.json",
                "kind": "json",
                "role": "verification_key_fields",
                "required": True,
            },
            {
                "path": "zk/noir/silent_witness_helper/target/silent_witness_helper.json",
                "kind": "json",
                "role": "acir",
                "required": True,
            },
            {
                "path": "frontend/public/noir/silent_witness.json",
                "kind": "json",
                "role": "published_acir",
                "required": False,
            },
        ]
        lock_file = root / "zk" / "toolchain.lock.json"
        lock_file.write_text(json.dumps(raw_lock, indent=2), encoding="utf-8")
        return lock_file

    def test_helper_edit_and_missing_upstream_surface_before_packaging(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "workspace"
            lock_file = self._build_fixture_tree(root)

            for p in root.rglob("*"):
                if p.is_file():
                    os.utime(p, ns=(1_000_000_000, 1_000_000_000))

            sw_tgt = root / "zk" / "noir" / "silent_witness" / "target"
            hlp_tgt = root / "zk" / "noir" / "silent_witness_helper" / "target"
            pub_dir = root / "frontend" / "public" / "noir"
            sw_tgt.mkdir(parents=True)
            hlp_tgt.mkdir(parents=True)
            pub_dir.mkdir(parents=True)

            acir_payload = b'{"bytecode":"CANONICAL_SW_V1","debug_symbols":"x"}'
            (sw_tgt / "silent_witness.json").write_bytes(acir_payload)
            (hlp_tgt / "silent_witness_helper.json").write_bytes(b'{"bytecode":"HLP"}')
            (sw_tgt / "vk").write_bytes(b"\x00\x00\x00\x00" + (b"\x33" * 1760))
            (sw_tgt / "vk_fields.json").write_text('["0x01"]', encoding="utf-8")
            (pub_dir / "silent_witness.json").write_bytes(acir_payload)

            for built, ts in (
                (sw_tgt / "silent_witness.json", 2_000_000_000),
                (hlp_tgt / "silent_witness_helper.json", 2_000_000_000),
                (sw_tgt / "vk", 2_100_000_000),
                (sw_tgt / "vk_fields.json", 2_100_000_000),
                (pub_dir / "silent_witness.json", 2_200_000_000),
            ):
                os.utime(built, ns=(ts, ts))

            lock = am.load_lock(lock_file)
            with redirect_stderr(io.StringIO()):
                clean = am.build_dependency_graph(
                    lock,
                    root,
                    lock_path=lock_file,
                    packaging=True,
                )
            self.assertTrue(clean["ready_for_packaging"])
            self.assertEqual(clean["stale_artifacts"], [])

            # Determinism & privacy check: no host path or secret bytecode in graph JSON.
            serialized = am.serialize_manifest(clean)
            self.assertNotIn(str(root), serialized)
            self.assertNotIn("CANONICAL_SW_V1", serialized)

            # Mutate shared helper library `harpocrates_common/src/lib.nr` at T=3000.
            common_lib = root / "zk" / "noir" / "harpocrates_common" / "src" / "lib.nr"
            common_lib.write_text("pub fn domain_tag() -> Field { 8 }\n", encoding="utf-8")
            os.utime(common_lib, ns=(3_000_000_000, 3_000_000_000))

            with redirect_stderr(io.StringIO()):
                after_helper_edit = am.build_dependency_graph(
                    lock,
                    root,
                    lock_path=lock_file,
                    packaging=True,
                )
            self.assertFalse(after_helper_edit["ready_for_packaging"])
            stale_map = {
                entry["path"]: entry["reasons"]
                for entry in after_helper_edit["stale_artifacts"]
            }
            self.assertIn(
                "older_than_helper_dependency",
                stale_map["zk/noir/silent_witness/target/silent_witness.json"],
            )
            self.assertIn(
                "upstream_artifact_stale",
                stale_map["zk/noir/silent_witness/target/vk"],
            )
            self.assertIn(
                "upstream_artifact_stale",
                stale_map["frontend/public/noir/silent_witness.json"],
            )

            # Remove upstream target ACIR while leaving derived `vk` behind -> missing_upstream_artifact.
            (sw_tgt / "silent_witness.json").unlink()
            with redirect_stderr(io.StringIO()):
                missing_up = am.build_dependency_graph(
                    lock,
                    root,
                    lock_path=lock_file,
                    packaging=True,
                )
            missing_map = {
                entry["path"]: entry["reasons"] for entry in missing_up["stale_artifacts"]
            }
            self.assertIn(
                "missing_upstream_artifact",
                missing_map["zk/noir/silent_witness/target/vk"],
            )

            # Verify CLI packaging gate returns EXIT_DRIFT.
            dg_args = bc.create_parser().parse_args(
                ["dependency-graph", "--lock", str(lock_file), "--packaging"]
            )
            with redirect_stderr(io.StringIO()), io.StringIO() as out_buf:
                orig_stdout = sys.stdout
                sys.stdout = out_buf
                try:
                    rc = bc.cmd_dependency_graph(dg_args, repo_root=root)
                finally:
                    sys.stdout = orig_stdout
            self.assertEqual(rc, bc.EXIT_DRIFT)


if __name__ == "__main__":
    unittest.main()
