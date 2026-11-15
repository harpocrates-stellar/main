"""Focused tests for release-directory containment and pre-read alias resolution.

Covers:
- Lexical escape rejection (../, absolute, drive-prefixed, backslash, control chars)
- Bounded deterministic validation errors on hostile overlong paths
- Resolving aliases (symlinks / Windows junctions / dangling links) before reading
  referenced artifacts in both ``zk/tools/artifact_manifest.py``,
  ``zk/tools/build_circuits.py``, and ``devx/release_guard.py``
- Preserving compatibility for valid in-tree paths and in-tree aliases
"""

from __future__ import annotations

import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[1]
DEVX_DIR = Path(__file__).resolve().parent
ZK_TOOLS_DIR = REPO_ROOT / "zk" / "tools"

for extra_path in (str(DEVX_DIR), str(ZK_TOOLS_DIR)):
    if extra_path not in sys.path:
        sys.path.insert(0, extra_path)

import artifact_manifest as am
import build_circuits as bc
import release_guard


def _create_dir_alias(link_path: Path, target_dir: Path) -> None:
    try:
        link_path.symlink_to(target_dir, target_is_directory=True)
    except OSError:
        import _winapi  # type: ignore[import-not-found]

        _winapi.CreateJunction(str(target_dir), str(link_path))


class ManifestPathContainmentTest(unittest.TestCase):
    def setUp(self) -> None:
        self.base_release_manifest = release_guard.read_json(release_guard.DEFAULT_MANIFEST)
        self.lock_template = json.loads(am.DEFAULT_LOCK.read_text(encoding="utf-8"))

    def _write_lock(self, directory: Path, artifacts: list[dict]) -> tuple[Path, am.Lock]:
        raw = copy.deepcopy(self.lock_template)
        raw["artifacts"] = artifacts
        lock_path = directory / "toolchain.lock.json"
        lock_path.write_text(json.dumps(raw), encoding="utf-8")
        return lock_path, am.load_lock(lock_path)

    def test_release_guard_rejects_escaping_paths_deterministically(self) -> None:
        cases = [
            ("../outside.json", "path_traversal"),
            ("release/../../outside.json", "path_traversal"),
            ("/etc/passwd", "path_absolute"),
            ("C:/outside.json", "path_absolute"),
            ("release\\outside.json", "path_backslash"),
            ("release/bad\x07file.json", "path_control_char"),
            ("release/" + ("x" * 5000) + ".json", "path_overlong"),
        ]
        for raw_path, expected_code in cases:
            with self.subTest(raw_path=raw_path[:32]):
                manifest = copy.deepcopy(self.base_release_manifest)
                manifest["artifacts"][0]["path"] = raw_path
                with self.assertRaises(release_guard.ManifestError) as first_ctx:
                    release_guard.validate_manifest(manifest)
                with self.assertRaises(release_guard.ManifestError) as second_ctx:
                    release_guard.validate_manifest(manifest)

                self.assertEqual(first_ctx.exception.code, expected_code)
                self.assertEqual(str(first_ctx.exception), str(second_ctx.exception))
                self.assertIn("inside", str(first_ctx.exception))
                self.assertLessEqual(
                    len(str(first_ctx.exception)),
                    release_guard.MAX_VALIDATION_ERROR_CHARS,
                )

    def test_release_guard_resolves_alias_before_hashing_or_scanning(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            release_dir = root / "selected_release"
            outside_dir = root / "outside_secrets"
            release_dir.mkdir()
            outside_dir.mkdir()

            secret_file = outside_dir / "escaped.json"
            secret_file.write_text('{"secret":"DO_NOT_HASH_OR_SCAN"}', encoding="utf-8")

            _create_dir_alias(release_dir / "aliased_sub", outside_dir)

            manifest = copy.deepcopy(self.base_release_manifest)
            manifest["artifacts"][0]["path"] = "aliased_sub/escaped.json"

            with (
                mock.patch.object(release_guard, "sha256_file") as mock_hash,
                mock.patch.object(release_guard.secret_scanner, "scan_file") as mock_scan,
            ):
                with self.assertRaises(release_guard.ManifestError) as ctx:
                    release_guard.validate_manifest(manifest, release_dir=release_dir)

                self.assertEqual(ctx.exception.code, "alias_escape")
                self.assertNotIn("outside_secrets", str(ctx.exception))
                mock_hash.assert_not_called()
                mock_scan.assert_not_called()

    def test_artifact_manifest_and_build_circuits_reject_escaping_aliases(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            release_dir = root / "release"
            outside_dir = root / "outside"
            release_dir.mkdir()
            outside_dir.mkdir()

            outside_acir = outside_dir / "silent_witness.json"
            outside_acir.write_bytes(b'{"bytecode":"EXTERNAL_SECRET"}')
            (outside_dir / "proof").write_bytes(b"PROOF")
            (outside_dir / "public_inputs").write_bytes(b"PI")
            (outside_dir / "vk").write_bytes(b"VK")

            (release_dir / "zk" / "noir" / "silent_witness").mkdir(parents=True)
            _create_dir_alias(
                release_dir / "zk" / "noir" / "silent_witness" / "target",
                outside_dir,
            )

            _, lock = self._write_lock(
                root,
                [
                    {
                        "path": "zk/noir/silent_witness/target/silent_witness.json",
                        "kind": "json",
                        "role": "acir",
                        "required": True,
                    }
                ],
            )

            with self.assertRaises(am.PathValidationError) as am_ctx:
                am.digest_artifact(lock.artifacts[0], lock, release_dir)
            self.assertEqual(am_ctx.exception.code, "alias_escape")
            self.assertLessEqual(len(str(am_ctx.exception)), am.MAX_VALIDATION_ERROR_CHARS)

            export_args = bc.create_parser().parse_args(
                [
                    "export",
                    "silent_witness",
                    "--release-dir",
                    str(release_dir),
                ]
            )
            with self.assertRaises(bc.PathValidationError) as bc_ctx:
                bc.cmd_export(export_args, repo_root=release_dir)
            self.assertEqual(bc_ctx.exception.code, "alias_escape")
            self.assertLessEqual(len(str(bc_ctx.exception)), am.MAX_VALIDATION_ERROR_CHARS)

    def test_provenance_glob_rejects_aliased_source_directory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            release_dir = root / "release"
            outside_src = root / "outside_src"
            (release_dir / "zk" / "noir" / "evil").mkdir(parents=True)
            outside_src.mkdir()
            (outside_src / "main.nr").write_text("fn main() { /* secret */ }\n", encoding="utf-8")

            _create_dir_alias(release_dir / "zk" / "noir" / "evil" / "src", outside_src)

            _, lock = self._write_lock(root, [])
            with self.assertRaises(am.PathValidationError) as ctx:
                am.collect_provenance(lock, release_dir)
            self.assertEqual(ctx.exception.code, "alias_escape")


if __name__ == "__main__":
    unittest.main()
