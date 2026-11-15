from __future__ import annotations

import copy
import gzip
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT / "devx") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "devx"))
if str(REPO_ROOT / "zk" / "tools") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "zk" / "tools"))

import artifact_manifest as am
import release_guard


class ManifestByteSizesTest(unittest.TestCase):
    def setUp(self) -> None:
        self.base_manifest = release_guard.read_json(release_guard.DEFAULT_MANIFEST)

    def test_release_guard_accepts_consistent_size_bytes_and_total(self) -> None:
        manifest = copy.deepcopy(self.base_manifest)
        for index, entry in enumerate(manifest["artifacts"], start=1):
            entry["size_bytes"] = index * 10
        manifest["total_artifact_bytes"] = sum(
            entry["size_bytes"] for entry in manifest["artifacts"]
        )
        release_guard.validate_manifest(manifest)

    def test_release_guard_rejects_inconsistent_size_declarations(self) -> None:
        manifest = copy.deepcopy(self.base_manifest)
        manifest["artifacts"][0]["size_bytes"] = 10
        manifest["artifacts"][0]["bytes"] = 12
        with self.assertRaisesRegex(release_guard.ManifestError, "inconsistent size"):
            release_guard.validate_manifest(manifest)

        empty_conflict = copy.deepcopy(self.base_manifest)
        empty_conflict["artifacts"][0]["size_bytes"] = 0
        with self.assertRaisesRegex(release_guard.ManifestError, "conflicts with sha256"):
            release_guard.validate_manifest(empty_conflict)

        bad_total = copy.deepcopy(self.base_manifest)
        for entry in bad_total["artifacts"]:
            entry["size_bytes"] = 16
        bad_total["total_artifact_bytes"] = 1
        with self.assertRaisesRegex(release_guard.ManifestError, "disagrees with sum"):
            release_guard.validate_manifest(bad_total)

    def test_release_guard_validates_size_before_hashing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_root = Path(tmp)
            manifest = copy.deepcopy(self.base_manifest)
            # Populate synthetic files matching paths in manifest, with first file wrong size
            for idx, entry in enumerate(manifest["artifacts"]):
                dest = tmp_root / entry["path"]
                dest.parent.mkdir(parents=True, exist_ok=True)
                payload = b"synthetic-content"
                dest.write_bytes(payload)
                entry["sha256"] = release_guard.sha256_file(dest)
                entry["size_bytes"] = len(payload) + (10 if idx == 0 else 0)

            manifest_path = tmp_root / "manifest.json"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

            hashed_paths: list[str] = []
            real_sha = release_guard.sha256_file

            def spy_sha(path: Path) -> str:
                hashed_paths.append(path.relative_to(tmp_root).as_posix())
                return real_sha(path)

            with (
                mock.patch.object(release_guard, "_verify_declared_component_versions"),
                mock.patch.object(release_guard, "sha256_file", side_effect=spy_sha),
                mock.patch.object(release_guard.secret_scanner, "scan_file", return_value=[]),
                self.assertRaisesRegex(release_guard.ManifestError, "size mismatch"),
            ):
                release_guard.verify(manifest_path, root=tmp_root)

            self.assertNotIn(manifest["artifacts"][0]["path"], hashed_paths)

    def test_artifact_manifest_gzip_validates_size_before_decompression_and_hashing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            raw_lock = json.loads(
                (REPO_ROOT / "zk" / "toolchain.lock.json").read_text(encoding="utf-8")
            )
            raw_lock["artifacts"] = [
                {
                    "path": "artifact.json.gz",
                    "kind": "json",
                    "role": "acir",
                    "compression": "gzip",
                    "expected_decompressed_bytes": 18,
                    "required": True,
                }
            ]
            lock_path = tmp_path / "lock.json"
            lock_path.write_text(json.dumps(raw_lock), encoding="utf-8")
            lock = am.load_lock(lock_path)

            payload = b'{"bytecode":"AAA"}'
            self.assertEqual(len(payload), 18)
            gz_path = tmp_path / "artifact.json.gz"
            gz_path.write_bytes(gzip.compress(payload))

            ok_res = am.digest_artifact(lock.artifacts[0], lock, tmp_path)
            self.assertEqual(ok_res.state, am.ArtifactState.DIGESTED)
            self.assertEqual(ok_res.decompressed_bytes, 18)

            # Now write payload with mismatched decompressed byte size; must fail before hashing
            gz_path.write_bytes(gzip.compress(b'{"bytecode":"BBBBBB"}'))
            with mock.patch.object(
                am, "sha256_hex", side_effect=AssertionError("must not hash mismatched size")
            ):
                bad_res = am.digest_artifact(lock.artifacts[0], lock, tmp_path)
            self.assertEqual(bad_res.state, am.ArtifactState.SIZE_MISMATCH)


if __name__ == "__main__":
    unittest.main()
