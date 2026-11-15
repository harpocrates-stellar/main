"""Focused devx regression coverage for signed circuit release manifests (#1214)."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
TOOLS_DIR = REPO_ROOT / "zk" / "tools"
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

import artifact_manifest as am


class SignedReleaseManifestDevxTest(unittest.TestCase):
    def test_sign_and_offline_verify_cli_and_client_loader(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            (root / "zk" / "noir" / "silent_witness" / "src").mkdir(parents=True)
            (root / "zk" / "noir" / "silent_witness" / "Nargo.toml").write_text(
                '[package]\nname = "silent_witness"\ntype = "bin"\n', encoding="utf-8"
            )
            (root / "zk" / "noir" / "silent_witness" / "src" / "main.nr").write_text(
                "fn main(x: pub Field) { assert(x == 7); }\n", encoding="utf-8"
            )
            pub_dir = root / "frontend" / "public" / "noir"
            pub_dir.mkdir(parents=True)
            acir_path = pub_dir / "silent_witness.json"
            acir_path.write_text(
                '{"noir_version":"1.0.0-beta.9","bytecode":"CAFE","abi":{"parameters":[]}}',
                encoding="utf-8",
            )

            lock_path = root / "zk" / "toolchain.lock.json"
            lock_path.write_text(
                json.dumps(
                    {
                        "format": "harpocrates.zk-toolchain-lock",
                        "version": 1,
                        "toolchain": {
                            "nargo": {"version": "1.0.0-beta.9"},
                            "barretenberg": {"version": "0.87.0"},
                            "proving_scheme": "ultra_honk",
                            "oracle_hash": "keccak",
                        },
                        "environment": {"SOURCE_DATE_EPOCH": "0", "TZ": "UTC"},
                        "limits": {
                            "max_artifact_bytes": 1048576,
                            "max_artifacts": 32,
                            "max_provenance_files": 64,
                            "max_circuits": 16,
                        },
                        "normalization": {
                            "json": {"volatile_keys": ["debug_symbols", "file_map", "names"]},
                            "wasm": {"strip_custom_sections": ["producers", "name"]},
                        },
                        "provenance_sources": {
                            "globs": ["zk/noir/*/Nargo.toml", "zk/noir/*/src/**/*.nr"]
                        },
                        "artifacts": [
                            {
                                "path": "frontend/public/noir/silent_witness.json",
                                "kind": "json",
                                "role": "published_acir",
                                "required": False,
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            seed_hex, pub_hex, key_id = am.generate_release_signing_keypair(b"\x55" * 32)
            key_file = root / "signer.seed"
            key_file.write_text(seed_hex, encoding="utf-8")
            signed_path = root / "zk" / "release.manifest.signed.json"

            rc_sign = am.main(
                [
                    "--lock",
                    str(lock_path),
                    "sign-release",
                    "--scope",
                    "browser",
                    "--source-revision",
                    "release-v1.2.0",
                    "--signing-key-file",
                    str(key_file),
                    "--output",
                    str(signed_path),
                    "--root",
                    str(root),
                ]
            )
            self.assertEqual(rc_sign, am.EXIT_OK)
            key_file.unlink()

            # Verify offline in pure client mode (--skip-lock --skip-sources)
            rc_verify = am.main(
                [
                    "--lock",
                    str(lock_path),
                    "verify-release",
                    "--manifest",
                    str(signed_path),
                    "--public-key",
                    pub_hex,
                    "--expected-source-revision",
                    "release-v1.2.0",
                    "--skip-lock",
                    "--skip-sources",
                    "--root",
                    str(root),
                ]
            )
            self.assertEqual(rc_verify, am.EXIT_OK)

            loaded = am.load_verified_client_artifacts(
                signed_manifest=signed_path,
                trusted_public_keys={key_id: pub_hex},
                root=root,
                expected_source_revision="release-v1.2.0",
            )
            self.assertIn("frontend/public/noir/silent_witness.json", loaded)

            # Reject path escape attempts before reading outside root
            outside = root.parent / "escaped_secret.json"
            outside.write_text('{"secret":"nope"}', encoding="utf-8")
            try:
                tampered_doc = json.loads(signed_path.read_text(encoding="utf-8"))
                tampered_doc["payload"]["artifacts"][0]["path"] = "../escaped_secret.json"
                resigned = am.sign_release_manifest(tampered_doc["payload"], seed_hex=seed_hex)
                with self.assertRaises(am.BuildError):
                    am.load_verified_release_artifact(
                        "../escaped_secret.json",
                        signed_manifest=resigned,
                        trusted_public_keys={key_id: pub_hex},
                        root=root,
                    )
            finally:
                outside.unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
