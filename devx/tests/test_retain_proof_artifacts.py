import contextlib
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import retain_proof_artifacts as rpa  # noqa: E402

# Synthetic only: never a real key. Matches the secret-seed shape.
FAKE_SEED = "S" + "A" * 55


def run(args):
    err = io.StringIO()
    with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
        code = rpa.main(args)
    return code, err.getvalue()


class RetainTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.src = self.root / "src"
        self.src.mkdir()
        self.out = self.root / "out"

    def tearDown(self):
        self.tmp.cleanup()

    def w(self, name, data):
        p = self.src / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data if isinstance(data, bytes) else data.encode())
        return p

    def go(self, *extra):
        return run(["--src", str(self.src), "--out", str(self.out), *extra])

    def assert_violation(self, code_name, *extra):
        code, err = self.go(*extra)
        self.assertEqual(code, 2)
        self.assertIn(f"policy violation: {code_name}", err)
        self.assertFalse(self.out.exists(), "nothing may be written on violation")

    # positive
    def test_retains_allowlisted_and_writes_manifest(self):
        self.w("a.proof", b"\x01\x02")
        self.w("vk.json", json.dumps({"vk": "abcd"}))
        code, _ = self.go()
        self.assertEqual(code, 0)
        manifest = json.loads((self.out / "retention-manifest.json").read_text())
        self.assertEqual(manifest["schema"], rpa.SCHEMA)
        self.assertEqual(len(manifest["files"]), 2)
        self.assertTrue((self.out / "src0" / "a.proof").exists())

    def test_manifest_is_deterministic(self):
        self.w("a.proof", b"x")
        self.w("b.hex", b"ff")
        self.go()
        first = (self.out / "retention-manifest.json").read_text()
        import shutil
        shutil.rmtree(self.out)
        self.go()
        self.assertEqual(first, (self.out / "retention-manifest.json").read_text())

    def test_non_allowlisted_files_are_skipped_not_retained(self):
        self.w("a.proof", b"x")
        self.w("notes.md", b"hello")
        self.go()
        self.assertFalse((self.out / "src0" / "notes.md").exists())

    def test_dry_run_writes_nothing(self):
        self.w("a.proof", b"x")
        code, _ = self.go("--dry-run")
        self.assertEqual(code, 0)
        self.assertFalse(self.out.exists())

    # negative
    def test_real_media_is_rejected(self):
        self.w("a.proof", b"x")
        self.w("evidence.mp4", b"\x00")
        self.assert_violation("DENIED_TYPE")

    def test_keys_and_witness_files_are_rejected(self):
        self.w("a.proof", b"x")
        self.w("signer.pem", b"x")
        self.assert_violation("DENIED_TYPE")

    def test_witness_gz_is_rejected(self):
        self.w("a.proof", b"x")
        self.w("circuit.gz", b"x")
        self.assert_violation("DENIED_TYPE")

    def test_prover_toml_is_rejected(self):
        self.w("Prover.toml", "x = 1")
        self.assert_violation("DENIED_NAME")

    def test_secret_content_is_rejected(self):
        self.w("a.hex", FAKE_SEED)
        self.assert_violation("SECRET_CONTENT")

    def test_private_key_block_is_rejected(self):
        self.w("a.json", '{"a": "-----BEGIN PRIVATE KEY-----"}')
        self.assert_violation("SECRET_CONTENT")

    def test_forbidden_json_key_is_rejected_when_nested(self):
        self.w("a.json", json.dumps({"ok": [{"nested": {"Witness": "1"}}]}))
        self.assert_violation("FORBIDDEN_JSON_KEY")

    def test_malformed_json_is_rejected(self):
        self.w("a.json", "{not json")
        self.assert_violation("MALFORMED_JSON")

    def test_symlink_is_rejected(self):
        real = self.root / "real.proof"
        real.write_bytes(b"x")
        try:
            os.symlink(real, self.src / "link.proof")
        except (OSError, NotImplementedError):
            self.skipTest("symlinks unavailable on this platform")
        self.assert_violation("SYMLINK")

    def test_missing_source_is_rejected(self):
        code, err = run(["--src", str(self.root / "nope"), "--out", str(self.out)])
        self.assertEqual(code, 2)
        self.assertIn("MISSING_SOURCE", err)

    def test_nothing_to_retain_fails_closed(self):
        self.w("notes.md", b"x")
        self.assert_violation("NOTHING_TO_RETAIN")

    def test_non_empty_output_dir_is_rejected(self):
        self.w("a.proof", b"x")
        self.out.mkdir()
        (self.out / "old").write_text("x")
        code, err = self.go()
        self.assertEqual(code, 2)
        self.assertIn("OUT_NOT_EMPTY", err)

    # boundary
    def test_file_exactly_at_limit_is_ok_and_one_over_is_not(self):
        self.w("a.proof", b"x" * 10)
        self.assertEqual(self.go("--max-file-bytes", "10")[0], 0)
        import shutil
        shutil.rmtree(self.out)
        self.w("a.proof", b"x" * 11)
        self.assert_violation("OVERSIZED", "--max-file-bytes", "10")

    def test_total_cap(self):
        self.w("a.proof", b"x" * 6)
        self.w("b.proof", b"x" * 6)
        self.assert_violation("TOTAL_TOO_LARGE", "--max-total-bytes", "10")

    # regression: privacy-safe messages
    def test_error_output_never_contains_file_names_or_secrets(self):
        self.w("very-sensitive-name.mp4", b"x")
        self.w("b.hex", FAKE_SEED)
        code, err = self.go()
        self.assertEqual(code, 2)
        self.assertNotIn("very-sensitive-name", err)
        self.assertNotIn(FAKE_SEED, err)


if __name__ == "__main__":
    unittest.main()