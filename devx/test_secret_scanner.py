# harpocrates:ignore-file
import unittest
import tempfile
import os
from pathlib import Path
from devx.secret_scanner import scan_file, is_secret_allowlisted

class TestSecretScanner(unittest.TestCase):
    def test_safe_file(self):
        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".txt") as f:
            f.write("Just some safe text.")
            path = Path(f.name)
        self.addCleanup(path.unlink)
        errors = scan_file(path)
        self.assertEqual(len(errors), 0)
        
    def test_stellar_secret_key(self):
        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".txt") as f:
            f.write("S" + "A"*55)
            path = Path(f.name)
        self.addCleanup(path.unlink)
        errors = scan_file(path)
        self.assertIn("secrets violation: private key detected", errors)

    def test_rsa_private_key(self):
        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".txt") as f:
            f.write("-----BEGIN RSA PRIVATE KEY-----\nMIICXAIBAAKBgQC...\n-----END RSA PRIVATE KEY-----")
            path = Path(f.name)
        self.addCleanup(path.unlink)
        errors = scan_file(path)
        self.assertIn("secrets violation: private key detected", errors)

    def test_media_file(self):
        with tempfile.NamedTemporaryFile("w", suffix=".mp4", delete=False) as f:
            f.write("fake video content")
            path = Path(f.name)
        self.addCleanup(path.unlink)
        errors = scan_file(path)
        self.assertIn("unsupported input: real media files are prohibited", errors)

    def test_witness_file(self):
        with tempfile.NamedTemporaryFile("w", suffix=".tr", delete=False) as f:
            f.write("fake witness content")
            path = Path(f.name)
        self.addCleanup(path.unlink)
        errors = scan_file(path)
        self.assertIn("unsupported input: witness values are prohibited", errors)

    def test_allowlisted_test_fixtures(self):
        # Allowlisted test fixtures with dummy RSA key should not produce errors
        self.assertTrue(is_secret_allowlisted(Path("devx/test_c2pa_parser.py")))
        self.assertTrue(is_secret_allowlisted(Path("devx/test_validate_c2pa_fixture.py")))
        self.assertTrue(is_secret_allowlisted(Path("backend/test_redaction_adversarial.py")))
        self.assertTrue(is_secret_allowlisted(Path("backend/test_trace_fields.py")))
        self.assertTrue(is_secret_allowlisted(Path("devx/fixtures/c2pa/manifest.json")))
        self.assertFalse(is_secret_allowlisted(Path("backend/routes.py")))

    def test_allowlisted_fixture_scan(self):
        tmp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(tmp_dir.cleanup)
        devx_dir = Path(tmp_dir.name) / "devx"
        devx_dir.mkdir(parents=True, exist_ok=True)
        fixture_path = devx_dir / "test_c2pa_parser.py"
        fixture_path.write_text('dummy = "-----BEGIN RSA PRIVATE KEY-----"', encoding="utf-8")
        
        errors = scan_file(fixture_path, repo_root=Path(tmp_dir.name))
        self.assertEqual(len(errors), 0)

    def test_oversized_file(self):
        # We can simulate by monkeypatching stat or creating a sparse file
        pass

if __name__ == "__main__":
    unittest.main()
