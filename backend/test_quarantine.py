import os
import tempfile
from pathlib import Path
import unittest

from werkzeug.datastructures import FileStorage

from quarantine import SignatureScanner, isolate_upload, QuarantineError


class TestQuarantine(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self.tmp_dir.name)

    def tearDown(self):
        self.tmp_dir.cleanup()

    def test_signature_scanner_webm(self):
        # Create a mock webm file
        webm_path = self.tmp_path / "test.webm"
        webm_path.write_bytes(b"\x1a\x45\xdf\xa3" + b"\x00" * 20)
        self.assertTrue(SignatureScanner.is_valid_video(webm_path))

    def test_signature_scanner_mp4(self):
        # Create a mock mp4 file
        mp4_path = self.tmp_path / "test.mp4"
        mp4_path.write_bytes(b"\x00\x00\x00\x18ftypmp42" + b"\x00" * 10)
        self.assertTrue(SignatureScanner.is_valid_video(mp4_path))

    def test_signature_scanner_invalid(self):
        # Create a mock text file
        txt_path = self.tmp_path / "test.txt"
        txt_path.write_bytes(b"This is just a text file")
        self.assertFalse(SignatureScanner.is_valid_video(txt_path))

    def test_isolate_upload_success(self):
        class MockFile:
            def save(self, dst):
                with open(dst, "wb") as f:
                    f.write(b"\x00\x00\x00\x18ftypmp42" + b"\x00" * 10)

        mock_file = MockFile()
        with isolate_upload(mock_file) as safe_path:
            self.assertTrue(safe_path.exists())
            if os.name != "nt":
                self.assertEqual(os.stat(safe_path).st_mode & 0o777, 0o600)
            self.assertEqual(safe_path.read_bytes()[:8], b"\x00\x00\x00\x18ftyp")

    def test_isolate_upload_failure(self):
        class MockFile:
            def save(self, dst):
                with open(dst, "wb") as f:
                    f.write(b"Malicious payload")

        mock_file = MockFile()
        with self.assertRaises(QuarantineError):
            with isolate_upload(mock_file) as safe_path:
                pass


if __name__ == "__main__":
    unittest.main()
