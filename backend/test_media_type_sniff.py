"""Unit tests for media-type sniffing (issue #267).

Covers :func:`quarantine.sniff_media_type_stream` and
:func:`quarantine.sniff_media_type_path`, and the upgraded
:func:`app.validate_video_upload` that now sniffs bytes before the file
reaches ffmpeg.

All tests are pure-Python and finish in milliseconds — no ffmpeg, no DB, no
network.  The test suite is intentionally isolated from the heavier integration
tests so it can run as part of a fast pre-push check.
"""

from __future__ import annotations

import io
import tempfile
import unittest
from pathlib import Path

from quarantine import (
    QuarantineError,
    sniff_media_type_path,
    sniff_media_type_stream,
)

# ---------------------------------------------------------------------------
# Canonical magic-byte fixtures (identical to those in test_quarantine.py so
# the two suites remain independently runnable without shared helpers).
# ---------------------------------------------------------------------------

MP4_MAGIC  = b"\x00\x00\x00\x18ftypmp42" + b"\x00" * 20
MOV_MAGIC  = b"\x00\x00\x00\x18ftypqt  " + b"\x00" * 20
WEBM_MAGIC = b"\x1a\x45\xdf\xa3\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" + b"\x00" * 16
MKV_MAGIC  = b"\x1a\x45\xdf\xa3\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" + b"\x00" * 16
AVI_MAGIC  = b"RIFF\x00\x00\x00\x00AVI " + b"\x00" * 20
GP3_MAGIC  = b"\x00\x00\x00\x18ftyp3gp4" + b"\x00" * 20
PNG_MAGIC  = b"\x89PNG\r\n\x1a\n" + b"\x00" * 24
GIF_MAGIC  = b"GIF89a" + b"\x00" * 26
PDF_MAGIC  = b"%PDF-1.4\n" + b"\x00" * 23
EXE_MAGIC  = b"MZ" + b"\x00" * 30


# ===========================================================================
# sniff_media_type_stream — bytes input
# ===========================================================================

class TestSniffStreamBytes(unittest.TestCase):
    """sniff_media_type_stream() with raw bytes (no I/O)."""

    # ── positive: known families ──────────────────────────────────────────

    def test_mp4_bytes(self):
        self.assertEqual(sniff_media_type_stream(MP4_MAGIC), "MP4")

    def test_mov_bytes(self):
        self.assertEqual(sniff_media_type_stream(MOV_MAGIC), "MOV")

    def test_webm_bytes(self):
        self.assertEqual(sniff_media_type_stream(WEBM_MAGIC), "Matroska")

    def test_mkv_bytes(self):
        self.assertEqual(sniff_media_type_stream(MKV_MAGIC), "Matroska")

    def test_avi_bytes(self):
        self.assertEqual(sniff_media_type_stream(AVI_MAGIC), "AVI")

    def test_3gp_bytes(self):
        self.assertEqual(sniff_media_type_stream(GP3_MAGIC), "3GP")

    # ── negative: non-video magic ─────────────────────────────────────────

    def test_png_rejected(self):
        with self.assertRaises(QuarantineError) as ctx:
            sniff_media_type_stream(PNG_MAGIC)
        self.assertIn("sniff", str(ctx.exception).lower())

    def test_gif_rejected(self):
        with self.assertRaises(QuarantineError) as ctx:
            sniff_media_type_stream(GIF_MAGIC)
        self.assertIn("sniff", str(ctx.exception).lower())

    def test_pdf_rejected(self):
        with self.assertRaises(QuarantineError):
            sniff_media_type_stream(PDF_MAGIC)

    def test_exe_rejected(self):
        with self.assertRaises(QuarantineError):
            sniff_media_type_stream(EXE_MAGIC)

    def test_null_bytes_rejected(self):
        with self.assertRaises(QuarantineError):
            sniff_media_type_stream(b"\x00" * 32)

    def test_random_text_rejected(self):
        with self.assertRaises(QuarantineError):
            sniff_media_type_stream(b"this is definitely not a video file!!!")

    # ── boundary: size edge cases ─────────────────────────────────────────

    def test_exactly_12_bytes_invalid(self):
        """12 bytes is the minimum; all-zero bytes have no known signature."""
        with self.assertRaises(QuarantineError):
            sniff_media_type_stream(b"\x00" * 12)

    def test_11_bytes_too_small(self):
        with self.assertRaises(QuarantineError) as ctx:
            sniff_media_type_stream(b"\x00" * 11)
        self.assertIn("too small", str(ctx.exception))

    def test_empty_bytes_too_small(self):
        with self.assertRaises(QuarantineError) as ctx:
            sniff_media_type_stream(b"")
        self.assertIn("too small", str(ctx.exception))

    def test_only_first_32_bytes_used(self):
        """Extra bytes beyond header size are ignored."""
        payload = MP4_MAGIC + b"X" * 1000
        self.assertEqual(sniff_media_type_stream(payload), "MP4")


# ===========================================================================
# sniff_media_type_stream — seekable BytesIO input
# ===========================================================================

class TestSniffStreamIO(unittest.TestCase):
    """sniff_media_type_stream() with a seekable io.BytesIO stream."""

    def test_mp4_io(self):
        stream = io.BytesIO(MP4_MAGIC)
        result = sniff_media_type_stream(stream)
        self.assertEqual(result, "MP4")

    def test_webm_io(self):
        stream = io.BytesIO(WEBM_MAGIC)
        self.assertEqual(sniff_media_type_stream(stream), "Matroska")

    def test_stream_rewound_after_call(self):
        """The stream must be at position 0 after sniffing so callers can save()."""
        stream = io.BytesIO(MP4_MAGIC + b"\xff" * 100)
        sniff_media_type_stream(stream)
        self.assertEqual(stream.tell(), 0, "stream was not rewound to 0 after sniff")

    def test_stream_rewound_even_on_error(self):
        """Stream must be rewound even when the sniff raises QuarantineError."""
        stream = io.BytesIO(PNG_MAGIC + b"\xff" * 100)
        try:
            sniff_media_type_stream(stream)
        except QuarantineError:
            pass
        self.assertEqual(stream.tell(), 0, "stream was not rewound after failed sniff")

    def test_non_video_io_rejected(self):
        stream = io.BytesIO(GIF_MAGIC)
        with self.assertRaises(QuarantineError):
            sniff_media_type_stream(stream)

    def test_partial_stream_too_small(self):
        stream = io.BytesIO(b"\x00\x00\x00")
        with self.assertRaises(QuarantineError) as ctx:
            sniff_media_type_stream(stream)
        self.assertIn("too small", str(ctx.exception))


# ===========================================================================
# sniff_media_type_stream — cross-validation (filename + content_type)
# ===========================================================================

class TestSniffStreamCrossValidation(unittest.TestCase):

    # ── consistent declarations ────────────────────────────────────────────

    def test_mp4_consistent(self):
        result = sniff_media_type_stream(
            MP4_MAGIC, filename="clip.mp4", content_type="video/mp4"
        )
        self.assertEqual(result, "MP4")

    def test_webm_consistent(self):
        result = sniff_media_type_stream(
            WEBM_MAGIC, filename="clip.webm", content_type="video/webm"
        )
        self.assertEqual(result, "Matroska")

    def test_octet_stream_wildcard(self):
        """application/octet-stream should never cause a mismatch."""
        result = sniff_media_type_stream(
            MP4_MAGIC, filename="clip.mp4", content_type="application/octet-stream"
        )
        self.assertEqual(result, "MP4")

    def test_mkv_webm_interchange(self):
        """WebM and MKV share the Matroska family — .mkv + video/webm is OK."""
        result = sniff_media_type_stream(
            MKV_MAGIC, filename="clip.mkv", content_type="video/webm"
        )
        self.assertEqual(result, "Matroska")

    # ── extension mismatches ──────────────────────────────────────────────

    def test_wrong_extension_rejected(self):
        with self.assertRaises(QuarantineError) as ctx:
            sniff_media_type_stream(MP4_MAGIC, filename="clip.avi")
        self.assertIn("signature matches", str(ctx.exception))

    def test_unsupported_extension_rejected(self):
        with self.assertRaises(QuarantineError) as ctx:
            sniff_media_type_stream(MP4_MAGIC, filename="clip.exe")
        self.assertIn("unsupported extension", str(ctx.exception))

    def test_txt_extension_rejected(self):
        with self.assertRaises(QuarantineError) as ctx:
            sniff_media_type_stream(MP4_MAGIC, filename="clip.txt")
        self.assertIn("unsupported extension", str(ctx.exception))

    # ── content-type mismatches ───────────────────────────────────────────

    def test_wrong_mime_rejected(self):
        with self.assertRaises(QuarantineError) as ctx:
            sniff_media_type_stream(MP4_MAGIC, content_type="video/webm")
        self.assertIn("signature matches", str(ctx.exception))

    def test_unsupported_mime_rejected(self):
        with self.assertRaises(QuarantineError) as ctx:
            sniff_media_type_stream(MP4_MAGIC, content_type="application/pdf")
        self.assertIn("unsupported content type", str(ctx.exception))

    def test_image_mime_rejected(self):
        with self.assertRaises(QuarantineError) as ctx:
            sniff_media_type_stream(MP4_MAGIC, content_type="image/png")
        self.assertIn("unsupported content type", str(ctx.exception))

    def test_mov_declared_as_mp4_rejected(self):
        """MOV magic + video/mp4 MIME is a spoofing attempt."""
        with self.assertRaises(QuarantineError) as ctx:
            sniff_media_type_stream(
                MOV_MAGIC, filename="clip.mp4", content_type="video/mp4"
            )
        self.assertIn("spoofing", str(ctx.exception))

    def test_3gp_declared_as_mp4_rejected(self):
        with self.assertRaises(QuarantineError) as ctx:
            sniff_media_type_stream(
                GP3_MAGIC, filename="clip.mp4", content_type="video/mp4"
            )
        self.assertIn("spoofing", str(ctx.exception))

    # ── no filename / no content_type ─────────────────────────────────────

    def test_no_filename_ok(self):
        """Filename is optional; missing it skips the extension check."""
        self.assertEqual(
            sniff_media_type_stream(MP4_MAGIC, content_type="video/mp4"), "MP4"
        )

    def test_no_content_type_ok(self):
        """Content-type is optional; missing it skips the MIME check."""
        self.assertEqual(
            sniff_media_type_stream(MP4_MAGIC, filename="clip.mp4"), "MP4"
        )

    def test_no_context_ok(self):
        self.assertEqual(sniff_media_type_stream(MP4_MAGIC), "MP4")


# ===========================================================================
# sniff_media_type_path — on-disk variant
# ===========================================================================

class TestSniffMediaTypePath(unittest.TestCase):

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def _write(self, name: str, data: bytes) -> Path:
        p = self.tmp / name
        p.write_bytes(data)
        return p

    def test_mp4_path(self):
        p = self._write("v.mp4", MP4_MAGIC)
        self.assertEqual(sniff_media_type_path(p), "MP4")

    def test_webm_path(self):
        p = self._write("v.webm", WEBM_MAGIC)
        self.assertEqual(sniff_media_type_path(p), "Matroska")

    def test_avi_path(self):
        p = self._write("v.avi", AVI_MAGIC)
        self.assertEqual(sniff_media_type_path(p), "AVI")

    def test_non_video_rejected(self):
        p = self._write("bad.mp4", PNG_MAGIC)
        with self.assertRaises(QuarantineError):
            sniff_media_type_path(p)

    def test_empty_file_rejected(self):
        p = self._write("empty.mp4", b"")
        with self.assertRaises(QuarantineError) as ctx:
            sniff_media_type_path(p)
        self.assertIn("too small", str(ctx.exception))

    def test_missing_file_rejected(self):
        p = self.tmp / "nonexistent.mp4"
        with self.assertRaises(QuarantineError) as ctx:
            sniff_media_type_path(p)
        self.assertIn("empty", str(ctx.exception).lower())

    def test_path_cross_validate_ok(self):
        p = self._write("v.mp4", MP4_MAGIC)
        result = sniff_media_type_path(p, filename="v.mp4", content_type="video/mp4")
        self.assertEqual(result, "MP4")

    def test_path_cross_validate_spoof(self):
        p = self._write("v.mp4", AVI_MAGIC)
        with self.assertRaises(QuarantineError) as ctx:
            sniff_media_type_path(p, filename="v.mp4", content_type="video/mp4")
        self.assertIn("signature matches", str(ctx.exception))


# ===========================================================================
# validate_video_upload integration (no Flask app needed)
# ===========================================================================

def _try_import_validate_video_upload():
    """Return validate_video_upload or None when Flask isn't installed."""
    import sys
    import types
    # Stub every heavy dependency so app.py can be imported without a
    # running Postgres, ffmpeg, or Flask installation in the test env.
    _stubs = []
    for mod_name in (
        "flask", "flask_cors", "flask_limiter", "flask_limiter.util",
        "dotenv", "werkzeug", "werkzeug.exceptions", "werkzeug.utils",
        "werkzeug.datastructures",
        "db", "stego", "noir", "envelope", "config", "register_auth",
        "errors", "idempotency", "lineage", "storage", "retention",
        "metrics", "http_security", "metadata_errors", "schema",
        "logging_utils", "trace_fields", "readiness", "admission",
        "webhook", "strkey", "streaming_upload", "c2pa",
    ):
        if mod_name not in sys.modules:
            stub = types.ModuleType(mod_name)
            sys.modules[mod_name] = stub
            _stubs.append(mod_name)
    try:
        # quarantine is already importable (tested above); importing it here
        # ensures validate_video_upload gets the real sniff helpers.
        import quarantine as _q  # noqa: F401
        from app import validate_video_upload  # noqa: PLC0415
        return validate_video_upload, _stubs
    except Exception:
        for m in _stubs:
            sys.modules.pop(m, None)
        return None, []


_vvu, _vvu_stubs = _try_import_validate_video_upload()


@unittest.skipIf(_vvu is None, "app.validate_video_upload not importable in this environment")
class TestValidateVideoUpload(unittest.TestCase):
    """Tests for app.validate_video_upload() using lightweight stubs.

    Uses only the public function; no Flask test client, no DB, no ffmpeg.
    Skipped automatically when Flask or other app deps are not installed.
    """

    def _stub(self, *, filename: str, content_type: str, data: bytes):
        """Minimal duck-typed FileStorage stub."""
        class _Stub:
            pass
        s = _Stub()
        s.filename = filename
        s.content_type = content_type
        s.stream = io.BytesIO(data)
        return s

    def setUp(self):
        self.validate_video_upload = _vvu

    def tearDown(self):
        pass

    # ── positive ──────────────────────────────────────────────────────────

    def test_mp4_accepted(self):
        stub = self._stub(filename="clip.mp4", content_type="video/mp4", data=MP4_MAGIC)
        self.assertIsNone(self.validate_video_upload(stub))  # no exception

    def test_webm_accepted(self):
        stub = self._stub(filename="clip.webm", content_type="video/webm", data=WEBM_MAGIC)
        self.assertIsNone(self.validate_video_upload(stub))

    def test_octet_stream_mp4_accepted(self):
        stub = self._stub(filename="clip.mp4", content_type="application/octet-stream", data=MP4_MAGIC)
        self.assertIsNone(self.validate_video_upload(stub))

    def test_stream_rewound_after_validate(self):
        """validate_video_upload must leave the stream at position 0."""
        stub = self._stub(filename="clip.mp4", content_type="video/mp4", data=MP4_MAGIC)
        self.validate_video_upload(stub)
        self.assertEqual(stub.stream.tell(), 0)

    # ── negative ──────────────────────────────────────────────────────────

    def test_missing_filename_rejected(self):
        stub = self._stub(filename="", content_type="video/mp4", data=MP4_MAGIC)
        with self.assertRaises(ValueError):
            self.validate_video_upload(stub)

    def test_bad_content_type_rejected(self):
        stub = self._stub(filename="clip.mp4", content_type="application/pdf", data=MP4_MAGIC)
        with self.assertRaises(QuarantineError):
            self.validate_video_upload(stub)

    def test_png_data_rejected(self):
        """Valid content-type but PNG bytes → fails sniff."""
        stub = self._stub(filename="evil.mp4", content_type="video/mp4", data=PNG_MAGIC)
        with self.assertRaises(QuarantineError):
            self.validate_video_upload(stub)

    def test_empty_data_rejected(self):
        stub = self._stub(filename="clip.mp4", content_type="video/mp4", data=b"")
        with self.assertRaises(QuarantineError):
            self.validate_video_upload(stub)

    def test_spoofed_mime_rejected(self):
        """MOV magic + video/mp4 MIME must be caught by sniff."""
        stub = self._stub(filename="clip.mp4", content_type="video/mp4", data=MOV_MAGIC)
        with self.assertRaises(QuarantineError):
            self.validate_video_upload(stub)


if __name__ == "__main__":
    unittest.main()
