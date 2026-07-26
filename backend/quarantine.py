import contextlib
import os
import tempfile
from pathlib import Path


class QuarantineError(ValueError):
    """Raised when an uploaded file fails quarantine signature checks."""
    pass


class SignatureScanner:
    """
    Scans file magic bytes to verify structural compatibility with expected
    video formats (MP4, WebM) before allowing ffmpeg to parse them.
    """
    @staticmethod
    def is_valid_video(path: Path) -> bool:
        if not path.is_file():
            return False
            
        try:
            with path.open("rb") as f:
                header = f.read(16)
        except OSError:
            return False
            
        if len(header) < 12:
            return False
            
        # Check for WebM EBML signature
        if header.startswith(b'\x1a\x45\xdf\xa3'):
            return True
            
        # Check for MP4 ftyp box
        if header[4:8] == b'ftyp':
            return True
            
        return False


@contextlib.contextmanager
def isolate_upload(flask_file):
    """
    Context manager to safely save an uploaded file to an isolated
    temporary directory for quarantine processing. Yields the path
    to the safely quarantined file if it passes the signature scan.
    """
    with tempfile.TemporaryDirectory(prefix="harpocrates-quarantine-") as tmp_dir:
        tmp_path = Path(tmp_dir) / "upload.tmp"
        flask_file.save(str(tmp_path))
        
        # Restrict permissions
        os.chmod(tmp_path, 0o600)
        
        if not SignatureScanner.is_valid_video(tmp_path):
            raise QuarantineError("uploaded file failed signature scan; invalid video format")
            
        yield tmp_path
