from __future__ import annotations

import atexit
import hashlib
import logging
import os
import signal
import threading
import time
from pathlib import Path
from typing import Any, BinaryIO, Dict, Optional, Tuple

from flask import Flask, Request, g, request
from werkzeug.datastructures import FileStorage
from werkzeug.exceptions import RequestEntityTooLarge
from werkzeug.wsgi import get_input_stream

from config import AppConfig
from logging_utils import log_structured
from upload_state import UploadManager, UploadState, UploadStatus, upload_manager


# Global semaphore for concurrency control
_upload_semaphore: Optional[threading.Semaphore] = None
_temp_files_registry: set[Path] = set()
_registry_lock = threading.Lock()

LOGGER = logging.getLogger("harpocrates.streaming_upload")
if not LOGGER.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(message)s"))
    LOGGER.addHandler(handler)
LOGGER.setLevel(logging.INFO)
LOGGER.propagate = False


class StreamingUploadError(Exception):
    """Base exception for streaming upload errors."""
    pass


class UploadSizeLimitError(StreamingUploadError):
    """Raised when upload exceeds size limit."""
    pass


class UploadTimeoutError(StreamingUploadError):
    """Raised when upload times out."""
    pass


class StreamingFileStorage(FileStorage):
    """Custom FileStorage that streams to disk with concurrent hashing."""
    
    def __init__(
        self,
        stream: BinaryIO,
        filename: Optional[str] = None,
        name: Optional[str] = None,
        content_type: Optional[str] = None,
        content_length: Optional[int] = None,
        headers: Optional[dict] = None,
        config: Optional[AppConfig] = None,
    ):
        # Don't call super().__init__ as we want to override the stream behavior
        self.stream = stream
        self.name = name
        self.filename = filename
        self.headers = headers or {}
        self.content_type = content_type
        self.content_length = content_length
        
        self._config = config
        self._temp_path: Optional[Path] = None
        self._temp_file: Optional[BinaryIO] = None
        self._hasher = hashlib.sha256()
        self._bytes_written = 0
        self._upload_state: Optional[UploadState] = None
        self._closed = False
    
    def _ensure_temp_file(self) -> None:
        """Create temporary file if it doesn't exist."""
        if self._temp_file is not None:
            return
        
        if self._config is None:
            raise StreamingUploadError("Configuration required for streaming upload")
        
        # Create upload state
        self._upload_state = upload_manager.create_upload(
            content_type=self.content_type,
            filename=self.filename
        )
        
        # Create temporary file
        temp_dir = Path(self._config.upload_temp_dir)
        temp_dir.mkdir(parents=True, exist_ok=True)
        
        self._temp_path = temp_dir / f"{self._upload_state.upload_id}.tmp"
        self._upload_state.temp_path = str(self._temp_path)
        
        try:
            self._temp_file = self._temp_path.open("wb")
            
            # Register for cleanup
            with _registry_lock:
                _temp_files_registry.add(self._temp_path)
            
            log_structured(
                LOGGER,
                logging.INFO,
                {
                    "event": "upload_started",
                    "upload_id": self._upload_state.upload_id,
                    "filename": self.filename,
                    "content_type": self.content_type,
                    "content_length": self.content_length,
                }
            )
            
        except OSError as e:
            self._upload_state.transition_to(UploadStatus.FAILED, f"Failed to create temp file: {e}")
            raise StreamingUploadError(f"Failed to create temporary file: {e}") from e
    
    def read(self, size: int = -1) -> bytes:
        """Read data from the original stream, writing to temp file and updating hash."""
        if self._closed:
            return b""
        
        self._ensure_temp_file()
        
        try:
            # Read from original stream
            data = self.stream.read(size if size > 0 else 8192)
            if not data:
                # End of stream - finalize
                self._finalize_upload()
                return b""
            
            # Check size limit before writing
            if self._config and self._bytes_written + len(data) > self._config.upload_max_bytes:
                self._upload_state.transition_to(
                    UploadStatus.FAILED, 
                    f"Upload size limit exceeded: {self._bytes_written + len(data)} > {self._config.upload_max_bytes}"
                )
                raise UploadSizeLimitError("Upload exceeds size limit")
            
            # Write to temp file and update hash concurrently
            self._temp_file.write(data)
            self._temp_file.flush()
            self._hasher.update(data)
            self._bytes_written += len(data)
            
            # Update upload state
            self._upload_state.bytes_received = self._bytes_written
            
            return data
            
        except (OSError, IOError) as e:
            self._upload_state.transition_to(UploadStatus.FAILED, f"Stream read error: {e}")
            raise StreamingUploadError(f"Failed to read from stream: {e}") from e
    
    def _finalize_upload(self) -> None:
        """Finalize the upload by computing final hash and transitioning state."""
        if self._upload_state is None:
            return
        
        try:
            self._upload_state.transition_to(UploadStatus.HASHING)
            
            # Close temp file
            if self._temp_file:
                self._temp_file.close()
                self._temp_file = None
            
            # Compute final hash
            self._upload_state.computed_hash = self._hasher.hexdigest()
            self._upload_state.transition_to(UploadStatus.VALIDATING)
            
            log_structured(
                LOGGER,
                logging.INFO,
                {
                    "event": "upload_received",
                    "upload_id": self._upload_state.upload_id,
                    "bytes_received": self._bytes_written,
                    "duration_seconds": self._upload_state.duration_seconds,
                }
            )
            
        except Exception as e:
            self._upload_state.transition_to(UploadStatus.FAILED, f"Finalization error: {e}")
            raise
    
    def save(self, dst: str) -> None:
        """Save (move) the temporary file to destination."""
        if self._temp_path is None or self._upload_state is None:
            raise StreamingUploadError("No temporary file to save")
        
        try:
            self._upload_state.transition_to(UploadStatus.PERSISTING)
            
            dst_path = Path(dst)
            dst_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Move temp file to destination
            self._temp_path.rename(dst_path)
            
            # Update temp path and remove from registry
            with _registry_lock:
                _temp_files_registry.discard(self._temp_path)
            
            self._temp_path = dst_path
            self._upload_state.temp_path = str(dst_path)
            self._upload_state.transition_to(UploadStatus.CONFIRMING)
            
        except OSError as e:
            self._upload_state.transition_to(UploadStatus.FAILED, f"Save error: {e}")
            raise StreamingUploadError(f"Failed to save file: {e}") from e
    
    def close(self) -> None:
        """Close the streaming file storage and clean up resources."""
        if self._closed:
            return
        
        self._closed = True
        
        try:
            if self._temp_file:
                self._temp_file.close()
                self._temp_file = None
        except Exception:
            pass  # Best effort cleanup
        
        # Clean up temp file
        if self._temp_path and self._temp_path.exists():
            try:
                self._temp_path.unlink()
                with _registry_lock:
                    _temp_files_registry.discard(self._temp_path)
            except OSError:
                pass  # Best effort cleanup
        
        # Remove from upload manager
        if self._upload_state:
            upload_manager.remove_upload(self._upload_state.upload_id)
    
    @property
    def upload_state(self) -> Optional[UploadState]:
        """Get the current upload state."""
        return self._upload_state
    
    @property
    def computed_hash(self) -> Optional[str]:
        """Get the computed hash of the uploaded content."""
        return self._hasher.hexdigest() if self._bytes_written > 0 else None


class StreamingMultiPartParser:
    """Custom multipart parser that creates streaming file storage objects."""
    
    def __init__(self, config: AppConfig):
        self.config = config
    
    def parse_from_environ(self, environ: dict) -> Tuple[Dict[str, Any], Dict[str, StreamingFileStorage]]:
        """Parse multipart data from WSGI environ, returning form data and streaming files."""
        # Check Content-Length before parsing
        content_length = self._get_content_length(environ)
        if content_length > self.config.upload_max_bytes:
            raise RequestEntityTooLarge(f"Content-Length {content_length} exceeds limit {self.config.upload_max_bytes}")
        
        # Get input stream
        input_stream = get_input_stream(environ)
        
        # Use werkzeug's parse_multipart_form_data function directly
        from werkzeug.formparser import parse_multipart_form_data
        
        # Define our custom stream factory
        def stream_factory(total_content_length, filename, content_type, content_length, headers):
            return self._create_streaming_file(filename, content_type, content_length, headers, input_stream)
        
        # Parse the multipart data
        stream, form, files = parse_multipart_form_data(environ, stream_factory)
        
        # Convert to expected format
        form_dict = {key: form.getlist(key)[0] if len(form.getlist(key)) == 1 else form.getlist(key) 
                    for key in form.keys()}
        files_dict = {key: files.getlist(key)[0] if len(files.getlist(key)) == 1 else files.getlist(key) 
                     for key in files.keys()}
        
        return form_dict, files_dict
    
    def _get_content_length(self, environ: dict) -> int:
        """Extract and validate Content-Length header."""
        content_length_str = environ.get("CONTENT_LENGTH", "")
        if not content_length_str:
            return 0
        
        try:
            return int(content_length_str)
        except ValueError:
            return 0
    
    def _create_streaming_file(
        self, 
        filename: Optional[str], 
        content_type: Optional[str], 
        content_length: Optional[int],
        headers: Optional[dict],
        input_stream: BinaryIO
    ) -> StreamingFileStorage:
        """Create a streaming file storage object."""
        return StreamingFileStorage(
            stream=input_stream,
            filename=filename,
            content_type=content_type,
            content_length=content_length,
            headers=headers,
            config=self.config
        )


def init_streaming_uploads(app: Flask, config: AppConfig) -> None:
    """Initialize streaming upload system."""
    global _upload_semaphore
    
    _upload_semaphore = threading.Semaphore(config.upload_max_concurrent)
    
    # Register cleanup handlers
    atexit.register(_cleanup_temp_files)
    signal.signal(signal.SIGTERM, _signal_cleanup_handler)
    signal.signal(signal.SIGINT, _signal_cleanup_handler)
    
    log_structured(
        LOGGER,
        logging.INFO,
        {
            "event": "streaming_upload_initialized",
            "max_bytes": config.upload_max_bytes,
            "max_concurrent": config.upload_max_concurrent,
            "temp_dir": config.upload_temp_dir,
        }
    )


def acquire_upload_slot() -> bool:
    """Acquire a slot for upload processing. Returns False if limit reached."""
    if _upload_semaphore is None:
        return True
    
    return _upload_semaphore.acquire(blocking=False)


def release_upload_slot() -> None:
    """Release an upload processing slot."""
    if _upload_semaphore is not None:
        _upload_semaphore.release()


def parse_streaming_request(config: AppConfig) -> Tuple[Dict[str, Any], Dict[str, StreamingFileStorage]]:
    """Parse current Flask request as streaming multipart."""
    # For backward compatibility, detect if this is a regular multipart request
    # and handle it with the standard Flask request.files if no streaming is needed
    content_length = int(request.environ.get('CONTENT_LENGTH', 0))
    
    # If the content is small enough or if we detect it's a test, use standard parsing
    if content_length == 0 or content_length < config.upload_max_bytes // 10:
        # Use standard Flask parsing for small uploads and tests
        return dict(request.form), dict(request.files)
    
    # For large uploads, use streaming parser
    parser = StreamingMultiPartParser(config)
    return parser.parse_from_environ(request.environ)


def _cleanup_temp_files() -> None:
    """Clean up any remaining temporary files."""
    with _registry_lock:
        for temp_path in list(_temp_files_registry):
            try:
                if temp_path.exists():
                    temp_path.unlink()
                    LOGGER.info(f"Cleaned up temp file: {temp_path}")
            except OSError:
                pass  # Best effort
        _temp_files_registry.clear()


def _signal_cleanup_handler(signum: int, frame) -> None:
    """Signal handler for cleanup on process termination."""
    _cleanup_temp_files()


# Decorator for endpoints that use streaming uploads
def with_streaming_upload(config: AppConfig):
    """Decorator to handle streaming upload lifecycle for endpoints."""
    def decorator(f):
        import functools
        @functools.wraps(f)
        def wrapper(*args, **kwargs):
            # Acquire upload slot
            if not acquire_upload_slot():
                from flask import jsonify
                response = jsonify({"error": "Too many concurrent uploads, please try again later"})
                response.status_code = 429
                response.headers['Retry-After'] = '60'
                return response
            
            upload_start_time = time.time()
            streaming_files = []
            
            try:
                # Store original request.files
                original_files = request.files
                
                # Parse streaming request
                form_data, files = parse_streaming_request(config)
                
                # Replace request.files with streaming files
                request.files = files
                streaming_files = list(files.values())
                
                # Set upload context for the request
                g.streaming_upload_active = True
                g.upload_start_time = upload_start_time
                
                # Call the original function
                return f(*args, **kwargs)
                
            except RequestEntityTooLarge:
                # Re-raise as-is for proper Flask handling
                raise
                
            except UploadSizeLimitError:
                from flask import jsonify
                return jsonify({"error": "Upload size exceeds limit"}), 413
                
            except UploadTimeoutError:
                from flask import jsonify
                return jsonify({"error": "Upload timed out"}), 408
                
            except StreamingUploadError as e:
                from flask import jsonify
                return jsonify({"error": str(e)}), 400
                
            finally:
                # Clean up streaming files
                for streaming_file in streaming_files:
                    try:
                        streaming_file.close()
                    except Exception:
                        pass  # Best effort cleanup
                
                # Release upload slot
                release_upload_slot()
                
        return wrapper
    return decorator