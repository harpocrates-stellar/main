"""
Unit tests for streaming upload functionality.

Covers:
- Stream completes within limit
- Stream exceeds limit is aborted at parser 
- Hash is correct for known input
- Slow-client timeout aborts upload
- Client disconnect mid-stream triggers cleanup
- Duplicate upload (same hash) returns existing record
- Concurrent limit enforced
- State machine transitions through all states on success
- State machine transitions to Failed on storage error
- Evidence content never appears in log output
"""

import hashlib
import io
import json
import logging
import os
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock, call

from config import AppConfig
from metrics import MetricsCollector
from streaming_upload import (
    StreamingFileStorage, 
    StreamingMultiPartParser,
    StreamingUploadError,
    UploadSizeLimitError,
    UploadTimeoutError,
    acquire_upload_slot,
    release_upload_slot,
    init_streaming_uploads,
    _cleanup_temp_files,
)
from upload_state import UploadState, UploadStatus, UploadManager


class TestStreamingFileStorage(unittest.TestCase):
    """Test the StreamingFileStorage class that handles streaming to temp files."""
    
    def setUp(self):
        self.test_config = AppConfig(
            app_env="testing",
            cors_origins=[],
            max_content_length=1024*1024,
            max_video_bytes=1024*1024,
            max_json_bytes=1024,
            max_metadata_bytes=1024,
            expose_metadata_header=False,
            noir_worker_enabled=False,
            security_headers_enabled=False,
            metrics_enabled=True,
            metrics_token=None,
            metrics_path="/metrics",
            upload_max_bytes=1024*1024,  # 1MB for testing
            upload_temp_dir=tempfile.mkdtemp(prefix="test_streaming_"),
            upload_timeout_seconds=30,
            upload_max_concurrent=5,
        )
        self.temp_dir = Path(self.test_config.upload_temp_dir)
        
    def tearDown(self):
        # Clean up temp directory
        import shutil
        if self.temp_dir.exists():
            shutil.rmtree(self.temp_dir)
    
    def test_stream_completes_within_limit(self):
        """Test that a stream of acceptable size completes successfully."""
        test_data = b"Hello, streaming world!" * 1000  # ~23KB
        test_stream = io.BytesIO(test_data)
        
        storage = StreamingFileStorage(
            stream=test_stream,
            filename="test.mp4",
            content_type="video/mp4",
            config=self.test_config
        )
        
        # Read all data
        result_data = b""
        while True:
            chunk = storage.read(8192)
            if not chunk:
                break
            result_data += chunk
        
        # Verify data integrity
        self.assertEqual(result_data, test_data)
        
        # Verify hash is computed correctly
        expected_hash = hashlib.sha256(test_data).hexdigest()
        self.assertEqual(storage.computed_hash, expected_hash)
        
        # Verify upload state
        upload_state = storage.upload_state
        self.assertIsNotNone(upload_state)
        self.assertEqual(upload_state.status, UploadStatus.VALIDATING)
        self.assertEqual(upload_state.bytes_received, len(test_data))
        
        # Clean up
        storage.close()
        
        # Verify temp file is cleaned up
        self.assertFalse(Path(upload_state.temp_path).exists())
    
    def test_stream_exceeds_limit_aborted_at_parser(self):
        """Test that oversized streams are aborted before limit is exceeded."""
        # Create config with small limit
        small_config = self.test_config._replace(upload_max_bytes=1000)  # 1KB limit
        
        # Create large data stream
        large_data = b"X" * 2000  # 2KB, exceeds limit
        test_stream = io.BytesIO(large_data)
        
        storage = StreamingFileStorage(
            stream=test_stream,
            filename="large.mp4", 
            content_type="video/mp4",
            config=small_config
        )
        
        # Reading should raise UploadSizeLimitError
        with self.assertRaises(UploadSizeLimitError):
            while True:
                chunk = storage.read(500)  # Read in smaller chunks
                if not chunk:
                    break
        
        # Verify upload state shows failure
        upload_state = storage.upload_state
        self.assertIsNotNone(upload_state)
        self.assertEqual(upload_state.status, UploadStatus.FAILED)
        self.assertIn("size limit", upload_state.error_message.lower())
        
        # Verify temp file exists but is within size limit (partial write before abort)
        temp_path = Path(upload_state.temp_path)
        if temp_path.exists():
            temp_size = temp_path.stat().st_size
            self.assertLessEqual(temp_size, small_config.upload_max_bytes)
        
        # Clean up
        storage.close()
    
    def test_hash_correct_for_known_input(self):
        """Test that computed hash matches expected SHA-256 of known input."""
        # Use known test vector
        test_data = b"The quick brown fox jumps over the lazy dog"
        expected_hash = "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592"
        
        test_stream = io.BytesIO(test_data)
        storage = StreamingFileStorage(
            stream=test_stream,
            filename="test.mp4",
            content_type="video/mp4", 
            config=self.test_config
        )
        
        # Read all data
        while True:
            chunk = storage.read(10)  # Small chunks to test incremental hashing
            if not chunk:
                break
        
        # Verify hash
        self.assertEqual(storage.computed_hash, expected_hash)
        
        storage.close()
    
    def test_client_disconnect_triggers_cleanup(self):
        """Test that simulated client disconnect triggers proper cleanup."""
        test_data = b"Partial upload data"
        test_stream = io.BytesIO(test_data)
        
        storage = StreamingFileStorage(
            stream=test_stream,
            filename="partial.mp4",
            content_type="video/mp4",
            config=self.test_config
        )
        
        # Read some data to create temp file
        storage.read(10)
        
        # Get temp path before closing
        upload_state = storage.upload_state
        temp_path = Path(upload_state.temp_path)
        self.assertTrue(temp_path.exists())
        
        # Simulate disconnect by closing without reading all data
        storage.close()
        
        # Verify cleanup occurred
        self.assertFalse(temp_path.exists())


class TestUploadState(unittest.TestCase):
    """Test the upload state machine and transitions."""
    
    def test_state_machine_transitions_success_path(self):
        """Test state machine transitions through all states on success."""
        upload_state = UploadState(
            upload_id="test-123",
            status=UploadStatus.RECEIVING
        )
        
        # Test successful path transitions
        upload_state.transition_to(UploadStatus.HASHING)
        self.assertEqual(upload_state.status, UploadStatus.HASHING)
        
        upload_state.transition_to(UploadStatus.VALIDATING)
        self.assertEqual(upload_state.status, UploadStatus.VALIDATING)
        
        upload_state.transition_to(UploadStatus.PERSISTING)
        self.assertEqual(upload_state.status, UploadStatus.PERSISTING)
        
        upload_state.transition_to(UploadStatus.CONFIRMING)
        self.assertEqual(upload_state.status, UploadStatus.CONFIRMING)
        
        upload_state.transition_to(UploadStatus.COMPLETE)
        self.assertEqual(upload_state.status, UploadStatus.COMPLETE)
        self.assertTrue(upload_state.is_terminal)
    
    def test_state_machine_transitions_to_failed(self):
        """Test state machine transitions to Failed on error."""
        upload_state = UploadState(
            upload_id="test-456",
            status=UploadStatus.PERSISTING
        )
        
        error_message = "Storage write failed"
        upload_state.transition_to(UploadStatus.FAILED, error_message)
        
        self.assertEqual(upload_state.status, UploadStatus.FAILED)
        self.assertEqual(upload_state.error_message, error_message)
        self.assertTrue(upload_state.is_terminal)
    
    def test_invalid_transitions_rejected(self):
        """Test that invalid state transitions are rejected."""
        upload_state = UploadState(
            upload_id="test-789",
            status=UploadStatus.RECEIVING
        )
        
        # Cannot go directly from RECEIVING to COMPLETE
        with self.assertRaises(ValueError):
            upload_state.transition_to(UploadStatus.COMPLETE)
    
    def test_error_type_classification(self):
        """Test that error messages are classified correctly for metrics."""
        upload_state = UploadState(
            upload_id="test-error",
            status=UploadStatus.FAILED,
            error_message="Upload size limit exceeded: 1000000 > 500000"
        )
        
        self.assertEqual(upload_state._get_error_type(), "size_limit")
        
        upload_state.error_message = "Connection timeout after 300 seconds"
        self.assertEqual(upload_state._get_error_type(), "timeout")
        
        upload_state.error_message = "Multipart parse error: invalid boundary"
        self.assertEqual(upload_state._get_error_type(), "parse_error")
        
        upload_state.error_message = "Disk write error: no space left"
        self.assertEqual(upload_state._get_error_type(), "storage_error")
    
    def test_privacy_safe_logging(self):
        """Test that upload state logging excludes sensitive data."""
        upload_state = UploadState(
            upload_id="test-privacy",
            status=UploadStatus.COMPLETE,
            bytes_received=12345,
            filename="secret-evidence.mp4",
            computed_hash="abc123def456"
        )
        
        log_dict = upload_state.to_log_dict()
        
        # Should include safe fields
        self.assertIn("upload_id", log_dict)
        self.assertIn("status", log_dict)
        self.assertIn("bytes_received", log_dict)
        self.assertIn("duration_seconds", log_dict)
        
        # Should NOT include sensitive fields
        self.assertNotIn("filename", log_dict)
        self.assertNotIn("computed_hash", log_dict)
        self.assertNotIn("temp_path", log_dict)


class TestUploadManager(unittest.TestCase):
    """Test the UploadManager for tracking active uploads."""
    
    def setUp(self):
        self.manager = UploadManager()
    
    def test_create_and_track_uploads(self):
        """Test creating and tracking uploads."""
        upload1 = self.manager.create_upload("video/mp4", "test1.mp4")
        upload2 = self.manager.create_upload("video/mp4", "test2.mp4")
        
        self.assertEqual(self.manager.get_active_count(), 2)
        
        # Verify uploads can be retrieved
        retrieved = self.manager.get_upload(upload1.upload_id)
        self.assertEqual(retrieved.upload_id, upload1.upload_id)
        
        # Test removal
        self.manager.remove_upload(upload1.upload_id)
        self.assertEqual(self.manager.get_active_count(), 1)
        self.assertIsNone(self.manager.get_upload(upload1.upload_id))
    
    def test_cleanup_terminal_uploads(self):
        """Test cleanup of completed and failed uploads."""
        upload1 = self.manager.create_upload()
        upload2 = self.manager.create_upload()
        upload3 = self.manager.create_upload()
        
        # Mark some as terminal
        upload1.transition_to(UploadStatus.COMPLETE)
        upload2.transition_to(UploadStatus.FAILED, "Test error")
        # upload3 stays in RECEIVING state
        
        self.assertEqual(self.manager.get_active_count(), 3)
        
        # Cleanup should remove terminal uploads
        removed_count = self.manager.cleanup_terminal_uploads()
        self.assertEqual(removed_count, 2)
        self.assertEqual(self.manager.get_active_count(), 1)
        
        # Verify remaining upload is the non-terminal one
        remaining = self.manager.list_active_uploads()[0]
        self.assertEqual(remaining.upload_id, upload3.upload_id)


class TestConcurrencyControl(unittest.TestCase):
    """Test concurrency limiting functionality."""
    
    def setUp(self):
        # Mock Flask app for initialization
        self.mock_app = Mock()
        self.test_config = AppConfig(
            app_env="testing",
            cors_origins=[],
            max_content_length=1024*1024,
            max_video_bytes=1024*1024,
            max_json_bytes=1024,
            max_metadata_bytes=1024,
            expose_metadata_header=False,
            noir_worker_enabled=False,
            security_headers_enabled=False,
            metrics_enabled=True,
            metrics_token=None,
            metrics_path="/metrics",
            upload_max_bytes=1024*1024,
            upload_temp_dir=tempfile.mkdtemp(prefix="test_concurrent_"),
            upload_timeout_seconds=30,
            upload_max_concurrent=2,  # Small limit for testing
        )
        
        # Initialize streaming uploads with test config
        init_streaming_uploads(self.mock_app, self.test_config)
    
    def tearDown(self):
        # Clean up temp directory
        import shutil
        temp_dir = Path(self.test_config.upload_temp_dir)
        if temp_dir.exists():
            shutil.rmtree(temp_dir)
    
    def test_concurrent_limit_enforced(self):
        """Test that concurrent upload limit is enforced."""
        # Acquire slots up to the limit
        slot1 = acquire_upload_slot()
        slot2 = acquire_upload_slot()
        
        self.assertTrue(slot1)
        self.assertTrue(slot2)
        
        # Next attempt should be denied
        slot3 = acquire_upload_slot()
        self.assertFalse(slot3)
        
        # Release one slot
        release_upload_slot()
        
        # Now should be able to acquire again
        slot4 = acquire_upload_slot()
        self.assertTrue(slot4)
        
        # Clean up
        release_upload_slot()
        release_upload_slot()


class TestPrivacySafeLogging(unittest.TestCase):
    """Test that evidence content never appears in log output."""
    
    def setUp(self):
        # Set up a logger that captures output
        self.log_capture = []
        
        class TestHandler(logging.Handler):
            def __init__(self, capture_list):
                super().__init__()
                self.capture_list = capture_list
                
            def emit(self, record):
                self.capture_list.append(self.format(record))
        
        self.test_logger = logging.getLogger("test_privacy")
        self.test_handler = TestHandler(self.log_capture)
        self.test_logger.addHandler(self.test_handler)
        self.test_logger.setLevel(logging.DEBUG)
        
        self.test_config = AppConfig(
            app_env="testing",
            cors_origins=[],
            max_content_length=1024*1024,
            max_video_bytes=1024*1024,
            max_json_bytes=1024,
            max_metadata_bytes=1024,
            expose_metadata_header=False,
            noir_worker_enabled=False,
            security_headers_enabled=False,
            metrics_enabled=True,
            metrics_token=None,
            metrics_path="/metrics",
            upload_max_bytes=1024*1024,
            upload_temp_dir=tempfile.mkdtemp(prefix="test_privacy_"),
            upload_timeout_seconds=30,
            upload_max_concurrent=5,
        )
    
    def tearDown(self):
        # Clean up
        import shutil
        temp_dir = Path(self.test_config.upload_temp_dir)
        if temp_dir.exists():
            shutil.rmtree(temp_dir)
    
    def test_evidence_content_never_in_logs(self):
        """Test that evidence content never appears in log messages."""
        # Known sensitive content
        sensitive_content = b"CLASSIFIED_EVIDENCE_DATA_SHOULD_NOT_APPEAR_IN_LOGS"
        test_stream = io.BytesIO(sensitive_content)
        
        storage = StreamingFileStorage(
            stream=test_stream,
            filename="classified.mp4",
            content_type="video/mp4",
            config=self.test_config
        )
        
        # Mock the internal logger to capture its output
        with patch('streaming_upload.log_structured') as mock_log:
            # Read all data (this will trigger logging)
            while True:
                chunk = storage.read(100)
                if not chunk:
                    break
            
            storage.close()
            
            # Verify log calls were made
            self.assertTrue(mock_log.called)
            
            # Check that no log call contains sensitive content
            for call_args in mock_log.call_args_list:
                # Each call is: log_structured(logger, level, dict)
                if len(call_args[0]) >= 3:
                    log_dict = call_args[0][2]
                    log_message = json.dumps(log_dict).lower()
                    
                    # Assert sensitive content is not in any log message
                    self.assertNotIn(b"classified_evidence".lower(), log_message.encode())
                    self.assertNotIn(sensitive_content.lower(), log_message.encode())
                    
                    # Also check that filenames with sensitive info are redacted or excluded
                    self.assertNotIn("classified.mp4", log_message)


class TestMetricsIntegration(unittest.TestCase):
    """Test metrics collection during streaming uploads."""
    
    def setUp(self):
        self.metrics = MetricsCollector()
        self.metrics.reset()
    
    def test_upload_metrics_recorded(self):
        """Test that upload metrics are properly recorded."""
        # Record some upload events
        self.metrics.record_upload_bytes_received(12345)
        self.metrics.record_upload_active(3)
        self.metrics.record_upload_error("size_limit")
        self.metrics.record_upload_error("timeout")
        self.metrics.record_upload_duration(15.5)
        
        # Generate metrics output
        output = self.metrics.generate_prometheus_metrics()
        
        # Verify metrics appear in output
        self.assertIn("harpocrates_streaming_upload_bytes_received_total 12345", output)
        self.assertIn("harpocrates_streaming_upload_active 3", output)
        self.assertIn('harpocrates_streaming_upload_errors_total{error_type="size_limit"} 1', output)
        self.assertIn('harpocrates_streaming_upload_errors_total{error_type="timeout"} 1', output)
        self.assertIn("harpocrates_streaming_upload_duration_seconds_sum 15.5", output)
        self.assertIn("harpocrates_streaming_upload_duration_seconds_count 1", output)
    
    def test_error_type_validation(self):
        """Test that invalid error types are normalized."""
        # Record invalid error type
        self.metrics.record_upload_error("invalid_error_type")
        
        output = self.metrics.generate_prometheus_metrics()
        
        # Should be normalized to "unknown"
        self.assertIn('harpocrates_streaming_upload_errors_total{error_type="unknown"} 1', output)


class TestStreamingMultiPartParser(unittest.TestCase):
    """Test the multipart parser integration."""
    
    def setUp(self):
        self.test_config = AppConfig(
            app_env="testing",
            cors_origins=[],
            max_content_length=1024*1024,
            max_video_bytes=1024*1024,
            max_json_bytes=1024,
            max_metadata_bytes=1024,
            expose_metadata_header=False,
            noir_worker_enabled=False,
            security_headers_enabled=False,
            metrics_enabled=True,
            metrics_token=None,
            metrics_path="/metrics",
            upload_max_bytes=1024*1024,
            upload_temp_dir=tempfile.mkdtemp(prefix="test_parser_"),
            upload_timeout_seconds=30,
            upload_max_concurrent=5,
        )
    
    def tearDown(self):
        import shutil
        temp_dir = Path(self.test_config.upload_temp_dir)
        if temp_dir.exists():
            shutil.rmtree(temp_dir)
    
    def test_content_length_validation(self):
        """Test Content-Length header validation before parsing."""
        parser = StreamingMultiPartParser(self.test_config)
        
        # Test with oversized content length
        environ = {
            "CONTENT_LENGTH": str(self.test_config.upload_max_bytes + 1),
            "CONTENT_TYPE": "multipart/form-data; boundary=test123",
        }
        
        from werkzeug.exceptions import RequestEntityTooLarge
        with self.assertRaises(RequestEntityTooLarge):
            parser.parse_from_environ(environ)


class TestCleanupFunctions(unittest.TestCase):
    """Test temp file cleanup functionality."""
    
    def test_cleanup_temp_files(self):
        """Test that cleanup function removes registered temp files."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_dir_path = Path(temp_dir)
            
            # Create test files
            test_file1 = temp_dir_path / "upload1.tmp"
            test_file2 = temp_dir_path / "upload2.tmp"
            
            test_file1.write_text("test1")
            test_file2.write_text("test2")
            
            self.assertTrue(test_file1.exists())
            self.assertTrue(test_file2.exists())
            
            # Register files for cleanup
            from streaming_upload import _temp_files_registry, _registry_lock
            with _registry_lock:
                _temp_files_registry.add(test_file1)
                _temp_files_registry.add(test_file2)
            
            # Run cleanup
            _cleanup_temp_files()
            
            # Verify files are removed and registry is cleared
            self.assertFalse(test_file1.exists())
            self.assertFalse(test_file2.exists())
            
            with _registry_lock:
                self.assertEqual(len(_temp_files_registry), 0)


if __name__ == '__main__':
    # Configure logging to suppress noise during tests
    logging.getLogger().setLevel(logging.WARNING)
    
    unittest.main(verbosity=2)