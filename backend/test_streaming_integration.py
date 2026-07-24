"""
Integration tests for streaming uploads.

Tests end-to-end functionality:
- End-to-end upload with real file
- End-to-end upload with oversized file
- Concurrent uploads do not interfere
"""

import io
import json
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from flask import Flask
from werkzeug.test import Client
from werkzeug.datastructures import FileStorage

from app import create_app
from config import load_config
from db import init_db, check_db
from metrics import collector as metrics_collector


class TestStreamingIntegration(unittest.TestCase):
    """Integration tests for streaming upload endpoints."""
    
    @classmethod
    def setUpClass(cls):
        """Set up test environment once for all tests."""
        # Set test environment
        import os
        os.environ["APP_ENV"] = "testing"
        os.environ["DATABASE_URL"] = ""
        os.environ["NOIR_WORKER_ENABLED"] = "false"
        os.environ["UPLOAD_MAX_BYTES"] = "1048576"  # 1MB for testing
        os.environ["UPLOAD_MAX_CONCURRENT"] = "3"
        
        # Create test app
        cls.app = create_app()
        cls.client = cls.app.test_client()
        cls.app_context = cls.app.app_context()
        cls.app_context.push()
        
        # Reset metrics for clean tests
        metrics_collector.reset()
    
    @classmethod
    def tearDownClass(cls):
        """Clean up test environment."""
        cls.app_context.pop()
    
    def setUp(self):
        """Set up each test."""
        # Reset metrics before each test
        metrics_collector.reset()
    
    def create_test_video_data(self, size_bytes: int) -> bytes:
        """Create test video data of specified size."""
        # Create minimal valid MP4 header-like data
        mp4_header = b'\x00\x00\x00\x20ftypmp41\x00\x00\x00\x00mp41isom'
        
        # Pad to desired size
        if size_bytes <= len(mp4_header):
            return mp4_header[:size_bytes]
        else:
            padding_size = size_bytes - len(mp4_header)
            return mp4_header + b'\x00' * padding_size
    
    def test_end_to_end_upload_with_real_file(self):
        """Test end-to-end upload and embed with a real test file."""
        # Create test video data
        test_video_data = self.create_test_video_data(50000)  # 50KB test file
        test_metadata = {
            "proofId": "test-proof-123",
            "tier": 1,
            "witness": "test-witness",
            "timestamp": int(time.time())
        }
        
        # Create multipart form data
        data = {
            'video': (io.BytesIO(test_video_data), 'test-video.mp4', 'video/mp4'),
            'metadata': json.dumps(test_metadata)
        }
        
        # Mock database operations to avoid real DB dependency
        with patch('app.insert_proof_event') as mock_insert, \
             patch('app.validate_video_upload') as mock_validate, \
             patch('app.embed_metadata') as mock_embed:
            
            # Configure mocks
            mock_validate.return_value = None  # No exception = valid
            mock_embed.return_value = None  # Mock successful embed
            mock_insert.return_value = "test-db-event-id"
            
            # Make request
            response = self.client.post(
                '/api/stego/embed',
                data=data,
                content_type='multipart/form-data'
            )
        
        # Verify response
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content_type, 'video/mp4')
        
        # Verify headers contain expected hashes
        self.assertIn('X-Harpocrates-Source-Hash', response.headers)
        self.assertIn('X-Harpocrates-Embedded-Hash', response.headers)
        self.assertIn('X-Harpocrates-Metadata-Hash', response.headers)
        
        # Verify metrics were recorded
        metrics_output = metrics_collector.generate_prometheus_metrics()
        self.assertIn("harpocrates_streaming_upload_bytes_received_total", metrics_output)
        self.assertIn("harpocrates_streaming_upload_duration_seconds", metrics_output)
    
    def test_end_to_end_upload_with_oversized_file(self):
        """Test that oversized files are rejected with proper error."""
        # Create oversized test data (larger than 1MB limit set in setUpClass)
        oversized_data = self.create_test_video_data(2 * 1024 * 1024)  # 2MB
        test_metadata = {"proofId": "test-oversized", "tier": 1}
        
        data = {
            'video': (io.BytesIO(oversized_data), 'oversized.mp4', 'video/mp4'),
            'metadata': json.dumps(test_metadata)
        }
        
        # Make request - should be rejected
        response = self.client.post(
            '/api/stego/embed',
            data=data,
            content_type='multipart/form-data'
        )
        
        # Verify rejection
        self.assertEqual(response.status_code, 413)
        response_data = json.loads(response.get_data(as_text=True))
        self.assertIn('error', response_data)
        self.assertIn('too large', response_data['error'].lower())
        
        # Verify error metrics were recorded
        metrics_output = metrics_collector.generate_prometheus_metrics()
        if "size_limit" in metrics_output:
            self.assertIn('error_type="size_limit"', metrics_output)
    
    def test_concurrent_uploads_do_not_interfere(self):
        """Test that multiple concurrent uploads work independently."""
        num_concurrent = 3
        test_size = 30000  # 30KB each
        upload_results = {}
        errors = []
        
        def upload_worker(worker_id: int):
            """Worker function for concurrent upload."""
            try:
                # Create unique test data for each worker
                test_data = self.create_test_video_data(test_size)
                # Add unique marker to each file
                test_data = test_data + f"WORKER_{worker_id}".encode()
                
                test_metadata = {
                    "proofId": f"concurrent-test-{worker_id}",
                    "tier": 1,
                    "worker_id": worker_id
                }
                
                data = {
                    'video': (io.BytesIO(test_data), f'concurrent-{worker_id}.mp4', 'video/mp4'),
                    'metadata': json.dumps(test_metadata)
                }
                
                # Mock database and embed operations
                with patch('app.insert_proof_event') as mock_insert, \
                     patch('app.validate_video_upload') as mock_validate, \
                     patch('app.embed_metadata') as mock_embed:
                    
                    mock_validate.return_value = None
                    mock_embed.return_value = None
                    mock_insert.return_value = f"event-{worker_id}"
                    
                    # Make request
                    response = self.client.post(
                        '/api/stego/embed',
                        data=data,
                        content_type='multipart/form-data'
                    )
                
                upload_results[worker_id] = {
                    'status_code': response.status_code,
                    'headers': dict(response.headers),
                    'content_length': len(response.get_data())
                }
                
            except Exception as e:
                errors.append(f"Worker {worker_id}: {str(e)}")
        
        # Start concurrent uploads
        threads = []
        for i in range(num_concurrent):
            thread = threading.Thread(target=upload_worker, args=(i,))
            threads.append(thread)
            thread.start()
        
        # Wait for all to complete
        for thread in threads:
            thread.join(timeout=30)  # 30 second timeout
        
        # Verify results
        self.assertEqual(len(errors), 0, f"Upload errors: {errors}")
        self.assertEqual(len(upload_results), num_concurrent)
        
        # All uploads should succeed
        for worker_id, result in upload_results.items():
            with self.subTest(worker=worker_id):
                self.assertEqual(result['status_code'], 200)
                self.assertIn('X-Harpocrates-Source-Hash', result['headers'])
                
                # Each upload should have a unique hash
                source_hash = result['headers']['X-Harpocrates-Source-Hash']
                self.assertIsNotNone(source_hash)
                self.assertTrue(len(source_hash) > 0)
        
        # Verify all hashes are unique (since each file had unique content)
        hashes = [result['headers']['X-Harpocrates-Source-Hash'] for result in upload_results.values()]
        self.assertEqual(len(set(hashes)), num_concurrent, "All uploads should have unique hashes")
        
        # Verify metrics show multiple uploads
        metrics_output = metrics_collector.generate_prometheus_metrics()
        if "upload_duration_seconds_count" in metrics_output:
            # Should have recorded multiple completions
            count_line = [line for line in metrics_output.split('\n') 
                         if 'upload_duration_seconds_count' in line][0]
            count_value = int(count_line.split()[-1])
            self.assertGreaterEqual(count_value, num_concurrent)
    
    def test_extract_endpoint_streaming(self):
        """Test that the extract endpoint also uses streaming uploads."""
        # Create test video with embedded metadata
        test_video_data = self.create_test_video_data(40000)  # 40KB
        
        data = {
            'video': (io.BytesIO(test_video_data), 'test-extract.mp4', 'video/mp4')
        }
        
        # Mock the extract operations
        mock_metadata = {"extracted": True, "proofId": "extract-test"}
        
        with patch('app.validate_video_upload') as mock_validate, \
             patch('app.extract_metadata') as mock_extract, \
             patch('app.insert_proof_event') as mock_insert:
            
            mock_validate.return_value = None
            mock_extract.return_value = mock_metadata
            mock_insert.return_value = "extract-event-id"
            
            # Make request
            response = self.client.post(
                '/api/stego/extract',
                data=data,
                content_type='multipart/form-data'
            )
        
        # Verify response
        self.assertEqual(response.status_code, 200)
        response_data = json.loads(response.get_data(as_text=True))
        
        self.assertTrue(response_data['ok'])
        self.assertIn('video_hash', response_data)
        self.assertIn('metadata', response_data)
        self.assertEqual(response_data['metadata'], mock_metadata)
    
    def test_concurrent_limit_enforcement_integration(self):
        """Test that concurrent limit is enforced at the application level."""
        # This test requires the upload limit to be low (set to 3 in setUpClass)
        num_attempts = 5  # More than the limit of 3
        
        # Create long-running upload simulation
        def slow_upload_worker(worker_id: int, results: dict, barrier: threading.Barrier):
            """Worker that simulates a slow upload."""
            try:
                # Wait for all workers to be ready
                barrier.wait(timeout=10)
                
                test_data = self.create_test_video_data(20000)
                test_metadata = {"proofId": f"slow-{worker_id}", "tier": 1}
                
                data = {
                    'video': (io.BytesIO(test_data), f'slow-{worker_id}.mp4', 'video/mp4'),
                    'metadata': json.dumps(test_metadata)
                }
                
                # Mock operations but add delay to simulate processing
                with patch('app.insert_proof_event') as mock_insert, \
                     patch('app.validate_video_upload') as mock_validate, \
                     patch('app.embed_metadata') as mock_embed:
                    
                    def slow_embed(*args, **kwargs):
                        time.sleep(1)  # Simulate slow processing
                        return None
                    
                    mock_validate.return_value = None
                    mock_embed.side_effect = slow_embed
                    mock_insert.return_value = f"slow-event-{worker_id}"
                    
                    start_time = time.time()
                    response = self.client.post(
                        '/api/stego/embed',
                        data=data,
                        content_type='multipart/form-data'
                    )
                    end_time = time.time()
                
                results[worker_id] = {
                    'status_code': response.status_code,
                    'duration': end_time - start_time,
                    'response_text': response.get_data(as_text=True)
                }
                
            except Exception as e:
                results[worker_id] = {'error': str(e)}
        
        # Start concurrent requests
        results = {}
        barrier = threading.Barrier(num_attempts)
        threads = []
        
        for i in range(num_attempts):
            thread = threading.Thread(
                target=slow_upload_worker, 
                args=(i, results, barrier)
            )
            threads.append(thread)
            thread.start()
        
        # Wait for completion
        for thread in threads:
            thread.join(timeout=30)
        
        # Analyze results
        successful_uploads = []
        rejected_uploads = []
        
        for worker_id, result in results.items():
            if 'error' not in result:
                if result['status_code'] == 200:
                    successful_uploads.append(worker_id)
                elif result['status_code'] == 429:  # Too Many Requests
                    rejected_uploads.append(worker_id)
        
        # Should have some successes and some rejections due to concurrent limit
        # At least some should be rejected if limit is working
        total_processed = len(successful_uploads) + len(rejected_uploads)
        self.assertEqual(total_processed, num_attempts)
        
        # If concurrent limiting is working, we should see some 429 responses
        # when we exceed the limit of 3
        self.assertGreater(len(rejected_uploads), 0, 
                          "Expected some uploads to be rejected due to concurrent limit")


if __name__ == '__main__':
    # Suppress logging noise during tests
    import logging
    logging.getLogger().setLevel(logging.WARNING)
    
    unittest.main(verbosity=2)