import unittest
import json
import sys
from unittest.mock import patch, MagicMock
from devx.testnet_dry_run import (
    run_dry_run,
    validate_metadata,
    validate_payload_size,
    compute_hash,
    check_dependencies,
    MalformedInputError,
    OversizedInputError,
    UnsupportedVersionError,
    DependencyFailureError
)


class TestValidateMetadata(unittest.TestCase):
    """Test metadata validation logic."""
    
    def test_valid_metadata(self):
        """Test valid metadata structure."""
        metadata = {
            'version': 'v1',
            'timestamp': '2024-01-01T00:00:00Z',
            'hash': 'abc123'
        }
        self.assertTrue(validate_metadata(metadata))
    
    def test_missing_version(self):
        """Test metadata without version key."""
        metadata = {
            'timestamp': '2024-01-01T00:00:00Z',
            'hash': 'abc123'
        }
        with self.assertRaises(MalformedInputError):
            validate_metadata(metadata)
    
    def test_missing_timestamp(self):
        """Test metadata without timestamp key."""
        metadata = {
            'version': 'v1',
            'hash': 'abc123'
        }
        with self.assertRaises(MalformedInputError):
            validate_metadata(metadata)
    
    def test_missing_hash(self):
        """Test metadata without hash key."""
        metadata = {
            'version': 'v1',
            'timestamp': '2024-01-01T00:00:00Z'
        }
        with self.assertRaises(MalformedInputError):
            validate_metadata(metadata)
    
    def test_unsupported_version(self):
        """Test unsupported version."""
        metadata = {
            'version': 'v3',
            'timestamp': '2024-01-01T00:00:00Z',
            'hash': 'abc123'
        }
        with self.assertRaises(UnsupportedVersionError):
            validate_metadata(metadata)
    
    def test_invalid_metadata_type(self):
        """Test non-dictionary metadata."""
        with self.assertRaises(MalformedInputError):
            validate_metadata("not a dict")


class TestValidatePayloadSize(unittest.TestCase):
    """Test payload size validation."""
    
    def test_valid_size(self):
        """Test payload within size limits."""
        payload = b"x" * 1024
        self.assertTrue(validate_payload_size(payload))
    
    def test_max_size(self):
        """Test payload at maximum size."""
        from devx.testnet_dry_run import MAX_PAYLOAD_SIZE
        payload = b"x" * MAX_PAYLOAD_SIZE
        self.assertTrue(validate_payload_size(payload))
    
    def test_oversized_payload(self):
        """Test payload exceeding size limits."""
        from devx.testnet_dry_run import MAX_PAYLOAD_SIZE
        payload = b"x" * (MAX_PAYLOAD_SIZE + 1)
        with self.assertRaises(OversizedInputError):
            validate_payload_size(payload)


class TestComputeHash(unittest.TestCase):
    """Test hash computation."""
    
    def test_consistent_hash(self):
        """Test that same input produces same hash."""
        data = b"test data"
        hash1 = compute_hash(data)
        hash2 = compute_hash(data)
        self.assertEqual(hash1, hash2)
    
    def test_different_data_different_hash(self):
        """Test that different inputs produce different hashes."""
        data1 = b"test data 1"
        data2 = b"test data 2"
        hash1 = compute_hash(data1)
        hash2 = compute_hash(data2)
        self.assertNotEqual(hash1, hash2)


class TestCheckDependencies(unittest.TestCase):
    """Test dependency checking."""
    
    def test_empty_dependencies(self):
        """Test with empty dependencies list."""
        self.assertTrue(check_dependencies([]))
    
    def test_with_dependencies(self):
        """Test with dependencies list."""
        self.assertTrue(check_dependencies(['dep1', 'dep2']))


class TestRunDryRun(unittest.TestCase):
    """Test main dry run functionality."""
    
    def test_successful_dry_run(self):
        """Test successful dry run execution."""
        input_data = {
            'metadata': {
                'version': 'v1',
                'timestamp': '2024-01-01T00:00:00Z',
                'hash': 'abc123'
            },
            'payload': b'test payload',
            'dependencies': []
        }
        result = run_dry_run(input_data)
        self.assertEqual(result['status'], 'success')
        self.assertTrue(result['privacy_preserved'])
        self.assertTrue(result['interoperable'])
        self.assertTrue(result['safe'])
    
    def test_malformed_metadata(self):
        """Test dry run with malformed metadata."""
        input_data = {
            'metadata': 'invalid',
            'payload': b'test payload',
            'dependencies': []
        }
        result = run_dry_run(input_data)
        self.assertEqual(result['status'], 'error')
        self.assertEqual(result['error_type'], 'malformed_input')
        self.assertTrue(result['privacy_preserved'])
    
    def test_oversized_payload(self):
        """Test dry run with oversized payload."""
        from devx.testnet_dry_run import MAX_PAYLOAD_SIZE
        input_data = {
            'metadata': {
                'version': 'v1',
                'timestamp': '2024-01-01T00:00:00Z',
                'hash': 'abc123'
            },
            'payload': b'x' * (MAX_PAYLOAD_SIZE + 1),
            'dependencies': []
        }
        result = run_dry_run(input_data)
        self.assertEqual(result['status'], 'error')
        self.assertEqual(result['error_type'], 'oversized_input')
        self.assertTrue(result['privacy_preserved'])
    
    def test_unsupported_version(self):
        """Test dry run with unsupported version."""
        input_data = {
            'metadata': {
                'version': 'v3',
                'timestamp': '2024-01-01T00:00:00Z',
                'hash': 'abc123'
            },
            'payload': b'test payload',
            'dependencies': []
        }
        result = run_dry_run(input_data)
        self.assertEqual(result['status'], 'error')
        self.assertEqual(result['error_type'], 'unsupported_version')
        self.assertTrue(result['privacy_preserved'])
    
    def test_dependency_failure(self):
        """Test dry run with dependency failure."""
        with patch('devx.testnet_dry_run.check_dependencies', return_value=False):
            input_data = {
                'metadata': {
                    'version': 'v1',
                    'timestamp': '2024-01-01T00:00:00Z',
                    'hash': 'abc123'
                },
                'payload': b'test payload',
                'dependencies': ['dep1']
            }
            result = run_dry_run(input_data)
            self.assertEqual(result['status'], 'error')
            self.assertEqual(result['error_type'], 'dependency_failure')
            self.assertTrue(result['privacy_preserved'])
    
    def test_string_payload_conversion(self):
        """Test that string payloads are converted to bytes."""
        input_data = {
            'metadata': {
                'version': 'v1',
                'timestamp': '2024-01-01T00:00:00Z',
                'hash': 'abc123'
            },
            'payload': 'test string payload',
            'dependencies': []
        }
        result = run_dry_run(input_data)
        self.assertEqual(result['status'], 'success')


class TestPrivacySafety(unittest.TestCase):
    """Test that sensitive data is never logged."""
    
    def test_no_sensitive_data_in_error_responses(self):
        """Test that error responses don't contain sensitive data."""
        input_data = {
            'metadata': {
                'version': 'v1',
                'timestamp': '2024-01-01T00:00:00Z',
                'hash': 'abc123'
            },
            'payload': b'sensitive_data_here',
            'dependencies': []
        }
        result = run_dry_run(input_data)
        # Result should not contain the actual payload
        self.assertNotIn('sensitive_data_here', json.dumps(result))


if __name__ == '__main__':
    unittest.main()