import { runDryRun, validateMetadata, validatePayloadSize, computeHash, checkDependencies } from '../src/dry-run';

const MAX_PAYLOAD_SIZE = 1024 * 1024;

// Mock crypto for testing
jest.mock('crypto', () => ({
  createHash: jest.fn(() => ({
    update: jest.fn().mockReturnThis(),
    digest: jest.fn().mockReturnValue('mock_hash_123')
  }))
}));

describe('Dry Run Validation', () => {
  describe('validateMetadata', () => {
    it('should accept valid metadata', () => {
      const metadata = {
        version: 'v1',
        timestamp: '2024-01-01T00:00:00Z',
        hash: 'abc123'
      };
      expect(() => validateMetadata(metadata)).not.toThrow();
    });

    it('should reject non-object metadata', () => {
      expect(() => validateMetadata('not an object')).toThrow('Metadata must be an object');
    });

    it('should reject missing version', () => {
      const metadata = {
        timestamp: '2024-01-01T00:00:00Z',
        hash: 'abc123'
      };
      expect(() => validateMetadata(metadata)).toThrow('Missing required metadata key: version');
    });

    it('should reject missing timestamp', () => {
      const metadata = {
        version: 'v1',
        hash: 'abc123'
      };
      expect(() => validateMetadata(metadata)).toThrow('Missing required metadata key: timestamp');
    });

    it('should reject missing hash', () => {
      const metadata = {
        version: 'v1',
        timestamp: '2024-01-01T00:00:00Z'
      };
      expect(() => validateMetadata(metadata)).toThrow('Missing required metadata key: hash');
    });

    it('should reject unsupported version', () => {
      const metadata = {
        version: 'v3',
        timestamp: '2024-01-01T00:00:00Z',
        hash: 'abc123'
      };
      expect(() => validateMetadata(metadata)).toThrow('Unsupported version: v3');
    });
  });

  describe('validatePayloadSize', () => {
    it('should accept valid payload size', () => {
      const payload = 'x'.repeat(1024);
      expect(() => validatePayloadSize(payload)).not.toThrow();
    });

    it('should accept maximum size payload', () => {
      const payload = 'x'.repeat(MAX_PAYLOAD_SIZE);
      expect(() => validatePayloadSize(payload)).not.toThrow();
    });

    it('should reject oversized payload', () => {
      const payload = 'x'.repeat(MAX_PAYLOAD_SIZE + 1);
      expect(() => validatePayloadSize(payload)).toThrow('exceeds maximum');
    });
  });

  describe('computeHash', () => {
    it('should return consistent hash for same input', () => {
      const data = 'test data';
      const hash1 = computeHash(data);
      const hash2 = computeHash(data);
      expect(hash1).toBe(hash2);
    });

    it('should return different hashes for different inputs', () => {
      const hash1 = computeHash('data1');
      const hash2 = computeHash('data2');
      expect(hash1).not.toBe(hash2);
    });
  });

  describe('checkDependencies', () => {
    it('should return true for empty dependencies', () => {
      expect(checkDependencies([])).toBe(true);
    });

    it('should return true for valid dependencies', () => {
      expect(checkDependencies(['dep1', 'dep2'])).toBe(true);
    });
  });

  describe('runDryRun', () => {
    it('should return success for valid input', () => {
      const input = {
        metadata: {
          version: 'v1',
          timestamp: '2024-01-01T00:00:00Z',
          hash: 'abc123'
        },
        payload: 'test payload',
        dependencies: []
      };
      
      const result = runDryRun(input);
      expect(result.status).toBe('success');
      expect(result.privacy_preserved).toBe(true);
      expect(result.interoperable).toBe(true);
      expect(result.safe).toBe(true);
      expect(result.payload_hash).toBe('mock_hash_123');
    });

    it('should return error for malformed metadata', () => {
      const input = {
        metadata: 'invalid',
        payload: 'test payload',
        dependencies: []
      };
      
      const result = runDryRun(input);
      expect(result.status).toBe('error');
      expect(result.error_type).toBe('malformed_input');
      expect(result.privacy_preserved).toBe(true);
    });

    it('should return error for oversized payload', () => {
      const input = {
        metadata: {
          version: 'v1',
          timestamp: '2024-01-01T00:00:00Z',
          hash: 'abc123'
        },
        payload: 'x'.repeat(MAX_PAYLOAD_SIZE + 1),
        dependencies: []
      };
      
      const result = runDryRun(input);
      expect(result.status).toBe('error');
      expect(result.error_type).toBe('oversized_input');
      expect(result.privacy_preserved).toBe(true);
    });

    it('should return error for unsupported version', () => {
      const input = {
        metadata: {
          version: 'v3',
          timestamp: '2024-01-01T00:00:00Z',
          hash: 'abc123'
        },
        payload: 'test payload',
        dependencies: []
      };
      
      const result = runDryRun(input);
      expect(result.status).toBe('error');
      expect(result.error_type).toBe('unsupported_version');
      expect(result.privacy_preserved).toBe(true);
    });

    it('should not leak sensitive data in error responses', () => {
      const input = {
        metadata: {
          version: 'v1',
          timestamp: '2024-01-01T00:00:00Z',
          hash: 'abc123'
        },
        payload: 'sensitive_data_here',
        dependencies: []
      };
      
      const result = runDryRun(input);
      const resultString = JSON.stringify(result);
      expect(resultString).not.toContain('sensitive_data_here');
    });
  });
});