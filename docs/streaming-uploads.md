# Streaming Upload Architecture

This document describes the streaming multipart upload system implemented for the Harpocrates backend, which enables handling large privacy-sensitive evidence files without buffering entire payloads in memory.

## Architecture Overview

### Core Components

1. **StreamingFileStorage** (`streaming_upload.py`)
   - Custom `FileStorage` implementation that streams directly to temporary files
   - Concurrent SHA-256 hash computation during streaming
   - Size limit enforcement at the byte level before writing to disk
   - Automatic cleanup on completion or failure

2. **Upload State Machine** (`upload_state.py`)
   - Explicit state tracking: `receiving → hashing → validating → persisting → confirming → complete/failed`
   - Privacy-safe logging with no evidence content exposure
   - Error categorization for metrics collection

3. **Concurrency Control** (`streaming_upload.py`)
   - Semaphore-based upload slot management
   - Configurable maximum concurrent uploads
   - HTTP 429 responses when limits are reached

4. **Metrics Collection** (`metrics.py`)
   - Upload volume, duration, error rates, and active upload tracking
   - Privacy-safe Prometheus metrics with no sensitive data in labels
   - Error type classification for operational monitoring

### State Machine Lifecycle

```
RECEIVING → HASHING → VALIDATING → PERSISTING → CONFIRMING → COMPLETE
    ↓          ↓           ↓            ↓           ↓
  FAILED ← FAILED ← FAILED ← FAILED ← FAILED
```

**State Descriptions:**
- **RECEIVING**: Bytes are being streamed and written to temporary file
- **HASHING**: All bytes received; SHA-256 hash finalization (if not computed concurrently)
- **VALIDATING**: Content-type, size, and format validation
- **PERSISTING**: Temporary file moved to durable storage or processing location
- **CONFIRMING**: Database/contract records created
- **COMPLETE**: Upload successful; all resources cleaned up
- **FAILED**: Any error occurred; cleanup triggered with error categorization

### Temporary File Lifecycle

1. **Creation**: `{UPLOAD_TEMP_DIR}/{uuid}.tmp` where UUID is generated per upload
2. **Writing**: Direct streaming write with concurrent hash computation
3. **Processing**: File moved/copied to processing location after validation
4. **Cleanup**: Automatic deletion on success, failure, or process exit

**Cleanup Triggers:**
- Normal completion: File deleted after successful processing
- Upload failure: Immediate deletion with error logging
- Client disconnect: Cleanup on connection termination detection
- Process exit: `atexit` handler removes orphaned temporary files
- Signal handling: `SIGTERM` and `SIGINT` trigger cleanup

## Configuration

All configuration parameters are validated and have secure defaults:

| Variable | Default | Description | Valid Range |
|----------|---------|-------------|-------------|
| `UPLOAD_MAX_BYTES` | 262,144,000 (250MB) | Maximum bytes per upload | 1 - 10GB |
| `UPLOAD_TEMP_DIR` | System temp directory | Temporary file location | Valid directory path |
| `UPLOAD_TIMEOUT_SECONDS` | 300 (5 minutes) | Upload completion deadline | 30 - 3600 |
| `UPLOAD_MAX_CONCURRENT` | 10 | Maximum concurrent uploads | 1 - 100 |

### Configuration Validation

- `UPLOAD_MAX_BYTES`: Must be positive integer, enforced before any data is written
- `UPLOAD_TEMP_DIR`: Directory created automatically if it doesn't exist, with appropriate permissions
- `UPLOAD_TIMEOUT_SECONDS`: Applied at the HTTP connection level via Werkzeug timeouts
- `UPLOAD_MAX_CONCURRENT`: Enforced via semaphore; excess requests receive HTTP 429

## Threat Model

### Adversarial Inputs Handled

1. **Oversized Payloads**
   - **Attack**: Client sends Content-Length exceeding `UPLOAD_MAX_BYTES`
   - **Defense**: Rejected with HTTP 413 before any parsing begins
   - **Guarantee**: No temporary file created, no memory consumption

2. **Slow Client Attacks**
   - **Attack**: Client sends initial bytes then stops, holding connection open
   - **Defense**: Connection terminated after `UPLOAD_TIMEOUT_SECONDS`
   - **Guarantee**: Resources released, temporary files cleaned up

3. **Concurrent Request Flooding**
   - **Attack**: Client opens many simultaneous upload connections
   - **Defense**: Semaphore limits to `UPLOAD_MAX_CONCURRENT`, excess get HTTP 429
   - **Guarantee**: Server resources bounded, legitimate traffic unaffected

4. **Malformed Multipart Data**
   - **Attack**: Invalid multipart boundaries or headers
   - **Defense**: Werkzeug parser validation with error categorization
   - **Guarantee**: Parsing fails early, temporary files cleaned up

5. **Duplicate Upload Spam**
   - **Attack**: Repeated uploads of identical content to waste resources
   - **Defense**: SHA-256-based idempotency detection
   - **Guarantee**: Duplicate content returns existing records without reprocessing

6. **Client Disconnect Mid-Stream**
   - **Attack**: Abrupt connection termination during upload
   - **Defense**: Connection error detection triggers immediate cleanup
   - **Guarantee**: Partial temporary files removed, upload slots released

## Privacy Boundaries

### Data Never Logged or Exposed

**Strictly Prohibited in Logs:**
- Evidence file content (any bytes from uploaded files)
- Witness identity information
- Proof metadata content
- File paths containing evidence identifiers
- Computed file hashes in error conditions

**Logging Safeguards:**
```python
# CORRECT: Privacy-safe logging
log_structured(logger, logging.INFO, {
    "event": "upload_completed",
    "upload_id": "uuid-only",
    "bytes_received": 12345,
    "duration_seconds": 15.2
})

# FORBIDDEN: Evidence content exposure
log_structured(logger, logging.ERROR, {
    "error": "validation failed",
    "file_content": evidence_bytes,  # ❌ NEVER
    "witness_id": witness_data,      # ❌ NEVER
    "file_path": "/evidence/witness123.mp4"  # ❌ NEVER
})
```

**Metrics Safeguards:**
- Only aggregate counters and histograms exposed
- Error labels limited to predefined types: `size_limit`, `timeout`, `parse_error`, `storage_error`, `contract_error`, `unknown`
- No user-provided strings in metric labels or values

## Operational Monitoring

### Key Metrics

**Volume Metrics:**
```prometheus
# Total bytes processed across all uploads
harpocrates_streaming_upload_bytes_received_total

# Current uploads in progress
harpocrates_streaming_upload_active
```

**Performance Metrics:**
```prometheus
# Upload completion time distribution
harpocrates_streaming_upload_duration_seconds_bucket{le="1"}
harpocrates_streaming_upload_duration_seconds_bucket{le="5"}
harpocrates_streaming_upload_duration_seconds_bucket{le="15"}
# ... additional buckets up to 300 seconds
```

**Error Metrics:**
```prometheus
# Error counts by type
harpocrates_streaming_upload_errors_total{error_type="size_limit"}
harpocrates_streaming_upload_errors_total{error_type="timeout"}
harpocrates_streaming_upload_errors_total{error_type="parse_error"}
```

### Alerting Queries

**Saturation Detection:**
```prometheus
# High concurrent upload usage
harpocrates_streaming_upload_active / UPLOAD_MAX_CONCURRENT > 0.8

# Upload queue building up (high rejection rate)
rate(harpocrates_streaming_upload_errors_total{error_type="concurrent_limit"}[5m]) > 0.1
```

**Performance Degradation:**
```prometheus
# Slow uploads (95th percentile > 60 seconds)
histogram_quantile(0.95, rate(harpocrates_streaming_upload_duration_seconds_bucket[5m])) > 60

# High error rate
rate(harpocrates_streaming_upload_errors_total[5m]) / rate(harpocrates_streaming_upload_duration_seconds_count[5m]) > 0.05
```

**Storage Issues:**
```prometheus
# Disk space problems
rate(harpocrates_streaming_upload_errors_total{error_type="storage_error"}[5m]) > 0
```

## Local Verification

### Testing Positive Path

```bash
# 1. Start development server
cd backend
python -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python run.py

# 2. Test small upload (should succeed)
curl -X POST http://localhost:5050/api/stego/embed \
  -F "video=@test-video-small.mp4" \
  -F 'metadata={"proofId":"test-123","tier":1}' \
  -o embedded-output.mp4

# 3. Verify metrics
curl http://localhost:5050/metrics | grep streaming_upload
```

### Testing Adversarial Paths

```bash
# Test size limit enforcement
dd if=/dev/zero of=oversized.mp4 bs=1M count=300  # 300MB file
curl -X POST http://localhost:5050/api/stego/embed \
  -F "video=@oversized.mp4" \
  -F 'metadata={"proofId":"oversized"}' \
# Expected: HTTP 413 response

# Test concurrent limit
for i in {1..15}; do
  curl -X POST http://localhost:5050/api/stego/embed \
    -F "video=@test-video.mp4" \
    -F "metadata={\"proofId\":\"concurrent-$i\"}" &
done
wait
# Expected: Some requests get HTTP 429

# Test timeout (requires slow network simulation)
# Use traffic shaping tools like tc or a proxy to simulate slow uploads

# Test malformed multipart
curl -X POST http://localhost:5050/api/stego/embed \
  -H "Content-Type: multipart/form-data; boundary=invalid" \
  --data-raw "invalid multipart data"
# Expected: HTTP 400 with parse error
```

### Monitoring During Tests

```bash
# Watch active uploads
watch 'curl -s http://localhost:5050/metrics | grep upload_active'

# Monitor error rates
watch 'curl -s http://localhost:5050/metrics | grep upload_errors'

# Check temp file cleanup
watch 'ls -la $UPLOAD_TEMP_DIR/*.tmp 2>/dev/null || echo "No temp files"'
```

## Deployment Rollback Strategy

### Graceful Rollback Process

1. **Stop New Uploads**: Set `UPLOAD_MAX_CONCURRENT=0` to reject new uploads with HTTP 429
2. **Wait for Completion**: Monitor `harpocrates_streaming_upload_active` until it reaches 0
3. **Deploy Previous Version**: Standard deployment rollback process
4. **Cleanup**: Any remaining temp files are cleaned by the new process on startup

### Mid-Operation Rollback Behavior

**In-Flight Uploads During Rollback:**
- **Receiving State**: Upload fails gracefully, client gets connection error, temp file cleaned
- **Processing States**: Upload may complete or fail depending on timing; database consistency maintained
- **Complete State**: No impact, upload already finished

**Temp File Handling:**
- Orphaned temp files cleaned by `atexit` handlers during process shutdown
- New process startup cleans any remaining files from previous deployment
- No manual cleanup required under normal circumstances

**Database Consistency:**
- Upload records only created after successful streaming and validation
- No partial or corrupted records from interrupted uploads
- Failed uploads leave no persistent state

## Limitations and Edge Cases

### Current Limitations

1. **Maximum Tested File Size**: 500MB
   - Theoretical limit: 10GB (based on `UPLOAD_MAX_BYTES` validation)
   - Production recommendation: Monitor disk space and adjust accordingly

2. **Concurrency Ceiling**: 100 concurrent uploads
   - Practical limit depends on available file descriptors and disk I/O capacity
   - Recommended: Start with 10, increase based on system performance

3. **Timeout Resolution**: 1-second granularity
   - Minimum practical timeout: 30 seconds (for network latency)
   - Maximum timeout: 1 hour (prevents indefinite resource holding)

### Known Edge Cases

1. **Disk Full During Upload**
   - **Behavior**: Upload fails with `storage_error`, temp file removed if possible
   - **Monitoring**: Watch `storage_error` metrics and disk space alerts

2. **Process Kill During Upload**
   - **Behavior**: Temp files may remain until next process startup
   - **Mitigation**: Startup cleanup routine removes orphaned files

3. **Clock Skew in Timeout Calculation**
   - **Behavior**: Timeouts may be slightly inaccurate on systems with clock drift
   - **Impact**: Minimal; timeouts are approximate safeguards, not precise contracts

4. **Very Small Files**
   - **Behavior**: Still go through full streaming process (slight overhead)
   - **Optimization**: Could add fast path for files < 1KB, but complexity not justified

### Monitoring Recommendations

1. **Set up alerts for error rates > 5%**
2. **Monitor 95th percentile upload duration**
3. **Track concurrent upload utilization**
4. **Watch for storage errors indicating disk issues**
5. **Alert on orphaned temp files accumulating**

## Future Enhancements

### Potential Optimizations

1. **Chunked Hash Verification**: For very large files, implement chunked hash computation with progress reporting
2. **Resumable Uploads**: Add support for resuming interrupted uploads using range requests
3. **Direct Object Storage**: Stream directly to S3/GCS instead of local temp files
4. **Compression**: Add transparent compression for certain file types
5. **Parallel Processing**: Allow multiple concurrent hash algorithms (SHA-256 + SHA-512)

### Compatibility Considerations

All enhancements must maintain:
- Current API contract compatibility
- Privacy boundary enforcement
- Metrics schema stability
- Configuration parameter backward compatibility