# Streaming Upload Hashing (Bounded Chunks)

Stream upload hashing keeps Harpocrates privacy-preserving at the public upload
boundary: bytes are copied to temporary disk in **bounded chunks** while a
SHA-256 digest is updated concurrently. Callers never need a second full-file
read to obtain the content hash, and oversized uploads abort before a partial
destination artifact is retained.

## Behavior

| Concern | Behavior |
|---------|----------|
| Chunk size | Configurable via `UPLOAD_CHUNK_BYTES` (clamped to 4 KiB–1 MiB; default 64 KiB) |
| Hashing | SHA-256 updated per chunk during copy (`hash_stream_to_path` / `StreamingFileStorage.save`) |
| Size limit | Enforced mid-stream in bytes; raises `RequestEntityTooLarge` without logging payload bytes. Distinguishes an absent limit (unlimited) from a zero-byte allowance (`0`, rejecting non-empty uploads) |
| Session commit | Chunk files are concatenated with the same bounded reader (`hash_paths_concat`) |
| Streaming trigger | Multipart bodies larger than `UPLOAD_STREAM_THRESHOLD_BYTES` (default 1 MiB) wrap `FileStorage` |
| Session expiry | Sessions exceeding `UPLOAD_SESSION_TTL_SECONDS` expire and return 410 `GONE` on further chunk/commit actions |
| Worker protection | Sessions actively referenced by in-flight worker requests are never purged during retention runs |

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `UPLOAD_CHUNK_BYTES` | `65536` | Bounded read/write size for stream hashing |
| `UPLOAD_STREAM_THRESHOLD_BYTES` | `1048576` | Content-Length above which embed/extract wrap uploads |
| `UPLOAD_MAX_BYTES` | `MAX_VIDEO_BYTES` | Hard mid-stream size ceiling in bytes; `0` enforces a zero-byte allowance (rejects non-empty uploads fail-closed), while absent (`None`) falls back or allows unlimited |
| `UPLOAD_TEMP_DIR` | OS temp | Optional temp directory for stream scratch files |
| `UPLOAD_SESSION_TTL_SECONDS` | `3600` | Time-to-live for upload sessions in seconds (default 1 hour) |

## Upload Session Expiry and Operator Retention

Upload sessions create an isolated staging directory under `UPLOAD_TEMP_DIR` (or the system temporary directory) prefixed with `harpocrates-session-`. Each session directory tracks metadata (`.session_meta`) recording timestamps for creation, last touch, and active configuration.

### Session Lifecycle & Expiry
1. **Creation**: `POST /api/upload-session` generates a UUID session ID and initializes the session directory with `.session_meta`.
2. **Chunk Ingestion**: `POST /api/upload-chunk/<session_id>` touches `.session_meta` upon receiving valid chunks. If the session has already expired, HTTP 410 `GONE` (`UPLOAD_SESSION_EXPIRED`) is returned.
3. **Commit**: `POST /api/upload-session/<session_id>/commit` reassembles chunks. Expired sessions are rejected with HTTP 410 `GONE`.

### Active Worker Protection
The `AdmissionController` tracks active worker references for in-flight requests on upload sessions. When chunks are being received or sessions are being committed:
- An active reference is acquired before chunk storage/assembly and released upon completion.
- Retention preview and purge operations check `admission_controller.is_session_active(session_id)` and **strictly skip** any active session. Chunks and directories currently being read or written by active workers are never deleted.

### Operator Retention Preview & Purge
Operators can preview and clean up expired upload session storage using `manage.py retention`:
- **Bounded Scanning**: Scans are capped to `--session-limit` (default: 500) sessions to prevent unbound filesystem operations or memory spikes.
- **Dry Run**: `python manage.py retention --dry-run` reports `total_sessions_scanned`, `expired_sessions_count`, `active_worker_sessions_skipped`, `reclaimable_bytes`, and detailed per-session preview records without modifying disk state.
- **Purge Run**: `python manage.py retention --run` safely removes expired, non-active session directories and reclaims disk space.

## Trust boundary, privacy, migration, rollback

- **Trust boundary:** Only the public multipart / upload-session HTTP surface is
  affected. Canonical metadata, proof, contract, and deployment boundaries are
  unchanged — stream hashes are ordinary SHA-256 hex digests compatible with
  existing `sha256_file` / workspace digests.
- **Privacy:** Failure responses stay stable (`Upload exceeds size limit`). Real
  media bytes, secrets, witness values, and private keys are never logged by
  this module.
- **Migration:** Additive. Compatible callers that already post multipart video
  continue to work. Units are consistently measured in bytes across declared headers,
  streaming limit enforcement, and rejection bodies.
- **Rollback:** Revert this change set; no schema or protocol version bump is
  required. Temporary stream files live under the process temp directory and are
  removed on success or size-abort.

## Testing

`backend/test_streaming_focused.py` covers positive hashing, oversized abort,
exact-limit boundary, zero-byte allowance, absent limit, memory-bounded reads, concat
hashing, and empty-stream regression.
