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
| Size limit | Enforced mid-stream; raises `RequestEntityTooLarge` without logging payload bytes |
| Session commit | Chunk files are concatenated with the same bounded reader (`hash_paths_concat`) |
| Streaming trigger | Multipart bodies larger than `UPLOAD_STREAM_THRESHOLD_BYTES` (default 1 MiB) wrap `FileStorage` |

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `UPLOAD_CHUNK_BYTES` | `65536` | Bounded read/write size for stream hashing |
| `UPLOAD_STREAM_THRESHOLD_BYTES` | `1048576` | Content-Length above which embed/extract wrap uploads |
| `UPLOAD_MAX_BYTES` | `MAX_VIDEO_BYTES` | Hard mid-stream size ceiling |
| `UPLOAD_TEMP_DIR` | OS temp | Optional temp directory for stream scratch files |

## Trust boundary, privacy, migration, rollback

- **Trust boundary:** Only the public multipart / upload-session HTTP surface is
  affected. Canonical metadata, proof, contract, and deployment boundaries are
  unchanged — stream hashes are ordinary SHA-256 hex digests compatible with
  existing `sha256_file` / workspace digests.
- **Privacy:** Failure responses stay stable (`Upload exceeds size limit`). Real
  media bytes, secrets, witness values, and private keys are never logged by
  this module.
- **Migration:** Additive. Compatible callers that already post multipart video
  continue to work. Digests match whole-file SHA-256, so stored evidence remains
  interoperable.
- **Rollback:** Revert this change set; no schema or protocol version bump is
  required. Temporary stream files live under the process temp directory and are
  removed on success or size-abort.

## Testing

`backend/test_streaming_focused.py` covers positive hashing, oversized abort,
exact-limit boundary, memory-bounded reads, concat hashing, and empty-stream
regression.
