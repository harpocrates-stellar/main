# Resumable Encrypted Upload Sessions

Harpocrates supports resumable, at-rest encrypted upload sessions with explicit ownership and pre-admission final content hash verification.

## Overview

1. **Authenticated ownership**: When a session is created with an `owner` (e.g., a Stellar `G-...` address or authenticated principal identifier), the server issues a one-time `sessionToken` and persists only its SHA-256 digest in the session manifest. Subsequent status, chunk, and commit requests must present the matching bearer token (and, if supplied, matching `X-Upload-Owner`).
2. **At-rest chunk encryption**: Each session generates a fresh 256-bit Data Encryption Key (DEK) wrapped with AES-256-GCM using `UPLOAD_SESSION_MASTER_KEY` (falling back to `MASTER_ENCRYPTION_KEY` or an ephemeral process key). Every bounded chunk is encrypted with AES-256-GCM using a unique 96-bit nonce and Associated Authenticated Data (AAD) binding `(session_id, owner, chunk_index)`.
3. **Persisted bounded progress**: Each chunk write atomically persists the encrypted chunk (`chunk-<index>.enc`) and updates `manifest.json` (`receivedChunks`, `nextChunkIndex`, `totalBytes`, per-chunk SHA-256). Clients can query `GET /api/stego/upload-session/<session_id>` to resume interrupted uploads and safely re-upload chunks.
4. **Final hash verification before admission**: On `POST /api/stego/upload-session/<session_id>/commit`, the server authenticates the session, decrypts and assembles contiguous chunks `0..N-1`, and verifies the final SHA-256 content hash against `expectedSha256` **before** acquiring an admission slot from `AdmissionController` for steganography processing.

## HTTP Interface

### Create Session

`POST /api/stego/upload-session`

Optional JSON body (or equivalent headers `X-Upload-Owner`, `X-Upload-Owner-Tier`, `X-Expected-Sha256`):

```json
{
  "owner": "GABC...",
  "ownerTier": "scoped",
  "expectedSha256": "<64-char lowercase hex>",
  "expectedSize": 1048576
}
```

Response (`200 OK`):

```json
{
  "sessionId": "550e8400-e29b-41d4-a716-446655440000",
  "owner": "GABC...",
  "ownerTier": "scoped",
  "sessionToken": "<opaque bearer token, returned once>",
  "expectedSha256": "<64-char lowercase hex>",
  "expectedSize": 1048576,
  "encrypted": true
}
```

> **Backward compatibility**: Calling `POST /api/stego/upload-session` with no body or `owner` continues to succeed and returns `{"sessionId": "...", "encrypted": true}` without requiring a session token.

### Query Progress (Resume)

`GET /api/stego/upload-session/<session_id>`

Headers (for owned sessions):
- `Authorization: Bearer <sessionToken>` (or `X-Upload-Session-Token: <sessionToken>`)
- `X-Upload-Owner: <owner>` (optional; if present, must match the session owner)

Response (`200 OK`):

```json
{
  "sessionId": "550e8400-e29b-41d4-a716-446655440000",
  "owner": "GABC...",
  "ownerTier": "scoped",
  "state": "open",
  "encrypted": true,
  "receivedChunks": [0, 1],
  "nextChunkIndex": 2,
  "totalBytes": 131072,
  "expectedSha256": "<64-char lowercase hex>",
  "expectedSize": 1048576
}
```

### Upload Chunk

`PUT /api/stego/upload-session/<session_id>/chunk/<chunk_index>`

- Multipart field `chunk`: bounded chunk bytes
- Optional header `X-Chunk-Sha256`: expected SHA-256 hex digest of the chunk plaintext (verified before persisting)
- Auth headers as above for owned sessions

### Commit Session

`POST /api/stego/upload-session/<session_id>/commit`

- Multipart/form field `metadata`: JSON embed metadata
- Optional form field `expectedSha256` or header `X-Expected-Sha256`
- Auth headers as above for owned sessions

Failure modes (all fail closed before consuming admission capacity):
- `401 SESSION_UNAUTHORIZED`: missing or invalid `sessionToken`
- `403 SESSION_OWNER_MISMATCH`: `X-Upload-Owner` does not match session owner
- `400 SESSION_INCOMPLETE`: missing chunks (gaps in `0..N-1`)
- `413 PAYLOAD_TOO_LARGE`: total bytes exceed `UPLOAD_MAX_BYTES` / `MAX_VIDEO_BYTES`
- `422 CONTENT_HASH_MISMATCH`: final assembled SHA-256 (or size / AEAD tag) does not match

## Configuration

| Environment Variable | Description |
| :--- | :--- |
| `UPLOAD_SESSION_MASTER_KEY` | Secret used to derive the 256-bit AES-GCM key wrapping per-session DEKs. Falls back to `MASTER_ENCRYPTION_KEY`, or an ephemeral per-process key. |
| `UPLOAD_CHUNK_BYTES` | Bounded read chunk size (clamped to 4 KiB..1 MiB, default 64 KiB). |
| `UPLOAD_MAX_BYTES` | Maximum total upload size in bytes (falls back to `MAX_VIDEO_BYTES`). |
| `UPLOAD_TEMP_DIR` | Directory where encrypted upload session state is persisted. |
