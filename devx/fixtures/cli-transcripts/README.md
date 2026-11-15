# Reproducible CLI Transcript Fixtures

`transcripts.json` provides a self-contained, deterministic test corpus of CLI
invocations (`argv`, optional `stdin`, optional temporary synthetic `files`),
rendered outputs (`stdout`, `stderr`), and exit codes (`expected.exitCode`) for
verifying independent implementations of the Harpocrates CLI.

## Design Boundaries

- **Offline & endpoint-free:** Every transcript executes locally using stdin,
  synthetic temporary files (`{{dir}}/<filename>`), offline verification flags,
  or `--fixture` lineage snapshots. No Stellar RPC endpoint, Horizon server, or
  signing key is contacted.
- **Privacy-preserving:** Fixtures contain exclusively synthetic hex digests,
  public test JWKs, and placeholder contract addresses. Real media files,
  witness payloads, private keys, and credential secrets are prohibited and
  rejected by `parseTranscriptSuite`.
- **Canonical & deterministic:** Commands with wall-clock verification
  timestamps (`verify --offline`) set `"normalizeDynamicTimestamps": true`,
  normalizing ISO-8601 `verifiedAt` values to `<ISO-8601>` before comparison.

## Schema (`harpocrates-cli-transcripts` v1)

| Field | Type | Description |
| :--- | :--- | :--- |
| `protocol` | `"harpocrates-cli-transcripts"` | Suite protocol identifier. |
| `schemaVersion` | `1` | Schema version number. |
| `cases[].id` | `string` | Stable lowercase identifier for the case. |
| `cases[].argv` | `string[]` | CLI arguments passed after the executable; `{{dir}}` expands to an isolated temp directory. |
| `cases[].stdin` | `string` (optional) | UTF-8 payload piped to standard input. |
| `cases[].files` | `{ name, content }[]` (optional) | Synthetic text files materialized inside `{{dir}}` prior to execution. |
| `cases[].normalizeDynamicTimestamps` | `boolean` (optional) | Replaces ISO-8601 `verifiedAt` timestamps with `<ISO-8601>`. |
| `cases[].expected` | `{ exitCode, stdout, stderr }` | Exact exit code and normalized standard streams expected from any conformant implementation. |

## Running Against the Reference CLI

From [`../../../cli/README.md`](../../../cli/README.md):

```sh
cd cli
npm ci
npm run build
npx vitest run test/transcripts.test.ts
```
