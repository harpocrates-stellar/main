import type { VerificationResult } from './receipt.js'

/**
 * Stable, documented CLI exit codes shared across single-item and batch
 * verification commands.
 *
 * Distinct codes separate:
 * - `INVALID` (`8`): cryptographic, schema, or statement verification failed.
 * - `INCOMPLETE` (`6`): required verification checks were skipped (e.g. `--offline`)
 *   or remain pending on-chain; never reported as `0`.
 * - `UNAVAILABLE` (`9`): a required verification dependency (such as Stellar RPC)
 *   timed out or could not be reached.
 */
export const CLI_EXIT_CODES = {
  VALID: 0,
  EXPIRED: 1,
  REVOKED: 2,
  NOT_FOUND: 3,
  NETWORK_MISMATCH: 4,
  CONTRACT_MISMATCH: 5,
  INCOMPLETE: 6,
  FAILED: 7,
  INVALID: 8,
  UNAVAILABLE: 9,
} as const

export type CliExitCode = (typeof CLI_EXIT_CODES)[keyof typeof CLI_EXIT_CODES]

export type VerificationCheckStatus = 'passed' | 'failed' | 'skipped' | 'unavailable'

export type RequiredVerificationCheck = {
  name: string
  required: boolean
  status: VerificationCheckStatus
}

export type VerificationCheckSummaryOutcome =
  | 'valid'
  | 'invalid'
  | 'incomplete'
  | 'unavailable'

/**
 * Evaluate a set of verification checks fail-closed.
 *
 * Skipped required checks NEVER resolve to `'valid'`; they resolve to
 * `'incomplete'` (exit code `6`) unless superseded by a `'failed'` (`8`) or
 * `'unavailable'` (`9`) required check.
 */
export function evaluateVerificationChecks(
  checks: readonly RequiredVerificationCheck[],
): { outcome: VerificationCheckSummaryOutcome; exitCode: CliExitCode } {
  const requiredChecks = checks.filter((c) => c.required)
  if (requiredChecks.length === 0) {
    return { outcome: 'incomplete', exitCode: CLI_EXIT_CODES.INCOMPLETE }
  }
  if (requiredChecks.some((c) => c.status === 'failed')) {
    return { outcome: 'invalid', exitCode: CLI_EXIT_CODES.INVALID }
  }
  if (requiredChecks.some((c) => c.status === 'unavailable')) {
    return { outcome: 'unavailable', exitCode: CLI_EXIT_CODES.UNAVAILABLE }
  }
  if (requiredChecks.some((c) => c.status === 'skipped')) {
    return { outcome: 'incomplete', exitCode: CLI_EXIT_CODES.INCOMPLETE }
  }
  return { outcome: 'valid', exitCode: CLI_EXIT_CODES.VALID }
}

const RESULT_TO_EXIT_CODE: Record<
  VerificationResult | 'incomplete' | 'invalid' | 'unavailable',
  CliExitCode
> = {
  valid: CLI_EXIT_CODES.VALID,
  expired: CLI_EXIT_CODES.EXPIRED,
  revoked: CLI_EXIT_CODES.REVOKED,
  not_found: CLI_EXIT_CODES.NOT_FOUND,
  network_mismatch: CLI_EXIT_CODES.NETWORK_MISMATCH,
  contract_mismatch: CLI_EXIT_CODES.CONTRACT_MISMATCH,
  pending: CLI_EXIT_CODES.INCOMPLETE,
  incomplete: CLI_EXIT_CODES.INCOMPLETE,
  failed: CLI_EXIT_CODES.FAILED,
  error: CLI_EXIT_CODES.INVALID,
  invalid: CLI_EXIT_CODES.INVALID,
  unavailable: CLI_EXIT_CODES.UNAVAILABLE,
}

/**
 * Map a discrete verification result label to its stable CLI exit code.
 */
export function exitCodeForVerificationResult(
  result: VerificationResult | 'incomplete' | 'invalid' | 'unavailable',
): CliExitCode {
  return RESULT_TO_EXIT_CODE[result] ?? CLI_EXIT_CODES.INVALID
}

const BATCH_PRECEDENCE: readonly CliExitCode[] = [
  CLI_EXIT_CODES.INVALID,
  CLI_EXIT_CODES.REVOKED,
  CLI_EXIT_CODES.FAILED,
  CLI_EXIT_CODES.CONTRACT_MISMATCH,
  CLI_EXIT_CODES.NETWORK_MISMATCH,
  CLI_EXIT_CODES.EXPIRED,
  CLI_EXIT_CODES.NOT_FOUND,
  CLI_EXIT_CODES.UNAVAILABLE,
  CLI_EXIT_CODES.INCOMPLETE,
  CLI_EXIT_CODES.VALID,
]

/**
 * Aggregate per-item verification exit codes for a batch run.
 *
 * - An empty batch resolves to `INCOMPLETE` (`6`), never `0`.
 * - A batch exits `0` if and only if every item exited `0`.
 * - Mixed non-zero outcomes resolve deterministically:
 *   `INVALID (8)` > `REVOKED (2)` > `FAILED (7)` > `CONTRACT_MISMATCH (5)` >
 *   `NETWORK_MISMATCH (4)` > `EXPIRED (1)` > `NOT_FOUND (3)` >
 *   `UNAVAILABLE (9)` > `INCOMPLETE (6)`.
 */
export function aggregateBatchExitCode(itemExitCodes: readonly number[]): CliExitCode {
  if (itemExitCodes.length === 0) {
    return CLI_EXIT_CODES.INCOMPLETE
  }
  const observed = new Set<number>(itemExitCodes)
  for (const code of itemExitCodes) {
    if (!BATCH_PRECEDENCE.includes(code as CliExitCode)) {
      return CLI_EXIT_CODES.INVALID
    }
  }
  for (const candidate of BATCH_PRECEDENCE) {
    if (observed.has(candidate)) {
      return candidate
    }
  }
  return CLI_EXIT_CODES.INVALID
}
