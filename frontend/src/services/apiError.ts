/**
 * apiError — map backend error envelopes to actionable, privacy-safe UI copy.
 *
 * Backend envelope (see backend/errors.py)::
 *
 *   {
 *     "ok": false,
 *     "error": {
 *       "code": "VALIDATION_ERROR" | "PAYLOAD_TOO_LARGE" | ...,
 *       "message": "human-readable string",
 *       "request_id": "..."
 *     }
 *   }
 *
 * Legacy string envelopes (`{ "error": "..." }`) are still accepted.
 * HTML is stripped and messages are truncated so secrets/media never leak.
 */

const MAX_ERROR_LENGTH = 500

/** Machine-readable codes emitted by the Harpocrates Flask API. */
export type BackendErrorCode =
  | 'VALIDATION_ERROR'
  | 'PAYLOAD_TOO_LARGE'
  | 'NOT_FOUND'
  | 'INTERNAL_ERROR'
  | 'UNSUPPORTED_MEDIA_TYPE'
  | 'REPORTER_ON_COOLDOWN'
  | 'TOO_MANY_OPEN_DISPUTES'
  | 'DISPUTE_WINDOW_EXPIRED'
  | 'UNAUTHORIZED_RESPONDER'
  | 'DISPUTE_NOT_FOUND'
  | 'DISPUTE_ALREADY_CLOSED'
  | 'INVALID_DISPUTE_TRANSITION'
  | 'UNKNOWN'

/** What the UI should nudge the user to do next. */
export type ActionHint =
  | 'fix_input'
  | 'reduce_file_size'
  | 'use_supported_format'
  | 'retry'
  | 'check_resource'
  | 'none'

export type ActionableApiError = {
  code: BackendErrorCode
  /** User-facing actionable message (safe to render as plain text). */
  message: string
  /** Sanitized backend detail when useful; never includes raw media/secrets. */
  detail: string | null
  requestId: string | null
  action: ActionHint
  retryable: boolean
  status: number
}

const KNOWN_CODES: ReadonlySet<string> = new Set([
  'VALIDATION_ERROR',
  'PAYLOAD_TOO_LARGE',
  'NOT_FOUND',
  'INTERNAL_ERROR',
  'UNSUPPORTED_MEDIA_TYPE',
  'REPORTER_ON_COOLDOWN',
  'TOO_MANY_OPEN_DISPUTES',
  'DISPUTE_WINDOW_EXPIRED',
  'UNAUTHORIZED_RESPONDER',
  'DISPUTE_NOT_FOUND',
  'DISPUTE_ALREADY_CLOSED',
  'INVALID_DISPUTE_TRANSITION',
])

type CodeGuidance = {
  action: ActionHint
  retryable: boolean
  /** Default actionable copy when the backend message is empty/generic. */
  fallbackMessage: string
}

const CODE_GUIDANCE: Record<Exclude<BackendErrorCode, 'UNKNOWN'>, CodeGuidance> = {
  VALIDATION_ERROR: {
    action: 'fix_input',
    retryable: false,
    fallbackMessage: 'The request was invalid. Check your input and try again.',
  },
  PAYLOAD_TOO_LARGE: {
    action: 'reduce_file_size',
    retryable: false,
    fallbackMessage: 'File is too large for the server. Choose a smaller video and try again.',
  },
  NOT_FOUND: {
    action: 'check_resource',
    retryable: false,
    fallbackMessage: 'The requested resource was not found. Confirm the link or try a different artifact.',
  },
  INTERNAL_ERROR: {
    action: 'retry',
    retryable: true,
    fallbackMessage: 'A temporary server error occurred. Retry in a moment.',
  },
  UNSUPPORTED_MEDIA_TYPE: {
    action: 'use_supported_format',
    retryable: false,
    fallbackMessage: 'Unsupported file type. Use an MP4, WebM, or MOV video.',
  },
  REPORTER_ON_COOLDOWN: {
    action: 'retry',
    retryable: true,
    fallbackMessage: 'You are on cooldown. Please wait 24 hours between dispute submissions for this proof before trying again.',
  },
  TOO_MANY_OPEN_DISPUTES: {
    action: 'check_resource',
    retryable: false,
    fallbackMessage: 'Maximum open disputes reached for this proof (limit: 4). Existing disputes must be resolved before a new one can be opened.',
  },
  DISPUTE_WINDOW_EXPIRED: {
    action: 'none',
    retryable: false,
    fallbackMessage: 'The dispute window has expired. The deadline for responding or resolving this dispute has passed.',
  },
  UNAUTHORIZED_RESPONDER: {
    action: 'fix_input',
    retryable: false,
    fallbackMessage: 'Unauthorized responder. Only the proof issuer or source may submit a dispute response.',
  },
  DISPUTE_NOT_FOUND: {
    action: 'check_resource',
    retryable: false,
    fallbackMessage: 'Dispute or proof record not found. Verify the identifiers and try again.',
  },
  DISPUTE_ALREADY_CLOSED: {
    action: 'none',
    retryable: false,
    fallbackMessage: 'This dispute is already closed and cannot be transitioned.',
  },
  INVALID_DISPUTE_TRANSITION: {
    action: 'fix_input',
    retryable: false,
    fallbackMessage: 'Invalid dispute transition. The dispute is not in a state that permits this action.',
  },
}

function stripHtml(input: string): string {
  return input
    .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '')
    .replace(/<style\b[^<]*(?:(?!<\/style>)<[^<]*)*<\/style>/gi, '')
    .replace(/<[^>]*>/g, '')
}

function truncate(input: string): string {
  if (input.length <= MAX_ERROR_LENGTH) return input
  return input.slice(0, MAX_ERROR_LENGTH) + '…'
}

function sanitizeText(input: string): string {
  return truncate(stripHtml(input.trim()))
}

function isKnownCode(value: string): value is Exclude<BackendErrorCode, 'UNKNOWN'> {
  return KNOWN_CODES.has(value)
}

function codeFromStatus(status: number): BackendErrorCode {
  if (status === 413) return 'PAYLOAD_TOO_LARGE'
  if (status === 415) return 'UNSUPPORTED_MEDIA_TYPE'
  if (status === 404) return 'NOT_FOUND'
  if (status === 400 || status === 422) return 'VALIDATION_ERROR'
  if (status >= 500) return 'INTERNAL_ERROR'
  return 'UNKNOWN'
}

function buildActionableMessage(code: BackendErrorCode, detail: string | null): string {
  if (code !== 'UNKNOWN') {
    const guidance = CODE_GUIDANCE[code]
    // Prefer backend detail when it already sounds actionable; otherwise use guidance.
    if (detail && detail.length > 0) {
      // Ensure size/type codes always include a concrete next step.
      if (code === 'PAYLOAD_TOO_LARGE' && !/smaller|size|large|limit|MB|bytes/i.test(detail)) {
        return sanitizeText(`${detail} Choose a smaller video and try again.`)
      }
      if (code === 'UNSUPPORTED_MEDIA_TYPE' && !/MP4|WebM|MOV/i.test(detail)) {
        return sanitizeText(`${detail} Use an MP4, WebM, or MOV video.`)
      }
      if (code === 'INTERNAL_ERROR' && !/retry|try again|moment/i.test(detail)) {
        return sanitizeText(`${detail} Retry in a moment.`)
      }
      return detail
    }
    return guidance.fallbackMessage
  }
  return detail && detail.length > 0
    ? detail
    : 'Something went wrong. Retry or choose a different artifact.'
}

function extractEnvelope(body: unknown): {
  code: string | null
  message: string | null
  requestId: string | null
} {
  if (body == null || typeof body !== 'object') {
    return { code: null, message: null, requestId: null }
  }
  const record = body as Record<string, unknown>
  const raw = record.error
  let code: string | null = null
  let message: string | null = null
  let requestId: string | null =
    typeof record.request_id === 'string' ? record.request_id : null

  if (typeof raw === 'string') {
    message = raw
  } else if (raw != null && typeof raw === 'object') {
    const inner = raw as Record<string, unknown>
    if (typeof inner.code === 'string') code = inner.code
    if (typeof inner.message === 'string') message = inner.message
    if (typeof inner.request_id === 'string') requestId = inner.request_id
  }

  return { code, message, requestId }
}

/**
 * Parse a non-OK API Response into a structured, actionable error for the UI.
 */
export async function parseActionableApiError(
  response: Response,
  fallback: string,
): Promise<ActionableApiError> {
  const status = typeof response.status === 'number' ? response.status : 0
  let body: unknown
  try {
    body = await response.json()
  } catch {
    const code = codeFromStatus(status)
    const guidance = code !== 'UNKNOWN' ? CODE_GUIDANCE[code] : null
    return {
      code,
      message: guidance?.fallbackMessage ?? sanitizeText(fallback),
      detail: null,
      requestId: null,
      action: guidance?.action ?? (status >= 500 ? 'retry' : 'none'),
      retryable: guidance?.retryable ?? status >= 500,
      status,
    }
  }

  const extracted = extractEnvelope(body)
  const detail = extracted.message ? sanitizeText(extracted.message) : null
  const code: BackendErrorCode =
    extracted.code && isKnownCode(extracted.code)
      ? extracted.code
      : codeFromStatus(status)

  const guidance = code !== 'UNKNOWN' ? CODE_GUIDANCE[code] : null
  const message = buildActionableMessage(code, detail) || sanitizeText(fallback)

  return {
    code,
    message,
    detail,
    requestId: extracted.requestId,
    action: guidance?.action ?? 'none',
    retryable: guidance?.retryable ?? false,
    status,
  }
}

/**
 * Extract a human-readable actionable error message from a non-OK API Response.
 * Back-compat wrapper used by existing service call sites.
 */
export async function parseApiError(
  response: Response,
  fallback: string,
): Promise<string> {
  const actionable = await parseActionableApiError(response, fallback)
  return actionable.message
}

/** Error thrown by frontend API helpers so hooks can branch on `code` / `action`. */
export class ApiClientError extends Error {
  readonly code: BackendErrorCode
  readonly action: ActionHint
  readonly retryable: boolean
  readonly requestId: string | null
  readonly status: number
  readonly detail: string | null

  constructor(actionable: ActionableApiError) {
    super(actionable.message)
    this.name = 'ApiClientError'
    this.code = actionable.code
    this.action = actionable.action
    this.retryable = actionable.retryable
    this.requestId = actionable.requestId
    this.status = actionable.status
    this.detail = actionable.detail
  }
}

/** Map a backend/API client error onto verification portal error codes. */
export function toVerificationErrorCode(
  error: unknown,
):
  | 'UNSUPPORTED_ARTIFACT'
  | 'OVERSIZED_ARTIFACT'
  | 'INVALID_EVIDENCE'
  | 'TIMEOUT'
  | 'DEPENDENCY_UNAVAILABLE'
  | null {
  if (
    error instanceof Error &&
    ((('code' in error) && error.code === 'timeout') || error.name === 'TimeoutError')
  ) return 'TIMEOUT'
  if (!(error instanceof ApiClientError)) return null
  switch (error.code) {
    case 'PAYLOAD_TOO_LARGE':
      return 'OVERSIZED_ARTIFACT'
    case 'UNSUPPORTED_MEDIA_TYPE':
      return 'UNSUPPORTED_ARTIFACT'
    case 'VALIDATION_ERROR':
      return 'INVALID_EVIDENCE'
    case 'NOT_FOUND':
    case 'INTERNAL_ERROR':
    case 'UNKNOWN':
      return 'DEPENDENCY_UNAVAILABLE'
    default:
      return 'DEPENDENCY_UNAVAILABLE'
  }
}

/**
 * Parse an on-chain / Soroban RPC error and map it to an actionable message.
 * Surfaces contract dispute errors (cooldown #66, cap #61, deadline #62, etc.).
 */
export function parseContractError(
  error: unknown,
  fallback = 'Transaction failed. Please check your inputs and try again.',
): ActionableApiError {
  const str =
    error instanceof Error
      ? error.message
      : typeof error === 'string'
        ? error
        : JSON.stringify(error ?? '')

  let matchedCode: BackendErrorCode | null = null

  if (/Error\(Contract,\s*#?66\)|ContractError\(66\)|#66\b|\bReporterOnCooldown\b|cooldown/i.test(str)) {
    matchedCode = 'REPORTER_ON_COOLDOWN'
  } else if (/Error\(Contract,\s*#?61\)|ContractError\(61\)|#61\b|\bTooManyOpenDisputes\b|dispute\s*cap|open\s*dispute.*cap/i.test(str)) {
    matchedCode = 'TOO_MANY_OPEN_DISPUTES'
  } else if (/Error\(Contract,\s*#?62\)|ContractError\(62\)|#62\b|\bDisputeWindowExpired\b|deadline/i.test(str)) {
    matchedCode = 'DISPUTE_WINDOW_EXPIRED'
  } else if (/Error\(Contract,\s*#?65\)|ContractError\(65\)|#65\b|\bUnauthorizedResponder\b|unauthorized\s*responder/i.test(str)) {
    matchedCode = 'UNAUTHORIZED_RESPONDER'
  } else if (/Error\(Contract,\s*#?45\)|ContractError\(45\)|#45\b|\bDisputeNotFound\b|dispute\s*not\s*found/i.test(str)) {
    matchedCode = 'DISPUTE_NOT_FOUND'
  } else if (/Error\(Contract,\s*#?63\)|ContractError\(63\)|#63\b|\bDisputeAlreadyClosed\b|dispute\s*already\s*closed/i.test(str)) {
    matchedCode = 'DISPUTE_ALREADY_CLOSED'
  } else if (/Error\(Contract,\s*#?67\)|ContractError\(67\)|#67\b|\bInvalidDisputeTransition\b|invalid\s*dispute\s*transition/i.test(str)) {
    matchedCode = 'INVALID_DISPUTE_TRANSITION'
  }

  if (matchedCode && matchedCode in CODE_GUIDANCE) {
    const guidance = CODE_GUIDANCE[matchedCode as Exclude<BackendErrorCode, 'UNKNOWN'>]
    return {
      code: matchedCode,
      message: guidance.fallbackMessage,
      detail: sanitizeText(str),
      requestId: null,
      action: guidance.action,
      retryable: guidance.retryable,
      status: 400,
    }
  }

  return {
    code: 'UNKNOWN',
    message: sanitizeText(str) || fallback,
    detail: null,
    requestId: null,
    action: 'none',
    retryable: false,
    status: 400,
  }
}

/**
 * Format a contract error into a user-facing actionable error string.
 */
export function formatContractErrorMessage(
  error: unknown,
  fallback = 'Transaction failed. Please check your inputs and try again.',
): string {
  return parseContractError(error, fallback).message
}

