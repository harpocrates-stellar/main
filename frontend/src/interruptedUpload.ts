/**
 * interruptedUpload – classifies a stalled evidence session into one of four
 * recovery categories and surfaces the choices to the StudioView recovery banner.
 *
 * Recovery categories
 * -------------------
 * resumable       – the session was interrupted mid-upload and the original
 *                   source file is still available; the user can retry with the
 *                   same file without re-selecting it.
 * source-changed  – the user has selected a different file since the session
 *                   was interrupted; retrying with the stale cached source hash
 *                   would produce invalid evidence.  The user must discard.
 * expired         – the interrupted session is older than MAX_SESSION_AGE_MS
 *                   (default 4 hours); the timestamp embedded in the evidence
 *                   would be too far in the past to be useful.
 * unrecoverable   – the session ended in a terminal error from which a simple
 *                   retry cannot recover (e.g. the backend rejected the upload
 *                   rather than a transient network failure).
 */

import type { Stage } from './types'

export const MAX_SESSION_AGE_MS = 4 * 60 * 60 * 1000 // 4 hours

/** Error messages that indicate a terminal server-side rejection. */
const TERMINAL_ERROR_PATTERNS: ReadonlyArray<RegExp> = [
  /payload exceeds size limit/i,
  /video upload must use a video content type/i,
  /request body is too large/i,
  /413/,
]

export type RecoveryCategory =
  | 'resumable'
  | 'source-changed'
  | 'expired'
  | 'unrecoverable'
  | 'none'

export type InterruptedUploadSession = {
  /** Recovery category — 'none' means no interrupted session is present. */
  category: RecoveryCategory
  /**
   * The file name captured when the upload began (from `file.name`).
   * Present for all categories except 'none'.
   */
  fileName: string | null
  /**
   * When the session was last active (epoch ms).
   * Present for all categories except 'none'.
   */
  interruptedAt: number | null
}

export type ClassifyOptions = {
  /** Current stage from useEvidence. */
  stage: Stage
  /** Current file from useEvidence (may differ from the originally uploaded file). */
  currentFile: File | null
  /**
   * The file that was being processed when the upload was interrupted.
   * Retained by useEvidence in a ref; null if no upload was attempted.
   */
  interruptedFile: File | null
  /** Wall-clock ms when the interruption occurred (from Date.now()). */
  interruptedAt: number | null
  /** Error message, populated when stage === 'error'. */
  errorMessage: string | null
  /**
   * Current clock time in ms.  Injected so tests can control time without
   * touching global Date.
   */
  nowMs?: number
}

/**
 * Classify the current evidence session into a recovery category.
 *
 * Returns `{ category: 'none' }` when there is nothing to recover from.
 */
export function classifyInterruptedSession(opts: ClassifyOptions): InterruptedUploadSession {
  const { stage, currentFile, interruptedFile, interruptedAt, errorMessage } = opts
  const nowMs = opts.nowMs ?? Date.now()

  // Terminal success states: nothing to recover.
  if (stage === 'ready' || stage === 'registered' || stage === 'idle') {
    return { category: 'none', fileName: null, interruptedAt: null }
  }

  // Active (in-flight) stages: not interrupted yet.
  if (stage === 'hashing' || stage === 'embedding' || stage === 'proving') {
    return { category: 'none', fileName: null, interruptedAt: null }
  }

  const isInterruptedStage =
    stage === 'cancelled' || stage === 'error'

  if (!isInterruptedStage) {
    return { category: 'none', fileName: null, interruptedAt: null }
  }

  const fileName = interruptedFile?.name ?? null

  // Terminal server errors cannot be retried without changing the input.
  if (stage === 'error' && errorMessage) {
    const isTerminal = TERMINAL_ERROR_PATTERNS.some((pattern) => pattern.test(errorMessage))
    if (isTerminal) {
      return { category: 'unrecoverable', fileName, interruptedAt }
    }
  }

  // Check expiry.
  if (interruptedAt !== null && nowMs - interruptedAt > MAX_SESSION_AGE_MS) {
    return { category: 'expired', fileName, interruptedAt }
  }

  // Detect source-file change: the user has picked a different file since
  // the session was interrupted.  Comparing by object identity is correct here
  // because useEvidence already uses object identity to gate hash memoisation
  // — if the user picks a new file (even with the same name/size/mtime), it
  // will be a different File object.
  if (interruptedFile !== null && currentFile !== null && currentFile !== interruptedFile) {
    return { category: 'source-changed', fileName, interruptedAt }
  }

  return { category: 'resumable', fileName, interruptedAt }
}

/**
 * Human-readable label for each recovery category, suitable for a banner heading.
 */
export const RECOVERY_CATEGORY_LABELS: Record<Exclude<RecoveryCategory, 'none'>, string> = {
  resumable: 'Upload interrupted — resume?',
  'source-changed': 'Source file changed — previous session discarded',
  expired: 'Previous session expired',
  unrecoverable: 'Upload failed',
}

/**
 * Description copy for each recovery category, shown below the heading.
 */
export const RECOVERY_CATEGORY_DESCRIPTIONS: Record<Exclude<RecoveryCategory, 'none'>, string> = {
  resumable: 'Your upload was interrupted. You can retry with the same file or start over.',
  'source-changed':
    'You selected a different file. The previous interrupted session cannot be resumed and has been discarded.',
  expired:
    'The previous upload session is too old to resume. Start a new upload to continue.',
  unrecoverable:
    'The upload was rejected by the server and cannot be retried with the same file. Check the error message and try a different file.',
}
