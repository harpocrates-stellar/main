export const TRANSCRIPT_PROTOCOL = 'harpocrates-cli-transcripts'
export const TRANSCRIPT_SCHEMA_VERSION = 1
export const DYNAMIC_ISO_PLACEHOLDER = '<ISO-8601>'

const FORBIDDEN_PATTERNS: ReadonlyArray<RegExp> = [
  /-----BEGIN (?:RSA |EC |DSA |OPENSSH |AGE )?PRIVATE KEY/i,
  /\bS[A-Z2-7]{55}\b/,
  /credential[_-]?secret/i,
  /nullifier[_-]?secret/i,
  /private[_-]?key/i,
  /\bwitness(?:[_-]?data|[_-]?value)?\b/i,
]

const FORBIDDEN_MEDIA_EXTENSION_RE = /\.(?:mp4|mov|avi|mkv|jpg|jpeg|png|wav|mp3|tr)$/i

export type CliTranscriptFileInput = {
  /** Relative filename materialized inside a temporary working directory (referenced via `{{dir}}/<name>`). */
  name: string
  /** Synthetic UTF-8 text content written to the temporary file before execution. */
  content: string
}

export type CliTranscriptCase = {
  id: string
  description: string
  argv: string[]
  stdin?: string
  files?: CliTranscriptFileInput[]
  normalizeDynamicTimestamps?: boolean
  expected: {
    exitCode: number
    stdout: string
    stderr: string
  }
}

export type CliTranscriptSuite = {
  protocol: typeof TRANSCRIPT_PROTOCOL
  schemaVersion: typeof TRANSCRIPT_SCHEMA_VERSION
  description: string
  cases: CliTranscriptCase[]
}

export type CliExecutionResult = {
  exitCode: number
  stdout: string
  stderr: string
}

export type CliTranscriptRunner = (entry: CliTranscriptCase) => Promise<CliExecutionResult> | CliExecutionResult

export type TranscriptCaseVerification = {
  id: string
  passed: boolean
  expected: CliExecutionResult
  actual: CliExecutionResult
  mismatches: string[]
}

export type TranscriptSuiteVerification = {
  passed: boolean
  total: number
  failed: number
  results: TranscriptCaseVerification[]
}

function assertPrivacySafeString(value: string, context: string): void {
  for (const pattern of FORBIDDEN_PATTERNS) {
    if (pattern.test(value)) {
      throw new Error(`transcript ${context} contains prohibited secret or witness material`)
    }
  }
}

function validateFileInput(raw: unknown, caseId: string): CliTranscriptFileInput {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    throw new Error(`transcript case "${caseId}" file entry must be an object`)
  }
  const entry = raw as Record<string, unknown>
  if (typeof entry.name !== 'string' || !entry.name.trim()) {
    throw new Error(`transcript case "${caseId}" file entry must have a non-empty name`)
  }
  if (entry.name.includes('..') || entry.name.startsWith('/') || entry.name.startsWith('\\')) {
    throw new Error(`transcript case "${caseId}" file name "${entry.name}" must be a relative filename`)
  }
  if (FORBIDDEN_MEDIA_EXTENSION_RE.test(entry.name)) {
    throw new Error(`transcript case "${caseId}" file "${entry.name}" uses a prohibited media or witness extension`)
  }
  if (typeof entry.content !== 'string') {
    throw new Error(`transcript case "${caseId}" file "${entry.name}" content must be a string`)
  }
  assertPrivacySafeString(entry.content, `case "${caseId}" file "${entry.name}"`)
  return {
    name: entry.name,
    content: entry.content,
  }
}

/**
 * Parse and validate a reproducible CLI transcript fixture suite.
 * Rejects unsupported schema versions, malformed cases, path traversal, and
 * any secret, witness, or real-media artifacts.
 */
export function parseTranscriptSuite(json: string): CliTranscriptSuite {
  let parsed: unknown
  try {
    parsed = JSON.parse(json)
  } catch {
    throw new Error('transcript suite is not valid JSON')
  }

  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error('transcript suite must be a JSON object')
  }

  const suite = parsed as Record<string, unknown>
  if (suite.protocol !== TRANSCRIPT_PROTOCOL) {
    throw new Error(`transcript suite protocol must be "${TRANSCRIPT_PROTOCOL}"`)
  }
  if (suite.schemaVersion !== TRANSCRIPT_SCHEMA_VERSION) {
    throw new Error('unsupported transcript suite schemaVersion')
  }
  if (typeof suite.description !== 'string' || !suite.description.trim()) {
    throw new Error('transcript suite description must be a non-empty string')
  }
  if (!Array.isArray(suite.cases) || suite.cases.length === 0) {
    throw new Error('transcript suite must contain at least one case')
  }

  const seenIds = new Set<string>()
  const cases: CliTranscriptCase[] = suite.cases.map((rawCase, index) => {
    if (!rawCase || typeof rawCase !== 'object' || Array.isArray(rawCase)) {
      throw new Error(`transcript case at index ${index} must be an object`)
    }
    const c = rawCase as Record<string, unknown>
    if (typeof c.id !== 'string' || !/^[a-z0-9][a-z0-9_-]*$/.test(c.id)) {
      throw new Error(`transcript case at index ${index} has an invalid id`)
    }
    if (seenIds.has(c.id)) {
      throw new Error(`duplicate transcript case id "${c.id}"`)
    }
    seenIds.add(c.id)

    if (typeof c.description !== 'string' || !c.description.trim()) {
      throw new Error(`transcript case "${c.id}" must have a non-empty description`)
    }
    if (!Array.isArray(c.argv) || c.argv.length === 0 || c.argv.some((arg) => typeof arg !== 'string')) {
      throw new Error(`transcript case "${c.id}" must specify a non-empty string argv array`)
    }
    for (const arg of c.argv as string[]) {
      assertPrivacySafeString(arg, `case "${c.id}" argv`)
      if (FORBIDDEN_MEDIA_EXTENSION_RE.test(arg)) {
        throw new Error(`transcript case "${c.id}" argv references a prohibited media or witness extension`)
      }
    }

    let stdin: string | undefined
    if (c.stdin !== undefined) {
      if (typeof c.stdin !== 'string') {
        throw new Error(`transcript case "${c.id}" stdin must be a string`)
      }
      assertPrivacySafeString(c.stdin, `case "${c.id}" stdin`)
      stdin = c.stdin
    }

    let files: CliTranscriptFileInput[] | undefined
    if (c.files !== undefined) {
      if (!Array.isArray(c.files)) {
        throw new Error(`transcript case "${c.id}" files must be an array`)
      }
      files = c.files.map((item) => validateFileInput(item, c.id as string))
    }

    const normalizeDynamicTimestamps =
      c.normalizeDynamicTimestamps === undefined ? undefined : Boolean(c.normalizeDynamicTimestamps)
    if (c.normalizeDynamicTimestamps !== undefined && typeof c.normalizeDynamicTimestamps !== 'boolean') {
      throw new Error(`transcript case "${c.id}" normalizeDynamicTimestamps must be a boolean`)
    }

    if (!c.expected || typeof c.expected !== 'object' || Array.isArray(c.expected)) {
      throw new Error(`transcript case "${c.id}" must define an expected object`)
    }
    const exp = c.expected as Record<string, unknown>
    if (typeof exp.exitCode !== 'number' || !Number.isInteger(exp.exitCode) || exp.exitCode < 0 || exp.exitCode > 255) {
      throw new Error(`transcript case "${c.id}" expected.exitCode must be an integer between 0 and 255`)
    }
    if (typeof exp.stdout !== 'string' || typeof exp.stderr !== 'string') {
      throw new Error(`transcript case "${c.id}" expected stdout and stderr must be strings`)
    }
    assertPrivacySafeString(exp.stdout, `case "${c.id}" expected.stdout`)
    assertPrivacySafeString(exp.stderr, `case "${c.id}" expected.stderr`)

    const normalizedCase: CliTranscriptCase = {
      id: c.id,
      description: c.description,
      argv: c.argv as string[],
      expected: {
        exitCode: exp.exitCode,
        stdout: exp.stdout,
        stderr: exp.stderr,
      },
    }
    if (stdin !== undefined) normalizedCase.stdin = stdin
    if (files !== undefined) normalizedCase.files = files
    if (normalizeDynamicTimestamps !== undefined) {
      normalizedCase.normalizeDynamicTimestamps = normalizeDynamicTimestamps
    }
    return normalizedCase
  })

  return {
    protocol: TRANSCRIPT_PROTOCOL,
    schemaVersion: TRANSCRIPT_SCHEMA_VERSION,
    description: suite.description,
    cases,
  }
}

/**
 * Normalize line endings and (when enabled) wall-clock verification timestamps
 * so independent CLI implementations can compare outputs deterministically.
 */
export function normalizeTranscriptOutput(text: string, normalizeTimestamps = false): string {
  let normalized = text.replace(/\r\n/g, '\n')
  if (normalizeTimestamps) {
    normalized = normalized.replace(
      /"verifiedAt":\s*"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z"/g,
      `"verifiedAt": "${DYNAMIC_ISO_PLACEHOLDER}"`,
    )
    normalized = normalized.replace(
      /(Verified at:\s+)\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z/g,
      `$1${DYNAMIC_ISO_PLACEHOLDER}`,
    )
  }
  return normalized
}

/**
 * Execute and verify a single transcript case against a CLI runner.
 */
export async function verifyTranscriptCase(
  entry: CliTranscriptCase,
  runner: CliTranscriptRunner,
): Promise<TranscriptCaseVerification> {
  const rawActual = await runner(entry)
  const normalizeTs = Boolean(entry.normalizeDynamicTimestamps)
  const actual: CliExecutionResult = {
    exitCode: rawActual.exitCode,
    stdout: normalizeTranscriptOutput(rawActual.stdout, normalizeTs),
    stderr: normalizeTranscriptOutput(rawActual.stderr, normalizeTs),
  }
  const expected: CliExecutionResult = {
    exitCode: entry.expected.exitCode,
    stdout: normalizeTranscriptOutput(entry.expected.stdout, normalizeTs),
    stderr: normalizeTranscriptOutput(entry.expected.stderr, normalizeTs),
  }

  const mismatches: string[] = []
  if (actual.exitCode !== expected.exitCode) {
    mismatches.push(`exitCode mismatch: expected ${expected.exitCode}, got ${actual.exitCode}`)
  }
  if (actual.stdout !== expected.stdout) {
    mismatches.push(`stdout mismatch: expected ${JSON.stringify(expected.stdout)}, got ${JSON.stringify(actual.stdout)}`)
  }
  if (actual.stderr !== expected.stderr) {
    mismatches.push(`stderr mismatch: expected ${JSON.stringify(expected.stderr)}, got ${JSON.stringify(actual.stderr)}`)
  }

  return {
    id: entry.id,
    passed: mismatches.length === 0,
    expected,
    actual,
    mismatches,
  }
}

/**
 * Execute and verify every case in a transcript suite sequentially.
 */
export async function verifyTranscriptSuite(
  suite: CliTranscriptSuite,
  runner: CliTranscriptRunner,
): Promise<TranscriptSuiteVerification> {
  const results: TranscriptCaseVerification[] = []
  for (const entry of suite.cases) {
    results.push(await verifyTranscriptCase(entry, runner))
  }
  const failed = results.filter((r) => !r.passed).length
  return {
    passed: failed === 0,
    total: results.length,
    failed,
    results,
  }
}
