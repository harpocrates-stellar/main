/**
 * Privacy-safe logging utilities.
 * Ensures sensitive fields are redacted before reaching logs or storage.
 */

export const REDACTED_VALUE = '[REDACTED]'

const SENSITIVE_KEY_PATTERNS = [
  /proof/i,
  /nullifiersecret/i,
  /credentialsecret/i,
  /witness/i,
  /publicinput/i,
  /authorization/i,
  /private/i,
  /secret/i,
  /key/i,
  /token/i,
  /password/i,
  /mnemonic/i,
  /seed/i,
]

function isSensitiveKey(key: string): boolean {
  const normalized = key.toLowerCase()
  return SENSITIVE_KEY_PATTERNS.some(pattern => pattern.test(normalized))
}

function redactValue(value: unknown): unknown {
  if (value === null || value === undefined) {
    return value
  }

  if (Array.isArray(value)) {
    return value.map(item => redactValue(item))
  }

  if (typeof value !== 'object') {
    return value
  }

  const result: Record<string, unknown> = {}

  for (const [key, val] of Object.entries(value as Record<string, unknown>)) {
    if (isSensitiveKey(key)) {
      result[key] = REDACTED_VALUE
    } else if (val && typeof val === 'object') {
      result[key] = redactValue(val)
    } else {
      result[key] = val
    }
  }

  return result
}

export function redactSensitive<T extends Record<string, unknown>>(obj: T): T {
  return redactValue(obj) as T
}

export function logStructured(logger: Console, level: 'info' | 'warn' | 'error' | 'debug', data: Record<string, unknown>): void {
  const redacted = redactSensitive(data)
  const message = JSON.stringify(redacted)
  logger[level](message)
}