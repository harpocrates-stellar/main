import { describe, it, expect } from 'vitest'
import {
  parseApiError,
  parseActionableApiError,
  ApiClientError,
  toVerificationErrorCode,
  parseContractError,
  formatContractErrorMessage,
} from './apiError'

function makeResponse(body: unknown, status = 400): Response {
  return {
    ok: false,
    status,
    json: () => Promise.resolve(body),
  } as unknown as Response
}

function makeTextResponse(status = 500): Response {
  return {
    ok: false,
    status,
    json: () => Promise.reject(new SyntaxError('Unexpected token')),
  } as unknown as Response
}

describe('parseApiError', () => {
  const FALLBACK = 'Something went wrong.'

  it('returns the string error from the legacy envelope', async () => {
    const res = makeResponse({ error: 'video payload exceeds size limit' })
    expect(await parseApiError(res, FALLBACK)).toBe('video payload exceeds size limit')
  })

  it('returns the nested message when error is an object', async () => {
    const res = makeResponse({ error: { message: 'API key has expired' } })
    expect(await parseApiError(res, FALLBACK)).toBe('API key has expired')
  })

  it('returns actionable guidance for PAYLOAD_TOO_LARGE', async () => {
    const res = makeResponse(
      { ok: false, error: { code: 'PAYLOAD_TOO_LARGE', message: 'body too large', request_id: 'r1' } },
      413,
    )
    const msg = await parseApiError(res, FALLBACK)
    expect(msg.toLowerCase()).toMatch(/smaller|large|size/)
  })

  it('returns actionable guidance for UNSUPPORTED_MEDIA_TYPE', async () => {
    const res = makeResponse(
      { error: { code: 'UNSUPPORTED_MEDIA_TYPE', message: 'bad type' } },
      400,
    )
    const msg = await parseApiError(res, FALLBACK)
    expect(msg).toMatch(/MP4|WebM|MOV/)
  })

  it('returns fallback-style guidance when body has no error field', async () => {
    const res = makeResponse({ message: 'unknown' }, 500)
    const msg = await parseApiError(res, FALLBACK)
    expect(msg.toLowerCase()).toMatch(/retry|temporary|server/)
  })

  it('returns fallback when error is an empty string', async () => {
    const res = makeResponse({ error: '' }, 400)
    const msg = await parseApiError(res, FALLBACK)
    expect(msg.length).toBeGreaterThan(0)
    expect(msg).not.toBe('')
  })

  it('returns fallback when error is null', async () => {
    const res = makeResponse({ error: null }, 400)
    const msg = await parseApiError(res, FALLBACK)
    expect(msg.length).toBeGreaterThan(0)
  })

  it('returns status-based guidance when JSON parsing fails', async () => {
    const res = makeTextResponse(500)
    const msg = await parseApiError(res, FALLBACK)
    expect(msg.toLowerCase()).toMatch(/retry|temporary|server/)
  })

  it('returns fallback when body is null', async () => {
    const res = makeResponse(null, 400)
    const msg = await parseApiError(res, FALLBACK)
    expect(msg.length).toBeGreaterThan(0)
  })

  it('returns fallback when body is a primitive', async () => {
    const res = makeResponse('oops', 400)
    const msg = await parseApiError(res, FALLBACK)
    expect(msg.length).toBeGreaterThan(0)
  })

  it('strips HTML tags from error messages', async () => {
    const res = makeResponse({ error: '<script>alert(1)</script>bad input' })
    const msg = await parseApiError(res, FALLBACK)
    expect(msg).toBe('bad input')
    expect(msg).not.toContain('<script>')
  })

  it('strips nested HTML in object-style errors', async () => {
    const res = makeResponse({ error: { message: '<b>server</b> error' } })
    const msg = await parseApiError(res, FALLBACK)
    expect(msg).toBe('server error')
  })

  it('truncates very long error messages', async () => {
    const longMsg = 'x'.repeat(600)
    const res = makeResponse({ error: longMsg })
    const msg = await parseApiError(res, FALLBACK)
    expect(msg).toHaveLength(501) // 500 + '…'
    expect(msg.endsWith('…')).toBe(true)
  })

  it('does not truncate messages under the limit', async () => {
    const msg300 = 'y'.repeat(300)
    const res = makeResponse({ error: msg300 })
    const msg = await parseApiError(res, FALLBACK)
    expect(msg).toBe(msg300)
  })

  it('trims whitespace from the error message', async () => {
    const res = makeResponse({ error: '  session not found  ' })
    const msg = await parseApiError(res, FALLBACK)
    expect(msg).toBe('session not found')
  })
})

describe('parseActionableApiError', () => {
  it('maps canonical backend codes to action hints', async () => {
    const cases: Array<[string, number, string, boolean]> = [
      ['VALIDATION_ERROR', 400, 'fix_input', false],
      ['PAYLOAD_TOO_LARGE', 413, 'reduce_file_size', false],
      ['NOT_FOUND', 404, 'check_resource', false],
      ['INTERNAL_ERROR', 500, 'retry', true],
      ['UNSUPPORTED_MEDIA_TYPE', 400, 'use_supported_format', false],
    ]
    for (const [code, status, action, retryable] of cases) {
      const res = makeResponse(
        { ok: false, error: { code, message: `detail for ${code}`, request_id: 'abc' } },
        status,
      )
      const err = await parseActionableApiError(res, 'fallback')
      expect(err.code).toBe(code)
      expect(err.action).toBe(action)
      expect(err.retryable).toBe(retryable)
      expect(err.requestId).toBe('abc')
      expect(err.status).toBe(status)
      expect(err.message.length).toBeGreaterThan(0)
    }
  })

  it('infers code from HTTP status when envelope lacks code', async () => {
    const res = makeResponse({ error: 'too big' }, 413)
    const err = await parseActionableApiError(res, 'fallback')
    expect(err.code).toBe('PAYLOAD_TOO_LARGE')
    expect(err.action).toBe('reduce_file_size')
  })
})

describe('ApiClientError / toVerificationErrorCode', () => {
  it('preserves structured fields on the Error subclass', async () => {
    const res = makeResponse(
      { error: { code: 'INTERNAL_ERROR', message: 'boom', request_id: 'rid' } },
      500,
    )
    const actionable = await parseActionableApiError(res, 'fallback')
    const err = new ApiClientError(actionable)
    expect(err).toBeInstanceOf(Error)
    expect(err.name).toBe('ApiClientError')
    expect(err.code).toBe('INTERNAL_ERROR')
    expect(err.retryable).toBe(true)
    expect(err.requestId).toBe('rid')
    expect(err.message.toLowerCase()).toMatch(/retry|temporary|boom/)
  })

  it('maps client errors onto verification portal codes', async () => {
    const oversized = new ApiClientError({
      code: 'PAYLOAD_TOO_LARGE',
      message: 'too large',
      detail: 'too large',
      requestId: null,
      action: 'reduce_file_size',
      retryable: false,
      status: 413,
    })
    expect(toVerificationErrorCode(oversized)).toBe('OVERSIZED_ARTIFACT')

    const unsupported = new ApiClientError({
      code: 'UNSUPPORTED_MEDIA_TYPE',
      message: 'bad type',
      detail: null,
      requestId: null,
      action: 'use_supported_format',
      retryable: false,
      status: 400,
    })
    expect(toVerificationErrorCode(unsupported)).toBe('UNSUPPORTED_ARTIFACT')

    expect(toVerificationErrorCode(Object.assign(new Error('request timed out'), { code: 'timeout' }))).toBe('TIMEOUT')
    expect(toVerificationErrorCode(new Error('nope'))).toBeNull()
  })
})

describe('parseContractError & formatContractErrorMessage', () => {
  it('maps cooldown error (#66 / ReporterOnCooldown) to actionable message', () => {
    const error = new Error('HostError: Error(Contract, #66)')
    const parsed = parseContractError(error)
    expect(parsed.code).toBe('REPORTER_ON_COOLDOWN')
    expect(parsed.retryable).toBe(true)
    expect(parsed.action).toBe('retry')
    expect(parsed.message.toLowerCase()).toContain('cooldown')
    expect(formatContractErrorMessage(error).toLowerCase()).toContain('cooldown')
  })

  it('maps max open disputes error (#61 / TooManyOpenDisputes) to actionable message', () => {
    const error = new Error('HostError: Error(Contract, #61)')
    const parsed = parseContractError(error)
    expect(parsed.code).toBe('TOO_MANY_OPEN_DISPUTES')
    expect(parsed.retryable).toBe(false)
    expect(parsed.action).toBe('check_resource')
    expect(parsed.message.toLowerCase()).toContain('maximum open disputes')
  })

  it('maps dispute window expired error (#62 / DisputeWindowExpired) to actionable message', () => {
    const error = new Error('Error(Contract, #62)')
    const parsed = parseContractError(error)
    expect(parsed.code).toBe('DISPUTE_WINDOW_EXPIRED')
    expect(parsed.retryable).toBe(false)
    expect(parsed.message.toLowerCase()).toContain('deadline')
  })

  it('maps unauthorized responder error (#65 / UnauthorizedResponder)', () => {
    const error = new Error('ContractError(65)')
    const parsed = parseContractError(error)
    expect(parsed.code).toBe('UNAUTHORIZED_RESPONDER')
    expect(parsed.action).toBe('fix_input')
    expect(parsed.message.toLowerCase()).toContain('unauthorized responder')
  })

  it('maps dispute not found error (#45 / DisputeNotFound)', () => {
    const error = new Error('DisputeNotFound')
    const parsed = parseContractError(error)
    expect(parsed.code).toBe('DISPUTE_NOT_FOUND')
    expect(parsed.message.toLowerCase()).toContain('not found')
  })

  it('handles unknown contract error with fallback', () => {
    const error = new Error('Random unexpected failure')
    const parsed = parseContractError(error)
    expect(parsed.code).toBe('UNKNOWN')
    expect(parsed.message).toBe('Random unexpected failure')
  })
})

