import { describe, expect, it, vi, beforeEach } from 'vitest'
import { act, renderHook, waitFor } from '@testing-library/react'
import { getIssuerRecord } from '../harpocratesRegistry'
import { STELLAR_STRKEY_LENGTH } from '../provenance/issuerTrust'
import { useIssuerTrust } from './useIssuerTrust'

vi.mock('../harpocratesRegistry', () => ({
  getIssuerRecord: vi.fn(),
}))

const mockedGetIssuerRecord = vi.mocked(getIssuerRecord)

const CONTRACT_ID = `C${'A'.repeat(STELLAR_STRKEY_LENGTH - 1)}`
const ISSUER = `G${'B'.repeat(STELLAR_STRKEY_LENGTH - 1)}`
const OTHER_ISSUER = `G${'C'.repeat(STELLAR_STRKEY_LENGTH - 1)}`
const NOW = 1_800_000_000

const ACTIVE_RECORD = { metadataHash: 'ab'.repeat(32), active: true }
const INACTIVE_RECORD = { metadataHash: 'cd'.repeat(32), active: false }

beforeEach(() => {
  mockedGetIssuerRecord.mockReset()
})

describe('useIssuerTrust', () => {
  it('reports a trusted issuer for an active registry record', async () => {
    mockedGetIssuerRecord.mockResolvedValue(ACTIVE_RECORD)

    const { result } = renderHook(() =>
      useIssuerTrust({ issuer: ISSUER, contractId: CONTRACT_ID, now: NOW }),
    )

    expect(result.current.state).toBe('checking')
    await waitFor(() => expect(result.current.state).toBe('trusted'))
    expect(mockedGetIssuerRecord).toHaveBeenCalledWith(CONTRACT_ID, ISSUER)
  })

  it('reports a revoked issuer for an inactive registry record', async () => {
    mockedGetIssuerRecord.mockResolvedValue(INACTIVE_RECORD)

    const { result } = renderHook(() =>
      useIssuerTrust({ issuer: ISSUER, contractId: CONTRACT_ID, now: NOW }),
    )

    await waitFor(() => expect(result.current.state).toBe('revoked'))
    expect(result.current.severity).toBe('critical')
  })

  it('reports an unknown issuer when the registry holds no record', async () => {
    mockedGetIssuerRecord.mockResolvedValue(null)

    const { result } = renderHook(() =>
      useIssuerTrust({ issuer: ISSUER, contractId: CONTRACT_ID, now: NOW }),
    )

    await waitFor(() => expect(result.current.state).toBe('unknown'))
  })

  it('reports an unavailable lookup when the registry read fails', async () => {
    mockedGetIssuerRecord.mockRejectedValue(new Error('simulation failed'))

    const { result } = renderHook(() =>
      useIssuerTrust({ issuer: ISSUER, contractId: CONTRACT_ID, now: NOW }),
    )

    await waitFor(() => expect(result.current.state).toBe('unavailable'))
    expect(result.current.description).not.toContain('simulation failed')
  })

  it('does not turn a missing registry id into an unknown issuer', async () => {
    const { result } = renderHook(() =>
      useIssuerTrust({ issuer: ISSUER, contractId: '', now: NOW }),
    )

    await waitFor(() => expect(result.current.state).toBe('unavailable'))
    expect(mockedGetIssuerRecord).not.toHaveBeenCalled()
  })

  it.each([
    ['null', null],
    ['undefined', undefined],
    ['an empty string', ''],
    ['a malformed address', 'not-an-address'],
    ['an oversized address', `${ISSUER}A`],
  ])('skips the registry read for %s', async (_label, issuer) => {
    const { result } = renderHook(() =>
      useIssuerTrust({ issuer, contractId: CONTRACT_ID, now: NOW }),
    )

    await waitFor(() => expect(result.current.state).not.toBe('checking'))
    expect(mockedGetIssuerRecord).not.toHaveBeenCalled()
  })

  it('holds at checking without reading while disabled', () => {
    const { result } = renderHook(() =>
      useIssuerTrust({ issuer: ISSUER, contractId: CONTRACT_ID, enabled: false, now: NOW }),
    )

    expect(result.current.state).toBe('checking')
    expect(mockedGetIssuerRecord).not.toHaveBeenCalled()
  })

  it('starts the read once the issuer becomes eligible', async () => {
    mockedGetIssuerRecord.mockResolvedValue(ACTIVE_RECORD)

    const { result, rerender } = renderHook(
      ({ issuer }: { issuer: string | null }) =>
        useIssuerTrust({ issuer, contractId: CONTRACT_ID, now: NOW }),
      { initialProps: { issuer: null as string | null } },
    )

    expect(result.current.state).toBe('unsupported')
    expect(mockedGetIssuerRecord).not.toHaveBeenCalled()

    rerender({ issuer: ISSUER })

    await waitFor(() => expect(result.current.state).toBe('trusted'))
  })

  it('reports an expired endorsement for an active issuer past expiry', async () => {
    mockedGetIssuerRecord.mockResolvedValue(ACTIVE_RECORD)

    const { result } = renderHook(() =>
      useIssuerTrust({
        issuer: ISSUER,
        contractId: CONTRACT_ID,
        expiresAt: NOW - 1,
        now: NOW,
      }),
    )

    await waitFor(() => expect(result.current.state).toBe('expired'))
  })

  it('keeps a never-expiring record trusted', async () => {
    mockedGetIssuerRecord.mockResolvedValue(ACTIVE_RECORD)

    const { result } = renderHook(() =>
      useIssuerTrust({ issuer: ISSUER, contractId: CONTRACT_ID, expiresAt: 0, now: NOW }),
    )

    await waitFor(() => expect(result.current.state).toBe('trusted'))
  })

  it('reads again when the issuer changes', async () => {
    mockedGetIssuerRecord.mockResolvedValue(INACTIVE_RECORD)

    const { result, rerender } = renderHook(
      ({ issuer }: { issuer: string }) =>
        useIssuerTrust({ issuer, contractId: CONTRACT_ID, now: NOW }),
      { initialProps: { issuer: ISSUER } },
    )

    await waitFor(() => expect(result.current.state).toBe('revoked'))

    mockedGetIssuerRecord.mockResolvedValue(ACTIVE_RECORD)
    rerender({ issuer: OTHER_ISSUER })

    await waitFor(() => expect(result.current.state).toBe('trusted'))
    expect(mockedGetIssuerRecord).toHaveBeenCalledWith(CONTRACT_ID, OTHER_ISSUER)
    expect(mockedGetIssuerRecord).toHaveBeenCalledTimes(2)
  })

  it('ignores a stale response from a superseded issuer', async () => {
    let releaseFirst: ((record: typeof ACTIVE_RECORD) => void) | undefined
    const first = new Promise<typeof ACTIVE_RECORD>((resolve) => {
      releaseFirst = resolve
    })

    mockedGetIssuerRecord.mockReturnValueOnce(first)
    mockedGetIssuerRecord.mockResolvedValue(INACTIVE_RECORD)

    const { result, rerender } = renderHook(
      ({ issuer }: { issuer: string }) =>
        useIssuerTrust({ issuer, contractId: CONTRACT_ID, now: NOW }),
      { initialProps: { issuer: ISSUER } },
    )

    rerender({ issuer: OTHER_ISSUER })
    await waitFor(() => expect(result.current.state).toBe('revoked'))

    await act(async () => {
      releaseFirst?.(ACTIVE_RECORD)
      await first
    })

    expect(result.current.state).toBe('revoked')
  })
})
