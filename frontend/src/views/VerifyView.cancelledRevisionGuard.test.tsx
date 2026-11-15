import { act, fireEvent, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'
import '../App.css'
import { VerifyView } from './VerifyView'
import type { UseVerificationReturn } from '../hooks/useVerification'
import {
  createVerificationRevisionGate,
  runRevisionBoundUploadedVideoVerification,
  runRevisionBoundVerificationFlow,
} from '../services/verificationFlow'
import * as verificationService from '../services/verificationService'
import type { ChainProofRecord, Hex32 } from '../stellarTypes'
import { expectNoA11yViolations, runAxe } from '../test/axeA11y'

vi.mock('../stellar', () => ({
  CONTRACT_NETWORK_PASSPHRASE: 'Test SDF Future Network ; October 2022',
  getProofByVideoHash: vi.fn(),
  WatchWalletChanges: vi.fn(),
  connectFreighter: vi.fn(),
  getWalletNetwork: vi.fn(),
}))

vi.mock('../components/ChainProofPanel', () => ({
  ChainProofPanel: () => <div data-testid="chain-proof-panel" />,
  formatProofExpiry: () => 'Never',
}))

vi.mock('../components/VerifierSetStatusPanel', () => ({
  VerifierSetStatusPanel: () => <div data-testid="verifier-set-status-panel" />,
}))

vi.mock('../provenance/ProvenanceCard', () => ({
  default: () => <div data-testid="provenance-card" />,
}))

const HASH_OLD = '1'.repeat(64) as Hex32
const HASH_NEW = '2'.repeat(64) as Hex32
const META_OLD = 'a'.repeat(64) as Hex32
const META_NEW = 'b'.repeat(64) as Hex32

function deferred<T>() {
  let resolve!: (value: T) => void
  let reject!: (reason?: unknown) => void
  const promise = new Promise<T>((res, rej) => {
    resolve = res
    reject = rej
  })
  return { promise, resolve, reject }
}

function makeChainRecord(videoHash: Hex32, metadataHash: Hex32): ChainProofRecord {
  return {
    videoHash,
    metadataHash,
    tier: 1,
    source: null,
    issuer: null,
    createdAt: '1750000000',
    expiresAt: 0,
    status: 1,
  }
}

function makeHook(overrides: Partial<UseVerificationReturn> = {}): UseVerificationReturn {
  return {
    verifyHash: '',
    verifyResult: '',
    events: [],
    chainProof: null,
    status: 'idle',
    errorCode: null,
    isVerifying: false,
    offline: false,
    setOffline: vi.fn(),
    verifyEvidence: vi.fn(),
    loadEvents: vi.fn(),
    loadSharedVerification: vi.fn(),
    cancel: vi.fn(),
    retry: vi.fn(),
    clear: vi.fn(),
    ...overrides,
  }
}

describe('Cancelled verification revision guard (#1136)', () => {
  it('binds asynchronous verification flow and upload requests to monotonic revisions and ignores cancelled or superseded completions', async () => {
    const firstEvents = deferred<[]>()
    const secondEvents = deferred<[]>()
    const uploadExtract = deferred<{ hasHarpocratesMetadata: boolean }>()

    const extractSpy = vi
      .spyOn(verificationService, 'extractMetadata')
      .mockImplementation(() => uploadExtract.promise)
    const eventsSpy = vi
      .spyOn(verificationService, 'fetchProofEventsByVideo')
      .mockImplementationOnce(() => firstEvents.promise)
      .mockImplementationOnce(() => secondEvents.promise)
      .mockResolvedValue([])
    const chainSpy = vi
      .spyOn(verificationService, 'getOnChainProof')
      .mockImplementation(async (hash) =>
        makeChainRecord(
          hash as Hex32,
          (hash === HASH_OLD ? META_OLD : META_NEW) as Hex32,
        ),
      )

    const gate = createVerificationRevisionGate()
    const runOne = runRevisionBoundVerificationFlow(gate, HASH_OLD)
    gate.cancelActive()
    const runTwo = runRevisionBoundVerificationFlow(gate, HASH_NEW)

    secondEvents.resolve([])
    const secondOutcome = await runTwo
    expect(secondOutcome.committed).toBe(true)
    if (secondOutcome.committed) {
      expect(secondOutcome.result.videoHash).toBe(HASH_NEW)
    }

    // Late resolution of cancelled Request 1 must be ignored
    firstEvents.resolve([])
    const firstOutcome = await runOne
    expect(firstOutcome).toEqual({
      committed: false,
      revision: 1,
      ignoredReason: 'REQUEST_CANCELLED',
    })

    // Upload verification superseded by newer evidence selection is ignored
    const uploadFile = new File(['abc'], 'clip.mp4', { type: 'video/mp4' })
    const uploadRun = runRevisionBoundUploadedVideoVerification(
      gate,
      uploadFile,
      HASH_OLD,
    )
    gate.selectEvidence(HASH_NEW)
    uploadExtract.resolve({ hasHarpocratesMetadata: true })
    const uploadOutcome = await uploadRun
    expect(uploadOutcome).toEqual({
      committed: false,
      revision: 4,
      ignoredReason: 'SUPERSEDED_BY_NEWER_SELECTION',
    })

    extractSpy.mockRestore()
    eventsSpy.mockRestore()
    chainSpy.mockRestore()
  })

  it('prevents a cancelled verification request or slow manifest read from updating a newer selection in VerifyView', async () => {
    const user = userEvent.setup()
    const cancelSpy = vi.fn()

    // Start in-flight verification on HASH_OLD
    const { container, rerender } = render(
      <VerifyView
        wallet=""
        networkMismatch={null}
        verification={makeHook({
          verifyHash: HASH_OLD,
          status: 'verifying',
          isVerifying: true,
          cancel: cancelSpy,
        })}
        provenanceRecord={null}
      />,
    )

    // User cancels active verification on HASH_OLD
    await user.click(screen.getByRole('button', { name: /cancel verification/i }))
    expect(cancelSpy).toHaveBeenCalledTimes(1)

    // Portal transitions out of verifying; user selects newer evidence HASH_NEW
    rerender(
      <VerifyView
        wallet=""
        networkMismatch={null}
        verification={makeHook({
          verifyHash: HASH_OLD,
          status: 'cancelled',
          errorCode: 'CANCELLED',
          verifyResult: 'Verification cancelled.',
          isVerifying: false,
          cancel: cancelSpy,
        })}
        provenanceRecord={null}
      />,
    )

    const hashInput = screen.getByLabelText(/video hash/i)
    await user.clear(hashInput)
    await user.type(hashInput, HASH_NEW)

    // Simulate late completion from cancelled Request 1 (HASH_OLD) arriving after HASH_NEW was selected
    rerender(
      <VerifyView
        wallet=""
        networkMismatch={null}
        verification={makeHook({
          verifyHash: HASH_OLD,
          status: 'success',
          verifyResult: 'Stale confirmed result for old artifact.',
          chainProof: makeChainRecord(HASH_OLD, META_OLD),
          isVerifying: false,
        })}
        provenanceRecord={null}
      />,
    )

    // Newer selection HASH_NEW remains intact; stale HASH_OLD success banner is ignored!
    expect(screen.getByLabelText(/video hash/i)).toHaveValue(HASH_NEW)
    expect(
      screen.queryByText(/stale confirmed result for old artifact/i),
    ).not.toBeInTheDocument()

    // Also verify slow manifest file read started earlier cannot overwrite newer typed selection
    const slowFileRead = deferred<string>()
    const slowManifestFile = new File(['{}'], 'slow-manifest.json', {
      type: 'application/json',
    })
    Object.defineProperty(slowManifestFile, 'text', {
      value: () => slowFileRead.promise,
    })

    fireEvent.change(
      screen.getByLabelText(/drop or choose a proof manifest json/i),
      { target: { files: [slowManifestFile] } },
    )

    await user.clear(hashInput)
    await user.type(hashInput, HASH_NEW)

    await act(async () => {
      slowFileRead.resolve(
        JSON.stringify({
          protocol: 'harpocrates',
          version: 2,
          proofId: `0x${'9'.repeat(64)}`,
          tier: 'silent',
          network: 'Test SDF Future Network ; October 2022',
          contractId: 'CAAAAAAAAABCD1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890',
          transactionRef: `0x${'8'.repeat(64)}`,
          videoHash: HASH_OLD,
          metadataHash: META_OLD,
          sourceHash: META_OLD,
          timestamp: '2026-10-19T00:00:00Z',
          verifierScope: '0',
          epoch: 0,
        }),
      )
      await Promise.resolve()
    })

    expect(screen.getByLabelText(/video hash/i)).toHaveValue(HASH_NEW)
    expectNoA11yViolations(
      await runAxe(container),
      'VerifyView cancelled revision guard',
    )
  })
})
