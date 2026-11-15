import { fireEvent, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'
import '../App.css'
import { VerifyView } from './VerifyView'
import type { UseVerificationReturn } from '../hooks/useVerification'
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

const VALID_BUNDLE = {
  protocol: 'harpocrates-offline-bundle',
  version: 1,
  videoHash: '1'.repeat(64),
  metadataHash: 'a'.repeat(64),
  proofId: `0x${'b'.repeat(64)}`,
  tier: 'source',
  networkPassphrase: 'Test SDF Future Network ; October 2022',
  contractId: 'CAAAAAAAAABCD1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890',
  timestamp: '2026-10-05T14:22:00Z',
  receipt: {
    videoHash: '1'.repeat(64),
    metadataHash: 'a'.repeat(64),
    proofId: `0x${'b'.repeat(64)}`,
  },
}

describe('VerifyView offline portable bundle entry point (#1137)', () => {
  it('imports a bounded portable bundle, shows unavailable live checks, and never labels skipped revocation checks as passed', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
    const hook = makeHook()
    const { container } = render(
      <VerifyView
        wallet=""
        networkMismatch={null}
        verification={hook}
        provenanceRecord={null}
      />,
    )

    const bundleFile = new File([JSON.stringify(VALID_BUNDLE)], 'bundle.json', {
      type: 'application/json',
    })
    const fileInput = screen.getByLabelText(/import portable bundle file/i)
    fireEvent.change(fileInput, { target: { files: [bundleFile] } })

    const revocationItem = await screen.findByTestId(
      'offline-live-check-soroban-revocation-check',
    )
    expect(revocationItem).toHaveAttribute(
      'data-check-status',
      'unavailable-offline',
    )
    expect(revocationItem).not.toHaveAttribute('data-check-status', 'passed')
    expect(revocationItem).toHaveTextContent(
      /not checked offline — skipped online revocation checks are never treated as passed/i,
    )

    // Verify all 4 live checks are explicitly marked unavailable-offline (never passed)
    for (const id of [
      'soroban-revocation-check',
      'soroban-expiry-check',
      'issuer-directory-standing',
      'neondb-event-corroboration',
    ]) {
      expect(screen.getByTestId(`offline-live-check-${id}`)).toHaveAttribute(
        'data-check-status',
        'unavailable-offline',
      )
    }

    expect(
      screen.getByText(/disposition \(local-bundle-inspected-unconfirmed\)/i),
    ).toBeInTheDocument()
    expect(hook.setOffline).toHaveBeenCalledWith(true)
    expect(fetchSpy).not.toHaveBeenCalled()
    expect(hook.loadSharedVerification).not.toHaveBeenCalled()

    expectNoA11yViolations(await runAxe(container), 'VerifyView offline bundle')
    fetchSpy.mockRestore()
  })

  it('rejects oversized (>128 KB), digest-mismatched, and secret-bearing bundles fail-closed', async () => {
    const user = userEvent.setup()
    render(
      <VerifyView
        wallet=""
        networkMismatch={null}
        verification={makeHook({ offline: true })}
        provenanceRecord={null}
      />,
    )

    // Oversized bundle > 128 KB rejected before JSON parsing
    const oversizedFile = new File(['x'.repeat(130 * 1024)], 'huge.json', {
      type: 'application/json',
    })
    fireEvent.change(screen.getByLabelText(/import portable bundle file/i), {
      target: { files: [oversizedFile] },
    })

    expect(await screen.findByRole('alert')).toHaveTextContent(
      /exceeds the 128 KB offline limit/i,
    )
    expect(screen.getByText(/bundle error code: OVERSIZED_BUNDLE/i)).toBeInTheDocument()

    // Secret witness field rejected
    fireEvent.change(screen.getByLabelText(/portable bundle json/i), {
      target: {
        value: JSON.stringify({
          ...VALID_BUNDLE,
          credentialSeed: 'deadbeef',
        }),
      },
    })
    await user.click(screen.getByRole('button', { name: /inspect bundle offline/i }))
    expect(screen.getByRole('alert')).toHaveTextContent(/credentialSeed/i)
    expect(
      screen.getByText(/bundle error code: SECRET_MATERIAL_REJECTED/i),
    ).toBeInTheDocument()

    // Nested receipt digest mismatch rejected
    fireEvent.change(screen.getByLabelText(/portable bundle json/i), {
      target: {
        value: JSON.stringify({
          ...VALID_BUNDLE,
          receipt: { ...VALID_BUNDLE.receipt, videoHash: '9'.repeat(64) },
        }),
      },
    })
    await user.click(screen.getByRole('button', { name: /inspect bundle offline/i }))
    expect(
      screen.getByText(/bundle error code: DIGEST_BINDING_MISMATCH/i),
    ).toBeInTheDocument()
  })
})
