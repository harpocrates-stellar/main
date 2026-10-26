import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { IssuersView } from './IssuersView'
import * as registry from '../harpocratesRegistry'

vi.mock('../harpocratesRegistry', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../harpocratesRegistry')>()
  return {
    ...actual,
    getIssuerRecord: vi.fn(),
    getIssuerRotation: vi.fn(),
    isIssuerVerifiable: vi.fn(),
  }
})

describe('IssuersView component', () => {
  const mockIssuer1 = 'GBRPYHIL2CI3FNQ4BXLFMNDLFJUNPU2HY3ZMFSHONUCEOASW7QC7OX2H'
  const mockIssuer2 = 'GA2C5RFPE6GCKMY3US5PAB6UZLKIGAHWKXX2GNXEDACHIXABVW64GIT5'
  const mockIssuer3 = 'GD3C5RFPE6GCKMY3US5PAB6UZLKIGAHWKXX2GNXEDACHIXABVW64G123'

  beforeEach(() => {
    vi.resetAllMocks()
    vi.stubEnv('VITE_KNOWN_ISSUERS', `${mockIssuer1},${mockIssuer2},${mockIssuer3}`)
  })

  it('renders loading state initially', async () => {
    vi.mocked(registry.getIssuerRecord).mockImplementation(
      () => new Promise((resolve) => setTimeout(() => resolve(null), 100))
    )
    vi.mocked(registry.getIssuerRotation).mockResolvedValue(null)
    vi.mocked(registry.isIssuerVerifiable).mockResolvedValue(false)

    render(<IssuersView contractId="CTEST" />)

    expect(screen.getByRole('status', { name: /loading issuer directory/i })).toBeInTheDocument()
    expect(screen.getByText(/loading issuer directory/i)).toBeInTheDocument()
  })

  it('renders empty state when no issuers are configured', async () => {
    vi.stubEnv('VITE_KNOWN_ISSUERS', '')
    vi.stubEnv('VITE_ISSUERS', '')

    render(<IssuersView contractId="CTEST" apiBase="" />)

    await waitFor(() => {
      expect(screen.getByText(/no issuers configured/i)).toBeInTheDocument()
    })
  })

  it('renders error state and retries successfully', async () => {
    vi.stubEnv('VITE_KNOWN_ISSUERS', mockIssuer1)
    vi.mocked(registry.getIssuerRecord).mockRejectedValueOnce(new Error('Network failure'))

    render(<IssuersView contractId="CTEST" />)

    await waitFor(() => {
      expect(screen.getByText(/network failure/i)).toBeInTheDocument()
    })

    // Now mock success
    vi.mocked(registry.getIssuerRecord).mockResolvedValue({
      metadataHash: 'aa'.repeat(32),
      active: true,
    })
    vi.mocked(registry.getIssuerRotation).mockResolvedValue(null)
    vi.mocked(registry.isIssuerVerifiable).mockResolvedValue(true)

    const user = userEvent.setup()
    await user.click(screen.getByRole('button', { name: /retry/i }))

    await waitFor(() => {
      expect(screen.getByText(/showing 1 of 1 issuers/i)).toBeInTheDocument()
    })
  })

  it('renders populated directory with active, rotating, and revoked issuers', async () => {
    // mockIssuer1: Active
    vi.mocked(registry.getIssuerRecord).mockImplementation(async (_contractId, addr) => {
      if (addr === mockIssuer1) {
        return { metadataHash: '11'.repeat(32), active: true }
      }
      if (addr === mockIssuer2) {
        // Rotating out
        return { metadataHash: '22'.repeat(32), active: false }
      }
      if (addr === mockIssuer3) {
        // Revoked
        return { metadataHash: '33'.repeat(32), active: false }
      }
      return null
    })

    vi.mocked(registry.getIssuerRotation).mockImplementation(async (_contractId, addr) => {
      if (addr === mockIssuer2) {
        return {
          previousIssuer: mockIssuer2,
          replacementIssuer: mockIssuer1,
          rotatedAt: 1700000000,
          graceExpiresAt: 1735689600, // future timestamp
          graceSecs: 86400,
        }
      }
      return null
    })

    vi.mocked(registry.isIssuerVerifiable).mockImplementation(async (_contractId, addr) => {
      if (addr === mockIssuer1) return true
      if (addr === mockIssuer2) return true
      return false
    })

    render(<IssuersView contractId="CTEST" />)

    await waitFor(() => {
      expect(screen.getByText(/showing 3 of 3 issuers/i)).toBeInTheDocument()
    })

    // Check states
    const row1 = screen.getByTestId(`issuer-row-${mockIssuer1}`)
    expect(row1).toHaveTextContent(/active/i)

    const row2 = screen.getByTestId(`issuer-row-${mockIssuer2}`)
    expect(row2).toHaveTextContent(/rotating/i)

    const row3 = screen.getByTestId(`issuer-row-${mockIssuer3}`)
    expect(row3).toHaveTextContent(/revoked/i)

    // Check heading accessibility
    const heading = screen.getByRole('heading', { name: /issuer directory/i })
    expect(heading).toHaveAttribute('id', 'issuers-heading')
    expect(heading).toHaveAttribute('tabIndex', '-1')
  })

  it('copies address and metadata hash to clipboard', async () => {
    vi.stubEnv('VITE_KNOWN_ISSUERS', mockIssuer1)
    vi.mocked(registry.getIssuerRecord).mockResolvedValue({
      metadataHash: 'aa'.repeat(32),
      active: true,
    })
    vi.mocked(registry.getIssuerRotation).mockResolvedValue(null)
    vi.mocked(registry.isIssuerVerifiable).mockResolvedValue(true)

    const writeText = vi.fn().mockResolvedValue(undefined)
    Object.defineProperty(navigator, 'clipboard', {
      value: { writeText },
      writable: true,
      configurable: true,
    })

    render(<IssuersView contractId="CTEST" />)

    await waitFor(() => {
      expect(screen.getByText(/showing 1 of 1 issuers/i)).toBeInTheDocument()
    })

    const user = userEvent.setup()
    const copyAddrBtn = screen.getByRole('button', { name: new RegExp(`Copy address for ${mockIssuer1}`, 'i') })
    await user.click(copyAddrBtn)

    expect(writeText).toHaveBeenCalledWith(mockIssuer1)

    const copyHashBtn = screen.getByRole('button', { name: new RegExp(`Copy metadata hash for ${mockIssuer1}`, 'i') })
    await user.click(copyHashBtn)

    expect(writeText).toHaveBeenCalledWith('aa'.repeat(32))
  })

  it('filters issuers by search query', async () => {
    vi.mocked(registry.getIssuerRecord).mockResolvedValue({
      metadataHash: 'aa'.repeat(32),
      active: true,
    })
    vi.mocked(registry.getIssuerRotation).mockResolvedValue(null)
    vi.mocked(registry.isIssuerVerifiable).mockResolvedValue(true)

    render(<IssuersView contractId="CTEST" />)

    await waitFor(() => {
      expect(screen.getByText(/showing 3 of 3 issuers/i)).toBeInTheDocument()
    })

    const user = userEvent.setup()
    const searchInput = screen.getByRole('searchbox', { name: /filter issuers/i })
    await user.type(searchInput, mockIssuer1.slice(0, 6))

    expect(screen.getByText(/showing 1 of 3 issuers/i)).toBeInTheDocument()
    expect(screen.getByTestId(`issuer-row-${mockIssuer1}`)).toBeInTheDocument()
    expect(screen.queryByTestId(`issuer-row-${mockIssuer2}`)).not.toBeInTheDocument()
  })
})
