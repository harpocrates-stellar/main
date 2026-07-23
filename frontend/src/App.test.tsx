import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import App from './App'

vi.mock('./components/EvilEye', () => ({
  default: () => <div data-testid="evil-eye" />,
}))

describe('App', () => {
  beforeEach(() => {
    vi.restoreAllMocks()
    Object.defineProperty(window, 'scrollTo', {
      configurable: true,
      value: vi.fn(),
    })
    window.history.replaceState(null, '', '/')
  })

  it('smoke renders the landing view without opening workspace panels', () => {
    render(<App />)

    expect(screen.getByRole('heading', { name: /evidence integrity for silent witnesses/i })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /begin evidence flow/i })).toBeInTheDocument()
    expect(screen.getByText(/stellar testnet/i)).toBeInTheDocument()
    expect(screen.queryByRole('heading', { name: /evidence studio/i })).not.toBeInTheDocument()
    expect(screen.queryByRole('heading', { name: /verify artifact/i })).not.toBeInTheDocument()
  })

  it('opens the evidence studio and updates identity tier controls', async () => {
    const user = userEvent.setup()

    render(<App />)
    await user.click(screen.getByRole('button', { name: /begin evidence flow/i }))

    expect(screen.getByRole('heading', { name: /evidence studio/i })).toBeInTheDocument()
    expect(screen.getByText(/upload evidence to begin/i)).toBeInTheDocument()
    expect(screen.getByLabelText(/credential seed/i)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /register proof/i })).toBeDisabled()

    await user.click(screen.getByRole('button', { name: /consistent source/i }))

    const studio = screen.getByRole('heading', { name: /evidence studio/i }).closest('section')
    expect(studio).not.toBeNull()
    expect(within(studio as HTMLElement).getByText(/freighter signature links evidence/i)).toBeInTheDocument()
    expect(screen.queryByLabelText(/credential seed/i)).not.toBeInTheDocument()
    expect(screen.queryByLabelText(/nullifier seed/i)).not.toBeInTheDocument()
  })

  it('shows the unavailable-services path when verify upload cannot reach the API', async () => {
    const user = userEvent.setup()
    vi.spyOn(globalThis, 'fetch').mockRejectedValue(new Error('network unavailable'))

    render(<App />)
    await user.click(screen.getByRole('button', { name: /^verify$/i }))
    await user.upload(screen.getByLabelText(/drop or choose a received video/i), new File(['video'], 'clip.mp4', {
      type: 'video/mp4',
    }))

    expect(await screen.findByText(/verification services are unavailable/i)).toBeInTheDocument()
    await waitFor(() => expect(globalThis.fetch).toHaveBeenCalledWith('http://127.0.0.1:5050/api/stego/extract', {
      body: expect.any(FormData),
      method: 'POST',
    }))
    expect(screen.getByText(/chain status/i).nextElementSibling).toHaveTextContent(/not loaded/i)
  })
})
