import { fireEvent, render, screen } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import { VaultRecoveryBanner } from './VaultRecoveryBanner'

describe('VaultRecoveryBanner', () => {
  it('renders notice with reason and recovery controls', () => {
    const onRecover = vi.fn()
    render(
      <VaultRecoveryBanner
        staleReason="envelope-updated"
        onRecover={onRecover}
      />
    )

    expect(screen.getByRole('alert')).toBeInTheDocument()
    expect(screen.getByText(/Cross-tab vault change detected/i)).toBeInTheDocument()
    expect(screen.getByText(/envelope was updated with new credentials/i)).toBeInTheDocument()
    expect(
      screen.getByRole('button', { name: /Overwrite storage with current active work/i })
    ).toBeInTheDocument()
    expect(
      screen.getByRole('button', { name: /Reload remote vault and discard local active work/i })
    ).toBeInTheDocument()
    expect(
      screen.getByRole('button', { name: /Discard local active work and lock vault/i })
    ).toBeInTheDocument()
  })

  it('renders preserved custom active work if provided', () => {
    const preservedWork = {
      seeds: { credentialSeed: 'c', nullifierSeed: 'n' },
      capturedAt: Date.now(),
      staleReason: 'envelope-updated' as const,
      customData: { draftId: 'doc-99' },
    }

    render(
      <VaultRecoveryBanner
        staleReason="envelope-updated"
        preservedWork={preservedWork}
        onRecover={vi.fn()}
      />
    )

    expect(screen.getByText(/Active work preserved:/i)).toBeInTheDocument()
    expect(screen.getByText(/doc-99/i)).toBeInTheDocument()
  })

  it('triggers discard without requiring passphrase', () => {
    const onRecover = vi.fn()
    render(
      <VaultRecoveryBanner
        staleReason="envelope-removed"
        onRecover={onRecover}
      />
    )

    fireEvent.click(
      screen.getByRole('button', { name: /Discard local active work and lock vault/i })
    )

    expect(onRecover).toHaveBeenCalledWith('discard', undefined)
  })

  it('requires passphrase for overwrite action', () => {
    const onRecover = vi.fn()
    render(
      <VaultRecoveryBanner
        staleReason="envelope-updated"
        onRecover={onRecover}
      />
    )

    fireEvent.click(
      screen.getByRole('button', { name: /Overwrite storage with current active work/i })
    )

    expect(onRecover).not.toHaveBeenCalled()
    expect(screen.getByText(/Please provide a vault passphrase/i)).toBeInTheDocument()

    // Now type passphrase
    const input = screen.getByLabelText(/Vault passphrase/i)
    fireEvent.change(input, { target: { value: 'securePass123!' } })

    fireEvent.click(
      screen.getByRole('button', { name: /Overwrite storage with current active work/i })
    )

    expect(onRecover).toHaveBeenCalledWith('overwrite', 'securePass123!')
  })

  it('passes optional passphrase to reload action if provided', () => {
    const onRecover = vi.fn()
    render(
      <VaultRecoveryBanner
        staleReason="envelope-updated"
        onRecover={onRecover}
      />
    )

    const input = screen.getByLabelText(/Vault passphrase/i)
    fireEvent.change(input, { target: { value: 'newPass456' } })

    fireEvent.click(
      screen.getByRole('button', { name: /Reload remote vault and discard local active work/i })
    )

    expect(onRecover).toHaveBeenCalledWith('reload', 'newPass456')
  })
})
