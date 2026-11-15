import { describe, it, expect, beforeEach, vi } from 'vitest';
import * as freighterApi from '@stellar/freighter-api';
import { connectFreighter, getWalletNetwork } from './stellar';

vi.mock('@stellar/freighter-api');

const mockedApi = vi.mocked(freighterApi);

describe('stellar wallet adapter', () => {
  beforeEach(() => {
    vi.resetAllMocks();
  });

  describe('connectFreighter', () => {
    it('returns the public key on success', async () => {
      mockedApi.requestAccess.mockResolvedValue({
        address: 'GABCDEFGHIJKLMNOPQRSTUVWXYZ2345678901234567890',
      } as Awaited<ReturnType<typeof freighterApi.requestAccess>>);

      await expect(connectFreighter()).resolves.toBe(
        'GABCDEFGHIJKLMNOPQRSTUVWXYZ2345678901234567890',
      );
    });

    it('throws when the wallet returns an error', async () => {
      mockedApi.requestAccess.mockResolvedValue({
        address: '',
        error: { message: 'User declined' },
      } as Awaited<ReturnType<typeof freighterApi.requestAccess>>);

      await expect(connectFreighter()).rejects.toThrow('User declined');
    });
  });

  describe('getWalletNetwork', () => {
    it('returns the network passphrase on success', async () => {
      mockedApi.getNetwork.mockResolvedValue({
        network: 'TESTNET',
        networkPassphrase: 'Test Stellar Network ; September 2015',
      } as Awaited<ReturnType<typeof freighterApi.getNetwork>>);

      await expect(getWalletNetwork()).resolves.toBe(
        'Test Stellar Network ; September 2015',
      );
    });

    it('returns an empty string when the wallet returns an error', async () => {
      mockedApi.getNetwork.mockResolvedValue({
        network: '',
        networkPassphrase: '',
        error: { message: 'Not connected' },
      } as Awaited<ReturnType<typeof freighterApi.getNetwork>>);

      await expect(getWalletNetwork()).resolves.toBe('');
    });

    it('returns an empty string when networkPassphrase is missing', async () => {
      mockedApi.getNetwork.mockResolvedValue({} as Awaited<ReturnType<typeof freighterApi.getNetwork>>);

      await expect(getWalletNetwork()).resolves.toBe('');
    });
  });
});
