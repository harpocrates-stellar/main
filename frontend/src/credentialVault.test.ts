import { describe, it, expect, vi } from 'vitest';
import { CredentialVault, StorageUnavailableError } from './credentialVault';
import type { SeedPair } from './seedVault';

const dummySeeds: SeedPair = { credentialSeed: 'cred', nullifierSeed: 'null' };

describe('CredentialVault storage error handling', () => {
  it('throws StorageUnavailableError on setup when localStorage.setItem fails', async () => {
    const vault = new CredentialVault();
    vi.spyOn(window.localStorage, 'setItem').mockImplementation(() => {
      throw new Error('QuotaExceeded');
    });
    await expect(vault.setup('pwd', dummySeeds)).rejects.toBeInstanceOf(StorageUnavailableError);
    vi.restoreAllMocks();
  });

  it('throws StorageUnavailableError on unlock when localStorage.getItem fails', async () => {
    const vault = new CredentialVault();
    vi.spyOn(window.localStorage, 'getItem').mockImplementation(() => {
      throw new Error('Access denied');
    });
    await expect(vault.unlock('pwd')).rejects.toBeInstanceOf(StorageUnavailableError);
    vi.restoreAllMocks();
  });
});
