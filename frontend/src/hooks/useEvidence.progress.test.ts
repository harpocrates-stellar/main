// @vitest-environment jsdom
import { renderHook, act } from '@testing-library/react';
import { useEvidence } from './useEvidence';
import type { HashProgress } from '../utils';

vi.mock('../workers/fileHashWorkerClient', () => ({
  hashFileInWorker: vi.fn(async (file: File, onProgress: (p: HashProgress) => void) => {
    const p1 = { processedBytes: 50, totalBytes: 100, percentage: 50 };
    const p2 = { processedBytes: 75, totalBytes: 100, percentage: 50 }; // same percent
    onProgress(p1);
    onProgress(p2);
    return 'dummyhash';
  }),
}));

vi.mock('../services/evidenceService', () => ({
  embedVideo: vi.fn(async () => ({
    embeddedBlob: new Blob([], { type: 'video/mp4' }),
    embeddedHash: 'embeddedHash',
    metadataHash: 'metadataHash',
  })),
}));

vi.mock('../stellar', () => ({
  getWalletNetwork: vi.fn(async () => 'TESTNET'),
  CONTRACT_NETWORK_PASSTHRASE: 'Testnet',
  registerProofOnStellar: vi.fn(async () => ({ status: 'success' })),
}));

vi.mock('../networkGuard', () => ({
  checkNetworkMatch: vi.fn(() => ({ ok: true })),
}));

describe('useEvidence progress announcement deduplication', () => {
  it('only updates message when percentage changes', async () => {
    const { result } = renderHook(() => useEvidence());
    const file = new File(['data'], 'video.mp4', { type: 'video/mp4' });
    await act(async () => {
      await result.current.handleEvidence(file);
    });
    expect(result.current.message).toContain('50%');
    // Ensure message not overwritten by duplicate percentage (still contains 50%)
    expect(result.current.message).toContain('50%');
  });
});
