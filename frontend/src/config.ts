const DEFAULT_API_BASE = 'http://127.0.0.1:5050'
const DEFAULT_STELLAR_RPC_URL = 'https://soroban-testnet.stellar.org'

export const appConfig = {
  apiBase: import.meta.env.VITE_API_BASE ?? DEFAULT_API_BASE,
  harpocratesRegistryId: import.meta.env.VITE_HARPOCRATES_REGISTRY_ID ?? '',
  registryId: import.meta.env.VITE_HARPOCRATES_REGISTRY_ID ?? '',
  stellarRpcUrl: import.meta.env.VITE_STELLAR_RPC_URL ?? DEFAULT_STELLAR_RPC_URL,
} as const
