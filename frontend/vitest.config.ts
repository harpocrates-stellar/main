import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    environment: 'jsdom',
    setupFiles: ['./src/test/setup.ts', '@vitest/web-worker'],
    env: {
      VITE_HARPOCRATES_REGISTRY_ID: 'CTESTID',
    },
  },
})