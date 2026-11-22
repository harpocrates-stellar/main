import { defineConfig } from 'vitest/config'

export default defineConfig({
  server: {
    fs: {
      strict: false,
    },
  },
  test: {
    environment: 'happy-dom',
    setupFiles: ['./src/test/setup.ts', '@vitest/web-worker'],
    env: {
      VITE_HARPOCRATES_REGISTRY_ID: 'CTESTID',
    },
  },
})