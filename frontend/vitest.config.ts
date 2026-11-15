import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    environment: 'happy-dom',
    include: ['src/**/*.{test,spec}.{ts,tsx}'],
    setupFiles: ['./src/test/setup.ts', '@vitest/web-worker'],
    env: {
      VITE_HARPOCRATES_REGISTRY_ID: 'CTESTID',
    },
    coverage: {
      include: ['src/**/*.{ts,tsx}'],
      exclude: ['src/**/*.{test,spec}.{ts,tsx}', 'src/test/**', 'src/**/*.d.ts'],
    },
  },
})
