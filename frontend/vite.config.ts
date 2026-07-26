import { defineConfig } from 'vitest/config'
import react from '@vitejs/plugin-react'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react() as any],
  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: [],
  },
  build: {
    chunkSizeWarningLimit: 3600,
    rollupOptions: {
      output: {
        manualChunks(id) {
          if (id.includes('@noir-lang')) return 'noir-runtime'
          if (id.includes('@stellar') || id.includes('@scure') || id.includes('@noble')) {
            return 'stellar'
          }
          if (id.includes('react') || id.includes('react-dom')) return 'react'
        },
      },
    },
  },
})
