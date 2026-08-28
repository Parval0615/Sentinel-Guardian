import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import { existsSync, renameSync } from 'node:fs'
import { resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = fileURLToPath(new URL('.', import.meta.url))

export default defineConfig({
  plugins: [
    react(),
    {
      name: 'sentinel-app-entry',
      closeBundle() {
        const source = resolve(root, 'dist/app.html')
        if (existsSync(source)) {
          renameSync(source, resolve(root, 'dist/index.html'))
        }
      },
    },
  ],
  build: {
    rollupOptions: {
      input: resolve(root, 'app.html'),
    },
  },
  server: {
    port: 5173,
    proxy: {
      '/v1': {
        target: 'http://127.0.0.1:8000',
        changeOrigin: true,
      },
    },
  },
})
