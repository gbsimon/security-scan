import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import mkcert from 'vite-plugin-mkcert'
import { fileURLToPath, URL } from 'node:url'

export default defineConfig(({ mode }) => ({
  base: './',
  server: { host: true, open: true, port: 5173 },
  resolve: {
    alias: { '@': fileURLToPath(new URL('./src', import.meta.url)) },
  },
  build: {
    assetsDir: 'assets',
    sourcemap: mode !== 'production',
    rollupOptions: {
      output: { manualChunks: { vendor: ['react', 'react-dom'] } },
    },
  },
  plugins: [mkcert(), react()],
  assetsInclude: ['**/*.png', '**/*.mind'],
  optimizeDeps: { exclude: ['lottie-web'] },
}))
