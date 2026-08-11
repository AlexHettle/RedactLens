/// <reference types="vitest/config" />
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export const contentSecurityPolicy =
  "default-src 'self'; base-uri 'none'; connect-src 'self'; font-src 'self'; " +
  "form-action 'self'; frame-ancestors 'none'; img-src 'self' data:; " +
  "object-src 'none'; script-src 'self'; style-src 'self'; " +
  "style-src-attr 'unsafe-inline'"

export const securityHeaders = {
  'Content-Security-Policy': contentSecurityPolicy,
  'X-Frame-Options': 'DENY',
}

// React Refresh injects a development-only inline module and Vite uses a
// loopback WebSocket for hot reload. The installed production UI receives the
// strict policy above without either exception.
export const developmentSecurityHeaders = {
  ...securityHeaders,
  'Content-Security-Policy':
    "default-src 'self'; base-uri 'none'; " +
    "connect-src 'self' ws://127.0.0.1:* ws://localhost:*; font-src 'self'; " +
    "form-action 'self'; frame-ancestors 'none'; img-src 'self' data:; " +
    "object-src 'none'; script-src 'self' 'unsafe-inline'; style-src 'self'; " +
    "style-src-attr 'unsafe-inline'",
}

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    strictPort: true,
    headers: developmentSecurityHeaders,
  },
  preview: {
    headers: securityHeaders,
  },
  test: {
    include: ['src/**/*.test.{ts,tsx}', 'vite.config.test.ts'],
    environment: 'jsdom',
    globals: true,
    setupFiles: './src/test/setup.ts',
  },
})
