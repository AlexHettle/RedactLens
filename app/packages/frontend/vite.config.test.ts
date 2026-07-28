import type { Server } from 'node:http'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { describe, expect, it } from 'vitest'
import { build, createServer, preview } from 'vite'
import config, {
  contentSecurityPolicy,
  developmentSecurityHeaders,
  securityHeaders,
} from './vite.config'

function serverUrl(server: Server): string {
  const address = server.address()
  if (!address || typeof address === 'string') throw new Error('Vite did not bind a TCP port.')
  return `http://127.0.0.1:${address.port}`
}

async function expectSecurityHeaders(url: string, expectedPolicy: string) {
  const response = await fetch(url, { headers: { Connection: 'close' } })
  expect(response.status).toBe(200)
  expect(response.headers.get('Content-Security-Policy')).toBe(expectedPolicy)
  expect(response.headers.get('X-Frame-Options')).toBe('DENY')
  await response.body?.cancel()
}

function closeServer(server: Server): Promise<void> {
  return new Promise((resolve, reject) => {
    server.close((error) => (error ? reject(error) : resolve()))
  })
}

describe('Vite browser security headers', () => {
  it('protects both development and production-preview responses', () => {
    expect(securityHeaders).toEqual({
      'Content-Security-Policy': contentSecurityPolicy,
      'X-Frame-Options': 'DENY',
    })
    expect(config).toMatchObject({
      server: { headers: developmentSecurityHeaders },
      preview: { headers: securityHeaders },
    })
    expect(contentSecurityPolicy).toContain("connect-src 'self'")
    expect(contentSecurityPolicy).toContain("script-src 'self'")
    expect(contentSecurityPolicy).not.toContain("script-src 'self' 'unsafe-inline'")
    expect(contentSecurityPolicy).not.toContain("'unsafe-eval'")
  })

  it('serves anti-framing headers from live development and preview servers', async () => {
    const configFile = resolve(process.cwd(), 'vite.config.ts')
    const temporaryRoot = await mkdtemp(join(tmpdir(), 'redactlens-vite-headers-'))
    const outDir = join(temporaryRoot, 'dist')
    let devServer: Awaited<ReturnType<typeof createServer>> | null = null
    let previewServer: Awaited<ReturnType<typeof preview>> | null = null

    try {
      devServer = await createServer({
        configFile,
        logLevel: 'silent',
        server: { host: '127.0.0.1', port: 0, strictPort: false },
      })
      await devServer.listen()
      if (!devServer.httpServer) throw new Error('Vite development server did not start.')
      await expectSecurityHeaders(
        serverUrl(devServer.httpServer),
        developmentSecurityHeaders['Content-Security-Policy'],
      )

      await build({
        configFile,
        logLevel: 'silent',
        build: { outDir, emptyOutDir: true },
      })
      previewServer = await preview({
        configFile,
        logLevel: 'silent',
        build: { outDir },
        preview: { host: '127.0.0.1', port: 0, strictPort: false },
      })
      await expectSecurityHeaders(serverUrl(previewServer.httpServer), contentSecurityPolicy)
    } finally {
      if (previewServer) await closeServer(previewServer.httpServer)
      if (devServer) await devServer.close()
      await rm(temporaryRoot, { recursive: true, force: true })
    }
  }, 30_000)
})
