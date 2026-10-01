// The vector specs in real browsers, where WebCrypto's X25519, PKCS#8 export
// and module workers come from the browser rather than from Node: Chromium,
// Firefox and WebKit through Playwright. CI's js-browser job runs this before
// any release (npx playwright install --with-deps chromium firefox webkit,
// then npm run test:browser).
//
// Left out: the specs that need Node by design. cross.spec.ts writes files,
// package.spec.ts reads package.json, and v020.spec.ts checks vectors of
// modules the kit does not ship yet against node:crypto.

import { fileURLToPath } from 'node:url'
import { defineConfig } from 'vitest/config'

const browsers = (process.env.KIT_BROWSERS ?? 'chromium,firefox,webkit').split(',')

export default defineConfig({
  // The vectors live beside js/, at the repository root.
  server: { fs: { allow: [fileURLToPath(new URL('..', import.meta.url))] } },
  test: {
    include: ['test/**/*.spec.ts'],
    exclude: ['test/cross.spec.ts', 'test/package.spec.ts', 'test/v020.spec.ts'],
    testTimeout: 120_000,
    browser: {
      enabled: true,
      provider: 'playwright',
      headless: true,
      screenshotFailures: false,
      instances: browsers.map((browser) => ({ browser: browser as 'chromium' | 'firefox' | 'webkit' })),
    },
  },
})
