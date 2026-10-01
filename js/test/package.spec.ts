import { readdirSync, readFileSync } from 'node:fs'
import { join, relative } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'

const root = fileURLToPath(new URL('..', import.meta.url))
const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'))

function sources(dir: string): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((e) => e.isDirectory() ? sources(join(dir, e.name)) : [join(dir, e.name)])
}

describe('the package', () => {
  it('exports every module outside src/internal, and nothing else', () => {
    // src/internal holds the implementation behind a facade (the platform
    // profile's): shipped, imported by the facade, never a subpath export.
    const modules = sources(join(root, 'src'))
      .map((f) => './' + relative(join(root, 'src'), f).replace(/\.ts$/, ''))
      .filter((m) => !m.startsWith('./internal/'))
      .sort()
    expect(Object.keys(pkg.exports).sort()).toEqual(modules)
    expect(sources(join(root, 'src', 'internal')).length).toBeGreaterThan(0)
    for (const [name, target] of Object.entries(pkg.exports) as [string, { types: string; import: string }][]) {
      expect(target.import).toBe(`./dist/${name.slice(2)}.js`)
      expect(target.types).toBe(`./dist/${name.slice(2)}.d.ts`)
    }
  })

  it('has one runtime dependency, pinned, and no install scripts', () => {
    expect(pkg.dependencies).toEqual({ '@noble/hashes': '2.4.0' })
    for (const version of Object.values(pkg.devDependencies)) expect(version).toMatch(/^\d+\.\d+\.\d+$/)
    for (const name of ['preinstall', 'install', 'postinstall', 'prepare', 'prepack']) expect(pkg.scripts[name]).toBeUndefined()
  })

  it('runs in a browser: no Node import, and nothing from a product', () => {
    for (const file of sources(join(root, 'src'))) {
      const text = readFileSync(file, 'utf8')
      const imports = [...text.matchAll(/from '([^']+)'|import\('([^']+)'\)/g)].map((m) => m[1] ?? m[2])
      for (const spec of imports) expect(spec.startsWith('.') || spec.startsWith('@noble/hashes/'), `${file}: ${spec}`).toBe(true)
    }
  })
})
