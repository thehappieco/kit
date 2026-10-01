// Builds the release tarball from clean and checks what goes into it.
//
//   node scripts/pack.mjs                 build, pack, check, write SHA256SUMS
//   node scripts/pack.mjs --reproduce     do it twice from clean and compare
//   node scripts/pack.mjs --tag v0.1.0    also require the version to match a tag
//
// What reproduces is the tar inside the .tgz: npm writes it with fixed
// times, owners and order, so the same tree and the same npm give the same
// tar on any machine. The gzip around it is Node's zlib, whose output changes
// between Node versions (22 and 25 give different .tgz bytes around the same
// tar). So SHA256SUMS records both: the .tgz, which is what a lockfile's
// integrity pins and what CI built with the Node in .node-version, and the
// tar (as thehappieco-kit-<v>.tar), which anyone rebuilding from the tag
// compares, whatever their Node: gunzip -c the release asset | sha256sum.
//
// Every byte of the tarball ends up measured in Wappie's enclave image, so the
// checks are strict: only dist/ plus the files npm always adds and NOTICE; no
// src/ or test/ directory and no source map under dist/ (Wappie's enclave
// build prunes those names); no install scripts (a tarball dependency runs
// them); every export resolving to a file; LICENSE and NOTICE identical to
// the repository's.

import { execFileSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { existsSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { gunzipSync } from 'node:zlib'

const root = join(dirname(fileURLToPath(import.meta.url)), '..')
const args = process.argv.slice(2)
const fail = (message) => {
  console.error(`pack: ${message}`)
  process.exit(1)
}

const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'))
const lifecycle = ['preinstall', 'install', 'postinstall', 'prepare', 'prepack', 'postpack', 'prepublish', 'prepublishOnly', 'publish', 'postpublish']
for (const name of lifecycle) if (pkg.scripts?.[name]) fail(`package.json has a ${name} script`)
const tagAt = args.indexOf('--tag')
if (tagAt >= 0 && args[tagAt + 1] !== `v${pkg.version}`) fail(`package.json is ${pkg.version}, the tag is ${args[tagAt + 1]}`)
for (const name of ['LICENSE', 'NOTICE']) {
  if (readFileSync(join(root, name), 'utf8') !== readFileSync(join(root, '..', name), 'utf8')) fail(`js/${name} differs from the repository's ${name}`)
}

function build() {
  rmSync(join(root, 'dist'), { recursive: true, force: true })
  execFileSync('npm', ['run', 'build'], { cwd: root, stdio: 'inherit' })
  const out = execFileSync('npm', ['pack', '--json', '--ignore-scripts'], { cwd: root, encoding: 'utf8' })
  const [info] = JSON.parse(out)
  const files = info.files.map((f) => f.path).sort()
  const allowed = (path) => ['package.json', 'README.md', 'LICENSE', 'NOTICE'].includes(path) || path.startsWith('dist/')
  for (const path of files) {
    if (!allowed(path)) fail(`unexpected file in the tarball: ${path}`)
    if (/(^|\/)(src|test)\//.test(path.slice('dist/'.length)) && path.startsWith('dist/')) fail(`${path}: dist/ must not hold a src/ or test/ directory`)
    if (path.endsWith('.map')) fail(`${path}: no source maps`)
  }
  for (const [name, target] of Object.entries(pkg.exports)) {
    for (const file of Object.values(target)) {
      if (!files.includes(file.replace(/^\.\//, ''))) fail(`export ${name} points at ${file}, which is not in the tarball`)
    }
  }
  const tarball = join(root, info.filename)
  const bytes = readFileSync(tarball)
  return {
    filename: info.filename,
    files,
    sha256: createHash('sha256').update(bytes).digest('hex'),
    integrity: 'sha512-' + createHash('sha512').update(bytes).digest('base64'),
    tarSHA256: createHash('sha256').update(gunzipSync(bytes)).digest('hex'),
  }
}

const npm = execFileSync('npm', ['--version'], { cwd: root, encoding: 'utf8' }).trim()
const first = build()
if (args.includes('--reproduce')) {
  const again = build()
  if (again.tarSHA256 !== first.tarSHA256) fail(`two builds from clean differ: tar ${first.tarSHA256} and ${again.tarSHA256}`)
  if (again.integrity !== first.integrity) fail(`two builds from clean differ: ${first.integrity} and ${again.integrity}`)
  console.log(`reproducible: two builds from clean are both tar ${first.tarSHA256}, ${first.integrity}`)
}
const tarName = first.filename.replace(/\.tgz$/, '.tar')
writeFileSync(join(root, 'SHA256SUMS'), `${first.sha256}  ${first.filename}\n${first.tarSHA256}  ${tarName}\n`)
console.log(`${first.filename}: ${first.files.length} files, node ${process.version}, npm ${npm}`)
console.log(`sha256     ${first.sha256}`)
console.log(`integrity  ${first.integrity}`)
console.log(`tar sha256 ${first.tarSHA256} (the reproducible part: gunzip -c ${first.filename} | sha256sum)`)
if (!existsSync(join(root, first.filename))) fail('the tarball is missing')
