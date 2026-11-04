/**
 * 无依赖打包器：把 package.json 的 `files` 列表打成 npm 风格的 .tgz（package/ 前缀）。
 * 不依赖 npm / tar / 7z。GitHub Release 直接传这个文件即可。
 *
 *   node scripts/pack.mjs            → dsh-risk-gate-<version>.tgz
 *   node scripts/pack.mjs --list     → 只列出会打进去的文件
 */
import fs from 'node:fs'
import path from 'node:path'
import zlib from 'node:zlib'
import { fileURLToPath } from 'node:url'

const here = path.dirname(fileURLToPath(import.meta.url))
const repoRoot = path.resolve(here, '..')
const pkg = JSON.parse(fs.readFileSync(path.join(repoRoot, 'package.json'), 'utf8'))

const listOnly = process.argv.includes('--list')
const always = ['package.json', 'README.md', 'README.en.md', 'LICENSE', 'CHANGELOG.md', 'cordis.patch.yml']
const wanted = [...new Set([...always, ...(pkg.files ?? [])])]

function walk(target, out = []) {
  const abs = path.join(repoRoot, target)
  if (!fs.existsSync(abs)) return out
  const stat = fs.statSync(abs)
  if (stat.isDirectory()) {
    for (const entry of fs.readdirSync(abs, { withFileTypes: true })) {
      if (entry.name === 'node_modules' || entry.name === '.git') continue
      walk(path.join(target, entry.name), out)
    }
  } else {
    out.push(target.replace(/\\/g, '/'))
  }
  return out
}

const files = wanted.flatMap((entry) => walk(entry)).sort()
if (files.length === 0) {
  console.error('没有可打包的文件')
  process.exit(1)
}
if (listOnly) {
  for (const file of files) console.log(file)
  process.exit(0)
}

const BLOCK = 512
const pad = (buffer) => {
  const rest = buffer.length % BLOCK
  return rest === 0 ? buffer : Buffer.concat([buffer, Buffer.alloc(BLOCK - rest)])
}

function octal(value, width) {
  return value.toString(8).padStart(width - 1, '0') + '\0'
}

function header(name, size, mtimeSeconds) {
  const buffer = Buffer.alloc(BLOCK, 0)
  const write = (text, offset, length) => buffer.write(text, offset, length, 'utf8')
  write(name.slice(0, 99), 0, 100)
  write('0000644\0', 100, 8)
  write('0000000\0', 108, 8)
  write('0000000\0', 116, 8)
  write(octal(size, 12), 124, 12)
  write(octal(mtimeSeconds, 12), 136, 12)
  write('        ', 148, 8) // 校验和占位：8 个空格
  write('0', 156, 1)
  write('ustar\0', 257, 6)
  write('00', 263, 2)
  write('root', 265, 32)
  write('root', 297, 32)
  write('0000000\0', 329, 8)
  write('0000000\0', 337, 8)
  let sum = 0
  for (const byte of buffer) sum += byte
  write(sum.toString(8).padStart(6, '0') + '\0 ', 148, 8)
  return buffer
}

const chunks = []
const now = Math.floor(Date.now() / 1000)
for (const file of files) {
  const data = fs.readFileSync(path.join(repoRoot, file))
  const name = `package/${file}`
  chunks.push(header(name, data.length, now), pad(data))
}
chunks.push(Buffer.alloc(BLOCK * 2, 0))

const tarball = zlib.gzipSync(Buffer.concat(chunks), { level: 9 })
const outName = `${pkg.name}-${pkg.version}.tgz`
const outPath = path.join(repoRoot, outName)
fs.writeFileSync(outPath, tarball)

console.log(`打包完成：${outName}`)
console.log(`文件数：${files.length}，大小：${(tarball.length / 1024).toFixed(1)} KB`)
for (const file of files) console.log(`  ${file}`)
