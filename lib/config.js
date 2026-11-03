// Config layering for openjs-cna-tools.
//
// Precedence (highest → lowest):
//   1. CLI flag (resolved by each component; not in scope here)
//   2. Environment (OPENJS_CNA_TOKEN, OPENJS_CNA_BASE_URL, …)
//   3. Project config: ./.openjs-cna.json in CWD
//   4. Global config:  ~/.config/openjs-cna/config.json (XDG-friendly)
//
// Encryption-at-rest for secrets is on the roadmap (matches NCU's `-x` flag
// shape via a `gpg` subprocess — no JS dep). Until that lands, secrets are
// stored as plaintext and `set -x` is a no-op with a warning. The merged
// config still uses property-descriptor merging so the encrypted-getter
// pattern can drop in later without a breaking change to callers.

import fs from 'node:fs'
import path from 'node:path'
import os from 'node:os'

const ENV_PREFIX = 'OPENJS_CNA_'

const ENV_TO_KEY = {
  OPENJS_CNA_TOKEN: 'openjs_cna_token',
  OPENJS_CNA_BASE_URL: 'openjs_cna_base_url'
}

export function globalConfigPath () {
  const xdg = process.env.XDG_CONFIG_HOME || path.join(os.homedir(), '.config')
  return path.join(xdg, 'openjs-cna-experimental', 'config.json')
}

export function projectConfigPath (cwd = process.cwd()) {
  return path.join(cwd, '.openjs-cna.json')
}

function safeReadJson (filePath) {
  try {
    const raw = fs.readFileSync(filePath, 'utf8')
    return JSON.parse(raw)
  } catch {
    return {}
  }
}

function envOverrides () {
  const out = {}
  for (const [envName, key] of Object.entries(ENV_TO_KEY)) {
    if (process.env[envName] != null) out[key] = process.env[envName]
  }
  // Pass-through for any future OPENJS_CNA_* env vars we haven't mapped yet.
  for (const [name, value] of Object.entries(process.env)) {
    if (!name.startsWith(ENV_PREFIX)) continue
    if (ENV_TO_KEY[name]) continue
    const key = name.slice(ENV_PREFIX.length).toLowerCase()
    out[key] = value
  }
  return out
}

// Merge configs using property descriptors so future encrypted-getter
// properties survive the merge without being prematurely evaluated. Today
// every value is a plain string; this is a no-op cost paid for future-
// proofing.
function mergeWithDescriptors (...sources) {
  const out = Object.create(null)
  for (const source of sources) {
    if (!source) continue
    Object.defineProperties(out, Object.getOwnPropertyDescriptors(source))
  }
  return out
}

export function getMergedConfig ({ cwd } = {}) {
  const global = safeReadJson(globalConfigPath())
  const project = safeReadJson(projectConfigPath(cwd))
  const env = envOverrides()
  return mergeWithDescriptors(global, project, env)
}

function ensureDir (filePath) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true })
}

export function setConfigValue (key, value, { scope = 'global', cwd } = {}) {
  const target = scope === 'project' ? projectConfigPath(cwd) : globalConfigPath()
  const current = safeReadJson(target)
  current[key] = value
  ensureDir(target)
  fs.writeFileSync(target, JSON.stringify(current, null, 2) + '\n', { mode: 0o600 })
  return target
}

export function getConfigValue (key, opts = {}) {
  const merged = getMergedConfig(opts)
  return merged[key]
}

export function deleteConfigValue (key, { scope = 'global', cwd } = {}) {
  const target = scope === 'project' ? projectConfigPath(cwd) : globalConfigPath()
  const current = safeReadJson(target)
  if (!(key in current)) return false
  delete current[key]
  ensureDir(target)
  fs.writeFileSync(target, JSON.stringify(current, null, 2) + '\n', { mode: 0o600 })
  return true
}

// Returns a redacted view of the merged config: secret-looking keys
// (anything containing 'token' or 'secret') are replaced with a fixed
// placeholder so `openjs-cna-experimental config list` can be piped without leaking.
export function listConfig (opts = {}) {
  const merged = getMergedConfig(opts)
  const out = {}
  for (const [key, value] of Object.entries(merged)) {
    if (/token|secret|password/i.test(key)) {
      out[key] = '<redacted>'
    } else {
      out[key] = value
    }
  }
  return out
}
