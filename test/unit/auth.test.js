import { describe, it, beforeEach, afterEach } from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'

import { resolveCredentials } from '../../lib/auth.js'
import { setConfigValue } from '../../lib/config.js'

// resolveCredentials reads from getMergedConfig, which means we need the
// same XDG-isolated harness the config tests use. Otherwise the developer
// machine's real `~/.config/openjs-cna/config.json` would leak in.

let tmpRoot, savedXdg, savedCwd

beforeEach(() => {
  tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'cna-tools-auth-'))
  savedXdg = process.env.XDG_CONFIG_HOME
  process.env.XDG_CONFIG_HOME = path.join(tmpRoot, 'xdg')
  fs.mkdirSync(process.env.XDG_CONFIG_HOME, { recursive: true })
  savedCwd = process.cwd()
  fs.mkdirSync(path.join(tmpRoot, 'project'), { recursive: true })
  process.chdir(path.join(tmpRoot, 'project'))
  delete process.env.OPENJS_CNA_TOKEN
  delete process.env.OPENJS_CNA_BASE_URL
})

afterEach(() => {
  process.chdir(savedCwd)
  if (savedXdg === undefined) delete process.env.XDG_CONFIG_HOME
  else process.env.XDG_CONFIG_HOME = savedXdg
  fs.rmSync(tmpRoot, { recursive: true, force: true })
})

describe('resolveCredentials', () => {
  it('returns undefined fields when nothing is configured', () => {
    const creds = resolveCredentials()
    assert.equal(creds.token, undefined)
    assert.equal(creds.baseUrl, undefined)
  })

  it('reads from the global config', () => {
    setConfigValue('openjs_cna_token', 'bucket:secret', { scope: 'global' })
    setConfigValue('openjs_cna_base_url', 'https://cna.example.com', { scope: 'global' })
    const creds = resolveCredentials()
    assert.equal(creds.token, 'bucket:secret')
    assert.equal(creds.baseUrl, 'https://cna.example.com')
  })

  it('reads from the project config and lets it override global', () => {
    setConfigValue('openjs_cna_base_url', 'https://global', { scope: 'global' })
    setConfigValue('openjs_cna_base_url', 'https://project', { scope: 'project' })
    const creds = resolveCredentials()
    assert.equal(creds.baseUrl, 'https://project')
  })

  it('lets env override both project and global', () => {
    setConfigValue('openjs_cna_token', 'global:secret', { scope: 'global' })
    process.env.OPENJS_CNA_TOKEN = 'env:secret'
    try {
      assert.equal(resolveCredentials().token, 'env:secret')
    } finally {
      delete process.env.OPENJS_CNA_TOKEN
    }
  })

  it('lets explicit overrides beat env', () => {
    process.env.OPENJS_CNA_TOKEN = 'env:secret'
    try {
      const creds = resolveCredentials({ overrides: { token: 'cli:secret' } })
      assert.equal(creds.token, 'cli:secret')
    } finally {
      delete process.env.OPENJS_CNA_TOKEN
    }
  })

  it('lets explicit overrides beat config', () => {
    setConfigValue('openjs_cna_base_url', 'https://config')
    const creds = resolveCredentials({ overrides: { baseUrl: 'https://cli' } })
    assert.equal(creds.baseUrl, 'https://cli')
  })
})
