import { describe, it, beforeEach, afterEach } from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'

import {
  getMergedConfig,
  setConfigValue,
  getConfigValue,
  deleteConfigValue,
  listConfig
} from '../../lib/config.js'

// Each test runs against its own throwaway XDG_CONFIG_HOME and CWD so
// the global and project layers are isolated from the developer's real
// machine.
let tmpRoot, savedXdg, savedCwd

beforeEach(() => {
  tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'cna-tools-config-'))
  savedXdg = process.env.XDG_CONFIG_HOME
  process.env.XDG_CONFIG_HOME = path.join(tmpRoot, 'xdg')
  fs.mkdirSync(process.env.XDG_CONFIG_HOME, { recursive: true })
  savedCwd = process.cwd()
  fs.mkdirSync(path.join(tmpRoot, 'project'), { recursive: true })
  process.chdir(path.join(tmpRoot, 'project'))
  // Strip env overrides that might leak from the real process env.
  delete process.env.OPENJS_CNA_TOKEN
  delete process.env.OPENJS_CNA_BASE_URL
})

afterEach(() => {
  process.chdir(savedCwd)
  if (savedXdg === undefined) delete process.env.XDG_CONFIG_HOME
  else process.env.XDG_CONFIG_HOME = savedXdg
  fs.rmSync(tmpRoot, { recursive: true, force: true })
})

describe('setConfigValue + getConfigValue (global scope, plaintext)', () => {
  it('writes and reads back a plaintext value', () => {
    setConfigValue('openjs_cna_base_url', 'https://cna.example.com')
    assert.equal(getConfigValue('openjs_cna_base_url'), 'https://cna.example.com')
  })

  it('persists across multiple gets', () => {
    setConfigValue('openjs_cna_base_url', 'https://cna.example.com')
    assert.equal(getConfigValue('openjs_cna_base_url'), 'https://cna.example.com')
    assert.equal(getConfigValue('openjs_cna_base_url'), 'https://cna.example.com')
  })

  it('returns undefined for an unknown key', () => {
    assert.equal(getConfigValue('does_not_exist'), undefined)
  })

  it('writes file with mode 0600', () => {
    const writePath = setConfigValue('openjs_cna_base_url', 'https://cna.example.com')
    const stat = fs.statSync(writePath)
    // POSIX: mode & 0o777 is the permission. Be tolerant of umask quirks
    // by checking that group and other bits are unset (the security
    // intent), rather than asserting exact 0600.
    assert.equal(stat.mode & 0o077, 0, 'group/other permissions should be unset')
  })
})

describe('deleteConfigValue', () => {
  it('removes a previously-set key and returns true', () => {
    setConfigValue('openjs_cna_base_url', 'https://cna.example.com')
    const removed = deleteConfigValue('openjs_cna_base_url')
    assert.equal(removed, true)
    assert.equal(getConfigValue('openjs_cna_base_url'), undefined)
  })

  it('returns false when the key was not present', () => {
    assert.equal(deleteConfigValue('does_not_exist'), false)
  })
})

describe('config layering', () => {
  it('project config overrides global', () => {
    setConfigValue('openjs_cna_base_url', 'https://global', { scope: 'global' })
    setConfigValue('openjs_cna_base_url', 'https://project', { scope: 'project' })
    assert.equal(getConfigValue('openjs_cna_base_url'), 'https://project')
  })

  it('env override beats both project and global', () => {
    setConfigValue('openjs_cna_base_url', 'https://global', { scope: 'global' })
    setConfigValue('openjs_cna_base_url', 'https://project', { scope: 'project' })
    process.env.OPENJS_CNA_BASE_URL = 'https://env'
    try {
      assert.equal(getConfigValue('openjs_cna_base_url'), 'https://env')
    } finally {
      delete process.env.OPENJS_CNA_BASE_URL
    }
  })

  it('forwards unmapped OPENJS_CNA_* env vars into the merged config', () => {
    process.env.OPENJS_CNA_DEBUG = 'true'
    try {
      const merged = getMergedConfig()
      assert.equal(merged.debug, 'true')
    } finally {
      delete process.env.OPENJS_CNA_DEBUG
    }
  })
})

describe('listConfig', () => {
  it('redacts secret-looking keys', () => {
    setConfigValue('openjs_cna_token', 'super-secret-token')
    setConfigValue('openjs_cna_base_url', 'https://cna.example.com')
    const list = listConfig()
    assert.equal(list.openjs_cna_token, '<redacted>')
    assert.equal(list.openjs_cna_base_url, 'https://cna.example.com')
  })
})
