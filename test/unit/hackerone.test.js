import { describe, it } from 'node:test'
import assert from 'node:assert/strict'

import {
  HACKERONE_WEAKNESSES_GENERATED,
  hackerOneWeakness,
  hackerOneWeaknessProblemType
} from '../../lib/hackerone/index.js'

describe('hackerOneWeakness', () => {
  it('maps a HackerOne weakness id to its CWE and name', () => {
    assert.deepEqual(hackerOneWeakness(26), { cwe: 'CWE-284', name: 'Improper Access Control - Generic' })
    assert.deepEqual(hackerOneWeakness('48'), { cwe: 'CWE-400', name: 'Uncontrolled Resource Consumption' })
    assert.deepEqual(hackerOneWeakness(' 28 '), { cwe: 'CWE-295', name: 'Improper Certificate Validation' })
  })

  it('keeps weaknesses that have no CWE on HackerOne, with cwe null', () => {
    assert.deepEqual(hackerOneWeakness(75), { cwe: null, name: 'Privilege Escalation' })
  })

  it('returns null for unknown or malformed ids', () => {
    assert.equal(hackerOneWeakness(999999999), null)
    assert.equal(hackerOneWeakness('CWE-284'), null)
    assert.equal(hackerOneWeakness(''), null)
    assert.equal(hackerOneWeakness(undefined), null)
  })

  it('ships generation metadata', () => {
    assert.match(HACKERONE_WEAKNESSES_GENERATED.date, /^\d{4}-\d{2}-\d{2}$/)
    assert.ok(HACKERONE_WEAKNESSES_GENERATED.entries > 1000)
    assert.ok(HACKERONE_WEAKNESSES_GENERATED.withCwe > 0)
  })
})

describe('hackerOneWeaknessProblemType', () => {
  it('builds the problemTypes entry with the CWE and HackerOne name', () => {
    assert.deepEqual(hackerOneWeaknessProblemType(26), {
      descriptions: [{ lang: 'en', type: 'CWE', cweId: 'CWE-284', description: 'Improper Access Control - Generic' }]
    })
  })

  it('returns null without a CWE to put on the record', () => {
    assert.equal(hackerOneWeaknessProblemType(75), null)
    assert.equal(hackerOneWeaknessProblemType(999999999), null)
  })
})
