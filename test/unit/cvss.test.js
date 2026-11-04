import { describe, it } from 'node:test'
import assert from 'node:assert/strict'

import {
  calculateBaseScore,
  parseCvssVector,
  roundUp,
  severityFromScore
} from '../../lib/cvss.js'

// Scores published by MITRE for the October 2026 Node.js release, used as
// ground truth for the calculator.
const PUBLISHED = [
  ['CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:H/A:N', 6.5, 'MEDIUM'],
  ['CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N', 7.4, 'HIGH'],
  ['CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N', 3.7, 'LOW'],
  ['CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:N/CR:M/IR:M/AR:M', 3.6, 'LOW'],
  ['CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:L', 6.7, 'MEDIUM'],
  ['CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N', 3.3, 'LOW'],
  ['CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N', 4.8, 'MEDIUM']
]

describe('calculateBaseScore', () => {
  it('matches scores MITRE published for Node.js CVEs', () => {
    for (const [vector, score, severity] of PUBLISHED) {
      const result = calculateBaseScore(vector)
      assert.equal(result.baseScore, score, vector)
      assert.equal(result.baseSeverity, severity, vector)
      assert.equal(result.version, '3.0')
      assert.equal(result.vectorString, vector)
    }
  })

  it('handles CVSS 3.1, scope changed and the extremes', () => {
    assert.deepEqual(
      calculateBaseScore('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H'),
      {
        version: '3.1',
        vectorString: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',
        baseScore: 10,
        baseSeverity: 'CRITICAL'
      }
    )
    assert.equal(calculateBaseScore('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H').baseScore, 9.8)
    assert.equal(calculateBaseScore('CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N').baseScore, 6.4)
    assert.deepEqual(
      calculateBaseScore('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N'),
      {
        version: '3.1',
        vectorString: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N',
        baseScore: 0,
        baseSeverity: 'NONE'
      }
    )
  })

  it('trims surrounding whitespace from the vector', () => {
    const result = calculateBaseScore('  CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H\n')
    assert.equal(result.vectorString, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H')
    assert.equal(result.baseScore, 9.8)
  })
})

describe('parseCvssVector', () => {
  it('rejects unsupported and malformed vectors', () => {
    assert.throws(() => parseCvssVector('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N'),
      /Unsupported CVSS vector/)
    assert.throws(() => parseCvssVector('AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'),
      /Unsupported CVSS vector/)
    assert.throws(() => parseCvssVector('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H'),
      /missing or has an invalid A metric/)
    assert.throws(() => parseCvssVector('CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'),
      /invalid AV metric/)
    assert.throws(() => parseCvssVector('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E'),
      /Malformed CVSS component/)
    assert.throws(() => parseCvssVector(''), /Unsupported CVSS vector/)
    assert.throws(() => parseCvssVector(undefined), /Unsupported CVSS vector/)
  })

  it('returns the version and every component, including temporal ones', () => {
    const parsed = parseCvssVector('CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:N/CR:M')
    assert.equal(parsed.version, '3.0')
    assert.equal(parsed.metrics.AV, 'L')
    assert.equal(parsed.metrics.CR, 'M')
  })
})

describe('roundUp', () => {
  it('follows the CVSS 3.1 specification', () => {
    assert.equal(roundUp(4), 4)
    assert.equal(roundUp(4.02), 4.1)
    assert.equal(roundUp(4.000001), 4)
    assert.equal(roundUp(3.562), 3.6)
  })
})

describe('severityFromScore', () => {
  it('maps the qualitative bands', () => {
    assert.equal(severityFromScore(0), 'NONE')
    assert.equal(severityFromScore(0.1), 'LOW')
    assert.equal(severityFromScore(3.9), 'LOW')
    assert.equal(severityFromScore(4), 'MEDIUM')
    assert.equal(severityFromScore(6.9), 'MEDIUM')
    assert.equal(severityFromScore(7), 'HIGH')
    assert.equal(severityFromScore(8.9), 'HIGH')
    assert.equal(severityFromScore(9), 'CRITICAL')
  })
})
