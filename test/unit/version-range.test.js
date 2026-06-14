import { describe, it } from 'node:test'
import assert from 'node:assert/strict'

import { parseVersionRange } from '../../lib/convert/version-range.js'
import { VERSION_RANGE_MATRIX } from '../fixtures/version-range-matrix.js'

// Drives the entire test matrix at test/fixtures/version-range-matrix.js
// through the parser. Each case in the matrix is a one-shot assertion so a
// regression on a specific shape is named clearly in the failure output.
describe('parseVersionRange — driven by version-range-matrix.js', () => {
  for (const matrixCase of VERSION_RANGE_MATRIX) {
    it(`${matrixCase.category}: '${matrixCase.input}'`, () => {
      const actual = parseVersionRange(matrixCase.input)
      assert.deepEqual(actual, matrixCase.expected,
        `Mismatch for category '${matrixCase.category}'.\n` +
        `  input:    ${JSON.stringify(matrixCase.input)}\n` +
        `  expected: ${JSON.stringify(matrixCase.expected)}\n` +
        `  actual:   ${JSON.stringify(actual)}`
      )
    })
  }
})

// A handful of focused tests that go beyond the matrix — multi-segment
// outputs, defensive behavior on weird input.
describe('parseVersionRange — defensive behavior', () => {
  it('returns [] for empty string', () => {
    assert.deepEqual(parseVersionRange(''), [])
  })

  it('returns [] for whitespace-only', () => {
    assert.deepEqual(parseVersionRange('   \n\t  '), [])
  })

  it('returns [] for non-string input', () => {
    assert.deepEqual(parseVersionRange(null), [])
    assert.deepEqual(parseVersionRange(undefined), [])
    assert.deepEqual(parseVersionRange(42), [])
  })

  it('preserves segment order for multi-line ranges', () => {
    const result = parseVersionRange('< 6.24.0; 7.0.0 < 7.24.0; >= 8.0.0')
    assert.equal(result.length, 3)
    assert.equal(result[0].lessThan, '6.24.0')
    assert.equal(result[1].version, '7.0.0')
    assert.equal(result[2].version, '8.0.0')
  })
})
