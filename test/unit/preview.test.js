import { describe, it } from 'node:test'
import assert from 'node:assert/strict'

import { renderPreview } from '../../lib/preview.js'
import { ENGINE_ID } from '../../lib/convert/ghsa.js'

// Helper: wrap a bare cna container in the full CVE Record shape that
// renderPreview expects. Tests can mutate the returned object's nested
// cna fields directly via `r.containers.cna.*`.
const wrap = (cna) => ({
  dataType: 'CVE_RECORD',
  dataVersion: '5.2',
  containers: { cna }
})

const singleCna = () => ({
  title: 'demo: vulnerable to demonstration',
  descriptions: [{ lang: 'en', value: 'A short description.' }],
  affected: [{
    vendor: 'npm',
    product: 'demo',
    defaultStatus: 'unaffected',
    versions: [{ version: '0', lessThan: '1.2.3', status: 'affected', versionType: 'semver' }]
  }],
  metrics: [{
    format: 'CVSS',
    cvssV3_1: {
      version: '3.1',
      vectorString: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H',
      baseScore: 7.5,
      baseSeverity: 'HIGH'
    }
  }],
  problemTypes: [{ descriptions: [{ lang: 'en', cweId: 'CWE-400', type: 'CWE' }] }],
  credits: [{ lang: 'en', type: 'reporter', value: 'reporter-handle' }],
  references: [{ url: 'https://example.com/a' }, { url: 'https://example.com/b' }],
  x_generator: { engine: ENGINE_ID }
})
const single = () => wrap(singleCna())

describe('renderPreview — single-package advisory', () => {
  it('renders all the main fields', () => {
    const text = renderPreview(single(), null)
    assert.match(text, /Title:.*demo: vulnerable to demonstration/)
    assert.match(text, /Description:.*A short description\./)
    assert.match(text, /Affected:.*npm:demo \(0 → < 1\.2\.3\)/)
    assert.match(text, /CVSS 3\.1:.*7\.5 HIGH/)
    assert.match(text, /CWE:.*CWE-400/)
    assert.match(text, /Credits:.*reporter: reporter-handle/)
    assert.match(text, /References:.*https:\/\/example\.com\/a/)
    // Every reference is listed on its own line (no "+N more" elision).
    assert.match(text, /https:\/\/example\.com\/b/)
    assert.match(text, /Generator:.*@ulisesgascon\/openjs-cna-tools/)
  })

  it('renders multi-line descriptions across multiple lines', () => {
    const r = single()
    r.containers.cna.descriptions[0].value = 'First line of the description.\nSecond line.\nThird line with detail.'
    const text = renderPreview(r, null)
    assert.match(text, /Description:.*First line of the description\./)
    assert.match(text, /Second line\./)
    assert.match(text, /Third line with detail\./)
  })

  it('omits sections that are absent', () => {
    const r = wrap({ title: 'demo' }) // only title
    const text = renderPreview(r, null)
    assert.match(text, /Title:.*demo/)
    assert.ok(!/CVSS/.test(text))
    assert.ok(!/CWE/.test(text))
    assert.ok(!/Credits/.test(text))
  })

  it('renders a cvssV3_0 metric', () => {
    const cna = singleCna()
    cna.metrics = [{
      format: 'CVSS',
      cvssV3_0: {
        version: '3.0',
        vectorString: 'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H',
        baseScore: 7.5,
        baseSeverity: 'HIGH'
      }
    }]
    const text = renderPreview(wrap(cna), null)
    assert.match(text, /CVSS 3\.0:.*7\.5 HIGH/)
  })
})

describe('renderPreview — multi-package advisory', () => {
  const multi = () => wrap({
    title: 'lodash family vulnerability',
    descriptions: [{ lang: 'en', value: 'Multiple packages affected.' }],
    affected: [
      { vendor: 'npm', product: 'lodash', versions: [{ version: '4.0.0', status: 'affected', versionType: 'semver' }] },
      { vendor: 'npm', product: 'lodash-amd', versions: [{ version: '4.0.0', status: 'affected', versionType: 'semver' }] },
      { vendor: 'npm', product: 'lodash-es', versions: [{ version: '4.0.0', status: 'affected', versionType: 'semver' }] },
      { vendor: 'npm', product: 'lodash.unset', versions: [{ version: '4.0.0', status: 'affected', versionType: 'semver' }] }
    ]
  })

  it('lists every affected package on its own line', () => {
    const text = renderPreview(multi(), null)
    assert.match(text, /npm:lodash /)
    assert.match(text, /npm:lodash-amd/)
    assert.match(text, /npm:lodash-es/)
    assert.match(text, /npm:lodash\.unset/)
  })

  it('renders every package when many are affected', () => {
    const r = multi()
    const cna = r.containers.cna
    // Pad up to 30 packages (lodash advisories routinely hit this).
    const baseNames = cna.affected.map(a => a.product)
    for (let i = 0; i < 26; i += 1) {
      cna.affected.push({
        vendor: 'npm',
        product: `lodash.method${i}`,
        versions: [{ version: '4.0.0', status: 'affected', versionType: 'semver' }]
      })
    }
    assert.equal(cna.affected.length, 30)
    const text = renderPreview(r, null)
    const allNames = [...baseNames, ...Array.from({ length: 26 }, (_, i) => `lodash.method${i}`)]
    for (const name of allNames) {
      assert.ok(text.includes(`npm:${name}`), `expected preview to contain npm:${name}`)
    }
  })
})

describe('renderPreview — version-range formatting', () => {
  it('shows "version → < X" for lessThan', () => {
    const r = single()
    r.containers.cna.affected[0].versions = [{ version: '0', lessThan: '1.2.3', status: 'affected', versionType: 'semver' }]
    const text = renderPreview(r, null)
    assert.match(text, /0 → < 1\.2\.3/)
  })

  it('shows "version → ≤ X" for lessThanOrEqual', () => {
    const r = single()
    r.containers.cna.affected[0].versions = [{ version: '0', lessThanOrEqual: '1.2.3', status: 'affected', versionType: 'semver' }]
    const text = renderPreview(r, null)
    assert.match(text, /0 → ≤ 1\.2\.3/)
  })

  it('shows just the version for a bare entry', () => {
    const r = single()
    r.containers.cna.affected[0].versions = [{ version: '4.0.0', status: 'affected', versionType: 'semver' }]
    const text = renderPreview(r, null)
    assert.match(text, /\(4\.0\.0\)/)
  })
})

describe('renderPreview — robustness', () => {
  it('does not throw on null or non-object input', () => {
    assert.doesNotThrow(() => renderPreview(null, null))
    assert.doesNotThrow(() => renderPreview('not-an-object', null))
  })
})
