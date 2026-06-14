import { describe, it } from 'node:test'
import assert from 'node:assert/strict'

import { buildAuditPrompt } from '../../lib/prompt.js'

// Minimal CVE Record fixture for the prompt builder. Tests mutate
// `r.containers.cna.*` to focus on individual fields.
const sampleRecord = () => ({
  dataType: 'CVE_RECORD',
  dataVersion: '5.2',
  cveMetadata: {
    cveId: 'CVE-2026-3520',
    assignerOrgId: 'ce714d77-add3-4f53-aff5-83d477b104bb',
    state: 'PUBLISHED'
  },
  containers: {
    cna: {
      title: 'multer vulnerable to Denial of Service via uncontrolled recursion',
      descriptions: [{
        lang: 'en',
        value: 'Impact:\n\nA vulnerability in multer allows DoS.\n\nPatches:\n\nUpgrade to 2.1.1.',
        supportingMedia: [{
          type: 'text/markdown',
          base64: false,
          value: '### Impact\n\nA vulnerability in multer allows DoS.\n\n### Patches\n\nUpgrade to `2.1.1`.'
        }]
      }],
      affected: [{
        vendor: 'npm',
        product: 'multer',
        versions: [{ version: '0', lessThan: '2.1.1', status: 'affected', versionType: 'semver' }]
      }],
      problemTypes: [{ descriptions: [{ lang: 'en', cweId: 'CWE-674', type: 'CWE' }] }],
      metrics: [{
        format: 'CVSS',
        cvssV4_0: {
          version: '4.0',
          vectorString: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N',
          baseScore: 8.7,
          baseSeverity: 'HIGH'
        }
      }]
    }
  }
})

describe('buildAuditPrompt — structure', () => {
  it('includes the editorial guideline headings', () => {
    const out = buildAuditPrompt(sampleRecord())
    assert.match(out, /Editorial guidelines/)
    assert.match(out, /\*\*Title\*\*/)
    assert.match(out, /\*\*Description\*\*/)
  })

  it('quotes the title and the plain-text description verbatim', () => {
    const out = buildAuditPrompt(sampleRecord())
    assert.ok(out.includes('multer vulnerable to Denial of Service via uncontrolled recursion'))
    assert.ok(out.includes('A vulnerability in multer allows DoS.'))
  })

  it('embeds the supportingMedia Markdown block when present', () => {
    const out = buildAuditPrompt(sampleRecord())
    assert.match(out, /original Markdown/)
    assert.ok(out.includes('### Impact'))
    assert.ok(out.includes('Upgrade to `2.1.1`'))
  })

  it('omits the Markdown block when supportingMedia is absent', () => {
    const r = sampleRecord()
    delete r.containers.cna.descriptions[0].supportingMedia
    const out = buildAuditPrompt(r)
    assert.ok(!/original Markdown/.test(out))
  })

  it('includes the facts block (CVE, affected, CVSS, CWE)', () => {
    const out = buildAuditPrompt(sampleRecord())
    assert.match(out, /CVE-2026-3520/)
    assert.match(out, /npm:multer \(0 → < 2\.1\.1\)/)
    assert.match(out, /\*\*CVSS 4\.0\*\*: 8\.7 HIGH/)
    assert.match(out, /CWE-674/)
  })

  it('asks for a Markdown response shape with Rating + Issues', () => {
    const out = buildAuditPrompt(sampleRecord())
    assert.match(out, /Respond in this exact Markdown shape/)
    assert.match(out, /\*\*Rating\*\*: ready \| needs-work \| blocked/)
    assert.match(out, /### Issues/)
  })

  it('flags PoCs / em-dashes / URLs-in-prose explicitly', () => {
    const out = buildAuditPrompt(sampleRecord())
    assert.match(out, /No raw PoCs/i)
    assert.match(out, /No em-dashes/i)
    assert.match(out, /URLs do \*\*not\*\* belong in the description prose/i)
  })
})

describe('buildAuditPrompt — robustness', () => {
  it('does not throw on a near-empty record', () => {
    assert.doesNotThrow(() => buildAuditPrompt({ containers: { cna: {} } }))
  })

  it('uses "(no title)" / "(no description)" placeholders when fields are missing', () => {
    const out = buildAuditPrompt({ containers: { cna: {} } })
    assert.match(out, /\(no title\)/)
    assert.match(out, /\(no description\)/)
  })
})
