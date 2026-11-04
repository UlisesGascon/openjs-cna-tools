import { describe, it } from 'node:test'
import assert from 'node:assert/strict'

import { USER_AGENT } from '../../lib/client.js'
import { DATA_VERSION, buildCvssMetric, buildRecordEnvelope } from '../../lib/record.js'
import { reviewRecord } from '../../lib/review/index.js'
import { OPENJS_CNA_ORG_ID } from '../../lib/review/schema.js'

describe('buildCvssMetric', () => {
  it('computes score and severity for a v3.1 vector', () => {
    assert.deepEqual(buildCvssMetric('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H'), {
      format: 'CVSS',
      cvssV3_1: {
        version: '3.1',
        vectorString: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H',
        baseScore: 7.5,
        baseSeverity: 'HIGH'
      }
    })
  })

  it('picks the cvssV3_0 block for a v3.0 vector', () => {
    const metric = buildCvssMetric(' CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:H/A:N ')
    assert.deepEqual(Object.keys(metric), ['format', 'cvssV3_0'])
    assert.deepEqual(metric.cvssV3_0, {
      version: '3.0',
      vectorString: 'CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:H/A:N',
      baseScore: 6.5,
      baseSeverity: 'MEDIUM'
    })
  })

  it('keeps a provided score and derives its severity', () => {
    const metric = buildCvssMetric('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H', { baseScore: 9.9 })
    assert.equal(metric.cvssV3_1.baseScore, 9.9)
    assert.equal(metric.cvssV3_1.baseSeverity, 'CRITICAL')
  })

  it('emits a cvssV4_0 block with the given score and no computation', () => {
    const vector = 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N'
    assert.deepEqual(buildCvssMetric(vector, { baseScore: 8.7 }), {
      format: 'CVSS',
      cvssV4_0: { version: '4.0', vectorString: vector, baseScore: 8.7, baseSeverity: 'HIGH' }
    })
    assert.deepEqual(buildCvssMetric(vector), {
      format: 'CVSS',
      cvssV4_0: { version: '4.0', vectorString: vector }
    })
  })

  it('passes an unparseable vector through without a score', () => {
    assert.deepEqual(buildCvssMetric('CVSS:3.1/AV:N/AC:L'), {
      format: 'CVSS',
      cvssV3_1: { version: '3.1', vectorString: 'CVSS:3.1/AV:N/AC:L' }
    })
    assert.deepEqual(buildCvssMetric('totally bogus'), {
      format: 'CVSS',
      cvssV3_1: { version: '3.1', vectorString: 'totally bogus' }
    })
  })
})

describe('buildRecordEnvelope', () => {
  const cna = () => ({
    title: 'demo: vulnerable to demonstration',
    descriptions: [{ lang: 'en', value: 'A short description.' }],
    affected: [{
      vendor: 'npm',
      product: 'demo',
      defaultStatus: 'unaffected',
      versions: [{ version: '0', lessThan: '1.2.3', status: 'affected', versionType: 'semver' }]
    }],
    references: [{ url: 'https://example.com/a' }]
  })

  it('wraps the container with the OpenJS defaults', () => {
    const record = buildRecordEnvelope({ cveId: 'CVE-2026-0001', cna: cna() })
    assert.equal(record.dataType, 'CVE_RECORD')
    assert.equal(record.dataVersion, DATA_VERSION)
    assert.deepEqual(record.cveMetadata, {
      cveId: 'CVE-2026-0001',
      assignerOrgId: OPENJS_CNA_ORG_ID,
      state: 'PUBLISHED'
    })
    assert.deepEqual(record.containers.cna.providerMetadata, { orgId: OPENJS_CNA_ORG_ID })
    assert.deepEqual(record.containers.cna.x_generator, { engine: USER_AGENT })
    assert.equal(record.containers.cna.title, 'demo: vulnerable to demonstration')
  })

  it('omits cveMetadata without a CVE id', () => {
    const record = buildRecordEnvelope({ cna: cna() })
    assert.equal(record.cveMetadata, undefined)
  })

  it('honours overrides and container-provided metadata', () => {
    const container = { ...cna(), x_generator: { engine: 'custom-tool 1.2.3' } }
    const record = buildRecordEnvelope({
      cveId: 'CVE-2026-0001',
      cna: container,
      assignerOrgId: '00000000-0000-4000-8000-000000000000',
      engineId: 'ignored because the container has one'
    })
    assert.equal(record.cveMetadata.assignerOrgId, '00000000-0000-4000-8000-000000000000')
    assert.deepEqual(record.containers.cna.providerMetadata, { orgId: '00000000-0000-4000-8000-000000000000' })
    assert.deepEqual(record.containers.cna.x_generator, { engine: 'custom-tool 1.2.3' })
  })

  it('does not mutate the container it is given', () => {
    const container = cna()
    buildRecordEnvelope({ cveId: 'CVE-2026-0001', cna: container })
    assert.equal(container.providerMetadata, undefined)
    assert.equal(container.x_generator, undefined)
  })

  it('rejects a missing container', () => {
    assert.throws(() => buildRecordEnvelope({ cveId: 'CVE-2026-0001' }), TypeError)
  })

  it('produces a record that passes the MITRE schema check', () => {
    const container = {
      ...cna(),
      metrics: [buildCvssMetric('CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:H/A:N')]
    }
    const report = reviewRecord(buildRecordEnvelope({ cveId: 'CVE-2026-0001', cna: container }))
    assert.deepEqual(report.issues.filter(i => i.rule === 'mitre-schema'), [])
  })
})
