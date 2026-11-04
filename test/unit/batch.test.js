import { describe, it } from 'node:test'
import assert from 'node:assert/strict'

import { publishRecords, reviewRecords } from '../../lib/batch.js'
import { CnaAuthError, CnaOperationError } from '../../lib/errors.js'
import { buildCvssMetric, buildRecordEnvelope } from '../../lib/record.js'

// A record that passes the strict reviewer, so tests only break it on
// purpose.
function goodRecord (cveId = 'CVE-2026-0001') {
  return buildRecordEnvelope({
    cveId,
    cna: {
      title: 'demo: vulnerable to demonstration',
      descriptions: [{
        lang: 'en',
        value: 'The demo package before 1.2.3 accepts an unbounded request body when parsing ' +
          'multipart uploads, so a remote attacker can exhaust process memory with a single ' +
          'crafted request and take the service down. Version 1.2.3 caps the body size and ' +
          'rejects oversized uploads with a 413 response.'
      }],
      affected: [{
        vendor: 'npm',
        product: 'demo',
        defaultStatus: 'unaffected',
        versions: [{ version: '0', lessThan: '1.2.3', status: 'affected', versionType: 'semver' }]
      }],
      problemTypes: [{ descriptions: [{ lang: 'en', cweId: 'CWE-400', type: 'CWE', description: 'CWE-400' }] }],
      metrics: [buildCvssMetric('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H')],
      credits: [
        { lang: 'en', type: 'reporter', value: 'reporter-handle' },
        { lang: 'en', type: 'remediation developer', value: 'fix-handle' }
      ],
      references: [{ url: 'https://example.com/advisory' }]
    }
  })
}

function entries (...ids) {
  return ids.map((cveId) => ({ file: `records/${cveId}.json`, record: goodRecord(cveId) }))
}

// Fake client: `script` maps a cveId to what publishCve should do,
// `published` lists ids getCve should answer with a container, and
// `getResults` overrides what getCve resolves with per id.
function fakeClient ({ script = {}, published = [], getResults = {} } = {}) {
  const calls = []
  return {
    calls,
    async getCve (cveId) {
      calls.push(['getCve', cveId])
      if (cveId in getResults) return getResults[cveId]
      if (published.includes(cveId)) return goodRecord(cveId).containers.cna
      throw new CnaOperationError(`get-cve failed for ${cveId}`, { conclusion: 'failure' })
    },
    async publishCve (cveId, container) {
      calls.push(['publishCve', cveId, container])
      const outcome = script[cveId]
      if (outcome instanceof Error) throw outcome
      return outcome ?? { correlationId: `corr-${cveId}`, runId: 1 }
    }
  }
}

describe('reviewRecords', () => {
  it('reviews every entry and reports them in order', () => {
    const list = entries('CVE-2026-0001', 'CVE-2026-0002')
    list[1].record.containers.cna.metrics[0].cvssV3_1.vectorString = 'totally bogus'
    const review = reviewRecords(list)
    assert.deepEqual(review.map((r) => [r.file, r.cveId, r.ready]), [
      ['records/CVE-2026-0001.json', 'CVE-2026-0001', true],
      ['records/CVE-2026-0002.json', 'CVE-2026-0002', false]
    ])
    assert.equal(review[0].summary.blockers, 0)
    assert.ok(review[1].issues.some((i) => i.rule === 'cvss-vector-parseable'))
  })

  it('blocks a record without a CVE id', () => {
    const [entry] = entries('CVE-2026-0001')
    delete entry.record.cveMetadata
    const [review] = reviewRecords([entry])
    assert.equal(review.cveId, undefined)
    assert.equal(review.ready, false)
    assert.equal(review.summary.rating, 'blocked')
    assert.equal(review.issues[0].rule, 'cve-id-present')
  })

  it('passes strictness through to the reviewer', () => {
    const [entry] = entries('CVE-2026-0001')
    delete entry.record.containers.cna.credits
    assert.equal(reviewRecords([entry]).at(0).ready, false)
    assert.equal(reviewRecords([entry], { strict: false }).at(0).ready, true)
  })
})

describe('publishRecords', () => {
  it('publishes nothing when any record has a blocker', async () => {
    const list = entries('CVE-2026-0001', 'CVE-2026-0002')
    list[1].record.containers.cna.affected = []
    const client = fakeClient()
    const outcome = await publishRecords(list, { client })
    assert.equal(outcome.blocked, true)
    assert.deepEqual(outcome.results, [])
    assert.deepEqual(outcome.review.map((r) => r.ready), [true, false])
    assert.deepEqual(client.calls, [])
  })

  it('publishes each record and keeps going after a failure', async () => {
    const list = entries('CVE-2026-0001', 'CVE-2026-0002', 'CVE-2026-0003')
    const failure = new CnaOperationError('Run x concluded with failure', { correlationId: 'corr-x', runId: 7 })
    const client = fakeClient({ script: { 'CVE-2026-0002': failure } })
    const progress = []
    const outcome = await publishRecords(list, { client, onProgress: (e) => progress.push(e.status) })
    assert.equal(outcome.blocked, false)
    assert.deepEqual(outcome.results, [
      { file: 'records/CVE-2026-0001.json', cveId: 'CVE-2026-0001', status: 'published', correlationId: 'corr-CVE-2026-0001', runId: 1 },
      { file: 'records/CVE-2026-0002.json', cveId: 'CVE-2026-0002', status: 'failed', error: 'Run x concluded with failure', correlationId: 'corr-x', runId: 7 },
      { file: 'records/CVE-2026-0003.json', cveId: 'CVE-2026-0003', status: 'published', correlationId: 'corr-CVE-2026-0003', runId: 1 }
    ])
    assert.deepEqual(progress, ['published', 'failed', 'published'])
    assert.deepEqual(client.calls.map((c) => c[1]), ['CVE-2026-0001', 'CVE-2026-0002', 'CVE-2026-0003'])
    assert.deepEqual(client.calls[0][2], list[0].record.containers.cna)
  })

  it('skips ids the CNA already has when skipPublished is set', async () => {
    const list = entries('CVE-2026-0001', 'CVE-2026-0002')
    const client = fakeClient({ published: ['CVE-2026-0001'] })
    const outcome = await publishRecords(list, { client, skipPublished: true })
    assert.deepEqual(outcome.results.map((r) => [r.cveId, r.status, r.reason]), [
      ['CVE-2026-0001', 'skipped', 'already published'],
      ['CVE-2026-0002', 'published', undefined]
    ])
    assert.deepEqual(client.calls.map((c) => c.slice(0, 2)), [
      ['getCve', 'CVE-2026-0001'],
      ['getCve', 'CVE-2026-0002'],
      ['publishCve', 'CVE-2026-0002']
    ])
  })

  it('only skips when the published check answers with something record-shaped', async () => {
    const list = entries('CVE-2026-0001', 'CVE-2026-0002', 'CVE-2026-0003', 'CVE-2026-0004')
    const client = fakeClient({
      getResults: {
        'CVE-2026-0001': {},
        'CVE-2026-0002': null,
        'CVE-2026-0003': { error: 'not found' },
        'CVE-2026-0004': goodRecord('CVE-2026-0004')
      }
    })
    const outcome = await publishRecords(list, { client, skipPublished: true })
    assert.deepEqual(outcome.results.map((r) => [r.cveId, r.status]), [
      ['CVE-2026-0001', 'published'],
      ['CVE-2026-0002', 'published'],
      ['CVE-2026-0003', 'published'],
      ['CVE-2026-0004', 'skipped']
    ])
  })

  it('does not treat auth failures on the published check as "not published"', async () => {
    const list = entries('CVE-2026-0001')
    const client = fakeClient()
    client.getCve = async () => { throw new CnaAuthError('bad token', { status: 401 }) }
    await assert.rejects(publishRecords(list, { client, skipPublished: true }), CnaAuthError)
    assert.deepEqual(client.calls, [])
  })

  it('with skipReview still requires a CVE id on every record', async () => {
    const [entry] = entries('CVE-2026-0001')
    delete entry.record.cveMetadata
    await assert.rejects(publishRecords([entry], { client: fakeClient(), skipReview: true }), /needs cveMetadata.cveId/)
  })
})
