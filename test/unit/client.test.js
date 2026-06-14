import { describe, it } from 'node:test'
import assert from 'node:assert/strict'

import {
  CnaClient,
  CnaAuthError,
  CnaTimeoutError,
  CnaOperationError
} from '../../lib/index.js'

const CREDS = {
  token: 'test_nodejs:0123456789abcdef',
  baseUrl: 'https://worker.example.workers.dev'
}

// Build a fetch stub that returns a programmed sequence of Response-like
// objects. Each entry can be a Response-shaped value or a function returning
// one. Calls beyond the programmed length throw.
const stubFetch = (queue) => {
  let i = -1
  return async (url, opts) => {
    i += 1
    if (i >= queue.length) {
      throw new Error(`fetch stub exhausted (call ${i + 1} for ${url})`)
    }
    const entry = queue[i]
    return typeof entry === 'function' ? entry(url, opts) : entry
  }
}

const okJson = (body, status = 200) => ({
  ok: status < 400,
  status,
  json: async () => body
})

describe('CnaClient construction', () => {
  it('does no I/O in the constructor', () => {
    // If the constructor touched the network or fs, it would throw because
    // the global fetch is unset for this test scope.
    const client = new CnaClient() // no token, no baseUrl, no fetch
    assert.ok(client instanceof CnaClient)
  })

  it('throws CnaAuthError when accessing the token without one configured', () => {
    const client = new CnaClient()
    assert.throws(() => client.token, CnaAuthError)
  })

  it('throws CnaAuthError when accessing the baseUrl without one configured', () => {
    const client = new CnaClient()
    assert.throws(() => client.baseUrl, CnaAuthError)
  })

  it('strips trailing slash from baseUrl', () => {
    const client = new CnaClient({ token: 'a:b', baseUrl: 'https://foo.com/' })
    assert.equal(client.baseUrl, 'https://foo.com')
  })
})

describe('CnaClient.dispatch', () => {
  it('POSTs /dispatch with bearer token and JSON body', async () => {
    let captured
    const client = new CnaClient({
      ...CREDS,
      fetch: async (url, opts) => {
        captured = { url, opts }
        return okJson({ correlation_id: 'abc-123', status: 'queued' })
      }
    })
    const result = await client.dispatch('reserve-cve', { foo: 'bar' })
    assert.deepEqual(result, { correlation_id: 'abc-123', status: 'queued' })
    assert.equal(captured.url, 'https://worker.example.workers.dev/dispatch')
    assert.equal(captured.opts.method, 'POST')
    assert.equal(captured.opts.headers.Authorization, 'Bearer test_nodejs:0123456789abcdef')
    assert.deepEqual(JSON.parse(captured.opts.body), {
      operation: 'reserve-cve',
      inputs: { foo: 'bar' }
    })
  })

  it('throws CnaAuthError on 401', async () => {
    const client = new CnaClient({
      ...CREDS,
      fetch: async () => okJson({ error: 'unauthorized' }, 401)
    })
    await assert.rejects(() => client.dispatch('reserve-cve'), CnaAuthError)
  })

  it('throws CnaOperationError when the Worker returns an error envelope', async () => {
    const client = new CnaClient({
      ...CREDS,
      fetch: async () => okJson({ error: 'unknown_operation' })
    })
    await assert.rejects(
      () => client.dispatch('do-the-thing'),
      (err) => err instanceof CnaOperationError && /unknown_operation/.test(err.message)
    )
  })
})

describe('CnaClient.waitForCompletion', () => {
  it('returns the run object on completed+success', async () => {
    const queue = [
      okJson({ status: 'in_progress' }),
      okJson({
        status: 'completed',
        conclusion: 'success',
        run_id: 42,
        url: 'https://github.com/.../runs/42',
        result: { cve_id: 'CVE-2026-1234' }
      })
    ]
    const client = new CnaClient({ ...CREDS, fetch: stubFetch(queue) })
    const run = await client.waitForCompletion('abc', { timeoutMs: 1000, intervalMs: 5 })
    assert.equal(run.run_id, 42)
    assert.deepEqual(run.result, { cve_id: 'CVE-2026-1234' })
  })

  it('throws CnaOperationError on conclusion=failure', async () => {
    const client = new CnaClient({
      ...CREDS,
      fetch: async () => okJson({
        status: 'completed',
        conclusion: 'failure',
        url: 'https://...'
      })
    })
    await assert.rejects(
      () => client.waitForCompletion('abc', { timeoutMs: 100, intervalMs: 5 }),
      CnaOperationError
    )
  })

  it('throws CnaTimeoutError when no completion before deadline', async () => {
    const client = new CnaClient({
      ...CREDS,
      fetch: async () => okJson({ status: 'in_progress' })
    })
    await assert.rejects(
      () => client.waitForCompletion('abc', { timeoutMs: 30, intervalMs: 5 }),
      CnaTimeoutError
    )
  })

  it('honors AbortSignal', async () => {
    const controller = new AbortController()
    const client = new CnaClient({
      ...CREDS,
      fetch: async () => {
        // Trigger abort during the first poll cycle so the abort check at
        // the top of the next iteration fires.
        controller.abort()
        return okJson({ status: 'in_progress' })
      }
    })
    await assert.rejects(
      () => client.waitForCompletion('abc', {
        timeoutMs: 5000, intervalMs: 5, signal: controller.signal
      }),
      (err) => err.name === 'AbortError'
    )
  })

  it('fires onPoll on each poll cycle', async () => {
    const seen = []
    const queue = [
      okJson({ status: 'in_progress' }),
      okJson({ status: 'completed', conclusion: 'success', run_id: 1, url: 'u' })
    ]
    const client = new CnaClient({ ...CREDS, fetch: stubFetch(queue) })
    await client.waitForCompletion('abc', {
      timeoutMs: 1000,
      intervalMs: 5,
      onPoll: (run) => seen.push(run.status)
    })
    assert.deepEqual(seen, ['in_progress', 'completed'])
  })
})

describe('CnaClient high-level operations', () => {
  it('reserveCve returns the cve_id', async () => {
    const queue = [
      okJson({ correlation_id: 'r1', status: 'queued' }),
      okJson({
        status: 'completed',
        conclusion: 'success',
        run_id: 7,
        url: 'u',
        result: { cve_id: 'CVE-2026-1234' }
      })
    ]
    const client = new CnaClient({ ...CREDS, fetch: stubFetch(queue) })
    const result = await client.reserveCve({ timeoutMs: 1000, intervalMs: 5 })
    assert.equal(result.cveId, 'CVE-2026-1234')
  })

  it('reserveCve throws CnaOperationError if the result has no cve_id', async () => {
    const queue = [
      okJson({ correlation_id: 'r1', status: 'queued' }),
      okJson({
        status: 'completed',
        conclusion: 'success',
        run_id: 7,
        url: 'u',
        result: { wat: true }
      })
    ]
    const client = new CnaClient({ ...CREDS, fetch: stubFetch(queue) })
    await assert.rejects(
      () => client.reserveCve({ timeoutMs: 1000, intervalMs: 5 }),
      (err) => err instanceof CnaOperationError && /no cve_id/.test(err.message)
    )
  })

  it('publishCve sends cve_id and cnaContainer in the dispatch body', async () => {
    let captured
    const queue = [
      (url, opts) => {
        if (url.endsWith('/dispatch')) {
          captured = JSON.parse(opts.body)
          return okJson({ correlation_id: 'p1', status: 'queued' })
        }
        return okJson({ status: 'in_progress' })
      },
      okJson({
        status: 'completed',
        conclusion: 'success',
        run_id: 8,
        url: 'u',
        result: { published: true }
      })
    ]
    const client = new CnaClient({ ...CREDS, fetch: stubFetch(queue) })
    const container = { descriptions: [{ lang: 'en', value: 'x' }] }
    await client.publishCve('CVE-2026-9999', container, { timeoutMs: 1000, intervalMs: 5 })
    assert.equal(captured.operation, 'publish-cve')
    assert.equal(captured.inputs.cve_id, 'CVE-2026-9999')
    assert.deepEqual(captured.inputs.cnaContainer, container)
  })

  it('listCves accepts both result shapes', async () => {
    // Shape 1: { cve_ids: [...] }
    let client = new CnaClient({
      ...CREDS,
      fetch: stubFetch([
        okJson({ correlation_id: 'l1', status: 'queued' }),
        okJson({
          status: 'completed',
          conclusion: 'success',
          run_id: 1,
          url: 'u',
          result: { cve_ids: ['CVE-A', 'CVE-B'] }
        })
      ])
    })
    assert.deepEqual(await client.listCves({ timeoutMs: 1000, intervalMs: 5 }), ['CVE-A', 'CVE-B'])

    // Shape 2: direct array
    client = new CnaClient({
      ...CREDS,
      fetch: stubFetch([
        okJson({ correlation_id: 'l2', status: 'queued' }),
        okJson({
          status: 'completed',
          conclusion: 'success',
          run_id: 2,
          url: 'u',
          result: ['CVE-X']
        })
      ])
    })
    assert.deepEqual(await client.listCves({ timeoutMs: 1000, intervalMs: 5 }), ['CVE-X'])
  })
})

describe('CnaClient.poll', () => {
  it('maps a 502 run_result_unavailable to CnaOperationError', async () => {
    const client = new CnaClient({
      ...CREDS,
      fetch: async () => okJson({
        error: 'run_result_unavailable',
        message: 'no marker',
        run_id: 99
      }, 502)
    })
    await assert.rejects(
      () => client.poll('abc'),
      (err) => err instanceof CnaOperationError && err.runId === 99
    )
  })
})
