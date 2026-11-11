// CnaClient — the transport layer for the OpenJS Foundation CNA API.
//
// The CNA API is a thin edge in front of a `workflow_dispatch`-backed GitHub
// Actions workflow. POST /dispatch returns a Worker-minted correlation_id;
// GET /runs/{id} polls the backing run and, once it completes, returns the
// operation's structured result extracted from the job log.
//
// Two layers:
//
//   * High-level methods (`reserveCve`, `publishCve`, `getCve`, `listCves`,
//     `updateCve`, `health`) dispatch, wait for completion, throw on failure,
//     and return the operation result.
//
//   * Low-level methods (`dispatch`, `poll`, `waitForCompletion`) expose the
//     three primitives for callers that want to bridge polling externally
//     (UIs, queues, retries, custom progress reporting).
//
// The constructor is non-allocating — no network, no fs, no subprocess. Token
// and base-url validation is deferred until the first operation (the
// self-replacing-getter pattern from node-core-utils).

import { createRequire } from 'node:module'
import {
  CnaAuthError,
  CnaTimeoutError,
  CnaOperationError
} from './errors.js'

const require = createRequire(import.meta.url)
const pkg = require('../package.json')

// Single identity string used as the User-Agent on every outbound HTTP
// request AND as `cna.x_generator.engine` on every container we publish.
// Pinning both to the same string means a downstream reader of a CVE
// record can find the exact `openjs-cna-tools <version>` that produced
// the call.
export const USER_AGENT = `${pkg.name} ${pkg.version}`

const DEFAULT_TIMEOUT_MS = 600_000 // 10 minutes; matches NCU's choice
const DEFAULT_POLL_INTERVAL_MS = 5_000

export class CnaClient {
  constructor ({ token, baseUrl, timeoutMs, pollIntervalMs, fetch: fetchImpl } = {}) {
    this._token = token
    this._baseUrl = baseUrl
    this._timeoutMs = timeoutMs ?? DEFAULT_TIMEOUT_MS
    this._pollIntervalMs = pollIntervalMs ?? DEFAULT_POLL_INTERVAL_MS
    // Injectable for tests; defaults to the runtime's global fetch.
    this._fetch = fetchImpl ?? globalThis.fetch
  }

  // Lazy validation. Reading `client.token` once is the only time we check
  // the configuration. Re-reads pay no cost; missing-token failures throw at
  // the exact moment the caller is about to make a network call, which is
  // also the moment the operator can act on the error.
  get token () {
    if (!this._token) {
      throw new CnaAuthError(
        'OPENJS_CNA_TOKEN is not configured. Run:\n' +
        '  openjs-cna-experimental config set -x openjs_cna_token "<bucket>:<hex-secret>"\n' +
        'or pass --token / set OPENJS_CNA_TOKEN in the environment.'
      )
    }
    return this._token
  }

  get baseUrl () {
    if (!this._baseUrl) {
      throw new CnaAuthError(
        'OPENJS_CNA_BASE_URL is not configured. Run:\n' +
        '  openjs-cna-experimental config set openjs_cna_base_url "https://cna.openjsf.org"\n' +
        'or pass --base-url / set OPENJS_CNA_BASE_URL in the environment.'
      )
    }
    return this._baseUrl.replace(/\/$/, '')
  }

  _authHeaders () {
    return {
      Authorization: `Bearer ${this.token}`,
      Accept: 'application/json',
      'User-Agent': USER_AGENT
    }
  }

  // Unauthenticated liveness probe. Useful for `openjs-cna-experimental health` and for
  // catching base-url misconfiguration without burning a workflow dispatch.
  async health () {
    const res = await this._fetch(`${this.baseUrl}/health`, {
      headers: { 'User-Agent': USER_AGENT }
    })
    if (!res.ok) {
      throw new CnaOperationError(`Health check failed: ${res.status} ${res.statusText}`)
    }
    return res.json()
  }

  // Low-level: POST /dispatch. Returns { correlation_id, status } from the
  // Worker. Throws CnaAuthError on 401 so the CLI can map to exit 2.
  async dispatch (operation, inputs = {}) {
    const res = await this._fetch(`${this.baseUrl}/dispatch`, {
      method: 'POST',
      headers: { ...this._authHeaders(), 'Content-Type': 'application/json' },
      body: JSON.stringify({ operation, inputs })
    })
    if (res.status === 401) {
      throw new CnaAuthError(
        'The CNA API rejected the bearer token (401). Check that ' +
        '`openjs_cna_token` matches the bucket your CNA coordinator provisioned.',
        { status: 401 }
      )
    }
    let body
    try {
      body = await res.json()
    } catch (e) {
      throw new CnaOperationError(
        `Dispatch returned non-JSON response (${res.status}): ${e.message}`
      )
    }
    if (body?.error) {
      throw new CnaOperationError(`Dispatch failed (${operation}): ${body.error}`)
    }
    return body
  }

  // Low-level: GET /runs/{id}. Returns the run object, possibly with a
  // `result` field when the workflow has completed successfully.
  async poll (correlationId) {
    const res = await this._fetch(`${this.baseUrl}/runs/${correlationId}`, {
      headers: this._authHeaders()
    })
    if (res.status === 401) {
      throw new CnaAuthError('CNA API rejected the bearer token (401)', { status: 401 })
    }
    // 502 run_result_unavailable: completed+success but the Worker could not
    // extract the marker block. Surface as an operation error with the run
    // metadata still attached so the CLI can suggest `openjs-cna-experimental runs <id>`.
    if (res.status === 502) {
      const body = await res.json().catch(() => ({}))
      throw new CnaOperationError(
        body?.message ?? `CNA API returned 502 for run ${correlationId}`,
        {
          correlationId,
          runId: body?.run_id
        }
      )
    }
    return res.json()
  }

  // Poll until the run completes. Throws on timeout, on a non-success
  // conclusion, or on AbortSignal cancellation. `onPoll` lets callers update
  // a progress UI without owning the polling loop.
  async waitForCompletion (correlationId, opts = {}) {
    const {
      timeoutMs = this._timeoutMs,
      intervalMs = this._pollIntervalMs,
      signal,
      onPoll
    } = opts
    const deadline = Date.now() + timeoutMs
    while (Date.now() < deadline) {
      if (signal?.aborted) throw new DOMException('aborted', 'AbortError')
      const run = await this.poll(correlationId)
      if (typeof onPoll === 'function') onPoll(run)
      if (run.status === 'completed') {
        if (run.conclusion !== 'success') {
          throw new CnaOperationError(
            `Run ${correlationId} concluded with '${run.conclusion}'. ` +
            'Forward correlation_id and run_id to your CNA coordinator for inspection.',
            {
              correlationId,
              runId: run.run_id,
              conclusion: run.conclusion,
              result: run.result
            }
          )
        }
        return run
      }
      await new Promise(resolve => setTimeout(resolve, intervalMs))
    }
    throw new CnaTimeoutError(
      `Run ${correlationId} did not complete within ${timeoutMs}ms`,
      { correlationId, timeoutMs }
    )
  }

  // Internal: dispatch + wait. Every high-level method funnels through here.
  async _runAndWait (operation, inputs, opts) {
    const dispatched = await this.dispatch(operation, inputs)
    const run = await this.waitForCompletion(dispatched.correlation_id, opts)
    return { ...run, correlationId: dispatched.correlation_id }
  }

  // ----- High-level operations -----

  async reserveCve (opts = {}) {
    const run = await this._runAndWait('reserve-cve', {}, opts)
    const cveId = run.result?.cve_id
    if (!cveId) {
      throw new CnaOperationError(
        'reserve-cve completed but no cve_id in the result. ' +
        'Forward correlation_id and run_id to your CNA coordinator.',
        {
          correlationId: run.correlationId,
          runId: run.run_id,
          result: run.result
        }
      )
    }
    return { cveId, correlationId: run.correlationId, runId: run.run_id, run }
  }

  async publishCve (cveId, container, opts = {}) {
    const run = await this._runAndWait('publish-cve', {
      cve_id: cveId,
      cnaContainer: container
    }, opts)
    return { correlationId: run.correlationId, runId: run.run_id, run, result: run.result }
  }

  async updateCve (cveId, container, opts = {}) {
    const run = await this._runAndWait('update-cve', {
      cve_id: cveId,
      cnaContainer: container
    }, opts)
    return { correlationId: run.correlationId, runId: run.run_id, run, result: run.result }
  }

  async getCve (cveId, opts = {}) {
    const run = await this._runAndWait('get-cve', { cve_id: cveId }, opts)
    return run.result
  }

  async listCves (opts = {}) {
    const run = await this._runAndWait('list-cve', {}, opts)
    // Accepted result shapes:
    //   * { cve_ids: [...] }  — array of ids
    //   * [ ... ]              — direct array of ids, or of MITRE record
    //                            stubs ({ cveMetadata: { cveId, state } }),
    //                            which is what the workflow emits today
    // Always resolves to plain CVE id strings.
    const entries = run.result?.cve_ids ?? (Array.isArray(run.result) ? run.result : [])
    return entries.map(listedCveId).filter(Boolean)
  }
}

function listedCveId (entry) {
  const id = entry?.cveMetadata?.cveId ?? entry?.cveId ?? entry?.cve_id ?? entry
  return typeof id === 'string' ? id.trim() : ''
}
