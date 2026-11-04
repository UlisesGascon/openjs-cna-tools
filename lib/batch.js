// Review and publish several CVE Records in one go.
//
// This is the "all or none" flow a release pipeline wants: every record is
// reviewed first and nothing is sent unless all of them pass. Publication
// itself is best effort per record, since MITRE has no batch operation and
// the records are independent; a failed id is reported and the rest still
// go out. `--skip-published` style reruns are supported by asking the CNA
// whether an id already has a published container before sending it.
//
// Both functions take `entries`: an array of `{ record, file? }` where
// `record` is a full v5.2 CVE Record (`containers.cna` plus `cveMetadata`)
// and `file` is only used to label output. The CLI `review` and `publish`
// commands are thin wrappers over them.

import { reviewRecord } from './review/index.js'
import { CnaOperationError } from './errors.js'

function labelOf (entry) {
  return entry.record?.cveMetadata?.cveId ?? entry.file ?? '<record>'
}

/**
 * Review every entry. Never stops early, so the caller sees all problems at
 * once. A record without `cveMetadata.cveId` gets an extra blocker: in a
 * batch there is no CLI argument to fall back on for the id.
 *
 * Returns `[{ file, cveId, ready, summary, issues }]` in input order.
 */
export function reviewRecords (entries, { strict = true } = {}) {
  return entries.map((entry) => {
    const report = reviewRecord(entry.record, { strict })
    const cveId = entry.record?.cveMetadata?.cveId
    const issues = [...report.issues]
    const summary = { ...report.summary }
    if (!cveId) {
      issues.unshift({
        rule: 'cve-id-present',
        tier: 'mitre-common',
        severity: 'blocker',
        path: 'cveMetadata.cveId',
        message: 'Record carries no cveMetadata.cveId; batch publish needs one per record'
      })
      summary.blockers += 1
      summary.rating = 'blocked'
    }
    return {
      file: entry.file,
      cveId,
      ready: summary.blockers === 0,
      summary,
      issues
    }
  })
}

// `getCve` resolves with the container when MITRE has a published record.
// For a RESERVED id there is nothing to fetch and the CNA either fails the
// run or completes it with an empty result; neither is pinned down, so
// only positive evidence counts: an operational failure, or a result that
// does not look like a record, means "not published" and the id is sent.
// Erring towards publishing is the safe side, since the CNA rejects a
// second publish loudly while a wrong skip would exit 0 having sent
// nothing. Auth and timeout errors propagate so a broken setup does not
// look like a clean slate.
async function isPublished (client, cveId) {
  let result
  try {
    result = await client.getCve(cveId)
  } catch (error) {
    if (error instanceof CnaOperationError) return false
    throw error
  }
  const cna = result?.containers?.cna ?? result
  return result?.cveMetadata?.state === 'PUBLISHED' ||
    Array.isArray(cna?.descriptions) ||
    Array.isArray(cna?.affected)
}

/**
 * Review every entry, then publish each one through `client.publishCve`.
 *
 * Options:
 *   client        — a CnaClient (required unless every record is skipped)
 *   strict        — reviewer strictness (default true, warnings block)
 *   skipReview    — publish without reviewing (discouraged)
 *   skipPublished — ask the CNA first and skip ids already published
 *   onProgress    — called with `{ phase, cveId, file, status, ... }` as
 *                   each step completes, for CLI progress lines
 *
 * Returns `{ blocked, review, results }`. When `blocked` is true the review
 * found blockers, `results` is empty and nothing was sent. Otherwise
 * `results` has one `{ file, cveId, status, ... }` per entry, with status
 * `published`, `skipped` or `failed`, plus `correlationId` / `runId` when
 * the CNA returned them and `error` for failures.
 */
export async function publishRecords (entries, {
  client,
  strict = true,
  skipReview = false,
  skipPublished = false,
  onProgress = () => {}
} = {}) {
  const review = skipReview ? [] : reviewRecords(entries, { strict })
  if (review.some((item) => !item.ready)) {
    return { blocked: true, review, results: [] }
  }
  if (skipReview && entries.some((entry) => !entry.record?.cveMetadata?.cveId)) {
    throw new Error('Every record needs cveMetadata.cveId to be published in a batch')
  }

  const results = []
  for (const entry of entries) {
    const cveId = labelOf(entry)
    const base = { file: entry.file, cveId }
    let result
    if (skipPublished && await isPublished(client, cveId)) {
      result = { ...base, status: 'skipped', reason: 'already published' }
    } else {
      try {
        const response = await client.publishCve(cveId, entry.record.containers.cna)
        result = {
          ...base,
          status: 'published',
          correlationId: response.correlationId,
          runId: response.runId
        }
      } catch (error) {
        result = {
          ...base,
          status: 'failed',
          error: error.message,
          correlationId: error.correlationId,
          runId: error.runId
        }
      }
    }
    results.push(result)
    onProgress({ phase: 'publish', ...result })
  }
  return { blocked: false, review, results }
}
