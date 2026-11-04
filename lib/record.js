// Helpers for the parts of a v5.2 CVE Record that are about the record
// format rather than about where the data came from: the description, the
// CVSS metric block, the problem type and the record envelope. Converters
// (GHSA here, release trackers in downstream projects) build the container
// fields they know about and use these so the format-level details are
// written once.

import { USER_AGENT } from './client.js'
import { calculateBaseScore, severityFromScore } from './cvss.js'
import { OPENJS_CNA_ORG_ID } from './review/schema.js'

// MITRE schema version we emit on every Record. Matches what every CVE
// published by the OpenJS CNA carries today.
export const DATA_VERSION = '5.2'

/**
 * Strip Markdown formatting down to readable plain text. Generic: headers
 * become "Label:" lines (the published OpenJS CVE convention), emphasis,
 * code spans and links collapse to their text, list bullets and blockquote
 * markers drop, line endings normalise to `\n`.
 */
export function stripMarkdown (md) {
  if (typeof md !== 'string') return ''
  let text = md.replace(/\r\n/g, '\n').replace(/\r/g, '\n')
  // Headers → "Label:" (any ATX heading, level 1–6). [ \t]* rather than
  // \s* so the blank lines around the heading survive.
  text = text.replace(/^[ \t]*#{1,6}[ \t]+(.+?)[ \t]*$/gm, '$1:')
  // **bold** / __bold__ / *italic* / _italic_ → inner text
  text = text.replace(/\*\*(.+?)\*\*/g, '$1')
  text = text.replace(/__(.+?)__/g, '$1')
  text = text.replace(/(?<![*\w])\*(?!\s)(.+?)(?<!\s)\*(?![*\w])/g, '$1')
  text = text.replace(/(?<![_\w])_(?!\s)(.+?)(?<!\s)_(?![_\w])/g, '$1')
  // `inline code` → inner text
  text = text.replace(/`(.+?)`/g, '$1')
  // [link](url) → link
  text = text.replace(/\[(.+?)\]\([^)]+\)/g, '$1')
  // Bullet / ordered-list markers at line start → strip the marker
  text = text.replace(/^\s*(?:[-*+]|\d+\.)\s+/gm, '')
  // Blockquote markers
  text = text.replace(/^\s*>\s?/gm, '')
  // Collapse 3+ blank lines to a single blank line.
  text = text.replace(/\n{3,}/g, '\n\n')
  return text.trim()
}

/**
 * Build one `descriptions[]` entry from text that may carry Markdown.
 *
 * MITRE's `value` is plain text (NVD and cve.org show it verbatim), so the
 * Markdown is stripped for `value` and the original is kept in
 * `supportingMedia` as `text/markdown`, only when the two differ. Returns
 * `null` for empty input so callers can leave `descriptions` out.
 */
export function buildDescription (text, { lang = 'en' } = {}) {
  const raw = String(text ?? '').replace(/\r\n/g, '\n').replace(/\r/g, '\n').trim()
  if (!raw) return null
  const plain = stripMarkdown(raw) || raw
  const description = { lang, value: plain }
  if (raw !== plain) {
    description.supportingMedia = [{ type: 'text/markdown', base64: false, value: raw }]
  }
  return description
}

// Metric block key per CVSS version prefix. v2 is not emitted by anything
// the foundation publishes, so it is left out on purpose.
const METRIC_KEYS = new Map([
  ['3.0', 'cvssV3_0'],
  ['3.1', 'cvssV3_1'],
  ['4.0', 'cvssV4_0']
])

/**
 * Build one `metrics[]` entry from a CVSS vector string.
 *
 * The block key (`cvssV3_0`, `cvssV3_1`, `cvssV4_0`) follows the vector's
 * `CVSS:<version>/` prefix, which is what MITRE validates each block
 * against. `baseScore` is taken from `options.baseScore` when given and
 * computed from the vector otherwise (v3.x only; v4.0 has no bundled
 * calculator). `baseSeverity` is always derived from the final score.
 *
 * A vector with an unknown prefix or one the calculator rejects is passed
 * through under the closest key with no score, so the reviewer can report
 * it instead of this helper guessing.
 */
export function buildCvssMetric (vectorString, { baseScore } = {}) {
  const vector = String(vectorString ?? '').trim()
  const version = vector.match(/^CVSS:(\d\.\d)\//)?.[1]
  const key = METRIC_KEYS.get(version) ?? 'cvssV3_1'

  let score = typeof baseScore === 'number' ? baseScore : undefined
  if (score === undefined && (version === '3.0' || version === '3.1')) {
    try {
      score = calculateBaseScore(vector).baseScore
    } catch {}
  }

  return {
    format: 'CVSS',
    [key]: {
      version: version ?? '3.1',
      vectorString: vector,
      ...(score !== undefined ? { baseScore: score, baseSeverity: severityFromScore(score) } : {})
    }
  }
}

/**
 * Build one `problemTypes[]` entry from one or more CWE references.
 *
 * Accepts a single `{ cweId, name? }` or an array of them. `cweId` may be
 * given as `400`, `CWE-400` or `cwe-400` and is normalised to the
 * `CWE-<number>` form MITRE's pattern requires; anything else throws so
 * the mistake surfaces at build time. `description` is required by MITRE,
 * so it is the CWE name when known and the id otherwise.
 */
export function buildProblemType (cwes) {
  const list = Array.isArray(cwes) ? cwes : [cwes]
  if (list.length === 0) {
    throw new TypeError('buildProblemType: at least one CWE reference is required')
  }
  return {
    descriptions: list.map(({ cweId, name } = {}) => {
      const id = String(cweId ?? '').trim().match(/^(?:CWE-)?([1-9]\d*)$/i)?.[1]
      if (!id) {
        throw new TypeError(`buildProblemType: '${cweId}' is not a CWE id (expected CWE-<number>)`)
      }
      const text = String(name ?? '').trim()
      return {
        lang: 'en',
        type: 'CWE',
        cweId: `CWE-${id}`,
        description: text || `CWE-${id}`
      }
    })
  }
}

/**
 * Wrap a CNA container in the v5.2 Record envelope.
 *
 * Sets `providerMetadata.orgId` and `x_generator.engine` on the container
 * when the caller has not, so no consumer needs to know the OpenJS CNA org
 * id or the generator string. `cveMetadata` is emitted only when `cveId` is
 * given; without it the publisher's CLI argument is the sole source of
 * truth for the id.
 */
export function buildRecordEnvelope ({
  cna,
  cveId,
  assignerOrgId = OPENJS_CNA_ORG_ID,
  engineId = USER_AGENT,
  dataVersion = DATA_VERSION
} = {}) {
  if (!cna || typeof cna !== 'object') {
    throw new TypeError('buildRecordEnvelope: `cna` must be the CNA container object')
  }
  const container = {
    providerMetadata: { orgId: assignerOrgId },
    ...cna,
    // x_ prefixes are MITRE's extension namespace. x_generator is the
    // canonical place to surface "this container was produced by …".
    x_generator: cna.x_generator ?? { engine: engineId }
  }
  return {
    dataType: 'CVE_RECORD',
    dataVersion,
    ...(cveId
      ? { cveMetadata: { cveId, assignerOrgId, state: 'PUBLISHED' } }
      : {}),
    containers: { cna: container }
  }
}
