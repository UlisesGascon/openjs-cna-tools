// Convert a GitHub Security Advisory into a v5.2 CNA Container draft.
//
// Input shapes:
//
//   1. **Per-repository advisory URL** —
//      `https://github.com/<owner>/<repo>/security/advisories/<GHSA>`.
//      Routes to `GET https://api.github.com/repos/<owner>/<repo>/security-advisories/<GHSA>`.
//      Public, no auth required for published advisories.
//
//   2. **Global database advisory URL** —
//      `https://github.com/advisories/<GHSA>`.
//      Routes to `GET https://api.github.com/advisories/<GHSA>`.
//      Public, no auth required.
//
//   3. **Pre-fetched advisory object** — for callers that already have
//      the advisory JSON in hand (webhook payloads, cached responses,
//      tests, or `openjs-cna-experimental convert -` reading from stdin).
//
// This tool only reads PUBLIC published advisories. Private drafts are
// out of scope — operators with access can `gh api … > advisory.json &&
// openjs-cna-experimental convert -` to convert from stdin instead.
//
// The mapper (`mapAdvisoryToRecord`) is exported separately so the pure
// shape-translation logic is testable without touching the network.

import { USER_AGENT } from '../client.js'
import { buildCvssMetric, buildRecordEnvelope } from '../record.js'
import { OPENJS_CNA_ORG_ID } from '../review/schema.js'
import { parseVersionRange } from './version-range.js'

// `ENGINE_ID` is the same string we send as `User-Agent` on every HTTP
// call (see lib/client.js). Re-exported here so callers that only need
// the converter don't have to reach into the transport module.
export const ENGINE_ID = USER_AGENT

// GHSA credit `type` values use underscores. MITRE's CVE Record Format
// schema (cnaPublishedContainer → credits → type) requires the
// space-separated forms. Map each known GHSA role to its MITRE spelling.
const CREDIT_TYPE_MAP = {
  finder: 'finder',
  reporter: 'reporter',
  analyst: 'analyst',
  coordinator: 'coordinator',
  remediation_developer: 'remediation developer',
  remediation_reviewer: 'remediation reviewer',
  remediation_verifier: 'remediation verifier',
  tool: 'tool',
  sponsor: 'sponsor',
  other: 'other'
}

const URL_REPO_RE = /^https:\/\/github\.com\/([^/]+)\/([^/]+)\/security\/advisories\/(GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4})/i
const URL_GLOBAL_RE = /^https:\/\/github\.com\/advisories\/(GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4})/i

// Tag the canonical GitHub advisory URL (the GHSA we are converting) as
// `vendor-advisory`. Everything else is left untagged — the operator
// can hand-tag in Vulnogram or by editing the JSON before publish.
//
// Why: heuristics for CVE / commit / blog URLs accumulate edge cases
// fast (different hosts, different URL shapes, redirects) and the cost
// of a wrong tag at publish time is real. Better to ship one tag we can
// be sure of than several that drift.
function tagForUrl (url, { selfGhsaId } = {}) {
  if (!selfGhsaId) return null
  const selfRe = new RegExp(
    `(github\\.com/.*/security/advisories/${selfGhsaId}\\b|github\\.com/advisories/${selfGhsaId}\\b)`,
    'i'
  )
  return selfRe.test(url) ? 'vendor-advisory' : null
}

// Parse a github.com advisory URL into a structured descriptor or return
// null if the input doesn't look like one. The `kind` field tells the
// fetcher which GitHub REST endpoint to hit.
//
//   { kind: 'repo',   owner, repo, ghsaId } → /repos/{owner}/{repo}/security-advisories/{ghsaId}
//   { kind: 'global', ghsaId }              → /advisories/{ghsaId}
//
// Exported so tests and other callers can use the same parser.
export function parseAdvisoryUrl (url) {
  if (typeof url !== 'string') return null
  const repoMatch = url.match(URL_REPO_RE)
  if (repoMatch) {
    return { kind: 'repo', owner: repoMatch[1], repo: repoMatch[2], ghsaId: repoMatch[3] }
  }
  const globalMatch = url.match(URL_GLOBAL_RE)
  if (globalMatch) {
    return { kind: 'global', ghsaId: globalMatch[1] }
  }
  return null
}

// GitHub's REST API for published advisories is public. We pass
// `User-Agent` and `Accept` headers per GitHub's docs, but no auth.
// Injectable `fetchImpl` for tests.
async function ghFetch (url, { fetchImpl = globalThis.fetch } = {}) {
  const res = await fetchImpl(url, {
    headers: {
      Accept: 'application/vnd.github+json',
      'User-Agent': USER_AGENT,
      'X-GitHub-Api-Version': '2022-11-28'
    }
  })
  if (!res.ok) {
    throw new Error(
      `GitHub returned ${res.status} for ${url}. ` +
      'The advisory may be private or unpublished — this tool only supports public advisories.'
    )
  }
  return res.json()
}

async function fetchAdvisory (source, opts = {}) {
  if (source && typeof source === 'object') return source
  if (typeof source !== 'string') {
    throw new TypeError(`source must be a string or object, got ${typeof source}`)
  }
  const parsed = parseAdvisoryUrl(source)
  if (parsed?.kind === 'repo') {
    return ghFetch(`https://api.github.com/repos/${parsed.owner}/${parsed.repo}/security-advisories/${parsed.ghsaId}`, opts)
  }
  if (parsed?.kind === 'global') {
    return ghFetch(`https://api.github.com/advisories/${parsed.ghsaId}`, opts)
  }
  throw new Error(
    `Cannot parse advisory source: '${source}'. Pass a public advisory URL:\n` +
    '  - per-repository:  https://github.com/<owner>/<repo>/security/advisories/<GHSA>\n' +
    '  - global database: https://github.com/advisories/<GHSA>'
  )
}

// ----- Mappers --------------------------------------------------------------

// Drop the References section (and everything after it) from a Markdown
// description. The URLs are already structured in `cna.references[]`,
// so leaving them in the description would duplicate the data. We strip
// this from BOTH the plain-text value and the raw Markdown that travels
// in supportingMedia, so neither representation carries the duplicate.
function stripReferencesSection (md) {
  if (typeof md !== 'string') return ''
  const normalized = md.replace(/\r\n/g, '\n').replace(/\r/g, '\n')
  // Case-insensitive (trailing /i flag), so "References", "references",
  // and "REFERENCES" all match across the three shapes we accept:
  // ATX heading (`### References`), bold (`**References**`), and
  // plain label (`References:`).
  const refIdx = normalized.search(
    /(?:^|\n)\s*(?:#{1,6}\s+References\b|\*\*References\*\*|References\s*:)\s*\n/i
  )
  return refIdx >= 0 ? normalized.slice(0, refIdx).trimEnd() : normalized
}

// Strip Markdown formatting down to readable plain text. Generic — no
// hard-coded section names beyond the References block (which is dropped
// upstream by stripReferencesSection because cna.references[] is its
// structured home). Headers become "Label:" lines (matches the published
// OpenJS CVE convention), emphasis/code/links collapse to their text
// content, list bullets drop the bullet marker, blockquote markers drop.
function stripMarkdown (md) {
  if (typeof md !== 'string') return ''
  // Normalize line endings — GitHub serves CRLF, every regex below uses
  // `\n` as the line boundary.
  let text = md.replace(/\r\n/g, '\n').replace(/\r/g, '\n')
  // Headers → "Label:" (any ATX heading, level 1–6, generic). We use
  // [ \t]* (not \s*) for leading/trailing whitespace so we don't eat the
  // preceding/following blank lines — those are what visually separate
  // the heading label from neighboring paragraphs.
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

function buildDescriptions (advisory) {
  // GHSA advisory descriptions are authored in Markdown. MITRE's
  // descriptions[0].value field is plain-text in every published OpenJS
  // CVE on record, so we strip the Markdown for the value and put the
  // (de-duplicated) original Markdown into supportingMedia[0]. The
  // References block is removed from both representations because its
  // URLs already live in cna.references[] as structured data.
  const original = (advisory.description ?? '').trim() || (advisory.summary ?? '').trim()
  if (!original) return []
  const raw = stripReferencesSection(original).trim()
  if (!raw) return []
  const plain = stripMarkdown(raw) || raw
  const description = {
    lang: 'en',
    value: plain
  }
  // Only attach supportingMedia when the raw Markdown still carries
  // formatting after the References strip. If plain === raw the markdown
  // form has nothing extra to offer.
  if (raw !== plain) {
    description.supportingMedia = [{ type: 'text/markdown', base64: false, value: raw }]
  }
  return [description]
}

function buildAffected (advisory) {
  const vulnerabilities = advisory.vulnerabilities ?? []
  return vulnerabilities.map((v) => {
    // parseVersionRange expands a GHSA range string into MITRE-shaped
    // entries (version + lessThan/lessThanOrEqual + versionType). Multi-
    // segment inputs (e.g. "< 6.24.0; 7.0.0 < 7.24.0") become multiple
    // entries; empty input becomes []. See lib/convert/version-range.js
    // and the matrix at test/fixtures/version-range-matrix.js for the
    // full shape coverage.
    const versions = parseVersionRange(v.vulnerable_version_range ?? '')
    return {
      vendor: v.package?.ecosystem === 'npm' ? 'npm' : 'unknown',
      product: v.package?.name ?? 'unknown',
      defaultStatus: 'unaffected',
      versions
    }
  })
}

function buildProblemTypes (advisory) {
  const cwes = advisory.cwes ?? []
  if (cwes.length === 0) return undefined
  return [{
    descriptions: cwes.map((cwe) => ({
      lang: 'en',
      cweId: cwe.cwe_id,
      type: 'CWE',
      description: cwe.name ?? cwe.cwe_id
    }))
  }]
}

function buildMetrics (advisory) {
  // GHSA serves CVSS in two parallel places, depending on endpoint and
  // age of the advisory:
  //
  //   * Top-level `cvss` / `cvss_v3` — older v3.1-only shape, may be
  //     null when the reporter only filed a v4 vector.
  //   * `cvss_severities.cvss_v3` / `cvss_severities.cvss_v4` — newer
  //     shape; v4 can be the only populated entry when the reporter
  //     used the v4 calculator.
  //
  // Emit a `cvssV3_1` block whenever a v3.1 vector exists, and a
  // `cvssV4_0` block whenever a v4 vector exists. Both can appear; we
  // emit each in its own metric entry so the MITRE schema (which gates
  // additional properties on cvssVx blocks) is happy. GHSA only issues
  // 3.1 and 4.0 vectors; `buildCvssMetric` computes a missing v3.1 score
  // and passes through a vector it cannot parse for the reviewer to flag.
  const metrics = []
  const v3Vector = advisory.cvss?.vector_string ??
    advisory.cvss_v3?.vector_string ??
    advisory.cvss_severities?.cvss_v3?.vector_string
  const v3Score = advisory.cvss?.score ??
    advisory.cvss_v3?.score ??
    advisory.cvss_severities?.cvss_v3?.score
  if (v3Vector) {
    metrics.push(buildCvssMetric(v3Vector, { baseScore: v3Score }))
  }
  const v4Vector = advisory.cvss_v4?.vector_string ??
    advisory.cvss_severities?.cvss_v4?.vector_string
  const v4Score = advisory.cvss_v4?.score ??
    advisory.cvss_severities?.cvss_v4?.score
  if (v4Vector) {
    metrics.push(buildCvssMetric(v4Vector, { baseScore: v4Score }))
  }
  return metrics.length > 0 ? metrics : undefined
}

function buildCredits (advisory) {
  // GitHub's two advisory endpoints return credits in different shapes:
  //
  //   * Global `/advisories/{id}` returns `credits: [{ user: { login }, type }]`
  //   * Per-repo `/repos/.../security-advisories/{id}` returns
  //     `credits: [{ login, type }]` (login at the top level, no `user`
  //     wrapper) AND `credits_detailed: [{ user: { login }, ... }]`.
  //
  // Prefer `credits_detailed` when it has entries (richer per-repo shape);
  // otherwise fall back to `credits`. The login extractor below tolerates
  // both shapes so a hand-fed advisory object works either way.
  const sourceCredits = advisory.credits_detailed?.length
    ? advisory.credits_detailed
    : (advisory.credits ?? [])
  if (sourceCredits.length === 0) return undefined
  return sourceCredits.map((c) => {
    // Try every shape we know about: { login }, { user: 'string' },
    // { user: { login } }, falling through to 'unknown'.
    const login = c.login ??
      (typeof c.user === 'string' ? c.user : c.user?.login) ??
      'unknown'
    const ghsaType = c.type ?? 'finder'
    // MITRE's schema uses space-separated values for multi-word types
    // (e.g. 'remediation developer'). GHSA uses underscores. Map across.
    const mitreType = CREDIT_TYPE_MAP[ghsaType] ?? 'other'
    // We do NOT set `user` on the MITRE credit (the schema requires a
    // UUID there and we don't have one). `value` carries the GitHub login
    // verbatim, which is the human-readable identity MITRE expects on
    // free-form attribution.
    return {
      lang: 'en',
      type: mitreType,
      value: login
    }
  })
}

// Pull URLs out of the description's "References" section. Per-repo
// advisories return `references: null` from the REST API but operators
// usually list the URLs in the Markdown body under a heading like
// `### References` or `**References**`. From the first such header to
// the end of the description (or the next heading), grab every URL.
function extractReferencesFromDescription (text) {
  if (typeof text !== 'string') return []
  // Match the "References" header. We accept Markdown headings (`#+`),
  // bold (`**References**`), and bare `References:` followed by colon
  // or newline. Case-insensitive.
  const headerRe = /(?:^|\n)\s*(?:#{1,6}\s+References\b|\*\*References\*\*|References\s*:)\s*\n/i
  const headerMatch = text.match(headerRe)
  if (!headerMatch) return []
  const start = headerMatch.index + headerMatch[0].length
  // Cut off at the next Markdown heading so we don't pull URLs from a
  // following section. If there is none, take the rest of the text.
  const after = text.slice(start)
  const nextHeading = after.match(/\n\s*#{1,6}\s+\S/)
  const section = nextHeading ? after.slice(0, nextHeading.index) : after
  // Pull every http(s) URL; let the dedupe in buildReferences handle
  // duplicates if the same URL appears twice in the section.
  const urls = section.match(/https?:\/\/\S+/g) ?? []
  // Strip trailing punctuation common in Markdown bullets/sentences.
  return urls.map(u => u.replace(/[).,;]+$/, ''))
}

// Walk GHSA's `references[]` and emit MITRE references. When the API
// returns an empty/null `references` (per-repo endpoint does this), fall
// back to scraping the description's "References" section. The
// `vendor-advisory` tag is heuristic — see tagForUrl. URLs that don't
// match a known pattern get no tag (MITRE accepts untagged references).
function buildReferences (advisory) {
  const out = []
  const seen = new Set()
  // Pass the advisory's own GHSA id into tagForUrl so the self-reference
  // (the canonical GitHub advisory page for the same GHSA) doesn't get
  // mislabeled `third-party-advisory`.
  const selfGhsaId = advisory.ghsa_id
  const push = (url) => {
    if (!url || seen.has(url)) return
    seen.add(url)
    const tag = tagForUrl(url, { selfGhsaId })
    out.push(tag ? { url, tags: [tag] } : { url })
  }
  // Primary source: the API's structured `references[]`.
  for (const ref of advisory.references ?? []) {
    const url = typeof ref === 'string' ? ref : ref?.url
    push(url)
  }
  // Fallback: scrape the description's References section. Only kicks
  // in when the structured list was empty.
  if (out.length === 0) {
    for (const url of extractReferencesFromDescription(advisory.description)) {
      push(url)
    }
  }
  return out
}

// ----- Public API -----------------------------------------------------------

// Pure mapper: GHSA advisory JSON → full v5.2 **CVE Record**.
//
// Output shape (Vulnogram-compatible, matches every published OpenJS CVE
// on MITRE):
//
//   {
//     dataType: 'CVE_RECORD',
//     dataVersion: '5.2',
//     cveMetadata: { cveId, assignerOrgId, state: 'PUBLISHED' },
//     containers: { cna: { ...the actual container... } }
//   }
//
// CVE id resolution:
//   - If the advisory carries `cve_id`, the mapper stamps it into
//     `cveMetadata.cveId` automatically.
//   - The caller can also pass an explicit `cveId` option as a safety
//     belt. If both are present and they disagree, that's a hard error.
//   - If neither side has a CVE id, the record carries no `cveMetadata`;
//     the publisher's CLI arg becomes the sole source of truth.
//
// Inputs:
//   advisory      — the GHSA advisory object (REST API shape)
//   cveId         — optional explicit CVE id. Cross-checked against
//                   `advisory.cve_id` when both are present.
//   engineId      — override the x_generator.engine string (default:
//                   this package + version)
//   assignerOrgId — override the CNA org UUID (default: OpenJS Foundation)
//
// References are derived from `advisory.references[]` with a fallback
// to scraping the description's "References" section for per-repo
// advisories where the API returns null.
//
// Exposed for tests and for callers that already have the advisory in hand.
export function mapAdvisoryToRecord (advisory, {
  cveId,
  engineId = ENGINE_ID,
  assignerOrgId = OPENJS_CNA_ORG_ID
} = {}) {
  if (!advisory || typeof advisory !== 'object') {
    throw new TypeError('mapAdvisoryToRecord: `advisory` must be the GHSA object')
  }
  // Reconcile the two possible CVE-id sources. Both API endpoints
  // (per-repo and global) expose `cve_id` when one's been assigned.
  const advisoryCveId = advisory.cve_id || undefined
  if (cveId && advisoryCveId && cveId !== advisoryCveId) {
    throw new Error(
      `CVE id mismatch: caller passed ${cveId}, advisory reports ${advisoryCveId}. ` +
      'Refusing to publish — re-check which CVE you meant to associate.'
    )
  }
  const resolvedCveId = cveId ?? advisoryCveId

  // The envelope, providerMetadata and x_generator come from
  // buildRecordEnvelope so every converter emits them the same way.
  return buildRecordEnvelope({
    cveId: resolvedCveId,
    assignerOrgId,
    engineId,
    cna: {
      title: advisory.summary,
      descriptions: buildDescriptions(advisory),
      affected: buildAffected(advisory),
      problemTypes: buildProblemTypes(advisory),
      metrics: buildMetrics(advisory),
      credits: buildCredits(advisory),
      references: buildReferences(advisory)
    }
  })
}

// Fetch + map convenience. Returns the full CVE Record (Vulnogram-
// compatible). `fetchImpl` is injectable for tests.
export async function convertGhsaToRecord ({
  source, cveId, engineId, assignerOrgId, fetchImpl
} = {}) {
  if (!source) throw new Error('convertGhsaToRecord: `source` is required')
  const advisory = await fetchAdvisory(source, { fetchImpl })
  return mapAdvisoryToRecord(advisory, { cveId, engineId, assignerOrgId })
}
