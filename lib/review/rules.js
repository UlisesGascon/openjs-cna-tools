// One universal review ruleset. No profiles — these rules are the things
// every CNA we know about agrees on (schema validity, basic credit hygiene,
// readable descriptions, references that aren't lies). Org-specific style
// preferences live in *callers*, not here.
//
// Adding a rule: append an entry below. Each rule is
// `{ id, severity, tier, check }` where check(container) returns either null
// (passes) or { path, message } (fails). The reviewer in ./index.js handles
// aggregation.
//
// `tier` classifies the rule against MITRE's v5.2 schema:
//   - `mitre-common`: MITRE's schema (or a CVSS subschema MITRE imports)
//     enforces the same constraint, so publish to MITRE would also fail.
//   - `openjs-extra`: OpenJS Foundation editorial preference that is stricter
//     than what MITRE itself enforces.
// See docs/mitre-schema-summary.md for the constraint inventory the tiers
// are derived from.

import { calculateBaseScore } from '../cvss.js'

const isString = (v) => typeof v === 'string'
const isNonEmptyArray = (v) => Array.isArray(v) && v.length > 0

// ----- Helpers --------------------------------------------------------------

function getDescription (c) {
  return c?.descriptions?.find(d => d?.lang === 'en') ??
      c?.descriptions?.[0]
}

// CVSS v3 blocks the record format accepts, newest first. v3.0 and v3.1
// share the same metrics and vector grammar; only the `CVSS:<version>/`
// prefix differs, and MITRE validates each block against its own schema.
const CVSS_V3_KEYS = [
  { key: 'cvssV3_1', version: '3.1' },
  { key: 'cvssV3_0', version: '3.0' }
]

// First CVSS v3 block (3.1 or 3.0) with a vector, plus the key it lives
// under so issue paths and prefix checks can name the right version.
function getCvssV3 (c) {
  for (const m of c?.metrics ?? []) {
    for (const { key, version } of CVSS_V3_KEYS) {
      if (m?.[key]?.vectorString) return { key, version, block: m[key] }
    }
  }
  return null
}

function getCvssScore (c) {
  for (const m of c?.metrics ?? []) {
    for (const { key } of CVSS_V3_KEYS) {
      if (typeof m?.[key]?.baseScore === 'number') return m[key].baseScore
    }
  }
  return null
}

function expectedSeverityBand (score) {
  if (score >= 9.0) return 'CRITICAL'
  if (score >= 7.0) return 'HIGH'
  if (score >= 4.0) return 'MEDIUM'
  if (score >= 0.1) return 'LOW'
  return 'NONE'
}

// ----- Rules ----------------------------------------------------------------
//
// The MITRE schema check (in ./schema.js) runs before these rules and
// handles structural concerns: required fields, type shape, CWE/CVSS id
// format, version pairings. The rules below cover the editorial / style
// dimensions schema validation can't enforce.

export const RULES = [
  // Descriptions
  {
    id: 'description-present',
    severity: 'blocker',
    // MITRE: `descriptions` is required on the container, the array has
    // minItems: 1, and `contains: englishLanguageDescription` requires at
    // least one en-tagged entry. Same failure as this rule.
    tier: 'mitre-common',
    check (c) {
      if (!isNonEmptyArray(c?.descriptions)) {
        return { path: 'descriptions', message: 'No descriptions provided' }
      }
      const en = getDescription(c)
      if (!en || !isString(en.value)) {
        return { path: 'descriptions[lang=en]', message: 'No English description provided' }
      }
      return null
    }
  },
  {
    id: 'description-not-empty',
    severity: 'blocker',
    // MITRE's `description.value` has minLength: 1, so an empty string is a
    // schema violation. This rule additionally rejects whitespace-only values
    // (e.g. "   "), which MITRE would accept. Classified as openjs-extra
    // because the marginal coverage over MITRE is the editorial bit.
    tier: 'openjs-extra',
    check (c) {
      const en = getDescription(c)
      if (!en) return null // covered by description-present
      if (!en.value.trim()) {
        return { path: 'descriptions[lang=en].value', message: 'Description is empty' }
      }
      return null
    }
  },
  {
    id: 'description-length',
    severity: 'warning',
    // MITRE: minLength 1, maxLength 4096. The 200-2000 band here is purely
    // editorial — readable prose, not too long.
    tier: 'openjs-extra',
    check (c) {
      const en = getDescription(c)
      const text = en?.value?.trim() ?? ''
      if (!text) return null
      if (text.length < 200) {
        return {
          path: 'descriptions[lang=en].value',
          message: `Description is ${text.length} chars; recommend at least 200`
        }
      }
      if (text.length > 2000) {
        return {
          path: 'descriptions[lang=en].value',
          message: `Description is ${text.length} chars; recommend at most 2000`
        }
      }
      return null
    }
  },
  // Credits
  {
    id: 'reporter-credit-present',
    severity: 'warning',
    // MITRE makes `credits` itself optional and does not require any
    // particular role to appear. OpenJS prefers a reporter/finder for
    // attribution hygiene but does not strictly require one — some
    // advisories are self-reported by the maintainer team.
    tier: 'openjs-extra',
    check (c) {
      const credits = c?.credits ?? []
      const hasReporter = credits.some(cr =>
        cr?.type === 'reporter' || cr?.type === 'finder'
      )
      if (!hasReporter) {
        return { path: 'credits', message: 'No reporter or finder credit found' }
      }
      return null
    }
  },
  {
    id: 'remediation-credit-present',
    severity: 'warning',
    // OpenJS editorial preference: at least one of the remediation roles
    // (developer / reviewer / verifier) should be credited so consumers
    // can trace who shipped the fix. MITRE does not require any specific
    // role. We accept the MITRE space-separated form AND the GHSA
    // underscore form so hand-written containers pass either way.
    tier: 'openjs-extra',
    check (c) {
      const credits = c?.credits ?? []
      const remediationRoles = new Set([
        'remediation developer',
        'remediation_developer',
        'remediation reviewer',
        'remediation_reviewer',
        'remediation verifier',
        'remediation_verifier'
      ])
      const has = credits.some(cr => remediationRoles.has(cr?.type))
      if (!has) {
        return {
          path: 'credits',
          message: 'No remediation credit found (expected one of: remediation developer / reviewer / verifier)'
        }
      }
      return null
    }
  },
  {
    id: 'no-duplicate-credit-role',
    severity: 'warning',
    // MITRE's `credits` array has uniqueItems, but items with the same
    // identity and different `type` values are NOT equal items, so the schema
    // accepts them. Editorial preference to flag the dupe.
    tier: 'openjs-extra',
    check (c) {
      const seen = new Map()
      for (const cr of c?.credits ?? []) {
        // `value` carries the free-form identity (login, name, etc.).
        // `user` is the UUID-typed field per MITRE; we fall back to it
        // for hand-written containers that prefer that shape.
        const identity = cr?.value ?? cr?.user
        if (!identity) continue
        const key = typeof identity === 'string' ? identity : JSON.stringify(identity)
        if (seen.has(key)) {
          return {
            path: 'credits',
            message: `Identity appears in credits with more than one role: ${seen.get(key)} + ${cr.type}`
          }
        }
        seen.set(key, cr.type)
      }
      return null
    }
  },

  // Severity / CVSS
  {
    id: 'metrics-present',
    severity: 'warning',
    // MITRE doesn't require a metrics block, but every published OpenJS
    // CVE carries at least one (v3.0, v3.1 or v4.0). Without metrics the
    // record looks half-finished to consumers parsing NVD/OSV.
    tier: 'openjs-extra',
    check (c) {
      const metrics = c?.metrics ?? []
      const hasCvss = getCvssV3(c) != null || metrics.some(m => m?.cvssV4_0?.vectorString)
      if (hasCvss) return null
      return {
        path: 'metrics',
        message: 'No CVSS metric present. Add at least one cvssV3_1, cvssV3_0 or cvssV4_0 block.'
      }
    }
  },
  {
    id: 'cvss-vector-parseable',
    severity: 'blocker',
    // MITRE imports the FIRST.org CVSS v3.x schemas, which constrain
    // `vectorString` with a pattern that requires the `CVSS:3.1/` (or
    // `CVSS:3.0/` in a cvssV3_0 block) prefix and validates every KEY:VAL
    // component. Same failure as this rule.
    tier: 'mitre-common',
    check (c) {
      const cvss = getCvssV3(c)
      if (!cvss) return null
      const vec = cvss.block.vectorString
      const prefix = `CVSS:${cvss.version}/`
      const path = `metrics[].${cvss.key}.vectorString`
      // Minimal CVSS v3 sanity check. Full parsing would need an external
      // library; we just verify the prefix matches the block's version and
      // that every component looks like KEY:VAL pairs.
      if (!vec.startsWith(prefix)) {
        return { path, message: `CVSS vector does not start with ${prefix}` }
      }
      const parts = vec.slice(prefix.length).split('/')
      if (parts.some(p => !/^[A-Z]+:[A-Z]+$/.test(p))) {
        return { path, message: 'CVSS vector has malformed components' }
      }
      return null
    }
  },
  {
    id: 'cvss-score-matches-band',
    severity: 'warning',
    // MITRE's bundled CVSS v3.x schemas have an `anyOf` that pairs each score
    // band (none/low/medium/high/critical) with the matching baseSeverity
    // enum, so a band mismatch is a schema violation upstream too.
    tier: 'mitre-common',
    check (c) {
      const score = getCvssScore(c)
      const cvss = getCvssV3(c)
      const band = cvss?.block.baseSeverity
      if (score == null || !band) return null
      const expected = expectedSeverityBand(score)
      if (expected !== band) {
        return {
          path: `metrics[].${cvss.key}`,
          message: `baseSeverity is '${band}' but the score ${score} falls in band '${expected}'`
        }
      }
      return null
    }
  },
  {
    id: 'cvss-score-matches-vector',
    severity: 'blocker',
    // MITRE does not recompute scores, so a baseScore that disagrees with
    // its vector is accepted upstream and then contradicts every consumer
    // that scores the vector itself (NVD, OSV, scanners). The vector is the
    // source of truth; the score must be the one FIRST.org's v3.x formula
    // yields for it. Unparseable vectors are left to cvss-vector-parseable.
    tier: 'openjs-extra',
    check (c) {
      const cvss = getCvssV3(c)
      if (!cvss || typeof cvss.block.baseScore !== 'number') return null
      let computed
      try {
        computed = calculateBaseScore(cvss.block.vectorString)
      } catch {
        return null
      }
      if (computed.baseScore !== cvss.block.baseScore) {
        return {
          path: `metrics[].${cvss.key}.baseScore`,
          message: `baseScore is ${cvss.block.baseScore} but the vector scores ${computed.baseScore}`
        }
      }
      return null
    }
  },

  // CWE
  {
    id: 'cwe-id-format',
    severity: 'blocker',
    // MITRE constrains cweId with pattern ^CWE-[1-9][0-9]*$ (actually a bit
    // stricter than this rule, which would accept CWE-0). Either way, any
    // value this rule rejects also fails MITRE.
    tier: 'mitre-common',
    check (c) {
      for (const pt of c?.problemTypes ?? []) {
        for (const d of pt?.descriptions ?? []) {
          if (d?.cweId && !/^CWE-\d+$/.test(d.cweId)) {
            return { path: 'problemTypes[].descriptions[].cweId', message: `'${d.cweId}' is not a valid CWE id` }
          }
        }
      }
      return null
    }
  },

  // Affected
  {
    id: 'affected-not-empty',
    severity: 'blocker',
    // MITRE: `affected` is required on the container with minItems: 1. Same
    // failure as this rule.
    tier: 'mitre-common',
    check (c) {
      if (!isNonEmptyArray(c?.affected)) {
        return { path: 'affected', message: 'No affected products listed' }
      }
      return null
    }
  },
  {
    id: 'affected-product-present',
    severity: 'blocker',
    // MITRE accepts EITHER (vendor + product) OR (collectionURL + packageName)
    // via anyOf. This rule only allows the first combo, so it rejects
    // schema-valid entries that use collectionURL + packageName. Editorial
    // preference for the vendor/product convention.
    tier: 'openjs-extra',
    check (c) {
      for (const a of c?.affected ?? []) {
        if (!isString(a?.vendor) || !isString(a?.product)) {
          return { path: 'affected[]', message: 'Each affected entry needs vendor + product' }
        }
      }
      return null
    }
  },
  {
    id: 'affected-versions-present',
    severity: 'blocker',
    // MITRE accepts EITHER `versions` OR `defaultStatus` per the product
    // anyOf, so an entry with only `defaultStatus` is schema-valid. This rule
    // insists on an explicit versions list; that's editorial.
    tier: 'openjs-extra',
    check (c) {
      for (const a of c?.affected ?? []) {
        if (!isNonEmptyArray(a?.versions)) {
          return { path: 'affected[].versions', message: 'Each affected entry needs at least one version' }
        }
      }
      return null
    }
  },
  {
    id: 'less-than-on-same-major',
    severity: 'warning',
    // MITRE has no opinion on the semantic relationship between `version`
    // and `lessThan`. Editorial heuristic for catching typo-style mistakes.
    tier: 'openjs-extra',
    check (c) {
      for (const a of c?.affected ?? []) {
        for (const v of a?.versions ?? []) {
          if (v?.version && v?.lessThan) {
            // `version: '0'` is the "no lower bound" sentinel the
            // converter emits for shapes like "< 2.1.1". The cross-
            // major check doesn't apply here — the bound is intentional.
            if (v.version === '0') continue
            const lhsMajor = String(v.version).split('.')[0]
            const rhsMajor = String(v.lessThan).split('.')[0]
            if (lhsMajor && rhsMajor && lhsMajor !== rhsMajor) {
              return {
                path: 'affected[].versions[]',
                message: `version '${v.version}' and lessThan '${v.lessThan}' span different majors`
              }
            }
          }
        }
      }
      return null
    }
  },

  // References
  {
    id: 'references-present',
    severity: 'warning',
    // MITRE: `references` is required on the container with minItems: 1.
    // Same failure as this rule.
    tier: 'mitre-common',
    check (c) {
      if (!isNonEmptyArray(c?.references)) {
        return { path: 'references', message: 'No references provided' }
      }
      return null
    }
  },
  {
    id: 'references-https',
    severity: 'warning',
    // MITRE's `uriType` accepts any URI scheme (http, https, ftp, ...).
    // Editorial preference for transport-secure links.
    tier: 'openjs-extra',
    check (c) {
      for (const r of c?.references ?? []) {
        if (r?.url && !/^https:\/\//.test(r.url)) {
          return { path: 'references[].url', message: `Non-HTTPS reference: '${r.url}'` }
        }
      }
      return null
    }
  }
]
