// Parse GHSA-style `vulnerable_version_range` strings into MITRE v5.2
// `affected[].versions[]` entries.
//
// GHSA is permissive: maintainers type freeform range expressions and we
// see ~60 distinct shapes across the vulnerabilities tracked
// (see test/fixtures/version-range-matrix.js for the canonical list).
// MITRE is strict: every entry needs { version, status, versionType } plus
// at most one of { lessThan, lessThanOrEqual, changes }.
//
// Strategy:
//
//   1. Split multi-line inputs on `; ` or `&&` first — each segment becomes
//      its own entry in the output array.
//   2. For each segment, strip incidental noise (package-name prefix,
//      parenthetical annotations, leading/trailing whitespace, leading
//      `v` on tokens like `v5.2.1`).
//   3. Try a sequence of structural matchers most-specific first: hyphen
//      range, caret range, bounded (lower + upper), single operator,
//      implicit-lower-bound shape, bare semver, commit hash.
//   4. Unparseable segments fall back to `versionType: 'custom'` carrying
//      the original text, unless we extracted an embedded commit hash —
//      in which case use that.
//
// Always emits at least one entry per non-empty input, or [] for empty
// strings. The function never throws on input.

const SEMVER_TOKEN = String.raw`v?\d+(?:\.\d+){0,2}(?:-[\w.]+)?`
const HASH_TOKEN = '[0-9a-f]{7,40}'
const COMMIT_HASH = new RegExp(`^${HASH_TOKEN}$`, 'i')

const RX = {
  bareSemver: new RegExp(`^${SEMVER_TOKEN}$`),
  rangeHyphen: new RegExp(`^(${SEMVER_TOKEN})\\s*-\\s*(${SEMVER_TOKEN})$`),
  caret: new RegExp(`^\\^(${SEMVER_TOKEN})$`),

  // Single-operator forms. The optional whitespace lets `<4.0.0` and
  // `< 4.0.0` both match.
  opUpperEx: new RegExp(`^<\\s*(${SEMVER_TOKEN}|${HASH_TOKEN})$`, 'i'),
  opUpperInc: new RegExp(`^(?:<=|=<)\\s*(${SEMVER_TOKEN})$`),
  opLowerEx: new RegExp(`^>\\s*(${SEMVER_TOKEN})$`),
  opLowerInc: new RegExp(`^>=\\s*(${SEMVER_TOKEN})$`),
  opEquals: new RegExp(`^=\\s*(${SEMVER_TOKEN})$`),

  // Bounded ranges: lower + upper, glued together with comma, whitespace,
  // or nothing. `>=4.0.0, <4.18.0` / `>=4.0.0 <4.18.0` / `>=4.0.0,<4.18.0`
  // / `>=4.0.0<4.18.0` all match.
  bounded: new RegExp(
    `^>=?\\s*(${SEMVER_TOKEN})\\s*(?:,\\s*|\\s+|)\\s*(<=?|=<)\\s*(${SEMVER_TOKEN})$`
  ),

  // Implicit lower bound: "7.0.0 < 7.24.0" — no leading operator, the
  // bare version IS the lower bound.
  implicitBounded: new RegExp(
    `^(${SEMVER_TOKEN})\\s*(<=?|=<)\\s*(${SEMVER_TOKEN})$`
  )
}

function stripV (s) {
  return String(s).replace(/^v/, '')
}

// Remove incidental noise from a segment before structural matching:
// parenthetical annotations, leading package-name prefixes, surrounding
// whitespace.
function clean (segment) {
  let s = segment.trim()
  // Strip parenthetical clarifications: "<=5.2.1 (includes all 4.x)".
  s = s.replace(/\s*\([^)]*\)\s*/g, '').trim()
  // Strip package-name prefix: "lodash <= 4.18.1" or "lodash<=4.18.1".
  // We only fire this when the prefix is alphabetic AND followed by an
  // OPERATOR (`<`, `>`, `=`). If we widened to digits we'd shred
  // freeform inputs like "Leangheng2004" into the bare "4".
  s = s.replace(/^[a-z@][\w@/.-]*\s*(?=[<>=])/i, '').trim()
  return s
}

// Split multi-line inputs on `;` or `&&`. Each segment becomes its own
// entry in the output.
function splitMultiline (input) {
  return input
    .split(/\s*(?:;|&&)\s*/)
    .map(s => s.trim())
    .filter(Boolean)
}

// Try to parse a single segment. Returns the MITRE entry if a structural
// matcher hits, or null if the segment cannot be understood.
function parseSegment (raw) {
  const segment = clean(raw)
  if (!segment) return null

  // Wildcards
  if (segment === '*' || /^all$/i.test(segment)) {
    return { version: '0', status: 'affected', versionType: 'semver' }
  }

  // Hyphen range: "4.0.0 - 4.17.23"
  const hyphenMatch = segment.match(RX.rangeHyphen)
  if (hyphenMatch) {
    return {
      version: stripV(hyphenMatch[1]),
      lessThanOrEqual: stripV(hyphenMatch[2]),
      status: 'affected',
      versionType: 'semver'
    }
  }

  // Caret range: "^4.19.2" → [4.19.2, 5.0.0)
  const caretMatch = segment.match(RX.caret)
  if (caretMatch) {
    const base = stripV(caretMatch[1])
    const major = base.split('.')[0]
    return {
      version: base,
      lessThan: `${Number(major) + 1}.0.0`,
      status: 'affected',
      versionType: 'semver'
    }
  }

  // Bounded: ">=4.0.0, <4.18.0" / ">= 4.0.0 <= 4.18.1" / ">=4.0.0<4.18.0"
  const bounded = segment.match(RX.bounded)
  if (bounded) {
    const lower = stripV(bounded[1])
    const upperOp = bounded[2]
    const upper = stripV(bounded[3])
    const entry = { version: lower, status: 'affected', versionType: 'semver' }
    if (upperOp === '<') entry.lessThan = upper
    else entry.lessThanOrEqual = upper
    return entry
  }

  // Implicit lower: "7.0.0 < 7.24.0" — bare version followed by operator.
  const implicit = segment.match(RX.implicitBounded)
  if (implicit) {
    const lower = stripV(implicit[1])
    const upperOp = implicit[2]
    const upper = stripV(implicit[3])
    const entry = { version: lower, status: 'affected', versionType: 'semver' }
    if (upperOp === '<') entry.lessThan = upper
    else entry.lessThanOrEqual = upper
    return entry
  }

  // Single-operator forms — try most specific (two-char ops) first.
  const opUpperInc = segment.match(RX.opUpperInc)
  if (opUpperInc) {
    return {
      version: '0',
      lessThanOrEqual: stripV(opUpperInc[1]),
      status: 'affected',
      versionType: 'semver'
    }
  }
  const opLowerInc = segment.match(RX.opLowerInc)
  if (opLowerInc) {
    return { version: stripV(opLowerInc[1]), status: 'affected', versionType: 'semver' }
  }
  const opUpperEx = segment.match(RX.opUpperEx)
  if (opUpperEx) {
    const value = opUpperEx[1]
    if (COMMIT_HASH.test(value)) {
      return { version: '0', lessThan: value, status: 'affected', versionType: 'git' }
    }
    return { version: '0', lessThan: stripV(value), status: 'affected', versionType: 'semver' }
  }
  const opLowerEx = segment.match(RX.opLowerEx)
  if (opLowerEx) {
    return { version: stripV(opLowerEx[1]), status: 'affected', versionType: 'semver' }
  }
  const opEquals = segment.match(RX.opEquals)
  if (opEquals) {
    return { version: stripV(opEquals[1]), status: 'affected', versionType: 'semver' }
  }

  // Bare semver: "4.6.2"
  if (RX.bareSemver.test(segment)) {
    return { version: stripV(segment), status: 'affected', versionType: 'semver' }
  }

  // Bare commit hash: "39fd9827942..."
  if (COMMIT_HASH.test(segment)) {
    return { version: segment, status: 'affected', versionType: 'git' }
  }

  return null
}

// Public entry. See module header.
export function parseVersionRange (input) {
  if (typeof input !== 'string') return []
  const trimmed = input.trim()
  if (!trimmed) return []

  const segments = splitMultiline(trimmed)
  const out = []
  const fallbacks = [] // { kind: 'hash'|'custom', entry, hadDigits }

  for (const seg of segments) {
    const parsed = parseSegment(seg)
    if (parsed) {
      out.push(parsed)
      continue
    }
    // Fall back: extract an embedded commit hash if present, otherwise
    // pass the segment through verbatim under `versionType: 'custom'`.
    // We stage fallbacks separately so that, in multi-segment inputs,
    // pure-prose segments can be dropped when at least one other segment
    // yielded something useful.
    const hashMatch = seg.match(new RegExp(`\\b(${HASH_TOKEN})\\b`, 'i'))
    if (hashMatch) {
      fallbacks.push({
        kind: 'hash',
        entry: { version: hashMatch[1], status: 'affected', versionType: 'custom' },
        hadDigits: true
      })
    } else {
      const hadDigits = /\d/.test(seg)
      fallbacks.push({
        kind: 'custom',
        entry: { version: seg, status: 'affected', versionType: 'custom' },
        hadDigits
      })
    }
  }

  if (segments.length > 1 && out.length > 0) {
    // Multi-segment: only keep fallbacks that surfaced a hash or had
    // digits. Prose-only fallbacks are dropped because the structured
    // segments already carry the load-bearing information.
    for (const f of fallbacks) {
      if (f.kind === 'hash' || f.hadDigits) out.push(f.entry)
    }
  } else if (segments.length > 1) {
    // Multi-segment with zero structured hits: surface hashes if any,
    // otherwise nothing — the input is pure prose.
    for (const f of fallbacks) {
      if (f.kind === 'hash') out.push(f.entry)
    }
    if (out.length === 0 && fallbacks.length > 0) {
      // Truly nothing — surface the first segment so the operator sees
      // what was there.
      out.push(fallbacks[0].entry)
    }
  } else {
    // Single segment: pass the fallback through verbatim.
    for (const f of fallbacks) out.push(f.entry)
  }

  return out
}
