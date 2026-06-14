// Compact preview of a v5.2 CNA Container, designed for terminal output
// before / instead of editing the JSON by hand.
//
// Shape goal: key/value rows, pipe-friendly (no boxes, no ANSI). Preview
// is the operator's last chance to review before publish, so values are
// rendered in full lenght

const KEY_WIDTH = 14
const SEPARATOR_WIDTH = 56
const SEPARATOR = '·'.repeat(SEPARATOR_WIDTH)

function pad (key) {
  if (!key) return ' '.repeat(KEY_WIDTH)
  return (key + ':').padEnd(KEY_WIDTH)
}

function getDescription (c) {
  return c?.descriptions?.find(d => d?.lang === 'en')?.value ??
      c?.descriptions?.[0]?.value ??
      ''
}

function getCvss (c) {
  for (const m of c?.metrics ?? []) {
    if (m?.cvssV3_1?.vectorString) {
      return {
        version: '3.1',
        score: m.cvssV3_1.baseScore,
        severity: m.cvssV3_1.baseSeverity,
        vector: m.cvssV3_1.vectorString
      }
    }
    if (m?.cvssV4_0?.vectorString) {
      return {
        version: '4.0',
        score: m.cvssV4_0.baseScore,
        severity: m.cvssV4_0.baseSeverity,
        vector: m.cvssV4_0.vectorString
      }
    }
  }
  return null
}

function getCwes (c) {
  const out = new Set()
  for (const pt of c?.problemTypes ?? []) {
    for (const d of pt?.descriptions ?? []) {
      if (d?.cweId) out.add(d.cweId)
    }
  }
  return [...out]
}

function summarizeAffected (entry) {
  const product = `${entry.vendor ?? '?'}:${entry.product ?? '?'}`
  const ranges = (entry.versions ?? []).map(v => {
    if (v.lessThan) return `${v.version} → < ${v.lessThan}`
    if (v.lessThanOrEqual) return `${v.version} → ≤ ${v.lessThanOrEqual}`
    return v.version
  })
  return ranges.length === 0 ? product : `${product} (${ranges.join(', ')})`
}

function summarizeCredit (cr) {
  const identity = cr.value ?? cr.user ?? '?'
  return `${cr.type}: ${identity}`
}

// Render the preview into the given CLI. Stays sync and side-effect-free
// apart from the cli writes. Callers can null-out cli to get a string
// instead (useful for tests).
export function renderPreview (record, cli) {
  const lines = []
  const out = (line = '') => {
    if (cli) cli.log(line)
    lines.push(line)
  }

  if (!record || typeof record !== 'object') {
    out('Record preview: (no record provided)')
    return lines.join('\n')
  }

  const container = record?.containers?.cna ?? {}
  const cveId = record?.cveMetadata?.cveId

  out('')
  out('Record preview: (edit visually at https://vulnogram.org/#source)')

  // Each field becomes a "row" via `row(key, value, ...extras)`. The
  // helper emits a dotted separator before every row except the first
  // so the operator can scan the preview as a stack of distinct fields.
  let rowsEmitted = 0
  const row = (key, value, ...extras) => {
    if (rowsEmitted > 0) out(`  ${SEPARATOR}`)
    out(`  ${pad(key)} ${value}`)
    const continuation = ' '.repeat(2 + KEY_WIDTH + 1)
    for (const line of extras) out(`${continuation}${line}`)
    rowsEmitted += 1
  }

  if (cveId) row('CVE', cveId)
  if (container.title) row('Title', container.title)

  const description = getDescription(container)
  if (description) {
    const [firstLine, ...rest] = String(description).split('\n')
    row('Description', firstLine, ...rest)
  }

  const affected = container.affected ?? []
  if (affected.length > 0) {
    const [first, ...rest] = affected
    row('Affected', summarizeAffected(first), ...rest.map(summarizeAffected))
  }

  const cvss = getCvss(container)
  if (cvss) {
    const score = typeof cvss.score === 'number' ? cvss.score.toFixed(1) : '?'
    row(`CVSS ${cvss.version}`, `${score} ${cvss.severity ?? ''} (${cvss.vector})`.trimEnd().replace(/^\s+/, ''))
  }

  const cwes = getCwes(container)
  if (cwes.length > 0) row('CWE', cwes.join(', '))

  const credits = container.credits ?? []
  if (credits.length > 0) {
    row('Credits', credits.map(summarizeCredit).join(', '))
  }

  const refs = container.references ?? []
  if (refs.length > 0) {
    const [first, ...rest] = refs.map(r => r?.url ?? '?')
    row('References', first, ...rest)
  }

  if (container.x_generator?.engine) {
    row('Generator', container.x_generator.engine)
  }

  out('')
  return lines.join('\n')
}
