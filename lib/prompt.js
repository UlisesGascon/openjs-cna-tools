// Build an LLM audit prompt for a v5.2 CVE Record's natural-language
// fields. The CLI side just prints the result; the user pastes it into
// the LLM of their choice (no network call from this tool).
//
// What we ask the LLM to do:
//   * audit the title against the OpenJS naming convention
//   * audit the description for clarity, tone, and editorial rules
//     (no PoCs, no em/en-dashes, no cross-references to other private
//     advisories, references belong in cna.references[] not in prose)
//   * return Markdown with a rating + a per-issue list including a
//     suggested rewrite where applicable.
//
// The prompt embeds:
//   * the title
//   * the plain-text description (descriptions[0].value)
//   * the raw Markdown if supportingMedia[0].type === text/markdown
//   * a short facts block (affected, CVSS, CWE) so the LLM grounds its
//     suggestions in what the vulnerability actually is.

function getCna (record) {
  return record?.containers?.cna ?? {}
}

function getDescription (cna) {
  return cna?.descriptions?.find(d => d?.lang === 'en') ?? cna?.descriptions?.[0] ?? null
}

function getMarkdown (description) {
  if (!description?.supportingMedia) return null
  const media = description.supportingMedia.find(m => m?.type === 'text/markdown')
  return media?.value ?? null
}

function summarizeAffected (cna) {
  return (cna?.affected ?? []).map((a) => {
    const product = `${a.vendor ?? '?'}:${a.product ?? '?'}`
    const ranges = (a.versions ?? []).map((v) => {
      if (v.lessThan) return `${v.version} → < ${v.lessThan}`
      if (v.lessThanOrEqual) return `${v.version} → ≤ ${v.lessThanOrEqual}`
      return v.version
    })
    return ranges.length === 0 ? product : `${product} (${ranges.join(', ')})`
  })
}

// Metric blocks the record format accepts, in display preference order.
const CVSS_BLOCKS = [
  { key: 'cvssV3_1', label: 'CVSS 3.1' },
  { key: 'cvssV4_0', label: 'CVSS 4.0' },
  { key: 'cvssV3_0', label: 'CVSS 3.0' }
]

function summarizeCvss (cna) {
  for (const m of cna?.metrics ?? []) {
    for (const { key, label } of CVSS_BLOCKS) {
      if (m?.[key]?.vectorString) {
        const { vectorString, baseScore, baseSeverity } = m[key]
        return { label, body: `${baseScore ?? '?'} ${baseSeverity ?? ''} (${vectorString})`.replace(/\s+/g, ' ').trim() }
      }
    }
  }
  return null
}

function summarizeCwes (cna) {
  const out = new Set()
  for (const pt of cna?.problemTypes ?? []) {
    for (const d of pt?.descriptions ?? []) {
      if (d?.cweId) out.add(d.cweId)
    }
  }
  return [...out]
}

// Generate the full LLM prompt as a string. Caller is responsible for
// printing it; this stays pure so it's trivial to test.
export function buildAuditPrompt (record) {
  const cna = getCna(record)
  const description = getDescription(cna)
  const title = cna?.title ?? '(no title)'
  const value = description?.value ?? '(no description)'
  const markdown = getMarkdown(description)
  const affected = summarizeAffected(cna)
  const cvss = summarizeCvss(cna)
  const cwes = summarizeCwes(cna)
  const cveId = record?.cveMetadata?.cveId

  const lines = []
  lines.push(
    'You are reviewing the natural-language fields of a CVE record before it ships to MITRE.',
    'The fields are read by application developers and security tooling worldwide.',
    'Be concise, factual, and editorial. Flag what should change and why.',
    '',
    '## Editorial guidelines',
    '',
    '**Title** (`cna.title`):',
    '- Format: `<package> vulnerable to <Vulnerability Type>` or `<package> vulnerable to <Type> via <Vector>`.',
    '- 6 to 15 words. Package name lowercase as it appears on npm.',
    '- Spell out vulnerability classes (e.g. "Denial of Service", not "DoS"; "Cross-Site Scripting", not "XSS").',
    '',
    '**Description** (`cna.descriptions[0].value`):',
    '- Plain English. No raw PoCs, exploit code, or step-by-step attack walkthroughs. Those belong in the advisory body, not the CVE record.',
    '- No em-dashes (—) or en-dashes (–). Use periods or commas instead.',
    '- No references to other private advisories (consumers cannot see them).',
    '- URLs do **not** belong in the description prose. They live in `cna.references[]`. Flag any that leaked in.',
    '- Match the tone of prior published advisories: short, neutral, factual. No alarmist language ("catastrophic", "blocks the entire event loop"). State facts.',
    '- Sections (Impact / Patches / Workarounds) should be labelled clearly and read as standalone paragraphs.',
    '',
    '**General**:',
    '- Confusing or ambiguous wording is a defect. Flag it.',
    '- Inconsistencies between the title, description, and the facts block (affected, CWE, CVSS) are also defects.',
    '- Do not invent facts. If a guideline cannot be evaluated from the text alone, say so.',
    '',
    '## Record context',
    ''
  )
  if (cveId) lines.push(`- **CVE**: ${cveId}`)
  if (affected.length > 0) lines.push(`- **Affected**: ${affected.join('; ')}`)
  if (cvss) lines.push(`- **${cvss.label}**: ${cvss.body}`)
  if (cwes.length > 0) lines.push(`- **CWE**: ${cwes.join(', ')}`)
  lines.push(
    '',
    '## Title to audit',
    '',
    '```',
    title,
    '```',
    '',
    '## Description (plain-text value)',
    '',
    '```',
    value,
    '```'
  )
  if (markdown) {
    lines.push(
      '',
      '## Description (original Markdown, from supportingMedia)',
      '',
      '```markdown',
      markdown,
      '```'
    )
  }
  lines.push(
    '',
    '## Respond in this exact Markdown shape',
    '',
    '```markdown',
    '**Rating**: ready | needs-work | blocked',
    '',
    '### Issues',
    '',
    '- **[field]** *(severity: blocker | warning | suggestion)*: what is wrong, in one sentence.',
    '  - **Suggested rewrite**: a concrete replacement, OR "n/a" if the issue is about deletion / structure rather than wording.',
    '',
    '(Omit the Issues section entirely if Rating is "ready".)',
    '',
    '### Rewritten title (only if the title needs work)',
    '',
    'Single-line suggested replacement.',
    '',
    '### Rewritten description (only if the description needs material edits)',
    '',
    'A full replacement, in the same plain-text style as the original.',
    '```',
    ''
  )
  return lines.join('\n')
}
