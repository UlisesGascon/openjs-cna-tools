import { describe, it } from 'node:test'
import assert from 'node:assert/strict'

import {
  mapAdvisoryToRecord,
  parseAdvisoryUrl,
  ENGINE_ID
} from '../../lib/convert/ghsa.js'

// Sample GHSA advisory in the shape the GitHub REST API returns. Tests
// override fields per case to focus the assertion.
const sampleAdvisory = () => ({
  ghsa_id: 'GHSA-xxxx-xxxx-xxxx',
  summary: 'demo: vulnerable to demonstration',
  description: (
    'A demonstration vulnerability that affects the demo package when ' +
    'the input is crafted in a particular way. The fix limits the input ' +
    'size to a reasonable bound.'
  ),
  vulnerabilities: [{
    package: { ecosystem: 'npm', name: 'demo' },
    vulnerable_version_range: '< 1.2.3',
    patched_versions: '1.2.3'
  }],
  cvss: {
    vector_string: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H',
    score: 7.5
  },
  cwes: [
    { cwe_id: 'CWE-400', name: 'Uncontrolled Resource Consumption' }
  ],
  credits: [
    { user: { login: 'reporter-handle' }, type: 'finder' },
    { user: { login: 'fix-handle' }, type: 'remediation_developer' }
  ],
  references: [
    { url: 'https://github.com/demo/demo/security/advisories/GHSA-xxxx-xxxx-xxxx' }
  ]
})

describe('parseAdvisoryUrl', () => {
  it('parses a per-repository advisory URL', () => {
    const result = parseAdvisoryUrl(
      'https://github.com/nodejs/undici/security/advisories/GHSA-vxpw-j846-p89q'
    )
    assert.deepEqual(result, {
      kind: 'repo',
      owner: 'nodejs',
      repo: 'undici',
      ghsaId: 'GHSA-vxpw-j846-p89q'
    })
  })

  it('parses a global database advisory URL', () => {
    const result = parseAdvisoryUrl(
      'https://github.com/advisories/GHSA-vxpw-j846-p89q'
    )
    assert.deepEqual(result, {
      kind: 'global',
      ghsaId: 'GHSA-vxpw-j846-p89q'
    })
  })

  it('parses per-repo URLs that have a trailing path or query', () => {
    const result = parseAdvisoryUrl(
      'https://github.com/expressjs/express/security/advisories/GHSA-aaaa-bbbb-cccc?utm=x'
    )
    assert.equal(result.kind, 'repo')
    assert.equal(result.owner, 'expressjs')
    assert.equal(result.repo, 'express')
    assert.equal(result.ghsaId, 'GHSA-aaaa-bbbb-cccc')
  })

  it('parses global URLs that have a trailing path or query', () => {
    const result = parseAdvisoryUrl(
      'https://github.com/advisories/GHSA-aaaa-bbbb-cccc?ref=registry'
    )
    assert.equal(result.kind, 'global')
    assert.equal(result.ghsaId, 'GHSA-aaaa-bbbb-cccc')
  })

  it('returns null for a bare GHSA id (URL is required now)', () => {
    assert.equal(parseAdvisoryUrl('GHSA-xxxx-xxxx-xxxx'), null)
  })

  it('returns null for a non-advisory URL', () => {
    assert.equal(parseAdvisoryUrl('https://example.com/foo'), null)
    assert.equal(parseAdvisoryUrl('https://github.com/nodejs/undici'), null)
  })

  it('returns null for non-string input', () => {
    assert.equal(parseAdvisoryUrl(undefined), null)
    assert.equal(parseAdvisoryUrl(null), null)
    assert.equal(parseAdvisoryUrl(42), null)
  })
})

describe('mapAdvisoryToRecord — shape', () => {
  it('leaves cveMetadata.cveId unset when the advisory carries no cve_id', () => {
    const c = mapAdvisoryToRecord(sampleAdvisory())
    assert.equal(c.cveMetadata?.cveId, undefined)
  })

  it('stamps cveMetadata.cveId automatically when advisory.cve_id is set', () => {
    const advisory = { ...sampleAdvisory(), cve_id: 'CVE-2026-3520' }
    const c = mapAdvisoryToRecord(advisory)
    assert.equal(c.cveMetadata?.cveId, 'CVE-2026-3520')
  })

  it('lets caller pass cveId as a safety belt when advisory has none', () => {
    const c = mapAdvisoryToRecord(sampleAdvisory(), { cveId: 'CVE-2026-9999' })
    assert.equal(c.cveMetadata?.cveId, 'CVE-2026-9999')
  })

  it('throws on cveId mismatch between caller and advisory.cve_id', () => {
    const advisory = { ...sampleAdvisory(), cve_id: 'CVE-2026-3520' }
    assert.throws(
      () => mapAdvisoryToRecord(advisory, { cveId: 'CVE-2026-0001' }),
      /CVE id mismatch/
    )
  })

  it('accepts caller cveId when it matches advisory.cve_id', () => {
    const advisory = { ...sampleAdvisory(), cve_id: 'CVE-2026-3520' }
    const c = mapAdvisoryToRecord(advisory, { cveId: 'CVE-2026-3520' })
    assert.equal(c.cveMetadata?.cveId, 'CVE-2026-3520')
  })

  it('sets x_generator.engine from the package name + version', () => {
    const c = mapAdvisoryToRecord(sampleAdvisory())
    assert.ok(c.containers.cna.x_generator)
    assert.equal(c.containers.cna.x_generator.engine, ENGINE_ID)
    assert.match(c.containers.cna.x_generator.engine, /^@openjsfoundation\/cna-tools \d+\.\d+\.\d+/)
  })

  it('allows overriding x_generator.engine via engineId option', () => {
    const c = mapAdvisoryToRecord(sampleAdvisory(), { engineId: 'custom-tool 1.2.3' })
    assert.equal(c.containers.cna.x_generator.engine, 'custom-tool 1.2.3')
  })

  it('keeps the title from the GHSA summary', () => {
    const c = mapAdvisoryToRecord(sampleAdvisory())
    assert.equal(c.containers.cna.title, 'demo: vulnerable to demonstration')
  })
})

describe('mapAdvisoryToRecord — descriptions (markdown)', () => {
  it('puts the description text in value', () => {
    const c = mapAdvisoryToRecord(sampleAdvisory())
    assert.equal(c.containers.cna.descriptions[0].lang, 'en')
    assert.match(c.containers.cna.descriptions[0].value, /demonstration vulnerability/)
  })

  it('strips Markdown from descriptions[0].value (plain text only)', () => {
    const advisory = sampleAdvisory()
    advisory.description = [
      '### Impact',
      '',
      'A **bug** affects `pkg` versions <1.2.3.',
      '',
      '### Patches',
      '',
      'Upgrade to `1.2.3`.',
      '',
      '### References',
      '',
      '- https://example.com/should-not-appear-in-description'
    ].join('\n')
    const c = mapAdvisoryToRecord(advisory)
    const value = c.containers.cna.descriptions[0].value
    assert.ok(!/^#{1,6}\s/m.test(value), 'no markdown headers')
    assert.ok(!/\*\*/.test(value), 'no bold markers')
    assert.ok(!/`/.test(value), 'no inline-code backticks')
    assert.ok(/Impact:/.test(value), 'header → "Impact:" label')
    assert.ok(/Patches:/.test(value), 'header → "Patches:" label')
    assert.ok(!/References:/i.test(value),
      'References section dropped (URLs belong in cna.references[])')
    assert.ok(!/should-not-appear-in-description/.test(value),
      'References URLs dropped from description value')
    assert.ok(/A bug affects pkg versions/.test(value), 'inline markdown collapsed')
  })

  it('drops the References section from supportingMedia too', () => {
    const advisory = sampleAdvisory()
    advisory.description = [
      '### Impact',
      '',
      'A **bug** affects `pkg`.',
      '',
      '### References',
      '',
      '- https://example.com/should-not-appear-in-supportingMedia'
    ].join('\n')
    const c = mapAdvisoryToRecord(advisory)
    const media = c.containers.cna.descriptions[0].supportingMedia?.[0]
    assert.ok(media, 'supportingMedia present (raw retained markdown structure)')
    assert.ok(!/References/i.test(media.value),
      'References heading dropped from supportingMedia value')
    assert.ok(!/should-not-appear-in-supportingMedia/.test(media.value),
      'References URLs dropped from supportingMedia value')
    assert.ok(/### Impact/.test(media.value),
      'non-References sections kept as raw Markdown')
  })

  it('still routes the description References URLs into cna.references[]', () => {
    const advisory = sampleAdvisory()
    // No API references[]; the description is the only source.
    advisory.references = null
    advisory.description = [
      '### Impact',
      '',
      'A bug.',
      '',
      '### References',
      '',
      '- https://example.com/from-description-only'
    ].join('\n')
    const c = mapAdvisoryToRecord(advisory)
    const urls = (c.containers.cna.references ?? []).map(r => r.url)
    assert.ok(urls.includes('https://example.com/from-description-only'),
      'URL from description References block surfaced in cna.references[]')
  })

  it('preserves the original Markdown in supportingMedia[0]', () => {
    const advisory = sampleAdvisory()
    advisory.description = '### Impact\n\nA **bug**.'
    const c = mapAdvisoryToRecord(advisory)
    const media = c.containers.cna.descriptions[0].supportingMedia[0]
    assert.equal(media.type, 'text/markdown')
    assert.equal(media.base64, false)
    assert.equal(media.value, '### Impact\n\nA **bug**.')
  })

  it('omits supportingMedia when the source has no Markdown formatting', () => {
    const advisory = sampleAdvisory()
    advisory.description = 'Just plain text, no markdown at all.'
    const c = mapAdvisoryToRecord(advisory)
    assert.equal(c.containers.cna.descriptions[0].supportingMedia, undefined,
      'no markdown → no supportingMedia entry')
  })

  it('falls back to summary when description is empty', () => {
    const advisory = sampleAdvisory()
    advisory.description = ''
    const c = mapAdvisoryToRecord(advisory)
    assert.equal(c.containers.cna.descriptions[0].value, advisory.summary)
  })

  it('emits empty descriptions when both summary and description are blank', () => {
    const advisory = sampleAdvisory()
    advisory.description = ''
    advisory.summary = ''
    const c = mapAdvisoryToRecord(advisory)
    assert.deepEqual(c.containers.cna.descriptions, [])
  })
})

describe('mapAdvisoryToRecord — credits', () => {
  it('maps credits with the MITRE space-separated type vocabulary', () => {
    const c = mapAdvisoryToRecord(sampleAdvisory())
    const types = c.containers.cna.credits.map(cr => cr.type)
    assert.ok(types.includes('finder'))
    assert.ok(types.includes('remediation developer'))
  })

  it('puts the GitHub login in value (not user — user requires UUID)', () => {
    const c = mapAdvisoryToRecord(sampleAdvisory())
    const finder = c.containers.cna.credits.find(cr => cr.type === 'finder')
    assert.equal(finder.value, 'reporter-handle')
    assert.equal(finder.user, undefined)
  })

  it('maps every snake_case GHSA role to its MITRE space-separated form', () => {
    const advisory = sampleAdvisory()
    advisory.credits = [
      { user: { login: 'u1' }, type: 'reporter' },
      { user: { login: 'u2' }, type: 'analyst' },
      { user: { login: 'u3' }, type: 'remediation_reviewer' },
      { user: { login: 'u4' }, type: 'remediation_verifier' },
      { user: { login: 'u5' }, type: 'coordinator' }
    ]
    const c = mapAdvisoryToRecord(advisory)
    const types = c.containers.cna.credits.map(cr => cr.type).sort()
    assert.deepEqual(types, [
      'analyst', 'coordinator', 'remediation reviewer', 'remediation verifier', 'reporter'
    ])
  })

  it('falls back to "other" for unknown GHSA roles', () => {
    const advisory = sampleAdvisory()
    advisory.credits = [{ user: { login: 'u1' }, type: 'made_up_role' }]
    const c = mapAdvisoryToRecord(advisory)
    assert.equal(c.containers.cna.credits[0].type, 'other')
  })

  it('handles credits whose user is already a string login', () => {
    const advisory = sampleAdvisory()
    advisory.credits = [{ user: 'plain-string-login', type: 'finder' }]
    const c = mapAdvisoryToRecord(advisory)
    assert.equal(c.containers.cna.credits[0].value, 'plain-string-login')
  })

  it('reads the per-repo `{ login, type }` shape (no user wrapper)', () => {
    // Per-repo /security-advisories/{ghsa} returns credits as bare
    // { login, type } objects rather than the global API's
    // { user: { login }, type }.
    const advisory = sampleAdvisory()
    advisory.credits = [
      { login: 'reporter-login', type: 'reporter' },
      { login: 'fixer-login', type: 'remediation_developer' }
    ]
    advisory.credits_detailed = []
    const c = mapAdvisoryToRecord(advisory)
    const reporter = c.containers.cna.credits.find(cr => cr.type === 'reporter')
    const fixer = c.containers.cna.credits.find(cr => cr.type === 'remediation developer')
    assert.equal(reporter.value, 'reporter-login')
    assert.equal(fixer.value, 'fixer-login')
  })

  it('prefers credits_detailed over credits when both are present (per-repo richer shape)', () => {
    const advisory = sampleAdvisory()
    // Per-repo emits a thin `credits` AND a rich `credits_detailed`. We
    // should pick the rich one because it carries more.
    advisory.credits = [{ login: 'thin-login', type: 'finder' }]
    advisory.credits_detailed = [{ user: { login: 'rich-login' }, type: 'finder' }]
    const c = mapAdvisoryToRecord(advisory)
    assert.equal(c.containers.cna.credits[0].value, 'rich-login')
  })

  it('omits credits when the advisory has no credits', () => {
    const advisory = sampleAdvisory()
    advisory.credits = []
    const c = mapAdvisoryToRecord(advisory)
    assert.equal(c.containers.cna.credits, undefined)
  })
})

describe('mapAdvisoryToRecord — CVSS metrics', () => {
  it('emits format: CVSS + cvssV3_1.version 3.1', () => {
    const c = mapAdvisoryToRecord(sampleAdvisory())
    assert.equal(c.containers.cna.metrics[0].format, 'CVSS')
    assert.equal(c.containers.cna.metrics[0].cvssV3_1.version, '3.1')
  })

  it('carries the vectorString and baseScore', () => {
    const c = mapAdvisoryToRecord(sampleAdvisory())
    assert.equal(c.containers.cna.metrics[0].cvssV3_1.vectorString,
      'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H')
    assert.equal(c.containers.cna.metrics[0].cvssV3_1.baseScore, 7.5)
  })

  it('omits metrics when the advisory has no CVSS vector', () => {
    const advisory = sampleAdvisory()
    advisory.cvss = undefined
    advisory.cvss_v3 = undefined
    const c = mapAdvisoryToRecord(advisory)
    assert.equal(c.containers.cna.metrics, undefined)
  })
})

describe('mapAdvisoryToRecord — problemTypes (CWE)', () => {
  it('maps CWE to v5.2 problemTypes shape', () => {
    const c = mapAdvisoryToRecord(sampleAdvisory())
    const description = c.containers.cna.problemTypes[0].descriptions[0]
    assert.equal(description.cweId, 'CWE-400')
    assert.equal(description.type, 'CWE')
    assert.equal(description.lang, 'en')
  })

  it('omits problemTypes when the advisory has no CWE entries', () => {
    const advisory = sampleAdvisory()
    advisory.cwes = []
    const c = mapAdvisoryToRecord(advisory)
    assert.equal(c.containers.cna.problemTypes, undefined)
  })
})

describe('mapAdvisoryToRecord — affected (with versionType)', () => {
  it('emits versionType: semver on every entry', () => {
    const c = mapAdvisoryToRecord(sampleAdvisory())
    assert.equal(c.containers.cna.affected[0].versions[0].versionType, 'semver')
  })

  it('maps affected with vendor=npm and expands the vulnerable_version_range', () => {
    const c = mapAdvisoryToRecord(sampleAdvisory())
    assert.equal(c.containers.cna.affected[0].vendor, 'npm')
    assert.equal(c.containers.cna.affected[0].product, 'demo')
    assert.equal(c.containers.cna.affected[0].defaultStatus, 'unaffected')
    // The sample advisory uses '< 1.2.3'. The parser at
    // lib/convert/version-range.js expands that to a structured pair
    // with `version: '0'` as the implicit lower bound and `lessThan`
    // as the upper.
    assert.deepEqual(c.containers.cna.affected[0].versions, [{
      version: '0',
      lessThan: '1.2.3',
      status: 'affected',
      versionType: 'semver'
    }])
  })
})

describe('mapAdvisoryToRecord — references (derived from advisory)', () => {
  it('falls back to the description "### References" section when references is null (per-repo)', () => {
    // Per-repo /security-advisories returns references: null. The actual
    // URLs live in the Markdown description under a "References" header.
    const advisory = {
      ...sampleAdvisory(),
      references: null,
      description: [
        '### Impact',
        '',
        'Some impact text.',
        '',
        '### References',
        '',
        '- https://github.com/expressjs/multer/security/advisories/GHSA-xxxx-xxxx-xxxx',
        '- https://www.cve.org/CVERecord?id=CVE-2026-3520',
        '- https://github.com/expressjs/multer/commit/abc123def456',
        '- https://cna.openjsf.org/security-advisories.html'
      ].join('\n')
    }
    const c = mapAdvisoryToRecord(advisory)
    const urls = c.containers.cna.references.map(r => r.url)
    assert.ok(urls.includes('https://github.com/expressjs/multer/security/advisories/GHSA-xxxx-xxxx-xxxx'))
    assert.ok(urls.includes('https://www.cve.org/CVERecord?id=CVE-2026-3520'))
    assert.ok(urls.includes('https://github.com/expressjs/multer/commit/abc123def456'))
    assert.ok(urls.includes('https://cna.openjsf.org/security-advisories.html'))
  })

  it('parses the **References** bold header too', () => {
    const advisory = {
      ...sampleAdvisory(),
      references: [],
      description: '**References**\n\n- https://example.com/x\n- https://example.com/y'
    }
    const c = mapAdvisoryToRecord(advisory)
    const urls = c.containers.cna.references.map(r => r.url).sort()
    assert.deepEqual(urls, ['https://example.com/x', 'https://example.com/y'])
  })

  it('stops at the next heading instead of pulling URLs from later sections', () => {
    const advisory = {
      ...sampleAdvisory(),
      references: [],
      description: [
        '### References',
        '',
        '- https://example.com/in-references',
        '',
        '### Follow-up',
        '',
        '- https://example.com/NOT-a-reference'
      ].join('\n')
    }
    const c = mapAdvisoryToRecord(advisory)
    const urls = c.containers.cna.references.map(r => r.url)
    assert.ok(urls.includes('https://example.com/in-references'))
    assert.ok(!urls.includes('https://example.com/NOT-a-reference'))
  })

  it('passes the GHSA references through verbatim', () => {
    const c = mapAdvisoryToRecord(sampleAdvisory())
    const urls = c.containers.cna.references.map(r => r.url)
    assert.ok(urls.includes('https://github.com/demo/demo/security/advisories/GHSA-xxxx-xxxx-xxxx'))
  })

  it('tags the canonical (self-reference) advisory URL as vendor-advisory', () => {
    // The advisory's own GitHub page is what we're publishing — the
    // OpenJS CNA is the vendor. Every other URL is left untagged so the
    // operator can hand-tag in Vulnogram before publish if needed.
    const advisory = sampleAdvisory() // ghsa_id: 'GHSA-xxxx-xxxx-xxxx'
    advisory.references = [
      { url: 'https://github.com/demo/demo/security/advisories/GHSA-xxxx-xxxx-xxxx' }
    ]
    const c = mapAdvisoryToRecord(advisory)
    assert.deepEqual(c.containers.cna.references[0].tags, ['vendor-advisory'])
  })

  it('leaves third-party GitHub advisory URLs (different GHSA) untagged', () => {
    const advisory = sampleAdvisory()
    advisory.references = [
      { url: 'https://github.com/other/repo/security/advisories/GHSA-aaaa-bbbb-cccc' }
    ]
    const c = mapAdvisoryToRecord(advisory)
    assert.equal(c.containers.cna.references[0].tags, undefined,
      'third-party advisory URLs are left untagged for the operator to classify')
  })

  it('leaves CVE / commit / blog URLs untagged (no auto-classification)', () => {
    const advisory = sampleAdvisory()
    advisory.references = [
      { url: 'https://www.cve.org/CVERecord?id=CVE-2026-3520' },
      { url: 'https://github.com/demo/demo/commit/7e66481f8b2e6c54b982b34c152479e096ce2752' },
      { url: 'https://nodejs.org/en/blog/vulnerability/april-2026-security-releases' }
    ]
    const c = mapAdvisoryToRecord(advisory)
    for (const ref of c.containers.cna.references) {
      assert.equal(ref.tags, undefined,
        `URL ${ref.url} should be left untagged (no auto-classification)`)
    }
  })

  it('omits tags for URLs that do not match a known pattern', () => {
    const advisory = sampleAdvisory()
    advisory.references = [{ url: 'https://example.com/random-page' }]
    const c = mapAdvisoryToRecord(advisory)
    assert.equal(c.containers.cna.references[0].url, 'https://example.com/random-page')
    assert.equal(c.containers.cna.references[0].tags, undefined)
  })

  it('handles references that are plain URL strings', () => {
    const advisory = sampleAdvisory()
    advisory.references = ['https://example.com/raw-ref-1', { url: 'https://example.com/object-ref' }]
    const c = mapAdvisoryToRecord(advisory)
    const urls = c.containers.cna.references.map(r => r.url)
    assert.ok(urls.includes('https://example.com/raw-ref-1'))
    assert.ok(urls.includes('https://example.com/object-ref'))
  })

  it('deduplicates references that appear more than once', () => {
    const advisory = sampleAdvisory()
    advisory.references = [
      { url: 'https://example.com/x' },
      'https://example.com/x',
      { url: 'https://example.com/x' }
    ]
    const c = mapAdvisoryToRecord(advisory)
    const urls = c.containers.cna.references.map(r => r.url)
    assert.equal(urls.filter(u => u === 'https://example.com/x').length, 1)
  })
})

describe('convertGhsaToRecord — fetch (no gh subprocess)', () => {
  it('routes per-repo URLs to /repos/.../security-advisories/<GHSA>', async () => {
    const calls = []
    const fetchImpl = async (url) => {
      calls.push(url)
      return { ok: true, json: async () => sampleAdvisory() }
    }
    await import('../../lib/convert/ghsa.js').then(({ convertGhsaToRecord }) =>
      convertGhsaToRecord({
        source: 'https://github.com/nodejs/undici/security/advisories/GHSA-xxxx-xxxx-xxxx',
        fetchImpl
      })
    )
    assert.equal(calls[0],
      'https://api.github.com/repos/nodejs/undici/security-advisories/GHSA-xxxx-xxxx-xxxx')
  })

  it('routes global URLs to /advisories/<GHSA>', async () => {
    const calls = []
    const fetchImpl = async (url) => {
      calls.push(url)
      return { ok: true, json: async () => sampleAdvisory() }
    }
    await import('../../lib/convert/ghsa.js').then(({ convertGhsaToRecord }) =>
      convertGhsaToRecord({
        source: 'https://github.com/advisories/GHSA-xxxx-xxxx-xxxx',
        fetchImpl
      })
    )
    assert.equal(calls[0], 'https://api.github.com/advisories/GHSA-xxxx-xxxx-xxxx')
  })

  it('throws on non-2xx with a message that points operators at the public-only limitation', async () => {
    const fetchImpl = async () => ({ ok: false, status: 404, json: async () => ({}) })
    const { convertGhsaToRecord } = await import('../../lib/convert/ghsa.js')
    await assert.rejects(
      () => convertGhsaToRecord({
        source: 'https://github.com/advisories/GHSA-xxxx-xxxx-xxxx',
        fetchImpl
      }),
      /GitHub returned 404.*public advisories/s
    )
  })
})

describe('mapAdvisoryToRecord — input validation', () => {
  it('throws when advisory is not an object', () => {
    assert.throws(() => mapAdvisoryToRecord(null), TypeError)
    assert.throws(() => mapAdvisoryToRecord('not-an-object'), TypeError)
  })
})
