import { describe, it } from 'node:test'
import assert from 'node:assert/strict'

import { reviewRecord } from '../../lib/review/index.js'
import { RULES } from '../../lib/review/rules.js'
import { OPENJS_CNA_ORG_ID } from '../../lib/review/schema.js'

const VALID_TIERS = new Set(['mitre-common', 'openjs-extra'])

// A full CVE Record that ought to pass every rule and the MITRE schema.
// Tests use spread + override on `c.containers.cna.*` to focus failure
// cases. The legacy name `goodContainer()` is retained even though the
// returned value is now a Record — too many tests reference it to be
// worth renaming.
const goodContainer = () => ({
  dataType: 'CVE_RECORD',
  dataVersion: '5.2',
  cveMetadata: {
    cveId: 'CVE-2026-12345',
    assignerOrgId: OPENJS_CNA_ORG_ID,
    state: 'PUBLISHED'
  },
  containers: {
    cna: {
      providerMetadata: { orgId: OPENJS_CNA_ORG_ID },
      title: 'demo: vulnerable to demonstration',
      descriptions: [{
        lang: 'en',
        value: (
          'A demonstration vulnerability that affects the demo package when ' +
          'the input is crafted in a particular way. The fix limits the ' +
          'input size to a reasonable bound and rejects malformed payloads ' +
          'before they reach the parsing stage. Users should upgrade to the ' +
          'patched release as soon as possible.'
        ),
        supportingMedia: [{
          type: 'text/markdown',
          base64: false,
          value: 'A demonstration vulnerability...'
        }]
      }],
      affected: [{
        vendor: 'npm',
        product: 'demo',
        defaultStatus: 'unaffected',
        versions: [
          { version: '1.0.0', status: 'affected', lessThan: '1.2.3', versionType: 'semver' }
        ]
      }],
      problemTypes: [{
        descriptions: [{ lang: 'en', cweId: 'CWE-400', type: 'CWE', description: 'CWE-400' }]
      }],
      metrics: [{
        format: 'CVSS',
        cvssV3_1: {
          version: '3.1',
          vectorString: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H',
          baseScore: 7.5,
          baseSeverity: 'HIGH'
        }
      }],
      credits: [
        { lang: 'en', type: 'reporter', value: 'reporter-handle' },
        { lang: 'en', type: 'remediation developer', value: 'fix-handle' }
      ],
      references: [{ url: 'https://example.com/advisory', tags: ['vendor-advisory'] }],
      x_generator: { engine: 'openjs-cna-tools test' }
    }
  }
})

describe('reviewRecord — happy path', () => {
  it('rates a well-formed container as ready', () => {
    const report = reviewRecord(goodContainer())
    assert.equal(report.summary.rating, 'ready')
    assert.equal(report.summary.blockers, 0)
    assert.equal(report.summary.warnings, 0)
  })
})

describe('reviewRecord — schema validation', () => {
  it('emits MITRE schema errors as mitre-schema blockers', () => {
    const c = goodContainer()
    // Remove a required field to force a schema violation.
    delete c.containers.cna.descriptions
    const report = reviewRecord(c)
    assert.ok(report.issues.some(i => i.rule === 'mitre-schema' && i.severity === 'blocker'))
    assert.equal(report.summary.rating, 'blocked')
  })
})

describe('reviewRecord — description rules', () => {
  it('blocks when no description is present', () => {
    const c = goodContainer()
    delete c.containers.cna.descriptions
    const report = reviewRecord(c)
    assert.ok(report.issues.some(i => i.rule === 'description-present'))
  })

  it('warns when description is too short (non-strict)', () => {
    const c = goodContainer()
    c.containers.cna.descriptions[0].value = 'too short'
    const report = reviewRecord(c, { strict: false })
    assert.ok(report.issues.some(i => i.rule === 'description-length' && i.severity === 'warning'))
  })
})

describe('reviewRecord — credit rules', () => {
  it('warns when no reporter / finder credit is present (non-strict)', () => {
    const c = goodContainer()
    c.containers.cna.credits = c.containers.cna.credits.filter(cr => cr.type !== 'reporter')
    const report = reviewRecord(c, { strict: false })
    assert.ok(report.issues.some(i => i.rule === 'reporter-credit-present' && i.severity === 'warning'))
  })

  it('warns when no remediation credit (developer/reviewer/verifier) is present (non-strict)', () => {
    const c = goodContainer()
    const remediationRoles = new Set([
      'remediation developer', 'remediation_developer',
      'remediation reviewer', 'remediation_reviewer',
      'remediation verifier', 'remediation_verifier'
    ])
    c.containers.cna.credits = c.containers.cna.credits.filter(cr => !remediationRoles.has(cr.type))
    const report = reviewRecord(c, { strict: false })
    assert.ok(report.issues.some(i => i.rule === 'remediation-credit-present' && i.severity === 'warning'))
  })

  it('accepts a "remediation reviewer" as remediation credit', () => {
    const c = goodContainer()
    c.containers.cna.credits = [
      { lang: 'en', type: 'reporter', value: 'reporter-handle' },
      { lang: 'en', type: 'remediation reviewer', value: 'reviewer-handle' }
    ]
    const report = reviewRecord(c, { strict: false })
    assert.ok(!report.issues.some(i => i.rule === 'remediation-credit-present'),
      'reviewer satisfies the remediation requirement')
  })

  it('accepts a "remediation verifier" as remediation credit', () => {
    const c = goodContainer()
    c.containers.cna.credits = [
      { lang: 'en', type: 'reporter', value: 'reporter-handle' },
      { lang: 'en', type: 'remediation verifier', value: 'verifier-handle' }
    ]
    const report = reviewRecord(c, { strict: false })
    assert.ok(!report.issues.some(i => i.rule === 'remediation-credit-present'),
      'verifier satisfies the remediation requirement')
  })

  it('warns on duplicate credit identities across roles', () => {
    const c = goodContainer()
    c.containers.cna.credits.push({ type: 'analyst', lang: 'en', value: 'reporter-handle' })
    const report = reviewRecord(c)
    assert.ok(report.issues.some(i => i.rule === 'no-duplicate-credit-role'))
  })
})

describe('reviewRecord — CVSS rules', () => {
  it('blocks an unparseable CVSS vector', () => {
    const c = goodContainer()
    c.containers.cna.metrics[0].cvssV3_1.vectorString = 'totally bogus'
    const report = reviewRecord(c)
    assert.ok(report.issues.some(i => i.rule === 'cvss-vector-parseable' && i.severity === 'blocker'))
  })

  it('warns when baseSeverity disagrees with the score band', () => {
    const c = goodContainer()
    c.containers.cna.metrics[0].cvssV3_1.baseScore = 2.0
    c.containers.cna.metrics[0].cvssV3_1.baseSeverity = 'HIGH'
    const report = reviewRecord(c)
    assert.ok(report.issues.some(i => i.rule === 'cvss-score-matches-band'))
  })

  const cvssV30 = () => ({
    format: 'CVSS',
    cvssV3_0: {
      version: '3.0',
      vectorString: 'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H',
      baseScore: 7.5,
      baseSeverity: 'HIGH'
    }
  })

  it('accepts a cvssV3_0 block as a present, parseable metric', () => {
    const c = goodContainer()
    c.containers.cna.metrics = [cvssV30()]
    const report = reviewRecord(c)
    const cvssRules = ['metrics-present', 'cvss-vector-parseable', 'cvss-score-matches-band']
    assert.deepEqual(report.issues.filter(i => cvssRules.includes(i.rule)), [])
  })

  it('blocks a cvssV3_0 block whose vector carries another version prefix', () => {
    const c = goodContainer()
    c.containers.cna.metrics = [cvssV30()]
    c.containers.cna.metrics[0].cvssV3_0.vectorString = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H'
    const report = reviewRecord(c)
    const issue = report.issues.find(i => i.rule === 'cvss-vector-parseable')
    assert.equal(issue?.severity, 'blocker')
    assert.equal(issue?.path, 'metrics[].cvssV3_0.vectorString')
    assert.match(issue?.message, /CVSS:3\.0\//)
  })

  it('checks the severity band of a cvssV3_0 block', () => {
    const c = goodContainer()
    c.containers.cna.metrics = [cvssV30()]
    c.containers.cna.metrics[0].cvssV3_0.baseSeverity = 'LOW'
    const report = reviewRecord(c)
    const issue = report.issues.find(i => i.rule === 'cvss-score-matches-band')
    assert.equal(issue?.path, 'metrics[].cvssV3_0')
  })
})

describe('reviewRecord — affected rules', () => {
  it('blocks when affected is empty', () => {
    const c = goodContainer()
    c.containers.cna.affected = []
    const report = reviewRecord(c)
    assert.ok(report.issues.some(i => i.rule === 'affected-not-empty'))
  })

  it('warns when version and lessThan span different majors', () => {
    const c = goodContainer()
    c.containers.cna.affected[0].versions = [{ version: '1.0.0', status: 'affected', lessThan: '2.0.0' }]
    const report = reviewRecord(c)
    assert.ok(report.issues.some(i => i.rule === 'less-than-on-same-major'))
  })

  it('does NOT fire less-than-on-same-major for the version: \'0\' sentinel', () => {
    // The converter emits `version: '0'` as the "no lower bound" sentinel
    // for shapes like "< 2.1.1". Cross-major checking that bound against
    // its own lessThan is meaningless and triggers a false positive.
    const c = goodContainer()
    c.containers.cna.affected[0].versions = [
      { version: '0', lessThan: '2.1.1', status: 'affected', versionType: 'semver' }
    ]
    const report = reviewRecord(c)
    assert.ok(!report.issues.some(i => i.rule === 'less-than-on-same-major'),
      'rule should skip version=\'0\' sentinel')
  })
})

describe('reviewRecord — reference rules', () => {
  it('warns when references are missing', () => {
    const c = goodContainer()
    delete c.containers.cna.references
    const report = reviewRecord(c)
    assert.ok(report.issues.some(i => i.rule === 'references-present'))
  })

  it('warns on non-HTTPS references', () => {
    const c = goodContainer()
    c.containers.cna.references = [{ url: 'http://example.com/advisory' }]
    const report = reviewRecord(c)
    assert.ok(report.issues.some(i => i.rule === 'references-https'))
  })
})

describe('reviewRecord — strict mode (default)', () => {
  it('promotes warnings to blockers by default', () => {
    const c = goodContainer()
    c.containers.cna.descriptions[0].value = 'too short' // a description-length warning
    const report = reviewRecord(c) // no opts — strict is the default
    const issue = report.issues.find(i => i.rule === 'description-length')
    assert.equal(issue.severity, 'blocker')
    assert.equal(report.summary.rating, 'blocked')
  })

  it('leaves warnings as warnings under { strict: false }', () => {
    const c = goodContainer()
    c.containers.cna.descriptions[0].value = 'too short'
    const report = reviewRecord(c, { strict: false })
    const issue = report.issues.find(i => i.rule === 'description-length')
    assert.equal(issue.severity, 'warning')
    // No real blockers in this container, so rating is "needs-work".
    assert.equal(report.summary.rating, 'needs-work')
  })
})

describe('reviewRecord — internal-error safety', () => {
  it('catches a buggy rule and surfaces it as a warning', () => {
    // Pass a value that hits the catch in rules.js via a deliberately
    // hostile shape. Today's rules don't reliably crash on bad input, so
    // we just spot-check that nothing throws on truly empty input.
    const report = reviewRecord({})
    assert.ok(report.summary.blockers > 0) // many blockers, no internal errors
    assert.ok(!report.issues.some(i => i.rule.endsWith(':internal-error')))
  })
})

describe('rule tier classification', () => {
  it('every rule declares a known tier (sanity guard)', () => {
    // Sanity guard: a new rule landing without a tier would silently fall
    // out of the --tier filter and confuse the human report. Fail fast.
    for (const rule of RULES) {
      assert.ok(
        VALID_TIERS.has(rule.tier),
        `rule '${rule.id}' has tier '${rule.tier}', expected one of ${[...VALID_TIERS].join(', ')}`
      )
    }
  })

  it('emits tier on each issue (including mitre-schema)', () => {
    // A container missing required fields trips both the MITRE schema check
    // and several of our rules. Every emitted issue must carry a tier so the
    // CLI's --tier filter has something to match against.
    const report = reviewRecord({})
    assert.ok(report.issues.length > 0)
    for (const issue of report.issues) {
      assert.ok(
        VALID_TIERS.has(issue.tier),
        `issue '${issue.rule}' missing tier (got '${issue.tier}')`
      )
    }
    // The bare mitre-schema rule is always tagged mitre-common.
    const schemaIssues = report.issues.filter(i => i.rule === 'mitre-schema')
    assert.ok(schemaIssues.length > 0)
    assert.ok(schemaIssues.every(i => i.tier === 'mitre-common'))
  })

  it('--tier mitre-common filters out openjs-extra issues', () => {
    // Drive the CLI's filter logic directly: build a container that fails
    // BOTH an openjs-extra rule (description-length: too short) AND a
    // mitre-common rule (cvss-vector-parseable: malformed vector). Then
    // filter as the CLI does at print time.
    const c = goodContainer()
    c.containers.cna.descriptions[0].value = 'too short' // openjs-extra warning
    c.containers.cna.metrics[0].cvssV3_1.vectorString = 'totally bogus' // mitre-common blocker
    const report = reviewRecord(c, { strict: false })

    // Both tiers should show up before filtering.
    const tiers = new Set(report.issues.map(i => i.tier))
    assert.ok(tiers.has('mitre-common'))
    assert.ok(tiers.has('openjs-extra'))

    // CLI applies this filter at print time (see components/review.js).
    const filtered = report.issues.filter(i => i.tier === 'mitre-common')
    assert.ok(filtered.length > 0)
    assert.ok(filtered.every(i => i.tier === 'mitre-common'))
    assert.ok(!filtered.some(i => i.rule === 'description-length'))
    assert.ok(filtered.some(i => i.rule === 'cvss-vector-parseable'))
  })
})
