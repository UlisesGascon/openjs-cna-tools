// reviewRecord(record, { strict }) -> review report
//
// Sync, offline. Validates a full v5.2 CVE Record:
//   { dataType, dataVersion, cveMetadata, containers: { cna: {...} } }
//
// MITRE's official schema check (via ajv) runs against the whole Record;
// the editorial rules in ./rules.js then walk the inner cna container.

import { RULES } from './rules.js'
import { validateAgainstMitreSchema } from './schema.js'

// `strict` defaults to true because publishing to MITRE is irreversible:
// every warning the reviewer surfaces blocks until the operator opts out
// explicitly via `--no-strict` (CLI) or `{ strict: false }` (library).
export function reviewRecord (record, { strict = true } = {}) {
  const issues = []

  // MITRE schema first. Every schema violation is a blocker because
  // publish will fail downstream — there is no soft version of "doesn't
  // match the schema MITRE uses". One issue per ajv error so operators
  // see exactly what's wrong.
  for (const err of validateAgainstMitreSchema(record)) {
    issues.push({
      rule: 'mitre-schema',
      // Schema violations always fail at MITRE's end too.
      tier: 'mitre-common',
      severity: 'blocker',
      path: err.path,
      message: err.message
    })
  }

  // Editorial rules look at just the cna container — drill in once here.
  const cna = record?.containers?.cna ?? {}

  for (const rule of RULES) {
    let result
    try {
      result = rule.check(cna)
    } catch (e) {
      // A buggy rule shouldn't fail the review. Surface as a warning so the
      // operator knows to file an issue.
      issues.push({
        rule: `${rule.id}:internal-error`,
        // Carry the source rule's tier through so the --tier filter still
        // works in the unlikely event the rule itself blew up.
        tier: rule.tier,
        severity: 'warning',
        path: 'reviewer',
        message: `Rule '${rule.id}' threw: ${e.message}`
      })
      continue
    }
    if (result) {
      issues.push({
        rule: rule.id,
        tier: rule.tier,
        severity: strict && rule.severity === 'warning' ? 'blocker' : rule.severity,
        path: result.path,
        message: result.message
      })
    }
  }

  const blockers = issues.filter(i => i.severity === 'blocker').length
  const warnings = issues.filter(i => i.severity === 'warning').length
  const suggestions = issues.filter(i => i.severity === 'suggestion').length

  let rating
  if (blockers > 0) rating = 'blocked'
  else if (warnings > 0) rating = 'needs-work'
  else rating = 'ready'

  return {
    summary: { rating, blockers, warnings, suggestions, total: issues.length },
    issues
  }
}
