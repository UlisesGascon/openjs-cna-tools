// HackerOne weakness ids -> CWE.
//
// HackerOne identifies a report's weakness by its own numeric id, which is
// what its REST API exposes as `weakness_id` and what projects end up
// storing. It is not a CWE number: weakness 26 is "Improper Access Control"
// (CWE-284), 48 is "Uncontrolled Resource Consumption" (CWE-400). The CWE
// is a separate attribute of the weakness, and HackerOne's taxonomy is the
// same for every program, so the mapping ships here as data
// (./weaknesses.json, regenerated with scripts/build-hackerone-weaknesses.js).

import { createRequire } from 'node:module'
import { buildProblemType } from '../record.js'

const require = createRequire(import.meta.url)
const { weaknesses, _generated: generated } = require('./weaknesses.json')

export const HACKERONE_WEAKNESSES_GENERATED = generated

/**
 * Look a HackerOne weakness id up. Accepts a number or a string.
 *
 * Returns `{ cwe, name }` where `cwe` is `CWE-<number>` or `null` for a
 * weakness HackerOne maps to no CWE (CAPEC entries), or `null` when the id
 * is unknown.
 */
export function hackerOneWeakness (id) {
  const key = String(id ?? '').trim()
  if (!/^\d+$/.test(key)) return null
  const entry = weaknesses[key]
  return entry ? { cwe: entry.cwe, name: entry.name } : null
}

/**
 * The `problemTypes[]` entry for a HackerOne weakness id, or `null` when
 * the id is unknown or has no CWE. The CWE name on the record is
 * HackerOne's weakness name.
 */
export function hackerOneWeaknessProblemType (id) {
  const entry = hackerOneWeakness(id)
  if (!entry?.cwe) return null
  return buildProblemType({ cweId: entry.cwe, name: entry.name })
}
