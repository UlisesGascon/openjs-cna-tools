// CVSS v3.0 / v3.1 base score calculator.
//
// Vulnerability trackers often store only the vector string, while MITRE's
// record format requires `baseScore` and `baseSeverity` on every CVSS
// block. This module derives both from the vector so converters never have
// to guess or call out to a third-party calculator, and so the reviewer can
// verify that a submitted score actually matches its vector.
//
// Only the base metric group is scored. Temporal and environmental metrics
// that may follow in the vector are preserved in the string but ignored.

const SUPPORTED_VERSIONS = new Set(['3.0', '3.1'])

const WEIGHTS = {
  AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 },
  AC: { L: 0.77, H: 0.44 },
  // Privileges Required depends on Scope: [unchanged, changed].
  PR: { N: [0.85, 0.85], L: [0.62, 0.68], H: [0.27, 0.5] },
  UI: { N: 0.85, R: 0.62 },
  S: { U: 'U', C: 'C' },
  C: { H: 0.56, L: 0.22, N: 0 },
  I: { H: 0.56, L: 0.22, N: 0 },
  A: { H: 0.56, L: 0.22, N: 0 }
}

const BASE_METRICS = ['AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A']

/**
 * Parse a CVSS v3.x vector string into its version and metrics.
 * Throws on unsupported versions and on missing or invalid base metrics.
 */
export function parseCvssVector (vectorString) {
  const text = String(vectorString || '').trim()
  const match = text.match(/^CVSS:(3\.[01])\/(.+)$/)
  if (!match) {
    throw new Error(`Unsupported CVSS vector: ${JSON.stringify(vectorString)}`)
  }
  const [, version, body] = match
  if (!SUPPORTED_VERSIONS.has(version)) {
    throw new Error(`Unsupported CVSS version ${version}`)
  }
  const metrics = {}
  for (const part of body.split('/')) {
    const [key, value] = part.split(':')
    if (!key || value === undefined) {
      throw new Error(`Malformed CVSS component ${JSON.stringify(part)}`)
    }
    metrics[key] = value
  }
  for (const key of BASE_METRICS) {
    if (!metrics[key] || !Object.hasOwn(WEIGHTS[key], metrics[key])) {
      throw new Error(`CVSS vector is missing or has an invalid ${key} metric`)
    }
  }
  return { version, vectorString: text, metrics }
}

/**
 * CVSS v3.1 "Roundup": smallest number, to one decimal place, that is equal
 * to or higher than the input. v3.1 specified an integer-based algorithm to
 * avoid floating-point surprises; it yields the same results as the v3.0
 * definition for every realistic input, so it is used for both versions.
 */
export function roundUp (value) {
  const scaled = Math.round(value * 100000)
  if (scaled % 10000 === 0) return scaled / 100000
  return (Math.floor(scaled / 10000) + 1) / 10
}

/** Qualitative severity band for a base score (shared by v3.0, v3.1 and v4.0). */
export function severityFromScore (score) {
  if (score === 0) return 'NONE'
  if (score < 4) return 'LOW'
  if (score < 7) return 'MEDIUM'
  if (score < 9) return 'HIGH'
  return 'CRITICAL'
}

/**
 * Compute the base score and severity of a CVSS v3.0 / v3.1 vector.
 * Returns `{ version, vectorString, baseScore, baseSeverity }`.
 */
export function calculateBaseScore (vectorString) {
  const { version, metrics, vectorString: text } = parseCvssVector(vectorString)
  const scopeChanged = metrics.S === 'C'
  const iss = 1 - (
    (1 - WEIGHTS.C[metrics.C]) *
    (1 - WEIGHTS.I[metrics.I]) *
    (1 - WEIGHTS.A[metrics.A])
  )
  const impact = scopeChanged
    ? 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
    : 6.42 * iss
  const exploitability = 8.22 *
    WEIGHTS.AV[metrics.AV] *
    WEIGHTS.AC[metrics.AC] *
    WEIGHTS.PR[metrics.PR][scopeChanged ? 1 : 0] *
    WEIGHTS.UI[metrics.UI]

  let baseScore = 0
  if (impact > 0) {
    baseScore = scopeChanged
      ? roundUp(Math.min(1.08 * (impact + exploitability), 10))
      : roundUp(Math.min(impact + exploitability, 10))
  }

  return {
    version,
    vectorString: text,
    baseScore,
    baseSeverity: severityFromScore(baseScore)
  }
}
