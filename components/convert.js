// openjs-cna convert <advisory-url> [--cve <CVE-...>]
//
// Reads a public GitHub Security Advisory and emits a v5.2 CNA Container
// draft on stdout. Two URL shapes accepted: per-repository and global-
// database. Pre-fetched JSON can be piped via stdin (`openjs-cna convert -`).
// When `--cve` is provided, the produced container carries
// `cveMetadata.cveId` so a downstream publish/update can cross-check the
// id against its CLI argument.

import { parseComponentArgs, buildCli, readFileOrStdin } from '../lib/component-utils.js'
import { convertGhsaToRecord } from '../lib/convert/ghsa.js'

export const command = 'convert'
export const describe = 'Convert a GitHub Security Advisory into a v5.2 CNA Container draft.'

export async function handler (argv) {
  const parsed = parseComponentArgs(argv, {
    cve: { type: 'string' }
  }, { allowPositionals: true })
  if (parsed.values.help) return printHelp()

  const cli = buildCli(parsed)
  const positional = parsed.positionals[0]

  let source
  if (positional === '-') {
    // Read raw GHSA JSON from stdin and pass through as a pre-fetched object.
    const raw = await readFileOrStdin('-')
    try { source = JSON.parse(raw) } catch (e) {
      process.stderr.write(`✖ stdin is not valid JSON: ${e.message}\n`)
      process.exit(64)
    }
  } else if (typeof positional === 'string' && positional.length > 0) {
    source = positional
  } else {
    process.stderr.write(
      '✖ Missing advisory URL. Usage:\n' +
      '    openjs-cna convert <advisory-url>\n' +
      '    openjs-cna convert -                  (read raw GHSA JSON from stdin)\n'
    )
    process.exit(64)
  }

  cli.info('Converting → CVE Record')
  const record = await convertGhsaToRecord({ source, cveId: parsed.values.cve })
  cli.ok('Conversion complete')
  process.stdout.write(JSON.stringify(record, null, 2) + '\n')
}

function printHelp () {
  process.stderr.write(
`openjs-cna convert <advisory-url>

Convert a GitHub Security Advisory into a v5.2 CNA Container draft. The
result is the CNA-container portion of a CVE Record (cveMetadata is
supplied by 'openjs-cna publish' at publish time). Output is a starting
point — run 'openjs-cna review' on it before publish.

This tool only reads PUBLIC published advisories. Both URL shapes hit
api.github.com anonymously.

Input shapes:

  openjs-cna convert https://github.com/<owner>/<repo>/security/advisories/<GHSA>
    Per-repository advisory URL. Resolves via
    GET https://api.github.com/repos/<owner>/<repo>/security-advisories/<GHSA>.

  openjs-cna convert https://github.com/advisories/<GHSA>
    Global advisory database URL. Resolves via
    GET https://api.github.com/advisories/<GHSA>.

  openjs-cna convert -
    Read raw GHSA advisory JSON from stdin (for pre-fetched payloads
    or private/draft advisories the operator has fetched themselves).

References for the CNA Container are derived from the advisory's
\`references[]\` array. Put your vendor-advisory URL there before
converting.
`
  )
}
