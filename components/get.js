// openjs-cna get <cve-id>
// Fetches the v5.2 container for a published CVE from MITRE via the CNA API.

import { parseComponentArgs, buildClient, buildCli } from '../lib/component-utils.js'

export const command = 'get'
export const describe = 'Fetch the CNA Container for a published CVE.'

export async function handler (argv) {
  const parsed = parseComponentArgs(argv, {}, { allowPositionals: true })
  if (parsed.values.help) return printHelp()
  const cveId = parsed.positionals[0]
  if (!cveId) {
    process.stderr.write('✖ Missing CVE id. Usage: openjs-cna get <CVE-...>\n')
    process.exit(64)
  }
  const cli = buildCli(parsed)
  const client = buildClient(parsed)
  cli.info(`Fetching ${cveId}…`)
  const record = await client.getCve(cveId, {
    onPoll: (run) => { if (run.status !== 'completed') cli.info(`run status: ${run.status}`) }
  })
  cli.ok(`Got ${cveId}`)
  process.stdout.write(JSON.stringify(record, null, 2) + '\n')
}

function printHelp () {
  process.stderr.write(
`openjs-cna get <cve-id>

Fetch a published CVE's v5.2 container from MITRE. Prints the container
JSON on stdout.
`
  )
}
