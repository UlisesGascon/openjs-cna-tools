// openjs-cna reserve
// Reserves a CVE id via the CNA API and prints it on stdout.

import { parseComponentArgs, buildClient, buildCli } from '../lib/component-utils.js'

export const command = 'reserve'
export const describe = 'Reserve a CVE id via the OpenJS Foundation CNA.'

export async function handler (argv) {
  const parsed = parseComponentArgs(argv)
  if (parsed.values.help) return printHelp()
  const cli = buildCli(parsed)
  const client = buildClient(parsed)

  cli.info('Reserving CVE…')
  const { cveId, correlationId, runId } = await client.reserveCve({
    onPoll: (run) => {
      if (run.status && run.status !== 'completed') {
        // Honest progress — one line per poll cycle, no animation.
        cli.info(`run status: ${run.status}`)
      }
    }
  })
  cli.ok(`Reserved ${cveId}`)
  if (correlationId || runId) {
    cli.info(`Forward to coordinator if needed: correlation_id=${correlationId ?? '?'}, run_id=${runId ?? '?'}`)
  }

  // Data on stdout, no decoration — `CVE=$(openjs-cna reserve)` Just Works.
  process.stdout.write(`${cveId}\n`)
}

function printHelp () {
  process.stderr.write(
`openjs-cna reserve

Reserve a CVE id from the configured bucket. Prints the CVE id on stdout
once the workflow completes.

Usage:
  openjs-cna reserve [global flags]

Example:
  CVE=$(openjs-cna reserve)
  openjs-cna publish "$CVE" -f container.json
`
  )
}
