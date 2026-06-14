// openjs-cna health
// Unauthenticated liveness check against the configured CNA API.

import { parseComponentArgs, buildClient, buildCli } from '../lib/component-utils.js'

export const command = 'health'
export const describe = 'Check that the CNA API is reachable.'

export async function handler (argv) {
  const parsed = parseComponentArgs(argv)
  if (parsed.values.help) return printHelp()
  const cli = buildCli(parsed)
  const client = buildClient(parsed)
  const status = await client.health()
  cli.ok(`API is reachable (${status?.status ?? 'ok'})`)
  process.stdout.write(JSON.stringify(status, null, 2) + '\n')
}

function printHelp () {
  process.stderr.write(
`openjs-cna health

Probe the configured CNA API's /health endpoint. Useful to catch base-url
misconfiguration before burning a workflow dispatch.

Usage:
  openjs-cna health [global flags]
`
  )
}
