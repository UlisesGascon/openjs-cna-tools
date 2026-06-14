// openjs-cna list
// Lists all CVE ids in the bucket. One id per line by default; --json for array.

import { parseComponentArgs, buildClient, buildCli } from '../lib/component-utils.js'

export const command = 'list'
export const describe = 'List all CVEs in the bucket.'

export async function handler (argv) {
  const parsed = parseComponentArgs(argv)
  if (parsed.values.help) return printHelp()
  const cli = buildCli(parsed)
  const client = buildClient(parsed)
  cli.info('Listing CVEs…')
  const ids = await client.listCves({
    onPoll: (run) => { if (run.status !== 'completed') cli.info(`run status: ${run.status}`) }
  })
  cli.ok(`Found ${ids.length} CVE id(s)`)
  if (parsed.values.json) {
    process.stdout.write(JSON.stringify(ids, null, 2) + '\n')
  } else {
    for (const id of ids) process.stdout.write(`${id}\n`)
  }
}

function printHelp () {
  process.stderr.write(
`openjs-cna list

List every CVE id in the bucket. Default output: one id per line.

Options:
  --json    emit a JSON array instead
`
  )
}
