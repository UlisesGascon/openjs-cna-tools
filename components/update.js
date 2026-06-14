// openjs-cna update <cve-id> [-f container.json] [--skip-review] [--no-strict]
//
// Same shape as `publish`, but issues the update-cve operation. Same
// cveMetadata.cveId cross-check, same strict-by-default reviewer, same
// correlation_id + run_id surfacing on success.

import {
  parseComponentArgs,
  buildClient,
  buildCli,
  readFileOrStdin
} from '../lib/component-utils.js'
import { reviewRecord } from '../lib/review/index.js'
import { CnaReviewBlockedError } from '../lib/errors.js'

export const command = 'update'
export const describe = 'Update an already-published CVE record.'

export async function handler (argv) {
  const parsed = parseComponentArgs(argv, {
    file: { type: 'string', short: 'f' },
    'skip-review': { type: 'boolean' },
    'no-strict': { type: 'boolean' }
  }, { allowPositionals: true })
  if (parsed.values.help) return printHelp()

  const cveId = parsed.positionals[0]
  if (!cveId) {
    process.stderr.write('✖ Missing CVE id. Usage: openjs-cna update <CVE-...> -f container.json\n')
    process.exit(64)
  }

  const cli = buildCli(parsed)
  const client = buildClient(parsed)

  const raw = await readFileOrStdin(parsed.values.file)
  let record
  try {
    record = JSON.parse(raw)
  } catch (e) {
    process.stderr.write(`✖ File is not valid JSON: ${e.message}\n`)
    process.exit(64)
  }

  // CVE id consistency check (same logic as publish).
  const recordCveId = record?.cveMetadata?.cveId
  if (recordCveId && recordCveId !== cveId) {
    process.stderr.write(
      `✖ CVE id mismatch: CLI argument is ${cveId}, record.cveMetadata.cveId is ${recordCveId}.\n` +
      '  Aborting before update to prevent overwriting the wrong record.\n'
    )
    process.exit(64)
  }

  // Workflow expects just the inner cna container.
  const container = record.containers.cna

  if (!parsed.values['skip-review']) {
    const strict = !parsed.values['no-strict']
    const report = reviewRecord(record, { strict })
    if (report.summary.blockers > 0) {
      cli.error(`Review blocked update: ${report.summary.blockers} blocker(s)`)
      for (const issue of report.issues) {
        const tag = issue.severity === 'blocker' ? '✖' : '⚠'
        cli.log(`  ${tag} [${issue.rule}] ${issue.message}`)
      }
      throw new CnaReviewBlockedError(`Review blocked update for ${cveId}`, { report })
    }
    cli.ok('Review clean.')
  }

  const confirmed = await cli.prompt(
    `Update ${cveId}? This will replace the public MITRE record.`,
    { defaultAnswer: !parsed.values['skip-review'] }
  )
  if (!confirmed) {
    cli.info('Aborted.')
    return
  }

  cli.info(`Updating ${cveId}…`)
  const { correlationId, runId } = await client.updateCve(cveId, container, {
    onPoll: (run) => { if (run.status !== 'completed') cli.info(`run status: ${run.status}`) }
  })
  cli.ok(`Updated ${cveId}`)
  if (correlationId || runId) {
    cli.info(`Forward to coordinator if needed: correlation_id=${correlationId ?? '?'}, run_id=${runId ?? '?'}`)
  }
}

function printHelp () {
  process.stderr.write(
`openjs-cna update <cve-id> [-f container.json]

Update a published CVE record. Same review semantics as publish (strict
by default — warnings block too).

Options:
  -f, --file <path>     read the container from a file (default: stdin)
  --skip-review         do not run the reviewer
  --no-strict           let warnings pass through (only true blockers abort)
`
  )
}
