// openjs-cna publish <cve-id> [-f container.json] [--skip-review] [--no-strict]
//
// Cross-checks the CLI <cve-id> against `container.cveMetadata.cveId` if
// present (hard-error on mismatch); fills cveMetadata in when absent.
// Then runs the reviewer (strict by default — warnings block too). On a
// clean review (or `--skip-review`), prompts for confirmation and
// publishes. Surfaces `correlation_id` + `run_id` after publish so the
// operator can forward to a CNA coordinator if needed.

import {
  parseComponentArgs,
  buildClient,
  buildCli,
  readFileOrStdin
} from '../lib/component-utils.js'
import { reviewRecord } from '../lib/review/index.js'
import { CnaReviewBlockedError } from '../lib/errors.js'

export const command = 'publish'
export const describe = 'Publish a v5.2 CNA Container for a reserved CVE.'

export async function handler (argv) {
  const parsed = parseComponentArgs(argv, {
    file: { type: 'string', short: 'f' },
    'skip-review': { type: 'boolean' },
    'no-strict': { type: 'boolean' }
  }, { allowPositionals: true })
  if (parsed.values.help) return printHelp()

  const cveId = parsed.positionals[0]
  if (!cveId) {
    process.stderr.write('✖ Missing CVE id. Usage: openjs-cna publish <CVE-...> -f container.json\n')
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

  // CVE id consistency check. The Record's cveMetadata.cveId must match
  // the CLI arg; mismatch is a hard error (operator was probably about to
  // publish the wrong record). If cveMetadata is missing, the CLI arg is
  // the sole source of truth.
  const recordCveId = record?.cveMetadata?.cveId
  if (recordCveId && recordCveId !== cveId) {
    process.stderr.write(
      `✖ CVE id mismatch: CLI argument is ${cveId}, record.cveMetadata.cveId is ${recordCveId}.\n` +
      '  Aborting before publish to prevent updating the wrong record.\n'
    )
    process.exit(64)
  }

  // Extract the inner cna container — the workflow expects just that,
  // not the full Record (it builds the Record server-side with the
  // assignerOrgId and dateUpdated MITRE injects).
  const container = record.containers.cna

  if (!parsed.values['skip-review']) {
    const strict = !parsed.values['no-strict']
    const report = reviewRecord(record, { strict })
    // Strict mode promotes warnings to blockers inside reviewRecord, so
    // the `summary.blockers` count already reflects strictness. We just
    // need to check that single number.
    if (report.summary.blockers > 0) {
      cli.error(
        `Review blocked publish: ${report.summary.blockers} blocker(s)`
      )
      for (const issue of report.issues) {
        const tag = issue.severity === 'blocker' ? '✖' : issue.severity === 'warning' ? '⚠' : '·'
        cli.log(`  ${tag} [${issue.rule}] ${issue.message}`)
      }
      cli.log('')
      cli.log('  Re-run with --skip-review to bypass.')
      throw new CnaReviewBlockedError(
        `Review blocked publish for ${cveId}`,
        { report }
      )
    }
    if (report.summary.warnings) {
      cli.warn(`Review surfaced ${report.summary.warnings} warning(s); proceeding.`)
    } else {
      cli.ok(`Review clean (${report.summary.suggestions} suggestion(s)).`)
    }
  }

  // Confirmation prompt. Defaults to "yes" only when the review was clean
  // (and we got here without --skip-review). Honors --yes / OPENJS_CNA_YES.
  const confirmed = await cli.prompt(
    `Publish ${cveId}? This is irreversible.`,
    { defaultAnswer: !parsed.values['skip-review'] }
  )
  if (!confirmed) {
    cli.info('Aborted.')
    return
  }

  cli.info(`Publishing ${cveId}…`)
  const { correlationId, runId, result } = await client.publishCve(cveId, container, {
    onPoll: (run) => {
      if (run.status && run.status !== 'completed') cli.info(`run status: ${run.status}`)
    }
  })
  cli.ok(`Published ${cveId}`)
  if (correlationId || runId) {
    cli.info(`Forward to coordinator if needed: correlation_id=${correlationId ?? '?'}, run_id=${runId ?? '?'}`)
  }
  if (result) process.stdout.write(JSON.stringify(result, null, 2) + '\n')
}

function printHelp () {
  process.stderr.write(
`openjs-cna publish <cve-id> [-f container.json]

Publish a v5.2 CNA Container against an already-reserved CVE id. Default
behavior runs the reviewer first (strict — warnings block too) and aborts
on any issue.

Options:
  -f, --file <path>     read the container from a file (default: stdin)
  --skip-review         do not run the reviewer
  --no-strict           let warnings pass through (only true blockers abort)
  [global flags]
`
  )
}
