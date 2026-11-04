// openjs-cna-experimental publish <cve-id> [-f record.json] [--skip-review] [--no-strict]
// openjs-cna-experimental publish -f a.json -f b.json … [--skip-published] [--json]
//
// Single record: cross-checks the CLI <cve-id> against `record.cveMetadata.cveId`
// if present (hard-error on mismatch); the CLI arg is the sole source of
// truth when the record has none. Runs the reviewer (strict by default —
// warnings block too). On a clean review (or `--skip-review`), prompts for
// confirmation and publishes. Surfaces `correlation_id` + `run_id` after
// publish so the operator can forward them to a CNA coordinator if needed.
//
// Batch (no <cve-id>, one or more -f): every record must carry
// cveMetadata.cveId. All records are reviewed first and nothing is sent
// unless all of them pass; then each one is published in order, a failure
// is recorded and the rest still go out. One confirmation covers the whole
// batch. --skip-published asks the CNA first and skips ids that already
// have a published record, so reruns after a partial failure stay green.
// --json prints one result per record on stdout. Exit code is 1 when the
// review blocked or any record failed.

import {
  parseComponentArgs,
  buildClient,
  buildCli,
  readFileOrStdin
} from '../lib/component-utils.js'
import { reviewRecord } from '../lib/review/index.js'
import { publishRecords } from '../lib/batch.js'
import { CnaReviewBlockedError } from '../lib/errors.js'

export const command = 'publish'
export const describe = 'Publish one or more v5.2 CVE Records for reserved CVE ids.'

export async function handler (argv) {
  const parsed = parseComponentArgs(argv, {
    file: { type: 'string', short: 'f', multiple: true },
    'skip-review': { type: 'boolean' },
    'no-strict': { type: 'boolean' },
    'skip-published': { type: 'boolean' }
  }, { allowPositionals: true })
  if (parsed.values.help) return printHelp()

  const cveId = parsed.positionals[0]
  const files = parsed.values.file ?? []
  const strict = !parsed.values['no-strict']
  const skipReview = parsed.values['skip-review']

  if (!cveId) {
    if (files.length === 0) {
      process.stderr.write('✖ Missing CVE id. Usage: openjs-cna-experimental publish <CVE-...> -f record.json\n' +
        '  or, for a batch: openjs-cna-experimental publish -f a.json -f b.json\n')
      process.exit(64)
    }
    return publishMany(files, {
      parsed, strict, skipReview, skipPublished: parsed.values['skip-published']
    })
  }
  if (files.length > 1) {
    process.stderr.write('✖ Several -f files need batch mode: drop the <cve-id> argument.\n')
    process.exit(64)
  }

  const cli = buildCli(parsed)
  const client = buildClient(parsed)
  const record = await readRecord(files[0])

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

  if (!skipReview) {
    const report = reviewRecord(record, { strict })
    // Strict mode promotes warnings to blockers inside reviewRecord, so
    // the `summary.blockers` count already reflects strictness. We just
    // need to check that single number.
    if (report.summary.blockers > 0) {
      cli.error(
        `Review blocked publish: ${report.summary.blockers} blocker(s)`
      )
      printIssues(cli, report.issues)
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
    { defaultAnswer: !skipReview }
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

async function publishMany (files, { parsed, strict, skipReview, skipPublished }) {
  const cli = buildCli(parsed)
  const entries = []
  for (const file of files) {
    entries.push({ file, record: await readRecord(file) })
  }

  // The reviewer runs inside publishRecords too; this early pass exists so
  // the operator sees the ids before confirming, and so a missing id is
  // caught before credentials are even resolved.
  const ids = entries.map((entry) => entry.record?.cveMetadata?.cveId ?? `${entry.file} (no cveMetadata.cveId)`)
  cli.info(`Publishing ${entries.length} record(s): ${ids.join(', ')}`)
  const confirmed = await cli.prompt(
    `Publish ${entries.length} record(s)? This is irreversible.`,
    { defaultAnswer: !skipReview }
  )
  if (!confirmed) {
    cli.info('Aborted.')
    return
  }

  const client = buildClient(parsed)
  const outcome = await publishRecords(entries, {
    client,
    strict,
    skipReview,
    skipPublished,
    onProgress: (event) => {
      const trace = traceOf(event)
      if (event.status === 'published') cli.ok(`Published ${event.cveId}${trace}`)
      else if (event.status === 'skipped') cli.info(`Skipped ${event.cveId}: ${event.reason}`)
      else cli.error(`Failed ${event.cveId}: ${event.error}${trace}`)
    }
  })

  if (outcome.blocked) {
    const blocked = outcome.review.filter((item) => !item.ready)
    cli.error(`Review blocked publish: ${blocked.length} of ${outcome.review.length} record(s) have blockers. Nothing was sent.`)
    for (const item of blocked) {
      cli.log(`  ${item.file}${item.cveId ? ` (${item.cveId})` : ''}`)
      printIssues(cli, item.issues.filter((issue) => issue.severity === 'blocker'), '    ')
    }
    if (parsed.values.json) process.stdout.write(JSON.stringify(outcome.review, null, 2) + '\n')
    process.exit(1)
  }

  if (parsed.values.json) process.stdout.write(JSON.stringify(outcome.results, null, 2) + '\n')
  const failed = outcome.results.filter((item) => item.status === 'failed')
  const published = outcome.results.filter((item) => item.status === 'published').length
  const skipped = outcome.results.filter((item) => item.status === 'skipped').length
  cli.log('')
  cli.info(`${published} published · ${skipped} skipped · ${failed.length} failed`)
  if (failed.length) {
    cli.info('Forward the correlation_id / run_id pairs above to your CNA coordinator.')
    process.exit(1)
  }
}

function traceOf (event) {
  const parts = []
  if (event.correlationId) parts.push(`correlation_id=${event.correlationId}`)
  if (event.runId) parts.push(`run_id=${event.runId}`)
  return parts.length ? ` (${parts.join(', ')})` : ''
}

function printIssues (cli, issues, indent = '  ') {
  for (const issue of issues) {
    const tag = issue.severity === 'blocker' ? '✖' : issue.severity === 'warning' ? '⚠' : '·'
    cli.log(`${indent}${tag} [${issue.rule}] ${issue.message}`)
  }
}

async function readRecord (file) {
  const raw = await readFileOrStdin(file)
  try {
    return JSON.parse(raw)
  } catch (e) {
    process.stderr.write(`✖ ${file ?? 'stdin'} is not valid JSON: ${e.message}\n`)
    process.exit(64)
  }
}

function printHelp () {
  process.stderr.write(
`openjs-cna-experimental publish <cve-id> [-f record.json]
openjs-cna-experimental publish -f a.json -f b.json … [--skip-published]

Publish v5.2 CVE Records against already-reserved CVE ids. Default
behavior runs the reviewer first (strict — warnings block too) and aborts
on any issue.

Without <cve-id> every -f record is published as a batch: each record must
carry cveMetadata.cveId, all records are reviewed before anything is sent,
then each is published in order (a failure does not stop the others). One
confirmation covers the batch. Exit code is 1 if the review blocked or any
record failed.

Options:
  -f, --file <path>     read a record from a file (default: stdin); repeatable
  --skip-review         do not run the reviewer
  --no-strict           let warnings pass through (only true blockers abort)
  --skip-published      batch only: skip ids the CNA already has published
  --json                batch only: print one result per record on stdout
  [global flags]
`
  )
}
