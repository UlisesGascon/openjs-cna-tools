// openjs-cna review <container.json> [--no-strict] [--no-preview] [--tier <name>] [--json]
//
// Runs the offline reviewer against a CNA Container. Strict by default
// (warnings block); --no-strict surfaces them as warnings. Renders the
// preview before the issues list unless --no-preview. --tier filters the
// printed issues to a single severity tier (mitre-common / openjs-extra)
// without changing the exit code, which always reflects the full review.

import { parseComponentArgs, buildCli, readFileOrStdin } from '../lib/component-utils.js'
import { reviewRecord } from '../lib/review/index.js'
import { renderPreview } from '../lib/preview.js'

export const command = 'review'
export const describe = 'Review a v5.2 CNA Container against best-practice rules.'

const VALID_TIERS = new Set(['mitre-common', 'openjs-extra'])

export async function handler (argv) {
  const parsed = parseComponentArgs(argv, {
    'no-strict': { type: 'boolean' },
    'no-preview': { type: 'boolean' },
    tier: { type: 'string' }
  }, { allowPositionals: true })
  if (parsed.values.help) return printHelp()

  const cli = buildCli(parsed)
  const file = parsed.positionals[0]

  // Validate the --tier filter early so a typo doesn't silently match
  // nothing and look like a clean review.
  const tierFilter = parsed.values.tier
  if (tierFilter && !VALID_TIERS.has(tierFilter)) {
    process.stderr.write(
      `✖ Unknown --tier '${tierFilter}'. Expected one of: ${[...VALID_TIERS].join(', ')}\n`
    )
    process.exit(64)
  }

  const raw = await readFileOrStdin(file)
  let container
  try {
    container = JSON.parse(raw)
  } catch (e) {
    process.stderr.write(`✖ Container is not valid JSON: ${e.message}\n`)
    process.exit(64)
  }

  const report = reviewRecord(container, { strict: !parsed.values['no-strict'] })

  if (parsed.values.json) {
    process.stdout.write(JSON.stringify(report, null, 2) + '\n')
  } else {
    // Preview goes first so the operator sees what they're about to ship
    // alongside what the reviewer caught. --no-preview drops it for
    // CI / pipeline use.
    if (!parsed.values['no-preview']) renderPreview(container, cli)
    printHumanReport(cli, report, { tierFilter })
  }

  // Exit code: 0 if ready, 1 if blockers (or strict + warnings).
  if (report.summary.blockers > 0) process.exit(1)
}

function printHumanReport (cli, report, { tierFilter } = {}) {
  const { summary, issues } = report
  const ratingLabel = {
    ready: '✔ ready',
    'needs-work': '⚠ needs work',
    blocked: '✖ blocked'
  }[summary.rating]
  cli.log('')
  cli.log(`Review: ${ratingLabel}`)
  cli.log(`  ${summary.blockers} blocker(s) · ${summary.warnings} warning(s) · ${summary.suggestions} suggestion(s)`)
  if (tierFilter) {
    cli.log(`  (filtered to tier: ${tierFilter})`)
  }
  cli.log('')
  // Filter at print time so the summary counts above still reflect the full
  // review. This keeps `--tier mitre-common` from hiding the broader picture
  // while still letting operators focus on the must-fix items.
  const shown = tierFilter
    ? issues.filter(i => i.tier === tierFilter)
    : issues
  if (shown.length === 0) {
    if (tierFilter && issues.length > 0) {
      cli.log(`  No ${tierFilter} issues found.`)
    } else {
      cli.log('  No issues found.')
    }
    return
  }
  for (const issue of shown) {
    const tag = issue.severity === 'blocker'
      ? '✖'
      : issue.severity === 'warning'
        ? '⚠'
        : '·'
    // Tier rides inline with the rule id so a glance at the report tells
    // the operator whether MITRE would have caught the issue too.
    const tierLabel = issue.tier ? `${issue.tier}: ` : ''
    cli.log(`  ${tag} [${tierLabel}${issue.rule}] ${issue.path}`)
    cli.log(`      ${issue.message}`)
  }
}

function printHelp () {
  process.stderr.write(
`openjs-cna review <container.json>

Run the offline reviewer against a CNA Container. Strict by default —
warnings are treated as blockers because publishing to MITRE is
irreversible. Pass --no-strict to surface warnings as warnings.

Options:
  --no-strict        surface warnings as warnings (default treats them as blockers)
  --json             emit a structured JSON report instead of the human view
  --no-preview       skip the container preview (for CI / pipelines)
  --tier <tier>      filter the printed issue list to a single tier
                     (mitre-common | openjs-extra). Summary counts still
                     reflect the full review; exit code is unaffected.
`
  )
}
