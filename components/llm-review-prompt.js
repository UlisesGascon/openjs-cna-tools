// openjs-cna llm-review-prompt <record.json>
//
// Print a prompt for an LLM-driven editorial review of the record's
// natural-language fields (title + description). The tool does not call
// an LLM itself. Paste the output into the LLM of your choice. Pure
// read; no network.

import { parseComponentArgs, buildCli, readFileOrStdin } from '../lib/component-utils.js'
import { buildAuditPrompt } from '../lib/prompt.js'

export const command = 'llm-review-prompt'
export const describe = 'Print a prompt for an LLM editorial review of the record\'s title + description.'

export async function handler (argv) {
  const parsed = parseComponentArgs(argv, {}, { allowPositionals: true })
  if (parsed.values.help) return printHelp()

  // Keep buildCli for help/diagnostic plumbing even though we don't
  // print status. Keeps the component shape consistent with peers.
  buildCli(parsed)

  const file = parsed.positionals[0]
  const raw = await readFileOrStdin(file)
  let record
  try {
    record = JSON.parse(raw)
  } catch (e) {
    process.stderr.write(`✖ Record is not valid JSON: ${e.message}\n`)
    process.exit(64)
  }

  // Banner goes to stderr so a pipe like `| pbcopy` or `| llm` only
  // captures the prompt itself, not the human-facing how-to.
  process.stderr.write(buildBanner())
  process.stdout.write(buildAuditPrompt(record))
}

function buildBanner () {
  const lines = [
    'How to use this prompt',
    '',
    '1. Paste everything that follows into an LLM (Claude, ChatGPT,',
    '   Gemini, etc.).',
    '2. Also attach the full CVE Record JSON so the LLM can cross-check',
    '   the natural-language fields against the rest of the record.',
    '3. The LLM returns a Markdown review you can act on.'
  ]
  const width = Math.max(...lines.map(l => l.length))
  const top = '┌' + '─'.repeat(width + 2) + '┐'
  const bottom = '└' + '─'.repeat(width + 2) + '┘'
  const body = lines.map(l => '│ ' + l.padEnd(width) + ' │').join('\n')
  return top + '\n' + body + '\n' + bottom + '\n'
}

function printHelp () {
  process.stderr.write(
`openjs-cna llm-review-prompt <record.json>

Build a prompt that asks an LLM for an editorial review of the record's
title and description. The prompt includes the OpenJS naming and tone
guidelines, the texts to audit, and a short facts block (affected,
CVSS, CWE) so the LLM can ground its suggestions.

The tool does not call any LLM. Paste the output into the LLM of your
choice and read the reply. Attach the full CVE Record JSON in the same
turn so the LLM can cross-check the prose against the structured data.

Reads the record from a file (positional) or from stdin if the
positional is '-' or absent.

A how-to banner is written to stderr so a pipe like \`| pbcopy\` only
captures the prompt itself.

Pipeline use (audit a freshly converted draft before publish):

  openjs-cna convert https://github.com/<owner>/<repo>/security/advisories/<GHSA> \\
    | tee draft.json \\
    | openjs-cna llm-review-prompt - | pbcopy

Open the LLM, paste, attach \`draft.json\`, then iterate before
\`openjs-cna publish\`.
`
  )
}
