// openjs-cna preview <container.json>
// Compact terminal view of a v5.2 CNA Container. Pure read; no network.

import { parseComponentArgs, buildCli, readFileOrStdin } from '../lib/component-utils.js'
import { renderPreview } from '../lib/preview.js'

export const command = 'preview'
export const describe = 'Print a compact preview of a CNA Container.'

export async function handler (argv) {
  const parsed = parseComponentArgs(argv, {}, { allowPositionals: true })
  if (parsed.values.help) return printHelp()

  const cli = buildCli(parsed)
  const file = parsed.positionals[0]
  const raw = await readFileOrStdin(file)
  let container
  try {
    container = JSON.parse(raw)
  } catch (e) {
    process.stderr.write(`✖ Container is not valid JSON: ${e.message}\n`)
    process.exit(64)
  }

  renderPreview(container, cli)
}

function printHelp () {
  process.stderr.write(
`openjs-cna preview <container.json>

Print a compact summary of the container — title, description, affected
products, CVSS, CWE, credits, references, and the x_generator engine.

Useful as a quick sanity check before publish, or as a step in a pipeline
('openjs-cna get CVE-... | openjs-cna preview -').

Reads the container from a file (positional) or from stdin if the
positional is '-' or absent.
`
  )
}
