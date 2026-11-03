#!/usr/bin/env node

// Router. Autoloads components/<verb>.js and hands the remaining argv to its
// `handler`.

import { readdirSync } from 'node:fs'
import { createRequire } from 'node:module'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import {
  CnaAuthError,
  CnaTimeoutError,
  CnaOperationError,
  CnaReviewBlockedError
} from '../lib/errors.js'

const require = createRequire(import.meta.url)
const pkg = require('../package.json')

const componentsDir = new URL('../components/', import.meta.url)
const here = path.dirname(fileURLToPath(import.meta.url))

function listVerbs () {
  try {
    return readdirSync(componentsDir)
      .filter(name => name.endsWith('.js'))
      .map(name => name.slice(0, -3))
      .sort()
  } catch {
    return []
  }
}

function showHelp () {
  const verbs = listVerbs()
  process.stderr.write(
`openjs-cna-experimental — operate the OpenJS Foundation CNA API

Usage:
  openjs-cna-experimental <command> [options]

Commands:
${verbs.map(v => '  ' + v).join('\n')}

Global flags:
  --token <value>           override resolved token
  --base-url <url>          override resolved base URL
  --timeout <seconds>       per-operation timeout
  --poll-interval <secs>    polling interval
  --json                    force JSON output where applicable
  --quiet                   suppress non-essential stderr
  --yes                     accept all confirmation prompts
  --no-color                disable color output
  --version, -v
  --help, -h

Run 'openjs-cna-experimental <command> --help' for command-specific options.
`
  )
}

function showVersion () {
  process.stdout.write(`${pkg.version}\n`)
}

function mapErrorToExit (e) {
  if (e instanceof CnaAuthError) return 2
  if (e instanceof CnaTimeoutError) return 3
  if (e instanceof CnaReviewBlockedError) return 1
  if (e instanceof CnaOperationError) return 1
  return 1
}

async function main () {
  const argv = process.argv.slice(2)
  if (argv.length === 0 || argv[0] === '--help' || argv[0] === '-h') {
    showHelp()
    process.exit(argv.length === 0 ? 0 : 0)
  }
  if (argv[0] === '--version' || argv[0] === '-v') {
    showVersion()
    process.exit(0)
  }

  const verb = argv[0]
  const rest = argv.slice(1)

  let mod
  try {
    mod = await import(new URL(`../components/${verb}.js`, import.meta.url))
  } catch (e) {
    if (e.code === 'ERR_MODULE_NOT_FOUND') {
      process.stderr.write(`Unknown command: ${verb}\n\n`)
      showHelp()
      process.exit(64) // EX_USAGE
    }
    throw e
  }

  try {
    await mod.handler(rest)
    process.exit(0)
  } catch (e) {
    // The CLI components already log structured error context; we just need
    // to map the error class to an exit code here. Anything not in the
    // CnaError family bubbles its stack so unexpected bugs aren't silent.
    if (
      e instanceof CnaAuthError ||
      e instanceof CnaTimeoutError ||
      e instanceof CnaOperationError ||
      e instanceof CnaReviewBlockedError
    ) {
      process.stderr.write(`✖ ${e.message}\n`)
      if (e.correlationId || e.runId) {
        process.stderr.write(`  Forward to coordinator: correlation_id=${e.correlationId ?? '?'}, run_id=${e.runId ?? '?'}\n`)
      }
      process.exit(mapErrorToExit(e))
    }
    throw e
  }
}

main()

// Make the import order quiet for linters/tools that expect a non-empty
// epilogue when this file is imported as a module (it never is, but keep
// the symbol stable).
export { here }
