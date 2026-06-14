// Shared bootstrap for CLI components.
//
// Every component runs the same opening sequence: parse argv (mixing global
// flags with its own), resolve credentials, build a CLI + CnaClient. This
// module factors that out so each component file in components/ can stay
// at ~30 lines.

import { parseArgs } from 'node:util'
import { CLI } from './cli.js'
import { CnaClient } from './client.js'
import { resolveCredentials } from './auth.js'

const GLOBAL_OPTIONS = {
  token: { type: 'string' },
  'base-url': { type: 'string' },
  timeout: { type: 'string' },
  'poll-interval': { type: 'string' },
  json: { type: 'boolean' },
  quiet: { type: 'boolean' },
  yes: { type: 'boolean', short: 'y' },
  'no-color': { type: 'boolean' },
  help: { type: 'boolean', short: 'h' }
}

export function parseComponentArgs (argv, componentOptions = {}, { allowPositionals = false } = {}) {
  const options = { ...GLOBAL_OPTIONS, ...componentOptions }
  let parsed
  try {
    parsed = parseArgs({ args: argv, options, allowPositionals })
  } catch (e) {
    process.stderr.write(`✖ ${e.message}\n`)
    process.exit(64) // EX_USAGE
  }
  return parsed
}

export function buildCli ({ values } = { values: {} }) {
  return new CLI(process.stderr, {
    color: values['no-color'] ? false : undefined,
    assumeYes: values.yes || process.env.OPENJS_CNA_YES === '1'
  })
}

export function buildClient ({ values } = { values: {} }) {
  const creds = resolveCredentials({
    overrides: {
      token: values.token,
      baseUrl: values['base-url']
    }
  })
  return new CnaClient({
    token: creds.token,
    baseUrl: creds.baseUrl,
    timeoutMs: values.timeout ? Number(values.timeout) * 1000 : undefined,
    pollIntervalMs: values['poll-interval'] ? Number(values['poll-interval']) * 1000 : undefined
  })
}

// Convenience: read a file or stdin to text. Used by publish/update/review/
// convert when -f is omitted.
export async function readFileOrStdin (filePath) {
  const fs = await import('node:fs/promises')
  if (filePath && filePath !== '-') {
    return fs.readFile(filePath, 'utf8')
  }
  // Read all of stdin.
  return new Promise((resolve, reject) => {
    let data = ''
    process.stdin.setEncoding('utf8')
    process.stdin.on('data', (chunk) => { data += chunk })
    process.stdin.on('end', () => resolve(data))
    process.stdin.on('error', reject)
  })
}
