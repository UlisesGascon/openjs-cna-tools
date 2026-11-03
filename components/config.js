// openjs-cna-experimental config <set|get|list|delete> ...

import {
  parseComponentArgs,
  buildCli
} from '../lib/component-utils.js'
import {
  getConfigValue,
  setConfigValue,
  deleteConfigValue,
  listConfig
} from '../lib/config.js'

export const command = 'config'
export const describe = 'Read / write openjs-cna-experimental configuration.'

export async function handler (argv) {
  const parsed = parseComponentArgs(argv, {
    project: { type: 'boolean' }
  }, { allowPositionals: true })
  if (parsed.values.help) return printHelp()

  const cli = buildCli(parsed)
  const [subverb, ...rest] = parsed.positionals
  const scope = parsed.values.project ? 'project' : 'global'

  switch (subverb) {
    case 'set': {
      const [key, value] = rest
      if (!key || value === undefined) {
        process.stderr.write('✖ Usage: openjs-cna-experimental config set <key> <value> [--project]\n')
        process.exit(64)
      }
      const target = setConfigValue(key, value, { scope })
      cli.ok(`Wrote ${key} to ${target}`)
      return
    }
    case 'get': {
      const [key] = rest
      if (!key) {
        process.stderr.write('✖ Usage: openjs-cna-experimental config get <key>\n')
        process.exit(64)
      }
      const value = getConfigValue(key)
      if (value === undefined) {
        cli.error(`No config value for '${key}'`)
        process.exit(1)
      }
      process.stdout.write(`${value}\n`)
      return
    }
    case 'list': {
      const config = listConfig()
      process.stdout.write(JSON.stringify(config, null, 2) + '\n')
      return
    }
    case 'delete': {
      const [key] = rest
      if (!key) {
        process.stderr.write('✖ Usage: openjs-cna-experimental config delete <key> [--project]\n')
        process.exit(64)
      }
      const removed = deleteConfigValue(key, { scope })
      if (removed) cli.ok(`Deleted ${key} from ${scope} config`)
      else cli.warn(`Key '${key}' was not present in ${scope} config`)
      return
    }
    default:
      process.stderr.write(`✖ Unknown config subcommand: ${subverb ?? '(none)'}\n`)
      printHelp()
      process.exit(64)
  }
}

function printHelp () {
  process.stderr.write(
`openjs-cna-experimental config <subcommand> [options]

Subcommands:
  set <key> <value>    write a value (plaintext at ~/.config/openjs-cna/config.json,
                       file mode 0600). For tokens you don't want on disk, use the
                       OPENJS_CNA_TOKEN environment variable instead.
  get <key>            read a value
  list                 print the merged config (secrets redacted)
  delete <key>         remove a value

Options:
  --project    operate on the project config (./.openjs-cna.json)
               default is the global config (~/.config/openjs-cna/config.json)
`
  )
}
