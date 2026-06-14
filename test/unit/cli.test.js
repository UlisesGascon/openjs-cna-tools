import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { PassThrough } from 'node:stream'

import { CLI } from '../../lib/cli.js'

// Build a CLI that writes into a PassThrough so tests can assert on
// exactly what hit the stream. Color is disabled by default to keep the
// assertions free of ANSI noise.
function makeCli (opts = {}) {
  const stream = new PassThrough()
  const cli = new CLI(stream, { color: false, ...opts })
  const chunks = []
  stream.on('data', (c) => chunks.push(c))
  return { cli, stream, output: () => Buffer.concat(chunks).toString('utf8') }
}

describe('CLI — log levels', () => {
  it('writes ok / info / warn / error each on its own line', () => {
    const { cli, output } = makeCli()
    cli.ok('one')
    cli.info('two')
    cli.warn('three')
    cli.error('four')
    const lines = output().trim().split('\n')
    assert.equal(lines.length, 4)
    assert.match(lines[0], /one/)
    assert.match(lines[1], /two/)
    assert.match(lines[2], /three/)
    assert.match(lines[3], /four/)
  })

  it('renders ANSI escapes when color is on, plain text when off', () => {
    const { cli: colored, output: outColored } = makeCli({ color: true })
    colored.error('boom')
    // eslint-disable-next-line no-control-regex
    assert.match(outColored(), /\x1b\[/) // some ANSI escape present

    const { cli: plain, output: outPlain } = makeCli({ color: false })
    plain.error('boom')
    // eslint-disable-next-line no-control-regex
    assert.ok(!/\x1b\[/.test(outPlain()), 'plain mode should not include escapes')
  })

  it('log() writes the line verbatim, without a severity prefix', () => {
    const { cli, output } = makeCli()
    cli.log('just data')
    assert.equal(output(), 'just data\n')
  })

  it('separator() writes a blank line', () => {
    const { cli, output } = makeCli()
    cli.separator()
    assert.equal(output(), '\n')
  })
})

describe('CLI — exit-code tracking', () => {
  it('starts at 0 and remembers the last set code', () => {
    const { cli } = makeCli()
    assert.equal(cli.exitCode(), 0)
    cli.setExitCode(7)
    assert.equal(cli.exitCode(), 7)
  })
})

describe('CLI — spinner', () => {
  it('startSpinner returns an object with stop() and writes a line', () => {
    const { cli, output } = makeCli()
    const s = cli.startSpinner('working…')
    assert.equal(typeof s.stop, 'function')
    s.stop()
    assert.match(output(), /working…/)
  })

  it('stopSpinner with text writes a completion line', () => {
    const { cli, output } = makeCli()
    cli.stopSpinner('done')
    assert.match(output(), /done/)
  })

  it('stopSpinner without text writes nothing', () => {
    const { cli, output } = makeCli()
    cli.stopSpinner()
    assert.equal(output(), '')
  })
})

describe('CLI — prompt', () => {
  it('honors assumeYes by returning defaultAnswer immediately', async () => {
    const { cli } = makeCli({ assumeYes: true })
    const yes = await cli.prompt('continue?', { defaultAnswer: true })
    const no = await cli.prompt('continue?', { defaultAnswer: false })
    assert.equal(yes, true)
    assert.equal(no, false)
  })

  it('setAssumeYes(true) flips the behavior on an existing instance', async () => {
    const { cli } = makeCli()
    cli.setAssumeYes(true)
    assert.equal(await cli.prompt('?', { defaultAnswer: true }), true)
  })

  it('falls back to defaultAnswer when stdin is not a TTY (CI mode)', async () => {
    // In the test runner process.stdin.isTTY is false, so the prompt
    // short-circuits to defaultAnswer without trying to read stdin.
    const { cli } = makeCli()
    const result = await cli.prompt('continue?', { defaultAnswer: true })
    assert.equal(result, true)
  })
})
