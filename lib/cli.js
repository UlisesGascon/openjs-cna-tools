// Minimal CLI: a stream wrapper, four log levels, a non-animated spinner,
// and a confirm/input prompt. Zero deps — ANSI escapes inline, gated by
// stream.isTTY so piped output stays clean.
//
// Output discipline: this class always writes to its `stream` (defaulting
// to stderr). The CLI verbs are responsible for writing data (CVE ids,
// JSON records) to stdout directly. That keeps `CVE=$(openjs-cna reserve)`
// pipeline-safe by construction.

const ANSI = {
  reset: '\x1b[0m',
  bold: '\x1b[1m',
  red: '\x1b[31m',
  yellow: '\x1b[33m',
  green: '\x1b[32m',
  blue: '\x1b[34m',
  gray: '\x1b[90m'
}

export class CLI {
  constructor (stream = process.stderr, { color, assumeYes } = {}) {
    this.stream = stream
    // Default to color when stderr is a TTY and the user didn't opt out.
    this.color = color ?? (stream.isTTY === true && !process.env.NO_COLOR)
    this.assumeYes = assumeYes ?? false
    this._exitCode = 0
  }

  setAssumeYes (value = true) { this.assumeYes = value }
  setExitCode (code) { this._exitCode = code }
  exitCode () { return this._exitCode }

  _paint (code, text) { return this.color ? `${code}${text}${ANSI.reset}` : text }
  _write (line) { this.stream.write(line + '\n') }

  // Severity-leveled log lines. Match NCU's vocabulary (ok / info / warn /
  // error) so a developer moving between the two codebases doesn't have to
  // re-learn the lexicon.
  ok (msg) { this._write(this._paint(ANSI.green, '✔ ') + msg) }
  info (msg) { this._write(this._paint(ANSI.blue, 'ℹ ') + msg) }
  warn (msg) { this._write(this._paint(ANSI.yellow, '⚠ ') + msg) }
  error (msg) { this._write(this._paint(ANSI.red, '✖ ') + msg) }
  log (msg) { this._write(msg) }
  separator () { this._write('') }

  // Non-animated spinner replacement. Prints a "starting…" line on start
  // and a "done" line on stop. Honest about progress without leaning on
  // ora's TTY animation. Future: rewrite-in-place when stream.isTTY, fall
  // back to discrete lines when piped.
  startSpinner (text) {
    this._write(this._paint(ANSI.gray, '… ') + text)
    return { stop: () => {} }
  }

  stopSpinner (text) {
    if (text) this._write(this._paint(ANSI.green, '✔ ') + text)
  }

  // Confirm or input prompt. Honors --yes (or assumeYes flag) by returning
  // the defaultAnswer without rendering. Non-TTY stdin also defaults to
  // the default so the CLI is safe to drive from CI without explicit --yes.
  async prompt (question, { defaultAnswer = false, questionType = 'confirm' } = {}) {
    if (this.assumeYes) return defaultAnswer
    if (!process.stdin.isTTY) return defaultAnswer
    const { createInterface } = await import('node:readline/promises')
    const rl = createInterface({ input: process.stdin, output: this.stream })
    try {
      const hint = questionType === 'confirm'
        ? (defaultAnswer ? '[Y/n]' : '[y/N]')
        : ''
      const raw = (await rl.question(`${question} ${hint} `.trimEnd() + ' ')).trim()
      if (questionType === 'confirm') {
        if (!raw) return defaultAnswer
        return /^y(es)?$/i.test(raw)
      }
      return raw || defaultAnswer
    } finally {
      rl.close()
    }
  }
}
