// Error classes for openjs-cna-tools.
//
// Each error carries enough structured context that a recovery flow (or the
// CLI exit-code mapping) can act on it without parsing the message. Messages
// themselves are written to teach the next operator how to fix the problem
// (see "Errors that teach" — the NCU pattern this borrows from).

export class CnaAuthError extends Error {
  constructor (message, { status } = {}) {
    super(message)
    this.name = 'CnaAuthError'
    this.status = status
  }
}

export class CnaTimeoutError extends Error {
  constructor (message, { correlationId, runId, timeoutMs } = {}) {
    super(message)
    this.name = 'CnaTimeoutError'
    this.correlationId = correlationId
    this.runId = runId
    this.timeoutMs = timeoutMs
  }
}

export class CnaOperationError extends Error {
  constructor (message, { correlationId, runId, conclusion, result } = {}) {
    super(message)
    this.name = 'CnaOperationError'
    this.correlationId = correlationId
    this.runId = runId
    this.conclusion = conclusion
    this.result = result
  }
}

export class CnaReviewBlockedError extends Error {
  constructor (message, { report } = {}) {
    super(message)
    this.name = 'CnaReviewBlockedError'
    this.report = report
    this.blockers = report?.issues?.filter(i => i.severity === 'blocker') ?? []
  }
}
