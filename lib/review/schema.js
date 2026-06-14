// MITRE schema validation for v5.2 CVE Records.
//
// Wraps ajv around the official CVE Record Format schema from the CVE
// Project at https://github.com/CVEProject/cve-schema. The schema lives
// in this repo at `lib/review/schemas/cve-record-format.json` and is
// refreshed by hand when MITRE publishes a new revision.
//
// Two notes on the integration:
//
//   1. The schema is JSON Schema draft-07. ajv supports draft-07 natively
//      via `Ajv` (not `Ajv2019`/`Ajv2020`). We layer `ajv-formats` on top
//      so the `format: 'uri'`/`format: 'date'` keywords MITRE uses are
//      actually validated rather than silently ignored.
//
//   2. The CVE Project schemas mix drafts (the main file is draft-07, the
//      CVSS v2.0 import is draft-04). We pre-normalize the CVSS v2/v3.0/
//      v3.1 files in `lib/review/schemas/imports/cvss/` to use `$id`
//      instead of the draft-04 `id` keyword so ajv can compile them; the
//      normalization is documented in BACKLOG (rebundle step).

import { createRequire } from 'node:module'
import Ajv from 'ajv'
import addFormats from 'ajv-formats'

// `createRequire` lets us load the bundled JSON schemas without the ESM
// `import ... with { type: 'json' }` attribute syntax, which standard's
// parser does not yet support.
const require = createRequire(import.meta.url)
const schemaFile = require('./schemas/cve-record-format.json')
const adpTags = require('./schemas/tags/adp-tags.json')
const cnaTags = require('./schemas/tags/cna-tags.json')
const referenceTags = require('./schemas/tags/reference-tags.json')
const cvssV2 = require('./schemas/imports/cvss/cvss-v2.0.json')
const cvssV30 = require('./schemas/imports/cvss/cvss-v3.0.json')
const cvssV31 = require('./schemas/imports/cvss/cvss-v3.1.json')
const cvssV4 = require('./schemas/imports/cvss/cvss-v4.0.json')

// OpenJS Foundation CNA orgId in MITRE's directory. Source: any of the
// CVEs the foundation has already published, e.g. `cves/CVE-2026-*.json`
// in the security-work repo each carry this orgId in their
// `containers.cna.providerMetadata.orgId`.
export const OPENJS_CNA_ORG_ID = 'ce714d77-add3-4f53-aff5-83d477b104bb'

const ajv = new Ajv({
  allErrors: true,
  // `validateSchema: false` because the bundled MITRE schemas span
  // multiple JSON Schema drafts and we don't ship the older meta-
  // schemas. We trust MITRE's schemas; the job here is to validate
  // containers AGAINST them, not validate the schemas themselves.
  validateSchema: false,
  // `strict: false` because MITRE's schemas use a custom `license`
  // keyword and several definitions omit explicit `type: 'object'`
  // declarations. ajv's strict mode would refuse to compile them.
  // The actual data-validation behavior (the thing operators rely on)
  // is unaffected — strict mode is about strictness of the SCHEMAS,
  // not strictness of the validation against them. Where strict
  // matters most for us — `format: 'uri'` / `format: 'date'` — is
  // covered by ajv-formats below.
  strict: false
})

// ajv-formats teaches ajv about the `uri`, `date`, `email`, `uuid` etc.
// formats that MITRE's schemas use. Without this they'd parse-but-not-
// actually-validate.
addFormats(ajv)

// Register every companion schema under the `file:` URI that the main
// CVE_Record_Format.json file uses to reference them. The CVE Project's
// schemas use bare `file:tags/...` and `file:imports/...` refs because
// the canonical layout assumes a checked-out copy of the schema repo.
ajv.addSchema(adpTags, 'file:tags/adp-tags.json')
ajv.addSchema(cnaTags, 'file:tags/cna-tags.json')
ajv.addSchema(referenceTags, 'file:tags/reference-tags.json')
ajv.addSchema(cvssV2, 'file:imports/cvss/cvss-v2.0.json')
ajv.addSchema(cvssV30, 'file:imports/cvss/cvss-v3.0.json')
ajv.addSchema(cvssV31, 'file:imports/cvss/cvss-v3.1.json')
ajv.addSchema(cvssV4, 'file:imports/cvss/cvss-v4.0.json')

// Compile the schema's top-level oneOf (Published-Record / Rejected-
// Record). This validates the WHOLE Record in one pass — `dataType`,
// `dataVersion`, `cveMetadata`, and `containers.cna` — against the same
// shape Vulnogram and every published OpenJS CVE on MITRE use.
const validator = ajv.compile(schemaFile)

// Validate a full CVE Record against MITRE's schema. Returns an array of
// { path, message } per violation. Empty array means clean.
export function validateAgainstMitreSchema (record) {
  if (!record || typeof record !== 'object') {
    return [{ path: '/', message: 'record is not an object' }]
  }
  const ok = validator(record)
  if (ok) return []
  return (validator.errors || []).map((err) => ({
    path: err.instancePath || '/',
    message: err.message + (err.params && Object.keys(err.params).length
      ? ' ' + JSON.stringify(err.params)
      : '')
  }))
}
