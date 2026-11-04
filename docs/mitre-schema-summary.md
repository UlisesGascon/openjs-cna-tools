# MITRE CVE Record Format v5.2 — Constraint Summary

This document summarizes the structural constraints MITRE's official CVE Record
Format v5.2 schema places on a `cnaPublishedContainer` (the object a CNA submits
when publishing a CVE). It exists to help reviewers tell apart **what MITRE's
schema itself enforces** from **what OpenJS Foundation adds on top as editorial
policy**. The reviewer in `lib/review/` tags each rule with a `tier` (either
`mitre-common` or `openjs-extra`) and the classifications below explain why.

Source: `lib/review/schemas/cve-record-format.json`. The
`cnaPublishedContainer` definition lives at lines 606-690 and references the
other definitions enumerated here.

## Top-level container (`cnaPublishedContainer`)

- **Required properties:** `providerMetadata`, `descriptions`, `affected`,
  `references`.
- `additionalProperties: false`, except for `x_*` extension properties.
- All other fields (`title`, `problemTypes`, `metrics`, `credits`, `impacts`,
  `configurations`, `workarounds`, `solutions`, `exploits`, `timeline`,
  `source`, `tags`, `taxonomyMappings`, `cpeApplicability`, `dateAssigned`,
  `datePublic`) are optional.

`providerMetadata` is filled in by MITRE's CVE Services API server-side from
the authed CNA. The reviewer stubs it during validation (see
`lib/review/schema.js`) so its absence in operator-authored drafts is not a
violation.

## `title`

- Optional, `string`.
- `minLength: 1`, `maxLength: 256`.

## `descriptions` (required)

- Array, `minItems: 1`, `uniqueItems: true`.
- `contains: englishLanguageDescription` — the array MUST contain at least one
  description whose `lang` matches `^en([_-]...)?$`.
- Each item is a `description` object with:
  - **Required:** `lang`, `value`.
  - `lang` matches BCP 47 pattern `^[A-Za-z]{2,4}([_-]...)?$`.
  - `value`: `string`, `minLength: 1`, `maxLength: 4096`.
  - `supportingMedia` (optional): array, `minItems: 1`, `uniqueItems: true`.
    Each item requires `type` and `value`, both with `minLength: 1` and
    `maxLength` of 256 and 16384 respectively. `base64` is optional boolean.
  - `additionalProperties: false`.

## `affected` (required)

- Array, `minItems: 1`. Items are `product` objects.
- Each `product` must satisfy two `anyOf` constraints:
  1. **Identity:** `(vendor + product)` OR `(collectionURL + packageName)`.
  2. **Coverage:** `versions` OR `defaultStatus`.
- `additionalProperties: false`.
- `vendor`: `string`, `minLength: 1`, `maxLength: 512`.
- `product`: `string`, `minLength: 1`, `maxLength: 2048`.
- `packageName`: `string`, `minLength: 1`, `maxLength: 2048`.
- `collectionURL`, `repo`, `packageURL`: `uriType` (URI, `maxLength: 2048`).
- `defaultStatus`: enum `affected | unaffected | unknown`.
- `versions` (when present): `array`, `minItems: 1`, `uniqueItems: true`.
  - Each entry is one of four shapes via `oneOf`:
    - `{version, status}` with `maxProperties: 2`.
    - `{version, status, versionType}` with `maxProperties: 3`.
    - `{version, status, versionType, lessThan}`.
    - `{version, status, versionType, lessThanOrEqual}`.
  - `version` / `lessThan` / `lessThanOrEqual`: `string`, `minLength: 1`,
    `maxLength: 1024`.
  - `status`: enum `affected | unaffected | unknown`.
  - `versionType`: `string`, `minLength: 1`, `maxLength: 128` (examples
    include `semver`, `git`, `maven`, `python`, `rpm`, `custom`).
  - `changes` (optional): `array`, `minItems: 1`, `uniqueItems: true`. Items
    require `at` + `status`.
- `cpes`, `modules`, `programFiles`, `programRoutines`, `platforms`: all
  `uniqueItems: true`. Various `minLength` / `maxLength` per item.

The schema does **not** constrain semantic relationships between `version`
and `lessThan` (e.g. whether they share a major). That's editorial.

## `problemTypes`

- Optional. Array, `minItems: 1`, `uniqueItems: true`.
- Each item requires a `descriptions` array (`minItems: 1`, `uniqueItems: true`).
  - Each inner description requires `lang` + `description`.
  - `description`: `string`, `minLength: 1`, `maxLength: 4096`.
  - `cweId` (optional): `string`, `minLength: 5`, `maxLength: 9`,
    `pattern: ^CWE-[1-9][0-9]*$` (so `CWE-0` and leading-zero ids are rejected).
  - `type` (optional): `string`, `minLength: 1`, `maxLength: 128`.
  - `references` (optional): per `references` definition below.

## `references` (required)

- Array, `minItems: 1`, `maxItems: 512`, `uniqueItems: true`.
- Each item is a `reference` object:
  - **Required:** `url`.
  - `url`: `uriType` — `format: uri`, `minLength: 1`, `maxLength: 2048`.
    The `uri` format permits any URI scheme (http, https, ftp, ...).
  - `name` (optional): `string`, `minLength: 1`, `maxLength: 512`.
  - `tags` (optional): array, `minItems: 1`, `uniqueItems: true`. Each item
    must match either a `tagExtension` (`^x_.*$`) or a controlled value from
    `reference-tags.json`.
  - `additionalProperties: false`.

## `metrics`

- Optional. Array, `minItems: 1`, `uniqueItems: true`.
- Each item must satisfy `anyOf` requiring one of: `cvssV4_0`, `cvssV3_1`,
  `cvssV3_0`, `cvssV2_0`, or `other`.
- `format` (optional): `string`, `minLength: 1`, `maxLength: 64`.
- `scenarios` (optional): array, `minItems: 1`, `uniqueItems: true`.
- The CVSS v3.1 import (`imports/cvss/cvss-v3.1.json`) enforces:
  - `version` enum: `["3.1"]`.
  - `vectorString` pattern that requires the `CVSS:3.1/` prefix and validates
    every `KEY:VAL` component against the v3.1 metric vocabulary.
  - `baseScore` + `baseSeverity` are required (along with `version` and
    `vectorString`).
  - An `anyOf` block pairs each `baseScore` band (none / low / medium / high /
    critical) with the matching `baseSeverity` enum value, so a score-band
    mismatch is a schema violation.
- The CVSS v3.0 import (`imports/cvss/cvss-v3.0.json`) mirrors the v3.1 one
  with `version` enum `["3.0"]` and a `CVSS:3.0/` vector prefix.
- Not enforced by the schema: that `baseScore` is the score the vector
  actually yields. MITRE stores whatever is submitted. The reviewer covers
  this with `cvss-score-matches-vector` (tier `openjs-extra`), backed by the
  calculator in `lib/cvss.js`.

## `credits`

- Optional. Array, `minItems: 1`, `uniqueItems: true`.
- Each item requires `lang` + `value`.
  - `value`: `string`, `minLength: 1`, `maxLength: 4096`.
  - `user` (optional): UUID v4 pattern.
  - `type` (optional): enum `finder | reporter | analyst | coordinator |
    remediation developer | remediation reviewer | remediation verifier |
    tool | sponsor | other`. Default: `finder`.
- `additionalProperties: false`.

The schema does **not** require any specific `type` (e.g. reporter) to be
present, nor does it forbid the same identity from appearing under multiple
roles. Those are editorial concerns.

## `impacts`

- Optional. Array, `minItems: 1`, `uniqueItems: true`.
- Each item requires `descriptions` (per the `descriptions` definition).
- `capecId` (optional): `string`, `minLength: 7`, `maxLength: 11`,
  `pattern: ^CAPEC-[1-9][0-9]{0,4}$`.

## `configurations`, `workarounds`, `solutions`, `exploits`

- All optional. Each is an array of `description` objects with `minItems: 1`
  and `uniqueItems: true`.

## `timeline`

- Optional. Array, `minItems: 1`, `uniqueItems: true`.
- Each item requires `time` (`timestamp`), `lang`, `value` (`string`,
  `minLength: 1`, `maxLength: 4096`).

## `source`

- Optional. Object with `minProperties: 1`. No further constraints in schema.

## `tags`

- Optional. `cnaTags` array, `minItems: 1`, `uniqueItems: true`. Each tag is
  either a controlled value from `cna-tags.json` or an `x_*` extension.

## `taxonomyMappings`

- Optional. Array, `minItems: 1`, `uniqueItems: true`. Each item requires
  `taxonomyName` + `taxonomyRelations`. Nested length constraints apply.

## Recurring primitive types

- `uriType`: `string`, `format: uri`, `minLength: 1`, `maxLength: 2048`.
- `uuidType`: `string`, `pattern: ^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-4[...]$`
  (v4 UUID).
- `version`: `string`, `minLength: 1`, `maxLength: 1024`.
- `language`: BCP 47 pattern `^[A-Za-z]{2,4}([_-]...)?$`.
- `englishLanguage`: must match `^en([_-]...)?$`.
- `status`: enum `affected | unaffected | unknown`.
- `timestamp`: RFC 3339 / ISO 8601 with optional timezone, validated by pattern.
- `datestamp`: RFC 3339 date-only with a calendar-correct pattern.

## What the schema does NOT enforce

Things callers sometimes assume MITRE enforces but it does not:

- **No minimum description prose length.** MITRE only requires `minLength: 1`.
  An empty-trimmed value such as `"   "` passes the schema.
- **No prohibition on code fences / Markdown in descriptions.** Descriptions
  are plain `string`; the schema is content-neutral.
- **No requirement that any credit role be present.** A container with zero
  credits is schema-valid.
- **No de-duplication across credit roles.** The same identity may appear
  under multiple `type` values without tripping `uniqueItems` (the items
  differ by `type`).
- **No HTTPS requirement on references.** Any URI scheme is accepted.
- **No same-major-version constraint on `version` / `lessThan` pairs.**
- **No requirement that `vendor + product` be used instead of
  `collectionURL + packageName`** — either combo satisfies the `anyOf`.
- **No requirement that `versions` be present** when `defaultStatus` is set
  (the `anyOf` allows either).
