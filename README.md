# OpenJS CNA Tools

[![npm](https://img.shields.io/npm/v/@openjsfoundation/cna-tools.svg?style=flat-square)](https://npmjs.org/package/@openjsfoundation/cna-tools)

CLI and library for operating the [OpenJS Foundation CNA API](https://cna.openjsf.org/api.html).

For project maintainers under the OpenJS CNA who need to reserve, publish, update, and inspect CVEs against the OpenJS CNA API (MITRE wrapper) without leaving their terminal.

<!-- TOC -->

- [Commands](#commands)
- [Usage](#usage)
  - [Install](#install)
  - [Setting up CNA credentials](#setting-up-cna-credentials)
  - [Protecting your credentials](#protecting-your-credentials)
  - [Typical workflow](#typical-workflow)
  - [Troubleshooting](#troubleshooting)
- [Library](#library)
- [Design](#design)
- [License](#license)

<!-- /TOC -->

## Commands

`openjs-cna` is a single binary that dispatches subcommands.

| Command | Description |
|---|---|
| `openjs-cna reserve` | Reserve a CVE id and print it on stdout. |
| `openjs-cna publish <cve-id> -f container.json` | Publish a v5.2 CNA Container. Runs the reviewer first by default. |
| `openjs-cna update <cve-id> -f container.json` | Update a published CVE record. Same review semantics as `publish`. |
| `openjs-cna get <cve-id>` | Fetch a published CVE's container from MITRE. |
| `openjs-cna list` | List every CVE id in the bucket. |
| `openjs-cna convert <advisory-url>` | Turn a GitHub Security Advisory into a draft CNA Container. Accepts published per-repo URLs (`https://github.com/<owner>/<repo>/security/advisories/<GHSA>`) and global-database URLs (`https://github.com/advisories/<GHSA>`) for public ones. |
| `openjs-cna review <container.json>` | Run the offline reviewer against a container. Defaults to showing a preview + issues. Exits non-zero on blockers. |
| `openjs-cna preview <container.json>` | Print a compact summary of a container — title, description, affected, CVSS, CWE, credits, refs, etc. |
| `openjs-cna llm-review-prompt <record.json>` | Print a prompt for an LLM-driven editorial review of the record's title and description. The tool does not call an LLM; paste the prompt into the LLM of your choice. |
| `openjs-cna health` | Unauthenticated liveness check against the CNA API. |
| `openjs-cna config` | Read / write `openjs-cna` configuration. |

Run `openjs-cna <command> --help` for command-specific options.

## Usage

### Install

```sh
pnpm add -g @openjsfoundation/cna-tools
# or
npm install -g @openjsfoundation/cna-tools
```

To build from source:

```sh
git clone https://github.com/openjs-foundation/cna-tools.git
cd cna-tools
pnpm install
pnpm link --global
```

Requires Node.js **22.0.0** or newer. The package is ESM-only and uses native `fetch`, `node:util parseArgs`, and `node:readline/promises`. Runtime dependencies are [`ajv`](https://github.com/ajv-validator/ajv) and [`ajv-formats`](https://github.com/ajv-validator/ajv-formats), used solely for JSON Schema validation against MITRE's official v5.2 CNA Container schema.

### Setting up CNA credentials

`openjs-cna` needs two values to talk to the CNA API:

- `openjs_cna_token` — bearer in `bucket:secret` form. Your CNA coordinator issues this.
- `openjs_cna_base_url` — the API base URL (e.g. `https://cna.openjsf.org`).

Configure them with `openjs-cna config`:

```sh
openjs-cna config set openjs_cna_token    "<bucket>:<hex-secret>"
openjs-cna config set openjs_cna_base_url "https://cna.openjsf.org"
```

> **Stored values are not encrypted at rest.** They live as plaintext in `~/.config/openjs-cna/config.json` with file mode `0600`. If you'd rather not put a token on disk, pass them via environment variables instead:
>
> ```sh
> export OPENJS_CNA_TOKEN="<bucket>:<hex-secret>"
> export OPENJS_CNA_BASE_URL="https://cna.openjsf.org"
> ```

Configuration is layered. Precedence (highest first):

1. CLI flag (`--token`, `--base-url`)
2. Environment (`OPENJS_CNA_*`)
3. Project config (`./.openjs-cna.json` in CWD)
4. Global config (`~/.config/openjs-cna/config.json` or `$XDG_CONFIG_HOME/openjs-cna/config.json`)

### Protecting your credentials

Add the following to your [global `gitignore`](https://git-scm.com/docs/git-config#Documentation/git-config.txt-coreexcludesFile) (or the per-repo `.gitignore` if you only need it locally):

```
# openjs-cna-tools project-scope config
.openjs-cna.json
```

The global config at `~/.config/openjs-cna/config.json` lives outside any repo, so it doesn't need a gitignore entry. The project-scope `.openjs-cna.json` does.

If you ever commit a token, revoke it with your CNA coordinator and request a new one.

### Typical workflow

```sh
# 1. Reserve a CVE id for an upcoming release.
CVE=$(openjs-cna reserve)
echo "Reserved $CVE"

# 2. Draft a container from a published GitHub Security Advisory.
#    `--cve` stamps cveMetadata.cveId into the container so step 5 can
#    cross-check the CLI argument against it.
openjs-cna convert https://github.com/owner/repo/security/advisories/GHSA-xxxx-xxxx-xxxx \
  --cve "$CVE" > container.json

# 3. (Optional) Editorial polish via an LLM. Pipes a prompt to your
#    clipboard; paste it plus container.json into the LLM of your choice.
openjs-cna llm-review-prompt container.json | pbcopy

# 4. Review before you publish. The output renders a preview of the
#    container plus the issues list (tip: edit visually at
#    https://vulnogram.org/#source).
openjs-cna review container.json

# 5. Publish. Review runs again automatically (strict, warnings block);
#    if `container.cveMetadata.cveId` is set, it must match "$CVE" or
#    publish aborts before sending anything to MITRE.
openjs-cna publish "$CVE" -f container.json
```

Useful flags:

- `--no-strict` (on `review`, `publish`, `update`): let warnings pass as warnings. True blockers still abort.
- `--skip-review` (on `publish`, `update`): bypass the reviewer entirely. Discouraged.
- `--no-preview` (on `review`): drop the container summary; print issues only. Useful in CI.
- `--tier mitre-common|openjs-extra` (on `review`): filter the printed issues to a single tier without changing the exit code.
- `--yes` / `OPENJS_CNA_YES=1`: accept confirmation prompts non-interactively.

### Troubleshooting

- **Review reports schema blockers**: paste the container into <https://vulnogram.org/#source> to edit it visually; rerun `openjs-cna review` when done.
- **Publish fails with a CVE-id mismatch**: the CLI argument and `container.cveMetadata.cveId` disagree. Re-check which container you meant to publish before retrying.
- **An operation errors out**: the CLI prints `correlation_id` and `run_id`. Forward both to your CNA coordinator — that's everything they need to look up the underlying GitHub Actions run. (We deliberately don't surface the run URL because most operators don't have access to it.)

## Library

The same module powers the CLI and is importable for automation:

```js
import { CnaClient } from '@openjsfoundation/cna-tools/client'
import { reviewRecord } from '@openjsfoundation/cna-tools/review'
import { convertGhsaToRecord } from '@openjsfoundation/cna-tools/convert'

const cna = new CnaClient({
  token: process.env.OPENJS_CNA_TOKEN,
  baseUrl: process.env.OPENJS_CNA_BASE_URL
})

const { cveId } = await cna.reserveCve()

// `source` is a published GitHub advisory URL. References (including any
// vendor-advisory blog post you want surfaced on the CVE record) come
// from the advisory's own `references[]` — set them on GitHub, not via
// any per-call override here. Pass `cveId` to stamp it into `cveMetadata`.
const record = await convertGhsaToRecord({
  source: 'https://github.com/owner/repo/security/advisories/GHSA-xxxx-xxxx-xxxx',
  cveId
})

// reviewRecord is strict by default — warnings count as blockers.
// Pass `{ strict: false }` to surface warnings as warnings.
const report = reviewRecord(record)
if (report.summary.blockers > 0) {
  throw new Error('record is not ready to publish')
}

await cna.publishCve(cveId, record.containers.cna)
```

Error classes (`CnaAuthError`, `CnaTimeoutError`, `CnaOperationError`, `CnaReviewBlockedError`) are exported from the package root.

## Design

- **Two runtime dependencies.** Built on Node.js 22+ built-ins (`fetch`, `node:test`, `node:util parseArgs`, `node:readline/promises`) with [`ajv`](https://github.com/ajv-validator/ajv) + [`ajv-formats`](https://github.com/ajv-validator/ajv-formats) — used only for validating containers against MITRE's official v5.2 schema before publish.
- **Validates against MITRE's official schema.** The CVE Record Format schema and its companion files (CVSS v2/v3/v4, CNA/ADP/reference tags) ship bundled from the [CVE Project](https://github.com/CVEProject/cve-schema). `openjs-cna review` and the default behavior of `openjs-cna publish` catch anything that would fail at MITRE.
- **Two-tier rule classification.** Issues carry a `tier`: `mitre-common` (MITRE's schema itself would reject) or `openjs-extra` (OpenJS Foundation editorial preference, stricter than MITRE). The `--tier mitre-common` flag on `review` filters the printed list without changing the exit code.
- **Preview before commit.** `openjs-cna preview` and the default `openjs-cna review` render a full summary of the container (title, full description, every affected package, CVSS, CWE, credits, references) so an operator can see *exactly* what they're about to send. The output includes a tip to edit the JSON visually at <https://vulnogram.org/#source>.
- **Strict by default.** `review`, `publish`, and `update` treat warnings as blockers. Pass `--no-strict` only when you understand the warning is acceptable.
- **CVE-id consistency.** When `container.cveMetadata.cveId` is set and the CLI argument differs, `publish` and `update` abort before touching MITRE.
- **Multi-package advisories handled.** One CNA Container can carry every package an advisory affects (the lodash family of per-method packages is a common case). The converter expands GHSA's `vulnerabilities[]` array into MITRE's `affected[]` entries one-to-one.
- **GHSA descriptions are Markdown.** The converter declares `descriptions[].supportingMedia[]` with `type: 'text/markdown'` so the formatting isn't lost on the way to MITRE.
- **Identified at the source.** Every container the converter produces carries `cna.x_generator = { engine: '@openjsfoundation/cna-tools <version>' }`, and every outbound HTTP call uses the same string as `User-Agent`. A downstream reviewer can always trace a record back to the exact tool version that drafted it.
- **Operator-friendly error surfacing.** Failures emit `correlation_id` and `run_id` (not opaque GitHub URLs) so operators can forward a single line to a coordinator.
- **Stdout is data; stderr is the show.** Every command's primary output goes to stdout so `CVE=$(openjs-cna reserve)` works without flags. Spinners, prompts, and progress go to stderr.
- **The constructor does no I/O.** `new CnaClient()` makes zero network calls. Credentials are validated lazily on the first operation that needs them.

The design draws heavily on [`node-core-utils`](https://github.com/nodejs/node-core-utils) — lazy auth accessors, errors that double as setup instructions, yargs-as-router (`node:util parseArgs` here), stdout/stderr discipline, and no mocking library. A longer design write-up will land in `docs/` as the package matures.

## License

MIT. See [LICENSE](./LICENSE).
