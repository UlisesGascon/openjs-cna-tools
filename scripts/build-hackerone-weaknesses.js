#!/usr/bin/env node
// Regenerate lib/hackerone/weaknesses.json from a HackerOne GraphQL dump.
//
//   node scripts/build-hackerone-weaknesses.js <dump.json>
//
// HackerOne stores a report's weakness as its own numeric id (the
// `weakness_id` the REST API returns). The CWE lives on the weakness
// itself as `external_id` (`cwe-284`), and HackerOne's taxonomy is shared
// by every program. The dump is the response of the GraphQL query the
// HackerOne web app issues for a report's "weakness" picker, which lists
// the team's enabled weaknesses:
//
//   data.reports.nodes[0].team.team_weaknesses.edges[].node.weakness
//     { database_id, name, external_id }
//
// Only id, CWE and name are kept. Entries whose external_id is not a CWE
// (CAPEC ids, null) keep `cwe: null` so a lookup can tell "known weakness
// without a CWE" from "unknown id".

import { readFileSync, writeFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const here = dirname(fileURLToPath(import.meta.url))
const target = resolve(here, '..', 'lib', 'hackerone', 'weaknesses.json')

const source = process.argv[2]
if (!source) {
  process.stderr.write('Usage: node scripts/build-hackerone-weaknesses.js <dump.json>\n')
  process.exit(64)
}

const dump = JSON.parse(readFileSync(source, 'utf8'))
const edges = dump?.data?.reports?.nodes?.[0]?.team?.team_weaknesses?.edges
if (!Array.isArray(edges)) {
  process.stderr.write('✖ dump has no data.reports.nodes[0].team.team_weaknesses.edges\n')
  process.exit(65)
}

const weaknesses = {}
for (const edge of edges) {
  const weakness = edge?.node?.weakness
  const id = String(weakness?.database_id ?? '').trim()
  if (!id) continue
  const cwe = String(weakness.external_id ?? '').match(/^cwe-(\d+)$/i)?.[1] ?? null
  weaknesses[id] = {
    cwe: cwe ? `CWE-${cwe}` : null,
    name: String(weakness.name ?? '').trim()
  }
}

const ids = Object.keys(weaknesses).sort((a, b) => Number(a) - Number(b))
const output = {
  _generated: {
    date: new Date().toISOString().slice(0, 10),
    source: 'HackerOne GraphQL team_weaknesses dump, see scripts/build-hackerone-weaknesses.js',
    entries: ids.length,
    withCwe: ids.filter((id) => weaknesses[id].cwe).length
  },
  weaknesses: Object.fromEntries(ids.map((id) => [id, weaknesses[id]]))
}

writeFileSync(target, `${JSON.stringify(output, null, 2)}\n`)
process.stderr.write(`✔ ${ids.length} weaknesses (${output._generated.withCwe} with a CWE) written to ${target}\n`)
