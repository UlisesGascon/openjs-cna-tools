// Resolve token + base URL from the precedence chain (flags > env > project >
// global) and feed them to a CnaClient.
//
// The CLI passes any explicit --token / --base-url flags as `overrides`.
// Everything else comes from the merged config (see ./config.js).
//
// Validation here is permissive: we surface what we have, the CnaClient
// throws lazy CnaAuthError on the first operation that actually needs a
// credential. That keeps `openjs-cna --help` and `openjs-cna config list`
// usable without any auth at all.

import { getMergedConfig } from './config.js'

export function resolveCredentials ({ overrides = {}, cwd } = {}) {
  const config = getMergedConfig({ cwd })
  return {
    token: overrides.token ?? config.openjs_cna_token,
    baseUrl: overrides.baseUrl ?? config.openjs_cna_base_url
  }
}
