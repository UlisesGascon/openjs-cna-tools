// Matrix of GHSA-style `vulnerable_version_range` strings to the MITRE
// v5.2 `affected[].versions[]` shape we expect to emit from them.
//
// The cases below were extracted from a sweep of real GHSA advisories
// and cluster into 12 conceptual categories. Several categories cover
// multiple syntactic spellings (e.g. `< 1.0.0`, `<1.0.0`, `=< 1.0.0`,
// `=<1.0.0` all collapse to "upper-bound exclusive").
//
// Convention for MITRE output:
//
//   * `versionType: 'semver'` for every semver-shaped value.
//   * `versionType: 'git'`     for raw commit hashes.
//   * `versionType: 'custom'`  for freeform inputs we cannot parse.
//   * `version: '0'`           when GHSA gave no lower bound (the
//                              MITRE schema requires `version`).
//   * `status: 'affected'`     on every emitted entry.
//   * Empty / `*` / `all` / unparseable input still emits a single
//     `versions[]` entry so downstream tools have something to react to;
//     the converter should warn at the same time, not silently swallow.
//
// Multi-range inputs (`; ` or `&&` separated) expand into multiple entries.

export const VERSION_RANGE_MATRIX = [
  // --- single version ----------------------------------------------------
  {
    category: 'single-version-bare',
    input: '4.6.2',
    expected: [
      { version: '4.6.2', status: 'affected', versionType: 'semver' }
    ]
  },
  {
    category: 'single-version-equals',
    input: '= 4.17.23',
    expected: [
      { version: '4.17.23', status: 'affected', versionType: 'semver' }
    ]
  },

  // --- upper bound only --------------------------------------------------
  {
    category: 'upper-exclusive-spaced',
    input: '< 5.0.0',
    expected: [
      { version: '0', lessThan: '5.0.0', status: 'affected', versionType: 'semver' }
    ]
  },
  {
    category: 'upper-exclusive-tight',
    input: '<4.17.24',
    expected: [
      { version: '0', lessThan: '4.17.24', status: 'affected', versionType: 'semver' }
    ]
  },
  {
    category: 'upper-inclusive-spaced',
    input: '<= 4.6.2',
    expected: [
      { version: '0', lessThanOrEqual: '4.6.2', status: 'affected', versionType: 'semver' }
    ]
  },
  {
    category: 'upper-inclusive-tight',
    input: '<=4.18.1',
    expected: [
      { version: '0', lessThanOrEqual: '4.18.1', status: 'affected', versionType: 'semver' }
    ]
  },
  {
    category: 'upper-inclusive-typo-spaced',
    input: '=< 5.8.1',
    expected: [
      { version: '0', lessThanOrEqual: '5.8.1', status: 'affected', versionType: 'semver' }
    ]
  },
  {
    category: 'upper-with-v-prefix',
    input: '< v5.2.1',
    expected: [
      { version: '0', lessThan: '5.2.1', status: 'affected', versionType: 'semver' }
    ]
  },

  // --- lower bound only --------------------------------------------------
  {
    category: 'lower-inclusive-spaced',
    input: '>= 3.7.0',
    expected: [
      { version: '3.7.0', status: 'affected', versionType: 'semver' }
    ]
  },
  {
    category: 'lower-exclusive',
    input: '> 1.20.1',
    expected: [
      { version: '1.20.1', status: 'affected', versionType: 'semver' }
    ]
  },

  // --- bounded ranges ----------------------------------------------------
  {
    category: 'range-comma-both-exclusive',
    input: '>=4.0.0, <4.18.0',
    expected: [
      { version: '4.0.0', lessThan: '4.18.0', status: 'affected', versionType: 'semver' }
    ]
  },
  {
    category: 'range-comma-inclusive-upper',
    input: '>= 4.0.0, <= 4.18.1',
    expected: [
      { version: '4.0.0', lessThanOrEqual: '4.18.1', status: 'affected', versionType: 'semver' }
    ]
  },
  {
    category: 'range-space-inclusive-upper',
    input: '>= 4.0.0 <= 4.10.1',
    expected: [
      { version: '4.0.0', lessThanOrEqual: '4.10.1', status: 'affected', versionType: 'semver' }
    ]
  },
  {
    category: 'range-hyphen',
    input: '4.0.0 - 4.17.23',
    expected: [
      { version: '4.0.0', lessThanOrEqual: '4.17.23', status: 'affected', versionType: 'semver' }
    ]
  },

  // --- caret/tilde semver shortcuts -------------------------------------
  {
    category: 'caret-range',
    input: '^4.19.2',
    expected: [
      { version: '4.19.2', lessThan: '5.0.0', status: 'affected', versionType: 'semver' }
    ]
  },

  // --- multi-line ranges (split on `; ` or `&&`) -------------------------
  {
    category: 'multi-line-semicolon',
    input: '< 6.24.0; 7.0.0 < 7.24.0',
    expected: [
      { version: '0', lessThan: '6.24.0', status: 'affected', versionType: 'semver' },
      { version: '7.0.0', lessThan: '7.24.0', status: 'affected', versionType: 'semver' }
    ]
  },
  {
    category: 'multi-line-three',
    input: '>= 4.5.0 < 5.28.5; >= 6.0.0 < 6.21.1; >= 7.0.0 < 7.2.3',
    expected: [
      { version: '4.5.0', lessThan: '5.28.5', status: 'affected', versionType: 'semver' },
      { version: '6.0.0', lessThan: '6.21.1', status: 'affected', versionType: 'semver' },
      { version: '7.0.0', lessThan: '7.2.3', status: 'affected', versionType: 'semver' }
    ]
  },
  {
    category: 'multi-line-ampersand',
    input: '<= 1.0.1 && 2.0.0 <= 2.2.0',
    expected: [
      { version: '0', lessThanOrEqual: '1.0.1', status: 'affected', versionType: 'semver' },
      { version: '2.0.0', lessThanOrEqual: '2.2.0', status: 'affected', versionType: 'semver' }
    ]
  },

  // --- wildcards ---------------------------------------------------------
  {
    category: 'wildcard-all',
    input: 'all',
    expected: [
      { version: '0', status: 'affected', versionType: 'semver' }
    ]
  },
  {
    category: 'wildcard-star',
    input: '*',
    expected: [
      { version: '0', status: 'affected', versionType: 'semver' }
    ]
  },

  // --- commit hash references --------------------------------------------
  {
    category: 'commit-hash-upper-bound',
    input: '< 3469357cff39',
    expected: [
      { version: '0', lessThan: '3469357cff39', status: 'affected', versionType: 'git' }
    ]
  },

  // --- unparseable / freeform -------------------------------------------
  {
    category: 'empty',
    input: '',
    expected: []
  },
  {
    category: 'freeform-prose',
    input: 'issue observed on commit 39fd982794217d5747a3bdf6541cdbada87eaecb; released version tags still need confirmation',
    expected: [
      { version: '39fd982794217d5747a3bdf6541cdbada87eaecb', status: 'affected', versionType: 'custom' }
    ]
  },
  {
    category: 'freeform-name',
    input: 'Leangheng2004',
    expected: [
      { version: 'Leangheng2004', status: 'affected', versionType: 'custom' }
    ]
  },

  // --- prose annotations alongside semver --------------------------------
  {
    category: 'parenthetical-annotation',
    input: '<= 5.2.1 (includes all 4.x)',
    expected: [
      { version: '0', lessThanOrEqual: '5.2.1', status: 'affected', versionType: 'semver' }
    ]
  },
  {
    category: 'package-name-prefix',
    input: 'lodash <= 4.18.1',
    expected: [
      { version: '0', lessThanOrEqual: '4.18.1', status: 'affected', versionType: 'semver' }
    ]
  }
]
