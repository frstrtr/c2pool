# Contributing to c2pool

Contributions are welcome. c2pool is a mining pool: it constructs coinbase
transactions and decides who gets paid. A subtle change in the wrong place
moves other people's money, so the review bar is deliberately high — higher
than the size of a diff would usually suggest.

Please read this before opening a pull request.

## Hard requirements

A PR will not be reviewed until all of these hold.

1. **CI is green on your branch.** Open the PR only after the build and tests
   pass. A PR with no checks reported has not been verified to compile, and
   reviewing uncompiled code wastes everyone's time.
2. **Licensing is preserved.** This project is `AGPL-3.0-or-later`, with an
   Apache-2.0 engine (`c2pool-core-engine`) split out. Every source file
   carries an `SPDX-License-Identifier` line. **Do not remove, alter, or omit
   it.** A PR that strips a license identifier will be closed.
3. **You have the right to contribute the code**, and you agree it may be
   distributed under the project's licence.
4. **The PR description says what changed and why**, and links the issue it
   addresses with a real number. Leave no template placeholders.

## Scope discipline

**Change the smallest thing that fixes the problem.**

- Do not reformat, restructure, or rewrite a file you are fixing a function in.
- Do not replace a file wholesale. If a diff deletes far more than it adds,
  something has gone wrong.
- Do not change a public function's signature or return type as a side effect.
  `src/core/` is shared by every coin lane — LTC, DOGE, DGB, BCH, BTC, DASH —
  and a signature change there breaks all of them.
- Before deleting anything, count its call sites. If it is called, it is used.

If a fix genuinely requires broad change, open an issue and discuss the
approach first.

## Areas with extra scrutiny

Changes here get read line by line, and need tests that demonstrate the
behaviour rather than assert that it compiles:

- **Address handling** (`src/core/address_utils.*`, `address_validator.*`) —
  feeds payout script construction. Never weaken checksum validation. Never
  drop a bounds check before a fixed-width copy.
- **Coinbase construction and payouts** (`*/coinbase_builder.*`, `pplns.*`,
  `share_producer.*`) — consensus-visible. Any change to who receives share
  weight alters share content and must be version-gated, not silently applied.
- **Sharechain and share serialisation** — a node producing different bytes
  from its peers is a node whose shares are rejected.
- **P2P message handlers** — a handler that parses a message and discards the
  result is worse than one that does not exist, because it looks implemented.
  Either do the work or log loudly that you did not.

## Consensus safety

Transport, logging, telemetry and tooling changes are low risk. Anything that
can change the bytes of a share, or the outputs of a coinbase, is not. If you
are unsure which category your change is in, say so in the PR — that question
is welcome and asking it early saves a revert later.

## Tests

New behaviour needs a test that would fail without the change. For the
scrutiny areas above, include the negative cases: malformed input, wrong
network, short buffers, missing peer support. "It builds" is not evidence.

## Reporting a security issue

Do not open a public issue or PR for a vulnerability that could be used to
misdirect funds or disrupt a running pool. Contact the maintainers privately
first.

## What gets closed without detailed review

- PRs with no CI run
- PRs that remove or alter licence identifiers
- Whole-file replacements offered as small fixes
- Machine-generated changes submitted without being built or read, including
  ones that delete working code they do not appear to have examined
- PRs whose description still contains unfilled template text

None of this is meant to discourage genuine contributions. Small, focused,
tested fixes are very welcome, and a first PR that follows the rules above
will get a careful read.
