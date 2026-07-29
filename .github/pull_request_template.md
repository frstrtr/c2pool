<!--
Please read CONTRIBUTING.md before opening this PR.

c2pool constructs coinbase transactions and decides who gets paid. Review is
deliberately strict. Delete this comment block and fill in the sections below —
a PR left with template placeholders will be closed unread.
-->

## What this changes

<!-- One or two sentences. What was wrong, what does this do about it. -->

Fixes #<!-- issue number — a real one, not a placeholder -->

## Why this approach

<!-- Why here, why this way. If you considered a broader change and chose not
to, say so. -->

## Checklist

- [ ] **CI is green on this branch.** I opened this PR only after the build and
      tests passed. (A PR with no checks reported has not been verified to
      compile.)
- [ ] **No `SPDX-License-Identifier` line is removed or altered.** This project
      is AGPL-3.0-or-later with an Apache-2.0 engine split.
- [ ] I have the right to contribute this code and agree it may be distributed
      under the project's licence.
- [ ] **This is the smallest change that fixes the problem.** No unrelated
      reformatting, no file replaced wholesale, no public signature changed as
      a side effect.
- [ ] If I deleted anything, I counted its call sites first and either updated
      them or confirmed there are none.
- [ ] Tests included that **fail without this change**.

## Blast radius

<!-- Which coin lanes does this touch? src/core/ is shared by LTC, DOGE, DGB,
BCH, BTC and DASH — a change there affects all of them. Say "single lane: X" or
list them. -->

## Consensus safety

<!-- Tick one.

- [ ] Transport / logging / telemetry / tooling only — cannot change share
      bytes or coinbase outputs.
- [ ] Touches share serialisation, coinbase construction, or payout weighting.
      (If so: explain how it is version-gated. A node producing different bytes
      from its peers has its shares rejected.)
- [ ] Not sure — please advise.

"Not sure" is a fine answer and asking early is welcome.
-->

## How this was tested

<!-- What you actually ran, and what it showed. Include the negative cases for
anything touching address handling, payouts, or P2P message handlers:
malformed input, wrong network, short buffers, peers lacking support. -->
