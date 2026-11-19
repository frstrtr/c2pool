# Sharechain withholding / selfish-sharing defence (#1830)

Status: design only. No code, no consensus change. Tracking issue: #1830.

Scope: the DASH lane, v16 (public network) and v36 (the DASH v36 network that is
about to launch and is expected to become the main one). The p2pool oracle has
no defence against any of the strategies below, so nothing here is a port gap;
it is a protocol-level property of PPLNS sharechains. Everything that touches
consensus is an operator decision and is marked as such.

Code is cited as `file:line` on the branch that was read:

- `v36` = `dash/v36-e2e` at `9635566f146d`
- `master` = `origin/master` at `a301b73ce48f`

## 1. What the chain does today (facts the analysis rests on)

| Fact | Where |
|---|---|
| `SHARE_PERIOD = 20 s`, `CHAIN_LENGTH = REAL_CHAIN_LENGTH = 4320` (24 h), `TARGET_LOOKBEHIND = 100`, `SPREAD = 10` | v36 `src/impl/dash/config_pool.hpp:36-40` |
| v36 PPLNS: window starts at the share's parent, `CHAIN_LENGTH` shares, no weight cap, unrooted chains shorter than `CHAIN_LENGTH` refused | v36 `src/impl/dash/pplns_v36.hpp:19-22`, `:209-229` |
| v36 decay: per-depth factor with `half_life = max(chain_len/4, 1) = 1080` shares (6 h); weight of a share at depth d is `2^(-d/1080)` | v36 `src/impl/dash/pplns_v36.hpp:95-101`, `:114-118`, `:157-184` |
| v36 amounts: full weight, **no block-finder fee**, remainder to the donation script | v36 `src/impl/dash/pplns_v36.hpp:23-25`, `:245` |
| v16 PPLNS: oracle window from the grandparent, `min(height, RCL)-1` shares, capped at `65535*SPREAD*ata(block_target)`, **no decay** | v36 `src/impl/dash/share_producer.hpp:389-400`, `:412-460`, `:950-953` |
| v16 amounts: 49/50 by weight, 1/50 to the block finder | v36 `src/impl/dash/share_check.hpp:981-999`; producer `share_producer.hpp:729-730` |
| Best tail = longest verified chain, then `work / time_span` over the last `CHAIN_LENGTH/16` shares; best head within a tail = **max cumulative work** | v36 `src/impl/dash/share_tracker.hpp:65-76`, `:681-747`, `:1395-1412` |
| Head scoring key = `(work - punish, -reason, -time_seen)`: on equal work the **first-seen** head wins; punish deducts one share's work and applies only to `naughty` heads | v36 `src/impl/dash/share_tracker.hpp:78-92`, `:1470-1497` |
| Naughty propagates 6 generations and drives a walk-back in Phase 5, but nothing on DASH ever seeds it (#1827) | v36 `src/impl/dash/share_tracker.hpp:653-667`, `:1505-1550` |
| Only timestamp rule: `timestamp <= now + 600` on the v36 share profile, none on public v16; no lower bound | v36 `src/impl/dash/share_check.hpp:235-273`, `:320-323`, `:638-639` |
| Any node that verifies a share whose hash meets the block target submits the block | v36 `src/impl/dash/share_tracker.hpp:416-418` |
| A found block is recorded with the finder address, share hash, share difficulty and subsidy | master `src/impl/dash/dashboard_found_block.hpp:82-92`, `:132-140` |
| Luck today is one sample per block (`single_hashrate`), pool-wide, not per miner | master `src/core/web_server.cpp:2622-2660`, `:2737-2757` |
| The CI95 "effective vs reported" diagnostic: Gamma prior `(alpha0 = 5, beta0 = alpha0/lambda_reported)`, posterior `Gamma(alpha0+k, beta0+window)`, band `mean +/- 1.96 sd`, "low evidence" below 3 blocks | master `web-static/dashboard.html:7742-7810` |
| Alert relay over the p2p mesh, `Kind = {Offline, BackOnline, Digest, Test}`, signed and sealed frames, forwarders, acks (#1833) | master `src/impl/dash/alert_relay.hpp:84-95`, `docs/design/d-miner-7-p2p-alert-relay.md` |
| Dashboard payouts are computed from the same window walk the coinbase uses | master `src/impl/dash/dashboard_pplns.hpp:28-37` |

Grep on master for `withhold|selfish` in `src/impl/dash`, `src/pool`, `src/sharechain`,
`src/core` finds only mempool/job-registry comments. There is no defence.

### Derived v36 numbers used below

- `SHARE_PERIOD = 20 s`, `CHAIN_LENGTH = 4320` shares = 24 h of wall time.
- Half-life 1080 shares = **6 h**. Per-share decay factor `2^(-1/1080) = 0.999358`.
- Effective window (sum of decay weights over 4320 shares) = **1461 share-equivalents = 8.1 h**.
  The oldest share in the window still carries `2^-4 = 6.25 %` of a fresh share's weight.
- Weight fraction held by the most recent T hours of the window:

  | T | 0.5 h | 1 h | 2 h | 3 h | 6 h | 12 h | 24 h |
  |---|---|---|---|---|---|---|---|
  | share of window weight | 6.0 % | 11.6 % | 22.0 % | 31.2 % | 53.3 % | 80.0 % | 100 % |

  On v16 the same row would be uniform: `T/24` (2.1 %, 4.2 %, 8.3 %, 12.5 %, 25 %, 50 %, 100 %).
- DASH block period 150 s: 576 blocks/day network-wide.

## 2. Threat model

### 2.1 Actors and the launch profile

The DASH v36 network starts with about **2 % of DASH network hashrate from one large
miner**. Everything else that joins is small. The quantity that matters for every
attack below is not the miner's share of the *network* but its share `f` of the
*sharechain*:

| Other hashrate on the sharechain (% of network) | 0 | 0.5 | 1 | 2 | 4 | 8 |
|---|---|---|---|---|---|---|
| Large miner's fraction `f` of the sharechain | 100 % | 80 % | 67 % | 50 % | 33 % | 20 % |
| Pool block rate (blocks/day) | 11.5 | 14.4 | 17.3 | 23.0 | 34.6 | 57.6 |
| Large miner's mean share interval (`20 s / f`) | 20 s | 25 s | 30 s | 40 s | 60 s | 100 s |

For the foreseeable launch window the large miner is at or above 50 % of the
sharechain. The sharechain **cannot** technically protect a minority against a
miner at `f >= 0.5`; that protection is commercial (the operator's arrangement
with the miner) plus measurement so that misbehaviour is at least visible. The
design must therefore (a) make everything measurable from day one, and (b) be
ready for the day `f` drops below one third, where the mechanisms below start to
have teeth.

Attacker capabilities assumed: runs its own c2pool (or oracle) node, controls
the timestamps and parents of its own shares, can delay or select what it
broadcasts, can split hashrate across several payout addresses (an address is
not an identity), cannot forge other miners' shares, cannot exceed `+600 s`
future timestamps on v36 (`share_check.hpp:248-267`).

### 2.2 Strategy A: block withholding (share, discard the block)

The miner mines public shares normally but, when a share's hash also meets the
DASH block target, it does not broadcast it. On p2pool the block-solving share
*is* the share (`share_tracker.hpp:416-418`), so withholding the block means
withholding that one share as well; the cost to the attacker is one share of
weight (`20/f` seconds of its own work) per withheld block plus its own PPLNS
cut of that block.

Let the attacker hold fraction `f` of the sharechain and withhold all of its
blocks. Pool block rate falls to `(1-f)` of nominal, and:

| `f` | honest miners' income | attacker's income (from honest blocks only) | attacker's honest income |
|---|---|---|---|
| 0.10 | x 0.90 | 0.090 of pool blocks | 0.10 |
| 0.25 | x 0.75 | 0.188 | 0.25 |
| 0.50 | x 0.50 | 0.250 | 0.50 |
| 0.67 | x 0.33 | 0.221 | 0.67 |

Honest miners lose fraction `f` of their income; the attacker loses the same
fraction of its own. **Block withholding by a miner who has nowhere better to
put the hashrate is pure sabotage, never profit.** It becomes profitable only when
the attacker is also a competing pool (the miner's-dilemma setting: the withheld
blocks would otherwise have been shared with that pool's members, so a pool of
size `p1` attacking a pool of size `p2` gains), when it is paid to do it, or via
the second-order difficulty effect (withheld blocks lower the network block rate
so everyone else's blocks are worth a little more), which at 2 % of the network
is below 0.1 % and can be ignored. For a solo attacker with `alpha` of the network
infiltrating a pool of `p` with `beta <= alpha`, revenue is
`(alpha - beta) + p * beta / (p + beta)`, maximised at `beta = 0` for every
`(alpha, p)` in the launch range.

Cost to others per withheld block is `(1-f) * V`, with `V` the miners' part of
the DASH block value. At `f = 0.5` and 11.5 pool blocks/day, honest miners lose
~5.8 blocks/day of revenue share, i.e. half of everything.

Partial withholding (`w` of own blocks) is the realistic version because it is
harder to see: the attacker then loses `w * f` of its own cut and honest miners
lose `w * f` of theirs.

### 2.3 Strategy B: selective share withholding / selfish sharing

The miner keeps its shares back, extends its own branch, and releases the
branch when it is heavier than the public branch so that the honest shares on
the public branch are orphaned. Best-head selection is by cumulative work
(`share_tracker.hpp:1395-1412`, `:1489`), so a heavier withheld branch always
wins; on an equal-work race the first-seen head wins (`:78-92`), which puts the
attacker's tie-win probability `gamma` near zero on nodes that saw the honest
share first.

PPLNS pays by accepted window weight, so the attacker's payout fraction is the
selfish-mining revenue `R(f, gamma)` of Eyal and Sirer applied to shares:

| `f` | `R`, `gamma = 0` | `R`, `gamma = 0.5` | `R`, `gamma = 1` |
|---|---|---|---|
| 0.20 | 0.130 | 0.182 | 0.235 |
| 0.25 | 0.195 | 0.250 | 0.305 |
| 0.30 | 0.273 | 0.327 | 0.381 |
| 0.333 | 0.333 | 0.385 | 0.436 |
| 0.40 | 0.484 | 0.526 | 0.567 |
| 0.45 | 0.652 | 0.681 | 0.709 |
| 0.50 | 1.000 | 1.000 | 1.000 |

Profitability thresholds: `f* = 1/3` at `gamma = 0` (first-seen tie-break, which
is what c2pool does), `f* = 1/4` at `gamma = 0.5`, `f* = 0` at `gamma = 1`. Above
`f = 0.5` the withheld branch is always heavier and the attacker can orphan every
honest share: honest miners are paid nothing while still holding up their end of
the difficulty. Below one third with first-seen tie-breaking, selfish sharing
loses money and the only remaining damage is the orphaned honest shares during
the attempt.

Two p2pool-specific amplifiers:

1. **The block does not need the branch to win.** A block found on the withheld
   branch is a valid DASH block whose coinbase pays the *withheld* branch's window
   (the parent-rooted walk, `pplns_v36.hpp:209-229`). The attacker publishes the
   block with its branch; the honest shares mined since the fork point are simply
   absent from that payout. Head selection matters for *future* payouts, not for
   that block.
2. **v36 decay makes recent exclusion worth more than on v16.** If a withheld
   branch of `T` hours wins, the attacker's window share becomes
   `f + (1-f) * w(T)` with `w(T)` from the table in section 1:

   | `T` | `f = 0.5`, v36 | `f = 0.5`, v16 | `f = 0.67`, v36 | `f = 0.67`, v16 |
   |---|---|---|---|---|
   | 0.5 h | 0.530 | 0.510 | 0.690 | 0.677 |
   | 1 h | 0.558 | 0.521 | 0.708 | 0.684 |
   | 2 h | 0.610 | 0.542 | 0.743 | 0.698 |
   | 3 h | 0.656 | 0.562 | 0.773 | 0.711 |

   A one-hour withheld branch is worth roughly three times more on v36 than on v16.
   The flip side is that honest miners recover in hours rather than a day once
   the attack stops.

The cost to the attacker while the withheld branch is unpublished is that it earns
nothing from honest miners' blocks found in that period (its shares are not in
the public window). For `f < 1/3` that cost dominates; for `f >= 0.5` there are
hardly any honest blocks to forgo.

### 2.4 Strategy C: stale-parent racing and Sybil addresses

- Deliberately mining on a parent one behind the best head to race a specific
  rival share. Cheap, low yield, and the honest first-seen rule makes it lose
  most races; it shows up as an elevated stale-parent rate for one address.
- Splitting hashrate across many payout addresses. It does not change any of
  the economics above but defeats any *per-address* penalty and any per-address
  statistical test with a fixed threshold. Every mitigation below must be read
  with "the address is not an identity" in mind; only work is.

### 2.5 What the 2 % miner can gain or cost others, summarised

| Situation | Gain to the miner | Cost to others |
|---|---|---|
| Block withholding, `f = 0.5` | none (loses `f` of own cut) | honest income halved |
| Block withholding, `f = 0.5`, miner also runs a rival pool | rival pool's members gain what this pool loses | as above |
| Selfish sharing, `f >= 0.5` | up to 100 % of window weight | honest income towards zero |
| Selfish sharing, `f = 0.4` | 0.48 vs 0.40 honest (+21 %) | honest 0.52 vs 0.60 (-13 %) |
| Selfish sharing, `f <= 1/3` | negative | orphaned shares during attempts |
| Any strategy, `f = 1.0` | nothing to gain, nobody to cost | none |

## 3. What is detectable from the chain

All of the following are computable by every node from data it already holds:
the verified window (shares, targets, addresses, timestamps, `time_seen`,
`peer_addr`) and the found-block table.

### 3.1 Expected vs observed blocks per miner (the primary signal)

For an accepted share with share target `t_s` on a block target `t_b`, the
probability that its hash also meets the block target is `t_b / t_s =
ata(t_s) / ata(t_b)`. So the expected number of blocks a miner *should have found*
is exactly the sum of its accepted share work divided by block work:

```
E_m = sum over m's accepted shares of  share_work / ata(block_target at that share)
```

`share_work` is what the tracker already accumulates per share (`chain.get_work`,
`share_tracker.hpp:787`); `block_target` is committed in each share's header.
This is a proven-work estimator, not a reported hashrate, so it is strictly
better than the CI95 diagnostic's "reported" input. Observed `B_m` is the count
of `FoundBlockRow.miner == m` (`dashboard_found_block.hpp:88`). A withheld block
also hides its share, so `E_m` is short by one share per withheld block; at
`20/f` seconds of work per share that bias is negligible.

`B_m ~ Poisson(E_m)` under honest behaviour. Two tests, same as the existing
diagnostic's family:

- **Frequentist band**: flag when `B_m` is below the 2.5 % Poisson quantile of
  `E_m` (warning) or `P(B <= B_m | E_m) < 1 %` (critical).
- **Gamma-Poisson posterior**, reusing the `dashboard.html:7742-7810` form with
  `alpha0 = 5`, `beta0 = alpha0 / lambda_m` (prior centred on the share-work rate)
  and `k = B_m` over the window: "effective block rate" CI95 vs the share-work
  rate. Same "low evidence below 3 blocks" rule.

Detection horizons for a pool at 2 % of the network (11.52 blocks/day):

| Miner's fraction `f` of the sharechain | expected blocks/day | days until 0 blocks is `p < 5 %` | `p < 1 %` |
|---|---|---|---|
| 0.05 | 0.58 | 5.2 | 8.0 |
| 0.10 | 1.15 | 2.6 | 4.0 |
| 0.25 | 2.88 | 1.0 | 1.6 |
| 0.50 | 5.76 | 0.5 | 0.8 |
| 1.00 | 11.52 | 0.3 | 0.4 |

Partial withholding at `f = 0.5` (5.76 expected blocks/day), one-sided test at
5 %, 80 % power: `w = 0.75` in ~2 days, `w = 0.5` in ~4 days, `w = 0.25` in
~16 days. Anything below `w = 0.25` needs a month or more and is indistinguishable
from bad luck at these block rates; that is the floor of what measurement can do.

Whole-pool bands for reference (2 % of network): 1 day `[5, 19]` around 11.5,
7 days `[64, 99]` around 80.6, 30 days `[310, 383]` around 345.6.

Sybil note: an attacker splitting across `n` addresses divides `E_m` by `n` and
lengthens each per-address horizon by `n`; the pool-wide test (sum over all
addresses, i.e. the existing luck line made per-work rather than per-block) is
Sybil-proof and should be reported alongside.

### 3.2 Share-timing patterns

Every share carries the miner's `timestamp` and the node records `time_seen`
(`share_tracker.hpp:1475`) and `peer_addr` (`:912-917`). Honest propagation puts
`time_seen - timestamp` at a second or two. Signals per payout address and per
peer:

- **Arrival delay**: median and p95 of `time_seen - timestamp`. A withheld branch
  shows delays of many share periods.
- **Burst arrival**: `n >= 3` shares from one address arriving within one second
  whose timestamps are spaced ~`20/f` s apart, forming a parent chain. This is the
  release of a withheld branch.
- **Stale-parent rate**: fraction of an address's shares whose parent was not
  this node's best head at `time_seen`. Honest baseline is roughly
  `propagation delay / 20 s`; a miner racing or releasing branches sits well above it.
- **Difficulty drift**: share timestamps feed the retarget over
  `TARGET_LOOKBEHIND = 100` shares (`config_pool.hpp:39`). An attacker can push
  its timestamps forward (up to `+600 s` on v36, unbounded on v16) to disguise
  arrival delay, at the price of distorting the retarget in a way that is itself
  visible: compare the timestamp-derived share rate with the `time_seen`-derived
  rate over the same 100 shares.

Timing signals are local (each node sees its own `time_seen`) and are affected by
clock skew, so they are corroboration for 3.1 and 3.3, never a standalone verdict.

### 3.3 Orphan-on-release patterns

When the best head moves to a different branch, attribute the shares that fell
off the old head and the shares that make up the winning segment to their payout
addresses. Under honest racing both sides are a random draw from the miner
population; under selfish sharing the winning segment is one address and the
losers are everyone else, repeatedly. Per event, the probability that a winning
segment of `n` shares is single-authored by chance is about `f^n`; three events
with `n >= 3` from the same address at `f = 0.5` is already `p < 0.2 %`.

Report per address: orphaned-share count and weight, "displaced others" count,
and the pool's natural orphan rate `epsilon` (the structural floor from
propagation latency) so the operator sees the excess, not the raw number.
Orphaned weight is exactly the money the honest side lost, so this statistic
also prices the damage.

## 4. Mitigation options

Each option is marked **measurement only**, **local policy** (changes what this
node does or which head it extends; never changes a coinbase) or **consensus
change** (changes share validity or payout; needs a share-version bump and the
60 % weighted switch rule, and splits from oracle nodes that do not implement it).

### 4.1 Measurement and dashboard alerting — measurement only

- Per-address `expected_blocks`, `found_blocks`, Poisson `p`, CI95 effective
  block rate, share of window weight; pool-wide `expected_blocks_from_work` next
  to the existing luck aggregate (`web_server.cpp:2737-2757`).
- Per-address timing: arrival delay p50/p95, burst count, stale-parent rate.
- Per-reorg orphan attribution and the per-address "displaced others" counter.
- Dashboard: one card per miner with verdict text in the CI95 style
  (`Low evidence` / `OK` / `Warning` / `Critical`), plus the pool-wide row.
- Alerting: a new `Kind` in the alert relay (`alert_relay.hpp:84`), e.g.
  `Anomaly = 5`, carrying `address, expected, found, p, kind_of_signal`, sent by
  any node that runs the detector, delivered to the designated Telegram group by
  the relay exactly as offline alerts are (#1833). Also a log line and a JSON
  field so a node without the relay still surfaces it.

Costs: an `O(window)` walk per refresh, already done for the payouts view
(`dashboard_pplns.hpp:28-37`); a few hundred bytes of state per address;
additive JSON. Consensus impact: none. Oracle compatibility: full (oracle nodes
simply do not show it). False positives: bounded by the chosen `p`; with the
`< 3 expected blocks` gate nothing fires on a miner too small to test.

### 4.2 Payout-side penalties — consensus change

Reduce the PPLNS weight of shares whose address is statistically short of blocks
(a "luck-weighted PPLNS"). The statistic *is* chain-deterministic: block-solving
shares are visible to every node by their hash, and `E_m` is a function of the
window, so every node could compute the same penalty. It is still a bad first
move:

- Poisson variance at 5-12 blocks/day guarantees honest miners get penalised; the
  penalty would have to be so mild (or the horizon so long) that it does not
  deter.
- The address is not an identity: the attacker splits hashrate and every
  per-address penalty evaporates (section 2.4).
- It changes the coinbase, so it is a share-version bump and a hard split from
  oracle nodes and from every c2pool build that does not carry it.

A milder consensus option with a real track record: **reinstate a block-finder
fee on v36**. v16 pays 1/50 to the finder (`share_check.hpp:997-999`); v36
removed it (`pplns_v36.hpp:23-24`). A finder fee `phi` makes each withheld block
cost the attacker `phi * V` on top of its PPLNS cut, which shifts the miner's-dilemma
profit region for a rival-pool attacker and is the classic anti-withholding
lever. It does nothing against selfish sharing. It is a coinbase change, so it
is also a consensus change and oracle-incompatible with p2pool-merged-v36.

Recommendation: keep both on the list for a v37 discussion, do not ship either
without Phase 1 data showing an actual loss.

### 4.3 Share-release / acceptance rules — local policy

Rules that change which head *this node* extends without changing any coinbase:

- **First-seen tie-break** (already in place, `share_tracker.hpp:78-92`): keeps
  `gamma` near 0 and the selfish threshold at 1/3. Keep it; the uniform tie-break
  proposed in the selfish-mining literature raises the threshold only to 1/4 and
  is worse here.
- **Late-arrival discount**: score a head whose shares arrived more than `X`
  seconds after their timestamps (or as a burst) as if it carried one share less
  work, i.e. the existing punish deduction (`:1489-1496`) with a new reason. A
  withheld branch then has to out-work the honest branch by one extra share to
  displace it, which turns every marginal release into a loss for `f < 0.5`. It
  cannot stop `f >= 0.5`. Because each node scores with its own `time_seen`, nodes
  can briefly disagree on the best head; they reconverge as work accumulates,
  exactly as they do on any race today. Oracle nodes ignore the rule and follow
  raw work, so mixed networks lean towards the raw-work answer.
- **Acceptance throttle**: refuse to *relay* (still store) more than `N` shares
  per second from one peer that form a chain older than `X`. This slows the
  release of a withheld branch through this node but cannot stop it reaching
  others, so it is only a nuisance to the attacker and a footgun for a node that
  is catching up after downtime. Not recommended.

Local policy costs nothing on the wire and is reversible by flag. It must ship
**default OFF** with the measurement from 4.1 as its only justification for
being turned on, because a wrong `X` on a network with a slow link would
penalise honest miners behind it.

### 4.4 The naughty / punish mechanism — local policy (with a prerequisite)

`naughty` exists to deprioritise heads built on invalid-block shares: seeded in
the oracle when a share's block fails validation, propagated 6 generations
(`share_tracker.hpp:653-667`), deducted from head work (`:1489-1496`) and walked
back in Phase 5 (`:1505-1550`). On DASH it is inert because nothing seeds it
(#1827). It is the natural enforcement hook for 4.3's late-arrival discount:
a new `reason` value, the same deduction, the same walk-back. Order of work:

1. Fix #1827 for its original purpose (port the seeding point, add the KAT that a
   head built on an invalid-block share loses selection).
2. Only then add further reasons behind flags.

Using punish for withholding has the same limits as any local policy: it is a
head-selection nudge worth one share of work, it cannot stop a majority, and it
must never be seeded from a non-deterministic statistic in a way that changes a
coinbase (it does not today: the coinbase is derived from the chain, not from
the score).

### 4.5 Out of scope, recorded for completeness — consensus change

- Oblivious shares (a miner cannot tell whether its share is a block): needs a
  two-stage commitment that p2pool's miner-built coinbase cannot provide.
- Timestamp attestation by receiving nodes (unforgeable "freshness"): a new wire
  and share format, and it moves the trust to the attesting nodes.
- Shortening the decay half-life to shrink the exclusion window of a withheld
  branch: trades a little selfish-sharing exposure for much higher payout
  variance for every honest miner; not worth it at launch scale.

## 5. Recommended phased plan

### Phase 0 — accept the launch profile (operator, now)

At `f >= 0.5` no sharechain rule constrains the large miner; the protection is
the commercial arrangement plus visibility. Record that as the launch position
so nobody reads the absence of a defence as a bug later. Measurement is what
makes the arrangement checkable.

### Phase 1 — ship measurement first (no operator decision needed beyond thresholds)

1. Per-address `expected_blocks` from accepted share work, `found_blocks`,
   Poisson `p` and the Gamma-Poisson CI95 band, with the `< 3 expected` gate;
   pool-wide `expected_from_work` beside the existing luck line.
2. Per-address arrival-delay p50/p95, burst count, stale-parent rate.
3. Per-reorg orphan attribution and "displaced others" per address, with the
   pool's natural orphan rate shown as the baseline.
4. JSON fields (additive), a dashboard card per miner, log lines, and an
   `Anomaly` alert kind through the relay (#1833) with `Warning` at Poisson
   `p < 2.5 %` and `Critical` at `p < 1 %` or zero blocks with `E_m >= 4.6`.
5. Soak on the DASH v36 network from launch so the false-positive rate is
   known before anything else is built on the numbers.

Everything in Phase 1 is measurement only, oracle-compatible, and carries no
consensus risk.

### Phase 2 — local policy, default OFF (operator decision: on/off and `X`)

1. Seed `naughty` (#1827) and land its KAT.
2. Add the late-arrival / burst reason behind `--sharechain-late-punish X`
   (default off). Turn it on only if Phase 1 shows selfish-sharing signatures
   (3.2 + 3.3 together) and `f` is below 0.5.

### Phase 3 — consensus, only with evidence (operator decision, v37)

Finder fee on v36 or a luck-weighted window, decided on Phase 1 data showing an
actual loss, shipped as a share-version bump with the 60 % weighted switch rule,
and only once the DASH v36 network is c2pool-only (both are oracle-incompatible).

### Decisions that belong to the operator

| Decision | Why it is the operator's |
|---|---|
| Alert thresholds (`p`, minimum expected blocks) and who receives the alerts | trades false pages against detection delay on a network with ~12 blocks/day |
| Whether a payout address counts as an identity for any penalty | a per-address rule can be evaded by splitting; a per-work rule cannot single anyone out |
| Turning on any punish/discount rule and its `X` | it can penalise honest miners behind a slow link |
| Any consensus change (finder fee, luck-weighted window) | money and a hard split from oracle nodes |
| The Phase 0 position on the launch miner at `f >= 0.5` | a commercial arrangement, not a protocol property |

## 6. References

- Rosenfeld, "Analysis of Bitcoin Pooled Mining Reward Systems" (2011): block
  withholding and the finder-fee argument.
- Eyal, Sirer, "Majority is not Enough: Bitcoin Mining is Vulnerable" (2014):
  the selfish-mining revenue `R(alpha, gamma)` and thresholds used in 2.3.
- Eyal, "The Miner's Dilemma" (2015): why block withholding pays for a pool
  attacking a pool and not for a solo miner.
- Courtois, Bahack, "On Subversive Miner Strategies and Block Withholding
  Attack" (2014): the second-order difficulty effect.
- #1827 (naughty inert on DASH), #1833 (alert relay), `web-static/dashboard.html:7742`
  (existing CI95 Gamma-Poisson diagnostic).
