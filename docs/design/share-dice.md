# Design: provably-fair share-dice (PPLNS bet, donation-address house)

Status: DRAFT / design-only. No code. Nothing here is implemented or armed.
Sibling of #157 (tx-injection runtime): both are operator-armed, default-OFF,
money-path features. This document is a feasibility study and full design; it
is written to be rejected as easily as accepted.

---

## 0. Feasibility verdict (read this first)

**Is the dice sound and genuinely "simple"? Yes — the fairness primitive is.**
The provably-fair roll is a standard, well-understood commit-reveal construction
(server-seed hash chain + client entropy), roughly a hundred lines of pure hash
arithmetic with no consensus surface. It is sound against both a grinding miner
and a cheating house, and it is the *easy* part.

**Where it gets hard is not the dice — it is the money.** Three things make this
a genuinely delicate feature, and none of them are about randomness:

1. **The sharechain is consensus.** In c2pool the PPLNS payout is *recomputed
   from the shared sharechain by every node* (`src/impl/dash/pplns.hpp`,
   `compute_payouts()` walks shares backward and splits the block value by
   per-share weight). Shares carry a `donation` field and a weight; every node
   derives the same coinbase from the same shares. **Putting a bet into a share
   is therefore a network-wide consensus fork** — every p2pool node would have
   to adopt new share-validation rules or reject the modified shares. That is a
   non-starter for adoption and is explicitly rejected below (§3). The dice must
   live in a **pool-LOCAL accounting overlay** that never touches shares.

2. **Settlement realization is a trust boundary, not a proof.** Because we may
   not touch shares, "settlement in shares" can only mean the operator adjusts
   *its own local view* of who is owed what, out of the *donation pot the
   operator already controls*. Provably-fair proves the **roll** was not rigged.
   It does **not** prove the pool paid. This is exactly the trust model of the
   original SatoshiDice, and it must be stated to miners plainly (§2, §3.4).

3. **It is regulated-gambling-adjacent and money-real.** Shares map to real
   block-reward satoshis. That pulls in solvency safety (§3.3) and legal
   exposure (§5).

**Net:** the mechanism is *simple and sound as a fairness primitive*, and
*manageable but not trivial as a pool-money feature*, **provided** it stays
strictly off-consensus, pot-capped, default-OFF, and testnet/play-money first.
If the operator is not willing to accept the "trust the pool to pay" model and
the legal posture, the correct answer is not to ship it. The crux decisions are
collected in §7.

---

## 1. Background and grounding in the repo

### 1.1 The game table (from `frstrtr/satoshidice`, MIT)

`main.py` is the canonical SatoshiDice bet table. A roll is an integer in
`[0, 65535]` (`total_outcomes = 65536`). Eleven tiers, each a
`(winning_threshold, multiplier)` pair; the bet **wins iff `roll <= threshold`**:

| Tier | Threshold | Multiplier | Win probability | Payout×prob (RTP) |
|-----:|----------:|-----------:|----------------:|------------------:|
| 1  | 65    | 1000  | 0.1007% | 1.0071 |
| 2  | 649   | 100   | 0.9918% | 0.9918 |
| 3  | 1289  | 50    | 1.9684% | 0.9842 |
| 4  | 2596  | 25    | 3.9642% | 0.9910 |
| 5  | 6488  | 10    | 9.9030% | 0.9903 |
| 6  | 21627 | 3     | 33.0032% | 0.9901 |
| 7  | 32440 | 2     | 49.5010% | 0.9900 |
| 8  | 43253 | 1.5   | 66.0004% | 0.9900 |
| 9  | 48103 | 1.33  | 73.4009% | 0.9762 |
| 10 | 58982 | 1.1   | 90.0009% | 0.9900 |
| 11 | 61790 | 1.05  | 94.2856% | 0.9900 |

`winning_thresholds = [65,649,1289,2596,6488,21627,32440,43253,48103,58982,61790]`
`multipliers = [1000,100,50,25,10,3,2,1.5,1.33,1.1,1.05]`

The house edge is baked into the threshold-vs-multiplier gap (RTP ≈ 0.99, i.e.
~1% edge; note tier 1 as written is very slightly player-favorable at 1.0071 and
tier 9 is heavier at ~2.38% edge — the operator may want to re-tune, see §7).

**We take this table verbatim as the game spec.** What we do *not* take is
`random.randint(0, 65535)` — that is a local PRNG, not provably-fair. Designing
the fairness is the point of this document.

### 1.2 How c2pool actually accounts for payout (must respect these)

- **PPLNS is derived from the sharechain, deterministically, by every node.**
  `src/impl/dash/pplns.hpp` `compute_payouts()`: given a tip and a window, it
  walks shares backward, aggregates weight per recipient `pubkey_hash`, and
  splits `miner_value` proportionally. Each share splits its own weight into a
  worker portion and a donation portion via the share's `donation` field
  (0–65535): `worker_w = w * (65535 - donation) / 65535`,
  `donation_w = w * donation / 65535`. Dust allocations are dropped and the
  residue pushed onto the largest payout.
- **The donation address is a fixed, coin-invariant script**
  (`src/core/donation.hpp`, `core::donation::get_donation_script()`): P2PK
  pre-v36, a 1-of-2 P2SH combined multisig at v36+. It receives the
  donation-weighted portions **plus** the PPLNS rounding remainder. This is the
  natural "house" pot: a place value already flows to, whose key the operator
  co-controls.
- **Payout config already distinguishes actors** (`src/c2pool/payout/`):
  `DeveloperPayoutConfig` (attribution, default fee ~0.1% per operator standing
  rule — historically 0.5% in the struct default, operator overrides to 0.1%)
  and `NodeOwnerPayoutConfig`. There is a `payout_manager` seam, but note it is
  an *attribution/fee* layer, not a mutable per-miner betting ledger.
- **The dashboard already has a read-model and API for "who is owed what."**
  `src/impl/dash/dashboard_pplns.hpp` computes `/current_payouts`,
  `/current_merged_payouts`, `/pplns/current`, and a per-share PPLNS treemap
  (`window["pplns"][<short hash>]`). **Note (measurement trap): c2pool status/
  dashboard API paths have NO `/api/` prefix** — routes are `/v36_status`,
  `/local_stats`, `/current_payouts`, etc. The verifier surface (§4) must
  follow that convention.

### 1.3 The critical fact: there is no free-standing per-miner ledger

A payout is not a row in a mutable table the pool can quietly edit. It is a
*function of the sharechain*. There is no "credit" the dice can adjust without
either (a) changing shares (consensus fork), or (b) introducing a **new
pool-local overlay** that the operator's node applies on top of the
consensus-derived split. This document designs (b).

---

## 2. Trust model (stated honestly, up front)

Two different claims, do not conflate them:

- **Provably-fair proves the ROLL.** Anyone can verify, after the fact, that the
  house did not rig the random outcome of any bet — the house committed to its
  seed before the bet existed, and the miner committed to its entropy before the
  seed was revealed. Neither could bias the result. This is a hard cryptographic
  guarantee (§3.1).
- **Provably-fair does NOT prove PAYMENT.** Because settlement lives in a
  pool-local overlay (not in shares, not in consensus), a miner ultimately
  trusts the pool operator to honor the published bet log — to actually move the
  won satoshis out of the donation pot. This is identical to the real
  SatoshiDice: the chain (there, Bitcoin; here, the sharechain) does not enforce
  the game; it only makes cheating on the *roll* detectable.

The verifiability surface (§4) narrows the trust to exactly one thing: **"the
pool computes and honors payouts consistent with its own public, tamper-evident
commit-reveal + bet log."** A pool caught deviating is publicly, permanently
caught. That is the strongest guarantee possible without a consensus change, and
it must be advertised as such — no more, no less.

---

## 3. Design

### 3.1 Provably-fair, grinding-resistant roll

**The pool-specific hazard.** A miner produces *many* share hashes and could
grind them: if the roll were any function of a share hash the miner chooses, the
miner selects a favorable share. **Therefore the share hash is NOT an input to
the roll.** This closes the pool-specific grinding vector directly.

**Construction: hash-chain server seed + client entropy (mutual commit-reveal).**

*Server seed chain (fixes ALL future seeds at genesis, removes house freedom).*
The house picks a random terminal seed `S_N` (32 bytes, CSPRNG) and builds a
reverse hash chain:

```
S_{i-1} = SHA256(S_i)          for i = N, N-1, ..., 1
```

The house publishes the **head** `S_0` (equivalently `commit = SHA256(S_1)`,
which equals `S_0`) and anchors it to a concrete block: the head commitment is
posted with the current bitcoin/sharechain block height + hash, so its
publication cannot be back-dated. Seeds are then *revealed in forward order*
`S_1, S_2, …, S_N`, one per round. Each reveal is self-authenticating:
`SHA256(S_i)` must equal the previously published `S_{i-1}`. **Because the entire
chain is fixed the moment `S_0` is published, the house has zero freedom to
choose any future seed as a function of any bet.** (The chain is finite; when it
nears exhaustion the house publishes a new head anchored to a fresh block.)

*Client entropy (removes the house's advance knowledge of the roll).* A single
committed server seed is public-by-hash but known in full to the house. If the
per-bet identifier were a house-assigned sequence number, the house — which
knows the whole seed chain — would know every roll in advance and could steer
which miner lands on which slot. So the **miner** supplies unpredictable entropy.
A bet carries a `client_seed` chosen by the miner. The per-bet id is:

```
bet_id = SHA256( client_seed ‖ miner_id ‖ round_index ‖ per_round_seq )
```

*The roll.* After the round closes and `S_i` is revealed:

```
h    = SHA256( "c2pool-share-dice/v1" ‖ S_i_hex ‖ ":" ‖ bet_id_hex )
roll = int.from_bytes(h[0:4], "big") mod 65536
win  = roll <= winning_thresholds[tier]
```

Fixed domain-separation prefix (`"c2pool-share-dice/v1"`) prevents cross-protocol
hash reuse. SHA-256 is specified for both the commitment and the roll: it is
already vendored/used across the tree, is preimage- and collision-resistant at
the needed level, and keeps the verifier trivial. (Taking `mod 65536` of a
32-bit draw introduces no measurable modulo bias: 2^32 is an exact multiple of
2^16.)

**Ordering is the whole game** and it is strict:

```
1. house commits seed chain head S_0  (seed hidden, only hashes public)  ── anchored to a block
2. round i opens; miners place bets: (amount, tier, client_seed) → bet_id, sequence-logged immutably
3. round i closes at a published cutoff (block height or timestamp) — no more bets accepted
4. house reveals S_i; SHA256(S_i) == S_{i-1} is checked publicly
5. roll computed for every bet in the round; settlement applied to the overlay
```

**Adversarial analysis (both directions ruled out):**

- **Can the miner grind?** No. The roll depends on `S_i`, which is secret until
  step 4 (only its hash is public). Without `S_i` the miner cannot compute the
  roll for any candidate `client_seed`; for a fixed unknown `S_i` the roll is
  uniform in the miner's choice of `client_seed`. Crucially, **share hashes are
  not an input**, so producing extra shares buys the miner nothing. Bets are
  immutable once logged (step 2), so a miner cannot place a bet, watch the
  reveal, and repudiate.
- **Can the house grind (choose which seed to reveal)?** No. `S_0` is published
  before any bet exists, and the hash chain binds every `S_i`: SHA-256 preimage
  resistance means the house cannot find a different `S_i'` with
  `SHA256(S_i') == S_{i-1}`. The house is committed to exactly one seed per round
  *before it has ever seen a `bet_id`* — so it cannot tune the seed to a bet.
- **Can the house pre-know / steer the roll via bet ordering?** No. Even though
  the house knows the full seed chain, each roll also depends on `bet_id`, which
  contains the miner's `client_seed` — unknown to the house until the bet lands
  (step 2, after the seed is already fixed). The house cannot predict or select
  outcomes.
- **Can either party see the other's input first?** No. House commits first with
  a hidden seed (step 1); miner commits second with `client_seed` while the seed
  is still hidden (step 2); house reveals last (step 4). This is a clean mutual
  commit-reveal: each side is bound before it can observe the other's value.
- **Residual house powers (censorship and non-reveal) — bounded and detectable.**
  The house can refuse a bet (censorship) or refuse to reveal `S_i`. Both are
  publicly visible. Mitigation: a **mandatory reveal deadline** (a block height);
  if `S_i` is not revealed by the deadline, the entire round is **void** and all
  stakes are returned — and the missing reveal stands as public evidence of
  misbehavior. Non-reveal can never be more profitable for the house than paying,
  because voiding returns stakes.

There is no known way for either party to bias the roll under this construction.
The primitive is sound.

### 3.2 Where it lives — sharechain-consensus vs pool-local

**Rejected: bets in the sharechain.** Encoding bets (or a bet-adjusted weight)
into shares changes what `compute_payouts()` derives. Since every p2pool node
recomputes payouts from the shared sharechain, a bet-carrying share is only valid
if **every node** adopts new validation rules. That is a hard fork of the
sharechain — it fragments the network (nodes on old rules reject the shares),
destroys cross-pool share compatibility, and requires coordinated multi-operator
consensus for what is one operator's game. **Non-starter. Do not do this.** It
also violates the standing rule against sharechain-prefix / consensus regressions
on public nodes.

**Recommended: a pool-LOCAL PPLNS-accounting overlay.** The dice is a module the
operator's node runs *beside* PPLNS, never inside it:

- The consensus-derived split (`compute_payouts()` output) is untouched, byte for
  byte. Shares are untouched. Block validity, subsidy, and coinbase construction
  rules are untouched.
- The overlay maintains a local ledger: for each miner, a `net_bet_delta`
  (satoshi-equivalent), and for the house, `house_delta`, seeded from the
  donation pot's accrued value. A settled bet adjusts these deltas only.
- "Bet unit = accrued share-credit" means: the overlay reads a miner's *pending
  PPLNS value* (the satoshi-equivalent of their accrued weight, exactly the
  number the dashboard already computes in §1.2) as the ceiling on what they may
  stake. The bet then moves value **within the overlay**, not within shares.

Two realization options for actually paying a winner (this is the honest crux):

- **(A) Off-chain settlement from donation holdings (RECOMMENDED).** The overlay
  is pure bookkeeping; the operator, who co-controls the donation key, pays net
  winners out of realized donation-pot funds (a periodic settlement transaction,
  or credited into the miner's next normal payout via the operator's own payout
  bookkeeping). Cleanest, keeps coinbases 100% canonical, matches real
  SatoshiDice semantics. Trust boundary is explicit (§2).
- **(B) Coinbase overlay on operator-found blocks only.** When the operator's own
  node finds a block, its coinbase builder shifts satoshis from the donation
  output to winners' outputs per the net-bet ledger — *only* on blocks this node
  finds, *only* on its own coinbase, never altering shares or other nodes'
  behavior. Keeps settlement "in-band" but (i) only settles on the operator's
  fraction of found blocks, (ii) produces coinbases that differ from what the
  canonical PPLNS split would build for the same shares, which a miner comparing
  against the dashboard could flag as anomalous. Weaker than (A) in practice.

Recommendation: **(A)**, with the overlay ledger and the public log as the
source of truth, and settlement realized from the operator-controlled donation
pot. In neither option do shares, subsidy, coinbase *rules*, or block validity
change. The dice cannot make an invalid block or a wrong PPLNS split; the worst a
bug can do is misattribute *within the operator's own discretionary donation
funds*.

### 3.3 Bet unit, settlement, and solvency (HARD money-safety)

Denominate everything in satoshi-equivalent credit.

- **Bet unit:** accrued share-credit — the satoshi-equivalent of the miner's
  pending PPLNS weight, as already computed for the dashboard.
- **House:** the donation address's accrued pot (satoshi-equivalent), tracked as
  `house_balance` in the overlay.

Settlement per bet (`mult = multipliers[tier]`, integer-satoshi math with
banker-safe rounding; reject sub-dust bets):

```
on accept:  require 0 < bet <= miner_credit
            require (mult - 1) * bet <= house_balance      # solvency: max net payout ≤ pot
            debit bet from miner_credit (escrow)
on WIN:     miner_credit += mult * bet                     # stake returned + winnings
            house_balance -= (mult - 1) * bet
on LOSE:    house_balance += bet                           # stake to house
```

**Hard invariants (any violation ⇒ reject the bet, never settle into deficit):**

1. `bet <= miner_credit` — a miner can never stake more than they have accrued.
2. `(mult - 1) * bet <= house_balance` at accept time — the **maximum possible
   payout is always fully covered by the current house pot**. No insolvency, no
   negative balance, and therefore **no bet can ever reduce any *other* miner's
   PPLNS payout** — winnings come only from the donation pot the house owns.
   Because the top tier pays 1000×, this caps a tier-1 bet at `house_balance/999`;
   the overlay must expose a per-tier max-bet = `house_balance / (mult - 1)`.
3. `house_balance >= 0` and every `miner_credit >= 0` at all times.
4. Settlement stays entirely in the overlay ledger and the operator's own
   discretionary donation funds. It **NEVER** touches coinbase amounts that
   affect other miners, subsidy, sharechain weights, share validity, or block
   validity. The consensus PPLNS split is read-only input to the dice; the dice
   is never an input to consensus.
5. Concurrency: bets settle in the round's published sequence order; solvency is
   checked at accept AND re-checked at settle against the running pot within the
   round, so a burst of winning bets in one round cannot collectively overdraw
   the pot (later bets in the round that would breach solvency are rejected at
   accept, so this cannot arise; the re-check is defense-in-depth).

**Default OFF. Operator-armed (a money-tap).** The module ships disabled behind a
config flag; arming it is a deliberate operator action, gated the same way as
#157's tx-injection. No auto-arm, ever.

### 3.4 What "settled in shares" means, precisely

The task frames settlement "in shares (PPLNS payout weight)." Given §1.3 and §3.2,
the accurate reading is: **bets are denominated against, and settle against, the
satoshi-equivalent of PPLNS credit, in a pool-local overlay** — not by mutating
share weights (which are consensus). The miner's realized benefit is that net
winnings are paid from the donation pot into their payout. This is the only
reading that does not fork the network, and it is the reading this design adopts.

### 3.5 Rejected / out-of-scope

- No leverage, no credit, no negative balances, no borrowing against future
  shares. A bet is fully funded by already-accrued credit.
- No auto-betting bots wired into the node; the API accepts explicit bets only.
- No cross-pool or cross-node bet state. Purely local to the operator's node.
- No change to share format, share validation, coinbase rules, or subsidy.

---

## 4. Verifiability surface (dashboard + API)

Everything needed to verify every roll is published; the trust residue is only
"did the pool honor the log" (§2). Following the repo convention, API routes take
**no `/api/` prefix**.

The pool publishes:

1. **Server-seed-hash chain, block-anchored** — route e.g. `/dice/seed_chain`:
   the head commitment `S_0`, the block height + hash it was anchored to, the
   per-round `commit_i` values, and (once revealed) each `S_i`. Every revealed
   `S_i` is checkable by `SHA256(S_i) == S_{i-1}`.
2. **Per-bet records** — route e.g. `/dice/bets`: for each bet, `miner_id`,
   `amount`, `tier`, `bet_id`, `client_seed` (published after the round closes),
   `timestamp`, `round_index`, `per_round_seq`, and the pre-committed `commit_i`
   the bet was placed against.
3. **Post-round reveals** — the `S_i` reveal, its verification against `S_{i-1}`,
   and the computed `roll`, `win/lose`, `payout` for every bet in the round.
4. **House balance over time** — route e.g. `/dice/house`: the running
   `house_balance`, so solvency (`max_payout <= house_balance` at each accept) is
   independently auditable.
5. **A verifier snippet** — a short standalone script (Python and JS), depending
   only on SHA-256, that: (a) walks the seed chain and checks every link; (b)
   recomputes `bet_id` from `client_seed ‖ miner_id ‖ round_index ‖ per_round_seq`;
   (c) recomputes `roll = int(SHA256("c2pool-share-dice/v1" ‖ S_i ‖ ":" ‖ bet_id)[0:4]) mod 65536`;
   (d) checks win/lose and payout against the table in §1.1. Reference form:

   ```python
   import hashlib
   THRESH = [65,649,1289,2596,6488,21627,32440,43253,48103,58982,61790]
   MULT   = [1000,100,50,25,10,3,2,1.5,1.33,1.1,1.05]
   def sha(b): return hashlib.sha256(b).digest()
   def check_chain(S_prev_hex, S_i_hex):        # S_{i-1} == SHA256(S_i)
       return sha(bytes.fromhex(S_i_hex)).hex() == S_prev_hex
   def bet_id(client_seed, miner_id, rnd, seq):
       return sha(f"{client_seed}|{miner_id}|{rnd}|{seq}".encode()).hex()
   def roll(S_i_hex, bet_id_hex):
       h = sha(b"c2pool-share-dice/v1" + S_i_hex.encode() + b":" + bet_id_hex.encode())
       return int.from_bytes(h[:4], "big") % 65536
   def settle(r, tier): return ("win", MULT[tier]) if r <= THRESH[tier] else ("lose", 0)
   ```

This is illustrative, not a spec of field encodings; exact serialization is an
implementation detail to be pinned when/if code is written.

---

## 5. Legal / ethical flag (plain)

This is a legitimate mechanism on the operator's own pool, and provably-fair dice
is a well-known dual-use cryptographic primitive — this document does not refuse
it. It must, however, be flagged clearly:

- **Regulated gambling.** Operating a dice game for real value is regulated or
  outright prohibited in many jurisdictions. Whether the "value" is block-reward
  satoshis does not exempt it. The operator is responsible for the legality of
  running it wherever the pool and its miners are located.
- **Terms of service / disclosure.** Miners must be told, before any bet, that
  (a) this is gambling with real payout value, (b) the house edge is ~1% (the
  §1.1 table), (c) settlement is trust-based on the pool's published log
  (provably-fair covers the roll, not payment — §2), and (d) it is default-OFF
  and operator-run.
- **KYC / AML.** Depending on jurisdiction, running a game of chance for value
  may trigger KYC/AML obligations. Out of scope to solve here, but must be on the
  operator's checklist before arming.
- **Miner protection.** Hard per-tier max-bet caps (§3.3), no leverage, no credit,
  and a visible house edge are the minimum responsible defaults.

**Recommended rollout posture:**

1. **Testnet / play-money first.** Ship against a testnet coin or a play-money
   credit with no real settlement, prove the commit-reveal log and verifier
   end-to-end, and let miners audit rolls before any real value is at stake.
2. **Default OFF**, operator-armed, exactly like #157. Arming for real value is a
   deliberate, logged operator decision.
3. Publish the trust model (§2) and the legal disclosure alongside the game, not
   buried.

---

## 6. Interaction with existing invariants

- **Sharechain consensus:** untouched. The dice never reads into or writes out of
  share validation. (This is the whole reason for the pool-local design.)
- **Donation address:** the pot is the donation script's accrued value
  (`src/core/donation.hpp`); the operator co-controls its key, which is what makes
  option (A) settlement possible. The author/dev-fee attribution
  (`src/c2pool/payout/`) is a separate concern and is not repurposed as the house.
- **Dashboard PPLNS read-model:** the dice *reads* the same pending-payout numbers
  the dashboard already computes (`src/impl/dash/dashboard_pplns.hpp`) to size the
  bet ceiling; it adds new read-only `/dice/*` routes and does not alter existing
  ones.
- **Default-OFF money-tap:** consistent with #157 and the standing rule that live
  arming of a money path is an operator decision, never auto-armed.

---

## 7. Crux decisions for the operator

1. **Sharechain-consensus vs pool-local (settled recommendation: pool-local).**
   Bets in shares fork the whole network and are rejected (§3.2). The design is a
   pool-local overlay. Confirm this is acceptable — it is the load-bearing
   decision, and it dictates the trust model.
2. **Settlement realization: (A) off-chain from donation holdings vs (B)
   coinbase-overlay on operator-found blocks.** Recommendation (A): canonical
   coinbases, honest trust boundary, matches SatoshiDice. Operator picks.
3. **Trust model acceptance.** Provably-fair proves the roll, not payment (§2).
   If a chain-enforced guarantee of payment is required, this feature cannot
   provide it without a consensus change — and then it should not ship.
4. **Legal posture and testnet-first (§5).** Confirm jurisdiction/ToS/KYC are the
   operator's to own, and that rollout is testnet/play-money first, default-OFF.
5. **House-edge re-tuning (§1.1).** The verbatim table is slightly
   player-favorable at tier 1 (RTP 1.0071) and heavier at tier 9 (~2.38% edge).
   Decide whether to ship the table as-is or normalize the edge across tiers.
6. **Round cadence and reveal deadline.** How long a round stays open (per pool
   block? per N bets? per time window?) and the block-height reveal deadline that
   triggers void-and-refund (§3.1).
7. **Seed-chain length and rotation.** Chain length `N` and the block-anchored
   re-commit procedure when it nears exhaustion.

---

## 8. Non-goals

This document does not implement, arm, or enable anything. It specifies no field
encodings, no config-flag names, no wire formats — only the mechanism, the safety
invariants, and the decisions the operator must make before a single line of code
is written. Any implementation is a separate, reviewed, default-OFF change.
