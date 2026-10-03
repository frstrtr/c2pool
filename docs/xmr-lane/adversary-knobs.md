# XMR lane: adversary test knobs (TEST-ONLY, refused on mainnet)

Hardening tooling for the stagenet soaks. One node is told to misbehave on a
test network so the soak can prove the pool survives a real attacker: honest
nodes stay on ONE ledger (equal `owed_digest`), ban/refuse per the existing
rules, and nothing the adversary does splits the pool or lowers an earned
balance.

Every knob is HIDDEN (no `--help` row), INTEGER-ONLY, `0 = OFF` (zero code path
change for an honest node), REFUSED at start on `--network mainnet`, and loud:
a start banner plus one `adv: <knob> ...` line per action so a soak counts
attacks with `grep -c 'adv: <knob>'`.

## 1. The module (landed, pure, tested)

`src/c2pool/v37/xmr/xmr_adversary_knobs.hpp` -- `AdversaryKnobs` (the six
integers + per-action counters), `refusal(network_is_mainnet, k)` (non-empty =>
the daemon refuses to start; every knob is named), `banner()`, the per-action
`log(knob, detail)`, the probability gate `withhold(draw_0_99)`, the censor
decisions `keep_in_cut(is_own)` / `relay_onward(is_own)`, and `AdvRateGate`
(at most one `due()` edge every `60000/rate` ms, `rate 0 = OFF`, never at t=0).

`src/c2pool/v37/test/v37_xmr_adversary_knobs_kat.cpp` pins: OFF-by-default
touches nothing; every knob (and all six together) is REFUSED on mainnet and
allowed off it (the task's KAT contract part (c), for all six); the rate gate
fires RATE/min; the withhold gate withholds P/100; the censor decision keeps
own / drops foreign. 34/34.

## 2. The CLI surface (landed in `main_v37_xmr.cpp`)

| flag | field | knob |
|---|---|---|
| `--adv-withhold-blocks P` | `withhold_pct` (0..100) | 1 |
| `--adv-censor-receipts` | `censor_receipts` | 2 |
| `--adv-garbage RATE` | `garbage_rate` (per min) | 3 |
| `--adv-stale-replay RATE` | `replay_rate` (per min) | 4 |
| `--adv-self-pay` | `self_pay` | 5 |
| `--adv-wrong-epoch-ballot` | `wrong_epoch_ballot` | 6 |

Parsed at `main_v37_xmr.cpp:6677-6682`; the global `g_adv` at :289; the mainnet
refusal + `banner()` in `run_live` at :1625-1630 (right after the
`--test-crash-after-publish` refusal). The flags are accepted on every test
network and refused on mainnet by name, today.

## 3. The per-knob ACTION gates (operator-applied at the seams)

The action gates live in the block-publish, relay and settlement paths. Those
paths are the pool's consensus / transport core; in this repo they are edited
by the operator's own hand (the agent tooling is fenced off the block / relay /
consensus code). Each gate is a few lines of glue over the module above, at the
seam named here, with the honest-node property it must leave standing and the
existing harness that pins it.

### knob 1 -- `--adv-withhold-blocks P`
* Seam: `GatedShareSinkT::submit_network_block` (`main_v37_xmr.cpp:~511`),
  immediately BEFORE `m_pre_publish` / `m_inner.submit_network_block(...)` --
  the single gate every found network block passes. Gate:
  `if (g_adv.withhold(draw_0_99())) { ++g_adv.n_withheld; log("withhold-blocks", "height="+...); return; }`
  Skipping that call skips the monerod submit (`xmr_live_submit.hpp:414`), the
  p2p announce (`xmr_p2p_block_publisher.hpp:201`) and the `FoundBlockEvent`.
* Must hold: the other four honest nodes keep producing; the withheld block's
  reward is simply lost to the adversary (counted). No honest ledger effect.
* Pins: a submit-path KAT counting withheld vs published at a known draw.

### knob 2 -- `--adv-censor-receipts`
* Two seams. (a) onward-relay suppression: the re-flood path
  `XmrRelayNode::flood(raw, except)` (`relay/xmr_relay_node.hpp:3641`) -- skip
  foreign receipts (`relay_onward(is_own)==false`). (b) own-cut censorship: the
  node's own lane-block cut builder (the V37C credit-cut selection in the
  settlement source) -- keep only own-minted receipts (`keep_in_cut(is_own)`).
  "own" = the receipt's minter identity equals this node's miners'.
* Must hold: it is the adversary's own block and its own choice, so this is
  LEGAL censorship; honest nodes recompute that block canonical against THEIR
  own cut and stay on one `owed_digest`; the censored receipts still reach
  everyone else by other peers' relay, so the ledger is unchanged. Censorship
  is bounded by the late tail of the order rule (`coinbase-recompute.md` 6.1).
* Pins: a multinode KAT (`v37_xmr_relay_multinode_kat` harness) -- the censoring
  node's cut omits foreign receipts, the other nodes' `owed_digest` stay equal,
  no honest ban.

### knob 3 -- `--adv-garbage RATE`
* Seam: a rate-limited `adv_tick(now_ms)` in `XmrRelayNode::maint_loop`
  (`relay/xmr_relay_node.hpp:~4586`, beside `disc_tick`), gated by an
  `AdvRateGate(garbage_rate)`; emit malformed family-B frames (truncated /
  corrupt body / byte-flipped copy of a real vaulted frame = forged share with
  bad PoW, wrong `pool_id`, bad `rbind`) to each `ready_peers()` via
  `m_net.send_to(p, f)`.
* Must hold: honest peers REFUSE and ban per the existing rules without
  affecting each other -- the structural-strike path (`process()`
  `:2866`, counter `m_st.structural`) and the RandomX-confirmed-invalid ban
  (`:2996`, `m_st.bans` + `ban_later`). A banned adversary does not partition
  the honest peers from each other.
* Pins: a multinode KAT asserting `relay.stats().bans` rises on the adversary
  link only, honest<->honest links stay up and digests stay equal.

### knob 4 -- `--adv-stale-replay RATE`
* Seam: the same `adv_tick`, gated by `AdvRateGate(replay_rate)`; re-send old
  valid frames from `m_won_raw` (recent `FB_BLOCK_WON`) or `m_vault` (flooded
  receipts) to `ready_peers()` via `m_net.send_to`.
* Must hold: honest peers REFUSE the replay (dedup by id in the vault / the WON
  serve index) with no new credit and no ban storm; equal `owed_digest`.
* Pins: a multinode KAT -- replayed frames admitted exactly zero extra times,
  no ledger change.

### knob 5 -- `--adv-self-pay`
* Seam: the lane-coinbase payee build (`XmrOwedSettlementSource::build` -> X6
  `build_coinbase` / `allocate_exact_sum`): replace the payee/output map with a
  single output to this node's own payout identity.
* Must hold: honest receivers run `book_from_chain_ex` -> the recompute is a
  Mismatch (`coinbase-recompute.md` 2-3): credit DROPPED, the on-chain payout
  DEBITED (forward repair), the block treated as withheld, alarm
  `cba-ALARM recompute_mismatch`. NEVER a split; one `owed_digest` across the
  honest nodes.
* Pins: a recompute KAT (`v37_xmr_coinbase_recompute_kat` pattern, R11 books a
  mismatch on two receivers and checks one `owed_digest`).

### knob 6 -- `--adv-wrong-epoch-ballot`
* Seam: the ballot word written into a minted receipt's job binding
  (`JobBinding.ballot`, `make_job_binding(...)` in
  `relay/xmr_rbind_registry.hpp`): set it to a word naming an UNDEFINED epoch
  (e.g. `epoch_max + 1`).
* Must hold: receipt admission does NOT range-check the ballot against the
  descriptor table (spec sec. 11 item 3 / MINER-VOTE M1: admission must be
  identical on every node). So the receipt stays VISIBLE and earns its share;
  the ballot is carried, counted as its own-abstain / shown in the receipt view,
  and ACTED ON by nothing in R1 (the tally is R3). Visible-only per V8.
* Pins: a ballot KAT (`v37_xmr_ballot_kat` pattern) -- a receipt with an
  undefined-epoch ballot is still admitted/visible and changes no digest.

## 4. Status

Landed and tested: the module, its KAT (34/34), and the CLI surface (the six
flags, the mainnet refusal for every knob, the banner). The six action gates in
section 3 are the operator's step, each a few lines over the module at the named
seam. The attempt-10 rig plan (`/mnt/ci/adv/ATTEMPT10.md`) gates the adversary
schedule on those gates being in the running binary.
