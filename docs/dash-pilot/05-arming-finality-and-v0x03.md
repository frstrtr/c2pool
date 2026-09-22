# Dash pilot, design note 5: arming finality, pilot caps, and the v0x03 payout-set wire

Status: DESIGN NOTE. No code. Needs operator rulings.
Scope: the v37 btc-dash arm, DASH testnet pilot T1. Read note 4 (the residual
rule) first; this note assumes its recommendation.

## 1. Where the arm stands after T1-prep

* `--settlement off` is the only mode that runs. `on` is refused at startup.
* Every found block is credited: the own fold reads the **mined** coinbase
  miner slice, and a peer fold is verified against dashd (the block is on the
  best chain at `H_b`, and `reward == sum(coinbase vout) - masternode
  payments`). See `mined_block_verify.hpp`.
* W5 emission is withheld: `assemble_if_buried` runs at depth 0, so the
  descriptor always carries `payout_emitted = 0`. Peers **refuse** any
  descriptor with `payout_emitted = 1` (`btc_node.hpp`, refusal (b)), because
  the payout map is not on the v0x02 wire and cannot be reproduced.

So turning emission on needs three things, in this order: a finality rule for
arming, fixed caps, and a wire that lets a peer reproduce and verify the
payout.

## 2. Arming finality: ChainLock or D_conf = 100

A W5 payout may only spend balances whose crediting block cannot be reorged
away. Otherwise a reorg un-credits a balance that was already paid.

| | D_conf = 100 (today) | ChainLock |
|---|---|---|
| what it means | buried 100 deep = coinbase maturity | LLMQ-signed, cannot be reorged under DASH consensus |
| latency | about 4 h on mainnet (2.6 min blocks) | seconds (`getblockheader.chainlock == true`) |
| trust | honest hash-power majority | DASH masternode quorum (already trusted by DASH consensus) |
| available on testnet | yes | yes (block `0000002d24f3…1dbd` showed `chainlock: true`) |
| daemonless later | header chain depth | needs CLSIG verification (quorum keys, BLS) |

**Recommendation: arm on ChainLock, finalize on D_conf.**

* **Emission gate** (`BurialGate`): `canonical && (confirmations >= D_conf ||
  chainlocked)`. A chainlocked credit can be paid in the next block the pool
  wins. That removes the 4-hour lag between earning and being paid.
* **FINALIZE** (the F1 driver, `finalW += credit - payout`) stays at `D_conf =
  100`. A chainlocked coinbase is irreversible but still **not spendable** for
  100 blocks. Finalizing earlier would let the ledger count value the pool
  cannot move yet. Keep the two rules separate.
* **Seam:** `DashRpcCoinBackend::probe_header` already reads the
  `getblockheader` JSON. Add `chainlock` to `HeaderProbe`, and add a
  `chainlocked(bid)` probe to the backend. That is roughly 20 lines, outside
  canon.
* **Fail-closed:** with no chainlock answer (transport error, or a
  pre-DIP0008 chain), fall back to `D_conf`. Never treat "unknown" as locked.
* **Ruling needed:** ChainLock early-arm, yes (recommended) or no.

## 3. Pilot caps: C, K_max, h_min

Today `slot_budget_C = 0` and `max_payout_bytes = 0` (both mean unbounded),
and `k_floor = 1` (`btc_node.hpp`, own and peer fold).

| cap | pilot value | why |
|---|---|---|
| `slot_budget_C` | **32** outputs | bounds the verification work per block. A DASH coinbase already carries the CbTx payload plus masternode and burn outputs |
| `max_payout_bytes` (K_max) | **32 × 34 = 1088 B** | matches C for P2PKH outputs. P2SH is 32 B each, so C binds first |
| `k_floor` | **17**, so `h_min(P2PKH) = 578 >= 546` duffs | DASH dust at the default relay fee. Below the floor a balance carries forward, never dropped (note 4) |

These are consensus-fixed values and must be identical fleet-wide. They go in
with the flag day below, not as flags.

## 4. The v0x03 descriptor: payout set or reproducible inputs

The receiver has to reproduce the winner's coinbase payout **exactly**, then
verify it against the mined block. There are two ways to carry it:

1. **The payout set itself:** `u16 n; n × {bytes32 key, u64 amount}`, bounded
   by C (32 × 40 B = 1.3 KB). The receiver checks that the set equals the
   mined outputs. It cannot check that the set was *fair* (K_fair,
   oldest-first) without the owed state.
2. **Reproducible inputs:** `{owed state_root, k_floor, C, K_max,
   residual_identity (finder), finality_bit (chainlock | D_conf)}` plus
   `payout_root = sha256d(sorted payout set)`. The receiver runs its own
   `assemble()` over its **own** owed ledger. The ledgers are equal because
   S-1c converges them, and `owed_digest_at_win` is already on the wire. The
   receiver then checks (i) `payout_root` matches its own assembly, and (ii)
   the mined coinbase contains exactly that set plus the residual output (the
   step-3 `getblock` + `masternode payments` machinery, extended from "sum"
   to "set").

**Recommendation: (2), with `payout_root`.** It is smaller on the wire. It
verifies fairness and not just consistency. It reuses RECON's
reconstruct-at-cut + verify-vs-on-chain + fail-closed shape. A mismatch at any
step is a refusal with a counter (never a silent credit), like the
reward-verification refusals added in T1-prep. The `payout_emitted = 1`
refusal is removed **only** for v0x03 frames whose payout set verifies. It
stays for everything else.

Wire shape: a trailer after the v0x02 cut descriptor, under the same F-5 rules
as v0x02 (`w3_relay.hpp`). It gets new frozen goldens and a
`layout_id_v3`. The boot self-check covers v0x01, v0x02 and v0x03.

## 5. Flag-day plan (a v37.0x subversion, not v38)

1. **v37.0x-a (this branch, T1-prep):** reward verification, pool identity,
   `--settlement off`, the strict soak verdict. No wire change.
2. **v37.0x-b:** the v0x03 encoder/decoder + goldens, and accept
   {v0x01, v0x02, v0x03}, while still **emitting v0x02**. Soak: a mixed fleet
   stays convergent.
3. **v37.0x-c:** the residual rule (note 4), the caps (section 3), and
   ChainLock arming (section 2), all behind `--settlement on`. It emits v0x03
   only once the activation position is reached. Put that position next to
   the WinGate `win_activation_pos` (`v37_lane.hpp`, the ruling-M seam) so
   there is one activation point and not two.
4. **Activation:** from `activation_pos` on, blocks carry W5 payouts and v0x03
   descriptors. From `activation_pos + N` bins (N to be ruled; 2016 is
   suggested), refuse v0x02 block-winner frames, because a v0x02 frame cannot
   say whether it paid.
5. **Pool identity:** activation must also bring the pool/consensus id from
   the roundabout S1 `lane_tag` track (it is committed under the lane digest).
   Then a node whose LaneParams or caps differ refuses explicitly, instead of
   diverging silently. It is deliberately not in T1-prep.

**Rulings needed:** (1) ChainLock early-arm; (2) C = 32 / K_max = 1088 /
k_floor = 17; (3) v0x03 = reproducible inputs + `payout_root`; (4) the N for
the v0x02 sunset; (5) co-locating `activation_pos` with WinGate.
