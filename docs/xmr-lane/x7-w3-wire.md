# W3 — XMR carrier/receipt wire type + RandomX DoS budget (Family B)

**Leg:** `w3-wire` (v37 Track X / Family B: Monero/RandomX lane). WBS **X7** in the scoping note (`v37-monero-randomx-lane-scoping.md` §5), item **A2/4-12** ("W3 wire: XMR carrier/receipt message type; relay validation with the RandomX + re-derivation DoS budget").
**Author-clean, AGPL-3.0-or-later.** New `src/impl/xmr/` tree; touches no `src/sharechain/v37/*` consensus-digest code; no git, no PR.
**Status:** skeleton + wire schema + DoS-budget rationale, compile+run-checked (43 assertions, `check/build.sh`). Consensus wording and the R-1/carrier-target split are owed rulings, flagged below.

This leg is the **relay (W3) layer**: it defines the *message that carries a `MoneroReceipt` over the v37 relay* and the *non-consensus DoS budget* that keeps an unauthenticated peer from turning the ~15 ms light-mode RandomX verify into a cheap denial of service. It sits **around** the consensus admission order (the `share-format-addendum` leg), never inside it.

---

## 1. Files

| File | What it is | Compiled in KAT |
|---|---|---|
| `src/impl/xmr/xmr_carrier_wire.hpp` | **Wire schema** — byte-exact, dependency-free codec for `MoneroReceipt` and the carrier message; every length prefix bounded before allocation; running total held under the digest-committed per-receipt budget. | yes |
| `src/impl/xmr/xmr_carrier_dos_budget.hpp` | **DoS budget** — per-peer RandomX-evaluation token bucket, global backstop bucket, ban-on-invalid-PoW scoring, the p2pool "UNSTABLE HARDWARE" re-verify guard. Header-only per-instance policy (min_protocol_gate style). | yes |
| `src/impl/xmr/xmr_carrier_relay.hpp` | **Relay ingress skeleton** — control flow tying codec → admission → budget, with the token seam at admission stage 5. All crypto/index/RandomX injected. | yes |
| `src/impl/xmr/messages.hpp` | **c2pool-native message** `message_xmr_carrier` (`BEGIN_MESSAGE`/`MESSAGE_FIELDS` idiom) + `MessageHandler` registration — the in-tree integration target. | no (needs the tree) |
| `check/w3_wire_check.cpp`, `check/build.sh` | Light single-TU KAT: codec round-trip byte-identity, every wire bound, token-bucket sizing, relay accept/ban/defer/hw-flap, saturation arithmetic. | — |

Reuses (includes, does not copy) the sibling `share-format-addendum` leg: `v37::xmr::MoneroReceipt` and components (`xmr_receipt.hpp`) and `v37::xmr::admit_receipt_keyed_heavy` / `AdmitOutcome` / `AdmitStage` / `LaneKeyedHeavy` (`xmr_admission.hpp`). The `rx_verify` hook is the `randomx-vendor` leg's `c2pool::xmr::LightVerifier::verify` behind a `std::function` so this leg builds cache-free.

---

## 2. Wire schema

The pool p2p layer already frames every message as `command || length || payload` (`RawMessage`; `pack.hpp WriteCompactSize` for the length). The new command is **`xmr_carrier`**; its payload is exactly `v37::xmr::wire::encode_carrier(CarrierMessage)`. One schema definition (the codec), not two.

**All integers little-endian; all lengths CompactSize (Bitcoin/c2pool `WriteCompactSize`); one-canon (re-encoding a decoded message reproduces the exact bytes — KAT T1).**

### 2.1 `CarrierMessage` payload

| # | field | encoding | notes |
|---|---|---|---|
| 1 | `chain_id` | `u32` LE (4 B) | the keyed_heavy lane; must match a live lane |
| 2 | `carrier` | `MoneroReceipt` (§2.2) | the difficulty-gated transport share, proven at the **carrier** target |
| 3 | `receipts` | `compact(count)` then `count × MoneroReceipt` | `0 .. R_MAX_XMR` (=2); `count > R_MAX_XMR` is a hard reject |

### 2.2 `MoneroReceipt` payload (the schema of record for `§1.5` of the scoping note)

| # | field | encoding | bound |
|---|---|---|---|
| 1 | `hashing_blob` | `compact(len)` + bytes | ~77 B; sanity cap 256. `serialize(header) ‖ tree_root(32) ‖ varint(n_tx)`; `prev_id` inside → `bin` |
| 2 | `seed_ref.policy` | `u8` | `0`=DerivedFromBin (0 B), `1`=CarriedSeedHash |
| 2b | `seed_ref.carried` | 32 B | **iff** policy==CarriedSeedHash |
| 3 | `coinbase_opening.midstate` | 200 B fixed | Keccak-256 sponge state (rate 136, cap 64) at the `tx_extra` boundary |
| 3b | `coinbase_opening.prefix_tail` | `compact(len)` + bytes | `< 136`; sanity cap 135 |
| 3c | `coinbase_opening.tx_extra` | `compact(len)` + bytes | 0x01 pubkey / 0x02 nonce / 0x03 MM tag; sanity cap 1060 (`MAX_TX_EXTRA_SIZE`, txpool-only) |
| 4 | `tree_branch.depth` | `u8` | `= path.size()`; sanity cap 16 |
| 4b | `tree_branch.path` | `depth × 32 B` | leaf-0 left-spine siblings, root-ward (`tree_branch`, no direction bits) |
| 5 | `info_digest` | 32 B | ref-side binding digest (share-format §3) |

**Bounds (all enforced in `decode_*`, all KAT'd):**
- per-receipt hard cap **`PER_RECEIPT_BUDGET = 768 B`** (digest-committed; the sibling receipt-leg value — worst realistic receipt is 756 B). Enforced *during* decode via a running-total guard after every field, so an oversize receipt never even allocates its components, and re-checked against `MoneroReceipt::wire_size()` (the same value the admission pre-gate uses).
- per-message hard cap **`MSG_MAX = 2311 B`** = `4 + 768 (carrier) + 3 (count) + 2×768 (receipts)`. A frame over `MSG_MAX` is dropped at the transport read, before parse.
- every length prefix is range-checked against its sanity cap **before** allocation (KAT T2: a CompactSize claiming a 4 GiB blob is rejected, not allocated).
- `count > R_MAX_XMR`, trailing bytes, truncation, non-canonical CompactSize, unknown `SeedRefPolicy` — all hard rejects.

Typical receipt ~615 B (derived seed) / ~647 B (carried seed); matches the scoping-note `~600–660 B` estimate (KAT T1). A carrier + 2 receipts ≈ 1.9 KB, well under `MSG_MAX`.

### 2.3 Relationship to `message_xmr_carrier`

`messages.hpp` carries the payload as one length-prefixed `std::vector<uint8_t>` (== the codec bytes) rather than re-listing `MoneroReceipt` fields in a second `READWRITE` body. This keeps the schema single-source (no drift) for zero wire-size cost — CompactSize/LE framing is identical to what `pack.hpp` would emit field-by-field. The field-by-field alternative (native `FORMAT_METHODS` wrappers) is documented at the foot of `messages.hpp` for the day the tree prefers it; the bytes on the wire are unchanged.

---

## 3. DoS-budget rationale

### 3.1 The threat, quantified

Family-B verification runs **RandomX last** (the `xmr_admission.hpp` inversion: `dedup → expiry → structural/binding → R-1 target → RandomX`). RandomX is therefore reached only by a carrier that already passed the microsecond checks — but those checks are satisfiable by a **structurally valid carrier whose PoW simply misses the opened `T_origin`**. Minting one is free for an attacker (any nonce that misses target; the coinbase/tree are a few Keccak, microseconds); verifying it costs one full light-mode RandomX hash.

```
light-mode RandomX ≈ 15 ms/hash  (scoping §1.1: monerod "10–15 ms/hash/thread")
one core:  1 s / 0.015 s  =  66.7 hashes/s   ⇒  ~65 bogus carriers/s SATURATE one light core.
```

That `~65 carriers/s` (KAT T5: 66.7) is the number this leg is sized to defeat. Precedent: every Monero p2pool node RandomX-hashes every external share (`SideChain::add_external_block → PoolBlock::get_pow_hash → check_pow`) and **bans on bad PoW**, re-hashing a failing share in forced light mode to flag `"UNSTABLE HARDWARE DETECTED"` before trusting the failure.

### 3.2 The mitigation — meter RandomX *evaluations*, not messages

A token = one permitted RandomX evaluation. The token is taken at **admission stage-5 entry** (seed resolved and resident), not per message. The seam: the budget's `grant_randomx()` is injected into the admission `seed_for_bin` hook, so `rx_check` runs **iff a token was granted**, which makes its result unambiguous:

| stage-5 result | `spent_randomx` | budget action | relay result |
|---|---|---|---|
| PoW meets target (`Accept`) | true | **refund** the token | Accepted → push |
| PoW below target (`BelowTarget`) | true | keep token spent; `on_invalid_pow(confirmed)` | **Banned** (or Dropped if unconfirmed) |
| seed not resident / VM OOM (our fault, after grant) | true | **refund** the token | Deferred (never ban) |
| no token (budget exhausted) or seed not resident (before grant) | **false** | none | Deferred, **no penalty** |
| rejected at stages 1–4 (structural/expiry/dedup/R-1) | false | soft score `+1` | Dropped (cheap) |

Because valid work is **refunded** (`refund_on_valid`, default on), the per-peer bucket depletes **only on wasted (invalid) RandomX**. And a valid carrier requires real Monero PoW at the carrier/receipt target — self-limiting by the PoW gate — so refunding it cannot be abused. Invalid carriers are the free DoS, and those are exactly what deplete the bucket and trip the ban.

### 3.3 Sizing (defaults; per-instance knobs, operator-ratified at wiring)

- **Honest per-peer demand is tiny.** Carriers are difficulty-gated at the ~10 s share cadence; each carrier drives ≤ `1 + R_MAX = 3` RandomX hashes; dedup (on a *cheap* blob digest, never the RandomX hash) collapses duplicate relays of the same carrier before any hash. A single honest peer forces well under 1 wasted hash/s.
- **Per-peer bucket:** `refill = 1 token/s`, `capacity = 20`. A throttled flooder costs ≤ 1 wasted hash/s ≈ **1.5 % of one core** (KAT T5); a burst of 20 costs 0.3 s of CPU, then throttles.
- **Global backstop bucket:** `refill = 16/s`, `capacity = 256` ⇒ ≤ **~24 % of one light core** sustained across *all* peers (KAT T5). This is the real aggregate ceiling (N per-peer buckets otherwise sum to N·refill·15 ms — one core at ~66 hostile peers); the per-peer bucket is the fairness layer that stops any single peer eating the global budget. `grant_randomx` takes from the global bucket first, then the per-peer bucket, refunding the global take if the per-peer take fails.
- **Ban scoring:** `score_invalid_pow = 100`, `ban_threshold = 100` ⇒ **one confirmed invalid PoW bans** (p2pool parity). Raise the threshold for hardware-flap tolerance when the re-verify guard is enabled. Cheap stage-1–4 rejects score `+1` (soft) — a structural flooder is bounded by the coarse message-rate limit, not by banning honest reorg-races.

### 3.4 The UNSTABLE-HARDWARE guard

Before trusting a `BelowTarget` verdict, an optional `rx_reverify` independently re-hashes the same `(seed, blob)`. `confirm_invalid()` bans **only if the two hashes agree and both miss target**; a disagreement means *our* verifier is unstable and the peer is not penalised (KAT T4d). This mirrors p2pool's `force_light_mode` re-hash. When no re-verify is wired, a `BelowTarget` is trusted directly (confirmed) — an unmet target on a completed light hash is otherwise incontrovertible.

---

## 4. Integration points (out of scope here; the reception slice owns them)

1. **`LaneParams` / lane digest.** `pow_verify_class` (u8) + the `LaneKeyedHeavy` block fold into the lane digest exactly where `n_ctx` folds (share-format-addendum §B1). Family-A lanes keep `stateless_cheap` and stay byte-identical. **Consensus tap.**
2. **`MessageHandler`.** Append `message_xmr_carrier` to the XMR node's handler variant; add `xmr_carrier` to `core::obs::P2PMessage` (`p2p_message_stats.hpp`) so `/p2p_stats` reports it.
3. **Relay call site.** Register `handle_xmr_carrier(peer_id, lane, frame, len, lp, env, dos, now, on_accept)` on inbound `xmr_carrier`; `on_accept` is the caller's §4 push (`push(miner, work(T_origin), flags|L0F_RECEIPT, bin)`) + dedup-store insert. Wire `dos.forget(peer_id)` into peer disconnect and the ban verdict into the disconnect/ban-list.
4. **`LaneEnv` oracles.** `cheap_digest`/`seen`/`bin_of`/`open_and_bind`/`consensus_difficulty` from `monero-primitives` + the `monerod-adapter` index (≥ 2112-block seed reach); `seed_resolve` + `rx_verify` from `randomx-vendor` `LightVerifier` (prefetch epochs off the hot path — invariant I2). The relay never allocates an Argon2d cache on the hot path; a not-yet-resident seed is a Defer, not a hash.
5. **Prefetch.** On a new mainchain tip (and when a peer first advertises a bin in a not-yet-resident epoch), call `LightVerifier::prefetch_epoch` for the two live seed heights. `grant_randomx` + residency together bound how much RandomX an unverified peer can ever cause.

---

## 5. Open questions / owed rulings

- **OQ-X3 (where each lives).** `pow_verify_class` is consensus (digest-committed `LaneParams`); the token bucket + ban policy are non-consensus (relay). This leg keeps that split: nothing in `xmr_carrier_dos_budget.hpp` touches a wire byte or a digest. Confirm the split at wiring.
- **Carrier target vs R-1 receipt target.** `handle_xmr_carrier` verifies the carrier at the *carrier* target and each receipt at its *R-1* target through the same `admit_one`. The `consensus_difficulty(bin)` oracle must return the correct target for each — i.e. it needs a carrier/receipt flavor, or two oracles. Left to the reception slice + the R-1 pinning ruling (share-format-addendum §B4). **Flagged.**
- **Dedup key.** The relay dedups on `cheap_digest(hashing_blob)` (never the RandomX hash — that would defeat the inversion). This is the admission leg's `receipt_id`; the relay and the §5 dedup store must share the class. Confirm one store.
- **`R_MAX_XMR` / byte budget (OQ-X2).** Uses the sibling leg's `R_MAX_XMR = 2`, `PER_RECEIPT_BUDGET = 768`, `MSG_MAX = 2311`. If the ratified per-lane budget differs, only the `cap::` constants change; the codec and bounds are unaffected.
- **Refund-on-valid.** Default meters only wasted RandomX. An operator wanting to bound *total* RandomX CPU regardless of validity sets `refund_on_valid = false`; the global bucket is then the CPU ceiling. Policy knob, not a schema change.

---

## 6. What is deliberately NOT here

No RandomX build, no cache, no dataset, no monerod, no network. No coinbase **output** derivation (pre-CARROT, W5-XMR leg, behind the fork-major-version guard) — the wire only carries an *opening* of an already-built miner_tx prefix and is fork-agnostic. No PPLNS/uncle/sidechain porting (v37 has its own RDWR model). No consensus digest code touched.
