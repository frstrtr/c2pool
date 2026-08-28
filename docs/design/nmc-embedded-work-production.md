# NMC embedded merged mining -- work production (resolves #980)

**Status:** design decision, ready for implementation.
**Scope:** `src/impl/nmc/` + the NMC wiring block in `src/c2pool/main_ltc.cpp`.
**Consensus/reward impact:** none -- this is SPV header-follow plus aux-template
production; it does not change share validity, the parent (BTC) coinbase, the
reward split, or the dual-target check that qualifies a found share as a real
Namecoin block.

---

## 1. The question (#980)

Issue #980 asks, with citations but without a live run: `nmc_chain` is
constructed and genesis-seeded, but nothing appears to feed it headers, while
`AuxChainEmbedded::get_work_template()` gates on `is_synced()`. Can the NMC
merged-mining lane produce work at all?

**Answer, confirmed against master:** no. As shipped, the embedded NMC lane can
never emit an aux-work template. This document confirms the reading, explains
*why* a naive DOGE-style header feed does not fix it, and specifies the correct
mechanism -- which is parity with how the already-working DOGE lane follows its
aux chain, not a heavier new subsystem.

All line numbers below are against the master commit this document is authored
on. They are anchors for review, not guarantees against future drift.

---

## 2. Confirmation -- three structural gaps

The embedded NMC backend is constructed **only** in the `c2pool-ltc` binary
(`src/c2pool/main_ltc.cpp`, the `nmc_chain` / `nmc_pool` / `nmc_params_ptr`
block around L5235 and L5467-5490). `main_btc.cpp` does not construct
`nmc_chain`. The genesis header is seeded (`add_header(mainnet_genesis_header())`
on mainnet), and `AuxChainEmbedded` is registered as the aux backend, but three
gaps compound so the chain never advances past that genesis seed:

1. **No P2P peers for NMC.** `get_chain_p2p_prefix()` (main_ltc.cpp L790-828)
   has DOGE / LTC / BTC / DGB / DASH / PEP / BELLS / LKY / JKC / SHIC / DINGO
   cases but **no NMC case**, so it returns `{}` and the whole broadcaster block
   (guarded `if (!prefix.empty())`, L5565) is skipped. There is likewise no NMC
   `valid_ports` case (L5582-5588) and no NMC `set_dns_seeds` / `set_fixed_seeds`
   wiring (L5606-5620) -- even though `nmc::coin::nmc_dns_seeds()` /
   `nmc_fixed_seeds()` (`nmc/coin/chain_seeds.hpp`) and
   `NMCChainParams::p2p_magic` (`nmc/coin/header_chain.hpp` L637 mainnet
   `f9 be b4 fe`, L665 testnet `fa bf b5 fe`) already exist. Net: `nmc_chain`
   gets zero peers.

2. **No header-feed wiring for NMC.** Only DOGE binds
   `set_on_new_headers(...)` + `set_on_peer_height(...)` + a periodic
   `getheaders` sync timer (main_ltc.cpp L5640-5730). No NMC analog exists.

3. **The NMC header chain refuses a plain header feed.** This is the decisive
   gap and the reason gaps (1)+(2) alone are not enough.
   `nmc::coin::HeaderChain::connect_locked()` runs `check_activation_gate()`
   (`nmc/coin/header_chain.hpp` L1109-1117), which returns
   `REJECT_MISSING_AUXPOW` for any header at or after the AuxPoW activation
   height that does not carry a parsed AuxPoW. `add_headers()` (L1147) always
   calls `connect_locked(h, std::nullopt)` (no AuxPoW). Activation height is
   `0` on testnet (L665 region) and `19200` on mainnet (L641 region). Namecoin
   has been AuxPoW since 2014, so a plain header feed admits **nothing** above
   genesis on testnet and nothing past height 19200 on mainnet. The tip never
   advances, so `is_synced()` (24 h tip-age gate, L1185-1193) stays false, so
   `get_work_template()` returns `{}` forever (`aux_chain_embedded.hpp` L72).

Gaps (1) and (2) are ordinary wiring. Gap (3) is a **design choice in the NMC
header chain** and is what the fix must resolve. Simply copying the DOGE feed
on top of the current gate would be rejected at the gate -- exactly the trap the
prior review flagged.

---

## 3. Why the naive fix fails, and what DOGE actually does

The already-working merged lane is DOGE-under-LTC. DOGE has produced real
merged blocks (README records first merged-mined DOGE block #6135703). It is the
correct reference for "how does an embedded aux chain follow its tip well enough
to build aux work?" -- and it does **not** cryptographically verify each aux
block's AuxPoW during header-follow. It follows the aux chain by SPV:

`doge::coin::HeaderChain` connect path (`doge/coin/header_chain.hpp` L446-472):

```cpp
bool is_auxpow = m_params.is_auxpow(new_height);
uint256 pow_hash;
if (is_auxpow) {
    // AuxPoW: trust PoW (validated by the parent chain), store SHA256d placeholder
    pow_hash = block_hash(header);
} else {
    // Non-AuxPoW: scrypt PoW validation (with fast-sync skip for old headers)
    ...
    if (!check_pow(pow_hash, header.m_bits, m_params.pow_limit)) return false;
}
```

For AuxPoW-height blocks DOGE **admits the plain 80-byte base header** on
prev-hash linkage and difficulty-retarget structure alone, storing a placeholder
PoW hash. The AuxPoW proof is *stripped during parsing*
(`doge::coin::parse_doge_headers_message`, `doge/coin/auxpow_header.hpp` L74,
wired via `broadcaster->set_raw_headers_parser(...)`, main_ltc.cpp L5631) so the
variable-length AuxPoW framing in the `headers` message does not choke the
standard 80-byte parser, and then plain `add_headers()` advances the chain.

The NMC header chain is **stricter**: it returns `REJECT_MISSING_AUXPOW` where
DOGE would admit. That strictness -- cryptographically verifying every aux block
before admitting it -- is a legitimate *higher* security posture, but it is
inconsistent with the shipping DOGE lane, and it structurally gates NMC work
production because there is no path today that carries the parsed AuxPoW from
the P2P `headers` payload into `add_auxpow_header()`:

- The AuxPoW verifier is fully present and KAT-locked. `AuxPow::check_proof()`
  runs all four legs (`nmc/coin/header_chain.hpp` L438-540), `AuxPow::Unserialize`
  is byte-faithful (L402), `add_auxpow_header()` (L1128) verifies then connects,
  and `nmc/test/auxpow_merkle_test.cpp` KAT-locks the verdicts.
- But the shared `CoinBroadcaster` header seam carries only
  `std::vector<ltc::coin::BlockHeaderType>` -- its `HeadersCallback`
  (`src/c2pool/merged/coin_broadcaster.hpp` L147) and `RawHeadersParser`
  (L161) both **drop the AuxPoW**. So there is no route from the wire to
  `add_auxpow_header()` without changing a seam shared with DOGE and DGB.

This is why "wire a DOGE-style feed" does not work as-is: DOGE's feed reaches a
chain that *accepts* auxpow-height plain headers; NMC's chain *rejects* them.

---

## 4. Decision

Two mechanisms produce work. They differ in security posture and cost.

### Mechanism A -- SPV-follow parity with DOGE **(RECOMMENDED)**

Make the NMC header chain follow its tip the same way DOGE does, then wire the
peers and feed.

- **Relax the NMC connect path** so that at or after activation a header
  *without* AuxPoW is **admitted structurally** (prev-hash linkage + difficulty
  retarget), storing a placeholder PoW hash -- mirroring DOGE's `is_auxpow`
  branch. Below activation, verify the pure SHA256d PoW as today. Concretely,
  `check_activation_gate()` stops returning `REJECT_MISSING_AUXPOW` for the
  plain-follow path; the `add_auxpow_header()` / `check_proof()` machinery stays
  in place, available and KAT-locked, for callers that *do* supply a proof.
- **Add `nmc::coin::parse_nmc_headers_message`** (mirror of
  `parse_doge_headers_message`) that consumes an NMC `headers` batch, strips any
  AuxPoW framing, and yields clean base headers. Wire it via the existing
  `set_raw_headers_parser` seam. **No shared-seam change.**
- **Wire the NMC block in main_ltc.cpp**, mirroring DOGE: an NMC case in
  `get_chain_p2p_prefix` (from `NMCChainParams::p2p_magic`), NMC `valid_ports`
  `{8334, 18334}`, `set_dns_seeds`/`set_fixed_seeds` from
  `nmc_dns_seeds`/`nmc_fixed_seeds`, and an `set_on_new_headers` ->
  `add_headers` + `set_on_peer_height` + periodic `getheaders` block.

Result: `nmc_chain` gets peers, receives headers, advances, `is_synced()`
becomes reachable, and `get_work_template()` emits aux work -- with a security
model **identical to the DOGE lane already in production**. No shared-seam
change, and no live-namecoind goldens are required to produce work (a synthetic
round-trip KAT is sufficient -- see section 6; a live capture later confirms exact wire
framing).

### Mechanism B -- strict AuxPoW verification (optional future hardening)

Keep the mandatory-AuxPoW gate and instead extend the shared `CoinBroadcaster`
seam (`HeadersCallback` / `RawHeadersParser`) to carry the parsed AuxPoW, so the
feed admits via `add_auxpow_header()` with full `check_proof()`. This
cryptographically verifies every NMC block.

Costs: a change to a seam shared with DOGE and DGB (each needs its own KATs);
live-namecoind goldens to lock the exact `headers`-message framing; and it makes
NMC *stricter than the DOGE lane it sits beside*, for a security gain that only
matters if a peer feeds a false-but-well-formed header chain. The failure mode
that gain defends against is bounded: a bad NMC tip causes us to build aux work
on a wrong prev-hash, so any NMC block we find is orphaned by the real network -- 
wasted aux effort, **not** a loss on the parent (BTC) block, which is
independently valid. That is the same bounded risk DOGE already accepts.

**Recommendation: ship Mechanism A.** It resolves #980 with the minimum change,
stays consistent with the working sibling lane, touches no shared seam, and
needs no external daemon capture to prove work production. Mechanism B remains
available as a later hardening pass -- its verifier is already implemented and
tested -- and, if pursued, should be adopted for DOGE and DGB in the same seam
change rather than for NMC alone.

---

## 5. Classification

`touches_consensus_reward = FALSE`. The blocker and both candidate fixes are
header-feed / SPV-sync plus aux-template production. They do not alter share
validity, the parent coinbase, the reward/coinbase split, or the template
content miners build. The dual-target check that qualifies a found share as a
real NMC block is unchanged and runs at share submission, not during
header-follow. This is a non-Dash, nudge-paused, low-priority lane; it ships
only as a dedicated, verified PR.

---

## 6. Implementation checklist (Mechanism A)

1. `nmc/coin/header_chain.hpp` -- relax the connect path: admit plain headers at
   or after activation on structural grounds (placeholder PoW hash), matching
   DOGE's `is_auxpow` branch; keep sub-activation pure-PoW verification; keep
   `add_auxpow_header()`/`check_proof()` intact.
2. `nmc/coin/auxpow_header.hpp` (new) -- `parse_nmc_headers_message`, mirroring
   `doge/coin/auxpow_header.hpp`.
3. `src/c2pool/main_ltc.cpp` -- NMC cases in `get_chain_p2p_prefix`,
   `valid_ports`, seeds, and the header-sync block (peer-height +
   `on_new_headers` -> `add_headers` + periodic `getheaders`), mirroring the DOGE
   block.
4. Telemetry #980 asked for: a counter that stays zero until the aux chain
   advances beyond its seed, surfaced on the dashboard / status, so
   "constructed and seeded" can never again read as "operational".
5. **KAT** (allowlisted `nmc/test` target): feed a captured or synthetically
   round-tripped NMC `headers` batch through `parse_nmc_headers_message` +
   `add_headers`, assert the tip advances past the activation height and
   `is_synced()` becomes true. A synthetic golden -- a header batch serialized by
   the same code and round-tripped -- proves the mechanism end to end without a
   live daemon; a later live-namecoind capture confirms exact wire framing.

## 7. README

`README.md` currently says NMC merged mining is "in development", which is
accurate and should stay until Mechanism A lands *and* a work template is
observed on a running node. Do not advertise NMC as operational before the
zero-until-advance telemetry (item 4) shows the chain advancing.
