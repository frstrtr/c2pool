# BTC Greenlight Gate G2 — RATCHET Staged-Migration — Evidence

Gate sequence: G1 (version_gate SSOT boundary KAT) → **G2 (this)** → G3a/G3b (regtest block production, shipped #435).
Harness: `scripts/btc_g2_ratchet_staged_migration_harness.sh` (mirrors DGB #427).
Oracle (conformance reference): `p2pool-btc-jtoomim @ece15b03` — SPB share VERSION=35, sharechain protocol 3502.
c2pool-btc drives the **35 → 36 ratchet**, backward-compatible with the v35 oracle during the migration window. This is the BTC per-coin migration gate against its OWN oracle — a **separate SHA256d sharechain**, NOT the LTC v35 crossing (never gated on the LTC soak).

## Testbed (self-provisioned, isolated — bucket-1 isolation primitives kept per-instance)
| Field | Value |
|---|---|
| Net | isolated bitcoind **testnet** (BTC has no `--regtest` parent), diff held low |
| Sharechain IDENTIFIER (bucket-1, `--network-id`) | `b7c0920263617465` (private; both pools peer as ONE sharechain) |
| Sharechain PREFIX (bucket-1, `--prefix`) | `526174636821` (independent constant — no algebraic tie to IDENTIFIER) |
| POOL O (oracle v35 jtoomim, SPB/proto 3502) | p2p `9333`, stratum `9332` |
| POOL V (v36 c2pool-btc) | p2p `9533`, stratum `9532`, web/stats `8350` |
| Parent bitcoind | rpc `18332`, p2p `18333`, self-service creds (600, not on any card) |
| Staged-migration shape | `STAGES=7` miners staged ONE AT A TIME |
| Run SHA (c2pool-btc) | `__________` |
| Date / operator-acked | `__________` |

## The 5 checks

| # | Check | Property under test | Evidence | Verdict |
|---|---|---|---|---|
| G1/anchor | VERSION_GATE SSOT | The 35→36 boundary the ratchet keys off: `is_v36_active(36)=true`, `is_v36_active(35)=false`, `V36_ACTIVATION_VERSION=36`; segwit (v33) NOT folded into the v36 gate. **Rig-free, provable now.** | **PASS 2/2** `BTC_version_gate.{V36ActivationBoundary,SegwitNotFoldedIntoV36Gate}` (ctest `build`, 2026-06-24) | ☑ PASS (no rig dependency) |
| C1 | BASELINE COHABIT | v36 c2pool-btc peers the v35 jtoomim oracle on the private `IDENTIFIER` and **accepts** v35 SPB shares (backward-compat in-window). No sharechain split. Work-weighted tally **readout mechanism** (`sampling_desired_version` / `shares_by_desired_version` on `/local_stats`) confirmed reachable. | substrate + readout reachable on provision / live-peer+v35-accept: `__________` | ☐ substrate reachable · live [GATED: rigs] |
| C2 | VOTING MINT | In VOTING, c2pool-btc mints `base_version=35` (oracle-faithful) and advertises `desired_version=36` (the vote); **no premature v36-format mint**. | live: `__________` | live [GATED: rigs] |
| C3 | STAGED ACCEPT GATE (#288) — **THE acceptance criterion** | Miners staged **ONE AT A TIME**; after each stage the work-weighted v36 tally (`sampling_desired_version`) must advance **MONOTONICALLY** (hard-fail on any regression at a stage boundary), and the 95%-**by-COUNT** activation must NOT flip `VOTING→ACTIVATED` until work ≥ **60%** (`get_desired_version_weights`). Mint **cannot outrun accept**. **Per-stage tally captured in the RESULT line.** | asserts armed (monotonic + #288 ordering) / per-stage tally readout: `__________` | live [GATED: rigs] |
| C4 | RATCHET + PERSIST | On 60%-by-work + 95% sustained for `2*CHAIN_LENGTH`: VOTING→ACTIVATED→CONFIRMED; v36-format mint begins; v35 oracle still accepts in-window; **CONFIRMED survives c2pool-btc restart**. | live: `__________` | live [GATED: rigs] |
| C5 | ALGO POSTURE | BTC is **single-algo by construction** — SHA-256d is THE one validated/work-weighted algo; there is no multi-algo leg to gate (contrast DGB's scrypt-among-5). Recorded explicitly — **not a skipped check**. | by construction (no other BTC PoW algo exists) | ☑ PASS (no rig dependency) |

## Rig dependency + BTC-specific gap (why C1–C4 LIVE rows are GATED)
C1/C2/C3/C4 **live** work-weighted evidence needs real **SHA256d hashrate** to move `sampling_desired_version` through staged stratum miners. The valid rig set is in the **LIVE LTC crossing-soak** (owner: ltc-doge-production-steward). Per the DGB #427 precedent: **author first, then request the rig window — do NOT pull rigs off a live soak.**

**BTC-specific (differs from DGB #427):** DGB simulated the staged-gate **logic** now via a rich `AutoRatchet*` ctest suite (`--sim-votes`). **BTC has NO AutoRatchet ctest suite** — only the two `BTC_version_gate.*` boundary KATs. So there is **no sim fallback** for C2/C3/C4; the staged tally must be proven **LIVE/rig-fed**. The harness arms the monotonic + #288-ordering asserts and confirms the readout mechanism now; the asserts only carry a verdict once a rig-fed run drives non-zero work weights.

→ **Open to integrator:** (a) request the rig window to run C1–C4 live, OR (b) authorize a small `BTC AutoRatchet` KAT suite mirroring DGB's so the staged-gate logic can be sim-proven rig-free (note: that would touch `src/impl/btc/test/` + `build.yml` allowlist — **crosses the scripts/ fence**, needs explicit go-ahead).

## Run record (provable now, rig-free)
`./scripts/btc_g2_ratchet_staged_migration_harness.sh gate-logic` on 2026-06-24, dev-host `build` @ branch `btc/g2-ratchet-staged-migration` (off master `549f4f621`):

```
GATE-LOGIC ANCHOR: version_gate SSOT 35->36 boundary ... PASS 2/2
  BTC_version_gate.V36ActivationBoundary ....... Passed
  BTC_version_gate.SegwitNotFoldedIntoV36Gate .. Passed
C1 BASELINE COHABIT ........ substrate + tally-readout reachable; live-peer/v35-accept [GATED: rigs]
C2 VOTING MINT ............. [GATED: rigs]  (no BTC AutoRatchet sim KAT)
C3 STAGED ACCEPT GATE #288 . asserts armed (monotonic + 60%-work<-95%-count ordering); per-stage tally [GATED: rigs]
C4 RATCHET + PERSIST ....... [GATED: rigs]  (no BTC AutoRatchet sim KAT)
C5 ALGO POSTURE ............ PASS  (SHA-256d single-algo by construction)
-> version_gate anchor + C5 green NOW; C1 substrate/readout reachable; C2/C3/C4 LIVE rows GATED on rigs.
```

## Sign-off
- Harness SHA: `__________`  ·  GPG-signed, no attribution.
- Gate-logic anchor pass (rig-free): `__________`
- Live pass (rig window): `__________`  ← requested from integrator; brokered against LTC soak.
- Greenlight to G3a/G3b: G3a already shipped (#435); G2 live pass closes the gate.
