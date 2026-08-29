# DASH Greenlight Gate G2 — RATCHET Staged-Migration — Evidence

Gate sequence: G1 (version_gate SSOT boundary KAT) → **G2 (this)** → G3a/G3b (regtest block production, **already PROVEN**: populated won blocks crossed + submitblock-accepted on regtest).
Harness: `scripts/dash_g2_ratchet_staged_migration_harness.sh` (mirrors DGB #427 / BTC #436).
Oracle (conformance reference): `frstrtr/p2pool-dash @9a0a609` — sharechain share **VERSION=16** (NOT v35).
c2pool-dash drives the **16 → 36 ratchet**, backward-compatible with the v16 oracle during the migration window. This is the DASH per-coin migration gate against its OWN oracle — a **separate X11 sharechain**, NOT the LTC v35 crossing (DASH is UNFENCED from the LTC soak; never gated on it).

## Testbed (self-provisioned, isolated — bucket-1 isolation primitives kept per-instance)
| Field | Value |
|---|---|
| Net | isolated **dashd regtest** (DASH **has** a `--regtest` parent — same substrate as the G3a/G3b populated won blocks), diff held low |
| Sharechain IDENTIFIER (bucket-1, `--network-id`) | `d3a5c0920263617` (private; both pools peer as ONE sharechain) |
| Sharechain PREFIX (bucket-1, `--prefix`) | `446173686721` (independent constant — no algebraic tie to IDENTIFIER) |
| POOL O (oracle v16 p2pool-dash, ver=16) | p2p `7903`, stratum `7902` |
| POOL V (v36 c2pool-dash) | p2p `8903`, stratum `8902`, web/stats `8350` |
| Parent dashd | rpc `19998`, p2p `19999`, self-service creds (600, not on any card; VMID 200/201 via `ssh pve`) |
| Staged-migration shape | `STAGES=7` miners staged ONE AT A TIME |
| Run SHA (c2pool-dash) | `__________` |
| Date / operator-acked | `__________` |

## The 5 checks

| # | Check | Property under test | Evidence | Verdict |
|---|---|---|---|---|
| G1/anchor | VERSION_GATE SSOT + weighted rule | The 16→36 boundary the ratchet keys off: `core::version_gate` `is_v36_active(36)=true` / `(16)=false`, `V36_ACTIVATION_VERSION=36`, plus the weighted accept/activate rule. **Rig-free, provable NOW on master.** | **PASS** `test_dash_conformance` — `DashConformanceVersionNeg.{SuccessorGuard60PercentWeightedKat, V36GateWeighted95PercentKat, GateUsesWeightNotPlainCount, SwitchClassifier5CaseKat}` + `DashConformanceVersionWiring.*` | ☑ PASS (no rig dependency) |
| C1 | BASELINE COHABIT | v36 c2pool-dash peers the v16 p2pool-dash oracle on the private `IDENTIFIER` and **accepts** v16 shares (backward-compat in-window). No sharechain split. Work-weighted tally **readout mechanism** (`sampling_desired_version` / `shares_by_desired_version` on `/local_stats`) confirmed reachable. | substrate + readout reachable on provision / live-peer+v16-accept: `__________` | ☐ substrate reachable · live [GATED: rigs] |
| C2 | VOTING MINT | In VOTING, c2pool-dash mints `base_version=16` (oracle-faithful) and advertises `desired_version=36` (the vote); **no premature v36-format mint**. **LOGIC sim-proven** by `DashConformanceVersionWiring` (`SameVersionAdmitted` / `StalePreV36ShareRejected`). | logic PASS (master) / LIVE mint: `__________` | ☑ logic PASS · live [GATED: rigs] |
| C3 | STAGED ACCEPT GATE (#288-class) — **THE acceptance criterion** | Miners staged **ONE AT A TIME**; after each stage the work-weighted v36 tally (`sampling_desired_version`) must advance **MONOTONICALLY** (hard-fail on any regression at a stage boundary), and the 95%-**by-COUNT** activation must NOT flip `VOTING→ACTIVATED` until work ≥ **60%**. Mint **cannot outrun accept**. **Per-stage tally captured in the RESULT line.** **ORDERING LOGIC sim-proven** by `DashConformanceVersionNeg` (weighted 60% / weighted 95% / weight-not-count / 5-case switch). | logic PASS (master); asserts armed (monotonic + #288 ordering) / per-stage LIVE tally readout: `__________` | ☑ logic PASS · live [GATED: rigs] |
| C4 | RATCHET + PERSIST | On 60%-by-work + 95% sustained for `2*CHAIN_LENGTH`: VOTING→ACTIVATED→CONFIRMED; v36-format mint begins; v16 oracle still accepts in-window; **CONFIRMED survives c2pool-dash restart**. Persisted-latch state machine = **Component A #466** (tap-bound); its **8/8 KAT** sim-proves the transitions + restart-survival off the master gate. | latch sim lands with #466 / LIVE: `__________` | latch sim ☐ (#466) · live [GATED: rigs] |
| C5 | ALGO POSTURE | DASH is **single-algo by construction** — X11 is THE one validated/work-weighted algo; there is no multi-algo leg to gate (contrast DGB's scrypt-among-5; same posture as BTC's SHA-256d). Recorded explicitly — **not a skipped check**. | by construction (no other DASH PoW algo exists) | ☑ PASS (no rig dependency) |

## DASH advantage over BTC #436 (why more rows are sim-green here)
BTC had **no AutoRatchet ctest** — its C2/C3/C4 staged-gate logic could only be proven LIVE/rig-fed. DASH (like DGB #427) carries a real **weighted-gate KAT suite on master** (`test_dash_conformance` `VersionNeg.*` + `VersionWiring.*`), so the staged-gate **LOGIC** — weighted accept ≥60%, weighted v36 gate ≥95%, weight-not-count, the 5-case switch classifier, and the wired-path admit/reject — is **sim-proven rig-free NOW**. Only the **LIVE work-weighted tally** through staged X11 stratum miners needs the rig window. DASH also **has a real `--regtest` parent** (BTC had to fall back to an isolated testnet).

## Rig dependency (why C1–C4 LIVE rows are GATED)
C1/C2/C3/C4 **live** work-weighted evidence needs real **X11 hashrate** to move `sampling_desired_version` through staged stratum miners. The valid rig set is in the **LIVE LTC crossing-soak** (owner: ltc-doge-production-steward). Per the DGB #427 / BTC #436 precedent: **author first, then request the rig window — do NOT pull rigs off a live soak.** The harness arms the monotonic + #288-ordering asserts and confirms the readout mechanism now; the LIVE rows carry a verdict once a rig-fed run drives non-zero work weights.

→ **Open to integrator:** request the X11 rig window to run C1–C4 **live**. No sim gap to close (unlike BTC): DASH's staged-gate logic is already sim-covered on master; C4's persisted-latch sim lands when **Component A #466** is tapped.

## Run record (provable now, rig-free)
`./scripts/dash_g2_ratchet_staged_migration_harness.sh gate-logic` on `__________`, dev-host `build` @ branch `dash/g2-ratchet-staged-migration` (off master `5ef41ff0`):

```
GATE-LOGIC ANCHOR: version_gate SSOT 16->36 boundary + weighted accept/activate rule ... PASS
  DashConformanceVersionNeg.SuccessorGuard60PercentWeightedKat ... Passed
  DashConformanceVersionNeg.V36GateWeighted95PercentKat ........... Passed
  DashConformanceVersionNeg.GateUsesWeightNotPlainCount ........... Passed
  DashConformanceVersionNeg.SwitchClassifier5CaseKat .............. Passed
  DashConformanceVersionWiring.{SameVersionAdmitted,StalePreV36ShareRejected,...} ... Passed
C1 BASELINE COHABIT ........ substrate + tally-readout reachable; live-peer/v16-accept [GATED: rigs]
C2 VOTING MINT ............. LOGIC PASS (VersionWiring); LIVE [GATED: rigs]
C3 STAGED ACCEPT GATE #288 . LOGIC PASS (VersionNeg); asserts armed (monotonic + 60%-work<-95%-count ordering); per-stage LIVE tally [GATED: rigs]
C4 RATCHET + PERSIST ....... latch sim lands with Component A #466; LIVE [GATED: rigs]
C5 ALGO POSTURE ............ PASS  (X11 single-algo by construction)
-> version_gate anchor + C2/C3 logic + C5 green NOW; C1 substrate/readout reachable; C1-C4 LIVE rows GATED on rigs.
```

## Sign-off
- Harness SHA: `__________`  ·  GPG-signed, no attribution.
- Gate-logic anchor pass (rig-free): `__________`
- Live pass (rig window): `__________`  ← requested from integrator; brokered against LTC soak.
- Greenlight to G3a/G3b: **G3a/G3b already PROVEN** (populated won blocks crossed + submitblock-accepted on regtest); G2 live pass closes the gate.
