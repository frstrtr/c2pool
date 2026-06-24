# DGB Greenlight Gate G2 — RATCHET Staged-Migration — Evidence

Gate sequence: G1 (oracle byte-parity KAT) → **G2 (this)** → G3a/G3b (testnet block production).
Harness: `scripts/dgb_g2_ratchet_staged_migration_harness.sh`
Oracle (conformance reference): `frstrtr/p2pool-dgb-scrypt` — share VERSION=35, SUCCESSOR=None.
c2pool-dgb drives the **35 → 36 ratchet**, backward-compatible with the ver35 oracle during the migration window. This is the DGB per-coin migration gate against its OWN oracle — NOT the LTC v35 transition.

## Testbed (self-provisioned, VM115 isolated scrypt net — vm-fleet NOT used)
| Field | Value |
|---|---|
| Net | isolated DGB scrypt testnet, diff-1, 192.168.86.42 |
| Sharechain IDENTIFIER (bucket-1) | `4B62545B1A631AFE` (both pools peer as ONE sharechain) |
| Donation tag | `4104ffd0…` (oracle) → v36 P2SH 1-of-2 in-window |
| POOL O (oracle ver35) | p2p `5024`, stratum `9327` |
| POOL V (v36 c2pool-dgb) | p2p `5025`, stratum `9328` |
| Parent digibyted | rpc `14022`, p2p `14023`, self-service creds (600, not on any card) |
| Run SHA (c2pool-dgb) | `__________` |
| Date / operator-acked | `__________` |

## The 5 checks

| # | Check | Property under test | Evidence | Verdict |
|---|---|---|---|---|
| C1 | BASELINE COHABIT | v36 c2pool-dgb peers the ver35 oracle on `IDENTIFIER 4B62545B1A631AFE` and **accepts** ver35 shares (backward-compat in-window). No sharechain split. | `__________` | ☐ PASS / [GATED: rigs] |
| C2 | VOTING MINT | In VOTING, c2pool-dgb mints `base_version=35` (oracle-faithful) and advertises `desired_version=36` (the vote); **no premature v36-format mint**. | **sim PASS 3/3** `DGB_share_test.AutoRatchet{BootstrapMintsBaselineWhileVoting,WireBootstrapMints35Votes36,BaseVersionParameterized}` / live: `__________` | ☑ sim PASS · live [GATED: rigs] |
| C3 | STAGED ACCEPT GATE (#288) | The 95%-**by-flat-count** desired trigger is **gated behind the 60%-by-WORK accept** (`get_desired_version_weights` idx→work). Mint **cannot outrun accept**: flat 95% does NOT activate until work ≥ 60%. (Exercised directly per integrator.) | **sim PASS 9/9** `AutoRatchetTailGuard.*` (incl `SwitchedHonoursSixtyPercentFloor`, `TailGuardPassesOnWorkWeightedMajority`) / live: `__________` | ☑ sim PASS · live [GATED: rigs] |
| C4 | RATCHET + PERSIST | On 60%-by-work + 95% sustained for `2*CHAIN_LENGTH`: VOTING→ACTIVATED→CONFIRMED; v36-format mint begins; ver35 oracle still accepts in-window; **CONFIRMED survives c2pool-dgb restart** (JSON state). | **sim PASS 3/3** `DGB_share_test.AutoRatchet{StatePersistsAcrossRestart,ThresholdsMatchCanonical,WireBaselineConstantsFromOracle}` / live: `__________` | ☑ sim PASS · live [GATED: rigs] |
| C5 | ALGO POSTURE | Scrypt is the ONLY validated/work-weighted algo. SHA-256d / Skein / Qubit / Odocrypt = **N/A-by-continuity** (V36 scope; V37 defers). Recorded N/A explicitly — **not a skipped check**. | **PASS 12/12** `DgbAlgoSelect.*` (incl `AllKnownNonScryptAlgosAreContinuity`) + `DgbScryptPowKAT.*` | ☑ PASS (no rig dependency) |

### Multi-algo leg detail (C5 — explicit N/A, not skipped)
| Algo | V36 posture | Note |
|---|---|---|
| Scrypt | **VALIDATED + work-weighted** | the only consensus-bearing algo for c2pool-dgb V36 |
| SHA-256d | N/A-by-continuity | accept-by-continuity / ignored; V37 scope |
| Skein | N/A-by-continuity | V37 scope |
| Qubit | N/A-by-continuity | V37 scope |
| Odocrypt | N/A-by-continuity | V37 scope |

## Rig dependency (why some rows are GATED)
C2/C3/C4 **live** work-weighted evidence needs real scrypt hashrate to move `desired_version_weights`. The only valid scrypt set is the **3× R1-LTC rigs**, currently in the LIVE LTC crossing-soak (owner: ltc-doge-production-steward). Per integrator (UID2208): author first, then request the rig window — do **not** pull rigs off a live soak.

Until rigs are brokered, the harness proves the staged-gate **logic** now via the AutoRatchet KAT seam (`--sim-votes`): C2/C3/C4 sim rows can read PASS while their LIVE rows stay `[GATED: rigs]`. C1 substrate is reachable on provision; C1 live-peer assertion is GATED on both pools running on the rig-fed net. C5 is fully provable now (no rig dependency).

## Sim run record (staged-gate LOGIC, rig-independent)
`./scripts/dgb_g2_ratchet_staged_migration_harness.sh checks --sim-votes` on 2026-06-24, dev-host build_dgb @ branch `dgb/g2-ratchet-staged-migration-harness` (off master `fc9342b12`):

```
C1 BASELINE COHABIT ........ [GATED: rigs]  (substrate provision reachable; live-peer needs both pools on rig-fed net)
C2 VOTING MINT ............. sim PASS 3/3
C3 STAGED ACCEPT GATE #288 . sim PASS 9/9
C4 RATCHET + PERSIST ....... sim PASS 3/3
C5 ALGO POSTURE ............ PASS 12/12  (Scrypt-only; 4 algos N/A-by-continuity)
-> 27/27 logic checks green; C1 + the C2/C3/C4 LIVE rows GATED on rigs.
```

## Sign-off
- Harness SHA: `__________`  ·  GPG-signed, no attribution.
- Sim pass (logic): `__________`
- Live pass (rig window): `__________`  ← requested from integrator; brokered against LTC soak.
- Greenlight to G3a/G3b: ☐ (operator)
