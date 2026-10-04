# Deviations register: XMR lane implementation vs the v37 design of record

Started 2026-10-04 after the operator found that the XMR lane had drifted from the design. Rule from now on: any departure from the design of record needs an explicit operator ruling and an entry here before code is written.

This is the c2pool copy of the register. The origin is frstrtr/the, branch `v37/xmr-path-b-2026-10-04`, file `v37/steward-capture-2026-10-04-xmr-path-b/DEVIATIONS.md`. Keep the two in sync: an entry added, ruled or closed in one is mirrored in the other on the same day. The daily canon cron compares the ids of both copies and logs a difference to its drift log. This copy adds the columns the checker reads: the canon rule (docs/canon/CANON.yaml), the ruling and the closing PR.

How `tools/canon/canon_check.py` reads this table: one row per deviation, `id` is `D<n>`, `canon rule` lists rule ids (`C01`), and the first word of `status` is one of `open`, `closed`, `rejected`, `withdrawn`. Every failing canon rule must name an open deviation here, and the row must name the rule back (rule C09). When every rule of an open deviation passes, the checker reports it closable: set the status to `closed`, fill in the closing PR, and mirror the change in frstrtr/the.

| id | canon rule | design of record | as built (frstrtr/c2pool) | effect | ruling (who, when) | status | closing PR |
|---|---|---|---|---|---|---|---|
| D1 | C01, C08 | Carriers are ordinary shares of a sharechain; they order the network (docs/c2pool-v37-work-receipts.md section 2, Work Receipts paper section 2) | No carrier sharechain. Receipts are flooded as fb_receipt frames and ordered by (bin, id) with a late tail (src/c2pool/v37/xmr/relay/xmr_order_rule.hpp) | Agreement had to come from lane-block cuts: cut decisions, HOLD, repair, F3 deep order, G9 | operator, 2026-10-04 (Path B 11:22 +04; built on Work Receipts and carriers, correction 15:00 +04) | open: undocumented until 2026-10-04; to be removed under Path B (slice S1) | - |
| D2 | C02 | A receipt binds the miner's previous on-chain share and rides the miner's own next carrier | prev_own_share is display-only (src/impl/xmr/receipt/xmr_receipt.hpp:207-215) | No self-carriage; any node may present any receipt | operator, 2026-10-04 (Path B, correction 15:00 +04) | open: to be removed under Path B (slice S2) | - |
| D3 | C03 | Context window N_CTX = 2 mainchain blocks (ratified V37.0) | 30-bin full-weight late tail, about 1 hour (kLateTailBins = 30) | Stale work paid in full for an hour (free ride, measured 99.8 % of stale work admitted) | operator, 2026-10-04 11:22 +04 (Path B: Path A "accepts 1 hour of useless work") | open: to be replaced by LEGALLY DEAD (Path B, slice S2) | - |
| D4 | C04, C08 | Owed ledger (ledger #2) as carry-forward bank | Built and extended (drain, K_fair, dust decay, debit-only booking, DROPS due) | Cut decisions and HOLD needed for agreement on a shared ledger | operator, 2026-10-04 11:22 +04 (Path B: no owed ledger before mainnet) | open: ruled out by Path B; code removed in slice S6 | - |
| D5 | C05 | Shares and receipts are separate objects | The 2026-10-04 ledger-free design run fused them into a P2Pool-style share chain with uncles | Orphans, uncles, uncle penalty and selfish share mining came back | operator, 2026-10-04 (rejected the same day, correction 15:00 +04) | rejected: never merged; the next design run starts from RDWR | - |

Lesson: every fix round in an area that already needed one round is checked against the design of record before the next round is written.

## Notes of the c2pool copy

- C08 (no wall clock in XMR lane consensus) maps to D1 and D4. The clock reads that the canon baseline counts outside its allowlist sit in the agreement machinery those two deviations describe: the receipt ingest closes a bin after a wall-clock grace period (`src/c2pool/v37/xmr/relay/xmr_receipt_ingest.hpp`, `tick`), the relay node times repair, ordering and peer state (`xmr_relay_node.hpp`), and the lineage vote ages its observations by wall-clock seconds (`src/c2pool/v37/xmr/xmr_o2_finalize_connect.hpp`, `vote_stale_s`). They go when Path B removes that machinery (slices S1, S2, S6).
- D5 never reached frstrtr/c2pool. Rule C05 keeps it out.
