# Deviations register

Rows where the XMR lane code in this tree differs from a canon rule (docs/canon/CANON.yaml). `tools/canon/canon_check.py` reads the table: `id` is `D<n>`, `canon rule` lists rule ids, and the first word of `status` is `open`, `closed`, `rejected` or `withdrawn`. Every failing ruled rule names an open deviation here and the row names the rule back (rule C09). The full text of each row is kept outside this repository under its reference.

| id | canon rule | differs | status | closing | full text |
|---|---|---|---|---|---|
| D1 | C01, C08, C22, C33, C42, C43 | no carrier sharechain; receipts ordered by (bin, id); no catch-up template rule | open | slice S4w | ref: the:D1 |
| D2 | C02 | a display-only prev_own_share field | open | slice S2 | ref: the:D2 |
| D3 | C03, C22 | full-weight late tail (kLateTailBins = 30) | open | slices S2, S4w | ref: the:D3 |
| D4 | C04, C08, C21 | owed ledger in the payout path | open | slice S4w | ref: the:D4 |
| D5 | C05 | share chain with uncles (not merged) | rejected | - | ref: the:D5 |
| D6 | C11 | fixed --share-diff per node, no retarget | open | slice S4w | ref: the:D6 |
| D7 | C13 | fixed output cap ceiling 2700 with pay-now selection above it | open | slice S4w | ref: the:D7 |
| D8 | none | raindrops default ON | closed | #1921 | ref: the:D8 |
| D9 | C19 | owner fee as payee substitution at job issue | open | slices S2, S6 | ref: the:D9 |
| D10 | C20 | no payout proof in the stratum dialect | open | slice S6 | ref: the:D10 |
| D11 | C23, C24 | no rules ratchet on master | open | slice S4w | ref: the:D11 |
| D12 | C26 | author donation default 0.1 % | closed | #1921 | ref: the:D12 |
| D13 | C32 | AGPL-3.0-or-later headers | closed | #1921 | ref: the:D13 |
| D14 | none | positional window, no towing path (towing is not in v1; the window part is D21) | withdrawn | - | ref: the:D14 |
| D15 | C35 | narrowing casts in the consensus core not each proven; no extreme-value KAT | open | allowlist review; slice S3 | ref: the:D15 |
| D16 | C27 | not applicable to this tree | closed | 480c3dc6 | ref: the:D16 |
| D17 | C32 | third-party copyleft template | closed | #1922 | ref: the:D17 |
| D18 | C03 | admission n_ctx = 2; no tip freshness; no own-position liveness | open | slice S4w | ref: the:D18 |
| D19 | C36 | R_MAX_XMR = 2; no canonical selection | open | slice S4w | ref: the:D19 |
| D20 | C37 | no per-receipt coinbase check at admission; lagged finalize anchor | open | slices S2, S4w | ref: the:D20 |
| D21 | C38, C41 | positional window; no work bound; no W_max; window inputs not read on the tip's branch | open | slice S4w | ref: the:D21 |
| D22 | C38 | design text: time-denominated window with bin decay | open | text rewrite | ref: the:D22 |
| D23 | C39 | reference fairness scenarios not in CTest | open | a reader check of the C39 KATs | ref: the:D23 |
| D24 | C45 | receipt and frame caps as literals (768, 1024, 8 receipts per frame); coinbase midstate in the receipt | open | slice S4w | ref: the:D24 |
| D25 | C43 | journal depth inside the lane digest | open | slice S4w | ref: the:D25 |
| D26 | C44 | Monero context blocks from lane peers not PoW-checked | closed | #1931 (context-block PoW check) | ref: the:D26 |
| D27 | none | fee output beside the full-R split (never entered) | withdrawn | - | ref: the:D27 |
| D28 | C18 | raindrop wiring armed in every default build | open | slice S4w | ref: the:D28 |
| D29 | C45, C46 | relay and stratum values as literals without a flag | open | slices S1, S2 | ref: the:D29 |
| D30 | C25 | receipt side data v3 and the MMR light-proof vectors not built | open | slice S4w | ref: the:D30 |
| D31 | C26 | author donation as a 0-amount marker output; no weight share | open | slice S4w | ref: the:D31 |
| D32 | C27 | no monero_rules_digest | open | slice S4w | ref: the:D32 |
| D33 | C36 | S2 self-carried receipts only; open carriage and header rules #9 in a later slice | closed | #1953 | ref: the:D33 |
| D34 | C43 | FC_GETBUCKETS carries at; FC_BUCKETS carries key references, leaf_count, peaks, S and paged rows | closed | #1965 | ref: the:D34 |
| D35 | C43 | joiner: #12 / #13 checked from x1; earlier span positions by PoW, hashes and roots | closed | #1987 | ref: the:D35 |
| D36 | C04, C23, C48, C49 | old payout path removed and Path B wired in a later flag-day slice S4w, after the unwired ratchet module S4 | open | slice S4w | ref: the:D36 |
| D37 | C43 | deep switch through the joiner path | open | S4w-a | ref: the:D37 |
| D38 | C25, C38, C41, C43 | SPEC S3 scope completed in S3b-1a..S3b-4; S4 module merged before S3b-1b..4 | closed | #1976, #1987 | ref: the:D38 |
| D39 | C01, C23, C43 | carrier tree on master: carried_root 0 fold and carrier-only, non-activating state step | closed | #1966 | ref: the:D39 |
| D40 | C21, C38 | window gives finder-only when the newest bin alone fails W_max | closed | #1964 | ref: the:D40 |
| D41 | C20 | signed job receipts without an on-chain anchor | open | first upgrade epoch | ref: the:D41 |
| D43 | C50 | private line cites in public code | closed | #1964, #1968 | ref: the:D43 |
| D44 | C25 | in-bin cut keyed on carrier position q descending, then id ascending (standing exception; re-examined before the raindrops epoch) | open | - | ref: the:D44 |
| D45 | C05, C49 | no re-pend after a switch by the joiner path (deeper than the journal, at least J_0 = 1152); a carried receipt is deferred when its tip's branch, or recursively the branch of the tip of any receipt carried on such a branch, forks from the carrier's chain more than J_0 below the carrier's parent | open | - | ref: the:D45 |
