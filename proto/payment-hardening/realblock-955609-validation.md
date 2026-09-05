# V37 payment-layer validation against real p2pool block 955609 (G3 witness)

Status: design/research for `frstrtr/the` (branch, attribution-gate clean). DESIGN ONLY — no c2pool code.
Validates `c2pool-v37-coinbase-prioritization.md` (Rule 0 floor + Rule 2 efficiency + Rule 5 carry)
and the byte-denominated `h_min` finding against a real canonical-p2pool BTC mainnet coinbase.

## Witness
Block 955609, hash `00000000…716fb7`; coinbase `a5e166f2…d461dcf9`; P2Pool/-spb.xyz tagged; fabe6d6d
sharechain commitment. Subsidy 312,500,000 sat; fees ONLY 14,189 sat (near-empty 2-tx block → the whole
subsidy PPLNS-split 53 ways). 53 paying outputs (full serialized sizes): 42× v0_p2wpkh (31 B), 8× p2pkh
(34 B), 2× p2sh (32 B), 1× p2pk. Total payout bytes 1,714; coinbase ≈ 1.86 KB incl. 2 OP_RETURNs.

Real p2pool emitted a **27-sat output to an UNCOMPRESSED-key P2PK** (spk `0x4104…ac` = push-65 →
76 B full output), eff = 27/76 = **0.355 sat/B**. 27 sat is below BTC dust (294 P2WPKH / 546 P2PKH);
coinbase outputs are dust-exempt, so real p2pool blindly emitted an economically-UNSPENDABLE output —
exactly the failure V37 Rule 0 + Rule 5 roll-forward fix (ties to the DASH dust-payout CONFORM ruling).
Next-smallest legit payout = 11,508 sat p2pkh (34 B, eff 338.47 sat/B).

## A. Rule 0 + Rule 5 replay (deterministic, all 53 outputs)
At every `k ∈ [1, 338]` sat/B, **exactly one** output is sub-floor and DEFERS — the 27-sat P2PK —
and all 52 legit outputs PAY in one block. The 11,508-sat P2PKH stays payable until `k > 338.47`.
Coinbase 1.7 KB ≪ K_max and there is no fee-tx competition, so Rule 1 Budget = Σsize (all payable fit).
**Verdict: V37 defers exactly the unspendable dust and pays everything spendable. Confirmed.**

## B. k calibration pinned by this block
Defer the 27-sat P2PK (76 B) ⇒ `k > 27/76 = 0.355`. Keep the 11,508 P2PKH (34 B) ⇒ `k ≤ 11508/34 =
338.47`. Real-data window: **0.355 < k ≤ 338.47 sat/B**.
Recommend **k = 1 sat/B** (1 sat per output byte = relay-floor opportunity cost): 2.8× margin above
the dust-defer threshold, 338× below the first legit deferral. `h_min(type) = k·size` at k=1:
P2WPKH 31, P2SH 32, P2PKH 34, P2TR 43, P2PK 76 (uncompressed) / 44 (compressed) sat.
At a fee-env framing (if one wished k≈fee_rate): ×10 → P2WPKH 310 / P2PKH 340 / P2PK 760; ×50 →
P2WPKH 1550 / P2PKH 1700 / P2PK 3800. Even at 50 sat/vB the 27-sat defers and all legit outputs pay.

## C. k MUST be a flat consensus constant, NOT fee-adaptive (correctness)
This near-zero-fee block makes the case concrete. A fee-rate-adaptive floor would (i) over-defer when
blockspace is nearly free (no fee txs to deny), and (ii) — fatally — make eligibility depend on
realized in-block fees, which are finder-chosen → reintroduces finder discretion over WHO is payable
(**violates F4 SELECT-determinism**, self-dealing surface). The fee-market tradeoff is already handled
by Rule 2 eff-sort + the Rule 1 `K_max` Budget cap (which shrinks payout bytes only when valuable fee
txs actually compete). k's sole job is anti-dust + Rule 4 net-positive. Keep k flat; pin k = 1 sat/B.

## D. Proposed adjustments (docs)
1. **Size-table convention bug (consensus-relevant).** `coinbase-prioritization.md` lists P2WPKH 31 /
   P2SH 32 / P2PKH 34 / P2TR 43 as full-output bytes but P2PK "~67 B" as the SCRIPT size (full output =
   76 B uncompressed). "A byte-size disagreement is a consensus split" → restate the whole table as
   **full serialized output bytes** and fix P2PK to 76 B (uncompressed) / 44 B (compressed).
2. **PayoutDescriptor must encode pubkey key-form.** The witness is an uncompressed-key P2PK (76 B) vs
   compressed (44 B): a **32-byte same-label size delta**. size[m] feeds both T_floor and eff and the
   Budget sum, so the descriptor's size derivation + the KAT must cover {type × key-form}, not just type.
   Extends the byte-denominated-h_min descriptor fold.
3. **Pin k = 1 sat/B flat** with the real-data justification above; document that fee-market adaptation
   is delegated to eff-sort + K_max, never to k (F4).
4. **Cite block 955609** as the G3 witness in both `coinbase-prioritization.md` and
   `payment-hardening.md` (the real-world dust-emission that motivates Rule 0 + Rule 5).

GLM adversarial cross-check of A–D queued on .45:8090 (cold-load); results fold here before PR.
