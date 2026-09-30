# Integer-design audit of the consensus code

Audit of 2026-09-30, branch `claude/nifty-allen-ktyg1s`.

**The rule.** Anything that decides consensus state must be pure integer,
deterministic across platforms, with an explicit rule for truncation and
saturation. That covers lane weights, the E_b split, the owed ledger, coinbase
amounts, share and raindrop admission, targets, estimator credit and digests.
Work is derived from the **target**, never from the achieved hash:

- `att(T) = floor(2^256 / (T+1))`, the stdlib twin of
  `target_to_average_attempts`, which returns a uint288;
- on XMR, the 288-bit normalised geometry
  `N = floor(H · share_diff / 2^32)`.

## Result

**No float is on any consensus path, and there is no live consensus bug.**

Checked and clean:

- `w2_receipt.hpp`: `work_of_lz` and `work_from_target` saturate.
- `normalized_hash`.
- `rescale_price`, `work_numerator` and `divfloor_clamped_576`.
- `split_reward`.
- The lane: Q62 decay, `mul_q` factors ≤ 1, and the width law's damp →
  clamp → floor.
- `nr_ladder` and roundabout.
- XMR settle: `paynow_split`, `allocate_exact_sum`, the spend floor in u128,
  and dust decay by halving.
- The V37R total, the fee-model weight split, the owed digest, the Monero
  difficulty checks and `get_block_reward`.

## Findings and what was done

| # | where | finding | status |
|---|---|---|---|
| C1 | `share_covered_work` | `floor(S·2^256/h_T)` where the design sums `att(T) = floor(2^256/(h_T+1))` per share. Equal on the leading-zero geometry. | **Count (XMR) uses the att form** (`share_covered_work_att`), so both sides of its delta are att sums. The K-min modes keep the old form because the minted Family-A DROPS goldens depend on it. Moving them is an operator ruling. |
| C2 | `estimate_combined` | K-min derives work from the achieved hash's order statistic (and is biased, see `drops-split/`). | **XMR moved to Count** (work from the target). Family-A still selects Combined. It needs its own ruling before any Family-A flip. |
| C3 | `compose_credit_from_delta` (BTC/DASH) | A peer-carried DROPS delta is added to `long long` with no range bound, which can overflow (UB). | Open. Family-A only, and gated (flip 0 for non-XMR). XMR re-derives its delta and uses the carried map only as a checked witness. Fix before a Family-A flip: bound \|v\| by the reward at decode time and use saturating adds. |
| C4 | `U256::mul_small` | Wrapped silently past 2^256 (width-law numerator, roundabout). | **Fixed: saturates** to 2^256−1, as `div_u128_to_u64` does. No value below 2^256 changes. |
| C5 | `U256 +=`, `mul_q` | Wrap on overflow, relying on range pinning. | No action. Every factor checked is ≤ 1, and the MRR carry has an explicit headroom check. |
| C6 | `split_give_author` | No overflow guard. | No action. The bound cannot be reached with lane-derived values. |
| N1 | `--give-author-pct`, `--node-owner-fee-pct` | Parsed as `double`. The resulting u16 is PoW-committed, so an x87/FMA build could round a `.5` boundary differently. | **Fixed:** `parse_pct_exact` reads the decimal text as `num / 10^k`, and `give_author_u16` / `pct_to_bp` round half-up in u128. It equals the double form on all 10001 hundredths 0.00..100.00 (`v37_xmr_fee_model_kat`). The doubles remain for display only. |
| N2 | legacy `payout/payout_manager.cpp` | `reward*pct/100.0` in double. A 150% RPC value made the miner amount wrap. RPC/display only. | **Fixed:** integer amounts (u128, clamped percent), the fees never exceed the reward (`PayoutRules.DemoCoinbaseNeverWrapsOnOverHundredPercent`). |
| N3–N6 | tx selection, rate limiters, stats, diagnostic digests, the loose stratum pre-check | Double or host-endian, but local policy, display or a superset pre-check that the exact rule re-decides. | No action. None of them feeds a receiver's decision. |

## Related

- `drops-split/README.md`: why XMR credits raindrops by Count.
- `window-pulse/README.md`: the window under pulsing hashrate.
