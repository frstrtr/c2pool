# V37 payment-hardening — h_min / dust-anchor analyses + real-block replay

Analysis scripts and consolidated findings for the v37 payout-hardening track:
the byte-denominated, script-type-aware h_min floor (Rule-0) and the dust-anchor
model, validated against real p2pool mainnet data. Prototype/analysis code on
the v37 design track — no consensus code.

## Contents

- `realblock-955609-replay.py` — replays the real p2pool BTC block 955609
  coinbase (`data/coinbase.json`, committed) through the Rule-0 h_min floor +
  carry rules; the executable validation of the byte-denominated h_min design.

  ```
  python3 realblock-955609-replay.py
  ```

- `hmin-dust-anchor-longitudinal.py` — longitudinal dust-anchor model over a
  multi-block p2pool dataset. The dataset (~94 MB `blocks.json`) is NOT
  committed; place it at `data/longitudinal/blocks.json` (collected from the
  public p2pool block index) to run this script.

- `c2pool-v37-m4-hmin-dust-anchor.md` — the h_min/dust-anchor design analysis.
- `realblock-955609-validation.md` — findings from the block-955609 replay.
- `c2pool-v37-payment-hardening-consolidated-DRAFT.md` — consolidated track
  draft (landed in prose form as frstrtr/the #20, the payment-hardening fold).
- `FINDINGS-glm-xcheck-running.md` — cross-check run notes.

## Relations

- The h_min floor consumed here is encoded per script type by
  `PayoutDescriptor` (`src/sharechain/v37/v37_descriptor.hpp`, the ratified
  payout-identity canon).
- W5 of the A2 bring-up (coinbase assembly) names the block-955609 replay as
  its golden gate.
