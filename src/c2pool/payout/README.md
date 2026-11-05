# src/c2pool/payout — legacy payout module (pre-v37)

`payout_manager.{hpp,cpp}` is the payout and fee module of the pre-v37 (V36)
LTC path. It is built as `c2pool_payout`, and only `src/c2pool/main_ltc.cpp`
and `src/core/web_server.{hpp,cpp}` include it. No v37 settlement code does.

It does not build the real coinbase; the V36 sharechain does. The module
reports the fees as the sharechain pays them (the startup log, the local
solo split, the P2P current-payout display and the demo coinbase RPC):

- **Donation (give-author):** exactly the miner's `--give-author` percent of
  each share's weight, with no floor. 0 leaves only the 1-satoshi V36
  donation marker. The LTC donation address is the V36 combined donation
  script.
- **Node-owner fee:** in P2P mode it is a payee substitution at job issue
  and is already inside the share weights, so the display deducts nothing.
  In the local solo split it is its own output. The only bound is
  donation + owner <= 100%.

The old `developer_payout.{hpp,cpp}`, with its 0.5% developer floor, was never
compiled and has been removed. The rules above are pinned by `core_test`
`PayoutRules.*` (`src/core/test/payout_manager_rules_test.cpp`).

This module is **not** part of the v37 settlement path (W4 owed ledger, W5
coinbase, the XMR lane). The XMR lane's fee model is
`src/c2pool/v37/xmr/xmr_fee_model.hpp`, described in
`docs/xmr-lane/payout-fairness.md` §5.
