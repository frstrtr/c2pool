# src/c2pool/payout — legacy payout module (pre-v37)

`developer_payout.{hpp,cpp}` and `payout_manager.{hpp,cpp}` are the payout
and fee module of the pre-v37 LTC path. They are compiled and used only by
`src/c2pool/main_ltc.cpp` and `src/core/web_server.{hpp,cpp}`.

They are **not** part of the v37 settlement path (W4 owed ledger, W5
coinbase, the XMR lane). Their numbers do not apply there:

- `default_fee_percent = 0.5` (a 0.5% developer floor the operator may raise
  but not lower);
- `set_node_owner_fee()` accepts up to 50%.

The v37 XMR lane has its own, separately documented fee model:
`src/c2pool/v37/xmr/xmr_fee_model.hpp` and
`docs/xmr-lane/payout-fairness.md` §5.
