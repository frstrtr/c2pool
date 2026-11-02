// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// Scan & Plan (companion) — the dashd source (design §3.2, SourceDashd).
//
//   1. Tip loop (tools/export_utxos.py): getblockchaininfo -> getaddressutxos
//      {"addresses":[...], "chainInfo":true} -> getblockcount, retried while the
//      tip moved; the tip is the chainInfo object's height/hash. A dashd
//      without -addressindex answers -32600: fall back to one scantxoutset
//      "start" ["addr(A)", ...] for every address (height / bestblock are the
//      tip; success:false is refused), then getbestblockhash must still be the
//      bestblock, else the scan is repeated once.
//   2. gettxout txid n true per row: null => the output is spent in the mempool
//      (or in a block the index has not caught up with) and goes to
//      mempool_spent; otherwise its bestblock must be the scan's tip (else the
//      whole scan is repeated), round(value * 1e8) must equal the row's
//      satoshis, scriptPubKey.hex the row's script and confirmations
//      tip - height + 1 — a mismatch refuses the scan
//      (scan-source-inconsistent). The coinbase flag comes from gettxout (and
//      must agree with scantxoutset's own flag on that path).
//   3. Rows grouped per address (each must pay that address's P2PKH), sorted
//      (height, txid, vout), confirmations = tip - height + 1.
//
// getaddressutxos rows name the output index `outputIndex` (dashd 23.x, the
// captured fixture) while the RPC help text says `index`: both are accepted.

#include "RpcApi.hpp"
#include "ScanTypes.hpp"

namespace c2w::companion::scan {

// One input of a signed tx, re-checked right before it is queued (preflight).
struct UnspentCheck {
    Outpoint outpoint;
    bool unspent = false;
    std::string problem;          // empty: unspent with the expected value and script
};

class SourceDashd : public UtxoSource {
public:
    explicit SourceDashd(RpcApi& rpc) : rpc_(rpc) {}
    ScanResult scan(const std::vector<std::string>& addresses, const ScanOptions& opt) override;
    const char* kind() const override { return "dashd"; }

    // gettxout txid n true per input (mempool spends count as spent): each
    // must still be unspent with exactly the value and script given.
    std::vector<UnspentCheck> check_unspent(const std::vector<c2w::dash::Utxo>& inputs, const ScanOptions& opt);

private:
    RpcApi& rpc_;
};

} // namespace c2w::companion::scan
