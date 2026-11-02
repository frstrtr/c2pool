// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// Scan & Plan (companion) — the c2pool node source (design §3.2 SourceC2pool,
// the client side of node slice N1, §3.6).
//
//   GET /api/utxo/scan?address=A[&address=B...]&exclude_mempool_spent=1
//
// over the existing sched::NodeApi seam (loopback only; the node answers this
// route only to a direct-local peer). Reply (200):
//   {"ok": true, "tip_height", "tip_hash",
//    "utxo": {"mode": "full", "state": "serving", "coins"},
//    "scanned", "elapsed_ms", "tip_moved", "truncated",
//    "scripts": [{"address", "script_hex"}],
//    "unspents": [{"txid", "vout", "value", "script_hex", "height", "coinbase"}],
//    "mempool_spent": [{"txid", "vout"}], "total_value"}
//
// Refusals: utxo.mode != "full" or state != "serving", or a 409
// utxo-set-not-full / -withheld / -catching-up => scan-node-utxo-not-full (a
// scan of the 288-block accrual view would silently miss old coins); 404 =>
// scan-node-no-route (a node without the N1 slice); 403 / 409 busy / 429 =>
// scan-node-refused; truncated:true => scan-truncated (an incomplete set is
// never exported); tip_moved:true is retried up to ScanOptions::
// c2pool_tip_retries times, then scan-tip-unstable. Every script the node
// echoes must be the requested address's P2PKH, every row must pay one of
// them, and total_value must equal the sum of the rows.
//
// The endpoint is node slice N1 (separate); this client is tested against
// fixtures through a fake NodeApi only.

#include "ScanTypes.hpp"

#include "../sched/NodeApi.hpp"

#include <string>
#include <vector>

namespace c2w::companion::scan {

inline constexpr const char* kUtxoScanRoute = "/api/utxo/scan";

// The request path for `addresses` (already validated base58, which needs no
// URL escaping).
std::string utxo_scan_path(const std::vector<std::string>& addresses, bool exclude_mempool_spent);

class SourceC2pool : public UtxoSource {
public:
    explicit SourceC2pool(sched::NodeApi& node) : node_(node) {}
    ScanResult scan(const std::vector<std::string>& addresses, const ScanOptions& opt) override;
    const char* kind() const override { return "c2pool"; }

private:
    sched::NodeApi& node_;
};

} // namespace c2w::companion::scan
