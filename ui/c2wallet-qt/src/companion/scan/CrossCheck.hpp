// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// Scan & Plan (companion) — the dual-source cross-check (design §3.2 "Both",
// §4.2 "before export").
//
// Run dashd and the c2pool node; both must report the same tip hash. When they
// do not, the lagging one (the lower tip height; both on a height tie with
// different hashes) is read again, up to `tip_rounds` times (a DASH block
// arrives every 2.6 min on average), then scan-tips-differ. At one tip the two
// row sets must be identical on (txid, vout, value, script, height, coinbase)
// after the union of both mempool_spent lists is removed from both sides; any
// difference refuses with every differing outpoint named
// (scan-source-mismatch). The result carries dashd's rows, the union of the
// mempool-spent lists, both source details and cross_checked = true.
//
// A source that cannot serve a scan at all (no route, no full UTXO set,
// transport down) refuses the whole scan unless allow_single_source is set:
// then the other source's result is returned with cross_checked = false and a
// warning naming the missing source (the sidecar records it, the signer shows
// it in red). A disagreement (tips, rows, a self-inconsistent source) is never
// downgraded.

#include "ScanTypes.hpp"

#include <string>
#include <vector>

namespace c2w::companion::scan {

struct CrossCheckOptions {
    int tip_rounds = 3;
    bool allow_single_source = false;
};

// The differences between two scans of the same addresses at one tip, one
// line per outpoint ("<txid>:<vout> value 1 != 2"), the union of both
// mempool-spent lists removed first. Empty when they agree.
std::vector<std::string> diff_scans(const ScanResult& a, const ScanResult& b);

ScanResult scan_both(UtxoSource& dashd, UtxoSource& c2pool, const std::vector<std::string>& addresses,
                     const ScanOptions& opt, const CrossCheckOptions& cc);

} // namespace c2w::companion::scan
