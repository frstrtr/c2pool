// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// S2 (RUNTIME-INJECT-DESIGN 5.4): one line per inject per template height,
/// so an operator sees from the log alone whether an admitted inject is in
/// the block being mined:
///   [GBT-EMB] inject RIDES h=<H> txid=<16> vin=<n> fee=<duffs>
///   [GBT-EMB] inject HELD  h=<H> txid=<16> cause=<coinbase-only-template|not-selected>
/// A template rebuilt at the same height logs again only when the verdict
/// changes. Telemetry only: nothing here touches the template.
///
/// S4: every build also records each inject's verdict in the read-only
/// per-inject ledger (core::obs::inject_ledger().set_last_build), BEFORE the
/// log's dedup, so /api/tx-inject/ledger always shows the current verdict
/// while the log stays quiet on repeats. An inject the ledger does not track
/// gets no entry there (set_last_build is a no-op for it).

#include "mempool.hpp"
#include "utxo_adapter.hpp"

#include <core/inject_ledger_obs.hpp>
#include <core/log.hpp>
#include <core/uint256.hpp>

#include <cstdint>
#include <map>
#include <mutex>
#include <set>
#include <string>
#include <utility>
#include <vector>

namespace dash {
namespace coin {

/// The lines for one build. Returns them as well (KATs read them).
inline std::vector<std::string> log_inject_rides(const Mempool& mempool,
                                                 const std::vector<Mempool::SelectedTx>& selected,
                                                 uint32_t height, bool coinbase_only)
{
    std::vector<std::string> lines;
    const auto injects = mempool.inject_txids_in_pool();
    static std::mutex mu;
    static std::map<uint256, std::pair<uint32_t, bool>> last;   // txid -> (height, rode)
    std::lock_guard<std::mutex> lock(mu);
    const std::set<uint256> live(injects.begin(), injects.end());
    for (auto it = last.begin(); it != last.end();)
        it = live.count(it->first) ? std::next(it) : last.erase(it);
    auto& ledger = ::core::obs::inject_ledger();
    for (const auto& id : injects) {
        const Mempool::SelectedTx* ride = nullptr;
        for (const auto& s : selected)
            if (dash_txid(s.tx) == id) { ride = &s; break; }
        const char* held_cause = coinbase_only ? "coinbase-only-template" : "not-selected";
        {
            ::core::obs::InjectLedgerBuild b;
            b.height = height;
            b.rides  = ride != nullptr;
            b.cause  = ride ? "ok" : held_cause;
            b.vin    = ride ? static_cast<uint32_t>(ride->tx.vin.size()) : 0u;
            b.fee    = ride ? static_cast<uint64_t>(ride->fee) : 0u;
            ledger.set_last_build(id, b);
        }
        auto prev = last.find(id);
        if (prev != last.end() && prev->second.first == height && prev->second.second == (ride != nullptr))
            continue;
        last[id] = {height, ride != nullptr};
        std::string line = ride
            ? "[GBT-EMB] inject RIDES h=" + std::to_string(height) + " txid=" + id.GetHex().substr(0, 16) +
                  " vin=" + std::to_string(ride->tx.vin.size()) + " fee=" + std::to_string(ride->fee)
            : "[GBT-EMB] inject HELD h=" + std::to_string(height) + " txid=" + id.GetHex().substr(0, 16) +
                  " cause=" + held_cause;
        LOG_INFO << line;
        lines.push_back(std::move(line));
    }
    return lines;
}

} // namespace coin
} // namespace dash
