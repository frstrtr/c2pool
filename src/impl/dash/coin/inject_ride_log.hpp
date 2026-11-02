// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// S2 (RUNTIME-INJECT-DESIGN 5.4): one line per inject per template height,
/// so an operator sees from the log alone whether an admitted inject is in
/// the block being mined:
///   [GBT-EMB] inject RIDES h=<H> txid=<16> vin=<n> fee=<duffs>
///   [GBT-EMB] inject HELD  h=<H> txid=<16> cause=<coinbase-only-template|not-selected>
/// A template rebuilt at the same height logs again only when the verdict
/// changes. Telemetry only: nothing here touches the template.

#include "mempool.hpp"
#include "utxo_adapter.hpp"

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
    for (const auto& id : injects) {
        const Mempool::SelectedTx* ride = nullptr;
        for (const auto& s : selected)
            if (dash_txid(s.tx) == id) { ride = &s; break; }
        auto prev = last.find(id);
        if (prev != last.end() && prev->second.first == height && prev->second.second == (ride != nullptr))
            continue;
        last[id] = {height, ride != nullptr};
        std::string line = ride
            ? "[GBT-EMB] inject RIDES h=" + std::to_string(height) + " txid=" + id.GetHex().substr(0, 16) +
                  " vin=" + std::to_string(ride->tx.vin.size()) + " fee=" + std::to_string(ride->fee)
            : "[GBT-EMB] inject HELD h=" + std::to_string(height) + " txid=" + id.GetHex().substr(0, 16) +
                  " cause=" + (coinbase_only ? "coinbase-only-template" : "not-selected");
        LOG_INFO << line;
        lines.push_back(std::move(line));
    }
    return lines;
}

} // namespace coin
} // namespace dash
