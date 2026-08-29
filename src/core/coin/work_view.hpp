#pragma once

// ---------------------------------------------------------------------------
// core::coin::WorkView -- the coin-AGNOSTIC slice of a per-coin WorkData that
// src/core/web_server actually consumes (family-1 link fix, P2 seam).
//
// nm census of web_server.cpp.o @ c4547575 (ci-steward, authoritative): the TU
// reads a WorkData via ONLY these three fields -- m_data, m_hashes, m_latency.
// It NEVER touches m_txs (grep 'm_txs' src/core/web_server.cpp == 0 hits). So
// the link break is not "abstract the interface", it is "stop crossing the seam
// with the payload": the per-coin WorkData (incl. vector<Transaction> m_txs)
// stays coin-side via work.set(wd); only this view crosses into core. That
// severs BOTH cluster A (ltc:: symbols) and cluster B (Transaction type) at
// once -- web_server.cpp.o then names no ltc:: symbol and no Transaction type.
//
// Field names mirror the concrete per-coin WorkData EXACTLY so every existing
// web_server line (wd.m_data / wd.m_hashes / wd.m_latency) is UNCHANGED.
//   - m_data    : getblocktemplate-shaped json the stratum/getwork path serves
//   - m_hashes  : merkle/branch hashes (vector<uint256>)
//   - m_latency : template build latency; consumed at web_server.cpp:2381 as
//                 static_cast<double>(wd.m_latency) -> m_last_work_latency.store
// ---------------------------------------------------------------------------

#include <ctime>
#include <vector>

#include <nlohmann/json.hpp>
#include <core/uint256.hpp>

namespace core::coin {

struct WorkView {
    nlohmann::json          m_data;
    std::vector<uint256>    m_hashes;
    std::time_t             m_latency = 0;
};

} // namespace core::coin
