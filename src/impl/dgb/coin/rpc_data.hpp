#pragma once

// ---------------------------------------------------------------------------
// dgb::coin::rpc::WorkData -- per-coin work payload for the family-1 P2
// WorkView seam (Path A minimal-stub).
//
// Mirrors src/impl/btc/coin/rpc_data.hpp with ONE deliberate trim: btc's
// WorkData carries std::vector<Transaction> m_txs, but DGB has no
// coin/transaction.{hpp,cpp} port yet -- that lands with the M3 embedded
// daemon slice. The ICoinNode seam contract makes the trim safe: web_server
// consumes ONLY the agnostic slice (m_data/m_hashes/m_latency); the full
// per-coin WorkData (incl. txs) never crosses the seam
// (src/core/coin/node_iface.hpp). When the DGB transaction port lands, m_txs
// is restored here and the coin-side work.set(wd) retention in
// CoinNode::get_work_view() carries it without any seam change.
//
// V36 master compat: field semantics match p2pool-merged-v36 getwork result
// (data / txhashes / latency); impl plan section 3 (frstrtr/the, 8ef8d2d).
// ---------------------------------------------------------------------------

#include <ctime>
#include <utility>
#include <vector>

#include <core/uint256.hpp>

#include <nlohmann/json.hpp>

namespace dgb
{

namespace coin
{

namespace rpc
{

struct WorkData
{
    nlohmann::json m_data;
    std::vector<uint256> m_hashes; // transaction hashes
    time_t m_latency = 0;

    // TODO(M3): std::vector<Transaction> m_txs once coin/transaction.{hpp,cpp}
    // is ported (DGB txs are bitcoin-family; expected near-verbatim from btc's
    // port). Kept out of the stub so the rpc chain compiles without the
    // Transaction/Block types dgb does not have yet.

    WorkData() {}
    WorkData(nlohmann::json data, std::vector<uint256> txhashes, time_t latency)
        : m_data(std::move(data)), m_hashes(std::move(txhashes)), m_latency(latency)
    {
    }

    bool operator==(const WorkData& rhs) const { return m_data == rhs.m_data; }
    bool operator!=(const WorkData& rhs) const { return !(*this == rhs); }
};

} // namespace rpc

} // namespace coin

} // namespace dgb
