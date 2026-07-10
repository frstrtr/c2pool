// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

#include <vector>

#include "transaction.hpp"

#include <nlohmann/json.hpp>

// bch::coin getwork/GBT result -- ported from src/impl/btc/coin/rpc_data.hpp.
// Coin-agnostic slice (m_data/m_hashes/m_latency) is what crosses the
// core::coin::WorkView seam; the full WorkData (incl. m_txs) stays coin-side.
//
// BCH notes (vs the BTC source):
//  - No MWEB: the LTC mweb extension field is N/A and omitted (BCH/btc neither).
//  - m_txs holds bch::coin::Transaction (legacy, no-witness; see transaction.hpp).
//  - GBT field mapping (version/previousblockhash/transactions/coinbasevalue/
//    time|curtime/coinbaseflags|coinbaseaux/bits/height/rules) is shared with
//    BTC and lands when the template builder/rpc slice is ported (later in M3).

namespace bch
{

namespace coin
{

namespace rpc
{

struct WorkData
{
    nlohmann::json m_data;
    std::vector<Transaction> m_txs;
    std::vector<uint256> m_hashes; // transaction hashes
    time_t m_latency;

    WorkData() {}
    WorkData(nlohmann::json data, std::vector<Transaction> txs, std::vector<uint256> txhashes, time_t latency)
        : m_data(data), m_txs(txs), m_hashes(txhashes), m_latency(latency)
    {

    }

    bool operator==(const WorkData& rhs) const { return m_data == rhs.m_data; }
    bool operator!=(const WorkData& rhs) const { return !(*this == rhs); }
};

} // namespace rpc

} // namespace coin

} // namespace bch