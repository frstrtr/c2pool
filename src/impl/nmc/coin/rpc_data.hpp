#pragma once

// NMC (Namecoin) RPC work-data type.
//
// Re-homed mirror of src/impl/btc/coin/rpc_data.hpp into namespace nmc::coin /
// nmc::coin::rpc so the NMC coin tree is self-contained and does not pull
// btc::coin symbols. WorkData is the block-template payload produced by the
// embedded TemplateBuilder (P1 PC) and consumed downstream (share creation,
// Stratum) exactly as the GBT JSON path was. No btc header is modified.

#include <vector>

#include "transaction.hpp"

#include <nlohmann/json.hpp>

namespace nmc
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

} // namespace nmc
