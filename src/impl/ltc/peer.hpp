#pragma once

#include "transaction.hpp"

#include <set>
#include <optional>
#include <core/uint256.hpp>

namespace ltc
{

struct Peer
{
    std::optional<uint32_t> m_other_version;
    std::string m_other_subversion;
    uint64_t m_other_services;
    uint64_t m_nonce;
    
    std::set<uint256> m_remote_txs; // hashes
    // int32_t remote_remembered_txs_size = 0;

    std::map<uint256, ltc::Transaction> m_remembered_txs;
    // int32_t remembered_txs_size = 0;
    // const int32_t max_remembered_txs_size = 25000000;
};

}; // namespace ltc