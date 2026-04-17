#pragma once

#include "coin/transaction.hpp"

#include <set>
#include <optional>
#include <core/uint256.hpp>

namespace dash
{

struct Peer
{
    std::optional<uint32_t> m_other_version;
    std::string m_other_subversion;
    uint64_t m_other_services{0};
    uint64_t m_nonce{0};
    uint256 m_best_share;
    std::set<uint256> m_remote_txs;
    std::map<uint256, coin::Transaction> m_remembered_txs;
};

} // namespace dash
