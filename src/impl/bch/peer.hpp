#pragma once

#include "coin/transaction.hpp"

#include <chrono>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <core/uint256.hpp>

namespace bch
{

// Per-connection peer state for the BCH share/pool p2p layer.
// Mirrors btc::Peer; BCH carries no witness data, so m_remembered_txs holds
// plain (non-witness) coin::Transaction — see coin/transaction.hpp.
struct Peer
{
    std::optional<uint32_t> m_other_version;
    std::string m_other_subversion;
    uint64_t m_other_services;
    uint64_t m_nonce;
    std::chrono::steady_clock::time_point m_connected_at{std::chrono::steady_clock::now()};

    std::set<uint256> m_remote_txs; // hashes advertised by the peer

    std::map<uint256, coin::Transaction> m_remembered_txs;
};

}; // namespace bch
