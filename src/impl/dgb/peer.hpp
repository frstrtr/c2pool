#pragma once

/// DGB p2pool peer protocol handlers (pool-layer, distinct from coin-layer p2p_connection).
///
/// Phase B B2 (pool-node layer). Ported verbatim from src/impl/ltc/peer.hpp,
/// Scrypt-only — DGB shares use the identical share format and peer state as LTC.
/// COMPAT: byte-identical-except-namespace to ltc::Peer keeps wire/state parity
/// with frstrtr/p2pool-merged-v36; any divergence => [decision-needed].

#include "coin/transaction.hpp"

#include <chrono>
#include <set>
#include <optional>
#include <core/uint256.hpp>

namespace dgb
{

struct Peer
{
    std::optional<uint32_t> m_other_version;
    std::string m_other_subversion;
    uint64_t m_other_services;
    uint64_t m_nonce;
    std::chrono::steady_clock::time_point m_connected_at{std::chrono::steady_clock::now()};

    std::set<uint256> m_remote_txs; // hashes
    // int32_t remote_remembered_txs_size = 0;

    std::map<uint256, coin::Transaction> m_remembered_txs;
    // int32_t remembered_txs_size = 0;
    // const int32_t max_remembered_txs_size = 25000000;
};

}; // namespace dgb
