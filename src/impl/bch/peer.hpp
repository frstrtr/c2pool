// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

#include "coin/transaction.hpp"

#include <chrono>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <core/tx_advertiser.hpp>
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

    // Send side of the tx-pool advertisement: our reconstruction of what this
    // peer believes WE hold, so each sweep can emit only the delta as
    // have_tx / losing_tx. Mirror image of m_remote_txs above (what the peer
    // told us IT holds). See core/tx_advertiser.hpp for canonical semantics.
    core::TxAdvertState m_tx_advert;
};

}; // namespace bch