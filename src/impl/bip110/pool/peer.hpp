// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once
//
// bip110::pool::Peer — sharechain peer state. Structural copy of the BTC lane's
// peer.hpp; coin:: resolves to bip110::coin via enclosing-namespace lookup, so the
// remembered/remote tx types bind to the BIP-110 coin transaction.

#include "../coin/transaction.hpp"

#include <chrono>
#include <set>
#include <map>
#include <optional>
#include <core/tx_advertiser.hpp>
#include <core/uint256.hpp>

namespace bip110::pool
{

struct Peer
{
    std::optional<uint32_t> m_other_version;
    std::string m_other_subversion;
    uint64_t m_other_services;
    uint64_t m_nonce;
    std::chrono::steady_clock::time_point m_connected_at{std::chrono::steady_clock::now()};

    std::set<uint256> m_remote_txs; // hashes

    std::map<uint256, coin::Transaction> m_remembered_txs;

    // Send-side tx-pool advertisement state (mirror of core/tx_advertiser.hpp).
    core::TxAdvertState m_tx_advert;
};

} // namespace bip110::pool
