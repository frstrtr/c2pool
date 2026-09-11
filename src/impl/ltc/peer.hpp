// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

#include "coin/transaction.hpp"

#include <chrono>
#include <cstdint>
#include <map>
#include <set>
#include <optional>
#include <core/tx_advertiser.hpp>
#include <core/uint256.hpp>

namespace ltc
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

    // ── Per-peer remembered-tx store, BYTE-BOUNDED (p2pool parity) ────────
    // p2pool p2p.py bounds this store and raises PeerMisbehavingError('too much
    // transaction data stored') past the cap. The c2pool port carried the bound
    // over as two COMMENTED-OUT lines, so a single peer could grow this map
    // without limit: the only erase path is that same peer sending forget_tx,
    // and nothing obliges it to. Full coin::Transaction objects, peer-driven —
    // one of the unbounded structures behind the RSS self-abort.
    //
    // REWARD-SAFE: m_remembered_txs feeds only the send-side tx-completeness
    // gate and the v13-33 tx lookup; v36 shares carry no new-tx list through it.
    // Dropping the peer drops its map; shares it already delivered are in the
    // chain and unaffected. No share acceptance, PPLNS input or payout reads it.
    std::map<uint256, coin::Transaction> m_remembered_txs;

    // Packed size charged per entry, so forget_tx subtracts EXACTLY what
    // remember_tx added (re-packing on forget could drift and un-bound the cap).
    std::map<uint256, std::int64_t> m_remembered_txs_bytes;
    std::int64_t m_remembered_txs_size = 0;

    // p2pool p2p.py: 2.5 MB, plus its ~100 B per-entry bookkeeping charge. (The
    // 25000000 in the commented-out line this replaces has one zero too many.)
    static constexpr std::int64_t MAX_REMEMBERED_TXS_SIZE = 2500000;
    static constexpr std::int64_t REMEMBERED_TX_OVERHEAD = 100;

    /// Store one remembered tx and charge its packed size to this peer.
    void remember_tx(const uint256& hash, const coin::Transaction& tx,
                     std::int64_t packed_bytes)
    {
        const std::int64_t charge = packed_bytes + REMEMBERED_TX_OVERHEAD;
        auto it = m_remembered_txs_bytes.find(hash);
        if (it != m_remembered_txs_bytes.end())
            m_remembered_txs_size -= it->second;   // insert_or_assign overwrite
        m_remembered_txs.insert_or_assign(hash, tx);
        m_remembered_txs_bytes[hash] = charge;
        m_remembered_txs_size += charge;
    }

    /// Drop one remembered tx and give back exactly what it was charged.
    void forget_tx(const uint256& hash)
    {
        auto it = m_remembered_txs_bytes.find(hash);
        if (it != m_remembered_txs_bytes.end())
        {
            m_remembered_txs_size -= it->second;
            m_remembered_txs_bytes.erase(it);
        }
        m_remembered_txs.erase(hash);
        if (m_remembered_txs_size < 0) m_remembered_txs_size = 0;
    }

    bool remembered_txs_over_cap() const
    {
        return m_remembered_txs_size > MAX_REMEMBERED_TXS_SIZE;
    }

    // Send side of the tx-pool advertisement: our reconstruction of what this
    // peer believes WE hold, so each sweep can emit only the delta as
    // have_tx / losing_tx. Mirror image of m_remote_txs above (what the peer
    // told us IT holds). See core/tx_advertiser.hpp for canonical semantics.
    core::TxAdvertState m_tx_advert;
};

}; // namespace ltc