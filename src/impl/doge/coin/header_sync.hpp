// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// Embedded DOGE: when the header chain asks peers for headers (main_ltc's
/// DOGE header handlers), as Dogecoin/Bitcoin Core does it
/// (net_processing.cpp ProcessHeadersMessage):
///   - after a headers batch, more are asked only of the peer that sent new
///     ones, with the chain's locator; a batch with nothing new asks nothing.
///     Before, a full batch with nothing accepted asked every peer again, and
///     an accepted one asked every peer with a bare last-hash locator (a
///     peer without that hash answers from genesis): ~80 getheaders a minute
///     and ~190 MB a minute of AuxPoW headers, which delayed every other
///     answer on those connections (the hash schedule's among them);
///   - the periodic getheaders asks one peer per tick while the chain is
///     catching up (round robin), and every peer once it is synced;
///   - a block announcement (inv) asks the announcing peer, at once, never
///     every peer (HeaderAsks): no second getheaders to a peer while one is
///     unanswered (2 min, Core's HEADERS_RESPONSE_TIME), and while the chain
///     catches up one announcer per new block (Core: one new peer per
///     block). Before, every inv during catch-up asked every peer.

#include <core/uint256.hpp>

#include <chrono>
#include <map>
#include <mutex>
#include <string>

namespace doge {
namespace coin {

/// What to do after a headers batch.
enum class HeadersFollowUp {
    None,       // nothing new in it: ask nothing
    AskSender,  // new headers: ask the same peer for more, from the chain's locator
};

inline HeadersFollowUp headers_follow_up(int accepted)
{
    return accepted > 0 ? HeadersFollowUp::AskSender : HeadersFollowUp::None;
}

/// Who the periodic getheaders goes to.
enum class HeadersPoll {
    OnePeer,    // catching up: one peer per tick
    EveryPeer,  // synced: every peer (the tip's headers)
};

inline HeadersPoll headers_poll(bool chain_synced)
{
    return chain_synced ? HeadersPoll::EveryPeer : HeadersPoll::OnePeer;
}

/// The header chain's getheaders per peer (net_processing.cpp
/// MaybeSendGetHeaders, the inv handling of a block not known).
/// Thread safety: every method takes the internal mutex.
class HeaderAsks {
public:
    using Clock = std::chrono::steady_clock;
    static constexpr std::chrono::minutes RESPONSE_TIME{2};

    /// `peer` announced `block`, which the chain does not have: ask it now?
    /// true = send it a getheaders (recorded as sent).
    bool on_inv(const std::string& peer, const uint256& block, bool chain_synced, Clock::time_point now)
    {
        std::lock_guard<std::mutex> lock(m_mu);
        if (peer.empty() || outstanding_locked(peer, now))
            return false;
        if (!chain_synced && block == m_last_block)
            return false;  // this block already brought one peer in
        m_last_block = block;
        sent_locked(peer, now);
        return true;
    }

    /// A getheaders went to `peer` (any path: the poll, a follow-up).
    void sent(const std::string& peer, Clock::time_point now)
    {
        std::lock_guard<std::mutex> lock(m_mu);
        if (!peer.empty())
            sent_locked(peer, now);
    }

    /// A headers message came from `peer`: its getheaders is answered.
    void answered(const std::string& peer)
    {
        std::lock_guard<std::mutex> lock(m_mu);
        m_sent.erase(peer);
    }

    /// `peer` has a getheaders of the header chain unanswered.
    bool outstanding(const std::string& peer, Clock::time_point now)
    {
        std::lock_guard<std::mutex> lock(m_mu);
        return outstanding_locked(peer, now);
    }

private:
    static constexpr size_t MAX_PEERS = 512;

    bool outstanding_locked(const std::string& peer, Clock::time_point now) const
    {
        auto it = m_sent.find(peer);
        return it != m_sent.end() && now - it->second < RESPONSE_TIME;
    }

    void sent_locked(const std::string& peer, Clock::time_point now)
    {
        if (m_sent.size() >= MAX_PEERS) {
            for (auto it = m_sent.begin(); it != m_sent.end();)
                it = now - it->second >= RESPONSE_TIME ? m_sent.erase(it) : std::next(it);
            if (m_sent.size() >= MAX_PEERS)
                m_sent.clear();
        }
        m_sent[peer] = now;
    }

    std::mutex m_mu;
    std::map<std::string, Clock::time_point> m_sent;  // peer -> an unanswered getheaders
    uint256 m_last_block;                             // the last block that brought a peer in
};

} // namespace coin
} // namespace doge
