// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// own_share_reject_marks.hpp: re-broadcast hold-off for OUR OWN shares that a
// peer appeared to reject. Pure and templated. No consensus surface, no I/O.
//
// Origin (dba0be63d). A PoW-invalid genesis share made canonical p2pool drop us.
// The documented loop ran through the SERVE path: we advertise our best share
// in the version message, p2pool requests it (sharereq), we serve it, p2pool
// rejects it and aborts, we reconnect, and so on, about 90 times. The fix kept
// a global, never-expiring set of every hash pushed to a peer that disconnected
// within 10 s of a push, and stopped SERVING those hashes: handle_get_share and
// send_shares skipped them.
//
// That broke share sync (ltc.voidbind, 11-2026: 725 main-chain shares, about
// 39% of the main chain, branded in about 7 h):
//   * readvertise_best_share() pushes the 5 head shares, mostly OTHER miners'
//     shares, to every peer on every best-share change. So any drop inside the
//     window branded them, not just our own.
//   * The usual drop was a plain "Connection timed out", which says nothing
//     about the share.
//   * The brand never expired, and getshares replies skipped the branded
//     hashes. Every syncing peer got a reply with holes and had to fail over
//     (90 s retry window each). Canonical handle_get_shares
//     (p2pool-merged-v36 p2pool/node.py:141-152) skips nothing.
//
// What is deliberately NOT kept: the serve-path loop guard. Serving is never
// filtered, as in p2pool. We still advertise our best share in the version
// message and serve it on request even when it is marked here. So a share of
// ours that a python p2pool peer rejects can make that peer abort us once per
// handshake. That is bounded by p2pool's own escalating ban (badPeerHappened:
// 3600 s * banscore^2; its acceptor and dialer skip a banned host). Localhost
// is never banned, so a same-host p2pool sees about one abort per redial (~30 s).
// After the 3601 flag day, python p2pool and other pre-3601 peers are
// disconnected anyway (disconnect_pre_3601_peers). The case therefore only
// matters before the flag day or on a private chain.
//
// What this class does, and only this:
//   * It holds OUR OWN shares off RE-broadcast (broadcast_share and
//     readvertise_best_share) for MARK_TTL (10 min). Nothing in the get_shares
//     / send_shares serve path consults it.
//   * Only shares we minted in this process are recorded (the caller passes
//     only those). A share we received was validated by us and relayed by
//     others, so a peer dropping us says nothing about it. Our own shares
//     reloaded from LevelDB carry peer_addr "database" and are not marked
//     either.
//   * Only a peer ABORT counts as a rejection. Canonical p2pool drops a peer
//     that sends a bad share by raising PeerMisbehavingError ('share PoW
//     invalid', data.py), which packetReceived (p2p.py:106-108) turns into
//     badPeerHappened -> disconnect() -> transport.abortConnection()
//     (util/p2protocol.py:104-107). That is a TCP RST: asio
//     error::connection_reset, "Connection reset by peer". A timeout, an EOF
//     (an orderly close: restart, shutdown) and any close we initiate
//     ourselves never count.
//   * A mis-attributed abort can delay the RE-push of one of our shares by at
//     most MARK_TTL. The share is still served to anyone who asks.

#include <boost/asio/error.hpp>
#include <boost/system/error_code.hpp>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <map>
#include <string_view>
#include <utility>
#include <vector>

namespace ltc {

// Did the peer actively abort the connection (TCP RST)? Preferred form: the
// socket's error_code. asio's connection_reset is ECONNRESET on POSIX and
// WSAECONNRESET on Windows, so this does not depend on the message text.
inline bool disconnect_is_peer_abort(const boost::system::error_code& ec)
{
    return ec == boost::asio::error::connection_reset;
}

// Text fallback, for paths that only hand NodeImpl::error() a string
// (e.g. "Socket::write error: " + ec.message()). Unknown or localized text is
// NOT an abort, so a misclassification only ever loses the hold-off and never
// withholds a share.
inline bool disconnect_is_peer_abort(std::string_view reason)
{
    // POSIX strerror(ECONNRESET) on Linux, macOS and the BSDs.
    if (reason.find("reset by peer") != std::string_view::npos)
        return true;
    // Windows WSAECONNRESET (10054), English text.
    if (reason.find("forcibly closed by the remote host") != std::string_view::npos)
        return true;
    return false;
}

template <typename HashT, typename PeerKeyT>
class OwnShareRejectMarks
{
public:
    using clock      = std::chrono::steady_clock;
    using time_point = clock::time_point;

    // A drop this soon after a push is attributed to the push (unchanged from
    // dba0be63d).
    static constexpr std::chrono::seconds REJECT_WINDOW{10};
    // How long a marked share is held off re-broadcast.
    static constexpr std::chrono::seconds MARK_TTL{600};
    // Hard cap on live marks. We mint a few shares a minute at most, so this
    // is never reached in normal operation. It bounds a pathological case.
    static constexpr std::size_t MAX_MARKS = 1024;

    enum class Verdict
    {
        NoRecentPush,   // nothing of ours pushed to this peer within the window
        NotARejection,  // recent push, but timeout/EOF/other: not a rejection
        Marked,         // peer aborted within the window after a push of ours
    };

    struct DisconnectOutcome
    {
        Verdict verdict{Verdict::NoRecentPush};
        std::vector<HashT> newly_marked;   // hashes that were not already held off
        std::size_t own_in_push{0};        // own hashes in the attributed push
        std::chrono::milliseconds since_push{0};
    };

    // We just pushed `own_sent` (our OWN minted hashes that actually reached
    // the peer's write path) to `peer`. The latest push replaces the previous
    // record, as the old per-peer record did. An empty push clears the record,
    // so a later drop is never blamed on an older push.
    void note_push(const PeerKeyT& peer, std::vector<HashT> own_sent, time_point now)
    {
        if (own_sent.empty()) {
            m_pushes.erase(peer);
            return;
        }
        m_pushes[peer] = Push{std::move(own_sent), now};
    }

    // We closed the connection ourselves (ban, duplicate, misfit, pre-3601,
    // admin drop). What we pushed was not rejected by the peer.
    void forget_peer(const PeerKeyT& peer) { m_pushes.erase(peer); }

    enum class DropKind
    {
        PeerAbort,   // TCP RST: the canonical bad-share drop
        Other,       // timeout, EOF, protocol error, anything else
    };

    // The peer went away; `reason` is classified by its text.
    DisconnectOutcome on_disconnect(const PeerKeyT& peer, std::string_view reason, time_point now)
    {
        return on_disconnect(peer, disconnect_is_peer_abort(reason) ? DropKind::PeerAbort : DropKind::Other,
                             now);
    }

    // The peer went away; the caller already classified the drop.
    DisconnectOutcome on_disconnect(const PeerKeyT& peer, DropKind kind, time_point now)
    {
        DisconnectOutcome out;
        auto it = m_pushes.find(peer);
        if (it == m_pushes.end())
            return out;
        Push push = std::move(it->second);
        m_pushes.erase(it);

        const auto elapsed = now - push.when;
        if (elapsed >= REJECT_WINDOW)
            return out;

        out.own_in_push = push.own.size();
        out.since_push  = std::chrono::duration_cast<std::chrono::milliseconds>(elapsed);
        if (kind != DropKind::PeerAbort) {
            out.verdict = Verdict::NotARejection;
            return out;
        }

        out.verdict = Verdict::Marked;
        for (const auto& h : push.own) {
            if (!suppressed(h, now))
                out.newly_marked.push_back(h);
            m_expiry[h] = now + MARK_TTL;
        }
        enforce_cap(now);
        return out;
    }

    // Is `h` (one of our own shares) held off re-broadcast at `now`? Consulted
    // ONLY by the broadcast / re-advertise walks, never when serving.
    bool suppressed(const HashT& h, time_point now) const
    {
        auto it = m_expiry.find(h);
        return it != m_expiry.end() && now < it->second;
    }

    // Drop expired marks and push records too old to be blamed for a drop.
    void prune(time_point now)
    {
        for (auto it = m_expiry.begin(); it != m_expiry.end();)
            it = (now >= it->second) ? m_expiry.erase(it) : std::next(it);
        for (auto it = m_pushes.begin(); it != m_pushes.end();)
            it = (now - it->second.when >= REJECT_WINDOW) ? m_pushes.erase(it) : std::next(it);
    }

    std::size_t marked_count() const { return m_expiry.size(); }
    std::size_t pending_push_count() const { return m_pushes.size(); }

private:
    struct Push
    {
        std::vector<HashT> own;
        time_point when{};
    };

    void enforce_cap(time_point now)
    {
        if (m_expiry.size() <= MAX_MARKS)
            return;
        for (auto it = m_expiry.begin(); it != m_expiry.end();)
            it = (now >= it->second) ? m_expiry.erase(it) : std::next(it);
        while (m_expiry.size() > MAX_MARKS) {
            auto oldest = std::min_element(m_expiry.begin(), m_expiry.end(),
                [](const auto& a, const auto& b) { return a.second < b.second; });
            m_expiry.erase(oldest);
        }
    }

    std::map<PeerKeyT, Push> m_pushes;   // per peer: our own hashes in the latest push
    std::map<HashT, time_point> m_expiry;  // own hash -> end of its hold-off
};

} // namespace ltc
