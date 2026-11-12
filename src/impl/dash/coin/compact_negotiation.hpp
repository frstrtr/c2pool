// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// #968a: BIP 152 sendcmpct negotiation and high-bandwidth peer selection
// (dashcore net_processing.cpp: SENDCMPCT branch of ProcessMessage,
// MaybeSetPeerAsAnnouncingHeaderAndIDs).
//
// INBOUND sendcmpct: dashcore accepts version 1 only. The first one latches
// fProvidesHeaderAndIDs / fSupportsDesiredCmpctVersion, and every accepted
// sendcmpct overwrites fPreferHeaderAndIDs with the announce flag. Any other
// version is ignored and leaves the state as it was. supports_compact() is what
// the client checks before it asks a peer for a block as MSG_CMPCT_BLOCK and
// before it asks a peer for high-bandwidth push (dashcore
// m_provides_cmpctblocks).
//
// OUTBOUND: dashcore sends sendcmpct(0, 1) to every peer at VERACK, because a
// dashcore node serves cmpctblock / getblocktxn for every block it holds. We
// do not send that blanket message. A sendcmpct of version 1 tells the peer we
// provide compact blocks, and a peer that thinks so may put us in one of its
// three high-bandwidth slots (its MaybeSetPeerAsAnnouncingHeaderAndIDs, run
// when a block we delivered validates) and then wait for us to push new blocks
// as cmpctblock, which we never do: we are a pool node and do not relay
// blocks. So the only sendcmpct we send is the one that asks for something:
//
//   * sendcmpct(1, 1) to at most three peers that served us a new tip block
//     (CompactHighBandwidthSet below, the receiver half of
//     MaybeSetPeerAsAnnouncingHeaderAndIDs), so they push cmpctblock to us as
//     soon as they have validated the header and PoW of a new block;
//   * sendcmpct(0, 1) to the peer that falls out of that set.
//
// A peer we asked for high-bandwidth push also learns we provide compact
// blocks, so it can still select us after we deliver it a block, which only
// happens when we broadcast a block the pool won. For that case the client
// serves getdata(MSG_CMPCT_BLOCK) and getblocktxn for the few recent blocks it
// holds (CoinClient serve_* in p2p_client.hpp). We are always an INBOUND peer
// to them, and dashcore never lets an inbound high-bandwidth peer push out its
// last outbound one, so the cost to that peer is bounded to one of its three
// slots until a different peer delivers a block first.
//
// Pure logic, keyed by peer string like CompactBlockReceiver, so the KAT
// drives it without sockets.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <map>
#include <optional>
#include <string>

namespace dash {
namespace coin {

// dashcore src/net_processing.cpp / version.h (Dash values).
inline constexpr uint64_t CMPCTBLOCKS_VERSION      = 1;
inline constexpr uint32_t SHORT_IDS_BLOCKS_VERSION = 70209;

// The common protocol version must reach SHORT_IDS_BLOCKS_VERSION before
// either side may use BIP 152 messages (dashcore sends nothing below it).
inline bool compact_blocks_version_ok(uint32_t our_version, uint32_t peer_version)
{
    const uint32_t common = our_version < peer_version ? our_version : peer_version;
    return common >= SHORT_IDS_BLOCKS_VERSION;
}

class CompactPeerNegotiation
{
public:
    struct PeerState {
        bool provides_header_and_ids{false};   // dashcore fProvidesHeaderAndIDs
        bool prefer_header_and_ids{false};     // dashcore fPreferHeaderAndIDs
        bool supports_desired_version{false};  // dashcore fSupportsDesiredCmpctVersion
    };

    // Returns true when the message was accepted (version 1).
    bool on_sendcmpct(const std::string& peer, bool announce, uint64_t version)
    {
        if (version != CMPCTBLOCKS_VERSION)
            return false;
        auto& st = m_peers[peer];
        st.provides_header_and_ids  = true;
        st.prefer_header_and_ids    = announce;
        st.supports_desired_version = true;
        return true;
    }

    void on_disconnect(const std::string& peer) { m_peers.erase(peer); }
    void clear() { m_peers.clear(); }

    PeerState state(const std::string& peer) const
    {
        auto it = m_peers.find(peer);
        return it == m_peers.end() ? PeerState{} : it->second;
    }

    bool supports_compact(const std::string& peer) const
    {
        return state(peer).supports_desired_version;
    }

    // The peer asked US for high-bandwidth push (it sent sendcmpct(1, 1)).
    bool prefers_compact_announce(const std::string& peer) const
    {
        return state(peer).prefer_header_and_ids;
    }

    size_t peer_count() const { return m_peers.size(); }

private:
    std::map<std::string, PeerState> m_peers;
};

// dashcore lNodesAnnouncingHeaderAndIDs + MaybeSetPeerAsAnnouncingHeaderAndIDs:
// the (at most three) peers we asked to push new blocks as cmpctblock.
// Every one of our peers is OUTBOUND (we only dial), so dashcore's inbound
// branch (keep the last outbound slot when an inbound peer is added) never
// applies here.
class CompactHighBandwidthSet
{
public:
    // BIP 152: "we only get 3 of our peers to announce blocks using compact
    // encodings".
    static constexpr size_t MAX_PEERS = 3;

    struct Change {
        std::optional<std::string> announce_on;    // send sendcmpct(1, 1)
        std::optional<std::string> announce_off;   // send sendcmpct(0, 1)
    };

    // A block this peer delivered became our new tip. The caller has already
    // checked that the peer supports compact blocks (m_provides_cmpctblocks).
    // An existing member moves to the back (most recent) and nothing is sent.
    Change select(const std::string& peer)
    {
        Change c;
        auto it = std::find(m_peers.begin(), m_peers.end(), peer);
        if (it != m_peers.end()) {
            m_peers.erase(it);
            m_peers.push_back(peer);
            return c;
        }
        m_peers.push_back(peer);
        c.announce_on = peer;
        if (m_peers.size() > MAX_PEERS) {
            c.announce_off = m_peers.front();
            m_peers.pop_front();
        }
        return c;
    }

    void on_disconnect(const std::string& peer)
    {
        m_peers.erase(std::remove(m_peers.begin(), m_peers.end(), peer), m_peers.end());
    }
    void clear() { m_peers.clear(); }

    bool contains(const std::string& peer) const
    {
        return std::find(m_peers.begin(), m_peers.end(), peer) != m_peers.end();
    }
    size_t size() const { return m_peers.size(); }
    const std::deque<std::string>& peers() const { return m_peers; }

private:
    std::deque<std::string> m_peers;   // front = oldest
};

} // namespace coin
} // namespace dash
