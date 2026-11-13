// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// #968a: BIP 152 sendcmpct state (dashcore net_processing.cpp SENDCMPCT branch
// of ProcessMessage, 4291-4306).
//
// INBOUND sendcmpct: dashcore accepts version 1 only. The first one latches
// fProvidesHeaderAndIDs / fSupportsDesiredCmpctVersion, and every accepted
// sendcmpct overwrites fPreferHeaderAndIDs with the announce flag. Any other
// version is ignored and leaves the state as it was. supports_compact() is
// what the client checks before it asks a peer for a block as
// MSG_CMPCT_BLOCK (dashcore HeadersDirectFetchBlocks reads the same bit,
// m_provides_cmpctblocks, net_processing.cpp:3254). A dashcore peer sends us
// sendcmpct(0, 1) at VERACK (4224-4231).
//
// OUTBOUND: we send NO sendcmpct at all.
//   * Receiving does not need it. dashcore answers getdata(MSG_CMPCT_BLOCK)
//     in ProcessGetBlockData (2741; the MSG_CMPCT_BLOCK branch 2870-2884)
//     with no check of anything we sent: the only gates are that it holds
//     the block, CanDirectFetch() and the MAX_CMPCTBLOCK_DEPTH window. The
//     state our sendcmpct would set (m_provides_cmpctblocks /
//     m_requested_hb_cmpctblocks, 4300-4301) is read only where that peer
//     would fetch compact blocks FROM us (3254), choose us as a
//     high-bandwidth announcer (1370), or push cmpctblock TO us (2263, 6430,
//     6492). Checked live: a v24.0.0 testnet node answered our
//     getdata(MSG_CMPCT_BLOCK) with a cmpctblock on a connection where we
//     never sent sendcmpct.
//   * No high-bandwidth mode. A high-bandwidth peer pushes cmpctblock from
//     NewPoWValidBlock (validation.cpp:4843), after the header and PoW checks
//     but BEFORE the block is connected, so the block is not known to be
//     valid. Our bodies come only from getdata for blocks a peer announced
//     by inv, which it sends after connecting the block.
//   * Nothing to serve. A sendcmpct v1 tells the peer we provide compact
//     blocks; we serve none (we hold no block store), so we never claim it.
//
// Pure logic, keyed by peer string like CompactBlockReceiver, so the KAT
// drives it without sockets.

#include <cstddef>
#include <cstdint>
#include <map>
#include <string>

namespace dash {
namespace coin {

// dashcore src/net_processing.cpp CMPCTBLOCKS_VERSION.
inline constexpr uint64_t CMPCTBLOCKS_VERSION = 1;

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
    // Recorded only; we never push.
    bool prefers_compact_announce(const std::string& peer) const
    {
        return state(peer).prefer_header_and_ids;
    }

    size_t peer_count() const { return m_peers.size(); }

private:
    std::map<std::string, PeerState> m_peers;
};

// --embedded-compact-blocks[=false] (default ON). Process-wide switch read on
// every body request and every cmpctblock, so a canary can turn compact
// blocks off without a rebuild: OFF, every body is fetched as MSG_BLOCK and
// any cmpctblock is dropped unprocessed. Function-local static so the header
// stays dependency-free and a KAT can flip it (same shape as the getmnlistd
// tracker flag).
inline bool& embedded_compact_blocks_flag_ref() { static bool f = true; return f; }
inline bool  embedded_compact_blocks_enabled() { return embedded_compact_blocks_flag_ref(); }
inline void  set_embedded_compact_blocks_enabled(bool v) { embedded_compact_blocks_flag_ref() = v; }

} // namespace coin
} // namespace dash
