// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// #968a slice 2: BIP 152 sendcmpct negotiation (dashcore net_processing.cpp,
// VERACK and SENDCMPCT branches of ProcessMessage).
//
// Outbound, at verack: dashcore sends sendcmpct(announce=false, version=1)
// when the common protocol version is at least SHORT_IDS_BLOCKS_VERSION.
// announce=false is BIP 152 low-bandwidth mode: the peer keeps announcing by
// inv/headers and never pushes cmpctblock unasked, so sending it changes no
// block-fetch behaviour. It only tells the peer we understand compact blocks.
// Asking up to three peers for high-bandwidth push
// (MaybeSetPeerAsAnnouncingHeaderAndIDs) is a later slice.
//
// Inbound sendcmpct: dashcore accepts version 1 only. On the first one it
// latches fProvidesHeaderAndIDs and fSupportsDesiredCmpctVersion, and every
// accepted sendcmpct overwrites fPreferHeaderAndIDs with the announce flag.
// Any other version is ignored and leaves the state as it was.
//
// Pure logic, keyed by peer string like CompactBlockReceiver, so the KAT
// drives it without sockets.

#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <string>

namespace dash {
namespace coin {

// dashcore src/blockencodings.h / version.h (Dash values).
inline constexpr uint64_t CMPCTBLOCKS_VERSION      = 1;
inline constexpr uint32_t SHORT_IDS_BLOCKS_VERSION = 70209;

struct SendCmpctPayload
{
    bool     announce{false};
    uint64_t version{CMPCTBLOCKS_VERSION};
};

// What we send right after verack. nullopt = the common version is below
// SHORT_IDS_BLOCKS_VERSION, so dashcore sends nothing.
inline std::optional<SendCmpctPayload>
sendcmpct_on_verack(uint32_t our_version, uint32_t peer_version)
{
    const uint32_t common = our_version < peer_version ? our_version : peer_version;
    if (common < SHORT_IDS_BLOCKS_VERSION)
        return std::nullopt;
    return SendCmpctPayload{false, CMPCTBLOCKS_VERSION};
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

    PeerState state(const std::string& peer) const
    {
        auto it = m_peers.find(peer);
        return it == m_peers.end() ? PeerState{} : it->second;
    }

    bool supports_compact(const std::string& peer) const
    {
        return state(peer).supports_desired_version;
    }

    bool prefers_compact_announce(const std::string& peer) const
    {
        return state(peer).prefer_header_and_ids;
    }

    size_t peer_count() const { return m_peers.size(); }

private:
    std::map<std::string, PeerState> m_peers;
};

} // namespace coin
} // namespace dash
