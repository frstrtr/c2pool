// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// ─────────────────────────────────────────────────────────────────────────────
// LocalAddrTable + SelfNonceRegistry — the BIP-110 coin-p2p SELF-ADDRESS /
// SELF-CONNECT primitives (Bitcoin Knots net.cpp port, BLAKE2b-scoped).
//
// WHY (the reachability root cause, live-verified on contabo 2026-09-03):
// The InboundListener is up on :8333 and reachable, but after ~16 min ZERO
// inbound connections arrive. Listening is necessary but NOT sufficient — the
// fork network never LEARNS our address. A node becomes dialable only once peers
// record our reachable IP:port and gossip it into their addrman. We only DIAL
// OUT (ephemeral source ports); nobody knows we listen on :8333, so nobody
// dials us. The fix is self-address advertisement, which needs two Knots
// primitives this header provides:
//
//   LocalAddrTable  — the port of Knots net.cpp mapLocalHost / AddLocal /
//     SeenLocal / GetLocalAddress. It answers "what is OUR reachable address?"
//     Two sources, in priority order:
//       (1) an operator-pinned --coin-externalip (authoritative, like Knots
//           -externalip / AddLocal(LOCAL_MANUAL)),
//       (2) peer-echo scoring (Knots SeenLocal): each fork peer echoes the
//           address it saw us dial FROM in its version.addr_to; on contabo the
//           public IP is interface-bound (no NAT) so that echoed IP IS our
//           reachable IP. We score by how many distinct peers agree and take the
//           winner. The port is ALWAYS substituted for our real listen port
//           (8333) — the echoed port is our EPHEMERAL outbound source port and
//           advertising it would point peers at a dead port (the #1 trap).
//
//   SelfNonceRegistry — the port of Knots net.cpp CConnman self-connect guard
//     (each version carries a random nonce; a version whose nonce equals one WE
//     sent means we dialed ourselves). Once self-advertise lands, our own
//     routable addr is gossiped back, banked in our addrman, drawn by the dial
//     planner, and our listener would happily handshake our own dialer (both
//     sides pass the NODE_BLAKE2B gate) → addrman self-poison + a wasted slot.
//     This drops that at the version handler on BOTH the outbound and inbound
//     arms.
//
// SCOPE: network-identity/reachability ONLY. Nothing here touches consensus,
// reward, share-validity, or the wire params — addr/version are free p2p. Both
// types are thread-safe (a std::mutex) so the shared instances can be read from
// the io thread (version/verack handlers) without a data race.
// ─────────────────────────────────────────────────────────────────────────────

#include <core/netaddress.hpp>   // NetService, is_routable()

#include <cstdint>
#include <deque>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <unordered_set>

namespace bip110
{
namespace coin
{
namespace p2p
{

// Knots net.cpp mapLocalHost + SeenLocal + GetLocalAddress, BLAKE2b-scoped.
// Shared (one instance in main) across the primary NodeP2P, every fan-out slot,
// and the InboundListener, so a peer echo learned on any arm advertises on all.
class LocalAddrTable
{
public:
    explicit LocalAddrTable(uint16_t listen_port) : m_listen_port(listen_port) {}

    // Knots -externalip / AddLocal(LOCAL_MANUAL): an operator-pinned reachable
    // address. Authoritative — always wins over peer-echo. Routable only.
    void set_external(const std::string& ip)
    {
        if (!is_routable(ip)) return;
        std::lock_guard<std::mutex> lk(m_mutex);
        m_external = NetService{ip, m_listen_port};
    }

    // Knots SeenLocal(): a fork peer echoed OUR address back in its version
    // addr_to. Bump the vote for that IP. Routable only (never advertise an
    // RFC1918/loopback echo — a NAT-mangled or LAN echo must not be gossiped).
    // The port is NOT taken from the echo — best_local() always substitutes the
    // real listen port.
    void seen_local(const std::string& echoed_ip)
    {
        if (!is_routable(echoed_ip)) return;
        std::lock_guard<std::mutex> lk(m_mutex);
        ++m_votes[echoed_ip];
    }

    // Knots GetLocalAddress(): our best reachable address, or nullopt if we do
    // not yet know one (no --coin-externalip and no routable peer echo). When
    // nullopt the callers advertise nothing / an empty addr_from — NEVER a guess
    // (a wrong self-addr poisons every peer that learns it).
    std::optional<NetService> best_local() const
    {
        std::lock_guard<std::mutex> lk(m_mutex);
        if (m_external) return m_external;
        const std::string* best = nullptr;
        uint32_t best_votes = 0;
        for (const auto& [ip, votes] : m_votes) {
            if (votes > best_votes) { best_votes = votes; best = &ip; }
        }
        if (!best) return std::nullopt;
        return NetService{*best, m_listen_port};
    }

    uint16_t listen_port() const { return m_listen_port; }

private:
    mutable std::mutex                        m_mutex;
    uint16_t                                  m_listen_port;
    std::optional<NetService>                 m_external;
    std::unordered_map<std::string, uint32_t> m_votes;   // echoed IP -> vote count
};

// Knots CConnman self-connect nonce guard. Every version we SEND records its
// nonce here; every version we RECEIVE is checked against it. A match means the
// peer on the other end is us (we dialed our own listener), so the handshake is
// dropped. Bounded ring so a long-lived node cannot grow it without bound.
class SelfNonceRegistry
{
public:
    explicit SelfNonceRegistry(size_t capacity = 256) : m_capacity(capacity) {}

    void record(uint64_t nonce)
    {
        if (nonce == 0) return;   // 0 is never treated as a self-nonce
        std::lock_guard<std::mutex> lk(m_mutex);
        if (m_set.insert(nonce).second) {
            m_order.push_back(nonce);
            while (m_order.size() > m_capacity) {
                m_set.erase(m_order.front());
                m_order.pop_front();
            }
        }
    }

    bool is_self(uint64_t nonce) const
    {
        if (nonce == 0) return false;
        std::lock_guard<std::mutex> lk(m_mutex);
        return m_set.count(nonce) != 0;
    }

private:
    mutable std::mutex               m_mutex;
    size_t                           m_capacity;
    std::unordered_set<uint64_t>     m_set;
    std::deque<uint64_t>             m_order;
};

} // namespace p2p
} // namespace coin
} // namespace bip110
