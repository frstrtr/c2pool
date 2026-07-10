// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// DASH sharechain minimum-protocol-version gate (v36 min-proto ratchet, #643).
//
// SCOPE: a parameterized, per-instance policy for the reject-if-proto<floor
// decision at the version handshake. This leaf carries ONLY the policy object
// and its accept/reject predicate; the LIVE call site in NodeImpl::handle_version
// is the reception/handshake slice (B) and is deliberately out of scope here.
//
// RATCHET SEMANTICS (operator #643, integrator-concurred 2026-07-06 option a):
//   - The floor defaults to dash::SharechainConfig::MINIMUM_PROTOCOL_VERSION
//     (1700), which is the current DASH oracle accept-all floor. At the default
//     this gate is a NO-OP: a peer advertising protocol=1700 MUST be accepted.
//   - The floor is a per-instance MEMBER, not a baked-in constant, so the actual
//     v36 ratchet value is a one-line operator knob set at G2-migration time.
//     This leaf commits NO premature v36 constant (DASH share ver 16->36 is
//     older-than-v35; the floor is a chosen constant, not an oracle-derived one).
//
// ISOLATION: fenced to src/impl/dash/. Touches NO shared bitcoin_family / core
// version-handshake types (per-coin isolation primitive boundary).

#include <cstdint>

#include "config_pool.hpp"

namespace dash
{

// Per-instance minimum-protocol-version policy. Default-constructed it holds the
// oracle accept-all floor (1700) and accepts every peer at or above it.
struct MinProtocolGate
{
    // The rejection floor. A peer is admitted iff peer_protocol >= min_version.
    uint32_t min_version = SharechainConfig::MINIMUM_PROTOCOL_VERSION;

    MinProtocolGate() = default;
    explicit MinProtocolGate(uint32_t floor) : min_version(floor) {}

    // reject-if-proto<floor predicate. True => admit the peer.
    // At the default floor (1700) this is accept-all for every real DASH peer.
    [[nodiscard]] bool accepts(uint32_t peer_protocol) const
    {
        return peer_protocol >= min_version;
    }

    // Convenience inverse for handshake sites that branch on rejection.
    [[nodiscard]] bool rejects(uint32_t peer_protocol) const
    {
        return !accepts(peer_protocol);
    }
};

} // namespace dash