// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/p2pool/p2pool_handshake.hpp
//
// THE HANDSHAKE, which is P2Pool's entire membership test.
//
// Both ends send an 8-byte random challenge plus an 8-byte peer id the moment
// the TCP connection is up. Each end then answers the OTHER end's challenge
// with
//
//     H = keccak256( challenge[8] || consensus_id[32] || salt[8] )
//
// and sends H together with its salt. The consensus id is NEVER transmitted --
// it is the shared secret that says which sidechain you are on -- so an end
// that has the wrong one produces an H the other end cannot reproduce, and the
// connection is closed. There is no version negotiation and no capability
// exchange in it at all: agreement on 32 bytes is the protocol.
//
// THE PROOF OF WORK, and the asymmetry that matters here. The end that DIALLED
// must additionally find a salt whose H clears a difficulty of 10000; the end
// that accepted is exempt. Upstream's test (P2PClient::on_handshake_solution)
// is the 128-bit product
//
//     umul128( last_u64_of(H), 10000, &high );  accept iff high == 0
//
// which is exactly "the top 64 bits of H, read little-endian, are below
// 2^64 / 10000". An observer always dials, so it always pays; at ~10^4 keccaks
// the cost is single-digit milliseconds and the loop below is the honest,
// unoptimised spelling of it. The bound is computed once as a constant rather
// than by emulating umul128, and the KAT pins the two forms against each other
// on the captured live challenge so the simplification cannot silently drift.
//
// WHY THIS FILE EXISTS SEPARATELY from p2pool_wire.hpp: the wire codec is pure
// STL and links nothing. This is the first file in the tree that needs a hash,
// and it takes the one the repository already has -- xmr::coin::keccak256, the
// vendored Monero keccak behind impl/xmr/coin/ that the settlement lane's
// coinbase KATs already pin. A second keccak in the same binary is a divergence
// waiting to happen.
//
// Header-only. STL plus xmr_coin.
// ---------------------------------------------------------------------------
#pragma once

#include <array>
#include <cstdint>
#include <cstring>
#include <vector>

#include "impl/xmr/p2pool/p2pool_consensus.hpp"
#include "impl/xmr/p2pool/p2pool_wire.hpp"
#include "impl/xmr/coin/xmr_keccak_midstate.hpp"   // xmr::coin::keccak256

namespace c2pool::xmr::p2pool {

using Challenge = std::array<std::uint8_t, kChallengeSize>;
using Hash32    = std::array<std::uint8_t, kHashSize>;

// keccak256( challenge || consensus_id || salt ). The one hash the handshake
// is made of, in both directions.
inline Hash32 handshake_hash(const Challenge& challenge,
                             const ConsensusId& consensus,
                             const Challenge& salt) {
    std::array<std::uint8_t, kChallengeSize + 32 + kChallengeSize> buf{};
    std::memcpy(buf.data(), challenge.data(), kChallengeSize);
    std::memcpy(buf.data() + kChallengeSize, consensus.data(), 32);
    std::memcpy(buf.data() + kChallengeSize + 32, salt.data(), kChallengeSize);

    const ::xmr::coin::Hash256 h = ::xmr::coin::keccak256(buf.data(), buf.size());
    Hash32 out{};
    std::memcpy(out.data(), h.data(), 32);
    return out;
}

// The last 8 bytes of H, little-endian -- upstream's `solution.u64()[3]`.
inline std::uint64_t handshake_pow_value(const Hash32& h) noexcept {
    std::uint64_t v = 0;
    for (int i = 7; i >= 0; --i) v = (v << 8) | h[static_cast<std::size_t>(24 + i)];
    return v;
}

// umul128(value, 10000, &high) == 0  <=>  value * 10000 < 2^128 / ... -- see the
// header comment: high is zero exactly when value < floor(2^64 / 10000).
inline constexpr std::uint64_t kHandshakePowBound =
        (~static_cast<std::uint64_t>(0)) / kChallengeDifficulty;

inline bool handshake_pow_ok(const Hash32& h) noexcept {
    return handshake_pow_value(h) <= kHandshakePowBound;
}

// The reference spelling, kept so the KAT can assert the two agree: the high
// half of the 128-bit product value * CHALLENGE_DIFFICULTY.
inline std::uint64_t handshake_pow_high(const Hash32& h) noexcept {
    const unsigned __int128 p =
            static_cast<unsigned __int128>(handshake_pow_value(h)) * kChallengeDifficulty;
    return static_cast<std::uint64_t>(p >> 64);
}

struct HandshakeSolution {
    Hash32        solution{};
    Challenge     salt{};
    std::uint64_t iterations = 0;
};

// Find a salt whose hash clears the dial-side difficulty. `salt_seed` makes the
// search deterministic for the KAT and random in production.
inline HandshakeSolution solve_handshake(const Challenge& peer_challenge,
                                         const ConsensusId& consensus,
                                         std::uint64_t salt_seed,
                                         std::uint64_t max_iterations = 1u << 22) {
    HandshakeSolution out{};
    std::uint64_t s = salt_seed;
    for (std::uint64_t i = 0; i < max_iterations; ++i, ++s) {
        Challenge salt{};
        std::uint64_t k = s;
        for (std::size_t b = 0; b < kChallengeSize; ++b) {
            salt[b] = static_cast<std::uint8_t>(k & 0xFFu);
            k >>= 8;
        }
        const Hash32 h = handshake_hash(peer_challenge, consensus, salt);
        if (handshake_pow_ok(h)) {
            out.solution   = h;
            out.salt       = salt;
            out.iterations = i + 1;
            return out;
        }
    }
    out.iterations = 0;   // exhausted -- caller treats as failure
    return out;
}

// Verify the peer's answer to OUR challenge. This is the membership test: a
// peer on a different sidechain cannot produce it. The dial-side PoW is NOT
// required of the peer here -- upstream exempts the accepting end, and this
// observer is always the dialling end.
inline bool verify_handshake(const Challenge& our_challenge,
                             const ConsensusId& consensus,
                             const Hash32& peer_solution,
                             const Challenge& peer_salt) {
    return handshake_hash(our_challenge, consensus, peer_salt) == peer_solution;
}

} // namespace c2pool::xmr::p2pool
