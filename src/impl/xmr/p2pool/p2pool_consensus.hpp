// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/p2pool/p2pool_consensus.hpp
//
// WHICH SIDECHAIN, and the handful of constants that answer it.
//
// P2Pool (SChernykh/p2pool) is a decentralised Monero pool whose miners share a
// PPLNS window carried on its OWN peer-to-peer sidechain -- a binary protocol
// over TCP that is NOT Monero levin and shares nothing with it. A node picks a
// sidechain by a 32-byte CONSENSUS ID, which is never sent on the wire: it is
// folded into the handshake hash (p2pool_handshake.hpp) and into every
// sidechain block's own id (p2pool_block.hpp), so two nodes on different
// sidechains simply fail to agree and hang up. That is the whole membership
// test, and it is why this file is the first one to read.
//
// The three public sidechains derive their consensus id from a NUL-separated
// config tuple
//
//     network "\0" pool_name "\0" password "\0"
//     target_block_time "\0" min_difficulty "\0" pplns_window "\0" uncle_penalty "\0"
//
// hashed through RandomX -- but upstream hardcodes the three results rather
// than running RandomX at start-up, and so do we. The bytes below are copied
// from p2pool's src/side_chain.cpp (default/mini/nano_consensus_id) and are
// pinned by the parser KAT, which recomputes a real captured block's id against
// them: a wrong consensus id there produces a mismatch, so the constant cannot
// rot silently.
//
// A CORRECTION TO A COMMON BELIEF, worth writing down because it changed how
// this observer was run: "mini" is NOT a faster chain. Both `default` and
// `mini` set target_block_time = 10 seconds and min_difficulty = 100000; the
// only differences are the pool name in the tuple (hence a different consensus
// id, hence a different chain) and the hashrate that shows up, which moves the
// DIFFICULTY, not the cadence. `nano` is the one with a different cadence (30
// seconds) and a different uncle penalty (10%). Observing main rather than mini
// therefore costs nothing in block rate.
//
// SCOPE FENCE (standing XMR-lane rule): everything under src/impl/xmr/. This
// tree observes a foreign network; it is not part of the v37 share-chain
// record, activates no consensus, and does not touch src/sharechain/.
//
// Header-only, STL only.
// ---------------------------------------------------------------------------
#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace c2pool::xmr::p2pool {

using ConsensusId = std::array<std::uint8_t, 32>;

enum class Sidechain : std::uint8_t {
    Main = 0,   // pool name "default", p2p port 37889
    Mini = 1,   // pool name "mini",    p2p port 37888
    Nano = 2,   // pool name "nano",    p2p port 37890
};

inline const char* to_string(Sidechain s) noexcept {
    switch (s) {
        case Sidechain::Main: return "main";
        case Sidechain::Mini: return "mini";
        case Sidechain::Nano: return "nano";
    }
    return "?";
}

// p2pool src/side_chain.cpp :: default_consensus_id
inline constexpr ConsensusId kConsensusMain{{
    34, 175, 126, 231, 181,  11, 104, 146, 227, 153, 218, 107,  44, 108,  68,  39,
   178,  81,   4, 212, 169,   4, 142,   0, 177, 110, 157, 240,  68,   7, 249,  24
}};

// p2pool src/side_chain.cpp :: mini_consensus_id
inline constexpr ConsensusId kConsensusMini{{
    57, 130, 201,  26, 149, 174, 199, 250,  66,  80, 189,  18, 108, 216, 194, 220,
   136,  23,  63,  24,  64, 113, 221,  44, 219,  86,  39, 163,  53,  24, 126, 196
}};

// p2pool src/side_chain.cpp :: nano_consensus_id
inline constexpr ConsensusId kConsensusNano{{
   171, 248, 206, 148, 210, 226, 114,  99, 250, 145, 221,  96,  13, 216,  23,  63,
   104,  53, 129, 168, 244,  80, 141, 138, 157, 250,  50,  54,  37, 189,   5,  89
}};

inline const ConsensusId& consensus_id(Sidechain s) noexcept {
    switch (s) {
        case Sidechain::Mini: return kConsensusMini;
        case Sidechain::Nano: return kConsensusNano;
        case Sidechain::Main: break;
    }
    return kConsensusMain;
}

// p2pool src/p2p_server.h :: DEFAULT_P2P_PORT{,_MINI,_NANO}
inline constexpr std::uint16_t kPortMain = 37889;
inline constexpr std::uint16_t kPortMini = 37888;
inline constexpr std::uint16_t kPortNano = 37890;

inline std::uint16_t default_port(Sidechain s) noexcept {
    switch (s) {
        case Sidechain::Mini: return kPortMini;
        case Sidechain::Nano: return kPortNano;
        case Sidechain::Main: break;
    }
    return kPortMain;
}

// The DNS seeds p2pool itself bootstraps from (src/p2p_server.cpp). Resolved,
// never trusted: a seed answer is an address to dial, and everything that
// matters afterwards is authenticated by the consensus id in the handshake.
inline std::vector<std::string> seed_hosts(Sidechain s) {
    switch (s) {
        case Sidechain::Mini: return {"seeds-mini.p2pool.io", "mini.p2poolpeers.net"};
        case Sidechain::Nano: return {"seeds-nano.p2pool.io", "nano.p2poolpeers.net"};
        case Sidechain::Main: break;
    }
    return {"seeds.p2pool.io", "main.p2poolpeers.net"};
}

// Sidechain parameters, for the read model's derived numbers. These are the
// tuple that GENERATES the consensus ids above, so they cannot drift from the
// chain without the handshake failing first.
struct SidechainParams {
    std::uint64_t target_block_time = 10;      // seconds
    std::uint64_t min_difficulty    = 100000;
    std::uint64_t pplns_window      = 2160;    // blocks
    std::uint64_t uncle_penalty     = 20;      // percent
};

inline SidechainParams params_of(Sidechain s) noexcept {
    SidechainParams p{};
    if (s == Sidechain::Nano) { p.target_block_time = 30; p.uncle_penalty = 10; }
    return p;
}

// p2pool src/pool_block.h :: MAX_BLOCK_SIZE -- 128 KiB minus the 5-byte
// BLOCK_RESPONSE header. Every length-prefixed message body is bounded by it.
inline constexpr std::uint32_t kMaxBlockSize = 128u * 1024u - 5u;

// p2pool src/p2p_server.h :: PROTOCOL_VERSION_1_4 / SUPPORTED_PROTOCOL_VERSION.
inline constexpr std::uint32_t kProtocolVersion14 = 0x00010004u;

// p2pool src/pool_block.h :: MAX_UNCLES_PER_BLOCK, MAX_SIDECHAIN_HEIGHT,
// MERGE_MINING_MAX_CHAINS, LOG2_MERGE_MINING_MAX_CHAINS.
inline constexpr std::uint64_t kMaxUnclesPerBlock   = 5;
inline constexpr std::uint64_t kMaxSidechainHeight  = 31556952000ull;
inline constexpr std::uint64_t kMergeMiningMaxChains = 256;
inline constexpr std::uint8_t  kLog2MergeMiningMaxChains = 8;

// p2pool src/pool_block.h :: BASE_BLOCK_REWARD (0.6 XMR) and MAX_OUTPUT_VALUE
// (the reward is stored in a 56-bit field).
inline constexpr std::uint64_t kBaseBlockReward = 600000000000ull;
inline constexpr std::uint64_t kMaxOutputValue  = (1ull << 56) - 1;

} // namespace c2pool::xmr::p2pool
