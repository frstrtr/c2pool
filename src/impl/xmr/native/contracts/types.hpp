// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/native/contracts/types.hpp
//
// Wave 0 of the native-minimal Monero embedded node: the shared VALUE TYPES
// every native-node component (C1 levin P2P, C2 chain-state index, C3 relayed
// txpool, C4 template source, C5 block relay, C6 parity oracle) exchanges.
//
// Header-only, STL only plus the existing lane value types from
// src/impl/xmr/node/xmr_node_types.hpp. Nothing here allocates a thread, opens
// a socket, or hashes anything: this file is the collision fence for the
// parallel implementation waves, not an implementation.
//
// SCOPE FENCE (standing XMR-lane isolation rule): everything under
// src/impl/xmr/. This tree is a WORK SOURCE for the pool, not part of the v37
// share-chain record: no file here is consensus-activating for v37, and
// src/sharechain/v37 is not touched.
//
// PINNED DECISION D-NS (one namespace root): every native-node type and
// interface lives in `c2pool::xmr::native`. The two neighbouring roots are
// reached through the aliases declared below, never by re-opening them.
//
// A change to any signature in this contracts/ family after Wave 0 requires an
// explicit contract-amendment commit touching only contracts/ and the affected
// fakes.
// ---------------------------------------------------------------------------
#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "impl/xmr/node/xmr_node_types.hpp"

// Forward-declare the settlement-submit namespace so the alias below is legal
// without dragging c2pool/v37/xmr/xmr_live_submit.hpp (and its transport
// dependencies) into every contracts consumer. Components that actually touch
// submit::BlockCandidate include that header themselves.
namespace c2pool::v37n::xmr::submit {}

namespace c2pool::xmr::native {

// --- D-NS namespace aliases --------------------------------------------------
// `node::` = the existing lane value types (Hash, Difficulty128, MinerData,
// ChainMainBlock, MainchainEvent, TxBacklogEntry). `submit::` = the existing
// live-submit surface reused by C5 (BlockCandidate / SubmitOutcome).
namespace node   = ::c2pool::xmr::node;
namespace submit = ::c2pool::v37n::xmr::submit;

using Hash = node::Hash;
using U128 = node::Difficulty128;

// --- 128-bit helpers ---------------------------------------------------------
// Cumulative difficulty is a 128-bit running sum; fork-choice compares it and
// the index accumulates it. Kept here so every component uses ONE definition.
inline constexpr U128 u128_add(const U128& a, const U128& b) noexcept {
    U128 r{};
    r.lo = a.lo + b.lo;
    r.hi = a.hi + b.hi + (r.lo < a.lo ? 1u : 0u);
    return r;
}
inline constexpr bool u128_less(const U128& a, const U128& b) noexcept {
    return (a.hi != b.hi) ? (a.hi < b.hi) : (a.lo < b.lo);
}
// Strictly-greater is the ONLY switch condition for fork-choice; equal
// cumulative difficulty resolves by D-14 PREFER-OWN at the index, never here.
inline constexpr bool u128_greater(const U128& a, const U128& b) noexcept {
    return u128_less(b, a);
}

// --- peer identity -----------------------------------------------------------
// Opaque to everything except C1; carried through so C2/C3 can attribute a
// fault back to the connection that supplied the data.
struct PeerRef {
    std::uint64_t peer_id  = 0;   // levin peer_id, stable for the connection
    std::string   addr;           // "ip:port", for logs and ban keys
    std::uint32_t asn_hint = 0;   // 0 = unknown; feeds the ASN-diversity guard
};

// --- transaction / block carriers -------------------------------------------
// A tx as it arrives from the wire. `pruned` blobs carry the prefix + the rct
// base only (D-4: chain sync and completion always request prune=true), which
// is enough for weights (consensus/xmr_tx_weight.hpp), key images and fees.
struct TxBlobEntry {
    std::vector<std::uint8_t> blob;
    Hash                      prunable_hash{};  // zero when !pruned
    bool                      pruned = false;
};

// A block plus its transactions, as returned by GET_OBJECTS (2004) or pushed by
// NOTIFY_NEW_BLOCK / NOTIFY_NEW_FLUFFY_BLOCK (2008/2001).
//
// HINT FIELD (must-fix c, same rule as ChainEntry): `block_weight_claimed_hint`
// is the peer's claim. It is a scheduling hint only (buffer sizing, progress
// display). The index RECOMPUTES the weight from the blobs and never trusts
// this number for consensus.
struct BlockEntry {
    std::vector<std::uint8_t> block_blob;
    std::vector<TxBlobEntry>  txs;
    std::uint64_t             block_weight_claimed_hint = 0;  // HINT, recomputed
    bool                      pruned = false;
};

// A span of the peer's chain, from RESPONSE_CHAIN_ENTRY (2007). ids[0] is the
// last id we already know (the splice point).
//
// HINT FIELDS (must-fix c): `cumulative_difficulty_hint` and
// `weights_claimed_hint` are the PEER'S CLAIM about its branch. C2 recomputes
// both from verified blocks (difficulty from its own 735-row window, weights
// from the pruned bodies) and uses these only to prioritise which peer to
// fetch from and to detect an obviously lying peer early. Fork-choice NEVER
// switches on a hint.
struct ChainEntry {
    std::uint64_t              start_height = 0;
    std::uint64_t              total_height = 0;
    U128                       cumulative_difficulty_hint{};  // HINT, recomputed
    std::vector<Hash>          ids;                           // ids[0] is known to us
    std::vector<std::uint64_t> weights_claimed_hint;          // HINT, recomputed
    std::vector<std::uint8_t>  first_block;                   // optional, may be empty
};

// The peer's advertised sync state (HANDSHAKE 1001 / TIMED_SYNC 1002).
struct PeerSyncData {
    std::uint64_t current_height = 0;   // == their tip height + 1
    U128          cumulative_difficulty{};
    Hash          top_id{};
    std::uint8_t  top_version  = 0;
    std::uint32_t pruning_seed = 0;
    std::uint32_t support_flags = 0;
};

// Why a peer is being penalised. BadPow is the only 24 h ban by itself.
enum class PeerFault : std::uint8_t {
    BadPow = 0,
    BadData,
    BadChainEntry,
    Unresponsive,
    VersionMismatch,
};

inline const char* to_string(PeerFault f) noexcept {
    switch (f) {
        case PeerFault::BadPow:          return "BadPow";
        case PeerFault::BadData:         return "BadData";
        case PeerFault::BadChainEntry:   return "BadChainEntry";
        case PeerFault::Unresponsive:    return "Unresponsive";
        case PeerFault::VersionMismatch: return "VersionMismatch";
    }
    return "?";
}

// --- template inputs ---------------------------------------------------------
// The five chain-state windows a Monero template consumes, in one snapshot.
// C2 produces it; C3 derives its fee context from it (D-11); C4 turns it into
// node::MinerData for the untouched option-B assembler.
struct TemplateInputs {
    std::uint8_t  major_version = 0;
    std::uint8_t  minor_version = 0;
    std::uint64_t height        = 0;      // the block being mined (tip + 1)
    Hash          prev_id{};
    Hash          seed_hash{};
    std::optional<Hash> next_seed_hash;   // set inside the 64-block epoch lag

    U128          difficulty{};           // next difficulty over the 735-row window
    std::uint64_t median_weight = 0;      // short-window effective median
    std::uint64_t block_weight_limit = 0;
    std::uint64_t long_term_effective_median_weight = 0;
    std::uint64_t already_generated_coins = 0;
    std::uint64_t median_timestamp = 0;   // 60-block median, template lower bound
    std::uint64_t expected_base_reward = 0;
    std::uint64_t fee_quantization_mask = 1;

    std::uint64_t epoch_seq = 0;          // bumps on every tip change
    bool          synced    = false;      // fail-closed: no template when false

    // tx_backlog is deliberately left EMPTY: the backlog comes from C3 through
    // ITxpoolSnapshot, so this conversion stays a pure function of chain state.
    node::MinerData to_miner_data() const {
        node::MinerData m;
        m.major_version = major_version;
        m.height        = height;
        m.prev_id       = prev_id;
        m.seed_hash     = seed_hash;
        m.difficulty    = difficulty;
        m.median_weight = median_weight;
        m.already_generated_coins = already_generated_coins;
        m.median_timestamp        = median_timestamp;
        return m;
    }
};

// --- per-block transaction events -------------------------------------------
// Emitted by C2 alongside MainchainEvent; consumed by C3 (drop mined ids, evict
// key-image conflicts, return disconnected bodies to the pool).
//
// BEST-EFFORT FIELD (must-fix d): on Disconnected, `tx_blobs` carries the
// bodies of the rolled-back transactions so C3 can put them back in the pool.
// It is BEST EFFORT and may be short, empty, or contain pruned blobs: the
// index keeps full bodies only while it has them (D-4 syncs pruned). C3 MUST
// treat a missing body as "gone" and re-learn the tx from relay, and MUST NOT
// use tx_blobs to decide anything about validity. `tx_blobs_complete` says
// whether every hash in tx_hashes has a matching full body at the same index.
struct BlockTxEvent {
    enum class Kind : std::uint8_t { Connected = 0, Disconnected = 1 };

    Kind          kind   = Kind::Connected;
    std::uint64_t height = 0;
    Hash          block_id{};

    std::vector<Hash> tx_hashes;    // both kinds; excludes the coinbase
    std::vector<Hash> key_images;   // Connected only (D-12), from the prefixes

    std::vector<std::vector<std::uint8_t>> tx_blobs;  // Disconnected, BEST EFFORT
    bool tx_blobs_complete = false;                   // see the note above
};

// --- index / sync telemetry --------------------------------------------------
// One struct, read by the dashboard, the readiness gate and the parity oracle.
enum class RandomXMode : std::uint8_t { Disabled = 0, LightJit = 1, LightInterpreter = 2 };

struct SyncState {
    std::uint64_t anchor_height    = 0;  // trust root; nothing below it is reorgable
    std::uint64_t verified_frontier = 0; // highest fully L4-verified height
    std::uint64_t header_frontier   = 0; // highest height with an id, maybe unverified
    std::uint64_t cohort_height     = 0; // median of the peer cohort's advertised tip
    U128          best_cumulative_difficulty{};

    std::uint64_t rows = 0;       // populated rows retained (D-9: 2048)
    std::uint64_t alt_rows = 0;
    std::uint64_t orphans = 0;
    std::uint64_t reorgs  = 0;

    std::uint64_t pow_verified = 0;
    std::uint64_t pow_failed   = 0;
    std::uint64_t seed_rekeys  = 0;
    std::uint64_t bans         = 0;
    std::uint64_t bytes_in     = 0;
    std::uint64_t bytes_out    = 0;

    RandomXMode randomx_mode = RandomXMode::Disabled;

    // Fail-closed: the template arm refuses to serve unless this is true.
    bool synced = false;
};

} // namespace c2pool::xmr::native
