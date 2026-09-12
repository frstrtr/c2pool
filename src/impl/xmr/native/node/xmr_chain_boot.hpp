// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/native/node/xmr_chain_boot.hpp
//
// M0: WHERE THE INDEX'S HISTORY IS ALLOWED TO START, and the gate that puts it
// there before a single peer message reaches the index.
//
// C2c's index refuses to judge anything until it has a trust root: `offer_block`
// parks a block whose parent it does not know, and `on_chain_entry` refuses an
// entry whose splice point `ids[0]` is not a block it already holds. Both are
// correct and both mean the SAME thing at boot: something has to seed row zero.
// There are two honest ways to do that and this file implements both.
//
// ANCHOR (the production path, plan M0..M5). `load_anchor()` gives a
// self-checked AnchorBundle -- a release-pinned or daemon-minted statement of
// what the chain looked like at H_a, carrying the five windows the consensus
// state needs -- and `ChainIndex::boot_from_anchor()` installs it. Nothing below
// H_a is ever verified or reorgable, which is what bounds a cold start to the
// anchor's AGE rather than the chain's LENGTH.
//
// GENESIS (the private-chain path). A regtest chain is younger than the anchor
// format can describe: `generate_anchor()` refuses any height below the
// 100 000-block long-term weight window, and a fresh fakechain has ten blocks.
// So on regtest the trust root is the block the whole network agrees on for
// free -- height 0 -- and the useful part is that it can be obtained WITHOUT
// A DAEMON RPC: the genesis id is pinned per network in chain_seeds.hpp (it has
// to be, it is the mandatory terminus of every locator we send), so the node
// asks its peer for that one id over levin `NOTIFY_REQUEST_GET_OBJECTS` and
// derives every number in the row from the bytes that come back.
//
// DERIVED, NOT TAKEN. The only thing this gate accepts from the wire is the
// BLOB. The id is recomputed from it and compared against the pinned genesis id
// (a peer that answers with different bytes is refused, not believed); the
// weight, the coinbase sum and therefore already_generated_coins come out of
// this repository's own parser. That is the same discipline the anchor loader
// applies to a bundle, and it is why the boot path cannot be used to walk the
// node onto a chain of the peer's choosing.
//
// WHY IT IS A GATE AND NOT A FUNCTION. The blob arrives as a normal
// `on_objects` callback, which the index would answer by parking a block with
// an unknown parent. So the boot sits IN FRONT of the index on the same
// (verify) thread, watches for the one id it is waiting for, seeds, and from
// then on is a transparent forwarder. Everything before the seed is dropped
// with a counter rather than queued: the sync driver re-asks, and holding an
// unbounded pre-boot backlog is the same unbounded allocation the queue caps
// exist to prevent.
//
// SCOPE FENCE (standing XMR-lane rule): everything under src/impl/xmr/. No
// consensus digest, no src/sharechain/v37.
//
// Header-only. STL only (plus the tree's own consensus primitives, which link
// xmr_coin for keccak and the tree hash).
// ---------------------------------------------------------------------------
#pragma once

#include <cstdint>
#include <mutex>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "impl/xmr/native/anchor/xmr_anchor_load.hpp"
#include "impl/xmr/native/chain/xmr_chain_index.hpp"
#include "impl/xmr/native/consensus/xmr_block_id.hpp"
#include "impl/xmr/native/consensus/xmr_block_parse.hpp"
#include "impl/xmr/native/consensus/xmr_hf_table.hpp"
#include "impl/xmr/native/contracts/chain_index.hpp"
#include "impl/xmr/native/contracts/serving.hpp"
#include "impl/xmr/native/contracts/types.hpp"

namespace c2pool::xmr::native::rt {

enum class BootMode : std::uint8_t {
    Genesis = 0,   // seed row 0 from the genesis blob, fetched over levin
    Anchor,        // seed from a loaded, self-checked AnchorBundle
};

inline const char* to_string(BootMode m) noexcept {
    switch (m) {
        case BootMode::Genesis: return "genesis";
        case BootMode::Anchor:  return "anchor";
    }
    return "?";
}

// ---------------------------------------------------------------------------
// The genesis row, derived from the genesis blob.
//
// difficulty and cumulative_difficulty are 1 because monerod's own
// `get_difficulty_for_next_block` answers 1 at db height 0 and the genesis
// block's stored cumulative difficulty is that same 1 -- which
// `get_block_header_by_height(0)` reports on every network, and which the
// parity oracle re-checks against the daemon at every sampled height, so a
// wrong constant here cannot pass unnoticed.
// ---------------------------------------------------------------------------
inline bool genesis_row_from_blob(const std::vector<std::uint8_t>& blob,
                                  const Hash& expected_id, ChainRow& out,
                                  std::string& why) {
    out = ChainRow{};
    why.clear();

    ParsedBlock pb;
    const BlockParseStatus ps = parse_block(blob, pb);
    if (ps != BlockParseStatus::Ok) {
        why = std::string("genesis blob does not parse: ") + to_string(ps);
        return false;
    }
    const BlockIdentity id = block_identity(blob.data(), pb);
    if (id.id != expected_id) {
        why = "the block a peer answered with is not this network's genesis block";
        return false;
    }
    CoinbaseFields cb;
    if (!parse_coinbase_fields(blob.data(), pb, cb)) {
        why = "genesis coinbase fields do not read back";
        return false;
    }
    if (cb.height != 0 || !pb.tx_hashes.empty()) {
        why = "the genesis block must be height 0 with no transactions";
        return false;
    }

    out.height           = 0;
    out.id               = id.id;
    out.prev_id          = pb.header.prev_id;
    out.timestamp        = pb.header.timestamp;
    out.major_version    = static_cast<std::uint8_t>(pb.header.major_version);
    out.minor_version    = static_cast<std::uint8_t>(pb.header.minor_version);
    out.block_weight     = pb.miner_tx.weight;
    out.long_term_weight = pb.miner_tx.weight;
    out.difficulty            = U128{1, 0};
    out.cumulative_difficulty = U128{1, 0};
    out.base_reward      = cb.output_sum;
    out.fees             = 0;
    out.reward           = cb.output_sum;
    out.already_generated_coins = cb.output_sum;
    // The trust root is verified by agreement, not by work: it is the one block
    // every implementation of this network compiles in.
    out.pow_verified     = true;
    return true;
}

// ---------------------------------------------------------------------------
// ChainBoot
//
// It is BOTH halves of the boot, and the second half is the one that is easy to
// miss until a real daemon is on the other end of the socket.
//
// THE INBOUND HALF is the obvious one: watch for the genesis blob, seed, then
// forward.
//
// THE SERVING HALF is what keeps the connection alive long enough for that to
// happen. monerod's process_payload_sync_data asks `m_core.have_block(top_id)`
// about the tip its peer advertised; when the answer is no it moves the
// connection to state_synchronizing and sends NOTIFY_REQUEST_CHAIN. An index
// with no rows advertises an ALL-ZERO top id -- a block no daemon has -- so
// every peer immediately asks us for a chain we cannot supply, our
// find_supplement answers nullopt, and monerod's own rule (no common block =>
// close) drops the connection before the boot fetch can be issued. Observed
// exactly that way on the first live regtest run: `handshakes=2` and
// `last_close=... (no common block for a chain request)`.
//
// So before the seed lands this class answers the io-thread serving reads
// ITSELF, with the truthful description of a node that holds only the block
// every implementation of this network compiles in:
//
//     current_height = 1, top_id = <pinned genesis id>, cumulative_difficulty = 1
//
// which is byte-for-byte what a freshly initialised monerod on the same network
// advertises. Once the index is seeded every one of these calls is a plain
// forward and this class stops having an opinion.
// ---------------------------------------------------------------------------
class ChainBoot final : public IChainIndexInbound, public IChainServing {
public:
    // What a RESPONSE_CHAIN_ENTRY said, recorded whether or not the index was
    // ready to consume it. This is the read-only probe's whole evidence: a
    // daemon that answers a genesis-terminated locator with its own height and
    // a run of ids has accepted our network id, our handshake and our locator
    // terminus -- the three things a levin client can get wrong and see nothing
    // but silence for.
    struct ChainEntryNote {
        bool          have         = false;
        std::uint64_t start_height = 0;
        std::uint64_t total_height = 0;
        std::size_t   ids          = 0;
        Hash          first_id{};
        Hash          last_id{};
        bool          first_block_present = false;
        std::size_t   first_block_size    = 0;
    };

    struct Stats {
        bool          booted           = false;
        std::uint64_t blobs_inspected  = 0;
        std::uint64_t dropped_preboot  = 0;
        std::uint64_t refusals         = 0;   // a blob that claimed to be genesis and was not
        std::uint64_t chain_entries    = 0;
        std::string   why;                    // the last refusal, or the boot's own note
        ChainEntryNote last_entry{};
    };

    ChainBoot(ChainIndex& index, BootMode mode, Hash genesis_id, XmrNet net)
        : index_(index), mode_(mode), genesis_id_(genesis_id), net_(net) {}

    // The anchor path boots before the network is touched at all.
    bool boot_from_anchor(const std::string& path_or_empty, XmrNet net,
                          const std::vector<std::uint64_t>& timestamps_60,
                          std::string& why) {
        AnchorBundle b;
        if (!load_anchor(path_or_empty, net, b, why)) return false;
        if (!index_.boot_from_anchor(b, timestamps_60, why)) return false;
        std::lock_guard<std::mutex> lk(mu_);
        booted_ = true;
        stats_.booted = true;
        stats_.why = "anchor at height " + std::to_string(b.height);
        return true;
    }

    bool booted() const {
        std::lock_guard<std::mutex> lk(mu_);
        return booted_;
    }

    Stats stats() const {
        std::lock_guard<std::mutex> lk(mu_);
        return stats_;
    }

    // The one id the genesis path is waiting for; the sync driver asks for it.
    const Hash& wanted_genesis() const noexcept { return genesis_id_; }
    BootMode    mode()           const noexcept { return mode_; }

    // --- IChainIndexInbound ------------------------------------------------
    // Peer bookkeeping is never gated: the cohort height (and the synced flag
    // derived from it) must track peers from the first handshake, boot or no
    // boot.
    void on_peer_sync_data(const PeerRef& p, const PeerSyncData& d) override {
        index_.on_peer_sync_data(p, d);
    }

    void on_peer_gone(const PeerRef& p) override { index_.on_peer_gone(p); }

    void on_objects(const PeerRef& p, std::vector<BlockEntry>&& blocks,
                    std::vector<Hash>&& missed, std::uint64_t peer_height) override {
        if (!booted()) {
            for (const BlockEntry& b : blocks) {
                if (try_seed_(b.block_blob)) break;
            }
            if (!booted()) {
                drop_("pre-boot objects");
                return;
            }
        }
        index_.on_objects(p, std::move(blocks), std::move(missed), peer_height);
    }

    void on_chain_entry(const PeerRef& p, ChainEntry&& e) override {
        note_entry_(e);
        if (!booted()) {
            // monerod puts the blob of the block at `start_height` in
            // `first_block`, so a locator that terminates at genesis gets the
            // genesis block for free with the very first answer. Taking it here
            // saves a round trip; the object request is still the path that is
            // guaranteed to work (an older daemon may leave the field empty).
            if (!e.first_block.empty()) (void)try_seed_(e.first_block);
            if (!booted()) {
                drop_("pre-boot chain entry");
                return;
            }
        }
        index_.on_chain_entry(p, std::move(e));
    }

    void on_new_block(const PeerRef& p, BlockEntry&& block, std::uint64_t peer_height,
                      bool fluffy) override {
        if (!booted()) { drop_("pre-boot block push"); return; }
        index_.on_new_block(p, std::move(block), peer_height, fluffy);
    }

    // --- IChainServing (io thread) -----------------------------------------
    PeerSyncData our_sync_data() const override {
        if (booted()) return index_.our_sync_data();
        PeerSyncData d;
        d.current_height        = 1;             // one PAST the tip, monerod's spelling
        d.cumulative_difficulty = U128{1, 0};    // the genesis block's own
        d.top_id                = genesis_id_;
        d.top_version           = hf_version_for_height(net_, 0);
        d.pruning_seed          = 0;
        d.support_flags         = 1;             // fluffy blocks
        return d;
    }

    bool have_block(const Hash& id) const override {
        if (booted()) return index_.have_block(id);
        return id == genesis_id_;
    }

    std::vector<Hash> locator() const override {
        if (booted()) return index_.locator();
        return {genesis_id_};
    }

    std::optional<ChainEntry> find_supplement(const std::vector<Hash>& peer_locator) const override {
        if (booted()) return index_.find_supplement(peer_locator);
        for (const Hash& id : peer_locator) {
            if (id != genesis_id_) continue;
            ChainEntry e;
            e.start_height = 0;
            e.total_height = 1;
            e.cumulative_difficulty_hint = U128{1, 0};
            e.ids.push_back(genesis_id_);
            return e;
        }
        return std::nullopt;
    }

    // We know the genesis ID before we hold its BYTES, and serving a block we
    // cannot produce is worse than reporting it missed.
    std::optional<BlockEntry> get_block_entry(const Hash& id, bool prune) const override {
        if (booted()) return index_.get_block_entry(id, prune);
        return std::nullopt;
    }

private:
    bool try_seed_(const std::vector<std::uint8_t>& blob) {
        if (blob.empty()) return false;
        {
            std::lock_guard<std::mutex> lk(mu_);
            ++stats_.blobs_inspected;
        }
        ChainRow    row;
        std::string why;
        if (!genesis_row_from_blob(blob, genesis_id_, row, why)) {
            std::lock_guard<std::mutex> lk(mu_);
            ++stats_.refusals;
            stats_.why = why;
            return false;
        }
        index_.seed_direct(row,
                           /*difficulty_window=*/{DifficultyRow{row.timestamp,
                                                                row.cumulative_difficulty}},
                           /*short_term_weights=*/{row.block_weight},
                           /*long_term_weights=*/{row.long_term_weight},
                           /*timestamps_60=*/{row.timestamp},
                           /*seed_ids=*/{{0, row.id}});
        std::lock_guard<std::mutex> lk(mu_);
        booted_       = true;
        stats_.booted = true;
        stats_.why    = "genesis row seeded from the levin-delivered blob";
        return true;
    }

    void note_entry_(const ChainEntry& e) {
        std::lock_guard<std::mutex> lk(mu_);
        ++stats_.chain_entries;
        ChainEntryNote n;
        n.have                = true;
        n.start_height        = e.start_height;
        n.total_height        = e.total_height;
        n.ids                 = e.ids.size();
        if (!e.ids.empty()) { n.first_id = e.ids.front(); n.last_id = e.ids.back(); }
        n.first_block_present = !e.first_block.empty();
        n.first_block_size    = e.first_block.size();
        stats_.last_entry     = n;
    }

    void drop_(const char* what) {
        std::lock_guard<std::mutex> lk(mu_);
        ++stats_.dropped_preboot;
        stats_.why = what;
    }

    ChainIndex&        index_;
    BootMode           mode_;
    Hash               genesis_id_;
    XmrNet             net_;
    mutable std::mutex mu_;
    bool               booted_ = false;
    Stats              stats_{};
};

} // namespace c2pool::xmr::native::rt
