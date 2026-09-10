// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/native/txpool/xmr_relayed_txpool.hpp
//
// COMPONENT C3 of the native-minimal Monero node: the relayed transaction pool.
//
// It is fed by exactly one thing -- transactions C1 delivers from levin
// NOTIFY_NEW_TRANSACTIONS (2002) and from the answers to a txpool-complement
// request (2010) -- and it feeds exactly two things: the option-B template
// assembler through ITxpoolSnapshot, and the block relay through ITxBlobSource.
// It never talks to a daemon, never reads the chain, and holds no history.
//
// ADMISSION (ruling R-VAL, operator-ruled): a transaction is admitted on
//
//     AdmissionEvidence::Structural | AdmissionEvidence::NonInputConsensus
//
// which means: it decodes, it satisfies every structural relay rule monerod
// applies, its commitments balance against its plaintext fee, and its
// Bulletproof+ range proofs verify. A BAD-VALUE transaction is therefore caught
// and rejected here. A DOUBLE SPEND is not: detecting one needs the historical
// spent-key-image set, which a pool-scoped node does not carry. Two partial
// defences remain and both are implemented: a key image already owned by a pool
// entry makes the newcomer a no-drop KeyImageConflict rejection, and a key image
// appearing in a connected block evicts the pool entry that shares it. The
// residual -- a transaction spending an output that was spent long ago in a
// block the pool never saw the body of -- is left to monerod parity (C6) and to
// the network, which is exactly what the ruling says.
//
// FIRST-SEEN WINS, and this is a DELIBERATE DIVERGENCE from the C3 design lens,
// which proposed marking both sides of a pool-local key-image collision
// `conflicted` and selecting neither. That rule is unsafe at THIS admission
// depth. Non-input consensus does not cover the transaction PREFIX, so anyone
// who sees a relayed transaction can produce a twin of it -- same key images,
// one byte changed in tx_extra, same commitments, same range proof, different
// id -- that passes every check this component runs. Under "neither is
// selectable" that twin is a free eviction of any transaction from our
// template: a few bytes per censored transaction. Under first-seen-wins the
// twin is refused and the original keeps its place, which is also exactly what
// monerod does (`have_tx_keyimges_as_spent` keeps the first and marks the
// second a no-drop double spend). The KAT exercises the twin construction.
//
// RESIDUAL RISK OF THE RULING, stated plainly because it is larger than "one
// lost fee". Non-input consensus does not cover the transaction PREFIX and does
// not check ring signatures, so a transaction whose CLSAG does not verify is
// admissible here -- and one is trivial to manufacture from any relayed
// transaction by changing a byte of its tx_extra. If such a transaction reaches
// us BEFORE the original does, first-seen-wins holds the forgery and the
// template built on it would be a block the network rejects. This is inherent
// to admitting on non-input consensus, not to the conflict rule: checking a
// CLSAG needs the ring members' public keys, which live in the global output
// set, which a node that starts from a recent anchor does not have. The
// defences that remain are outside this component and must stay armed until
// C2 can answer for inputs: the monerod submit arm (a block the daemon refuses
// never reaches the network), the parity oracle C6 (which compares our
// selection against a real monerod's pool before the daemon is demoted), and
// the operator option of requiring AdmissionEvidence::DaemonConfirmed in the
// select policy while a daemon is armed.
//
// EVIDENCE NOT PRODUCED HERE: AdmissionEvidence::FeePolicy. Replicating
// monerod's check_fee needs C2's long-term effective median weight, which is a
// separate component and a separate co-KAT. A policy that REQUIRES FeePolicy is
// therefore unsatisfiable by this component and yields an empty backlog rather
// than a silently relaxed one -- fail-closed, and asserted by the KAT.
// AdmissionEvidence::DaemonConfirmed is likewise never set here; it belongs to
// the arm that has a daemon.
//
// THREADING: one mutex, in the shape of the DASH mempool. Every public method
// takes it; snapshots are copied out under it. Decoding and proof verification
// happen INSIDE on_relayed, so the caller must not be the io thread once the
// heavy leg is on (the plan's C3 pool thread, section 3).
// ---------------------------------------------------------------------------
#pragma once

#include <cstdint>
#include <cstring>
#include <deque>
#include <functional>
#include <mutex>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "impl/xmr/native/contracts/txpool.hpp"
#include "impl/xmr/native/contracts/types.hpp"
#include "xmr_tx_decode.hpp"

namespace c2pool::xmr::native {

// Hash / key-image hasher for the unordered containers.
struct HashHasher {
    std::size_t operator()(const Hash& h) const noexcept {
        std::size_t v = 0;
        std::memcpy(&v, h.data(), sizeof(v));   // the id is already a hash
        return v;
    }
};

// --- consensus and policy limits --------------------------------------------
// Values are monerod's, named after the constant they mirror.
struct TxpoolConfig {
    // What the snapshot filter demands. Defaults to the R-VAL ruling.
    TxpoolSelectPolicy policy{
            AdmissionEvidence::Structural | AdmissionEvidence::NonInputConsensus,
            /*min_peers=*/1,
            /*allow_stem=*/false};

    // CRYPTONOTE_MAX_TX_SIZE
    std::uint64_t max_tx_blob_size = 1000000;
    // get_transaction_weight_limit(hf) = get_min_block_weight/2 - reserve
    //                                  = 300000/2 - 600
    std::uint64_t max_tx_weight = 149400;
    // MAX_TX_EXTRA_SIZE, a txpool-only rule (monero PR #8733)
    std::size_t   max_extra_size = 1060;
    // HF_VERSION_MIN_MIXIN_15: ring size is exactly 16 from HF15
    std::uint64_t required_ring_size = 16;
    // HF_VERSION_MIN_2_OUTPUTS .. BULLETPROOF_PLUS_MAX_OUTPUTS
    std::size_t   min_outputs = 2;
    std::size_t   max_outputs = 16;

    // Pool sizing (ruling C3-R4 in the lens: 64 MiB of blobs).
    std::uint64_t max_pool_bytes = 64ull * 1024 * 1024;
    // Age eviction, monerod's CRYPTONOTE_MEMPOOL_TX_LIVETIME.
    std::uint64_t max_age_seconds = 3 * 24 * 60 * 60;

    // The heavy leg. Off only for tests that want to exercise pool mechanics
    // without paying for range proofs; a node NEVER runs with this off, and
    // with it off no entry ever gains NonInputConsensus evidence, so the
    // default policy selects nothing. Fail-closed by construction.
    bool verify_non_input_consensus = true;
};

// --- one pool entry ----------------------------------------------------------
struct RelayedTx {
    Hash                      id{};
    std::vector<std::uint8_t> blob;      // the EXACT bytes received
    std::uint64_t             blob_size = 0;
    std::uint64_t             weight    = 0;
    std::uint64_t             fee       = 0;
    std::uint8_t              rct_type  = 0;
    std::uint16_t             n_inputs  = 0;
    std::uint16_t             n_outputs = 0;

    std::vector<Hash> key_images;

    std::uint64_t time_received = 0;   // FIRST sighting, never reset
    std::unordered_set<std::uint64_t> peers;   // distinct relaying peer ids
    bool seen_fluff  = false;          // any sighting outside the stem phase

    AdmissionEvidence evidence = AdmissionEvidence::None;

    std::uint32_t seen_from_peers() const noexcept {
        return static_cast<std::uint32_t>(peers.size());
    }
};

struct TxpoolStats {
    std::uint64_t count            = 0;
    std::uint64_t bytes            = 0;
    std::uint64_t weight           = 0;
    std::uint64_t pinned_templates = 0;

    std::uint64_t accepted         = 0;
    std::uint64_t duplicates       = 0;
    std::uint64_t rejected         = 0;
    std::uint64_t evicted_age      = 0;
    std::uint64_t evicted_cap      = 0;
    std::uint64_t evicted_mined    = 0;
    std::uint64_t evicted_conflict = 0;
};

// --- the pool ----------------------------------------------------------------
class RelayedTxPool final : public IRelayedTxSink,
                            public ITxpoolSnapshot,
                            public ITxSource,
                            public ITxBlobSource {
public:
    // The clock is injectable so age eviction is testable without sleeping.
    using ClockFn = std::function<std::uint64_t()>;

    explicit RelayedTxPool(TxpoolConfig cfg = TxpoolConfig{}, ClockFn clock = nullptr);

    // --- IRelayedTxSink (C1 -> C3) -----------------------------------------
    std::vector<TxRelayVerdict> on_relayed(const PeerRef&                          from,
                                           std::vector<std::vector<std::uint8_t>>  blobs,
                                           bool dandelionpp_fluff) override;
    std::vector<Hash> complement_request_ids() const override;

    // --- ITxpoolSnapshot (C3 -> C4) ----------------------------------------
    std::vector<node::TxBacklogEntry> selectable_backlog() const override;
    std::vector<node::TxBacklogEntry> selectable_backlog(const TxpoolSelectPolicy&) const override;
    TxpoolSelectPolicy policy() const override;
    std::uint64_t      backlog_version() const override;

    // --- ITxSource (C3 -> C2) ----------------------------------------------
    bool get_tx(const Hash& id, std::vector<std::uint8_t>& full_blob) override;

    // --- ITxBlobSource (C3 -> C5) ------------------------------------------
    bool get_blobs(const std::vector<Hash>&                ids,
                   std::vector<std::vector<std::uint8_t>>& out,
                   std::vector<Hash>&                      missing) override;
    void pin(const Hash& template_id, const std::vector<Hash>& ids) override;
    void unpin(const Hash& template_id) override;

    // --- C2 -> C3 chain context ---------------------------------------------
    // Connected: drop every mined id, then evict any entry sharing a key image
    // with the block (the common double-spend race, resolved without history).
    // Disconnected: re-admit the bodies the index still had, best effort, and
    // never trust them for validity -- they are re-decoded and re-verified.
    void on_block_connected(const BlockTxEvent& ev);
    void on_block_disconnected(const BlockTxEvent& ev);

    // Fail-closed relay gate: no transaction is admitted before C2 says the
    // index is at the tip, mirroring monerod's is_synchronized() gate.
    void set_synced(bool synced);
    bool synced() const;

    // Age eviction pass. Called on a tick; on_relayed also runs it.
    std::size_t expire_old();

    // --- introspection (dashboard, KATs, C6 parity probe) -------------------
    TxpoolStats stats() const;
    bool        contains(const Hash& id) const;
    bool        lookup(const Hash& id, RelayedTx& out) const;
    std::size_t size() const;

private:
    // Called with the mutex held.
    TxRelayVerdict admit_locked(const PeerRef& from, std::vector<std::uint8_t>&& blob,
                                bool fluff);
    void  insert_locked(RelayedTx&& tx);
    void  erase_locked(const Hash& id);
    bool  make_room_locked(std::uint64_t incoming_bytes, std::uint64_t incoming_fee,
                           std::uint64_t incoming_weight);
    bool  is_pinned_locked(const Hash& id) const;
    std::size_t expire_old_locked();
    std::vector<node::TxBacklogEntry> snapshot_locked(const TxpoolSelectPolicy& p) const;
    std::uint64_t now() const;

    mutable std::mutex mu_;
    TxpoolConfig       cfg_;
    ClockFn            clock_;

    std::unordered_map<Hash, RelayedTx, HashHasher>          by_id_;
    // key image -> the ONE entry that owns it (first-seen wins, see above)
    std::unordered_map<Hash, Hash, HashHasher>               ki_owners_;
    std::deque<Hash>                                         arrival_;
    std::unordered_map<Hash, std::vector<Hash>, HashHasher>  pins_;

    std::uint64_t pool_bytes_      = 0;
    std::uint64_t backlog_version_ = 0;
    bool          synced_          = false;
    TxpoolStats   stats_{};
};

} // namespace c2pool::xmr::native
