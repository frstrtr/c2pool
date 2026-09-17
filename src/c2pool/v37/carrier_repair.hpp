#pragma once
// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ===========================================================================
// src/c2pool/v37/carrier_repair.hpp   (Track A2 / Stage 2 APPLY — the REPAIR)
//
// CONSUMER-TREE ONLY. Nothing here computes a consensus byte: the lane digest
// is computed by the canon LaneExecutor inside a SCRATCH V37Engine, the fold is
// settle::fold_eb (unchanged), and every path out of this header is either "a
// verified projection at exactly the prefix the winner named" or "nothing".
//
// ── THE DEFECT THIS CLOSES ──────────────────────────────────────────────────
// btc_node.hpp XbtcNode::on_peer_block_won folds E_b at the WINNER'S lane cut
// (w.cut_next_pos, w.cut_spine_digest) read back out of OUR OWN settlement ring
// (V37Engine::settlement_view_by_cut). When our order at P is not the winner's,
// that read returns nullptr and the arm REFUSES with one of two bits:
//
//   cut_miss              we never PUBLISHED prefix P at all. Under ruling A
//                         (node-local order + winner-cut authority) the ordinary
//                         cause is that we DROPPED a share the winner admitted,
//                         so our lane is SHORTER and P is simply not a prefix we
//                         ever reached.
//   cut_digest_mismatch   we published P, with different bytes: we admitted a
//                         DIFFERENT record multiset into the same prefix length
//                         (an extra own carrier, or a different drop).
//
// Both are the SAME repairable condition — "my local order at P is not the
// winner's" — and before Stage 2 both were terminal: the peer's block was never
// credited here, and the two nodes' owed_digests stayed forked forever. That is
// root cause (2) of the 09-13 sustained-convergence finding.
//
// ── WHAT THE REPAIR IS, AND WHAT IT IS NOT ──────────────────────────────────
// It is NOT "fold at a neighbouring prefix" and it is NOT "trust the winner".
// It is: FETCH the winner's ordered carrier ids over [a, P) and their FRAME
// BYTES over the Stage-1 supply channel (carrier_supply.hpp), REPLAY that record
// stream into a SCRATCH engine through the w6 slow path (PrefixResolver +
// ReplayDriver, w6_persistence.hpp §5.5), and accept the result ONLY IF the
// digest the scratch engine reaches at P is byte-equal to the winner's
// cut_spine_digest. The digest gate is the whole security argument:
//
//   * every fetched frame is hash-verified against the id that was asked for
//     (SupplyRequester, fail-closed — a lying peer is rejected wholesale);
//   * every push is derived by OUR OWN W2 ReceiptAdmitter over OUR OWN
//     mainchain index, so a peer cannot make us account work we would not have
//     admitted ourselves;
//   * the replayed prefix must land on the winner's exact commitment, so a
//     genuine ADMISSION-VERDICT fork (we and the winner disagree about whether
//     some receipt is valid) still fails closed and still refuses.
//
// The repair therefore changes WHICH SettlementView settle::fold_eb reads. It
// does not change the fold, the ledger, the owed commitment, when
// on_block_finalized fires, or one byte of any frozen wire golden.
//
// ── THE STRUCTURAL PRE-CHECK (free, and it catches a lying order early) ─────
// The ORDER answer is a list of (lane position, carrier id) pairs. Each carrier
// contributes exactly n_pushes lane positions, so for a CONTIGUOUS served run
//     pos[i+1] - pos[i] == n_pushes(carrier i)     and     P - pos[last] == n_pushes(last)
// must hold. We re-derive n_pushes locally by admitting the fetched frame, so a
// server that reorders, omits or invents an entry is caught BEFORE any digest is
// computed, with a distinct counter.
//
// ── THE BOUND (stated, not hidden) ──────────────────────────────────────────
// A lane digest at P is a function of the WHOLE lane [0, P), not of a suffix, so
// the replay starts at lane position 0. A repair is therefore possible only
// while the serving node still retains position 0 in its FrameVault (the
// window horizon, default 8640 positions). Past that the ORDER answer is
// BELOW_HORIZON and the repair REFUSES — it never silently repairs a suffix.
//
// ── THREADING ───────────────────────────────────────────────────────────────
// arm() / on_order() / on_frames() are driven from the transport reader thread.
// The driver holds its own mutex and NEVER calls the engine or the ledger while
// holding it; the completion callback (the S3 re-drive) is invoked with no lock
// held. The scratch V37Engine is created, driven and destroyed inside one
// replay call; the SettlementView it publishes is a shared_ptr<const> that
// outlives the engine (v37_engine.hpp O1.1).
// ===========================================================================

#include <algorithm>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include <c2pool/v37/carrier_supply.hpp>
#include <c2pool/v37/frame_vault.hpp>
#include <c2pool/v37/v37_engine.hpp>
#include <c2pool/v37/carrier_ingest.hpp>    // MemShareTracker
#include <c2pool/v37/w2_admission.hpp>
#include <c2pool/v37/w3_relay.hpp>
#include <c2pool/v37/w6_persistence.hpp>

namespace c2pool::v37n {

namespace persist = ::c2pool::v37n::persist;

// ═══════════════════════════════════════════════════════════════════════════
// (1) FrameVaultChainReader — persist::ISharechainReader over a FrameVault.
//
// The w6 slow path walks a sharechain BACKWARD by prev_hash. A FrameVault has
// something strictly better for this purpose: a total order BY LANE POSITION
// (the (chain, pos) -> carrier-hash index that exists nowhere else in the tree).
// `get_chain_hashes(start, max, forward=false)` therefore walks the position
// index down from `start`, element 0 == start, which is exactly the contract
// walk_lane_forward() consumes (it post-truncates at the lane genesis hash and
// reverses). `load_share` returns the w6 MIRROR share encoding (§5.2
// DecodedShare) derived from the retained CarrierWire frame, so
// ReplayDriver::pushes_for_carrier reads it unchanged.
//
// Payout ids: the w6 mirror keys a push by a u64 `payout_id`. That id is
// node-local by construction (§5.2), so this reader interns descriptors into a
// caller-owned table and emits the table index. The scratch engine seam maps it
// back. Nothing about the id reaches a digest — the descriptor does.
// ═══════════════════════════════════════════════════════════════════════════
class DescriptorTable {
public:
    std::uint64_t intern(const ::v37::PayoutDescriptor& d) {
        const ::v37::bytes32 k = d.identity_key();
        std::lock_guard<std::mutex> lk(m_mtx);
        auto it = m_by_key.find(k);
        if (it != m_by_key.end()) return it->second;
        const std::uint64_t id = m_tbl.size();
        m_tbl.push_back(d);
        m_by_key.emplace(k, id);
        return id;
    }
    std::optional<::v37::PayoutDescriptor> at(std::uint64_t id) const {
        std::lock_guard<std::mutex> lk(m_mtx);
        if (id >= m_tbl.size()) return std::nullopt;
        return m_tbl[static_cast<std::size_t>(id)];
    }
    std::size_t size() const { std::lock_guard<std::mutex> lk(m_mtx); return m_tbl.size(); }
private:
    mutable std::mutex                    m_mtx;
    std::vector<::v37::PayoutDescriptor>  m_tbl;
    std::map<::v37::bytes32, std::uint64_t> m_by_key;
};

class FrameVaultChainReader final : public persist::ISharechainReader {
public:
    FrameVaultChainReader(const FrameVault& vault, std::uint32_t chain,
                          std::shared_ptr<DescriptorTable> tbl)
        : m_vault(vault), m_chain(chain), m_tbl(std::move(tbl)) {}

    // Backward walk by lane POSITION, element 0 == start. Bounded by `max`.
    std::vector<::v37::bytes32> get_chain_hashes(const ::v37::bytes32& start,
                                                 ::v37::u64 max,
                                                 bool forward) const override {
        std::vector<::v37::bytes32> out;
        if (forward || max == 0) return out;          // only the §5.2 backward walk
        // The vault has no hash -> position map on its public surface, so walk
        // the whole retained order once and cut at `start`. Bounded by the
        // vault's own entry cap; never unbounded.
        const VaultOrder all = m_vault.serve_order(m_chain, 0, ~std::uint64_t{0},
                                                   kOrderScanCap);
        std::size_t at = all.ids.size();
        for (std::size_t i = 0; i < all.ids.size(); ++i)
            if (all.ids[i].id == start) { at = i; break; }
        if (at == all.ids.size()) return out;          // we do not hold `start`
        for (std::size_t i = at + 1; i-- > 0;) {
            out.push_back(all.ids[i].id);
            if (out.size() >= static_cast<std::size_t>(max)) break;
        }
        return out;
    }

    std::optional<std::string> load_share(const ::v37::bytes32& h) const override {
        std::vector<std::pair<::v37::bytes32, std::vector<std::uint8_t>>> got;
        m_vault.serve_frames({h}, 1, kFrameServeCap, got);
        if (got.empty()) return std::nullopt;
        const DecodeResult dr = CarrierWire::decode(got.front().second);
        if (!dr.ok()) return std::nullopt;
        persist::DecodedShare ds;
        ds.carrier_payout_id = m_tbl->intern(dr.carrier.carrier.descriptor);
        for (const WorkEvent& r : dr.carrier.receipts)
            ds.receipt_payout_ids.push_back(m_tbl->intern(r.descriptor));
        return persist::encode_share(ds);
    }

    // The ordered run the vault retains for [a, p), straight through.
    VaultOrder order(std::uint64_t a, std::uint64_t p, std::size_t max_ids) const {
        return m_vault.serve_order(m_chain, a, p, max_ids);
    }

private:
    // Both caps are the transport's own, so this reader can never be asked to
    // materialise more than one honest supply answer's worth of state.
    static constexpr std::size_t kOrderScanCap  = 1u << 20;
    static constexpr std::size_t kFrameServeCap = static_cast<std::size_t>(kMaxCarrierFrame);

    const FrameVault&                m_vault;
    std::uint32_t                    m_chain;
    std::shared_ptr<DescriptorTable> m_tbl;
};

// ═══════════════════════════════════════════════════════════════════════════
// (2) RepairStore — an in-memory persist::ISettleStore holding ONLY the three
// record families the w6 replay reads: GENESIS, TIP and one CARRIER per share.
// It is written once per repair attempt from the fetched order and never
// touched again; it is not the node's durable store and it never becomes one.
// ═══════════════════════════════════════════════════════════════════════════
class RepairStore final : public persist::ISettleStore {
public:
    class Batch final : public persist::ISettleBatch {
    public:
        explicit Batch(RepairStore& s) : m_s(s) {}
        void put(const std::string& k, const std::string& v) override { m_ops.emplace_back(k, v); }
        void remove(const std::string& k) override { m_ops.emplace_back(k, std::string()); }
        bool commit_sync() override {
            for (auto& [k, v] : m_ops) {
                if (v.empty()) m_s.m_kv.erase(k); else m_s.m_kv[k] = v;
            }
            return true;
        }
    private:
        RepairStore& m_s;
        std::vector<std::pair<std::string, std::string>> m_ops;
    };

    std::unique_ptr<persist::ISettleBatch> batch() override {
        return std::make_unique<Batch>(*this);
    }
    std::optional<std::string> get(const std::string& k) override {
        auto it = m_kv.find(k);
        return it == m_kv.end() ? std::nullopt : std::optional<std::string>(it->second);
    }
    bool for_each_prefix(const std::string& prefix,
                         const std::function<bool(const std::string&, const std::string&)>& fn) override {
        for (const auto& [k, v] : m_kv)
            if (k.compare(0, prefix.size(), prefix) == 0 && !fn(k, v)) return false;
        return true;
    }
    void put(const std::string& k, const std::string& v) { m_kv[k] = v; }

private:
    std::map<std::string, std::string> m_kv;
};

// ═══════════════════════════════════════════════════════════════════════════
// (3) ScratchEngineSeam — persist::IEngineSeam over a REAL V37Engine.
//
// The w6 mirror record carries a payout_id; the canon record carries the
// PayoutDescriptor itself. This seam is the one place the two meet, and it is
// deliberately fail-closed: an id the table cannot resolve poisons the seam so
// the replay's own snapshot check fails rather than silently dropping a push
// (a dropped push would give a SHORTER prefix and a wrong digest — the exact
// class of error the digest gate exists to catch, but caught here by name).
// ═══════════════════════════════════════════════════════════════════════════
class ScratchEngineSeam final : public persist::IEngineSeam {
public:
    // `poisoned` is SHARED with the caller on purpose: PrefixResolver owns the
    // seam for exactly the duration of resolve() and destroys it on return, so a
    // raw back-pointer would dangle the moment the answer is inspected.
    ScratchEngineSeam(V37Engine& e, ::v37::LaneParams params,
                      std::shared_ptr<const DescriptorTable> tbl,
                      std::shared_ptr<bool> poisoned)
        : m_e(e), m_params(std::move(params)), m_tbl(std::move(tbl)),
          m_poisoned(std::move(poisoned)) {}

    void submit(const persist::LaneRecord& r) override {
        using K = persist::LaneRecord::K;
        if (*m_poisoned) return;
        const ::v37::ChainId c = static_cast<::v37::ChainId>(r.chain);
        switch (r.kind) {
            case K::AddLane:
                // The mirror LaneParamsRec is a lossy projection of LaneParams;
                // the replay uses OUR OWN ratified geometry instead. A winner on
                // a different geometry reaches a different digest and is refused
                // by the gate — never accommodated here.
                wait(m_e.submit_tracked(::v37::LaneRecord::add_lane(c, m_params)));
                return;
            case K::RemoveLane:
                wait(m_e.submit_tracked(::v37::LaneRecord::remove_lane(c)));
                return;
            case K::Rewind:
                wait(m_e.submit_tracked(::v37::LaneRecord::rewind(c, r.depth)));
                return;
            case K::Push: {
                std::optional<::v37::PayoutDescriptor> d = m_tbl->at(r.payout_id);
                if (!d) { *m_poisoned = true; return; }
                wait(m_e.submit_tracked(::v37::LaneRecord::push(
                    c, *d, r.w_raw, r.flags)));
                return;
            }
        }
    }

    std::shared_ptr<const persist::LaneSnapshotView> snapshot(::v37::ChainId c) const override {
        if (*m_poisoned) return nullptr;
        std::shared_ptr<const ::v37::LaneSnapshot> s = m_e.snapshot(c);
        if (!s) return nullptr;
        auto v = std::make_shared<persist::LaneSnapshotView>();
        v->version     = s->version;
        v->incarnation = s->incarnation;
        v->chain       = c;
        v->next_pos    = s->next_pos;
        v->digest      = s->digest;
        return v;
    }

    bool poisoned() const { return *m_poisoned; }

private:
    static void wait(std::future<::v37::SubmitResult> f) {
        try { (void)f.get(); } catch (...) { /* engine stopped: the gate catches it */ }
    }
    V37Engine&                               m_e;
    ::v37::LaneParams                        m_params;
    std::shared_ptr<const DescriptorTable>   m_tbl;
    std::shared_ptr<bool>                    m_poisoned;
};

// ═══════════════════════════════════════════════════════════════════════════
// (4) The replay itself.
// ═══════════════════════════════════════════════════════════════════════════

// Why a repair attempt ended the way it did. Every non-OK value REFUSES.
enum class RepairOutcome : std::uint8_t {
    OK = 0,
    NO_ORDER,          // the server refused / could not serve [0, P)
    BELOW_HORIZON,     // the server no longer retains position 0
    ORDER_GAP,         // the served run does not cover [0, P) contiguously
    MISSING_FRAME,     // an ordered id whose bytes we never got
    UNDECODABLE,       // a fetched frame did not decode as a carrier
    NOT_ADMISSIBLE,    // OUR W2 would not admit a frame the winner ordered
    PUSH_COUNT,        // the order's position deltas disagree with our admission
    REPLAY_FAILED,     // the w6 PrefixResolver did not reach P
    DIGEST_MISMATCH,   // reached P with a DIFFERENT commitment: a real fork
    NO_VIEW,           // reached the digest but the scratch ring had no view (unreachable)
};

inline const char* repair_outcome_name(RepairOutcome o) {
    switch (o) {
        case RepairOutcome::OK:              return "OK";
        case RepairOutcome::NO_ORDER:        return "no order served";
        case RepairOutcome::BELOW_HORIZON:   return "server no longer retains lane position 0";
        case RepairOutcome::ORDER_GAP:       return "the served order is not contiguous over [0, P)";
        case RepairOutcome::MISSING_FRAME:   return "an ordered carrier's bytes were never delivered";
        case RepairOutcome::UNDECODABLE:     return "a served frame did not decode";
        case RepairOutcome::NOT_ADMISSIBLE:  return "our own W2 refuses a carrier the winner ordered";
        case RepairOutcome::PUSH_COUNT:      return "order positions disagree with our push derivation";
        case RepairOutcome::REPLAY_FAILED:   return "the replay never reached prefix P";
        case RepairOutcome::DIGEST_MISMATCH: return "replayed P with a DIFFERENT digest (real divergence)";
        case RepairOutcome::NO_VIEW:         return "no settlement view at the verified prefix";
    }
    return "?";
}

struct RepairResult {
    RepairOutcome outcome = RepairOutcome::NO_ORDER;
    // The verified projection at exactly (P, spine_digest). Non-null IFF
    // outcome == OK. This is the ONLY thing the cut-miss arm consumes.
    std::shared_ptr<const SettlementView> view;
    std::uint64_t carriers = 0;    // frames replayed
    std::uint64_t pushes   = 0;    // lane positions replayed
    bool ok() const { return outcome == RepairOutcome::OK && view != nullptr; }
};

// The inputs one replay needs. `frames` is keyed by carrier id and holds the
// VERBATIM wire bytes the supply channel verified (hash(bytes) == id).
struct RepairInput {
    std::uint32_t                 chain = 0;
    std::uint64_t                 target_pos = 0;          // P
    ::v37::bytes32                spine_digest{};          // the winner's commitment at P
    ::v37::LaneParams             params{};                // OUR ratified geometry
    std::vector<VaultOrderId>     order;                   // (pos, id), ascending, from 0
    std::map<::v37::bytes32, std::vector<std::uint8_t>> frames;
};

// Replay [0, P) into a scratch engine and return the projection IFF the reached
// digest == spine_digest. `index` is OUR mainchain index — the admission of
// every fetched frame is OURS, never the server's word for it.
inline RepairResult replay_to_cut(const RepairInput& in, const IMainchainIndex& index) {
    RepairResult out;
    if (in.order.empty() || in.order.front().pos != 0) {
        out.outcome = RepairOutcome::ORDER_GAP;
        return out;
    }

    // ── (a) build the repair-local vault + w6 records by ADMITTING each frame
    //        through OUR OWN W2. The admitter is fresh (incarnation 1, empty
    //        dedup window, empty tracker), so the replay is a pure function of
    //        the fetched bytes and our index.
    auto tbl = std::make_shared<DescriptorTable>();
    FrameVault vault;                         // repair-local; default bounds
    RepairStore store;
    MemShareTracker tracker;
    ReceiptAdmitter adm(in.chain, index, tracker, /*incarnation=*/1);

    ::v37::bytes32 first_hash{};
    ::v37::bytes32 last_hash{};
    std::uint64_t  next_expected = 0;
    for (std::size_t i = 0; i < in.order.size(); ++i) {
        const VaultOrderId& oid = in.order[i];
        if (oid.pos != next_expected) { out.outcome = RepairOutcome::ORDER_GAP; return out; }
        if (oid.pos >= in.target_pos) break;

        auto fit = in.frames.find(oid.id);
        if (fit == in.frames.end()) { out.outcome = RepairOutcome::MISSING_FRAME; return out; }
        const DecodeResult dr = CarrierWire::decode(fit->second);
        if (!dr.ok()) { out.outcome = RepairOutcome::UNDECODABLE; return out; }
        if (!(dr.carrier.carrier.hash() == oid.id)) {
            out.outcome = RepairOutcome::UNDECODABLE;   // the supply layer already
            return out;                                 // checks this; belt and braces
        }

        // OUR admission verdict, and nobody else's.
        const ReceiptAdmitter::Result ar = adm.admit(dr.carrier.carrier, dr.carrier.receipts);
        if (ar.carrier_status != CarrierStatus::OK || ar.pushes.empty()) {
            out.outcome = RepairOutcome::NOT_ADMISSIBLE;
            return out;
        }
        const std::uint32_t n_pushes = static_cast<std::uint32_t>(ar.pushes.size());

        // ★ THE STRUCTURAL PRE-CHECK: the winner's own position deltas must
        //   agree with the push count we just derived, BEFORE any digest runs.
        const std::uint64_t next_pos_claim =
            (i + 1 < in.order.size() && in.order[i + 1].pos < in.target_pos)
                ? in.order[i + 1].pos
                : in.target_pos;
        if (next_pos_claim != oid.pos + n_pushes) {
            out.outcome = RepairOutcome::PUSH_COUNT;
            return out;
        }

        // The w6 CARRIER record: w_raw + accepted_mask pinned from OUR verdict,
        // exactly as §4.3 requires (replay independent of the live index).
        persist::CarrierRec cr;
        cr.boot_id = 1;
        cr.incarnation = 1;
        cr.next_pos_after = oid.pos + n_pushes;
        cr.w_raw_carrier = ar.pushes.front().w_raw;
        std::uint8_t mask = 0;
        {
            std::size_t pi = 1;
            for (std::size_t ri = 0; ri < dr.carrier.receipts.size() && ri < persist::R_MAX; ++ri) {
                if (pi < ar.pushes.size() &&
                    ar.pushes[pi].tag == dr.carrier.receipts[ri].tag) {
                    mask |= static_cast<std::uint8_t>(1u << ri);
                    cr.w_raw_receipt.push_back(ar.pushes[pi].w_raw);
                    ++pi;
                }
            }
            if (pi != ar.pushes.size()) { out.outcome = RepairOutcome::PUSH_COUNT; return out; }
        }
        cr.accepted_mask = mask;
        store.put(persist::keys::carrier(in.chain, oid.id), persist::encode_carrier(cr));
        vault.insert(in.chain, oid.id, oid.pos, n_pushes, fit->second);

        if (i == 0) first_hash = oid.id;
        last_hash = oid.id;
        next_expected = oid.pos + n_pushes;
        ++out.carriers;
    }
    if (next_expected != in.target_pos) { out.outcome = RepairOutcome::ORDER_GAP; return out; }

    persist::GenesisRec g;
    g.first_share_hash = first_hash;
    store.put(persist::keys::genesis(in.chain), persist::encode_genesis(g));
    persist::TipRec t;
    t.share_hash = last_hash;
    t.next_pos   = in.target_pos;
    t.boot_id    = 1;
    store.put(persist::keys::tip(in.chain), persist::encode_tip(t));

    // ── (b) the w6 slow path: canonical_records -> PrefixResolver -> digest gate
    FrameVaultChainReader reader(vault, in.chain, tbl);
    persist::ReplayDriver replay(store, reader);
    std::optional<std::vector<persist::LaneRecord>> records =
        replay.canonical_records(static_cast<persist::ChainId>(in.chain));
    if (!records) { out.outcome = RepairOutcome::REPLAY_FAILED; return out; }

    // The scratch engine outlives resolve(): the verified SettlementView is read
    // back off ITS ring once the digest gate has passed.
    V37Engine scratch;
    scratch.start();
    // The seam's fail-closed latch, held HERE: PrefixResolver destroys the seam
    // when resolve() returns, so the flag has to outlive it.
    auto poisoned = std::make_shared<bool>(false);
    persist::PrefixResolver resolver([&]() -> std::unique_ptr<persist::IEngineSeam> {
        return std::make_unique<ScratchEngineSeam>(
            scratch, in.params, std::static_pointer_cast<const DescriptorTable>(tbl),
            poisoned);
    });
    const std::optional<persist::LaneSnapshotView> reached =
        resolver.resolve(static_cast<persist::ChainId>(in.chain), in.target_pos,
                         in.spine_digest, *records);
    if (!reached) {
        // resolve() returns nullopt both for "never reached P" and for "reached
        // P with another digest". Separate the two for the operator: only the
        // second is a real sharechain divergence.
        std::shared_ptr<const ::v37::LaneSnapshot> s =
            scratch.snapshot(static_cast<::v37::ChainId>(in.chain));
        const bool at_p = s && s->next_pos == in.target_pos;
        out.outcome = (*poisoned || !at_p) ? RepairOutcome::REPLAY_FAILED
                                          : RepairOutcome::DIGEST_MISMATCH;
        scratch.stop();
        return out;
    }
    // Digest-gated. Read the FULL projection (payout + identities) at exactly
    // that prefix and that commitment — the same by-cut reader the live arm uses.
    std::shared_ptr<const SettlementView> view = scratch.settlement_view_by_cut(
        static_cast<::v37::ChainId>(in.chain), in.target_pos, in.spine_digest);
    scratch.stop();
    if (!view) { out.outcome = RepairOutcome::NO_VIEW; return out; }
    out.view    = std::move(view);
    out.pushes  = in.target_pos;
    out.outcome = RepairOutcome::OK;
    return out;
}

// ═══════════════════════════════════════════════════════════════════════════
// (5) RepairDriver — the ASYNC driver: arm on a refused peer win, fetch over
// the Stage-1 supply channel, replay, cache the verified view, and hand the
// daemon an S3 RE-DRIVE so the one-shot refused peer win is retried.
//
// One repair in flight per (chain, P, spine). A second arm for the same cut
// while one is running is a no-op, so a flood of re-offers of the same winner
// carrier cannot multiply the work.
//
// ── ★ ONE SERVING PEER, TWO CUTS: THE LIVENESS RULE ────────────────────────
// The supply channel allows exactly ONE outstanding request per peer
// (SupplyRequester::request_order returns false / refused_busy otherwise), and
// on the 2-node shape there IS only one peer — the very peer whose wins we are
// refusing. So "a second distinct cut arrives while a repair is in flight
// against the only peer that can serve it" is the ORDINARY case, not a corner.
//
// The rule this driver enforces for that case:
//
//   an in-flight repair job NEVER loses its peer binding because another cut
//   was armed or finished.
//
// Two writes used to break it:
//
//   (1) a second arm k2 OVERWROTE the binding of the live job k1 before its own
//       ask was even refused;
//   (2) finish() erased m_by_peer BY BARE PEER ID. finish(k2) — reached
//       immediately, because the ask was refused_busy — then erased the
//       binding outright. k1's ORDER reply had nowhere to land, k1 stayed in
//       m_jobs forever, and every later arm of that cut COALESCED into the
//       dead job: permanently unrepairable, silently, with no refusal logged.
//
// Both are fixed by the QUEUE and the IDENTITY-GUARDED ERASE: a second cut
// whose only peer is already serving is QUEUED (m_deferred) without touching
// m_by_peer and without creating a job, and finish() erases only the binding
// that is still ITS OWN. A queued cut is re-armed the moment the peer falls
// free, and — because nothing recorded it as in flight — it also stays
// re-armable by a later S3 re-offer.
//
// ── ★ AND THE BINDING IS WRITTEN BEFORE THE ASK, NOT AFTER ─────────────────
// A first cut at (1) moved the binding to AFTER request_order() returned, on
// the argument that "the reply is delivered later, by the same thread". That
// argument does not hold: arm() is reached from the block-event path, from
// drain_deferred() on a COMPLETING repair, and from the daemon's S3 re-drive,
// none of which is the transport reader thread. Binding after the ask left a
// window in which an ORDER reply for THIS job lands while m_by_peer still
// holds nothing — on_order() finds no binding, DROPS the reply, and the job
// sits in m_jobs with no reply ever coming. The same zombie, entered from the
// other side, and one an ablation reproduces deterministically.
//
// So the binding is written INSIDE the arm's critical section, before the ask
// goes out. That is safe precisely because the other two rules are kept:
// the queue gate has already returned for any peer that is serving, so this
// write can never land on a live job's binding; and finish() erases by job
// identity, so a locally refused ask rolls back exactly its own binding.
// ═══════════════════════════════════════════════════════════════════════════
struct RepairStats {
    std::uint64_t armed          = 0;   // repairs started
    std::uint64_t coalesced      = 0;   // arm() for a cut already in flight / cached
    std::uint64_t order_failed   = 0;
    std::uint64_t fetch_failed   = 0;
    std::uint64_t replayed       = 0;   // replays actually run
    std::uint64_t repaired       = 0;   // ★ replays that reached the winner's digest
    std::uint64_t refused        = 0;   // ★ replays that did NOT — still REFUSED
    std::uint64_t redriven       = 0;   // S3 re-drives issued
    std::uint64_t frames_fetched = 0;
    std::uint64_t unservable     = 0;   // ids the server holds but cannot send
    // ── the one-serving-peer queue ──────────────────────────────────────────
    std::uint64_t deferred       = 0;   // ★ cuts QUEUED because their only peer was serving
    std::uint64_t resumed        = 0;   // ★ queued cuts re-armed once the peer fell free
    std::uint64_t deferred_drop  = 0;   // queue full, or its peer went away: cleanly refused
};

// The key a repair is addressed by: exactly the cut the winner named.
struct RepairKey {
    std::uint32_t  chain = 0;
    std::uint64_t  pos = 0;
    ::v37::bytes32 spine{};
    bool operator<(const RepairKey& o) const {
        if (chain != o.chain) return chain < o.chain;
        if (pos != o.pos) return pos < o.pos;
        return spine < o.spine;
    }
    // Identity, so a binding can be erased by WHOSE it is rather than by peer.
    bool operator==(const RepairKey& o) const {
        return chain == o.chain && pos == o.pos && spine == o.spine;
    }
    bool operator!=(const RepairKey& o) const { return !(*this == o); }
};

class RepairDriver {
public:
    using PeerId = CarrierPeerNode::PeerId;
    // Invoked with NO lock held once a repair finished (either way). `bid` is
    // the block the repair was armed for; the daemon re-drives that peer win.
    using RedriveFn = std::function<void(const std::string& bid, const RepairResult&)>;
    using LogFn     = std::function<void(bool /*warn*/, const std::string&)>;

    RepairDriver(SupplyRequester& fetch, const IMainchainIndex& index,
                 std::uint32_t chain, ::v37::LaneParams params)
        : m_fetch(fetch), m_index(index), m_chain(chain), m_params(std::move(params)) {}

    void set_redrive(RedriveFn f) { std::lock_guard<std::mutex> lk(m_mtx); m_redrive = std::move(f); }
    void set_log(LogFn f)         { std::lock_guard<std::mutex> lk(m_mtx); m_log = std::move(f); }
    RepairStats stats() const     { std::lock_guard<std::mutex> lk(m_mtx); return m_stats; }
    std::size_t in_flight() const { std::lock_guard<std::mutex> lk(m_mtx); return m_jobs.size(); }
    std::size_t cached() const    { std::lock_guard<std::mutex> lk(m_mtx); return m_done.size(); }

    // ── the SYNCHRONOUS read the cut-miss arm makes ─────────────────────────
    // "Do you already hold a VERIFIED projection at exactly this cut?" This is
    // what XbtcNode::set_repair_source() is bound to. It returns a view ONLY
    // when a completed replay proved it against the winner's own digest, and it
    // NEVER blocks the arm: on the first (un-repaired) pass it answers nullptr,
    // the arm refuses exactly as it does today, and the S3 re-drive retries once
    // the async repair lands.
    std::shared_ptr<const SettlementView> verified_view(std::uint32_t chain,
                                                        std::uint64_t pos,
                                                        const ::v37::bytes32& spine) const {
        std::lock_guard<std::mutex> lk(m_mtx);
        auto it = m_done.find(RepairKey{chain, pos, spine});
        return it == m_done.end() ? nullptr : it->second;
    }

    // ── arm a repair for a refused peer win ─────────────────────────────────
    // Returns true iff a fetch was actually started. Safe to call on every
    // refusal: a cut already cached or already in flight is coalesced, and a cut
    // whose only peer is busy serving another repair is QUEUED, never merged
    // into somebody else's job.
    bool arm(PeerId peer, const std::string& bid, std::uint64_t pos,
             const ::v37::bytes32& spine) {
        const RepairKey k{m_chain, pos, spine};
        // Read the transport's own per-peer slot BEFORE taking our lock, so we
        // never hold m_mtx across the requester's mutex.
        const bool channel_busy = m_fetch.busy(peer);
        {
            std::lock_guard<std::mutex> lk(m_mtx);
            if (m_done.count(k) || m_jobs.count(k)) { ++m_stats.coalesced; return false; }

            // ── ★ THE QUEUE, NOT THE OVERWRITE ──────────────────────────────
            // This peer is already serving a live repair (ours, per m_by_peer,
            // or the channel's, per the requester's outstanding slot). Touching
            // m_by_peer here is precisely the write that used to orphan that
            // repair, so we touch NOTHING: no binding, no job, no coalesce.
            // The cut is remembered as PENDING and re-armed by drain_deferred()
            // the moment the peer falls free; if the queue is full it is simply
            // refused, and a later S3 re-offer arms it cleanly because no state
            // says it is in flight.
            auto pit = m_by_peer.find(peer);
            const bool we_are_serving =
                (pit != m_by_peer.end() && m_jobs.count(pit->second) != 0);
            if (we_are_serving || channel_busy) {
                if (m_deferred.count(k) || m_deferred.size() < kMaxDeferred) {
                    m_deferred[k] = Deferred{peer, bid};
                    ++m_stats.deferred;
                } else {
                    ++m_stats.deferred_drop;
                }
                return false;
            }

            Job j;
            j.key  = k;
            j.bid  = bid;
            j.peer = peer;
            m_jobs.emplace(k, std::move(j));
            m_deferred.erase(k);                   // it is live now, not queued
            ++m_stats.armed;
            // ── ★ BIND BEFORE THE ASK ───────────────────────────────────────
            // The answer is delivered by the transport READER thread, which is
            // NOT in general the thread that armed. Binding after the ask
            // returned therefore left a cross-thread window in which the reply
            // beat the bind and on_order() dropped it — a zombie job with no
            // reply ever coming. Writing the binding here closes that window,
            // and cannot orphan anybody: the queue gate above has already
            // returned for every peer that is serving, so the only binding
            // this line can replace is a dead one.
            m_by_peer[peer] = k;
        }
        // Ask for the winner's order over [0, P). `spine` is the commitment we
        // are asking the server to stand behind; the REPLAY, not either side's
        // claim, is what decides whether it holds.
        if (!m_fetch.request_order(peer, m_chain, 0, pos, spine)) {
            bump_fetch_failed();
            // ── ★ THE ROLLBACK ──────────────────────────────────────────────
            // The ask never went out, so nothing will ever answer it. finish()
            // drops the job and — BY JOB IDENTITY — the binding written above,
            // which is exactly the rollback this needs: the peer is left as it
            // was before this arm, no other job's binding is touched, and
            // whatever was queued behind the peer drains.
            finish(k, RepairResult{});             // refused locally: fail closed
            return false;
        }
        return true;
    }

    // How many cuts are queued behind a busy peer. Diagnostics only.
    std::size_t deferred() const {
        std::lock_guard<std::mutex> lk(m_mtx);
        return m_deferred.size();
    }
    // How many peers currently hold a repair binding. This is the number the
    // liveness invariant is ABOUT: an in-flight job must still be reachable
    // from its peer when the reply lands, so a job whose binding was erased by
    // somebody else's arm shows up here as a missing binding, not merely as a
    // job that happens to be counted by in_flight().
    std::size_t bindings() const {
        std::lock_guard<std::mutex> lk(m_mtx);
        return m_by_peer.size();
    }

    // ── SupplyRequester callbacks ───────────────────────────────────────────
    void on_order(PeerId peer, const CtrlOrder& o) {
        RepairKey k;
        bool fail = false, more = false, go = false;
        std::uint64_t from = 0;
        {
            std::lock_guard<std::mutex> lk(m_mtx);
            auto pit = m_by_peer.find(peer);
            if (pit == m_by_peer.end()) return;
            k = pit->second;
            auto jit = m_jobs.find(k);
            if (jit == m_jobs.end()) return;
            Job& j = jit->second;
            if (o.status != CtrlOrderStatus::OK) {
                // BELOW_HORIZON lands here: the server no longer retains lane
                // position 0, so a whole-prefix replay is impossible and we
                // refuse rather than repair a suffix.
                ++m_stats.order_failed;
                fail = true;
            } else {
                for (const VaultOrderId& v : o.ids) j.order.push_back(v);
                if (!o.ids.empty() && o.p_served < k.pos) {
                    // A TRUNCATED order (the server's per-answer id cap). Ask
                    // again from where it stopped; the requester's slot for this
                    // peer was released before this callback, so re-arming it
                    // here is safe and keeps the walk on one peer.
                    more = true;
                    from = o.p_served;
                } else if (j.order.empty()) {
                    ++m_stats.order_failed;
                    fail = true;
                } else {
                    go = true;
                }
            }
        }
        if (fail) { finish(k, RepairResult{}); return; }
        if (more) {
            if (!m_fetch.request_order(peer, m_chain, from, k.pos, k.spine)) {
                bump_fetch_failed();
                finish(k, RepairResult{});
            }
            return;
        }
        if (go) start_frame_fetch(peer, k);
    }

    void on_frames(PeerId peer, const std::vector<VerifiedFrame>& v) {
        RepairKey k;
        bool chunk_done = false, next_chunk = false;
        {
            std::lock_guard<std::mutex> lk(m_mtx);
            auto pit = m_by_peer.find(peer);
            if (pit == m_by_peer.end()) return;
            k = pit->second;
            auto jit = m_jobs.find(k);
            if (jit == m_jobs.end()) return;
            Job& j = jit->second;
            for (const VerifiedFrame& f : v) {
                j.frames[f.id] = f.frame;
                ++m_stats.frames_fetched;
            }
            chunk_done = true;
            for (const ::v37::bytes32& id : j.chunk)
                if (!j.frames.count(id)) { chunk_done = false; break; }
            if (!chunk_done) return;               // the ask is still being served
            next_chunk = j.fetch_at < j.wanted.size();
        }
        // The ask this chunk belonged to is exhausted (a TRUNCATED reply leaves
        // ids missing and returns above), so the requester's per-peer slot is
        // free and the next GETFRAMES can be armed from here directly.
        if (next_chunk) { start_frame_fetch(peer, k); return; }
        run_replay(k);
    }

    // Ids the server HOLDS but cannot put on this channel. The replay needs
    // every carrier in the prefix, so this is a hard repair failure, not a
    // partial one — named, counted, and refused.
    void on_unservable(PeerId peer, const std::vector<::v37::bytes32>& ids) {
        std::lock_guard<std::mutex> lk(m_mtx);
        m_stats.unservable += ids.size();
        auto pit = m_by_peer.find(peer);
        if (pit == m_by_peer.end()) return;
        auto jit = m_jobs.find(pit->second);
        if (jit != m_jobs.end()) jit->second.hard_fail = true;
    }

    void on_fail(PeerId peer, SupplyFailure) {
        RepairKey k;
        {
            std::lock_guard<std::mutex> lk(m_mtx);
            auto pit = m_by_peer.find(peer);
            if (pit == m_by_peer.end()) return;
            k = pit->second;
            if (!m_jobs.count(k)) return;
            ++m_stats.fetch_failed;
        }
        finish(k, RepairResult{});
    }

    void forget_peer(PeerId peer) {
        RepairKey k;
        {
            std::lock_guard<std::mutex> lk(m_mtx);
            // A cut queued behind THIS peer can never run: the only node that
            // offered to serve it is gone. Drop it (counted) rather than leave a
            // queue entry aimed at a dead peer; a reconnecting peer's re-offer
            // arms it again from scratch.
            for (auto it = m_deferred.begin(); it != m_deferred.end();) {
                if (it->second.peer == peer) {
                    it = m_deferred.erase(it);
                    ++m_stats.deferred_drop;
                } else {
                    ++it;
                }
            }
            auto pit = m_by_peer.find(peer);
            if (pit == m_by_peer.end()) return;
            k = pit->second;
            if (!m_jobs.count(k)) { m_by_peer.erase(pit); return; }
        }
        finish(k, RepairResult{});
    }

private:
    // A cut we want repaired, waiting for its only serving peer to fall free.
    // It is NOT a job: it holds no binding and no fetch state, so it can never
    // be mistaken for something in flight and never swallows a later re-offer.
    struct Deferred {
        PeerId      peer = 0;
        std::string bid;
    };

    struct Job {
        RepairKey                   key;
        std::string                 bid;
        PeerId                      peer = 0;
        std::vector<VaultOrderId>   order;
        std::vector<::v37::bytes32> wanted;     // every carrier id in [0, P)
        std::vector<::v37::bytes32> chunk;      // the ids of the GETFRAMES in flight
        std::size_t                 fetch_at = 0;
        std::map<::v37::bytes32, std::vector<std::uint8_t>> frames;
        bool                        hard_fail = false;
    };
    void bump_fetch_failed() {
        std::lock_guard<std::mutex> lk(m_mtx);
        ++m_stats.fetch_failed;
    }

    void start_frame_fetch(PeerId peer, const RepairKey& k) {
        std::vector<::v37::bytes32> chunk;
        bool empty_ask = false;
        {
            std::lock_guard<std::mutex> lk(m_mtx);
            auto jit = m_jobs.find(k);
            if (jit == m_jobs.end()) return;
            Job& j = jit->second;
            if (j.wanted.empty())
                for (const VaultOrderId& v : j.order)
                    if (v.pos < k.pos) j.wanted.push_back(v.id);
            while (j.fetch_at < j.wanted.size() &&
                   chunk.size() < static_cast<std::size_t>(kCtrlMaxIdsPerFetch))
                chunk.push_back(j.wanted[j.fetch_at++]);
            j.chunk = chunk;
            empty_ask = chunk.empty();
        }
        if (empty_ask) { run_replay(k); return; }
        if (!m_fetch.request_frames(peer, m_chain, chunk)) {
            bump_fetch_failed();
            finish(k, RepairResult{});
        }
    }

    void run_replay(const RepairKey& k) {
        RepairInput in;
        bool hard_fail = false;
        {
            std::lock_guard<std::mutex> lk(m_mtx);
            auto jit = m_jobs.find(k);
            if (jit == m_jobs.end()) return;
            Job& j = jit->second;
            hard_fail = j.hard_fail;
            if (!hard_fail) {
                in.chain        = k.chain;
                in.target_pos   = k.pos;
                in.spine_digest = k.spine;
                in.params       = m_params;
                in.order        = j.order;
                in.frames       = j.frames;
                ++m_stats.replayed;
            }
        }
        if (hard_fail) { finish(k, RepairResult{}); return; }
        // The replay runs with NO lock held: it drives a scratch V37Engine.
        const RepairResult r = replay_to_cut(in, m_index);
        finish(k, r);
    }

    // The single completion point. Records the outcome, drops the job, and then
    // — with no lock held — fires the S3 RE-DRIVE so the one-shot refused peer
    // win is retried now that a verified view may exist, and releases whatever
    // was queued behind the peer this job was using.
    void finish(const RepairKey& k, const RepairResult& r) {
        std::string bid;
        RedriveFn cb;
        LogFn log;
        {
            std::lock_guard<std::mutex> lk(m_mtx);
            auto jit = m_jobs.find(k);
            if (jit == m_jobs.end()) return;
            bid = jit->second.bid;
            // ── ★ ERASE OUR OWN BINDING, AND ONLY OUR OWN ───────────────────
            // An erase by bare peer id drops whatever binding that peer holds
            // NOW, which need not be this job's: that is how a second, locally
            // refused arm used to orphan a live repair. Keyed by job identity,
            // a finishing job can only ever release itself — and a job that
            // never got as far as binding (request_order refused) releases
            // nothing at all.
            auto pit = m_by_peer.find(jit->second.peer);
            if (pit != m_by_peer.end() && pit->second == k) m_by_peer.erase(pit);
            m_jobs.erase(jit);
            if (r.ok()) { m_done[k] = r.view; ++m_stats.repaired; }
            else        { ++m_stats.refused; }
            ++m_stats.redriven;
            cb  = m_redrive;
            log = m_log;
        }
        if (log)
            log(!r.ok(),
                std::string("[v37-repair] cut P=") + std::to_string(k.pos) + " " +
                    (r.ok() ? "REPAIRED" : "REFUSED") + " (" +
                    repair_outcome_name(r.outcome) + ")");
        if (cb) cb(bid, r);
        drain_deferred();
    }

    // ── ★ THE QUEUE DRAIN ───────────────────────────────────────────────────
    // Re-arm the cuts that were queued because their only peer was busy. Runs
    // with NO lock held (arm() takes its own), is bounded, is re-entrancy
    // guarded — arm() can call finish(), which calls back in here — and never
    // retries the same key twice in one pass, so a cut that immediately re-
    // defers cannot spin. Anything still queued when this returns is picked up
    // by the next completion, or by a later S3 re-offer.
    void drain_deferred() {
        {
            std::lock_guard<std::mutex> lk(m_mtx);
            if (m_draining) return;
            m_draining = true;
        }
        std::set<RepairKey> tried;
        for (std::size_t round = 0; round < kMaxDrainRounds; ++round) {
            RepairKey k{};
            Deferred  d;
            bool      have = false;
            {
                std::lock_guard<std::mutex> lk(m_mtx);
                for (auto it = m_deferred.begin(); it != m_deferred.end();) {
                    if (tried.count(it->first)) { ++it; continue; }
                    // It landed some other way (cached, or armed directly).
                    if (m_done.count(it->first) || m_jobs.count(it->first)) {
                        it = m_deferred.erase(it);
                        continue;
                    }
                    auto pit = m_by_peer.find(it->second.peer);
                    if (pit != m_by_peer.end() && m_jobs.count(pit->second)) {
                        ++it;                       // its peer is still serving
                        continue;
                    }
                    k = it->first;
                    d = it->second;
                    it = m_deferred.erase(it);
                    have = true;
                    ++m_stats.resumed;
                    break;
                }
            }
            if (!have) break;
            tried.insert(k);
            (void)arm(d.peer, d.bid, k.pos, k.spine);
        }
        std::lock_guard<std::mutex> lk(m_mtx);
        m_draining = false;
    }

    // The queue is a liveness aid, not a buffer: a small bound keeps a peer
    // that floods us with distinct cuts from growing it without limit. An
    // over-the-bound cut is refused cleanly and stays re-armable.
    static constexpr std::size_t kMaxDeferred    = 64;
    static constexpr std::size_t kMaxDrainRounds = kMaxDeferred + 1;

    mutable std::mutex          m_mtx;
    SupplyRequester&            m_fetch;
    const IMainchainIndex&      m_index;
    std::uint32_t               m_chain;
    ::v37::LaneParams           m_params;
    RedriveFn                   m_redrive;
    LogFn                       m_log;
    RepairStats                 m_stats;
    std::map<RepairKey, Job>    m_jobs;
    std::map<PeerId, RepairKey> m_by_peer;
    std::map<RepairKey, Deferred> m_deferred;   // cuts waiting on a busy peer
    bool                        m_draining = false;
    std::map<RepairKey, std::shared_ptr<const SettlementView>> m_done;
};

} // namespace c2pool::v37n
