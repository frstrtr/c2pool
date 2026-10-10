// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// src/impl/xmr/pathb/pathb_store.hpp
// Path B, slice S4w-a: the node's own store (node-local records; a different
// layout forks nothing) and its load at a restart.
//
//   Kinds (beside K_BMMR 11, K_BLEAF 12, K_BLHASH 13 of pathb_bin_store.hpp);
//   every value starts u8 schema 1 | u8 kind:
//   14 K_PHEAD     v37s:phead:<chain %010u>
//                  u8 network | u32 chain_id | u8 form | u64 H | b32 block_hash
//                  | u8 len | headline | b32 pool_genesis | b32 pool_id
//                  | b32 genesis_id | u64 H(0) | b32 G | u64 best_pos | b32 best_id
//                  | u64 journal_base | u64 first_pos | u64 root_pos
//                  | u64 base_pos | u64 base_leaf_count | u8 n | n x peak
//                  | S_base[134]
//   15 K_PCARRIER  v37s:pcar:<chain>:<pos %020u>
//                  b32 id | b32 parent | u64 pos | u64 h | u64 d
//                  | u128 cum_work | u64 H | u8 has_state | S_x[134]
//                  | u8 kind (0 none, 1 carrier body, 2 header) | u32 len
//                  | bytes | u16 n | n x (u64 bin | u64 p_own | u8 live)
//   16 K_AR        v37s:ar:<chain>:<h_act %020u>    u16 e | u64 h_act | b32 digest
//   The poison mark v37s:poison:<chain> (one byte): a store write failed.
//   The directory of a store is named by its pool_id and G (store_dir_name).
//
//   One batch per new best-chain position: K_PCARRIER(x), the lane records
//   sealed at x and K_BMMR (BinStore), K_AR if x activates, K_PHEAD. A switch
//   is one batch: K_PCARRIER and K_AR above the fork deleted, the new branch
//   written. A joined store and the first batch of a pool launched here are
//   written into an empty store (every key of its prefixes deleted in the same
//   batch). A failed write leaves the poison mark (a batch of its own).
//
//   pathb_load (in order; any fault: the joiner path):
//     0. no poison mark;
//     1. K_PHEAD decodes and names the directory's pool_id and G (NoHead only
//        when no key of the store exists; an unreadable K_PHEAD, or one absent
//        beside other keys of the store, is a load failure);
//     2. K_PCARRIER from first_pos to the tip, each linked to the one below;
//        the lane records in their prefix form (the MMR from the store base);
//     3. the anchors: the tip carrier's committed mmr_root == the root over
//        lc(H(tip - 1)) leaves; its receipts_root == the fold of its carried
//        ids with rs_root(S_{tip - 1});
//     4. AR: ascending, at or below the tip, consistent with S_tip (or the
//        joiner seed of a joined store);
//     5. q0 = max(base_pos + 1, tip - J + 1); phase 1 (positions s1 .. q0 - 1,
//        s1 = the first position above the root with H(x) > H(q0 - 1) - F -
//        Fresh): the stored placements whose bin is open at q0 - 1, with their
//        stored p_own and live, each body checked against its stored id,
//        parent link and receipts_root fold; phase 2 (q0 .. tip): every position placed again
//        as a live node places it (tree, BinStore, rs_step_at, AR), its
//        stored S, d, cum_work, H, live flags, mmr_root and AR row compared;
//     6. the lane records at or beyond leaf_count deleted (one batch).
//
// Header-only. Not included by any running component; included by its KATs only.
// ---------------------------------------------------------------------------
#pragma once

#include <algorithm>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "impl/xmr/native/contracts/types.hpp"  // U128

#include "pathb_admit.hpp"           // placement_of, CarrierBodies, carrier_frame
#include "pathb_bin_store.hpp"
#include "pathb_fork_choice.hpp"
#include "pathb_kv.hpp"
#include "pathb_pool_identity.hpp"
#include "pathb_ratchet_activation.hpp"
#include "pathb_ratchet_state.hpp"

namespace c2pool::xmr::pathb {

inline constexpr std::uint8_t K_PHEAD = 14;
inline constexpr std::uint8_t K_PCARRIER = 15;
inline constexpr std::uint8_t K_AR = 16;

namespace store_keys {
inline std::string phead(std::uint32_t c) { return "v37s:phead:" + lane_keys::chain_fmt(c); }
inline std::string pcarrier_prefix(std::uint32_t c) { return "v37s:pcar:" + lane_keys::chain_fmt(c) + ":"; }
inline std::string pcarrier(std::uint32_t c, std::uint64_t pos) { return pcarrier_prefix(c) + lane_keys::index_fmt(pos); }
inline std::string ar_prefix(std::uint32_t c) { return "v37s:ar:" + lane_keys::chain_fmt(c) + ":"; }
inline std::string ar(std::uint32_t c, std::uint64_t h_act) { return ar_prefix(c) + lane_keys::index_fmt(h_act); }
// The poison mark: a store write failed; the next load is a load failure.
inline std::string poison(std::uint32_t c) { return "v37s:poison:" + lane_keys::chain_fmt(c); }
}  // namespace store_keys

// The directory of a store: <pool_id hex>-<G hex>.
inline std::string store_dir_name(const Hash32& pool_id, const Hash32& rules_g) {
    return pid_detail::hex(pool_id) + "-" + pid_detail::hex(rules_g);
}

// A LaneBatch into a KV batch, committed synced.
inline bool commit_lane_batch(PathbKv& kv, const LaneBatch& b) {
    std::unique_ptr<PathbKvBatch> w = kv.batch();
    if (!w) return false;
    for (const auto& [k, v] : b.ops) {
        if (v)
            w->put(k, *v);
        else
            w->remove(k);
    }
    return w->commit_sync();
}

// ---------------------------------------------------------------------------
// K_PHEAD
// ---------------------------------------------------------------------------
struct StoreHead {
    PoolIdentity identity;            // network, chain_id, form, H, spec, pool_genesis, pool_id
    Hash32 genesis_id{};              // position 0: pool_id
    std::uint64_t h0 = 0;             // H(0) = H + 1 = b0
    Hash32 rules_g{};                 // the compiled G
    std::uint64_t best_pos = 0;
    Hash32 best_id{};
    std::uint64_t journal_base = 0;
    std::uint64_t first_pos = 0;      // the lowest K_PCARRIER held (0; a joined store: x0 - N_rt)
    std::uint64_t root_pos = 0;       // the lowest position with its S (0; a joined store: x0 - 1)
    std::uint64_t base_pos = 0;       // the store base (0; a joined store: L_j)
    std::uint64_t base_leaf_count = 0;
    std::vector<Hash32> base_peaks;
    RatchetStateBytes s_base{};

    friend bool operator==(const StoreHead&, const StoreHead&) = default;
};

inline std::string encode_phead(const StoreHead& h) {
    lane_rec::Writer w;
    w.hdr(K_PHEAD);
    w.u8(static_cast<std::uint8_t>(h.identity.network));
    w.u32(h.identity.chain_id);
    w.u8(static_cast<std::uint8_t>(h.identity.form));
    w.u64(h.identity.height);
    w.bytes(h.identity.spec.block_hash);
    w.u8(static_cast<std::uint8_t>(h.identity.spec.headline.size()));
    w.s.append(h.identity.spec.headline);
    w.bytes(h.identity.pool_genesis);
    w.bytes(h.identity.pool_id);
    w.bytes(h.genesis_id);
    w.u64(h.h0);
    w.bytes(h.rules_g);
    w.u64(h.best_pos);
    w.bytes(h.best_id);
    w.u64(h.journal_base);
    w.u64(h.first_pos);
    w.u64(h.root_pos);
    w.u64(h.base_pos);
    w.u64(h.base_leaf_count);
    w.u8(static_cast<std::uint8_t>(h.base_peaks.size()));
    for (const Hash32& p : h.base_peaks) w.bytes(p);
    w.bytes(h.s_base);
    return w.s;
}

inline std::optional<StoreHead> decode_phead(const std::string& v) {
    lane_rec::Reader r(v);
    if (!lane_rec::read_hdr(r, K_PHEAD)) return std::nullopt;
    StoreHead h;
    const std::uint8_t net = r.u8();
    if (net > static_cast<std::uint8_t>(LaneNet::Regtest)) return std::nullopt;
    h.identity.network = static_cast<LaneNet>(net);
    h.identity.chain_id = r.u32();
    const std::uint8_t form = r.u8();
    if (form != static_cast<std::uint8_t>(GenesisForm::Derived) && form != static_cast<std::uint8_t>(GenesisForm::Raw))
        return std::nullopt;
    h.identity.form = static_cast<GenesisForm>(form);
    h.identity.height = r.u64();
    h.identity.spec.block_hash = r.bytes<kHashBytes>();
    const std::uint8_t len = r.u8();
    if (!r.need(len)) return std::nullopt;
    h.identity.spec.headline.assign(v, r.o, len);
    r.o += len;
    if (h.identity.form == GenesisForm::Derived) h.identity.spec.height = h.identity.height;
    h.identity.pool_genesis = r.bytes<kHashBytes>();
    h.identity.pool_id = r.bytes<kHashBytes>();
    h.genesis_id = r.bytes<kHashBytes>();
    h.h0 = r.u64();
    h.rules_g = r.bytes<kHashBytes>();
    h.best_pos = r.u64();
    h.best_id = r.bytes<kHashBytes>();
    h.journal_base = r.u64();
    h.first_pos = r.u64();
    h.root_pos = r.u64();
    h.base_pos = r.u64();
    h.base_leaf_count = r.u64();
    const std::uint8_t np = r.u8();
    if (!r.ok || np != popcount64(h.base_leaf_count) || np > r.remaining() / kHashBytes) return std::nullopt;
    h.base_peaks.resize(np);
    for (Hash32& p : h.base_peaks) p = r.bytes<kHashBytes>();
    h.s_base = r.bytes<rs_layout::kSize>();
    if (!r.done()) return std::nullopt;
    return h;
}

// ---------------------------------------------------------------------------
// K_PCARRIER
// ---------------------------------------------------------------------------
enum class RecordBody : std::uint8_t { None = 0, Carrier = 1, Header = 2 };

struct StoredPlacement {
    std::uint64_t bin = 0;
    std::uint64_t p_own = 0;
    bool live = false;

    friend bool operator==(const StoredPlacement&, const StoredPlacement&) = default;
};

struct CarrierRecord {
    Hash32 id{};
    Hash32 parent{};
    std::uint64_t pos = 0;
    std::uint64_t h = 0;
    std::uint64_t d = 0;
    ::c2pool::xmr::native::U128 cum_work{};
    std::uint64_t H = 0;
    std::optional<RatchetStateBytes> state;  // S_x (absent for a joined store's prefix headers)
    RecordBody kind = RecordBody::None;
    std::vector<std::uint8_t> bytes;         // the carrier body, or its header
    std::vector<StoredPlacement> placements; // the carried list (canonical order), then the carrier

    friend bool operator==(const CarrierRecord&, const CarrierRecord&) = default;
};

inline std::string encode_pcarrier(const CarrierRecord& c) {
    lane_rec::Writer w;
    w.hdr(K_PCARRIER);
    w.bytes(c.id);
    w.bytes(c.parent);
    w.u64(c.pos);
    w.u64(c.h);
    w.u64(c.d);
    w.u64(c.cum_work.lo);
    w.u64(c.cum_work.hi);
    w.u64(c.H);
    w.u8(c.state ? 1 : 0);
    w.bytes(c.state.value_or(RatchetStateBytes{}));
    w.u8(static_cast<std::uint8_t>(c.kind));
    w.u32(static_cast<std::uint32_t>(c.bytes.size()));
    w.s.append(reinterpret_cast<const char*>(c.bytes.data()), c.bytes.size());
    w.u8(static_cast<std::uint8_t>(c.placements.size() & 0xffu));
    w.u8(static_cast<std::uint8_t>(c.placements.size() >> 8));
    for (const StoredPlacement& p : c.placements) {
        w.u64(p.bin);
        w.u64(p.p_own);
        w.u8(p.live ? 1 : 0);
    }
    return w.s;
}

inline constexpr std::size_t kStoredPlacementBytes = kU64Bytes + kU64Bytes + kU8Bytes;

inline std::optional<CarrierRecord> decode_pcarrier(const std::string& v) {
    lane_rec::Reader r(v);
    if (!lane_rec::read_hdr(r, K_PCARRIER)) return std::nullopt;
    CarrierRecord c;
    c.id = r.bytes<kHashBytes>();
    c.parent = r.bytes<kHashBytes>();
    c.pos = r.u64();
    c.h = r.u64();
    c.d = r.u64();
    c.cum_work.lo = r.u64();
    c.cum_work.hi = r.u64();
    c.H = r.u64();
    const std::uint8_t has_state = r.u8();
    const RatchetStateBytes s = r.bytes<rs_layout::kSize>();
    if (has_state > 1) return std::nullopt;
    if (has_state == 1) c.state = s;
    const std::uint8_t kind = r.u8();
    if (kind > static_cast<std::uint8_t>(RecordBody::Header)) return std::nullopt;
    c.kind = static_cast<RecordBody>(kind);
    const std::uint32_t len = r.u32();
    if (!r.need(len)) return std::nullopt;
    c.bytes.assign(v.begin() + static_cast<std::ptrdiff_t>(r.o), v.begin() + static_cast<std::ptrdiff_t>(r.o + len));
    r.o += len;
    const std::uint32_t n_lo = r.u8();
    const std::uint32_t n_hi = r.u8();
    const std::uint32_t n = n_lo | (n_hi << 8);
    if (!r.ok || n > r.remaining() / kStoredPlacementBytes) return std::nullopt;
    c.placements.resize(n);
    for (StoredPlacement& p : c.placements) {
        p.bin = r.u64();
        p.p_own = r.u64();
        const std::uint8_t live = r.u8();
        if (live > 1) return std::nullopt;
        p.live = live == 1;
    }
    if (!r.done()) return std::nullopt;
    return c;
}

// The carrier body of a record (kind Carrier), its own body's header (kind
// Header); nullopt: none or it does not decode.
inline std::optional<CarrierBodyV3> record_body(const CarrierRecord& c, const LaneParams& p) {
    if (c.kind != RecordBody::Carrier) return std::nullopt;
    CarrierBodyV3 b;
    if (decode_carrier_body_v3(c.bytes.data(), c.bytes.size(),
                               CarrierLimits{receipt_max(UINT8_MAX), p.r_max}, b) != WireError::None)
        return std::nullopt;
    return b;
}

// ---------------------------------------------------------------------------
// K_AR
// ---------------------------------------------------------------------------
inline std::string encode_ar_row(const ActivationRow& a) {
    lane_rec::Writer w;
    w.hdr(K_AR);
    w.u8(static_cast<std::uint8_t>(a.epoch & 0xffu));
    w.u8(static_cast<std::uint8_t>(a.epoch >> 8));
    w.u64(a.h_act);
    w.bytes(a.rules_digest);
    return w.s;
}

inline std::optional<ActivationRow> decode_ar_row(const std::string& v) {
    lane_rec::Reader r(v);
    if (!lane_rec::read_hdr(r, K_AR)) return std::nullopt;
    ActivationRow a;
    const std::uint32_t e_lo = r.u8();
    const std::uint32_t e_hi = r.u8();
    a.epoch = static_cast<std::uint16_t>(e_lo | (e_hi << 8));
    a.h_act = r.u64();
    a.rules_digest = r.bytes<kHashBytes>();
    if (!r.done()) return std::nullopt;
    return a;
}

// ---------------------------------------------------------------------------
// Writes
// ---------------------------------------------------------------------------
inline void put_position(LaneBatch& b, std::uint32_t chain, const CarrierRecord& rec,
                         const std::optional<ActivationRow>& ar_row) {
    b.put(store_keys::pcarrier(chain, rec.pos), encode_pcarrier(rec));
    if (ar_row) b.put(store_keys::ar(chain, ar_row->h_act), encode_ar_row(*ar_row));
}

// A switch: K_PCARRIER of fork + 1 .. old_tip and K_AR rows above the fork deleted.
inline void delete_above(LaneBatch& b, std::uint32_t chain, std::uint64_t fork, std::uint64_t old_tip,
                         const ActivationRecord& ar_before) {
    for (std::uint64_t x = fork + 1; x <= old_tip; ++x) b.del(store_keys::pcarrier(chain, x));
    for (const ActivationRow& a : ar_before.rows())
        if (a.h_act > fork) b.del(store_keys::ar(chain, a.h_act));
}

inline void put_head(LaneBatch& b, std::uint32_t chain, const StoreHead& h) { b.put(store_keys::phead(chain), encode_phead(h)); }

// The record of a placed carrier at its position: the tree node's values,
// the body and the placements as the store holds them.
inline CarrierRecord record_of(const CarrierNode& n, const CarrierBodyV3* body, const LaneDelta* delta) {
    CarrierRecord c;
    c.id = n.id;
    c.parent = n.parent;
    c.pos = n.pos;
    c.h = n.h;
    c.d = n.d;
    c.cum_work = n.cum_work;
    c.H = n.H;
    c.state = encode_ratchet_state(n.rs);
    if (body != nullptr) {
        c.kind = RecordBody::Carrier;
        encode_carrier_body_v3(*body, UINT8_MAX, c.bytes);
    }
    if (delta != nullptr)
        for (const Placement& x : delta->placed) c.placements.push_back(StoredPlacement{x.bin, x.p_own, x.live});
    return c;
}

// The head of a store at its best tip (the identity fields kept).
inline void head_at_tip(StoreHead& h, const BinStore& store) {
    h.best_pos = store.tip_pos();
    h.best_id = store.best_tip();
    h.journal_base = store.base_pos();
}

// The first batch of a pool launched here: K_PCARRIER(0) (the genesis node,
// its S), the lane records of position 0, K_PHEAD.
inline LaneBatch genesis_batch(std::uint32_t chain, StoreHead& head, const CarrierTree& tree, const BinStore& store) {
    LaneBatch b;
    store.write_all(b);
    const CarrierNode& g = tree.genesis();
    put_position(b, chain, record_of(g, nullptr, nullptr), std::nullopt);
    head_at_tip(head, store);
    put_head(b, chain, head);
    return b;
}

// The batch of one new best-chain position (place_admitted Extended): its lane
// records (`lane`, filled by switch_best), K_PCARRIER(x), the AR row of x, K_PHEAD.
inline LaneBatch extension_batch(std::uint32_t chain, StoreHead& head, const CarrierTree& tree, const BinStore& store,
                                 const CarrierBodies& bodies, const Hash32& id, LaneBatch lane,
                                 const std::optional<ActivationRow>& row) {
    const CarrierNode* n = tree.find(id);
    if (n != nullptr) put_position(lane, chain, record_of(*n, bodies.get(id), store.delta(id)), row);
    head_at_tip(head, store);
    put_head(lane, chain, head);
    return lane;
}

// The batch of a switch by the journal from old_tip to the store's new best
// tip forking at `fork`: its lane records (`lane`, filled by switch_best),
// K_PCARRIER and K_AR above the fork deleted (AR before the rewind), the new
// branch written (`ar_after`: AR after the replay), K_PHEAD.
inline LaneBatch switch_batch(std::uint32_t chain, StoreHead& head, const CarrierTree& tree, const BinStore& store,
                              const CarrierBodies& bodies, std::uint64_t fork, std::uint64_t old_tip,
                              const ActivationRecord& ar_before, const ActivationRecord& ar_after, LaneBatch lane) {
    delete_above(lane, chain, fork, old_tip, ar_before);
    for (std::uint64_t x = fork + 1; x <= store.tip_pos(); ++x) {
        const std::optional<Hash32> id = store.best_at(x);
        const CarrierNode* n = id ? tree.find(*id) : nullptr;
        if (n == nullptr) continue;
        std::optional<ActivationRow> row;
        for (const ActivationRow& a : ar_after.rows())
            if (a.h_act == x) row = a;
        put_position(lane, chain, record_of(*n, bodies.get(*id), store.delta(*id)), row);
    }
    head_at_tip(head, store);
    put_head(lane, chain, head);
    return lane;
}

// The batch of an adoption (S4wD 3.3; the caller prepends clear_store_batch:
// an EMPTY store, its poison mark deleted with it): the adopted state at its
// tip L. The lane records from the MMR's first leaf on; K_PCARRIER of every
// position the store holds: the claimed prefix [first_pos, root_pos) as
// header records without S, the root (x0 - 1, or position 0 of a young chain)
// with its S, the span with its bodies and placements; every AR row; K_PHEAD
// with the store base: base_pos = L, base_leaf_count = first_leaf() =
// lc(H(x0 - 1)) and base_peaks its peaks (0 and none on a young chain),
// S_base = S_L. nullopt: a position the store names that the tree does not
// hold.
inline std::optional<LaneBatch> adoption_batch(std::uint32_t chain, StoreHead& head, const CarrierTree& tree,
                                               const BinStore& store, const CarrierBodies& bodies,
                                               const ActivationRecord& ar, std::uint64_t root_pos) {
    LaneBatch b;
    store.write_all(b);
    // the open-bin placements by carrier (a position below the journal holds no delta)
    std::map<Hash32, std::map<Hash32, StoredPlacement>> open;
    for (const auto& [bin, xs] : store.placements_by_bin())
        for (const Placement& x : xs) open[x.carrier][x.id] = StoredPlacement{x.bin, x.p_own, x.live};
    const std::uint64_t first = store.first_record_pos();
    for (std::uint64_t x = first; x <= store.tip_pos(); ++x) {
        const std::optional<Hash32> id = store.best_at(x);
        const CarrierNode* n = id ? tree.find(*id) : nullptr;
        if (n == nullptr) return std::nullopt;
        CarrierRecord c = record_of(*n, bodies.get(*id), store.delta(*id));
        const CarrierBodyV3* body = bodies.get(*id);
        if (x > root_pos && store.delta(*id) == nullptr && body != nullptr) {
            // a placement of a bin sealed at the tip: {0, 0, false} (a restart ingests the open bins only)
            const auto oc = open.find(*id);
            const auto sp = [&](const ReceiptBodyV3& r) {
                if (oc != open.end())
                    if (const auto it = oc->second.find(receipt_id(r)); it != oc->second.end()) return it->second;
                return StoredPlacement{};
            };
            c.placements.clear();
            for (const ReceiptBodyV3& r : body->carried) c.placements.push_back(sp(r));
            c.placements.push_back(sp(body->own));
        }
        if (x < root_pos) {  // a claimed prefix header: no S, no body
            c.state.reset();
            c.kind = RecordBody::None;
            c.bytes.clear();
            c.placements.clear();
        }
        if (x > first)
            if (const std::optional<Hash32> below = store.best_at(x - 1)) c.parent = *below;
        put_position(b, chain, c, std::nullopt);
    }
    for (const ActivationRow& a : ar.rows()) b.put(store_keys::ar(chain, a.h_act), encode_ar_row(a));
    head_at_tip(head, store);
    head.first_pos = first;
    head.root_pos = root_pos;
    head.base_pos = store.tip_pos();
    head.base_leaf_count = store.first_leaf();
    head.base_peaks.clear();
    if (store.first_leaf() > 0) {
        const std::optional<std::vector<Hash32>> pk = store.best_mmr().prefix_peaks(store.first_leaf());
        if (!pk) return std::nullopt;
        head.base_peaks = *pk;
    }
    const CarrierNode* tip = tree.find(store.best_tip());
    if (tip == nullptr) return std::nullopt;
    head.s_base = encode_ratchet_state(tip->rs);
    put_head(b, chain, head);
    return b;
}

// The key prefixes of a store (its records, its lane records, its poison mark).
inline std::vector<std::string> store_prefixes(std::uint32_t chain) {
    return {store_keys::phead(chain),        store_keys::pcarrier_prefix(chain), store_keys::ar_prefix(chain),
            lane_keys::bmmr(chain),          lane_keys::blhash_prefix(chain),    lane_keys::bleaf_prefix(chain),
            store_keys::poison(chain)};
}

// An adoption (the first completed join, or a replacement by rule (4)) and the
// first batch of a pool launched here write into an empty store: every key of
// the store's prefixes deleted first.
inline bool clear_store_batch(PathbKv& kv, std::uint32_t chain, LaneBatch& b) {
    for (const std::string& prefix : store_prefixes(chain)) {
        if (!kv.for_each_prefix(prefix, [&](const std::string& k, const std::string&) {
                b.del(k);
                return true;
            }))
            return false;
    }
    return true;
}

// The batch of the poison mark (a store write failed).
inline LaneBatch poison_batch(std::uint32_t chain) {
    LaneBatch b;
    b.put(store_keys::poison(chain), std::string(1, '\x01'));
    return b;
}

// ---------------------------------------------------------------------------
// pathb_load
// ---------------------------------------------------------------------------
enum class StoreFault : std::uint8_t {
    None,
    NoHead,
    BadHead,
    Identity,   // K_PHEAD names another pool_id or G than its directory
    Records,    // a K_PCARRIER missing, torn, or not linked to the one below
    Lane,       // the lane records (load_lane_prefix)
    Anchor,     // the tip's committed mmr_root
    Fold,       // the tip's receipts_root fold
    Ar,         // AR inconsistent
    Phase1,     // a stored body below q0 fails its id, link or fold check
    Phase2,     // a replayed position differs from its record
    Scan,       // the KV scan failed
    Poisoned,   // the store's poison mark: a write failed before the last stop
};

struct LoadInputs {
    LaneParams p = kRuledLaneParams;
    RatchetParams rp = kRuledRatchetParams;
    EpochTable T;
    std::uint64_t journal_depth = 0;  // P-01
    std::uint32_t chain = 0;
};

struct LoadedState {
    StoreHead head;
    CarrierTree tree;
    BinStore store;
    ActivationRecord ar;
    CarrierBodies bodies;
    std::uint64_t q0 = 0;
    std::uint64_t phase1_from = 0;
    std::map<Hash32, XmrKeyRef> refs;  // the key references the restored placements and buckets hold, by identity
};

struct LoadResult {
    StoreFault fault = StoreFault::None;
    std::uint64_t at = 0;    // the position a Records / Phase1 / Phase2 fault names
    std::uint8_t check = 0;  // the check of that position that failed (diagnostics)
    std::optional<LoadedState> state;
};

namespace store_detail {

inline bool scan(PathbKv& kv, const std::string& prefix, LaneKv& out) {
    return kv.for_each_prefix(prefix, [&](const std::string& k, const std::string& v) {
        out[k] = v;
        return true;
    });
}

inline Placement placement_from(const ReceiptBodyV3& r, const StoredPlacement& sp, std::uint64_t q, const Hash32& carrier) {
    Placement x = admit_detail::placement_of(r, receipt_id(r), sp.bin, sp.p_own);
    x.q = q;
    x.live = sp.live;
    x.carrier = carrier;
    return x;
}

}  // namespace store_detail

// The phase-1 start: the first position x >= lo with H(x) > floor_h.
inline std::uint64_t first_above(const std::vector<std::uint64_t>& records, std::uint64_t first_pos, std::uint64_t lo,
                                 std::uint64_t floor_h) {
    std::uint64_t x = std::max(lo, first_pos);
    while (x - first_pos < records.size() && records[x - first_pos] <= floor_h) ++x;
    return x;
}

// The store of directory `dir_pool_id` / `dir_rules_g` at a restart.
inline LoadResult pathb_load(PathbKv& kv, const Hash32& dir_pool_id, const Hash32& dir_rules_g, const LoadInputs& in) {
    LoadResult out;
    const auto fail = [&out](StoreFault f, std::uint64_t at = 0, std::uint8_t check = 0) {
        out.fault = f;
        out.at = at;
        out.check = check;
        out.state.reset();
        return std::move(out);
    };
    const LaneParams& p = in.p;
    // 0. the poison mark
    {
        const KvRead pm = kv.read(store_keys::poison(in.chain));
        if (pm.status == KvRead::Status::Value) return fail(StoreFault::Poisoned);
        if (pm.status == KvRead::Status::Error) return fail(StoreFault::Scan);
    }
    // 1. K_PHEAD: absent in an empty store only; unreadable, or absent beside other keys of the store: a load failure
    const KvRead hv = kv.read(store_keys::phead(in.chain));
    if (hv.status == KvRead::Status::Error) return fail(StoreFault::BadHead);
    if (hv.status == KvRead::Status::Absent) {
        bool any = false;
        for (const std::string& prefix : store_prefixes(in.chain))
            if (!kv.for_each_prefix(prefix, [&any](const std::string&, const std::string&) {
                    any = true;
                    return false;
                }))
                return fail(StoreFault::Scan);
        return fail(any ? StoreFault::BadHead : StoreFault::NoHead);
    }
    const std::optional<StoreHead> head = decode_phead(hv.value);
    if (!head) return fail(StoreFault::BadHead);
    if (head->identity.pool_id != dir_pool_id || head->rules_g != dir_rules_g || head->genesis_id != head->identity.pool_id)
        return fail(StoreFault::Identity);
    const StoreHead& H = *head;
    const std::uint64_t tip = H.best_pos;
    if (tip < H.root_pos || H.root_pos < H.first_pos || H.base_pos < H.root_pos || H.base_pos > tip)
        return fail(StoreFault::BadHead);

    // 2. K_PCARRIER first_pos .. tip
    std::vector<CarrierRecord> recs;  // grows with the records read (a head naming more ends at the first missing one)
    for (std::uint64_t x = H.first_pos; x <= tip; ++x) {
        const KvRead v = kv.read(store_keys::pcarrier(in.chain, x));
        if (v.status != KvRead::Status::Value) return fail(StoreFault::Records, x);
        std::optional<CarrierRecord> c = decode_pcarrier(v.value);
        if (!c || c->pos != x) return fail(StoreFault::Records, x);
        if (x > H.first_pos && c->parent != recs.back().id) return fail(StoreFault::Records, x);
        if (x >= H.root_pos && !c->state) return fail(StoreFault::Records, x);
        recs.push_back(std::move(*c));
    }
    if (recs.back().id != H.best_id) return fail(StoreFault::Records, tip);
    if (H.first_pos == 0 && (recs[0].id != H.genesis_id || recs[0].H != H.h0)) return fail(StoreFault::Records, 0);
    std::vector<std::uint64_t> records;
    std::vector<Hash32> ids;
    for (const CarrierRecord& c : recs) {
        records.push_back(c.H);
        ids.push_back(c.id);
    }
    const auto rec_at = [&](std::uint64_t x) -> const CarrierRecord& { return recs[x - H.first_pos]; };
    LaneKv lane;
    const KvRead bm = kv.read(lane_keys::bmmr(in.chain));
    if (bm.status != KvRead::Status::Value || !store_detail::scan(kv, lane_keys::blhash_prefix(in.chain), lane)
        || !store_detail::scan(kv, lane_keys::bleaf_prefix(in.chain), lane))
        return fail(StoreFault::Scan);
    lane[lane_keys::bmmr(in.chain)] = bm.value;
    LaneLoad ll = load_lane_prefix(lane, in.chain, H.h0, p.open_bins, H.best_id, tip, records.back(), H.base_leaf_count,
                                   H.base_peaks);
    if (ll.fault != LoadFault::None) return fail(StoreFault::Lane);

    // 3. the anchors at the tip
    if (tip > H.root_pos) {
        const std::optional<CarrierBodyV3> tb = record_body(rec_at(tip), p);
        if (!tb || receipt_id(tb->own) != H.best_id) return fail(StoreFault::Records, tip);
        const std::uint64_t lc_parent = bin_leaf_count(rec_at(tip - 1).H, H.h0, p.open_bins);
        const std::optional<Hash32> root = ll.mmr.prefix_root(lc_parent);
        if (!root || *root != tb->own.side.mmr_root) return fail(StoreFault::Anchor);
        std::vector<Hash32> carried;
        for (const ReceiptBodyV3& r : tb->carried) carried.push_back(receipt_id(r));
        const RatchetState s_parent = decode_ratchet_state(*rec_at(tip - 1).state);
        if (check_carried_fold(tb->own.side.receipts_root, carried, s_parent) != FoldVerdict::Match)
            return fail(StoreFault::Fold);
    }

    // 4. AR
    std::vector<ActivationRow> rows;
    {
        LaneKv arkv;
        if (!store_detail::scan(kv, store_keys::ar_prefix(in.chain), arkv)) return fail(StoreFault::Scan);
        for (const auto& [k, v] : arkv) {
            const std::optional<ActivationRow> a = decode_ar_row(v);
            if (!a || k != store_keys::ar(in.chain, a->h_act) || a->h_act > tip) return fail(StoreFault::Ar);
            rows.push_back(*a);
        }
    }
    const RatchetState s_tip = decode_ratchet_state(*recs.back().state);
    const bool joined = H.root_pos > 0;  // a young-chain adoption (root at position 0) holds the genesis AR, no seed
    const std::uint64_t q0 = std::max(H.base_pos + 1, tip + 1 > in.journal_depth ? tip + 1 - in.journal_depth : 0);
    ActivationRecord ar;
    std::size_t ri = 0;
    if (joined) {
        // the joiner seed (S_{p0 - 1}.epoch_cur, p0 - 1, S_{p0 - 1}.rules_cur), p0 - 1 = the root
        const RatchetState s_root = decode_ratchet_state(*rec_at(H.root_pos).state);
        if (rows.empty() || rows[0] != ActivationRow{s_root.epoch_cur, H.root_pos, s_root.rules_cur})
            return fail(StoreFault::Ar);
        ar.seed_joiner(s_root, H.root_pos + 1);
        ri = 1;
    }
    std::vector<ActivationRow> replay_rows;
    for (; ri < rows.size(); ++ri) {
        if (rows[ri].h_act >= q0) {
            replay_rows.push_back(rows[ri]);
            continue;
        }
        if (!ar.append(rows[ri])) return fail(StoreFault::Ar);
    }
    {
        // the last row (all of them) against S_tip
        const ActivationRow* last = replay_rows.empty() ? (ar.rows().empty() ? nullptr : &ar.rows().back())
                                                        : &replay_rows.back();
        if (last == nullptr ? s_tip.epoch_cur != 0
                            : (last->epoch != s_tip.epoch_cur || last->rules_digest != s_tip.rules_cur))
            return fail(StoreFault::Ar);
    }

    // 5. phase 1: positions below q0 (the placements a judged tip's window may read)
    const std::uint64_t root = q0 - 1;
    const std::uint64_t H_root = rec_at(root).H;
    const std::uint64_t span = p.open_bins + p.fresh_max;
    const std::uint64_t floor_a = H_root > span ? H_root - span : 0;
    const std::uint64_t s1 = first_above(records, H.first_pos, H.root_pos + 1, floor_a);
    std::vector<Placement> placements;
    CarrierBodies bodies;
    for (std::uint64_t x = std::max(H.root_pos, H.first_pos); x <= root; ++x) {
        const CarrierRecord& c = rec_at(x);
        const std::optional<CarrierBodyV3> b = record_body(c, p);
        if (b) bodies.put(c.id, *b);
        if (x < s1) continue;
        // x > root_pos: its body, its id, its parent link and its receipts_root fold over S_{x-1}
        if (!b || receipt_id(b->own) != c.id || b->own.side.tip != c.parent) return fail(StoreFault::Phase1, x);
        std::vector<Hash32> carried;
        for (const ReceiptBodyV3& r : b->carried) carried.push_back(receipt_id(r));
        if (check_carried_fold(b->own.side.receipts_root, carried, decode_ratchet_state(*rec_at(x - 1).state))
            != FoldVerdict::Match)
            return fail(StoreFault::Phase1, x);
        if (c.placements.size() != b->carried.size() + 1) return fail(StoreFault::Phase1, x);
        // only the placements whose bin is open at q0 - 1 (b > H(q0 - 1) - F)
        const auto open = [&](const StoredPlacement& sp) { return open_at(H_root, sp.bin, p.open_bins); };
        for (std::size_t k = 0; k < b->carried.size(); ++k)
            if (open(c.placements[k])) placements.push_back(store_detail::placement_from(b->carried[k], c.placements[k], x, c.id));
        if (open(c.placements.back())) placements.push_back(store_detail::placement_from(b->own, c.placements.back(), x, c.id));
    }
    // the store at the root
    BinStore::RestoredStart rs;
    rs.b0 = H.h0;
    rs.first_pos = H.first_pos;
    rs.ids.assign(ids.begin(), ids.begin() + static_cast<std::ptrdiff_t>(root - H.first_pos + 1));
    rs.records.assign(records.begin(), records.begin() + static_cast<std::ptrdiff_t>(root - H.first_pos + 1));
    rs.root_h = rec_at(root).h;
    rs.lc0 = H.base_leaf_count;
    rs.peaks0 = H.base_peaks;
    const std::uint64_t lc_root = bin_leaf_count(H_root, H.h0, p.open_bins);
    if (lc_root < H.base_leaf_count) return fail(StoreFault::Lane);
    for (std::uint64_t i = H.base_leaf_count; i < lc_root; ++i) {
        SealedBin sb;
        if (ll.bodies[i]) {
            sb = *ll.bodies[i];
        } else {
            sb.bucket.bin_lo = sb.bucket.bin_hi = H.h0 + i;
            sb.leaf = *ll.mmr.leaf(i);
            sb.held = false;
        }
        rs.sealed.push_back(std::move(sb));
    }
    rs.placements = std::move(placements);
    std::optional<BinStore> store = BinStore::restored(p, in.journal_depth, std::move(rs), in.chain);
    if (!store) return fail(StoreFault::Lane);
    // the tree at the root
    std::vector<CarrierTree::RestoredNode> nodes;
    std::vector<RetargetEntry> inherited;
    for (std::uint64_t x = H.first_pos; x <= root; ++x) {
        const CarrierRecord& c = rec_at(x);
        if (x < H.root_pos) {
            continue;
        }
        CarrierTree::RestoredNode n;
        n.id = c.id;
        n.parent = c.parent;
        n.pos = c.pos;
        n.h = c.h;
        n.H = c.H;
        n.d = c.d;
        n.cum_work = c.cum_work;
        n.rs = decode_ratchet_state(*c.state);
        if (const CarrierBodyV3* b = bodies.get(c.id)) {
            n.receipts_root = b->own.side.receipts_root;
            n.ballot = b->own.side.ballot;
        }
        for (const ActivationRow& a : ar.rows())
            if (a.h_act == x && !(joined && a.h_act == H.root_pos)) n.activation = a;
        nodes.push_back(n);
    }
    if (H.root_pos > H.first_pos) {
        // the retarget entries of the N_rt positions through the root (position 0 is never in a window)
        const std::uint64_t lo = H.root_pos + 1 > p.retarget_span ? H.root_pos + 1 - p.retarget_span : 0;
        for (std::uint64_t x = std::max({lo, H.first_pos, std::uint64_t{1}}); x <= H.root_pos; ++x)
            inherited.push_back(RetargetEntry{rec_at(x).d, rec_at(x).H});
    }
    std::optional<CarrierTree> tree = CarrierTree::restored(p, nodes, in.T, inherited, in.rp);
    if (!tree) return fail(StoreFault::Records, root);

    // 6. phase 2: q0 .. tip placed again
    std::size_t rj = 0;
    for (std::uint64_t x = q0; x <= tip; ++x) {
        const CarrierRecord& c = rec_at(x);
        const std::optional<CarrierBodyV3> b = record_body(c, p);
        if (!b || receipt_id(b->own) != c.id || b->own.side.tip != c.parent || c.placements.size() != b->carried.size() + 1)
            return fail(StoreFault::Phase2, x, 1);
        std::vector<CarriedPlacement> cp;
        std::vector<Placement> sp;
        for (std::size_t k = 0; k < b->carried.size(); ++k) {
            const ReceiptBodyV3& r = b->carried[k];
            cp.push_back(CarriedPlacement{receipt_id(r), r.side.t_origin, r.side.ballot, c.placements[k].live});
            sp.push_back(admit_detail::placement_of(r, receipt_id(r), c.placements[k].bin, c.placements[k].p_own));
        }
        sp.push_back(admit_detail::placement_of(b->own, c.id, c.placements.back().bin, c.placements.back().p_own));
        const PlaceOutcome po =
                tree->place(CarrierAnnounce{c.id, c.parent, c.h, b->own.side.receipts_root, b->own.side.ballot}, cp);
        if (po.verdict != PlaceVerdict::Placed) return fail(StoreFault::Phase2, x, 2);
        if (store->add_carrier(c.id, c.parent, c.h) != AddVerdict::Added) return fail(StoreFault::Phase2, x, 3);
        for (const Placement& pl : sp) {
            const std::optional<Ingest> ig = store->ingest(c.id, pl);
            if (!ig || *ig != Ingest::Accepted) return fail(StoreFault::Phase2, x, 4);
        }
        const LaneDelta* d = store->delta(c.id);
        for (std::size_t k = 0; d != nullptr && k < d->placed.size(); ++k)
            if (d->placed[k].live != c.placements[k].live) return fail(StoreFault::Phase2, x, 5);
        if (!store->seal(c.id)) return fail(StoreFault::Phase2, x, 6);
        if (store->switch_best(c.id) != SwitchVerdict::Switched) return fail(StoreFault::Phase2, x, 7);
        tree->mark_verified(c.id);
        tree->mark_bodies(c.id);
        const CarrierNode* n = tree->find(c.id);
        if (n == nullptr || n->d != c.d || n->H != c.H || !(n->cum_work == c.cum_work) || !c.state
            || encode_ratchet_state(n->rs) != *c.state || tree->best().id != c.id)
            return fail(StoreFault::Phase2, x, 8);
        const LaneView pv = store->view_at(c.parent);
        if (!pv.ok() || pv.mmr_root_at(pv.pos()) != b->own.side.mmr_root) return fail(StoreFault::Phase2, x, 9);
        if (n->activation) {
            if (rj >= replay_rows.size() || replay_rows[rj] != *n->activation || !ar.append(*n->activation))
                return fail(StoreFault::Phase2, x, 10);
            ++rj;
        }
        bodies.put(c.id, *b);
    }
    if (rj != replay_rows.size()) return fail(StoreFault::Ar);
    if (store->head().root != ll.head.root || store->best_tip() != H.best_id) return fail(StoreFault::Phase2, tip);
    // the lane records at or beyond leaf_count (3.4 step 2): deleted
    if (!ll.cleanup.ops.empty() && !commit_lane_batch(kv, ll.cleanup)) return fail(StoreFault::Lane);

    std::map<Hash32, XmrKeyRef> refs;
    const auto learn = [&refs](const ReceiptBodyV3& r) {
        refs[r.side.payee] = r.payee;
        if (r.owner) refs[r.side.owner] = *r.owner;
    };
    for (std::uint64_t x = s1; x <= tip; ++x)
        if (const CarrierBodyV3* b = bodies.get(rec_at(x).id)) {
            learn(b->own);
            for (const ReceiptBodyV3& r : b->carried) learn(r);
        }
    for (const std::optional<SealedBin>& sb : ll.bodies)
        if (sb)
            for (const XmrKeyRef& ref : sb->refs) refs[key_ref_identity(ref)] = ref;
    LoadedState st{H, std::move(*tree), std::move(*store), std::move(ar), std::move(bodies), q0, s1, std::move(refs)};
    out.state.emplace(std::move(st));
    out.fault = StoreFault::None;
    return out;
}

}  // namespace c2pool::xmr::pathb
