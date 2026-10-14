// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// src/impl/xmr/pathb/test/v37_xmr_pathb_store_kat.cpp
// The node's own store (pathb_store.hpp, BinStore::restored, load_lane_prefix):
//   (1) codecs: K_PHEAD, K_PCARRIER, K_AR round trip; refusals;
//   (2) one batch per position: genesis + every extension one commit, each
//       with K_PCARRIER(x) and K_PHEAD; a switch by the journal is one batch
//       (K_PCARRIER and K_AR above the fork deleted, the new branch written);
//   (3) load: a node reloaded from its store has the lane state of the live
//       node (tip, S, d, cum_work, AR, MMR head, window_root, mmr_root, every
//       open-bin entry list with q and p_own) at J 64 and at J_0 = 1,152, and
//       stays equal after both place the same next carriers (the phase-1
//       placements reproduce the next seals); a store younger than J reloads;
//   (4) the prefix load: a store whose leaves below its base are gone loads
//       from the base's peaks (the full form fails LeafHash); a joined-shape
//       store (first_pos, root_pos, base_pos, its AR seed) reloads with the
//       live node's window and roots; one position after the base reloads;
//       F-5: a joined store (its base at lc(H(x0 - 1)) and its peaks)
//       restarted at tip == base_pos reloads with no re-join, live-equal,
//       first_leaf() = lc(H(x0 - 1)) (V-F5a, a bin sealed at L_j and not);
//       a leaf it holds replaced: Anchor at tip == base_pos (V-F5b);
//   (5) phase 1 checks every stored body below q0 (id, parent, fold): a
//       corrupted body is a load failure; so is a broken parent link;
//   (6) a write failure poisons the node and leaves the poison mark (the
//       next load fails; the last committed batch is whole under it); a torn
//       K_PCARRIER, a stale K_AR row above the tip, an anchor mismatch, a
//       placement of a bin sealed in phase 2, a phase-1 parent link: load
//       failure (the joiner path);
//   (9) the head: K_PHEAD absent in an empty store only (NoHead); absent
//       beside other keys, or unreadable: a load failure; a head naming more
//       positions than the store holds: Records (no allocation from the head);
//       the lane records beyond leaf_count deleted at load;
//   (7) the directory: K_PHEAD naming another pool_id or G is a load failure;
//       another pool or G has its own directory name; an adoption clears
//       every key of the old store;
//   (8) the LevelDB archive: the same store written through it, reopened,
//       loads to the live state;
//  (10) a pruned store (prune_batch): records below first_pos deleted, header
//       records to root_pos, the root's record whole; K_BLHASH, K_BLEAF and
//       K_AR untouched; a store launched here and a joined store (its AR seed
//       below the pruned root) reload live-equal from the root.
// ---------------------------------------------------------------------------
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

#include "c2pool/v37/xmr/pathb/xmr_pathb_store.hpp"
#include "impl/xmr/pathb/pathb_store.hpp"
#include "pathb_kat_admit.hpp"
#include "pathb_kat_store.hpp"

using namespace pathb_kat;
namespace pb = ::c2pool::xmr::pathb;

namespace {

pb::LoadInputs inputs(const KatNode& n, std::uint64_t J) {
    pb::LoadInputs in;
    in.T = n.T;
    in.journal_depth = J;
    return in;
}

// A KatNode with the loaded state.
struct Reloaded {
    std::optional<KatNode> n;
    pb::LoadResult r;
};

Reloaded reload(const KatNet& net, MemoryKv& kv, std::uint64_t J) {
    Reloaded out;
    KatNode probe(net, J);
    out.r = pb::pathb_load(kv, net.pool_id, net.rules_g, inputs(probe, J));
    if (out.r.fault != pb::StoreFault::None || !out.r.state) return out;
    out.n.emplace(net, J);
    out.n->tree = std::move(out.r.state->tree);
    out.n->store = std::move(out.r.state->store);
    out.n->ar = std::move(out.r.state->ar);
    out.n->bodies = std::move(out.r.state->bodies);
    out.n->spy();
    return out;
}

const char* fault_name(pb::StoreFault f) {
    switch (f) {
        case pb::StoreFault::None: return "None";
        case pb::StoreFault::NoHead: return "NoHead";
        case pb::StoreFault::BadHead: return "BadHead";
        case pb::StoreFault::Identity: return "Identity";
        case pb::StoreFault::Records: return "Records";
        case pb::StoreFault::Lane: return "Lane";
        case pb::StoreFault::Anchor: return "Anchor";
        case pb::StoreFault::Fold: return "Fold";
        case pb::StoreFault::Ar: return "Ar";
        case pb::StoreFault::Phase1: return "Phase1";
        case pb::StoreFault::Phase2: return "Phase2";
        case pb::StoreFault::Scan: return "Scan";
        case pb::StoreFault::Poisoned: return "Poisoned";
        case pb::StoreFault::Work: return "Work";
    }
    return "?";
}

std::string why(const pb::LoadResult& r) {
    return std::string(fault_name(r.fault)) + " at " + std::to_string(r.at) + " check " + std::to_string(r.check);
}

// ---------------------------------------------------------------------------
void codecs() {
    const KatNet net;
    pb::StoreHead h = kat_head(net);
    h.best_pos = 77;
    h.best_id = seq32(0x44);
    h.journal_base = 13;
    h.first_pos = 2;
    h.root_pos = 3;
    h.base_pos = 9;
    h.base_leaf_count = 5;
    h.base_peaks = {seq32(1), seq32(2)};
    h.identity.form = pb::GenesisForm::Derived;
    h.identity.spec.headline = "a headline";
    h.identity.spec.height = h.identity.height;
    h.identity.spec.block_hash = seq32(0x10);
    for (std::size_t i = 0; i < h.s_base.size(); ++i) h.s_base[i] = static_cast<std::uint8_t>(i);
    const std::optional<pb::StoreHead> d = pb::decode_phead(pb::encode_phead(h));
    check(d && *d == h, "(1) K_PHEAD round trip");
    pb::StoreHead bad = h;
    bad.base_peaks.pop_back();
    check(!pb::decode_phead(pb::encode_phead(bad)), "(1) K_PHEAD with n_peaks != popcount(base_leaf_count) refused");
    std::string tr = pb::encode_phead(h);
    tr.push_back('x');
    check(!pb::decode_phead(tr), "(1) K_PHEAD with a trailing byte refused");

    pb::CarrierRecord c;
    c.id = seq32(0x20);
    c.parent = seq32(0x21);
    c.pos = 12;
    c.h = 3000200;
    c.d = 18180;
    c.cum_work = ::c2pool::xmr::native::U128{12345, 6};
    c.H = 3000201;
    c.state = pb::RatchetStateBytes{};
    c.kind = pb::RecordBody::Carrier;
    c.bytes = {1, 2, 3, 4};
    c.placements = {{3000100, 4, true}, {3000150, 12, false}};
    const std::optional<pb::CarrierRecord> cd = pb::decode_pcarrier(pb::encode_pcarrier(c));
    check(cd && *cd == c, "(1) K_PCARRIER round trip");
    std::string cs = pb::encode_pcarrier(c);
    cs.resize(cs.size() - 1);
    check(!pb::decode_pcarrier(cs), "(1) a torn K_PCARRIER refused");
    const pb::ActivationRow a{3, 4000, seq32(0x55)};
    const std::optional<pb::ActivationRow> ad = pb::decode_ar_row(pb::encode_ar_row(a));
    check(ad && *ad == a && pb::encode_ar_row(a).size() == 2 + 42, "(1) K_AR round trip (42 B row)");
    check(pb::store_keys::pcarrier(0, 12) == "v37s:pcar:0000000000:00000000000000000012", "(1) K_PCARRIER key");
}

// ---------------------------------------------------------------------------
void batches_and_load() {
    const KatNet net;
    for (const std::uint64_t J : {std::uint64_t{64}, std::uint64_t{1152}}) {
        KatStoreNode sn(net, J);
        const std::uint64_t count = J == 64 ? 420 : 1400;
        const std::vector<pb::Hash32> ids = store_chain(sn, count, 0x61, 3, 7 + J);
        const std::string tag = "(J " + std::to_string(J) + ") ";
        check(ids.size() == count && !sn.poisoned, tag + "(2) the chain placed and written");
        check(sn.kv.commits == count + 1, tag + "(2) one commit per position (genesis + " + std::to_string(count) + ")");
        bool keys = true;
        for (std::uint64_t x = 0; x <= count; ++x) keys = keys && sn.kv.get(pb::store_keys::pcarrier(0, x)).has_value();
        const std::optional<pb::StoreHead> h = pb::decode_phead(*sn.kv.get(pb::store_keys::phead(0)));
        check(keys && h && h->best_pos == count && h->best_id == ids.back(), tag + "(2) K_PCARRIER 0 .. tip and K_PHEAD at the tip");
        Reloaded r = reload(net, sn.kv, J);
        check(r.r.fault == pb::StoreFault::None, tag + "(3) the store loads: " + why(r.r));
        if (!r.n) continue;
        const std::string live = lane_digest(sn.n), loaded = lane_digest(*r.n);
        check(live == loaded, tag + "(3) the reloaded lane state equals the live node's");
        check(r.r.state->q0 == count + 1 - J, tag + "(3) q0 = tip - J + 1");
        // both place the same next carriers: the same state (the restored placements seal as the live ones)
        KatStoreNode* live_sn = &sn;
        Rng rng(99 + J);
        bool same = true;
        for (int i = 0; i < 150 && same; ++i) {
            const pb::CarrierNode& best = live_sn->n.tree.best();
            const std::uint64_t x = best.pos + 1;
            std::vector<pb::ReceiptBodyV3> carried;
            for (int k = 0; k < 2; ++k) {
                const std::uint64_t back = 1 + rng.below(20);
                const std::optional<pb::Hash32> tip = live_sn->n.store.best_at(best.pos - back);
                const pb::CarrierNode* t = live_sn->n.tree.find(*tip);
                carried.push_back(scaffold_receipt(live_sn->n, *tip, t->h + rng.below(3), rng.below(20), 0xABC000 + x * 4 + k));
            }
            canonical_sort(net, carried, best.id);
            const pb::CarrierBodyV3 c = scaffold_carrier(live_sn->n, best.id, h_pos(x), 0x62, x, rng.below(20), carried);
            const pb::WriteResult w1 = sn.place(c);
            const pb::WriteResult w2 = place_direct(*r.n, c);
            same = w1.outcome == pb::WriteOutcome::Extended && w2.outcome == pb::WriteOutcome::Extended
                   && lane_digest(sn.n) == lane_digest(*r.n);
        }
        check(same, tag + "(3) live and reloaded place the next 150 carriers to the same state (seals, windows, roots)");
    }
    // a store younger than J reloads (q0 = 1)
    {
        KatStoreNode sn(net, 1152);
        store_chain(sn, 300, 0x63, 2, 5);
        Reloaded r = reload(net, sn.kv, 1152);
        check(r.n && lane_digest(sn.n) == lane_digest(*r.n) && r.r.state->q0 == 1,
              "(3) a store younger than J reloads (the whole chain replayed): " + why(r.r));
    }
}

// ---------------------------------------------------------------------------
void switch_batch() {
    const KatNet net;
    KatStoreNode sn(net, 64);
    store_chain(sn, 200, 0x71, 2, 11);
    KatNode& n = sn.n;
    const pb::Hash32 fork = *n.store.best_at(190);
    // an activation row recorded on the losing branch (the switch must delete it)
    // branch A: 190 -> 200 is the best chain; branch B from 190, 12 carriers (heavier)
    pb::Hash32 p = fork;
    std::optional<pb::WriteResult> last;
    std::uint64_t commits_before = sn.kv.commits;
    std::vector<pb::Hash32> b_ids;
    for (std::uint64_t i = 1; i <= 12; ++i) {
        const std::uint64_t x = 190 + i;
        const pb::CarrierBodyV3 c = scaffold_carrier(n, p, h_pos(x), 0x72, 10000 + x, 3, {});
        pb::WriteResult w = place_direct(n, c);
        p = pb::receipt_id(c.own);
        b_ids.push_back(p);
        if (w.outcome == pb::WriteOutcome::SwitchToCaller) {
            // the switch by the journal: one batch
            const std::uint64_t old_tip = n.store.tip_pos();
            const pb::ActivationRecord ar_before = n.ar;
            pb::LaneBatch lane;
            const pb::SwitchVerdict sv = n.store.switch_best(n.tree.best().id, &lane);
            (void)n.ar.rewind(190);
            const pb::LaneBatch b = pb::switch_batch(0, sn.head, n.tree, n.store, n.bodies, 190, old_tip, ar_before, n.ar, lane);
            check(sv == pb::SwitchVerdict::Switched && pb::commit_lane_batch(sn.kv, b), "(2) the switch committed");
        } else if (w.outcome == pb::WriteOutcome::Extended) {
            const pb::LaneBatch b = pb::extension_batch(0, sn.head, n.tree, n.store, n.bodies, p, w.batch, w.ar_row);
            check(pb::commit_lane_batch(sn.kv, b), "(2) an extension committed");
        }
        last = w;
    }
    check(n.store.best_tip() == b_ids.back() && n.store.tip_pos() == 202, "(2) the node switched to branch B (tip 202)");
    check(sn.kv.commits - commits_before == 3, "(2) the switch is one batch (switch + 2 extensions after it)");
    bool a_gone = true;
    for (std::uint64_t x = 191; x <= 202; ++x) {
        const std::optional<pb::CarrierRecord> c = pb::decode_pcarrier(*sn.kv.get(pb::store_keys::pcarrier(0, x)));
        a_gone = a_gone && c && c->id == b_ids[x - 191];
    }
    check(a_gone, "(2) K_PCARRIER 191 .. 202 hold branch B");
    Reloaded r = reload(net, sn.kv, 64);
    check(r.n && lane_digest(n) == lane_digest(*r.n), "(3) the store after a switch reloads to the live state: " + why(r.r));
    // a losing branch that reached above the winner's tip (old tip 205): its records 203 .. 205 go in the same batch
    {
        MemoryKv kv2 = sn.kv;
        pb::LaneBatch stale;
        for (std::uint64_t x = 203; x <= 205; ++x)
            stale.put(pb::store_keys::pcarrier(0, x), *sn.kv.get(pb::store_keys::pcarrier(0, 202)));
        check(pb::commit_lane_batch(kv2, stale), "(2) stale records 203 .. 205 written");
        const pb::LaneBatch b = pb::switch_batch(0, sn.head, n.tree, n.store, n.bodies, 190, 205, n.ar, n.ar, pb::LaneBatch{});
        bool gone = pb::commit_lane_batch(kv2, b);
        for (std::uint64_t x = 203; x <= 205; ++x) gone = gone && !kv2.get(pb::store_keys::pcarrier(0, x));
        bool kept = true;
        for (std::uint64_t x = 191; x <= 202; ++x) kept = kept && kv2.get(pb::store_keys::pcarrier(0, x)) == sn.kv.get(pb::store_keys::pcarrier(0, x));
        check(gone && kept, "(2) the switch batch deletes K_PCARRIER above the fork through the old tip and writes the new branch");
    }
}

// ---------------------------------------------------------------------------
void prefix_and_joined() {
    const KatNet net;
    KatStoreNode sn(net, 64);
    store_chain(sn, 3700, 0x81, 2, 21);
    KatNode& n = sn.n;
    // a joined-shape store: first_pos = root - N_rt + 1, root_pos = x0 - 1, base_pos = L_j (every bin
    // open at the root sealed by the base, as in a join span), the leaves below the base's leaf count
    // gone, the AR seed at the root
    const std::uint64_t root = 2300, base = 3600;
    const std::uint64_t first = root + 1 - pb::kRuledLaneParams.retarget_span;
    MemoryKv kv = sn.kv;
    pb::StoreHead h = *pb::decode_phead(*kv.get(pb::store_keys::phead(0)));
    h.first_pos = first;
    h.root_pos = root;
    h.base_pos = base;
    // the base at the joined MMR's start (F-5): lc(H(x0 - 1)), its peaks
    h.base_leaf_count = pb::bin_leaf_count(n.tree.find(*n.store.best_at(root))->H, kLaneB0, pb::kRuledLaneParams.open_bins);
    h.base_peaks = *n.store.best_mmr().prefix_peaks(h.base_leaf_count);
    const pb::RatchetState s_root = n.tree.find(*n.store.best_at(root))->rs;
    h.s_base = pb::encode_ratchet_state(n.tree.find(*n.store.best_at(base))->rs);
    kv.data[pb::store_keys::phead(0)] = pb::encode_phead(h);
    kv.data[pb::store_keys::ar(0, root)] = pb::encode_ar_row(pb::ActivationRow{s_root.epoch_cur, root, s_root.rules_cur});
    for (std::uint64_t x = 0; x < first; ++x) kv.data.erase(pb::store_keys::pcarrier(0, x));
    for (std::uint64_t i = 0; i < h.base_leaf_count; ++i) {
        kv.data.erase(pb::lane_keys::blhash(0, i));
        kv.data.erase(pb::lane_keys::bleaf(0, i));
    }
    for (std::uint64_t x = first; x < root; ++x) {  // the prefix: headers, no S
        pb::CarrierRecord c = *pb::decode_pcarrier(kv.data[pb::store_keys::pcarrier(0, x)]);
        c.state.reset();
        c.kind = pb::RecordBody::None;
        c.bytes.clear();
        c.placements.clear();
        kv.data[pb::store_keys::pcarrier(0, x)] = pb::encode_pcarrier(c);
    }
    // the full form fails without the leaves below the base; the prefix form loads
    pb::LaneKv lane;
    kv.for_each_prefix("v37s:b", [&](const std::string& k, const std::string& v) {
        lane[k] = v;
        return true;
    });
    const pb::LaneView tv = n.store.view_at(n.store.best_tip());
    check(pb::load_lane(lane, 0, kLaneB0, 96, n.store.best_tip(), n.store.tip_pos(), tv.record(tv.pos())).fault
                  == pb::LoadFault::LeafHash,
          "(4) the full load of a store without its leaves below the base fails (LeafHash)");
    const pb::LaneLoad ll = pb::load_lane_prefix(lane, 0, kLaneB0, 96, n.store.best_tip(), n.store.tip_pos(),
                                                 tv.record(tv.pos()), h.base_leaf_count, h.base_peaks);
    check(ll.fault == pb::LoadFault::None && ll.mmr.root() == n.store.head().root, "(4) the prefix load from the base's peaks");
    // a joined store holds its K_BLO (x1 + 1; here x1 = the root); without it the load fails (Work)
    check(reload(net, kv, 64).r.fault == pb::StoreFault::Work, "(4) a joined-shape store without K_BLO: Work");
    kv.data[pb::store_keys::blo(0)] = pb::encode_blo(root + 1);
    Reloaded r = reload(net, kv, 64);
    check(r.r.fault == pb::StoreFault::None, "(4) the joined-shape store loads: " + why(r.r));
    if (r.n) {
        const pb::TipWindow a = n.window(n.tree.best().id), b = r.n->window(r.n->tree.best().id);
        check(a.ok() && b.ok() && a.window_root == b.window_root && a.mmr_root == b.mmr_root
                      && r.n->tree.best().id == n.tree.best().id && r.n->tree.best().rs == n.tree.best().rs
                      && r.n->ar.rows().size() == 1 && r.n->ar.joiner_p0() == root + 1,
              "(4) the joined-shape store: the live window and roots, S at the tip, AR = the joiner seed");
    }
    // K_BCLAIM's range: a sealed leaf at the tip, below the first leaf or at or below the adopt bound H(x0 - 1) + Fresh
    {
        const pb::LaneParams& p = pb::kRuledLaneParams;
        const std::uint64_t lc_tip = pb::bin_leaf_count(n.tree.best().H, kLaneB0, p.open_bins);
        const std::uint64_t bound = h.base_leaf_count + kLaneB0 + p.open_bins - 1 + p.fresh_max;
        const auto with_claim = [&](std::uint64_t bin) {
            MemoryKv k3 = kv;
            k3.data[pb::store_keys::bclaim(0, bin)] = pb::encode_bclaim(pb::BclaimRecord{bin, seq32(0x61), seq32(0x62)});
            return reload(net, k3, 64);
        };
        // a full store (no adopt bound): a sealed leaf at the tip loads, the first unsealed bin is Work
        const auto full_with_claim = [&](std::uint64_t bin) {
            MemoryKv k4 = sn.kv;
            k4.data[pb::store_keys::bclaim(0, bin)] = pb::encode_bclaim(pb::BclaimRecord{bin, seq32(0x63), seq32(0x64)});
            return reload(net, k4, 64).r.fault;
        };
        check(full_with_claim(kLaneB0 + lc_tip - 1) == pb::StoreFault::None
                      && full_with_claim(kLaneB0 + lc_tip) == pb::StoreFault::Work,
              "(4) K_BCLAIM in a full store: a sealed leaf at the tip loads; an unsealed bin: Work");
        const Reloaded below = with_claim(kLaneB0 + h.base_leaf_count - 1);
        const Reloaded at_bound = with_claim(bound);
        const Reloaded above_bound = with_claim(bound + 1);
        const Reloaded unsealed = with_claim(kLaneB0 + lc_tip);
        check(bound + 1 < kLaneB0 + lc_tip && below.r.fault == pb::StoreFault::None && below.r.state->claimed.size() == 1
                      && at_bound.r.fault == pb::StoreFault::None && above_bound.r.fault == pb::StoreFault::Work
                      && unsealed.r.fault == pb::StoreFault::Work,
              "(4) K_BCLAIM below the first leaf and at the adopt bound load; above the bound and on an unsealed bin: Work");
    }
    // one position after the base
    {
        MemoryKv k2 = kv;
        pb::StoreHead h2 = h;
        h2.base_pos = 3699;
        k2.data[pb::store_keys::phead(0)] = pb::encode_phead(h2);
        Reloaded r2 = reload(net, k2, 64);
        check(r2.n && r2.r.state->q0 == 3700 && r2.n->tree.best().id == n.tree.best().id,
              "(4) a store one position after its base reloads: " + why(r2.r));
    }
}

// ---------------------------------------------------------------------------
// (4) F-5: a joined store restarted at its base (tip == base_pos = L_j, before its first extension), the base at the
// joined MMR's start lc(H(x0 - 1)) with its peaks. V-F5a: L_j 3,708 (a bin sealed at L_j) and 3,700 load with no
// re-join, live-equal, first_leaf() = lc(H(x0 - 1)). V-F5b: a leaf in [lc(H(x0 - 1)), lc(H(L_j - 1))) replaced (K_BMMR
// consistent): the anchor at tip == base_pos -> Anchor.
void f5_at(std::uint64_t L) {
    const KatNet net;
    KatStoreNode sn(net, 64);
    store_chain(sn, L, 0x85, 2, 25);
    KatNode& n = sn.n;
    const std::uint64_t F = pb::kRuledLaneParams.open_bins;
    const auto Hx = [&](std::uint64_t x) { return n.tree.find(*n.store.best_at(x))->H; };
    const std::uint64_t root = 2300;  // x0 - 1
    const std::uint64_t lc0 = pb::bin_leaf_count(Hx(root), kLaneB0, F);
    const std::uint64_t lc_l1 = pb::bin_leaf_count(Hx(L - 1), kLaneB0, F);
    const std::uint64_t lc_l = pb::bin_leaf_count(Hx(L), kLaneB0, F);
    const std::string tag = "(4) joined store restarted at L_j " + std::to_string(L) + " (lc " + std::to_string(lc0) + " / " + std::to_string(lc_l1)
                            + " / " + std::to_string(lc_l) + "): ";
    check(n.tree.best().pos == L && lc0 < lc_l1 && (L % 12 != 0 || lc_l > lc_l1), tag + "the chain");
    {
        MemoryKv kv = joined_shape(sn.kv, n, root, L);
        const pb::StoreHead hd = *pb::decode_phead(kv.data[pb::store_keys::phead(0)]);
        Reloaded r = reload(net, kv, 64);
        bool same = false;
        if (r.n) {
            const pb::TipWindow a = n.window(n.tree.best().id), b = r.n->window(r.n->tree.best().id);
            same = a.ok() && b.ok() && a.window_root == b.window_root && a.mmr_root == b.mmr_root
                   && r.n->tree.best().id == n.tree.best().id && r.n->tree.best().rs == n.tree.best().rs
                   && r.n->store.head().root == n.store.head().root && r.n->ar.rows().size() == 1
                   && r.n->ar.joiner_p0() == root + 1;
        }
        check(hd.base_leaf_count == lc0 && r.r.fault == pb::StoreFault::None && r.r.state && r.r.state->q0 == L + 1 && same
                      && r.n && r.n->store.first_leaf() == lc0,
              tag + "restart at tip == base_pos loads with no re-join, live-equal (tip, S, AR seed, MMR head, "
                    "window_root, mmr_root), first_leaf() = lc(H(x0 - 1)): " + why(r.r));
    }
    {
        MemoryKv kv = joined_shape(sn.kv, n, root, L);
        pb::BmmrHead bh = *pb::decode_bmmr(kv.data[pb::lane_keys::bmmr(0)]);
        const std::uint64_t li = (lc0 + lc_l1) / 2;
        kv.data[pb::lane_keys::blhash(0, li)] = pb::encode_blhash(seq32(0x99));
        kv.data.erase(pb::lane_keys::bleaf(0, li));
        pb::BinMmr m = *pb::BinMmr::from_peaks(lc0, *n.store.best_mmr().prefix_peaks(lc0));
        for (std::uint64_t i = lc0; i < bh.leaf_count; ++i) m.append(*pb::decode_blhash(kv.data[pb::lane_keys::blhash(0, i)]));
        bh.root = m.root();
        bh.peaks = m.peaks();
        kv.data[pb::lane_keys::bmmr(0)] = pb::encode_bmmr(bh);
        const Reloaded r = reload(net, kv, 64);
        check(r.r.fault == pb::StoreFault::Anchor,
              tag + "leaf " + std::to_string(li) + " replaced (K_BMMR consistent): the anchor at tip == base_pos: " + why(r.r));
    }
}
void f5() {
    f5_at(3708);  // a bin sealed at L_j (309 x 12)
    f5_at(3700);  // none sealed at L_j
}

// ---------------------------------------------------------------------------
void faults() {
    const KatNet net;
    KatStoreNode sn(net, 64);
    const std::uint64_t T = 1300;
    store_chain(sn, T, 0x91, 3, 31);
    // (5) a corrupted body below q0 (phase 1)
    {
        MemoryKv kv = sn.kv;
        const std::uint64_t x = T - 64 - 5;  // below q0 = T - 63
        pb::CarrierRecord c = *pb::decode_pcarrier(kv.data[pb::store_keys::pcarrier(0, x)]);
        pb::CarrierBodyV3 b = *pb::record_body(c, pb::kRuledLaneParams);
        check(!b.carried.empty(), "(5) the corrupted position carries receipts");
        b.carried[0].blob.nonce ^= 1;  // another carried id: the fold no longer matches
        c.bytes.clear();
        pb::encode_carrier_body_v3(b, 16, c.bytes);
        kv.data[pb::store_keys::pcarrier(0, x)] = pb::encode_pcarrier(c);
        const Reloaded r = reload(net, kv, 64);
        check(r.r.fault == pb::StoreFault::Phase1 && r.r.at == x, "(5) a corrupted carried body below q0: Phase1 at x: " + why(r.r));
        pb::CarrierRecord c2 = *pb::decode_pcarrier(sn.kv.data[pb::store_keys::pcarrier(0, x)]);
        pb::CarrierBodyV3 b2 = *pb::record_body(c2, pb::kRuledLaneParams);
        b2.own.blob.nonce ^= 1;  // another own id
        c2.bytes.clear();
        pb::encode_carrier_body_v3(b2, 16, c2.bytes);
        MemoryKv kv2 = sn.kv;
        kv2.data[pb::store_keys::pcarrier(0, x)] = pb::encode_pcarrier(c2);
        check(reload(net, kv2, 64).r.fault == pb::StoreFault::Phase1, "(5) a stored body whose id differs from its record: Phase1");
        MemoryKv kv3 = sn.kv;
        pb::CarrierRecord c3 = *pb::decode_pcarrier(kv3.data[pb::store_keys::pcarrier(0, x)]);
        c3.parent[0] ^= 1;
        kv3.data[pb::store_keys::pcarrier(0, x)] = pb::encode_pcarrier(c3);
        check(reload(net, kv3, 64).r.fault == pb::StoreFault::Records, "(5) a broken parent link: Records");
    }
    // (6) a torn K_PCARRIER, a stale K_AR row, the anchor
    {
        MemoryKv kv = sn.kv;
        kv.data[pb::store_keys::pcarrier(0, T)].resize(20);
        check(reload(net, kv, 64).r.fault == pb::StoreFault::Records, "(6) a torn K_PCARRIER at the tip: load failure");
        MemoryKv kv2 = sn.kv;
        kv2.data[pb::store_keys::ar(0, T + 1)] = pb::encode_ar_row(pb::ActivationRow{1, T + 1, seq32(0x66)});
        check(reload(net, kv2, 64).r.fault == pb::StoreFault::Ar, "(6) a stale K_AR row above the tip: load failure");
        MemoryKv kv3 = sn.kv;
        kv3.data[pb::store_keys::ar(0, T - 10)] = pb::encode_ar_row(pb::ActivationRow{1, T - 10, seq32(0x66)});
        check(reload(net, kv3, 64).r.fault == pb::StoreFault::Ar, "(6) a K_AR row S_tip does not show: load failure");
        MemoryKv kv4 = sn.kv;
        pb::BmmrHead bh = *pb::decode_bmmr(kv4.data[pb::lane_keys::bmmr(0)]);
        (void)bh;
        // a leaf the tip's mmr_root covers, replaced (its K_BLHASH and K_BMMR rewritten consistently)
        pb::LaneKv lane;
        for (const auto& [k, v] : kv4.data)
            if (k.rfind("v37s:bl", 0) == 0) lane[k] = v;
        const std::string k0 = pb::lane_keys::blhash(0, 0);
        check(kv4.data.count(k0) == 1, "(6) leaf 0 is held");
        kv4.data[k0] = pb::encode_blhash(seq32(0x99));
        kv4.data.erase(pb::lane_keys::bleaf(0, 0));
        pb::BinMmr m;
        for (std::uint64_t i = 0; i < bh.leaf_count; ++i) m.append(*pb::decode_blhash(kv4.data[pb::lane_keys::blhash(0, i)]));
        bh.root = m.root();
        bh.peaks = m.peaks();
        kv4.data[pb::lane_keys::bmmr(0)] = pb::encode_bmmr(bh);
        check(reload(net, kv4, 64).r.fault == pb::StoreFault::Anchor, "(6) a lane MMR the tip's mmr_root does not commit: Anchor");
    }
    // (6) a stored placement whose bin seals during phase 2, altered: its leaf differs from the one the next carrier's
    // mmr_root commits (phase 2 check 9 at that carrier, before the final root)
    {
        MemoryKv kv = sn.kv;
        const std::uint64_t x = 120;  // own bin b0 + 10: sealed at H = b0 + 106, inside q0 .. tip
        pb::CarrierRecord c = *pb::decode_pcarrier(kv.data[pb::store_keys::pcarrier(0, x)]);
        c.placements.back().live = !c.placements.back().live;
        kv.data[pb::store_keys::pcarrier(0, x)] = pb::encode_pcarrier(c);
        const Reloaded r = reload(net, kv, 64);
        check(r.r.fault == pb::StoreFault::Phase2 && r.r.check == 9 && r.r.at < T,
              "(6) an altered placement of a bin sealed in phase 2: Phase2 check 9 at the first carrier over it: " + why(r.r));
    }
    // (6) a write failure poisons the node and leaves the poison mark: the next load is a load failure (the joiner path)
    {
        KatStoreNode s2(net, 64);
        store_chain(s2, 100, 0x92, 2, 41);
        s2.kv.fail_next = 1;
        store_chain(s2, 1, 0x92, 2, 42);
        check(s2.poisoned && s2.kv.get(pb::store_keys::poison(0)).has_value(),
              "(6) a failed commit poisons the node and writes the poison mark");
        const Reloaded r = reload(net, s2.kv, 64);
        check(!r.n && r.r.fault == pb::StoreFault::Poisoned, "(6) the next load: Poisoned (a load failure): " + why(r.r));
        MemoryKv kv3 = s2.kv;
        kv3.data.erase(pb::store_keys::poison(0));
        const Reloaded r3 = reload(net, kv3, 64);
        check(r3.n && r3.n->tree.best().pos == 100, "(6) under the mark the last committed batch is whole: " + why(r3.r));
    }
}

// ---------------------------------------------------------------------------
// (9) the head: absent only in an empty store; unreadable or missing beside other keys: a load failure.
void head_reads() {
    const KatNet net;
    KatStoreNode sn(net, 64);
    store_chain(sn, 40, 0xC1, 1, 71);
    {
        MemoryKv empty;
        check(reload(net, empty, 64).r.fault == pb::StoreFault::NoHead, "(9) an empty store: NoHead (the empty-store start)");
        MemoryKv kv = sn.kv;
        kv.data.erase(pb::store_keys::phead(0));
        const Reloaded r = reload(net, kv, 64);
        check(r.r.fault == pb::StoreFault::BadHead, "(9) K_PHEAD absent beside the store's other keys: a load failure, "
                                                   "not an empty store: " + why(r.r));
        MemoryKv kv2 = sn.kv;
        kv2.read_error.insert(pb::store_keys::phead(0));
        const Reloaded r2 = reload(net, kv2, 64);
        check(r2.r.fault == pb::StoreFault::BadHead, "(9) an unreadable K_PHEAD (IO / checksum error): a load failure: " + why(r2.r));
        MemoryKv kv3 = sn.kv;
        kv3.read_error.insert(pb::store_keys::pcarrier(0, 20));
        check(reload(net, kv3, 64).r.fault == pb::StoreFault::Records, "(9) an unreadable K_PCARRIER: Records");
    }
    {
        // a head that names more positions than the store holds: Records at the first missing one, no allocation from it
        MemoryKv kv = sn.kv;
        pb::StoreHead h = *pb::decode_phead(kv.data[pb::store_keys::phead(0)]);
        h.best_pos = UINT64_MAX - 3;
        kv.data[pb::store_keys::phead(0)] = pb::encode_phead(h);
        pb::LoadResult r;
        bool threw = false;
        try {
            KatNode probe(net, 64);
            r = pb::pathb_load(kv, net.pool_id, net.rules_g, inputs(probe, 64));
        } catch (...) {
            threw = true;
        }
        check(!threw && r.fault == pb::StoreFault::Records && r.at == 41,
              "(9) a head naming position 2^64 - 4: Records at 41, no exception: " + why(r));
    }
    {
        // the lane records beyond leaf_count: deleted at load (3.4 step 2)
        MemoryKv kv = sn.kv;
        const pb::BmmrHead bh = *pb::decode_bmmr(kv.data[pb::lane_keys::bmmr(0)]);
        const std::string stale = pb::lane_keys::blhash(0, bh.leaf_count + 3);
        kv.data[stale] = pb::encode_blhash(seq32(0x5A));
        const Reloaded r = reload(net, kv, 64);
        check(r.n && kv.data.count(stale) == 0, "(9) a K_BLHASH beyond leaf_count: deleted at load: " + why(r.r));
    }
}

// (6) the phase-1 body parent link: a stored body whose tip is not its record's parent (the record links consistent)
void phase1_link() {
    const KatNet net;
    KatStoreNode sn(net, 64);
    store_chain(sn, 3000, 0xC5, 1, 73);
    KatNode probe(net, 64);
    const pb::LoadResult clean = pb::pathb_load(sn.kv, net.pool_id, net.rules_g, inputs(probe, 64));
    check(clean.fault == pb::StoreFault::None && clean.state, "(6) the 3,000-position store loads");
    if (!clean.state) return;
    const std::uint64_t s1 = clean.state->phase1_from;
    check(s1 > 1, "(6) phase 1 starts above position 1 (s1 " + std::to_string(s1) + ")");
    MemoryKv kv = sn.kv;
    const pb::Hash32 fake = seq32(0xFA);
    pb::CarrierRecord below = *pb::decode_pcarrier(kv.data[pb::store_keys::pcarrier(0, s1 - 1)]);
    pb::CarrierRecord at = *pb::decode_pcarrier(kv.data[pb::store_keys::pcarrier(0, s1)]);
    below.id = fake;  // below phase 1: its body is not checked
    at.parent = fake;  // the record links stay consistent
    kv.data[pb::store_keys::pcarrier(0, s1 - 1)] = pb::encode_pcarrier(below);
    kv.data[pb::store_keys::pcarrier(0, s1)] = pb::encode_pcarrier(at);
    const Reloaded r = reload(net, kv, 64);
    check(r.r.fault == pb::StoreFault::Phase1 && r.r.at == s1,
          "(6) a stored body whose tip is not its record's parent: Phase1 at s1: " + why(r.r));
}

void directory() {
    const KatNet net;
    KatStoreNode sn(net, 64);
    store_chain(sn, 40, 0xA1, 1, 51);
    KatNode probe(net, 64);
    check(pb::pathb_load(sn.kv, seq32(0x01), net.rules_g, inputs(probe, 64)).fault == pb::StoreFault::Identity,
          "(7) a store opened under another pool_id: Identity (load failure)");
    check(pb::pathb_load(sn.kv, net.pool_id, seq32(0x02), inputs(probe, 64)).fault == pb::StoreFault::Identity,
          "(7) a store opened under another G: Identity (load failure)");
    check(pb::store_dir_name(net.pool_id, net.rules_g) != pb::store_dir_name(seq32(0x01), net.rules_g)
                  && pb::store_dir_name(net.pool_id, net.rules_g) != pb::store_dir_name(net.pool_id, seq32(0x02))
                  && pb::store_dir_name(net.pool_id, net.rules_g).size() == 129,
          "(7) the directory is named by pool_id and G (64 + 1 + 64 characters)");
    pb::LaneBatch clear;
    check(pb::clear_store_batch(sn.kv, 0, clear) && pb::commit_lane_batch(sn.kv, clear), "(7) an adoption's clear batch");
    std::size_t left = 0;
    for (const auto& [k, v] : sn.kv.data) left += k.rfind("v37s:", 0) == 0 ? 1 : 0;
    check(left == 0, "(7) an adoption leaves no key of the old store (K_PCARRIER, K_AR, lane records, K_PHEAD)");
}

// ---------------------------------------------------------------------------
void archive() {
    const KatNet net;
    KatStoreNode sn(net, 64);
    store_chain(sn, 300, 0xB1, 2, 61);
    const std::filesystem::path dir = std::filesystem::temp_directory_path()
                                      / ("pathb_store_kat_" + pb::store_dir_name(net.pool_id, net.rules_g).substr(0, 16));
    std::filesystem::remove_all(dir);
    {
        std::unique_ptr<pb::PathbKv> db = pb::open_pathb_store(dir.string());
        check(db != nullptr, "(8) the archive opens a new directory");
        if (!db) return;
        pb::LaneBatch all;
        for (const auto& [k, v] : sn.kv.data) all.put(k, v);
        check(pb::commit_lane_batch(*db, all), "(8) a batch commits (synced)");
    }
    {
        std::unique_ptr<pb::PathbKv> db = pb::open_pathb_store(dir.string());
        check(db != nullptr && db->get(pb::store_keys::phead(0)) == sn.kv.get(pb::store_keys::phead(0)),
              "(8) the archive reopens with its records");
        if (!db) return;
        KatNode probe(net, 64);
        pb::LoadResult r = pb::pathb_load(*db, net.pool_id, net.rules_g, inputs(probe, 64));
        check(r.fault == pb::StoreFault::None && r.state && r.state->tree.best().id == sn.n.tree.best().id
                      && r.state->store.head().root == sn.n.store.head().root,
              "(8) the store loads from the archive to the live tip and MMR: " + why(r));
        pb::LaneBatch del;
        del.del(pb::store_keys::phead(0));
        check(pb::commit_lane_batch(*db, del) && !db->get(pb::store_keys::phead(0)), "(8) a delete commits");
    }
    std::filesystem::remove_all(dir);
}

// ---------------------------------------------------------------------------
// (10) a pruned store (prune_batch): K_PCARRIER below first deleted, [first, root) header records, the record at the
// root whole, K_PHEAD first_pos / root_pos / base_pos >= root; K_BLHASH, K_BLEAF and K_AR untouched. A store launched
// here (no AR seed) and a joined store (its AR seed below the pruned root) reload live-equal (the tree from the root,
// its retarget window from the records), the header records as prefix headers; the reloaded node places the next
// carriers as the live one.
std::size_t keys_under(const MemoryKv& kv, const std::string& prefix) {
    std::size_t n = 0;
    for (auto it = kv.data.lower_bound(prefix); it != kv.data.end() && it->first.compare(0, prefix.size(), prefix) == 0; ++it)
        ++n;
    return n;
}

std::vector<std::pair<std::uint64_t, std::uint64_t>> window_through(const pb::CarrierTree& t, const pb::Hash32& id) {
    std::vector<std::pair<std::uint64_t, std::uint64_t>> out;
    if (const auto e = t.window_entries(id, pb::kRuledLaneParams.retarget_span))
        for (const pb::RetargetEntry& r : *e) out.emplace_back(r.d, r.H);
    return out;
}

void pruned() {
    const KatNet net;
    KatStoreNode sn(net, 64);
    store_chain(sn, 3700, 0x87, 2, 27);
    KatNode& n = sn.n;
    const auto header_only = [](const std::optional<std::string>& v) {
        const std::optional<pb::CarrierRecord> c = v ? pb::decode_pcarrier(*v) : std::nullopt;
        return c && !c->state && c->kind == pb::RecordBody::Header && c->placements.empty();
    };
    const auto whole = [](const std::optional<std::string>& v) {
        const std::optional<pb::CarrierRecord> c = v ? pb::decode_pcarrier(*v) : std::nullopt;
        return c && c->state && c->kind == pb::RecordBody::Carrier;
    };
    {
        const std::uint64_t first = 100, root = 2400;  // first <= root + 1 - N_rt: the root's retarget window held
        MemoryKv kv = sn.kv;
        pb::StoreHead h = *pb::decode_phead(*kv.get(pb::store_keys::phead(0)));
        const std::size_t blhash = keys_under(kv, pb::lane_keys::blhash_prefix(0)),
                          bleaf = keys_under(kv, pb::lane_keys::bleaf_prefix(0));
        const std::optional<pb::LaneBatch> b = pb::prune_batch(0, h, n.tree, n.store, n.bodies, first, root);
        check(b && pb::commit_lane_batch(kv, *b), "(10) the prune batch of a store launched here commits");
        const pb::StoreHead hd = *pb::decode_phead(*kv.get(pb::store_keys::phead(0)));
        check(!kv.get(pb::store_keys::pcarrier(0, first - 1)) && header_only(kv.get(pb::store_keys::pcarrier(0, first)))
                      && header_only(kv.get(pb::store_keys::pcarrier(0, root - 1))) && whole(kv.get(pb::store_keys::pcarrier(0, root)))
                      && hd.first_pos == first && hd.root_pos == root && hd.base_pos >= root
                      && keys_under(kv, pb::lane_keys::blhash_prefix(0)) == blhash && keys_under(kv, pb::lane_keys::bleaf_prefix(0)) == bleaf
                      && keys_under(kv, pb::store_keys::ar_prefix(0)) == 0,
              "(10) records below first deleted, header records to the root, the root's whole; K_BLHASH, K_BLEAF untouched");
        Reloaded r = reload(net, kv, 64);
        check(r.r.fault == pb::StoreFault::None, "(10) the pruned store reloads: " + why(r.r));
        if (r.n) {
            const pb::Hash32 root_id = *n.store.best_at(root);
            check(lane_digest(*r.n) == lane_digest(n) && r.n->tree.genesis().id == root_id && r.n->store.first_record_pos() == first
                          && r.r.state->prefix_headers.size() == root - first && r.n->ar.rows().empty() && !r.n->ar.joiner_p0()
                          && window_through(r.n->tree, root_id) == window_through(n.tree, root_id)
                          && window_through(n.tree, root_id).size() == pb::kRuledLaneParams.retarget_span,
                  "(10) live-equal from the root (" + std::to_string(root) + "), the root's retarget window, the prefix headers, "
                  "the genesis AR");
            KatNode live(n);
            bool same = true;
            for (std::uint64_t k = 0; k < 5; ++k) {
                const pb::CarrierNode& best = live.tree.best();
                const pb::CarrierBodyV3 c = scaffold_carrier(live, best.id, h_pos(best.pos + 1), 0x88, 9000 + k, 2, {});
                same = same && place_direct(live, c).outcome == pb::WriteOutcome::Extended
                       && place_direct(*r.n, c).outcome == pb::WriteOutcome::Extended && lane_digest(live) == lane_digest(*r.n);
            }
            check(same, "(10) the reloaded node places the next carriers as the live one");
        }
    }
    {
        // a joined store (root 2,300, its AR seed there, base 3,600) pruned at root 2,450 (the seed below it; at or
        // below the phase-1 start of a restart at J 64), its records from 200 (the root's retarget window held)
        const std::uint64_t first = 200, root = 2450;
        MemoryKv kv = joined_shape(sn.kv, n, 2300, 3600);
        pb::StoreHead h = *pb::decode_phead(*kv.get(pb::store_keys::phead(0)));
        const std::string seed = *kv.get(pb::store_keys::ar(0, 2300));
        const std::optional<pb::LaneBatch> b = pb::prune_batch(0, h, n.tree, n.store, n.bodies, first, root);
        check(b && pb::commit_lane_batch(kv, *b) && kv.get(pb::store_keys::ar(0, 2300)) == seed,
              "(10) the prune batch of a joined store commits; its AR seed row kept");
        Reloaded r = reload(net, kv, 64);
        check(r.r.fault == pb::StoreFault::None, "(10) the pruned joined store reloads: " + why(r.r));
        if (r.n) {
            const pb::TipWindow a = n.window(n.tree.best().id), c = r.n->window(r.n->tree.best().id);
            check(a.ok() && c.ok() && a.window_root == c.window_root && a.mmr_root == c.mmr_root
                          && r.n->tree.best().id == n.tree.best().id && r.n->tree.best().rs == n.tree.best().rs
                          && r.n->tree.genesis().pos == root && r.n->ar.rows().size() == 1 && r.n->ar.joiner_p0() == 2301,
                  "(10) the pruned joined store: the live window and roots, S at the tip, AR = the joiner seed below the root");
        }
    }
}

}  // namespace

int main(int argc, char** argv) {
    std::printf("v37_xmr_pathb_store_kat\n");
    const std::string only = argc > 1 ? argv[1] : "";
    const auto run = [&](const char* name, void (*fn)()) {
        if (only.empty() || only == name) run_part(name, fn);
    };
    run("codecs", codecs);
    run("load", batches_and_load);
    run("switch", switch_batch);
    run("prefix", prefix_and_joined);
    run("f5", f5);
    run("faults", faults);
    run("head", head_reads);
    run("phase1link", phase1_link);
    run("directory", directory);
    run("archive", archive);
    run("pruned", pruned);
    return finish("v37_xmr_pathb_store_kat");
}
