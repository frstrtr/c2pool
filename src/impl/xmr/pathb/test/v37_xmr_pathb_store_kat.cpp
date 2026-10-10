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
//   (5) phase 1 checks every stored body below q0 (id, parent, fold): a
//       corrupted body is a load failure; so is a broken parent link;
//   (6) a write failure poisons the node and leaves the last committed
//       position loadable; a torn K_PCARRIER, a stale K_AR row above the tip,
//       an anchor mismatch: load failure (the joiner path);
//   (7) the directory: K_PHEAD naming another pool_id or G is a load failure;
//       another pool or G has its own directory name; an adoption clears
//       every key of the old store;
//   (8) the LevelDB archive: the same store written through it, reopened,
//       loads to the live state.
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
    const pb::LaneView bv = n.store.view_at(*n.store.best_at(base));
    h.base_leaf_count = bv.leaf_count();
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
    Reloaded r = reload(net, kv, 64);
    check(r.r.fault == pb::StoreFault::None, "(4) the joined-shape store loads: " + why(r.r));
    if (r.n) {
        const pb::TipWindow a = n.window(n.tree.best().id), b = r.n->window(r.n->tree.best().id);
        check(a.ok() && b.ok() && a.window_root == b.window_root && a.mmr_root == b.mmr_root
                      && r.n->tree.best().id == n.tree.best().id && r.n->tree.best().rs == n.tree.best().rs
                      && r.n->ar.rows().size() == 1 && r.n->ar.joiner_p0() == root + 1,
              "(4) the joined-shape store: the live window and roots, S at the tip, AR = the joiner seed");
    }
    // one position after the base
    {
        MemoryKv k2 = kv;
        pb::StoreHead h2 = h;
        h2.base_pos = 3699;
        h2.base_leaf_count = n.store.view_at(*n.store.best_at(3699)).leaf_count();
        h2.base_peaks = *n.store.best_mmr().prefix_peaks(h2.base_leaf_count);
        k2.data[pb::store_keys::phead(0)] = pb::encode_phead(h2);
        for (std::uint64_t i = h.base_leaf_count; i < h2.base_leaf_count; ++i) {
            k2.data.erase(pb::lane_keys::blhash(0, i));
            k2.data.erase(pb::lane_keys::bleaf(0, i));
        }
        Reloaded r2 = reload(net, k2, 64);
        check(r2.n && r2.r.state->q0 == 3700 && r2.n->tree.best().id == n.tree.best().id,
              "(4) a store one position after its base reloads: " + why(r2.r));
    }
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
    // (6) a write failure poisons the node; the store keeps its last committed position
    {
        KatStoreNode s2(net, 64);
        store_chain(s2, 100, 0x92, 2, 41);
        s2.kv.fail_next = 1;
        store_chain(s2, 1, 0x92, 2, 42);
        check(s2.poisoned, "(6) a failed commit poisons the node (templates stop; the joiner path at the next start)");
        const Reloaded r = reload(net, s2.kv, 64);
        check(r.n && r.n->tree.best().pos == 100, "(6) the store loads at its last committed position: " + why(r.r));
    }
}

// ---------------------------------------------------------------------------
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
    run("faults", faults);
    run("directory", directory);
    run("archive", archive);
    return finish("v37_xmr_pathb_store_kat");
}
