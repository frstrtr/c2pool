// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// v37_xmr_bin_fold_kat (pathb_buckets.hpp, pathb_receipt_admission.hpp, C01,
// C33, K06, ruling 27 K-11): the fold carrier f is the first position with
// H(f) >= b + F; f still carries bin b, f+1 does not (open_at over H(pos - 1));
// the bin SEALS at f, D_fin = 0; a late push into a sealed bin is REFUSED by
// check_carried_list (STRIKE SealedBin, the entry named), never dropped
// silently; a reorg across the fold re-seals to the same bytes as a fresh node.
// ---------------------------------------------------------------------------
#include <cstdint>
#include <vector>

#include "impl/xmr/pathb/pathb_buckets.hpp"
#include "impl/xmr/pathb/pathb_params.hpp"
#include "impl/xmr/pathb/pathb_ratchet_state.hpp"
#include "impl/xmr/pathb/pathb_receipt_admission.hpp"
#include "pathb_kat_bodies.hpp"
#include "pathb_kat_check.hpp"

using namespace pathb_kat;
namespace pb = ::c2pool::xmr::pathb;

static pb::Hash32 rep(std::uint8_t b) { pb::Hash32 h{}; h.fill(b); return h; }

// ---------------------------------------------------------------------------
// S3b-1a (pathb_bin_store.hpp; C25, C36, E-8, ruling 31 P-2 / P-3): the bin
// store per held branch, the seal driver, the dense MMR.
//   V1  sealed push: q = f Accepted, q = f + 1 Expired, the store unchanged
//   V2  dedup and rewind: Duplicate on one chain, Accepted after a rewind
//   V3  FR-B1 gap: dense leaves, mmr_root dc6ff5da..., not the sparse fc3c8bd1...
//   V4  dead-only bin: the empty leaf; window W 240,000, 3 payees
//   V5  S(b) = the live placements with q <= f
//   V6  leaf_count law: b0 + 95 -> 0, b0 + 96 -> 1, b0 + 98 -> 3
//   V7  reorg across a fold: leaf popped, a different leaf re-sealed, a fresh
//       store reproduces leaf_count, mmr_root and the bucket bytes
//   V8  bucket cross-check against the rows
//   V9  sibling race with a shared receipt and an orphan re-carry: both admitted
//   V10 deep fork: DEFER, no verdict
//   V11 side-branch seal: the side view's mmr_root_at == a fresh node's root
//   P-2 miner_count = distinct row.miner, rows with w_miner 0 included
// ---------------------------------------------------------------------------
#include <exception>
#include <optional>
#include <string>

#include "impl/xmr/pathb/pathb_bin_store.hpp"
#include "impl/xmr/pathb/pathb_window.hpp"

namespace {

constexpr std::uint64_t kB0 = 3500000;
constexpr std::uint64_t kJ = 64;

// distinct ids: tag byte, then a counter.
pb::Hash32 idn(std::uint8_t tag, std::uint64_t n) {
    pb::Hash32 h{};
    h[0] = tag;
    for (int i = 0; i < 8; ++i) h[1 + i] = static_cast<std::uint8_t>(n >> (8 * i));
    return h;
}

std::string hx(const pb::Hash32& h) { return hex(h.data(), h.size()); }

pb::Placement rcpt(const pb::Hash32& id, std::uint64_t bin, std::uint64_t p_own, const pb::Hash32& payee,
                   std::uint64_t work, std::uint16_t p = 0, std::uint16_t ga = 0,
                   const pb::Hash32& owner = pb::Hash32{}) {
    pb::Placement x;
    x.id = id;
    x.bin = bin;
    x.p_own = p_own;
    x.payee = payee;
    x.owner = owner;
    x.p = p;
    x.give_author_bp = ga;
    x.work = work;
    return x;
}

// add + ingest + seal (+ best); every verdict appended to *v.
bool extend(pb::BinStore& s, const pb::Hash32& id, const pb::Hash32& parent, std::uint64_t h,
            const std::vector<pb::Placement>& pls, bool best, std::vector<pb::Ingest>* v = nullptr) {
    if (s.add_carrier(id, parent, h) != pb::AddVerdict::Added) return false;
    for (const pb::Placement& x : pls) {
        const std::optional<pb::Ingest> r = s.ingest(id, x);
        if (!r) return false;
        if (v) v->push_back(*r);
    }
    if (!s.seal(id)) return false;
    if (best && s.switch_best(id) != pb::SwitchVerdict::Switched) return false;
    return true;
}

pb::L1Bucket bucket_of(const std::vector<pb::Placement>& xs, std::uint64_t bin, std::uint64_t q) {
    std::vector<pb::WinEntry> e;
    for (pb::Placement x : xs) {
        x.q = q;
        e.push_back(pb::win_entry_of(x));
    }
    return pb::seal_from_entries(bin, e);
}

std::size_t count_id(const std::vector<const pb::Placement*>& v, const pb::Hash32& id) {
    std::size_t n = 0;
    for (const pb::Placement* x : v) n += x->id == id ? 1 : 0;
    return n;
}

}  // namespace

// A vector that throws (a broken store invariant) fails by name instead of aborting the KAT.
template <class Body>
static void run_vector(const char* name, Body&& body) {
    try {
        body();
    } catch (const std::exception& e) {
        check(false, std::string(name) + ": exception " + e.what());
    }
}

static void s3b_store_vectors() {
    const pb::LaneParams P = pb::kRuledLaneParams;
    const std::uint64_t F = P.open_bins;  // 96
    // H over carriers: one Monero height every 12 positions (120 s / T 10 s).
    auto h_at = [](std::uint64_t pos) -> std::uint64_t { return kB0 + pos / 12; };
    const std::uint64_t b = kB0;
    bool found = false;
    const std::uint64_t f = pb::fold_pos(h_at, /*n_positions=*/4000, b, F, found);
    check(found && f == 1152 && h_at(f) == b + F && h_at(f - 1) == b + F - 1,
          "store chain: fold at f = 1152, H(f) = b + 96 exactly, H(f - 1) = b + 95");

    // ---- V1 / V5 / V6 on one best chain: positions 1 .. 1180, h = b0 + pos / 12 ----
    run_vector("V1 / V5 / V6 on one best chain: positions 1 .. 1180, h = b0 + pos / 12", [&] {
        pb::BinStore s(P, kB0, kJ, idn(0xC0, 0), h_at(0));
        const pb::Placement p1 = rcpt(idn(0xA1, 1), b, 9, rep(0x11), 30000);   // q 10: H(9) = b0, live
        const pb::Placement p2 = rcpt(idn(0xA1, 2), b, 5, rep(0x12), 25000);   // q 50, tip at 4: live
        const pb::Placement pa = rcpt(idn(0xA1, 3), b, 3, rep(0x13), 40000);   // q = f, tip at 2: live
        const pb::Placement pb_late = rcpt(idn(0xA1, 4), b, 3, rep(0x14), 50000);  // q = f + 1
        bool built = true;
        std::optional<pb::Ingest> at_f, at_f1;
        std::size_t count_before = 0, count_after = 0, delta_before = 0, delta_after = 0;
        for (std::uint64_t x = 1; x <= 1180 && built; ++x) {
            const pb::Hash32 id = idn(0xC0, x), parent = idn(0xC0, x - 1);
            built = s.add_carrier(id, parent, h_at(x)) == pb::AddVerdict::Added;
            if (x == 10) built = built && s.ingest(id, p1) == pb::Ingest::Accepted;
            if (x == 50) built = built && s.ingest(id, p2) == pb::Ingest::Accepted;
            if (x == f) at_f = s.ingest(id, pa);
            if (x == f + 1) {
                count_before = s.view_at(parent).placement_count();
                delta_before = s.delta(id)->placed.size();
                at_f1 = s.ingest(id, pb_late);
                delta_after = s.delta(id)->placed.size();
            }
            built = built && s.seal(id).has_value() && s.switch_best(id) == pb::SwitchVerdict::Switched;
            if (x == f + 1) count_after = s.view_at(id).placement_count();
        }
        check(built, "V1 chain of 1,180 carriers built");
        check(at_f == pb::Ingest::Accepted, "V1 bin-b placement carried by the fold carrier (q = f) Accepted");
        check(at_f1 == pb::Ingest::Expired, "V1 bin-b placement at q = f + 1 Expired (H(f) == b + F)");
        check(delta_before == delta_after && count_before == count_after,
              "V1 the refusal leaves the store unchanged");
        check(s.ingest(idn(0xC0, 1180), pb_late) == std::nullopt, "V1 a sealed carrier takes no placement");

        const pb::LaneView v = s.view_at(s.best_tip());
        check(v.ok() && v.pos() == 1180, "best view at 1,180");
        // V5: S(b) = {q 10, q 50, q f}; the q f + 1 attempt is not in it.
        const pb::SealedBin* sb = v.bucket(b);
        const pb::L1Bucket want = [&] {
            std::vector<pb::WinEntry> e;
            pb::Placement a = p1, c = p2, d = pa;
            a.q = 10;
            c.q = 50;
            d.q = f;
            for (const pb::Placement* x : {&a, &c, &d}) e.push_back(pb::win_entry_of(*x));
            return pb::seal_from_entries(b, e);
        }();
        check(sb != nullptr && sb->sealed_at == f, "V5 bin b sealed at f");
        check(sb != nullptr && pb::mmr_leaf_of(sb->bucket) == pb::mmr_leaf_of(want),
              "V5 S(b) = the live placements with q <= f (q 10, q 50, q f)");
        check(sb != nullptr && sb->bucket.raw_sum == pb::Work(95000) && sb->bucket.miner_count == 3
                      && sb->bucket.d_min == 25000 && sb->bucket.rows.size() == 3,
              "V5 raw_sum 95,000, miner_count 3, d_min 25,000 from the rows");
        check(sb != nullptr && pb::bucket_consistent(sb->bucket), "V5 the sealed bucket is consistent");
        // V6: the leaf_count law on the chain's own record.
        check(v.record(1151) == b + 95 && v.leaf_count_at(1151) == 0, "V6 H = b0 + 95 -> leaf_count 0");
        check(v.record(1152) == b + 96 && v.leaf_count_at(1152) == 1, "V6 H = b0 + 96 -> leaf_count 1");
        check(v.record(1176) == b + 98 && v.leaf_count_at(1176) == 3, "V6 H = b0 + 98 -> leaf_count 3");
        check(pb::bin_leaf_count(b + 95, kB0, F) == 0 && pb::bin_leaf_count(b + 96, kB0, F) == 1
                      && pb::bin_leaf_count(b + 98, kB0, F) == 3 && pb::bin_leaf_count(b - 1, kB0, F) == 0,
              "V6 lc(H) = max(0, H - F - b0 + 1)");
        check(s.best_mmr().leaf_count() == v.leaf_count() && s.head().root == v.mmr_root(),
              "V6 the best MMR holds exactly lc(H(tip)) leaves");
        check(v.mmr_root_at(1151) == pb::Hash32{} && v.mmr_root_at(1152) != pb::Hash32{}
                      && v.mmr_root_at(1152) == *s.best_mmr().prefix_root(1),
              "mmr_root_at(t) = the root over lc(H(t)) leaves (zero before the first seal)");
    });
    {
        // a bin below b0 is refused by the store (no leaf would ever commit it).
        pb::BinStore s(P, kB0, kJ, idn(0xC9, 0), kB0);
        check(s.add_carrier(idn(0xC9, 1), idn(0xC9, 0), kB0) == pb::AddVerdict::Added, "below-b0 store");
        check(s.ingest(idn(0xC9, 1), rcpt(idn(0xA9, 1), kB0 - 1, 1, rep(0x19), 30000)) == pb::Ingest::Expired,
              "a placement of bin b0 - 1 Expired");
    }

    // ---- V2 dedup and rewind ----
    run_vector("V2 dedup and rewind", [&] {
        pb::BinStore s(P, kB0, kJ, idn(0xD0, 0), kB0);
        const pb::Placement r = rcpt(idn(0xA2, 1), kB0, 1, rep(0x21), 30000);
        bool ok = true;
        ok = ok && extend(s, idn(0xD0, 1), idn(0xD0, 0), kB0, {}, true);
        std::vector<pb::Ingest> v;
        ok = ok && s.add_carrier(idn(0xD0, 2), idn(0xD0, 1), kB0) == pb::AddVerdict::Added;
        v.push_back(*s.ingest(idn(0xD0, 2), r));
        v.push_back(*s.ingest(idn(0xD0, 2), r));
        ok = ok && s.seal(idn(0xD0, 2)) && s.switch_best(idn(0xD0, 2)) == pb::SwitchVerdict::Switched;
        for (std::uint64_t x = 3; x <= 5; ++x) ok = ok && extend(s, idn(0xD0, x), idn(0xD0, x - 1), kB0, {}, true);
        ok = ok && s.add_carrier(idn(0xD0, 6), idn(0xD0, 5), kB0) == pb::AddVerdict::Added;
        v.push_back(*s.ingest(idn(0xD0, 6), r));
        check(ok && v[0] == pb::Ingest::Accepted && v[1] == pb::Ingest::Duplicate && v[2] == pb::Ingest::Duplicate,
              "V2 the same id twice on one chain -> Duplicate");
        // branch E forks at position 1 (below the placement at q 2) and grows to 7.
        bool okb = true;
        for (std::uint64_t x = 2; x <= 7; ++x)
            okb = okb && extend(s, idn(0xE0, x), x == 2 ? idn(0xD0, 1) : idn(0xE0, x - 1), kB0, {}, false);
        check(okb && s.switch_best(idn(0xE0, 7)) == pb::SwitchVerdict::Switched, "V2 switch to the branch forked at 1");
        check(!s.view_at(idn(0xE0, 7)).placed_open(r.id), "V2 the rewind freed the id");
        check(s.add_carrier(idn(0xE0, 8), idn(0xE0, 7), kB0) == pb::AddVerdict::Added
                      && s.ingest(idn(0xE0, 8), r) == pb::Ingest::Accepted,
              "V2 the same id Accepted again after the rewind (S:430-432)");
        check(s.view_at(idn(0xD0, 5)).status() == pb::ViewStatus::Ok && s.view_at(idn(0xD0, 5)).placed_open(r.id),
              "V2 the abandoned branch still sees its own placement");
    });

    // ---- V3 FR-B1 gap: dense MMR (E-8) ----
    run_vector("V3 FR-B1 gap: dense MMR (E-8)", [&] {
        pb::BinStore s(P, kB0, kJ, idn(0xF0, 0), kB0);
        const pb::Hash32 aa = rep(0xAA);
        bool ok = extend(s, idn(0xF0, 1), idn(0xF0, 0), kB0, {rcpt(idn(0xA3, 1), kB0, 1, aa, 18180)}, true);
        ok = ok && extend(s, idn(0xF0, 2), idn(0xF0, 1), kB0 + 2, {rcpt(idn(0xA3, 2), kB0 + 2, 2, aa, 18180)}, true);
        ok = ok && s.add_carrier(idn(0xF0, 3), idn(0xF0, 2), kB0 + 98) == pb::AddVerdict::Added;
        const std::optional<std::uint64_t> n_sealed = s.seal(idn(0xF0, 3));
        ok = ok && s.switch_best(idn(0xF0, 3)) == pb::SwitchVerdict::Switched;
        const pb::LaneView v = s.view_at(idn(0xF0, 3));
        check(ok && n_sealed == std::uint64_t{3}, "V3 one carrier seals three bins (record jump)");
        check(v.leaf_count() == 3 && s.best_mmr().leaf_count() == 3, "V3 H = 3,500,098: leaf_count 3");
        const pb::BinMmr& m = s.best_mmr();
        check(m.leaf(0) && hx(*m.leaf(0)) == "2236549787e6f158bfe596d94b96457abc7e6c822c2c9793f6e073e50485a201",
              "V3 leaf 0 golden");
        check(m.leaf(1) && hx(*m.leaf(1)) == "dcd7becdd422d3ff25c6477a1f9f26de4c109baf2930b1361bc7d09d46dc8417",
              "V3 leaf 1 = the zero leaf of 3,500,001");
        check(m.leaf(2) && hx(*m.leaf(2)) == "891c80d0569ee5b875f2d4f3c53b011845a9086cd940074d7821644ef76ff239",
              "V3 leaf 2 golden");
        check(hx(v.mmr_root()) == "dc6ff5da350b6e8e7b21fd6e75332e3d5acb872e3637378a5c476486ed9dd49c",
              "V3 mmr_root golden (dense)");
        check(hx(v.mmr_root()) != "fc3c8bd1c504726dc626436ae725d1c7a62007142e006a1e4bf5950fcaf5fdff",
              "V3 the sparse form is not the root");
        const pb::SealedBin* e = v.bucket(kB0 + 1);
        check(e != nullptr && e->bucket.rows.empty() && e->bucket.raw_sum.is_zero() && e->bucket.d_min == 0
                      && e->bucket.miner_count == 0 && e->bucket.comp_root_v == pb::Hash32{},
              "V3 the empty bin's LeafPayload: raw_sum 0, miner_count 0, d_min 0, comp_root zero");
    });

    // ---- V4 dead-only bin ----
    run_vector("V4 dead-only bin", [&] {
        pb::BinStore s(P, kB0, kJ, idn(0xF4, 0), kB0);
        bool ok = extend(s, idn(0xF4, 1), idn(0xF4, 0), kB0,
                         {rcpt(idn(0xA4, 1), kB0, 1, rep(0xBB), 80000), rcpt(idn(0xA4, 2), kB0, 1, rep(0xCC), 80000)},
                         true);
        ok = ok && extend(s, idn(0xF4, 2), idn(0xF4, 1), kB0 + 2, {rcpt(idn(0xA4, 3), kB0 + 2, 2, rep(0xAA), 80000)},
                          true);
        // q 3, own position 3: live iff b0 + 1 >= H(2) = b0 + 2: DEAD (open: H(2) < b0 + 1 + F).
        const pb::Placement dead = rcpt(idn(0xA4, 4), kB0 + 1, 3, rep(0xDD), 18180);
        std::vector<pb::Ingest> iv;
        ok = ok && extend(s, idn(0xF4, 3), idn(0xF4, 2), kB0 + 5, {dead}, true, &iv);
        check(ok && iv.size() == 1 && iv[0] == pb::Ingest::Accepted, "V4 the dead placement is stored");
        const pb::LaneView v3 = s.view_at(idn(0xF4, 3));
        check(v3.placement_count() == 4 && v3.live_entries(kB0 + 1, 3).empty(), "V4 stored dead, never live");
        check(s.add_carrier(idn(0xF4, 4), idn(0xF4, 3), kB0 + 98) == pb::AddVerdict::Added
                      && s.ingest(idn(0xF4, 4), dead) == pb::Ingest::Duplicate,
              "V4 a dead placement still deduplicates");
        ok = ok && s.seal(idn(0xF4, 4)) && s.switch_best(idn(0xF4, 4)) == pb::SwitchVerdict::Switched;
        const pb::LaneView v = s.view_at(idn(0xF4, 4));
        check(ok && v.leaf_count() == 3, "V4 three bins sealed");
        check(s.best_mmr().leaf(1)
                      && hx(*s.best_mmr().leaf(1)) == "dcd7becdd422d3ff25c6477a1f9f26de4c109baf2930b1361bc7d09d46dc8417",
              "V4 the dead-only bin seals the zero leaf");
        std::vector<pb::WinBin> bins;
        for (std::uint64_t bin : {kB0 + 2, kB0 + 1, kB0}) {
            pb::WinBin wb;
            wb.bin = bin;
            for (const pb::Placement* x : v.live_entries(bin, v.pos())) wb.entries.push_back(pb::win_entry_of(*x));
            bins.push_back(wb);
        }
        const std::uint64_t B = 600000000000ull;
        const pb::Window w = pb::window(bins, /*D_net=*/1000000000ull, B, /*f_spend=*/B / 4, /*N=*/100, pb::Hash32{});
        check(w.W == pb::Work(240000) && pb::detail_win::payee_count(w) == 3,
              "V4 window over the sealed views: W 240,000, 3 payees");
    });

    // ---- V7 reorg across a fold ----
    run_vector("V7 reorg across a fold", [&] {
        const pb::Placement r1 = rcpt(idn(0xA7, 1), kB0, 1, rep(0x21), 30000);
        const pb::Placement r2 = rcpt(idn(0xA7, 2), kB0, 1, rep(0x22), 40000);
        const pb::Placement r3 = rcpt(idn(0xA7, 3), kB0, 1, rep(0x23), 50000);
        pb::BinStore s(P, kB0, kJ, idn(0x70, 0), kB0);
        bool ok = extend(s, idn(0x70, 1), idn(0x70, 0), kB0, {r1}, true);
        ok = ok && extend(s, idn(0x70, 2), idn(0x70, 1), kB0 + 96, {r2}, true);  // fold of bin b0 at 2
        const pb::Hash32 leaf_a = *s.best_mmr().leaf(0);
        const pb::Hash32 root_fork = s.view_at(idn(0x70, 1)).mmr_root();
        check(ok && s.head().leaf_count == 1, "V7 branch A seals bin b0 at position 2");
        // branch B forks at 1 (below f): its position 2 does not fold.
        ok = ok && extend(s, idn(0x7B, 2), idn(0x70, 1), kB0 + 50, {}, false);
        check(ok && s.switch_best(idn(0x7B, 2)) == pb::SwitchVerdict::Switched, "V7 switch to B");
        check(s.head().leaf_count == 0 && s.best_mmr().leaf_count() == 0 && s.head().root == root_fork,
              "V7 the switch pops the leaf: leaf_count and root of the fork point");
        ok = ok && extend(s, idn(0x7B, 3), idn(0x7B, 2), kB0 + 96, {r2, r3}, true);  // B's fold carries one more
        check(ok && s.head().leaf_count == 1 && *s.best_mmr().leaf(0) != leaf_a, "V7 B seals a different leaf");
        pb::BinStore fresh(P, kB0, kJ, idn(0x70, 0), kB0);
        bool okf = extend(fresh, idn(0x70, 1), idn(0x70, 0), kB0, {r1}, true);
        okf = okf && extend(fresh, idn(0x7B, 2), idn(0x70, 1), kB0 + 50, {}, true);
        okf = okf && extend(fresh, idn(0x7B, 3), idn(0x7B, 2), kB0 + 96, {r2, r3}, true);
        check(okf && fresh.head().leaf_count == s.head().leaf_count && fresh.head().root == s.head().root,
              "V7 a fresh store fed B reproduces leaf_count and mmr_root");
        const pb::SealedBin* x = s.view_at(s.best_tip()).bucket(kB0);
        const pb::SealedBin* y = fresh.view_at(fresh.best_tip()).bucket(kB0);
        check(x && y && pb::encode_bleaf(*x) == pb::encode_bleaf(*y), "V7 ... and the bucket bytes");
        check(s.switch_best(idn(0x70, 2)) == pb::SwitchVerdict::Switched && *s.best_mmr().leaf(0) == leaf_a,
              "V7 switching back re-seals branch A's leaf");
    });

    // ---- V8 cross-check of a bucket against its rows ----
    run_vector("V8 cross-check of a bucket against its rows", [&] {
        std::vector<pb::Placement> xs = {rcpt(idn(0xA8, 1), kB0, 1, rep(0x31), 30000, 100, 10, rep(0x51)),
                                         rcpt(idn(0xA8, 2), kB0, 1, rep(0x32), 20000)};
        const pb::L1Bucket good = bucket_of(xs, kB0, 1);
        check(pb::bucket_check(good) == pb::BucketFault::None, "V8 a sealed bucket is consistent");
        pb::L1Bucket bad = good;
        bad.raw_sum += pb::Work(1);
        check(pb::bucket_check(bad) == pb::BucketFault::RawSum && !pb::bucket_consistent(bad),
              "V8 raw_sum off by 1 from the rows fails");
        bad = good;
        bad.miner_count = 3;
        check(pb::bucket_check(bad) == pb::BucketFault::MinerCount, "V8 miner_count not from the rows fails");
        bad = good;
        bad.comp_root_v[0] ^= 1;
        check(pb::bucket_check(bad) == pb::BucketFault::CompRoot, "V8 comp_root not from the rows fails");
        bad = good;
        std::swap(bad.rows[0], bad.rows[1]);
        check(pb::bucket_check(bad) == pb::BucketFault::RowOrder, "V8 rows out of order fail");
        bad = good;
        bad.d_min = 0;
        check(pb::bucket_check(bad) == pb::BucketFault::Empty, "V8 d_min 0 in a non-empty bucket fails");
        bad = good;
        bad.d_min = 25001;
        check(pb::bucket_check(bad) == pb::BucketFault::RowBound, "V8 rows x d_min > raw_sum fails");
        bad = good;
        bad.bin_hi = bad.bin_lo + 1;
        check(pb::bucket_check(bad) == pb::BucketFault::BinRange, "V8 bin_lo != bin_hi fails");
        check(pb::bucket_consistent(pb::seal_from_entries(kB0, {})), "V8 the empty bucket is consistent");
    });

    // ---- P-2 miner_count (ruling 31) ----
    run_vector("P-2 miner_count (ruling 31)", [&] {
        // one miner with two owners -> two rows, one miner; a row whose w_miner is 0 is counted.
        const pb::L1Bucket two_owner = bucket_of({rcpt(idn(0xA9, 1), kB0, 1, rep(0x41), 30000, 100, 0, rep(0x61)),
                                                  rcpt(idn(0xA9, 2), kB0, 1, rep(0x41), 30000, 200, 0, rep(0x62)),
                                                  rcpt(idn(0xA9, 3), kB0, 1, rep(0x42), 30000)},
                                                 kB0, 1);
        check(two_owner.rows.size() == 3 && two_owner.miner_count == 2,
              "P-2 miner_count = distinct row.miner (3 rows, 2 miners)");
        const pb::L1Bucket zero_w = bucket_of({rcpt(idn(0xAA, 1), kB0, 1, rep(0x43), 20000, 9990, 10, rep(0x63)),
                                               rcpt(idn(0xAA, 2), kB0, 1, rep(0x44), 20000)},
                                              kB0, 1);
        bool has_zero = false;
        for (const pb::BucketRow& r : zero_w.rows) has_zero = has_zero || r.w_miner.is_zero();
        check(has_zero && zero_w.miner_count == 2, "P-2 a row with w_miner 0 (p + give_author_bp = 10000) is counted");
        check(pb::bucket_consistent(two_owner) && pb::bucket_consistent(zero_w), "P-2 both buckets consistent");
    });

    // ---- V9 sibling race: shared receipt, orphan re-carry ----
    run_vector("V9 sibling race: shared receipt, orphan re-carry", [&] {
        pb::BinStore s(P, kB0, kJ, idn(0x90, 0), kB0);
        bool ok = extend(s, idn(0x90, 1), idn(0x90, 0), kB0, {}, true);
        const pb::Hash32 c1 = idn(0x9F, 2), c2 = idn(0x91, 2), c3 = idn(0x91, 3);  // c2 < c1
        const pb::Placement r = rcpt(idn(0xAB, 1), kB0, 2, rep(0x71), 30000);
        const pb::Placement own_c1 = rcpt(c1, kB0, 2, rep(0x72), 30000);
        const pb::Placement own_c2 = rcpt(c2, kB0, 2, rep(0x73), 30000);
        const pb::Placement own_c3 = rcpt(c3, kB0, 3, rep(0x74), 30000);
        std::vector<pb::Ingest> iv;
        ok = ok && extend(s, c1, idn(0x90, 1), kB0, {r, own_c1}, true, &iv);   // seen first: best
        ok = ok && extend(s, c2, idn(0x90, 1), kB0, {r, own_c2}, false, &iv);  // r on c2's own view
        ok = ok && s.add_carrier(c3, c2, kB0) == pb::AddVerdict::Added;
        iv.push_back(*s.ingest(c3, own_c1));  // the orphan c1 re-carried on c2's chain
        check(s.ingest(c3, r) == pb::Ingest::Duplicate, "V9 r is placed on c2's chain already");
        iv.push_back(*s.ingest(c3, own_c3));
        check(s.best_tip() == c1 && s.view_at(c1).placed_open(c1), "V9 the best chain still holds c1");
        ok = ok && s.seal(c3).has_value();
        std::uint64_t dup = 0, tokens = 0;
        for (pb::Ingest x : iv) {
            dup += x == pb::Ingest::Duplicate ? 1 : 0;
            tokens += pb::strike_tokens(x == pb::Ingest::Accepted ? pb::AdmitVerdict::AdmitCarrier
                                                                  : pb::AdmitVerdict::Strike);
        }
        check(ok && iv.size() == 6 && dup == 0 && tokens == 0,
              "V9 both siblings and the orphan re-carry admitted: Duplicate 0, strike tokens 0");
        check(s.switch_best(c3) == pb::SwitchVerdict::Switched, "V9 fork choice moves to c2's branch");
        const pb::LaneView v = s.view_at(c3);
        const std::vector<const pb::Placement*> e = v.live_entries(kB0, v.pos());
        check(count_id(e, r.id) == 1 && count_id(e, c1) == 1 && count_id(e, c2) == 1 && count_id(e, c3) == 1,
              "V9 r placed once on the new best chain; the orphan c1 credited once");
        check(!s.view_at(idn(0x90, 1)).placed_open(r.id) && s.view_at(c1).placed_open(r.id),
              "V9 each branch reads its own placements");
    });

    // ---- V10 deep fork: DEFER, never a verdict ----
    run_vector("V10 deep fork: DEFER, never a verdict", [&] {
        const std::uint64_t J = 8;
        pb::BinStore s(P, kB0, J, idn(0x10, 0), kB0);
        bool ok = true;
        for (std::uint64_t x = 1; x <= 19; ++x) ok = ok && extend(s, idn(0x10, x), idn(0x10, x - 1), kB0, {}, true);
        // a side branch forking at 11 while the tip is 19 (fork depth J): held.
        ok = ok && extend(s, idn(0x1F, 12), idn(0x10, 11), kB0, {}, false);
        ok = ok && extend(s, idn(0x1F, 13), idn(0x1F, 12), kB0, {}, false);
        ok = ok && s.add_carrier(idn(0x1F, 14), idn(0x1F, 13), kB0) == pb::AddVerdict::Added;
        check(s.add_carrier(idn(0x1F, 15), idn(0x1F, 14), kB0) == pb::AddVerdict::ParentUnknown,
              "V10 a carrier on a parent whose seal has not run waits (DEFER)");
        ok = ok && extend(s, idn(0x10, 20), idn(0x10, 19), kB0, {}, true);
        check(ok && s.base_pos() == 12, "V10 tip 20, J 8: journal base 12");
        const pb::AddVerdict deep = s.add_carrier(idn(0x1E, 12), idn(0x10, 11), kB0);  // fork J + 1 below the tip
        check(deep == pb::AddVerdict::Deep && pb::add_defers(deep), "V10 fork J + 1 below the tip: Deep -> DEFER");
        check(s.view_at(idn(0x1E, 12)).status() == pb::ViewStatus::Unknown, "V10 nothing stored for it");
        check(s.view_at(idn(0x1F, 13)).status() == pb::ViewStatus::Deep, "V10 a held side branch now forks too deep");
        check(s.ingest(idn(0x1F, 14), rcpt(idn(0xAC, 1), kB0, 1, rep(0x81), 30000)) == std::nullopt
                      && s.switch_best(idn(0x1F, 13)) == pb::SwitchVerdict::Deep,
              "V10 no verdict and no switch on a deep branch");
        check(s.add_carrier(idn(0x1D, 13), idn(0x10, 12), kB0) == pb::AddVerdict::Added,
              "V10 control: fork J below the tip is held");
        check(s.add_carrier(idn(0x1C, 1), idn(0x77, 0), kB0) == pb::AddVerdict::ParentUnknown
                      && pb::add_defers(pb::AddVerdict::ParentUnknown),
              "V10 an unknown parent DEFERs");
    });

    // ---- V11 side-branch seal ----
    run_vector("V11 side-branch seal", [&] {
        const pb::Placement r = rcpt(idn(0xAD, 1), kB0, 1, rep(0x91), 30000);
        pb::BinStore s(P, kB0, kJ, idn(0x20, 0), kB0);
        bool ok = extend(s, idn(0x20, 1), idn(0x20, 0), kB0, {r}, true);
        ok = ok && extend(s, idn(0x20, 2), idn(0x20, 1), kB0 + 50, {}, true);         // best: no fold
        ok = ok && extend(s, idn(0x2A, 2), idn(0x20, 1), kB0 + 96, {}, false);        // side: folds bin b0
        const pb::LaneView side = s.view_at(idn(0x2A, 2));
        check(ok && side.ok() && side.fork_pos() == 1 && side.leaf_count() == 1, "V11 the side branch seals bin b0");
        check(s.head().leaf_count == 0 && s.delta(idn(0x2A, 2))->sealed.size() == 1,
              "V11 ... in its own delta; the best chain has not");
        pb::BinStore fresh(P, kB0, kJ, idn(0x20, 0), kB0);
        bool okf = extend(fresh, idn(0x20, 1), idn(0x20, 0), kB0, {r}, true);
        okf = okf && extend(fresh, idn(0x2A, 2), idn(0x20, 1), kB0 + 96, {}, true);
        check(okf && side.mmr_root_at(2) == fresh.head().root && side.mmr_root_at(1) == pb::Hash32{},
              "V11 view_at(side).mmr_root_at == a fresh node's root with that branch best");
        const pb::SealedBin* sb = side.bucket(kB0);
        check(sb != nullptr && sb->bucket.raw_sum == pb::Work(30000) && s.view_at(idn(0x20, 2)).bucket(kB0) == nullptr,
              "V11 the side bucket is read through the side view only");
    });
}

int main() {
    const pb::LaneParams& lp = pb::kRuledLaneParams;
    const std::uint64_t F = lp.open_bins;  // 96
    check(pb::seal_depth(lp) == 0, "D_fin == 0 (K06, ruling 27 K-11)");

    // H over carriers: height advances by 1 every 12 positions (Monero/T cadence).
    auto h_at = [](std::uint64_t pos) -> std::uint64_t { return 1000 + pos / 12; };
    const std::uint64_t origin_bin = 1000;  // b

    // fold_pos: first f with H(f) >= b + F = 1096. H(f) = 1000 + f/12 >= 1096 ->
    // f/12 >= 96 -> f >= 1152.
    bool found = false;
    const std::uint64_t f = pb::fold_pos(h_at, /*n_positions=*/4000, origin_bin, F, found);
    check(found && f == 1152, "fold at the first f with H(f) >= b + F");
    check(h_at(f) >= origin_bin + F, "f carries: H(f) >= b + F");
    check(h_at(f - 1) < origin_bin + F, "f-1 does not: H(f-1) < b + F");

    // open_at reads H at the carrier's parent: the carrier at f (parent f-1) is
    // still open for bin b; the carrier at f+1 (parent f) is sealed.
    check(pb::open_at(h_at(f - 1), origin_bin, F), "carrier f: bin b open (H(f-1) < b + F)");
    check(!pb::open_at(h_at(f), origin_bin, F), "carrier f+1: bin b sealed (H(f) >= b + F)");
    check(!pb::open_at(h_at(f + 500), origin_bin, F), "every later carrier: bin b sealed");
    check(pb::open_at(h_at(f), origin_bin + 1, F), "carrier f+1: bin b+1 still open");

    // seal at f, D_fin 0: the live entries become a frozen L1 bucket + MMR leaf.
    pb::BucketRow x; x.miner = rep(0x41); x.w_miner = pb::Work(50000);
    pb::BucketRow y; y.miner = rep(0x42); y.w_miner = pb::Work(70000);
    const pb::L1Bucket sealed = pb::seal_bucket(origin_bin, {x, y}, pb::Work(120000), 2, 50000);
    const pb::Hash32 leaf = pb::mmr_leaf_of(sealed);

    // a late push into the SEALED bin is REFUSED (never dropped silently): a
    // carrier at f+1 carrying a bin-b receipt is STRIKE SealedBin naming the entry;
    // the same list on the carrier at f is admitted.
    {
        const pb::RatchetState s_tip = pb::genesis_ratchet_state(seq32(0x55));
        const pb::ReceiptBodyV3 late = make_body(2, false, 0x43);
        const pb::ReceiptBodyV3 open_one = make_body(2, false, 0x44);
        std::vector<pb::CarriedReceipt> list{{late, origin_bin}};
        std::vector<pb::Hash32> ids{pb::receipt_id(late)};
        pb::ReceiptBodyV3 c = make_body(2, false, 0x10);
        c.side.receipts_root = pb::carrier_receipts_root_over(ids, s_tip);
        pb::PlacedSet placed;
        const pb::CarriedListResult at_f = pb::check_carried_list(c, h_at(f - 1), list, placed, s_tip, lp);
        check(!at_f.verdict && at_f.fault == pb::CarriedFault::None && at_f.ids == ids,
              "carrier f carries the bin-b receipt");
        const pb::CarriedListResult at_f1 = pb::check_carried_list(c, h_at(f), list, placed, s_tip, lp);
        check(at_f1.verdict == pb::AdmitVerdict::Strike && at_f1.fault == pb::CarriedFault::SealedBin
                      && at_f1.index == 0 && pb::strike_tokens(*at_f1.verdict) == 1,
              "late push into a sealed bin REFUSED: STRIKE SealedBin at entry 0 (not dropped)");
        // the same carrier with a bin b+1 receipt instead: still open at f+1.
        std::vector<pb::CarriedReceipt> next{{open_one, origin_bin + 1}};
        std::vector<pb::Hash32> next_ids{pb::receipt_id(open_one)};
        c.side.receipts_root = pb::carrier_receipts_root_over(next_ids, s_tip);
        const pb::CarriedListResult r2 = pb::check_carried_list(c, h_at(f), next, placed, s_tip, lp);
        check(!r2.verdict && r2.fault == pb::CarriedFault::None, "carrier f+1 carries a bin b+1 receipt");
    }

    // a reorg across the fold rewinds and re-seals to the SAME bytes as a fresh
    // node (determinism of the seal).
    const pb::L1Bucket reseal = pb::seal_bucket(origin_bin, {y, x}, pb::Work(120000), 2, 50000);
    check(pb::mmr_leaf_of(reseal) == leaf, "reorg re-seal reproduces the same MMR leaf");
    check(reseal.comp_root_v == sealed.comp_root_v, "re-seal reproduces comp_root");

    s3b_store_vectors();

    return finish("v37_xmr_bin_fold_kat");
}
