// v37_rb_checkpoint_kat — S4: checkpoint summaries, summary merkle, the k-leg
// cut token, and exact settlement conservation across roundabout topologies.
//
//   A  Summary canonical serialization golden (independent Python ref), parse
//      round-trip, strict parse (trailing / zero weight / unsorted / dup reject),
//      zero-weight rows do not change the bytes
//   B  merkle goldens (1, 2, 3, 5 leaves; odd node PROMOTED, never duplicated),
//      summary_merkle is order-independent
//   C  CutTokenK: holds -> token; torn legs retried; ledger tear retried; budget
//      exhausted -> nullopt; ring miss -> nullopt
//   D  Σ_key E_b == R_b EXACTLY (largest remainder over Σ_i payout_map_i), 3000
//      random trials over k in {1,2,4,8,16}, rewards 1 .. 2^63
//   E  Σ-conservation across split / merge / stripe move with LEGACY rings
//      (weight still draining in the old roundabout): the combined map, E_b, and
//      the REAL OwedLedger owed_digest after FOUND+FINALIZE are byte-identical to
//      the k = 1 run
#include <algorithm>
#include <map>
#include <string>
#include <vector>

#include <c2pool/v37/roundabout/rb_checkpoint.hpp>
#include <c2pool/v37/roundabout/rb_settle.hpp>

#include "rb_kat_harness.hpp"

using namespace c2pool::v37n::rb;
using rbkat::fill;
using rbkat::hx;
using rbkat::ok;
namespace S = ::c2pool::v37n::settle;

static U256 big(u64 lo, u64 l1 = 0, u64 l2 = 0, u64 l3 = 0) {
    U256 x; x.v = {lo, l1, l2, l3}; return x;
}

// Owed digest after FOUND+FINALIZE of one block with entitlement E.
static bytes32 ledger_digest(const std::map<bytes32, u64>& E) {
    S::OwedLedger L(0);
    S::OwedLedger::Amounts credit;
    for (const auto& [k, v] : E) credit[k] = static_cast<long long>(v);
    L.on_block_found("blk", credit, {});
    L.on_block_finalized("blk", 500);
    return L.owed_digest();
}

int main() {
    std::printf("v37_rb_checkpoint_kat\n");

    // ── A: summary serialization ───────────────────────────────────────────
    {
        Summary s;
        s.rb_index = 2;
        s.period = 77;
        s.lane_digest = fill(0xD1);
        s.W = (u128(1) << 70) + 12345;
        s.payout_map[fill(0x22)] = big(5);
        s.payout_map[fill(0x11)] = big(9, 0, 0, 0) + big(0, 0, 0, 0);
        s.payout_map[fill(0x11)].v[3] = u64(1) << 8;     // (1<<200) + 9
        s.payout_map[fill(0x33)] = big(0);               // zero row: omitted
        const auto b = s.canonical_bytes();
        ok(b.size() == 198, "A1 canonical bytes = 6+4+8+32+16+4+2*64 = 198");
        ok(hx(s.hash()) == "8d0a8d5283dd595ef26ef33ad960b2b8f65b04eb6b746af3d1267bdb1185c8ac",
           "A2 summary hash golden (py ref)");
        const auto p = parse_summary(b);
        ok(p && p->canonical_bytes() == b && p->payout_map.size() == 2, "A3 parse round-trip (zero row dropped)");
        Summary s2 = s; s2.payout_map.erase(fill(0x33));
        ok(s2.canonical_bytes() == b, "A4 zero-weight rows do not change the bytes");
        auto tr = b; tr.push_back(0);
        ok(!parse_summary(tr), "A5 trailing byte rejects");
        auto zw = b; std::fill(zw.end() - 32, zw.end(), 0);
        ok(!parse_summary(zw), "A6 zero weight rejects");
        auto sw = b;  // swap the two 64-byte rows -> keys descending
        std::swap_ranges(sw.begin() + 70, sw.begin() + 134, sw.begin() + 134);
        ok(!parse_summary(sw), "A7 unsorted keys reject");
        auto dup = b;  // copy row 1 over row 2 -> duplicate key
        std::copy(dup.begin() + 70, dup.begin() + 134, dup.begin() + 134);
        ok(!parse_summary(dup), "A8 duplicate key rejects");
        auto tag = b; tag[0] = 'X';
        ok(!parse_summary(tag), "A9 wrong domain tag rejects");
    }

    // ── B: merkle ──────────────────────────────────────────────────────────
    {
        auto leaves = [](int n) { std::vector<bytes32> v; for (int i = 0; i < n; ++i) v.push_back(fill(std::uint8_t(0x40 + i))); return v; };
        ok(hx(merkle_root(leaves(1))) == "1f1a5042d7b8302b9e01c151b4380f4d8c7e24602f50d3ee99dd4755dbcb31d4", "B1 merkle(1) golden");
        ok(hx(merkle_root(leaves(2))) == "fb798c7f8ce3c7a65ec2898205307555b9ef792ff5556e6dece16b0e46bbad67", "B2 merkle(2) golden");
        ok(hx(merkle_root(leaves(3))) == "cf18de028215a19c044ade9612e961b1c6101a9fd3a84640f6557095f814caed", "B3 merkle(3) golden (odd promoted)");
        ok(hx(merkle_root(leaves(5))) == "aaf563ccd94d240b5b23f59a0530aa380a60fb522b65e65cd505f23f4456c5ca", "B4 merkle(5) golden");
        auto l3 = leaves(3); auto l4 = l3; l4.push_back(l3[2]);
        ok(merkle_root(l3) != merkle_root(l4), "B5 no duplicate-last malleability ([a,b,c] != [a,b,c,c])");
        ok(merkle_root({}) == bytes32{}, "B6 empty -> zero root");
        std::vector<Summary> ss(4);
        for (RbIndex i = 0; i < 4; ++i) { ss[i].rb_index = i; ss[i].lane_digest = fill(std::uint8_t(0x40 + i)); }
        const bytes32 r1 = summary_merkle(ss);
        std::reverse(ss.begin(), ss.end());
        ok(summary_merkle(ss) == r1 && r1 == merkle_root(leaves(4)), "B7 summary_merkle canonical in rb_index order");
    }

    // ── C: CutTokenK ───────────────────────────────────────────────────────
    {
        std::vector<CutLeg> legs(4);
        for (RbIndex i = 0; i < 4; ++i) legs[i] = CutLeg{i, 1, 10 + i, 100 + i, fill(std::uint8_t(0x70 + i))};
        LedgerLeg led{55, fill(0x99)};
        // A concurrent writer: bumps leg 0's version at the listed leg-read
        // ordinals (i.e. between a leg's first read and its re-read).
        int reads = 0;
        std::vector<int> bump_at;
        bool bump_always = false;
        auto rleg = [&](RbIndex i) -> std::optional<CutLeg> {
            ++reads;
            if (bump_always || std::find(bump_at.begin(), bump_at.end(), reads) != bump_at.end())
                legs[0].version++;
            return legs[i];
        };
        int lreads = 0, ltear_at = 0;
        auto rled = [&]() {
            ++lreads;
            LedgerLeg x = led;
            if (lreads == ltear_at) led.ledger_seq++;   // writer commits right after our read
            return x;
        };
        unsigned used = 0;
        auto t = read_cut_k(4, rleg, rled, 4, &used);
        ok(t && used == 1 && t->legs == legs && t->ledger == led, "C1 quiet cut holds first try");
        std::vector<bytes32> d; for (auto& l : legs) d.push_back(l.spine_digest);
        ok(t && t->lanes_root == merkle_root(d), "C2 lanes_root = merkle(spine digests)");
        // attempt 1: reads 1-4 | ledger | 5.. (bump at 3 -> leg0 re-read at 5 differs)
        // attempt 2: reads 6-9 | ledger | 10.. (bump at 7 -> leg0 re-read at 10 differs)
        reads = 0; bump_at = {3, 7};
        const u64 v0 = legs[0].version;
        t = read_cut_k(4, rleg, rled, 4, &used);
        ok(t && used == 3 && t->legs == legs && t->legs[0].version == v0 + 2,
           "C3 torn legs discarded + retried; held on attempt 3 at the writer's latest state");
        reads = 0; bump_at.clear(); bump_always = true;
        ok(!read_cut_k(4, rleg, rled, 4, &used) && used == 4, "C4 retry budget exhausted -> nullopt");
        bump_always = false; lreads = 0; ltear_at = 1;
        t = read_cut_k(4, rleg, rled, 4, &used);
        ok(t && used == 2 && t->ledger == led && t->ledger.ledger_seq == 56, "C5 ledger tear retried");
        auto miss = [&](RbIndex i) -> std::optional<CutLeg> { if (i == 2) return std::nullopt; return legs[i]; };
        ok(!read_cut_k(4, miss, rled), "C6 ring miss on any leg -> nullopt (slow path)");
    }

    // ── D: Σ E_b == R_b exactly ────────────────────────────────────────────
    {
        rbkat::SplitMix64 r(0x5E1);
        bool exact = true, keys_ok = true;
        const u64 rewards[] = {1, 2, 3, 7, 312500000, 625000000, 1ull << 40, (1ull << 63) - 1};
        for (int trial = 0; trial < 3000; ++trial) {
            const RbIndex k = RbIndex(1) << r.below(5);
            std::vector<Summary> ss(k);
            const int nkeys = 1 + int(r.below(60));
            std::vector<bytes32> keys;
            for (int i = 0; i < nkeys; ++i) keys.push_back(r.key());
            for (RbIndex i = 0; i < k; ++i) {
                ss[i].rb_index = i;
                for (int j = 0; j < nkeys; ++j) {
                    if (r.below(3) == 0) continue;
                    U256 w;
                    w.v[0] = r.next();
                    w.v[1] = r.below(4) == 0 ? r.next() : 0;
                    w.v[2] = r.below(16) == 0 ? r.below(1u << 20) : 0;
                    ss[i].payout_map[keys[j]] = w;
                }
            }
            const u64 R = rewards[r.below(8)];
            const auto E = settle_roundabouts(R, ss);
            const auto comb = combine_summaries(ss);
            if (!comb.empty() && sum_amounts(E) != R) exact = false;
            for (const auto& kv : E) if (!comb.count(kv.first)) keys_ok = false;
        }
        ok(exact, "D1 sum_key E_b == R_b exactly (3000 trials, k in 1..16, 3-limb weights)");
        ok(keys_ok, "D2 E_b only credits keys present in some payout_map_i");
    }

    // ── E: conservation across split / merge / move with legacy rings ──────
    {
        rbkat::SplitMix64 r(0xC0C0);
        const int NK = 120;
        std::vector<bytes32> keys;
        std::map<bytes32, u64> base;       // the key's total decayed weight
        for (int i = 0; i < NK; ++i) { bytes32 k = r.key(); keys.push_back(k); base[k] = 1 + r.below(1ull << 50); }

        // Distribute each key's weight over `k` roundabouts as `parts` pieces
        // (stripes, legacy rings), summing exactly to base[key].
        auto topology = [&](RbIndex k, int parts, std::uint64_t seed) {
            rbkat::SplitMix64 t(seed);
            std::vector<Summary> ss(k);
            for (RbIndex i = 0; i < k; ++i) ss[i].rb_index = i;
            for (const auto& [key, w] : base) {
                u64 left = w;
                for (int p = 0; p < parts; ++p) {
                    const u64 piece = (p == parts - 1) ? left : t.below(left + 1);
                    left -= piece;
                    if (piece) ss[t.below(k)].payout_map[key] += U256(piece);
                }
            }
            return ss;
        };
        const u64 R = 312500000;
        const auto one = topology(1, 1, 1);                       // k = 1 (gate OFF)
        const auto k4 = topology(4, 4, 2);                        // 4 roundabouts, 4 stripes/key
        const auto split8 = topology(8, 6, 3);                    // after split: new children + legacy ring pieces
        const auto merge2 = topology(2, 3, 4);                    // after merge
        const auto moved = topology(4, 9, 5);                     // bounded-load moves mid-drain
        const auto P1 = combine_summaries(one);
        bool same_map = true;
        for (const auto* ss : {&k4, &split8, &merge2, &moved})
            if (combine_summaries(*ss) != P1) same_map = false;
        ok(same_map, "E1 combined payout map identical across k=1/4/8/2/moved (Σ-conservation per key)");
        const U256 tot = sum_weights(P1);
        bool same_tot = true;
        for (const auto* ss : {&k4, &split8, &merge2, &moved}) if (!(sum_weights(combine_summaries(*ss)) == tot)) same_tot = false;
        ok(same_tot, "E2 total weight conserved across every topology");
        const auto E1 = settle_roundabouts(R, one);
        bool same_E = true;
        for (const auto* ss : {&k4, &split8, &merge2, &moved}) if (settle_roundabouts(R, *ss) != E1) same_E = false;
        ok(same_E && sum_amounts(E1) == R, "E3 E_b byte-identical across topologies and Σ == R");
        const bytes32 od1 = ledger_digest(E1);
        bool same_od = true;
        for (const auto* ss : {&k4, &split8, &merge2, &moved}) if (ledger_digest(settle_roundabouts(R, *ss)) != od1) same_od = false;
        ok(same_od, "E4 REAL OwedLedger owed_digest identical across topologies (D1 replicated ledger)");
        // k = 1 equals the direct W4 split over the single lane map
        std::vector<S::WeightedPayee> py;
        for (const auto& [k, w] : P1) { S::WeightedPayee p; p.key = k; p.weight = w; py.push_back(p); }
        const auto amt = S::split_reward(R, py);
        std::map<bytes32, u64> direct;
        for (std::size_t i = 0; i < py.size(); ++i) if (amt[i]) direct[py[i].key] = amt[i];
        ok(direct == E1, "E5 k=1 path == settle::split_reward on the lane map (OFF byte-identity)");
        // negative control: dropping a legacy ring piece MUST change the result
        auto lossy = split8;
        for (auto& s : lossy) if (!s.payout_map.empty()) { s.payout_map.erase(s.payout_map.begin()); break; }
        ok(combine_summaries(lossy) != P1, "E6 negative control: losing a legacy ring row is detected");
        std::printf("   E owed_digest(k-invariant) %s  Σw=%s\n", hx(od1).c_str(), tot.hex().c_str());
    }

    return rbkat::finish("v37_rb_checkpoint_kat");
}
