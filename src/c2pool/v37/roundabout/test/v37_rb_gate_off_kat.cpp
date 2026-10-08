// v37_rb_gate_off_kat — S5: RoundaboutGate is add-only and DEFAULT OFF, and
// OFF is byte-identical to master.
//
//   A  RoundaboutGate::for_version(v) is OFF (k_max = 1) for every v; the bare
//      {} default equals it; candidate profiles are well-formed and ON
//   B  structural validity: ill-formed ON gates are rejected by well_formed()
//      and derive the k = 1 map (fail-safe)
//   C  OFF path everywhere: n = 1, one roundabout, admission no-op
//   D  lane digest golden: with EVERY rb header in this TU, ::v37::Lane under
//      LaneParams::v37_0()/v37_1()/shipped() on the pinned schedule reproduces
//      w4_estimator_wiring_golden_v1.hpp LANE_DIGEST_HEX (37756e9f...)
//   E  owed_digest golden: the k = 1 roundabout settlement path feeding the
//      REAL OwedLedger reproduces OWED_DIGEST_GATE_OFF_HEX (6c85fd89...), and a
//      k = 4 split of the same weights reproduces it too
#include <cstring>
#include <map>
#include <string>
#include <vector>

#include <c2pool/v37/roundabout/rb_admission.hpp>
#include <c2pool/v37/roundabout/rb_cb_class.hpp>
#include <c2pool/v37/roundabout/rb_checkpoint.hpp>
#include <c2pool/v37/roundabout/rb_gate.hpp>
#include <c2pool/v37/roundabout/rb_lane_tag.hpp>
#include <c2pool/v37/roundabout/rb_map.hpp>
#include <c2pool/v37/roundabout/rb_settle.hpp>
#include <c2pool/v37/roundabout/rb_stripe.hpp>
#include <c2pool/v37/test/w4_estimator_wiring_golden_v1.hpp>
#include <sharechain/v37/v37_lane.hpp>

#include "rb_kat_harness.hpp"

using namespace c2pool::v37n::rb;
using rbkat::fill;
using rbkat::hx;
using rbkat::ok;
namespace S = ::c2pool::v37n::settle;
namespace wg = ::c2pool::v37n::settle::wiring_golden;

// The pinned push schedule of v37_w4_estimator_wiring_test.cpp lane_digest().
static bytes32 lane_digest(const ::v37::LaneParams& p) {
    auto id_key = [](::v37::MinerId m) -> bytes32 {
        std::uint8_t b[4] = {(std::uint8_t)m, (std::uint8_t)(m >> 8), (std::uint8_t)(m >> 16),
                             (std::uint8_t)(m >> 24)};
        return ::v37::sha256d(b, 4);
    };
    ::v37::Lane lane(p);
    rbkat::SplitMix64 rng(0x5CEDUL);
    for (int i = 0; i < 300; ++i) lane.push((::v37::MinerId)(rng.next() % 7), 1 + (rng.next() % 1000000), 0);
    return lane.digest(id_key);
}

int main() {
    std::printf("v37_rb_gate_off_kat  (lane golden %s, owed golden %s)\n", wg::LANE_DIGEST_HEX,
                wg::OWED_DIGEST_GATE_OFF_HEX);

    // ── A ──
    {
        bool off = true;
        for (std::uint32_t v = 0; v < 64; ++v) {
            const auto g = RoundaboutGate::for_version(v);
            if (!g.is_off() || g.k_max != 1 || g.version != 0 || !(g == RoundaboutGate{})) off = false;
        }
        off = off && RoundaboutGate::for_version(0xFFFFFFFFu).is_off();
        ok(off, "A1 for_version(v) == {} == OFF (k_max 1) for every v incl. unknown");
        ok(RoundaboutGate{}.is_off() && RoundaboutGate{}.well_formed(), "A2 default is OFF and trivially valid");
        const auto b = RoundaboutGate::btc_candidate();
        const auto x = RoundaboutGate::xmr_candidate(1000000000ull);
        ok(b.enabled() && b.well_formed() && b.S == 256 && b.eps_num == 1 && b.eps_den == 4 &&
               b.delta_num == 1 && b.delta_den == 8 && b.E_map_bins == 144 && b.ckpt_bins == 64 &&
               b.H_ref_per_s == 86000000000000000ull,
           "A3 BTC candidate = D3-D5 (86 PH/s, S 256, eps 1/4, delta 1/8, 144-bin period, 64-bin ckpt)");
        ok(x.enabled() && x.well_formed() && x.E_map_bins == 720 && x.bin_seconds == 120,
           "A4 XMR candidate = 720-bin period, 120 s bins, H_ref a parameter");
    }

    // ── B ──
    {
        const auto b = RoundaboutGate::btc_candidate();
        auto bad = [&](auto mut) { RoundaboutGate g = b; mut(g); return !g.well_formed(); };
        const bool all_bad =
            bad([](RoundaboutGate& g) { g.S = 255; }) && bad([](RoundaboutGate& g) { g.S = 131072; }) &&
            bad([](RoundaboutGate& g) { g.k_max = 3; }) && bad([](RoundaboutGate& g) { g.k_max = 512; }) &&
            bad([](RoundaboutGate& g) { g.eps_den = 0; }) && bad([](RoundaboutGate& g) { g.delta_num = 8; }) &&
            bad([](RoundaboutGate& g) { g.H_ref_per_s = 0; }) && bad([](RoundaboutGate& g) { g.bin_seconds = 0; }) &&
            bad([](RoundaboutGate& g) { g.ckpt_bins = 145; }) && bad([](RoundaboutGate& g) { g.E_map_bins = 0; }) &&
            bad([](RoundaboutGate& g) { g.miss_grace = 0; });
        ok(all_bad, "B1 every malformed ON gate is rejected");
        RoundaboutGate g = b; g.S = 255;
        PeriodInput in; in.W_by_rb = {u128(1) << 100}; in.ids = {IdWork{fill(1), u128(1) << 90}};
        const Map m = derive_map(genesis_map(0), in, g);
        ok(m.m == 0 && m.n.empty() && m.overrides.empty(), "B2 ill-formed gate derives the k = 1 map");
    }

    // ── C ──
    {
        const RoundaboutGate off{};
        PeriodInput in;
        in.W_by_rb = {u128(1) << 100};
        rbkat::SplitMix64 r(7);
        for (int i = 0; i < 100; ++i) in.ids.push_back(IdWork{r.key(), u128(r.next()) << 40});
        Map m = genesis_map(0);
        for (int e = 0; e < 5; ++e) m = derive_map(m, in, off);
        bool one = m.m == 0 && m.k() == 1 && m.n.empty() && m.overrides.empty() && m.epoch == 5;
        for (const auto& w : in.ids) if (m.assign(w.id_key, 0) != 0 || n_of(w.h_obs, off) != 1) one = false;
        ok(one, "C1 OFF: every period derives one roundabout, n = 1, no stored state");
        const auto ctx = LaneTagContext::of(0, ::v37::LaneParams::shipped(), ::v37::SHIPPED_CONSENSUS_VERSION);
        ok(check_roundabout(off, ctx, m, 0, fill(3), RbCarriage{}).ok(), "C2 OFF admission is a no-op");
    }

    // ── D: lane digest golden with all rb headers in the TU ──
    {
        const std::string d0 = hx(lane_digest(::v37::LaneParams::v37_0()));
        const std::string d1 = hx(lane_digest(::v37::LaneParams::v37_1()));
        const std::string ds = hx(lane_digest(::v37::LaneParams::shipped()));
        std::printf("   lane digest v37_0=%s\n", d0.c_str());
        ok(d0 == wg::LANE_DIGEST_HEX && d1 == wg::LANE_DIGEST_HEX && ds == wg::LANE_DIGEST_HEX,
           "D1 lane digest == pinned golden for v37_0 / v37_1 / shipped (rb module is digest-neutral)");
        // negative control: a geometry change must move it (the check is live)
        ::v37::LaneParams pw = ::v37::LaneParams::v37_0(); pw.half_life = 2161;
        ok(hx(lane_digest(pw)) != wg::LANE_DIGEST_HEX, "D2 negative control: geometry change moves the digest");
    }

    // ── E: owed_digest golden through the k = 1 roundabout settlement path ──
    {
        const bytes32 A = fill(0xA1), B = fill(0xB2);
        // weights 2:1 over reward 1'500'000 -> E_b = {A: 1'000'000, B: 500'000}
        Summary s; s.payout_map[A] = U256(2); s.payout_map[B] = U256(1);
        const auto E = settle_roundabouts(1500000, {s});
        ok(E.size() == 2 && E.at(A) == 1000000 && E.at(B) == 500000, "E1 k=1 split reproduces the golden schedule's E_b");
        auto od = [&](const std::map<bytes32, u64>& e) {
            S::OwedLedger L(7);
            S::OwedLedger::Amounts credit;
            for (const auto& [k, v] : e) credit[k] = (long long)v;
            L.on_block_found("blk1", credit, {});
            L.on_block_finalized("blk1", 100);
            return hx(L.owed_digest());
        };
        ok(od(E) == wg::OWED_DIGEST_GATE_OFF_HEX, "E2 owed_digest == pinned gate-OFF golden (6c85fd89...)");
        std::vector<Summary> k4(4);
        for (RbIndex i = 0; i < 4; ++i) k4[i].rb_index = i;
        k4[0].payout_map[A] = U256(1); k4[3].payout_map[A] = U256(1); k4[2].payout_map[B] = U256(1);
        ok(od(settle_roundabouts(1500000, k4)) == wg::OWED_DIGEST_GATE_OFF_HEX,
           "E3 the same weights split over k = 4 roundabouts -> identical owed_digest");
    }

    return rbkat::finish("v37_rb_gate_off_kat");
}
