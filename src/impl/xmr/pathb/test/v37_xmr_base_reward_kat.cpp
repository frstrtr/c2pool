// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// v37_xmr_base_reward_kat (pathb_emission.hpp, pathb_branch.hpp, C28, M-04): B(A)
// from the emission state already_generated_coins at the anchor A_t; the mainnet
// tail = 6e11; a pre-tail anchor pays its full emission; B(A) is monotone in the
// supply. Through select_window_inputs: B(A_t) is the weight input read at A_t
// (60 below P_t); an anchor whose weight inputs are absent -> DEFER
// (MissingWeights, the anchor id, no B(A) invented); weight inputs above A_t are
// not read.
// S3b-1b, the follower-backed view (pathb_branch_follower.hpp; C28, M-03,
// M-04, R-14): (1) a tail anchor -> B 600,000,000,000; (2) regtest from its
// genesis row (agc 17,592,186,044,415): h(P_t) 9 < K_A -> A_t = genesis, B
// 35,184,338,534,400 (an agc-0 genesis would give 35,184,372,088,831); a
// snapshot is RowWeights of the row the state ends at, none before its
// connect; (3) P_t at anchor + 59 -> A_t below the anchor -> DEFER
// (MissingWeights), anchor + 60 -> A_t = the anchor, its RowWeights seeded from
// the anchor bundle; (4) an anchor text without already_generated_coins ->
// MissingKey; (5) RowWeights through the codec: after a restart that re-applies
// 64 rows, a tip whose A_t is 150 below the Monero tip is Selected with the
// same B; codec refusals; (6) a fresh anchor: D_net for a child of anchor + 1
// through the bundle's rows == a full chain's; (7) R-14: Z 600,000 and
// long-term effective median 300,000 -> M 300,000, f_spend 12,530,000.
// ---------------------------------------------------------------------------
#include <algorithm>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "impl/xmr/native/anchor/xmr_anchor_codec.hpp"
#include "impl/xmr/pathb/pathb_branch.hpp"
#include "impl/xmr/pathb/pathb_branch_follower.hpp"
#include "impl/xmr/pathb/pathb_emission.hpp"
#include "pathb_kat_branch_view.hpp"
#include "pathb_kat_check.hpp"
#include "pathb_kat_lane.hpp"

using namespace pathb_kat;
namespace pb = ::c2pool::xmr::pathb;

namespace {

constexpr std::uint8_t kMain = 0x4d;

// main 0..top; already_generated_coins after block h = agc0 + h x 10^13.
KatBranchView chain(std::uint64_t top, std::uint64_t agc0) {
    KatBranchView v;
    pb::Hash32 parent{};
    for (std::uint64_t h = 0; h <= top; ++h)
        parent = v.add(kMain, h, parent, 1600000000ull + 120 * h, 1000 + h, agc0 + h * 10000000000000ull, 300000,
                       300000);
    return v;
}

}  // namespace

namespace nat = ::c2pool::xmr::native;

namespace {

nat::ChainRow chain_row(std::uint8_t tag, std::uint64_t h, std::uint8_t major, std::uint64_t agc, std::uint64_t base) {
    nat::ChainRow r;
    r.height = h;
    r.id = block_id(tag, h);
    r.prev_id = h > 0 ? block_id(tag, h - 1) : pb::Hash32{};
    r.timestamp = 1600000000ull + 120 * h;
    r.major_version = major;
    r.minor_version = major;
    r.block_weight = 80;
    r.long_term_weight = 80;
    r.difficulty = pb::U128{1, 0};
    r.cumulative_difficulty = pb::U128{h + 1, 0};
    r.base_reward = base;
    r.reward = base;
    r.already_generated_coins = agc;
    r.pow_verified = true;
    return r;
}

void s3b_follower_view() {
    constexpr std::uint8_t kTag = 0x46;
    // (1) a tail anchor through the follower view.
    {
        KatMoneroRows m = monero_chain(kTag, 100, 1000, [](std::uint64_t) {
            return std::optional<pb::RowWeights>(rw(kTailAgc, 300000, 300000));
        });
        const pb::FollowerBranchView view(m);
        pb::WindowInputs w;
        check(view.window_inputs(block_id(kTag, 100), 16, w).selected() && w.a_t == block_id(kTag, 40)
                      && w.weights.base_reward == 600000000000ull && w.weights.fee_median == 300000
                      && w.weights.zone == 300000 && w.weights.reserve == 0,
              "(1) tail: B(A_t) 600,000,000,000, M 300,000, Z 300,000 from RowWeights at A_t");
    }

    // (2) regtest from its genesis row.
    {
        constexpr std::uint64_t kGenesisCoins = 17592186044415ull;
        check(nat::emission_base_reward(0, 1) == kGenesisCoins, "(2) the genesis coinbase 17,592,186,044,415");
        const nat::ChainRow g = chain_row(0x52, 0, 1, kGenesisCoins, kGenesisCoins);
        nat::ConsensusState st(nat::XmrNet::Regtest);
        check(!pb::snapshot_after_connect(st, g), "(2) before the genesis row is seeded: no RowWeights");
        st.seed_direct(g, {nat::DifficultyRow{g.timestamp, g.cumulative_difficulty}}, {80}, {80}, {g.timestamp});
        const std::optional<pb::RowWeights> wg = pb::snapshot_after_connect(st, g);
        check(wg && wg->agc_after == kGenesisCoins && wg->hf_child == 16 && wg->z_child == 300000
                      && wg->ltem_child == 300000 && wg->m_child == 300000,
              "(2) genesis RowWeights: agc 17,592,186,044,415, hf 16, Z = M = 300,000");
        // the next row's snapshot exists only once the state ends at it.
        const nat::ChainRow r1 = chain_row(0x52, 1, 16, kGenesisCoins + 35184338534400ull, 35184338534400ull);
        check(!pb::snapshot_after_connect(st, r1), "(2) row 1 not connected: no RowWeights for it");
        nat::ConsensusState st1(nat::XmrNet::Regtest);
        st1.seed_direct(r1, {nat::DifficultyRow{r1.timestamp, r1.cumulative_difficulty}}, {80}, {80}, {r1.timestamp});
        const std::optional<pb::RowWeights> w1 = pb::snapshot_after_connect(st1, r1);
        check(w1 && w1->agc_after == r1.already_generated_coins, "(2) row 1 RowWeights: its own agc");
        KatMoneroRows m;
        m.seed_anchor(0x52, 0, 0, 1600000000ull, 1, wg);
        pb::Hash32 parent = m.anchor_row.id;
        for (std::uint64_t h = 1; h <= 9; ++h)
            parent = m.add(0x52, h, parent, 1600000000ull + 120 * h, 1, std::nullopt);
        const pb::FollowerBranchView view(m);
        pb::WindowInputs w;
        check(view.window_inputs(block_id(0x52, 9), 16, w).selected() && w.a_t == block_id(0x52, 0)
                      && w.a_t_height == 0,
              "(2) h(P_t) 9 < K_A: A_t = genesis");
        check(w.weights.base_reward == 35184338534400ull && w.weights.base_reward != 35184372088831ull,
              "(2) B(A_t) 35,184,338,534,400 (not the agc-0 value 35,184,372,088,831)");
    }

    // (3) / (4) / (6) an anchor bundle at 1,000.
    {
        constexpr std::uint64_t Ha = 1000;
        constexpr std::uint64_t kDiff = 1000000;
        nat::AnchorBundle b;
        b.network = "mainnet";
        b.height = Ha;
        b.id = block_id(kTag, Ha);
        b.prev_id = block_id(kTag, Ha - 1);
        b.timestamp = 1600000000ull + 120 * Ha;
        b.major_version = 16;
        b.cumulative_difficulty = pb::U128{kDiff * (Ha + 1), 0};
        b.already_generated_coins = kTailAgc;
        for (std::uint64_t h = Ha - 734; h <= Ha; ++h)
            b.difficulty_window.emplace_back(1600000000ull + 120 * h, pb::U128{kDiff * (h + 1), 0});
        b.short_term_weights.assign(100, 300000);
        b.long_term_weights.assign(Ha + 1, 300000);
        std::vector<std::uint64_t> ts60;
        for (std::uint64_t h = Ha - 59; h <= Ha; ++h) ts60.push_back(1600000000ull + 120 * h);
        nat::ConsensusState sa(nat::XmrNet::Mainnet);
        sa.seed_from_anchor(b, ts60);
        const std::optional<pb::RowWeights> wa = pb::snapshot_after_connect(sa, *sa.tip());
        check(wa && wa->agc_after == kTailAgc && wa->hf_child == 16 && wa->z_child == 300000 && wa->m_child == 300000,
              "(3) the anchor row's RowWeights seeded from the bundle (agc, Z, M, hf 16)");

        // (4) the anchor codec refuses a text without already_generated_coins.
        {
            const std::string text = nat::write_anchor_inc(b);
            nat::AnchorBundle back;
            std::string why;
            check(nat::parse_anchor_inc(text, back, why) == nat::AnchorParse::Ok
                          && back.already_generated_coins == kTailAgc,
                  "(4) the full anchor text parses, agc read back");
            std::string cut;
            std::size_t pos = 0;
            while (pos < text.size()) {
                const std::size_t nl = text.find('\n', pos);
                const std::string line = text.substr(pos, nl == std::string::npos ? std::string::npos : nl - pos + 1);
                if (line.rfind("already_generated_coins", 0) != 0) cut += line;
                if (nl == std::string::npos) break;
                pos = nl + 1;
            }
            nat::AnchorBundle none;
            check(cut.size() < text.size() && nat::parse_anchor_inc(cut, none, why) == nat::AnchorParse::MissingKey,
                  "(4) an anchor text without already_generated_coins -> MissingKey");
        }

        KatMoneroRows m;
        m.seed_anchor(kTag, Ha, 734, 1600000000ull, kDiff, wa);
        pb::Hash32 parent = m.anchor_row.id;
        for (std::uint64_t h = Ha + 1; h <= Ha + 200; ++h)
            parent = m.add(kTag, h, parent, 1600000000ull + 120 * h, kDiff,
                           rw(kTailAgc - h, 300000, 300000));
        const pb::FollowerBranchView view(m);
        {
            pb::WindowInputs w;
            w.weights.base_reward = 123;
            const pb::BranchStatus st = view.window_inputs(block_id(kTag, Ha + 59), 16, w);
            check(!st.selected() && st.reason == pb::DeferReason::MissingWeights && st.missing == b.prev_id
                          && w.weights.base_reward == 123,
                  "(3) P_t at anchor + 59: A_t below the anchor -> DEFER MissingWeights, no B computed");
            pb::WindowInputs w60;
            check(view.window_inputs(block_id(kTag, Ha + 60), 16, w60).selected() && w60.a_t == b.id
                          && w60.weights.base_reward == 600000000000ull,
                  "(3) P_t at anchor + 60: A_t = the anchor, B 600,000,000,000");
        }
        // (6) D_net for a child of anchor + 1 through the bundle's rows.
        {
            pb::U128 d{};
            const pb::BranchStatus st = pb::dnet_for_child(view, block_id(kTag, Ha + 1), 16, d);
            KatBranchView ref;
            pb::Hash32 rp{};
            for (std::uint64_t h = 0; h <= Ha + 1; ++h)
                rp = ref.add(kTag, h, rp, 1600000000ull + 120 * h, kDiff, kTailAgc, 300000, 300000);
            pb::U128 d_ref{};
            check(st.selected() && pb::dnet_for_child(ref, block_id(kTag, Ha + 1), 16, d_ref).selected() && d == d_ref
                          && d.lo == kDiff,
                  "(6) fresh anchor: D_net for a child of anchor + 1 through the bundle's rows == a full chain's");
        }
    }

    // (5) RowWeights through the codec; a restart re-applies the last 64 rows.
    {
        KatMoneroRows m = monero_chain(kTag, 400, 1000, [](std::uint64_t h) {
            return std::optional<pb::RowWeights>(rw(1000000000000000ull + h * 10000000000000ull, 300000, 300000));
        });
        const pb::FollowerBranchView view(m);
        pb::WindowInputs before;
        const pb::Hash32 p_t = block_id(kTag, 400 - 90);  // A_t = Monero tip - 150
        check(view.window_inputs(p_t, 16, before).selected() && before.a_t == block_id(kTag, 250),
              "(5) before the restart: A_t 150 below the Monero tip, Selected");
        const std::vector<std::uint8_t> snap = pb::encode_row_weights_table(m.w);
        check(snap.size() == 4 + m.w.size() * (32 + pb::kRowWeightsBytes), "(5) the snapshot: u32 n | n x 65 B");
        KatMoneroRows r = m;
        r.w.clear();
        for (std::uint64_t h = 400 - 63; h <= 400; ++h) r.w[block_id(kTag, h)] = m.w.at(block_id(kTag, h));
        {
            const pb::FollowerBranchView v0(r);
            pb::WindowInputs x;
            const pb::BranchStatus st = v0.window_inputs(p_t, 16, x);
            check(!st.selected() && st.reason == pb::DeferReason::MissingWeights,
                  "(5) control: 64 re-applied rows only -> DEFER");
        }
        const std::optional<std::map<pb::Hash32, pb::RowWeights>> back = pb::decode_row_weights_table(snap);
        if (back)
            for (const auto& [id, w] : *back) r.w.emplace(id, w);
        const pb::FollowerBranchView v1(r);
        pb::WindowInputs after;
        check(back && back->size() == m.w.size() && v1.window_inputs(p_t, 16, after).selected()
                      && after.weights == before.weights && after.a_t == before.a_t,
              "(5) RowWeights restored from the snapshot: Selected, the same B, M, Z");
        // codec refusals.
        std::vector<std::uint8_t> one;
        pb::encode_row_weights(rw(5, 400000, 300000), one);
        check(one.size() == 33 && pb::decode_row_weights(one) == rw(5, 400000, 300000), "(5) RowWeights: 33 B round trip");
        std::vector<std::uint8_t> bad_m = one;
        bad_m[16] ^= 1;
        std::vector<std::uint8_t> hf0 = one;
        hf0[32] = 0;
        std::vector<std::uint8_t> longer = one;
        longer.push_back(0);
        check(!pb::decode_row_weights(bad_m) && !pb::decode_row_weights(hf0) && !pb::decode_row_weights(longer)
                      && !pb::decode_row_weights(std::span<const std::uint8_t>(one.data(), 32)),
              "(5) RowWeights refused: M != min(Z, ltem), hf 0, 34 B, 32 B");
        std::vector<std::uint8_t> extra = snap;
        extra.push_back(0);
        std::vector<std::uint8_t> count = snap;
        count[0] ^= 1;
        std::map<pb::Hash32, pb::RowWeights> two{{block_id(kTag, 1), rw(1, 300000, 300000)},
                                                 {block_id(kTag, 2), rw(2, 300000, 300000)}};
        std::vector<std::uint8_t> swapped = pb::encode_row_weights_table(two);
        std::swap_ranges(swapped.begin() + 4, swapped.begin() + 4 + 65, swapped.begin() + 4 + 65);
        check(!pb::decode_row_weights_table(extra) && !pb::decode_row_weights_table(count)
                      && !pb::decode_row_weights_table(swapped) && pb::decode_row_weights_table(pb::encode_row_weights_table(two)),
              "(5) table refused: a trailing byte, a wrong count, ids not ascending");
    }

    // (7) R-14: M = min(Z, long-term effective median).
    {
        const nat::ChainRow r = chain_row(0x37, 1000, 16, kTailAgc, 600000000000ull);
        nat::ConsensusState st(nat::XmrNet::Mainnet);
        std::vector<nat::DifficultyRow> dw{nat::DifficultyRow{r.timestamp, r.cumulative_difficulty}};
        st.seed_direct(r, dw, std::vector<std::uint64_t>(100, 600000), std::vector<std::uint64_t>(100, 300000),
                       {r.timestamp});
        const std::optional<pb::RowWeights> w = pb::snapshot_after_connect(st, r);
        check(w && w->z_child == 600000 && w->ltem_child == 300000, "(7) Z 600,000, long-term effective median 300,000");
        check(w && w->m_child == 300000, "(7) M = min(Z, ltem) = 300,000 (R-14)");
        KatMoneroRows m;
        m.seed_anchor(0x37, 1000, 0, 1600000000ull, 1000, w);
        const pb::FollowerBranchView view(m);
        const std::optional<pb::WeightInputs> wi = view.weights_at(block_id(0x37, 1000));
        check(wi && wi->fee_median == 300000 && wi->zone == 600000
                      && pb::f_spend(wi->base_reward, wi->fee_median, 16) == 12530000ull
                      && pb::n_rule(wi->zone, 16, wi->base_reward) == 7497,
              "(7) the view: M 300,000 -> f_spend 12,530,000; Z 600,000 -> N(B) 7,497");
    }
}

}  // namespace

int main() {
    run_part("s3b_follower_view", s3b_follower_view);

    // mainnet tail: a fully-emitted supply pays the floor 6e11 (0.6 XMR).
    check(pb::base_reward_at(18446744073000000000ull, 16) == pb::kTailBaseReward
                  && pb::kTailBaseReward == 600000000000ull,
          "mainnet tail B(A) == 6e11");

    // pre-tail: B(A) above the tail and monotone in the supply.
    {
        const std::uint64_t agc = 1000000000000000ull;  // ~1e15 piconero emitted
        const std::uint64_t B = pb::base_reward_at(agc, 16);
        check(B == 35182464740199ull, "pre-tail B(1e15) == 35,182,464,740,199");
        check(pb::base_reward_at(agc + 500000000000000ull, 16) < B, "B(A) monotone: more supply -> smaller base");
    }

    // regtest at a low height, fees 0: B(A_t) from emission, R = its own base.
    check(pb::base_reward_at(/*agc=*/0, 16) == ((~std::uint64_t{0}) >> 19), "regtest genesis B(A) == MONEY_SUPPLY >> 19");

    // ---- B(A_t) through select_window_inputs ----
    const KatBranchView v = chain(100, 0);
    {
        pb::WindowInputs w;
        const pb::BranchStatus s = pb::select_window_inputs(v, block_id(kMain, 100), 16, w);
        check(s.selected(), "P_t = main 100: window inputs selected");
        check(w.a_t == block_id(kMain, 40) && w.a_t_height == 40, "A_t = main 40 (60 below P_t)");
        check(w.weights.base_reward == 35183609149378ull, "B(A_t) == base_reward_at(agc 4e14) == 35,183,609,149,378");
    }
    {
        // a fully-emitted supply at the anchor: B(A_t) == the tail 6e11.
        const KatBranchView t = chain(100, 18446000000000000000ull);
        pb::WindowInputs w;
        check(pb::select_window_inputs(t, block_id(kMain, 100), 16, w).selected()
                      && w.weights.base_reward == 600000000000ull,
              "tail anchor: B(A_t) == 6e11");
    }
    {
        // chain start: P_t below K_A -> A_t = genesis, B(A_t) at agc 0.
        pb::WindowInputs w;
        check(pb::select_window_inputs(v, block_id(kMain, 30), 16, w).selected() && w.a_t == block_id(kMain, 0)
                      && w.weights.base_reward == 35184372088831ull,
              "P_t = main 30: A_t = genesis, B(A_t) == 35,184,372,088,831");
    }

    // ---- an anchor WITHOUT weight inputs -> DEFER (nothing invented) ----
    {
        KatBranchView d = v;
        d.weights.erase(block_id(kMain, 40));
        pb::WindowInputs w;
        w.weights.base_reward = 123;
        const pb::BranchStatus s = pb::select_window_inputs(d, block_id(kMain, 100), 16, w);
        check(!s.selected() && s.verdict == pb::BranchVerdict::Defer && s.reason == pb::DeferReason::MissingWeights
                      && s.missing == block_id(kMain, 40),
              "anchor without weight inputs -> DEFER MissingWeights naming A_t");
        check(w.weights.base_reward == 123 && w.a_t == pb::Hash32{}, "DEFER leaves B(A) uncomputed");
    }

    // ---- weight inputs are read at A_t only ----
    {
        KatBranchView d = v;
        for (std::uint64_t h = 41; h <= 100; ++h) d.weights.erase(block_id(kMain, h));
        pb::WindowInputs w;
        check(pb::select_window_inputs(d, block_id(kMain, 100), 16, w).selected()
                      && w.weights.base_reward == 35183609149378ull,
              "no weight inputs above A_t: selected, B(A_t) unchanged");
    }

    return finish("v37_xmr_base_reward_kat");
}
