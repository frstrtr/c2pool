// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// src/impl/xmr/pathb/test/v37_xmr_receipt_header_rules_kat.cpp
// Receipt header rules (pathb_header_rules.hpp, S2.3 #9) [consensus]:
//   (1) major != hf_version(h) refused (STRIKE): mainnet h 2,689,608 -> 16,
//       2,689,607 -> 15; a version above the table's is refused too;
//   (2) timestamp < median60 refused (STRIKE); == median60 admitted; median60 =
//       the epee median of the 60 blocks ending at P_r: main chain 0..200, a
//       child of main 200 -> mid(ts(170), ts(171));
//   (3) median60 is read on the receipt's OWN P_r branch: a side branch from
//       main 150 with later timestamps gives a different median, and a
//       timestamp between the two is admitted on main and refused on the side;
//   (4) a timestamp 3 h ahead of the newest block admitted by consensus (no
//       clock input; the future bound is relay policy P-29);
//   (5) a child below height 60 has no median: the rule does not apply;
//   (6) a missing block of the 60 -> Defer naming its id;
//   (7) through header_fields: the header rules run before the size rules
//       and the cap; the verdict is STRIKE with one strike token;
//   (8) the vote rule (E-48): vote(minor) >= hf_version(h), minor 0 counting
//       as 1: at hf 16 minor 0 and 15 refused (STRIKE), 16 and 17 admitted;
//       at hf 1 minor 0 admitted (it votes 1);
//   (9) the floor reading (operator ruling): P_r held without its weights
//       reads Z = Z_lt = min_block_weight(hf) (300,000 at hf 16; none at
//       hf 17); n_tx or a length above the floor's bounds is undecided
//       (DEFER), the exact weights decide it; on a shared vector set the
//       floor node gives the exact node's verdict or DEFERs, never a STRIKE
//       the exact node would not give.
// ---------------------------------------------------------------------------
#include <cstdint>
#include <cstdio>
#include <map>
#include <optional>
#include <vector>

#include "impl/xmr/native/consensus/xmr_hf_table.hpp"
#include "impl/xmr/pathb/pathb_branch.hpp"
#include "impl/xmr/pathb/pathb_header_rules.hpp"
#include "pathb_kat_bodies.hpp"
#include "pathb_kat_check.hpp"

using namespace pathb_kat;
namespace pb = ::c2pool::xmr::pathb;
namespace nat = ::c2pool::xmr::native;

namespace {

constexpr std::uint8_t kMain = 0x4d;
constexpr std::uint8_t kSide = 0x53;
constexpr std::uint64_t kBase = 1700000000;
constexpr std::uint64_t kSideShift = 100000;

pb::Hash32 bid(std::uint8_t tag, std::uint64_t h) {
    pb::Hash32 id{};
    id[0] = tag;
    for (int i = 0; i < 8; ++i) id[1 + i] = static_cast<std::uint8_t>(h >> (8 * i));
    id[31] = 0x77;
    return id;
}

class MapView final : public pb::IBranchView {
public:
    std::map<pb::Hash32, pb::BranchBlock> blocks;

    std::optional<pb::BranchBlock> block(const pb::Hash32& id) const override {
        const auto it = blocks.find(id);
        if (it == blocks.end()) return std::nullopt;
        return it->second;
    }
    std::optional<pb::WeightInputs> weights_at(const pb::Hash32&) const override { return std::nullopt; }

    void add(std::uint8_t tag, std::uint64_t h, const pb::Hash32& parent, std::uint64_t ts) {
        pb::BranchBlock b;
        b.id = bid(tag, h);
        b.prev_id = parent;
        b.height = h;
        b.timestamp = ts;
        blocks[b.id] = b;
    }
};

std::optional<std::uint64_t> median_of_child(const MapView& v, const pb::Hash32& parent, pb::BranchStatus* st = nullptr) {
    std::optional<std::uint64_t> m;
    const pb::BranchStatus s = pb::timestamp_median_for_child(v, parent, m);
    if (st) *st = s;
    return s.selected() ? m : std::nullopt;
}

pb::HashingBlob blob(std::uint64_t major, std::uint64_t ts) {
    pb::HashingBlob b;
    b.major = major;
    b.minor = major;
    b.timestamp = ts;
    b.tx_count = 6;
    return b;
}

}  // namespace

int main() {
    std::printf("v37_xmr_receipt_header_rules_kat\n");

    // (1) major == hf_version(h)
    {
        const std::uint8_t hf16 = nat::hf_version_for_height(nat::XmrNet::Mainnet, 2689608);
        const std::uint8_t hf15 = nat::hf_version_for_height(nat::XmrNet::Mainnet, 2689607);
        check(hf16 == 16 && hf15 == 15, "mainnet hf_version: 2,689,608 -> 16, 2,689,607 -> 15");
        check(pb::header_rules(blob(16, kBase), hf16, std::nullopt) == pb::HeaderFault::None, "major 16 at hf 16 admitted");
        check(pb::header_rules(blob(15, kBase), hf16, std::nullopt) == pb::HeaderFault::MajorVersion,
              "major 15 at hf 16 refused");
        check(pb::header_rules(blob(17, kBase), hf16, std::nullopt) == pb::HeaderFault::MajorVersion,
              "major 17 at hf 16 refused (equality, not a lower bound)");
        check(pb::header_rules(blob(16, kBase), hf15, std::nullopt) == pb::HeaderFault::MajorVersion,
              "major 16 one height before the v16 activation refused");
        check(pb::header_rules(blob(15, kBase), hf15, std::nullopt) == pb::HeaderFault::None,
              "major 15 one height before the v16 activation admitted");
        check(nat::hf_version_for_height(nat::XmrNet::Regtest, 5) == 16, "regtest runs hf 16 from height 1");
        check(pb::header_fields_verdict(pb::HeaderFault::MajorVersion) == pb::AdmitVerdict::Strike
                      && pb::strike_tokens(pb::AdmitVerdict::Strike) == 1,
              "a wrong major is STRIKE (one token)");
    }

    // (8) the vote rule
    {
        const auto with_minor = [](std::uint64_t major, std::uint64_t minor) {
            pb::HashingBlob b = blob(major, kBase);
            b.minor = minor;
            return b;
        };
        check(pb::block_vote(0) == 1 && pb::block_vote(1) == 1 && pb::block_vote(16) == 16, "vote(0) = 1, vote(m) = m");
        check(pb::header_rules(with_minor(16, 0), 16, std::nullopt) == pb::HeaderFault::MinorVote,
              "vote: minor 0 at hf 16 refused (votes 1)");
        check(pb::header_rules(with_minor(16, 15), 16, std::nullopt) == pb::HeaderFault::MinorVote,
              "vote: minor 15 at hf 16 refused");
        check(pb::header_rules(with_minor(16, 16), 16, std::nullopt) == pb::HeaderFault::None,
              "vote: minor 16 at hf 16 admitted");
        check(pb::header_rules(with_minor(16, 17), 16, std::nullopt) == pb::HeaderFault::None,
              "vote: minor 17 at hf 16 admitted");
        check(pb::header_rules(with_minor(1, 0), 1, std::nullopt) == pb::HeaderFault::None,
              "vote: minor 0 at hf 1 admitted");
        check(pb::header_fields_verdict(pb::HeaderFault::MinorVote) == pb::AdmitVerdict::Strike,
              "vote: a refused vote is STRIKE");
    }

    // Branches: main 0..200 at kBase + 120 h; side 151..200 on main 150 at kBase + 120 h + kSideShift.
    MapView v;
    for (std::uint64_t h = 0; h <= 200; ++h) v.add(kMain, h, h ? bid(kMain, h - 1) : pb::Hash32{}, kBase + 120 * h);
    for (std::uint64_t h = 151; h <= 200; ++h)
        v.add(kSide, h, h == 151 ? bid(kMain, 150) : bid(kSide, h - 1), kBase + 120 * h + kSideShift);

    // (2) timestamp >= median60 over the 60 blocks ending at P_r
    const std::optional<std::uint64_t> m_main = median_of_child(v, bid(kMain, 200));
    const std::uint64_t expect_main = kBase + 120 * 170 + 60;  // mid(ts(170), ts(171))
    {
        std::vector<std::uint64_t> ts;
        for (std::uint64_t h = 141; h <= 200; ++h) ts.push_back(kBase + 120 * h);
        check(m_main.has_value() && *m_main == expect_main && *m_main == nat::median_of(ts),
              "median60 for a child of main 200 = mid(ts(170), ts(171))");
        check(pb::header_rules(blob(16, expect_main), 16, m_main) == pb::HeaderFault::None,
              "timestamp == median60 admitted");
        check(pb::header_rules(blob(16, expect_main - 1), 16, m_main) == pb::HeaderFault::TimestampBelowMedian,
              "timestamp == median60 - 1 refused");
        check(pb::header_rules(blob(16, 0), 16, m_main) == pb::HeaderFault::TimestampBelowMedian, "timestamp 0 refused");
        check(pb::header_fields_verdict(pb::HeaderFault::TimestampBelowMedian) == pb::AdmitVerdict::Strike,
              "a timestamp below median60 is STRIKE");
    }

    // (3) the receipt's own P_r branch
    {
        const std::optional<std::uint64_t> m_side = median_of_child(v, bid(kSide, 200));
        const std::uint64_t expect_side = kBase + 120 * 170 + 60 + kSideShift;
        std::vector<std::uint64_t> ts;
        for (std::uint64_t h = 141; h <= 150; ++h) ts.push_back(kBase + 120 * h);
        for (std::uint64_t h = 151; h <= 200; ++h) ts.push_back(kBase + 120 * h + kSideShift);
        check(m_side.has_value() && *m_side == expect_side && *m_side == nat::median_of(ts),
              "median60 for a child of side 200: main 141..150 + side 151..200");
        check(m_side != m_main, "the side branch median differs from the main chain's");
        const std::uint64_t between = expect_main + 1000;
        check(pb::header_rules(blob(16, between), 16, m_main) == pb::HeaderFault::None,
              "a timestamp between the medians: admitted on main P_r");
        check(pb::header_rules(blob(16, between), 16, m_side) == pb::HeaderFault::TimestampBelowMedian,
              "the same timestamp: refused on the side P_r");
    }

    // (4) no clock: far ahead of the newest block is admitted by consensus
    {
        const std::uint64_t newest = kBase + 120 * 200;
        check(pb::header_rules(blob(16, newest + 3 * 3600), 16, m_main) == pb::HeaderFault::None,
              "a timestamp 3 h ahead admitted by consensus");
        check(pb::header_rules(blob(16, (1ull << 35) - 1), 16, m_main) == pb::HeaderFault::None,
              "the largest encodable timestamp admitted by consensus");
    }

    // (5) chain start: below 60 blocks there is no median
    {
        pb::BranchStatus st;
        const std::optional<std::uint64_t> m58 = median_of_child(v, bid(kMain, 58), &st);
        check(st.selected() && !m58.has_value(), "child at height 59: no median");
        check(pb::header_rules(blob(16, 0), 16, m58) == pb::HeaderFault::None,
              "child at height 59: the timestamp rule does not apply");
        const std::optional<std::uint64_t> m59 = median_of_child(v, bid(kMain, 59), &st);
        check(st.selected() && m59 == std::optional<std::uint64_t>(kBase + 120 * 29 + 60),
              "child at height 60: median over heights 0..59");
    }

    // (6) a missing block of the 60 -> Defer naming it
    {
        MapView gap = v;
        gap.blocks.erase(bid(kMain, 160));
        pb::BranchStatus st;
        const std::optional<std::uint64_t> m = median_of_child(gap, bid(kMain, 200), &st);
        check(!st.selected() && st.reason == pb::DeferReason::MissingBlock && st.missing == bid(kMain, 160)
                      && !m.has_value(),
              "a missing block inside the 60 -> Defer naming its id");
        pb::BranchStatus st2;
        median_of_child(gap, bid(kMain, 220), &st2);
        check(!st2.selected() && st2.missing == bid(kMain, 220), "unknown P_r -> Defer naming it");
    }

    // (7) header_fields: header rules first, then size, then the cap
    {
        pb::ReceiptBodyV3 r = make_body(2, false, 5);
        r.blob.major = 16;
        r.blob.timestamp = expect_main;
        r.blob.tx_count = 6;  // D 2 at hf 16
        const pb::HeaderInputs in{16, m_main, 300000, 300000};
        const std::uint64_t len = enc(r).size();
        check(pb::header_fields(r, len, in) == pb::HeaderFault::None
                      && !pb::header_fields_verdict(pb::header_fields(r, len, in)).has_value(),
              "a valid receipt passes #9 (no verdict)");
        pb::ReceiptBodyV3 both = r;
        both.blob.major = 15;
        both.branch.push_back(seq32(0x99));  // D 3: also a size fault
        check(pb::header_fields(both, enc(both).size(), in) == pb::HeaderFault::MajorVersion,
              "header rules are judged before the size rules");
        pb::ReceiptBodyV3 early = r;
        early.blob.timestamp = expect_main - 1;
        check(pb::header_fields(early, enc(early).size(), in) == pb::HeaderFault::TimestampBelowMedian,
              "#9: timestamp below median60 STRIKE");
        pb::ReceiptBodyV3 depth = r;
        depth.branch.push_back(seq32(0x98));
        check(pb::header_fields(depth, enc(depth).size(), in) == pb::HeaderFault::Depth, "#9: wrong D STRIKE");
    }

    // (9) the floor reading (operator ruling): P_r held verified without its weights reads Monero's floor
    {
        const std::optional<pb::HeaderInputs> f16 = pb::header_inputs_floor(16, m_main);
        check(f16 && f16->hf == 16 && f16->z == 300000 && f16->z_lt == 300000 && f16->floor && f16->median60 == m_main
                      && !pb::header_inputs_floor(17, m_main) && !pb::header_inputs_floor(4, m_main),
              "the floor: Z = Z_lt = min_block_weight(hf) = 300,000 at hf 16; none at hf 17 (FORK-FUSE) or below hf 5");
        check(pb::max_tx_count(300000) == 411, "the floor's n_tx bound at hf 16: 411 (2 x 300,000 / w_min)");
        // n_tx - 1 = 412: above the floor's bound
        pb::ReceiptBodyV3 band = make_body(8, false, 5);
        band.blob.major = 16;
        band.blob.timestamp = expect_main;
        band.blob.tx_count = 413;  // D 8
        const std::uint64_t blen = enc(band).size();
        const pb::HeaderInputs ex1{16, m_main, 300000, 300000}, ex2{16, m_main, 600000, 600000};
        const pb::HeaderFault ff = pb::header_fields(band, blen, *f16);
        check(ff == pb::HeaderFault::SizeUndecided && pb::header_fields_verdict(ff) == pb::AdmitVerdict::Defer,
              "the floor: 413 transactions (above 411 + 1) is undecided: DEFER, never STRIKE");
        check(pb::header_fields(band, blen, ex1) == pb::HeaderFault::TxCount && pb::header_fields(band, blen, ex2) == pb::HeaderFault::None,
              "the exact weights decide it: STRIKE at Z = 300,000, PASS at Z = 600,000");
        // a length above RECEIPT_CAP at the floor
        const std::uint64_t cap = pb::receipt_cap(16, 300000).value_or(0);
        pb::ReceiptBodyV3 small = make_body(2, false, 5);
        small.blob.major = 16;
        small.blob.timestamp = expect_main;
        small.blob.tx_count = 6;
        check(cap > 0 && pb::header_fields(small, cap + 1, *f16) == pb::HeaderFault::SizeUndecided
                      && pb::header_fields(small, cap + 1, ex1) == pb::HeaderFault::OverCap
                      && pb::header_fields(small, cap, *f16) == pb::HeaderFault::None,
              "the floor: a length above RECEIPT_CAP(16, floor) is undecided (exact: STRIKE at the zone); at the cap PASS");
        check(pb::header_fields(small, 0, pb::HeaderInputs{16, m_main, 300000, 300000, true}) == pb::HeaderFault::None,
              "the floor: a receipt inside the floor's bounds passes");
        // a shared vector set: the floor node's verdict equals the exact node's, or it DEFERs; it never STRIKEs where
        // the exact node passes, and at Z = the zone it differs only by DEFERring an exact size STRIKE
        int same = 0, deferred = 0, bad = 0;
        const std::uint64_t txs[] = {0, 1, 2, 6, 100, 412, 413, 800, 5000};
        const std::uint64_t zs[] = {300000, 450000, 600000, 3000000};
        for (const std::uint64_t n : txs)
            for (const int dshift : {0, 1})
                for (const std::uint64_t major : {16u, 15u})
                    for (const std::uint64_t z : zs)
                        for (const std::uint64_t len : {std::uint64_t{0}, cap, cap + 1, 4 * cap}) {
                            const std::uint64_t d = (n == 0 ? 0 : pb::receipt_depth_for(16, n)) + dshift;
                            pb::ReceiptBodyV3 r = make_body(d, false, 5);
                            r.blob.major = major;
                            r.blob.timestamp = expect_main;
                            r.blob.tx_count = n;
                            const pb::HeaderFault e = pb::header_fields(r, len, pb::HeaderInputs{16, m_main, z, z});
                            const pb::HeaderFault fl = pb::header_fields(r, len, *f16);
                            if (fl == e) {
                                ++same;
                            } else if (fl == pb::HeaderFault::SizeUndecided) {
                                ++deferred;
                                if (z == 300000 && e != pb::HeaderFault::TxCount && e != pb::HeaderFault::OverCap
                                    && e != pb::HeaderFault::Depth)
                                    ++bad;
                            } else {
                                ++bad;
                            }
                        }
        check(bad == 0 && same > 0 && deferred > 0,
              "the floor and the exact node: " + std::to_string(same) + " vectors the same verdict, " +
                      std::to_string(deferred) + " DEFERred on the floor, 0 differing otherwise (" + std::to_string(bad) + ")");
    }

    return finish("v37_xmr_receipt_header_rules_kat");
}
