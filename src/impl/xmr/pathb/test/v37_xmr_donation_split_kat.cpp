// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// v37_xmr_donation_split_kat (C26, K16; pathb_lane_rules.hpp, pathb_window.hpp):
//   give_author_bp 10 credits floor(work x 10 / 10000) to the author identity;
//   0 credits nothing; the login disclosure of give_author_pct and
//   node_owner_fee_pct; no marker output; merge-back below the floor; the K16
//   author identity per network = sha256d(0x01 || author_ref) with the four
//   goldens, the reference equal to master's donation keys byte for byte; an
//   author that is also a miner; p + give_author_bp = 10000 exactly.
// ---------------------------------------------------------------------------
#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

#include "impl/xmr/pathb/pathb_lane_rules.hpp"
#include "impl/xmr/pathb/pathb_window.hpp"
#include "pathb_kat_check.hpp"
#include "sharechain/v37/v37_descriptor_xmr.hpp"

using namespace pathb_kat;
namespace pb = ::c2pool::xmr::pathb;

namespace {

pb::Hash32 id_of(std::uint8_t a) {
    pb::Hash32 h{};
    h.fill(a);
    return h;
}

}  // namespace

int main() {
    // floor(work x 10 / 10000) to the author
    for (std::uint64_t work : {1ull, 999ull, 1000ull, 18180ull, 123456789ull}) {
        const pb::Shares s = pb::shares_of(work, 0, pb::kDonationBp);
        check(s.w_author == work * 10 / 10000 && s.w_miner + s.w_author == work,
              "give_author_bp 10: author floor(work x 10 / 10000) at work " + std::to_string(work));
    }
    check(pb::shares_of(5000, 0, 0).w_author == 0, "give_author_bp 0 credits nothing");
    const pb::Shares edge = pb::shares_of(77777, 9990, 10);
    check(edge.w_miner + edge.w_owner + edge.w_author == 77777 && edge.w_owner == 77777 * 9990 / 10000
              && edge.w_author == 77777 * 10 / 10000,
          "p + give_author_bp = 10000 exactly: the three shares sum to the work");

    // the window credits the author identity; no marker output; merge-back below the floor
    const pb::Hash32 author = pb::author_identity(pb::LaneNet::Mainnet);
    pb::WinBin bin;
    bin.bin = 1;
    for (std::uint8_t m = 0; m < 4; ++m) {
        pb::WinEntry e;
        e.miner = id_of(0x20 + m);
        e.work = 10000000;
        e.position = m;
        e.id = id_of(0x60 + m);
        e.give_author_bp = pb::kDonationBp;
        bin.entries.push_back(e);
    }
    const pb::Window w = pb::window({bin}, 1ull << 40, 600000000000ull, 1, 1000, author);
    check(w.weight.count(author) == 1 && w.weight.at(author) == pb::Work(4 * 10000), "the window credits the author identity 4 x 10,000");
    const std::vector<pb::SplitOutput> out = pb::split(600000000000ull, w);
    bool no_zero = !out.empty();
    for (const pb::SplitOutput& o : out) no_zero = no_zero && o.amount > 0;
    check(no_zero && out.size() == 5, "no 0-amount marker output: four miners + the author, every amount > 0");
    // below the spend floor the author share merges back to the contributing miners (W constant)
    const pb::Window wm = pb::window({bin}, 1ull << 40, 600000000000ull, 6000000000ull, 1000, author);
    check(wm.weight.count(author) == 0 && wm.W == w.W && wm.weight.at(id_of(0x20)) == pb::Work(10000000),
          "below the floor the author share merges back to the miners (the S3 merge-back rule)");
    // an author that is also a miner: one identity, its two parts summed
    pb::WinBin both = bin;
    both.entries[0].miner = author;
    const pb::Window wb = pb::window({both}, 1ull << 40, 600000000000ull, 1, 1000, author);
    check(wb.weight.at(author) == pb::Work(10000000 - 10000 + 4 * 10000), "an author that is also a miner gets miner + author weight");

    // the login disclosure
    check(pb::login_fee_disclosure(pb::kDonationBp, 0) == "\"give_author_pct\":0.1000,\"node_owner_fee_pct\":0.0000",
          "login reply discloses give_author_pct 0.1000 and node_owner_fee_pct");
    check(pb::login_fee_disclosure(0, 250) == "\"give_author_pct\":0.0000,\"node_owner_fee_pct\":2.5000", "0 bp and 250 bp disclosed");

    // K16: identities per network (independent goldens) and master's keys byte for byte
    const char* gold[4] = {"0bf5439fbd213a43d5c0cf066577adb9b39bb0ccfe622e789eba2b58e6e590aa",
                           "7fa3b4863ab50ab27505ca97b483169dfa1f65177e3de563de6eaa2e51938623",
                           "315230ba6c46179c1f0b1ded16329ff3f5da7a30a7804fb16ff9a46de21cd9d6",
                           "257bc98f17b786625362a8e56819ca1b4ce7e5c06cfa038ce015dfa97978a618"};
    // master's donation keys per network as author_ref (kind 0x10 | len 64 | spend | view, 66 B)
    const char* ref66[4] = {"1040"
                            "14d413e6ccb14f0ba30999b97c8912a07321d893789b7f149810b7885b2cd7c7"
                            "b3157741ab68969aeb7fe9ebd4fa3ec5ce4dcdc7b43249fdb40311cb03779e03",
                            "1040"
                            "a7731abbe9bb2cf3264395231a8645172ffd7f08c6097e3402197f3f1c6ffcbb"
                            "ef3c9a659a67c3bf081a352e7cfbfb94cc5e11921a3e8953223fca1ed14e2200",
                            "1040"
                            "7f095705904be1df109bdf44b0027c339fde3ece7d85069f8bdfb19fd8c16c41"
                            "0abca326ba53a6f5387785822296c1d15df03e6c51cd44d7dbe270667b5fe34c",
                            "1040"
                            "3091e80a51918c67eb67b6fefaf77e374dd898240953bbb75d47b82b8615c638"
                            "c5d453f0d54332e4f48f12abab2551132f00037f0c51892ebe3b41928ab5bec1"};
    for (int i = 0; i < 4; ++i) {
        const pb::LaneNet n = pb::kLaneNets[i];
        const pb::XmrKeyRef r = pb::author_ref(n);
        const pb::Hash32 idn = pb::author_identity(n);
        check(hex(idn.data(), idn.size()) == gold[i], std::string("K16 author identity golden ") + std::string(pb::lane_net_name(n)));
        std::array<std::uint8_t, 32> B{}, A{};
        std::copy(r.spend.begin(), r.spend.end(), B.begin());
        std::copy(r.view.begin(), r.view.end(), A.begin());
        const ::v37::bytes32 master_id = ::v37::xmr::xmr_identity_key(::v37::xmr::make_xmr_std(B, A));
        check(std::equal(master_id.begin(), master_id.end(), idn.begin()), "identity == xmr_identity_key(make_xmr_std(B, A))");
        const std::string ref = ref66[i];
        const std::string spend = ref.substr(4, 64);
        const std::string view = ref.substr(68, 64);
        check(hex(r.spend.data(), 32) == spend && hex(r.view.data(), 32) == view && !spend.empty(),
              std::string("author_ref equals master's donation keys byte for byte: ") + std::string(pb::lane_net_name(n)));
        // K16 on the TLV: give_author_bp | 0x10 | 0x40 | spend | view (put_key_ref; the TLV golden holds these bytes)
        const std::vector<std::uint8_t> k16 = pb::lane_rule_value(pb::epoch0_lane_rules(n), 0x10);
        check(k16.size() == 68 && k16[0] == 10 && k16[1] == 0 && k16[2] == 0x10 && k16[3] == 0x40
                      && hex(k16.data() + 4, 32) == spend && hex(k16.data() + 36, 32) == view,
              std::string("K16 TLV value = u16 10 | 0x10 | 0x40 | spend | view: ") + std::string(pb::lane_net_name(n)));
    }
    check(pb::epoch0_lane_rules(pb::LaneNet::Testnet).author == pb::author_ref(pb::LaneNet::Testnet)
              && pb::epoch0_lane_rules(pb::LaneNet::Mainnet).give_author_bp == 10,
          "K16 in the lane rules: give_author_bp 10 + author_ref(net)");
    return finish("v37_xmr_donation_split_kat");
}
