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
#include <fstream>
#include <sstream>
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

std::string read_file(const std::string& path) {
    std::ifstream f(path);
    std::stringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

// the quoted value of `name[] = "..."` in a source text
std::string quoted(const std::string& text, const std::string& name) {
    const std::size_t at = text.find(name + "[]");
    if (at == std::string::npos) return {};
    const std::size_t q0 = text.find('"', at);
    const std::size_t q1 = text.find('"', q0 + 1);
    return text.substr(q0 + 1, q1 - q0 - 1);
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
    const char* suffix[4] = {"", "Testnet", "Stagenet", "Regtest"};
    const std::string fee_model = read_file(std::string(C2POOL_SRC_DIR) + "/c2pool/v37/xmr/xmr_fee_model.hpp");
    check(!fee_model.empty(), "master's xmr_fee_model.hpp read");
    for (int i = 0; i < 4; ++i) {
        const pb::LaneNet n = pb::kLaneNets[i];
        const pb::KeyRef r = pb::author_ref(n);
        const pb::Hash32 idn = pb::author_identity(n);
        check(hex(idn.data(), idn.size()) == gold[i], std::string("K16 author identity golden ") + std::string(pb::lane_net_name(n)));
        std::array<std::uint8_t, 32> B{}, A{};
        std::copy(r.begin() + 2, r.begin() + 34, B.begin());
        std::copy(r.begin() + 34, r.end(), A.begin());
        const ::v37::bytes32 master_id = ::v37::xmr::xmr_identity_key(::v37::xmr::make_xmr_std(B, A));
        check(std::equal(master_id.begin(), master_id.end(), idn.begin()), "identity == xmr_identity_key(make_xmr_std(B, A))");
        const std::string spend = quoted(fee_model, std::string("kDonationSpendHex") + suffix[i]);
        const std::string view = quoted(fee_model, std::string("kDonationViewHex") + suffix[i]);
        check(r[0] == 0x10 && r[1] == 0x40 && hex(r.data() + 2, 32) == spend && hex(r.data() + 34, 32) == view && !spend.empty(),
              std::string("author_ref equals master's donation keys byte for byte: ") + std::string(pb::lane_net_name(n)));
    }
    check(pb::epoch0_lane_rules(pb::LaneNet::Testnet).author == pb::author_ref(pb::LaneNet::Testnet)
              && pb::epoch0_lane_rules(pb::LaneNet::Mainnet).give_author_bp == 10,
          "K16 in the lane rules: give_author_bp 10 + author_ref(net)");
    return finish("v37_xmr_donation_split_kat");
}
