// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// v37_xmr_pathb_hello_kat (pathb_hello.hpp, pathb_lane_rules.hpp): the Path B
// FB_HELLO rules block and the S4 trailer.
//   the epoch-0 TLV golden (263 B) beside the 29-byte S3 golden (its seven
//   S3 entries); the rules block = codec 2 | LE16 263 | TLV; an unknown id
//   (0x0c, K12, absent in v1) refused naming it; codec byte 1 refused naming
//   K22; the 68-byte trailer round trip; a trailer of another length refused.
// ---------------------------------------------------------------------------
#include <cstdint>
#include <string>
#include <vector>

#include "impl/xmr/pathb/pathb_hello.hpp"
#include "impl/xmr/pathb/pathb_lane_rules.hpp"
#include "pathb_kat_check.hpp"

using namespace pathb_kat;
namespace pb = ::c2pool::xmr::pathb;

namespace {

const char* kS3Golden = "0901020a01010b0101110101180859003d0022005400190202011d0101";
const char* kTlvMainnet =
        "01080a00000000000000020804470000000000000311700800000000000001090000000000000004086000000000000000050801"
        "000000000000000608000000000000000007080200000000000000080810000000000000000901020a01010b01010f010110440a"
        "00104014d413e6ccb14f0ba30999b97c8912a07321d893789b7f149810b7885b2cd7c7b3157741ab68969aeb7fe9ebd4fa3ec5ce"
        "4dcdc7b43249fdb40311cb03779e03110101120101142061affbea4c4ab212b9fbfd8b3a9ae6954840660890df6fca9d8027b8f0"
        "9738f41503031001170101180859003d0022005400190202011d01011e1901418800000000000080d8010000000000c05e0e0000"
        "000000";

std::vector<std::uint8_t> subset(const std::vector<std::uint8_t>& t, std::initializer_list<std::uint8_t> ids) {
    std::vector<std::uint8_t> out;
    for (std::size_t o = 0; o + 2 <= t.size();) {
        const std::uint8_t id = t[o], n = t[o + 1];
        for (std::uint8_t w : ids)
            if (w == id) out.insert(out.end(), t.begin() + o, t.begin() + o + 2 + n);
        o += 2 + n;
    }
    return out;
}

}  // namespace

int main() {
    const pb::PathbLaneRules r = pb::epoch0_lane_rules(pb::LaneNet::Mainnet);
    const std::vector<std::uint8_t> t = pb::encode_lane_rules_tlv(r);
    check(t.size() == 263 && hex(t.data(), t.size()) == kTlvMainnet, "epoch-0 TLV golden, 263 B (mainnet)");
    const std::vector<std::uint8_t> s3 = subset(t, {0x09, 0x0a, 0x0b, 0x11, 0x18, 0x19, 0x1d});
    check(s3.size() == 29 && hex(s3.data(), s3.size()) == kS3Golden, "its seven S3 entries are the 29-byte S3 golden");
    const std::vector<std::uint8_t> blk = pb::rules_block(r);
    check(blk.size() == 266 && blk[0] == 2 && blk[1] == 0x07 && blk[2] == 0x01, "rules block = codec 2 | LE16 263 | TLV");
    check(pb::rules_digest_preimage(r).size() == 294, "rules_digest preimage 294 B");

    // unknown id 0x0c (K12, absent in v1) between 0x0b and 0x0f
    std::vector<std::uint8_t> bad;
    for (std::size_t o = 0; o < t.size();) {
        const std::uint8_t id = t[o], n = t[o + 1];
        if (id == 0x0f) {
            bad.push_back(0x0c);
            bad.push_back(1);
            bad.push_back(1);
        }
        bad.insert(bad.end(), t.begin() + o, t.begin() + o + 2 + n);
        o += 2 + n;
    }
    std::vector<std::uint8_t> bblk{2};
    bblk.push_back(static_cast<std::uint8_t>(bad.size()));
    bblk.push_back(static_cast<std::uint8_t>(bad.size() >> 8));
    bblk.insert(bblk.end(), bad.begin(), bad.end());
    const pb::LaneRulesDecode d = pb::decode_rules_block(bblk);
    check(d.error == pb::LaneRulesError::UnknownId && d.id == 0x0c, "an unknown id 0x0c is refused naming it");
    const pb::LaneRulesCompare c = pb::lane_rules_mismatch(blk, bblk);
    check(c.verdict == pb::LaneRulesVerdict::Refused && c.id == 0x0c, "HELLO: refused naming id12: " + c.text);
    // the ratchet entry 0x1e is a known id from S4
    check(pb::lane_rule_field(0x1e) != nullptr && pb::lane_rule_field(0x0c) == nullptr, "0x1e (K30) known, 0x0c unknown");
    // codec byte 1 refused naming K22
    std::vector<std::uint8_t> c1 = blk;
    c1[0] = 1;
    const pb::LaneRulesCompare cc = pb::lane_rules_mismatch(blk, c1);
    check(cc.verdict == pb::LaneRulesVerdict::Refused && cc.id == 22 && cc.text.find("field=K22") != std::string::npos,
          "codec byte 1 refused naming K22");

    // trailer round trip
    pb::HelloTrailer tr;
    tr.epoch_cur = 0x0102;
    tr.deploy_top = 0x0103;
    tr.deploy_digest = seq32(0x20);
    tr.next_digest = seq32(0x60);
    const pb::HelloTrailerBytes tb = pb::encode_hello_trailer(tr);
    check(tb.size() == 68 && tb[0] == 0x02 && tb[1] == 0x01 && tb[2] == 0x03 && tb[3] == 0x01 && tb[4] == 0x20 && tb[36] == 0x60,
          "trailer = LE16 epoch_cur | LE16 deploy_top | deploy_digest | next_digest (68 B)");
    check(pb::decode_hello_trailer(tb) == std::optional<pb::HelloTrailer>(tr), "trailer round trip");
    std::vector<std::uint8_t> shortb(tb.begin(), tb.end() - 1), longb(tb.begin(), tb.end());
    longb.push_back(0);
    check(!pb::decode_hello_trailer(shortb).has_value() && !pb::decode_hello_trailer(longb).has_value(), "a trailer of 67 or 69 B refused");
    return finish("v37_xmr_pathb_hello_kat");
}
