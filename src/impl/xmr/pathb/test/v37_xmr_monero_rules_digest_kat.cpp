// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// v37_xmr_monero_rules_digest_kat (K20; pathb_lane_rules.hpp): one digest over
// the named Monero constant set, 26 entries in their order, values from the
// symbols the Path B code reads; the TLV (287 B) and digest goldens, equal on
// every network; each constant changed alone changes the digest; two builds
// whose sets differ in one hf-17 value refuse each other naming 0x14.
// ---------------------------------------------------------------------------
#include <array>
#include <cstdint>
#include <string>
#include <vector>

#include "impl/xmr/pathb/pathb_lane_rules.hpp"
#include "pathb_kat_check.hpp"

using namespace pathb_kat;
namespace pb = ::c2pool::xmr::pathb;

namespace {

const char* kK20TlvGolden =
        "010878000000000000000208d00200000000000003080f0000000000000004083c000000000000000508ffffffffffffffff0608"
        "1400000000000000070800b864d945000000080893020000000000000910b80b000000000000d4300000000000000a10e093040000"
        "00000068890900000000000b0810270000000000000c01010d0810000000000000000e0810270000000000000f08b30500000000"
        "0000101000000000000000000200000000000000111032000000000000000800000000000000120864000000000000001308a086"
        "01000000000014083c0000000000000015080008000000000000160840000000000000001701011810000000000000000021000000"
        "000000001901011a1059000000000000003d00000000000000";
const char* kK20DigestGolden = "61affbea4c4ab212b9fbfd8b3a9ae6954840660890df6fca9d8027b8f09738f4";

}  // namespace

int main() {
    using pb::MoneroRuleClass;
    const auto& R = pb::kMoneroRules;
    check(R.size() == 26, "26 entries");
    bool ids = true;
    for (std::size_t i = 0; i < R.size(); ++i) ids = ids && R[i].id == i + 1;
    check(ids, "ids 1..26 in D 2.15 order");
    check(pb::kMoneroRulesDomain == "c2pool-v37-xmr-monero-rules-v1" && pb::kMoneroRulesDomain.size() == 30,
          "domain c2pool-v37-xmr-monero-rules-v1, 30 bytes");

    // values (D 2.15; CONSTANTS M-01..M-15)
    struct Want { std::uint8_t id; MoneroRuleClass c; std::uint64_t a, b; };
    const Want want[] = {
        {1, MoneroRuleClass::Scalar, 120, 0},       {2, MoneroRuleClass::Scalar, 720, 0},
        {3, MoneroRuleClass::Scalar, 15, 0},        {4, MoneroRuleClass::Scalar, 60, 0},
        {5, MoneroRuleClass::Scalar, ~std::uint64_t{0}, 0},
        {6, MoneroRuleClass::Scalar, 20, 0},        {7, MoneroRuleClass::Scalar, 300000000000ull, 0},
        {8, MoneroRuleClass::Scalar, 659, 0},       {9, MoneroRuleClass::Pair, 3000, 12500},
        {10, MoneroRuleClass::Pair, 300000, 625000}, {11, MoneroRuleClass::Scalar, 10000, 0},
        {12, MoneroRuleClass::Version, 1, 0},       {13, MoneroRuleClass::Scalar, 16, 0},
        {14, MoneroRuleClass::Scalar, 10000, 0},    {15, MoneroRuleClass::Scalar, 1459, 0},
        {16, MoneroRuleClass::Pair, 0, 2},          {17, MoneroRuleClass::Pair, 50, 8},
        {18, MoneroRuleClass::Scalar, 100, 0},      {19, MoneroRuleClass::Scalar, 100000, 0},
        {20, MoneroRuleClass::Scalar, 60, 0},       {21, MoneroRuleClass::Scalar, 2048, 0},
        {22, MoneroRuleClass::Scalar, 64, 0},       {23, MoneroRuleClass::Version, 1, 0},
        {24, MoneroRuleClass::Pair, 0, 33},         {25, MoneroRuleClass::Version, 1, 0},
        {26, MoneroRuleClass::Pair, 89, 61},
    };
    bool vals = true;
    for (const Want& w : want) {
        const pb::MoneroRule& r = R[w.id - 1];
        const bool ok = r.id == w.id && r.cls == w.c && r.hf16 == w.a && (w.c != MoneroRuleClass::Pair || r.hf17 == w.b);
        if (!ok) std::printf("  entry %u %s: %llu / %llu\n", r.id, std::string(r.name).c_str(),
                             (unsigned long long)r.hf16, (unsigned long long)r.hf17);
        vals = vals && ok;
    }
    check(vals, "every entry's class and value(s) equal the ruled K20 table");

    // goldens
    const std::vector<std::uint8_t> t = pb::monero_rules_tlv(R);
    check(t.size() == 287, "K20 TLV 287 B");
    check(hex(t.data(), t.size()) == kK20TlvGolden, "K20 TLV golden (independent recompute)");
    const pb::Hash32 d = pb::monero_rules_digest();
    check(hex(d.data(), d.size()) == kK20DigestGolden, "K20 digest golden: " + hex(d.data(), d.size()));
    for (pb::LaneNet n : pb::kLaneNets)
        check(pb::epoch0_lane_rules(n).monero_rules_digest == d, std::string("K20 equal on ") + std::string(pb::lane_net_name(n)));

    // each named constant changed alone changes the digest
    bool each = true;
    for (std::size_t i = 0; i < R.size(); ++i) {
        std::array<pb::MoneroRule, 26> m = R;
        m[i].hf16 += 1;
        each = each && pb::monero_rules_digest(m) != d;
        if (m[i].cls == MoneroRuleClass::Pair) {
            std::array<pb::MoneroRule, 26> m17 = R;
            m17[i].hf17 += 1;
            each = each && pb::monero_rules_digest(m17) != d;
        }
    }
    check(each, "each named constant (each hf column) changed alone changes the digest");

    // two builds that differ in one hf-17 value (hf-16 values equal): different K20, LANE_RULES_MISMATCH naming 0x14
    std::array<pb::MoneroRule, 26> b = R;
    b[9].hf17 = 600000;  // CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5 pair, hf 17 column only
    pb::PathbLaneRules ours = pb::epoch0_lane_rules(pb::LaneNet::Mainnet), theirs = ours;
    theirs.monero_rules_digest = pb::monero_rules_digest(b);
    const pb::LaneRulesCompare c = pb::lane_rules_mismatch(pb::rules_block(ours), pb::rules_block(theirs));
    check(theirs.monero_rules_digest != ours.monero_rules_digest && c.verdict == pb::LaneRulesVerdict::Mismatch && c.id == 0x14
              && c.text.rfind("LANE_RULES_MISMATCH field=monero_rules_digest", 0) == 0,
          "an hf-17-only difference: " + c.text.substr(0, 60));
    return finish("v37_xmr_monero_rules_digest_kat");
}
