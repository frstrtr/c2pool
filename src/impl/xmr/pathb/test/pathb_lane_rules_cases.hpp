// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// src/impl/xmr/pathb/test/pathb_lane_rules_cases.hpp
// The Path B case group of v37_xmr_lane_rules_kat (pathb_lane_rules.hpp):
//   the field set (22 TLV ids = the K numbers, the codec byte K22, epoch_cur in
//   the trailer); the epoch-0 TLV (263 B) and G per network against the
//   independent goldens; rules_digest changes when any K value changes; a
//   node whose compiled G differs refuses to start; LANE_RULES_MISMATCH names
//   the first differing id with both values; unknown / missing / out-of-order
//   ids and codec byte 1 refused; peers at another epoch_cur accepted; the 29
//   retired fields, the pool identity and the policy values are not fields.
// ---------------------------------------------------------------------------
#pragma once

#include <cstdint>
#include <cstdio>
#include <string>
#include <string_view>
#include <vector>

#include "impl/xmr/pathb/pathb_ratchet_activation.hpp"

namespace pathb_lane_rules_cases {

namespace pb = ::c2pool::xmr::pathb;

inline int g_checks = 0;
inline int g_fail = 0;

inline void check(bool cond, const std::string& msg) {
    ++g_checks;
    if (!cond) {
        ++g_fail;
        std::printf("  FAIL (path B): %s\n", msg.c_str());
    }
}

inline std::string hx(const pb::Hash32& h) { return pb::lr_detail::hex(h.data(), h.size()); }

inline std::vector<std::uint8_t> block_of(const std::vector<std::uint8_t>& tlv, std::uint8_t codec = pb::kPathbRulesCodec) {
    std::vector<std::uint8_t> b{codec, static_cast<std::uint8_t>(tlv.size()), static_cast<std::uint8_t>(tlv.size() >> 8)};
    b.insert(b.end(), tlv.begin(), tlv.end());
    return b;
}

inline int run() {
    std::printf("== v37_xmr_lane_rules_kat: Path B case group ==\n");
    // the field set
    const std::uint8_t want_ids[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
                                     0x0f, 0x10, 0x11, 0x12, 0x14, 0x15, 0x17, 0x18, 0x19, 0x1d, 0x1e};
    const char* want_names[] = {"carrier_interval_s", "d_min", "retarget", "open_bins", "liveness_delta", "seal_depth",
                                "fresh_max", "r_max", "coverage", "n_rule_version", "w_max_rule_version",
                                "owner_fee_version", "donation", "payment_groups", "receipt_size_rule",
                                "monero_rules_digest", "side_data_and_format", "roundabout_chains", "ovh_out",
                                "coinbase_reserve", "split_rule_version", "ratchet"};
    bool set = pb::kPathbLaneRuleFieldCount == 22;
    for (std::size_t i = 0; set && i < 22; ++i)
        set = pb::kPathbLaneRuleFields[i].id == want_ids[i] && pb::kPathbLaneRuleFields[i].name == want_names[i];
    check(set, "the X-macro field set equals the S4.5 list (22 ids = K numbers), codec byte K22 = 2");
    check(pb::kPathbRulesCodec == 2 && pb::kHelloTrailerBytes == 68, "K22 is the codec byte; epoch_cur travels in the trailer");

    // goldens per network
    const char* G[4] = {"31ac3ccf21f4aa825bb1ef657fe418b9f58861c1698bbfe357649176fac54e55",
                        "bf2df9c500f3cee6344b862917ab0234ec5e65e0fbccf10ad568bfc6080ae213",
                        "45744e8c486eac5068f5e8179c8e96b7ecdb264ab43610447318b46ff3ffda49",
                        "f91737946910674cbe8dac71618f5c02ab5c6c7d4a431163c9b4d2222ce67e0e"};
    for (int i = 0; i < 4; ++i) {
        const pb::LaneNet n = pb::kLaneNets[i];
        const pb::PathbLaneRules r = pb::epoch0_lane_rules(n);
        const std::string net(pb::lane_net_name(n));
        check(pb::encode_lane_rules_tlv(r).size() == 263 && pb::rules_digest_preimage(r).size() == 294, net + ": TLV 263 B, preimage 294 B");
        check(hx(pb::rules_digest(r)) == G[i], net + ": G = rules_digest(epoch 0) golden " + hx(pb::rules_digest(r)));
        check(pb::genesis_rules_digest(n) == pb::rules_digest(r), net + ": the compiled G equals rules_digest of the epoch-0 list");
        const pb::LaneRulesDecode d = pb::decode_rules_block(pb::rules_block(r));
        check(d.error == pb::LaneRulesError::None && d.rules == r, net + ": the rules block round-trips");
        pb::EpochTable T;
        T.compiled.push_back(pb::CompiledEpoch{0, pb::genesis_rules_digest(n), r});
        check(pb::lane_rules_valid(n, T).ok, net + ": lane_rules_valid");
        pb::EpochTable bad = T;
        bad.compiled[0].digest[5] ^= 1;
        check(!pb::lane_rules_valid(n, bad).ok, net + ": a compiled G that differs from rules_digest of the list: the node refuses to start");
    }
    // regtest: a rig list differing in K30 only computes G at start; any other difference refuses
    pb::PathbLaneRules rig = pb::epoch0_lane_rules(pb::LaneNet::Regtest);
    rig.vote_window = 4;
    rig.grace = 6;
    rig.timeout = 9;
    check(pb::genesis_digest_for(pb::LaneNet::Regtest, rig) == std::optional<pb::Hash32>(pb::rules_digest(rig))
              && !pb::genesis_digest_for(pb::LaneNet::Mainnet, rig).has_value(),
          "regtest rig K30: G computed at start; the same list on mainnet refused");
    pb::PathbLaneRules rig2 = rig;
    rig2.r_max = 17;
    check(!pb::genesis_digest_for(pb::LaneNet::Regtest, rig2).has_value(), "regtest: a difference outside K30 refused");
    // an own attempt whose digest is not the compiled rules: refused
    {
        const pb::PathbLaneRules r0 = pb::epoch0_lane_rules(pb::LaneNet::Mainnet);
        pb::PathbLaneRules r1 = r0;
        r1.r_max = 17;
        pb::EpochTable T;
        T.compiled.push_back(pb::CompiledEpoch{0, pb::genesis_rules_digest(pb::LaneNet::Mainnet), r0});
        T.compiled.push_back(pb::CompiledEpoch{1, pb::rules_digest(r1), r1});
        T.attempts.push_back(pb::Deployment{1, pb::rules_digest(r1), pb::kKindVote, 0, 26 * 34881, 0});
        check(pb::lane_rules_valid(pb::LaneNet::Mainnet, T).ok, "an implemented epoch with its own attempt's digest == rules_digest(rules_of(e))");
        T.attempts[0].rules_digest[0] ^= 1;
        check(!pb::lane_rules_valid(pb::LaneNet::Mainnet, T).ok, "an own attempt whose digest is not rules_digest(rules_of(e)): refused");
    }

    // rules_digest changes when any K value changes; the mismatch names the field with both values
    const pb::PathbLaneRules base = pb::epoch0_lane_rules(pb::LaneNet::Mainnet);
    const pb::Hash32 g0 = pb::rules_digest(base);
    const std::vector<std::uint8_t> ours = pb::rules_block(base);
    for (const pb::LaneRuleField& f : pb::kPathbLaneRuleFields) {
        std::vector<std::uint8_t> t = pb::encode_lane_rules_tlv(base);
        std::size_t o = 0;
        while (t[o] != f.id) o += 2 + t[o + 1];
        t[o + 2 + f.len - 1] ^= 0x01;  // the field's last byte
        const std::vector<std::uint8_t> theirs = block_of(t);
        const pb::LaneRulesDecode d = pb::decode_rules_block(theirs);
        check(d.error == pb::LaneRulesError::None && pb::rules_digest(d.rules) != g0,
              "rules_digest changes when " + std::string(f.name) + " changes");
        const pb::LaneRulesCompare c = pb::lane_rules_mismatch(ours, theirs);
        check(c.verdict == pb::LaneRulesVerdict::Mismatch && c.id == f.id
                  && c.text.rfind(std::string(pb::kLaneRulesMismatchText) + " field=" + std::string(f.name) + " ours=", 0) == 0
                  && c.text.find(" theirs=") != std::string::npos,
              "LANE_RULES_MISMATCH names " + std::string(f.name) + " with both values");
    }
    // refusals: unknown id, missing id, ids out of order, codec byte 1
    {
        const std::vector<std::uint8_t> t = pb::encode_lane_rules_tlv(base);
        std::vector<std::uint8_t> missing(t.begin() + 10, t.end());  // drop 0x01 (8 + 2 bytes)
        const pb::LaneRulesDecode dm = pb::decode_rules_block(block_of(missing));
        check(dm.error == pb::LaneRulesError::Missing && dm.id == 0x01, "a missing id is refused naming it");
        std::vector<std::uint8_t> swapped;  // 0x02 before 0x01
        swapped.insert(swapped.end(), t.begin() + 10, t.begin() + 20);
        swapped.insert(swapped.end(), t.begin(), t.begin() + 10);
        swapped.insert(swapped.end(), t.begin() + 20, t.end());
        const pb::LaneRulesDecode ds = pb::decode_rules_block(block_of(swapped));
        check(ds.error == pb::LaneRulesError::Order, "ids out of order are refused");
        std::vector<std::uint8_t> unknown = t;
        unknown.push_back(0x1f);
        unknown.push_back(1);
        unknown.push_back(0);
        const pb::LaneRulesDecode du = pb::decode_rules_block(block_of(unknown));
        check(du.error == pb::LaneRulesError::UnknownId && du.id == 0x1f, "an unknown id is refused naming it");
        const pb::LaneRulesDecode dc = pb::decode_rules_block(block_of(t, 1));
        const pb::LaneRulesCompare cc = pb::lane_rules_mismatch(ours, block_of(t, 1));
        check(dc.error == pb::LaneRulesError::Codec && cc.verdict == pb::LaneRulesVerdict::Refused && cc.text.find("K22") != std::string::npos,
              "a codec byte 1 is refused naming K22");
        std::vector<std::uint8_t> wide = t;
        wide[1] = 9;  // 0x01 declared 9 bytes wide
        check(pb::decode_rules_block(block_of(wide)).error != pb::LaneRulesError::None, "a known id with another width is refused");
        std::vector<std::uint8_t> blk = block_of(t);
        blk[1] ^= 1;
        check(pb::decode_rules_block(blk).error != pb::LaneRulesError::None, "a wrong rules_len is refused");
    }
    // peers at another epoch_cur are accepted, their TLVs not compared
    {
        pb::PathbLaneRules other = base;
        other.d_min = 1;
        check(pb::hello_rules_compare(1, ours, 2, pb::rules_block(other)).verdict == pb::LaneRulesVerdict::Equal,
              "peers at another epoch_cur are accepted and not compared");
    }
    // not fields: the 29 retired fields, the pool identity, the policy values
    const char* retired[] = {"d_conf", "settle_h_min", "output_cap", "recon_max_root_age", "book_deferral", "arm_floor",
                             "rotate_on_payment", "decay_horizon", "decay_half_life", "anchor_cut", "merkle_rows",
                             "drops_rule", "drops_window_rw", "kfair_salted_ties", "commit_total", "input_weight",
                             "tail_subsidy", "coinbase_maturity", "fee_version", "residual_sink_id",
                             "pool_rules_version", "owed_demo_amount", "drain_q", "drain_h_cap", "drain_rule_version",
                             "pool_tag_codec", "lane_params_digest", "enrol_digest", "spend_floor"};
    const char* never[] = {"pool_id", "pool_identity", "journal_depth", "pending_cap", "heal_period_h", "vote",
                           "deploy_top", "epoch_cur"};
    bool absent = true;
    for (const pb::LaneRuleField& f : pb::kPathbLaneRuleFields) {
        for (const char* n : retired) absent = absent && f.name != n;
        for (const char* n : never) absent = absent && f.name != n;
    }
    check(absent, "the 29 retired fields, the pool identity, epoch_cur and the Appendix-P policy values are not fields");

    std::printf("v37_xmr_lane_rules_kat (path B): %s: %d checks, %d failures\n", g_fail ? "FAIL" : "PASS", g_checks, g_fail);
    return g_fail;
}

}  // namespace pathb_lane_rules_cases
