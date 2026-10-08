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
//   S3b-3: the Path B tail (rules block | LE128 best_cum_work | best_tip |
//   LE64 best_h | LE64 mmr_leaf_count) golden layout and round trip; bytes after
//   the tail not read; a codec byte 1 refused naming K22; a short
//   tail refused; K09 = 3 -> LANE_RULES_MISMATCH naming 0x09; OVH(16) 88 ->
//   naming 0x18; the unknown id 0x1f (assigned by neither codec 1 nor codec
//   2) refused naming it; K29 missing refused naming 0x1d; ids out of order
//   refused; another epoch_cur not compared; mmr_leaf_count against
//   H(best) - F - b0 + 1; the N-rule / reserve literals 128 / 2676 / 3568 /
//   1248 / 1665 / 42 / 85 / 100 / 720 absent from the code lines of the
//   scanned Path B headers (allowlist: DIFFICULTY_WINDOW, kAltDepth,
//   retarget_growth_den).
// ---------------------------------------------------------------------------
#include <array>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <optional>
#include <set>
#include <span>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include "impl/xmr/pathb/pathb_hello.hpp"
#include "impl/xmr/pathb/pathb_lane_rules.hpp"
#include "pathb_kat_check.hpp"

#ifndef PATHB_SRC_DIR
#error "PATHB_SRC_DIR must name src/impl/xmr/pathb"
#endif

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

// ---------------------------------------------------------------------------
// S3b-3: the Path B tail
// ---------------------------------------------------------------------------
using Entries = std::vector<std::pair<std::uint8_t, std::vector<std::uint8_t>>>;

Entries entries_of(const std::vector<std::uint8_t>& tlv) {
    Entries out;
    for (std::size_t o = 0; o + 2 <= tlv.size();) {
        const std::uint8_t id = tlv[o], n = tlv[o + 1];
        out.emplace_back(id, std::vector<std::uint8_t>(tlv.begin() + o + 2, tlv.begin() + o + 2 + n));
        o += 2 + n;
    }
    return out;
}

std::vector<std::uint8_t> block_of(const Entries& es) {
    std::vector<std::uint8_t> tlv;
    for (const auto& [id, v] : es) {
        tlv.push_back(id);
        tlv.push_back(static_cast<std::uint8_t>(v.size()));
        tlv.insert(tlv.end(), v.begin(), v.end());
    }
    std::vector<std::uint8_t> b{2, static_cast<std::uint8_t>(tlv.size()), static_cast<std::uint8_t>(tlv.size() >> 8)};
    b.insert(b.end(), tlv.begin(), tlv.end());
    return b;
}

constexpr std::uint64_t kB0 = 3500000;

void tail_vectors() {
    const pb::PathbLaneRules r = pb::epoch0_lane_rules(pb::LaneNet::Mainnet);
    ::c2pool::xmr::native::U128 cw{};
    cw.lo = 0x0807060504030201ull;
    cw.hi = 0x100f0e0d0c0b0a09ull;
    const pb::HelloTail t = pb::make_hello_tail(r, cw, seq32(0x40), 3500123, 3);
    const std::vector<std::uint8_t> b = *pb::encode_hello_tail(t);
    check(b.size() == 330 && std::vector<std::uint8_t>(b.begin(), b.begin() + 266) == pb::rules_block(r),
          "tail = the rules block (266 B) | 64 B of state");
    check(b[266] == 0x01 && b[273] == 0x08 && b[274] == 0x09 && b[281] == 0x10 && b[282] == 0x40 && b[313] == 0x5f &&
                  b[314] == 0x5b && b[315] == 0x68 && b[316] == 0x35 && b[322] == 3 && b[329] == 0,
          "tail state: LE128 best_cum_work 266, best_tip 282, LE64 best_h 314, LE64 mmr_leaf_count 322");
    const pb::HelloTailDecode d = pb::decode_hello_tail(b);
    check(d.error == pb::HelloTailError::None && d.tail == t && d.consumed == 330, "tail round trip");

    // bytes after the tail are not read by the tail decoder
    std::vector<std::uint8_t> more = b;
    for (std::uint8_t x = 0; x < 7; ++x) more.push_back(x);
    const pb::HelloTailDecode dm = pb::decode_hello_tail(more);
    check(dm.error == pb::HelloTailError::None && dm.consumed == 330 && dm.tail == t,
          "bytes after the tail: the tail decodes alone and consumes 330 B");

    std::vector<std::uint8_t> c1 = b;
    c1[0] = 1;
    const pb::HelloTailDecode dc = pb::decode_hello_tail(c1);
    check(dc.error == pb::HelloTailError::Codec && dc.id == 22, "tail with codec byte 1 refused naming K22");
    std::vector<std::uint8_t> sh(b.begin(), b.end() - 1);
    check(pb::decode_hello_tail(sh).error == pb::HelloTailError::Truncated &&
                  pb::decode_hello_tail(std::vector<std::uint8_t>(b.begin(), b.begin() + 2)).error ==
                          pb::HelloTailError::Truncated,
          "a tail one byte short, or shorter than the rules block head, refused");
    check(pb::decode_hello_tail(std::span<const std::uint8_t>()).error == pb::HelloTailError::Truncated,
          "an empty tail refused");
    std::vector<std::uint8_t> ln = b;
    ln[1] = static_cast<std::uint8_t>(ln[1] + 1);
    check(pb::decode_hello_tail(ln).error == pb::HelloTailError::Truncated,
          "rules_len one higher: the state fields are short, refused");
    pb::HelloTail bad = t;
    bad.rules[0] = 1;
    pb::HelloTail badlen = t;
    badlen.rules.pop_back();
    check(!pb::encode_hello_tail(bad).has_value() && !pb::encode_hello_tail(badlen).has_value(),
          "the encoder refuses a rules block with codec 1 or a wrong rules_len");

    // comparisons at equal epoch_cur
    const std::vector<std::uint8_t> ours = pb::rules_block(r);
    const auto theirs_of = [&](const pb::PathbLaneRules& x) {
        return pb::decode_hello_tail(*pb::encode_hello_tail(pb::make_hello_tail(x, cw, seq32(0x40), 3500123, 3))).tail.rules;
    };
    pb::PathbLaneRules r9 = r;
    r9.coverage = 3;
    const pb::LaneRulesCompare c9 = pb::hello_rules_compare(0, ours, 0, theirs_of(r9));
    check(c9.verdict == pb::LaneRulesVerdict::Mismatch && c9.id == 0x09 &&
                  c9.text == "LANE_RULES_MISMATCH field=coverage ours=02 theirs=03",
          "K09 = 3 -> LANE_RULES_MISMATCH naming 0x09 with both values");
    pb::PathbLaneRules r24 = r;
    r24.ovh_hf16 = 88;
    const pb::LaneRulesCompare c24 = pb::hello_rules_compare(0, ours, 0, theirs_of(r24));
    check(c24.verdict == pb::LaneRulesVerdict::Mismatch && c24.id == 0x18 &&
                  c24.text.find("field=ovh_out ours=59003d0022005400 theirs=58003d0022005400") != std::string::npos,
          "K24 OVH(16) 88 -> LANE_RULES_MISMATCH naming 0x18 with both values");

    const Entries es = entries_of(pb::encode_lane_rules_tlv(r));
    // 0x1f: no K row, not an id of codec 1 (1..29), not K30 (0x1e)
    Entries unk = es;
    unk.emplace_back(0x1f, std::vector<std::uint8_t>{1});
    const pb::LaneRulesCompare cu = pb::hello_rules_compare(0, ours, 0, block_of(unk));
    check(pb::lane_rule_field(0x1f) == nullptr && pb::lane_rule_field(0x1e) != nullptr &&
                  cu.verdict == pb::LaneRulesVerdict::Refused && cu.id == 0x1f && cu.text.find("field=id31") != std::string::npos,
          "the unknown id 0x1f refused naming it");
    Entries miss;
    for (const auto& e : es)
        if (e.first != 0x1d) miss.push_back(e);
    const pb::LaneRulesCompare cm = pb::hello_rules_compare(0, ours, 0, block_of(miss));
    check(cm.verdict == pb::LaneRulesVerdict::Refused && cm.id == 0x1d && cm.text.find("field=split_rule_version") != std::string::npos,
          "K29 missing refused naming 0x1d");
    Entries swp = es;
    std::swap(swp[8], swp[9]);  // 0x0a before 0x09
    const pb::LaneRulesCompare co = pb::hello_rules_compare(0, ours, 0, block_of(swp));
    check(swp[8].first == 0x0a && co.verdict == pb::LaneRulesVerdict::Refused &&
                  pb::decode_rules_block(block_of(swp)).error == pb::LaneRulesError::Order,
          "ids out of order refused");
    check(pb::hello_rules_compare(0, ours, 0, block_of(es)).verdict == pb::LaneRulesVerdict::Equal &&
                  pb::hello_rules_compare(0, ours, 1, block_of(unk)).verdict == pb::LaneRulesVerdict::Equal,
          "equal rules are Equal; a peer at another epoch_cur is not compared (its unknown id included)");

    // mmr_leaf_count against the best tip's header
    const std::uint64_t F = pb::kRuledLaneParams.open_bins;
    check(pb::hello_leaf_count_check(t, kB0 + 98, kB0, F) == pb::HelloLeafCount::Equal,
          "mmr_leaf_count 3 at H(best) = b0 + 98: equal");
    pb::HelloTail t4 = t;
    t4.mmr_leaf_count = 4;
    pb::HelloTail t0 = t;
    t0.mmr_leaf_count = 0;
    check(pb::hello_leaf_count_check(t4, kB0 + 98, kB0, F) == pb::HelloLeafCount::Mismatch &&
                  pb::hello_leaf_count_check(t4, std::nullopt, kB0, F) == pb::HelloLeafCount::Pending &&
                  pb::hello_leaf_count_check(t0, kB0 + 95, kB0, F) == pb::HelloLeafCount::Equal &&
                  pb::hello_leaf_count_check(t, kB0 + 95, kB0, F) == pb::HelloLeafCount::Mismatch,
          "mmr_leaf_count 4 at b0 + 98: mismatch; best tip not held: pending; b0 + 95: 0");
}

// ---------------------------------------------------------------------------
// The forbidden literals (S3.4): decimal integer literals in code lines
// (comments and string / character literals removed).
// ---------------------------------------------------------------------------
std::string code_only(const std::string& text) {
    std::string out;
    enum { Code, Str, Chr } st = Code;
    for (std::size_t i = 0; i < text.size(); ++i) {
        const char c = text[i];
        if (st == Code) {
            if (c == '/' && i + 1 < text.size() && text[i + 1] == '/') {
                while (i < text.size() && text[i] != '\n') ++i;
                out.push_back('\n');
            } else if (c == '/' && i + 1 < text.size() && text[i + 1] == '*') {
                i += 2;
                while (i + 1 < text.size() && !(text[i] == '*' && text[i + 1] == '/')) {
                    if (text[i] == '\n') out.push_back('\n');
                    ++i;
                }
                ++i;
                out.push_back(' ');
            } else if (c == '"') {
                st = Str;
                out.push_back(' ');
            } else if (c == '\'' && !(i > 0 && std::isalnum(static_cast<unsigned char>(text[i - 1])))) {
                st = Chr;
                out.push_back(' ');
            } else {
                out.push_back(c);
            }
        } else {
            if (c == '\\') {
                ++i;
            } else if ((st == Str && c == '"') || (st == Chr && c == '\'')) {
                st = Code;
            } else if (c == '\n') {
                out.push_back('\n');
            }
        }
    }
    return out;
}

void forbidden_literals() {
    const std::set<std::uint64_t> forbidden{128, 2676, 3568, 1248, 1665, 42, 85, 100, 720};
    const std::vector<std::string> files{"pathb_params.hpp",    "pathb_caps.hpp",      "pathb_emission.hpp",
                                         "pathb_window.hpp",    "pathb_bin_store.hpp", "pathb_miner_tx.hpp",
                                         "pathb_bucket_wire.hpp", "pathb_hello.hpp"};
    // (file, raw line text): the named constants of record
    const std::vector<std::pair<std::string, std::string>> allow{
            {"pathb_params.hpp", "DIFFICULTY_WINDOW = 720;"},
            {"pathb_caps.hpp", "kAltDepth = 720;"},
            {"pathb_params.hpp", "/*retarget_growth_den=*/100,"},
    };
    check(allow.size() == 3, "the allowlist holds 3 named constants");
    std::vector<int> allow_hits(allow.size(), 0);
    std::vector<std::string> hits;
    std::size_t scanned = 0;
    for (const std::string& name : files) {
        std::ifstream in(std::filesystem::path(PATHB_SRC_DIR) / name);
        std::stringstream ss;
        ss << in.rdbuf();
        const std::string raw = ss.str();
        if (raw.empty()) continue;
        ++scanned;
        std::vector<std::string> raw_lines, code_lines;
        {
            std::istringstream a(raw), b(code_only(raw));
            for (std::string l; std::getline(a, l);) raw_lines.push_back(l);
            for (std::string l; std::getline(b, l);) code_lines.push_back(l);
        }
        for (std::size_t ln = 0; ln < code_lines.size(); ++ln) {
            const std::string& l = code_lines[ln];
            for (std::size_t i = 0; i < l.size();) {
                const unsigned char ch = static_cast<unsigned char>(l[i]);
                if (!(std::isalnum(ch) || ch == '_' || ch == '.' || ch == '\'')) {
                    ++i;
                    continue;
                }
                std::size_t j = i;
                while (j < l.size() && (std::isalnum(static_cast<unsigned char>(l[j])) || l[j] == '_' || l[j] == '.' || l[j] == '\''))
                    ++j;
                std::string tok = l.substr(i, j - i);
                i = j;
                if (!std::isdigit(static_cast<unsigned char>(tok[0]))) continue;
                if (tok.size() > 1 && tok[0] == '0' && (tok[1] == 'x' || tok[1] == 'X' || tok[1] == 'b' || tok[1] == 'B'))
                    continue;
                std::string digits;
                for (char c : tok)
                    if (c != '\'') digits.push_back(c);
                while (!digits.empty() && (digits.back() == 'u' || digits.back() == 'U' || digits.back() == 'l' ||
                                           digits.back() == 'L'))
                    digits.pop_back();
                if (digits.empty() || digits.size() > 18 ||
                    digits.find_first_not_of("0123456789") != std::string::npos)
                    continue;
                if (forbidden.count(std::stoull(digits)) == 0) continue;
                const std::string& rl = ln < raw_lines.size() ? raw_lines[ln] : l;
                bool allowed = false;
                for (std::size_t k = 0; k < allow.size(); ++k)
                    if (allow[k].first == name && rl.find(allow[k].second) != std::string::npos) {
                        ++allow_hits[k];
                        allowed = true;
                    }
                if (!allowed) hits.push_back(name + ":" + std::to_string(ln + 1) + ": " + tok);
            }
        }
    }
    for (const std::string& h : hits) std::printf("  forbidden literal: %s\n", h.c_str());
    check(scanned == files.size(), "the 8 Path B headers were scanned (" + std::to_string(scanned) + ")");
    check(hits.empty(), "no forbidden N-rule / reserve literal in a code line");
    check(allow_hits == std::vector<int>{1, 1, 1}, "each allowlisted constant is hit exactly once");
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

    tail_vectors();
    forbidden_literals();
    return finish("v37_xmr_pathb_hello_kat");
}
