// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// v37_xmr_lane_rules_kat -- LANE-RULES (operator ruling R3, 2026-10-02: the
// pool id covers every consensus-relevant lane parameter BEFORE the drain rule
// may activate). A node with other lane rules must be refused at HELLO by name
// and must not recognise the other's lane blocks as its own.
//
//   A  codec: TLV golden bytes + rules_digest golden for a literal list, the
//      field table (31 ids, ascending, names), round trip, strict decode
//      (width, order, missing, truncated), an unknown id is kept and named;
//      the daemon's builder (lane_rules_of) maps every config knob to its field
//   B  one refusal per parameter: two HELLOs equal except field i (every i in
//      1..31) -> hello_mismatch starts "LANE_RULES_MISMATCH field=<name_i>
//      ours=<v> theirs=<v>", both directions; three fields -> "+2 more" names
//      the other two
//   C  equal lists -> compatible and byte-identical HELLO frames; the frame
//      round-trips; the 102/142/174(/206) legacy lengths still decode with
//      rules = none; a wrong rules_len is refused
//   D  migration: a peer without the list -> field=rules_absent, and the
//      symmetric case
//   E  property (K8): 10,000 random perturbations of 1-3 fields of a list:
//      hello_mismatch == "" <=> equal pool_tag; the digest of the list read
//      back from the HELLO frame is the digest the pool_tag folds; drain_q
//      0 vs 16 alone flips both
//
// RE-PIN (RULES RATCHET R1, receipt admission, operator ruling 2026-10-03):
// field 30 empty_cut (u8) joins the list: 29 -> 30 fields, the literal TLV
// 278 -> 281 bytes (+ "1e 01 01"), a new rules_digest golden, the HELLO with
// the list 521 -> 524 bytes, and the "newer build" unknown id is now 31.
//
// RE-PIN (G9 review O6, the epoch-1 rule set of R1): field 31 noncanon_net
// (u8) joins the list: 30 -> 31 fields, the literal TLV 281 -> 284 bytes
// (+ "1f 01 01"), a new rules_digest golden, the HELLO with the list 524 ->
// 527 bytes, the "newer build" unknown id is now 32, and two nodes that
// differ only in it refuse each other as LANE_RULES_MISMATCH
// field=noncanon_net. Built on a tree without the field this file compiles
// (the field is set through the X-macro table) and A / B / C FAIL.
//
// Red on master: the header, the HELLO list and the pool_tag fold do not
// exist (the KAT does not compile); with the list carried but not compared /
// not folded, B, D and E fail (every refusal is "").
#include <cstdlib>
#include <string>

#include "xmr_relay_test_util.hpp"
#include <c2pool/v37/xmr/xmr_lane_rules.hpp>
#include <c2pool/v37/xmr/xmr_lane_rules_build.hpp>
#include <c2pool/v37/xmr/xmr_pool_tag.hpp>

using namespace gap2test;
namespace lr      = c2pool::v37n::xmr::lanerules;
namespace lineage = c2pool::v37n::xmr::lineage;

static bool g_print = false;
static std::string hx(const std::vector<u8>& v) {
    static const char* d = "0123456789abcdef";
    std::string s;
    for (u8 b : v) { s.push_back(d[b >> 4]); s.push_back(d[b & 15]); }
    return s;
}
static std::string hx(const bytes32& b) { return hx(std::vector<u8>(b.begin(), b.end())); }
static void golden(Checker& C, const std::string& name, const std::string& got, const char* want) {
    if (g_print || !*want) std::printf("    GOLDEN %s = \"%s\"\n", name.c_str(), got.c_str());
    C(got == want, name + " golden");
}

// Field i of a list, moved to another value (numbers +1, flags flipped, b32 byte 0 flipped).
template <class T> static void bump_value(T& v) {
    if constexpr (std::is_same_v<T, bytes32>) v[0] ^= 0x5a;
    else if constexpr (std::is_same_v<T, std::uint8_t>) v = static_cast<T>(v ^ 1);
    else v = static_cast<T>(v + 1);
}
// ... or to a random value (the property suite).
template <class T> static void random_value(T& v, std::uint64_t& s) {
    auto next = [&s] { s ^= s << 13; s ^= s >> 7; s ^= s << 17; return s; };
    if constexpr (std::is_same_v<T, bytes32>) { for (auto& b : v) b = static_cast<u8>(next()); if (next() & 1) v[0] ^= 1; }
    else if constexpr (std::is_same_v<T, std::uint8_t>) v = static_cast<T>(next() & 1);   // flags: 0/1, often unchanged
    else v = static_cast<T>((next() & 3) == 0 ? v : next() % 1000);                       // sometimes unchanged
}
static void bump(lr::LaneRules& r, u8 id) {
    switch (id) {
#define KAT_BUMP(fid, name, T) case fid: bump_value<T>(r.name); break;
        C2POOL_XMR_LANE_RULES_FIELDS(KAT_BUMP)
#undef KAT_BUMP
    default: break;
    }
}
static void randomize(lr::LaneRules& r, u8 id, std::uint64_t& s) {
    switch (id) {
#define KAT_RAND(fid, name, T) case fid: random_value<T>(r.name, s); break;
        C2POOL_XMR_LANE_RULES_FIELDS(KAT_RAND)
#undef KAT_RAND
    default: break;
    }
}

// A literal list: the stagenet daemon defaults (D_conf 60, cap ceiling 2700,
// root age 240, deferral on, arm floor 12,530,000, decay 8640/2160, anchor +
// Merkle rows, DROPS due + raindrop enrol + window (rule 7, rw 1), salted ties,
// commit_total, spend floor, kInputWeight 659, kTailSubsidy, maturity 60, fee
// OFF, pool rules v4, codec V37P.1, EMPTY-CUT, noncanon_net) with fixed digests.
// Pins the codec only.
static lr::LaneRules literal_rules() {
    lr::LaneRules r;
    r.d_conf = 60; r.settle_h_min = 0; r.output_cap = 2700; r.recon_max_root_age = 240; r.book_deferral = 1;
    r.arm_floor = 12530000; r.rotate_on_payment = 1; r.decay_horizon = 8640; r.decay_half_life = 2160;
    r.anchor_cut = 1; r.merkle_rows = 1; r.drops_rule = 7; r.drops_window_rw = 1; r.kfair_salted_ties = 1;
    r.commit_total = 1; r.input_weight = 659; r.tail_subsidy = 600000000000ull; r.coinbase_maturity = 60;
    r.fee_version = 0; r.residual_sink_id = b32_of(0x51); r.pool_rules_version = 4; r.owed_demo_amount = 0;
    r.drain_q = 0; r.drain_h_cap = 0; r.drain_rule_version = 0; r.pool_tag_codec = 1;
    r.lane_params_digest = b32_of(0x27); r.enrol_digest = b32_of(0x28); r.spend_floor = 1;
    r.empty_cut = 1;   // R1 RECEIPT ADMISSION
    bump(r, 31);       // G9 O6: noncanon_net 0 -> 1 (through the field table: a no-op where id 31 is unknown)
    return r;
}

static Hello hello_with(const std::optional<lr::LaneRules>& r, u64 nonce) {
    Hello h;
    h.network = 2; h.chain_id = 0; h.share_diff = 1000; h.node_nonce = nonce; h.listen_port = 53111;
    h.pool = pool_id_of(0, ::v37::LaneParams{}); h.pool->genesis = b32_of(0x6e);
    h.lane_params_digest = r ? r->lane_params_digest : b32_of(0x27);
    h.rules = r;
    return h;
}

static void suite_codec(Checker& C) {
    std::printf("-- A codec: the TLV list, its digest, strict decode, the builder\n");
    C(lr::kFieldCount == 31, "A the v1 list has 31 fields (" + std::to_string(lr::kFieldCount) + ")");
    bool asc = true, named = true;
    for (std::size_t i = 0; i < lr::kFieldCount; ++i) {
        if (lr::kFields[i].id != i + 1) asc = false;
        if (!lr::field_name(lr::kFields[i].id) || std::string(lr::field_name(lr::kFields[i].id)) != lr::kFields[i].name) named = false;
    }
    C(asc && named, "A ids are 1..31 in table order, every id has its name");
    auto name_of = [](u8 id) { const char* n = lr::field_name(id); return std::string(n ? n : "(unknown)"); };
    C(std::string(lr::field_name(1)) == "d_conf" && std::string(lr::field_name(23)) == "drain_q" &&
      std::string(lr::field_name(27)) == "lane_params_digest" && std::string(lr::field_name(29)) == "spend_floor" &&
      std::string(lr::field_name(30)) == "empty_cut" && name_of(31) == "noncanon_net",
      "A pinned names: 1 d_conf, 23 drain_q, 27 lane_params_digest, 29 spend_floor, 30 empty_cut, 31 noncanon_net (" + name_of(31) + ")");
    const lr::LaneRules r = literal_rules();
    const auto t = lr::encode_tlv(r);
    C(t.size() == 284, "A the v1 list is 284 bytes (62 B of id|len + 222 B of values): " + std::to_string(t.size()));
    golden(C, "A literal TLV", hx(t),
           "01083c000000000000000208000000000000000003048c0a00000408f00000000000000005010106085031bf00000000000701010808c021000000000000090870080000000000000a01010b01010c04070000000d0801000000000000000e01010f01011008930200000000000011080070c9b28b00000012083c000000000000001304000000001420d0d7dee5ecf3fa01080f161d242b323940474e555c636a71787f868d949ba2a9150404000000160800000000000000001704000000001804000000001904000000001a01011b20bac1c8cfd6dde4ebf2f900070e151c232a31383f464d545b626970777e858c931c20d9e0e7eef5fc030a11181f262d343b424950575e656c737a81888f969da4abb21d01011e01011f0101");
    golden(C, "A literal rules_digest", hx(lr::rules_digest(r)), "2d2cb1d4aa82baa5b1ebde5be179aec70316d619e3f9f34ecb67bc4336dd3447");
    lr::LaneRules back; std::string why;
    C(lr::decode_tlv(t, back, &why) && back == r && lr::encode_tlv(back) == t, "A round trip (decode . encode = id, re-encode byte-identical)");
    C(t[0] == 1 && t[1] == 8 && t[2] == 60, "A entry 1 = d_conf, 8 bytes, little-endian 60");
    // strict decode
    auto refuse = [&](std::vector<u8> x, const std::string& what, const std::string& needle) {
        lr::LaneRules o; std::string w;
        const bool ok = lr::decode_tlv(x, o, &w);
        C(!ok && w.find(needle) != std::string::npos, "A " + what + " -> refused (" + w + ")");
    };
    { auto x = t; x[1] = 7; refuse(x, "d_conf with width 7", "width"); }
    { auto x = t; x.pop_back(); refuse(x, "a truncated last value", "runs past"); }
    { auto x = t; x.push_back(32); refuse(x, "a dangling entry header", "truncated"); }
    { auto x = t; x[0] = 2; refuse(x, "ids out of order (2 then 2)", "ascending"); }
    { auto x = t; x[0] = 0; refuse(x, "id 0", "ascending"); }
    { std::vector<u8> x(t.begin() + 10, t.end()); refuse(x, "d_conf missing", "d_conf missing"); }
    // an unknown id (a newer build's field 32) is kept, re-encoded and named
    {
        auto x = t; x.push_back(32); x.push_back(2); x.push_back(0xAB); x.push_back(0xCD);
        lr::LaneRules nr; std::string w;
        const bool ok = lr::decode_tlv(x, nr, &w);
        C(ok && nr.unknown.size() == 1 && nr.unknown[0].first == 32 && lr::encode_tlv(nr) == x,
          "A an unknown id 32 is kept and re-encoded byte-identical");
        const std::string m = lr::lane_rules_mismatch(r, nr);
        std::printf("    %s\n", m.c_str());
        C(lr::is_lane_rules_mismatch(m) && m.find("field=rules_unknown_id 32") != std::string::npos && m.find("newer build") != std::string::npos,
          "A a peer with an unknown field: LANE_RULES_MISMATCH field=rules_unknown_id 32 (a newer build)");
        C(lr::rules_digest(nr) != lr::rules_digest(r), "A the unknown field moves the digest (and the pool_tag)");
    }
    // the daemon's builder: every knob lands in its field
    {
        c2pool::v37n::xmr::XmrNodeConfig c;
        c.network = c2pool::v37n::xmr::MoneroNetwork::Stagenet;
        lr::LaneRulesInputs in;
        in.lane_params_digest = b32_of(0x27);
        const lr::LaneRules d = lr::lane_rules_of(c, in);
        C(d.d_conf == 60 && d.output_cap == 2700 && d.recon_max_root_age == 240 && d.book_deferral == 1 && d.drain_q == 0 &&
          d.input_weight == 659 && d.coinbase_maturity == 60 && d.pool_tag_codec == 2 &&   // RULES RATCHET: the V37P v2 codec
          d.pool_rules_version == c2pool::v37n::xmr::relay::kXmrPoolRulesVersion && d.lane_params_digest == b32_of(0x27),
          "A builder: default stagenet config -> d_conf 60, cap 2700, root age 240, deferral on, drain 0, constants");
        auto moved = [&](auto edit, const char* field) {
            c2pool::v37n::xmr::XmrNodeConfig k = c; lr::LaneRulesInputs ki = in;
            edit(k, ki);
            const auto dd = lr::diff_fields(d, lr::lane_rules_of(k, ki));
            C(dd.size() >= 1 && std::string(dd[0].name) == field, std::string("A builder: the knob moves field ") + field);
        };
        moved([](auto& k, auto&) { k.d_conf = 61; }, "d_conf");
        moved([](auto& k, auto&) { k.settle_h_min = 5; }, "settle_h_min");
        moved([](auto& k, auto&) { k.settle_output_cap = 16; }, "output_cap");
        moved([](auto&, auto& i) { i.recon_max_root_age = 7; }, "recon_max_root_age");
        moved([](auto&, auto& i) { i.book_deferral = false; }, "book_deferral");
        moved([](auto& k, auto&) { k.ledger_arm_floor = 1; }, "arm_floor");
        moved([](auto& k, auto&) { k.ledger_decay_half_life = 1; }, "decay_half_life");
        moved([](auto& k, auto&) { k.ledger_drops_due = !k.ledger_drops_due; }, "drops_rule");
        moved([](auto&, auto& i) { i.kfair_salted_ties = false; }, "kfair_salted_ties");
        moved([](auto&, auto& i) { i.residual_sink_id = b32_of(9); }, "residual_sink_id");
        moved([](auto& k, auto&) { k.owed_demo_amount = 1; }, "owed_demo_amount");
        moved([](auto& k, auto&) { k.drain_q = 16; }, "drain_q");
        moved([](auto& k, auto&) { k.drain_h_cap = 64; }, "drain_h_cap");                 // THE DRAIN RULE (B16)
        moved([](auto& k, auto&) { k.drain_rule_version = 1; }, "drain_rule_version");
        moved([](auto&, auto& i) { i.enrol_digest = b32_of(3); }, "enrol_digest");
        moved([](auto&, auto& i) { i.spend_floor = false; }, "spend_floor");
        moved([](auto& k, auto&) {   // G9 O6 (a generic lambda: compiles where the knob is absent, and then moves nothing)
            if constexpr (requires { k.ledger_noncanon_net; }) k.ledger_noncanon_net = !k.ledger_noncanon_net;
        }, "noncanon_net");
        c2pool::v37n::xmr::XmrNodeConfig f = c; f.lane_params.fee = ::v37::FeeModelGate::for_version(1);
        const lr::LaneRules df = lr::lane_rules_of(f, in);
        C(df.fee_version == 1 && df.residual_sink_id == c2pool::v37n::xmr::fee::donation_identity(c2pool::v37n::xmr::fee::DonationNet::Stagenet),
          "A builder: fee model v1 -> fee_version 1, the sink field is the network's donation identity");
    }
}

static void suite_refusal(Checker& C) {
    std::printf("-- B one refusal per parameter (every field 1..31, both directions)\n");
    const lr::LaneRules base = literal_rules();
    const Hello ours = hello_with(base, 1);
    int named = 0, both = 0;
    for (const auto& f : lr::kFields) {
        lr::LaneRules t = base;
        bump(t, f.id);
        Hello theirs = hello_with(t, 2);
        theirs.lane_params_digest = base.lane_params_digest;   // the HELLO's own digest stays equal: only the list differs
        const std::string m = hello_mismatch(ours, theirs), mr = hello_mismatch(theirs, ours);
        const auto d = lr::diff_fields(base, t);
        const std::string want = std::string(lr::kLaneRulesMismatch) + " field=" + f.name + " ours=" + (d.empty() ? "" : d[0].ours) +
                                 " theirs=" + (d.empty() ? "" : d[0].theirs);
        const bool ok = d.size() == 1 && m.rfind(want, 0) == 0;
        const bool okr = d.size() == 1 && mr.rfind(std::string(lr::kLaneRulesMismatch) + " field=" + f.name + " ours=" + d[0].theirs +
                                                   " theirs=" + d[0].ours, 0) == 0;
        if (ok) ++named;
        if (ok && okr) ++both;
        if (!ok || !okr || f.id == 1 || f.id == 23 || f.id == 27)
            std::printf("    field %2u %-19s -> \"%s\"\n", unsigned(f.id), f.name, m.substr(0, 110).c_str());
        if (!ok) C(false, std::string("B field ") + f.name + " is refused by name with both values");
    }
    C(named == 31, "B all 31 fields are refused BY NAME with both values (" + std::to_string(named) + "/31)");
    C(both == 31, "B ... in both directions, values swapped (" + std::to_string(both) + "/31)");
    {   // G9 O6: a node without the net booking and one with it are two pools, refused by name
        lr::LaneRules t31 = base;
        bump(t31, 31);
        const std::string m31 = hello_mismatch(ours, hello_with(t31, 6));
        std::printf("    %s\n", m31.substr(0, 110).c_str());
        C(m31.rfind("LANE_RULES_MISMATCH field=noncanon_net ours=1 theirs=0", 0) == 0,
          "B noncanon_net 1 vs 0: LANE_RULES_MISMATCH field=noncanon_net ours=1 theirs=0 (mixed nodes refuse each other at HELLO)");
        C(lr::to_text(base).find(" noncanon_net=1") != std::string::npos, "B to_text prints noncanon_net=1 (the lane-rules: startup line)");
        C(!(lr::rules_digest(t31) == lr::rules_digest(base)), "B noncanon_net moves the rules_digest (the epoch-1 Deployment)");
    }
    // three fields at once: the first is named in full, the other two in the tail
    lr::LaneRules t3 = base; t3.d_conf = 61; t3.output_cap = 16; t3.drain_q = 16;
    const std::string m3 = hello_mismatch(ours, hello_with(t3, 3));
    std::printf("    %s\n", m3.c_str());
    C(m3.rfind("LANE_RULES_MISMATCH field=d_conf ours=60 theirs=61 (+2 more: output_cap 2700/16, drain_q 0/16)", 0) == 0 &&
      m3.find("ANOTHER pool") != std::string::npos,
      "B three fields: field=d_conf ours=60 theirs=61 (+2 more: output_cap 2700/16, drain_q 0/16) + the reason");
    // the LaneParams digest differing (with the HELLO's own digest) keeps its specific text
    lr::LaneRules tl = base; tl.lane_params_digest = b32_of(0x99);
    const std::string ml = hello_mismatch(ours, hello_with(tl, 4));
    C(ml.find("lane_params_digest differs") != std::string::npos && !lr::is_lane_rules_mismatch(ml),
      "B a LaneParams difference still gets the specific HELLO text (" + ml.substr(0, 40) + ")");
    lr::LaneRules tb = base; tb.lane_params_digest = b32_of(0x99); tb.d_conf = 59;
    const std::string mb = hello_mismatch(ours, hello_with(tb, 5));
    C(mb.rfind("LANE_RULES_MISMATCH field=d_conf ours=60 theirs=59 (+1 more: lane_params_digest", 0) == 0,
      "B d_conf AND the LaneParams digest: the rules refusal names d_conf first, the digest in the tail");
}

static void suite_frames(Checker& C) {
    std::printf("-- C equal lists interoperate; the frame; D migration (rules_absent)\n");
    const lr::LaneRules r = literal_rules();
    const Hello a = hello_with(r, 7), b = hello_with(literal_rules(), 8);
    C(hello_mismatch(a, b).empty() && hello_mismatch(b, a).empty(), "C equal lists (built twice), other nonce -> compatible");
    Hello a2 = a; a2.node_nonce = 8;
    C(encode_hello(a2) == encode_hello(b), "C equal lists -> byte-identical HELLO frames");
    const auto f = encode_hello(a);
    C(f.size() == kHelloBytesPoolGenesis + 1 + 2 + 284 + 66, "C HELLO with the list = 174 + flag 1 + len 2 + 284 + epoch trailer 66 = 527 B (" +
                                                            std::to_string(f.size()) + ")");
    Hello back; std::string why;
    Hello a_rx = a; a_rx.epochs = hello_epochs_of(a);   // the decoder fills the epoch list it read
    C(decode_hello(f, back, &why) && back == a_rx && back.rules && *back.rules == r && back.epochs.size() == 1 && back.epoch_cur == 1,
      "C the 527-byte HELLO round-trips (list + the one-entry epoch trailer kept)");
    C(lr::rules_digest(*back.rules) == lr::rules_digest(r), "C the digest of the list read back == the sender's digest");
    Hello legacy = a; legacy.rules.reset();
    const auto f174 = encode_hello(legacy);
    Hello lb;
    C(f174.size() == kHelloBytesPoolGenesis && decode_hello(f174, lb, &why) && !lb.rules, "C a 174-byte HELLO still decodes (rules = none)");
    Hello l142 = legacy; l142.pool->genesis.reset();
    Hello l102 = legacy; l102.pool.reset();
    Hello b142, b102;
    C(decode_hello(encode_hello(l142), b142, &why) && !b142.rules && decode_hello(encode_hello(l102), b102, &why) && !b102.rules,
      "C the 142- and 102-byte HELLOs still decode (rules = none)");
    Hello nogen = a; nogen.pool->genesis.reset();
    C(encode_hello(nogen).size() == kHelloBytesPoolId, "C no genesis -> no list on the wire (142 B)");
    auto bad_len = f; bad_len[kHelloBytesPoolGenesis + 1] ^= 0x80;   // rules_len low byte (284 = 0x11c; ^ 0x80 = 412 runs past the frame)
    C(!decode_hello(bad_len, back, &why) && why == "hello: rules length mismatch", "C a wrong rules_len -> \"" + why + "\"");
    auto bad_flag = f; bad_flag[kHelloBytesPoolGenesis] = 2;
    C(!decode_hello(bad_flag, back, &why), "C an unknown enrol flag -> refused (" + why + ")");
    auto bad_tlv = f; bad_tlv[kHelloBytesPoolGenesis + 3 + 1] = 7;   // d_conf width 7
    C(!decode_hello(bad_tlv, back, &why) && why.find("rules:") != std::string::npos, "C a malformed list -> refused (" + why + ")");
    Hello inc = a; inc.lane_params_digest = b32_of(0x13);
    C(!decode_hello(encode_hello(inc), back, &why) && why.find("inconsistent") != std::string::npos,
      "C a list whose lane_params_digest is not the HELLO's own -> refused (" + why + ")");
    if (kHelloEnrolSetLive) {
        Hello e = a; e.enrol_set = b32_of(0x28);
        const auto fe = encode_hello(e);
        Hello be;
        Hello e_rx = e; e_rx.epochs = hello_epochs_of(e);
        C(fe.size() == f.size() + 32 && decode_hello(fe, be, &why) && be == e_rx, "C with the enrol slot: +32 B, round trip (flag 1)");
    }
    // D migration
    const std::string m = hello_mismatch(a, legacy), mr = hello_mismatch(legacy, a);
    std::printf("    %s\n", m.substr(0, 120).c_str());
    C(m.rfind("LANE_RULES_MISMATCH field=rules_absent", 0) == 0 && m.find("pre-LANE-RULES") != std::string::npos,
      "D a peer without the list (a pre-LANE-RULES build) -> LANE_RULES_MISMATCH field=rules_absent");
    C(mr.rfind("LANE_RULES_MISMATCH field=rules_absent", 0) == 0, "D symmetric: our side without it, the peer with it -> rules_absent");
    Hello l2 = legacy; l2.node_nonce = 99;
    C(hello_mismatch(legacy, l2).empty(), "D two list-less ends compare exactly as before (compatible)");
}

static void suite_property(Checker& C) {
    std::printf("-- E property: HELLO-compatible <=> the same rules_digest, the epoch-1 Deployment's (10,000 random perturbations of 1-3 fields)\n");
    const lr::LaneRules base = literal_rules();
    auto tag_of = [&](const lr::LaneRules& r) { return lr::rules_digest(r); };   // RULES RATCHET: the digest HELLO's Deployment carries
    const bytes32 base_tag = tag_of(base);
    const Hello ours = hello_with(base, 1);
    std::uint64_t s = 0x9e3779b97f4a7c15ull;
    auto next = [&s] { s ^= s << 13; s ^= s >> 7; s ^= s << 17; return s; };
    int n = 0, iff_ok = 0, readback_ok = 0, equal_cases = 0, refused_cases = 0;
    for (int i = 0; i < 10000; ++i) {
        lr::LaneRules t = base;
        const int k = 1 + static_cast<int>(next() % 3);
        for (int j = 0; j < k; ++j) randomize(t, static_cast<u8>(1 + next() % lr::kFieldCount), s);
        Hello theirs = hello_with(t, 2);   // the HELLO's own lane_params_digest follows its list (a consistent peer)
        const auto frame = encode_hello(theirs);
        Hello rx; std::string why;
        const bool dec = decode_hello(frame, rx, &why);
        const bool compatible = dec && hello_mismatch(ours, rx).empty();
        const bool same_tag = tag_of(t) == base_tag;
        ++n;
        if (compatible == same_tag) ++iff_ok;
        else std::printf("    counterexample %d: compatible=%d same_digest=%d (%s)\n", i, compatible, same_tag, hello_mismatch(ours, rx).c_str());
        if (dec && rx.rules && lr::rules_digest(*rx.rules) == lr::rules_digest(t)) ++readback_ok;
        if (same_tag) ++equal_cases; else ++refused_cases;
    }
    std::printf("    %d cases: %d unchanged lists, %d changed; iff held %d, read-back digest held %d\n", n, equal_cases,
                refused_cases, iff_ok, readback_ok);
    C(iff_ok == n, "E hello_mismatch == \"\" <=> equal rules_digest (the epoch-1 Deployment) on every case (" + std::to_string(iff_ok) + "/" + std::to_string(n) + ")");
    C(readback_ok == n, "E the list read back from the HELLO frame has the digest its Deployment carries (" + std::to_string(readback_ok) + ")");
    C(equal_cases > 100 && refused_cases > 5000, "E both sides of the iff are exercised");
    lr::LaneRules q = base; q.drain_q = 16;
    const std::string mq = hello_mismatch(ours, hello_with(q, 3));
    C(mq.rfind("LANE_RULES_MISMATCH field=drain_q ours=0 theirs=16", 0) == 0 && tag_of(q) != base_tag,
      "E drain_q 0 vs 16 alone flips both: the HELLO refusal (" + mq.substr(0, 52) + ") and the rules_digest");
    // B16: THE DRAIN RULE's flag day, {1,16,64} against master's {0,0,0}: one refusal naming all three, another rules_digest
    lr::LaneRules on = base; on.drain_q = 16; on.drain_h_cap = 64; on.drain_rule_version = 1;
    const std::string m16 = hello_mismatch(hello_with(on, 4), hello_with(base, 5));
    std::printf("    %s\n", m16.c_str());
    C(m16.rfind("LANE_RULES_MISMATCH field=drain_q ours=16 theirs=0 (+2 more: drain_h_cap 64/0, drain_rule_version 1/0)", 0) == 0 &&
      tag_of(on) != base_tag && tag_of(on) != tag_of(q),
      "E drain {1,16,64} vs {0,0,0}: field=drain_q ours=16 theirs=0 (+2 more: drain_h_cap 64/0, drain_rule_version 1/0), another rules_digest");
}

// RULES RATCHET R1 (spec sec. 7, C16): R-MIN -- what no epoch may change.
static void suite_rmin(Checker& C) {
    std::printf("-- F R-MIN: constitutional_check on mainnet (a, b) and the drain floor wherever a drain exists (c)\n");
    const bytes32 sink = b32_of(0x51);   // the "mainnet donation identity" of this rig
    lr::LaneRules m = literal_rules();   // settle_h_min 0, owed_demo_amount 0, residual_sink_id = sink, drain 0/0/0
    m.drain_q = 16; m.drain_h_cap = 64; m.drain_rule_version = 1;
    C(lr::constitutional_check(0, m, &sink).empty(), "F mainnet rules at the floor (h_min 0, demo 0, the fixed sink, drain 16/64/1): constitutional");
    { lr::LaneRules t = m; t.settle_h_min = 1;
      const std::string w = lr::constitutional_check(0, t, &sink);
      C(lr::is_r_min_violation(w) && w.rfind("R_MIN_VIOLATION field=settle_h_min value=1", 0) == 0, "F (a) mainnet settle_h_min 1: " + w.substr(0, 60)); }
    { lr::LaneRules t = m; t.owed_demo_amount = 5;
      const std::string w = lr::constitutional_check(0, t, &sink);
      C(w.rfind("R_MIN_VIOLATION field=owed_demo_amount value=5", 0) == 0, "F (a) mainnet owed_demo_amount 5 (a premine): " + w.substr(0, 60)); }
    { lr::LaneRules t = m; t.residual_sink_id = b32_of(0x52);
      const std::string w = lr::constitutional_check(0, t, &sink);
      C(w.rfind("R_MIN_VIOLATION field=residual_sink_id", 0) == 0, "F (b) mainnet another residual sink: " + w.substr(0, 50));
      C(lr::constitutional_check(0, t, nullptr).empty(), "F (b) ... not checked when the caller has no fixed sink to compare with"); }
    { lr::LaneRules t = m; t.drain_q = 32;
      const std::string w = lr::constitutional_check(0, t, &sink);
      C(w.rfind("R_MIN_VIOLATION field=drain_q value=32", 0) == 0, "F (c) drain_q 32 (16 Q > 256: a slower drain): " + w.substr(0, 50)); }
    { lr::LaneRules t = m; t.drain_h_cap = 32;
      const std::string w = lr::constitutional_check(0, t, &sink);
      C(w.rfind("R_MIN_VIOLATION field=drain_h_cap value=32", 0) == 0, "F (c) drain_h_cap 32 (< 64: a delayed drain): " + w.substr(0, 50)); }
    { lr::LaneRules t = m; t.drain_h_cap = 256;
      const std::string w = lr::constitutional_check(0, t, &sink);
      C(w.rfind("R_MIN_VIOLATION field=drain_h_cap value=256", 0) == 0, "F (c) drain_h_cap 256 (>= 16 Q: nobody admitted): " + w.substr(0, 50)); }
    { lr::LaneRules t = m; t.drain_q = 8; t.drain_h_cap = 64;
      C(lr::constitutional_check(0, t, &sink).empty(), "F (c) a FASTER drain (Q 8, H_cap 64) is constitutional (what a majority may still decide)"); }
    { lr::LaneRules t = m; t.drain_h_cap = 128;
      C(lr::constitutional_check(0, t, &sink).empty(), "F (c) a larger cap (H_cap 128 < 16 Q) is constitutional (the attempt-11 epoch-2 rule)"); }
    // (a) / (b) are mainnet-only; (c) binds every network that runs a drain; a network without a drain (version 0) is not bound
    { lr::LaneRules t = m; t.settle_h_min = 1; t.owed_demo_amount = 5; t.residual_sink_id = b32_of(0x52);
      C(lr::constitutional_check(2, t, &sink).empty(), "F stagenet: h_min / demo / sink are knobs (R-MIN (a), (b) are mainnet)"); }
    { lr::LaneRules t = m; t.drain_h_cap = 32;
      C(lr::is_r_min_violation(lr::constitutional_check(2, t, &sink)), "F stagenet: the drain floor binds (H_cap 32 refused)"); }
    { lr::LaneRules t = literal_rules();   // drain 0/0/0: no drain exists
      C(lr::constitutional_check(3, t, &sink).empty(), "F regtest without a drain: not bound by (c)"); }
    // point 3: decode_hello refuses a MAINNET peer's unconstitutional TLV by name; a stagenet peer's passes
    {
        lr::LaneRules t = m; t.owed_demo_amount = 7;
        Hello h = hello_with(t, 9); h.network = 0;
        h.pool->genesis = b32_of(0x6e);
        const auto f = encode_hello(h);
        Hello back; std::string why;
        C(!f.empty() && !decode_hello(f, back, &why) && why.find("R_MIN_VIOLATION field=owed_demo_amount value=7") != std::string::npos,
          "F decode_hello: a mainnet peer with owed_demo_amount 7 is refused by name (" + why.substr(0, 60) + ")");
        Hello s = h; s.network = 2;
        const auto fs = encode_hello(s);
        C(decode_hello(fs, back, &why), "F decode_hello: the same TLV from a stagenet peer decodes (" + why + ")");
    }
}

int main() {
    g_print = std::getenv("V37_LANE_RULES_KAT_PRINT") != nullptr;
    Checker C;
    std::printf("== v37_xmr_lane_rules_kat ==\n");
    suite_codec(C);
    suite_refusal(C);
    suite_frames(C);
    suite_property(C);
    suite_rmin(C);
    return C.done("v37_xmr_lane_rules_kat");
}
