// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// xmr_relay_wire_kat -- GAP-2 stage 1, KAT 1 (RandomX-free).
//
// Pins the Family-B receipt-relay wire (xmr/relay/xmr_relay_wire.hpp):
//   W1  first-byte namespace: 0x40..0x4f never collides with a Family-A
//       CarrierWire version (w3_wire_freeze kAcceptedVersions) nor with the
//       control opcodes (>= kCtrlOpcodeBase)
//   W2  FB_HELLO: golden bytes, round trip, every refusal (length, opcode,
//       version, magic, bind mode) and hello_mismatch's reasons
//   W3  FB_BLOCK_WON: golden bytes, round trip, refusals
//   W4  side_data_v2 digest, rbind_v1 and lane_params_digest goldens; the
//       lane digest moves with every field it covers
//   W5  fb_receipt / FB_RECEIPTS: round trip of a minted receipt; decode is
//       TOTAL under truncation at every length, oversize n, oversize len, a
//       non-XMR payee kind, trailing bytes -- never throws, never accepts
//   W6  receipt_id == v37::xmr::verify::cheap_receipt_id (the admission key)
//   W7  base58 address decode (checksum, prefixes) of a known address
// Regenerate goldens: V37_GAP2_KAT_PRINT=1.
#include <cstdlib>
#include <set>

#include "xmr_relay_test_util.hpp"
#include <c2pool/v37/xmr/relay/xmr_address.hpp>
#include <c2pool/v37/carrier_net.hpp>
#include <c2pool/v37/w3_wire_freeze.hpp>

using namespace gap2test;

static bool g_print = false;
static void golden(Checker& C, const std::string& name, const std::string& got, const char* want) {
    if (g_print || !*want) std::printf("    GOLDEN %s = \"%s\"\n", name.c_str(), got.c_str());
    C(got == want, name + " golden");
}

int main() {
    g_print = std::getenv("V37_GAP2_KAT_PRINT") != nullptr;
    Checker C;
    std::printf("== xmr_relay_wire_kat ==\n");

    // ── W1 namespace ────────────────────────────────────────────────────────
    {
        bool clash = false;
        for (std::uint8_t v : c2pool::v37n::wire_freeze::kAcceptedVersions)
            if (is_family_b_opcode(v)) clash = true;
        C(!clash, "W1 no Family-A accepted CarrierWire version lies in 0x40..0x4f");
        C(FB_NS_LAST < c2pool::v37n::kCtrlOpcodeBase, "W1 0x40..0x4f is below the control-opcode base 0x80");
        C(is_family_b_opcode(FB_HELLO) && is_family_b_opcode(FB_RECEIPTS) && is_family_b_opcode(FB_BLOCK_WON),
          "W1 HELLO/RECEIPTS/BLOCK_WON are in the claimed range");
        C(!is_family_b_opcode(0x01) && !is_family_b_opcode(0x02) && !is_family_b_opcode(0x80),
          "W1 0x01/0x02/0x80 are NOT Family-B opcodes");
        C(kHelloBytes == 102 && kBlockWonBytes == 127 && kSideV2Bytes == 56, "W1 fixed frame sizes 102/127, side_data_v2 56 B");
        C(kFbMaxFrame < c2pool::v37n::kMaxCarrierFrame, "W1 the largest FB_RECEIPTS frame fits the transport ceiling");
    }

    // ── W2 HELLO ────────────────────────────────────────────────────────────
    Hello h;
    h.network = 3; h.chain_id = 7; h.lane_params_digest = b32_of(1); h.share_diff = 2000; h.node_nonce = 0x1122334455667788ull;
    h.listen_port = 45000; h.lane_next_pos = 4242; h.lane_digest = b32_of(2); h.bind = BindMode::None;
    {
        const auto f = encode_hello(h);
        C(f.size() == kHelloBytes, "W2 hello encodes to 102 bytes");
        golden(C, "W2 hello", hex(f),
               "400143325852030700000020272e353c434a51585f666d747b828990979ea5acb3bac1c8cfd6dde4ebf2f9d0070000000000008877665544332211c8af92100000000000003f464d545b626970777e858c939aa1a8afb6bdc4cbd2d9e0e7eef5fc030a111800");
        Hello back; std::string why;
        C(decode_hello(f, back, &why) && back == h, "W2 hello round trip");
        auto t = f; t.pop_back();                 C(!decode_hello(t, back, &why), "W2 hello short -> refused");
        t = f; t.push_back(0);                     C(!decode_hello(t, back, &why), "W2 hello long -> refused");
        t = f; t[0] = FB_RECEIPTS;                 C(!decode_hello(t, back, &why), "W2 hello wrong opcode -> refused");
        t = f; t[1] = 2;                           C(!decode_hello(t, back, &why), "W2 hello unknown version -> refused");
        t = f; t[2] ^= 1;                          C(!decode_hello(t, back, &why), "W2 hello bad magic -> refused");
        t = f; t.back() = 7;                       C(!decode_hello(t, back, &why), "W2 hello unknown bind mode -> refused");
        Hello o = h; o.node_nonce = 1;
        C(hello_mismatch(h, o).empty(), "W2 identical params, other nonce -> compatible");
        Hello m = o; m.share_diff = 2001;          C(hello_mismatch(h, m).find("share_diff") != std::string::npos, "W2 share_diff mismatch named");
        m = o; m.chain_id = 8;                     C(hello_mismatch(h, m).find("chain_id") != std::string::npos, "W2 chain mismatch named");
        m = o; m.network = 2;                      C(hello_mismatch(h, m).find("network") != std::string::npos, "W2 network mismatch named");
        m = o; m.bind = BindMode::Rbind;           C(hello_mismatch(h, m).find("bind") != std::string::npos, "W2 bind-mode mismatch named");
        m = o; m.lane_params_digest = b32_of(9);   C(hello_mismatch(h, m).find("lane_params_digest") != std::string::npos, "W2 LaneParams mismatch named");
        C(hello_mismatch(h, h).find("self") != std::string::npos, "W2 own nonce -> self-connection");
    }
    // ── W2r LANE-RULES: the HELLO with the lane-rules list (a new length class) ─
    {
        Hello r = h;
        r.pool = pool_id_of(7, ::v37::LaneParams{}); r.pool->genesis = b32_of(6);
        c2pool::v37n::xmr::lanerules::LaneRules lr;
        lr.d_conf = 60; lr.output_cap = 2700; lr.recon_max_root_age = 240; lr.book_deferral = 1; lr.coinbase_maturity = 60;
        lr.input_weight = 659; lr.pool_tag_codec = 1; lr.lane_params_digest = h.lane_params_digest; lr.residual_sink_id = b32_of(8);
        r.rules = lr;
        const auto f = encode_hello(r);
        // RULES RATCHET R1: the rules frame carries the epoch trailer u32 epoch_cur | u8 n | n x 61 B after the TLV.
        C(f.size() == kHelloBytesPoolGenesis + 1 + 2 + 278 + 4 + 1 + 61, "W2r hello + rules + epoch trailer = 174 + 1 + 2 + 278 + 66 = 521 bytes");
        golden(C, "W2r hello+rules+epochs", hex(f),
               "400143325852030700000020272e353c434a51585f666d747b828990979ea5acb3bac1c8cfd6dde4ebf2f9d0070000000000008877665544332211c8af92100000000000003f464d545b626970777e858c939aa1a8afb6bdc4cbd2d9e0e7eef5fc030a111800e61c22c223c04b630ec8759d185602087e34b312241af9d35dee518f35f7c3a80100000000000000bbc2c9d0d7dee5ecf3fa01080f161d242b323940474e555c636a71787f868d9400160101083c000000000000000208000000000000000003048c0a00000408f0000000000000000501010608000000000000000007010008080000000000000000090800000000000000000a01000b01000c04000000000d0800000000000000000e01000f0100100893020000000000001108000000000000000012083c000000000000001304000000001420f900070e151c232a31383f464d545b626970777e858c939aa1a8afb6bdc4cbd2150400000000160800000000000000001704000000001804000000001904000000001a01011b2020272e353c434a51585f666d747b828990979ea5acb3bac1c8cfd6dde4ebf2f91c2000000000000000000000000000000000000000000000000000000000000000001d0100010000000101000000b0dba289f348cf078385aa04f486feea5a6e5dda3752b5a717b796ef02448f7700000000000000000000000000000000000000000000000000");
        Hello back; std::string why;
        Hello r_expl = r; r_expl.epoch_cur = 1; r_expl.epochs = hello_epochs_of(r);   // the decoder fills the list it read
        C(decode_hello(f, back, &why) && back == r_expl && back.epochs.size() == 1 && back.epochs[0].epoch_no == 1 && back.epochs[0].kind == 0 &&
          back.epochs[0].rules_digest == c2pool::v37n::xmr::lanerules::rules_digest(lr),
          "W2r round trip: epoch_cur 1, one Deployment {1, rules_digest(TLV), kind 0} (" + why + ")");
        {   // the trailer is MANDATORY: the pre-ratchet 455-byte frame (TLV, no trailer) is refused by name
            std::vector<u8> pre(f.begin(), f.begin() + static_cast<std::ptrdiff_t>(kHelloBytesPoolGenesis + 1 + 2 + 278));
            { const bool rf = !decode_hello(pre, back, &why); C(rf && why == "hello: rules length mismatch", "W2r a pre-ratchet rules frame (no epoch trailer) -> \"" + why + "\""); }
            auto bad_cur = f; bad_cur[kHelloBytesPoolGenesis + 1 + 2 + 278] = 2;   // epoch_cur 2: not in the list
            { const bool rf = !decode_hello(bad_cur, back, &why); C(rf && why == "hello: epoch_cur is not an epoch of the list", "W2r epoch_cur outside the list -> \"" + why + "\""); }
            auto bad_dig = f; bad_dig[kHelloBytesPoolGenesis + 1 + 2 + 278 + 5 + 4] ^= 1;   // the Deployment's rules_digest != the TLV's
            { const bool rf = !decode_hello(bad_dig, back, &why); C(rf && why.find("not the rules of epoch_cur") != std::string::npos, "W2r a Deployment digest that is not the TLV's -> refused (" + why + ")"); }
            auto bad_kind = f; bad_kind[kHelloBytesPoolGenesis + 1 + 2 + 278 + 5 + 36] = 1;   // epoch 1 kind 1
            { const bool rf = !decode_hello(bad_kind, back, &why); C(rf && why.find("epoch 1 must be kind 0") != std::string::npos, "W2r epoch 1 of another kind -> refused (" + why + ")"); }
            Hello two = r; two.epochs = hello_epochs_of(r);
            c2pool::v37n::xmr::epoch::Deployment d2; d2.epoch_no = 2; d2.kind = 1; d2.rules_digest = b32_of(0x22); d2.start_height = 100; d2.timeout_height = 200;
            two.epochs.push_back(d2);
            const auto f2 = encode_hello(two);
            Hello b2;
            C(f2.size() == f.size() + 61 && decode_hello(f2, b2, &why) && b2.epochs.size() == 2 && b2.epochs[1] == d2, "W2r two Deployments: +61 B, round trip");
            Hello one = two; one.epochs.pop_back(); one.node_nonce = 97;
            C(hello_mismatch(one, two).empty() && hello_mismatch(two, one).empty(), "W2r a peer that knows FEWER / MORE epochs is accepted (follower either way)");
            Hello other = two; other.node_nonce = 99; other.epochs[1].start_height = 101;
            const std::string em = hello_mismatch(two, other);
            C(em.rfind("LANE_RULES_MISMATCH epoch=2 field=start ours=100 theirs=101", 0) == 0, "W2r a common Deployment that differs is refused by name: " + em.substr(0, 60));
            Hello od = two; od.node_nonce = 98; od.epochs[1].rules_digest = b32_of(0x23);
            const std::string dm = hello_mismatch(two, od);
            C(dm.rfind("LANE_RULES_MISMATCH epoch=2 field=rules_digest", 0) == 0, "W2r a common Deployment with another rules_digest: " + dm.substr(0, 50));
        }
        C(std::equal(f.begin(), f.begin() + kHelloBytesPoolGenesis, encode_hello([&] { Hello x = r; x.rules.reset(); return x; }()).begin()),
          "W2r the first 174 bytes are the POOL-LINEAGE HELLO, unchanged");
        Hello l = r; l.rules.reset();
        Hello l142 = l; l142.pool->genesis.reset();
        Hello l102 = l; l102.pool.reset();
        bool legacy_ok = true;
        for (const Hello* x : {&l, &l142, &l102}) {
            Hello b; legacy_ok = legacy_ok && decode_hello(encode_hello(*x), b, &why) && !b.rules && b == *x;
        }
        C(legacy_ok, "W2r the 174/142/102-byte HELLOs still decode, rules = none");
        auto t = f; t[kHelloBytesPoolGenesis + 1] ^= 1;
        C(!decode_hello(t, back, &why) && why == "hello: rules length mismatch", "W2r a wrong rules_len -> \"" + why + "\"");
        t = f; t.pop_back();
        C(!decode_hello(t, back, &why) && why == "hello: rules length mismatch", "W2r one byte short -> rules length mismatch");
        t = std::vector<u8>(f.begin(), f.begin() + kHelloBytesEnrolSet + 1);
        C(!decode_hello(t, back, &why), "W2r 207 bytes (a rules frame too short for its length) -> refused (" + why + ")");
    }

    // ── W3 BLOCK_WON ────────────────────────────────────────────────────────
    {
        BlockWon b; b.chain_id = 7; b.bid = b32_of(3); b.h_b = 150; b.cut_next_pos = 99; b.cut_spine_digest = b32_of(4);
        b.reward = 600000000000ull; b.payout_emitted = true; b.owed_digest_at_win = b32_of(5);
        const auto f = encode_block_won(b);
        C(f.size() == kBlockWonBytes, "W3 block_won encodes to 127 bytes");
        golden(C, "W3 block_won", hex(f),
               "4201070000005e656c737a81888f969da4abb2b9c0c7ced5dce3eaf1f8ff060d141b22293037960000000000000063000000000000007d848b9299a0a7aeb5bcc3cad1d8dfe6edf4fb020910171e252c333a41484f560070c9b28b000000019ca3aab1b8bfc6cdd4dbe2e9f0f7fe050c131a21282f363d444b525960676e75");
        BlockWon back; std::string why;
        C(decode_block_won(f, back, &why) && back == b, "W3 block_won round trip");
        auto t = f; t.pop_back();                  C(!decode_block_won(t, back, &why), "W3 short -> refused");
        t = f; t[f.size() - 33] = 2;               C(!decode_block_won(t, back, &why), "W3 payout_emitted not 0/1 -> refused");
        t = f; t[1] = 9;                           C(!decode_block_won(t, back, &why), "W3 unknown version -> refused");
    }

    // ── W4 digests ──────────────────────────────────────────────────────────
    const ::v37::ScriptRef payA = payee_of("A");
    {
        const SideDataV2 s = side_for(payA, 7, 2000, 5);
        C(s.bytes().size() == kSideV2Bytes && SideDataV2::from(s.bytes().data()) == s, "W4 side_data_v2 56-byte round trip");
        // RULES RATCHET R1: the former reserved word is the BALLOT; at 0 the bytes are the pre-ratchet bytes
        C(s.ballot == 0 && s.bytes()[54] == 0 && s.bytes()[55] == 0, "W4 ballot 0 (no vote) occupies bytes [54..56) of side_data_v2, zero: byte-identical to the pre-ratchet receipt");
        golden(C, "W4 side_digest_v2", hex(side_digest_v2(s)), "b8b09a4358b09d5702273ef064633f007f0bfdcc47a0ca7c2e16df52a0865430");
        golden(C, "W4 rbind_v1", hex(rbind_v1(7, s)), "2875c5ba6ecf23bb13106b3de55fbd6fae3c5eb811d1cd23a5a9b5ce6fad1ad1");
        SideDataV2 sb = s; sb.ballot = 0x8002;   // epoch 2 stated by the miner
        C(sb.bytes()[54] == 0x02 && sb.bytes()[55] == 0x80 && SideDataV2::from(sb.bytes().data()).ballot == 0x8002,
          "W4 ballot 0x8002 is LE at [54..56) and round-trips");
        C(side_digest_v2(sb) != side_digest_v2(s) && rbind_v1(7, sb) != rbind_v1(7, s), "W4 the ballot moves the digest and the binding (under rbind)");
        golden(C, "W4 side_digest_v2(ballot 0x8002)", hex(side_digest_v2(sb)), "000bcd1a97d86f164bbd0902fa17a56d01df2763301a4380635eafe8733b9bcd");
        SideDataV2 s2 = s; s2.give_author = 6;
        C(side_digest_v2(s2) != side_digest_v2(s) && rbind_v1(7, s2) != rbind_v1(7, s), "W4 give_author moves the digest and the binding");
        C(rbind_v1(8, s) != rbind_v1(7, s), "W4 rbind is chain-scoped");
        const ::v37::LaneParams lp{};
        const bytes32 d0 = lane_params_digest(lp, 2000, BindMode::None);
        golden(C, "W4 lane_params_digest(default, 2000, none)", hex(d0), "8f49947a8716dc16cf3cbceb01529ba9eb930042693da93f8a43a4186157da3f");
        std::set<bytes32> seen{d0};
        auto moved = [&](const ::v37::LaneParams& p, u64 sd, BindMode bm) { return seen.insert(lane_params_digest(p, sd, bm)).second; };
        ::v37::LaneParams p = lp; p.window = 8641;            C(moved(p, 2000, BindMode::None), "W4 window moves the lane digest");
        p = lp; p.level_caps.push_back(1);                    C(moved(p, 2000, BindMode::None), "W4 level_caps move it");
        p = lp; p.subthreshold.enabled = true;                C(moved(p, 2000, BindMode::None), "W4 subthreshold gate moves it");
        p = lp; p.win.win_version = 1;                        C(moved(p, 2000, BindMode::None), "W4 win gate moves it");
        p = lp; p.nr.nr_version = 1;                          C(moved(p, 2000, BindMode::None), "W4 nr gate moves it");
        p = lp; p.mrr.activation_pos = 0;                     C(moved(p, 2000, BindMode::None), "W4 mrr gate moves it");
        // STEP-0 hotfix: LaneParams::k_floor (the coinbase no-dust floor) is
        // folded iff non-zero, so the XMR default (0) keeps the golden above
        // and any node that sets a floor is refused at HELLO.
        p = lp; p.k_floor = 1;                                C(moved(p, 2000, BindMode::None), "W4 k_floor 1 moves it");
        p = lp; p.k_floor = ::v37::K_FLOOR_F_REF;             C(moved(p, 2000, BindMode::None), "W4 k_floor 10 moves it");
        golden(C, "W4 lane_params_digest(family_a, 2000, none)",
               hex(lane_params_digest(::v37::LaneParams::family_a(), 2000, BindMode::None)), "bef300a00a350c1ab405c6c002d2ef3dc217e02e7dbb7a50cface332303f5ba1");
        {
            Hello a; a.network = 3; a.chain_id = 7; a.share_diff = 2000; a.node_nonce = 1;
            a.lane_params_digest = d0;
            Hello b = a; b.node_nonce = 2;
            b.lane_params_digest = lane_params_digest(::v37::LaneParams::family_a(), 2000, BindMode::None);
            C(hello_mismatch(a, b).find("lane_params_digest") != std::string::npos,
              "W4 a peer on another k_floor is REFUSED at HELLO, by name");
            b.lane_params_digest = d0;
            C(hello_mismatch(a, b).empty(), "W4 ...and the same k_floor is compatible");
        }
        C(moved(lp, 2001, BindMode::None), "W4 share_diff moves it");
        C(moved(lp, 2000, BindMode::Rbind), "W4 bind mode moves it");
    }

    // ── W5 receipts ─────────────────────────────────────────────────────────
    {
        const SynthBlock sb = make_block(150, b32_of(11), 3, nullptr, 5, 1);
        FbReceipt r; std::string why;
        C(mint_on(sb, 77, payA, 7, 2000, r, &why), "W5 mint a receipt on a 6-tx synthetic lane block " + why);
        const auto raw = encode_fb_receipt(r);
        C(!raw.empty() && raw.size() <= kFbReceiptMaxBytes, "W5 fb_receipt encodes (" + std::to_string(raw.size()) + " B)");
        FbReceipt back;
        C(decode_fb_receipt(raw, back, &why) && encode_fb_receipt(back) == raw, "W5 fb_receipt round trip is byte-exact");
        bool total = true, never = true;
        for (std::size_t n = 0; n < raw.size(); ++n) {
            std::vector<u8> t(raw.begin(), raw.begin() + static_cast<std::ptrdiff_t>(n));
            try { FbReceipt x; if (decode_fb_receipt(t, x)) never = false; } catch (...) { total = false; }
        }
        C(total, "W5 decode is TOTAL (no throw) under truncation at every one of " + std::to_string(raw.size()) + " lengths");
        C(never, "W5 no truncation of a receipt decodes");
        auto t = raw; t.push_back(0);              C(!decode_fb_receipt(t, back), "W5 trailing byte -> refused");
        t = raw; t[0] = 0x01; t[1] = 0x04;         C(!decode_fb_receipt(t, back), "W5 receipt len 1025 > relay budget -> refused");
        t = raw; t[raw.size() - 66] = 0x01;        C(!decode_fb_receipt(t, back), "W5 non-XMR payee kind -> refused");
        t = raw; t[raw.size() - 65] = 32;          C(!decode_fb_receipt(t, back), "W5 payee length != 64 -> refused");
        const auto f1 = encode_receipts_frame(7, {&raw});
        ReceiptsFrame rf;
        C(decode_receipts_frame(f1, rf, &why) && rf.chain_id == 7 && rf.receipts.size() == 1 && rf.raw[0] == raw,
          "W5 FB_RECEIPTS n=1 round trip (raw slice == encoded receipt)");
        std::vector<const std::vector<u8>*> eight(8, &raw), nine(9, &raw);
        const auto f8 = encode_receipts_frame(7, eight);
        C(!f8.empty() && f8.size() <= kFbMaxFrame && decode_receipts_frame(f8, rf) && rf.receipts.size() == 8, "W5 n=8 frame fits and decodes");
        C(encode_receipts_frame(7, nine).empty(), "W5 n=9 refused at encode");
        t = f1; t[6] = 9;                          C(!decode_receipts_frame(t, rf), "W5 n=9 header -> refused");
        t = f1; t[6] = 0;                          C(!decode_receipts_frame(t, rf), "W5 n=0 -> refused");
        t = f1; t[6] = 2;                          C(!decode_receipts_frame(t, rf), "W5 n claims 2, carries 1 -> refused");
        bool ftotal = true;
        for (std::size_t n = 0; n < f8.size(); n += 7) {
            std::vector<u8> tt(f8.begin(), f8.begin() + static_cast<std::ptrdiff_t>(n));
            try { ReceiptsFrame x; (void)decode_receipts_frame(tt, x); } catch (...) { ftotal = false; }
        }
        C(ftotal, "W5 FB_RECEIPTS decode is total under truncation");
        std::vector<u8> huge(kFbMaxFrame + 1, 0); huge[0] = FB_RECEIPTS; huge[1] = 1; huge[6] = 1;
        C(!decode_receipts_frame(huge, rf), "W5 frame over kFbMaxFrame -> refused before parsing");

        // ── W6 the dedup key ────────────────────────────────────────────────
        C(receipt_id(r) == ::v37::xmr::verify::cheap_receipt_id(r.receipt.hashing_blob), "W6 receipt_id == cheap_receipt_id(hashing_blob)");
        FbReceipt r2; mint_on(sb, 78, payA, 7, 2000, r2);
        C(receipt_id(r2) != receipt_id(r), "W6 another nonce is another receipt id");
    }

    // ── W7 base58 ───────────────────────────────────────────────────────────
    {
        const std::string addr = "47hHNpPZU8qQRAQ2LZupNPiQoeQvo18tA5DPZvwkWajH1qsUkwHmbugfMyoXv1yQdPQhDTq6x8MFiV6cMmi7uUmX7yhotxk";
        const auto d = decode_address(addr);
        C(d.has_value() && d->prefix == 18 && !d->subaddress && !d->integrated, "W7 mainnet/regtest standard address decodes (prefix 18, checksum ok)");
        if (d) {
            golden(C, "W7 spend", hex(std::vector<u8>(d->spend.begin(), d->spend.end())), "a03ab8e2191c928bffa5c875c42834f793a356c12cd6d319310619055bcc7005");
            golden(C, "W7 view", hex(std::vector<u8>(d->view.begin(), d->view.end())), "099b5b60c9a497e55985b3843c3fda8da741814c39f0cda7fab35c0c4c1c023d");
            C(::v37::xmr::xmr_ref_valid(d->ref()), "W7 decoded keys are valid ed25519 points (payee ref valid)");
        }
        std::string bad = addr; bad[20] = (bad[20] == 'a') ? 'b' : 'a';
        C(!decode_address(bad).has_value(), "W7 one flipped character -> checksum refusal");
        C(!decode_address(addr.substr(0, 90)).has_value(), "W7 truncated address -> refused");
        C(!decode_address("0OIl" + addr.substr(4)).has_value(), "W7 non-alphabet characters -> refused");
    }
    // ── W8 RELAY-DISCOVERY: FB_GETADDR (0x4c) / FB_ADDR (0x4d) ──────────────
    {
        const std::vector<u8> ops = {FB_HELLO, FB_RECEIPTS, FB_BLOCK_WON, FB_GETCTX, FB_CTX, FB_GETDROPS,
                                     FB_DROPINV, FB_GETWON, FB_PING, FB_PONG, FB_GETADDR, FB_ADDR};
        C(std::set<u8>(ops.begin(), ops.end()).size() == ops.size(), "W8 every Family-B opcode constant is distinct");
        bool in_ns = true; for (u8 o : ops) in_ns = in_ns && is_family_b_opcode(o);
        C(in_ns, "W8 every Family-B opcode lies in 0x40..0x4f");
        C(FB_GETADDR == 0x4c && FB_ADDR == 0x4d, "W8 FB_GETADDR = 0x4c, FB_ADDR = 0x4d (0x4a/0x4b stay reserved for LANE-EPOCH)");
        bool no_epoch = true; for (u8 o : ops) no_epoch = no_epoch && o != 0x4a && o != 0x4b;
        C(no_epoch, "W8 no opcode uses the LANE-EPOCH reservation 0x4a/0x4b");

        const auto g = encode_getaddr(7, 64);
        golden(C, "W8 getaddr(7,64)", hex(g), "4c01070000004000");
        u32 ch = 0; u16 want = 0; std::string why;
        C(decode_getaddr(g, ch, want, &why) && ch == 7 && want == 64, "W8 getaddr round-trip");
        C(encode_getaddr(7, 0).empty() && encode_getaddr(7, 257).empty(), "W8 getaddr want 0 / 257 not encodable");
        auto gb = g; gb[6] = 0; gb[7] = 0;
        C(!decode_getaddr(gb, ch, want), "W8 getaddr want 0 refused");
        gb = g; gb.push_back(0);
        C(!decode_getaddr(gb, ch, want), "W8 getaddr trailing byte refused");
        gb = g; gb[1] = 2;
        C(!decode_getaddr(gb, ch, want), "W8 getaddr unknown version refused");

        AddrEntry a4, a6;
        C(addr_entry_of("203.0.113.9", 59321, 1700000000, a4) && a4.family == kAddrFamV4, "W8 IPv4 literal -> entry");
        C(addr_entry_of("2001:db8::7", 59321, 1700000001, a6) && a6.family == kAddrFamV6, "W8 IPv6 literal -> entry");
        C(!addr_entry_of("pool.example", 1, 0, a4 = AddrEntry{}) , "W8 a DNS name is not an entry (no resolution on the wire)");
        addr_entry_of("203.0.113.9", 59321, 1700000000, a4);
        const auto f = encode_addr(7, {a4, a6});
        C(f.size() == kAddrHeader + 2 * kAddrEntryBytes, "W8 addr frame = 8 + 2 x 27 bytes");
        golden(C, "W8 addr(7,[v4,v6])", hex(f),
               "4d0107000000020004cb007109000000000000000000000000b9e700f15365000000000620010db8000000000000000000000007b9e701f1536500000000");
        std::vector<AddrEntry> v;
        C(decode_addr(f, ch, v, &why) && ch == 7 && v.size() == 2 && v[0] == a4 && v[1] == a6, "W8 addr round-trip (v4 + v6)");
        C(addr_host(v[0]) == "203.0.113.9" && addr_host(v[1]) == "2001:db8::7", "W8 entry -> host literal");
        std::vector<u8> empty = encode_addr(7, {});
        C(decode_addr(empty, ch, v) && v.empty(), "W8 an empty ADDR (nothing known) decodes");
        std::vector<AddrEntry> many(kAddrMaxEntries, a4), over(kAddrMaxEntries + 1, a4);
        const auto fm = encode_addr(7, many);
        C(fm.size() == kAddrMaxFrame && decode_addr(fm, ch, v) && v.size() == kAddrMaxEntries, "W8 256 entries = the bound, accepted");
        C(encode_addr(7, over).empty(), "W8 257 entries not encodable");
        auto fb = fm; fb[6] = 1; fb[7] = 1;   // n = 257 claimed
        C(!decode_addr(fb, ch, v) && v.empty(), "W8 n > 256 refused");
        fb = f; fb.pop_back();
        C(!decode_addr(fb, ch, v), "W8 truncated entry refused");
        fb = f; fb[8] = 5;
        C(!decode_addr(fb, ch, v) && v.empty(), "W8 unknown address family refused (total: no partial output)");
        fb = f; fb[8 + 1 + 5] = 1;
        C(!decode_addr(fb, ch, v), "W8 IPv4 entry with non-zero padding refused");
        fb = f; fb[8 + 17] = 0; fb[8 + 18] = 0;
        C(!decode_addr(fb, ch, v), "W8 port 0 refused");
        AddrEntry z = a4; z.port = 0;
        C(encode_addr(7, {z}).empty(), "W8 port 0 not encodable");
        auto is_pub = [](const char* h) { AddrEntry e; return addr_entry_of(h, 1, 0, e) && addr_routable(e); };
        C(is_pub("1.1.1.1") && is_pub("8.8.8.8") && is_pub("2001:4860::1"), "W8 public addresses are routable");
        C(!is_pub("127.0.0.1") && !is_pub("10.1.2.3") && !is_pub("192.168.86.114") && !is_pub("172.20.0.1") &&
          !is_pub("100.64.0.1") && !is_pub("169.254.1.1") && !is_pub("0.0.0.0") && !is_pub("224.0.0.1") &&
          !is_pub("::1") && !is_pub("fd00::1") && !is_pub("fe80::1") && !is_pub("::ffff:192.168.1.1"),
          "W8 loopback / RFC1918 / CGNAT / link-local / unspecified / multicast / ULA / mapped-private are NOT routable");
    }
    return C.done("xmr_relay_wire_kat");
}
