// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ===========================================================================
// src/c2pool/v37/test/v37_xmr_stranger_mm_tail_kat.cpp   (MM-PARSE-2)
//
// A stranger's coinbase that ends in the same 03 21 00 <root> merge-mining
// tail as ours is a DECIDED not-lane block, never "lane-root-unknown".
// MM-PARSE found 25 of 9,764 mainnet coinbases (74 B tx_extra: 01 pubkey |
// 02 4-byte nonce | 03 21 00 root -- p2pool and other merge-mining pools) that
// the coinbase authority decoded as lane-root-unknown: a node RETRIES them
// while holding the finalize gate, HOLDS them past the retry bound and, once
// synced, REFUSES them with a cba-ALARM + a node-local LIABILITY + a lineage
// vote observation. The lane-candidate test is now a pure function of the
// bytes that needs a V37 field (V37P / V37C / V37D) in the 0x02 payload.
//
// Two callers of decode_lane_coinbase are exercised:
//   BYTES   no pool_tag (the pre-lineage API: tools, scanners, KATs)
//   DAEMON  our pool_tag (what main_v37_xmr passes since POOL-LINEAGE #1774)
//
//   D  the coinbase authority:
//      (1) the REAL mainnet block 3700900 (p2pool shape) -> not-lane in both
//          (base BYTES: lane-root-unknown);
//      (2) our lane block stripped to the p2pool shape (01 R | 02 4-byte nonce |
//          our own 03 root) -> not-lane in both (base BYTES: BOOKED as ours);
//      (3) a FOREIGN pool tag -> DAEMON: Foreign not-lane (POOL-LINEAGE,
//          unchanged); BYTES: fields present, root matched (unchanged);
//      (4) OUR tag, root not in the ring -> lane-root-unknown in both, root
//          fingerprint kept (the relay-lag wait, unchanged);
//      (5) OUR tag, root in the ring -> books in both (unchanged);
//      (6) a pre-#1774 lane block (V37C cut, no V37P) -> BYTES books,
//          DAEMON Untagged not-lane (unchanged).
//   F  through FinalizeConnect (d_conf 3), with main's lane-root-unknown ->
//      lane-root-refused mapping (decidable = synced to the builder cut and a
//      seeded ring), per caller: h5 = block 3700900, h6 = (2) [BYTES] or (3)
//      [DAEMON], h7 = (5), h8 = (4) until the relay catches up. Phase 1 (ring
//      not seeded, relay lagging), phase 2 (seeded, caught up). Expected: h5 /
//      h6 decided not-lane at the FIRST attempt, never retried / HELD /
//      refused / alarmed / liable / voted; h7 books; h8 waits (retries, then
//      HELD holding the cursor at 4) and books once the relay catches up; the
//      cursor reaches the frontier 11; 0 lane-root-refused, 0 liability, 0
//      refused vote observations. Base BYTES: h5 HELD at cursor 1, then
//      refused with alarm + liability + a vote observation.
//
// Network-free, RandomX-free (the v37_xmr_coinbase_extra_kat shape). Nonzero
// exit on any failure.
// ===========================================================================
#include <unistd.h>

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <vector>

#include "impl/xmr/coin/xmr_derivation.hpp"
#include "impl/xmr/native/consensus/xmr_block_parse.hpp"
#include "impl/xmr/native/template/xmr_monerod_miner_data.hpp"
#include "impl/xmr/template/xmr_block_assembly.hpp"

#include "c2pool/v37/xmr/xmr_coinbase_authority.hpp"
#include "c2pool/v37/xmr/xmr_o2_finalize_connect.hpp"
#include "c2pool/v37/xmr/xmr_o2_settlement_fixture.hpp"
#include "c2pool/v37/xmr/xmr_o2_settlement_provider.hpp"

#include "xmr_c4_parity_golden.hpp"

namespace o2     = c2pool::v37n::xmr::o2;
namespace asm_   = c2pool::xmr::assembly;
namespace auth   = c2pool::v37n::xmr::authority;
namespace credit = c2pool::v37n::xmr::credit;
namespace cons   = c2pool::xmr::native;
namespace G4     = c2pool::xmr::native::golden_c4;
using Bytes = std::vector<std::uint8_t>;

namespace {

int g_fail = 0;
void check(const char* name, bool ok, const std::string& detail = {}) {
    std::printf("  [%s] %s%s%s\n", ok ? "PASS" : "FAIL", name, detail.empty() ? "" : "  -- ", detail.c_str());
    if (!ok) ++g_fail;
}
Bytes from_hex(const char* h) {
    Bytes b; const std::size_t n = std::strlen(h) / 2; b.reserve(n);
    auto nib = [](char c) -> int { return c <= '9' ? c - '0' : (c | 0x20) - 'a' + 10; };
    for (std::size_t i = 0; i < n; ++i) b.push_back(static_cast<std::uint8_t>(nib(h[2 * i]) << 4 | nib(h[2 * i + 1])));
    return b;
}
std::string hexs(const std::uint8_t* p, std::size_t n) {
    static const char* d = "0123456789abcdef"; std::string s;
    for (std::size_t i = 0; i < n; ++i) { s += d[p[i] >> 4]; s += d[p[i] & 15]; }
    return s;
}
bool starts(const std::string& s, const char* p) { return s.rfind(p, 0) == 0; }

// Mainnet block 3700900, id 12700b8423d1959295a1af42abf9c79f97ec212cc2450835a90f8aef888cbf6d,
// get_block(height=3700900).result.blob (the operator's synced mainnet monerod; one of
// the 25 MM-PARSE lane-root-unknown blocks). Its coinbase tx_extra (74 B) is
//   01 11c73e31..f7d9 | 02 04 f2a25eb0 | 03 21 00 8f9c637c..1e93
const char* kBlock3700900 =
    "1010d3c4ddd1068919c33e9346c4e6894c362c54d7c5850cfd8130587d50d1441e66c3006c95849411002702e0f1e10101ffa4f1e10101e0"
    "abc6a8c01103cbef56137f43f7a90a88e6bb2af06f05a88986ca0ff46da97341996e71c0453f864a0111c73e31e29c3b146fa19a17cbc621"
    "50bdcb04da916336a5970686dc57faf7d90204f2a25eb00321008f9c637c04bcc1f5173f4490af9f0cb5b891081faa4ebd4c9b126f3dd16b"
    "1e930005e06162855b19af4e0616d0ac0fd6c24f9203bb0a0535139d461a8ceb7c0ae5a0d016c11b3d15db4fa1a05b6a38c973595c467d18"
    "016c5c97c4cd2aafdaa8543582489867aba7551585fd40cb1ec16a434625fa6eaf614b0d9dfb6fc3a40c11fd549aba29218400258b4618b3"
    "6a10c01fe6ceec9af3e9dc225a35d17eb36d91fdb1e464f3e80b41e5805bd4a2f4aeb7f538e7cbaa2ec069837ab25260966ab378";
const char* kRoot3700900 = "8f9c637c04bcc1f5173f4490af9f0cb5b891081faa4ebd4c9b126f3dd16b1e93";

void put_varint(Bytes& o, std::uint64_t v) { while (v >= 0x80) { o.push_back(static_cast<std::uint8_t>((v & 0x7f) | 0x80)); v >>= 7; } o.push_back(static_cast<std::uint8_t>(v)); }

// Re-serialise a block blob with its coinbase tx_extra replaced (the
// v37_xmr_coinbase_extra_kat helper).
bool with_extra(const Bytes& blob, const Bytes& new_extra, Bytes& out) {
    cons::ParsedBlock pb;
    const auto st = cons::parse_block(blob.data(), blob.size(), pb);
    if (st != cons::BlockParseStatus::Ok && st != cons::BlockParseStatus::TxCountMismatch) return false;
    const std::uint8_t* p = blob.data() + pb.miner_tx_offset;
    const std::uint8_t* it = p; const std::uint8_t* end = p + pb.miner_tx_size;
    std::uint64_t v = 0;
    for (int k = 0; k < 3; ++k) if (tools::read_varint(it, end, v) <= 0) return false;
    ++it;
    if (tools::read_varint(it, end, v) <= 0) return false;
    std::uint64_t nout = 0; if (tools::read_varint(it, end, nout) <= 0) return false;
    for (std::uint64_t i = 0; i < nout; ++i) { if (tools::read_varint(it, end, v) <= 0) return false; it += 1 + 32 + 1; }
    const std::size_t xlen_at = static_cast<std::size_t>(it - p);
    std::uint64_t xlen = 0; if (tools::read_varint(it, end, xlen) <= 0) return false;
    const std::size_t after = static_cast<std::size_t>(it - p) + static_cast<std::size_t>(xlen);
    out.assign(blob.begin(), blob.begin() + static_cast<std::ptrdiff_t>(pb.miner_tx_offset + xlen_at));
    put_varint(out, new_extra.size());
    out.insert(out.end(), new_extra.begin(), new_extra.end());
    out.insert(out.end(), blob.begin() + static_cast<std::ptrdiff_t>(pb.miner_tx_offset + after), blob.end());
    return true;
}
Bytes tx_extra_of(const Bytes& blob) {
    cons::ParsedBlock pb; ::v37::xmr::settle::ReceivedCoinbase got; std::uint64_t h = 0; std::size_t used = 0;
    const auto st = cons::parse_block(blob.data(), blob.size(), pb);
    if (st != cons::BlockParseStatus::Ok && st != cons::BlockParseStatus::TxCountMismatch) return {};
    if (!asm_::parse_coinbase_prefix(blob.data() + pb.miner_tx_offset, pb.miner_tx_size, got, &h, &used)) return {};
    return got.tx_extra;
}

// ---- the lane fixture (v37_xmr_coinbase_extra_kat / v37_xmr_credit_cut_kat) ----
std::array<std::uint8_t, 32> point_of(std::uint8_t k) {
    ::xmr::coin::SecretKey sec{}; sec.data()[0] = k;
    ::xmr::coin::PublicKey pub{};
    if (!::xmr::coin::secret_key_to_public_key(sec, pub)) return {};
    std::array<std::uint8_t, 32> out{}; std::memcpy(out.data(), pub.data(), 32); return out;
}
const std::uint32_t LANE_CHAIN = 0x0000ABCDu;
::v37::bytes32 fill32(std::uint8_t b) { ::v37::bytes32 x; x.fill(b); return x; }
const ::v37::bytes32 TAG_A = fill32(0xA1);   // OUR pool
const ::v37::bytes32 TAG_B = fill32(0xB2);   // another pool, same lane config
class CannedTransport final : public ::c2pool::xmr::node::IMonerodTransport {
public:
    explicit CannedTransport(std::string body) : body_(std::move(body)) {}
    void rpc_post(const std::string&, std::function<void(const ::c2pool::xmr::node::RpcResponse&)> cb) override {
        ::c2pool::xmr::node::RpcResponse r; r.body.assign(body_.begin(), body_.end()); cb(r);
    }
    void zmq_subscribe(const std::string&, std::function<void(const ::c2pool::xmr::node::ZmqFrame&)>) override {}
private:
    std::string body_;
};
struct LaneBlock {
    o2::XmrOwedFixture                                 ledger{static_cast<::v37::ChainId>(LANE_CHAIN)};
    o2::XmrSettlementConfig                            scfg;
    CannedTransport                                    tx{G4::MD_RAW_JSON};
    c2pool::xmr::native::tmpl::MonerodMinerDataSource  src{tx};
    std::unique_ptr<o2::XmrSettlementTemplateProvider> provider;
    o2::SettlementSnapshot                             snap;
    asm_::BlockBytes                                   bytes;
    bool ok = false; std::string why;
    LaneBlock(const ::v37::bytes32* tag, bool cut) {
        const auto P1 = point_of(1), P2 = point_of(2), P3 = point_of(3), P4 = point_of(4);
        ledger.seed_owed(::v37::xmr::make_xmr_std(P1, P2), 3'000'000'000ull);
        ledger.seed_owed(::v37::xmr::make_xmr_std(P3, P2), 2'000'000'000ull);
        ledger.seed_owed(::v37::xmr::make_xmr_sub(P1, P2), 1'000'000'000ull);
        scfg.h_min = 0; scfg.output_cap = 0;
        scfg.set_residual_sink_std(P4, P2);
        if (tag) scfg.pool_tag = *tag;
        if (cut) scfg.credit_cut_source = [](std::uint64_t& P, ::v37::bytes32& dg) { P = 0x00BC614Eull; dg = fill32(0x5C); return true; };
        if (!src.poll(&why)) return;
        provider = std::make_unique<o2::XmrSettlementTemplateProvider>(src, ledger, scfg, 0);
        if (!provider->refresh()) { why = provider->last_error(); return; }
        snap = provider->current();
        if (!snap.valid || !snap.tpl) { why = "no template"; return; }
        ok = snap.tpl->materialize(0, bytes, &why);
    }
    ::v37::bytes32 digest() { return ledger.ledger().owed_digest(); }
};

enum class Caller { Bytes, Daemon };
const char* name_of(Caller c) { return c == Caller::Bytes ? "BYTES" : "DAEMON"; }

// decode_blob exactly as main_v37_xmr (gate OFF): the candidate ring, our keys,
// the configured sink, and (DAEMON) our pool_tag.
auth::CoinbaseBooking decode(LaneBlock& L, const Bytes& blob, Caller c, bool root_known = true) {
    std::vector<::v37::bytes32> cands{root_known ? L.digest() : fill32(0x77)};
    return auth::decode_lane_coinbase(blob, LANE_CHAIN, cands, L.ledger.keys(), L.scfg.residual_sink,
                                      L.scfg.residual_sink_identity, L.ledger.pay_of(),
                                      c == Caller::Daemon ? &TAG_A : nullptr);
}

struct Blocks { Bytes p2pool, stripped, foreign, own, precut; bool ok = false; std::string why; };

std::string brief(const auth::CoinbaseBooking& b) {
    return std::string("ok=") + (b.ok ? "1" : "0") + " is_lane=" + (b.is_lane ? "1" : "0") + " why=" + b.why.substr(0, 90);
}

void suite_decode(LaneBlock& A, Blocks& X) {
    std::printf("-- D: the coinbase authority, both callers --\n");
    const Bytes px = tx_extra_of(X.p2pool);
    check("D0 block 3700900 is the p2pool shape: 74 B tx_extra 01 R | 02 04 nonce | 03 21 00 root",
          px.size() == 74 && px[0] == 0x01 && px[33] == 0x02 && px[34] == 0x04 && px[39] == 0x03 && px[40] == 0x21 &&
          px[41] == 0x00 && hexs(px.data() + 42, 32) == kRoot3700900, "extra=" + std::to_string(px.size()) + " B");
    const Bytes sx = tx_extra_of(X.stripped);
    check("D0' the stripped lane block is the same shape (74 B) and keeps OUR 03 root",
          sx.size() == 74 && std::memcmp(sx.data() + 39, tx_extra_of(X.own).data() + tx_extra_of(X.own).size() - 35, 35) == 0);
    for (Caller c : {Caller::Bytes, Caller::Daemon}) {
        const std::string n = name_of(c);
        const auto d1 = decode(A, X.p2pool, c);
        check(("D1 [" + n + "] real mainnet block 3700900 (p2pool shape) -> DECIDED not-lane, no root fingerprint").c_str(),
              !d1.ok && !d1.is_lane && starts(d1.why, "not-lane:") && !d1.has_onchain_root, brief(d1));
        const auto d2 = decode(A, X.stripped, c);
        check(("D2 [" + n + "] our block stripped to the p2pool shape (no V37 field, OUR root) -> DECIDED not-lane, never booked").c_str(),
              !d2.ok && !d2.is_lane && starts(d2.why, "not-lane:") && d2.payout.empty(), brief(d2));
        const auto d4 = decode(A, X.own, c, /*root_known=*/false);
        check(("D4 [" + n + "] OUR tag, root not (yet) in the ring -> lane-root-unknown, root fingerprint kept (relay-lag wait, unchanged)").c_str(),
              !d4.ok && !d4.is_lane && starts(d4.why, "lane-root-unknown:") && d4.has_onchain_root, brief(d4));
        const auto d5 = decode(A, X.own, c);
        check(("D5 [" + n + "] OUR tag, root in the ring -> BOOKS (unchanged)").c_str(),
              d5.ok && d5.is_lane && !d5.payout.empty(), brief(d5));
    }
    const auto d3 = decode(A, X.foreign, Caller::Daemon);
    check("D3 [DAEMON] a FOREIGN pool tag -> Foreign, \"not-lane:\", the seen tag recorded (POOL-LINEAGE, unchanged)",
          !d3.ok && !d3.is_lane && d3.lineage_gated && d3.lineage == credit::BlockLineage::Foreign && d3.lineage_seen_tag == TAG_B &&
          starts(d3.why, "not-lane: foreign"), brief(d3));
    const auto d3b = decode(A, X.foreign, Caller::Bytes);
    check("D3' [BYTES] the foreign-tag block carries V37 fields: still a candidate, its (same-ledger) root matches (pre-lineage, unchanged)",
          d3b.is_lane, brief(d3b));
    const auto d6b = decode(A, X.precut, Caller::Bytes), d6d = decode(A, X.precut, Caller::Daemon);
    check("D6 [BYTES] a pre-#1774 lane block (V37C cut, no V37P) is still a lane candidate and books",
          d6b.ok && d6b.is_lane && d6b.has_credit_cut, brief(d6b));
    check("D6' [DAEMON] the same pre-#1774 block -> Untagged, \"not-lane:\" (POOL-LINEAGE, unchanged)",
          !d6d.is_lane && d6d.lineage == credit::BlockLineage::Untagged && starts(d6d.why, "not-lane:"), brief(d6d));
}

struct FcResult {
    std::uint64_t cur1 = 0, cur2 = 0, held1 = 0, held2 = 0, held_entered = 0, refused = 0, refused_not_credited = 0,
                  liability = 0, obs_refused = 0, root_unknown_retries = 0, alarm_refused = 0, alarm_unknown = 0;
    int att5 = 0, att6 = 0; std::string why5, why6, why7, why8; bool h8_settled = false, h7_settled = false;
    bool held5 = false, held6 = false;
};

FcResult run_fc(LaneBlock& A, Blocks& X, Caller c, const std::filesystem::path& tmp) {
    using c2pool::xmr::node::MockMonerodTransport;
    using namespace c2pool::v37n::xmr;
    FcResult r;
    XmrNodeConfig cfg;
    cfg.network = MoneroNetwork::Stagenet; cfg.lane_chain = 7; cfg.d_conf = 3;
    cfg.settle_db_path = (tmp / (std::string("store-") + name_of(c))).string();
    std::filesystem::create_directories(cfg.settle_db_path);
    o2::FinalizeConnectOptions o;
    o.out = nullptr;
    o.sidecar_path = (std::filesystem::path(cfg.settle_db_path) / "pfound.tsv").string();
    o.retry_bound = 30; o.held_retry_every = 5;
    MockMonerodTransport mock;
    XmrNode node(cfg, mock, &smoke::test_point_check);
    try { node.bring_up(); } catch (const std::exception& ex) { check("F0 bring_up", false, ex.what()); return r; }

    std::map<std::uint64_t, const Bytes*> have{{5, &X.p2pool}, {6, c == Caller::Bytes ? &X.stripped : &X.foreign},
                                               {7, &X.own}, {8, &X.own}};
    std::map<std::uint64_t, int> attempts; std::map<std::uint64_t, std::string> last_why;
    bool ring_seeded = false, relay_caught_up = false;
    std::set<std::string> unknown_seen;
    // main_v37_xmr book_from_chain_ex, the not-ok branch verbatim in behaviour: an
    // unmatched root is transient until this node is SYNCED to the builder cut with a
    // seeded ring, then "lane-root-refused:<root>:" (alarm, liability, vote).
    o.book_from_chain_ex = [&](std::uint64_t h, const std::string& bid, o2::FinalizeConnectOptions::ChainBooking& bk) {
        ++attempts[h];
        auto it = have.find(h);
        if (it == have.end()) { bk.why = "not-lane: test"; return false; }
        const auto d = decode(A, *it->second, c, h != 8 || relay_caught_up);
        bk.total_pico = d.total;
        if (d.has_onchain_root) bk.onchain_root_hex = hexs(d.onchain_root.data(), 32);
        if (!d.ok) {
            std::string why = d.why;
            if (starts(why, "lane-root-unknown:")) {
                const std::uint64_t bcut = (h >= 1 + cfg.d_conf) ? h - 1 - cfg.d_conf : 0;
                const std::uint64_t cur  = node.finalize_driver().cursor_height();
                if (cur >= bcut && ring_seeded && d.has_onchain_root) {
                    why = "lane-root-refused:" + bk.onchain_root_hex + ":" + why.substr(std::string("lane-root-unknown:").size());
                    bk.unattributed_pico = d.total;
                    if (unknown_seen.insert(bid).second) ++r.alarm_refused;   // cba-ALARM lane_root_refused
                } else if (unknown_seen.insert(bid).second) {
                    ++r.alarm_unknown;                                        // cba-ALARM lane_root_unknown
                }
            }
            bk.why = why; last_why[h] = why;
            return false;
        }
        bk.credit.clear();
        for (const auto& [k, v] : d.payout) bk.credit[k] = v;
        bk.payout = bk.credit; bk.payout_decoded = true;
        last_why[h] = "booked";
        return true;
    };
    o2::FoundBlockQueue q;
    o2::FinalizeConnect fc(node, cfg, q, o);
    auto chain = [&](std::uint64_t from, std::uint64_t to) {
        for (std::uint64_t h = from; h <= to; ++h)
            smoke::apply_row(node, h, smoke::blk_id(static_cast<std::uint8_t>(h)), smoke::blk_id(static_cast<std::uint8_t>(h - 1)));
    };
    const std::string bid5 = hex_of(smoke::blk_id(5)), bid6 = hex_of(smoke::blk_id(6)),
                      bid7 = hex_of(smoke::blk_id(7)), bid8 = hex_of(smoke::blk_id(8));
    chain(1, 4); (void)fc.tick();
    chain(5, 14);
    for (int i = 0; i < 45; ++i) (void)fc.tick();             // phase 1: ring warming, h8's relay lagging
    r.cur1 = node.finalize_driver().cursor_height(); r.held1 = fc.stats().held_now;
    r.held5 = fc.held().count(bid5) != 0; r.held6 = fc.held().count(bid6) != 0;
    ring_seeded = true; relay_caught_up = true;
    for (int i = 0; i < 12; ++i) (void)fc.tick();             // phase 2: synced, seeded, caught up
    r.cur2 = node.finalize_driver().cursor_height(); r.held2 = fc.stats().held_now;
    const auto& s = fc.stats();
    r.held_entered = s.held_entered; r.refused = s.refused; r.refused_not_credited = s.refused_not_credited;
    r.liability = s.liability_blocks; r.obs_refused = s.obs_refused; r.root_unknown_retries = s.lane_root_unknown_retries;
    r.att5 = attempts[5]; r.att6 = attempts[6];
    r.why5 = last_why[5]; r.why6 = last_why[6]; r.why7 = last_why[7]; r.why8 = last_why[8];
    r.h7_settled = node.ledger().is_settled(bid7); r.h8_settled = node.ledger().is_settled(bid8);
    (void)fc.drain_before_stop();
    std::printf("  FC[%s] phase1 cursor=%llu held_now=%llu | phase2 cursor=%llu held_now=%llu | held_entered=%llu refused=%llu "
                "lane_root_refused=%llu liability_blocks=%llu vote_obs_refused=%llu root_unknown_retries=%llu "
                "alarm(lane_root_refused)=%llu alarm(lane_root_unknown)=%llu | attempts h5=%d h6=%d | h7 settled=%d h8 settled=%d\n"
                "      why5=%s\n      why6=%s\n",
                name_of(c), (unsigned long long)r.cur1, (unsigned long long)r.held1, (unsigned long long)r.cur2,
                (unsigned long long)r.held2, (unsigned long long)r.held_entered, (unsigned long long)r.refused,
                (unsigned long long)r.refused_not_credited, (unsigned long long)r.liability, (unsigned long long)r.obs_refused,
                (unsigned long long)r.root_unknown_retries, (unsigned long long)r.alarm_refused, (unsigned long long)r.alarm_unknown,
                r.att5, r.att6, r.h7_settled, r.h8_settled, r.why5.substr(0, 110).c_str(), r.why6.substr(0, 110).c_str());
    return r;
}

void suite_finalize(LaneBlock& A, Blocks& X, const std::filesystem::path& tmp) {
    std::printf("-- F: through FinalizeConnect (d_conf 3), both callers --\n");
    for (Caller c : {Caller::Bytes, Caller::Daemon}) {
        const std::string n = name_of(c);
        const FcResult r = run_fc(A, X, c, tmp);
        check(("F1 [" + n + "] h5 = mainnet 3700900: booked NOT-LANE at the first attempt, never retried, never HELD").c_str(),
              r.att5 == 1 && !r.held5 && starts(r.why5, "not-lane:"), "attempts=" + std::to_string(r.att5) + " why=" + r.why5.substr(0, 70));
        check(("F2 [" + n + "] h6 = " + (c == Caller::Bytes ? "stripped p2pool shape" : "foreign tag") + ": NOT-LANE at the first attempt, never HELD").c_str(),
              r.att6 == 1 && !r.held6 && starts(r.why6, "not-lane:"), "attempts=" + std::to_string(r.att6) + " why=" + r.why6.substr(0, 70));
        check(("F3 [" + n + "] no alarm, no liability, no vote: 0 lane-root-refused, 0 liability blocks, 0 refused vote observations, 0 refused").c_str(),
              r.refused_not_credited == 0 && r.liability == 0 && r.obs_refused == 0 && r.refused == 0 && r.alarm_refused == 0,
              "lane_root_refused=" + std::to_string(r.refused_not_credited) + " liability=" + std::to_string(r.liability) +
              " obs_refused=" + std::to_string(r.obs_refused) + " refused=" + std::to_string(r.refused));
        check(("F4 [" + n + "] h8 = OUR tag, root unknown while the relay lags: WAITS (retried, then HELD holding the cursor at 4 = 8-1-d_conf; unchanged)").c_str(),
              r.cur1 == 4 && r.held1 == 1 && r.root_unknown_retries >= 30 && r.alarm_unknown == 1,
              "phase1 cursor=" + std::to_string(r.cur1) + " held_now=" + std::to_string(r.held1) +
              " retries=" + std::to_string(r.root_unknown_retries));
        check(("F5 [" + n + "] once the relay catches up h8 books, h7 and h8 settle, the cursor walks to the frontier 11, nothing HELD").c_str(),
              r.cur2 == 11 && r.held2 == 0 && r.h7_settled && r.h8_settled && r.why7 == "booked" && r.why8 == "booked",
              "phase2 cursor=" + std::to_string(r.cur2) + " held_now=" + std::to_string(r.held2) + " why8=" + r.why8.substr(0, 40));
    }
}

} // namespace

int main() {
    std::filesystem::path tmp = std::filesystem::temp_directory_path() / ("v37-xmr-mmtail-" + std::to_string(::getpid()));
    std::filesystem::remove_all(tmp);
    std::filesystem::create_directories(tmp);
    std::printf("== v37_xmr_stranger_mm_tail_kat ==\n");
    LaneBlock A(&TAG_A, false), B(&TAG_B, false), U(nullptr, true);
    Blocks X;
    X.p2pool = from_hex(kBlock3700900);
    if (!A.ok || !B.ok || !U.ok) { check("fixtures build", false, A.why + " | " + B.why + " | " + U.why); return 1; }
    X.own = A.bytes.full_blob; X.foreign = B.bytes.full_blob; X.precut = U.bytes.full_blob;
    {   // our lane block stripped to the p2pool shape: 01 R | 02 04 <nonce 4> | our 03 tail
        const Bytes x = tx_extra_of(X.own);
        const bool shape = x.size() > 33 + 2 + 35 && x[0] == 0x01 && x[33] == 0x02 && x[34] < 0x80;
        Bytes nx(x.begin(), x.begin() + 33);
        nx.push_back(0x02); nx.push_back(0x04);
        if (shape) nx.insert(nx.end(), x.begin() + 35, x.begin() + 39);
        nx.insert(nx.end(), x.end() - 35, x.end());
        if (!shape || !with_extra(X.own, nx, X.stripped)) { check("stripped block builds", false); return 1; }
        check("V0 our lane coinbase carries the V37P field (01 R | 02 payload [.. V37P tag] | 03 21 00 root)",
              credit::parse_pool_tag(x) == credit::PoolTagParse::Present, "extra=" + std::to_string(x.size()) + " B");
    }
    suite_decode(A, X);
    suite_finalize(A, X, tmp);
    std::filesystem::remove_all(tmp);
    std::printf("== %s (%d failure(s)) ==\n", g_fail ? "FAIL" : "PASS", g_fail);
    return g_fail ? 1 : 0;
}
