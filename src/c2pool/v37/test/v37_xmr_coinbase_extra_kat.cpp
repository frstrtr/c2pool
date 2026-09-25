// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ===========================================================================
// src/c2pool/v37/test/v37_xmr_coinbase_extra_kat.cpp   (MM-PARSE)
//
// A valid mainnet block whose coinbase tx_extra does not start with 0x01 must
// never stop the finalize walk. Mainnet block 3765869 (f40bea91...ab1b) carries
//     tx_extra = 03 21 00 <root>  01 <R>  02 20 <32 B nonce>
// (a merge-mining tag FIRST). The pre-fix parse_coinbase_prefix() demanded
// tx_extra[0] == 0x01, the coinbase authority reported "miner_tx prefix does
// not parse", and FinalizeConnect filed that as a transient fetch failure:
// RETRY #1..#600, then HELD for ever, the cursor stuck, the lane suspended.
//
//   P  the parser: the real 3765869 miner tx parses (R = its 0x01 key, tags
//      03,01,02 walked in order); a garbage tx_extra is kept as opaque bytes
//      (R = 0) instead of failing the prefix; the walk follows monerod's field
//      grammar (padding / 0x02 <= 255 / 0x04 count / 0xDE / unknown tag stops);
//      and every coinbase the OLD parser accepted parses byte-identically
//      (legacy reference copied below).
//   D  the coinbase authority, a pure function of the block bytes:
//      (a) the real block 3765869 and (b) a lane block whose tx_extra was
//      replaced by garbage are "not-lane:" (decided); (c) our own lane
//      coinbase with its fields reordered / an extra 0xDE field before the
//      pubkey is still recognised and books the SAME payout as the canonical
//      layout; (c0) the canonical lane coinbase books exactly as before;
//      (e) a coinbase whose prefix itself does not read (unlock != height +
//      60) inside a block that parses is "not-lane:" as well, never transient.
//   F  end to end through FinalizeConnect (d_conf 3): (a) at h5, (b) at h6 and
//      (e) at h9 are booked not-lane and the cursor passes them, (c) at h7 books as a
//      lane block, (d) at h8 whose bytes are MISSING is still RETRIED then
//      HELD (unchanged) and holds the cursor; once h8's bytes arrive the cursor
//      walks to the frontier. On the pre-fix code h5 is HELD and the cursor
//      stays at 1.
//
// Network-free, RandomX-free (monerod STUB + the injected test point-check
// backend, the v37_xmr_cba_native_booking_kat shape; the lane block comes from
// the captured C4 get_miner_data as in v37_xmr_credit_cut_kat). Nonzero exit
// on any failure.
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

namespace o2   = c2pool::v37n::xmr::o2;
namespace asm_ = c2pool::xmr::assembly;
namespace auth = c2pool::v37n::xmr::authority;
namespace cons = c2pool::xmr::native;
namespace G4   = c2pool::xmr::native::golden_c4;
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

// Mainnet block 3765869, id f40bea91c9faf27f30f587ae1c43277495fd1d8bb5ba4bffd65f493aa4c8ab1b,
// get_block(height=3765869).result.blob (the operator's synced mainnet monerod).
const char* kBlock3765869 =
    "1010bd8bbad5061cc424fd114d1e6c35ec9c79a81bfcf233eaf1a4cbbbea6675ce9253f263c31c718400e802a9ede50101ffedece5010180"
    "cfe387c311030e038000e020e125df0a8d1d7eb4568addfb0098dee00dcd30442c071af86d674f66032100addc9a6058c3fd3c3da0208979"
    "857cec99db85b37f8f21d2228e09ffe669a40d0135e8b5dc993710dab0e6f3fb4d8a732168bf36747534cbb373902e2f1e5a87f002200000"
    "00000000000096e2c0fa7600000000000000000000000000000000000000000ac51a7af51401ef279f6ca2e581a1d0ca050c7aba88c809ef"
    "7196974361a2d02200b84c9ef35c1ae06d0d974a548996e1d564bafdb149146929bd5d8a29050303544f2b137812cca6acbb0a9fc6e069c7"
    "d4a1ebab3c72c0ce7ed3eb3c333ec96e6c9db31e9e14fbd6b29fd8351ffaa8d879864273e14164857418df7985b09bcf7503edc8af790432"
    "2277d0890e76c8112318b807439c81be983739ab1d2f2860c8b93fe26c5f5b0195e9eb2aba1b171e85430fd2abb6d50c521669a8bdc7a7a2"
    "7868a038163528c87506fc610c70ef5ffe3fb6f0e528a715e21a7db3ee74b866fe1b66e675a41170e1e3c33e9315de235777d467bd7438b5"
    "9159ce7e9e5026717190fc70c092c2807c81b309f98670147999c73caa4cc25e934341fbe8125bd2572f22a66abf3ff4bc63c963c88cbefe"
    "5a826c8146f2d96a27a4d09290d29739";
const std::uint64_t kHeight3765869 = 3765869;

// The PRE-FIX parser, verbatim in behaviour (tx_extra[0] must be 0x01): the
// reference every accepted coinbase must still parse identically against.
bool legacy_parse(const std::uint8_t* p, std::size_t n, ::v37::xmr::settle::ReceivedCoinbase& out,
                  std::uint64_t* height_out, std::size_t* consumed) {
    const std::uint8_t* it = p; const std::uint8_t* end = p + n;
    auto rd = [&](std::uint64_t& v) -> bool { return tools::read_varint(it, end, v) > 0; };
    std::uint64_t version = 0, unlock = 0, vin = 0, height = 0, nout = 0, xlen = 0;
    if (!rd(version) || version != 2) return false;
    if (!rd(unlock)) return false;
    if (!rd(vin) || vin != 1) return false;
    if (it >= end || *it++ != 0xff) return false;
    if (!rd(height)) return false;
    if (unlock != height + 60) return false;
    if (!rd(nout)) return false;
    out.amounts.clear(); out.keys.clear(); out.view_tags.clear();
    for (std::uint64_t i = 0; i < nout; ++i) {
        std::uint64_t amt = 0;
        if (!rd(amt)) return false;
        if (it >= end || *it++ != 0x03) return false;
        if (static_cast<std::size_t>(end - it) < 33) return false;
        ::xmr::coin::PublicKey k; std::memcpy(k.data(), it, 32); it += 32;
        ::xmr::coin::ViewTag vt; vt.tag = *it++;
        out.amounts.push_back(amt); out.keys.push_back(k); out.view_tags.push_back(vt);
    }
    if (!rd(xlen) || static_cast<std::size_t>(end - it) < xlen) return false;
    out.tx_extra.assign(it, it + xlen); it += xlen;
    if (out.tx_extra.size() < 33 || out.tx_extra[0] != 0x01) return false;
    std::memcpy(out.R.data(), out.tx_extra.data() + 1, 32);
    if (height_out) *height_out = height;
    if (consumed) *consumed = static_cast<std::size_t>(it - p);
    return true;
}

bool same_parse(const ::v37::xmr::settle::ReceivedCoinbase& a, const ::v37::xmr::settle::ReceivedCoinbase& b) {
    if (!(a.R == b.R) || a.amounts != b.amounts || a.keys != b.keys || a.tx_extra != b.tx_extra) return false;
    if (a.view_tags.size() != b.view_tags.size()) return false;
    for (std::size_t i = 0; i < a.view_tags.size(); ++i) if (a.view_tags[i].tag != b.view_tags[i].tag) return false;
    return true;
}

std::size_t varint_len(std::uint64_t v) { std::size_t n = 1; while (v >= 0x80) { v >>= 7; ++n; } return n; }
void put_varint(Bytes& o, std::uint64_t v) { while (v >= 0x80) { o.push_back(static_cast<std::uint8_t>((v & 0x7f) | 0x80)); v >>= 7; } o.push_back(static_cast<std::uint8_t>(v)); }

// Re-serialise a block blob with its coinbase tx_extra replaced (header, the
// prefix head, the rct_type byte and the tx-hash list untouched). Uses the
// block parser for the miner_tx span and a manual prefix walk for the extra.
bool with_extra(const Bytes& blob, const Bytes& new_extra, Bytes& out) {
    cons::ParsedBlock pb;
    const auto st = cons::parse_block(blob.data(), blob.size(), pb);
    if (st != cons::BlockParseStatus::Ok && st != cons::BlockParseStatus::TxCountMismatch) return false;
    const std::uint8_t* p = blob.data() + pb.miner_tx_offset;
    const std::uint8_t* it = p; const std::uint8_t* end = p + pb.miner_tx_size;
    std::uint64_t v = 0;
    for (int k = 0; k < 3; ++k) if (tools::read_varint(it, end, v) <= 0) return false;   // version, unlock, vin
    ++it;                                                                                // 0xff txin_gen
    if (tools::read_varint(it, end, v) <= 0) return false;                              // height
    std::uint64_t nout = 0; if (tools::read_varint(it, end, nout) <= 0) return false;
    for (std::uint64_t i = 0; i < nout; ++i) { if (tools::read_varint(it, end, v) <= 0) return false; it += 1 + 32 + 1; }
    const std::size_t xlen_at = static_cast<std::size_t>(it - p);
    std::uint64_t xlen = 0; if (tools::read_varint(it, end, xlen) <= 0) return false;
    const std::size_t after = static_cast<std::size_t>(it - p) + static_cast<std::size_t>(xlen);   // rct_type byte
    out.assign(blob.begin(), blob.begin() + static_cast<std::ptrdiff_t>(pb.miner_tx_offset + xlen_at));
    put_varint(out, new_extra.size());
    out.insert(out.end(), new_extra.begin(), new_extra.end());
    out.insert(out.end(), blob.begin() + static_cast<std::ptrdiff_t>(pb.miner_tx_offset + after), blob.end());
    return true;
}

// ---- the lane fixture (v37_xmr_credit_cut_kat) ----------------------------
std::array<std::uint8_t, 32> point_of(std::uint8_t k) {
    ::xmr::coin::SecretKey sec{}; sec.data()[0] = k;
    ::xmr::coin::PublicKey pub{};
    if (!::xmr::coin::secret_key_to_public_key(sec, pub)) return {};
    std::array<std::uint8_t, 32> out{}; std::memcpy(out.data(), pub.data(), 32); return out;
}
const std::uint32_t LANE_CHAIN = 0x0000ABCDu;
struct LaneFixture {
    o2::XmrOwedFixture      ledger{static_cast<::v37::ChainId>(LANE_CHAIN)};
    o2::XmrSettlementConfig scfg;
    LaneFixture() {
        const auto P1 = point_of(1), P2 = point_of(2), P3 = point_of(3), P4 = point_of(4);
        ledger.seed_owed(::v37::xmr::make_xmr_std(P1, P2), 3'000'000'000ull);
        ledger.seed_owed(::v37::xmr::make_xmr_std(P3, P2), 2'000'000'000ull);
        ledger.seed_owed(::v37::xmr::make_xmr_sub(P1, P2), 1'000'000'000ull);
        scfg.h_min = 0; scfg.output_cap = 0;
        scfg.set_residual_sink_std(P4, P2);
    }
};
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
    LaneFixture                                        lane;
    CannedTransport                                    tx{G4::MD_RAW_JSON};
    c2pool::xmr::native::tmpl::MonerodMinerDataSource  src{tx};
    std::unique_ptr<o2::XmrSettlementTemplateProvider> provider;
    o2::SettlementSnapshot                             snap;
    asm_::BlockBytes                                   bytes;
    bool ok = false; std::string why;
    LaneBlock() {
        if (!src.poll(&why)) return;
        provider = std::make_unique<o2::XmrSettlementTemplateProvider>(src, lane.ledger, lane.scfg, 0);
        if (!provider->refresh()) { why = provider->last_error(); return; }
        snap = provider->current();
        if (!snap.valid || !snap.tpl) { why = "no template"; return; }
        ok = snap.tpl->materialize(0, bytes, &why);
    }
    auth::CoinbaseBooking decode(const Bytes& blob) {
        std::vector<::v37::bytes32> cands{lane.ledger.ledger().owed_digest()};
        return auth::decode_lane_coinbase(blob, LANE_CHAIN, cands, lane.ledger.keys(),
                                          lane.scfg.residual_sink, lane.scfg.residual_sink_identity, lane.ledger.pay_of());
    }
};

struct Coinbase {
    bool parses = false, legacy = false;
    ::v37::xmr::settle::ReceivedCoinbase got, got_legacy;
    std::uint64_t h = 0, h_legacy = 0; std::size_t used = 0, used_legacy = 0;
    std::size_t miner_tx_size = 0;
};
Coinbase coinbase_of(const Bytes& blob) {
    Coinbase c; cons::ParsedBlock pb;
    const auto st = cons::parse_block(blob.data(), blob.size(), pb);
    if (st != cons::BlockParseStatus::Ok && st != cons::BlockParseStatus::TxCountMismatch) return c;
    c.miner_tx_size = pb.miner_tx_size;
    c.parses = asm_::parse_coinbase_prefix(blob.data() + pb.miner_tx_offset, pb.miner_tx_size, c.got, &c.h, &c.used);
    c.legacy = legacy_parse(blob.data() + pb.miner_tx_offset, pb.miner_tx_size, c.got_legacy, &c.h_legacy, &c.used_legacy);
    return c;
}

// The lane tx_extra's three fields: 01 R | 02 len payload | 03 21 00 root.
struct LaneExtra { Bytes pub, nonce, mm; bool ok = false; };
LaneExtra split_lane_extra(const Bytes& x) {
    LaneExtra e;
    if (x.size() < 33 + 2 + 35 || x[0] != 0x01 || x[33] != 0x02) return e;
    const std::size_t nlen = x[34];   // < 0x80: one-byte varint (the weight-invariant shape)
    if (nlen >= 0x80 || 35 + nlen + 35 != x.size()) return e;
    e.pub.assign(x.begin(), x.begin() + 33);
    e.nonce.assign(x.begin() + 33, x.begin() + 35 + static_cast<std::ptrdiff_t>(nlen));
    e.mm.assign(x.begin() + 35 + static_cast<std::ptrdiff_t>(nlen), x.end());
    e.ok = (e.mm[0] == 0x03 && e.mm[1] == 0x21 && e.mm[2] == 0x00);
    return e;
}
Bytes cat(std::initializer_list<const Bytes*> parts) { Bytes o; for (const Bytes* p : parts) o.insert(o.end(), p->begin(), p->end()); return o; }

// ===========================================================================
void suite_parser(LaneBlock& L) {
    std::printf("-- P: parse_coinbase_prefix / walk_tx_extra --\n");
    const Bytes mb = from_hex(kBlock3765869);
    const Coinbase c = coinbase_of(mb);
    check("P0 the real mainnet block 3765869 parses at block level (miner tx located)", c.miner_tx_size > 0,
          "miner_tx " + std::to_string(c.miner_tx_size) + " B");
    const Bytes& x = c.got.tx_extra;
    check("P1 its coinbase prefix PARSES (pre-fix: 'miner_tx prefix does not parse' -> RETRY/HELD for ever)",
          c.parses && c.h == kHeight3765869 && c.used + 1 == c.miner_tx_size,
          "parses=" + std::to_string(c.parses) + " h=" + std::to_string(c.h) + " used=" + std::to_string(c.used));
#ifdef C2POOL_XMR_TX_EXTRA_WALK
    const asm_::TxExtraWalk w = asm_::walk_tx_extra(x.data(), x.size());
    std::string tags; for (const auto& f : w.fields) tags += hexs(&f.tag, 1) + " ";
    check("P2 its tx_extra walks COMPLETE as 03 01 02 (merge-mining tag first)",
          w.complete && w.fields.size() == 3 && w.fields[0].tag == 0x03 && w.fields[1].tag == 0x01 && w.fields[2].tag == 0x02,
          "tags=" + tags + "extra=" + std::to_string(x.size()) + " B");
    const asm_::TxExtraField* pk = w.first(0x01);
    check("P3 R is the 32 bytes of its 0x01 field (not tx_extra[1..33))",
          c.parses && pk && std::memcmp(c.got.R.data(), x.data() + pk->data_offset, 32) == 0 && x[0] == 0x03,
          pk ? "R=" + hexs(c.got.R.data(), 8) + ".." : std::string("no 0x01"));
#else
    check("P2 walk_tx_extra() exists (the any-order tx_extra walk)", false, "pre-fix tree: no walk_tx_extra");
#endif
    check("P4 the OLD parser rejects exactly this block (the mainnet dry-run halt, reproduced)", !c.legacy);

    // garbage tx_extra: an unknown tag first -> opaque, R = 0, prefix still parses
    Bytes garbage = {0xFF, 0x13, 0x37, 0x00, 0x01, 0x02};
    for (int i = 0; i < 40; ++i) garbage.push_back(static_cast<std::uint8_t>(0xA5 ^ i));
    Bytes gb; const bool built = with_extra(mb, garbage, gb);
    const Coinbase g = coinbase_of(gb);
#ifdef C2POOL_XMR_TX_EXTRA_WALK
    const asm_::TxExtraWalk gw = asm_::walk_tx_extra(g.got.tx_extra.data(), g.got.tx_extra.size());
    check("P5 a GARBAGE tx_extra is kept as opaque bytes: the prefix parses, tx_extra verbatim, R = 0, walk stops at 0 (unknown tag)",
          built && g.parses && g.got.tx_extra == garbage && g.got.R == ::xmr::coin::PublicKey{} && !gw.complete &&
          gw.stop_offset == 0 && gw.fields.empty() && !g.legacy,
          std::string("stop=") + gw.stop_why);

    // grammar: monerod's parse_tx_extra field rules
    auto W = [](const Bytes& b) { return asm_::walk_tx_extra(b.data(), b.size()); };
    Bytes r32(32, 0x11);
    Bytes pad_ok = cat({&r32}); pad_ok.insert(pad_ok.begin(), 0x01); pad_ok.push_back(0x00); pad_ok.push_back(0x00);
    Bytes pad_bad = pad_ok; pad_bad.back() = 0x07;
    Bytes pad_long(1 + 32 + 256, 0x00); pad_long[0] = 0x01;
    Bytes n255 = {0x02, 0xFF, 0x01}; n255.resize(3 + 255, 0x00);
    Bytes n256 = {0x02, 0x80, 0x02}; n256.resize(3 + 256, 0x00);
    Bytes add2 = {0x04, 0x02}; add2.resize(2 + 64, 0x22); add2.push_back(0x01); add2.insert(add2.end(), r32.begin(), r32.end());
    Bytes add_trunc = {0x04, 0x03}; add_trunc.resize(2 + 64, 0x22);
    Bytes de = {0xDE, 0x03, 0xAA, 0xBB, 0xCC, 0x01}; de.insert(de.end(), r32.begin(), r32.end());
    Bytes mm_short = {0x03, 0x05, 0x00, 0x01, 0x02, 0x03, 0x04};
    check("P6 grammar: padding = zeros to the end (ok), a non-zero byte in it stops, > 255 B stops",
          W(pad_ok).complete && W(pad_ok).fields.size() == 2 && !W(pad_bad).complete && W(pad_bad).stop_offset == 33 && !W(pad_long).complete);
    check("P7 grammar: 0x02 nonce of 255 B ok, 256 B stops (TX_EXTRA_NONCE_MAX_COUNT)", W(n255).complete && !W(n256).complete);
    check("P8 grammar: 0x04 = varint count + 32*count (a following 0x01 is found); a short 0x04 stops",
          W(add2).complete && W(add2).fields.size() == 2 && W(add2).first(0x01) && W(add2).first(0x01)->offset == 66 && !W(add_trunc).complete);
    check("P9 grammar: 0xDE minergate blob is skipped and the 0x01 after it is found; a 0x03 without depth+root[32] stops",
          W(de).complete && W(de).first(0x01) && W(de).first(0x01)->data_offset == 6 && !W(mm_short).complete);

#else
    check("P5 a GARBAGE tx_extra is kept as opaque bytes (the prefix parses)", built && g.parses, "pre-fix tree");
#endif
    // INVARIANCE: our own coinbase parses byte-identically to the pre-fix parser
    if (!L.ok) { check("P10 lane fixture builds", false, L.why); return; }
    const Coinbase lc = coinbase_of(L.bytes.full_blob);
    check("P10 INVARIANCE: our lane coinbase parses identically under the new and the pre-fix parser (R, vouts, view tags, tx_extra, height, length)",
          lc.parses && lc.legacy && same_parse(lc.got, lc.got_legacy) && lc.h == lc.h_legacy && lc.used == lc.used_legacy &&
          lc.used + 1 == L.bytes.miner_tx_size,
          "outputs=" + std::to_string(lc.got.amounts.size()) + " extra=" + std::to_string(lc.got.tx_extra.size()) + " B");
}

struct DecodeCase { Bytes blob; auth::CoinbaseBooking bk; };
std::map<std::string, DecodeCase> g_cases;   // shared with suite F

void suite_decode(LaneBlock& L) {
    std::printf("-- D: the coinbase authority (a pure function of the block bytes) --\n");
    if (!L.ok) { check("D0 lane fixture builds", false, L.why); return; }
    const Bytes mb = from_hex(kBlock3765869);
    const Coinbase lc = coinbase_of(L.bytes.full_blob);
    const LaneExtra e = split_lane_extra(lc.got.tx_extra);
    check("D0 the lane tx_extra is 01 R | 02 payload | 03 21 00 root (the X6 layout)", e.ok);

    const auto c0 = L.decode(L.bytes.full_blob);
    g_cases["c0"] = {L.bytes.full_blob, c0};
    check("(c0) the canonical lane coinbase books as a lane block, exactly as before (ok, is_lane, payout decoded)",
          c0.ok && c0.is_lane && !c0.payout.empty(), c0.ok ? std::to_string(c0.payout.size()) + " payees, total " + std::to_string(c0.total) : c0.why);

    const auto a = L.decode(mb);
    g_cases["a"] = {mb, a};
    check("(a) real mainnet block 3765869 -> DECIDED not-lane (pre-fix: 'miner_tx prefix does not parse' = transient)",
          !a.ok && !a.is_lane && a.why.rfind("not-lane:", 0) == 0, a.why);

    Bytes garbage = {0xFF, 0x13, 0x37};
    for (int i = 0; i < 64; ++i) garbage.push_back(static_cast<std::uint8_t>(0x5A ^ (i * 7)));
    Bytes gb; const bool gok = with_extra(L.bytes.full_blob, garbage, gb);
    const auto b = L.decode(gb);
    g_cases["b"] = {gb, b};
    check("(b) our lane block with its tx_extra replaced by GARBAGE -> DECIDED not-lane",
          gok && !b.ok && !b.is_lane && b.why.rfind("not-lane:", 0) == 0, b.why);

    // (e) the miner_tx PREFIX itself is not a coinbase this parser reads (unlock != height + 60),
    // the block still parses: decided not-lane too (pre-fix: 'miner_tx prefix does not parse' = transient)
    Bytes eb = L.bytes.full_blob;
    const std::size_t unlock_at = L.bytes.miner_tx_offset + 1;   // version varint (0x02) then unlock_time
    const bool eok = (eb[unlock_at] & 0x7f) != 0x7f;
    if (eok) eb[unlock_at] = static_cast<std::uint8_t>(eb[unlock_at] + 1);
    const auto ee = L.decode(eb);
    g_cases["e"] = {eb, ee};
    check("(e) a coinbase whose PREFIX does not read (unlock != height + 60) in a parsing block -> DECIDED not-lane, never 'does not parse'",
          eok && !ee.ok && !ee.is_lane && ee.why.rfind("not-lane:", 0) == 0 && ee.why.find("does not parse") == std::string::npos, ee.why);

    if (!e.ok) return;
    const Bytes x_reord = cat({&e.nonce, &e.pub, &e.mm});
    Bytes cb; const bool cok = with_extra(L.bytes.full_blob, x_reord, cb);
    const auto c = L.decode(cb);
    g_cases["c"] = {cb, c};
    check("(c) our lane coinbase with an UNUSUAL field order (02 nonce | 01 R | 03 tail) is recognised and books the SAME payout/total/lane_commitment",
          cok && c.ok && c.is_lane && c.payout == c0.payout && c.total == c0.total && c.lane_commitment == c0.lane_commitment &&
          c.sink_total == c0.sink_total && c.has_extra_nonce == c0.has_extra_nonce && c.extra_nonce == c0.extra_nonce,
          c.ok ? "payees " + std::to_string(c.payout.size()) : c.why);
    const Bytes de = {0xDE, 0x02, 0xC2, 0x9F};
    const Bytes x_de = cat({&de, &e.pub, &e.nonce, &e.mm});
    Bytes cb2; const bool cok2 = with_extra(L.bytes.full_blob, x_de, cb2);
    const auto c2 = L.decode(cb2);
    check("(c') our lane coinbase with a 0xDE field BEFORE the pubkey books the same payout",
          cok2 && c2.ok && c2.is_lane && c2.payout == c0.payout && c2.total == c0.total, c2.ok ? "" : c2.why);
    // strict recognition: a stranger reusing our tail but not our r -> never credited as ours
    Bytes fakeR = e.pub; fakeR[5] ^= 0x01;
    const Bytes x_fake = cat({&fakeR, &e.nonce, &e.mm});
    Bytes fb; (void)with_extra(L.bytes.full_blob, x_fake, fb);
    const auto f = L.decode(fb);
    check("(c'') strictness kept: our 03 root with a WRONG 0x01 key is not booked (r*G != R)",
          !f.ok && f.why.find("r*G") != std::string::npos, f.why);
}

void suite_finalize(LaneBlock& L, const std::filesystem::path& tmp) {
    std::printf("-- F: through FinalizeConnect (the booking gate, d_conf 3) --\n");
    if (!g_cases.count("a") || !g_cases.count("b") || !g_cases.count("c") || !g_cases.count("e")) { check("F0 decode cases present", false); return; }
    using c2pool::xmr::node::MockMonerodTransport;
    using namespace c2pool::v37n::xmr;
    XmrNodeConfig cfg;
    cfg.network = MoneroNetwork::Stagenet; cfg.lane_chain = 7; cfg.d_conf = 3;
    cfg.settle_db_path = (tmp / "store-mmparse").string();
    std::filesystem::create_directories(cfg.settle_db_path);
    o2::FinalizeConnectOptions o;
    o.out = nullptr;
    o.sidecar_path = (std::filesystem::path(cfg.settle_db_path) / "pfound.tsv").string();
    o.retry_bound = 30; o.held_retry_every = 5;
    MockMonerodTransport mock;
    XmrNode node(cfg, mock, &smoke::test_point_check);
    try { node.bring_up(); } catch (const std::exception& ex) { check("F0 bring_up", false, ex.what()); return; }

    std::map<std::uint64_t, Bytes> have;   // what the block source holds, by height
    have[5] = g_cases["a"].blob; have[6] = g_cases["b"].blob; have[7] = g_cases["c"].blob; have[9] = g_cases["e"].blob;   // h8: MISSING
    std::map<std::uint64_t, int> attempts;
    std::map<std::uint64_t, std::string> last_why;
    o.book_from_chain_ex = [&](std::uint64_t h, const std::string& bid, o2::FinalizeConnectOptions::ChainBooking& bk) {
        ++attempts[h];
        if (h < 5 || h > 9) { bk.why = "not-lane: test"; return false; }
        auto it = have.find(h);
        if (it == have.end()) { bk.why = "get_block(" + bid.substr(0, 12) + "): mock: block body missing"; last_why[h] = bk.why; return false; }
        const auto d = L.decode(it->second);   // exactly main's decode_blob contract
        bk.total_pico = d.total;
        if (!d.ok) { bk.why = d.why; last_why[h] = bk.why; return false; }
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
                      bid7 = hex_of(smoke::blk_id(7)), bid8 = hex_of(smoke::blk_id(8)), bid9 = hex_of(smoke::blk_id(9));
    chain(1, 4); (void)fc.tick();
    chain(5, 14);
    for (int i = 0; i < 45; ++i) (void)fc.tick();
    const std::uint64_t cur = node.finalize_driver().cursor_height();
    auto st = [&]() {
        return "cursor=" + std::to_string(node.finalize_driver().cursor_height()) + " held_now=" + std::to_string(fc.stats().held_now) +
               " refused=" + std::to_string(fc.stats().refused) + " attempts(5,6,7,8)=" + std::to_string(attempts[5]) + "," +
               std::to_string(attempts[6]) + "," + std::to_string(attempts[7]) + "," + std::to_string(attempts[8]) +
               " why5=" + last_why[5].substr(0, 48);
    };
    check("F1 (a) mainnet block 3765869 at h5: booked NOT-LANE once, never retried, never HELD (pre-fix: RETRY then HELD, cursor stuck at 1)",
          attempts[5] == 1 && !fc.held().count(bid5) && last_why[5].rfind("not-lane:", 0) == 0, st());
    check("F2 (b) garbage tx_extra at h6: booked NOT-LANE once, the cursor passes 5 and 6",
          attempts[6] == 1 && !fc.held().count(bid6) && last_why[6].rfind("not-lane:", 0) == 0 && cur >= 4, st());
    check("F3 (c) our lane block with the unusual field order at h7: BOOKED as a lane block (pending in the ledger)",
          last_why[7] == "booked" && (node.ledger().is_pending(bid7) || node.ledger().is_settled(bid7)) && fc.stats().refused == 0, st());
    check("F4 (d) h8 whose bytes are MISSING: retried then HELD (unchanged), holding the cursor at 4 = 8 - 1 - d_conf",
          fc.held().count(bid8) && fc.stats().held_now == 1 && attempts[8] > 30 && cur == 4 &&
          last_why[8].rfind("get_block", 0) == 0, st());
    have[8] = g_cases["a"].blob;   // the body arrives (a stranger's block): decided, the gate releases
    for (int i = 0; i < 8; ++i) (void)fc.tick();
    check("F5 once h8's bytes arrive the HELD block resolves (not-lane) and the cursor walks to the frontier 11; h7 finalizes (settled)",
          node.finalize_driver().cursor_height() == 11 && fc.stats().held_now == 0 && node.ledger().is_settled(bid7) &&
          fc.stats().refused == 0, st());
    check("F6 (e) the unreadable-prefix coinbase at h9 is booked not-lane once and never HELD",
          attempts[9] == 1 && !fc.held().count(bid9) && last_why[9].rfind("not-lane:", 0) == 0, "why9=" + last_why[9]);
    (void)fc.drain_before_stop();
}

} // namespace

int main() {
    std::filesystem::path tmp = std::filesystem::temp_directory_path() / ("v37-xmr-cbextra-" + std::to_string(::getpid()));
    std::filesystem::remove_all(tmp);
    std::filesystem::create_directories(tmp);
    std::printf("== v37_xmr_coinbase_extra_kat ==\n");
    LaneBlock L;   // one lane fixture: the D cases are decoded against it, and so is the F booking callback
    suite_parser(L);
    suite_decode(L);
    suite_finalize(L, tmp);
    std::filesystem::remove_all(tmp);
    std::printf("== %s (%d failure(s)) ==\n", g_fail ? "FAIL" : "PASS", g_fail);
    return g_fail ? 1 : 0;
}
