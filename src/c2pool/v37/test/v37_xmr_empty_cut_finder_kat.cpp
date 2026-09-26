// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// v37_xmr_empty_cut_finder_kat -- EMPTY-CUT FINDER (operator ruling 09-26).
//
// The gap: with SAME-BLOCK PAY-NOW a pool block pays the miners whose work is
// in its on-chain credit cut. When that cut is EMPTY (a brand-new pool's first
// 1-3 blocks) nobody is credited, so the WHOLE reward still went to the
// donation output (fee model ON) / residual sink (fee model OFF). The rule: in
// an empty cut the finder's own share counts as the work -- the block pays its
// finder the pay-now pool (reward - 1 with the fee model ON: the donation keeps
// its 1-piconero marker; the whole reward with it OFF), and the finder payee
// is committed in the block itself ("V37F" || kind || payee[64], right before
// V37N) so every node reproduces the coinbase and the booking from the bytes.
//
//   E1  codec: V37F | V37N | V37D | V37P | V37C read back from one payload;
//       V37F without V37N is not read; a malformed kind is flagged.
//   E2  the settlement source, fee model ON and OFF, empty cut: the finder is
//       paid reward - 1 / reward, the donation 1 / the sink nothing; the tail
//       is V37F || V37N || (V37D) || V37C; shape stable across the fixpoint.
//   E3  receive-side rule on the maps + a REAL OwedLedger: credit {finder: P},
//       net at FOUND, FINALIZE books nothing more (no double pay, paid ==
//       credited - outstanding); refusals: a finder claim on a NON-empty cut,
//       no V37N base, malformed kind, a coinbase under-paying the finder, a
//       coinbase paying a known other payee instead.
//   E4  REAL assembled blocks (provider over the C4 capture), fee ON (fresh
//       pool) and OFF (seeded owed): V37F on chain, the finder output maps from
//       the block alone and books net; the canonical coinbase check rebuilt
//       from the ON-CHAIN V37F matches byte for byte, a FORGED finder (V37F
//       rewritten to another payee) is refused by the canonical check AND by
//       the booking (unmapped output).
//   E5  NON-EMPTY cut unchanged: a block whose cut credits work is byte-
//       identical with and without the finder armed, and equal to the golden
//       minted on the base tree (fee ON and OFF).
//   E6  the widest payload rbind + V37F + V37N + V37D + V37P + V37C = 220 B
//       assembles and every field parses back.
//
// RED on the base (PAY-NOW #1787 without this rule): the BASE branch builds
// the same empty-cut blocks and the "finder is paid" checks FAIL with the
// measured donation / sink amount; the non-empty goldens PASS there.
// ---------------------------------------------------------------------------
#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "impl/xmr/coin/xmr_derivation.hpp"
#include "impl/xmr/coin/xmr_keccak_midstate.hpp"
#include "impl/xmr/native/consensus/xmr_block_parse.hpp"
#include "impl/xmr/native/template/xmr_monerod_miner_data.hpp"
#include "impl/xmr/template/xmr_block_assembly.hpp"

#include "c2pool/v37/xmr/xmr_coinbase_authority.hpp"
#include "c2pool/v37/xmr/xmr_credit_cut.hpp"
#include "c2pool/v37/xmr/xmr_fee_model.hpp"
#include "c2pool/v37/xmr/xmr_o2_settlement_fixture.hpp"
#include "c2pool/v37/xmr/xmr_o2_settlement_provider.hpp"
#include "c2pool/v37/xmr/xmr_paynow.hpp"
#include "c2pool/v37/xmr/xmr_settlement_coinbase_shape.hpp"
#ifdef C2POOL_V37_XMR_ECUT_FINDER
#define ECUT_FIX 1
static_assert(::c2pool::xmr::assembly::FINDER_FIELD_BYTES == c2pool::v37n::xmr::paynow::kFinderFieldBytes,
              "impl-tree FINDER_FIELD_BYTES must mirror paynow::kFinderFieldBytes (69)");
#else
#define ECUT_FIX 0
#endif

#include "xmr_c4_parity_golden.hpp"

using namespace c2pool::xmr::native;

namespace o2     = c2pool::v37n::xmr::o2;
namespace asm_   = c2pool::xmr::assembly;
namespace credit = c2pool::v37n::xmr::credit;
namespace auth   = c2pool::v37n::xmr::authority;
namespace fee    = c2pool::v37n::xmr::fee;
namespace pn     = c2pool::v37n::xmr::paynow;
namespace x6     = ::v37::xmr::settle;
namespace st     = c2pool::v37n::settle;
namespace G4     = c2pool::xmr::native::golden_c4;
using Amounts = std::map<::v37::bytes32, long long>;

namespace {

int g_fail = 0, g_checks = 0;
#define CHECK(cond, ...)                                       \
    do {                                                       \
        const bool _ok = (cond);                               \
        ++g_checks;                                            \
        if (!_ok) ++g_fail;                                    \
        std::printf("  [%s] ", _ok ? "PASS" : "FAIL");         \
        std::printf(__VA_ARGS__);                              \
        std::printf("\n");                                     \
    } while (0)

constexpr fee::DonationNet kNet = fee::DonationNet::Regtest;
constexpr std::uint64_t    kReward = 600000000000ull + 12345ull;
const std::uint32_t        LANE_CHAIN = 0x0000ABCDu;

std::array<std::uint8_t, 32> point_of(std::uint8_t k) {
    ::xmr::coin::SecretKey sec{};
    sec.data()[0] = k;
    ::xmr::coin::PublicKey pub{};
    if (!::xmr::coin::secret_key_to_public_key(sec, pub)) return {};
    std::array<std::uint8_t, 32> out{};
    std::memcpy(out.data(), pub.data(), 32);
    return out;
}
::v37::ScriptRef ref_of(std::uint8_t k) { return ::v37::xmr::make_xmr_std(point_of(k), point_of(static_cast<std::uint8_t>(k + 100))); }
::v37::bytes32 id_of(const ::v37::ScriptRef& r) { return ::v37::xmr::xmr_identity_key(r); }
std::string hex(const std::uint8_t* p, std::size_t n) {
    static const char* d = "0123456789abcdef"; std::string s;
    for (std::size_t i = 0; i < n; ++i) { s += d[p[i] >> 4]; s += d[p[i] & 15]; }
    return s;
}
std::string blob_digest(const std::vector<std::uint8_t>& b) {
    const auto h = ::xmr::coin::keccak256(b.data(), b.size());
    return hex(reinterpret_cast<const std::uint8_t*>(h.data()), 32);
}
credit::CreditCut fixture_cut() {
    credit::CreditCut c;
    c.next_pos = 0x0000000000BC614Eull;
    for (std::size_t i = 0; i < 32; ++i) c.spine_digest[i] = static_cast<std::uint8_t>(0xA0 + i);
    return c;
}
std::uint64_t pm_get(const Amounts& m, const ::v37::bytes32& k) { auto it = m.find(k); return it == m.end() ? 0 : static_cast<std::uint64_t>(it->second); }

// The finder of every empty-cut block below (the building node's own payee).
const ::v37::ScriptRef& finder_ref() { static const ::v37::ScriptRef r = ref_of(21); return r; }
const ::v37::ScriptRef& forger_ref() { static const ::v37::ScriptRef r = ref_of(22); return r; }

// ---- the settlement source over one context (fee model ON / OFF) ----------
struct SrcCase {
    st::OwedLedger L{7};
    std::map<::v37::bytes32, ::v37::ScriptRef> refs;
    o2::XmrCoinbaseContext ctx;
    explicit SrcCase(bool fee_on) {
        refs[fee::donation_identity(kNet)] = fee::donation_ref(kNet);
        ctx.monero_major_version = 16; ctx.height = 1234; ctx.base_reward = kReward; ctx.fees = 0; ctx.chain_id = 7;
        ctx.lane_commitment = L.owed_digest();
        if (fee_on) {
            ctx.residual_sink = fee::donation_ref(kNet); ctx.residual_sink_identity = fee::donation_identity(kNet);
            ctx.fixed = {fee::donation_marker(kNet)};
        } else {
            const auto S = ref_of(77); ctx.residual_sink = S; ctx.residual_sink_identity = id_of(S);
        }
        ctx.h_min = 0; ctx.output_cap = 64;
        ctx.has_credit_cut = true; ctx.credit_cut = fixture_cut();
        ctx.has_paynow = true;           // the view at the cut exists ...
        ctx.paynow_payees.clear();       // ... and credits NOBODY: the empty cut
    }
    o2::PayOfFn pay_of() const {
        const auto m = refs;
        return [m](const ::v37::bytes32& k) {
            auto it = m.find(k); if (it != m.end()) return it->second;
            ::v37::ScriptRef r; r.kind = ::v37::ScriptKind::RAW; return r; };
    }
};

// ---- REAL assembled blocks: the provider over the C4 monerod capture ------
struct LaneFixture {
    o2::XmrOwedFixture      ledger{static_cast<::v37::ChainId>(LANE_CHAIN)};
    o2::XmrSettlementConfig scfg;
    std::vector<st::WeightedPayee> wp;
    LaneFixture(bool fee_on, bool seed) {
        const auto P2 = point_of(2);
        const ::v37::ScriptRef r[3] = {::v37::xmr::make_xmr_std(point_of(1), P2), ::v37::xmr::make_xmr_std(point_of(3), P2),
                                       ::v37::xmr::make_xmr_std(point_of(5), P2)};
        const std::uint64_t owed[3] = {3'000'000'000ull, 2'000'000'000ull, 1'000'000'000ull};
        for (int i = 0; i < 3; ++i) {
            const ::v37::bytes32 k = seed ? ledger.seed_owed(r[i], owed[i]) : id_of(r[i]);
            st::WeightedPayee w; w.key = k; w.weight = ::v37::U256(static_cast<std::uint64_t>(i + 1)); w.pay = r[i];
            wp.push_back(w);
        }
        scfg.h_min = 0;
        scfg.output_cap = 0;
        if (fee_on) {
            scfg.residual_sink = fee::donation_ref(kNet);
            scfg.residual_sink_identity = fee::donation_identity(kNet);
            scfg.fixed = {fee::donation_marker(kNet)};
        } else {
            scfg.set_residual_sink_std(point_of(4), P2);
        }
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

enum class Cut { None, Empty, Work };   // no pay-now view / empty view / view with the three payees

struct Built {
    LaneFixture                                        lane;
    CannedTransport                                    tx{G4::MD_RAW_JSON};
    tmpl::MonerodMinerDataSource                       src{tx};
    std::unique_ptr<o2::XmrSettlementTemplateProvider> provider;
    o2::SettlementSnapshot                             snap;
    asm_::BlockBytes                                   bytes;
    bool                                               ok = false;
    std::string                                        why;
    Built(bool fee_on, bool seed, Cut cut, std::optional<::v37::ScriptRef> finder) : lane(fee_on, seed) {
        lane.scfg.credit_cut_source = [](std::uint64_t& P, ::v37::bytes32& dg) {
            const credit::CreditCut c = fixture_cut(); P = c.next_pos; dg = c.spine_digest; return true; };
        if (cut != Cut::None) {
            const auto wp = cut == Cut::Work ? lane.wp : std::vector<st::WeightedPayee>{};
            // the daemon's source: true = the view at the cut exists (possibly empty)
            lane.scfg.paynow_source = [wp](std::uint64_t, const ::v37::bytes32&, std::vector<st::WeightedPayee>& out) {
                out = wp; return true; };
        }
#if ECUT_FIX
        lane.scfg.ecut_finder = finder;
#else
        (void)finder;
#endif
        if (!src.poll(&why)) { why = "daemon arm did not parse the capture: " + why; return; }
        provider = std::make_unique<o2::XmrSettlementTemplateProvider>(src, lane.ledger, lane.scfg, 0);
        if (!provider->refresh()) { why = provider->last_error(); return; }
        snap = provider->current();
        if (!snap.valid || !snap.tpl) { why = "no template"; return; }
        ok = snap.tpl->materialize(0, bytes, &why);
    }
};

struct Parsed_ { x6::ReceivedCoinbase got; bool ok = false; };
Parsed_ parse_(const std::vector<std::uint8_t>& blob, const asm_::BlockBytes& b) {
    Parsed_ p; std::uint64_t h = 0; std::size_t used = 0;
    p.ok = asm_::parse_coinbase_prefix(blob.data() + b.miner_tx_offset, b.miner_tx_size, p.got, &h, &used);
    return p;
}

auth::CoinbaseBooking decode(const Built& x, const std::vector<std::uint8_t>& blob, bool fee_on) {
    std::vector<::v37::bytes32> cands{x.lane.ledger.ledger().owed_digest()};
    const auto keys = x.lane.ledger.keys();
    if (fee_on) return auth::decode_lane_coinbase_fee(blob, LANE_CHAIN, cands, keys, x.lane.ledger.pay_of(), kNet);
    return auth::decode_lane_coinbase(blob, LANE_CHAIN, cands, keys, x.lane.scfg.residual_sink,
                                      x.lane.scfg.residual_sink_identity, x.lane.ledger.pay_of());
}

// ---------------------------------------------------------------------------
// E5 (both trees): a cut that credits work is byte-identical to the base tree.
// Goldens: keccak256(miner_tx) of the base tree's block (53d8228fa + PAY-NOW);
// the miner_tx is a pure function of the capture + ledger (the header's
// timestamp is not, so the full blob is compared within one run only).
const char* kGoldenWorkFeeOff = "1a9225c45708bc260c6cd3f6357c4ef6d519c9c0f1e382a1060b1d067f7cda45";
const char* kGoldenWorkFeeOn  = "928bbe617a68d3068179a1efd293d23bd0cd85fe38c68aea4029112bfac869f0";
void suite_nonempty_unchanged() {
    std::printf("== E5. NON-EMPTY cut: byte-identical to the base (finder armed or not) ==\n");
    for (int f = 0; f < 2; ++f) {
        const bool fee_on = f == 1;
        Built plain(fee_on, true, Cut::Work, std::nullopt), armed(fee_on, true, Cut::Work, finder_ref());
        CHECK(plain.ok && armed.ok, "fee %s: both blocks build: %s", fee_on ? "ON" : "OFF", plain.ok ? (armed.ok ? "ok" : armed.why.c_str()) : plain.why.c_str());
        if (!(plain.ok && armed.ok)) continue;
        auto mtx = [](const Built& x) {
            return std::vector<std::uint8_t>(x.bytes.full_blob.begin() + static_cast<std::ptrdiff_t>(x.bytes.miner_tx_offset),
                                             x.bytes.full_blob.begin() + static_cast<std::ptrdiff_t>(x.bytes.miner_tx_offset + x.bytes.miner_tx_size));
        };
        const std::string d = blob_digest(mtx(plain));
        std::printf("    fee %s work-cut block keccak(miner_tx) = %s (%zu B, %zu outputs)\n", fee_on ? "ON" : "OFF", d.c_str(),
                    plain.bytes.miner_tx_size, plain.snap.tpl->outputs().size());
        CHECK(mtx(plain) == mtx(armed), "fee %s: a cut WITH work: the finder never changes a coinbase byte (%zu B)",
              fee_on ? "ON" : "OFF", plain.bytes.miner_tx_size);
        CHECK(d == (fee_on ? kGoldenWorkFeeOn : kGoldenWorkFeeOff), "fee %s: == the base tree's golden block", fee_on ? "ON" : "OFF");
        const Parsed_ p = parse_(armed.bytes.full_blob, armed.bytes);
        CHECK(p.ok && pn::parse(p.got.tx_extra).has_value(), "fee %s: pay-now (V37N) armed as before", fee_on ? "ON" : "OFF");
    }
}

#if ECUT_FIX
// ---------------------------------------------------------------------------
std::vector<std::uint8_t> payload(bool v37f, std::optional<std::uint64_t> v37n, bool v37d, const ::v37::bytes32* tag, bool cut) {
    std::vector<std::uint8_t> p(14, 0x00);
    p[0] = 0xDE; p[1] = 0xAD; p[2] = 0xBE; p[3] = 0xEF;
    if (v37f) { const auto t = pn::encode_finder_field(finder_ref());    p.insert(p.end(), t.begin(), t.end()); }
    if (v37n) { const auto t = pn::encode_tail(*v37n);                   p.insert(p.end(), t.begin(), t.end()); }
    if (v37d) { const auto t = fee::encode_donation_owed_tail(424242);   p.insert(p.end(), t.begin(), t.end()); }
    if (tag)  { const auto t = credit::encode_pool_tag_field(*tag);      p.insert(p.end(), t.begin(), t.end()); }
    if (cut)  { const auto t = credit::encode_tail(fixture_cut());       p.insert(p.end(), t.begin(), t.end()); }
    return p;
}
void suite_codec() {
    std::printf("== E1. codec: V37F | V37N | V37D | V37P | V37C ==\n");
    ::v37::bytes32 T{}; T[0] = 0x77;
    CHECK(pn::encode_finder_field(finder_ref()).size() == pn::kFinderFieldBytes, "V37F field is %zu bytes", pn::kFinderFieldBytes);
    for (int m = 0; m < 4; ++m) {
        const bool d = m & 1, t = m & 2;
        const auto p = payload(true, 5, d, t ? &T : nullptr, true);
        const auto f = pn::parse_finder_payload(p);
        CHECK(f && *f == finder_ref() && pn::parse_payload(p) == std::optional<std::uint64_t>(5) &&
                  fee::parse_donation_owed_payload(p).has_value() == d && credit::parse_tail(p).has_value(),
              "[..|V37F|V37N%s%s|V37C]: finder, base, V37D, V37C all read back", d ? "|V37D" : "", t ? "|V37P" : "");
    }
    CHECK(!pn::parse_finder_payload(payload(false, 5, true, &T, true)), "no V37F -> no finder (every non-empty-cut block)");
    CHECK(!pn::parse_finder_payload(payload(true, std::nullopt, true, nullptr, true)) &&
              !pn::finder_magic_present(payload(true, std::nullopt, true, nullptr, true)),
          "V37F without V37N is never read (the field is located only right before V37N)");
    auto bad = payload(true, 5, true, nullptr, true);
    bad[14 + 4] = 0x01;   // kind byte -> P2SH
    CHECK(pn::finder_magic_present(bad) && !pn::parse_finder_payload(bad), "a non-XMR kind byte: magic present, finder unreadable (malformed)");
}

// ---------------------------------------------------------------------------
void suite_source() {
    std::printf("== E2. settlement source, empty cut: the finder is paid ==\n");
    for (int f = 0; f < 2; ++f) {
        const bool fee_on = f == 0;
        SrcCase c(fee_on);
        c.ctx.ecut_finder = finder_ref();
        std::string why;
        auto src = o2::XmrOwedSettlementSource::build(c.L, c.pay_of(), c.ctx, kReward, &why);
        CHECK(src != nullptr, "fee %s: source builds: %s", fee_on ? "ON" : "OFF", why.empty() ? "ok" : why.c_str());
        if (!src) continue;
        const std::uint64_t B = fee_on ? fee::kDonationDustPico : 0;
        CHECK(src->paynow_on() && src->ecut_finder() && *src->ecut_finder() == finder_ref() && src->paynow_base() == B,
              "fee %s: empty-cut finder armed, V37N base = %llu", fee_on ? "ON" : "OFF", (unsigned long long)src->paynow_base());
        std::vector<std::uint8_t> want = pn::encode_finder_field(finder_ref());
        const auto n = pn::encode_tail(B); want.insert(want.end(), n.begin(), n.end());
        if (fee_on) { const auto d = fee::encode_donation_owed_tail(0); want.insert(want.end(), d.begin(), d.end()); }
        const auto cc = credit::encode_tail(fixture_cut()); want.insert(want.end(), cc.begin(), cc.end());
        CHECK(src->extra_nonce_tail() == want, "fee %s: tail == V37F || V37N(%llu)%s || V37C byte for byte (%zu B)", fee_on ? "ON" : "OFF",
              (unsigned long long)B, fee_on ? " || V37D(0)" : "", want.size());
        for (std::uint64_t R : std::vector<std::uint64_t>{kReward, kReward + 777777ull}) {
            const auto pm = src->payout_map_at(R);
            const std::uint64_t fnd = pm_get(pm, id_of(finder_ref()));
            const std::uint64_t sink = pm_get(pm, c.ctx.residual_sink_identity);
            CHECK(src->shape_matches_at(R) && fnd == R - B && sink == B && pm.size() == (fee_on ? 2u : 1u),
                  "fee %s @ reward %llu: finder %llu (= reward - %llu), %s %llu, %zu outputs, shape stable", fee_on ? "ON" : "OFF",
                  (unsigned long long)R, (unsigned long long)fnd, (unsigned long long)B, fee_on ? "donation" : "sink",
                  (unsigned long long)sink, pm.size());
        }
        // no finder configured -> master's residual shape, no V37F / V37N
        SrcCase c0(fee_on);
        auto s0 = o2::XmrOwedSettlementSource::build(c0.L, c0.pay_of(), c0.ctx, kReward, &why);
        CHECK(s0 && !s0->paynow_on() && !s0->ecut_finder() && !pn::parse_payload(s0->extra_nonce_tail()) &&
                  pm_get(s0->payout_map(), c0.ctx.residual_sink_identity) == kReward,
              "fee %s: no finder configured -> the whole reward to the %s, no V37F/V37N (master's shape)", fee_on ? "ON" : "OFF",
              fee_on ? "donation" : "sink");
    }
}

// ---------------------------------------------------------------------------
void suite_receive() {
    std::printf("== E3. receive-side rule + a real OwedLedger ==\n");
    const ::v37::bytes32 F = id_of(finder_ref()), D = fee::donation_identity(kNet);
    const std::uint64_t B = 1, P = kReward - B;
    // the chain view of the fee-ON empty-cut block: finder output P, donation output 1 (coverage)
    Amounts credit_m;                           // the fold at an EMPTY cut
    Amounts payout{{F, static_cast<long long>(P)}};
    const long long sink_total = 1;
    std::string w; ::v37::bytes32 fid{};
    CHECK(pn::apply_empty_cut_finder(finder_ref(), false, B, kReward, credit_m, &w, &fid) && fid == F &&
              credit_m.size() == 1 && credit_m.at(F) == static_cast<long long>(P),
          "empty fold + V37F -> credit { finder : total - B = %llu }", (unsigned long long)P);
    const Amounts gross_credit = credit_m, gross_payout = payout;
    const auto r = pn::net_booking(B, kReward, credit_m, payout, sink_total, D, 1);
    CHECK(r.ok && r.alloc.size() == 1 && r.alloc.at(F) == static_cast<long long>(P) && credit_m.empty() && payout.empty(),
          "net_booking: the finder's pay-now %lld nets its credit AND payout to 0", r.alloc.count(F) ? r.alloc.at(F) : -1);
    st::OwedLedger L(7);
    L.on_block_found("b1", credit_m, payout);
    L.on_block_finalized("b1", 1);
    const long long outstanding = L.finalW().count(F) ? L.finalW().at(F) : 0;
    long long eo_min = 0; for (const auto& [k, v] : L.effective_owed_all()) if (v < eo_min) eo_min = v;
    CHECK(outstanding == 0 && eo_min == 0 && static_cast<long long>(P) == static_cast<long long>(P) - outstanding,
          "FINALIZE: paid %llu == credited %llu - outstanding %lld; EffectiveOwed min %lld (no double pay)",
          (unsigned long long)P, (unsigned long long)P, outstanding, eo_min);
    {
        st::OwedLedger G(7);
        G.on_block_found("b1", gross_credit, gross_payout); G.on_block_finalized("b1", 1);
        long long gmin = 0; for (const auto& [k, v] : G.effective_owed_all()) if (v < gmin) gmin = v;
        const long long gfin = G.finalW().count(F) ? G.finalW().at(F) : 0;
        std::printf("    (contrast) GROSS booking: finalW[finder]=%lld eo_min=%lld\n", gfin, gmin);
    }
    // refusals (maps untouched)
    {
        Amounts c{{F, 5}};
        CHECK(!pn::apply_empty_cut_finder(finder_ref(), false, B, kReward, c, &w) && c.size() == 1 && c.at(F) == 5,
              "a V37F claim on a NON-empty cut is REFUSED: %s", w.c_str());
    }
    {
        Amounts c;
        CHECK(!pn::apply_empty_cut_finder(finder_ref(), false, std::nullopt, kReward, c, &w) && c.empty(), "V37F without a V37N base is REFUSED: %s", w.c_str());
    }
    {
        Amounts c;
        CHECK(!pn::apply_empty_cut_finder(std::nullopt, true, B, kReward, c, &w) && c.empty(), "a malformed V37F is REFUSED: %s", w.c_str());
    }
    {
        Amounts c;
        ::v37::ScriptRef junk = finder_ref(); junk.payload[0] ^= 0xFF; junk.payload[31] = 0xFF;
        const bool bad_point = !::v37::xmr::xmr_ref_valid(junk);
        CHECK(!bad_point || (!pn::apply_empty_cut_finder(junk, false, B, kReward, c, &w) && c.empty()),
              "a finder payee that is not a valid XMR point is REFUSED: %s", bad_point ? w.c_str() : "(mutation stayed a valid point)");
    }
    {   // the coinbase pays the finder 1 piconero less than the pool
        Amounts c; Amounts p{{F, static_cast<long long>(P) - 1}};
        (void)pn::apply_empty_cut_finder(finder_ref(), false, B, kReward, c, &w);
        const auto rr = pn::net_booking(B, kReward, c, p, 2, D, 1);
        CHECK(!rr.ok, "a coinbase under-paying its committed finder by 1 piconero is REFUSED: %s", rr.why.c_str());
    }
    {   // the coinbase pays a KNOWN other payee (a forger) the pool, the finder nothing
        Amounts c; Amounts p{{id_of(forger_ref()), static_cast<long long>(P)}};
        (void)pn::apply_empty_cut_finder(finder_ref(), false, B, kReward, c, &w);
        const auto rr = pn::net_booking(B, kReward, c, p, 1, D, 1);
        CHECK(!rr.ok, "a coinbase paying another (known) payee instead of the committed finder is REFUSED: %s", rr.why.c_str());
    }
    {   // no V37F: a no-op (pay-now as before)
        Amounts c; CHECK(pn::apply_empty_cut_finder(std::nullopt, false, B, kReward, c, &w) && c.empty(), "no V37F -> no-op (non-empty-cut blocks unchanged)");
    }
}

// ---------------------------------------------------------------------------
void suite_blocks() {
    std::printf("== E4. REAL assembled empty-cut blocks: V37F, booking, canonical check, forgery ==\n");
    for (int f = 0; f < 2; ++f) {
        const bool fee_on = f == 0;
        const bool seed = !fee_on;   // fee ON: a FRESH pool (no owed); fee OFF: seeded owed (6e9)
        const char* tag = fee_on ? "fee ON, fresh pool" : "fee OFF, owed 6e9";
        Built b(fee_on, seed, Cut::Empty, finder_ref());
        CHECK(b.ok, "%s: empty-cut block builds + materializes: %s", tag, b.ok ? "ok" : b.why.c_str());
        if (!b.ok) continue;
        const std::uint64_t B = (fee_on ? fee::kDonationDustPico : 0) + (seed ? 6'000'000'000ull : 0);
        const Parsed_ p = parse_(b.bytes.full_blob, b.bytes);
        CHECK(p.ok && pn::parse_finder(p.got.tx_extra) == std::optional<::v37::ScriptRef>(finder_ref()) &&
                  pn::parse(p.got.tx_extra) == std::optional<std::uint64_t>(B),
              "%s: the block's 0x02 carries V37F(finder) and V37N base %llu", tag, (unsigned long long)B);
        const auto bk = decode(b, b.bytes.full_blob, fee_on);
        const ::v37::bytes32 F = id_of(finder_ref());
        CHECK(bk.ok && bk.ecut_finder && pm_get(bk.payout, F) == bk.total - B,
              "%s: every output maps from the block alone; finder paid %llu = total %llu - B (%s)", tag,
              (unsigned long long)pm_get(bk.payout, F), (unsigned long long)bk.total, bk.ok ? "ok" : bk.why.c_str());
        if (fee_on) CHECK(bk.ok && !bk.out_amount.empty() && bk.out_amount.back() == 1 && bk.out_identity.back() == fee::donation_identity(kNet),
                          "%s: the donation output LAST carries only its 1-piconero marker", tag);
        else CHECK(bk.ok && bk.sink_total == 0, "%s: the residual sink gets nothing (sink_total %lld)", tag, bk.sink_total);
        if (bk.ok) {
            Amounts credit_m, payout = bk.payout; std::string w;
            const ::v37::bytes32 sink_id = fee_on ? fee::donation_identity(kNet) : b.lane.scfg.residual_sink_identity;
            const bool ap = pn::apply_empty_cut_finder(bk.ecut_finder, bk.ecut_finder_malformed, bk.paynow_base, bk.total, credit_m, &w);
            const auto r = pn::net_booking(bk.paynow_base, bk.total, credit_m, payout, bk.sink_total, sink_id, fee_on ? 1 : 0);
            bool owed_left = true;
            if (seed) for (const auto& wpp : b.lane.wp) owed_left = owed_left && payout.count(wpp.key);
            CHECK(ap && r.ok && r.netted == static_cast<long long>(bk.total - B) && credit_m.empty() && !payout.count(F) && owed_left,
                  "%s: booked NET: finder credit/payout netted %lld, the owed takes stay the payout (%s)", tag, r.netted,
                  r.ok ? (ap ? "ok" : w.c_str()) : r.why.c_str());
        }
        // THE CANONICAL CHECK: the ACCEPT rebuild from the ON-CHAIN V37F finder
        const auto nf = credit::extra_nonce_field(p.got.tx_extra);
        auto rebuild = [&](const ::v37::ScriptRef& fr) {
            x6::CoinbaseInputs in = b.snap.tpl->coinbase_inputs();
            if (nf) in.extra_nonce = *nf;
            const ::v37::bytes32 fid = id_of(fr);
            in.paynow_at = [fr, fid](std::uint64_t budget) { x6::PayNowEntry e; e.pay = fr; e.identity = fid; e.eb = budget; return std::vector<x6::PayNowEntry>{e}; };
            in.paynow_n = 1;
            return in;
        };
        const auto m_ok = x6::canonical_coinbase_matches(rebuild(*pn::parse_finder(p.got.tx_extra)), p.got);
        CHECK(m_ok.matches, "%s: canonical check rebuilt from the ON-CHAIN V37F matches byte for byte %s", tag, m_ok.reason.c_str());
        const auto m_bad = x6::canonical_coinbase_matches(rebuild(forger_ref()), p.got);
        CHECK(!m_bad.matches, "%s: a different finder identity does not reproduce the coinbase: %s", tag, m_bad.reason.c_str());
        // FORGED: rewrite the block's V37F payee to the forger (outputs still pay the real finder)
        std::vector<std::uint8_t> forged = b.bytes.full_blob;
        const std::vector<std::uint8_t> ff = pn::encode_finder_field(finder_ref()), fg = pn::encode_finder_field(forger_ref());
        auto it = std::search(forged.begin() + static_cast<std::ptrdiff_t>(b.bytes.extra_nonce_offset), forged.end(), ff.begin(), ff.end());
        const bool located = it != forged.end();
        if (located) std::copy(fg.begin(), fg.end(), it);
        const Parsed_ pf = parse_(forged, b.bytes);
        const auto nff = pf.ok ? credit::extra_nonce_field(pf.got.tx_extra) : std::nullopt;
        bool canon_refused = false;
        if (pf.ok && nff) {
            if (const auto claimed = pn::parse_finder(pf.got.tx_extra)) {
                x6::CoinbaseInputs in = rebuild(*claimed); in.extra_nonce = *nff;
                canon_refused = !x6::canonical_coinbase_matches(in, pf.got).matches;
            }
        }
        const auto fbk = decode(b, forged, fee_on);
        CHECK(located && pn::parse_finder(pf.got.tx_extra) == std::optional<::v37::ScriptRef>(forger_ref()) && canon_refused,
              "%s: FORGED finder (V37F rewritten to another payee) is REFUSED by the canonical check", tag);
        CHECK(!fbk.ok && fbk.unmapped_outputs >= 1, "%s: ... and by the booking: %s", tag, fbk.why.c_str());
    }
}

// ---------------------------------------------------------------------------
void suite_widest() {
    std::printf("== E6. widest payload rbind + V37F + V37N + V37D + V37P + V37C ==\n");
    namespace akat = ::c2pool::xmr::assembly::kat;
    asm_::AssemblyInputs a;
    a.miner = akat::miner(3000000, 300000, 18000000000000000000ull);
    a.settle = akat::lane_ctx();
    a.settle.residual_sink = fee::donation_ref(kNet);
    a.settle.residual_sink_identity = fee::donation_identity(kNet);
    a.settle.fixed = {fee::donation_marker(kNet)};
    a.mempool = akat::txs(5, 2000, 30000000);
    const ::v37::ScriptRef fr = finder_ref(); const ::v37::bytes32 fid = id_of(fr);
    a.settle.paynow_at = [fr, fid](std::uint64_t budget) { x6::PayNowEntry e; e.pay = fr; e.identity = fid; e.eb = budget; return std::vector<x6::PayNowEntry>{e}; };
    a.settle.paynow_n = 1;
    ::v37::bytes32 T{}; T[3] = 0x44;
    a.extra_nonce_tail = pn::encode_finder_field(fr);
    for (const auto& part : {pn::encode_tail(1), fee::encode_donation_owed_tail(0), credit::encode_pool_tag_field(T), credit::encode_tail(fixture_cut())})
        a.extra_nonce_tail.insert(a.extra_nonce_tail.end(), part.begin(), part.end());
    a.extra_nonce_bind_size = 32;
    a.extra_nonce_bind = [](std::uint32_t en, std::uint8_t* out) { for (int i = 0; i < 32; ++i) out[i] = static_cast<std::uint8_t>(en * 7 + i); return true; };
    std::string why;
    auto t = asm_::XmrBlockAssembler::build(a, &why);
    const std::size_t widest = static_cast<std::size_t>(::c2pool::xmr::EXTRA_NONCE_MAX_SIZE) + ::c2pool::xmr::EXTRA_NONCE_BIND_MAX +
                               asm_::FINDER_FIELD_BYTES + asm_::PAYNOW_TAIL_BYTES + asm_::DONATION_OWED_TAIL_BYTES +
                               asm_::POOL_TAG_FIELD_BYTES + asm_::CREDIT_CUT_TAIL_BYTES;
    CHECK(t != nullptr && widest <= 255, "the widest payload assembles (bound %zu <= 255): %s", widest, t ? "ok" : why.c_str());
    if (!t) return;
    asm_::BlockBytes b;
    CHECK(t->materialize(5, b, &why), "materializes (0x02 payload %zu B)", b.extra_nonce_size);
    x6::ReceivedCoinbase rc; std::uint64_t h = 0; std::size_t used = 0;
    const bool pp = asm_::parse_coinbase_prefix(b.full_blob.data() + b.miner_tx_offset, b.miner_tx_size, rc, &h, &used);
    ::v37::bytes32 got{};
    const auto nf = credit::extra_nonce_field(rc.tx_extra);
    CHECK(pp && pn::parse_finder(rc.tx_extra) == std::optional<::v37::ScriptRef>(fr) && pn::parse(rc.tx_extra) == std::optional<std::uint64_t>(1) &&
              fee::parse_donation_owed(rc.tx_extra).has_value() && nf && credit::parse_pool_tag_payload(*nf, &got) == credit::PoolTagParse::Present &&
              got == T && credit::parse_from_tx_extra(rc.tx_extra) == std::optional<credit::CreditCut>(fixture_cut()),
          "every field reads back from the block's own bytes");
    std::uint64_t to_f = 0; for (const auto& o : t->outputs()) if (o.identity == fid) to_f += o.amount;
    CHECK(to_f == t->reward() - 1, "assembled: finder paid reward - 1 = %llu", (unsigned long long)to_f);
    const auto shp = o2::inspect_kfair_coinbase(*t, a.settle.lane_commitment, 5);
    CHECK(shp.kfair_order, "the K_fair coinbase shape gate ACCEPTS the finder output: %s", shp.why.empty() ? "ok" : shp.why.c_str());
}
#else
// ---------------------------------------------------------------------------
void suite_base() {
    std::printf("== BASE: PAY-NOW without the empty-cut finder rule ==\n");
    for (int f = 0; f < 2; ++f) {
        const bool fee_on = f == 0;
        SrcCase c(fee_on);
        std::string why;
        auto src = o2::XmrOwedSettlementSource::build(c.L, c.pay_of(), c.ctx, kReward, &why);
        if (!src) { CHECK(false, "fee %s: source builds: %s", fee_on ? "ON" : "OFF", why.c_str()); continue; }
        const auto pm = src->payout_map();
        const std::uint64_t fnd = pm_get(pm, id_of(finder_ref())), sink = pm_get(pm, c.ctx.residual_sink_identity);
        const std::uint64_t B = fee_on ? 1 : 0;
        CHECK(fnd == kReward - B, "fee %s empty cut: the finder is paid reward - %llu -- got %llu; the %s got %llu of %llu",
              fee_on ? "ON" : "OFF", (unsigned long long)B, (unsigned long long)fnd, fee_on ? "donation" : "sink",
              (unsigned long long)sink, (unsigned long long)kReward);
    }
    for (int f = 0; f < 2; ++f) {
        const bool fee_on = f == 0;
        Built b(fee_on, !fee_on, Cut::Empty, finder_ref());
        if (!b.ok) { CHECK(false, "real empty-cut block builds: %s", b.why.c_str()); continue; }
        std::uint64_t to_sink = 0;
        for (const auto& o : b.snap.tpl->outputs()) if (o.identity == b.lane.scfg.residual_sink_identity) to_sink += o.amount;
        const Parsed_ p = parse_(b.bytes.full_blob, b.bytes);
        CHECK(false, "fee %s real empty-cut block: no finder output, %s %llu of reward %llu, V37N %s",
              fee_on ? "ON" : "OFF", fee_on ? "donation" : "sink", (unsigned long long)to_sink, (unsigned long long)b.snap.tpl->reward(),
              p.ok && pn::parse(p.got.tx_extra) ? "present" : "absent");
    }
    CHECK(false, "a forged finder identity cannot be refused: no V37F rule on this tree");
}
#endif

}  // namespace

int main() {
    std::printf("v37_xmr_empty_cut_finder_kat (%s)\n", ECUT_FIX ? "fix" : "base");
#if ECUT_FIX
    suite_codec();
    suite_source();
    suite_receive();
    suite_blocks();
    suite_nonempty_unchanged();
    suite_widest();
#else
    suite_base();
    suite_nonempty_unchanged();
#endif
    std::printf("\n%d/%d checks passed -- %s\n", g_checks - g_fail, g_checks, g_fail ? "FAIL" : "ALL PASS");
    return g_fail ? 1 : 0;
}
