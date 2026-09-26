// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// v37_xmr_paynow_lineage_kat -- SAME-BLOCK PAY-NOW on top of POOL-LINEAGE.
//
// Both rules change the lane coinbase's 0x02 tail. A lane block of a pool with
// pay-now armed carries BOTH fields, in ONE canonical order, V37C last:
//
//     [ nonce 4 | rbind? | pad | "V37N" B | "V37D" owed_in? | "V37P" 1 pool_tag | "V37C" P spine ]
//
// and every reader strips the fields after its own from the END. The pool tag
// classifies the block BEFORE anything is booked: another pool's block (or an
// untagged one) is an ordinary Monero block, so its V37N field is never read
// and nothing is ever netted against it.
//
// Suites
//   L1  codec: V37N / V37D / V37P / V37C all read back from one payload (with
//       and without V37D); a malformed V37P makes the V37N read fail CLOSED;
//       pay-now's own untagged layout is unchanged.
//   L2  the settlement source emits the canonical order byte for byte.
//   L3  REAL assembled blocks (monerod arm over the C4 capture, credit cut +
//       pay-now + pool tag armed): OUR block is Own and books net of the
//       committed pay-now (receiver allocation == builder's); another pool's
//       block with a V37N field is Foreign -> ordinary, no V37N read, nothing
//       netted; an untagged pay-now block is ordinary too.
//   L4  the widest payload rbind + V37N + V37D + V37P + V37C = 151 B assembles
//       and every field parses back.
//
// RED on the base (POOL-LINEAGE alone): there is no pay-now there, so this
// file builds its BASE branch and the "lane block carries V37N" check FAILS.
// RED on a conflict-only merge (pay-now's parser not taught the V37P field):
// every "pay-now base reads back through V37P" check FAILS.
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
#include "impl/xmr/native/consensus/xmr_block_parse.hpp"
#include "impl/xmr/native/template/xmr_monerod_miner_data.hpp"
#include "impl/xmr/template/xmr_block_assembly.hpp"

#include "c2pool/v37/xmr/xmr_coinbase_authority.hpp"
#include "c2pool/v37/xmr/xmr_credit_cut.hpp"
#include "c2pool/v37/xmr/xmr_fee_model.hpp"
#include "c2pool/v37/xmr/xmr_o2_settlement_fixture.hpp"
#include "c2pool/v37/xmr/xmr_o2_settlement_provider.hpp"
#include "c2pool/v37/xmr/xmr_pool_tag.hpp"
#include "c2pool/v37/xmr/xmr_settlement_coinbase_shape.hpp"
#if __has_include("c2pool/v37/xmr/xmr_paynow.hpp")
#include "c2pool/v37/xmr/xmr_paynow.hpp"
#define PAYNOW_FIX 1
#else
#define PAYNOW_FIX 0
#endif

#include "xmr_c4_parity_golden.hpp"

using namespace c2pool::xmr::native;

namespace o2      = c2pool::v37n::xmr::o2;
namespace asm_    = c2pool::xmr::assembly;
namespace credit  = c2pool::v37n::xmr::credit;
namespace auth    = c2pool::v37n::xmr::authority;
namespace fee     = c2pool::v37n::xmr::fee;
namespace lineage = c2pool::v37n::xmr::lineage;
namespace x6      = ::v37::xmr::settle;
namespace st      = c2pool::v37n::settle;
namespace G4      = c2pool::xmr::native::golden_c4;
using Amounts = std::map<::v37::bytes32, long long>;

namespace {

int g_fail = 0;
int g_checks = 0;

#define CHECK(cond, ...)                                       \
    do {                                                       \
        const bool _ok = (cond);                               \
        ++g_checks;                                            \
        if (!_ok) ++g_fail;                                    \
        std::printf("  [%s] ", _ok ? "PASS" : "FAIL");         \
        std::printf(__VA_ARGS__);                              \
        std::printf("\n");                                     \
    } while (0)

::v37::bytes32 b32(std::uint8_t seed) { ::v37::bytes32 b{}; for (int i = 0; i < 32; ++i) b[i] = static_cast<std::uint8_t>(seed + i); return b; }

credit::CreditCut fixture_cut() {
    credit::CreditCut c;
    c.next_pos = 0x0000000000BC614Eull;
    for (std::size_t i = 0; i < 32; ++i) c.spine_digest[i] = static_cast<std::uint8_t>(0xA0 + i);
    return c;
}

std::array<std::uint8_t, 32> point_of(std::uint8_t k) {
    ::xmr::coin::SecretKey sec{};
    sec.data()[0] = k;
    ::xmr::coin::PublicKey pub{};
    if (!::xmr::coin::secret_key_to_public_key(sec, pub)) return {};
    std::array<std::uint8_t, 32> out{};
    std::memcpy(out.data(), pub.data(), 32);
    return out;
}

const std::uint32_t LANE_CHAIN = 0x0000ABCDu;

// The lineage KAT's lane fixture (fee model OFF, separate residual sink) plus
// the cut's projected payees = the three seeded owed identities, weights 1:2:3.
struct LaneFixture {
    o2::XmrOwedFixture      ledger{static_cast<::v37::ChainId>(LANE_CHAIN)};
    o2::XmrSettlementConfig scfg;
    std::vector<st::WeightedPayee> wp;
    LaneFixture() {
        // three DISTINCT wallets (a std and a sub address of one wallet decode to one identity on the receive side)
        const auto P1 = point_of(1), P2 = point_of(2), P3 = point_of(3), P4 = point_of(4);
        const ::v37::ScriptRef r[3] = {::v37::xmr::make_xmr_std(P1, P2), ::v37::xmr::make_xmr_std(P3, P2), ::v37::xmr::make_xmr_std(point_of(5), P2)};
        const std::uint64_t owed[3] = {3'000'000'000ull, 2'000'000'000ull, 1'000'000'000ull};
        for (int i = 0; i < 3; ++i) {
            const auto k = ledger.seed_owed(r[i], owed[i]);
            st::WeightedPayee w; w.key = k; w.weight = ::v37::U256(static_cast<std::uint64_t>(i + 1)); w.pay = r[i];
            wp.push_back(w);
        }
        scfg.h_min      = 0;
        scfg.output_cap = 0;
        scfg.set_residual_sink_std(P4, P2);
    }
};

class CannedTransport final : public ::c2pool::xmr::node::IMonerodTransport {
public:
    explicit CannedTransport(std::string body) : body_(std::move(body)) {}
    void rpc_post(const std::string&,
                  std::function<void(const ::c2pool::xmr::node::RpcResponse&)> cb) override {
        ::c2pool::xmr::node::RpcResponse r;
        r.body.assign(body_.begin(), body_.end());
        cb(r);
    }
    void zmq_subscribe(const std::string&,
                       std::function<void(const ::c2pool::xmr::node::ZmqFrame&)>) override {}
private:
    std::string body_;
};

struct Built {
    LaneFixture                                        lane;
    CannedTransport                                    tx{G4::MD_RAW_JSON};
    tmpl::MonerodMinerDataSource                       src{tx};
    std::unique_ptr<o2::XmrSettlementTemplateProvider> provider;
    o2::SettlementSnapshot                             snap;
    asm_::BlockBytes                                   bytes;
    bool                                               ok = false;
    std::string                                        why;
    Built(std::optional<::v37::bytes32> tag, bool paynow) {
        lane.scfg.credit_cut_source = [](std::uint64_t& P, ::v37::bytes32& dg) {
            const credit::CreditCut c = fixture_cut(); P = c.next_pos; dg = c.spine_digest; return true; };
        lane.scfg.pool_tag = tag;
#if PAYNOW_FIX
        if (paynow) {
            const auto wp = lane.wp;
            lane.scfg.paynow_source = [wp](std::uint64_t, const ::v37::bytes32&, std::vector<st::WeightedPayee>& out) {
                out = wp; return !out.empty(); };
        }
#else
        (void)paynow;
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
Parsed_ parse_(const asm_::BlockBytes& b) {
    Parsed_ p; std::uint64_t h = 0; std::size_t used = 0;
    p.ok = asm_::parse_coinbase_prefix(b.full_blob.data() + b.miner_tx_offset, b.miner_tx_size, p.got, &h, &used);
    return p;
}

#if PAYNOW_FIX
namespace pn = c2pool::v37n::xmr::paynow;

std::vector<std::uint8_t> payload_of(std::optional<std::uint64_t> v37n, bool v37d, const ::v37::bytes32* tag, bool cut,
                                     std::size_t lead = 14) {
    std::vector<std::uint8_t> p(lead, 0x00);
    if (lead >= 4) { p[0] = 0xDE; p[1] = 0xAD; p[2] = 0xBE; p[3] = 0xEF; }
    if (v37n) { const auto t = pn::encode_tail(*v37n);             p.insert(p.end(), t.begin(), t.end()); }
    if (v37d) { const auto t = fee::encode_donation_owed_tail(424242); p.insert(p.end(), t.begin(), t.end()); }
    if (tag)  { const auto t = credit::encode_pool_tag_field(*tag);   p.insert(p.end(), t.begin(), t.end()); }
    if (cut)  { const auto t = credit::encode_tail(fixture_cut());   p.insert(p.end(), t.begin(), t.end()); }
    return p;
}

// ---------------------------------------------------------------------------
void suite_codec() {
    std::printf("== L1. codec: V37N | V37D | V37P | V37C in one payload ==\n");
    const auto T = b32(0x50);
    constexpr std::uint64_t B = 0x0102030405060708ull;
    for (int v37d = 0; v37d < 2; ++v37d) {
        const auto p = payload_of(B, v37d, &T, true);
        ::v37::bytes32 got{};
        CHECK(pn::parse_payload(p) == std::optional<std::uint64_t>(B), "[..|V37N%s|V37P|V37C]: the pay-now base reads back through V37P",
              v37d ? "|V37D" : "");
        CHECK(credit::parse_pool_tag_payload(p, &got) == credit::PoolTagParse::Present && got == T, "  the pool tag reads back (Present)");
        const auto dn = fee::parse_donation_owed_payload(p);
        CHECK(v37d ? (dn && *dn == 424242) : !dn, "  V37D %s", v37d ? "reads back" : "absent");
        const auto cc = credit::parse_tail(p);
        CHECK(cc && *cc == fixture_cut(), "  V37C still LAST (parse_tail unchanged)");
    }
    CHECK(pn::parse_payload(payload_of(B, true, nullptr, true)) == std::optional<std::uint64_t>(B),
          "untagged [..|V37N|V37D|V37C] (pay-now's own layout) still parses");
    CHECK(!pn::parse_payload(payload_of(std::nullopt, true, &T, true)), "tagged, no V37N -> no pay-now (nullopt)");
    auto pm = payload_of(B, true, &T, true);
    pm[pm.size() - 44 - 37 + 4] = 2;   // V37P version byte
    CHECK(credit::parse_pool_tag_payload(pm) == credit::PoolTagParse::Malformed && !pn::parse_payload(pm) &&
              !fee::parse_donation_owed_payload(pm),
          "malformed V37P (version 2): V37N and V37D reads fail CLOSED (never mis-located)");
}

// ---------------------------------------------------------------------------
void suite_source_order() {
    std::printf("== L2. the settlement source emits V37N | V37D | V37P | V37C ==\n");
    constexpr fee::DonationNet kNet = fee::DonationNet::Regtest;
    constexpr std::uint64_t kReward = 600000000000ull + 12345ull;
    LaneFixture f;
    st::OwedLedger L(7);
    std::map<::v37::bytes32, ::v37::ScriptRef> refs;
    for (const auto& w : f.wp) refs[w.key] = w.pay;
    refs[fee::donation_identity(kNet)] = fee::donation_ref(kNet);
    o2::PayOfFn pay_of = [refs](const ::v37::bytes32& k) {
        auto it = refs.find(k); if (it != refs.end()) return it->second;
        ::v37::ScriptRef r; r.kind = ::v37::ScriptKind::RAW; return r; };
    o2::XmrCoinbaseContext ctx;
    ctx.monero_major_version = 16; ctx.height = 1234; ctx.base_reward = kReward; ctx.fees = 0; ctx.chain_id = 7;
    ctx.lane_commitment = L.owed_digest();
    ctx.residual_sink = fee::donation_ref(kNet); ctx.residual_sink_identity = fee::donation_identity(kNet);
    ctx.fixed = {fee::donation_marker(kNet)}; ctx.h_min = 0; ctx.output_cap = 64;
    ctx.has_credit_cut = true; ctx.credit_cut = fixture_cut();
    ctx.has_paynow = true; ctx.paynow_payees = f.wp;
    const auto T = b32(0x77);
    ctx.has_pool_tag = true; ctx.pool_tag = T;
    std::string why;
    auto src = o2::XmrOwedSettlementSource::build(L, pay_of, ctx, kReward, &why);
    CHECK(src != nullptr && src->paynow_on(), "source builds with pay-now + pool tag + fee model ON: %s", why.empty() ? "ok" : why.c_str());
    if (!src) return;
    const auto tail = src->extra_nonce_tail();
    std::vector<std::uint8_t> want = pn::encode_tail(src->paynow_base());
    for (const auto& part : {fee::encode_donation_owed_tail(0), credit::encode_pool_tag_field(T), credit::encode_tail(fixture_cut())})
        want.insert(want.end(), part.begin(), part.end());
    CHECK(tail == want && tail.size() == 12 + 12 + 37 + 44,
          "tail == V37N(%llu) || V37D(0) || V37P || V37C byte for byte (%zu B)", (unsigned long long)src->paynow_base(), tail.size());
    ::v37::bytes32 got{};
    CHECK(pn::parse_payload(tail) == std::optional<std::uint64_t>(src->paynow_base()) && fee::parse_donation_owed_payload(tail) &&
              credit::parse_pool_tag_payload(tail, &got) == credit::PoolTagParse::Present && got == T && credit::parse_tail(tail),
          "every field reads back from the source's own tail");
}

// ---------------------------------------------------------------------------
void suite_blocks() {
    std::printf("== L3. real assembled blocks: tag classifies BEFORE any pay-now booking ==\n");
    const ::v37::LaneParams lp{};
    const auto TAG_A = lineage::pool_tag_for(LANE_CHAIN, lp, b32(0xA0));
    const auto TAG_B = lineage::pool_tag_for(LANE_CHAIN, lp, b32(0xB0));
    Built a(TAG_A, true), b(TAG_B, true), u(std::nullopt, true), t(TAG_A, false);
    CHECK(a.ok && b.ok && u.ok && t.ok, "four templates build + materialize (A tag+pay-now, B tag+pay-now, untagged pay-now, A tag only): %s",
          !a.ok ? a.why.c_str() : !b.ok ? b.why.c_str() : !u.ok ? u.why.c_str() : !t.ok ? t.why.c_str() : "ok");
    if (!(a.ok && b.ok && u.ok && t.ok)) return;
    // fee OFF, no fixed outputs, every owed take paid in full: B = Σ owed = 6e9.
    const std::uint64_t B = 6'000'000'000ull;
    Parsed_ pa = parse_(a.bytes), pt = parse_(t.bytes);
    CHECK(pa.ok && pt.ok && pn::parse(pa.got.tx_extra) == std::optional<std::uint64_t>(B) && !pn::parse(pt.got.tx_extra),
          "pay-now armed on A (V37N base %llu = the owed takes), absent on the tag-only block", (unsigned long long)B);
    CHECK(pa.ok && pt.ok && pa.got.tx_extra.size() == pt.got.tx_extra.size() + 12 && a.bytes.extra_nonce_size == t.bytes.extra_nonce_size + 12,
          "A vs the tag-only block: 0x02 payload %zu -> %zu B (+12: the V37N field only)", t.bytes.extra_nonce_size, a.bytes.extra_nonce_size);
    const std::uint8_t* ap = a.bytes.full_blob.data() + a.bytes.extra_nonce_offset;
    const std::size_t en = a.bytes.extra_nonce_size;
    const auto fn = pn::encode_tail(B), fp = credit::encode_pool_tag_field(TAG_A), fc = credit::encode_tail(fixture_cut());
    CHECK(en >= 93 && std::memcmp(ap + en - 44, fc.data(), 44) == 0 && std::memcmp(ap + en - 81, fp.data(), 37) == 0 &&
              std::memcmp(ap + en - 93, fn.data(), 12) == 0,
          "A's payload ends V37N | V37P | V37C (fee OFF: no V37D), V37C last");

    std::vector<::v37::bytes32> cands{a.lane.ledger.ledger().owed_digest()};
    const auto keys = a.lane.ledger.keys();
    auto decode = [&](const Built& x, const ::v37::bytes32* tag) {
        return auth::decode_lane_coinbase(x.bytes.full_blob, LANE_CHAIN, cands, keys, a.lane.scfg.residual_sink,
                                          a.lane.scfg.residual_sink_identity, a.lane.ledger.pay_of(), tag);
    };
    // --- OUR block: Own, both fields, booked NET of its pay-now
    const auto own = decode(a, &TAG_A);
    CHECK(own.ok && own.is_lane && own.lineage == lineage::BlockLineage::Own && own.has_credit_cut && own.paynow_base == std::optional<std::uint64_t>(B),
          "OUR tagged pay-now block: Own, lane block, V37N base %llu parsed (%s)", (unsigned long long)B, own.ok ? "ok" : own.why.c_str());
    if (own.ok && own.paynow_base) {
        const std::vector<std::uint64_t> eb = st::split_reward(own.total, a.lane.wp);
        Amounts credit_m, payout = own.payout;
        for (std::size_t i = 0; i < eb.size(); ++i) if (eb[i]) credit_m[a.lane.wp[i].key] += static_cast<long long>(eb[i]);
        const Amounts gross_credit = credit_m;
        const auto r = pn::net_booking(own.paynow_base, own.total, credit_m, payout, own.sink_total, a.lane.scfg.residual_sink_identity, 0);
        bool same = r.ok && !r.alloc.empty();
        const long long owed[3] = {3'000'000'000ll, 2'000'000'000ll, 1'000'000'000ll};
        for (std::size_t i = 0; same && i < a.lane.wp.size(); ++i) {
            const auto& k = a.lane.wp[i].key;
            const long long builder = own.payout.at(k) - owed[i];
            same = r.alloc.count(k) && r.alloc.at(k) == builder && payout.at(k) == owed[i] &&
                   credit_m[k] == gross_credit.at(k) - builder && credit_m[k] >= 0;
        }
        CHECK(same && r.netted > 0 && r.pool == own.total - B,
              "receiver nets exactly the builder's pay-now per payee (netted %lld of pool %llu); payout left == the owed takes%s%s",
              r.netted, (unsigned long long)r.pool, r.ok ? "" : ": ", r.why.c_str());
        if (!same)
            for (std::size_t i = 0; i < a.lane.wp.size(); ++i) {
                const auto& k = a.lane.wp[i].key;
                std::printf("    payee %zu: E_b %lld on-chain %lld alloc %lld\n", i, gross_credit.count(k) ? gross_credit.at(k) : -1,
                            own.payout.count(k) ? own.payout.at(k) : -1, r.alloc.count(k) ? r.alloc.at(k) : -1);
            }
    } else {
        CHECK(false, "receiver net booking not reached (no V37N base on OUR block)");
    }
    // --- another pool's block WITH a V37N field: ordinary, never netted
    const auto foreign = decode(b, &TAG_A);
    CHECK(!foreign.ok && !foreign.is_lane && foreign.lineage == lineage::BlockLineage::Foreign && foreign.lineage_seen_tag == TAG_B &&
              foreign.why.rfind("not-lane:", 0) == 0 && !foreign.paynow_base && foreign.payout.empty() && !foreign.has_credit_cut,
          "pool B's pay-now block seen by pool A: Foreign -> \"not-lane:\", V37N never read, no payout, no cut");
    {
        Amounts c0, p0;
        const auto r0 = pn::net_booking(foreign.paynow_base, foreign.total, c0, p0, foreign.sink_total, a.lane.scfg.residual_sink_identity, 0);
        CHECK(r0.ok && r0.netted == 0 && r0.alloc.empty(), "  net booking of the foreign block is a no-op (netted 0)");
    }
    const auto ungated = decode(b, nullptr);
    CHECK(ungated.is_lane && ungated.paynow_base.has_value(),
          "  (contrast) ungated, pool B's block DOES carry a V37N base %llu: only the tag gate keeps it from being netted",
          ungated.paynow_base ? (unsigned long long)*ungated.paynow_base : 0ull);
    const auto b_own = decode(b, &TAG_B);
    CHECK(b_own.ok && b_own.lineage == lineage::BlockLineage::Own && b_own.paynow_base.has_value(),
          "symmetric: pool B books its own block with its V37N base");
    // --- an untagged pay-now block (pay-now without lineage): ordinary
    const auto old = decode(u, &TAG_A);
    CHECK(!old.ok && !old.is_lane && old.lineage == lineage::BlockLineage::Untagged && !old.paynow_base,
          "an untagged pay-now block: Untagged -> \"not-lane:\", V37N never read");
    // --- a malformed V37P on our pay-now block: strict reject, no V37N
    std::vector<std::uint8_t> mal = a.bytes.full_blob;
    mal[a.bytes.extra_nonce_offset + en - 81 + 4] = 2;
    const auto mk = auth::decode_lane_coinbase(mal, LANE_CHAIN, cands, keys, a.lane.scfg.residual_sink,
                                               a.lane.scfg.residual_sink_identity, a.lane.ledger.pay_of(), &TAG_A);
    CHECK(!mk.is_lane && mk.lineage == lineage::BlockLineage::Malformed && !mk.paynow_base, "V37P version flipped to 2: Malformed -> ordinary, V37N never read");
    // --- the K_fair shape gate ACCEPTs the tagged pay-now template
    const o2::KFairCoinbaseShape sa = o2::inspect_kfair_coinbase(*a.snap.tpl, a.lane.ledger.ledger().owed_digest());
    CHECK(sa.ok && sa.canonical, "shape gate ACCEPTs the tagged pay-now template: %s", sa.ok ? "ok" : sa.why.c_str());
    asm_::BlockBytes a1; std::string w1;
    CHECK(a.snap.tpl->materialize(1, a1, &w1) && std::memcmp(a1.full_blob.data() + a1.extra_nonce_offset + 4, ap + 4, en - 4) == 0,
          "extra_nonce 1: padding + V37N + V37P + V37C untouched");
}

// ---------------------------------------------------------------------------
void suite_widest() {
    std::printf("== L4. widest payload [nonce|rbind 32|pad|V37N|V37D|V37P|V37C] = 151 B ==\n");
    namespace akat = ::c2pool::xmr::assembly::kat;
    asm_::AssemblyInputs a;
    a.miner = akat::miner(3000000, 300000, 18000000000000000000ull);
    a.settle = akat::lane_ctx();
    a.settle.residual_sink = fee::donation_ref();
    a.settle.residual_sink_identity = fee::donation_identity();
    a.settle.fixed = {fee::donation_marker()};
    a.mempool = akat::txs(5, 2000, 30000000);
    for (unsigned char i = 0; i < 4; ++i) {
        x6::OwedEntry e; e.pay = akat::std_ref(); e.owed = 1000000000ull * (i + 1); e.first_eligible = 100 + i;
        e.identity = akat::id_of(static_cast<unsigned char>(0x40 + i));
        a.settle.owed.push_back(e);
    }
    const auto TAG = b32(0x77);
    constexpr std::uint64_t B = 10000000001ull;
    a.extra_nonce_tail = pn::encode_tail(B);
    { const auto d = fee::encode_donation_owed_tail(x6::fold_identity_owed(a.settle)); a.extra_nonce_tail.insert(a.extra_nonce_tail.end(), d.begin(), d.end()); }
    { const auto f = credit::encode_pool_tag_field(TAG); a.extra_nonce_tail.insert(a.extra_nonce_tail.end(), f.begin(), f.end()); }
    { const auto c = credit::encode_tail(fixture_cut()); a.extra_nonce_tail.insert(a.extra_nonce_tail.end(), c.begin(), c.end()); }
    a.extra_nonce_bind_size = 32;
    a.extra_nonce_bind = [](std::uint32_t en, std::uint8_t* out) { for (int i = 0; i < 32; ++i) out[i] = static_cast<std::uint8_t>(en * 7 + i); return true; };
    std::string why;
    auto t = asm_::XmrBlockAssembler::build(a, &why);
    const std::size_t bound = static_cast<std::size_t>(::c2pool::xmr::EXTRA_NONCE_MAX_SIZE) + ::c2pool::xmr::EXTRA_NONCE_BIND_MAX +
                              asm_::PAYNOW_TAIL_BYTES + asm_::DONATION_OWED_TAIL_BYTES + asm_::POOL_TAG_FIELD_BYTES + asm_::CREDIT_CUT_TAIL_BYTES;
    CHECK(t != nullptr && bound == 151, "the widest payload builds (bound 14 + 32 + 12 + 12 + 37 + 44 = %zu): %s", bound, t ? "ok" : why.c_str());
    if (!t) return;
    asm_::BlockBytes b;
    const bool m = t->materialize(5, b, &why);
    CHECK(m && b.extra_nonce_size >= 0x80 && b.full_blob[b.extra_nonce_offset - 3] == 0x02 && b.full_blob[b.extra_nonce_offset - 1] == 0x01,
          "materializes; 0x02 payload %zu B behind a two-byte length varint", b.extra_nonce_size);
    if (!m) return;
    x6::ReceivedCoinbase rc; std::uint64_t h = 0; std::size_t used = 0;
    const bool pp = asm_::parse_coinbase_prefix(b.full_blob.data() + b.miner_tx_offset, b.miner_tx_size, rc, &h, &used);
    CHECK(pp && pn::parse(rc.tx_extra) == std::optional<std::uint64_t>(B) && fee::parse_donation_owed(rc.tx_extra).has_value() &&
              lineage::classify_lineage(rc.tx_extra, TAG) == lineage::BlockLineage::Own && credit::parse_from_tx_extra(rc.tx_extra) == std::optional<credit::CreditCut>(fixture_cut()),
          "V37N base, V37D, V37P (Own) and V37C all read back from the block");
}
#else
void suite_base() {
    std::printf("== BASE: POOL-LINEAGE alone, no pay-now on this tree ==\n");
    const ::v37::LaneParams lp{};
    Built a(lineage::pool_tag_for(LANE_CHAIN, lp, b32(0xA0)), true);
    CHECK(a.ok, "tagged template builds: %s", a.ok ? "ok" : a.why.c_str());
    bool has_n = false;
    if (a.ok) {
        const std::uint8_t* ap = a.bytes.full_blob.data() + a.bytes.extra_nonce_offset;
        for (std::size_t i = 0; i + 4 <= a.bytes.extra_nonce_size; ++i) if (std::memcmp(ap + i, "V37N", 4) == 0) has_n = true;
    }
    CHECK(has_n, "a lane block of this pool carries the V37N pay-now field -- absent (the pool pays its own miners nothing now)");
}
#endif

}  // namespace

int main() {
    std::printf("=== v37_xmr_paynow_lineage_kat (PAY-NOW on POOL-LINEAGE, %s) ===\n", PAYNOW_FIX ? "fix" : "base");
#if PAYNOW_FIX
    suite_codec();
    suite_source_order();
    suite_blocks();
    suite_widest();
#else
    suite_base();
#endif
    std::printf("=== %d/%d checks passed ===\n", g_checks - g_fail, g_checks);
    return g_fail == 0 ? 0 : 1;
}
