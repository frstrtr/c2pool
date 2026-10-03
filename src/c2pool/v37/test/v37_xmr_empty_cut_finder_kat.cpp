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
// finder the pay-now pool (the whole reward, fee model ON or OFF: the donation
// keeps only its 0-amount marker), and the finder payee
// is committed in the block itself ("V37F" || kind || payee[64], right before
// V37N) so every node reproduces the coinbase and the booking from the bytes.
//
//   E1  codec: V37F | V37N | V37D | V37P | V37C read back from one payload;
//       V37F without V37N is not read; a malformed kind is flagged.
//   E2  the settlement source, fee model ON and OFF, empty cut: the finder is
//       paid the whole reward, the donation 0 / the sink nothing; the tail
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
//   E7  CUT-FLOOR (#1803 review): three nodes book one lineage in chain order;
//       the FIRST lane block (P=0, empty, V37F) pays its finder, a later block
//       committing P below the previous lane block's P (P=0 + V37F: the
//       reproducible empty-cut theft) is REFUSED on every node, a restarted
//       node included; a refused block never lowers the floor; a reorg drops
//       the orphan's cut. RED on 272cac0d (no floor: the theft books).
//   E8  PER-JOB FINDER (rulings 09-27): the empty-cut block a job's share
//       submits pays that job's login L; owner-fee job -> owner; subaddress /
//       integrated / invalid login -> donation; never the node payout; a work
//       cut is byte-unchanged. RED on 9d6d3648 (finder = the node payout).
//   E9  FRESH POOL UNDER THE RULES (stagenet attempts 7/8): the daemon's live
//       configuration (anchor rule, DROPS due, fee model, spend floor, drain
//       {1,16,64}, salted ties, V37R, pool_tag, rbind) with NO finalized lane
//       block: every bound job's block pays its finder R - Delta as V37F + V37N,
//       the donation keeps its 0 marker, the booking nets to nothing, another
//       node's recompute calls it canonical. F = 0 and F = 499999999998. RED on
//       master 64c4372df (the default template was served: nobody paid).
//   E10 the `sink-unbacked` alarm counts sink cash only against credit still
//       to be booked: an empty-cut block without V37N and no credit is 0.
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
#include <tuple>
#include <vector>

#include "impl/xmr/coin/xmr_derivation.hpp"
#include "impl/xmr/coin/xmr_keccak_midstate.hpp"
#include "impl/xmr/native/consensus/xmr_block_parse.hpp"
#include "impl/xmr/native/template/xmr_monerod_miner_data.hpp"
#include "impl/xmr/template/xmr_block_assembly.hpp"

#include "c2pool/v37/xmr/xmr_coinbase_authority.hpp"
#include "c2pool/v37/xmr/xmr_coinbase_recompute.hpp"   // E9: the receiver's canonical verdict
#include "c2pool/v37/xmr/xmr_credit_cut.hpp"
#include "c2pool/v37/xmr/xmr_fee_model.hpp"
#include "c2pool/v37/xmr/xmr_o2_settlement_fixture.hpp"
#include "c2pool/v37/xmr/xmr_o2_settlement_provider.hpp"
#include "c2pool/v37/xmr/xmr_paynow.hpp"
#include "c2pool/v37/xmr/relay/xmr_address.hpp"
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
namespace rc     = c2pool::v37n::xmr::recompute;   // E9
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
// E9 "FRESH POOL UNDER THE RULES": the daemon's live configuration (main_v37_xmr.cpp
// with the anchor rule, DROPS due, the spend floor, the drain triple of the test
// networks, salted ties, the V37R total, a pool_tag and --relay-bind rbind), over a
// ledger with NO finalized lane block (anchor none). `seeds` = finalized owed on
// DEMO keys nobody mines for (--owed-demo-amount): the float F the drain repays.
struct LiveRules {
    bool on = false;
    std::vector<std::uint64_t> seeds;
};
st::OwedLedgerRules live_ledger_rules() {
    st::OwedLedgerRules r;
    r.arm_floor = static_cast<long long>(x6::spend_floor(x6::kTailSubsidy));
    r.anchor_cut = true;         // ANCHOR (ruling A 2026-09-29): pay-now pays the view at the anchor
    r.drops_due = true;          // DROPS DUE (A5): on with the anchor
    r.lane_height = true;        // THE DRAIN RULE's ledger bits (lane-rules 23-25 ON)
    r.decay_from_gross = true;
    return r;
}
::v37::bytes32 live_tag() { ::v37::bytes32 t{}; t[0] = 0xE9; t[31] = 0x37; return t; }
const ::v37::ScriptRef& demo_ref(int i) {   // the three DEMO keys of --owed-demo-amount (1x, 2x, 3x)
    static const ::v37::ScriptRef r[3] = {ref_of(61), ref_of(62), ref_of(63)};
    return r[i % 3];
}

struct LaneFixture {
    st::OwedLedger          ext;      // the ledger the fixture wraps (rules fixed at construction)
    o2::XmrOwedFixture      ledger;
    o2::XmrSettlementConfig scfg;
    std::vector<st::WeightedPayee> wp;
    LaneFixture(bool fee_on, bool seed, const LiveRules* live = nullptr)
        : ext(static_cast<::v37::ChainId>(LANE_CHAIN), live && live->on ? live_ledger_rules() : st::OwedLedgerRules{}),
          ledger(ext) {
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
        if (live && live->on) {
            for (std::size_t i = 0; i < live->seeds.size(); ++i) ledger.seed_owed(demo_ref(static_cast<int>(i)), live->seeds[i]);
            scfg.spend_floor = true;                        // main: payout-threshold.md §2-§3
            scfg.drain = o2::DrainRule{1, 16, 64};          // main: drain_rule_of(cfg), the test-network triple
            scfg.kfair_salted_ties = true;                  // main: #1867
            scfg.commit_total = true;                       // main: "V37R" in every lane coinbase
            scfg.pool_tag = live_tag();                     // main: POOL-LINEAGE
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
    Built(bool fee_on, bool seed, Cut cut, std::optional<::v37::ScriptRef> finder, const LiveRules* live = nullptr)
        : lane(fee_on, seed, live) {
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
        if (live && live->on)   // main: --relay-bind rbind writes [extra_nonce 4 | rbind 32] into the 0x02 payload
            provider->set_extra_nonce_bind(32, [](std::uint32_t en, std::uint8_t* b) {
                for (int i = 0; i < 32; ++i) b[i] = static_cast<std::uint8_t>(en * 13 + i); return true; });
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
    const ::v37::bytes32* tag = x.lane.scfg.pool_tag ? &*x.lane.scfg.pool_tag : nullptr;   // E9: the lineage gate, as main
    if (fee_on) return auth::decode_lane_coinbase_fee(blob, LANE_CHAIN, cands, keys, x.lane.ledger.pay_of(), kNet, tag);
    return auth::decode_lane_coinbase(blob, LANE_CHAIN, cands, keys, x.lane.scfg.residual_sink,
                                      x.lane.scfg.residual_sink_identity, x.lane.ledger.pay_of(), tag);
}

// ---------------------------------------------------------------------------
// E5 (both trees): a cut that credits work is byte-identical to the base tree.
// Goldens: keccak256(miner_tx) of the base tree's block (53d8228fa + PAY-NOW;
// the fee-ON golden re-pinned 2026-09-29 for the 0-amount donation marker);
// the miner_tx is a pure function of the capture + ledger (the header's
// timestamp is not, so the full blob is compared within one run only).
const char* kGoldenWorkFeeOff = "1a9225c45708bc260c6cd3f6357c4ef6d519c9c0f1e382a1060b1d067f7cda45";
const char* kGoldenWorkFeeOn  = "f8fc466b8b4dda7c4cc436e7c018f8144d8be75ffe468dd899520ef1975627fb";
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
        const std::uint64_t B = fee_on ? fee::kDonationMarkerPico : 0;
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
        const std::uint64_t B = (fee_on ? fee::kDonationMarkerPico : 0) + (seed ? 6'000'000'000ull : 0);
        const Parsed_ p = parse_(b.bytes.full_blob, b.bytes);
        CHECK(p.ok && pn::parse_finder(p.got.tx_extra) == std::optional<::v37::ScriptRef>(finder_ref()) &&
                  pn::parse(p.got.tx_extra) == std::optional<std::uint64_t>(B),
              "%s: the block's 0x02 carries V37F(finder) and V37N base %llu", tag, (unsigned long long)B);
        const auto bk = decode(b, b.bytes.full_blob, fee_on);
        const ::v37::bytes32 F = id_of(finder_ref());
        CHECK(bk.ok && bk.ecut_finder && pm_get(bk.payout, F) == bk.total - B,
              "%s: every output maps from the block alone; finder paid %llu = total %llu - B (%s)", tag,
              (unsigned long long)pm_get(bk.payout, F), (unsigned long long)bk.total, bk.ok ? "ok" : bk.why.c_str());
        if (fee_on) CHECK(bk.ok && !bk.out_amount.empty() && bk.out_amount.back() == 0 && bk.out_identity.back() == fee::donation_identity(kNet),
                          "%s: the donation output LAST is the 0-amount marker (present, maps, pays nothing)", tag);
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
    for (const auto& part : {pn::encode_tail(fee::kDonationMarkerPico), fee::encode_donation_owed_tail(0), credit::encode_pool_tag_field(T), credit::encode_tail(fixture_cut())})
        a.extra_nonce_tail.insert(a.extra_nonce_tail.end(), part.begin(), part.end());
    a.extra_nonce_bind_size = 32;
    a.extra_nonce_bind = [](std::uint32_t en, std::uint8_t* out) { for (int i = 0; i < 32; ++i) out[i] = static_cast<std::uint8_t>(en * 7 + i); return true; };
    a.reward_total_field = true;   // main: scfg.commit_total -- "V37R" first in the tail (the E9 width: 220 + 12 = 232 B)
    std::string why;
    auto t = asm_::XmrBlockAssembler::build(a, &why);
    const std::size_t widest = static_cast<std::size_t>(::c2pool::xmr::EXTRA_NONCE_MAX_SIZE) + ::c2pool::xmr::EXTRA_NONCE_BIND_MAX +
                               asm_::REWARD_TOTAL_FIELD_BYTES + asm_::FINDER_FIELD_BYTES + asm_::PAYNOW_TAIL_BYTES + asm_::DONATION_OWED_TAIL_BYTES +
                               asm_::POOL_TAG_FIELD_BYTES + asm_::CREDIT_CUT_TAIL_BYTES;
    CHECK(t != nullptr && widest == 232 && widest <= 255, "the widest payload rbind + V37R + V37F + V37N + V37D + V37P + V37C assembles (bound %zu <= 255): %s", widest, t ? "ok" : why.c_str());
    if (!t) return;
    asm_::BlockBytes b;
    // The padded nonce is 4..14 B (the amount-varint slack), so `widest` is a bound: the live
    // payload here is 222 B, above the pre-fix bound of 220 that refused every finder variant.
    CHECK(t->materialize(5, b, &why) && b.extra_nonce_size > 220 && b.extra_nonce_size <= widest,
          "materializes wider than the pre-fix bound 220 and within %zu (0x02 payload %zu B)", widest, b.extra_nonce_size);
    CHECK(pn::parse_reward_total(parse_(b.full_blob, b).got.tx_extra) == std::optional<std::uint64_t>(t->reward()), "V37R reads back as the template's reward");
    x6::ReceivedCoinbase rc; std::uint64_t h = 0; std::size_t used = 0;
    const bool pp = asm_::parse_coinbase_prefix(b.full_blob.data() + b.miner_tx_offset, b.miner_tx_size, rc, &h, &used);
    ::v37::bytes32 got{};
    const auto nf = credit::extra_nonce_field(rc.tx_extra);
    CHECK(pp && pn::parse_finder(rc.tx_extra) == std::optional<::v37::ScriptRef>(fr) && pn::parse(rc.tx_extra) == std::optional<std::uint64_t>(fee::kDonationMarkerPico) &&
              fee::parse_donation_owed(rc.tx_extra).has_value() && nf && credit::parse_pool_tag_payload(*nf, &got) == credit::PoolTagParse::Present &&
              got == T && credit::parse_from_tx_extra(rc.tx_extra) == std::optional<credit::CreditCut>(fixture_cut()),
          "every field reads back from the block's own bytes");
    std::uint64_t to_f = 0; for (const auto& o : t->outputs()) if (o.identity == fid) to_f += o.amount;
    CHECK(to_f == t->reward(), "assembled: finder paid the whole reward = %llu (the donation marker is 0)", (unsigned long long)to_f);
    const auto shp = o2::inspect_kfair_coinbase(*t, a.settle.lane_commitment, 5);
    CHECK(shp.kfair_order, "the K_fair coinbase shape gate ACCEPTS the finder output: %s", shp.why.empty() ? "ok" : shp.why.c_str());
}

// ---------------------------------------------------------------------------
// E7 CUT-FLOOR (#1803 review): three nodes book one lineage in chain order
// the way main_v37_xmr does (floor gate -> empty-cut finder -> net booking);
// node C restarts mid-chain from its persisted floor lines.
struct FloorNode {
#ifdef C2POOL_V37_XMR_CUT_FLOOR
    pn::LaneCutFloor floor;
#endif
    std::string lines;   // what the node persisted
};
struct LaneBlk { std::uint64_t h; std::string bid; std::uint64_t P; bool finder; ::v37::ScriptRef who; bool work; };
// true = booked (the finder credit written to *finder_credit); false + why = refused
bool book_on(FloorNode& n, const LaneBlk& b, std::string& why, long long* finder_credit) {
    const ::v37::bytes32 D = fee::donation_identity(kNet);
    const std::uint64_t B = 1, pool = kReward - B;
#ifdef C2POOL_V37_XMR_CUT_FLOOR
    n.floor.on_block_at(b.h, b.bid);
    if (!n.floor.check(b.h, b.P, &why)) return false;
#endif
    Amounts fold;   // the fold at the committed cut: EMPTY at P=0, work at the honest cuts
    if (b.work) fold[id_of(ref_of(31))] = 7;
    Amounts payout;
    if (b.finder) payout[id_of(b.who)] = static_cast<long long>(pool);
    const std::optional<::v37::ScriptRef> fnd = b.finder ? std::optional<::v37::ScriptRef>(b.who) : std::nullopt;
    const std::optional<std::uint64_t> base = b.finder ? std::optional<std::uint64_t>(B) : std::nullopt;
    if (!pn::apply_empty_cut_finder(fnd, false, base, kReward, fold, &why)) return false;
    if (finder_credit) *finder_credit = fold.count(id_of(b.who)) ? fold.at(id_of(b.who)) : 0;
    const auto r = pn::net_booking(base, kReward, fold, payout, b.finder ? 1 : 0, D, 1);
    if (!r.ok) { why = r.why; return false; }
#ifdef C2POOL_V37_XMR_CUT_FLOOR
    if (n.floor.note_booked(b.h, b.P, b.bid)) n.lines += pn::LaneCutFloor::line_of(b.h, b.P, b.bid);
#endif
    return true;
}
void suite_cut_floor() {
    std::printf("== E7. CUT-FLOOR: a lane block's cut never regresses below the previous lane block's ==\n");
    const ::v37::ScriptRef F = finder_ref(), X = forger_ref();
    const std::vector<LaneBlk> chain = {
        {100, "b100", 0, true, F, false},    // the lineage's FIRST lane block: P = 0, empty cut, finder
        {101, "b101", 40, false, F, true},   // honest: P = 40, the cut credits work
        {102, "x102", 0, true, X, false},    // EXPLOIT: P = 0 (empty, reproducible) + V37F(forger)
        {103, "x103", 0, true, X, false},    // again, right after its own refused block
        {104, "x104", 39, true, X, false},   // one position below the floor
        {105, "b105", 40, false, F, true},   // honest, equal to the floor
        {106, "b106", 41, false, F, true},   // honest, above it
    };
    const std::vector<bool> want = {true, true, false, false, false, true, true};
    FloorNode A, B, C;
    std::vector<std::vector<bool>> got(3);
    long long first_credit = -1, stolen = 0;
    for (std::size_t i = 0; i < chain.size(); ++i) {
        if (chain[i].h == 104) {   // node C restarts: a fresh floor from what it persisted
            FloorNode C2; C2.lines = C.lines;
#ifdef C2POOL_V37_XMR_CUT_FLOOR
            std::size_t n = 0, pos = 0;
            while (pos < C.lines.size()) { const auto e = C.lines.find('\n', pos); if (C2.floor.load_line(C.lines.substr(pos, e - pos))) ++n; pos = e + 1; }
            CHECK(n == C.floor.size() && C2.floor.floor_below(104) == C.floor.floor_below(104),
                  "node C restarts: %zu persisted floor line(s) restore floor %llu", n, (unsigned long long)C2.floor.floor_below(104).value_or(0));
#endif
            C = std::move(C2);
        }
        FloorNode* nodes[3] = {&A, &B, &C};
        std::string w[3];
        for (int k = 0; k < 3; ++k) {
            long long fc = 0;
            got[k].push_back(book_on(*nodes[k], chain[i], w[k], &fc));
            if (k == 0 && chain[i].h == 100 && got[k].back()) first_credit = fc;
            if (k == 0 && chain[i].bid[0] == 'x' && got[k].back()) stolen += fc;
        }
        std::printf("    h=%llu %s P=%llu%s -> A:%s B:%s C:%s %s\n", (unsigned long long)chain[i].h, chain[i].bid.c_str(),
                    (unsigned long long)chain[i].P, chain[i].finder ? " V37F" : "", got[0].back() ? "BOOKED" : "REFUSED",
                    got[1].back() ? "BOOKED" : "REFUSED", got[2].back() ? "BOOKED" : "REFUSED", w[0].c_str());
    }
    CHECK(got[0][0] && got[1][0] && got[2][0] && first_credit == static_cast<long long>(kReward - 1),
          "an honest FIRST lane block with P=0 still pays its finder on every node (credit %lld = reward - 1)", first_credit);
    CHECK(!got[0][2] && !got[1][2] && !got[2][2], "a lane block committing P=0 below the previous lane block's P=40 is REFUSED on every node");
    CHECK(!got[0][3] && !got[1][3] && !got[2][3], "a second P=0 right after the refused one is REFUSED too (a refused block never lowers the floor)");
    CHECK(!got[0][4] && !got[1][4] && !got[2][4], "P=39 below the floor 40 is REFUSED on every node, a restarted node included");
    CHECK(stolen == 0, "the regressing finder claims credited %lld piconero to the forger (want 0)", stolen);
    CHECK(got[0] == want && got[1] == want && got[2] == want, "every node takes the same decision on every block (honest P=40 / 41 at or above the floor BOOK)");
#ifdef C2POOL_V37_XMR_CUT_FLOOR
    {   // a reorg replaces h=106 by a block committing P=40: the orphan's P=41 no longer bounds it
        std::string w;
        const bool ok = book_on(A, LaneBlk{106, "b106r", 40, false, F, true}, w, nullptr);
        CHECK(ok && A.floor.floor_below(107) == std::optional<std::uint64_t>(40),
              "a reorg at h=106 drops the orphan's cut (41): the replacement at P=40 BOOKS, floor above it = 40 (%s)", w.c_str());
    }
    {   // the REAL empty-cut block: its committed P read from its own bytes
        Built b(true, false, Cut::Empty, F);
        const auto bk = b.ok ? decode(b, b.bytes.full_blob, true) : auth::CoinbaseBooking{};
        pn::LaneCutFloor first, later;
        later.note_booked(200, bk.credit_cut.next_pos + 1, "prev");
        std::string w1, w2;
        CHECK(bk.ok && bk.has_credit_cut && first.check(201, bk.credit_cut.next_pos, &w1) && !later.check(201, bk.credit_cut.next_pos, &w2),
              "real empty-cut block (P=%llu from its V37C): books as the lineage's first, REFUSED over a booked P+1: %s",
              (unsigned long long)bk.credit_cut.next_pos, w2.c_str());
    }
#endif
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

// ---------------------------------------------------------------------------
// E8 PER-JOB FINDER (operator rulings 09-27): an empty-cut block pays the
// WINNING JOB's finder -- its stratum login L when L is a valid standard
// address of the network, the node OWNER on an owner-fee job, else the
// DONATION (subaddress / integrated / invalid / other network / no login).
// The node's own payout (finder_ref() here) is never an empty-cut finder.
// RED on 9d6d3648: the finder is the building node's payee for every job.
std::string addr_body(std::uint64_t prefix, const std::vector<std::uint8_t>& body) {
    namespace b58 = c2pool::v37n::xmr::relay::b58;
    std::vector<std::uint8_t> b;
    for (std::uint64_t v = prefix;;) { const std::uint8_t c = v & 0x7f; v >>= 7; if (v) b.push_back(c | 0x80); else { b.push_back(c); break; } }
    b.insert(b.end(), body.begin(), body.end());
    const auto h = ::xmr::coin::keccak256(b.data(), b.size());
    b.insert(b.end(), h.data(), h.data() + 4);
    std::string out;
    for (std::size_t off = 0; off < b.size(); off += b58::kFullBlock) {
        const int n = static_cast<int>(std::min<std::size_t>(b58::kFullBlock, b.size() - off));
        std::uint64_t v = 0;
        for (int i = 0; i < n; ++i) v = (v << 8) | b[off + i];
        std::string blk(static_cast<std::size_t>(b58::kEncodedBlockSizes[n]), b58::kAlphabet[0]);
        for (int i = static_cast<int>(blk.size()) - 1; i >= 0 && v; --i) { blk[i] = b58::kAlphabet[v % 58]; v /= 58; }
        out += blk;
    }
    return out;
}
std::string addr_of(const ::v37::ScriptRef& r, std::uint64_t prefix, bool integrated = false) {
    std::vector<std::uint8_t> body(r.payload.begin(), r.payload.end());
    if (integrated) for (int i = 0; i < 8; ++i) body.push_back(static_cast<std::uint8_t>(0x11 * (i + 1)));
    return addr_body(prefix, body);
}
const ::v37::ScriptRef& login_ref() { static const ::v37::ScriptRef r = ref_of(41); return r; }   // worker L
const ::v37::ScriptRef& owner_r()   { static const ::v37::ScriptRef r = ref_of(43); return r; }   // node owner O

// One job of a real empty-cut block: bind (or not) its finder, then decode the
// block the job's share would submit.
struct JobBlock { bool ok = false; std::string why; std::optional<::v37::ScriptRef> v37f; auth::CoinbaseBooking bk; std::vector<std::uint8_t> mtx; std::vector<std::uint8_t> blob; };
JobBlock job_block(Built& b, std::uint32_t en, bool fee_on) {
    JobBlock j;
    c2pool::v37n::xmr::submit::BlockCandidate c;
    if (!b.provider->candidate_by_id(b.snap.template_id, en, c, &j.why)) return j;
    asm_::BlockBytes bb; if (!b.snap.tpl->materialize(en, bb, &j.why)) return j;   // the header (miner_tx offset) is the same for every job
    x6::ReceivedCoinbase got; std::uint64_t h = 0; std::size_t used = 0;   // the miner_tx length is the job's own (V37F or not)
    if (!asm_::parse_coinbase_prefix(c.full_blob.data() + bb.miner_tx_offset, c.full_blob.size() - bb.miner_tx_offset, got, &h, &used)) {
        j.why = "coinbase parse"; return j;
    }
    j.v37f = pn::parse_finder(got.tx_extra);
    j.bk = decode(b, c.full_blob, fee_on);
    j.blob = c.full_blob;   // E9: the block another node recomputes
    j.mtx.assign(c.full_blob.begin() + static_cast<std::ptrdiff_t>(bb.miner_tx_offset),
                 c.full_blob.begin() + static_cast<std::ptrdiff_t>(bb.miner_tx_offset + bb.miner_tx_size + c.full_blob.size() - bb.full_blob.size()));
    o2::SettlementStratumTemplateSource ts(*b.provider);
    ::v37::xmr::stratum::TemplateJob tj;
    j.ok = ts.rebuild_blob(b.snap.template_id, en, tj) && tj.blob == c.hashing_blob;   // served blob == submitted block's
    if (!j.ok) j.why = "served job blob != the candidate's hashing blob";
    return j;
}
#ifdef C2POOL_V37_XMR_ECUT_FINDER_LOGIN
void suite_login() {
    std::printf("== E8. PER-JOB FINDER: login / owner-fee job -> owner / sub|integrated|invalid -> donation ==\n");
    const ::v37::ScriptRef L = login_ref(), O = owner_r(), D = fee::donation_ref(kNet), NODE = finder_ref();
    const std::uint64_t P = fee::kPrefixMainnetStd;   // regtest addresses use the mainnet bytes
    struct Case { const char* what; std::string login; bool owner_hit; std::optional<::v37::ScriptRef> owner; pn::FinderFrom want_from; ::v37::ScriptRef want; };
    const std::vector<Case> cases = {
        {"valid standard login L", addr_of(L, P), false, O, pn::FinderFrom::Login, L},
        {"subaddress login", addr_of(L, fee::kPrefixMainnetSub), false, O, pn::FinderFrom::Donation, D},
        {"integrated login", addr_of(L, fee::kPrefixMainnetInt, true), false, O, pn::FinderFrom::Donation, D},
        {"garbage login", "not-an-address", false, O, pn::FinderFrom::Donation, D},
        {"testnet login on a regtest node", addr_of(L, fee::kPrefixTestnetStd), false, O, pn::FinderFrom::Donation, D},
        {"no login (in-process miner)", "", false, O, pn::FinderFrom::Donation, D},
        {"owner-fee job (roll hit)", addr_of(L, P), true, O, pn::FinderFrom::Owner, O},
        {"owner-fee hit without an owner", addr_of(L, P), true, std::nullopt, pn::FinderFrom::Login, L},
    };
    for (const auto& c : cases) {
        const auto fc = pn::choose_ecut_finder(c.login, kNet, c.owner_hit, c.owner);
        CHECK(fc.from == c.want_from && fc.payee == c.want && !(fc.payee == NODE) &&
                  (c.want_from != pn::FinderFrom::Donation || !fc.why.empty()),
              "%-32s -> %s%s%s", c.what, pn::to_string(fc.from), fc.why.empty() ? "" : " (logged: ", fc.why.empty() ? "" : (fc.why + ")").c_str());
    }
    for (int f = 0; f < 2; ++f) {
        const bool fee_on = f == 0;
        const char* tag = fee_on ? "fee ON" : "fee OFF";
        // main's default job: fee ON = no V37F (the residual pays the donation), OFF = V37F(donation)
        Built b(fee_on, false, Cut::Empty, fee_on ? std::nullopt : std::optional<::v37::ScriptRef>(D));
        CHECK(b.ok, "%s: fresh-pool empty-cut template builds: %s", tag, b.ok ? "ok" : b.why.c_str());
        if (!b.ok) continue;
        const std::uint64_t B = fee_on ? fee::kDonationMarkerPico : 0;
        b.provider->bind_finder(11, pn::choose_ecut_finder(addr_of(L, P), kNet, false, O).payee);
        b.provider->bind_finder(12, pn::choose_ecut_finder(addr_of(L, fee::kPrefixMainnetSub), kNet, false, O).payee);
        b.provider->bind_finder(13, pn::choose_ecut_finder(addr_of(L, P), kNet, true, O).payee);
        b.provider->bind_finder(15, pn::choose_ecut_finder(addr_of(ref_of(44), P), kNet, false, O).payee);   // worker M
        for (const auto& [en, who, name] : std::vector<std::tuple<std::uint32_t, ::v37::ScriptRef, const char*>>{
                 {11, L, "login L"}, {13, O, "owner-fee job -> owner"}, {15, ref_of(44), "login M"}}) {
            JobBlock j = job_block(b, en, fee_on);
            const ::v37::bytes32 W = id_of(who);
            CHECK(j.ok && j.v37f == std::optional<::v37::ScriptRef>(who) && j.bk.ok && j.bk.ecut_finder &&
                      pm_get(j.bk.payout, W) == j.bk.total - B && pm_get(j.bk.payout, id_of(NODE)) == 0,
                  "%s job en=%u (%s): V37F = it, its output key derives for it and carries %llu = total %llu - %llu; node payout 0 (%s)",
                  tag, en, name, (unsigned long long)pm_get(j.bk.payout, W), (unsigned long long)j.bk.total, (unsigned long long)B,
                  j.ok ? (j.bk.ok ? "ok" : j.bk.why.c_str()) : j.why.c_str());
            Amounts cr; std::string w;
            CHECK(j.bk.ok && pn::apply_empty_cut_finder(j.bk.ecut_finder, j.bk.ecut_finder_malformed, j.bk.paynow_base, j.bk.total, cr, &w) &&
                      cr.size() == 1 && cr.count(W) && cr.at(W) == static_cast<long long>(j.bk.total - B),
                  "%s job en=%u: the receive rule books credit {%s : %lld} %s", tag, en, name, cr.count(W) ? cr.at(W) : 0LL, w.c_str());
        }
        for (const std::uint32_t en : {12u, 14u}) {   // subaddress login -> donation; unbound job -> the default (donation)
            JobBlock j = job_block(b, en, fee_on);
            const ::v37::bytes32 Did = fee::donation_identity(kNet);
            const bool ok = fee_on ? (j.ok && !j.v37f && j.bk.ok && pm_get(j.bk.payout, Did) + j.bk.sink_total >= static_cast<long long>(j.bk.total))
                                   : (j.ok && j.v37f == std::optional<::v37::ScriptRef>(D) && j.bk.ok && pm_get(j.bk.payout, Did) == j.bk.total);
            CHECK(ok && pm_get(j.bk.payout, id_of(NODE)) == 0 && pm_get(j.bk.payout, id_of(L)) == 0,
                  "%s job en=%u (%s): the DONATION takes the reward (%s), not L, not the node payout (%s)", tag, en,
                  en == 12 ? "subaddress login" : "unbound job", fee_on ? "residual, no V37F" : "V37F = donation",
                  j.ok ? (j.bk.ok ? "ok" : j.bk.why.c_str()) : j.why.c_str());
        }
        CHECK(b.provider->finder_variants() == 3, "%s: 3 finder variants built (L, O, M), each once (%llu)", tag,
              (unsigned long long)b.provider->finder_variants());
    }
    for (int f = 0; f < 2; ++f) {   // a cut WITH work: a bound login changes no byte
        const bool fee_on = f == 1;
        Built w(fee_on, true, Cut::Work, fee_on ? std::nullopt : std::optional<::v37::ScriptRef>(D));
        if (!w.ok) { CHECK(false, "work-cut block builds: %s", w.why.c_str()); continue; }
        w.provider->bind_finder(0, L);
        const JobBlock j = job_block(w, 0, fee_on);
        CHECK(j.ok && !j.v37f && blob_digest(j.mtx) == (fee_on ? kGoldenWorkFeeOn : kGoldenWorkFeeOff) && w.provider->finder_variants() == 0,
              "fee %s: NON-empty cut with login L bound: no V37F, miner_tx == the base golden, no variant", fee_on ? "ON" : "OFF");
    }
}
#else
void suite_login_base() {
    std::printf("== E8 (BASE). PER-JOB FINDER absent: every job's finder is the node payout ==\n");
    Built b(false, false, Cut::Empty, finder_ref());   // 9d6d3648 main: ecut_finder = the node's --payout-address
    if (!b.ok) { CHECK(false, "empty-cut block builds: %s", b.why.c_str()); return; }
    const JobBlock j = job_block(b, 11, false);        // the job of worker L (login cannot reach the builder here)
    CHECK(j.ok && j.v37f == std::optional<::v37::ScriptRef>(login_ref()),
          "empty-cut block for a share from login L pays L -- got V37F = %s", j.v37f == std::optional<::v37::ScriptRef>(finder_ref()) ? "the NODE payout" : "other");
    CHECK(j.bk.ok && pm_get(j.bk.payout, id_of(finder_ref())) == 0, "the node payout is never the empty-cut finder -- it got %llu",
          (unsigned long long)pm_get(j.bk.payout, id_of(finder_ref())));
    CHECK(false, "subaddress login -> donation, owner-fee job -> owner: no per-job finder choice on this tree");
}
#endif

// ---------------------------------------------------------------------------
// E9 FRESH POOL UNDER THE RULES (stagenet attempts 7 and 8, the `sink-unbacked:
// blocks=9 total=5117686357972` alarm): the daemon's live configuration -- the
// anchor rule, DROPS due, the fee model, the spend floor, the drain triple
// {1,16,64}, salted ties, the V37R total, a pool_tag, --relay-bind rbind -- over
// a ledger with NO finalized lane block (no anchor yet). The rulings of
// 09-26/09-27 and docs/xmr-lane/coinbase-recompute.md: such a block credits
// nobody and pays its FINDER (the winning job's bound login) the pool
// P = R - Delta as V37F + V37N; the donation output is its 0-amount marker.
// Twice: F = 0 (mainnet from block 1: Delta = 0, P = R) and F = 499999999998
// on three DEMO keys (attempt 8: Delta = R * 64 / 256, the first lane block).
// Every bound job's block must carry V37F(login) + V37N, pay the finder exactly
// R - debt_paid, book net with no credit left and no unexplained sink coverage,
// and be CANONICAL for another node's recompute. RED on master 64c4372df: the
// bound jobs are served the DEFAULT template (no V37F / V37N, R - Delta to the
// donation); diagnose_variant() replays tpl_for()'s silent exits and names the
// refusing link.
// ---------------------------------------------------------------------------
#ifdef C2POOL_V37_XMR_ECUT_FINDER_LOGIN
std::string diagnose_variant(const Built& b, const ::v37::ScriptRef& fr) {
    if (!b.snap.ecut) return "snapshot not an eligible empty cut (snap.ecut == nullptr: XmrOwedSettlementSource::m_ecut_eligible false)";
    std::string why;
    auto src = b.snap.ecut->src->with_finder(fr, &why);
    if (!src) return "with_finder REFUSED: " + why;
    asm_::AssemblyInputs a = b.snap.ecut->recipe;
    a.settle = o2::assembly_settle_inputs(*src, /*weight_aware_cap=*/true);
    a.extra_nonce_tail = src->extra_nonce_tail();
    auto t = asm_::XmrBlockAssembler::build(a, &why);
    if (!t) return "assembler REFUSED the variant: " + why;
    asm_::BlockBytes probe;
    if (!t->materialize(0, probe, &why)) return "variant probe materialize REFUSED: " + why;
    const o2::KFairCoinbaseShape sh = o2::inspect_kfair_coinbase(*t, src->owed_digest());
    if (!sh.ok) return "shape gate REFUSED the variant: " + sh.why;
    return "variant builds (V37F armed, " + std::to_string(t->outputs().size()) + " outputs)";
}

void suite_fresh_pool_under_rules() {
    std::printf("== E9. FRESH POOL UNDER THE RULES: anchor ON + DROPS due + fee ON + drain {1,16,64} + rbind, no finalized lane block ==\n");
    const ::v37::ScriptRef L = login_ref(), M = ref_of(44), N = ref_of(45);
    const std::uint64_t P = fee::kPrefixMainnetStd;   // regtest addresses use the mainnet bytes
    const ::v37::bytes32 Did = fee::donation_identity(kNet);
    for (int pass = 0; pass < 2; ++pass) {
        LiveRules lr; lr.on = true;
        if (pass == 1) lr.seeds = {83333333333ull, 166666666666ull, 249999999999ull};   // attempt 8: F0 = 499999999998 (1x, 2x, 3x)
        const char* tag = pass == 0 ? "F = 0 (mainnet genesis)" : "F = 499999999998 (attempt 8 seeds)";
        Built b(true, false, Cut::Empty, std::nullopt, &lr);
        CHECK(b.ok, "%s: the fresh-pool template builds under the live rules: %s", tag, b.ok ? "ok" : b.why.c_str());
        if (!b.ok) continue;
        const st::OwedLedger& Lg = b.lane.ledger.ledger();
        CHECK(!Lg.anchor_cut() && Lg.rules().anchor_cut && Lg.rules().drops_due && b.lane.scfg.drain.on() && b.lane.scfg.spend_floor,
              "%s: no anchor yet; anchor rule ON, DROPS due ON, drain ON, spend floor ON", tag);
        unsigned long long F = 0;
        for (const auto& [k, eo] : Lg.effective_owed_all()) { (void)k; if (eo > 0) F += static_cast<unsigned long long>(eo); }
        const std::uint64_t R = b.snap.reward;
        const std::uint64_t Delta = x6::drain_delta(F, R, Lg.heights_since_last_lane(b.snap.height), 16, 64);
        CHECK(F == (pass == 0 ? 0ull : 499999999998ull) && Delta == (pass == 0 ? 0 : R * 64 / 256),
              "%s: F = %llu, R = %llu, dh = 0 -> the cap 64, Delta = %llu", tag, F, (unsigned long long)R, (unsigned long long)Delta);
        {   // the default job (no binding): attempt 8's on-chain shape, for the record
            const JobBlock d = job_block(b, 14, true);
            const std::uint64_t don = d.bk.ok && !d.bk.out_amount.empty() ? d.bk.out_amount.back() : 0;
            std::printf("  [info] %s: unbound job en=14 (the default template): V37F %s, V37N %s, outputs %zu, donation output %llu (%s)\n", tag,
                        d.v37f ? "yes" : "no", d.bk.paynow_base ? "yes" : "no", d.bk.out_amount.size(), (unsigned long long)don,
                        d.ok ? (d.bk.ok ? "ok" : d.bk.why.c_str()) : d.why.c_str());
        }
        // Three logins through the real finder choice (main's job binder: choose_ecut_finder -> provider.bind_finder).
        b.provider->bind_finder(11, pn::choose_ecut_finder(addr_of(L, P), kNet, false, std::nullopt).payee);
        b.provider->bind_finder(12, pn::choose_ecut_finder(addr_of(M, P), kNet, false, std::nullopt).payee);
        b.provider->bind_finder(13, pn::choose_ecut_finder(addr_of(N, P), kNet, false, std::nullopt).payee);
        LaneFixture other(true, false, &lr);   // another node of the lane: the same rules and seeds, no anchor either
        CHECK(other.ledger.ledger().owed_digest() == Lg.owed_digest(), "%s: a second node holds the same ledger state (owed_digest)", tag);
        for (const auto& [en, who, name] : std::vector<std::tuple<std::uint32_t, ::v37::ScriptRef, const char*>>{
                 {11, L, "login L"}, {12, M, "login M"}, {13, N, "login N"}}) {
            const JobBlock j = job_block(b, en, true);
            const ::v37::bytes32 W = id_of(who);
            std::uint64_t debt = 0;   // what the owed outputs pay (the DEMO keys): debt_paid <= Delta
            for (const auto& [k, v] : j.bk.payout) if (k != W && k != Did) debt += static_cast<std::uint64_t>(v);
            const std::uint64_t finder_paid = pm_get(j.bk.payout, W);
            const std::uint64_t don = j.bk.ok && !j.bk.out_amount.empty() ? j.bk.out_amount.back() : ~0ull;
            const bool armed = j.ok && j.v37f == std::optional<::v37::ScriptRef>(who) && j.bk.ok && j.bk.ecut_finder && j.bk.paynow_base.has_value();
            CHECK(armed, "%s job en=%u (%s): the served + submitted block carries V37F = %s and V37N -- %s", tag, en, name, name,
                  j.ok ? (j.bk.ok ? (armed ? "ok" : diagnose_variant(b, who).c_str()) : j.bk.why.c_str()) : j.why.c_str());
            if (!armed) continue;
            CHECK(finder_paid == j.bk.total - debt && debt <= Delta && (pass == 0 ? debt == 0 : debt == Delta) &&
                      don == fee::kDonationMarkerPico && !j.bk.out_identity.empty() && j.bk.out_identity.back() == Did,
                  "%s job en=%u: the finder is paid R - Delta = %llu - %llu = %llu; the donation output is its 0 marker (%llu)", tag, en,
                  (unsigned long long)j.bk.total, (unsigned long long)debt, (unsigned long long)finder_paid, (unsigned long long)don);
            // The booking every node does (main paynow_net): the finder's credit is the pool P, netted to nothing.
            Amounts credit; std::string w; ::v37::bytes32 fid{};
            const bool fok = pn::apply_empty_cut_finder(j.bk.ecut_finder, j.bk.ecut_finder_malformed, j.bk.paynow_base, j.bk.total, credit, &w, &fid);
            pn::drain_finder_credit(credit, fid, j.bk.total - debt, j.bk.total);
            Amounts payout = j.bk.payout;
            const auto nb = pn::net_booking(j.bk.paynow_base, j.bk.total, credit, payout, j.bk.sink_total, Did,
                                            static_cast<long long>(fee::kDonationMarkerPico), true);
            long long alloc_sink = 0;
            if (const auto it = nb.alloc.find(Did); it != nb.alloc.end()) alloc_sink = it->second;
            long long left = 0;
            for (const auto& [k, c] : credit) { (void)k; if (c > 0) left += c; }
            CHECK(fok && nb.ok && left == 0 && nb.netted == static_cast<long long>(finder_paid) &&
                      j.bk.sink_total - alloc_sink - static_cast<long long>(fee::kDonationMarkerPico) == 0,
                  "%s job en=%u: booked net: the finder credited and paid %llu, credit left 0, sink coverage no pay-now explains 0 (%s)", tag, en,
                  (unsigned long long)finder_paid, fok ? (nb.ok ? "ok" : nb.why.c_str()) : w.c_str());
            // The recompute on another node. Pre-anchor = the view credits nobody (main credit_payees: none -> has_view, payees {}).
            rc::LaneInputs li;
            li.chain_id = LANE_CHAIN; li.h_min = 0;
            li.owed_cap = b.lane.scfg.resolved_output_cap(); li.wire_cap = li.owed_cap;
            li.residual_sink = b.lane.scfg.residual_sink; li.residual_sink_identity = b.lane.scfg.residual_sink_identity;
            li.fixed = b.lane.scfg.fixed; li.pool_tag = b.lane.scfg.pool_tag;
            li.kfair_salted_ties = true; li.spend_floor = true; li.commit_total = true; li.drain = b.lane.scfg.drain;
            rc::CutInputs ci; ci.has_view = true;
            const rc::Result r = rc::verify_lane_coinbase(j.blob, j.bk, other.ledger.ledger(), other.ledger.pay_of(), li, ci);
            CHECK(r.canonical() && r.debt_paid == debt && r.split_at == j.bk.total - debt,
                  "%s job en=%u: another node's recompute: %s (debt_paid %llu, P %llu) %s", tag, en, rc::to_string(r.verdict),
                  (unsigned long long)r.debt_paid, (unsigned long long)r.split_at, r.why.c_str());
        }
        CHECK(b.provider->finder_variants() == 3, "%s: 3 finder variants built (L, M, N), each once (%llu)", tag,
              (unsigned long long)b.provider->finder_variants());
    }
}
#endif

// ---------------------------------------------------------------------------
// E10 the `sink-unbacked` status alarm (main paynow_net) means NoClaimWithoutCash:
// coverage the sink / donation output carries that no pay-now of THIS block
// explains, counted only while the cut still holds credit FINALIZE will book.
// A block whose fold at the cut is EMPTY and which commits no V37N (attempt 8's
// nine pre-anchor blocks, credit {}) is not a claim: it must not count. RED on
// master 64c4372df: every residual without V37N counted (blocks=9).
// ---------------------------------------------------------------------------
void suite_sink_unbacked_scope() {
    std::printf("== E10. sink-unbacked alarm scope: sink cash counts only against credit still to be booked ==\n");
#ifdef C2POOL_V37_XMR_SINK_UNBACKED_SCOPED
    const Amounts none;
    Amounts some; some[id_of(ref_of(31))] = 5;
    CHECK(pn::sink_unbacked_amount(450000000000ll, 0, 0, none) == 0,
          "an empty-cut block without V37N and no credit left: 0 (attempt 8 block 2220893: donation 450000000000, credit {})");
    CHECK(pn::sink_unbacked_amount(450000000000ll, 0, 0, some) == 450000000000ll,
          "the same coverage while the cut still holds credit (the #1865 gap): counted in full");
    CHECK(pn::sink_unbacked_amount(571295573ll, 571295573ll, 0, some) == 0,
          "coverage fully explained by the sink's own pay-now share: 0 (attempt 8 block 2220964)");
    CHECK(pn::sink_unbacked_amount(7, 0, 7, some) == 0, "the marker alone: 0");
    Amounts neg; neg[id_of(ref_of(31))] = -3;
    CHECK(pn::sink_unbacked_amount(100, 0, 0, neg) == 0, "only negative credit left (over-credit netted forward): nothing to book, 0");
    // the real pre-anchor DEFAULT block (an unbound job), booked as main does
    LiveRules lr; lr.on = true; lr.seeds = {83333333333ull, 166666666666ull, 249999999999ull};
    Built b(true, false, Cut::Empty, std::nullopt, &lr);
    if (!b.ok) { CHECK(false, "fresh-pool template builds: %s", b.why.c_str()); return; }
    const JobBlock d = job_block(b, 14, true);
    Amounts credit, payout = d.bk.payout;
    const auto nb = pn::net_booking(d.bk.paynow_base, d.bk.total, credit, payout, d.bk.sink_total, fee::donation_identity(kNet), 0, true);
    long long alloc_sink = 0;
    if (const auto it = nb.alloc.find(fee::donation_identity(kNet)); it != nb.alloc.end()) alloc_sink = it->second;
    CHECK(d.ok && d.bk.ok && !d.bk.paynow_base && d.bk.sink_total > 0 && pn::sink_unbacked_amount(d.bk.sink_total, alloc_sink, 0, credit) == 0,
          "the default pre-anchor block (no V37N, donation coverage %lld, credit {}) does not increment the counter", d.bk.sink_total);
#else
    CHECK(false, "no scoped sink-unbacked predicate on this tree (main counts every residual without V37N: attempt 8 'sink-unbacked: blocks=9')");
#endif
}

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
    suite_cut_floor();
#endif
#ifdef C2POOL_V37_XMR_ECUT_FINDER_LOGIN
    suite_login();
    suite_fresh_pool_under_rules();
#else
    suite_login_base();
#endif
    suite_sink_unbacked_scope();
#if !ECUT_FIX
    suite_base();
    suite_nonempty_unchanged();
#endif
    std::printf("\n%d/%d checks passed -- %s\n", g_checks - g_fail, g_checks, g_fail ? "FAIL" : "ALL PASS");
    return g_fail ? 1 : 0;
}
