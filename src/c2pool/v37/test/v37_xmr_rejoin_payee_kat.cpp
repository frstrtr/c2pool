// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// v37_xmr_rejoin_payee_kat -- REJOIN-PAYEE: a node that joined late (or was
// restarted after a downtime) must book the canonical lane blocks of its
// downtime exactly like every other node.
//
// The defect (flip 0 AND flip 1, 3-node regtest): SAME-BLOCK PAY-NOW pays a
// block's miners out of its own E_b, i.e. to the projected payees of the view
// at the block's on-chain credit cut. The receive side maps outputs only
// through refs its payee resolver learned from receipts THIS node pushed. A
// late/restarted node that had not pushed those receipts (it folds the cut by
// relay repair) REFUSED the block at decode ("output 0 maps to no known
// payee"), booked a NODE-LOCAL liability, and -- flip 0 -- its owed ledger
// left the others' state, so the next block's 0x03 root was unknown to it and
// its finalize cursor was HELD for good (live rig: cursor 127, hw 234).
//
// The fix (xmr_cut_payees.hpp): an output-unmapped lane block is resolved
// against the payees of the view at ITS OWN credit cut before the refusal; a
// view not readable yet makes the block UNDECIDED (cut-pending: retry / HOLD).
//
// Suites (REAL assembled blocks, monerod arm over the C4 capture, pay-now to
// three payees, empty owed ledger -- the first blocks of a pool):
//   J1  the informed node (it pushed the receipts) books the block; the late
//       node's plain decode fails closed on output 0 (the defect's first step).
//   J2  the late node resolves through the cut's payees: books it, payout map
//       byte-identical to the informed node's, three refs learned.
//   J3  the cut not readable yet (relay repair in flight): UNDECIDED, the
//       reason carries "cut-pending:" + "relay repair of P=" (RC-HOLD family).
//   J4  a genuine stranger output (the cut projects other payees): still
//       fail-closed, refused, mapped part kept for the liability.
//   J5  a decided cut mismatch: refused as before (never a fold elsewhere).
//   J6  a node that already knows the payees: decoded first time, the cut is
//       never asked (no extra work, no behaviour change on the common path).
//   J7  two late nodes resolve identically; afterwards a plain decode books.
//
// RED on the base: there is no xmr_cut_payees.hpp there, so the booking rule
// is master's plain decode and J2/J3/J7 FAIL with the measured refusal.
// ---------------------------------------------------------------------------
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
#include "c2pool/v37/xmr/xmr_o2_settlement_fixture.hpp"
#include "c2pool/v37/xmr/xmr_o2_settlement_provider.hpp"
#include "c2pool/v37/xmr/xmr_pool_tag.hpp"
#if __has_include("c2pool/v37/xmr/xmr_cut_payees.hpp")
#include "c2pool/v37/xmr/xmr_cut_payees.hpp"
#define RJP_FIX 1
#else
#define RJP_FIX 0
#endif

#include "xmr_c4_parity_golden.hpp"

using namespace c2pool::xmr::native;

namespace o2      = c2pool::v37n::xmr::o2;
namespace asm_    = c2pool::xmr::assembly;
namespace credit  = c2pool::v37n::xmr::credit;
namespace auth    = c2pool::v37n::xmr::authority;
namespace lineage = c2pool::v37n::xmr::lineage;
namespace st      = c2pool::v37n::settle;
namespace G4      = c2pool::xmr::native::golden_c4;

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

const std::uint32_t LANE_CHAIN = 0x0000ABCDu;

::v37::bytes32 b32(std::uint8_t seed) { ::v37::bytes32 b{}; for (int i = 0; i < 32; ++i) b[i] = static_cast<std::uint8_t>(seed + i); return b; }

std::array<std::uint8_t, 32> point_of(std::uint8_t k) {
    ::xmr::coin::SecretKey sec{};
    sec.data()[0] = k;
    ::xmr::coin::PublicKey pub{};
    if (!::xmr::coin::secret_key_to_public_key(sec, pub)) return {};
    std::array<std::uint8_t, 32> out{};
    std::memcpy(out.data(), pub.data(), 32);
    return out;
}

credit::CreditCut fixture_cut() {
    credit::CreditCut c;
    c.next_pos = 1;   // the pool's first receipt: the cut the live rig's first refused block committed
    for (std::size_t i = 0; i < 32; ++i) c.spine_digest[i] = static_cast<std::uint8_t>(0x60 + i);
    return c;
}

// the payees of the view at the cut: three wallets, weights 1:2:3, NOT owed
std::vector<st::WeightedPayee> cut_payees(std::uint8_t first_point) {
    std::vector<st::WeightedPayee> wp;
    const auto V = point_of(2);
    for (int i = 0; i < 3; ++i) {
        st::WeightedPayee w;
        w.pay = ::v37::xmr::make_xmr_std(point_of(static_cast<std::uint8_t>(first_point + 2 * i)), V);
        w.key = ::v37::xmr::xmr_identity_key(w.pay);
        w.weight = ::v37::U256(static_cast<std::uint64_t>(i + 1));
        wp.push_back(w);
    }
    return wp;
}

class CannedTransport final : public ::c2pool::xmr::node::IMonerodTransport {
public:
    explicit CannedTransport(std::string body) : body_(std::move(body)) {}
    void rpc_post(const std::string&, std::function<void(const ::c2pool::xmr::node::RpcResponse&)> cb) override {
        ::c2pool::xmr::node::RpcResponse r;
        r.body.assign(body_.begin(), body_.end());
        cb(r);
    }
    void zmq_subscribe(const std::string&, std::function<void(const ::c2pool::xmr::node::ZmqFrame&)>) override {}
private:
    std::string body_;
};

// The WINNER's side: an empty owed ledger (the first blocks of the pool), the
// cut's three payees learned from the receipts it pushed, pay-now armed.
struct Winner {
    o2::XmrOwedFixture                                 ledger{static_cast<::v37::ChainId>(LANE_CHAIN)};
    o2::XmrSettlementConfig                            scfg;
    std::vector<st::WeightedPayee>                     wp = cut_payees(11);
    CannedTransport                                    tx{G4::MD_RAW_JSON};
    tmpl::MonerodMinerDataSource                       src{tx};
    std::unique_ptr<o2::XmrSettlementTemplateProvider> provider;
    asm_::BlockBytes                                   bytes;
    ::v37::bytes32                                     tag{};
    bool                                               ok = false;
    std::string                                        why;
    Winner() {
        for (const auto& w : wp) ledger.learn_ref(w.pay);
        scfg.h_min = 0; scfg.output_cap = 0;
        scfg.set_residual_sink_std(point_of(4), point_of(2));
        scfg.credit_cut_source = [](std::uint64_t& P, ::v37::bytes32& dg) {
            const credit::CreditCut c = fixture_cut(); P = c.next_pos; dg = c.spine_digest; return true; };
        tag = lineage::pool_tag_for(LANE_CHAIN, ::v37::LaneParams{}, b32(0xA0));
        scfg.pool_tag = tag;
        const auto w = wp;
        scfg.paynow_source = [w](std::uint64_t, const ::v37::bytes32&, std::vector<st::WeightedPayee>& out) { out = w; return !out.empty(); };
        if (!src.poll(&why)) { why = "daemon arm did not parse the capture: " + why; return; }
        provider = std::make_unique<o2::XmrSettlementTemplateProvider>(src, ledger, scfg, 0);
        if (!provider->refresh()) { why = provider->last_error(); return; }
        const auto snap = provider->current();
        if (!snap.valid || !snap.tpl) { why = "no template"; return; }
        ok = snap.tpl->materialize(0, bytes, &why);
    }
};

// A RECEIVER: its own payee resolver (what its ingest taught it) over the same
// (empty) owed ledger state, so the 0x03 root matches.
struct Receiver {
    o2::XmrOwedFixture ledger{static_cast<::v37::ChainId>(LANE_CHAIN)};
    std::size_t        cut_asks = 0;
    auth::CoinbaseBooking decode(const Winner& w) const {
        const std::vector<::v37::bytes32> cands{ledger.ledger().owed_digest()};
        std::vector<::v37::bytes32> keys;
        for (const auto& [k, v] : ledger.ledger().effective_owed_all()) { (void)v; keys.push_back(k); }
        for (const auto& k : ledger.keys()) keys.push_back(k);
        return auth::decode_lane_coinbase(w.bytes.full_blob, LANE_CHAIN, cands, keys, w.scfg.residual_sink,
                                          w.scfg.residual_sink_identity, ledger.pay_of(), &w.tag);
    }
};

// The booking rule under test. mode: 1 = the view at the cut is read (it
// projects `view`), 0 = not readable yet, -1 = a decided mismatch.
struct Outcome {
    auth::CoinbaseBooking bk;
    bool        pending = false;
    std::size_t learned = 0;
    std::string why;
};
Outcome book_rule(Receiver& r, const Winner& w, int mode, const std::vector<st::WeightedPayee>& view) {
    Outcome o;
#if RJP_FIX
    auth::CutPayeeResult res;
    o.bk = auth::decode_resolving_cut_payees(
        [&] { return r.decode(w); },
        [&](const credit::CreditCut& cc, std::vector<st::WeightedPayee>& out, std::string& why) -> int {
            ++r.cut_asks;
            if (!(cc == fixture_cut())) { why = "credit-cut: not the block's own cut"; return -1; }
            if (mode == 0) {
                why = "cut-pending: relay repair of P=1 spine=606162636465 in flight (fetching the winner-side order + missing receipts)";
                return 0;
            }
            if (mode < 0) { why = "credit-cut MISMATCH after replay: prefix P=1 reconstructs a DIFFERENT lane digest"; return -1; }
            out = view;
            return 1;
        },
        [&](const ::v37::ScriptRef& ref) { return r.ledger.learn_ref(ref); }, &res);
    o.pending = res.status == auth::CutPayeeStatus::Pending;
    o.learned = res.learned;
    o.why = res.why;
#else
    (void)mode; (void)view;
    o.bk = r.decode(w);   // master: the first unmapped output refuses the block
    o.why = o.bk.why;
#endif
    return o;
}

std::string payout_str(const std::map<::v37::bytes32, long long>& m) {
    std::string s;
    static const char* hx = "0123456789abcdef";
    for (const auto& [k, v] : m) { for (int i = 0; i < 4; ++i) { s += hx[k[i] >> 4]; s += hx[k[i] & 15]; } s += "=" + std::to_string(v) + " "; }
    return s;
}

void run() {
    Winner w;
    CHECK(w.ok, "winner's pay-now lane block (empty owed ledger, cut P=1, three cut payees) builds + materializes: %s",
          w.ok ? "ok" : w.why.c_str());
    if (!w.ok) return;

    std::printf("== J1. informed node books; the late node's plain decode fails closed ==\n");
    Receiver informed;
    for (const auto& p : w.wp) informed.ledger.learn_ref(p.pay);
    const auto ib = informed.decode(w);
    std::uint64_t paid = 0; for (const auto& [k, v] : ib.payout) paid += static_cast<std::uint64_t>(v);
    CHECK(ib.ok && ib.is_lane && ib.payout.size() == 3 && ib.paynow_base.has_value() && paid + static_cast<std::uint64_t>(ib.sink_total) == ib.total,
          "informed node (pushed the receipts): books it, payout{ %s} + sink %lld == total %llu", payout_str(ib.payout).c_str(),
          ib.sink_total, (unsigned long long)ib.total);
    Receiver late0;
    const auto lb = late0.decode(w);
    CHECK(!lb.ok && lb.is_lane && lb.payout_partial && lb.unmapped_outputs == 3 && lb.why.find("maps to no known payee") != std::string::npos,
          "late node, plain decode: REFUSED (%s), %zu unmapped outputs = %llu piconero", lb.why.c_str(), lb.unmapped_outputs,
          (unsigned long long)lb.unmapped_total);

    std::printf("== J2. the late node resolves through the payees of the block's own cut ==\n");
    Receiver late;
    const auto o2r = book_rule(late, w, 1, w.wp);
    CHECK(o2r.bk.ok && !o2r.pending, "late node BOOKS the canonical block (%s)", o2r.bk.ok ? "ok" : o2r.bk.why.c_str());
    CHECK(o2r.bk.ok && o2r.bk.payout == ib.payout && o2r.bk.total == ib.total && o2r.bk.sink_total == ib.sink_total &&
              o2r.bk.lane_commitment == ib.lane_commitment && o2r.bk.credit_cut == ib.credit_cut && o2r.bk.paynow_base == ib.paynow_base,
          "  payout map, total, sink, lane_commitment, cut, V37N base byte-identical to the informed node's (payout{ %s})",
          payout_str(o2r.bk.payout).c_str());
    CHECK(o2r.learned == 3 && late.ledger.keys().size() == 3, "  the cut taught its three payees (learned %zu, resolver holds %zu)",
          o2r.learned, late.ledger.keys().size());

    std::printf("== J3. the cut is not readable here yet: UNDECIDED, never refused ==\n");
    Receiver pend;
    const auto o3 = book_rule(pend, w, 0, w.wp);
    CHECK(!o3.bk.ok && o3.pending && o3.why.rfind("cut-pending:", 0) == 0 && o3.why.find("relay repair of P=") != std::string::npos,
          "relay repair in flight -> pending (%s), not a refusal", o3.pending ? o3.why.c_str() : o3.bk.why.c_str());
    CHECK(pend.ledger.keys().empty(), "  nothing learned while pending");
    const auto o3b = book_rule(pend, w, 1, w.wp);
    CHECK(o3b.bk.ok && o3b.bk.payout == ib.payout, "  the retry after the repair lands books it identically");

    std::printf("== J4. a genuine stranger output stays fail-closed ==\n");
    Receiver strg;
    const auto others = cut_payees(41);   // the cut projects three OTHER payees
    const auto o4 = book_rule(strg, w, 1, others);
    CHECK(!o4.bk.ok && !o4.pending && o4.bk.payout_partial && o4.bk.unmapped_outputs == 3 &&
              o4.bk.why.find("maps to no known payee") != std::string::npos,
          "outputs paying none of the cut's payees: REFUSED (%s), unmapped %zu", o4.bk.why.c_str(), o4.bk.unmapped_outputs);
    std::vector<st::WeightedPayee> two(w.wp.begin(), w.wp.begin() + 2);
    Receiver part;
    const auto o4b = book_rule(part, w, 1, two);
    CHECK(!o4b.bk.ok && !o4b.pending && o4b.bk.payout_partial && o4b.bk.unmapped_outputs == 1 && o4b.bk.payout.size() == 2,
          "a cut that projects only 2 of the 3 paid payees: still REFUSED, 1 unmapped, 2 mapped kept for the liability");

    std::printf("== J5. a decided cut mismatch: refused as before ==\n");
    Receiver mm;
    const auto o5 = book_rule(mm, w, -1, w.wp);
    CHECK(!o5.bk.ok && !o5.pending && o5.bk.why.find("maps to no known payee") != std::string::npos && mm.ledger.keys().empty(),
          "mismatch -> REFUSED (%s), nothing learned", o5.bk.why.c_str());

    std::printf("== J6. a node that knows the payees: the cut is never asked ==\n");
    Receiver known;
    for (const auto& p : w.wp) known.ledger.learn_ref(p.pay);
    const auto o6 = book_rule(known, w, 0, w.wp);
    CHECK(o6.bk.ok && !o6.pending && known.cut_asks == 0 && o6.bk.payout == ib.payout,
          "decoded at once (cut asks %zu, even with the cut marked unreadable)", known.cut_asks);

    std::printf("== J7. two late nodes agree; afterwards a plain decode books ==\n");
    Receiver l1, l2;
    const auto a1 = book_rule(l1, w, 1, w.wp);
    const auto a2 = book_rule(l2, w, 1, w.wp);
    CHECK(a1.bk.ok && a2.bk.ok && a1.bk.payout == a2.bk.payout && a1.bk.payout == ib.payout,
          "two late receivers book the same payout map as the informed node");
    const auto again = l1.decode(w);
    CHECK(again.ok && again.payout == ib.payout, "  resolved once: the next plain decode (a later K_fair take) maps too");
}

}  // namespace

int main() {
    std::printf("v37_xmr_rejoin_payee_kat (%s)\n", RJP_FIX ? "fix" : "base");
    run();
    std::printf("\n%d/%d checks passed -- %s\n", g_checks - g_fail, g_checks, g_fail ? "FAIL" : "ALL PASS");
    return g_fail ? 1 : 0;
}
