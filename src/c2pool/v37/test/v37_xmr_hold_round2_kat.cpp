// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// v37_xmr_hold_round2_kat -- HOLD-ROUND-2 N3: the stagenet attempt-7 split,
// three nodes A / B / C, end to end over the layers that produced it.
//
// ATTEMPT 7 (binary b261fb1a5, 2026-10-02). B found lane block h2 (2220689).
// A and C had not booked it when B's next shares arrived: B's shares commit
// owed takes cut at dh 4 (its h2 pending), A/C rebuilt them at dh 14 -> every
// share -1 -> a strike each -> B banned (86350 bans on A). The order of h2 was
// servable to A/C only as a SUFFIX above B's vault horizon, B's link reset every
// ~3 s, the repair never finished; "drops lane prefix ... SUFFIX" was not in the
// relay-repair HOLD list, so at retry 601 A and C REFUSED h2 (node-local
// liability) while B booked and finalized it. A/C then recomputed B's h3 on
// their ledger without h2 (dh 15 vs 5): recompute_mismatch -> DEBIT-ONLY, a
// second split point.
//
// THE RIG. Real code at every seam, composed in one process:
//   shares    real drain-rule coinbases (the node's builder, fee model, V37R,
//             the provider's reward fixpoint), opened through the receipt's own
//             midstate, judged by relay::share_verdict on each node's published
//             state store; each -1 is a strike in the relay's CarrierDosBudget
//             (the relay's own policy: 100 strikes ban), a ban keeps B's link
//             down;
//   booking   each receiver's FinalizeConnect (the real connector, retry bound
//             30) books h2 through a booking callback that answers the
//             attempt-7 SUFFIX reason while the repair cannot finish, and books
//             once it does: the repair needs B's link up and completes at
//             attempt 45 (> the bound) -- a slow but live peer;
//   recompute rc::verify_lane_coinbase of B's h3 on each node's own ledger;
//   ledgers   st::OwedLedger (lane_height rule) per node: what each booked,
//             finalized; owed_digest compared at FINALIZE(h3).
//
//   N3a base: A/C strike B's shares (bans > 0), REFUSE h2 at the bound
//       (refused=1), recompute_mismatch on h3, owed_digest A/C != B.  (RED)
//   N3b fix:  bans = 0 (AHEAD, parked), h2 HELD past the bound and booked at
//       attempt 45 (stall decisions 0), B's parked shares re-judged canonical,
//       h3 canonical on all three, owed_digest identical x3 at FINALIZE(h3).
// ---------------------------------------------------------------------------
#include <unistd.h>

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <functional>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "impl/xmr/coin/xmr_blob.hpp"
#include "impl/xmr/coin/xmr_derivation.hpp"
#include "impl/xmr/native/consensus/xmr_block_parse.hpp"
#include "impl/xmr/receipt/xmr_receipt_verify.hpp"
#include "impl/xmr/settle/xmr_coinbase.hpp"
#include "impl/xmr/template/xmr_block_assembly.hpp"
#include "impl/xmr/wire/xmr_carrier_dos_budget.hpp"
#include "c2pool/v37/xmr/xmr_coinbase_authority.hpp"
#include "c2pool/v37/xmr/xmr_coinbase_recompute.hpp"
#include "c2pool/v37/xmr/xmr_fee_model.hpp"
#include "c2pool/v37/xmr/xmr_o2_finalize_connect.hpp"
#include "c2pool/v37/xmr/xmr_o2_settlement_fixture.hpp"
#include "c2pool/v37/xmr/xmr_paynow.hpp"
#include "c2pool/v37/xmr/relay/xmr_share_verdict.hpp"

namespace x6   = ::v37::xmr::settle;
namespace fee  = c2pool::v37n::xmr::fee;
namespace o2   = c2pool::v37n::xmr::o2;
namespace st   = c2pool::v37n::settle;
namespace cr   = c2pool::v37n::xmr::credit;
namespace auth = c2pool::v37n::xmr::authority;
namespace rc   = c2pool::v37n::xmr::recompute;
namespace rl   = c2pool::v37n::xmr::relay;
namespace asm_ = ::c2pool::xmr::assembly;
namespace akat = ::c2pool::xmr::assembly::kat;
namespace cons = ::c2pool::xmr::native;
using Amounts = std::map<::v37::bytes32, long long>;

namespace {

int g_fail = 0, g_checks = 0;
void check(const std::string& name, bool ok, const std::string& detail = {}) {
    ++g_checks; if (!ok) ++g_fail;
    std::printf("  [%s] %s%s%s\n", ok ? "PASS" : "FAIL", name.c_str(), detail.empty() ? "" : "  -- ", detail.c_str());
}

constexpr fee::DonationNet kNet = fee::DonationNet::Regtest;
constexpr std::uint32_t kChain = 0x0000ABCD;
constexpr std::uint64_t kHeight = 3000000;               // h3 and B's post-h2 shares (one template height)
constexpr std::uint64_t kH1 = kHeight - 14, kH2 = kHeight - 4;
constexpr std::uint64_t kAgc = 18000000000000000000ull;  // tail emission
constexpr std::uint64_t kRetryBound = 30, kRepairAt = 45;

std::array<std::uint8_t, 32> point_of(std::uint8_t k) {
    ::xmr::coin::SecretKey sec{}; sec.data()[0] = k; sec.data()[1] = 0x5a;
    ::xmr::coin::PublicKey pub{};
    if (!::xmr::coin::secret_key_to_public_key(sec, pub)) return {};
    std::array<std::uint8_t, 32> out{}; std::memcpy(out.data(), pub.data(), 32); return out;
}
struct Payee { ::v37::ScriptRef ref; ::v37::bytes32 id; std::uint64_t w = 1; };
Payee payee(std::uint8_t k, std::uint64_t w = 1) {
    Payee p; p.ref = ::v37::xmr::make_xmr_std(point_of(k), point_of(static_cast<std::uint8_t>(k + 100)));
    p.id = ::v37::xmr::xmr_identity_key(p.ref); p.w = w; return p;
}
std::vector<st::WeightedPayee> weighted(const std::vector<Payee>& ps) {
    std::vector<st::WeightedPayee> v;
    for (const auto& p : ps) { st::WeightedPayee w; w.key = p.id; w.weight = ::v37::U256(p.w); w.pay = p.ref; v.push_back(w); }
    return v;
}
cr::CreditCut the_cut() { cr::CreditCut c; c.next_pos = 4242; c.spine_digest[3] = 0x77; return c; }
::v37::bytes32 the_tag() { ::v37::bytes32 t{}; t[0] = 0xC2; t[31] = 0x37; return t; }

struct World {
    std::map<::v37::bytes32, ::v37::ScriptRef> refs;
    Payee K1 = payee(21), K2 = payee(22), K4 = payee(24);
    std::vector<Payee> cut = {payee(11, 1), payee(12, 2), payee(13, 3)};
    World() {
        learn(K1); learn(K2); learn(K4);
        for (const auto& p : cut) learn(p);
        refs[fee::donation_identity(kNet)] = fee::donation_ref(kNet);
    }
    void learn(const Payee& p) { refs[p.id] = p.ref; }
    o2::PayOfFn pay_of() const {
        auto r = refs;
        return [r](const ::v37::bytes32& k) {
            auto it = r.find(k); if (it != r.end()) return it->second;
            ::v37::ScriptRef raw; raw.kind = ::v37::ScriptKind::RAW; return raw;
        };
    }
    std::vector<::v37::bytes32> keys() const { std::vector<::v37::bytes32> k; for (const auto& [id, r] : refs) { (void)r; k.push_back(id); } return k; }
};
rc::LaneInputs lane_inputs() {
    rc::LaneInputs li;
    li.chain_id = kChain; li.h_min = 0; li.owed_cap = 2700; li.wire_cap = 2700;
    li.residual_sink = fee::donation_ref(kNet); li.residual_sink_identity = fee::donation_identity(kNet);
    li.fixed = {fee::donation_marker(kNet)};
    li.pool_field = cr::PoolField{the_tag(), 1, 1};   // RULES RATCHET: the V37P v2 head (epoch 1 of 1)
    li.spend_floor = true; li.commit_total = true;
    li.drain = o2::DrainRule{1, 16, 64};
    return li;
}
// B's builder on ledger L: a real drain-rule template at `height` (the provider's reward fixpoint)
struct Built { bool ok = false; std::string why; std::vector<std::uint8_t> blob; };
Built build_block(const st::OwedLedger& L, const World& w, std::uint32_t extra_nonce, std::uint64_t height) {
    Built out;
    const auto md = akat::miner(height, 300000, kAgc);
    const std::uint64_t subsidy = asm_::xmr_base_reward(md.already_generated_coins);
    const auto mempool = akat::txs(3, 2000, 30000000);
    std::uint64_t fees = 0; for (const auto& t : mempool) fees += t.fee;
    o2::XmrCoinbaseContext ctx;
    ctx.monero_major_version = md.major_version; ctx.height = md.height;
    std::memcpy(ctx.prev_id.data(), md.prev_id.h, 32);
    ctx.base_reward = subsidy; ctx.fees = fees; ctx.chain_id = kChain;
    ctx.lane_commitment = L.owed_digest();
    ctx.residual_sink = fee::donation_ref(kNet); ctx.residual_sink_identity = fee::donation_identity(kNet);
    ctx.fixed = {fee::donation_marker(kNet)};
    ctx.h_min = 0; ctx.output_cap = 2700;
    ctx.has_credit_cut = true; ctx.credit_cut = the_cut();
    ctx.has_pool_field = true; ctx.pool_field = cr::PoolField{the_tag(), 1, 1};   // RULES RATCHET: the V37P v2 head
    ctx.has_paynow = true; ctx.paynow_payees = weighted(w.cut);
    ctx.spend_floor = true; ctx.drain = o2::DrainRule{1, 16, 64};
    std::string why;
    auto src = o2::XmrOwedSettlementSource::build(L, w.pay_of(), ctx, subsidy + fees, &why);
    if (!src) { out.why = "source: " + why; return out; }
    asm_::AssemblyInputs a;
    a.miner = md; a.mempool = mempool; a.reward_total_field = true;
    a.settle = o2::assembly_settle_inputs(*src, true); a.extra_nonce_tail = src->extra_nonce_tail(); a.extra_nonce_head = src->extra_nonce_head();   // RULES RATCHET: the V37P v2 head
    a.extra_nonce_bind_size = 32;
    a.extra_nonce_bind = [](std::uint32_t en, std::uint8_t* b) { for (int i = 0; i < 32; ++i) b[i] = static_cast<std::uint8_t>(en * 13 + i); return true; };
    auto t = asm_::XmrBlockAssembler::build(a, &why);
    if (!t) { out.why = "assembler: " + why; return out; }
    for (int pass = 0; src->drain_on() && t->reward() != src->reward_hint() && pass < 4; ++pass) {
        src = o2::XmrOwedSettlementSource::build(L, w.pay_of(), ctx, t->reward(), &why);
        if (!src) { out.why = "source (fixpoint): " + why; return out; }
        a.settle = o2::assembly_settle_inputs(*src, true); a.extra_nonce_tail = src->extra_nonce_tail(); a.extra_nonce_head = src->extra_nonce_head();   // RULES RATCHET: the V37P v2 head
        t = asm_::XmrBlockAssembler::build(a, &why);
        if (!t) { out.why = "assembler (fixpoint): " + why; return out; }
    }
    asm_::BlockBytes b;
    if (!t->materialize(extra_nonce, b, &why)) { out.why = "materialize: " + why; return out; }
    out.ok = true; out.blob = b.full_blob;
    return out;
}
// What a relay peer has from B's receipt: the opened tx_extra + H(prefix) + the blob's height / parent.
bool share_of(const Built& b, rl::FbReceipt& fb, ::v37::xmr::verify::ParsedBlob& pbo, std::uint64_t& height) {
    cons::ParsedBlock pb;
    const auto stt = cons::parse_block(b.blob.data(), b.blob.size(), pb);
    if (stt != cons::BlockParseStatus::Ok && stt != cons::BlockParseStatus::TxCountMismatch) return false;
    x6::ReceivedCoinbase got; std::size_t used = 0;
    if (!asm_::parse_coinbase_prefix(b.blob.data() + pb.miner_tx_offset, pb.miner_tx_size, got, &height, &used)) return false;
    const std::vector<std::uint8_t> prefix(b.blob.begin() + static_cast<std::ptrdiff_t>(pb.miner_tx_offset),
                                           b.blob.begin() + static_cast<std::ptrdiff_t>(pb.miner_tx_offset + used));
    if (!::v37::xmr::verify::build_coinbase_opening(prefix, prefix.size() - got.tx_extra.size(), fb.receipt.coinbase_opening)) return false;
    pbo.major = static_cast<std::uint8_t>(pb.header.major_version);
    std::memcpy(pbo.prev_id.data(), pb.header.prev_id.data(), 32);
    return true;
}

// One pool node's lane state: its owed ledger, the share-state store its relay
// workers judge against (share_publish), the relay's DoS budget for B's link.
struct PoolNode {
    std::string name;
    st::OwedLedger L;
    rl::ShareStateStore store;
    ::c2pool::xmr::CarrierDosBudget dos;
    std::uint64_t strikes = 0, bans = 0, parked = 0, admitted = 0, recompute_mismatch = 0;
    bool b_banned = false;
    explicit PoolNode(std::string n) : name(std::move(n)), L(kChain, [] { st::OwedLedgerRules r; r.lane_height = true; return r; }()) {}
    void publish(const World& w) {   // main's share_publish: a frozen copy of this state
        auto e = std::make_shared<rl::ShareStateEntry>();
        e->digest = L.owed_digest(); e->ledger_seq = L.ledger_seq();
        const auto r = x6::mm_commitment_root(kChain, e->digest);
        std::memcpy(e->root.data(), r.data(), 32);
        e->ledger = std::make_shared<st::OwedLedger>(L); (void)e->ledger->owed_digest();
        e->refs = w.refs; e->lane = lane_inputs();
        e->has_view = true; e->view_ratified = true; e->payees = weighted(w.cut);
        store.put(e);
    }
    // the relay's verify worker on one of B's receipts: -1 = a strike in the DoS budget
    int judge(const rl::FbReceipt& fb, const ::v37::xmr::verify::ParsedBlob& pb, std::uint64_t h, std::string& why) {
        const int v = rl::share_verdict(store, fb, pb, h, why);
        if (v == 1) ++admitted;
        else if (v < 0) {
            ++strikes;
            if (dos.on_cheap_reject(2) == ::c2pool::xmr::Action::Ban && !b_banned) { b_banned = true; ++bans; }
        } else ++parked;   // 0 / AHEAD: parked (a re-judge follows the state)
        return v;
    }
};
// The booking every node applies to a lane block it decided (the same function
// everywhere: a divergence can only come from a different DECISION).
void book(st::OwedLedger& L, const std::string& bid, std::uint64_t h, const rc::Result& r, const auth::CoinbaseBooking& bk,
          const World& w, bool canonical) {
    Amounts credit, payout = bk.payout;
    if (canonical) {
        const auto wp = weighted(w.cut);
        const auto amt = st::split_reward(r.split_at ? r.split_at : bk.total, wp);
        for (std::size_t i = 0; i < wp.size(); ++i) if (amt[i]) credit[wp[i].key] += static_cast<long long>(amt[i]);
    }
    st::LaneFound lf; lf.height = h;
    L.on_block_found(bid, credit, payout, std::nullopt, nullptr, &lf);
}
// A receiver's recompute of a lane block (decode under coinbase authority, then rc::verify_lane_coinbase).
struct Verified { auth::CoinbaseBooking bk; rc::Result r; };
Verified receive(const std::vector<std::uint8_t>& blob, const st::OwedLedger& L, const World& w) {
    Verified v;
    std::vector<::v37::bytes32> keys = w.keys();
    for (const auto& [k, e] : L.effective_owed_all()) { (void)e; keys.push_back(k); }
    const ::v37::bytes32 tag = the_tag();
    v.bk = auth::decode_lane_coinbase_fee(blob, kChain, {L.owed_digest()}, keys, w.pay_of(), kNet, &tag);
    rc::CutInputs ci; ci.has_view = true; ci.payees = weighted(w.cut);
    v.r = rc::verify_lane_coinbase(blob, v.bk, L, w.pay_of(), lane_inputs(), ci);
    return v;
}

// The receiver's REAL FinalizeConnect booking h2 (the v37_xmr_relay_repair_hold_kat rig): the
// callback answers the attempt-7 SUFFIX reason until the repair completes; the repair needs
// B's link up and completes at attempt kRepairAt (> kRetryBound). Returns booked / refused.
const std::string kSuffixWhy =
    "cut-pending: drops lane prefix of P=2356: the served order is the SUFFIX [225,2356) and our [0,225) is not the "
    "order the spine verified (shadow base without a DROPS record, or the settlement replay is pending) -- HOLD, never "
    "composed from a suffix";
struct ConnectOutcome { std::uint64_t attempts = 0, booked = 0, refused = 0, held_max = 0, stall_timeout = 0, liability = 0; };
ConnectOutcome connect_h2(const std::filesystem::path& tmp, const std::string& name, const std::function<bool()>& link_up) {
    using namespace c2pool::v37n::xmr;
    ConnectOutcome out;
    XmrNodeConfig c; c.network = MoneroNetwork::Stagenet; c.lane_chain = 7; c.d_conf = 3;
    c.settle_db_path = (tmp / ("store-" + name)).string();
    std::filesystem::create_directories(c.settle_db_path);
    o2::FinalizeConnectOptions o;
    o.out = nullptr; o.sidecar_path = (std::filesystem::path(c.settle_db_path) / "pfound.tsv").string();
    o.retry_bound = kRetryBound; o.held_retry_every = 1;
    c2pool::xmr::node::MockMonerodTransport mock;
    XmrNode node(c, mock, &smoke::test_point_check);
    try { node.bring_up(); } catch (const std::exception& e) { check("connect bring_up " + name, false, e.what()); return out; }
    const ::v37::bytes32 pay = smoke::key_of(0xC3);
    std::uint64_t repair_progress = 0;
    o.book_from_chain_ex = [&](std::uint64_t h, const std::string&, o2::FinalizeConnectOptions::ChainBooking& bk) {
        if (h != 5) { bk.why = "not-lane: test"; return false; }
        ++out.attempts;
        if (link_up()) ++repair_progress;   // the order / its base can only come from B
        bk.payout.clear(); bk.payout[pay] = 600000000000ll; bk.payout_decoded = true; bk.total_pico = 600000000000ll;
        if (repair_progress < kRepairAt) { bk.why = kSuffixWhy; return false; }
        bk.credit.clear(); bk.credit[pay] = 600000000000ll; bk.payout.clear();
        ++out.booked;
        return true;
    };
    o2::FoundBlockQueue q;
    o2::FinalizeConnect fc(node, c, q, o);
    for (std::uint64_t h = 1; h <= 4; ++h) smoke::apply_row(node, h, smoke::blk_id(static_cast<std::uint8_t>(h)), smoke::blk_id(static_cast<std::uint8_t>(h - 1)));
    (void)fc.tick();
    for (std::uint64_t h = 5; h <= 10; ++h) smoke::apply_row(node, h, smoke::blk_id(static_cast<std::uint8_t>(h)), smoke::blk_id(static_cast<std::uint8_t>(h - 1)));
    for (int i = 0; i < 80 && !out.booked && !fc.stats().refused; ++i) { (void)fc.tick(); out.held_max = std::max<std::uint64_t>(out.held_max, fc.stats().held_now); }
    out.refused = fc.stats().refused; out.stall_timeout = fc.stats().booking_stall_timeout; out.liability = fc.stats().liability_blocks;
    (void)fc.drain_before_stop();
    return out;
}

void run(const std::filesystem::path& tmp) {
    World w;
    PoolNode A("A"), B("B"), C("C");
    std::vector<PoolNode*> all{&A, &B, &C};
    // the pool before h2: identical seeds and B's earlier lane block h1, booked + finalized everywhere
    for (auto* n : all) {
        int k = 0;
        for (const auto& [p, amt] : std::vector<std::pair<const Payee*, long long>>{{&w.K1, 40000000000ll}, {&w.K2, 25000000000ll}, {&w.K4, 900000000000ll}}) {
            const std::string sb = "seed-" + std::to_string(k++);
            n->L.on_block_found(sb, Amounts{{p->id, amt}}, {}); n->L.on_block_finalized(sb, 10 + k);
        }
        st::LaneFound lf; lf.height = kH1;
        n->L.on_block_found("h1", Amounts{{w.K1.id, 1000}}, {}, std::nullopt, nullptr, &lf);
        n->L.on_block_finalized("h1", 20);
        n->publish(w);
    }
    check("pool before h2: A, B, C at one owed_digest, prev lane h1", A.L.owed_digest() == B.L.owed_digest() &&
          B.L.owed_digest() == C.L.owed_digest() && A.L.prev_lane_height() == kH1);
    // B FINDS h2: its own FOUND is pending at once; A and C have not booked it yet
    const Built b2 = build_block(B.L, w, 5, kH2);
    const auto v2 = receive(b2.blob, B.L, w);
    check("B's h2 is canonical on B's prefix (dh 10)", b2.ok && v2.r.canonical() && v2.r.dh == 10, b2.why + " " + v2.r.why);
    if (!b2.ok || !v2.r.canonical()) return;
    book(B.L, "h2", kH2, v2.r, v2.bk, w, true);
    B.publish(w);
    // B's post-h2 shares (120 receipts of its next template) reach A and C before they book h2
    const Built t3 = build_block(B.L, w, 9, kHeight);
    rl::FbReceipt fb; ::v37::xmr::verify::ParsedBlob pb; std::uint64_t sh = 0;
    check("B's next template (h2 pending: dh 4) builds and opens as a receipt", t3.ok && share_of(t3, fb, pb, sh) && sh == kHeight, t3.why);
    std::string why_a;
    for (int i = 0; i < 120; ++i) for (auto* n : {&A, &C}) { std::string wv; const int v = n->judge(fb, pb, sh, wv); if (n == &A && i == 0) why_a = std::to_string(v) + " " + wv; }
    std::printf("  A's verdict on B's share: %s\n  strikes A=%llu C=%llu bans A=%llu C=%llu parked A=%llu\n", why_a.c_str(),
                (unsigned long long)A.strikes, (unsigned long long)C.strikes, (unsigned long long)A.bans, (unsigned long long)C.bans,
                (unsigned long long)A.parked);
    check("N3 B's post-h2 shares on A/C: no strike, no ban (AHEAD, parked) -- base: -1 x 120 -> 100-strike ban (attempt 7: 86350 bans)",
          A.strikes == 0 && C.strikes == 0 && A.bans == 0 && C.bans == 0 && A.parked == 120,
          "strikes " + std::to_string(A.strikes) + "/" + std::to_string(C.strikes) + " bans " + std::to_string(A.bans) + "/" + std::to_string(C.bans));
    // A and C book h2 through the REAL connector: the repair needs B's link (banned = down)
    const auto ca = connect_h2(tmp, "A", [&] { return !A.b_banned; });
    const auto cc = connect_h2(tmp, "C", [&] { return !C.b_banned; });
    std::printf("  connector A: attempts=%llu booked=%llu refused=%llu held_max=%llu liability=%llu | C: attempts=%llu booked=%llu refused=%llu\n",
                (unsigned long long)ca.attempts, (unsigned long long)ca.booked, (unsigned long long)ca.refused, (unsigned long long)ca.held_max,
                (unsigned long long)ca.liability, (unsigned long long)cc.attempts, (unsigned long long)cc.booked, (unsigned long long)cc.refused);
    check("N3 h2 on A and C: HELD past the bound (30) and BOOKED at attempt 45, refused=0, liability=0 -- base: REFUSED at 31 (the split)",
          ca.booked == 1 && cc.booked == 1 && ca.refused == 0 && cc.refused == 0 && ca.held_max == 1 && ca.liability == 0 &&
          ca.attempts >= kRepairAt && ca.stall_timeout == 0);
    for (auto [n, o] : {std::pair<PoolNode*, ConnectOutcome>{&A, ca}, {&C, cc}}) {
        if (!o.booked) continue;   // refused: node-local liability, nothing booked (rework-3)
        const auto v = receive(b2.blob, n->L, w);
        book(n->L, "h2", kH2, v.r, v.bk, w, v.r.canonical());
        n->publish(w);   // share_publish -> the relay re-judges its AHEAD shares
    }
    std::string why_r;
    std::uint64_t rejudged_ok = 0;
    for (auto* n : {&A, &C}) { std::string wv; if (rl::share_verdict(n->store, fb, pb, sh, wv) == 1) ++rejudged_ok; if (n == &A) why_r = wv; }
    check("N3 after A/C book h2 the parked shares re-judge CANONICAL on both", rejudged_ok == 2, why_r);
    // B FINDS h3 (built on its prefix: h2 pending); every node recomputes it on its own ledger
    const Built b3 = build_block(B.L, w, 11, kHeight);
    check("B's h3 builds", b3.ok, b3.why);
    if (!b3.ok) return;
    for (auto* n : all) {
        const auto v = receive(b3.blob, n->L, w);
        if (!v.r.canonical()) {
            ++n->recompute_mismatch;
            std::printf("  %s: cba-ALARM recompute_mismatch h3: %s (dh %llu prev_lane %llu skew_dh %llu)\n", n->name.c_str(), v.r.why.c_str(),
                        (unsigned long long)v.r.dh,
#if defined(C2POOL_XMR_RECOMPUTE_TAKE_SKEW)
                        (unsigned long long)v.r.prev_lane, (unsigned long long)v.r.skew_dh);
#else
                        0ull, 0ull);
#endif
        }
        book(n->L, "h3", kHeight, v.r, v.bk, w, v.r.canonical());   // canonical: credit; else DEBIT-ONLY
    }
    check("N3 h3 canonical on A, B and C (recompute_mismatch = 0) -- base: A/C recompute it without h2 (dh 14 vs 4): DEBIT-ONLY",
          A.recompute_mismatch == 0 && B.recompute_mismatch == 0 && C.recompute_mismatch == 0,
          "mismatch A/B/C = " + std::to_string(A.recompute_mismatch) + "/" + std::to_string(B.recompute_mismatch) + "/" + std::to_string(C.recompute_mismatch));
    // FINALIZE(h2), FINALIZE(h3) on every node that booked them
    for (auto* n : all) { n->L.on_block_finalized("h2", 30); n->L.on_block_finalized("h3", 31); }
    auto hx = [](const ::v37::bytes32& d) { static const char* x = "0123456789abcdef"; std::string s; for (int i = 0; i < 6; ++i) { s += x[d[i] >> 4]; s += x[d[i] & 15]; } return s; };
    std::printf("  owed_digest at FINALIZE(h3): A=%s B=%s C=%s\n", hx(A.L.owed_digest()).c_str(), hx(B.L.owed_digest()).c_str(), hx(C.L.owed_digest()).c_str());
    check("N3 owed_digest IDENTICAL on A, B and C at FINALIZE(h3) -- base: A/C != B (refused h2 + debit-only h3: the attempt-7 split)",
          A.L.owed_digest() == B.L.owed_digest() && B.L.owed_digest() == C.L.owed_digest() &&
          A.L.last_settled_lane_height() == kHeight && B.L.last_settled_lane_height() == kHeight);
}

}  // namespace

int main() {
    std::printf("== v37_xmr_hold_round2_kat (N3: the attempt-7 shape, three nodes) ==\n");
    const std::filesystem::path tmp = std::filesystem::temp_directory_path() / ("v37-xmr-hr2-" + std::to_string(::getpid()));
    std::filesystem::remove_all(tmp);
    std::filesystem::create_directories(tmp);
    run(tmp);
    std::filesystem::remove_all(tmp);
    std::printf("\n%d/%d checks passed -- %s\n", g_checks - g_fail, g_checks, g_fail ? "FAIL" : "ALL PASS");
    return g_fail ? 1 : 0;
}
