// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// v37_xmr_share_verdict_kat -- a share's coinbase must be the canonical one
// (xmr_coinbase_recompute.hpp verify_share_coinbase; P2Pool's share rule).
//
// Without it a miner can mine on a template that pays the whole block to
// itself, keep a found block, and still earn pool credit for every share: a
// receipt hides the outputs in its Keccak midstate and nothing checked them.
//
// Every coinbase here is a REAL assembled Monero block (the node's builder
// pipeline, fee model v1, rbind, credit cut, pool tag, "V37R" total), and the
// share side goes through the receipt's own opening: build_coinbase_opening
// over the miner_tx prefix, then resume_prefix_hash, as a relay peer does.
//
//   S1  honest share: CANONICAL, at two different worker extra-nonces.
//   S2  a thief template (the owed queue replaced by the finder, the donation
//       output kept): MISMATCH.
//   S3  a thief template without the donation output: MISMATCH.
//   S4  an honest share whose opened V37R total was rewritten: MISMATCH.
//   S5  a template without V37R: MISMATCH (a share must state its total).
//   S6  the verifier holds another ledger state: UNDECIDABLE (never a verdict).
//   S7  the block path: the same honest block is canonical under the V37R
//       rule, and V37R must equal the block's output sum.
//   S8  cost: one canonical rebuild per template.
// ---------------------------------------------------------------------------
#include <array>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
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
#include "c2pool/v37/xmr/xmr_coinbase_authority.hpp"
#include "c2pool/v37/xmr/xmr_coinbase_recompute.hpp"
#include "c2pool/v37/xmr/xmr_fee_model.hpp"
#include "c2pool/v37/xmr/xmr_o2_settlement_fixture.hpp"
#include "c2pool/v37/xmr/xmr_paynow.hpp"
#include "c2pool/v37/xmr/relay/xmr_share_verdict.hpp"

namespace x6   = ::v37::xmr::settle;
namespace fee  = c2pool::v37n::xmr::fee;
namespace o2   = c2pool::v37n::xmr::o2;
namespace st   = c2pool::v37n::settle;
namespace pn   = c2pool::v37n::xmr::paynow;
namespace cr   = c2pool::v37n::xmr::credit;
namespace auth = c2pool::v37n::xmr::authority;
namespace rc   = c2pool::v37n::xmr::recompute;
namespace asm_ = ::c2pool::xmr::assembly;
namespace akat = ::c2pool::xmr::assembly::kat;
namespace cons = ::c2pool::xmr::native;
using Amounts = std::map<::v37::bytes32, long long>;

static_assert(asm_::REWARD_TOTAL_FIELD_BYTES == pn::kRewardTotalFieldBytes,
              "the impl-tree mirror of the V37R field size");

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
constexpr std::uint32_t kChain = 0x0000ABCD;
constexpr std::uint64_t kHeight = 3000000;
constexpr std::uint64_t kAgc = 18000000000000000000ull;   // tail emission: 0.6 XMR subsidy

std::array<std::uint8_t, 32> point_of(std::uint8_t k) {
    ::xmr::coin::SecretKey sec{};
    sec.data()[0] = k;
    sec.data()[1] = 0x5a;
    ::xmr::coin::PublicKey pub{};
    if (!::xmr::coin::secret_key_to_public_key(sec, pub)) return {};
    std::array<std::uint8_t, 32> out{};
    std::memcpy(out.data(), pub.data(), 32);
    return out;
}
::v37::ScriptRef ref_of(std::uint8_t k) { return ::v37::xmr::make_xmr_std(point_of(k), point_of(static_cast<std::uint8_t>(k + 100))); }
::v37::bytes32 id_of(const ::v37::ScriptRef& r) { return ::v37::xmr::xmr_identity_key(r); }

struct Payee { ::v37::ScriptRef ref; ::v37::bytes32 id; std::uint64_t w = 1; };
Payee payee(std::uint8_t k, std::uint64_t w = 1) { Payee p; p.ref = ref_of(k); p.id = id_of(p.ref); p.w = w; return p; }

struct Lane {
    std::map<::v37::bytes32, ::v37::ScriptRef> refs;
    void learn(const Payee& p) { refs[p.id] = p.ref; }
    o2::PayOfFn pay_of() const {
        auto r = refs;
        return [r](const ::v37::bytes32& k) {
            auto it = r.find(k); if (it != r.end()) return it->second;
            ::v37::ScriptRef raw; raw.kind = ::v37::ScriptKind::RAW; return raw;
        };
    }
    Lane() { Payee d; d.ref = fee::donation_ref(kNet); d.id = fee::donation_identity(kNet); learn(d); }
};

int g_seed = 0;
void seed(st::OwedLedger& L, const ::v37::bytes32& k, long long amount, std::uint64_t bin) {
    const std::string bid = "seed-" + std::to_string(g_seed++);
    L.on_block_found(bid, Amounts{{k, amount}}, {});
    L.on_block_finalized(bid, bin);
}

std::vector<st::WeightedPayee> weighted(const std::vector<Payee>& ps) {
    std::vector<st::WeightedPayee> v;
    for (const auto& p : ps) { st::WeightedPayee w; w.key = p.id; w.weight = ::v37::U256(p.w); w.pay = p.ref; v.push_back(w); }
    return v;
}

cr::CreditCut the_cut() { cr::CreditCut c; c.next_pos = 4242; c.spine_digest[3] = 0x77; return c; }
::v37::bytes32 the_tag() { ::v37::bytes32 t{}; t[0] = 0xC2; t[31] = 0x37; return t; }

struct BuildOpts {
    std::vector<Payee> cut_payees;
    bool commit_total = true;
    std::function<void(x6::CoinbaseInputs&)> mutate;   // a modified builder
};

struct Block {
    bool ok = false;
    std::string why;
    std::vector<std::uint8_t> blob;
    std::uint64_t reward = 0;
    std::unique_ptr<asm_::AssembledTemplate> tpl;
};

Block build_block(const st::OwedLedger& L, const Lane& lane, const BuildOpts& o, std::uint32_t extra_nonce = 7) {
    Block out;
    const auto md = akat::miner(kHeight, 300000, kAgc);
    const std::uint64_t subsidy = asm_::xmr_base_reward(md.already_generated_coins);
    const auto mempool = akat::txs(3, 2000, 30000000);
    std::uint64_t fees = 0; for (const auto& t : mempool) fees += t.fee;
    o2::XmrCoinbaseContext ctx;
    ctx.monero_major_version = md.major_version;
    ctx.height = md.height;
    std::memcpy(ctx.prev_id.data(), md.prev_id.h, 32);
    ctx.base_reward = subsidy; ctx.fees = fees;
    ctx.chain_id = kChain;
    ctx.lane_commitment = L.owed_digest();
    ctx.residual_sink = fee::donation_ref(kNet); ctx.residual_sink_identity = fee::donation_identity(kNet);
    ctx.fixed = {fee::donation_marker(kNet)};
    ctx.h_min = 0; ctx.output_cap = 2700;
    ctx.has_credit_cut = true; ctx.credit_cut = the_cut();
    ctx.has_pool_tag = true; ctx.pool_tag = the_tag();
    ctx.has_paynow = true;
    ctx.paynow_payees = weighted(o.cut_payees);
    ctx.spend_floor = true;
    std::string why;
    auto src = o2::XmrOwedSettlementSource::build(L, lane.pay_of(), ctx, subsidy + fees, &why);
    if (!src) { out.why = "source: " + why; return out; }
    asm_::AssemblyInputs a;
    a.miner = md;
    a.mempool = mempool;
    a.settle = o2::assembly_settle_inputs(*src, /*weight_aware_cap=*/true);
    a.extra_nonce_tail = src->extra_nonce_tail();
    a.reward_total_field = o.commit_total;
    if (o.mutate) o.mutate(a.settle);   // the thief keeps the honest tails: only the outputs change
    a.extra_nonce_bind_size = 32;
    a.extra_nonce_bind = [](std::uint32_t en, std::uint8_t* b) { for (int i = 0; i < 32; ++i) b[i] = static_cast<std::uint8_t>(en * 13 + i); return true; };
    auto t = asm_::XmrBlockAssembler::build(a, &why);
    if (!t) { out.why = "assembler: " + why; return out; }
    asm_::BlockBytes b;
    if (!t->materialize(extra_nonce, b, &why)) { out.why = "materialize: " + why; return out; }
    out.ok = true;
    out.blob = b.full_blob;
    out.reward = t->reward();
    out.tpl = std::move(t);
    return out;
}

// What a relay peer has from a receipt: the opened tx_extra, H(prefix) resumed
// from the opening's midstate, and the hashing blob's height / parent.
struct Share {
    bool ok = false;
    std::vector<unsigned char> tx_extra;
    ::v37::bytes32 prefix_hash{};
    std::uint8_t major = 0;
    std::uint64_t height = 0;
    ::v37::bytes32 prev_id{};
    ::v37::xmr::CoinbaseOpening opening;
};
Share share_of(const Block& b) {
    Share s;
    cons::ParsedBlock pb;
    const auto st = cons::parse_block(b.blob.data(), b.blob.size(), pb);
    if (st != cons::BlockParseStatus::Ok && st != cons::BlockParseStatus::TxCountMismatch) return s;
    x6::ReceivedCoinbase rc; std::uint64_t h = 0; std::size_t used = 0;
    if (!asm_::parse_coinbase_prefix(b.blob.data() + pb.miner_tx_offset, pb.miner_tx_size, rc, &h, &used)) return s;
    const std::vector<std::uint8_t> prefix(b.blob.begin() + static_cast<std::ptrdiff_t>(pb.miner_tx_offset),
                                           b.blob.begin() + static_cast<std::ptrdiff_t>(pb.miner_tx_offset + used));
    ::v37::xmr::CoinbaseOpening op;
    if (!::v37::xmr::verify::build_coinbase_opening(prefix, prefix.size() - rc.tx_extra.size(), op)) return s;
    ::v37::bytes32 hp{};
    if (!::v37::xmr::verify::resume_prefix_hash(op, hp)) return s;
    // the opening's own hash is the tx-prefix hash (pinned against the direct one)
    const auto direct = ::xmr::coin::tx_prefix_hash(prefix);
    if (std::memcmp(direct.data(), hp.data(), 32) != 0) return s;
    s.ok = true;
    s.opening = op;
    s.tx_extra = op.tx_extra;
    s.prefix_hash = hp;
    s.major = static_cast<std::uint8_t>(pb.header.major_version);
    s.height = h;
    std::memcpy(s.prev_id.data(), pb.header.prev_id.data(), 32);
    return s;
}

rc::LaneInputs lane_inputs() {
    rc::LaneInputs li;
    li.chain_id = kChain; li.h_min = 0; li.owed_cap = 2700; li.wire_cap = 2700;
    li.residual_sink = fee::donation_ref(kNet); li.residual_sink_identity = fee::donation_identity(kNet);
    li.fixed = {fee::donation_marker(kNet)};
    li.pool_tag = the_tag();
    li.spend_floor = true;
    li.commit_total = true;
    return li;
}

struct World {
    Lane lane;
    Payee K1 = payee(21), K2 = payee(22), thief = payee(66);
    std::vector<Payee> cut = {payee(11, 1), payee(12, 2), payee(13, 3)};
    st::OwedLedger L{kChain};
    World() {
        for (const auto& p : cut) lane.learn(p);
        lane.learn(K1); lane.learn(K2);
        seed(L, K1.id, 40000000000ll, 10);
        seed(L, K2.id, 25000000000ll, 11);
    }
    rc::CutInputs cut_inputs() const { rc::CutInputs ci; ci.has_view = true; ci.payees = weighted(cut); return ci; }
    rc::Result verdict(const Share& s, const st::OwedLedger* other = nullptr) const {
        return rc::verify_share_coinbase(s.tx_extra, s.prefix_hash, s.major, s.height, s.prev_id,
                                         other ? *other : L, lane.pay_of(), lane_inputs(), cut_inputs());
    }
};

void s1_honest() {
    std::printf("== S1. honest share: canonical ==\n");
    World w;
    BuildOpts o; o.cut_payees = w.cut;
    for (const std::uint32_t en : {7u, 91u}) {
        const Block b = build_block(w.L, w.lane, o, en);
        CHECK(b.ok, "builds (extra_nonce %u): %s", en, b.ok ? "ok" : b.why.c_str());
        if (!b.ok) return;
        const Share s = share_of(b);
        CHECK(s.ok, "the receipt opening resumes to the tx-prefix hash");
        const auto t = pn::parse_reward_total(s.tx_extra);
        CHECK(t && *t == b.reward, "the opened tx_extra states V37R == the block reward %llu", (unsigned long long)b.reward);
        const auto r = w.verdict(s);
        CHECK(r.canonical(), "extra_nonce %u: %s %s", en, rc::to_string(r.verdict), r.why.c_str());
    }
}

void s2_thief_keeps_donation() {
    std::printf("== S2. thief template: the finder takes the owed queue, the donation output kept ==\n");
    World w;
    BuildOpts o; o.cut_payees = w.cut;
    o.mutate = [&](x6::CoinbaseInputs& in) {
        for (auto& e : in.owed) { e.pay = w.thief.ref; e.identity = w.thief.id; }
    };
    const Block b = build_block(w.L, w.lane, o);
    CHECK(b.ok, "builds: %s", b.ok ? "ok" : b.why.c_str());
    if (!b.ok) return;
    const Share s = share_of(b);
    bool has_d = false;
    for (const auto& x : b.tpl->outputs()) if (x.identity == fee::donation_identity(kNet)) has_d = true;
    CHECK(has_d, "the thief's coinbase still ends in the donation output");
    const auto r = w.verdict(s);
    CHECK(s.ok && r.verdict == rc::Verdict::Mismatch, "share: %s -- %s", rc::to_string(r.verdict), r.why.c_str());
}

void s3_thief_no_donation() {
    std::printf("== S3. thief template without the donation output ==\n");
    World w;
    BuildOpts o; o.cut_payees = w.cut;
    o.mutate = [&](x6::CoinbaseInputs& in) {
        in.fixed.clear();
        in.residual_sink = w.thief.ref; in.residual_sink_identity = w.thief.id;
        in.paynow_at = nullptr; in.paynow_n = 0;
        in.owed.clear();
    };
    const Block b = build_block(w.L, w.lane, o);
    CHECK(b.ok, "builds: %s", b.ok ? "ok" : b.why.c_str());
    if (!b.ok) return;
    const Share s = share_of(b);
    CHECK(s.ok && b.tpl->outputs().size() == 1 && b.tpl->outputs()[0].identity == w.thief.id,
          "the coinbase pays the whole reward to the thief (%zu output)", b.tpl->outputs().size());
    const auto r = w.verdict(s);
    CHECK(r.verdict == rc::Verdict::Mismatch, "share: %s -- %s", rc::to_string(r.verdict), r.why.c_str());
}

void s4_total_rewritten() {
    std::printf("== S4. the opened V37R total is rewritten ==\n");
    World w;
    BuildOpts o; o.cut_payees = w.cut;
    const Block b = build_block(w.L, w.lane, o);
    if (!b.ok) { CHECK(false, "builds: %s", b.why.c_str()); return; }
    Share s = share_of(b);
    const auto nf = cr::extra_nonce_field(s.tx_extra);
    bool patched = false;
    if (nf) {
        const std::size_t end = pn::end_before_finder(*nf);
        // locate the payload inside tx_extra and bump the total's low byte
        for (std::size_t i = 0; i + nf->size() <= s.tx_extra.size(); ++i)
            if (std::equal(nf->begin(), nf->end(), s.tx_extra.begin() + static_cast<std::ptrdiff_t>(i))) {
                s.tx_extra[i + end - 8] ^= 0x01; patched = true; break;
            }
    }
    CHECK(patched, "the V37R value was rewritten in the opened tx_extra");
    const auto r = w.verdict(s);
    CHECK(r.verdict == rc::Verdict::Mismatch, "share: %s -- %s", rc::to_string(r.verdict), r.why.c_str());
}

void s5_no_total() {
    std::printf("== S5. a template without V37R ==\n");
    World w;
    BuildOpts o; o.cut_payees = w.cut; o.commit_total = false;
    const Block b = build_block(w.L, w.lane, o);
    if (!b.ok) { CHECK(false, "builds: %s", b.why.c_str()); return; }
    const Share s = share_of(b);
    const auto r = w.verdict(s);
    CHECK(s.ok && r.verdict == rc::Verdict::Mismatch && r.why.find("V37R") != std::string::npos,
          "share: %s -- %s", rc::to_string(r.verdict), r.why.c_str());
}

void s6_other_state() {
    std::printf("== S6. the verifier holds another ledger state ==\n");
    World w;
    BuildOpts o; o.cut_payees = w.cut;
    const Block b = build_block(w.L, w.lane, o);
    if (!b.ok) { CHECK(false, "builds: %s", b.why.c_str()); return; }
    const Share s = share_of(b);
    st::OwedLedger other = w.L;
    seed(other, w.K2.id, 1000000000ll, 12);
    const auto r = w.verdict(s, &other);
    CHECK(r.verdict == rc::Verdict::Undecidable, "share: %s -- %s", rc::to_string(r.verdict), r.why.c_str());
}

void s7_block_path() {
    std::printf("== S7. the block path: V37R == the output sum ==\n");
    World w;
    BuildOpts o; o.cut_payees = w.cut;
    const Block b = build_block(w.L, w.lane, o);
    if (!b.ok) { CHECK(false, "builds: %s", b.why.c_str()); return; }
    std::vector<::v37::bytes32> keys;
    for (const auto& [k, r] : w.lane.refs) { (void)r; keys.push_back(k); }
    const ::v37::bytes32 tag = the_tag();
    const auto bk = auth::decode_lane_coinbase_fee(b.blob, kChain, {w.L.owed_digest()}, keys, w.lane.pay_of(), kNet, &tag);
    const auto r = rc::verify_lane_coinbase(b.blob, bk, w.L, w.lane.pay_of(), lane_inputs(), w.cut_inputs());
    CHECK(bk.ok && r.canonical(), "the honest block with V37R is canonical: %s %s", rc::to_string(r.verdict), r.why.c_str());
    BuildOpts o2; o2.cut_payees = w.cut; o2.commit_total = false;
    const Block b2 = build_block(w.L, w.lane, o2);
    if (!b2.ok) { CHECK(false, "builds: %s", b2.why.c_str()); return; }
    const auto bk2 = auth::decode_lane_coinbase_fee(b2.blob, kChain, {w.L.owed_digest()}, keys, w.lane.pay_of(), kNet, &tag);
    const auto r2 = rc::verify_lane_coinbase(b2.blob, bk2, w.L, w.lane.pay_of(), lane_inputs(), w.cut_inputs());
    CHECK(r2.verdict == rc::Verdict::Mismatch && r2.why.find("V37R") != std::string::npos,
          "a lane block without V37R under the rule: %s -- %s", rc::to_string(r2.verdict), r2.why.c_str());
}

void s8_cost() {
    std::printf("== S8. cost of one share verdict ==\n");
    World w;
    BuildOpts o; o.cut_payees = w.cut;
    const Block b = build_block(w.L, w.lane, o);
    if (!b.ok) { CHECK(false, "builds: %s", b.why.c_str()); return; }
    const Share s = share_of(b);
    const int n = 50;
    int ok = 0;
    const auto t0 = std::chrono::steady_clock::now();
    for (int i = 0; i < n; ++i) ok += w.verdict(s).canonical() ? 1 : 0;
    const auto us = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - t0).count();
    std::printf("    %d verdicts on a %zu-output coinbase: %lld us each (derivations cached)\n",
                n, b.tpl->outputs().size(), static_cast<long long>(us / n));
    CHECK(ok == n, "every repeat is canonical (%d/%d)", ok, n);
}

void s9_relay_store() {
    std::printf("== S9. the relay verdict through the published state store (ANCHOR rule) ==\n");
    namespace rl = c2pool::v37n::xmr::relay;
    World w;
    st::OwedLedgerRules R; R.anchor_cut = true;
    st::OwedLedger L(kChain, R);
    seed(L, w.K1.id, 40000000000ll, 10);
    {   // a lane block finalized with its cut: the ledger's anchor (its view: w.cut)
        st::AnchorCut a; a.next_pos = 4242; a.spine[3] = 0x77;
        L.on_block_found("lane-1", Amounts{}, {}, a);
        L.on_block_finalized("lane-1", 12);
    }
    rl::ShareStateStore store;
    auto publish = [&](bool with_view) {
        auto e = std::make_shared<rl::ShareStateEntry>();
        e->digest = L.owed_digest();
        const auto r = x6::mm_commitment_root(kChain, e->digest);
        std::memcpy(e->root.data(), r.data(), 32);
        e->ledger = std::make_shared<st::OwedLedger>(L);
        (void)e->ledger->owed_digest();
        e->refs = w.lane.refs;
        e->lane = lane_inputs();
        e->has_view = with_view; e->view_ratified = with_view;
        if (with_view) e->payees = weighted(w.cut);
        std::lock_guard<std::mutex> lk(store.mu);
        store.ring.clear();
        store.ring.push_back(e);
    };
    auto verdict = [&](const Share& sh, std::string& why) {
        rl::FbReceipt fb;
        fb.receipt.coinbase_opening = sh.opening;
        ::v37::xmr::verify::ParsedBlob pb;
        pb.major = sh.major; pb.prev_id = sh.prev_id;
        return rl::share_verdict(store, fb, pb, sh.height, why);
    };
    BuildOpts o; o.cut_payees = w.cut;
    const Block b = build_block(L, w.lane, o);
    CHECK(b.ok, "an honest template on the anchor ledger builds: %s", b.ok ? "ok" : b.why.c_str());
    if (!b.ok) return;
    const Share sh = share_of(b);
    std::string why;
    CHECK(verdict(sh, why) == 0, "the state is not published yet: undecidable (%s)", why.c_str());
    publish(false);
    CHECK(verdict(sh, why) == 0, "published without the view at its anchor: undecidable (%s)", why.c_str());
    publish(true);
    CHECK(verdict(sh, why) == 1, "published with the view: CANONICAL (%s)", why.c_str());
    BuildOpts t; t.cut_payees = w.cut;
    t.mutate = [&](x6::CoinbaseInputs& in) { in.paynow_at = nullptr; in.paynow_n = 0; in.owed.clear();
                                             x6::OwedEntry e; e.pay = w.thief.ref; e.identity = w.thief.id; e.owed = 1ull << 50; in.owed.push_back(e); };
    const Block tb = build_block(L, w.lane, t);
    CHECK(tb.ok, "a thief template on the same state builds: %s", tb.ok ? "ok" : tb.why.c_str());
    if (tb.ok) {
        const int v = verdict(share_of(tb), why);
        CHECK(v == -1, "the thief's share: REFUSED (%s)", why.c_str());
    }
}

void s10_template_cache() {
    std::printf("== S10. the per-template cache: one rebuild per template, then one Keccak per share ==\n");
    namespace rl = c2pool::v37n::xmr::relay;
    World w;
    rl::ShareStateStore store;
    auto e = std::make_shared<rl::ShareStateEntry>();
    e->digest = w.L.owed_digest();
    const auto r = x6::mm_commitment_root(kChain, e->digest);
    std::memcpy(e->root.data(), r.data(), 32);
    e->ledger = std::make_shared<st::OwedLedger>(w.L);
    (void)e->ledger->owed_digest();
    e->refs = w.lane.refs;
    e->lane = lane_inputs();
    e->has_view = true; e->view_ratified = true;
    e->payees = weighted(w.cut);
    store.ring.push_back(e);
    auto verdict = [&](const Share& sh, std::string& why) {
        rl::FbReceipt fb;
        fb.receipt.coinbase_opening = sh.opening;
        ::v37::xmr::verify::ParsedBlob pb;
        pb.major = sh.major; pb.prev_id = sh.prev_id;
        return rl::share_verdict(store, fb, pb, sh.height, why);
    };
    BuildOpts o; o.cut_payees = w.cut;
    std::vector<Share> shares;
    for (const std::uint32_t en : {7u, 91u, 1234u, 65000u}) {
        const Block b = build_block(w.L, w.lane, o, en);
        if (!b.ok) { CHECK(false, "builds: %s", b.why.c_str()); return; }
        shares.push_back(share_of(b));
    }
    std::string why;
    CHECK(verdict(shares[0], why) == 1 && e->cache->misses == 1 && e->cache->hits == 0,
          "the first share of the template: canonical, one rebuild (misses %llu)", (unsigned long long)e->cache->misses);
    bool all = true;
    for (std::size_t i = 1; i < shares.size(); ++i) all = all && verdict(shares[i], why) == 1;
    CHECK(all && e->cache->hits == 3 && e->cache->misses == 1,
          "three more workers' shares (other extra-nonces): canonical from the cache (hits %llu)", (unsigned long long)e->cache->hits);
    BuildOpts t; t.cut_payees = w.cut;
    t.mutate = [&](x6::CoinbaseInputs& in) { for (auto& x : in.owed) { x.pay = w.thief.ref; x.identity = w.thief.id; } };
    const Block tb = build_block(w.L, w.lane, t, 91);
    if (tb.ok) {
        const int v = verdict(share_of(tb), why);
        CHECK(v == -1, "a thief share with the same template tails: REFUSED through the cache (%s)", why.c_str());
    }
    const int n = 200;
    int ok = 0;
    const auto t0 = std::chrono::steady_clock::now();
    for (int i = 0; i < n; ++i) ok += verdict(shares[static_cast<std::size_t>(i) % shares.size()], why) == 1;
    const auto us = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - t0).count();
    std::printf("    %d cached verdicts: %lld us each (vs a full rebuild in S8)\n", n, static_cast<long long>(us / n));
    CHECK(ok == n, "every cached verdict is canonical (%d/%d)", ok, n);
}

}  // namespace

int main() {
    std::printf("v37_xmr_share_verdict_kat\n");
    s1_honest();
    s2_thief_keeps_donation();
    s3_thief_no_donation();
    s4_total_rewritten();
    s5_no_total();
    s6_other_state();
    s7_block_path();
    s8_cost();
    s9_relay_store();
    s10_template_cache();
    std::printf("\n%d/%d checks passed -- %s\n", g_checks - g_fail, g_checks, g_fail ? "FAIL" : "ALL PASS");
    return g_fail ? 1 : 0;
}
