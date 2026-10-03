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
//   S12 a sibling FOUND (same owed_digest, next ledger_seq): shares of both
//       states are canonical; a forged or mixed share is refused; the state
//       store is bounded (handoff gap 1).
//   S14 HOLD-ROUND-2 V2: an F-capped take (F below R*dh/256, or both dh past
//       H_cap) is AHEAD / BEHIND too, 120 copies -> strikes 0 bans 0; a take
//       above every drain regime still strikes.
//   S13 HOLD-ROUND-2 (B): a drain take that is the Delta at another dh is
//       lane-prefix SKEW: AHEAD (parked) / BEHIND / LATE (dropped), never -1;
//       a forged take or a thief template stays -1; the AHEAD share re-judges
//       canonical once the state advances (stagenet attempt 7's ban loop).
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
#include "impl/xmr/wire/xmr_carrier_dos_budget.hpp"
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
::v37::bytes32 the_tag() { ::v37::bytes32 t{}; t[0] = 0xC2; t[31] = 0x37; return t; }   // the pool_id of this rig
cr::PoolField the_field() { return cr::PoolField{the_tag(), 1, 1}; }                         // RULES RATCHET: V37P v2 (epoch 1 of 1)

struct BuildOpts {
    std::vector<Payee> cut_payees;
    bool commit_total = true;
    std::function<void(x6::CoinbaseInputs&)> mutate;   // a modified builder
    // HOLD-ROUND-2 (B): THE DRAIN RULE on (spend floor, {1,16,64}) with the
    // provider's reward fixpoint; retail = re-derive the V37N / V37D tails from
    // the MUTATED inputs (a builder that commits a forged take)
    bool drain = false;
    bool retail = false;
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
    ctx.has_pool_field = true; ctx.pool_field = the_field();   // RULES RATCHET: the V37P v2 head
    ctx.has_paynow = true;
    ctx.paynow_payees = weighted(o.cut_payees);
    ctx.spend_floor = true;
    if (o.drain) ctx.drain = o2::DrainRule{1, 16, 64};
    std::string why;
    auto src = o2::XmrOwedSettlementSource::build(L, lane.pay_of(), ctx, subsidy + fees, &why);
    if (!src) { out.why = "source: " + why; return out; }
    asm_::AssemblyInputs a;
    a.miner = md;
    a.mempool = mempool;
    a.reward_total_field = o.commit_total;
    auto settle_from = [&]() {
        a.settle = o2::assembly_settle_inputs(*src, /*weight_aware_cap=*/true);
        a.extra_nonce_tail = src->extra_nonce_tail();
        a.extra_nonce_head = src->extra_nonce_head();   // RULES RATCHET: the V37P v2 head
        if (o.mutate) o.mutate(a.settle);   // the thief keeps the honest tails: only the outputs change
        if (o.mutate && o.retail) {         // ... unless it re-derives them (a forged V37N base)
            std::vector<std::uint8_t> t;
            if (src->paynow_on()) {
                std::uint64_t B = 0;
                for (const auto& f : a.settle.fixed) B += f.amount;
                for (const auto& e : a.settle.owed) B += e.owed;
                const auto n = pn::encode_tail(B); t.insert(t.end(), n.begin(), n.end());
            }
            const auto d = fee::encode_donation_owed_tail(x6::fold_identity_owed(a.settle)); t.insert(t.end(), d.begin(), d.end());
            const auto c = cr::encode_tail(the_cut()); t.insert(t.end(), c.begin(), c.end());
            a.extra_nonce_tail = t;
        }
    };
    settle_from();
    a.extra_nonce_bind_size = 32;
    a.extra_nonce_bind = [](std::uint32_t en, std::uint8_t* b) { for (int i = 0; i < 32; ++i) b[i] = static_cast<std::uint8_t>(en * 13 + i); return true; };
    auto t = asm_::XmrBlockAssembler::build(a, &why);
    if (!t) { out.why = "assembler: " + why; return out; }
    // THE DRAIN RULE: the provider's reward fixpoint (the takes are chosen at the FINAL reward)
    for (int pass = 0; o.drain && src->drain_on() && t->reward() != src->reward_hint() && pass < 4; ++pass) {
        src = o2::XmrOwedSettlementSource::build(L, lane.pay_of(), ctx, t->reward(), &why);
        if (!src) { out.why = "source (fixpoint): " + why; return out; }
        settle_from();
        t = asm_::XmrBlockAssembler::build(a, &why);
        if (!t) { out.why = "assembler (fixpoint): " + why; return out; }
    }
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
    li.pool_field = the_field();
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

// S11 (handoffs A5 + A4b): the share verdict reads the DROPS WINDOW from the
// frozen ledger it is handed (XmrOwedSettlementSource::build), like the
// builder: the pay-now split is the cut's payees plus the window at the cut.
void s11_drops_due() {
    std::printf("== S11. the share verdict reads the DROPS window of its ledger (A4b) ==\n");
#if defined(C2POOL_XMR_DROPS_WINDOW)
    World w;
    const Payee X = payee(77);        // a DROPS-only miner: no share in the view
    w.lane.learn(X);                  // its ref, taught with the booked composition (note_booked_refs)
    st::OwedLedgerRules rules; rules.drops_due = true;
    rules.drops_window = st::DropsWindowRule{8640, 2160, 4096, 1, 62};   // work == lane weight (lz 62, rw 1)
    st::OwedLedger D(kChain, rules), N(kChain, rules);
    for (st::OwedLedger* L : {&D, &N}) { seed(*L, w.K1.id, 40000000000ll, 10); seed(*L, w.K2.id, 25000000000ll, 11); }
    const std::uint64_t c = the_cut().next_pos;   // the entries sit at the cut (age 0)
    st::DropsFound dep; dep.window = {{{c, X.id}, 2ll}, {{c, w.cut[0].id}, -3ll}};
    D.on_block_found("dep", {}, {}, std::nullopt, &dep);
    D.on_block_finalized("dep", 12);
    N.on_block_found("dep", {}, {}, std::nullopt);
    N.on_block_finalized("dep", 12);
    CHECK(D.drops_window().size() == 2 && N.drops_window().empty() && D.drops_due().empty(),
          "ledger D holds window entries for 2 keys (no due), ledger N none");
    BuildOpts o; o.cut_payees = w.cut;
    const Block b = build_block(D, w.lane, o);
    CHECK(b.ok, "a template on D builds: %s", b.ok ? "ok" : b.why.c_str());
    if (!b.ok) return;
    const Share s = share_of(b);
    const auto r = w.verdict(s, &D);
    CHECK(r.canonical(), "a share of the honest template (the window in pay-now) is canonical against D: %s %s", rc::to_string(r.verdict), r.why.c_str());
    const auto rn = w.verdict(s, &N);
    CHECK(!rn.canonical(), "the same share is NOT canonical against a ledger without the window: %s", rc::to_string(rn.verdict));
    BuildOpts om = o;   // a builder that forgets the window: the DROPS-only payee left out
    om.mutate = [&](x6::CoinbaseInputs& in) {
        auto orig = in.paynow_at;
        const ::v37::bytes32 xid = X.id;
        in.paynow_at = [orig, xid](std::uint64_t budget) {
            std::vector<x6::PayNowEntry> out;
            for (auto e : orig(budget)) if (!(e.identity == xid)) out.push_back(e);
            return out;
        };
    };
    const Block bm = build_block(D, w.lane, om);
    CHECK(bm.ok, "the window-omitting template builds");
    if (!bm.ok) return;
    const auto rm = w.verdict(share_of(bm), &D);
    CHECK(!rm.canonical(), "a share of a template that omits the window is refused: %s %s", rc::to_string(rm.verdict), rm.why.c_str());
#else
    CHECK(false, "no DROPS window rule on the base");
#endif
}

// S12 (handoff gap 1): a sibling FOUND bumps ledger_seq, not owed_digest, and
// the builder then reads the new pending claims (A5 avail). The relay store is
// keyed by (digest, ledger_seq) and the verdict tries every held state with
// the share's root, so a share built before the FOUND and one built after it
// are both canonical. On the base the store is keyed by the digest (the first
// state of a digest is kept) and the verdict reads only the newest root match.
namespace rl = c2pool::v37n::xmr::relay;
std::shared_ptr<rl::ShareStateEntry> state_entry(const st::OwedLedger& L, const World& w) {
    auto e = std::make_shared<rl::ShareStateEntry>();
    e->digest = L.owed_digest();
#if defined(C2POOL_XMR_SHARE_STATE_BY_SEQ)
    e->ledger_seq = L.ledger_seq();
#endif
    const auto r = x6::mm_commitment_root(kChain, e->digest);
    std::memcpy(e->root.data(), r.data(), 32);
    e->ledger = std::make_shared<st::OwedLedger>(L);
    (void)e->ledger->owed_digest();
    e->refs = w.lane.refs;
    e->lane = lane_inputs();
    e->has_view = true; e->view_ratified = true;
    e->payees = weighted(w.cut);
    return e;
}
// The node's publisher rule (main_v37_xmr.cpp share_publish).
void publish_state(rl::ShareStateStore& store, const st::OwedLedger& L, const World& w) {
#if defined(C2POOL_XMR_SHARE_STATE_BY_SEQ)
    if (auto x = store.find_state(L.owed_digest(), L.ledger_seq()); x && x->has_view) return;
    store.put(state_entry(L, w));
#else   // the base: an entry with the same owed_digest (and a view) is kept as is
    std::lock_guard<std::mutex> lk(store.mu);
    for (const auto& x : store.ring) if (x->digest == L.owed_digest() && x->has_view) return;
    store.ring.push_back(state_entry(L, w));
    while (store.ring.size() > 16) store.ring.pop_front();
#endif
}
int relay_verdict(rl::ShareStateStore& store, const Share& sh, std::string& why) {
    rl::FbReceipt fb;
    fb.receipt.coinbase_opening = sh.opening;
    ::v37::xmr::verify::ParsedBlob pb;
    pb.major = sh.major; pb.prev_id = sh.prev_id;
    return rl::share_verdict(store, fb, pb, sh.height, why);
}

void s12_state_by_seq() {
    std::printf("== S12. a sibling FOUND: same owed_digest, next ledger_seq (gap 1) ==\n");
    World w;
    const Payee X = payee(77);   // a DROPS-only miner with a due
    w.lane.learn(X);
    st::OwedLedgerRules rules; rules.drops_due = true;
    st::OwedLedger D(kChain, rules);
    seed(D, w.K1.id, 40000000000ll, 10); seed(D, w.K2.id, 25000000000ll, 11);
    st::DropsFound dep; dep.deposit = {{X.id, 3000000000ll}};
    D.on_block_found("dep", {}, {}, std::nullopt, &dep);
    D.on_block_finalized("dep", 12);
    const st::OwedLedger Dn = D;   // state n: X has a due
    st::DropsFound sib; sib.claim = true; sib.claimed = D.drops_available();
    D.on_block_found("sibling", {}, {}, std::nullopt, &sib);   // a sibling lane block claims it
    const st::OwedLedger Dn1 = D;  // state n+1
    CHECK(Dn.owed_digest() == Dn1.owed_digest() && Dn1.ledger_seq() == Dn.ledger_seq() + 1,
          "the FOUND keeps owed_digest and bumps ledger_seq (%llu -> %llu)",
          (unsigned long long)Dn.ledger_seq(), (unsigned long long)Dn1.ledger_seq());
    CHECK(Dn.drops_available().count(X.id) == 1 && Dn1.drops_available().count(X.id) == 0,
          "avail(X) is claimed by the pending sibling: the builder's input changed");
    BuildOpts o; o.cut_payees = w.cut;
    const Block bn = build_block(Dn, w.lane, o), bn1 = build_block(Dn1, w.lane, o);
    CHECK(bn.ok && bn1.ok, "a template on each state builds");
    if (!bn.ok || !bn1.ok) return;
    const Share sa = share_of(bn), sb = share_of(bn1);
    CHECK(sa.ok && sb.ok && sa.prefix_hash != sb.prefix_hash, "the two canonical coinbases differ (same 0x03 root)");
    std::string why;
    {   // the node's publisher, at state n and again at state n+1
        rl::ShareStateStore store;
        publish_state(store, Dn, w);
        publish_state(store, Dn1, w);
        const int va = relay_verdict(store, sa, why);
        CHECK(va == 1, "publisher at n, n+1: the share built BEFORE the FOUND is canonical (%d: %s)", va, why.c_str());
        const int vb = relay_verdict(store, sb, why);
        CHECK(vb == 1, "publisher at n, n+1: the share built AFTER the FOUND is canonical (%d: %s)", vb, why.c_str());
    }
    rl::ShareStateStore both;   // both states held, n+1 newest
    both.ring.push_back(state_entry(Dn, w)); both.ring.push_back(state_entry(Dn1, w));
    const int va = relay_verdict(both, sa, why);
    CHECK(va == 1, "both states held: the share built BEFORE the FOUND is canonical (%d: %s)", va, why.c_str());
    const int vb = relay_verdict(both, sb, why);
    CHECK(vb == 1, "both states held: the share built AFTER the FOUND is canonical (%d: %s)", vb, why.c_str());
    BuildOpts t; t.cut_payees = w.cut;   // a forged share: the owed queue to the thief
    t.mutate = [&](x6::CoinbaseInputs& in) { for (auto& x : in.owed) { x.pay = w.thief.ref; x.identity = w.thief.id; } };
    const Block tb = build_block(Dn1, w.lane, t);
    CHECK(tb.ok, "the forged template builds: %s", tb.ok ? "ok" : tb.why.c_str());
    if (tb.ok) {
        const int v = relay_verdict(both, share_of(tb), why);
        CHECK(v == -1, "a forged share on the same root: REFUSED against every held state (%s)", why.c_str());
    }
    BuildOpts om = o;   // a stale mix: the due of state n paid on top of state n+1's claim
    om.mutate = [&](x6::CoinbaseInputs& in) { x6::OwedEntry e; e.pay = X.ref; e.identity = X.id; e.owed = 3000000000ull; in.owed.push_back(e); };
    const Block mb = build_block(Dn1, w.lane, om);
    CHECK(mb.ok, "the mixed template builds: %s", mb.ok ? "ok" : mb.why.c_str());
    if (mb.ok) {
        const int v = relay_verdict(both, share_of(mb), why);
        CHECK(v == -1, "a share that is canonical for neither state: REFUSED (%s)", why.c_str());
    }
#if defined(C2POOL_XMR_SHARE_STATE_BY_SEQ)
    {   // retention: kMaxStates entries; the oldest is evicted
        rl::ShareStateStore store;
        store.put(state_entry(Dn, w));
        st::OwedLedger Lk = Dn1;
        for (std::size_t i = 0; i < rl::ShareStateStore::kMaxStates; ++i) {
            st::DropsFound s2; s2.claim = true;
            Lk.on_block_found("more-" + std::to_string(i), {}, {}, std::nullopt, &s2);
            store.put(state_entry(Lk, w));
        }
        const bool evicted = !store.find_state(Dn.owed_digest(), Dn.ledger_seq());
        CHECK(store.ring.size() == rl::ShareStateStore::kMaxStates && evicted,
              "retention bound %zu: %zu held after %zu puts, the oldest (seq %llu) evicted",
              rl::ShareStateStore::kMaxStates, store.ring.size(), rl::ShareStateStore::kMaxStates + 1,
              (unsigned long long)Dn.ledger_seq());
        const int v = relay_verdict(store, sa, why);
        CHECK(v != 1, "a share of the evicted state is no longer canonical here (%d: %s)", v, why.c_str());
    }
#else
    CHECK(false, "no (digest, ledger_seq) state key on the base: no retention test");
#endif
}

// ── S13 (HOLD-ROUND-2 B): lane-prefix SKEW is never a strike ──────────────
// Stagenet attempt 7: the finder B FOUND h=2220689; its next shares committed
// owed takes cut at dh 4 (R*4/256) while receivers A/C, whose ledger did not
// hold that lane block yet, rebuilt them at dh 14 (R*14/256): "under-take" ->
// -1 -> a strike each -> B banned every ~3 s. Here: L0 = prev lane at h-14;
// L1 = L0 + a PENDING lane block at h-4 (same owed_digest, next ledger_seq).
//   B1 a share built on L1, judged by a store holding L0 only -> AHEAD (2)
//   B2 a share built on L0, judged by a store holding L1 only -> BEHIND (3)
//   B2b a share built on L0, judged on L2 (a lane block AT the share's height) -> LATE (4)
//   B3 a forged take (no dh' reproduces it) and a thief template -> -1 (strike) as before
//   B4 the store then receives L1 (share_publish): the AHEAD share re-judged -> 1
#if defined(C2POOL_XMR_SHARE_VERDICT_SKEW)
constexpr int kAhead = rl::kShareVerdictAhead, kBehind = rl::kShareVerdictBehind, kLate = rl::kShareVerdictLate;
#else
constexpr int kAhead = 2, kBehind = 3, kLate = 4;   // the base has no skew codes (it returns -1)
#endif
rc::LaneInputs lane_inputs_drain() { rc::LaneInputs li = lane_inputs(); li.drain = o2::DrainRule{1, 16, 64}; return li; }
std::shared_ptr<rl::ShareStateEntry> drain_entry(const st::OwedLedger& L, const World& w) {
    auto e = state_entry(L, w);
    e->lane = lane_inputs_drain();
    return e;
}
void s13_lane_prefix_skew() {
    std::printf("== S13. lane-prefix skew (the drain take at another dh): park / drop, never a strike ==\n");
    World w;
    st::OwedLedgerRules rules; rules.lane_height = true;
    st::OwedLedger L0(kChain, rules);
    seed(L0, w.K1.id, 40000000000ll, 10); seed(L0, w.K2.id, 25000000000ll, 11);
    st::LaneFound la; la.height = kHeight - 14;
    L0.on_block_found("lane-a", Amounts{{w.K1.id, 1000}}, {}, std::nullopt, nullptr, &la);
    L0.on_block_finalized("lane-a", 12);
    st::OwedLedger L1 = L0;
    st::LaneFound lb; lb.height = kHeight - 4;
    L1.on_block_found("lane-b", Amounts{}, {}, std::nullopt, nullptr, &lb);   // the finder's own FOUND, pending
    st::OwedLedger L2 = L0;
    st::LaneFound lc; lc.height = kHeight;
    L2.on_block_found("lane-c", Amounts{}, {}, std::nullopt, nullptr, &lc);   // a lane block AT the share's height
    CHECK(L0.prev_lane_height() == kHeight - 14 && L1.prev_lane_height() == kHeight - 4 && L2.prev_lane_height() == kHeight &&
          L0.owed_digest() == L1.owed_digest() && L1.ledger_seq() == L0.ledger_seq() + 1,
          "L0 prev_lane h-14, L1 = L0 + pending lane block at h-4 (same owed_digest, seq+1), L2 prev_lane = h");
    BuildOpts o; o.cut_payees = w.cut; o.drain = true;
    const Block b0 = build_block(L0, w.lane, o), b1 = build_block(L1, w.lane, o);
    CHECK(b0.ok && b1.ok, "drain templates build on L0 and L1: %s %s", b0.why.c_str(), b1.why.c_str());
    if (!b0.ok || !b1.ok) return;
    const Share s0 = share_of(b0), s1 = share_of(b1);
    std::string why;
    {   // each share is canonical on its own state (the drain rule, both sides)
        rl::ShareStateStore own0, own1;
        own0.put(drain_entry(L0, w)); own1.put(drain_entry(L1, w));
        const int v0 = relay_verdict(own0, s0, why); const std::string w0 = why;
        const int v1 = relay_verdict(own1, s1, why);
        CHECK(v0 == 1 && v1 == 1, "each share is CANONICAL on the state it was built on (L0: %d %s; L1: %d %s)", v0, w0.c_str(), v1, why.c_str());
    }
    rl::ShareStateStore at0;   // the receiver: the finder's lane block not booked here yet
    at0.put(drain_entry(L0, w));
    const int vb1 = relay_verdict(at0, s1, why);
    CHECK(vb1 == kAhead && why.find("ahead") != std::string::npos,
          "B1 the finder's post-FOUND share on a receiver at L0: AHEAD (%d, never a strike; base: -1 under-take -> strike) -- %s", vb1, why.c_str());
    rl::ShareStateStore at1;
    at1.put(drain_entry(L1, w));
    const int vb2 = relay_verdict(at1, s0, why);
    CHECK(vb2 == kBehind && why.find("behind") != std::string::npos,
          "B2 a share built before the receiver's lane block: BEHIND (%d, dropped, never a strike; base: -1 over-take) -- %s", vb2, why.c_str());
    rl::ShareStateStore at2;
    at2.put(drain_entry(L2, w));
    const int vb2b = relay_verdict(at2, s0, why);
    CHECK(vb2b == kLate && why.find("late") != std::string::npos,
          "B2b a lane block AT the share's height is booked here (dh 0 -> cap): LATE (%d, dropped; base: -1, the attempt-7 'dh 0' re-offers) -- %s",
          vb2b, why.c_str());
    {   // B3: a forged take (+1.000000007 XMR over Delta, its V37N re-derived) and a thief template stay -1
        BuildOpts f = o; f.retail = true;
        f.mutate = [](x6::CoinbaseInputs& in) { if (!in.owed.empty()) in.owed.front().owed += 1000000007ull; in.drain_budget += 1000000007ull; };
        const Block fb = build_block(L0, w.lane, f);
        CHECK(fb.ok, "a forged-take template builds: %s", fb.why.c_str());
        if (fb.ok) {
            const int v = relay_verdict(at0, share_of(fb), why);
            CHECK(v == -1 && why.find("take") != std::string::npos, "B3 a forged take no dh' reproduces: REFUSED -1 (a strike, as before) -- %s", why.c_str());
        }
        BuildOpts t = o;
        t.mutate = [&](x6::CoinbaseInputs& in) { for (auto& x : in.owed) { x.pay = w.thief.ref; x.identity = w.thief.id; } };
        const Block tb = build_block(L0, w.lane, t);
        if (tb.ok) {
            const int v = relay_verdict(at0, share_of(tb), why);
            CHECK(v == -1, "B3 a thief template (the owed queue to the thief, honest takes): REFUSED -1 (%s)", why.c_str());
        }
    }
    // B4: the receiver books the finder's lane block (share_publish puts L1): the AHEAD share is canonical
    at0.put(drain_entry(L1, w));
    const int vb4 = relay_verdict(at0, s1, why);
    CHECK(vb4 == 1, "B4 after the state advances to L1 the parked share re-judges CANONICAL (%d %s)", vb4, why.c_str());
    // the inversion is integer-only and bounded: Delta(dh') at <= log2(64)+3 evaluations
#if defined(C2POOL_XMR_RECOMPUTE_TAKE_SKEW)
    const std::uint64_t R = 600000000000ull, F = 176492049454ull;
    const std::uint64_t took_b = R * 4 / 256;   // the attempt-7 numbers: B dh 4, A dh 14
    CHECK(rc::drain_skew_dh(took_b, F, R, 14, 16, 64) == 4 && rc::drain_skew_dh(R * 14 / 256, F, R, 4, 16, 64) == 14 &&
          rc::drain_skew_dh(took_b + 1, F, R, 14, 16, 64) == 0 && rc::drain_skew_dh(took_b, F, R, 4, 16, 64) == 0 &&
          rc::drain_skew_dh(took_b, took_b, R, 14, 16, 64) == 0,
          "drain_skew_dh: attempt-7 9375000000 at ours dh 14 -> 4; 32812500000 at dh 4 -> 14; +1 -> none; our own dh -> none; took >= F -> none");
#else
    CHECK(false, "no drain_skew_dh on the base");
#endif
}

// ── S14 (HOLD-ROUND-2 V2): an F-capped take is a skew too, never a strike ──
// VERIFY V2: the dh-only inversion (drain_skew_dh) is exact only while the
// take is below F on BOTH sides; past that it fell back to -1. Attempt 7's F
// fell 5.0e11 -> 1.65e11 in 6 h against R/4 = 1.5e11: the ban loop was hours
// away. Same owed_digest, the sender one PENDING lane block apart (its payout
// lowers the sender's F):
//   V2a F below R*dh/256 on both sides (F ~7e9 < R*4/256 ~1.33e10): the
//       finder's share (took = F_s) on a receiver without its block -> AHEAD;
//       the mirror (took = F_r > ours) -> BEHIND; 120 copies of each through
//       the relay's DoS budget -> strikes 0, bans 0; the state advances -> 1.
//   V2b both dh past H_cap (dh 100 vs 80 > 64), F_r > G(64) > F_s: the
//       F-capped take -> AHEAD; the mirror (G(64) >= our F) -> BEHIND.
//   V2c forged takes outside every drain regime still strike: above G(H_cap)
//       (in the small-F world and the past-H_cap world) and B3's over-take
//       below our F off every larger dh.
int s14_judge_n(rl::ShareStateStore& st, const Share& sh, int n, std::uint64_t& strikes, std::uint64_t& bans,
                std::uint64_t& parked, std::uint64_t& dropped, std::string& why) {
    ::c2pool::xmr::CarrierDosBudget dos;
    bool banned = false;
    int v = 0;
    for (int i = 0; i < n; ++i) {
        v = relay_verdict(st, sh, why);
        if (v < 0) { ++strikes; if (dos.on_cheap_reject(2) == ::c2pool::xmr::Action::Ban && !banned) { banned = true; ++bans; } }
        else if (v == kAhead) ++parked;
        else if (v == kBehind || v == kLate) ++dropped;
    }
    return v;
}
struct S14World {
    st::OwedLedger S0, S1;   // S1 = S0 + the finder's pending lane block (payout `paid`)
};
S14World s14_ledgers(const World& w, long long k1, long long k2, std::uint64_t prev_dh, std::uint64_t found_dh, long long paid) {
    st::OwedLedgerRules rules; rules.lane_height = true;
    st::OwedLedger S0(kChain, rules);
    seed(S0, w.K1.id, k1, 10); seed(S0, w.K2.id, k2, 11);
    st::LaneFound la; la.height = kHeight - prev_dh;
    S0.on_block_found("s14-prev", Amounts{}, {}, std::nullopt, nullptr, &la);
    S0.on_block_finalized("s14-prev", 12);
    S14World x{S0, S0};
    st::LaneFound lb; lb.height = kHeight - found_dh;
    x.S1.on_block_found("s14-found", Amounts{}, Amounts{{w.K1.id, paid}}, std::nullopt, nullptr, &lb);
    return x;
}
long long s14_F(const st::OwedLedger& L) {
    long long f = 0; for (const auto& [k, e] : L.effective_owed_all()) { (void)k; if (e > 0) f += e; } return f;
}
// one skew family: AHEAD (S1's share at S0), BEHIND (S0's share at S1), each n times; then S0 advances to S1
void s14_family(const char* tag, const World& w, const S14World& x, int n) {
    BuildOpts o; o.cut_payees = w.cut; o.drain = true;
    const Block b0 = build_block(x.S0, w.lane, o), b1 = build_block(x.S1, w.lane, o);
    CHECK(b0.ok && b1.ok && x.S0.owed_digest() == x.S1.owed_digest(),
          "%s drain templates build on S0 / S1 (same owed_digest; F %lld / %lld, prev_lane %llu / %llu): %s %s", tag, s14_F(x.S0), s14_F(x.S1),
          (unsigned long long)x.S0.prev_lane_height(), (unsigned long long)x.S1.prev_lane_height(), b0.why.c_str(), b1.why.c_str());
    if (!b0.ok || !b1.ok) return;
    const Share s0 = share_of(b0), s1 = share_of(b1);
    std::string why;
    std::uint64_t strikes = 0, bans = 0, parked = 0, dropped = 0;
    rl::ShareStateStore at0; at0.put(drain_entry(x.S0, w));
    rl::ShareStateStore at1; at1.put(drain_entry(x.S1, w));
    {
        const int v0 = relay_verdict(at0, s0, why); const std::string w0 = why;
        const int v1 = relay_verdict(at1, s1, why);
        CHECK(v0 == 1 && v1 == 1, "%s each share is CANONICAL on its own state (%d %s / %d %s)", tag, v0, w0.c_str(), v1, why.c_str());
    }
    const int va = s14_judge_n(at0, s1, n, strikes, bans, parked, dropped, why);
    CHECK(va == kAhead && why.find("ahead") != std::string::npos && strikes == 0 && bans == 0 && parked == (std::uint64_t)n,
          "%s the finder's share on a receiver without its lane block: AHEAD x%d, strikes %llu bans %llu parked %llu (cc97146361: -1, a strike each) -- %s",
          tag, n, (unsigned long long)strikes, (unsigned long long)bans, (unsigned long long)parked, why.c_str());
    strikes = bans = parked = dropped = 0;
    const int vb = s14_judge_n(at1, s0, n, strikes, bans, parked, dropped, why);
    CHECK(vb == kBehind && why.find("behind") != std::string::npos && strikes == 0 && bans == 0 && dropped == (std::uint64_t)n,
          "%s a share built before the receiver's lane block: BEHIND x%d, strikes %llu bans %llu dropped %llu (cc97146361: -1) -- %s",
          tag, n, (unsigned long long)strikes, (unsigned long long)bans, (unsigned long long)dropped, why.c_str());
    at0.put(drain_entry(x.S1, w));
    const int vr = relay_verdict(at0, s1, why);
    CHECK(vr == 1, "%s the receiver's state advances to S1: the parked share re-judges CANONICAL (%d %s)", tag, vr, why.c_str());
}
// a forged take on ledger L (owed.front + `add`, its V37N re-derived), judged on L's own state
int s14_forged(const World& w, const st::OwedLedger& L, std::uint64_t add, std::string& why) {
    BuildOpts f; f.cut_payees = w.cut; f.drain = true; f.retail = true;
    f.mutate = [add](x6::CoinbaseInputs& in) { if (!in.owed.empty()) in.owed.front().owed += add; in.drain_budget += add; };
    const Block fb = build_block(L, w.lane, f);
    if (!fb.ok) { why = "forged template does not build: " + fb.why; return 99; }
    rl::ShareStateStore st; st.put(drain_entry(L, w));
    return relay_verdict(st, share_of(fb), why);
}
void s14_f_capped_take() {
    std::printf("== S14. an F-capped take (F below R*dh/256; both dh past H_cap) is a skew: park / drop, never a strike ==\n");
    World w;
    const int n = 120;   // past the relay's 100-strike ban threshold
    // V2a: F ~7e9 below R*4/256 ~1.33e10 on both sides (R ~8.52e11; receiver dh 14, finder dh 4)
    const S14World a = s14_ledgers(w, 4000000000ll, 3000000000ll, 14, 4, 2000000000ll);
    s14_family("V2a", w, a, n);
    // V2b: both dh past H_cap 64 (receiver dh 100, finder dh 80); F_r 2.5e11 > G(64) ~2.13e11 > F_s 1.9e11
    const S14World b = s14_ledgers(w, 150000000000ll, 100000000000ll, 100, 80, 60000000000ll);
    s14_family("V2b", w, b, n);
    // V2c: forged takes outside every drain regime still strike
    std::string why;
    int v = s14_forged(w, a.S0, 300000000000ull, why);   // took ~3.07e11 > G(64) ~2.13e11
    CHECK(v == -1 && why.find("take") != std::string::npos,
          "V2c a forged take above G(H_cap) in the small-F world: REFUSED -1 (a strike) -- %s", why.c_str());
    v = s14_forged(w, b.S0, 1000000007ull, why);          // took = G(64) + 1.000000007 XMR
    CHECK(v == -1 && why.find("take") != std::string::npos,
          "V2c a forged take 1.000000007 XMR above G(H_cap) past H_cap: REFUSED -1 (a strike) -- %s", why.c_str());
#if defined(C2POOL_XMR_TAKE_SKEW_REGIMES)
    // the classifier on the attempt-7 numbers (R/4 = 150021985000) once F < R/4
    const std::uint64_t R = 600087940000ull, G = R * 64 / 256, F = 120000000000ull;
    using rc::TakeSkew;
    const auto c1 = rc::classify_take_skew(110000000000ull, F, F, F, R, 70, 16, 64);        // finder F-capped below ours
    const auto c2 = rc::classify_take_skew(G, F, F, F, R, 70, 16, 64);                       // finder at G(64), we F-capped
    const auto c3 = rc::classify_take_skew(G + 1, F, F, F, R, 70, 16, 64);                   // above every regime
    const auto c4 = rc::classify_take_skew(R * 4 / 256, R * 14 / 256, F, R * 14 / 256, R, 14, 16, 64);   // attempt-7 dh 4 vs 14
    const auto c5 = rc::classify_take_skew(R * 14 / 256 + 1000000007ull, R * 14 / 256, F, R * 14 / 256, R, 14, 16, 64);   // B3
    const auto c6 = rc::classify_take_skew(R * 20 / 256, R * 14 / 256, F, R * 14 / 256, R, 14, 16, 64);  // the Delta at dh 20
    CHECK(c1.kind == TakeSkew::Ahead && c1.dh == 0 && c2.kind == TakeSkew::Behind && c3.kind == TakeSkew::None &&
          c4.kind == TakeSkew::Ahead && c4.dh == 4 && c5.kind == TakeSkew::None && c6.kind == TakeSkew::Behind && c6.dh == 20 &&
          rc::drain_grid_dh(G, R, 16, 64) == 64 && rc::drain_grid_dh(G + 1, R, 16, 64) == 0,
          "classify_take_skew: F-capped under-take AHEAD; G(64) over our F BEHIND; G(64)+1 NONE; dh 4 vs 14 AHEAD@4; "
          "B3 over-take below F NONE; G(20) at ours 14 BEHIND@20 (%s / %s / %s / %s / %s / %s)",
          c1.regime, c2.regime, c3.regime, c4.regime, c5.regime, c6.regime);
#else
    CHECK(false, "no classify_take_skew on cc97146361");
#endif
}

}  // namespace

// ── S15 (HOLD-ROUND-3 F4): a prefix-hash mismatch with NO V37N base is never a strike ──
// Stagenet attempt 8: before pay-now armed (the view at the cut credits nobody
// for the first hours of a pool) templates carry no V37N base, so the finder's
// post-FOUND shares -- cut at ITS dh, judged at the receivers' older dh -- fail
// only at the last step ("the coinbase prefix hash is not the canonical one"),
// the take classifier of S13/S14 had no number to classify, and every copy
// was a strike (A 223, B 126, C 162; A banned B). Each struck receipt was
// admitted later, in the late tail: three lane lineages, and the P > horizon
// SUFFIX hold of 2220998 downstream. Same owed_digest both sides, the sender
// one PENDING lane block apart, the cut EMPTY (no pay-now, no V37N):
//   U1 the finder's share (built on L1) judged at L0 -> UNBASED (5): parked
//      like AHEAD, never a strike; 120 copies -> strikes 0 bans 0 (base: -1 x 120 -> a ban)
//   U2 the mirror (built on L0) judged at L1 -> UNBASED too (the sender's lag is
//      invisible without a take; the relay expires it after kShareUnbasedMaxRounds)
//   U3 a lane block AT the share's height booked here -> LATE (as the take form)
//   U4 a thief template with no V37N is UNBASED as well (never a strike: the
//      park bounds and the re-judge rounds are the only cost); a V37N-bearing
//      forged take still strikes (S13 B3 unchanged)
//   U5 the receiver books the finder's block (share_publish puts L1): the parked
//      share re-judges CANONICAL
#if defined(C2POOL_XMR_SHARE_VERDICT_UNBASED)
constexpr int kUnbased = rl::kShareVerdictUnbased;
#else
constexpr int kUnbased = 5;   // the base has no UNBASED code (it returns -1)
#endif
std::shared_ptr<rl::ShareStateEntry> unbased_entry(const st::OwedLedger& L, const World& w) {
    auto e = drain_entry(L, w);
    e->payees.clear();   // the view at the anchor credits nobody: pay-now not armed, no V37N in the canonical tail
    return e;
}
void s15_unbased_prefix_mismatch() {
    std::printf("== S15. a prefix-hash mismatch with no V37N base (pay-now not armed): parked, never a strike ==\n");
    World w;
    st::OwedLedgerRules rules; rules.lane_height = true;
    st::OwedLedger L0(kChain, rules);
    seed(L0, w.K1.id, 40000000000ll, 10); seed(L0, w.K2.id, 25000000000ll, 11);
    st::LaneFound la; la.height = kHeight - 14;
    L0.on_block_found("lane-a", Amounts{{w.K1.id, 1000}}, {}, std::nullopt, nullptr, &la);
    L0.on_block_finalized("lane-a", 12);
    st::OwedLedger L1 = L0;
    st::LaneFound lb; lb.height = kHeight - 4;
    L1.on_block_found("lane-b", Amounts{}, Amounts{{w.K1.id, 2000000000ll}}, std::nullopt, nullptr, &lb);   // the finder's own FOUND, pending
    st::OwedLedger L2 = L0;
    st::LaneFound lc; lc.height = kHeight;
    L2.on_block_found("lane-c", Amounts{}, {}, std::nullopt, nullptr, &lc);
    CHECK(L0.prev_lane_height() == kHeight - 14 && L1.prev_lane_height() == kHeight - 4 && L0.owed_digest() == L1.owed_digest(),
          "L0 prev_lane h-14, L1 = L0 + pending lane block at h-4 (same owed_digest), L2 prev_lane = h");
    BuildOpts o; o.cut_payees = {}; o.drain = true;   // an EMPTY cut: pay-now not armed -> no V37N base
    const Block b0 = build_block(L0, w.lane, o), b1 = build_block(L1, w.lane, o);
    CHECK(b0.ok && b1.ok, "drain templates with an empty cut build on L0 and L1: %s %s", b0.why.c_str(), b1.why.c_str());
    if (!b0.ok || !b1.ok) return;
    const Share s0 = share_of(b0), s1 = share_of(b1);
    const auto p0 = cr::extra_nonce_field(s0.tx_extra), p1 = cr::extra_nonce_field(s1.tx_extra);
    CHECK(s0.ok && s1.ok && p0 && p1 && !pn::parse_payload(*p0) && !pn::parse_payload(*p1),
          "neither share commits a V37N base (the attempt-8 first-hours shape)");
    std::string why;
    {
        rl::ShareStateStore own0, own1;
        own0.put(unbased_entry(L0, w)); own1.put(unbased_entry(L1, w));
        const int v0 = relay_verdict(own0, s0, why); const std::string w0 = why;
        const int v1 = relay_verdict(own1, s1, why);
        CHECK(v0 == 1 && v1 == 1, "each share is CANONICAL on the state it was built on (L0: %d %s; L1: %d %s)", v0, w0.c_str(), v1, why.c_str());
    }
    rl::ShareStateStore at0;
    at0.put(unbased_entry(L0, w));
    {
        std::uint64_t strikes = 0, bans = 0, parked = 0, dropped = 0;
        ::c2pool::xmr::CarrierDosBudget dos;
        bool banned = false;
        int v = 0;
        for (int i = 0; i < 120; ++i) {
            v = relay_verdict(at0, s1, why);
            if (v < 0) { ++strikes; if (dos.on_cheap_reject(2) == ::c2pool::xmr::Action::Ban && !banned) { banned = true; ++bans; } }
            else if (v == kUnbased || v == kAhead) ++parked;
            else ++dropped;
        }
        CHECK(v == kUnbased && why.find("unbased") != std::string::npos && why.find("no V37N base") != std::string::npos,
              "U1 the finder's post-FOUND share (no V37N) on a receiver at L0: UNBASED (%d; base: -1 'prefix hash is not the canonical one' -> a strike) -- %s",
              v, why.c_str());
        CHECK(strikes == 0 && bans == 0 && parked == 120,
              "U1 120 copies: strikes %llu bans %llu parked %llu (8a7ed91b3: 120 strikes -> 1 ban; attempt 8: A banned B)",
              (unsigned long long)strikes, (unsigned long long)bans, (unsigned long long)parked);
    }
    rl::ShareStateStore at1;
    at1.put(unbased_entry(L1, w));
    const int vb = relay_verdict(at1, s0, why);
    CHECK(vb == kUnbased, "U2 the mirror (a share built before the receiver's lane block, no V37N): UNBASED too (%d, parked; the relay expires it) -- %s", vb, why.c_str());
    rl::ShareStateStore at2;
    at2.put(unbased_entry(L2, w));
    const int vl = relay_verdict(at2, s0, why);
    CHECK(vl == kLate && why.find("late") != std::string::npos, "U3 a lane block AT the share's height booked here: LATE (%d, dropped, no strike) -- %s", vl, why.c_str());
    {
        BuildOpts t = o;
        t.mutate = [&](x6::CoinbaseInputs& in) { for (auto& x : in.owed) { x.pay = w.thief.ref; x.identity = w.thief.id; } };
        const Block tb = build_block(L0, w.lane, t);
        CHECK(tb.ok, "a thief template with no V37N builds: %s", tb.why.c_str());
        if (tb.ok) {
            const int v = relay_verdict(at0, share_of(tb), why);
            CHECK(v == kUnbased, "U4 a thief template with no V37N base is UNBASED (%d): parked, never a strike -- bounded by the park and its re-judge rounds (the accepted no-strike channel)", v);
        }
        BuildOpts f; f.cut_payees = w.cut; f.drain = true; f.retail = true;   // pay-now armed: a V37N base
        f.mutate = [](x6::CoinbaseInputs& in) { if (!in.owed.empty()) in.owed.front().owed += 1000000007ull; in.drain_budget += 1000000007ull; };
        const Block fb = build_block(L0, w.lane, f);
        if (fb.ok) {
            rl::ShareStateStore d0; d0.put(drain_entry(L0, w));
            const int v = relay_verdict(d0, share_of(fb), why);
            CHECK(v == -1, "U4 a V37N-bearing forged take still strikes (-1, as S13 B3): F4 widens no channel for shares that state a take -- %s", why.c_str());
        }
    }
    at0.put(unbased_entry(L1, w));   // the receiver books the finder's lane block: share_publish puts L1
    const int v5 = relay_verdict(at0, s1, why);
    CHECK(v5 == 1, "U5 after the state advances to L1 the parked share re-judges CANONICAL (%d %s)", v5, why.c_str());
}

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
    s11_drops_due();
    s12_state_by_seq();
    s13_lane_prefix_skew();   // HOLD-ROUND-2 (B)
    s14_f_capped_take();      // HOLD-ROUND-2 V2
    s15_unbased_prefix_mismatch();   // HOLD-ROUND-3 F4
    std::printf("\n%d/%d checks passed -- %s\n", g_checks - g_fail, g_checks, g_fail ? "FAIL" : "ALL PASS");
    return g_fail ? 1 : 0;
}
