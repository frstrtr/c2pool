// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ===========================================================================
// v37_xmr_o2_settlement_kat.cpp
//   The multi-node settlement KATs for the X9 option-B coinbase, pinning the
//   two operator rulings of 2026-09-10 and the count-invariance fixpoint that
//   has to survive them.
//
//   RULED (1) K_fair source == W4Propose. The XMR coinbase selects payees by
//     the ONE ratified K_fair rule: OwedLedger::propose_coinbase — oldest-owed-
//     first, (first_eligible ASC, identity ASC), take = min(EffectiveOwed,
//     remaining), CARRY a sub-h_min take, count-capped at C (whitepaper
//     erratum E-1). Every node derives the SAME set from the same ledger.
//   RULED (2) lane_commitment == the whitepaper §13 StateCommitment Merkle
//     root. The MM-root leaf in the coinbase tx_extra 0x03 commits that root
//     (via keccak(MM_LEAF_DOMAIN || chain_id_le32 || root)), not the narrower
//     owed_digest. Strict subsumption: the §13 summary leaf CONTAINS
//     owed_digest.
//
//   There was no test executable over the consumer option-B settlement path
//   before this file; the impl-side self-check (xmr_block_assembly_kat) covers
//   only the halves that need no OwedLedger.
//
//   Group KW: the payee set IS the canonical K_fair proposal at the reward the
//             block PAYS, proven against an INDEPENDENT reference walk written
//             in this file (never by calling the code under test).
//   Group KS: the §13 root is what the block commits, and a verifier holding
//             the same ledger recovers it; a one-piconero ledger difference
//             moves it; the §13 O(log n) balance proof verifies against exactly
//             the committed root.
//   Group KC: the reward/payee-set fixpoint stays fail-closed under a
//             re-projected set that may CHANGE SIZE with the reward, and the
//             cap_owed == 0 CONVENTION COLLISION between W4 (0 == unbounded)
//             and X6 (0 == no room) is translated, never forwarded (KC-5..7).
//   Group KF: R-7 (2026-09-10) — ONE ledger, and the ledger decrement is
//             EXACTLY the coinbase-paid Role::Owed set. effective_owed stays
//             non-negative (INV-1) and a FINALIZE moves it by exactly +credit
//             (INV-2, OI-W4-5); an owed row in flight cannot be re-proposed
//             (no-double-pay, whitepaper section 9). Each carries a REGRESSION
//             PIN that reproduces the shipped split-ledger defect side by side.
// ===========================================================================
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <map>
#include <string>
#include <vector>

#include <c2pool/v37/w5_coinbase.hpp>
#include <c2pool/v37/xmr/xmr_o2_settlement_fixture.hpp>
#include <c2pool/v37/xmr/xmr_o2_settlement_source.hpp>

#include "impl/xmr/settle/xmr_coinbase.hpp"
#include "impl/xmr/template/xmr_block_assembly.hpp"

namespace o2   = ::c2pool::v37n::xmr::o2;
namespace asm_ = ::c2pool::xmr::assembly;
namespace x6   = ::v37::xmr::settle;
namespace cb37 = ::c2pool::v37n::coinbase;

using Out = x6::CoinbaseOutput;

// ---------------------------------------------------------------------------
// tiny check harness (same shape as the impl-side self-check)
// ---------------------------------------------------------------------------
namespace {

int g_pass = 0, g_fail = 0;

bool CHECK(bool ok, const std::string& what) {
    std::printf("  [%s] %s\n", ok ? "PASS" : "FAIL", what.c_str());
    if (ok) ++g_pass; else ++g_fail;
    return ok;
}

std::string hex(const void* p, std::size_t n) {
    static const char* d = "0123456789abcdef";
    const auto* b = static_cast<const unsigned char*>(p);
    std::string s;
    for (std::size_t i = 0; i < n; ++i) { s.push_back(d[b[i] >> 4]); s.push_back(d[b[i] & 0xf]); }
    return s;
}
std::string hex(const ::v37::bytes32& b) { return hex(b.data(), 32); }

std::array<std::uint8_t, 32> unhex32(const char* h) {
    std::array<std::uint8_t, 32> o{};
    auto nib = [](char c) -> int {
        return (c >= '0' && c <= '9') ? c - '0'
             : (c >= 'a' && c <= 'f') ? c - 'a' + 10
             : (c >= 'A' && c <= 'F') ? c - 'A' + 10 : 0;
    };
    for (std::size_t i = 0; i < 32; ++i) o[i] = static_cast<std::uint8_t>((nib(h[2 * i]) << 4) | nib(h[2 * i + 1]));
    return o;
}

// THREE distinct, TORSION-VALID ed25519 points. This matters: the canonical
// K_fair projection downgrades a key whose ScriptRef fails xmr_ref_valid() to a
// RAW sentinel and CARRIES it, so a payee built on a torsion-failing point is
// silently never paid. (The vectors in monero-project tests/crypto/tests.txt
// that the impl-side xmr_block_assembly_kat uses do NOT pass this check — X6
// only requires well-formedness of an owed ref, the consumer projection
// requires validity. Use the canon's own KAT identities plus the regtest
// wallet keys the FOUND->FINALIZE proof pays.)
const std::array<std::uint8_t, 32> SINK_B = unhex32("a03ab8e2191c928bffa5c875c42834f793a356c12cd6d319310619055bcc7005");
const std::array<std::uint8_t, 32> SINK_A = unhex32("099b5b60c9a497e55985b3843c3fda8da741814c39f0cda7fab35c0c4c1c023d");

::v37::ScriptRef ref_a() {                                           // payee A
    return ::v37::xmr::make_xmr_std(::v37::xmr::kat::STD_KAT.p0, ::v37::xmr::kat::STD_KAT.p1);
}
::v37::ScriptRef ref_b() {                                           // payee B (distinct identity)
    return ::v37::xmr::make_xmr_std(::v37::xmr::kat::SUB_KAT.p0, ::v37::xmr::kat::STD_KAT.p1);
}
::v37::ScriptRef ref_sink() { return ::v37::xmr::make_xmr_std(SINK_B, SINK_A); }

// ---------------------------------------------------------------------------
// THE INDEPENDENT K_fair REFERENCE. Written from the whitepaper rule, NOT by
// calling OwedLedger::propose_coinbase / project_w4_owed / allocate_exact_sum.
//   order  : (first_eligible ASC, identity_key ASC)
//   take   : min(owed, remaining)
//   floor  : take < h_min  =>  CARRY (skip and CONTINUE — never break, never
//                              emit a sub-floor owed output)
//   cap    : at most C owed entries (C = total_output_cap - n_fixed - 1)
//   sink   : the exact-sum residual, iff residual > 0, LAST.
// ---------------------------------------------------------------------------
struct RefRow {
    std::uint64_t  first_eligible;
    ::v37::bytes32 key;
    std::uint64_t  owed;
};
struct RefOut {
    ::v37::bytes32 key;
    std::uint64_t  amount;
    bool           is_sink;
};

std::vector<RefOut> kfair_reference(std::vector<RefRow> rows, std::uint64_t reward,
                                    std::uint64_t fixed_sum, std::size_t n_fixed,
                                    std::uint32_t total_output_cap, std::uint64_t h_min,
                                    const ::v37::bytes32& sink_identity) {
    std::sort(rows.begin(), rows.end(), [](const RefRow& a, const RefRow& b) {
        if (a.first_eligible != b.first_eligible) return a.first_eligible < b.first_eligible;
        return a.key < b.key;
    });
    const std::size_t cap = static_cast<std::size_t>(total_output_cap) - n_fixed - 1;
    std::vector<RefOut> out;
    std::uint64_t remaining = reward - fixed_sum;
    for (const RefRow& r : rows) {
        if (out.size() >= cap) break;
        if (remaining == 0) break;
        const std::uint64_t take = std::min<std::uint64_t>(r.owed, remaining);
        if (take < h_min) continue;                       // CARRY, keep walking
        out.push_back(RefOut{r.key, take, false});
        remaining -= take;
    }
    // (this KAT never configures fixed outputs; they would slot in here)
    if (remaining > 0) out.push_back(RefOut{sink_identity, remaining, true});
    return out;
}

std::string describe(const std::vector<Out>& outs) {
    std::string s;
    for (const auto& o : outs) {
        s += (o.role == Out::Role::Owed ? "owed:" : o.role == Out::Role::Fixed ? "fixed:" : "sink:");
        s += hex(o.identity).substr(0, 8);
        s += "=" + std::to_string(o.amount) + " ";
    }
    return s;
}

bool same_as_reference(const std::vector<Out>& got, const std::vector<RefOut>& want) {
    if (got.size() != want.size()) return false;
    for (std::size_t i = 0; i < got.size(); ++i) {
        if (got[i].amount != want[i].amount) return false;
        if (!(got[i].identity == want[i].key)) return false;
        const bool is_sink = got[i].role == Out::Role::Sink;
        if (is_sink != want[i].is_sink) return false;
    }
    return true;
}

// ---------------------------------------------------------------------------
// One assembled option-B template, wired EXACTLY as the daemon provider wires
// it (build_settlement_source -> assembly_settle_inputs -> make_reproject_owed
// -> XmrBlockAssembler::build).
// ---------------------------------------------------------------------------
struct Lane {
    o2::XmrSettlementConfig cfg;
    o2::XmrOwedFixture      fx;
    std::vector<RefRow>     seeded;      // the KAT's OWN model of the ledger
    std::uint64_t           next_age = 1;

    // OWNING form: the lane holds its own ledger.
    explicit Lane(::v37::ChainId chain, std::uint64_t h_min = 0) : fx(chain) {
        init(chain, h_min);
    }
    // NON-OWNING form (R-7 one-ledger wiring): the lane's coinbase is built
    // against an EXTERNAL OwedLedger — in the daemon, XmrNode::ledger(), the
    // one the finalize driver writes.
    explicit Lane(o2::OwedLedger& external, std::uint64_t h_min = 0) : fx(external) {
        init(external.chain(), h_min);
    }

    void init(::v37::ChainId chain, std::uint64_t h_min) {
        cfg.chain_id   = chain;
        cfg.h_min      = h_min;
        cfg.output_cap = 0;              // 0 => the ceiling; the assembler resolves weight-aware
        cfg.residual_sink          = ref_sink();
        cfg.residual_sink_identity = ::v37::xmr::xmr_identity_key(cfg.residual_sink);
    }

    ::v37::bytes32 seed(const ::v37::ScriptRef& pay, std::uint64_t amount) {
        const ::v37::bytes32 k = fx.seed_owed(pay, amount);
        seeded.push_back(RefRow{next_age++, k, amount});   // fixture arms at bin_height 1,2,...
        return k;
    }
};

std::unique_ptr<asm_::AssembledTemplate>
assemble(Lane& lane, const ::c2pool::xmr::XmrMinerData& md,
         const std::vector<::c2pool::xmr::XmrTxMempoolData>& mempool,
         std::uint32_t wire_cap, std::string& why, bool wire_reprojection = true) {
    o2::XmrSettlementConfig scfg = lane.cfg;
    scfg.monero_major_version = md.major_version;

    std::uint64_t fees = 0, weight_all = 0;
    for (const auto& t : mempool) { fees += t.fee; weight_all += t.weight; }
    const std::uint64_t subsidy = asm_::xmr_base_reward(md.already_generated_coins);

    o2::XmrParentContext parent = o2::XmrParentContext::from_miner(md, subsidy, fees);

    std::unique_ptr<o2::XmrOwedSettlementSource> src = o2::build_settlement_source(
        scfg, parent, lane.fx.ledger(), lane.fx.pay_of(), subsidy + fees, &why);
    if (!src) return nullptr;

    asm_::AssemblyInputs a;
    a.miner    = md;
    a.mempool  = mempool;
    a.settle   = o2::assembly_settle_inputs(*src, /*weight_aware_cap=*/true);
    a.wire_cap = wire_cap;
    if (wire_reprojection) a.reproject_owed = o2::make_reproject_owed(scfg, lane.fx);
    return asm_::XmrBlockAssembler::build(a, &why);
}

::c2pool::xmr::XmrMinerData miner(std::uint64_t height, std::uint64_t median_weight,
                                  std::uint64_t agc, std::uint8_t major = 16) {
    ::c2pool::xmr::XmrMinerData d;
    d.major_version = major;
    d.height        = height;
    for (std::size_t i = 0; i < 32; ++i) d.prev_id.h[i] = static_cast<std::uint8_t>(0x31 * 7 + i);
    d.already_generated_coins = agc;
    d.median_weight   = median_weight;
    d.median_timestamp = 1700000000;
    d.difficulty.lo = 1000;
    for (std::size_t i = 0; i < 32; ++i) d.seed_hash.h[i] = static_cast<std::uint8_t>(0x53 * 7 + i);
    d.lane_target.lo = 0xFFFFFFFFFFFFFFFFull;
    return d;
}

std::vector<::c2pool::xmr::XmrTxMempoolData> txs(std::size_t n, std::uint64_t weight, std::uint64_t fee) {
    std::vector<::c2pool::xmr::XmrTxMempoolData> v;
    for (std::size_t i = 0; i < n; ++i) {
        ::c2pool::xmr::XmrTxMempoolData t;
        for (std::size_t j = 0; j < 32; ++j) t.id.h[j] = static_cast<std::uint8_t>((0x80 + i) * 7 + j);
        t.weight = weight; t.fee = fee;
        v.push_back(t);
    }
    return v;
}

// The TOTAL output cap the assembler actually resolved for this template — the
// value the canonical proposal must have been cut at (RULED; it is the
// weight-aware cap, not the config ceiling).
std::uint32_t resolved_cap(const asm_::AssembledTemplate& t) {
    return t.coinbase_inputs().output_cap;
}

// =========================================================================
// GROUP KW — the payee set IS the canonical K_fair proposal
// =========================================================================

// KW-1 / KC-1: a PENALTY-ZONE template where the canonical set at the FINAL
// reward is strictly different from the set at the sizing reward, because the
// tail payee's take falls BELOW h_min and W4 therefore CARRIES it whole. The
// pre-ruling assembler froze the sizing-pass rows and let X6 pay that payee a
// sub-floor dust output; the ruled assembler re-projects and pays the sink.
void kw1_kc1() {
    std::printf("KW-1 / KC-1: payee set == canonical K_fair reference at the FINAL reward\n");

    const std::uint64_t H_MIN = 5000000000ull;                 // 5e9 piconero owed floor
    Lane lane(7, H_MIN);
    const std::uint64_t subsidy = asm_::xmr_base_reward(18000000000000000000ull);
    const ::v37::bytes32 kA = lane.seed(ref_a(), subsidy);      // oldest (first_eligible 1)
    const ::v37::bytes32 kB = lane.seed(ref_b(), 100000000000ull);
    (void)kB;

    // median 2000 with 10 txs of 500 B / 1e9 fee: the greedy keeps 3, so the
    // FINAL reward is subsidy + 3e9 while the SIZING reward is subsidy + 10e9.
    auto md = miner(3000000, 2000, 18000000000000000000ull);
    auto mp = txs(10, 500, 1000000000ull);

    std::string why;
    auto t = assemble(lane, md, mp, 2700, why);
    if (!CHECK(t != nullptr, "KW-1 assemble: " + why)) return;

    const std::uint64_t final_reward = t->reward();
    CHECK(final_reward == subsidy + 3000000000ull,
          "KW-1 final reward == subsidy + 3 fees (" + std::to_string(final_reward) + ")");
    CHECK(final_reward < subsidy + 10000000000ull, "KW-1 penalty zone: final reward < sizing reward");

    const std::vector<RefOut> want = kfair_reference(lane.seeded, final_reward, 0, 0,
                                                     resolved_cap(*t), H_MIN,
                                                     lane.cfg.residual_sink_identity);
    CHECK(same_as_reference(t->outputs(), want),
          "KW-1 outputs == INDEPENDENT canonical K_fair walk at the final reward and resolved cap "
          "[got " + describe(t->outputs()) + "]");
    // The discriminating detail: B's take at the final reward is 3e9 < h_min, so
    // the canonical rule CARRIES B whole and the residual goes to the SINK.
    CHECK(t->outputs().size() == 2 &&
          t->outputs()[0].role == Out::Role::Owed && t->outputs()[0].identity == kA &&
          t->outputs()[0].amount == subsidy &&
          t->outputs()[1].role == Out::Role::Sink && t->outputs()[1].amount == 3000000000ull,
          "KW-1 the sub-floor tail payee is CARRIED (sink absorbs 3e9), not paid dust");
    CHECK(t->passes() == 2, "KC-1 re-projection changed the set => fixpoint took 2 passes, passes=" +
                            std::to_string(t->passes()));
    std::uint64_t sum = 0;
    for (const auto& o : t->outputs()) sum += o.amount;
    CHECK(sum == final_reward, "KC-1 exact-sum: sum(outputs) == template reward");

    // Regression pin: with the re-projection hook UNWIRED (the pre-ruling
    // assembler) the very same lane emits a DIFFERENT set — the dust output the
    // canonical rule forbids. This is what the ruling closes.
    std::string why2;
    auto old = assemble(lane, md, mp, 2700, why2, /*wire_reprojection=*/false);
    if (CHECK(old != nullptr, "KW-1 control: unwired assemble: " + why2)) {
        CHECK(!same_as_reference(old->outputs(), want),
              "KW-1 control: WITHOUT re-projection the set is NOT the canonical proposal "
              "[got " + describe(old->outputs()) + "]");
    }
}

// KW-2: the non-ruled K_fair source is refused at BOTH gates, and the refusal
// names the ruling.
void kw2() {
    std::printf("KW-2: KFairSource::X6Allocate is refused, config-level and build-level\n");

    Lane lane(7);
    o2::XmrSettlementConfig bad = lane.cfg;
    bad.kfair = o2::KFairSource::X6Allocate;
    std::string w;
    CHECK(!bad.validate_structural(&w) && w.find("RULED") != std::string::npos,
          "KW-2 config gate refuses X6Allocate: " + w);

    o2::XmrParentContext parent;
    parent.height = 100; parent.base_reward = 600000000000ull; parent.fees = 0;
    auto ctx = o2::make_xmr_coinbase_context(lane.cfg, parent, lane.fx.ledger(), &w);
    if (!CHECK(ctx.has_value(), "KW-2 the RULED config still builds a context: " + w)) return;

    auto src = o2::XmrOwedSettlementSource::build(lane.fx.ledger(), lane.fx.pay_of(), *ctx,
                                                  parent.budget(), &w, o2::KFairSource::X6Allocate);
    CHECK(src == nullptr && w.find("RULED") != std::string::npos,
          "KW-2 build gate refuses X6Allocate: " + w);

    auto ok = o2::XmrOwedSettlementSource::build(lane.fx.ledger(), lane.fx.pay_of(), *ctx,
                                                 parent.budget(), &w, o2::KFairSource::W4Propose);
    CHECK(ok != nullptr && ok->kfair_source() == o2::KFairSource::W4Propose,
          "KW-2 W4Propose (the ruled source) builds: " + w);
}

// KW-3: canonical ORDER survives the whole template — proposal order first,
// then fixed, then the sink LAST, with the configured sink identity.
// KW-4: payout_map_at(final reward) is honest.
void kw3_kw4() {
    std::printf("KW-3 / KW-4: canonical order through the template + payout-map honesty\n");

    Lane lane(7);
    const ::v37::bytes32 kA = lane.seed(ref_a(), 1000000000ull);      // older
    const ::v37::bytes32 kB = lane.seed(ref_b(), 2000000000ull);      // younger

    auto md = miner(3000000, 300000, 18000000000000000000ull);
    std::string why;
    auto t = assemble(lane, md, {}, 2700, why);
    if (!CHECK(t != nullptr, "KW-3 assemble: " + why)) return;

    const auto& outs = t->outputs();
    CHECK(outs.size() == 3, "KW-3 2 owed + sink");
    CHECK(outs.size() == 3 && outs[0].identity == kA && outs[1].identity == kB,
          "KW-3 oldest-owed-first order (A before B) preserved through the block template");
    CHECK(outs.size() == 3 && outs[0].role == Out::Role::Owed && outs[1].role == Out::Role::Owed &&
          outs[2].role == Out::Role::Sink,
          "KW-3 roles: owed ++ fixed ++ sink, sink LAST");
    CHECK(!outs.empty() && outs.back().identity == lane.cfg.residual_sink_identity,
          "KW-3 the last output pays the CONFIGURED residual_sink_identity");

    const std::vector<RefOut> want = kfair_reference(lane.seeded, t->reward(), 0, 0,
                                                     resolved_cap(*t), lane.cfg.h_min,
                                                     lane.cfg.residual_sink_identity);
    CHECK(same_as_reference(outs, want), "KW-3 outputs == canonical reference [" + describe(outs) + "]");

    // KW-4: the FOUND-record payout map sums to the block reward and its owed
    // part is exactly the proposal's takes.
    std::map<::v37::bytes32, long long> pm;
    for (const auto& o : outs) pm[o.identity] += static_cast<long long>(o.amount);
    long long total = 0;
    for (const auto& [k, v] : pm) { (void)k; total += v; }
    CHECK(static_cast<std::uint64_t>(total) == t->reward(),
          "KW-4 payout map sums to the block reward");
    CHECK(pm[kA] == 1000000000ll && pm[kB] == 2000000000ll,
          "KW-4 the owed part of the payout map == the proposal takes");
}

// =========================================================================
// GROUP KS — the §13 state root is what the block commits
// =========================================================================

void ks1_ks2_ks3_ks4() {
    std::printf("KS: the whitepaper section-13 StateCommitment root is committed and recoverable\n");

    Lane lane(7);
    const ::v37::bytes32 kA = lane.seed(ref_a(), 1000000000ull);
    lane.seed(ref_b(), 2000000000ull);

    const ::v37::bytes32 root = cb37::StateCommitment(lane.fx.ledger(), lane.fx.ledger().chain()).root();
    CHECK(!(root == ::v37::bytes32{}), "KS-1 the section-13 root is non-zero (" + hex(root).substr(0, 16) + "...)");
    CHECK(o2::resolve_lane_commitment(lane.cfg, lane.fx.ledger()) == root,
          "KS-1 the RULED default lane_commitment IS StateCommitment::root()");

    auto md = miner(3000000, 300000, 18000000000000000000ull);
    std::string why;
    auto t = assemble(lane, md, {}, 2700, why);
    if (!CHECK(t != nullptr, "KS-1 assemble: " + why)) return;

    CHECK(t->coinbase_inputs().lane_commitment == root,
          "KS-1 the coinbase's lane_commitment is the section-13 root");

    // KS-1: the 32 bytes patched inside the tx_extra 0x03 tag are
    // mm_commitment_root(chain_id, state_root).
    asm_::BlockBytes b;
    std::string me;
    if (!CHECK(t->materialize(0, b, &me), "KS-1 materialize: " + me)) return;
    const ::xmr::coin::Hash256 want_leaf = x6::mm_commitment_root(lane.cfg.chain_id, root);
    CHECK(b.merkle_root == want_leaf,
          "KS-1 tx_extra 0x03 root == mm_commitment_root(chain_id, section-13 root)");
    CHECK(std::memcmp(b.full_blob.data() + b.merkle_root_offset, want_leaf.data(), 32) == 0,
          "KS-1 the patched bytes at merkle_root_offset are that value");

    // KS-2: an INDEPENDENT verifier that holds the same ledger parses the served
    // miner_tx prefix and recomputes root -> leaf -> compare.
    x6::ReceivedCoinbase rc;
    std::uint64_t h = 0; std::size_t used = 0;
    const bool parsed = asm_::parse_coinbase_prefix(b.full_blob.data() + b.miner_tx_offset,
                                                    b.miner_tx_size, rc, &h, &used);
    if (CHECK(parsed && h == t->height(), "KS-2 the served miner_tx prefix parses")) {
        // the 0x03 tag is the LAST prefix field: [03][varint(33)][00][root32]
        const bool tail_ok = rc.tx_extra.size() >= 32 &&
            std::memcmp(rc.tx_extra.data() + rc.tx_extra.size() - 32, want_leaf.data(), 32) == 0;
        CHECK(tail_ok, "KS-2 a verifier recomputes the leaf from its own ledger copy and it MATCHES "
                       "the served tx_extra");
    }
    // KS-2 negative control: a ledger differing by ONE piconero on one balance
    // yields a DIFFERENT section-13 root, hence a different MM leaf.
    {
        Lane other(7);
        other.seed(ref_a(), 1000000000ull);
        other.seed(ref_b(), 2000000001ull);              // one piconero apart
        const ::v37::bytes32 r2 = cb37::StateCommitment(other.fx.ledger(), other.fx.ledger().chain()).root();
        CHECK(!(r2 == root), "KS-2 negative: a 1-piconero ledger difference moves the section-13 root");
        CHECK(!(x6::mm_commitment_root(lane.cfg.chain_id, r2) == want_leaf),
              "KS-2 negative: and therefore moves the MM leaf the block commits");
    }

    // KS-3: the whitepaper section-13 O(log n) balance proof verifies against
    // EXACTLY the root the block commits.
    {
        cb37::StateCommitment sc(lane.fx.ledger(), lane.fx.ledger().chain());
        ::v37::bytes32 leaf{};
        ::v37::Lane::MerkleProof proof;
        const bool have = sc.prove(kA, leaf, proof);
        CHECK(have, "KS-3 a balance proof exists for a finalized payee key");
        CHECK(have && ::v37::Lane::verify_proof(root, leaf, proof),
              "KS-3 Lane::verify_proof(leaf, proof, committed root) accepts");
        if (have) {
            ::v37::bytes32 tampered = leaf; tampered[0] ^= 0x01;
            CHECK(!::v37::Lane::verify_proof(root, tampered, proof),
                  "KS-3 negative: a tampered leaf is rejected against the committed root");
        }
    }

    // KS-4: an EMPTY ledger still has a summary-leaf-only root (non-zero) and a
    // sink-only coinbase still builds against it.
    {
        Lane empty(7);
        const ::v37::bytes32 er = cb37::StateCommitment(empty.fx.ledger(), empty.fx.ledger().chain()).root();
        CHECK(!(er == ::v37::bytes32{}), "KS-4 empty ledger: summary-leaf-only root is non-zero");
        CHECK(cb37::StateCommitment(empty.fx.ledger(), empty.fx.ledger().chain()).leaf_count() == 1,
              "KS-4 empty ledger: exactly one leaf (the V37S summary)");
        std::string w2;
        auto et = assemble(empty, miner(1, 300000, 0), {}, 2700, w2);
        if (CHECK(et != nullptr, "KS-4 sink-only coinbase builds on an empty ledger: " + w2)) {
            CHECK(et->outputs().size() == 1 && et->outputs()[0].role == Out::Role::Sink,
                  "KS-4 the whole reward flows to the residual sink");
            CHECK(et->coinbase_inputs().lane_commitment == er,
                  "KS-4 and it commits the empty ledger's section-13 root");
        }
    }
}

// KS-5: the same lane under owed-digest vs state-root gives a different tx
// secret key r, a different R, different one-time keys and different block
// bytes — the reason every pinned option-B byte golden was regenerated.
void ks5() {
    std::printf("KS-5: switching the lane commitment moves r / R / P_i and the block bytes\n");

    Lane lane(7);
    lane.seed(ref_a(), 1000000000ull);

    o2::XmrSettlementConfig old_cfg = lane.cfg;
    old_cfg.lc_source = o2::LaneCommitmentSource::OwedDigest;
    old_cfg.allow_nonruled_local_only = true;                 // single-pool escape hatch

    o2::XmrParentContext parent;
    parent.height = 100; parent.base_reward = 600000000000ull; parent.fees = 0;

    std::string w;
    auto ruled = o2::build_settlement_source(lane.cfg, parent, lane.fx.ledger(), lane.fx.pay_of(),
                                             parent.budget(), &w);
    if (!CHECK(ruled != nullptr, "KS-5 ruled (state-root) source builds: " + w)) return;
    auto legacy = o2::build_settlement_source(old_cfg, parent, lane.fx.ledger(), lane.fx.pay_of(),
                                              parent.budget(), &w);
    if (!CHECK(legacy != nullptr, "KS-5 legacy (owed-digest) source builds: " + w)) return;

    CHECK(std::memcmp(ruled->tx_secret_key().h, legacy->tx_secret_key().h, 32) != 0,
          "KS-5 tx secret key r differs");
    CHECK(std::memcmp(ruled->tx_public_key().h, legacy->tx_public_key().h, 32) != 0,
          "KS-5 tx public key R differs");
    CHECK(std::memcmp(ruled->commitment_leaf(0).h, legacy->commitment_leaf(0).h, 32) != 0,
          "KS-5 the MM commitment leaf differs");
    CHECK(ruled->built().prefix != legacy->built().prefix,
          "KS-5 the whole miner_tx prefix differs (golden regeneration is EXPECTED, not a regression)");
    CHECK(ruled->payees().size() == legacy->payees().size(),
          "KS-5 the PAYEE SET is unchanged by the commitment switch (only the keys move)");
}

// =========================================================================
// GROUP KC — the fixpoint stays fail-closed
// =========================================================================

// KC-2: the proposal is cut at the RESOLVED (weight-aware) cap, so the W4 tail
// is CARRIED rather than truncated by X6 — the two caps agree by construction.
void kc2() {
    std::printf("KC-2: the canonical proposal is cut at the RESOLVED weight-aware cap\n");

    Lane lane(7);
    for (int i = 0; i < 6; ++i)
        lane.seed(i % 2 ? ref_b() : ref_a(), 1000000000ull * static_cast<std::uint64_t>(i + 1));
    // NOTE: ref_a()/ref_b() alternate, so only 2 distinct identity keys exist —
    // seeding the same ref twice ACCUMULATES on one ledger key. That is exactly
    // what we want here: 2 real payees, and a wire cap that leaves room for
    // fewer owed slots than the config ceiling would.
    auto md = miner(3000000, 300000, 18000000000000000000ull);

    std::string why;
    auto t = assemble(lane, md, {}, /*wire_cap=*/2, why);      // total cap 2 => 1 owed slot + sink
    if (!CHECK(t != nullptr, "KC-2 assemble at wire_cap 2: " + why)) return;

    CHECK(resolved_cap(*t) == 2, "KC-2 the assembler resolved the weight-aware cap to 2 (not the 2700 ceiling)");
    CHECK(t->coinbase_inputs().owed.size() <= 1,
          "KC-2 the proposal handed to X6 holds at most cap-1 owed rows (the tail was CARRIED, "
          "not truncated after the fact); rows=" + std::to_string(t->coinbase_inputs().owed.size()));
    CHECK(t->outputs().size() == 2 && t->outputs()[0].role == Out::Role::Owed &&
          t->outputs()[1].role == Out::Role::Sink,
          "KC-2 one owed output + sink [" + describe(t->outputs()) + "]");

    // Build the reference over the KAT's own accumulated model of the ledger.
    std::map<::v37::bytes32, RefRow> acc;
    for (const RefRow& r : lane.seeded) {
        auto it = acc.find(r.key);
        if (it == acc.end()) acc.emplace(r.key, r);           // oldest arming wins (first_eligible)
        else it->second.owed += r.owed;
    }
    std::vector<RefRow> rows;
    for (const auto& [k, r] : acc) { (void)k; rows.push_back(r); }
    const std::vector<RefOut> want = kfair_reference(rows, t->reward(), 0, 0, resolved_cap(*t),
                                                     lane.cfg.h_min, lane.cfg.residual_sink_identity);
    CHECK(same_as_reference(t->outputs(), want),
          "KC-2 outputs == canonical reference AT THE RESOLVED CAP [" + describe(t->outputs()) + "]");
}

// KC-3: fail-closed. A re-projection callback that refuses must abort the whole
// assembly with a NAMED reason — never a silently different payee set.
void kc3() {
    std::printf("KC-3: a refusing re-projection callback fails the assembly closed\n");

    Lane lane(7);
    lane.seed(ref_a(), 1000000000ull);
    auto md = miner(3000000, 300000, 18000000000000000000ull);

    o2::XmrSettlementConfig scfg = lane.cfg;
    scfg.monero_major_version = md.major_version;
    const std::uint64_t subsidy = asm_::xmr_base_reward(md.already_generated_coins);
    o2::XmrParentContext parent = o2::XmrParentContext::from_miner(md, subsidy, 0);

    std::string why;
    auto src = o2::build_settlement_source(scfg, parent, lane.fx.ledger(), lane.fx.pay_of(),
                                           subsidy, &why);
    if (!CHECK(src != nullptr, "KC-3 source builds: " + why)) return;

    asm_::AssemblyInputs a;
    a.miner   = md;
    a.settle  = o2::assembly_settle_inputs(*src, true);
    a.reproject_owed = [](std::uint64_t, std::uint32_t, std::vector<x6::OwedEntry>&, std::string* w) {
        if (w) *w = "synthetic ledger read failure";
        return false;
    };
    std::string w2;
    auto t = asm_::XmrBlockAssembler::build(a, &w2);
    CHECK(t == nullptr, "KC-3 the assembler refuses to serve a template");
    CHECK(w2.find("reproject_owed refused") != std::string::npos &&
          w2.find("synthetic ledger read failure") != std::string::npos,
          "KC-3 and names the cause: " + w2);

    // The other two fail-closed exits are unchanged and still reachable: the
    // CARROT fence and a missing residual sink.
    asm_::AssemblyInputs f;
    f.miner  = miner(1, 300000, 0, 17);
    f.settle = o2::assembly_settle_inputs(*src, true);
    f.reproject_owed = o2::make_reproject_owed(scfg, lane.fx);
    std::string w3;
    const bool fenced = asm_::XmrBlockAssembler::build(f, &w3) == nullptr;
    CHECK(fenced && w3.find("CARROT") != std::string::npos,
          "KC-3 CARROT fence still refuses under the ruled wiring: " + w3);
}

// KC-4: with reproject_owed EMPTY the impl-only assembler is byte-identical to
// master — the pre-ruling behaviour is preserved for every caller that does not
// opt in (this is what keeps xmr_block_assembly_kat K0..K6 green unchanged).
void kc4() {
    std::printf("KC-4: back-compat — an empty reproject_owed keeps the old assembler behaviour\n");

    Lane lane(7);
    lane.seed(ref_a(), 1000000000ull);
    lane.seed(ref_b(), 2000000000ull);
    auto md = miner(3000000, 300000, 18000000000000000000ull);

    std::string w1, w2;
    auto wired   = assemble(lane, md, {}, 2700, w1, /*wire_reprojection=*/true);
    auto unwired = assemble(lane, md, {}, 2700, w2, /*wire_reprojection=*/false);
    if (!CHECK(wired != nullptr && unwired != nullptr, "KC-4 both assemble: " + w1 + " / " + w2)) return;

    // In the NON-penalty case the sizing reward IS the final reward, so the
    // re-projection is a no-op and the two must agree BYTE for byte.
    asm_::BlockBytes bw, bu;
    std::string me;
    if (!CHECK(wired->materialize(0, bw, &me) && unwired->materialize(0, bu, &me),
               "KC-4 materialize: " + me)) return;
    CHECK(bw.full_blob == bu.full_blob,
          "KC-4 identical block bytes when the reward never moves (re-projection is a no-op)");
    CHECK(wired->passes() == unwired->passes() && wired->passes() == 1, "KC-4 both converge in 1 pass");
}

// =========================================================================
// GROUP KF — R-7: effective_owed non-negative + finality-invariant, and the
// ledger decrement is EXACTLY the coinbase-paid owed set.
//
// The defect these pin: the daemon used to hold TWO disjoint OwedLedger objects
// — a settlement one the coinbase was built from and a node one FINALIZE booked
// into — and booked a FICTIONAL payout ({ operator --payee-* : FULL block
// reward }) into the second. Consequences, both empirically confirmed on the
// PR's own regtest run: effective_owed went NEGATIVE by one reward per pending
// FOUND, and the settlement ledger, never decremented, re-proposed the SAME
// owed row at its full EffectiveOwed on EVERY block (no-double-pay violation of
// whitepaper section 9 / OI-W4-5).
// =========================================================================

// { identity : amount } over the EMITTED Role::Owed outputs of an assembled
// template — the ONLY legal FOUND payout map. Written here independently of the
// provider's owed_payout_of() so the KAT does not test the code by calling it.
o2::Amounts emitted_owed(const asm_::AssembledTemplate& t) {
    o2::Amounts m;
    for (const auto& o : t.outputs())
        if (o.role == Out::Role::Owed) m[o.identity] += static_cast<long long>(o.amount);
    return m;
}
o2::Amounts emitted_by_role(const asm_::AssembledTemplate& t, Out::Role want) {
    o2::Amounts m;
    for (const auto& o : t.outputs())
        if (o.role == want) m[o.identity] += static_cast<long long>(o.amount);
    return m;
}
bool all_nonnegative(const o2::OwedLedger& led) {
    for (const auto& [k, v] : led.effective_owed_all()) { (void)k; if (v < 0) return false; }
    return true;
}
long long min_effective_owed(const o2::OwedLedger& led) {
    long long m = 0;
    for (const auto& [k, v] : led.effective_owed_all()) { (void)k; if (v < m) m = v; }
    return m;
}

// KF-1: ONE-LEDGER INVARIANTS with THREE CONCURRENT pending FOUNDs — the exact
// shape that produced the reported divergence ("found registered=30 settled=25
// orphaned=2 refused=0 pending=3").
void kf1() {
    std::printf("KF-1: R-7 one-ledger invariants over 3 concurrent pending FOUNDs\n");

    o2::OwedLedger led(7);                       // THE ledger (the node's, in the daemon)
    Lane lane(led);
    auto md = miner(3000000, 300000, 18000000000000000000ull);

    const std::uint64_t ARM[3] = {1000000000ull, 700000000ull, 250000000ull};
    std::vector<o2::Amounts> booked;
    bool inv1 = true;

    for (int i = 0; i < 3; ++i) {
        lane.seed(ref_a(), ARM[i]);              // a fresh E_b credit arms more owed
        std::string why;
        auto t = assemble(lane, md, {}, 2700, why);
        if (!CHECK(t != nullptr, "KF-1 assemble block " + std::to_string(i) + ": " + why)) return;

        const o2::Amounts owed = emitted_owed(*t);
        if (!CHECK(owed.size() == 1 && owed.begin()->second == static_cast<long long>(ARM[i]),
                   "KF-1 block " + std::to_string(i) + " pays exactly the newly armed owed"))
            return;
        // This is what FinalizeConnect books: credit == {} (no S-1 fold yet),
        // payout == the EMITTED Role::Owed set, into the SAME ledger.
        led.on_block_found("kf1-blk-" + std::to_string(i), /*credit=*/{}, owed);
        booked.push_back(owed);
        inv1 = inv1 && all_nonnegative(led);
    }
    CHECK(inv1, "KF-1 INV-1: effective_owed >= 0 after EVERY on_block_found (3 pending), min=" +
                std::to_string(min_effective_owed(led)));
    CHECK(led.effective_owed(::v37::xmr::xmr_identity_key(ref_a())) == 0,
          "KF-1 with all three in flight the payee's effective_owed is exactly 0 (fully committed, "
          "never negative)");

    // INV-2 (OI-W4-5): a FINALIZE moves effective_owed by EXACTLY +credit[k].
    // credit == {} here, so it is INVARIANT. Do NOT assert monotonicity across
    // the FOUND transition — effective_owed legitimately drops there; that IS
    // the pending-payout deduction the coinbase drew on.
    bool inv2 = true;
    for (int i = 0; i < 3; ++i) {
        const o2::Amounts before = led.effective_owed_all();
        led.on_block_finalized("kf1-blk-" + std::to_string(i), 100 + static_cast<std::uint64_t>(i));
        const o2::Amounts after = led.effective_owed_all();
        for (const auto& [k, v] : after) {
            const auto it = before.find(k);
            const long long b = it == before.end() ? 0 : it->second;
            if (v != b) inv2 = false;            // credit == {} => exactly unchanged
        }
        inv1 = inv1 && all_nonnegative(led);
    }
    CHECK(inv2, "KF-1 INV-2: each FINALIZE changed effective_owed by EXACTLY +credit[k] "
                "(credit == {} => unchanged, never decreased)");
    CHECK(inv1 && min_effective_owed(led) == 0,
          "KF-1 INV-1 holds through FINALIZE too: no negative row anywhere in the run");

    // ── REGRESSION PIN: the SHIPPED split-ledger wiring goes NEGATIVE ────────
    // Same three blocks, but the payout is booked into a SECOND ledger the
    // coinbase never read (and, as shipped, the payout was the full reward).
    {
        o2::OwedLedger settle_led(7);            // the coinbase's ledger
        o2::OwedLedger node_led(7);              // the finalize driver's ledger
        Lane split(settle_led);
        split.seed(ref_a(), 1000000000ull);
        std::string why;
        auto t = assemble(split, md, {}, 2700, why);
        if (CHECK(t != nullptr, "KF-1 split-arm assemble: " + why)) {
            const ::v37::bytes32 payee = ::v37::xmr::xmr_identity_key(ref_a());
            for (int i = 0; i < 3; ++i) {
                o2::Amounts fictional;           // the pre-R-7 record: payee -> FULL reward
                fictional[payee] = static_cast<long long>(t->reward());
                node_led.on_block_found("split-" + std::to_string(i), fictional, fictional);
            }
            CHECK(node_led.effective_owed(payee) ==
                      -3ll * static_cast<long long>(t->reward()),
                  "KF-1 REGRESSION PIN: the shipped split-ledger + full-reward record drives "
                  "effective_owed to -3*reward with 3 pending (" +
                  std::to_string(node_led.effective_owed(payee)) + ") — the class that must "
                  "never come back");
            CHECK(min_effective_owed(node_led) < 0,
                  "KF-1 REGRESSION PIN: and the ledger-wide minimum is negative");
        }
    }
}

// KF-2: the COINBASE-PAID SET is EXACTLY what the ledger decrements — no fixed
// key, no sink key, no extra key; and the sink/fixed identities are never
// touched by the ledger at all.
void kf2() {
    std::printf("KF-2: ledger decrement == the emitted Role::Owed set (fixed + sink EXCLUDED)\n");

    o2::OwedLedger led(7);
    Lane lane(led);
    // One mandated fixed output, so the template carries all three roles.
    ::v37::ScriptRef fixed_pay = ref_b();
    const ::v37::bytes32 fixed_id = ::v37::xmr::xmr_identity_key(fixed_pay);
    lane.cfg.fixed.push_back(x6::FixedOutput{fixed_pay, 250000000ull, fixed_id});

    const ::v37::bytes32 kA = lane.seed(ref_a(), 1000000000ull);
    auto md = miner(3000000, 300000, 18000000000000000000ull);

    std::string why;
    auto t = assemble(lane, md, {}, 2700, why);
    if (!CHECK(t != nullptr, "KF-2 assemble: " + why)) return;

    const o2::Amounts owed  = emitted_owed(*t);
    const o2::Amounts fixed = emitted_by_role(*t, Out::Role::Fixed);
    const o2::Amounts sink  = emitted_by_role(*t, Out::Role::Sink);
    CHECK(owed.size() == 1 && owed.count(kA) == 1 && fixed.size() == 1 && sink.size() == 1,
          "KF-2 the template carries owed + fixed + sink [" + describe(t->outputs()) + "]");

    // (a) exactly the Role::Owed keys — no fixed, no sink, nothing extra.
    CHECK(owed.count(fixed_id) == 0 && owed.count(lane.cfg.residual_sink_identity) == 0,
          "KF-2(a) the payout map holds NO fixed and NO sink identity");
    // (b) amounts are the emitted ones, and strictly less than the block reward.
    long long owed_sum = 0;
    for (const auto& [k, v] : owed) { (void)k; owed_sum += v; }
    CHECK(owed.at(kA) == 1000000000ll && static_cast<std::uint64_t>(owed_sum) < t->reward(),
          "KF-2(b) amounts == the emitted owed amounts and sum < reward (a sink exists)");

    // (c) the ledger decrement is exactly that, and the fixed/sink identities are
    //     never created as ledger keys.
    const long long eo_before = led.effective_owed(kA);
    led.on_block_found("kf2", /*credit=*/{}, owed);
    CHECK(led.effective_owed(kA) == eo_before - owed.at(kA) && led.effective_owed(kA) >= 0,
          "KF-2(c) FOUND decremented effective_owed by EXACTLY the coinbase-paid owed");
    led.on_block_finalized("kf2", 42);
    const o2::Amounts all = led.effective_owed_all();
    CHECK(all.count(fixed_id) == 0 && all.count(lane.cfg.residual_sink_identity) == 0,
          "KF-2(c) the fixed and sink identities are NOT ledger keys (they were never credited, "
          "so booking them would drive their finalW permanently negative)");
    CHECK(led.effective_owed(kA) == eo_before - owed.at(kA) && min_effective_owed(led) == 0,
          "KF-2(c) after FINALIZE the balance is unchanged (credit == {}) and nothing is negative");

    // (d) WHY the emitted set — not the W4 proposal — is the load-bearing read.
    //     Today they cannot diverge, because the projection forces h_min := 0
    //     into X6 (xmr_o2_settlement_source.hpp) after W4 has applied the floor.
    //     PIN that, then show at the X6 level that a NON-zero X6 h_min WOULD make
    //     allocate_exact_sum emit a strict PREFIX of the proposal (X6 BREAKs on a
    //     budget-truncated sub-floor partial; W4 CARRYs and keeps scanning), i.e.
    //     booking the proposal would decrement owed the sink actually swallowed.
    CHECK(t->coinbase_inputs().h_min == 0,
          "KF-2(d) the X6 h_min the block was built with is 0 — LOAD-BEARING: it is what makes "
          "the emitted set equal the W4 proposal today");
    {
        x6::CoinbaseInputs in = t->coinbase_inputs();
        in.owed.clear();
        // two rows; the second's take will be budget-truncated below the floor
        x6::OwedEntry e0; e0.pay = ref_a(); e0.identity = kA; e0.owed = 1000000000ull; e0.first_eligible = 0;
        x6::OwedEntry e1; e1.pay = ref_b(); e1.identity = fixed_id; e1.owed = 1000000000ull; e1.first_eligible = 1;
        in.owed = {e0, e1};
        in.fixed.clear();
        in.base_reward = 1000000100ull; in.fees = 0;   // room for row 0 + 100 piconero
        in.h_min = 1000ull;                            // a NON-zero X6 floor
        x6::BuildError err = x6::BuildError::None;
        const std::vector<Out> outs = x6::allocate_exact_sum(in, &err);
        std::size_t n_owed = 0;
        for (const auto& o : outs) if (o.role == Out::Role::Owed) ++n_owed;
        CHECK(err == x6::BuildError::None && n_owed == 1,
              "KF-2(d) with a non-zero X6 h_min the executor emits a STRICT PREFIX (1 of 2 rows) "
              "and the sink absorbs the rest — proof that the FOUND map must be read from the "
              "EMITTED outputs, never from a re-run of the W4 projection");
    }
}

// KF-3: NO-DOUBLE-PAY across consecutive blocks. This is the harder half of the
// defect and the one the PR's own offline verifier saw on all 28 blocks ("the
// owed payee first at its full EffectiveOwed").
void kf3() {
    std::printf("KF-3: an owed row already in flight cannot be re-proposed by the next block\n");

    o2::OwedLedger led(7);
    Lane lane(led);
    const ::v37::bytes32 kA = lane.seed(ref_a(), 1000000000ull);
    auto md = miner(3000000, 300000, 18000000000000000000ull);

    std::string why;
    auto b1 = assemble(lane, md, {}, 2700, why);
    if (!CHECK(b1 != nullptr, "KF-3 assemble block 1: " + why)) return;
    const o2::Amounts paid1 = emitted_owed(*b1);
    CHECK(paid1.size() == 1 && paid1.at(kA) == 1000000000ll, "KF-3 block 1 pays the whole owed row");

    led.on_block_found("kf3-b1", /*credit=*/{}, paid1);      // FOUND, NOT yet finalized
    CHECK(led.effective_owed(kA) == 0,
          "KF-3 the pending payout is already deducted from EffectiveOwed");

    auto b2 = assemble(lane, md, {}, 2700, why);
    if (!CHECK(b2 != nullptr, "KF-3 assemble block 2: " + why)) return;
    CHECK(emitted_owed(*b2).empty(),
          "KF-3 block 2 emits NO owed output — the row in flight cannot be paid twice [" +
          describe(b2->outputs()) + "]");
    CHECK(b2->outputs().size() == 1 && b2->outputs()[0].role == Out::Role::Sink,
          "KF-3 block 2 is sink-only");

    led.on_block_finalized("kf3-b1", 7);
    CHECK(led.effective_owed(kA) == 0 && min_effective_owed(led) == 0,
          "KF-3 after FINALIZE the row is extinguished EXACTLY ONCE and nothing is negative");

    // REGRESSION PIN: under the shipped split-ledger wiring the settlement ledger
    // is never decremented, so block 2 re-emits the SAME row at the SAME amount.
    {
        o2::OwedLedger settle_led(7);
        o2::OwedLedger node_led(7);
        Lane split(settle_led);
        const ::v37::bytes32 sk = split.seed(ref_a(), 1000000000ull);
        std::string w;
        auto s1 = assemble(split, md, {}, 2700, w);
        if (!CHECK(s1 != nullptr, "KF-3 split-arm block 1: " + w)) return;
        node_led.on_block_found("split-b1", /*credit=*/{}, emitted_owed(*s1));   // wrong ledger
        auto s2 = assemble(split, md, {}, 2700, w);
        if (!CHECK(s2 != nullptr, "KF-3 split-arm block 2: " + w)) return;
        const o2::Amounts again = emitted_owed(*s2);
        CHECK(again.size() == 1 && again.count(sk) == 1 && again.at(sk) == 1000000000ll,
              "KF-3 REGRESSION PIN: with the ledgers SPLIT, block 2 re-pays the identical owed "
              "row at its full EffectiveOwed — 28 payments of a balance the paper extinguishes "
              "once. Never again.");
    }
}

// =========================================================================
// GROUP KC (continued) — the count-invariance convention collision
// =========================================================================

// KC-5: cap_owed == 0 must emit ZERO owed rows. Canon reads slot_budget_C == 0
// as UNBOUNDED; X6 reads its own cap_owed == 0 as "no room". The projection MUST
// translate, never forward.
void kc5() {
    std::printf("KC-5: cap_owed == 0 (total cap == n_fixed + 1) emits ZERO owed rows\n");

    // ---- n_fixed == 0, resolved total cap 1 --------------------------------
    {
        o2::OwedLedger led(7);
        Lane lane(led);
        const ::v37::bytes32 kA = lane.seed(ref_a(), 1000000000ull);
        const ::v37::bytes32 kB = lane.seed(ref_b(), 2000000000ull);
        auto md = miner(3000000, 300000, 18000000000000000000ull);

        // (a) the projection itself, at total_output_cap == 1.
        std::vector<x6::OwedEntry> out;
        std::string why;
        const bool ok = o2::project_w4_owed(led, lane.fx.pay_of(), /*h_min=*/0, /*n_fixed=*/0,
                                            /*fixed_sum=*/0, /*reward=*/600000000000ull,
                                            /*total_output_cap=*/1, out, nullptr, &why);
        CHECK(ok, "KC-5(a) project_w4_owed SUCCEEDS at cap_owed == 0 (clear-and-succeed, not a "
                  "refusal: a refusal is permanently fatal, never a retry signal): " + why);
        CHECK(out.empty(), "KC-5(a) and it emits ZERO owed rows over a 2-eligible ledger "
                           "(canon's 0 == UNBOUNDED is NEVER forwarded); rows=" +
                           std::to_string(out.size()));

        // (b) the assembled block at wire_cap 1: exactly the residual sink.
        auto t = assemble(lane, md, {}, /*wire_cap=*/1, why);
        if (CHECK(t != nullptr, "KC-5(b) the template still BUILDS at cap 1 (fail-closed, not "
                                "fail-stopped): " + why)) {
            CHECK(resolved_cap(*t) == 1, "KC-5(b) resolved total cap == 1");
            CHECK(t->outputs().size() == 1 && t->outputs()[0].role == Out::Role::Sink &&
                  t->outputs()[0].identity == lane.cfg.residual_sink_identity &&
                  t->outputs()[0].amount == t->reward(),
                  "KC-5(b) exactly n_fixed + 1 == 1 output: the whole owed budget in the sink [" +
                  describe(t->outputs()) + "]");
            CHECK(emitted_owed(*t).empty(),
                  "KC-5(b) and therefore the FOUND payout map is EMPTY — nothing is decremented "
                  "for money the sink took");
        }

        // (c) every carried key keeps its age: the very next block at a normal
        //     cap pays them in the SAME canonical order, at their FULL owed.
        auto t2 = assemble(lane, md, {}, 2700, why);
        if (CHECK(t2 != nullptr, "KC-5(c) next block at a normal cap: " + why)) {
            const std::vector<RefOut> want = kfair_reference(lane.seeded, t2->reward(), 0, 0,
                                                             resolved_cap(*t2), 0,
                                                             lane.cfg.residual_sink_identity);
            CHECK(same_as_reference(t2->outputs(), want),
                  "KC-5(c) the CARRIED keys keep their first_eligible ages — same disposition as "
                  "W4's sub-h_min CARRY, no starvation damage [" + describe(t2->outputs()) + "]");
            const o2::Amounts owed2 = emitted_owed(*t2);
            CHECK(owed2.size() == 2 && owed2.at(kA) == 1000000000ll && owed2.at(kB) == 2000000000ll,
                  "KC-5(c) and both are paid in full by the next block with cap room");
        }
    }

    // ---- n_fixed == 2, resolved total cap 3 --------------------------------
    {
        o2::OwedLedger led(7);
        Lane lane(led);
        lane.cfg.fixed.push_back(x6::FixedOutput{ref_a(), 1000000ull, ::v37::xmr::xmr_identity_key(ref_a())});
        lane.cfg.fixed.push_back(x6::FixedOutput{ref_b(), 2000000ull, ::v37::xmr::xmr_identity_key(ref_b())});
        lane.seed(ref_a(), 1000000000ull);
        lane.seed(ref_b(), 2000000000ull);

        std::vector<x6::OwedEntry> out;
        std::string why;
        const bool ok = o2::project_w4_owed(led, lane.fx.pay_of(), 0, /*n_fixed=*/2,
                                            /*fixed_sum=*/3000000ull, 600000000000ull,
                                            /*total_output_cap=*/3, out, nullptr, &why);
        CHECK(ok && out.empty(),
              "KC-5 n_fixed == 2, total cap 3 => cap_owed == 0 => ZERO owed rows; rows=" +
              std::to_string(out.size()) + " " + why);

        auto md = miner(3000000, 300000, 18000000000000000000ull);
        auto t = assemble(lane, md, {}, /*wire_cap=*/3, why);
        if (CHECK(t != nullptr, "KC-5 n_fixed == 2 template builds at cap 3: " + why)) {
            CHECK(t->outputs().size() == 3 && emitted_owed(*t).empty(),
                  "KC-5 exactly n_fixed + 1 == 3 outputs (2 fixed + sink), no owed [" +
                  describe(t->outputs()) + "]");
        }
    }
}

// KC-6: REACHABILITY + the CONVENTION COLLISION, asserted side by side so a
// future "simplification" of the new guard fails loudly.
void kc6() {
    std::printf("KC-6: cap_owed == 0 is reachable on an ordinary FULL block; the two 0-conventions\n");

    // (a) an ordinary full block resolves the weight-aware cap to 1.
    CHECK(x6::weight_aware_output_cap(300000, 299900, 2700) == 1,
          "KC-6(a) weight_aware_output_cap(median 300000, reserved 299900, wire 2700) == 1 — "
          "cap_owed == 0 arises when the chain is BUSIEST, not from a synthetic config");
    CHECK(x6::weight_aware_output_cap(300000, 0, 2700) > 1,
          "KC-6(a) control: an empty block leaves plenty of owed slots");

    // (b) the two conventions, in the same check.
    o2::OwedLedger led(7);
    Lane lane(led);
    lane.seed(ref_a(), 1000000000ull);
    lane.seed(ref_b(), 2000000000ull);

    auto h_min_0 = [](::v37::ScriptKind) -> std::uint64_t { return 0; };
    o2::PayOfFn pay = lane.fx.pay_of();
    const o2::OwedLedger::Proposal p =
        led.propose_coinbase(600000000000ull, /*slot_budget_C=*/0, pay, h_min_0);
    CHECK(!p.outs.empty(),
          "KC-6(b) CANON: OwedLedger::propose_coinbase(slot_budget_C = 0) is UNBOUNDED — it "
          "proposes " + std::to_string(p.outs.size()) + " rows");

    x6::CoinbaseInputs in;
    in.monero_major_version = 16;
    in.height      = 100;
    in.base_reward = 600000000000ull;
    in.chain_id    = 7;
    in.residual_sink          = ref_sink();
    in.residual_sink_identity = lane.cfg.residual_sink_identity;
    in.output_cap  = 1;                       // == fixed.size() + 1: LEGAL for X6
    for (const auto& po : p.outs) {
        x6::OwedEntry e;
        e.pay = po.pay; e.identity = po.key; e.owed = po.amount; e.first_eligible = in.owed.size();
        in.owed.push_back(e);
    }
    x6::BuildError err = x6::BuildError::None;
    const std::vector<Out> outs = x6::allocate_exact_sum(in, &err);
    std::size_t n_owed = 0;
    for (const auto& o : outs) if (o.role == Out::Role::Owed) ++n_owed;
    CHECK(err == x6::BuildError::None && n_owed == 0 && outs.size() == 1,
          "KC-6(b) X6: allocate_exact_sum with output_cap == fixed.size() + 1 is LEGAL (not "
          "CapTooSmall) and emits ZERO owed outputs");
    CHECK(!p.outs.empty() && n_owed == 0,
          "KC-6(b) THEREFORE the projection MUST TRANSLATE the cap, never forward the 0 — this is "
          "the guard against 'simplifying' the cap_owed == 0 early return away");
}

// KC-7: BACK-COMPAT — the new guard is unreachable on the default path, so an
// empty reproject_owed stays byte-identical to the pre-ruling assembler.
void kc7() {
    std::printf("KC-7: the cap_owed == 0 guard is unreachable at the default cap\n");

    o2::OwedLedger led(7);
    Lane lane(led);
    lane.seed(ref_a(), 1000000000ull);
    auto md = miner(3000000, 300000, 18000000000000000000ull);

    std::string why;
    auto t = assemble(lane, md, {}, 2700, why);
    if (!CHECK(t != nullptr, "KC-7 assemble: " + why)) return;
    CHECK(resolved_cap(*t) > 1,
          "KC-7 the resolved cap on an EMPTY block leaves owed slots (cap=" +
          std::to_string(resolved_cap(*t)) + "), so the guard never fires");
    CHECK(!emitted_owed(*t).empty(),
          "KC-7 and the owed row IS paid — the guard did not swallow it");

    std::vector<x6::OwedEntry> out;
    const bool ok = o2::project_w4_owed(led, lane.fx.pay_of(), 0, 0, 0, t->reward(),
                                        resolved_cap(*t), out, nullptr, &why);
    CHECK(ok && out.size() == 1,
          "KC-7 project_w4_owed at the resolved cap is unchanged by the guard; rows=" +
          std::to_string(out.size()));
}

// The backend-free config/context self-check (S1..S8), including the two RULED
// refusals and the state-root resolver.
void fixture_selftest() {
    std::printf("S: fixture config/context self-check (S1..S8)\n");
    std::string why;
    CHECK(o2::selftest::run(&why), "S1..S8 fixture selftest: " + why);
}

} // namespace

int main() {
    std::printf("v37_xmr_o2_settlement_kat "
                "(multi-node option B: W4Propose K_fair + section-13 state-root commitment)\n");
    CHECK(::v37::xmr::point_check_backend() != nullptr,
          "prelude: an ed25519 point-check backend is installed (ref10)");

    fixture_selftest();
    kw1_kc1();
    kw2();
    kw3_kw4();
    ks1_ks2_ks3_ks4();
    ks5();
    kc2();
    kc3();
    kc4();
    kf1();
    kf2();
    kf3();
    kc5();
    kc6();
    kc7();

    std::printf("summary: %d passed, %d failed\n", g_pass, g_fail);
    std::printf("RESULT: %s\n", g_fail == 0 ? "GREEN" : "RED");
    return g_fail == 0 ? 0 : 1;
}
