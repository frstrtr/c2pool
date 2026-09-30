// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// v37_xmr_canonical_coinbase_kat -- CANON: the canonical-coinbase rule
// (xmr_canonical_coinbase.hpp, LaneParams::canon).
//
// In classic p2pool a block candidate hashes a header whose coinbase already pays
// every miner by the PPLNS rule. Here a peer RECOMPUTES the lane coinbase from
// replicated state and compares it with the opening a receipt carries (or with
// the block's own bytes). This KAT drives REAL assembled templates
// (XmrBlockAssembler, fee model ON, rbind, pay-now, V37D, V37P, V37C, V37R) through
// the verifier:
//
//   K1  V37R wire: encode / parse / stripped by every reader, assembler bound.
//   K2  an honest canonical build MATCHES (receipt opening at three extra nonces,
//       and the block prefix); V37R == the template reward; cap is the lane constant.
//   K3  a build without the gate carries no V37R and is not canonical.
//   K4  a builder that deviates is a MISMATCH: omitted payee, underpaid payee,
//       re-ordered payees, wrong declared total, altered V37D / V37N, a stolen
//       residual sink.
//   K5  UNDECIDABLE, never a verdict: another owed_digest, another pool lineage,
//       an unreadable view at the cut, an owed key whose ref is not learned.
//   K6  ledger_before: a lane block booked AFTER the coinbase's height does not
//       change the verdict once it is rolled back; without the roll-back the same
//       honest block would be accused.
//   K7  the start-up rules and the HELLO digest fold.
//   K8  the receipt ingest hook: alarm mode counts and still pushes, enforcement
//       refuses a mismatch before the lane, undecidable is never refused.
//   K9  ledger_at: the builder's pending set is rebuilt from an OLDER retained
//       ledger state (a lane block booked late, a later block removed).
//   K10 the recompute cache: receipts of one template share the outputs and the
//       verdict is identical to the uncached one; a different tail misses.
//   K11 the booking decision (match / mismatch / undecidable x enforce / alarm).
//   K12 the ingest hold: an undecidable receipt is held, released on a match,
//       refused on a mismatch, expired after the hold bound; raindrops exempt.
#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <functional>
#include <map>
#include <string>
#include <vector>

#include "impl/xmr/coin/xmr_derivation.hpp"
#include "impl/xmr/settle/xmr_coinbase.hpp"
#include "impl/xmr/template/xmr_block_assembly.hpp"
#include "c2pool/v37/xmr/xmr_canonical_coinbase.hpp"
#include "c2pool/v37/xmr/xmr_fee_model.hpp"
#include "c2pool/v37/xmr/xmr_o2_settlement_fixture.hpp"
#include "c2pool/v37/xmr/relay/xmr_receipt_ingest.hpp"
#include "c2pool/v37/xmr/relay/xmr_receipt_mint.hpp"
#include "c2pool/v37/xmr/relay/xmr_relay_wire.hpp"

namespace x6  = ::v37::xmr::settle;
namespace fee = c2pool::v37n::xmr::fee;
namespace o2  = c2pool::v37n::xmr::o2;
namespace cn  = c2pool::v37n::xmr::canon;
namespace pn  = c2pool::v37n::xmr::paynow;
namespace cr  = c2pool::v37n::xmr::credit;
namespace asm_ = ::c2pool::xmr::assembly;
namespace akat = ::c2pool::xmr::assembly::kat;
namespace vx  = ::v37::xmr::verify;
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

constexpr fee::DonationNet kNet = fee::DonationNet::Regtest;
constexpr std::uint32_t kChain = 7;

struct Payee { ::v37::ScriptRef ref; ::v37::bytes32 id; std::uint64_t w; };
std::vector<Payee> payees_of(std::initializer_list<std::uint8_t> ks, std::uint64_t w0 = 1) {
    std::vector<Payee> v;
    std::uint64_t w = w0;
    for (auto k : ks) { auto r = ref_of(k); v.push_back({r, id_of(r), w++}); }
    std::sort(v.begin(), v.end(), [](const Payee& a, const Payee& b) { return a.id < b.id; });
    return v;
}

// The lane a verifier and a builder share: a ledger of finalized balances, the
// refs learned for those keys, and the settlement config.
struct Lane {
    o2::OwedLedger L{kChain};
    std::map<::v37::bytes32, ::v37::ScriptRef> refs;
    std::vector<Payee> cutw;   // the lane view at the committed cut
    o2::XmrSettlementConfig cfg;
    int n = 0;
    Lane() {
        cfg.chain_id = kChain;
        cfg.residual_sink = fee::donation_ref(kNet);
        cfg.residual_sink_identity = fee::donation_identity(kNet);
        cfg.fixed = {fee::donation_marker(kNet)};
        cfg.canonical = true;
        ::v37::bytes32 tag{}; tag[0] = 0xC2; tag[31] = 0x37;
        cfg.pool_tag = tag;
        cfg.credit_cut_source = [](std::uint64_t& P, ::v37::bytes32& dg) { P = 77; dg = {}; dg[5] = 0x33; return true; };
        cutw = payees_of({31, 32, 33});
        cfg.paynow_source = [this](std::uint64_t P, const ::v37::bytes32&, std::vector<::c2pool::v37n::settle::WeightedPayee>& out) -> bool {
            if (P != 77) return false;
            out.clear();
            for (const auto& p : cutw) { ::c2pool::v37n::settle::WeightedPayee w; w.key = p.id; w.weight = ::v37::U256(p.w); w.pay = p.ref; out.push_back(w); }
            return true;
        };
    }
    void owe(const Payee& p, long long amt) {
        refs[p.id] = p.ref;
        const std::string b = "seed" + std::to_string(n);
        L.on_block_found(b, Amounts{{p.id, amt}}, {});
        L.on_block_finalized(b, static_cast<std::uint64_t>(++n));
    }
    o2::PayOfFn pay_of(std::set<::v37::bytes32> unknown = {}) const {
        return [this, unknown](const ::v37::bytes32& k) -> ::v37::ScriptRef {
            auto it = refs.find(k);
            if (it != refs.end() && !unknown.count(k)) return it->second;
            for (const auto& p : cutw) if (p.id == k && !unknown.count(k)) return p.ref;
            ::v37::ScriptRef raw; raw.kind = ::v37::ScriptKind::RAW; return raw;
        };
    }
};

// Sabotage hook on the builder's assembler inputs / source.
using Mutate = std::function<void(asm_::AssemblyInputs&, const o2::XmrOwedSettlementSource&)>;

std::unique_ptr<asm_::AssembledTemplate> assemble(const o2::XmrSettlementConfig& cfg, const o2::OwedLedger& L,
                                                  const o2::PayOfFn& pay_of, const Mutate& mut = {},
                                                  std::string* why_out = nullptr) {
    const auto miner = akat::miner(3000000, 300000, 18000000000000000000ull);
    const std::uint64_t base = asm_::xmr_base_reward(miner.already_generated_coins);
    const auto mp = akat::txs(5, 2000, 30000000);
    std::uint64_t fees = 0; for (const auto& t : mp) fees += t.fee;
    const o2::XmrParentContext parent = o2::XmrParentContext::from_miner(miner, base, fees);
    std::string why;
    auto src = o2::build_settlement_source(cfg, parent, L, pay_of, base + fees, &why);
    if (!src) { if (why_out) *why_out = why; return nullptr; }
    asm_::AssemblyInputs a;
    a.miner = miner;
    a.mempool = mp;
    a.settle = o2::assembly_settle_inputs(*src, /*weight_aware_cap=*/!cfg.canonical);
    a.extra_nonce_tail = src->extra_nonce_tail();
    a.reward_commit = cfg.canonical; a.reward_tail_at = src->reward_tail_offset();
    a.extra_nonce_bind_size = 32;
    a.extra_nonce_bind = [](std::uint32_t en, std::uint8_t* out) { for (int i = 0; i < 32; ++i) out[i] = static_cast<std::uint8_t>(en * 7 + i); return true; };
    if (mut) mut(a, *src);
    auto t = asm_::XmrBlockAssembler::build(a, &why);
    if (!t && why_out) *why_out = why;
    return t;
}

// What a verifier reads off one materialised block.
struct Seen {
    bool ok = false;
    cn::BlockFacts f;
    std::vector<std::uint8_t> prefix;
    ::v37::xmr::CoinbaseOpening opening;
};
Seen see(const asm_::AssembledTemplate& t, std::uint32_t en) {
    Seen s;
    asm_::BlockBytes b; std::string why;
    if (!t.materialize(en, b, &why)) return s;
    c2pool::v37n::xmr::relay::BlockLayout L;
    if (!c2pool::v37n::xmr::relay::parse_block_layout(b.full_blob, L, &why)) return s;
    s.prefix = b.coinbase_prefix();
    s.f.major = 16;
    s.f.height = L.height;
    std::memcpy(s.f.prev_id.data(), L.prev_id.data(), 32);
    s.f.tx_extra.assign(s.prefix.end() - static_cast<std::ptrdiff_t>(L.extra_size), s.prefix.end());
    s.ok = vx::build_coinbase_opening(s.prefix, s.prefix.size() - L.extra_size, s.opening);
    return s;
}

cn::Result check_receipt(const Lane& ver, const Seen& s, const o2::PayOfFn& pay_of, const o2::OwedLedger* led = nullptr) {
    const cn::Expected e = cn::expected_coinbase(ver.cfg, led ? *led : ver.L, pay_of, s.f);
    return cn::verify_opening(e, s.opening);
}
cn::Result check_block(const Lane& ver, const Seen& s, const o2::PayOfFn& pay_of) {
    const cn::Expected e = cn::expected_coinbase(ver.cfg, ver.L, pay_of, s.f);
    return cn::verify_block_prefix(e, s.prefix);
}

Lane make_lane() {
    Lane l;
    const auto ps = payees_of({11, 12, 13, 14}, 1);
    long long amt = 900000000LL;
    for (const auto& p : ps) { l.owe(p, amt); amt += 400000000LL; }
    return l;
}

// ---------------------------------------------------------------------------
void k1_wire() {
    std::printf("== K1. V37R wire ==\n");
    static_assert(::c2pool::xmr::assembly::REWARD_TAIL_BYTES == pn::kRewardTailBytes, "impl-tree REWARD_TAIL_BYTES must mirror paynow::kRewardTailBytes (12)");
    CHECK(std::memcmp(::c2pool::xmr::assembly::REWARD_MAGIC, pn::kRewardMagic, 4) == 0, "impl-tree V37R magic == consumer-tree magic");
    const auto r = pn::encode_reward_tail(0x1122334455667788ull);
    CHECK(r.size() == 12 && pn::parse_reward_payload(r) == std::optional<std::uint64_t>(0x1122334455667788ull), "encode/parse round trip (12 B)");
    // full canonical order [nonce | rbind | pad | V37F | V37N | V37R | V37D | V37P | V37C]
    std::vector<std::uint8_t> p(40, 0);
    const auto fnd = pn::encode_finder_field(ref_of(21));
    const auto n = pn::encode_tail(123456);
    const auto d = fee::encode_donation_owed_tail(99);
    ::v37::bytes32 tag{}; tag[0] = 1;
    const auto pt = cr::encode_pool_tag_field(tag);
    cr::CreditCut cc; cc.next_pos = 5; cc.spine_digest[0] = 9;
    const auto c = cr::encode_tail(cc);
    for (auto* part : {&fnd, &n, &r, &d, &pt, &c}) p.insert(p.end(), part->begin(), part->end());
    CHECK(pn::parse_reward_payload(p) == std::optional<std::uint64_t>(0x1122334455667788ull), "V37R parsed from a full payload (after V37D/V37P/V37C are stripped)");
    CHECK(pn::parse_payload(p) == std::optional<std::uint64_t>(123456), "V37N still parsed with V37R between N and D");
    CHECK(fee::parse_donation_owed_payload(p) == std::optional<std::uint64_t>(99), "V37D still parsed");
    CHECK(pn::parse_finder_payload(p).has_value() && cr::parse_tail(p) == std::optional<cr::CreditCut>(cc), "V37F and V37C still parsed");
    CHECK(cr::parse_pool_tag_payload(p) == cr::PoolTagParse::Present, "V37P still parsed");
    std::vector<std::uint8_t> q(40, 0); q.insert(q.end(), n.begin(), n.end()); q.insert(q.end(), r.begin(), r.end());   // no D/P/C
    CHECK(pn::parse_payload(q) == std::optional<std::uint64_t>(123456) && pn::parse_reward_payload(q).has_value(), "V37N | V37R alone (no D/P/C) parse too");
    std::vector<std::uint8_t> z(40, 0);
    CHECK(!pn::parse_reward_payload(z).has_value(), "no V37R -> nullopt (gate-OFF bytes unchanged)");
}

void k2_honest() {
    std::printf("== K2. an honest canonical build matches ==\n");
    Lane b = make_lane(), v = make_lane();
    std::string why;
    auto t = assemble(b.cfg, b.L, b.pay_of(), {}, &why);
    CHECK(t != nullptr, "canonical template assembles: %s", t ? "ok" : why.c_str());
    if (!t) return;
    const Seen s0 = see(*t, 0);
    CHECK(s0.ok, "block materialises and the opening is cut");
    const auto payload = cr::extra_nonce_field(s0.f.tx_extra);
    CHECK(payload && pn::parse_reward_payload(*payload) == std::optional<std::uint64_t>(t->reward()),
          "V37R == the template reward (%llu)", (unsigned long long)t->reward());
    CHECK(pn::parse_payload(*payload).has_value() && fee::parse_donation_owed_payload(*payload).has_value() && cr::parse_tail(*payload).has_value(),
          "the widest payload carries V37N + V37R + V37D + V37P + V37C");
    CHECK(t->outputs().size() <= c2pool::v37n::xmr::kCanonOutputCap, "outputs (%zu) within the lane-constant cap %u",
          t->outputs().size(), (unsigned)c2pool::v37n::xmr::kCanonOutputCap);
    for (std::uint32_t en : {0u, 5u, 1234567u}) {
        const Seen s = see(*t, en);
        const cn::Result r = check_receipt(v, s, v.pay_of());
        CHECK(s.ok && r.v == cn::Verdict::Match, "receipt opening at extra_nonce %u: %s %s", en, cn::to_string(r.v), r.why.c_str());
    }
    const Seen s = see(*t, 9);
    const cn::Result rb = check_block(v, s, v.pay_of());
    CHECK(rb.v == cn::Verdict::Match, "the block's miner_tx prefix: %s %s", cn::to_string(rb.v), rb.why.c_str());
}

void k3_off() {
    std::printf("== K3. without the gate nothing is committed ==\n");
    Lane b = make_lane(), v = make_lane();
    b.cfg.canonical = false;
    auto t = assemble(b.cfg, b.L, b.pay_of());
    CHECK(t != nullptr, "gate-OFF template assembles (weight-aware cap)");
    if (!t) return;
    const Seen s = see(*t, 3);
    const auto payload = cr::extra_nonce_field(s.f.tx_extra);
    CHECK(payload && !pn::parse_reward_payload(*payload).has_value(), "no V37R in a gate-OFF coinbase (master's bytes)");
    const cn::Result r = check_receipt(v, s, v.pay_of());
    CHECK(r.v == cn::Verdict::Mismatch, "a verifier holds a non-canonical build to the rule: %s (%s)", cn::to_string(r.v), r.why.c_str());
}

void k4_tamper() {
    std::printf("== K4. a deviating builder is a mismatch ==\n");
    Lane v = make_lane();
    auto run = [&](const char* what, const Mutate& m, bool expect_tail = false) {
        Lane b = make_lane();
        std::string why;
        auto t = assemble(b.cfg, b.L, b.pay_of(), m, &why);
        if (!t) { CHECK(false, "%s: the tampered template does not assemble: %s", what, why.c_str()); return; }
        const Seen s = see(*t, 4);
        const cn::Result r = check_receipt(v, s, v.pay_of());
        const cn::Result rb = check_block(v, s, v.pay_of());
        CHECK(r.v == cn::Verdict::Mismatch && rb.v == cn::Verdict::Mismatch, "%s -> receipt %s, block %s%s%s", what,
              cn::to_string(r.v), cn::to_string(rb.v), expect_tail ? " [tail] " : " ", r.why.c_str());
    };
    run("omit the oldest payee", [](asm_::AssemblyInputs& a, const o2::XmrOwedSettlementSource&) {
        a.settle.owed.erase(a.settle.owed.begin());
    });
    run("underpay the oldest payee by 1000 piconero", [](asm_::AssemblyInputs& a, const o2::XmrOwedSettlementSource&) {
        a.settle.owed[0].owed -= 1000;
    });
    run("re-order the payees", [](asm_::AssemblyInputs& a, const o2::XmrOwedSettlementSource&) {
        std::swap(a.settle.owed[0].first_eligible, a.settle.owed[1].first_eligible);
    });
    run("steal the residual sink", [](asm_::AssemblyInputs& a, const o2::XmrOwedSettlementSource&) {
        a.settle.fixed.clear();
        a.settle.residual_sink = ref_of(77); a.settle.residual_sink_identity = id_of(ref_of(77));
    });
    run("declare a wrong total reward", [](asm_::AssemblyInputs& a, const o2::XmrOwedSettlementSource& src) {
        a.reward_commit = false;   // hand-written V37R = total + 1
        const std::size_t at = src.reward_tail_offset();
        const auto r = pn::encode_reward_tail(src.reward_hint() + 1);
        a.extra_nonce_tail.insert(a.extra_nonce_tail.begin() + static_cast<std::ptrdiff_t>(at), r.begin(), r.end());
    }, true);
    run("alter V37D (owed_in)", [](asm_::AssemblyInputs& a, const o2::XmrOwedSettlementSource& src) {
        a.extra_nonce_tail[src.reward_tail_offset() + 4] ^= 1;
    }, true);
    run("alter V37N (pay-now base)", [](asm_::AssemblyInputs& a, const o2::XmrOwedSettlementSource&) {
        a.extra_nonce_tail[4] ^= 1;
    }, true);
}

void k5_undecidable() {
    std::printf("== K5. what cannot be reproduced is not a verdict ==\n");
    Lane b = make_lane();
    auto t = assemble(b.cfg, b.L, b.pay_of());
    if (!t) { CHECK(false, "honest template"); return; }
    const Seen s = see(*t, 2);
    {   // 5a: the verifier's ledger is at another owed_digest (a later finalize)
        Lane v = make_lane(); v.owe(payees_of({15})[0], 123456789);
        const cn::Result r = check_receipt(v, s, v.pay_of());
        CHECK(r.v == cn::Verdict::Undecidable, "another owed_digest -> %s (%s)", cn::to_string(r.v), r.why.c_str());
    }
    {   // 5b: another pool lineage
        Lane v = make_lane(); ::v37::bytes32 other{}; other[0] = 0x99; v.cfg.pool_tag = other;
        const cn::Result r = check_receipt(v, s, v.pay_of());
        CHECK(r.v == cn::Verdict::Undecidable, "another pool lineage -> %s (%s)", cn::to_string(r.v), r.why.c_str());
    }
    {   // 5c: the lane view at the committed cut is not readable here yet
        Lane v = make_lane(); v.cfg.paynow_source = [](std::uint64_t, const ::v37::bytes32&, std::vector<::c2pool::v37n::settle::WeightedPayee>&) { return false; };
        const cn::Result r = check_receipt(v, s, v.pay_of());
        CHECK(r.v == cn::Verdict::Undecidable, "unreadable view at the cut -> %s (%s)", cn::to_string(r.v), r.why.c_str());
    }
    {   // 5d: an owed key whose payout ref this verifier has not learned (REJOIN-PAYEE)
        Lane v = make_lane();
        const auto ps = payees_of({11, 12, 13, 14}, 1);
        const cn::Result r = check_receipt(v, s, v.pay_of({ps[0].id}));
        CHECK(r.v == cn::Verdict::Undecidable, "an unlearned owed ref -> %s (%s)", cn::to_string(r.v), r.why.c_str());
    }
    {   // 5e: a real tamper with an unlearned ref stays undecidable (cannot tell), never a verdict
        Lane b2 = make_lane(), v = make_lane();
        auto t2 = assemble(b2.cfg, b2.L, b2.pay_of(), [](asm_::AssemblyInputs& a, const o2::XmrOwedSettlementSource&) { a.settle.owed.erase(a.settle.owed.begin()); });
        const Seen s2 = see(*t2, 2);
        const auto ps = payees_of({11, 12, 13, 14}, 1);
        const cn::Result r = check_receipt(v, s2, v.pay_of({ps[0].id}));
        CHECK(r.v == cn::Verdict::Undecidable, "a deviation seen through an unlearned ref -> %s (held, not accused)", cn::to_string(r.v));
    }
}

void k6_rollback() {
    std::printf("== K6. ledger_before: the builder's pending set ==\n");
    // Builder: a pending lane block X (paid the oldest key in full) is booked; it builds block at H.
    Lane b = make_lane();
    const auto ps = payees_of({11, 12, 13, 14}, 1);
    // find the oldest-first payee of the honest proposal and book a block that pays it
    const Amounts pay_first = [&] {
        Amounts m; for (const auto& [k, v] : b.L.finalW()) { (void)v; m[k] = 0; }
        return m;
    }();
    (void)pay_first; (void)ps;
    const ::v37::bytes32 oldest = id_of(ref_of(11));   // seeded first => armed first
    const long long bal = b.L.finalW().at(oldest);
    b.L.on_block_found("X", Amounts{}, Amounts{{oldest, bal}});   // X at height H-1, pending
    auto t = assemble(b.cfg, b.L, b.pay_of());
    if (!t) { CHECK(false, "builder template"); return; }
    const Seen s = see(*t, 1);
    // Verifier: same finalized partition, X pending too, PLUS a block Y booked at height H (after the coinbase was built).
    Lane v = make_lane();
    v.L.on_block_found("X", Amounts{}, Amounts{{oldest, bal}});
    const ::v37::bytes32 second = id_of(ref_of(12));
    const long long bal2 = v.L.finalW().at(second);
    v.L.on_block_found("Y", Amounts{}, Amounts{{second, bal2}});
    const cn::Result raw = check_receipt(v, s, v.pay_of());
    CHECK(raw.v != cn::Verdict::Match, "without the roll-back the later block Y changes the verdict (%s) -- the honest builder would be accused", cn::to_string(raw.v));
    const o2::OwedLedger rolled = cn::ledger_before(v.L, {{"Y", Amounts{{second, bal2}}}});
    const cn::Result ok = check_receipt(v, s, v.pay_of(), &rolled);
    CHECK(ok.v == cn::Verdict::Match, "ledger_before(Y removed) reproduces the builder's state: %s %s", cn::to_string(ok.v), ok.why.c_str());
    // and a builder that IGNORED pending X (double-pays) is caught against the rolled-back ledger
    Lane b2 = make_lane();   // never booked X
    auto t2 = assemble(b2.cfg, b2.L, b2.pay_of());
    const Seen s2 = see(*t2, 1);
    const cn::Result dbl = check_receipt(v, s2, v.pay_of(), &rolled);
    CHECK(dbl.v == cn::Verdict::Mismatch, "a builder that ignored the pending payout X (re-pays it) -> %s (%s)", cn::to_string(dbl.v), dbl.why.c_str());
}

void k7_gate() {
    static_assert(c2pool::v37n::xmr::kCanonOutputCap == 256, "update the --canonical-coinbase help text in main_v37_xmr.cpp");
    std::printf("== K7. start-up rules and the HELLO digest ==\n");
    using c2pool::v37n::xmr::canon_refusal;
    CHECK(canon_refusal(false, true, true, true, 1, 0).empty(), "testnet: canon v1 + fee v1 accepted");
    CHECK(canon_refusal(false, true, false, false, 0, 0).empty(), "testnet: both gates OFF stays master-identical");
    CHECK(!canon_refusal(false, true, false, true, 1, 0).empty(), "canon without the fee model refused");
    CHECK(!canon_refusal(false, false, true, true, 1, 0).empty(), "canon without the v37 settlement coinbase refused");
    CHECK(!canon_refusal(false, true, true, true, 1, 64).empty(), "canon with --settle-output-cap refused (the cap is a lane constant)");
    CHECK(!canon_refusal(false, true, true, true, 2, 0).empty(), "unknown canon version refused");
    CHECK(canon_refusal(true, true, true, true, 1, 0).empty(), "mainnet: fee v1 + canon v1 accepted");
    CHECK(!canon_refusal(true, true, false, false, 0, 0).empty(), "mainnet without the fee model refused");
    CHECK(!canon_refusal(true, true, true, false, 0, 0).empty(), "mainnet without canon refused");
    ::v37::LaneParams p0 = ::v37::LaneParams::v37_1();
    ::v37::LaneParams p1 = p0; p1.canon = ::v37::CanonGate::for_version(1);
    using c2pool::v37n::xmr::relay::lane_params_digest;
    using c2pool::v37n::xmr::relay::BindMode;
    CHECK(lane_params_digest(p0, 5000, BindMode::Rbind) != lane_params_digest(p1, 5000, BindMode::Rbind), "gate ON changes the HELLO lane digest");
    ::v37::LaneParams p2 = p0; p2.canon = ::v37::CanonGate::for_version(0);
    CHECK(lane_params_digest(p0, 5000, BindMode::Rbind) == lane_params_digest(p2, 5000, BindMode::Rbind), "gate OFF is digest-neutral (master's digest)");
    CHECK(!::v37::CanonGate::for_version(9).enabled, "an unknown version is OFF (fail-safe)");
}

void k8_ingest() {
    std::printf("== K8. the ingest hook ==\n");
    namespace rl = c2pool::v37n::xmr::relay;
    auto run = [&](cn::Verdict verdict, bool enforce, rl::XmrReceiptIngest::Stats& st) {
        rl::XmrReceiptIngest::Options o; o.chain = kChain; o.order = rl::XmrReceiptIngest::Order::Arrival;
        std::uint64_t pos = 0;
        rl::XmrReceiptIngest ing(o,
            [&](const ::v37::ScriptRef&, std::uint64_t, std::uint64_t& next_after, ::v37::bytes32& dg) { next_after = ++pos; dg = {}; return true; },
            [](const rl::Admitted&, std::uint64_t, std::uint32_t, std::uint64_t, const ::v37::bytes32&) {});
        ing.set_canon_check([verdict](const rl::Admitted&) { return cn::Result{verdict, "x"}; }, enforce);
        rl::Admitted a; a.r.payee = ref_of(41); a.id[0] = 1;
        ing.on_admitted(a);
        rl::Admitted d = a; d.id[0] = 2; d.drop = true;   // a raindrop is never held to the coinbase rule
        ing.on_admitted(d);
        st = ing.stats();
    };
    rl::XmrReceiptIngest::Stats st;
    run(cn::Verdict::Mismatch, false, st);
    CHECK(st.canon_mismatch == 1 && st.canon_refused == 0 && st.pushed == 2, "alarm mode: a mismatch is counted and the receipt STILL counts (pushed=%llu)", (unsigned long long)st.pushed);
    run(cn::Verdict::Mismatch, true, st);
    CHECK(st.canon_mismatch == 1 && st.canon_refused == 1 && st.pushed == 1, "enforcing: the mismatching receipt never reaches the lane (refused=%llu pushed=%llu)", (unsigned long long)st.canon_refused, (unsigned long long)st.pushed);
    run(cn::Verdict::Undecidable, true, st);
    CHECK(st.canon_undecidable == 1 && st.canon_refused == 0 && st.canon_held == 1 && st.pushed == 1,
          "enforcing: an undecidable receipt is counted and HELD (not refused, not pushed); the raindrop is exempt");
    run(cn::Verdict::Match, true, st);
    CHECK(st.canon_match == 1 && st.pushed == 2, "a match passes");
}

void k9_ledger_at() {
    std::printf("== K9. ledger_at from an older retained state ==\n");
    Lane b = make_lane();
    const o2::OwedLedger snapshot = b.L;   // the state a verifier retained when this digest became current
    const ::v37::bytes32 oldest = id_of(ref_of(11));
    const long long bal = b.L.finalW().at(oldest);
    b.L.on_block_found("X", Amounts{}, Amounts{{oldest, bal}});   // booked AFTER the snapshot, at height H-1
    auto t = assemble(b.cfg, b.L, b.pay_of());
    if (!t) { CHECK(false, "builder template"); return; }
    const Seen s = see(*t, 1);
    const std::uint64_t H = s.f.height;
    // the verifier moved on: a later finalize (another digest) + pending X and Y (Y at H, after the coinbase)
    Lane v = make_lane();
    v.owe(payees_of({15})[0], 123456789);
    const ::v37::bytes32 second = id_of(ref_of(12));
    const cn::Result stale = check_receipt(v, s, v.pay_of());
    CHECK(stale.v == cn::Verdict::Undecidable, "the live state is at another digest -> %s", cn::to_string(stale.v));
    const std::vector<cn::Booked> booked = {
        {"X", H - 1, Amounts{}, Amounts{{oldest, bal}}},
        {"Y", H, Amounts{}, Amounts{{second, 1000}}}};
    v.L.on_block_found("X", Amounts{}, Amounts{{oldest, bal}});
    v.L.on_block_found("Y", Amounts{}, Amounts{{second, 1000}});
    const o2::OwedLedger rolled = cn::ledger_at(snapshot, booked, H);
    CHECK(rolled.is_pending("X") && !rolled.is_pending("Y") && rolled.owed_digest() == snapshot.owed_digest(),
          "X (below H) is booked again over the snapshot, Y (at H) is not; the finalized partition is the snapshot's");
    const cn::Result ok = check_receipt(v, s, v.pay_of(), &rolled);
    CHECK(ok.v == cn::Verdict::Match, "the honest builder matches against the reconstructed state: %s %s", cn::to_string(ok.v), ok.why.c_str());
    const o2::OwedLedger live_rolled = cn::ledger_at(v.L, booked, H);
    CHECK(live_rolled.is_pending("X") && !live_rolled.is_pending("Y"), "with base == the live ledger it is ledger_before");
}

void k10_cache() {
    std::printf("== K10. the recompute cache ==\n");
    Lane b = make_lane(), v = make_lane();
    auto t = assemble(b.cfg, b.L, b.pay_of());
    if (!t) { CHECK(false, "builder template"); return; }
    cn::Cache cache;
    bool all = true;
    for (std::uint32_t en : {0u, 7u, 99u, 123456u}) {
        const Seen s = see(*t, en);
        const cn::Expected c = cn::expected_coinbase_cached(cache, "st1", 4 + 32, v.cfg, v.L, v.pay_of(), s.f);
        const cn::Expected u = cn::expected_coinbase(v.cfg, v.L, v.pay_of(), s.f);
        all = all && c.ready() && u.ready() && c.cb.prefix == u.cb.prefix && c.cb.tx_extra == u.cb.tx_extra &&
              cn::verify_opening(c, s.opening).v == cn::Verdict::Match;
    }
    CHECK(all, "cached == uncached (prefix, tx_extra) and Match at four extra nonces");
    CHECK(cache.misses == 1 && cache.hits == 3, "one rebuild, three hits (hits=%llu misses=%llu)", (unsigned long long)cache.hits, (unsigned long long)cache.misses);
    {   // a tampered builder has another tail: the cache must not answer for it
        Lane b2 = make_lane();
        auto t2 = assemble(b2.cfg, b2.L, b2.pay_of(), [](asm_::AssemblyInputs& a, const o2::XmrOwedSettlementSource& src) {
            a.extra_nonce_tail[src.reward_tail_offset() + 4] ^= 1; });
        const Seen s2 = see(*t2, 7);
        const cn::Expected e2 = cn::expected_coinbase_cached(cache, "st1", 4 + 32, v.cfg, v.L, v.pay_of(), s2.f);
        CHECK(cn::verify_opening(e2, s2.opening).v == cn::Verdict::Mismatch, "a receipt with another tail is not answered from the cache");
    }
    {   // a different state key misses
        const Seen s = see(*t, 5);
        const std::uint64_t m0 = cache.misses;
        (void)cn::expected_coinbase_cached(cache, "st2", 4 + 32, v.cfg, v.L, v.pay_of(), s.f);
        CHECK(cache.misses == m0 + 1, "another ledger state key rebuilds");
    }
}

void k11_decision() {
    std::printf("== K11. booking decision ==\n");
    using cn::BookAs; using cn::Verdict;
    CHECK(cn::book_decision(Verdict::Match, true) == BookAs::Normal, "match + enforcing -> normal");
    CHECK(cn::book_decision(Verdict::Mismatch, true) == BookAs::PayoutOnly, "mismatch + enforcing -> debit its payouts, drop its credit");
    CHECK(cn::book_decision(Verdict::Undecidable, true) == BookAs::Hold, "undecidable + enforcing -> hold (never refuse)");
    CHECK(cn::book_decision(Verdict::Mismatch, false) == BookAs::Normal && cn::book_decision(Verdict::Undecidable, false) == BookAs::Normal,
          "alarm-only: everything books as before");
}

void k12_hold() {
    std::printf("== K12. the ingest hold ==\n");
    namespace rl = c2pool::v37n::xmr::relay;
    using Clock = std::chrono::steady_clock;
    cn::Verdict now_v = cn::Verdict::Undecidable;
    std::uint64_t pos = 0;
    rl::XmrReceiptIngest::Options o; o.chain = kChain; o.order = rl::XmrReceiptIngest::Order::Arrival; o.canon_hold_ms = 1000;
    rl::XmrReceiptIngest ing(o,
        [&](const ::v37::ScriptRef&, std::uint64_t, std::uint64_t& next_after, ::v37::bytes32& dg) { next_after = ++pos; dg = {}; return true; },
        [](const rl::Admitted&, std::uint64_t, std::uint32_t, std::uint64_t, const ::v37::bytes32&) {});
    ing.set_canon_check([&](const rl::Admitted&) { return cn::Result{now_v, "x"}; }, true);
    rl::Admitted a; a.r.payee = ref_of(41); a.id[0] = 1;
    rl::Admitted b = a; b.id[0] = 2;
    ing.on_admitted(a); ing.on_admitted(b);
    CHECK(ing.canon_pending() == 2 && ing.stats().pushed == 0 && ing.stats().canon_held == 2, "two undecidable receipts are held, nothing pushed");
    const auto t0 = Clock::now();
    ing.tick(0, t0 + std::chrono::milliseconds(100));
    CHECK(ing.canon_pending() == 2, "still undecidable within the hold bound: kept");
    now_v = cn::Verdict::Match;
    ing.tick(0, t0 + std::chrono::milliseconds(200));
    CHECK(ing.canon_pending() == 0 && ing.stats().pushed == 2 && ing.stats().canon_released == 2, "decided Match: released into the lane (pushed=%llu)", (unsigned long long)ing.stats().pushed);
    now_v = cn::Verdict::Undecidable;
    rl::Admitted c = a; c.id[0] = 3;
    ing.on_admitted(c);
    now_v = cn::Verdict::Mismatch;
    ing.tick(0, Clock::now() + std::chrono::milliseconds(50));
    CHECK(ing.canon_pending() == 0 && ing.stats().pushed == 2 && ing.stats().canon_refused == 1, "decided Mismatch later: refused, never pushed");
    now_v = cn::Verdict::Undecidable;
    rl::Admitted d = a; d.id[0] = 4;
    ing.on_admitted(d);
    ing.tick(0, Clock::now() + std::chrono::milliseconds(5000));
    CHECK(ing.canon_pending() == 0 && ing.stats().canon_expired == 1 && ing.stats().pushed == 2, "still undecidable past the hold bound: expired, not credited");
}

}  // namespace

int main() {
    std::printf("v37_xmr_canonical_coinbase_kat\n");
    k1_wire();
    k2_honest();
    k3_off();
    k4_tamper();
    k5_undecidable();
    k6_rollback();
    k7_gate();
    k8_ingest();
    k9_ledger_at();
    k10_cache();
    k11_decision();
    k12_hold();
    std::printf("\n%d/%d checks passed -- %s\n", g_checks - g_fail, g_checks, g_fail ? "FAIL" : "ALL PASS");
    return g_fail ? 1 : 0;
}
