// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// v37_xmr_drops_due_kat -- handoff A5 (ruling 2026-09-30): the DROPS delta of
// a lane block is a DEPOSIT into a committed ledger map `due`, never credit;
// the next canonical lane block claims the whole avail in its E_b, clamped per
// key at 0 (the negative rest is written off). Plus the planning-audit gaps
// 2 (minority converge books the DROPS delta) and 3 (the carriage row bound
// applies to the wire witness only).
//
//   D1  exactly once: the deposit enters `due` at FINALIZE, not before and
//       not as credit; a second block on the same ledger sees avail 0;
//       ORPHAN before settle returns the claim; no key ever negative.
//   D2  the clamp: E = 100, due = -150 -> E' = 0, write-off -50; a positive
//       due with no view weight is a new entry.
//   D3  owed_digest: gate OFF byte-identical whatever the caller passes;
//       gate ON commits "V37U" and moves with `due` only.
//   D4  settle store schema 3 round trip; schema 1/2 records byte-identical.
//   D5  the finalize driver books the carried delta as the deposit (rule on),
//       and a restarted ledger replayed from the store has the same digest.
//   D6  gap 2: the minority-converge refold books the DROPS delta exactly as
//       the live node does (rule off: composed credit; rule on: deposit +
//       claim): the refold digest equals the live digest.
//   D7  gap 3: a delta with more rows than the carriage bound stays whole in
//       the booking; only the wire witness is empty; a witness check agrees.
//
// RED on the base (5600fbb8f): no C2POOL_V37_DROPS_DUE / wire-bound API, so
// the base branch of each shim books the delta as credit at FOUND (the
// shipped composition), has no due, no clamp, and clears the whole booked
// delta above the row bound; the same checks then fail by number.
// ---------------------------------------------------------------------------
#include <cstdint>
#include <cstdio>
#include <functional>
#include <map>
#include <optional>
#include <string>
#include <vector>

#include <c2pool/v37/w4_settlement.hpp>
#include <c2pool/v37/xmr/xmr_settle_store.hpp>
#include <c2pool/v37/xmr/xmr_finalize_driver.hpp>
#include <c2pool/v37/xmr/xmr_minority_converge.hpp>
#include <c2pool/v37/xmr/xmr_drops_wiring.hpp>

namespace st = ::c2pool::v37n::settle;
namespace xs = ::c2pool::v37n::xmr;
namespace mc = ::c2pool::v37n::xmr::minority;
using Amounts = st::OwedLedger::Amounts;

static int g_pass = 0, g_fail = 0;
#define CHECK(cond, ...)                                                        \
    do {                                                                        \
        if (cond) { ++g_pass; std::printf("  PASS "); }                         \
        else      { ++g_fail; std::printf("  FAIL "); }                         \
        std::printf(__VA_ARGS__); std::printf("\n");                            \
    } while (0)

static ::v37::bytes32 key(std::uint8_t b) { ::v37::bytes32 k{}; k[0] = b; k[31] = 0x5a; return k; }
static const ::v37::bytes32 X = key(0x11);   // a DROPS-only miner (no share in any view)
static const ::v37::bytes32 Y = key(0x22);   // a share miner with J = 0 (negative REPLACE delta)
static const ::v37::bytes32 Z = key(0x33);   // another share miner
constexpr ::v37::ChainId kChain = 0x0000ABCD;

static bool no_negative(const st::OwedLedger& L) {
    for (const auto& [k, v] : L.finalW()) { (void)k; if (v < 0) return false; }
    return true;
}
static long long fw(const st::OwedLedger& L, const ::v37::bytes32& k) {
    const auto it = L.finalW().find(k);
    return it == L.finalW().end() ? 0 : it->second;
}
static std::string amap(const Amounts& m) {
    std::string s;
    for (const auto& [k, v] : m) s += (k == X ? "X" : k == Y ? "Y" : k == Z ? "Z" : "?") + std::string("=") + std::to_string(v) + " ";
    return s.empty() ? "{}" : "{ " + s + "}";
}

// ── the shims: FIX = the A5 API; BASE = the shipped composition ─────────────
#if defined(C2POOL_V37_DROPS_DUE)
static st::OwedLedgerRules rules_on() { st::OwedLedgerRules r; r.anchor_cut = true; r.drops_due = true; return r; }
static Amounts avail_of(const st::OwedLedger& L) { return L.drops_available(); }
static Amounts due_of(const st::OwedLedger& L) { return L.drops_due(); }
static void clamp(Amounts& E, const Amounts& avail, Amounts* wo) { st::apply_drops_due(E, avail, wo); }
// A canonical booking of lane block `bid` on L: E' = clamp(E, avail(L)), then
// FOUND with the deposit and the claim. Returns the credit it booked.
static Amounts book(st::OwedLedger& L, const std::string& bid, Amounts E, const Amounts& deposit,
                    Amounts* writeoff = nullptr) {
    st::DropsFound d;
    d.deposit = deposit; d.claim = true; d.claimed = L.drops_available();
    st::apply_drops_due(E, d.claimed, &d.writeoff);
    if (writeoff) *writeoff = d.writeoff;
    L.on_block_found(bid, E, {}, std::nullopt, &d);
    return E;
}
#else
static st::OwedLedgerRules rules_on() { st::OwedLedgerRules r; r.anchor_cut = true; return r; }
static Amounts avail_of(const st::OwedLedger&) { return {}; }
static Amounts due_of(const st::OwedLedger&) { return {}; }
static void clamp(Amounts& E, const Amounts& avail, Amounts*) { E = st::compose_credit_from_delta(E, avail); }
static Amounts book(st::OwedLedger& L, const std::string& bid, Amounts E, const Amounts& deposit,
                    Amounts* writeoff = nullptr) {
    if (writeoff) writeoff->clear();
    const Amounts c = st::compose_credit_from_delta(E, deposit);   // the shipped rule: the delta is credit
    L.on_block_found(bid, c, {});
    return c;
}
#endif

// ── D1: exactly once ─────────────────────────────────────────────────────────
static void d1_exactly_once() {
    std::printf("== D1. the deposit enters the due at FINALIZE, is claimed once, ORPHAN returns the claim ==\n");
    st::OwedLedger L(kChain, rules_on());
    // B1: E = {Y:1000, Z:400}; its DROPS delta: X +500 (DROPS only), Y -900 (J = 0: -63/64 of 1024-ish)
    const Amounts dep1 = {{X, 500}, {Y, -900}};
    const Amounts c1 = book(L, "B1", {{Y, 1000}, {Z, 400}}, dep1);
    CHECK(c1 == (Amounts{{Y, 1000}, {Z, 400}}), "B1 books its E_b as credit, the delta is NOT credit: %s", amap(c1).c_str());
    CHECK(avail_of(L).empty(), "before FINALIZE(B1) nothing is available: %s", amap(avail_of(L)).c_str());
    L.on_block_finalized("B1", 10);
    CHECK(fw(L, X) == 0 && fw(L, Y) == 1000 && fw(L, Z) == 400,
          "FINALIZE(B1): finalW X=%lld Y=%lld Z=%lld (want 0 / 1000 / 400: the delta never touches finalW)", fw(L, X), fw(L, Y), fw(L, Z));
    CHECK(due_of(L) == dep1, "FINALIZE(B1): due == D_B1 %s (got %s)", amap(dep1).c_str(), amap(due_of(L)).c_str());
    CHECK(avail_of(L) == dep1, "avail == due with no pending claim: %s", amap(avail_of(L)).c_str());
    // B2 books on L: E = {Y:1000, Z:400}; E' = {X:500, Y:100, Z:400}
    const Amounts c2 = book(L, "B2", {{Y, 1000}, {Z, 400}}, {});
    CHECK(c2 == (Amounts{{X, 500}, {Y, 100}, {Z, 400}}), "B2 claims the whole avail: E' = %s (want X=500 Y=100 Z=400)", amap(c2).c_str());
    CHECK(avail_of(L).empty(), "a second block on the same ledger sees avail 0: %s", amap(avail_of(L)).c_str());
    const Amounts c3 = book(L, "B3", {{Z, 700}}, {});
    CHECK(c3 == (Amounts{{Z, 700}}), "B3 (sibling on the same ledger) claims nothing: %s", amap(c3).c_str());
    // ORPHAN(B2) before settle: the claim comes back
    L.on_block_orphaned("B2", {});
    CHECK(avail_of(L) == dep1, "ORPHAN(B2) pre-settle returns the claim: avail %s", amap(avail_of(L)).c_str());
    const Amounts c2b = book(L, "B2b", {{Y, 1000}}, {{X, 30}});
    CHECK(c2b == (Amounts{{X, 500}, {Y, 100}}), "the replacement B2b claims it once: %s", amap(c2b).c_str());
    L.on_block_finalized("B3", 11);
    CHECK(due_of(L) == dep1, "FINALIZE(B3) (no claim, no deposit) leaves due %s", amap(due_of(L)).c_str());
    L.on_block_finalized("B2b", 12);
    CHECK(due_of(L) == (Amounts{{X, 30}}), "FINALIZE(B2b): due -= claimed, due += D = %s (want X=30)", amap(due_of(L)).c_str());
    CHECK(fw(L, X) == 500 && fw(L, Y) == 1100 && fw(L, Z) == 1100,
          "finalW X=%lld Y=%lld Z=%lld (want 500 / 1100 / 1100)", fw(L, X), fw(L, Y), fw(L, Z));
    CHECK(no_negative(L), "no key is ever negative");
}

// ── D2: the clamp ────────────────────────────────────────────────────────────
static void d2_clamp() {
    std::printf("== D2. the clamp: E = 100, due = -150 -> E' = 0, write-off -50 ==\n");
    Amounts E = {{Y, 100}, {Z, 5}}, wo;
    clamp(E, {{Y, -150}, {X, 70}}, &wo);
    const long long ey = E.count(Y) ? E.at(Y) : 0;
    CHECK(ey == 0 && !E.count(Y), "E'(Y) = %lld (want 0, row dropped)", ey);
    CHECK(wo.count(Y) && wo.at(Y) == -50 && wo.size() == 1, "write-off(Y) = %lld (want -50)", wo.count(Y) ? wo.at(Y) : 0);
    CHECK(E.count(X) && E.at(X) == 70, "a positive due with no view weight is a new entry: E'(X) = %lld", E.count(X) ? E.at(X) : 0);
    CHECK(E.count(Z) && E.at(Z) == 5, "a key without a due is untouched: E'(Z) = %lld", E.count(Z) ? E.at(Z) : 0);
    // through the ledger: B books E(Y)=100 against due(Y)=-150; finalW(Y) never goes negative
    st::OwedLedger L(kChain, rules_on());
    book(L, "A", {{Z, 1}}, {{Y, -150}});
    L.on_block_finalized("A", 5);
    Amounts w2;
    const Amounts c = book(L, "B", {{Y, 100}}, {}, &w2);
    L.on_block_finalized("B", 6);
    CHECK(fw(L, Y) == 0 && no_negative(L), "ledger: finalW(Y) = %lld after the clamp (want 0, never negative)", fw(L, Y));
    CHECK(due_of(L).empty(), "the whole due (folded + written off) left at FINALIZE: due %s", amap(due_of(L)).c_str());
    CHECK(w2.count(Y) && w2.at(Y) == -50, "the booking reports the write-off -50 (got %lld)", w2.count(Y) ? w2.at(Y) : 0);
#if defined(C2POOL_V37_DROPS_DUE)
    CHECK(L.drops_written_off() == -50, "the ledger's write-off total = %lld", L.drops_written_off());
#endif
    (void)c;
}

// ── D3: owed_digest ──────────────────────────────────────────────────────────
static void d3_digest() {
    std::printf("== D3. owed_digest: gate OFF byte-identical, gate ON commits V37U ==\n");
#if defined(C2POOL_V37_DROPS_DUE)
    st::OwedLedgerRules off; off.anchor_cut = true;
    st::OwedLedger a(kChain, off), b(kChain, off);
    st::DropsFound d; d.deposit = {{X, 500}}; d.claim = true; d.claimed = {{Y, 7}};
    a.on_block_found("B1", {{Y, 1000}}, {}, std::nullopt);
    b.on_block_found("B1", {{Y, 1000}}, {}, std::nullopt, &d);
    CHECK(a.owed_digest() == b.owed_digest() && a.owed_event_mmr_root() == b.owed_event_mmr_root(),
          "gate OFF: FOUND with DropsFound == FOUND without (digest and event leaf identical)");
    a.on_block_finalized("B1", 3); b.on_block_finalized("B1", 3);
    CHECK(a.owed_digest() == b.owed_digest() && b.drops_due().empty() && b.drops_available().empty(),
          "gate OFF: FINALIZE keeps no due, digests identical");
    st::OwedLedgerRules on = off; on.drops_due = true;
    st::OwedLedger c(kChain, on), e(kChain, on);
    CHECK(!(c.owed_digest() == st::OwedLedger(kChain, off).owed_digest()), "gate ON: the empty ledger commits the V37U section (digest differs from gate OFF)");
    c.on_block_found("B1", {{Y, 1000}}, {}, std::nullopt, &d);
    e.on_block_found("B1", {{Y, 1000}}, {}, std::nullopt);
    CHECK(c.owed_digest() == e.owed_digest(), "gate ON: a pending deposit is not committed (owed_digest is finalized-only)");
    c.on_block_finalized("B1", 3); e.on_block_finalized("B1", 3);
    CHECK(!(c.owed_digest() == e.owed_digest()), "gate ON: FINALIZE moves the committed due -> digest moves");
    st::OwedLedgerRules onm = on; onm.merkle_rows = true;
    st::OwedLedger f(kChain, onm), g(kChain, onm);
    f.on_block_found("B1", {{Y, 1000}}, {}, std::nullopt, &d); f.on_block_finalized("B1", 3);
    g.on_block_found("B1", {{Y, 1000}}, {}, std::nullopt);     g.on_block_finalized("B1", 3);
    CHECK(!(f.owed_digest() == g.owed_digest()), "gate ON + merkle_rows: V37U rides the rest digest");
#else
    CHECK(false, "no DROPS-due rule on the base (V37U absent)");
#endif
}

// ── D4: settle store schema 3 ────────────────────────────────────────────────
static void d4_store() {
    std::printf("== D4. settle store: schema 3 carries the drops fields; schema 1/2 unchanged ==\n");
    xs::SettleEvent e; e.kind = xs::SettleEvKind::Found; e.bid = "B1"; e.credit = {{Y, 1000}}; e.payout = {{Z, 3}};
    const std::string s1 = e.serialize();
    CHECK(!s1.empty() && s1[0] == 1, "no cut, no drops: schema-1 record (first byte %d)", s1.empty() ? -1 : (int)s1[0]);
    st::AnchorCut cut; cut.next_pos = 42; cut.spine = key(0x77);
    xs::set_cut(e, cut);
    const std::string s2 = e.serialize();
    CHECK(s2[0] == 2, "cut, no drops: schema-2 record (first byte %d)", (int)s2[0]);
#if defined(C2POOL_V37_DROPS_DUE)
    st::DropsFound d; d.deposit = {{X, 500}, {Y, -900}}; d.claim = true; d.claimed = {{X, 11}};
    xs::set_drops(e, d);
    const std::string s3 = e.serialize();
    const auto r = xs::SettleEvent::deserialize(s3);
    CHECK(s3[0] == 3 && xs::drops_of(r) && *xs::drops_of(r) == d && xs::anchor_of(r) == cut,
          "cut + drops: schema-3 record round-trips (first byte %d)", (int)s3[0]);
    xs::SettleEvent n; n.kind = xs::SettleEvKind::Found; n.bid = "B2"; xs::set_drops(n, d);
    const auto rn = xs::SettleEvent::deserialize(n.serialize());
    CHECK(xs::drops_of(rn) && *xs::drops_of(rn) == d && !xs::anchor_of(rn), "drops without a cut round-trips");
    xs::set_drops(n, st::DropsFound{});
    CHECK(n.serialize()[0] == 1, "an empty DropsFound writes no drops section (schema 1)");
#else
    CHECK(false, "no schema-3 drops fields on the base");
#endif
}

// ── D5: the finalize driver books the carried delta as the deposit ──────────
static void d5_driver() {
    std::printf("== D5. finalize driver: carried delta -> deposit (rule on); restart replays it ==\n");
    xs::MemSettleStore store;
    st::OwedLedger L(kChain, rules_on());
    st::SettleHW hw;
    xs::XmrFinalizeDriver drv(L, hw, store, kChain, 1, 0, 0, [](std::uint64_t, const std::string&) { return true; });
    xs::FoundBlock fb;
    fb.bid = "b1"; fb.height = 7; fb.credit = {{Y, 1000}}; fb.payout = {};
    fb.has_carried_drops = true; fb.carried_drops = {{X, 500}, {Y, -900}};
#if defined(C2POOL_V37_DROPS_DUE)
    st::DropsFound claim; claim.claim = true;   // a canonical booking on an empty due
    fb.due = claim;
#endif
    drv.on_block_found(fb);
    st::OwedLedger R(kChain, rules_on());
    bool ok = false;
    xs::RecoveryDriver(store, kChain).recover(R, ok);
    CHECK(ok && R.is_pending("b1") && R.owed_event_mmr_root() == L.owed_event_mmr_root(),
          "the FOUND replays from the store into a fresh ledger (same event root)");
    L.on_block_finalized("b1", 8);
    R.on_block_finalized("b1", 8);
    CHECK(fw(L, X) == 0 && fw(L, Y) == 1000, "finalW X=%lld Y=%lld (want 0 / 1000: the carried delta is not credit)", fw(L, X), fw(L, Y));
    CHECK(due_of(L) == fb.carried_drops, "the carried delta is the deposit: due %s", amap(due_of(L)).c_str());
    CHECK(R.owed_digest() == L.owed_digest() && due_of(R) == due_of(L), "the restarted ledger has the same digest and due");
    CHECK(no_negative(L), "no key negative");
}

// ── D6: gap 2, the minority-converge refold books the DROPS delta ───────────
static Amounts credit_at(std::uint64_t h) { return {{Y, 1000}, {Z, static_cast<long long>(100 * h)}}; }
static Amounts delta_at(std::uint64_t h) { return {{X, static_cast<long long>(50 * h)}, {Y, -300}}; }
static void d6_converge(bool rule_on) {
    std::printf("== D6. gap 2: the converge refold books the DROPS delta (rule %s) ==\n", rule_on ? "ON" : "OFF");
    st::OwedLedgerRules rules;
#if defined(C2POOL_V37_DROPS_DUE)
    rules.drops_due = rule_on;
#else
    if (rule_on) { CHECK(false, "no DROPS-due rule on the base"); return; }
#endif
    auto bid_of = [](std::uint64_t h) { return "c" + std::to_string(h); };
    // the LIVE node: book_from_chain_ex -> XmrFinalizeDriver (delta composed into
    // the credit with the rule off, booked as the deposit + claim with it on)
    auto live_book = [&](st::OwedLedger& L, std::uint64_t h) {
        Amounts E = credit_at(h);
#if defined(C2POOL_V37_DROPS_DUE)
        if (rule_on) {
            st::DropsFound d; d.deposit = delta_at(h); d.claim = true; d.claimed = L.drops_available();
            st::apply_drops_due(E, d.claimed, &d.writeoff);
            L.on_block_found(bid_of(h), E, {}, std::nullopt, &d);
            return;
        }
#endif
        L.on_block_found(bid_of(h), st::compose_credit_from_delta(E, delta_at(h)), {});
    };
    const std::uint64_t D = 1, cursor = 3;
    st::OwedLedger live(kChain, rules);
    live_book(live, 1); live_book(live, 2);
    for (std::uint64_t h = 1; h <= cursor; ++h) { live.on_block_finalized(bid_of(h), h + D); live_book(live, h + 1 + D); }
    // the REFOLD, through the scratch decoder (book_scratch -> ChainBooking)
    mc::RefoldInput in;
    in.chain = kChain; in.rules = rules; in.d_conf = D; in.fork_h = 0; in.cursor = cursor;
    for (std::uint64_t h = 1; h <= cursor + 1 + D; ++h) in.chain_blocks[h] = bid_of(h);
    std::size_t decoded = 0;
    const mc::DecodeFn decode = [&](std::uint64_t h, const std::string&, const std::vector<::v37::bytes32>&,
                                    const std::vector<std::uint64_t>&, bool, const st::OwedLedger& L) {
        ++decoded;
        mc::DecodeResult r;
        r.outcome = mc::DecodeOutcome::Booked;
        r.credit = credit_at(h);
#if defined(C2POOL_V37_DROPS_DUE)
        st::DropsFound d; d.deposit = delta_at(h);
        if (L.rules().drops_due) { d.claim = true; d.claimed = L.drops_available(); st::apply_drops_due(r.credit, d.claimed, &d.writeoff); }
        r.drops = d;
#else
        (void)L;   // base: book_scratch only journals the delta; the refold books without it
#endif
        return r;
    };
    const mc::RefoldResult out = mc::refold(in, decode);
    CHECK(out.ok && decoded == cursor + 1 + D, "the refold booked %zu blocks and finalized %zu", decoded, out.finalized);
    CHECK(out.digest == live.owed_digest(), "refold digest == live digest (%s)", out.digest == live.owed_digest() ? "equal" : "DIFFERENT");
    CHECK(out.ledger_seq == live.ledger_seq(), "refold ledger_seq %llu == live %llu",
          (unsigned long long)out.ledger_seq, (unsigned long long)live.ledger_seq());
    // replay the refold's event log (what the adoption writes to the store): same digest
    st::OwedLedger replay(kChain, rules);
    for (const auto& e : out.events) {
        if (e.kind == xs::SettleEvKind::Found) {
#if defined(C2POOL_V37_DROPS_DUE)
            const auto df = xs::drops_of(e);
            replay.on_block_found(e.bid, e.credit, e.payout, xs::anchor_of(e), df ? &*df : nullptr);
#else
            replay.on_block_found(e.bid, e.credit, e.payout, xs::anchor_of(e));
#endif
        } else if (e.kind == xs::SettleEvKind::Finalize) replay.on_block_finalized(e.bid, e.bin_height);
        else replay.on_block_orphaned(e.bid, e.payout);
    }
    CHECK(replay.owed_digest() == live.owed_digest(), "the adopted event log replays to the live digest");
    std::size_t with_drops = 0;
    for (const auto& p : out.pending) {
#if defined(C2POOL_V37_DROPS_DUE)
        if (p.drops) ++with_drops;
#else
        (void)p;
#endif
    }
    CHECK(!rule_on || with_drops == out.pending.size(), "rule on: every pending record carries its DropsFound (%zu/%zu)", with_drops, out.pending.size());
}

// ── D7: gap 3, the row bound applies to the wire witness only ───────────────
namespace dw = ::c2pool::v37n::xmr::drops;
static Amounts rows(std::size_t n) {
    Amounts m;
    for (std::size_t i = 0; i < n; ++i) { ::v37::bytes32 k{}; k[0] = 0xd0; k[1] = static_cast<std::uint8_t>(i >> 8); k[2] = static_cast<std::uint8_t>(i); m[k] = 1 + static_cast<long long>(i); }
    return m;
}
#if defined(C2POOL_XMR_DROPS_WIRE_BOUND)
static Amounts booked_of(const Amounts& composed) { return composed; }                 // fix: the whole composition
static Amounts wire_of(const Amounts& composed) { return dw::wire_witness_delta(composed); }
static bool agrees(const Amounts& carried, const Amounts& composed) { return dw::carried_delta_agrees(carried, composed); }
#else
static Amounts booked_of(const Amounts& composed) {                                    // base: main's drops_compose_lane
    return composed.size() > dw::kDropsCarryMaxRows ? Amounts{} : composed;
}
static Amounts wire_of(const Amounts& composed) { return booked_of(composed); }
static bool agrees(const Amounts& carried, const Amounts& composed) { return carried == booked_of(composed); }
#endif
static void d7_row_bound() {
    std::printf("== D7. gap 3: a >256-row delta stays whole in the ledger; only the wire witness is bounded ==\n");
    const Amounts big = rows(dw::kDropsCarryMaxRows + 44), small = rows(12);
    long long sum = 0; for (const auto& [k, v] : big) { (void)k; sum += v; }
    const Amounts b = booked_of(big);
    CHECK(b.size() == big.size(), "booked delta keeps all %zu rows (got %zu)", big.size(), b.size());
    CHECK(wire_of(big).empty(), "the wire witness of the %zu-row delta is empty (bounded at %zu)", big.size(), dw::kDropsCarryMaxRows);
    CHECK(wire_of(small) == small && booked_of(small) == small, "a %zu-row delta travels whole", small.size());
    CHECK(agrees(wire_of(big), big) && agrees(small, small) && !agrees(big, big) && !agrees(Amounts{}, small),
          "the carried witness is checked against the witness of the lane composition");
    // booked through the due: every row reaches `due`
    st::OwedLedger L(kChain, rules_on());
    book(L, "W", {{Z, 1}}, b);
    L.on_block_finalized("W", 2);
    long long got = 0; for (const auto& [k, v] : due_of(L)) { (void)k; got += v; }
    CHECK(got == sum && due_of(L).size() == big.size(), "due holds %zu rows summing to %lld (want %zu / %lld)",
          due_of(L).size(), got, big.size(), sum);
}

int main() {
#if defined(C2POOL_V37_DROPS_DUE)
    std::printf("v37_xmr_drops_due_kat: FIX tree (C2POOL_V37_DROPS_DUE)\n");
#else
    std::printf("v37_xmr_drops_due_kat: BASE tree (no DROPS-due API: the shipped composition)\n");
#endif
    d1_exactly_once();
    d2_clamp();
    d3_digest();
    d4_store();
    d5_driver();
    d6_converge(false);
    d6_converge(true);
    d7_row_bound();
    std::printf("\nv37_xmr_drops_due_kat: %d passed, %d failed\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
