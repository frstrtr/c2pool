// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// v37_xmr_order_rule_kat -- the canonical lane order over a relay repair's
// COMPOSED order (handoff gap 4, the A6 remainder; xmr_order_rule.hpp).
//
// A repair receiver replays its own [0, a0) followed by the served [a0, P).
// A6 refused a served order that repeats an id INSIDE [a0, P) only, so a
// winner could count a receipt twice across the seam, and there was no order
// rule at all. Three receivers with different horizons (a0 = 40, 70, 100)
// judge the same winner's order:
//
//   O1  the honest order (bins sorted by (bin, id), two late receipts inside
//       the tail): accepted by all three.
//   O2  one id of [0, a0) repeated in [a0, P) (inside the tail): refused by all.
//   O3  a receipt placed behind a later bin by more than the late tail (no
//       repeat): refused by all; one inside the tail: accepted by all.
//   O4  a repeat of an OLD id (far below the tail): refused by all.
//   O5  a repeat inside [a0, P) (the A6 case): still refused.
//   O6  the builder: the ingest with the late tail drops a late receipt the
//       receiver would refuse, pushes one it would accept, and its own order
//       passes the receivers' check (the same predicate on both sides).
//   O7  the own-order tail store: bounded, and a walk that meets a gap uses
//       what it read.
// RED on the base (only the A6 served-only repeat check exists there).
// ---------------------------------------------------------------------------
#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <functional>
#include <set>
#include <string>
#include <vector>

#include "xmr_relay_test_util.hpp"
#include <c2pool/v37/xmr/relay/xmr_receipt_ingest.hpp>
#if __has_include(<c2pool/v37/xmr/relay/xmr_order_rule.hpp>)
#include <c2pool/v37/xmr/relay/xmr_order_rule.hpp>
#endif

namespace rl = c2pool::v37n::xmr::relay;
using bytes32 = ::v37::bytes32;

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

struct Ent { bytes32 id{}; std::uint64_t bin = 0; };
bytes32 id_of(std::uint64_t bin, int k) {
    bytes32 b{};
    for (int i = 0; i < 8; ++i) b[i] = static_cast<std::uint8_t>(bin >> (8 * (7 - i)));
    b[8] = static_cast<std::uint8_t>(k * 37 + 11);   // id order inside a bin is not k order
    b[31] = 0x5a;
    return b;
}
// Bins 100..139, three receipts each, every bin sorted by id; two late
// receipts (bins 125 and 128, arrived after bin 130 closed) at the tail
// of bin 130 (2 and 5 bins behind: inside the tail).
std::vector<Ent> honest_order() {
    std::vector<Ent> v;
    for (std::uint64_t b = 100; b < 140; ++b) {
        std::vector<Ent> bin;
        for (int k = 0; k < 3; ++k) bin.push_back(Ent{id_of(b, k), b});
        std::sort(bin.begin(), bin.end(), [](const Ent& x, const Ent& y) { return x.id < y.id; });
        v.insert(v.end(), bin.begin(), bin.end());
        if (b == 130) { v.push_back(Ent{id_of(128, 9), 128}); v.push_back(Ent{id_of(125, 9), 125}); }
    }
    return v;
}

// A receiver with horizon a0: its own [0, a0) is the winner's (the digest
// gate at a0 held), and it is served [a0, P). true = the composed order is
// accepted.
bool receiver_accepts(const std::vector<Ent>& order, std::uint64_t a0, std::string& why) {
    std::vector<Ent> served(order.begin() + static_cast<std::ptrdiff_t>(a0), order.end());
#if defined(C2POOL_XMR_ORDER_RULE)
    rl::OwnOrderTail own;
    for (std::uint64_t i = 0; i < a0; ++i) own.note(i, 1, order[i].id, order[i].bin);
    std::vector<rl::OrderEntry> s;
    for (const auto& e : served) s.push_back(rl::OrderEntry{e.id, e.bin});
    const auto oc = rl::check_composed_order(a0, s, [&](std::uint64_t pos, rl::OrderEntry& e, std::uint64_t& first) {
        return own.at(pos, e, first);
    });
    why = oc.why;
    return oc.ok;
#else   // the base: A6 refuses a repeat inside the served [a0, P) only
    std::set<bytes32> seen;
    for (const auto& e : served) if (!seen.insert(e.id).second) { why = "A6: the served order repeats a receipt"; return false; }
    why = "accepted (base: no composed-order rule)";
    return true;
#endif
}

const std::uint64_t kA0[3] = {40, 70, 100};

int accepted_by(const std::vector<Ent>& order, const char* label) {
    int n = 0;
    for (const std::uint64_t a0 : kA0) {
        std::string why;
        const bool ok = receiver_accepts(order, a0, why);
        std::printf("    %s, receiver a0=%llu: %s%s%s\n", label, (unsigned long long)a0, ok ? "ACCEPT" : "REFUSE",
                    why.empty() ? "" : " -- ", why.c_str());
        n += ok ? 1 : 0;
    }
    return n;
}

}  // namespace

static void o1_to_o5() {
    const std::vector<Ent> honest = honest_order();
    const std::size_t P = honest.size();
    std::printf("== O1. the honest order (P=%zu, two late receipts inside the tail) ==\n", P);
    CHECK(accepted_by(honest, "honest") == 3, "accepted by all three receivers");

    std::printf("== O2. an id of [0, a0) repeated in [a0, P), inside the tail ==\n");
    std::vector<Ent> dup = honest;
    dup.push_back(honest[36]);   // bin 112, position 36 < every a0; 27 bins behind the high-water 139
    CHECK(accepted_by(dup, "seam repeat") == 0, "refused by all three receivers (the repeat spans the seam)");

    std::printf("== O3. a receipt placed behind a later bin by more than the late tail (no repeat) ==\n");
    std::vector<Ent> late = honest;
    late.push_back(Ent{id_of(105, 9), 105});   // a fresh receipt of bin 105 after bin 139: 34 bins behind
    CHECK(accepted_by(late, "beyond the tail") == 0, "refused by all three receivers (34 > %llu bins behind)",
#if defined(C2POOL_XMR_ORDER_RULE)
          (unsigned long long)rl::kLateTailBins
#else
          30ull
#endif
    );
    std::vector<Ent> in_tail = honest;
    in_tail.push_back(Ent{id_of(112, 9), 112});   // 27 bins behind: inside the tail
    CHECK(accepted_by(in_tail, "late inside the tail") == 3, "a fresh late receipt 27 bins behind: accepted by all three");

    std::printf("== O4. a repeat of an OLD id (far below the tail) ==\n");
    std::vector<Ent> old = honest;
    old.push_back(honest[0]);   // bin 100: 39 bins behind
    CHECK(accepted_by(old, "old repeat") == 0, "refused by all three receivers");

    std::printf("== O5. a repeat inside [a0, P) (the A6 case) ==\n");
    std::vector<Ent> a6 = honest;
    a6.push_back(honest[P - 2]);
    CHECK(accepted_by(a6, "served repeat") == 0, "refused by all three receivers");
}

static void o6_builder() {
    std::printf("== O6. the builder: the ingest applies the same predicate ==\n");
#if defined(C2POOL_XMR_ORDER_RULE)
    rl::XmrReceiptIngest::Options io;
    io.chain = 7; io.bin_lag = 1; io.grace_ms = 0;
    io.late_tail_bins = rl::kLateTailBins;
    std::vector<Ent> lane;   // the builder's own order, as pushed
    std::uint64_t next = 0;
    rl::XmrReceiptIngest ing(io,
        [&](const ::v37::ScriptRef&, std::uint64_t, std::uint64_t& next_after, bytes32& dig) { next_after = ++next; dig = bytes32{}; return true; },
        [&](const rl::Admitted& a, std::uint64_t, std::uint32_t, std::uint64_t, const bytes32&) { lane.push_back(Ent{a.id, a.bin}); });
    const auto payee = gap2test::payee_of("miner");
    auto admit = [&](std::uint64_t bin, int k) {
        rl::Admitted a; a.id = id_of(bin, k); a.bin = bin; a.r.payee = payee; a.raw = {1, 2, 3};
        ing.on_admitted(std::move(a));
    };
    const auto t0 = std::chrono::steady_clock::now();
    for (std::uint64_t b = 100; b < 140; ++b) {
        for (int k = 0; k < 3; ++k) admit(b, k);
        ing.tick(b + 1, t0);   // bin b closes (lag 1, no grace)
        if (b == 130) { admit(128, 9); admit(125, 9); }   // late, 2 and 5 bins behind
    }
    admit(112, 9);   // late, 27 bins behind 139: inside the tail
    admit(105, 9);   // late, 34 bins behind: beyond it
    const auto& st = ing.stats();
    CHECK(st.late == 4 && st.late_dropped == 1 && lane.size() == 123,
          "late=%llu late_dropped=%llu pushed=%zu: the receipt 34 bins behind is dropped, the others pushed",
          (unsigned long long)st.late, (unsigned long long)st.late_dropped, lane.size());
    CHECK(accepted_by(lane, "the builder's own order") == 3, "the builder's order passes all three receivers");
    std::vector<Ent> forged = lane;
    forged.push_back(Ent{id_of(105, 9), 105});   // what the builder dropped, placed anyway
    CHECK(accepted_by(forged, "the dropped receipt placed anyway") == 0, "refused by all three receivers");
#else
    CHECK(false, "no late tail in the ingest on the base");
#endif
}

static void o7_own_tail() {
    std::printf("== O7. the own-order tail: bounded; a gap ends the walk ==\n");
#if defined(C2POOL_XMR_ORDER_RULE)
    rl::OwnOrderTail t(8);
    for (std::uint64_t i = 0; i < 20; ++i) t.note(i, 1, id_of(100 + i, 0), 100 + i);
    rl::OrderEntry e; std::uint64_t first = 0;
    CHECK(t.size() == 8 && !t.at(11, e, first) && t.at(12, e, first) && e.bin == 112,
          "cap 8: %zu held, position 11 evicted, position 12 held", t.size());
    rl::OwnOrderTail m;   // a two-push receipt (the legacy fee split) at [4, 6)
    m.note(4, 2, id_of(104, 0), 104);
    CHECK(m.at(5, e, first) && first == 4 && e.bin == 104, "an inner position maps to its receipt's first position");
    const std::vector<rl::OrderEntry> served = {rl::OrderEntry{id_of(119, 0), 119}, rl::OrderEntry{id_of(105, 0), 105}};
    const auto oc = rl::check_composed_order(20, served, [&](std::uint64_t pos, rl::OrderEntry& x, std::uint64_t& f) {
        return t.at(pos, x, f);
    });
    CHECK(!oc.ok && !oc.own_complete && oc.own_walked == 8,
          "a repeat inside what the walk read is refused (walked %llu, partial): %s", (unsigned long long)oc.own_walked, oc.why.c_str());
#else
    CHECK(false, "no own-order tail on the base");
#endif
}

int main() {
    std::printf("v37_xmr_order_rule_kat\n");
    o1_to_o5();
    o6_builder();
    o7_own_tail();
    std::printf("\n%d/%d checks passed -- %s\n", g_checks - g_fail, g_checks, g_fail ? "FAIL" : "ALL PASS");
    return g_fail ? 1 : 0;
}
