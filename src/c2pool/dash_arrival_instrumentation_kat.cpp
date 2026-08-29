// SPDX-License-Identifier: AGPL-3.0-or-later
// KAT: PR-0 ARRIVAL INSTRUMENTATION schema (dashd-cut coin-P2P foundation).
//
// Locks the two invariants the stacked coin-P2P PRs consume:
//   (1) OffEmbeddedWindow's arrival/fold split partitions the window exactly:
//         arrival_ms + fold_ms == window_ms       on every complete window,
//       across synthetic windows with KNOWN t_open/t_data_arrived/
//       t_fold_complete/t_resumed, including the boundary cases (zero-wire,
//       zero-fold, single-instant window) and the order/duplicate guards.
//   (2) DeliveryLatencyEwma's per-peer per-datum-class update follows the exact
//       RTT-style sequence ewma += (sample - ewma)/8, seeded on the first
//       sample, ignoring negative (unmatched) samples.
//
// Pure red/green over ONE header-only unit, NO node and NO daemon. Header-only
// so it builds under -DC2POOL_DASH_BLS=ON without the c2pool-dash object graph.

#include <impl/dash/coin/arrival_timing.hpp>

#include <cstdio>
#include <string>

using dash::coin::DatumClass;
using dash::coin::DeliveryLatencyEwma;
using dash::coin::OffEmbeddedWindow;
using dash::coin::PeerDeliveryLatency;

static int g_fail = 0;
#define CHECK(cond) do { if (!(cond)) { \
    std::printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); ++g_fail; } } while (0)

// Build a complete window from four absolute monotonic-ms marks and assert the
// split math holds and matches the expected component spans.
static void check_window(int64_t open, int64_t arrived, int64_t fold_done,
                         int64_t resumed,
                         int64_t exp_arrival, int64_t exp_fold,
                         int64_t exp_window)
{
    OffEmbeddedWindow w;
    w.open(open);
    CHECK(w.open_pending());
    CHECK(!w.complete());
    w.data_arrived(arrived);
    w.fold_complete(fold_done);
    w.resumed(resumed);

    CHECK(w.complete());
    CHECK(!w.open_pending());
    CHECK(w.arrival_ms() == exp_arrival);
    CHECK(w.fold_ms()    == exp_fold);
    CHECK(w.window_ms()  == exp_window);
    CHECK(w.derive_ms()  == fold_done - arrived);
    // THE core invariant the emit and the stacked PRs rely on:
    CHECK(w.arrival_ms() + w.fold_ms() == w.window_ms());
    CHECK(w.split_consistent());
}

int main()
{
    // ── (1) WINDOW SPLIT MATH ────────────────────────────────────────────────
    // Ordinary window: 40 ms on the wire, 60 ms folding, 100 ms total.
    check_window(/*open*/1000, /*arrived*/1040, /*fold_done*/1075,
                 /*resumed*/1100, /*arrival*/40, /*fold*/60, /*window*/100);
    // Zero-wire (datum already in hand at open): all time is fold.
    check_window(2000, 2000, 2010, 2050, 0, 50, 50);
    // Zero-fold (resumed the instant the datum arrived): all time is arrival.
    check_window(3000, 3080, 3080, 3080, 80, 0, 80);
    // Single-instant window (everything at once): both spans zero, sum zero.
    check_window(4000, 4000, 4000, 4000, 0, 0, 0);
    // Large window that survives the sub-second tip round trip proportions
    // measured on the hotel (issue #1154): 54 ms wire, rest fold.
    check_window(5000, 5054, 5100, 5891, 54, 837, 891);

    // ── ORDER / DUPLICATE GUARDS ─────────────────────────────────────────────
    // A fresh open() resets a half-filled window (no stale boundary survives).
    {
        OffEmbeddedWindow w;
        w.open(100); w.data_arrived(150);
        w.open(200);                       // abandon + restart
        CHECK(w.t_data_arrived == -1);
        CHECK(w.arrival_ms() == -1);
        CHECK(!w.complete());
        w.data_arrived(260); w.resumed(300);
        CHECK(w.arrival_ms() == 60);
        CHECK(w.fold_ms()    == 40);
        CHECK(w.arrival_ms() + w.fold_ms() == w.window_ms());
    }
    // data_arrived before open() is ignored; a duplicate reply cannot rewrite
    // the banked arrival boundary; a duplicate resume cannot rewrite t_resumed.
    {
        OffEmbeddedWindow w;
        w.data_arrived(50);                // no open yet -> ignored
        CHECK(w.t_data_arrived == -1);
        w.open(100);
        w.data_arrived(140);
        w.data_arrived(999);               // duplicate -> ignored (first wins)
        CHECK(w.t_data_arrived == 140);
        w.resumed(200);
        w.resumed(777);                    // duplicate -> ignored (first wins)
        CHECK(w.t_resumed == 200);
        CHECK(w.arrival_ms() == 40);
        CHECK(w.fold_ms()    == 60);
    }
    // An incomplete window reports -1 spans and is NOT split_consistent.
    {
        OffEmbeddedWindow w;
        w.open(0); w.data_arrived(10);     // never resumed
        CHECK(w.fold_ms() == -1);
        CHECK(w.window_ms() == -1);
        CHECK(!w.split_consistent());
    }

    // ── (2) PER-PEER PER-DATUM-CLASS DELIVERY-LATENCY EWMA ───────────────────
    // Exact RTT-style sequence: seed, then ewma += (sample - ewma)/8.
    {
        DeliveryLatencyEwma e;
        CHECK(!e.has_sample());
        CHECK(e.ewma_ms() == -1);
        e.observe(100);                    // seed
        CHECK(e.has_sample());
        CHECK(e.samples() == 1);
        CHECK(e.ewma_ms() == 100);
        CHECK(e.last_ms() == 100);
        e.observe(180);                    // 100 + (180-100)/8 = 100 + 10 = 110
        CHECK(e.ewma_ms() == 110);
        CHECK(e.last_ms() == 180);
        e.observe(180);                    // 110 + (180-110)/8 = 110 + 8 = 118
        CHECK(e.ewma_ms() == 118);
        e.observe(-5);                     // negative -> ignored entirely
        CHECK(e.ewma_ms() == 118);
        CHECK(e.samples() == 3);
        e.observe(10);                     // 118 + (10-118)/8 = 118 + (-13) = 105
        CHECK(e.ewma_ms() == 105);         // trunc-toward-zero: -108/8 = -13
        CHECK(e.samples() == 4);
    }
    // A single fast sample seeds exactly; the EWMA never lags its only datum.
    {
        DeliveryLatencyEwma e;
        e.observe(7);
        CHECK(e.ewma_ms() == 7);
    }

    // ── PER-PEER HOLDER: the three classes are INDEPENDENT ───────────────────
    {
        PeerDeliveryLatency peer;
        CHECK(!peer.has_any());
        peer.observe(DatumClass::MnListDiff, 200);
        peer.observe(DatumClass::MnListDiff, 200);   // 200 seed, stays 200
        peer.observe(DatumClass::TipBody,    40);
        peer.observe(DatumClass::QrInfo,     1000);
        CHECK(peer.has_any());
        CHECK(peer.ewma_ms(DatumClass::MnListDiff) == 200);
        CHECK(peer.ewma_ms(DatumClass::TipBody)    == 40);
        CHECK(peer.ewma_ms(DatumClass::QrInfo)     == 1000);
        // A slow mnlistdiff does NOT move the tip_body average (independence).
        peer.observe(DatumClass::MnListDiff, 360);   // 200 + (360-200)/8 = 220
        CHECK(peer.ewma_ms(DatumClass::MnListDiff) == 220);
        CHECK(peer.ewma_ms(DatumClass::TipBody)    == 40);
        CHECK(peer.get(DatumClass::QrInfo).samples() == 1);
    }

    // Datum-class names are stable (the emit + grep contract).
    CHECK(std::string(dash::coin::datum_class_name(DatumClass::TipBody))    == "tip_body");
    CHECK(std::string(dash::coin::datum_class_name(DatumClass::MnListDiff)) == "mnlistdiff");
    CHECK(std::string(dash::coin::datum_class_name(DatumClass::QrInfo))     == "qrinfo");

    // Default-OFF emit flag (byte-identical-to-master guarantee).
    CHECK(dash::coin::arrival_instr_enabled() == false);
    dash::coin::set_arrival_instr_enabled(true);
    CHECK(dash::coin::arrival_instr_enabled() == true);
    dash::coin::set_arrival_instr_enabled(false);
    CHECK(dash::coin::arrival_instr_enabled() == false);

    if (g_fail == 0) { std::printf("dash_arrival_instrumentation_kat PASS\n"); return 0; }
    std::printf("dash_arrival_instrumentation_kat FAIL (%d)\n", g_fail);
    return 1;
}
