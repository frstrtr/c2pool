// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ===========================================================================
// src/c2pool/v37/test/v37_xmr_cba_native_booking_kat.cpp   (D6a)
//
// The coinbase-authority booking reads lane blocks from the NATIVE chain index
// (xmr/xmr_cba_block_source.hpp), not monerod get_block:
//
//   N1-N7  the source policy: a native hit makes 0 RPCs; a native miss HOLDS
//          ("native-hold:", counted) with 0 RPCs; the compare oracle counts
//          equal / mismatch / unavailable and never decides; the fallback runs
//          only when explicitly enabled; without a native source the legacy
//          monerod path and its "get_block..." reasons are unchanged.
//   F1-F4  end to end through FinalizeConnect: a lane block the native index
//          does not hold yet is RETRIED, then HELD past the retry bound (never
//          refused, never dropped, the R4 gate holds the cursor); once the
//          index holds it, it books and the cursor walks. 0 monerod calls
//          throughout. Pre-D6a FinalizeConnect REFUSED such a block on the
//          first attempt (credit dropped), which is what F1/F2 catch.
//
// Network-free, RandomX-free (monerod STUB + the injected test point-check
// backend, the v37_xmr_o2_finalize_connect_selfcheck shape). Nonzero exit on
// any failure.
// ===========================================================================
#include <unistd.h>

#include <cstdio>
#include <filesystem>
#include <map>
#include <string>
#include <vector>

#include "c2pool/v37/xmr/xmr_cba_block_source.hpp"
#include "c2pool/v37/xmr/xmr_o2_finalize_connect.hpp"

namespace o2 = c2pool::v37n::xmr::o2;
using o2::CbaBlockSource;

namespace {

int g_fail = 0;
void check(const char* name, bool ok, const std::string& detail = {}) {
    std::printf("  [%s] %s%s%s\n", ok ? "PASS" : "FAIL", name, detail.empty() ? "" : "  -- ", detail.c_str());
    if (!ok) ++g_fail;
}

std::vector<std::uint8_t> blob_of(std::uint8_t tag, std::size_t n = 96) {
    std::vector<std::uint8_t> b(n);
    for (std::size_t i = 0; i < n; ++i) b[i] = static_cast<std::uint8_t>(tag * 31u + i);
    return b;
}

// A fake native index + a fake monerod that counts every get_block.
struct Fakes {
    std::map<std::string, std::vector<std::uint8_t>> native;   // what the native index holds
    std::map<std::string, std::vector<std::uint8_t>> daemon;   // what monerod would answer
    bool daemon_down = false;
    std::uint64_t rpc_seen = 0;
    CbaBlockSource::NativeFn native_fn() {
        return [this](const std::string& bid, std::vector<std::uint8_t>& blob) {
            auto it = native.find(bid);
            if (it == native.end()) return false;
            blob = it->second;
            return true;
        };
    }
    CbaBlockSource::RpcFn rpc_fn() {
        return [this](const std::string& bid, std::vector<std::uint8_t>& blob, std::string& why) {
            ++rpc_seen;
            if (daemon_down) { why = "get_block(" + bid.substr(0, 12) + "): connection refused"; return false; }
            auto it = daemon.find(bid);
            if (it == daemon.end()) { why = "get_block: no/invalid result.blob"; return false; }
            blob = it->second;
            return true;
        };
    }
};

const std::string kBidA(64, 'a'), kBidB(64, 'b');

void policy_cases() {
    std::printf("-- source policy --\n");
    {   // N1: native hit
        Fakes f; f.native[kBidA] = blob_of(1); f.daemon[kBidA] = blob_of(1);
        CbaBlockSource s(f.native_fn(), f.rpc_fn());
        std::vector<std::uint8_t> b; std::string why;
        const bool ok = s.fetch(kBidA, b, why);
        check("N1 native hit: the native blob is returned with 0 monerod calls",
              ok && b == blob_of(1) && f.rpc_seen == 0 && s.stats().rpc_calls == 0 && s.stats().native_hits == 1,
              "rpc=" + std::to_string(f.rpc_seen));
    }
    {   // N2 + N3: native miss holds, then resolves
        Fakes f; f.daemon[kBidA] = blob_of(1);
        std::vector<std::string> log;
        CbaBlockSource s(f.native_fn(), f.rpc_fn(), {}, [&](const std::string& l) { log.push_back(l); });
        std::vector<std::uint8_t> b; std::string why;
        bool any_ok = false;
        for (int i = 0; i < 5; ++i) any_ok |= s.fetch(kBidA, b, why);
        check("N2 native miss HOLDS (no silent fallback): false, reason 'native-hold:', 5 holds counted, 1 held bid, 0 monerod calls, loud alarm",
              !any_ok && why.rfind(o2::kNativeHoldPrefix, 0) == 0 && s.stats().native_hold == 5 && s.holding_now() == 1 &&
              f.rpc_seen == 0 && !log.empty() && log.front().find("cba-ALARM native_hold") != std::string::npos,
              "why=" + why.substr(0, 40) + " rpc=" + std::to_string(f.rpc_seen));
        f.native[kBidA] = blob_of(1);
        const bool ok = s.fetch(kBidA, b, why);
        check("N3 once the index holds it: booked from native, hold cleared, still 0 monerod calls",
              ok && b == blob_of(1) && s.holding_now() == 0 && f.rpc_seen == 0);
    }
    {   // N4 + N5: compare oracle
        Fakes f; f.native[kBidA] = blob_of(1); f.daemon[kBidA] = blob_of(1);
        f.native[kBidB] = blob_of(2); f.daemon[kBidB] = blob_of(3);
        std::vector<std::string> log;
        CbaBlockSource s(f.native_fn(), f.rpc_fn(), o2::CbaBlockSourceOptions{true, false},
                         [&](const std::string& l) { log.push_back(l); });
        std::vector<std::uint8_t> a, b; std::string why;
        const bool oka = s.fetch(kBidA, a, why), okb = s.fetch(kBidB, b, why);
        check("N4 compare oracle ON: one get_block per booking, equal counted",
              oka && a == blob_of(1) && s.stats().compare_equal == 1 && f.rpc_seen == 2);
        check("N5 compare oracle MISMATCH is counted + alarmed but never decides: the NATIVE blob is booked",
              okb && b == blob_of(2) && s.stats().compare_mismatch == 1 && !log.empty() &&
              log.back().find("compare_mismatch") != std::string::npos);
        f.daemon_down = true;
        std::vector<std::uint8_t> c; const bool okc = s.fetch(kBidA, c, why);
        check("N6 compare oracle unavailable (monerod down): counted, booking unaffected",
              okc && c == blob_of(1) && s.stats().compare_unavailable == 1);
    }
    {   // N7: explicit fallback
        Fakes f; f.daemon[kBidA] = blob_of(1);
        CbaBlockSource s(f.native_fn(), f.rpc_fn(), o2::CbaBlockSourceOptions{false, true});
        std::vector<std::uint8_t> b; std::string why;
        const bool ok = s.fetch(kBidA, b, why);
        check("N7 explicit fallback ON: a native miss is read from monerod (counted), not held",
              ok && b == blob_of(1) && s.stats().fallback_used == 1 && s.stats().native_hold == 0 && f.rpc_seen == 1);
    }
    {   // N8: no native source -> the legacy monerod path, reasons unchanged
        Fakes f; f.daemon[kBidA] = blob_of(1); f.daemon_down = true;
        CbaBlockSource s(CbaBlockSource::NativeFn{}, f.rpc_fn());
        std::vector<std::uint8_t> b; std::string why;
        const bool bad = s.fetch(kBidA, b, why);
        f.daemon_down = false;
        const bool ok = s.fetch(kBidA, b, why);
        check("N8 no native source (daemon-first): monerod get_block as before, failure reason kept verbatim ('get_block(...)')",
              !s.native_mode() && !bad && ok && b == blob_of(1) && f.rpc_seen == 2 && s.stats().rpc_calls == 2 &&
              s.stats().rpc_failed == 1);
    }
}

void finalize_cases(const std::filesystem::path& tmp) {
    std::printf("-- through FinalizeConnect (the booking gate) --\n");
    using c2pool::xmr::node::MockMonerodTransport;
    using namespace c2pool::v37n::xmr;
    XmrNodeConfig c;
    c.network = MoneroNetwork::Stagenet;
    c.lane_chain = 7;
    c.d_conf = 3;
    c.settle_db_path = (tmp / "store-native-hold").string();
    std::filesystem::create_directories(c.settle_db_path);
    o2::FinalizeConnectOptions o;
    o.out = nullptr;
    o.sidecar_path = (std::filesystem::path(c.settle_db_path) / "pfound.tsv").string();
    o.retry_bound = 30; o.held_retry_every = 5;

    MockMonerodTransport mock;
    XmrNode node(c, mock, &smoke::test_point_check);
    try { node.bring_up(); } catch (const std::exception& e) { check("F0 bring_up", false, e.what()); return; }

    const std::string bid5 = hex_of(smoke::blk_id(5));
    const ::v37::bytes32 payee = smoke::key_of(0xC3);
    Fakes f;   // the native index does NOT hold block 5 yet; monerod would
    f.daemon[bid5] = blob_of(5);
    CbaBlockSource src(f.native_fn(), f.rpc_fn());
    std::uint64_t booked5 = 0;
    o.book_from_chain_ex = [&](std::uint64_t h, const std::string& bid, o2::FinalizeConnectOptions::ChainBooking& bk) {
        if (h != 5) { bk.why = "not-lane: test"; return false; }
        std::vector<std::uint8_t> blob;
        if (!src.fetch(bid, blob, bk.why)) return false;         // exactly main's fetch_decode contract
        if (blob != blob_of(5)) { bk.why = "test: wrong blob"; return false; }
        bk.credit.clear(); bk.credit[payee] = 600000000000ll; bk.payout = bk.credit; bk.total_pico = 600000000000ull;
        ++booked5;
        return true;
    };
    o2::FoundBlockQueue q;
    o2::FinalizeConnect fc(node, c, q, o);
    auto chain = [&](std::uint64_t from, std::uint64_t to) {
        for (std::uint64_t h = from; h <= to; ++h)
            smoke::apply_row(node, h, smoke::blk_id(static_cast<std::uint8_t>(h)), smoke::blk_id(static_cast<std::uint8_t>(h - 1)));
    };
    chain(1, 4); (void)fc.tick();
    chain(5, 10);
    (void)fc.tick();
    check("F1 a lane block the native index does not hold is RETRIED, not refused (pre-D6a: REFUSED on attempt 1)",
          fc.stats().refused == 0 && booked5 == 0 && node.finalize_driver().cursor_height() == 1,
          "refused=" + std::to_string(fc.stats().refused) + " cursor=" + std::to_string(node.finalize_driver().cursor_height()));
    for (int i = 0; i < 45; ++i) (void)fc.tick();
    check("F2 past the retry bound it is HELD (never dropped): held_now=1, refused=0, cursor held at 1 by the R4 gate",
          fc.stats().held_entered == 1 && fc.stats().held_now == 1 && fc.held().count(bid5) && fc.stats().refused == 0 &&
          node.finalize_driver().cursor_height() == 1,
          "held_now=" + std::to_string(fc.stats().held_now) + " refused=" + std::to_string(fc.stats().refused) +
          " cursor=" + std::to_string(node.finalize_driver().cursor_height()));
    f.native[bid5] = blob_of(5);   // the native node connects / re-fetches the body
    for (int i = 0; i < 6; ++i) (void)fc.tick();
    check("F3 once the native index holds the body the HELD block books from it and the cursor walks to the frontier (7)",
          booked5 == 1 && fc.stats().held_resolved == 1 && fc.stats().held_now == 0 && node.ledger().is_settled(bid5) &&
          node.finalize_driver().cursor_height() == 7,
          "booked=" + std::to_string(booked5) + " cursor=" + std::to_string(node.finalize_driver().cursor_height()));
    check("F4 zero monerod get_block calls across the whole hold -> book (native_hold counted)",
          f.rpc_seen == 0 && src.stats().rpc_calls == 0 && src.stats().native_hold > 0 && src.stats().native_hits == 1,
          "rpc=" + std::to_string(f.rpc_seen) + " holds=" + std::to_string(src.stats().native_hold));
    (void)fc.drain_before_stop();
}

} // namespace

int main() {
    std::filesystem::path tmp = std::filesystem::temp_directory_path() / ("v37-xmr-cba-native-" + std::to_string(::getpid()));
    std::filesystem::remove_all(tmp);
    std::filesystem::create_directories(tmp);
    std::printf("== v37_xmr_cba_native_booking_kat ==\n");
    policy_cases();
    finalize_cases(tmp);
    std::filesystem::remove_all(tmp);
    std::printf("== %s (%d failure(s)) ==\n", g_fail ? "FAIL" : "PASS", g_fail);
    return g_fail ? 1 : 0;
}
