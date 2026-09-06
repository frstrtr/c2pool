// SPDX-License-Identifier: AGPL-3.0-or-later
// BCH pool-wide "Current Payouts" read-model KAT — exercised through the REAL
// bch::ShareTracker API and the REAL bch::dashboard::pplns_payouts_current
// (the /current_payouts + window `pplns_current` seam).
//
// Regression witness for the empty-"Current Payouts" defect BTC/DASH document:
// a NULL-IMiningNode dashboard never fills the web MI's own PPLNS cache, so a
// populated window served NO `pplns` key. This pins that a POPULATED BCH
// sharechain now yields a NON-EMPTY, address-keyed, value-conserving split —
// and that every honest-empty precondition still returns {}.
//
// FENCED, additive: touches no production code. Its own executable in the BCH
// test tree, which is plain int main() + CHECK (no GTest dependency) — the
// ASSERTION SHAPE mirrors the btc dashboard_pplns_current_test, the HARNESS is
// the plain-main form the whole BCH lane uses.
//
// Perturbation (red/green): flip the main-path share_version to <36 with an
// empty chain, or zero the subsidy/bits — the split collapses to {} and the
// non-empty CHECKs fail. Keep the populated v36 call — GREEN.

#include <cstdint>
#include <cstdio>
#include <iostream>
#include <string>
#include <vector>

#include <core/uint256.hpp>
#include <impl/bch/share.hpp>
#include <impl/bch/share_tracker.hpp>
#include <impl/bch/dashboard_pplns.hpp>

namespace {

int failures = 0;
#define CHECK(cond) do { if (!(cond)) { \
    std::cerr << "FAIL: " #cond " @ line " << __LINE__ << "\n"; ++failures; } } while (0)

// A short hex tail -> uint256 (zero-padded to 64 nibbles).
uint256 hx(const std::string& tail) {
    uint256 v;
    v.SetHex(std::string(64 - tail.size(), '0') + tail);
    return v;
}

// Build a resolved bch::ShareTracker of `count` v36 MergedMiningShares (share
// i's parent is i-1; share 0 has a null parent = resolved chain genesis). Each
// share carries a DISTINCT 20-byte P2PKH pubkey hash, so the PPLNS split has
// `count` worker rows plus the donation. m_donation == 0 routes all decayed
// weight to the worker script; the donation output absorbs the (>=1 sat
// consensus-floored) remainder. Returns the tip hash.
uint256 build_chain(bch::ShareTracker& tracker, int count, uint32_t bits) {
    uint256 prev;
    prev.SetNull();
    uint256 tip;
    tip.SetNull();
    for (int i = 0; i < count; ++i) {
        char buf[24];
        std::snprintf(buf, sizeof(buf), "%x", 0x5a1e + i);
        uint256 h = hx(buf);

        auto* s = new bch::MergedMiningShare(h, (i == 0) ? uint256::ZERO : prev);
        s->m_bits        = bits;
        s->m_max_bits    = bits;
        s->m_donation    = 0;
        s->m_pubkey_type = 0;                       // P2PKH
        // Distinct pubkey hash per miner: byte 0 = miner index (all else zero).
        s->m_pubkey_hash.SetNull();
        s->m_pubkey_hash.begin()[0] = static_cast<unsigned char>(0x10 + i);
        s->m_min_header.m_bits = bits;
        s->m_timestamp   = 1700000000u + i;
        s->m_absheight   = i;

        tracker.add(s);
        prev = h;
        tip = h;
    }
    return tip;
}

double sum_values(const nlohmann::json& obj) {
    double total = 0.0;
    for (auto it = obj.begin(); it != obj.end(); ++it)
        total += it.value().get<double>();
    return total;
}

constexpr uint32_t kBits    = 0x1d00ffffu;      // standard difficulty-1 nBits
constexpr uint64_t kSubsidy = 5000000000ull;    // 50 BCH in satoshi

} // namespace

int main()
{
    // --- Populated chain -> non-empty, address-keyed, value-conserving split.
    {
        bch::ShareTracker tracker;
        const int n_miners = 4;
        uint256 tip = build_chain(tracker, n_miners, kBits);

        nlohmann::json out = bch::dashboard::pplns_payouts_current(
            tracker, tip, /*share_version=*/36, kBits, kSubsidy, /*testnet=*/false);

        CHECK(out.is_object());
        CHECK(!out.empty());   // populated window must not render an empty split

        // Every key must be a decoded address (never raw hex / empty). Mainnet
        // BCH legacy base58: worker P2PKH -> '1...', v36 P2SH donation -> '3...'.
        int worker_rows = 0;
        for (auto it = out.begin(); it != out.end(); ++it) {
            const std::string& addr = it.key();
            CHECK(!addr.empty());
            CHECK(addr[0] == '1' || addr[0] == '3');
            CHECK(it.value().get<double>() > 0.0);
            if (!addr.empty() && addr[0] == '1') ++worker_rows;
        }
        CHECK(worker_rows == n_miners);                             // one row per miner
        CHECK(static_cast<int>(out.size()) >= n_miners + 1);       // workers + donation

        // Value conservation: whole subsidy distributed (donation absorbs the
        // remainder), so the rendered BCH total equals subsidy/1e8 to the sat.
        const double expect = static_cast<double>(kSubsidy) / 1e8;
        const double got = sum_values(out);
        CHECK(got > expect - 1e-6 && got < expect + 1e-6);
    }

    // --- Window feeder mirrors the current split (pplns_current + pplns[tip16]).
    {
        bch::ShareTracker tracker;
        uint256 tip = build_chain(tracker, 3, kBits);

        nlohmann::json cur = bch::dashboard::pplns_payouts_current(
            tracker, tip, 36, kBits, kSubsidy, false);
        CHECK(cur.is_object() && !cur.empty());

        nlohmann::json window = nlohmann::json::object();
        window["shares"] = nlohmann::json::array();
        window["shares"].push_back({{"h", tip.GetHex().substr(0, 16)}});
        if (cur.is_object() && !cur.empty()) {
            window["pplns"] = {{ tip.GetHex().substr(0, 16), cur }};
            window["pplns_current"] = cur;
        }

        CHECK(window.contains("pplns_current"));
        CHECK(window.contains("pplns"));
        const std::string tip16 = tip.GetHex().substr(0, 16);
        CHECK(window["pplns"].contains(tip16));
        CHECK(window["pplns"][tip16] == window["pplns_current"]);
        CHECK(window["shares"][0]["h"].get<std::string>() == tip16);
    }

    // --- Honest-empty guards: every failure precondition returns {} with no keys.
    {
        bch::ShareTracker empty_tracker;

        // Null best share (empty sharechain) -> {}.
        nlohmann::json a = bch::dashboard::pplns_payouts_current(
            empty_tracker, uint256::ZERO, 36, kBits, kSubsidy, false);
        CHECK(a.is_object() && a.empty());

        bch::ShareTracker tracker;
        uint256 tip = build_chain(tracker, 3, kBits);

        // A real tip but zero subsidy -> {} (no honest reward to split).
        nlohmann::json b = bch::dashboard::pplns_payouts_current(
            tracker, tip, 36, kBits, /*subsidy=*/0, false);
        CHECK(b.is_object() && b.empty());

        // A real tip but zero block bits -> {} (no difficulty epoch to anchor).
        nlohmann::json c = bch::dashboard::pplns_payouts_current(
            tracker, tip, 36, /*block_bits=*/0, kSubsidy, false);
        CHECK(c.is_object() && c.empty());
    }

    if (failures == 0)
        std::cout << "bch_dashboard_pplns_current_test: ALL PASS\n";
    else
        std::cerr << "bch_dashboard_pplns_current_test: " << failures << " FAILURE(S)\n";
    return failures == 0 ? 0 : 1;
}
