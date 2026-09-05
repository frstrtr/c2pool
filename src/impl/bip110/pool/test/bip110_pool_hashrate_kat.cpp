// SPDX-License-Identifier: AGPL-3.0-or-later
//
// bip110_pool_hashrate_kat — F1 REPORTED-POOL-HASHRATE known-answer test.
//
// The dashboard "Pool Hashrate" (CURRENT/AVERAGE/PEAK), the "Good" graph series,
// /global_stats.pool_hash_rate and the effective-CI footer's "reported" value all
// read TrackerSnapshot.pool_hashrate, which publish_snapshot() (node.hpp) fills by
//     aps = ShareTracker::get_pool_attempts_per_second(best, lookback, /*min_work*/false)
//     double hr = fold(aps)                         // uint288 -> double, base 2^32
// The DEFECT the operator saw was NOT a broken computation: this producer existed
// but set_pool_hashrate_fn was never installed on the bip110 web MI, so every
// dashboard sample read the default 0.0 -> summary "0 H/s" while the node minted.
// The main_bip110 fix wires that fn to this exact snapshot field. THIS KAT proves
// the underlying computation is sound and non-zero over a real minted share stream
// (the necessary half; the sufficient half is the LIVE dashboard check post-deploy):
//
//   [1] EMPTY / SINGLE-share window (dist < 2)  -> 0 H/s   (the "reads 0" state:
//       no window to average over -> honest zero, exactly what the dashboard showed
//       before ANY window existed).
//   [2] A minted MULTI-share window             -> > 0 H/s (the fix's signal: a
//       real pseudoshare/share stream yields a NON-ZERO smoothed rate).
//   [3] The returned attempts/sec EQUALS an INDEPENDENT hand computation:
//       sum over the window shares of target_to_average_attempts(bits_to_target(bits))
//       (== each share's stored ShareIndex.work, share.hpp:196) divided by
//       (near.timestamp - far.timestamp). This is the p2pool get_pool_attempts_
//       per_second contract (data.py:2489-2499), recomputed WITHOUT get_delta.
//   [4] The uint288 -> double fold (the EXACT publish_snapshot() code) is finite
//       and > 0 — i.e. the value handed to the web MI is a real H/s number.
//   [5] SMOOTHING (windowed, not per-interval): after an IRREGULAR longer-than-
//       cadence trailing gap, a SINGLE-interval sample (dist=2: the last gap alone)
//       reads low/zero — the shape of the "spiky series decaying to 0" bug — while
//       the multi-share WINDOW estimate (the value publish_snapshot actually uses,
//       over TARGET_LOOKBEHIND) stays > 0 because it averages over the whole
//       window's timespan, not the trailing interval. NOTE: at the KAT's easy
//       share target each share carries only ~2 attempts of work, so the window is
//       kept short enough that work_sum >= timespan (a 600s gap over ~2-att shares
//       would legitimately round to 0 — that is correct arithmetic, not a bug; on
//       the live node real shares carry ~GH of work so a long gap still averages
//       to a large H/s).
//
// Shares are minted via the same create_local_share extend path the extend/mint
// KATs use (easy override target, a few nonce grinds), so the work/timestamps are
// REAL tracker state, not hand-poked fields.

#include "../share_tracker.hpp"        // ShareTracker + create_local_share + get_pool_attempts_per_second
#include "../config_pool.hpp"
#include "../../coin/block.hpp"        // coin::BlockHeaderType
#include "../../coin/gentx_coinbase.hpp"  // assemble_gentx_coinbase

#include <core/uint256.hpp>            // uint256 + uint128 + uint288
#include <core/pack.hpp>
#include <core/hash.hpp>
#include <core/target_utils.hpp>       // chain::bits_to_target / target_to_average_attempts

#include <cmath>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <span>
#include <string>
#include <vector>

namespace {

int g_fail = 0;

void expect_true(const std::string& name, bool cond)
{
    if (cond) std::printf("  [ok]   %s\n", name.c_str());
    else { std::printf("  [FAIL] %s\n", name.c_str()); ++g_fail; }
}

std::vector<unsigned char> from_hex(const std::string& s)
{
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return 0;
    };
    std::vector<unsigned char> out;
    out.reserve(s.size() / 2);
    for (size_t i = 0; i + 1 < s.size(); i += 2)
        out.push_back(static_cast<unsigned char>((nib(s[i]) << 4) | nib(s[i + 1])));
    return out;
}

// REAL BIP-110 block 961640 v2 header (flags/clear_bits/xor_key = 0). Same carrier
// the identity/mint/extend KATs use; we grind its nonce for the easy share target.
const char* HDR_961640 =
    "000000a0657e02138733654183a2c7320d85ca9d743fe139c4bb01000000000000000000"
    "c137a8515a0f6b3aaf6049cc7611787c022ad523d51094be0a0363d0dc0bc768"
    "4dca936a4f8d001a5671798c84daeb494dca936a00000000b1ccf00d030000000000000000"
    "0000001e0300000000000000000000000000000000000068ac0e0000000000000000000000"
    "00000000000000000000000000000000000000000000000000";

const uint32_t EASY_BITS = 0x207fffffu;  // ~2^255 share target (a few nonce grinds)
const uint64_t SUBSIDY    = 312500000ULL;

const std::vector<unsigned char> PAYOUT_SCRIPT = {
    0x76, 0xa9, 0x14,
    0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,
    0xbb,0xcc,0xdd,0xee,0xff,0x01,0x02,0x03,0x04,0x05,
    0x88, 0xac };

// The EXACT uint288 -> double fold publish_snapshot() (node.hpp) applies to the
// aps result before handing it to set_pool_hashrate_fn. Kept byte-identical here
// so the KAT tests the real conversion, not a paraphrase.
double fold_aps_to_double(const uint288& aps)
{
    double hr = 0;
    for (int i = uint288::WIDTH - 1; i >= 0; --i)
        hr = hr * 4294967296.0 + aps.pn[i];
    return hr;
}

// Mint a genesis-branch tip (has_frozen genesis path, absheight=1).
uint256 seed_genesis_tip(bip110::pool::ShareTracker& tracker,
                         bip110::coin::BlockHeaderType carrier,
                         uint32_t timestamp)
{
    using namespace bip110::pool;
    BaseScript coinbase_bs;
    coinbase_bs.m_data = { 0x03, 0x28,0xab,0x0e, 0x00, 0x00, 0x2f, 0x67, 0x65,
                           0x6e, 0x2f, 0x00, 0x00, 0x00, 0x00 };
    std::vector<unsigned char> cb(80, 0xCD);
    for (int i = 0; i < 32; ++i) cb[cb.size() - 44 + i] = (unsigned char)(0x20 + i);
    const uint64_t gnonce = 0x1111222233334444ULL;
    std::memcpy(cb.data() + cb.size() - 12, &gnonce, 8);
    cb[cb.size()-4]=cb[cb.size()-3]=cb[cb.size()-2]=cb[cb.size()-1]=0;

    for (uint32_t g = 0; g < 200000; ++g) {
        carrier.m_nonce = g;
        uint256 h;
        try {
            h = create_local_share(
                tracker, carrier, coinbase_bs, SUBSIDY, /*prev (genesis)*/ uint256(),
                std::vector<uint256>{}, PAYOUT_SCRIPT, /*donation*/ 66, {},
                StaleInfo::none, /*segwit_active*/ true, /*witness_commitment*/ std::string{},
                {}, /*actual_coinbase*/ cb, /*witness_root*/ uint256(),
                /*override_max_bits*/ EASY_BITS, /*override_bits*/ EASY_BITS,
                /*frozen_absheight*/ 1, /*frozen_abswork*/ uint128(1234),
                /*frozen_far*/ uint256(), /*frozen_timestamp*/ timestamp,
                /*frozen_merged_payout*/ uint256(), /*has_frozen*/ true,
                std::vector<uint256>{}, uint256(), std::vector<unsigned char>{},
                /*share_version*/ 36, /*desired_version*/ 36);
        } catch (const std::exception&) { break; }
        if (!h.IsNull()) return h;
    }
    return uint256();
}

// Mint ONE share extending `prev` at the given timestamp — mirrors the extend KAT's
// frozen-field derivation (ref_hash + real coinbase) so the minted share is a fully
// valid tracker element carrying stored work == target_to_average_attempts(EASY_BITS).
uint256 mint_extend(bip110::pool::ShareTracker& tracker,
                    bip110::coin::BlockHeaderType carrier,
                    const uint256& prev,
                    uint32_t timestamp)
{
    using namespace bip110::pool;
    namespace coin = bip110::coin;

    uint128 prev_abswork; uint32_t prev_absheight = 0;
    tracker.chain.get(prev).share.invoke([&](auto* s) {
        prev_abswork = s->m_abswork; prev_absheight = s->m_absheight;
    });

    const uint32_t block_bits = carrier.m_bits;
    RefHashParams p;
    p.share_version   = 36;
    p.desired_version = 36;
    p.prev_share      = prev;
    p.coinbase_scriptSig = { 0x03, 0x29,0xab,0x0e, 0x00, 0x00, 0x2f, 0x62, 0x69,
                             0x70, 0x31, 0x31, 0x30, 0x2f, 0x00, 0x00, 0x00, 0x00 };
    p.share_nonce = 0;
    p.subsidy     = SUBSIDY;
    p.donation    = 66;
    p.stale_info  = 0;
    std::memcpy(p.pubkey_hash.data(), PAYOUT_SCRIPT.data() + 3, 20);
    p.pubkey_type = 0;
    p.has_segwit  = true;
    p.segwit_data = SegwitDataDefault::get();
    p.segwit_data.m_wtxid_merkle_root = uint256();  // ZERO (coinbase-only)
    p.absheight      = prev_absheight + 1;
    p.timestamp      = timestamp;
    p.far_share_hash = uint256::ZERO;               // prev_height < 99
    p.bits = EASY_BITS; p.max_bits = EASY_BITS;
    {
        auto attempts = chain::target_to_average_attempts(chain::bits_to_target(EASY_BITS));
        p.abswork = uint128((prev_abswork + uint128(attempts.GetLow64())).GetLow64());
    }
    try {
        p.merged_payout_hash = tracker.compute_merged_payout_hash(
            prev, chain::bits_to_target(block_bits));
    } catch (const std::exception&) { p.merged_payout_hash = uint256(); }

    auto [intended_ref, intended_nonce] = compute_ref_hash_for_work(p);

    std::vector<unsigned char> op_return = {0x6a, 0x28};
    op_return.insert(op_return.end(), intended_ref.data(), intended_ref.data() + 32);
    { const auto* np = reinterpret_cast<const unsigned char*>(&intended_nonce);
      op_return.insert(op_return.end(), np, np + 8); }

    std::vector<std::pair<std::vector<unsigned char>, uint64_t>> payouts = {
        { PAYOUT_SCRIPT, SUBSIDY } };
    std::vector<unsigned char> donation_script = PoolConfig::get_donation_script(36);
    auto cbres = coin::assemble_gentx_coinbase(
        p.coinbase_scriptSig, /*segwit_commit*/ std::nullopt,
        payouts, /*donation_amt*/ 0, donation_script, op_return);
    const std::vector<unsigned char>& coinbase = cbres.bytes;

    BaseScript coinbase_bs; coinbase_bs.m_data = p.coinbase_scriptSig;
    for (uint32_t g = 0; g < 400000; ++g) {
        carrier.m_nonce = g;
        uint256 h;
        try {
            h = create_local_share(
                tracker, carrier, coinbase_bs, SUBSIDY, /*prev*/ prev,
                std::vector<uint256>{}, PAYOUT_SCRIPT, /*donation*/ 66, {},
                StaleInfo::none, /*segwit_active*/ true, /*witness_commitment*/ std::string{},
                {}, /*actual_coinbase*/ coinbase, /*witness_root*/ uint256(),
                /*override_max_bits*/ EASY_BITS, /*override_bits*/ EASY_BITS,
                /*frozen_absheight*/ p.absheight, /*frozen_abswork*/ p.abswork,
                /*frozen_far*/ p.far_share_hash, /*frozen_timestamp*/ p.timestamp,
                /*frozen_merged_payout*/ p.merged_payout_hash, /*has_frozen*/ true,
                std::vector<uint256>{}, uint256(), std::vector<unsigned char>{},
                /*share_version*/ 36, /*desired_version*/ 36);
        } catch (const std::exception&) { break; }
        if (!h.IsNull()) return h;
    }
    return uint256();
}

// Independent hand computation of get_pool_attempts_per_second WITHOUT get_delta:
// walk (dist-1) shares back from `near` (near inclusive, far exclusive) summing each
// share's target_to_average_attempts(bits_to_target(m_bits)) (== ShareIndex.work,
// share.hpp:196), divide by (near.ts - far.ts). p2pool data.py:2489-2499.
uint288 hand_attempts_per_second(bip110::pool::ShareTracker& tracker,
                                 const uint256& near, int32_t dist)
{
    uint288 work_sum(0);
    uint256 cur = near;
    uint32_t near_ts = 0;
    tracker.chain.get_share(near).invoke([&](auto* s) { near_ts = s->m_timestamp; });
    // Sum the (dist-1) shares from near back toward far (near inclusive).
    for (int32_t i = 0; i < dist - 1; ++i) {
        tracker.chain.get_share(cur).invoke([&](auto* s) {
            work_sum += chain::target_to_average_attempts(chain::bits_to_target(s->m_bits));
        });
        auto* idx = tracker.chain.get_index(cur);
        cur = idx ? idx->tail : uint256();
    }
    // `cur` is now the far share (dist-1 hops back).
    uint32_t far_ts = 0;
    tracker.chain.get_share(cur).invoke([&](auto* s) { far_ts = s->m_timestamp; });
    int32_t time_span = static_cast<int32_t>(near_ts) - static_cast<int32_t>(far_ts);
    if (time_span <= 0) time_span = 1;
    return work_sum / uint288(time_span);
}

} // namespace

int main()
{
    using namespace bip110::pool;
    namespace coin = bip110::coin;

    std::printf("bip110_pool_hashrate_kat: F1 reported pool hashrate from the share stream\n");

    ShareTracker tracker;

    std::vector<unsigned char> hdr_bytes = from_hex(HDR_961640);
    coin::BlockHeaderType carrier;
    { PackStream ps(hdr_bytes); ps >> carrier; }

    // ── Build a real minted stream: genesis + N extends, 1s apart. ────────────
    const uint32_t T0 = carrier.m_timestamp;
    uint256 genesis = seed_genesis_tip(tracker, carrier, T0);
    expect_true("[pre] genesis tip minted", !genesis.IsNull() && tracker.chain.contains(genesis));
    if (genesis.IsNull()) { std::printf("RESULT: FAIL — no genesis.\n"); return 1; }

    // [1] Before any window exists (single share): the estimate is honest ZERO —
    // this is the state that rendered "0 H/s" on the dashboard before a window.
    {
        uint288 aps1 = tracker.get_pool_attempts_per_second(genesis, /*dist*/1, false);
        double hr1 = fold_aps_to_double(aps1);
        std::printf("  [info] BEFORE (single share, dist<2): reported = %.2f H/s\n", hr1);
        expect_true("[1] single-share window -> 0 H/s (no window to average)", hr1 == 0.0);
    }

    // Extend the chain: 5 shares total, timestamps T0, T0+1, ... T0+4.
    uint256 tip = genesis;
    const int N_EXTEND = 4;
    for (int i = 1; i <= N_EXTEND; ++i) {
        tip = mint_extend(tracker, carrier, tip, T0 + static_cast<uint32_t>(i));
        expect_true("[pre] extend share minted", !tip.IsNull() && tracker.chain.contains(tip));
        if (tip.IsNull()) { std::printf("RESULT: FAIL — extend mint failed at i=%d.\n", i); return 1; }
    }
    const int32_t CHAIN_LEN = N_EXTEND + 1;  // 5 shares, absheight 1..5

    // ── [2]+[3]+[4] the full-window estimate ──────────────────────────────────
    const int32_t dist = CHAIN_LEN;  // window across the whole minted chain
    uint288 aps = tracker.get_pool_attempts_per_second(tip, dist, false);
    double hr = fold_aps_to_double(aps);
    std::printf("  [info] AFTER  (%d-share window, dist=%d): reported = %.2f H/s\n",
                CHAIN_LEN, dist, hr);

    expect_true("[2] multi-share window -> NON-ZERO reported hashrate", hr > 0.0);
    expect_true("[4] uint288->double fold (publish_snapshot code) is finite & > 0",
                std::isfinite(hr) && hr > 0.0);

    uint288 aps_hand = hand_attempts_per_second(tracker, tip, dist);
    double hr_hand = fold_aps_to_double(aps_hand);
    std::printf("  [info] hand-computed (sum att / dt, no get_delta): %.2f H/s\n", hr_hand);
    expect_true("[3] tracker aps == independent hand computation (attempts/sec)",
                aps == aps_hand);
    expect_true("[3] folded double matches hand computation", hr == hr_hand);

    // ── [5] Smoothing: windowed estimate absorbs an irregular trailing gap. ────
    // Mint one more share after a 3x-cadence (3s) trailing gap. A SINGLE-interval
    // sample (dist=2 — the trailing gap alone: ~2 att / 3 s) reads 0, the shape of
    // the "spiky series decaying to 0" behavior; the WINDOW estimate (the value
    // publish_snapshot uses) averages over the whole chain's timespan and stays > 0.
    {
        const uint32_t GAP = 3;  // 3x the 1s cadence; kept small because easy-target
                                 // shares carry only ~2 att each (see the header note).
        uint256 late = mint_extend(tracker, carrier, tip, T0 + static_cast<uint32_t>(N_EXTEND) + GAP);
        expect_true("[pre] late (post-gap) share minted", !late.IsNull() && tracker.chain.contains(late));
        if (!late.IsNull()) {
            // Single trailing interval: near=late, far=tip (1 hop). Illustrates the
            // per-interval "spiky-zero" shape a raw counter would produce in a gap.
            uint288 aps_interval = tracker.get_pool_attempts_per_second(late, /*dist*/2, false);
            double hr_interval = fold_aps_to_double(aps_interval);
            // Full window across the whole chain incl. the late share.
            uint288 aps_gap = tracker.get_pool_attempts_per_second(late, dist + 1, false);
            double hr_gap = fold_aps_to_double(aps_gap);
            std::printf("  [info] AFTER %us trailing gap: single-interval = %.2f H/s, "
                        "%d-share WINDOW = %.2f H/s\n", GAP, hr_interval, CHAIN_LEN + 1, hr_gap);
            expect_true("[5] windowed estimate absorbs the trailing gap (> 0, smoothed)",
                        hr_gap > 0.0);
            expect_true("[5] window >= single trailing-interval sample (not spiky-zero)",
                        hr_gap >= hr_interval);
            // The windowed value still equals the independent hand computation.
            uint288 aps_gap_hand = hand_attempts_per_second(tracker, late, dist + 1);
            expect_true("[5] gap-window aps == hand computation", aps_gap == aps_gap_hand);
        }
    }

    if (g_fail == 0) {
        std::printf("RESULT: PASS — reported pool hashrate is 0 with no window, "
                    "NON-ZERO over a real minted share stream, equals the independent "
                    "attempts/sec hand computation, folds to a finite H/s double, and "
                    "absorbs an irregular trailing gap (windowed, not spiky-zero).\n");
        return 0;
    }
    std::printf("RESULT: FAIL — %d check(s) failed.\n", g_fail);
    return 1;
}
