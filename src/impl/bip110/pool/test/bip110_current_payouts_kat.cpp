// SPDX-License-Identifier: AGPL-3.0-or-later
//
// bip110_current_payouts_kat — the /current_payouts DASHBOARD-SEAM known-answer test.
//
// LIVE BUG (contabo): with 196+ real shares on the sharechain, GET /current_payouts
// returned {} and the dashboard "Current Payouts" card showed "0.0000 BIP110" over
// an EMPTY address/V36?/amount table. Root cause: rest_current_payouts() (web_server
// .cpp:2408) has three sources and ALL are dead on the bip110 lane — the #939 direct
// seam was wired only by DASH, MI stratum is OFF so the PPLNS cache never fills, and
// no PayoutManager is set — so the handler fell through to {}.
//
// The fix wires the direct seam (main_bip110.cpp mi->set_current_payouts_fn) with the
// SAME PPLNS SSOT the coinbase is minted from: bip110::pool::current_payouts_report,
// which walks ShareTracker::get_expected_payouts (the exact map work_source's pplns_fn_
// emits) and resolves each scriptPubKey to a bip110 address. THIS KAT drives that
// EXACT reporting transform (not a re-implementation) and proves:
//
//   [1] a real 2-share window (miner A genesis <- miner B) is seeded,
//   [2] current_payouts_report returns a NON-EMPTY object with >= 2 miner addresses
//       plus the donation address (>= 3 rows),
//   [3] the reported coins sum EXACTLY to the payable coinbase (subsidy, no fees) —
//       donation residual folded in, integer-truncation exact,
//   [4] an EMPTY chain (null best share) yields {} — honest empty, never faked,
//   [5] a null best share on a POPULATED tracker also yields {} (the guard main's
//       lambda applies before taking the read guard).
//
// READ-ONLY: current_payouts_report never touches gentx/coinbase/consensus/reward —
// it is a const window walk. Same heavy link closure as bip110_multiminer_pplns_kat.

#include "../current_payouts_report.hpp"   // bip110::pool::current_payouts_report (SUT)
#include "../share_tracker.hpp"            // ShareTracker, create_local_share, get_expected_payouts
#include "../config_pool.hpp"
#include "../share_types.hpp"              // SegwitDataDefault
#include "../../coin/block.hpp"            // coin::BlockHeaderType
#include "../../coin/gentx_coinbase.hpp"   // assemble_gentx_coinbase (seed helper)

#include <core/uint256.hpp>
#include <core/pack.hpp>
#include <core/hash.hpp>
#include <core/target_utils.hpp>

#include <nlohmann/json.hpp>

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <optional>
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

// REAL BIP-110 block 961640 v2 header (same carrier the identity/extend/multiminer
// KATs grind against).
const char* HDR_961640 =
    "000000a0657e02138733654183a2c7320d85ca9d743fe139c4bb01000000000000000000"
    "c137a8515a0f6b3aaf6049cc7611787c022ad523d51094be0a0363d0dc0bc768"
    "4dca936a4f8d001a5671798c84daeb494dca936a00000000b1ccf00d030000000000000000"
    "0000001e0300000000000000000000000000000000000068ac0e0000000000000000000000"
    "00000000000000000000000000000000000000000000000000";

const uint32_t EASY_BITS = 0x207fffffu;   // ~2^255 share target
const uint64_t SUBSIDY    = 312500000ULL;

// Two DISTINCT 25-byte P2PKH payout scripts -> two miner entries in the decayed
// PPLNS window. A third (C) is the connecting miner of the final share.
std::vector<unsigned char> p2pkh(unsigned char fill)
{
    std::vector<unsigned char> s = { 0x76, 0xa9, 0x14 };
    for (int i = 0; i < 20; ++i) s.push_back(fill);
    s.push_back(0x88); s.push_back(0xac);
    return s;
}
const std::vector<unsigned char> PAYOUT_A = p2pkh(0xA1);
const std::vector<unsigned char> PAYOUT_B = p2pkh(0xB2);

using bip110::pool::ShareTracker;
using bip110::pool::RefHashParams;
using bip110::pool::PoolConfig;
using bip110::pool::SegwitDataDefault;

// Fill the deterministic chain-position fields off `prev` EXACTLY as main_bip110's
// ref_hash_fn does — copied from bip110_multiminer_pplns_kat (the seed machinery is
// not the SUT here, only current_payouts_report is).
RefHashParams frozen_params(ShareTracker& tracker,
                            const bip110::coin::BlockHeaderType& carrier,
                            const uint256& prev,
                            const std::vector<unsigned char>& payout_script)
{
    RefHashParams p;
    p.share_version   = 36;
    p.desired_version = 36;
    p.prev_share      = prev;
    p.coinbase_scriptSig = { 0x03, 0x29,0xab,0x0e, 0x00, 0x00, 0x2f, 0x62, 0x69,
                             0x70, 0x31, 0x31, 0x30, 0x2f, 0x00, 0x00, 0x00, 0x00 };
    p.share_nonce     = 0;
    p.subsidy         = SUBSIDY;
    p.donation        = 66;
    p.stale_info      = 0;
    std::memcpy(p.pubkey_hash.data(), payout_script.data() + 3, 20);
    p.pubkey_type = 0;
    p.has_segwit  = true;
    p.segwit_data = SegwitDataDefault::get();
    p.segwit_data.m_wtxid_merkle_root = uint256();  // ZERO
    p.timestamp   = carrier.m_timestamp;
    p.bits = EASY_BITS; p.max_bits = EASY_BITS;
    const uint32_t block_bits = carrier.m_bits;

    if (!prev.IsNull() && tracker.chain.contains(prev)) {
        uint128 prev_abswork; uint32_t prev_ts = 0; uint32_t prev_absheight = 0;
        tracker.chain.get(prev).share.invoke([&](auto* s) {
            prev_abswork = s->m_abswork; prev_ts = s->m_timestamp; prev_absheight = s->m_absheight;
        });
        p.absheight = prev_absheight + 1;
        if (p.timestamp <= prev_ts) p.timestamp = prev_ts + 1;
        auto [prev_height, _last] = tracker.chain.get_height_and_last(prev);
        p.far_share_hash = (prev_height >= 99)
            ? tracker.chain.get_nth_parent_key(prev, 99) : uint256::ZERO;
        auto attempts = chain::target_to_average_attempts(chain::bits_to_target(EASY_BITS));
        p.abswork = uint128((prev_abswork + uint128(attempts.GetLow64())).GetLow64());
        try {
            p.merged_payout_hash = tracker.compute_merged_payout_hash(prev, chain::bits_to_target(block_bits));
        } catch (const std::exception&) { p.merged_payout_hash = uint256(); }
    } else {
        p.absheight      = 1;
        p.far_share_hash = uint256::ZERO;
        p.abswork        = uint128(1234);
        p.merged_payout_hash = uint256();
    }
    return p;
}

// Mint a SEED share off `prev` with `payout_script` (non-PPLNS placeholder coinbase;
// create_local_share's PPLNS cross-check is non-blocking, so the share still lands).
uint256 seed_share(ShareTracker& tracker, const bip110::coin::BlockHeaderType& carrier,
                   const uint256& prev, const std::vector<unsigned char>& payout_script)
{
    using namespace bip110::pool;
    RefHashParams p = frozen_params(tracker, carrier, prev, payout_script);
    auto [ref, nonce] = compute_ref_hash_for_work(p);

    std::vector<unsigned char> op_return = {0x6a, 0x28};
    op_return.insert(op_return.end(), ref.data(), ref.data() + 32);
    { const auto* np = reinterpret_cast<const unsigned char*>(&nonce);
      op_return.insert(op_return.end(), np, np + 8); }
    std::vector<std::pair<std::vector<unsigned char>, uint64_t>> payouts = { { payout_script, SUBSIDY } };
    auto cb = bip110::coin::assemble_gentx_coinbase(
        p.coinbase_scriptSig, std::nullopt, payouts, 0,
        PoolConfig::get_donation_script(36), op_return);

    BaseScript coinbase_bs; coinbase_bs.m_data = p.coinbase_scriptSig;
    bip110::coin::BlockHeaderType full = carrier;
    for (uint32_t g = 0; g < 400000; ++g) {
        full.m_nonce = g;
        uint256 h;
        try {
            h = create_local_share(
                tracker, full, coinbase_bs, SUBSIDY, prev,
                std::vector<uint256>{}, payout_script, 66, {},
                StaleInfo::none, true, std::string{}, {}, cb.bytes, uint256(),
                EASY_BITS, EASY_BITS,
                p.absheight, p.abswork, p.far_share_hash, p.timestamp, p.merged_payout_hash,
                true, std::vector<uint256>{}, uint256(), std::vector<unsigned char>{}, 36, 36);
        } catch (const std::exception&) { return uint256(); }
        if (!h.IsNull()) return h;
    }
    return uint256();
}

} // namespace

int main()
{
    using namespace bip110::pool;
    namespace coin = bip110::coin;

    std::printf("bip110_current_payouts_kat: /current_payouts dashboard-seam projected PPLNS split\n");

    ShareTracker tracker;
    std::vector<unsigned char> hdr_bytes = from_hex(HDR_961640);
    coin::BlockHeaderType carrier;
    { PackStream ps(hdr_bytes); ps >> carrier; }

    const uint256 block_target = chain::bits_to_target(carrier.m_bits);
    const std::vector<unsigned char> donation_script = PoolConfig::get_donation_script(36);

    // ── [4] EMPTY chain FIRST — null best share -> {} (honest empty, never faked) ──
    {
        nlohmann::json empty = current_payouts_report(
            tracker, /*best=*/uint256(), block_target, SUBSIDY, donation_script,
            PoolConfig::is_testnet);
        expect_true("[4] empty chain (null best) -> {} object", empty.is_object() && empty.empty());
    }

    // ── [1] seed a real 2-share window: miner A genesis <- miner B (tip) ──────────
    uint256 shareA = seed_share(tracker, carrier, uint256(), PAYOUT_A);
    expect_true("[1] genesis share A minted + tracked", !shareA.IsNull() && tracker.chain.contains(shareA));
    if (shareA.IsNull()) { std::printf("RESULT: FAIL — could not seed A.\n"); return 1; }
    uint256 tip = seed_share(tracker, carrier, shareA, PAYOUT_B);
    expect_true("[1] extend share B (tip) minted + tracked", !tip.IsNull() && tracker.chain.contains(tip));
    if (tip.IsNull()) { std::printf("RESULT: FAIL — could not seed tip.\n"); return 1; }

    // ── [2]+[3] the SUT: current_payouts_report over the live window ──────────────
    nlohmann::json payouts = current_payouts_report(
        tracker, tip, block_target, SUBSIDY, donation_script, PoolConfig::is_testnet);

    expect_true("[2] current_payouts_report returned a non-empty object", payouts.is_object() && !payouts.empty());
    expect_true("[2] >= 3 rows (2 miner addresses + donation address)", payouts.size() >= 3);

    // Every row is a positive coins value keyed by a resolved address string.
    bool all_positive = true, all_addr_keys = true;
    for (auto it = payouts.begin(); it != payouts.end(); ++it) {
        if (!it.value().is_number() || it.value().get<double>() <= 0.0) all_positive = false;
        if (it.key().empty()) all_addr_keys = false;
    }
    expect_true("[2] all rows have a non-empty address key", all_addr_keys);
    expect_true("[2] all rows carry a positive coins amount", all_positive);

    // [3] the reported coins sum EXACTLY to the payable coinbase (subsidy, no fees).
    // Values are coins == sat/1e8; get_expected_payouts amounts are integer sat, so
    // llround(coins * 1e8) recovers the exact sat with no float drift, and the seam
    // folds the donation residual so the total == subsidy to the satoshi.
    uint64_t total_sat = 0;
    for (auto it = payouts.begin(); it != payouts.end(); ++it)
        total_sat += static_cast<uint64_t>(std::llround(it.value().get<double>() * 1e8));
    std::printf("  [info] rows=%zu total_sat=%llu subsidy=%llu\n",
                payouts.size(), (unsigned long long)total_sat, (unsigned long long)SUBSIDY);
    expect_true("[3] sum(miners + donation) == payable coinbase (subsidy)", total_sat == SUBSIDY);

    // ── [5] null best on a POPULATED tracker -> {} (main's pre-guard behaviour) ───
    {
        nlohmann::json nullbest = current_payouts_report(
            tracker, /*best=*/uint256(), block_target, SUBSIDY, donation_script,
            PoolConfig::is_testnet);
        expect_true("[5] null best on populated tracker -> {}", nullbest.is_object() && nullbest.empty());
    }

    if (g_fail == 0) { std::printf("RESULT: PASS — /current_payouts seam lights the card.\n"); return 0; }
    std::printf("RESULT: FAIL — %d check(s) failed.\n", g_fail);
    return 1;
}
