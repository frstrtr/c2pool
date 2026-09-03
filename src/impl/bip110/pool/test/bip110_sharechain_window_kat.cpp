// SPDX-License-Identifier: AGPL-3.0-or-later
//
// bip110_sharechain_window_kat — the /sharechain/window DASHBOARD-SEAM known-answer test.
//
// LIVE BUG (contabo): with a live sharechain (197+ shares, legion64 mining) the
// sharechain-transparency EXPLORER was empty and the "Current Payouts" card's V36?
// column stayed blank. Root cause: MiningInterface::m_sharechain_window_fn was
// UNWIRED on the bip110 lane, so GET /sharechain/window served the stub {shares:[]}
// (web_server.cpp rest_sharechain_window). The V36? column is filled ENTIRELY
// client-side by getMinerVersion(addr) scanning defrag.shares (= this window) for
// s.m === addr — an empty window blanks it.
//
// The fix wires the seam (main_bip110.cpp mi->set_sharechain_window_fn) via
// bip110::pool::sharechain_window_report, which walks the SAME tallest-chain PPLNS
// window ShareTracker feeds the coinbase + /current_payouts from. THIS KAT drives
// that EXACT reporting transform (not a re-implementation) and proves:
//
//   [1] a real 2-share window (miner A genesis <- miner B) is seeded,
//   [2] the report returns shares.size()==2 / total==2, best_hash set, window_size set,
//   [3] every share row carries h/H/V/m/dv and V == 36 (native share version — the
//       feed the V36? column tallies; BTC omits it),
//   [4] s.m is the ADDRESS form and MATCHES the /current_payouts keys (so the
//       client-side getMinerVersion s.m === addr join lights the column),
//   [5] an EMPTY chain (null best share) yields shares == [] — honest empty, never faked.
//
// READ-ONLY: sharechain_window_report never touches gentx/coinbase/consensus/reward —
// it is a const window walk. Same heavy link closure as bip110_current_payouts_kat.

#include "../sharechain_window_report.hpp"  // bip110::pool::sharechain_window_report (SUT)
#include "../current_payouts_report.hpp"    // current_payouts_report (address-key cross-check)
#include "../share_tracker.hpp"             // ShareTracker, create_local_share, get_expected_payouts
#include "../config_pool.hpp"
#include "../share_types.hpp"               // SegwitDataDefault
#include "../../coin/block.hpp"             // coin::BlockHeaderType
#include "../../coin/gentx_coinbase.hpp"    // assemble_gentx_coinbase (seed helper)

#include <core/uint256.hpp>
#include <core/pack.hpp>
#include <core/hash.hpp>
#include <core/target_utils.hpp>

#include <nlohmann/json.hpp>

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <optional>
#include <set>
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

// REAL BIP-110 block 961640 v2 header (same carrier the current_payouts/multiminer KATs use).
const char* HDR_961640 =
    "000000a0657e02138733654183a2c7320d85ca9d743fe139c4bb01000000000000000000"
    "c137a8515a0f6b3aaf6049cc7611787c022ad523d51094be0a0363d0dc0bc768"
    "4dca936a4f8d001a5671798c84daeb494dca936a00000000b1ccf00d030000000000000000"
    "0000001e0300000000000000000000000000000000000068ac0e0000000000000000000000"
    "00000000000000000000000000000000000000000000000000";

const uint32_t EASY_BITS = 0x207fffffu;   // ~2^255 share target
const uint64_t SUBSIDY    = 312500000ULL;

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

    std::printf("bip110_sharechain_window_kat: /sharechain/window explorer + V36? column feed\n");

    ShareTracker tracker;
    std::vector<unsigned char> hdr_bytes = from_hex(HDR_961640);
    coin::BlockHeaderType carrier;
    { PackStream ps(hdr_bytes); ps >> carrier; }

    const uint32_t WIN = PoolConfig::chain_length();

    // ── [5] EMPTY chain FIRST — null best -> shares == [] (honest empty, never faked) ──
    {
        nlohmann::json w = sharechain_window_report(
            tracker, /*best=*/uint256(), WIN, /*my_address=*/"", /*fee_hash160=*/"",
            PoolConfig::is_testnet);
        expect_true("[5] empty chain: object with shares[]",
                    w.is_object() && w.contains("shares") && w["shares"].is_array());
        expect_true("[5] empty chain: shares empty", w["shares"].empty());
        expect_true("[5] empty chain: total == 0", w.value("total", -1) == 0);
        expect_true("[5] empty chain: best_hash == \"\"", w.value("best_hash", "X") == "");
    }

    // ── [1] seed a real 2-share window: miner A genesis <- miner B (tip) ──────────
    uint256 shareA = seed_share(tracker, carrier, uint256(), PAYOUT_A);
    expect_true("[1] genesis share A minted + tracked", !shareA.IsNull() && tracker.chain.contains(shareA));
    if (shareA.IsNull()) { std::printf("RESULT: FAIL — could not seed A.\n"); return 1; }
    uint256 tip = seed_share(tracker, carrier, shareA, PAYOUT_B);
    expect_true("[1] extend share B (tip) minted + tracked", !tip.IsNull() && tracker.chain.contains(tip));
    if (tip.IsNull()) { std::printf("RESULT: FAIL — could not seed tip.\n"); return 1; }

    // ── [2]+[3]+[4] the SUT: sharechain_window_report over the live window ─────────
    nlohmann::json w = sharechain_window_report(
        tracker, tip, WIN, /*my_address=*/"", /*fee_hash160=*/"", PoolConfig::is_testnet);

    expect_true("[2] object with shares array", w.is_object() && w.contains("shares") && w["shares"].is_array());
    expect_true("[2] shares.size() == 2", w["shares"].size() == 2);
    expect_true("[2] total == 2", w.value("total", -1) == 2);
    expect_true("[2] best_hash == tip", w.value("best_hash", std::string{}) == tip.GetHex());
    expect_true("[2] window_size reported", w.value("window_size", 0) == static_cast<int>(WIN));

    // [3] every row carries the fields the explorer + V36? column read, and V == 36.
    bool all_fields = true, all_v36 = true, all_addr = true;
    std::set<std::string> window_addrs;
    for (const auto& s : w["shares"]) {
        if (!(s.contains("h") && s.contains("H") && s.contains("m")
              && s.contains("V") && s.contains("dv") && s.contains("t")))
            all_fields = false;
        if (s.value("V", 0) != 36) all_v36 = false;
        std::string m = s.value("m", std::string{});
        if (m.empty()) all_addr = false; else window_addrs.insert(m);
    }
    expect_true("[3] every row has h/H/m/V/dv/t", all_fields);
    expect_true("[3] every row V == 36 (native share version feed)", all_v36);
    expect_true("[3] every row s.m non-empty (address marker)", all_addr);

    // [4] s.m addresses MATCH the /current_payouts keys — the client-side
    // getMinerVersion(addr) join (s.m === addr) that lights the V36? column.
    const std::vector<unsigned char> donation_script = PoolConfig::get_donation_script(36);
    const uint256 block_target = chain::bits_to_target(carrier.m_bits);
    nlohmann::json pays = current_payouts_report(
        tracker, tip, block_target, SUBSIDY, donation_script, PoolConfig::is_testnet);
    bool intersects = false;
    for (const auto& a : window_addrs)
        if (pays.contains(a)) { intersects = true; break; }
    std::printf("  [info] window_addrs=%zu payout_keys=%zu\n", window_addrs.size(), pays.size());
    expect_true("[4] window s.m addresses match /current_payouts keys (V36? join)", intersects);

    if (g_fail == 0) { std::printf("RESULT: PASS — /sharechain/window seam lights the explorer + V36? column.\n"); return 0; }
    std::printf("RESULT: FAIL — %d check(s) failed.\n", g_fail);
    return 1;
}
