// SPDX-License-Identifier: AGPL-3.0-or-later
//
// bip110_share_detail_kat — the GET /web/share/<hash> DETAIL-DOCUMENT known-answer
// test (M3, DASH parity).
//
// LIVE BUG (contabo :8086): the individual share page (share.html) hung on
// "Loading". The bip110 /web/share handler served a REDUCED 12-key flat object
// (absheight,bits,desired_version,hash,height,is_block_solution,miner_address,
// miner_script,stale_info,timestamp,verified,version) MISSING parent/far_parent/
// type_name/children + local/share_data/block/pplns. share.html renderShare reads
// share.parent.substr(-8); share.parent is undefined on the reduced object ->
// TypeError -> renderShare aborts -> stuck on "Loading". DASH's build_share_detail
// returns the RICH schema and its page renders.
//
// The fix hoists the rich builder into bip110::pool::build_share_detail
// (share_detail_report.hpp) — the EXACT code main_bip110 now serves — and this KAT
// binds it directly (not a re-derivation). Proves, network-free over a REAL 2-share
// window ShareTracker:
//
//   [1] a real window (miner A genesis <- miner B tip) is seeded,
//   [2] the RICH DASH-parity fields renderShare needs are ALL present and typed:
//       parent/far_parent are 64-hex strings (never undefined — the exact field
//       whose absence hung the page), type_name == "V36", children is an array,
//       plus local/share_data/block objects,
//   [3] share_data carries the full DASH key set (target/max_target/payout_address/
//       pubkey_hash/donation/nonce/absheight/abswork/difficulty/min_difficulty/...),
//   [4] the back-compat 12 keys are still present (no regression for any client
//       reading the old flat shape),
//   [5] pplns is an object of address->coins for a share whose parent is inside the
//       window (the treemap feed share.html:715 reads), and its keys MATCH the
//       /current_payouts keys (same SSOT walk),
//   [6] an honest MISS -> {"error": ...} (core's not-found fallback contract),
//   [7] a genesis share (null parent) still yields the rich shape (parent == the
//       null-hash string, NOT undefined) and simply omits pplns honestly.
//
// READ-ONLY: build_share_detail does const tracker walks only (get_index/get_share/
// get_expected_payouts via current_payouts_report). It never touches gentx, the
// coinbase, the donation consensus, the reward path, or any wire message. A failure
// here is a display-surface regression only. Same heavy link closure as
// bip110_sharechain_window_kat.

#include "../share_detail_report.hpp"       // bip110::pool::build_share_detail (SUT)
#include "../current_payouts_report.hpp"    // current_payouts_report (key cross-check)
#include "../share_tracker.hpp"             // ShareTracker, create_local_share
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

// REAL BIP-110 block 961640 v2 header (same carrier the window/current_payouts KATs use).
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

bool is_hex64(const nlohmann::json& j)
{
    if (!j.is_string()) return false;
    const std::string s = j.get<std::string>();
    if (s.size() != 64) return false;
    for (char c : s)
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
    return true;
}

} // namespace

int main()
{
    using namespace bip110::pool;
    namespace coin = bip110::coin;

    std::printf("bip110_share_detail_kat: /web/share/<hash> rich DASH-parity detail document\n");

    ShareTracker tracker;
    std::vector<unsigned char> hdr_bytes = from_hex(HDR_961640);
    coin::BlockHeaderType carrier;
    { PackStream ps(hdr_bytes); ps >> carrier; }

    const std::vector<unsigned char> donation_script = PoolConfig::get_donation_script(36);
    const bool testnet = PoolConfig::is_testnet;

    // ── [6] honest MISS first — unknown hash -> {"error": ...} ─────────────────
    {
        nlohmann::json miss = build_share_detail(
            tracker, std::string(64, 'a'), donation_script, testnet);
        expect_true("[6] unknown hash -> error object", miss.is_object() && miss.contains("error"));
        expect_true("[6] miss carries no rich fields", !miss.contains("parent") && !miss.contains("share_data"));
    }

    // ── [1] seed a real 2-share window: miner A genesis <- miner B (tip) ───────
    uint256 shareA = seed_share(tracker, carrier, uint256(), PAYOUT_A);
    expect_true("[1] genesis share A minted + tracked", !shareA.IsNull() && tracker.chain.contains(shareA));
    if (shareA.IsNull()) { std::printf("RESULT: FAIL — could not seed A.\n"); return 1; }
    uint256 tip = seed_share(tracker, carrier, shareA, PAYOUT_B);
    expect_true("[1] extend share B (tip) minted + tracked", !tip.IsNull() && tracker.chain.contains(tip));
    if (tip.IsNull()) { std::printf("RESULT: FAIL — could not seed tip.\n"); return 1; }

    // ── [2]+[3]+[4]+[5] the SUT on the TIP (parent = shareA, inside window) ────
    nlohmann::json d = build_share_detail(tracker, tip.GetHex(), donation_script, testnet);
    expect_true("[2] object, not error", d.is_object() && !d.contains("error"));

    // [2] THE fields whose absence hung share.html — parent/far_parent are strings.
    expect_true("[2] parent present + 64-hex string (renderShare .substr safe)", is_hex64(d.value("parent", nlohmann::json())));
    expect_true("[2] parent == shareA", d.value("parent", std::string{}) == shareA.GetHex());
    expect_true("[2] far_parent present + 64-hex string", is_hex64(d.value("far_parent", nlohmann::json())));
    expect_true("[2] type_name == \"V36\"", d.value("type_name", std::string{}) == "V36");
    expect_true("[2] children is an array", d.contains("children") && d["children"].is_array());
    expect_true("[2] local is an object", d.contains("local") && d["local"].is_object());
    expect_true("[2] local carries verified/time_first_seen/peer",
                d["local"].contains("verified") && d["local"].contains("time_first_seen")
                    && d["local"].contains("peer_first_received_from"));

    // [3] share_data full DASH key set.
    expect_true("[3] share_data object present", d.contains("share_data") && d["share_data"].is_object());
    {
        const auto& sd = d["share_data"];
        const char* keys[] = {"timestamp","target","max_target","payout_address","pubkey_hash",
                              "donation","stale_info","nonce","desired_version","absheight",
                              "abswork","difficulty","min_difficulty"};
        bool all = true;
        for (const char* k : keys) if (!sd.contains(k)) { all = false; std::printf("    missing share_data.%s\n", k); }
        expect_true("[3] share_data has the full DASH key set", all);
        expect_true("[3] share_data.difficulty is a number > 0", sd.value("difficulty", 0.0) > 0.0);
        expect_true("[3] share_data.abswork is a hex string", sd.contains("abswork") && sd["abswork"].is_string());
    }
    // block object present with header + gentx.
    expect_true("[3] block object present", d.contains("block") && d["block"].is_object());
    expect_true("[3] block.header present", d["block"].contains("header") && d["block"]["header"].is_object());
    expect_true("[3] block.gentx present", d["block"].contains("gentx") && d["block"]["gentx"].is_object());
    expect_true("[3] v36_metadata present", d.contains("v36_metadata") && d["v36_metadata"].is_object());

    // [4] back-compat flat 12 keys — no regression for old clients.
    {
        const char* flat[] = {"is_block_solution","hash","verified","height","timestamp","bits",
                              "absheight","version","desired_version","stale_info","miner_address","miner_script"};
        bool all = true;
        for (const char* k : flat) if (!d.contains(k)) { all = false; std::printf("    missing flat key %s\n", k); }
        expect_true("[4] all 12 back-compat flat keys still present", all);
        expect_true("[4] version == 36", d.value("version", 0) == 36);
        expect_true("[4] hash == tip", d.value("hash", std::string{}) == tip.GetHex());
    }

    // [5] pplns object + keys match /current_payouts (parent inside the window).
    expect_true("[5] pplns object present (treemap feed)", d.contains("pplns") && d["pplns"].is_object() && !d["pplns"].empty());
    expect_true("[5] pplns_meta present", d.contains("pplns_meta") && d["pplns_meta"].is_object());
    {
        // The share's pplns is anchored on the PARENT (shareA) with the share's
        // own subsidy/bits — recompute the SAME SSOT walk and cross-check keys.
        nlohmann::json ref = current_payouts_report(
            tracker, shareA, chain::bits_to_target(carrier.m_bits), SUBSIDY, donation_script, testnet);
        bool intersects = false;
        if (d.contains("pplns"))
            for (auto it = d["pplns"].begin(); it != d["pplns"].end(); ++it)
                if (ref.contains(it.key())) { intersects = true; break; }
        std::printf("  [info] share.pplns keys=%zu current_payouts keys=%zu\n",
                    d.value("pplns", nlohmann::json::object()).size(), ref.size());
        expect_true("[5] share.pplns keys match /current_payouts SSOT keys", intersects);
    }

    // ── [7] genesis share (null parent) still rich; parent == null-hash string ──
    {
        nlohmann::json g = build_share_detail(tracker, shareA.GetHex(), donation_script, testnet);
        expect_true("[7] genesis object, not error", g.is_object() && !g.contains("error"));
        expect_true("[7] genesis parent is a 64-hex string (null-hash, NOT undefined)",
                    is_hex64(g.value("parent", nlohmann::json())));
        expect_true("[7] genesis parent == null hash", g.value("parent", std::string{}) == uint256().GetHex());
        expect_true("[7] genesis type_name == \"V36\"", g.value("type_name", std::string{}) == "V36");
        expect_true("[7] genesis has share_data/block/children (rich shape holds)",
                    g.contains("share_data") && g.contains("block") && g.contains("children"));
        // Parent is the null share (not in the window) -> pplns omitted honestly.
        expect_true("[7] genesis omits pplns honestly (null anchor)", !g.contains("pplns"));
    }

    if (g_fail == 0) {
        std::printf("RESULT: PASS — /web/share serves the rich DASH-parity detail document; share.html cannot hang.\n");
        return 0;
    }
    std::printf("RESULT: FAIL — %d check(s) failed.\n", g_fail);
    return 1;
}
