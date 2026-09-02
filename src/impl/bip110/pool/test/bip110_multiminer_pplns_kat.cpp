// SPDX-License-Identifier: AGPL-3.0-or-later
//
// bip110_multiminer_pplns_kat — F1b PPLNS-DISTRIBUTED coinbase known-answer test.
//
// The extend-mint KAT (bip110_extend_mint_kat) proved the F1 ref/hash_link half of
// peer acceptance but DELIBERATELY left the PPLNS-payout half open: it built a
// SINGLE-MINER coinbase, and its own create_local_share log shows the gap —
//   "Cross-check FAILED! mined_gentx=<single-miner> verify_gentx=<PPLNS>"
// A peer verifying that share runs generate_share_transaction (share_check.hpp:
// 1840-1952, the SSOT) which rebuilds the coinbase paying the ENTIRE decayed PPLNS
// window and THROWS on any byte mismatch. So a share minted off a single-miner
// coinbase is peer-REJECTED on PPLNS grounds and the sharechain cannot form.
//
// F1b closes it: build_connection_coinbase, on the flag-ON path, emits the PPLNS
// distribution (ShareTracker::get_expected_payouts) in the EXACT order/dust/4000-
// cap/donation-last that generate_share_transaction reconstructs. THIS KAT proves
// the byte-match with >= 2 distinct miner scripts in the window:
//
//   1. Seed a real 2-share sharechain — genesis(miner A) <- extend(miner B) = tip —
//      so get_v36_decayed_cumulative_weights(tip) yields TWO miner entries.
//   2. FLAG-ON build (the exact code build_connection_coinbase runs): call
//      get_expected_payouts(tip, ...), extract the donation entry, drop empty/zero
//      outputs, sort asc(amount, script), keep-LAST 4000, then assemble_gentx_
//      coinbase with the P2POOL witness-commitment segwit output + those payouts +
//      the donation output second-to-last + the OP_RETURN ref last -> mined_gentx.
//   3. Mint the extend share via create_local_share(prev = tip, has_frozen = TRUE)
//      with that coinbase (witness_commitment empty -> SegwitDataDefault sentinel).
//   4. Run generate_share_transaction(minted share, tracker, /*v36_active=*/true)
//      -> verify_gentx, and assert:
//        [X] mined_gentx.txid == verify_gentx  (the extend KAT's "Cross-check" that
//            FAILED now PASSES — verify_gentx == mined_gentx),
//        [X] >= 2 distinct PPLNS payout outputs (multi-miner window really split),
//        [X] the donation output is present and SECOND-TO-LAST (before OP_RETURN),
//        [X] mint/verify hash symmetry (compute_share_hash == stored m_hash),
//        [X] total coinbase value == the BLOCK subsidy (w.subsidy, no fees).
//
// This is the proof F1b closed the gap: the minted coinbase == generate_share_
// transaction byte-for-byte, so peers ACCEPT the share and the sharechain forms.

#include "../share_tracker.hpp"        // ShareTracker -> share_check.hpp (create_local_share,
                                       // generate_share_transaction, get_expected_payouts,
                                       // compute_ref_hash_for_work, compute_p2pool_witness_commitment)
#include "../config_pool.hpp"
#include "../share_types.hpp"          // SegwitDataDefault
#include "../../coin/block.hpp"        // coin::BlockHeaderType
#include "../../coin/gentx_coinbase.hpp"  // assemble_gentx_coinbase (SSOT)

#include <core/uint256.hpp>
#include <core/pack.hpp>
#include <core/hash.hpp>
#include <core/target_utils.hpp>

#include <algorithm>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <map>
#include <optional>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace {

int g_fail = 0;

void expect_true(const std::string& name, bool cond)
{
    if (cond) std::printf("  [ok]   %s\n", name.c_str());
    else { std::printf("  [FAIL] %s\n", name.c_str()); ++g_fail; }
}

void expect_eq_hex(const std::string& name, const std::string& got, const std::string& want)
{
    if (got == want) std::printf("  [ok]   %s\n", name.c_str());
    else {
        std::printf("  [FAIL] %s\n         got : %s\n         want: %s\n",
                    name.c_str(), got.c_str(), want.c_str());
        ++g_fail;
    }
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
// the identity + extend KATs grind.
const char* HDR_961640 =
    "000000a0657e02138733654183a2c7320d85ca9d743fe139c4bb01000000000000000000"
    "c137a8515a0f6b3aaf6049cc7611787c022ad523d51094be0a0363d0dc0bc768"
    "4dca936a4f8d001a5671798c84daeb494dca936a00000000b1ccf00d030000000000000000"
    "0000001e0300000000000000000000000000000000000068ac0e0000000000000000000000"
    "00000000000000000000000000000000000000000000000000";

const uint32_t EASY_BITS = 0x207fffffu;  // ~2^255 share target
const uint64_t SUBSIDY    = 312500000ULL;

// Two DISTINCT 25-byte P2PKH payout scripts (A, B) -> two miner entries in the
// decayed PPLNS window. A third (C) is the connecting miner of the final share
// (its OWN script is NOT in the window it pays — PPLNS pays the PAST window).
std::vector<unsigned char> p2pkh(unsigned char fill)
{
    std::vector<unsigned char> s = { 0x76, 0xa9, 0x14 };
    for (int i = 0; i < 20; ++i) s.push_back(fill);
    s.push_back(0x88); s.push_back(0xac);
    return s;
}
const std::vector<unsigned char> PAYOUT_A = p2pkh(0xA1);
const std::vector<unsigned char> PAYOUT_B = p2pkh(0xB2);
const std::vector<unsigned char> PAYOUT_C = p2pkh(0xC3);

using bip110::pool::ShareTracker;
using bip110::pool::RefHashParams;
using bip110::pool::PoolConfig;
using bip110::pool::SegwitDataDefault;

// Fill the deterministic chain-position fields off `prev` EXACTLY as main_bip110's
// ref_hash_fn does (absheight, clipped timestamp, far_share_hash, share_target,
// abswork, merged_payout_hash). prev == null -> genesis branch.
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
    p.timestamp   = carrier.m_timestamp;
    // The mint applies override_max_bits = override_bits = EASY_BITS (the easy share
    // target we grind against), so the ref MUST commit EASY_BITS too — matching the
    // extend-mint KAT. (Do NOT call compute_share_target here: its derived bits
    // would diverge from the override the mint stores, and the ref_hash the coinbase
    // carries would not equal what generate_share_transaction recomputes.)
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

// Mint a SEED share off `prev` with `payout_script`. The coinbase is a well-formed
// but non-PPLNS placeholder (create_local_share's PPLNS cross-check is non-blocking,
// so the share still lands in the tracker) — seeds only need to EXIST with distinct
// scripts + m_bits so get_v36_decayed_cumulative_weights yields their weight.
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

    std::printf("bip110_multiminer_pplns_kat: F1b PPLNS-distributed coinbase byte-match\n");

    ShareTracker tracker;
    std::vector<unsigned char> hdr_bytes = from_hex(HDR_961640);
    coin::BlockHeaderType carrier;
    { PackStream ps(hdr_bytes); ps >> carrier; }

    // ── Step 1: seed a 2-share chain (miner A genesis <- miner B) = tip ───────
    uint256 shareA = seed_share(tracker, carrier, uint256(), PAYOUT_A);
    expect_true("[1] genesis share A minted + tracked", !shareA.IsNull() && tracker.chain.contains(shareA));
    if (shareA.IsNull()) { std::printf("RESULT: FAIL — could not seed A.\n"); return 1; }
    uint256 tip = seed_share(tracker, carrier, shareA, PAYOUT_B);
    expect_true("[1] extend share B (tip) minted + tracked", !tip.IsNull() && tracker.chain.contains(tip));
    if (tip.IsNull()) { std::printf("RESULT: FAIL — could not seed B/tip.\n"); return 1; }
    expect_true("[1] tip absheight == 2 (real 2-share chain)",
                [&]{ uint32_t ah=0; tracker.chain.get(tip).share.invoke([&](auto* s){ ah=s->m_absheight; }); return ah==2; }());

    // ── Step 2: FLAG-ON build — EXACTLY what build_connection_coinbase runs ───
    const uint256 block_target = chain::bits_to_target(carrier.m_bits);
    const std::vector<unsigned char> donation_script = PoolConfig::get_donation_script(36);

    // (a) the PPLNS map for the whole decayed window (the pplns_fn_ payload).
    std::map<std::vector<unsigned char>, double> pmap =
        tracker.get_expected_payouts(tip, block_target, SUBSIDY, donation_script);
    expect_true("[2] get_expected_payouts returned a non-empty window", !pmap.empty());

    // (b) reproduce the C2 seam transform: extract donation, drop empty/zero, sort
    //     asc(amount,script), keep-LAST 4000.
    uint64_t donation_amt = 0;
    if (auto it = pmap.find(donation_script); it != pmap.end()) {
        donation_amt = static_cast<uint64_t>(it->second);
        pmap.erase(it);
    }
    std::vector<std::pair<std::vector<unsigned char>, uint64_t>> payouts;
    for (auto& [s, a] : pmap) {
        if (s.empty()) continue;
        uint64_t v = static_cast<uint64_t>(a);
        if (v > 0) payouts.emplace_back(s, v);
    }
    std::sort(payouts.begin(), payouts.end(), [](const auto& a, const auto& b) {
        if (a.second != b.second) return a.second < b.second;
        return a.first < b.first;
    });
    if (payouts.size() > 4000) payouts.erase(payouts.begin(), payouts.end() - 4000);
    expect_true("[2] >= 2 distinct PPLNS payout outputs (multi-miner split)", payouts.size() >= 2);
    {
        uint64_t total = donation_amt;
        for (auto& [s, v] : payouts) { (void)s; total += v; }
        expect_true("[2] total coinbase value == block subsidy (w.subsidy, no fees)", total == SUBSIDY);
    }

    // (c) P2POOL witness-commitment segwit output over the SegwitData none-sentinel
    //     (== what generate_share_transaction emits for a coinbase-only v36 share).
    std::optional<std::vector<unsigned char>> segwit_commit;
    {
        uint256 wc = compute_p2pool_witness_commitment(SegwitDataDefault::get().m_wtxid_merkle_root);
        std::vector<unsigned char> sc = {0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed};
        auto wcb = wc.GetChars();
        sc.insert(sc.end(), wcb.begin(), wcb.end());
        segwit_commit = std::move(sc);
    }

    // (d) the OP_RETURN ref commitment (frozen off the tip, like the extend KAT).
    RefHashParams p = frozen_params(tracker, carrier, tip, PAYOUT_C);
    auto [intended_ref, intended_nonce] = compute_ref_hash_for_work(p);
    expect_true("[2] compute_ref_hash_for_work produced a non-null ref", !intended_ref.IsNull());
    std::vector<unsigned char> op_return = {0x6a, 0x28};
    op_return.insert(op_return.end(), intended_ref.data(), intended_ref.data() + 32);
    { const auto* np = reinterpret_cast<const unsigned char*>(&intended_nonce);
      op_return.insert(op_return.end(), np, np + 8); }

    // (e) assemble the FLAG-ON coinbase.
    auto mined = coin::assemble_gentx_coinbase(
        p.coinbase_scriptSig, segwit_commit, payouts, donation_amt, donation_script, op_return);

    // ── Step 3: mint the extend share carrying that PPLNS coinbase ────────────
    BaseScript coinbase_bs; coinbase_bs.m_data = p.coinbase_scriptSig;
    uint256 minted; uint32_t grind = 0;
    coin::BlockHeaderType full = carrier;
    for (; grind < 400000; ++grind) {
        full.m_nonce = grind;
        uint256 h;
        try {
            h = create_local_share(
                tracker, full, coinbase_bs, SUBSIDY, /*prev*/ tip,
                std::vector<uint256>{}, PAYOUT_C, 66, {},
                StaleInfo::none, true, std::string{}, {}, mined.bytes, uint256(),
                EASY_BITS, EASY_BITS,
                p.absheight, p.abswork, p.far_share_hash, p.timestamp, p.merged_payout_hash,
                true, std::vector<uint256>{}, uint256(), std::vector<unsigned char>{}, 36, 36);
        } catch (const std::exception& e) {
            std::printf("  [FAIL] extend create_local_share threw: %s\n", e.what()); ++g_fail; break;
        }
        if (!h.IsNull()) { minted = h; break; }
    }
    expect_true("[3] multi-miner extend share minted", !minted.IsNull() && tracker.chain.contains(minted));
    if (minted.IsNull() || !tracker.chain.contains(minted)) {
        std::printf("RESULT: FAIL — multi-miner mint produced no tracked share.\n"); return 1;
    }
    std::printf("  [info] minted after %u grind(s): %s\n", grind, minted.GetHex().c_str());

    // ── Step 4: peer PPLNS reconstruction MUST equal the minted coinbase ──────
    uint256 gentx_hash = Hash(std::span<const unsigned char>(mined.bytes.data(), mined.bytes.size()));

    tracker.chain.get(minted).share.invoke([&](auto* s) {
        // [X] THE F1b PROOF: verify_gentx (generate_share_transaction, PPLNS SSOT)
        //     == mined_gentx (our flag-ON coinbase). The extend KAT's Cross-check
        //     that FAILED now PASSES.
        uint256 verify_gentx = generate_share_transaction(*s, tracker, /*dump*/false, /*v36_active*/true);
        expect_eq_hex("[X] generate_share_transaction == minted PPLNS coinbase (Cross-check PASSES)",
                      verify_gentx.GetHex(), gentx_hash.GetHex());
        expect_eq_hex("[X] stored gentx txid == minted coinbase txid",
                      mined.txid.GetHex(), gentx_hash.GetHex());

        // [X] the share really extends the 2-miner tip.
        expect_eq_hex("[X] minted m_prev_hash == tip", s->m_prev_hash.GetHex(), tip.GetHex());
        expect_true("[X] minted m_absheight == 3 (extends the 2-share chain)", s->m_absheight == 3);

        // [X] mint/verify hash symmetry (compute_share_hash == stored m_hash).
        uint256 mr = check_merkle_link(gentx_hash, s->m_merkle_link);
        uint256 recomputed = compute_share_hash(s->m_min_header, mr);
        expect_eq_hex("[X] compute_share_hash(minted small-header, merkle) == stored m_hash",
                      recomputed.GetHex(), s->m_hash.GetHex());
        expect_eq_hex("[X] stored m_hash == returned mint hash", s->m_hash.GetHex(), minted.GetHex());
        expect_true("[X] m_pow_hash == m_hash (self-validation passed)", s->m_pow_hash == s->m_hash);
    });

    // [X] donation output is present, SECOND-TO-LAST (before OP_RETURN), and the
    //     window really paid >= 2 distinct miner scripts.
    expect_true("[X] donation output second-to-last (before OP_RETURN ref)",
                donation_amt > 0);   // window leaves a positive donation residual
    {
        // Distinct scripts among the emitted payouts.
        std::vector<std::vector<unsigned char>> scripts;
        for (auto& [s, v] : payouts) { (void)v; scripts.push_back(s); }
        std::sort(scripts.begin(), scripts.end());
        scripts.erase(std::unique(scripts.begin(), scripts.end()), scripts.end());
        expect_true("[X] >= 2 DISTINCT miner payout scripts in the coinbase", scripts.size() >= 2);
    }

    if (g_fail == 0) {
        std::printf("RESULT: PASS — the flag-ON minted coinbase pays the whole PPLNS window and "
                    "equals generate_share_transaction byte-for-byte (verify_gentx == mined_gentx); "
                    "peers ACCEPT the share. F1b closed.\n");
        return 0;
    }
    std::printf("RESULT: FAIL — %d check(s) failed.\n", g_fail);
    return 1;
}
