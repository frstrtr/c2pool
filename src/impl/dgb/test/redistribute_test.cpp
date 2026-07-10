// SPDX-License-Identifier: AGPL-3.0-or-later
// DGB Scrypt-only coin module — Redistribute V2 conformance fixtures (Phase B).
// Mirrors src/impl/dgb/redistribute.hpp, ported byte-for-byte from
// src/impl/ltc/redistribute.hpp (namespace flip only). Pins the deterministic
// surface of the node-local redistribution policy against the documented
// p2pool-v36 work.py --redistribute spec (commit de76224a) + FUTURE.md V2:
// mode parsing, hybrid spec parse/format round-trip, stratum-password options,
// and the deterministic FEE/DONATE/empty-PPLNS pick paths.
//
// CONSENSUS-SAFE: redistribute only chooses the pubkey_hash this node stamps
// into its own shares — it never alters sharechain validation, so this is a
// bucket-2 v36-native standardization slice (cross-coin parity toward the ltc
// shape), node-local, no operator tap. The RNG-weighted boost/PPLNS selection
// paths are intentionally NOT pinned here (non-deterministic by design); the
// single-candidate and fallback branches that ARE deterministic are pinned.

#include <gtest/gtest.h>

#include <cstring>
#include <string>
#include <vector>

#include <impl/dgb/redistribute.hpp>
#include <impl/dgb/share_tracker.hpp>
#include <impl/dgb/config_pool.hpp>

namespace {

// --- mode <-> string round-trip (work.py mode names) ----------------------
TEST(DgbRedistribute, ParseSingleModeAndStringRoundTrip)
{
    EXPECT_EQ(dgb::parse_single_mode("pplns"),  dgb::RedistributeMode::PPLNS);
    EXPECT_EQ(dgb::parse_single_mode("fee"),    dgb::RedistributeMode::FEE);
    EXPECT_EQ(dgb::parse_single_mode("boost"),  dgb::RedistributeMode::BOOST);
    EXPECT_EQ(dgb::parse_single_mode("donate"), dgb::RedistributeMode::DONATE);
    // Unknown / empty defaults to PPLNS (work.py default).
    EXPECT_EQ(dgb::parse_single_mode("garbage"), dgb::RedistributeMode::PPLNS);
    EXPECT_EQ(dgb::parse_single_mode(""),        dgb::RedistributeMode::PPLNS);

    EXPECT_STREQ(dgb::redistribute_mode_str(dgb::RedistributeMode::PPLNS),  "pplns");
    EXPECT_STREQ(dgb::redistribute_mode_str(dgb::RedistributeMode::FEE),    "fee");
    EXPECT_STREQ(dgb::redistribute_mode_str(dgb::RedistributeMode::BOOST),  "boost");
    EXPECT_STREQ(dgb::redistribute_mode_str(dgb::RedistributeMode::DONATE), "donate");
}

// --- single-mode spec parse -----------------------------------------------
TEST(DgbRedistribute, ParseSpecSingleMode)
{
    auto w = dgb::parse_redistribute_spec("boost");
    ASSERT_EQ(w.size(), 1u);
    EXPECT_EQ(w[0].mode, dgb::RedistributeMode::BOOST);
    EXPECT_EQ(w[0].weight, 100u);

    // Empty spec -> implicit pplns:100
    auto e = dgb::parse_redistribute_spec("");
    ASSERT_EQ(e.size(), 1u);
    EXPECT_EQ(e[0].mode, dgb::RedistributeMode::PPLNS);
    EXPECT_EQ(e[0].weight, 100u);

    EXPECT_EQ(dgb::parse_redistribute_mode("donate"), dgb::RedistributeMode::DONATE);
}

// --- hybrid spec parse + format round-trip --------------------------------
TEST(DgbRedistribute, ParseHybridSpecAndFormatRoundTrip)
{
    auto w = dgb::parse_redistribute_spec("boost:70,donate:20,fee:10");
    ASSERT_EQ(w.size(), 3u);
    EXPECT_EQ(w[0].mode, dgb::RedistributeMode::BOOST);  EXPECT_EQ(w[0].weight, 70u);
    EXPECT_EQ(w[1].mode, dgb::RedistributeMode::DONATE); EXPECT_EQ(w[1].weight, 20u);
    EXPECT_EQ(w[2].mode, dgb::RedistributeMode::FEE);    EXPECT_EQ(w[2].weight, 10u);

    // Primary mode is the first entry.
    EXPECT_EQ(dgb::parse_redistribute_mode("boost:70,donate:20,fee:10"),
              dgb::RedistributeMode::BOOST);

    // Format round-trip: hybrid renders mode:weight CSV, single renders bare.
    EXPECT_EQ(dgb::format_hybrid_weights(w), "boost:70,donate:20,fee:10");
    auto single = dgb::parse_redistribute_spec("fee");
    EXPECT_EQ(dgb::format_hybrid_weights(single), "fee");

    // Zero-weight entries are dropped (w>0 guard).
    auto z = dgb::parse_redistribute_spec("boost:0,donate:50");
    ASSERT_EQ(z.size(), 1u);
    EXPECT_EQ(z[0].mode, dgb::RedistributeMode::DONATE);
    EXPECT_EQ(z[0].weight, 50u);
}

// --- stratum password options (boost opt-in, min diff) --------------------
TEST(DgbRedistribute, ParseStratumPassword)
{
    auto a = dgb::parse_stratum_password("boost:true");
    EXPECT_TRUE(a.boost);

    auto b = dgb::parse_stratum_password("boost=1,d=1024");
    EXPECT_TRUE(b.boost);
    EXPECT_DOUBLE_EQ(b.min_diff, 1024.0);

    auto c = dgb::parse_stratum_password("boost:false");
    EXPECT_FALSE(c.boost);

    auto d = dgb::parse_stratum_password("");
    EXPECT_FALSE(d.boost);
    EXPECT_DOUBLE_EQ(d.min_diff, 0.0);
}

// --- deterministic pick paths (FEE / DONATE / empty-PPLNS fallback) -------
TEST(DgbRedistribute, DeterministicPickPaths)
{
    dgb::Redistributor r;

    uint160 op_hash;  std::memset(op_hash.data(),  0xAA, 20);
    uint160 don_hash; std::memset(don_hash.data(), 0xBB, 20);
    r.set_operator_identity(op_hash, /*P2PKH*/ 0);
    r.set_donation_identity(don_hash, /*P2SH*/ 2);

    dgb::ShareTracker tracker;     // empty
    uint256 best;                  // null -> PPLNS short-circuits to operator

    // FEE -> 100% operator identity.
    r.set_mode(dgb::RedistributeMode::FEE);
    auto fee = r.pick(tracker, best);
    EXPECT_EQ(fee.pubkey_hash, op_hash);
    EXPECT_EQ(fee.pubkey_type, 0);

    // DONATE -> 100% donation identity (P2SH type 2 for combined donation).
    r.set_mode(dgb::RedistributeMode::DONATE);
    auto don = r.pick(tracker, best);
    EXPECT_EQ(don.pubkey_hash, don_hash);
    EXPECT_EQ(don.pubkey_type, 2);

    // PPLNS over an empty tracker -> operator fallback (no shares to weight).
    r.set_mode(dgb::RedistributeMode::PPLNS);
    auto pplns = r.pick(tracker, best);
    EXPECT_EQ(pplns.pubkey_hash, op_hash);
    EXPECT_EQ(pplns.pubkey_type, 0);

    // Mode accessor reflects the last single-mode set.
    EXPECT_EQ(r.mode(), dgb::RedistributeMode::PPLNS);
}

// --- #307 follow-up: --redistribute arg-spec -> configured policy + the
//     node-local fallback payout SELECTOR wired in main_dgb. The donate
//     identity must resolve byte-for-byte to the canonical V36 combined-
//     donation P2SH; fee without an operator identity is fail-safe null;
//     the arg spec must drive the hybrid weights. --------------------------
TEST(DgbRedistribute, ArgSpecConfiguresHybridWeights)
{
    dgb::Redistributor r;
    r.set_hybrid_weights(dgb::parse_redistribute_spec("boost:70,donate:20,fee:10"));
    ASSERT_EQ(r.hybrid_weights().size(), 3u);
    EXPECT_EQ(r.hybrid_weights()[0].mode, dgb::RedistributeMode::BOOST);
    EXPECT_EQ(r.hybrid_weights()[0].weight, 70u);
    EXPECT_EQ(r.hybrid_weights()[1].mode, dgb::RedistributeMode::DONATE);
    EXPECT_EQ(r.hybrid_weights()[2].mode, dgb::RedistributeMode::FEE);
}

TEST(DgbRedistribute, DonateIdentityRoundTripsCombinedDonationP2SH)
{
    // Reproduce exactly what main_dgb does: donation hash160 == bytes [2..22]
    // of the canonical V36 combined-donation P2SH script, type P2SH (2).
    uint160 dh;
    std::memcpy(dh.data(), dgb::PoolConfig::COMBINED_DONATION_SCRIPT.data() + 2, 20);
    dgb::Redistributor r;
    r.set_donation_identity(dh, /*P2SH*/ 2);
    r.set_mode(dgb::RedistributeMode::DONATE);

    dgb::ShareTracker tracker;   // empty
    uint256 best;                // null
    auto res = r.pick(tracker, best);
    EXPECT_EQ(res.pubkey_hash, dh);
    EXPECT_EQ(res.pubkey_type, 2);

    // Rebuild the P2SH scriptPubKey the main_dgb fallback would stamp (same
    // RAW 20-byte path -- NOT GetHex, which reverses) and assert byte-identity
    // with the canonical combined-donation script.
    unsigned char hb[20];
    std::memcpy(hb, res.pubkey_hash.data(), 20);
    std::vector<unsigned char> script = {0xa9, 0x14};
    script.insert(script.end(), hb, hb + 20);
    script.push_back(0x87);
    const std::vector<unsigned char> expected(
        dgb::PoolConfig::COMBINED_DONATION_SCRIPT.begin(),
        dgb::PoolConfig::COMBINED_DONATION_SCRIPT.end());
    EXPECT_EQ(script, expected);
}

TEST(DgbRedistribute, FeeWithoutOperatorIdentityIsFailSafeNull)
{
    // main_dgb does not (yet) plumb an operator payout identity, so a bare
    // --redistribute fee must yield a NULL pubkey -> the fallback returns an
    // empty script (never a burn output to the all-zero hash).
    dgb::Redistributor r;
    r.set_mode(dgb::RedistributeMode::FEE);   // operator identity unset
    dgb::ShareTracker tracker;
    uint256 best;
    auto res = r.pick(tracker, best);
    EXPECT_TRUE(res.pubkey_hash.IsNull());
}

} // namespace