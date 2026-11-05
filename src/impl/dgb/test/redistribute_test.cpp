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
#include <impl/dgb/address_encoding.hpp>

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
    // A bare --redistribute fee with NO --node-owner-address leaves the operator
    // payout identity unset, so pick() must yield a NULL pubkey -> the fallback
    // returns an empty script (never a burn output to the all-zero hash). The
    // address-plumbed path is covered by
    // FeeIdentityPlumbedFromNodeOwnerAddressMintsOperatorScript below.
    dgb::Redistributor r;
    r.set_mode(dgb::RedistributeMode::FEE);   // operator identity unset
    dgb::ShareTracker tracker;
    uint256 best;
    auto res = r.pick(tracker, best);
    EXPECT_TRUE(res.pubkey_hash.IsNull());
}

// --- #307 fee-identity PLUMBING (this PR) ---------------------------------
// --redistribute fee + a configured --node-owner-address must mint under the
// operator's payout script, NOT the empty-script no-op.
//
// RED before this PR: main_dgb never called set_operator_identity for the fee
// arm, so pick(FEE) handed back a null hash and the fallback closure returned
// {} (empty script). GREEN after: dgb::set_operator_identity_from_address
// decodes the operator address to a hash160 and arms the FEE identity, so the
// fee arm mints the operator P2PKH script. This test reproduces main_dgb.cpp's
// fallback-payout script builder byte-for-byte.
TEST(DgbRedistribute, FeeIdentityPlumbedFromNodeOwnerAddressMintsOperatorScript)
{
    // Canonical DGB mainnet P2PKH address (base58 version byte 0x1e) whose
    // hash160 is 0102..14. Independently derived: base58check over
    // 0x1e || hash160 || sha256d(0x1e||hash160)[:4].
    const std::string kNodeOwnerAddr = "D5ERdEN1gsouFSs7zsq7VYJxyWP6dP28H1";
    static const uint8_t kExpectedH160[20] = {
        0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,
        0x0b,0x0c,0x0d,0x0e,0x0f,0x10,0x11,0x12,0x13,0x14};

    dgb::Redistributor r;
    r.set_hybrid_weights(dgb::parse_redistribute_spec("fee")); // --redistribute fee
    dgb::ShareTracker tracker;   // empty
    uint256 best;                // null

    // Reproduce main_dgb.cpp's fallback-payout closure: pick() -> script bytes
    // (RAW 20-byte / script-order path, NOT uint160::GetHex which reverses).
    auto fallback_script = [&]() -> std::vector<unsigned char> {
        dgb::RedistributeResult rr = r.pick(tracker, best);
        if (rr.pubkey_hash.IsNull()) return {};    // the master no-op
        unsigned char hb[20];
        std::memcpy(hb, rr.pubkey_hash.data(), 20);
        std::vector<unsigned char> sp;
        if (rr.pubkey_type == 2) {                 // P2SH:  a9 14 <h160> 87
            sp = {0xa9, 0x14};
            sp.insert(sp.end(), hb, hb + 20);
            sp.push_back(0x87);
        } else {                                   // P2PKH: 76 a9 14 <h160> 88 ac
            sp = {0x76, 0xa9, 0x14};
            sp.insert(sp.end(), hb, hb + 20);
            sp.push_back(0x88);
            sp.push_back(0xac);
        }
        return sp;
    };

    // RED baseline (no operator identity, exactly master's shipped fee arm):
    // the fallback yields an EMPTY script.
    EXPECT_TRUE(fallback_script().empty());

    // GREEN (the fix): plumb the operator identity from the node-owner address.
    const auto kMainnet = dgb::address_acceptance(/*testnet=*/false, /*regtest=*/false);
    ASSERT_TRUE(dgb::set_operator_identity_from_address(r, kNodeOwnerAddr, kMainnet));

    // The fee arm now mints under the operator's P2PKH payout identity.
    dgb::RedistributeResult armed = r.pick(tracker, best);
    ASSERT_FALSE(armed.pubkey_hash.IsNull());
    EXPECT_EQ(armed.pubkey_type, 0);   // P2PKH (0x1e is not a P2SH version byte)
    EXPECT_EQ(std::memcmp(armed.pubkey_hash.data(), kExpectedH160, 20), 0);

    // ...and the fallback closure builds the canonical 25-byte P2PKH script.
    std::vector<unsigned char> expected = {0x76, 0xa9, 0x14};
    expected.insert(expected.end(), kExpectedH160, kExpectedH160 + 20);
    expected.push_back(0x88);
    expected.push_back(0xac);
    EXPECT_EQ(fallback_script(), expected);

    // Empty / undecodable address -> false, operator identity left untouched
    // (fail-safe: the fee arm stays the empty-script no-op).
    dgb::Redistributor r2;
    EXPECT_FALSE(dgb::set_operator_identity_from_address(r2, "", kMainnet));
    EXPECT_FALSE(dgb::set_operator_identity_from_address(r2, "not-a-valid-address", kMainnet));
    r2.set_mode(dgb::RedistributeMode::FEE);
    EXPECT_TRUE(r2.pick(tracker, best).pubkey_hash.IsNull());
}

// --- #1312: DGB P2SH operator address must arm a P2SH fee identity ----------
// RED before: core::address_to_hash160's chain-agnostic P2SH whitelist has no
// DGB P2SH byte (mainnet 0x3f 'S', testnet 0x8c), so an S-address armed type 0
// and the fee arm paid 76a914<h160>88ac -- a script nobody holds the key for
// (fee burn). It also armed foreign-coin addresses. GREEN after: the address is
// classified against DGB's own network acceptance and typed by script shape.
//
// Every vector below encodes the SAME hash160 0102..14, independently derived
// (base58check over version || hash160 || sha256d(..)[:4]; bech32 per BIP173).
// The encoder reproduces the mainnet P2PKH vector pinned in the test above.
const uint8_t kH160[20] = {
    0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,
    0x0b,0x0c,0x0d,0x0e,0x0f,0x10,0x11,0x12,0x13,0x14};

// Arm a fresh FEE-mode redistributor from `addr`; returns the pick result
// (null pubkey_hash when the setter refused the address).
dgb::RedistributeResult arm_fee(const std::string& addr,
                                const core::CoinAddressAcceptance& acc,
                                bool& armed)
{
    dgb::Redistributor r;
    r.set_hybrid_weights(dgb::parse_redistribute_spec("fee"));
    armed = dgb::set_operator_identity_from_address(r, addr, acc);
    dgb::ShareTracker tracker;
    uint256 best;
    return r.pick(tracker, best);
}

TEST(DgbRedistribute, Issue1312MainnetSAddressArmsP2shFeeIdentity)
{
    const auto mainnet = dgb::address_acceptance(false, false);
    bool armed = false;
    auto rr = arm_fee("SMPL7pCX7q6pEkTyoipdVgHvk9tE5D6XNW", mainnet, armed);  // 0x3f
    ASSERT_TRUE(armed);
    EXPECT_EQ(rr.pubkey_type, 2);   // P2SH -> a914<h160>87, not a burn P2PKH
    EXPECT_EQ(std::memcmp(rr.pubkey_hash.data(), kH160, 20), 0);
}

TEST(DgbRedistribute, Issue1312TestnetP2shAndP2pkhFollowNetwork)
{
    const auto testnet = dgb::address_acceptance(/*testnet=*/true, false);
    const auto regtest = dgb::address_acceptance(false, /*regtest=*/true);
    const auto mainnet = dgb::address_acceptance(false, false);
    bool armed = false;

    // testnet P2SH 0x8c: also absent from the core whitelist -> was type 0.
    auto rr = arm_fee("yLQmwB9hninHD8Ceh2UAqLFWCzirppNLik", testnet, armed);
    ASSERT_TRUE(armed);
    EXPECT_EQ(rr.pubkey_type, 2);
    EXPECT_EQ(std::memcmp(rr.pubkey_hash.data(), kH160, 20), 0);

    // Regtest reuses the testnet base58 bytes.
    rr = arm_fee("yLQmwB9hninHD8Ceh2UAqLFWCzirppNLik", regtest, armed);
    ASSERT_TRUE(armed);
    EXPECT_EQ(rr.pubkey_type, 2);

    // testnet P2PKH 0x7e stays type 0.
    rr = arm_fee("shgL9eyfrCJ1m4FSM9oi3aSVPw7etdbBf3", testnet, armed);
    ASSERT_TRUE(armed);
    EXPECT_EQ(rr.pubkey_type, 0);
    EXPECT_EQ(std::memcmp(rr.pubkey_hash.data(), kH160, 20), 0);

    // Wrong network for the running node -> refused, fee arm stays null.
    rr = arm_fee("yLQmwB9hninHD8Ceh2UAqLFWCzirppNLik", mainnet, armed);
    EXPECT_FALSE(armed);
    EXPECT_TRUE(rr.pubkey_hash.IsNull());
    rr = arm_fee("SMPL7pCX7q6pEkTyoipdVgHvk9tE5D6XNW", testnet, armed);
    EXPECT_FALSE(armed);
    EXPECT_TRUE(rr.pubkey_hash.IsNull());
}

TEST(DgbRedistribute, Issue1312ForeignOrWitnessAddressNeverArms)
{
    const auto mainnet = dgb::address_acceptance(false, false);
    bool armed = true;
    for (const char* addr : {
             "LKKHMBjCU89fyFNgSRprDoD8Jb25N8uWvd",              // LTC P2PKH 0x30
             "16L5yRNPTuciSgXGHqYwn9N6NeoKqopAu",               // BTC P2PKH 0x00
             "ltc1qqypqxpq9qcrsszg2pvxq6rs0zqg3yyc5dyg36p",     // LTC P2WPKH
             "dgb1qqypqxpq9qcrsszg2pvxq6rs0zqg3yyc57rkd6l"}) {  // own P2WPKH: no (h160,type) form
        auto rr = arm_fee(addr, mainnet, armed);
        EXPECT_FALSE(armed) << addr;
        EXPECT_TRUE(rr.pubkey_hash.IsNull()) << addr;
    }
}

} // namespace