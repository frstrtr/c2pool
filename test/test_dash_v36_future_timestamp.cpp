// SPDX-License-Identifier: AGPL-3.0-or-later
// DASH future-timestamp bound (#1825) — behaviour KATs through the production
// verify path, share_init_verify (and the producer self-verify that calls it).
//
// Rule: a share whose timestamp is more than 600 s ahead of the local clock is
// rejected with "share timestamp is too far in the future" (port of the LTC
// rule, ltc/share_check.hpp share_check step 1). ACTIVE ONLY on the
// private/isolated DASH v36 sharechain profile (custom --network-id). The public
// v16 network keeps today's behaviour exactly: the p2pool-dash oracle
// (data.py check()) has no such bound, and neither does master.
//
// This file uses only symbols that already exist before the rule lands, so it
// compiles against the base revision and its red/green is behavioural:
//   IsolatedRejectsFarFutureShare            RED on base, GREEN with the rule
//   IsolatedProducerRefusesFarFutureOwnShare RED on base, GREEN with the rule
//   IsolatedAcceptsPastPresentAndPersisted   green on both (regression guard:
//                                            inverted comparison / reload path)
//   PublicAcceptsFarFutureShareByteIdentical green on both (public-path pin:
//                                            same accept, same share hash)
// The injectable-clock boundary KATs for the free function live in
// test_dash_v36_future_timestamp_bound.cpp.
//
// Linked into test_dash_network_id_override (not its own executable) because
// the profile is keyed on the process-global SharechainConfig identity; every
// test resets it on entry and exit.

#include <gtest/gtest.h>

#include <impl/dash/config_pool.hpp>
#include <impl/dash/params.hpp>
#include <impl/dash/share.hpp>
#include <impl/dash/share_chain.hpp>
#include <impl/dash/share_check.hpp>
#include <impl/dash/share_producer.hpp>

#include <core/coin_params.hpp>
#include <core/uint256.hpp>
#include <btclibs/util/strencodings.h>  // HexStr

#include <chrono>
#include <cstdint>
#include <functional>
#include <limits>
#include <span>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

using dash::SharechainConfig;
using dash::producer::ProspectiveShareInfo;

constexpr const char* MAIN_ID  = "7242ef345e1bed6b";  // oracle networks/dash.py
constexpr const char* TEST_ID  = "b6deb1e543fe2427";  // oracle networks/dash_testnet.py
constexpr const char* ISO_ID   = "d3a5c0920263617";   // any custom id => isolated v36
constexpr const char* ISO_PFX  = "0badc0ffee11";

// The LTC error text, verbatim (ltc/share_check.hpp).
constexpr const char* FUTURE_TS_ERR = "share timestamp is too far in the future";

// Far past the 600 s bound; well inside uint32 for decades.
constexpr uint32_t FAR_FUTURE_SECS = 10000;

// RAII: every test starts and ends on the public identity, mainnet.
struct IdentityGuard {
    IdentityGuard()  { SharechainConfig::reset_network_id(); SharechainConfig::is_testnet = false; }
    ~IdentityGuard() { SharechainConfig::reset_network_id(); SharechainConfig::is_testnet = false; }
};

uint32_t real_now() {
    return static_cast<uint32_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
}

std::string hex_of(const uint256& h) {
    auto c = h.GetChars();
    return HexStr(std::span<const unsigned char>(c.data(), c.size()));
}

// ── F1 fixture: transcribed from test_dash_network_id_override.cpp /
// test_dash_share_producer.cpp (genesis mint, no payload, one '!' payment). ──
constexpr uint32_t BITS_DIFF1 = 0x1d00ffffu;
const char* ATA_DIFF1_HEX = "100010001";

uint160 h160_uniform(uint8_t byte) { return uint160(std::vector<unsigned char>(20, byte)); }
uint128 u128_hex(const char* h) { uint128 v; v.SetHex(h); return v; }
uint256 h256_tag(uint8_t tag) {
    std::vector<unsigned char> v(32, 0x00);
    v[0] = tag; v[31] = 0xa5;
    return uint256(v);
}

ProspectiveShareInfo fixture_f1_info() {
    ProspectiveShareInfo info;
    info.prev_hash        = uint256();
    info.coinbase         = {0x03, 0x01, 0x02, 0x03};
    info.coinbase_payload = {};
    info.nonce            = 0x01020304;
    info.pubkey_hash      = h160_uniform(0x11);
    info.subsidy          = 500000000;
    info.donation         = 200;
    info.stale_info       = dash::StaleInfo::none;
    info.desired_version  = 16;
    info.payment_amount   = 100000000;
    {
        dash::PackedPayment pp;
        pp.m_payee  = "!6a04deadbeef";
        pp.m_amount = 100000000;
        info.packed_payments.push_back(pp);
    }
    info.far_share_hash = uint256();
    info.max_bits  = BITS_DIFF1;
    info.bits      = BITS_DIFF1;
    info.timestamp = 1700000000;  // in the past
    info.absheight = 1;
    info.abswork   = u128_hex(ATA_DIFF1_HEX);
    return info;
}

bitcoin_family::coin::SmallBlockHeaderType fixture_min_header() {
    bitcoin_family::coin::SmallBlockHeaderType h;
    h.m_version = 536870912;
    h.m_previous_block = h256_tag(0x77);
    h.m_timestamp = 1700000005;
    h.m_bits = 0x1b00ffffu;
    h.m_nonce = 0xdeadbeefu;
    return h;
}

constexpr uint64_t F1_NONCE64 = 0x0807060504030201ull;

dash::producer::BuiltShare build_f1(const core::CoinParams& pm,
                                    const ProspectiveShareInfo& info) {
    dash::ShareChain chain;
    return dash::producer::build_share(
        chain, pm, info, fixture_min_header(), F1_NONCE64, /*check_pow=*/false);
}

// Runs `fn`, requires it to throw std::invalid_argument with the LTC text.
void expect_future_reject(const std::function<void()>& fn) {
    bool threw = false;
    try {
        fn();
    } catch (const std::invalid_argument& e) {
        threw = true;
        EXPECT_STREQ(e.what(), FUTURE_TS_ERR);
    }
    EXPECT_TRUE(threw) << "expected std::invalid_argument(\"" << FUTURE_TS_ERR << "\")";
}

// Public-path goldens: the X11 share hash share_init_verify returns for the F1
// share (built under the public identity) re-stamped to m_timestamp=UINT32_MAX.
// Recorded on the base revision (no bound); must be unchanged with the rule.
constexpr const char* PUB_MAIN_TSMAX_HASH_HEX =
    "e738c092a89281839289f252190377871566495221b32df8eeb49c9d5b622aa9";
constexpr const char* PUB_TEST_TSMAX_HASH_HEX =
    "02868ecc7243ba57ff30e34ec3994f934b02f41169a00e2140a02c1a1ec35e52";

} // namespace

// ─────────────────────────────────────────────────────────────────────────────
// Isolated profile: a peer's share stamped now+10000 is rejected by the first
// verify step, with the LTC error text. RED on base (base returns a hash).
// ─────────────────────────────────────────────────────────────────────────────
TEST(DashV36FutureTimestamp, IsolatedRejectsFarFutureShare) {
    IdentityGuard g;
    SharechainConfig::set_network_id(ISO_ID, ISO_PFX);
    ASSERT_TRUE(SharechainConfig::share_profile().future_timestamp_bound);

    for (bool testnet : {false, true}) {
        SCOPED_TRACE(testnet ? "testnet" : "mainnet");
        SharechainConfig::is_testnet = testnet;
        const auto pm = dash::make_coin_params(testnet);
        auto built = build_f1(pm, fixture_f1_info());  // past timestamp: builds

        // Re-stamp as a post-dated share from a peer. With check_pow=false the
        // rest of share_init_verify still returns a hash (ref_hash moves, the
        // hash_link fold does not throw), so any throw here is the bound.
        dash::DashShare share = built.share;
        share.m_timestamp = real_now() + FAR_FUTURE_SECS;
        expect_future_reject([&] { (void)dash::share_init_verify(share, pm, false); });
        // The PoW-checking entry (node receive / tracker) rejects it the same
        // way, BEFORE any PoW work: same exception, same text.
        expect_future_reject([&] { (void)dash::share_init_verify(share, pm, true); });

        share.m_timestamp = std::numeric_limits<uint32_t>::max();
        expect_future_reject([&] { (void)dash::share_init_verify(share, pm, false); });
    }
}

// Isolated profile: our own producer refuses to emit a post-dated share (the
// build_share self-verify runs share_init_verify). RED on base (builds).
TEST(DashV36FutureTimestamp, IsolatedProducerRefusesFarFutureOwnShare) {
    IdentityGuard g;
    SharechainConfig::set_network_id(ISO_ID, ISO_PFX);
    const auto pm = dash::make_coin_params(false);
    auto info = fixture_f1_info();
    info.timestamp = real_now() + FAR_FUTURE_SECS;
    expect_future_reject([&] { (void)build_f1(pm, info); });
}

// Isolated profile: everything not in the future is still accepted — the
// fixture's 2023 timestamp (a persisted share on reload), now, one year ago and
// a few minutes ahead (inside the 600 s window). Guards an inverted comparison
// and the PR1 self-verify. Green on base and with the rule (regression guard).
TEST(DashV36FutureTimestamp, IsolatedAcceptsPastPresentAndPersisted) {
    IdentityGuard g;
    SharechainConfig::set_network_id(ISO_ID, ISO_PFX);
    const auto pm = dash::make_coin_params(false);

    auto built = build_f1(pm, fixture_f1_info());
    ASSERT_FALSE(built.share.m_hash.IsNull());
    EXPECT_EQ(hex_of(dash::share_init_verify(built.share, pm, false)),
              hex_of(built.share.m_hash));

    const uint32_t now = real_now();
    for (uint32_t ts : {uint32_t(1700000000u), now, now - 31536000u, now + 300u}) {
        SCOPED_TRACE("ts=" + std::to_string(ts));
        dash::DashShare share = built.share;
        share.m_timestamp = ts;
        uint256 h;
        EXPECT_NO_THROW(h = dash::share_init_verify(share, pm, false));
        EXPECT_FALSE(h.IsNull());
    }

    // Our own mint stamped "now" still builds and self-verifies.
    auto info = fixture_f1_info();
    info.timestamp = now;
    EXPECT_NO_THROW({
        auto b = build_f1(pm, info);
        EXPECT_EQ(hex_of(dash::share_init_verify(b.share, pm, false)), hex_of(b.share.m_hash));
    });
}

// Public v16 network (no --network-id, mainnet AND testnet): a share stamped
// now+10000 — and UINT32_MAX — is still accepted by the same check path as on
// master, and yields the SAME share hash (golden recorded on the base
// revision). Our own producer still builds a post-dated share. Green on base
// and with the rule: this is the byte-identical public-path pin.
TEST(DashV36FutureTimestamp, PublicAcceptsFarFutureShareByteIdentical) {
    IdentityGuard g;
    ASSERT_FALSE(SharechainConfig::has_custom_network_id());
    ASSERT_FALSE(SharechainConfig::share_profile().future_timestamp_bound);

    for (bool testnet : {false, true}) {
        SCOPED_TRACE(testnet ? "testnet" : "mainnet");
        SharechainConfig::is_testnet = testnet;
        const auto pm = dash::make_coin_params(testnet);
        ASSERT_EQ(pm.active_identifier_hex(), testnet ? TEST_ID : MAIN_ID);

        auto built = build_f1(pm, fixture_f1_info());

        dash::DashShare share = built.share;
        share.m_timestamp = real_now() + FAR_FUTURE_SECS;
        uint256 h1, h2;
        EXPECT_NO_THROW(h1 = dash::share_init_verify(share, pm, false));
        EXPECT_NO_THROW(h2 = dash::share_init_verify(share, pm, false));
        EXPECT_FALSE(h1.IsNull());
        EXPECT_EQ(hex_of(h1), hex_of(h2));

        share.m_timestamp = std::numeric_limits<uint32_t>::max();
        uint256 hmax;
        EXPECT_NO_THROW(hmax = dash::share_init_verify(share, pm, false));
        EXPECT_EQ(hex_of(hmax), testnet ? PUB_TEST_TSMAX_HASH_HEX : PUB_MAIN_TSMAX_HASH_HEX);

        auto info = fixture_f1_info();
        info.timestamp = real_now() + FAR_FUTURE_SECS;
        EXPECT_NO_THROW({
            auto b = build_f1(pm, info);
            EXPECT_EQ(hex_of(dash::share_init_verify(b.share, pm, false)), hex_of(b.share.m_hash));
        });
    }
}
