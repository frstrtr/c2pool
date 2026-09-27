// SPDX-License-Identifier: AGPL-3.0-or-later
// DASH private-sharechain identity override KAT (--network-id / --prefix).
//
// The DASH sharechain IDENTIFIER is not only p2p framing: it is the first 8
// bytes of every share's ref stream (share_check.hpp share_init_verify,
// share_producer.hpp compute_ref_hash, both via
// CoinParams::active_identifier_hex()). This KAT pins:
//   (a) the NO-FLAG identity is byte-identical to master (accessors, CoinParams
//       and the F1 ref stream/ref_hash golden transcribed from
//       test_dash_share_producer.cpp);
//   (b) an override moves the frame prefix AND the ref-stream identifier on
//       both networks, and a share minted under it verifies under it but not
//       under the public identity;
//   (c) invalid input is rejected before it can reach the ref stream;
//   (d) sharechain bootstrap-mode precedence (btc parity).
//
// OWN EXECUTABLE ON PURPOSE: the override lives in process-global statics.
// test_dash_share_hash_link / test_dash_conformance hold goldens on the DEFAULT
// identity, so this file must never be compiled into them. Every test still
// resets the statics on entry and exit.
//
// Goldens are INDEPENDENT transcriptions (literals), never re-exports of the
// SharechainConfig constants, so a drift of the SSOT fails here.

#include <gtest/gtest.h>

#include <impl/dash/config_pool.hpp>
#include <impl/dash/params.hpp>
#include <impl/dash/share.hpp>
#include <impl/dash/share_chain.hpp>
#include <impl/dash/share_check.hpp>
#include <impl/dash/share_producer.hpp>

#include <core/coin_params.hpp>
#include <core/hash.hpp>
#include <core/pack.hpp>
#include <core/pack_types.hpp>
#include <core/uint256.hpp>
#include <btclibs/util/strencodings.h>  // ParseHexBytes, HexStr

#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace {

using dash::SharechainConfig;
using dash::producer::ProspectiveShareInfo;

// Live p2pool-dash fleet identity (oracle p2pool/networks/dash.py:9-10) and the
// testnet identity (dash_testnet.py). Transcribed, not re-exported.
constexpr const char* MAIN_ID  = "7242ef345e1bed6b";
constexpr const char* MAIN_PFX = "3b3e1286f446b891";
constexpr const char* TEST_ID  = "b6deb1e543fe2427";
constexpr const char* TEST_PFX = "198b644f6821e3b3";

// RAII: every test starts and ends on the public identity, mainnet.
struct IdentityGuard {
    IdentityGuard()  { SharechainConfig::reset_network_id(); SharechainConfig::is_testnet = false; }
    ~IdentityGuard() { SharechainConfig::reset_network_id(); SharechainConfig::is_testnet = false; }
};

std::string hex_of(const uint256& h) {
    auto c = h.GetChars();
    return HexStr(std::span<const unsigned char>(c.data(), c.size()));
}

std::string hex_of_bytes(const std::vector<unsigned char>& v) {
    return HexStr(std::span<const unsigned char>(v.data(), v.size()));
}

std::vector<unsigned char> unhex(const std::string& h) {
    std::vector<unsigned char> out;
    for (size_t i = 0; i + 1 < h.size(); i += 2)
        out.push_back(static_cast<unsigned char>(std::stoul(h.substr(i, 2), nullptr, 16)));
    return out;
}

// ── F1 fixture: transcribed from test_dash_share_producer.cpp (genesis mint,
// no payload, one '!' script payment). Kept byte-identical so (a) pins the
// same ref stream the producer golden does. ──────────────────────────────────
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
    info.timestamp = 1700000000;
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

// identifier (8 B) || share_info (171 B) — test_dash_share_producer.cpp F1.
const char* F1_REF_STREAM_HEX =
    "7242ef345e1bed6b"
    "0000000000000000000000000000000000000000000000000000000000000000"
    "0403010203"
    "00"
    "04030201"
    "1111111111111111111111111111111111111111"
    "0065cd1d00000000"
    "c800"
    "00"
    "10"
    "00e1f50500000000"
    "010d213661303464656164626565660" "0e1f50500000000"
    "00"
    "00"
    "0000000000000000000000000000000000000000000000000000000000000000"
    "ffff001d" "ffff001d"
    "00f15365"
    "01000000"
    "01000100010000000000000000000000";

const char* F1_REF_HASH_HEX =
    "ae9fd236e3de3647ce76bf2eb3172ad0ec51d3edba4b231b4b1e2d204771880b";

// The ref stream exactly as share_producer.hpp compute_ref_hash builds it:
// identifier bytes from params.active_identifier_hex(), then share_info.
std::vector<unsigned char> ref_stream_bytes(const core::CoinParams& params,
                                            const ProspectiveShareInfo& info) {
    PackStream s;
    {
        const std::string hex = params.active_identifier_hex();
        for (size_t i = 0; i + 1 < hex.size(); i += 2) {
            unsigned char b = static_cast<unsigned char>(
                std::stoul(hex.substr(i, 2), nullptr, 16));
            s.write(std::span<const std::byte>(reinterpret_cast<const std::byte*>(&b), 1));
        }
    }
    dash::producer::serialize_share_info(s, info);
    return std::vector<unsigned char>(
        reinterpret_cast<const unsigned char*>(s.data()),
        reinterpret_cast<const unsigned char*>(s.data()) + s.size());
}

} // namespace

// ═════════════════════════════════════════════════════════════════════════════
// (a) No flag => identity byte-identical to master.
// ═════════════════════════════════════════════════════════════════════════════
TEST(DashNetworkIdOverride, NoFlagIdentityIsByteIdenticalToMaster) {
    IdentityGuard g;

    EXPECT_TRUE(SharechainConfig::override_identifier_hex.empty());
    EXPECT_TRUE(SharechainConfig::override_prefix_hex.empty());
    EXPECT_FALSE(SharechainConfig::has_custom_network_id());

    SharechainConfig::is_testnet = false;
    EXPECT_EQ(SharechainConfig::identifier_hex(), MAIN_ID);
    EXPECT_EQ(SharechainConfig::prefix_hex(),     MAIN_PFX);
    SharechainConfig::is_testnet = true;
    EXPECT_EQ(SharechainConfig::identifier_hex(), TEST_ID);
    EXPECT_EQ(SharechainConfig::prefix_hex(),     TEST_PFX);

    // CoinParams: all four slots carry the oracle constants, as on master.
    const auto pt = dash::make_coin_params(true);
    EXPECT_EQ(pt.active_identifier_hex(), TEST_ID);
    EXPECT_EQ(pt.active_prefix_hex(),     TEST_PFX);
    const auto pm = dash::make_coin_params(false);
    EXPECT_EQ(pm.active_identifier_hex(), MAIN_ID);
    EXPECT_EQ(pm.active_prefix_hex(),     MAIN_PFX);
    EXPECT_EQ(pm.identifier_hex,          MAIN_ID);
    EXPECT_EQ(pm.prefix_hex,              MAIN_PFX);
    EXPECT_EQ(pm.testnet_identifier_hex,  TEST_ID);
    EXPECT_EQ(pm.testnet_prefix_hex,      TEST_PFX);

    // The actual ref-hash byte stream on the no-flag path.
    const auto info = fixture_f1_info();
    const auto bytes = ref_stream_bytes(pm, info);
    EXPECT_EQ(bytes.size(), 179u);
    EXPECT_EQ(hex_of_bytes(bytes), F1_REF_STREAM_HEX);
    EXPECT_EQ(hex_of_bytes(bytes).substr(0, 16), MAIN_ID);
    EXPECT_EQ(hex_of(dash::producer::compute_ref_hash(pm, info)), F1_REF_HASH_HEX);
}

// ═════════════════════════════════════════════════════════════════════════════
// (b) Override moves the frame prefix and the ref-stream identifier.
// ═════════════════════════════════════════════════════════════════════════════
TEST(DashNetworkIdOverride, OverrideChangesPrefixAndRefHashStream) {
    IdentityGuard g;

    // 15 hex chars (7.5 B) exercises the left-pad; prefix pads to 8 B too.
    SharechainConfig::set_network_id("d3a5c0920263617", "0badc0ffee11");
    EXPECT_TRUE(SharechainConfig::has_custom_network_id());
    EXPECT_EQ(SharechainConfig::identifier_hex(), "0d3a5c0920263617");
    EXPECT_EQ(SharechainConfig::prefix_hex(),     "00000badc0ffee11");
    // The wire-frame prefix main_dash.cpp installs (config.pool()->m_prefix).
    EXPECT_EQ(ParseHexBytes(SharechainConfig::prefix_hex()).size(), 8u);

    // Same answer on testnet (override is network-independent, BTC parity).
    SharechainConfig::is_testnet = true;
    EXPECT_EQ(SharechainConfig::identifier_hex(), "0d3a5c0920263617");
    EXPECT_EQ(SharechainConfig::prefix_hex(),     "00000badc0ffee11");
    const auto pt = dash::make_coin_params(true);
    EXPECT_EQ(pt.active_identifier_hex(), "0d3a5c0920263617");
    EXPECT_EQ(pt.active_prefix_hex(),     "00000badc0ffee11");

    const auto pm = dash::make_coin_params(false);
    EXPECT_EQ(pm.active_identifier_hex(), "0d3a5c0920263617");
    EXPECT_EQ(pm.active_prefix_hex(),     "00000badc0ffee11");

    // Ref stream: ONLY the 8 identifier bytes moved; share_info tail identical.
    const auto info = fixture_f1_info();
    const auto bytes = ref_stream_bytes(pm, info);
    ASSERT_EQ(bytes.size(), 179u);
    const std::string hx = hex_of_bytes(bytes);
    EXPECT_EQ(hx.substr(0, 16), "0d3a5c0920263617");
    EXPECT_EQ(hx.substr(16), std::string(F1_REF_STREAM_HEX).substr(16));

    // compute_ref_hash consumes the moved identifier: == sha256d(stream)
    // (empty ref merkle link is identity) and != the public F1 golden.
    const uint256 got = dash::producer::compute_ref_hash(pm, info);
    const uint256 want = Hash(std::span<const unsigned char>(bytes.data(), bytes.size()));
    EXPECT_EQ(hex_of(got), hex_of(want));
    EXPECT_NE(hex_of(got), F1_REF_HASH_HEX);

    // Verify side: a share minted under the override self-verifies under the
    // override (share_check.hpp recomputes ref_hash from the same params) ...
    dash::ShareChain chain;
    auto built = dash::producer::build_share(
        chain, pm, info, fixture_min_header(), F1_NONCE64, /*check_pow=*/false);
    EXPECT_EQ(hex_of(built.ref_hash), hex_of(got));
    EXPECT_EQ(hex_of(dash::share_init_verify(built.share, pm, false)),
              hex_of(built.share.m_hash));

    // ... but NOT under the public identity: a public-fleet node recomputes a
    // different ref_hash, so it throws or derives a different share hash.
    SharechainConfig::reset_network_id();
    const auto pub = dash::make_coin_params(false);
    ASSERT_EQ(pub.active_identifier_hex(), MAIN_ID);
    bool rejected = false;
    try {
        rejected = hex_of(dash::share_init_verify(built.share, pub, false))
                   != hex_of(built.share.m_hash);
    } catch (const std::exception&) {
        rejected = true;
    }
    EXPECT_TRUE(rejected);
}

TEST(DashNetworkIdOverride, BareNetworkIdKeepsCompiledPrefix) {
    IdentityGuard g;

    SharechainConfig::set_network_id("abcd");
    EXPECT_EQ(SharechainConfig::identifier_hex(), "000000000000abcd");
    EXPECT_TRUE(SharechainConfig::override_prefix_hex.empty());
    EXPECT_EQ(SharechainConfig::prefix_hex(), MAIN_PFX);
    EXPECT_EQ(dash::make_coin_params(false).active_prefix_hex(), MAIN_PFX);

    SharechainConfig::is_testnet = true;
    EXPECT_EQ(SharechainConfig::identifier_hex(), "000000000000abcd");
    EXPECT_EQ(SharechainConfig::prefix_hex(), TEST_PFX);
    const auto pt = dash::make_coin_params(true);
    EXPECT_EQ(pt.active_identifier_hex(), "000000000000abcd");
    EXPECT_EQ(pt.active_prefix_hex(), TEST_PFX);
}

// ═════════════════════════════════════════════════════════════════════════════
// (c) Invalid input never reaches set_network_id / the ref stream.
// ═════════════════════════════════════════════════════════════════════════════
TEST(DashNetworkIdOverride, PublicSpellingsAreNoOp) {
    IdentityGuard g;
    for (const char* v : {"", "0", "00000000"}) {
        SharechainConfig::set_network_id(v, "");
        EXPECT_TRUE(SharechainConfig::override_identifier_hex.empty()) << v;
        EXPECT_TRUE(SharechainConfig::override_prefix_hex.empty()) << v;
        EXPECT_EQ(SharechainConfig::identifier_hex(), MAIN_ID) << v;

        std::string id = v, pfx, err;
        EXPECT_TRUE(dash::validate_network_id_args(id, pfx, err)) << v << " " << err;
    }
}

TEST(DashNetworkIdOverride, InvalidInputRejected) {
    IdentityGuard g;
    auto ok = [](std::string id, std::string pfx) {
        std::string err;
        return dash::validate_network_id_args(id, pfx, err);
    };

    EXPECT_FALSE(ok("zz", ""));                    // not hex
    EXPECT_FALSE(ok("abc", ""));                   // odd length
    EXPECT_FALSE(ok("0123456789abcdef0", ""));     // 17 chars (> 8 bytes)
    EXPECT_FALSE(ok("0123456789abcdef01", ""));    // 18 chars (9 bytes): no silent truncation
    EXPECT_FALSE(ok("", "abcd"));                  // prefix without network id
    EXPECT_FALSE(ok("0", "abcd"));                 // prefix on the public identity
    EXPECT_FALSE(ok("abcd", "xyz1"));              // bad prefix
    EXPECT_FALSE(ok("abcd", "0123456789abcdef01")); // prefix > 8 bytes
    EXPECT_TRUE(ok("0123456789abcdef", ""));       // exactly 8 bytes
    EXPECT_TRUE(ok("abcd", "0badc0ffee11"));

    // Accepted values are lower-cased in place (canonical log / marker).
    std::string id = "ABCD", pfx = "0BADC0FFEE11", err;
    ASSERT_TRUE(dash::validate_network_id_args(id, pfx, err)) << err;
    EXPECT_EQ(id, "abcd");
    EXPECT_EQ(pfx, "0badc0ffee11");

    // A rejected value leaves the identity untouched (main() returns before
    // set_network_id).
    EXPECT_TRUE(SharechainConfig::override_identifier_hex.empty());
    EXPECT_EQ(SharechainConfig::identifier_hex(), MAIN_ID);
}

// ═════════════════════════════════════════════════════════════════════════════
// (d) Bootstrap precedence (mirror of btc regtest_sharechain_isolation_test).
// ═════════════════════════════════════════════════════════════════════════════
TEST(DashNetworkIdOverride, BootstrapModePrecedence) {
    using M = dash::SharechainBootstrapMode;
    EXPECT_EQ(dash::select_sharechain_bootstrap_mode(true,  false, true),  M::ExplicitPeers);
    EXPECT_EQ(dash::select_sharechain_bootstrap_mode(true,  false, false), M::ExplicitPeers);
    EXPECT_EQ(dash::select_sharechain_bootstrap_mode(false, false, true),  M::CustomNetSuppressed);
    EXPECT_EQ(dash::select_sharechain_bootstrap_mode(false, false, false), M::PublicDefault);
}
