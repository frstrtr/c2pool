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
//   (d) sharechain bootstrap-mode precedence (btc parity);
//   (e) per-network on-disk state is identity-scoped: the data subdir is the
//       legacy "dash"/"dash_testnet" with no flag and "<legacy>_<id>_v36" with
//       one (keyed on the identity AND the share version it mints),
//       and a share persisted through the production SharechainStorage under
//       identity A is invisible to a node configured with identity B (or with
//       no flag), while A still finds it after switching back;
//   (f) the private/isolated DASH v36 sharechain profile: keyed on the custom
//       network id, exposes the v36 targets (share version 36, ratchet seed
//       3600, P2PKH v36 donation, maintainer-only message authority, future-
//       timestamp bound, emergency decay); the isolated CoinParams carry
//       current_share_version 36 (the chain mints and admits v36), the public
//       ones 16, and every no-flag CoinParams field is pinned byte-identical
//       to master.
//       (The future-timestamp bound IS consumed, by share_init_verify; its
//       KATs live in test_dash_v36_future_timestamp*.cpp, linked into this
//       same executable for the same process-global-identity reason.)
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
#include <impl/dash/share_messages.hpp>  // authority_pubkeys, hash160

#include <core/coin_params.hpp>
#include <core/version_gate.hpp>
#include <core/hash.hpp>
#include <core/pack.hpp>
#include <core/pack_types.hpp>
#include <core/uint256.hpp>
#include <btclibs/util/strencodings.h>  // ParseHexBytes, HexStr
#include <c2pool/storage/sharechain_storage.hpp>
#include <core/filesystem.hpp>

#include <chrono>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <memory>
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

// ── (f) goldens: independent literal transcriptions ────────────────────────
// DASH P2PKH DONATION_SCRIPT (oracle p2pool-dash data.py; share_check.hpp).
constexpr const char* P2PKH_DONATION_HEX =
    "76a914" "20cb5c22b1e4d5947e5c112c7696b51ad9af3c61" "88ac";
// Unified cross-coin v36 COMBINED P2SH (test_dash_donation_combined.cpp).
constexpr const char* COMBINED_DONATION_HEX =
    "a914" "8c6272621d89e8fa526dd86acff60c7136be8e85" "87";
// hash160 of the maintainer authority key == the P2PKH payee above.
constexpr const char* MAINTAINER_HASH160_HEX = "20cb5c22b1e4d5947e5c112c7696b51ad9af3c61";

// DASH mainnet genesis header -> X11 (main_dash.cpp selftest check_coin_params).
std::string x11_genesis_hex(const core::CoinParams& p) {
    unsigned char hdr[80];
    const uint32_t version = 1, time = 1390095618u, bits = 0x1e0ffff0u, nonce = 28917698u;
    uint256 prev;  prev.SetHex("0000000000000000000000000000000000000000000000000000000000000000");
    uint256 merk;  merk.SetHex("e0028eb9648db56b1ac77cf090b99048a8007e2bb64b68f092c03c7f56a662c7");
    size_t off = 0;
    std::memcpy(hdr + off, &version, 4);     off += 4;
    std::memcpy(hdr + off, prev.data(), 32); off += 32;
    std::memcpy(hdr + off, merk.data(), 32); off += 32;
    std::memcpy(hdr + off, &time, 4);        off += 4;
    std::memcpy(hdr + off, &bits, 4);        off += 4;
    std::memcpy(hdr + off, &nonce, 4);
    return p.pow_func(std::span<const unsigned char>(hdr, 80)).GetHex();
}

// Every CoinParams field make_coin_params() fills, pinned to master's values.
// `isolated` relaxes ONLY what the private/isolated profile is allowed to move:
// the identifier/prefix slots (network id override), the v36+ donation arm
// (P2PKH instead of COMBINED) and current_share_version (36: the isolated
// chain mints and admits v36). Everything else, including both
// protocol-version fields, must match master on BOTH profiles.
void expect_coin_params_master_fields(const core::CoinParams& p, bool testnet, bool isolated) {
    SCOPED_TRACE(std::string(testnet ? "testnet" : "mainnet") + (isolated ? " isolated" : " public"));
    EXPECT_EQ(p.symbol, "DASH");
    EXPECT_EQ(p.block_period, 150u);
    EXPECT_EQ(p.address_version,      testnet ? 140 : 76);
    EXPECT_EQ(p.address_p2sh_version, testnet ? 19 : 16);
    EXPECT_EQ(p.address_p2sh_version2, 0);
    EXPECT_EQ(p.bech32_hrp, "");
    EXPECT_EQ(p.dust_threshold, 100000u);
    EXPECT_TRUE(p.softforks_required.empty());
    EXPECT_EQ(p.segwit_activation_version, 0u);
    EXPECT_EQ(p.p2p_port,    testnet ? 18999 : 8999);
    EXPECT_EQ(p.worker_port, testnet ? 17903 : 7903);
    EXPECT_EQ(p.share_period, 20u);
    EXPECT_EQ(p.chain_length, 4320u);
    EXPECT_EQ(p.real_chain_length, 4320u);
    EXPECT_EQ(p.target_lookbehind, 100u);
    EXPECT_EQ(p.spread, 10u);
    EXPECT_EQ(p.minimum_protocol_version, 1700u);
    EXPECT_EQ(p.advertised_protocol_version, 3600u);
    EXPECT_EQ(p.block_max_size, 0u);
    EXPECT_EQ(p.block_max_weight, 0u);
    EXPECT_EQ(p.max_target.GetHex(), testnet
        ? "00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        : "00000000ffff0000000000000000000000000000000000000000000000000000");
    if (!isolated) {
        EXPECT_EQ(p.identifier_hex,         MAIN_ID);
        EXPECT_EQ(p.prefix_hex,             MAIN_PFX);
        EXPECT_EQ(p.testnet_identifier_hex, TEST_ID);
        EXPECT_EQ(p.testnet_prefix_hex,     TEST_PFX);
    }
    EXPECT_TRUE(p.bootstrap_addrs.empty());
    ASSERT_TRUE(static_cast<bool>(p.donation_script_func));
    for (int64_t v : {0, 1, 15, 16, 17, 35})
        EXPECT_EQ(hex_of_bytes(p.donation_script_func(v)), P2PKH_DONATION_HEX) << "v=" << v;
    for (int64_t v : {36, 37, 3600})
        EXPECT_EQ(hex_of_bytes(p.donation_script_func(v)),
                  isolated ? P2PKH_DONATION_HEX : COMBINED_DONATION_HEX) << "v=" << v;
    EXPECT_EQ(p.current_share_version, isolated ? 36u : 16u);
    EXPECT_EQ(p.is_testnet, testnet);
    // Vardiff: make_coin_params leaves the CoinParams defaults.
    EXPECT_DOUBLE_EQ(p.vardiff.target_share_rate, 3.0);
    EXPECT_EQ(p.vardiff.shares_trigger, 12u);
    EXPECT_DOUBLE_EQ(p.vardiff.timeout_mult, 10.0);
    EXPECT_EQ(p.vardiff.quickup_shares, 0u);
    EXPECT_DOUBLE_EQ(p.vardiff.quickup_divisor, 3.0);
    EXPECT_DOUBLE_EQ(p.vardiff.min_adjust, 0.1);
    EXPECT_DOUBLE_EQ(p.vardiff.max_adjust, 10.0);
    EXPECT_FALSE(p.vardiff.use_full_window);
    // Subsidy: 5 DASH, -1/14 per 210240 blocks, keyed on (height + 1).
    ASSERT_TRUE(static_cast<bool>(p.subsidy_func));
    EXPECT_EQ(p.subsidy_func(0),      500000000u);
    EXPECT_EQ(p.subsidy_func(210238), 500000000u);
    EXPECT_EQ(p.subsidy_func(210239), 464285715u);
    EXPECT_EQ(p.subsidy_func(210240), 464285715u);
    // X11 work AND block identity (genesis hash).
    ASSERT_TRUE(static_cast<bool>(p.pow_func));
    ASSERT_TRUE(static_cast<bool>(p.block_hash_func));
    EXPECT_EQ(x11_genesis_hex(p),
              "00000ffd590b1485b3caadc19b22e6379c733355108f107a430458cdf3407ab6");
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
    // The private/isolated chain mints and admits v36; the v16 DashShare
    // built below exercises the identifier move in the (unchanged) v16 ref
    // stream, which a peer on either identity would compute.
    EXPECT_EQ(pm.current_share_version, 36u);

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
    // Empty or ANY all-'0' spelling (any length, odd or even) is the public
    // network: an all-zero id left-pads to the same 16 zeros, so none of these
    // may become a private identity.
    for (const char* v : {"", "0", "00", "000", "0000", "00000000",
                          "0000000000000000", "00000000000000000"}) {
        SCOPED_TRACE(std::string("id=\"") + v + "\"");
        EXPECT_TRUE(SharechainConfig::is_public_network_id(v));
        SharechainConfig::set_network_id(v, "");
        EXPECT_TRUE(SharechainConfig::override_identifier_hex.empty());
        EXPECT_TRUE(SharechainConfig::override_prefix_hex.empty());
        EXPECT_FALSE(SharechainConfig::has_custom_network_id());
        EXPECT_EQ(SharechainConfig::identifier_hex(), MAIN_ID);
        EXPECT_EQ(SharechainConfig::data_subdir(false), "dash");

        // A prefix passed alongside a public spelling is ignored by
        // set_network_id (public = no override at all) ...
        SharechainConfig::set_network_id(v, "0badc0ffee11");
        EXPECT_TRUE(SharechainConfig::override_prefix_hex.empty());
        EXPECT_EQ(SharechainConfig::prefix_hex(), MAIN_PFX);

        // ... and validation accepts the bare spelling but rejects it with a
        // prefix (a prefix on the public identity only isolates the node).
        std::string id = v, pfx, err;
        EXPECT_TRUE(dash::validate_network_id_args(id, pfx, err)) << err;
        std::string id2 = v, pfx2 = "0badc0ffee11", err2;
        EXPECT_FALSE(dash::validate_network_id_args(id2, pfx2, err2));
    }
    // Not public: a single non-zero nibble anywhere.
    for (const char* v : {"01", "10", "0000000000000001", "1000000000000000"})
        EXPECT_FALSE(SharechainConfig::is_public_network_id(v)) << v;
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

    // Accepted values are lower-cased in place (canonical log / data subdir).
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

// ═════════════════════════════════════════════════════════════════════════════
// (e) Identity-scoped persistence. load_persisted_shares() (node.cpp) trusts
//     the stored hashes AND their is_verified flags, so a store written under
//     one identity must never be opened under another.
// ═════════════════════════════════════════════════════════════════════════════
TEST(DashNetworkIdOverride, DataSubdirIsIdentityScoped) {
    IdentityGuard g;
    // No flag: legacy subdirs, byte-identical to master's literal.
    EXPECT_EQ(SharechainConfig::data_subdir(false), "dash");
    EXPECT_EQ(SharechainConfig::data_subdir(true),  "dash_testnet");

    SharechainConfig::set_network_id("abcd", "");
    EXPECT_EQ(SharechainConfig::data_subdir(false), "dash_000000000000abcd_v36");
    EXPECT_EQ(SharechainConfig::data_subdir(true),  "dash_testnet_000000000000abcd_v36");

    // Keyed on the identifier, not the prefix: the ref_hash commits the
    // identifier, not the prefix, so a prefix change keeps the (still valid) store.
    SharechainConfig::reset_network_id();
    SharechainConfig::set_network_id("abcd", "0badc0ffee11");
    EXPECT_EQ(SharechainConfig::data_subdir(false), "dash_000000000000abcd_v36");

    SharechainConfig::reset_network_id();
    SharechainConfig::set_network_id("0123456789abcdef", "");
    EXPECT_EQ(SharechainConfig::data_subdir(false), "dash_0123456789abcdef_v36");

    SharechainConfig::reset_network_id();
    EXPECT_EQ(SharechainConfig::data_subdir(false), "dash");
}

// The version key: a custom identity's store is also keyed on the share
// version its chain mints ("_v36"), so the pre-v36 store of the same identity
// ("dash_<id>", what a build before the v36 flip wrote v16 rows into) is a
// DIFFERENT directory and is never opened by the v36 chain. The public
// (no-flag) subdirs carry no version key and are master's literals.
TEST(DashNetworkIdOverride, DataSubdirIsKeyedOnIdentityAndShareVersion) {
    IdentityGuard g;
    ASSERT_EQ(SharechainConfig::share_profile().target_share_version, 16u);
    EXPECT_EQ(SharechainConfig::data_subdir(false), "dash");
    EXPECT_EQ(SharechainConfig::data_subdir(true),  "dash_testnet");

    SharechainConfig::set_network_id("abcd", "");
    ASSERT_EQ(SharechainConfig::share_profile().target_share_version, 36u);
    const std::string pre_flip_mainnet = "dash_000000000000abcd";
    const std::string pre_flip_testnet = "dash_testnet_000000000000abcd";
    EXPECT_EQ(SharechainConfig::data_subdir(false), pre_flip_mainnet + "_v36");
    EXPECT_EQ(SharechainConfig::data_subdir(true),  pre_flip_testnet + "_v36");
    EXPECT_NE(SharechainConfig::data_subdir(false), pre_flip_mainnet);
    EXPECT_NE(SharechainConfig::data_subdir(true),  pre_flip_testnet);

    SharechainConfig::reset_network_id();
    EXPECT_EQ(SharechainConfig::data_subdir(false), "dash");
    EXPECT_EQ(SharechainConfig::data_subdir(true),  "dash_testnet");
}

TEST(DashNetworkIdOverride, PersistedShareDoesNotCrossIdentities) {
    namespace fs = std::filesystem;
    IdentityGuard g;

    // Private, per-test data dir (the process-wide --data-dir seam).
    const fs::path root = fs::temp_directory_path()
        / ("c2pool_dash_netid_kat_" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
    std::error_code ec;
    fs::remove_all(root, ec);
    fs::create_directories(root);
    core::filesystem::set_data_dir(root);

    uint256 h;
    h.SetHex("00000000000000000000000000000000000000000000000000000000c0ffee01");
    const std::vector<uint8_t> payload = {0x10, 0, 0, 0, 0, 0, 0, 0, 0xde, 0xad, 0xbe, 0xef};

    auto open_as = [](const std::string& id) {
        SharechainConfig::reset_network_id();
        SharechainConfig::set_network_id(id, "");
        const std::string sub = SharechainConfig::data_subdir(false);
        fs::create_directories(core::filesystem::config_path() / sub);
        return std::make_unique<c2pool::storage::SharechainStorage>(sub);
    };

    // Identity A persists one share.
    {
        auto a = open_as("aaaa");
        ASSERT_TRUE(a->is_available());
        ASSERT_TRUE(a->store_share(h, payload, uint256::ZERO, /*height=*/1,
                                   /*timestamp=*/1700000000, uint256::ONE, uint256::ONE));
        EXPECT_TRUE(a->has_share(h));
    }
    EXPECT_TRUE(fs::exists(root / "dash_000000000000aaaa_v36" / "sharechain_leveldb"));

    // Identity B: a different store, the share is invisible to the loader's scan.
    {
        auto b = open_as("bbbb");
        ASSERT_TRUE(b->is_available());
        EXPECT_FALSE(b->has_share(h));
        EXPECT_TRUE(b->get_shares_by_height_range(0, UINT64_MAX).empty());
    }
    EXPECT_TRUE(fs::exists(root / "dash_000000000000bbbb_v36" / "sharechain_leveldb"));

    // No flag (public identity): the legacy store, also blind to A's share.
    {
        auto pub = open_as("");
        ASSERT_TRUE(pub->is_available());
        EXPECT_FALSE(pub->has_share(h));
        EXPECT_TRUE(pub->get_shares_by_height_range(0, UINT64_MAX).empty());
    }
    EXPECT_TRUE(fs::exists(root / "dash" / "sharechain_leveldb"));

    // Reversible: switching back to A finds its own state untouched.
    {
        auto a2 = open_as("aaaa");
        ASSERT_TRUE(a2->is_available());
        EXPECT_TRUE(a2->has_share(h));
        const auto all = a2->get_shares_by_height_range(0, UINT64_MAX);
        ASSERT_EQ(all.size(), 1u);
        EXPECT_EQ(all[0], h);
    }

    core::filesystem::set_data_dir({});
    fs::remove_all(root, ec);
}

// ═════════════════════════════════════════════════════════════════════════════
// (f) Private/isolated DASH v36 sharechain profile.
// ═════════════════════════════════════════════════════════════════════════════

// Byte-identity PROOF for the public path: every make_coin_params field on the
// no-flag path equals master's literal value. Green on the base revision by
// design (it pins master); it fails if this slice (or any later one) moves a
// public CoinParams field.
TEST(DashNetworkIdOverride, NoFlagCoinParamsByteIdenticalToMaster) {
    IdentityGuard g;
    ASSERT_FALSE(SharechainConfig::has_custom_network_id());
    expect_coin_params_master_fields(dash::make_coin_params(false), false, false);
    expect_coin_params_master_fields(dash::make_coin_params(true),  true,  false);

    // pool.yaml overrides stay the only tunables, and only the three fields.
    dash::PoolOverrides o;
    o.p2p_port = 1234; o.worker_port = 5678; o.bootstrap_addrs = std::vector<std::string>{"a:1"};
    const auto po = dash::make_coin_params(false, o);
    EXPECT_EQ(po.p2p_port, 1234);
    EXPECT_EQ(po.worker_port, 5678);
    ASSERT_EQ(po.bootstrap_addrs.size(), 1u);
    EXPECT_EQ(po.current_share_version, 16u);
    EXPECT_EQ(hex_of_bytes(po.donation_script_func(36)), COMBINED_DONATION_HEX);

    // F1 ref stream / ref hash on the no-flag path (unchanged golden).
    const auto pm = dash::make_coin_params(false);
    const auto info = fixture_f1_info();
    EXPECT_EQ(hex_of_bytes(ref_stream_bytes(pm, info)), F1_REF_STREAM_HEX);
    EXPECT_EQ(hex_of(dash::producer::compute_ref_hash(pm, info)), F1_REF_HASH_HEX);
}

TEST(DashNetworkIdOverride, IsolatedProfileIsKeyedOnCustomNetworkId) {
    IdentityGuard g;
    EXPECT_FALSE(SharechainConfig::isolated_v36());

    // Every spelling of the public network is NEVER isolated.
    for (const char* v : {"", "0", "00", "000", "0000", "00000000",
                          "0000000000000000", "00000000000000000"}) {
        SCOPED_TRACE(std::string("id=\"") + v + "\"");
        SharechainConfig::set_network_id(v, "");
        EXPECT_FALSE(SharechainConfig::isolated_v36());
        SharechainConfig::set_network_id(v, "0badc0ffee11");
        EXPECT_FALSE(SharechainConfig::isolated_v36());
    }

    for (bool testnet : {false, true}) {
        SCOPED_TRACE(testnet ? "testnet" : "mainnet");
        SharechainConfig::reset_network_id();
        SharechainConfig::is_testnet = testnet;
        EXPECT_FALSE(SharechainConfig::isolated_v36());
        SharechainConfig::set_network_id("abcd");
        EXPECT_TRUE(SharechainConfig::isolated_v36());
        EXPECT_EQ(SharechainConfig::isolated_v36(), SharechainConfig::has_custom_network_id());
        SharechainConfig::reset_network_id();
        EXPECT_FALSE(SharechainConfig::isolated_v36());
    }
}

TEST(DashNetworkIdOverride, PublicProfileIsTheV16Baseline) {
    IdentityGuard g;
    const auto& prof = SharechainConfig::share_profile();
    EXPECT_EQ(&prof, &SharechainConfig::PUBLIC_PROFILE);
    EXPECT_EQ(prof.target_share_version, 16u);
    EXPECT_EQ(prof.ratchet_floor_protocol_version, 1700u);
    EXPECT_EQ(prof.advertised_protocol_version, 3600u);
    EXPECT_FALSE(prof.v36_donation_p2pkh);
    EXPECT_FALSE(prof.maintainer_only_authority);
    EXPECT_FALSE(prof.future_timestamp_bound);
    EXPECT_FALSE(prof.emergency_decay);

    // The public profile agrees with what the public CoinParams already carry.
    for (bool testnet : {false, true}) {
        const auto p = dash::make_coin_params(testnet);
        EXPECT_EQ(p.current_share_version,       prof.target_share_version);
        EXPECT_EQ(p.minimum_protocol_version,    prof.ratchet_floor_protocol_version);
        EXPECT_EQ(p.advertised_protocol_version, prof.advertised_protocol_version);
    }
}

TEST(DashNetworkIdOverride, IsolatedProfileExposesV36Targets) {
    IdentityGuard g;
    SharechainConfig::set_network_id("d3a5c0920263617", "0badc0ffee11");
    const auto& prof = SharechainConfig::share_profile();
    EXPECT_EQ(&prof, &SharechainConfig::ISOLATED_V36_PROFILE);
    EXPECT_EQ(prof.target_share_version, 36u);
    EXPECT_EQ(prof.ratchet_floor_protocol_version, 3600u);
    EXPECT_EQ(prof.advertised_protocol_version, 3600u);
    EXPECT_TRUE(prof.v36_donation_p2pkh);
    EXPECT_TRUE(prof.maintainer_only_authority);
    EXPECT_TRUE(prof.future_timestamp_bound);
    EXPECT_TRUE(prof.emergency_decay);

    for (bool testnet : {false, true}) {
        const auto p = dash::make_coin_params(testnet);
        // The flip: the isolated chain mints and admits the profile's target
        // share version, v36 (the public profile keeps 16,
        // PublicProfileIsTheV16Baseline).
        EXPECT_EQ(p.current_share_version, 36u);
        EXPECT_EQ(p.current_share_version, prof.target_share_version);
        // The cold floor stays 1700 (the 3600 seed goes to the node runtime,
        // not into CoinParams); the advert is 3600 on both profiles.
        EXPECT_EQ(p.minimum_protocol_version, 1700u);
        EXPECT_EQ(p.advertised_protocol_version, prof.advertised_protocol_version);
        // Identity behaviour unchanged by the profile.
        EXPECT_EQ(p.active_identifier_hex(), "0d3a5c0920263617");
        EXPECT_EQ(p.active_prefix_hex(),     "00000badc0ffee11");
        // Every other field is master's (identifier slots + v36 donation arm
        // are the only profile-dependent ones).
        expect_coin_params_master_fields(p, testnet, /*isolated=*/true);
    }

    SharechainConfig::reset_network_id();
    EXPECT_EQ(&SharechainConfig::share_profile(), &SharechainConfig::PUBLIC_PROFILE);
}

TEST(DashNetworkIdOverride, IsolatedV36DonationIsP2PKHPublicIsCombined) {
    IdentityGuard g;
    ASSERT_TRUE(core::version_gate::is_v36_active(36u));
    ASSERT_FALSE(core::version_gate::is_v36_active(35u));

    SharechainConfig::set_network_id("abcd");
    const auto iso_main = dash::make_coin_params(false);
    const auto iso_test = dash::make_coin_params(true);
    for (const auto* p : {&iso_main, &iso_test}) {
        EXPECT_EQ(p->donation_script_func(36), dash::DONATION_SCRIPT);
        EXPECT_EQ(p->donation_script_func(16), dash::DONATION_SCRIPT);
        EXPECT_NE(p->donation_script_func(36), dash::COMBINED_DONATION_SCRIPT);
    }

    SharechainConfig::reset_network_id();
    const auto pub = dash::make_coin_params(false);
    EXPECT_EQ(pub.donation_script_func(36), dash::COMBINED_DONATION_SCRIPT);
    EXPECT_EQ(pub.donation_script_func(16), dash::DONATION_SCRIPT);

    // Snapshot semantics (same contract as the copied identifier): params built
    // under the flag keep the P2PKH v36 arm after the identity is cleared.
    EXPECT_EQ(iso_main.donation_script_func(36), dash::DONATION_SCRIPT);
    EXPECT_EQ(iso_main.active_identifier_hex(), "000000000000abcd");
}

TEST(DashNetworkIdOverride, IsolatedAuthoritySetIsMaintainerOnlyAndPaysTheDonationScript) {
    IdentityGuard g;
    const auto iso = dash::authority_pubkeys(true);
    ASSERT_EQ(iso.size(), 1u);
    EXPECT_EQ(iso[0], &dash::DONATION_PUBKEY_MAINTAINER());

    const auto pub = dash::authority_pubkeys(false);
    ASSERT_EQ(pub.size(), 2u);
    EXPECT_EQ(pub.data(), dash::DONATION_AUTHORITY_PUBKEYS().data());
    EXPECT_EQ(pub[0], &dash::DONATION_PUBKEY_FORRESTV());
    EXPECT_EQ(pub[1], &dash::DONATION_PUBKEY_MAINTAINER());

    // The selector follows the profile flag.
    EXPECT_EQ(dash::authority_pubkeys(SharechainConfig::share_profile().maintainer_only_authority).size(), 2u);
    SharechainConfig::set_network_id("abcd");
    EXPECT_EQ(dash::authority_pubkeys(SharechainConfig::share_profile().maintainer_only_authority).size(), 1u);

    // Coherence: the sole isolated authority key IS the P2PKH donation payee.
    const auto& mk = dash::DONATION_PUBKEY_MAINTAINER();
    const auto mh = dash::hash160(mk.data(), mk.size());
    const std::vector<unsigned char> mhv(mh.begin(), mh.end());
    EXPECT_EQ(hex_of_bytes(mhv), MAINTAINER_HASH160_HEX);
    ASSERT_EQ(dash::DONATION_SCRIPT.size(), 25u);
    const std::vector<unsigned char> payee(dash::DONATION_SCRIPT.begin() + 3,
                                           dash::DONATION_SCRIPT.begin() + 23);
    EXPECT_EQ(mhv, payee);
    const auto& fk = dash::DONATION_PUBKEY_FORRESTV();
    const auto fh = dash::hash160(fk.data(), fk.size());
    EXPECT_NE(std::vector<unsigned char>(fh.begin(), fh.end()), payee);
}
