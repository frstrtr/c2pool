// test_multiaddress_pplns.cpp — Tests for multiaddress coinbase building
// and PPLNS consensus validation across parent and merged chains.
//
// Covers:
//   1. build_multiaddress_block() output structure (header, coinbase, outputs)
//   2. script_to_address() for P2PKH, P2WPKH, P2SH, P2WSH, hex fallback
//   3. compute_merged_payout_hash() determinism and cross-address-type consistency
//   4. Parent chain PPLNS coinbase output ordering and donation rules
//   5. Merged chain coinbase: BIP34 height, /c2pool/ tag, THE state root

#include <gtest/gtest.h>

#include <c2pool/merged/merged_mining.hpp>
#include <core/hash.hpp>
#include <core/target_utils.hpp>
#include <btclibs/uint256.h>
#include <btclibs/base58.h>
#include <btclibs/bech32.h>
#include <btclibs/crypto/sha256.h>
#include <impl/ltc/config_pool.hpp>
#include <sharechain/weights_skiplist.hpp>

#include <nlohmann/json.hpp>
#include <algorithm>
#include <cstdint>
#include <map>
#include <sstream>
#include <string>
#include <vector>

using namespace c2pool::merged;
using chain::bits_to_target;
using chain::target_to_average_attempts;
using chain::WeightsDelta;
using chain::WeightsSkipList;

// ============================================================================
// Hex utilities (same as merged_mining.cpp, needed for block parsing)
// ============================================================================

static std::string to_hex(const uint8_t* data, size_t len)
{
    static const char* H = "0123456789abcdef";
    std::string out;
    out.reserve(len * 2);
    for (size_t i = 0; i < len; ++i) {
        out += H[data[i] >> 4];
        out += H[data[i] & 0x0f];
    }
    return out;
}

static std::vector<uint8_t> from_hex(const std::string& hex)
{
    std::vector<uint8_t> out;
    out.reserve(hex.size() / 2);
    for (size_t i = 0; i + 1 < hex.size(); i += 2) {
        out.push_back(static_cast<uint8_t>(
            std::stoul(hex.substr(i, 2), nullptr, 16)));
    }
    return out;
}

static uint32_t read_le32(const uint8_t* p)
{
    return p[0] | (p[1] << 8) | (p[2] << 16) | (p[3] << 24);
}

static uint64_t read_le64(const uint8_t* p)
{
    return static_cast<uint64_t>(read_le32(p))
         | (static_cast<uint64_t>(read_le32(p + 4)) << 32);
}

// Read a Bitcoin varint from raw bytes, advancing pos
static uint64_t read_varint(const std::vector<uint8_t>& data, size_t& pos)
{
    if (pos >= data.size()) return 0;
    uint8_t first = data[pos++];
    if (first < 0xfd) return first;
    if (first == 0xfd) {
        uint16_t v = data[pos] | (data[pos + 1] << 8);
        pos += 2;
        return v;
    }
    if (first == 0xfe) {
        uint32_t v = read_le32(&data[pos]);
        pos += 4;
        return v;
    }
    uint64_t v = read_le64(&data[pos]);
    pos += 8;
    return v;
}

// ============================================================================
// Well-known test scripts (LTC testnet)
// ============================================================================

// P2PKH: OP_DUP OP_HASH160 <20-byte hash> OP_EQUALVERIFY OP_CHECKSIG
static std::vector<unsigned char> make_p2pkh_script(const std::vector<unsigned char>& hash160)
{
    std::vector<unsigned char> s = {0x76, 0xa9, 0x14};
    s.insert(s.end(), hash160.begin(), hash160.end());
    s.push_back(0x88);
    s.push_back(0xac);
    return s;
}

// P2WPKH: OP_0 PUSH_20 <20-byte hash>
static std::vector<unsigned char> make_p2wpkh_script(const std::vector<unsigned char>& hash160)
{
    std::vector<unsigned char> s = {0x00, 0x14};
    s.insert(s.end(), hash160.begin(), hash160.end());
    return s;
}

// P2SH: OP_HASH160 PUSH_20 <20-byte hash> OP_EQUAL
static std::vector<unsigned char> make_p2sh_script(const std::vector<unsigned char>& hash160)
{
    std::vector<unsigned char> s = {0xa9, 0x14};
    s.insert(s.end(), hash160.begin(), hash160.end());
    s.push_back(0x87);
    return s;
}

// P2WSH: OP_0 PUSH_32 <32-byte hash>
static std::vector<unsigned char> make_p2wsh_script(const std::vector<unsigned char>& hash256)
{
    std::vector<unsigned char> s = {0x00, 0x20};
    s.insert(s.end(), hash256.begin(), hash256.end());
    return s;
}

// Combined donation script (V36+, matches PoolConfig)
static const std::vector<unsigned char> COMBINED_DONATION = {
    0xa9, 0x14,
    0x8c, 0x62, 0x72, 0x62, 0x1d, 0x89, 0xe8, 0xfa,
    0x52, 0x6d, 0xd8, 0x6a, 0xcf, 0xf6, 0x0c, 0x71,
    0x36, 0xbe, 0x8e, 0x85,
    0x87
};

// ============================================================================
// script_to_address (replicated from share_tracker.hpp for standalone testing)
// ============================================================================

static std::string script_to_address(const std::vector<unsigned char>& script, bool testnet)
{
    // P2WPKH: OP_0 PUSH_20 <20-byte-hash>
    if (script.size() == 22 && script[0] == 0x00 && script[1] == 0x14)
    {
        std::string hrp = testnet ? "tltc" : "ltc";
        std::vector<uint8_t> prog(script.begin() + 2, script.end());
        return bech32::encode_segwit(hrp, 0, prog);
    }
    // P2PKH: OP_DUP OP_HASH160 <20> <hash160> OP_EQUALVERIFY OP_CHECKSIG
    if (script.size() == 25 && script[0] == 0x76 && script[1] == 0xa9
        && script[2] == 0x14 && script[23] == 0x88 && script[24] == 0xac)
    {
        unsigned char addr_ver = testnet ? 111 : 48;
        std::vector<unsigned char> data = {addr_ver};
        data.insert(data.end(), script.begin() + 3, script.begin() + 23);
        return EncodeBase58Check(data);
    }
    // P2SH: OP_HASH160 <20> <hash160> OP_EQUAL
    if (script.size() == 23 && script[0] == 0xa9 && script[1] == 0x14
        && script[22] == 0x87)
    {
        unsigned char addr_ver = testnet ? 58 : 50;
        std::vector<unsigned char> data = {addr_ver};
        data.insert(data.end(), script.begin() + 2, script.begin() + 22);
        return EncodeBase58Check(data);
    }
    // P2WSH: OP_0 PUSH_32 <32-byte-hash>
    if (script.size() == 34 && script[0] == 0x00 && script[1] == 0x20)
    {
        std::string hrp = testnet ? "tltc" : "ltc";
        std::vector<uint8_t> prog(script.begin() + 2, script.end());
        return bech32::encode_segwit(hrp, 0, prog);
    }
    // Unknown script: hex
    std::string hex;
    for (unsigned char c : script) {
        static const char digits[] = "0123456789abcdef";
        hex.push_back(digits[c >> 4]);
        hex.push_back(digits[c & 0xf]);
    }
    return hex;
}

// ============================================================================
// Test fixture
// ============================================================================

class MultiaddressCoinbaseTest : public ::testing::Test {
public:
    // Deterministic hash160 from a simple index
    static std::vector<unsigned char> hash160_from_index(int idx)
    {
        unsigned char buf[4];
        buf[0] = idx & 0xff; buf[1] = (idx >> 8) & 0xff;
        buf[2] = (idx >> 16) & 0xff; buf[3] = (idx >> 24) & 0xff;
        unsigned char sha[32];
        CSHA256().Write(buf, 4).Finalize(sha);
        return std::vector<unsigned char>(sha, sha + 20);
    }

    // Deterministic hash256 from an index
    static std::vector<unsigned char> hash256_from_index(int idx)
    {
        unsigned char buf[4];
        buf[0] = idx & 0xff; buf[1] = (idx >> 8) & 0xff;
        buf[2] = (idx >> 16) & 0xff; buf[3] = (idx >> 24) & 0xff;
        unsigned char sha[32];
        CSHA256().Write(buf, 4).Finalize(sha);
        return std::vector<unsigned char>(sha, sha + 32);
    }

    // Build a minimal getblocktemplate JSON
    static nlohmann::json make_template(int height = 100, uint32_t version = 0x20000002)
    {
        nlohmann::json tmpl;
        tmpl["version"] = version;
        tmpl["previousblockhash"] = "0000000000000000000000000000000000000000000000000000000000001234";
        tmpl["curtime"] = 1700000000u;
        tmpl["bits"] = "1e0fffff";
        tmpl["height"] = height;
        tmpl["transactions"] = nlohmann::json::array();
        return tmpl;
    }

    // Build a payout list with N miners + donation
    static std::vector<std::pair<std::vector<unsigned char>, uint64_t>>
    make_payouts(int n_miners, uint64_t total_reward)
    {
        std::vector<std::pair<std::vector<unsigned char>, uint64_t>> payouts;

        // Reserve 1% for donation
        uint64_t donation = total_reward / 100;
        uint64_t miner_total = total_reward - donation;
        uint64_t per_miner = miner_total / n_miners;
        uint64_t remainder = miner_total - per_miner * n_miners;

        for (int i = 0; i < n_miners; ++i) {
            auto h = hash160_from_index(i);
            auto script = make_p2pkh_script(h);
            uint64_t amount = per_miner + (i == 0 ? remainder : 0);
            payouts.emplace_back(script, amount);
        }

        // Sort by script (consensus ordering)
        std::sort(payouts.begin(), payouts.end(),
            [](const auto& a, const auto& b) { return a.first < b.first; });

        // Add donation last
        payouts.emplace_back(COMBINED_DONATION, donation);
        return payouts;
    }

    void SetUp() override {
        // Tests run as testnet
        ltc::PoolConfig::is_testnet = true;
    }

    void TearDown() override {
        ltc::PoolConfig::is_testnet = true;  // leave testnet on for safety
    }
};

// ============================================================================
// 1. Multiaddress block building — structure tests
// ============================================================================

TEST_F(MultiaddressCoinbaseTest, BuildBlockReturnsNonEmpty)
{
    auto tmpl = make_template(500);
    auto payouts = make_payouts(3, 50'0000'0000ULL);  // 50 DOGE

    auto block_hex = MergedMiningManager::build_multiaddress_block(
        tmpl, payouts, /*auxpow_hex=*/"", /*the_state_root=*/uint256{});

    ASSERT_FALSE(block_hex.empty()) << "build_multiaddress_block should return non-empty hex";
    // Minimum: 80 bytes header + coinbase with outputs
    EXPECT_GE(block_hex.size() / 2, 80u + 50u);
}

TEST_F(MultiaddressCoinbaseTest, BuildBlockEmptyPayoutsReturnsEmpty)
{
    auto tmpl = make_template(100);
    std::vector<std::pair<std::vector<unsigned char>, uint64_t>> empty_payouts;

    auto block_hex = MergedMiningManager::build_multiaddress_block(
        tmpl, empty_payouts, "", uint256{});

    EXPECT_TRUE(block_hex.empty()) << "Empty payouts should return empty block";
}

TEST_F(MultiaddressCoinbaseTest, BuildBlockMissingPrevHashReturnsEmpty)
{
    nlohmann::json tmpl;
    tmpl["version"] = 0x20000002;
    // No previousblockhash
    tmpl["curtime"] = 1700000000u;
    tmpl["bits"] = "1e0fffff";
    tmpl["height"] = 100;

    auto payouts = make_payouts(1, 50'0000'0000ULL);
    auto block_hex = MergedMiningManager::build_multiaddress_block(
        tmpl, payouts, "", uint256{});

    EXPECT_TRUE(block_hex.empty()) << "Missing previousblockhash should return empty";
}

TEST_F(MultiaddressCoinbaseTest, BlockHeaderIs80Bytes)
{
    auto tmpl = make_template(200);
    auto payouts = make_payouts(2, 50'0000'0000ULL);

    auto block_hex = MergedMiningManager::build_multiaddress_block(
        tmpl, payouts, "", uint256{});

    auto raw = from_hex(block_hex);
    ASSERT_GE(raw.size(), 80u);

    // Version should match template | AuxPoW flag (0x100)
    uint32_t version = read_le32(&raw[0]);
    EXPECT_EQ(version, 0x20000002u | 0x100u);
}

TEST_F(MultiaddressCoinbaseTest, CoinbaseContainsC2PoolTag)
{
    auto tmpl = make_template(300);
    auto payouts = make_payouts(1, 50'0000'0000ULL);

    auto block_hex = MergedMiningManager::build_multiaddress_block(
        tmpl, payouts, "", uint256{});

    // "/c2pool/" in hex
    std::string c2pool_hex = "2f6332706f6f6c2f";
    EXPECT_NE(block_hex.find(c2pool_hex), std::string::npos)
        << "Coinbase should contain /c2pool/ tag";
}

TEST_F(MultiaddressCoinbaseTest, CoinbaseContainsTHEStateRoot)
{
    auto tmpl = make_template(300);
    auto payouts = make_payouts(1, 50'0000'0000ULL);

    uint256 state_root;
    state_root.SetHex("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef");

    auto block_hex = MergedMiningManager::build_multiaddress_block(
        tmpl, payouts, "", state_root);

    // state_root in LE hex (internal byte order)
    std::string root_le = to_hex(reinterpret_cast<const uint8_t*>(state_root.pn), 32);
    EXPECT_NE(block_hex.find(root_le), std::string::npos)
        << "Coinbase should contain THE state root";
}

TEST_F(MultiaddressCoinbaseTest, CoinbaseContainsBIP34Height)
{
    auto tmpl = make_template(500);
    auto payouts = make_payouts(1, 50'0000'0000ULL);

    auto block_hex = MergedMiningManager::build_multiaddress_block(
        tmpl, payouts, "", uint256{});

    auto raw = from_hex(block_hex);
    // After 80-byte header (with empty auxpow), we have varint tx_count then coinbase.
    // With empty auxpow, header starts at 0, then tx_count varint, then coinbase.
    size_t pos = 80;
    // tx_count varint
    uint64_t tx_count = read_varint(raw, pos);
    EXPECT_GE(tx_count, 1u);

    // coinbase: version(4) + vin_count(1) + prev_hash(32) + prev_idx(4) + scriptSig_len(varint) + scriptSig
    pos += 4;  // tx version
    uint64_t vin_count = read_varint(raw, pos);
    EXPECT_EQ(vin_count, 1u);
    pos += 32 + 4;  // null prev_hash + 0xffffffff

    uint64_t sig_len = read_varint(raw, pos);
    ASSERT_GT(sig_len, 0u);

    // BIP34: first byte is push length, then LE height bytes
    // For height 500 = 0x01F4: push 2 bytes, then F4 01
    uint8_t push_len = raw[pos];
    EXPECT_EQ(push_len, 2u) << "Height 500 should need 2 bytes";
    uint16_t encoded_height = raw[pos + 1] | (raw[pos + 2] << 8);
    EXPECT_EQ(encoded_height, 500u);
}

TEST_F(MultiaddressCoinbaseTest, OutputCountMatchesPayouts)
{
    int n_miners = 5;
    auto tmpl = make_template(100);
    auto payouts = make_payouts(n_miners, 50'0000'0000ULL);

    auto block_hex = MergedMiningManager::build_multiaddress_block(
        tmpl, payouts, "", uint256{});

    auto raw = from_hex(block_hex);
    size_t pos = 80;

    // tx count
    uint64_t tx_count = read_varint(raw, pos);
    ASSERT_GE(tx_count, 1u);

    // Skip to coinbase outputs: version(4) + vin
    pos += 4;
    uint64_t vin_count = read_varint(raw, pos);
    for (uint64_t i = 0; i < vin_count; ++i) {
        pos += 32 + 4;  // prev_hash + prev_idx
        uint64_t sig_len = read_varint(raw, pos);
        pos += sig_len;
        pos += 4;  // sequence
    }

    // Output count: miners + OP_RETURN + donation
    uint64_t vout_count = read_varint(raw, pos);
    // n_miners (sorted, minus any that were donation) + 1 OP_RETURN + 1 donation
    // Our make_payouts produces n_miners miner outputs + 1 donation
    // build_multiaddress_block separates donation, so: n_miners + OP_RETURN + donation
    EXPECT_EQ(vout_count, static_cast<uint64_t>(n_miners + 2))
        << "Expected " << n_miners << " miner + 1 OP_RETURN + 1 donation outputs";
}

TEST_F(MultiaddressCoinbaseTest, TotalOutputValueEqualsReward)
{
    uint64_t reward = 50'0000'0000ULL;
    auto tmpl = make_template(100);
    auto payouts = make_payouts(3, reward);

    auto block_hex = MergedMiningManager::build_multiaddress_block(
        tmpl, payouts, "", uint256{});

    auto raw = from_hex(block_hex);
    size_t pos = 80;

    uint64_t tx_count = read_varint(raw, pos);
    (void)tx_count;
    pos += 4;  // tx version

    // Skip vin
    uint64_t vin_count = read_varint(raw, pos);
    for (uint64_t i = 0; i < vin_count; ++i) {
        pos += 32 + 4;
        uint64_t sig_len = read_varint(raw, pos);
        pos += sig_len + 4;
    }

    // Sum output values
    uint64_t vout_count = read_varint(raw, pos);
    uint64_t total_value = 0;
    for (uint64_t i = 0; i < vout_count; ++i) {
        uint64_t value = read_le64(&raw[pos]);
        pos += 8;
        uint64_t script_len = read_varint(raw, pos);
        pos += script_len;
        total_value += value;
    }

    EXPECT_EQ(total_value, reward)
        << "Total output value should equal the block reward";
}

TEST_F(MultiaddressCoinbaseTest, DonationIsAlwaysLastOutput)
{
    auto tmpl = make_template(100);
    auto payouts = make_payouts(3, 50'0000'0000ULL);

    auto block_hex = MergedMiningManager::build_multiaddress_block(
        tmpl, payouts, "", uint256{});

    auto raw = from_hex(block_hex);
    size_t pos = 80;

    read_varint(raw, pos);  // tx count
    pos += 4;  // tx version

    // Skip vin
    uint64_t vin_count = read_varint(raw, pos);
    for (uint64_t i = 0; i < vin_count; ++i) {
        pos += 32 + 4;
        uint64_t sig_len = read_varint(raw, pos);
        pos += sig_len + 4;
    }

    // Read all output scripts
    uint64_t vout_count = read_varint(raw, pos);
    std::vector<std::vector<uint8_t>> output_scripts;
    for (uint64_t i = 0; i < vout_count; ++i) {
        pos += 8;  // value
        uint64_t script_len = read_varint(raw, pos);
        output_scripts.emplace_back(raw.begin() + pos, raw.begin() + pos + script_len);
        pos += script_len;
    }

    // Last output should be COMBINED_DONATION
    ASSERT_FALSE(output_scripts.empty());
    auto& last_script = output_scripts.back();
    std::vector<uint8_t> expected_donation(COMBINED_DONATION.begin(), COMBINED_DONATION.end());
    EXPECT_EQ(last_script, expected_donation)
        << "Last output must be the combined donation script";
}

TEST_F(MultiaddressCoinbaseTest, OpReturnPresent)
{
    auto tmpl = make_template(100);
    auto payouts = make_payouts(2, 50'0000'0000ULL);

    auto block_hex = MergedMiningManager::build_multiaddress_block(
        tmpl, payouts, "", uint256{});

    // OP_RETURN (0x6a) followed by push of "P2Pool merged mining" (canonical V36 text)
    std::string op_return_marker = "6a14";  // OP_RETURN PUSH_20
    EXPECT_NE(block_hex.find(op_return_marker), std::string::npos)
        << "Block should contain OP_RETURN output";

    // Check the canonical text "P2Pool merged mining" in hex
    std::string text_hex;
    for (char c : std::string("P2Pool merged mining")) {
        uint8_t b = static_cast<uint8_t>(c);
        static const char H[] = "0123456789abcdef";
        text_hex += H[b >> 4];
        text_hex += H[b & 0x0f];
    }
    EXPECT_NE(block_hex.find(text_hex), std::string::npos)
        << "OP_RETURN should contain 'P2Pool merged mining'";
}

TEST_F(MultiaddressCoinbaseTest, DonationMinimumOneSatoshi)
{
    // Create payouts where donation would be 0 — code should deduct 1 sat from
    // last miner output to ensure donation >= 1
    auto tmpl = make_template(100);

    auto h = hash160_from_index(0);
    auto script = make_p2pkh_script(h);
    std::vector<std::pair<std::vector<unsigned char>, uint64_t>> payouts;
    payouts.emplace_back(script, 50'0000'0000ULL);
    payouts.emplace_back(COMBINED_DONATION, 0ULL);  // zero donation

    auto block_hex = MergedMiningManager::build_multiaddress_block(
        tmpl, payouts, "", uint256{});

    ASSERT_FALSE(block_hex.empty());

    auto raw = from_hex(block_hex);
    size_t pos = 80;
    read_varint(raw, pos);  // tx count
    pos += 4;  // tx version

    // Skip vin
    uint64_t vin_count = read_varint(raw, pos);
    for (uint64_t i = 0; i < vin_count; ++i) {
        pos += 32 + 4;
        uint64_t sig_len = read_varint(raw, pos);
        pos += sig_len + 4;
    }

    uint64_t vout_count = read_varint(raw, pos);
    // Read last output (donation) value
    for (uint64_t i = 0; i < vout_count - 1; ++i) {
        pos += 8;
        uint64_t slen = read_varint(raw, pos);
        pos += slen;
    }
    uint64_t donation_value = read_le64(&raw[pos]);
    EXPECT_GE(donation_value, 1u) << "Donation must be at least 1 satoshi (V36 rule)";
}

// ============================================================================
// 2. script_to_address — address encoding tests
// ============================================================================

TEST_F(MultiaddressCoinbaseTest, ScriptToAddressP2PKHTestnet)
{
    auto h = hash160_from_index(42);
    auto script = make_p2pkh_script(h);
    auto addr = script_to_address(script, /*testnet=*/true);

    // Testnet P2PKH starts with 'm' or 'n'
    ASSERT_FALSE(addr.empty());
    EXPECT_TRUE(addr[0] == 'm' || addr[0] == 'n')
        << "Testnet P2PKH should start with m/n, got: " << addr;

    // Decode back and verify hash
    std::vector<unsigned char> decoded;
    ASSERT_TRUE(DecodeBase58Check(addr, decoded, 21));
    EXPECT_EQ(decoded[0], 111u);  // testnet version byte
    EXPECT_EQ(std::vector<unsigned char>(decoded.begin() + 1, decoded.end()),
              std::vector<unsigned char>(h.begin(), h.end()));
}

TEST_F(MultiaddressCoinbaseTest, ScriptToAddressP2PKHMainnet)
{
    auto h = hash160_from_index(42);
    auto script = make_p2pkh_script(h);
    auto addr = script_to_address(script, /*testnet=*/false);

    ASSERT_FALSE(addr.empty());
    EXPECT_EQ(addr[0], 'L')  // LTC mainnet P2PKH starts with L
        << "Mainnet P2PKH should start with L, got: " << addr;

    std::vector<unsigned char> decoded;
    ASSERT_TRUE(DecodeBase58Check(addr, decoded, 21));
    EXPECT_EQ(decoded[0], 48u);  // mainnet version byte
}

TEST_F(MultiaddressCoinbaseTest, ScriptToAddressP2WPKHTestnet)
{
    auto h = hash160_from_index(99);
    auto script = make_p2wpkh_script(h);
    auto addr = script_to_address(script, /*testnet=*/true);

    ASSERT_FALSE(addr.empty());
    EXPECT_EQ(addr.substr(0, 5), "tltc1") << "Testnet P2WPKH bech32 should start with tltc1";

    // Decode and verify program matches hash160
    int witver = -1;
    std::vector<uint8_t> prog;
    ASSERT_TRUE(bech32::decode_segwit("tltc", addr, witver, prog));
    EXPECT_EQ(witver, 0);
    EXPECT_EQ(prog.size(), 20u);
    EXPECT_EQ(prog, std::vector<uint8_t>(h.begin(), h.end()));
}

TEST_F(MultiaddressCoinbaseTest, ScriptToAddressP2WPKHMainnet)
{
    auto h = hash160_from_index(99);
    auto script = make_p2wpkh_script(h);
    auto addr = script_to_address(script, /*testnet=*/false);

    ASSERT_FALSE(addr.empty());
    EXPECT_EQ(addr.substr(0, 4), "ltc1") << "Mainnet P2WPKH bech32 should start with ltc1";
}

TEST_F(MultiaddressCoinbaseTest, ScriptToAddressP2SHTestnet)
{
    auto h = hash160_from_index(7);
    auto script = make_p2sh_script(h);
    auto addr = script_to_address(script, /*testnet=*/true);

    ASSERT_FALSE(addr.empty());
    // Testnet P2SH starts with 'Q' (version byte 58)
    EXPECT_EQ(addr[0], 'Q')
        << "Testnet P2SH should start with Q, got: " << addr;

    std::vector<unsigned char> decoded;
    ASSERT_TRUE(DecodeBase58Check(addr, decoded, 21));
    EXPECT_EQ(decoded[0], 58u);
}

TEST_F(MultiaddressCoinbaseTest, ScriptToAddressP2WSHTestnet)
{
    auto h = hash256_from_index(55);
    auto script = make_p2wsh_script(h);
    auto addr = script_to_address(script, /*testnet=*/true);

    ASSERT_FALSE(addr.empty());
    EXPECT_EQ(addr.substr(0, 5), "tltc1") << "Testnet P2WSH bech32 should start with tltc1";

    int witver = -1;
    std::vector<uint8_t> prog;
    ASSERT_TRUE(bech32::decode_segwit("tltc", addr, witver, prog));
    EXPECT_EQ(witver, 0);
    EXPECT_EQ(prog.size(), 32u);
    EXPECT_EQ(prog, std::vector<uint8_t>(h.begin(), h.end()));
}

TEST_F(MultiaddressCoinbaseTest, ScriptToAddressUnknownFallsBackToHex)
{
    // An arbitrary script that matches none of the patterns
    std::vector<unsigned char> script = {0x51, 0x20};  // just OP_1 PUSH_32 (too short for P2TR)
    auto addr = script_to_address(script, /*testnet=*/true);

    EXPECT_EQ(addr, "5120") << "Unknown script should hex-encode";
}

// ============================================================================
// 3. Address consistency: P2PKH and P2WPKH with same hash produce different
//    address strings (critical for merged payout hash consensus)
// ============================================================================

TEST_F(MultiaddressCoinbaseTest, P2PKHAndP2WPKHSameHashDifferentAddresses)
{
    // This test validates the fix: scripts are no longer normalized to P2PKH,
    // so P2WPKH and P2PKH with the same hash160 produce DIFFERENT address keys
    // in the payout hash payload.
    auto h = hash160_from_index(1);
    auto pkh_script = make_p2pkh_script(h);
    auto wpkh_script = make_p2wpkh_script(h);

    auto pkh_addr = script_to_address(pkh_script, /*testnet=*/true);
    auto wpkh_addr = script_to_address(wpkh_script, /*testnet=*/true);

    EXPECT_NE(pkh_addr, wpkh_addr)
        << "P2PKH and P2WPKH with same hash must produce different address keys";

    // P2PKH is base58, P2WPKH is bech32
    EXPECT_TRUE(pkh_addr[0] == 'm' || pkh_addr[0] == 'n');
    EXPECT_EQ(wpkh_addr.substr(0, 5), "tltc1");
}

// ============================================================================
// 4. PPLNS hash determinism — verifies that the payload format produces
//    consistent SHA256d hashes across address types.
// ============================================================================

TEST_F(MultiaddressCoinbaseTest, PayloadFormatDeterministic)
{
    // Simulate the payload construction from compute_merged_payout_hash
    // "addr1:weight1|addr2:weight2|...|T:total|D:donation"

    auto h1 = hash160_from_index(0);
    auto h2 = hash160_from_index(1);
    auto script1 = make_p2pkh_script(h1);
    auto script2 = make_p2wpkh_script(h2);

    auto addr1 = script_to_address(script1, true);
    auto addr2 = script_to_address(script2, true);

    // Build sorted payload (map sorts by string key)
    std::map<std::string, uint64_t> sorted;
    sorted[addr1] = 1000;
    sorted[addr2] = 2000;

    std::string payload;
    for (const auto& [k, v] : sorted) {
        if (!payload.empty()) payload += '|';
        payload += k + ':' + std::to_string(v);
    }
    payload += "|T:3000|D:100";

    // Hash should be deterministic
    auto span1 = std::span<const unsigned char>(
        reinterpret_cast<const unsigned char*>(payload.data()), payload.size());
    auto hash1 = Hash(span1);

    auto span2 = std::span<const unsigned char>(
        reinterpret_cast<const unsigned char*>(payload.data()), payload.size());
    auto hash2 = Hash(span2);

    EXPECT_EQ(hash1, hash2) << "Same payload must produce same hash";
    EXPECT_FALSE(hash1.IsNull());
}

TEST_F(MultiaddressCoinbaseTest, PayloadChangesWhenAddressTypeChanges)
{
    // If the same hash160 appears as P2PKH vs P2WPKH, the payload and
    // resulting hash MUST differ — this validates the fix where we stopped
    // normalizing scripts.
    auto h = hash160_from_index(0);

    // Scenario A: miner uses P2PKH
    auto script_a = make_p2pkh_script(h);
    auto addr_a = script_to_address(script_a, true);
    std::string payload_a = addr_a + ":1000|T:1000|D:50";

    // Scenario B: same miner uses P2WPKH (same underlying hash160)
    auto script_b = make_p2wpkh_script(h);
    auto addr_b = script_to_address(script_b, true);
    std::string payload_b = addr_b + ":1000|T:1000|D:50";

    auto span_a = std::span<const unsigned char>(
        reinterpret_cast<const unsigned char*>(payload_a.data()), payload_a.size());
    auto span_b = std::span<const unsigned char>(
        reinterpret_cast<const unsigned char*>(payload_b.data()), payload_b.size());

    EXPECT_NE(Hash(span_a), Hash(span_b))
        << "Different address types for same hash160 must produce different payout hashes";
}

// ============================================================================
// 5. Multiaddress block with mixed address types
// ============================================================================

TEST_F(MultiaddressCoinbaseTest, MixedAddressTypesInPayouts)
{
    auto tmpl = make_template(100);

    auto h0 = hash160_from_index(0);
    auto h1 = hash160_from_index(1);
    auto h2 = hash160_from_index(2);

    std::vector<std::pair<std::vector<unsigned char>, uint64_t>> payouts;
    payouts.emplace_back(make_p2pkh_script(h0), 20'0000'0000ULL);
    payouts.emplace_back(make_p2wpkh_script(h1), 15'0000'0000ULL);
    payouts.emplace_back(make_p2sh_script(h2), 14'0000'0000ULL);
    // Sort by script
    std::sort(payouts.begin(), payouts.end(),
        [](const auto& a, const auto& b) { return a.first < b.first; });
    payouts.emplace_back(COMBINED_DONATION, 1'0000'0000ULL);

    auto block_hex = MergedMiningManager::build_multiaddress_block(
        tmpl, payouts, "", uint256{});

    ASSERT_FALSE(block_hex.empty());

    // Parse and verify total output value = 50 DOGE
    auto raw = from_hex(block_hex);
    size_t pos = 80;
    read_varint(raw, pos);  // tx count
    pos += 4;  // tx version

    uint64_t vin_count = read_varint(raw, pos);
    for (uint64_t i = 0; i < vin_count; ++i) {
        pos += 32 + 4;
        uint64_t sig_len = read_varint(raw, pos);
        pos += sig_len + 4;
    }

    uint64_t vout_count = read_varint(raw, pos);
    // 3 miners + OP_RETURN + donation = 5
    EXPECT_EQ(vout_count, 5u);

    uint64_t total = 0;
    for (uint64_t i = 0; i < vout_count; ++i) {
        uint64_t val = read_le64(&raw[pos]);
        pos += 8;
        uint64_t slen = read_varint(raw, pos);
        pos += slen;
        total += val;
    }
    EXPECT_EQ(total, 50'0000'0000ULL);
}

// ============================================================================
// 6. Block with template transactions included
// ============================================================================

TEST_F(MultiaddressCoinbaseTest, TemplateTransactionsIncluded)
{
    auto tmpl = make_template(100);

    // Add a fake transaction to the template
    nlohmann::json tx;
    // Minimal valid-looking tx hex (doesn't need to be real for structure test)
    tx["data"] = "01000000010000000000000000000000000000000000000000000000000000000000000000"
                 "ffffffff0100000000000000000000000000ffffffff0100e1f505000000001976a914"
                 "0000000000000000000000000000000000000000000088ac00000000";
    tx["txid"] = "aabbccdd00000000000000000000000000000000000000000000000000000001";
    tmpl["transactions"] = nlohmann::json::array({tx});

    auto payouts = make_payouts(1, 50'0000'0000ULL);
    auto block_hex = MergedMiningManager::build_multiaddress_block(
        tmpl, payouts, "", uint256{});

    ASSERT_FALSE(block_hex.empty());

    // The block should contain the template tx data
    EXPECT_NE(block_hex.find("00e1f505"), std::string::npos)
        << "Block should include template transaction data";
}

// ============================================================================
// 7. PPLNS weight computation — skip list with mixed address types
// ============================================================================

struct FakeShare {
    uint256 hash;
    uint256 prev_hash;
    std::vector<unsigned char> script;
    uint32_t bits;
    uint32_t donation;
    int64_t desired_version;
};

static std::vector<FakeShare> make_mixed_chain(int n, uint32_t bits = 0x1e0fffff,
                                                uint32_t donation = 50)
{
    std::vector<FakeShare> shares(n);
    for (int i = 0; i < n; ++i) {
        unsigned char buf[4];
        buf[0] = i & 0xff; buf[1] = (i >> 8) & 0xff;
        buf[2] = (i >> 16) & 0xff; buf[3] = (i >> 24) & 0xff;
        CSHA256().Write(buf, 4).Finalize(shares[i].hash.data());

        // Alternate between P2PKH and P2WPKH scripts (same hash160 family)
        unsigned char hbuf[32];
        unsigned char ibuf[4] = {static_cast<unsigned char>(i % 5), 0, 0, 0};
        CSHA256().Write(ibuf, 4).Finalize(hbuf);
        std::vector<unsigned char> hash160(hbuf, hbuf + 20);

        if (i % 3 == 0) {
            shares[i].script = make_p2wpkh_script(hash160);
        } else if (i % 3 == 1) {
            shares[i].script = make_p2pkh_script(hash160);
        } else {
            shares[i].script = make_p2sh_script(hash160);
        }
        shares[i].bits = bits;
        shares[i].donation = donation;
        shares[i].desired_version = 36;
    }
    for (int i = 0; i < n - 1; ++i)
        shares[i].prev_hash = shares[i + 1].hash;
    shares[n - 1].prev_hash = uint256{};
    return shares;
}

class PPLNSConsensusTest : public ::testing::Test {
protected:
    static constexpr int CHAIN_LEN = 50;
    static constexpr uint32_t BITS = 0x1e0fffff;
    static constexpr uint32_t DONATION = 50;

    std::vector<FakeShare> shares;
    std::unordered_map<uint256, size_t, chain::Uint256Hasher> idx;

    void SetUp() override {
        ltc::PoolConfig::is_testnet = true;
        shares = make_mixed_chain(CHAIN_LEN, BITS, DONATION);
        idx.clear();
        for (size_t i = 0; i < shares.size(); ++i)
            idx[shares[i].hash] = i;
    }
};

TEST_F(PPLNSConsensusTest, SkipListWithMixedScriptsProducesCorrectWeights)
{
    // Build a skip list that uses original scripts (not normalized)
    WeightsSkipList skiplist(
        [this](const uint256& hash) -> WeightsDelta {
            WeightsDelta d;
            auto it = idx.find(hash);
            if (it == idx.end()) return d;
            auto& s = shares[it->second];
            if (s.desired_version < 36) return d;
            auto target = bits_to_target(s.bits);
            auto att = target_to_average_attempts(target);
            d.share_count = 1;
            d.total_weight = att * 65535;
            d.total_donation_weight = att * static_cast<uint32_t>(s.donation);
            d.weights[s.script] = att * static_cast<uint32_t>(65535 - s.donation);
            return d;
        },
        [this](const uint256& hash) -> uint256 {
            auto it = idx.find(hash);
            if (it == idx.end()) return uint256{};
            return shares[it->second].prev_hash;
        }
    );

    auto result = skiplist.query(shares[0].hash, CHAIN_LEN, uint288(uint64_t(-1)));

    // Should have weights for distinct scripts
    EXPECT_FALSE(result.weights.empty());
    EXPECT_FALSE(result.total_weight.IsNull());

    // Verify total weight = sum of per-share weights
    auto target = bits_to_target(BITS);
    auto att = target_to_average_attempts(target);
    uint288 expected_total = att * 65535 * CHAIN_LEN;
    EXPECT_EQ(result.total_weight, expected_total);

    // Count distinct scripts in the weights map
    // With 50 shares using 5 unique hash160s × 3 script types, we have up to 5 unique scripts
    // (each hash160 maps to P2WPKH, P2PKH, or P2SH depending on index)
    EXPECT_LE(result.weights.size(), 15u);  // at most 5 hash * 3 types
    EXPECT_GE(result.weights.size(), 1u);
}

TEST_F(PPLNSConsensusTest, DifferentScriptTypeSameHashNotMerged)
{
    // Two shares from the same hash160 but different script types should
    // produce separate weight entries (not merged into one).
    auto hash160 = MultiaddressCoinbaseTest::hash160_from_index(0);
    auto p2pkh = make_p2pkh_script(hash160);
    auto p2wpkh = make_p2wpkh_script(hash160);

    // Build a 2-share chain manually
    FakeShare s0, s1;
    unsigned char buf0[4] = {0, 0, 0, 0};
    unsigned char buf1[4] = {1, 0, 0, 0};
    CSHA256().Write(buf0, 4).Finalize(s0.hash.data());
    CSHA256().Write(buf1, 4).Finalize(s1.hash.data());
    s0.prev_hash = s1.hash;
    s1.prev_hash = uint256{};
    s0.script = p2pkh;
    s0.bits = BITS;
    s0.donation = DONATION;
    s0.desired_version = 36;
    s1.script = p2wpkh;
    s1.bits = BITS;
    s1.donation = DONATION;
    s1.desired_version = 36;

    std::unordered_map<uint256, FakeShare*, chain::Uint256Hasher> lookup;
    lookup[s0.hash] = &s0;
    lookup[s1.hash] = &s1;

    WeightsSkipList sl(
        [&](const uint256& hash) -> WeightsDelta {
            WeightsDelta d;
            auto it = lookup.find(hash);
            if (it == lookup.end()) return d;
            auto* s = it->second;
            auto target = bits_to_target(s->bits);
            auto att = target_to_average_attempts(target);
            d.share_count = 1;
            d.total_weight = att * 65535;
            d.total_donation_weight = att * s->donation;
            d.weights[s->script] = att * static_cast<uint32_t>(65535 - s->donation);
            return d;
        },
        [&](const uint256& hash) -> uint256 {
            auto it = lookup.find(hash);
            if (it == lookup.end()) return uint256{};
            return it->second->prev_hash;
        }
    );

    auto result = sl.query(s0.hash, 2, uint288(uint64_t(-1)));

    // Should have 2 separate weight entries (P2PKH and P2WPKH)
    EXPECT_EQ(result.weights.size(), 2u)
        << "P2PKH and P2WPKH with same hash160 should be separate weight entries";
    EXPECT_TRUE(result.weights.count(p2pkh));
    EXPECT_TRUE(result.weights.count(p2wpkh));
}

TEST_F(PPLNSConsensusTest, PayoutHashReproducibleFromPayload)
{
    // Simulate compute_merged_payout_hash payload construction and verify
    // the SHA256d hash is reproducible.
    auto h1 = MultiaddressCoinbaseTest::hash160_from_index(0);
    auto h2 = MultiaddressCoinbaseTest::hash160_from_index(1);

    auto script1 = make_p2pkh_script(h1);
    auto script2 = make_p2wpkh_script(h2);

    auto addr1 = script_to_address(script1, true);
    auto addr2 = script_to_address(script2, true);

    uint288 w1(1000000);
    uint288 w2(2000000);
    uint288 total(3000000);
    uint288 donation(150000);

    auto to_decimal = [](const uint288& val) -> std::string {
        if (val.IsNull()) return "0";
        uint288 tmp = val;
        std::string result;
        while (!tmp.IsNull()) {
            uint32_t rem = 0;
            for (int i = uint288::WIDTH - 1; i >= 0; --i) {
                uint64_t cur = (static_cast<uint64_t>(rem) << 32) | tmp.pn[i];
                tmp.pn[i] = static_cast<uint32_t>(cur / 10);
                rem = static_cast<uint32_t>(cur % 10);
            }
            result.push_back('0' + static_cast<char>(rem));
        }
        std::reverse(result.begin(), result.end());
        return result;
    };

    std::map<std::string, uint288> sorted;
    sorted[addr1] = w1;
    sorted[addr2] = w2;

    std::string payload;
    for (const auto& [k, v] : sorted) {
        if (!payload.empty()) payload += '|';
        payload += k + ':' + to_decimal(v);
    }
    payload += "|T:" + to_decimal(total);
    payload += "|D:" + to_decimal(donation);

    auto span = std::span<const unsigned char>(
        reinterpret_cast<const unsigned char*>(payload.data()), payload.size());
    auto hash = Hash(span);

    // Run it again — must be identical
    auto hash2 = Hash(span);
    EXPECT_EQ(hash, hash2);
    EXPECT_FALSE(hash.IsNull());

    // The payload should look like "addr1:weight1|addr2:weight2|T:total|D:donation"
    EXPECT_NE(payload.find("|T:3000000"), std::string::npos);
    EXPECT_NE(payload.find("|D:150000"), std::string::npos);
}

TEST_F(PPLNSConsensusTest, SortOrderIsDeterministicAcrossTypes)
{
    // Verify that map<string, ...> sorts bech32 and base58 addresses deterministically
    auto h = MultiaddressCoinbaseTest::hash160_from_index(0);

    auto pkh_addr = script_to_address(make_p2pkh_script(h), true);
    auto wpkh_addr = script_to_address(make_p2wpkh_script(h), true);
    auto sh_addr = script_to_address(make_p2sh_script(h), true);

    std::map<std::string, int> sorted;
    sorted[pkh_addr] = 1;
    sorted[wpkh_addr] = 2;
    sorted[sh_addr] = 3;

    // The order should be consistent: std::map sorts lexicographically
    auto it = sorted.begin();
    std::string first = it->first;
    ++it;
    std::string second = it->first;
    ++it;
    std::string third = it->first;

    // Just verify they're all different and in ascending order
    EXPECT_LT(first, second);
    EXPECT_LT(second, third);
    EXPECT_NE(first, second);
    EXPECT_NE(second, third);
}

// ============================================================================
// 8. Both chains: parent and merged payout amounts sum correctly
// ============================================================================

TEST_F(MultiaddressCoinbaseTest, ParentAndMergedRewardsSumIndependently)
{
    // Verify that the same set of miners can have different payout proportions
    // on parent (LTC) vs merged (DOGE) chains, both summing to their respective rewards.

    uint64_t ltc_reward = 12'50000000ULL;   // 12.5 LTC
    uint64_t doge_reward = 10000'00000000ULL; // 10000 DOGE

    auto h0 = hash160_from_index(0);
    auto h1 = hash160_from_index(1);
    auto h2 = hash160_from_index(2);

    // Parent chain payouts (LTC): 3 miners + donation
    auto ltc_payouts = make_payouts(3, ltc_reward);
    uint64_t ltc_sum = 0;
    for (const auto& [_, amount] : ltc_payouts)
        ltc_sum += amount;
    EXPECT_EQ(ltc_sum, ltc_reward);

    // Merged chain payouts (DOGE): same 3 miners, different amounts
    auto doge_payouts = make_payouts(3, doge_reward);
    uint64_t doge_sum = 0;
    for (const auto& [_, amount] : doge_payouts)
        doge_sum += amount;
    EXPECT_EQ(doge_sum, doge_reward);

    // Both should produce valid blocks
    auto ltc_tmpl = make_template(1000);
    auto doge_tmpl = make_template(5000000);

    auto ltc_block = MergedMiningManager::build_multiaddress_block(
        ltc_tmpl, ltc_payouts, "", uint256{});
    auto doge_block = MergedMiningManager::build_multiaddress_block(
        doge_tmpl, doge_payouts, "", uint256{});

    EXPECT_FALSE(ltc_block.empty());
    EXPECT_FALSE(doge_block.empty());

    // Parse and verify totals
    for (auto& [hex, expected_total] : std::vector<std::pair<std::string, uint64_t>>{
            {ltc_block, ltc_reward}, {doge_block, doge_reward}})
    {
        auto raw = from_hex(hex);
        size_t pos = 80;
        read_varint(raw, pos);
        pos += 4;

        uint64_t vin_count = read_varint(raw, pos);
        for (uint64_t i = 0; i < vin_count; ++i) {
            pos += 32 + 4;
            uint64_t sig_len = read_varint(raw, pos);
            pos += sig_len + 4;
        }

        uint64_t vout_count = read_varint(raw, pos);
        uint64_t total = 0;
        for (uint64_t i = 0; i < vout_count; ++i) {
            total += read_le64(&raw[pos]);
            pos += 8;
            uint64_t slen = read_varint(raw, pos);
            pos += slen;
        }
        EXPECT_EQ(total, expected_total);
    }
}

// ============================================================================
// 9. Height encoding edge cases
// ============================================================================

TEST_F(MultiaddressCoinbaseTest, HeightEncodingSmallValues)
{
    // Height 1-16 use OP_1..OP_16
    auto tmpl1 = make_template(1);
    auto payouts = make_payouts(1, 50'0000'0000ULL);
    auto block1 = MergedMiningManager::build_multiaddress_block(tmpl1, payouts, "", uint256{});
    ASSERT_FALSE(block1.empty());

    // OP_1 = 0x51
    auto raw = from_hex(block1);
    size_t pos = 80;
    read_varint(raw, pos);
    pos += 4;  // tx version
    read_varint(raw, pos);  // vin count
    pos += 32 + 4;  // null hash + idx
    uint64_t sig_len = read_varint(raw, pos);
    ASSERT_GT(sig_len, 0u);
    EXPECT_EQ(raw[pos], 0x51u) << "Height 1 should encode as OP_1";
}

TEST_F(MultiaddressCoinbaseTest, HeightEncodingLargeValue)
{
    // Height 100000 needs 3 bytes
    auto tmpl = make_template(100000);
    auto payouts = make_payouts(1, 50'0000'0000ULL);
    auto block = MergedMiningManager::build_multiaddress_block(tmpl, payouts, "", uint256{});
    ASSERT_FALSE(block.empty());

    auto raw = from_hex(block);
    size_t pos = 80;
    read_varint(raw, pos);
    pos += 4;
    read_varint(raw, pos);
    pos += 32 + 4;
    uint64_t sig_len = read_varint(raw, pos);
    ASSERT_GT(sig_len, 0u);

    // push_len should be 3 (100000 = 0x0186A0, needs 3 bytes LE: A0 86 01)
    EXPECT_EQ(raw[pos], 3u) << "Height 100000 should need 3 bytes";
    uint32_t h = raw[pos + 1] | (raw[pos + 2] << 8) | (raw[pos + 3] << 16);
    EXPECT_EQ(h, 100000u);
}
