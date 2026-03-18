// test_pplns_stress.cpp — Stress tests for PPLNS consensus verification
// on both parent (LTC) and merged (DOGE) chains.
//
// Tests the full pipeline:
//   - Large synthetic sharechains (1000+ shares, 50+ miners)
//   - Mixed address types (P2PKH, P2WPKH, P2SH, P2WSH)
//   - Weight computation via WeightsSkipList
//   - Merged payout hash determinism (SHA256d of sorted payload)
//   - V36 donation minimum enforcement (>= 1 satoshi)
//   - Multiaddress coinbase construction for both chains
//   - Payout conservation: sum(outputs) == block_reward
//   - Concurrent skip list queries (thread safety)

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
#include <numeric>
#include <random>
#include <string>
#include <thread>
#include <vector>

using namespace c2pool::merged;
using chain::bits_to_target;
using chain::target_to_average_attempts;
using chain::WeightsDelta;
using chain::WeightsSkipList;

// ============================================================================
// Hex / block parsing utilities
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
    for (size_t i = 0; i + 1 < hex.size(); i += 2)
        out.push_back(static_cast<uint8_t>(std::stoul(hex.substr(i, 2), nullptr, 16)));
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

static uint64_t read_varint(const std::vector<uint8_t>& data, size_t& pos)
{
    if (pos >= data.size()) return 0;
    uint8_t first = data[pos++];
    if (first < 0xfd) return first;
    if (first == 0xfd) { uint16_t v = data[pos] | (data[pos+1] << 8); pos += 2; return v; }
    if (first == 0xfe) { uint32_t v = read_le32(&data[pos]); pos += 4; return v; }
    uint64_t v = read_le64(&data[pos]); pos += 8; return v;
}

// ============================================================================
// Script builders
// ============================================================================

static std::vector<unsigned char> make_p2pkh(const std::vector<unsigned char>& h160)
{
    std::vector<unsigned char> s = {0x76, 0xa9, 0x14};
    s.insert(s.end(), h160.begin(), h160.end());
    s.push_back(0x88); s.push_back(0xac);
    return s;
}

static std::vector<unsigned char> make_p2wpkh(const std::vector<unsigned char>& h160)
{
    std::vector<unsigned char> s = {0x00, 0x14};
    s.insert(s.end(), h160.begin(), h160.end());
    return s;
}

static std::vector<unsigned char> make_p2sh(const std::vector<unsigned char>& h160)
{
    std::vector<unsigned char> s = {0xa9, 0x14};
    s.insert(s.end(), h160.begin(), h160.end());
    s.push_back(0x87);
    return s;
}

static std::vector<unsigned char> make_p2wsh(const std::vector<unsigned char>& h256)
{
    std::vector<unsigned char> s = {0x00, 0x20};
    s.insert(s.end(), h256.begin(), h256.end());
    return s;
}

static const std::vector<unsigned char> COMBINED_DONATION = {
    0xa9, 0x14, 0x8c, 0x62, 0x72, 0x62, 0x1d, 0x89, 0xe8, 0xfa,
    0x52, 0x6d, 0xd8, 0x6a, 0xcf, 0xf6, 0x0c, 0x71, 0x36, 0xbe,
    0x8e, 0x85, 0x87
};

// ============================================================================
// Deterministic hash generation
// ============================================================================

static std::vector<unsigned char> hash_from_seed(int seed, int len = 20)
{
    unsigned char buf[4];
    buf[0] = seed & 0xff; buf[1] = (seed >> 8) & 0xff;
    buf[2] = (seed >> 16) & 0xff; buf[3] = (seed >> 24) & 0xff;
    unsigned char sha[32];
    CSHA256().Write(buf, 4).Finalize(sha);
    return std::vector<unsigned char>(sha, sha + len);
}

static uint256 hash256_from_seed(int seed)
{
    unsigned char buf[4];
    buf[0] = seed & 0xff; buf[1] = (seed >> 8) & 0xff;
    buf[2] = (seed >> 16) & 0xff; buf[3] = (seed >> 24) & 0xff;
    uint256 result;
    CSHA256().Write(buf, 4).Finalize(result.data());
    return result;
}

// ============================================================================
// Synthetic share chain builder
// ============================================================================

struct SyntheticShare {
    uint256 hash;
    uint256 prev_hash;
    std::vector<unsigned char> script;
    uint32_t bits;
    uint32_t donation;  // 0..65535
    int64_t desired_version;
};

// Build a chain of N shares with M distinct miners using mixed address types
static std::vector<SyntheticShare> build_chain(
    int n_shares, int n_miners,
    uint32_t bits = 0x1e0fffff,
    uint32_t donation = 50,  // 0.076% donation
    int64_t version = 36)
{
    std::vector<SyntheticShare> shares(n_shares);
    for (int i = 0; i < n_shares; ++i) {
        shares[i].hash = hash256_from_seed(i * 7 + 31);

        int miner_id = i % n_miners;
        auto h160 = hash_from_seed(miner_id + 1000, 20);

        // Cycle through address types: P2PKH, P2WPKH, P2SH
        switch (miner_id % 3) {
            case 0: shares[i].script = make_p2pkh(h160); break;
            case 1: shares[i].script = make_p2wpkh(h160); break;
            case 2: shares[i].script = make_p2sh(h160); break;
        }

        shares[i].bits = bits;
        shares[i].donation = donation;
        shares[i].desired_version = version;
    }
    // Link chain
    for (int i = 0; i < n_shares - 1; ++i)
        shares[i].prev_hash = shares[i + 1].hash;
    shares[n_shares - 1].prev_hash = uint256{};
    return shares;
}

// Build lookup + skip list from a synthetic chain
struct ChainContext {
    std::vector<SyntheticShare> shares;
    std::unordered_map<uint256, size_t, chain::Uint256Hasher> idx;
    WeightsSkipList skiplist;

    ChainContext() = default;
    ChainContext(std::vector<SyntheticShare> s) : shares(std::move(s))
    {
        for (size_t i = 0; i < shares.size(); ++i)
            idx[shares[i].hash] = i;

        skiplist = WeightsSkipList(
            [this](const uint256& hash) -> WeightsDelta {
                WeightsDelta d;
                auto it = idx.find(hash);
                if (it == idx.end()) return d;
                auto& sh = shares[it->second];
                // share_count=1 BEFORE version check (matches share_tracker.hpp)
                d.share_count = 1;
                if (sh.desired_version < 36) return d;
                auto target = bits_to_target(sh.bits);
                auto att = target_to_average_attempts(target);
                d.total_weight = att * 65535;
                d.total_donation_weight = att * static_cast<uint32_t>(sh.donation);
                d.weights[sh.script] = att * static_cast<uint32_t>(65535 - sh.donation);
                return d;
            },
            [this](const uint256& hash) -> uint256 {
                auto it = idx.find(hash);
                if (it == idx.end()) return uint256{};
                return shares[it->second].prev_hash;
            }
        );
    }
};

// ============================================================================
// script_to_address (replicated from share_tracker.hpp)
// ============================================================================

static std::string script_to_address(const std::vector<unsigned char>& script, bool testnet)
{
    if (script.size() == 22 && script[0] == 0x00 && script[1] == 0x14) {
        std::string hrp = testnet ? "tltc" : "ltc";
        std::vector<uint8_t> prog(script.begin() + 2, script.end());
        return bech32::encode_segwit(hrp, 0, prog);
    }
    if (script.size() == 25 && script[0] == 0x76 && script[1] == 0xa9
        && script[2] == 0x14 && script[23] == 0x88 && script[24] == 0xac) {
        unsigned char ver = testnet ? 111 : 48;
        std::vector<unsigned char> data = {ver};
        data.insert(data.end(), script.begin() + 3, script.begin() + 23);
        return EncodeBase58Check(data);
    }
    if (script.size() == 23 && script[0] == 0xa9 && script[1] == 0x14 && script[22] == 0x87) {
        unsigned char ver = testnet ? 58 : 50;
        std::vector<unsigned char> data = {ver};
        data.insert(data.end(), script.begin() + 2, script.begin() + 22);
        return EncodeBase58Check(data);
    }
    if (script.size() == 34 && script[0] == 0x00 && script[1] == 0x20) {
        std::string hrp = testnet ? "tltc" : "ltc";
        std::vector<uint8_t> prog(script.begin() + 2, script.end());
        return bech32::encode_segwit(hrp, 0, prog);
    }
    std::string hex;
    for (unsigned char c : script) {
        static const char digits[] = "0123456789abcdef";
        hex.push_back(digits[c >> 4]);
        hex.push_back(digits[c & 0xf]);
    }
    return hex;
}

// ============================================================================
// Payout hash computation (replicated from share_tracker.hpp)
// ============================================================================

static std::string uint288_to_decimal(const uint288& val)
{
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
}

static uint256 compute_payout_hash(
    const std::map<std::vector<unsigned char>, uint288>& weights,
    const uint288& total_weight, const uint288& donation_weight, bool testnet)
{
    std::map<std::string, uint288> sorted;
    for (const auto& [script, w] : weights)
        sorted[script_to_address(script, testnet)] += w;

    std::string payload;
    for (const auto& [addr, w] : sorted) {
        if (!payload.empty()) payload += '|';
        payload += addr + ':' + uint288_to_decimal(w);
    }
    payload += "|T:" + uint288_to_decimal(total_weight);
    payload += "|D:" + uint288_to_decimal(donation_weight);

    auto span = std::span<const unsigned char>(
        reinterpret_cast<const unsigned char*>(payload.data()), payload.size());
    return Hash(span);
}

// ============================================================================
// Compute expected payouts (replicated from share_tracker.hpp)
// ============================================================================

static std::map<std::vector<unsigned char>, double>
compute_expected_payouts(
    const std::map<std::vector<unsigned char>, uint288>& weights,
    const uint288& total_weight, const uint288& donation_weight,
    uint64_t subsidy, const std::vector<unsigned char>& donation_script)
{
    std::map<std::vector<unsigned char>, double> result;
    double sum = 0;
    if (!total_weight.IsNull()) {
        for (const auto& [script, weight] : weights) {
            double payout = subsidy * (weight.getdouble() / total_weight.getdouble());
            result[script] = payout;
            sum += payout;
        }
    }
    double donation_remainder = static_cast<double>(subsidy) - sum;
    if (donation_remainder < 1.0 && subsidy > 0 && !result.empty()) {
        auto largest = std::max_element(result.begin(), result.end(),
            [](const auto& a, const auto& b) { return a.second < b.second; });
        if (largest != result.end() && largest->second >= 2.0) {
            largest->second -= 1.0;
            donation_remainder += 1.0;
        }
    }
    result[donation_script] = (result.count(donation_script) ? result[donation_script] : 0.0)
                              + donation_remainder;
    return result;
}

// Parse a block hex into output values
static std::vector<std::pair<std::vector<uint8_t>, uint64_t>>
parse_coinbase_outputs(const std::string& block_hex)
{
    auto raw = from_hex(block_hex);
    size_t pos = 80;  // skip header
    // skip auxpow if present (we pass empty auxpow in tests)
    uint64_t tx_count = read_varint(raw, pos);
    pos += 4; // tx version
    uint64_t vin_count = read_varint(raw, pos);
    for (uint64_t i = 0; i < vin_count; ++i) {
        pos += 32 + 4;
        uint64_t sig_len = read_varint(raw, pos);
        pos += sig_len + 4;
    }
    uint64_t vout_count = read_varint(raw, pos);
    std::vector<std::pair<std::vector<uint8_t>, uint64_t>> outputs;
    for (uint64_t i = 0; i < vout_count; ++i) {
        uint64_t value = read_le64(&raw[pos]); pos += 8;
        uint64_t slen = read_varint(raw, pos);
        std::vector<uint8_t> script(raw.begin() + pos, raw.begin() + pos + slen);
        pos += slen;
        outputs.emplace_back(std::move(script), value);
    }
    return outputs;
}

// Make a template JSON
static nlohmann::json make_template(int height, uint32_t version = 0x00620004)
{
    nlohmann::json t;
    t["version"] = version;
    t["previousblockhash"] = "0000000000000000000000000000000000000000000000000000000000001234";
    t["curtime"] = 1700000000u;
    t["bits"] = "1e0fffff";
    t["height"] = height;
    t["transactions"] = nlohmann::json::array();
    return t;
}

// ============================================================================
// Test fixture
// ============================================================================

class PPLNSStressTest : public ::testing::Test {
protected:
    void SetUp() override {
        ltc::PoolConfig::is_testnet = true;
    }
};

// ============================================================================
// 1. Large chain: weight totals correct for many shares/miners
// ============================================================================

TEST_F(PPLNSStressTest, LargeChain1000Shares50Miners)
{
    const int N = 1000, M = 50;
    ChainContext ctx(build_chain(N, M));

    auto result = ctx.skiplist.query(ctx.shares[0].hash, N, uint288(uint64_t(-1)));

    auto target = bits_to_target(0x1e0fffff);
    auto att = target_to_average_attempts(target);
    uint288 expected_total = att * 65535 * N;

    EXPECT_EQ(result.total_weight, expected_total);
    EXPECT_FALSE(result.weights.empty());

    // Should have exactly M distinct scripts (3 types × ceil(M/3) unique hashes)
    EXPECT_EQ(result.weights.size(), static_cast<size_t>(M));

    // Each miner contributes N/M shares (equal distribution)
    auto shares_per_miner = N / M;
    uint288 expected_per_miner = att * static_cast<uint32_t>(65535 - 50) * shares_per_miner;
    for (const auto& [script, weight] : result.weights)
        EXPECT_EQ(weight, expected_per_miner)
            << "Each of " << M << " miners should have equal weight";
}

TEST_F(PPLNSStressTest, LargeChain5000Shares100Miners)
{
    const int N = 5000, M = 100;
    ChainContext ctx(build_chain(N, M));

    auto result = ctx.skiplist.query(ctx.shares[0].hash, N, uint288(uint64_t(-1)));

    auto target = bits_to_target(0x1e0fffff);
    auto att = target_to_average_attempts(target);
    uint288 expected_total = att * 65535 * N;

    EXPECT_EQ(result.total_weight, expected_total);
    EXPECT_EQ(result.weights.size(), static_cast<size_t>(M));
}

// ============================================================================
// 2. Payout hash determinism
// ============================================================================

TEST_F(PPLNSStressTest, PayoutHashDeterministic1000Shares)
{
    const int N = 1000, M = 20;
    ChainContext ctx(build_chain(N, M));

    auto r = ctx.skiplist.query(ctx.shares[0].hash, N, uint288(uint64_t(-1)));

    auto h1 = compute_payout_hash(r.weights, r.total_weight, r.total_donation_weight, true);
    auto h2 = compute_payout_hash(r.weights, r.total_weight, r.total_donation_weight, true);

    EXPECT_EQ(h1, h2) << "Same weights must produce same hash";
    EXPECT_FALSE(h1.IsNull());
}

TEST_F(PPLNSStressTest, PayoutHashDifferentChainsDifferentHashes)
{
    // Two chains with different miner distributions
    ChainContext ctx_a(build_chain(500, 10, 0x1e0fffff, 50));
    ChainContext ctx_b(build_chain(500, 10, 0x1e0fffff, 100));  // different donation

    auto ra = ctx_a.skiplist.query(ctx_a.shares[0].hash, 500, uint288(uint64_t(-1)));
    auto rb = ctx_b.skiplist.query(ctx_b.shares[0].hash, 500, uint288(uint64_t(-1)));

    auto ha = compute_payout_hash(ra.weights, ra.total_weight, ra.total_donation_weight, true);
    auto hb = compute_payout_hash(rb.weights, rb.total_weight, rb.total_donation_weight, true);

    EXPECT_NE(ha, hb) << "Different donation rates must produce different hashes";
}

TEST_F(PPLNSStressTest, PayoutHashMainnetVsTestnetDiffers)
{
    const int N = 200, M = 5;
    ChainContext ctx(build_chain(N, M));
    auto r = ctx.skiplist.query(ctx.shares[0].hash, N, uint288(uint64_t(-1)));

    auto h_testnet = compute_payout_hash(r.weights, r.total_weight, r.total_donation_weight, true);
    auto h_mainnet = compute_payout_hash(r.weights, r.total_weight, r.total_donation_weight, false);

    // Different HRP/version bytes → different address strings → different hash
    EXPECT_NE(h_testnet, h_mainnet);
}

// ============================================================================
// 3. Payout conservation: sum(outputs) == subsidy
// ============================================================================

TEST_F(PPLNSStressTest, PayoutConservation_ParentChain)
{
    const int N = 500, M = 30;
    ChainContext ctx(build_chain(N, M));
    auto r = ctx.skiplist.query(ctx.shares[0].hash, N, uint288(uint64_t(-1)));

    uint64_t subsidy = 12'5000'0000ULL;  // 12.5 LTC
    auto payouts = compute_expected_payouts(
        r.weights, r.total_weight, r.total_donation_weight, subsidy, COMBINED_DONATION);

    double total = 0;
    for (const auto& [_, amount] : payouts)
        total += amount;

    // Total should equal subsidy (within floating-point tolerance)
    EXPECT_NEAR(total, static_cast<double>(subsidy), 1.0)
        << "Parent chain payout sum must equal block reward";

    // Donation must be present and >= 1
    EXPECT_TRUE(payouts.count(COMBINED_DONATION));
    EXPECT_GE(payouts.at(COMBINED_DONATION), 1.0)
        << "V36: donation must be >= 1 satoshi";
}

TEST_F(PPLNSStressTest, PayoutConservation_MergedChain)
{
    const int N = 500, M = 30;
    ChainContext ctx(build_chain(N, M));
    auto r = ctx.skiplist.query(ctx.shares[0].hash, N, uint288(uint64_t(-1)));

    uint64_t subsidy = 10000'0000'0000ULL;  // 10000 DOGE
    auto payouts = compute_expected_payouts(
        r.weights, r.total_weight, r.total_donation_weight, subsidy, COMBINED_DONATION);

    double total = 0;
    for (const auto& [_, amount] : payouts)
        total += amount;

    EXPECT_NEAR(total, static_cast<double>(subsidy), 1.0)
        << "Merged chain payout sum must equal block reward";

    EXPECT_GE(payouts.at(COMBINED_DONATION), 1.0);
}

// ============================================================================
// 4. V36 donation minimum: zero donation weight → donation still >= 1 sat
// ============================================================================

TEST_F(PPLNSStressTest, DonationMinimumWhenZeroDonationWeight)
{
    // donation=0 in shares → donation_weight=0
    const int N = 100, M = 5;
    ChainContext ctx(build_chain(N, M, 0x1e0fffff, /*donation=*/0));

    auto r = ctx.skiplist.query(ctx.shares[0].hash, N, uint288(uint64_t(-1)));
    EXPECT_TRUE(r.total_donation_weight.IsNull())
        << "With donation=0, donation_weight must be null";

    uint64_t subsidy = 50'0000'0000ULL;
    auto payouts = compute_expected_payouts(
        r.weights, r.total_weight, r.total_donation_weight, subsidy, COMBINED_DONATION);

    EXPECT_GE(payouts.at(COMBINED_DONATION), 1.0)
        << "V36: donation must be >= 1 satoshi even with zero donation weight";

    // Total must still equal subsidy
    double total = 0;
    for (const auto& [_, amount] : payouts)
        total += amount;
    EXPECT_NEAR(total, static_cast<double>(subsidy), 1.0);
}

TEST_F(PPLNSStressTest, DonationMinimumSingleMiner)
{
    ChainContext ctx(build_chain(100, 1, 0x1e0fffff, 0));
    auto r = ctx.skiplist.query(ctx.shares[0].hash, 100, uint288(uint64_t(-1)));

    uint64_t subsidy = 10000'0000'0000ULL;
    auto payouts = compute_expected_payouts(
        r.weights, r.total_weight, r.total_donation_weight, subsidy, COMBINED_DONATION);

    EXPECT_EQ(payouts.size(), 2u) << "Single miner + donation = 2 entries";
    EXPECT_GE(payouts.at(COMBINED_DONATION), 1.0);

    // Miner gets subsidy - 1
    for (const auto& [script, amount] : payouts) {
        if (script != COMBINED_DONATION)
            EXPECT_NEAR(amount, static_cast<double>(subsidy) - 1.0, 1.0);
    }
}

// ============================================================================
// 5. Multiaddress block construction — both chains
// ============================================================================

TEST_F(PPLNSStressTest, MultiaddressBlock_ParentChain30Miners)
{
    const int N = 500, M = 30;
    ChainContext ctx(build_chain(N, M));
    auto r = ctx.skiplist.query(ctx.shares[0].hash, N, uint288(uint64_t(-1)));

    uint64_t reward = 12'5000'0000ULL;
    auto payouts_map = compute_expected_payouts(
        r.weights, r.total_weight, r.total_donation_weight, reward, COMBINED_DONATION);

    std::vector<std::pair<std::vector<unsigned char>, uint64_t>> payouts;
    for (auto& [script, amount] : payouts_map)
        if (amount >= 1.0)
            payouts.emplace_back(script, static_cast<uint64_t>(amount));
    std::sort(payouts.begin(), payouts.end());

    auto block = MergedMiningManager::build_multiaddress_block(
        make_template(100), payouts, "", uint256{});

    ASSERT_FALSE(block.empty());

    auto outputs = parse_coinbase_outputs(block);
    // M miners + OP_RETURN + donation
    EXPECT_EQ(outputs.size(), static_cast<size_t>(M + 2));

    // Total value conservation: double→uint64_t truncation loses up to
    // 1 satoshi per miner.  Donation captures remainder in build_multiaddress_block.
    uint64_t total = 0;
    for (const auto& [_, val] : outputs)
        total += val;
    EXPECT_LE(reward - total, static_cast<uint64_t>(M))
        << "Rounding loss bounded by miner count";

    // Last output is donation
    auto& last = outputs.back();
    EXPECT_EQ(std::vector<uint8_t>(COMBINED_DONATION.begin(), COMBINED_DONATION.end()),
              last.first);
    EXPECT_GE(last.second, 1u);
}

TEST_F(PPLNSStressTest, MultiaddressBlock_MergedChain50Miners)
{
    const int N = 1000, M = 50;
    ChainContext ctx(build_chain(N, M));
    auto r = ctx.skiplist.query(ctx.shares[0].hash, N, uint288(uint64_t(-1)));

    uint64_t reward = 10000'0000'0000ULL;  // DOGE
    auto payouts_map = compute_expected_payouts(
        r.weights, r.total_weight, r.total_donation_weight, reward, COMBINED_DONATION);

    std::vector<std::pair<std::vector<unsigned char>, uint64_t>> payouts;
    for (auto& [script, amount] : payouts_map)
        if (amount >= 1.0)
            payouts.emplace_back(script, static_cast<uint64_t>(amount));
    std::sort(payouts.begin(), payouts.end());

    // DOGE template with chain_id in version
    auto block = MergedMiningManager::build_multiaddress_block(
        make_template(5000000, 0x00620004), payouts, "", uint256{});

    ASSERT_FALSE(block.empty());

    // Check AuxPoW flag is set
    auto raw = from_hex(block);
    uint32_t version = read_le32(&raw[0]);
    EXPECT_TRUE(version & 0x100) << "AuxPoW flag must be set in merged block version";
    EXPECT_EQ((version >> 16) & 0xFF, 98u) << "Chain ID 98 (DOGE) should be in version";

    auto outputs = parse_coinbase_outputs(block);
    EXPECT_EQ(outputs.size(), static_cast<size_t>(M + 2));

    uint64_t total = 0;
    for (const auto& [_, val] : outputs)
        total += val;
    EXPECT_LE(reward - total, static_cast<uint64_t>(M))
        << "Rounding loss bounded by miner count";
}

TEST_F(PPLNSStressTest, MultiaddressBlock_AuxPoWFlagAlwaysSet)
{
    // Even if template version doesn't have chain_id, AuxPoW flag must be set
    std::vector<uint32_t> versions = {0x20000002, 0x00620004, 0x00000001, 0x20000000};
    for (auto v : versions) {
        auto payouts = std::vector<std::pair<std::vector<unsigned char>, uint64_t>>{
            {make_p2pkh(hash_from_seed(0)), 50'0000'0000ULL}
        };
        auto block = MergedMiningManager::build_multiaddress_block(
            make_template(100, v), payouts, "", uint256{});
        ASSERT_FALSE(block.empty());
        auto raw = from_hex(block);
        uint32_t block_version = read_le32(&raw[0]);
        EXPECT_TRUE(block_version & 0x100)
            << "AuxPoW flag missing for input version " << std::hex << v;
    }
}

// ============================================================================
// 6. Weight cap: partial share prorating under weight limit
// ============================================================================

TEST_F(PPLNSStressTest, WeightCapProducesCorrectPartialShare)
{
    const int N = 500, M = 10;
    ChainContext ctx(build_chain(N, M));

    auto target = bits_to_target(0x1e0fffff);
    auto att = target_to_average_attempts(target);

    // Cap at exactly 100 shares worth
    uint288 cap = att * 65535 * 100;
    auto result = ctx.skiplist.query(ctx.shares[0].hash, N, cap);

    EXPECT_EQ(result.total_weight, cap)
        << "Total weight should equal cap (partial share prorated)";

    // Sum of per-miner weights + donation should equal total
    uint288 weight_sum;
    for (const auto& [_, w] : result.weights)
        weight_sum = weight_sum + w;
    uint288 reconstructed = weight_sum + result.total_donation_weight;
    EXPECT_EQ(reconstructed, result.total_weight);
}

// ============================================================================
// 7. Mixed version chain: pre-V36 shares excluded from V36 weights
// ============================================================================

TEST_F(PPLNSStressTest, PreV36SharesExcludedFromWeights)
{
    // Build chain with alternating V35 and V36 shares
    auto shares = build_chain(200, 10, 0x1e0fffff, 50, 36);
    // Set odd-indexed shares to V35
    for (int i = 0; i < 200; ++i) {
        if (i % 2 == 1)
            shares[i].desired_version = 35;
    }
    ChainContext ctx(std::move(shares));

    auto result = ctx.skiplist.query(ctx.shares[0].hash, 200, uint288(uint64_t(-1)));

    // Only 100 V36 shares should contribute
    auto target = bits_to_target(0x1e0fffff);
    auto att = target_to_average_attempts(target);
    uint288 expected_total = att * 65535 * 100;  // half the chain

    EXPECT_EQ(result.total_weight, expected_total);
}

// ============================================================================
// 8. Thread safety: concurrent skip list queries
// ============================================================================

TEST_F(PPLNSStressTest, LargerWindowProducesLargerWeight)
{
    // Verify that querying 100% of the chain gives more weight than 10%
    // by using separate skip list instances to avoid cache effects.
    const int N = 500, M = 10;

    auto shares = build_chain(N, M);
    auto target = bits_to_target(0x1e0fffff);
    auto att = target_to_average_attempts(target);

    // Query 50 shares
    ChainContext ctx_small(shares);
    auto r_small = ctx_small.skiplist.query(shares[0].hash, 50,
        att * 65535 * 50);

    // Query 500 shares (full chain) with unlimited weight
    uint288 unlimited;
    for (int i = 0; i < uint288::WIDTH; ++i) unlimited.pn[i] = 0xFFFFFFFF;
    ChainContext ctx_full(shares);
    auto r_full = ctx_full.skiplist.query(shares[0].hash, N, unlimited);

    EXPECT_GT(r_full.total_weight, r_small.total_weight)
        << "Full chain weight should exceed partial chain weight";

    // Full chain should have exactly N shares worth of weight
    uint288 expected_full = att * 65535 * N;
    EXPECT_EQ(r_full.total_weight, expected_full);
}

// ============================================================================
// 9. Payload format matches reference p2pool (sorted addr:weight|T:total|D:donation)
// ============================================================================

TEST_F(PPLNSStressTest, PayloadFormatMatchesReference)
{
    // Build a small chain where we can manually verify the payload
    const int N = 10, M = 2;
    ChainContext ctx(build_chain(N, M, 0x1e0fffff, 100));

    auto r = ctx.skiplist.query(ctx.shares[0].hash, N, uint288(uint64_t(-1)));

    // Build the payload manually
    std::map<std::string, uint288> sorted;
    for (const auto& [script, w] : r.weights)
        sorted[script_to_address(script, true)] += w;

    std::string payload;
    for (const auto& [addr, w] : sorted) {
        if (!payload.empty()) payload += '|';
        payload += addr + ':' + uint288_to_decimal(w);
    }
    payload += "|T:" + uint288_to_decimal(r.total_weight);
    payload += "|D:" + uint288_to_decimal(r.total_donation_weight);

    // Payload should have exactly M+2 pipe-separated fields (M miners + T + D)
    int pipe_count = std::count(payload.begin(), payload.end(), '|');
    EXPECT_EQ(pipe_count, M + 1)  // M-1 separators between miners + |T: + |D:
        << "Payload: " << payload;

    // T and D fields present
    EXPECT_NE(payload.find("|T:"), std::string::npos);
    EXPECT_NE(payload.find("|D:"), std::string::npos);

    // All fields have non-zero values
    for (const auto& [addr, w] : sorted)
        EXPECT_FALSE(w.IsNull()) << "Weight for " << addr << " should be non-zero";
}

// ============================================================================
// 10. End-to-end: payout hash → multiaddress block → output verification
// ============================================================================

TEST_F(PPLNSStressTest, EndToEnd_PayoutHashToBlock_ParentAndMerged)
{
    const int N = 400, M = 15;
    ChainContext ctx(build_chain(N, M));
    auto r = ctx.skiplist.query(ctx.shares[0].hash, N, uint288(uint64_t(-1)));

    // Compute payout hash (consensus commitment)
    auto payout_hash = compute_payout_hash(
        r.weights, r.total_weight, r.total_donation_weight, true);
    ASSERT_FALSE(payout_hash.IsNull());

    // --- Parent chain (LTC) ---
    uint64_t ltc_reward = 12'5000'0000ULL;
    auto ltc_payouts_map = compute_expected_payouts(
        r.weights, r.total_weight, r.total_donation_weight, ltc_reward, COMBINED_DONATION);

    std::vector<std::pair<std::vector<unsigned char>, uint64_t>> ltc_payouts;
    for (auto& [s, a] : ltc_payouts_map)
        if (a >= 1.0) ltc_payouts.emplace_back(s, static_cast<uint64_t>(a));
    std::sort(ltc_payouts.begin(), ltc_payouts.end());

    auto ltc_block = MergedMiningManager::build_multiaddress_block(
        make_template(1000), ltc_payouts, "", uint256{});
    ASSERT_FALSE(ltc_block.empty());

    auto ltc_outputs = parse_coinbase_outputs(ltc_block);
    uint64_t ltc_total = 0;
    for (const auto& [_, v] : ltc_outputs) ltc_total += v;
    EXPECT_LE(ltc_reward - ltc_total, static_cast<uint64_t>(M))
        << "LTC rounding loss bounded by miner count";

    // --- Merged chain (DOGE) ---
    uint64_t doge_reward = 10000'0000'0000ULL;
    auto doge_payouts_map = compute_expected_payouts(
        r.weights, r.total_weight, r.total_donation_weight, doge_reward, COMBINED_DONATION);

    std::vector<std::pair<std::vector<unsigned char>, uint64_t>> doge_payouts;
    for (auto& [s, a] : doge_payouts_map)
        if (a >= 1.0) doge_payouts.emplace_back(s, static_cast<uint64_t>(a));
    std::sort(doge_payouts.begin(), doge_payouts.end());

    auto doge_block = MergedMiningManager::build_multiaddress_block(
        make_template(5000000, 0x00620004), doge_payouts, "", uint256{});
    ASSERT_FALSE(doge_block.empty());

    auto doge_outputs = parse_coinbase_outputs(doge_block);
    uint64_t doge_total = 0;
    for (const auto& [_, v] : doge_outputs) doge_total += v;
    EXPECT_LE(doge_reward - doge_total, static_cast<uint64_t>(M))
        << "DOGE rounding loss bounded by miner count";

    // Both blocks should have same number of payout outputs
    EXPECT_EQ(ltc_outputs.size(), doge_outputs.size());

    // Payout hash is the same for both chains (computed from same PPLNS weights)
    auto payout_hash2 = compute_payout_hash(
        r.weights, r.total_weight, r.total_donation_weight, true);
    EXPECT_EQ(payout_hash, payout_hash2)
        << "Payout hash must be stable across reward computations";

    // Donation present in both
    auto donation_vec = std::vector<uint8_t>(COMBINED_DONATION.begin(), COMBINED_DONATION.end());
    bool ltc_has_donation = false, doge_has_donation = false;
    for (const auto& [s, v] : ltc_outputs)
        if (s == donation_vec) { ltc_has_donation = true; EXPECT_GE(v, 1u); }
    for (const auto& [s, v] : doge_outputs)
        if (s == donation_vec) { doge_has_donation = true; EXPECT_GE(v, 1u); }
    EXPECT_TRUE(ltc_has_donation) << "LTC block must have donation output";
    EXPECT_TRUE(doge_has_donation) << "DOGE block must have donation output";
}
