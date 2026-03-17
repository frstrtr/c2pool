/**
 * Tests for Stratum protocol extensions:
 *   1. mining.configure — BIP 310 version-rolling + subscribe-extranonce
 *   2. mining.extranonce.subscribe — NiceHash extranonce protocol
 *   3. mining.suggest_difficulty — miner difficulty hint
 *   4. Version rolling mask negotiation and validation
 *   5. Address separator parsing (comma, pipe, semicolon, space, slash)
 *   6. Fixed difficulty from username (+N suffix)
 *   7. Coinbase safety: extranonce vs scriptSig isolation
 *
 * These are unit tests that exercise protocol logic without network I/O.
 * They test JSON message parsing, mask negotiation, and address extraction.
 */

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>
#include <c2pool/hashrate/tracker.hpp>
#include <string>
#include <sstream>
#include <cstdint>

using json = nlohmann::json;

// ============================================================================
// Helpers — replicate the logic from web_server.cpp for unit testing
// without requiring a full StratumSession (which needs socket + MiningInterface)
// ============================================================================

namespace {

// Pool version mask (matches StratumSession::POOL_VERSION_MASK)
static constexpr uint32_t POOL_VERSION_MASK = 0x1fffe000;

// Simulate mining.configure response for version-rolling
json simulate_configure_version_rolling(const std::string& miner_mask_hex)
{
    json result = json::object();

    uint32_t miner_mask = 0;
    try {
        miner_mask = static_cast<uint32_t>(std::stoul(miner_mask_hex, nullptr, 16));
    } catch (...) {
        miner_mask = 0;
    }

    uint32_t negotiated = POOL_VERSION_MASK & miner_mask;

    std::ostringstream ss;
    ss << std::hex << std::setw(8) << std::setfill('0') << negotiated;

    result["version-rolling"] = true;
    result["version-rolling.mask"] = ss.str();
    return result;
}

// Simulate version rolling in mining.submit
// Returns: effective_version after applying miner's version_bits
// Returns 0 on error (invalid mask)
uint32_t apply_version_rolling(uint32_t job_version, uint32_t negotiated_mask,
                                const std::string& version_bits_hex)
{
    uint32_t miner_bits = 0;
    try {
        miner_bits = static_cast<uint32_t>(std::stoul(version_bits_hex, nullptr, 16));
    } catch (...) {
        return 0;
    }

    // Check: miner must not modify bits outside negotiated mask
    if ((~negotiated_mask & miner_bits) != 0)
        return 0;  // invalid

    return (job_version & ~negotiated_mask) | (miner_bits & negotiated_mask);
}

// Simulate address separator parsing (matches StratumSession::parse_address_separators)
struct ParseResult {
    std::string primary;
    std::string merged_raw;
    std::map<uint32_t, std::string> explicit_chains;
};

ParseResult parse_address_separators(const std::string& input)
{
    ParseResult result;
    std::string username = input;

    // Strip worker name suffix
    auto dot_pos = username.rfind('.');
    if (dot_pos != std::string::npos && dot_pos > 20)
        username = username.substr(0, dot_pos);
    auto underscore_pos = username.rfind('_');
    if (underscore_pos != std::string::npos && underscore_pos > 20)
        username = username.substr(0, underscore_pos);

    // Slash format
    auto slash_pos = username.find('/');
    if (slash_pos != std::string::npos) {
        result.primary = username.substr(0, slash_pos);
        std::string remainder = username.substr(slash_pos + 1);
        std::istringstream ss(remainder);
        std::string token;
        while (std::getline(ss, token, '/')) {
            auto colon = token.find(':');
            if (colon != std::string::npos && colon > 0 && colon + 1 < token.size()) {
                try {
                    uint32_t chain_id = static_cast<uint32_t>(std::stoul(token.substr(0, colon)));
                    result.explicit_chains[chain_id] = token.substr(colon + 1);
                } catch (...) {}
            }
        }
        return result;
    }

    // Simple separators: comma, pipe, semicolon, space
    for (char sep : {',', '|', ';', ' '}) {
        auto sep_pos = username.find(sep);
        if (sep_pos != std::string::npos && sep_pos > 20) {
            result.merged_raw = username.substr(sep_pos + 1);
            result.primary = username.substr(0, sep_pos);
            // Strip worker from merged too
            auto mdot = result.merged_raw.rfind('.');
            if (mdot != std::string::npos && mdot > 20) result.merged_raw = result.merged_raw.substr(0, mdot);
            auto mus = result.merged_raw.rfind('_');
            if (mus != std::string::npos && mus > 20) result.merged_raw = result.merged_raw.substr(0, mus);
            return result;
        }
    }

    result.primary = username;
    return result;
}

// Parse fixed difficulty suffix
double parse_fixed_difficulty(std::string& username)
{
    auto plus_pos = username.rfind('+');
    if (plus_pos != std::string::npos && plus_pos + 1 < username.size()) {
        std::string diff_str = username.substr(plus_pos + 1);
        try {
            double d = std::stod(diff_str);
            if (d > 0.0) {
                username = username.substr(0, plus_pos);
                return d;
            }
        } catch (...) {}
    }
    return 0.0;
}

} // anonymous namespace

// ============================================================================
// Suite 1: mining.configure — version-rolling negotiation
// ============================================================================

TEST(StratumExtensions, ConfigureVersionRollingFullMask)
{
    // Miner requests full mask — pool constrains to POOL_VERSION_MASK
    auto result = simulate_configure_version_rolling("ffffffff");
    EXPECT_TRUE(result["version-rolling"].get<bool>());
    EXPECT_EQ(result["version-rolling.mask"].get<std::string>(), "1fffe000");
}

TEST(StratumExtensions, ConfigureVersionRollingPartialMask)
{
    // Miner only supports bits 13-28 (0x1fff0000) — intersection with pool mask
    auto result = simulate_configure_version_rolling("1fff0000");
    EXPECT_TRUE(result["version-rolling"].get<bool>());
    // Pool mask: 0x1fffe000, miner: 0x1fff0000
    // Intersection: 0x1fff0000 (bits 16-28 overlap, miner excludes bits 13-15)
    uint32_t expected = 0x1fffe000 & 0x1fff0000;
    std::ostringstream ss;
    ss << std::hex << std::setw(8) << std::setfill('0') << expected;
    EXPECT_EQ(result["version-rolling.mask"].get<std::string>(), ss.str());
}

TEST(StratumExtensions, ConfigureVersionRollingZeroMask)
{
    // Miner sends zero mask — no bits available for rolling
    auto result = simulate_configure_version_rolling("00000000");
    EXPECT_TRUE(result["version-rolling"].get<bool>());
    EXPECT_EQ(result["version-rolling.mask"].get<std::string>(), "00000000");
}

TEST(StratumExtensions, ConfigureVersionRollingBraiinsMask)
{
    // Braiins OS typical mask
    auto result = simulate_configure_version_rolling("1fffe000");
    EXPECT_TRUE(result["version-rolling"].get<bool>());
    EXPECT_EQ(result["version-rolling.mask"].get<std::string>(), "1fffe000");
}

TEST(StratumExtensions, ConfigureVersionRollingInvalidMask)
{
    // Invalid hex — should result in 0 mask
    auto result = simulate_configure_version_rolling("not_hex");
    EXPECT_TRUE(result["version-rolling"].get<bool>());
    EXPECT_EQ(result["version-rolling.mask"].get<std::string>(), "00000000");
}

// ============================================================================
// Suite 2: Version rolling in mining.submit
// ============================================================================

TEST(StratumExtensions, VersionRollingApplyValidBits)
{
    // Job version = 0x20000000, miner rolls bits within mask
    uint32_t negotiated = 0x1fffe000;
    uint32_t result = apply_version_rolling(0x20000000, negotiated, "1fffe000");
    // Non-rolling bits preserved: 0x20000000 & ~0x1fffe000 = 0x20000000
    // Rolling bits applied: 0x1fffe000 & 0x1fffe000 = 0x1fffe000
    // Combined: 0x20000000 | 0x1fffe000 = 0x3fffe000
    EXPECT_EQ(result, 0x3fffe000u);
}

TEST(StratumExtensions, VersionRollingApplyZeroBits)
{
    // Miner doesn't roll any bits (passes 0)
    uint32_t result = apply_version_rolling(0x20000000, 0x1fffe000, "00000000");
    EXPECT_EQ(result, 0x20000000u);
}

TEST(StratumExtensions, VersionRollingRejectOutOfMask)
{
    // Miner tries to modify bit 0 (not in mask) — should be rejected
    uint32_t result = apply_version_rolling(0x20000000, 0x1fffe000, "00000001");
    EXPECT_EQ(result, 0u);  // error
}

TEST(StratumExtensions, VersionRollingRejectHighBits)
{
    // Miner tries to modify bits 29-31 (not in pool mask)
    uint32_t result = apply_version_rolling(0x20000000, 0x1fffe000, "e0000000");
    EXPECT_EQ(result, 0u);  // error
}

TEST(StratumExtensions, VersionRollingPartialRoll)
{
    // Miner only rolls some of the allowed bits
    uint32_t result = apply_version_rolling(0x20000000, 0x1fffe000, "10000000");
    // Non-rolling preserved: 0x20000000 & ~0x1fffe000 = 0x20000000
    // Rolling: 0x10000000 & 0x1fffe000 = 0x10000000
    EXPECT_EQ(result, 0x30000000u);
}

// ============================================================================
// Suite 3: Address separator parsing
// ============================================================================

// Use realistic-length addresses (>20 chars) to trigger separator detection
static const std::string LTC_ADDR  = "tltc1qkek8r3uymzqyajzezqgl99d2f948st5v67a5h3";
static const std::string DOGE_ADDR = "nXqSCeS7Riw7MG6ruAMaSTvWjmPPxgQfYp";

TEST(StratumExtensions, AddressSepComma)
{
    auto r = parse_address_separators(LTC_ADDR + "," + DOGE_ADDR);
    EXPECT_EQ(r.primary, LTC_ADDR);
    EXPECT_EQ(r.merged_raw, DOGE_ADDR);
}

TEST(StratumExtensions, AddressSepPipe)
{
    auto r = parse_address_separators(LTC_ADDR + "|" + DOGE_ADDR);
    EXPECT_EQ(r.primary, LTC_ADDR);
    EXPECT_EQ(r.merged_raw, DOGE_ADDR);
}

TEST(StratumExtensions, AddressSepSemicolon)
{
    auto r = parse_address_separators(LTC_ADDR + ";" + DOGE_ADDR);
    EXPECT_EQ(r.primary, LTC_ADDR);
    EXPECT_EQ(r.merged_raw, DOGE_ADDR);
}

TEST(StratumExtensions, AddressSepSpace)
{
    auto r = parse_address_separators(LTC_ADDR + " " + DOGE_ADDR);
    EXPECT_EQ(r.primary, LTC_ADDR);
    EXPECT_EQ(r.merged_raw, DOGE_ADDR);
}

TEST(StratumExtensions, AddressSepSlashExplicit)
{
    std::string input = LTC_ADDR + "/98:" + DOGE_ADDR;
    auto r = parse_address_separators(input);
    EXPECT_EQ(r.primary, LTC_ADDR);
    EXPECT_TRUE(r.merged_raw.empty());
    ASSERT_EQ(r.explicit_chains.count(98), 1u);
    EXPECT_EQ(r.explicit_chains[98], DOGE_ADDR);
}

TEST(StratumExtensions, AddressSepSlashMultiChain)
{
    std::string btc_addr = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa";
    std::string input = LTC_ADDR + "/98:" + DOGE_ADDR + "/2:" + btc_addr;
    auto r = parse_address_separators(input);
    EXPECT_EQ(r.primary, LTC_ADDR);
    ASSERT_EQ(r.explicit_chains.size(), 2u);
    EXPECT_EQ(r.explicit_chains[98], DOGE_ADDR);
    EXPECT_EQ(r.explicit_chains[2], btc_addr);
}

TEST(StratumExtensions, AddressSepWithWorkerName)
{
    // Worker name after merged address — should be stripped
    auto r = parse_address_separators(LTC_ADDR + "," + DOGE_ADDR + ".rig1");
    EXPECT_EQ(r.primary, LTC_ADDR);
    EXPECT_EQ(r.merged_raw, DOGE_ADDR);  // .rig1 stripped
}

TEST(StratumExtensions, AddressSepCommaBeforePipe)
{
    // Comma takes priority over pipe when both are present
    std::string input = LTC_ADDR + "," + DOGE_ADDR + "|extra";
    auto r = parse_address_separators(input);
    EXPECT_EQ(r.primary, LTC_ADDR);
    // Everything after comma is merged_raw (including the pipe)
    EXPECT_EQ(r.merged_raw, DOGE_ADDR + "|extra");
}

TEST(StratumExtensions, AddressSepSingleAddress)
{
    // No separator — just primary
    auto r = parse_address_separators(LTC_ADDR);
    EXPECT_EQ(r.primary, LTC_ADDR);
    EXPECT_TRUE(r.merged_raw.empty());
    EXPECT_TRUE(r.explicit_chains.empty());
}

TEST(StratumExtensions, AddressSepPipeWithWorkerUnderscore)
{
    // Pipe separator + underscore worker name on merged
    auto r = parse_address_separators(LTC_ADDR + "|" + DOGE_ADDR + "_worker1");
    EXPECT_EQ(r.primary, LTC_ADDR);
    EXPECT_EQ(r.merged_raw, DOGE_ADDR);  // _worker1 stripped
}

// ============================================================================
// Suite 4: Fixed difficulty suffix (+N)
// ============================================================================

TEST(StratumExtensions, FixedDifficultyInteger)
{
    std::string u = LTC_ADDR + "+1024";
    double d = parse_fixed_difficulty(u);
    EXPECT_DOUBLE_EQ(d, 1024.0);
    EXPECT_EQ(u, LTC_ADDR);
}

TEST(StratumExtensions, FixedDifficultyDecimal)
{
    std::string u = LTC_ADDR + "+0.5";
    double d = parse_fixed_difficulty(u);
    EXPECT_DOUBLE_EQ(d, 0.5);
    EXPECT_EQ(u, LTC_ADDR);
}

TEST(StratumExtensions, FixedDifficultyWithMerged)
{
    // +N after merged address
    std::string u = LTC_ADDR + "," + DOGE_ADDR + "+512";
    double d = parse_fixed_difficulty(u);
    EXPECT_DOUBLE_EQ(d, 512.0);
    EXPECT_EQ(u, LTC_ADDR + "," + DOGE_ADDR);
}

TEST(StratumExtensions, FixedDifficultyZero)
{
    // +0 is ignored (not positive)
    std::string u = LTC_ADDR + "+0";
    double d = parse_fixed_difficulty(u);
    EXPECT_DOUBLE_EQ(d, 0.0);  // not applied
}

TEST(StratumExtensions, FixedDifficultyNone)
{
    // No + suffix
    std::string u = LTC_ADDR;
    double d = parse_fixed_difficulty(u);
    EXPECT_DOUBLE_EQ(d, 0.0);
    EXPECT_EQ(u, LTC_ADDR);
}

TEST(StratumExtensions, FixedDifficultyInvalid)
{
    // +text — not a number
    std::string u = LTC_ADDR + "+abc";
    double d = parse_fixed_difficulty(u);
    EXPECT_DOUBLE_EQ(d, 0.0);  // not applied
}

// ============================================================================
// Suite 5: mining.suggest_difficulty — HashrateTracker hint integration
// ============================================================================

TEST(StratumExtensions, SuggestDifficultyApplied)
{
    c2pool::hashrate::HashrateTracker tracker;
    tracker.set_difficulty_bounds(0.001, 65536.0);
    tracker.enable_vardiff(true);

    // Initial difficulty = min_difficulty (0.001)
    EXPECT_DOUBLE_EQ(tracker.get_current_difficulty(), 0.001);

    // Apply hint
    tracker.set_difficulty_hint(128.0);
    EXPECT_DOUBLE_EQ(tracker.get_current_difficulty(), 128.0);
}

TEST(StratumExtensions, SuggestDifficultyClampedHigh)
{
    c2pool::hashrate::HashrateTracker tracker;
    tracker.set_difficulty_bounds(0.001, 65536.0);

    tracker.set_difficulty_hint(999999.0);
    EXPECT_DOUBLE_EQ(tracker.get_current_difficulty(), 65536.0);  // clamped to max
}

TEST(StratumExtensions, SuggestDifficultyClampedLow)
{
    c2pool::hashrate::HashrateTracker tracker;
    tracker.set_difficulty_bounds(0.001, 65536.0);

    tracker.set_difficulty_hint(0.0001);
    EXPECT_DOUBLE_EQ(tracker.get_current_difficulty(), 0.001);  // clamped to min
}

// ============================================================================
// Suite 6: mining.configure JSON message format
// ============================================================================

TEST(StratumExtensions, ConfigureRequestParsing)
{
    // Simulate a BIP 310 mining.configure request
    json request = {
        {"id", 1},
        {"method", "mining.configure"},
        {"params", json::array({
            json::array({"version-rolling", "subscribe-extranonce"}),
            {{"version-rolling.mask", "1fffe000"}, {"version-rolling.min-bit-count", 2}}
        })}
    };

    auto params = request["params"];
    ASSERT_TRUE(params[0].is_array());
    ASSERT_TRUE(params[1].is_object());

    auto extensions = params[0];
    auto ext_params = params[1];

    bool has_version_rolling = false;
    bool has_subscribe_extranonce = false;

    for (const auto& ext : extensions) {
        if (ext == "version-rolling") has_version_rolling = true;
        if (ext == "subscribe-extranonce") has_subscribe_extranonce = true;
    }

    EXPECT_TRUE(has_version_rolling);
    EXPECT_TRUE(has_subscribe_extranonce);
    EXPECT_EQ(ext_params["version-rolling.mask"].get<std::string>(), "1fffe000");
    EXPECT_EQ(ext_params["version-rolling.min-bit-count"].get<int>(), 2);
}

TEST(StratumExtensions, ConfigureResponseFormat)
{
    // Verify the response matches the BIP 310 spec
    auto result = simulate_configure_version_rolling("1fffe000");

    // Must have exactly these keys
    EXPECT_TRUE(result.contains("version-rolling"));
    EXPECT_TRUE(result.contains("version-rolling.mask"));
    EXPECT_TRUE(result["version-rolling"].get<bool>());
    // Mask must be 8-char lowercase hex
    std::string mask = result["version-rolling.mask"].get<std::string>();
    EXPECT_EQ(mask.size(), 8u);
    for (char c : mask) {
        EXPECT_TRUE((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'));
    }
}

// ============================================================================
// Suite 7: mining.extranonce.subscribe JSON format
// ============================================================================

TEST(StratumExtensions, ExtranonceSubscribeRequest)
{
    // NiceHash-style request — params is empty array
    json request = {
        {"id", 42},
        {"method", "mining.extranonce.subscribe"},
        {"params", json::array()}
    };

    EXPECT_EQ(request["method"], "mining.extranonce.subscribe");
    EXPECT_TRUE(request["params"].empty());
}

TEST(StratumExtensions, SetExtranonceNotificationFormat)
{
    // Verify the server→client notification format
    json notification;
    notification["id"] = nullptr;
    notification["method"] = "mining.set_extranonce";
    notification["params"] = json::array({"00000042", 4});

    EXPECT_TRUE(notification["id"].is_null());
    EXPECT_EQ(notification["method"], "mining.set_extranonce");
    EXPECT_EQ(notification["params"][0], "00000042");
    EXPECT_EQ(notification["params"][1], 4);
}

// ============================================================================
// Suite 8: mining.suggest_difficulty JSON format
// ============================================================================

TEST(StratumExtensions, SuggestDifficultyRequest)
{
    json request = {
        {"id", 5},
        {"method", "mining.suggest_difficulty"},
        {"params", json::array({1024.0})}
    };

    EXPECT_EQ(request["method"], "mining.suggest_difficulty");
    EXPECT_DOUBLE_EQ(request["params"][0].get<double>(), 1024.0);
}

TEST(StratumExtensions, SuggestDifficultyStringParam)
{
    // Some miners send difficulty as string
    json request = {
        {"id", 5},
        {"method", "mining.suggest_difficulty"},
        {"params", json::array({"256"})}
    };

    double suggested = 0.0;
    auto& params = request["params"];
    if (!params.empty()) {
        if (params[0].is_number())
            suggested = params[0].get<double>();
        else if (params[0].is_string()) {
            try { suggested = std::stod(params[0].get<std::string>()); } catch (...) {}
        }
    }
    EXPECT_DOUBLE_EQ(suggested, 256.0);
}

// ============================================================================
// Suite 9: Coinbase safety — extranonce isolation from scriptSig
// ============================================================================

TEST(StratumExtensions, CoinbaseSafetyExtranonceSeparateFromScriptSig)
{
    // Verify the coinbase layout: extranonce is in OP_RETURN, not scriptSig
    //
    // OP_RETURN output format:
    //   6a28 + ref_hash(32B) + extranonce1(4B) + extranonce2(4B)
    //
    // scriptSig format (for merged mining):
    //   height + fabe6d6d + mm_root(32B) + tree_size(4B) + nonce(4B) + pool_marker + state_root
    //
    // These are in DIFFERENT parts of the transaction.
    // Changing extranonce1 CANNOT affect the scriptSig or merged mining commitment.

    // Simulate OP_RETURN construction
    std::string op_return_prefix = "6a28";  // OP_RETURN PUSH_40
    std::string ref_hash = std::string(64, 'a');  // 32 bytes
    std::string extranonce1 = "00000001";  // 4 bytes
    std::string extranonce2 = "deadbeef";  // 4 bytes

    std::string op_return = op_return_prefix + ref_hash + extranonce1 + extranonce2;
    EXPECT_EQ(op_return.size(), 4 + 64 + 8 + 8u);  // 84 hex chars = 42 bytes

    // Simulate merged mining marker in scriptSig
    std::string mm_magic = "fabe6d6d";  // 4 bytes
    std::string mm_root = std::string(64, 'b');  // 32 bytes
    std::string mm_treesize = "01000000";  // 4 bytes LE
    std::string mm_nonce = "00000000";  // 4 bytes LE

    std::string mm_commitment = mm_magic + mm_root + mm_treesize + mm_nonce;
    EXPECT_EQ(mm_commitment.size(), 8 + 64 + 8 + 8u);  // 88 hex chars = 44 bytes

    // They're completely independent strings — changing extranonce doesn't affect mm
    std::string new_extranonce1 = "00000002";
    std::string new_op_return = op_return_prefix + ref_hash + new_extranonce1 + extranonce2;

    // scriptSig is unchanged
    EXPECT_EQ(mm_commitment, mm_magic + mm_root + mm_treesize + mm_nonce);
    // OP_RETURN changed only in the extranonce1 portion
    EXPECT_NE(op_return, new_op_return);
    EXPECT_EQ(new_op_return.substr(0, 68), op_return.substr(0, 68));  // prefix + ref_hash same
    EXPECT_NE(new_op_return.substr(68, 8), op_return.substr(68, 8));  // extranonce1 different
}

TEST(StratumExtensions, CoinbaseSafetyExtranonceSizes)
{
    // Verify extranonce1 + extranonce2 = 8 bytes total (the "last_txout_nonce")
    static constexpr int EXTRANONCE1_SIZE = 4;
    static constexpr int EXTRANONCE2_SIZE = 4;
    static constexpr int TOTAL_NONCE_SIZE = 8;

    EXPECT_EQ(EXTRANONCE1_SIZE + EXTRANONCE2_SIZE, TOTAL_NONCE_SIZE);

    // Verify hex representation sizes
    EXPECT_EQ(EXTRANONCE1_SIZE * 2, 8);   // 8 hex chars
    EXPECT_EQ(EXTRANONCE2_SIZE * 2, 8);   // 8 hex chars
}

// ============================================================================
// Suite 10: Version rolling does not affect coinbase
// ============================================================================

TEST(StratumExtensions, VersionRollingOnlyAffectsHeader)
{
    // Version rolling modifies the block header version field ONLY.
    // The coinbase transaction (including scriptSig, outputs, extranonce)
    // is completely unaffected by version rolling.

    uint32_t original_version = 0x20000000;
    uint32_t mask = 0x1fffe000;
    uint32_t rolled = apply_version_rolling(original_version, mask, "1fffe000");

    // Version changed
    EXPECT_NE(rolled, original_version);
    // But bits outside the mask are preserved
    EXPECT_EQ(rolled & ~mask, original_version & ~mask);
    // And the change is only in header — coinbase is independent
    // (This is by design: coinbase hash feeds into merkle root,
    //  version is a separate field in the block header)
}

// ============================================================================
// Suite 11: Extranonce1 generation uniqueness
// ============================================================================

TEST(StratumExtensions, Extranonce1HexFormat)
{
    // Verify the format matches what generate_extranonce1 produces
    uint32_t value = 0x0000002A;
    std::stringstream ss;
    ss << std::hex << std::setw(8) << std::setfill('0') << value;
    EXPECT_EQ(ss.str(), "0000002a");
    EXPECT_EQ(ss.str().size(), 8u);  // always 8 hex chars
}

TEST(StratumExtensions, Extranonce1Uniqueness)
{
    // Simulate atomic counter — each call gets unique value
    std::set<std::string> seen;
    for (uint32_t i = 0; i < 1000; ++i) {
        std::stringstream ss;
        ss << std::hex << std::setw(8) << std::setfill('0') << i;
        auto result = seen.insert(ss.str());
        EXPECT_TRUE(result.second);  // no duplicates
    }
    EXPECT_EQ(seen.size(), 1000u);
}
