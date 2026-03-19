/**
 * Unit tests for the hash_link round-trip:
 *   prefix_to_hash_link(prefix, const_ending) → hash_link
 *   check_hash_link(hash_link, suffix, const_ending) → gentx_hash
 *   Hash(prefix + suffix) → expected gentx_hash
 *
 * Must match for p2pool peers to accept c2pool shares.
 */

#include <gtest/gtest.h>

#include <btclibs/uint256.h>
#include <btclibs/crypto/sha256.h>
#include <core/hash.hpp>
#include <impl/ltc/share_check.hpp>

#include <cstring>
#include <numeric>
#include <vector>

namespace {

// Build a byte vector of given size with sequential values
std::vector<unsigned char> make_bytes(size_t len, unsigned char start = 0) {
    std::vector<unsigned char> v(len);
    for (size_t i = 0; i < len; ++i)
        v[i] = static_cast<unsigned char>((start + i) & 0xff);
    return v;
}

// Simple round-trip test: verify that check_hash_link(prefix_to_hash_link(prefix, ce), suffix, ce)
// produces the same result as Hash(prefix + suffix).
bool verify_hash_link_roundtrip(
    const std::vector<unsigned char>& full_data,
    size_t split_pos,
    const std::vector<unsigned char>& const_ending)
{
    // The prefix must end with const_ending
    std::vector<unsigned char> prefix(full_data.begin(), full_data.begin() + split_pos);
    std::vector<unsigned char> suffix(full_data.begin() + split_pos, full_data.end());

    // Forward: compute hash_link from prefix
    auto hash_link = ltc::prefix_to_hash_link(prefix, const_ending);

    // Reverse: reconstruct gentx_hash from hash_link + suffix
    uint256 hl_result = ltc::check_hash_link(hash_link, suffix, const_ending);

    // Direct: Hash(full_data) = double-SHA256
    auto span = std::span<const unsigned char>(full_data.data(), full_data.size());
    uint256 direct_result = Hash(span);

    if (hl_result != direct_result) {
        std::cerr << "MISMATCH: split_pos=" << split_pos
                  << " prefix_len=" << prefix.size()
                  << " suffix_len=" << suffix.size()
                  << " const_ending_len=" << const_ending.size()
                  << " total=" << full_data.size() << "\n";
        std::cerr << "  direct =" << direct_result.GetHex() << "\n";
        std::cerr << "  hashlink=" << hl_result.GetHex() << "\n";

        // Dump hash_link internals
        std::cerr << "  hl.m_length=" << hash_link.m_length
                  << " hl.extra_data.size=" << hash_link.m_extra_data.m_data.size() << "\n";

        // Dump the state
        std::cerr << "  hl.state=";
        for (size_t i = 0; i < hash_link.m_state.m_data.size(); ++i)
            fprintf(stderr, "%02x", hash_link.m_state.m_data[i]);
        std::cerr << "\n";

        // Single SHA256 of full data for comparison
        unsigned char single[32];
        CSHA256().Write(full_data.data(), full_data.size()).Finalize(single);
        std::cerr << "  single_sha256=";
        for (int i = 0; i < 32; ++i) fprintf(stderr, "%02x", single[i]);
        std::cerr << "\n";

        // CSHA256 state after writing prefix
        CSHA256 hasher;
        hasher.Write(prefix.data(), prefix.size());
        std::cerr << "  prefix_state: s[0..7]=";
        for (int i = 0; i < 8; ++i) fprintf(stderr, " %08x", hasher.s[i]);
        std::cerr << "\n  prefix_bufsize=" << (hasher.bytes % 64)
                  << " bytes=" << hasher.bytes << "\n";
        std::cerr << "  prefix_buf[0..bufsize]=";
        size_t bs = hasher.bytes % 64;
        for (size_t i = 0; i < bs; ++i) fprintf(stderr, "%02x", hasher.buf[i]);
        std::cerr << "\n";

        return false;
    }
    return true;
}

} // namespace

// Test 1: Empty const_ending, various sizes
TEST(HashLink, RoundTripEmptyConstEnding) {
    std::vector<unsigned char> empty_ce;

    // Various total sizes and split positions
    for (size_t total : {64, 100, 128, 200, 256, 300}) {
        auto data = make_bytes(total);
        for (size_t split = 1; split < total; split += 7) {
            EXPECT_TRUE(verify_hash_link_roundtrip(data, split, empty_ce))
                << "total=" << total << " split=" << split;
        }
    }
}

// Test 2: Non-empty const_ending that matches end of prefix
TEST(HashLink, RoundTripWithConstEnding) {
    // Simulate p2pool's gentx_before_refhash (83 bytes)
    auto full = make_bytes(300);
    auto const_ending = make_bytes(83, 0);  // must match end of prefix

    // Place const_ending at the end of prefix (before suffix)
    // prefix = full[0:200], suffix = full[200:300]
    // const_ending must be full[200-83:200] = full[117:200]
    size_t split = 200;
    std::vector<unsigned char> ce(full.begin() + split - 83, full.begin() + split);

    EXPECT_TRUE(verify_hash_link_roundtrip(full, split, ce));
}

// Test 3: Prefix exactly on block boundary (64 bytes)
TEST(HashLink, RoundTripBlockBoundary) {
    std::vector<unsigned char> empty_ce;
    auto data = make_bytes(128);

    // Split at exactly 64 bytes (one full block processed, empty buffer)
    EXPECT_TRUE(verify_hash_link_roundtrip(data, 64, empty_ce));

    // Split at 128 bytes (two full blocks, empty buffer)
    auto data2 = make_bytes(192);
    EXPECT_TRUE(verify_hash_link_roundtrip(data2, 128, empty_ce));
}

// Test 4: Very small prefix (less than one block)
TEST(HashLink, RoundTripSmallPrefix) {
    std::vector<unsigned char> empty_ce;
    auto data = make_bytes(100);

    EXPECT_TRUE(verify_hash_link_roundtrip(data, 10, empty_ce));
    EXPECT_TRUE(verify_hash_link_roundtrip(data, 1, empty_ce));
    EXPECT_TRUE(verify_hash_link_roundtrip(data, 63, empty_ce));
}

// Test 5: Realistic coinbase-like data with actual gentx_before_refhash
TEST(HashLink, RoundTripRealisticCoinbase) {
    // Simulate a realistic coinbase: ~250 bytes with the last 44 as suffix
    auto coinbase = make_bytes(250, 0x01);

    // compute_gentx_before_refhash would give ~83 bytes
    auto gentx_before_refhash = ltc::compute_gentx_before_refhash(int64_t(36));

    // For the test, we must ensure the prefix ends with gentx_before_refhash.
    // Place gentx_before_refhash at the end of the prefix (before suffix).
    size_t suffix_len = 44;
    size_t split = coinbase.size() - suffix_len;

    // Overwrite end of prefix with gentx_before_refhash
    if (gentx_before_refhash.size() <= split) {
        std::memcpy(coinbase.data() + split - gentx_before_refhash.size(),
                     gentx_before_refhash.data(), gentx_before_refhash.size());
    }

    EXPECT_TRUE(verify_hash_link_roundtrip(coinbase, split, gentx_before_refhash));
}

// Test 6: const_ending larger than buffer (bufsize < ce.size())
TEST(HashLink, RoundTripLargeConstEnding) {
    // 200 bytes total, split at 200-44=156
    // bufsize = 156 % 64 = 28
    // const_ending = 83 bytes > 28 = bufsize
    // extra_len = 0 (all buffer bytes are from const_ending)
    auto full = make_bytes(200);
    size_t split = 156;

    // Place 83-byte const_ending at end of prefix
    auto ce_data = std::vector<unsigned char>(full.begin() + split - 83, full.begin() + split);

    EXPECT_TRUE(verify_hash_link_roundtrip(full, split, ce_data));
}

// Test 7: const_ending smaller than buffer (bufsize > ce.size())
TEST(HashLink, RoundTripSmallConstEnding) {
    // 200 bytes total, split at 190
    // bufsize = 190 % 64 = 62
    // const_ending = 10 bytes < 62
    // extra_len = 62 - 10 = 52
    auto full = make_bytes(200);
    size_t split = 190;

    auto ce_data = std::vector<unsigned char>(full.begin() + split - 10, full.begin() + split);

    EXPECT_TRUE(verify_hash_link_roundtrip(full, split, ce_data));
}

// Test 8: Verify state extraction/restoration directly
TEST(HashLink, StateExtractionDirect) {
    auto prefix = make_bytes(200);

    // Hash the prefix to get state
    CSHA256 hasher;
    hasher.Write(prefix.data(), prefix.size());

    // Extract state
    uint32_t original_state[8];
    for (int i = 0; i < 8; ++i)
        original_state[i] = hasher.s[i];

    // Round-trip through WriteBE32 / ReadBE32
    unsigned char state_bytes[32];
    for (int i = 0; i < 8; ++i)
        WriteBE32(state_bytes + i * 4, hasher.s[i]);

    uint32_t restored_state[8];
    for (int i = 0; i < 8; ++i)
        restored_state[i] = ReadBE32(state_bytes + i * 4);

    for (int i = 0; i < 8; ++i) {
        EXPECT_EQ(original_state[i], restored_state[i])
            << "State mismatch at index " << i;
    }
}

// Test 9: Verify that WRONG const_ending causes MISMATCH (this is the likely live bug)
TEST(HashLink, MismatchedConstEndingFails) {
    auto full = make_bytes(200);
    size_t split = 156;

    // Correct const_ending = actual last 35 bytes of prefix
    auto correct_ce = std::vector<unsigned char>(full.begin() + split - 35, full.begin() + split);

    // VERIFY correct case passes
    EXPECT_TRUE(verify_hash_link_roundtrip(full, split, correct_ce));

    // WRONG const_ending: flip a byte in the LAST bufsize bytes (which are actually used)
    // bufsize = 156 % 64 = 28, so last 28 bytes of CE are used
    auto wrong_ce = correct_ce;
    wrong_ce[wrong_ce.size() - 1] ^= 0xFF;  // Flip last byte (definitely in the used range)

    // This should FAIL because the reconstructed buffer bytes are wrong
    auto prefix = std::vector<unsigned char>(full.begin(), full.begin() + split);
    auto suffix = std::vector<unsigned char>(full.begin() + split, full.end());

    auto hash_link = ltc::prefix_to_hash_link(prefix, wrong_ce);
    uint256 hl_result = ltc::check_hash_link(hash_link, suffix, wrong_ce);
    auto span = std::span<const unsigned char>(full.data(), full.size());
    uint256 direct_result = Hash(span);

    // Wrong const_ending → MISMATCH (reproduces live MATCH=NO)
    EXPECT_NE(hl_result, direct_result) << "Wrong const_ending should cause mismatch!";
}

// Test 10: Verify CSHA256 custom constructor produces same result as continuous Write
TEST(HashLink, CustomConstructorEquivalence) {
    auto prefix = make_bytes(200);
    auto suffix = make_bytes(44, 0xAA);

    // Method A: continuous hash
    CSHA256 hasher_a;
    hasher_a.Write(prefix.data(), prefix.size());
    hasher_a.Write(suffix.data(), suffix.size());
    unsigned char out_a[32];
    hasher_a.Finalize(out_a);

    // Method B: capture state after prefix, then continue with custom constructor
    CSHA256 hasher_b;
    hasher_b.Write(prefix.data(), prefix.size());

    // Extract state, buffer, and length
    uint32_t state[8];
    for (int i = 0; i < 8; ++i)
        state[i] = hasher_b.s[i];
    size_t bufsize = hasher_b.bytes % 64;
    std::vector<unsigned char> buf_data(hasher_b.buf, hasher_b.buf + bufsize);
    uint64_t length = hasher_b.bytes;

    // Create new hasher from captured state
    CSHA256 hasher_c(state, buf_data, length);
    hasher_c.Write(suffix.data(), suffix.size());
    unsigned char out_c[32];
    hasher_c.Finalize(out_c);

    EXPECT_EQ(memcmp(out_a, out_c, 32), 0)
        << "Custom constructor produces different result than continuous Write";
}

// Test 11: Production-path coinbase — build a coinbase the same way
// build_coinbase_parts does (hex-encoded, parsed to bytes, split at len-44)
// and verify hash_link round-trip with compute_gentx_before_refhash(36).
TEST(HashLink, ProductionPathCoinbase) {
    // Build a realistic coinbase TX in hex, matching build_coinbase_parts output order:
    //   version(4) + vin_count(1) + prevhash(32) + previdx(4) + scriptSig_len(1) +
    //   scriptSig(varies) + sequence(4) + vout_count(1) +
    //   [segwit_output] + [pplns_outputs...] + [donation_output] + [op_return_output] +
    //   locktime(4)
    //
    // Donation output: value(8) + VarStr(COMBINED_DONATION_SCRIPT)
    // OP_RETURN output: value(8=0) + 0x2a + 0x6a + 0x28 + ref_hash(32) + nonce(8)

    auto gentx_before_refhash = ltc::compute_gentx_before_refhash(int64_t(36));
    ASSERT_GT(gentx_before_refhash.size(), 0u);

    // Print gentx_before_refhash for debugging
    {
        std::string hex;
        for (unsigned char b : gentx_before_refhash) {
            char buf[3];
            snprintf(buf, sizeof(buf), "%02x", b);
            hex += buf;
        }
        std::cerr << "gentx_before_refhash(" << gentx_before_refhash.size() << ")=" << hex << "\n";
    }

    // Build coinbase hex string exactly like build_coinbase_parts
    std::ostringstream coinb1;

    // Version
    coinb1 << "01000000";
    // vin_count = 1
    coinb1 << "01";
    // prev_hash = zeros (coinbase)
    coinb1 << "0000000000000000000000000000000000000000000000000000000000000000";
    // prev_idx = 0xffffffff
    coinb1 << "ffffffff";
    // scriptSig: height(4 bytes = 03AABBCC) + tag "/c2pool/" (8 bytes)
    int script_len = 4 + 8;  // height + tag
    coinb1 << std::hex << std::setfill('0') << std::setw(2) << script_len;
    coinb1 << "03aabbcc";  // BIP34 height push
    coinb1 << "2f6332706f6f6c2f"; // "/c2pool/"
    // sequence
    coinb1 << "ffffffff";

    // Outputs: segwit_commitment + 2 PPLNS + donation + OP_RETURN = 4 outputs
    // (or 5 if segwit)
    // Let's do: 2 PPLNS + donation + OP_RETURN = 4 outputs
    int num_outputs = 4;
    coinb1 << std::hex << std::setfill('0') << std::setw(2) << num_outputs;

    // Helper: encode LE64 to hex
    auto encode_le64 = [](uint64_t v) -> std::string {
        std::ostringstream os;
        for (int i = 0; i < 8; ++i)
            os << std::hex << std::setfill('0') << std::setw(2)
               << static_cast<int>((v >> (i * 8)) & 0xFF);
        return os.str();
    };

    // PPLNS output 1: 1000000 sats to a P2PKH script (25 bytes)
    coinb1 << encode_le64(1000000);
    coinb1 << "19"; // script_len = 25
    coinb1 << "76a914" << "0000000000000000000000000000000000000001" << "88ac";

    // PPLNS output 2: 2000000 sats to a P2PKH script
    coinb1 << encode_le64(2000000);
    coinb1 << "19"; // script_len = 25
    coinb1 << "76a914" << "0000000000000000000000000000000000000002" << "88ac";

    // Donation output: donation_amount sats to COMBINED_DONATION_SCRIPT (23 bytes)
    uint64_t donation_amount = 50000;
    coinb1 << encode_le64(donation_amount);
    {
        // VarStr(COMBINED_DONATION_SCRIPT): varint(23=0x17) + 23 bytes
        auto ds = ltc::PoolConfig::get_donation_script(36);
        coinb1 << std::hex << std::setfill('0') << std::setw(2) << ds.size();
        for (unsigned char b : ds) {
            coinb1 << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(b);
        }
    }

    // OP_RETURN output: value=0, script = 0x6a28 + ref_hash(32) + nonce(8)
    // total script = 42 bytes = 0x2a
    coinb1 << encode_le64(0);  // 0 satoshis
    coinb1 << "2a";            // script_len = 42
    coinb1 << "6a28";          // OP_RETURN + PUSH_40
    // ref_hash: 32 bytes of dummy data
    for (int i = 0; i < 32; ++i) {
        coinb1 << std::hex << std::setfill('0') << std::setw(2) << (0xaa + i) % 256;
    }
    // nonce(8) = en1+en2 placeholder (will be replaced)
    std::string en1 = "deadbeef";
    std::string en2 = "cafebabe";
    std::string coinb2 = "00000000"; // locktime

    std::string full_hex = coinb1.str() + en1 + en2 + coinb2;

    // Parse hex to bytes
    std::vector<unsigned char> coinbase_bytes;
    coinbase_bytes.reserve(full_hex.size() / 2);
    for (size_t i = 0; i + 1 < full_hex.size(); i += 2) {
        coinbase_bytes.push_back(static_cast<unsigned char>(
            std::stoul(full_hex.substr(i, 2), nullptr, 16)));
    }

    std::cerr << "coinbase_bytes.size()=" << coinbase_bytes.size() << "\n";

    // Split at len-44
    constexpr size_t suffix_len = 32 + 8 + 4;
    ASSERT_GT(coinbase_bytes.size(), suffix_len);
    size_t split = coinbase_bytes.size() - suffix_len;

    std::vector<unsigned char> prefix(coinbase_bytes.begin(), coinbase_bytes.begin() + split);
    std::vector<unsigned char> suffix(coinbase_bytes.begin() + split, coinbase_bytes.end());

    // Verify prefix ends with gentx_before_refhash
    ASSERT_GE(prefix.size(), gentx_before_refhash.size());
    bool ends_match = std::equal(
        gentx_before_refhash.begin(), gentx_before_refhash.end(),
        prefix.end() - gentx_before_refhash.size());

    if (!ends_match) {
        std::cerr << "MISMATCH: prefix does NOT end with gentx_before_refhash!\n";
        std::cerr << "prefix_tail:";
        for (size_t i = prefix.size() - gentx_before_refhash.size(); i < prefix.size(); ++i)
            fprintf(stderr, " %02x", prefix[i]);
        std::cerr << "\nexpected_CE:";
        for (unsigned char b : gentx_before_refhash)
            fprintf(stderr, " %02x", b);
        std::cerr << "\n";
    }
    EXPECT_TRUE(ends_match) << "Prefix must end with gentx_before_refhash";

    // Hash_link round-trip test
    EXPECT_TRUE(verify_hash_link_roundtrip(coinbase_bytes, split, gentx_before_refhash))
        << "Production-path coinbase hash_link round-trip failed";
}
