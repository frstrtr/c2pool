/**
 * Unit tests for the MWEB builder (mweb_builder.hpp).
 *
 * Tests MWEBHeader serialization, MWEBState defaults, blake3 hashing,
 * HogEx transaction construction, serialization, txid computation,
 * MWEBTracker thread safety / invalidation, and build_empty_mweb_block().
 */

#include <gtest/gtest.h>
#include <impl/ltc/coin/mweb_builder.hpp>

#include <algorithm>
#include <cstring>
#include <thread>
#include <vector>

using namespace ltc::coin;

// ============================================================================
// Helpers — synthetic MWEB state for deterministic tests
// ============================================================================

namespace {

/// Create a uint256 filled with a repeating byte pattern.
uint256 make_uint256(uint8_t fill) {
    uint256 v;
    std::memset(v.data(), fill, 32);
    return v;
}

/// Create a synthetic MWEBState with deterministic data.
MWEBState make_test_state() {
    MWEBState state;
    state.prev_hogex_txid = make_uint256(0xAA);
    state.prev_hogex_vout = 0;
    state.hogaddr_value = 123456789;
    state.captured_at_height = 1000;
    state.valid = true;

    state.prev_header.height = 1000;
    state.prev_header.output_root = make_uint256(0x11);
    state.prev_header.kernel_root = make_uint256(0x22);
    state.prev_header.leafset_root = make_uint256(0x33);
    state.prev_header.kernel_offset.fill(0x44);
    state.prev_header.stealth_offset.fill(0x55);
    state.prev_header.output_mmr_size = 500;
    state.prev_header.kernel_mmr_size = 200;

    return state;
}

/// Build a minimal fake block with a HogEx-like last transaction.
/// Used for MWEBTracker::update() tests.
BlockType make_fake_block_with_hogex(const uint256& hogex_txid_unused) {
    BlockType block;
    block.m_version = 0x20000000;

    // First tx: coinbase (non-HogEx)
    MutableTransaction coinbase;
    coinbase.version = 2;
    coinbase.locktime = 0;
    TxIn cb_in;
    cb_in.prevout.hash.SetNull();
    cb_in.prevout.index = 0xffffffff;
    cb_in.sequence = 0xffffffff;
    coinbase.vin.push_back(std::move(cb_in));
    TxOut cb_out;
    cb_out.value = 5000000000;
    cb_out.scriptPubKey.m_data = {0x76, 0xa9, 0x14};  // partial P2PKH
    cb_out.scriptPubKey.m_data.resize(25, 0x00);
    coinbase.vout.push_back(std::move(cb_out));
    block.m_txs.push_back(std::move(coinbase));

    // Second tx: HogEx
    MutableTransaction hogex;
    hogex.version = 2;
    hogex.locktime = 0;
    hogex.m_hogEx = true;
    TxIn hog_in;
    hog_in.prevout.hash = make_uint256(0xBB);
    hog_in.prevout.index = 0;
    hog_in.sequence = 0xffffffff;
    hogex.vin.push_back(std::move(hog_in));
    TxOut hog_out;
    hog_out.value = 123456789;
    // HogAddr script: OP_8 (0x58) PUSH32 (0x20) <32 bytes>
    hog_out.scriptPubKey.m_data.resize(34);
    hog_out.scriptPubKey.m_data[0] = 0x58;
    hog_out.scriptPubKey.m_data[1] = 0x20;
    std::memset(hog_out.scriptPubKey.m_data.data() + 2, 0xCC, 32);
    hogex.vout.push_back(std::move(hog_out));
    block.m_txs.push_back(std::move(hogex));

    return block;
}

/// Build raw MWEB block bytes from a synthetic header.
std::vector<unsigned char> make_test_mweb_raw() {
    MWEBBlock mweb_block;
    mweb_block.header.height = 1000;
    mweb_block.header.output_root = make_uint256(0x11);
    mweb_block.header.kernel_root = make_uint256(0x22);
    mweb_block.header.leafset_root = make_uint256(0x33);
    mweb_block.header.kernel_offset.fill(0x44);
    mweb_block.header.stealth_offset.fill(0x55);
    mweb_block.header.output_mmr_size = 500;
    mweb_block.header.kernel_mmr_size = 200;

    PackStream ps;
    ps << mweb_block;
    auto sp = ps.get_span();
    return std::vector<unsigned char>(
        reinterpret_cast<const unsigned char*>(sp.data()),
        reinterpret_cast<const unsigned char*>(sp.data()) + sp.size());
}

} // anonymous namespace

// ============================================================================
// 1. MWEBHeader serialization round-trip
// ============================================================================

TEST(MWEBBuilder, HeaderSerializationRoundTrip) {
    MWEBHeader original;
    original.height = 42000;
    original.output_root = make_uint256(0xAB);
    original.kernel_root = make_uint256(0xCD);
    original.leafset_root = make_uint256(0xEF);
    original.kernel_offset.fill(0x01);
    original.stealth_offset.fill(0x02);
    original.output_mmr_size = 9999;
    original.kernel_mmr_size = 5555;

    // Serialize
    PackStream ps;
    ps << original;

    // Deserialize
    MWEBHeader restored;
    ps >> restored;

    EXPECT_EQ(restored.height, original.height);
    EXPECT_EQ(restored.output_root, original.output_root);
    EXPECT_EQ(restored.kernel_root, original.kernel_root);
    EXPECT_EQ(restored.leafset_root, original.leafset_root);
    EXPECT_EQ(restored.kernel_offset, original.kernel_offset);
    EXPECT_EQ(restored.stealth_offset, original.stealth_offset);
    EXPECT_EQ(restored.output_mmr_size, original.output_mmr_size);
    EXPECT_EQ(restored.kernel_mmr_size, original.kernel_mmr_size);
}

TEST(MWEBBuilder, HeaderSerializationDeterministic) {
    MWEBHeader hdr;
    hdr.height = 100;
    hdr.output_root = make_uint256(0x01);
    hdr.kernel_root = make_uint256(0x02);
    hdr.leafset_root = make_uint256(0x03);
    hdr.kernel_offset.fill(0x04);
    hdr.stealth_offset.fill(0x05);
    hdr.output_mmr_size = 50;
    hdr.kernel_mmr_size = 25;

    PackStream ps1, ps2;
    ps1 << hdr;
    ps2 << hdr;

    auto sp1 = ps1.get_span();
    auto sp2 = ps2.get_span();
    ASSERT_EQ(sp1.size(), sp2.size());
    EXPECT_EQ(std::memcmp(sp1.data(), sp2.data(), sp1.size()), 0);
}

// ============================================================================
// 2. MWEBState default construction
// ============================================================================

TEST(MWEBBuilder, StateDefaultConstruction) {
    MWEBState state;
    EXPECT_TRUE(state.prev_hogex_txid.IsNull());
    EXPECT_EQ(state.prev_hogex_vout, 0u);
    EXPECT_EQ(state.hogaddr_value, 0);
    EXPECT_EQ(state.captured_at_height, 0u);
    EXPECT_FALSE(state.valid);
    EXPECT_TRUE(state.prev_mweb_raw.empty());
    EXPECT_EQ(state.prev_header.height, 0);
    EXPECT_EQ(state.prev_header.output_mmr_size, 0u);
    EXPECT_EQ(state.prev_header.kernel_mmr_size, 0u);
}

// ============================================================================
// 3. compute_mweb_hash() — blake3 of serialized header
// ============================================================================

TEST(MWEBBuilder, ComputeMwebHashNonNull) {
    auto state = make_test_state();
    uint32_t next_height = 1001;
    uint256 hash = MWEBBuilder::compute_mweb_hash(state, next_height);
    EXPECT_FALSE(hash.IsNull());
}

TEST(MWEBBuilder, ComputeMwebHashDeterministic) {
    auto state = make_test_state();
    uint256 h1 = MWEBBuilder::compute_mweb_hash(state, 1001);
    uint256 h2 = MWEBBuilder::compute_mweb_hash(state, 1001);
    EXPECT_EQ(h1, h2);
}

TEST(MWEBBuilder, ComputeMwebHashDiffersByHeight) {
    auto state = make_test_state();
    uint256 h1 = MWEBBuilder::compute_mweb_hash(state, 1001);
    uint256 h2 = MWEBBuilder::compute_mweb_hash(state, 1002);
    EXPECT_NE(h1, h2);
}

// ============================================================================
// 4. build_hogex() — HogEx transaction structure
// ============================================================================

TEST(MWEBBuilder, BuildHogexStructure) {
    auto state = make_test_state();
    uint32_t next_height = 1001;
    auto hogex = MWEBBuilder::build_hogex(state, next_height);

    // Exactly 1 input spending the previous HogEx txid
    ASSERT_EQ(hogex.vin.size(), 1u);
    EXPECT_EQ(hogex.vin[0].prevout.hash, state.prev_hogex_txid);
    EXPECT_EQ(hogex.vin[0].prevout.index, state.prev_hogex_vout);
    EXPECT_EQ(hogex.vin[0].sequence, 0xffffffff);

    // Exactly 1 output (HogAddr)
    ASSERT_EQ(hogex.vout.size(), 1u);
    EXPECT_EQ(hogex.vout[0].value, state.hogaddr_value);

    // HogAddr script: OP_8 (0x58) PUSH32 (0x20) <32 bytes blake3 hash>
    const auto& script = hogex.vout[0].scriptPubKey.m_data;
    ASSERT_EQ(script.size(), 34u);
    EXPECT_EQ(script[0], 0x58);
    EXPECT_EQ(script[1], 0x20);

    // The embedded hash should match compute_mweb_hash
    uint256 expected_hash = MWEBBuilder::compute_mweb_hash(state, next_height);
    EXPECT_EQ(std::memcmp(script.data() + 2, expected_hash.data(), 32), 0);

    // Version and locktime
    EXPECT_EQ(hogex.version, 2);
    EXPECT_EQ(hogex.locktime, 0u);
    EXPECT_TRUE(hogex.m_hogEx);
}

TEST(MWEBBuilder, BuildHogexValueCarriedForward) {
    auto state = make_test_state();
    state.hogaddr_value = 999888777;
    auto hogex = MWEBBuilder::build_hogex(state, 1001);
    ASSERT_EQ(hogex.vout.size(), 1u);
    EXPECT_EQ(hogex.vout[0].value, 999888777);
}

// ============================================================================
// 5. serialize_hogex_hex() — correct version bytes and MWEB flag
// ============================================================================

TEST(MWEBBuilder, SerializeHogexHexFormat) {
    auto state = make_test_state();
    auto hogex = MWEBBuilder::build_hogex(state, 1001);
    std::string hex = MWEBBuilder::serialize_hogex_hex(hogex);

    // Non-empty hex string
    EXPECT_FALSE(hex.empty());
    // Must be even-length (valid hex)
    EXPECT_EQ(hex.size() % 2, 0u);

    // First 4 bytes = version (little-endian int32: version=2 => "02000000")
    ASSERT_GE(hex.size(), 8u);
    EXPECT_EQ(hex.substr(0, 8), "02000000");

    // Next: dummy empty vin (0x00) + flags (0x08 for MWEB)
    // After version "02000000", dummy vin = "00", flags = "08"
    EXPECT_EQ(hex.substr(8, 2), "00");   // dummy empty vin vector
    EXPECT_EQ(hex.substr(10, 2), "08");  // MWEB flag
}

TEST(MWEBBuilder, SerializeHogexHexAllHexChars) {
    auto state = make_test_state();
    auto hogex = MWEBBuilder::build_hogex(state, 1001);
    std::string hex = MWEBBuilder::serialize_hogex_hex(hogex);

    // Verify all characters are valid hex
    for (char c : hex) {
        EXPECT_TRUE((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'));
    }
}

// ============================================================================
// 6. compute_hogex_txid() — hash changes with different inputs
// ============================================================================

TEST(MWEBBuilder, ComputeHogexTxidNonNull) {
    auto state = make_test_state();
    auto hogex = MWEBBuilder::build_hogex(state, 1001);
    uint256 txid = MWEBBuilder::compute_hogex_txid(hogex);
    EXPECT_FALSE(txid.IsNull());
}

TEST(MWEBBuilder, ComputeHogexTxidDeterministic) {
    auto state = make_test_state();
    auto hogex = MWEBBuilder::build_hogex(state, 1001);
    uint256 t1 = MWEBBuilder::compute_hogex_txid(hogex);
    uint256 t2 = MWEBBuilder::compute_hogex_txid(hogex);
    EXPECT_EQ(t1, t2);
}

TEST(MWEBBuilder, ComputeHogexTxidDiffersWithDifferentInput) {
    auto state1 = make_test_state();
    auto state2 = make_test_state();
    state2.prev_hogex_txid = make_uint256(0xFF);  // different prev txid

    auto hogex1 = MWEBBuilder::build_hogex(state1, 1001);
    auto hogex2 = MWEBBuilder::build_hogex(state2, 1001);

    uint256 txid1 = MWEBBuilder::compute_hogex_txid(hogex1);
    uint256 txid2 = MWEBBuilder::compute_hogex_txid(hogex2);
    EXPECT_NE(txid1, txid2);
}

TEST(MWEBBuilder, ComputeHogexTxidDiffersWithDifferentHeight) {
    auto state = make_test_state();
    auto hogex1 = MWEBBuilder::build_hogex(state, 1001);
    auto hogex2 = MWEBBuilder::build_hogex(state, 2000);

    uint256 txid1 = MWEBBuilder::compute_hogex_txid(hogex1);
    uint256 txid2 = MWEBBuilder::compute_hogex_txid(hogex2);
    EXPECT_NE(txid1, txid2);
}

TEST(MWEBBuilder, ComputeHogexWtxidEqualsTxid) {
    auto state = make_test_state();
    auto hogex = MWEBBuilder::build_hogex(state, 1001);
    uint256 txid = MWEBBuilder::compute_hogex_txid(hogex);
    uint256 wtxid = MWEBBuilder::compute_hogex_wtxid(hogex);
    EXPECT_EQ(txid, wtxid);
}

// ============================================================================
// 7. MWEBTracker thread safety — concurrent operations don't crash
// ============================================================================

TEST(MWEBBuilder, TrackerThreadSafety) {
    MWEBTracker tracker;

    // We can't use update() easily without a proper block, but we can test
    // the thread-safe get/has/invalidate accessors concurrently.
    constexpr int kIterations = 10000;
    constexpr int kThreads = 4;

    std::vector<std::thread> threads;

    // Half the threads call has_state() + get_state() in a loop
    for (int t = 0; t < kThreads / 2; ++t) {
        threads.emplace_back([&tracker]() {
            for (int i = 0; i < kIterations; ++i) {
                (void)tracker.has_state();
                (void)tracker.get_state();
            }
        });
    }

    // Other half call invalidate() in a loop
    for (int t = 0; t < kThreads / 2; ++t) {
        threads.emplace_back([&tracker]() {
            for (int i = 0; i < kIterations; ++i) {
                tracker.invalidate();
            }
        });
    }

    for (auto& th : threads) {
        th.join();
    }

    // If we get here without crashing, the test passes.
    EXPECT_FALSE(tracker.has_state());
}

// ============================================================================
// 8. MWEBTracker invalidate() — resets state to empty
// ============================================================================

TEST(MWEBBuilder, TrackerInvalidateResetsState) {
    MWEBTracker tracker;

    // Initially no state
    EXPECT_FALSE(tracker.has_state());
    EXPECT_FALSE(tracker.get_state().has_value());

    // Invalidate on already-empty state should be a no-op
    tracker.invalidate();
    EXPECT_FALSE(tracker.has_state());
    EXPECT_FALSE(tracker.get_state().has_value());
}

TEST(MWEBBuilder, TrackerUpdateThenInvalidate) {
    MWEBTracker tracker;

    // Build a fake block with HogEx and MWEB raw data
    auto block = make_fake_block_with_hogex(make_uint256(0xBB));
    auto mweb_raw = make_test_mweb_raw();

    bool ok = tracker.update(block, 1000, mweb_raw);
    ASSERT_TRUE(ok);
    EXPECT_TRUE(tracker.has_state());

    auto state_opt = tracker.get_state();
    ASSERT_TRUE(state_opt.has_value());
    EXPECT_EQ(state_opt->captured_at_height, 1000u);
    EXPECT_EQ(state_opt->hogaddr_value, 123456789);
    EXPECT_TRUE(state_opt->valid);

    // Invalidate
    tracker.invalidate();
    EXPECT_FALSE(tracker.has_state());
    EXPECT_FALSE(tracker.get_state().has_value());
}

// ============================================================================
// 9. build_empty_mweb_block() — produces non-empty serialized block
// ============================================================================

TEST(MWEBBuilder, BuildEmptyMwebBlockNonEmpty) {
    auto state = make_test_state();
    auto raw = MWEBBuilder::build_empty_mweb_block(state, 1001);
    EXPECT_FALSE(raw.empty());
    // Must be larger than just the header (header alone is ~100+ bytes with varints)
    EXPECT_GT(raw.size(), 50u);
}

TEST(MWEBBuilder, BuildEmptyMwebBlockRoundTrip) {
    auto state = make_test_state();
    uint32_t next_height = 1001;
    auto raw = MWEBBuilder::build_empty_mweb_block(state, next_height);

    // Deserialize back
    PackStream ps(raw);
    MWEBBlock block;
    ps >> block;

    // Height should be updated
    EXPECT_EQ(block.header.height, static_cast<int64_t>(next_height));
    // Roots should carry forward from state
    EXPECT_EQ(block.header.output_root, state.prev_header.output_root);
    EXPECT_EQ(block.header.kernel_root, state.prev_header.kernel_root);
    EXPECT_EQ(block.header.leafset_root, state.prev_header.leafset_root);
    EXPECT_EQ(block.header.output_mmr_size, state.prev_header.output_mmr_size);
    EXPECT_EQ(block.header.kernel_mmr_size, state.prev_header.kernel_mmr_size);
}

TEST(MWEBBuilder, BuildEmptyMwebBlockHeightUpdated) {
    auto state = make_test_state();
    auto raw1 = MWEBBuilder::build_empty_mweb_block(state, 1001);
    auto raw2 = MWEBBuilder::build_empty_mweb_block(state, 2000);

    // Different heights should produce different serialized blocks
    EXPECT_NE(raw1, raw2);

    // But same height should be deterministic
    auto raw3 = MWEBBuilder::build_empty_mweb_block(state, 1001);
    EXPECT_EQ(raw1, raw3);
}

// ============================================================================
// Additional edge cases
// ============================================================================

TEST(MWEBBuilder, ExtractStateFailsOnEmptyBlock) {
    BlockType empty_block;
    MWEBState state;
    EXPECT_FALSE(MWEBBuilder::extract_state(empty_block, 100, state));
    EXPECT_FALSE(state.valid);
}

TEST(MWEBBuilder, ExtractStateFailsOnSingleTxBlock) {
    BlockType block;
    MutableTransaction coinbase;
    coinbase.version = 2;
    coinbase.locktime = 0;
    block.m_txs.push_back(std::move(coinbase));

    MWEBState state;
    EXPECT_FALSE(MWEBBuilder::extract_state(block, 100, state));
}

TEST(MWEBBuilder, ExtractMwebHeaderFromEmptyRaw) {
    MWEBState state;
    std::vector<unsigned char> empty;
    EXPECT_FALSE(MWEBBuilder::extract_mweb_header_from_raw(empty, state));
}

TEST(MWEBBuilder, ExtractMwebHeaderFromGarbage) {
    MWEBState state;
    std::vector<unsigned char> garbage(10, 0xFF);
    // Should fail gracefully (not crash)
    EXPECT_FALSE(MWEBBuilder::extract_mweb_header_from_raw(garbage, state));
}

TEST(MWEBBuilder, Blake3HashDifferentData) {
    std::vector<unsigned char> d1 = {0x01, 0x02, 0x03};
    std::vector<unsigned char> d2 = {0x04, 0x05, 0x06};
    uint256 h1 = blake3_hash(d1);
    uint256 h2 = blake3_hash(d2);
    EXPECT_FALSE(h1.IsNull());
    EXPECT_FALSE(h2.IsNull());
    EXPECT_NE(h1, h2);
}
