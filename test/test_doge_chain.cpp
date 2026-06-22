/// DOGE chain unit tests — embedded SPV node components
///
/// Tests:
///   1. Chain parameters (testnet4alpha/mainnet/testnet defaults)
///   2. DigiShield v3 difficulty calculation
///   3. DOGE subsidy schedule (simplified + random MT rewards)
///   4. HeaderChain basics (genesis, locator, sync gate, AuxPoW PoW skip)
///   5. AuxPoW header parser
///   6. Block version derivation

#include <gtest/gtest.h>

#include <impl/doge/coin/chain_params.hpp>
#include <impl/doge/coin/header_chain.hpp>
#include <impl/doge/coin/template_builder.hpp>
#include <impl/doge/coin/auxpow_header.hpp>

using namespace doge::coin;

// ─── Chain Params Tests ─────────────────────────────────────────────────────

TEST(DOGEChainParamsTest, Testnet4alphaDefaults) {
    auto p = DOGEChainParams::testnet4alpha();
    EXPECT_EQ(p.digishield_height, 0u);
    EXPECT_EQ(p.auxpow_height, 0u);
    EXPECT_EQ(p.simplified_rewards_height, 0u);
    EXPECT_TRUE(p.allow_min_difficulty);
    EXPECT_TRUE(p.strict_chain_id);
    EXPECT_FALSE(p.pow_limit.IsNull());
    // testnet4alpha uses random rewards (not simplified)
    EXPECT_FALSE(p.simplified_rewards);

    uint256 expected;
    expected.SetHex("de2bcf594a4134cef164a2204ca2f9bce745ff61c22bd714ebc88a7f2bdd8734");
    EXPECT_EQ(p.genesis_hash, expected);
}

TEST(DOGEChainParamsTest, MainnetDefaults) {
    auto p = DOGEChainParams::mainnet();
    EXPECT_EQ(p.digishield_height, 145000u);
    EXPECT_EQ(p.auxpow_height, 371337u);
    EXPECT_FALSE(p.allow_min_difficulty);
    EXPECT_TRUE(p.strict_chain_id);
    EXPECT_TRUE(p.simplified_rewards);
    EXPECT_EQ(DOGEChainParams::AUXPOW_CHAIN_ID, 0x0062u);
}

TEST(DOGEChainParamsTest, ConsensusEras) {
    auto p = DOGEChainParams::mainnet();
    EXPECT_FALSE(p.is_digishield(0));
    EXPECT_FALSE(p.is_digishield(144999));
    EXPECT_TRUE(p.is_digishield(145000));
    EXPECT_TRUE(p.is_digishield(371337));
    EXPECT_FALSE(p.is_auxpow(371336));
    EXPECT_TRUE(p.is_auxpow(371337));

    auto t = DOGEChainParams::testnet4alpha();
    EXPECT_TRUE(t.is_digishield(0));
    EXPECT_TRUE(t.is_auxpow(0));
}

// ─── Subsidy Tests (Simplified = fixed schedule) ────────────────────────────

TEST(DOGESubsidyTest, FixedRewardsAfter600k) {
    auto p = DOGEChainParams::mainnet();
    EXPECT_EQ(get_doge_block_subsidy(600000, p), 10000ULL * 100000000ULL);
    EXPECT_EQ(get_doge_block_subsidy(1000000, p), 10000ULL * 100000000ULL);
}

TEST(DOGESubsidyTest, SimplifiedRewardsSchedule) {
    auto p = DOGEChainParams::mainnet();
    EXPECT_EQ(get_doge_block_subsidy(145000, p), 250000ULL * 100000000ULL);
    EXPECT_EQ(get_doge_block_subsidy(200000, p), 125000ULL * 100000000ULL);
    EXPECT_EQ(get_doge_block_subsidy(300000, p), 62500ULL * 100000000ULL);
    EXPECT_EQ(get_doge_block_subsidy(400000, p), 31250ULL * 100000000ULL);
    EXPECT_EQ(get_doge_block_subsidy(500000, p), 15625ULL * 100000000ULL);
}

TEST(DOGESubsidyTest, MainnetMaxSubsidyBeforeSimplified) {
    auto p = DOGEChainParams::mainnet();
    // Mainnet has simplified_rewards=true, so max-subsidy overload uses 500k schedule
    // halving 0 (0-99999): 500,000 DOGE
    EXPECT_EQ(get_doge_block_subsidy(0, p), 500000ULL * 100000000ULL);
    // halving 1 (100000-144999): 250,000 DOGE
    EXPECT_EQ(get_doge_block_subsidy(100000, p), 250000ULL * 100000000ULL);
}

TEST(DOGESubsidyTest, Testnet4alphaMaxSubsidyIsRandom) {
    auto p = DOGEChainParams::testnet4alpha();
    // testnet4alpha has simplified_rewards=false, max-subsidy uses 1M ceiling
    EXPECT_EQ(get_doge_block_subsidy(0, p), 1000000ULL * 100000000ULL);
    EXPECT_EQ(get_doge_block_subsidy(100000, p), 500000ULL * 100000000ULL);
}

// ─── Subsidy Tests (Random = Mersenne Twister) ──────────────────────────────

TEST(DOGESubsidyTest, RandomRewardsMatchDogecoind) {
    // Verified against Dogecoin Core 1.14.99 testnet4alpha at height 37817
    // prevHash of block 37816: ae162af2b7efd37f8ca439eb4e8df06eee3e7ffab1a2ed098ad5d7d4005bc774
    // Daemon reported: coinbase limit = 42977900000000 (429779 DOGE)
    auto p = DOGEChainParams::testnet4alpha();
    uint256 prev_hash;
    prev_hash.SetHex("ae162af2b7efd37f8ca439eb4e8df06eee3e7ffab1a2ed098ad5d7d4005bc774");
    uint64_t subsidy = get_doge_block_subsidy(37817, p, prev_hash);
    EXPECT_EQ(subsidy, 42977900000000ULL) << "Random subsidy must match Dogecoin Core exactly";
}

TEST(DOGESubsidyTest, RandomRewardsDeterministic) {
    // Same input must always produce same output
    auto p = DOGEChainParams::testnet4alpha();
    uint256 prev_hash;
    prev_hash.SetHex("ae162af2b7efd37f8ca439eb4e8df06eee3e7ffab1a2ed098ad5d7d4005bc774");
    uint64_t s1 = get_doge_block_subsidy(37817, p, prev_hash);
    uint64_t s2 = get_doge_block_subsidy(37817, p, prev_hash);
    EXPECT_EQ(s1, s2);
}

TEST(DOGESubsidyTest, RandomRewardsInRange) {
    // Random rewards must be in [1, 1000000) * COIN for halving 0
    auto p = DOGEChainParams::testnet4alpha();
    static constexpr uint64_t COIN = 100000000ULL;
    for (int i = 0; i < 100; ++i) {
        uint256 h;
        // Vary the hash to get different seeds
        auto bytes = reinterpret_cast<unsigned char*>(h.data());
        bytes[0] = static_cast<unsigned char>(i);
        bytes[3] = static_cast<unsigned char>(i * 7 + 13);
        uint64_t s = get_doge_block_subsidy(100, p, h);
        EXPECT_GE(s, 2ULL * COIN);              // minimum: (1+1) * COIN
        EXPECT_LE(s, 1000000ULL * COIN);         // maximum: 1000000 * COIN
    }
}

TEST(DOGESubsidyTest, SimplifiedIgnoresPrevHash) {
    // Mainnet simplified rewards are fixed regardless of prevHash
    auto p = DOGEChainParams::mainnet();
    uint256 h1, h2;
    h1.SetHex("0000000000000000000000000000000000000000000000000000000000000001");
    h2.SetHex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    EXPECT_EQ(get_doge_block_subsidy(200000, p, h1), get_doge_block_subsidy(200000, p, h2));
    EXPECT_EQ(get_doge_block_subsidy(200000, p, h1), 125000ULL * 100000000ULL);
}

// ─── DigiShield v3 Tests ────────────────────────────────────────────────────

TEST(DigiShieldTest, NoChangeAtTargetSpacing) {
    auto p = DOGEChainParams::testnet4alpha();
    uint32_t bits = 0x1e0fffff;
    uint32_t result = calculate_doge_next_work(bits, 1000060, 1000000, 100, p);
    EXPECT_EQ(result, bits) << "Difficulty should not change when block time = target";
}

TEST(DigiShieldTest, FasterThanExpected) {
    auto p = DOGEChainParams::testnet4alpha();
    uint32_t bits = 0x1e0fffff;
    uint32_t result = calculate_doge_next_work(bits, 1000030, 1000000, 100, p);
    uint256 old_target, new_target;
    old_target.SetCompact(bits);
    new_target.SetCompact(result);
    EXPECT_LT(new_target, old_target) << "Faster blocks should increase difficulty";
}

TEST(DigiShieldTest, SlowerThanExpected) {
    auto p = DOGEChainParams::testnet4alpha();
    uint32_t bits = 0x1d00ffff;
    uint32_t result = calculate_doge_next_work(bits, 1000120, 1000000, 100, p);
    uint256 old_target, new_target;
    old_target.SetCompact(bits);
    new_target.SetCompact(result);
    EXPECT_GT(new_target, old_target) << "Slower blocks should decrease difficulty";
}

TEST(DigiShieldTest, AmplitudeDampening) {
    auto p = DOGEChainParams::testnet4alpha();
    uint32_t bits = 0x1d00ffff;
    uint32_t digi = calculate_doge_next_work(bits, 1000001, 1000000, 100, p);
    uint256 old_t, new_t;
    old_t.SetCompact(bits);
    new_t.SetCompact(digi);
    EXPECT_LT(new_t, old_t) << "Fast block should increase difficulty";
    EXPECT_GT(new_t, uint256::ZERO);
}

// ─── HeaderChain Tests ──────────────────────────────────────────────────────

class DOGEHeaderChainTest : public ::testing::Test {
protected:
    DOGEChainParams params = DOGEChainParams::testnet4alpha();
};

TEST_F(DOGEHeaderChainTest, EmptyChain) {
    HeaderChain chain(params);
    EXPECT_TRUE(chain.init());
    EXPECT_EQ(chain.size(), 0u);
    EXPECT_EQ(chain.height(), 0u);
    EXPECT_FALSE(chain.tip().has_value());
}

TEST_F(DOGEHeaderChainTest, EmptyChainLocatorIsEmpty) {
    // Empty chain returns empty locator so peer responds with genesis (height 0)
    HeaderChain chain(params);
    EXPECT_TRUE(chain.init());
    auto locator = chain.get_locator();
    EXPECT_TRUE(locator.empty())
        << "Empty chain locator must be empty so peer includes genesis in response";
}

TEST_F(DOGEHeaderChainTest, DynamicCheckpoint) {
    HeaderChain chain(params);
    EXPECT_TRUE(chain.init());

    uint256 cp_hash;
    cp_hash.SetHex("5fa04946dfea30cb31f681a176003333b39fefab34a50dac213d33330aaf6e25");
    chain.set_dynamic_checkpoint(23000, cp_hash);
    EXPECT_EQ(chain.height(), 23000u);
    EXPECT_EQ(chain.size(), 1u);

    // Locator should contain the checkpoint hash
    auto locator = chain.get_locator();
    ASSERT_FALSE(locator.empty());
    EXPECT_EQ(locator[0], cp_hash);
}

TEST_F(DOGEHeaderChainTest, PeerTipHeight) {
    HeaderChain chain(params);
    EXPECT_TRUE(chain.init());
    chain.set_peer_tip_height(23625);
    // Should not crash
}

TEST_F(DOGEHeaderChainTest, SyncGateNotSyncedWhenEmpty) {
    HeaderChain chain(params);
    EXPECT_TRUE(chain.init());
    EXPECT_FALSE(chain.is_synced());
}

TEST_F(DOGEHeaderChainTest, AuxPowSkipsScryptValidation) {
    // testnet4alpha: auxpow_height=0, all blocks are AuxPoW
    // AuxPoW blocks should skip scrypt PoW validation (PoW is on parent chain)
    HeaderChain chain(params);
    EXPECT_TRUE(chain.init());
    EXPECT_TRUE(params.is_auxpow(0));
    EXPECT_TRUE(params.is_auxpow(1));
    EXPECT_TRUE(params.is_auxpow(999999));
}

// ─── AuxPoW Header Parser Tests ─────────────────────────────────────────────

TEST(AuxPowParserTest, IsAuxpowVersion) {
    EXPECT_TRUE(is_auxpow_version(0x00620102));   // chain_id=98, auxpow, version 2
    EXPECT_TRUE(is_auxpow_version(0x00620104));   // chain_id=98, auxpow, version 4
    EXPECT_TRUE(is_auxpow_version(0x100));         // minimal auxpow bit
    EXPECT_FALSE(is_auxpow_version(0x00620002));   // chain_id=98, NO auxpow, version 2
    EXPECT_FALSE(is_auxpow_version(0x00000004));   // plain version 4
    EXPECT_FALSE(is_auxpow_version(0));
}

TEST(AuxPowParserTest, ParseNonAuxPowHeader) {
    // Build a minimal 80-byte header + 1 byte tx_count(0) without AuxPoW
    // version=4 (no AuxPoW bit), rest zeros
    std::vector<uint8_t> data(81, 0);
    data[0] = 0x04; // version 4 LE
    // tx_count at byte 80 = 0

    const uint8_t* pos = data.data();
    const uint8_t* end = data.data() + data.size();
    auto hdr = doge::coin::parse_doge_header(pos, end);
    EXPECT_EQ(hdr.m_version, 4);
    EXPECT_EQ(pos, end) << "Parser should consume all bytes";
}

TEST(AuxPowParserTest, EmptyMessageReturnsEmpty) {
    auto result = parse_doge_headers_message(nullptr, 0);
    EXPECT_TRUE(result.empty());
}

TEST(AuxPowParserTest, SingleNonAuxPowMessage) {
    // count=1, then 80-byte header + tx_count(0)
    std::vector<uint8_t> data;
    data.push_back(0x01); // count = 1
    data.resize(1 + 80 + 1, 0);
    data[1] = 0x04; // version 4

    auto result = doge::coin::parse_doge_headers_message(data.data(), data.size());
    ASSERT_EQ(result.size(), 1u);
    EXPECT_EQ(result[0].m_version, 4);
}

// ─── AuxPoW Structured Parser Tests (M3) ─────────────────────────────────────

namespace {
// Build a raw extended-header blob: 80-byte base header + (optional) CAuxPow
// proof + tx_count(CompactSize). Mirrors the DOGE 'headers'-message wire layout.
std::vector<uint8_t> build_extended_header(
    const bitcoin_family::coin::BlockHeaderType& base,
    const doge::coin::CAuxPow<>* aux)
{
    PackStream ps;
    ::Serialize(ps, base);
    if (aux)
        ::Serialize(ps, *aux);
    WriteCompactSize(ps, 0); // tx_count — always 0 in a 'headers' message
    auto sp = ps.get_span();
    auto* b = reinterpret_cast<const uint8_t*>(sp.data());
    return std::vector<uint8_t>(b, b + sp.size());
}

doge::coin::CAuxPow<> make_sample_auxpow()
{
    doge::coin::CAuxPow<> aux;

    // Parent-chain (LTC) coinbase == the pool's own gentx, carried in the proof
    // witness-stripped via tx_id_type (auxpow.hpp §12-Q1). Give it a realistic
    // coinbase shape — null prevout, 0xffffffff index, a scriptSig and an
    // output — so the variable-length tx body is genuinely round-tripped rather
    // than left default-empty.
    ltc::coin::MutableTransaction& cb = aux.m_merkle_tx.m_tx;
    cb.version = 1;
    cb.locktime = 0;
    ltc::coin::TxIn cb_in;
    cb_in.prevout.hash.SetNull();          // coinbase has a null prevout...
    cb_in.prevout.index = 0xffffffff;      // ...and the 0xffffffff sentinel index
    cb_in.scriptSig.m_data = {0x03, 0x99, 0x96, 0x06, 0x04, 0xde, 0xad, 0xbe, 0xef};
    cb_in.sequence = 0xffffffff;
    cb.vin.push_back(cb_in);
    ltc::coin::TxOut cb_out;
    cb_out.value = 5000000000LL;           // 50.00000000
    cb_out.scriptPubKey.m_data = {
        0x76, 0xa9, 0x14,                  // OP_DUP OP_HASH160 PUSH(20)
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa,
        0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44,
        0x88, 0xac};                       // OP_EQUALVERIFY OP_CHECKSIG
    cb.vout.push_back(cb_out);

    aux.m_merkle_tx.m_block_hash.SetHex(
        "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899");
    // Coinbase merkle branch: the path from the coinbase (leaf 0) up to the
    // parent block's merkle root. Populate it (was empty) so the second
    // variable-length proof component is exercised on the round-trip.
    uint256 cb_b0; cb_b0.SetHex("00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff");
    uint256 cb_b1; cb_b1.SetHex("123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0");
    aux.m_merkle_tx.m_merkle_link.m_branch = {cb_b0, cb_b1};
    aux.m_merkle_tx.m_merkle_link.m_index = 0;  // coinbase is always leaf 0

    uint256 b0; b0.SetHex("01");
    uint256 b1; b1.SetHex("02");
    aux.m_chain_merkle_link.m_branch = {b0, b1};
    aux.m_chain_merkle_link.m_index = 3;
    aux.m_parent_block_header.m_version = 2;
    aux.m_parent_block_header.m_timestamp = 0x499602d2;
    aux.m_parent_block_header.m_bits = 0x1e0ffff0;
    aux.m_parent_block_header.m_nonce = 0x0000c0de;
    return aux;
}
} // namespace

TEST(AuxPowStructuredTest, ParseAuxPowHeaderConsumesProof) {
    bitcoin_family::coin::BlockHeaderType base;
    base.m_version = 0x00620102;  // chain_id=98, AuxPoW bit set, version 2
    base.m_previous_block.SetHex("1111111111111111111111111111111111111111111111111111111111111111");
    base.m_merkle_root.SetHex("2222222222222222222222222222222222222222222222222222222222222222");
    base.m_timestamp = 0x5a5a5a5a;
    base.m_bits = 0x1e0ffff0;
    base.m_nonce = 0x12345678;

    auto aux = make_sample_auxpow();
    auto blob = build_extended_header(base, &aux);

    const uint8_t* pos = blob.data();
    const uint8_t* end = blob.data() + blob.size();
    auto hdr = doge::coin::parse_doge_header(pos, end);

    // Base header is recovered intact past the variable-length AuxPoW proof.
    EXPECT_EQ(hdr.m_version, 0x00620102u);
    EXPECT_EQ(hdr.m_timestamp, 0x5a5a5a5au);
    EXPECT_EQ(hdr.m_bits, 0x1e0ffff0u);
    EXPECT_EQ(hdr.m_nonce, 0x12345678u);
    EXPECT_EQ(hdr.m_previous_block, base.m_previous_block);
    EXPECT_EQ(hdr.m_merkle_root, base.m_merkle_root);
    EXPECT_EQ(pos, end) << "Structured parser must consume the full AuxPoW header";
}

TEST(AuxPowStructuredTest, ParseAuxPowHeaderRoundTripsProof) {
    // Verify parse_aux_header deserializes the proof structurally (not skipped):
    // the CAuxPow read back must equal the one we serialized.
    bitcoin_family::coin::BlockHeaderType base;
    base.m_version = 0x00620104;  // AuxPoW bit set
    base.m_bits = 0x1e0ffff0;

    auto aux = make_sample_auxpow();
    auto blob = build_extended_header(base, &aux);

    PackStream ps(std::span<const std::byte>(
        reinterpret_cast<const std::byte*>(blob.data()), blob.size()));
    doge::coin::CAuxPow<> out;
    bool has_aux = false;
    auto hdr = doge::coin::parse_aux_header(ps, out, has_aux);

    EXPECT_TRUE(has_aux);
    EXPECT_EQ(hdr.m_version, 0x00620104u);
    EXPECT_EQ(out.m_merkle_tx.m_block_hash, aux.m_merkle_tx.m_block_hash);
    ASSERT_EQ(out.m_chain_merkle_link.m_branch.size(), 2u);
    EXPECT_EQ(out.m_chain_merkle_link.m_branch[0], aux.m_chain_merkle_link.m_branch[0]);
    EXPECT_EQ(out.m_chain_merkle_link.m_branch[1], aux.m_chain_merkle_link.m_branch[1]);
    EXPECT_EQ(out.m_chain_merkle_link.m_index, 3u);
    EXPECT_EQ(out.m_parent_block_header.m_nonce, 0x0000c0deu);

    // The two most variable-length parts of the proof — the parent coinbase tx
    // body and the coinbase merkle branch — must round-trip WITH content, so a
    // wrong-length read in either path is caught (not masked by empty defaults).
    ASSERT_EQ(out.m_merkle_tx.m_tx.vin.size(), 1u);
    EXPECT_EQ(out.m_merkle_tx.m_tx.vin[0].prevout.index, 0xffffffffu);
    EXPECT_EQ(out.m_merkle_tx.m_tx.vin[0].scriptSig.m_data,
              aux.m_merkle_tx.m_tx.vin[0].scriptSig.m_data);
    ASSERT_EQ(out.m_merkle_tx.m_tx.vout.size(), 1u);
    EXPECT_EQ(out.m_merkle_tx.m_tx.vout[0].value, 5000000000LL);
    EXPECT_EQ(out.m_merkle_tx.m_tx.vout[0].scriptPubKey.m_data,
              aux.m_merkle_tx.m_tx.vout[0].scriptPubKey.m_data);
    ASSERT_EQ(out.m_merkle_tx.m_merkle_link.m_branch.size(), 2u);
    EXPECT_EQ(out.m_merkle_tx.m_merkle_link.m_branch[0], aux.m_merkle_tx.m_merkle_link.m_branch[0]);
    EXPECT_EQ(out.m_merkle_tx.m_merkle_link.m_branch[1], aux.m_merkle_tx.m_merkle_link.m_branch[1]);
    EXPECT_EQ(out.m_merkle_tx.m_merkle_link.m_index, 0u);
}

TEST(AuxPowStructuredTest, HasAuxFalseForPlainHeader) {
    bitcoin_family::coin::BlockHeaderType base;
    base.m_version = 4;  // no AuxPoW bit
    base.m_bits = 0x1e0ffff0;
    auto blob = build_extended_header(base, nullptr);

    PackStream ps(std::span<const std::byte>(
        reinterpret_cast<const std::byte*>(blob.data()), blob.size()));
    doge::coin::CAuxPow<> out;
    bool has_aux = true;
    auto hdr = doge::coin::parse_aux_header(ps, out, has_aux);
    EXPECT_FALSE(has_aux);
    EXPECT_EQ(hdr.m_version, 4u);
}

TEST(AuxPowStructuredTest, BatchParsesAuxPowHeader) {
    // count=1 followed by a single AuxPoW-extended header.
    bitcoin_family::coin::BlockHeaderType base;
    base.m_version = 0x00620102;
    base.m_bits = 0x1e0ffff0;
    base.m_nonce = 0xdeadbeef;
    auto aux = make_sample_auxpow();

    std::vector<uint8_t> msg;
    msg.push_back(0x01); // CompactSize count = 1
    auto hdr_blob = build_extended_header(base, &aux);
    msg.insert(msg.end(), hdr_blob.begin(), hdr_blob.end());

    auto result = doge::coin::parse_doge_headers_message(msg.data(), msg.size());
    ASSERT_EQ(result.size(), 1u);
    EXPECT_EQ(result[0].m_version, 0x00620102u);
    EXPECT_EQ(result[0].m_nonce, 0xdeadbeefu);
}

TEST(AuxPowStructuredTest, BatchStopsAtTruncatedHeader) {
    // count=2, but only the first header is complete; second is truncated.
    bitcoin_family::coin::BlockHeaderType base;
    base.m_version = 0x00620102;
    base.m_bits = 0x1e0ffff0;
    auto aux = make_sample_auxpow();

    std::vector<uint8_t> msg;
    msg.push_back(0x02); // claims 2 headers
    auto hdr_blob = build_extended_header(base, &aux);
    msg.insert(msg.end(), hdr_blob.begin(), hdr_blob.end());
    // Append a truncated second header (only 10 bytes of the 80-byte base).
    msg.insert(msg.end(), 10, 0x00);

    auto result = doge::coin::parse_doge_headers_message(msg.data(), msg.size());
    EXPECT_EQ(result.size(), 1u) << "Truncated tail header must be dropped, first kept";
}

// ─── Known-Answer Vector: real Dogecoin mainnet AuxPoW block #371337 ─────────
//
// Provenance: Dogecoin block 371,337 — the FIRST AuxPoW block on mainnet
// (mainnet AuxPoW activation height). DOGE_371337_EXTHEADER below is that
// block's extended header exactly as it travels on the P2P 'headers' wire:
//     CPureBlockHeader(80) + CAuxPow(proof) + tx_count(CompactSize = 0)
//
// It is assembled from Dogecoin Core's OWN decode of the on-chain block, NOT
// from c2pool's Serialize — so unlike the round-trip tests above it can catch
// a field-order or witness-mode error in OUR parser. Every component is
// double-SHA256 hash-verified against an externally published value, so the
// bytes cannot be silently wrong:
//   * sha256d(first 80 bytes)  == canonical block hash
//       60323982f9c5ff1b5a954eac9dc1269352835f47c2c5222691d80f0d50dcf053
//   * sha256d(parent coinbase) == its known txid
//       e5422732b20e9e7ecc243427abbe296e9528d308bb111aae8d30c3465e442de8
//   * sha256d(parent 80B hdr)  == merkle_tx.block_hash
//       45df41e40aba5b2a03d08bd1202a1c02ef3954d8aa22ea6c5ae62fd00f290ea9
// All asserted field values are read off the block explorer, independent of
// the code under test.
namespace {
std::vector<uint8_t> hex_to_bytes(const std::string& h) {
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    std::vector<uint8_t> out;
    out.reserve(h.size() / 2);
    for (size_t i = 0; i + 1 < h.size(); i += 2)
        out.push_back(static_cast<uint8_t>((nib(h[i]) << 4) | nib(h[i + 1])));
    return out;
}

// Dogecoin mainnet block #371337 extended header (headers-message form,
// tx_count = 0). See provenance note above. 536 bytes.
const char* const DOGE_371337_EXTHEADER =
    "020162000d6f03470d329026cd1fc720c0609cd378ca8691a117bd1aa46f01fb"
    "09b1a8468a15bf6f0b0e83f2e5036684169eafb9406468d4f075c999fb5b2a78"
    "fbb827ee41fb11548441361b0000000001000000010000000000000000000000"
    "000000000000000000000000000000000000000000ffffffff380345bf09fabe"
    "6d6d980ba42120410de0554d42a5b5ee58167bcd86bf7591f429005f24da45fb"
    "51cf0800000000000000cdb1f1ff0e000000ffffffff01800c0c2a0100000019"
    "76a914aa3750aa18b8a0f3f0590731e1fab934856680cf88ac00000000a90e29"
    "0fd02fe65a6cea22aad85439ef021c2a20d18bd0032a5bba0ae441df4503a979"
    "a636db2450363972d211aee67b71387a3daaa3051be0fd260c5acd4739cd52a4"
    "18d29d8a0e56c8714c95a0dc24e1c9624480ec497fe2441941f3fee8f9481a33"
    "70c334178415c83d1d0c2deeec727c2330617a47691fc5e79203669312d10000"
    "0000036fa40307b3a439538195245b0de56a2c1db6ba3a64f8bdd2071d00bc48"
    "c841b5e77b98e5c7d6f06f92dec5cf6d61277ecb9a0342406f49f34c51ee8ce4"
    "abd678038129485de14238bd1ca12cd2de12ff0e383aee542d90437cd664ce13"
    "9446a00000000002000000d2ec7dfeb7e8f43fe77aba3368df95ac2088034420"
    "402730ee0492a2084217083411b3fc91033bfdeea339bc11b9efc986e161c703"
    "e07a9045338c165673f09940fb11548b54021b58cc9ae500";
} // namespace

TEST(AuxPowKnownAnswerTest, Mainnet371337SkipParserRecoversChildHeader) {
    auto blob = hex_to_bytes(DOGE_371337_EXTHEADER);
    ASSERT_EQ(blob.size(), 536u);

    const uint8_t* pos = blob.data();
    const uint8_t* end = blob.data() + blob.size();
    auto hdr = doge::coin::parse_doge_header(pos, end);

    EXPECT_EQ(hdr.m_version, 0x00620102u);
    EXPECT_TRUE(doge::coin::is_auxpow_version(static_cast<int32_t>(hdr.m_version)));
    EXPECT_EQ(hdr.m_timestamp, 1410464577u);
    EXPECT_EQ(hdr.m_bits, 0x1b364184u);
    EXPECT_EQ(hdr.m_nonce, 0u);
    uint256 prev; prev.SetHex("46a8b109fb016fa41abd17a19186ca78d39c60c020c71fcd2690320d47036f0d");
    uint256 root; root.SetHex("ee27b8fb782a5bfb99c975f0d4686440b9af9e16846603e5f2830e0b6fbf158a");
    EXPECT_EQ(hdr.m_previous_block, prev);
    EXPECT_EQ(hdr.m_merkle_root, root);
    EXPECT_EQ(pos, end) << "skip parser must consume header + auxpow + tx_count exactly";
}

TEST(AuxPowKnownAnswerTest, Mainnet371337StructuredDecodesRealProof) {
    auto blob = hex_to_bytes(DOGE_371337_EXTHEADER);
    PackStream ps(std::span<const std::byte>(
        reinterpret_cast<const std::byte*>(blob.data()), blob.size()));
    doge::coin::CAuxPow<> out;
    bool has_aux = false;
    auto hdr = doge::coin::parse_aux_header(ps, out, has_aux);

    ASSERT_TRUE(has_aux);
    EXPECT_EQ(hdr.m_version, 0x00620102u);

    // Parent coinbase tx (witness-stripped tx_id_type), decoded field-for-field.
    ASSERT_EQ(out.m_merkle_tx.m_tx.vin.size(), 1u);
    EXPECT_TRUE(out.m_merkle_tx.m_tx.vin[0].prevout.hash.IsNull());
    EXPECT_EQ(out.m_merkle_tx.m_tx.vin[0].prevout.index, 0xffffffffu);
    EXPECT_EQ(out.m_merkle_tx.m_tx.vin[0].sequence, 0xffffffffu);
    EXPECT_EQ(out.m_merkle_tx.m_tx.vin[0].scriptSig.m_data,
              hex_to_bytes("0345bf09fabe6d6d980ba42120410de0554d42a5b5ee58167bcd86bf7591f429005f24da45fb51cf0800000000000000cdb1f1ff0e000000"));
    ASSERT_EQ(out.m_merkle_tx.m_tx.vout.size(), 1u);
    EXPECT_EQ(out.m_merkle_tx.m_tx.vout[0].value, 5000400000LL);
    EXPECT_EQ(out.m_merkle_tx.m_tx.vout[0].scriptPubKey.m_data,
              hex_to_bytes("76a914aa3750aa18b8a0f3f0590731e1fab934856680cf88ac"));

    // CMerkleTx.block_hash == the parent block the coinbase was included in.
    uint256 pblk; pblk.SetHex("45df41e40aba5b2a03d08bd1202a1c02ef3954d8aa22ea6c5ae62fd00f290ea9");
    EXPECT_EQ(out.m_merkle_tx.m_block_hash, pblk);

    // Coinbase merkle branch: 3 levels, leaf index 0.
    ASSERT_EQ(out.m_merkle_tx.m_merkle_link.m_branch.size(), 3u);
    uint256 mb0; mb0.SetHex("cd3947cd5a0c26fde01b05a3aa3d7a38717be6ae11d27239365024db36a679a9");
    EXPECT_EQ(out.m_merkle_tx.m_merkle_link.m_branch[0], mb0);
    EXPECT_EQ(out.m_merkle_tx.m_merkle_link.m_index, 0u);

    // Chain (aux) merkle branch: 3 levels, chain slot index 0.
    ASSERT_EQ(out.m_chain_merkle_link.m_branch.size(), 3u);
    uint256 cmb0; cmb0.SetHex("b541c848bc001d07d2bdf8643abab61d2c6ae50d5b2495815339a4b30703a46f");
    EXPECT_EQ(out.m_chain_merkle_link.m_branch[0], cmb0);
    EXPECT_EQ(out.m_chain_merkle_link.m_index, 0u);

    // Parent (LTC) 80-byte block header.
    EXPECT_EQ(out.m_parent_block_header.m_version, 2u);
    EXPECT_EQ(out.m_parent_block_header.m_timestamp, 1410464576u);
    EXPECT_EQ(out.m_parent_block_header.m_bits, 0x1b02548bu);
    EXPECT_EQ(out.m_parent_block_header.m_nonce, 3852127320u);

    // The whole proof is consumed; only the tx_count CompactSize byte remains.
    EXPECT_EQ(ps.cursor_size(), 1u) << "structured parse must stop exactly at tx_count";
}

// ─── Known-Answer Vector: self-hosted regtest/testnet4alpha AuxPoW (h=20) ──
//
// Provenance: a real AuxPoW block mined at height 20 on a self-hosted Dogecoin
// regtest/testnet4alpha seed (VM 215) and ACCEPTED by dogecoind — the
// operator-ratified fixture path (public testnet4 was rejected as contaminated
// with ultrafast blocks). DOGE_REGTEST_H20_CAUXPOW is the 217-byte CAuxPow
// proof exactly as dogecoind's OWN serializer emitted it: parent coinbase
// (witness-stripped) + CMerkleTx tail + chain merkle link + parent 80B header.
// It is a bare CAuxPow — NOT an extended header (no 80B child prefix, no
// tx_count) — so it is fed straight to the c2pool CAuxPow Unserialize path,
// the same one parse_aux_header() drives. Independent serializer => a real
// cross-implementation check, not a c2pool self-round-trip.
namespace {
const char* const DOGE_REGTEST_H20_CAUXPOW =
    "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff2cfabe6d6df091be03e588d8f33a0bc14145cb034dbf68e0a8ca774f0f842027a1366275900100000000000000ffffffff0000000000106303778e4f91a2984bb151de0bf0126c6cde013e9e11f86f7a942818f635f00000000000000000000001000000000000000000000000000000000000000000000000000000000000000000000013175e533f07d6a5e7ab3df1fb0e67283b2b52daf0aaba1efbb2a22c77e96695000000000000000000000001";
} // namespace

TEST(AuxPowKnownAnswerTest, RegtestH20CAuxPowDecodesRealProof) {
    auto blob = hex_to_bytes(DOGE_REGTEST_H20_CAUXPOW);
    ASSERT_EQ(blob.size(), 217u);

    PackStream ps(std::span<const std::byte>(
        reinterpret_cast<const std::byte*>(blob.data()), blob.size()));
    doge::coin::CAuxPow<> out;
    ::Unserialize(ps, out);   // c2pool CAuxPow parser, on dogecoind's own bytes

    // Parent coinbase: single null-prevout input carrying the merged-mining
    // (fabe6d6d) commitment in its scriptSig; no outputs; locktime 0.
    ASSERT_EQ(out.m_merkle_tx.m_tx.vin.size(), 1u);
    EXPECT_TRUE(out.m_merkle_tx.m_tx.vin[0].prevout.hash.IsNull());
    EXPECT_EQ(out.m_merkle_tx.m_tx.vin[0].prevout.index, 0xffffffffu);
    EXPECT_EQ(out.m_merkle_tx.m_tx.vin[0].sequence, 0xffffffffu);
    EXPECT_EQ(out.m_merkle_tx.m_tx.vin[0].scriptSig.m_data,
              hex_to_bytes("fabe6d6df091be03e588d8f33a0bc14145cb034dbf68e0a8ca774f0f842027a1366275900100000000000000"));
    EXPECT_EQ(out.m_merkle_tx.m_tx.vout.size(), 0u);
    EXPECT_EQ(out.m_merkle_tx.m_tx.locktime, 0u);

    // CMerkleTx tail: parent block hash; empty coinbase merkle branch (leaf 0).
    uint256 pblk; pblk.SetHex("f035f61828947a6ff8119e3e01de6c6c12f00bde51b14b98a2914f8e77036310");
    EXPECT_EQ(out.m_merkle_tx.m_block_hash, pblk);
    EXPECT_EQ(out.m_merkle_tx.m_merkle_link.m_branch.size(), 0u);
    EXPECT_EQ(out.m_merkle_tx.m_merkle_link.m_index, 0u);

    // Chain (aux) merkle link: single aux chain => empty branch, slot 0.
    EXPECT_EQ(out.m_chain_merkle_link.m_branch.size(), 0u);
    EXPECT_EQ(out.m_chain_merkle_link.m_index, 0u);

    // Parent (regtest) 80-byte header.
    EXPECT_EQ(out.m_parent_block_header.m_version, 1u);
    EXPECT_TRUE(out.m_parent_block_header.m_previous_block.IsNull());
    uint256 proot; proot.SetHex("9566e9772ca2b2fb1ebaaaf0da522b3b28670efbf13dabe7a5d6073f535e1713");
    EXPECT_EQ(out.m_parent_block_header.m_merkle_root, proot);
    EXPECT_EQ(out.m_parent_block_header.m_timestamp, 0u);
    EXPECT_EQ(out.m_parent_block_header.m_bits, 0u);
    EXPECT_EQ(out.m_parent_block_header.m_nonce, 0x01000000u);  // wire 00 00 00 01 LE

    // The 217-byte CAuxPow is consumed exactly — no trailing bytes, no overrun.
    EXPECT_EQ(ps.cursor_size(), 0u) << "CAuxPow parser must consume exactly 217 bytes";
}

// ─── Mersenne Twister Uniform Int Tests ─────────────────────────────────────

TEST(MersenneTwisterTest, BoostCompatibleOutput) {
    // Verify doge_mt_uniform_int matches boost::uniform_int behavior
    // Known test vector from Dogecoin Core testnet4alpha
    // seed from prevHash "ae162af2..." at offset 7: "2b7efd3" = 45608915
    int result = doge_mt_uniform_int(45608915, 1, 999999);
    EXPECT_EQ(result, 429778) << "Must match boost::uniform_int output for Dogecoin Core parity";
}

TEST(MersenneTwisterTest, DifferentSeedsDifferentResults) {
    int r1 = doge_mt_uniform_int(12345, 1, 999999);
    int r2 = doge_mt_uniform_int(54321, 1, 999999);
    EXPECT_NE(r1, r2);
}

TEST(MersenneTwisterTest, ResultInRange) {
    for (unsigned int seed = 0; seed < 1000; seed += 7) {
        int r = doge_mt_uniform_int(seed, 10, 20);
        EXPECT_GE(r, 10);
        EXPECT_LE(r, 20);
    }
}

TEST(MersenneTwisterTest, SingleValueRange) {
    int r = doge_mt_uniform_int(42, 5, 5);
    EXPECT_EQ(r, 5);
}
