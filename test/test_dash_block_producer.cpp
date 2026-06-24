// DASH block PRODUCER KAT (launcher slice 5) — NETWORK-FREE.
//
// Pins the producer primitives that turn an embedded/dashd block template into
// a fully-serialized, X11-mined block ready for NodeRPC::submit_block_hex:
//
//   dash::coin::compute_merkle_root      — standard Bitcoin/Dash merkle fold
//   dash::coin::target_from_nbits        — compact nBits -> 256-bit target
//   dash::coin::meets_target             — PoW <= target predicate
//   dash::coin::serialize_full_block_hex — header || CompactSize(ntx) || txs
//   dash::coin::mine_block               — X11 nonce search to target
//
// All assertions are REAL and counted (no node, no socket). The merkle KATs use
// an INDEPENDENT in-test reference fold (raw core::Hash over 64-byte concats) so
// the pin is not circular with the production compute_merkle_root.

#include <gtest/gtest.h>

#include <impl/dash/coin/block_producer.hpp>
#include <impl/dash/coin/rpc_data.hpp>
#include <impl/dash/coinbase_builder.hpp>
#include <impl/dash/share_check.hpp>          // dash::DONATION_SCRIPT
#include <impl/dash/params.hpp>
#include <impl/dash/crypto/hash_x11.hpp>

#include <core/hash.hpp>
#include <core/uint256.hpp>
#include <btclibs/util/strencodings.h>        // ParseHex, HexStr

#include <cstdint>
#include <cstring>
#include <map>
#include <span>
#include <vector>

using dash::coin::compute_merkle_root;
using dash::coin::target_from_nbits;
using dash::coin::meets_target;
using dash::coin::serialize_full_block;
using dash::coin::serialize_full_block_hex;
using dash::coin::mine_block;
using dash::coin::coinbase_txid;
using dash::coin::DashWorkData;

namespace {

// Independent reference sha256d-of-pair (NOT the production helper).
uint256 ref_hash_pair(const uint256& a, const uint256& b)
{
    unsigned char buf[64];
    std::memcpy(buf,      a.data(), 32);
    std::memcpy(buf + 32, b.data(), 32);
    return Hash(std::span<const unsigned char>(buf, 64));
}

uint256 leaf_from_byte(unsigned char i)
{
    unsigned char b = i;
    return Hash(std::span<const unsigned char>(&b, 1));
}

// Read a little-endian uint32 out of a byte buffer.
uint32_t rd_u32(const std::vector<unsigned char>& v, size_t off)
{
    return (uint32_t)v[off] | ((uint32_t)v[off+1] << 8)
         | ((uint32_t)v[off+2] << 16) | ((uint32_t)v[off+3] << 24);
}

} // namespace

// (a) Determinism + hand-folded 1-tx and 2-tx cases.
TEST(DashBlockProducer, MerkleRootSingleTx)
{
    uint256 cb = leaf_from_byte(0x01);
    std::vector<uint256> one{cb};
    // 1-tx merkle root == the coinbase txid itself.
    EXPECT_EQ(compute_merkle_root(one).GetHex(), cb.GetHex());
    // Deterministic across calls.
    EXPECT_EQ(compute_merkle_root(one), compute_merkle_root(one));
}

TEST(DashBlockProducer, MerkleRootTwoTx)
{
    uint256 cb = leaf_from_byte(0x01);
    uint256 t1 = leaf_from_byte(0x02);
    std::vector<uint256> two{cb, t1};
    uint256 expect = ref_hash_pair(cb, t1);     // independent reference fold
    EXPECT_EQ(compute_merkle_root(two).GetHex(), expect.GetHex());
}

TEST(DashBlockProducer, MerkleRootThreeTxDuplicatesLast)
{
    // Odd layer -> duplicate last. 3 leaves -> H(H(a,b), H(c,c)).
    uint256 a = leaf_from_byte(0x0a);
    uint256 b = leaf_from_byte(0x0b);
    uint256 c = leaf_from_byte(0x0c);
    std::vector<uint256> three{a, b, c};
    uint256 left  = ref_hash_pair(a, b);
    uint256 right = ref_hash_pair(c, c);        // last duplicated
    uint256 expect = ref_hash_pair(left, right);
    EXPECT_EQ(compute_merkle_root(three).GetHex(), expect.GetHex());
}

TEST(DashBlockProducer, MerkleRootEmptyIsZero)
{
    std::vector<uint256> none;
    EXPECT_TRUE(compute_merkle_root(none).IsNull());
}

// Target / meets_target sanity.
TEST(DashBlockProducer, TargetFromNbitsAndMeets)
{
    // Regtest-style trivial target: huge.
    uint256 easy = target_from_nbits(0x207fffffu);
    EXPECT_FALSE(easy.IsNull());
    // A small hash trivially meets an easy target.
    uint256 tiny; tiny.SetHex("0000000000000000000000000000000000000000000000000000000000000001");
    EXPECT_TRUE(meets_target(tiny, 0x207fffffu));
    // A hash above the target does NOT meet it (use a strict mainnet-ish bits).
    uint256 big; big.SetHex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    EXPECT_FALSE(meets_target(big, 0x1e0ffff0u));
}

// Build a synthetic regtest-style DashWorkData with a real coinbase.
static DashWorkData make_synth_work()
{
    DashWorkData w;
    w.m_version = 0x20000000;
    w.m_previous_block.SetHex(
        "00000000000000000000000000000000000000000000000000000000deadbeef");
    w.m_height = 5;
    w.m_coinbase_value = 5000000000ull;     // 50 DASH-ish
    w.m_bits = 0x207fffffu;                  // regtest trivial target
    w.m_curtime = 1700000000u;
    // Two fake GBT txs: raw hex + their txids (txid = sha256d(rawtx)).
    auto mk_tx = [](unsigned char tag) {
        std::vector<unsigned char> raw(10, tag);  // 10 arbitrary bytes
        return raw;
    };
    for (unsigned char tag : {0x11, 0x22}) {
        auto raw = mk_tx(tag);
        w.m_tx_data_hex.push_back(HexStr(std::span<const unsigned char>(raw.data(), raw.size())));
        w.m_tx_hashes.push_back(Hash(std::span<const unsigned char>(raw.data(), raw.size())));
    }
    return w;
}

// Build a real coinbase for the synthetic work (genesis-style payout).
static std::vector<unsigned char> make_coinbase(const DashWorkData& w)
{
    const core::CoinParams params = dash::make_coin_params(/*testnet=*/true);
    uint160 finder;  // all-zero placeholder pubkey hash
    std::map<std::vector<unsigned char>, uint64_t> empty_weights;
    auto tx_outs = dash::coinbase::compute_dash_payouts(
        w.m_coinbase_value, w.m_packed_payments, finder,
        empty_weights, /*total_weight=*/0, params);
    auto layout = dash::coinbase::build(w, tx_outs, "c2pool", params, uint256::ZERO);
    return layout.bytes;
}

// (c) serialize_full_block_hex round-trips header fields + CompactSize tx-count.
TEST(DashBlockProducer, SerializeFullBlockRoundTrip)
{
    DashWorkData w = make_synth_work();
    auto coinbase = make_coinbase(w);

    const uint32_t nonce = 0x12345678u;
    const uint32_t time  = w.m_curtime;
    auto block = serialize_full_block(w, coinbase, nonce, time);

    // Header is 80 bytes; block has header + CompactSize + coinbase + 2 txs.
    ASSERT_GE(block.size(), (size_t)80 + 1 + coinbase.size());

    // version @0, time @68, bits @72, nonce @76 (all LE u32).
    EXPECT_EQ(rd_u32(block, 0),  (uint32_t)w.m_version);
    EXPECT_EQ(rd_u32(block, 68), time);
    EXPECT_EQ(rd_u32(block, 72), w.m_bits);
    EXPECT_EQ(rd_u32(block, 76), nonce);

    // prev_block @4 (32 bytes, internal LE order).
    EXPECT_EQ(std::memcmp(block.data() + 4, w.m_previous_block.data(), 32), 0);

    // merkle_root @36 == compute_merkle_root([coinbase_txid] + tx_hashes).
    std::vector<uint256> txids{coinbase_txid(coinbase)};
    for (auto& h : w.m_tx_hashes) txids.push_back(h);
    uint256 mr = compute_merkle_root(txids);
    EXPECT_EQ(std::memcmp(block.data() + 36, mr.data(), 32), 0);

    // CompactSize tx-count @80 == 1 coinbase + 2 GBT txs == 3 (< 0xfd: 1 byte).
    EXPECT_EQ(block[80], (unsigned char)3);

    // Coinbase bytes follow the CompactSize verbatim.
    EXPECT_EQ(std::memcmp(block.data() + 81, coinbase.data(), coinbase.size()), 0);

    // hex form decodes back to the same byte vector.
    std::string hex = serialize_full_block_hex(w, coinbase, nonce, time);
    auto decoded = ParseHex(hex);
    ASSERT_EQ(decoded.size(), block.size());
    EXPECT_EQ(std::memcmp(decoded.data(), block.data(), block.size()), 0);
}

// (b) mine_block finds a nonce whose X11 hash meets the slack regtest target,
//     and the winning block's header re-hashes to the reported block_hash.
TEST(DashBlockProducer, MineBlockFindsWinningNonce)
{
    DashWorkData w = make_synth_work();   // bits 0x207fffff -> trivial
    auto coinbase = make_coinbase(w);

    auto mr = mine_block(w, coinbase, /*max_nonce=*/1000000ull);
    ASSERT_TRUE(mr.found);
    EXPECT_TRUE(meets_target(mr.block_hash, w.m_bits));
    EXPECT_FALSE(mr.block_hex.empty());

    // Re-derive the header from the winning block_hex and confirm X11 hash
    // matches the reported block_hash (independent recompute).
    auto block = ParseHex(mr.block_hex);
    ASSERT_GE(block.size(), (size_t)80);
    EXPECT_EQ(rd_u32(block, 76), mr.nonce);     // nonce slot carries the winner
    uint256 pow = dash::crypto::hash_x11(block.data(), 80);
    EXPECT_EQ(pow.GetHex(), mr.block_hash.GetHex());
}

// mine_block is deterministic: same work+coinbase -> same winning nonce.
TEST(DashBlockProducer, MineBlockDeterministic)
{
    DashWorkData w = make_synth_work();
    auto coinbase = make_coinbase(w);
    auto a = mine_block(w, coinbase, 1000000ull);
    auto b = mine_block(w, coinbase, 1000000ull);
    ASSERT_TRUE(a.found);
    ASSERT_TRUE(b.found);
    EXPECT_EQ(a.nonce, b.nonce);
    EXPECT_EQ(a.block_hex, b.block_hex);
}
