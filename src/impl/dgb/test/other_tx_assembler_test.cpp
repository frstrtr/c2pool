// ---------------------------------------------------------------------------
// dgb_other_tx_assembler_test -- pins coin/other_tx_assembler.hpp, the won-block
// reconstructor's (#82 sub-slice 2) bridge from the ordered other_tx hash list
// (resolve_other_tx_hashes, sub-slice 1) to the MutableTransaction vector that
// assemble_won_block frames as txs = [gentx] ++ other_txs.
//
// Faithful to p2pool data.py as_block:  other_txs = [known_txs[h] for h in
// transaction_hashes].  Proves:
//   * the known_txs lookup PRESERVES ref/hash order (= block other_txs order,
//     which fixes the merkle root) and is the SAME order assemble_won_block frames;
//   * a hash absent from known_txs THROWS std::out_of_range (loud failure: a
//     dropped other_tx => wrong merkle root => daemon-rejected block);
//   * empty hash list => empty other_txs;
//   * END-TO-END: resolve_other_tx_hashes -> assemble_other_txs -> assemble_won_block
//     lands the resolved txs in the block in order, after the coinbase;
//   * WITNESS reachability via the other_tx path: a witness-bearing other_tx
//     flips the assembled block to the TX_WITH_WITNESS codec (DGB is
//     segwit-active), proving witness framing is not gentx-only dead code.
//
// Links the dgb OBJECT lib (assemble_won_block reuses dgb::check_merkle_link +
// the live BlockType submitblock codec) like dgb_block_assembly_test. MUST also
// appear in the build.yml --target allowlist (#143 NOT_BUILT trap).
// ---------------------------------------------------------------------------

#include <gtest/gtest.h>

#include <functional>
#include <map>
#include <stdexcept>
#include <vector>

#include <core/pack.hpp>
#include <core/uint256.hpp>

#include "../coin/other_tx_assembler.hpp"
#include "../coin/other_tx_resolver.hpp"
#include "../coin/block_assembly.hpp"

namespace {

using dgb::coin::MutableTransaction;
using dgb::coin::BlockType;
using dgb::coin::SmallBlockHeaderType;
using dgb::coin::assemble_other_txs;
using dgb::coin::assemble_won_block;
using dgb::coin::resolve_other_tx_hashes;
using dgb::TxHashRefs;

uint256 H(const char* two)
{
    std::string s;
    for (int i = 0; i < 32; ++i) s += two;
    uint256 h; h.SetHex(s);
    return h;
}

// A tx whose output value tags it, so we can assert identity/order after the
// lookup and after the block round-trip.
MutableTransaction tagged_tx(int64_t value)
{
    MutableTransaction tx;
    tx.version = 1;
    tx.locktime = 0;
    dgb::coin::TxIn in;
    in.prevout.hash.SetNull();
    in.prevout.index = 0;
    in.sequence = 0xffffffff;
    tx.vin.push_back(in);
    dgb::coin::TxOut out;
    out.value = value;
    tx.vout.push_back(out);
    return tx;
}

MutableTransaction witness_tx(int64_t value)
{
    auto tx = tagged_tx(value);
    tx.vin[0].scriptWitness.stack.assign(1, std::vector<unsigned char>(4, 0xab));
    return tx;
}

MutableTransaction coinbase_gentx()
{
    MutableTransaction tx;
    tx.version = 1;
    tx.locktime = 0;
    dgb::coin::TxIn in;
    in.prevout.hash.SetNull();
    in.prevout.index = 0xffffffff;
    in.sequence = 0xffffffff;
    tx.vin.push_back(in);
    dgb::coin::TxOut out;
    out.value = 5000000000LL;
    tx.vout.push_back(out);
    return tx;
}

SmallBlockHeaderType small_header()
{
    SmallBlockHeaderType h;
    h.m_version = 0x20000000;
    h.m_previous_block.SetHex("00000000000000000000000000000000000000000000000000000000deadbeef");
    h.m_timestamp = 1718700000;
    h.m_bits = 0x1a0fffff;
    h.m_nonce = 0x12345678;
    return h;
}

// A synthetic known_txs store keyed by hash, with a lookup matching the
// assembler's injected (hash)->const MutableTransaction* contract.
struct KnownTxs
{
    std::map<uint256, MutableTransaction> by_hash;
    const MutableTransaction* lookup(const uint256& h) const
    {
        auto it = by_hash.find(h);
        return it == by_hash.end() ? nullptr : &it->second;
    }
    std::function<const MutableTransaction*(const uint256&)> fn() const
    {
        return [this](const uint256& h) { return lookup(h); };
    }
};

// --- Test 1: lookup preserves order ----------------------------------------
TEST(DgbOtherTxAssembler, PreservesHashOrder)
{
    KnownTxs k;
    k.by_hash[H("c0")] = tagged_tx(10);
    k.by_hash[H("c1")] = tagged_tx(20);
    k.by_hash[H("c2")] = tagged_tx(30);

    // hashes deliberately NOT in map-sorted order -- output must follow input.
    std::vector<uint256> hashes = { H("c2"), H("c0"), H("c1") };
    auto txs = assemble_other_txs(hashes, k.fn());

    ASSERT_EQ(txs.size(), 3u);
    EXPECT_EQ(txs[0].vout[0].value, 30);
    EXPECT_EQ(txs[1].vout[0].value, 10);
    EXPECT_EQ(txs[2].vout[0].value, 20);
}

// --- Test 2: missing hash throws (loud failure, no partial block) ----------
TEST(DgbOtherTxAssembler, MissingHashThrows)
{
    KnownTxs k;
    k.by_hash[H("c0")] = tagged_tx(10);

    std::vector<uint256> hashes = { H("c0"), H("ff") };  // ff is unknown
    EXPECT_THROW(assemble_other_txs(hashes, k.fn()), std::out_of_range);
}

// --- Test 3: empty hash list => empty other_txs ----------------------------
TEST(DgbOtherTxAssembler, EmptyHashesEmptyTxs)
{
    KnownTxs k;
    std::vector<uint256> none;
    auto txs = assemble_other_txs(none, k.fn());
    EXPECT_TRUE(txs.empty());
}

// --- Test 4: end-to-end resolve -> assemble -> won-block --------------------
// Walks the full reconstructor bridge: a 2-share ancestry's refs resolve to
// hashes (sub-slice 1), the hashes resolve to txs (sub-slice 2), and the txs
// frame into the block after the coinbase, in order.
TEST(DgbOtherTxAssembler, EndToEndResolveAssembleFrame)
{
    // ancestry: won <- p1 ; won.nths=[c0,c1], p1.nths=[d0]
    const uint256 won = H("a0"), p1 = H("a1");
    std::map<uint256, uint256> parent = { {won, p1} };
    std::map<uint256, std::vector<uint256>> nths = {
        {won, { H("c0"), H("c1") }},
        {p1,  { H("d0") }},
    };
    auto nth_parent_fn = [&](const uint256& start, uint64_t n) -> uint256 {
        uint256 cur = start;
        for (uint64_t i = 0; i < n; ++i) {
            auto it = parent.find(cur);
            if (it == parent.end()) { uint256 z; z.SetNull(); return z; }
            cur = it->second;
        }
        return cur;
    };
    auto new_tx_hashes_fn = [&](const uint256& h) -> const std::vector<uint256>& {
        return nths.at(h);
    };

    // refs: (0,1)=won.nths[1]=c1 ; (1,0)=p1.nths[0]=d0 ; (0,0)=won.nths[0]=c0
    std::vector<TxHashRefs> refs = { {0,1}, {1,0}, {0,0} };
    auto hashes = resolve_other_tx_hashes(won, refs, nth_parent_fn, new_tx_hashes_fn);
    ASSERT_EQ(hashes.size(), 3u);
    EXPECT_EQ(hashes[0], H("c1"));
    EXPECT_EQ(hashes[1], H("d0"));
    EXPECT_EQ(hashes[2], H("c0"));

    KnownTxs k;
    k.by_hash[H("c0")] = tagged_tx(100);
    k.by_hash[H("c1")] = tagged_tx(200);
    k.by_hash[H("d0")] = tagged_tx(300);
    auto other = assemble_other_txs(hashes, k.fn());

    auto gentx = coinbase_gentx();
    uint256 gtx_hash; gtx_hash.SetHex("1111111111111111111111111111111111111111111111111111111111111111");
    ::dgb::MerkleLink link;  // empty branch => root == gtx_hash
    auto [bytes, hex] = assemble_won_block(small_header(), gentx, gtx_hash, link, other);

    PackStream ps(bytes);
    BlockType blk;
    ps >> blk;
    // [gentx] ++ other_txs, in resolved (ref) order: 200 (c1), 300 (d0), 100 (c0)
    ASSERT_EQ(blk.m_txs.size(), 4u);
    EXPECT_EQ(blk.m_txs[0].vin[0].prevout.index, 0xffffffffu); // coinbase first
    EXPECT_EQ(blk.m_txs[1].vout[0].value, 200);
    EXPECT_EQ(blk.m_txs[2].vout[0].value, 300);
    EXPECT_EQ(blk.m_txs[3].vout[0].value, 100);
}

// --- Test 5: witness-bearing other_tx flips block to TX_WITH_WITNESS --------
// Proves the segwit-active path is reachable via the other_tx leg (not just the
// gentx): an other_tx carrying a witness stack makes the conditional codec emit
// a witness block, and the witness round-trips through BlockType.
TEST(DgbOtherTxAssembler, WitnessOtherTxEmitsWitnessBlock)
{
    KnownTxs k;
    k.by_hash[H("c0")] = witness_tx(42);
    std::vector<uint256> hashes = { H("c0") };
    auto other = assemble_other_txs(hashes, k.fn());
    ASSERT_EQ(other.size(), 1u);
    ASSERT_TRUE(other[0].HasWitness());

    auto gentx = coinbase_gentx();             // legacy coinbase
    ASSERT_FALSE(gentx.HasWitness());
    uint256 gtx_hash; gtx_hash.SetHex("1111111111111111111111111111111111111111111111111111111111111111");
    ::dgb::MerkleLink link;

    auto [wbytes, whex] = assemble_won_block(small_header(), gentx, gtx_hash, link, other);
    // same block but with a legacy other_tx => strictly smaller (no witness).
    KnownTxs kl; kl.by_hash[H("c0")] = tagged_tx(42);
    auto legacy_other = assemble_other_txs(hashes, kl.fn());
    auto [lbytes, lhex] = assemble_won_block(small_header(), gentx, gtx_hash, link, legacy_other);
    EXPECT_GT(wbytes.size(), lbytes.size());

    PackStream ps(wbytes);
    BlockType blk;
    ps >> blk;
    ASSERT_EQ(blk.m_txs.size(), 2u);
    EXPECT_FALSE(blk.m_txs[0].HasWitness());   // coinbase legacy
    EXPECT_TRUE(blk.m_txs[1].HasWitness());    // other_tx carries witness
    ASSERT_EQ(blk.m_txs[1].vin[0].scriptWitness.stack.size(), 1u);
    EXPECT_EQ(blk.m_txs[1].vin[0].scriptWitness.stack[0],
              std::vector<unsigned char>(4, 0xab));
}

} // namespace
