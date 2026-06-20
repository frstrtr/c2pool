// ---------------------------------------------------------------------------
// nmc_reconstruct_won_block_test -- pins coin/reconstruct_won_block.hpp, the
// PE-2e won merge-mined block reconstructor.  Proves the captured-GBT-template
// path frames a faithful, daemon-acceptable Namecoin parent block end to end,
// against a SYNTHETIC captured template (no live ShareTracker / node / daemon).
//
// THE FORCED-WON-SHARE SEAM (integrator decision 2026-06-20, mirror dgb #271):
// PE-2e must exercise the won-block reconstruct + relay codec WITHOUT shipping a
// BTC parent --regtest CLI (production/consensus-adjacent surface).  The seam is
// purely test-scoped: WonTemplateFixture synthesizes the exact inputs that exist
// at the instant a share wins the parent block -- the captured GBT template
// (gentx + other txs + their txids) the miner mined against -- so on the won
// path reconstruct_won_block_from_template can be driven directly.  No
// src/impl/btc, src/core, or production NMC node change is involved.
//
// Coverage:
//   * tx layout is [gentx] ++ template_other_txs in template order;
//   * the framed block round-trips through the BlockType codec (the live
//     submitblock / P2P-relay wire encoding) and hex == HexStr(bytes);
//   * merkle_root == compute_merkle_root([gentx_hash] ++ template_txids)
//     (direct compute -- aux chain has the whole template, no branch walk);
//   * an empty captured template => a valid coinbase-only block
//     (correct-and-empty, root == gentx_hash), NEVER a throw / fail-closed.
//
// Links the nmc OBJECT lib + core like the sibling nmc tests (BlockType codec /
// compute_merkle_root / out-of-line MutableTransaction ctor).  MUST also appear
// in the build.yml --target allowlist (#143 NOT_BUILT trap).
// Per-coin isolation: src/impl/nmc/ only.
// ---------------------------------------------------------------------------
#include <gtest/gtest.h>

#include <cstdint>
#include <span>
#include <vector>

#include <core/pack.hpp>
#include <core/uint256.hpp>
#include <util/strencodings.h>

#include "../coin/reconstruct_won_block.hpp"

using nmc::coin::reconstruct_won_block_from_template;
using nmc::coin::ReconstructedWonBlock;
using nmc::coin::compute_merkle_root;
using nmc::coin::SmallBlockHeaderType;
using nmc::coin::MutableTransaction;
using nmc::coin::BlockType;
using nmc::coin::TxIn;
using nmc::coin::TxOut;

namespace {

uint256 H(const char* two) // 0x"two" repeated to 64 hex chars
{
    std::string s;
    for (int i = 0; i < 32; ++i) s += two;
    uint256 h; h.SetHex(s);
    return h;
}

MutableTransaction make_tx(int64_t value)
{
    MutableTransaction tx;
    tx.version = 1;
    tx.locktime = 0;
    TxIn in;
    in.prevout.hash.SetNull();
    in.prevout.index = 0;
    in.sequence = 0xffffffff;
    tx.vin.push_back(in);
    TxOut out;
    out.value = value;
    tx.vout.push_back(out);
    return tx;
}

MutableTransaction make_gentx()
{
    MutableTransaction tx;
    tx.version = 1;
    tx.locktime = 0;
    TxIn in;
    in.prevout.hash.SetNull();
    in.prevout.index = 0xffffffff;   // coinbase marker
    in.sequence = 0xffffffff;
    tx.vin.push_back(in);
    TxOut out;
    out.value = 5000000000LL;
    tx.vout.push_back(out);
    return tx;
}

SmallBlockHeaderType make_small_header()
{
    SmallBlockHeaderType h;
    h.m_version = 0x20000000;
    h.m_previous_block.SetHex(
        "00000000000000000000000000000000000000000000000000000000deadbeef");
    h.m_timestamp = 1718700000;
    h.m_bits = 0x1a0fffff;
    h.m_nonce = 0x12345678;
    return h;
}

uint256 fixed_gentx_hash()
{
    uint256 h;
    h.SetHex("1111111111111111111111111111111111111111111111111111111111111111");
    return h;
}

// THE FORCED-WON-SHARE SEAM (test-only): the captured GBT template snapshot at
// the instant a share wins the parent block -- gentx + other txs + their txids,
// exactly the (current_work transactions[] / transaction_hashes[]) the miner
// mined against.  No live node / daemon / BTC --regtest is stood up.
struct WonTemplateFixture
{
    SmallBlockHeaderType            small_header = make_small_header();
    MutableTransaction              gentx        = make_gentx();
    uint256                         gentx_hash   = fixed_gentx_hash();
    std::vector<MutableTransaction> other_txs;
    std::vector<uint256>            other_txids;

    void add(int64_t value, const char* txid)
    {
        other_txs.push_back(make_tx(value));
        other_txids.push_back(H(txid));
    }

    ReconstructedWonBlock reconstruct() const
    {
        return reconstruct_won_block_from_template(
            small_header, gentx, gentx_hash, other_txs, other_txids);
    }
};

// --- Test 1: tx layout is [gentx] ++ template_other_txs in template order -----
TEST(NmcReconstructWonBlock, CoinbaseFirstThenTemplateOrder)
{
    WonTemplateFixture f;
    f.add(11, "c1");
    f.add(22, "d0");

    auto got = f.reconstruct();

    PackStream ps(got.bytes);
    BlockType blk;
    ps >> blk;
    ASSERT_EQ(blk.m_txs.size(), 3u);                       // gentx + 2 template txs
    EXPECT_EQ(blk.m_txs[0].vin[0].prevout.index, 0xffffffffu); // coinbase first
    EXPECT_EQ(blk.m_txs[1].vout[0].value, 11);             // template order preserved
    EXPECT_EQ(blk.m_txs[2].vout[0].value, 22);
}

// --- Test 2: framed block round-trips through the submitblock/relay codec ------
TEST(NmcReconstructWonBlock, RoundTripsAndHexMatchesBytes)
{
    WonTemplateFixture f;
    f.add(11, "c1");
    f.add(22, "d0");

    auto got = f.reconstruct();

    auto sp = std::span<const std::byte>(
        reinterpret_cast<const std::byte*>(got.bytes.data()), got.bytes.size());
    EXPECT_EQ(got.hex, HexStr(sp));

    // Re-serializing the deserialized block reproduces the same wire bytes.
    PackStream ps(got.bytes);
    BlockType blk;
    ps >> blk;
    PackStream re = pack<BlockType>(blk);
    auto resp = re.get_span();
    std::vector<unsigned char> rebytes(
        reinterpret_cast<const unsigned char*>(resp.data()),
        reinterpret_cast<const unsigned char*>(resp.data()) + resp.size());
    EXPECT_EQ(rebytes, got.bytes);
}

// --- Test 3: merkle_root == direct compute over [gentx_hash] ++ template txids -
TEST(NmcReconstructWonBlock, MerkleRootIsDirectComputeOverFullTxSet)
{
    WonTemplateFixture f;
    f.add(11, "c1");
    f.add(22, "d0");

    std::vector<uint256> txids = { f.gentx_hash, H("c1"), H("d0") };
    uint256 expected = compute_merkle_root(txids);

    auto got = f.reconstruct();
    PackStream ps(got.bytes);
    BlockType blk;
    ps >> blk;
    EXPECT_EQ(blk.m_merkle_root, expected);
}

// --- Test 4: empty captured template => valid coinbase-only block -------------
// The embedded path emits transactions[]==[] until mempool tx-selection wires;
// reconstruct must yield a valid gentx-only block (correct-and-empty), and with
// a single leaf the merkle root collapses to the gentx hash -- never throw.
TEST(NmcReconstructWonBlock, EmptyTemplateGentxOnly)
{
    WonTemplateFixture f;   // no .add() -> empty captured template

    auto got = f.reconstruct();

    PackStream ps(got.bytes);
    BlockType blk;
    ps >> blk;
    ASSERT_EQ(blk.m_txs.size(), 1u);
    EXPECT_EQ(blk.m_txs[0].vin[0].prevout.index, 0xffffffffu);
    EXPECT_EQ(blk.m_merkle_root, f.gentx_hash);  // single leaf => root == gentx_hash

    auto sp = std::span<const std::byte>(
        reinterpret_cast<const std::byte*>(got.bytes.data()), got.bytes.size());
    EXPECT_EQ(got.hex, HexStr(sp));
}

} // namespace
