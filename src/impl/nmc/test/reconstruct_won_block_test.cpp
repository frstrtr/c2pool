// ---------------------------------------------------------------------------
// nmc_reconstruct_won_block_test -- pins coin/reconstruct_won_block.hpp +
// coin/block_assembly.hpp, the PE-2e (#251) won-block reconstructor.  Mirrors
// the dgb #271 captured-template SSOT and exercises it through a FORCED-WON-
// SHARE SEAM (the integrator's PE-2e won-block-seam decision: a test-only
// synthetic share where share == the parent block, so the on_block_found path
// fires -- NO BTC --regtest CLI / production surface is added).
//
// Proves, against synthetic inputs (no live ShareTracker / mempool / daemon):
//   * the forced-won-share seam fires the reconstruct and hands the broadcaster
//     a faithful parent block (header fields preserved, coinbase at tx 0);
//   * the captured GBT template is the broadcast tx source: block tx layout is
//     [gentx] ++ template_other_txs in template order;
//   * the merkle_root is RECOMPUTED via the aux_merkle_root SSOT (empty branch
//     => root == gentx_hash; non-empty branch => the walked root), not passed
//     through -- so the reconstructed block hashes correctly and the daemon
//     accepts it via the live BlockType / submitblock codec (bytes round-trip,
//     hex == HexStr);
//   * an empty captured template yields a valid coinbase-only block
//     (correct-and-empty, never fail-closed).
//
// Links the nmc OBJECT lib like the sibling nmc_template_builder_test
// (block_assembly.hpp pulls BlockType / MutableTransaction; header_chain.hpp
// pulls aux_merkle_root).  MUST also appear in the build.yml --target allowlist
// (#143 NOT_BUILT trap).  Per-coin isolation: src/impl/nmc/ only.
// ---------------------------------------------------------------------------
#include <gtest/gtest.h>

#include <cstdint>
#include <span>
#include <vector>

#include <core/pack.hpp>
#include <core/uint256.hpp>
#include <btclibs/util/strencodings.h>

#include "../coin/reconstruct_won_block.hpp"
#include "../coin/block_assembly.hpp"
#include "../coin/header_chain.hpp"   // aux_merkle_root, for the merkle-root oracle
#include "../coin/block.hpp"
#include "../coin/transaction.hpp"

using nmc::coin::reconstruct_won_block_from_template;
using nmc::coin::assemble_won_block;
using nmc::coin::aux_merkle_root;
using nmc::coin::ReconstructedWonBlock;
using nmc::coin::BlockType;
using nmc::coin::SmallBlockHeaderType;
using nmc::coin::MutableTransaction;

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
    nmc::coin::TxIn in;
    in.prevout.hash.SetNull();
    in.prevout.index = 0;
    in.sequence = 0xffffffff;
    tx.vin.push_back(in);
    nmc::coin::TxOut out;
    out.value = value;
    tx.vout.push_back(out);
    return tx;
}

MutableTransaction make_gentx()
{
    MutableTransaction tx;
    tx.version = 1;
    tx.locktime = 0;
    nmc::coin::TxIn in;
    in.prevout.hash.SetNull();
    in.prevout.index = 0xffffffff;   // coinbase
    in.sequence = 0xffffffff;
    tx.vin.push_back(in);
    nmc::coin::TxOut out;
    out.value = 5000000000LL;
    tx.vout.push_back(out);
    return tx;
}

SmallBlockHeaderType make_small_header()
{
    SmallBlockHeaderType h;
    h.m_version = 0x20000000;
    h.m_previous_block.SetHex("00000000000000000000000000000000000000000000000000000000deadbeef");
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

// --- The forced-won-share seam (test-only) -----------------------------------
// Models the PE-2e injection point: a synthetic share whose header IS the parent
// block header and whose coinbase IS the parent gentx (share == parent block),
// plus the GBT template captured at job hand-out.  In the run-loop this is what
// on_block_found receives when a share's PoW also satisfies the parent target;
// here it is hand-built so the won-block reconstruct + relay path can be driven
// without standing up a regtest daemon or adding any production CLI surface.
struct ForcedWonShare
{
    SmallBlockHeaderType header;
    MutableTransaction   gentx;
    uint256              gentx_hash;
    std::vector<uint256> merkle_branch;   // gentx -> root sibling branch
    uint32_t             merkle_index = 0;
    std::vector<MutableTransaction> captured_template_txs; // current_work transactions[]
};

ForcedWonShare make_forced_won_share(std::vector<MutableTransaction> template_txs,
                                     std::vector<uint256> branch = {},
                                     uint32_t index = 0)
{
    ForcedWonShare s;
    s.header = make_small_header();
    s.gentx = make_gentx();
    s.gentx_hash = fixed_gentx_hash();
    s.merkle_branch = std::move(branch);
    s.merkle_index = index;
    s.captured_template_txs = std::move(template_txs);
    return s;
}

// The seam's reconstruct closure: exactly what make_on_block_found would invoke
// when share == parent block -- reconstruct the broadcast block from the
// captured template (NOT a share ref-walk).
ReconstructedWonBlock fire_on_block_found(const ForcedWonShare& s)
{
    return reconstruct_won_block_from_template(
        s.header, s.merkle_branch, s.merkle_index,
        s.gentx, s.gentx_hash, s.captured_template_txs);
}

// --- Test 1: the seam fires and hands the broadcaster a faithful parent block -
TEST(NmcReconstructWonBlock, ForcedWonShareSeamFiresReconstruct)
{
    auto share = make_forced_won_share({ make_tx(11), make_tx(22) });

    ReconstructedWonBlock got = fire_on_block_found(share);

    ASSERT_FALSE(got.bytes.empty());          // a block was produced -> relay fires
    PackStream ps(got.bytes);
    BlockType blk;
    ps >> blk;

    // Header fields preserved from the forced share (share == parent block).
    EXPECT_EQ(blk.m_version,        share.header.m_version);
    EXPECT_EQ(blk.m_previous_block, share.header.m_previous_block);
    EXPECT_EQ(blk.m_timestamp,      share.header.m_timestamp);
    EXPECT_EQ(blk.m_bits,           share.header.m_bits);
    EXPECT_EQ(blk.m_nonce,          share.header.m_nonce);
    // Empty branch => merkle_root == gentx_hash (recomputed, not passed through).
    EXPECT_EQ(blk.m_merkle_root, share.gentx_hash);
    // Coinbase is tx 0.
    ASSERT_GE(blk.m_txs.size(), 1u);
    EXPECT_EQ(blk.m_txs[0].vin[0].prevout.index, 0xffffffffu);
    EXPECT_TRUE(blk.m_txs[0].vin[0].prevout.hash.IsNull());
}

// --- Test 2: captured GBT template is the broadcast tx source, in order -------
TEST(NmcReconstructWonBlock, TemplateIsBroadcastTxSourceInOrder)
{
    auto share = make_forced_won_share({ make_tx(11), make_tx(22) });

    ReconstructedWonBlock got = fire_on_block_found(share);

    PackStream ps(got.bytes);
    BlockType blk;
    ps >> blk;
    ASSERT_EQ(blk.m_txs.size(), 3u);                       // gentx + 2 template txs
    EXPECT_EQ(blk.m_txs[0].vin[0].prevout.index, 0xffffffffu);
    EXPECT_EQ(blk.m_txs[1].vout[0].value, 11);             // template order preserved
    EXPECT_EQ(blk.m_txs[2].vout[0].value, 22);

    // bytes round-trip and hex == HexStr (the live submitblock codec).
    auto sp = std::span<const std::byte>(
        reinterpret_cast<const std::byte*>(got.bytes.data()), got.bytes.size());
    EXPECT_EQ(got.hex, HexStr(sp));

    // from_template framing == direct assemble_won_block of the same tx set.
    auto direct = assemble_won_block(share.header, share.gentx, share.gentx_hash,
                                     share.merkle_branch, share.merkle_index,
                                     share.captured_template_txs);
    EXPECT_EQ(got.bytes, direct.first);
    EXPECT_EQ(got.hex, direct.second);
}

// --- Test 3: empty captured template => valid coinbase-only block -------------
// The embedded path emits transactions[]==[] until mempool tx-selection wires;
// reconstruct must yield a valid gentx-only block (correct-and-empty), not throw.
TEST(NmcReconstructWonBlock, EmptyTemplateGentxOnly)
{
    auto share = make_forced_won_share({});   // captured template was empty

    ReconstructedWonBlock got = fire_on_block_found(share);

    PackStream ps(got.bytes);
    BlockType blk;
    ps >> blk;
    ASSERT_EQ(blk.m_txs.size(), 1u);
    EXPECT_EQ(blk.m_txs[0].vin[0].prevout.index, 0xffffffffu);
    EXPECT_EQ(blk.m_merkle_root, share.gentx_hash);  // empty branch => root == gentx_hash
    auto sp = std::span<const std::byte>(
        reinterpret_cast<const std::byte*>(got.bytes.data()), got.bytes.size());
    EXPECT_EQ(got.hex, HexStr(sp));
}

// --- Test 4: non-empty merkle branch => root is the walked aux_merkle_root -----
// Proves the header reconstruct recomputes the root via the SSOT branch walk
// (not a passthrough), so a won share that committed the gentx below a non-
// trivial merkle branch still frames a daemon-acceptable block.
TEST(NmcReconstructWonBlock, NonEmptyBranchRecomputesRootViaSsot)
{
    std::vector<uint256> branch = { H("ab"), H("cd") };
    uint32_t index = 0b10;   // gentx on the right at level 0, left at level 1
    auto share = make_forced_won_share({ make_tx(7) }, branch, index);

    ReconstructedWonBlock got = fire_on_block_found(share);

    PackStream ps(got.bytes);
    BlockType blk;
    ps >> blk;
    EXPECT_EQ(blk.m_merkle_root,
              aux_merkle_root(share.gentx_hash, branch, index));
    // Not the leaf -- branch is non-trivial, so root must differ from gentx_hash.
    EXPECT_NE(blk.m_merkle_root, share.gentx_hash);
}

} // namespace
