// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// dgb_reconstruct_won_block_test -- pins coin/reconstruct_won_block.hpp, the
// won-block reconstructor's (#82) BODY: the single composition the dispatch
// handler injects as its WonBlockReconstructor.  Proves the three landed
// sub-slices compose into a faithful p2pool Share.as_block, end to end, against
// a SYNTHETIC ancestry + known-tx set (no live ShareTracker / mempool):
//   * refs --resolve--> ordered hashes --assemble--> txs --frame--> {bytes,hex}
//   * the composed bytes are IDENTICAL to assemble_won_block fed the manually
//     resolved other_txs (no step reorders / drops / duplicates), hex==HexStr;
//   * block tx layout is [gentx] ++ other_txs in transaction_hash_refs order;
//   * empty refs => block carries the gentx only;
//   * a malformed ref (walk past chain end) and an unknown other_tx hash each
//     PROPAGATE as std::out_of_range -- the reconstructor never emits a partial
//     or wrong block.
//
// Links the dgb OBJECT lib like dgb_block_assembly_test (block_assembly.hpp pulls
// BlockType / MutableTransaction / check_merkle_link).  MUST also appear in the
// build.yml --target allowlist (#143 NOT_BUILT trap).
// ---------------------------------------------------------------------------
#include <gtest/gtest.h>

#include <functional>
#include <map>
#include <span>
#include <stdexcept>
#include <vector>

#include <core/pack.hpp>
#include <core/uint256.hpp>
#include <util/strencodings.h>

#include "../coin/reconstruct_won_block.hpp"
#include "../coin/won_share_inputs.hpp"

using dgb::coin::reconstruct_won_block;
using dgb::coin::reconstruct_won_block_from_template;
using dgb::coin::assemble_won_block;
using dgb::coin::resolve_other_tx_hashes;
using dgb::coin::assemble_other_txs;
using dgb::coin::ReconstructedWonBlock;
using dgb::coin::BlockType;
using dgb::coin::SmallBlockHeaderType;
using dgb::coin::MutableTransaction;
using dgb::TxHashRefs;
using dgb::coin::won_share_inputs;
using dgb::coin::WonShareInputs;

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

MutableTransaction make_gentx()
{
    MutableTransaction tx;
    tx.version = 1;
    tx.locktime = 0;
    dgb::coin::TxIn in;
    in.prevout.hash.SetNull();
    in.prevout.index = 0xffffffff;   // coinbase
    in.sequence = 0xffffffff;
    tx.vin.push_back(in);
    dgb::coin::TxOut out;
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

// Synthetic ancestry won <- p1 <- p2, each share carrying new_transaction_hashes,
// plus a known_txs store mapping those hashes to distinct MutableTransactions.
struct Fixture
{
    uint256 won = H("a0"), p1 = H("a1"), p2 = H("a2");
    std::map<uint256, uint256> parent;
    std::map<uint256, std::vector<uint256>> nths;
    std::map<uint256, MutableTransaction> known;

    Fixture()
    {
        parent[won] = p1;
        parent[p1]  = p2;
        nths[won] = { H("c0"), H("c1") };
        nths[p1]  = { H("d0") };
        nths[p2]  = { H("e0"), H("e1") };
        // distinct values so order is observable downstream
        known[H("c1")] = make_tx(11);
        known[H("d0")] = make_tx(22);
        known[H("c0")] = make_tx(33);
    }

    std::function<uint256(const uint256&, uint64_t)> nth_parent() const
    {
        auto p = parent;
        return [p](const uint256& start, uint64_t n) {
            uint256 cur = start;
            for (uint64_t i = 0; i < n; ++i) {
                auto it = p.find(cur);
                if (it == p.end()) return uint256();
                cur = it->second;
            }
            return cur;
        };
    }
    std::function<const std::vector<uint256>&(const uint256&)> new_tx() const
    {
        return [this](const uint256& h) -> const std::vector<uint256>& { return nths.at(h); };
    }
    std::function<const MutableTransaction*(const uint256&)> known_fn() const
    {
        return [this](const uint256& h) -> const MutableTransaction* {
            auto it = known.find(h);
            return it == known.end() ? nullptr : &it->second;
        };
    }
};

// --- Test 1: end-to-end composition == manual resolve+assemble+frame ----------
TEST(DgbReconstructWonBlock, ComposesToIdenticalBlock)
{
    Fixture f;
    auto sh = make_small_header();
    auto gentx = make_gentx();
    auto gh = fixed_gentx_hash();
    ::dgb::MerkleLink link;  // empty branch => root == gentx_hash
    // refs: (0,1) -> won.nths[1]=c1 ; (1,0) -> p1.nths[0]=d0
    std::vector<TxHashRefs> refs = { TxHashRefs(0, 1), TxHashRefs(1, 0) };

    auto got = reconstruct_won_block(sh, link, gentx, gh, f.won, refs,
                                     f.nth_parent(), f.new_tx(), f.known_fn());

    // Independently drive the three SSOT steps and frame directly.
    auto hashes = resolve_other_tx_hashes(f.won, refs, f.nth_parent(), f.new_tx());
    auto others = assemble_other_txs(hashes, f.known_fn());
    auto direct = assemble_won_block(sh, gentx, gh, link, others);

    EXPECT_EQ(got.bytes, direct.first);
    EXPECT_EQ(got.hex, direct.second);
    auto sp = std::span<const std::byte>(
        reinterpret_cast<const std::byte*>(got.bytes.data()), got.bytes.size());
    EXPECT_EQ(got.hex, HexStr(sp));
}

// --- Test 2: tx layout is [gentx] ++ other_txs in ref order -------------------
TEST(DgbReconstructWonBlock, CoinbaseFirstThenRefOrder)
{
    Fixture f;
    auto sh = make_small_header();
    auto gentx = make_gentx();
    auto gh = fixed_gentx_hash();
    ::dgb::MerkleLink link;
    std::vector<TxHashRefs> refs = { TxHashRefs(0, 1), TxHashRefs(1, 0) };

    auto got = reconstruct_won_block(sh, link, gentx, gh, f.won, refs,
                                     f.nth_parent(), f.new_tx(), f.known_fn());

    PackStream ps(got.bytes);
    BlockType blk;
    ps >> blk;

    ASSERT_EQ(blk.m_txs.size(), 3u);           // gentx + 2 others
    // Header merkle_root is recomputed over the ACTUAL block tx vector
    // ([gentx_hash] ++ each other-tx txid), per the #303 bad-txnmrklroot fix --
    // NOT the empty-merkle_link walk (which would yield gentx_hash alone).  Pin
    // header/body consistency via the same build_block_merkle_root SSOT.
    {
        std::vector<uint256> expect_txids = {
            gh,
            dgb::coin::compute_txid(blk.m_txs[1]),
            dgb::coin::compute_txid(blk.m_txs[2]),
        };
        EXPECT_EQ(blk.m_merkle_root,
                  dgb::coin::build_block_merkle_root(expect_txids));
    }
    EXPECT_EQ(blk.m_txs[0].vin[0].prevout.index, 0xffffffffu); // coinbase at 0
    EXPECT_TRUE(blk.m_txs[0].vin[0].prevout.hash.IsNull());
    EXPECT_EQ(blk.m_txs[1].vout[0].value, 11); // c1 -> make_tx(11), ref order
    EXPECT_EQ(blk.m_txs[2].vout[0].value, 22); // d0 -> make_tx(22)
}

// --- Test 3: empty refs => block carries only the gentx -----------------------
TEST(DgbReconstructWonBlock, EmptyRefsGentxOnly)
{
    Fixture f;
    auto sh = make_small_header();
    auto gentx = make_gentx();
    auto gh = fixed_gentx_hash();
    ::dgb::MerkleLink link;
    std::vector<TxHashRefs> refs;  // none

    auto got = reconstruct_won_block(sh, link, gentx, gh, f.won, refs,
                                     f.nth_parent(), f.new_tx(), f.known_fn());

    PackStream ps(got.bytes);
    BlockType blk;
    ps >> blk;
    ASSERT_EQ(blk.m_txs.size(), 1u);
    EXPECT_EQ(blk.m_txs[0].vin[0].prevout.index, 0xffffffffu);
}

// --- Test 4: malformed ref (walk past chain end) propagates as throw ----------
TEST(DgbReconstructWonBlock, RefPastChainThrows)
{
    Fixture f;
    auto sh = make_small_header();
    auto gentx = make_gentx();
    auto gh = fixed_gentx_hash();
    ::dgb::MerkleLink link;
    // share_count 9 walks far past p2 (the chain end) -> null ancestor.
    std::vector<TxHashRefs> refs = { TxHashRefs(9, 0) };

    EXPECT_THROW(
        reconstruct_won_block(sh, link, gentx, gh, f.won, refs,
                              f.nth_parent(), f.new_tx(), f.known_fn()),
        std::out_of_range);
}

// --- Test 5: unknown other_tx hash propagates as throw ------------------------
TEST(DgbReconstructWonBlock, UnknownKnownTxThrows)
{
    Fixture f;
    f.known.erase(H("c1"));   // resolves but is absent from known_txs
    auto sh = make_small_header();
    auto gentx = make_gentx();
    auto gh = fixed_gentx_hash();
    ::dgb::MerkleLink link;
    std::vector<TxHashRefs> refs = { TxHashRefs(0, 1) }; // -> c1, now missing

    EXPECT_THROW(
        reconstruct_won_block(sh, link, gentx, gh, f.won, refs,
                              f.nth_parent(), f.new_tx(), f.known_fn()),
        std::out_of_range);
}

// --- Test 5: template path == ref path for the SAME tx set (equivalence) ------
// Proves reconstruct_won_block_from_template (the CORRECT block-broadcast
// source: captured GBT template txs) frames a byte-identical block to the
// ref-walk path when fed the same non-coinbase tx set -- i.e. the re-scope is a
// pure SOURCE swap, the framing/merkle/codec are unchanged.
TEST(DgbReconstructWonBlock, TemplatePathMatchesRefPathForSameTxSet)
{
    Fixture f;
    auto sh = make_small_header();
    auto gentx = make_gentx();
    auto gh = fixed_gentx_hash();
    ::dgb::MerkleLink link;
    std::vector<TxHashRefs> refs = { TxHashRefs(0, 1), TxHashRefs(1, 0) };

    // Ref-walk path: resolve hashes -> assemble the other_txs the share refs to.
    auto hashes = resolve_other_tx_hashes(f.won, refs, f.nth_parent(), f.new_tx());
    auto template_txs = assemble_other_txs(hashes, f.known_fn());

    auto ref_got = reconstruct_won_block(sh, link, gentx, gh, f.won, refs,
                                         f.nth_parent(), f.new_tx(), f.known_fn());
    auto tmpl_got = reconstruct_won_block_from_template(sh, link, gentx, gh,
                                                        template_txs);

    EXPECT_EQ(tmpl_got.bytes, ref_got.bytes);
    EXPECT_EQ(tmpl_got.hex, ref_got.hex);

    PackStream ps(tmpl_got.bytes);
    BlockType blk;
    ps >> blk;
    ASSERT_EQ(blk.m_txs.size(), 3u);                       // gentx + 2 template txs
    EXPECT_EQ(blk.m_txs[0].vin[0].prevout.index, 0xffffffffu);
    EXPECT_EQ(blk.m_txs[1].vout[0].value, 11);             // template order preserved
    EXPECT_EQ(blk.m_txs[2].vout[0].value, 22);
}

// --- Test 6: empty captured template => valid coinbase-only block -------------
// Today's embedded path emits transactions[]==[]; reconstruct must yield a
// valid gentx-only block (correct-and-empty), never throw / fail closed.
TEST(DgbReconstructWonBlock, EmptyTemplateGentxOnly)
{
    auto sh = make_small_header();
    auto gentx = make_gentx();
    auto gh = fixed_gentx_hash();
    ::dgb::MerkleLink link;
    std::vector<MutableTransaction> template_txs;  // captured template was empty

    auto got = reconstruct_won_block_from_template(sh, link, gentx, gh, template_txs);

    PackStream ps(got.bytes);
    BlockType blk;
    ps >> blk;
    ASSERT_EQ(blk.m_txs.size(), 1u);
    EXPECT_EQ(blk.m_txs[0].vin[0].prevout.index, 0xffffffffu);
    EXPECT_EQ(blk.m_merkle_root, gh);  // empty link => root == gentx_hash
    auto sp = std::span<const std::byte>(
        reinterpret_cast<const std::byte*>(got.bytes.data()), got.bytes.size());
    EXPECT_EQ(got.hex, HexStr(sp));
}


// --- Test 7: won_share_inputs extracts the two share-carried inputs verbatim --
// The share-side half of the faithful reconstruct closure: a won share carries
// small_header (m_min_header) + merkle_link (m_merkle_link) verbatim. The seam
// is a pure read -- no field is transformed, reordered, or dropped.
TEST(DgbReconstructWonBlock, WonShareInputsExtractsHeaderAndMerkleLink)
{
    // Minimal duck-typed stand-in for dgb::Share (keeps this TU off share.hpp's
    // tracker/base_uint TU, per won_share_inputs.hpp's #143 note). Exposes the
    // two members won_share_inputs reads by name.
    struct FakeShare {
        SmallBlockHeaderType m_min_header;
        ::dgb::MerkleLink    m_merkle_link;
    };

    FakeShare s;
    s.m_min_header = make_small_header();
    s.m_merkle_link.m_branch = { H("b0"), H("b1") };
    s.m_merkle_link.m_index = 0;

    WonShareInputs got = won_share_inputs(s);

    EXPECT_EQ(got.small_header.m_version, s.m_min_header.m_version);
    EXPECT_EQ(got.small_header.m_previous_block, s.m_min_header.m_previous_block);
    EXPECT_EQ(got.small_header.m_timestamp, s.m_min_header.m_timestamp);
    EXPECT_EQ(got.small_header.m_bits, s.m_min_header.m_bits);
    EXPECT_EQ(got.small_header.m_nonce, s.m_min_header.m_nonce);
    ASSERT_EQ(got.merkle_link.m_branch.size(), 2u);
    EXPECT_EQ(got.merkle_link.m_branch[0], H("b0"));
    EXPECT_EQ(got.merkle_link.m_branch[1], H("b1"));
    EXPECT_EQ(got.merkle_link.m_index, 0u);
}

// --- Test 8: won_share_inputs feeds reconstruct_won_block_from_template -------
// End-to-end seam check: the extracted {small_header, merkle_link} drive a block
// byte-identical to passing those same fields directly. Proves the share-side
// seam is a faithful pass-through into the won-block framing path -- the run-loop
// closure may source small_header/merkle_link via won_share_inputs(share) with
// no change to the reconstructed block.
TEST(DgbReconstructWonBlock, WonShareInputsDrivesTemplateReconstructIdentically)
{
    struct FakeShare {
        SmallBlockHeaderType m_min_header;
        ::dgb::MerkleLink    m_merkle_link;
    };

    FakeShare s;
    s.m_min_header = make_small_header();
    // Non-empty link so the merkle-root math actually consumes it.
    s.m_merkle_link.m_branch = { H("b0") };
    s.m_merkle_link.m_index = 0;

    auto gentx = make_gentx();
    auto gh = fixed_gentx_hash();
    std::vector<MutableTransaction> template_txs = { make_tx(11), make_tx(22) };

    WonShareInputs in = won_share_inputs(s);

    auto via_seam = reconstruct_won_block_from_template(
        in.small_header, in.merkle_link, gentx, gh, template_txs);
    auto direct = reconstruct_won_block_from_template(
        s.m_min_header, s.m_merkle_link, gentx, gh, template_txs);

    EXPECT_EQ(via_seam.bytes, direct.bytes);
    EXPECT_EQ(via_seam.hex, direct.hex);

    PackStream ps(via_seam.bytes);
    BlockType blk;
    ps >> blk;
    ASSERT_EQ(blk.m_txs.size(), 3u);                    // gentx + 2 template txs
    EXPECT_EQ(blk.m_txs[0].vin[0].prevout.index, 0xffffffffu);
}
} // namespace