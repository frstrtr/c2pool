// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// LTC v3 compact blocks -> MWEB state KAT (rides share_test).
//
// Real mainnet vector: block 3200424 with its mw::Block (see
// ltc_mweb_cmpct_fixtures.hpp). Pins:
//   - MWEBTracker::update over the real block: HogEx outpoint/value, MWEB
//     header, and the block hash the state belongs to;
//   - the v3 cmpctblock wire format (HogEx prefilled LAST, wire diff 24 for 26
//     txs, then 01 + mw::Block), its parse, and that a reconstruction from the
//     mempool -- or a getblocktxn completion -- carries the mw::Block and
//     yields the same state as the full block;
//   - the fallbacks: no HogEx prefill, presence 0, v2 stream -> full block;
//   - V2/V4/V5: a forged HogEx never survives reconstruction (Merkle root), a
//     flipped MWEB header byte fails the commitment, a replayed (older) MWEB
//     header fails the height check, a block not ending in a HogEx is refused;
//   - BIP 152 SipHash keys (single SHA256 over header || nonce), the 65535
//     count limit, and the sendcmpct announcement order (v3 first);
//   - the header screen (PoW, parent) the compact-block hook runs first.
// Folded into the allowlisted share_test target (no new executable: #769).
// ---------------------------------------------------------------------------

#include <gtest/gtest.h>

#include <cstdint>
#include <cstring>
#include <map>
#include <optional>
#include <string>
#include <vector>

#include <core/uint256.hpp>
#include <core/pack.hpp>
#include <core/hash.hpp>
#include <btclibs/crypto/sha256.h>
#include <btclibs/crypto/siphash.h>
#include <btclibs/util/strencodings.h>

#include <impl/ltc/coin/block.hpp>
#include <impl/ltc/coin/transaction.hpp>
#include <impl/ltc/coin/compact_blocks.hpp>
#include <impl/ltc/coin/p2p_messages.hpp>
#include <impl/ltc/coin/header_chain.hpp>
#include <impl/ltc/coin/mweb_builder.hpp>

#include "ltc_mweb_cmpct_fixtures.hpp"

namespace {

using namespace ltc::coin;
namespace fx = ltc_mweb_cmpct_fixture;

std::vector<unsigned char> bytes_of(PackStream& ps)
{
    auto sp = ps.get_span();
    return std::vector<unsigned char>(reinterpret_cast<const unsigned char*>(sp.data()),
                                      reinterpret_cast<const unsigned char*>(sp.data()) + sp.size());
}

BlockType vector_block()
{
    auto bytes = ParseHex(fx::kBlockWithMwebHex);
    PackStream ps(bytes);
    BlockType b;
    ps >> b;
    return b;
}

uint256 hash_of(const BlockHeaderType& h)
{
    auto packed = pack(h);
    return Hash(packed.get_span());
}

uint256 wtxid_of(const MutableTransaction& tx)
{
    auto packed = pack(TX_WITH_WITNESS(tx));
    return Hash(packed.get_span());
}

std::vector<unsigned char> serialize_tx(const MutableTransaction& tx)
{
    PackStream ps;
    ps << TX_WITH_WITNESS(tx);
    return bytes_of(ps);
}

// The mempool a node would have: every tx except the coinbase and the HogEx
// (both prefilled), keyed by wtxid like Mempool::all_txs_map_wtxid.
std::map<uint256, MutableTransaction> mempool_of(const BlockType& b, size_t skip_first = 0)
{
    std::map<uint256, MutableTransaction> known;
    for (size_t i = 1 + skip_first; i + 1 < b.m_txs.size(); ++i)
        known.emplace(wtxid_of(b.m_txs[i]), b.m_txs[i]);
    return known;
}

std::vector<unsigned char> serialize_cmpct(const CompactBlock& cb)
{
    PackStream ps;
    ps << cb;
    return bytes_of(ps);
}

CompactBlock parse_cmpct(const std::vector<unsigned char>& bytes)
{
    PackStream ps(bytes);
    CompactBlock cb;
    ps >> cb;
    return cb;
}

MWEBHeader parse_mweb_header(const std::vector<unsigned char>& raw)
{
    PackStream ps(raw);
    MWEBBlock mb;
    ps >> mb;
    return mb.header;
}

void expect_same_state(const MWEBState& a, const MWEBState& b)
{
    EXPECT_EQ(a.prev_hogex_txid, b.prev_hogex_txid);
    EXPECT_EQ(a.prev_hogex_vout, b.prev_hogex_vout);
    EXPECT_EQ(a.hogaddr_value, b.hogaddr_value);
    EXPECT_EQ(a.prev_header.height, b.prev_header.height);
    EXPECT_EQ(a.prev_header.output_root, b.prev_header.output_root);
    EXPECT_EQ(a.prev_header.kernel_root, b.prev_header.kernel_root);
    EXPECT_EQ(a.prev_header.leafset_root, b.prev_header.leafset_root);
    EXPECT_EQ(a.prev_header.kernel_offset, b.prev_header.kernel_offset);
    EXPECT_EQ(a.prev_header.stealth_offset, b.prev_header.stealth_offset);
    EXPECT_EQ(a.prev_header.output_mmr_size, b.prev_header.output_mmr_size);
    EXPECT_EQ(a.prev_header.kernel_mmr_size, b.prev_header.kernel_mmr_size);
    EXPECT_EQ(a.prev_mweb_raw, b.prev_mweb_raw);
    EXPECT_EQ(a.captured_at_height, b.captured_at_height);
    EXPECT_EQ(a.captured_block_hash, b.captured_block_hash);
    EXPECT_EQ(a.valid, b.valid);
}

// A HogEx that commits to `hdr` (HogAddr = blake3(hdr)), spending `prev`.
MutableTransaction forged_hogex(const MWEBHeader& hdr, const uint256& prev, int64_t value)
{
    MutableTransaction tx;
    tx.version = 2;
    tx.locktime = 0;
    tx.m_hogEx = true;
    TxIn in;
    in.prevout.hash = prev;
    in.prevout.index = 0;
    in.sequence = 0xffffffff;
    tx.vin.push_back(in);
    TxOut out;
    out.value = value;
    out.scriptPubKey.m_data.resize(34);
    out.scriptPubKey.m_data[0] = 0x58;
    out.scriptPubKey.m_data[1] = 0x20;
    const uint256 h = blake3_hash_serialized(hdr);
    std::memcpy(out.scriptPubKey.m_data.data() + 2, h.data(), 32);
    tx.vout.push_back(out);
    return tx;
}

std::vector<unsigned char> mweb_raw_for(const MWEBHeader& hdr)
{
    MWEBBlock mb;
    mb.header = hdr;
    PackStream ps;
    ps << mb;
    return bytes_of(ps);
}

} // namespace

// 1. The full block: real HogEx + mw::Block -> the MWEB state.
TEST(LtcCmpctV3MwebState, FullBlockYieldsState)
{
    const BlockType b = vector_block();
    ASSERT_EQ(b.m_txs.size(), fx::kTxCount);
    ASSERT_TRUE(b.m_txs.back().m_hogEx);
    ASSERT_EQ(b.m_mweb_raw.size(), fx::kMwebRawLen);
    EXPECT_EQ(hash_of(b).GetHex(), fx::kBlockHash);
    EXPECT_EQ(ComputeTxMerkleRoot(b.m_txs), b.m_merkle_root);
    EXPECT_EQ(HexStr(b.m_mweb_raw), fx::kMwebRawHex);
    EXPECT_EQ(HexStr(b.m_txs.back().vout[0].scriptPubKey.m_data), fx::kHogAddrScript);

    // The commitment litecoind checks holds for the real block.
    EXPECT_FALSE(MWEBBuilder::check_commitment(b.m_txs.back(), parse_mweb_header(b.m_mweb_raw),
                                               fx::kHeight));

    MWEBTracker tracker;
    ASSERT_TRUE(tracker.update(b, fx::kHeight, b.m_mweb_raw));
    auto st = tracker.get_state();
    ASSERT_TRUE(st);
    EXPECT_EQ(st->prev_hogex_txid.GetHex(), fx::kHogexTxid);
    EXPECT_EQ(st->prev_hogex_vout, 0u);
    EXPECT_EQ(st->hogaddr_value, fx::kHogaddrValue);
    EXPECT_EQ(st->prev_header.height, static_cast<int64_t>(fx::kHeight));
    EXPECT_EQ(st->prev_header.output_mmr_size, fx::kOutputMmrSize);
    EXPECT_EQ(st->prev_header.kernel_mmr_size, fx::kKernelMmrSize);
    EXPECT_EQ(st->captured_at_height, fx::kHeight);
    EXPECT_EQ(st->captured_block_hash.GetHex(), fx::kBlockHash);
    EXPECT_EQ(tracker.state_hash().GetHex(), fx::kBlockHash);
}

// 2. v3 cmpctblock: wire format, parse, reconstruction from the mempool.
TEST(LtcCmpctV3MwebState, V3CompactBlockReconstructsTheSameState)
{
    const BlockType b = vector_block();
    MWEBTracker full_tracker;
    ASSERT_TRUE(full_tracker.update(b, fx::kHeight, b.m_mweb_raw));
    const MWEBState state_a = *full_tracker.get_state();

    const CompactBlock built = BuildCompactBlockV3(b, 0x0123456789abcdefULL);
    ASSERT_EQ(built.prefilled_txns.size(), 2u);
    ASSERT_EQ(built.short_ids.size(), fx::kTxCount - 2);
    EXPECT_EQ(built.prefilled_txns[1].index, fx::kTxCount - 1);

    // Wire: ... | diff 24 | HogEx | 01 | mw::Block (171 B), the field LAST.
    const auto wire = serialize_cmpct(built);
    const auto hogex_bytes = serialize_tx(b.m_txs.back());
    const size_t tail = 1 + fx::kMwebRawLen;
    ASSERT_GT(wire.size(), tail + hogex_bytes.size() + 1);
    const size_t hogex_at = wire.size() - tail - hogex_bytes.size();
    EXPECT_EQ(wire[hogex_at - 1], 24) << "HogEx wire diff = vtx.size() - 2";
    EXPECT_TRUE(std::equal(hogex_bytes.begin(), hogex_bytes.end(), wire.begin() + hogex_at));
    EXPECT_EQ(wire[wire.size() - tail], 0x01) << "MWEB presence byte";
    EXPECT_TRUE(std::equal(b.m_mweb_raw.begin(), b.m_mweb_raw.end(), wire.end() - fx::kMwebRawLen));

    // The P2P message path parses the same.
    auto rmsg = p2p::message_cmpctblock::make_raw(built);
    auto parsed_msg = p2p::message_cmpctblock::make(rmsg->m_data);
    const CompactBlock cb = parsed_msg->m_compact_block;
    EXPECT_EQ(cb.cmpct_version, 3);
    EXPECT_EQ(cb.mweb_raw, b.m_mweb_raw);
    EXPECT_EQ(cb.nonce, 0x0123456789abcdefULL);
    ASSERT_EQ(cb.BlockTxCount(), fx::kTxCount);
    const MutableTransaction* hog = hogex_from_cmpct(cb);
    ASSERT_NE(hog, nullptr);
    EXPECT_EQ(cb.prefilled_txns.back().index, fx::kTxCount - 1);
    EXPECT_EQ(MWEBBuilder::compute_hogex_txid(*hog).GetHex(), fx::kHogexTxid);
    EXPECT_EQ(cmpct_mweb_verdict(cb, true).fallback, CmpctFallback::None);

    auto rec = ReconstructBlock(cb, mempool_of(b));
    ASSERT_TRUE(rec.complete);
    EXPECT_FALSE(rec.merkle_mismatch);
    EXPECT_EQ(hash_of(rec.block).GetHex(), fx::kBlockHash);
    EXPECT_EQ(ComputeTxMerkleRoot(rec.block.m_txs), rec.block.m_merkle_root);
    ASSERT_EQ(rec.block.m_mweb_raw.size(), fx::kMwebRawLen) << "reconstruction carries the mw::Block";

    MWEBTracker tracker;
    ASSERT_TRUE(tracker.update(rec.block, fx::kHeight, rec.block.m_mweb_raw));
    expect_same_state(*tracker.get_state(), state_a);
}

// 2b. The getblocktxn completion carries the mw::Block too.
TEST(LtcCmpctV3MwebState, BlocktxnCompletionCarriesMwebAndState)
{
    const BlockType b = vector_block();
    MWEBTracker full_tracker;
    ASSERT_TRUE(full_tracker.update(b, fx::kHeight, b.m_mweb_raw));
    const MWEBState state_a = *full_tracker.get_state();

    const CompactBlock cb = parse_cmpct(serialize_cmpct(BuildCompactBlockV3(b, 7)));
    // The mempool lacks the first three non-coinbase txs.
    auto partial = ReconstructBlock(cb, mempool_of(b, 3));
    ASSERT_FALSE(partial.complete);
    ASSERT_FALSE(partial.invalid);
    ASSERT_EQ(partial.missing_indexes, (std::vector<uint32_t>{1, 2, 3}));

    std::vector<MutableTransaction> answer{b.m_txs[1], b.m_txs[2], b.m_txs[3]};
    auto done = FillBlockFromBlocktxn(cb, partial, answer);
    ASSERT_TRUE(done.complete);
    EXPECT_EQ(hash_of(done.block).GetHex(), fx::kBlockHash);
    ASSERT_EQ(done.block.m_mweb_raw.size(), fx::kMwebRawLen) << "blocktxn completion carries the mw::Block";

    MWEBTracker tracker;
    ASSERT_TRUE(tracker.update(done.block, fx::kHeight, done.block.m_mweb_raw));
    expect_same_state(*tracker.get_state(), state_a);

    // A wrong blocktxn answer never completes the block.
    std::vector<MutableTransaction> wrong{b.m_txs[2], b.m_txs[1], b.m_txs[3]};
    auto bad = FillBlockFromBlocktxn(cb, partial, wrong);
    EXPECT_FALSE(bad.complete);
    EXPECT_TRUE(bad.merkle_mismatch);
    auto short_answer = FillBlockFromBlocktxn(cb, partial, {b.m_txs[1]});
    EXPECT_FALSE(short_answer.complete);
    EXPECT_TRUE(short_answer.invalid);
}

// 3. HogEx not prefilled (its wtxid in the short ids): no MWEB state from the
// reconstruction, the handler falls back to the full block.
TEST(LtcCmpctV3MwebState, MissingHogexPrefillFallsBackToFullBlock)
{
    const BlockType b = vector_block();
    CompactBlock cb = BuildCompactBlockV3(b, 11);
    cb.prefilled_txns.pop_back();
    cb.short_ids.push_back(cb.GetShortID(wtxid_of(b.m_txs.back())));
    cb = parse_cmpct(serialize_cmpct(cb));

    EXPECT_EQ(hogex_from_cmpct(cb), nullptr);
    const auto verdict = cmpct_mweb_verdict(cb, true);
    EXPECT_EQ(verdict.fallback, CmpctFallback::FullBlock);
    EXPECT_STREQ(verdict.reason, "no-hogex-prefill");

    auto known = mempool_of(b);
    known.emplace(wtxid_of(b.m_txs.back()), b.m_txs.back());
    auto rec = ReconstructBlock(cb, known);
    ASSERT_TRUE(rec.complete) << "the txs are all there";
    EXPECT_TRUE(rec.block.m_mweb_raw.empty()) << "a tail without the prefilled HogEx is not carried";

    MWEBTracker tracker;
    EXPECT_FALSE(tracker.update(rec.block, fx::kHeight, rec.block.m_mweb_raw));
    EXPECT_FALSE(tracker.has_state());
}

// 4. Presence byte 0 / v2 stream while the block has a HogEx: fallback.
TEST(LtcCmpctV3MwebState, MwebAbsentFallsBackToFullBlock)
{
    const BlockType b = vector_block();

    CompactBlock presence0 = BuildCompactBlockV3(b, 3);
    presence0.mweb_raw.clear();
    const auto wire0 = serialize_cmpct(presence0);
    EXPECT_EQ(wire0.back(), 0x00) << "presence 0 is the last byte";
    CompactBlock cb0 = parse_cmpct(wire0);
    EXPECT_EQ(cb0.cmpct_version, 3);
    EXPECT_TRUE(cb0.mweb_raw.empty());
    ASSERT_NE(hogex_from_cmpct(cb0), nullptr);
    auto v0 = cmpct_mweb_verdict(cb0, true);
    EXPECT_EQ(v0.fallback, CmpctFallback::FullBlock);
    EXPECT_STREQ(v0.reason, "mweb-absent");
    auto rec0 = ReconstructBlock(cb0, mempool_of(b));
    ASSERT_TRUE(rec0.complete);
    MWEBTracker tracker;
    EXPECT_FALSE(tracker.update(rec0.block, fx::kHeight, rec0.block.m_mweb_raw));

    // A v1/v2 sender: no field at all.
    CompactBlock v2 = BuildCompactBlockV3(b, 3);
    v2.cmpct_version = 2;
    CompactBlock cb2 = parse_cmpct(serialize_cmpct(v2));
    EXPECT_EQ(cb2.cmpct_version, 2);
    EXPECT_TRUE(cb2.mweb_raw.empty());
    EXPECT_EQ(cmpct_mweb_verdict(cb2, true).fallback, CmpctFallback::FullBlock);

    // MWEB active, no HogEx prefilled at all (a v2 encoding): "not-v3".
    CompactBlock plain = BuildCompactBlock(static_cast<const BlockHeaderType&>(b), b.m_txs, 3);
    auto vp = cmpct_mweb_verdict(plain, true);
    EXPECT_EQ(vp.fallback, CmpctFallback::FullBlock);
    EXPECT_STREQ(vp.reason, "not-v3");
    // Before MWEB a plain compact block is fine.
    EXPECT_EQ(cmpct_mweb_verdict(plain, false).fallback, CmpctFallback::None);
}

// 5. Bogus commitments never become MWEB state.
TEST(LtcCmpctV3MwebState, BogusCommitmentNeverBecomesState)
{
    const BlockType b = vector_block();
    MWEBTracker tracker;
    ASSERT_TRUE(tracker.update(b, fx::kHeight, b.m_mweb_raw));
    const MWEBState before = *tracker.get_state();

    // (a) One flipped byte in the MWEB header (output root) of a v3 compact
    // block: the txs still match the header, the commitment does not.
    CompactBlock cb = BuildCompactBlockV3(b, 5);
    cb.mweb_raw[10] ^= 0x01;
    cb = parse_cmpct(serialize_cmpct(cb));
    auto rec = ReconstructBlock(cb, mempool_of(b));
    ASSERT_TRUE(rec.complete);
    ASSERT_EQ(rec.block.m_mweb_raw.size(), fx::kMwebRawLen);
    auto why = MWEBBuilder::check_commitment(rec.block.m_txs.back(),
                                             parse_mweb_header(rec.block.m_mweb_raw), fx::kHeight);
    ASSERT_TRUE(why);
    EXPECT_EQ(*why, "mweb-hash-mismatch");
    EXPECT_FALSE(tracker.update(rec.block, fx::kHeight, rec.block.m_mweb_raw));
    expect_same_state(*tracker.get_state(), before);

    // (b) A forged, self-consistent HogEx + mw::Block in a compact block of
    // the real header (HogAddr = blake3(forged header), height right). The
    // HogEx is not in the block: the Merkle root rejects the reconstruction,
    // so nothing reaches the tracker.
    MWEBHeader forged_hdr = parse_mweb_header(b.m_mweb_raw);
    forged_hdr.output_mmr_size += 1;
    uint256 fake_prev;
    fake_prev.SetHex("1111111111111111111111111111111111111111111111111111111111111111");
    const MutableTransaction fake = forged_hogex(forged_hdr, fake_prev, 1);
    ASSERT_FALSE(MWEBBuilder::check_commitment(fake, forged_hdr, fx::kHeight))
        << "the forgery is self-consistent";
    CompactBlock forged_cb = BuildCompactBlockV3(b, 5);
    forged_cb.prefilled_txns.back().tx = fake;
    forged_cb.mweb_raw = mweb_raw_for(forged_hdr);
    forged_cb = parse_cmpct(serialize_cmpct(forged_cb));
    ASSERT_NE(hogex_from_cmpct(forged_cb), nullptr);
    EXPECT_EQ(cmpct_mweb_verdict(forged_cb, true).fallback, CmpctFallback::None)
        << "the shape alone looks fine";
    auto forged_rec = ReconstructBlock(forged_cb, mempool_of(b));
    EXPECT_FALSE(forged_rec.complete);
    EXPECT_TRUE(forged_rec.merkle_mismatch);
    if (forged_rec.complete)
        tracker.update(forged_rec.block, fx::kHeight, forged_rec.block.m_mweb_raw);
    expect_same_state(*tracker.get_state(), before);

    // (c) A replayed MWEB header: an older height, HogAddr consistent with it.
    MWEBHeader old_hdr = parse_mweb_header(b.m_mweb_raw);
    old_hdr.height = fx::kHeight - 1;
    BlockType replay = b;
    replay.m_txs.back() = forged_hogex(old_hdr, fake_prev, 1);
    replay.m_mweb_raw = mweb_raw_for(old_hdr);
    why = MWEBBuilder::check_commitment(replay.m_txs.back(), old_hdr, fx::kHeight);
    ASSERT_TRUE(why);
    EXPECT_EQ(*why, "mweb-height-mismatch");
    EXPECT_FALSE(tracker.update(replay, fx::kHeight, replay.m_mweb_raw));
    expect_same_state(*tracker.get_state(), before);

    // (d) The last tx is not a HogEx.
    BlockType no_hogex = b;
    no_hogex.m_txs.back().m_hogEx = false;
    why = MWEBBuilder::check_commitment(no_hogex.m_txs.back(), parse_mweb_header(b.m_mweb_raw),
                                        fx::kHeight);
    ASSERT_TRUE(why);
    EXPECT_EQ(*why, "last-tx-not-hogex");
    EXPECT_FALSE(tracker.update(no_hogex, fx::kHeight, b.m_mweb_raw));
    expect_same_state(*tracker.get_state(), before);

    // (e) Two HogEx in one block.
    BlockType two = b;
    two.m_txs[1].m_hogEx = true;
    EXPECT_FALSE(tracker.update(two, fx::kHeight, b.m_mweb_raw));
    expect_same_state(*tracker.get_state(), before);
}

// 6. A v2 stream (no tail) still parses as before.
TEST(LtcCmpctV3MwebState, V2StreamUnchanged)
{
    const BlockType b = vector_block();
    CompactBlock v2 = BuildCompactBlock(static_cast<const BlockHeaderType&>(b), b.m_txs, 99);
    const auto wire = serialize_cmpct(v2);
    CompactBlock cb = parse_cmpct(wire);
    EXPECT_EQ(cb.cmpct_version, 2);
    EXPECT_TRUE(cb.mweb_raw.empty());
    EXPECT_EQ(cb.short_ids.size(), fx::kTxCount - 1);
    ASSERT_EQ(cb.prefilled_txns.size(), 1u);
    EXPECT_EQ(serialize_cmpct(cb), wire) << "v2 round trip is byte-identical";
}

// BIP 152: k0/k1 from a single SHA256 over the 80-byte header and the
// little-endian nonce, computed here from the raw block bytes.
TEST(LtcCmpctV3MwebState, ShortIdKeysAreBip152)
{
    const BlockType b = vector_block();
    const uint64_t nonce = 0x8877665544332211ULL;
    const auto raw = ParseHex(fx::kBlockWithMwebHex);
    std::vector<unsigned char> pre(raw.begin(), raw.begin() + 80);
    for (int i = 0; i < 8; ++i)
        pre.push_back(static_cast<unsigned char>(nonce >> (8 * i)));
    unsigned char digest[CSHA256::OUTPUT_SIZE];
    CSHA256().Write(pre.data(), pre.size()).Finalize(digest);
    uint64_t want_k0 = 0, want_k1 = 0;
    for (int i = 0; i < 8; ++i) {
        want_k0 |= static_cast<uint64_t>(digest[i]) << (8 * i);
        want_k1 |= static_cast<uint64_t>(digest[8 + i]) << (8 * i);
    }

    CompactBlock cb;
    cb.header = static_cast<const BlockHeaderType&>(b);
    cb.nonce = nonce;
    uint64_t k0 = 0, k1 = 0;
    cb.GetSipHashKeys(k0, k1);
    EXPECT_EQ(k0, want_k0);
    EXPECT_EQ(k1, want_k1);
    const uint256 w = wtxid_of(b.m_txs[1]);
    EXPECT_EQ(cb.GetShortID(w).to_uint64(), SipHashUint256(want_k0, want_k1, w) & 0xffffffffffffULL);
}

// litecoind: at most 65535 txs per compact block; bound before allocating.
TEST(LtcCmpctV3MwebState, TxCountLimit)
{
    const BlockType b = vector_block();
    PackStream ps;
    ps << static_cast<const BlockHeaderType&>(b);
    ps << uint64_t{0};
    WriteCompactSize(ps, 65536);
    auto too_many = bytes_of(ps);
    EXPECT_THROW(parse_cmpct(too_many), std::ios_base::failure);

    // A prefilled index past 16 bits.
    PackStream ps2;
    ps2 << static_cast<const BlockHeaderType&>(b);
    ps2 << uint64_t{0};
    WriteCompactSize(ps2, 0);
    WriteCompactSize(ps2, 1);
    WriteCompactSize(ps2, 70000);
    ps2 << TX_WITH_WITNESS(b.m_txs[0]);
    EXPECT_THROW(parse_cmpct(bytes_of(ps2)), std::ios_base::failure);

    // Presence byte other than 0/1.
    auto wire = serialize_cmpct(BuildCompactBlockV3(b, 1));
    wire[wire.size() - 1 - fx::kMwebRawLen] = 0x02;
    EXPECT_THROW(parse_cmpct(wire), std::ios_base::failure);
}

// sendcmpct after verack: v3 FIRST (litecoind locks the version on the first
// one it accepts), then v2 low-bandwidth. Byte sequence of the payloads.
TEST(LtcCmpctV3MwebState, SendcmpctAnnounceOrder)
{
    auto payloads = [](uint64_t version, bool hb) {
        std::vector<std::string> out;
        for (const auto& a : cmpct_announcements(version, hb)) {
            auto rmsg = p2p::message_sendcmpct::make_raw(a.high_bandwidth, a.version);
            EXPECT_EQ(rmsg->m_command, "sendcmpct");
            out.push_back(HexStr(rmsg->m_data.get_span()));
        }
        return out;
    };
    EXPECT_EQ(payloads(3, true),
              (std::vector<std::string>{"010300000000000000", "000200000000000000"}));
    EXPECT_EQ(payloads(3, false),
              (std::vector<std::string>{"000300000000000000", "000200000000000000"}));
    EXPECT_EQ(payloads(2, true), (std::vector<std::string>{"000200000000000000"}))
        << "rollback: v2 low-bandwidth only";
}

// The compact-block hook screens the header before any reconstruction work:
// a header that names a known parent but fails PoW (a random nonce) or names
// an unknown parent is dropped; nothing is stored either way.
TEST(LtcCmpctV3MwebState, HeaderScreenBeforeReconstruction)
{
    const BlockType b = vector_block();
    auto params = make_ltc_chain_params_mainnet();
    LTCChainParams::Checkpoint cp;
    cp.height = fx::kHeight - 1;
    cp.hash.SetHex(fx::kPrevBlockHash);
    params.fast_start_checkpoint = cp;
    HeaderChain chain(params);
    ASSERT_TRUE(chain.init());

    const BlockHeaderType hdr = static_cast<const BlockHeaderType&>(b);
    EXPECT_TRUE(chain.check_header(hdr)) << "the real header: parent known, PoW ok";
    EXPECT_EQ(chain.height(), fx::kHeight - 1) << "nothing stored";
    EXPECT_FALSE(chain.has_header(hash_of(hdr)));

    BlockHeaderType bad_nonce = hdr;
    bad_nonce.m_nonce ^= 0x01;
    EXPECT_FALSE(chain.check_header(bad_nonce)) << "PoW fails";

    BlockHeaderType orphan = hdr;
    orphan.m_previous_block.SetHex("1111111111111111111111111111111111111111111111111111111111111111");
    EXPECT_FALSE(chain.check_header(orphan)) << "unknown parent";
}
