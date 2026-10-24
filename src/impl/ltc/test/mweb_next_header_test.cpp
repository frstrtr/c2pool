// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// ltc_mweb_next_header (rides share_test) -- the MWEB header of the next
// empty-body block, on real mainnet bytes.
//
// litecoind builds the next block's MWEB header in CoinsViewCache::
// BuildNextBlock: output_root, leafset_root, num_txos and kernel_offset are
// cumulative chain state and carry over an empty block; kernel_root,
// num_kernels and stealth_offset describe the block's own body and are zero
// for an empty one. c2pool used to copy the previous header whole, which
// matches litecoind only after a block with no kernels; after a block with
// kernels (17 of 60 recent mainnet blocks) the HogAddr committed to a header
// litecoind rejects (bad-blk-mweb).
//
//   - 3200603 (2 kernels) -> 3200604 (empty, mined by litecoind): the header,
//     its blake3 hash, the 171-byte mw::Block and the 97-byte HogEx built from
//     3200603's state are byte-equal to block 3200604's;
//   - 3200424 (empty) -> 3200425: both rules give the same header (why the
//     carry-over passed the earlier vector);
//   - 3200604 -> 3200605: equal to the "mweb" of litecoind's own template.
// ---------------------------------------------------------------------------

#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

#include <core/pack.hpp>
#include <core/uint256.hpp>
#include <btclibs/util/strencodings.h>

#include <impl/ltc/coin/block.hpp>
#include <impl/ltc/coin/mweb_builder.hpp>
#include <impl/ltc/coin/transaction.hpp>

#include "ltc_mweb_tx_fixtures.hpp"

namespace {

using namespace ltc::coin;
namespace fx = ltc_mweb_tx_fixture;

std::string hex_of(const std::vector<unsigned char>& b)
{
    return HexStr(std::span<const unsigned char>(b.data(), b.size()));
}

// Raw byte order (as in a HogAddr script), not uint256::GetHex().
std::string raw_hex(const uint256& h)
{
    return HexStr(std::span<const unsigned char>(h.data(), 32));
}

std::string serialized_hex(const MWEBHeader& hdr)
{
    PackStream ps;
    ps << hdr;
    return HexStr(ps.get_span());
}

MutableTransaction parse_tx(const char* hex)
{
    auto bytes = ParseHex(hex);
    PackStream ps(bytes);
    MutableTransaction tx;
    ps >> TX_WITH_WITNESS(tx);
    return tx;
}

// The MWEB state c2pool derives from a block: its HogEx (behind a placeholder
// coinbase) and its mw::Block.
MWEBState state_from(const char* hogex_hex, const char* mweb_raw_hex, uint32_t height)
{
    BlockType b;
    MutableTransaction cb;
    TxIn in;
    in.prevout.hash.SetNull();
    in.prevout.index = 0xffffffff;
    in.sequence = 0xffffffff;
    cb.vin.push_back(in);
    TxOut out;
    out.value = 0;
    cb.vout.push_back(out);
    b.m_txs = {cb, parse_tx(hogex_hex)};

    MWEBState st;
    EXPECT_TRUE(MWEBBuilder::extract_state(b, height, st));
    EXPECT_TRUE(MWEBBuilder::extract_mweb_header_from_raw(ParseHex(mweb_raw_hex), st));
    return st;
}

} // namespace

// 3200603 -> 3200604: from the state of a block with kernels, the header,
// its hash, the mw::Block and the HogEx are the ones litecoind mined.
TEST(LtcMwebNextHeader, AfterKernelsMatchesBlock3200604)
{
    const MWEBState st = state_from(fx::kBlock3200603HogexHex, fx::kBlock3200603MwebRawHex,
                                    fx::kBlock3200603Height);
    EXPECT_EQ(st.prev_hogex_txid.GetHex(), fx::kBlock3200603HogexTxid);
    EXPECT_EQ(st.hogaddr_value, fx::kBlock3200603HogaddrValue);
    EXPECT_EQ(st.prev_header.height, static_cast<int64_t>(fx::kBlock3200603Height));
    EXPECT_EQ(st.prev_header.kernel_mmr_size, 2u);
    EXPECT_FALSE(st.prev_header.kernel_root.IsNull());
    EXPECT_NE(st.prev_header.stealth_offset, (std::array<uint8_t, 32>{}));

    const std::string real_raw = fx::kBlock3200604MwebRawHex;
    const std::string real_header = real_raw.substr(0, 2 * 168);

    const MWEBHeader next = MWEBBuilder::next_empty_header(st.prev_header, fx::kBlock3200604Height);
    EXPECT_EQ(serialized_hex(next), real_header)
        << "kernel_root, num_kernels and stealth_offset are per block: zero for an empty body";
    EXPECT_EQ(raw_hex(blake3_hash_serialized(next)), fx::kBlock3200604MwebHash);
    EXPECT_EQ(raw_hex(MWEBBuilder::compute_mweb_hash(st, fx::kBlock3200604Height)),
              fx::kBlock3200604MwebHash);

    EXPECT_EQ(hex_of(MWEBBuilder::build_empty_mweb_block(st, fx::kBlock3200604Height)), real_raw);

    const MutableTransaction hogex = MWEBBuilder::build_hogex(st, fx::kBlock3200604Height);
    EXPECT_EQ(MWEBBuilder::serialize_hogex_hex(hogex), fx::kBlock3200604HogexHex);
    EXPECT_EQ(MWEBBuilder::compute_hogex_txid(hogex).GetHex(), fx::kBlock3200604HogexTxid);
}

// Copying the previous header whole gives the next header only after an
// empty body. After 3200603 (kernels) it is the rejected template's header
// (a10614ce..); after 3200424 (empty body: per-block fields already zero)
// both give the header c2pool's 3200425 template logged -- why the earlier
// vector never showed the difference.
TEST(LtcMwebNextHeader, CarryOverMatchesOnlyAfterAnEmptyBody)
{
    const MWEBState st = state_from(fx::kBlock3200603HogexHex, fx::kBlock3200603MwebRawHex,
                                    fx::kBlock3200603Height);
    MWEBHeader carried = st.prev_header;
    carried.height = fx::kBlock3200604Height;
    EXPECT_EQ(serialized_hex(carried), fx::kBlock3200604HeaderCarryOverHex);
    EXPECT_EQ(raw_hex(blake3_hash_serialized(carried)), fx::kBlock3200604CarryOverHash);
    EXPECT_NE(raw_hex(MWEBBuilder::compute_mweb_hash(st, fx::kBlock3200604Height)),
              fx::kBlock3200604CarryOverHash);

    const std::string raw424 = fx::kBlock3200424MwebRawHex;
    MWEBState st424;
    st424.prev_hogex_txid.SetHex(fx::kBlock3200424HogexTxid);
    st424.hogaddr_value = fx::kBlock3200424HogaddrValue;
    ASSERT_TRUE(MWEBBuilder::extract_mweb_header_from_raw(ParseHex(raw424), st424));
    ASSERT_EQ(st424.prev_header.kernel_mmr_size, 0u);
    const MWEBHeader next = MWEBBuilder::next_empty_header(st424.prev_header, fx::kBlock3200424Height + 1);
    EXPECT_EQ(serialized_hex(next), fx::kHeader3200425After3200424Hex);
    MWEBHeader carried424 = st424.prev_header;
    carried424.height = fx::kBlock3200424Height + 1;
    EXPECT_EQ(serialized_hex(carried424), fx::kHeader3200425After3200424Hex);

    const MutableTransaction hogex = MWEBBuilder::build_hogex(st424, fx::kBlock3200424Height + 1);
    ASSERT_EQ(hogex.vin.size(), 1u);
    EXPECT_EQ(hogex.vin[0].prevout.hash.GetHex(), fx::kBlock3200424HogexTxid);
    EXPECT_EQ(hogex.vout[0].value, fx::kBlock3200424HogaddrValue);
}

// Two consecutive templates over real chain data: on 3200603 (kernels) the
// mw::Block is block 3200604's; on 3200604 (empty) it is the "mweb" of
// litecoind's own 3200605 template.
TEST(LtcMwebNextHeader, ConsecutiveTemplatesMatchLitecoind)
{
    const MWEBState st603 = state_from(fx::kBlock3200603HogexHex, fx::kBlock3200603MwebRawHex,
                                       fx::kBlock3200603Height);
    EXPECT_EQ(hex_of(MWEBBuilder::build_empty_mweb_block(st603, fx::kBlock3200604Height)),
              fx::kBlock3200604MwebRawHex);

    const MWEBState st604 = state_from(fx::kBlock3200604HogexHex, fx::kBlock3200604MwebRawHex,
                                       fx::kBlock3200604Height);
    EXPECT_EQ(hex_of(MWEBBuilder::build_empty_mweb_block(st604, fx::kBlock3200604Height + 1)),
              fx::kGbt3200605MwebHex);
}
