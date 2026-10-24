// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// ltc_mweb_tx_wire (rides share_test) -- txs with an MWEB part, parsed byte
// for byte, on real mainnet bytes (ltc_mweb_tx_fixtures.hpp).
//
// litecoind relays a tx to a NODE_MWEB peer with its mw::Transaction after
// the outputs (flag 0x08, presence byte 1). c2pool consumed nothing after the
// presence byte, read the locktime from the mw::Transaction's first bytes and
// left the rest of the message unread: an MWEB-only tx became a 10-byte stub
// with no inputs, a peg-in kept a garbage locktime, and both entered the
// mempool and every template (bad-txns-vin-empty).
//
//   - the peg-in (V2) and the peg-out (V3) parse to the end of the message;
//     txid, wtxid, locktime and the re-encoding are litecoind's; the walked
//     mw::Transaction gives kernel ids, fees, peg-in / peg-out amounts and
//     the MWEB weight litecoind reports;
//   - a tx message with bytes left over is dropped; a truncated one throws at
//     every length; presence bytes other than 1 mean "no mw::Transaction"
//     (litecoind's OptionalPtr); no kernel, a VARINT overflow or a
//     non-canonical CompactSize throw;
//   - mw::Block bodies (3200572, 3200601, 3200603) walk exactly, with
//     CompactSize vector lengths (300 inputs: fd2c01), and a header whose
//     kernel count disagrees with its body is not trusted;
//   - block path: block 3200572 parses with its peg-in stripped and yields
//     MWEB state; the same block with the MWEB-carrying peg-in spliced into
//     its transactions parses byte-exactly and is refused
//     (unexpected-mweb-data);
//   - a HogEx's wtxid is its txid (no witness), also as a short id.
// ---------------------------------------------------------------------------

#include <gtest/gtest.h>

#include <cstdint>
#include <cstring>
#include <ios>
#include <memory>
#include <span>
#include <string>
#include <vector>

#include <core/pack.hpp>
#include <core/uint256.hpp>
#include <core/hash.hpp>
#include <core/message.hpp>
#include <btclibs/util/strencodings.h>

#include <impl/ltc/coin/p2p_messages.hpp>
#include <impl/ltc/coin/compact_blocks.hpp>
#include <impl/ltc/coin/mempool.hpp>
#include <impl/ltc/coin/mweb_tx_wire.hpp>
#include <impl/ltc/coin/mweb_builder.hpp>

#include "ltc_mweb_tx_fixtures.hpp"

namespace {

using namespace ltc::coin;
namespace fx = ltc_mweb_tx_fixture;
namespace mw = ltc::coin::mweb_wire;

using Bytes = std::vector<unsigned char>;

std::string hex_of(std::span<const unsigned char> b) { return HexStr(b); }
std::string hex_of(const Bytes& b) { return HexStr(std::span<const unsigned char>(b.data(), b.size())); }
std::string raw_hex(const uint256& h) { return HexStr(std::span<const unsigned char>(h.data(), 32)); }

Bytes to_bytes(PackStream& ps)
{
    auto sp = ps.get_span();
    return Bytes(reinterpret_cast<const unsigned char*>(sp.data()),
                 reinterpret_cast<const unsigned char*>(sp.data()) + sp.size());
}

// A tx message payload through the message's own parser; `left` = bytes the
// parse did not consume.
MutableTransaction parse_tx_message(const Bytes& payload, size_t& left)
{
    PackStream ps(payload);
    auto msg = p2p::message_tx::make(ps);
    left = ps.cursor_size();
    return msg->m_tx;
}

Bytes encode(const MutableTransaction& tx, const TxParams& params)
{
    PackStream ps;
    ps << params(tx);
    return to_bytes(ps);
}

mw::MwebTxSummary summary_of(const MutableTransaction& tx)
{
    auto s = mw::summarize_mw_transaction(tx.mweb_tx_raw);
    if (!s) {
        ADD_FAILURE() << "the tx carries no mw::Transaction that walks";
        return {};
    }
    return *s;
}

Bytes cat(std::initializer_list<Bytes> parts)
{
    Bytes out;
    for (const auto& p : parts) out.insert(out.end(), p.begin(), p.end());
    return out;
}
Bytes rep(unsigned char b, size_t n) { return Bytes(n, b); }

// An MWEB-only tx message around a synthetic mw::Transaction body.
Bytes mweb_only_tx(const Bytes& body)
{
    return cat({ParseHex("02000000" "00" "08" "00" "00" "01"), rep(0x11, 32), rep(0x22, 32), body,
                ParseHex("00000000")});
}

// A kernel with only a fee (features 0x01): VARINT fee | excess | signature.
Bytes fee_kernel(const Bytes& varint_fee)
{
    return cat({{0x01}, varint_fee, rep(0x08, 33), rep(0x55, 64)});
}

// An input with no optional field: features | output_id | commitment |
// output_pubkey | signature.
Bytes plain_input(unsigned char tag)
{
    return cat({{0x00}, rep(tag, 32), rep(0x09, 33), rep(0x02, 33), rep(0x66, 64)});
}

BlockType parse_block(const Bytes& b)
{
    PackStream ps(b);
    BlockType blk;
    ps >> blk;
    return blk;
}

uint256 block_hash(const BlockType& b)
{
    auto packed = pack(static_cast<const BlockHeaderType&>(b));
    return Hash(packed.get_span());
}

} // namespace

// ─── the two relayed txs ────────────────────────────────────────────────────

TEST(LtcMwebTxWire, PeginParsesToTheEndOfTheMessage)
{
    const Bytes wire = ParseHex(fx::kPeginTxHex);
    size_t left = 99;
    const MutableTransaction tx = parse_tx_message(wire, left);
    EXPECT_EQ(left, 0u) << "the whole tx message is consumed";

    EXPECT_TRUE(tx.HasMWEBTx());
    EXPECT_FALSE(tx.IsMWEBOnly());
    EXPECT_FALSE(tx.m_hogEx);
    EXPECT_EQ(tx.mweb_tx_raw.size(), fx::kPeginMwTxLen);
    ASSERT_EQ(tx.vin.size(), 1u);
    ASSERT_EQ(tx.vout.size(), 1u);
    EXPECT_EQ(tx.vout[0].value, fx::kPeginAmount);
    EXPECT_EQ(tx.locktime, fx::kPeginLocktime);
    EXPECT_NE(tx.locktime, fx::kPeginMisparsedLocktime);

    EXPECT_EQ(compute_txid(tx).GetHex(), fx::kPeginTxid);
    EXPECT_NE(compute_txid(tx).GetHex(), fx::kPeginMisparsedTxid);
    EXPECT_EQ(compute_wtxid(tx).GetHex(), fx::kPeginWtxid)
        << "wtxid: witness serialization without the MWEB part";

    EXPECT_EQ(hex_of(encode(tx, TX_WITH_WITNESS)), fx::kPeginTxHex)
        << "re-encoded with witness + MWEB it is the relayed tx";
    const Bytes wtxid_ser = encode(tx, TX_WTXID);
    ASSERT_GT(wtxid_ser.size(), 6u);
    EXPECT_EQ(wtxid_ser[4], 0x00);
    EXPECT_EQ(wtxid_ser[5], 0x01) << "witness flag only, no MWEB flag";
    EXPECT_LT(wtxid_ser.size(), wire.size() - fx::kPeginMwTxLen);
}

TEST(LtcMwebTxWire, PegoutParsesToTheEndOfTheMessage)
{
    const Bytes wire = ParseHex(fx::kPegoutTxHex);
    size_t left = 99;
    const MutableTransaction tx = parse_tx_message(wire, left);
    EXPECT_EQ(left, 0u) << "the whole tx message is consumed";

    EXPECT_TRUE(tx.HasMWEBTx());
    EXPECT_TRUE(tx.IsMWEBOnly());
    EXPECT_TRUE(tx.vin.empty());
    EXPECT_TRUE(tx.vout.empty());
    EXPECT_EQ(tx.mweb_tx_raw.size(), fx::kPegoutMwTxLen);
    EXPECT_EQ(tx.locktime, fx::kPegoutLocktime);
    EXPECT_NE(tx.locktime, fx::kPegoutMisparsedLocktime);

    // An MWEB-only tx is identified by its first kernel id.
    EXPECT_EQ(compute_txid(tx).GetHex(), fx::kPegoutTxid);
    EXPECT_EQ(raw_hex(compute_txid(tx)), fx::kPegoutKernelId);
    EXPECT_NE(compute_txid(tx).GetHex(), fx::kPegoutMisparsedTxid);
    EXPECT_EQ(compute_wtxid(tx), compute_txid(tx)) << "no witness: wtxid == txid";

    EXPECT_EQ(hex_of(encode(tx, TX_WITH_WITNESS)), fx::kPegoutTxHex);
    const Bytes no_mweb = encode(tx, TX_WTXID);
    EXPECT_EQ(no_mweb.size(), 10u) << "version | no vin | no vout | locktime";
    EXPECT_EQ(hex_of(no_mweb), hex_of(encode(tx, TX_NO_WITNESS)));
    EXPECT_NE(hex_of(no_mweb), fx::kPegoutStubHex) << "the locktime is the real one";
}

TEST(LtcMwebTxWire, MwebPartSummaries)
{
    size_t left = 0;
    const MutableTransaction pegin = parse_tx_message(ParseHex(fx::kPeginTxHex), left);
    const mw::MwebTxSummary a = summary_of(pegin);
    EXPECT_EQ(a.raw, pegin.mweb_tx_raw);
    EXPECT_EQ(a.n_inputs, 0u);
    EXPECT_EQ(a.n_outputs, 2u);
    ASSERT_EQ(a.kernels.size(), 1u);
    EXPECT_EQ(a.kernels[0].features, 0x13);
    EXPECT_EQ(a.kernels[0].fee, fx::kPeginKernelFee);
    ASSERT_TRUE(a.kernels[0].pegin.has_value());
    EXPECT_EQ(*a.kernels[0].pegin, fx::kPeginAmount);
    EXPECT_TRUE(a.kernels[0].pegouts.empty());
    EXPECT_EQ(raw_hex(a.kernels[0].kernel_id), fx::kPeginKernelId);
    EXPECT_TRUE(a.has_pegin());
    EXPECT_FALSE(a.has_pegout());
    EXPECT_EQ(a.total_fee(), fx::kPeginKernelFee);
    EXPECT_EQ(a.mweb_weight(), fx::kPeginMwebWeight);
    // The canonical pegin output pays to the kernel id (OP_9 PUSH32 <id>).
    auto pegin_kernel = mw::pegin_kernel_of(pegin.vout[0].scriptPubKey);
    ASSERT_TRUE(pegin_kernel.has_value());
    EXPECT_EQ(*pegin_kernel, a.kernels[0].kernel_id);

    const MutableTransaction pegout = parse_tx_message(ParseHex(fx::kPegoutTxHex), left);
    const mw::MwebTxSummary b = summary_of(pegout);
    EXPECT_EQ(b.n_inputs, 4u);
    EXPECT_EQ(b.n_outputs, 1u);
    ASSERT_EQ(b.kernels.size(), 1u);
    EXPECT_EQ(b.kernels[0].features, 0x15);
    EXPECT_EQ(b.kernels[0].fee, fx::kPegoutKernelFee);
    EXPECT_FALSE(b.kernels[0].pegin.has_value());
    ASSERT_EQ(b.kernels[0].pegouts.size(), 1u);
    EXPECT_EQ(b.kernels[0].pegouts[0].amount, fx::kPegoutAmount);
    EXPECT_EQ(hex_of(b.kernels[0].pegouts[0].script), fx::kPegoutScript);
    EXPECT_EQ(raw_hex(b.kernels[0].kernel_id), fx::kPegoutKernelId);
    EXPECT_FALSE(b.has_pegin());
    EXPECT_TRUE(b.has_pegout());
    EXPECT_EQ(b.mweb_weight(), fx::kPegoutMwebWeight);
    // The kernel's bytes are where the summary says.
    EXPECT_EQ(raw_hex(mw::kernel_id(std::span<const unsigned char>(
                  b.raw.data() + b.kernels[0].off, b.kernels[0].len))),
              fx::kPegoutKernelId);
}

// ─── message framing and malformed parts ────────────────────────────────────

TEST(LtcMwebTxWire, TxMessageWithTrailingBytesIsDropped)
{
    p2p::Handler handler;
    const Bytes wire = ParseHex(fx::kPeginTxHex);

    auto exact = std::make_unique<RawMessage>("tx", PackStream(wire));
    EXPECT_NO_THROW(handler.parse(exact));

    Bytes longer = wire;
    longer.push_back(0x00);
    auto with_tail = std::make_unique<RawMessage>("tx", PackStream(longer));
    EXPECT_THROW(handler.parse(with_tail), std::ios_base::failure);

    // Strict framing is opt-in: a version message carrying the relay flag
    // c2pool does not read still parses.
    p2p::message_version v;
    v.m_version = 70016;
    v.m_services = 0;
    v.m_timestamp = 0;
    v.m_nonce = 1;
    v.m_subversion = "/x/";
    v.m_start_height = 0;
    PackStream vps = pack(v);
    Bytes vbytes = to_bytes(vps);
    vbytes.push_back(0x01);
    auto version = std::make_unique<RawMessage>("version", PackStream(vbytes));
    EXPECT_NO_THROW(handler.parse(version));
}

TEST(LtcMwebTxWire, TruncatedTxThrowsAtEveryLength)
{
    for (const char* hex : {fx::kPeginTxHex, fx::kPegoutTxHex}) {
        const Bytes wire = ParseHex(hex);
        size_t parsed = 0;
        for (size_t len = 0; len < wire.size(); ++len) {
            const Bytes cut(wire.begin(), wire.begin() + len);
            size_t left = 0;
            try {
                parse_tx_message(cut, left);
                ++parsed;
            } catch (const std::ios_base::failure&) {
            }
        }
        EXPECT_EQ(parsed, 0u) << "a prefix of the tx parsed as a tx (" << wire.size() << " B)";
    }
}

// litecoind's OptionalPtr reads the mw::Transaction only for presence byte 1;
// any other value is "none", i.e. a HogEx (which needs an output).
TEST(LtcMwebTxWire, PresenceByteOtherThanOneIsNoMwebPart)
{
    const std::string hogex_body =
        std::string("01") + std::string(64, 'a') + "00000000" "00" "ffffffff"
        "01" "0010a5d4e8000000" "22" "5820" + std::string(64, 'b');
    const Bytes presence2 = ParseHex("02000000" "00" "08" + hogex_body + "02" "00000000");
    size_t left = 99;
    MutableTransaction tx;
    ASSERT_NO_THROW(tx = parse_tx_message(presence2, left));
    EXPECT_EQ(left, 0u);
    EXPECT_TRUE(tx.m_hogEx);
    EXPECT_FALSE(tx.HasMWEBTx());
    EXPECT_EQ(tx.locktime, 0u);
    EXPECT_EQ(hex_of(encode(tx, TX_WITH_WITNESS)),
              "02000000" "00" "08" + hogex_body + "00" "00000000")
        << "re-encoded as litecoind does: presence 0";

    // No output: not a HogEx either.
    const Bytes no_output = ParseHex("02000000" "00" "08" "01" + std::string(64, 'a') +
                                     "00000000" "00" "ffffffff" "00" "02" "00000000");
    EXPECT_THROW(parse_tx_message(no_output, left), std::ios_base::failure);
}

TEST(LtcMwebTxWire, MalformedMwebPartThrows)
{
    size_t left = 0;
    // No kernel.
    EXPECT_THROW(parse_tx_message(mweb_only_tx(ParseHex("00" "00" "00")), left),
                 std::ios_base::failure);
    // Fee VARINT past int64.
    EXPECT_THROW(parse_tx_message(mweb_only_tx(cat({ParseHex("00" "00" "01"),
                                                     fee_kernel(ParseHex("80fefefefefefefefe7f"))})),
                                  left),
                 std::ios_base::failure);
    // Non-canonical CompactSize (1 encoded in 3 bytes).
    EXPECT_THROW(parse_tx_message(mweb_only_tx(cat({ParseHex("fd0100"), plain_input(0x01),
                                                     ParseHex("00" "01"),
                                                     fee_kernel(ParseHex("00"))})),
                                  left),
                 std::ios_base::failure);
    // Empty pegout script.
    const Bytes pegout_kernel = cat({{0x05}, ParseHex("00"), ParseHex("01" "00" "00"),
                                     rep(0x08, 33), rep(0x55, 64)});
    EXPECT_THROW(parse_tx_message(mweb_only_tx(cat({ParseHex("00" "00" "01"), pegout_kernel})), left),
                 std::ios_base::failure);
}

// Kernel fees across the VARINT boundaries (serialize.h bit patterns) and a
// 300-input body (CompactSize fd2c01), through the tx message parser.
TEST(LtcMwebTxWire, VarintAndCompactSizeBoundaries)
{
    const std::pair<const char*, int64_t> fees[] = {
        {"00", 0},
        {"7f", 0x7f},
        {"8000", 0x80},
        {"a334", 0x1234},
        {"82fe7f", 0xffff},
        {"c7e756", 0x123456},
        {"86ffc7e756", 0x80123456LL},
        {"8efefefe7f", 0xffffffffLL},
        {"fefefefefefefefe7f", 0x7fffffffffffffffLL},
    };
    for (const auto& [enc, value] : fees) {
        size_t left = 99;
        const MutableTransaction tx = parse_tx_message(
            mweb_only_tx(cat({ParseHex("00" "00" "01"), fee_kernel(ParseHex(enc))})), left);
        EXPECT_EQ(left, 0u) << enc;
        const mw::MwebTxSummary s = summary_of(tx);
        ASSERT_EQ(s.kernels.size(), 1u) << enc;
        EXPECT_EQ(s.kernels[0].fee, value) << enc;
    }

    Bytes inputs = ParseHex("fd2c01");
    for (int i = 0; i < 300; ++i) {
        const Bytes in = plain_input(static_cast<unsigned char>(i));
        inputs.insert(inputs.end(), in.begin(), in.end());
    }
    size_t left = 99;
    const MutableTransaction tx = parse_tx_message(
        mweb_only_tx(cat({inputs, ParseHex("00" "01"), fee_kernel(ParseHex("00"))})), left);
    EXPECT_EQ(left, 0u);
    const mw::MwebTxSummary s = summary_of(tx);
    EXPECT_EQ(s.n_inputs, 300u);
    EXPECT_EQ(s.n_outputs, 0u);
    EXPECT_EQ(s.kernels.size(), 1u);
}

// ─── mw::Block bodies ───────────────────────────────────────────────────────

TEST(LtcMwebTxWire, RealBlockBodiesWalkExactly)
{
    const BlockType b572 = parse_block(ParseHex(fx::kBlock3200572Hex));
    struct Case {
        const char* name;
        Bytes raw;
        int64_t height;
        size_t n_in, n_out, n_kernels;
        const char* hash;
    } cases[] = {
        {"3200572", b572.m_mweb_raw, 3200572, 0, 1, 1, fx::kBlock3200572MwebHash},
        {"3200601", ParseHex(fx::kBlock3200601MwebRawHex), 3200601, 1, 2, 2, fx::kBlock3200601MwebHash},
        {"3200603", ParseHex(fx::kBlock3200603MwebRawHex), 3200603, 6, 2, 2, nullptr},
    };
    for (const auto& c : cases) {
        PackStream ps(c.raw);
        MWEBBlock blk;
        ASSERT_NO_THROW(ps >> blk) << c.name;
        EXPECT_EQ(ps.cursor_size(), 0u) << c.name << ": the mw::Block is consumed exactly";
        EXPECT_EQ(blk.header.height, c.height) << c.name;
        EXPECT_EQ(blk.body.summary.n_inputs, c.n_in) << c.name;
        EXPECT_EQ(blk.body.summary.n_outputs, c.n_out) << c.name;
        EXPECT_EQ(blk.body.summary.kernels.size(), c.n_kernels) << c.name;
        EXPECT_EQ(blk.header.kernel_mmr_size, c.n_kernels) << c.name;
        if (c.hash)
            EXPECT_EQ(raw_hex(blake3_hash_serialized(blk.header)), c.hash) << c.name;

        MWEBState st;
        EXPECT_TRUE(MWEBBuilder::extract_mweb_header_from_raw(c.raw, st)) << c.name;
    }

    // 3200572: one peg-in kernel.
    {
        PackStream ps(b572.m_mweb_raw);
        MWEBBlock blk;
        ps >> blk;
        const auto& k = blk.body.summary.kernels;
        ASSERT_EQ(k.size(), 1u);
        EXPECT_EQ(k[0].features, 0x13);
        EXPECT_EQ(k[0].fee, 2100);
        ASSERT_TRUE(k[0].pegin.has_value());
        EXPECT_EQ(*k[0].pegin, fx::kBlock3200572PeginValue);
        EXPECT_EQ(raw_hex(k[0].kernel_id), fx::kBlock3200572KernelId);
    }
    // 3200601: a peg-in and a peg-out.
    {
        const Bytes raw = ParseHex(fx::kBlock3200601MwebRawHex);
        PackStream ps(raw);
        MWEBBlock blk;
        ps >> blk;
        const auto& k = blk.body.summary.kernels;
        ASSERT_EQ(k.size(), 2u);
        EXPECT_EQ(k[0].features, 0x13);
        EXPECT_EQ(k[0].fee, 2100);
        EXPECT_EQ(k[0].pegin.value_or(-1), 570771880);
        EXPECT_EQ(raw_hex(k[0].kernel_id), fx::kBlock3200601PeginKernelId);
        EXPECT_EQ(k[1].features, 0x15);
        EXPECT_EQ(k[1].fee, 2540);
        ASSERT_EQ(k[1].pegouts.size(), 1u);
        EXPECT_EQ(k[1].pegouts[0].amount, 30000000);
        EXPECT_EQ(hex_of(k[1].pegouts[0].script), fx::kBlock3200601PegoutScript);
        EXPECT_EQ(raw_hex(k[1].kernel_id), fx::kBlock3200601PegoutKernelId);
        EXPECT_EQ(blk.body.summary.total_fee(), 2100 + 2540);
    }
    // 3200603: a plain kernel and a peg-out kernel.
    {
        const Bytes raw = ParseHex(fx::kBlock3200603MwebRawHex);
        PackStream ps(raw);
        MWEBBlock blk;
        ps >> blk;
        const auto& k = blk.body.summary.kernels;
        ASSERT_EQ(k.size(), 2u);
        EXPECT_EQ(k[0].features, 0x11);
        EXPECT_EQ(k[0].fee, 50000);
        EXPECT_EQ(k[1].features, 0x15);
        EXPECT_EQ(k[1].fee, 2262);
        ASSERT_EQ(k[1].pegouts.size(), 1u);
        EXPECT_EQ(k[1].pegouts[0].amount, 2500000000LL);
    }
}

// Body vector lengths are CompactSize (TxBody's std::vectors), not VARINT:
// the encodings agree only below 128.
TEST(LtcMwebTxWire, BlockBodyLengthsAreCompactSize)
{
    MWEBHeader hdr;
    hdr.height = 3200700;
    PackStream hps;
    hps << hdr;
    Bytes raw = to_bytes(hps);
    const Bytes count = ParseHex("fd2c01");
    raw.insert(raw.end(), count.begin(), count.end());
    for (int i = 0; i < 300; ++i) {
        const Bytes in = plain_input(static_cast<unsigned char>(i));
        raw.insert(raw.end(), in.begin(), in.end());
    }
    raw.push_back(0x00);  // outputs
    raw.push_back(0x00);  // kernels

    PackStream ps(raw);
    MWEBBlock blk;
    ASSERT_NO_THROW(ps >> blk);
    EXPECT_EQ(ps.cursor_size(), 0u);
    EXPECT_EQ(blk.body.summary.n_inputs, 300u);
    MWEBState st;
    EXPECT_TRUE(MWEBBuilder::extract_mweb_header_from_raw(raw, st));
}

// The state is trusted only from exactly one mw::Block whose header agrees
// with its body (mw::Block::Validate: num_kernels == body kernels).
TEST(LtcMwebTxWire, MalformedMwebBlockIsNotTrusted)
{
    MWEBBlock blk;
    blk.header.height = 3200700;
    blk.header.kernel_mmr_size = 1;  // an empty body has no kernel
    PackStream ps;
    ps << blk;
    const Bytes lying = to_bytes(ps);
    MWEBState st;
    EXPECT_FALSE(MWEBBuilder::extract_mweb_header_from_raw(lying, st));

    Bytes trailing = ParseHex(fx::kBlock3200604MwebRawHex);
    ASSERT_TRUE(MWEBBuilder::extract_mweb_header_from_raw(trailing, st));
    trailing.push_back(0x00);
    EXPECT_FALSE(MWEBBuilder::extract_mweb_header_from_raw(trailing, st));
}

// ─── block path ─────────────────────────────────────────────────────────────

// A block never carries MWEB data in its transactions (litecoind strips it
// from a peg-in). Block 3200572 parses with its stripped peg-in and yields
// state; with the MWEB-carrying peg-in spliced in it still parses byte for
// byte (so the error is the right one), and the tracker refuses it.
TEST(LtcMwebTxWire, BlockWithMwebDataInATransactionIsRefused)
{
    const Bytes wire = ParseHex(fx::kBlock3200572Hex);
    const BlockType b = parse_block(wire);
    ASSERT_EQ(b.m_txs.size(), fx::kBlock3200572TxCount);
    EXPECT_EQ(block_hash(b).GetHex(), fx::kBlock3200572Hash);
    EXPECT_TRUE(b.m_txs.back().m_hogEx);
    EXPECT_EQ(b.m_mweb_raw.size(), fx::kBlock3200572MwebRawLen);
    for (const auto& tx : b.m_txs)
        EXPECT_FALSE(tx.HasMWEBTx());
    EXPECT_EQ(compute_txid(b.m_txs[fx::kBlock3200572PeginTxIndex]).GetHex(), fx::kBlock3200572PeginTxid);
    EXPECT_EQ(compute_txid(b.m_txs.back()).GetHex(), fx::kBlock3200572HogexTxid);
    {
        MWEBTracker tracker;
        EXPECT_TRUE(tracker.update(b, fx::kBlock3200572Height, b.m_mweb_raw));
        auto st = tracker.get_state();
        ASSERT_TRUE(st);
        EXPECT_EQ(st->prev_hogex_txid.GetHex(), fx::kBlock3200572HogexTxid);
        EXPECT_EQ(st->prev_header.kernel_mmr_size, 1u);
    }

    // Splice: header | 92 txs (the relayed peg-in after tx 10) | 01 | mw::Block.
    PackStream hps = pack(static_cast<const BlockHeaderType&>(b));
    Bytes spliced = to_bytes(hps);
    PackStream cps;
    WriteCompactSize(cps, b.m_txs.size() + 1);
    const Bytes count = to_bytes(cps);
    spliced.insert(spliced.end(), count.begin(), count.end());
    for (size_t i = 0; i < b.m_txs.size(); ++i) {
        if (i == fx::kBlock3200572PeginTxIndex + 1) {
            const Bytes pegin = ParseHex(fx::kPeginTxHex);
            spliced.insert(spliced.end(), pegin.begin(), pegin.end());
        }
        const Bytes t = encode(b.m_txs[i], TX_WITH_WITNESS);
        spliced.insert(spliced.end(), t.begin(), t.end());
    }
    spliced.push_back(0x01);
    spliced.insert(spliced.end(), b.m_mweb_raw.begin(), b.m_mweb_raw.end());

    BlockType s;
    try {
        s = parse_block(spliced);
    } catch (const std::exception& e) {
        FAIL() << "the spliced block does not parse: " << e.what();
    }
    ASSERT_EQ(s.m_txs.size(), fx::kBlock3200572TxCount + 1);
    const auto& carried = s.m_txs[fx::kBlock3200572PeginTxIndex + 1];
    EXPECT_TRUE(carried.HasMWEBTx());
    EXPECT_EQ(compute_txid(carried).GetHex(), fx::kPeginTxid);
    EXPECT_EQ(s.m_mweb_raw, b.m_mweb_raw);
    PackStream reps;
    reps << s;
    EXPECT_EQ(hex_of(to_bytes(reps)), hex_of(spliced)) << "byte-exact round trip";

    MWEBTracker tracker;
    EXPECT_FALSE(tracker.update(s, fx::kBlock3200572Height, s.m_mweb_raw))
        << "unexpected-mweb-data";
    EXPECT_FALSE(tracker.has_state());
}

// litecoind: a tx without a witness has wtxid == txid. For a HogEx the old
// with-witness serialization added the MWEB flag and presence byte.
TEST(LtcMwebTxWire, HogexWtxidIsItsTxid)
{
    size_t left = 0;
    const MutableTransaction hogex = parse_tx_message(ParseHex(fx::kBlock3200604HogexHex), left);
    ASSERT_TRUE(hogex.m_hogEx);
    EXPECT_EQ(compute_txid(hogex).GetHex(), fx::kBlock3200604HogexTxid);
    EXPECT_EQ(compute_wtxid(hogex).GetHex(), fx::kBlock3200604HogexTxid);

    // As a BIP 152 short id (BuildCompactBlock keys every non-coinbase tx by wtxid).
    MutableTransaction cb;
    TxIn in;
    in.prevout.hash.SetNull();
    in.prevout.index = 0xffffffff;
    in.sequence = 0xffffffff;
    cb.vin.push_back(in);
    TxOut out;
    out.value = 1;
    cb.vout.push_back(out);
    BlockHeaderType hdr;
    hdr.m_version = 0x20000000;
    hdr.m_bits = 0x1d00ffff;
    const CompactBlock c = BuildCompactBlock(hdr, {cb, hogex}, 7);
    ASSERT_EQ(c.short_ids.size(), 1u);
    EXPECT_EQ(c.short_ids[0], c.GetShortID(compute_txid(hogex)));
}
