// SPDX-License-Identifier: AGPL-3.0-or-later
// DASH tx extra-payload gate KAT — dashd nVersion==3 parity (mainnet 842284).
//
// dashd (primitives/transaction.h) carries vExtraPayload on the wire ONLY
// when nVersion==3 && nType!=0. The c2pool codec used to read/write it on
// type!=0 alone. DASH mainnet block 842284's coinbase is a pre-DIP2 tx whose
// raw 32-bit nVersion is 0x20000000 (a BIP9-style value a miner put in the tx
// version field): split as version16|type16 that is version=0, type=0x2000 —
// a PLAIN tx that dashd round-trips untouched, but the old codec consumed a
// phantom extra payload out of the NEXT tx's bytes, misaligned the whole
// body, and delivered a partially-parsed block (2 of 14 txs). The merkle fold
// over the garbage txids never matched the header's committed root, so the
// bulk-replay lane re-requested the byte-identical consensus data from every
// peer forever: the [BULK] MERKLE-BIND FAIL livelock at delivered=842283.
//
// Fixture: the canonical mainnet block 842284
//   hash        000000000000000cdf5cc24c3beb0669b31e942d1301e07b53d6f0c7db10860d
//   merkleroot  88b1bcf06eca702b68d9443cd7567bd2fd03e04edfab6b8ea33b99e803c8c50c
//   14 txs, pre-DIP3 (no special txs anywhere in the block).
// Red on the old codec (parse throws, 2 txs, wrong root); green with the
// dashd-exact gate: 14 txs, byte-identical round-trip, merkle bind holds.
//
// Also covers the aggravator: core MessageHandler used to swallow ANY parse
// throw (a DOGE-AuxPoW raw-headers fallback) and deliver the partially-parsed
// message even for types with no raw-bytes fallback — which is exactly how
// the misparse above reached the merkle bind with zero errors logged. It must
// rethrow for types without m_raw_payload and keep the fallback for types
// with it.

#include <gtest/gtest.h>

#include <impl/dash/coin/block.hpp>
#include <impl/dash/coin/block_producer.hpp>
#include <impl/dash/coin/transaction.hpp>

#include <core/hash.hpp>
#include <core/message.hpp>
#include <core/pack.hpp>
#include <core/uint256.hpp>

#include <cstdint>
#include <cstring>
#include <fstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

using dash::coin::BlockType;
using dash::coin::MutableTransaction;

std::vector<unsigned char> load_fixture_hex(const std::string& name)
{
    const std::string path = std::string(DASH_FIXTURE_DIR) + "/" + name;
    std::ifstream f(path);
    EXPECT_TRUE(f.good()) << "missing fixture " << path;
    std::string hex;
    f >> hex;
    std::vector<unsigned char> out;
    out.reserve(hex.size() / 2);
    for (size_t i = 0; i + 1 < hex.size(); i += 2)
        out.push_back(static_cast<unsigned char>(
            std::stoul(hex.substr(i, 2), nullptr, 16)));
    return out;
}

// uint256 (internal LE order) -> display-order hex, as explorers print it.
std::string to_display_hex(const uint256& u)
{
    static const char* hx = "0123456789abcdef";
    std::string out;
    const auto* d = reinterpret_cast<const unsigned char*>(u.data());
    for (int i = 31; i >= 0; --i) {
        out += hx[d[i] >> 4];
        out += hx[d[i] & 15];
    }
    return out;
}

BlockType parse_block_842284()
{
    auto bytes = load_fixture_hex("dash_mainnet_block_842284.hex");
    EXPECT_FALSE(bytes.empty());
    PackStream s(bytes);
    BlockType blk;
    s >> blk; // old codec: throws "ReadCompactSize(): size too large" at tx2
    return blk;
}

// ---------------------------------------------------------------------------
// Block 842284: the whole body parses — all 14 txs, not 2.
TEST(DashTxVersionGate, Block842284ParsesAllFourteenTxs)
{
    const BlockType blk = parse_block_842284();
    ASSERT_EQ(blk.m_txs.size(), 14u);

    // The coinbase is the trigger: raw nVersion 0x20000000 splits into
    // version16=0 / type16=0x2000, and it must parse as a PLAIN tx —
    // no phantom extra payload consumed out of tx1's bytes.
    const auto& cb = blk.m_txs.front();
    EXPECT_EQ(cb.version, 0);
    EXPECT_EQ(cb.type, 0x2000);
    EXPECT_TRUE(cb.extra_payload.empty());
    EXPECT_EQ(cb.vin.size(), 1u);
}

// The parsed body re-serializes byte-identical to the canonical wire bytes —
// the codec neither drops nor invents a single byte anywhere in the block.
TEST(DashTxVersionGate, Block842284RoundTripsByteIdentical)
{
    const auto bytes = load_fixture_hex("dash_mainnet_block_842284.hex");
    PackStream s(bytes);
    BlockType blk;
    s >> blk;

    auto repacked = ::pack(blk);
    ASSERT_EQ(repacked.size(), bytes.size());
    EXPECT_EQ(std::memcmp(repacked.data(), bytes.data(), bytes.size()), 0);
}

// The reward-critical bind: the merkle fold over the parsed tx set equals the
// header's committed root. This is the exact check the bulk lane livelocked on.
TEST(DashTxVersionGate, Block842284BindsBodyToHeader)
{
    const BlockType blk = parse_block_842284();
    ASSERT_EQ(blk.m_txs.size(), 14u);
    EXPECT_EQ(to_display_hex(blk.m_merkle_root),
              "88b1bcf06eca702b68d9443cd7567bd2fd03e04edfab6b8ea33b99e803c8c50c");
    EXPECT_TRUE(dash::coin::block_body_binds_to_header(blk));
}

// ---------------------------------------------------------------------------
// Guard: real special txs (nVersion==3, nType!=0) keep their payload on the
// wire byte-for-byte — the gate must not disturb CbTx/ProTx serialization.
TEST(DashTxVersionGate, SpecialV3TxKeepsExtraPayload)
{
    MutableTransaction tx;
    tx.version = 3;
    tx.type = 5; // CbTx
    tx.vin.resize(1);
    tx.vout.resize(1);
    tx.extra_payload = {0xde, 0xad, 0xbe, 0xef};

    auto packed = ::pack(tx);
    PackStream s2(std::span<const std::byte>(packed.data(), packed.size()));
    MutableTransaction back;
    s2 >> back;

    EXPECT_EQ(back.version, 3);
    EXPECT_EQ(back.type, 5);
    EXPECT_EQ(back.extra_payload, tx.extra_payload);
    EXPECT_EQ(s2.size(), 0u) << "payload round-trip must consume every byte";
}

// dashd writes the payload compact-size even when the payload is EMPTY
// (an nVersion==3 special tx always carries the varint). The old codec
// skipped the field on empty and could not re-read its own bytes.
TEST(DashTxVersionGate, SpecialV3TxEmptyPayloadRoundTrips)
{
    MutableTransaction tx;
    tx.version = 3;
    tx.type = 5;
    tx.vin.resize(1);
    tx.vout.resize(1);
    tx.extra_payload.clear();

    auto packed = ::pack(tx);
    PackStream s2(std::span<const std::byte>(packed.data(), packed.size()));
    MutableTransaction back;
    s2 >> back;

    EXPECT_EQ(back.version, 3);
    EXPECT_EQ(back.type, 5);
    EXPECT_TRUE(back.extra_payload.empty());
    EXPECT_EQ(s2.size(), 0u);
}

// A plain tx whose raw 32-bit version carries BIP9-style high bits (the
// 842284 coinbase shape) round-trips with no payload field at all.
TEST(DashTxVersionGate, Bip9StyleVersionBitsTxHasNoPayloadField)
{
    MutableTransaction tx;
    tx.version = 0;      // low 16 bits of 0x20000000
    tx.type = 0x2000;    // high 16 bits
    tx.vin.resize(1);
    tx.vout.resize(1);

    auto packed = ::pack(tx);
    PackStream s2(std::span<const std::byte>(packed.data(), packed.size()));
    MutableTransaction back;
    s2 >> back;

    EXPECT_EQ(back.version, 0);
    EXPECT_EQ(back.type, 0x2000);
    EXPECT_TRUE(back.extra_payload.empty());
    EXPECT_EQ(s2.size(), 0u) << "no phantom extra-payload byte may be consumed";
}

// ---------------------------------------------------------------------------
// Aggravator: MessageHandler must NOT silently deliver a partially-parsed
// message for a type with no raw-bytes fallback…
struct ThrowingParseMsg : Message
{
    ThrowingParseMsg() : Message("kat_throwing") {}
    template <typename StreamType> void Serialize(StreamType&) const {}
    template <typename StreamType> void Unserialize(StreamType&)
    {
        throw std::runtime_error("kat: codec throw mid-message");
    }
};

// …but must keep the raw-payload fallback (DOGE AuxPoW headers) working.
struct RawFallbackMsg : Message
{
    std::vector<uint8_t> m_raw_payload;
    RawFallbackMsg() : Message("kat_rawfb") {}
    template <typename StreamType> void Serialize(StreamType&) const {}
    template <typename StreamType> void Unserialize(StreamType&)
    {
        throw std::runtime_error("kat: codec throw mid-message");
    }
};

TEST(DashTxVersionGate, MessageHandlerRethrowsWithoutRawFallback)
{
    MessageHandler<ThrowingParseMsg, RawFallbackMsg> handler;

    auto rmsg = std::make_unique<RawMessage>("kat_throwing", PackStream{});
    rmsg->m_data << static_cast<int32_t>(842284);
    EXPECT_THROW(handler.parse(rmsg), std::runtime_error)
        << "a partially-parsed message with no raw fallback must not be "
           "delivered silently";
}

TEST(DashTxVersionGate, MessageHandlerKeepsRawPayloadFallback)
{
    MessageHandler<ThrowingParseMsg, RawFallbackMsg> handler;

    auto rmsg = std::make_unique<RawMessage>("kat_rawfb", PackStream{});
    rmsg->m_data << static_cast<int32_t>(842284);
    const size_t payload_size = rmsg->m_data.size();

    auto result = handler.parse(rmsg); // must NOT throw — fallback path
    auto* msg = std::get<std::unique_ptr<RawFallbackMsg>>(result).get();
    ASSERT_NE(msg, nullptr);
    EXPECT_EQ(msg->m_raw_payload.size(), payload_size);
}

} // namespace
