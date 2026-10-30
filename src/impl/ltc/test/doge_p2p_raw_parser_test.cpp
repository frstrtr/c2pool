// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// ltc::coin::p2p::NodeP2P with a raw (AuxPoW) parser set (rides share_test):
//   - a 'headers' message the raw parser returns nothing for delivers
//     nothing: the standard 80-byte parse is never a fallback for an AuxPoW
//     chain (it reads AuxPoW data as transactions: garbage headers);
//   - a 'block' the raw block parser cannot read is dropped, never handed on
//     from the standard parse;
//   - what the raw parser returns is the batch (the control).
// Driven through NodeP2P's public handle(RawMessage) with payloads the
// standard parser reads, so a fallback would deliver them. The pre-fix
// fallback also touched the connection, which a unit test has none of: each
// case runs in a child process, and a crash fails it like a delivery does.
// ---------------------------------------------------------------------------
#include <gtest/gtest.h>

#include <impl/ltc/coin/node_interface.hpp>
#include <impl/ltc/coin/p2p_node.hpp>
#include <impl/ltc/config_coin.hpp>

#include <boost/asio/io_context.hpp>

#include <cstdlib>
#include <memory>
#include <stdexcept>
#include <vector>

namespace {

using ltc::coin::BlockHeaderType;
using ltc::coin::BlockType;

/// What NodeP2P<Config> needs of its config: coin()->m_p2p.
class TestConfig {
public:
    struct CoinPart {
        ltc::config::P2PData m_p2p;
        ltc::config::RPCData m_rpc;
    };
    CoinPart* coin() { return &m_coin; }
    const CoinPart* coin() const { return &m_coin; }

private:
    CoinPart m_coin;
};

struct Harness {
    boost::asio::io_context ioc;
    TestConfig config;
    ltc::interfaces::Node coin;
    ltc::coin::p2p::NodeP2P<TestConfig> node{&ioc, &coin, &config, "DOGE"};
    int header_events = 0;
    size_t headers_delivered = 0;
    int blocks = 0;

    Harness()
    {
        coin.new_headers.subscribe([this](const std::vector<BlockHeaderType>& v) {
            ++header_events;
            headers_delivered += v.size();
        });
        coin.full_block.subscribe([this](const BlockType&) { ++blocks; });
    }
    void deliver(std::unique_ptr<RawMessage> m) { node.handle(std::move(m), NetService()); }
};

BlockType a_block(uint32_t nonce)
{
    BlockType b;
    b.m_version = 0x00620104;
    b.m_merkle_root.SetHex(std::to_string(4242 + nonce));
    b.m_timestamp = 1700000000 + nonce;
    b.m_bits = 0x1e0ffff0;
    b.m_nonce = nonce;
    return b;
}

/// Each case runs in a child process (EXPECT_EXIT) and exits 0 when the
/// node delivered what it should have, 1 when it did not.
[[noreturn]] void unreadable_headers_case()
{
    Harness h;
    h.node.set_raw_headers_parser([](const uint8_t*, size_t) { return std::vector<BlockHeaderType>{}; });
    std::vector<BlockType> standard{a_block(1), a_block(2)};
    h.deliver(ltc::coin::p2p::message_headers::make_raw(standard, {}));
    std::exit(h.header_events == 0 ? 0 : 1);
}

[[noreturn]] void unreadable_block_case()
{
    Harness h;
    h.node.set_raw_block_parser(
        [](const uint8_t*, size_t) -> BlockType { throw std::runtime_error("unreadable AuxPoW"); });
    h.deliver(ltc::coin::p2p::message_block::make_raw(a_block(3), {}));
    std::exit(h.blocks == 0 ? 0 : 1);
}

[[noreturn]] void raw_batch_case()
{
    Harness h;
    const std::vector<BlockHeaderType> parsed{a_block(7), a_block(8), a_block(9)};
    h.node.set_raw_headers_parser([parsed](const uint8_t*, size_t) { return parsed; });
    std::vector<BlockType> standard{a_block(1)};
    h.deliver(ltc::coin::p2p::message_headers::make_raw(standard, {}));
    std::exit(h.header_events == 1 && h.headers_delivered == 3 ? 0 : 1);
}

} // namespace

TEST(DogeP2PRawParser, AHeadersMessageTheRawParserCannotReadDeliversNothing)
{
    GTEST_FLAG_SET(death_test_style, "threadsafe");
    EXPECT_EXIT(unreadable_headers_case(), ::testing::ExitedWithCode(0), "")
        << "a headers message the raw parser could not read was delivered from the standard parse";
}

TEST(DogeP2PRawParser, ABlockTheRawParserCannotReadIsDropped)
{
    GTEST_FLAG_SET(death_test_style, "threadsafe");
    EXPECT_EXIT(unreadable_block_case(), ::testing::ExitedWithCode(0), "")
        << "a block the raw parser could not read was delivered from the standard parse";
}

TEST(DogeP2PRawParser, WhatTheRawParserReturnsIsTheBatch)
{
    GTEST_FLAG_SET(death_test_style, "threadsafe");
    EXPECT_EXIT(raw_batch_case(), ::testing::ExitedWithCode(0), "");
}
