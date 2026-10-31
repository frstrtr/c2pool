// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// ltc::coin::p2p::NodeP2P with a raw (AuxPoW) parser set (rides share_test):
//   - a 'headers' message the raw parser returns nothing for delivers
//     nothing: the standard 80-byte parse is never a fallback for an AuxPoW
//     chain (it reads AuxPoW data as transactions: garbage headers);
//   - a 'block' the raw block parser cannot read is dropped, never handed on
//     from the standard parse;
//   - what the raw parser returns is the batch (the control);
//   - a raw parse that stops before the message's count (it returned fewer
//     entries than the CompactSize declares) goes to the truncation hook
//     with what parsed and the count, never to new_headers (VERIFY5 S3); a
//     complete one goes to new_headers, not the hook;
//   - an inv announcing a block, with announced fetches off: the header
//     chain hears of it (new_block), no body getdata goes out (the embedded
//     DOGE node's tip handler asks the announcer once; every announcer sent
//     the body before: 18-22 copies of each tip).
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

/// A message declaring three headers; the raw parser returns `parsed` of
/// them. Exits 0 when the truncation hook got (parsed, 3) and new_headers
/// nothing (parsed < 3), or new_headers got all three and the hook nothing.
[[noreturn]] void truncation_case(size_t parsed)
{
    Harness h;
    const std::vector<BlockType> sent{a_block(1), a_block(2), a_block(3)};
    std::vector<BlockHeaderType> prefix(sent.begin(), sent.begin() + parsed);
    h.node.set_raw_headers_parser([prefix](const uint8_t*, size_t) { return prefix; });
    int hooked = 0;
    size_t hook_headers = 0;
    uint64_t hook_count = 0;
    h.node.set_on_headers_truncated([&](const std::vector<BlockHeaderType>& v, uint64_t count) {
        ++hooked;
        hook_headers = v.size();
        hook_count = count;
    });
    h.deliver(ltc::coin::p2p::message_headers::make_raw(sent, {}));
    const bool ok = parsed < 3
        ? hooked == 1 && hook_headers == parsed && hook_count == 3 && h.header_events == 0
        : hooked == 0 && h.header_events == 1 && h.headers_delivered == 3;
    std::exit(ok ? 0 : 1);
}

/// An inv for a block on a DOGE node whose announced fetches are off. The
/// harness has no connection: a getdata would crash the child.
[[noreturn]] void inv_case()
{
    Harness h;
    int announced = 0;
    h.coin.new_block.subscribe([&](const uint256&) { ++announced; });
    h.node.set_fetch_announced_blocks(false);
    uint256 b;
    b.SetHex("00000000000000000000000000000000000000000000000000000000c0ffee01");
    h.deliver(ltc::coin::p2p::message_inv::make_raw(
        {ltc::coin::p2p::inventory_type(ltc::coin::p2p::inventory_type::block, b)}));
    std::exit(announced == 1 ? 0 : 1);
}

} // namespace

TEST(DogeP2PRawParser, AShortRawParseGoesToTheTruncationHookNotNewHeaders)
{
    GTEST_FLAG_SET(death_test_style, "threadsafe");
    EXPECT_EXIT(truncation_case(2), ::testing::ExitedWithCode(0), "")
        << "2 of 3 parsed: not handed to the truncation hook as (2, 3), or delivered as new headers";
    EXPECT_EXIT(truncation_case(0), ::testing::ExitedWithCode(0), "")
        << "0 of 3 parsed: not handed to the truncation hook as (0, 3)";
    EXPECT_EXIT(truncation_case(3), ::testing::ExitedWithCode(0), "")
        << "3 of 3 parsed: not delivered as new headers, or the hook was called";
}

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

TEST(DogeP2PRawParser, AnInvAsksNoBodyWhenAnnouncedFetchesAreOff)
{
    GTEST_FLAG_SET(death_test_style, "threadsafe");
    EXPECT_EXIT(inv_case(), ::testing::ExitedWithCode(0), "");
}
