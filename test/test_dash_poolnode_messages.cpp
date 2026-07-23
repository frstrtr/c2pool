// SPDX-License-Identifier: AGPL-3.0-or-later
// KAT for the Dash sharechain pool-node wire layer (src/impl/dash/messages.hpp).
// Proves each pool-node BEGIN_MESSAGE round-trips byte-for-byte and the type-list
// instantiates — the btc/dgb/ltc analog ported namespace-only to dash.
// Mirrors test_dash_p2p_messages.cpp idiom.
#include <gtest/gtest.h>

#include <impl/dash/messages.hpp>

using namespace dash;

namespace {

// Non-destructive byte view of a PackStream (does not advance the read cursor).
static std::vector<unsigned char> bytes_of(PackStream& ps) {
    auto sp = ps.get_span();
    auto* p = reinterpret_cast<const unsigned char*>(sp.data());
    return std::vector<unsigned char>(p, p + sp.size());
}

static addr_t make_addr(uint16_t port) {
    return addr_t(1u, NetService("192.168.1.1", port));
}

} // namespace

TEST(DashPoolNodeMessages, Message_Version_RoundTrip) {
    auto rmsg = message_version::make_raw(
        70238u, 1u, make_addr(9999), make_addr(8888), uint64_t(0xABCDEF),
        std::string("c2pool-dash"), 1u, uint256(0x11ull));
    EXPECT_EQ(rmsg->m_command, "version");

    auto parsed = message_version::make(rmsg->m_data);
    EXPECT_EQ(parsed->m_version, 70238u);
    EXPECT_EQ(parsed->m_services, 1u);
    EXPECT_EQ(parsed->m_nonce, uint64_t(0xABCDEF));
    EXPECT_EQ(parsed->m_subversion, std::string("c2pool-dash"));
    EXPECT_EQ(parsed->m_mode, 1u);
    EXPECT_EQ(parsed->m_addr_to.m_endpoint.port(), 9999);
    EXPECT_EQ(parsed->m_addr_from.m_endpoint.port(), 8888);
    EXPECT_EQ(parsed->m_best_share, uint256(0x11ull));
}

TEST(DashPoolNodeMessages, Message_Ping_Empty) {
    auto rmsg = message_ping::make_raw();
    EXPECT_EQ(rmsg->m_command, "ping");
    EXPECT_EQ(bytes_of(rmsg->m_data).size(), 0u);
}

TEST(DashPoolNodeMessages, Message_Addrme_LayoutPinned) {
    auto rmsg = message_addrme::make_raw(uint16_t(0x1234));
    EXPECT_EQ(rmsg->m_command, "addrme");
    // uint16_t port, little-endian: 2 bytes 0x34 0x12
    auto b = bytes_of(rmsg->m_data);
    ASSERT_EQ(b.size(), 2u);
    EXPECT_EQ(b[0], 0x34);
    EXPECT_EQ(b[1], 0x12);

    auto parsed = message_addrme::make(rmsg->m_data);
    EXPECT_EQ(parsed->m_port, 0x1234);
}

TEST(DashPoolNodeMessages, Message_Getaddrs_RoundTrip) {
    auto rmsg = message_getaddrs::make_raw(42u);
    EXPECT_EQ(rmsg->m_command, "getaddrs");
    auto parsed = message_getaddrs::make(rmsg->m_data);
    EXPECT_EQ(parsed->m_count, 42u);
}

TEST(DashPoolNodeMessages, Message_Addrs_RoundTrip) {
    std::vector<addr_record_t> addrs{
        addr_record_t(make_addr(19999), 1710000000ull),
        addr_record_t(make_addr(29999), 1710000001ull),
    };
    auto rmsg = message_addrs::make_raw(addrs);
    EXPECT_EQ(rmsg->m_command, "addrs");
    auto parsed = message_addrs::make(rmsg->m_data);
    ASSERT_EQ(parsed->m_addrs.size(), 2u);
    EXPECT_EQ(parsed->m_addrs[0].m_endpoint.port(), 19999);
    EXPECT_EQ(parsed->m_addrs[0].m_timestamp, 1710000000ull);
    EXPECT_EQ(parsed->m_addrs[1].m_endpoint.port(), 29999);
}

TEST(DashPoolNodeMessages, Message_Shares_RoundTrip_V16) {
    // Dash sharechain carries v16 shares in the envelope (transition 16->36).
    std::vector<chain::RawShare> shares{
        chain::RawShare(16u, BaseScript(std::vector<unsigned char>{0xde, 0xad, 0xbe, 0xef})),
        chain::RawShare(36u, BaseScript(std::vector<unsigned char>{0x01, 0x02})),
    };
    auto rmsg = message_shares::make_raw(shares);
    EXPECT_EQ(rmsg->m_command, "shares");
    auto parsed = message_shares::make(rmsg->m_data);
    ASSERT_EQ(parsed->m_shares.size(), 2u);
    EXPECT_EQ(parsed->m_shares[0].type, 16u);
    EXPECT_EQ(parsed->m_shares[1].type, 36u);
    EXPECT_EQ(parsed->m_shares[0].contents.m_data,
              (std::vector<unsigned char>{0xde, 0xad, 0xbe, 0xef}));
}

TEST(DashPoolNodeMessages, Message_Sharereq_RoundTrip) {
    auto rmsg = message_sharereq::make_raw(
        uint256(0xaaull),
        std::vector<uint256>{uint256(0x01ull), uint256(0x02ull)},
        5ull,
        std::vector<uint256>{uint256(0xffull)});
    EXPECT_EQ(rmsg->m_command, "sharereq");
    auto parsed = message_sharereq::make(rmsg->m_data);
    EXPECT_EQ(parsed->m_id, uint256(0xaaull));
    ASSERT_EQ(parsed->m_hashes.size(), 2u);
    EXPECT_EQ(parsed->m_parents, 5ull);
    ASSERT_EQ(parsed->m_stops.size(), 1u);
    EXPECT_EQ(parsed->m_stops[0], uint256(0xffull));
}

TEST(DashPoolNodeMessages, Message_Sharereply_EnumResult) {
    std::vector<chain::RawShare> shares{
        chain::RawShare(16u, BaseScript(std::vector<unsigned char>{0x42})),
    };
    auto rmsg = message_sharereply::make_raw(uint256(0xccull), good, shares);
    EXPECT_EQ(rmsg->m_command, "sharereply");
    auto parsed = message_sharereply::make(rmsg->m_data);
    EXPECT_EQ(parsed->m_id, uint256(0xccull));
    EXPECT_EQ(parsed->m_result, good);
    ASSERT_EQ(parsed->m_shares.size(), 1u);
}

TEST(DashPoolNodeMessages, Message_HaveTx_RoundTrip) {
    std::vector<uint256> hashes{uint256(0x07ull), uint256(0x08ull)};
    auto rmsg = message_have_tx::make_raw(hashes);
    EXPECT_EQ(rmsg->m_command, "have_tx");
    auto parsed = message_have_tx::make(rmsg->m_data);
    ASSERT_EQ(parsed->m_tx_hashes.size(), 2u);
    EXPECT_EQ(parsed->m_tx_hashes[1], uint256(0x08ull));
}

TEST(DashPoolNodeMessages, Handler_TypeList_Compiles) {
    // The pool-node dispatch type-list must instantiate (variadic pack valid).
    // Type-only check: avoids ODR-using MessageHandler::m_handlers static
    // storage, which is defined out-of-line in the (not-yet-landed) node.cpp.
    using HandlerResult = Handler::result_t;
    EXPECT_GT(sizeof(HandlerResult), 0u);
}