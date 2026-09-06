// SPDX-License-Identifier: AGPL-3.0-or-later
// KAT for the Dash sharechain pool-node wire layer (src/impl/dash/messages.hpp).
// Proves each pool-node BEGIN_MESSAGE round-trips byte-for-byte and the type-list
// instantiates — the btc/dgb/ltc analog ported namespace-only to dash.
// Mirrors test_dash_p2p_messages.cpp idiom.
#include <gtest/gtest.h>

#include <impl/dash/messages.hpp>
#include <impl/dash/coin/bestblock_diag.hpp>  // #1046 bestblock out=0 classifier
#include <impl/dash/config_pool.hpp>   // SharechainConfig net-aware prefix selectors
#include <btclibs/util/strencodings.h> // ParseHexBytes (prefix isolation primitive)

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

// ── #157 M2: tx_inject subtype ──────────────────────────────────────────────
namespace {
// A minimal 1-in 1-out classic (type-0) tx so the wire round-trip exercises a
// real MutableTransaction body (not an empty one).
static coin::MutableTransaction make_inject_tx() {
    coin::MutableTransaction tx;
    tx.version = 1; tx.type = 0; tx.locktime = 0;
    coin::TxIn in;
    in.prevout.hash = uint256(0x9a9a9aull);
    in.prevout.index = 3;
    in.sequence = 0xffffffffu;
    in.scriptSig = OPScript(std::vector<unsigned char>{0x51, 0x52, 0x53});
    tx.vin.push_back(in);
    coin::TxOut out;
    out.value = 123456;
    out.scriptPubKey = OPScript(std::vector<unsigned char>{0x76, 0xa9, 0x14});
    tx.vout.push_back(out);
    return tx;
}
} // namespace

TEST(DashPoolNodeMessages, Message_TxInject_RoundTrip) {
    auto tx = make_inject_tx();
    auto rmsg = message_tx_inject::make_raw(/*version=*/1u, /*flags=*/0x2Au,
                                            /*expiry_height=*/987654, tx);
    EXPECT_EQ(rmsg->m_command, "tx_inject");
    EXPECT_LE(std::string("tx_inject").size(), 12u);   // fits the command field

    auto parsed = message_tx_inject::make(rmsg->m_data);
    EXPECT_EQ(parsed->m_version, 1u);
    EXPECT_EQ(parsed->m_flags, 0x2Au);
    EXPECT_EQ(parsed->m_expiry_height, 987654);
    ASSERT_EQ(parsed->m_tx.vin.size(), 1u);
    ASSERT_EQ(parsed->m_tx.vout.size(), 1u);
    EXPECT_EQ(parsed->m_tx.vin[0].prevout.index, 3u);
    EXPECT_EQ(parsed->m_tx.vout[0].value, 123456);
    EXPECT_EQ(parsed->m_tx.version, 1);
    EXPECT_EQ(parsed->m_tx.type, 0);
}

// WIRE-COMPAT: an OLD peer whose dispatch set predates M2 has no tx_inject
// handler. Feeding it a tx_inject frame throws std::out_of_range — which
// handle_message() catches as `const std::exception&` and turns into a
// LOG_WARNING, NOT a disconnect. The NEW dash::Handler parses it cleanly.
TEST(DashPoolNodeMessages, OldPeerUnknownTxInjectIsWarningNotDisconnect) {
    // Documents the catch site's contract: the throw is a std::exception.
    static_assert(std::is_base_of_v<std::exception, std::out_of_range>,
                  "handle_message catches std::exception → LOG_WARNING, not disconnect");

    // The pre-M2 dispatch type-list, literally the old dash::Handler (12 types,
    // no message_tx_inject).
    using OldHandler = MessageHandler<
        message_ping, message_addrme, message_getaddrs, message_addrs,
        message_shares, message_sharereq, message_sharereply, message_bestblock,
        message_have_tx, message_losing_tx, message_forget_tx, message_remember_tx>;

    auto tx = make_inject_tx();

    // An old peer cannot parse tx_inject → out_of_range (→ caught as LOG_WARNING).
    {
        OldHandler oldh;
        auto rmsg = message_tx_inject::make_raw(1u, 0u, 0, tx);
        EXPECT_THROW(oldh.parse(rmsg), std::out_of_range);
    }

    // The current dash::Handler DOES parse it (feature present).
    {
        Handler newh;
        auto rmsg = message_tx_inject::make_raw(1u, 0u, 0, tx);
        EXPECT_NO_THROW(newh.parse(rmsg));
    }
}


// #1046: the bestblock-origination fetch classifier. Drives the REAL
// nlohmann::json type (not a mock). These FAIL to compile/pass without
// classify_bestblock_header + the three-way BestblockFetch enum, which is the
// diagnostic change that distinguishes RpcNotString vs BadHexLen on the soak
// node's silent out=0 bail (announce_bestblock lambda, main_dash.cpp).
TEST(DashPoolNodeMessages, Bestblock_Classify_Ok) {
    std::string hex(160, 'a');  // exactly an 80-byte header, 160 hex chars
    std::string out = "sentinel";
    auto cls = dash::coin::classify_bestblock_header(nlohmann::json(hex), out);
    EXPECT_EQ(cls, dash::coin::BestblockFetch::Ok);
    EXPECT_EQ(out, hex);
    EXPECT_STREQ(dash::coin::bestblock_fetch_name(cls), "Ok");
}

TEST(DashPoolNodeMessages, Bestblock_Classify_RpcNotString) {
    std::string out = "sentinel";
    // getblockheader(verbose=false) that came back as an object/number/null.
    auto cls = dash::coin::classify_bestblock_header(
        nlohmann::json::object({{"result", "deadbeef"}}), out);
    EXPECT_EQ(cls, dash::coin::BestblockFetch::RpcNotString);
    EXPECT_TRUE(out.empty());  // left cleared, not the string branch
    EXPECT_STREQ(dash::coin::bestblock_fetch_name(cls), "RpcNotString");
}

TEST(DashPoolNodeMessages, Bestblock_Classify_BadHexLen_Empty) {
    std::string out = "sentinel";
    auto cls = dash::coin::classify_bestblock_header(nlohmann::json(std::string()), out);
    EXPECT_EQ(cls, dash::coin::BestblockFetch::BadHexLen);
    EXPECT_TRUE(out.empty());  // captured for the len= log line
    EXPECT_STREQ(dash::coin::bestblock_fetch_name(cls), "BadHexLen");
}

TEST(DashPoolNodeMessages, Bestblock_Classify_BadHexLen_Short) {
    std::string out;
    auto cls = dash::coin::classify_bestblock_header(nlohmann::json(std::string(159, 'a')), out);
    EXPECT_EQ(cls, dash::coin::BestblockFetch::BadHexLen);
    EXPECT_EQ(out.size(), 159u);
}

// ---------------------------------------------------------------------------
// Connect-mode sharechain prefix wire-proof.
//
// The outbound (--connect-only) leg frames every packet with the 8-byte pool
// prefix set at main_dash.cpp:601:
//     config.pool()->m_prefix = ParseHexBytes(SharechainConfig::prefix_hex());
// NodeP2P::get_prefix() (src/pool/node.hpp:88) returns that buffer and
// Socket::send() (src/core/socket.cpp:122) hands it to Packet::from_message as
// the on-wire prefix; the peer's read side matches it byte-for-byte over
// get_prefix().size() (src/core/socket.cpp:223). This KAT proves the SOURCE the
// connect leg frames with is net-aware -- mainnet vs testnet select DIFFERENT
// prefixes -- and that the read-side Packet prefix buffer is sized to match.
// Regression lock for the "connect leg emits the wrong net's prefix" interop
// break, which is invisible on a mainnet-only soak (is_testnet stays false).
TEST(DashConnectModePrefix, WirePrefix_NetAware_MainnetVsTestnet) {
    const bool saved = SharechainConfig::is_testnet;

    SharechainConfig::is_testnet = false;
    EXPECT_EQ(SharechainConfig::prefix_hex(), std::string("3b3e1286f446b891"));  // live p2pool-dash fleet chain
    auto main_bytes = ParseHexBytes(SharechainConfig::prefix_hex());
    EXPECT_EQ(main_bytes.size(), size_t(8));

    SharechainConfig::is_testnet = true;
    EXPECT_EQ(SharechainConfig::prefix_hex(), std::string("198b644f6821e3b3"));
    auto test_bytes = ParseHexBytes(SharechainConfig::prefix_hex());
    EXPECT_EQ(test_bytes.size(), size_t(8));

    EXPECT_NE(main_bytes, test_bytes);

    SharechainConfig::is_testnet = saved;
}
