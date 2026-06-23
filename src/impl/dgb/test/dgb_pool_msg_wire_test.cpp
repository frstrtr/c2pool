// dgb pool wire-message layer — serialization conformance KAT.
//
// FENCED conformance test (no production code touched). src/impl/dgb/messages.hpp
// carries the V36 DGB-Scrypt pool P2P wire-message set and asserts in its header
// comment "message format byte-parity with p2pool-merged-v36" — yet NO test in
// the repo (dgb, ltc, btc or core) pinned any of it. A silent drift in a field
// order, a READWRITE list, a vector framing, or a command name would let two
// c2pool-dgb peers (or a c2pool-dgb peer and a p2pool-merged-v36 reference node)
// fail to exchange shares with no compile error. This KAT closes that gap.
//
// Three invariants, oracle-aligned with p2pool-merged-v36 / frstrtr/p2pool-dgb-
// scrypt p2p/p2protocol message numbering:
//   1. WIRE COMMAND NAMES — the routing key MessageHandler dispatches on. These
//      strings ARE the protocol; a typo silently un-routes a message type.
//   2. SCALAR LE BYTE PINS — the deterministic-format messages (ping/getaddrs/
//      addrme) serialize to exact, hand-derivable little-endian bytes.
//   3. ROUND-TRIP FIELD EQUALITY — pack(populated) -> read back -> fields equal,
//      exercising both directions of every READWRITE for the share-exchange and
//      tx-gossip messages (sharereq/sharereply/shares/have_tx/losing_tx/
//      forget_tx/remember_tx) plus the version handshake.
//
// Per-coin isolation: src/impl/dgb/ only; messages.hpp is a namespace-only
// divergence from src/impl/ltc/messages.hpp, so this anchors the shared Scrypt-
// family wire shape for the dgb tree without touching ltc.
//
// MUST appear in BOTH the ctest registration (this dir CMakeLists.txt) AND the
// build.yml --target allowlist, or it becomes a #143-style NOT_BUILT sentinel
// that reds master.

#include <impl/dgb/messages.hpp>

#include <core/pack.hpp>
#include <core/uint256.hpp>

#include <gtest/gtest.h>

#include <cstdint>
#include <string>
#include <vector>

namespace {

// Copy a freshly-packed PackStream's bytes out as a flat vector (the on-wire
// payload), so we can re-open it from cursor 0 for the read-back leg.
std::vector<unsigned char> wire_bytes(PackStream& s) {
    auto* p = reinterpret_cast<unsigned char*>(s.data());
    return std::vector<unsigned char>(p, p + s.size());
}

std::string tohex(const std::vector<unsigned char>& v) {
    static const char* H = "0123456789abcdef";
    std::string out;
    out.reserve(v.size() * 2);
    for (unsigned char b : v) { out.push_back(H[b >> 4]); out.push_back(H[b & 0xf]); }
    return out;
}

uint256 u256(const char* hex) {
    uint256 t;
    t.SetHex(hex);
    return t;
}

// --------------------------------------------------------------------------
// 1. Wire command-name parity — the dispatch keys MessageHandler routes on.
// --------------------------------------------------------------------------
TEST(DgbPoolMsgWire, CommandNames) {
    EXPECT_EQ(dgb::message_version().m_command,     "version");
    EXPECT_EQ(dgb::message_ping().m_command,        "ping");
    EXPECT_EQ(dgb::message_addrme().m_command,      "addrme");
    EXPECT_EQ(dgb::message_getaddrs().m_command,    "getaddrs");
    EXPECT_EQ(dgb::message_addrs().m_command,       "addrs");
    EXPECT_EQ(dgb::message_shares().m_command,      "shares");
    EXPECT_EQ(dgb::message_sharereq().m_command,    "sharereq");
    EXPECT_EQ(dgb::message_sharereply().m_command,  "sharereply");
    EXPECT_EQ(dgb::message_bestblock().m_command,   "bestblock");
    EXPECT_EQ(dgb::message_have_tx().m_command,     "have_tx");
    EXPECT_EQ(dgb::message_losing_tx().m_command,   "losing_tx");
    EXPECT_EQ(dgb::message_forget_tx().m_command,   "forget_tx");
    EXPECT_EQ(dgb::message_remember_tx().m_command, "remember_tx");
}

// --------------------------------------------------------------------------
// 2. Deterministic-format messages -> exact little-endian wire bytes.
// --------------------------------------------------------------------------
TEST(DgbPoolMsgWire, PingIsEmptyPayload) {
    auto ps = dgb::message_ping::make();
    EXPECT_EQ(ps.size(), 0u);
}

TEST(DgbPoolMsgWire, GetaddrsUint32LittleEndian) {
    auto ps = dgb::message_getaddrs::make(static_cast<uint32_t>(0x01020304));
    EXPECT_EQ(tohex(wire_bytes(ps)), "04030201");
}

TEST(DgbPoolMsgWire, AddrmeUint16LittleEndian) {
    auto ps = dgb::message_addrme::make(static_cast<uint16_t>(0x1234));
    EXPECT_EQ(tohex(wire_bytes(ps)), "3412");
}

// --------------------------------------------------------------------------
// 3. Round-trip field equality — pack(populated) -> read back -> equal.
// --------------------------------------------------------------------------
TEST(DgbPoolMsgWire, SharereqRoundTrip) {
    const uint256 id = u256("11");
    std::vector<uint256> hashes{ u256("aa"), u256("bb") };
    std::vector<uint256> stops{ u256("cc") };
    const uint64_t parents = 7;

    auto ps = dgb::message_sharereq::make(id, hashes, parents, stops);
    auto bytes = wire_bytes(ps);
    PackStream rs(bytes);
    auto m = dgb::message_sharereq::make(rs);

    EXPECT_EQ(m->m_id, id);
    EXPECT_EQ(m->m_parents, parents);
    ASSERT_EQ(m->m_hashes.size(), hashes.size());
    EXPECT_EQ(m->m_hashes[0], hashes[0]);
    EXPECT_EQ(m->m_hashes[1], hashes[1]);
    ASSERT_EQ(m->m_stops.size(), stops.size());
    EXPECT_EQ(m->m_stops[0], stops[0]);
}

TEST(DgbPoolMsgWire, SharereplyRoundTripResultEnum) {
    const uint256 id = u256("22");
    auto ps = dgb::message_sharereply::make(id, dgb::too_long,
                                            std::vector<chain::RawShare>{});
    auto bytes = wire_bytes(ps);
    PackStream rs(bytes);
    auto m = dgb::message_sharereply::make(rs);

    EXPECT_EQ(m->m_id, id);
    EXPECT_EQ(m->m_result, dgb::too_long);
    EXPECT_TRUE(m->m_shares.empty());
}

TEST(DgbPoolMsgWire, TxGossipHashVectorsRoundTrip) {
    std::vector<uint256> hs{ u256("01"), u256("02"), u256("03") };

    auto rt = [&](auto packed) {
        auto bytes = wire_bytes(packed);
        PackStream rs(bytes);
        return rs;
    };

    {
        auto ps = dgb::message_have_tx::make(hs);
        auto rs = rt(std::move(ps));
        auto m = dgb::message_have_tx::make(rs);
        ASSERT_EQ(m->m_tx_hashes.size(), hs.size());
        EXPECT_EQ(m->m_tx_hashes[2], hs[2]);
    }
    {
        auto ps = dgb::message_losing_tx::make(hs);
        auto rs = rt(std::move(ps));
        auto m = dgb::message_losing_tx::make(rs);
        EXPECT_EQ(m->m_tx_hashes.size(), hs.size());
    }
    {
        auto ps = dgb::message_forget_tx::make(hs);
        auto rs = rt(std::move(ps));
        auto m = dgb::message_forget_tx::make(rs);
        EXPECT_EQ(m->m_tx_hashes.size(), hs.size());
    }
}

TEST(DgbPoolMsgWire, SharesEmptyVectorRoundTrip) {
    auto ps = dgb::message_shares::make(std::vector<chain::RawShare>{});
    auto bytes = wire_bytes(ps);
    PackStream rs(bytes);
    auto m = dgb::message_shares::make(rs);
    EXPECT_TRUE(m->m_shares.empty());
}

TEST(DgbPoolMsgWire, RememberTxEmptyRoundTrip) {
    auto ps = dgb::message_remember_tx::make(std::vector<uint256>{},
                                             std::vector<dgb::coin::MutableTransaction>{});
    auto bytes = wire_bytes(ps);
    PackStream rs(bytes);
    auto m = dgb::message_remember_tx::make(rs);
    EXPECT_TRUE(m->m_tx_hashes.empty());
    EXPECT_TRUE(m->m_txs.empty());
}

TEST(DgbPoolMsgWire, VersionDefaultRoundTrip) {
    dgb::message_version v;
    v.m_version = 3501;
    v.m_services = 0;
    v.m_nonce = 0xdeadbeefcafef00dULL;
    v.m_subversion = "c2pool-dgb";
    v.m_mode = 1;  // always 1 for legacy compatibility
    v.m_best_share = u256("7f");

    auto ps = pack(v);
    auto bytes = wire_bytes(ps);
    PackStream rs(bytes);
    auto m = dgb::message_version::make(rs);

    EXPECT_EQ(m->m_version, 3501u);
    EXPECT_EQ(m->m_nonce, 0xdeadbeefcafef00dULL);
    EXPECT_EQ(m->m_subversion, "c2pool-dgb");
    EXPECT_EQ(m->m_mode, 1u);
    EXPECT_EQ(m->m_best_share, u256("7f"));
}

} // namespace
