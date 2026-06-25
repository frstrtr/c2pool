/// test_dash_embedded_relay_e2e.cpp
///
/// Phase S8 — EMBEDDED won-block relay END-TO-END KAT (won-block-reaches-network).
///
/// G3b proved the dashd `submitblock` RPC FALLBACK arm of the dual-path
/// block-viability gate end-to-end on regtest (c2pool-dash won block 272,
/// ACCEPTED, mempool drained). This KAT proves the OTHER arm — the EMBEDDED P2P
/// relay — at the wire-framing level, which G3b did NOT exercise:
///
///     DashBroadcaster (leaf, #405) --fan-out hook--> per-slot submit seam
///                                                          |
///                                       WonBlockRelay (#432/#441) framer
///                                       inv(MSG_BLOCK,h) -> getdata -> block
///                                                          |
///                                                  [peer reconstructs block]
///
/// Both leaves are on master but had only ISOLATED unit coverage; the embedded
/// arm is the COMPOSITION the (operator-gated) broadcaster_full.hpp keystone
/// drives onto a live socket. Here we drive that composition socket-free and
/// assert every LIVE peer reconstructs the EXACT won block (byte-parity vs the
/// canonical serialization), and that a COLD pool reaches zero peers — which is
/// precisely why the dashd-RPC fallback arm (proven in G3b) is never removed.
///
/// Single dash tree, non-consensus, zero sockets. Block hash is producer-
/// supplied (not recomputed), so this carries no consensus value.

#include <gtest/gtest.h>

#include <impl/dash/broadcaster.hpp>
#include <impl/dash/block_relay.hpp>
#include <impl/dash/config.hpp>
#include <impl/dash/coin/p2p_messages.hpp>

#include <core/netaddress.hpp>
#include <core/uint256.hpp>
#include <core/pack.hpp>

#include <boost/asio.hpp>

#include <array>
#include <cstring>
#include <memory>
#include <span>
#include <string>
#include <vector>

using namespace dash;
using dash::coin::BlockType;
using dash::coin::p2p::message_inv;
using dash::coin::p2p::message_block;
using dash::coin::p2p::inventory_type;
using nlohmann::json;

namespace {

constexpr uint16_t kCanonicalPort = 19999;
constexpr char     kPrimaryHost[] = "10.9.9.9";

uint256 hash_seq(uint8_t base) {
    std::array<uint8_t, 32> p{};
    for (size_t i = 0; i < 32; ++i) p[i] = static_cast<uint8_t>(base + i);
    uint256 h; std::memcpy(h.data(), p.data(), 32); return h;
}

BlockType make_block(uint8_t seed) {
    BlockType b;
    b.m_version        = 0x20000000u | seed;
    b.m_previous_block = hash_seq(0x10 + seed);
    b.m_merkle_root    = hash_seq(0x50 + seed);
    b.m_timestamp      = 0x5f5e1000u + seed;
    b.m_bits           = 0x1d00ffffu;
    b.m_nonce          = 0xdeadbeefu - seed;
    return b;
}

// Non-destructive byte view of a PackStream (does not advance the read cursor).
std::vector<unsigned char> bytes_of(PackStream& ps) {
    auto sp = ps.get_span();
    auto* p = reinterpret_cast<const unsigned char*>(sp.data());
    return std::vector<unsigned char>(p, p + sp.size());
}

std::unique_ptr<Config> make_config() {
    auto cfg = std::make_unique<Config>("dash-s8-embedded-relay-e2e-kat");
    cfg->coin()->m_p2p.address =
        NetService{std::string{"127.0.0.1"}, std::to_string(kCanonicalPort)};
    return cfg;
}

json peer(const std::string& addr) {
    json p = json::object();
    p["addr"] = addr;
    return p;
}

// Leaf broadcaster with a bare-NodeP2P factory + injected liveness, populated
// with N live slots via a discovery pass (mirrors test_dash_broadcaster_full).
struct PoolEnv {
    boost::asio::io_context ioc;
    std::unique_ptr<Config> cfg{make_config()};
    bool all_live{true};
    std::unique_ptr<DashBroadcaster> pool;

    explicit PoolEnv(size_t max_peers = 16) {
        pool = std::make_unique<DashBroadcaster>(
            &ioc, cfg.get(),
            NetService{std::string{kPrimaryHost}, std::to_string(kCanonicalPort)},
            max_peers);
        pool->set_slot_factory([this](const NetService&) {
            return std::make_unique<dash::coin::p2p::NodeP2P>(&ioc);
        });
        pool->set_live_predicate(
            [this](const dash::coin::p2p::NodeP2P&) { return all_live; });
    }

    void dial(size_t n) {
        json peers = json::array();
        for (size_t i = 0; i < n; ++i)
            peers.push_back(peer("10.0.0." + std::to_string(i + 1) + ":19999"));
        size_t got = pool->discover(peers);
        ASSERT_EQ(got, n);
    }
};

// Wire the leaf's fan-out seam to the WonBlockRelay handshake: each LIVE peer
// the fan-out reaches runs getdata(h) against the relay and reconstructs the
// served block. Records one reconstructed block per peer reached.
struct EmbeddedRelayHarness {
    WonBlockRelay relay;
    BlockType     won;
    uint256       won_hash;
    std::vector<unsigned char> won_wire;            // canonical serialized block
    std::vector<BlockType>     delivered;            // one per reached peer
    std::vector<std::vector<unsigned char>> fanned;  // bytes the seam handed each peer

    EmbeddedRelayHarness(uint8_t seed, uint8_t hashbase)
        : won(make_block(seed)), won_hash(hash_seq(hashbase))
    {
        won_wire = bytes_of(message_block::make_raw(won)->m_data);
    }

    // Announce once (records the won block + builds the inv to fan out), wire the
    // leaf seam to the per-peer getdata->block handshake, then drive the won
    // block through submit_block_raw_all. Returns the live-peer fan-out count.
    size_t broadcast(DashBroadcaster& pool) {
        auto inv = relay.announce(won_hash, won);
        // The inv that fans to every peer carries exactly our MSG_BLOCK hash.
        EXPECT_EQ(inv->m_command, "inv");
        auto pinv = message_inv::make(inv->m_data);
        EXPECT_EQ(pinv->m_invs.size(), 1u);
        EXPECT_EQ(static_cast<uint32_t>(pinv->m_invs[0].m_type),
                  static_cast<uint32_t>(inventory_type::block));
        EXPECT_EQ(pinv->m_invs[0].m_hash, won_hash);

        pool.set_fan_out_hook([this](dash::coin::p2p::NodeP2P&,
                                     std::span<const unsigned char> b) {
            fanned.emplace_back(b.begin(), b.end());
            // Peer side: getdata(MSG_BLOCK, h) -> full `block` message -> parse.
            auto blkmsg = relay.on_getdata_block(won_hash);
            ASSERT_NE(blkmsg, nullptr);
            EXPECT_EQ(blkmsg->m_command, "block");
            auto parsed = message_block::make(blkmsg->m_data);
            delivered.push_back(parsed->m_block);
        });
        return pool.submit_block_raw_all(won_wire);
    }
};

void expect_block_eq(const BlockType& a, const BlockType& b) {
    EXPECT_EQ(a.m_version,        b.m_version);
    EXPECT_EQ(a.m_previous_block, b.m_previous_block);
    EXPECT_EQ(a.m_merkle_root,    b.m_merkle_root);
    EXPECT_EQ(a.m_timestamp,      b.m_timestamp);
    EXPECT_EQ(a.m_bits,           b.m_bits);
    EXPECT_EQ(a.m_nonce,          b.m_nonce);
}

} // namespace

// (1) Embedded arm delivers the EXACT won block to EVERY live peer ────────────
TEST(DashEmbeddedRelayE2E, DeliversExactWonBlockToEveryLivePeer) {
    PoolEnv env;
    env.dial(3);
    EmbeddedRelayHarness h{7, 0xA0};

    size_t reached = h.broadcast(*env.pool);

    EXPECT_EQ(reached, 3u);                    // leaf fanned to all live slots
    ASSERT_EQ(h.delivered.size(), 3u);         // 3 peers completed the handshake
    ASSERT_EQ(h.fanned.size(), 3u);
    for (size_t i = 0; i < h.delivered.size(); ++i) {
        expect_block_eq(h.delivered[i], h.won); // reconstructed == won block
        // byte-parity: relay-served bytes == canonical won-block wire bytes, and
        // the bytes the seam handed the peer are the same won-block bytes.
        auto served = bytes_of(message_block::make_raw(h.delivered[i])->m_data);
        EXPECT_EQ(served, h.won_wire);
        EXPECT_EQ(h.fanned[i], h.won_wire);
    }
}

// (2) COLD pool: zero live peers -> embedded arm reaches NO peer ──────────────
//     The embedded arm alone can silently drop a won block — exactly why the
//     authoritative dashd-RPC fallback arm (proven end-to-end in G3b) is kept.
TEST(DashEmbeddedRelayE2E, ColdPoolReachesNoPeer) {
    PoolEnv env;
    env.dial(3);
    env.all_live = false;                      // every slot now dead
    EmbeddedRelayHarness h{4, 0x30};

    size_t reached = h.broadcast(*env.pool);

    EXPECT_EQ(reached, 0u);
    EXPECT_TRUE(h.delivered.empty());          // no peer reconstructed a block
    EXPECT_TRUE(h.fanned.empty());
}

// (3) The embedded arm never serves a block the producer did not announce ─────
TEST(DashEmbeddedRelayE2E, NeverServesUnannouncedBlock) {
    WonBlockRelay relay;
    const uint256 announced = hash_seq(0x11);
    relay.announce(announced, make_block(2));

    // getdata for a hash we never announced as won -> nothing on the wire.
    EXPECT_EQ(relay.on_getdata_block(hash_seq(0x99)), nullptr);

    // The announced won block is served intact.
    auto msg = relay.on_getdata_block(announced);
    ASSERT_NE(msg, nullptr);
    auto parsed = message_block::make(msg->m_data);
    expect_block_eq(parsed->m_block, make_block(2));
}

// (4) Byte-parity is identical across ALL peers — no per-peer fan-out drift ───
TEST(DashEmbeddedRelayE2E, ByteParityIdenticalAcrossAllPeers) {
    PoolEnv env;
    env.dial(5);
    EmbeddedRelayHarness h{9, 0xC0};

    size_t reached = h.broadcast(*env.pool);

    ASSERT_EQ(reached, 5u);
    ASSERT_EQ(h.delivered.size(), 5u);
    for (const auto& d : h.delivered) {
        auto served = bytes_of(message_block::make_raw(d)->m_data);
        EXPECT_EQ(served, h.won_wire);          // every peer got identical bytes
    }
}
