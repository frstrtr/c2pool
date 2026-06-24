/// Phase S8 — WonBlockRelay (embedded-P2P won-block relay framer) KATs.
///
/// Exercises src/impl/dash/block_relay.hpp — the framing half of the
/// embedded-P2P broadcast leg of the dual-path block-viability gate. Pins the
/// `inv(MSG_BLOCK,hash)` announce -> getdata -> full `block` handshake that the
/// DashBroadcaster pool fans out when DASH wins a block, WITHOUT any socket or
/// live dashd:
///
///   (a) announce      — returns an `inv` RawMessage carrying exactly one
///                       inventory_type, type == MSG_BLOCK (2), hash == the
///                       supplied (consensus-computed) hash; layout PINNED by
///                       independent reparse, not a self round-trip.
///   (b) on_getdata    — a known hash returns the full `block` message whose
///                       header bytes reconstruct the announced block; an
///                       UNKNOWN hash returns nullptr (never serve unannounced).
///   (c) bookkeeping   — knows / pending / forget / clear; re-announce is
///                       idempotent (refreshes, no duplicate slot).
///
/// SCOPE NOTE (honest): pure framer + pending-block book. The block hash is an
/// INPUT (the consensus layer's X11 header hash) — not recomputed here, so no
/// consensus value is asserted. The live on_block_found -> announce -> socket
/// fan-out is the operator-gated broadcaster_full concern and is not claimed.

#include <gtest/gtest.h>

#include <impl/dash/block_relay.hpp>
#include <impl/dash/coin/p2p_messages.hpp>

#include <core/uint256.hpp>
#include <core/pack.hpp>

#include <array>
#include <cstdint>
#include <cstring>
#include <vector>

using dash::WonBlockRelay;
using dash::coin::BlockType;
using dash::coin::p2p::message_inv;
using dash::coin::p2p::message_block;
using dash::coin::p2p::inventory_type;

namespace {

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

} // namespace

// (a) announce frames a single MSG_BLOCK inv for the supplied hash ────────────
TEST(DashWonBlockRelay, Announce_FramesSingleBlockInv) {
    WonBlockRelay relay;
    const uint256 h = hash_seq(0x77);

    auto rmsg = relay.announce(h, make_block(1));
    ASSERT_NE(rmsg, nullptr);
    EXPECT_EQ(rmsg->m_command, "inv");

    // Reparse the inv payload independently (layout-sensitive, not self-rt).
    auto parsed = message_inv::make(rmsg->m_data);
    ASSERT_EQ(parsed->m_invs.size(), 1u);
    EXPECT_EQ(static_cast<uint32_t>(parsed->m_invs[0].m_type),
              static_cast<uint32_t>(inventory_type::block));   // MSG_BLOCK == 2
    EXPECT_EQ(static_cast<uint32_t>(inventory_type::block), 2u);
    EXPECT_EQ(parsed->m_invs[0].m_hash, h);
}

// (b) getdata on a known hash yields the full announced block ─────────────────
TEST(DashWonBlockRelay, GetData_KnownHash_ReturnsFullBlock) {
    WonBlockRelay relay;
    const uint256 h = hash_seq(0x20);
    const BlockType blk = make_block(4);
    relay.announce(h, blk);

    auto rmsg = relay.on_getdata_block(h);
    ASSERT_NE(rmsg, nullptr);
    EXPECT_EQ(rmsg->m_command, "block");

    auto parsed = message_block::make(rmsg->m_data);
    EXPECT_EQ(parsed->m_block.m_version,        blk.m_version);
    EXPECT_EQ(parsed->m_block.m_previous_block, blk.m_previous_block);
    EXPECT_EQ(parsed->m_block.m_merkle_root,    blk.m_merkle_root);
    EXPECT_EQ(parsed->m_block.m_timestamp,      blk.m_timestamp);
    EXPECT_EQ(parsed->m_block.m_bits,           blk.m_bits);
    EXPECT_EQ(parsed->m_block.m_nonce,          blk.m_nonce);
}

// (b') never serve a block we did not announce ────────────────────────────────
TEST(DashWonBlockRelay, GetData_UnknownHash_ReturnsNull) {
    WonBlockRelay relay;
    relay.announce(hash_seq(0x01), make_block(1));
    EXPECT_EQ(relay.on_getdata_block(hash_seq(0xfe)), nullptr);
    EXPECT_FALSE(relay.knows(hash_seq(0xfe)));
}

// (c) bookkeeping: knows / pending / forget / clear ───────────────────────────
TEST(DashWonBlockRelay, Bookkeeping_KnowsPendingForgetClear) {
    WonBlockRelay relay;
    EXPECT_EQ(relay.pending(), 0u);

    const uint256 a = hash_seq(0x10), b = hash_seq(0x40);
    relay.announce(a, make_block(1));
    relay.announce(b, make_block(2));
    EXPECT_EQ(relay.pending(), 2u);
    EXPECT_TRUE(relay.knows(a));
    EXPECT_TRUE(relay.knows(b));

    relay.forget(a);
    EXPECT_FALSE(relay.knows(a));
    EXPECT_EQ(relay.pending(), 1u);
    EXPECT_EQ(relay.on_getdata_block(a), nullptr);

    relay.clear();
    EXPECT_EQ(relay.pending(), 0u);
}

// (c') re-announce of a known hash is idempotent (refresh, no dup) ────────────
TEST(DashWonBlockRelay, ReAnnounce_SameHash_IsIdempotentRefresh) {
    WonBlockRelay relay;
    const uint256 h = hash_seq(0x33);

    relay.announce(h, make_block(1));
    relay.announce(h, make_block(9));   // refresh under same hash
    EXPECT_EQ(relay.pending(), 1u);

    auto rmsg = relay.on_getdata_block(h);
    ASSERT_NE(rmsg, nullptr);
    auto parsed = message_block::make(rmsg->m_data);
    EXPECT_EQ(parsed->m_block.m_nonce, make_block(9).m_nonce);  // latest wins
}
