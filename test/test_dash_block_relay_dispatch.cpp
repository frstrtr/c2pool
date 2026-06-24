/// Phase S8 — WonBlockRelay getdata-dispatch KATs.
///
/// Exercises src/impl/dash/block_relay_dispatch.hpp — the INBOUND half of the
/// embedded-P2P won-block relay handshake. The framer (block_relay.hpp) emits
/// the outbound inv/block frames; this dispatcher decodes a single inbound
/// `getdata` RawMessage (a VECTOR of inventory requests, as a peer actually
/// sends it) and routes each MSG_BLOCK request through the relay's pending-block
/// book, WITHOUT any socket or live dashd:
///
///   (a) mixed getdata — block-known + tx + block-unknown in one message:
///       only the known block is served (in order), the unknown block lands in
///       `notfound`, the tx request is ignored.
///   (b) all-known    — every block request served, NO notfound emitted.
///   (c) all-unknown  — zero blocks served, notfound carries every block hash.
///   (d) non-block    — a tx-only getdata yields nothing (no blocks, no
///                      notfound): the won-block relay is not a general server.
///   (e) byte-parity  — a served `block` message reparses to the announced
///                      block (layout pinned by independent reparse, not self-rt).
///   (f) witness flag — MSG_WITNESS_BLOCK matches base_type==block and is served
///                      from the same canonical pending entry.
///   (g) order        — served blocks preserve the peer's request order.
///
/// SCOPE NOTE (honest): pure dispatcher over a pending-block book. Block hashes
/// are INPUTS (the consensus layer's X11 header hashes the framer recorded) —
/// never recomputed here, and a block is served only if it was announced, so no
/// consensus value is asserted. The live getdata -> socket reply path is the
/// operator-gated broadcaster_full concern and is not claimed.

#include <gtest/gtest.h>

#include <impl/dash/block_relay_dispatch.hpp>
#include <impl/dash/block_relay.hpp>
#include <impl/dash/coin/p2p_messages.hpp>

#include <core/uint256.hpp>
#include <core/pack.hpp>

#include <array>
#include <cstdint>
#include <cstring>
#include <vector>

using dash::WonBlockRelay;
using dash::dispatch_getdata;
using dash::coin::BlockType;
using dash::coin::p2p::message_getdata;
using dash::coin::p2p::message_block;
using dash::coin::p2p::message_notfound;
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

// Build a `getdata` RawMessage carrying exactly the supplied inventory items.
std::unique_ptr<RawMessage> make_getdata(std::vector<inventory_type> reqs) {
    return message_getdata::make_raw(std::move(reqs));
}

inventory_type inv_block(const uint256& h) {
    return inventory_type(inventory_type::block, h);
}

} // namespace

// (a) mixed getdata: known block served, unknown -> notfound, tx ignored ──────
TEST(DashGetDataDispatch, Mixed_ServesKnown_NotfoundsUnknown_IgnoresTx) {
    WonBlockRelay relay;
    const uint256 known = hash_seq(0x20);
    const uint256 unknown = hash_seq(0xa0);
    const BlockType blk = make_block(4);
    relay.announce(known, blk);

    auto gd = make_getdata({
        inv_block(known),
        inventory_type(inventory_type::tx, hash_seq(0x66)),
        inv_block(unknown),
    });

    auto out = dispatch_getdata(*gd, relay);

    ASSERT_EQ(out.served(), 1u);
    EXPECT_EQ(out.blocks[0]->m_command, "block");
    ASSERT_TRUE(out.has_misses());
    EXPECT_EQ(out.notfound->m_command, "notfound");

    auto nf = message_notfound::make(out.notfound->m_data);
    ASSERT_EQ(nf->m_invs.size(), 1u);
    EXPECT_EQ(nf->m_invs[0].m_hash, unknown);
    EXPECT_EQ(static_cast<uint32_t>(nf->m_invs[0].m_type),
              static_cast<uint32_t>(inventory_type::block));
}

// (b) all-known -> every block served, NO notfound ────────────────────────────
TEST(DashGetDataDispatch, AllKnown_NoNotfound) {
    WonBlockRelay relay;
    const uint256 a = hash_seq(0x10), b = hash_seq(0x40);
    relay.announce(a, make_block(1));
    relay.announce(b, make_block(2));

    auto out = dispatch_getdata(*make_getdata({inv_block(a), inv_block(b)}), relay);

    EXPECT_EQ(out.served(), 2u);
    EXPECT_FALSE(out.has_misses());
    EXPECT_EQ(out.notfound, nullptr);
}

// (c) all-unknown -> zero served, notfound carries every hash ─────────────────
TEST(DashGetDataDispatch, AllUnknown_AllNotfound) {
    WonBlockRelay relay;
    relay.announce(hash_seq(0x01), make_block(1));   // a different hash

    const uint256 u1 = hash_seq(0x80), u2 = hash_seq(0xc0);
    auto out = dispatch_getdata(*make_getdata({inv_block(u1), inv_block(u2)}), relay);

    EXPECT_EQ(out.served(), 0u);
    ASSERT_TRUE(out.has_misses());
    auto nf = message_notfound::make(out.notfound->m_data);
    ASSERT_EQ(nf->m_invs.size(), 2u);
    EXPECT_EQ(nf->m_invs[0].m_hash, u1);
    EXPECT_EQ(nf->m_invs[1].m_hash, u2);
}

// (d) tx-only getdata -> nothing served, no notfound (not a general server) ────
TEST(DashGetDataDispatch, TxOnly_ServesNothing_NoNotfound) {
    WonBlockRelay relay;
    relay.announce(hash_seq(0x20), make_block(4));

    auto out = dispatch_getdata(*make_getdata({
        inventory_type(inventory_type::tx, hash_seq(0x66)),
        inventory_type(inventory_type::filtered_block, hash_seq(0x77)),
    }), relay);

    EXPECT_EQ(out.served(), 0u);
    EXPECT_FALSE(out.has_misses());
}

// (e) a served block reparses to the announced block (byte parity) ────────────
TEST(DashGetDataDispatch, ServedBlock_ReparsesToAnnounced) {
    WonBlockRelay relay;
    const uint256 h = hash_seq(0x33);
    const BlockType blk = make_block(7);
    relay.announce(h, blk);

    auto out = dispatch_getdata(*make_getdata({inv_block(h)}), relay);
    ASSERT_EQ(out.served(), 1u);

    auto parsed = message_block::make(out.blocks[0]->m_data);
    EXPECT_EQ(parsed->m_block.m_version,        blk.m_version);
    EXPECT_EQ(parsed->m_block.m_previous_block, blk.m_previous_block);
    EXPECT_EQ(parsed->m_block.m_merkle_root,    blk.m_merkle_root);
    EXPECT_EQ(parsed->m_block.m_timestamp,      blk.m_timestamp);
    EXPECT_EQ(parsed->m_block.m_bits,           blk.m_bits);
    EXPECT_EQ(parsed->m_block.m_nonce,          blk.m_nonce);
}

// (f) MSG_WITNESS_BLOCK matches base_type==block and is served ─────────────────
TEST(DashGetDataDispatch, WitnessBlockFlag_ServedFromCanonicalEntry) {
    WonBlockRelay relay;
    const uint256 h = hash_seq(0x44);
    relay.announce(h, make_block(5));

    auto out = dispatch_getdata(*make_getdata({
        inventory_type(inventory_type::witness_block, h),
    }), relay);

    EXPECT_EQ(out.served(), 1u);
    EXPECT_FALSE(out.has_misses());
    EXPECT_EQ(out.blocks[0]->m_command, "block");
}

// (g) served blocks preserve the peer's request order ─────────────────────────
TEST(DashGetDataDispatch, ServedBlocks_PreserveRequestOrder) {
    WonBlockRelay relay;
    const uint256 a = hash_seq(0x10), b = hash_seq(0x40), c = hash_seq(0x70);
    relay.announce(a, make_block(1));
    relay.announce(b, make_block(2));
    relay.announce(c, make_block(3));

    // request order c, a, b
    auto out = dispatch_getdata(
        *make_getdata({inv_block(c), inv_block(a), inv_block(b)}), relay);
    ASSERT_EQ(out.served(), 3u);

    auto p0 = message_block::make(out.blocks[0]->m_data);
    auto p1 = message_block::make(out.blocks[1]->m_data);
    auto p2 = message_block::make(out.blocks[2]->m_data);
    EXPECT_EQ(p0->m_block.m_nonce, make_block(3).m_nonce);  // c
    EXPECT_EQ(p1->m_block.m_nonce, make_block(1).m_nonce);  // a
    EXPECT_EQ(p2->m_block.m_nonce, make_block(2).m_nonce);  // b
}
