/// Phase S8 — WonBlockRelay live-slots reply-path KATs.
///
/// Exercises src/impl/dash/block_relay_plan.hpp — the planner that binds the
/// relay handshake (framer + getdata dispatcher) to the broadcaster's LIVE SLOT
/// keys, producing a per-slot SEND PLAN, WITHOUT any socket or live dashd:
///
///   (a) announce fan-out  — a won block records in the relay AND yields one inv
///                           frame addressed to every live slot, in order.
///   (b) dedupe/skip-empty  — duplicate and empty slot keys collapse so a slot
///                           is never announced to twice.
///   (c) zero-slots record  — with no live peers the block is STILL recorded
///                           (fan-out empty, relay.knows == true): recording is
///                           decoupled from fan-out (the submitblock arm carries
///                           it and a late peer can still getdata it).
///   (d) inv frame parity   — the announce inv reparses to exactly one MSG_BLOCK
///                           inventory carrying the announced hash.
///   (e) reply served       — a getdata from slot "peerA" for a known block is
///                           routed back tagged to "peerA"; the block reparses.
///   (f) reply notfound     — an unknown hash yields a notfound tagged to the
///                           same slot; nothing served.
///   (g) reply empty/tagged — a tx-only getdata serves nothing and emits no
///                           notfound, yet the slot tag is preserved.
///   (h) end-to-end         — announce to slots, then that peer's getdata for the
///                           announced hash returns the block (the round-trip the
///                           keystone executes against real sockets).
///
/// SCOPE NOTE (honest): pure planner over opaque string slot keys. No socket is
/// opened, no io_context touched, no hash recomputed; a block is served only if
/// announced. The live plan -> socket write path is the operator-gated
/// broadcaster_full concern and is not claimed here.

#include <gtest/gtest.h>

#include <impl/dash/block_relay_plan.hpp>
#include <impl/dash/block_relay.hpp>
#include <impl/dash/coin/p2p_messages.hpp>

#include <core/uint256.hpp>
#include <core/pack.hpp>

#include <array>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

using dash::WonBlockRelay;
using dash::WonBlockRelayPlanner;
using dash::AnnouncePlan;
using dash::ReplyPlan;
using dash::coin::BlockType;
using dash::coin::p2p::message_getdata;
using dash::coin::p2p::message_block;
using dash::coin::p2p::message_notfound;
using dash::coin::p2p::message_inv;
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

std::unique_ptr<RawMessage> make_getdata(std::vector<inventory_type> reqs) {
    return message_getdata::make_raw(std::move(reqs));
}

inventory_type inv_block(const uint256& h) {
    return inventory_type(inventory_type::block, h);
}

} // namespace

// (a) announce fan-out: block recorded + one inv addressed to every slot ──────
TEST(DashRelayPlan, Announce_RecordsAndFansOutToEverySlot) {
    WonBlockRelay relay;
    WonBlockRelayPlanner planner(relay);

    const uint256 h = hash_seq(0x20);
    const std::vector<std::string> slots{"10.0.0.1:9999", "10.0.0.2:9999", "10.0.0.3:9999"};

    AnnouncePlan plan = planner.plan_announce(slots, h, make_block(4));

    EXPECT_TRUE(relay.knows(h));
    ASSERT_NE(plan.inv, nullptr);
    EXPECT_EQ(plan.inv->m_command, "inv");
    ASSERT_EQ(plan.fanout(), 3u);
    EXPECT_EQ(plan.slots[0], "10.0.0.1:9999");
    EXPECT_EQ(plan.slots[1], "10.0.0.2:9999");
    EXPECT_EQ(plan.slots[2], "10.0.0.3:9999");
}

// (b) duplicate + empty slot keys collapse ────────────────────────────────────
TEST(DashRelayPlan, Announce_DedupesAndSkipsEmptySlots) {
    WonBlockRelay relay;
    WonBlockRelayPlanner planner(relay);

    const std::vector<std::string> slots{"a:1", "", "b:2", "a:1", "", "b:2", "c:3"};
    AnnouncePlan plan = planner.plan_announce(slots, hash_seq(0x30), make_block(1));

    ASSERT_EQ(plan.fanout(), 3u);
    // first-seen order preserved (set is only for dedupe membership)
    EXPECT_EQ(plan.slots[0], "a:1");
    EXPECT_EQ(plan.slots[1], "b:2");
    EXPECT_EQ(plan.slots[2], "c:3");
}

// (c) zero live slots: block STILL recorded, fan-out empty ────────────────────
TEST(DashRelayPlan, Announce_ZeroSlots_StillRecords) {
    WonBlockRelay relay;
    WonBlockRelayPlanner planner(relay);

    const uint256 h = hash_seq(0x40);
    AnnouncePlan plan = planner.plan_announce(std::vector<std::string>{}, h, make_block(2));

    EXPECT_EQ(plan.fanout(), 0u);
    EXPECT_NE(plan.inv, nullptr);       // frame built even with no recipients
    EXPECT_TRUE(relay.knows(h));        // recording decoupled from fan-out
    EXPECT_EQ(relay.pending(), 1u);
}

// (d) the inv frame reparses to one MSG_BLOCK inventory of the announced hash ──
TEST(DashRelayPlan, Announce_InvFrameReparsesToBlockHash) {
    WonBlockRelay relay;
    WonBlockRelayPlanner planner(relay);

    const uint256 h = hash_seq(0x55);
    AnnouncePlan plan = planner.plan_announce(std::vector<std::string>{"p:1"}, h, make_block(3));

    auto inv = message_inv::make(plan.inv->m_data);
    ASSERT_EQ(inv->m_invs.size(), 1u);
    EXPECT_EQ(inv->m_invs[0].m_hash, h);
    EXPECT_EQ(static_cast<uint32_t>(inv->m_invs[0].m_type),
              static_cast<uint32_t>(inventory_type::block));
}

// (e) reply path: known block routed back tagged to the requesting slot ───────
TEST(DashRelayPlan, Reply_KnownBlock_TaggedToSlot) {
    WonBlockRelay relay;
    WonBlockRelayPlanner planner(relay);

    const uint256 h = hash_seq(0x33);
    const BlockType blk = make_block(7);
    planner.plan_announce(std::vector<std::string>{"peerA"}, h, blk);

    ReplyPlan rp = planner.plan_getdata_reply("peerA", *make_getdata({inv_block(h)}));

    EXPECT_EQ(rp.slot, "peerA");
    ASSERT_EQ(rp.served(), 1u);
    EXPECT_FALSE(rp.has_misses());
    auto parsed = message_block::make(rp.blocks[0]->m_data);
    EXPECT_EQ(parsed->m_block.m_nonce, blk.m_nonce);
    EXPECT_EQ(parsed->m_block.m_merkle_root, blk.m_merkle_root);
}

// (f) reply path: unknown hash -> notfound tagged to the same slot ────────────
TEST(DashRelayPlan, Reply_UnknownBlock_NotfoundTaggedToSlot) {
    WonBlockRelay relay;
    WonBlockRelayPlanner planner(relay);
    planner.plan_announce(std::vector<std::string>{"peerB"}, hash_seq(0x10), make_block(1));

    const uint256 unknown = hash_seq(0x90);
    ReplyPlan rp = planner.plan_getdata_reply("peerB", *make_getdata({inv_block(unknown)}));

    EXPECT_EQ(rp.slot, "peerB");
    EXPECT_EQ(rp.served(), 0u);
    ASSERT_TRUE(rp.has_misses());
    auto nf = message_notfound::make(rp.notfound->m_data);
    ASSERT_EQ(nf->m_invs.size(), 1u);
    EXPECT_EQ(nf->m_invs[0].m_hash, unknown);
}

// (g) reply path: tx-only serves nothing, no notfound, slot tag preserved ─────
TEST(DashRelayPlan, Reply_TxOnly_EmptyButTagged) {
    WonBlockRelay relay;
    WonBlockRelayPlanner planner(relay);
    planner.plan_announce(std::vector<std::string>{"peerC"}, hash_seq(0x20), make_block(4));

    ReplyPlan rp = planner.plan_getdata_reply("peerC", *make_getdata({
        inventory_type(inventory_type::tx, hash_seq(0x66)),
    }));

    EXPECT_EQ(rp.slot, "peerC");
    EXPECT_EQ(rp.served(), 0u);
    EXPECT_FALSE(rp.has_misses());
}

// (h) end-to-end: announce then the peer's getdata returns the block ──────────
TEST(DashRelayPlan, EndToEnd_AnnounceThenGetdataReturnsBlock) {
    WonBlockRelay relay;
    WonBlockRelayPlanner planner(relay);

    const uint256 h = hash_seq(0x44);
    const BlockType blk = make_block(5);
    AnnouncePlan ap = planner.plan_announce(std::vector<std::string>{"miner-peer"}, h, blk);
    ASSERT_EQ(ap.fanout(), 1u);

    // the peer answers our inv with getdata for the same hash
    ReplyPlan rp = planner.plan_getdata_reply("miner-peer", *make_getdata({inv_block(h)}));
    ASSERT_EQ(rp.served(), 1u);
    EXPECT_EQ(rp.slot, "miner-peer");
    auto parsed = message_block::make(rp.blocks[0]->m_data);
    EXPECT_EQ(parsed->m_block.m_version,        blk.m_version);
    EXPECT_EQ(parsed->m_block.m_previous_block, blk.m_previous_block);
    EXPECT_EQ(parsed->m_block.m_nonce,          blk.m_nonce);
}
