// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ===========================================================================
// src/c2pool/v37/test/v37_xmr_race_rebook_kat.cpp   (RACE-DIVERGE)
//
// A depth-1 same-height flip-flop X -> Y -> X that completes INSIDE ONE tick
// (no FinalizeConnect::tick() between the two switches) must leave this node
// with the same finalized set and the same owed_digest as a node that followed
// X's branch directly.
//
// Live evidence (09-25 race-heavy 3-node regtest, origin/master 89d6a149, flip
// 0, D_conf 10): node B booked the peer's lane block 50bf.. at h=134, its native
// index switched to B's own 19e0.. at 134 (Orphan 50bf + Reorg 134), and the
// peer's 135 (built on 50bf) switched it back (Orphan 19e0 + Reorg 135) before
// the next tick. The D2-0 re-delivery handed 50bf to book_chain_block, whose
// dedup still found it in FinalizeConnect's m_pending (the ledger had already
// removed it on the Orphan; m_pending is reconciled only at the tick) -> not
// re-booked; the tick's reconcile() then reported BOTH 134 blocks ORPHANED.
// A and C finalized 50bf, B did not: owed_digest diverged at cursor 134 with
// every reorg at depth 1 (< D_conf) -- a class-(b) divergence, not a deep
// reorg. With a tick between the two switches (FC30b shape) it re-books fine.
//
//   R1  the one-tick flip-flop: the canonical peer 9 is RE-BOOKED and SETTLED,
//       our own 9 never settles (base: peer 9 never settles)
//   R2  R1's node ends byte-identical (owed_digest, settled set) to a node
//       that followed the peer's branch directly (base: digests differ)
//   R3  control: the same flip-flop with a tick between the switches (the
//       FC30b shape) -- green on base and fix, identical digest
//   R4  a stale pending entry that is NOT canonical again is still disposed
//       ORPHANED by the tick's reconcile (orphaned counter), nothing late
//
// Network-free, RandomX-free (monerod STUB + the injected test point-check
// backend, the v37_xmr_o2_finalize_connect_selfcheck shape). Nonzero exit on
// any failure.
// ===========================================================================
#include <unistd.h>

#include <cstdio>
#include <filesystem>
#include <map>
#include <optional>
#include <string>

#include "c2pool/v37/xmr/xmr_o2_finalize_connect.hpp"

namespace o2 = c2pool::v37n::xmr::o2;

namespace {

int g_fail = 0;
void check(const char* name, bool ok, const std::string& detail = {}) {
    std::printf("  [%s] %s%s%s\n", ok ? "PASS" : "FAIL", name, detail.empty() ? "" : "  -- ", detail.c_str());
    if (!ok) ++g_fail;
}

using c2pool::xmr::node::Hash;
using c2pool::xmr::node::MainchainEvent;
using c2pool::xmr::node::MainchainEventKind;
using c2pool::xmr::node::MockMonerodTransport;
using namespace c2pool::v37n::xmr;

Hash own(std::uint64_t h)  { return smoke::blk_id(static_cast<std::uint8_t>(h)); }
Hash peer(std::uint64_t h) { return smoke::blk_id(static_cast<std::uint8_t>(100 + h)); }

// How the chain reaches the node.
enum class Shape {
    Direct,            // the reference: the peer's 9, 10, ... in order
    FlipFlopOneTick,   // peer 9 booked; own 9 replaces it; peer 10 re-establishes peer 9 -- NO tick between
    FlipFlopTicked,    // the same with a tick between the two switches (FC30b)
    OrphanOnly,        // peer 9 booked; own 9 replaces it and STAYS canonical (no tick between orphan and next event)
};

struct Result {
    ::v37::bytes32 digest{};
    bool peer9_settled = false, own9_settled_or_pending = false;
    std::uint64_t cursor = 0, orphaned = 0, late = 0, redelivered = 0, registered = 0;
    bool own9_canonical_settled = false;
};

Result run(Shape shape, const std::filesystem::path& tmp, const char* name) {
    Result r;
    XmrNodeConfig c;
    c.network = MoneroNetwork::Stagenet;
    c.lane_chain = 7;
    c.d_conf = 3;
    c.arm_order = ArmOrderMode::P2PFirst;
    c.settle_db_path = (tmp / name).string();
    std::filesystem::create_directories(c.settle_db_path);
    std::map<std::uint64_t, Hash> canon;
    MockMonerodTransport mock;
    XmrNode node(c, mock, &smoke::test_point_check);
    node.set_native_chain_presence([&](std::uint64_t h, const std::string& bid) {
        const auto it = canon.find(h); return it != canon.end() && hex_of(it->second) == bid; });
    node.set_native_row_lookup([&](std::uint64_t h) -> std::optional<std::string> {
        const auto it = canon.find(h); if (it == canon.end()) return std::nullopt; return hex_of(it->second); });
    try { node.bring_up(); } catch (const std::exception& e) { check("bring_up", false, e.what()); return r; }
    o2::FinalizeConnectOptions o; o.out = nullptr;
    o.sidecar_path = (std::filesystem::path(c.settle_db_path) / "pfound.tsv").string();
    const ::v37::bytes32 kOwn = smoke::key_of(0xA1), kPeer = smoke::key_of(0xB2);
    // every block at h >= 5 is a lane block; the peer's branch pays kPeer, ours kOwn,
    // so crediting the wrong block OR dropping one both move the owed_digest.
    o.book_from_chain_ex = [&](std::uint64_t h, const std::string& bid, o2::FinalizeConnectOptions::ChainBooking& bk) -> bool {
        if (h < 5) { bk.why = "not-lane: test"; return false; }
        const bool is_peer = (h >= 9 && bid == hex_of(peer(h)));
        bk.credit[is_peer ? kPeer : kOwn] = static_cast<long long>(100 + h);
        bk.payout_decoded = true;
        return true;
    };
    o2::FoundBlockQueue q;
    o2::FinalizeConnect fc(node, c, q, o);
    (void)fc.reseed_after_bring_up();
    auto send = [&](MainchainEventKind k, std::uint64_t h, const Hash& id, std::uint64_t depth, const Hash& orphaned) {
        MainchainEvent ev; ev.kind = k; ev.block.height = h; ev.block.id = id; ev.depth = depth; ev.orphaned_id = orphaned;
        node.pump_mainchain_event(ev);
    };
    auto extend = [&](std::uint64_t h, const Hash& id) {
        canon[h] = id; send(MainchainEventKind::Extend, h, id, 0, {}); (void)fc.tick();
    };
    for (std::uint64_t h = 1; h <= 8; ++h) extend(h, own(h));
    const bool own_stays = (shape == Shape::OrphanOnly);
    if (shape == Shape::Direct) {
        extend(9, peer(9));
        extend(10, peer(10));
    } else {
        extend(9, peer(9));                                  // the peer's 9 arrives first: booked
        canon[9] = own(9);                                   // our own 9 (same height) replaces it
        send(MainchainEventKind::Orphan, 9, peer(9), 0, peer(9));
        send(MainchainEventKind::Reorg, 9, own(9), 1, {});
        if (shape == Shape::FlipFlopTicked) (void)fc.tick();
        if (!own_stays) {
            canon[9] = peer(9); canon[10] = peer(10);        // the peer's 10 (built on its 9) switches back
            send(MainchainEventKind::Orphan, 9, own(9), 0, own(9));
            send(MainchainEventKind::Reorg, 10, peer(10), 1, {});
        } else {
            canon[10] = own(10);                             // our branch keeps growing
            send(MainchainEventKind::Extend, 10, own(10), 0, {});
        }
        (void)fc.tick();
    }
    for (std::uint64_t h = 11; h <= 16; ++h) extend(h, own_stays ? own(h) : peer(h));
    for (int i = 0; i < 3; ++i) (void)fc.tick();
    r.digest = node.ledger().owed_digest();
    r.peer9_settled = node.ledger().is_settled(hex_of(peer(9)));
    r.own9_settled_or_pending = node.ledger().is_settled(hex_of(own(9))) || node.ledger().is_pending(hex_of(own(9)));
    r.own9_canonical_settled = node.ledger().is_settled(hex_of(own(9)));
    r.cursor = node.finalize_driver().cursor_height();
    r.orphaned = fc.stats().orphaned;
    r.late = fc.stats().late_unbooked;
    r.redelivered = node.reorg_redelivered();
    r.registered = fc.stats().registered;
    (void)fc.drain_before_stop();
    return r;
}

std::string d16(const ::v37::bytes32& d) { return hex_of(d).substr(0, 16); }

} // namespace

int main() {
    std::filesystem::path tmp = std::filesystem::temp_directory_path() / ("v37-xmr-race-rebook-" + std::to_string(::getpid()));
    std::filesystem::remove_all(tmp);
    std::filesystem::create_directories(tmp);
    std::printf("== v37_xmr_race_rebook_kat ==\n");

    const Result ref = run(Shape::Direct, tmp, "direct");
    check("R0 reference (followed the peer's branch directly): peer 9 SETTLED, cursor 13, nothing orphaned",
          ref.peer9_settled && !ref.own9_settled_or_pending && ref.cursor == 13 && ref.orphaned == 0,
          "cursor=" + std::to_string(ref.cursor) + " orphaned=" + std::to_string(ref.orphaned));

    const Result one = run(Shape::FlipFlopOneTick, tmp, "flipflop-onetick");
    check("R1 one-tick flip-flop (peer 9 -> own 9 -> peer 9 under peer 10, no tick between): the canonical peer 9 is RE-BOOKED and SETTLED, our own 9 never settles",
          one.peer9_settled && !one.own9_settled_or_pending && one.cursor == 13 && one.late == 0 && one.redelivered >= 1,
          "peer9_settled=" + std::to_string(one.peer9_settled) + " own9=" + std::to_string(one.own9_settled_or_pending) +
          " cursor=" + std::to_string(one.cursor) + " late=" + std::to_string(one.late) +
          " redelivered=" + std::to_string(one.redelivered) + " orphaned=" + std::to_string(one.orphaned));
    check("R2 ... and that node ends byte-identical to the direct follower (owed_digest equal)",
          one.digest == ref.digest, "flipflop=" + d16(one.digest) + " direct=" + d16(ref.digest));

    const Result tk = run(Shape::FlipFlopTicked, tmp, "flipflop-ticked");
    check("R3 control: the same flip-flop WITH a tick between the switches (FC30b shape) re-books peer 9, digest equal to the direct follower",
          tk.peer9_settled && !tk.own9_settled_or_pending && tk.cursor == 13 && tk.digest == ref.digest,
          "peer9_settled=" + std::to_string(tk.peer9_settled) + " digest=" + d16(tk.digest));

    const Result oo = run(Shape::OrphanOnly, tmp, "orphan-only");
    check("R4 a pending bid orphaned for good is still disposed ORPHANED by the tick (peer 9 never settles, own 9 settles, 1 orphaned, 0 late)",
          !oo.peer9_settled && oo.own9_canonical_settled && oo.orphaned == 1 && oo.late == 0 && oo.cursor == 13,
          "peer9_settled=" + std::to_string(oo.peer9_settled) + " own9_settled=" + std::to_string(oo.own9_canonical_settled) +
          " orphaned=" + std::to_string(oo.orphaned) + " cursor=" + std::to_string(oo.cursor));

    std::filesystem::remove_all(tmp);
    std::printf("== %s (%d failure(s)) ==\n", g_fail ? "FAIL" : "PASS", g_fail);
    return g_fail ? 1 : 0;
}
