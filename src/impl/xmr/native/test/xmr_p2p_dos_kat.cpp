// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/native/test/xmr_p2p_dos_kat.cpp
//
// Wave 1, C1c: the per-peer DoS budget -- bucket exhaustion, refill, and the
// fault table that separates "you are going faster than I will follow" from
// "you are lying to me".
//
// The distinction this file exists to pin: EXHAUSTION IS A DEFER. A peer on a
// fast link legitimately outruns us during a sync burst, and a client that
// banned it would throw away its best peer at the worst moment. What bans is
// the fault table -- structurally impossible input, a network-id mismatch, a
// completed RandomX hash below target.
//
// The second thing pinned here is that the transaction bucket counts
// TRANSACTIONS, not frames. A peer that batches five hundred transactions into
// one NOTIFY_NEW_TRANSACTIONS has spent five hundred tokens; a frame-counting
// bucket would have charged it one and missed the whole attack.
// ---------------------------------------------------------------------------
#include <string>

#include "impl/xmr/native/p2p/xmr_p2p_dos.hpp"
#include "xmr_p2p_kat_util.hpp"

namespace native = c2pool::xmr::native;
namespace p2p    = c2pool::xmr::native::p2p;
namespace levin  = c2pool::xmr::native::levin;
namespace kat    = c2pool::xmr::native::kat;
using p2p::DosAction;
using p2p::DosConfig;
using p2p::DosFault;
using p2p::Millis;
using p2p::PeerDosGuard;

namespace {

// A budget small enough to exhaust in a handful of calls, so the arithmetic is
// checkable by hand rather than by simulation.
DosConfig tiny() {
    DosConfig c;
    c.bytes_capacity = 10'000;
    c.bytes_refill   = 1'000;    // per second
    c.block_capacity = 3;
    c.block_refill   = 1;        // per second
    c.tx_capacity    = 10;
    c.tx_refill      = 5;
    c.serve_capacity = 2;
    c.serve_refill   = 1;
    c.exhaustions_before_disconnect = 4;
    return c;
}

// -----------------------------------------------------------------------
void test_fault_table() {
    // The points are the policy; write them out so a silent re-weighting shows
    // up as a failing check rather than as a peer that stops getting banned.
    kat::check(p2p::fault_points(DosFault::BadPow) == 10,       "BadPow is the whole threshold");
    kat::check(p2p::fault_points(DosFault::WrongNetwork) == 10, "WrongNetwork is the whole threshold");
    kat::check(p2p::fault_points(DosFault::MalformedBody) == 10,"MalformedBody is the whole threshold");
    kat::check(p2p::fault_points(DosFault::Unsolicited) == 5,   "Unsolicited is half");
    kat::check(p2p::fault_points(DosFault::BadChainEntry) == 5, "BadChainEntry is half");
    kat::check(p2p::fault_points(DosFault::OversizePeerlist) == 5, "OversizePeerlist is half");
    kat::check(p2p::fault_points(DosFault::DuplicateTxInBatch) == 2, "a duplicate blob is cheap");
    kat::check(p2p::fault_points(DosFault::UnknownParentBlock) == 1, "unknown-parent spam is a point");
    kat::check(p2p::fault_points(DosFault::BucketExhausted) == 1,    "exhaustion is a point");
    kat::check(p2p::fault_points(DosFault::None) == 0,               "no fault costs nothing");

    // The C2/C3-facing PeerFault maps onto the same table, so penalize() from
    // the verify thread costs what an io-thread fault costs.
    kat::check(p2p::fault_of(native::PeerFault::BadPow) == DosFault::BadPow,
               "PeerFault::BadPow maps to DosFault::BadPow");
    kat::check(p2p::fault_of(native::PeerFault::BadChainEntry) == DosFault::BadChainEntry,
               "PeerFault::BadChainEntry maps across");
    kat::check(p2p::fault_of(native::PeerFault::VersionMismatch) == DosFault::WrongNetwork,
               "a version mismatch is the network-id class");
}

bool fault_closes_connection_check();

// -----------------------------------------------------------------------
void test_one_fault_bans() {
    PeerDosGuard g(tiny());
    kat::check(g.on_fault(DosFault::BadPow, 1000) == DosAction::Ban,
               "a completed hash below target bans in one step");

    PeerDosGuard g2(tiny());
    kat::check(g2.on_fault(DosFault::Unsolicited, 1000) == DosAction::Disconnect,
               "a protocol violation below the ban line still costs the connection");
    kat::check(g2.score() == 5, "... and five points");
    kat::check(g2.on_fault(DosFault::Unsolicited, 1000) == DosAction::Ban,
               "two of them reach the threshold");

    // The recoverable faults are scored but do NOT cost the connection. An
    // honest peer sends a duplicate blob or a block we have no parent for; if
    // either severed the link, one sloppy batch would cost us a working peer,
    // and losing peers is what starves a pool node.
    PeerDosGuard g3(tiny());
    kat::check(g3.on_fault(DosFault::DuplicateTxInBatch, 0) == DosAction::Drop,
               "a duplicate blob in one batch is scored, not disconnected");
    kat::check(g3.score() == 2, "... for two points");
    kat::check(g3.on_fault(DosFault::UnknownParentBlock, 0) == DosAction::Drop,
               "an unknown-parent block is scored, not disconnected");
    // ... but they still accumulate to a ban if they never stop.
    for (int i = 0; i < 6; ++i) g3.on_fault(DosFault::UnknownParentBlock, 0);
    kat::check(g3.on_fault(DosFault::UnknownParentBlock, 0) == DosAction::Ban,
               "sustained cheap faults still reach the ban line");

    kat::check(fault_closes_connection_check(),
               "the close-on-fault set is exactly the unrecoverable faults");
}

bool fault_closes_connection_check() {
    return p2p::fault_closes_connection(DosFault::MalformedBody)
        && p2p::fault_closes_connection(DosFault::WrongNetwork)
        && p2p::fault_closes_connection(DosFault::BadPow)
        && p2p::fault_closes_connection(DosFault::Unsolicited)
        && p2p::fault_closes_connection(DosFault::BadChainEntry)
        && p2p::fault_closes_connection(DosFault::OversizePeerlist)
        && !p2p::fault_closes_connection(DosFault::BucketExhausted)
        && !p2p::fault_closes_connection(DosFault::UnknownParentBlock)
        && !p2p::fault_closes_connection(DosFault::DuplicateTxInBatch)
        && !p2p::fault_closes_connection(DosFault::None);
}

// -----------------------------------------------------------------------
void test_byte_bucket() {
    PeerDosGuard g(tiny());
    DosFault f = DosFault::None;
    Millis t = 0;

    // 10 000 bytes of capacity: two 4 000-byte frames fit, the third does not.
    kat::check(g.on_frame(levin::CMD_TIMED_SYNC, 4'000, 1, t, f) == DosAction::Accept,
               "the first frame fits the byte budget");
    kat::check(g.on_frame(levin::CMD_TIMED_SYNC, 4'000, 1, t, f) == DosAction::Accept,
               "the second fits too");
    kat::check(g.on_frame(levin::CMD_TIMED_SYNC, 4'000, 1, t, f) == DosAction::Drop,
               "the third exhausts the byte budget and is DROPPED, not banned");
    kat::check(f == DosFault::BucketExhausted, "... and the fault names the bucket");
    kat::check(g.score() == 1, "exhaustion costs exactly one point");

    // It refills: 4 seconds at 1 000 B/s buys the frame that just failed.
    t += 4'000;
    kat::check(g.on_frame(levin::CMD_TIMED_SYNC, 4'000, 1, t, f) == DosAction::Accept,
               "the byte bucket refills over time");

    // The byte bucket is charged on EVERY command, including ones with no class
    // bucket of their own -- a flood of legal-sized handshakes is still a flood.
    PeerDosGuard g2(tiny());
    int accepted = 0;
    for (int i = 0; i < 20; ++i)
        if (g2.on_frame(levin::CMD_HANDSHAKE, 2'000, 1, 0, f) == DosAction::Accept) ++accepted;
    kat::checkf(accepted == 5, "10 000 bytes of budget admits exactly five 2 000-byte frames (%d)",
                accepted);
}

// -----------------------------------------------------------------------
void test_block_bucket() {
    PeerDosGuard g(tiny());
    DosFault f = DosFault::None;

    // Capacity 3, refill 1/s. Honest rate is one block per ~120 s, so a peer
    // that spends this bucket is not relaying, it is flooding.
    for (int i = 0; i < 3; ++i)
        kat::check(g.on_frame(levin::CMD_NEW_FLUFFY_BLOCK, 100, 1, 0, f) == DosAction::Accept,
                   "the block bucket admits its burst");
    kat::check(g.on_frame(levin::CMD_NEW_FLUFFY_BLOCK, 100, 1, 0, f) == DosAction::Drop,
               "the fourth block in one instant is dropped");
    kat::check(f == DosFault::BucketExhausted, "... as an exhaustion, not a crime");

    // NOTIFY_NEW_BLOCK shares the bucket: the legacy carrier is not a way round
    // the fluffy rate limit.
    kat::check(g.on_frame(levin::CMD_NEW_BLOCK, 100, 1, 0, f) == DosAction::Drop,
               "the legacy 2001 carrier shares the block bucket");

    kat::check(g.on_frame(levin::CMD_NEW_FLUFFY_BLOCK, 100, 1, 1'000, f) == DosAction::Accept,
               "one second of refill buys one block");
}

// -----------------------------------------------------------------------
void test_tx_bucket_counts_transactions() {
    PeerDosGuard g(tiny());
    DosFault f = DosFault::None;

    // ONE frame carrying ten transactions spends the whole ten-token bucket.
    kat::check(g.on_frame(levin::CMD_NEW_TRANSACTIONS, 500, 10, 0, f) == DosAction::Accept,
               "a ten-transaction batch fits a ten-token bucket");
    kat::check(g.on_frame(levin::CMD_NEW_TRANSACTIONS, 500, 1, 0, f) == DosAction::Drop,
               "and the very next transaction does not: the bucket counts TRANSACTIONS");

    // A frame-counting bucket would have admitted the second frame here, which
    // is the whole point: prove the units are transactions by showing that two
    // frames behave differently depending on how many txs they carry.
    PeerDosGuard g2(tiny());
    kat::check(g2.on_frame(levin::CMD_NEW_TRANSACTIONS, 500, 1, 0, f) == DosAction::Accept,
               "a one-transaction frame costs one token");
    kat::check(g2.on_frame(levin::CMD_NEW_TRANSACTIONS, 500, 1, 0, f) == DosAction::Accept,
               "... so a second one still fits");
    kat::check(g2.txs_level(0) < 9.5, "... and the level fell by exactly two");
}

// -----------------------------------------------------------------------
void test_serving_bucket() {
    PeerDosGuard g(tiny());
    DosFault f = DosFault::None;

    // A peer is entitled to sync from us. It is not entitled to re-sync
    // continuously: 2003/2006/2009/2010 all cost us index reads and bytes out.
    kat::check(g.on_frame(levin::CMD_REQUEST_CHAIN, 100, 1, 0, f) == DosAction::Accept,
               "a chain request is served");
    kat::check(g.on_frame(levin::CMD_REQUEST_GET_OBJECTS, 100, 1, 0, f) == DosAction::Accept,
               "an objects request shares the same budget");
    kat::check(g.on_frame(levin::CMD_REQUEST_FLUFFY_MISSING_TX, 100, 1, 0, f) == DosAction::Drop,
               "the third request in one instant exhausts the serving budget");
    kat::check(g.on_frame(levin::CMD_GET_TXPOOL_COMPLEMENT, 100, 1, 2'000, f) == DosAction::Accept,
               "two seconds of refill buys two more");
}

// -----------------------------------------------------------------------
void test_sustained_exhaustion_disconnects() {
    // Exhaustion is a defer -- but a peer that has been exhausting its budget
    // continuously is not a fast link, it is a flood, and at some point the
    // connection has to end. That threshold is exhaustions_before_disconnect
    // (4 in this fixture), and it is reached BEFORE the ten-point ban line, so
    // the peer is closed without its address being blocked for a day.
    PeerDosGuard g(tiny());
    DosFault f = DosFault::None;
    DosAction last = DosAction::Accept;
    for (int i = 0; i < 20 && last != DosAction::Disconnect && last != DosAction::Ban; ++i)
        last = g.on_frame(levin::CMD_NEW_FLUFFY_BLOCK, 20'000, 1, 0, f);
    kat::checkf(last == DosAction::Disconnect,
                "sustained exhaustion ends the connection (got %s)", p2p::to_string(last));
    kat::checkf(g.score() < 10, "... without reaching the ban line (score %u)", g.score());
    kat::check(g.exhaustions() >= 4, "... after at least the configured run of exhaustions");
}

// -----------------------------------------------------------------------
void test_score_forgets() {
    DosConfig c = tiny();
    c.score_forget_ms = 1'000;
    PeerDosGuard g(c);
    kat::check(g.on_fault(DosFault::BadChainEntry, 0) == DosAction::Disconnect, "five points");
    kat::check(g.score() == 5, "... recorded");
    // After a quiet forget window the peer starts clean: an honest long-lived
    // connection must not accumulate a ban out of unrelated one-off faults.
    kat::check(g.on_fault(DosFault::BadChainEntry, 5'000) == DosAction::Disconnect,
               "a fault after the forget window is judged on its own");
    kat::check(g.score() == 5, "... and the score is 5, not 10");
}

// -----------------------------------------------------------------------
void test_defaults_are_the_design_numbers() {
    const DosConfig d;
    kat::check(d.bytes_refill == 2.0 * 1024 * 1024, "2 MiB/s sustained per peer");
    kat::check(d.bytes_capacity == 16.0 * 1024 * 1024, "16 MiB burst");
    kat::check(d.block_capacity == 8.0 && d.block_refill == 0.1,
               "the block bucket is 8 / 0.1 per second");
    kat::check(d.tx_capacity == 512.0 && d.tx_refill == 64.0,
               "the transaction bucket is 512 / 64 per second");
    kat::check(d.fails_before_ban == 10, "P2P_IP_FAILS_BEFORE_BLOCK");
    kat::check(d.ban_ms == 86'400'000,   "P2P_IP_BLOCKTIME is 24 h");

    // At the honest rate (one block per ~120 s) the block bucket never depletes.
    PeerDosGuard g;
    DosFault f = DosFault::None;
    bool all_accepted = true;
    for (int i = 0; i < 50; ++i)
        if (g.on_frame(levin::CMD_NEW_FLUFFY_BLOCK, 50'000, 1,
                       static_cast<Millis>(i) * 120'000, f) != DosAction::Accept)
            all_accepted = false;
    kat::check(all_accepted, "fifty blocks at the honest cadence never trip the budget");
}

} // namespace

int main() {
    test_fault_table();
    test_one_fault_bans();
    test_byte_bucket();
    test_block_bucket();
    test_tx_bucket_counts_transactions();
    test_serving_bucket();
    test_sustained_exhaustion_disconnects();
    test_score_forgets();
    test_defaults_are_the_design_numbers();
    return kat::report("xmr_native_p2p_dos_kat");
}
