// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/native/test/xmr_anchor_gate4_kat.cpp
//
// GATE 4: the anchor, confirmed against the network before the node serves.
//
// anchor/xmr_anchor_load.hpp's banner has always named this duty and named the
// function that discharges it; until this change nothing CALLED it, so an
// anchor was trusted by provenance alone. That is survivable for a release-
// pinned stagenet bundle the project minted itself and fatal for a mainnet
// bundle handed to a pool operator on the command line. What is pinned here is
// the wire-up, and specifically its REFUSALS -- a gate that has never been seen
// to refuse is not a gate.
//
// The four cases the wiring owes, each with a mock levin GET_OBJECTS peer so
// the answers are deterministic and no daemon is involved:
//
//   (a) A bundle whose height and id match the block a peer serves: CONFIRMS,
//       and only then does ChainBoot forward to the index and serve blocks.
//   (b) A TAMPERED bundle.id: the block the peer serves hashes to something
//       else. The id is recomputed here, never taken from the peer, so the
//       mismatch is visible; the gate refuses by exhaustion rather than by
//       believing the bundle.
//   (c) A TAMPERED bundle.height: the id still matches, so
//       anchor_confirmed_by_network() alone says yes -- and the block's OWN
//       height, read out of its coinbase, says no. REFUSED. This case is the
//       reason gate 4 is more than one `!=`, and it is checked in both
//       directions (the peer serving the right block at the wrong claimed
//       height, and the peer serving an entirely different block).
//   (d) NO PEER can serve the height within the window: REFUSED, both by
//       exhausting the peer set and by expiring the deadline. Fail-closed, not
//       silent-trust: an anchor nobody on this network holds is exactly the
//       shape a fabricated anchor takes.
//
// Plus the BOUND, because "refuse on exhaustion" is only meaningful if the
// asking stops: at most AnchorConfirmConfig::peers distinct peers are asked,
// each request carries exactly the anchor id, a silent peer's turn expires, and
// the whole gate has a wall deadline it cannot outlive.
//
// THE BLOCK BLOBS ARE BUILT HERE, not captured, because the anchor is at a
// height whose real block is 200 000 blocks of stagenet history away and the
// property under test is not "monerod's block parses" (xmr_native_node_kat
// pins that against a real genesis blob) but "the id and the height this gate
// judges come out of the BYTES". Every blob this file builds is round-tripped
// through the production parse_block() and block_identity() before it is used,
// so a builder bug is a failed check here rather than a test that proves
// nothing.
//
// STL, xmr_coin (keccak + tree hash for the block id) and boost's header-only
// multiprecision (the chain index's difficulty type). No RandomX, no sockets,
// no daemon: the ordinary ctest lane on both CI legs.
// ---------------------------------------------------------------------------
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <string>
#include <utility>
#include <vector>

#include "impl/xmr/native/anchor/xmr_anchor_codec.hpp"
#include "impl/xmr/native/anchor/xmr_anchor_load.hpp"
#include "impl/xmr/native/chain/xmr_chain_index.hpp"
#include "impl/xmr/native/consensus/xmr_block_id.hpp"
#include "impl/xmr/native/consensus/xmr_block_parse.hpp"
#include "impl/xmr/native/contracts/anchor.hpp"
#include "impl/xmr/native/contracts/fakes/fake_fetcher.hpp"
#include "impl/xmr/native/node/xmr_anchor_confirm.hpp"
#include "impl/xmr/native/node/xmr_chain_boot.hpp"
#include "impl/xmr/native/p2p/chain_seeds.hpp"
#include "xmr_p2p_kat_util.hpp"

namespace native = c2pool::xmr::native;
namespace rt     = c2pool::xmr::native::rt;
namespace kat    = c2pool::xmr::native::kat;

using native::AnchorBundle;
using native::BlockEntry;
using native::ChainEntry;
using native::Hash;
using native::PeerRef;
using native::PeerSyncData;
using native::U128;
using rt::AnchorConfirmConfig;
using rt::AnchorConfirmDriver;
using rt::AnchorConfirmState;
using rt::AnchorNetworkConfirm;

namespace {

// ===========================================================================
// 0. A Monero block blob, built from fields
//
// The layout is cryptonote_basic.h's, and it is the same one
// consensus/xmr_block_parse.hpp documents at the top of its own file:
//
//   varint major, varint minor, varint timestamp, prev_id[32], nonce[4] LE,
//   miner_tx (version 2 + RCTTypeNull from HF 12 on), varint tx_hash_count.
//
// Only what a coinbase needs is emitted: one txin_gen input carrying the
// height, one txout_to_tagged_key output, a tx_extra, and the single 0x00 rct
// type byte. Anything richer would be testing the parser rather than the gate.
// ===========================================================================
struct BlockSpec {
    std::uint64_t height    = 0;
    std::uint64_t timestamp = 1788965550;
    std::uint64_t major     = 16;
    std::uint64_t minor     = 16;
    std::uint32_t nonce     = 0x0badc0de;
    std::uint64_t reward    = 600000000000ull;
    std::uint8_t  flavour   = 0x11;   // varies the tx_extra, and so the id
};

void put_varint(std::vector<std::uint8_t>& out, std::uint64_t v) {
    native::blob_write_varint(out, v);
}

std::vector<std::uint8_t> build_block_blob(const BlockSpec& spec) {
    std::vector<std::uint8_t> b;

    // --- header --------------------------------------------------------------
    put_varint(b, spec.major);
    put_varint(b, spec.minor);
    put_varint(b, spec.timestamp);
    for (std::size_t i = 0; i < 32; ++i)                     // prev_id
        b.push_back(static_cast<std::uint8_t>((spec.height - 1 + i) ^ spec.flavour));
    b.push_back(static_cast<std::uint8_t>(spec.nonce & 0xff));
    b.push_back(static_cast<std::uint8_t>((spec.nonce >> 8) & 0xff));
    b.push_back(static_cast<std::uint8_t>((spec.nonce >> 16) & 0xff));
    b.push_back(static_cast<std::uint8_t>((spec.nonce >> 24) & 0xff));

    // --- miner_tx ------------------------------------------------------------
    put_varint(b, 2);                                        // version
    put_varint(b, spec.height + 60);                         // unlock_time
    put_varint(b, 1);                                        // one input
    b.push_back(native::TX_IN_GEN);
    put_varint(b, spec.height);                              // THE height gate 4 reads
    put_varint(b, 1);                                        // one output
    put_varint(b, spec.reward);
    b.push_back(native::TX_OUT_TO_TAGGED_KEY);
    for (std::size_t i = 0; i < 33; ++i)                     // key + view tag
        b.push_back(static_cast<std::uint8_t>((i * 7u) ^ spec.flavour));
    {
        std::vector<std::uint8_t> extra;
        extra.push_back(0x01);                               // TX_EXTRA_TAG_PUBKEY
        for (std::size_t i = 0; i < 32; ++i)
            extra.push_back(static_cast<std::uint8_t>((i * 3u) + spec.flavour));
        put_varint(b, extra.size());
        b.insert(b.end(), extra.begin(), extra.end());
    }
    b.push_back(0x00);                                       // rct type NULL

    // --- tx_hashes -----------------------------------------------------------
    put_varint(b, 0);
    return b;
}

// Round-tripped through the PRODUCTION parser and hasher, so nothing below
// rests on the builder being right by inspection.
bool blob_facts(const std::vector<std::uint8_t>& blob, Hash& id, std::uint64_t& height) {
    native::ParsedBlock pb;
    if (native::parse_block(blob, pb) != native::BlockParseStatus::Ok) return false;
    native::CoinbaseFields cb;
    if (!native::parse_coinbase_fields(blob.data(), pb, cb)) return false;
    id     = native::block_identity(blob.data(), pb).id;
    height = cb.height;
    return true;
}

BlockEntry entry_of(const std::vector<std::uint8_t>& blob) {
    BlockEntry e;
    e.block_blob = blob;
    return e;
}

// ===========================================================================
// 0b. A valid stagenet bundle at the model height, with the id we choose
//
// Same shape as the trust-anchor KAT's synthetic bundle (real stagenet height
// and fork version, so the hard-fork table is exercised for real), except that
// `id` is the id of a block this file BUILT -- which is the whole point: the
// network confirm has to be able to succeed, not only to refuse.
// ===========================================================================
constexpr std::uint64_t kAnchorHeight = 2204000;

Hash model_hash(std::uint64_t seed, std::uint8_t tag) {
    Hash h{};
    for (std::size_t i = 0; i < 8; ++i) h[i] = static_cast<std::uint8_t>(seed >> (8 * i));
    for (std::size_t i = 8; i < h.size(); ++i) h[i] = static_cast<std::uint8_t>(tag + i);
    return h;
}

AnchorBundle make_bundle(std::uint64_t height, const Hash& id) {
    AnchorBundle b;
    b.network       = "stagenet";
    b.height        = height;
    b.id            = id;
    b.prev_id       = model_hash(height - 1, 0x10);
    b.timestamp     = 1788965550;
    b.major_version = 16;
    b.cumulative_difficulty.hi = 0;
    b.cumulative_difficulty.lo = 0xc3772e00dbull;
    b.already_generated_coins  = 18163913490712907281ull;

    const std::uint64_t seed_h = native::rx_seedheight(b.height + 1);
    b.seed_ids.emplace_back(seed_h, model_hash(seed_h, 0x20));

    U128 cd{};
    cd.lo = 0xc2cb6d9d38ull;
    for (std::size_t i = 0; i < native::ANCHOR_DIFFICULTY_WINDOW; ++i) {
        b.difficulty_window.emplace_back(1788876380ull + i * 37ull, cd);
        cd = native::u128_add(cd, U128{0, 3766353ull});
    }
    for (std::size_t i = 0; i < native::ANCHOR_SHORT_TERM_WEIGHTS; ++i)
        b.short_term_weights.push_back(87ull + (i % 5));
    b.long_term_weights.assign(native::ANCHOR_LONG_TERM_WEIGHTS, 176470ull);
    b.monerod_checkpoints.emplace_back(b.height + 4096, model_hash(b.height + 4096, 0x30));
    b.digest = native::anchor_digest(b);
    return b;
}

// The bundle on disk, which is the shape --native-anchor-path hands the node.
bool write_bundle(const std::string& path, const AnchorBundle& b) {
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    if (!f) return false;
    f << native::write_anchor_inc(b, "gate-4 KAT bundle");
    return static_cast<bool>(f);
}

native::ChainIndexOptions stagenet_options() {
    native::ChainIndexOptions o;
    o.net         = native::XmrNet::Stagenet;
    o.require_pow = false;    // this KAT is about the gate, not about hashes
    return o;
}

PeerRef peer(const char* addr, std::uint64_t id) {
    PeerRef p;
    p.addr    = addr;
    p.peer_id = id;
    return p;
}

// ===========================================================================
// 1. The builder, pinned before anything rests on it
// ===========================================================================
void test_blob_builder() {
    BlockSpec spec;
    spec.height = kAnchorHeight;
    const std::vector<std::uint8_t> blob = build_block_blob(spec);

    Hash id{};
    std::uint64_t h = 0;
    kat::check(blob_facts(blob, id, h),
               "the built block blob parses with the production parse_block()");
    kat::checkf(h == kAnchorHeight,
                "the coinbase txin_gen height reads back as %llu, got %llu",
                (unsigned long long)kAnchorHeight, (unsigned long long)h);

    // Two blocks that differ only in a tx_extra byte must have different ids,
    // or every "the peer served a different block" case below would be vacuous.
    BlockSpec other = spec;
    other.flavour = 0x22;
    Hash id2{};
    std::uint64_t h2 = 0;
    kat::check(blob_facts(build_block_blob(other), id2, h2), "the variant parses too");
    kat::check(id != id2, "two different blocks at the same height have different ids");
    kat::check(h2 == kAnchorHeight, "and the variant is still at the same height");

    // The id is a function of the bytes: the same bytes twice give the same id.
    Hash again{};
    std::uint64_t hagain = 0;
    kat::check(blob_facts(blob, again, hagain) && again == id,
               "the block id is derived from the blob, deterministically");
}

// ===========================================================================
// 2. AnchorNetworkConfirm on its own: the judgement, all four outcomes
// ===========================================================================
void test_confirm_judgement() {
    BlockSpec spec;
    spec.height = kAnchorHeight;
    const std::vector<std::uint8_t> blob = build_block_blob(spec);
    Hash real_id{};
    std::uint64_t real_h = 0;
    kat::check(blob_facts(blob, real_id, real_h), "fixture blob is sane");

    // --- disarmed: the genesis path must not be affected at all --------------
    {
        AnchorNetworkConfirm c;
        kat::check(!c.armed(), "a fresh confirm is disarmed");
        kat::check(c.ready(), "a DISARMED gate is ready: the genesis boot path is untouched");
        kat::check(c.state() == AnchorConfirmState::Disarmed, "and says so");
        kat::check(!c.offer_blob(blob), "a disarmed gate has no opinion about a blob");
    }

    // --- (a) the honest case -------------------------------------------------
    {
        AnchorNetworkConfirm c;
        c.arm(make_bundle(kAnchorHeight, real_id));
        kat::check(c.armed() && c.state() == AnchorConfirmState::Pending,
                   "arming an anchor leaves the gate PENDING");
        kat::check(!c.ready(), "a pending gate is NOT ready: nothing may be served yet");
        kat::check(c.wanted() == real_id && c.wanted_height() == kAnchorHeight,
                   "the gate asks for exactly the id and height the bundle pinned");
        kat::check(c.offer_blob(blob), "the matching block SETTLES the gate");
        kat::check(c.state() == AnchorConfirmState::Confirmed,
                   "a correct bundle whose height and id match a served block CONFIRMS");
        kat::check(c.ready(), "and only then is the node ready to serve");
        const AnchorNetworkConfirm::Stats s = c.stats();
        kat::check(s.served_id == real_id && s.served_height == kAnchorHeight,
                   "the confirmation records the id it RECOMPUTED and the height it READ");
        kat::check(s.foreign == 0, "no foreign blob was counted on the honest path");
    }

    // --- (b) a tampered bundle.id -------------------------------------------
    {
        Hash tampered = real_id;
        tampered[0] = static_cast<std::uint8_t>(tampered[0] ^ 0x01);
        AnchorNetworkConfirm c;
        c.arm(make_bundle(kAnchorHeight, tampered));
        kat::check(!c.offer_blob(blob),
                   "the block the network serves hashes to the REAL id, not the tampered "
                   "one, so it does not settle the gate in the bundle's favour");
        kat::check(c.state() == AnchorConfirmState::Pending, "the gate is still waiting");
        kat::check(!c.ready(), "and is emphatically not ready");
        kat::check(c.stats().foreign == 1, "the mismatch is counted, not ignored");
        c.refuse_exhausted(4);
        kat::check(c.state() == AnchorConfirmState::Refused,
                   "a tampered bundle.id ends in REFUSED once the peer set is exhausted");
        kat::check(!c.ready(), "a refused gate never becomes ready");
        kat::check(c.stats().why.find("not one served it") != std::string::npos,
                   "and the refusal says what was asked and what came back");
    }

    // --- (c) a tampered bundle.height ---------------------------------------
    // The id still matches, so anchor_confirmed_by_network() on its own is
    // satisfied. The block's own coinbase height is what refuses.
    {
        std::string why;
        AnchorBundle probe = make_bundle(kAnchorHeight + 1, real_id);
        kat::check(native::anchor_confirmed_by_network(probe, real_id, why),
                   "the pinned id comparison alone CANNOT see a tampered height "
                   "(which is why gate 4 also reads the block's own height)");

        AnchorNetworkConfirm c;
        c.arm(probe);
        kat::check(c.offer_blob(blob), "the served block settles the gate");
        kat::check(c.state() == AnchorConfirmState::Refused,
                   "a tampered bundle.height is REFUSED");
        kat::check(!c.ready(), "and the node may not serve");
        const AnchorNetworkConfirm::Stats s = c.stats();
        kat::checkf(s.served_height == kAnchorHeight,
                    "the refusal records the height the block really is at (%llu)",
                    (unsigned long long)s.served_height);
        kat::check(s.why.find("but the bundle pins") != std::string::npos,
                   "and names both heights so an operator can see the lie");
    }

    // --- (c') the other spelling: the peer serves a DIFFERENT-id block -------
    {
        BlockSpec other = spec;
        other.flavour = 0x55;
        const std::vector<std::uint8_t> other_blob = build_block_blob(other);
        AnchorNetworkConfirm c;
        c.arm(make_bundle(kAnchorHeight, real_id));
        kat::check(!c.offer_blob(other_blob),
                   "a different block at the same height does not confirm the anchor");
        kat::check(c.state() == AnchorConfirmState::Pending, "it is foreign, not fatal");
        kat::check(c.stats().foreign == 1, "and it is counted");
    }

    // --- garbage, and a missed id -------------------------------------------
    {
        AnchorNetworkConfirm c;
        c.arm(make_bundle(kAnchorHeight, real_id));
        kat::check(!c.offer_blob({}), "an empty blob settles nothing");
        kat::check(!c.offer_blob({0x01, 0x02, 0x03}), "an unparseable blob settles nothing");
        kat::check(c.state() == AnchorConfirmState::Pending,
                   "garbage cannot push the gate either way");
        c.note_missed("203.0.113.7:38080");
        kat::check(c.stats().peers_spent == 1,
                   "a peer that reports the anchor id MISSED is spent");
        kat::check(c.state() == AnchorConfirmState::Pending,
                   "one peer missing it is not yet exhaustion");
    }
}

// ===========================================================================
// 3. The DRIVER: the fetch is bounded, and (d) exhaustion/deadline refuse
// ===========================================================================
void test_driver_bound() {
    BlockSpec spec;
    spec.height = kAnchorHeight;
    const std::vector<std::uint8_t> blob = build_block_blob(spec);
    Hash real_id{};
    std::uint64_t real_h = 0;
    kat::check(blob_facts(blob, real_id, real_h), "fixture blob is sane");

    // A mock levin GET_OBJECTS peer set: five handshaked peers, none of which
    // will answer unless this test hands the answer back.
    auto make_peers = [](std::size_t n) {
        std::vector<std::pair<PeerRef, PeerSyncData>> t;
        for (std::size_t i = 0; i < n; ++i) {
            char buf[32];
            std::snprintf(buf, sizeof(buf), "198.51.100.%zu:38080", i + 1);
            t.emplace_back(peer(buf, 1000 + i), PeerSyncData{});
        }
        return t;
    };

    // --- (d1) exhaustion: every peer asked, nobody served --------------------
    {
        native::fakes::FakeFetcher f;
        f.peer_table = make_peers(5);
        AnchorNetworkConfirm c;
        c.arm(make_bundle(kAnchorHeight, real_id));

        std::uint64_t now = 0;
        AnchorConfirmConfig cfg;
        cfg.peers       = 3;
        cfg.per_peer_ms = 1000;
        cfg.timeout_ms  = 1'000'000;      // deliberately huge: EXHAUSTION must fire first
        AnchorConfirmDriver drv(f, c, cfg, [&now] { return now; });

        AnchorConfirmState st = drv.poll();
        kat::check(st == AnchorConfirmState::Pending, "the first poll asks a peer");
        kat::check(f.object_requests.size() == 1, "exactly one request, to one peer");
        kat::check(drv.poll() == AnchorConfirmState::Pending && f.object_requests.size() == 1,
                   "a second poll inside the peer's turn does NOT re-ask: the gate is "
                   "bounded in requests, not only in time");

        now += cfg.per_peer_ms;
        kat::check(drv.poll() == AnchorConfirmState::Pending && f.object_requests.size() == 2,
                   "a silent peer's turn expires and the next peer is asked");
        now += cfg.per_peer_ms;
        kat::check(drv.poll() == AnchorConfirmState::Pending && f.object_requests.size() == 3,
                   "and the third");
        now += cfg.per_peer_ms;
        st = drv.poll();
        kat::check(st == AnchorConfirmState::Refused,
                   "(d) no peer served the anchor within the window: REFUSED, not "
                   "silently trusted");
        kat::checkf(f.object_requests.size() == 3,
                    "the fetch is BOUNDED: %zu requests for a 3-peer budget, and two "
                    "handshaked peers were never asked",
                    f.object_requests.size());
        kat::check(!c.ready(), "a refused gate leaves the node unable to serve");
        kat::check(c.stats().why.find("fail-closed") != std::string::npos,
                   "the refusal says out loud that it is fail-closed");

        // Every request was for exactly the anchor id, and nothing else.
        bool shape_ok = true;
        for (const native::fakes::FakeFetcher::ObjectsReq& r : f.object_requests)
            if (r.ids.size() != 1 || r.ids[0] != real_id || r.prune) shape_ok = false;
        kat::check(shape_ok,
                   "every GET_OBJECTS carries exactly the anchor id, unpruned");
        kat::check(f.chain_requests.empty(),
                   "the gate asks for the BLOCK, not for a chain: no locator walk, no "
                   "cold-start cost beyond the anchor's age");

        kat::check(drv.poll() == AnchorConfirmState::Refused,
                   "polling a settled gate is idempotent");
    }

    // --- (d2) the deadline: no peer ever appears -----------------------------
    {
        native::fakes::FakeFetcher f;             // no peers at all
        AnchorNetworkConfirm c;
        c.arm(make_bundle(kAnchorHeight, real_id));

        std::uint64_t now = 0;
        AnchorConfirmConfig cfg;
        cfg.peers      = 4;
        cfg.timeout_ms = 5000;
        AnchorConfirmDriver drv(f, c, cfg, [&now] { return now; });

        kat::check(drv.poll() == AnchorConfirmState::Pending,
                   "with nobody to ask the gate waits rather than passing");
        now = 4999;
        kat::check(drv.poll() == AnchorConfirmState::Pending, "still inside the deadline");
        now = 5000;
        kat::check(drv.poll() == AnchorConfirmState::Refused,
                   "(d) the deadline expires as a REFUSAL: an unreachable network cannot "
                   "confirm a trust root, and starting anyway is the posture gate 4 removes");
        kat::check(f.object_requests.empty(), "and nothing was ever asked");
        kat::check(c.stats().why.find("5000 ms") != std::string::npos,
                   "the refusal names the deadline it expired");
    }

    // --- a peer that goes away mid-turn loses its slot ------------------------
    {
        native::fakes::FakeFetcher f;
        f.peer_table = make_peers(2);
        AnchorNetworkConfirm c;
        c.arm(make_bundle(kAnchorHeight, real_id));
        std::uint64_t now = 0;
        AnchorConfirmConfig cfg;
        cfg.peers       = 2;
        cfg.per_peer_ms = 100000;         // its turn would never expire on time
        cfg.timeout_ms  = 1'000'000;
        AnchorConfirmDriver drv(f, c, cfg, [&now] { return now; });
        kat::check(drv.poll() == AnchorConfirmState::Pending && f.object_requests.size() == 1,
                   "peer one is asked");
        f.peer_table.erase(f.peer_table.begin());   // it disconnects
        now += 10;
        kat::check(drv.poll() == AnchorConfirmState::Pending && f.object_requests.size() == 2,
                   "a peer that disconnects does not hold the gate hostage for its whole turn");
        kat::check(c.stats().peers_spent >= 1, "and it is counted as spent");
    }

    // --- (a) through the driver: one honest peer settles it -------------------
    {
        native::fakes::FakeFetcher f;
        f.peer_table = make_peers(4);
        AnchorNetworkConfirm c;
        c.arm(make_bundle(kAnchorHeight, real_id));
        std::uint64_t now = 0;
        AnchorConfirmConfig cfg;
        AnchorConfirmDriver drv(f, c, cfg, [&now] { return now; });
        kat::check(drv.poll() == AnchorConfirmState::Pending, "peer one is asked");
        kat::check(c.offer_blob(blob), "peer one answers with the anchor block");
        kat::check(drv.poll() == AnchorConfirmState::Confirmed,
                   "(a) the gate confirms and the driver stops asking");
        kat::check(f.object_requests.size() == 1,
                   "one honest answer is enough: no further peers are troubled");
    }
}

// ===========================================================================
// 4. ChainBoot end to end: the bundle on disk, the gate, and what is withheld
// ===========================================================================
void boot_case(const char* label, std::uint64_t bundle_height, std::uint8_t id_xor,
               bool expect_confirm) {
    BlockSpec spec;
    spec.height = kAnchorHeight;
    const std::vector<std::uint8_t> blob = build_block_blob(spec);
    Hash real_id{};
    std::uint64_t real_h = 0;
    if (!blob_facts(blob, real_id, real_h)) { kat::check(false, "fixture blob is sane"); return; }

    Hash bundle_id = real_id;
    bundle_id[0] = static_cast<std::uint8_t>(bundle_id[0] ^ id_xor);

    const std::string path = std::string("gate4_kat_") + label + ".inc";
    if (!write_bundle(path, make_bundle(bundle_height, bundle_id))) {
        kat::check(false, "the KAT can write its bundle");
        return;
    }

    native::NoPowSource pow;
    native::ChainIndex  index(stagenet_options(), pow);
    rt::ChainBoot       boot(index, rt::BootMode::Anchor,
                             native::p2p::genesis_id(native::p2p::XmrNet::Stagenet),
                             native::XmrNet::Stagenet);

    std::string why;
    const bool booted = boot.boot_from_anchor(path, native::XmrNet::Stagenet, {}, why);
    std::remove(path.c_str());
    kat::checkf(booted, "%s: gates 1..3 accept the bundle (%s)", label, why.c_str());
    if (!booted) return;

    kat::checkf(boot.booted(), "%s: the anchor is INSTALLED", label);
    kat::checkf(!boot.serving_ready(),
                "%s: installed is NOT trusted -- gate 4 is pending and the node is not "
                "ready to serve", label);
    kat::checkf(boot.stats().anchor.state == AnchorConfirmState::Pending,
                "%s: and the status line says pending", label);

    // What a peer can get out of us while the anchor is unconfirmed.
    const PeerSyncData sd = boot.our_sync_data();
    kat::checkf(sd.current_height == bundle_height + 1,
                "%s: our_sync_data stays TRUTHFUL while pending (a handshake is a "
                "precondition of the fetch this gate needs)", label);
    kat::checkf(!boot.get_block_entry(bundle_id, false).has_value(),
                "%s: we serve no block off an unconfirmed anchor", label);
    kat::checkf(!boot.find_supplement({bundle_id}).has_value(),
                "%s: and we splice no peer onto it", label);

    {
        ChainEntry e;
        e.start_height = bundle_height;
        e.total_height = bundle_height + 10;
        e.ids.push_back(bundle_id);
        boot.on_chain_entry(peer("198.51.100.9:38080", 77), std::move(e));
        kat::checkf(boot.stats().dropped_unconfirmed >= 1,
                    "%s: inbound chain entries are DROPPED, not fed to the index, while "
                    "the anchor is unconfirmed", label);
    }

    // The mock peer answers our GET_OBJECTS with the real block.
    std::vector<BlockEntry> blocks;
    blocks.push_back(entry_of(blob));
    boot.on_objects(peer("198.51.100.1:38080", 1001), std::move(blocks), {}, bundle_height + 10);

    const rt::ChainBoot::Stats s = boot.stats();
    if (expect_confirm) {
        kat::checkf(s.anchor.state == AnchorConfirmState::Confirmed,
                    "%s: the network CONFIRMS the anchor (%s)", label, s.anchor.why.c_str());
        kat::checkf(boot.serving_ready(), "%s: and only now may the node serve", label);
        // The withholding stops: a chain entry that would have been dropped a
        // moment ago is now forwarded to the index.
        const std::uint64_t dropped_before = s.dropped_unconfirmed;
        {
            ChainEntry e;
            e.start_height = bundle_height;
            e.total_height = bundle_height + 10;
            e.ids.push_back(bundle_id);
            boot.on_chain_entry(peer("198.51.100.9:38080", 77), std::move(e));
        }
        kat::checkf(boot.stats().dropped_unconfirmed == dropped_before,
                    "%s: once confirmed, inbound is forwarded rather than dropped", label);
    } else {
        kat::checkf(s.anchor.state != AnchorConfirmState::Confirmed,
                    "%s: the network does NOT confirm this anchor", label);
        kat::checkf(!boot.serving_ready(),
                    "%s: so the node stays unable to serve (fail-closed)", label);
    }
}

void test_chain_boot_gate() {
    // (a) height and id both match the served block.
    boot_case("ok", kAnchorHeight, 0x00, /*expect_confirm=*/true);
    // (b) a tampered bundle.id: the served block hashes to something else.
    boot_case("bad_id", kAnchorHeight, 0x01, /*expect_confirm=*/false);
    // (c) a tampered bundle.height: the id matches, the coinbase height does not.
    boot_case("bad_height", kAnchorHeight + 1, 0x00, /*expect_confirm=*/false);

    // (c) refused, explicitly: the state is REFUSED rather than merely not-yet.
    {
        BlockSpec spec;
        spec.height = kAnchorHeight;
        const std::vector<std::uint8_t> blob = build_block_blob(spec);
        Hash real_id{};
        std::uint64_t real_h = 0;
        kat::check(blob_facts(blob, real_id, real_h), "fixture blob is sane");

        const std::string path = "gate4_kat_refuse.inc";
        kat::check(write_bundle(path, make_bundle(kAnchorHeight + 1, real_id)),
                   "the KAT can write its bundle");
        native::NoPowSource pow;
        native::ChainIndex  index(stagenet_options(), pow);
        rt::ChainBoot       boot(index, rt::BootMode::Anchor,
                                 native::p2p::genesis_id(native::p2p::XmrNet::Stagenet),
                                 native::XmrNet::Stagenet);
        std::string why;
        const bool ok = boot.boot_from_anchor(path, native::XmrNet::Stagenet, {}, why);
        std::remove(path.c_str());
        kat::checkf(ok, "the tampered-height bundle still passes gates 1..3 (%s)", why.c_str());
        if (!ok) return;

        std::vector<BlockEntry> blocks;
        blocks.push_back(entry_of(blob));
        boot.on_objects(peer("198.51.100.1:38080", 1001), std::move(blocks), {},
                        kAnchorHeight + 11);
        kat::check(boot.stats().anchor.state == AnchorConfirmState::Refused,
                   "a tampered bundle.height is REFUSED at the boot, not left pending");
        kat::check(!boot.serving_ready(), "and the node never becomes ready");

        // A later honest answer cannot rescue a refused gate.
        std::vector<BlockEntry> again;
        again.push_back(entry_of(blob));
        boot.on_objects(peer("198.51.100.2:38080", 1002), std::move(again), {},
                        kAnchorHeight + 11);
        kat::check(boot.stats().anchor.state == AnchorConfirmState::Refused,
                   "a refusal is terminal");
    }

    // A MISSED id routed through ChainBoot marks the peer spent -- case (d)'s
    // real wire shape, since monerod answers a 2003 for a block it does not hold
    // by naming the id in missed_ids.
    {
        BlockSpec spec;
        spec.height = kAnchorHeight;
        const std::vector<std::uint8_t> blob = build_block_blob(spec);
        Hash real_id{};
        std::uint64_t real_h = 0;
        kat::check(blob_facts(blob, real_id, real_h), "fixture blob is sane");
        Hash phantom = real_id;
        phantom[1] = static_cast<std::uint8_t>(phantom[1] ^ 0x80);

        const std::string path = "gate4_kat_missed.inc";
        kat::check(write_bundle(path, make_bundle(kAnchorHeight, phantom)),
                   "the KAT can write its bundle");
        native::NoPowSource pow;
        native::ChainIndex  index(stagenet_options(), pow);
        rt::ChainBoot       boot(index, rt::BootMode::Anchor,
                                 native::p2p::genesis_id(native::p2p::XmrNet::Stagenet),
                                 native::XmrNet::Stagenet);
        std::string why;
        const bool ok = boot.boot_from_anchor(path, native::XmrNet::Stagenet, {}, why);
        std::remove(path.c_str());
        kat::checkf(ok, "a bundle naming a block nobody has still passes gates 1..3 (%s)",
                    why.c_str());
        if (!ok) return;

        std::vector<Hash> missed;
        missed.push_back(phantom);
        boot.on_objects(peer("198.51.100.3:38080", 1003), {}, std::move(missed),
                        kAnchorHeight + 11);
        const rt::ChainBoot::Stats s = boot.stats();
        kat::check(s.anchor.peers_spent == 1,
                   "a peer that reports the anchor id MISSED is spent, which is how (d) "
                   "reaches exhaustion on the real wire");
        kat::check(s.anchor.state == AnchorConfirmState::Pending,
                   "one miss is not yet a refusal");
        kat::check(!boot.serving_ready(), "and nothing is served meanwhile");
    }
}

// ===========================================================================
// 5. The genesis path is untouched
// ===========================================================================
void test_genesis_path_unchanged() {
    native::NoPowSource pow;
    native::ChainIndexOptions o;
    o.net         = native::XmrNet::Regtest;
    o.require_pow = false;
    native::ChainIndex index(o, pow);
    rt::ChainBoot      boot(index, rt::BootMode::Genesis, native::p2p::MAINNET_GENESIS,
                            native::XmrNet::Regtest);

    kat::check(!boot.booted(), "a genesis boot starts un-booted");
    kat::check(!boot.serving_ready(), "and is not ready to serve");
    kat::check(boot.stats().anchor.state == AnchorConfirmState::Disarmed,
               "gate 4 is DISARMED on the genesis path: it has nothing to confirm");
    kat::check(boot.our_sync_data().top_id == native::p2p::MAINNET_GENESIS,
               "the pre-boot advertisement is unchanged");
    kat::check(boot.find_supplement({native::p2p::MAINNET_GENESIS}).has_value(),
               "and so is the pre-boot supplement");
}

// ===========================================================================
// 6. The duty is quoted where it is discharged
// ===========================================================================
void test_duty_is_quoted() {
    const std::string duty = native::anchor_boot_duty();
    kat::check(duty.find("anchor_confirmed_by_network") != std::string::npos,
               "the loader still names the function the boot owes");
    kat::check(duty.find("refuse to start") != std::string::npos,
               "and still says the answer to a failure is to refuse to start");
}

}  // namespace

int main() {
    test_blob_builder();
    test_confirm_judgement();
    test_driver_bound();
    test_chain_boot_gate();
    test_genesis_path_unchanged();
    test_duty_is_quoted();
    return kat::report("xmr_native_anchor_gate4_kat");
}
