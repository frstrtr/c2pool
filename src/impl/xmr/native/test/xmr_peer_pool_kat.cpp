// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/native/test/xmr_peer_pool_kat.cpp
//
// Wave 1, C1c: the pool driven against hand-rolled monerod stand-ins on
// loopback. What is proven here is the wiring the pure KATs cannot reach:
//
//   * the pool DIALS what the plan chose, handshakes, and promotes the address
//     to white in its own store;
//   * a peerlist arriving inside the handshake response is LEARNED, which is
//     the only address discovery Monero has (no addr gossip, no getaddr);
//   * IChainFetcher::request_objects CHUNKS a span into <= 100-id requests --
//     monerod drops a 2003 carrying more, and
//     encode_request_get_objects() refuses to build one -- and REASSEMBLES the
//     answers into exactly one on_objects() per span, so C2 sees the span it
//     planned;
//   * IChainFetcher::request_chain always puts the GENESIS ID last, even when
//     the caller hands it a locator that does not;
//   * the SERVING side answers a peer's 2006 and 2003 out of IChainServing --
//     the state_normal obligation, without which a monerod peer drops us in
//     ~20 s and the node starves in silence;
//   * a pushed fluffy block reaches the index and IBroadcastPort reaches the
//     peers.
//
// THE FOURTH C1-LENS FACT is asserted here as well as in C1b, from the other
// side: every stand-in answers with return_code = 1 (RC_HANDLER_OK), exactly as
// a real monerod does, because epee copies the handler's own return value into
// the response header and every monerod handler ends in `return 1`. A matcher
// that insisted on LEVIN_OK (0) would refuse every honest daemon on the
// network. The live run below prints the return code it actually received.
//
// --live <host>:<port> dials a REAL daemon: handshake, peerlist, one
// NOTIFY_REQUEST_CHAIN with a genesis-terminated locator, then disconnect. It
// is read-only, costs the daemon one connection and a few hundred bytes, and is
// deliberately NOT what ctest runs.
// ---------------------------------------------------------------------------
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <memory>
#include <thread>
#include <string>
#include <vector>

#include <boost/asio.hpp>

#include "impl/xmr/native/contracts/fakes/fake_chain.hpp"
#include "impl/xmr/native/contracts/fakes/fake_txpool.hpp"
#include "impl/xmr/native/p2p/xmr_peer_pool.hpp"
#include "xmr_p2p_kat_util.hpp"

namespace native = c2pool::xmr::native;
namespace p2p    = c2pool::xmr::native::p2p;
namespace levin  = c2pool::xmr::native::levin;
namespace kat    = c2pool::xmr::native::kat;
namespace asio   = boost::asio;
using tcp  = asio::ip::tcp;
using native::Hash;

namespace {

constexpr std::uint64_t STANDIN_PEER_ID = 0x00c0ffee00c0ffeeull;

Hash hash_of_byte(std::uint8_t v) { Hash h{}; h.fill(v); return h; }

// ---------------------------------------------------------------------------
// A stand-in monerod: accepts one connection, answers the handshake with
// return_code = 1, and can be scripted to answer 2006/2003 or push traffic.
// ---------------------------------------------------------------------------
class StandinDaemon {
public:
    explicit StandinDaemon(asio::io_context& io)
        : io_(io), acc_(io, tcp::endpoint(asio::ip::make_address("127.0.0.1"), 0)), sock_(io) {
        acc_.listen();
        accept();
    }

    std::uint16_t port() const { return acc_.local_endpoint().port(); }
    std::string   key()  const { return "127.0.0.1:" + std::to_string(port()); }

    // Scripted behaviour.
    bool answer_chain   = true;
    bool answer_objects = true;
    std::vector<levin::PeerlistEntry> peerlist;
    native::PeerSyncData sync = default_sync();

    // Observed.
    std::vector<std::uint32_t>                commands;
    std::vector<std::vector<std::uint8_t>>    bodies;
    bool connected = false;

    std::size_t count(std::uint32_t cmd) const {
        std::size_t n = 0;
        for (std::uint32_t c : commands) if (c == cmd) ++n;
        return n;
    }

    void push_fluffy_block(const Hash& id, std::uint64_t height) {
        levin::NewBlock nb;
        nb.b.block_blob.assign(64, 0x11);
        nb.b.block_blob[0] = id[0];
        nb.current_blockchain_height = height;
        std::vector<std::uint8_t> body;
        levin::MessageError err = levin::MessageError::None;
        if (!levin::encode_new_fluffy_block(nb, body, err)) return;
        write(levin::make_notify(levin::CMD_NEW_FLUFFY_BLOCK, body));
    }

    void push_transactions(std::size_t n, bool duplicate_one = false) {
        levin::NewTransactions m;
        for (std::size_t i = 0; i < n; ++i)
            m.txs.push_back(std::vector<std::uint8_t>(48, static_cast<std::uint8_t>(i + 1)));
        if (duplicate_one && !m.txs.empty()) m.txs.push_back(m.txs.front());
        std::vector<std::uint8_t> body;
        levin::MessageError err = levin::MessageError::None;
        if (!levin::encode_new_transactions(m, body, err)) return;
        write(levin::make_notify(levin::CMD_NEW_TRANSACTIONS, body));
    }

    // Ask US for a chain supplement / objects: the state_normal obligation.
    void request_chain(const std::vector<Hash>& locator) {
        levin::RequestChain m;
        m.block_ids = locator;
        m.prune     = true;
        std::vector<std::uint8_t> body;
        levin::MessageError err = levin::MessageError::None;
        if (!levin::encode_request_chain(m, body, err)) return;
        write(levin::make_notify(levin::CMD_REQUEST_CHAIN, body));
    }

    void request_objects(const std::vector<Hash>& ids) {
        levin::RequestGetObjects m;
        m.blocks = ids;
        m.prune  = true;
        std::vector<std::uint8_t> body;
        levin::MessageError err = levin::MessageError::None;
        if (!levin::encode_request_get_objects(m, body, err)) return;
        write(levin::make_notify(levin::CMD_REQUEST_GET_OBJECTS, body));
    }

    void write(const std::vector<std::uint8_t>& frame) {
        boost::system::error_code ec;
        asio::write(sock_, asio::buffer(frame), ec);
    }

    static native::PeerSyncData default_sync() {
        native::PeerSyncData s;
        s.current_height        = 2'204'100;
        s.cumulative_difficulty = native::U128{0xc3772e00dbull, 0};
        s.top_id                = hash_of_byte(0x5a);
        s.top_version           = 16;
        return s;
    }

private:
    void accept() {
        acc_.async_accept(sock_, [this](const boost::system::error_code& ec) {
            if (ec) return;
            connected = true;
            arm();
        });
    }

    void arm() {
        sock_.async_read_some(asio::buffer(chunk_),
            [this](const boost::system::error_code& ec, std::size_t n) {
                if (ec) return;
                buf_.insert(buf_.end(), chunk_, chunk_ + n);
                drain();
                arm();
            });
    }

    static std::uint64_t le64(const std::uint8_t* p) {
        std::uint64_t v = 0;
        for (int i = 7; i >= 0; --i) v = (v << 8) | p[i];
        return v;
    }
    static std::uint32_t le32(const std::uint8_t* p) {
        std::uint32_t v = 0;
        for (int i = 3; i >= 0; --i) v = (v << 8) | p[i];
        return v;
    }

    void drain() {
        for (;;) {
            if (buf_.size() < levin::HEADER_SIZE) return;
            const std::uint8_t* p = buf_.data();
            const std::uint64_t cb = le64(p + 8);
            const std::uint32_t cmd = le32(p + 17);
            const std::uint32_t flags = le32(p + 25);
            if (cb > 64u * 1024u * 1024u) { buf_.clear(); return; }
            if (buf_.size() < levin::HEADER_SIZE + cb) return;
            std::vector<std::uint8_t> body(buf_.begin() + levin::HEADER_SIZE,
                                           buf_.begin() + levin::HEADER_SIZE
                                               + static_cast<std::ptrdiff_t>(cb));
            buf_.erase(buf_.begin(),
                       buf_.begin() + levin::HEADER_SIZE + static_cast<std::ptrdiff_t>(cb));
            commands.push_back(cmd);
            bodies.push_back(body);
            handle(cmd, flags, body);
        }
    }

    void handle(std::uint32_t cmd, std::uint32_t flags, const std::vector<std::uint8_t>& body) {
        const bool is_response = (flags & levin::PACKET_RESPONSE) != 0;
        if (is_response) return;
        levin::MessageError err = levin::MessageError::None;

        if (cmd == levin::CMD_HANDSHAKE) {
            levin::HandshakeResponse r;
            r.node_data.network_id  = levin::network_id_of(levin::XmrNet::Stagenet);
            r.node_data.peer_id     = STANDIN_PEER_ID;
            r.node_data.my_port     = 38080;
            r.node_data.support_flags = levin::SUPPORT_FLAG_FLUFFY_BLOCKS;
            r.payload_data          = sync;
            r.local_peerlist_new    = peerlist;
            std::vector<std::uint8_t> out;
            if (!levin::encode_handshake_response(r, out, err)) return;
            // return_code = 1, exactly as monerod does: every handler ends in
            // `return 1` and epee copies that into the response header.
            write(levin::make_response(levin::CMD_HANDSHAKE, out, levin::RC_HANDLER_OK));
            return;
        }
        if (cmd == levin::CMD_TIMED_SYNC) {
            levin::TimedSyncResponse r;
            r.payload_data = sync;
            std::vector<std::uint8_t> out;
            if (!levin::encode_timed_sync_response(r, out, err)) return;
            write(levin::make_response(levin::CMD_TIMED_SYNC, out, levin::RC_HANDLER_OK));
            return;
        }
        if (cmd == levin::CMD_REQUEST_CHAIN && answer_chain) {
            levin::RequestChain m;
            if (!levin::decode_request_chain(body.data(), body.size(), m, err)) return;
            native::ChainEntry e;
            e.start_height = 2'204'000;
            e.total_height = 2'204'100;
            for (int i = 0; i < 4; ++i) e.ids.push_back(hash_of_byte(static_cast<std::uint8_t>(0x40 + i)));
            std::vector<std::uint8_t> out;
            if (!levin::encode_response_chain_entry(e, out, err)) return;
            write(levin::make_notify(levin::CMD_RESPONSE_CHAIN_ENTRY, out));
            return;
        }
        if (cmd == levin::CMD_REQUEST_GET_OBJECTS && answer_objects) {
            levin::RequestGetObjects m;
            if (!levin::decode_request_get_objects(body.data(), body.size(), m, err)) return;
            object_request_sizes.push_back(m.blocks.size());
            levin::ResponseGetObjects r;
            r.current_blockchain_height = sync.current_height;
            for (const Hash& id : m.blocks) {
                native::BlockEntry b;
                b.block_blob.assign(32, id[0]);
                b.pruned = m.prune;
                r.blocks.push_back(std::move(b));
            }
            std::vector<std::uint8_t> out;
            if (!levin::encode_response_get_objects(r, out, err)) return;
            write(levin::make_notify(levin::CMD_RESPONSE_GET_OBJECTS, out));
            return;
        }
    }

public:
    std::vector<std::size_t> object_request_sizes;

private:
    asio::io_context&         io_;
    tcp::acceptor             acc_;
    tcp::socket               sock_;
    std::uint8_t              chunk_[16384]{};
    std::vector<std::uint8_t> buf_;
};

// ---------------------------------------------------------------------------
p2p::XmrPeerPool::Config fast_config() {
    p2p::XmrPeerPool::Config c;
    c.net = levin::XmrNet::Stagenet;
    c.link.handshake.net         = levin::XmrNet::Stagenet;
    c.link.handshake.our_peer_id = 0x1122334455667788ull;
    c.link.handshake_timeout_ms   = 2'000;
    c.link.invoke_timeout_ms      = 2'000;
    c.link.timed_sync_interval_ms = 3'600'000;   // parked: no beat during a test
    c.link.timed_sync_jitter_ms   = 0;
    c.link.peer_timeout_ms        = 3'600'000;
    c.link.tick_ms                = 50;
    c.maintenance_tick_ms         = 25;
    c.connect_timeout_ms          = 2'000;
    c.use_seeds                   = false;       // never dial the real network
    c.dial.target_outbound        = 4;
    c.dial.max_per_netgroup       = 8;           // loopback is all one /16
    c.dial.anchor_slots           = 0;
    c.dial.rotation_interval_ms   = 0;
    return c;
}

void seed_chain(native::fakes::FakeChain& chain) {
    for (std::uint64_t h = 2'204'000; h <= 2'204'020; ++h) {
        native::node::ChainMainBlock b{};
        b.height = h;
        b.id     = hash_of_byte(static_cast<std::uint8_t>(h & 0xff));
        chain.rows.push_back(b);
    }
    chain.state.synced = true;
}

struct Rig {
    asio::io_context io;
    native::fakes::FakeChain     chain;
    native::fakes::FakeTxpool    txpool;
    std::shared_ptr<p2p::XmrPeerPool> pool;

    void pump(int ms = 100) {
        io.restart();
        io.run_for(std::chrono::milliseconds(ms));
    }

    // Pumps until `pred` holds or the budget runs out.
    template <class F>
    bool wait_for(F pred, int budget_ms = 4000) {
        for (int spent = 0; spent < budget_ms; spent += 25) {
            if (pred()) return true;
            pump(25);
        }
        return pred();
    }
};

// -----------------------------------------------------------------------
void test_dial_handshake_and_learn() {
    Rig rig;
    seed_chain(rig.chain);
    StandinDaemon daemon(rig.io);

    // A peerlist inside the handshake response: the ONLY address discovery
    // Monero offers.
    for (int i = 1; i <= 3; ++i) {
        levin::PeerlistEntry e;
        e.adr.kind = levin::NetworkAddress::Kind::Ipv4;
        e.adr.m_ip = levin::ipv4_from_octets(203, 0, 113, static_cast<std::uint8_t>(i));
        e.adr.port = 38080;
        e.id        = 0x2000 + i;
        e.last_seen = 1'790'000'000 + i;
        daemon.peerlist.push_back(e);
    }
    // One loopback entry, which must be ignored rather than learned.
    {
        levin::PeerlistEntry e;
        e.adr.kind = levin::NetworkAddress::Kind::Ipv4;
        e.adr.m_ip = levin::ipv4_from_octets(127, 0, 0, 1);
        e.adr.port = 38080;
        daemon.peerlist.push_back(e);
    }

    auto cfg = fast_config();
    cfg.manual_peers.push_back(daemon.key());
    rig.pool = p2p::XmrPeerPool::create(rig.io, cfg,
                                        {&rig.chain, &rig.chain, &rig.txpool});
    rig.pool->start();

    const bool up = rig.wait_for([&] { return rig.pool->peer_count() == 1; });
    kat::check(up, "the pool dials its pinned peer and completes the handshake");
    kat::check(daemon.connected, "the stand-in daemon saw the connection");
    kat::check(daemon.count(levin::CMD_HANDSHAKE) == 1, "exactly one HANDSHAKE was sent");

    const auto peers = rig.pool->peers();
    kat::check(peers.size() == 1, "the fetcher snapshot carries the peer");
    if (!peers.empty()) {
        kat::check(peers[0].first.peer_id == STANDIN_PEER_ID,
                   "the peer id from the handshake response is recorded");
        kat::check(peers[0].second.current_height == 2'204'100,
                   "and so is its advertised height");
    }

    // The store promoted it -- by OUR observation, not the peer's claim.
    const p2p::PeerRecord* r = rig.pool->store().find(daemon.key());
    kat::check(r != nullptr && r->tier == p2p::PeerTier::White,
               "a completed handshake promotes the address to white");

    // The peerlist was learned; the loopback entry was not.
    kat::check(rig.pool->store().find("203.0.113.1:38080") != nullptr,
               "an address from the handshake peerlist is learned");
    kat::check(rig.pool->store().find("203.0.113.3:38080") != nullptr,
               "... all of them");
    kat::check(rig.pool->store().find("127.0.0.1:38080") == nullptr
                   || rig.pool->store().find("127.0.0.1:38080")->source == p2p::PeerSource::Manual,
               "a loopback peerlist entry is not learned as a dial target");

    const p2p::PoolTelemetry t = rig.pool->telemetry();
    kat::check(t.peers_handshaked == 1, "telemetry reports the handshaked peer");
    kat::check(t.netgroups == 1, "... and its netgroup");
    kat::check(!t.eclipse_floor_met, "one netgroup does not meet the eclipse floor");
    kat::check(t.primary == daemon.key(), "the only handshaked peer is elected primary");

    rig.pool->stop();
    rig.pump(100);
}

// -----------------------------------------------------------------------
void test_object_chunking_and_span_reassembly() {
    Rig rig;
    seed_chain(rig.chain);
    StandinDaemon daemon(rig.io);

    auto cfg = fast_config();
    cfg.manual_peers.push_back(daemon.key());
    rig.pool = p2p::XmrPeerPool::create(rig.io, cfg, {&rig.chain, &rig.chain, &rig.txpool});
    rig.pool->start();
    kat::check(rig.wait_for([&] { return rig.pool->peer_count() == 1; }),
               "peer up before the span");

    // 250 ids: monerod drops a 2003 carrying more than 100, so this MUST leave
    // as three requests of 100 / 100 / 50.
    std::vector<Hash> ids;
    for (int i = 0; i < 250; ++i) ids.push_back(hash_of_byte(static_cast<std::uint8_t>(i)));

    native::PeerRef ref;
    ref.addr = daemon.key();
    kat::check(rig.pool->request_objects(ref, ids, /*prune=*/true),
               "the span is accepted");

    const bool done = rig.wait_for([&] { return !rig.chain.objects_calls.empty(); });
    kat::check(done, "the span completes");

    kat::checkf(daemon.object_request_sizes.size() == 3,
                "a 250-id span leaves as three requests (%zu)",
                daemon.object_request_sizes.size());
    for (std::size_t n : daemon.object_request_sizes)
        kat::checkf(n <= native::MAX_OBJECT_REQUEST_IDS,
                    "no request exceeds the 100-id cap (%zu)", n);
    if (daemon.object_request_sizes.size() == 3) {
        kat::check(daemon.object_request_sizes[0] == 100
                       && daemon.object_request_sizes[1] == 100
                       && daemon.object_request_sizes[2] == 50,
                   "the chunks are 100 / 100 / 50");
    }

    kat::checkf(rig.chain.objects_calls.size() == 1,
                "the three chunks are reassembled into ONE on_objects (%zu)",
                rig.chain.objects_calls.size());
    if (!rig.chain.objects_calls.empty()) {
        kat::checkf(rig.chain.objects_calls[0].blocks.size() == 250,
                    "the span C2 sees is the span C2 planned (%zu blocks)",
                    rig.chain.objects_calls[0].blocks.size());
        kat::check(rig.chain.objects_calls[0].peer_height == 2'204'100,
                   "the peer height rides with the span");
    }

    // A span larger than MAX_SPAN_IDS is refused outright rather than silently
    // truncated.
    std::vector<Hash> huge(native::MAX_SPAN_IDS + 1, hash_of_byte(0x77));
    kat::check(!rig.pool->request_objects(ref, huge, true),
               "a span over MAX_SPAN_IDS is refused");

    rig.pool->stop();
    rig.pump(100);
}

// -----------------------------------------------------------------------
void test_request_chain_forces_genesis_terminus() {
    Rig rig;
    seed_chain(rig.chain);
    StandinDaemon daemon(rig.io);

    auto cfg = fast_config();
    cfg.manual_peers.push_back(daemon.key());
    rig.pool = p2p::XmrPeerPool::create(rig.io, cfg, {&rig.chain, &rig.chain, &rig.txpool});
    rig.pool->start();
    kat::check(rig.wait_for([&] { return rig.pool->peer_count() == 1; }), "peer up");

    // Hand the fetcher a locator that does NOT end in genesis -- the shape an
    // anchored index produces. monerod would drop the connection for it, so the
    // pool must fix it on the way out.
    native::PeerRef ref;
    ref.addr = daemon.key();
    std::vector<Hash> bad{hash_of_byte(0x91), hash_of_byte(0x92)};
    kat::check(rig.pool->request_chain(ref, bad, /*prune=*/true), "the chain request is accepted");

    const bool sent = rig.wait_for([&] { return daemon.count(levin::CMD_REQUEST_CHAIN) == 1; });
    kat::check(sent, "a NOTIFY_REQUEST_CHAIN reached the peer");

    // Decode what actually went out.
    std::vector<std::uint8_t> body;
    for (std::size_t i = 0; i < daemon.commands.size(); ++i)
        if (daemon.commands[i] == levin::CMD_REQUEST_CHAIN) body = daemon.bodies[i];
    levin::RequestChain got;
    levin::MessageError err = levin::MessageError::None;
    kat::check(levin::decode_request_chain(body.data(), body.size(), got, err),
               "the request decodes");
    kat::check(got.block_ids.size() == 3, "the genesis id was appended");
    kat::check(p2p::locator_ends_with_genesis(got.block_ids,
                                              p2p::genesis_id(levin::XmrNet::Stagenet)),
               "THE LOCATOR ON THE WIRE ENDS WITH THE STAGENET GENESIS ID");
    kat::check(got.block_ids[0] == hash_of_byte(0x91),
               "the caller's tip-most id is still the splice candidate");
    kat::check(got.prune, "prune=true rides through (D-4)");

    const bool answered = rig.wait_for([&] { return !rig.chain.chain_entry_calls.empty(); });
    kat::check(answered, "the RESPONSE_CHAIN_ENTRY reaches the index");

    rig.pool->stop();
    rig.pump(100);
}

// -----------------------------------------------------------------------
void test_serving_obligation() {
    // THE STATE_NORMAL TRAP. A peer relays to us only while we answer its own
    // chain and objects requests. This is the check that would have caught a
    // silently starving node.
    Rig rig;
    seed_chain(rig.chain);
    StandinDaemon daemon(rig.io);

    auto cfg = fast_config();
    cfg.manual_peers.push_back(daemon.key());
    rig.pool = p2p::XmrPeerPool::create(rig.io, cfg, {&rig.chain, &rig.chain, &rig.txpool});
    rig.pool->start();
    kat::check(rig.wait_for([&] { return rig.pool->peer_count() == 1; }), "peer up");

    // The peer asks us for a supplement, with a locator containing an id we
    // hold.
    daemon.request_chain({hash_of_byte(static_cast<std::uint8_t>(2'204'010 & 0xff))});
    kat::check(rig.wait_for([&] {
                   return daemon.count(levin::CMD_RESPONSE_CHAIN_ENTRY) == 1;
               }), "we answered the peer's NOTIFY_REQUEST_CHAIN");
    kat::check(rig.pool->telemetry().served_chain == 1, "telemetry counts the served chain");

    // ... and for a block we retain.
    native::BlockEntry served;
    served.block_blob.assign(48, 0xbe);
    rig.chain.serve(hash_of_byte(0x33), served);
    daemon.request_objects({hash_of_byte(0x33), hash_of_byte(0x44)});
    kat::check(rig.wait_for([&] {
                   return daemon.count(levin::CMD_RESPONSE_GET_OBJECTS) == 1;
               }), "we answered the peer's NOTIFY_REQUEST_GET_OBJECTS");

    std::vector<std::uint8_t> body;
    for (std::size_t i = 0; i < daemon.commands.size(); ++i)
        if (daemon.commands[i] == levin::CMD_RESPONSE_GET_OBJECTS) body = daemon.bodies[i];
    levin::ResponseGetObjects r;
    levin::MessageError err = levin::MessageError::None;
    if (!body.empty()) {
        kat::check(levin::decode_response_get_objects(body.data(), body.size(), r, err),
                   "our answer decodes");
        kat::check(r.blocks.size() == 1, "the block we hold is served");
        kat::check(r.missed_ids.size() == 1, "the one we do not hold is reported as missed");
        kat::check(r.current_blockchain_height == 2'204'021,
                   "we advertise our own tip + 1, not the peer's");
    }

    rig.pool->stop();
    rig.pump(100);
}

// -----------------------------------------------------------------------
void test_serving_no_common_block_closes() {
    Rig rig;
    seed_chain(rig.chain);
    StandinDaemon daemon(rig.io);

    auto cfg = fast_config();
    cfg.manual_peers.push_back(daemon.key());
    rig.pool = p2p::XmrPeerPool::create(rig.io, cfg, {&rig.chain, &rig.chain, &rig.txpool});
    rig.pool->start();
    kat::check(rig.wait_for([&] { return rig.pool->peer_count() == 1; }), "peer up");

    // A locator with nothing we recognise. A misleading supplement would be
    // worse than a clean close, so monerod closes and so do we.
    daemon.request_chain({hash_of_byte(0xf0), hash_of_byte(0xf1)});
    const bool closed = rig.wait_for([&] { return rig.pool->peer_count() == 0; });
    kat::check(closed, "a chain request with no common block closes the connection");
    kat::check(rig.pool->telemetry().served_declined >= 1, "... and is counted as declined");
    kat::check(!rig.chain.peer_gone_calls.empty(), "the index is told the peer is gone");

    rig.pool->stop();
    rig.pump(100);
}

// -----------------------------------------------------------------------
void test_push_traffic_and_broadcast() {
    Rig rig;
    seed_chain(rig.chain);
    StandinDaemon daemon(rig.io);

    auto cfg = fast_config();
    cfg.manual_peers.push_back(daemon.key());
    rig.pool = p2p::XmrPeerPool::create(rig.io, cfg, {&rig.chain, &rig.chain, &rig.txpool});
    rig.pool->start();
    kat::check(rig.wait_for([&] { return rig.pool->peer_count() == 1; }), "peer up");

    daemon.push_fluffy_block(hash_of_byte(0x77), 2'204'101);
    kat::check(rig.wait_for([&] { return !rig.chain.new_block_calls.empty(); }),
               "a pushed fluffy block reaches the index");
    if (!rig.chain.new_block_calls.empty()) {
        kat::check(rig.chain.new_block_calls[0].fluffy, "... flagged as fluffy");
        kat::check(rig.chain.new_block_calls[0].peer_height == 2'204'101,
                   "... with the peer's claimed height");
    }

    // Three transactions plus one duplicate of the first: the duplicate is
    // dropped before the pool ever decodes the same bytes twice.
    daemon.push_transactions(3, /*duplicate_one=*/true);
    kat::check(rig.wait_for([&] { return !rig.txpool.relay_calls.empty(); }),
               "relayed transactions reach the txpool");
    if (!rig.txpool.relay_calls.empty()) {
        kat::checkf(rig.txpool.relay_calls[0].n_blobs == 3,
                    "the in-batch duplicate is dropped before the pool sees it (%zu)",
                    rig.txpool.relay_calls[0].n_blobs);
    }

    // Broadcast out. Called from THIS thread, which is not the io thread, so it
    // exercises the promise/future path that makes the count trustworthy.
    // The caller runs on ANOTHER thread on purpose: that is the path C5 takes,
    // and it is the one where broadcast_notify has to wait for the io thread to
    // tell it how many peers the frame actually reached. The rig keeps pumping
    // until the caller is done, because nobody else will run that io thread.
    std::vector<std::uint8_t> frame(16, 0xab);
    std::size_t       written = 0;
    std::atomic<bool> done{false};
    std::thread caller([&] {
        written = rig.pool->broadcast_notify(levin::CMD_NEW_FLUFFY_BLOCK, frame);
        done.store(true);
    });
    rig.wait_for([&] { return done.load(); }, 3000);
    caller.join();
    kat::checkf(written == 1, "broadcast_notify reports the peer it reached (%zu)", written);
    kat::check(rig.wait_for([&] { return daemon.count(levin::CMD_NEW_FLUFFY_BLOCK) >= 1; }),
               "the broadcast frame arrived at the peer");

    rig.pool->stop();
    rig.pump(100);
}

// -----------------------------------------------------------------------
void test_broadcast_with_no_peers_is_zero() {
    // The never-silent-drop rule: a found block that reached nobody must report
    // zero loudly, not shrug.
    Rig rig;
    seed_chain(rig.chain);
    auto cfg = fast_config();
    rig.pool = p2p::XmrPeerPool::create(rig.io, cfg, {&rig.chain, &rig.chain, &rig.txpool});
    rig.pool->start();
    rig.pump(100);

    std::vector<std::uint8_t> frame(16, 0xcd);
    std::size_t       written = 1;
    std::atomic<bool> done{false};
    std::thread caller([&] {
        written = rig.pool->broadcast_notify(levin::CMD_NEW_FLUFFY_BLOCK, frame);
        done.store(true);
    });
    rig.wait_for([&] { return done.load(); }, 3000);
    caller.join();
    kat::check(written == 0, "a broadcast with no peers reports zero");

    rig.pool->stop();
    rig.pump(100);
}

// -----------------------------------------------------------------------
void test_refill_across_several_daemons() {
    Rig rig;
    seed_chain(rig.chain);
    std::vector<std::unique_ptr<StandinDaemon>> daemons;
    for (int i = 0; i < 3; ++i) daemons.push_back(std::make_unique<StandinDaemon>(rig.io));

    auto cfg = fast_config();
    cfg.dial.target_outbound = 3;
    cfg.dial.max_concurrent_dials = 3;
    for (auto& d : daemons) cfg.manual_peers.push_back(d->key());
    rig.pool = p2p::XmrPeerPool::create(rig.io, cfg, {&rig.chain, &rig.chain, &rig.txpool});
    rig.pool->start();

    kat::check(rig.wait_for([&] { return rig.pool->peer_count() == 3; }),
               "refill reaches the target across three peers");
    const p2p::PoolTelemetry t = rig.pool->telemetry();
    kat::check(t.handshakes >= 3, "three handshakes were completed");
    kat::check(t.dials_started >= 3, "three dials were started");

    rig.pool->stop();
    rig.pump(150);
    kat::check(rig.pool->peer_count() == 0, "stop() tears the pool down");
}

// -----------------------------------------------------------------------
void test_unreachable_address_backs_off() {
    Rig rig;
    seed_chain(rig.chain);
    // Port 1 on loopback: nothing listens, and the connect is refused fast.
    auto cfg = fast_config();
    cfg.manual_peers.push_back("127.0.0.1:1");
    cfg.connect_timeout_ms = 300;
    rig.pool = p2p::XmrPeerPool::create(rig.io, cfg, {&rig.chain, &rig.chain, &rig.txpool});
    rig.pool->start();
    rig.wait_for([&] { return rig.pool->telemetry().dials_failed > 0; }, 2500);

    kat::check(rig.pool->telemetry().dials_failed > 0, "an unreachable address fails to dial");
    const p2p::PeerRecord* r = rig.pool->store().find("127.0.0.1:1");
    kat::check(r != nullptr && r->failures > 0, "the failure is recorded");
    kat::check(r != nullptr && r->fail_score == 0,
               "an unreachable address is NOT scored down: unreachable is not misbehaviour");
    kat::check(!rig.pool->store().is_banned("127.0.0.1:1", rig.pool->now_ms()),
               "... and is not banned");

    rig.pool->stop();
    rig.pump(100);
}

// ---------------------------------------------------------------------------
// --live <host>:<port>: dial a real daemon, read-only.
// ---------------------------------------------------------------------------
int run_live(const std::string& target) {
    std::string host;
    std::uint16_t port = 0;
    if (!p2p::split_peer_key(target, host, port)) {
        std::fprintf(stderr, "live: expected host:port, got '%s'\n", target.c_str());
        return 2;
    }

    Rig rig;
    // ADVERTISE THE GENESIS AS OUR TIP, and not a fabricated one.
    //
    // This is the live lesson, and it is a design fact rather than a test
    // convenience. monerod's process_payload_sync_data does
    // `if (m_core.have_block(hshd.top_id)) { context.m_state = state_normal; }`
    // -- and otherwise parks the connection in state_synchronizing and asks US
    // for a chain supplement. A node that advertises a top_id no peer has ever
    // seen is therefore never relayed to: it sits handshaked, healthy, and
    // starving, which is exactly the shape of the X9 bring-up's silent failure.
    // The first run of this live mode advertised a synthetic tip and got five
    // NOTIFY_REQUEST_CHAIN and zero relay frames, which is that trap reproduced.
    //
    // The genesis id is the one block EVERY peer has, so a cold node that has
    // not yet loaded its anchor should advertise exactly that -- truthfully --
    // rather than a height it cannot back up.
    native::node::ChainMainBlock g{};
    g.height = 0;
    g.id     = p2p::genesis_id(levin::XmrNet::Stagenet);
    rig.chain.rows.push_back(g);
    rig.chain.state.synced = true;

    auto cfg = fast_config();
    cfg.link.timed_sync_interval_ms = 60'000;
    cfg.link.peer_timeout_ms        = 240'000;
    cfg.connect_timeout_ms          = 10'000;
    // ONE connection, to the address named on the command line. Refill must not
    // spend the peerlist we just learned on dialling strangers: this mode is a
    // read-only probe of one daemon, not a network crawl.
    cfg.dial.target_outbound = 1;
    cfg.dial.max_outbound    = 1;
    cfg.manual_peers.push_back(target);
    rig.pool = p2p::XmrPeerPool::create(rig.io, cfg, {&rig.chain, &rig.chain, &rig.txpool});
    rig.pool->start();

    std::printf("live: dialing %s\n", target.c_str());
    const bool up = rig.wait_for([&] { return rig.pool->peer_count() == 1; }, 20'000);
    if (!up) {
        std::printf("live: FAILED to handshake\n");
        rig.pool->stop();
        rig.pump(200);
        return 1;
    }

    const auto peers = rig.pool->peers();
    std::printf("live: HANDSHAKED peer_id=%016llx height=%llu top_version=%u\n",
                static_cast<unsigned long long>(peers[0].first.peer_id),
                static_cast<unsigned long long>(peers[0].second.current_height),
                static_cast<unsigned>(peers[0].second.top_version));
    std::printf("live: learned %zu addresses from the handshake peerlist\n",
                rig.pool->store().size());
    std::size_t shown = 0;
    for (const auto& [key, rec] : rig.pool->store().all()) {
        if (rec.source != p2p::PeerSource::Peerlist) continue;
        std::printf("live:   peer %s (%s)\n", key.c_str(), p2p::to_string(rec.tier));
        if (++shown >= 5) break;
    }

    // One genesis-terminated locator. A wrong terminus here is a silent
    // drop_connection() inside monerod, so an answer IS the proof.
    native::PeerRef ref;
    ref.addr = target;
    const std::vector<Hash> locator{p2p::genesis_id(cfg.net)};   // genesis-only
    rig.pool->request_chain(ref, locator, /*prune=*/true);
    const bool answered = rig.wait_for([&] { return !rig.chain.chain_entry_calls.empty(); },
                                       30'000);
    if (answered) {
        const native::ChainEntry& e = rig.chain.chain_entry_calls[0].entry;
        std::printf("live: RESPONSE_CHAIN_ENTRY start_height=%llu total_height=%llu ids=%zu\n",
                    static_cast<unsigned long long>(e.start_height),
                    static_cast<unsigned long long>(e.total_height), e.ids.size());
        if (!e.ids.empty()) {
            std::printf("live: ids[0]=%s\n",
                        kat::to_hex(std::vector<std::uint8_t>(e.ids[0].begin(),
                                                              e.ids[0].end())).c_str());
            kat::check(e.ids[0] == p2p::genesis_id(cfg.net),
                       "live: the daemon echoed the genesis id at height 0");
        }
        kat::check(e.start_height == 0, "live: a genesis-only locator splices at height 0");
    } else {
        std::printf("live: no chain entry (daemon busy or terminus rejected)\n");
    }

    const p2p::PoolTelemetry t = rig.pool->telemetry();
    std::printf("live: frames_in=%llu blocks_in=%llu txs_in=%llu chain_entries=%llu "
                "dropped_dos=%llu relay_silent=%zu peers=%zu\n",
                static_cast<unsigned long long>(t.frames_in),
                static_cast<unsigned long long>(t.blocks_in),
                static_cast<unsigned long long>(t.txs_in),
                static_cast<unsigned long long>(t.chain_entries_in),
                static_cast<unsigned long long>(t.frames_dropped_dos),
                t.relay_silent_peers, rig.pool->peer_count());
    for (const auto& [cmd, n] : t.frames_by_cmd)
        std::printf("live:   inbound %s x%llu\n", levin::command_name(cmd),
                    static_cast<unsigned long long>(n));
    if (!t.last_close_why.empty())
        std::printf("live: last close %s: %s\n", t.last_close_peer.c_str(),
                    t.last_close_why.c_str());

    rig.pool->stop();
    rig.pump(300);
    return kat::report("xmr_native_peer_pool_kat(live)");
}

} // namespace

int main(int argc, char** argv) {
    for (int i = 1; i + 1 < argc; ++i)
        if (std::strcmp(argv[i], "--live") == 0) return run_live(argv[i + 1]);

    test_dial_handshake_and_learn();
    test_object_chunking_and_span_reassembly();
    test_request_chain_forces_genesis_terminus();
    test_serving_obligation();
    test_serving_no_common_block_closes();
    test_push_traffic_and_broadcast();
    test_broadcast_with_no_peers_is_zero();
    test_refill_across_several_daemons();
    test_unreachable_address_backs_off();
    return kat::report("xmr_native_peer_pool_kat");
}
