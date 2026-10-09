// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/native/test/xmr_native_peer_pool_budget_kat.cpp
//
// The pool charges a peer's inbound byte budget before decoding the body of a
// NEW_TRANSACTIONS (2002) frame. A loopback stand-in daemon, with the pool's
// byte budget set to 50 bytes, sends a 200-byte 2002 whose body is not epee.
//   PB1  budget_before_decode : an over-budget 2002 with an undecodable body
//        drops the frame and keeps the peer (it is not disconnected).
// STL plus boost::asio. No test framework, matching the neighbouring KATs.
// ---------------------------------------------------------------------------
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <memory>
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
using tcp = asio::ip::tcp;
using native::Hash;

namespace {

constexpr std::uint64_t STANDIN_PEER_ID = 0x00c0ffee00c0ffeeull;

Hash hash_of_byte(std::uint8_t v) { Hash h{}; h.fill(v); return h; }

// A stand-in monerod: accepts one connection, answers the handshake, and can be
// told to write a raw frame. It advertises a height BELOW ours, so the pool
// never asks it for a chain and the only inbound frame is the test frame.
class StandinDaemon {
public:
    explicit StandinDaemon(asio::io_context& io)
        : acc_(io, tcp::endpoint(asio::ip::make_address("127.0.0.1"), 0)), sock_(io) {
        acc_.listen();
        accept();
    }
    std::uint16_t port() const { return acc_.local_endpoint().port(); }
    std::string   key()  const { return "127.0.0.1:" + std::to_string(port()); }

    void write(const std::vector<std::uint8_t>& frame) {
        boost::system::error_code ec;
        asio::write(sock_, asio::buffer(frame), ec);
    }

private:
    void accept() {
        acc_.async_accept(sock_, [this](const boost::system::error_code& ec) {
            if (ec) return;
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
    static std::uint64_t le64(const std::uint8_t* p) { std::uint64_t v=0; for (int i=7;i>=0;--i) v=(v<<8)|p[i]; return v; }
    static std::uint32_t le32(const std::uint8_t* p) { std::uint32_t v=0; for (int i=3;i>=0;--i) v=(v<<8)|p[i]; return v; }
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
                                           buf_.begin() + levin::HEADER_SIZE + static_cast<std::ptrdiff_t>(cb));
            buf_.erase(buf_.begin(), buf_.begin() + levin::HEADER_SIZE + static_cast<std::ptrdiff_t>(cb));
            handle(cmd, flags);
        }
    }
    void handle(std::uint32_t cmd, std::uint32_t flags) {
        if (flags & levin::PACKET_RESPONSE) return;
        levin::MessageError err = levin::MessageError::None;
        if (cmd == levin::CMD_HANDSHAKE) {
            levin::HandshakeResponse r;
            r.node_data.network_id    = levin::network_id_of(levin::XmrNet::Stagenet);
            r.node_data.peer_id       = STANDIN_PEER_ID;
            r.node_data.my_port       = 38080;
            r.node_data.support_flags = levin::SUPPORT_FLAG_FLUFFY_BLOCKS;
            r.payload_data.current_height        = 2'204'010;   // BELOW our tip -> no chain request
            r.payload_data.cumulative_difficulty = native::U128{0xc3772e00dbull, 0};
            r.payload_data.top_id                = hash_of_byte(0x5a);
            r.payload_data.top_version           = 16;
            std::vector<std::uint8_t> out;
            if (!levin::encode_handshake_response(r, out, err)) return;
            write(levin::make_response(levin::CMD_HANDSHAKE, out, levin::RC_HANDLER_OK));
            return;
        }
        if (cmd == levin::CMD_TIMED_SYNC) {
            levin::TimedSyncResponse r;
            r.payload_data.current_height        = 2'204'010;
            r.payload_data.cumulative_difficulty = native::U128{0xc3772e00dbull, 0};
            r.payload_data.top_id                = hash_of_byte(0x5a);
            r.payload_data.top_version           = 16;
            std::vector<std::uint8_t> out;
            if (!levin::encode_timed_sync_response(r, out, err)) return;
            write(levin::make_response(levin::CMD_TIMED_SYNC, out, levin::RC_HANDLER_OK));
            return;
        }
    }

    tcp::acceptor             acc_;
    tcp::socket               sock_;
    std::uint8_t              chunk_[8192]{};
    std::vector<std::uint8_t> buf_;
};

p2p::XmrPeerPool::Config cfg_with_tiny_byte_budget(const std::string& peer) {
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
    c.use_seeds                   = false;
    c.dial.target_outbound        = 4;
    c.dial.max_per_netgroup       = 8;
    c.dial.anchor_slots           = 0;
    c.dial.rotation_interval_ms   = 0;
    c.manual_peers.push_back(peer);
    // A byte bucket smaller than the test frame.
    c.dos.bytes_capacity = 50.0;
    c.dos.bytes_refill   = 1.0;
    return c;
}

struct Rig {
    asio::io_context io;
    native::fakes::FakeChain  chain;
    native::fakes::FakeTxpool txpool;
    std::shared_ptr<p2p::XmrPeerPool> pool;
    void pump(int ms = 50) { io.restart(); io.run_for(std::chrono::milliseconds(ms)); }
    template <class F> bool wait_for(F pred, int budget_ms = 4000) {
        for (int s = 0; s < budget_ms; s += 25) { if (pred()) return true; pump(25); }
        return pred();
    }
};

void seed_chain(native::fakes::FakeChain& chain) {
    for (std::uint64_t h = 2'204'000; h <= 2'204'020; ++h) {
        native::node::ChainMainBlock b{};
        b.height = h;
        b.id     = hash_of_byte(static_cast<std::uint8_t>(h & 0xff));
        chain.rows.push_back(b);
    }
    chain.state.synced = true;
}

} // namespace

int main() {
    Rig rig;
    seed_chain(rig.chain);
    StandinDaemon daemon(rig.io);

    rig.pool = p2p::XmrPeerPool::create(rig.io, cfg_with_tiny_byte_budget(daemon.key()),
                                        {&rig.chain, &rig.chain, &rig.txpool});
    rig.pool->start();
    kat::check(rig.wait_for([&] { return rig.pool->peer_count() == 1; }),
               "PB1: the pool dials and handshakes the stand-in");

    // An over-budget 2002 whose body is not epee: expected dropped on the byte
    // budget (frames_dropped_dos >= 1), peer kept (peer_count 1).
    std::vector<std::uint8_t> junk(200, 0xAB);
    daemon.write(levin::make_notify(levin::CMD_NEW_TRANSACTIONS, junk));
    for (int i = 0; i < 12; ++i) rig.pump(50);

    const p2p::PoolTelemetry t = rig.pool->telemetry();
    kat::checkf(rig.pool->peer_count() == 1,
                "PB1: the peer survives an over-budget 2002 (peer_count=%zu)", rig.pool->peer_count());
    kat::checkf(t.frames_dropped_dos >= 1,
                "PB1: the frame was dropped on the byte budget, not decoded (dropped=%llu)",
                static_cast<unsigned long long>(t.frames_dropped_dos));

    rig.pool->stop();
    rig.pump(100);
    return kat::report("xmr_native_peer_pool_budget_kat");
}
