// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/native/test/xmr_native_levin_unsolicited_cap_kat.cpp
//
// A 2004 / 2007 is a notification with no id; the only thing that makes one
// legitimate is an outstanding request we sent. After the handshake (so the
// per-command cap, not the pre-handshake gate, is what applies) an unsolicited
// 2004 carrying a large body must be refused at HEADER time, before the socket
// sizes and reads its declared body. Observed through the link's own socket
// byte counter over a loopback pair.
//   UC1  unsolicited_response_at_header : across the unsolicited 2004 the link
//        read only the 33-byte header, not its body.
// STL plus boost::asio. No test framework, matching the neighbouring KATs.
// ---------------------------------------------------------------------------
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <memory>
#include <string>
#include <vector>

#include <boost/asio.hpp>

#include "impl/xmr/native/p2p/xmr_levin_link.hpp"
#include "xmr_p2p_kat_util.hpp"

using namespace c2pool::xmr::native::levin;
namespace native = c2pool::xmr::native;
namespace kat    = c2pool::xmr::native::kat;
namespace asio   = boost::asio;
using tcp = asio::ip::tcp;

namespace {

constexpr std::uint64_t PEER_PEER_ID = 0xfedcba9876543210ull;

native::PeerSyncData our_sync() {
    native::PeerSyncData s;
    s.current_height = 1'700'001;
    s.cumulative_difficulty = native::U128{0x1122334455667788ull, 0x9ull};
    s.top_id.fill(0xa5);
    s.top_version = 16;
    s.pruning_seed = 0;
    return s;
}

// A stand-in peer that answers the handshake and can write a raw frame.
class FakePeer {
public:
    explicit FakePeer(tcp::socket s) : sock_(std::move(s)) { arm(); }
    void write(const std::vector<std::uint8_t>& frame) {
        boost::system::error_code ec;
        asio::write(sock_, asio::buffer(frame), ec);
    }
private:
    static std::uint64_t le64(const std::uint8_t* p) { std::uint64_t v=0; for (int i=7;i>=0;--i) v=(v<<8)|p[i]; return v; }
    static std::uint32_t le32(const std::uint8_t* p) { std::uint32_t v=0; for (int i=3;i>=0;--i) v=(v<<8)|p[i]; return v; }
    void arm() {
        sock_.async_read_some(asio::buffer(chunk_),
            [this](const boost::system::error_code& ec, std::size_t n) {
                if (ec) return;
                buf_.insert(buf_.end(), chunk_, chunk_ + n);
                drain();
                arm();
            });
    }
    void drain() {
        for (;;) {
            if (buf_.size() < HEADER_SIZE) return;
            const std::uint8_t* p = buf_.data();
            const std::uint64_t cb  = le64(p + 8);
            const std::uint32_t cmd = le32(p + 17);
            if (cb > 64u * 1024u * 1024u) { buf_.clear(); return; }
            if (buf_.size() < HEADER_SIZE + cb) return;
            buf_.erase(buf_.begin(), buf_.begin() + HEADER_SIZE + static_cast<std::ptrdiff_t>(cb));
            if (cmd == CMD_HANDSHAKE) {
                HandshakeResponse r;
                r.node_data.network_id    = network_id_of(XmrNet::Stagenet);
                r.node_data.peer_id       = PEER_PEER_ID;
                r.node_data.my_port       = 38080;
                r.node_data.support_flags = SUPPORT_FLAG_FLUFFY_BLOCKS;
                r.payload_data            = our_sync();
                r.payload_data.top_id.fill(0x5a);
                std::vector<std::uint8_t> out;
                MessageError err = MessageError::None;
                if (encode_handshake_response(r, out, err))
                    write(make_response(CMD_HANDSHAKE, out, RC_HANDLER_OK));
            }
        }
    }
    tcp::socket               sock_;
    std::uint8_t              chunk_[8192]{};
    std::vector<std::uint8_t> buf_;
};

LinkConfig cfg() {
    LinkConfig c;
    c.handshake.net          = XmrNet::Stagenet;
    c.handshake.our_peer_id  = 0x0123456789abcdefull;
    c.handshake_timeout_ms   = 100'000;
    c.invoke_timeout_ms      = 100'000;
    c.timed_sync_interval_ms = 100'000;   // parked
    c.timed_sync_jitter_ms   = 0;
    c.peer_timeout_ms        = 100'000;
    c.tick_ms                = 10;
    return c;
}

} // namespace

int main() {
    asio::io_context io;
    tcp::acceptor acc(io, tcp::endpoint(asio::ip::make_address("127.0.0.1"), 0));
    acc.listen();
    tcp::socket a(io), b(io);
    bool ok_a = false, ok_b = false;
    acc.async_accept(b, [&](const boost::system::error_code& ec) { ok_b = !ec; });
    a.async_connect(acc.local_endpoint(), [&](const boost::system::error_code& ec) { ok_a = !ec; });
    io.restart();
    io.run_for(std::chrono::seconds(2));
    kat::check(ok_a && ok_b, "UC1: loopback pair connects");

    bool closed = false;
    bool handshaked = false;
    LinkCallbacks cb;
    cb.our_sync_data     = []() { return our_sync(); };
    cb.on_peer_sync_data = [](const native::PeerRef&, const native::PeerSyncData&) {};
    cb.on_peerlist       = [](const native::PeerRef&, const std::vector<PeerlistEntry>&) {};
    cb.on_handshaked     = [&](const native::PeerRef&) { handshaked = true; };
    cb.on_closed         = [&](const native::PeerRef&, LinkClose, const std::string&) { closed = true; };

    FakePeer peer(std::move(a));
    auto link = LevinLink::create(std::move(b), cfg(), cb);
    link->start();

    for (int i = 0; i < 40 && !handshaked; ++i) { io.restart(); io.run_for(std::chrono::milliseconds(50)); }
    kat::check(handshaked, "UC1: the link completes the handshake");
    io.restart(); io.run_for(std::chrono::milliseconds(50));

    // Byte counter just before the unsolicited frame (the handshake response
    // already counted toward bytes_in; we measure the DELTA the 2004 adds).
    const std::uint64_t before = link->socket()->stats().bytes_in;

    // An UNSOLICITED 2004 with a ~1 MiB body (well under the 32 MiB post-
    // handshake cap, so the header passes the size check). We armed no request.
    std::vector<std::uint8_t> payload(1024u * 1024u, 0xAB);
    peer.write(make_notify(CMD_RESPONSE_GET_OBJECTS, payload));

    for (int i = 0; i < 40 && !closed; ++i) { io.restart(); io.run_for(std::chrono::milliseconds(50)); }

    const std::uint64_t after = link->socket()->stats().bytes_in;
    const std::uint64_t delta = after - before;
    kat::check(closed, "UC1: the unsolicited response closes the link");
    kat::checkf(delta == HEADER_SIZE,
                "UC1: only the %u-byte header was read, not the body (delta bytes_in=%llu)",
                static_cast<unsigned>(HEADER_SIZE), static_cast<unsigned long long>(delta));

    link->stop("done");
    io.restart();
    io.run_for(std::chrono::milliseconds(50));
    return kat::report("xmr_native_levin_unsolicited_cap_kat");
}
