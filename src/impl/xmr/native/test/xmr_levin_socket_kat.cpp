// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/native/test/xmr_levin_socket_kat.cpp
//
// Wave 1, component C1b: the LOOPBACK TRANSPORT KAT. Half of K-C1-3.
//
// This exercises LevinSocket over real TCP on 127.0.0.1 -- an accepted socket
// and a connected one on the same io_context -- because the three disciplines
// it copies from core::Socket are all about what asio actually does, and none
// of them can be observed on a mock:
//
//   1. read loop      -- header first, body bounded by the cap for THAT command
//                        in THAT handshake state, no resync on a bad header.
//   2. write queue    -- one composed async_write in flight, FIFO drain. The
//                        regression this catches is issue #863: overlapping
//                        composed writes splice one message's bytes into
//                        another's middle. It only reproduces with buffers
//                        large enough to need more than one write round, which
//                        is why the frames below are hundreds of kilobytes.
//   3. lifetime       -- an async callback that finds its owner freed aborts
//                        the connection instead of dereferencing it. The check
//                        below is written as the actual use-after-free shape,
//                        so on the sanitizer CI leg ASan proves the guard
//                        rather than the assertion merely asserting it.
//
// Plus the RandomX fence: the frame handler runs on the io thread and nowhere
// else, asserted by comparing thread ids rather than by trusting a comment.
//
// STL plus boost::asio. No test framework, matching the neighbouring KATs.
// ---------------------------------------------------------------------------

#include <atomic>
#include <chrono>
#include <cstdint>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include <boost/asio.hpp>

#include "impl/xmr/native/p2p/levin_socket.hpp"
#include "xmr_p2p_kat_util.hpp"

using namespace c2pool::xmr::native::levin;
namespace kat = c2pool::xmr::native::kat;
namespace asio = boost::asio;
using tcp = asio::ip::tcp;

namespace {

// --- harness -----------------------------------------------------------------
// A connected loopback pair on one io_context. Both halves are ordinary asio
// sockets; the caller decides which of them gets wrapped in a LevinSocket.
struct SocketPair {
    tcp::socket client;
    tcp::socket server;
};

SocketPair connect_pair(asio::io_context& io) {
    tcp::acceptor acc(io, tcp::endpoint(asio::ip::make_address("127.0.0.1"), 0));
    acc.listen();

    tcp::socket client(io);
    tcp::socket server(io);
    bool accepted = false, connected = false;

    acc.async_accept(server, [&](const boost::system::error_code& ec) {
        accepted = !ec;
    });
    client.async_connect(acc.local_endpoint(), [&](const boost::system::error_code& ec) {
        connected = !ec;
    });

    io.restart();
    io.run_for(std::chrono::seconds(2));
    kat::check(accepted && connected, "loopback pair connects");
    return SocketPair{std::move(client), std::move(server)};
}

void pump(asio::io_context& io, int ms = 250) {
    io.restart();
    io.run_for(std::chrono::milliseconds(ms));
}

// One delivered frame, copied out of the socket's read buffer (the pointer the
// handler receives is only valid for the duration of the call -- copying here
// is also a check that the contract is stated correctly).
struct Got {
    BucketHead                head;
    std::vector<std::uint8_t> body;
    std::thread::id           on_thread;
};

// A LevinSocket wired up for observation.
struct Endpoint {
    std::shared_ptr<LevinSocket> sock;
    std::vector<Got>             frames;
    bool                         closed = false;
    std::string                  close_why;

    void wire(bool handshaked, std::size_t write_cap = 8u * 1024u * 1024u) {
        sock->set_frame_handler([this](const BucketHead& h, const std::uint8_t* b, std::size_t n) {
            Got g;
            g.head      = h;
            g.on_thread = std::this_thread::get_id();
            if (b && n) g.body.assign(b, b + n);
            frames.push_back(std::move(g));
        });
        sock->set_close_handler([this](const std::string& why) {
            closed    = true;
            close_why = why;
        });
        (void)handshaked;
        (void)write_cap;
    }
};

std::shared_ptr<LevinSocket> wrap(tcp::socket s, bool handshaked,
                                  std::size_t write_cap = 8u * 1024u * 1024u) {
    LevinSocket::Options opt;
    opt.policy.handshaked        = handshaked;
    opt.max_write_queue_bytes    = write_cap;
    return LevinSocket::create(std::move(s), opt);
}

std::vector<std::uint8_t> filler(std::size_t n, std::uint8_t seed) {
    std::vector<std::uint8_t> v(n);
    for (std::size_t i = 0; i < n; ++i)
        v[i] = static_cast<std::uint8_t>((i * 131u + seed) & 0xff);
    return v;
}

// --- 1: FIFO write ordering under multi-round composed writes ----------------
// The #863 shape. Twenty-four frames, most of them far larger than a socket
// buffer, all submitted inside ONE handler turn. If more than one composed
// write were ever in flight the receiver would see interleaved bytes, and
// because levin has no checksum the first symptom would be a "bad signature"
// close rather than a corrupted message -- so both the order check and the
// "still open" check matter.
void test_write_fifo() {
    asio::io_context io;
    SocketPair p = connect_pair(io);

    auto tx = wrap(std::move(p.client), /*handshaked=*/true);
    Endpoint rx;
    rx.sock = wrap(std::move(p.server), /*handshaked=*/true);
    rx.wire(true);

    tx->start();
    rx.sock->start();

    std::vector<std::vector<std::uint8_t>> sent_bodies;
    bool all_accepted = true;
    for (int i = 0; i < 24; ++i) {
        // Alternate a tiny frame and a ~150 KB one: the small ones would still
        // be ordered by luck, the large ones are what actually need the queue.
        const std::size_t n = (i % 2 == 0) ? (150u * 1024u + static_cast<std::size_t>(i))
                                           : (32u + static_cast<std::size_t>(i));
        auto body = filler(n, static_cast<std::uint8_t>(i));
        sent_bodies.push_back(body);
        all_accepted = tx->send(make_notify(CMD_NEW_FLUFFY_BLOCK, body)) && all_accepted;
    }
    kat::check(all_accepted, "write-fifo: every frame was accepted by the queue");

    for (int i = 0; i < 40 && rx.frames.size() < sent_bodies.size(); ++i) pump(io, 100);

    kat::checkf(rx.frames.size() == sent_bodies.size(),
                "write-fifo: %zu of %zu frames arrived",
                rx.frames.size(), sent_bodies.size());
    kat::check(!rx.closed, "write-fifo: the link stayed open (no spliced frame)");

    bool ordered = true;
    for (std::size_t i = 0; i < rx.frames.size() && i < sent_bodies.size(); ++i) {
        if (rx.frames[i].body != sent_bodies[i]) { ordered = false; break; }
        if (rx.frames[i].head.command != CMD_NEW_FLUFFY_BLOCK) { ordered = false; break; }
    }
    kat::check(ordered, "write-fifo: frames arrived in submission order, byte-identical");
}

// --- 2: the read loop, on a peer that writes bytes by hand -------------------
// A raw tcp::socket on the other end so the KAT can produce exactly the byte
// sequences a hostile peer would.
struct RawRig {
    asio::io_context io;
    tcp::socket      raw;
    Endpoint         ep;

    RawRig() : raw(io) {}

    void build(bool handshaked, std::size_t write_cap = 8u * 1024u * 1024u) {
        SocketPair p = connect_pair(io);
        raw = std::move(p.client);
        ep.sock = wrap(std::move(p.server), handshaked, write_cap);
        ep.wire(handshaked, write_cap);
        ep.sock->start();
        pump(io, 50);
    }

    void raw_write(const std::vector<std::uint8_t>& bytes) {
        boost::system::error_code ec;
        asio::write(raw, asio::buffer(bytes), ec);
    }
};

void test_header_then_body_split() {
    RawRig r;
    r.build(/*handshaked=*/true);

    auto body  = filler(4096, 7);
    auto frame = make_notify(CMD_NEW_FLUFFY_BLOCK, body);

    // Header alone first, then a pause, then the body: the reader must be
    // waiting on exactly `cb` more bytes, not on "whatever arrives next".
    std::vector<std::uint8_t> head(frame.begin(), frame.begin() + HEADER_SIZE);
    std::vector<std::uint8_t> tail(frame.begin() + HEADER_SIZE, frame.end());
    r.raw_write(head);
    pump(r.io, 100);
    kat::check(r.ep.frames.empty(), "split-read: nothing is delivered on a header alone");
    r.raw_write(tail);
    pump(r.io, 150);

    kat::checkf(r.ep.frames.size() == 1, "split-read: exactly one frame (%zu)",
                r.ep.frames.size());
    if (r.ep.frames.size() == 1)
        kat::check(r.ep.frames[0].body == body, "split-read: body is byte-identical");
    kat::check(!r.ep.closed, "split-read: the link stayed open");
}

void test_two_frames_in_one_write() {
    RawRig r;
    r.build(/*handshaked=*/true);

    auto b1 = filler(100, 1);
    auto b2 = filler(200, 2);
    auto f1 = make_notify(CMD_NEW_FLUFFY_BLOCK, b1);
    auto f2 = make_notify(CMD_NEW_TRANSACTIONS, b2);
    std::vector<std::uint8_t> both = f1;
    both.insert(both.end(), f2.begin(), f2.end());
    r.raw_write(both);
    pump(r.io, 200);

    kat::checkf(r.ep.frames.size() == 2, "coalesced: two frames out of one write (%zu)",
                r.ep.frames.size());
    if (r.ep.frames.size() == 2) {
        kat::check(r.ep.frames[0].body == b1 && r.ep.frames[1].body == b2,
                   "coalesced: both bodies intact and in order");
        kat::check(r.ep.frames[0].head.command == CMD_NEW_FLUFFY_BLOCK
                   && r.ep.frames[1].head.command == CMD_NEW_TRANSACTIONS,
                   "coalesced: commands preserved");
    }
}

void test_zero_length_body() {
    RawRig r;
    r.build(/*handshaked=*/true);
    // 1007 REQUEST_SUPPORT_FLAGS as monerod's own empty-body form would not be
    // zero-length (it is an empty epee section), but a cb == 0 frame is legal
    // at the transport layer and must not stall the reader.
    r.raw_write(make_notify(CMD_REQUEST_SUPPORT_FLAGS, {}));
    pump(r.io, 150);
    kat::checkf(r.ep.frames.size() == 1, "cb0: a zero-length body is delivered (%zu)",
                r.ep.frames.size());
    if (r.ep.frames.size() == 1)
        kat::check(r.ep.frames[0].body.empty() && r.ep.frames[0].head.cb == 0,
                   "cb0: delivered with an empty body");
    kat::check(!r.ep.closed, "cb0: the reader re-armed rather than stalling");
}

void test_bad_signature_closes_without_resync() {
    RawRig r;
    r.build(/*handshaked=*/true);

    auto frame = make_notify(CMD_NEW_FLUFFY_BLOCK, filler(64, 3));
    frame[0] ^= 0xff;                      // break Bender's nightmare
    // Append a PERFECTLY VALID frame right behind it. A reader that resynced by
    // scanning for the next signature would deliver this one; the discipline is
    // that it must not.
    auto good = make_notify(CMD_NEW_FLUFFY_BLOCK, filler(64, 4));
    frame.insert(frame.end(), good.begin(), good.end());
    r.raw_write(frame);
    pump(r.io, 200);

    kat::check(r.ep.closed, "bad-signature: the connection closed");
    kat::check(r.ep.close_why.find("BadSignature") != std::string::npos,
               "bad-signature: closed for the right reason");
    kat::check(r.ep.frames.empty(), "bad-signature: nothing was delivered, no resync");
}

void test_body_cap_enforced() {
    RawRig r;
    r.build(/*handshaked=*/true);

    // Claim a body one byte above the 2003 cap (4 KiB) and send NOTHING after
    // the header. The reader must refuse on the header alone -- refusing only
    // after buffering the body is the allocation an attacker is buying.
    BucketHead h;
    h.cb      = DEFAULT_CAPS.request_get_objects + 1;
    h.command = CMD_REQUEST_GET_OBJECTS;
    h.flags   = PACKET_REQUEST;
    std::vector<std::uint8_t> hdr;
    write_header(h, hdr);
    r.raw_write(hdr);
    pump(r.io, 200);

    kat::check(r.ep.closed, "cap: an over-cap header closes the connection");
    kat::check(r.ep.close_why.find("BodyTooLarge") != std::string::npos,
               "cap: closed for BodyTooLarge");
    kat::check(r.ep.frames.empty(), "cap: nothing delivered");
}

void test_pre_handshake_command_gate() {
    // Before the handshake only 1001 and 1007 are legal, whatever their size.
    RawRig r;
    r.build(/*handshaked=*/false);
    r.raw_write(make_notify(CMD_NEW_FLUFFY_BLOCK, filler(64, 5)));
    pump(r.io, 200);
    kat::check(r.ep.closed, "pre-handshake: a 2008 before the handshake closes the link");
    kat::check(r.ep.close_why.find("UnsupportedCommand") != std::string::npos,
               "pre-handshake: closed for UnsupportedCommand");

    // And after the cap flip the very same frame is fine.
    RawRig r2;
    r2.build(/*handshaked=*/false);
    r2.ep.sock->set_handshaked(true);
    pump(r2.io, 50);
    r2.raw_write(make_notify(CMD_NEW_FLUFFY_BLOCK, filler(64, 5)));
    pump(r2.io, 200);
    kat::check(!r2.ep.closed, "cap flip: the same frame is accepted after the handshake");
    kat::checkf(r2.ep.frames.size() == 1, "cap flip: the frame was delivered (%zu)",
                r2.ep.frames.size());
}

void test_pre_handshake_size_ceiling() {
    // 2008's own cap is 4 MiB, but pre-handshake the 256 KiB packet ceiling
    // also applies and min() wins. Use 1001, which IS legal pre-handshake, so
    // the refusal can only come from the size rule.
    RawRig r;
    r.build(/*handshaked=*/false);
    BucketHead h;
    h.cb      = MONEROD_INITIAL_MAX_PACKET_SIZE + 1;
    h.command = CMD_HANDSHAKE;
    h.flags   = PACKET_REQUEST;
    h.have_to_return_data = true;
    std::vector<std::uint8_t> hdr;
    write_header(h, hdr);
    r.raw_write(hdr);
    pump(r.io, 200);
    kat::check(r.ep.closed && r.ep.close_why.find("BodyTooLarge") != std::string::npos,
               "pre-handshake ceiling: 256 KiB + 1 on a legal command is refused");
}

void test_fragment_refused_on_clearnet() {
    RawRig r;
    r.build(/*handshaked=*/true);
    BucketHead h;
    h.cb      = 0;
    h.command = CMD_NEW_FLUFFY_BLOCK;
    h.flags   = PACKET_BEGIN;    // neither REQUEST nor RESPONSE: a fragment
    std::vector<std::uint8_t> hdr;
    write_header(h, hdr);
    r.raw_write(hdr);
    pump(r.io, 200);
    kat::check(r.ep.closed && r.ep.close_why.find("FragmentOnClearnet") != std::string::npos,
               "fragment: refused on a clearnet link");
}

// --- 3: the outbound queue cap -----------------------------------------------
// core::Socket leaves its queue uncapped because a dropped sharechain message
// is a lost share. Here a full queue means the peer stopped reading, and the
// never-silent-drop rule wants that surfaced as a false return -- not absorbed.
void test_write_queue_cap() {
    RawRig r;
    r.build(/*handshaked=*/true, /*write_cap=*/64 * 1024);

    // Do NOT pump: with no io_context turns nothing drains, so the queue fills.
    int accepted = 0, refused = 0;
    for (int i = 0; i < 16; ++i) {
        if (r.ep.sock->send(make_notify(CMD_NEW_FLUFFY_BLOCK, filler(16 * 1024, 9))))
            ++accepted;
        else
            ++refused;
    }
    kat::checkf(refused > 0, "queue cap: an over-full queue refuses (accepted %d, refused %d)",
                accepted, refused);
    kat::check(accepted > 0, "queue cap: it accepts up to the cap first");
    const auto st = r.ep.sock->stats();
    kat::checkf(st.frames_dropped_full == static_cast<std::uint64_t>(refused),
                "queue cap: every refusal is counted (%llu vs %d)",
                static_cast<unsigned long long>(st.frames_dropped_full), refused);

    // A frame shorter than a header is not a frame.
    kat::check(!r.ep.sock->send(std::vector<std::uint8_t>(10, 0)),
               "queue cap: a sub-header buffer is refused outright");
}

// --- 4: the lifetime guard ---------------------------------------------------
// Written as the use-after-free it prevents: the frame handler dereferences a
// RAW pointer to an owner object that the test frees while a read is in flight.
// With the guard, the callback aborts before the handler runs. Without it, this
// is a heap-use-after-free -- which is why this check is worth having on the
// sanitizer CI leg specifically.
struct Owner {
    int  frames_seen = 0;
    bool alive       = true;
};

void test_owner_freed_midflight() {
    asio::io_context io;
    SocketPair p = connect_pair(io);
    tcp::socket raw = std::move(p.client);

    auto sock  = wrap(std::move(p.server), /*handshaked=*/true);
    auto owner = std::make_shared<Owner>();
    Owner* raw_owner = owner.get();

    sock->set_owner_lifetime(std::weak_ptr<void>(owner));
    sock->set_frame_handler([raw_owner](const BucketHead&, const std::uint8_t*, std::size_t) {
        ++raw_owner->frames_seen;            // the dangling access, if unguarded
    });
    sock->set_close_handler([raw_owner](const std::string&) {
        raw_owner->alive = false;            // likewise
    });
    sock->start();
    pump(io, 50);

    // Free the owner with a read pending, then feed the socket a frame.
    owner.reset();
    {
        auto frame = make_notify(CMD_NEW_FLUFFY_BLOCK, filler(128, 11));
        boost::system::error_code ec;
        asio::write(raw, asio::buffer(frame), ec);
    }
    pump(io, 200);

    kat::check(sock->closed(),
               "lifetime: a callback that finds its owner freed aborts the connection");

    // And the same on the write path: a queued write completing after the owner
    // is gone must not reach the close handler either.
    kat::check(!sock->send(make_notify(CMD_NEW_FLUFFY_BLOCK, filler(8, 1))),
               "lifetime: send on the aborted socket is refused");
}

void test_unmanaged_owner_is_opt_out() {
    // An EMPTY weak_ptr means "no lifetime tracking" -- the escape hatch
    // core::Socket keeps for unmanaged nodes. It must not accidentally behave
    // like a freed owner, or every socket without an owner would abort at once.
    RawRig r;
    r.build(/*handshaked=*/true);
    r.ep.sock->set_owner_lifetime(std::weak_ptr<void>{});
    r.raw_write(make_notify(CMD_NEW_FLUFFY_BLOCK, filler(64, 12)));
    pump(r.io, 200);
    kat::check(!r.ep.closed, "lifetime: an unmanaged owner does not abort the link");
    kat::checkf(r.ep.frames.size() == 1, "lifetime: unmanaged owner still delivers (%zu)",
                r.ep.frames.size());
}

// --- 5: the RandomX fence, measured ------------------------------------------
// The rule is that a frame handler runs on the io thread and only there,
// because a RandomX evaluation on that thread would stall every other peer on
// the same io_context. Run the loop on a dedicated thread and compare ids.
void test_handler_runs_on_io_thread() {
    asio::io_context io;
    SocketPair p = connect_pair(io);
    tcp::socket raw = std::move(p.client);

    auto sock = wrap(std::move(p.server), /*handshaked=*/true);
    std::atomic<bool>            saw{false};
    std::atomic<bool>            on_io{false};
    std::thread::id              handler_thread{};
    std::atomic<bool>            have_thread{false};

    sock->set_frame_handler([&](const BucketHead&, const std::uint8_t*, std::size_t) {
        handler_thread = std::this_thread::get_id();
        have_thread.store(true, std::memory_order_release);
        on_io.store(sock->on_io_thread(), std::memory_order_release);
        saw.store(true, std::memory_order_release);
    });
    sock->start();

    // connect_pair() ran the loop to completion, which leaves the io_context in
    // its stopped state; run() on a stopped context returns at once and the
    // frame would never be delivered.
    io.restart();
    auto guard = asio::make_work_guard(io);
    std::thread io_thread([&io]() { io.run(); });
    const std::thread::id io_thread_id = io_thread.get_id();
    const std::thread::id main_thread_id = std::this_thread::get_id();

    {
        auto frame = make_notify(CMD_NEW_FLUFFY_BLOCK, filler(64, 13));
        boost::system::error_code ec;
        asio::write(raw, asio::buffer(frame), ec);
    }
    for (int i = 0; i < 100 && !saw.load(std::memory_order_acquire); ++i)
        std::this_thread::sleep_for(std::chrono::milliseconds(10));

    kat::check(saw.load(std::memory_order_acquire), "io-thread: the frame was delivered");
    kat::check(on_io.load(std::memory_order_acquire),
               "io-thread: on_io_thread() is true inside the handler");
    if (have_thread.load(std::memory_order_acquire)) {
        kat::check(handler_thread == io_thread_id,
                   "io-thread: the handler ran on the io_context thread");
        kat::check(handler_thread != main_thread_id,
                   "io-thread: and not on the thread that submitted the work");
    }
    kat::check(!sock->on_io_thread(),
               "io-thread: on_io_thread() is false off the io thread");

    sock->close("done");
    guard.reset();
    io.stop();
    io_thread.join();
}

// --- 6: close is idempotent and reported once --------------------------------
void test_close_once() {
    RawRig r;
    r.build(/*handshaked=*/true);
    int closes = 0;
    r.ep.sock->set_close_handler([&](const std::string&) { ++closes; });
    r.ep.sock->close("first");
    r.ep.sock->close("second");
    pump(r.io, 150);
    kat::checkf(closes == 1, "close: the close handler fires exactly once (%d)", closes);
    kat::check(r.ep.sock->closed(), "close: the socket reports itself closed");
    kat::check(!r.ep.sock->send(make_notify(CMD_NEW_FLUFFY_BLOCK, {})),
               "close: send after close is refused");
}

// --- 7: the wire tap sees both directions ------------------------------------
void test_wire_tap() {
    asio::io_context io;
    SocketPair p = connect_pair(io);

    auto tx = wrap(std::move(p.client), true);
    Endpoint rx;
    rx.sock = wrap(std::move(p.server), true);
    rx.wire(true);

    std::vector<std::vector<std::uint8_t>> out_frames, in_frames;
    tx->set_wire_tap([&](bool outbound, const std::uint8_t* f, std::size_t n) {
        (outbound ? out_frames : in_frames).emplace_back(f, f + n);
    });
    rx.sock->set_wire_tap([&](bool outbound, const std::uint8_t* f, std::size_t n) {
        (outbound ? out_frames : in_frames).emplace_back(f, f + n);
    });

    tx->start();
    rx.sock->start();

    auto frame = make_notify(CMD_NEW_FLUFFY_BLOCK, filler(256, 21));
    tx->send(frame);
    for (int i = 0; i < 20 && rx.frames.empty(); ++i) pump(io, 50);

    kat::checkf(out_frames.size() == 1, "tap: one outbound frame captured (%zu)",
                out_frames.size());
    kat::checkf(in_frames.size() == 1, "tap: one inbound frame captured (%zu)",
                in_frames.size());
    if (out_frames.size() == 1 && in_frames.size() == 1) {
        kat::check(out_frames[0] == frame, "tap: outbound bytes are the frame as sent");
        kat::check(in_frames[0] == frame,
                   "tap: inbound bytes match, header and body, for the C6 parity diff");
    }
}

} // namespace

int main() {
    test_write_fifo();
    test_header_then_body_split();
    test_two_frames_in_one_write();
    test_zero_length_body();
    test_bad_signature_closes_without_resync();
    test_body_cap_enforced();
    test_pre_handshake_command_gate();
    test_pre_handshake_size_ceiling();
    test_fragment_refused_on_clearnet();
    test_write_queue_cap();
    test_owner_freed_midflight();
    test_unmanaged_owner_is_opt_out();
    test_handler_runs_on_io_thread();
    test_close_once();
    test_wire_tap();
    return kat::report("xmr_levin_socket_kat");
}
