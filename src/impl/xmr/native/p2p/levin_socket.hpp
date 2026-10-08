// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/native/p2p/levin_socket.hpp
//
// Wave 1, component C1b: the levin TRANSPORT. One TCP connection, framed by
// C1a's 33-byte bucket header, on the node's own boost::asio io_context.
//
// WHY A NEW SOCKET AND NOT core::Socket. core::Socket (src/core/socket.hpp,
// src/core/socket.cpp) is hard-wired to Bitcoin framing -- a 4-byte network
// prefix, a 12-byte command string, a u32 length and a u32 checksum, assembled
// by core::Packet -- and core::Factory<core::Client> builds exactly that. Levin
// has no prefix, no command string and no checksum. What core::Socket has that
// is worth far more than its framing is THREE DISCIPLINES, each of which was
// paid for with a production incident, and all three are reproduced here:
//
//   1. READ LOOP. Read exactly the header, validate it, bound the body by the
//      cap that applies to THAT command in THAT handshake state, read exactly
//      that many bytes, dispatch, re-arm. A malformed header closes the
//      connection: we never resync by scanning for the next signature, because
//      a scanning reader is a reader an attacker can steer.
//
//   2. WRITE QUEUE (issue #863). Asio forbids starting a second COMPOSED write
//      on a descriptor before the first completes -- the two continuations are
//      serviced FIFO per descriptor, so a message needing more than one round
//      gets the other message's bytes spliced into its middle. On the Bitcoin
//      side that silently lost shares. Here it would corrupt every frame after
//      the splice, since levin has no checksum to catch it and the reader would
//      close on a bad signature. So: at most ONE composed async_write in flight
//      per socket, the queue drains strictly in submission order, and the next
//      write starts only from the previous completion handler.
//
//   3. LIFETIME. The owner's lock-per-async-op pattern from
//      core/socket.cpp::acquire_node and core/factory.hpp: every async callback
//      locks a weak_ptr to its owner at entry, and a callback that finds the
//      owner freed mid-flight aborts the connection instead of dereferencing a
//      dangling pointer. This is the fix for the Bug-9 use-after-free family.
//
// ONE DELIBERATE DIVERGENCE from core::Socket: its write queue is uncapped, on
// the grounds that dropping a queued sharechain message loses a share
// permanently. Here the queue is capped in bytes and send() returns false when
// it is full. The reason the trade flips: our outbound traffic is a handshake,
// a 60-second TIMED_SYNC and the occasional block push, so a queue growing past
// megabytes means the peer has stopped reading -- and the never-silent-drop
// rule in contracts/broadcast.hpp wants that reported as a loud failure with a
// peer count, not absorbed into unbounded memory.
//
// THREADING. All asio work runs on the io thread. send() may be called from any
// thread (C5 pushes a found block from the block path), so the queue is guarded
// by a leaf mutex and the drain is POSTED to the executor -- unlike
// core::Socket, which starts the composed write inline on the caller's thread.
// Posting keeps every operation on this socket object confined to one thread,
// which is what makes the single-io-thread model actually true rather than
// nearly true.
//
// RANDOMX NEVER RUNS ON THE IO THREAD. LightVerifier is not thread-safe
// (xmr_o2_randomx_verify.hpp) and a RandomX evaluation is milliseconds to
// hundreds of milliseconds; running one here would stall every other peer on
// the same io_context and let a single crafted push wedge the node. This file
// enforces the rule structurally: it includes no verifier, calls nothing that
// hashes, and its frame handler contract is "classify and enqueue, never
// verify". on_io_thread() is exposed so a consumer can assert the boundary in a
// KAT instead of trusting a comment.
//
// SCOPE FENCE (standing XMR-lane rule): everything under src/impl/xmr/. This
// tree is a WORK SOURCE for the pool, not part of the v37 share-chain record;
// nothing here activates v37 consensus and src/sharechain/v37 is not touched.
//
// Header-only. STL plus boost::asio.
// ---------------------------------------------------------------------------
#pragma once

#include <atomic>
#include <cstdint>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include <boost/asio.hpp>

#include "impl/xmr/native/p2p/levin_codec.hpp"

namespace c2pool::xmr::native::levin {

// A frame as delivered to the consumer. The body pointer is valid ONLY for the
// duration of the callback: it points into the socket's read buffer, which is
// reused by the next read. A consumer that needs the bytes copies them.
using FrameHandler = std::function<void(const BucketHead& head,
                                        const std::uint8_t* body,
                                        std::size_t         body_size)>;

// Called exactly once per socket, on the io thread, when the connection ends --
// for any reason, including our own close(). `why` is a human sentence.
using CloseHandler = std::function<void(const std::string& why)>;

// Raw wire tap for the C6 parity oracle: every complete frame, in both
// directions, exactly as it appears on the wire. Off unless installed.
using WireTap = std::function<void(bool outbound,
                                   const std::uint8_t* frame,
                                   std::size_t         frame_size)>;

class LevinSocket : public std::enable_shared_from_this<LevinSocket> {
public:
    using tcp = boost::asio::ip::tcp;

    struct Options {
        HeaderPolicy policy{};                                  // caps + strictness
        std::size_t  max_write_queue_bytes = 8u * 1024u * 1024u;
        bool         tcp_keepalive         = true;
    };

    struct Stats {
        std::uint64_t bytes_in    = 0;
        std::uint64_t bytes_out   = 0;
        std::uint64_t frames_in   = 0;
        std::uint64_t frames_out  = 0;
        std::uint64_t frames_dropped_full = 0;
    };

    // Factory: shared_ptr-only, because every async callback captures a
    // shared_from_this() and a stack-allocated one would be a crash waiting for
    // the first completion.
    static std::shared_ptr<LevinSocket> create(tcp::socket sock, Options opt) {
        return std::shared_ptr<LevinSocket>(new LevinSocket(std::move(sock), std::move(opt)));
    }

    ~LevinSocket() = default;

    LevinSocket(const LevinSocket&)            = delete;
    LevinSocket& operator=(const LevinSocket&) = delete;

    // --- wiring, all before start() ------------------------------------------
    void set_frame_handler(FrameHandler h) { frame_handler_ = std::move(h); }
    void set_close_handler(CloseHandler h) { close_handler_ = std::move(h); }
    void set_wire_tap(WireTap t)           { tap_ = std::move(t); }

    // Discipline 3. `owner` is a weak_ptr to whatever object owns the callbacks
    // installed above (LevinLink, in practice). If it is non-empty at the time
    // of this call, every async callback locks it first and aborts the
    // connection when the lock fails, so a callback can never reach into a
    // freed owner. An empty weak_ptr means "unmanaged owner", which skips the
    // check -- the same escape hatch core::Socket keeps for the legacy
    // unmanaged pool nodes, and the same rule: it is opt-out, never default.
    void set_owner_lifetime(std::weak_ptr<void> owner) {
        owner_lifetime_ = std::move(owner);
        owner_managed_  = (owner_lifetime_.lock() != nullptr);
    }

    // --- lifecycle ------------------------------------------------------------
    // Arms the read loop. Safe to call from any thread: the work is posted to
    // the io thread, which is also where the io-thread identity is recorded.
    void start() {
        auto self = shared_from_this();
        boost::asio::post(socket_.get_executor(), [self]() { self->do_start(); });
    }

    // Queues a complete frame (33-byte header + body, as produced by C1a's
    // make_invoke / make_notify / make_response). Returns false when the socket
    // is closed or the outbound queue is full; a false return is a real event
    // the caller must report, never a shrug.
    bool send(std::vector<std::uint8_t> frame) {
        if (frame.size() < HEADER_SIZE) return false;
        bool start_drain = false;
        {
            std::lock_guard<std::mutex> lock(write_mutex_);
            if (closed_.load(std::memory_order_acquire)) return false;
            if (write_queued_bytes_ + frame.size() > opt_.max_write_queue_bytes) {
                ++stats_.frames_dropped_full;
                return false;
            }
            write_queued_bytes_ += frame.size();
            write_queue_.push_back(std::make_shared<std::vector<std::uint8_t>>(std::move(frame)));
            if (!writing_) { writing_ = true; start_drain = true; }
        }
        if (start_drain) {
            // Outside the lock, and posted rather than started inline: the leaf
            // lock is never held across asio work, and every operation on this
            // socket stays on the io thread.
            auto self = shared_from_this();
            boost::asio::post(socket_.get_executor(), [self]() { self->do_write(); });
        }
        return true;
    }

    // Ends the connection. Idempotent, safe from any thread; the close handler
    // fires exactly once, on the io thread.
    void close(const std::string& why) {
        auto self = shared_from_this();
        boost::asio::post(socket_.get_executor(),
                          [self, why]() { self->do_close(why); });
    }

    // Discipline 1's cap flip: pre-handshake every frame is bounded by 256 KiB
    // and only 1001/1007 are legal at all; after the handshake the per-command
    // table in C1a applies. Posted, so the policy is only ever mutated on the
    // io thread that reads it.
    void set_handshaked(bool v) {
        auto self = shared_from_this();
        boost::asio::post(socket_.get_executor(),
                          [self, v]() { self->opt_.policy.handshaked = v; });
    }

    // --- observation ----------------------------------------------------------
    bool closed() const noexcept { return closed_.load(std::memory_order_acquire); }

    // True only when called from the io thread that runs this socket. The
    // RandomX fence is asserted with this rather than assumed.
    bool on_io_thread() const noexcept {
        return io_thread_known_.load(std::memory_order_acquire)
            && std::this_thread::get_id() == io_thread_;
    }

    // Snapshot. The counters are mutated only on the io thread, so read them
    // from there (or after io_context::run has returned, which is what the KATs
    // do); reading them from another thread while the loop runs is a data race.
    Stats stats() const { return stats_; }

    const std::string& remote() const noexcept { return remote_; }

    boost::asio::any_io_executor executor() { return socket_.get_executor(); }

private:
    LevinSocket(tcp::socket sock, Options opt)
        : socket_(std::move(sock)), opt_(std::move(opt)) {
        boost::system::error_code ec;
        const auto ep = socket_.remote_endpoint(ec);
        remote_ = ec ? std::string("<unconnected>")
                     : ep.address().to_string() + ":" + std::to_string(ep.port());
    }

    // Discipline 3, the lock itself. Returns false when the owner was managed
    // and has since been freed.
    bool acquire_owner(std::shared_ptr<void>& strong_out) {
        strong_out = owner_lifetime_.lock();
        if (!owner_managed_) return true;
        return strong_out != nullptr;
    }

    void do_start() {
        io_thread_ = std::this_thread::get_id();
        io_thread_known_.store(true, std::memory_order_release);

        if (opt_.tcp_keepalive && socket_.is_open()) {
            // Liveness only; never alters bytes on the wire. Same rationale as
            // core/socket.cpp::init -- a DPI-wedged flow can hold a pending
            // async_read open for tens of minutes with no FIN and no RST.
            boost::system::error_code kec;
            socket_.set_option(boost::asio::socket_base::keep_alive(true), kec);
        }
        do_read_header();
    }

    // --- discipline 1: read exactly the header, then exactly the body ---------
    void do_read_header() {
        if (closed_.load(std::memory_order_acquire) || !socket_.is_open()) return;
        auto self = shared_from_this();
        boost::asio::async_read(
            socket_, boost::asio::buffer(header_buf_, HEADER_SIZE),
            [self](const boost::system::error_code& ec, std::size_t n) {
                self->on_header(ec, n);
            });
    }

    void on_header(const boost::system::error_code& ec, std::size_t n) {
        if (closed_.load(std::memory_order_acquire)) return;
        std::shared_ptr<void> strong_owner;
        if (!acquire_owner(strong_owner)) { abort_connection(); return; }
        (void)strong_owner;   // keeps the owner alive for this scope

        if (ec) { do_close("read header: " + ec.message()); return; }
        stats_.bytes_in += n;

        HeaderError herr = HeaderError::None;
        if (!read_header(header_buf_, HEADER_SIZE, opt_.policy, head_, herr)) {
            // Never resync. A header we cannot trust means every byte after it
            // is of unknown provenance.
            do_close(std::string("bad levin header: ") + to_string(herr)
                     + " (command " + command_name(head_.command) + ")");
            return;
        }

        const std::size_t cb = static_cast<std::size_t>(head_.cb);
        if (cb == 0) { deliver(nullptr, 0); return; }

        // read_header already bounded cb by the cap for this command and
        // handshake state, so this resize cannot be steered by the peer.
        body_buf_.resize(cb);
        auto self = shared_from_this();
        boost::asio::async_read(
            socket_, boost::asio::buffer(body_buf_.data(), cb),
            [self](const boost::system::error_code& bec, std::size_t bn) {
                self->on_body(bec, bn);
            });
    }

    void on_body(const boost::system::error_code& ec, std::size_t n) {
        if (closed_.load(std::memory_order_acquire)) return;
        std::shared_ptr<void> strong_owner;
        if (!acquire_owner(strong_owner)) { abort_connection(); return; }
        (void)strong_owner;

        if (ec) { do_close("read body: " + ec.message()); return; }
        stats_.bytes_in += n;
        deliver(body_buf_.data(), n);
    }

    void deliver(const std::uint8_t* body, std::size_t size) {
        ++stats_.frames_in;
        if (tap_) {
            // The tap wants the frame as it was on the wire: header then body.
            tap_frame_.assign(header_buf_, header_buf_ + HEADER_SIZE);
            if (body && size) tap_frame_.insert(tap_frame_.end(), body, body + size);
            tap_(false, tap_frame_.data(), tap_frame_.size());
        }
        if (frame_handler_) frame_handler_(head_, body, size);
        // The handler may have closed us (a protocol violation, a matcher
        // failure); re-arming a closed socket is a no-op by the guard above.
        do_read_header();
    }

    // --- discipline 2: one composed write in flight, FIFO drain ---------------
    void do_write() {
        // The front buffer is held by shared_ptr, not by a reference into the
        // deque: send() runs on other threads and fail_write_queue() can empty
        // the deque, and a raw element pointer surviving either would be the
        // same class of bug the lifetime discipline exists to prevent.
        std::shared_ptr<std::vector<std::uint8_t>> front;
        {
            std::lock_guard<std::mutex> lock(write_mutex_);
            if (write_queue_.empty()) { writing_ = false; return; }
            front = write_queue_.front();
        }
        if (closed_.load(std::memory_order_acquire) || !socket_.is_open()) {
            fail_write_queue();
            return;
        }
        if (tap_) tap_(true, front->data(), front->size());

        auto self = shared_from_this();
        boost::asio::async_write(
            socket_, boost::asio::buffer(front->data(), front->size()),
            [self, front](const boost::system::error_code& ec, std::size_t n) {
                self->on_written(ec, n);
            });
    }

    void on_written(const boost::system::error_code& ec, std::size_t n) {
        std::shared_ptr<void> strong_owner;
        if (!acquire_owner(strong_owner)) { abort_connection(); return; }
        (void)strong_owner;

        if (ec) {
            // A failed write kills the connection, so nothing still queued
            // behind it could ever be delivered: drop the chain and report
            // once, exactly as a single failed write did before a queue existed.
            fail_write_queue();
            do_close("write: " + ec.message());
            return;
        }
        stats_.bytes_out += n;
        ++stats_.frames_out;
        {
            std::lock_guard<std::mutex> lock(write_mutex_);
            if (!write_queue_.empty()) {
                write_queued_bytes_ -= write_queue_.front()->size();
                write_queue_.pop_front();
            }
        }
        // The NEXT composed write starts only from here. Not unbounded
        // recursion: async_write never invokes its handler inline from the
        // initiating call, so each do_write() returns before the next runs.
        do_write();
    }

    void fail_write_queue() {
        std::lock_guard<std::mutex> lock(write_mutex_);
        write_queue_.clear();
        write_queued_bytes_ = 0;
        writing_ = false;
    }

    // --- teardown -------------------------------------------------------------
    void do_close(const std::string& why) {
        if (closed_.exchange(true, std::memory_order_acq_rel)) return;
        boost::system::error_code ec;
        socket_.cancel(ec);   // benign on an already-reset socket
        socket_.close(ec);
        fail_write_queue();
        if (close_handler_) {
            // The owner may be gone; the handler is only reached through the
            // same lock every other callback uses.
            std::shared_ptr<void> strong_owner;
            if (acquire_owner(strong_owner)) {
                (void)strong_owner;
                close_handler_(why);
            }
        }
    }

    // Owner freed mid-flight: tear the transport down without touching any
    // installed callback, since the callbacks live in the freed owner.
    void abort_connection() {
        if (closed_.exchange(true, std::memory_order_acq_rel)) return;
        boost::system::error_code ec;
        socket_.cancel(ec);
        socket_.close(ec);
        fail_write_queue();
    }

    tcp::socket socket_;
    Options     opt_;
    std::string remote_;

    FrameHandler frame_handler_;
    CloseHandler close_handler_;
    WireTap      tap_;

    std::weak_ptr<void> owner_lifetime_;
    bool                owner_managed_ = false;

    std::uint8_t              header_buf_[HEADER_SIZE]{};
    BucketHead                head_{};
    std::vector<std::uint8_t> body_buf_;
    std::vector<std::uint8_t> tap_frame_;

    mutable std::mutex write_mutex_;
    std::deque<std::shared_ptr<std::vector<std::uint8_t>>> write_queue_;
    std::size_t write_queued_bytes_ = 0;
    bool        writing_ = false;

    std::atomic<bool> closed_{false};
    std::atomic<bool> io_thread_known_{false};
    std::thread::id   io_thread_{};

    Stats stats_{};
};

} // namespace c2pool::xmr::native::levin
