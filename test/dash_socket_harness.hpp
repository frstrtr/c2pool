// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Real-socket harness for DASH pool-node wire KATs, shared by the
// test_dash_node sources (test_dash_addrme.cpp, test_dash_standing_forget.cpp).
//
// Drives REAL NodeImpl / dash::Legacy code over a real loopback TCP pair and
// reads back the exact frames the node put on the wire — the capture-level
// evidence a codec round-trip KAT cannot give (a handler can be registered,
// compile, and never write the frame). Extracted verbatim from
// test_dash_addrme.cpp (#882) so a second wire KAT does not duplicate it.

#pragma once

#include <gtest/gtest.h>

#include <impl/dash/node.hpp>
#include <impl/dash/config.hpp>
#include <impl/dash/messages.hpp>

#include <core/netaddress.hpp>
#include <core/packet.hpp>
#include <core/socket.hpp>
#include <core/uint256.hpp>

#include <boost/asio.hpp>

#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <memory>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

namespace dash_socket_harness {

using boost::asio::ip::tcp;

// Wire header written by core::Packet::from_message (src/core/packet.hpp:22):
//   prefix(N) | command(12, NUL-padded) | length(4, LE) | checksum(4) | payload
inline constexpr std::size_t kCommandLen  = 12;
inline constexpr std::size_t kLengthLen   = 4;
inline constexpr std::size_t kChecksumLen = 4;

inline const std::vector<std::byte>& test_prefix()
{
    // Arbitrary but fixed: the framing prefix is a per-net constant and is not
    // what this KAT is about. Same shape as core/test/socket_write_queue_test.cpp.
    static const std::vector<std::byte> prefix{
        std::byte{0xfc}, std::byte{0xc1}, std::byte{0xb7}, std::byte{0xdc}};
    return prefix;
}

// Minimal ICommunicator for core::Socket. On the WRITE path the socket only
// needs get_prefix(); error() covers the failure path. Constructed with an empty
// weak_ptr<INetwork> and was_managed=false, i.e. the legacy unmanaged-node path,
// so acquire_node() short-circuits to true and no INetwork is required.
struct StubCommunicator : public core::ICommunicator
{
    std::atomic<int> error_count{0};

    void error(const message_error_type&, const NetService&,
               const std::source_location = std::source_location::current()) override
    {
        error_count.fetch_add(1, std::memory_order_relaxed);
    }
    void error(const boost::system::error_code&, const NetService&,
               const std::source_location = std::source_location::current()) override
    {
        error_count.fetch_add(1, std::memory_order_relaxed);
    }
    void handle(std::unique_ptr<RawMessage>, const NetService&) override {}
    const std::vector<std::byte>& get_prefix() const override { return test_prefix(); }
};

// Real loopback TCP pair. `ours` is the end the node writes to (wrapped in a
// core::Socket and handed to a pool::Peer); `theirs` is the peer end, read
// synchronously so the test sees exactly the bytes that went on the wire.
struct LoopbackPair
{
    boost::asio::io_context ioc_peer;
    boost::asio::io_context ioc_node;
    std::unique_ptr<tcp::acceptor> acceptor;
    std::unique_ptr<tcp::socket> theirs;
    std::unique_ptr<tcp::socket> ours;

    // bind_addr defaults to the loopback HOST address (127.0.0.1). A test that
    // needs a source the Legacy self-probe treats as ROUTABLE binds to another
    // 127.0.0.0/8 address (e.g. 127.0.0.2): still loopback at the OS level, so it
    // is bindable without privilege, but NOT the string the self-probe compares
    // against — so the accepted peer presents a non-"127.0.0.1" source and the
    // handler takes the else (routable) arm. See the #925 case below.
    explicit LoopbackPair(const std::string& bind_addr = "127.0.0.1")
    {
        acceptor = std::make_unique<tcp::acceptor>(
            ioc_peer, tcp::endpoint(boost::asio::ip::make_address(bind_addr), 0));
        acceptor->listen();

        ours = std::make_unique<tcp::socket>(ioc_node);
        ours->connect(acceptor->local_endpoint());

        theirs = std::make_unique<tcp::socket>(acceptor->accept());

        boost::system::error_code ec;
        ours->set_option(tcp::no_delay(true), ec);
        theirs->set_option(tcp::no_delay(true), ec);
    }
};

// Runs an io_context on its own thread for the lifetime of the scope — the
// production shape: writes are submitted from the caller's thread and drained
// by the io thread.
struct IoThread
{
    boost::asio::executor_work_guard<boost::asio::io_context::executor_type> guard;
    std::thread thread;

    explicit IoThread(boost::asio::io_context& ioc)
        : guard(boost::asio::make_work_guard(ioc)), thread([&ioc] { ioc.run(); })
    {
    }
    void stop(boost::asio::io_context& ioc)
    {
        guard.reset();
        ioc.stop();
        if (thread.joinable()) thread.join();
    }
};

struct Frame
{
    std::string command;                 // trimmed of NUL padding
    std::vector<std::byte> payload;
};

// Drains up to `budget` bytes from a synchronous socket, stopping early once the
// socket goes quiet, then splits the stream into wire frames. Bounded by a read
// deadline so a missing message fails the assertion instead of hanging CI.
inline std::vector<Frame> read_frames(tcp::socket& s, std::chrono::milliseconds quiet_for)
{
    std::vector<std::byte> buf;
    const auto deadline = std::chrono::steady_clock::now() + quiet_for;

    // Non-blocking drain: poll until the deadline, accumulating whatever the
    // node wrote. There is no length prefix at the stream level to key off, so a
    // time budget is the honest stop condition.
    s.non_blocking(true);
    while (std::chrono::steady_clock::now() < deadline)
    {
        std::array<std::byte, 4096> chunk{};
        boost::system::error_code ec;
        const std::size_t n = s.read_some(boost::asio::buffer(chunk), ec);
        if (n > 0)
            buf.insert(buf.end(), chunk.begin(), chunk.begin() + n);
        else if (ec == boost::asio::error::would_block)
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        else if (ec)
            break;
    }

    std::vector<Frame> frames;
    const std::size_t prefix_len = test_prefix().size();
    const std::size_t header = prefix_len + kCommandLen + kLengthLen + kChecksumLen;
    std::size_t off = 0;
    while (off + header <= buf.size())
    {
        // Prefix must match or the stream is not what we think it is.
        if (std::memcmp(buf.data() + off, test_prefix().data(), prefix_len) != 0)
            break;

        const auto* cmd = reinterpret_cast<const char*>(buf.data() + off + prefix_len);
        std::string command(cmd, kCommandLen);
        if (const auto z = command.find('\0'); z != std::string::npos)
            command.resize(z);

        std::uint32_t len = 0;
        std::memcpy(&len, buf.data() + off + prefix_len + kCommandLen, kLengthLen);

        if (off + header + len > buf.size())
            break;

        Frame f;
        f.command = std::move(command);
        f.payload.assign(buf.begin() + off + header, buf.begin() + off + header + len);
        frames.push_back(std::move(f));

        off += header + len;
    }
    return frames;
}

inline const Frame* find_frame(const std::vector<Frame>& frames, std::string_view command)
{
    for (const auto& f : frames)
        if (f.command == command) return &f;
    return nullptr;
}

inline dash::NodeImpl::peer_ptr make_socket_peer(LoopbackPair& pair, StubCommunicator& stub)
{
    auto sock = std::make_shared<core::Socket>(
        std::move(pair.ours), core::outgoing, &stub,
        std::weak_ptr<core::INetwork>{}, /*was_managed=*/false);
    // init() latches m_addr from the REAL remote endpoint — this is where
    // peer->addr().address() gets its value on the live path.
    sock->init();
    return std::make_shared<dash::NodeImpl::peer_t>(sock);
}

inline std::unique_ptr<RawMessage> make_version(std::uint64_t nonce,
                                                std::string sub_version)
{
    return dash::message_version::make_raw(
        dash::SharechainConfig::MINIMUM_PROTOCOL_VERSION,          // exactly at the cold floor
        std::uint64_t{0},                                          // services
        addr_t(1u, NetService("192.168.1.1", 9999)),          // addr_to
        addr_t(1u, NetService("192.168.1.2", 8888)),          // addr_from
        nonce,
        std::move(sub_version),
        1u,                                                        // mode
        uint256());                                                // best_share = null
}

} // namespace dash_socket_harness
