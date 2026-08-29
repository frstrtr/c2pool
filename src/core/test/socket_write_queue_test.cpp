// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Outbound write-queue KAT for core::Socket (issue #863).
//
// Before the queue landed, core::Socket::write started a composed
// boost::asio::async_write IMMEDIATELY. Asio forbids initiating a second
// composed write on a descriptor before the first completes: the two
// async_write_some continuations are serviced FIFO per descriptor, so any
// message needing more than one round has bytes from the other message spliced
// into its middle. The peer then sees a bad length/checksum and drops us.
//
// Every coin hits this: send_shares issues three back-to-back writes on ONE
// socket in ONE handler turn (remember_tx -> shares -> forget_tx) —
// dash/node.cpp:1346/1357/1362, ltc:756/777/784, btc:757/778/785,
// dgb:737/758/765, bch:760/781/788 — and handle_version writes getaddrs/addrme
// before the (potentially ~32 KB) have_tx advert. Because send_shares reports
// its hashes as "sent" on SUBMISSION and broadcast_share never retries, a
// spliced frame silently loses that share to that peer forever.
//
// These tests drive a real loopback TCP pair with a deliberately small send
// buffer so every message needs many write_some rounds — the exact condition
// under which the pre-fix code interleaved. They FAIL without the queue.
//
// Folded into the EXISTING allowlisted core_test target, never a standalone
// add_executable: a target absent from build.yml's --target list is never built
// in CI and CTest reports its cases "Not Run" (the #769 trap).

#include <gtest/gtest.h>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <thread>
#include <vector>

#include <boost/asio.hpp>

#include <core/hash.hpp>
#include <core/message.hpp>
#include <core/netaddress.hpp>
#include <core/packet.hpp>
#include <core/socket.hpp>

namespace {

using boost::asio::ip::tcp;

// Small enough that a multi-hundred-KB message needs many write_some rounds,
// which is precisely when overlapping composed writes splice each other.
constexpr int kSmallSocketBuf = 4096;

// Wire header layout written by core::Packet::from_message:
//   prefix(N) | command(12) | length(4, LE) | checksum(4, first word of Hash)
constexpr size_t kCommandLen  = 12;
constexpr size_t kLengthLen   = 4;
constexpr size_t kChecksumLen = 4;

const std::vector<std::byte>& test_prefix()
{
    static const std::vector<std::byte> prefix{
        std::byte{0xfc}, std::byte{0xc1}, std::byte{0xb7}, std::byte{0xdc}};
    return prefix;
}

// Minimal ICommunicator: core::Socket only needs get_prefix() on the write
// path, plus error() for the failure path. Constructed with an empty
// weak_ptr<INetwork> and was_managed=false, i.e. the legacy unmanaged-node
// path, so acquire_node() short-circuits to true and no INetwork is needed.
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

// A message whose payload is `size` copies of `fill` — distinct per message so
// a splice is visible as a byte mismatch at a known offset.
std::unique_ptr<RawMessage> make_msg(const char* command, uint8_t fill, size_t size)
{
    std::vector<std::byte> payload(size, std::byte{fill});
    return std::make_unique<RawMessage>(command, PackStream(std::span<const std::byte>(payload)));
}

std::vector<std::byte> framed_bytes(const char* command, uint8_t fill, size_t size)
{
    auto msg = make_msg(command, fill, size);
    auto stream = core::Packet::from_message(test_prefix(), msg);
    return std::vector<std::byte>(stream.data(), stream.data() + stream.size());
}

// Loopback TCP pair. The reader lives on its own io_context and is only ever
// used synchronously, so the writer's io_context can be run from a dedicated
// thread — which is also how the bug is reachable in production: node/compute
// threads submit writes while the io thread drains them.
struct LoopbackPair
{
    boost::asio::io_context ioc_reader;
    boost::asio::io_context ioc_writer;
    std::unique_ptr<tcp::acceptor> acceptor;
    std::unique_ptr<tcp::socket> reader;
    std::unique_ptr<tcp::socket> writer;

    LoopbackPair()
    {
        acceptor = std::make_unique<tcp::acceptor>(
            ioc_reader, tcp::endpoint(boost::asio::ip::make_address("127.0.0.1"), 0));
        acceptor->listen();

        writer = std::make_unique<tcp::socket>(ioc_writer);
        writer->connect(acceptor->local_endpoint());

        reader = std::make_unique<tcp::socket>(acceptor->accept());

        boost::system::error_code ec;
        // ONLY the send buffer is squeezed: that is what forces async_write to
        // need many write_some rounds, which is the condition under which two
        // overlapping composed writes splice each other. The RECEIVE buffer is
        // left at the default on purpose — shrinking it below the 64 KB
        // loopback MSS collapses the receive window and the transfer crawls.
        writer->set_option(boost::asio::socket_base::send_buffer_size(kSmallSocketBuf), ec);
        writer->set_option(tcp::no_delay(true), ec);
        reader->set_option(tcp::no_delay(true), ec);
    }
};

// Runs the writer io_context on its own thread for the lifetime of the scope.
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

// Reads exactly n bytes from a synchronous socket.
std::vector<std::byte> read_exact(tcp::socket& s, size_t n)
{
    std::vector<std::byte> buf(n);
    boost::system::error_code ec;
    size_t got = boost::asio::read(s, boost::asio::buffer(buf.data(), n), ec);
    buf.resize(got);
    return buf;
}

size_t first_mismatch(const std::vector<std::byte>& a, const std::vector<std::byte>& b)
{
    size_t n = std::min(a.size(), b.size());
    for (size_t i = 0; i < n; ++i)
        if (a[i] != b[i]) return i;
    return (a.size() == b.size()) ? std::string::npos : n;
}

} // namespace

// ─────────────────────────────────────────────────────────────────────────────
// 1. The regression itself: overlapping writes must arrive concatenated in
//    submission order, with no interleaving. Fails without the queue.
// ─────────────────────────────────────────────────────────────────────────────
TEST(SocketWriteQueue, OverlappingWritesArriveConcatenatedInSubmissionOrder)
{
    // Mirrors send_shares' three back-to-back writes on one socket in one
    // handler turn, sized so each needs many write_some rounds.
    constexpr size_t kPayload = 256 * 1024;
    const struct { const char* cmd; uint8_t fill; } kMsgs[] = {
        {"remember_tx", 0xA1},
        {"shares",      0xB2},
        {"forget_tx",   0xC3},
        {"have_tx",     0xD4},
    };

    LoopbackPair pair;
    StubCommunicator stub;

    std::vector<std::byte> expected;
    for (const auto& m : kMsgs)
    {
        auto frame = framed_bytes(m.cmd, m.fill, kPayload);
        expected.insert(expected.end(), frame.begin(), frame.end());
    }

    auto sock = std::make_shared<core::Socket>(
        std::move(pair.writer), core::outgoing, &stub,
        std::weak_ptr<core::INetwork>{}, /*was_managed=*/false);

    IoThread io(pair.ioc_writer);

    // Submitted from the TEST thread, not the io thread — the production shape.
    for (const auto& m : kMsgs)
        sock->write(make_msg(m.cmd, m.fill, kPayload));

    auto received = read_exact(*pair.reader, expected.size());

    io.stop(pair.ioc_writer);

    ASSERT_EQ(received.size(), expected.size())
        << "short read: the stream was corrupted or truncated";
    size_t bad = first_mismatch(expected, received);
    EXPECT_EQ(bad, std::string::npos)
        << "byte streams diverge at offset " << bad
        << " -- overlapping composed writes spliced bytes mid-message "
        << "(expected 0x" << std::hex << (bad < expected.size() ? (int)expected[bad] : 0)
        << ", got 0x" << (bad < received.size() ? (int)received[bad] : 0) << std::dec << ")";
    EXPECT_EQ(stub.error_count.load(), 0);
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. Thread-safety: writes submitted concurrently from many threads must still
//    produce WHOLE frames (relative order across threads is not defined, but no
//    frame may ever be spliced). Fails without the queue.
// ─────────────────────────────────────────────────────────────────────────────
TEST(SocketWriteQueue, ConcurrentWritersProduceWholeFrames)
{
    constexpr int kThreads = 4;
    constexpr int kPerThread = 3;
    constexpr size_t kPayload = 64 * 1024;
    constexpr int kTotal = kThreads * kPerThread;

    LoopbackPair pair;
    StubCommunicator stub;

    const size_t frame_size = framed_bytes("shares", 0x00, kPayload).size();

    auto sock = std::make_shared<core::Socket>(
        std::move(pair.writer), core::outgoing, &stub,
        std::weak_ptr<core::INetwork>{}, /*was_managed=*/false);

    IoThread io(pair.ioc_writer);

    std::vector<std::thread> writers;
    writers.reserve(kThreads);
    for (int t = 0; t < kThreads; ++t)
    {
        writers.emplace_back([&sock, t] {
            for (int i = 0; i < kPerThread; ++i)
                sock->write(make_msg("shares",
                                     static_cast<uint8_t>(t * kPerThread + i + 1),
                                     kPayload));
        });
    }
    for (auto& w : writers) w.join();

    auto received = read_exact(*pair.reader, frame_size * kTotal);

    io.stop(pair.ioc_writer);

    ASSERT_EQ(received.size(), frame_size * kTotal);

    // Walk the stream frame by frame. Every frame must carry the right prefix,
    // a uniform payload (its fill byte), and a checksum matching that payload.
    const size_t prefix_len = test_prefix().size();
    const size_t header_len = prefix_len + kCommandLen + kLengthLen + kChecksumLen;
    std::set<uint8_t> seen_fills;

    for (int f = 0; f < kTotal; ++f)
    {
        const std::byte* p = received.data() + static_cast<size_t>(f) * frame_size;

        ASSERT_EQ(0, std::memcmp(p, test_prefix().data(), prefix_len))
            << "frame " << f << " has a corrupt prefix -- bytes were spliced";

        uint32_t length = 0;
        std::memcpy(&length, p + prefix_len + kCommandLen, kLengthLen);
        ASSERT_EQ(length, kPayload) << "frame " << f << " has a corrupt length field";

        uint32_t checksum = 0;
        std::memcpy(&checksum, p + prefix_len + kCommandLen + kLengthLen, kChecksumLen);

        const std::byte* payload = p + header_len;
        const uint8_t fill = static_cast<uint8_t>(payload[0]);
        for (size_t i = 1; i < kPayload; ++i)
            ASSERT_EQ(static_cast<uint8_t>(payload[i]), fill)
                << "frame " << f << " payload is not uniform at " << i
                << " -- another message was spliced into it";

        uint256 h = Hash(std::span<const std::byte>(payload, kPayload));
        EXPECT_EQ(checksum, h.pn[0]) << "frame " << f << " checksum mismatch";

        EXPECT_TRUE(seen_fills.insert(fill).second)
            << "duplicate frame payload " << (int)fill;
    }

    EXPECT_EQ(seen_fills.size(), static_cast<size_t>(kTotal))
        << "not every submitted message reached the wire intact";
    EXPECT_EQ(stub.error_count.load(), 0);
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. No behaviour change for the single-write case: byte-identical framing.
// ─────────────────────────────────────────────────────────────────────────────
TEST(SocketWriteQueue, SingleWriteIsByteIdentical)
{
    constexpr size_t kPayload = 1024;

    LoopbackPair pair;
    StubCommunicator stub;

    auto expected = framed_bytes("shares", 0x5A, kPayload);

    auto sock = std::make_shared<core::Socket>(
        std::move(pair.writer), core::outgoing, &stub,
        std::weak_ptr<core::INetwork>{}, /*was_managed=*/false);

    IoThread io(pair.ioc_writer);
    sock->write(make_msg("shares", 0x5A, kPayload));

    auto received = read_exact(*pair.reader, expected.size());
    io.stop(pair.ioc_writer);

    ASSERT_EQ(received.size(), expected.size());
    EXPECT_EQ(first_mismatch(expected, received), std::string::npos);
    EXPECT_EQ(stub.error_count.load(), 0);
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. Close/error semantics preserved: writes queued onto an already-closed
//    socket are dropped silently, exactly as the pre-queue no-op did, and the
//    socket does not wedge with a stuck in-flight flag.
// ─────────────────────────────────────────────────────────────────────────────
TEST(SocketWriteQueue, WritesOnClosedSocketAreDroppedWithoutError)
{
    LoopbackPair pair;
    StubCommunicator stub;

    auto sock = std::make_shared<core::Socket>(
        std::move(pair.writer), core::outgoing, &stub,
        std::weak_ptr<core::INetwork>{}, /*was_managed=*/false);

    IoThread io(pair.ioc_writer);

    sock->close();
    for (int i = 0; i < 5; ++i)
        sock->write(make_msg("shares", static_cast<uint8_t>(i), 512));

    io.stop(pair.ioc_writer);

    EXPECT_EQ(stub.error_count.load(), 0)
        << "write() on a closed socket must stay a silent no-op";
}
