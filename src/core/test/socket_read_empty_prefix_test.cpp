// SPDX-License-Identifier: AGPL-3.0-or-later
//
// core::Socket's read path for a node whose network prefix is empty.
//
// Socket::read_prefix handed asio &packet->prefix[0]. operator[] on an empty
// std::vector is undefined behaviour; UBSan reports "reference binding to null
// pointer" (stl_vector.h) and the sanitizer build aborts as soon as such a
// socket starts reading. prefix.data() with size 0 is a valid empty buffer, so
// the 0-byte prefix read completes and the message is read as before.
//
// Every coin's prefix is non-empty, so production never read an empty one.
// The cases that reached it (DualFamilyDial.FactoryClient*, whose probe node
// has an empty prefix) skip on a host where localhost does not resolve to
// both ::1 and 127.0.0.1, which includes the CI runners; that is why the CI
// sanitizer leg never saw it. This case needs IPv4 loopback only.
//
// RED without the fix under -fsanitize=undefined (the CI ASan+UBSan leg): the
// process aborts in Socket::read_prefix. Folded into the existing core_test
// target, never a new add_executable (the #769 "Not Run" trap).

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <cstddef>
#include <memory>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

#include <boost/asio.hpp>

#include <core/hash.hpp>  // packet.hpp uses Hash without including it
#include <core/message.hpp>
#include <core/netaddress.hpp>
#include <core/packet.hpp>
#include <core/socket.hpp>

namespace {

using boost::asio::ip::tcp;

const std::vector<std::byte>& empty_prefix()
{
    static const std::vector<std::byte> p{};
    return p;
}

struct EmptyPrefixCommunicator : public core::ICommunicator
{
    std::mutex mu;
    std::vector<std::pair<std::string, size_t>> got;  // command, payload bytes
    std::atomic<int> errors{0};

    void error(const message_error_type&, const NetService&,
               const std::source_location = std::source_location::current()) override
    {
        errors.fetch_add(1, std::memory_order_relaxed);
    }
    void error(const boost::system::error_code&, const NetService&,
               const std::source_location = std::source_location::current()) override
    {
        errors.fetch_add(1, std::memory_order_relaxed);
    }
    void handle(std::unique_ptr<RawMessage> msg, const NetService&) override
    {
        std::lock_guard<std::mutex> lock(mu);
        got.emplace_back(std::string(msg->m_command.c_str()), msg->m_data.size());
    }
    const std::vector<std::byte>& get_prefix() const override { return empty_prefix(); }

    size_t count()
    {
        std::lock_guard<std::mutex> lock(mu);
        return got.size();
    }
};

std::vector<std::byte> frame(const char* command, size_t payload_bytes)
{
    std::vector<std::byte> payload(payload_bytes, std::byte{0x5a});
    auto msg = std::make_unique<RawMessage>(command, PackStream(std::span<const std::byte>(payload)));
    auto stream = core::Packet::from_message(empty_prefix(), msg);
    return std::vector<std::byte>(stream.data(), stream.data() + stream.size());
}

} // namespace

// Two messages from a peer on an empty-prefix network, the first with an
// empty payload (a 0-byte payload read as well): both reach handle().
TEST(SocketRead, AnEmptyPrefixNodeReadsItsPeersMessages)
{
    boost::asio::io_context ioc;
    tcp::acceptor acceptor(ioc, tcp::endpoint(boost::asio::ip::make_address("127.0.0.1"), 0));
    acceptor.listen();
    auto local = std::make_unique<tcp::socket>(ioc);
    local->connect(acceptor.local_endpoint());
    tcp::socket peer = acceptor.accept();

    EmptyPrefixCommunicator comm;
    auto sock = std::make_shared<core::Socket>(std::move(local), core::outgoing, &comm,
                                               std::weak_ptr<core::INetwork>{}, /*was_managed=*/false);
    sock->init();  // starts reading: a 0-byte prefix first

    std::vector<std::byte> wire = frame("ping", 0);
    const auto second = frame("version", 37);
    wire.insert(wire.end(), second.begin(), second.end());
    boost::asio::write(peer, boost::asio::buffer(wire.data(), wire.size()));

    const auto t0 = std::chrono::steady_clock::now();
    while (comm.count() < 2 && std::chrono::steady_clock::now() - t0 < std::chrono::seconds(5))
        ioc.run_for(std::chrono::milliseconds(20));

    {
        std::lock_guard<std::mutex> lock(comm.mu);
        ASSERT_EQ(comm.got.size(), 2u) << "the messages never reached handle()";
        EXPECT_EQ(comm.got[0].first, "ping");
        EXPECT_EQ(comm.got[0].second, 0u);
        EXPECT_EQ(comm.got[1].first, "version");
        EXPECT_EQ(comm.got[1].second, 37u);
    }
    EXPECT_EQ(comm.errors.load(), 0);

    sock->close();
    ioc.restart();
    ioc.poll();
}
