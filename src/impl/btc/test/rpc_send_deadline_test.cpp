// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// NodeRPC Send() deadline KATs (P0-SUBMIT-CSMAIN, .234 wedge).
//
// Send() runs synchronously on the ioc thread, which also carries stratum,
// sharechain P2P and header sync. A daemon that accepts the connection and
// then never answers (bitcoind parked on cs_main under a submitblock flood)
// must not park the ioc: every RPC has to come back within the deadline.
//
// The old deadline was SO_RCVTIMEO on a blocking socket. On Linux asio's sync
// recv treats the EAGAIN that the kernel timeout produces as would_block and
// falls through to poll(fd, -1), so the call waited as long as the daemon did
// (rig: 178 s ioc stall behind one 178 s submitblock, zero "read failed"
// lines). These KATs drive a real NodeRPC over loopback against a fake daemon
// that swallows requests.
// ---------------------------------------------------------------------------

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <climits>
#include <future>
#include <memory>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#include <boost/asio.hpp>
#include <boost/beast.hpp>

#include <core/netaddress.hpp>
#include "../coin/rpc.hpp"

namespace
{

using ms = std::chrono::milliseconds;

// Short deadline so the suite stays fast; production is RPC_IO_TIMEOUT_SECONDS.
constexpr ms kDeadline{1000};
// A call that has not returned by now is hung, not slow.
constexpr ms kHangCap{6000};

// Loopback "bitcoind". Requests with index < answer_from are read and then
// swallowed (connection held open, never answered); later ones get a JSON-RPC
// null result, i.e. submitblock accepted.
class FakeDaemon
{
public:
    explicit FakeDaemon(int answer_from)
        : m_acceptor(m_io, {io::ip::make_address("127.0.0.1"), 0}),
          m_answer_from(answer_from)
    {
        m_port = m_acceptor.local_endpoint().port();
        accept();
        m_thread = std::thread([this] { m_io.run(); });
    }
    ~FakeDaemon() { shutdown(); }

    uint16_t port() const { return m_port; }
    int requests() const { return m_requests.load(); }
    std::size_t last_body_size() const { return m_last_body.load(); }

    // Close the listener and every held connection. A client parked in recv
    // sees EOF, so this also unblocks a hung Send().
    void shutdown()
    {
        if (!m_thread.joinable())
            return;
        io::post(m_io, [this] {
            boost::system::error_code ec;
            m_acceptor.close(ec);
            for (auto& s : m_sessions)
                s->sock.close(ec);
            m_io.stop();
        });
        m_thread.join();
    }

private:
    struct Session
    {
        explicit Session(io::ip::tcp::socket s) : sock(std::move(s)) {}
        io::ip::tcp::socket sock;
        beast::flat_buffer buf;
        std::optional<http::request_parser<http::string_body>> parser;
        http::response<http::string_body> res;
    };

    void accept()
    {
        m_acceptor.async_accept([this](boost::system::error_code ec, io::ip::tcp::socket s) {
            if (ec)
                return;
            auto session = std::make_shared<Session>(std::move(s));
            m_sessions.push_back(session);
            read(session);
            accept();
        });
    }

    void read(std::shared_ptr<Session> s)
    {
        s->parser.emplace();
        s->parser->body_limit(boost::none);   // multi-MB submitblock bodies
        http::async_read(s->sock, s->buf, *s->parser, [this, s](boost::system::error_code ec, std::size_t) {
            if (ec)
                return;
            const int idx = m_requests++;
            m_last_body = s->parser->get().body().size();
            if (idx < m_answer_from)
                return;   // swallow: never answer, keep the connection open
            s->res = {http::status::ok, 11};
            s->res.set(http::field::content_type, "application/json");
            s->res.keep_alive(true);
            s->res.body() = R"({"jsonrpc":"2.0","result":null,"id":"curltest"})";
            s->res.prepare_payload();
            http::async_write(s->sock, s->res, [this, s](boost::system::error_code ec, std::size_t) {
                if (!ec)
                    read(s);
            });
        });
    }

    io::io_context m_io;
    io::ip::tcp::acceptor m_acceptor;
    const int m_answer_from;
    uint16_t m_port{};
    std::vector<std::shared_ptr<Session>> m_sessions;
    std::atomic<int> m_requests{0};
    std::atomic<std::size_t> m_last_body{0};
    std::thread m_thread;
};

// NodeRPC plus the ioc it is bound to. The ioc is never run: Send() is
// synchronous, and connect() only needs to stage the endpoint and auth
// header before sync_reconnect() opens the socket.
struct Client
{
    io::io_context ioc;
    btc::coin::NodeRPC rpc{&ioc, nullptr, /*testnet=*/true};

    explicit Client(uint16_t port)
    {
        rpc.set_io_timeout(kDeadline);
        rpc.connect(NetService("127.0.0.1", port), "user:pass");
        rpc.sync_reconnect();
    }
};

struct Timed
{
    ms took;
    bool result;   // fn's return value; false if it threw
};

// Run `fn` on a worker and time it. Returns nullopt if it has not returned
// within kHangCap; `unblock` is then called and the worker is given one more
// kHangCap to unwind before being detached (it owns everything it touches),
// so a regression fails the test instead of hanging the suite.
template <class Fn, class Unblock>
std::optional<Timed> timed_call(std::shared_ptr<Client> client, Fn fn, Unblock unblock)
{
    auto done = std::make_shared<std::promise<bool>>();
    auto fut = done->get_future();
    const auto t0 = std::chrono::steady_clock::now();
    std::thread worker([client, fn, done] {
        bool result = false;
        try { result = fn(client->rpc); } catch (...) {}
        done->set_value(result);
    });
    if (fut.wait_for(kHangCap) == std::future_status::ready)
    {
        worker.join();
        return Timed{std::chrono::duration_cast<ms>(std::chrono::steady_clock::now() - t0), fut.get()};
    }
    unblock();
    if (fut.wait_for(kHangCap) == std::future_status::ready)
        worker.join();
    else
        worker.detach();
    return std::nullopt;
}

} // namespace

// The regression: a daemon that accepts, reads the submitblock and never
// answers. Send() must give up at the deadline, not wait for the daemon, and
// must NOT re-send (the daemon has the block; a second copy would queue behind
// cs_main again). The next call reconnects and gets a normal answer.
TEST(BtcRpcSendDeadline, SilentDaemonSubmitblockReturnsWithinDeadline)
{
    FakeDaemon daemon(/*answer_from=*/1);
    auto client = std::make_shared<Client>(daemon.port());

    const auto submit = [](btc::coin::NodeRPC& rpc) { return rpc.submit_block_hex(std::string(160, '0'), true); };
    const auto unblock = [&daemon] { daemon.shutdown(); };

    auto first = timed_call(client, submit, unblock);
    ASSERT_TRUE(first.has_value())
        << "submitblock to a silent daemon did not return within "
        << kHangCap.count() << " ms (deadline " << kDeadline.count() << " ms)";
    EXPECT_GE(first->took.count(), kDeadline.count() * 9 / 10) << "gave up before the deadline";
    EXPECT_LT(first->took.count(), kDeadline.count() + 1500) << "overran the deadline";
    EXPECT_FALSE(first->result);
    EXPECT_EQ(daemon.requests(), 1) << "a delivered submitblock was re-sent";

    // Recovery: the timed-out connection was dropped, so the late reply can
    // never be read as this call's answer; the call reconnects and succeeds.
    // A DIFFERENT block: the first one was delivered, so submit_flood_gate.hpp
    // dedupes a re-submit of it instead of sending it again.
    const auto submit_next = [](btc::coin::NodeRPC& rpc) { return rpc.submit_block_hex(std::string(160, '1'), true); };
    auto again = timed_call(client, submit_next, unblock);
    ASSERT_TRUE(again.has_value());
    EXPECT_TRUE(again->result);
    EXPECT_EQ(daemon.requests(), 2);

    // The delivered first block is never re-sent, even after the reconnect.
    auto dup = timed_call(client, submit, unblock);
    ASSERT_TRUE(dup.has_value());
    EXPECT_TRUE(dup->result) << "delivered-unknown counts as reached";
    EXPECT_EQ(daemon.requests(), 2) << "a delivered submitblock was re-sent";
}

// Same bound for a read-only call: the deadline lives in Send(), so every RPC
// on the ioc (getblocktemplate from getwork, check() on connect) gets it.
TEST(BtcRpcSendDeadline, SilentDaemonGetblocktemplateReturnsWithinDeadline)
{
    FakeDaemon daemon(/*answer_from=*/INT_MAX);
    auto client = std::make_shared<Client>(daemon.port());

    auto took = timed_call(client,
        [](btc::coin::NodeRPC& rpc) { rpc.getblocktemplate({"segwit"}); return true; },
        [&daemon] { daemon.shutdown(); });

    ASSERT_TRUE(took.has_value())
        << "getblocktemplate to a silent daemon did not return within " << kHangCap.count() << " ms";
    EXPECT_LT(took->took.count(), kDeadline.count() + 1500);
    EXPECT_FALSE(took->result);
    EXPECT_EQ(daemon.requests(), 1);
}

// Positive control: a mainnet-sized block (4 MB hex) against an answering
// daemon. The request is larger than the socket send buffer, so the write
// has to wait for the daemon to drain it; that must still complete.
TEST(BtcRpcSendDeadline, AnsweringDaemonLargeSubmitblockRoundTrips)
{
    FakeDaemon daemon(/*answer_from=*/0);
    auto client = std::make_shared<Client>(daemon.port());

    const std::string block_hex(4 * 1000 * 1000, '0');
    auto took = timed_call(client,
        [block_hex](btc::coin::NodeRPC& rpc) { return rpc.submit_block_hex(block_hex, true); },
        [&daemon] { daemon.shutdown(); });

    ASSERT_TRUE(took.has_value());
    EXPECT_TRUE(took->result);
    EXPECT_EQ(daemon.requests(), 1);
    EXPECT_GT(daemon.last_body_size(), block_hex.size());
}
