// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// Seeded start difficulty (rides core_test).
//
// IWorkSource::start_difficulty: a session whose login names no difficulty
// (no "+N", no password "d=N", no mining.suggest_difficulty) starts, at its
// first authorize, at the work source's difficulty (INTERNAL units, applied as
// the difficulty hint). The default (0) keeps today's start at the vardiff
// floor. Through a real core::StratumServer on 127.0.0.1.
// ---------------------------------------------------------------------------

#include <core/stratum_server.hpp>
#include <core/stratum_work_source.hpp>
#include <core/uint256.hpp>

#include <boost/asio/executor_work_guard.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/post.hpp>
#include <gtest/gtest.h>
#include <nlohmann/json.hpp>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <chrono>
#include <cmath>
#include <functional>
#include <future>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

namespace {

struct SeedSource : core::stratum::IWorkSource {
    core::stratum::StratumConfig cfg;
    double seed = 0.0;   // start_difficulty (0: the default)
    mutable std::mutex mu;
    mutable std::vector<std::string> asked;

    const core::stratum::StratumConfig& get_stratum_config() const override { return cfg; }
    std::function<uint256()> get_best_share_hash_fn() const override { return [] { return uint256(); }; }
    std::string get_current_gbt_prevhash() const override { return std::string(64, '1'); }
    uint64_t get_work_generation() const override { return 1; }
    bool has_merged_chain(uint32_t) const override { return false; }
    void register_stratum_worker(const std::string&, const core::stratum::WorkerInfo&) override {}
    void unregister_stratum_worker(const std::string&) override {}
    void update_stratum_worker(const std::string&, double, double, double, uint64_t, uint64_t, uint64_t) override {}
    nlohmann::json get_current_work_template() const override
    {
        return {{"bits", "207fffff"}, {"previousblockhash", std::string(64, '1')}, {"version", 0x20000000},
                {"curtime", 1793210000}, {"height", 100}};
    }
    std::vector<std::string> get_stratum_merkle_branches() const override { return {}; }
    std::pair<std::string, std::string> get_coinbase_parts() const override { return {"01000000", "00000000"}; }
    core::stratum::CoinbaseResult build_connection_coinbase(
        const uint256&, const std::string&, const std::vector<unsigned char>&,
        const std::vector<std::pair<uint32_t, std::vector<unsigned char>>>&) const override
    {
        core::stratum::CoinbaseResult r;
        r.coinb1 = "01000000";
        r.coinb2 = "00000000";
        return r;
    }
    nlohmann::json mining_submit(const std::string&, const std::string&, const std::string&, const std::string&,
                                 const std::string&, const std::string&, const std::string&,
                                 const std::map<uint32_t, std::vector<unsigned char>>&,
                                 const core::stratum::JobSnapshot*) override
    {
        return nlohmann::json(true);
    }
    uint32_t get_share_bits() const override { return 0x1d00ffff; }   // pool-share ceiling: difficulty 1
    uint32_t get_share_max_bits() const override { return 0x207fffff; }
    double compute_share_difficulty(const std::string&, const std::string&, const std::string&, const std::string&,
                                    const std::string&, const std::string&, uint32_t, const std::string&,
                                    const std::string&, const std::vector<std::string>&) const override
    {
        return 0.0;
    }
    void record_best_pseudoshare(double, const std::string&, const std::string&, const std::string&,
                                 const std::string&, const std::string&, const std::string&, const std::string&,
                                 uint32_t, const std::string&, const std::string&,
                                 const std::vector<std::string>&) override {}
    double start_difficulty(const core::stratum::PayoutKey&) const override { return seed; }
};

uint16_t free_port_seed()
{
    boost::asio::io_context io;
    boost::asio::ip::tcp::acceptor a(io, {boost::asio::ip::make_address("127.0.0.1"), 0});
    return a.local_endpoint().port();
}

struct SeedClient {
    int fd = -1;
    std::string buf;
    std::vector<double> difficulties;   // every mining.set_difficulty (wire)
    explicit SeedClient(uint16_t port)
    {
        fd = ::socket(AF_INET, SOCK_STREAM, 0);
        sockaddr_in a{};
        a.sin_family = AF_INET;
        a.sin_port = htons(port);
        a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        if (::connect(fd, reinterpret_cast<sockaddr*>(&a), sizeof a) != 0) {
            ::close(fd);
            fd = -1;
        }
        struct timeval tv{0, 50000};
        if (fd >= 0)
            setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    }
    ~SeedClient()
    {
        if (fd >= 0)
            ::close(fd);
    }
    void send(const nlohmann::json& j)
    {
        const std::string line = j.dump() + "\n";
        (void)::send(fd, line.data(), line.size(), MSG_NOSIGNAL);
    }
    std::optional<nlohmann::json> wait(int id, int ms = 3000)
    {
        const auto until = std::chrono::steady_clock::now() + std::chrono::milliseconds(ms);
        while (std::chrono::steady_clock::now() < until) {
            size_t nl;
            while ((nl = buf.find('\n')) != std::string::npos) {
                const std::string line = buf.substr(0, nl);
                buf.erase(0, nl + 1);
                nlohmann::json j;
                try { j = nlohmann::json::parse(line); } catch (...) { continue; }
                if (j.contains("method") && j["method"] == "mining.set_difficulty" && j["params"].is_array())
                    difficulties.push_back(j["params"][0].get<double>());
                if (id >= 0 && j.contains("id") && j["id"].is_number() && j["id"].get<int>() == id)
                    return j;
            }
            char tmp[16384];
            const ssize_t n = ::recv(fd, tmp, sizeof tmp, 0);
            if (n > 0)
                buf.append(tmp, static_cast<size_t>(n));
            if (n == 0)
                break;
        }
        return std::nullopt;
    }
};


// subscribe + authorize(login, password); every set_difficulty (wire) seen.
std::vector<double> session(double seed, const std::string& login, const std::string& password)
{
    auto ws = std::make_shared<SeedSource>();
    ws->seed = seed;
    boost::asio::io_context ioc;
    auto guard = boost::asio::make_work_guard(ioc);
    const uint16_t port = free_port_seed();
    auto srv = std::make_unique<core::StratumServer>(ioc, "127.0.0.1", port, ws);
    EXPECT_TRUE(srv->start());
    std::thread io([&] { ioc.run(); });
    std::vector<double> out;
    {
        SeedClient c(port);
        EXPECT_GE(c.fd, 0);
        c.send({{"id", 1}, {"method", "mining.subscribe"}, {"params", nlohmann::json::array()}});
        EXPECT_TRUE(c.wait(1).has_value());
        c.send({{"id", 2}, {"method", "mining.authorize"}, {"params", {login, password}}});
        EXPECT_TRUE(c.wait(2).has_value());
        c.wait(-1, 300);
        out = c.difficulties;
    }
    std::promise<void> done;
    boost::asio::post(ioc, [&] { srv->stop(); done.set_value(); });
    done.get_future().wait();
    guard.reset();
    ioc.stop();
    io.join();
    return out;
}

constexpr double kMult = 65536.0;   // StratumConfig::set_difficulty_multiplier default
const char* kLogin = "1BoatSLRHtKNngkdXEeobR76b53LETtpyT";

bool near(double a, double b) { return std::fabs(a - b) <= 1e-9 * std::max(1.0, std::fabs(b)); }

} // namespace

TEST(StratumStartDifficulty, DefaultKeepsTheVardiffFloor)
{
    const auto d = session(0.0, kLogin, "x");
    ASSERT_FALSE(d.empty());
    EXPECT_TRUE(near(d.back(), 0.0005 * kMult)) << d.back();
}

TEST(StratumStartDifficulty, SeedIsTheStartWhenTheLoginNamesNone)
{
    const auto d = session(0.25, kLogin, "x");
    ASSERT_FALSE(d.empty());
    EXPECT_TRUE(near(d.back(), 0.25 * kMult)) << d.back();
}

TEST(StratumStartDifficulty, LoginDifficultyKeepsPriority)
{
    // Password d=N (WIRE units).
    const auto pd = session(0.25, kLogin, "d=1024");
    ASSERT_FALSE(pd.empty());
    EXPECT_TRUE(near(pd.back(), 1024.0)) << pd.back();
    // "+N" (INTERNAL units), fixed.
    const auto fd = session(0.25, std::string(kLogin) + "+0.5", "x");
    ASSERT_FALSE(fd.empty());
    EXPECT_TRUE(near(fd.back(), 0.5 * kMult)) << fd.back();
}
