// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// An empty login is asked about too (rides core_test).
//
// mining.authorize asked the work source's authorize_refusal only for a
// non-empty login, so a work source that cannot build shares for an empty one
// (DGB: no redistribution of empty logins) could not tell the miner and served
// it no work. Now the empty login is asked too. A work source without a reason
// (the default: LTC, DASH, BTC, BIP110; BCH returns none for an empty login,
// bch work_source_authorize_refusal_test) keeps today's outcome.
// Through a real core::StratumServer on 127.0.0.1.
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
#include <functional>
#include <future>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

namespace {

struct LoginSource : core::stratum::IWorkSource {
    core::stratum::StratumConfig cfg;
    std::function<std::string(const std::string&)> refusal;   // unset: the default (none)
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
    uint32_t get_share_bits() const override { return 0x207fffff; }
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
    std::string authorize_refusal(const std::string& username) const override
    {
        {
            std::lock_guard<std::mutex> l(mu);
            asked.push_back(username);
        }
        return refusal ? refusal(username) : std::string();
    }
};

uint16_t free_port_login()
{
    boost::asio::io_context io;
    boost::asio::ip::tcp::acceptor a(io, {boost::asio::ip::make_address("127.0.0.1"), 0});
    return a.local_endpoint().port();
}

struct LoginClient {
    int fd = -1;
    std::string buf;
    explicit LoginClient(uint16_t port)
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
    ~LoginClient()
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
                if (j.contains("id") && j["id"].is_number() && j["id"].get<int>() == id)
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

// mining.authorize with `login` against `ws`; the response.
nlohmann::json authorize(const std::shared_ptr<LoginSource>& ws, const std::string& login)
{
    boost::asio::io_context ioc;
    auto guard = boost::asio::make_work_guard(ioc);
    const uint16_t port = free_port_login();
    auto srv = std::make_unique<core::StratumServer>(ioc, "127.0.0.1", port, ws);
    EXPECT_TRUE(srv->start());
    std::thread io([&] { ioc.run(); });
    nlohmann::json out;
    {
        LoginClient c(port);
        EXPECT_GE(c.fd, 0);
        c.send({{"id", 1}, {"method", "mining.subscribe"}, {"params", nlohmann::json::array()}});
        EXPECT_TRUE(c.wait(1).has_value());
        c.send({{"id", 2}, {"method", "mining.authorize"}, {"params", {login, "x"}}});
        if (auto r = c.wait(2))
            out = *r;
    }
    std::promise<void> done;
    boost::asio::post(ioc, [&] { srv->stop(); done.set_value(); });
    done.get_future().wait();
    guard.reset();
    ioc.stop();
    io.join();
    return out;
}

bool authorized(const nlohmann::json& r)
{
    return r.contains("result") && r["result"].is_boolean() && r["result"].get<bool>();
}

void bitcoin_like_acceptance(core::stratum::StratumConfig& cfg)
{
    cfg.payout_p2pkh_versions = {0x00};
    cfg.payout_p2sh_versions = {0x05};
    cfg.payout_bech32_hrps = {"bc"};
}

} // namespace

// A work source without a reason (the default): an empty login is authorized
// as before, with and without redistribution of unusable logins (the LTC pool
// redistributes; DASH, BTC, BIP110 do not).
TEST(StratumEmptyLogin, DefaultWorkSourceKeepsTodaysOutcome)
{
    for (bool redistribute : {false, true}) {
        SCOPED_TRACE(redistribute);
        auto ws = std::make_shared<LoginSource>();
        bitcoin_like_acceptance(ws->cfg);
        ws->cfg.redistribute_unusable_logins = redistribute;
        const auto r = authorize(ws, "");
        ASSERT_FALSE(r.is_null()) << "no reply to mining.authorize";
        EXPECT_TRUE(authorized(r)) << r.dump();
        // The default had no reason for the empty login it was asked about.
        std::lock_guard<std::mutex> l(ws->mu);
        ASSERT_FALSE(ws->asked.empty());
        EXPECT_EQ(ws->asked.back(), "");
    }
}

// A work source with a reason for an empty login: the miner is told.
TEST(StratumEmptyLogin, WorkSourceCanRefuseAnEmptyLogin)
{
    auto ws = std::make_shared<LoginSource>();
    bitcoin_like_acceptance(ws->cfg);
    ws->refusal = [](const std::string& u) { return u.empty() ? std::string("give a payout address") : std::string(); };
    const auto r = authorize(ws, "");
    ASSERT_FALSE(r.is_null()) << "no reply to mining.authorize";
    EXPECT_FALSE(authorized(r)) << r.dump();
    ASSERT_TRUE(r.contains("error") && r["error"].is_array()) << r.dump();
    EXPECT_EQ(r["error"][0].get<int>(), 24);
    EXPECT_NE(r["error"][1].get<std::string>().find("give a payout address"), std::string::npos) << r.dump();

    // A valid login on the same source is not refused.
    auto ok = std::make_shared<LoginSource>();
    bitcoin_like_acceptance(ok->cfg);
    ok->refusal = ws->refusal;
    EXPECT_TRUE(authorized(authorize(ok, "1BoatSLRHtKNngkdXEeobR76b53LETtpyT")));
}
