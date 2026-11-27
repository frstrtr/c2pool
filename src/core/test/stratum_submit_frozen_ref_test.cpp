// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// A job's frozen ref reaches mining_submit (rides core_test).
//
// The stratum session froze a job's share fields (absheight, bits, timestamp,
// ...) from the work source's coinbase result and handed them back with the
// submission (JobSnapshot::frozen_ref), but not the ref_hash the coinbase's
// OP_RETURN committed to nor its last_txout_nonce: those reached
// mining_submit as zero. A work source that checks or rebuilds the share at
// submit from them (DGB) then saw every real job as "not built here".
// Through a real core::StratumServer on 127.0.0.1: subscribe, authorize, the
// job, mining.submit; the snapshot carries the coinbase result's ref_hash and
// last_txout_nonce, and the job's other frozen fields as before.
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
#include <future>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

namespace {

const uint256 kRef(std::vector<unsigned char>(32, 0xab));
constexpr uint64_t kNonce = 0x0102030405060708ULL;

struct FrozenRefSource : core::stratum::IWorkSource {
    core::stratum::StratumConfig cfg;
    mutable std::mutex mu;
    std::vector<core::stratum::JobSnapshot> submits;

    const core::stratum::StratumConfig& get_stratum_config() const override { return cfg; }
    std::function<uint256()> get_best_share_hash_fn() const override
    {
        return [] { return uint256(std::vector<unsigned char>(32, 0x5b)); };
    }
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
        r.snapshot.subsidy = 777;
        r.snapshot.frozen_ref.ref_hash = kRef;
        r.snapshot.frozen_ref.last_txout_nonce = kNonce;
        r.snapshot.frozen_ref.absheight = 4242;
        r.snapshot.frozen_ref.bits = 0x207fffff;
        r.snapshot.frozen_ref.max_bits = 0x207fffff;
        r.snapshot.frozen_ref.timestamp = 1793210001;
        return r;
    }
    nlohmann::json mining_submit(const std::string&, const std::string&, const std::string&, const std::string&,
                                 const std::string&, const std::string&, const std::string&,
                                 const std::map<uint32_t, std::vector<unsigned char>>&,
                                 const core::stratum::JobSnapshot* job) override
    {
        std::lock_guard<std::mutex> l(mu);
        if (job)
            submits.push_back(*job);
        return nlohmann::json(true);
    }
    uint32_t get_share_bits() const override { return 0x207fffff; }
    uint32_t get_share_max_bits() const override { return 0x207fffff; }
    double compute_share_difficulty(const std::string&, const std::string&, const std::string&, const std::string&,
                                    const std::string&, const std::string&, uint32_t, const std::string&,
                                    const std::string&, const std::vector<std::string>&) const override
    {
        return 1e15;   // every submission is a share
    }
    void record_best_pseudoshare(double, const std::string&, const std::string&, const std::string&,
                                 const std::string&, const std::string&, const std::string&, const std::string&,
                                 uint32_t, const std::string&, const std::string&,
                                 const std::vector<std::string>&) override {}
};

uint16_t free_port_ref()
{
    boost::asio::io_context io;
    boost::asio::ip::tcp::acceptor a(io, {boost::asio::ip::make_address("127.0.0.1"), 0});
    return a.local_endpoint().port();
}

struct Client {
    int fd = -1;
    std::string buf;
    std::string last_job;
    explicit Client(uint16_t port)
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
    ~Client()
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
                if (j.contains("method") && j["method"] == "mining.notify" && j["params"].is_array())
                    last_job = j["params"][0].get<std::string>();
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

} // namespace

TEST(StratumSubmitFrozenRef, SubmitSnapshotCarriesTheJobsRefHashAndNonce)
{
    auto ws = std::make_shared<FrozenRefSource>();
    boost::asio::io_context ioc;
    auto guard = boost::asio::make_work_guard(ioc);
    const uint16_t port = free_port_ref();
    auto srv = std::make_unique<core::StratumServer>(ioc, "127.0.0.1", port, ws);
    ASSERT_TRUE(srv->start());
    std::thread io([&] { ioc.run(); });

    {
        Client c(port);
        ASSERT_GE(c.fd, 0);
        c.send({{"id", 1}, {"method", "mining.subscribe"}, {"params", nlohmann::json::array()}});
        ASSERT_TRUE(c.wait(1).has_value());
        c.send({{"id", 2}, {"method", "mining.authorize"}, {"params", {"1BoatSLRHtKNngkdXEeobR76b53LETtpyT", "x"}}});
        ASSERT_TRUE(c.wait(2).has_value());
        for (int i = 0; i < 40 && c.last_job.empty(); ++i)
            c.wait(-1, 100);
        ASSERT_FALSE(c.last_job.empty()) << "no job";
        c.send({{"id", 3}, {"method", "mining.submit"},
                {"params", {"w", c.last_job, "00000000", "6ae2a090", "00000000"}}});
        c.wait(3);
        for (int i = 0; i < 40; ++i) {
            {
                std::lock_guard<std::mutex> l(ws->mu);
                if (!ws->submits.empty())
                    break;
            }
            c.wait(-1, 50);
        }
    }

    {
        std::lock_guard<std::mutex> l(ws->mu);
        ASSERT_FALSE(ws->submits.empty()) << "the submission never reached mining_submit";
        const auto& j = ws->submits.back();
        EXPECT_EQ(j.frozen_ref.ref_hash, kRef) << "the job's ref_hash did not reach the submit";
        EXPECT_EQ(j.frozen_ref.last_txout_nonce, kNonce);
        // The other frozen fields, as before.
        EXPECT_EQ(j.frozen_ref.absheight, 4242u);
        EXPECT_EQ(j.frozen_ref.timestamp, 1793210001u);
        EXPECT_EQ(j.subsidy, 777u);
    }

    std::promise<void> done;
    boost::asio::post(ioc, [&] { srv->stop(); done.set_value(); });
    done.get_future().wait();
    guard.reset();
    ioc.stop();
    io.join();
}
