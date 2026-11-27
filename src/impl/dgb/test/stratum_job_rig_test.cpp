// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// A DGB miner never hashes the stub coinbase (rides dgb_work_source_test).
//
// Through a real core::StratumServer on 127.0.0.1 over the real DGBWorkSource,
// wired the way main_dgb wires it: the producer declines a null or unknown
// prev share (main_dgb set_pplns_inputs_fn). Before the fix the declined
// coinbase came back EMPTY, the server fell back to the global coinbase (empty
// on DGB) and then to its hard-coded stub (stratum_server.cpp send_notify_work:
// no scriptSig length / BIP34 height, 50 coins to hash160 0x00..00), and the
// miner was served that: nothing it found could ever be credited. Now the
// decline is HELD: no job at all until the producer can build a real
// coinbase, then the real one (the PPLNS SSOT bytes), never the stub.
// Uses only the work-source API that predates the fix, so the same test is RED
// on the pre-fix tree.
// ---------------------------------------------------------------------------

#include <impl/dgb/address_encoding.hpp>
#include <impl/dgb/coin/connection_coinbase.hpp>
#include <impl/dgb/coin/header_chain.hpp>
#include <impl/dgb/coin/mempool.hpp>
#include <impl/dgb/config_coin.hpp>
#include <impl/dgb/config_pool.hpp>
#include <impl/dgb/stratum/work_source.hpp>

#include <core/address_utils.hpp>
#include <core/pow.hpp>
#include <core/stratum_server.hpp>
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

#include <atomic>
#include <chrono>
#include <future>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

namespace {

using Bytes = std::vector<unsigned char>;

// The hard-coded fallback coinbase of core::StratumSession::send_notify_work.
const std::string kStubCoinb1 =
    "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff";
const std::string kStubCoinb2 =
    "0000000000f2052a010000001976a914000000000000000000000000000000000000000088ac00000000";

uint16_t rig_free_port()
{
    boost::asio::io_context io;
    boost::asio::ip::tcp::acceptor a(io, {boost::asio::ip::make_address("127.0.0.1"), 0});
    return a.local_endpoint().port();
}

struct RigClient {
    int fd = -1;
    std::string buf;
    std::vector<nlohmann::json> notifies;   // every mining.notify params array
    explicit RigClient(uint16_t port)
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
    ~RigClient()
    {
        if (fd >= 0)
            ::close(fd);
    }
    void send(const nlohmann::json& j)
    {
        const std::string line = j.dump() + "\n";
        (void)::send(fd, line.data(), line.size(), MSG_NOSIGNAL);
    }
    // Reads for `ms`; returns the response with `id` if seen.
    std::optional<nlohmann::json> pump(int ms, int id = -1)
    {
        std::optional<nlohmann::json> resp;
        const auto until = std::chrono::steady_clock::now() + std::chrono::milliseconds(ms);
        while (std::chrono::steady_clock::now() < until) {
            size_t nl;
            while ((nl = buf.find('\n')) != std::string::npos) {
                const std::string line = buf.substr(0, nl);
                buf.erase(0, nl + 1);
                nlohmann::json j;
                try { j = nlohmann::json::parse(line); } catch (...) { continue; }
                if (j.contains("method") && j["method"] == "mining.notify" && j["params"].is_array())
                    notifies.push_back(j["params"]);
                if (id >= 0 && j.contains("id") && j["id"].is_number() && j["id"].get<int>() == id)
                    resp = j;
            }
            if (resp)
                return resp;
            char tmp[16384];
            const ssize_t n = ::recv(fd, tmp, sizeof tmp, 0);
            if (n > 0)
                buf.append(tmp, static_cast<size_t>(n));
            if (n == 0)
                break;
        }
        return resp;
    }
};

const core::SubsidyFunc kRigSubsidy = [](uint32_t h) -> uint64_t { return dgb::CoinParams::subsidy(h); };

dgb::coin::ConnCoinbasePplnsInputs rig_inputs()
{
    dgb::coin::ConnCoinbasePplnsInputs in;
    in.coinbase_script = Bytes{0x03, 0x01, 0x02, 0x03};
    Bytes a{0x76, 0xa9, 0x14};
    a.insert(a.end(), 20, 0xa1);
    a.push_back(0x88);
    a.push_back(0xac);
    in.weights = {{a, uint288(1)}};
    in.total_weight = uint288(1);
    in.subsidy = 72000000000ULL;
    in.use_v36_pplns = true;
    in.donation_script = dgb::PoolConfig::get_donation_script(36);
    in.ref_hash = uint256(std::vector<unsigned char>(32, 0xab));
    in.last_txout_nonce = 0;
    return in;
}

struct JobRig {
    c2pool::dgb::HeaderChain chain;
    dgb::coin::Mempool mempool;
    std::shared_ptr<dgb::stratum::DGBWorkSource> ws;
    boost::asio::io_context ioc;
    std::optional<boost::asio::executor_work_guard<boost::asio::io_context::executor_type>> guard;
    std::unique_ptr<core::StratumServer> srv;
    std::thread io;
    uint16_t port = 0;
    std::mutex mu;
    uint256 known_share;          // the only share the producer knows (none yet)

    JobRig()
    {
        auto submit = [](const std::vector<unsigned char>&, uint32_t) -> bool { return false; };
        ws = std::make_shared<dgb::stratum::DGBWorkSource>(chain, mempool, /*is_testnet=*/false, submit,
                                                           kRigSubsidy);
        const auto acc = dgb::address_acceptance(false, false);
        ws->set_payout_acceptance(acc.p2pkh_versions, acc.p2sh_versions, acc.bech32_hrps);
        ws->set_gbt_tip_fn([]() -> std::optional<dgb::stratum::DGBWorkSource::GbtTip> {
            return dgb::stratum::DGBWorkSource::GbtTip{
                "ce2fd8d332d667c009e6e031fec6cba0e4d12c963d2c84f824d6c1ae676e7de9", "1b0404cb"};
        });
        // main_dgb's producer shape: decline a null or unknown prev share.
        ws->set_pplns_inputs_fn([this](const uint256& prev, const std::string&, const Bytes&,
                                       const std::vector<std::pair<uint32_t, Bytes>>&)
                                    -> std::optional<dgb::coin::ConnCoinbasePplnsInputs> {
            std::lock_guard<std::mutex> l(mu);
            if (prev.IsNull() || prev != known_share)
                return std::nullopt;
            return rig_inputs();
        });
        port = rig_free_port();
        guard.emplace(boost::asio::make_work_guard(ioc));
        srv = std::make_unique<core::StratumServer>(ioc, "127.0.0.1", port, ws);
        srv->start();
        io = std::thread([this] { ioc.run(); });
    }
    ~JobRig()
    {
        std::promise<void> done;
        boost::asio::post(ioc, [&] { srv->stop(); done.set_value(); });
        done.get_future().wait();
        guard.reset();
        ioc.stop();
        io.join();
    }
};

std::string dgb_address()
{
    Bytes s{0x76, 0xa9, 0x14};
    s.insert(s.end(), 20, 0xa1);
    s.push_back(0x88);
    s.push_back(0xac);
    return core::script_to_address(s, "", 30, 63);
}

} // namespace

TEST(DgbStratumJobs, NoJobEverCarriesTheStubCoinbase)
{
    JobRig rig;
    RigClient c(rig.port);
    ASSERT_GE(c.fd, 0);

    c.send({{"id", 1}, {"method", "mining.subscribe"}, {"params", nlohmann::json::array()}});
    ASSERT_TRUE(c.pump(2000, 1).has_value());
    c.send({{"id", 2}, {"method", "mining.authorize"}, {"params", {dgb_address(), "x"}}});
    auto auth = c.pump(2000, 2);
    ASSERT_TRUE(auth.has_value());
    EXPECT_TRUE((*auth)["result"].is_boolean() && (*auth)["result"].get<bool>()) << auth->dump();

    // No share to build on yet (main_dgb today: no best share bound, so a NULL
    // prev): the producer declines. No job, and never the stub.
    c.pump(1500);
    for (const auto& n : c.notifies) {
        ASSERT_GE(n.size(), 4u);
        EXPECT_NE(n[2].get<std::string>(), kStubCoinb1) << "a miner was served the stub coinbase";
        EXPECT_NE(n[3].get<std::string>(), kStubCoinb2) << "a miner was served the stub coinbase";
    }
    EXPECT_TRUE(c.notifies.empty()) << "a job was sent while the producer declined: " << c.notifies.size();

    // A share to build on: the next notify is the real coinbase (the PPLNS
    // SSOT bytes), sent by the held retry without any new event.
    const uint256 best(std::vector<unsigned char>(32, 0x5b));
    {
        std::lock_guard<std::mutex> l(rig.mu);
        rig.known_share = best;
    }
    rig.ws->set_best_share_hash_fn([best]() { return best; });
    rig.ws->bump_work_generation();
    const size_t before = c.notifies.size();
    for (int i = 0; i < 60 && c.notifies.size() == before; ++i)
        c.pump(100);
    ASSERT_GT(c.notifies.size(), before) << "no job once the producer could build one";
    const auto& n = c.notifies.back();
    const auto oracle = dgb::coin::build_connection_coinbase_from_pplns(rig_inputs());
    EXPECT_EQ(n[2].get<std::string>(), oracle.coinb1);
    EXPECT_EQ(n[3].get<std::string>(), oracle.coinb2);
    EXPECT_NE(n[2].get<std::string>(), kStubCoinb1);
}
