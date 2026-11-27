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
#include <impl/dgb/stratum_job_push.hpp>

#include <core/address_utils.hpp>
#include <core/pow.hpp>
#include <core/target_utils.hpp>
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
#include <cctype>
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
    // The frozen share fields the job carries (bits: every hash is a share).
    in.frozen_absheight = 1234;
    in.frozen_bits = 0x2100ffff;
    in.frozen_max_bits = 0x2100ffff;
    in.frozen_timestamp = 1793210001;
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
    std::vector<Bytes> payouts;   // the payout script of every job the producer built
    std::string tip_prev = "ce2fd8d332d667c009e6e031fec6cba0e4d12c963d2c84f824d6c1ae676e7de9";

    JobRig()
    {
        auto submit = [](const std::vector<unsigned char>&, uint32_t) -> bool { return false; };
        ws = std::make_shared<dgb::stratum::DGBWorkSource>(chain, mempool, /*is_testnet=*/false, submit,
                                                           kRigSubsidy);
        const auto acc = dgb::address_acceptance(false, false);
        ws->set_payout_acceptance(acc.p2pkh_versions, acc.p2sh_versions, acc.bech32_hrps);
        ws->set_gbt_tip_fn([this]() -> std::optional<dgb::stratum::DGBWorkSource::GbtTip> {
            std::lock_guard<std::mutex> l(mu);
            return dgb::stratum::DGBWorkSource::GbtTip{tip_prev, "1b0404cb"};
        });
        // main_dgb's producer shape: decline a null or unknown prev share.
        ws->set_pplns_inputs_fn([this](const uint256& prev, const std::string&, const Bytes& payout,
                                       const std::vector<std::pair<uint32_t, Bytes>>&, const Bytes&, const dgb::stratum::DGBWorkSource::JobBlock&)
                                    -> std::optional<dgb::coin::ConnCoinbasePplnsInputs> {
            std::lock_guard<std::mutex> l(mu);
            if (prev.IsNull() || prev != known_share)
                return std::nullopt;
            payouts.push_back(payout);
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

// The job payout script of a DGB P2SH "S..." and a "dgb1..." login is the
// login's own script type (core accepted_payout_script), the same one the DGB
// mint derives from the username: before, "S..." reached the producer as a
// P2PKH of the redeem-script hash and "dgb1..." as an empty script, so the
// job's ref and the share's never matched.
TEST(DgbStratumJobs, P2shAndBech32LoginsReachTheProducerAsTheirOwnScript)
{
    Bytes key(20, 0x66);
    Bytes p2sh{0xa9, 0x14};
    p2sh.insert(p2sh.end(), key.begin(), key.end());
    p2sh.push_back(0x87);
    Bytes wpkh{0x00, 0x14};
    wpkh.insert(wpkh.end(), key.begin(), key.end());
    const std::string s_login = core::script_to_address(p2sh, "", 30, 63);
    const std::string bech_login = core::script_to_address(wpkh, "dgb", 30, 63);
    ASSERT_EQ(s_login.front(), 'S');
    ASSERT_EQ(bech_login.rfind("dgb1", 0), 0u);

    for (const auto& [login, want] : std::vector<std::pair<std::string, Bytes>>{{s_login, p2sh}, {bech_login, wpkh}}) {
        SCOPED_TRACE(login);
        JobRig rig;
        const uint256 best(std::vector<unsigned char>(32, 0x5b));
        {
            std::lock_guard<std::mutex> l(rig.mu);
            rig.known_share = best;
        }
        rig.ws->set_best_share_hash_fn([best]() { return best; });
        RigClient c(rig.port);
        ASSERT_GE(c.fd, 0);
        c.send({{"id", 1}, {"method", "mining.subscribe"}, {"params", nlohmann::json::array()}});
        ASSERT_TRUE(c.pump(2000, 1).has_value());
        c.send({{"id", 2}, {"method", "mining.authorize"}, {"params", {login, "x"}}});
        auto auth = c.pump(2000, 2);
        ASSERT_TRUE(auth.has_value());
        EXPECT_TRUE((*auth)["result"].is_boolean() && (*auth)["result"].get<bool>()) << auth->dump();
        for (int i = 0; i < 30 && c.notifies.empty(); ++i)
            c.pump(100);
        ASSERT_FALSE(c.notifies.empty()) << "no job";
        std::lock_guard<std::mutex> l(rig.mu);
        ASSERT_FALSE(rig.payouts.empty());
        EXPECT_EQ(rig.payouts.back(), want);
    }
}

// ── Clean jobs on a new DGB tip / a new best share (stratum_job_push.hpp) ──

TEST(DgbStratumJobs, JobPushWatchDecisions)
{
    dgb::JobPushWatch w;
    using A = dgb::JobPushWatch::Action;
    EXPECT_EQ(w.tick("aa", 5), A::none) << "first tick primes";
    EXPECT_EQ(w.tick("aa", 5), A::none);
    EXPECT_EQ(w.tick("aa", 6), A::push) << "a bumped generation (best share / DOGE) pushes";
    EXPECT_EQ(w.tick("aa", 6), A::none);
    EXPECT_EQ(w.tick("bb", 6), A::bump_and_push) << "a new tip bumps and pushes";
    EXPECT_EQ(w.tick("bb", 7), A::none) << "the watch's own bump is not pushed twice";
    EXPECT_EQ(w.tick("", 7), A::none) << "no prevhash (no template yet) is not a tip change";
    EXPECT_EQ(w.tick("bb", 7), A::none);
}

// Review 713dc77a0 NIT 16: the watch runs main_dgb's best-share refresh at
// every tick; a best it finds (a bumped generation) is pushed by that tick.
TEST(DgbStratumJobs, JobPushWatchRunsItsBeforeTickHook)
{
    struct Ws {
        std::string prev = "aa";
        uint64_t gen = 5;
        std::string get_current_gbt_prevhash() const { return prev; }
        uint64_t get_work_generation() const { return gen; }
        void bump_work_generation() { ++gen; }
    } ws;
    boost::asio::io_context ioc;
    int hooks = 0, pushes = 0;
    auto stop = dgb::start_job_push_watch(
        ioc, &ws, [&](bool clean) { pushes += clean ? 1 : 0; }, std::chrono::milliseconds(5),
        [&]() {
            if (++hooks == 3)
                ws.bump_work_generation();   // the refresh found a new best
        });
    ioc.run_for(std::chrono::milliseconds(200));
    stop();
    EXPECT_GE(hooks, 3);
    EXPECT_EQ(pushes, 1) << "the hook's new best was not pushed (or pushed twice)";
}

TEST(DgbStratumJobs, NewTipPushesCleanJobsWithoutAMinerEvent)
{
    JobRig rig;
    const uint256 best(std::vector<unsigned char>(32, 0x5b));
    {
        std::lock_guard<std::mutex> l(rig.mu);
        rig.known_share = best;
    }
    rig.ws->set_best_share_hash_fn([best]() { return best; });
    auto* srv = rig.srv.get();
    auto stop = dgb::start_job_push_watch(rig.ioc, rig.ws.get(), [srv](bool clean) { srv->notify_all(clean); },
                                          std::chrono::milliseconds(100));
    RigClient c(rig.port);
    ASSERT_GE(c.fd, 0);
    c.send({{"id", 1}, {"method", "mining.subscribe"}, {"params", nlohmann::json::array()}});
    ASSERT_TRUE(c.pump(2000, 1).has_value());
    c.send({{"id", 2}, {"method", "mining.authorize"}, {"params", {dgb_address(), "x"}}});
    ASSERT_TRUE(c.pump(2000, 2).has_value());
    for (int i = 0; i < 30 && c.notifies.empty(); ++i)
        c.pump(100);
    ASSERT_FALSE(c.notifies.empty()) << "no first job";
    c.pump(500);
    const size_t before = c.notifies.size();

    // A new DGB tip: a clean job arrives well inside the 25 s keepalive.
    {
        std::lock_guard<std::mutex> l(rig.mu);
        rig.tip_prev = "0ad1" + std::string(60, '7');
    }
    const auto t0 = std::chrono::steady_clock::now();
    for (int i = 0; i < 80 && c.notifies.size() == before; ++i)
        c.pump(100);
    const auto waited = std::chrono::steady_clock::now() - t0;
    ASSERT_GT(c.notifies.size(), before) << "no job after the new tip";
    EXPECT_LT(waited, std::chrono::seconds(8));
    const auto& n = c.notifies.back();
    ASSERT_GE(n.size(), 9u);
    EXPECT_TRUE(n[8].get<bool>()) << "the job on the new tip is not clean";
    // Stop the watch on the io thread (its timer lives there).
    std::promise<void> stopped;
    boost::asio::post(rig.ioc, [&] { stop(); stopped.set_value(); });
    stopped.get_future().wait();
}

// Review 713dc77a0 R1: the stratum server did not carry the job's frozen ref
// (ref_hash, last_txout_nonce) to mining_submit, so the DGB work source saw
// every real job as "not built here" and refused every share. Through a real
// core::StratumServer over the real DGBWorkSource: subscribe, authorize, the
// producer's job, a nonce ground locally to the session's fixed difficulty,
// mining.submit; the share reaches the mint with the job's frozen fields.
TEST(DgbStratumJobs, RealSubmitReachesTheMintWithTheJobsFrozenRef)
{
    JobRig rig;
    const uint256 best(std::vector<unsigned char>(32, 0x5b));
    {
        std::lock_guard<std::mutex> l(rig.mu);
        rig.known_share = best;
    }
    rig.ws->set_best_share_hash_fn([best]() { return best; });
    std::mutex mint_mu;
    std::vector<dgb::stratum::DGBWorkSource::MintShareInputs> mints;
    rig.ws->set_mint_share_fn([&](const dgb::stratum::DGBWorkSource::MintShareInputs& in) -> uint256 {
        std::lock_guard<std::mutex> l(mint_mu);
        mints.push_back(in);
        return uint256(std::vector<unsigned char>(32, 0x77));
    });

    RigClient c(rig.port);
    ASSERT_GE(c.fd, 0);
    c.send({{"id", 1}, {"method", "mining.subscribe"}, {"params", nlohmann::json::array()}});
    auto sub = c.pump(2000, 1);
    ASSERT_TRUE(sub.has_value());
    const std::string en1 = (*sub)["result"][1].get<std::string>();
    const int en2_size = (*sub)["result"][2].get<int>();
    c.send({{"id", 2}, {"method", "mining.authorize"}, {"params", {dgb_address(), "x"}}});
    auto auth = c.pump(2000, 2);
    ASSERT_TRUE(auth.has_value());
    ASSERT_TRUE((*auth)["result"].is_boolean() && (*auth)["result"].get<bool>()) << auth->dump();
    for (int i = 0; i < 30 && c.notifies.empty(); ++i)
        c.pump(100);
    ASSERT_FALSE(c.notifies.empty()) << "no job";
    const auto n = c.notifies.back();
    const std::string job_id = n[0].get<std::string>();
    const std::string coinb1 = n[2].get<std::string>(), coinb2 = n[3].get<std::string>();
    std::vector<std::string> branches;
    for (const auto& b : n[4])
        branches.push_back(b.get<std::string>());
    const uint32_t version = static_cast<uint32_t>(std::stoul(n[5].get<std::string>(), nullptr, 16));
    const std::string nbits = n[6].get<std::string>(), ntime = n[7].get<std::string>();
    const std::string en2(static_cast<size_t>(en2_size) * 2, '0');

    // The session difficulty is bounded by the job's pool-share difficulty
    // (its frozen share bits, every hash a share): grind to that.
    const double need = chain::target_to_difficulty(chain::bits_to_target(rig_inputs().frozen_bits));
    std::string nonce;
    for (uint32_t k = 0; k < 20000 && nonce.empty(); ++k) {
        char buf[9];
        std::snprintf(buf, sizeof buf, "%08x", k);
        if (rig.ws->compute_share_difficulty(coinb1, coinb2, en1, en2, ntime, buf, version, rig.tip_prev, nbits,
                                             branches) >= need)
            nonce = buf;
    }
    ASSERT_FALSE(nonce.empty()) << "no nonce met the session difficulty " << need;

    c.send({{"id", 3}, {"method", "mining.submit"},
            {"params", {dgb_address(), job_id, en2, ntime, nonce}}});
    auto resp = c.pump(3000, 3);
    ASSERT_TRUE(resp.has_value()) << "no reply to mining.submit";
    EXPECT_TRUE((*resp)["result"].is_boolean() && (*resp)["result"].get<bool>()) << resp->dump();

    std::lock_guard<std::mutex> l(mint_mu);
    ASSERT_EQ(mints.size(), 1u) << "the share never reached the mint (every real submit refused)";
    const auto& m = mints.back();
    EXPECT_TRUE(m.has_frozen) << "the job's frozen ref did not reach mining_submit";
    EXPECT_EQ(m.prev_share, best);
    EXPECT_EQ(m.frozen_bits, rig_inputs().frozen_bits);
    EXPECT_EQ(m.frozen_timestamp, rig_inputs().frozen_timestamp);
    EXPECT_EQ(m.frozen_absheight, rig_inputs().frozen_absheight);
    EXPECT_FALSE(m.actual_coinbase.empty());
}

// Review 713dc77a0 #10 and #13: an empty login (DGB does not redistribute it)
// and a dgb1 P2WSH or P2TR login (a V35 share cannot carry it: it was paid to
// a P2PKH of the program's first 20 bytes) are refused at authorize, with the
// reason; D..., S..., dgb1q (20-byte) and a DOGE primary are not. Through a
// real core::StratumServer over the real DGBWorkSource: a refused login gets
// no job. An empty payout never gets a job either (defence in depth).
TEST(DgbStratumJobs, EmptyAndUncarriableLoginsAreRefusedAtAuthorize)
{
    Bytes prog32(32, 0x5a);
    Bytes wsh{0x00, 0x20};
    wsh.insert(wsh.end(), prog32.begin(), prog32.end());
    const std::string p2wsh = core::script_to_address(wsh, "dgb", 30, 63);
    ASSERT_EQ(p2wsh.rfind("dgb1q", 0), 0u) << p2wsh;
    Bytes tr{0x51, 0x20};
    tr.insert(tr.end(), prog32.begin(), prog32.end());
    const std::string p2tr = core::script_to_address(tr, "dgb", 30, 63);

    JobRig probe;
    EXPECT_NE(probe.ws->authorize_refusal("").find("DGB payout address"), std::string::npos);
    {
        // An UPPERCASE bech32 login is refused (python keys V35 weights by the
        // string as typed); its lowercase form is accepted.
        Bytes k20(20, 0x66);
        Bytes w{0x00, 0x14};
        w.insert(w.end(), k20.begin(), k20.end());
        const std::string lower = core::script_to_address(w, "dgb", 30, 63);
        std::string upper = lower;
        for (auto& ch : upper)
            ch = static_cast<char>(std::toupper(static_cast<unsigned char>(ch)));
        EXPECT_NE(probe.ws->authorize_refusal(upper).find(lower), std::string::npos) << upper;
        EXPECT_TRUE(probe.ws->authorize_refusal(lower).empty()) << lower;
    }
    EXPECT_FALSE(probe.ws->authorize_refusal(p2wsh).empty()) << p2wsh;
    if (!p2tr.empty())
        EXPECT_FALSE(probe.ws->authorize_refusal(p2tr).empty()) << p2tr;
    Bytes key(20, 0x66);
    Bytes p2sh{0xa9, 0x14};
    p2sh.insert(p2sh.end(), key.begin(), key.end());
    p2sh.push_back(0x87);
    Bytes wpkh{0x00, 0x14};
    wpkh.insert(wpkh.end(), key.begin(), key.end());
    Bytes doge_pkh{0x76, 0xa9, 0x14};
    doge_pkh.insert(doge_pkh.end(), key.begin(), key.end());
    doge_pkh.push_back(0x88);
    doge_pkh.push_back(0xac);
    for (const auto& ok : {dgb_address(), core::script_to_address(p2sh, "", 30, 63),
                           core::script_to_address(wpkh, "dgb", 30, 63),
                           core::script_to_address(doge_pkh, "", 30, 22) /* DOGE D... shares DGB's 30 */,
                           core::script_to_address(p2sh, "", 30, 22) /* DOGE A... */})
        EXPECT_TRUE(probe.ws->authorize_refusal(ok).empty()) << ok;

    // The empty payout is held, never built (the producer is not even asked).
    {
        std::lock_guard<std::mutex> l(probe.mu);
        probe.known_share = uint256(std::vector<unsigned char>(32, 0x5b));
    }
    size_t built = 0;
    {
        std::lock_guard<std::mutex> l(probe.mu);
        built = probe.payouts.size();
    }
    auto held = probe.ws->build_connection_coinbase(uint256(std::vector<unsigned char>(32, 0x5b)), "00", Bytes{}, {});
    EXPECT_TRUE(held.held);
    {
        std::lock_guard<std::mutex> l(probe.mu);
        EXPECT_EQ(probe.payouts.size(), built) << "the producer was asked for an empty payout";
    }

    for (const std::string& login : {std::string(""), p2wsh}) {
        SCOPED_TRACE(login);
        JobRig rig;
        const uint256 best(std::vector<unsigned char>(32, 0x5b));
        {
            std::lock_guard<std::mutex> l(rig.mu);
            rig.known_share = best;
        }
        rig.ws->set_best_share_hash_fn([best]() { return best; });
        RigClient c(rig.port);
        ASSERT_GE(c.fd, 0);
        c.send({{"id", 1}, {"method", "mining.subscribe"}, {"params", nlohmann::json::array()}});
        ASSERT_TRUE(c.pump(2000, 1).has_value());
        c.send({{"id", 2}, {"method", "mining.authorize"}, {"params", {login, "x"}}});
        auto auth = c.pump(2000, 2);
        ASSERT_TRUE(auth.has_value());
        EXPECT_FALSE((*auth)["result"].is_boolean() && (*auth)["result"].get<bool>()) << auth->dump();
        ASSERT_TRUE((*auth)["error"].is_array()) << auth->dump();
        EXPECT_EQ((*auth)["error"][0].get<int>(), 24);
        c.pump(1000);
        EXPECT_TRUE(c.notifies.empty()) << "a refused login was served a job";
    }
}
