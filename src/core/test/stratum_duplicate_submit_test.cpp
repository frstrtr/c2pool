// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// Duplicate mining.submit (rides core_test).
//
// With the flag on, the fields must also have their canonical spelling
// (core::stratum::canonical_submit_fields), else [20, "Invalid parameters"].
//
// StratumConfig::reject_duplicate_submits: the same (extranonce2, ntime,
// nonce, version) twice on one job, among submissions that passed the
// pseudoshare (vardiff) gate, is refused with [22, "Duplicate share"], so it
// is neither counted (vardiff, rates, the best-share feed) nor dispatched to
// the work source (p2pool work.py received_header_hashes, filled after
// pow <= pseudoshare target). A low-difficulty submission is not remembered,
// and at most duplicate_submit_keys_per_job are kept per job. Off (the
// default): today's behaviour, every repeat accepted, counted and
// dispatched again.
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

struct DupSource : core::stratum::IWorkSource {
    core::stratum::StratumConfig cfg;
    mutable std::mutex mu;
    std::vector<core::stratum::JobSnapshot> submits;
    int best_calls = 0;   // record_best_pseudoshare: once per accepted pseudoshare

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
                                    const std::string&, const std::string& nonce, uint32_t, const std::string&,
                                    const std::string&, const std::vector<std::string>&) const override
    {
        // Every submission is a share, except the nonce "0badd1ff": below
        // any vardiff.
        return nonce == "0badd1ff" ? 0.0 : 1e15;
    }
    void record_best_pseudoshare(double, const std::string&, const std::string&, const std::string&,
                                 const std::string&, const std::string&, const std::string&, const std::string&,
                                 uint32_t, const std::string&, const std::string&,
                                 const std::vector<std::string>&) override
    {
        std::lock_guard<std::mutex> l(mu);
        ++best_calls;
    }
};

uint16_t free_port_dup()
{
    boost::asio::io_context io;
    boost::asio::ip::tcp::acceptor a(io, {boost::asio::ip::make_address("127.0.0.1"), 0});
    return a.local_endpoint().port();
}

struct DupClient {
    int fd = -1;
    std::string buf;
    std::string last_job;
    explicit DupClient(uint16_t port)
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
    ~DupClient()
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


struct DupRun {
    std::vector<nlohmann::json> replies;
    size_t dispatched = 0;
    int best_calls = 0;
};

struct Submit {
    std::string extranonce2 = "00000000";
    std::string ntime = "6ae2a090";
    std::string nonce;
    std::string version_bits;   // empty: not sent
};

DupRun run_submits(bool reject_duplicates, const std::vector<Submit>& submits, size_t keys_per_job);

// Submits `nonces` in order on one job; the replies and what reached the source.
DupRun run(bool reject_duplicates, const std::vector<std::string>& nonces, size_t keys_per_job = 256)
{
    std::vector<Submit> v;
    for (const auto& n : nonces)
        v.push_back(Submit{"00000000", "6ae2a090", n, ""});
    return run_submits(reject_duplicates, v, keys_per_job);
}

DupRun run_submits(bool reject_duplicates, const std::vector<Submit>& submits, size_t keys_per_job)
{
    auto ws = std::make_shared<DupSource>();
    ws->cfg.reject_duplicate_submits = reject_duplicates;
    ws->cfg.duplicate_submit_keys_per_job = keys_per_job;
    boost::asio::io_context ioc;
    auto guard = boost::asio::make_work_guard(ioc);
    const uint16_t port = free_port_dup();
    auto srv = std::make_unique<core::StratumServer>(ioc, "127.0.0.1", port, ws);
    EXPECT_TRUE(srv->start());
    std::thread io([&] { ioc.run(); });
    DupRun out;
    {
        DupClient c(port);
        EXPECT_GE(c.fd, 0);
        c.send({{"id", 1}, {"method", "mining.subscribe"}, {"params", nlohmann::json::array()}});
        EXPECT_TRUE(c.wait(1).has_value());
        c.send({{"id", 2}, {"method", "mining.authorize"}, {"params", {"1BoatSLRHtKNngkdXEeobR76b53LETtpyT", "x"}}});
        EXPECT_TRUE(c.wait(2).has_value());
        for (int i = 0; i < 40 && c.last_job.empty(); ++i)
            c.wait(-1, 100);
        EXPECT_FALSE(c.last_job.empty());
        int id = 10;
        for (const auto& sub : submits) {
            nlohmann::json p = {"w", c.last_job, sub.extranonce2, sub.ntime, sub.nonce};
            if (!sub.version_bits.empty())
                p.push_back(sub.version_bits);
            c.send({{"id", id}, {"method", "mining.submit"}, {"params", p}});
            auto r = c.wait(id);
            out.replies.push_back(r ? *r : nlohmann::json());
            ++id;
        }
    }
    {
        std::lock_guard<std::mutex> l(ws->mu);
        out.dispatched = ws->submits.size();
        out.best_calls = ws->best_calls;
    }
    std::promise<void> done;
    boost::asio::post(ioc, [&] { srv->stop(); done.set_value(); });
    done.get_future().wait();
    guard.reset();
    ioc.stop();
    io.join();
    return out;
}

bool ok(const nlohmann::json& r) { return r.contains("result") && r["result"].is_boolean() && r["result"].get<bool>(); }

} // namespace

TEST(StratumDuplicateSubmit, RepeatIsRefusedNotCountedNotDispatched)
{
    const auto r = run(true, {"00000001", "00000001", "00000002", "00000001"});
    ASSERT_EQ(r.replies.size(), 4u);
    EXPECT_TRUE(ok(r.replies[0])) << r.replies[0].dump();
    EXPECT_FALSE(ok(r.replies[1])) << r.replies[1].dump();
    ASSERT_TRUE(r.replies[1].contains("error") && r.replies[1]["error"].is_array());
    EXPECT_EQ(r.replies[1]["error"][0].get<int>(), 22);
    EXPECT_EQ(r.replies[1]["error"][1].get<std::string>(), "Duplicate share");
    EXPECT_TRUE(ok(r.replies[2])) << "another nonce is not a duplicate";
    EXPECT_FALSE(ok(r.replies[3])) << "a later repeat is still a duplicate";
    EXPECT_EQ(r.dispatched, 2u) << "a duplicate reached the work source";
    EXPECT_EQ(r.best_calls, 2) << "a duplicate was counted";
}

TEST(StratumDuplicateSubmit, OffKeepsTodaysBehaviour)
{
    const auto r = run(false, {"00000001", "00000001", "00000001"});
    ASSERT_EQ(r.replies.size(), 3u);
    for (const auto& x : r.replies)
        EXPECT_TRUE(ok(x)) << x.dump();
    EXPECT_EQ(r.dispatched, 3u);
    EXPECT_EQ(r.best_calls, 3);
}

TEST(StratumDuplicateSubmit, HexCaseIsTheSameHeader)
{
    const auto r = run(true, {"0000abcd", "0000ABCD"});
    ASSERT_EQ(r.replies.size(), 2u);
    EXPECT_TRUE(ok(r.replies[0]));
    EXPECT_FALSE(ok(r.replies[1])) << "upper-case hex of the same nonce passed as a new header";
}

// Review dd1248abd REQUIRED 3: only a submission that passed the vardiff
// gate is remembered; a low-difficulty repeat is low-difficulty again.
TEST(StratumDuplicateSubmit, ALowDifficultySubmitIsNotRemembered)
{
    const auto r = run(true, {"0badd1ff", "0badd1ff", "00000001"});
    ASSERT_EQ(r.replies.size(), 3u);
    for (int i : {0, 1}) {
        ASSERT_TRUE(r.replies[i].contains("error") && r.replies[i]["error"].is_array()) << r.replies[i].dump();
        EXPECT_EQ(r.replies[i]["error"][0].get<int>(), 23) << "a low-difficulty submit was remembered";
    }
    EXPECT_TRUE(ok(r.replies[2]));
    EXPECT_EQ(r.dispatched, 1u);
}

// At most duplicate_submit_keys_per_job are remembered per job: past it a new
// submission is still checked against the remembered ones but not added.
TEST(StratumDuplicateSubmit, TheSetIsCappedPerJob)
{
    const auto r = run(true, {"00000001", "00000002", "00000003", "00000003", "00000001", "00000002"}, 2);
    ASSERT_EQ(r.replies.size(), 6u);
    EXPECT_TRUE(ok(r.replies[0]));
    EXPECT_TRUE(ok(r.replies[1]));
    EXPECT_TRUE(ok(r.replies[2])) << "past the cap: accepted";
    EXPECT_TRUE(ok(r.replies[3])) << "past the cap: not remembered, so not a duplicate";
    EXPECT_FALSE(ok(r.replies[4])) << "a remembered one is still a duplicate";
    EXPECT_FALSE(ok(r.replies[5]));
    EXPECT_EQ(r.dispatched, 4u);
}

// Review 7793bfb6c REQUIRED: with the flag on, a header has one spelling. The
// coin parsers read "1", "0x00000001", "00000001zz" and 300 leading zeros as
// nonce 1, so any spelling but exactly 8 hex digits (extranonce2 exactly 2x
// its size, version_bits at most 8) is refused [20] before the PoW, not
// counted, not dispatched, not remembered.
TEST(StratumDuplicateSubmit, OnlyTheCanonicalSpellingIsTaken)
{
    std::vector<Submit> v;
    v.push_back(Submit{"00000000", "6ae2a090", "00000001", ""});
    for (const std::string& n : std::vector<std::string>{"1", "0x00000001", "00000001zz", " 0000001", "+0000001",
                                                          std::string(300, '0') + "1", std::string(16000, '0')})
        v.push_back(Submit{"00000000", "6ae2a090", n, ""});
    v.push_back(Submit{"0000000", "6ae2a090", "00000002", ""});      // extranonce2 one digit short
    v.push_back(Submit{"0000000000", "6ae2a090", "00000002", ""});   // and one byte long
    v.push_back(Submit{"00000000", "6ae2a09", "00000002", ""});      // ntime short
    v.push_back(Submit{"00000000", "6ae2a090", "00000002", "1fffe0000"});   // version_bits 9 digits
    v.push_back(Submit{"00000000", "6ae2a090", "00000001", ""});      // the canonical one again
    const auto r = run_submits(true, v, 256);
    ASSERT_EQ(r.replies.size(), v.size());
    EXPECT_TRUE(ok(r.replies[0])) << r.replies[0].dump();
    for (size_t i = 1; i + 1 < v.size(); ++i) {
        SCOPED_TRACE(i);
        ASSERT_TRUE(r.replies[i].contains("error") && r.replies[i]["error"].is_array()) << r.replies[i].dump();
        EXPECT_EQ(r.replies[i]["error"][0].get<int>(), 20);
    }
    ASSERT_TRUE(r.replies.back().contains("error") && r.replies.back()["error"].is_array());
    EXPECT_EQ(r.replies.back()["error"][0].get<int>(), 22) << "the canonical repeat is the duplicate";
    EXPECT_EQ(r.dispatched, 1u) << "a non-canonical spelling reached the work source";
    EXPECT_EQ(r.best_calls, 1) << "a non-canonical spelling was counted";
}

// Off (every lane but DGB): no format check, today's parsing.
TEST(StratumDuplicateSubmit, OffTakesAnySpellingAsToday)
{
    const auto r = run_submits(false, {Submit{"00000000", "6ae2a090", "1", ""}}, 256);
    ASSERT_EQ(r.replies.size(), 1u);
    EXPECT_TRUE(ok(r.replies[0])) << r.replies[0].dump();
}

TEST(StratumDuplicateSubmit, CanonicalFieldsHelper)
{
    using core::stratum::canonical_submit_fields;
    EXPECT_TRUE(canonical_submit_fields("0a0B0c0D", "6AE2A090", "deadBEEF", "", 4));
    EXPECT_TRUE(canonical_submit_fields("0a0b0c0d", "6ae2a090", "deadbeef", "1fffe000", 4));
    EXPECT_TRUE(canonical_submit_fields("0a0b0c0d", "6ae2a090", "deadbeef", "2", 4));
    EXPECT_FALSE(canonical_submit_fields("0a0b0c0d", "6ae2a090", "deadbeef", "x", 4));
    EXPECT_FALSE(canonical_submit_fields("0a0b0c", "6ae2a090", "deadbeef", "", 4));
    EXPECT_TRUE(canonical_submit_fields("0a0b0c", "6ae2a090", "deadbeef", "", 3));
    EXPECT_FALSE(canonical_submit_fields("0a0b0c0d", "6ae2a090", "deadbee ", "", 4));
}
