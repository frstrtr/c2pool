// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Mining-hotel interim fix KATs — stratum admission cap + job eviction +
// shared-payload memory bound (core::StratumServer / core::StratumSession).
//
// Covers the three behavior changes of the "minimal stratum hotel-interim
// fix + strict per-node miner cap" slice:
//
//   1. CAP ENFORCEMENT — with max_stratum_connections=2 the 3rd (and 4th)
//      TCP connection is refused cleanly (socket closed, counter increments,
//      accept loop keeps running: a freed slot admits a new miner).
//
//   2. STALE-STORM / FIFO+TTL EVICTION — issue a job, then a 600-notify
//      storm. Pre-fix, capacity eviction was `erase(active_jobs_.begin())`
//      on an unordered_map: an ARBITRARY entry — possibly the job the miner
//      is currently hashing — was dropped, producing nondeterministic
//      "Stale share" rejects. Post-fix eviction is genuinely-oldest-first
//      (FIFO, cap 256) + 300 s TTL (p2pool ExpiringDict semantics). The rig
//      asserts the CURRENT job (and a recent one inside the FIFO window)
//      submits ACCEPTED after the storm — this FAILS on the pre-fix
//      arbitrary-evict with overwhelming probability (345 arbitrary
//      evictions over 601 string-keyed entries) — and that the genuinely
//      oldest job IS stale (cap still enforced, oldest-first).
//      NOTE on the spec's "submit against N after N+600 → ACCEPTED": with
//      MAX_ACTIVE_JOBS=256 (p2pool parity) a job 600 generations back is
//      GENUINELY oldest and correctly evicted; the bug being fixed is
//      arbitrary eviction of RECENT jobs. The assertion set here encodes
//      exactly that: newest-256 always survive, oldest are the ones dropped.
//
//   3. FLAT-RSS SCAFFOLD — N sessions × job churn: total active jobs stay
//      bounded by MAX_ACTIVE_JOBS per session, and the heavyweight template
//      payload (coinb1/coinb2 incl. PPLNS outputs + merkle branches) is
//      POINTER-IDENTICAL across all jobs of one work generation (one
//      refcounted block per generation per session, not jobs × copies).
//
// WIRE SAFETY / BYTE-PARITY: everything here is admission/eviction/memory
// only — no notify param, coinbase (coinb1‖en1‖en2‖coinb2), or share byte
// changes. The notify/coinbase/share BYTE-PARITY KAT is NOT this file: for
// DASH it must run against the frstrtr/p2pool-dash oracle (share version
// 16→36 transition line), NOT the v36-uniform baseline. See the dash lane
// parity tests (test_dash_coinbase_parity / test_dash_stratum_binding) for
// the oracle-pinned byte checks; this file deliberately reuses a synthetic
// work source and never asserts wire bytes.
//
// Self-contained: synthetic IWorkSource, loopback TCP on an ephemeral test
// port, no coin daemon / RPC / sharechain.

#include <gtest/gtest.h>

#include <boost/asio.hpp>
#include <nlohmann/json.hpp>

#include <core/stratum_server.hpp>
#include <core/stratum_types.hpp>
#include <core/stratum_work_source.hpp>
#include <core/uint256.hpp>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <future>
#include <memory>
#include <optional>
#include <string>
#include <thread>
#include <vector>

namespace asio = boost::asio;
using tcp = asio::ip::tcp;
using json = nlohmann::json;
using namespace std::chrono_literals;

namespace {

// ── Synthetic work source ───────────────────────────────────────────────────
// Minimal IWorkSource: constant template + constant per-connection coinbase.
// Constant bytes within one work generation are exactly what makes the
// shared-payload dedup observable (pointer identity across jobs).
class FakeWorkSource : public core::stratum::IWorkSource {
public:
    core::stratum::StratumConfig cfg;
    std::atomic<uint64_t> generation{1};

    FakeWorkSource()
    {
        tmpl_["previousblockhash"] =
            "00000000000000000000000000000000000000000000000000000000000000aa";
        tmpl_["version"] = 0x20000000;
        tmpl_["bits"]    = "1e0fffff";
        tmpl_["curtime"] = 1700000000ULL;
        tmpl_["height"]  = 1;
        tx_data_ = std::make_shared<const std::vector<std::string>>();
    }

    const core::stratum::StratumConfig& get_stratum_config() const override { return cfg; }
    std::function<uint256()> get_best_share_hash_fn() const override { return {}; }
    std::string get_current_gbt_prevhash() const override
    {
        return tmpl_["previousblockhash"].get<std::string>();
    }
    uint64_t get_work_generation() const override { return generation.load(); }
    bool has_merged_chain(uint32_t) const override { return false; }

    void register_stratum_worker(const std::string&,
                                 const core::stratum::WorkerInfo&) override {}
    void unregister_stratum_worker(const std::string&) override {}
    void update_stratum_worker(const std::string&, double, double, double,
                               uint64_t, uint64_t, uint64_t) override {}

    nlohmann::json get_current_work_template() const override { return tmpl_; }
    std::vector<std::string> get_stratum_merkle_branches() const override { return {}; }
    std::pair<std::string, std::string> get_coinbase_parts() const override { return {"", ""}; }

    core::stratum::CoinbaseResult build_connection_coinbase(
        const uint256&, const std::string&,
        const std::vector<unsigned char>&,
        const std::vector<std::pair<uint32_t, std::vector<unsigned char>>>&) const override
    {
        core::stratum::CoinbaseResult r;
        r.coinb1 = "01000000010000000000000000000000000000000000000000000000000000"
                   "000000000000ffffffff";
        r.coinb2 = "0000000000f2052a010000001976a914000000000000000000000000000000"
                   "000000000088ac00000000";
        r.snapshot.tx_data = tx_data_;
        return r;
    }

    nlohmann::json mining_submit(const std::string&, const std::string&,
                                 const std::string&, const std::string&,
                                 const std::string&, const std::string&,
                                 const std::string&,
                                 const std::map<uint32_t, std::vector<unsigned char>>&,
                                 const core::stratum::JobSnapshot*) override
    {
        json r;
        r["result"] = true;
        r["error"]  = nullptr;
        return r;
    }

    uint32_t get_share_bits() const override { return 0; }
    uint32_t get_share_max_bits() const override { return 0; }

    double compute_share_difficulty(const std::string&, const std::string&,
                                    const std::string&, const std::string&,
                                    const std::string&, const std::string&,
                                    uint32_t, const std::string&, const std::string&,
                                    const std::vector<std::string>&) const override
    {
        return 1.0e12;  // always above vardiff → submission accepted
    }

private:
    nlohmann::json tmpl_;
    std::shared_ptr<const std::vector<std::string>> tx_data_;
};

// ── Server harness: real StratumServer on loopback, io thread in the test ──
// (The PRODUCT stays single-threaded; the extra thread here only drives the
// test's io_context the way each coin main's ioc.run() does.)
class ServerHarness {
public:
    asio::io_context ioc;
    std::shared_ptr<FakeWorkSource> ws = std::make_shared<FakeWorkSource>();
    std::unique_ptr<core::StratumServer> server;
    uint16_t port = 0;

    bool start()
    {
        // Ephemeral-ish port with retry (StratumServer::start binds a fixed port).
        for (uint16_t p = 39411; p < 39511; ++p) {
            auto s = std::make_unique<core::StratumServer>(ioc, "127.0.0.1", p, ws);
            if (s->start()) {
                server = std::move(s);
                port = p;
                break;
            }
        }
        if (!server) return false;
        guard_.emplace(asio::make_work_guard(ioc));
        th_ = std::thread([this] { ioc.run(); });
        return true;
    }

    // Run fn on the io thread and wait for it (quiesce barrier: asio handlers
    // execute FIFO on the single io thread, so fn sees all prior work done).
    template <typename F>
    auto on_io(F&& fn) -> decltype(fn())
    {
        std::promise<decltype(fn())> prom;
        auto fut = prom.get_future();
        asio::post(ioc, [&] { prom.set_value(fn()); });
        return fut.get();
    }

    void notify_storm(int n)
    {
        std::promise<void> done;
        asio::post(ioc, [&] {
            for (int i = 0; i < n; ++i)
                server->notify_all();
            done.set_value();
        });
        done.get_future().wait();
    }

    ~ServerHarness()
    {
        if (server) {
            std::promise<void> done;
            asio::post(ioc, [&] { server->stop(); done.set_value(); });
            done.get_future().wait();
        }
        guard_.reset();
        ioc.stop();
        if (th_.joinable()) th_.join();
    }

private:
    std::optional<asio::executor_work_guard<asio::io_context::executor_type>> guard_;
    std::thread th_;
};

// ── Minimal blocking stratum client with timeouts ───────────────────────────
class Client {
public:
    explicit Client() : sock_(io_) {}

    bool connect(uint16_t port)
    {
        boost::system::error_code ec;
        sock_.connect(tcp::endpoint(asio::ip::make_address("127.0.0.1"), port), ec);
        return !ec;
    }

    void send_json(const json& j)
    {
        auto line = std::make_shared<std::string>(j.dump() + "\n");
        boost::system::error_code ec;
        asio::write(sock_, asio::buffer(*line), ec);
    }

    // Read one \n-terminated line; nullopt on timeout or close.
    std::optional<std::string> read_line(std::chrono::milliseconds timeout = 3000ms)
    {
        std::optional<std::string> out;
        bool finished = false;
        asio::async_read_until(sock_, buf_, '\n',
            [&](boost::system::error_code ec, std::size_t) {
                finished = true;
                if (!ec) {
                    std::istream is(&buf_);
                    std::string line;
                    std::getline(is, line);
                    if (!line.empty() && line.back() == '\r') line.pop_back();
                    out = line;
                } else {
                    closed_ = true;
                }
            });
        io_.restart();
        io_.run_for(timeout);
        if (!finished) {
            boost::system::error_code ec;
            sock_.cancel(ec);
            io_.restart();
            io_.run();  // drain the aborted handler
            closed_ = false;  // timeout, not close
        }
        return out;
    }

    bool was_closed_by_peer() const { return closed_; }

    // Drive subscribe (+ optional authorize); records notify job ids in order.
    bool subscribe(int id = 1)
    {
        send_json({{"id", id}, {"method", "mining.subscribe"}, {"params", json::array()}});
        return wait_response(id).has_value();
    }
    bool authorize(const std::string& user, int id = 2)
    {
        send_json({{"id", id}, {"method", "mining.authorize"},
                   {"params", json::array({user, "x"})}});
        auto resp = wait_response(id);
        return resp && (*resp)["result"].is_boolean() && (*resp)["result"].get<bool>();
    }

    // Read until the response with the given id arrives; notifies encountered
    // along the way are recorded into jobs/last_ntime.
    std::optional<json> wait_response(int id, std::chrono::milliseconds timeout = 5000ms)
    {
        const auto deadline = std::chrono::steady_clock::now() + timeout;
        while (std::chrono::steady_clock::now() < deadline) {
            auto line = read_line(500ms);
            if (!line) {
                if (was_closed_by_peer()) return std::nullopt;
                continue;
            }
            json j = json::parse(*line, nullptr, false);
            if (j.is_discarded()) continue;
            record_notify(j);
            if (j.contains("id") && !j["id"].is_null() && j["id"] == id)
                return j;
        }
        return std::nullopt;
    }

    // Drain notifies until `count` job ids collected (or timeout).
    bool collect_notifies(size_t count, std::chrono::milliseconds timeout = 20000ms)
    {
        const auto deadline = std::chrono::steady_clock::now() + timeout;
        while (jobs.size() < count && std::chrono::steady_clock::now() < deadline) {
            auto line = read_line(500ms);
            if (!line) {
                if (was_closed_by_peer()) return false;
                continue;
            }
            json j = json::parse(*line, nullptr, false);
            if (j.is_discarded()) continue;
            record_notify(j);
        }
        return jobs.size() >= count;
    }

    // Submit against a job id; returns the response json (or nullopt).
    std::optional<json> submit(const std::string& user, const std::string& job_id, int id)
    {
        send_json({{"id", id}, {"method", "mining.submit"},
                   {"params", json::array({user, job_id, "00000000", last_ntime, "12345678"})}});
        return wait_response(id);
    }

    std::vector<std::string> jobs;         // job ids, in notify order
    std::string last_ntime = "65a812c0";   // overwritten by record_notify

private:
    void record_notify(const json& j)
    {
        if (j.contains("method") && j["method"] == "mining.notify"
            && j.contains("params") && j["params"].is_array()
            && j["params"].size() >= 9) {
            jobs.push_back(j["params"][0].get<std::string>());
            last_ntime = j["params"][7].get<std::string>();
        }
    }

    asio::io_context io_;
    tcp::socket sock_;
    asio::streambuf buf_;
    bool closed_ = false;
};

}  // namespace

// ════════════════════════════════════════════════════════════════════════════
// KAT 1 — STRICT per-node miner cap: 3rd connection refused, counter bumps,
// accept loop survives and admits again once a slot frees.
// ════════════════════════════════════════════════════════════════════════════
TEST(StratumHotelInterim, CapEnforcementThirdConnectionRefused)
{
    ServerHarness h;
    h.ws->cfg.max_stratum_connections = 2;
    ASSERT_TRUE(h.start());

    auto c1 = std::make_unique<Client>();
    auto c2 = std::make_unique<Client>();
    ASSERT_TRUE(c1->connect(h.port));
    ASSERT_TRUE(c1->subscribe());
    ASSERT_TRUE(c2->connect(h.port));
    ASSERT_TRUE(c2->subscribe());
    EXPECT_EQ(h.on_io([&] { return h.server->get_session_count(); }), 2u);

    // 3rd connection: TCP-accepted then cleanly closed by the cap gate.
    Client c3;
    ASSERT_TRUE(c3.connect(h.port));
    auto line = c3.read_line(3000ms);
    EXPECT_FALSE(line.has_value());
    EXPECT_TRUE(c3.was_closed_by_peer()) << "3rd connection must be closed by the cap";
    EXPECT_EQ(h.on_io([&] { return h.server->get_refused_connections(); }), 1u);

    // 4th connection also refused; counter increments again.
    Client c4;
    ASSERT_TRUE(c4.connect(h.port));
    (void)c4.read_line(3000ms);
    EXPECT_TRUE(c4.was_closed_by_peer());
    EXPECT_EQ(h.on_io([&] { return h.server->get_refused_connections(); }), 2u);

    // Existing miners are untouched: c1 still gets work on demand.
    h.notify_storm(1);
    EXPECT_TRUE(c1->collect_notifies(2, 5000ms));  // subscribe notify + storm notify

    // Free a slot → the accept loop must still be alive and admit a new miner
    // (dead-session prune runs at-cap inside handle_accept).
    c1.reset();
    std::this_thread::sleep_for(300ms);  // let the server observe the close
    Client c5;
    ASSERT_TRUE(c5.connect(h.port));
    EXPECT_TRUE(c5.subscribe()) << "freed slot must admit a new miner";
}

// ════════════════════════════════════════════════════════════════════════════
// KAT 2 — Stale-storm: 600-notify storm, then submit.
//   * current job (newest)      → ACCEPTED  (pre-fix arbitrary-evict rig:
//     this is the assertion that fails on `erase(active_jobs_.begin())`)
//   * recent job (inside FIFO window of 256) → ACCEPTED
//   * genuinely-oldest pre-storm job → STALE (cap enforced, oldest-first)
// ════════════════════════════════════════════════════════════════════════════
TEST(StratumHotelInterim, StaleStormFifoEviction)
{
    ServerHarness h;
    ASSERT_TRUE(h.start());

    Client c;
    ASSERT_TRUE(c.connect(h.port));
    ASSERT_TRUE(c.subscribe());
    ASSERT_TRUE(c.authorize("hoteltestworker1"));
    ASSERT_TRUE(c.collect_notifies(1, 5000ms));
    const size_t base = c.jobs.size();  // jobs issued by subscribe/authorize

    // Notify storm: 600 further jobs on this session.
    h.notify_storm(600);
    ASSERT_TRUE(c.collect_notifies(base + 600)) << "storm notifies not received";

    // Session retains at most MAX_ACTIVE_JOBS (256) — FIFO cap held.
    const auto stats = h.on_io([&] { return h.server->get_job_payload_stats(); });
    EXPECT_LE(stats.second, 256u);
    EXPECT_GE(stats.second, 200u);  // storm actually filled the window

    // (a) CURRENT job — the one the miner is hashing right now — must never
    // have been evicted. This submit FAILS pre-fix (arbitrary eviction).
    {
        auto resp = c.submit("hoteltestworker1", c.jobs.back(), 100);
        ASSERT_TRUE(resp.has_value());
        EXPECT_TRUE((*resp)["result"].is_boolean() && (*resp)["result"].get<bool>())
            << "current job rejected: " << resp->dump();
    }
    // (b) A recent job inside the newest-256 window survives too.
    {
        const std::string& recent = c.jobs[c.jobs.size() - 100];
        auto resp = c.submit("hoteltestworker1", recent, 101);
        ASSERT_TRUE(resp.has_value());
        EXPECT_TRUE((*resp)["result"].is_boolean() && (*resp)["result"].get<bool>())
            << "recent (in-window) job rejected: " << resp->dump();
    }
    // (c) The genuinely-oldest pre-storm job is beyond the 256-job FIFO window
    // → correctly stale (error 21). Guards against the cap silently vanishing.
    {
        auto resp = c.submit("hoteltestworker1", c.jobs.front(), 102);
        ASSERT_TRUE(resp.has_value());
        ASSERT_TRUE(resp->contains("error") && (*resp)["error"].is_array());
        EXPECT_EQ((*resp)["error"][0].get<int>(), 21) << resp->dump();
    }
}

// ════════════════════════════════════════════════════════════════════════════
// KAT 3 — Flat-RSS scaffold: N sessions × job churn keeps retained job memory
// bounded; the heavyweight template payload is POINTER-IDENTICAL across all
// jobs of one work generation (1 shared block per generation per session).
// ════════════════════════════════════════════════════════════════════════════
TEST(StratumHotelInterim, FlatRssSharedPayloadIdentity)
{
    ServerHarness h;
    ASSERT_TRUE(h.start());

    constexpr size_t kSessions = 3;
    constexpr int kChurn = 50;

    std::vector<std::unique_ptr<Client>> clients;
    for (size_t i = 0; i < kSessions; ++i) {
        auto c = std::make_unique<Client>();
        ASSERT_TRUE(c->connect(h.port));
        ASSERT_TRUE(c->subscribe());
        clients.push_back(std::move(c));
    }

    h.notify_storm(kChurn);
    for (auto& c : clients)
        ASSERT_TRUE(c->collect_notifies(1 + kChurn));

    // Quiesced read on the io thread: {distinct payload blocks, total jobs}.
    const auto [distinct, total] =
        h.on_io([&] { return h.server->get_job_payload_stats(); });

    // Job churn happened…
    EXPECT_GE(total, kSessions * kChurn);
    // …and per-session job count is bounded by the FIFO cap.
    EXPECT_LE(total, kSessions * 256u);
    // Pointer identity: ONE shared payload per (session × work generation) —
    // the fake source never bumps the generation and emits byte-identical
    // coinbase parts, so each session must hold exactly one payload block, not
    // one copy per job. This is the de-duped "memory bomb" assertion.
    EXPECT_EQ(distinct, kSessions)
        << "expected 1 shared payload per session (jobs=" << total << ")";
}
