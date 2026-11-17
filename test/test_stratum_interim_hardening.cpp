// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Interim hardening fix KATs — stratum admission cap + job eviction +
// shared-payload memory bound (core::StratumServer / core::StratumSession).
//
// Covers the three behavior changes of the "minimal stratum interim-hardening
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
//   5. LINE CAP — an inbound line longer than
//      StratumSession::kMaxStratumLineBytes (16384, p2pool/twisted
//      LineOnlyReceiver.MAX_LENGTH) without a '\n' drops the session instead
//      of growing the read buffer without bound. A line of exactly the cap is
//      still served, and pipelined lines whose total exceeds the cap are all
//      answered (only the bytes since the last '\n' count).
//
//   6. MWEB FIELDS — WorkSnapshot -> JobEntry -> JobSnapshot carries mweb and
//      mweb_active into mining_submit. Block assembly keys the MWEB shape
//      check on mweb_active; if the copy were lost, an empty-mweb block on an
//      MWEB chain would pass assembly.
//
//   7. DOA WINDOW — after a node restart rigs flush results for job ids the
//      previous process issued. Those submits are still answered "Stale
//      share" and still counted in the cumulative stale counter, but the
//      windowed DOA rate the miner page shows leaves them out; a genuinely
//      expired job of this connection still counts. The window rolls off.
//
//   8. ZOMBIE SESSIONS ON LTC — the LTC node's StratumConfig
//      (ltc::default_stratum_config, what main_ltc.cpp starts from) turns on
//      the BTC/DASH protections; under it a connection that never authorizes
//      is dropped at the deadline, an unauthorized session silent past the
//      idle timeout is reaped while a quiet authorized rig stays, and at the
//      miner cap such a zombie is closed at once so a new miner is admitted.
//      The deadlines are cut to test size where they are on and left off
//      where they are off. Plus the per-source-IP cap
//      (max_stratum_connections_per_ip, default 0 = unlimited), and the
//      rate limit on the refusal WARN lines (refusal_log_interval_sec), the
//      TCP liveness options on an accepted socket (TCP_USER_TIMEOUT), and the
//      per-IP key (an IPv6 address counts by its /64).
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
#include <core/web_server.hpp>   // MiningInterface: worker registry + /miner_stats
#include <impl/ltc/stratum_defaults.hpp>   // the LTC node's StratumConfig (main_ltc.cpp)

#include <atomic>
#include <chrono>
#include <cstdint>
#include <future>
#include <iostream>
#include <memory>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#ifdef __linux__
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#endif

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
    // MWEB fields put into every WorkSnapshot (defaults: a non-MWEB coin).
    std::string snap_mweb;
    bool        snap_mweb_active{false};
    // The JobSnapshot the last mining_submit received (io thread only).
    std::optional<core::stratum::JobSnapshot> last_job;
    // Optional worker registry the session bookkeeping is forwarded to, so a
    // test can read /miner_stats exactly as the web API serves it.
    core::MiningInterface* registry{nullptr};
    // While set, every connection coinbase is held (CoinbaseResult::held: the
    // sharechain busy); every build_connection_coinbase call is counted.
    std::atomic<bool> hold{false};
    mutable std::atomic<int> build_calls{0};

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

    void register_stratum_worker(const std::string& sid,
                                 const core::stratum::WorkerInfo& wi) override
    {
        if (registry) registry->register_stratum_worker(sid, wi);
    }
    void unregister_stratum_worker(const std::string& sid) override
    {
        if (registry) registry->unregister_stratum_worker(sid);
    }
    void update_stratum_worker(const std::string& sid, double hr, double dead, double diff,
                               uint64_t acc, uint64_t rej, uint64_t stale) override
    {
        if (registry) registry->update_stratum_worker(sid, hr, dead, diff, acc, rej, stale);
    }

    nlohmann::json get_current_work_template() const override { return tmpl_; }
    std::vector<std::string> get_stratum_merkle_branches() const override { return {}; }
    std::pair<std::string, std::string> get_coinbase_parts() const override { return {"", ""}; }

    core::stratum::CoinbaseResult build_connection_coinbase(
        const uint256&, const std::string&,
        const std::vector<unsigned char>&,
        const std::vector<std::pair<uint32_t, std::vector<unsigned char>>>&) const override
    {
        ++build_calls;
        core::stratum::CoinbaseResult r;
        if (hold.load()) {
            r.held = true;
            return r;
        }
        r.coinb1 = "01000000010000000000000000000000000000000000000000000000000000"
                   "000000000000ffffffff";
        r.coinb2 = "0000000000f2052a010000001976a914000000000000000000000000000000"
                   "000000000088ac00000000";
        r.snapshot.tx_data = tx_data_;
        r.snapshot.mweb = snap_mweb;
        r.snapshot.mweb_active = snap_mweb_active;
        return r;
    }

    nlohmann::json mining_submit(const std::string&, const std::string&,
                                 const std::string&, const std::string&,
                                 const std::string&, const std::string&,
                                 const std::string&,
                                 const std::map<uint32_t, std::vector<unsigned char>>&,
                                 const core::stratum::JobSnapshot* job) override
    {
        if (job) last_job = *job;
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

    // Connect from a given loopback source address (127.0.0.2 is another
    // client address on Linux). false when the address cannot be bound.
    bool connect_from(uint16_t port, const char* source)
    {
        boost::system::error_code ec;
        sock_.open(tcp::v4(), ec);
        if (!ec) sock_.bind(tcp::endpoint(asio::ip::make_address(source), 0), ec);
        if (!ec) sock_.connect(tcp::endpoint(asio::ip::make_address("127.0.0.1"), port), ec);
        if (ec) {
            boost::system::error_code ignore;
            sock_.close(ignore);
        }
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

    // Write raw bytes as-is (no '\n' appended).
    void send_raw(const std::string& bytes)
    {
        boost::system::error_code ec;
        asio::write(sock_, asio::buffer(bytes), ec);
    }

    // Read (and discard) lines until the peer closes; false on timeout.
    bool wait_closed(std::chrono::milliseconds timeout = 5000ms)
    {
        const auto deadline = std::chrono::steady_clock::now() + timeout;
        while (std::chrono::steady_clock::now() < deadline) {
            (void)read_line(500ms);
            if (was_closed_by_peer()) return true;
        }
        return false;
    }

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
    std::vector<bool> clean_flags;         // clean_jobs (params[8]) per notify, in order
    std::string last_ntime = "65a812c0";   // overwritten by record_notify

private:
    void record_notify(const json& j)
    {
        if (j.contains("method") && j["method"] == "mining.notify"
            && j.contains("params") && j["params"].is_array()
            && j["params"].size() >= 9) {
            jobs.push_back(j["params"][0].get<std::string>());
            clean_flags.push_back(j["params"][8].get<bool>());
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
TEST(StratumInterimHardening, CapEnforcementThirdConnectionRefused)
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
TEST(StratumInterimHardening, StaleStormFifoEviction)
{
    ServerHarness h;
    ASSERT_TRUE(h.start());

    Client c;
    ASSERT_TRUE(c.connect(h.port));
    ASSERT_TRUE(c.subscribe());
    ASSERT_TRUE(c.authorize("interimtestworker1"));
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
        auto resp = c.submit("interimtestworker1", c.jobs.back(), 100);
        ASSERT_TRUE(resp.has_value());
        EXPECT_TRUE((*resp)["result"].is_boolean() && (*resp)["result"].get<bool>())
            << "current job rejected: " << resp->dump();
    }
    // (b) A recent job inside the newest-256 window survives too.
    {
        const std::string& recent = c.jobs[c.jobs.size() - 100];
        auto resp = c.submit("interimtestworker1", recent, 101);
        ASSERT_TRUE(resp.has_value());
        EXPECT_TRUE((*resp)["result"].is_boolean() && (*resp)["result"].get<bool>())
            << "recent (in-window) job rejected: " << resp->dump();
    }
    // (c) The genuinely-oldest pre-storm job is beyond the 256-job FIFO window
    // → correctly stale (error 21). Guards against the cap silently vanishing.
    {
        auto resp = c.submit("interimtestworker1", c.jobs.front(), 102);
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
TEST(StratumInterimHardening, FlatRssSharedPayloadIdentity)
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

// ════════════════════════════════════════════════════════════════════════════
// KAT 4 — IDLE KEEPALIVE-NOTIFY (D9 60 s backup-watchdog flap fix,
// StratumConfig::keepalive_notify_sec). An idle, subscribe-only, NON-submitting
// session must keep receiving mining.notify at the keepalive cadence even though
// the work generation NEVER changes and no share is ever submitted — this is
// what keeps an idle BACKUP pool connection alive under a client-side no-notify
// watchdog (measured Antminer D9: drops a pool after 60 s without a notify). The
// keepalive refresh must be NON-clean (clean_jobs=false) so the ASIC's current
// work is not reset. A control run with keepalive OFF must NOT emit those extra
// notifies (proving the notifies are the keepalive, not some other path, and
// that other coins with keepalive_notify_sec==0 are unaffected).
//
// Uses a 1 s keepalive interval so the KAT runs in a few seconds of wall-clock
// while exercising the real per-session steady-timer path end-to-end.
TEST(StratumInterimHardening, IdleKeepaliveNotifyFeedsSubscribeOnlySession)
{
    ServerHarness h;
    h.ws->cfg.keepalive_notify_sec = 1;   // 1 s cadence for a fast KAT
    ASSERT_TRUE(h.start());

    Client c;
    ASSERT_TRUE(c.connect(h.port));
    ASSERT_TRUE(c.subscribe());           // subscribe-only: never authorize, never submit

    // The generation is pinned (FakeWorkSource::generation stays 1) and we drive
    // NO notify_storm, so every notify beyond the initial subscribe push is a
    // pure idle keepalive. Collect over ~4.5 s: at a 1 s cadence an idle session
    // must receive several. Without the keepalive this would time out at 1.
    const bool got = c.collect_notifies(4, 4500ms);
    EXPECT_TRUE(got) << "idle subscribe-only session received only "
                     << c.jobs.size() << " notify(ies) — keepalive not firing";
    EXPECT_GE(c.jobs.size(), 4u);

    // Every keepalive refresh after the first (subscribe) notify must be
    // NON-clean: clean_jobs=false, so the ASIC keeps hashing its current work.
    ASSERT_FALSE(c.clean_flags.empty());
    for (size_t i = 1; i < c.clean_flags.size(); ++i)
        EXPECT_FALSE(c.clean_flags[i])
            << "keepalive notify #" << i << " forced clean_jobs (would reset ASIC work)";

    // Generation never moved: the notifies came purely from the keepalive path,
    // not from a work-generation change.
    EXPECT_EQ(h.ws->generation.load(), 1u);
}

// KAT 4b — CONTROL: with keepalive OFF (keepalive_notify_sec==0, the default and
// the LTC/BTC/DGB setting), an idle subscribe-only session receives NO periodic
// notify — the periodic push stays purely work-generation-gated. This pins that
// the extra notifies in KAT 4 are the keepalive and that the feature is opt-in.
TEST(StratumInterimHardening, KeepaliveOffLeavesIdleSessionUnfed)
{
    ServerHarness h;
    h.ws->cfg.keepalive_notify_sec = 0;   // default / other-coins behaviour
    ASSERT_TRUE(h.start());

    Client c;
    ASSERT_TRUE(c.connect(h.port));
    ASSERT_TRUE(c.subscribe());
    const size_t after_subscribe = c.jobs.size();

    // No generation change, no storm, keepalive off: no further notify should
    // arrive. collect_notifies must TIME OUT (return false) here.
    const bool got_more = c.collect_notifies(after_subscribe + 2, 3500ms);
    EXPECT_FALSE(got_more)
        << "idle session got unexpected notifies with keepalive OFF (jobs="
        << c.jobs.size() << ")";
}

// ════════════════════════════════════════════════════════════════════════════
// Held jobs (CoinbaseResult::held: the sharechain was busy, no coinbase its
// shares could verify). No job goes out while held, never the global coinbase;
// one pending retry per session (every 500 ms) whatever the notify rate; a
// clean notify held meanwhile makes the retry clean; the hold is bounded by
// StratumConfig::job_hold_limit_sec, after which the session waits for the
// next notify.
// ════════════════════════════════════════════════════════════════════════════
TEST(StratumJobHold, OnePendingRetryPerSessionAndTheCleanFlagCarried)
{
    ServerHarness h;
    ASSERT_TRUE(h.start());

    Client c;
    ASSERT_TRUE(c.connect(h.port));
    ASSERT_TRUE(c.subscribe());
    ASSERT_TRUE(c.authorize("interimtestworker1"));
    ASSERT_TRUE(c.collect_notifies(1, 5000ms));
    const size_t base = c.jobs.size();

    h.ws->hold = true;
    const int calls0 = h.ws->build_calls.load();
    // a non-clean notify held first, then nine clean ones while its retry is
    // pending
    h.on_io([&] { h.server->notify_all(false); return 0; });
    h.on_io([&] { for (int i = 0; i < 9; ++i) h.server->notify_all(true); return 0; });
    std::this_thread::sleep_for(1200ms);
    const int held_calls = h.ws->build_calls.load() - calls0;
    // ten notifies and the retries at 0.5 s and 1.0 s (one pending at a time);
    // a timer per held notify would make it 10 + 20
    EXPECT_GE(held_calls, 11);
    EXPECT_LE(held_calls, 13);
    EXPECT_FALSE(c.collect_notifies(base + 1, 300ms)) << "no job while it is held";

    h.ws->hold = false;
    ASSERT_TRUE(c.collect_notifies(base + 1, 2000ms)) << "the pending retry sends the job";
    EXPECT_EQ(c.jobs.size(), base + 1) << "one job, not one per held notify";
    EXPECT_TRUE(c.clean_flags.back()) << "a clean notify was held: the retry is clean";
}

TEST(StratumJobHold, TheHoldIsBoundedThenWaitsForTheNextNotify)
{
    ServerHarness h;
    h.ws->cfg.job_hold_limit_sec = 1;
    ASSERT_TRUE(h.start());

    Client c;
    ASSERT_TRUE(c.connect(h.port));
    ASSERT_TRUE(c.subscribe());
    ASSERT_TRUE(c.authorize("interimtestworker1"));
    ASSERT_TRUE(c.collect_notifies(1, 5000ms));
    const size_t base = c.jobs.size();

    h.ws->hold = true;
    const int calls0 = h.ws->build_calls.load();
    h.on_io([&] { h.server->notify_all(true); return 0; });
    std::this_thread::sleep_for(2000ms);
    const int bounded = h.ws->build_calls.load() - calls0;
    // the notify and its retries until 1 s since the hold began
    EXPECT_GE(bounded, 2);
    EXPECT_LE(bounded, 4);
    std::this_thread::sleep_for(1500ms);
    EXPECT_EQ(h.ws->build_calls.load() - calls0, bounded) << "no retry past the limit";
    EXPECT_FALSE(c.collect_notifies(base + 1, 300ms)) << "the miner keeps its last job";

    // the next notify starts a new hold, and the job goes out once it can be
    // built
    h.on_io([&] { h.server->notify_all(true); return 0; });
    std::this_thread::sleep_for(700ms);
    EXPECT_GE(h.ws->build_calls.load() - calls0, bounded + 2);
    h.ws->hold = false;
    ASSERT_TRUE(c.collect_notifies(base + 1, 2000ms));
}

// ════════════════════════════════════════════════════════════════════════════
// KAT 5 — Stratum line cap (StratumSession::kMaxStratumLineBytes = 16384).
// Before the cap the session's streambuf had no max_size: a peer that never
// sent '\n' grew it until the process ran out of memory. p2pool's stratum
// (twisted LineOnlyReceiver, MAX_LENGTH = 16384) drops such a peer.
// ════════════════════════════════════════════════════════════════════════════

// mining.authorize padded through the password (the handler reads params[0]
// only) to exactly `len` bytes, excluding the '\n'.
static std::string padded_authorize(int id, size_t len)
{
    json j = {{"id", id}, {"method", "mining.authorize"},
              {"params", json::array({"interimtestworker1", ""})}};
    const size_t base = j.dump().size();
    j["params"][1] = std::string(len - base, 'x');
    return j.dump();
}

// 5a — 17 KiB without a newline: the session is closed and counted, and the
// server keeps serving other miners. Without the cap the server keeps reading
// and the connection stays open (wait_closed times out).
TEST(StratumInterimHardening, LineCapDropsOverlongLineWithoutNewline)
{
    ServerHarness h;
    ASSERT_TRUE(h.start());

    Client bad;
    ASSERT_TRUE(bad.connect(h.port));
    bad.send_raw(std::string(17 * 1024, 'a'));
    EXPECT_TRUE(bad.wait_closed()) << "over-length line must close the session";
    EXPECT_EQ(h.on_io([&] { return h.server->get_oversized_line_drops(); }), 1u);

    Client good;
    ASSERT_TRUE(good.connect(h.port));
    EXPECT_TRUE(good.subscribe()) << "server must keep serving after a drop";
    EXPECT_EQ(h.on_io([&] { return h.server->get_oversized_line_drops(); }), 1u);
}

// 5b — boundary: a line of exactly kMaxStratumLineBytes plus '\n' is served;
// one byte more is dropped (twisted: len(line) > MAX_LENGTH).
TEST(StratumInterimHardening, LineCapBoundaryExactCapServedOneMoreDropped)
{
    constexpr size_t kCap = core::StratumSession::kMaxStratumLineBytes;
    ServerHarness h;
    ASSERT_TRUE(h.start());

    Client at_cap;
    ASSERT_TRUE(at_cap.connect(h.port));
    ASSERT_TRUE(at_cap.subscribe());
    const std::string ok_line = padded_authorize(20, kCap);
    ASSERT_EQ(ok_line.size(), kCap);
    at_cap.send_raw(ok_line + "\n");
    auto resp = at_cap.wait_response(20);
    ASSERT_TRUE(resp.has_value()) << "line of exactly the cap must be served";
    EXPECT_TRUE((*resp)["result"].is_boolean() && (*resp)["result"].get<bool>())
        << resp->dump();
    EXPECT_EQ(h.on_io([&] { return h.server->get_oversized_line_drops(); }), 0u);

    Client over;
    ASSERT_TRUE(over.connect(h.port));
    ASSERT_TRUE(over.subscribe());
    const std::string long_line = padded_authorize(21, kCap + 1);
    ASSERT_EQ(long_line.size(), kCap + 1);
    over.send_raw(long_line + "\n");
    EXPECT_TRUE(over.wait_closed()) << "line of cap+1 bytes must close the session";
    EXPECT_EQ(h.on_io([&] { return h.server->get_oversized_line_drops(); }), 1u);
}

// 5c — pipelining: several lines in one write, together well over the cap but
// each under it, are all answered. The cap applies per line, not per read.
TEST(StratumInterimHardening, LineCapPipelinedLinesOverCapInTotalAllServed)
{
    ServerHarness h;
    ASSERT_TRUE(h.start());

    Client c;
    ASSERT_TRUE(c.connect(h.port));
    std::string burst =
        json({{"id", 1}, {"method", "mining.subscribe"}, {"params", json::array()}}).dump() + "\n";
    for (int id = 31; id <= 34; ++id)
        burst += padded_authorize(id, 12000) + "\n";
    ASSERT_GT(burst.size(), 2 * core::StratumSession::kMaxStratumLineBytes);
    c.send_raw(burst);

    EXPECT_TRUE(c.wait_response(1).has_value());
    for (int id = 31; id <= 34; ++id) {
        auto resp = c.wait_response(id);
        ASSERT_TRUE(resp.has_value()) << "pipelined line id=" << id << " not answered";
        EXPECT_TRUE((*resp)["result"].is_boolean() && (*resp)["result"].get<bool>())
            << resp->dump();
    }
    EXPECT_EQ(h.on_io([&] { return h.server->get_oversized_line_drops(); }), 0u);
}

// ════════════════════════════════════════════════════════════════════════════
// KAT 6 — MWEB fields survive the job freeze: the JobSnapshot handed to
// mining_submit carries the mweb data and mweb_active of the WorkSnapshot the
// job was built from (stratum_server.cpp JobEntry fill + submit snapshot).
// ════════════════════════════════════════════════════════════════════════════
TEST(StratumInterimHardening, JobSnapshotCarriesMwebFields)
{
    struct Case { std::string mweb; bool active; };
    for (const Case& cs : {Case{"", true}, Case{"abab", true}, Case{"", false}}) {
        ServerHarness h;
        h.ws->snap_mweb = cs.mweb;
        h.ws->snap_mweb_active = cs.active;
        ASSERT_TRUE(h.start());

        Client c;
        ASSERT_TRUE(c.connect(h.port));
        ASSERT_TRUE(c.subscribe());
        ASSERT_TRUE(c.authorize("mwebsnapshotworker"));
        ASSERT_TRUE(c.collect_notifies(1, 5000ms));

        auto resp = c.submit("mwebsnapshotworker", c.jobs.back(), 40);
        ASSERT_TRUE(resp.has_value());

        const auto seen = h.on_io([&] { return h.ws->last_job; });
        ASSERT_TRUE(seen.has_value()) << "mining_submit never saw the job";
        EXPECT_EQ(seen->mweb_active, cs.active) << "mweb_active lost in the job freeze";
        EXPECT_EQ(seen->mweb, cs.mweb);
    }
}

// ════════════════════════════════════════════════════════════════════════════
// KAT 7 — DOA window. Production 2026-10-26: after a hard reboot rigs flushed
// ~2600 results for job ids the previous process had issued; every one was
// counted stale and the miner page showed "Error 10.90%" (cumulative since
// connect) long after the burst ended, while the sharechain had 0 dead.
// ════════════════════════════════════════════════════════════════════════════
namespace {
bool is_stale_reply(const std::optional<json>& resp)
{
    return resp && (*resp)["result"].is_boolean() && !(*resp)["result"].get<bool>()
        && (*resp)["error"].is_array() && (*resp)["error"][0] == 21
        && (*resp)["error"][1] == "Stale share";
}
bool is_accepted_reply(const std::optional<json>& resp)
{
    return resp && (*resp)["result"].is_boolean() && (*resp)["result"].get<bool>();
}
}  // namespace

// Unknown-job submits after a restart stay out of the windowed DOA; a job this
// connection issued and then expired still counts. Reply to the miner and the
// cumulative fields are unchanged.
TEST(StratumDoaWindow, RestartBurstUnknownJobsStayOutOfWindowedDoa)
{
    const std::string user = "doawindowworker";
    core::MiningInterface registry(/*testnet=*/true, /*node=*/nullptr);
    ServerHarness h;
    h.ws->registry = &registry;
    ASSERT_TRUE(h.start());

    Client c;
    ASSERT_TRUE(c.connect(h.port));
    ASSERT_TRUE(c.subscribe());
    ASSERT_TRUE(c.authorize(user));
    ASSERT_TRUE(c.collect_notifies(1, 5000ms));
    const std::string first_job = c.jobs.front();

    // Phase 1: the rig flushes 40 results for jobs of the previous process
    // (ids this connection never issued), then 10 good shares.
    int id = 100;
    for (int i = 0; i < 40; ++i) {
        auto resp = c.submit(user, "job_" + std::to_string(7000000 + i), id++);
        ASSERT_TRUE(is_stale_reply(resp)) << "wire reply changed: "
                                          << (resp ? resp->dump() : "none");
    }
    for (int i = 0; i < 10; ++i)
        ASSERT_TRUE(is_accepted_reply(c.submit(user, c.jobs.back(), id++)));

    json r = registry.rest_miner_stats(user);
    // Cumulative fields keep their meaning: every submit whose job was not
    // active is stale.
    EXPECT_EQ(r["dead_shares"].get<uint64_t>(), 40u);
    EXPECT_EQ(r["orphan_shares"].get<uint64_t>(), 40u);
    EXPECT_EQ(r["total_shares"].get<uint64_t>(), 50u);
    EXPECT_EQ(r["unstale_shares"].get<uint64_t>(), 10u);
    EXPECT_EQ(r["rejected_shares"].get<uint64_t>(), 0u);
    EXPECT_DOUBLE_EQ(r["doa_rate"].get<double>(), 40.0 / 50.0);
    // The windowed rate leaves the unknown jobs out and lists them apart.
    ASSERT_TRUE(r.contains("doa_rate_window")) << r.dump();
    EXPECT_DOUBLE_EQ(r["doa_rate_window"].get<double>(), 0.0)
        << "restart leftovers must not read as DOA";
    EXPECT_EQ(r["window_seconds"].get<int64_t>(), 600);
    EXPECT_EQ(r["window_accepted_shares"].get<uint64_t>(), 10u);
    EXPECT_EQ(r["window_dead_shares"].get<uint64_t>(), 0u);
    EXPECT_EQ(r["window_unknown_job_shares"].get<uint64_t>(), 40u);
    EXPECT_EQ(r["unknown_job_shares"].get<uint64_t>(), 40u);

    // Phase 2: push the first job of this connection out of the active set
    // (FIFO cap 256), then the rig returns a late result for it: genuine stale.
    const size_t base = c.jobs.size();
    h.notify_storm(300);
    ASSERT_TRUE(c.collect_notifies(base + 300)) << "storm notifies not received";
    ASSERT_TRUE(is_stale_reply(c.submit(user, first_job, id++)));

    r = registry.rest_miner_stats(user);
    EXPECT_EQ(r["dead_shares"].get<uint64_t>(), 41u);
    EXPECT_DOUBLE_EQ(r["doa_rate"].get<double>(), 41.0 / 51.0);
    ASSERT_TRUE(r.contains("doa_rate_window")) << r.dump();
    EXPECT_EQ(r["window_dead_shares"].get<uint64_t>(), 1u)
        << "a job this connection issued and then expired is genuine stale";
    EXPECT_EQ(r["window_unknown_job_shares"].get<uint64_t>(), 40u);
    EXPECT_EQ(r["unknown_job_shares"].get<uint64_t>(), 40u);
    EXPECT_DOUBLE_EQ(r["doa_rate_window"].get<double>(), 1.0 / 11.0);
}

// The window drops outcomes older than kWindowSeconds; the cumulative
// unknown-job count does not roll off.
TEST(StratumDoaWindow, WindowRollsOffAfterTenMinutes)
{
    using W = core::stratum::SubmitOutcomeWindow;
    using std::chrono::minutes;
    using std::chrono::seconds;
    ASSERT_EQ(W::kWindowSeconds, 600);

    // A minute-aligned origin so bucket edges are exact.
    const auto t0 = std::chrono::steady_clock::time_point{} + minutes(100000);
    W w;
    for (int i = 0; i < 5; ++i) w.record(W::Outcome::UnknownJob, t0 + seconds(10));
    for (int i = 0; i < 3; ++i) w.record(W::Outcome::Stale, t0 + seconds(20));
    for (int i = 0; i < 7; ++i) w.record(W::Outcome::Accepted, t0 + seconds(30));
    w.record(W::Outcome::Accepted, t0 + minutes(5));

    auto c = w.window(t0 + seconds(40));
    EXPECT_EQ(c.unknown_job, 5u);
    EXPECT_EQ(c.stale, 3u);
    EXPECT_EQ(c.accepted, 7u);

    // 9 minutes later the first minute is still inside the window.
    c = w.window(t0 + minutes(9) + seconds(59));
    EXPECT_EQ(c.unknown_job, 5u);
    EXPECT_EQ(c.stale, 3u);
    EXPECT_EQ(c.accepted, 8u);

    // 10 minutes later it has rolled off; the minute-5 share has not.
    c = w.window(t0 + minutes(10));
    EXPECT_EQ(c.unknown_job, 0u);
    EXPECT_EQ(c.stale, 0u);
    EXPECT_EQ(c.accepted, 1u);

    // Everything gone after another 5 minutes; a new outcome reuses a bucket.
    c = w.window(t0 + minutes(15));
    EXPECT_EQ(c.accepted, 0u);
    w.record(W::Outcome::Stale, t0 + minutes(20));
    c = w.window(t0 + minutes(20));
    EXPECT_EQ(c.stale, 1u);
    EXPECT_EQ(c.accepted, 0u);
    EXPECT_EQ(c.unknown_job, 0u);

    EXPECT_EQ(w.unknown_job_total(), 5u) << "cumulative count does not roll off";
}

// ════════════════════════════════════════════════════════════════════════════
// KAT 8 — Drain hooks (#866 action 2): set_accepting(false) refuses new miners
// without touching live ones or the cap counter; drop_sessions(n) closes
// exactly min(n, live); set_accepting(true) restores the legacy accept path.
// ════════════════════════════════════════════════════════════════════════════
TEST(StratumInterimHardening, DrainHooksRefuseAndDropExactly)
{
    ServerHarness h;   // cap 0 = unlimited: only the drain gate can refuse
    ASSERT_TRUE(h.start());
    EXPECT_TRUE(h.on_io([&] { return h.server->is_accepting(); }));

    auto c1 = std::make_unique<Client>();
    auto c2 = std::make_unique<Client>();
    ASSERT_TRUE(c1->connect(h.port));
    ASSERT_TRUE(c1->subscribe());
    ASSERT_TRUE(c2->connect(h.port));
    ASSERT_TRUE(c2->subscribe());

    h.on_io([&] { h.server->set_accepting(false); return 0; });
    Client c3;
    ASSERT_TRUE(c3.connect(h.port));
    EXPECT_FALSE(c3.read_line(3000ms).has_value());
    EXPECT_TRUE(c3.was_closed_by_peer()) << "draining server must refuse new miners";
    EXPECT_EQ(h.on_io([&] { return h.server->get_refused_draining(); }), 1u);
    EXPECT_EQ(h.on_io([&] { return h.server->get_refused_connections(); }), 0u)
        << "drain refusals must not be booked as cap refusals";

    // Live miners are untouched by the gate itself.
    h.notify_storm(1);
    EXPECT_TRUE(c1->collect_notifies(2, 5000ms));
    EXPECT_TRUE(c2->collect_notifies(2, 5000ms));

    EXPECT_EQ(h.on_io([&] { return h.server->drop_sessions(0); }), 0u);
    EXPECT_EQ(h.on_io([&] { return h.server->drop_sessions(1); }), 1u);
    (void)c1->read_line(1500ms);
    (void)c2->read_line(1500ms);
    EXPECT_EQ(int(c1->was_closed_by_peer()) + int(c2->was_closed_by_peer()), 1)
        << "drop_sessions(1) must close exactly one of two live miners";
    std::this_thread::sleep_for(300ms);  // let the disconnect path unregister
    EXPECT_EQ(h.on_io([&] { return h.server->drop_sessions(99); }), 1u)
        << "drop_sessions clamps to the live count";

    h.on_io([&] { h.server->set_accepting(true); return 0; });
    Client c4;
    ASSERT_TRUE(c4.connect(h.port));
    EXPECT_TRUE(c4.subscribe()) << "accepting=true must restore the accept path";
}

// ════════════════════════════════════════════════════════════════════════════
// Zombie sessions on LTC (+ merged DOGE). Field: an LTC node held 100/100
// stratum slots and refused every real miner (refused_total=264674) because
// LTC left every StratumConfig zombie protection off: a half-open NAT-dead
// socket or a connection that never authorizes kept its slot forever.
// ════════════════════════════════════════════════════════════════════════════
namespace {

// The LTC node's compiled StratumConfig with each deadline that is ON cut to a
// test-sized value; a deadline that is OFF stays off. So these KATs see the
// node LTC actually runs: where LTC leaves a protection off, they see it off.
core::stratum::StratumConfig ltc_config_short(uint32_t handshake_s, uint32_t idle_s,
                                              uint32_t keepalive_notify_s)
{
    auto c = ltc::default_stratum_config();
    if (c.handshake_timeout_sec) c.handshake_timeout_sec = handshake_s;
    if (c.session_idle_timeout_sec) c.session_idle_timeout_sec = idle_s;
    if (c.keepalive_notify_sec) c.keepalive_notify_sec = keepalive_notify_s;
    return c;
}

double seconds_since(std::chrono::steady_clock::time_point t0)
{
    return std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
}

// The session behind c is still open and served: read what is already
// buffered (a closed socket shows here, after its buffered lines), then one
// more notify must arrive after a notify_all.
bool still_served(ServerHarness& h, Client& c)
{
    for (int i = 0; i < 200 && c.read_line(300ms); ++i) {}
    if (c.was_closed_by_peer()) return false;
    const size_t had = c.jobs.size();
    h.notify_storm(1);
    return c.collect_notifies(had + 1, 5000ms) && !c.was_closed_by_peer();
}

}  // namespace

// The config main_ltc.cpp starts from (before CLI/YAML) has the BTC/DASH
// protections on, with the BTC/DASH values; the per-IP cap stays opt-in.
TEST(LtcStratumZombie, DefaultsTurnTheProtectionsOn)
{
    const auto c = ltc::default_stratum_config();
    EXPECT_EQ(c.coin_symbol, "LTC");
    EXPECT_TRUE(c.tcp_keepalive_enabled);
    EXPECT_EQ(c.tcp_keepalive_idle_sec, 60u);
    EXPECT_EQ(c.tcp_keepalive_interval_sec, 10u);
    EXPECT_EQ(c.tcp_keepalive_count, 3u);
    EXPECT_EQ(c.handshake_timeout_sec, 30u);
    EXPECT_EQ(c.session_idle_timeout_sec, 1800u);
    EXPECT_EQ(c.max_write_queue_depth, 256u);
    EXPECT_EQ(c.keepalive_notify_sec, 25u);
    EXPECT_EQ(c.max_stratum_connections, 100u);
    EXPECT_EQ(c.max_stratum_connections_per_ip, 0u);
}

// A connection that never authorizes -- a bare TCP probe, or one that
// subscribes and stops -- is closed at the authorize deadline. A miner that
// authorizes is kept past it.
TEST(LtcStratumZombie, NeverAuthorizingConnectionIsDroppedAtTheDeadline)
{
    ServerHarness h;
    h.ws->cfg = ltc_config_short(/*handshake*/ 1, /*idle*/ 1800, /*keepalive notify*/ 25);
    ASSERT_TRUE(h.start());

    Client miner;
    ASSERT_TRUE(miner.connect(h.port));
    ASSERT_TRUE(miner.subscribe());
    ASSERT_TRUE(miner.authorize("ltcminer1"));

    const auto t0 = std::chrono::steady_clock::now();
    Client probe;                       // connects, sends nothing
    ASSERT_TRUE(probe.connect(h.port));
    Client subscriber;                  // subscribes, never authorizes
    ASSERT_TRUE(subscriber.connect(h.port));
    ASSERT_TRUE(subscriber.subscribe());

    EXPECT_TRUE(probe.wait_closed(6000ms)) << "a bare probe must not keep its slot";
    EXPECT_TRUE(subscriber.wait_closed(6000ms)) << "a never-authorizing session must not keep its slot";
    EXPECT_GE(seconds_since(t0), 0.9) << "closed at the deadline, not on accept";

    // The authorized miner is past the deadline too and still served.
    EXPECT_TRUE(still_served(h, miner)) << "authorize must disarm the deadline";
}

// The idle reaper counts INBOUND lines only. An unauthorized session that
// sends nothing is reaped although the node keeps sending it keepalive
// notifies; an unauthorized session that keeps talking is kept; an authorized
// rig that sends nothing (a low hashrate on a high fixed difficulty) is kept,
// because TCP keepalive -- on for LTC -- vouches for its socket.
TEST(LtcStratumZombie, IdleReaperReapsInboundSilenceButKeepsAQuietRig)
{
    ServerHarness h;
    // No authorize deadline here, so only the reaper can close a session. The
    // reaper sweeps every max(15 s, min(60 s, timeout / 2)): first sweep at 15 s.
    h.ws->cfg = ltc_config_short(/*handshake*/ 0, /*idle*/ 2, /*keepalive notify*/ 1);
    ASSERT_TRUE(h.start());

    Client rig;          // authorized, then silent
    ASSERT_TRUE(rig.connect(h.port));
    ASSERT_TRUE(rig.subscribe());
    ASSERT_TRUE(rig.authorize("ltcminer1"));
    Client zombie;       // subscribed, then silent (receives keepalive notifies)
    ASSERT_TRUE(zombie.connect(h.port));
    ASSERT_TRUE(zombie.subscribe());
    Client talker;       // subscribed, never authorizes, keeps sending lines
    ASSERT_TRUE(talker.connect(h.port));
    ASSERT_TRUE(talker.subscribe());

    const auto t0 = std::chrono::steady_clock::now();
    bool zombie_closed = false;
    int zombie_notifies = 0;
    int ping = 100;
    while (!zombie_closed && seconds_since(t0) < 22.0) {
        talker.send_json({{"id", ping++}, {"method", "mining.extranonce.subscribe"},
                          {"params", json::array()}});
        const auto line = zombie.read_line(400ms);
        if (line && line->find("mining.notify") != std::string::npos)
            ++zombie_notifies;
        zombie_closed = zombie.was_closed_by_peer();
    }
    EXPECT_TRUE(zombie_closed) << "an unauthorized session silent past the idle timeout must be reaped";
    EXPECT_GE(zombie_notifies, 3) << "the zombie was sent keepalive notifies meanwhile";

    // The quiet rig and the talker were swept over too and are still served.
    EXPECT_TRUE(still_served(h, rig)) << "a quiet authorized rig must not be reaped";
    EXPECT_TRUE(still_served(h, talker)) << "inbound lines must keep a session";
}

// At the miner cap a zombie (here: unauthorized and silent past the idle
// timeout, before the 15 s reaper sweep and the 30 s authorize deadline) is
// closed the moment a new connection arrives, and the new miner is admitted.
// A live quiet rig is not touched, and a fresh session is not a zombie.
TEST(LtcStratumZombie, AtTheCapAZombieMakesRoomForANewMiner)
{
    ServerHarness h;
    h.ws->cfg = ltc_config_short(/*handshake*/ 30, /*idle*/ 2, /*keepalive notify*/ 25);
    h.ws->cfg.max_stratum_connections = 2;
    ASSERT_TRUE(h.start());

    Client rig;
    ASSERT_TRUE(rig.connect(h.port));
    ASSERT_TRUE(rig.subscribe());
    ASSERT_TRUE(rig.authorize("ltcminer1"));
    Client zombie;
    ASSERT_TRUE(zombie.connect(h.port));
    ASSERT_TRUE(zombie.subscribe());

    // Not idle yet: the cap holds.
    Client early;
    ASSERT_TRUE(early.connect(h.port));
    EXPECT_FALSE(early.subscribe());
    EXPECT_TRUE(early.was_closed_by_peer()) << "a session inside its idle window is not a zombie";
    EXPECT_EQ(h.on_io([&] { return h.server->get_refused_connections(); }), 1u);

    std::this_thread::sleep_for(2600ms);   // the zombie is now idle past 2 s

    Client miner;
    ASSERT_TRUE(miner.connect(h.port));
    EXPECT_TRUE(miner.subscribe()) << "at the cap a zombie must make room for a new miner";
    EXPECT_TRUE(miner.authorize("ltcminer2"));
    EXPECT_TRUE(zombie.wait_closed(3000ms)) << "the zombie was the one closed";
    EXPECT_EQ(h.on_io([&] { return h.server->get_refused_connections(); }), 1u);

    EXPECT_TRUE(still_served(h, rig)) << "a quiet authorized rig is not a zombie";

    // Both slots now hold live miners: the next connection is refused.
    Client late;
    ASSERT_TRUE(late.connect(h.port));
    EXPECT_FALSE(late.subscribe());
    EXPECT_TRUE(late.was_closed_by_peer());
    EXPECT_EQ(h.on_io([&] { return h.server->get_refused_connections(); }), 2u);
}

// max_stratum_connections_per_ip: 0 (the default) leaves one address
// unlimited; N refuses that address's (N+1)th live session, counted apart
// from the node cap, while another address is still admitted and a freed
// slot admits the address again.
TEST(StratumPerIpCap, OneAddressCannotTakeEverySlot)
{
    ServerHarness h;
    ASSERT_TRUE(h.start());

    std::vector<std::unique_ptr<Client>> same;
    for (int i = 0; i < 3; ++i) {
        auto c = std::make_unique<Client>();
        ASSERT_TRUE(c->connect(h.port));
        ASSERT_TRUE(c->subscribe()) << "default per-IP cap 0 = unlimited (connection " << i << ")";
        same.push_back(std::move(c));
    }

    // The server reads the config on the io thread at each accept.
    h.on_io([&] { h.ws->cfg.max_stratum_connections_per_ip = 3; return 0; });
    Client fourth;
    ASSERT_TRUE(fourth.connect(h.port));
    EXPECT_FALSE(fourth.subscribe());
    EXPECT_TRUE(fourth.was_closed_by_peer()) << "a 4th session from one address must be refused";
    EXPECT_EQ(h.on_io([&] { return h.server->get_refused_per_ip(); }), 1u);
    EXPECT_EQ(h.on_io([&] { return h.server->get_refused_connections(); }), 0u)
        << "per-IP refusals are not node-cap refusals";

    Client other;
    if (other.connect_from(h.port, "127.0.0.2")) {
        EXPECT_TRUE(other.subscribe()) << "another address is still admitted";
    } else {
        std::cout << "[ SKIPPED part ] 127.0.0.2 not bindable here: other-address admission not checked\n";
    }

    same.front().reset();                 // free one of this address's slots
    std::this_thread::sleep_for(300ms);   // let the server see the close
    Client again;
    ASSERT_TRUE(again.connect(h.port));
    EXPECT_TRUE(again.subscribe()) << "a freed slot admits the address again";
    EXPECT_EQ(h.on_io([&] { return h.server->get_refused_per_ip(); }), 1u);
}

// Refusal WARN lines are rate-limited (StratumConfig::refusal_log_interval_sec,
// core/stratum_refusal_log.hpp): a reconnect storm against a full node gets
// its first refusal logged at once and the rest in one summary line when the
// window ends, while the refusal counter still counts every one.
TEST(StratumRefusalLog, CapStormCountsEveryRefusalButLogsTwoLines)
{
    ServerHarness h;
    h.ws->cfg.max_stratum_connections = 1;
    h.ws->cfg.refusal_log_interval_sec = 3;
    ASSERT_TRUE(h.start());

    Client miner;
    ASSERT_TRUE(miner.connect(h.port));
    ASSERT_TRUE(miner.subscribe());

    const auto t0 = std::chrono::steady_clock::now();
    for (int i = 0; i < 20; ++i) {
        Client c;
        ASSERT_TRUE(c.connect(h.port));
        ASSERT_TRUE(c.wait_closed(3000ms)) << "connection " << i << " must be refused";
    }
    const double storm_s = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
    EXPECT_EQ(h.on_io([&] { return h.server->get_refused_connections(); }), 20u)
        << "every refusal is counted";
    if (storm_s < 2.5) {   // the storm fit in one window (it takes milliseconds)
        EXPECT_EQ(h.on_io([&] { return h.server->get_refusal_lines_logged(); }), 1u)
            << "only the first refusal is logged at once";
    }

    // The summary of the other 19 is written when the window ends, with no
    // further refusal to trigger it.
    uint64_t lines = 0;
    for (int i = 0; i < 60 && lines < 2; ++i) {
        std::this_thread::sleep_for(100ms);
        lines = h.on_io([&] { return h.server->get_refusal_lines_logged(); });
    }
    std::this_thread::sleep_for(500ms);
    lines = h.on_io([&] { return h.server->get_refusal_lines_logged(); });
    if (storm_s < 2.5)
        EXPECT_EQ(lines, 2u) << "one summary line for the rest of the window";
    EXPECT_LE(lines, 3u) << "20 refusals must not write 20 lines";
    EXPECT_EQ(h.on_io([&] { return h.server->get_refused_connections(); }), 20u);
}

// TCP liveness on an accepted stratum socket (core::apply_stratum_tcp_liveness,
// which StratumSession::start() runs). Linux sends no keepalive probe while
// sent data is unacknowledged, and an authorized rig is fed a notify every
// keepalive_notify_sec, so behind a dead NAT only TCP_USER_TIMEOUT ends such
// a session in minutes rather than after tcp_retries2 (~15 min). The default
// applies to every coin that turns keepalive on (BTC and DASH leave it as is).
TEST(StratumTcpLiveness, KeepaliveSocketGetsProbeTimingAndUserTimeout)
{
    EXPECT_EQ(core::stratum::StratumConfig{}.tcp_user_timeout_sec, 120u);
    EXPECT_EQ(ltc::default_stratum_config().tcp_user_timeout_sec, 120u);
#ifndef __linux__
    GTEST_SKIP() << "per-probe tuning and TCP_USER_TIMEOUT are Linux socket options";
#else
    asio::io_context io;
    tcp::acceptor acc(io, tcp::endpoint(asio::ip::make_address("127.0.0.1"), 0));
    tcp::socket client(io);
    tcp::socket server(io);
    client.connect(acc.local_endpoint());
    acc.accept(server);
    const auto get = [&](int level, int opt) {
        int v = -1;
        socklen_t len = sizeof v;
        if (::getsockopt(server.native_handle(), level, opt, &v, &len) != 0) return -2;
        return v;
    };

    core::apply_stratum_tcp_liveness(server, core::stratum::StratumConfig{});   // keepalive off (DGB, BCH)
    EXPECT_EQ(get(SOL_SOCKET, SO_KEEPALIVE), 0) << "keepalive off: the socket is left alone";
    EXPECT_EQ(get(IPPROTO_TCP, TCP_USER_TIMEOUT), 0);

    core::apply_stratum_tcp_liveness(server, ltc::default_stratum_config());
    EXPECT_NE(get(SOL_SOCKET, SO_KEEPALIVE), 0);
    EXPECT_EQ(get(IPPROTO_TCP, TCP_KEEPIDLE), 60);
    EXPECT_EQ(get(IPPROTO_TCP, TCP_KEEPINTVL), 10);
    EXPECT_EQ(get(IPPROTO_TCP, TCP_KEEPCNT), 3);
    EXPECT_EQ(get(IPPROTO_TCP, TCP_USER_TIMEOUT), 120000)
        << "unacknowledged data (the keepalive notifies) must not keep a dead peer for tcp_retries2";
#endif
}

// The per-IP cap counts an IPv6 address by its /64 (one host is handed a whole
// /64 and could rotate through it), an IPv4-mapped address as its IPv4
// address, and an IPv4 address as itself.
TEST(StratumPerIpCap, Ipv6CountsByItsSlash64)
{
    const auto key = [](const char* a) { return core::per_ip_cap_key(asio::ip::make_address(a)); };
    EXPECT_EQ(key("2001:db8:1:2::10"), key("2001:db8:1:2:aaaa:bbbb:cccc:dddd"));
    EXPECT_NE(key("2001:db8:1:2::10"), key("2001:db8:1:3::10"));
    EXPECT_EQ(key("::ffff:203.0.113.7"), key("203.0.113.7"));
    EXPECT_NE(key("203.0.113.7"), key("203.0.113.8"));
    EXPECT_EQ(key("203.0.113.7"), asio::ip::make_address("203.0.113.7"));
}
