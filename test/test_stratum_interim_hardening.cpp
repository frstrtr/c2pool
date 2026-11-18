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
    // MWEB fields put into every WorkSnapshot (defaults: a non-MWEB coin).
    std::string snap_mweb;
    bool        snap_mweb_active{false};
    // Share bits frozen into every WorkSnapshot (the job's pool-share
    // difficulty; 0 = none) and the difficulty every submission hashes to.
    std::atomic<uint32_t> snap_share_bits{0};
    std::atomic<double>   hash_diff{1.0e12};
    // mining_submit calls (pool shares and blocks).
    std::atomic<int>      submit_calls{0};
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
        r.snapshot.frozen_ref.bits = snap_share_bits.load();
        return r;
    }

    nlohmann::json mining_submit(const std::string&, const std::string&,
                                 const std::string&, const std::string&,
                                 const std::string&, const std::string&,
                                 const std::string&,
                                 const std::map<uint32_t, std::vector<unsigned char>>&,
                                 const core::stratum::JobSnapshot* job) override
    {
        ++submit_calls;
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
        return hash_diff.load();  // default 1e12: always above vardiff → accepted
    }

    // Block bits of the template (call before the server starts).
    void set_block_bits(const std::string& bits) { tmpl_["bits"] = bits; }

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
        return authorize_with(user, "x", id);
    }
    bool authorize_with(const std::string& user, const std::string& password, int id = 2)
    {
        send_json({{"id", id}, {"method", "mining.authorize"},
                   {"params", json::array({user, password})}});
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

    // Pipeline n submits against one job in a single write (a rig's burst),
    // then read until all n replies arrive. Returns the number accepted, -1
    // on timeout.
    int submit_burst(const std::string& user, const std::string& job_id, int n, int first_id,
                     std::chrono::milliseconds timeout = 20000ms)
    {
        std::string bytes;
        for (int i = 0; i < n; ++i)
            bytes += json({{"id", first_id + i}, {"method", "mining.submit"},
                           {"params", json::array({user, job_id, "00000000", last_ntime, "12345678"})}})
                         .dump() + "\n";
        send_raw(bytes);
        int replies = 0, accepted = 0;
        const auto deadline = std::chrono::steady_clock::now() + timeout;
        while (replies < n && std::chrono::steady_clock::now() < deadline) {
            auto line = read_line(500ms);
            if (!line) {
                if (was_closed_by_peer()) return -1;
                continue;
            }
            json j = json::parse(*line, nullptr, false);
            if (j.is_discarded()) continue;
            record_notify(j);
            if (j.contains("id") && j["id"].is_number_integer()) {
                const int id = j["id"].get<int>();
                if (id >= first_id && id < first_id + n) {
                    ++replies;
                    if (j["result"].is_boolean() && j["result"].get<bool>()) ++accepted;
                }
            }
        }
        return replies == n ? accepted : -1;
    }

    // Read whatever arrives within `quiet` (notifies, set_difficulty).
    void drain(std::chrono::milliseconds quiet = 300ms)
    {
        while (auto line = read_line(quiet)) {
            json j = json::parse(*line, nullptr, false);
            if (!j.is_discarded()) record_notify(j);
        }
    }

    std::vector<std::string> jobs;         // job ids, in notify order
    std::vector<bool> clean_flags;         // clean_jobs (params[8]) per notify, in order
    std::string last_ntime = "65a812c0";   // overwritten by record_notify
    std::vector<double> set_diffs;         // mining.set_difficulty values (wire), in order
    std::vector<double> diff_at_notify;    // the last set_difficulty before each notify (-1: none)

private:
    void record_notify(const json& j)
    {
        if (j.contains("method") && j["method"] == "mining.set_difficulty"
            && j.contains("params") && j["params"].is_array() && !j["params"].empty()
            && j["params"][0].is_number())
            set_diffs.push_back(j["params"][0].get<double>());
        if (j.contains("method") && j["method"] == "mining.notify"
            && j.contains("params") && j["params"].is_array()
            && j["params"].size() >= 9) {
            jobs.push_back(j["params"][0].get<std::string>());
            clean_flags.push_back(j["params"][8].get<bool>());
            diff_at_notify.push_back(set_diffs.empty() ? -1.0 : set_diffs.back());
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
// KAT 6b — Vardiff runaway + pool-share bound (core: LTC, BTC and DASH serve
// miners through this one server). Field (LTC, 2026-11): a restarted node's 15
// ASIC rigs all came up at max_difficulty 65536; four stayed. Each started at
// the 0.0005 floor and sent a burst of floor shares before applying the first
// raise; the issued-difficulty grace accepted them, and every accepted share
// was timed as if found at the CURRENT difficulty: 10x per 12 shares, 0.0005 ->
// 65536 in ~109 floor shares. At 65536 a 15 GH/s rig finds a pseudoshare every
// ~5 h, and it withholds every pool share under 65536 (~99% of its PPLNS
// weight; the pool-share difficulty was ~660). Covered here on the wire:
//   - a floor burst on the old job no longer ramps the session;
//   - no job is issued, and no set_difficulty sent, above the job's pool-share
//     difficulty (p2pool: target = max(target, share target)), and a share at
//     exactly the pool-share difficulty reaches share creation;
//   - a rig ramped high comes back within one share period (the next job) and
//     steps down after one share at the bound;
//   - "d=N" in the password (start, wire units), "+N" on the login (fixed,
//     internal units as in python p2pool), their bound and their precedence
//     over mining.suggest_difficulty.
// Each coin case runs the same code: LTC (wire = 65536 x internal, ratio
// vardiff), BTC (wire = internal, ratio vardiff), DASH (wire = internal,
// hashrate vardiff, 10 s target).
// ════════════════════════════════════════════════════════════════════════════
namespace {

constexpr uint32_t kPoolBitsDiff1 = 0x1d00ffff;   // pool-share difficulty 1.0 (the diff-1 target)
constexpr double   kPoolDiff1 = 1.0;
constexpr const char* kHardBlockBits = "1a00ffff"; // block difficulty 2^24: a pool share is not a block

struct CoinCase { const char* name; double mult; bool hashrate_vardiff; double target; };
const CoinCase kLtcCase{"LTC", 65536.0, false, 3.0};
const CoinCase kBtcCase{"BTC", 1.0, false, 3.0};
const CoinCase kDashCase{"DASH", 1.0, true, 10.0};

void apply_case(ServerHarness& h, const CoinCase& cc)
{
    h.ws->cfg.set_difficulty_multiplier = cc.mult;
    h.ws->cfg.use_hashrate_vardiff = cc.hashrate_vardiff;
    h.ws->cfg.target_time = cc.target;
    h.ws->set_block_bits(kHardBlockBits);
}

// subscribe (its set_difficulty + job), then authorize and its job.
bool login(Client& c, const std::string& user, const std::string& password = "x")
{
    if (!c.subscribe() || !c.collect_notifies(1, 5000ms))
        return false;
    const size_t n = c.jobs.size();
    return c.authorize_with(user, password) && c.collect_notifies(n + 1, 5000ms);
}

// A rig that applies every raise at once: bursts of 13 on the newest job until
// the advertised difficulty reaches `wire_goal` or `rounds` run out.
void ramp(Client& c, const std::string& user, double wire_goal, int rounds, int& id)
{
    for (int r = 0; r < rounds && !(c.set_diffs.back() >= wire_goal); ++r) {
        ASSERT_EQ(c.submit_burst(user, c.jobs.back(), 13, id), 13);
        id += 13;
    }
}

bool accepted(const std::optional<json>& resp)
{
    return resp && (*resp)["result"].is_boolean() && (*resp)["result"].get<bool>();
}

}  // namespace

// KAT 1 (+5): 120 accepted submits of the start job (issued at 0.0005) in one
// burst. Master: LTC/BTC end at 65536.
TEST(StratumVardiff, FloorBurstOnOldJobDoesNotRunAway)
{
    for (const CoinCase& cc : {kLtcCase, kBtcCase, kDashCase}) {
        SCOPED_TRACE(cc.name);
        ServerHarness h;
        apply_case(h, cc);
        h.ws->hash_diff = 0.001;   // a floor share
        ASSERT_TRUE(h.start());

        Client c;
        ASSERT_TRUE(c.connect(h.port));
        const std::string user = "vardiffburstworker";
        ASSERT_TRUE(login(c, user));
        ASSERT_DOUBLE_EQ(c.diff_at_notify.back(), 0.0005 * cc.mult) << "start job at the floor";

        const auto t0 = std::chrono::steady_clock::now();
        ASSERT_EQ(c.submit_burst(user, c.jobs.back(), 120, 1000), 120);
        const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                            std::chrono::steady_clock::now() - t0).count();
        c.drain(200ms);
        const double internal = c.set_diffs.back() / cc.mult;
        printf("[%s] 120-share floor burst answered in %lld ms; difficulty now %g (internal)\n",
               cc.name, static_cast<long long>(ms), internal);
        if (cc.hashrate_vardiff)
            EXPECT_LE(internal, 0.0625) << "hashrate vardiff: bounded by the credited work";
        else
            EXPECT_LE(internal, 0.005 * (1.0 + 1e-9)) << "floor burst ran the vardiff away";
    }
}

// KAT 2 (+5): a rig fast enough for any difficulty is never issued one above
// its job's pool-share difficulty, and a share at exactly that difficulty is
// accepted and goes to share creation. Master: ramps to 65536, the share is
// rejected "Low difficulty share".
TEST(StratumVardiff, NeverIssuedAbovePoolShareDifficulty)
{
    for (const CoinCase& cc : {kLtcCase, kBtcCase, kDashCase}) {
        SCOPED_TRACE(cc.name);
        ServerHarness h;
        apply_case(h, cc);
        h.ws->snap_share_bits = kPoolBitsDiff1;
        h.ws->hash_diff = 1.0e6;
        ASSERT_TRUE(h.start());

        Client c;
        ASSERT_TRUE(c.connect(h.port));
        const std::string user = "vardiffboundworker";
        ASSERT_TRUE(login(c, user));
        const double pool_wire = kPoolDiff1 * cc.mult;
        int id = 1000;
        ramp(c, user, 65536.0 * cc.mult, 40, id);
        c.drain(200ms);

        for (double d : c.set_diffs)
            EXPECT_LE(d, pool_wire) << "set_difficulty above the pool-share difficulty";
        for (double d : c.diff_at_notify)
            EXPECT_LE(d, pool_wire) << "a job issued above the pool-share difficulty";
        EXPECT_DOUBLE_EQ(c.set_diffs.back(), pool_wire) << "a fast rig sits at the bound";

        const int before = h.ws->submit_calls.load();
        h.ws->hash_diff = kPoolDiff1;
        EXPECT_TRUE(accepted(c.submit(user, c.jobs.back(), id++)))
            << "a share at the pool-share difficulty was rejected";
        EXPECT_EQ(h.ws->submit_calls.load(), before + 1) << "the pool share never reached share creation";
    }
}

// KAT 3: a rig ramped to 65536 while no pool-share bits were known. The next
// job (one sharechain share later) carries them: set_difficulty at the bound
// goes out ahead of it, the rig's next share at the bound is a pool share,
// and that one share brings the vardiff down. Test-sized target time (50 ms),
// so "past 10 x 2 x target" is 1 s.
TEST(StratumVardiff, MisRampedRigComesBackWithinOneShare)
{
    for (const CoinCase& cc : {kLtcCase, kBtcCase}) {
        SCOPED_TRACE(cc.name);
        ServerHarness h;
        apply_case(h, cc);
        h.ws->cfg.target_time = 0.05;
        h.ws->hash_diff = 1.0e6;
        ASSERT_TRUE(h.start());

        Client c;
        ASSERT_TRUE(c.connect(h.port));
        const std::string user = "vardiffmisrampworker";
        ASSERT_TRUE(login(c, user));
        int id = 1000;
        ramp(c, user, 65536.0 * cc.mult, 60, id);
        ASSERT_DOUBLE_EQ(c.set_diffs.back(), 65536.0 * cc.mult) << "precondition: ramped to max";

        h.ws->snap_share_bits = kPoolBitsDiff1;
        const size_t jobs_before = c.jobs.size();
        h.on_io([&] { h.server->notify_all(false); return 0; });
        ASSERT_TRUE(c.collect_notifies(jobs_before + 1, 5000ms));
        EXPECT_DOUBLE_EQ(c.diff_at_notify.back(), kPoolDiff1 * cc.mult)
            << "the next job must be issued (and announced) at the pool-share difficulty";

        std::this_thread::sleep_for(1200ms);   // the rig's share interval at the bound
        const int before = h.ws->submit_calls.load();
        h.ws->hash_diff = kPoolDiff1;
        EXPECT_TRUE(accepted(c.submit(user, c.jobs.back(), id++)));
        EXPECT_EQ(h.ws->submit_calls.load(), before + 1) << "the share at the bound is a pool share";
        c.drain(200ms);
        EXPECT_LT(c.set_diffs.back(), kPoolDiff1 * cc.mult)
            << "one share at the bound must bring the vardiff down";
    }
}

// "d=4096" in the password: the session's start difficulty in WIRE units, sent
// with set_difficulty at authorize, ahead of the first job; the floor job's
// burst does not move it (ratio vardiff) or only lowers it (hashrate vardiff).
TEST(StratumVardiff, PasswordStartDifficultySentAtOnce)
{
    for (const CoinCase& cc : {kLtcCase, kBtcCase, kDashCase}) {
        SCOPED_TRACE(cc.name);
        ServerHarness h;
        apply_case(h, cc);
        h.ws->hash_diff = 0.001;
        ASSERT_TRUE(h.start());

        Client c;
        ASSERT_TRUE(c.connect(h.port));
        const std::string user = "vardiffpasswordworker";
        ASSERT_TRUE(c.subscribe());
        ASSERT_TRUE(c.collect_notifies(1, 5000ms));
        const std::string floor_job = c.jobs.back();
        const size_t sd = c.set_diffs.size(), nj = c.jobs.size();
        ASSERT_TRUE(c.authorize_with(user, "x,d=4096"));
        ASSERT_TRUE(c.collect_notifies(nj + 1, 5000ms));
        ASSERT_GT(c.set_diffs.size(), sd) << "no set_difficulty after authorize";
        EXPECT_DOUBLE_EQ(c.set_diffs[sd], 4096.0) << "d=4096 is wire units";
        EXPECT_DOUBLE_EQ(c.diff_at_notify.back(), 4096.0);

        ASSERT_EQ(c.submit_burst(user, floor_job, 120, 1000), 120);
        c.drain(200ms);
        if (cc.hashrate_vardiff)
            EXPECT_LE(c.set_diffs.back(), 4096.0);
        else
            EXPECT_DOUBLE_EQ(c.set_diffs.back(), 4096.0) << "the floor burst moved the start difficulty";
    }
    // The other separator and order.
    ServerHarness h;
    ASSERT_TRUE(h.start());
    Client c;
    ASSERT_TRUE(c.connect(h.port));
    ASSERT_TRUE(login(c, "vardiffpasswordworker2", "d=8192;x"));
    EXPECT_DOUBLE_EQ(c.diff_at_notify.back(), 8192.0);
}

// "d=" above the pool-share difficulty is issued at it.
TEST(StratumVardiff, PasswordStartDifficultyBoundedByPoolShare)
{
    for (const CoinCase& cc : {kLtcCase, kBtcCase, kDashCase}) {
        SCOPED_TRACE(cc.name);
        ServerHarness h;
        apply_case(h, cc);
        h.ws->snap_share_bits = kPoolBitsDiff1;
        ASSERT_TRUE(h.start());
        Client c;
        ASSERT_TRUE(c.connect(h.port));
        ASSERT_TRUE(login(c, "vardiffpwboundworker", "d=100000000"));
        EXPECT_DOUBLE_EQ(c.diff_at_notify.back(), kPoolDiff1 * cc.mult);
        for (double d : c.set_diffs)
            EXPECT_LE(d, kPoolDiff1 * cc.mult);
    }
}

// Garbage, zero, negative, non-finite and empty "d=" values are ignored: the
// login succeeds and the difficulty stays where it was.
TEST(StratumVardiff, PasswordGarbageIgnored)
{
    for (const char* pw : {"d=abc", "d=-5", "d=0", "d=", "d=inf", "d=nan", "x,d=1e999", "d=0x10"}) {
        SCOPED_TRACE(pw);
        ServerHarness h;
        ASSERT_TRUE(h.start());
        Client c;
        ASSERT_TRUE(c.connect(h.port));
        ASSERT_TRUE(login(c, "vardiffgarbageworker", pw)) << "a bad d= must not fail the login";
        c.drain(200ms);
        for (double d : c.set_diffs)
            EXPECT_DOUBLE_EQ(d, 0.0005 * 65536.0);
    }
}

// "ADDR+N": a fixed difficulty in INTERNAL units, as python p2pool reads it
// (difficulty_to_target(float(N))), so the miner is sent N x the wire
// multiplier: "+1" is 65536 on LTC, "+4" is 4 on BTC and DASH. Sent at
// authorize, bounded by the pool-share difficulty, not moved by vardiff.
TEST(StratumVardiff, PlusSuffixIsFixedSentAndBounded)
{
    for (const CoinCase& cc : {kLtcCase, kBtcCase, kDashCase}) {
        SCOPED_TRACE(cc.name);
        ServerHarness h;
        apply_case(h, cc);
        h.ws->hash_diff = 1.0e6;
        ASSERT_TRUE(h.start());
        Client c;
        ASSERT_TRUE(c.connect(h.port));
        const std::string user = "vardiffplusworker";
        const bool scrypt = cc.mult > 1.0;
        const double wire = scrypt ? 1.0 * cc.mult : 4.0;   // "+1" on LTC, "+4" on BTC/DASH
        ASSERT_TRUE(c.subscribe());
        ASSERT_TRUE(c.collect_notifies(1, 5000ms));
        const size_t sd = c.set_diffs.size(), nj = c.jobs.size();
        ASSERT_TRUE(c.authorize(user + (scrypt ? "+1" : "+4")));
        ASSERT_TRUE(c.collect_notifies(nj + 1, 5000ms));
        ASSERT_GT(c.set_diffs.size(), sd) << "+N never sent";
        EXPECT_DOUBLE_EQ(c.set_diffs[sd], wire) << "+N is internal units: wire = N x multiplier";
        EXPECT_DOUBLE_EQ(c.diff_at_notify.back(), wire);
        int id = 1000;
        for (int r = 0; r < 4; ++r, id += 13)
            ASSERT_EQ(c.submit_burst(user, c.jobs.back(), 13, id), 13);
        c.drain(200ms);
        EXPECT_DOUBLE_EQ(c.set_diffs.back(), wire) << "vardiff moved a fixed +N";
    }
    {
        ServerHarness h;
        h.ws->snap_share_bits = kPoolBitsDiff1;
        ASSERT_TRUE(h.start());
        Client c;
        ASSERT_TRUE(c.connect(h.port));
        ASSERT_TRUE(login(c, "vardiffplusworker+1000000"));
        EXPECT_DOUBLE_EQ(c.diff_at_notify.back(), kPoolDiff1 * 65536.0) << "+N above the pool-share difficulty";
        for (double d : c.set_diffs)
            EXPECT_LE(d, kPoolDiff1 * 65536.0);
    }
}

// The two units side by side: "+N" internal, "d=N" wire. On scrypt "+1" and
// "d=65536" send the same difficulty; on BTC "+4096" and "d=4096" do.
TEST(StratumVardiff, PlusSuffixInternalPasswordWire)
{
    for (const CoinCase& cc : {kLtcCase, kBtcCase}) {
        SCOPED_TRACE(cc.name);
        const bool scrypt = cc.mult > 1.0;
        const double wire = scrypt ? 65536.0 : 4096.0;
        {
            ServerHarness h;
            apply_case(h, cc);
            ASSERT_TRUE(h.start());
            Client c;
            ASSERT_TRUE(c.connect(h.port));
            ASSERT_TRUE(login(c, std::string("vardiffunitsworker") + (scrypt ? "+1" : "+4096")));
            EXPECT_DOUBLE_EQ(c.diff_at_notify.back(), wire);
        }
        {
            ServerHarness h;
            apply_case(h, cc);
            ASSERT_TRUE(h.start());
            Client c;
            ASSERT_TRUE(c.connect(h.port));
            ASSERT_TRUE(login(c, "vardiffunitsworker", scrypt ? "d=65536" : "d=4096"));
            EXPECT_DOUBLE_EQ(c.diff_at_notify.back(), wire);
        }
    }
}

// Precedence: "+N" is fixed (d=N and mining.suggest_difficulty ignored);
// without it, d=N starts the session and a later suggest_difficulty wins.
TEST(StratumVardiff, PlusSuffixOverPasswordOverNothing)
{
    auto suggest = [](Client& c, double wire, int id) {
        c.send_json({{"id", id}, {"method", "mining.suggest_difficulty"}, {"params", json::array({wire})}});
        return c.wait_response(id).has_value();
    };
    {
        ServerHarness h;
        ASSERT_TRUE(h.start());
        Client c;
        ASSERT_TRUE(c.connect(h.port));
        ASSERT_TRUE(login(c, "vardiffprecworker+1", "d=8192"));   // LTC: +1 internal = 65536 wire
        EXPECT_DOUBLE_EQ(c.diff_at_notify.back(), 65536.0) << "+N must win over d=N";
        ASSERT_TRUE(suggest(c, 16384.0, 50));
        EXPECT_DOUBLE_EQ(c.set_diffs.back(), 65536.0) << "+N must win over suggest_difficulty";
    }
    {
        ServerHarness h;
        ASSERT_TRUE(h.start());
        Client c;
        ASSERT_TRUE(c.connect(h.port));
        ASSERT_TRUE(login(c, "vardiffprecworker", "d=8192"));
        EXPECT_DOUBLE_EQ(c.diff_at_notify.back(), 8192.0);
        ASSERT_TRUE(suggest(c, 16384.0, 50));
        EXPECT_DOUBLE_EQ(c.set_diffs.back(), 16384.0) << "a later suggest_difficulty is honoured";
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
