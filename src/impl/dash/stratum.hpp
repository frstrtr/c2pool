#pragma once

// Minimal Stratum v1 server for c2pool-dash.
//
// Scope (M6 Phase 3): protocol plumbing only.
//   - Accept TCP connections on configured port
//   - Dispatch mining.subscribe, mining.authorize, mining.submit
//   - Emit mining.set_difficulty + mining.notify on demand
//
// Scope explicitly NOT covered here (M6 Phase 4):
//   - Building coinb1/coinb2 from a DashWorkData (DIP3/DIP4 CBTX + packed_payments)
//   - X11 PoW validation on submit
//   - Share acceptance into the sharechain
//
// Per project feedback rule "no_waste_hashrate" we do NOT push stub work. The
// server accepts a connection and answers subscribe/authorize, but does not
// emit mining.notify until the caller has a real Job to push via notify_all().
//
// Reference for field layout: p2pool-dash/p2pool/dash/stratum.py::rpc_notify()

#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <random>
#include <set>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include <boost/asio.hpp>
#include <nlohmann/json.hpp>

#include <core/log.hpp>

namespace dash {
namespace stratum {

namespace io = boost::asio;
using tcp   = io::ip::tcp;

// A single mining.notify job, already hex-encoded in the wire format that
// Stratum v1 expects.
//
//   prevhash   — byte-reversed 64-hex
//   version    — byte-reversed 8-hex
//   nbits      — byte-reversed 8-hex
//   ntime      — byte-reversed 8-hex
//   merkle     — array of 64-hex hashes (not byte-reversed)
struct Job {
    std::string job_id;
    std::string prevhash_hex;
    std::string coinb1_hex;
    std::string coinb2_hex;
    std::vector<std::string> merkle_branches_hex;
    std::string version_hex;
    std::string nbits_hex;
    std::string ntime_hex;
    bool        clean_jobs{true};
    // Target the miner must beat (bdiff share difficulty used for set_difficulty).
    double      share_difficulty{1.0};
};

struct SubmittedShare {
    std::string worker_name;
    std::string job_id;
    std::string extranonce2_hex;
    std::string ntime_hex;
    std::string nonce_hex;
};

// Frozen snapshot of a job that the validator needs on submit. Kept by the
// Server keyed by job_id so submit can reconstruct the exact block header.
// We deliberately avoid coin-specific types here — the raw bytes / uint256s
// are enough for the validator to run.
struct JobContext {
    std::string job_id;
    std::vector<unsigned char> coinb1_bytes;     // tx bytes before the 8-byte en2 slot
    std::vector<unsigned char> coinb2_bytes;     // tx bytes after the en2 slot
    std::vector<std::vector<unsigned char>> merkle_branches_le;  // 32B LE each
    std::vector<unsigned char> prev_hash_le;     // 32B LE (block prev)
    int32_t  version{0};
    uint32_t nbits{0};
    uint32_t ntime{0};
    uint32_t height{0};
    double   share_difficulty{1.0};
    // Raw tx "data" hex for every non-coinbase tx in the GBT. Needed to
    // assemble the full block hex when a share turns out to be a full block.
    std::vector<std::string> tx_data_hex;
};

// Callback invoked when a miner submits a share. The JobContext pointer may
// be null if the job has expired (stale submit). Returns true to accept.
using SubmitHandler = std::function<bool(const SubmittedShare&,
                                         const JobContext*,
                                         std::string& reject_reason)>;

class Server;

class Session : public std::enable_shared_from_this<Session>
{
public:
    Session(tcp::socket socket, Server* server, uint32_t extranonce1)
        : m_socket(std::move(socket))
        , m_server(server)
        , m_extranonce1(extranonce1)
    {}

    void start()
    {
        m_peer = [&]{
            boost::system::error_code ec;
            auto ep = m_socket.remote_endpoint(ec);
            return ec ? std::string{"?"} : (ep.address().to_string() + ":" + std::to_string(ep.port()));
        }();
        LOG_INFO << "[DashStratum] " << m_peer << " connected (extranonce1="
                 << std::hex << m_extranonce1 << std::dec << ")";
        read_next();
    }

    void close()
    {
        if (m_closed.exchange(true)) return;
        boost::system::error_code ec;
        m_socket.shutdown(tcp::socket::shutdown_both, ec);
        m_socket.close(ec);
        LOG_INFO << "[DashStratum] " << m_peer << " disconnected";
    }

    bool is_closed() const { return m_closed.load(); }
    bool is_subscribed() const { return m_subscribed; }
    bool is_authorized() const { return m_authorized; }
    uint32_t extranonce1() const { return m_extranonce1; }
    const std::string& worker_name() const { return m_worker; }
    const std::string& peer() const { return m_peer; }

    // Push mining.set_difficulty — miners update their scan target.
    void send_set_difficulty(double difficulty)
    {
        nlohmann::json msg = {
            {"id", nullptr},
            {"method", "mining.set_difficulty"},
            {"params", nlohmann::json::array({difficulty})}
        };
        m_current_difficulty = difficulty;
        send_json(msg);
    }

    // Push mining.notify — miners switch to this job.
    void send_notify(const Job& job)
    {
        nlohmann::json msg = {
            {"id", nullptr},
            {"method", "mining.notify"},
            {"params", nlohmann::json::array({
                job.job_id,
                job.prevhash_hex,
                job.coinb1_hex,
                job.coinb2_hex,
                job.merkle_branches_hex,
                job.version_hex,
                job.nbits_hex,
                job.ntime_hex,
                job.clean_jobs
            })}
        };
        send_json(msg);
    }

private:
    void read_next()
    {
        if (m_closed.load()) return;
        auto self = shared_from_this();
        io::async_read_until(m_socket, io::dynamic_buffer(m_read_buf), '\n',
            [self](boost::system::error_code ec, std::size_t n) {
                if (ec) { self->close(); return; }
                std::string line = self->m_read_buf.substr(0, n);
                self->m_read_buf.erase(0, n);
                while (!line.empty() && (line.back() == '\n' || line.back() == '\r'))
                    line.pop_back();
                if (!line.empty())
                    self->handle_line(line);
                self->read_next();
            });
    }

    void handle_line(const std::string& line)
    {
        nlohmann::json j;
        try { j = nlohmann::json::parse(line); }
        catch (const std::exception& e) {
            LOG_WARNING << "[DashStratum] " << m_peer << " bad JSON: " << e.what();
            return;
        }

        auto id     = j.contains("id")     ? j["id"]     : nlohmann::json(nullptr);
        auto method = j.value("method", std::string{});
        auto params = j.contains("params") ? j["params"] : nlohmann::json::array();

        if      (method == "mining.subscribe")        handle_subscribe(id, params);
        else if (method == "mining.authorize")        handle_authorize(id, params);
        else if (method == "mining.submit")           handle_submit(id, params);
        else if (method == "mining.suggest_difficulty") handle_suggest_difficulty(id, params);
        else if (method == "mining.extranonce.subscribe") respond_ok(id);
        else {
            LOG_DEBUG_OTHER << "[DashStratum] " << m_peer << " unhandled method: " << method;
            respond_error(id, -3, "method not supported");
        }
    }

    void handle_subscribe(const nlohmann::json& id, const nlohmann::json& /*params*/)
    {
        m_subscribed = true;
        // We reserve EXTRANONCE2_SIZE (8) bytes of placeholder in the coinbase
        // scriptSig. Since coinbase has no separate extranonce1 slot, advertise
        // extranonce1="" so the miner inserts only its 8-byte extranonce2.
        // Per-session identification uses a hex subscription id derived from
        // m_extranonce1.
        char sid[9];
        std::snprintf(sid, sizeof(sid), "%08x", m_extranonce1);
        nlohmann::json result = nlohmann::json::array({
            nlohmann::json::array({
                nlohmann::json::array({"mining.set_difficulty", std::string(sid)}),
                nlohmann::json::array({"mining.notify",         std::string(sid)})
            }),
            std::string(""),                                     // extranonce1 (empty)
            static_cast<int>(EXTRANONCE2_SIZE)                   // extranonce2 size
        });
        respond_result(id, result);
        LOG_INFO << "[DashStratum] " << m_peer << " subscribed sid=" << sid
                 << " extranonce2_size=" << EXTRANONCE2_SIZE;
    }

    void handle_authorize(const nlohmann::json& id, const nlohmann::json& params)
    {
        // params: [username, password]
        if (params.is_array() && params.size() >= 1 && params[0].is_string())
            m_worker = params[0].get<std::string>();
        m_authorized = true;
        respond_result(id, true);
        LOG_INFO << "[DashStratum] " << m_peer << " authorized worker=" << m_worker;
    }

    void handle_submit(const nlohmann::json& id, const nlohmann::json& params);

    void handle_suggest_difficulty(const nlohmann::json& id, const nlohmann::json& params)
    {
        if (params.is_array() && params.size() >= 1 && params[0].is_number())
            m_suggested_difficulty = params[0].get<double>();
        respond_result(id, true);
    }

    void send_json(const nlohmann::json& j)
    {
        if (m_closed.load()) return;
        std::string line = j.dump() + "\n";
        auto self = shared_from_this();
        std::lock_guard<std::mutex> lock(m_write_mtx);
        bool write_in_progress = !m_write_queue.empty();
        m_write_queue.push_back(std::move(line));
        if (!write_in_progress)
            do_write();
    }

    void do_write()
    {
        // Called with m_write_mtx held for the initial schedule; each
        // continuation reacquires it.
        auto self = shared_from_this();
        io::async_write(m_socket, io::buffer(m_write_queue.front()),
            [self](boost::system::error_code ec, std::size_t /*n*/) {
                if (ec) { self->close(); return; }
                std::lock_guard<std::mutex> lock(self->m_write_mtx);
                self->m_write_queue.pop_front();
                if (!self->m_write_queue.empty())
                    self->do_write();
            });
    }

    void respond_result(const nlohmann::json& id, const nlohmann::json& result)
    {
        send_json({{"id", id}, {"result", result}, {"error", nullptr}});
    }
    void respond_ok(const nlohmann::json& id) { respond_result(id, true); }
    void respond_error(const nlohmann::json& id, int code, const std::string& msg)
    {
        send_json({{"id", id}, {"result", nullptr},
                   {"error", nlohmann::json::array({code, msg, nullptr})}});
    }

    static constexpr std::size_t EXTRANONCE2_SIZE = 8;

    tcp::socket m_socket;
    Server*     m_server;
    uint32_t    m_extranonce1;

    std::string m_read_buf;
    std::deque<std::string> m_write_queue;
    std::mutex  m_write_mtx;

    std::atomic<bool> m_closed{false};
    bool m_subscribed = false;
    bool m_authorized = false;
    std::string m_worker;
    std::string m_peer;

    double m_current_difficulty   = 0.0;
    double m_suggested_difficulty = 0.0;
};

class Server
{
public:
    Server(io::io_context& ioc, uint16_t port)
        : m_ioc(ioc)
        , m_acceptor(ioc, tcp::endpoint(tcp::v4(), port))
        , m_port(port)
        , m_rng(std::random_device{}())
    {}

    void start()
    {
        LOG_INFO << "[DashStratum] listening on 0.0.0.0:" << m_port;
        accept_next();
    }

    void stop()
    {
        boost::system::error_code ec;
        m_acceptor.close(ec);
        std::lock_guard<std::mutex> lock(m_sessions_mtx);
        for (auto& s : m_sessions) s->close();
        m_sessions.clear();
    }

    // Broadcast a job to every subscribed+authorized session.
    void notify_all(const Job& job, const JobContext& ctx)
    {
        {   // Record the job's frozen context for the submit validator.
            std::lock_guard<std::mutex> lock(m_jobs_mtx);
            m_job_contexts[job.job_id] = ctx;
            m_job_order.push_back(job.job_id);
            while (m_job_order.size() > MAX_JOB_HISTORY) {
                m_job_contexts.erase(m_job_order.front());
                m_job_order.pop_front();
            }
        }

        std::vector<std::shared_ptr<Session>> snapshot;
        {
            std::lock_guard<std::mutex> lock(m_sessions_mtx);
            snapshot.reserve(m_sessions.size());
            for (auto& s : m_sessions)
                if (s->is_subscribed() && s->is_authorized() && !s->is_closed())
                    snapshot.push_back(s);
        }
        for (auto& s : snapshot)
            s->send_notify(job);
        m_current_job = job;
        m_has_job = true;
    }

    // Backward-compat: a notify_all without a context does nothing to the
    // validator state (used in tests that don't need submit validation).
    void notify_all(const Job& job)
    {
        notify_all(job, JobContext{});
    }

    // Look up a frozen job by id. Returns nullptr when the id is unknown
    // (either stale beyond MAX_JOB_HISTORY or never issued).
    const JobContext* get_job(const std::string& job_id) const
    {
        std::lock_guard<std::mutex> lock(m_jobs_mtx);
        auto it = m_job_contexts.find(job_id);
        return it == m_job_contexts.end() ? nullptr : &it->second;
    }

    void set_difficulty_all(double difficulty)
    {
        std::vector<std::shared_ptr<Session>> snapshot;
        {
            std::lock_guard<std::mutex> lock(m_sessions_mtx);
            snapshot.reserve(m_sessions.size());
            for (auto& s : m_sessions)
                if (s->is_subscribed() && !s->is_closed())
                    snapshot.push_back(s);
        }
        for (auto& s : snapshot)
            s->send_set_difficulty(difficulty);
    }

    void set_submit_handler(SubmitHandler h) { m_submit_handler = std::move(h); }
    SubmitHandler& submit_handler()          { return m_submit_handler; }

    size_t session_count() const
    {
        std::lock_guard<std::mutex> lock(m_sessions_mtx);
        return m_sessions.size();
    }

    // Called by Session when socket closes.
    void drop(const std::shared_ptr<Session>& s)
    {
        std::lock_guard<std::mutex> lock(m_sessions_mtx);
        m_sessions.erase(s);
    }

private:
    void accept_next()
    {
        m_acceptor.async_accept(
            [this](boost::system::error_code ec, tcp::socket socket) {
                if (!ec) {
                    uint32_t en1 = static_cast<uint32_t>(m_rng());
                    auto session = std::make_shared<Session>(std::move(socket), this, en1);
                    {
                        std::lock_guard<std::mutex> lock(m_sessions_mtx);
                        m_sessions.insert(session);
                    }
                    session->start();
                    // If we already have a live job, push it immediately.
                    // (skipped here until notify_all has been called at least once)
                } else if (ec != io::error::operation_aborted) {
                    LOG_WARNING << "[DashStratum] accept error: " << ec.message();
                }
                if (m_acceptor.is_open()) accept_next();
            });
    }

    io::io_context& m_ioc;
    tcp::acceptor   m_acceptor;
    uint16_t        m_port;
    std::mt19937    m_rng;

    mutable std::mutex m_sessions_mtx;
    std::set<std::shared_ptr<Session>> m_sessions;

    SubmitHandler m_submit_handler;

    Job  m_current_job;
    bool m_has_job = false;

    mutable std::mutex m_jobs_mtx;
    std::unordered_map<std::string, JobContext> m_job_contexts;
    std::deque<std::string> m_job_order;
    static constexpr size_t MAX_JOB_HISTORY = 16;
};

inline void Session::handle_submit(const nlohmann::json& id, const nlohmann::json& params)
{
    // params: [worker_name, job_id, extranonce2, ntime, nonce]
    if (!params.is_array() || params.size() < 5) {
        respond_error(id, -1, "bad submit params");
        return;
    }
    SubmittedShare s;
    s.worker_name     = params[0].is_string() ? params[0].get<std::string>() : "";
    s.job_id          = params[1].is_string() ? params[1].get<std::string>() : "";
    s.extranonce2_hex = params[2].is_string() ? params[2].get<std::string>() : "";
    s.ntime_hex       = params[3].is_string() ? params[3].get<std::string>() : "";
    s.nonce_hex       = params[4].is_string() ? params[4].get<std::string>() : "";

    LOG_INFO << "[DashStratum] " << m_peer
             << " submit job=" << s.job_id
             << " en2=" << s.extranonce2_hex
             << " ntime=" << s.ntime_hex
             << " nonce=" << s.nonce_hex;

    const JobContext* ctx = m_server->get_job(s.job_id);

    std::string reject_reason;
    bool accepted = true;
    auto& handler = m_server->submit_handler();
    if (handler) {
        try {
            accepted = handler(s, ctx, reject_reason);
        } catch (const std::exception& e) {
            accepted = false;
            reject_reason = e.what();
        }
    } else {
        // No validator wired — stay honest: reject rather than pretend-accept.
        accepted = false;
        reject_reason = "stratum validator not yet wired";
    }

    if (accepted) respond_result(id, true);
    else          respond_error(id, -23, reject_reason.empty() ? "rejected" : reject_reason);
}

} // namespace stratum
} // namespace dash
