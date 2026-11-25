// SPDX-License-Identifier: AGPL-3.0-or-later
//
// The TLS stratum listener (stratum+ssl://).
//
// --stratum-tls [HOST:]PORT opens a second stratum listener on the same
// StratumServer: same sessions, caps, refusal log, worker registry and
// dashboard rows as the plain listener; only the bytes on the wire are
// wrapped in TLS. PORT alone binds the plain stratum listener's host.
// --stratum-tls-cert FILE (PEM, the full chain) and --stratum-tls-key FILE
// (PEM) are required with it; without the three flags nothing changes.
//
// - TLS 1.2 and 1.3 only, forward-secret AEAD cipher suites for TLS 1.2, no
//   compression, no renegotiation, no session resumption, no client
//   certificates.
// - The certificate and key are re-read when either file changes (checked at
//   each accept: modification time and size) and on SIGHUP. New connections
//   use the new pair; open connections keep theirs. A pair that does not load
//   leaves the last good one in use.
// - A TLS handshake that does not complete within the handshake timeout
//   (10 s) closes the connection, as does a failed one (a plaintext client
//   on the TLS port); failures are counted and logged at most once a minute.
// - A handshake costs the server CPU on the stratum io thread, and a client
//   can open connections faster than the connection caps see them (each one
//   closes after its failed handshake). New TLS connections are therefore
//   limited before the handshake: a token bucket for all addresses and one
//   per address (IPv6: per /64), and a bound on handshakes in progress, in
//   total and per address. Over any of them the connection is closed at the
//   accept, counted, and logged rate-limited. The plain listener is not
//   affected.
// - HTTP on the stratum port (--stratum-http) is served on the plain listener
//   only: on a TLS connection an HTTP request line is an invalid stratum line.
//
// OpenSSL is optional at build time (CMake option C2POOL_STRATUM_TLS). Without
// it this header is unchanged, stratum_tls_supported() is false and the flags
// are refused.
#pragma once

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <iterator>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

#include <boost/asio/any_completion_handler.hpp>
#include <boost/asio/buffer.hpp>
#include <boost/asio/ip/address.hpp>
#include <boost/asio/ip/tcp.hpp>

namespace core {

/// A TLS connection whose handshake has not completed this long after the
/// accept is closed (StratumServer::TlsOptions::handshake_timeout).
inline constexpr std::chrono::milliseconds kStratumTlsHandshakeTimeout{10000};
/// ... and one that has sent nothing (no ClientHello byte) this long after
/// the accept (TlsOptions::first_byte_timeout).
inline constexpr std::chrono::milliseconds kStratumTlsFirstByteTimeout{3000};
/// With the handshakes in progress at their limit, a new connection evicts
/// the oldest one that has been in progress at least this long (it is closed
/// and counted as a failed handshake); none that old: the new one is closed
/// (TlsOptions::evict_after).
inline constexpr std::chrono::milliseconds kStratumTlsHandshakeEvictAfter{1500};

/// New TLS connections a second, from all addresses (token bucket rate), and
/// the bucket size: at most kStratumTlsAcceptBurst back to back after a quiet
/// spell. 0 = no limit.
inline constexpr double kStratumTlsAcceptRate = 200.0;
inline constexpr double kStratumTlsAcceptBurst = 400.0;
/// The same from one address (IPv4 address, IPv6 /64: per_ip_cap_key):
/// --stratum-tls-rate-per-ip / --stratum-tls-burst-per-ip. Up to the burst
/// may arrive back to back (a farm behind one NAT reconnecting); at most
/// kStratumTlsMaxHandshakesPerIp of them handshake at the same moment, the
/// others are closed and retry.
inline constexpr double kStratumTlsAcceptRatePerIp = 5.0;
inline constexpr double kStratumTlsAcceptBurstPerIp = 20.0;
/// TLS handshakes in progress at once, in total and from one address
/// (--stratum-tls-handshakes / --stratum-tls-handshakes-per-ip). Separate
/// from max_stratum_connections. 0 = no limit.
inline constexpr std::size_t kStratumTlsMaxHandshakes = 32;
inline constexpr std::size_t kStratumTlsMaxHandshakesPerIp = 8;

/// The flags as given (command line or settings file). bind empty = off.
struct StratumTlsSettings {
    std::string bind;   // --stratum-tls [HOST:]PORT
    std::string cert;   // --stratum-tls-cert FILE
    std::string key;    // --stratum-tls-key FILE
    // --stratum-tls-rate-per-ip / --stratum-tls-burst-per-ip /
    // --stratum-tls-handshakes / --stratum-tls-handshakes-per-ip.
    double rate_per_ip = kStratumTlsAcceptRatePerIp;
    std::size_t burst_per_ip = static_cast<std::size_t>(kStratumTlsAcceptBurstPerIp);
    std::size_t max_handshakes = kStratumTlsMaxHandshakes;
    std::size_t max_handshakes_per_ip = kStratumTlsMaxHandshakesPerIp;
    bool limits_set = false;   // one of those four was given

    bool enabled() const { return !bind.empty(); }
    bool any_set() const { return !bind.empty() || !cert.empty() || !key.empty() || limits_set; }
};

/// The process's TLS stratum flags: the parse writes them, the wiring
/// (configure_stratum_tls) reads them.
inline StratumTlsSettings& stratum_tls_setting()
{
    static StratumTlsSettings s;
    return s;
}

/// One of the four limit flags (--stratum-tls-rate-per-ip R: a decimal
/// number >= 0; --stratum-tls-burst-per-ip, --stratum-tls-handshakes,
/// --stratum-tls-handshakes-per-ip N: a count) with its value. true: `s`
/// holds it (and limits_set); false: `error` says why (s unchanged), also for
/// a flag that is none of the four.
bool parse_stratum_tls_limit_flag(std::string_view flag, std::string_view value, StratumTlsSettings& s,
                                  std::string& error);

}  // namespace core
namespace c2pool::settings { class ResolvedConfig; }
namespace core {

/// The settings-file keys stratum.tls_bind / tls_cert / tls_key and the four
/// limits (stratum.tls_rate_per_ip, tls_burst_per_ip, tls_handshakes,
/// tls_handshakes_per_ip): the ones set by the file (the command line wins:
/// its keys are never file-set) go into `s`; a bad limit is warned about
/// and ignored.
void apply_stratum_tls_file_settings(const c2pool::settings::ResolvedConfig& rc, StratumTlsSettings& s);

/// A token bucket: `rate` tokens a second, at most `burst` held (it starts
/// full). rate <= 0: every take() succeeds. Not thread-safe.
class StratumTlsTokenBucket {
public:
    using clock = std::chrono::steady_clock;
    StratumTlsTokenBucket(double rate, double burst, clock::time_point now)
        : rate_(rate), burst_(std::max(burst, 1.0)), tokens_(std::max(burst, 1.0)), last_(now) {}
    /// A token is there now.
    bool ready(clock::time_point now)
    {
        refill(now);
        return rate_ <= 0 || tokens_ >= 1.0;
    }
    /// Spend one token (call after ready()).
    void take()
    {
        if (rate_ > 0) tokens_ -= 1.0;
    }
    /// Refilled to the brim: nothing to remember about this bucket.
    bool full(clock::time_point now)
    {
        refill(now);
        return rate_ <= 0 || tokens_ >= burst_;
    }

private:
    void refill(clock::time_point now)
    {
        if (rate_ <= 0 || now <= last_) return;
        tokens_ = std::min(burst_, tokens_ + rate_ * std::chrono::duration<double>(now - last_).count());
        last_ = now;
    }
    double rate_, burst_, tokens_;
    clock::time_point last_;
};

/// The accept rate limit of the TLS listener: one bucket for all addresses
/// and one per key (per_ip_cap_key of the remote address). An accept takes a
/// token from both or from neither. A refused accept never adds a key, so the
/// per-key map grows at most at the global rate; keys whose bucket is full
/// again are pruned. Not thread-safe (the stratum io thread).
class StratumTlsAcceptLimiter {
public:
    using clock = std::chrono::steady_clock;
    using address = boost::asio::ip::address;
    enum class Verdict { Admit, Rate, RatePerIp };

    StratumTlsAcceptLimiter(double rate, double burst, double per_ip_rate, double per_ip_burst,
                            clock::time_point now = clock::now())
        : global_(rate, burst, now), per_ip_rate_(per_ip_rate), per_ip_burst_(per_ip_burst) {}

    /// Would an accept from `key` get a token from both buckets now? Spends
    /// nothing (take() does).
    Verdict check(const address& key, clock::time_point now)
    {
        if (!global_.ready(now))
            return Verdict::Rate;
        auto it = per_key_.find(key);
        if (it == per_key_.end()) {
            prune(now);
            it = per_key_.emplace(key, StratumTlsTokenBucket(per_ip_rate_, per_ip_burst_, now)).first;
        }
        if (!it->second.ready(now))
            return Verdict::RatePerIp;
        return Verdict::Admit;
    }
    /// Spend the tokens of an accept check() admitted.
    void take(const address& key)
    {
        global_.take();
        if (auto it = per_key_.find(key); it != per_key_.end())
            it->second.take();
    }
    /// check() and, when it admits, take().
    Verdict admit(const address& key, clock::time_point now)
    {
        const Verdict v = check(key, now);
        if (v == Verdict::Admit)
            take(key);
        return v;
    }
    std::size_t keys() const { return per_key_.size(); }

private:
    // At most once a second, and only past kPruneAt keys: drop the buckets
    // that are full again (their key has been quiet for burst/rate seconds).
    void prune(clock::time_point now)
    {
        static constexpr std::size_t kPruneAt = 1024;
        if (per_key_.size() < kPruneAt || now - last_prune_ < std::chrono::seconds(1))
            return;
        last_prune_ = now;
        for (auto it = per_key_.begin(); it != per_key_.end();)
            it = it->second.full(now) ? per_key_.erase(it) : std::next(it);
    }
    StratumTlsTokenBucket global_;
    double per_ip_rate_, per_ip_burst_;
    std::map<address, StratumTlsTokenBucket> per_key_;
    clock::time_point last_prune_{};
};

/// Handshakes in progress on the TLS listener, in total and per key. A slot
/// is held from the accept until the session's handshake ends (or the
/// session goes). At a limit, the oldest handshake in progress at least
/// `evict_after` (from the same key when that key's limit is the one hit) is
/// evicted: its slot is freed at once and its on_evict function closes it;
/// none that old, the newcomer gets no slot. The counts live in shared
/// state, so a slot may outlive the gate. Thread-safe; on_evict functions run
/// on the calling thread, outside the lock.
class StratumTlsHandshakeGate {
    struct Entry {
        boost::asio::ip::address key;
        std::chrono::steady_clock::time_point since;
        std::function<void()> evict;
    };
    struct State {
        std::mutex mutex;
        std::map<uint64_t, Entry> entries;   // acquisition order: oldest first
        std::map<boost::asio::ip::address, std::size_t> per_key;
        uint64_t next_id = 0;
        uint64_t evictions = 0;
        void erase_locked(std::map<uint64_t, Entry>::iterator it)
        {
            auto k = per_key.find(it->second.key);
            if (k != per_key.end() && --k->second == 0)
                per_key.erase(k);
            entries.erase(it);
        }
    };

public:
    using clock = std::chrono::steady_clock;
    using address = boost::asio::ip::address;

    class Slot {
    public:
        ~Slot()
        {
            std::lock_guard<std::mutex> lk(st_->mutex);
            if (auto it = st_->entries.find(id_); it != st_->entries.end())
                st_->erase_locked(it);
        }
        Slot(const Slot&) = delete;
        Slot& operator=(const Slot&) = delete;
        /// How the gate closes this handshake when it evicts it (until set,
        /// it is not evicted).
        void on_evict(std::function<void()> fn)
        {
            std::lock_guard<std::mutex> lk(st_->mutex);
            if (auto it = st_->entries.find(id_); it != st_->entries.end())
                it->second.evict = std::move(fn);
        }

    private:
        friend class StratumTlsHandshakeGate;
        Slot(std::shared_ptr<State> st, uint64_t id) : st_(std::move(st)), id_(id) {}
        std::shared_ptr<State> st_;
        uint64_t id_;
    };

    StratumTlsHandshakeGate() : state_(std::make_shared<State>()) {}

    /// A slot for one handshake from `key` (0 limits: none), evicting one as
    /// above when at a limit; nullptr when no slot can be had.
    std::shared_ptr<Slot> try_acquire(const address& key, std::size_t max_total, std::size_t max_per_key,
                                      clock::time_point now = clock::now(),
                                      clock::duration evict_after = kStratumTlsHandshakeEvictAfter)
    {
        std::function<void()> evict;
        std::shared_ptr<Slot> slot;
        {
            std::lock_guard<std::mutex> lk(state_->mutex);
            const auto k = state_->per_key.find(key);
            const std::size_t from_key = k == state_->per_key.end() ? 0 : k->second;
            const bool key_full = max_per_key > 0 && from_key >= max_per_key;
            const bool total_full = max_total > 0 && state_->entries.size() >= max_total;
            if (key_full || total_full) {
                auto victim = state_->entries.end();
                for (auto it = state_->entries.begin(); it != state_->entries.end(); ++it) {
                    if (key_full && it->second.key != key)
                        continue;
                    if (now - it->second.since < evict_after)
                        break;   // oldest first: the rest are younger
                    if (it->second.evict) {
                        victim = it;
                        break;
                    }
                }
                if (victim == state_->entries.end())
                    return nullptr;
                evict = std::move(victim->second.evict);
                state_->erase_locked(victim);
                ++state_->evictions;
            }
            const uint64_t id = state_->next_id++;
            state_->entries.emplace(id, Entry{key, now, {}});
            ++state_->per_key[key];
            slot.reset(new Slot(state_, id));
        }
        if (evict)
            evict();
        return slot;
    }
    std::size_t in_progress() const
    {
        std::lock_guard<std::mutex> lk(state_->mutex);
        return state_->entries.size();
    }
    std::size_t in_progress_from(const address& key) const
    {
        std::lock_guard<std::mutex> lk(state_->mutex);
        auto it = state_->per_key.find(key);
        return it == state_->per_key.end() ? 0 : it->second;
    }
    /// Handshakes evicted since the gate was made.
    uint64_t evictions() const
    {
        std::lock_guard<std::mutex> lk(state_->mutex);
        return state_->evictions;
    }

private:
    std::shared_ptr<State> state_;
};

/// This build has the TLS listener (OpenSSL linked, C2POOL_STRATUM_TLS).
bool stratum_tls_supported();

/// The OpenSSL version this build is linked against ("" without TLS).
std::string stratum_tls_library_version();

/// A --stratum-tls value: "PORT", "HOST:PORT" or "[IPv6]:PORT", PORT 1-65535.
/// host is left empty for "PORT" (the plain stratum listener's host). false
/// for anything else (host and port are left unchanged).
inline bool parse_stratum_tls_bind(std::string_view v, std::string& host, uint16_t& port)
{
    std::string h;
    std::string_view p = v;
    if (!v.empty() && v.front() == '[') {
        const auto close = v.find(']');
        if (close == std::string_view::npos || close + 1 >= v.size() || v[close + 1] != ':')
            return false;
        h = std::string(v.substr(1, close - 1));
        if (h.empty())
            return false;
        p = v.substr(close + 2);
    } else if (const auto colon = v.rfind(':'); colon != std::string_view::npos) {
        if (colon == 0)
            return false;
        h = std::string(v.substr(0, colon));
        p = v.substr(colon + 1);
    }
    if (p.empty() || p.size() > 5 || p.find_first_not_of("0123456789") != std::string_view::npos)
        return false;
    unsigned long n = 0;
    for (char c : p)
        n = n * 10 + static_cast<unsigned long>(c - '0');
    if (n == 0 || n > 65535)
        return false;
    host = std::move(h);
    port = static_cast<uint16_t>(n);
    return true;
}

/// Checks the flags once they are all parsed (command line and settings
/// file): nullopt when they are fine (all unset, or a complete set whose
/// certificate and key load), else why they are refused. `supported`: this
/// build has TLS (any flag is refused when it does not).
std::optional<std::string> check_stratum_tls_settings(const StratumTlsSettings& s,
                                                      bool supported = stratum_tls_supported());

/// An OpenSSL server context with one certificate chain and key (opaque here;
/// stratum_tls.cpp). Shared by the connections it was handed to.
class StratumTlsContext;

/// Load `cert` (PEM chain) and `key` (PEM) into a server context with the
/// defaults above. nullptr and `error` set when they do not load (or the
/// build has no TLS).
std::shared_ptr<StratumTlsContext> load_stratum_tls_context(const std::string& cert,
                                                            const std::string& key,
                                                            std::string& error);

/// "subject /CN=pool.example, valid until Feb  1 12:00:00 2027 GMT".
std::string describe_stratum_tls_context(const StratumTlsContext& ctx);

/// "expired" / "not yet valid" when the certificate is outside its validity
/// period now (it still loads; the caller warns); nullopt when within it.
std::optional<std::string> stratum_tls_validity_problem(const StratumTlsContext& ctx);

/// A warning text when `key` can be read by its group or by others (POSIX
/// permissions); nullopt when not, or the permissions cannot be read.
std::optional<std::string> stratum_tls_key_permissions_problem(const std::string& key);

/// Test access: the context's OpenSSL SSL_CTX* (nullptr without TLS).
void* stratum_tls_native_context(StratumTlsContext& ctx);

/// The certificate and key a TLS listener hands to new connections, re-read
/// when either file changes. Thread-safe.
class StratumTlsCertStore {
public:
    StratumTlsCertStore(std::string cert, std::string key);

    /// (Re-)read the files now. false and `error` set when they do not load;
    /// the last good context stays in use.
    bool reload(std::string& error);

    /// The context for a new connection. When either file's modification
    /// time or size differs from the last read, they are read again first
    /// (once per change: a pair that does not load is not retried until a
    /// file changes again). nullptr until a first reload() succeeded.
    std::shared_ptr<StratumTlsContext> current();

    const std::string& cert_file() const { return cert_; }
    const std::string& key_file() const { return key_; }
    /// Successful reads after the first one / reads that failed.
    uint64_t reloads() const;
    uint64_t reload_failures() const;

private:
    struct Stamp {
        bool ok = false;
        int64_t cert_mtime = 0, key_mtime = 0;
        uint64_t cert_size = 0, key_size = 0;
        bool operator==(const Stamp& o) const
        {
            return ok == o.ok && cert_mtime == o.cert_mtime && key_mtime == o.key_mtime
                && cert_size == o.cert_size && key_size == o.key_size;
        }
    };
    Stamp stamp() const;
    bool reload_locked(const Stamp& now, std::string& error);

    const std::string cert_;
    const std::string key_;
    mutable std::mutex mutex_;
    Stamp last_;                                  // as of the last read attempt
    std::shared_ptr<StratumTlsContext> ctx_;      // last good
    uint64_t loads_ = 0;
    uint64_t failures_ = 0;
};

/// One stratum connection's byte stream: the accepted TCP socket, and, on the
/// TLS listener, a TLS stream over it. Meets the asio AsyncReadStream /
/// AsyncWriteStream requirements, so the session code (async_read_until,
/// async_write) is the same for both; the plain case forwards straight to the
/// socket. Not movable (the TLS stream refers to the socket).
class StratumStream {
public:
    using tcp = boost::asio::ip::tcp;
    using executor_type = tcp::socket::executor_type;
    using lowest_layer_type = tcp::socket;
    using HandshakeHandler = boost::asio::any_completion_handler<void(boost::system::error_code)>;
    using IoHandler = boost::asio::any_completion_handler<void(boost::system::error_code, std::size_t)>;

    /// A plain connection; with `tls` (non-null), a TLS one: async_handshake()
    /// before any read or write.
    explicit StratumStream(tcp::socket socket, std::shared_ptr<StratumTlsContext> tls = nullptr);
    ~StratumStream();
    StratumStream(const StratumStream&) = delete;
    StratumStream& operator=(const StratumStream&) = delete;

    bool is_tls() const noexcept { return tls_ != nullptr; }

    executor_type get_executor() noexcept { return socket_.get_executor(); }
    tcp::socket& lowest_layer() noexcept { return socket_; }
    const tcp::socket& lowest_layer() const noexcept { return socket_; }
    bool is_open() const { return socket_.is_open(); }
    void close() { socket_.close(); }
    void close(boost::system::error_code& ec) { socket_.close(ec); }
    tcp::endpoint remote_endpoint() const { return socket_.remote_endpoint(); }
    tcp::endpoint remote_endpoint(boost::system::error_code& ec) const { return socket_.remote_endpoint(ec); }
    tcp::socket::native_handle_type native_handle() { return socket_.native_handle(); }

    /// The server side of the TLS handshake (TLS connections only).
    void async_handshake(HandshakeHandler handler);

    template <typename MutableBufferSequence, typename ReadHandler>
    void async_read_some(const MutableBufferSequence& buffers, ReadHandler&& handler)
    {
        if (!tls_) {
            socket_.async_read_some(buffers, std::forward<ReadHandler>(handler));
            return;
        }
        // A read may return fewer bytes than asked: the first non-empty buffer
        // is enough.
        boost::asio::mutable_buffer first;
        for (auto it = boost::asio::buffer_sequence_begin(buffers);
             it != boost::asio::buffer_sequence_end(buffers); ++it) {
            boost::asio::mutable_buffer b(*it);
            if (b.size() != 0) { first = b; break; }
        }
        tls_read_some(first, IoHandler(std::forward<ReadHandler>(handler)));
    }

    template <typename ConstBufferSequence, typename WriteHandler>
    void async_write_some(const ConstBufferSequence& buffers, WriteHandler&& handler)
    {
        if (!tls_) {
            socket_.async_write_some(buffers, std::forward<WriteHandler>(handler));
            return;
        }
        boost::asio::const_buffer first;
        for (auto it = boost::asio::buffer_sequence_begin(buffers);
             it != boost::asio::buffer_sequence_end(buffers); ++it) {
            boost::asio::const_buffer b(*it);
            if (b.size() != 0) { first = b; break; }
        }
        tls_write_some(first, IoHandler(std::forward<WriteHandler>(handler)));
    }

private:
    void tls_read_some(boost::asio::mutable_buffer buffer, IoHandler handler);
    void tls_write_some(boost::asio::const_buffer buffer, IoHandler handler);

    tcp::socket socket_;
    struct Tls;                  // the TLS stream over socket_ (stratum_tls.cpp)
    std::unique_ptr<Tls> tls_;   // destroyed before socket_
};

} // namespace core
