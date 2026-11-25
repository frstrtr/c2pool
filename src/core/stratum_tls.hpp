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
// - HTTP on the stratum port (--stratum-http) is served on the plain listener
//   only: on a TLS connection an HTTP request line is an invalid stratum line.
//
// OpenSSL is optional at build time (CMake option C2POOL_STRATUM_TLS). Without
// it this header is unchanged, stratum_tls_supported() is false and the flags
// are refused.
#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

#include <boost/asio/any_completion_handler.hpp>
#include <boost/asio/buffer.hpp>
#include <boost/asio/ip/tcp.hpp>

namespace core {

/// The flags as given (command line or settings file). bind empty = off.
struct StratumTlsSettings {
    std::string bind;   // --stratum-tls [HOST:]PORT
    std::string cert;   // --stratum-tls-cert FILE
    std::string key;    // --stratum-tls-key FILE

    bool enabled() const { return !bind.empty(); }
    bool any_set() const { return !bind.empty() || !cert.empty() || !key.empty(); }
};

/// The process's TLS stratum flags: the parse writes them, the wiring
/// (configure_stratum_tls) reads them.
inline StratumTlsSettings& stratum_tls_setting()
{
    static StratumTlsSettings s;
    return s;
}

/// A TLS connection whose handshake has not completed this long after the
/// accept is closed (StratumServer::TlsOptions::handshake_timeout).
inline constexpr std::chrono::milliseconds kStratumTlsHandshakeTimeout{10000};

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
