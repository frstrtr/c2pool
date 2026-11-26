// SPDX-License-Identifier: AGPL-3.0-or-later
//
// The TLS stratum listener's OpenSSL side (core/stratum_tls.hpp): the server
// context, the certificate store and the TLS half of StratumStream. Built
// without OpenSSL (C2POOL_STRATUM_TLS undefined) the same symbols exist and
// refuse: no context loads, so no connection is ever TLS.
#include "stratum_tls.hpp"

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <system_error>

#include <algorithm>
#include <charconv>
#include <cstdlib>
#include <utility>

#include <boost/asio/append.hpp>
#include <boost/asio/ip/address.hpp>
#include <boost/asio/post.hpp>

#include <core/log.hpp>
#include <core/settings_file.hpp>

#ifdef C2POOL_STRATUM_TLS
#include <boost/asio/ssl.hpp>
#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/opensslv.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#endif

namespace core {

namespace net = boost::asio;

#ifdef C2POOL_STRATUM_TLS

class StratumTlsContext {
public:
    // Protocols below TLS 1.2 are switched off here as asio options and again
    // by SSL_CTX_set_min_proto_version(TLS1_2_VERSION) in the loader.
    StratumTlsContext() : ssl(net::ssl::context::tls_server)
    {
        ssl.set_options(net::ssl::context::default_workarounds
                        | net::ssl::context::no_sslv2
                        | net::ssl::context::no_sslv3
                        | net::ssl::context::no_tlsv1
                        | net::ssl::context::no_tlsv1_1
                        | net::ssl::context::single_dh_use);
    }
    net::ssl::context ssl;
    std::string description;
    std::optional<std::string> validity_problem;   // "expired" / "not yet valid"
};

struct StratumStream::Tls {
    Tls(tcp::socket& socket, std::shared_ptr<StratumTlsContext> c)
        : ctx(std::move(c)), stream(socket, ctx->ssl) {}
    std::shared_ptr<StratumTlsContext> ctx;     // outlives the stream
    net::ssl::stream<tcp::socket&> stream;
};

namespace {

// Every error OpenSSL queued, oldest first ("" when none). `mismatch`: one
// of them says the key is not the certificate's.
std::string take_openssl_errors(bool* mismatch = nullptr)
{
    std::string out;
    while (const unsigned long e = ERR_get_error()) {
        if (mismatch && ERR_GET_LIB(e) == ERR_LIB_X509
            && (ERR_GET_REASON(e) == X509_R_KEY_VALUES_MISMATCH
                || ERR_GET_REASON(e) == X509_R_KEY_TYPE_MISMATCH))
            *mismatch = true;
        char buf[256];
        ERR_error_string_n(e, buf, sizeof(buf));
        if (!out.empty()) out += "; ";
        out += buf;
    }
    return out;
}

// An encrypted key is refused, never prompted for on the terminal.
int no_passphrase(char*, int, int, void*) { return 0; }

// TLS 1.2 suites: ECDHE key exchange and AEAD ciphers only. TLS 1.3 suites
// are OpenSSL's defaults (all AEAD, all forward-secret).
constexpr const char* kTls12Ciphers =
    "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:"
    "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:"
    "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305";

std::string describe_certificate(SSL_CTX* h)
{
    X509* x = SSL_CTX_get0_certificate(h);
    if (!x) return "no certificate";
    std::string out;
    char name[512];
    if (X509_NAME_oneline(X509_get_subject_name(x), name, sizeof(name)))
        out = std::string("subject ") + name;
    if (BIO* bio = BIO_new(BIO_s_mem())) {
        if (ASN1_TIME_print(bio, X509_get0_notAfter(x)) == 1) {
            char* data = nullptr;
            const long n = BIO_get_mem_data(bio, &data);
            if (n > 0 && data)
                out += ", valid until " + std::string(data, static_cast<std::size_t>(n));
        }
        BIO_free(bio);
    }
    return out;
}

std::optional<std::string> certificate_validity_problem(SSL_CTX* h)
{
    X509* x = SSL_CTX_get0_certificate(h);
    if (!x) return std::nullopt;
    if (X509_cmp_current_time(X509_get0_notAfter(x)) <= 0)
        return std::string("expired");
    if (X509_cmp_current_time(X509_get0_notBefore(x)) > 0)
        return std::string("not yet valid");
    return std::nullopt;
}

}  // namespace

bool stratum_tls_supported() { return true; }

std::string stratum_tls_library_version() { return OpenSSL_version(OPENSSL_VERSION); }

std::shared_ptr<StratumTlsContext> load_stratum_tls_context(const std::string& cert,
                                                            const std::string& key,
                                                            std::string& error)
{
    // A missing or unreadable file is named as such, before OpenSSL's codes.
    for (const auto* f : {&cert, &key}) {
        std::FILE* fp = std::fopen(f->c_str(), "rb");
        if (!fp) {
            error = "cannot read " + *f + ": " + std::strerror(errno);
            return nullptr;
        }
        std::fclose(fp);
    }
    std::shared_ptr<StratumTlsContext> c;
    try {
        c = std::make_shared<StratumTlsContext>();
    } catch (const std::exception& e) {
        error = std::string("cannot create a TLS context: ") + e.what();
        return nullptr;
    }
    SSL_CTX* h = c->ssl.native_handle();
    ERR_clear_error();
    if (SSL_CTX_set_min_proto_version(h, TLS1_2_VERSION) != 1) {
        error = "cannot set the TLS 1.2 minimum: " + take_openssl_errors();
        return nullptr;
    }
    uint64_t opts = SSL_OP_NO_COMPRESSION | SSL_OP_CIPHER_SERVER_PREFERENCE | SSL_OP_NO_TICKET;
#ifdef SSL_OP_NO_RENEGOTIATION
    opts |= SSL_OP_NO_RENEGOTIATION;
#endif
    SSL_CTX_set_options(h, opts);
    SSL_CTX_set_session_cache_mode(h, SSL_SESS_CACHE_OFF);
    // Idle connections (a rig between shares) hold no read/write buffers.
    SSL_CTX_set_mode(h, SSL_MODE_RELEASE_BUFFERS);
#if OPENSSL_VERSION_NUMBER >= 0x10101000L
    SSL_CTX_set_num_tickets(h, 0);
#endif
    if (SSL_CTX_set_cipher_list(h, kTls12Ciphers) != 1) {
        error = "cannot set the TLS 1.2 cipher list: " + take_openssl_errors();
        return nullptr;
    }
    SSL_CTX_set_verify(h, SSL_VERIFY_NONE, nullptr);   // no client certificates
    SSL_CTX_set_default_passwd_cb(h, &no_passphrase);
    if (SSL_CTX_use_certificate_chain_file(h, cert.c_str()) != 1) {
        error = "cannot load the certificate chain " + cert + " (PEM): " + take_openssl_errors();
        return nullptr;
    }
    if (SSL_CTX_use_PrivateKey_file(h, key.c_str(), SSL_FILETYPE_PEM) != 1) {
        bool mismatch = false;
        const std::string why = take_openssl_errors(&mismatch);
        error = mismatch
            ? "the private key " + key + " does not match the certificate " + cert + ": " + why
            : "cannot load the private key " + key + " (PEM, not passphrase-protected): " + why;
        return nullptr;
    }
    if (SSL_CTX_check_private_key(h) != 1) {
        error = "the private key " + key + " does not match the certificate " + cert + ": "
              + take_openssl_errors();
        return nullptr;
    }
    c->description = describe_certificate(h);
    c->validity_problem = certificate_validity_problem(h);
    if (c->validity_problem)
        c->description += " (" + *c->validity_problem + ")";
    return c;
}

std::string describe_stratum_tls_context(const StratumTlsContext& ctx) { return ctx.description; }

std::optional<std::string> stratum_tls_validity_problem(const StratumTlsContext& ctx)
{
    return ctx.validity_problem;
}

void* stratum_tls_native_context(StratumTlsContext& ctx) { return ctx.ssl.native_handle(); }

StratumStream::StratumStream(tcp::socket socket, std::shared_ptr<StratumTlsContext> tls)
    : socket_(std::move(socket))
{
    if (tls)
        tls_ = std::make_unique<Tls>(socket_, std::move(tls));
}

void StratumStream::async_handshake(HandshakeHandler handler)
{
    if (tls_) {
        tls_->stream.async_handshake(net::ssl::stream_base::server, std::move(handler));
        return;
    }
    net::post(socket_.get_executor(), net::append(std::move(handler), boost::system::error_code{}));
}

void StratumStream::tls_read_some(net::mutable_buffer buffer, IoHandler handler)
{
    tls_->stream.async_read_some(buffer, std::move(handler));
}

void StratumStream::tls_write_some(net::const_buffer buffer, IoHandler handler)
{
    tls_->stream.async_write_some(buffer, std::move(handler));
}

#else  // !C2POOL_STRATUM_TLS

class StratumTlsContext {};
struct StratumStream::Tls {};

bool stratum_tls_supported() { return false; }

std::string stratum_tls_library_version() { return {}; }

std::shared_ptr<StratumTlsContext> load_stratum_tls_context(const std::string&, const std::string&,
                                                            std::string& error)
{
    error = "this build has no TLS support (built without OpenSSL: CMake option C2POOL_STRATUM_TLS=OFF)";
    return nullptr;
}

std::string describe_stratum_tls_context(const StratumTlsContext&) { return {}; }

std::optional<std::string> stratum_tls_validity_problem(const StratumTlsContext&) { return std::nullopt; }

void* stratum_tls_native_context(StratumTlsContext&) { return nullptr; }

StratumStream::StratumStream(tcp::socket socket, std::shared_ptr<StratumTlsContext>)
    : socket_(std::move(socket))
{
}

void StratumStream::async_handshake(HandshakeHandler handler)
{
    net::post(socket_.get_executor(), net::append(std::move(handler), boost::system::error_code{}));
}

void StratumStream::tls_read_some(net::mutable_buffer, IoHandler handler)
{
    net::post(socket_.get_executor(),
              net::append(std::move(handler), make_error_code(net::error::operation_not_supported),
                          std::size_t{0}));
}

void StratumStream::tls_write_some(net::const_buffer, IoHandler handler)
{
    net::post(socket_.get_executor(),
              net::append(std::move(handler), make_error_code(net::error::operation_not_supported),
                          std::size_t{0}));
}

#endif  // C2POOL_STRATUM_TLS

StratumStream::~StratumStream() = default;

std::optional<std::string> stratum_tls_key_permissions_problem(const std::string& key)
{
#ifdef _WIN32
    (void)key;
    return std::nullopt;
#else
    // Group read is fine (Debian's root:ssl-cert 0640 layout); others reading
    // it, or anyone but the owner writing it, is not.
    namespace fs = std::filesystem;
    std::error_code ec;
    const auto perms = fs::status(key, ec).permissions();
    if (ec || perms == fs::perms::unknown)
        return std::nullopt;
    const bool other_read = (perms & fs::perms::others_read) != fs::perms::none;
    const bool group_write = (perms & fs::perms::group_write) != fs::perms::none;
    const bool other_write = (perms & fs::perms::others_write) != fs::perms::none;
    if (!other_read && !group_write && !other_write)
        return std::nullopt;
    std::string what, fix;
    if (other_read) { what = "readable by others"; fix = "o-r"; }
    if (group_write || other_write) {
        what += what.empty() ? "" : " and ";
        what += group_write && other_write ? "writable by its group and others"
              : group_write ? "writable by its group" : "writable by others";
        fix += fix.empty() ? "" : ",";
        fix += group_write && other_write ? "go-w" : group_write ? "g-w" : "o-w";
    }
    char mode[8];
    std::snprintf(mode, sizeof(mode), "%03o", static_cast<unsigned>(perms) & 0777u);
    return "the private key " + key + " is " + what + " (mode " + mode + "); chmod " + fix + " " + key;
#endif
}

bool parse_stratum_tls_limit_flag(std::string_view flag, std::string_view value, StratumTlsSettings& s,
                                  std::string& error)
{
    const std::string f(flag);
    if (f == "--stratum-tls-rate-per-ip") {
        // A plain decimal: digits and at most one point (no sign, exponent,
        // inf or nan).
        const bool ok_chars = !value.empty() && value.find_first_not_of("0123456789.") == std::string_view::npos
                              && std::count(value.begin(), value.end(), '.') <= 1 && value != ".";
        if (ok_chars) {
            const std::string v(value);
            char* end = nullptr;
            const double r = std::strtod(v.c_str(), &end);
            if (end == v.c_str() + v.size() && r >= 0 && r <= 1e6) {
                s.rate_per_ip = r;
                s.limits_set = true;
                return true;
            }
        }
        error = "bad value: " + f + " " + std::string(value) + " (expected accepts a second, a number >= 0; 0 = no limit)";
        return false;
    }
    std::size_t* out = f == "--stratum-tls-burst-per-ip"         ? &s.burst_per_ip
                     : f == "--stratum-tls-handshakes"          ? &s.max_handshakes
                     : f == "--stratum-tls-handshakes-per-ip"   ? &s.max_handshakes_per_ip
                                                                : nullptr;
    if (!out) {
        error = "not a TLS stratum limit flag: " + f;
        return false;
    }
    std::size_t n = 0;
    const auto r = std::from_chars(value.data(), value.data() + value.size(), n);
    if (value.empty() || r.ec != std::errc{} || r.ptr != value.data() + value.size() || n > 1000000) {
        error = "bad value: " + f + " " + std::string(value) + " (expected a count; 0 = no limit)";
        return false;
    }
    *out = n;
    s.limits_set = true;
    return true;
}

void apply_stratum_tls_file_settings(const c2pool::settings::ResolvedConfig& rc, StratumTlsSettings& s)
{
    if (rc.file_set("stratum.tls_bind"))
        s.bind = rc.get_string("stratum.tls_bind").value_or("");
    if (rc.file_set("stratum.tls_cert"))
        s.cert = rc.get_string("stratum.tls_cert").value_or("");
    if (rc.file_set("stratum.tls_key"))
        s.key = rc.get_string("stratum.tls_key").value_or("");
    // The limits: the same values as on the command line; a bad one is
    // refused with a warning and leaves the setting as it was.
    for (const auto& [canon, flag] : {std::pair<const char*, const char*>{"stratum.tls_rate_per_ip", "--stratum-tls-rate-per-ip"},
                                      {"stratum.tls_burst_per_ip", "--stratum-tls-burst-per-ip"},
                                      {"stratum.tls_handshakes", "--stratum-tls-handshakes"},
                                      {"stratum.tls_handshakes_per_ip", "--stratum-tls-handshakes-per-ip"}}) {
        if (!rc.file_set(canon))
            continue;
        std::string error;
        const std::string v = rc.get_string(canon).value_or("");
        if (!parse_stratum_tls_limit_flag(flag, v, s, error))
            LOG_WARNING << "settings: " << canon << " = '" << v << "' ignored: " << error;
    }
}

std::optional<std::string> check_stratum_tls_settings(const StratumTlsSettings& s, bool supported)
{
    if (!s.any_set())
        return std::nullopt;
    if (!supported)
        return std::string("--stratum-tls, --stratum-tls-cert and --stratum-tls-key are refused: "
                           "this build has no TLS support (built without OpenSSL: CMake option "
                           "C2POOL_STRATUM_TLS=OFF)");
    if (s.bind.empty())
        return std::string("--stratum-tls-cert / --stratum-tls-key / --stratum-tls-* limits given without "
                           "--stratum-tls [HOST:]PORT");
    std::string host;
    uint16_t port = 0;
    if (!parse_stratum_tls_bind(s.bind, host, port))
        return "--stratum-tls " + s.bind + " is not [HOST:]PORT (PORT 1-65535)";
    if (!host.empty()) {
        boost::system::error_code ec;
        net::ip::make_address(host, ec);
        if (ec)
            return "--stratum-tls " + s.bind + ": HOST must be an IP address";
    }
    if (s.cert.empty() || s.key.empty())
        return std::string("--stratum-tls needs --stratum-tls-cert FILE (PEM, the full chain) and "
                           "--stratum-tls-key FILE (PEM)");
    std::string error;
    if (!load_stratum_tls_context(s.cert, s.key, error))
        return "--stratum-tls: " + error;
    return std::nullopt;
}

// ── StratumTlsCertStore ─────────────────────────────────────────────────────

StratumTlsCertStore::StratumTlsCertStore(std::string cert, std::string key)
    : cert_(std::move(cert)), key_(std::move(key))
{
}

StratumTlsCertStore::Stamp StratumTlsCertStore::stamp() const
{
    namespace fs = std::filesystem;
    Stamp s;
    std::error_code e1, e2, e3, e4;
    const auto cm = fs::last_write_time(cert_, e1);
    const auto km = fs::last_write_time(key_, e2);
    const auto cs = fs::file_size(cert_, e3);
    const auto ks = fs::file_size(key_, e4);
    if (e1 || e2 || e3 || e4)
        return s;   // ok = false: a file is missing or unreadable right now
    s.ok = true;
    s.cert_mtime = static_cast<int64_t>(cm.time_since_epoch().count());
    s.key_mtime = static_cast<int64_t>(km.time_since_epoch().count());
    s.cert_size = static_cast<uint64_t>(cs);
    s.key_size = static_cast<uint64_t>(ks);
    return s;
}

bool StratumTlsCertStore::reload_locked(const Stamp& now, std::string& error)
{
    last_ = now;
    auto ctx = load_stratum_tls_context(cert_, key_, error);
    if (!ctx) {
        ++failures_;
        return false;
    }
    ctx_ = std::move(ctx);
    ++loads_;
    return true;
}

bool StratumTlsCertStore::reload(std::string& error)
{
    std::lock_guard<std::mutex> lk(mutex_);
    return reload_locked(stamp(), error);
}

std::shared_ptr<StratumTlsContext> StratumTlsCertStore::current()
{
    std::lock_guard<std::mutex> lk(mutex_);
    if (!ctx_)
        return nullptr;
    const Stamp now = stamp();
    if (now == last_)
        return ctx_;
    std::string error;
    if (reload_locked(now, error)) {
        LOG_INFO << "stratum TLS: " << cert_ << " / " << key_ << " changed: reloaded ("
                 << describe_stratum_tls_context(*ctx_) << "); new connections use it";
        if (auto problem = stratum_tls_validity_problem(*ctx_))
            LOG_WARNING << "stratum TLS: the certificate " << cert_ << " is " << *problem
                        << "; miners that verify it will refuse it";
    } else
        LOG_WARNING << "stratum TLS: " << cert_ << " / " << key_ << " changed but did not load ("
                    << error << "); new connections keep the certificate loaded before";
    return ctx_;
}

uint64_t StratumTlsCertStore::reloads() const
{
    std::lock_guard<std::mutex> lk(mutex_);
    return loads_ > 0 ? loads_ - 1 : 0;
}

uint64_t StratumTlsCertStore::reload_failures() const
{
    std::lock_guard<std::mutex> lk(mutex_);
    return failures_;
}

} // namespace core
