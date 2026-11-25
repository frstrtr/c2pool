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

#include <boost/asio/append.hpp>
#include <boost/asio/ip/address.hpp>
#include <boost/asio/post.hpp>

#include <core/log.hpp>

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
    StratumTlsContext() : ssl(net::ssl::context::tls_server) {}
    net::ssl::context ssl;
    std::string description;
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
    if (X509_cmp_current_time(X509_get0_notAfter(x)) <= 0)
        out += " (EXPIRED)";
    else if (X509_cmp_current_time(X509_get0_notBefore(x)) > 0)
        out += " (NOT YET VALID)";
    return out;
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
    return c;
}

std::string describe_stratum_tls_context(const StratumTlsContext& ctx) { return ctx.description; }

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

std::optional<std::string> check_stratum_tls_settings(const StratumTlsSettings& s, bool supported)
{
    if (!s.any_set())
        return std::nullopt;
    if (!supported)
        return std::string("--stratum-tls, --stratum-tls-cert and --stratum-tls-key are refused: "
                           "this build has no TLS support (built without OpenSSL: CMake option "
                           "C2POOL_STRATUM_TLS=OFF)");
    if (s.bind.empty())
        return std::string("--stratum-tls-cert / --stratum-tls-key given without --stratum-tls [HOST:]PORT");
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
    if (reload_locked(now, error))
        LOG_INFO << "stratum TLS: " << cert_ << " / " << key_ << " changed: reloaded ("
                 << describe_stratum_tls_context(*ctx_) << "); new connections use it";
    else
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
