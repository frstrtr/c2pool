// SPDX-License-Identifier: AGPL-3.0-or-later
//
// The TLS stratum listener (core/stratum_tls.hpp, StratumServer::start_tls):
//
//   * --stratum-tls [HOST:]PORT parse, and the check of the three flags
//     (complete set, an IP host, a certificate and key that load), which
//     refuses every flag in a build without TLS;
//   * a real TLS handshake over loopback with a throwaway self-signed
//     certificate made here with the OpenSSL API, verified by the client;
//     mining.subscribe / mining.authorize over TLS get the replies a plain
//     connection gets from the same server, and the worker registry lists the
//     TLS session under its real remote address;
//   * TLS 1.2 and 1.3 clients connect, a client capped below TLS 1.2 does not;
//   * a plaintext client on the TLS port is closed cleanly and counted, a
//     client that never starts the handshake is closed at the handshake
//     timeout, and the listener keeps serving both ports after either;
//   * an HTTP request line over TLS is an invalid stratum line (HTTP on the
//     stratum port is the plain listener's only);
//   * the per-IP cap counts plain and TLS sessions together;
//   * certificate reload: a changed file is read at the next accept, new
//     connections get the new certificate while a connection opened before
//     keeps working; a pair that does not load leaves the last good one in
//     use; reload_tls() and SIGHUP re-read the files; a passphrase-protected
//     key is refused without a prompt.

#include <gtest/gtest.h>

#include <array>
#include <atomic>
#include <chrono>
#include <csignal>
#ifndef _WIN32
#include <signal.h>
#endif
#include <filesystem>
#include <fstream>
#include <functional>
#include <future>
#include <memory>
#include <optional>
#include <random>
#include <string>
#include <thread>
#include <cstring>
#include <utility>
#include <vector>

#include <nlohmann/json.hpp>

#include <core/stratum_server.hpp>
#include <core/stratum_tls.hpp>
#include <core/web_server.hpp>

#include "stratum_port_http_test_util.hpp"

#ifdef C2POOL_STRATUM_TLS
#include <boost/asio/ssl.hpp>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#endif

using namespace stratum_http_test;
using json = nlohmann::json;
namespace fs = std::filesystem;

namespace {

bool wait_until(const std::function<bool()>& done, std::chrono::milliseconds timeout = 5000ms)
{
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        if (done()) return true;
        std::this_thread::sleep_for(10ms);
    }
    return done();
}

// A fresh directory under the temp dir, removed with the object.
struct TempDir {
    fs::path path;
    TempDir()
    {
        std::random_device rd;
        path = fs::temp_directory_path() / ("c2pool-tls-test-" + std::to_string(rd()) + std::to_string(rd()));
        fs::create_directories(path);
    }
    ~TempDir()
    {
        std::error_code ec;
        fs::remove_all(path, ec);
    }
};

}  // namespace

// ── The flags ───────────────────────────────────────────────────────────────

TEST(StratumTlsFlags, BindParse)
{
    std::string host = "unchanged";
    uint16_t port = 1;
    ASSERT_TRUE(core::parse_stratum_tls_bind("3334", host, port));
    EXPECT_EQ(host, "");
    EXPECT_EQ(port, 3334);
    ASSERT_TRUE(core::parse_stratum_tls_bind("0.0.0.0:3335", host, port));
    EXPECT_EQ(host, "0.0.0.0");
    EXPECT_EQ(port, 3335);
    ASSERT_TRUE(core::parse_stratum_tls_bind("[::]:3336", host, port));
    EXPECT_EQ(host, "::");
    EXPECT_EQ(port, 3336);
    ASSERT_TRUE(core::parse_stratum_tls_bind("[2001:db8::1]:65535", host, port));
    EXPECT_EQ(host, "2001:db8::1");
    EXPECT_EQ(port, 65535);

    for (const char* bad : {"", "0", "65536", "99999999", "abc", "3334x", ":3334", "host:", "[::1]",
                            "[::1]3334", "[]:3334", "1.2.3.4:-1", "1.2.3.4: 80"}) {
        host = "unchanged";
        port = 7;
        EXPECT_FALSE(core::parse_stratum_tls_bind(bad, host, port)) << bad;
        EXPECT_EQ(host, "unchanged") << bad;
        EXPECT_EQ(port, 7) << bad;
    }
}

TEST(StratumTlsFlags, NothingSetIsFine)
{
    EXPECT_FALSE(core::check_stratum_tls_settings({}, true));
    EXPECT_FALSE(core::check_stratum_tls_settings({}, false));
    EXPECT_FALSE(core::check_stratum_tls_settings({}));
}

TEST(StratumTlsFlags, EveryFlagIsRefusedWithoutTlsSupport)
{
    for (const core::StratumTlsSettings& s :
         {core::StratumTlsSettings{"3334", "", ""}, core::StratumTlsSettings{"", "c.pem", ""},
          core::StratumTlsSettings{"", "", "k.pem"}, core::StratumTlsSettings{"3334", "c.pem", "k.pem"}}) {
        const auto why = core::check_stratum_tls_settings(s, /*supported=*/false);
        ASSERT_TRUE(why) << s.bind << "|" << s.cert << "|" << s.key;
        EXPECT_NE(why->find("this build has no TLS support"), std::string::npos) << *why;
    }
    if (!core::stratum_tls_supported()) {
        // This build: the real check refuses, and so does the listener.
        const auto why = core::check_stratum_tls_settings({"3334", "c.pem", "k.pem"});
        ASSERT_TRUE(why);
        EXPECT_NE(why->find("C2POOL_STRATUM_TLS=OFF"), std::string::npos) << *why;
        std::string err;
        EXPECT_FALSE(core::load_stratum_tls_context("c.pem", "k.pem", err));
        EXPECT_NE(err.find("no TLS support"), std::string::npos) << err;
    }
}

TEST(StratumTlsFlags, IncompleteOrMalformedSetsAreRefused)
{
    auto refused = [](core::StratumTlsSettings s, const std::string& needle) {
        const auto why = core::check_stratum_tls_settings(s, /*supported=*/true);
        if (!why) return ::testing::AssertionFailure() << "accepted: " << s.bind;
        if (why->find(needle) == std::string::npos)
            return ::testing::AssertionFailure() << "'" << *why << "' lacks '" << needle << "'";
        return ::testing::AssertionSuccess();
    };
    EXPECT_TRUE(refused({"3334", "", ""}, "needs --stratum-tls-cert FILE"));
    EXPECT_TRUE(refused({"3334", "c.pem", ""}, "needs --stratum-tls-cert FILE"));
    EXPECT_TRUE(refused({"3334", "", "k.pem"}, "needs --stratum-tls-cert FILE"));
    EXPECT_TRUE(refused({"", "c.pem", "k.pem"}, "without --stratum-tls [HOST:]PORT"));
    EXPECT_TRUE(refused({"", "c.pem", ""}, "without --stratum-tls [HOST:]PORT"));
    core::StratumTlsSettings limits_only;
    limits_only.limits_set = true;
    EXPECT_TRUE(refused(limits_only, "without --stratum-tls [HOST:]PORT"));
    EXPECT_TRUE(refused({"0", "c.pem", "k.pem"}, "is not [HOST:]PORT"));
    EXPECT_TRUE(refused({"70000", "c.pem", "k.pem"}, "is not [HOST:]PORT"));
    EXPECT_TRUE(refused({"pool.example:3334", "c.pem", "k.pem"}, "HOST must be an IP address"));
}

TEST(StratumTlsFlags, LimitFlags)
{
    core::StratumTlsSettings s;
    EXPECT_EQ(s.rate_per_ip, 5.0);
    EXPECT_EQ(s.burst_per_ip, 20u);
    EXPECT_EQ(s.max_handshakes, 32u);
    EXPECT_EQ(s.max_handshakes_per_ip, 8u);
    EXPECT_FALSE(s.limits_set);
    EXPECT_FALSE(s.any_set());
    std::string err;
    ASSERT_TRUE(core::parse_stratum_tls_limit_flag("--stratum-tls-rate-per-ip", "2.5", s, err)) << err;
    EXPECT_EQ(s.rate_per_ip, 2.5);
    EXPECT_TRUE(s.limits_set);
    EXPECT_TRUE(s.any_set());
    ASSERT_TRUE(core::parse_stratum_tls_limit_flag("--stratum-tls-rate-per-ip", "0", s, err));
    EXPECT_EQ(s.rate_per_ip, 0.0);
    ASSERT_TRUE(core::parse_stratum_tls_limit_flag("--stratum-tls-burst-per-ip", "64", s, err));
    EXPECT_EQ(s.burst_per_ip, 64u);
    ASSERT_TRUE(core::parse_stratum_tls_limit_flag("--stratum-tls-handshakes", "100", s, err));
    EXPECT_EQ(s.max_handshakes, 100u);
    ASSERT_TRUE(core::parse_stratum_tls_limit_flag("--stratum-tls-handshakes-per-ip", "0", s, err));
    EXPECT_EQ(s.max_handshakes_per_ip, 0u);
    const auto before = s;
    for (const auto& [flag, value] : std::vector<std::pair<std::string, std::string>>{
             {"--stratum-tls-rate-per-ip", "-1"}, {"--stratum-tls-rate-per-ip", "abc"},
             {"--stratum-tls-rate-per-ip", "1e3"}, {"--stratum-tls-rate-per-ip", "inf"},
             {"--stratum-tls-rate-per-ip", "1.2.3"}, {"--stratum-tls-rate-per-ip", ""},
             {"--stratum-tls-rate-per-ip", "."}, {"--stratum-tls-burst-per-ip", "1.5"},
             {"--stratum-tls-burst-per-ip", "-3"}, {"--stratum-tls-handshakes", "x"},
             {"--stratum-tls-handshakes-per-ip", ""}, {"--stratum-tls-handshakes", "99999999"},
             {"--stratum-tls-nope", "1"}}) {
        err.clear();
        EXPECT_FALSE(core::parse_stratum_tls_limit_flag(flag, value, s, err)) << flag << " " << value;
        EXPECT_FALSE(err.empty()) << flag << " " << value;
    }
    EXPECT_EQ(s.rate_per_ip, before.rate_per_ip);
    EXPECT_EQ(s.burst_per_ip, before.burst_per_ip);
    EXPECT_EQ(s.max_handshakes, before.max_handshakes);
    EXPECT_EQ(s.max_handshakes_per_ip, before.max_handshakes_per_ip);
}

// ── Limits before the handshake (header-only, every build) ──────────────────

TEST(StratumTlsDefaults, NamedValues)
{
    EXPECT_EQ(core::kStratumTlsHandshakeTimeout, std::chrono::milliseconds(10000));
    EXPECT_EQ(core::kStratumTlsFirstByteTimeout, std::chrono::milliseconds(3000));
    EXPECT_EQ(core::kStratumTlsHandshakeEvictAfter, std::chrono::milliseconds(1500));
    EXPECT_EQ(core::kStratumTlsAcceptRate, 200.0);
    EXPECT_EQ(core::kStratumTlsAcceptBurst, 400.0);
    EXPECT_EQ(core::kStratumTlsAcceptRatePerIp, 5.0);
    EXPECT_EQ(core::kStratumTlsAcceptBurstPerIp, 20.0);
    EXPECT_EQ(core::kStratumTlsMaxHandshakes, 32u);
    EXPECT_EQ(core::kStratumTlsMaxHandshakesPerIp, 8u);
    const core::StratumServer::TlsOptions o;
    EXPECT_EQ(o.handshake_timeout, std::chrono::milliseconds(10000));
    EXPECT_EQ(o.first_byte_timeout, std::chrono::milliseconds(3000));
    EXPECT_EQ(o.evict_after, std::chrono::milliseconds(1500));
    EXPECT_EQ(o.accept_rate, core::kStratumTlsAcceptRate);
    EXPECT_EQ(o.accept_burst, core::kStratumTlsAcceptBurst);
    EXPECT_EQ(o.accept_rate_per_ip, core::kStratumTlsAcceptRatePerIp);
    EXPECT_EQ(o.accept_burst_per_ip, core::kStratumTlsAcceptBurstPerIp);
    EXPECT_EQ(o.max_handshakes, core::kStratumTlsMaxHandshakes);
    EXPECT_EQ(o.max_handshakes_per_ip, core::kStratumTlsMaxHandshakesPerIp);
    EXPECT_TRUE(o.bind_address.empty());
    EXPECT_EQ(o.port, 0);
}

TEST(StratumTlsLimits, TokenBucketBurstThenRate)
{
    using clock = core::StratumTlsTokenBucket::clock;
    const auto t0 = clock::now();
    core::StratumTlsTokenBucket b(2.0, 4.0, t0);   // 2/s, 4 held
    for (int i = 0; i < 4; ++i) {
        ASSERT_TRUE(b.ready(t0)) << i;
        b.take();
    }
    EXPECT_FALSE(b.ready(t0));
    EXPECT_FALSE(b.ready(t0 + std::chrono::milliseconds(400)));   // 0.8 token
    EXPECT_TRUE(b.ready(t0 + std::chrono::milliseconds(500)));    // 1 token
    b.take();
    EXPECT_FALSE(b.full(t0 + std::chrono::milliseconds(1500)));   // 2 of 4
    EXPECT_TRUE(b.full(t0 + std::chrono::milliseconds(2600)));    // capped at 4
    // Never more than the burst, however long it was quiet.
    const auto t1 = t0 + std::chrono::hours(1);
    for (int i = 0; i < 4; ++i) {
        ASSERT_TRUE(b.ready(t1)) << i;
        b.take();
    }
    EXPECT_FALSE(b.ready(t1));
    // Rate 0 or burst 0: no limit (both flags document "0 = no limit").
    for (const auto& [rate, burst] : {std::pair<double, double>{0.0, 1.0}, {5.0, 0.0}, {0.0, 0.0}}) {
        core::StratumTlsTokenBucket unlimited(rate, burst, t0);
        EXPECT_TRUE(unlimited.unlimited()) << rate << "/" << burst;
        for (int i = 0; i < 1000; ++i) {
            ASSERT_TRUE(unlimited.ready(t0)) << rate << "/" << burst;
            unlimited.take();
        }
        EXPECT_TRUE(unlimited.full(t0));
    }
    // A burst below 1 still holds one token.
    core::StratumTlsTokenBucket half(1.0, 0.5, t0);
    EXPECT_FALSE(half.unlimited());
    EXPECT_TRUE(half.ready(t0));
    half.take();
    EXPECT_FALSE(half.ready(t0));
}

TEST(StratumTlsLimits, AcceptLimiterGlobalAndPerAddress)
{
    using L = core::StratumTlsAcceptLimiter;
    using clock = L::clock;
    const auto t0 = clock::now();
    const auto a = boost::asio::ip::make_address("192.0.2.1");
    const auto b = boost::asio::ip::make_address("192.0.2.2");
    {
        L lim(10.0, 3.0, 0.0, 0.0, t0);   // 3 at once from all addresses
        EXPECT_EQ(lim.admit(a, t0), L::Verdict::Admit);
        EXPECT_EQ(lim.admit(b, t0), L::Verdict::Admit);
        EXPECT_EQ(lim.admit(a, t0), L::Verdict::Admit);
        EXPECT_EQ(lim.admit(b, t0), L::Verdict::Rate);
        EXPECT_EQ(lim.admit(b, t0 + std::chrono::milliseconds(100)), L::Verdict::Admit);   // 1 token back
    }
    {
        L lim(0.0, 0.0, 1.0, 2.0, t0);   // 2 at once from one address
        EXPECT_EQ(lim.admit(a, t0), L::Verdict::Admit);
        EXPECT_EQ(lim.admit(a, t0), L::Verdict::Admit);
        EXPECT_EQ(lim.admit(a, t0), L::Verdict::RatePerIp);
        EXPECT_EQ(lim.admit(b, t0), L::Verdict::Admit);   // another address has its own
        EXPECT_EQ(lim.admit(a, t0 + std::chrono::seconds(1)), L::Verdict::Admit);
    }
    {
        // A refused accept takes no token anywhere, and adds no key.
        L lim(10.0, 1.0, 1.0, 1.0, t0);
        EXPECT_EQ(lim.admit(a, t0), L::Verdict::Admit);
        EXPECT_EQ(lim.keys(), 1u);
        EXPECT_EQ(lim.admit(b, t0), L::Verdict::Rate);
        EXPECT_EQ(lim.keys(), 1u);
        // A per-address refusal does not spend the global token.
        EXPECT_EQ(lim.admit(a, t0 + std::chrono::milliseconds(100)), L::Verdict::RatePerIp);
        EXPECT_EQ(lim.admit(b, t0 + std::chrono::milliseconds(100)), L::Verdict::Admit);
    }
    {
        // Keys whose bucket is full again are pruned once the map is large;
        // a key still drained survives (its refusal state is kept).
        L lim(0.0, 0.0, 0.1, 1.0, t0);   // one token per 10 s
        for (unsigned i = 0; i < 2000; ++i)
            ASSERT_EQ(lim.admit(boost::asio::ip::make_address_v4(0x0a000000u + i), t0), L::Verdict::Admit);
        EXPECT_EQ(lim.keys(), 2000u);
        const auto t1 = t0 + std::chrono::seconds(20);   // all 2000 full again
        const auto drained = boost::asio::ip::make_address("198.51.100.1");
        EXPECT_EQ(lim.admit(drained, t1), L::Verdict::Admit);   // prunes, then drains this one
        EXPECT_EQ(lim.keys(), 1u);
        for (unsigned i = 0; i < 1100; ++i)
            ASSERT_EQ(lim.admit(boost::asio::ip::make_address_v4(0x0b000000u + i), t1), L::Verdict::Admit);
        EXPECT_EQ(lim.keys(), 1101u);
        const auto t2 = t1 + std::chrono::seconds(2);   // a prune runs, nothing is full
        EXPECT_EQ(lim.admit(boost::asio::ip::make_address("198.51.100.2"), t2), L::Verdict::Admit);
        EXPECT_EQ(lim.keys(), 1102u);
        EXPECT_EQ(lim.admit(drained, t2), L::Verdict::RatePerIp);   // still drained: kept
    }
    {
        // A per-address burst of 0 is no per-address limit.
        L lim(0.0, 0.0, 5.0, 0.0, t0);
        for (int i = 0; i < 100; ++i)
            ASSERT_EQ(lim.admit(a, t0), L::Verdict::Admit) << i;
    }
    {
        // check() spends nothing; take() spends what check() admitted.
        L lim(10.0, 2.0, 1.0, 1.0, t0);
        EXPECT_EQ(lim.check(a, t0), L::Verdict::Admit);
        EXPECT_EQ(lim.check(a, t0), L::Verdict::Admit);
        lim.take(a);
        EXPECT_EQ(lim.check(a, t0), L::Verdict::RatePerIp);
        EXPECT_EQ(lim.check(b, t0), L::Verdict::Admit);
        lim.take(b);
        EXPECT_EQ(lim.check(b, t0), L::Verdict::Rate);   // the global two are spent
    }
}

TEST(StratumTlsLimits, HandshakeGateEvictsTheOldest)
{
    using clock = core::StratumTlsHandshakeGate::clock;
    const auto t0 = clock::now();
    const auto a = boost::asio::ip::make_address("192.0.2.1");
    const auto b = boost::asio::ip::make_address("192.0.2.2");
    const auto c = boost::asio::ip::make_address("192.0.2.3");
    const auto after = std::chrono::milliseconds(1500);
    {
        core::StratumTlsHandshakeGate gate;
        int closed1 = 0, closed2 = 0;
        auto s1 = gate.try_acquire(a, 2, 0, t0, after);
        auto s2 = gate.try_acquire(b, 2, 0, t0 + std::chrono::milliseconds(100), after);
        ASSERT_TRUE(s1 && s2);
        s1->on_evict([&] { ++closed1; });
        s2->on_evict([&] { ++closed2; });
        // At the limit, both younger than 1.5 s: refused.
        EXPECT_FALSE(gate.try_acquire(c, 2, 0, t0 + std::chrono::milliseconds(1000), after));
        // s1 old enough: evicted for the newcomer, at once.
        auto s3 = gate.try_acquire(c, 2, 0, t0 + std::chrono::milliseconds(1550), after);
        ASSERT_TRUE(s3);
        EXPECT_EQ(closed1, 1);
        EXPECT_EQ(closed2, 0);
        EXPECT_EQ(gate.evictions(), 1u);
        EXPECT_EQ(gate.in_progress(), 2u);
        EXPECT_EQ(gate.in_progress_from(a), 0u);
        s1.reset();   // the evicted session goes later: counts unchanged
        EXPECT_EQ(gate.in_progress(), 2u);
        // s2 next (s3 has no on_evict: never evicted).
        auto s4 = gate.try_acquire(a, 2, 0, t0 + std::chrono::seconds(5), after);
        ASSERT_TRUE(s4);
        EXPECT_EQ(closed2, 1);
        EXPECT_FALSE(gate.try_acquire(b, 2, 0, t0 + std::chrono::seconds(9), after));   // s3, s4: no on_evict
    }
    {
        // A key at its own limit evicts its own oldest, not another key's.
        core::StratumTlsHandshakeGate gate;
        int closed_a = 0, closed_b = 0;
        auto sb = gate.try_acquire(b, 10, 1, t0, after);
        auto sa = gate.try_acquire(a, 10, 1, t0 + std::chrono::milliseconds(10), after);
        ASSERT_TRUE(sa && sb);
        sb->on_evict([&] { ++closed_b; });
        sa->on_evict([&] { ++closed_a; });
        auto sa2 = gate.try_acquire(a, 10, 1, t0 + std::chrono::seconds(2), after);
        ASSERT_TRUE(sa2);
        EXPECT_EQ(closed_a, 1);
        EXPECT_EQ(closed_b, 0);
        EXPECT_EQ(gate.in_progress_from(a), 1u);
        EXPECT_EQ(gate.in_progress_from(b), 1u);
    }
}

TEST(StratumTlsLimits, HandshakeGateCountsAndReleases)
{
    core::StratumTlsHandshakeGate gate;
    const auto a = boost::asio::ip::make_address("192.0.2.1");
    const auto b = boost::asio::ip::make_address("192.0.2.2");
    auto s1 = gate.try_acquire(a, 3, 2);
    auto s2 = gate.try_acquire(a, 3, 2);
    ASSERT_TRUE(s1 && s2);
    EXPECT_FALSE(gate.try_acquire(a, 3, 2));   // two from a
    auto s3 = gate.try_acquire(b, 3, 2);
    ASSERT_TRUE(s3);
    EXPECT_FALSE(gate.try_acquire(b, 3, 2));   // three in all
    EXPECT_EQ(gate.in_progress(), 3u);
    EXPECT_EQ(gate.in_progress_from(a), 2u);
    auto copy = s1;
    s1.reset();
    EXPECT_EQ(gate.in_progress(), 3u);   // released with its last copy
    copy.reset();
    EXPECT_EQ(gate.in_progress(), 2u);
    EXPECT_EQ(gate.in_progress_from(a), 1u);
    EXPECT_TRUE(gate.try_acquire(a, 3, 2));   // a temporary: released at once
    EXPECT_EQ(gate.in_progress(), 2u);
    std::shared_ptr<void> outlives;
    {
        core::StratumTlsHandshakeGate g2;
        outlives = g2.try_acquire(a, 0, 0);
        ASSERT_TRUE(outlives);
    }
    outlives.reset();   // the gate is gone: still safe
    s2.reset();
    s3.reset();
    EXPECT_EQ(gate.in_progress(), 0u);
    EXPECT_EQ(gate.in_progress_from(a), 0u);
}

#ifdef C2POOL_STRATUM_TLS

namespace {

namespace ssl = boost::asio::ssl;

// A throwaway EC P-256 key and a self-signed certificate for CN=`cn`
// (SAN DNS:localhost, IP:127.0.0.1), written as PEM.
struct TestCert {
    std::string cert;
    std::string key;
};

bool write_self_signed(const fs::path& cert_path, const fs::path& key_path, const std::string& cn,
                       long serial, const char* passphrase = nullptr, bool rsa = false)
{
    EVP_PKEY* pkey = nullptr;
    EVP_PKEY_CTX* kctx = EVP_PKEY_CTX_new_id(rsa ? EVP_PKEY_RSA : EVP_PKEY_EC, nullptr);
    bool ok = kctx && EVP_PKEY_keygen_init(kctx) == 1
           && (rsa ? EVP_PKEY_CTX_set_rsa_keygen_bits(kctx, 2048) == 1
                   : EVP_PKEY_CTX_set_ec_paramgen_curve_nid(kctx, NID_X9_62_prime256v1) == 1)
           && EVP_PKEY_keygen(kctx, &pkey) == 1;
    EVP_PKEY_CTX_free(kctx);
    X509* x = ok ? X509_new() : nullptr;
    if (x) {
        X509_set_version(x, 2);
        ASN1_INTEGER_set(X509_get_serialNumber(x), serial);
        X509_gmtime_adj(X509_getm_notBefore(x), -3600);
        X509_gmtime_adj(X509_getm_notAfter(x), 86400);
        X509_set_pubkey(x, pkey);
        X509_NAME* name = X509_get_subject_name(x);
        X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                                   reinterpret_cast<const unsigned char*>(cn.c_str()), -1, -1, 0);
        X509_set_issuer_name(x, name);
        X509V3_CTX v3;
        X509V3_set_ctx_nodb(&v3);
        X509V3_set_ctx(&v3, x, x, nullptr, nullptr, 0);
        for (const auto& [nid, value] : {std::pair<int, const char*>{NID_basic_constraints, "critical,CA:TRUE"},
                                         {NID_subject_alt_name, "DNS:localhost,IP:127.0.0.1"}}) {
            X509_EXTENSION* ext = X509V3_EXT_nconf_nid(nullptr, &v3, nid, value);
            ok = ok && ext && X509_add_ext(x, ext, -1) == 1;
            X509_EXTENSION_free(ext);
        }
        ok = ok && X509_sign(x, pkey, EVP_sha256()) > 0;
    }
    if (ok) {
        BIO* cb = BIO_new_file(cert_path.string().c_str(), "wb");
        ok = cb && PEM_write_bio_X509(cb, x) == 1;
        BIO_free(cb);
        BIO* kb = BIO_new_file(key_path.string().c_str(), "wb");
        ok = ok && kb
          && (passphrase
                  ? PEM_write_bio_PrivateKey(kb, pkey, EVP_aes_128_cbc(),
                                             reinterpret_cast<const unsigned char*>(passphrase),
                                             static_cast<int>(std::strlen(passphrase)), nullptr, nullptr)
                  : PEM_write_bio_PrivateKey(kb, pkey, nullptr, nullptr, 0, nullptr, nullptr))
                 == 1;
        BIO_free(kb);
    }
    X509_free(x);
    EVP_PKEY_free(pkey);
    return ok;
}

TestCert make_cert(const fs::path& dir, const std::string& cn, long serial, bool rsa = false)
{
    TestCert c{(dir / (cn + ".crt")).string(), (dir / (cn + ".key")).string()};
    EXPECT_TRUE(write_self_signed(c.cert, c.key, cn, serial, nullptr, rsa)) << cn;
    return c;
}

// Replace `to` by `from`'s bytes in one rename, with a modification time
// `bump` past the old one (a renewal as certbot or an operator does it).
void replace_file(const std::string& from, const std::string& to, std::chrono::seconds bump = 2s)
{
    const auto before = fs::last_write_time(to);
    const std::string tmp = to + ".new";
    fs::copy_file(from, tmp, fs::copy_options::overwrite_existing);
    fs::last_write_time(tmp, before + bump);
    fs::rename(tmp, to);
}

// A blocking TLS client with timeouts (the TLS twin of RawClient).
class TlsClient {
public:
    // `trust`: verify the server against this PEM (and the name "localhost");
    // empty: no verification. max_version / min_version: OpenSSL protocol
    // bounds (0: the library's defaults).
    explicit TlsClient(const std::string& trust = {}, int max_version = 0, int min_version = 0)
        : ctx_(ssl::context::tls_client), stream_(io_, ctx_)
    {
        // On the connection itself: the SSL object already exists.
        if (min_version) SSL_set_min_proto_version(stream_.native_handle(), min_version);
        if (max_version) SSL_set_max_proto_version(stream_.native_handle(), max_version);
        if (!trust.empty()) {
            ctx_.load_verify_file(trust);
            stream_.set_verify_mode(ssl::verify_peer);
            stream_.set_verify_callback(ssl::host_name_verification("localhost"));
        } else {
            stream_.set_verify_mode(ssl::verify_none);
        }
        SSL_set_tlsext_host_name(stream_.native_handle(), "localhost");
    }

    // Let this client really offer TLS 1.0 / 1.1: OpenSSL 3 forbids them
    // below security level 0, so a refusal then comes from the server.
    void allow_legacy_protocols()
    {
        SSL_set_security_level(stream_.native_handle(), 0);
        SSL_set_cipher_list(stream_.native_handle(), "DEFAULT:@SECLEVEL=0");
    }

    // TCP connect, then the TLS handshake within `timeout`.
    bool connect(uint16_t port, std::chrono::milliseconds timeout = 3000ms)
    {
        boost::system::error_code ec;
        stream_.next_layer().connect(tcp::endpoint(net::ip::make_address("127.0.0.1"), port), ec);
        if (ec) { error_ = ec.message(); return false; }
        bool done = false;
        stream_.async_handshake(ssl::stream_base::client, [&](const boost::system::error_code& e) {
            done = true;
            if (e) error_ = e.message();
            handshake_ok_ = !e;
        });
        run(done, timeout);
        return handshake_ok_;
    }

    void send(const std::string& bytes)
    {
        bool done = false;
        net::async_write(stream_, net::buffer(bytes),
                         [&](const boost::system::error_code&, std::size_t) { done = true; });
        run(done, 3000ms);
    }

    std::optional<std::string> read_line(std::chrono::milliseconds timeout = 3000ms)
    {
        const auto deadline = std::chrono::steady_clock::now() + timeout;
        while (received_.find('\n') == std::string::npos && !closed_
               && std::chrono::steady_clock::now() < deadline) {
            bool done = false;
            stream_.async_read_some(net::buffer(buf_), [&](const boost::system::error_code& e, std::size_t n) {
                done = true;
                if (n) received_.append(buf_.data(), n);
                if (e) closed_ = true;
            });
            run(done, std::chrono::duration_cast<std::chrono::milliseconds>(
                          deadline - std::chrono::steady_clock::now()));
        }
        const auto nl = received_.find('\n');
        if (nl == std::string::npos) return std::nullopt;
        std::string line = received_.substr(0, nl);
        received_.erase(0, nl + 1);
        return line;
    }

    // The reply to request `id` (notifications before it are skipped).
    std::optional<json> reply(int id, std::chrono::milliseconds timeout = 3000ms)
    {
        for (int i = 0; i < 20; ++i) {
            auto line = read_line(timeout);
            if (!line) return std::nullopt;
            auto j = json::parse(*line, nullptr, false);
            if (j.is_object() && j.value("id", json()) == id) return j;
        }
        return std::nullopt;
    }

    // The subject CN of the certificate the server presented.
    std::string peer_cn()
    {
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
        X509* x = SSL_get1_peer_certificate(stream_.native_handle());
#else
        X509* x = SSL_get_peer_certificate(stream_.native_handle());
#endif
        if (!x) return {};
        char cn[256] = {};
        X509_NAME_get_text_by_NID(X509_get_subject_name(x), NID_commonName, cn, sizeof(cn));
        X509_free(x);
        return cn;
    }

    std::string version() { return SSL_get_version(stream_.native_handle()); }
    SSL* native() { return stream_.native_handle(); }

    // Run the client handshake again (after SSL_renegotiate): true when it
    // completed.
    bool handshake_again(std::chrono::milliseconds timeout = 3000ms)
    {
        bool done = false, ok = false;
        stream_.async_handshake(ssl::stream_base::client, [&](const boost::system::error_code& e) {
            done = true;
            ok = !e;
            if (e) error_ = e.message();
        });
        run(done, timeout);
        return ok;
    }
    uint16_t local_port() { return stream_.next_layer().local_endpoint().port(); }
    const std::string& error() const { return error_; }

private:
    void run(bool& done, std::chrono::milliseconds timeout)
    {
        io_.restart();
        io_.run_for(timeout);
        if (!done) {
            boost::system::error_code ec;
            stream_.next_layer().cancel(ec);
            io_.restart();
            io_.run();
        }
    }

    net::io_context io_;
    ssl::context ctx_;
    ssl::stream<tcp::socket> stream_;
    std::array<char, 4096> buf_{};
    std::string received_;
    std::string error_;
    bool handshake_ok_ = false;
    bool closed_ = false;
};

// The reply to request `id` on a plain connection.
std::optional<json> plain_reply(RawClient& c, int id)
{
    for (int i = 0; i < 20; ++i) {
        auto line = c.read_line();
        if (!line) return std::nullopt;
        auto j = json::parse(*line, nullptr, false);
        if (j.is_object() && j.value("id", json()) == id) return j;
    }
    return std::nullopt;
}

const std::string kSubscribe = R"({"id":1,"method":"mining.subscribe","params":["tls-test/1.0"]})" "\n";
const std::string kAuthorize =
    R"({"id":2,"method":"mining.authorize","params":["LTCtestaddress0123456789abcdef.rig1","x"]})" "\n";

// A StratumServer (plain listener) with a TLS listener, both on 127.0.0.1,
// on an io_context run on its own thread.
class TlsNode {
public:
    net::io_context ioc;
    std::shared_ptr<core::MiningInterface> work = std::make_shared<core::MiningInterface>(false);
    std::unique_ptr<core::StratumServer> stratum;
    uint16_t port = 0;
    uint16_t tls_port = 0;

    bool start(const TestCert& cert, const core::stratum::StratumConfig& cfg = {},
               std::chrono::milliseconds handshake_timeout = core::kStratumTlsHandshakeTimeout,
               const std::function<void(core::StratumServer::TlsOptions&)>& tweak = {})
    {
        work->set_stratum_config(cfg);
        for (int attempt = 0; attempt < 20 && !stratum; ++attempt) {
            auto s = std::make_unique<core::StratumServer>(ioc, "127.0.0.1", free_port(), work);
            if (s->start()) stratum = std::move(s);
        }
        if (!stratum) return false;
        port = stratum->get_port();
        core::StratumServer::TlsOptions o;
        o.bind_address = "127.0.0.1";
        o.port = 0;   // a free port
        o.cert_file = cert.cert;
        o.key_file = cert.key;
        o.handshake_timeout = handshake_timeout;
        if (tweak) tweak(o);
        std::string err;
        if (!stratum->start_tls(o, &err)) {
            ADD_FAILURE() << "start_tls: " << err;
            return false;
        }
        tls_port = stratum->get_tls_port();
        guard_.emplace(net::make_work_guard(ioc));
        th_ = std::thread([this] { ioc.run(); });
        return tls_port != 0;
    }

    template <typename F>
    auto on_io(F&& fn) -> decltype(fn())
    {
        std::promise<decltype(fn())> prom;
        auto fut = prom.get_future();
        net::post(ioc, [&] { prom.set_value(fn()); });
        return fut.get();
    }

    // Sessions still connected (notify_all prunes the closed ones first).
    size_t live_sessions()
    {
        return on_io([&] {
            stratum->notify_all(false);
            return stratum->get_session_count();
        });
    }

    ~TlsNode()
    {
        if (stratum && th_.joinable()) {
            std::promise<void> done;
            net::post(ioc, [&] { stratum->stop(); done.set_value(); });
            done.get_future().wait();
        }
        guard_.reset();
        ioc.stop();
        if (th_.joinable()) th_.join();
        stratum.reset();
    }

private:
    std::optional<net::executor_work_guard<net::io_context::executor_type>> guard_;
    std::thread th_;
};

}  // namespace

TEST(StratumTlsFlags, CertificateAndKeyMustLoad)
{
    TempDir dir;
    const auto a = make_cert(dir.path, "pool-a", 1);
    const auto b = make_cert(dir.path, "pool-b", 2);
    EXPECT_FALSE(core::check_stratum_tls_settings({"3334", a.cert, a.key}));
    EXPECT_FALSE(core::check_stratum_tls_settings({"127.0.0.1:3334", a.cert, a.key}));
    EXPECT_FALSE(core::check_stratum_tls_settings({"[::1]:3334", a.cert, a.key}));

    auto refused = [](core::StratumTlsSettings s, const std::string& needle) {
        const auto why = core::check_stratum_tls_settings(s);
        if (!why) return ::testing::AssertionFailure() << "accepted";
        if (why->find(needle) == std::string::npos)
            return ::testing::AssertionFailure() << "'" << *why << "' lacks '" << needle << "'";
        return ::testing::AssertionSuccess();
    };
    EXPECT_TRUE(refused({"3334", (dir.path / "missing.crt").string(), a.key}, "cannot read"));
    EXPECT_TRUE(refused({"3334", a.cert, (dir.path / "missing.key").string()}, "cannot read"));
    EXPECT_TRUE(refused({"3334", a.cert, b.key}, "does not match"));
    EXPECT_TRUE(refused({"3334", a.key, a.key}, "cannot load the certificate chain"));
    EXPECT_TRUE(refused({"3334", a.cert, a.cert}, "cannot load the private key"));
}

TEST(StratumTlsFlags, PassphraseProtectedKeyIsRefusedWithoutAPrompt)
{
    TempDir dir;
    const std::string cert = (dir.path / "enc.crt").string();
    const std::string key = (dir.path / "enc.key").string();
    ASSERT_TRUE(write_self_signed(cert, key, "pool-enc", 9, "secret"));
    // A prompt would read the terminal and block; the load returns at once.
    auto fut = std::async(std::launch::async, [&] { return core::check_stratum_tls_settings({"3334", cert, key}); });
    ASSERT_EQ(fut.wait_for(10s), std::future_status::ready);
    const auto why = fut.get();
    ASSERT_TRUE(why);
    EXPECT_NE(why->find("cannot load the private key"), std::string::npos) << *why;
}

TEST(StratumTlsListener, StartRefusals)
{
    TempDir dir;
    const auto a = make_cert(dir.path, "pool-a", 1);
    net::io_context ioc;
    auto work = std::make_shared<core::MiningInterface>(false);
    core::StratumServer s(ioc, "127.0.0.1", free_port(), work);
    core::StratumServer::TlsOptions o;
    o.bind_address = "127.0.0.1";
    o.cert_file = a.cert;
    o.key_file = a.key;
    std::string err;
    EXPECT_FALSE(s.start_tls(o, &err));   // the plain listener is not running
    EXPECT_NE(err.find("not running"), std::string::npos) << err;
    ASSERT_TRUE(s.start());
    o.port = s.get_port();
    EXPECT_FALSE(s.start_tls(o, &err));   // the plain listener's own address
    EXPECT_NE(err.find("plain stratum listener"), std::string::npos) << err;
    o.port = 0;
    o.key_file = a.cert;
    EXPECT_FALSE(s.start_tls(o, &err));
    EXPECT_NE(err.find("cannot load the private key"), std::string::npos) << err;
    EXPECT_FALSE(s.is_tls_running());
    EXPECT_EQ(s.get_tls_port(), 0);
    o.key_file = a.key;
    ASSERT_TRUE(s.start_tls(o, &err)) << err;
    EXPECT_TRUE(s.is_tls_running());
    EXPECT_NE(s.get_tls_port(), 0);
    EXPECT_NE(s.get_tls_certificate_summary().find("CN=pool-a"), std::string::npos)
        << s.get_tls_certificate_summary();
    EXPECT_FALSE(s.start_tls(o, &err));   // once
    EXPECT_NE(err.find("already open"), std::string::npos) << err;
    s.stop();
    EXPECT_FALSE(s.is_tls_running());
}

TEST(StratumTlsListener, ConfigureFromTheFlags)
{
    TempDir dir;
    const auto a = make_cert(dir.path, "pool-a", 1);
    net::io_context ioc;
    auto work = std::make_shared<core::MiningInterface>(false);
    core::StratumServer s(ioc, "127.0.0.1", free_port(), work);
    ASSERT_TRUE(s.start());
    EXPECT_FALSE(core::configure_stratum_tls(&s, {}));   // not set: nothing
    EXPECT_FALSE(s.is_tls_running());
    EXPECT_FALSE(core::configure_stratum_tls(nullptr, {"3334", a.cert, a.key}));   // no stratum listener
    const uint16_t p = free_port();
    // PORT alone: the stratum listener's host.
    core::StratumTlsSettings set{std::to_string(p), a.cert, a.key};
    set.rate_per_ip = 7.5;
    set.burst_per_ip = 30;
    set.max_handshakes = 64;
    set.max_handshakes_per_ip = 0;
    ASSERT_TRUE(core::configure_stratum_tls(&s, set));
    EXPECT_EQ(s.get_tls_bind_address(), "127.0.0.1");
    EXPECT_EQ(s.get_tls_port(), p);
    const auto o = s.get_tls_options();
    EXPECT_EQ(o.accept_rate_per_ip, 7.5);
    EXPECT_EQ(o.accept_burst_per_ip, 30.0);
    EXPECT_EQ(o.max_handshakes, 64u);
    EXPECT_EQ(o.max_handshakes_per_ip, 0u);
    EXPECT_EQ(o.accept_rate, core::kStratumTlsAcceptRate);   // not a flag
    s.stop();
}

TEST(StratumTlsSession, SubscribeAndAuthorizeOverTlsAnswerAsPlain)
{
    TempDir dir;
    const auto a = make_cert(dir.path, "localhost", 1);
    TlsNode node;
    ASSERT_TRUE(node.start(a));

    RawClient plain;
    ASSERT_TRUE(plain.connect("127.0.0.1", node.port));
    plain.send(kSubscribe);
    const auto p_sub = plain_reply(plain, 1);
    plain.send(kAuthorize);
    const auto p_auth = plain_reply(plain, 2);
    ASSERT_TRUE(p_sub && p_auth);

    // The client verifies the chain and the name against the certificate.
    TlsClient tls(a.cert);
    ASSERT_TRUE(tls.connect(node.tls_port)) << tls.error();
    EXPECT_EQ(tls.peer_cn(), "localhost");
    tls.send(kSubscribe);
    const auto t_sub = tls.reply(1);
    tls.send(kAuthorize);
    const auto t_auth = tls.reply(2);
    ASSERT_TRUE(t_sub && t_auth);

    // mining.subscribe: the same shape; only the per-session ids differ.
    ASSERT_TRUE((*p_sub)["error"].is_null());
    ASSERT_TRUE((*t_sub)["error"].is_null());
    ASSERT_TRUE((*p_sub)["result"].is_array() && (*t_sub)["result"].is_array());
    ASSERT_EQ((*p_sub)["result"].size(), (*t_sub)["result"].size());
    ASSERT_EQ((*t_sub)["result"].size(), 3u);
    EXPECT_EQ((*p_sub)["result"][2], (*t_sub)["result"][2]);   // extranonce2_size
    EXPECT_EQ((*p_sub)["result"][1].get<std::string>().size(),
              (*t_sub)["result"][1].get<std::string>().size());   // extranonce1
    EXPECT_NE((*p_sub)["result"][1], (*t_sub)["result"][1]);
    auto methods = [](const json& r) {
        std::vector<std::string> m;
        for (const auto& s : r["result"][0]) m.push_back(s[0].get<std::string>());
        return m;
    };
    EXPECT_EQ(methods(*p_sub), methods(*t_sub));
    // mining.authorize: byte-identical.
    EXPECT_EQ(p_auth->dump(), t_auth->dump());
    EXPECT_EQ((*t_auth)["result"], true) << t_auth->dump();

    // The registry lists the TLS session under its real remote address.
    const std::string tls_ep = "127.0.0.1:" + std::to_string(tls.local_port());
    const std::string plain_ep = "127.0.0.1:" + std::to_string(plain.socket().local_endpoint().port());
    ASSERT_TRUE(wait_until([&] { return node.work->get_stratum_workers().size() == 2; }));
    std::optional<core::MiningInterface::WorkerInfo> tls_row, plain_row;
    for (const auto& [id, w] : node.work->get_stratum_workers()) {
        if (w.remote_endpoint == tls_ep) tls_row = w;
        if (w.remote_endpoint == plain_ep) plain_row = w;
    }
    ASSERT_TRUE(tls_row) << tls_ep;
    ASSERT_TRUE(plain_row) << plain_ep;
    EXPECT_EQ(tls_row->username, plain_row->username);
    EXPECT_EQ(tls_row->worker_name, plain_row->worker_name);
    EXPECT_EQ(tls_row->payout_warning, plain_row->payout_warning);
    EXPECT_EQ(tls_row->difficulty, plain_row->difficulty);
    EXPECT_EQ(node.stratum->get_session_count(), 2u);
    EXPECT_EQ(node.stratum->get_tls_handshakes(), 1u);
    EXPECT_EQ(node.stratum->get_tls_handshake_failures(), 0u);

    // An unknown method and a malformed line: the same errors as plain.
    for (const std::string& line : {std::string(R"({"id":5,"method":"mining.nope","params":[]})"),
                                    std::string(R"({"id":6,"method":"mining.submit","params":[]})")}) {
        plain.send(line + "\n");
        tls.send(line + "\n");
        const int id = json::parse(line)["id"];
        const auto p = plain_reply(plain, id);
        const auto t = tls.reply(id);
        ASSERT_TRUE(p && t) << line;
        EXPECT_EQ(p->dump(), t->dump()) << line;
    }
}

TEST(StratumTlsSession, Tls12And13ClientsConnectOlderOnesDoNot)
{
    TempDir dir;
    const auto a = make_cert(dir.path, "localhost", 1);
    TlsNode node;
    ASSERT_TRUE(node.start(a));
    {
        TlsClient c(a.cert, TLS1_2_VERSION);
        ASSERT_TRUE(c.connect(node.tls_port)) << c.error();
        EXPECT_EQ(c.version(), "TLSv1.2");
        c.send(kSubscribe);
        EXPECT_TRUE(c.reply(1));
    }
    {
        TlsClient c(a.cert, 0, TLS1_3_VERSION);
        ASSERT_TRUE(c.connect(node.tls_port)) << c.error();
        EXPECT_EQ(c.version(), "TLSv1.3");
        c.send(kSubscribe);
        EXPECT_TRUE(c.reply(1));
    }
    {
        // A client that offers at most TLS 1.1 gets no session.
        TlsClient c({}, TLS1_1_VERSION);
        EXPECT_FALSE(c.connect(node.tls_port));
    }
    EXPECT_TRUE(wait_until([&] { return node.stratum->get_tls_handshake_failures() == 1; }));
    EXPECT_EQ(node.stratum->get_tls_handshakes(), 2u);
}

// One protocol version at a time, from a client able to offer TLS 1.0 and 1.1:
// the server refuses 1.0 and 1.1 and accepts 1.2 and 1.3. (The context's
// option and minimum-version bits are pinned in ServerContextDefaults.)
TEST(StratumTlsSession, EachProtocolVersionAloneBelowTls12IsRefused)
{
    TempDir dir;
    const auto a = make_cert(dir.path, "localhost", 1);
    TlsNode node;
    ASSERT_TRUE(node.start(a));
    const std::pair<int, bool> cases[] = {
        {TLS1_VERSION, false}, {TLS1_1_VERSION, false},
        {TLS1_2_VERSION, true}, {TLS1_3_VERSION, true}};
    for (const auto& [version, accepted] : cases) {
        TlsClient c({}, version, version);
        c.allow_legacy_protocols();
        EXPECT_EQ(c.connect(node.tls_port), accepted)
            << "protocol 0x" << std::hex << version << ": " << c.error();
        if (accepted) {
            // A reply proves the server finished its side of the handshake
            // (a TLS 1.3 client finishes first).
            c.send(kSubscribe);
            EXPECT_TRUE(c.reply(1));
        }
    }
    EXPECT_TRUE(wait_until([&] { return node.stratum->get_tls_handshake_failures() == 2; }));
    EXPECT_TRUE(wait_until([&] { return node.stratum->get_tls_handshakes() == 2; }));
}

TEST(StratumTlsSession, PlaintextClientOnTheTlsPortIsClosed)
{
    TempDir dir;
    const auto a = make_cert(dir.path, "localhost", 1);
    TlsNode node;
    ASSERT_TRUE(node.start(a));

    RawClient c;
    ASSERT_TRUE(c.connect("127.0.0.1", node.tls_port));
    c.send(kSubscribe);
    const std::string got = c.read_all(3000ms);
    EXPECT_TRUE(c.closed());
    EXPECT_EQ(got.find("\"result\""), std::string::npos) << got;   // at most a TLS alert
    ASSERT_TRUE(wait_until([&] { return node.stratum->get_tls_handshake_failures() == 1; }));
    EXPECT_EQ(node.stratum->get_tls_handshakes(), 0u);
    EXPECT_TRUE(node.work->get_stratum_workers().empty());
    EXPECT_EQ(node.live_sessions(), 0u);

    // Both listeners keep serving.
    TlsClient t(a.cert);
    ASSERT_TRUE(t.connect(node.tls_port)) << t.error();
    t.send(kSubscribe);
    EXPECT_TRUE(t.reply(1));
    RawClient p;
    ASSERT_TRUE(p.connect("127.0.0.1", node.port));
    p.send(kSubscribe);
    EXPECT_TRUE(plain_reply(p, 1));
}

TEST(StratumTlsSession, SilentClientIsClosedAtTheHandshakeTimeout)
{
    TempDir dir;
    const auto a = make_cert(dir.path, "localhost", 1);
    TlsNode node;
    ASSERT_TRUE(node.start(a, {}, 300ms));
    EXPECT_EQ(node.stratum->tls_handshake_timeout(), 300ms);

    RawClient c;
    ASSERT_TRUE(c.connect("127.0.0.1", node.tls_port));
    const auto t0 = std::chrono::steady_clock::now();
    const std::string got = c.read_all(5000ms);   // sends nothing
    const auto took = std::chrono::steady_clock::now() - t0;
    EXPECT_TRUE(c.closed());
    EXPECT_TRUE(got.empty()) << got.size();
    EXPECT_LT(took, 3000ms);
    ASSERT_TRUE(wait_until([&] { return node.stratum->get_tls_handshake_failures() == 1; }));
    EXPECT_EQ(node.live_sessions(), 0u);

    TlsClient t(a.cert);
    ASSERT_TRUE(t.connect(node.tls_port)) << t.error();
    t.send(kSubscribe);
    EXPECT_TRUE(t.reply(1));
}

TEST(StratumTlsSession, HttpOnTheStratumPortIsPlainOnly)
{
    TempDir dir;
    const auto a = make_cert(dir.path, "localhost", 1);
    TlsNode node;
    ASSERT_TRUE(node.start(a));
    std::atomic<int> handed{0};
    node.stratum->set_http(true, [&](core::StratumHttpRequest&) { ++handed; return false; });

    TlsClient t(a.cert);
    ASSERT_TRUE(t.connect(node.tls_port)) << t.error();
    t.send(request("GET", "/global_stats"));
    const auto line = t.read_line();
    ASSERT_TRUE(line);
    const auto j = json::parse(*line, nullptr, false);
    ASSERT_TRUE(j.is_object()) << *line;
    EXPECT_EQ(j["error"][1], "Invalid JSON") << *line;
    EXPECT_EQ(handed.load(), 0);

    // The plain port still hands HTTP over (its handler declined: a 503).
    const auto r = exchange("127.0.0.1", node.port, request("GET", "/global_stats"));
    EXPECT_TRUE(r.ok);
    EXPECT_EQ(r.status, 503u);
    EXPECT_EQ(handed.load(), 1);
}

TEST(StratumTlsSession, PerIpCapCountsPlainAndTlsTogether)
{
    TempDir dir;
    const auto a = make_cert(dir.path, "localhost", 1);
    core::stratum::StratumConfig cfg;
    cfg.max_stratum_connections_per_ip = 1;
    TlsNode node;
    ASSERT_TRUE(node.start(a, cfg));
    {
        RawClient p;
        ASSERT_TRUE(p.connect("127.0.0.1", node.port));
        p.send(kSubscribe);
        ASSERT_TRUE(plain_reply(p, 1));
        TlsClient t(a.cert);
        EXPECT_FALSE(t.connect(node.tls_port));   // refused at the accept
        EXPECT_TRUE(wait_until([&] { return node.stratum->get_refused_per_ip() == 1; }));
    }
    EXPECT_TRUE(wait_until([&] { return node.live_sessions() == 0; }));
    {
        TlsClient t(a.cert);
        ASSERT_TRUE(t.connect(node.tls_port)) << t.error();
        t.send(kSubscribe);
        ASSERT_TRUE(t.reply(1));
        RawClient p;
        ASSERT_TRUE(p.connect("127.0.0.1", node.port));
        p.send(kSubscribe);
        EXPECT_FALSE(plain_reply(p, 1));   // closed at the accept
        EXPECT_TRUE(wait_until([&] { return node.stratum->get_refused_per_ip() == 2; }));
    }
}

TEST(StratumTlsReload, NewConnectionsGetTheRenewedCertificate)
{
    TempDir dir;
    const auto a = make_cert(dir.path, "pool-a", 1);
    const auto b = make_cert(dir.path, "pool-b", 2);
    const auto c = make_cert(dir.path, "pool-c", 3);
    // The files the listener reads (a renewal replaces them in place).
    const TestCert live{(dir.path / "live.crt").string(), (dir.path / "live.key").string()};
    fs::copy_file(a.cert, live.cert);
    fs::copy_file(a.key, live.key);

    TlsNode node;
    ASSERT_TRUE(node.start(live));
    TlsClient first;
    ASSERT_TRUE(first.connect(node.tls_port)) << first.error();
    EXPECT_EQ(first.peer_cn(), "pool-a");
    first.send(kSubscribe);
    ASSERT_TRUE(first.reply(1));

    // Renewed: the next accept reads the new pair.
    replace_file(b.key, live.key);
    replace_file(b.cert, live.cert);
    TlsClient second;
    ASSERT_TRUE(second.connect(node.tls_port)) << second.error();
    EXPECT_EQ(second.peer_cn(), "pool-b");
    EXPECT_EQ(node.stratum->get_tls_reloads(), 1u);
    EXPECT_NE(node.stratum->get_tls_certificate_summary().find("CN=pool-b"), std::string::npos);

    // The connection opened before keeps working, on its certificate.
    first.send(kAuthorize);
    const auto auth = first.reply(2);
    ASSERT_TRUE(auth);
    EXPECT_EQ((*auth)["result"], true);
    EXPECT_EQ(first.peer_cn(), "pool-a");

    // Half-renewed (the certificate changed, the key not yet): it does not
    // load; the last good pair stays in use and is not retried until a file
    // changes again.
    replace_file(c.cert, live.cert);
    TlsClient third;
    ASSERT_TRUE(third.connect(node.tls_port)) << third.error();
    EXPECT_EQ(third.peer_cn(), "pool-b");
    EXPECT_EQ(node.stratum->get_tls_reload_failures(), 1u);
    TlsClient third_again;
    ASSERT_TRUE(third_again.connect(node.tls_port)) << third_again.error();
    EXPECT_EQ(node.stratum->get_tls_reload_failures(), 1u);
    // ... and the key follows: loaded.
    replace_file(c.key, live.key);
    TlsClient fourth;
    ASSERT_TRUE(fourth.connect(node.tls_port)) << fourth.error();
    EXPECT_EQ(fourth.peer_cn(), "pool-c");
    EXPECT_EQ(node.stratum->get_tls_reloads(), 2u);
}

TEST(StratumTlsReload, ReloadNowAndSighup)
{
    TempDir dir;
    const auto a = make_cert(dir.path, "pool-a", 1);
    const auto b = make_cert(dir.path, "pool-b", 2);
    const TestCert live{(dir.path / "live.crt").string(), (dir.path / "live.key").string()};
    fs::copy_file(a.cert, live.cert);
    fs::copy_file(a.key, live.key);
    TlsNode node;
    ASSERT_TRUE(node.start(live));

    // reload_tls(): a re-read now, whatever the files' stamps.
    std::string err;
    ASSERT_TRUE(node.stratum->reload_tls(&err)) << err;
    EXPECT_EQ(node.stratum->get_tls_reloads(), 1u);
    fs::copy_file(b.cert, live.cert, fs::copy_options::overwrite_existing);
    fs::copy_file(b.key, live.key, fs::copy_options::overwrite_existing);
    ASSERT_TRUE(node.stratum->reload_tls(&err)) << err;
    EXPECT_EQ(node.stratum->get_tls_reloads(), 2u);
    TlsClient c1;
    ASSERT_TRUE(c1.connect(node.tls_port)) << c1.error();
    EXPECT_EQ(c1.peer_cn(), "pool-b");
    EXPECT_EQ(node.stratum->get_tls_reloads(), 2u);   // the accept saw nothing new

    // A re-read of a pair that does not load keeps the last good one.
    std::ofstream(live.key, std::ios::binary | std::ios::trunc) << "not a key\n";
    EXPECT_FALSE(node.stratum->reload_tls(&err));
    EXPECT_NE(err.find("cannot load the private key"), std::string::npos) << err;
    EXPECT_EQ(node.stratum->get_tls_reload_failures(), 1u);
    TlsClient c2;
    ASSERT_TRUE(c2.connect(node.tls_port)) << c2.error();
    EXPECT_EQ(c2.peer_cn(), "pool-b");

#ifndef _WIN32
    // SIGHUP: the same re-read, on the io thread; armed again after each.
    fs::copy_file(a.cert, live.cert, fs::copy_options::overwrite_existing);
    fs::copy_file(a.key, live.key, fs::copy_options::overwrite_existing);
    const uint64_t before = node.stratum->get_tls_reloads();
    ASSERT_EQ(std::raise(SIGHUP), 0);
    ASSERT_TRUE(wait_until([&] { return node.stratum->get_tls_reloads() == before + 1; }));
    TlsClient c3;
    ASSERT_TRUE(c3.connect(node.tls_port)) << c3.error();
    EXPECT_EQ(c3.peer_cn(), "pool-a");
    ASSERT_EQ(std::raise(SIGHUP), 0);
    EXPECT_TRUE(wait_until([&] { return node.stratum->get_tls_reloads() == before + 2; }));
#endif
}

TEST(StratumTlsContextSettings, ServerContextDefaults)
{
    TempDir dir;
    const auto a = make_cert(dir.path, "pool-a", 1);
    std::string err;
    auto ctx = core::load_stratum_tls_context(a.cert, a.key, err);
    ASSERT_TRUE(ctx) << err;
    auto* h = static_cast<SSL_CTX*>(core::stratum_tls_native_context(*ctx));
    ASSERT_NE(h, nullptr);
    EXPECT_EQ(SSL_CTX_get_min_proto_version(h), TLS1_2_VERSION);
    const auto opts = SSL_CTX_get_options(h);
    // The asio options on the context (both bounds are kept).
    EXPECT_TRUE(opts & SSL_OP_NO_SSLv3);
    EXPECT_TRUE(opts & SSL_OP_NO_TLSv1);
    EXPECT_TRUE(opts & SSL_OP_NO_TLSv1_1);
    EXPECT_TRUE(opts & SSL_OP_NO_COMPRESSION);
    EXPECT_TRUE(opts & SSL_OP_CIPHER_SERVER_PREFERENCE);
    EXPECT_TRUE(opts & SSL_OP_NO_TICKET);
#ifdef SSL_OP_NO_RENEGOTIATION
    EXPECT_TRUE(opts & SSL_OP_NO_RENEGOTIATION);
#endif
    EXPECT_EQ(SSL_CTX_get_session_cache_mode(h), SSL_SESS_CACHE_OFF);
    EXPECT_EQ(SSL_CTX_get_num_tickets(h), 0u);
    EXPECT_EQ(SSL_CTX_get_verify_mode(h), SSL_VERIFY_NONE);
    EXPECT_TRUE(SSL_CTX_get_mode(h) & SSL_MODE_RELEASE_BUFFERS);
    // TLS 1.2 suites: ECDHE key exchange and AEAD only (TLS 1.3 suites are
    // all AEAD with their own key exchange).
    STACK_OF(SSL_CIPHER)* ciphers = SSL_CTX_get_ciphers(h);
    ASSERT_NE(ciphers, nullptr);
    int tls12 = 0;
    for (int i = 0; i < sk_SSL_CIPHER_num(ciphers); ++i) {
        const SSL_CIPHER* c = sk_SSL_CIPHER_value(ciphers, i);
        EXPECT_TRUE(SSL_CIPHER_is_aead(c)) << SSL_CIPHER_get_name(c);
        if (SSL_CIPHER_get_kx_nid(c) == NID_kx_any) continue;   // TLS 1.3
        ++tls12;
        EXPECT_EQ(SSL_CIPHER_get_kx_nid(c), NID_kx_ecdhe) << SSL_CIPHER_get_name(c);
    }
    EXPECT_EQ(tls12, 6);
    EXPECT_FALSE(core::stratum_tls_validity_problem(*ctx));
}

TEST(StratumTlsContextSettings, ExpiredCertificateLoadsAndIsNamed)
{
    TempDir dir;
    const auto a = make_cert(dir.path, "pool-a", 1);
    // Re-sign it with a validity period in the past.
    BIO* in = BIO_new_file(a.cert.c_str(), "rb");
    X509* x = PEM_read_bio_X509(in, nullptr, nullptr, nullptr);
    BIO_free(in);
    in = BIO_new_file(a.key.c_str(), "rb");
    EVP_PKEY* k = PEM_read_bio_PrivateKey(in, nullptr, nullptr, nullptr);
    BIO_free(in);
    ASSERT_TRUE(x && k);
    X509_gmtime_adj(X509_getm_notBefore(x), -7200);
    X509_gmtime_adj(X509_getm_notAfter(x), -3600);
    ASSERT_GT(X509_sign(x, k, EVP_sha256()), 0);
    BIO* out = BIO_new_file(a.cert.c_str(), "wb");
    PEM_write_bio_X509(out, x);
    BIO_free(out);
    X509_free(x);
    EVP_PKEY_free(k);
    std::string err;
    auto ctx = core::load_stratum_tls_context(a.cert, a.key, err);
    ASSERT_TRUE(ctx) << err;
    ASSERT_TRUE(core::stratum_tls_validity_problem(*ctx));
    EXPECT_EQ(*core::stratum_tls_validity_problem(*ctx), "expired");
    EXPECT_NE(core::describe_stratum_tls_context(*ctx).find("(expired)"), std::string::npos);
}

TEST(StratumTlsContextSettings, KeyReadableByOthersIsNamed)
{
#ifdef _WIN32
    GTEST_SKIP() << "POSIX permissions";
#else
    TempDir dir;
    const auto a = make_cert(dir.path, "pool-a", 1);
    using P = fs::perms;
    auto problem = [&](P perms) {
        fs::permissions(a.key, perms, fs::perm_options::replace);
        return core::stratum_tls_key_permissions_problem(a.key);
    };
    EXPECT_FALSE(problem(P::owner_read | P::owner_write));                    // 600
    EXPECT_FALSE(problem(P::owner_read));                                     // 400
    EXPECT_FALSE(problem(P::owner_read | P::owner_write | P::group_read));    // 640 (root:ssl-cert)
    auto p = problem(P::owner_read | P::owner_write | P::others_read);        // 604
    ASSERT_TRUE(p);
    EXPECT_NE(p->find("readable by others (mode 604); chmod o-r"), std::string::npos) << *p;
    p = problem(P::owner_read | P::owner_write | P::group_read | P::group_write);   // 660
    ASSERT_TRUE(p);
    EXPECT_NE(p->find("writable by its group (mode 660); chmod g-w"), std::string::npos) << *p;
    p = problem(P::owner_read | P::owner_write | P::others_read | P::others_write);  // 606
    ASSERT_TRUE(p);
    EXPECT_NE(p->find("readable by others and writable by others (mode 606); chmod o-r,o-w"),
              std::string::npos) << *p;
    fs::permissions(a.key, P::owner_read | P::owner_write, fs::perm_options::replace);
#endif
}

TEST(StratumTlsSession, DefaultHandshakeTimeoutIsTenSeconds)
{
    TempDir dir;
    const auto a = make_cert(dir.path, "localhost", 1);
    TlsNode node;
    ASSERT_TRUE(node.start(a));
    EXPECT_EQ(node.stratum->tls_handshake_timeout(), std::chrono::milliseconds(10000));
}

TEST(StratumTlsSession, RenegotiationIsRefused)
{
    TempDir dir;
    const auto a = make_cert(dir.path, "localhost", 1);
    TlsNode node;
    ASSERT_TRUE(node.start(a));
    TlsClient c(a.cert, TLS1_2_VERSION);
    ASSERT_TRUE(c.connect(node.tls_port)) << c.error();
    ASSERT_EQ(c.version(), "TLSv1.2");
    c.send(kSubscribe);
    ASSERT_TRUE(c.reply(1));
    c.read_line(1000ms);   // the set_difficulty after it: nothing else is in flight
    ASSERT_EQ(SSL_renegotiate(c.native()), 1);   // scheduled on this side
    EXPECT_FALSE(c.handshake_again()) << "a client-initiated renegotiation completed";
}

TEST(StratumTlsSession, NoSessionResumption)
{
    TempDir dir;
    const auto a = make_cert(dir.path, "localhost", 1);
    TlsNode node;
    ASSERT_TRUE(node.start(a));
    for (const int version : {TLS1_2_VERSION, TLS1_3_VERSION}) {
        SSL_SESSION* saved = nullptr;
        {
            TlsClient c(a.cert, version, version);
            ASSERT_TRUE(c.connect(node.tls_port)) << c.error();
            c.send(kSubscribe);
            ASSERT_TRUE(c.reply(1));   // reads any post-handshake ticket too
            saved = SSL_get1_session(c.native());
            ASSERT_NE(saved, nullptr);
        }
        TlsClient again(a.cert, version, version);
        ASSERT_EQ(SSL_set_session(again.native(), saved), 1);
        ASSERT_TRUE(again.connect(node.tls_port)) << again.error();
        EXPECT_FALSE(SSL_session_reused(again.native())) << "resumed at version " << version;
        SSL_SESSION_free(saved);
    }
}

TEST(StratumTlsSession, NonForwardSecretSuitesAreRefused)
{
    TempDir dir;
    const auto r = make_cert(dir.path, "localhost", 1, /*rsa=*/true);
    TlsNode node;
    ASSERT_TRUE(node.start(r));
    {
        TlsClient c(r.cert, TLS1_2_VERSION);
        ASSERT_EQ(SSL_set_cipher_list(c.native(), "AES128-SHA"), 1);
        EXPECT_FALSE(c.connect(node.tls_port));
    }
    {
        TlsClient c(r.cert, TLS1_2_VERSION);
        ASSERT_EQ(SSL_set_cipher_list(c.native(), "ECDHE-RSA-AES128-GCM-SHA256"), 1);
        ASSERT_TRUE(c.connect(node.tls_port)) << c.error();
        EXPECT_STREQ(SSL_CIPHER_get_name(SSL_get_current_cipher(c.native())), "ECDHE-RSA-AES128-GCM-SHA256");
    }
}

TEST(StratumTlsSession, NodeCapCountsPlainAndTlsTogether)
{
    TempDir dir;
    const auto a = make_cert(dir.path, "localhost", 1);
    core::stratum::StratumConfig cfg;
    cfg.max_stratum_connections = 1;
    TlsNode node;
    ASSERT_TRUE(node.start(a, cfg));
    {
        RawClient p;
        ASSERT_TRUE(p.connect("127.0.0.1", node.port));
        p.send(kSubscribe);
        ASSERT_TRUE(plain_reply(p, 1));
        TlsClient t(a.cert);
        EXPECT_FALSE(t.connect(node.tls_port));
        EXPECT_TRUE(wait_until([&] { return node.stratum->get_refused_connections() == 1; }));
    }
    EXPECT_TRUE(wait_until([&] { return node.live_sessions() == 0; }));
    {
        TlsClient t(a.cert);
        ASSERT_TRUE(t.connect(node.tls_port)) << t.error();
        t.send(kSubscribe);
        ASSERT_TRUE(t.reply(1));
        RawClient p;
        ASSERT_TRUE(p.connect("127.0.0.1", node.port));
        p.send(kSubscribe);
        EXPECT_FALSE(plain_reply(p, 1));
        EXPECT_TRUE(wait_until([&] { return node.stratum->get_refused_connections() == 2; }));
    }
}

TEST(StratumTlsSession, LeadingBlankLineIsAStratumLineOverTls)
{
    TempDir dir;
    const auto a = make_cert(dir.path, "localhost", 1);
    TlsNode node;
    ASSERT_TRUE(node.start(a));
    node.stratum->set_http(true, [](core::StratumHttpRequest&) { return false; });
    // Plain with HTTP on: a leading empty line is skipped (RFC 9112 2.2).
    RawClient p;
    ASSERT_TRUE(p.connect("127.0.0.1", node.port));
    p.send("\r\n" + kSubscribe);
    const auto pl = p.read_line();
    ASSERT_TRUE(pl);
    EXPECT_EQ(json::parse(*pl).value("id", json()), 1) << *pl;
    // TLS: no HTTP, so the empty line is an invalid stratum line.
    TlsClient t(a.cert);
    ASSERT_TRUE(t.connect(node.tls_port)) << t.error();
    t.send("\r\n" + kSubscribe);
    const auto tl = t.read_line();
    ASSERT_TRUE(tl);
    const auto j = json::parse(*tl, nullptr, false);
    ASSERT_TRUE(j.is_object()) << *tl;
    EXPECT_EQ(j["error"][1], "Invalid JSON") << *tl;
    EXPECT_TRUE(t.reply(1));   // the subscribe after it is answered
}

TEST(StratumTlsSession, FailedHandshakesAreLoggedOncePerMinute)
{
    TempDir dir;
    const auto a = make_cert(dir.path, "localhost", 1);
    TlsNode node;
    ASSERT_TRUE(node.start(a));
    for (int i = 0; i < 3; ++i) {
        RawClient c;
        ASSERT_TRUE(c.connect("127.0.0.1", node.tls_port));
        c.send(kSubscribe);
        c.read_all(3000ms);
        EXPECT_TRUE(c.closed());
    }
    ASSERT_TRUE(wait_until([&] { return node.stratum->get_tls_handshake_failures() == 3; }));
    EXPECT_EQ(node.stratum->get_tls_handshake_log_lines(), 1u);
}

TEST(StratumTlsSession, AHandshakeClosedByStopIsNoFailure)
{
    TempDir dir;
    const auto a = make_cert(dir.path, "localhost", 1);
    TlsNode node;
    ASSERT_TRUE(node.start(a));
    RawClient c;   // connects, never starts the handshake
    ASSERT_TRUE(c.connect("127.0.0.1", node.tls_port));
    ASSERT_TRUE(wait_until([&] { return node.stratum->get_tls_handshakes_in_progress() == 1; }));
    node.on_io([&] { node.stratum->stop(); return 0; });
    EXPECT_TRUE(wait_until([&] { return node.stratum->get_tls_handshakes_in_progress() == 0; }));
    c.read_all(2000ms);
    EXPECT_TRUE(c.closed());
    node.on_io([] { return 0; });   // the aborted handshake's handler has run
    EXPECT_EQ(node.stratum->get_tls_handshake_failures(), 0u);
    EXPECT_EQ(node.stratum->get_tls_handshake_log_lines(), 0u);
}

TEST(StratumTlsRate, OverTheAcceptRateIsClosedAndCounted)
{
    TempDir dir;
    const auto a = make_cert(dir.path, "localhost", 1);
    TlsNode node;
    ASSERT_TRUE(node.start(a, {}, core::kStratumTlsHandshakeTimeout, [](auto& o) {
        o.accept_rate = 0.2;   // one token every 5 s, 2 held
        o.accept_burst = 2;
        o.accept_rate_per_ip = 0;
    }));
    for (int i = 0; i < 2; ++i) {
        TlsClient c(a.cert);
        ASSERT_TRUE(c.connect(node.tls_port)) << i << ": " << c.error();
    }
    TlsClient over(a.cert);
    EXPECT_FALSE(over.connect(node.tls_port));
    EXPECT_TRUE(wait_until([&] { return node.stratum->get_tls_refused_rate() == 1; }));
    EXPECT_EQ(node.stratum->get_tls_refused_rate_per_ip(), 0u);
    EXPECT_EQ(node.stratum->get_tls_handshake_failures(), 0u);   // closed before any TLS
    EXPECT_GE(node.stratum->get_refusal_lines_logged(), 1u);
    // The plain port is not limited.
    for (int i = 0; i < 5; ++i) {
        RawClient p;
        ASSERT_TRUE(p.connect("127.0.0.1", node.port));
        p.send(kSubscribe);
        EXPECT_TRUE(plain_reply(p, 1)) << i;
    }
    EXPECT_EQ(node.stratum->get_refused_connections(), 0u);
}

TEST(StratumTlsRate, OverOneAddressesAcceptRateIsClosedAndCounted)
{
    TempDir dir;
    const auto a = make_cert(dir.path, "localhost", 1);
    TlsNode node;
    ASSERT_TRUE(node.start(a, {}, core::kStratumTlsHandshakeTimeout, [](auto& o) {
        o.accept_rate = 0;
        o.accept_rate_per_ip = 0.2;
        o.accept_burst_per_ip = 2;
    }));
    for (int i = 0; i < 2; ++i) {
        TlsClient c(a.cert);
        ASSERT_TRUE(c.connect(node.tls_port)) << i << ": " << c.error();
    }
    TlsClient over(a.cert);
    EXPECT_FALSE(over.connect(node.tls_port));
    EXPECT_TRUE(wait_until([&] { return node.stratum->get_tls_refused_rate_per_ip() == 1; }));
    EXPECT_EQ(node.stratum->get_tls_refused_rate(), 0u);
    RawClient p;
    ASSERT_TRUE(p.connect("127.0.0.1", node.port));
    p.send(kSubscribe);
    EXPECT_TRUE(plain_reply(p, 1));
}

TEST(StratumTlsRate, HandshakesInProgressAreBounded)
{
    TempDir dir;
    const auto a = make_cert(dir.path, "localhost", 1);
    TlsNode node;
    ASSERT_TRUE(node.start(a, {}, core::kStratumTlsHandshakeTimeout, [](auto& o) {
        o.max_handshakes = 2;
        o.max_handshakes_per_ip = 0;
        o.evict_after = std::chrono::seconds(60);   // nothing evicted here
        o.first_byte_timeout = std::chrono::seconds(10);
    }));
    auto silent1 = std::make_unique<RawClient>();
    RawClient silent2;
    ASSERT_TRUE(silent1->connect("127.0.0.1", node.tls_port));
    ASSERT_TRUE(silent2.connect("127.0.0.1", node.tls_port));
    ASSERT_TRUE(wait_until([&] { return node.stratum->get_tls_handshakes_in_progress() == 2; }));
    {
        TlsClient c(a.cert);
        EXPECT_FALSE(c.connect(node.tls_port));
        EXPECT_TRUE(wait_until([&] { return node.stratum->get_tls_refused_handshakes() == 1; }));
    }
    // The plain port is not bounded by it.
    RawClient p;
    ASSERT_TRUE(p.connect("127.0.0.1", node.port));
    p.send(kSubscribe);
    EXPECT_TRUE(plain_reply(p, 1));
    // A slot is freed when a handshake ends (here: the client goes).
    silent1.reset();
    ASSERT_TRUE(wait_until([&] { return node.stratum->get_tls_handshakes_in_progress() == 1; }));
    TlsClient c(a.cert);
    ASSERT_TRUE(c.connect(node.tls_port)) << c.error();
    c.send(kSubscribe);
    EXPECT_TRUE(c.reply(1));
    EXPECT_EQ(node.stratum->get_tls_handshakes_in_progress(), 1u);   // silent2 only
}

TEST(StratumTlsRate, HandshakesInProgressFromOneAddressAreBounded)
{
    TempDir dir;
    const auto a = make_cert(dir.path, "localhost", 1);
    TlsNode node;
    ASSERT_TRUE(node.start(a, {}, core::kStratumTlsHandshakeTimeout, [](auto& o) {
        o.max_handshakes = 10;
        o.max_handshakes_per_ip = 1;
        o.evict_after = std::chrono::seconds(60);
        o.first_byte_timeout = std::chrono::seconds(10);
    }));
    RawClient silent;
    ASSERT_TRUE(silent.connect("127.0.0.1", node.tls_port));
    ASSERT_TRUE(wait_until([&] { return node.stratum->get_tls_handshakes_in_progress() == 1; }));
    RawClient second;
    ASSERT_TRUE(second.connect("127.0.0.1", node.tls_port));
    second.read_all(2000ms);
    EXPECT_TRUE(second.closed());
    EXPECT_EQ(node.stratum->get_tls_refused_handshakes(), 1u);
    EXPECT_EQ(node.stratum->get_tls_handshakes_in_progress(), 1u);
}

TEST(StratumTlsReload, SighupIsRestartableAndThePreviousDispositionComesBack)
{
#ifdef _WIN32
    GTEST_SKIP() << "no SIGHUP";
#else
    struct sigaction ignore {};
    ignore.sa_handler = SIG_IGN;
    sigemptyset(&ignore.sa_mask);
    struct sigaction before {};
    ASSERT_EQ(::sigaction(SIGHUP, &ignore, &before), 0);   // as under nohup
    {
        TempDir dir;
        const auto a = make_cert(dir.path, "localhost", 1);
        TlsNode node;
        ASSERT_TRUE(node.start(a));
        struct sigaction now {};
        ASSERT_EQ(::sigaction(SIGHUP, nullptr, &now), 0);
        EXPECT_NE(now.sa_handler, SIG_IGN);           // the listener's handler
        EXPECT_TRUE(now.sa_flags & SA_RESTART);       // EINTR-free for other threads
        node.on_io([&] { node.stratum->stop(); return 0; });
        ASSERT_EQ(::sigaction(SIGHUP, nullptr, &now), 0);
        EXPECT_EQ(now.sa_handler, SIG_IGN);           // nohup's SIG_IGN is back
    }
    ASSERT_EQ(::sigaction(SIGHUP, &before, nullptr), 0);
#endif
}

TEST(StratumTlsRate, SilentHoldersAreEvictedForARealClient)
{
    TempDir dir;
    const auto a = make_cert(dir.path, "localhost", 1);
    TlsNode node;
    ASSERT_TRUE(node.start(a, {}, core::kStratumTlsHandshakeTimeout, [](auto& o) {
        o.max_handshakes = 2;
        o.max_handshakes_per_ip = 0;
        o.evict_after = std::chrono::milliseconds(200);
        o.first_byte_timeout = std::chrono::seconds(10);   // only the eviction frees them
    }));
    RawClient silent1, silent2;
    ASSERT_TRUE(silent1.connect("127.0.0.1", node.tls_port));
    ASSERT_TRUE(wait_until([&] { return node.stratum->get_tls_handshakes_in_progress() == 1; }));
    ASSERT_TRUE(silent2.connect("127.0.0.1", node.tls_port));
    ASSERT_TRUE(wait_until([&] { return node.stratum->get_tls_handshakes_in_progress() == 2; }));
    std::this_thread::sleep_for(400ms);
    TlsClient c(a.cert);
    ASSERT_TRUE(c.connect(node.tls_port)) << c.error();
    c.send(kSubscribe);
    EXPECT_TRUE(c.reply(1));
    EXPECT_EQ(node.stratum->get_tls_handshake_evictions(), 1u);
    EXPECT_EQ(node.stratum->get_tls_refused_handshakes(), 0u);
    silent1.read_all(2000ms);
    EXPECT_TRUE(silent1.closed());   // the oldest was the one evicted
    EXPECT_TRUE(silent2.silent_for(200ms));
    EXPECT_TRUE(wait_until([&] { return node.stratum->get_tls_handshake_failures() == 1; }));
}

TEST(StratumTlsSession, NoClientHelloWithinTheFirstByteTimeout)
{
    TempDir dir;
    const auto a = make_cert(dir.path, "localhost", 1);
    TlsNode node;
    ASSERT_TRUE(node.start(a, {}, std::chrono::milliseconds(1000), [](auto& o) {
        o.first_byte_timeout = std::chrono::milliseconds(300);
    }));
    EXPECT_EQ(node.stratum->tls_first_byte_timeout(), std::chrono::milliseconds(300));
    {
        RawClient c;   // sends nothing
        ASSERT_TRUE(c.connect("127.0.0.1", node.tls_port));
        const auto t0 = std::chrono::steady_clock::now();
        c.read_all(5000ms);
        const auto took = std::chrono::steady_clock::now() - t0;
        EXPECT_TRUE(c.closed());
        EXPECT_GE(took, 200ms);
        EXPECT_LT(took, 900ms);   // the first-byte bound, not the 1000 ms one
    }
    {
        RawClient c;   // one byte of a record header, then nothing
        ASSERT_TRUE(c.connect("127.0.0.1", node.tls_port));
        const auto t0 = std::chrono::steady_clock::now();
        c.send(std::string(1, '\x16'));
        c.read_all(5000ms);
        const auto took = std::chrono::steady_clock::now() - t0;
        EXPECT_TRUE(c.closed());
        EXPECT_GE(took, 800ms);   // the whole-handshake bound
        EXPECT_LT(took, 3000ms);
    }
    EXPECT_TRUE(wait_until([&] { return node.stratum->get_tls_handshake_failures() == 2; }));
    TlsClient t(a.cert);   // a real client is unaffected
    ASSERT_TRUE(t.connect(node.tls_port)) << t.error();
}

TEST(StratumTlsRate, AHandshakeBoundRefusalSpendsNoToken)
{
    TempDir dir;
    const auto a = make_cert(dir.path, "localhost", 1);
    TlsNode node;
    ASSERT_TRUE(node.start(a, {}, core::kStratumTlsHandshakeTimeout, [](auto& o) {
        o.accept_rate = 0;
        o.accept_rate_per_ip = 0.05;   // one token per 20 s: none come back here
        o.accept_burst_per_ip = 3;
        o.max_handshakes_per_ip = 1;
        o.evict_after = std::chrono::seconds(60);
        o.first_byte_timeout = std::chrono::seconds(10);
    }));
    auto silent = std::make_unique<RawClient>();   // token 1, holds the slot
    ASSERT_TRUE(silent->connect("127.0.0.1", node.tls_port));
    ASSERT_TRUE(wait_until([&] { return node.stratum->get_tls_handshakes_in_progress() == 1; }));
    {
        RawClient refused;   // the slot is taken: closed, no token spent
        ASSERT_TRUE(refused.connect("127.0.0.1", node.tls_port));
        refused.read_all(2000ms);
        EXPECT_TRUE(refused.closed());
        EXPECT_EQ(node.stratum->get_tls_refused_handshakes(), 1u);
    }
    silent.reset();
    ASSERT_TRUE(wait_until([&] { return node.stratum->get_tls_handshakes_in_progress() == 0; }));
    TlsClient c1(a.cert);   // token 2
    ASSERT_TRUE(c1.connect(node.tls_port)) << c1.error();
    TlsClient c2(a.cert);   // token 3 (gone if the refusal had spent one)
    ASSERT_TRUE(c2.connect(node.tls_port)) << c2.error();
    TlsClient c3(a.cert);
    EXPECT_FALSE(c3.connect(node.tls_port));
    EXPECT_TRUE(wait_until([&] { return node.stratum->get_tls_refused_rate_per_ip() == 1; }));
}

TEST(StratumTlsReload, TwoListenersRestoreTheDispositionWhenTheLastCloses)
{
#ifdef _WIN32
    GTEST_SKIP() << "no SIGHUP";
#else
    struct sigaction ignore {};
    ignore.sa_handler = SIG_IGN;
    sigemptyset(&ignore.sa_mask);
    struct sigaction before {};
    ASSERT_EQ(::sigaction(SIGHUP, &ignore, &before), 0);
    {
        TempDir dir;
        const auto a = make_cert(dir.path, "localhost", 1);
        TlsNode one, two;
        ASSERT_TRUE(one.start(a));
        ASSERT_TRUE(two.start(a));
        struct sigaction now {};
        one.on_io([&] { one.stratum->stop(); return 0; });
        ASSERT_EQ(::sigaction(SIGHUP, nullptr, &now), 0);
        EXPECT_NE(now.sa_handler, SIG_IGN);   // two still holds it
        const uint64_t reloads = two.stratum->get_tls_reloads();
        ASSERT_EQ(std::raise(SIGHUP), 0);
        EXPECT_TRUE(wait_until([&] { return two.stratum->get_tls_reloads() == reloads + 1; }));
        two.on_io([&] { two.stratum->stop(); return 0; });
        ASSERT_EQ(::sigaction(SIGHUP, nullptr, &now), 0);
        EXPECT_EQ(now.sa_handler, SIG_IGN);   // the last one closed: back
    }
    ASSERT_EQ(::sigaction(SIGHUP, &before, nullptr), 0);
#endif
}

TEST(StratumTlsRate, ABurstOfZeroIsNoPerAddressLimit)
{
    TempDir dir;
    const auto a = make_cert(dir.path, "localhost", 1);
    core::StratumTlsSettings set{"1", a.cert, a.key};
    std::string err;
    ASSERT_TRUE(core::parse_stratum_tls_limit_flag("--stratum-tls-burst-per-ip", "0", set, err)) << err;
    EXPECT_EQ(set.burst_per_ip, 0u);
    TlsNode node;
    ASSERT_TRUE(node.start(a, {}, core::kStratumTlsHandshakeTimeout, [&](auto& o) {
        o.accept_rate_per_ip = 0.05;   // would allow one in 20 s
        o.accept_burst_per_ip = static_cast<double>(set.burst_per_ip);
    }));
    for (int i = 0; i < 6; ++i) {
        TlsClient c(a.cert);
        ASSERT_TRUE(c.connect(node.tls_port)) << i << ": " << c.error();
    }
    EXPECT_EQ(node.stratum->get_tls_refused_rate_per_ip(), 0u);
}

TEST(StratumTlsRate, NoEvictionForANewcomerAdmitWouldRefuse)
{
    TempDir dir;
    const auto a = make_cert(dir.path, "localhost", 1);
    core::stratum::StratumConfig cfg;
    cfg.max_stratum_connections_per_ip = 2;   // the two holders fill it
    TlsNode node;
    ASSERT_TRUE(node.start(a, cfg, core::kStratumTlsHandshakeTimeout, [](auto& o) {
        o.max_handshakes = 2;
        o.max_handshakes_per_ip = 0;
        o.evict_after = std::chrono::milliseconds(200);
        o.first_byte_timeout = std::chrono::seconds(10);
    }));
    RawClient silent1, silent2;
    ASSERT_TRUE(silent1.connect("127.0.0.1", node.tls_port));
    ASSERT_TRUE(silent2.connect("127.0.0.1", node.tls_port));
    ASSERT_TRUE(wait_until([&] { return node.stratum->get_tls_handshakes_in_progress() == 2; }));
    std::this_thread::sleep_for(400ms);
    {
        TlsClient c(a.cert);   // the per-IP cap would refuse it: nobody is evicted
        EXPECT_FALSE(c.connect(node.tls_port));
    }
    EXPECT_EQ(node.stratum->get_tls_handshake_evictions(), 0u);
    EXPECT_EQ(node.stratum->get_tls_refused_handshakes(), 1u);
    EXPECT_TRUE(silent1.silent_for(200ms));
    EXPECT_TRUE(silent2.silent_for(200ms));
}

TEST(StratumTlsRate, NoEvictionWhileDraining)
{
    TempDir dir;
    const auto a = make_cert(dir.path, "localhost", 1);
    TlsNode node;
    ASSERT_TRUE(node.start(a, {}, core::kStratumTlsHandshakeTimeout, [](auto& o) {
        o.max_handshakes = 2;
        o.max_handshakes_per_ip = 0;
        o.evict_after = std::chrono::milliseconds(200);
        o.first_byte_timeout = std::chrono::seconds(10);
    }));
    RawClient silent1, silent2;
    ASSERT_TRUE(silent1.connect("127.0.0.1", node.tls_port));
    ASSERT_TRUE(silent2.connect("127.0.0.1", node.tls_port));
    ASSERT_TRUE(wait_until([&] { return node.stratum->get_tls_handshakes_in_progress() == 2; }));
    std::this_thread::sleep_for(400ms);
    node.stratum->set_accepting(false);
    {
        TlsClient c(a.cert);
        EXPECT_FALSE(c.connect(node.tls_port));
    }
    EXPECT_EQ(node.stratum->get_tls_handshake_evictions(), 0u);
    EXPECT_TRUE(silent1.silent_for(200ms));
    EXPECT_TRUE(silent2.silent_for(200ms));
    node.stratum->set_accepting(true);   // accepting again: the oldest makes room
    TlsClient c(a.cert);
    ASSERT_TRUE(c.connect(node.tls_port)) << c.error();
    EXPECT_EQ(node.stratum->get_tls_handshake_evictions(), 1u);
}

#endif  // C2POOL_STRATUM_TLS
