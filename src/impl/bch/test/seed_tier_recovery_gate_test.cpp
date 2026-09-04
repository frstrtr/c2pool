// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// bch::coin::SeedTier RECOVERY GATE -- IMPLEMENTED != PROVEN.
//
// The pure seed_tier_kat_test pins the tier-assembly LOGIC (build_ladder /
// should_run_ladder / CandidateWalk / EmergencyReArm) but never drives the
// ASYNC resolve_candidates() / http_fetch_coin_peers() I/O path, and the five
// test_phase*_live.cpp harnesses are ci-allowlist-exempt (excluded by
// ctest --exclude-regex 'LiveTest\.', GTEST_SKIP() on unreachable, dial a
// hardcoded LAN IP) -- so NOTHING actually EXERCISES the discovery ladder
// recovering across its tiers. This gate closes that hole.
//
// It drives the real SeedTier::resolve_candidates() over a live boost::asio
// io_context and proves the ladder RECOVERS through each tier -- DNS tier -> ,
// when dead, the fixed tier -> , when that is also dead, the HTTP-peer tier --
// with EACH tier exercised as the actual candidate SOURCE and EACH failure arm
// proven by NEGATIVE CONTROL: break the tier, and the outcome MUST change
// (either recovery falls through to the next tier, or -- when the last tier is
// broken -- there is NO phantom recovery and the ladder yields empty). Every
// endpoint is 127.0.0.1 loopback (a localhost DNS resolve + an in-process
// loopback HTTP stub + a closed loopback port), so the gate is fully
// network-free and deterministic under CI, ASan and UBSan.
//
// Harness: plain int main() + assert-style CHECK (CTest treats exit 0 as PASS),
// matching the sibling bch tests. Own coin tree only (src/impl/bch/**); no
// core / bitcoin_family / other-coin surface.
// ---------------------------------------------------------------------------

#include <array>
#include <atomic>
#include <cstdint>
#include <iostream>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include <boost/asio.hpp>
#include <boost/asio/ip/tcp.hpp>

#include "../coin/seed_tier.hpp"
#include <core/netaddress.hpp>

using bch::coin::SeedTier;
using boost::asio::ip::tcp;

// ── plain-main CHECK harness (no GTest in the bch tree) ────────────────────
static int g_failures = 0;
#define CHECK(cond)                                                            \
    do {                                                                       \
        if (!(cond)) {                                                         \
            ++g_failures;                                                      \
            std::cerr << "  CHECK FAILED @L" << __LINE__ << ": " #cond "\n";   \
        }                                                                      \
    } while (0)

static bool contains(const std::vector<NetService>& v, const NetService& n)
{
    for (const auto& e : v) if (e == n) return true;
    return false;
}

// ── Loopback HTTP stub: serves one /api/coin_peers JSON body per connection ──
// Own io_context + async_accept; the destructor stops the loop and joins, so
// no detached thread survives past the test (clean under LeakSanitizer).
class StubHttpServer
{
public:
    explicit StubHttpServer(std::string json_body)
        : m_body(std::move(json_body))
        , m_acceptor(m_ioc, tcp::endpoint(
              boost::asio::ip::make_address("127.0.0.1"), 0))
    {
        m_port = m_acceptor.local_endpoint().port();
        do_accept();
        m_thread = std::thread([this] { m_ioc.run(); });
    }

    ~StubHttpServer()
    {
        boost::asio::post(m_ioc, [this] {
            boost::system::error_code ec;
            m_acceptor.close(ec);
        });
        m_ioc.stop();
        if (m_thread.joinable()) m_thread.join();
    }

    uint16_t port() const { return m_port; }

private:
    void do_accept()
    {
        m_acceptor.async_accept(
            [this](boost::system::error_code ec, tcp::socket sock) {
                if (ec) return;                       // acceptor closed -> stop
                auto s = std::make_shared<tcp::socket>(std::move(sock));
                auto req = std::make_shared<std::array<char, 2048>>();
                s->async_read_some(boost::asio::buffer(*req),
                    [this, s, req](boost::system::error_code, std::size_t) {
                        auto resp = std::make_shared<std::string>(
                            "HTTP/1.0 200 OK\r\n"
                            "Content-Type: application/json\r\n"
                            "Connection: close\r\n\r\n" + m_body);
                        boost::asio::async_write(*s, boost::asio::buffer(*resp),
                            [s, resp](boost::system::error_code, std::size_t) {
                                // s released here -> socket closes -> client EOF
                            });
                    });
                do_accept();                          // keep serving
            });
    }

    boost::asio::io_context m_ioc;
    std::string             m_body;
    tcp::acceptor           m_acceptor;
    uint16_t                m_port{0};
    std::thread             m_thread;
};

// Acquire a loopback port, then release it -> connections to it are refused.
static uint16_t closed_loopback_port()
{
    boost::asio::io_context ioc;
    tcp::acceptor acc(ioc, tcp::endpoint(
        boost::asio::ip::make_address("127.0.0.1"), 0));
    uint16_t p = acc.local_endpoint().port();
    acc.close();
    return p;
}

// Drive the real async ladder to completion and return its ordered candidates.
static std::vector<NetService> run_ladder(SeedTier& tier)
{
    boost::asio::io_context ioc;
    auto work = boost::asio::make_work_guard(ioc);
    std::vector<NetService> got;
    std::atomic<bool> done{false};

    tier.resolve_candidates(ioc, [&](std::vector<NetService> c) {
        got  = std::move(c);
        done = true;
        work.reset();               // let ioc.run() drain and return
    });

    ioc.run();
    CHECK(done.load());             // the ladder MUST always deliver a verdict
    return got;
}

int main()
{
    std::cout << "[bch_seed_tier_recovery_gate] driving live resolve_candidates "
                 "ladder recovery + negative controls\n";

    // Distinct, documentation-range (RFC 5737) sentinels -- never routable, so
    // a match can only come from the tier under test, not an ambient peer.
    const NetService FIXED_SEED = NetService(std::string("203.0.113.7"),
                                             static_cast<uint16_t>(8333));
    const NetService HTTP_PEER  = NetService(std::string("198.51.100.9"),
                                             static_cast<uint16_t>(8333));
    const std::string HTTP_BODY = "{\"bch\":[\"198.51.100.9:8333\"]}";

    // ═══ TIER 1 -- DNS as the recovery SOURCE ═══════════════════════════════
    // localhost resolves on the loopback (no external network); the DNS tier
    // must win as primary, so the fixed sentinel is NOT substituted in.
    {
        SeedTier t;
        t.set_dns_seeds({{"localhost", 8333}});
        t.set_fixed_seeds({FIXED_SEED});
        auto out = run_ladder(t);
        std::cout << "  [T1 dns-live] " << out.size() << " candidate(s)\n";
        CHECK(!out.empty());                    // DNS tier recovered peers
        CHECK(!contains(out, FIXED_SEED));      // fixed did NOT substitute
    }
    // NEGATIVE CONTROL 1 -- break the DNS tier (resolves nothing). The SAME
    // config must now change outcome: the fixed sentinel MUST appear (proving
    // the DNS tier above was the load-bearing source, not the fixed tier).
    {
        SeedTier t;
        t.set_dns_seeds({});                    // DNS tier broken
        t.set_fixed_seeds({FIXED_SEED});
        auto out = run_ladder(t);
        std::cout << "  [T1-neg dns-dead] " << out.size() << " candidate(s)\n";
        CHECK(contains(out, FIXED_SEED));       // recovery fell through to fixed
    }

    // ═══ TIER 2 -- fixed as the recovery SOURCE (DNS dead) ══════════════════
    // DNS dead -> fixed substitutes as primary; because primary is non-empty
    // the HTTP tier is correctly NOT consulted (its peer must be absent).
    {
        StubHttpServer stub(HTTP_BODY);
        SeedTier t;
        t.set_dns_seeds({});
        t.set_fixed_seeds({FIXED_SEED});
        t.set_http_peer_seeds({{"127.0.0.1", stub.port()}});
        auto out = run_ladder(t);
        std::cout << "  [T2 fixed-source] " << out.size() << " candidate(s)\n";
        CHECK(!out.empty());
        CHECK(out.front() == FIXED_SEED);       // fixed tier recovered
        CHECK(!contains(out, HTTP_PEER));       // http tier deferred, not fired
    }
    // NEGATIVE CONTROL 2 -- break the fixed tier (empty). Outcome MUST change:
    // recovery falls through to the live HTTP stub (fixed was load-bearing).
    {
        StubHttpServer stub(HTTP_BODY);
        SeedTier t;
        t.set_dns_seeds({});
        t.set_fixed_seeds({});                  // fixed tier broken
        t.set_http_peer_seeds({{"127.0.0.1", stub.port()}});
        auto out = run_ladder(t);
        std::cout << "  [T2-neg fixed-dead] " << out.size() << " candidate(s)\n";
        CHECK(contains(out, HTTP_PEER));        // fell through to http tier
    }

    // ═══ TIER 3 -- HTTP-peer as the recovery SOURCE (DNS + fixed dead) ══════
    // The real http_fetch_coin_peers() GET hits the loopback stub and parses
    // the "bch" peer array -- the genuine tier-3 recovery path, end to end.
    {
        StubHttpServer stub(HTTP_BODY);
        SeedTier t;
        t.set_dns_seeds({});
        t.set_fixed_seeds({});
        t.set_http_peer_seeds({{"127.0.0.1", stub.port()}});
        auto out = run_ladder(t);
        std::cout << "  [T3 http-source] " << out.size() << " candidate(s)\n";
        CHECK(out.size() == 1);
        CHECK(out.front() == HTTP_PEER);        // http tier recovered
    }
    // NEGATIVE CONTROL 3 -- break the HTTP tier (closed loopback port ->
    // connection refused). This is the LAST tier: there is no lower fallback,
    // so recovery MUST yield EMPTY -- no phantom peer is ever fabricated. A
    // ladder that invented a candidate here would (correctly) RED this gate.
    {
        uint16_t dead = closed_loopback_port();
        SeedTier t;
        t.set_dns_seeds({});
        t.set_fixed_seeds({});
        t.set_http_peer_seeds({{"127.0.0.1", dead}});
        auto out = run_ladder(t);
        std::cout << "  [T3-neg http-dead] " << out.size() << " candidate(s)\n";
        CHECK(out.empty());                     // no recovery, no phantom peer
    }

    if (g_failures == 0) {
        std::cout << "[bch_seed_tier_recovery_gate] PASS -- all 3 tiers "
                     "recovered + all 3 negative controls held\n";
        return 0;
    }
    std::cerr << "[bch_seed_tier_recovery_gate] FAIL -- " << g_failures
              << " check(s) failed\n";
    return 1;
}
