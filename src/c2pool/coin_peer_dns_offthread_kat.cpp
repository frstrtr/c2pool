// SPDX-License-Identifier: AGPL-3.0-or-later
// KAT: a DNS seed round never blocks the io_context.
//
// Field crash (2026-11-15): a freshly started c2pool-ltc node aborted twice on
// "EVENT LOOP FREEZE DETECTED ... io_context unresponsive for 40 seconds". With
// no saved peers the LTC and DOGE broadcasters sat below min_peers, the
// emergency re-arm fired, and each peer manager resolved its DNS seeds with
// DnsSeeder::resolve_all_sync() inside the timer handler: one blocking
// getaddrinfo() after another, ~5 s per dead seed on that host.
//
// The fake resolver is getaddrinfo() itself, interposed below: hosts under
// .dns-kat.invalid answer after a delay, fail (NXDOMAIN) after a delay, or hang
// past the round's timeout; every other host goes to the real resolver. The
// production lookup path is exercised unchanged, so this file builds and runs
// on master too, where it fails: the io thread stalls for the sum of the delays.
//
// Every coin's peer manager copy is checked (merged LTC/DOGE/NMC, BTC, BCH,
// DGB, DASH, BIP110), one mode per ctest entry:
//   start      start() runs inside an io handler; a 100 ms timer must keep its
//              cadence (no gap > 1 s) and the seeds' peers must be added once
//              the round completes, without the hung seed's.
//   emergency  the emergency re-arm (60 s floor) fires the round from its timer
//              handler; same cadence and peer checks.
//   preloop    start() before the event loop runs waits for the round, so the
//              peers are there when it returns, but in parallel: about one
//              seed's delay, not the sum, and at most the round timeout.
//   stop       a round in flight when the manager is stopped or destroyed is
//              never delivered: stop()/destroy 500 ms into a round; and a round
//              whose delivery is already queued on the io_context when start()
//              runs again and the manager is stopped or destroyed. A stopped
//              manager must have no peers; a delivery to a destroyed one is a
//              heap-use-after-free (run it under ASan to see that leg fail).
// Linux only (ELF symbol preemption + dlsym(RTLD_NEXT)).

#include <boost/asio.hpp>

#include <c2pool/merged/coin_peer_manager.hpp>
#include <impl/bch/coin/coin_peer_manager.hpp>
#include <impl/bip110/coin/coin_peer_manager.hpp>
#include <impl/btc/coin/coin_peer_manager.hpp>
#include <impl/dash/coin/coin_peer_manager.hpp>
#include <impl/dgb/coin/coin_peer_manager.hpp>

#include <arpa/inet.h>
#include <dlfcn.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <functional>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <thread>
#include <vector>

using Clock = std::chrono::steady_clock;
using std::chrono::milliseconds;

namespace {

// ── Fake seeds, served by the getaddrinfo() interposer ──────────────────────
constexpr int kSlowMs  = 2000;    // a slow seed, or a slow NXDOMAIN
constexpr int kStuckMs = 12000;   // a seed that hangs past the round timeout
// ParallelSeedResolver::kDefaultSeedTimeout, spelled out so this file also
// builds on master (where the KAT must fail).
constexpr int kRoundTimeoutMs = 10000;

struct FakeSeed
{
    const char* host;
    int delay_ms;
    const char* ip;   // nullptr: NXDOMAIN
};

constexpr FakeSeed kFakeSeeds[] = {
    {"good-a.dns-kat.invalid",   kSlowMs,  "11.1.1.1"},
    {"good-b.dns-kat.invalid",   kSlowMs,  "12.2.2.2"},
    {"nxdomain.dns-kat.invalid", kSlowMs,  nullptr},
    {"stuck.dns-kat.invalid",    kStuckMs, "13.3.3.3"},
};

const FakeSeed* find_fake(const char* host)
{
    if (!host) return nullptr;
    for (const auto& f : kFakeSeeds)
        if (std::strcmp(f.host, host) == 0) return &f;
    return nullptr;
}

// One allocation per answer: the addrinfo first, so freeing it frees both.
struct FakeAnswer
{
    addrinfo ai;
    sockaddr_in sin;
};

// Heap-allocated and never freed: a hung worker may return after main().
std::mutex* g_answers_mutex = new std::mutex;
std::set<addrinfo*>* g_answers = new std::set<addrinfo*>;

} // namespace

extern "C" int getaddrinfo(const char* node, const char* service,
                           const struct addrinfo* hints, struct addrinfo** res)
{
    const FakeSeed* fake = find_fake(node);
    if (!fake) {
        using Fn = int (*)(const char*, const char*, const struct addrinfo*, struct addrinfo**);
        static Fn real = reinterpret_cast<Fn>(dlsym(RTLD_NEXT, "getaddrinfo"));
        return real ? real(node, service, hints, res) : EAI_FAIL;
    }
    std::this_thread::sleep_for(milliseconds(fake->delay_ms));
    if (!fake->ip) return EAI_NONAME;

    auto* answer = static_cast<FakeAnswer*>(std::calloc(1, sizeof(FakeAnswer)));
    if (!answer) return EAI_MEMORY;
    answer->sin.sin_family = AF_INET;
    answer->sin.sin_port = htons(static_cast<uint16_t>(service ? std::atoi(service) : 0));
    inet_pton(AF_INET, fake->ip, &answer->sin.sin_addr);
    answer->ai.ai_family = AF_INET;
    answer->ai.ai_socktype = hints && hints->ai_socktype ? hints->ai_socktype : SOCK_STREAM;
    answer->ai.ai_protocol = hints ? hints->ai_protocol : 0;
    answer->ai.ai_addrlen = sizeof(sockaddr_in);
    answer->ai.ai_addr = reinterpret_cast<sockaddr*>(&answer->sin);
    {
        std::lock_guard<std::mutex> lock(*g_answers_mutex);
        g_answers->insert(&answer->ai);
    }
    *res = &answer->ai;
    return 0;
}

extern "C" void freeaddrinfo(struct addrinfo* ai) noexcept
{
    {
        std::lock_guard<std::mutex> lock(*g_answers_mutex);
        if (g_answers->erase(ai)) {
            std::free(ai);
            return;
        }
    }
    using Fn = void (*)(struct addrinfo*);
    static Fn real = reinterpret_cast<Fn>(dlsym(RTLD_NEXT, "freeaddrinfo"));
    if (real) real(ai);
}

namespace {

int g_fail = 0;
#define CHECK(cond, ...) do { if (!(cond)) { ++g_fail; \
    std::printf("FAIL %s:%d  %s  ", __FILE__, __LINE__, #cond); \
    std::printf(__VA_ARGS__); std::printf("\n"); std::fflush(stdout); } } while (0)

std::vector<c2pool::dns::DnsSeed> seeds(bool with_stuck)
{
    std::vector<c2pool::dns::DnsSeed> out;
    for (const auto& f : kFakeSeeds)
        if (with_stuck || f.delay_ms != kStuckMs)
            out.push_back({f.host, 9333});
    return out;
}

/// One coin's peer manager behind a common face.
struct Subject
{
    std::string name;
    std::shared_ptr<void> owner;
    std::function<void(std::vector<c2pool::dns::DnsSeed>)> set_dns_seeds;
    std::function<void()> start;
    std::function<void()> stop;
    std::function<void()> arm_emergency;
    std::function<size_t()> peer_count;
};

std::filesystem::path g_scratch;

/// `tag` keeps each scenario's peer DB apart (a saved DB would pre-load peers).
template <class Mgr, class Cfg>
Subject make_subject(boost::asio::io_context& ioc, const std::string& name, const std::string& tag)
{
    const auto dir = g_scratch / tag / name;
    std::filesystem::create_directories(dir);
    Cfg cfg;
    auto mgr = std::make_shared<Mgr>(ioc, name, dir.string(), cfg);
    Mgr* m = mgr.get();
    Subject s;
    s.name = name;
    s.owner = mgr;
    s.set_dns_seeds = [m](std::vector<c2pool::dns::DnsSeed> v) { m->set_dns_seeds(std::move(v)); };
    s.start = [m] { m->start(); };
    s.stop = [m] { m->stop(); };
    s.arm_emergency = [m] { m->arm_emergency_fallbacks(); };
    s.peer_count = [m] { return static_cast<size_t>(m->peer_count()); };
    return s;
}

std::vector<Subject> make_subjects(boost::asio::io_context& ioc, const std::string& tag)
{
    std::vector<Subject> v;
    v.push_back(make_subject<c2pool::merged::CoinPeerManager, c2pool::merged::PeerManagerConfig>(ioc, "LTC", tag));
    v.push_back(make_subject<btc::coin::BtcCoinPeerManager, btc::coin::BtcPeerManagerConfig>(ioc, "BTC", tag));
    v.push_back(make_subject<bch::coin::BchCoinPeerManager, bch::coin::BchPeerManagerConfig>(ioc, "BCH", tag));
    v.push_back(make_subject<dgb::coin::DgbCoinPeerManager, dgb::coin::DgbPeerManagerConfig>(ioc, "DGB", tag));
    v.push_back(make_subject<dash::coin::DashCoinPeerManager, dash::coin::DashPeerManagerConfig>(ioc, "DASH", tag));
    v.push_back(make_subject<bip110::coin::BtcCoinPeerManager, bip110::coin::BtcPeerManagerConfig>(ioc, "BIP110", tag));
    return v;
}

/// stop() and destroy every manager (cancels any round still in flight).
void destroy(std::vector<Subject>& v)
{
    for (auto& s : v) s.owner.reset();
}

/// A 100 ms timer on the io_context; the worst gap between two fires is how
/// long the event loop was unresponsive.
class Cadence
{
public:
    explicit Cadence(boost::asio::io_context& ioc) : m_timer(ioc) {}

    void begin()
    {
        m_last = Clock::now();
        arm();
    }
    /// Stop, counting the time since the last fire too: a stall that ends
    /// the run before the timer fires again is still a stall.
    void end()
    {
        m_worst = std::max(m_worst, std::chrono::duration_cast<milliseconds>(Clock::now() - m_last));
        m_timer.cancel();
    }
    long long worst_ms() const { return m_worst.count(); }

private:
    void arm()
    {
        m_timer.expires_after(milliseconds(100));
        m_timer.async_wait([this](const boost::system::error_code& ec) {
            if (ec) return;
            const auto now = Clock::now();
            m_worst = std::max(m_worst, std::chrono::duration_cast<milliseconds>(now - m_last));
            m_last = now;
            arm();
        });
    }

    boost::asio::steady_timer m_timer;
    Clock::time_point m_last;
    milliseconds m_worst{0};
};

long long since_ms(Clock::time_point t)
{
    return std::chrono::duration_cast<milliseconds>(Clock::now() - t).count();
}

/// Run the io_context until pred() holds or `limit` passes. A context that
/// ran out of work is stopped and runs nothing more until restart(): restart
/// it, or handlers posted later (a round's delivery) would never run.
template <class Pred>
void run_until(boost::asio::io_context& ioc, Pred pred, Clock::time_point limit)
{
    while (!pred() && Clock::now() < limit) {
        if (ioc.stopped()) ioc.restart();
        if (ioc.run_one_for(milliseconds(50)) == 0)
            std::this_thread::sleep_for(milliseconds(10));
    }
}

bool all_have_peers(const std::vector<Subject>& v)
{
    for (const auto& s : v)
        if (s.peer_count() < 2) return false;
    return true;
}

/// The two answering seeds' peers are in; the NXDOMAIN and hung seeds' are not.
void check_peers(const std::vector<Subject>& v, const char* mode)
{
    for (const auto& s : v)
        CHECK(s.peer_count() == 2, "[%s/%s] peer_count=%zu (want the 2 answering seeds' peers,"
              " not the hung seed's)", mode, s.name.c_str(), s.peer_count());
}

int mode_start(boost::asio::io_context& ioc)
{
    auto subjects = make_subjects(ioc, "start");
    for (auto& s : subjects)
        s.set_dns_seeds(seeds(/*with_stuck=*/true));

    Cadence cadence(ioc);
    const auto t0 = Clock::now();
    cadence.begin();
    for (auto& s : subjects)
        boost::asio::post(ioc, [&s] { s.start(); });   // start() inside an io handler

    run_until(ioc, [&] { return all_have_peers(subjects); }, t0 + std::chrono::seconds(300));
    const long long peers_ms = since_ms(t0);
    // Keep running past the hung seed's answer: it must be dropped, and the
    // loop must stay responsive while that worker finishes.
    run_until(ioc, [] { return false; },
              std::max(t0 + milliseconds(kStuckMs + 1500), Clock::now() + milliseconds(1000)));
    cadence.end();

    std::printf("[start] peers after %lld ms, worst io gap %lld ms\n", peers_ms, cadence.worst_ms());
    CHECK(cadence.worst_ms() < 1000, "[start] io_context stalled %lld ms (DNS on the io thread)",
          cadence.worst_ms());
    CHECK(peers_ms <= kRoundTimeoutMs + 2000, "[start] peers took %lld ms (round timeout %d ms)",
          peers_ms, kRoundTimeoutMs);
    check_peers(subjects, "start");
    destroy(subjects);
    return 0;
}

int mode_emergency(boost::asio::io_context& ioc)
{
    auto subjects = make_subjects(ioc, "emergency");
    for (auto& s : subjects) {
        s.start();                                // no DNS seeds yet: nothing resolves here
        s.set_dns_seeds(seeds(/*with_stuck=*/true));
        s.arm_emergency();                        // fires after the 60 s floor
    }

    Cadence cadence(ioc);
    const auto t0 = Clock::now();
    cadence.begin();
    run_until(ioc, [&] { return all_have_peers(subjects); }, t0 + std::chrono::seconds(400));
    const long long peers_ms = since_ms(t0);
    run_until(ioc, [] { return false; }, Clock::now() + milliseconds(kStuckMs - kRoundTimeoutMs + 1500));
    cadence.end();

    std::printf("[emergency] peers after %lld ms, worst io gap %lld ms\n", peers_ms, cadence.worst_ms());
    CHECK(cadence.worst_ms() < 1000, "[emergency] io_context stalled %lld ms (DNS in the re-arm"
          " timer handler)", cadence.worst_ms());
    CHECK(peers_ms <= 60000 + kRoundTimeoutMs + 3000, "[emergency] peers took %lld ms", peers_ms);
    check_peers(subjects, "emergency");
    destroy(subjects);
    return 0;
}

int mode_preloop(boost::asio::io_context& ioc)
{
    // Every copy: three seeds that each take kSlowMs, resolved in parallel.
    auto subjects = make_subjects(ioc, "preloop");
    for (auto& s : subjects) {
        s.set_dns_seeds(seeds(/*with_stuck=*/false));
        const auto t = Clock::now();
        s.start();
        const long long ms = since_ms(t);
        std::printf("[preloop/%s] start() took %lld ms, %zu peers\n", s.name.c_str(), ms, s.peer_count());
        CHECK(ms < kSlowMs + 1500, "[preloop/%s] start() took %lld ms (seeds not resolved in parallel)",
              s.name.c_str(), ms);
        CHECK(s.peer_count() == 2, "[preloop/%s] peer_count=%zu right after start()",
              s.name.c_str(), s.peer_count());
    }
    destroy(subjects);

    // A hung seed holds start-up for the round timeout at most.
    std::vector<Subject> hung;
    hung.push_back(make_subject<c2pool::merged::CoinPeerManager, c2pool::merged::PeerManagerConfig>(
        ioc, "LTC", "preloop-hung"));
    auto& ltc = hung.front();
    ltc.set_dns_seeds(seeds(/*with_stuck=*/true));
    const auto t = Clock::now();
    ltc.start();
    const long long ms = since_ms(t);
    std::printf("[preloop/hung] start() took %lld ms, %zu peers\n", ms, ltc.peer_count());
    CHECK(ms < kRoundTimeoutMs + 1500, "[preloop/hung] start() took %lld ms (round timeout %d ms)",
          ms, kRoundTimeoutMs);
    CHECK(ltc.peer_count() == 2, "[preloop/hung] peer_count=%zu (want 2, not the hung seed's)",
          ltc.peer_count());
    destroy(hung);
    return 0;
}

int mode_stop(boost::asio::io_context& ioc)
{
    const auto slow = seeds(/*with_stuck=*/false);   // two answers and an NXDOMAIN, kSlowMs each

    // (a) stop() and (b) destroy, 500 ms into a round started from a handler;
    // the loop runs on past the answers. The control manager is left running
    // and must get its peers: the deliveries did run.
    auto stopped = make_subjects(ioc, "stop-a");
    auto destroyed = make_subjects(ioc, "stop-b");
    std::vector<Subject> control;
    control.push_back(make_subject<c2pool::merged::CoinPeerManager, c2pool::merged::PeerManagerConfig>(
        ioc, "LTC", "stop-control-ab"));
    for (auto* v : {&stopped, &destroyed, &control})
        for (auto& s : *v) {
            s.set_dns_seeds(slow);
            boost::asio::post(ioc, [&s] { s.start(); });
        }
    boost::asio::steady_timer at500(ioc);
    at500.expires_after(milliseconds(500));
    at500.async_wait([&](const boost::system::error_code&) {
        for (auto& s : stopped) s.stop();
        destroy(destroyed);
    });
    run_until(ioc, [] { return false; }, Clock::now() + milliseconds(kSlowMs + 1500));
    for (auto& s : stopped)
        CHECK(s.peer_count() == 0, "[stop/%s] peer_count=%zu: the round was delivered after stop()",
              s.name.c_str(), s.peer_count());
    CHECK(control.front().peer_count() == 2, "[stop/control] peer_count=%zu: the running manager's"
          " round was not delivered (the test ran nothing)", control.front().peer_count());
    destroy(stopped);
    destroy(control);

    // (c) stop() and (d) destroy while a finished round's delivery is queued:
    // a handler holds the io thread past the answers, then calls start() again
    // (a second round, if the resolver takes one) and stops or destroys.
    auto stale_stopped = make_subjects(ioc, "stop-c");
    auto stale_destroyed = make_subjects(ioc, "stop-d");
    control.clear();
    control.push_back(make_subject<c2pool::merged::CoinPeerManager, c2pool::merged::PeerManagerConfig>(
        ioc, "LTC", "stop-control-cd"));
    for (auto* v : {&stale_stopped, &stale_destroyed, &control})
        for (auto& s : *v) {
            s.set_dns_seeds(slow);
            boost::asio::post(ioc, [&s] { s.start(); });
        }
    boost::asio::post(ioc, [&] {
        std::this_thread::sleep_for(milliseconds(kSlowMs + 1000));  // deliveries get queued behind us
        for (auto& s : stale_stopped) { s.start(); s.stop(); }
        for (auto& s : stale_destroyed) { s.start(); s.owner.reset(); }
    });
    run_until(ioc, [] { return false; }, Clock::now() + milliseconds(2 * kSlowMs + 2500));
    for (auto& s : stale_stopped)
        CHECK(s.peer_count() == 0, "[stop/stale/%s] peer_count=%zu: a queued delivery reached the"
              " stopped manager", s.name.c_str(), s.peer_count());
    CHECK(control.front().peer_count() == 2, "[stop/stale/control] peer_count=%zu: the queued"
          " deliveries never ran (the test ran nothing)", control.front().peer_count());
    destroy(stale_stopped);
    destroy(control);
    std::printf("[stop] no round delivered after stop() or destruction\n");
    return 0;
}

} // namespace

int main(int argc, char** argv)
{
    const std::string mode = argc > 1 ? argv[1] : "";
    g_scratch = std::filesystem::temp_directory_path()
              / ("coin_peer_dns_kat_" + mode + "_" + std::to_string(::getpid()));
    std::filesystem::remove_all(g_scratch);

    boost::asio::io_context ioc;
    if (mode == "start")          mode_start(ioc);
    else if (mode == "emergency") mode_emergency(ioc);
    else if (mode == "preloop")   mode_preloop(ioc);
    else if (mode == "stop")      mode_stop(ioc);
    else {
        std::printf("usage: %s start|emergency|preloop|stop\n", argv[0]);
        return 2;
    }

    std::error_code ec;
    std::filesystem::remove_all(g_scratch, ec);
    if (g_fail == 0) std::printf("coin_peer_dns_offthread_kat %s PASS\n", mode.c_str());
    else             std::printf("coin_peer_dns_offthread_kat %s FAIL (%d)\n", mode.c_str(), g_fail);
    std::fflush(stdout);
    // A hung fake seed's worker may still be sleeping: skip static destruction
    // rather than race it.
    std::_Exit(g_fail == 0 ? 0 : 1);
}
