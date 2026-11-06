// SPDX-License-Identifier: AGPL-3.0-or-later
//
// The process's fd limit split between the embedded node's LevelDB stores
// and its sockets (doge::coin::FdPlan, main_ltc.cpp), and the startup raise
// of the soft limit (core::raise_nofile_limit_report). Pinned here:
//   * at every limit the plan admits, the stores' ceiling, the reserve and
//     the socket caps fit in it, every cap keeps its floor and none exceeds
//     what was configured;
//   * at 65536 (and an unknown or unlimited limit) nothing is mapped or
//     lowered: the shares are StoreFds' as before;
//   * at 256 (macOS's default soft limit, where the raise is refused) the
//     stores' tables are mapped and the caps lowered;
//   * a limit below the floors does not fit (the node refuses to start);
//   * the raise never lowers the limit and stops at the hard limit;
//   * at a 256 soft limit, the stores main_ltc opens, read and compacted in
//     parallel, beside every peer, stratum and HTTP socket the plan allows
//     (and one refused accept per listener), stay under the limit with no
//     read error and no refused socket.

#include <gtest/gtest.h>

#include <core/core_util.hpp>
#include <core/leveldb_store.hpp>
#include <impl/doge/coin/store_fds.hpp>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <iostream>
#include <memory>
#include <random>
#include <string>
#include <thread>
#include <vector>

#if defined(__linux__)
#include <arpa/inet.h>
#include <dirent.h>
#include <netinet/in.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

using doge::coin::FdPlan;
using doge::coin::FdWants;
using doge::coin::StoreFds;

namespace {

FdWants node_defaults()
{
    FdWants w;   // main_ltc's defaults, with the LTC full set on
    w.ltc_full = true;
    return w;
}

uint64_t floors_of(const FdWants& w)
{
    return std::min(w.ltc_peers, FdPlan::kPeerFloor) + w.merged_chains * std::min(w.merged_peers, FdPlan::kPeerFloor)
         + std::min(w.sharechain_peers, FdPlan::kSharechainFloor)
         + std::min(w.stratum == 0 ? FdPlan::kStratumUnlimited : w.stratum, FdPlan::kStratumFloor)
         + std::min(w.http, FdPlan::kHttpFloor);
}

} // namespace

TEST(LtcFdPlan, CapsFitTheLimitAndKeepTheirFloors)
{
    for (const bool ltc_full : {false, true}) {
        for (uint64_t nofile = 160; nofile <= 8192; nofile += 32) {
            FdWants w = node_defaults();
            w.ltc_full = ltc_full;
            const FdPlan p = FdPlan::make(nofile, w);
            if (!p.fits)
                continue;
            const uint64_t sockets = static_cast<uint64_t>(p.ltc_peers) + w.merged_chains * p.merged_peers
                                   + p.sharechain_peers + p.stratum + p.http;
            EXPECT_EQ(sockets, p.sockets) << nofile;
            EXPECT_LE(p.stores + FdPlan::kReserve + p.sockets, nofile) << nofile;
            EXPECT_GE(p.ltc_peers, FdPlan::kPeerFloor) << nofile;
            EXPECT_LE(p.ltc_peers, w.ltc_peers) << nofile;
            EXPECT_GE(p.merged_peers, FdPlan::kPeerFloor) << nofile;
            EXPECT_LE(p.merged_peers, w.merged_peers) << nofile;
            EXPECT_GE(p.sharechain_peers, FdPlan::kSharechainFloor) << nofile;
            EXPECT_LE(p.sharechain_peers, w.sharechain_peers) << nofile;
            EXPECT_GE(p.stratum, FdPlan::kStratumFloor) << nofile;
            EXPECT_LE(p.stratum, w.stratum) << nofile;
            EXPECT_GE(p.http, FdPlan::kHttpFloor) << nofile;
            if (!p.trimmed) {
                EXPECT_EQ(p.stratum, w.stratum) << nofile;
                EXPECT_GE(p.http, w.http) << nofile;
            }
            // A pread store's share is StoreFds' (the LTC full set's at most).
            if (!p.doge_headers.mmap_reads)
                EXPECT_EQ(p.doge_headers.max_open_files, StoreFds::header_store(nofile)) << nofile;
            if (!p.doge_full.mmap_reads)
                EXPECT_EQ(p.doge_full.max_open_files, StoreFds::full_set(nofile)) << nofile;
        }
    }
    // Every limit from 512 up fits the node's defaults without lowering a cap.
    for (uint64_t nofile = 512; nofile <= 8192; nofile += 32) {
        const FdPlan p = FdPlan::make(nofile, node_defaults());
        EXPECT_TRUE(p.fits) << nofile;
        EXPECT_FALSE(p.trimmed) << nofile;
    }
}

TEST(LtcFdPlan, A65536LimitKeepsTheSharesAndTheCaps)
{
    const FdWants w = node_defaults();
    for (const uint64_t nofile : {uint64_t{4096}, uint64_t{65536}}) {
        const FdPlan p = FdPlan::make(nofile, w);
        EXPECT_TRUE(p.fits);
        EXPECT_FALSE(p.mapped);
        EXPECT_FALSE(p.trimmed);
        EXPECT_EQ(p.doge_headers.max_open_files, StoreFds::header_store(nofile));
        EXPECT_EQ(p.doge_full.max_open_files, StoreFds::full_set(nofile));
        EXPECT_EQ(p.ltc_full.max_open_files, StoreFds::ltc_full_set(nofile).max_open_files);
        EXPECT_FALSE(p.ltc_full.mmap_reads);
        EXPECT_EQ(p.ltc_peers, 20);
        EXPECT_EQ(p.merged_peers, 20);
        EXPECT_EQ(p.sharechain_peers, 30);
        EXPECT_EQ(p.stratum, 100u);
        EXPECT_GT(p.http, w.http) << "what the limit leaves goes to HTTP";
    }
    // Unknown (no RLIMIT_NOFILE) or unlimited: as configured.
    for (const uint64_t nofile : {uint64_t{0}, UINT64_MAX}) {
        const FdPlan p = FdPlan::make(nofile, w);
        EXPECT_TRUE(p.fits);
        EXPECT_FALSE(p.mapped);
        EXPECT_FALSE(p.trimmed);
        EXPECT_EQ(p.doge_headers.max_open_files, StoreFds::header_store(0));
        EXPECT_EQ(p.doge_full.max_open_files, StoreFds::full_set(0));
        EXPECT_EQ(p.ltc_full.max_open_files, 512);
        EXPECT_EQ(p.stratum, 100u);
        EXPECT_EQ(p.http, w.http);
    }
}

TEST(LtcFdPlan, At256TheTablesAreMappedAndTheCapsLowered)
{
    const FdWants w = node_defaults();
    const FdPlan p = FdPlan::make(256, w);
    ASSERT_TRUE(p.fits);
    EXPECT_TRUE(p.mapped);
    EXPECT_TRUE(p.trimmed);
    EXPECT_TRUE(p.ltc_full.mmap_reads);
    EXPECT_TRUE(p.doge_full.mmap_reads);
    EXPECT_TRUE(p.doge_headers.mmap_reads);
    // 8 DBs x 10 + a fifth of the limit (LevelDB's default Env past its mmap
    // limit); 256 - 131 - 48 = 77 for the sockets.
    EXPECT_EQ(p.stores, 131u);
    EXPECT_EQ(p.ltc_peers, 8);
    EXPECT_EQ(p.merged_peers, 8);
    EXPECT_EQ(p.sharechain_peers, 14);
    EXPECT_EQ(p.stratum, 33u);
    EXPECT_EQ(p.http, 11u);
    EXPECT_LE(p.stores + FdPlan::kReserve + p.sockets, 256u);

    // Without the LTC full set: one DB less.
    FdWants w2 = w;
    w2.ltc_full = false;
    const FdPlan q = FdPlan::make(256, w2);
    ASSERT_TRUE(q.fits);
    EXPECT_GT(q.stratum, p.stratum);

    // 512: DOGE's header store keeps pread, the full sets are mapped, no cap lowered.
    const FdPlan r = FdPlan::make(512, w);
    EXPECT_TRUE(r.fits);
    EXPECT_FALSE(r.trimmed);
    EXPECT_FALSE(r.doge_headers.mmap_reads);
    EXPECT_TRUE(r.doge_full.mmap_reads);
    EXPECT_TRUE(r.ltc_full.mmap_reads);
}

TEST(LtcFdPlan, ALimitBelowTheFloorsDoesNotFit)
{
    const FdWants w = node_defaults();
    for (const uint64_t nofile : {uint64_t{64}, uint64_t{128}, uint64_t{192}}) {
        const FdPlan p = FdPlan::make(nofile, w);
        EXPECT_FALSE(p.fits) << nofile;
        EXPECT_EQ(p.sockets, floors_of(w)) << nofile;
    }
}

TEST(LtcFdPlan, AnUnlimitedStratumCapGetsWhatTheLimitLeaves)
{
    FdWants w = node_defaults();
    w.stratum = 0;
    const FdPlan big = FdPlan::make(65536, w);
    EXPECT_FALSE(big.trimmed);
    EXPECT_GT(big.stratum, 100u);
    EXPECT_LE(big.stores + FdPlan::kReserve + big.sockets, 65536u);
    const FdPlan small = FdPlan::make(256, w);
    ASSERT_TRUE(small.fits);
    EXPECT_GE(small.stratum, FdPlan::kStratumFloor);
    EXPECT_LE(small.stratum, 100u);
    EXPECT_LE(small.stores + FdPlan::kReserve + small.sockets, 256u);
}

#if defined(__linux__)

namespace {

/// The soft fd limit set to `soft` for the scope (lowering it is always
/// allowed), then put back.
struct SoftLimit {
    struct rlimit saved{};
    bool ok = false;
    explicit SoftLimit(rlim_t soft)
    {
        if (getrlimit(RLIMIT_NOFILE, &saved) != 0)
            return;
        struct rlimit want = saved;
        want.rlim_cur = soft;
        ok = (saved.rlim_max == RLIM_INFINITY || saved.rlim_max >= soft) && setrlimit(RLIMIT_NOFILE, &want) == 0;
    }
    ~SoftLimit()
    {
        if (ok)
            setrlimit(RLIMIT_NOFILE, &saved);
    }
};

int open_fds()
{
    int n = 0;
    DIR* d = opendir("/proc/self/fd");
    if (!d)
        return -1;
    while (readdir(d))
        ++n;
    closedir(d);
    return n - 3;   // ".", "..", the DIR's own fd
}

std::string key_of(size_t i)
{
    // Spread over the key space, as a UTXO set's outpoints are.
    const uint64_t x = i * 0x9E3779B97F4A7C15ULL;
    char b[24];
    snprintf(b, sizeof(b), "k%016llx", static_cast<unsigned long long>(x));
    return b;
}

std::vector<uint8_t> value_of(size_t i, uint32_t gen)
{
    std::mt19937 r(static_cast<uint32_t>(i * 2654435761u) ^ gen);
    std::vector<uint8_t> v(100);
    for (auto& c : v)
        c = static_cast<uint8_t>(r());
    v[0] = static_cast<uint8_t>(gen);
    return v;
}

bool fill(core::LevelDBStore& s, size_t n, uint32_t gen)
{
    for (size_t i = 0; i < n; i += 1000) {
        auto b = s.create_batch();
        for (size_t j = i; j < std::min(n, i + 1000); ++j)
            b.put(key_of(j), value_of(j, gen));
        if (!b.commit())
            return false;
    }
    return true;
}

struct TempDir {
    std::filesystem::path dir;
    TempDir()
    {
        std::mt19937_64 rng(std::random_device{}());
        dir = std::filesystem::temp_directory_path() / ("ltc_fd_plan_" + std::to_string(rng()));
        std::filesystem::create_directories(dir);
    }
    ~TempDir()
    {
        std::error_code ec;
        std::filesystem::remove_all(dir, ec);
    }
};

int listener(uint16_t& port)
{
    const int fd = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return -1;
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = 0;
    socklen_t len = sizeof(a);
    if (::bind(fd, reinterpret_cast<sockaddr*>(&a), sizeof(a)) != 0 || ::listen(fd, 1024) != 0
        || ::getsockname(fd, reinterpret_cast<sockaddr*>(&a), &len) != 0) {
        ::close(fd);
        return -1;
    }
    port = ntohs(a.sin_port);
    return fd;
}

int dial(uint16_t port)
{
    const int fd = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return -1;
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = htons(port);
    if (::connect(fd, reinterpret_cast<sockaddr*>(&a), sizeof(a)) != 0) {
        ::close(fd);
        return -1;
    }
    return fd;
}

/// One inbound session as the node holds it: the accepted fd (the client's
/// end, which a miner or browser would hold, closed here).
int inbound(int listen_fd, uint16_t port)
{
    const int c = dial(port);
    if (c < 0)
        return -1;
    const int s = ::accept4(listen_fd, nullptr, nullptr, SOCK_CLOEXEC);
    ::close(c);
    return s;
}

} // namespace

TEST(LtcFdPlan, TheRaiseNeverLowersAndStopsAtTheHardLimit)
{
    SoftLimit lim(256);
    if (!lim.ok)
        GTEST_SKIP() << "the hard fd limit is below 256";
    // Asking for less than the limit in effect leaves it.
    const core::NofileLimit low = core::raise_nofile_limit_report(128);
    EXPECT_EQ(low.before, 256u);
    EXPECT_EQ(low.after, 256u);
    // Asking for more raises it to the target, or to the hard limit.
    const core::NofileLimit r = core::raise_nofile_limit_report(4096);
    EXPECT_EQ(r.before, 256u);
    EXPECT_EQ(r.ceiling, r.hard);   // Linux: the hard limit only
    EXPECT_EQ(r.after, std::min<uint64_t>(4096, r.hard));
    EXPECT_EQ(core::raise_nofile_limit(4096), r.after);
}

TEST(LtcFdPlan, StoresPeersStratumAndHttpFitAt256)
{
    if (open_fds() < 0)
        GTEST_SKIP() << "no /proc/self/fd";
    SoftLimit lim(256);
    if (!lim.ok)
        GTEST_SKIP() << "the hard fd limit is below 256";
    const FdWants w = node_defaults();
    const FdPlan plan = FdPlan::make(256, w);
    ASSERT_TRUE(plan.fits);

    // The eight stores main_ltc opens, each with the options it gives them and
    // the plan's shares; 1 MB tables (LevelDB's least) so that the large
    // stores have more tables than their table caches hold.
    struct Spec {
        std::string name;
        core::LevelDBOptions opts;
        size_t keys;
    };
    const auto share = [](core::LevelDBOptions o, const StoreFds::Share& s) {
        o.max_open_files = s.max_open_files;
        o.mmap_reads = s.mmap_reads;
        return o;
    };
    std::vector<Spec> specs;
    core::LevelDBOptions o;
    o.max_file_size = 1024 * 1024;
    {
        core::LevelDBOptions h = o;   // doge/coin/header_chain.hpp init()
        h.write_buffer_size = 2 * 1024 * 1024;
        h.block_cache_size = 4 * 1024 * 1024;
        specs.push_back({"doge_headers", share(h, plan.doge_headers), 600000});
    }
    {
        core::LevelDBOptions f = o;   // the DOGE full set
        f.write_buffer_size = 64 * 1024 * 1024;
        f.block_cache_size = 128 * 1024 * 1024;
        specs.push_back({"doge_full", share(f, plan.doge_full), 600000});
        specs.push_back({"ltc_full", share(f, plan.ltc_full), 600000});
    }
    specs.push_back({"doge_accrual", o, 100000});
    specs.push_back({"ltc_headers", o, 100000});
    specs.push_back({"ltc_accrual", o, 20000});
    specs.push_back({"found_blocks", o, 2000});
    specs.push_back({"sharechain", o, 20000});
    ASSERT_EQ(specs.size(), static_cast<size_t>(w.other_dbs + 3));

    TempDir t;
    const int base = open_fds();
    std::vector<std::unique_ptr<core::LevelDBStore>> stores;
    for (const auto& s : specs) {
        stores.push_back(std::make_unique<core::LevelDBStore>((t.dir / s.name).string(), s.opts));
        ASSERT_TRUE(stores.back()->open()) << s.name;
        ASSERT_TRUE(fill(*stores.back(), s.keys, 1)) << s.name;
        stores.back()->compact();
    }

    // The sockets the plan allows, held through the run: the listeners
    // (sharechain, stratum, HTTP), outbound peers (LTC, merged, sharechain),
    // inbound stratum and HTTP sessions at their caps.
    std::vector<int> socks;
    uint16_t p2p_port = 0, stratum_port = 0, http_port = 0;
    const int p2p_l = listener(p2p_port), stratum_l = listener(stratum_port), http_l = listener(http_port);
    ASSERT_GE(p2p_l, 0);
    ASSERT_GE(stratum_l, 0);
    ASSERT_GE(http_l, 0);
    int refused = 0;
    const auto hold = [&](int fd) {
        if (fd < 0)
            ++refused;
        else
            socks.push_back(fd);
    };
    const int outbound = plan.ltc_peers + w.merged_chains * plan.merged_peers + plan.sharechain_peers;
    for (int i = 0; i < outbound; ++i)
        hold(dial(p2p_port));   // completes in the listener's backlog
    for (size_t i = 0; i < plan.stratum; ++i)
        hold(inbound(stratum_l, stratum_port));
    for (size_t i = 0; i < plan.http; ++i)
        hold(inbound(http_l, http_port));
    EXPECT_EQ(refused, 0) << "a socket within the plan's caps was refused";

    // Every store read across its keys while it is overwritten and compacted
    // again; meanwhile one connection beyond each cap is accepted and closed
    // (stratum's and HTTP's refusal), and the fd count is sampled.
    std::atomic<bool> stop{false};
    std::atomic<int> peak{0};
    std::thread mon([&]() {
        while (!stop.load()) {
            const int n = open_fds();
            int p = peak.load();
            while (n > p && !peak.compare_exchange_weak(p, n)) {
            }
            std::this_thread::sleep_for(std::chrono::microseconds(200));
        }
    });
    std::atomic<int> read_errors{0}, write_errors{0}, beyond_refused{0};
    std::thread beyond([&]() {
        while (!stop.load()) {
            for (const auto& [l, port] : {std::pair<int, uint16_t>{stratum_l, stratum_port}, {http_l, http_port}}) {
                const int fd = inbound(l, port);
                if (fd < 0)
                    ++beyond_refused;
                else
                    ::close(fd);
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(2));
        }
    });
    std::vector<std::thread> ws;
    for (size_t i = 0; i < specs.size(); ++i) {
        ws.emplace_back([&, i]() {
            auto& s = *stores[i];
            std::mt19937 r(static_cast<uint32_t>(i));
            for (int round = 0; round < 2; ++round) {
                std::vector<uint8_t> v;
                for (size_t k = 0; k < specs[i].keys; ++k) {
                    if (!s.get(key_of(r() % specs[i].keys), v))
                        ++read_errors;
                }
                if (!fill(s, specs[i].keys / 2, 2 + round))
                    ++write_errors;
                s.compact();
            }
        });
    }
    for (auto& t2 : ws)
        t2.join();
    stop = true;
    beyond.join();
    mon.join();

    // The stores still write and read after the run (no background error).
    for (size_t i = 0; i < specs.size(); ++i) {
        EXPECT_TRUE(stores[i]->put("after", {1})) << specs[i].name;
        std::vector<uint8_t> v;
        EXPECT_TRUE(stores[i]->get(key_of(0), v)) << specs[i].name;
    }

    const int sockets = static_cast<int>(socks.size()) + 3;
    std::cout << "[ltc-fd-plan] 256: baseline " << base << " fds; peak " << peak.load() << " with " << sockets
              << " sockets (" << outbound << " peers, " << plan.stratum << " stratum, " << plan.http << " HTTP, 3"
              << " listeners); the stores' ceiling " << plan.stores << ", the reserve " << FdPlan::kReserve
              << std::endl;
    EXPECT_EQ(read_errors.load(), 0);
    EXPECT_EQ(write_errors.load(), 0);
    EXPECT_EQ(beyond_refused.load(), 0);
    EXPECT_LT(peak.load(), 256);
    // The stores' measured peak (less the two fds of a connection beyond a
    // cap) is within the plan's ceiling for them.
    EXPECT_LE(peak.load() - base - sockets - 2, static_cast<int>(plan.stores));

    for (const int fd : socks)
        ::close(fd);
    ::close(p2p_l);
    ::close(stratum_l);
    ::close(http_l);
}

#endif // __linux__
