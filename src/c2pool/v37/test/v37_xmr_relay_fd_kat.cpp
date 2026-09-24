// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// v37_xmr_relay_fd_kat -- RELAY-FD: the GAP-2 receipt relay must not leak a
// descriptor per dropped connection, and its accept loop must back off (not
// spin) on an exhausted descriptor table.
//
// Found live (stagenet pre-capstone smoke, node A; D2 verify defect D-7): after
// the SIGUSR1 relay partition (the rig knob, XmrRelayNode::partition_for) node
// A's relay never healed -- fds=1024/1024, the accept thread spinning on EMFILE
// with a full listen backlog. Root cause: CarrierPeerNode never closed the
// descriptor of a dropped connection (only stop() did, and not even stop() once
// the drop had removed it from the peer set), so every connection the partition
// refused -- a peer redials about once a second -- leaked one fd on EACH side;
// and accept() failing with EMFILE was retried at once, forever.
//
//   F1  transport churn: 300 connections dialed and dropped (either side) leave
//       the process's open-descriptor count where it was (<= +8), and the
//       reader threads of unwound connections are reaped
//   F2  relay partition: B keeps redialing a partitioned A; the fd count stays
//       bounded during the partition and returns to the baseline after it, and
//       the relay HEALS (a fresh HELLO on both sides) once it ends, with no
//       ghost peer entry left behind by a refused dial
//   F3  EMFILE: with the descriptor table full and a connection queued, the
//       accept loop backs off (process CPU < 10% of one core, exhaustion
//       notices rate-limited to <= 1 per 5 s) and accepts the queued connection
//       once descriptors are freed
#include <dirent.h>
#include <fcntl.h>
#include <sys/resource.h>
#include <time.h>

#include <atomic>
#include <chrono>
#include <cstdlib>
#include <mutex>
#include <thread>

#include "xmr_relay_test_util.hpp"
#include <c2pool/v37/carrier_net.hpp>
#include <c2pool/v37/xmr/relay/xmr_relay_node.hpp>

using namespace gap2test;
using namespace std::chrono_literals;
using c2pool::v37n::CarrierPeerNode;

static constexpr u32 kChain = 7;
static constexpr u64 kShareDiff = 1000;

static int open_fds() {
    int n = 0;
    if (DIR* d = ::opendir("/proc/self/fd")) {
        while (dirent* e = ::readdir(d)) if (e->d_name[0] != '.') ++n;
        ::closedir(d);
    }
    return n - 1;   // the directory stream's own descriptor
}
static double cpu_seconds() {
    timespec ts{};
    ::clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
}
template <class F>
static bool wait_until(F cond, std::chrono::milliseconds limit) {
    const auto dl = std::chrono::steady_clock::now() + limit;
    while (std::chrono::steady_clock::now() < dl) {
        if (cond()) return true;
        std::this_thread::sleep_for(20ms);
    }
    return cond();
}
// Diagnostics that only the fixed transport has; the KAT still builds (and goes
// red on the behaviour, not on a compile error) against the base tree.
template <class N> static void try_set_log(N& n, std::function<void(const std::string&)> f) {
    if constexpr (requires { n.set_log(f); }) n.set_log(std::move(f));
}
template <class N> static long reader_threads(const N& n) {
    if constexpr (requires { n.reader_threads(); }) return static_cast<long>(n.reader_threads());
    else return -1;
}

static RelayOptions opts(bool listen, std::vector<u16> dial) {
    RelayOptions o;
    o.network = 3; o.chain = kChain; o.share_diff = kShareDiff; o.bind = BindMode::None;
    o.lane_params_digest = lane_params_digest(::v37::LaneParams{}, kShareDiff, BindMode::None);
    o.listen = listen; o.listen_host = "127.0.0.1"; o.listen_port = 0;
    for (u16 p : dial) o.peers.emplace_back("127.0.0.1", p);
    o.hello_timeout_ms = 3000;
    return o;
}

struct RNode {
    ChainView chain;
    std::unique_ptr<XmrRelayNode> relay;
    RNode(RelayOptions o) {
        relay = std::make_unique<XmrRelayNode>(
            std::move(o), chain,
            [](const std::vector<u8>&, const bytes32&, bytes32& pow) { pow.fill(0); return true; },
            []() -> std::pair<u64, bytes32> { return {0, bytes32{}}; },
            [](const std::string&) {});
    }
    ~RNode() { relay->stop(); }
};

int main() {
    Checker C;
    std::printf("== v37_xmr_relay_fd_kat ==\n");

    // ── F1 transport churn ──────────────────────────────────────────────────
    {
        std::printf("-- F1 transport churn: 300 connect/drop cycles\n");
        const int fd0 = open_fds();
        {
            CarrierPeerNode srv, cli;
            C(srv.listen("127.0.0.1", 0), "F1 server listens on an ephemeral port");
            int ok = 0;
            for (int i = 0; i < 300; ++i) {
                const auto pid = cli.add_peer_id("127.0.0.1", srv.listen_port());
                if (!pid) continue;
                ++ok;
                if (i % 2 == 0) cli.disconnect(pid);                     // dialer drops
                else {                                                   // listener refuses
                    wait_until([&] { return srv.n_peers() > 0; }, 2000ms);
                    for (auto p : srv.peer_ids()) srv.disconnect(p);
                }
                wait_until([&] { return cli.n_peers() == 0 && srv.n_peers() == 0; }, 2000ms);
            }
            C(ok == 300, "F1 all 300 dials connected (" + std::to_string(ok) + ")");
            std::this_thread::sleep_for(300ms);   // let the last readers unwind
            const int fd1 = open_fds();
            std::printf("    fds: before=%d after-churn=%d (delta %+d)\n", fd0, fd1, fd1 - fd0);
            // 1 listen socket is live on top of the baseline.
            C(fd1 - fd0 <= 8, "F1 no descriptor leaked per dropped connection (delta " +
                                  std::to_string(fd1 - fd0) + " <= 8)");
            // one more connect reaps every unwound reader of both nodes' past
            const auto pid = cli.add_peer_id("127.0.0.1", srv.listen_port());
            wait_until([&] { return srv.n_peers() == 1; }, 2000ms);
            const long rc = reader_threads(cli), rs = reader_threads(srv);
            std::printf("    unjoined reader threads after one more connect: client=%ld server=%ld\n", rc, rs);
            C(rc >= 0 && rc <= 4 && rs >= 0 && rs <= 4, "F1 unwound reader threads are reaped (not kept until stop())");
            cli.disconnect(pid);
        }
        std::this_thread::sleep_for(100ms);
        const int fd2 = open_fds();
        std::printf("    fds after both nodes stopped: %d (delta %+d)\n", fd2, fd2 - fd0);
        C(fd2 - fd0 <= 2, "F1 stop() releases every descriptor (delta " + std::to_string(fd2 - fd0) + ")");
    }

    // ── F2 relay partition + heal ───────────────────────────────────────────
    {
        std::printf("-- F2 relay partition (A partitioned 6 s, B redials) + heal\n");
        RNode A(opts(true, {}));
        std::string why;
        C(A.relay->start(why), "F2 A starts (listening)");
        RNode B(opts(false, {A.relay->listen_port()}));
        C(B.relay->start(why), "F2 B starts (dialing A)");
        C(wait_until([&] { return A.relay->stats().hello_ok.load() >= 1 && B.relay->stats().hello_ok.load() >= 1; }, 10000ms),
          "F2 A<->B HELLO ok before the partition");
        std::this_thread::sleep_for(300ms);
        const int base = open_fds();
        const u64 ha0 = A.relay->stats().hello_ok.load(), hb0 = B.relay->stats().hello_ok.load();
        const u64 dials0 = B.relay->stats().dials.load();
        A.relay->partition_for(std::chrono::seconds(6));
        int peak = base;
        const auto t0 = std::chrono::steady_clock::now();
        while (std::chrono::steady_clock::now() - t0 < 6s) {
            peak = std::max(peak, open_fds());
            std::this_thread::sleep_for(100ms);
        }
        const u64 dials_during = B.relay->stats().dials.load() - dials0;
        const bool healed = wait_until([&] {
            peak = std::max(peak, open_fds());
            return A.relay->stats().hello_ok.load() > ha0 && B.relay->stats().hello_ok.load() > hb0;
        }, 15000ms);
        const double heal_s = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count() - 6.0;
        std::this_thread::sleep_for(1500ms);
        const int after = open_fds();
        std::printf("    fds: steady=%d peak=%d after-heal=%d; B dials during partition=%llu; heal %.1f s after the partition\n",
                    base, peak, after, (unsigned long long)dials_during, heal_s);
        C(dials_during >= 3, "F2 B kept redialing the partitioned A (" + std::to_string(dials_during) + " dials)");
        C(peak - base <= 6, "F2 fds bounded during the partition (peak " + std::to_string(peak) +
                                " <= steady " + std::to_string(base) + " + 6)");
        C(after - base <= 2, "F2 fds back to steady after the heal (" + std::to_string(after) + " vs " +
                                 std::to_string(base) + ")");
        C(healed, "F2 relay healed after the partition (fresh HELLO ok on A and B)");
        C(A.relay->n_connections() == 1 && B.relay->n_connections() == 1,
          "F2 exactly one live A<->B link after the heal");
        // A dial the partitioned A refused at once must not leave a GHOST peer
        // entry on B (its down event raced ahead of its up event): a ghost is
        // re-counted as a HELLO timeout every maintenance tick and holds a
        // max_peers slot forever. Past the HELLO timeout, the counter is flat.
        std::this_thread::sleep_for(3500ms);
        const u64 t1 = B.relay->stats().hello_timeout.load() + A.relay->stats().hello_timeout.load();
        std::this_thread::sleep_for(2000ms);
        const u64 t2 = B.relay->stats().hello_timeout.load() + A.relay->stats().hello_timeout.load();
        std::printf("    HELLO timeouts after the heal: %llu -> %llu over 2 s\n", (unsigned long long)t1, (unsigned long long)t2);
        C(t2 == t1, "F2 no ghost peer entries after the partition (HELLO-timeout counter flat)");
    }

    // ── F3 EMFILE: accept loop backs off, heals once descriptors are free ──
    {
        std::printf("-- F3 EMFILE: descriptor table full, one connection queued\n");
        std::mutex lm; std::vector<std::string> lines;   // outlives srv (its accept thread logs here)
        CarrierPeerNode srv;
        try_set_log(srv, [&](const std::string& s) { std::lock_guard<std::mutex> lk(lm); lines.push_back(s); });
        C(srv.listen("127.0.0.1", 0), "F3 server listens");
        // Two clients, made BEFORE the table is full. A blocked accept(2) has
        // already reserved its descriptor slot (Linux allocates the fd before it
        // waits), so the FIRST queued connection is accepted into that slot; the
        // SECOND is the one that meets EMFILE.
        const int cs = ::socket(AF_INET, SOCK_STREAM, 0);
        const int cs2 = ::socket(AF_INET, SOCK_STREAM, 0);
        rlimit old{};
        ::getrlimit(RLIMIT_NOFILE, &old);
        rlimit lim = old;
        lim.rlim_cur = static_cast<rlim_t>(open_fds() + 16);
        if (lim.rlim_cur > old.rlim_max) lim.rlim_cur = old.rlim_max;
        ::setrlimit(RLIMIT_NOFILE, &lim);
        std::vector<int> fill;
        for (;;) { int f = ::open("/dev/null", O_RDONLY); if (f < 0) break; fill.push_back(f); }
        const bool full = ::open("/dev/null", O_RDONLY) < 0 && errno == EMFILE;
        std::size_t lines0 = 0; { std::lock_guard<std::mutex> lk(lm); lines0 = lines.size(); }
        sockaddr_in a{}; a.sin_family = AF_INET; a.sin_port = htons(srv.listen_port());
        ::inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);
        const bool queued = ::connect(cs, reinterpret_cast<sockaddr*>(&a), sizeof(a)) == 0 &&
                            (std::this_thread::sleep_for(200ms), ::connect(cs2, reinterpret_cast<sockaddr*>(&a), sizeof(a)) == 0);
        C(full && queued, "F3 descriptor table full (EMFILE) and a connection queued in the backlog");
        std::this_thread::sleep_for(300ms);
        const double c0 = cpu_seconds();
        const auto w0 = std::chrono::steady_clock::now();
        std::this_thread::sleep_for(3000ms);
        const double cpu = (cpu_seconds() - c0) /
                           std::chrono::duration<double>(std::chrono::steady_clock::now() - w0).count();
        std::size_t lines1 = 0; { std::lock_guard<std::mutex> lk(lm); lines1 = lines.size(); }
        const bool accepted_while_full = srv.n_peers() > 1;   // the pre-reserved slot takes the first
        for (int f : fill) ::close(f);
        ::setrlimit(RLIMIT_NOFILE, &old);
        std::printf("    while exhausted: process CPU %.1f%% of one core, %zu exhaustion notices in 3.5 s\n",
                    cpu * 100.0, lines1 - lines0);
        C(!accepted_while_full, "F3 nothing accepted while the table is full");
        C(cpu < 0.10, "F3 accept loop backs off on EMFILE (CPU " + std::to_string(cpu * 100.0) + "% < 10% of a core)");
        C(lines1 - lines0 <= 1, "F3 exhaustion notices rate-limited (<= 1 per 5 s)");
        const auto h0 = std::chrono::steady_clock::now();
        const bool healed = wait_until([&] { return srv.n_peers() == 2; }, 5000ms);
        std::printf("    queued connection accepted %.2f s after descriptors were freed\n",
                    std::chrono::duration<double>(std::chrono::steady_clock::now() - h0).count());
        C(healed, "F3 the queued connection is accepted once descriptors are free");
        ::close(cs); ::close(cs2);
        { std::lock_guard<std::mutex> lk(lm); for (auto& l : lines) std::printf("    [log] %s\n", l.c_str()); }
    }
    return C.done("v37_xmr_relay_fd_kat");
}
