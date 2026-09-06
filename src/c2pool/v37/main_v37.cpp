// c2pool-v37 — the Track A2 / W0 node-scaffold entrypoint.
//
// W0 stands the empty stage the v37 executor plugs into: an >= 8-process
// single-host loopback simnet whose processes come up, stand a live
// V37Engine each, seed identical lane-0 genesis geometry, mesh over real
// loopback sockets, idle EXCHANGING NOTHING (no receipt wire schema — that is
// W2/W3), then exit 0 with ops_committed()==1 (the single seeding AddLane).
//
// Two modes:
//   --selftest        network-free in-process invariants (the CI-runnable
//                     core; no peers needed), then exit.
//   (default)         one simnet node: --listen <port>, --peers <p,...>,
//                     --node-id <n>, --hold-ms <n>.
//
// NETWORKING NOTE / W0 spec deviation (documented): the design of record
// (spec §3/§5.1) grafts the v36 donor `src/pool/` p2p plumbing and links
// core+pool+Boost. W0 exchanges NO v37 payload (§4: "sends nothing"; an
// optional payload-free hello is all that is allowed), and the standing
// mandate is a MINIMAL link graph on a memory-pressured host. Dragging in the
// coin-specific pool/protocol stack (which needs a coin, network params, and
// the whole Boost.Asio node) to carry a payload-free hello would be the
// opposite of minimal. So the W0 mesh uses plain POSIX loopback sockets: zero
// extra link dependencies, and the seam W2 fills is UNCHANGED (W2 wires the
// stratum edge -> submit_tracked path, not this socket code). Grafting the
// real src/pool/ carrier transport is deferred to W3 (carrier relay), where a
// wire schema actually exists to carry.

#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <future>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include <c2pool/v37/v37_engine.hpp>
#include <sharechain/v37/v37_roundabout.hpp>

// ── W6 (Track A2 / persistence) wiring, ADD-ONLY and compile-guarded ────────
// The W0 simnet scaffold (this file's c2pool-v37 target) links Threads only (a
// deliberate minimal link graph on a memory-pressured host — see the NETWORKING
// NOTE above); it carries no settlement events, so it does NOT define
// W6_ENABLE_LEVELDB and stays leveldb-free. The W6 settlement store, restart
// recovery and SettlementJournal lifecycle below (store open BEFORE
// engine.start(), RecoveryDriver::recover(), close AFTER engine.stop()) is
// therefore gated behind W6_ENABLE_LEVELDB, which a production node target (one
// that links core + leveldb) defines. The header's LevelDBSettleStore is the
// only thing that pulls <core/leveldb_store.hpp> (spec §7.1).
//
// The gated code below is NOT dead and is NOT unchecked: a dedicated
// compile-only CI target, c2pool-v37-w6-leveldb-compile-check (an OBJECT library
// in src/c2pool/CMakeLists.txt), recompiles THIS translation unit with
// W6_ENABLE_LEVELDB defined and inherits core's include dirs, so both the header
// binding (LevelDBOptions' 9-field positional aggregate + create_batch()'s
// guaranteed-elided prvalue) and this lifecycle wiring are type-checked against
// src/core on every CI run. It is build-only (compiled, never linked or run) and
// is listed in build.yml's --target list on both legs so it cannot silently
// go NOT_BUILT. (Binding the ReplayDriver to the live V37Engine is OI-W6-3.)
#if defined(W6_ENABLE_LEVELDB)
#include <optional>
#include <core/filesystem.hpp>
#include <c2pool/v37/w6_persistence.hpp>
#endif

using c2pool::v37n::V37Engine;

// ── the ratified OQ-5 default lane geometry (LaneParams{} == the defaults) ──
static ::v37::LaneParams genesis_params() { return ::v37::LaneParams{}; }

static std::string hex32(const ::v37::bytes32& b) {
    static const char* k = "0123456789abcdef";
    std::string s;
    s.reserve(64);
    for (auto x : b) { s.push_back(k[x >> 4]); s.push_back(k[x & 0xf]); }
    return s;
}

// ── seed the same lane-0 geometry every node shares; return its digest ──────
static bool seed_genesis(V37Engine& e, ::v37::bytes32& digest_out) {
    ::v37::SubmitResult r =
        e.submit_tracked(::v37::LaneRecord::add_lane(0, genesis_params())).get();
    if (!r.applied()) return false;
    auto snap = e.snapshot(0);
    if (!snap || snap->version != 1 || snap->incarnation != 1) return false;
    digest_out = snap->digest;
    return true;
}

// ── --selftest: network-free invariants (mirrors the scaffold gate core) ────
static int run_selftest() {
    int fails = 0;
    auto check = [&](bool ok, const char* what) {
        if (!ok) { ++fails; std::printf("SELFTEST FAIL: %s\n", what); }
    };

    V37Engine e;
    e.start();

    // (a) genesis digest through the shell == direct-library digest.
    ::v37::bytes32 shell_digest{};
    check(seed_genesis(e, shell_digest), "seed genesis / snapshot v1");
    ::v37::Roundabout rb;
    rb.add_lane(0, genesis_params());
    check(shell_digest == rb.lane_digest(0), "genesis digest == direct lib");
    check(e.ops_committed() == 1, "ops_committed==1 after seed");

    // (b) MPSC -> single executor preserves order under many producers, and
    //     loses/duplicates nothing (a strict total order 2..1+T*M).
    const int T = 4, M = 200;
    std::vector<std::thread> prod;
    std::vector<std::vector<std::future<::v37::SubmitResult>>> futs(T);
    ::v37::PayoutDescriptor d;
    {
        std::vector<std::uint8_t> s = {0x76, 0xa9, 0x14};
        for (int i = 0; i < 20; ++i) s.push_back(0xab);
        s.push_back(0x88); s.push_back(0xac);
        d.pay = ::v37::canonicalize_script(s);
    }
    for (int t = 0; t < T; ++t)
        prod.emplace_back([&, t] {
            for (int i = 0; i < M; ++i)
                futs[t].push_back(
                    e.submit_tracked(::v37::LaneRecord::push(0, d, 1, 0)));
        });
    for (auto& th : prod) th.join();
    std::vector<std::uint64_t> vers;
    for (int t = 0; t < T; ++t)
        for (auto& f : futs[t]) {
            auto r = f.get();
            if (r.applied()) vers.push_back(r.lane_version);
        }
    std::sort(vers.begin(), vers.end());
    bool contiguous = vers.size() == std::size_t(T * M);
    for (std::size_t i = 0; i < vers.size() && contiguous; ++i)
        if (vers[i] != std::uint64_t(i + 2)) contiguous = false;
    check(contiguous, "MPSC total order 2..1+T*M, no loss/dup");

    // (c) the mailbox load() is callable from a non-executor thread and
    //     returns a stable snapshot across a concurrent submit (F1 smoke).
    auto held = e.snapshot(0);
    check(held != nullptr, "mailbox load from main thread");
    auto held_digest = held ? held->digest : ::v37::bytes32{};
    std::atomic<bool> stop{false};
    std::atomic<bool> reader_ok{true};
    std::thread reader([&] {
        while (!stop.load()) {
            auto s = e.snapshot(0);
            if (s && s->chain != 0) reader_ok.store(false);
        }
    });
    for (int i = 0; i < 500; ++i)
        (void)e.submit_tracked(::v37::LaneRecord::push(0, d, 1, 0)).get();
    stop.store(true);
    reader.join();
    check(reader_ok.load(), "concurrent reader saw consistent snapshots");
    check(held && held->digest == held_digest, "held snapshot not mutated");

    e.stop();
    std::printf("SELFTEST %s (%d failures)\n", fails ? "FAIL" : "OK", fails);
    return fails ? 1 : 0;
}

// ── minimal loopback socket helpers ─────────────────────────────────────────
static int listen_on(std::uint16_t port) {
    int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    int one = 1;
    ::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = ::htonl(INADDR_LOOPBACK);
    a.sin_port = ::htons(port);
    if (::bind(fd, reinterpret_cast<sockaddr*>(&a), sizeof(a)) < 0 ||
        ::listen(fd, 16) < 0) {
        ::close(fd);
        return -1;
    }
    return fd;
}

static int dial(std::uint16_t port) {
    int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = ::htonl(INADDR_LOOPBACK);
    a.sin_port = ::htons(port);
    if (::connect(fd, reinterpret_cast<sockaddr*>(&a), sizeof(a)) < 0) {
        ::close(fd);
        return -1;
    }
    return fd;
}

// ── default mode: one simnet node ────────────────────────────────────────────
static int run_node(std::uint16_t listen_port,
                    const std::vector<std::uint16_t>& peers, int node_id,
                    int hold_ms) {
    V37Engine engine;

#if defined(W6_ENABLE_LEVELDB)
    // ── W6: construct the settlement store, run restart recovery BEFORE the
    // engine starts, hand a SettlementJournal to the W4/W5 settlement callers.
    // Donor lifecycle order preserved: the store is opened before engine.start()
    // and closed after engine.stop() (below).
    const std::string w6_net = "v37sim";
    c2pool::v37n::persist::LevelDBSettleStore w6_store(
        core::filesystem::config_path().string(), w6_net);
    std::optional<c2pool::v37n::persist::SettlementJournal> w6_journal;
    if (auto w6_boot = w6_store.open()) {
        c2pool::v37n::recover::RecoveryHooks w6_hooks;   // families A/B; lane replay hook is OI-W6-3
        c2pool::v37n::recover::RecoveryDriver w6_recovery(w6_store, w6_hooks);
        auto w6_res = w6_recovery.recover();
        if (!w6_res.ok())
            std::printf("node %d: W6 recovery fail-closed — a chain did not start\n", node_id);
        // The journal is the single writer the W4 (settlement) / W5 (coinbase)
        // callers use; idle in the W0 scaffold, which emits no settlement events.
        w6_journal.emplace(w6_store, *w6_boot);
        (void)w6_journal;
    } else {
        std::printf("node %d: W6 settlement store open FAILED\n", node_id);
    }
#endif

    engine.start();

    ::v37::bytes32 digest{};
    if (!seed_genesis(engine, digest)) {
        std::printf("node %d: genesis seed FAILED\n", node_id);
        return 1;
    }

    int lfd = listen_on(listen_port);
    if (lfd < 0) {
        std::printf("node %d: listen(%u) FAILED\n", node_id, listen_port);
        return 1;
    }

    // Listener thread: accept inbound peers and hold them connected (payload-
    // free HELLO only). Runs until g_stop.
    std::atomic<bool> g_stop{false};
    std::atomic<int> inbound{0};
    std::vector<int> inbound_fds;
    std::mutex in_mtx;
    std::thread listener([&] {
        while (!g_stop.load()) {
            pollfd pfd{lfd, POLLIN, 0};
            int pr = ::poll(&pfd, 1, 50);
            if (pr <= 0) continue;
            int cfd = ::accept(lfd, nullptr, nullptr);
            if (cfd < 0) continue;
            char buf[64];
            ::recv(cfd, buf, sizeof(buf), 0);   // best-effort payload-free hello
            inbound.fetch_add(1);
            std::lock_guard<std::mutex> lk(in_mtx);
            inbound_fds.push_back(cfd);
        }
    });

    // Dial each peer (retry until connected or a global deadline), send a
    // payload-free hello, keep the socket open.
    std::vector<int> out_fds;
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
    int connected = 0;
    for (std::uint16_t p : peers) {
        int fd = -1;
        while (fd < 0 && std::chrono::steady_clock::now() < deadline) {
            fd = dial(p);
            if (fd < 0)
                std::this_thread::sleep_for(std::chrono::milliseconds(20));
        }
        if (fd < 0) {
            std::printf("node %d: dial peer %u FAILED (timeout)\n", node_id, p);
            g_stop.store(true);
            listener.join();
            ::close(lfd);
            return 1;
        }
        std::string hello = "HELLO " + std::to_string(node_id) + "\n";
        ::send(fd, hello.data(), hello.size(), 0);
        // Payload-free mesh: connect + hello proves the socket. We do NOT
        // wait for a reply (there is no wire protocol in W0), so the dialer
        // never blocks on the peer.
        out_fds.push_back(fd);
        ++connected;
    }

    std::printf("node %d: MESH up (out=%d) digest=%s\n", node_id, connected,
                hex32(digest).c_str());

    // Idle — the empty W0 stage. Hold long enough for the whole ring to form.
    std::this_thread::sleep_for(std::chrono::milliseconds(hold_ms));

    // Teardown in donor order: stop the network first, then drain-and-join
    // the engine (no wire event can fire post-stop).
    g_stop.store(true);
    listener.join();
    for (int fd : out_fds) ::close(fd);
    {
        std::lock_guard<std::mutex> lk(in_mtx);
        for (int fd : inbound_fds) ::close(fd);
    }
    ::close(lfd);

    engine.stop();

#if defined(W6_ENABLE_LEVELDB)
    w6_store.close();   // W6 teardown: after the engine has drained (donor order)
#endif

    std::uint64_t ops = engine.ops_committed();
    bool ok = (ops == 1);   // nothing was ever submitted but the one AddLane
    std::printf("node %d: RESULT ops_committed=%llu inbound=%d %s digest=%s\n",
                node_id, static_cast<unsigned long long>(ops), inbound.load(),
                ok ? "OK" : "BAD", hex32(digest).c_str());
    return ok ? 0 : 1;
}

int main(int argc, char** argv) {
    std::uint16_t listen_port = 0;
    int node_id = 0;
    int hold_ms = 400;
    std::vector<std::uint16_t> peers;
    bool selftest = false;

    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        auto next = [&](const char* def) -> std::string {
            return (i + 1 < argc) ? argv[++i] : def;
        };
        if (a == "--selftest") selftest = true;
        else if (a == "--listen") listen_port =
            static_cast<std::uint16_t>(std::stoi(next("0")));
        else if (a == "--node-id") node_id = std::stoi(next("0"));
        else if (a == "--hold-ms") hold_ms = std::stoi(next("400"));
        else if (a == "--peers") {
            std::string list = next("");
            std::size_t pos = 0;
            while (pos < list.size()) {
                std::size_t comma = list.find(',', pos);
                std::string tok = list.substr(
                    pos, comma == std::string::npos ? std::string::npos
                                                    : comma - pos);
                if (!tok.empty())
                    peers.push_back(static_cast<std::uint16_t>(std::stoi(tok)));
                if (comma == std::string::npos) break;
                pos = comma + 1;
            }
        }
    }

    if (selftest) return run_selftest();

    if (listen_port == 0) {
        std::printf("usage: c2pool-v37 --selftest\n"
                    "       c2pool-v37 --listen <port> --peers <p,...> "
                    "--node-id <n> [--hold-ms <n>]\n");
        return 2;
    }
    return run_node(listen_port, peers, node_id, hold_ms);
}
