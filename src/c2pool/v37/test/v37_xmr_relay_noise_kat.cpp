// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// v37_xmr_relay_noise_kat -- SMOKE-NOISE: the two relay-lane noise defects the
// pre-capstone stagenet smoke left behind.
//
//   N1  refused peer: B keeps dialing a PARTITIONED A (A accepts the TCP connect
//       and drops it at once). connect(2) succeeding used to reset B's backoff to
//       1 s -- and a link whose down event ran before B recorded it was redialed
//       on the very next 250 ms tick -- so B redialed ~once a second for the
//       whole partition. Now a link that ends before HELLO backs off
//       1, 1, 2, 4, 8, 16 s (cap 16): <= 6 dials in a 16 s partition, and the
//       relay still heals after it.
//   N2  silent peer: a listener that accepts but never answers HELLO. Each link
//       costs one HELLO timeout; B used to redial it 1 s later, forever (~1
//       timeout per (timeout + 1 s)). Now a HELLO timeout backs off 2, 8, 32,
//       60 s (cap 60): <= 4 HELLO timeouts in 12 s with a 0.5 s timeout (base ~6), i.e. at
//       most ~1 per minute in the long run.
//   N3  lane digest after a partition + heal, and after a restart: two nodes
//       that end up holding the SAME receipts push them in different orders
//       (the late tail), so their lane digests differ for good -- by design
//       (Ruling A). The value nodes compare, lane_set(B), is order-free: equal
//       on both once the heal delivered the missing receipts, and equal on a
//       node rebuilt from the durable log (bins resolved from prev_id).
//       Against a tree without lane_set() the KAT compares what nodes compared
//       there -- the lane digest -- and goes RED on that, not on a build error.
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#include <chrono>
#include <cstdio>
#include <filesystem>
#include <map>
#include <thread>

#include "xmr_relay_test_util.hpp"
#include <c2pool/v37/xmr/relay/xmr_relay_node.hpp>
#include <c2pool/v37/xmr/relay/xmr_receipt_ingest.hpp>

using namespace gap2test;
using namespace std::chrono_literals;

static constexpr u32 kChain = 7;
static constexpr u64 kShareDiff = 1000;

template <class F>
static bool wait_until(F cond, std::chrono::milliseconds limit) {
    const auto dl = std::chrono::steady_clock::now() + limit;
    while (std::chrono::steady_clock::now() < dl) {
        if (cond()) return true;
        std::this_thread::sleep_for(20ms);
    }
    return cond();
}

static RelayOptions opts(bool listen, std::vector<u16> dial, u32 hello_timeout_ms = 3000) {
    RelayOptions o;
    o.network = 3; o.chain = kChain; o.share_diff = kShareDiff; o.bind = BindMode::None;
    o.lane_params_digest = lane_params_digest(::v37::LaneParams{}, kShareDiff, BindMode::None);
    o.listen = listen; o.listen_host = "127.0.0.1"; o.listen_port = 0;
    for (u16 p : dial) o.peers.emplace_back("127.0.0.1", p);
    o.hello_timeout_ms = hello_timeout_ms;
    return o;
}

struct RNode {
    ChainView chain;
    std::unique_ptr<XmrRelayNode> relay;
    explicit RNode(RelayOptions o) {
        relay = std::make_unique<XmrRelayNode>(
            std::move(o), chain,
            [](const std::vector<u8>&, const bytes32&, bytes32& pow) { pow.fill(0); return true; },
            []() -> std::pair<u64, bytes32> { return {0, bytes32{}}; },
            [](const std::string&) {});
    }
    ~RNode() { relay->stop(); }
};

// ── N3 helpers: a lane = a hash chain over (payee, weight) pushes ──────────
struct FakeLane {
    u64 next = 0;
    bytes32 dig{};
    bool push(const ::v37::ScriptRef& payee, u64 w, u64& next_after, bytes32& digest_after) {
        std::vector<u8> m(dig.begin(), dig.end());
        m.insert(m.end(), payee.payload.begin(), payee.payload.end());
        le::put64(m, w);
        dig = keccak_bytes(m);
        next_after = ++next; digest_after = dig;
        return true;
    }
};
struct INode {
    FakeLane lane;
    std::unique_ptr<XmrReceiptIngest> ing;
    INode(const std::string& durable) {
        XmrReceiptIngest::Options o;
        o.chain = kChain; o.order = XmrReceiptIngest::Order::Canonical; o.bin_lag = 1; o.grace_ms = 0;
        o.durable_path = durable;
        ing = std::make_unique<XmrReceiptIngest>(
            o,
            [this](const ::v37::ScriptRef& p, u64 w, u64& na, bytes32& d) { return lane.push(p, w, na, d); },
            nullptr);
    }
    void admit(const Admitted& a) { ing->on_admitted(a); }
    void close_through(u64 template_height) { ing->tick(template_height, Clock::now() + 1h); }
};

static bytes32 prev_of(u64 h) { return b32_of(static_cast<u8>(h)); }

static Admitted receipt_at(u64 h, u32 k, Checker& C) {
    const SynthBlock sb = make_block(h, prev_of(h), k, nullptr, 1, static_cast<u8>(k));
    Admitted a;
    std::string why;
    const bool ok = mint_on(sb, k * 7919u, payee_of("miner" + std::to_string(k % 3)), kChain, kShareDiff, a.r, &why);
    if (!ok) C(false, "N3 mint receipt h=" + std::to_string(h) + " k=" + std::to_string(k) + ": " + why);
    a.id = receipt_id(a.r);
    a.raw = encode_fb_receipt(a.r);
    a.bin = h;
    return a;
}

// The digest two nodes compare. With lane_set() present (the fix) it is the
// order-free lane set through `through`; on the base tree it is what the
// nodes compared there: the lane digest.
static std::string compared(INode& n, u64 through) {
#ifdef C2POOL_XMR_LANE_SET_DIGEST
    const auto s = n.ing->lane_set(through);
    return hex(s.digest) + "/n=" + std::to_string(s.n) + "/unbinned=" + std::to_string(s.unbinned);
#else
    (void)through;
    return hex(n.lane.dig);
#endif
}

int main() {
    Checker C;
    std::printf("== v37_xmr_relay_noise_kat ==\n");

    // ── N1 refused peer: redial backoff during a partition ──────────────────
    {
        std::printf("-- N1 refused peer: B dials a partitioned A for 16 s\n");
        RNode A(opts(true, {}));
        std::string why;
        C(A.relay->start(why), "N1 A starts (listening)");
        RNode B(opts(false, {A.relay->listen_port()}));
        C(B.relay->start(why), "N1 B starts (dialing A)");
        C(wait_until([&] { return A.relay->stats().hello_ok.load() >= 1 && B.relay->stats().hello_ok.load() >= 1; }, 10000ms),
          "N1 A<->B HELLO ok before the partition");
        const u64 ha0 = A.relay->stats().hello_ok.load(), hb0 = B.relay->stats().hello_ok.load();
        const u64 d0 = B.relay->stats().dials.load();
        const u64 t0 = A.relay->stats().hello_timeout.load() + B.relay->stats().hello_timeout.load();
        A.relay->partition_for(std::chrono::seconds(16));
        const auto p0 = std::chrono::steady_clock::now();
        std::this_thread::sleep_for(16s);
        const u64 dials = B.relay->stats().dials.load() - d0;
        const u64 tmo = A.relay->stats().hello_timeout.load() + B.relay->stats().hello_timeout.load() - t0;
        const bool healed = wait_until([&] {
            return A.relay->stats().hello_ok.load() > ha0 && B.relay->stats().hello_ok.load() > hb0;
        }, 25000ms);
        const double heal_s = std::chrono::duration<double>(std::chrono::steady_clock::now() - p0).count() - 16.0;
        std::printf("    B dials during the 16 s partition=%llu (base ~1/s), HELLO timeouts=%llu; healed=%d %.1f s after it\n",
                    (unsigned long long)dials, (unsigned long long)tmo, healed ? 1 : 0, heal_s);
        C(dials >= 2, "N1 B still retries the refusing peer (" + std::to_string(dials) + " dials)");
        C(dials <= 6, "N1 refused links back off: <= 6 dials in 16 s (got " + std::to_string(dials) + ")");
        C(tmo == 0, "N1 a refused link is never counted as a HELLO timeout");
        C(healed, "N1 relay heals after the partition (fresh HELLO ok on A and B)");
        C(heal_s <= 20.0, "N1 heal within the 16 s backoff cap + slack (" + std::to_string(heal_s) + " s)");
    }

    // ── N2 silent peer: HELLO-timeout backoff ───────────────────────────────
    {
        std::printf("-- N2 silent peer: a listener that never answers HELLO, 0.5 s timeout, 12 s\n");
        const int ls = ::socket(AF_INET, SOCK_STREAM, 0);
        sockaddr_in a{}; a.sin_family = AF_INET; a.sin_port = 0;
        ::inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);
        int one = 1; ::setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
        const bool bound = ::bind(ls, reinterpret_cast<sockaddr*>(&a), sizeof(a)) == 0 && ::listen(ls, 64) == 0;
        socklen_t al = sizeof(a); ::getsockname(ls, reinterpret_cast<sockaddr*>(&a), &al);
        C(bound, "N2 silent listener up");
        // accept and hold every connection, never write (a hung / overloaded peer)
        std::atomic<bool> run{true};
        std::vector<int> held;
        std::thread acc([&] {
            while (run.load()) {
                fd_set rs; FD_ZERO(&rs); FD_SET(ls, &rs);
                timeval tv{0, 100000};
                if (::select(ls + 1, &rs, nullptr, nullptr, &tv) > 0) {
                    const int c = ::accept(ls, nullptr, nullptr);
                    if (c >= 0) held.push_back(c);
                }
            }
        });
        {
            RNode B(opts(false, {ntohs(a.sin_port)}, 500));
            std::string why;
            C(B.relay->start(why), "N2 B starts (dialing the silent peer)");
            std::this_thread::sleep_for(12s);
            const u64 tmo = B.relay->stats().hello_timeout.load();
            const u64 dials = B.relay->stats().dials.load();
            std::printf("    silent peer over 12 s: HELLO timeouts=%llu dials=%llu (base ~1 per 1.75 s)\n",
                        (unsigned long long)tmo, (unsigned long long)dials);
            C(tmo >= 1, "N2 the silent link is timed out (" + std::to_string(tmo) + ")");
            C(tmo <= 4, "N2 HELLO timeouts back off: <= 4 in 12 s (got " + std::to_string(tmo) + ")");
        }
        run = false; acc.join();
        for (int c : held) ::close(c);
        ::close(ls);
    }

    // ── N3 compared lane digest converges after partition + heal / restart ──
    {
        std::printf("-- N3 lane-set digest: partition + heal, then a restart from the durable log\n");
        const auto dir = std::filesystem::temp_directory_path() / ("v37_noise_kat_" + std::to_string(::getpid()));
        std::filesystem::remove_all(dir);
        std::filesystem::create_directories(dir);
        INode X((dir / "x.receipts").string()), Y((dir / "y.receipts").string());
        // bins 100, 101: both nodes see the same receipts, in different arrival orders
        std::vector<Admitted> b100{receipt_at(100, 1, C), receipt_at(100, 2, C), receipt_at(100, 3, C)};
        std::vector<Admitted> b101{receipt_at(101, 4, C), receipt_at(101, 5, C)};
        for (const auto& r : b100) X.admit(r);
        for (auto it = b100.rbegin(); it != b100.rend(); ++it) Y.admit(*it);
        X.admit(b101[0]); X.admit(b101[1]); Y.admit(b101[1]); Y.admit(b101[0]);
        X.close_through(102); Y.close_through(102);
        C(X.lane.dig == Y.lane.dig, "N3 same receipts per closed bin -> same lane digest (canonical bins)");
        // bin 102 under a PARTITION: X and Y each see only their own side's receipts
        const Admitted x1 = receipt_at(102, 6, C), x2 = receipt_at(102, 7, C), y1 = receipt_at(102, 8, C);
        X.admit(x1); X.admit(x2); Y.admit(y1);
        X.close_through(103); Y.close_through(103);
        C(compared(X, 102) != compared(Y, 102), "N3 during the partition the nodes differ (sanity)");
        // HEAL: the backfill delivers what the partition withheld -- LATE (bin 102 closed)
        X.admit(y1); Y.admit(x2); Y.admit(x1);
        // bin 103: normal again
        const Admitted c1 = receipt_at(103, 9, C);
        X.admit(c1); Y.admit(c1);
        X.close_through(104); Y.close_through(104);
        C(X.lane.next == Y.lane.next && X.lane.next == 9, "N3 both lanes hold all 9 receipts after the heal");
        std::printf("    lane digest X=%s… Y=%s… (node-local order)\n", hex(X.lane.dig).substr(0, 16).c_str(),
                    hex(Y.lane.dig).substr(0, 16).c_str());
        C(X.lane.dig != Y.lane.dig, "N3 the lane DIGEST stays different after the heal (late tail order: by design)");
        const std::string cx102 = compared(X, 102), cy102 = compared(Y, 102);
        const std::string cx103 = compared(X, 103), cy103 = compared(Y, 103);
        std::printf("    compared through 102: X=%s Y=%s\n", cx102.substr(0, 16).c_str(), cy102.substr(0, 16).c_str());
        std::printf("    compared through 103: X=%s Y=%s\n", cx103.substr(0, 16).c_str(), cy103.substr(0, 16).c_str());
        C(cx102 == cy102, "N3 compared digest EQUAL on both nodes after the heal (through bin 102)");
        C(cx103 == cy103, "N3 compared digest EQUAL on both nodes after the heal (through bin 103)");
        C(compared(X, 101) != cx102, "N3 the compared digest commits to the bins it covers");
        // RESTART: Z rebuilds X's lane from X's durable log (reloaded receipts carry no bin)
        {
            INode Z((dir / "x.receipts").string());
#ifdef C2POOL_XMR_LANE_SET_DIGEST
            const std::size_t n = Z.ing->reload(nullptr);
            C(n == 9, "N3 restart: 9 receipts reloaded from the durable log");
            C(Z.lane.dig == X.lane.dig, "N3 restart: lane rebuilt byte-identically (its own order)");
            const auto before = Z.ing->lane_set(103);
            C(before.unbinned == 9, "N3 restart: bins unknown until the chain view resolves prev_id (unbinned=" +
                                         std::to_string(before.unbinned) + ")");
            std::map<bytes32, u64> view;
            for (u64 h = 100; h <= 103; ++h) view[prev_of(h)] = h;
            Z.ing->set_bin_of([&](const FbReceipt& r) -> std::optional<u64> {
                ::v37::xmr::verify::ParsedBlob pb;
                if (!::v37::xmr::verify::parse_hashing_blob(r.receipt.hashing_blob, pb)) return std::nullopt;
                auto it = view.find(pb.prev_id);
                if (it == view.end()) return std::nullopt;
                return it->second;
            });
            C(compared(Z, 103) == cx103, "N3 restart: compared digest equal to the peers' once bins resolve");
            C(compared(Z, 102) == cy102, "N3 restart: equal through bin 102 too");
#else
            (void)Z;
            C(false, "N3 restart: no order-free compared digest on this tree");
#endif
        }
#ifdef C2POOL_XMR_LANE_SET_DIGEST
        {   // a bin still held back (not closed: the tip jumped inside the grace) is never covered
            X.admit(receipt_at(104, 10, C));
            const auto s = X.ing->lane_set(105);
            C(s.through == 103 && s.n == 9, "N3 lane_set never covers a bin this node still holds back (through=" +
                                                 std::to_string(s.through) + " n=" + std::to_string(s.n) + ")");
        }
#endif
        std::filesystem::remove_all(dir);
    }
    return C.done("v37_xmr_relay_noise_kat");
}
