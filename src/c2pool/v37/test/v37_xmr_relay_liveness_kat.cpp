// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// v37_xmr_relay_liveness_kat -- RELAY-LIVENESS + RELAY-BINCLOCK (capstone
// attempt 2, defects 2 and 5).
//
// Defect 2: the WAN relay link between C and A/B went silent in BOTH
// directions for ~3.5 min while TCP kept both sessions established (conns=2
// ready=2 throughout). Nothing was read, nothing refused, no down event fired,
// so no liveness check dropped or refreshed the sessions and both sides closed
// lane bins without each other's receipts.
// Defect 5: after node A's restart into a suspended lane its relay-lane-set
// stopped closing bins (through_bin stuck, bins_closed=1, pending bins
// growing): the canonical ingest's bin clock was the SERVED TEMPLATE height,
// which a suspended lane never advances.
//
//   L1  FB_PING/FB_PONG codec: 10 bytes, round-trips, a bad length / opcode /
//       version is refused; both opcodes sit in the Family-B namespace
//   L2  SILENT STALL: two relay nodes over an in-process TCP forwarder that can
//       BLACKHOLE its flows (the TCP sessions stay established, nothing is
//       forwarded either way -- a dead WAN path). Both nodes must detect the
//       silence within the silence timeout (+ slack), log LINK SILENT, count
//       silent_drops, and -- once the path works again for new flows --
//       redial and reach HELLO ok on both sides again.
//   L3  LEGACY PEER: a raw peer that completes HELLO but never answers a PING
//       (a pre-0x48 build) is NOT dropped for silence (kept > 3 silence
//       timeouts) and is counted as legacy once.
//   L4  keepalive_ms = 0: no PING goes out (the pre-liveness wire)
//   L5  BIN CLOCK: an ingest whose served template height is frozen (a
//       suspended lane) while the chain moves on still closes every bin whose
//       window passed, and the lane-set `through` follows the chain (RED on
//       the base: the template clock never closes them).
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <list>
#include <memory>
#include <mutex>
#include <thread>

#include "xmr_relay_test_util.hpp"
#include <c2pool/v37/carrier_net.hpp>
#include <c2pool/v37/xmr/relay/xmr_relay_node.hpp>
#include <c2pool/v37/xmr/relay/xmr_receipt_ingest.hpp>

using namespace gap2test;
using namespace std::chrono_literals;
using c2pool::v37n::CarrierPeerNode;
using SClock = std::chrono::steady_clock;

static constexpr u32 kChain = 7;
static constexpr u64 kShareDiff = 1000;

template <class F>
static bool wait_until(F cond, std::chrono::milliseconds limit) {
    const auto dl = SClock::now() + limit;
    while (SClock::now() < dl) {
        if (cond()) return true;
        std::this_thread::sleep_for(20ms);
    }
    return cond();
}
static long long ms_since(SClock::time_point t) {
    return std::chrono::duration_cast<std::chrono::milliseconds>(SClock::now() - t).count();
}

// ── the fix's knobs, set only where they exist (the KAT builds on the base
// tree and goes red on the behaviour, not on a compile error) ──────────────
template <class O> static void set_liveness(O& o, u32 keepalive_ms, u32 silence_ms) {
    if constexpr (requires { o.keepalive_ms; o.silence_timeout_ms; }) {
        o.keepalive_ms = keepalive_ms; o.silence_timeout_ms = silence_ms;
    }
}
template <class S> static long long silent_drops(const S& s) {
    if constexpr (requires { s.silent_drops.load(); }) return static_cast<long long>(s.silent_drops.load());
    else return -1;
}
template <class S> static long long ka_legacy(const S& s) {
    if constexpr (requires { s.ka_legacy.load(); }) return static_cast<long long>(s.ka_legacy.load());
    else return -1;
}
template <class S> static long long ping_tx(const S& s) {
    if constexpr (requires { s.ping_tx.load(); }) return static_cast<long long>(s.ping_tx.load());
    else return -1;
}
template <class S> static long long pong_rx(const S& s) {
    if constexpr (requires { s.pong_rx.load(); }) return static_cast<long long>(s.pong_rx.load());
    else return -1;
}

static RelayOptions opts(bool listen, std::vector<u16> dial, u32 keepalive_ms, u32 silence_ms) {
    RelayOptions o;
    o.network = 3; o.chain = kChain; o.share_diff = kShareDiff; o.bind = BindMode::None;
    o.lane_params_digest = lane_params_digest(::v37::LaneParams{}, kShareDiff, BindMode::None);
    o.listen = listen; o.listen_host = "127.0.0.1"; o.listen_port = 0;
    for (u16 p : dial) o.peers.emplace_back("127.0.0.1", p);
    o.hello_timeout_ms = 1500;
    set_liveness(o, keepalive_ms, silence_ms);
    return o;
}

struct RNode {
    ChainView chain;
    std::mutex lmtx;
    std::vector<std::string> logs;
    std::unique_ptr<XmrRelayNode> relay;
    explicit RNode(RelayOptions o) {
        relay = std::make_unique<XmrRelayNode>(
            std::move(o), chain,
            [](const std::vector<u8>&, const bytes32&, bytes32& pow) { pow.fill(0); return true; },
            []() -> std::pair<u64, bytes32> { return {0, bytes32{}}; },
            [this](const std::string& s) { std::lock_guard<std::mutex> lk(lmtx); logs.push_back(s); });
    }
    ~RNode() { relay->stop(); }
    std::size_t count_log(const std::string& needle) {
        std::lock_guard<std::mutex> lk(lmtx);
        std::size_t n = 0;
        for (const auto& l : logs) if (l.find(needle) != std::string::npos) ++n;
        return n;
    }
    std::string first_log(const std::string& needle) {
        std::lock_guard<std::mutex> lk(lmtx);
        for (const auto& l : logs) if (l.find(needle) != std::string::npos) return l;
        return "";
    }
};

// ── a TCP forwarder whose flows can be BLACKHOLED ──────────────────────────
// blackhole(true): every flow open now, and every flow accepted until
// blackhole(false), is DEAD: both directions are read and DISCARDED (so no
// sender ever blocks and no socket ever closes -- the TCP sessions stay
// established, exactly a dead WAN path under a live NAT mapping). A dead
// flow stays dead for good; one side closing it is never propagated. Flows
// accepted after blackhole(false) forward normally.
class BlackholeProxy {
public:
    explicit BlackholeProxy(u16 upstream) : m_up(upstream) {
        m_lfd = ::socket(AF_INET, SOCK_STREAM, 0);
        int one = 1; ::setsockopt(m_lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
        sockaddr_in a{}; a.sin_family = AF_INET; a.sin_addr.s_addr = htonl(INADDR_LOOPBACK); a.sin_port = 0;
        ::bind(m_lfd, reinterpret_cast<sockaddr*>(&a), sizeof a);
        ::listen(m_lfd, 16);
        socklen_t al = sizeof a; ::getsockname(m_lfd, reinterpret_cast<sockaddr*>(&a), &al);
        m_port = ntohs(a.sin_port);
        m_acc = std::thread([this] { accept_loop(); });
    }
    ~BlackholeProxy() {
        m_run = false;
        ::shutdown(m_lfd, SHUT_RDWR); ::close(m_lfd);
        if (m_acc.joinable()) m_acc.join();
        {
            std::lock_guard<std::mutex> lk(m_mtx);
            for (auto& f : m_flows) { ::shutdown(f->a, SHUT_RDWR); ::shutdown(f->b, SHUT_RDWR); }
        }
        for (auto& t : m_threads) if (t.joinable()) t.join();
        std::lock_guard<std::mutex> lk(m_mtx);
        for (auto& f : m_flows) { ::close(f->a); ::close(f->b); }
    }
    u16 port() const { return m_port; }
    void blackhole(bool on) {
        std::lock_guard<std::mutex> lk(m_mtx);
        m_black = on;
        if (on) for (auto& f : m_flows) f->dead = true;
    }
private:
    struct Flow { int a = -1, b = -1; std::atomic<bool> dead{false}; };
    void accept_loop() {
        while (m_run) {
            const int c = ::accept(m_lfd, nullptr, nullptr);
            if (c < 0) { if (!m_run) return; std::this_thread::sleep_for(10ms); continue; }
            const int u = ::socket(AF_INET, SOCK_STREAM, 0);
            sockaddr_in a{}; a.sin_family = AF_INET; a.sin_addr.s_addr = htonl(INADDR_LOOPBACK); a.sin_port = htons(m_up);
            if (::connect(u, reinterpret_cast<sockaddr*>(&a), sizeof a) != 0) { ::close(u); ::close(c); continue; }
            auto f = std::make_shared<Flow>(); f->a = c; f->b = u;
            std::lock_guard<std::mutex> lk(m_mtx);
            f->dead = m_black;
            m_flows.push_back(f);
            m_threads.emplace_back([this, f] { pump(f, f->a, f->b); });
            m_threads.emplace_back([this, f] { pump(f, f->b, f->a); });
        }
    }
    void pump(std::shared_ptr<Flow> f, int from, int to) {
        std::vector<char> buf(65536);
        for (;;) {
            const ssize_t n = ::recv(from, buf.data(), buf.size(), 0);
            if (n <= 0) break;
            if (f->dead) continue;                    // blackholed: swallow
            ssize_t off = 0;
            while (off < n) {
                const ssize_t k = ::send(to, buf.data() + off, static_cast<std::size_t>(n - off), MSG_NOSIGNAL);
                if (k <= 0) break;
                off += k;
            }
        }
        if (!f->dead) ::shutdown(to, SHUT_RDWR);      // a live flow propagates the close; a dead one never does
    }
    u16 m_up = 0, m_port = 0;
    int m_lfd = -1;
    std::atomic<bool> m_run{true};
    bool m_black = false;
    std::mutex m_mtx;
    std::list<std::shared_ptr<Flow>> m_flows;
    std::list<std::thread> m_threads;
    std::thread m_acc;
};

int main() {
    Checker C;
    std::printf("== v37_xmr_relay_liveness_kat ==\n");
#ifdef C2POOL_XMR_RELAY_LIVENESS
    std::printf("   (RELAY-LIVENESS present)\n");
#else
    std::printf("   (RELAY-LIVENESS ABSENT: base tree)\n");
#endif

    // ── L1 codec ────────────────────────────────────────────────────────────
    {
        std::printf("-- L1 FB_PING / FB_PONG codec\n");
#ifdef C2POOL_XMR_RELAY_LIVENESS
        const auto f = encode_ping(FB_PING, 0x1122334455667788ull);
        C(f.size() == 10 && f[0] == 0x48 && f[1] == kFbVersion && f[2] == 0x88 && f[9] == 0x11,
          "L1 PING = 48 01 | u64 LE nonce (10 B): " + hex(f));
        u8 op = 0; u64 n = 0;
        C(decode_ping(f, op, n) && op == FB_PING && n == 0x1122334455667788ull, "L1 PING round-trips");
        const auto g = encode_ping(FB_PONG, 7);
        C(g.size() == 10 && g[0] == 0x49 && decode_ping(g, op, n) && op == FB_PONG && n == 7, "L1 PONG = 49 01 | nonce, round-trips");
        auto bad = f; bad.push_back(0);
        C(!decode_ping(bad, op, n), "L1 wrong length refused");
        bad = f; bad[1] = 2;
        C(!decode_ping(bad, op, n), "L1 unknown version refused");
        bad = f; bad[0] = FB_CTX;
        C(!decode_ping(bad, op, n) && encode_ping(FB_HELLO, 1).empty(), "L1 wrong opcode refused / not encoded");
        C(is_family_b_opcode(FB_PING) && is_family_b_opcode(FB_PONG), "L1 0x48/0x49 inside the Family-B namespace (a pre-0x45 node counts them fb_unknown)");
#else
        C(false, "L1 FB_PING/FB_PONG codec absent");
#endif
    }

    // ── L2 silent stall ─────────────────────────────────────────────────────
    {
        std::printf("-- L2 silent stall (blackholed flows, TCP still established)\n");
        constexpr u32 kKeep = 200, kSilence = 1500;
        RNode X(opts(true, {}, kKeep, kSilence));
        std::string why;
        C(X.relay->start(why), "L2 X starts (" + why + ")");
        BlackholeProxy px(X.relay->listen_port());
        RNode Y(opts(false, {px.port()}, kKeep, kSilence));
        C(Y.relay->start(why), "L2 Y starts, dialing X through the forwarder");
        const bool up = wait_until([&] { return X.relay->ready_peers().size() == 1 && Y.relay->ready_peers().size() == 1; }, 5000ms);
        C(up, "L2 X<->Y HELLO ok through the forwarder");
        std::this_thread::sleep_for(600ms);   // a few keepalive rounds
        std::printf("    before stall: X ping_tx=%lld pong_rx=%lld | Y ping_tx=%lld pong_rx=%lld\n",
                    ping_tx(X.relay->stats()), pong_rx(X.relay->stats()), ping_tx(Y.relay->stats()), pong_rx(Y.relay->stats()));
        C(pong_rx(X.relay->stats()) > 0 && pong_rx(Y.relay->stats()) > 0, "L2 keepalive answered both ways on a healthy link");
        const u64 hx0 = X.relay->stats().hello_ok.load(), hy0 = Y.relay->stats().hello_ok.load();

        const auto t0 = SClock::now();
        px.blackhole(true);
        long long dx = -1, dy = -1;
        const bool gone = wait_until([&] {
            if (dx < 0 && X.relay->ready_peers().empty()) dx = ms_since(t0);
            if (dy < 0 && Y.relay->ready_peers().empty()) dy = ms_since(t0);
            return dx >= 0 && dy >= 0;
        }, std::chrono::milliseconds(kSilence + 2500));
        std::printf("    detection: X %lld ms, Y %lld ms (silence timeout %u ms; -1 = never within %u ms) | conns X=%zu Y=%zu\n",
                    dx, dy, kSilence, kSilence + 2500, X.relay->n_connections(), Y.relay->n_connections());
        C(gone, "L2 BOTH sides drop the silent link (TCP still up) within the silence timeout + 2.5 s");
        C(dx >= static_cast<long long>(kSilence) - 300 && dy >= static_cast<long long>(kSilence) - 300,
          "L2 ... and not before the silence timeout (no false drop of a merely quiet link)");
        C(silent_drops(X.relay->stats()) >= 1 && silent_drops(Y.relay->stats()) >= 1,
          "L2 silent_drops counted on both sides (X=" + std::to_string(silent_drops(X.relay->stats())) +
          " Y=" + std::to_string(silent_drops(Y.relay->stats())) + ")");
        const std::string ly = Y.first_log("LINK SILENT");
        std::printf("    Y log: %s\n", ly.c_str());
        C(!ly.empty() && X.count_log("LINK SILENT") >= 1, "L2 the drop is logged loudly (LINK SILENT) on both sides");

        std::this_thread::sleep_for(1000ms);  // the dead path persists a little longer
        px.blackhole(false);                  // new flows work again (the dead ones stay dead)
        const auto t1 = SClock::now();
        const bool healed = wait_until([&] {
            return X.relay->stats().hello_ok.load() > hx0 && Y.relay->stats().hello_ok.load() > hy0 &&
                   X.relay->ready_peers().size() == 1 && Y.relay->ready_peers().size() == 1;
        }, 20000ms);
        std::printf("    re-HELLO after the path returned: %lld ms (hello_ok X %llu->%llu Y %llu->%llu)\n", ms_since(t1),
                    (unsigned long long)hx0, (unsigned long long)X.relay->stats().hello_ok.load(),
                    (unsigned long long)hy0, (unsigned long long)Y.relay->stats().hello_ok.load());
        C(healed, "L2 Y redials: a fresh HELLO on both sides once the path works again");
        const std::string dx_s = X.relay->describe();
        const auto lp = dx_s.find("liveness");
        std::printf("    X %s\n", dx_s.substr(lp == std::string::npos ? dx_s.size() : lp).c_str());
    }

    // ── L3 legacy peer ──────────────────────────────────────────────────────
    {
        std::printf("-- L3 a pre-keepalive peer (HELLO, never a PONG) is not timed out\n");
        constexpr u32 kKeep = 200, kSilence = 1000;
        RNode X(opts(true, {}, kKeep, kSilence));
        std::string why;
        C(X.relay->start(why), "L3 X starts");
        CarrierPeerNode raw;
        std::atomic<bool> dropped{false};
        raw.set_on_peer_event([&](CarrierPeerNode::PeerId, bool up) { if (!up) dropped = true; });
        const auto pid = raw.add_peer_id("127.0.0.1", X.relay->listen_port());
        C(pid != 0, "L3 raw peer connects");
        Hello h = X.relay->our_hello(); h.node_nonce ^= 0x5a5a5a5aull; h.listen_port = 0;
        raw.send_to(pid, encode_hello(h));
        C(wait_until([&] { return X.relay->ready_peers().size() == 1; }, 3000ms), "L3 raw peer HELLO ok at X");
        std::this_thread::sleep_for(std::chrono::milliseconds(4 * kSilence));
        C(!dropped.load() && X.relay->ready_peers().size() == 1,
          "L3 the never-answering peer is KEPT past 4 silence timeouts (silent_drops=" + std::to_string(silent_drops(X.relay->stats())) + ")");
#ifdef C2POOL_XMR_RELAY_LIVENESS
        C(ka_legacy(X.relay->stats()) == 1, "L3 counted as legacy exactly once (" + std::to_string(ka_legacy(X.relay->stats())) + ")");
        C(ping_tx(X.relay->stats()) <= 4, "L3 probing stops after 3 unanswered PINGs (ping_tx=" + std::to_string(ping_tx(X.relay->stats())) + ")");
#endif
        raw.stop();
    }

    // ── L4 keepalive off ────────────────────────────────────────────────────
    {
        std::printf("-- L4 keepalive_ms = 0: no PING on the wire\n");
        RNode X(opts(true, {}, 0, 0));
        std::string why;
        C(X.relay->start(why), "L4 X starts");
        RNode Y(opts(false, {X.relay->listen_port()}, 0, 0));
        C(Y.relay->start(why), "L4 Y starts");
        C(wait_until([&] { return X.relay->ready_peers().size() == 1 && Y.relay->ready_peers().size() == 1; }, 5000ms), "L4 HELLO ok");
        std::this_thread::sleep_for(800ms);
        C(ping_tx(X.relay->stats()) <= 0 && ping_tx(Y.relay->stats()) <= 0 &&
          X.relay->stats().fb_unknown.load() == 0 && Y.relay->stats().fb_unknown.load() == 0,
          "L4 no PING sent, nothing unknown received (the pre-liveness wire)");
    }

    // ── L5 bin clock under a frozen template ────────────────────────────────
    {
        std::printf("-- L5 bins close while the served template is frozen (suspended lane)\n");
        XmrReceiptIngest::Options io; io.chain = kChain; io.bin_lag = 1; io.grace_ms = 4000;
        u64 next = 0;
        XmrReceiptIngest ing(io,
            [&](const ::v37::ScriptRef&, u64, u64& n_after, bytes32& d) { n_after = ++next; d.fill(0); return true; },
            nullptr);
        const auto payee = payee_of("liveness-L5");
        auto admit = [&](u64 bin, u8 salt) {
            Admitted a; a.id = b32_of(salt); a.bin = bin; a.r.payee = payee; a.raw = {salt};
            ing.on_admitted(std::move(a));
        };
        // the clock the daemon uses: bin_close_height() on the fix, the template height on the base
        auto clock = [](u64 tpl, u64 hw) -> u64 {
#ifdef C2POOL_XMR_INGEST_CHAIN_CLOCK
            return bin_close_height(tpl, hw);
#else
            (void)hw; return tpl;
#endif
        };
        const u64 kTpl = 1000;                 // frozen: the lane was suspended at this template
        auto t = SClock::now();
        ing.tick(clock(kTpl, kTpl - 1), t);
        for (u64 hw = kTpl; hw <= kTpl + 10; ++hw) {     // the chain moves on; peers' receipts keep arriving
            admit(hw, static_cast<u8>(hw - kTpl + 1));
            admit(hw, static_cast<u8>(hw - kTpl + 101));
            t += 30s;                                    // one block per 30 s, far over the 4 s grace
            ing.tick(clock(kTpl, hw), t);
            ing.tick(clock(kTpl, hw), t + 5s);
        }
        const u64 th = clock(kTpl, kTpl + 10);
        const auto ls = ing.lane_set(th > 2 ? th - 2 : 0);
        std::printf("    template frozen at %llu, chain hw -> %llu: bins_closed=%llu pending=%zu(bins=%zu) lane-set through=%llu n=%llu\n",
                    (unsigned long long)kTpl, (unsigned long long)(kTpl + 10), (unsigned long long)ing.stats().bins_closed,
                    ing.pending_receipts(), ing.pending_bins(), (unsigned long long)ls.through, (unsigned long long)ls.n);
        C(ing.stats().bins_closed >= 10, "L5 every bin whose window passed on the CHAIN closed (bins_closed=" +
                                              std::to_string(ing.stats().bins_closed) + " >= 10)");
        C(ing.pending_bins() <= 1, "L5 at most the tip bin is still pending (" + std::to_string(ing.pending_bins()) + ")");
        C(ls.through >= kTpl + 8, "L5 lane-set through follows the chain (" + std::to_string(ls.through) + " >= " +
                                      std::to_string(kTpl + 8) + ")");
#ifdef C2POOL_XMR_INGEST_CHAIN_CLOCK
        C(bin_close_height(1000, 0) == 1000 && bin_close_height(1000, 998) == 1000 && bin_close_height(1000, 1500) == 1501 &&
          bin_close_height(0, 5) == 6, "L5 bin_close_height = max(template, chain hw + 1); hw 0 = unknown");
#endif
    }

    return C.done("v37_xmr_relay_liveness_kat");
}
