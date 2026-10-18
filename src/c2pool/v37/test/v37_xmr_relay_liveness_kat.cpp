// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// v37_xmr_relay_liveness_kat -- RELAY-LIVENESS on the Path B relay node.
//
// A WAN relay link can go silent in BOTH directions while TCP keeps both
// sessions established: nothing is read, nothing refused, no down event fires.
//
//   L1  FB_PING/FB_PONG codec: 10 bytes, round-trips, a bad length / opcode /
//       version is refused; both opcodes sit in the Family-B namespace
//   L2  SILENT STALL: two Path B relay nodes over an in-process TCP forwarder
//       that can BLACKHOLE its flows (the TCP sessions stay established,
//       nothing is forwarded either way -- a dead WAN path). Both nodes must
//       detect the silence within the silence timeout (+ slack), log LINK
//       SILENT, count silent_drops, and -- once the path works again for new
//       flows -- redial and reach HELLO ok on both sides again.
//   L3  LEGACY PEER: a raw peer that completes HELLO but never answers a PING
//       is NOT dropped for silence (kept > 3 silence timeouts) and is counted
//       as legacy once.
//   L4  keepalive_ms = 0: no PING goes out
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

#include "xmr_pathb_relay_test_util.hpp"
#include <c2pool/v37/carrier_net.hpp>

using namespace pathb_relay_test;
using namespace std::chrono_literals;
using c2pool::v37n::CarrierPeerNode;
using SClock = std::chrono::steady_clock;

static long long ms_since(SClock::time_point t) {
    return std::chrono::duration_cast<std::chrono::milliseconds>(SClock::now() - t).count();
}

static pb::PathbRelayOptions opts(bool listen, std::vector<std::uint16_t> dial, u32 keepalive_ms, u32 silence_ms) {
    pb::PathbRelayOptions o = Rig::opts(listen, dial);
    o.hello_timeout_ms = 1500;
    o.keepalive_ms = keepalive_ms;
    o.silence_timeout_ms = silence_ms;
    return o;
}

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

    // ── L1 codec ────────────────────────────────────────────────────────────
    {
        std::printf("-- L1 FB_PING / FB_PONG codec\n");
        const auto f = encode_ping(FB_PING, 0x1122334455667788ull);
        C(f.size() == 10 && f[0] == 0x48 && f[1] == pb::kFrameVersion1 && f[2] == 0x88 && f[9] == 0x11,
          "L1 PING = 48 01 | u64 LE nonce (10 B): " + hex(f));
        u8 op = 0; u64 n = 0;
        C(decode_ping(f, op, n) && op == FB_PING && n == 0x1122334455667788ull, "L1 PING round-trips");
        const auto g = encode_ping(FB_PONG, 7);
        C(g.size() == 10 && g[0] == 0x49 && decode_ping(g, op, n) && op == FB_PONG && n == 7, "L1 PONG = 49 01 | nonce, round-trips");
        auto bad = f; bad.push_back(0);
        C(!decode_ping(bad, op, n), "L1 wrong length refused");
        bad = f; bad[1] = 2;
        C(!decode_ping(bad, op, n), "L1 unknown version refused");
        bad = f; bad[0] = pb::kOpFbCtx;
        C(!decode_ping(bad, op, n) && encode_ping(pb::kOpFbHello, 1).empty(), "L1 wrong opcode refused / not encoded");
        C(FB_PING == pb::kOpFbPing && FB_PONG == pb::kOpFbPong && pb::kOpFbPing >= 0x40 && pb::kOpFbPong <= 0x4f,
          "L1 0x48/0x49 inside the Family-B namespace (the Path B relay's PING / PONG)");
    }

    // ── L2 silent stall ─────────────────────────────────────────────────────
    {
        std::printf("-- L2 silent stall (blackholed flows, TCP still established)\n");
        constexpr u32 kKeep = 200, kSilence = 1500;
        Rig rig;
        auto X = rig.make("X", opts(true, {}, kKeep, kSilence));
        std::string why;
        C(X->start(why), "L2 X starts (" + why + ")");
        BlackholeProxy px(X->port());
        auto Y = rig.make("Y", opts(false, {px.port()}, kKeep, kSilence));
        C(Y->start(why), "L2 Y starts, dialing X through the forwarder");
        const bool up = wait_until([&] { return X->r().ready_peers().size() == 1 && Y->r().ready_peers().size() == 1; }, 5000ms);
        C(up, "L2 X<->Y HELLO ok through the forwarder");
        std::this_thread::sleep_for(600ms);   // a few keepalive rounds
        std::printf("    before stall: X ping_tx=%llu pong_rx=%llu | Y ping_tx=%llu pong_rx=%llu\n",
                    (unsigned long long)X->st().ping_tx.load(), (unsigned long long)X->st().pong_rx.load(),
                    (unsigned long long)Y->st().ping_tx.load(), (unsigned long long)Y->st().pong_rx.load());
        C(X->st().pong_rx.load() > 0 && Y->st().pong_rx.load() > 0, "L2 keepalive answered both ways on a healthy link");
        const u64 hx0 = X->st().hello_ok.load(), hy0 = Y->st().hello_ok.load();

        const auto t0 = SClock::now();
        px.blackhole(true);
        long long dx = -1, dy = -1;
        const bool gone = wait_until([&] {
            if (dx < 0 && X->r().ready_peers().empty()) dx = ms_since(t0);
            if (dy < 0 && Y->r().ready_peers().empty()) dy = ms_since(t0);
            return dx >= 0 && dy >= 0;
        }, std::chrono::milliseconds(kSilence + 2500));
        std::printf("    detection: X %lld ms, Y %lld ms (silence timeout %u ms; -1 = never within %u ms) | conns X=%zu Y=%zu\n",
                    dx, dy, kSilence, kSilence + 2500, X->links.n_peers(), Y->links.n_peers());
        C(gone, "L2 BOTH sides drop the silent link (TCP still up) within the silence timeout + 2.5 s");
        C(dx >= static_cast<long long>(kSilence) - 300 && dy >= static_cast<long long>(kSilence) - 300,
          "L2 ... and not before the silence timeout (no false drop of a merely quiet link)");
        C(X->st().silent_drops.load() >= 1 && Y->st().silent_drops.load() >= 1,
          "L2 silent_drops counted on both sides (X=" + std::to_string(X->st().silent_drops.load()) +
          " Y=" + std::to_string(Y->st().silent_drops.load()) + ")");
        const std::string ly = Y->first_log("LINK SILENT");
        std::printf("    Y log: %s\n", ly.c_str());
        C(!ly.empty() && X->count_logs("LINK SILENT") >= 1, "L2 the drop is logged loudly (LINK SILENT) on both sides");

        std::this_thread::sleep_for(1000ms);  // the dead path persists a little longer
        px.blackhole(false);                  // new flows work again (the dead ones stay dead)
        const auto t1 = SClock::now();
        const bool healed = wait_until([&] {
            return X->st().hello_ok.load() > hx0 && Y->st().hello_ok.load() > hy0 &&
                   X->r().ready_peers().size() == 1 && Y->r().ready_peers().size() == 1;
        }, 20000ms);
        std::printf("    re-HELLO after the path returned: %lld ms (hello_ok X %llu->%llu Y %llu->%llu)\n", ms_since(t1),
                    (unsigned long long)hx0, (unsigned long long)X->st().hello_ok.load(),
                    (unsigned long long)hy0, (unsigned long long)Y->st().hello_ok.load());
        C(healed, "L2 Y redials: a fresh HELLO on both sides once the path works again");
        const std::string dx_s = X->r().describe();
        const auto lp = dx_s.find("silent_drops");
        std::printf("    X %s\n", dx_s.substr(lp == std::string::npos ? dx_s.size() : lp).c_str());
    }

    // ── L3 legacy peer ──────────────────────────────────────────────────────
    {
        std::printf("-- L3 a peer that never answers a PING (HELLO, never a PONG) is not timed out\n");
        constexpr u32 kKeep = 200, kSilence = 1000;
        Rig rig;
        auto X = rig.make("X", opts(true, {}, kKeep, kSilence));
        std::string why;
        C(X->start(why), "L3 X starts");
        CarrierPeerNode raw;
        std::atomic<bool> dropped{false};
        raw.set_on_peer_event([&](CarrierPeerNode::PeerId, bool up) { if (!up) dropped = true; });
        const auto pid = raw.add_peer_id("127.0.0.1", X->port());
        C(pid != 0, "L3 raw peer connects");
        raw.send_to(pid, X->hello_bytes(X->r().node_nonce() ^ 0x5a5a5a5aull, 0));
        C(wait_until([&] { return X->r().ready_peers().size() == 1; }, 3000ms), "L3 raw peer HELLO ok at X");
        std::this_thread::sleep_for(std::chrono::milliseconds(4 * kSilence));
        C(!dropped.load() && X->r().ready_peers().size() == 1,
          "L3 the never-answering peer is KEPT past 4 silence timeouts (silent_drops=" + std::to_string(X->st().silent_drops.load()) + ")");
        C(X->st().ka_legacy.load() == 1, "L3 counted as legacy exactly once (" + std::to_string(X->st().ka_legacy.load()) + ")");
        C(X->st().ping_tx.load() <= 4, "L3 probing stops after 3 unanswered PINGs (ping_tx=" + std::to_string(X->st().ping_tx.load()) + ")");
        raw.stop();
    }

    // ── L4 keepalive off ────────────────────────────────────────────────────
    {
        std::printf("-- L4 keepalive_ms = 0: no PING on the wire\n");
        Rig rig;
        auto X = rig.make("X", opts(true, {}, 0, 0));
        std::string why;
        C(X->start(why), "L4 X starts");
        auto Y = rig.make("Y", opts(false, {X->port()}, 0, 0));
        C(Y->start(why), "L4 Y starts");
        C(wait_until([&] { return X->r().ready_peers().size() == 1 && Y->r().ready_peers().size() == 1; }, 5000ms), "L4 HELLO ok");
        std::this_thread::sleep_for(800ms);
        C(X->st().ping_tx.load() == 0 && Y->st().ping_tx.load() == 0 &&
          X->st().unknown_opcodes.load() == 0 && Y->st().unknown_opcodes.load() == 0,
          "L4 no PING sent, nothing unknown received");
    }

    return C.done("v37_xmr_relay_liveness_kat");
}
