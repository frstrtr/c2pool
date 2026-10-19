// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// v37_xmr_relay_addr_ban_kat -- relay bans and RandomX budgets by ADDRESS
// (the Path B relay node).
//
//   K1  address keys: one per IPv4 address and per IPv6 /64 (two addresses of
//       one /64 share a key, the next /64 does not); IPv4-mapped IPv6 keys as
//       IPv4; 127.0.0.1 and ::1 have no key; every key is >= kAddrKeyMin
//   K2  transport: an address banned for the relay default (133 s at one verify
//       worker) is refused at accept (no PeerId, no peer event) at +0 s and
//       +132 s and accepted at +134 s (test clock); another address is accepted
//       meanwhile; a banned address is not dialed
//   K3  transport: per-address accept cap 1: a second connection from the same
//       address is refused while the first is up and accepted after it ends;
//       127.0.0.1 is not capped
//   K4  RandomX budget per address, for n links, C verify workers and a global
//       refill G: per address C burst + G / n per s, global n x C burst + G per
//       s, address ban ceil(n x C / G) s. DosPolicy{} at n 113, C 1, G 4;
//       the relay's defaults n 113 (101 inbound + 12 outbound), C 1, G 0.85/s,
//       ban 133 s; bans 226 / 85 / 57 / 452 s at C 8 / 3 / 2 / 16 (G 4), 130 s
//       at C 8 and G 7; 16384 released addresses kept. At n 113, C 8, G 4: one
//       address gets 8 grants at once and 4 more over the next 120 s of
//       continuous asking; 113 addresses take the global burst (904) between
//       them and a 114th gets nothing more at that instant; an address that
//       spent its bucket finds it spent after it reconnects (released, kept); a
//       clean one is dropped
//   K5  relay: a peer dialing from 127.0.0.2 that sends a receipt whose PoW
//       fails is banned BY ADDRESS: dropped, its other queued receipts dropped
//       with no RandomX evaluation, its redial refused at accept and never
//       HELLO-ok, while a peer from 127.0.0.3 connects and passes HELLO
// Loopback only (127.0.0.x); a RandomX stub; no monerod.
#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <mutex>
#include <cstdlib>
#include <thread>

#include "xmr_pathb_relay_test_util.hpp"
#include <c2pool/v37/carrier_net.hpp>
#include <c2pool/v37/net_addr_ban.hpp>
#include "impl/xmr/wire/xmr_carrier_dos_budget.hpp"

using namespace pathb_relay_test;
using namespace std::chrono_literals;
namespace net = c2pool::v37n::net;
using c2pool::v37n::CarrierPeerNode;
using PeerId = CarrierPeerNode::PeerId;

static constexpr std::uint32_t kBadNonce = 0xDEADBEEF;

// A raw TCP client bound to `src` (127.0.0.x) connected to 127.0.0.1:port.
static int dial_from(const char* src, u16 port) {
    const int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    sockaddr_in s{}; s.sin_family = AF_INET; s.sin_port = 0;
    ::inet_pton(AF_INET, src, &s.sin_addr);
    if (::bind(fd, reinterpret_cast<sockaddr*>(&s), sizeof s) != 0) { ::close(fd); return -1; }
    sockaddr_in d{}; d.sin_family = AF_INET; d.sin_port = htons(port); d.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (::connect(fd, reinterpret_cast<sockaddr*>(&d), sizeof d) != 0) { ::close(fd); return -1; }
    return fd;
}
// true when the peer closed the socket within `ms`.
static bool closed_by_peer(int fd, int ms) {
    const auto dl = std::chrono::steady_clock::now() + std::chrono::milliseconds(ms);
    while (std::chrono::steady_clock::now() < dl) {
        pollfd p{fd, POLLIN, 0};
        if (::poll(&p, 1, 20) > 0) {
            char c;
            const ssize_t n = ::recv(fd, &c, 1, 0);
            if (n <= 0) return true;
        }
    }
    return false;
}
static net::AddrKey key_of(const char* ip) {
    sockaddr_in a{}; a.sin_family = AF_INET; ::inet_pton(AF_INET, ip, &a.sin_addr);
    return net::addr_key_of(reinterpret_cast<const sockaddr*>(&a));
}
static net::AddrKey key6_of(const char* ip) {
    sockaddr_in6 a{}; a.sin6_family = AF_INET6; ::inet_pton(AF_INET6, ip, &a.sin6_addr);
    return net::addr_key_of(reinterpret_cast<const sockaddr*>(&a));
}

// The transport under test, with its peer events counted and a test clock.
struct Srv {
    std::atomic<int> ups{0}, downs{0};
    std::atomic<PeerId> last{0};
    std::atomic<long long> offset_s{0};
    const std::chrono::steady_clock::time_point base = std::chrono::steady_clock::now();
    CarrierPeerNode node;   // last: destroyed first (its threads use the members above)
    Srv() {
        node.set_on_peer_event([this](PeerId p, bool up) { if (up) { ++ups; last = p; } else ++downs; });
        node.set_now_fn([this] { return base + std::chrono::seconds(offset_s.load()); });
    }
};

int main() {
    Checker C;
    std::printf("== v37_xmr_relay_addr_ban_kat ==\n");

    // ── K1 address keys ─────────────────────────────────────────────────────
    {
        const auto a = key_of("10.1.2.3"), b = key_of("10.1.2.4");
        const auto m = key6_of("::ffff:10.1.2.3");
        const auto v6a = key6_of("2001:db8:1:2::1"), v6b = key6_of("2001:db8:1:2:ffff::9"), v6c = key6_of("2001:db8:1:3::1");
        C(a && b && a != b && m == a, "K1 IPv4 keys per address; an IPv4-mapped IPv6 address keys as its IPv4 address");
        C(v6a && v6a == v6b && v6a != v6c, "K1 IPv6 keys per /64 (same /64 shares a key, the next /64 does not)");
        C(key_of("127.0.0.1") == 0 && key6_of("::1") == 0 && key_of("127.0.0.2") != 0,
          "K1 127.0.0.1 and ::1 have no key (exempt); 127.0.0.2 has one");
        C(net::is_addr_key(a) && net::is_addr_key(v6a) && !net::is_addr_key(12345),
          "K1 every key is >= kAddrKeyMin, a connection id is not");
        C(net::addr_key_str(a) == "10.1.2.3", "K1 key text " + net::addr_key_str(a));
    }

    // ── K2 ban at accept until expiry ───────────────────────────────────────
    {
        Srv S;
        C(S.node.listen("127.0.0.1", 0), "K2 transport listens");
        const u16 port = S.node.listen_port();
        int c1 = dial_from("127.0.0.2", port);
        C(c1 >= 0 && wait_until([&] { return S.ups.load() == 1; }, 5000ms, 10ms), "K2 127.0.0.2 connects (accepted)");
        const PeerId p1 = S.last.load();
        const long long ban_s = pb::PathbRelayNode::budget_of(pb::PathbRelayOptions{}).ban_seconds;
        const auto k = S.node.ban(p1, std::chrono::seconds(ban_s));
        C(ban_s == 133 && k == key_of("127.0.0.2") && closed_by_peer(c1, 3000) && wait_until([&] { return S.downs.load() == 1; }, 5000ms, 10ms),
          "K2 ban(peer, 133 s, the relay default) bans 127.0.0.2 and drops the link");
        ::close(c1);
        int c2 = dial_from("127.0.0.2", port);
        C(c2 >= 0 && closed_by_peer(c2, 3000) && wait_until([&] { return S.node.refused_banned() == 1; }, 5000ms, 10ms) && S.ups.load() == 1,
          "K2 redial from the banned address: closed at accept, no PeerId, no peer event");
        ::close(c2);
        int c3 = dial_from("127.0.0.3", port);
        C(c3 >= 0 && wait_until([&] { return S.ups.load() == 2; }, 5000ms, 10ms) && !closed_by_peer(c3, 200),
          "K2 another address (127.0.0.3) is accepted meanwhile");
        S.offset_s = ban_s - 1;
        int c4 = dial_from("127.0.0.2", port);
        C(c4 >= 0 && closed_by_peer(c4, 3000) && wait_until([&] { return S.node.refused_banned() == 2; }, 5000ms, 10ms) && S.ups.load() == 2,
          "K2 +132 s: still refused");
        ::close(c4);
        S.offset_s = ban_s + 1;
        int c5 = dial_from("127.0.0.2", port);
        C(c5 >= 0 && wait_until([&] { return S.ups.load() == 3; }, 5000ms, 10ms) && !closed_by_peer(c5, 200) && S.node.refused_banned() == 2,
          "K2 +134 s: the ban expired, 127.0.0.2 is accepted again");
        ::close(c3); ::close(c5);
        CarrierPeerNode cli;
        C(cli.ban_key(key_of("127.0.0.9"), std::chrono::seconds(60)) && cli.add_peer_id("127.0.0.9", port) == 0 &&
          cli.dial_refused_banned() == 1, "K2 a banned address is not dialed");
        C(!cli.ban_key(0, std::chrono::seconds(60)), "K2 key 0 (127.0.0.1 / ::1) is never banned");
        cli.stop();
        S.node.stop();
    }

    // ── K3 per-address accept cap ───────────────────────────────────────────
    {
        Srv S;
        S.node.set_inbound_limits(0, 1);
        C(S.node.listen("127.0.0.1", 0), "K3 transport listens (per-address cap 1)");
        const u16 port = S.node.listen_port();
        int a1 = dial_from("127.0.0.4", port);
        C(a1 >= 0 && wait_until([&] { return S.ups.load() == 1; }, 5000ms, 10ms), "K3 first link from 127.0.0.4 accepted");
        int a2 = dial_from("127.0.0.4", port);
        C(a2 >= 0 && closed_by_peer(a2, 3000) && wait_until([&] { return S.node.refused_addr_cap() == 1; }, 5000ms, 10ms) && S.ups.load() == 1,
          "K3 second link from 127.0.0.4 refused at accept while the first is up");
        ::close(a2);
        ::close(a1);
        C(wait_until([&] { return S.downs.load() == 1; }, 5000ms, 10ms), "K3 the first link ends");
        int a3 = dial_from("127.0.0.4", port);
        C(a3 >= 0 && wait_until([&] { return S.ups.load() == 2; }, 5000ms, 10ms), "K3 127.0.0.4 accepted again after its link ended");
        int l1 = dial_from("127.0.0.1", port), l2 = dial_from("127.0.0.1", port), l3 = dial_from("127.0.0.1", port);
        C(l1 >= 0 && l2 >= 0 && l3 >= 0 && wait_until([&] { return S.ups.load() == 5; }, 5000ms, 10ms) && S.node.refused_addr_cap() == 1,
          "K3 127.0.0.1 is not capped per address (3 links accepted)");
        ::close(a3); ::close(l1); ::close(l2); ::close(l3);
        S.node.stop();
    }

    // ── K4 RandomX budget per address ───────────────────────────────────────
    {
        namespace cx = ::c2pool::xmr;
        const cx::DosPolicy def;   // DosPolicy{} = dos_policy_for(113, 1, 4)
        const cx::DosPolicy d1 = cx::dos_policy_for(113, 1, 4);
        C(def.per_peer_capacity == 1.0 && def.per_peer_refill == 4.0 / 113.0 && def.global_capacity == 113.0 &&
          def.global_refill == 4.0 && def.retain_max == 16384 &&
          d1.per_peer_capacity == def.per_peer_capacity && d1.per_peer_refill == def.per_peer_refill &&
          d1.global_capacity == def.global_capacity && d1.global_refill == def.global_refill,
          "K4 default budget = dos_policy_for(113 links, 1 worker, 4/s): 1 burst + 4/113 per s per address, "
          "113 + 4/s global; 16384 released addresses kept");
        const pb::PathbRelayOptions ro{};
        const pb::RelayBudget rb = pb::PathbRelayNode::budget_of(ro);
        C(ro.max_inbound == 101 && ro.max_outbound == 12 && ro.max_inbound + ro.max_outbound == cx::kDosDefaultLinks &&
          rb.dos.per_peer_capacity == 1.0 && rb.dos.global_capacity == 113.0 && rb.dos.global_refill == 0.85 &&
          rb.dos.per_peer_refill == 0.85 / 113.0 && rb.ban_seconds == 133,
          "K4 relay defaults: 101 inbound + 12 outbound = 113 links, 1 worker, G 0.85/s; address ban ceil(113 x 1 / 0.85) = 133 s");
        C(cx::dos_ban_seconds(113, 8, 4) == 226 && cx::dos_ban_seconds(113, 3, 4) == 85 && cx::dos_ban_seconds(113, 2, 4) == 57 &&
          cx::dos_ban_seconds(113, 16, 4) == 452 && cx::dos_ban_seconds(113, 8, 7) == 130 && cx::dos_ban_seconds(113, 8, 0) == 0,
          "K4 address ban ceil(n x C / G): 226 / 85 / 57 / 452 s at C 8 / 3 / 2 / 16 (G 4), 130 s at C 8 and G 7, 0 at G 0");
        const cx::DosPolicy pol = cx::dos_policy_for(113, 8, 4);   // n 113, C 8, G 4
        C(pol.per_peer_capacity == 8.0 && pol.per_peer_refill == 4.0 / 113.0 && pol.global_capacity == 904.0 && pol.global_refill == 4.0,
          "K4 dos_policy_for(113, 8, 4): 8 burst + 4/113 per s per address, 904 + 4/s global");
        cx::CarrierDosBudget dos(pol);
        const cx::nanos_t t0 = 1'000'000'000LL;
        const u64 A = key_of("10.0.0.1");
        int got = 0;
        for (int i = 0; i < 1000; ++i) got += dos.grant_randomx(A, t0) ? 1 : 0;
        C(got == 8, "K4 one address asking 1000 times at once gets 8 grants: " + std::to_string(got));
        int later = 0;
        for (int s = 1; s <= 120; ++s)
            for (int i = 0; i < 100; ++i) later += dos.grant_randomx(A, t0 + s * 1'000'000'000LL) ? 1 : 0;
        C(later == 4, "K4 then 4/113 per s: 4 more grants over 120 s of continuous asking: " + std::to_string(later));
        cx::CarrierDosBudget dos2(pol);
        int total = 0, most = 0;
        for (u32 i = 0; i < 113; ++i) {
            int g = 0;
            for (int k = 0; k < 100; ++k) g += dos2.grant_randomx(key_of(("10.0.1." + std::to_string(i + 1)).c_str()), t0) ? 1 : 0;
            total += g; most = std::max(most, g);
        }
        int extra = 0;
        for (int k = 0; k < 100; ++k) extra += dos2.grant_randomx(key_of("10.0.2.1"), t0) ? 1 : 0;
        C(total == 904 && most == 8 && extra == 0,
          "K4 113 addresses share the global burst (904, at most 8 each); a 114th gets none at that instant (" +
              std::to_string(total) + "/" + std::to_string(most) + "/" + std::to_string(extra) + ")");
        cx::CarrierDosBudget dos3(pol);
        const u64 B = key_of("10.0.3.1"), Cc = key_of("10.0.3.2");
        for (int i = 0; i < 8; ++i) (void)dos3.grant_randomx(B, t0);   // spent (no valid PoW to refund)
        (void)dos3.grant_randomx(Cc, t0); dos3.on_valid_pow(Cc, t0);    // clean again
        dos3.release(B, t0 + 1);
        dos3.release(Cc, t0 + 1);
        C(dos3.known(B) && !dos3.known(Cc), "K4 release: a spent address is kept, a clean one is dropped");
        C(!dos3.grant_randomx(B, t0 + 2), "K4 the spent address reconnecting finds its bucket spent (no reset on reconnect)");
        C(dos3.on_invalid_pow(B, true) == cx::Action::Ban && dos3.is_banned(B), "K4 one confirmed invalid PoW bans the address");
    }

    // ── K5 relay: ban by address ────────────────────────────────────────────
    {
        Rig rig;
        auto B = rig.make("B", Rig::opts(true), /*launch=*/true);
        B->rx = [](const pb::HashingBlob& b, std::uint64_t, const pb::Hash32&) { return b.nonce != kBadNonce; };
        std::string why;
        C(B->start(why), "K5 relay B starts " + why);
        const u16 port = B->port();
        // receipts of B's own job on a tip B has moved past: pending receipts at B when they pass
        const bool c1 = rig.mine(*B, 0, 11).action == pb::NodeAction::Placed;
        const std::optional<pb::PathbJob> j = rig.job(*B, 4, 77);
        const bool c2 = rig.mine(*B, 0, 12).action == pb::NodeAction::Placed;
        C(c1 && c2 && j.has_value(), "K5 B mines two carriers; a job on the first");
        const pb::ReceiptBodyV3 bad = body_of(*j, kBadNonce), ok1 = body_of(*j, 41), ok2 = body_of(*j, 42);
        const std::vector<u8> frame =
                pb::encode_fb_receipts(0, std::vector<pb::ReceiptBodyV3>{bad, ok1, ok2}, pb::kRuledLaneParams).value_or(std::vector<u8>{});
        auto hello_from = [&](CarrierPeerNode& n, std::atomic<PeerId>& pid, std::atomic<bool>& down) {
            std::atomic<PeerId>* pp = &pid; std::atomic<bool>* dd = &down;
            n.set_on_peer_event([pp, dd](PeerId p, bool up) { if (up) *pp = p; else *dd = true; });
            const PeerId p = n.add_peer_id("127.0.0.1", port);
            if (!p) return PeerId{0};
            n.send_to(p, B->hello_bytes(B->r().node_nonce() ^ 0x5151, 0));
            return p;
        };

        CarrierPeerNode evil; evil.set_dial_source("127.0.0.2");
        std::atomic<PeerId> epid{0}; std::atomic<bool> edown{false};
        const PeerId e = hello_from(evil, epid, edown);
        C(e != 0 && wait_until([&] { return B->r().ready_peers().size() == 1; }, 5000ms, 10ms), "K5 E (from 127.0.0.2) passes HELLO at B");
        const u64 rx0 = B->rx_calls.load();
        evil.send_to(e, frame);
        const auto& s = B->st();
        C(wait_until([&] { return s.bans.load() >= 1 && s.addr_bans.load() == 1 && edown.load(); }, 5000ms, 10ms),
          "K5 one receipt whose PoW fails: E BANNED BY ADDRESS and dropped");
        C(wait_until([&] { return s.banned_src_dropped.load() == 2; }, 5000ms, 10ms) && B->rx_calls.load() - rx0 == 1 &&
          !B->pending_holds(pb::receipt_id(ok1)) && !B->pending_holds(pb::receipt_id(ok2)),
          "K5 E's two queued receipts dropped with no RandomX (1 evaluation: the failing one)");
        C(B->links.net().is_banned_key(key_of("127.0.0.2")), "K5 127.0.0.2 is in B's ban table");
        evil.stop();

        CarrierPeerNode evil2; evil2.set_dial_source("127.0.0.2");
        std::atomic<PeerId> e2pid{0}; std::atomic<bool> e2down{false};
        const u64 ref0 = B->links.net().refused_banned();
        (void)hello_from(evil2, e2pid, e2down);
        C(wait_until([&] { return B->links.net().refused_banned() == ref0 + 1 && e2down.load(); }, 5000ms, 10ms) && B->r().ready_peers().empty(),
          "K5 E redials from 127.0.0.2: refused at accept, never HELLO-ok");
        evil2.stop();

        CarrierPeerNode good; good.set_dial_source("127.0.0.3");
        std::atomic<PeerId> gpid{0}; std::atomic<bool> gdown{false};
        const PeerId g = hello_from(good, gpid, gdown);
        C(g != 0 && wait_until([&] { return B->r().ready_peers().size() == 1; }, 5000ms, 10ms) && !gdown.load(),
          "K5 a peer from 127.0.0.3 connects and passes HELLO meanwhile");
        good.stop();
        if (C.fail) B->dump_logs();
    }
    return C.done("v37_xmr_relay_addr_ban_kat");
}
