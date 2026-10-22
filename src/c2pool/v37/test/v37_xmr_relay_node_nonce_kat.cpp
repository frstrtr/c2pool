// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// v37_xmr_relay_node_nonce_kat -- NODE-NONCE (the Path B HELLO node nonce)
//   N1 HELLO nonce codec + bounds: a random 64-bit per-process nonce, never 0,
//      at the fixed byte offset 43 of the Path B HELLO (483 B at epoch 0);
//      every other frame length is refused
//   N2 the Family-B opcode map: exact values, all distinct, 0x4a/0x4b unused
//   N3 bootstrap -> discovery seeds: routed by the discovery switch; a seed is
//      dialed and is GOOD after its HELLO
//   N4 self-connection: a node given its own address (--relay-peer, exact and
//      an alias; an FB_ADDR naming it) never keeps a link to itself, dials an
//      alias at most once, marks it SELF in the book, never hands it out
//   N5 duplicate in/out pair: exactly one link per node pair, the SAME socket
//      on both ends, no churn, no penalty (dup_link_rule both-ends agreement)
//   N6 dial target release (manual node, logical clock): a target whose link
//      left the link table waits for the link's down event, then the pre-HELLO
//      backoff (A: the down event held); a down event that never comes
//      releases it at hello_timeout_ms; a HELLO run after its link's down
//      event still applies a self-connection verdict (B) and keeps nothing of
//      the gone link (C)
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <thread>

#include "xmr_pathb_relay_test_util.hpp"
#include <c2pool/v37/carrier_net.hpp>
#include <c2pool/v37/xmr/relay/xmr_relay_bootstrap.hpp>

using namespace pathb_relay_test;
using namespace std::chrono_literals;
using c2pool::v37n::CarrierPeerNode;

static void n1_codec(Checker& C, Rig& rig) {
    std::printf("-- N1 HELLO node nonce: codec + bounds\n");
    const u64 X = 0x8877665544332211ull;
    auto A = rig.make("A", Rig::opts(false));
    const pb::PathbHello ours = A->r().with_node([&](pb::PathbNode& n) { return n.our_hello(X, 7320); });
    const std::vector<u8> f = pb::encode_pathb_hello(ours).value_or(std::vector<u8>{});
    const pb::PathbHelloDecode d = pb::decode_pathb_hello(f);
    C(d.error == pb::HelloError::None && d.hello.node_nonce == X && d.hello == ours, "N1 the HELLO round-trips the 64-bit node nonce");
    u64 at43 = 0;
    for (int i = 7; i >= 0 && f.size() >= 51; --i) at43 = (at43 << 8) | f[43 + i];
    C(at43 == X, "N1 the nonce sits at byte 43 (LE) of the HELLO head");
    C(f.size() == 483, "N1 the HELLO length is 483 B at epoch 0 (" + std::to_string(f.size()) + ")");
    bool bounded = true;
    for (std::size_t n = 1; n <= f.size() + 40; ++n) {
        if (n == f.size()) continue;
        std::vector<u8> g(f.begin(), f.begin() + static_cast<std::ptrdiff_t>(std::min(n, f.size())));
        g.resize(n, 0);
        bounded = bounded && pb::decode_pathb_hello(g).error != pb::HelloError::None;
    }
    C(bounded, "N1 every other HELLO length (1.." + std::to_string(f.size() + 40) + ") is refused (bounded decoder)");
    pb::PathbHello other = ours;
    other.node_nonce = X ^ 1;
    const std::vector<u8> fo = pb::encode_pathb_hello(other).value_or(std::vector<u8>{});
    const pb::HelloCheck same = A->r().with_node([&](pb::PathbNode& n) { return n.on_hello(1, f, ours); });
    const pb::HelloCheck diff = A->r().with_node([&](pb::PathbNode& n) { return n.on_hello(2, fo, ours); });
    C(same.verdict == pb::HelloVerdict::SelfConnection && same.text.find("self-connection") != std::string::npos,
      "N1 equal nonce = self-connection");
    C(diff.verdict == pb::HelloVerdict::Accept, "N1 a different nonce with equal pool rules is accepted");
}

static void n2_opcodes(Checker& C) {
    std::printf("-- N2 Family-B opcode map\n");
    const std::vector<std::pair<const char*, std::pair<u8, u8>>> map = {
        {"HELLO", {pb::kOpFbHello, 0x40}}, {"RECEIPTS", {pb::kOpFbReceipts, 0x41}}, {"GETCTX", {pb::kOpFbGetCtx, 0x43}},
        {"CTX", {pb::kOpFbCtx, 0x44}},     {"PING", {pb::kOpFbPing, 0x48}},         {"PONG", {pb::kOpFbPong, 0x49}},
        {"GETADDR", {pb::kOpFbGetAddr, 0x4c}}, {"ADDR", {pb::kOpFbAddr, 0x4d}},
    };
    std::set<u8> seen; bool exact = true, range = true;
    for (const auto& [n, v] : map) {
        if (v.first != v.second) { exact = false; std::printf("    %s = 0x%02x, want 0x%02x\n", n, v.first, v.second); }
        range = range && v.first >= 0x40 && v.first <= 0x4f;
        seen.insert(v.first);
    }
    exact = exact && FB_GETCTX == pb::kOpFbGetCtx && FB_CTX == pb::kOpFbCtx && FB_PING == pb::kOpFbPing &&
            FB_PONG == pb::kOpFbPong && FB_GETADDR == pb::kOpFbGetAddr && FB_ADDR == pb::kOpFbAddr;
    C(exact, "N2 opcodes are 0x40 HELLO, 0x41 RECEIPTS, 0x43 GETCTX, 0x44 CTX, 0x48 PING, 0x49 PONG, 0x4c GETADDR, "
             "0x4d ADDR (the kept frames' codec constants equal)");
    C(seen.size() == map.size(), "N2 all Family-B opcodes are distinct");
    C(range && !seen.count(0x4a) && !seen.count(0x4b), "N2 all in 0x40..0x4f; 0x4a/0x4b stay reserved (LANE-EPOCH)");
    C(map.size() == 8, "N2 eight Family-B opcodes (GETADDR/ADDR present)");
}

static pb::PathbRelayOptions nopts(std::string listen_host, std::vector<std::pair<std::string, u16>> dial) {
    pb::PathbRelayOptions o = Rig::opts(true);
    o.listen_host = std::move(listen_host);
    o.peers = std::move(dial);
    o.discovery = true; o.max_outbound = 8;
    o.addr_reask_ms = 500; o.addr_answer_min_ms = 200; o.book_save_ms = 300; o.connect_timeout_ms = 1000;
    return o;
}
static std::size_t links(RNode& n) { return n.r().ready_links().size(); }

static void n3_seeds(Checker& C, Rig& rig) {
    std::printf("-- N3 bootstrap list -> discovery seeds\n");
    using PV = std::vector<std::pair<std::string, u16>>;
    PV seeds, peers;
    const std::vector<std::string> use = {"10.1.2.3:59321", "10.4.5.6:59321"};
    C(route_bootstrap(use, true, seeds, peers) == 2 && seeds.size() == 2 && peers.empty() &&
      seeds[0] == std::make_pair(std::string("10.1.2.3"), u16{59321}), "N3 discovery ON: the bootstrap nodes become seeds");
    seeds.clear();
    C(route_bootstrap(use, false, seeds, peers) == 2 && peers.size() == 2 && seeds.empty(),
      "N3 discovery OFF: they stay permanent dial targets");
    peers.clear();
    const auto none = resolve_bootstrap(0, true, {}, "", {});
    C(route_bootstrap(none.use, true, seeds, peers) == 0 && seeds.empty() && peers.empty(),
      "N3 --no-relay-bootstrap: no seed");
    auto T = rig.make("T", nopts("127.0.0.1", {}));
    C(T->start(), "N3 T (a bootstrap node) starts");
    pb::PathbRelayOptions os = nopts("127.0.0.1", {});
    route_bootstrap({"127.0.0.1:" + std::to_string(T->port())}, true, os.seeds, os.peers);
    auto S = rig.make("S", os);
    C(S->start() && S->r().book().contains("127.0.0.1", T->port()) && !S->r().book().is_good("127.0.0.1", T->port()),
      "N3 S starts with T as a seed CANDIDATE (not yet good)");
    C(wait_until([&] { return S->r().book().is_good("127.0.0.1", T->port()) && links(*S) == 1; }, 10000ms, 50ms),
      "N3 S dials the seed and it is GOOD after HELLO");
    C(T->r().node_nonce() != 0 && S->r().node_nonce() != 0 && T->r().node_nonce() != S->r().node_nonce(),
      "N1 two nodes draw different non-zero random 64-bit nonces");
}

static u16 free_port() {
    const int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in a{}; a.sin_family = AF_INET; a.sin_addr.s_addr = htonl(INADDR_LOOPBACK); a.sin_port = 0;
    ::bind(fd, reinterpret_cast<sockaddr*>(&a), sizeof a);
    socklen_t l = sizeof a; ::getsockname(fd, reinterpret_cast<sockaddr*>(&a), &l); ::close(fd);
    return ntohs(a.sin_port);
}
// A raw peer: HELLO (another nonce) to `n`, answers its GETADDR with `answer`,
// then asks for addresses; returns every FB_ADDR entry it received.
static std::vector<AddrEntry> raw_exchange(RNode& n, const std::vector<AddrEntry>& answer) {
    CarrierPeerNode raw;
    std::mutex m; std::vector<AddrEntry> got; std::atomic<int> getaddr{0}, addr{0};
    raw.set_inbound_from([&](CarrierPeerNode::PeerId, const std::vector<u8>& f) {
        if (!f.empty() && f[0] == FB_GETADDR) getaddr++;
        if (!f.empty() && f[0] == FB_ADDR) { u32 c = 0; std::vector<AddrEntry> v;
            if (decode_addr(f, c, v)) { std::lock_guard<std::mutex> lk(m); got.insert(got.end(), v.begin(), v.end()); } addr++; }
    });
    const auto pid = raw.add_peer_id("127.0.0.1", n.port());
    raw.send_to(pid, n.hello_bytes(n.r().node_nonce() ^ 0x5eedull, 0));
    wait_until([&] { return getaddr.load() >= 1; }, 3000ms, 50ms);
    raw.send_to(pid, encode_addr(0, answer));
    std::this_thread::sleep_for(400ms);
    raw.send_to(pid, encode_getaddr(0, 64));
    wait_until([&] { return addr.load() >= 1; }, 3000ms, 50ms);
    raw.stop();
    std::lock_guard<std::mutex> lk(m); return got;
}

static void n4_self(Checker& C, Rig& rig) {
    std::printf("-- N4 self-connection\n");
    const u16 P = free_port();
    pb::PathbRelayOptions oa = nopts("0.0.0.0", {{"127.0.0.1", P}, {"127.0.1.1", P}});   // its own address, exact + alias
    oa.listen_port = P;
    auto A = rig.make("A", oa);
    C(A->start() && A->port() == P, "N4 A listens on 0.0.0.0:P, --relay-peer = 127.0.0.1:P and 127.0.1.1:P (itself)");
    std::this_thread::sleep_for(7000ms);
    std::printf("    A: dials=%llu hello_ok=%llu refused=%llu | %s\n", (unsigned long long)A->st().dials.load(),
                (unsigned long long)A->st().hello_ok.load(), (unsigned long long)A->st().hello_rejected.load(),
                A->r().disc_describe().c_str());
    C(A->st().hello_ok.load() == 0 && links(*A) == 0, "N4 A never has a link to itself (0 self links reach HELLO ok)");
    C(A->st().dials.load() <= 1, "N4 A dials its own address at most once in 7 s (exact: never; alias: once)");
    C(A->st().self_conn.load() >= 1 && A->st().self_skipped.load() >= 1, "N4 alias self-dial detected by nonce on both ends; exact one skipped");
    C(A->r().book().is_self("127.0.1.1", P) && A->r().book().is_self("127.0.0.1", P), "N4 both addresses marked SELF in the book");
    const_cast<PeerBook&>(A->r().book()).mark_good("127.0.1.1", P, 1);
    C(!A->r().book().is_good("127.0.1.1", P), "N4 a SELF address can never become good");
    bool leaked = false;
    for (const auto& e : raw_exchange(*A, {})) leaked = leaked || e.port == P;
    C(!leaked, "N4 A never hands its own address out in FB_ADDR");

    auto Cc = rig.make("C", nopts("127.0.0.1", {}));
    C(Cc->start(), "N4 C (a control peer) starts");
    auto B = rig.make("B", nopts("127.0.0.1", {}));
    C(B->start(), "N4 B starts (no peers)");
    AddrEntry eb, ec; addr_entry_of("127.0.0.1", B->port(), 1, eb); addr_entry_of("127.0.0.1", Cc->port(), 1, ec);
    raw_exchange(*B, {eb, ec});   // an FB_ADDR naming B itself (and C)
    C(wait_until([&] { return links(*B) >= 1; }, 8000ms, 50ms), "N4 B learns C from the FB_ADDR and links to it");
    std::this_thread::sleep_for(2000ms);
    C(B->count_logs("self-connection") == 0 && B->st().disc_self.load() == 0, "N4 B never dials its own address fed by FB_ADDR (0 self-connections)");
    C(!B->r().book().contains("127.0.0.1", B->port()), "N4 B's own address is not in its book");
}

static void n5_dup(Checker& C, Rig& rig) {
    std::printf("-- N5 duplicate in/out pair\n");
    const u16 pp = free_port(), pq = free_port();
    pb::PathbRelayOptions op = nopts("127.0.0.1", {{"127.0.0.1", pq}}); op.listen_port = pp;
    pb::PathbRelayOptions oq = nopts("127.0.0.1", {{"127.0.0.1", pp}}); oq.listen_port = pq;
    auto P = rig.make("P", op);
    auto Q = rig.make("Q", oq);
    C(P->start() && Q->start(), "N5 P and Q each dial the other");
    C(wait_until([&] { return links(*P) == 1 && links(*Q) == 1; }, 8000ms, 50ms), "N5 one link each");
    std::this_thread::sleep_for(2000ms);
    const u64 hp = P->st().hello_ok.load(), hq = Q->st().hello_ok.load();
    std::this_thread::sleep_for(5000ms);
    const auto lp = P->r().ready_links(), lq = Q->r().ready_links();
    C(lp.size() == 1 && lq.size() == 1 && lp[0].second != lq[0].second, "N5 exactly ONE link per pair, the same socket on both ends");
    const bool p_low = P->r().node_nonce() < Q->r().node_nonce();
    C(lp.size() == 1 && lp[0].second == p_low, "N5 the kept link is the one dialed by the lower node nonce");
    C(P->st().hello_ok.load() == hp && Q->st().hello_ok.load() == hq, "N5 no churn over 5 s (no new HELLO)");
    C(P->st().bans.load() == 0 && Q->st().bans.load() == 0 && P->r().book().is_good("127.0.0.1", pq) &&
      Q->r().book().is_good("127.0.0.1", pp), "N5 no penalty: no ban, both still GOOD in each other's book");

    // same direction: P2 dials Q2 twice (two addresses of one node)
    const u16 p2 = free_port(), q2 = free_port();
    pb::PathbRelayOptions oq2 = nopts("0.0.0.0", {}); oq2.listen_port = q2;
    auto Q2 = rig.make("Q2", oq2);
    C(Q2->start(), "N5 Q2 listens on 0.0.0.0");
    pb::PathbRelayOptions op2 = nopts("127.0.0.1", {{"127.0.0.1", q2}, {"127.0.1.1", q2}}); op2.listen_port = p2;
    auto P2 = rig.make("P2", op2);
    C(P2->start(), "N5 P2 dials Q2 under two addresses (127.0.0.1 and 127.0.1.1)");
    C(wait_until([&] { return links(*P2) == 1 && links(*Q2) == 1; }, 8000ms, 50ms), "N5 one link each");
    pb::PathbRelayOptions or3 = nopts("127.0.0.1", {{"127.0.0.1", p2}});   // R knows only P2: learns BOTH addresses of Q2
    auto R3 = rig.make("R", or3);
    C(R3->start(), "N5 R starts, --relay-peer = P2 only");
    C(wait_until([&] { return links(*R3) == 2; }, 10000ms, 50ms), "N5 R links to P2 and Q2 (one link each)");
    std::this_thread::sleep_for(3000ms);
    const u64 hp2 = P2->st().hello_ok.load(), hq2 = Q2->st().hello_ok.load();
    const u64 hr3 = R3->st().hello_ok.load(), dr3 = R3->st().disc_dup_dropped.load(), dl3 = R3->st().disc_dialed.load();
    std::this_thread::sleep_for(6000ms);
    std::printf("    R %s\n", R3->r().disc_describe().c_str());
    C(links(*R3) == 2 && R3->st().hello_ok.load() == hr3 && R3->st().disc_dup_dropped.load() == dr3 && R3->st().disc_dialed.load() == dl3,
      "N5 a learned second address of a linked node is not redialed (no churn from the book)");
    std::printf("    P2 %s\n    Q2 %s\n", P2->r().disc_describe().c_str(), Q2->r().disc_describe().c_str());
    C(links(*P2) == 2 && links(*Q2) == 2, "N5 same-dialer duplicate: exactly ONE link per pair (P2, Q2 each: the other + R)");
    C(P2->st().hello_ok.load() == hp2 && Q2->st().hello_ok.load() == hq2, "N5 same-dialer duplicate: no redial churn over 6 s");
    C(Q2->st().dup_deferred.load() >= 1 && Q2->st().disc_dup_dropped.load() == 0 && P2->st().disc_dup_dropped.load() == 1,
      "N5 only the dialer (P2) closes the duplicate; the acceptor defers");
    std::printf("-- N5 dup_link_rule: both ends close the same socket\n");
    // Links are named by their dialer; each end sees the two links in either order.
    bool agree = true;
    for (u64 a : {u64{5}, u64{9}}) {
        const u64 b = a == 5 ? 9 : 5;
        // cross: L_a dialed by A, L_b dialed by B. Dropped link as seen from one end.
        auto dropped = [](u64 self, u64 peer, bool new_is_mine) -> int {   // returns dialer nonce of the closed link, 0 = none
            const DupPick k = dup_link_rule(self, peer, new_is_mine, !new_is_mine);
            if (k == DupPick::Defer) return 0;
            const bool closes_new = k == DupPick::DropNew;
            const bool closed_mine = closes_new ? new_is_mine : !new_is_mine;
            return static_cast<int>(closed_mine ? self : peer);
        };
        for (bool a_new_mine : {false, true}) for (bool b_new_mine : {false, true})
            agree = agree && dropped(a, b, a_new_mine) == static_cast<int>(std::max(a, b)) &&
                    dropped(b, a, b_new_mine) == static_cast<int>(std::max(a, b));
        // same dialer A: A closes its newer link, B defers
        agree = agree && dup_link_rule(a, b, true, true) == DupPick::DropNew && dup_link_rule(b, a, false, false) == DupPick::Defer;
    }
    C(agree, "N5 cross pair: both ends close the link dialed by the HIGHER nonce, in any arrival order; same dialer: only it closes");
}

// A logical relay clock (ms), moved by the KAT.
struct StepClock {
    std::shared_ptr<std::atomic<u64>> ms = std::make_shared<std::atomic<u64>>(1000000);
    pb::RelayClock clock() const {
        pb::RelayClock c = pb::RelayClock::system();
        c.mono_ms = [m = ms] { return m->load(); };
        return c;
    }
    void add(u64 d) const { *ms += d; }
};
// Holds every FB_HELLO frame on its reader thread, before the relay node sees it, until opened.
struct HelloGate {
    std::mutex m;
    std::condition_variable cv;
    bool open = false;
    int arrived = 0;
    void tap(const std::vector<u8>& f) {
        if (f.empty() || f[0] != pb::kOpFbHello) return;
        std::unique_lock<std::mutex> lk(m);
        ++arrived;
        cv.notify_all();
        cv.wait(lk, [&] { return open; });
    }
    int count() {
        std::lock_guard<std::mutex> lk(m);
        return arrived;
    }
    void release() {
        {
            std::lock_guard<std::mutex> lk(m);
            open = true;
        }
        cv.notify_all();
    }
};
struct GateOpener {
    HelloGate& g;
    ~GateOpener() { g.release(); }
};
// A manual node (no threads) on `clk`: listens on 0.0.0.0:P, --relay-peer = 127.0.1.1:P (itself).
static std::unique_ptr<RNode> self_alias_node(Rig& rig, const char* name, u16 P, const StepClock& clk, HelloGate& g) {
    pb::PathbRelayOptions o = nopts("0.0.0.0", {{"127.0.1.1", P}});
    o.listen_port = P;
    o.threads = false;
    auto A = rig.make(name, o, false, false, clk.clock());
    A->links.set_tap([&g](u64, const std::vector<u8>& f) { g.tap(f); });
    return A;
}
// One tick dials the alias; both HELLOs are sent and reach the relay node, where each waits on the owner queue
// (not pumped). out / in: the dialed and the accepted link.
static bool self_pair(RNode& A, HelloGate& g, u64& out, u64& in) {
    A.r().tick();
    if (!wait_until([&] { return A.links.net().n_peers() == 2; }, 8000ms, 5ms)) return false;
    if (!wait_until([&] { A.r().pump(); return A.st().hello_sent.load() == 2; }, 8000ms, 5ms)) return false;
    if (!wait_until([&] { return g.count() == 2; }, 8000ms, 5ms)) return false;
    g.release();
    if (!wait_until([&] { return A.links.handled(pb::kOpFbHello) == 2; }, 8000ms, 5ms)) return false;
    out = in = 0;
    for (u64 id : A.links.net().peer_ids()) (A.links.net().is_inbound(id) ? in : out) = id;
    return out != 0 && in != 0 && A.st().dials.load() == 1;
}

static void n6_release(Checker& C, Rig& rig) {
    std::printf("-- N6 dial target release\n");
    {   // A: the dialed link leaves the link table and its peer entry (hello_timeout_ms 3000); its down event is held
        StepClock clk;
        HelloGate g;
        const u16 P = free_port();
        auto A = self_alias_node(rig, "N6A", P, clk, g);
        GateOpener go{g};
        u64 out = 0, in = 0;
        C(A->start() && self_pair(*A, g, out, in), "N6 A: one dial of the alias, both HELLOs queued on the relay node");
        A->links.hold_downs();
        A->r().drop_peer(in);
        const bool gone = wait_until([&] { return A->links.held_downs() == 2 && !A->links.has_peer(out); }, 8000ms, 5ms);
        clk.add(3001);
        A->r().tick();
        C(gone && A->st().hello_timeout.load() == 2 && A->st().dials.load() == 1,
          "N6 A: the dialed link gone from the link table and its peer entry, its down event not run: no redial");
        A->links.release_downs();
        clk.add(1999);
        A->r().tick();
        C(A->links.downs() == 2 && A->st().dials.load() == 1,
          "N6 A: after its down event, no redial within its pre-HELLO backoff (2 s after a HELLO timeout)");
        A->r().pump();
        clk.add(2001);
        A->r().tick();
        C(A->st().dials.load() == 1 && A->st().self_conn.load() == 2 && A->r().book().is_self("127.0.1.1", P),
          "N6 A: the queued HELLOs of the gone links mark the alias SELF; no redial after the backoff");
    }
    {   // B: both down events run before the queued HELLOs
        StepClock clk;
        HelloGate g;
        const u16 P = free_port();
        auto A = self_alias_node(rig, "N6B", P, clk, g);
        GateOpener go{g};
        u64 out = 0, in = 0;
        C(A->start() && self_pair(*A, g, out, in), "N6 B: one dial of the alias, both HELLOs queued on the relay node");
        A->r().drop_peer(in);
        const bool down = wait_until([&] { return A->links.downs() == 2; }, 8000ms, 5ms);
        const u64 stale0 = A->st().stale_events.load();
        A->r().pump();
        clk.add(1001);
        A->r().tick();
        C(down && A->st().stale_events.load() == stale0 + 2 && A->st().self_conn.load() == 2 &&
              A->r().book().is_self("127.0.1.1", P) && A->count_logs("is THIS node -> never dialed again") == 1 &&
              A->st().dials.load() == 1,
          "N6 B: a HELLO run after its link's down event still marks the alias SELF; no redial after the backoff (1 s)");
        C(links(*A) == 0 && !A->r().with_node([](pb::PathbNode& n) { return n.has_pathb_peer(); }),
          "N6 B: nothing of the gone links is kept (no relay link, no Path B peer)");
    }
    {   // C: another node's HELLO that arrives after its link's down event
        StepClock clk;
        HelloGate g;
        pb::PathbRelayOptions o = nopts("127.0.0.1", {});
        o.threads = false;
        auto G = rig.make("N6C", o, false, false, clk.clock());
        G->links.set_tap([&g](u64, const std::vector<u8>& f) { g.tap(f); });
        GateOpener go{g};
        C(G->start(), "N6 C: a manual node G starts");
        CarrierPeerNode d;
        const auto dl = d.add_peer_id("127.0.0.1", G->port());
        const bool sent = dl != 0 && d.send_to(dl, G->hello_bytes(G->r().node_nonce() ^ 0x77ull, 4242));
        const bool held = sent && wait_until([&] { return g.count() == 1; }, 8000ms, 5ms);
        for (u64 id : G->links.net().peer_ids()) G->r().drop_peer(id);
        const bool down = wait_until([&] { return G->links.downs() == 1; }, 8000ms, 5ms);
        g.release();
        const bool queued = wait_until([&] { return G->links.handled(pb::kOpFbHello) == 1; }, 8000ms, 5ms);
        G->r().pump();
        C(held && down && queued && G->st().hello_ok.load() == 0 && G->st().self_conn.load() == 0 && links(*G) == 0 &&
              !G->r().with_node([](pb::PathbNode& n) { return n.has_pathb_peer(); }) &&
              !G->r().book().contains("127.0.0.1", 4242),
          "N6 C: a HELLO run after its link's down event (another node) keeps nothing (no Path B peer, no book entry)");
        d.stop();
    }
    {   // a down event that never comes: released at hello_timeout_ms (3000), redialed after the backoff (1 s)
        StepClock clk;
        CarrierPeerNode srv;
        C(srv.listen("127.0.0.1", 0), "N6 bound: a raw listener S");
        pb::PathbRelayOptions o = nopts("127.0.0.1", {{"127.0.0.1", srv.listen_port()}});
        o.threads = false;
        auto B = rig.make("N6T", o, false, false, clk.clock());
        C(B->start(), "N6 bound: a manual node dialing S starts");
        B->r().tick();
        const bool up = wait_until([&] { return srv.n_peers() == 1 && B->links.net().n_peers() == 1; }, 8000ms, 5ms);
        B->links.hold_downs();
        for (u64 id : srv.peer_ids()) srv.disconnect(id);
        const bool gone = wait_until([&] { return B->links.held_downs() == 1 && B->links.net().n_peers() == 0; }, 8000ms, 5ms);
        B->r().tick();
        clk.add(2999);
        B->r().tick();
        const u64 d_wait = B->st().dials.load();
        clk.add(1);
        B->r().tick();
        clk.add(999);
        B->r().tick();
        const u64 d_backoff = B->st().dials.load();
        clk.add(1);
        B->r().tick();
        const u64 d_after = B->st().dials.load();
        std::printf("    dials: %llu (2999 ms) %llu (3999 ms) %llu (4000 ms)\n", (unsigned long long)d_wait,
                    (unsigned long long)d_backoff, (unsigned long long)d_after);
        C(up && gone && d_wait == 1 && d_backoff == 1 && d_after == 2,
          "N6 bound: no redial before hello_timeout_ms with the down event held; released then, redialed 1 s later");
        B->links.release_downs();
        B->r().tick();
        C(B->st().dials.load() == 2 && wait_until([&] { return srv.n_peers() == 1; }, 8000ms, 5ms),
          "N6 bound: the late down event leaves the new link alone");
        B.reset();
        srv.stop();
    }
}

int main() {
    Checker C;
    std::printf("== v37_xmr_relay_node_nonce_kat ==\n");
    Rig rig;
    n1_codec(C, rig);
    n2_opcodes(C);
    n3_seeds(C, rig);
    n4_self(C, rig);
    n5_dup(C, rig);
    n6_release(C, rig);
    return C.done("v37_xmr_relay_node_nonce_kat");
}
