// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// v37_xmr_relay_node_nonce_kat -- NODE-NONCE (the relay HELLO node nonce)
//   N1 HELLO nonce codec + bounds: a random 64-bit per-process nonce, never 0,
//      at the fixed byte offset 51 of EVERY HELLO length (so every build that
//      speaks FB_HELLO v1 carries it); every other frame length is refused
//   N2 the Family-B opcode map: exact values, all distinct, 0x4a/0x4b unused
//   N3 bootstrap -> discovery seeds (#1819 x #1820): routed by the discovery
//      switch; a seed is dialed and is GOOD after its HELLO
//   N4 self-connection: a node given its own address (--relay-peer, exact and
//      an alias; an FB_ADDR naming it) never keeps a link to itself, dials an
//      alias at most once, marks it SELF in the book, never hands it out
//   N5 duplicate in/out pair: exactly one link per node pair, the SAME socket
//      on both ends, no churn, no penalty (dup_link_rule both-ends agreement)
// Red on master (no discovery: N3-N5 absent) and on the pre-NODE-NONCE train
// (self redial / alias churn); green with NODE-NONCE.
#include <atomic>
#include <chrono>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <thread>

#include "xmr_relay_test_util.hpp"
#if __has_include(<c2pool/v37/xmr/relay/xmr_relay_peerbook.hpp>)
#define NN_HAVE_DISC 1
#include <c2pool/v37/carrier_net.hpp>
#include <c2pool/v37/xmr/relay/xmr_relay_node.hpp>
#include <c2pool/v37/xmr/relay/xmr_relay_bootstrap.hpp>
using c2pool::v37n::CarrierPeerNode;
#endif
#if defined(NN_HAVE_DISC) && defined(C2POOL_XMR_RELAY_NODE_NONCE)
#define NN_API 1   // the NODE-NONCE self / duplicate API
#endif

using namespace gap2test;
using namespace std::chrono_literals;

static constexpr u64 kShareDiff = 1000;

static Hello base_hello(u64 nonce) {
    Hello h; ::v37::LaneParams lp{};
    h.network = 3; h.chain_id = 0; h.share_diff = kShareDiff; h.node_nonce = nonce; h.listen_port = 7320;
    h.lane_params_digest = lane_params_digest(lp, kShareDiff, BindMode::None, 3);
    return h;
}

static void n1_codec(Checker& C) {
    std::printf("-- N1 HELLO node nonce: codec + bounds\n");
    const u64 X = 0x8877665544332211ull;
    ::v37::LaneParams lp{};
    std::vector<Hello> forms;
    Hello a = base_hello(X); forms.push_back(a);                       // 102 B (tagless)
    Hello b = a; b.pool = pool_id_of(0, lp); forms.push_back(b);      // 142 B (POOL-ID)
    Hello c = b; c.pool->genesis = b32_of(9); forms.push_back(c);     // 174 B (POOL-LINEAGE)
    std::set<std::size_t> lens;
    bool rt = true, off = true;
    for (const auto& h : forms) {
        const auto f = encode_hello(h);
        lens.insert(f.size());
        Hello d; std::string why;
        rt = rt && decode_hello(f, d, &why) && d.node_nonce == X && d == h;
        u64 at51 = 0; for (int i = 7; i >= 0; --i) at51 = (at51 << 8) | f[51 + i];
        off = off && at51 == X;
    }
    C(rt, "N1 every HELLO form round-trips the 64-bit node nonce");
    C(off, "N1 the nonce sits at byte 51 (LE) of every HELLO length: no pre-nonce HELLO exists");
    C(lens == std::set<std::size_t>{kHelloBytes, kHelloBytesPoolId, kHelloBytesPoolGenesis},
      "N1 HELLO lengths are exactly {102, 142, 174} at flip 0");
    bool bounded = true;
    const auto full = encode_hello(c);
    for (std::size_t n = 1; n <= 260; ++n) {
        if (n == kHelloBytes || n == kHelloBytesPoolId || n == kHelloBytesPoolGenesis ||
            (kHelloEnrolSetLive && n == kHelloBytesEnrolSet)) continue;
        std::vector<u8> f(full.begin(), full.begin() + std::min(n, full.size()));
        f.resize(n, 0);
        Hello d; bounded = bounded && !decode_hello(f, d);
    }
    C(bounded, "N1 every other HELLO length (1..260) is refused (bounded decoder)");
    Hello same = a, other = a; other.node_nonce = X ^ 1;
    C(hello_mismatch(a, same).find("self-connection") != std::string::npos, "N1 equal nonce = self-connection");
    C(hello_mismatch(a, other).empty(), "N1 a different nonce with equal pool rules is accepted");
}

static void n2_opcodes(Checker& C) {
    std::printf("-- N2 Family-B opcode map\n");
    const std::vector<std::pair<const char*, std::pair<u8, u8>>> map = {
        {"HELLO", {FB_HELLO, 0x40}}, {"RECEIPTS", {FB_RECEIPTS, 0x41}}, {"BLOCK_WON", {FB_BLOCK_WON, 0x42}},
        {"GETCTX", {FB_GETCTX, 0x43}}, {"CTX", {FB_CTX, 0x44}}, {"GETDROPS", {FB_GETDROPS, 0x45}},
        {"DROPINV", {FB_DROPINV, 0x46}}, {"GETWON", {FB_GETWON, 0x47}}, {"PING", {FB_PING, 0x48}},
        {"PONG", {FB_PONG, 0x49}},
#ifdef NN_HAVE_DISC
        {"GETADDR", {FB_GETADDR, 0x4c}}, {"ADDR", {FB_ADDR, 0x4d}},
#endif
    };
    std::set<u8> seen; bool exact = true, range = true;
    for (const auto& [n, v] : map) {
        if (v.first != v.second) { exact = false; std::printf("    %s = 0x%02x, want 0x%02x\n", n, v.first, v.second); }
        range = range && v.first >= FB_NS_FIRST && v.first <= FB_NS_LAST;
        seen.insert(v.first);
    }
    C(exact, "N2 opcodes are 0x40 HELLO .. 0x49 PONG, 0x4c GETADDR, 0x4d ADDR");
    C(seen.size() == map.size(), "N2 all Family-B opcodes are distinct");
    C(range && !seen.count(0x4a) && !seen.count(0x4b), "N2 all in 0x40..0x4f; 0x4a/0x4b stay reserved (LANE-EPOCH)");
    C(map.size() == 12, "N2 twelve Family-B opcodes (GETADDR/ADDR present)");
}

#ifdef NN_HAVE_DISC
static RelayOptions nopts(std::string listen_host, std::vector<std::pair<std::string, u16>> dial) {
    RelayOptions o; ::v37::LaneParams lp{};
    o.network = 3; o.chain = 0; o.share_diff = kShareDiff; o.bind = BindMode::None;
    o.lane_params_digest = lane_params_digest(lp, kShareDiff, BindMode::None, 3);
    o.pool_id = pool_id_of(0, lp); o.pool_id->genesis = b32_of(1);
    o.listen = true; o.listen_host = std::move(listen_host); o.listen_port = 0;
    o.peers = std::move(dial);
    o.hello_timeout_ms = 3000; o.discovery = true; o.max_outbound = 8;
    o.addr_reask_ms = 500; o.addr_answer_min_ms = 200; o.book_save_ms = 300; o.connect_timeout_ms = 1000;
    return o;
}
struct NNode {
    ChainView chain;
    std::unique_ptr<XmrRelayNode> relay;
    std::mutex mtx; std::vector<std::string> logs;
    explicit NNode(RelayOptions o) {
        relay = std::make_unique<XmrRelayNode>(std::move(o), chain,
            [](const std::vector<u8>&, const bytes32&, bytes32& pow) { pow.fill(0); return true; },
            []() -> std::pair<u64, bytes32> { return {0, bytes32{}}; },
            [this](const std::string& l) { std::lock_guard<std::mutex> lk(mtx); logs.push_back(l); });
    }
    ~NNode() { relay->stop(); }
    bool start() { std::string why; return relay->start(why); }
    u16 port() const { return relay->listen_port(); }
    std::size_t count_logs(const std::string& a) {
        std::lock_guard<std::mutex> lk(mtx);
        std::size_t n = 0; for (const auto& l : logs) n += l.find(a) != std::string::npos; return n;
    }
    std::size_t links() const { return relay->ready_links().size(); }
    const RelayStats& st() const { return relay->stats(); }
};
template <class F> static bool wait_until(F cond, std::chrono::milliseconds limit) {
    const auto dl = std::chrono::steady_clock::now() + limit;
    while (std::chrono::steady_clock::now() < dl) { if (cond()) return true; std::this_thread::sleep_for(50ms); }
    return cond();
}

static void n3_seeds(Checker& C) {
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
    NNode T(nopts("127.0.0.1", {}));
    C(T.start(), "N3 T (a bootstrap node) starts");
    RelayOptions os = nopts("127.0.0.1", {});
    route_bootstrap({"127.0.0.1:" + std::to_string(T.port())}, true, os.seeds, os.peers);
    NNode S(os);
    C(S.start() && S.relay->book().contains("127.0.0.1", T.port()) && !S.relay->book().is_good("127.0.0.1", T.port()),
      "N3 S starts with T as a seed CANDIDATE (not yet good)");
    C(wait_until([&] { return S.relay->book().is_good("127.0.0.1", T.port()) && S.links() == 1; }, 10000ms),
      "N3 S dials the seed and it is GOOD after HELLO");
    C(T.relay->node_nonce() != 0 && S.relay->node_nonce() != 0 && T.relay->node_nonce() != S.relay->node_nonce(),
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
static std::vector<AddrEntry> raw_exchange(NNode& n, const std::vector<AddrEntry>& answer) {
    CarrierPeerNode raw;
    std::mutex m; std::vector<AddrEntry> got; std::atomic<int> getaddr{0}, addr{0};
    raw.set_inbound_from([&](CarrierPeerNode::PeerId, const std::vector<u8>& f) {
        if (!f.empty() && f[0] == FB_GETADDR) getaddr++;
        if (!f.empty() && f[0] == FB_ADDR) { u32 c = 0; std::vector<AddrEntry> v;
            if (decode_addr(f, c, v)) { std::lock_guard<std::mutex> lk(m); got.insert(got.end(), v.begin(), v.end()); } addr++; }
    });
    const auto pid = raw.add_peer_id("127.0.0.1", n.port());
    Hello h = n.relay->our_hello(); h.node_nonce = n.relay->node_nonce() ^ 0x5eedull; h.listen_port = 0;
    raw.send_to(pid, encode_hello(h));
    wait_until([&] { return getaddr.load() >= 1; }, 3000ms);
    raw.send_to(pid, encode_addr(0, answer));
    std::this_thread::sleep_for(400ms);
    raw.send_to(pid, encode_getaddr(0, 64));
    wait_until([&] { return addr.load() >= 1; }, 3000ms);
    raw.stop();
    std::lock_guard<std::mutex> lk(m); return got;
}

static void n4_self(Checker& C) {
    std::printf("-- N4 self-connection\n");
    const u16 P = free_port();
    RelayOptions oa = nopts("0.0.0.0", {{"127.0.0.1", P}, {"127.0.1.1", P}});   // its own address, exact + alias
    oa.listen_port = P;
    NNode A(oa);
    C(A.start() && A.port() == P, "N4 A listens on 0.0.0.0:P, --relay-peer = 127.0.0.1:P and 127.0.1.1:P (itself)");
    std::this_thread::sleep_for(7000ms);
    std::printf("    A: dials=%llu hello_ok=%llu refused=%llu | %s\n", (unsigned long long)A.st().dials.load(),
                (unsigned long long)A.st().hello_ok.load(), (unsigned long long)A.st().hello_rejected.load(),
                A.relay->disc_describe().c_str());
    C(A.st().hello_ok.load() == 0 && A.links() == 0, "N4 A never has a link to itself (0 self links reach HELLO ok)");
    C(A.st().dials.load() <= 1, "N4 A dials its own address at most once in 7 s (exact: never; alias: once)");
#ifdef NN_API
    C(A.st().self_conn.load() >= 1 && A.st().self_skipped.load() >= 1, "N4 alias self-dial detected by nonce on both ends; exact one skipped");
    C(A.relay->book().is_self("127.0.1.1", P) && A.relay->book().is_self("127.0.0.1", P), "N4 both addresses marked SELF in the book");
    const_cast<PeerBook&>(A.relay->book()).mark_good("127.0.1.1", P, 1);
    C(!A.relay->book().is_good("127.0.1.1", P), "N4 a SELF address can never become good");
#else
    C(false, "N4 NODE-NONCE self API absent (is_self / self_conn)");
#endif
    bool leaked = false;
    for (const auto& e : raw_exchange(A, {})) leaked = leaked || e.port == P;
    C(!leaked, "N4 A never hands its own address out in FB_ADDR");

    NNode Cc(nopts("127.0.0.1", {}));
    C(Cc.start(), "N4 C (a control peer) starts");
    NNode B(nopts("127.0.0.1", {}));
    C(B.start(), "N4 B starts (no peers)");
    AddrEntry eb, ec; addr_entry_of("127.0.0.1", B.port(), 1, eb); addr_entry_of("127.0.0.1", Cc.port(), 1, ec);
    raw_exchange(B, {eb, ec});   // an FB_ADDR naming B itself (and C)
    C(wait_until([&] { return B.links() >= 1; }, 8000ms), "N4 B learns C from the FB_ADDR and links to it");
    std::this_thread::sleep_for(2000ms);
    C(B.count_logs("self-connection") == 0 && B.st().disc_self.load() == 0, "N4 B never dials its own address fed by FB_ADDR (0 self-connections)");
    C(!B.relay->book().contains("127.0.0.1", B.port()), "N4 B's own address is not in its book");
}

static void n5_dup(Checker& C) {
    std::printf("-- N5 duplicate in/out pair\n");
    const u16 pp = free_port(), pq = free_port();
    RelayOptions op = nopts("127.0.0.1", {{"127.0.0.1", pq}}); op.listen_port = pp;
    RelayOptions oq = nopts("127.0.0.1", {{"127.0.0.1", pp}}); oq.listen_port = pq;
    NNode P(op), Q(oq);
    C(P.start() && Q.start(), "N5 P and Q each dial the other");
    C(wait_until([&] { return P.links() == 1 && Q.links() == 1; }, 8000ms), "N5 one link each");
    std::this_thread::sleep_for(2000ms);
    const u64 hp = P.st().hello_ok.load(), hq = Q.st().hello_ok.load();
    std::this_thread::sleep_for(5000ms);
    const auto lp = P.relay->ready_links(), lq = Q.relay->ready_links();
    C(lp.size() == 1 && lq.size() == 1 && lp[0].second != lq[0].second, "N5 exactly ONE link per pair, the same socket on both ends");
    const bool p_low = P.relay->node_nonce() < Q.relay->node_nonce();
    C(lp.size() == 1 && lp[0].second == p_low, "N5 the kept link is the one dialed by the lower node nonce");
    C(P.st().hello_ok.load() == hp && Q.st().hello_ok.load() == hq, "N5 no churn over 5 s (no new HELLO)");
    C(P.st().bans.load() == 0 && Q.st().bans.load() == 0 && P.relay->book().is_good("127.0.0.1", pq) &&
      Q.relay->book().is_good("127.0.0.1", pp), "N5 no penalty: no ban, both still GOOD in each other's book");

    // same direction: P2 dials Q2 twice (two addresses of one node)
    const u16 p2 = free_port(), q2 = free_port();
    RelayOptions oq2 = nopts("0.0.0.0", {}); oq2.listen_port = q2;
    NNode Q2(oq2);
    C(Q2.start(), "N5 Q2 listens on 0.0.0.0");
    RelayOptions op2 = nopts("127.0.0.1", {{"127.0.0.1", q2}, {"127.0.1.1", q2}}); op2.listen_port = p2;
    NNode P2(op2);
    C(P2.start(), "N5 P2 dials Q2 under two addresses (127.0.0.1 and 127.0.1.1)");
    C(wait_until([&] { return P2.links() == 1 && Q2.links() == 1; }, 8000ms), "N5 one link each");
    RelayOptions or3 = nopts("127.0.0.1", {{"127.0.0.1", p2}});   // R knows only P2: learns BOTH addresses of Q2
    NNode R3(or3);
    C(R3.start(), "N5 R starts, --relay-peer = P2 only");
    C(wait_until([&] { return R3.links() == 2; }, 10000ms), "N5 R links to P2 and Q2 (one link each)");
    std::this_thread::sleep_for(3000ms);
    const u64 hp2 = P2.st().hello_ok.load(), hq2 = Q2.st().hello_ok.load();
    const u64 hr3 = R3.st().hello_ok.load(), dr3 = R3.st().disc_dup_dropped.load(), dl3 = R3.st().disc_dialed.load();
    std::this_thread::sleep_for(6000ms);
    std::printf("    R %s\n", R3.relay->disc_describe().c_str());
    C(R3.links() == 2 && R3.st().hello_ok.load() == hr3 && R3.st().disc_dup_dropped.load() == dr3 && R3.st().disc_dialed.load() == dl3,
      "N5 a learned second address of a linked node is not redialed (no churn from the book)");
    std::printf("    P2 %s\n    Q2 %s\n", P2.relay->disc_describe().c_str(), Q2.relay->disc_describe().c_str());
    C(P2.links() == 2 && Q2.links() == 2, "N5 same-dialer duplicate: exactly ONE link per pair (P2, Q2 each: the other + R)");
    C(P2.st().hello_ok.load() == hp2 && Q2.st().hello_ok.load() == hq2, "N5 same-dialer duplicate: no redial churn over 6 s");
#ifdef NN_API
    C(Q2.st().dup_deferred.load() >= 1 && Q2.st().disc_dup_dropped.load() == 0 && P2.st().disc_dup_dropped.load() == 1,
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
#else
    C(false, "N5 NODE-NONCE duplicate API absent (dup_link_rule / dup_deferred)");
#endif
}
#endif  // NN_HAVE_DISC

int main() {
    Checker C;
    std::printf("== v37_xmr_relay_node_nonce_kat ==\n");
    n1_codec(C);
    n2_opcodes(C);
#ifdef NN_HAVE_DISC
    n3_seeds(C);
    n4_self(C);
    n5_dup(C);
#else
    C(false, "N3-N5 relay discovery absent on this tree (no peer book, no FB_GETADDR/FB_ADDR)");
#endif
    return C.done("v37_xmr_relay_node_nonce_kat");
}
