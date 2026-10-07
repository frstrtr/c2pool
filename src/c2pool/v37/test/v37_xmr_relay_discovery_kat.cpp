// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// v37_xmr_relay_discovery_kat -- RELAY-DISCOVERY (FB_GETADDR 0x4c / FB_ADDR 0x4d)
//   D1 PeerBook: learn / good / failed-backoff / bad (never re-learned) /
//      cap (a good entry is never displaced by a candidate) / expiry / order
//   D2 five nodes, each knowing ONLY node 0: every node ends linked to >= 3
//      others, learned through FB_ADDR; one link per node pair
//   D3 a node of ANOTHER pool (other pool genesis) offered as a candidate is
//      refused at HELLO, never good, never re-learned from an ADDR
//   D4 restart with node 0 DOWN and no seed: the persisted book alone
//      reconnects the node to its stored peers
//   D5 abuse: an unsolicited FB_ADDR is ignored; a GETADDR flood is throttled;
//      a discovery-OFF node counts 0x4c/0x4d as fb_unknown and keeps the socket
// Red on a tree without the frames (does not compile), green with them.
#include <atomic>
#include <chrono>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <thread>

#include "xmr_relay_test_util.hpp"
#include <c2pool/v37/carrier_net.hpp>
#include <c2pool/v37/xmr/relay/xmr_relay_node.hpp>

using namespace gap2test;
using namespace std::chrono_literals;
using c2pool::v37n::CarrierPeerNode;

static constexpr u64 kShareDiff = 1000;

static RelayOptions dopts(u8 genesis_seed, std::vector<u16> dial, bool discovery = true) {
    RelayOptions o;
    ::v37::LaneParams lp{};
    o.network = 3; o.chain = 0; o.share_diff = kShareDiff; o.bind = BindMode::None;
    o.lane_params_digest = lane_params_digest(lp, kShareDiff, BindMode::None, 3);
    o.pool_id = pool_id_of(0, lp);
    o.pool_id->genesis = b32_of(genesis_seed);
    o.listen = true; o.listen_host = "127.0.0.1"; o.listen_port = 0;
    for (u16 p : dial) o.peers.emplace_back("127.0.0.1", p);
    o.hello_timeout_ms = 3000;
    o.discovery = discovery;
    o.max_outbound = 8;
    o.addr_reask_ms = 500;
    o.addr_answer_min_ms = 200;
    o.book_save_ms = 300;
    o.connect_timeout_ms = 1000;
    return o;
}

struct DNode {
    std::string name;
    ChainView chain;
    std::unique_ptr<XmrRelayNode> relay;
    std::mutex mtx;
    std::vector<PeerRecord> saved;
    std::vector<std::string> logs;
    DNode(std::string n, RelayOptions o) : name(std::move(n)) {
        o.book_save = [this](const std::vector<PeerRecord>& v) { std::lock_guard<std::mutex> lk(mtx); saved = v; };
        relay = std::make_unique<XmrRelayNode>(
            std::move(o), chain,
            [](const std::vector<u8>&, const bytes32&, bytes32& pow) { pow.fill(0); return true; },
            []() -> std::pair<u64, bytes32> { return {0, bytes32{}}; },
            [this](const std::string& l) { std::lock_guard<std::mutex> lk(mtx); logs.push_back(l); });
    }
    ~DNode() { relay->stop(); }
    bool start() { std::string why; return relay->start(why); }
    u16 port() const { return relay->listen_port(); }
    std::string key() const { return peer_key("127.0.0.1", port()); }
    std::vector<PeerRecord> saved_book() { std::lock_guard<std::mutex> lk(mtx); return saved; }
    std::size_t links() const { return relay->ready_links().size(); }
    std::set<std::string> link_keys() const {
        std::set<std::string> s; for (const auto& [k, o] : relay->ready_links()) { (void)o; s.insert(k); } return s;
    }
    std::size_t count_logs(const std::string& a) {
        std::lock_guard<std::mutex> lk(mtx);
        std::size_t n = 0; for (const auto& l : logs) n += l.find(a) != std::string::npos; return n;
    }
};

template <class F>
static bool wait_until(F cond, std::chrono::milliseconds limit) {
    const auto dl = std::chrono::steady_clock::now() + limit;
    while (std::chrono::steady_clock::now() < dl) { if (cond()) return true; std::this_thread::sleep_for(50ms); }
    return cond();
}

static std::string graph(const std::vector<DNode*>& ns) {
    std::map<std::string, std::string> nm;
    for (auto* n : ns) nm[n->key()] = n->name;
    std::string g;
    for (auto* n : ns) {
        g += "      " + n->name + " -> {";
        bool first = true;
        for (const auto& k : n->link_keys()) { g += (first ? "" : ",") + (nm.count(k) ? nm[k] : k); first = false; }
        g += "}\n";
    }
    return g;
}

static void d1_book(Checker& C) {
    std::printf("-- D1 PeerBook policy\n");
    PeerBook::Limits L; L.max_entries = 4; L.candidate_ttl_s = 100; L.good_ttl_s = 1000; L.max_fails = 3; L.backoff_base_s = 5;
    PeerBook b(L);
    const u64 T = 1'000'000;
    C(b.learn("10.0.0.1", 1, T, T) && !b.learn("10.0.0.1", 1, T, T), "D1 learn is idempotent (second learn = not new)");
    C(!b.is_good("10.0.0.1", 1), "D1 a learned address is a candidate, NOT good");
    b.mark_good("10.0.0.1", 1, T);
    C(b.is_good("10.0.0.1", 1) && b.good() == 1, "D1 mark_good (HELLO ok, right pool id) -> good");
    C(b.learn("10.0.0.2", 2, T + 50, T), "D1 a future last_seen is clamped to now");
    b.mark_failed("10.0.0.2", 2, T);
    auto dc = b.dial_candidates(8, T + 1, {});
    C(dc.size() == 1 && dc[0].host == "10.0.0.1", "D1 a failed entry backs off (not a dial candidate at +1 s)");
    C(b.dial_candidates(8, T + 6, {}).size() == 2, "D1 ... and is again after the 5 s backoff");
    b.mark_failed("10.0.0.2", 2, T + 6); b.mark_failed("10.0.0.2", 2, T + 20);
    C(!b.contains("10.0.0.2", 2), "D1 max_fails consecutive failures drop the entry");
    b.learn("10.0.0.3", 3, T, T);
    b.mark_bad("10.0.0.3", 3);
    C(!b.contains("10.0.0.3", 3) && !b.learn("10.0.0.3", 3, T, T), "D1 mark_bad (refused at HELLO) erases and is never re-learned");
    b.mark_good("10.0.0.4", 4, T); b.mark_good("10.0.0.5", 5, T); b.mark_good("10.0.0.6", 6, T);
    C(b.size() == 4 && b.good() == 4, "D1 4 good entries fill the cap of 4");
    C(!b.learn("10.0.0.7", 7, T, T) && b.size() == 4, "D1 a full book of good peers is not displaced by a candidate");
    PeerBook c(L);
    for (int i = 0; i < 4; ++i) c.learn("10.1.0." + std::to_string(i), 9, T + i, T + 10);
    C(c.learn("10.1.0.9", 9, T + 9, T + 10) && !c.contains("10.1.0.0", 9) && c.size() == 4,
      "D1 at the cap a fresher candidate evicts the stalest candidate");
    auto s = b.sample_good(2, [](const PeerRecord& r) { return r.port != 4; });
    C(s.size() == 2 && s[0].port != 4 && s[1].port != 4, "D1 sample_good is bounded and honours the filter");
    dc = b.dial_candidates(8, T, {peer_key("10.0.0.5", 5)});
    bool skipped = true; for (const auto& r : dc) skipped = skipped && r.port != 5;
    C(skipped, "D1 dial_candidates skips linked / queued addresses");
    PeerBook e(L);
    e.learn("10.2.0.1", 1, T, T); e.mark_good("10.2.0.2", 2, T);
    C(e.expire(T + 101) == 1 && e.size() == 1 && e.is_good("10.2.0.2", 2), "D1 a stale candidate expires, a good one outlives it");
    C(e.expire(T + 1001) == 1 && e.size() == 0, "D1 a stale good entry expires too");
    PeerBook r(L);
    r.load({PeerRecord{"10.3.0.1", 7, T, T + 5, true, 0}, PeerRecord{"", 1, 0, 0, false, 0}}, T + 1);
    auto rec = r.records();
    C(rec.size() == 1 && rec[0].good && rec[0].last_seen == T + 1, "D1 load: invalid rows skipped, last_seen clamped, good kept");
}

int main() {
    Checker C;
    std::printf("== v37_xmr_relay_discovery_kat ==\n");
    d1_book(C);

    std::printf("-- D2 five nodes, each knowing only node 0\n");
    auto n0 = std::make_unique<DNode>("n0", dopts(1, {}));
    C(n0->start(), "D2 n0 starts (listens, dials nobody)");
    std::vector<std::unique_ptr<DNode>> ns;
    for (int i = 1; i <= 4; ++i) {
        ns.push_back(std::make_unique<DNode>("n" + std::to_string(i), dopts(1, {n0->port()})));
        C(ns.back()->start(), "D2 n" + std::to_string(i) + " starts, --relay-peer = n0 only");
    }
    std::vector<DNode*> all{n0.get()};
    for (auto& n : ns) all.push_back(n.get());
    const auto t0 = std::chrono::steady_clock::now();
    const bool meshed = wait_until([&] { for (auto* n : all) if (n->links() < 3) return false; return true; }, 30000ms);
    const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    std::printf("    graph after %lld ms:\n%s", (long long)ms, graph(all).c_str());
    C(meshed, "D2 every node linked to >= 3 others within 30 s");
    // Every link not to n0 exists because some node learned the other's address
    // from an FB_ADDR and dialed it (a node may end with only INBOUND learned
    // links: its peers dialed it first).
    bool via_addr = true; u64 dial_ok = 0;
    for (auto& n : ns) { via_addr = via_addr && n->relay->stats().addr_learned.load() >= 3; dial_ok += n->relay->stats().disc_dial_ok.load(); }
    C(via_addr, "D2 n1..n4 each learned >= 3 addresses via FB_ADDR");
    C(dial_ok >= 6, "D2 >= 6 learned dials completed HELLO (the 6 pairs among n1..n4)");
    bool one_link = true;
    for (auto* n : all) one_link = one_link && n->link_keys().size() == n->links();
    C(one_link, "D2 at most one link per node pair (duplicates dropped)");
    for (auto* n : all) std::printf("    %s %s\n", n->name.c_str(), n->relay->disc_describe().c_str());

    std::printf("-- D3 another pool's node offered as a candidate\n");
    DNode X("X", dopts(2, {}));
    C(X.start(), "D3 X (other --pool-genesis) starts");
    RelayOptions oy = dopts(1, {n0->port()});
    oy.seeds.emplace_back("127.0.0.1", X.port());
    DNode Y("Y", oy);
    C(Y.start(), "D3 Y starts with X as a SEED candidate (the bootstrap seam)");
    C(wait_until([&] { return Y.relay->book().is_bad("127.0.0.1", X.port()); }, 15000ms), "D3 Y dialed X, X refused at HELLO -> marked bad");
    C(!Y.relay->book().is_good("127.0.0.1", X.port()) && !Y.relay->book().contains("127.0.0.1", X.port()),
      "D3 X is never good and not in Y's book");
    C(!const_cast<PeerBook&>(Y.relay->book()).learn("127.0.0.1", X.port(), 1, 2), "D3 an FB_ADDR naming X cannot re-learn it");
    bool nobody = true;
    for (auto* n : all) nobody = nobody && !n->relay->book().is_good("127.0.0.1", X.port());
    C(nobody && X.links() == 0, "D3 no node of the pool holds X as good; X has no link");
    std::this_thread::sleep_for(500ms);
    bool saved_clean = true;
    for (const auto& r : Y.saved_book()) saved_clean = saved_clean && r.port != X.port();
    C(saved_clean, "D3 Y's persisted book does not contain X");

    std::printf("-- D4 restart n3 with n0 DOWN, no seed: the persisted book alone\n");
    std::this_thread::sleep_for(700ms);   // > book_save_ms: n3's book is on "disk"
    auto stored = ns[2]->saved_book();
    std::size_t good = 0; for (const auto& r : stored) good += r.good ? 1 : 0;
    std::printf("    n3 persisted %zu entries, %zu good\n", stored.size(), good);
    C(good >= 3, "D4 n3 persisted >= 3 good peers");
    n0->relay->stop();
    ns[2]->relay->stop();
    ns[2].reset();
    RelayOptions o3 = dopts(1, {n0->port()});   // its --relay-peer (n0) is DOWN
    o3.book_load = stored;
    DNode n3b("n3'", o3);
    C(n3b.start(), "D4 n3' starts with the stored book, n0 down");
    C(wait_until([&] { return n3b.links() >= 2; }, 20000ms), "D4 n3' reconnects to >= 2 stored peers without n0 / any seed");
    std::printf("    n3' links: "); for (const auto& k : n3b.link_keys()) std::printf("%s ", k.c_str()); std::printf("\n");
    C(!n3b.link_keys().count(n0->key()), "D4 n0 is not among them (it is down)");

    std::printf("-- D5 abuse limits + a discovery-OFF peer\n");
    RelayOptions oz = dopts(1, {});
    oz.addr_reask_ms = 60000; oz.addr_answer_min_ms = 5000;
    DNode Z("Z", oz);
    C(Z.start(), "D5 Z starts (re-ask 60 s, one answer per 5 s)");
    DNode* tgt = &Z;
    CarrierPeerNode raw;
    std::atomic<int> addr_rx{0}, getaddr_rx{0};
    raw.set_inbound_from([&](CarrierPeerNode::PeerId, const std::vector<u8>& f) {
        if (!f.empty() && f[0] == FB_ADDR) addr_rx++;
        if (!f.empty() && f[0] == FB_GETADDR) getaddr_rx++;
    });
    const auto pid = raw.add_peer_id("127.0.0.1", tgt->port());
    C(pid != 0, "D5 a raw client connects to Z");
    Hello h = tgt->relay->our_hello(); h.node_nonce = 0x5eed; h.listen_port = 0;
    raw.send_to(pid, encode_hello(h));
    C(wait_until([&] { return getaddr_rx.load() == 1; }, 3000ms), "D5 Z asks the new peer for addresses once (FB_GETADDR after HELLO ok)");
    raw.send_to(pid, encode_addr(0, {}));   // the solicited answer: nothing known
    std::this_thread::sleep_for(300ms);
    C(tgt->relay->stats().addr_rx.load() == 1, "D5 the solicited (empty) FB_ADDR is taken");
    const u64 before = tgt->relay->stats().addr_unsolicited.load();
    const std::size_t book_before = tgt->relay->book().size();
    AddrEntry e; addr_entry_of("127.0.0.1", 1, 0, e);
    std::vector<AddrEntry> flood;
    for (int i = 1; i <= 200; ++i) { e.port = static_cast<u16>(20000 + i); flood.push_back(e); }
    raw.send_to(pid, encode_addr(0, flood));
    std::this_thread::sleep_for(300ms);
    C(tgt->relay->stats().addr_unsolicited.load() == before + 1 && tgt->relay->book().size() == book_before,
      "D5 an unsolicited FB_ADDR (200 entries) is ignored: nothing learned");
    for (int i = 0; i < 5; ++i) raw.send_to(pid, encode_getaddr(0, 64));
    std::this_thread::sleep_for(400ms);
    C(addr_rx.load() == 1 && tgt->relay->stats().getaddr_throttled.load() >= 4, "D5 a GETADDR burst of 5 gets ONE answer (rest throttled)");
    raw.stop();
    DNode off("off", dopts(1, {}, /*discovery=*/false));
    C(off.start(), "D5 a discovery-OFF node starts");
    CarrierPeerNode raw2;
    const auto p2 = raw2.add_peer_id("127.0.0.1", off.port());
    Hello h2 = off.relay->our_hello(); h2.node_nonce = 0x5eee; h2.listen_port = 0;
    raw2.send_to(p2, encode_hello(h2));
    std::this_thread::sleep_for(300ms);
    raw2.send_to(p2, encode_getaddr(0, 8));
    raw2.send_to(p2, encode_addr(0, {}));
    std::this_thread::sleep_for(300ms);
    C(off.relay->stats().fb_unknown.load() == 2 && off.relay->ready_peers().size() == 1,
      "D5 discovery OFF: 0x4c/0x4d counted fb_unknown, socket kept");
    raw2.stop();
    return C.done("v37_xmr_relay_discovery_kat");
}
