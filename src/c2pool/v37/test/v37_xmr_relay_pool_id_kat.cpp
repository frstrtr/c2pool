// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// v37_xmr_relay_pool_id_kat -- POOL-ID: the roundabout S1 lane_tag in the XMR
// relay HELLO. Two XMR v37 nodes on the SAME chain_id but a different pool /
// consensus configuration must refuse each other EXPLICITLY at HELLO
// (TAG_MISMATCH, both tags + the first differing field named, a counter), and
// never admit a receipt, a context or a lane block from each other. Nodes of
// the same pool behave exactly as before.
//
//   P1  wire: pool_id_of() == rb::lane_tag(LaneTagContext::of(chain, p,
//       SHIPPED, 0), 0, 0, 0); it moves with chain_id, k_floor, half_life,
//       window and version and NOT with a node-local field; HELLO with the
//       extension is 142 B and round-trips; a 102-byte HELLO still decodes
//       (pool none); hello_mismatch names TAG_MISMATCH + field
//       (geometry / chain_id / version / lane_tag) + both tags
//   P2  live geometry mismatch (3 loopback nodes, C runs another k_floor on the
//       same chain_id): C gets 0 ready relay peers, A/B keep each other; every
//       attempt is refused in BOTH directions as TAG_MISMATCH field=geometry
//       naming both tags (per dial: >= 1 line at A/B AND >= 1 line at X, read
//       with a bounded poll, lines before dials, so a dial still in flight is
//       waited for and never credited by a later one); the tag_mismatch
//       counter moves on A, B and C
//   P2c/P2d UP-GATE: the same with X's (P2c) or A's (P2d) connection-up event
//       held 150 ms, so the remote HELLO deterministically reaches the reader
//       before that node's own HELLO goes out. Pre-UP-GATE, X refused before
//       its HELLO left (A/B logged nothing for the dial) and A dropped B's
//       early HELLO (A<->B only came up after a HELLO timeout + redial)
//   P3  live consensus-version mismatch (same LaneParams, version 2): refused
//       as TAG_MISMATCH field=version -- the lane_params_digest alone does NOT
//       see this one (the base admits the peer)
//   P4  live chain_id mismatch: refused as TAG_MISMATCH field=chain_id
//   P5  nothing crosses: receipts minted at C never reach A/B (and A/B's
//       never reach C); A and B admit each other's and publish byte-identical
//       lane digests; a raw peer that sends a mismatched HELLO and then
//       RECEIPTS + BLOCK_WON + GETCTX in the same burst gets NONE of them
//       admitted (0 receipts, 0 lane blocks, 0 contexts served)
//   P7  FLAG DAY (#1803 review): this build's HELLO pool id (node_pool_id)
//       folds kXmrPoolRulesVersion, so a pre-#1803 node (pool id at
//       SHIPPED_CONSENSUS_VERSION, e.g. RC4 5db1f675) is refused AT HELLO as
//       TAG_MISMATCH field=version (wire + live 3-node case). RED on 272cac0d
//       (the pre-#1803 node is admitted, then stalls on the pool's blocks).
//   P6  same pool: tagged A/B produce the SAME lane digest for the same
//       receipts as a tagless (master-wire) pair
//
// Built against the pre-POOL-ID relay it still compiles and goes RED on the
// behaviour: the version-mismatched peer is admitted and no refusal is a
// TAG_MISMATCH.
#include <atomic>
#include <chrono>
#include <cstdlib>
#include <mutex>
#include <thread>

#include "xmr_relay_test_util.hpp"
#include <c2pool/v37/carrier_net.hpp>
#include <c2pool/v37/roundabout/rb_lane_tag.hpp>
#include <c2pool/v37/xmr/relay/xmr_relay_node.hpp>
#include <c2pool/v37/xmr/relay/xmr_receipt_ingest.hpp>
#include <c2pool/v37/v37_engine.hpp>

using namespace gap2test;
using namespace std::chrono_literals;
using c2pool::v37n::CarrierPeerNode;

static constexpr u32 kChain = 0;          // the default lane_chain of every XMR node config
static constexpr u64 kShareDiff = 1000;

struct Cfg {
    u32 chain = kChain;
    ::v37::LaneParams lp{};
    u32 version = ::v37::SHIPPED_CONSENSUS_VERSION;
    bool tagged = true;
};

static RelayOptions opts(const Cfg& c, bool listen, std::vector<u16> dial) {
    RelayOptions o;
    o.network = 3; o.chain = c.chain; o.share_diff = kShareDiff; o.bind = BindMode::None;
    o.lane_params_digest = lane_params_digest(c.lp, kShareDiff, BindMode::None, 3);
#ifdef C2POOL_XMR_RELAY_POOL_ID
    if (c.tagged) o.pool_id = pool_id_of(c.chain, c.lp, c.version);
#endif
    o.listen = listen; o.listen_host = "127.0.0.1"; o.listen_port = 0;
    for (u16 p : dial) o.peers.emplace_back("127.0.0.1", p);
    o.hello_timeout_ms = 3000;
    return o;
}

struct TNode {
    std::string name;
    Cfg cfg;
    ChainView chain;
    std::unique_ptr<c2pool::v37n::V37Engine> engine;
    std::unique_ptr<XmrRelayNode> relay;
    std::unique_ptr<XmrReceiptIngest> ingest;
    u64 template_height = 0;
    std::vector<std::string> logs;
    std::mutex log_mtx;
    TNode(std::string n, Cfg c, bool listen, std::vector<u16> dial) : name(std::move(n)), cfg(c) {
        engine = std::make_unique<c2pool::v37n::V37Engine>(4096);
        engine->start();
        engine->submit_tracked(::v37::LaneRecord::add_lane(cfg.chain, cfg.lp)).get();
        relay = std::make_unique<XmrRelayNode>(
            opts(cfg, listen, std::move(dial)), chain,
            [](const std::vector<u8>&, const bytes32&, bytes32& pow) { pow.fill(0); return true; },
            [this]() -> std::pair<u64, bytes32> {
                auto s = engine->snapshot(cfg.chain);
                if (!s) return {0, bytes32{}};
                return {s->next_pos, s->digest};
            },
            [this](const std::string& l) { std::lock_guard<std::mutex> lk(log_mtx); logs.push_back(l); });
        XmrReceiptIngest::Options io; io.chain = cfg.chain; io.order = XmrReceiptIngest::Order::Canonical; io.bin_lag = 1; io.grace_ms = 0;
        ingest = std::make_unique<XmrReceiptIngest>(
            io,
            [this](const ::v37::ScriptRef& payee, u64 w, u64& next_after, bytes32& dig) {
                ::v37::PayoutDescriptor d; d.pay = payee;
                if (!engine->submit_tracked(::v37::LaneRecord::push(cfg.chain, d, w, 0)).get().applied()) return false;
                auto s = engine->snapshot(cfg.chain);
                next_after = s->next_pos; dig = s->digest;
                return true;
            },
            [this](const Admitted& a, u64 pos, u32 n_pushes, u64 next_after, const bytes32& dig) {
                relay->on_pushed(a.id, pos, n_pushes, a.raw, next_after, dig);
            });
    }
    ~TNode() { relay->stop(); engine->stop(); }
    // UP-GATE KAT: hold this node's connection-up events (0 = off)
    bool up_delay(u32 ms) {
#ifdef C2POOL_XMR_RELAY_UP_GATE
        relay->set_test_up_delay_ms(ms);
        return true;
#else
        return ms == 0;
#endif
    }
    bool start() { std::string why; return relay->start(why); }
    void note_bin(const bytes32& prev, u64 height) { chain.note(prev, height, bytes32{}); chain.set_tip(height); }
    void pump() {
        for (auto& a : relay->drain_admitted()) ingest->on_admitted(std::move(a));
        ingest->tick(template_height);
    }
    u64 next_pos() { auto s = engine->snapshot(cfg.chain); return s ? s->next_pos : 0; }
    bytes32 digest() { auto s = engine->snapshot(cfg.chain); return s ? s->digest : bytes32{}; }
    std::vector<std::string> log_lines() { std::lock_guard<std::mutex> lk(log_mtx); return logs; }
    std::size_t count_logs(const std::string& a, const std::string& b = "", const std::string& c = "") {
        std::size_t n = 0;
        for (const auto& l : log_lines())
            if (l.find(a) != std::string::npos && (b.empty() || l.find(b) != std::string::npos) &&
                (c.empty() || l.find(c) != std::string::npos)) ++n;
        return n;
    }
    // The status-surface counter ("pool-id tag_mismatch=N" in describe()); -1 = absent.
    long long tag_mismatch_counter() const {
        const std::string d = relay->describe();
        const auto k = d.find("tag_mismatch=");
        if (k == std::string::npos) return -1;
        return std::atoll(d.c_str() + k + 13);
    }
};

template <class F>
static bool wait_for(F cond, std::vector<TNode*> pump, std::chrono::milliseconds limit = 15000ms) {
    const auto dl = std::chrono::steady_clock::now() + limit;
    while (std::chrono::steady_clock::now() < dl) {
        for (auto* n : pump) n->pump();
        if (cond()) return true;
        std::this_thread::sleep_for(20ms);
    }
    for (auto* n : pump) n->pump();
    return cond();
}

static Admitted own(const SynthBlock& sb, std::uint32_t nonce, const ::v37::ScriptRef& payee, u32 chain) {
    Admitted a; std::string why;
    if (!mint_on(sb, nonce, payee, chain, kShareDiff, a.r, &why)) std::printf("    mint failed: %s\n", why.c_str());
    a.id = receipt_id(a.r); a.raw = encode_fb_receipt(a.r); a.bin = sb.height; a.own = true;
    return a;
}

static std::string tag_hex(const Cfg& c) {
    const auto ctx = ::c2pool::v37n::rb::LaneTagContext::of(c.chain, c.lp, c.version, 0);
    return hex(::c2pool::v37n::rb::lane_tag(ctx, 0, 0, 0));
}

// One live mismatch scenario: A listens, B dials A, X (the other pool) dials
// A and B. Returns after checking the refusal on every side. `a_up_ms` /
// `x_up_ms` hold A's / X's connection-up events (UP-GATE).
static void mismatch_case(Checker& C, const char* tagp, const Cfg& same, const Cfg& other, const char* field,
                          u32 a_up_ms = 0, u32 x_up_ms = 0) {
    const std::string P = tagp;
    TNode A("A", same, true, {});
    if (a_up_ms) C(A.up_delay(a_up_ms), P + " A holds its up events " + std::to_string(a_up_ms) + " ms (test hook present)");
    C(A.start(), P + " A starts");
    TNode B("B", same, true, {A.relay->listen_port()});
    C(B.start(), P + " B starts, dials A");
    TNode X("X", other, false, {A.relay->listen_port(), B.relay->listen_port()});
    if (x_up_ms) C(X.up_delay(x_up_ms), P + " X holds its up events " + std::to_string(x_up_ms) + " ms (test hook present)");
    C(X.start(), P + " X (other pool, same network) starts, dials A and B");
    std::vector<TNode*> all{&A, &B, &X};
    C(wait_for([&] { return A.relay->ready_peers().size() == 1 && B.relay->ready_peers().size() == 1; }, all),
      P + " A<->B (same pool) HELLO ok");
    // let X make several dial attempts (redial backoff 1 s, 2 s, ...)
    wait_for([&] { return A.relay->stats().hello_rejected.load() >= 2 && B.relay->stats().hello_rejected.load() >= 2; }, all, 6000ms);
    // Every X dial must end in a TAG_MISMATCH line at the dialed node (A or B)
    // AND one at X. X keeps redialing, so the dial counted last may still be in
    // flight (its HELLOs not yet handled) when first read: poll (bounded) until
    // the lines cover the dials. The lines are read BEFORE the dial counter and
    // one dial makes at most one line on A|B and one at X, so "lines >= dials"
    // is never met by a later dial's line standing in for a missing one.
    const std::string ta = tag_hex(same), tx = tag_hex(other);
    const std::string tl = "TAG_MISMATCH field=" + std::string(field);
    std::size_t la = 0, lb = 0, lx = 0, attempts = 0;
    const bool settled = wait_for([&] {
        la = A.count_logs(tl, "ours=" + ta, "theirs=" + tx);
        lb = B.count_logs(tl, "ours=" + ta, "theirs=" + tx);
        lx = X.count_logs(tl, "ours=" + tx, "theirs=" + ta);
        attempts = static_cast<std::size_t>(X.relay->stats().dials.load());
        return attempts >= 2 && la + lb >= attempts && lx >= attempts;
    }, all, 10000ms);
    const std::size_t xr = X.relay->ready_peers().size();
    std::printf("    ready peers: A=%zu B=%zu X=%zu | hello_rejected A=%llu B=%llu X=%llu | dials X=%llu | hello_ok A=%llu B=%llu X=%llu | hello_timeout A=%llu B=%llu\n",
                A.relay->ready_peers().size(), B.relay->ready_peers().size(), xr,
                (unsigned long long)A.relay->stats().hello_rejected.load(), (unsigned long long)B.relay->stats().hello_rejected.load(),
                (unsigned long long)X.relay->stats().hello_rejected.load(), (unsigned long long)X.relay->stats().dials.load(),
                (unsigned long long)A.relay->stats().hello_ok.load(), (unsigned long long)B.relay->stats().hello_ok.load(),
                (unsigned long long)X.relay->stats().hello_ok.load(),
                (unsigned long long)A.relay->stats().hello_timeout.load(), (unsigned long long)B.relay->stats().hello_timeout.load());
    C(xr == 0, P + " the other-pool node X has 0 ready relay peers (" + std::to_string(xr) + ")");
    C(A.relay->ready_peers().size() == 1 && B.relay->ready_peers().size() == 1, P + " A and B keep exactly each other");
    std::printf("    TAG_MISMATCH log lines: A=%zu B=%zu X=%zu (X dial attempts %zu, settled=%d); last reject at A: %s\n",
                la, lb, lx, attempts, settled ? 1 : 0, A.relay->last_reject().c_str());
    C(la >= 1 && lb >= 1, P + " A and B log an explicit TAG_MISMATCH field=" + field + " naming both tags");
    C(lx >= 1, P + " X refuses too (both directions), naming both tags");
    C(la + lb >= attempts, P + " >= 1 TAG_MISMATCH line per X dial attempt (" +
                               std::to_string(la + lb) + " for " + std::to_string(attempts) + ")");
    C(lx >= attempts, P + " X logs >= 1 TAG_MISMATCH naming both tags per own dial attempt (" +
                          std::to_string(lx) + " for " + std::to_string(attempts) + ")");
    const long long ca = A.tag_mismatch_counter(), cb = B.tag_mismatch_counter(), cx = X.tag_mismatch_counter();
    std::printf("    tag_mismatch counter: A=%lld B=%lld X=%lld\n", ca, cb, cx);
    C(ca > 0 && cb > 0 && cx > 0, P + " the status-surface tag_mismatch counter moved on A, B and X");
    C(A.relay->stats().hello_ok.load() == 1 && B.relay->stats().hello_ok.load() == 1 && X.relay->stats().hello_ok.load() == 0,
      P + " no HELLO ever completed across the mismatch");
    X.relay->set_dialing(false);
}

int main() {
    Checker C;
    std::printf("== v37_xmr_relay_pool_id_kat ==\n");
    const ::v37::LaneParams base{};
    ::v37::LaneParams kf = base; kf.k_floor = ::v37::K_FLOOR_F_REF;
    ::v37::LaneParams hl = base; hl.half_life = base.half_life * 2;
    ::v37::LaneParams wd = base; wd.window = base.window / 2;

    // ── P1 wire ─────────────────────────────────────────────────────────────
#ifdef C2POOL_XMR_RELAY_POOL_ID
    {
        const PoolId id = pool_id_of(kChain, base);
        C(hex(id.lane_tag) == tag_hex(Cfg{}) && id.version == ::v37::SHIPPED_CONSENSUS_VERSION && id.authority == 0,
          "P1 pool_id_of == rb::lane_tag(LaneTagContext::of(chain, LaneParams, SHIPPED, 0), 0, 0, 0)");
        std::printf("    lane_tag(chain 0, LaneParams{}, v%u) = %s\n", id.version, hex(id.lane_tag).c_str());
        C(pool_id_of(kChain, kf).lane_tag != id.lane_tag && pool_id_of(kChain, hl).lane_tag != id.lane_tag &&
          pool_id_of(kChain, wd).lane_tag != id.lane_tag, "P1 the tag moves with k_floor, half_life and window");
        C(pool_id_of(7, base).lane_tag != id.lane_tag && pool_id_of(kChain, base, 2).lane_tag != id.lane_tag,
          "P1 the tag moves with chain_id and the consensus version");
        ::v37::LaneParams fee = base; fee.fee = ::v37::FeeModelGate::for_version(1);
        ::v37::LaneParams jd = base; jd.journal_depth = 99;
        C(pool_id_of(kChain, fee).lane_tag == id.lane_tag && pool_id_of(kChain, jd).lane_tag == id.lane_tag,
          "P1 non-geometry fields (fee gate, journal_depth) leave the tag alone (lane_params_digest still pins them)");
        Hello h; h.network = 3; h.chain_id = kChain; h.share_diff = kShareDiff; h.node_nonce = 1; h.listen_port = 53100;
        h.lane_params_digest = lane_params_digest(base, kShareDiff, BindMode::None, 3);
        const auto legacy = encode_hello(h);
        C(legacy.size() == kHelloBytes && kHelloBytes == 102, "P1 a tagless HELLO is still the 102-byte master frame");
        h.pool = id;
        const auto f = encode_hello(h);
        C(f.size() == kHelloBytesPoolId && kHelloBytesPoolId == 142 && kHelloPoolIdBytes == 40,
          "P1 the tagged HELLO is 142 B (+40: lane_tag 32 | version u32 | authority u32)");
        C(std::equal(legacy.begin(), legacy.end(), f.begin()), "P1 the first 102 bytes are the master HELLO, unchanged");
        Hello back; std::string why;
        C(decode_hello(f, back, &why) && back == h && back.pool && back.pool->lane_tag == id.lane_tag, "P1 tagged HELLO round trip");
        Hello lb;
        C(decode_hello(legacy, lb, &why) && !lb.pool, "P1 a 102-byte HELLO decodes with pool = none");
        auto t = f; t.pop_back(); C(!decode_hello(t, back, &why), "P1 141 bytes -> refused");
        t = f; t.push_back(0);     C(!decode_hello(t, back, &why), "P1 143 bytes -> refused");
        Hello o = h; o.node_nonce = 2;
        C(hello_mismatch(h, o).empty(), "P1 same pool, other nonce -> compatible");
        Hello m = o; m.pool = pool_id_of(kChain, kf);
        std::string r = hello_mismatch(h, m);
        std::printf("    geometry: %s\n", r.c_str());
        C(is_tag_mismatch(r) && r.find("field=geometry") != std::string::npos && r.find("ours=" + hex(id.lane_tag)) != std::string::npos &&
          r.find("theirs=" + hex(m.pool->lane_tag)) != std::string::npos, "P1 geometry mismatch: TAG_MISMATCH field=geometry, both tags");
        m = o; m.chain_id = 7; m.pool = pool_id_of(7, base);
        r = hello_mismatch(h, m);
        C(is_tag_mismatch(r) && r.find("field=chain_id") != std::string::npos, "P1 chain mismatch: TAG_MISMATCH field=chain_id");
        m = o; m.pool = pool_id_of(kChain, base, 2);
        r = hello_mismatch(h, m);
        C(is_tag_mismatch(r) && r.find("field=version") != std::string::npos, "P1 version mismatch: TAG_MISMATCH field=version");
        m = o; m.pool.reset();
        r = hello_mismatch(h, m);
        C(is_tag_mismatch(r) && r.find("field=lane_tag") != std::string::npos && r.find("pre-POOL-ID") != std::string::npos,
          "P1 a tagless (pre-POOL-ID) peer is refused by name");
        Hello h0 = h; h0.pool.reset(); Hello o0 = o; o0.pool.reset();
        C(hello_mismatch(h0, o0).empty() && is_tag_mismatch(hello_mismatch(h0, o)), "P1 tagless<->tagless compatible; tagless vs tagged refused");
        m = o; m.network = 2; m.pool = pool_id_of(kChain, kf);
        C(hello_mismatch(h, m).find("network") == 0, "P1 network is still checked first");
    }
#else
    C(false, "P1 the relay HELLO carries a POOL-ID lane_tag (absent in this build)");
#endif

    // ── P2..P4 live mismatches ──────────────────────────────────────────────
    Cfg same;
    {
        std::printf("-- P2 geometry mismatch (X: k_floor %llu, same chain_id %u)\n", (unsigned long long)kf.k_floor, kChain);
        Cfg other = same; other.lp = kf;
        mismatch_case(C, "P2", same, other, "geometry");
    }
    {
        std::printf("-- P2b geometry mismatch (X: half_life %llu)\n", (unsigned long long)hl.half_life);
        Cfg other = same; other.lp = hl;
        mismatch_case(C, "P2b", same, other, "geometry");
    }
#ifdef C2POOL_XMR_RELAY_UP_GATE
    {
        std::printf("-- P2c UP-GATE: X's up events held 150 ms (A's/B's HELLO reaches X's reader first)\n");
        Cfg other = same; other.lp = kf;
        mismatch_case(C, "P2c", same, other, "geometry", 0, 150);
    }
    {
        std::printf("-- P2d UP-GATE: A's up events held 150 ms (B's and X's HELLO reach A's reader first)\n");
        Cfg other = same; other.lp = kf;
        mismatch_case(C, "P2d", same, other, "geometry", 150, 0);
    }
#else
    C(false, "P2c/P2d the relay UP-GATE (a HELLO read before our up event waits for it) (absent in this build)");
#endif
    {
        std::printf("-- P3 consensus-version mismatch (X: version 2, identical LaneParams)\n");
        Cfg other = same; other.version = 2;
        mismatch_case(C, "P3", same, other, "version");
    }
    {
        std::printf("-- P4 chain_id mismatch (X: chain 7)\n");
        Cfg other = same; other.chain = 7;
        mismatch_case(C, "P4", same, other, "chain_id");
    }

    // ── P5 nothing crosses the mismatch; same pool converges ────────────────
    std::vector<bytes32> prev(4);
    for (int i = 0; i < 4; ++i) prev[i] = b32_of(static_cast<u8>(100 + i));
    const ::v37::ScriptRef pA = payee_of("A"), pB = payee_of("B"), pX = payee_of("X");
    bytes32 tagged_digest{};
    {
        std::printf("-- P5 receipts across a geometry mismatch (X: k_floor %llu)\n", (unsigned long long)kf.k_floor);
        Cfg other = same; other.lp = kf;
        TNode A("A", same, true, {});
        C(A.start(), "P5 A starts");
        TNode B("B", same, true, {A.relay->listen_port()});
        C(B.start(), "P5 B starts");
        TNode X("X", other, false, {A.relay->listen_port(), B.relay->listen_port()});
        C(X.start(), "P5 X starts");
        std::vector<TNode*> all{&A, &B, &X};
        C(wait_for([&] { return A.relay->ready_peers().size() == 1 && B.relay->ready_peers().size() == 1; }, all), "P5 A<->B up");
        for (auto* n : all) { for (int i = 0; i < 4; ++i) n->note_bin(prev[i], 100 + i); n->template_height = 100; }
        const SynthBlock bA = make_block(100, prev[0], 1, nullptr, 3, 10);
        const SynthBlock bB = make_block(100, prev[0], 2, nullptr, 3, 11);
        const SynthBlock bX = make_block(100, prev[0], 3, nullptr, 3, 12);
        for (std::uint32_t k = 0; k < 4; ++k) A.relay->submit_own(own(bA, 10 + k, pA, kChain));
        for (std::uint32_t k = 0; k < 3; ++k) B.relay->submit_own(own(bB, 20 + k, pB, kChain));
        for (std::uint32_t k = 0; k < 5; ++k) X.relay->submit_own(own(bX, 30 + k, pX, kChain));
        C(wait_for([&] { return A.relay->cache_size() == 7 && B.relay->cache_size() == 7; }, all), "P5 A and B exchange their 7 receipts");
        std::this_thread::sleep_for(2500ms);   // X keeps redialing meanwhile
        for (auto* n : all) n->pump();
        const u64 fa = A.relay->stats().admitted_foreign.load(), fb = B.relay->stats().admitted_foreign.load(),
                  fx = X.relay->stats().admitted_foreign.load();
        std::printf("    admitted_foreign: A=%llu B=%llu X=%llu | cache A=%zu B=%zu X=%zu\n", (unsigned long long)fa,
                    (unsigned long long)fb, (unsigned long long)fx, A.relay->cache_size(), B.relay->cache_size(), X.relay->cache_size());
        C(fa == 3 && fb == 4, "P5 A admitted exactly B's 3, B exactly A's 4 -- none of X's 5");
        C(fx == 0 && X.relay->cache_size() == 5, "P5 X admitted 0 receipts from A/B (its cache is its own 5)");
        bool none_known = true;
        for (std::uint32_t k = 0; k < 5; ++k) {
            const bytes32 id = own(bX, 30 + k, pX, kChain).id;
            if (A.relay->known(id) || B.relay->known(id)) none_known = false;
        }
        C(none_known, "P5 none of X's 5 receipt ids is known at A or B");
        for (auto* n : all) n->template_height = 101;
        C(wait_for([&] { return A.next_pos() == 7 && B.next_pos() == 7; }, all), "P5 bin 100 closed on A and B (7 pushes)");
        C(A.digest() == B.digest(), "P5 A and B: byte-identical lane digests (" + hex(A.digest()).substr(0, 16) + ")");
        C(X.next_pos() == 5, "P5 X's lane holds only its own 5");
        tagged_digest = A.digest();

        // a raw other-pool peer that ignores the refusal and bursts frames
        const u64 fr0 = A.relay->stats().admitted_foreign.load(), won0 = A.relay->stats().block_won_rx.load(),
                  srv0 = A.relay->stats().ctx_served.load() + A.relay->stats().ctx_unknown_tx.load();
        CarrierPeerNode evil;
        std::atomic<bool> dropped{false};
        evil.set_on_peer_event([&](PeerId, bool up) { if (!up) dropped = true; });
        const PeerId pid = evil.add_peer_id("127.0.0.1", A.relay->listen_port());
        C(pid != 0, "P5 raw other-pool peer E connects to A");
        Hello h = A.relay->our_hello(); h.node_nonce ^= 0x5a5a; h.lane_next_pos = 0;
        h.lane_params_digest = lane_params_digest(kf, kShareDiff, BindMode::None, 3);
#ifdef C2POOL_XMR_RELAY_POOL_ID
        h.pool = pool_id_of(kChain, kf);
#endif
        const SynthBlock bE = make_block(101, prev[1], 4, nullptr, 1, 13);
        Admitted e = own(bE, 40, pX, kChain);
        const auto rawe = encode_fb_receipt(e.r);
        BlockWon bw; bw.chain_id = kChain; bw.bid = b32_of(77); bw.h_b = 101;
        evil.send_to(pid, encode_hello(h));
        evil.send_to(pid, encode_receipts_frame(kChain, {&rawe}));
        evil.send_to(pid, encode_block_won(bw));
        evil.send_to(pid, encode_getctx(kChain, {prev[0]}));
        C(wait_for([&] { return dropped.load(); }, all, 5000ms), "P5 A drops E after its HELLO");
        std::this_thread::sleep_for(300ms);
        for (auto* n : all) n->pump();
        C(A.relay->stats().admitted_foreign.load() == fr0 && !A.relay->known(e.id),
          "P5 E's receipt was never admitted (0 receipts)");
        C(A.relay->stats().block_won_rx.load() == won0 && A.relay->drain_block_won().empty(), "P5 E's BLOCK_WON was never admitted (0 lane blocks)");
        C(A.relay->stats().ctx_served.load() + A.relay->stats().ctx_unknown_tx.load() == srv0, "P5 E's GETCTX was never served (0 contexts)");
        evil.stop();
        X.relay->set_dialing(false);
    }

    // ── P6 same pool: tagged == tagless (master wire) ───────────────────────
    {
        std::printf("-- P6 the same receipts through a TAGLESS (master-wire) A/B pair\n");
        Cfg tl = same; tl.tagged = false;
        TNode A("A0", tl, true, {});
        C(A.start(), "P6 A0 starts");
        TNode B("B0", tl, true, {A.relay->listen_port()});
        C(B.start(), "P6 B0 starts");
        std::vector<TNode*> all{&A, &B};
        C(wait_for([&] { return A.relay->ready_peers().size() == 1 && B.relay->ready_peers().size() == 1; }, all), "P6 A0<->B0 up");
        for (auto* n : all) { for (int i = 0; i < 4; ++i) n->note_bin(prev[i], 100 + i); n->template_height = 100; }
        const SynthBlock bA = make_block(100, prev[0], 1, nullptr, 3, 10);
        const SynthBlock bB = make_block(100, prev[0], 2, nullptr, 3, 11);
        for (std::uint32_t k = 0; k < 4; ++k) A.relay->submit_own(own(bA, 10 + k, pA, kChain));
        for (std::uint32_t k = 0; k < 3; ++k) B.relay->submit_own(own(bB, 20 + k, pB, kChain));
        C(wait_for([&] { return A.relay->cache_size() == 7 && B.relay->cache_size() == 7; }, all), "P6 A0 and B0 exchange 7 receipts");
        for (auto* n : all) n->template_height = 101;
        C(wait_for([&] { return A.next_pos() == 7 && B.next_pos() == 7; }, all), "P6 bin 100 closed (7 pushes)");
        C(A.digest() == B.digest() && A.digest() == tagged_digest,
          "P6 tagless digest == tagged digest (" + hex(A.digest()).substr(0, 16) + "): the tag changes no lane byte");
    }

    // ── P7 FLAG DAY (#1803 review): a pre-#1803 node is refused AT HELLO ─────
    {
        std::printf("-- P7 FLAG DAY: this build's node_pool_id vs a pre-#1803 node (pool id at SHIPPED_CONSENSUS_VERSION)\n");
#ifdef C2POOL_XMR_POOL_RULES_VERSION
        const u32 ours_v = kXmrPoolRulesVersion;
        C(node_pool_id(kChain, base) == pool_id_of(kChain, base, ours_v) && ours_v > ::v37::SHIPPED_CONSENSUS_VERSION,
          "P7 the node's HELLO pool id (node_pool_id, what main_v37_xmr sends) folds kXmrPoolRulesVersion=" + std::to_string(ours_v) +
          " > SHIPPED_CONSENSUS_VERSION=" + std::to_string(::v37::SHIPPED_CONSENSUS_VERSION));
#else
        const u32 ours_v = ::v37::SHIPPED_CONSENSUS_VERSION;   // the base main: pool_id_of(chain, params)
        C(false, "P7 the node's HELLO pool id folds an XMR pool-rules version above SHIPPED_CONSENSUS_VERSION (absent in this build)");
#endif
        const bytes32 g = b32_of(0x5A);
        Hello now_h; now_h.network = 3; now_h.chain_id = kChain; now_h.share_diff = kShareDiff; now_h.node_nonce = 71;
        now_h.pool = pool_id_of(kChain, base, ours_v); now_h.pool->genesis = g;
        Hello pre_h = now_h; pre_h.node_nonce = 72; pre_h.pool = pool_id_of(kChain, base); pre_h.pool->genesis = g;
        Hello now2 = now_h; now2.node_nonce = 73;
        const std::string r = hello_mismatch(now_h, pre_h), r2 = hello_mismatch(pre_h, now_h);
        std::printf("    ours v%u vs pre-#1803 v%u: \"%s\"\n", ours_v, ::v37::SHIPPED_CONSENSUS_VERSION, r.c_str());
        C(is_tag_mismatch(r) && r.find("field=version") != std::string::npos && is_tag_mismatch(r2),
          "P7 a pre-#1803 HELLO is refused at HELLO, both directions, as TAG_MISMATCH field=version");
        C(hello_mismatch(now_h, now2).empty(), "P7 two nodes of this build stay compatible");
        Cfg now_c; now_c.version = ours_v;
        Cfg pre_c;   // version = SHIPPED_CONSENSUS_VERSION: the RC4 5db1f675 HELLO
        mismatch_case(C, "P7", now_c, pre_c, "version");
    }
    return C.done("v37_xmr_relay_pool_id_kat");
}
