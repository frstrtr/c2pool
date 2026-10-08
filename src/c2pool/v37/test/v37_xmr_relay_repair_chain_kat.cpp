// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ===========================================================================
// v37_xmr_relay_repair_chain_kat -- REPAIR-CHAIN (stagenet capstone attempt 4)
//
// Attempt 4 kept three daemonless XMR nodes' ledgers identical but lost
// liveness: three times a node could not rebuild another node's credit cut
// and the block HELD ("DEEP-DIVERGENCE: our lane order differs from the
// winner's BELOW the vault horizon of N peer(s) -- no connected peer retains
// the divergent positions"). Two holds followed a RESTART (the repair shadows
// were in memory only), one a CHAIN GAP longer than the vault horizon (no
// shadow of the winner's lineage ever covered the peer's horizon).
//
// Harness = the repair-horizon KAT's TNode (real XmrRelayNode + FrameVault +
// SupplyService over loopback TCP, the real canonical XmrReceiptIngest with a
// DURABLE receipts log, a real V37Engine lane, the daemon's RepairReplayer;
// fake RandomX only), with THREE nodes, a restart helper (destroy + rebuild
// on the same durable files, the boot reload) and the relay stall
// (partition_for). Scenario: a common prefix, two stalls -> three lane
// lineages (A, B, C), then winners rotating A, B, C with every non-winner
// repairing the winner's cut (P, spine) exactly like main_v37_xmr relay_view;
// a stall of C and a restart of C (the shadow holder) in the middle; the lanes
// grow to many vault horizons.
//
//   R1 CHAIN   every cross-side cut is BOOKED (Ready + replay reproduces the
//              winner's spine), 0 HELD. Base: holds with DEEP-DIVERGENCE.
//   R2 RESTART the restarted node's shadows before == after (F1). Base: 0.
//   R3 DEEP    repairs whose divergence is below every peer's vault horizon
//              are served from the durable order (deep pages > 0) and no repair
//              ends DEEP-exhausted (F2). Base: DEEP-exhausted > 0.
//   R4 COMPAT  the fix build with --relay-deep-order off + no persist = the
//              RC5 behaviour (the same holds as the base).
//   R5 LOUD    a peer whose lineage cannot reach the spine still ends DEEP
//              (walk failed -> named, never a silent fold) -- counted.
//   R6 TORN    a corrupt shadow file loads as zero shadows (RC5), loudly.
//
// Scale knobs (env; the defaults are the KAT): RC_HORIZON (8), RC_STEP (2),
// RC_PER_ROUND (4), RC_ROUNDS (12), RC_STALL_ROUND (4), RC_RESTART_ROUND (7),
// RC_CUT_LIMIT_MS (20000), RC_PORT_BASE (0 = ephemeral ports), RC_DIR (node
// dirs; default TMPDIR), RC_KEEP (keep them), RC_ONLY=fix|off (one mode),
// RC_PARTS=both|deep|persist (F1+F2 / F2 only / F1 only), RC_SKIP_R2B,
// RC_VERBOSE. The live measurement runs this binary at a larger scale (see
// the REPAIR-CHAIN report). RED on the base, GREEN on the fix.
// ===========================================================================
#include <sys/resource.h>

#include <atomic>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <thread>

#include "xmr_relay_test_util.hpp"
#include <c2pool/v37/xmr/relay/xmr_relay_node.hpp>
#include <c2pool/v37/xmr/relay/xmr_receipt_ingest.hpp>
#include <c2pool/v37/xmr/relay/xmr_repair_replay.hpp>
#include <c2pool/v37/v37_engine.hpp>

using namespace gap2test;
using namespace std::chrono_literals;

static constexpr u32 kChain = 7;
static constexpr u64 kShareDiff = 1000;

static u64 env_u64(const char* k, u64 d) { const char* v = std::getenv(k); return v && *v ? std::strtoull(v, nullptr, 10) : d; }
static long rss_kb() { rusage u{}; getrusage(RUSAGE_SELF, &u); return u.ru_maxrss; }

// Feature detection, so this KAT BUILDS on the base and fails there by value.
template <class O> static bool set_deep(O& o, bool on, const std::string& base, u64 step) {
    if constexpr (requires { o.deep_order; o.deep_order_path; o.receipts_log_path; o.deep_probe_step; }) {
        o.deep_order = on;
        o.deep_order_path = on ? base : std::string();
        o.receipts_log_path = on ? base + ".receipts" : std::string();
        o.deep_probe_step = step;
        return true;
    } else { (void)o; (void)on; (void)base; (void)step; return false; }
}
template <class R> static std::size_t shadow_setup(R& r, bool on, const std::string& path, const bytes32& tag, u64 step) {
    if constexpr (requires { r.enable_persist(path, kChain, tag); r.load(); r.set_checkpoint_step(step); }) {
        if (!on) return 0;
        r.set_checkpoint_step(step);
        r.enable_persist(path, kChain, tag);
        return r.load();
    } else { (void)r; (void)on; (void)path; (void)tag; (void)step; return 0; }
}
template <class R> static void set_step(R& r, u64 g) {
    if constexpr (requires { r.set_checkpoint_step(g); }) r.set_checkpoint_step(g); else { (void)r; (void)g; }
}
template <class R> static std::string shadow_load_error(const R& r) {
    if constexpr (requires { r.persist_stats().last_error; }) return r.persist_stats().last_error; else { (void)r; return "(base: no persistence)"; }
}
template <class R> static u64 shadow_file_bytes(const R& r) {
    if constexpr (requires { r.persist_stats().bytes; }) return r.persist_stats().bytes; else { (void)r; return 0; }
}
template <class N> static std::optional<bytes32> digest_deep(N& n, u64 pos) {
    if constexpr (requires { n.digest_at_deep(pos); }) return n.digest_at_deep(pos); else return n.digest_at(pos);
}
struct Served { u64 pages = 0, ids = 0, bytes = 0, frames = 0, frame_bytes = 0, disk = 0; };
template <class N> static Served served_of(N& n) {
    Served s;
    if constexpr (requires { n.durable_order_stats(); n.durable_order_bytes(); }) {
        const auto d = n.durable_order_stats();
        s.pages = d.pages; s.ids = d.ids; s.bytes = d.bytes; s.frames = d.frames; s.frame_bytes = d.frame_bytes;
        s.disk = n.durable_order_bytes();
    } else { (void)n; }
    return s;
}
struct Walk { u64 probe = 0, equal = 0, full = 0, ready = 0, rc5 = 0, lineage = 0; };
template <class S> static Walk walk_of(const S& s) {
    Walk w;
    if constexpr (requires { s.repair_deep_probe; s.repair_deep_equal; s.repair_deep_full; s.repair_deep_ready; s.repair_deep_rc5; s.repair_deep_lineage; }) {
        w.probe = s.repair_deep_probe.load(); w.equal = s.repair_deep_equal.load(); w.full = s.repair_deep_full.load();
        w.ready = s.repair_deep_ready.load(); w.rc5 = s.repair_deep_rc5.load(); w.lineage = s.repair_deep_lineage.load();
    } else { (void)s; }
    return w;
}

template <class R> static std::vector<std::pair<u64, bytes32>> shadow_ends_of(const R& r) {
    if constexpr (requires { r.shadow_ends(); }) return r.shadow_ends();
    else { std::vector<std::pair<u64, bytes32>> v(r.shadows()); return v; }
}
template <class O> static constexpr bool kHasDeep = requires(O o) { o.deep_order; };

struct Mode { bool fix = true; u64 H = 8, G = 2; bool deep = true, persist = true; };   // deep = F2, persist = F1

// One daemonless node: its settle db dir holds lane7.receipts (the durable
// log), lane7.order/.digest (REPAIR-CHAIN F2) and lane7.shadow (F1). A restart
// = destroy + construct on the same dir: the boot reload rebuilds the lane,
// feed, digests and sidecars; the shadows are loaded before the relay starts.
struct TNode {
    std::string name, dir;
    Mode mode;
    ChainView chain;
    std::unique_ptr<c2pool::v37n::V37Engine> engine;
    std::unique_ptr<XmrRelayNode> relay;
    std::unique_ptr<XmrReceiptIngest> ingest;
    std::unique_ptr<RepairReplayer> rep;
    std::map<u64, bytes32> dig_at;
    std::vector<std::pair<::v37::ScriptRef, u64>> feed;
    u64 template_height = 0;
    std::size_t reloaded = 0, shadows_loaded = 0;

    TNode(std::string n, std::string d, Mode m, RelayOptions ro, const std::vector<std::pair<bytes32, u64>>& bins, u64 tip = 0)
        : name(std::move(n)), dir(std::move(d)), mode(m) {
        std::filesystem::create_directories(dir);
        const std::string base = dir + "/lane" + std::to_string(kChain);
        set_deep(ro, m.fix && m.deep, base, m.G);
        for (const auto& [prev, h] : bins) chain.note(prev, h, bytes32{});
        chain.set_tip(tip ? tip : bins.front().second);
        rep = std::make_unique<RepairReplayer>(2 * m.H);
        engine = std::make_unique<c2pool::v37n::V37Engine>(4096);
        engine->start();
        engine->submit_tracked(::v37::LaneRecord::add_lane(kChain, ::v37::LaneParams{})).get();
        relay = std::make_unique<XmrRelayNode>(
            ro, chain,
            [](const std::vector<u8>&, const bytes32&, bytes32& pow) { pow.fill(0); return true; },
            [this]() -> std::pair<u64, bytes32> {
                auto s = engine->snapshot(kChain);
                if (!s) return {0, bytes32{}};
                return {s->next_pos, s->digest};
            },
            [this](const std::string& l) { if (std::getenv("RC_VERBOSE")) std::printf("   [%s] %s\n", name.c_str(), l.c_str()); });
        XmrReceiptIngest::Options io; io.chain = kChain; io.order = XmrReceiptIngest::Order::Canonical; io.bin_lag = 1; io.grace_ms = 0;
        io.durable_path = base + ".receipts";
        ingest = std::make_unique<XmrReceiptIngest>(
            io,
            [this](const ::v37::ScriptRef& payee, u64 w, u64& next_after, bytes32& dg) {
                ::v37::PayoutDescriptor pd; pd.pay = payee;
                if (!engine->submit_tracked(::v37::LaneRecord::push(kChain, pd, w, 0)).get().applied()) return false;
                feed.emplace_back(payee, w);
                auto s = engine->snapshot(kChain);
                next_after = s->next_pos; dg = s->digest; dig_at[next_after] = dg;
                return true;
            },
            [this](const Admitted& a, u64 pos, u32 n_pushes, u64 next_after, const bytes32& dg) {
                relay->on_pushed(a.id, pos, n_pushes, a.raw, next_after, dg);
            });
        reloaded = ingest->reload([this](const Admitted& a) { relay->note_reloaded(a); });
        shadows_loaded = shadow_setup(*rep, m.fix && m.persist, base + ".shadow", ro.lane_params_digest, m.G);
        if (m.fix && m.deep && !m.persist) {   // F2 only: the walk still needs the shadows' checkpoints
            set_step(*rep, m.G);
        }
        if (shadows_loaded) relay->note_alt_digests(rep->shadow_digests());
    }
    ~TNode() { relay->stop(); engine->stop(); }
    void pump() { for (auto& a : relay->drain_admitted()) ingest->on_admitted(std::move(a)); ingest->tick(template_height); }
    u64 next_pos() { auto s = engine->snapshot(kChain); return s ? s->next_pos : 0; }
};

static RelayOptions opts(u16 listen_port, bool listen, std::vector<u16> dial, u64 horizon) {
    RelayOptions o;
    o.network = 3; o.chain = kChain; o.share_diff = kShareDiff; o.bind = BindMode::None;
    o.lane_params_digest = lane_params_digest(::v37::LaneParams{}, kShareDiff, BindMode::None);
    o.listen = listen; o.listen_host = "127.0.0.1"; o.listen_port = listen_port;
    for (u16 p : dial) o.peers.emplace_back("127.0.0.1", p);
    o.reoffer_seconds = 60;
    o.hello_timeout_ms = 3000;
    o.vault.horizon_positions = horizon;
    o.cache_max = 1u << 20;
    o.dos.per_peer_capacity = 1e6; o.dos.per_peer_refill = 1e6; o.dos.global_capacity = 1e6; o.dos.global_refill = 1e6;
    return o;
}
template <class F>
static bool wait_for(F cond, const std::vector<TNode*>& pump, std::chrono::milliseconds limit = 15000ms) {
    const auto dl = std::chrono::steady_clock::now() + limit;
    while (std::chrono::steady_clock::now() < dl) {
        for (auto* n : pump) n->pump();
        if (cond()) return true;
        std::this_thread::sleep_for(5ms);
    }
    for (auto* n : pump) n->pump();
    return cond();
}
static Admitted own(const SynthBlock& sb, std::uint32_t nonce, const ::v37::ScriptRef& payee) {
    Admitted a; std::string why;
    if (!mint_on(sb, nonce, payee, kChain, kShareDiff, a.r, &why)) std::printf("    mint failed: %s\n", why.c_str());
    a.id = receipt_id(a.r); a.raw = encode_fb_receipt(a.r); a.bin = sb.height; a.own = true;
    return a;
}

// A non-winner books the winner's cut exactly like main_v37_xmr relay_view:
// own replay when our digest at P is the spine; else repair_poll until Ready,
// replay (own / shadow prefix + served suffix) through the RepairReplayer, and
// repair_reject + retry when the replay misses the spine. HELD = not booked
// within `limit`, or Exhausted with DEEP-DIVERGENCE (terminal until the peer
// set changes -- the capstone status).
struct CutResult { bool own = false, booked = false, deep = false; int base = 0; u64 a0 = 0; std::string status; };
static CutResult settle_cut(TNode& N, const std::vector<TNode*>& all, u64 P, const bytes32& spine, std::chrono::milliseconds limit) {
    CutResult r;
    if (const auto d = N.relay->digest_at(P); d && *d == spine) { r.own = r.booked = true; return r; }
    const auto dl = std::chrono::steady_clock::now() + limit;
    while (std::chrono::steady_clock::now() < dl) {
        for (auto* n : all) n->pump();
        std::vector<bytes32> ids;
        const auto st = N.relay->repair_poll(P, spine, 0, &ids);
        if (st == XmrRelayNode::RepairState::Exhausted) {
            u64 da = 0;
            if (N.relay->repair_deep_divergence(P, spine, &da)) { r.deep = true; r.a0 = da; break; }
        }
        if (st != XmrRelayNode::RepairState::Ready) { std::this_thread::sleep_for(5ms); continue; }
        std::optional<bytes32> peer_a0;
        const u64 a0 = N.relay->repair_a0(P, spine, &peer_a0);
        std::vector<std::pair<::v37::ScriptRef, u64>> served;
        bool miss = false;
        for (const auto& id : ids) {
            ::v37::ScriptRef ref;
            if (!N.relay->cached(id, &ref)) { miss = true; break; }
            served.emplace_back(ref, kReceiptWeight);
        }
        if (miss || a0 > N.feed.size()) { std::this_thread::sleep_for(5ms); continue; }
        RepairReplayer::Base used = RepairReplayer::kNone;
        auto view = N.rep->replay(kChain, ::v37::LaneParams{}, P, spine, a0, N.feed, served, &used, peer_a0,
                                  a0 ? digest_deep(*N.relay, a0) : std::nullopt);
        if (view) {
            N.relay->note_alt_digests(N.rep->shadow_digests());
            r.booked = true; r.a0 = a0; r.base = static_cast<int>(used);
            return r;
        }
        N.relay->repair_reject(P, spine);
    }
    r.status = N.relay->repair_status(P, spine);
    return r;
}

struct Metrics {
    u64 cuts = 0, cross = 0, own = 0, booked = 0, held = 0, deep_held = 0, via_shadow = 0, via_full = 0, via_own = 0;
    std::size_t sh_before = 0, sh_after = 0; bool sh_same = false;
    Served served; Walk walk; long rss0 = 0, rss1 = 0; u64 shadow_bytes = 0, lane = 0; double secs = 0;
    std::string first_hold;
    bool setup_ok = true;
};

struct Scn {
    u64 per_round = 4, rounds = 12, stall_round = 4, restart_round = 7;
    u16 port_base = 0;
    std::chrono::milliseconds cut_limit{20000};
};

static Metrics run_scenario(Mode m, const Scn& S, Checker& CK, const std::string& tag) {
    Metrics M;
    const auto t0 = std::chrono::steady_clock::now();
    M.rss0 = rss_kb();
    const char* rd = std::getenv("RC_DIR");
    const std::string dir = (rd && *rd ? std::string(rd) : std::filesystem::temp_directory_path().string()) +
                            "/rc-kat-" + std::to_string(::getpid()) + "-" + tag;
    std::filesystem::remove_all(dir);
    std::vector<std::pair<bytes32, u64>> bins;
    for (u64 h = 100; h < 110 + S.rounds; ++h) bins.emplace_back(b32_of(static_cast<u8>(7 + h)), h);
    std::string why;
    const u16 pA = S.port_base ? S.port_base : 0, pB = S.port_base ? static_cast<u16>(S.port_base + 1) : 0;
    auto A = std::make_unique<TNode>("A", dir + "/A", m, opts(pA, true, {}, m.H), bins);
    CK(A->relay->start(why), tag + " A starts " + why);
    const u16 portA = A->relay->listen_port();
    auto B = std::make_unique<TNode>("B", dir + "/B", m, opts(pB, true, {portA}, m.H), bins);
    CK(B->relay->start(why), tag + " B starts " + why);
    const u16 portB = B->relay->listen_port();
    const RelayOptions oC = opts(0, false, {portA, portB}, m.H);
    auto Cn = std::make_unique<TNode>("C", dir + "/C", m, oC, bins);
    CK(Cn->relay->start(why), tag + " C starts " + why);
    std::vector<TNode*> all{A.get(), B.get(), Cn.get()};
    auto up3 = [&] { return A->relay->ready_peers().size() == 2 && B->relay->ready_peers().size() == 2 && Cn->relay->ready_peers().size() == 2; };
    M.setup_ok &= wait_for(up3, all);
    CK(M.setup_ok, tag + " A-B-C mesh up (C dials A and B, B dials A)");
    const ::v37::ScriptRef pay[3] = {payee_of("A"), payee_of("B"), payee_of("C")};
    auto tmpl = [&](u64 h) { for (auto* n : all) { n->template_height = h; n->chain.set_tip(h); } };
    auto same_pos = [&](u64 want) { return wait_for([&] { for (auto* n : all) if (n->next_pos() != want) return false; return true; }, all, 25000ms); };
    tmpl(100);
    // common prefix: bin 100, 4 receipts of A
    const SynthBlock b100 = make_block(100, bins[0].first, 11, nullptr, 2, 14);
    for (u32 k = 0; k < 4; ++k) A->relay->submit_own(own(b100, 1000 + k, pay[0]));
    M.setup_ok &= wait_for([&] { for (auto* n : all) if (n->relay->cache_size() < 4) return false; return true; }, all);
    tmpl(101);
    M.setup_ok &= same_pos(4);
    // two stalls -> three lineages
    for (int st = 0; st < 2; ++st) {
        TNode& X = st == 0 ? *Cn : *B;          // the stalled node
        const u64 h = 101 + st, base_pos = st ? 9 : 4;
        X.relay->partition_for(std::chrono::seconds(3));
        M.setup_ok &= wait_for([&] { return X.relay->ready_peers().empty(); }, all, 8000ms);
        const SynthBlock ba = make_block(h, bins[h - 100].first, 20 + st, nullptr, 2, static_cast<u8>(30 + st));
        const SynthBlock bx = make_block(h, bins[h - 100].first, 40 + st, nullptr, 2, static_cast<u8>(50 + st));
        const u32 na = st ? 2 : 3, nx = 2;
        for (u32 k = 0; k < na; ++k) A->relay->submit_own(own(ba, 2000 + 100 * st + k, pay[0]));
        for (u32 k = 0; k < nx; ++k) X.relay->submit_own(own(bx, 3000 + 100 * st + k, pay[st ? 1 : 2]));
        tmpl(h + 1);
        M.setup_ok &= wait_for([&] { return A->next_pos() == base_pos + na && X.next_pos() == base_pos + nx; }, all, 8000ms);
        M.setup_ok &= same_pos(base_pos + na + nx);   // heal: the late tails arrive, each side appends the other's
    }
    CK(M.setup_ok, tag + " three lineages: A=[p,A3,C2,A2,B2] B=[p,A3,C2,B2,A2] C=[p,C2,A3,A2,B2] (lane 13)");
    if (!M.setup_ok) return M;
    // ── rotation: winner A, B, C, A, ...; every non-winner books the winner's cut
    u64 lane = 13;
    for (u64 k = 0; k < S.rounds; ++k) {
        TNode& W = *all[k % 3];
        const u64 h = 103 + k;
        const bool stall = (k == S.stall_round && &W != Cn.get());
        const SynthBlock bw = make_block(h, bins[h - 100].first, static_cast<u32>(100 + k), nullptr, 2, static_cast<u8>(60 + k % 150));
        if (stall) {   // the capstone's relay stall: C closes this bin alone, with a receipt of its own
            Cn->relay->partition_for(std::chrono::seconds(3));
            wait_for([&] { return Cn->relay->ready_peers().empty(); }, all, 8000ms);
            const SynthBlock bc = make_block(h, bins[h - 100].first, static_cast<u32>(900 + k), nullptr, 2, static_cast<u8>(200 + k % 50));
            Cn->relay->submit_own(own(bc, static_cast<u32>(9000 + k), pay[2]));
        }
        for (u64 i = 0; i < S.per_round; ++i) W.relay->submit_own(own(bw, static_cast<u32>(100000 + 10000 * k + i), pay[k % 3]));
        const std::size_t want_cache = W.relay->cache_size();
        wait_for([&] { for (auto* n : all) if (!(stall && n == Cn.get()) && n->relay->cache_size() < want_cache) return false; return true; }, all);
        tmpl(h + 1);
        const u64 want = lane + S.per_round;
        wait_for([&] { return W.next_pos() == want; }, all, 25000ms);
        const u64 P = W.next_pos();
        const bytes32 spine = W.dig_at[P];   // the winner's on-chain cut (P, spine)
        lane = want + (stall ? 1 : 0);
        M.setup_ok &= same_pos(lane);        // everyone has every receipt (a stall heals by late tails)
        for (auto* N : all) {
            if (N == &W) continue;
            ++M.cuts;
            const CutResult r = settle_cut(*N, all, P, spine, S.cut_limit);
            if (r.own) { ++M.own; ++M.booked; continue; }
            ++M.cross;
            if (r.booked) {
                ++M.booked;
                if (r.base == RepairReplayer::kShadow) ++M.via_shadow; else if (r.base == RepairReplayer::kFull) ++M.via_full; else ++M.via_own;
            } else {
                ++M.held; if (r.deep) ++M.deep_held;
                if (M.first_hold.empty())
                    M.first_hold = N->name + " on " + W.name + "'s cut P=" + std::to_string(P) + (r.deep ? " DEEP a0=" + std::to_string(r.a0) : "") +
                                   " [" + N->relay->repair_status(P, spine) + "]";
            }
            if (std::getenv("RC_VERBOSE") || !r.booked)
                std::printf("   %s round %llu: %s repairs %s's cut P=%llu -> %s%s a0=%llu\n", tag.c_str(), (unsigned long long)k, N->name.c_str(),
                            W.name.c_str(), (unsigned long long)P, r.booked ? "BOOKED" : "HELD", r.deep ? " (DEEP-DIVERGENCE)" : "",
                            (unsigned long long)r.a0);
        }
        if (k == S.restart_round) {   // restart the shadow holder (C) on its own durable files
            const auto before = shadow_ends_of(*Cn->rep);
            M.sh_before = before.size();
            Cn.reset();
            Cn = std::make_unique<TNode>("C", dir + "/C", m, oC, bins, h + 1);
            Cn->template_height = h + 1;
            CK(Cn->relay->start(why), tag + " C restarts " + why);
            all[2] = Cn.get();
            M.setup_ok &= wait_for(up3, all);
            M.sh_after = Cn->rep->shadows();
            M.sh_same = shadow_ends_of(*Cn->rep) == before;
            std::printf("   %s restart of C after round %llu: reloaded=%zu receipts, shadows before=%zu after=%zu%s\n", tag.c_str(),
                        (unsigned long long)k, Cn->reloaded, M.sh_before, M.sh_after, M.sh_same ? " (identical)" : "");
        }
    }
    M.lane = lane;
    for (auto* n : all) {
        const Served s = served_of(*n->relay);
        M.served.pages += s.pages; M.served.ids += s.ids; M.served.bytes += s.bytes; M.served.frames += s.frames;
        M.served.frame_bytes += s.frame_bytes; M.served.disk += s.disk;
        const Walk w = walk_of(n->relay->stats());
        M.walk.probe += w.probe; M.walk.equal += w.equal; M.walk.full += w.full; M.walk.ready += w.ready; M.walk.rc5 += w.rc5; M.walk.lineage += w.lineage;
        M.shadow_bytes += shadow_file_bytes(*n->rep);
    }
    M.rss1 = rss_kb();
    M.secs = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
    return M;
}

// R2b / R6: the H2 shape on two nodes (a repair RC5 completes from its OWN
// prefix, so the base holds a shadow too), then a restart of the repairing
// node: shadows before vs after; then the shadow file is corrupted and a fresh
// replayer loads zero shadows, loudly (R6). Returns {before, after}.
static std::pair<std::size_t, std::size_t> restart_case(Mode m, Checker& CK, const std::string& tag, std::string* torn_err) {
    const char* rd = std::getenv("RC_DIR");
    const std::string dir = (rd && *rd ? std::string(rd) : std::filesystem::temp_directory_path().string()) +
                            "/rc-kat-" + std::to_string(::getpid()) + "-" + tag;
    std::filesystem::remove_all(dir);
    std::vector<std::pair<bytes32, u64>> bins;
    for (u64 h = 100; h < 110; ++h) bins.emplace_back(b32_of(static_cast<u8>(170 + h)), h);
    std::string why;
    auto X = std::make_unique<TNode>("X", dir + "/X", m, opts(0, true, {}, m.H), bins);
    CK(X->relay->start(why), tag + " X starts " + why);
    const RelayOptions oY = opts(0, false, {X->relay->listen_port()}, m.H);
    auto Y = std::make_unique<TNode>("Y", dir + "/Y", m, oY, bins);
    CK(Y->relay->start(why), tag + " Y starts " + why);
    std::vector<TNode*> xy{X.get(), Y.get()};
    CK(wait_for([&] { return X->relay->ready_peers().size() == 1 && Y->relay->ready_peers().size() == 1; }, xy), tag + " X-Y up");
    auto tmpl = [&](u64 h) { for (auto* n : xy) { n->template_height = h; n->chain.set_tip(h); } };
    tmpl(100);
    const SynthBlock b100 = make_block(100, bins[0].first, 71, nullptr, 2, 14);
    for (u32 k = 0; k < 12; ++k) X->relay->submit_own(own(b100, 1000 + k, payee_of("X")));
    wait_for([&] { return Y->relay->cache_size() == 12; }, xy);
    tmpl(101);
    wait_for([&] { return X->next_pos() == 12 && Y->next_pos() == 12; }, xy);
    Y->relay->partition_for(std::chrono::seconds(3));
    wait_for([&] { return Y->relay->ready_peers().empty(); }, xy, 8000ms);
    const SynthBlock bx = make_block(101, bins[1].first, 72, nullptr, 2, 15), by = make_block(101, bins[1].first, 73, nullptr, 2, 16);
    for (u32 k = 0; k < 3; ++k) X->relay->submit_own(own(bx, 2000 + k, payee_of("X")));
    for (u32 k = 0; k < 2; ++k) Y->relay->submit_own(own(by, 3000 + k, payee_of("Y")));
    tmpl(102);
    wait_for([&] { return X->next_pos() == 15 && Y->next_pos() == 14; }, xy);
    const u64 P = 15;
    const bytes32 spine = X->dig_at[P];
    CK(wait_for([&] { return X->next_pos() == 17 && Y->next_pos() == 17; }, xy, 20000ms), tag + " heal (lane 17 > horizon 8, divergence at 12)");
    const CutResult r = settle_cut(*Y, xy, P, spine, 15000ms);
    CK(r.booked, tag + " Y books X's cut P=15 from its OWN prefix [0," + std::to_string(r.a0) + ") (RC5 path): one shadow");
    {   // R7 FRAMES: an order page + the frame of a receipt BELOW X's vault horizon, from X's durable files
        const auto vo = X->relay->vault().serve_order(kChain, 1, 17, 4096);
        bool frame_ok = false;
        if (vo.status == c2pool::v37n::VaultOrderStatus::OK && !vo.ids.empty() && vo.ids.front().pos == 1) {
            std::vector<std::pair<bytes32, std::vector<u8>>> out;
            (void)X->relay->vault().serve_frames_chunk({vo.ids.front().id}, 64, 1u << 20, out);
            FbReceipt fr;
            frame_ok = out.size() == 1 && decode_fb_receipt(out[0].second, fr) && receipt_id(fr) == vo.ids.front().id;
        }
        std::printf("   R7 X vault lowest_retained=%llu: serve_order[1,17) status=%d ids=%zu, frame below the horizon %s\n",
                    (unsigned long long)X->relay->vault().lowest_position(), static_cast<int>(vo.status), vo.ids.size(),
                    frame_ok ? "served from the receipts log (id verified)" : "NOT servable");
        CK(vo.status == c2pool::v37n::VaultOrderStatus::OK && vo.ids.size() == 16 && frame_ok,
           tag + " R7 FRAMES below the vault horizon: [1,17) served from the durable order (16 ids) and the frame of position 1 "
                 "read back from the receipts log, id verified (base: BELOW_HORIZON)");
    }
    const auto before = shadow_ends_of(*Y->rep);
    Y.reset();
    Y = std::make_unique<TNode>("Y", dir + "/Y", m, oY, bins, 102);
    const auto after = shadow_ends_of(*Y->rep);
    std::printf("   %s restart of Y: reloaded=%zu receipts, shadows before=%zu after=%zu%s\n", tag.c_str(), Y->reloaded, before.size(),
                after.size(), after == before ? " (identical)" : "");
    if (torn_err) {   // R6: flip one byte of the shadow file; a fresh replayer ignores it, loudly
        const std::string sp = dir + "/Y/lane" + std::to_string(kChain) + ".shadow";
        std::fstream f(sp, std::ios::in | std::ios::out | std::ios::binary);
        if (f) { f.seekp(40); char c = 0x5a; f.write(&c, 1); }
        f.close();
        RepairReplayer fresh(2 * m.H);
        const std::size_t n = shadow_setup(fresh, true, sp, oY.lane_params_digest, m.G);
        *torn_err = std::to_string(n) + " shadows; " + shadow_load_error(fresh);
    }
    return {before.size(), after.size()};
}

static void print_metrics(const char* tag, const Metrics& M) {
    std::printf("METRICS %s: lane=%llu cuts=%llu (own=%llu cross=%llu) booked=%llu HELD=%llu deep-exhausted=%llu | base own=%llu shadow=%llu full=%llu | "
                "walk probes=%llu equal=%llu full=%llu ready=%llu rc5=%llu lineage=%llu | served deep pages=%llu ids=%llu wire=%llu B "
                "frames=%llu (%llu B) sidecars=%llu B shadow-files=%llu B | shadows restart before=%zu after=%zu same=%d | "
                "maxrss %ld -> %ld kB (delta %ld kB) | %.1f s\n",
                tag, (unsigned long long)M.lane, (unsigned long long)M.cuts, (unsigned long long)M.own, (unsigned long long)M.cross,
                (unsigned long long)M.booked, (unsigned long long)M.held, (unsigned long long)M.deep_held, (unsigned long long)M.via_own,
                (unsigned long long)M.via_shadow, (unsigned long long)M.via_full, (unsigned long long)M.walk.probe,
                (unsigned long long)M.walk.equal, (unsigned long long)M.walk.full, (unsigned long long)M.walk.ready,
                (unsigned long long)M.walk.rc5, (unsigned long long)M.walk.lineage, (unsigned long long)M.served.pages,
                (unsigned long long)M.served.ids, (unsigned long long)M.served.bytes, (unsigned long long)M.served.frames,
                (unsigned long long)M.served.frame_bytes, (unsigned long long)M.served.disk, (unsigned long long)M.shadow_bytes,
                M.sh_before, M.sh_after, M.sh_same ? 1 : 0, M.rss0, M.rss1, M.rss1 - M.rss0, M.secs);
    if (!M.first_hold.empty()) std::printf("   first hold (%s): %s\n", tag, M.first_hold.c_str());
    std::fflush(stdout);
}

int main() {
    Checker C;
    std::printf("== v37_xmr_relay_repair_chain_kat ==\n");
    constexpr bool have_fix = kHasDeep<RelayOptions>;
    Mode base_mode{true, env_u64("RC_HORIZON", 8), env_u64("RC_STEP", 2)};
    const std::string parts = std::getenv("RC_PARTS") ? std::getenv("RC_PARTS") : "both";   // both | deep (F2 only) | persist (F1 only)
    base_mode.deep = parts != "persist"; base_mode.persist = parts != "deep";
    Scn S;
    S.per_round = env_u64("RC_PER_ROUND", 4); S.rounds = env_u64("RC_ROUNDS", 12);
    S.stall_round = env_u64("RC_STALL_ROUND", 4); S.restart_round = env_u64("RC_RESTART_ROUND", 7);
    S.port_base = static_cast<u16>(env_u64("RC_PORT_BASE", 0));
    S.cut_limit = std::chrono::milliseconds(env_u64("RC_CUT_LIMIT_MS", 20000));
    const std::string only = std::getenv("RC_ONLY") ? std::getenv("RC_ONLY") : "";
    std::printf("-- scale: vault horizon %llu, probe step %llu, %llu receipts x %llu rounds, stall C at round %llu, restart C after round %llu; build=%s\n",
                (unsigned long long)base_mode.H, (unsigned long long)base_mode.G, (unsigned long long)S.per_round,
                (unsigned long long)S.rounds, (unsigned long long)S.stall_round, (unsigned long long)S.restart_round,
                have_fix ? "REPAIR-CHAIN" : "base (RC5)");
    if (only != "off") {
        std::printf("-- FIX: --relay-deep-order %s, --relay-shadow-persist %s\n", base_mode.deep ? "on" : "off", base_mode.persist ? "on" : "off");
        const Metrics M = run_scenario(base_mode, S, C, "FIX");
        print_metrics("FIX", M);
        C(M.setup_ok, "FIX scenario ran (three lineages, rotation, stall, restart)");
        C(M.cross > 0 && M.held == 0 && M.booked == M.cuts,
          "R1 CHAIN every cross-side cut BOOKED: cross=" + std::to_string(M.cross) + " booked=" + std::to_string(M.booked) + "/" +
          std::to_string(M.cuts) + " HELD=" + std::to_string(M.held) + " (base: HELD > 0, DEEP-DIVERGENCE)");
        C(M.sh_before > 0 && M.sh_same && M.sh_after == M.sh_before,
          "R2 RESTART the shadow holder's shadows survive: before=" + std::to_string(M.sh_before) + " after=" + std::to_string(M.sh_after) +
          " (base: after=0)");
        C(M.deep_held == 0 && M.served.pages > 0 && M.walk.ready > 0,
          "R3 DEEP below-horizon repairs served from the durable order: deep pages=" + std::to_string(M.served.pages) +
          " walk-ready=" + std::to_string(M.walk.ready) + ", DEEP-exhausted=" + std::to_string(M.deep_held) + " (base: > 0)");
    }
    if (only != "off" && !std::getenv("RC_SKIP_R2B")) {
        std::printf("-- R2b/R6: a shadow RC5 builds itself (own-prefix repair, the H2 shape), then a restart\n");
        std::string torn;
        const auto [bef, aft] = restart_case(base_mode, C, "R2b", &torn);
        C(bef == 1 && aft == bef, "R2b RESTART a shadow built by an RC5 own-prefix repair survives the restart: before=" +
                                  std::to_string(bef) + " after=" + std::to_string(aft) + " (base: after=0)");
        std::printf("   R6 corrupt shadow file -> %s\n", torn.c_str());
        C(torn.rfind("0 shadows; trailer hash mismatch", 0) == 0, "R6 TORN a corrupt shadow file loads as zero shadows with a loud reason (RC5 fallback)");
    }
    if (have_fix && only != "fix") {
        std::printf("-- OFF: the same scenario with --relay-deep-order off --relay-shadow-persist off (RC5 paths)\n");
        Mode off = base_mode; off.fix = false;
        const Metrics M = run_scenario(off, S, C, "OFF");
        print_metrics("OFF", M);
        C(M.held > 0 && M.deep_held > 0,
          "R4 COMPAT flags off = RC5: the capstone hold reproduces (HELD=" + std::to_string(M.held) + ", DEEP-exhausted=" +
          std::to_string(M.deep_held) + ")");
        C(M.served.pages == 0 && M.walk.probe == 0 && M.walk.full == 0 && M.sh_after == 0,
          "R4 COMPAT flags off: no deep page served, no walk probe, no shadow restored (the RC5 wire and state)");
    }
    if (!std::getenv("RC_KEEP")) {   // the per-run node dirs (durable logs, sidecars, shadow files)
        const char* rd = std::getenv("RC_DIR");
        const std::filesystem::path root = rd && *rd ? std::filesystem::path(rd) : std::filesystem::temp_directory_path();
        const std::string pre = "rc-kat-" + std::to_string(::getpid()) + "-";
        std::error_code ec;
        for (const auto& e : std::filesystem::directory_iterator(root, ec))
            if (e.path().filename().string().rfind(pre, 0) == 0) std::filesystem::remove_all(e.path(), ec);
    }
    return C.done("v37_xmr_relay_repair_chain_kat");
}
