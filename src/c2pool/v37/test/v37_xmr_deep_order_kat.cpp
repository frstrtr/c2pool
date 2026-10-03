// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ===========================================================================
// v37_xmr_deep_order_kat -- HOLD-ROUND-3 F3 (stagenet attempt 8): the
// WHOLE-ORDER fallback in pages, and bounded retention of the durable order.
//
// THE HOLD THIS CLOSES. A receiver that holds NO base for the finder's order
// below a0 -- a fresh node (own lane empty or short: its digest at a0 is
// unknown), a long-partitioned one, one whose shadows were evicted, or one
// whose matching shadow has no DROPS record -- is served the SUFFIX [a0, P)
// by a peer's vault, replays it after every base it has (own order, every
// shadow), reaches the spine from none, rejects the repair, and the relay
// marks the serving peer DEEP; every peer ends DEEP -> Exhausted ->
// "DEEP-DIVERGENCE ... no connected peer retains the divergent positions",
// for ever. Nothing is missing: every peer's durable order holds [0, P); the
// requester never asks for it (the only key to a deep [0, P) page was a probe
// below the server's horizon in the last 30 s, which an a0 probe landing
// exactly at the vault start never sets). A fresh node also held earlier, in
// relay_view: "our replay log has only N pushes (retry)" -- for ever, since
// lane positions are node-local and its log never reaches a0.
//
// THE FIX (node-local; no lane rule, V37C/V37P field, owed_digest byte or
// FB_* wire byte changes).
//   F3a requester: a suffix replay that reaches the spine from no base turns
//       the repair into a WHOLE-ORDER fallback (repair_reject -> full_only; the
//       shell's drops_lane_prefix arms it too when a verified view exists but
//       no DROPS base does): [0, P) is asked of every peer, in pages, that peer
//       first. The server refuses the FIRST [0, P) ask of a (peer, P) exactly
//       as today (every repair asks [0, P) first and re-arms to a suffix); the
//       SECOND ask is deliberate and is served -- so a fallback re-asks once
//       after a refusal and sets the peer aside on the second. The replay
//       from 0 verifies the fetched order against the committed digest (the
//       spine at P). Every peer refusing twice = a loud alarm naming the
//       retention and the cold-boot path (never a silent hold).
//   F3b server: deep pages are served under a per-peer budget (ids_factor x P
//       + one page ids per (peer, P); cuts_per_hour distinct cuts per peer),
//       not a 30-s walker mark. The durable order keeps the last R positions
//       (--relay-order-retain; 1,000,000 on mainnet, unbounded elsewhere),
//       hole-punches .order/.digest below, refuses a pruned position loudly
//       (the alarm names R), and a restart re-derives the same state. The
//       shadows' RAM is bounded (LRU shadows fold to digest-only witnesses).
//
// THE RIG (the hold-round-3 KAT's): real XmrRelayNode + FrameVault +
// SupplyService over loopback TCP, the real canonical XmrReceiptIngest with a
// DURABLE receipts log, a real V37Engine lane, the daemon's RepairReplayer
// (deep order + shadow persistence on); fake RandomX. Every receiver repairs
// the finder's cut exactly like main_v37_xmr relay_view (poll -> replay ->
// reject on failure -> poll again).
//
//   D1 (R3-3) a FRESH receiver D joins A/B after the lane passed the horizon
//             (its own lane = the last 8 backfilled receipts: digest at a0
//             unknown, no shadow, no record): the suffix replay fails, the
//             relay falls back to the WHOLE order, A serves it in pages with
//             no prior walker mark, D's replay from 0 reproduces the spine
//             (lane digest identical), the composed order's push multiset is
//             the finder's. Base: Exhausted + DEEP-DIVERGENCE, no deep page.
//   D1b       the attempt-8 CLASS exactly: the relay's probe is EQUAL through a
//             stale shadow digest (the shadow evicted / its record missing: no
//             base behind it), so no walk ever starts; the suffix replay fails
//             from every base; the fix falls back to the whole order, DEEP-free.
//             Base: every peer DEEP -> Exhausted -> DEEP-DIVERGENCE, for ever.
//   D2        page budget: the same cut asked whole again and again -- each
//             server serves at most its budget (one whole order here), then
//             refuses (over-ids-budget), the fallback ends Exhausted with the
//             retention/cold-boot text; no server can be made to serve
//             unbounded pages. Base: no fallback API (FAIL by value).
//   D3 (R3-5) retention: server E keeps R=16 positions (slab 4) of a 70-long
//             lane -> prunes (range, bytes), refuses a pruned position with
//             the ALARM line while F (unbounded) serves the whole order: G
//             books, no needed position lost; a receiver with E alone ends
//             Exhausted naming the retention + cold-boot path; above R served.
//   D3r       restart: E rebuilt on its durable files reloads the lane
//             (digest identical), re-derives the same lowest retained
//             position, serves above it, refuses below it.
//   D4        DeepServeBudget unit: first ask refused / second served, ids
//             cap, cuts-per-hour cap with an injected clock, window expiry,
//             once-per-verdict logging.
//   D5        shadow RAM bound: over the budget the LRU shadow folds to its
//             digests (witness kept, pushes gone, not a base).
//   D6        source pins (main_v37_xmr.cpp): the shell arms the fallback
//             from the DROPS prefix hold, alarms once per cut, wires the
//             flag and the mainnet default.
//
// RED on the base (9f681a377), GREEN on the fix. Knobs (env): DO_H (48),
// DO_G (4), DO_DIR, DO_KEEP, DO_VERBOSE.
// ===========================================================================
#include <atomic>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <set>
#include <sstream>
#include <thread>

#include "xmr_relay_test_util.hpp"
#include <c2pool/v37/xmr/relay/xmr_relay_node.hpp>
#include <c2pool/v37/xmr/relay/xmr_receipt_ingest.hpp>
#include <c2pool/v37/xmr/relay/xmr_repair_replay.hpp>
#include <c2pool/v37/xmr/relay/xmr_durable_order.hpp>
#include <c2pool/v37/v37_engine.hpp>

#ifndef V37_XMR_SHELL_SRC
#define V37_XMR_SHELL_SRC ""
#endif

using namespace gap2test;
using namespace std::chrono_literals;

static constexpr u32 kChain = 7;
static constexpr u64 kShareDiff = 1000;

static u64 env_u64(const char* k, u64 d) { const char* v = std::getenv(k); return v && *v ? std::strtoull(v, nullptr, 10) : d; }
static bool verbose() { return std::getenv("DO_VERBOSE") != nullptr; }
static std::string slurp(const std::string& p) { std::ifstream f(p, std::ios::binary); std::stringstream ss; ss << f.rdbuf(); return ss.str(); }
static std::string hex12(const bytes32& b) { return hex(b).substr(0, 12); }

// ── feature detection: the KAT builds on the base and fails there by value ──
template <class O> static void set_deep(O& o, const std::string& base, u64 step) {
    if constexpr (requires { o.deep_order; o.deep_order_path; o.receipts_log_path; o.deep_probe_step; }) {
        o.deep_order = true; o.deep_order_path = base; o.receipts_log_path = base + ".receipts"; o.deep_probe_step = step;
    } else { (void)o; (void)base; (void)step; }
}
template <class O> static bool set_retain(O& o, u64 R, u64 slab) {
    if constexpr (requires { o.deep_order_retain; o.deep_order_retain_slab; }) { o.deep_order_retain = R; o.deep_order_retain_slab = slab; return true; }
    else { (void)o; (void)R; (void)slab; return false; }
}
template <class O> static bool set_budget(O& o, u64 factor, u64 page, u32 cuts) {
    if constexpr (requires { o.deep_order_ids_factor; o.deep_order_budget_page_ids; o.deep_order_cuts_per_hour; }) {
        o.deep_order_ids_factor = factor; o.deep_order_budget_page_ids = page; o.deep_order_cuts_per_hour = cuts; return true;
    } else { (void)o; (void)factor; (void)page; (void)cuts; return false; }
}
template <class R> static std::size_t shadow_setup(R& r, const std::string& path, const bytes32& tag, u64 step) {
    if constexpr (requires { r.enable_persist(path, kChain, tag); r.load(); r.set_checkpoint_step(step); }) {
        r.set_checkpoint_step(step);
        r.enable_persist(path, kChain, tag);
        return r.load();
    } else { (void)r; (void)path; (void)tag; (void)step; return 0; }
}
template <class N> static std::optional<bytes32> digest_deep(N& n, u64 pos) {
    if constexpr (requires { n.digest_at_deep(pos); }) return n.digest_at_deep(pos); else return n.digest_at(pos);
}
template <class S> static u64 full_ready_of(const S& s) { if constexpr (requires { s.repair_full_ready; }) return s.repair_full_ready.load(); else return 0; }
template <class S> static u64 full_required_of(const S& s) { if constexpr (requires { s.repair_full_required; }) return s.repair_full_required.load(); else return 0; }
template <class S> static u64 full_refused_of(const S& s) { if constexpr (requires { s.repair_full_refused; }) return s.repair_full_refused.load(); else return 0; }
template <class S> static u64 full_exhausted_of(const S& s) { if constexpr (requires { s.repair_full_exhausted; }) return s.repair_full_exhausted.load(); else return 0; }
template <class S> static u64 serve_cuts_of(const S& s) { if constexpr (requires { s.deep_serve_cuts; }) return s.deep_serve_cuts.load(); else return 0; }
template <class S> static u64 serve_first_of(const S& s) { if constexpr (requires { s.deep_serve_first_ask; }) return s.deep_serve_first_ask.load(); else return 0; }
template <class S> static u64 serve_over_of(const S& s) { if constexpr (requires { s.deep_serve_over_budget; }) return s.deep_serve_over_budget.load(); else return 0; }
template <class S> static u64 serve_below_of(const S& s) { if constexpr (requires { s.deep_serve_below_retention; }) return s.deep_serve_below_retention.load(); else return 0; }
template <class S> static u64 deep_of(const S& s) { if constexpr (requires { s.repair_deep; }) return s.repair_deep.load(); else return 0; }
template <class N> static u64 lowest_of(N& n) { if constexpr (requires { n.durable_order_lowest(); }) return n.durable_order_lowest(); else return 0; }
template <class N> static bool full_exhausted(N& n, u64 P, const bytes32& s, std::string* d) {
    if constexpr (requires { n.repair_full_exhausted(P, s, d); }) return n.repair_full_exhausted(P, s, d); else { (void)d; return false; }
}
template <class N> static bool require_full(N& n, u64 P, const bytes32& s) {
    if constexpr (requires { n.repair_require_full(P, s); }) { n.repair_require_full(P, s); return true; } else return false;
}
struct DStats { u64 pages = 0, ids = 0, prunes = 0, pruned = 0, freed = 0, punch_fail = 0, below = 0; };
template <class S> static void dstats_retention(const S& s, DStats& d) {   // the retention counters exist on the fix only
    if constexpr (requires { s.prunes; s.pruned_positions; s.freed_bytes; s.punch_fail; s.below_retention; }) {
        d.prunes = s.prunes; d.pruned = s.pruned_positions; d.freed = s.freed_bytes; d.punch_fail = s.punch_fail; d.below = s.below_retention;
    } else { (void)s; (void)d; }
}
template <class N> static DStats dstats(N& n) {
    DStats d;
    if constexpr (requires { n.durable_order_stats(); }) {
        const auto s = n.durable_order_stats();
        d.pages = s.pages; d.ids = s.ids;
        dstats_retention(s, d);
    }
    return d;
}

// One daemonless node: relay + durable ingest + lane engine + replayer (the
// hold-round-3 KAT's TNode without the DROPS bookkeeping).
struct TNode {
    std::string name, dir;
    u64 H, G;
    ChainView chain;
    std::unique_ptr<c2pool::v37n::V37Engine> engine;
    std::unique_ptr<XmrRelayNode> relay;
    std::unique_ptr<XmrReceiptIngest> ingest;
    std::unique_ptr<RepairReplayer> rep;
    std::map<u64, bytes32> dig_at;
    std::vector<std::pair<::v37::ScriptRef, u64>> feed;
    u64 template_height = 0;
    std::size_t reloaded = 0, shadows_loaded = 0;
    std::mutex lmtx;                  // the relay logs from its reader threads too
    std::vector<std::string> lines;   // the relay's log lines (alarms, prunes, deep-serve)

    TNode(std::string n, std::string d, u64 h, u64 g, RelayOptions ro, const std::vector<std::pair<bytes32, u64>>& bins, u64 tip)
        : name(std::move(n)), dir(std::move(d)), H(h), G(g) {
        std::filesystem::create_directories(dir);
        const std::string base = dir + "/lane" + std::to_string(kChain);
        set_deep(ro, base, G);
        ro.vault.horizon_positions = H;
        for (const auto& [prev, hh] : bins) chain.note(prev, hh, bytes32{});
        chain.set_tip(tip);
        rep = std::make_unique<RepairReplayer>(2 * H);
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
            [this](const std::string& l) {
                { std::lock_guard<std::mutex> lk(lmtx); lines.push_back(l); }
                if (verbose()) std::printf("   [%s] %s\n", name.c_str(), l.c_str());
            });
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
        shadows_loaded = shadow_setup(*rep, base + ".shadow", ro.lane_params_digest, G);
        if (shadows_loaded) relay->note_alt_digests(rep->shadow_digests());
    }
    ~TNode() { relay->stop(); engine->stop(); }
    void pump() { for (auto& a : relay->drain_admitted()) ingest->on_admitted(std::move(a)); ingest->tick(template_height); }
    u64 next_pos() { auto s = engine->snapshot(kChain); return s ? s->next_pos : 0; }
    std::size_t lines_with(const std::string& needle) {
        std::lock_guard<std::mutex> lk(lmtx);
        std::size_t n = 0; for (const auto& l : lines) if (l.find(needle) != std::string::npos) ++n; return n;
    }
};

static RelayOptions opts(bool listen, std::vector<u16> dial, u64 backfill = 2048) {
    RelayOptions o;
    o.network = 3; o.chain = kChain; o.share_diff = kShareDiff; o.bind = BindMode::None;
    o.lane_params_digest = lane_params_digest(::v37::LaneParams{}, kShareDiff, BindMode::None);
    o.listen = listen; o.listen_host = "127.0.0.1"; o.listen_port = 0;
    for (u16 p : dial) o.peers.emplace_back("127.0.0.1", p);
    o.reoffer_seconds = 0;   // no HELLO re-offer: a fresh node must NOT receive the whole lane as a gift (its own lane stays short)
    o.hello_timeout_ms = 3000;
    o.cache_max = 1u << 20;
    o.backfill_positions = backfill;
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

// main's relay_view loop on N for the cut (P, spine): poll until Ready, replay
// the served order after our bases (RepairReplayer), reject on failure and
// poll again; until a replay reproduces the spine or `limit` passes.
struct Booking {
    bool ready = false, replay_ok = false;
    u64 a0 = ~u64{0}; std::size_t ids = 0, attempts = 0, rejected = 0;
    RepairReplayer::Base base = RepairReplayer::kNone;
    std::vector<std::pair<::v37::ScriptRef, u64>> pushes;
    std::string status;
};
static Booking book_via_relay(TNode& N, const std::vector<TNode*>& all, u64 P, const bytes32& spine, std::chrono::milliseconds limit) {
    Booking b;
    const auto dl = std::chrono::steady_clock::now() + limit;
    while (std::chrono::steady_clock::now() < dl) {
        for (auto* n : all) n->pump();
        std::vector<bytes32> ids;
        const auto st = N.relay->repair_poll(P, spine, 0, &ids);
        if (st != XmrRelayNode::RepairState::Ready) { std::this_thread::sleep_for(5ms); continue; }
        std::optional<bytes32> peer_a0;
        const u64 a0 = N.relay->repair_a0(P, spine, &peer_a0);
        std::vector<std::pair<::v37::ScriptRef, u64>> pushes;
        bool miss = false;
        for (const auto& id : ids) { ::v37::ScriptRef ref; if (!N.relay->cached(id, &ref)) { miss = true; break; } pushes.emplace_back(ref, kReceiptWeight); }
        if (miss) { std::this_thread::sleep_for(5ms); continue; }
        ++b.attempts;
        RepairReplayer::Base used = RepairReplayer::kNone;
        auto view = N.rep->replay(kChain, ::v37::LaneParams{}, P, spine, a0, N.feed, pushes, &used, peer_a0,
                                  a0 ? digest_deep(*N.relay, a0) : std::nullopt);
        if (!view) { ++b.rejected; N.relay->repair_reject(P, spine); continue; }   // main: reject -> ask again
        N.relay->note_alt_digests(N.rep->shadow_digests());
        b.ready = b.replay_ok = true; b.a0 = a0; b.ids = ids.size(); b.base = used; b.pushes = std::move(pushes);
        return b;
    }
    b.status = N.relay->repair_status(P, spine);
    return b;
}
static std::vector<std::vector<u8>> payload_multiset(const std::vector<std::pair<::v37::ScriptRef, u64>>& v, std::size_t n) {
    std::vector<std::vector<u8>> out;
    for (std::size_t i = 0; i < n && i < v.size(); ++i) out.push_back(v[i].first.payload);
    std::sort(out.begin(), out.end());
    return out;
}

int main() {
    Checker C;
    const u64 H = env_u64("DO_H", 48), G = env_u64("DO_G", 4);
    const char* rd = std::getenv("DO_DIR");
    const std::string dir = (rd && *rd ? std::string(rd) : std::filesystem::temp_directory_path().string()) + "/do-kat-" + std::to_string(::getpid());
    std::filesystem::remove_all(dir);
    std::printf("== v37_xmr_deep_order_kat (H=%llu G=%llu) ==\n", (unsigned long long)H, (unsigned long long)G);

    std::vector<std::pair<bytes32, u64>> bins;
    for (u64 h = 100; h < 140; ++h) bins.emplace_back(b32_of(static_cast<u8>(7 + h)), h);
    // every receipt pays its OWN payee: the lane digest is a Merkle root over the lane
    // STATE, so with one payee for all receipts every order would reproduce every
    // spine (identical pushes) and no base could ever be missing -- the real lanes
    // differ by payee at every position, and so must this rig
    auto mint = [&](TNode& W, u64 h, u32 salt, u32 n, const std::string& label, u32 nonce0) {
        const SynthBlock b = make_block(h, bins[h - 100].first, salt, nullptr, 2, static_cast<u8>(salt % 200 + 10));
        for (u32 k = 0; k < n; ++k) W.relay->submit_own(own(b, nonce0 + k, payee_of(label + "#" + std::to_string(h) + "." + std::to_string(k))));
    };

    // ── D1 (R3-3) + D2 (budget) + D5 (shadow RAM): a fresh receiver, no base anywhere ──
    std::printf("D1: a fresh receiver with no base anywhere books through the whole-order fallback\n");
    {
        std::string why;
        RelayOptions oA = opts(true, {}), oB = opts(true, {});
        // budget: exactly ONE whole order per (peer, cut) (factor 1, no page slack), so D2 can show the bound at KAT scale
        const bool budget_api = set_budget(oA, 1, 0, 8) && set_budget(oB, 1, 0, 8);
        auto A = std::make_unique<TNode>("A", dir + "/A", H, G, oA, bins, 100);
        C(A->relay->start(why), "D1 A starts " + why);
        const u16 pA = A->relay->listen_port();
        oB.peers.emplace_back("127.0.0.1", pA);
        auto B = std::make_unique<TNode>("B", dir + "/B", H, G, oB, bins, 100);
        C(B->relay->start(why), "D1 B starts " + why);
        const u16 pB = B->relay->listen_port();
        std::vector<TNode*> ab{A.get(), B.get()};
        bool ok = wait_for([&] { return A->relay->ready_peers().size() == 1 && B->relay->ready_peers().size() == 1; }, ab);
        C(ok, "D1 A-B up");
        auto tmpl = [&](u64 h, const std::vector<TNode*>& who) { for (auto* n : who) { n->template_height = h; n->chain.set_tip(h); } };
        auto same_pos = [&](u64 want, const std::vector<TNode*>& who) {
            return wait_for([&] { for (auto* n : who) if (n->next_pos() != want) return false; return true; }, who, 25000ms);
        };
        u64 lane = 0;
        for (u64 h = 100; h < 107; ++h) {   // 70 receipts of A over 7 bins: the lane passes H = 48
            tmpl(h, ab);
            mint(*A, h, static_cast<u32>(50 + h), 10, "A", static_cast<u32>(10000 + 100 * h));
            tmpl(h + 1, ab);
            lane += 10;
            ok &= same_pos(lane, ab);
        }
        const u64 P2 = A->next_pos();
        const bytes32 spine2 = A->dig_at[P2];
        C(ok && P2 == 70 && P2 > H && B->dig_at[P2] == spine2, "D1 A's lane at P2=" + std::to_string(P2) + " > H (" + std::to_string(H) + "); B shares A's whole order");
        // D joins FRESH: an empty lane, a small backfill (its own lane = A's last 8 receipts at positions 0..8)
        auto D = std::make_unique<TNode>("D", dir + "/D", H, G, opts(false, {pA, pB}, /*backfill=*/8), bins, 107);
        D->template_height = 107;
        C(D->relay->start(why), "D1 D (fresh) starts " + why);
        std::vector<TNode*> all{A.get(), B.get(), D.get()};
        ok = wait_for([&] { return D->relay->ready_peers().size() == 2 && D->next_pos() == 8; }, all, 20000ms);
        C(ok && D->next_pos() == 8 && D->feed.size() == 8,
          "D1 D is up with 2 peers; its own lane holds the 8 backfilled receipts at positions [0,8): no digest at a0, no shadow, no record");
        C(!digest_deep(*D->relay, P2 - H) && D->rep->shadows() == 0, "D1 precondition: D's digest at a0=" + std::to_string(P2 - H) + " is unknown and D holds no shadow");
        const DStats a_before = dstats(*A->relay), b_before = dstats(*B->relay);
        const Booking bk = book_via_relay(*D, all, P2, spine2, 40000ms);
        C(bk.ready && bk.replay_ok && bk.a0 == 0 && bk.ids == P2 && bk.base == RepairReplayer::kFull,
          "D1 ★ D books A's cut at P2 through the WHOLE order [0," + std::to_string(P2) + ") (a0=" + std::to_string(bk.a0) + ", " + std::to_string(bk.ids) + " ids, base=" + std::to_string(static_cast<int>(bk.base)) + ", attempts=" +
              std::to_string(bk.attempts) + " rejected=" + std::to_string(bk.rejected) + ") -- 9f681a377: Exhausted + DEEP-DIVERGENCE for ever [" + bk.status + "]");
        C(bk.rejected >= 1, "D1 the suffix replay failed first (no base here reproduces the spine from [0,a0)): rejected=" + std::to_string(bk.rejected));
        const DStats a_after = dstats(*A->relay), b_after = dstats(*B->relay);
        const u64 deep_pages = (a_after.pages - a_before.pages) + (b_after.pages - b_before.pages);
        const u64 deep_ids = (a_after.ids - a_before.ids) + (b_after.ids - b_before.ids);
        C(deep_pages >= 1 && deep_ids == P2,
          "D1 the whole order came from a peer's DURABLE order in deep pages (pages=" + std::to_string(deep_pages) + " ids=" + std::to_string(deep_ids) +
              ") with NO prior walk probe below the server's horizon (D's probe landed at the vault start)");
        C(serve_cuts_of(A->relay->stats()) + serve_cuts_of(B->relay->stats()) == 1 && serve_first_of(A->relay->stats()) + serve_first_of(B->relay->stats()) >= 1,
          "D1 ask-twice: the first [0,P) ask was refused (BELOW_HORIZON, as today), the second served -- one whole-order cut on the servers");
        C(full_required_of(D->relay->stats()) >= 1 && full_ready_of(D->relay->stats()) >= 1 && deep_of(D->relay->stats()) == 0 &&
              !D->relay->repair_deep_divergence(P2, spine2),
          "D1 D's relay: fallback required=" + std::to_string(full_required_of(D->relay->stats())) + " ready=" + std::to_string(full_ready_of(D->relay->stats())) +
              ", no peer named DEEP, no DEEP-DIVERGENCE");
        C(D->lines_with("relay-deep-order: fetched the WHOLE order [0," + std::to_string(P2) + ")") == 1,
          "D1 one fetch line (peer, pages, bytes, the committed digest it is verified against) on D");
        C(A->lines_with("asked the WHOLE order [0," + std::to_string(P2) + ") a second time -> serving") + B->lines_with("asked the WHOLE order [0," + std::to_string(P2) + ") a second time -> serving") == 1,
          "D1 one serve line on the serving peer (budget named)");
        // the lane digest at P2 is identical: the replay's view reproduced A's spine; D now holds A's lineage as a shadow ending at P2
        bool shadow_ok = false;
        for (const auto& [L, dg] : D->rep->shadow_ends()) if (L == P2 && dg == spine2) shadow_ok = true;
        C(shadow_ok && D->rep->shadow_with_digest(P2, spine2).has_value(),
          "D1 lane_digest identical: D's replay from 0 reproduced spine2 (" + hex12(spine2) + "); the fetched order is D's shadow of A's lineage (P_end=P2)");
        C(payload_multiset(bk.pushes, P2) == payload_multiset(A->feed, P2) && bk.pushes.size() == P2,
          "D1 the composed order's push multiset over [0,P2) equals the finder's (the DROPS prefix is the same multiset on every node)");

        // ── D1b: the attempt-8 CLASS exactly -- the probe is EQUAL through a shadow digest the relay
        // still holds, but the replayer has no base behind it (the shadow evicted / its record
        // missing): no walk is ever started (the probe did not differ), the suffix replay fails
        // from every base, and on the base every peer ends DEEP -> Exhausted -> DEEP-DIVERGENCE
        // for ever (re-asked every 5 s, the same answer). The fix falls back to the whole order.
        std::printf("D1b: probe equal through a stale shadow digest, no base behind it\n");
        {
            for (u64 h = 107; h < 108; ++h) {   // A's next cut: P3 = 80, a0 = P3 - H = 32 (a shadow checkpoint: G | 32)
                tmpl(h, ab);
                mint(*A, h, static_cast<u32>(50 + h), 10, "A", static_cast<u32>(10000 + 100 * h));
                tmpl(h + 1, ab);
                lane += 10;
                ok &= same_pos(lane, ab);
            }
            D->template_height = 108; D->chain.set_tip(108);
            const u64 P3 = A->next_pos();
            const bytes32 spine3 = A->dig_at[P3];
            const u64 a0 = P3 - H;
            C(ok && P3 == 80 && B->dig_at[P3] == spine3 && a0 % G == 0, "D1b A's next cut at P3=" + std::to_string(P3) + ", a0=" + std::to_string(a0));
            // D's relay keeps the shadow's digests (note_alt_digests after D1's replay); D's replayer loses the shadow itself
            auto fresh = std::make_unique<RepairReplayer>(2 * H);
            std::swap(D->rep, fresh);
            C(D->relay->alt_digest_is(a0, A->dig_at[a0]) && D->rep->shadows() == 0 && digest_deep(*D->relay, a0) && *digest_deep(*D->relay, a0) != A->dig_at[a0],
              "D1b precondition: the relay's probe witness at a0 EQUALS the finder's digest (stale shadow digest), the replayer holds no shadow, D's own digest at a0 differs");
            const u64 deep_before = deep_of(D->relay->stats());
            const Booking b3 = book_via_relay(*D, all, P3, spine3, 20000ms);
            C(b3.ready && b3.replay_ok && b3.a0 == 0 && b3.ids == P3 && b3.base == RepairReplayer::kFull && b3.rejected >= 1,
              "D1b ★ D books P3 through the WHOLE order after the suffix replay failed (a0=" + std::to_string(b3.a0) + ", ids=" + std::to_string(b3.ids) +
                  ", attempts=" + std::to_string(b3.attempts) + " rejected=" + std::to_string(b3.rejected) + ") -- 9f681a377: every peer DEEP, Exhausted + DEEP-DIVERGENCE for ever, "
                  "no walk (the probe never differed) [" + b3.status + "]");
            C(deep_of(D->relay->stats()) == deep_before && !D->relay->repair_deep_divergence(P3, spine3),
              "D1b no peer was named DEEP for a lineage every peer holds (deep=" + std::to_string(deep_of(D->relay->stats())) + ")");
            C(D->lines_with("relay-deep-order: fetched the WHOLE order [0," + std::to_string(P3) + ")") == 1 &&
                  D->lines_with("REPAIR-DEEP repair of P=" + std::to_string(P3) + ": the suffix [" + std::to_string(a0) + "," + std::to_string(P3) + ")") == 1,
              "D1b the relay named the switch (suffix reached the spine from no base -> whole-order fallback) and the fetch, once each");
            std::swap(D->rep, fresh);   // D1's replayer (its shadow of A's lineage at P2) back for D5
        }

        // ── D2: the page budget -- a peer cannot be made to serve unbounded pages ──
        std::printf("D2: the per-peer deep-serve budget\n");
        if (budget_api) {
            const u64 budget_per_server = P2;   // factor 1 x P2 + 0 slack
            std::size_t extra_ok = 0, exhausted_seen = 0;
            std::string detail, status;
            for (int cycle = 0; cycle < 4; ++cycle) {
                D->relay->repair_reject(P2, spine2);   // forget the Ready order, ask the whole order again
                require_full(*D->relay, P2, spine2);
                const auto dl = std::chrono::steady_clock::now() + 9000ms;
                bool got = false;
                while (std::chrono::steady_clock::now() < dl) {
                    for (auto* n : all) n->pump();
                    std::vector<bytes32> ids;
                    if (D->relay->repair_poll(P2, spine2, 0, &ids) == XmrRelayNode::RepairState::Ready && D->relay->repair_a0(P2, spine2) == 0) { got = true; break; }
                    if (full_exhausted(*D->relay, P2, spine2, &detail)) { ++exhausted_seen; status = D->relay->repair_status(P2, spine2); break; }
                    std::this_thread::sleep_for(5ms);
                }
                if (got) ++extra_ok;
            }
            const DStats a2 = dstats(*A->relay), b2 = dstats(*B->relay);
            C(extra_ok >= 1 && exhausted_seen >= 1,
              "D2 the same cut asked whole again: served while within the budget (extra whole orders=" + std::to_string(extra_ok) + "), then the fallback ends EXHAUSTED (" +
                  std::to_string(exhausted_seen) + "x) -- " + detail);
            // served so far: D1 (one whole order of P2), D1b (one whole order of P3 = 80), D2 (one more whole order of P2, from the
            // other server); 4 asks of P2 in D2 could not add more than that one: per server <= P2 + P3, in all exactly 2 x P2 + P3
            const u64 P3 = A->next_pos();
            C(extra_ok == 1 && a2.ids <= budget_per_server + P3 && b2.ids <= budget_per_server + P3 && a2.ids + b2.ids == 2 * budget_per_server + P3,
              "D2 ★ no server served more than its budget: A ids=" + std::to_string(a2.ids) + " B ids=" + std::to_string(b2.ids) + " (budget " +
                  std::to_string(budget_per_server) + " per server for this cut + the " + std::to_string(P3) + " of D1b's cut); " + std::to_string(extra_ok) +
                  " extra whole order in 4 asks: the asker cannot make a peer serve unbounded pages");
            C(serve_over_of(A->relay->stats()) + serve_over_of(B->relay->stats()) >= 1 && full_refused_of(D->relay->stats()) >= 1 &&
                  (A->lines_with("REFUSED, over-ids-budget") + B->lines_with("REFUSED, over-ids-budget")) >= 1,
              "D2 over-budget asks were refused and logged once per (peer, cut) (over_budget=" +
                  std::to_string(serve_over_of(A->relay->stats()) + serve_over_of(B->relay->stats())) + ", D refused=" + std::to_string(full_refused_of(D->relay->stats())) + ")");
            C(status.find("WHOLE-ORDER fallback") != std::string::npos && status.find("retention") != std::string::npos && status.find("cold-boot") != std::string::npos,
              "D2 the exhausted status names the fallback, the retention and the cold-boot path: " + status.substr(0, 160) + "...");
            C(full_exhausted_of(D->relay->stats()) >= 1 && D->lines_with("relay-ALARM REPAIR-DEEP RETENTION") >= 1,
              "D2 the relay alarmed once per repair (never a silent hold): exhausted=" + std::to_string(full_exhausted_of(D->relay->stats())));
        } else {
            C(false, "D2 the base has no whole-order fallback API (repair_require_full / deep-serve budget): nothing bounds a deep page");
        }

        // ── D5: the shadows' RAM bound ──
        std::printf("D5: the shadows' RAM bound\n");
#if defined(C2POOL_XMR_SHADOW_RAM_BUDGET)
        {
            const auto before = D->rep->pushes_held();
            D->rep->set_ram_budget(1);   // below one shadow: the LRU shadow folds to its digests
            C(before == P2 && D->rep->shadows() == 1 && D->rep->shadows_folded() == 1 && D->rep->pushes_held() == 0 && D->rep->folds() == 1,
              "D5 over the budget the shadow folds to digests only (pushes " + std::to_string(before) + " -> " + std::to_string(D->rep->pushes_held()) + ")");
            bool ends_ok = false;
            for (const auto& [L, dg] : D->rep->shadow_ends()) if (L == P2 && dg == spine2) ends_ok = true;
            C(ends_ok && D->rep->shadow_with_digest(P2, spine2).has_value() && D->rep->shadow_with_digest(P2, spine2)->first == P2,
              "D5 the folded shadow stays a probe witness (digests, end, record key) ...");
            RepairReplayer::Base used = RepairReplayer::kNone;
            std::vector<std::pair<::v37::ScriptRef, u64>> suffix(A->feed.begin() + static_cast<std::ptrdiff_t>(P2 - H), A->feed.begin() + static_cast<std::ptrdiff_t>(P2));
            auto v = D->rep->replay(kChain, ::v37::LaneParams{}, P2, spine2, P2 - H, D->feed, suffix, &used, A->dig_at[P2 - H], std::nullopt);
            C(!v && used == RepairReplayer::kNone, "D5 ... but is no replay BASE any more (the caller takes the whole-order fallback)");
            D->rep->set_ram_budget(0);
        }
#else
        C(false, "D5 the base has no shadow RAM budget");
#endif
        for (auto* n : all) n->relay->set_dialing(false);
    }

    // ── D3 (R3-5): retention -- prune, refuse + alarm a pruned position, a longer-retaining peer serves; D3r restart ──
    std::printf("D3: retention of the durable order\n");
    {
        std::string why;
        const u64 R = 16, slab = 4;
        RelayOptions oE = opts(true, {}), oF = opts(true, {});
        const bool retain_api = set_retain(oE, R, slab);
        auto E = std::make_unique<TNode>("E", dir + "/E", H, G, oE, bins, 100);
        C(E->relay->start(why), "D3 E (retain R=" + std::to_string(R) + ") starts " + why);
        const u16 pE = E->relay->listen_port();
        oF.peers.emplace_back("127.0.0.1", pE);
        auto F = std::make_unique<TNode>("F", dir + "/F", H, G, oF, bins, 100);
        C(F->relay->start(why), "D3 F (unbounded) starts " + why);
        const u16 pF = F->relay->listen_port();
        std::vector<TNode*> ef{E.get(), F.get()};
        bool ok = wait_for([&] { return E->relay->ready_peers().size() == 1 && F->relay->ready_peers().size() == 1; }, ef);
        auto tmpl = [&](u64 h, const std::vector<TNode*>& who) { for (auto* n : who) { n->template_height = h; n->chain.set_tip(h); } };
        u64 lane = 0;
        for (u64 h = 100; h < 107; ++h) {
            tmpl(h, ef);
            mint(*E, h, static_cast<u32>(50 + h), 10, "E", static_cast<u32>(20000 + 100 * h));
            tmpl(h + 1, ef);
            lane += 10;
            ok &= wait_for([&] { for (auto* n : ef) if (n->next_pos() != lane) return false; return true; }, ef, 25000ms);
        }
        const u64 P = E->next_pos();
        const bytes32 spine = E->dig_at[P];
        C(ok && P == 70 && F->dig_at[P] == spine, "D3 E's lane at P=" + std::to_string(P) + "; F shares it");
        const DStats es = dstats(*E->relay);
        const u64 low = lowest_of(*E->relay);
        C(retain_api && es.prunes >= 1 && low > 0 && low >= P - R - slab && low <= P - R + 2 && es.pruned == low,
          "D3 ★ E pruned its durable order below position " + std::to_string(low) + " (prunes=" + std::to_string(es.prunes) + ", pruned_positions=" +
              std::to_string(es.pruned) + ", R=" + std::to_string(R) + ", lane " + std::to_string(P) + ") -- 9f681a377: no retention bound exists");
        C(E->lines_with("relay-deep-order: pruned the durable order below position") == es.prunes && es.prunes >= 1,
          "D3 one log line per prune (range, bytes freed): " + std::to_string(E->lines_with("relay-deep-order: pruned the durable order below position")) +
              " line(s) for " + std::to_string(es.prunes) + " prune(s)" +
              (es.freed ? " (" + std::to_string(es.freed) + " B freed)" : es.punch_fail ? " (this filesystem cannot punch holes: logical retention only)" : ""));
        {
            std::vector<std::pair<u64, bytes32>> ids;
            const bool above = E->relay->own_order_ids(low, P, ids) && ids.size() == P - low;
            const bool below = !E->relay->own_order_ids(0, P, ids);
            C(above && below && digest_deep(*E->relay, low).has_value() && digest_deep(*E->relay, P).has_value(),
              "D3 above R served (own_order_ids [" + std::to_string(low) + "," + std::to_string(P) + ") = " + std::to_string(P - low) + " ids), below R refused");
        }
        // G: a fresh receiver with E (retains 16) and F (unbounded): E refuses the pruned positions loudly, F serves the whole order
        auto Gn = std::make_unique<TNode>("G", dir + "/G", H, G, opts(false, {pE, pF}, 8), bins, 107);
        Gn->template_height = 107;
        C(Gn->relay->start(why), "D3 G (fresh) starts " + why);
        std::vector<TNode*> all{E.get(), F.get(), Gn.get()};
        ok = wait_for([&] { return Gn->relay->ready_peers().size() == 2 && Gn->next_pos() == 8; }, all, 20000ms);
        C(ok, "D3 G is up with E and F");
        const DStats f_before = dstats(*F->relay);
        const Booking bk = book_via_relay(*Gn, all, P, spine, 40000ms);
        const DStats f_after = dstats(*F->relay), e_after = dstats(*E->relay);
        C(bk.ready && bk.replay_ok && bk.a0 == 0 && bk.ids == P && f_after.ids - f_before.ids == P && e_after.ids == 0,
          "D3 ★ G books the cut through F's whole order (F served " + std::to_string(f_after.ids - f_before.ids) + " ids, E served " + std::to_string(e_after.ids) +
              " -- it pruned [0," + std::to_string(low) + ")): no needed position was lost [" + bk.status + "]");
        // G2: E alone -> every whole-order ask refused twice -> EXHAUSTED, the alarm names the retention and the cold-boot path (forced)
        auto G2 = std::make_unique<TNode>("G2", dir + "/G2", H, G, opts(false, {pE}, 8), bins, 107);
        G2->template_height = 107;
        C(G2->relay->start(why), "D3 G2 (fresh, E only) starts " + why);
        std::vector<TNode*> eg{E.get(), G2.get()};
        ok = wait_for([&] { return G2->relay->ready_peers().size() == 1 && G2->next_pos() == 8; }, eg, 20000ms);
        std::string detail;
        bool exhausted = false;
        {
            const auto dl = std::chrono::steady_clock::now() + 30000ms;
            while (std::chrono::steady_clock::now() < dl) {
                for (auto* n : eg) n->pump();
                std::vector<bytes32> ids;
                const auto st = G2->relay->repair_poll(P, spine, 0, &ids);
                if (st == XmrRelayNode::RepairState::Ready) {
                    std::optional<bytes32> pa0;
                    const u64 a0 = G2->relay->repair_a0(P, spine, &pa0);
                    std::vector<std::pair<::v37::ScriptRef, u64>> pushes;
                    bool miss = false;
                    for (const auto& id : ids) { ::v37::ScriptRef ref; if (!G2->relay->cached(id, &ref)) { miss = true; break; } pushes.emplace_back(ref, kReceiptWeight); }
                    if (miss) { std::this_thread::sleep_for(5ms); continue; }
                    RepairReplayer::Base used = RepairReplayer::kNone;
                    auto v = G2->rep->replay(kChain, ::v37::LaneParams{}, P, spine, a0, G2->feed, pushes, &used, pa0, a0 ? digest_deep(*G2->relay, a0) : std::nullopt);
                    if (v) { C(false, "D3 G2 must not book from E alone (E pruned [0," + std::to_string(low) + "))"); break; }
                    G2->relay->repair_reject(P, spine);
                    continue;
                }
                if (full_exhausted(*G2->relay, P, spine, &detail)) { exhausted = true; break; }
                std::this_thread::sleep_for(5ms);
            }
        }
        const std::string st2 = G2->relay->repair_status(P, spine);
        C(exhausted && detail.find("retains >= " + std::to_string(low)) != std::string::npos,
          "D3 ★ forced: with E alone the whole-order fallback ends EXHAUSTED and the detail names what E retains -- " + detail);
        C(serve_below_of(E->relay->stats()) >= 1 && E->lines_with("relay-deep-serve: ALARM peer") >= 1 &&
              E->lines_with("below our retention: lowest retained " + std::to_string(low)) >= 1,
          "D3 E refused the pruned positions with the ALARM line naming its lowest retained position and --relay-order-retain (below_retention=" +
              std::to_string(serve_below_of(E->relay->stats())) + ")");
        C(st2.find("retention") != std::string::npos && st2.find("cold-boot") != std::string::npos && G2->lines_with("relay-ALARM REPAIR-DEEP RETENTION") >= 1 &&
              !G2->relay->repair_deep_divergence(P, spine),
          "D3 the alarm names the retention (--relay-order-retain) and the cold-boot path, never DEEP-DIVERGENCE: " + st2.substr(0, 140) + "...");
        for (auto* n : all) n->relay->set_dialing(false);
        G2->relay->set_dialing(false);
        G2.reset(); Gn.reset(); F.reset();

        // ── D3r: restart E on its durable files: the pruned state reloads deterministically ──
        std::printf("D3r: restart after a prune\n");
        const bytes32 tip_before = E->dig_at[P];
        const u64 low_before = low;
        const DStats before = dstats(*E->relay);
        E.reset();
        auto E2 = std::make_unique<TNode>("E", dir + "/E", H, G, oE, bins, 107);
        C(E2->relay->start(why), "D3r E restarts on its durable files " + why);
        const DStats after = dstats(*E2->relay);
        C(E2->reloaded == P && E2->next_pos() == P && E2->dig_at[P] == tip_before,
          "D3r the receipts log (kept whole) rebuilt the lane: " + std::to_string(E2->reloaded) + " receipts, digest at P identical");
        C(lowest_of(*E2->relay) == low_before && after.prunes == before.prunes && after.pruned == before.pruned,
          "D3r ★ the durable order re-derived the SAME lowest retained position (" + std::to_string(lowest_of(*E2->relay)) + ") and prune count (" +
              std::to_string(after.prunes) + ") -- the pruned state reloads deterministically");
        {
            std::vector<std::pair<u64, bytes32>> ids;
            const bool above = E2->relay->own_order_ids(low_before, P, ids) && ids.size() == P - low_before;
            const bool below = !E2->relay->own_order_ids(0, P, ids);
            C(above && below && digest_deep(*E2->relay, low_before).has_value() && !digest_deep(*E2->relay, 4).has_value(),
              "D3r after the restart: above R served, below R refused (digest at position 4 -- below the in-memory horizon too -- unknown)");
        }
        E2->relay->set_dialing(false);
    }

    // ── D4: DeepServeBudget unit ──
    std::printf("D4: DeepServeBudget\n");
#if defined(C2POOL_XMR_DEEP_SERVE_BUDGET)
    {
        using B = DeepServeBudget;
        B::Options o; o.ids_factor = 2; o.page_ids = 10; o.cuts_per_hour = 2; o.window = std::chrono::seconds(3600);
        B b(o);
        auto t0 = B::Clock::now();
        const auto a1 = b.ask(1, 0, 100, 50, t0);
        const auto a2 = b.ask(1, 0, 100, 50, t0);
        C(a1.v == B::Verdict::FirstAsk && a2.v == B::Verdict::Serve && a2.first_page && a2.ids_max == 210,
          "D4 the first [0,P) ask is refused, the second served (ids budget 2 x 100 + 10)");
        b.served(1, 100, 50);
        const auto a3 = b.ask(1, 0, 100, 50, t0); b.served(1, 100, 50);
        const auto a4 = b.ask(1, 50, 100, 50, t0); b.served(1, 100, 50);
        const auto a5 = b.ask(1, 50, 100, 50, t0); b.served(1, 100, 50);
        const auto a6 = b.ask(1, 50, 100, 50, t0);
        C(a3.v == B::Verdict::Serve && !a3.first_page && a4.v == B::Verdict::Serve && a5.v == B::Verdict::Serve && a6.v == B::Verdict::OverIds && a6.ids_used == 200,
          "D4 pages (a > 0 too) count against the cut's ids budget; the 5th page (250 > 210) is refused over-ids-budget");
        const auto c1 = b.ask(1, 0, 200, 10, t0); const auto c2 = b.ask(1, 0, 200, 10, t0);
        const auto c3 = b.ask(1, 0, 300, 10, t0); const auto c4 = b.ask(1, 0, 300, 10, t0);
        C(c1.v == B::Verdict::FirstAsk && c2.v == B::Verdict::Serve && c3.v == B::Verdict::FirstAsk && c4.v == B::Verdict::OverCuts && c4.cuts_hour == 2,
          "D4 the per-peer cuts-per-hour cap: a 3rd distinct cut in the hour is refused over-cuts-budget");
        const auto c5 = b.ask(1, 0, 300, 10, t0 + std::chrono::seconds(3601));
        C(c5.v == B::Verdict::Serve && c5.cuts_hour == 1, "D4 the window rolls: an hour later the cut is served (cuts this hour = 1)");
        const auto d1 = b.ask(2, 0, 100, 10, t0); const auto d2 = b.ask(2, 0, 100, 10, t0);
        C(d1.v == B::Verdict::FirstAsk && d2.v == B::Verdict::Serve, "D4 budgets are per peer");
        C(b.note_logged(1, 100, B::Verdict::OverIds) && !b.note_logged(1, 100, B::Verdict::OverIds) && b.note_logged(1, 100, B::Verdict::OverCuts),
          "D4 a refusal is logged once per (peer, cut, verdict)");
        const auto s = b.stats();
        C(s.cuts == 4 && s.first_ask == 4 && s.over_ids == 1 && s.over_cuts == 1 && s.served_ids == 200, "D4 counters");
    }
#else
    C(false, "D4 the base has no DeepServeBudget");
#endif

    // ── D6: source pins (the shell wires F3) ──
    std::printf("D6: source pins (main_v37_xmr.cpp)\n");
    {
        const std::string sh = slurp(V37_XMR_SHELL_SRC);
        C(!sh.empty(), "D6 shell source readable");
        C(sh.find("relay_node->repair_require_full(P, cc.spine_digest,") != std::string::npos &&
              sh.find("WHOLE-ORDER fallback: fetching [0,") != std::string::npos,
          "D6 F3a: drops_lane_prefix arms the whole-order fallback when no DROPS base for [0,a0) exists (hold text names it)");
        C(sh.find("relay_node->repair_full_exhausted(P, spine, &full_detail)") != std::string::npos &&
              sh.find("relay_full_alarmed.insert(key).second") != std::string::npos &&
              sh.find("relay-ALARM REPAIR-DEEP RETENTION") != std::string::npos,
          "D6 F3a: relay_view alarms once per cut when every peer refused the whole order (retention + cold-boot named)");
        C(sh.find("a0 > feed_log.size()") == std::string::npos,
          "D6 F3a: the 'our replay log has only N pushes (retry)' early return is gone (the replayer skips a short own log and tries the shadows)");
        C(sh.find("\"--relay-order-retain\"") != std::string::npos && sh.find("kRelayOrderRetainMainnet = 1000000") != std::string::npos &&
              sh.find("ro.deep_order_retain = relay_order_retain;") != std::string::npos &&
              sh.find("relay_replayer.set_ram_budget(4 * relay_order_retain)") != std::string::npos,
          "D6 F3b: --relay-order-retain (mainnet default 1,000,000; 0 = unbounded elsewhere) feeds the durable order and the shadows' RAM budget");
        C(sh.find("relay-deep-order: fallback required=") != std::string::npos && sh.find("retain=%llu lowest=%llu prunes=%llu") != std::string::npos,
          "D6 the status line reports the fallback, the serve budget, the retention and the shadow RAM");
    }

    if (!std::getenv("DO_KEEP")) std::filesystem::remove_all(dir);
    return C.done("v37_xmr_deep_order_kat");
}
