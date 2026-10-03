// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ===========================================================================
// v37_xmr_hold_round3_kat -- HOLD-ROUND-3 (stagenet attempt 8, 2026-10-03):
// the P > vault-horizon SUFFIX hold and the restart origin-bin hold.
//
// ATTEMPT 8 (binary 8a7ed91b3). A and C held the SAME receipt set but
// different lane ORDERS (receivers had struck the finder's post-FOUND shares
// before pay-now armed and admitted them later, in the late tail). C found
// 2220998 at P=2451 > horizon 2160: A's relay repair served the SUFFIX
// [312,2451) and its prefix probe matched C's digest at 312 through A's SHADOW
// of C's lineage -- but the DROPS prefix derivation accepted only our own
// digest at a0 or a FINISHED settlement replay, and the replay ran only from
// the fold, AFTER the DROPS composition the hold aborted on every retry:
// "a0 digests differ; the settlement replay of this cut has not run" x490.
// B (restarted) got the whole order, then the replay's canonical-order check
// could not bin 5 receipts whose parent was an ORPHANED block (gone from a
// ChainView rebuilt from main-chain headers): the DROPS path had the journal
// fallback, the replay path did not. Permanent, both.
//
// THE RIG (the repair-chain KAT's): real XmrRelayNode + FrameVault +
// SupplyService over loopback TCP, the real canonical XmrReceiptIngest with a
// DURABLE receipts log, a real V37Engine lane, the daemon's RepairReplayer
// (deep order + shadow persistence on), the daemon's LaneBinJournal; fake
// RandomX. Every non-winner repairs the winner's cut exactly like
// main_v37_xmr relay_view, and the DROPS prefix base is decided exactly like
// main's drops_lane_prefix (drops::decide_suffix_base, F1) in MAIN'S ORDER:
// the prefix derivation BEFORE the fold.
//
//   R3-1 the attempt-8 shape: three nodes; C's order differs from A's in an
//        early window; A's cut h1 at P1 < H gives C a FULL repair (a shadow +
//        DROPS record of A's lineage); the lane grows past H; A's cut h2 at
//        P2 > H has a0 = P2 - H inside (divergence, P1): the relay serves the
//        suffix with the probe matched through the shadow; the DROPS prefix
//        base is decided before any fold ran: the replay is RUN NOW, once, and
//        the base is the shadow's record (exact digest at a0). Base: HOLD
//        ("the settlement replay of this cut has not run"), forever.
//        Mirror (the WON frame after the pre-fold replay): no second replay,
//        the same base. A node with no shadow of A's lineage HOLDs with the
//        replay's own reason named (never a composition from a suffix).
//   R3-2 B's shape: a receipt whose parent is a side block; B restarts on a
//        ChainView without that header: the reload resolves its bin through
//        the origin-bin journal BEFORE the relay cache sees it, so the replay
//        path (cached_share -> bin) and the lane set both have it. Base: bin
//        0 in the cache (the replay path holds), `unbinned` names nothing.
//   R3-4 green pin: a receiver sharing [0, a0) with the finder (B) takes its
//        OWN order as the base (kOwn), no replay run.
//   R3-7 green pin: the lane digest at P2 is identical on every path (A own,
//        B own, C via the shadow); the composed order's push multiset equals
//        the finder's.
//   R3-8 held-node cost: a composition memo keyed by every input serves 100
//        retries from one composition; a cause change (new key) is one more;
//        the shell consults it before composing (source pin). Base: +1 per retry.
//   R3-9 source pins: the shell decides the suffix base through
//        decide_suffix_base with relay_view as the replay; one bin resolver
//        (ChainView, then the journal) on both paths; the base is named.
//
// RED on the base (8a7ed91b3), GREEN on the fix. Knobs (env): HR3_H (48),
// HR3_G (4), HR3_DIR, HR3_KEEP, HR3_VERBOSE.
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
#include <c2pool/v37/xmr/xmr_drops_wiring.hpp>
#include <c2pool/v37/v37_engine.hpp>
#include "impl/xmr/receipt/xmr_receipt_verify.hpp"

#ifndef V37_XMR_SHELL_SRC
#define V37_XMR_SHELL_SRC ""
#endif

using namespace gap2test;
using namespace std::chrono_literals;
namespace dx = ::c2pool::v37n::xmr::drops;

static constexpr u32 kChain = 7;
static constexpr u64 kShareDiff = 1000;

static u64 env_u64(const char* k, u64 d) { const char* v = std::getenv(k); return v && *v ? std::strtoull(v, nullptr, 10) : d; }
static bool verbose() { return std::getenv("HR3_VERBOSE") != nullptr; }
static std::string slurp(const std::string& p) { std::ifstream f(p, std::ios::binary); std::stringstream ss; ss << f.rdbuf(); return ss.str(); }
static std::string hex12(const bytes32& b) { return hex(b).substr(0, 12); }
static std::string key_of(u64 P, const bytes32& d) { return std::to_string(P) + ":" + hex(d); }

// Feature detection (the KAT builds on the base and fails there by value).
template <class O> static void set_deep(O& o, const std::string& base, u64 step) {
    if constexpr (requires { o.deep_order; o.deep_order_path; o.receipts_log_path; o.deep_probe_step; }) {
        o.deep_order = true; o.deep_order_path = base; o.receipts_log_path = base + ".receipts"; o.deep_probe_step = step;
    } else { (void)o; (void)base; (void)step; }
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

// One daemonless node: relay + durable ingest + lane engine + replayer + the
// origin-bin journal (main's drops_bin_journal, written at push time), and the
// node-local DROPS bookkeeping main keeps for a suffix repair: replay_base and
// the DROPS record keys ("P:digesthex"; a record's content is XmrDropsWiring's
// business, pinned by v37_xmr_drops_carry_suffix_kat -- here its EXISTENCE
// gates the base exactly as in main).
struct TNode {
    std::string name, dir;
    u64 H, G;
    ChainView chain;
    std::unique_ptr<c2pool::v37n::V37Engine> engine;
    std::unique_ptr<XmrRelayNode> relay;
    std::unique_ptr<XmrReceiptIngest> ingest;
    std::unique_ptr<RepairReplayer> rep;
    dx::LaneBinJournal journal;
    std::map<u64, bytes32> dig_at;
    std::vector<std::pair<::v37::ScriptRef, u64>> feed;
    std::vector<bytes32> order_ids;   // our own order, receipt by receipt (one push each: fee model off)
    u64 template_height = 0;
    std::size_t reloaded = 0, shadows_loaded = 0, journal_loaded = 0;
    // main's DROPS bookkeeping for suffix repairs
    struct ReplayBase { int base = 0; u64 a0 = 0; std::string shadow_key; };
    std::map<std::string, ReplayBase> replay_base;
    std::set<std::string> records;
    u64 replays_run = 0;

    TNode(std::string n, std::string d, u64 h, u64 g, RelayOptions ro, const std::vector<std::pair<bytes32, u64>>& bins, u64 tip = 0)
        : name(std::move(n)), dir(std::move(d)), H(h), G(g) {
        std::filesystem::create_directories(dir);
        const std::string base = dir + "/lane" + std::to_string(kChain);
        set_deep(ro, base, G);
        ro.vault.horizon_positions = H;
        for (const auto& [prev, hh] : bins) chain.note(prev, hh, bytes32{});
        chain.set_tip(tip ? tip : bins.back().second);
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
            [this](const std::string& l) { if (verbose()) std::printf("   [%s] %s\n", name.c_str(), l.c_str()); });
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
                order_ids.push_back(a.id);
                ::v37::xmr::verify::ParsedBlob pb;   // main: drops_bin_journal.note(pb.prev_id, a.bin) at push time
                if (a.bin && ::v37::xmr::verify::parse_hashing_blob(a.r.receipt.hashing_blob, pb)) journal.note(pb.prev_id, a.bin);
            });
        // main's boot order: the origin-bin journal, then set_bin_of (the ONE
        // resolver: ChainView, then the journal), then the receipts-log reload
        journal = dx::LaneBinJournal(io.durable_path + ".bins");
        journal_loaded = journal.load();
        ingest->set_bin_of([this](const FbReceipt& r) -> std::optional<u64> {
            ::v37::xmr::verify::ParsedBlob pb;
            if (!::v37::xmr::verify::parse_hashing_blob(r.receipt.hashing_blob, pb)) return std::nullopt;
            if (const auto c = chain.lookup(pb.prev_id)) return c->height;
            return journal.lookup(pb.prev_id);
        });
        reloaded = ingest->reload([this](const Admitted& a) { relay->note_reloaded(a); });
        shadows_loaded = shadow_setup(*rep, base + ".shadow", ro.lane_params_digest, G);
        if (shadows_loaded) relay->note_alt_digests(rep->shadow_digests());
    }
    ~TNode() { relay->stop(); engine->stop(); }
    void pump() { for (auto& a : relay->drain_admitted()) ingest->on_admitted(std::move(a)); ingest->tick(template_height); }
    u64 next_pos() { auto s = engine->snapshot(kChain); return s ? s->next_pos : 0; }
};

static RelayOptions opts(bool listen, std::vector<u16> dial) {
    RelayOptions o;
    o.network = 3; o.chain = kChain; o.share_diff = kShareDiff; o.bind = BindMode::None;
    o.lane_params_digest = lane_params_digest(::v37::LaneParams{}, kShareDiff, BindMode::None);
    o.listen = listen; o.listen_host = "127.0.0.1"; o.listen_port = 0;
    for (u16 p : dial) o.peers.emplace_back("127.0.0.1", p);
    o.reoffer_seconds = 60;
    o.hello_timeout_ms = 3000;
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

// The relay repair of a winner's cut (P, spine) on N, exactly like main's
// relay_view up to the replay: own when our digest at P is the spine; else
// repair_poll until Ready, then the served ids + repair_a0. The replay itself
// is left to the caller (main runs it from relay_view -- which, after F1, the
// DROPS prefix derivation may call first).
struct Served {
    bool own = false, ready = false;
    u64 P = 0, a0 = 0;
    std::optional<bytes32> peer_a0;
    std::vector<bytes32> ids;
    std::vector<std::pair<::v37::ScriptRef, u64>> pushes;
    std::string status;
};
static Served repair_served(TNode& N, const std::vector<TNode*>& all, u64 P, const bytes32& spine, std::chrono::milliseconds limit) {
    Served s; s.P = P;
    if (const auto d = N.relay->digest_at(P); d && *d == spine) { s.own = s.ready = true; return s; }
    const auto dl = std::chrono::steady_clock::now() + limit;
    while (std::chrono::steady_clock::now() < dl) {
        for (auto* n : all) n->pump();
        std::vector<bytes32> ids;
        const auto st = N.relay->repair_poll(P, spine, 0, &ids);
        if (st != XmrRelayNode::RepairState::Ready) { std::this_thread::sleep_for(5ms); continue; }
        s.a0 = N.relay->repair_a0(P, spine, &s.peer_a0);
        bool miss = false;
        std::vector<std::pair<::v37::ScriptRef, u64>> pushes;
        for (const auto& id : ids) {
            ::v37::ScriptRef ref;
            if (!N.relay->cached(id, &ref)) { miss = true; break; }
            pushes.emplace_back(ref, kReceiptWeight);
        }
        if (miss || s.a0 > N.feed.size()) { std::this_thread::sleep_for(5ms); continue; }
        s.ids = std::move(ids); s.pushes = std::move(pushes); s.ready = true;
        return s;
    }
    s.status = N.relay->repair_status(P, spine);
    return s;
}
// main's relay_view tail: the scratch replay through the RepairReplayer, and on
// success the bookkeeping drops_on_replay leaves (replay_base + the record of
// the whole cut, when the base's own record exists). `store_cut_record` = the
// shell's drops_merge succeeded (false models a record_miss).
static bool run_replay(TNode& N, const Served& s, const bytes32& spine, bool store_cut_record, std::string& why) {
    ++N.replays_run;
    RepairReplayer::Base used = RepairReplayer::kNone;
    std::pair<u64, bytes32> shadow_end{0, {}};
    auto view = N.rep->replay(kChain, ::v37::LaneParams{}, s.P, spine, s.a0, N.feed, s.pushes, &used, s.peer_a0,
                              s.a0 ? digest_deep(*N.relay, s.a0) : std::nullopt, &shadow_end);
    if (!view) { why = "the repaired order did not reproduce the winner's spine at P=" + std::to_string(s.P) + " from any base"; return false; }
    N.relay->note_alt_digests(N.rep->shadow_digests());
    const std::string pkey = key_of(s.P, spine);
    N.replay_base[pkey] = TNode::ReplayBase{static_cast<int>(used), s.a0,
                                            used == RepairReplayer::kShadow ? key_of(shadow_end.first, shadow_end.second) : std::string()};
    // drops_on_replay: the record of the whole cut, from our log (own / full) or the shadow's record
    bool base_ok = s.a0 == 0 || used == RepairReplayer::kOwn ||
                   (used == RepairReplayer::kShadow && N.records.count(N.replay_base[pkey].shadow_key));
    if (base_ok && store_cut_record) N.records.insert(pkey);
    return true;
}

#if defined(C2POOL_XMR_SUFFIX_BASE_NOW)
// main's drops_lane_prefix after F1: the base decided NOW, through the helper.
static dx::SuffixBaseDecision decide(TNode& N, const Served& s, const bytes32& spine, bool store_cut_record) {
    const std::string pkey = key_of(s.P, spine);
    dx::SuffixBaseQuery q;
    q.P = s.P; q.a0 = s.a0; q.peer_a0 = s.peer_a0; q.ours_a0 = s.a0 ? digest_deep(*N.relay, s.a0) : std::nullopt;
    q.cut_key = pkey;
    q.replay_base = [&](int& base, u64& a0, std::string& skey) {
        const auto it = N.replay_base.find(pkey);
        if (it == N.replay_base.end()) return false;
        base = it->second.base; a0 = it->second.a0; skey = it->second.shadow_key; return true;
    };
    q.run_replay = [&](std::string& w) { return run_replay(N, s, spine, store_cut_record, w); };
    q.cut_record = [&] { return N.records.count(pkey) != 0; };
    q.shadow_record = [&](const std::string& k) { return N.records.count(k) != 0; };
    q.shadow_with_digest = [&](u64 at, const bytes32& d) -> std::optional<std::string> {
        const auto m = N.rep->shadow_with_digest(at, d);
        if (!m) return std::nullopt;
        return key_of(m->first, m->second);
    };
    return dx::decide_suffix_base(q);
}
#else
// The BASE shell rule (8a7ed91b3 drops_lane_prefix): own digest at a0 == the
// peer's, or a replay_base entry a fold ALREADY left; the replay is never run
// from here. Rendered in the fix's vocabulary so the checks read the same.
struct BaseDecision { int kind = 0; bool replay_ran_now = false; bool exact = false; std::string shadow_key; };
static BaseDecision decide(TNode& N, const Served& s, const bytes32& spine, bool) {
    BaseDecision d;
    const std::string pkey = key_of(s.P, spine);
    const auto ours = s.a0 ? digest_deep(*N.relay, s.a0) : std::nullopt;
    if (s.a0 == 0 || (s.peer_a0 && ours && *ours == *s.peer_a0)) { d.kind = 1; d.exact = true; return d; }
    const auto it = N.replay_base.find(pkey);
    if (it != N.replay_base.end() && it->second.a0 == s.a0) {
        if (it->second.base == 2) { d.kind = 1; return d; }
        if (it->second.base == 3 && N.records.count(it->second.shadow_key)) { d.kind = 3; d.shadow_key = it->second.shadow_key; return d; }
    }
    return d;   // HOLD: "a0 digests differ; the settlement replay of this cut has not run"
}
#endif
static const char* kind_name(int k) { return k == 1 ? "own" : k == 2 ? "record" : k == 3 ? "shadow" : "HOLD"; }

static std::vector<std::vector<u8>> payload_multiset(const std::vector<std::pair<::v37::ScriptRef, u64>>& v, std::size_t n) {
    std::vector<std::vector<u8>> out;
    for (std::size_t i = 0; i < n && i < v.size(); ++i) out.push_back(v[i].first.payload);
    std::sort(out.begin(), out.end());
    return out;
}

int main() {
    Checker C;
    const u64 H = env_u64("HR3_H", 48), G = env_u64("HR3_G", 4);
    const char* rd = std::getenv("HR3_DIR");
    const std::string dir = (rd && *rd ? std::string(rd) : std::filesystem::temp_directory_path().string()) + "/hr3-kat-" + std::to_string(::getpid());
    std::filesystem::remove_all(dir);
    std::printf("== v37_xmr_hold_round3_kat (H=%llu G=%llu) ==\n", (unsigned long long)H, (unsigned long long)G);

    // ── R3-1 / R3-4 / R3-7: the attempt-8 shape on three nodes ─────────────
    {
        std::vector<std::pair<bytes32, u64>> bins;
        for (u64 h = 100; h < 140; ++h) bins.emplace_back(b32_of(static_cast<u8>(7 + h)), h);
        std::string why;
        auto A = std::make_unique<TNode>("A", dir + "/A", H, G, opts(true, {}), bins, 100);
        C(A->relay->start(why), "R3-1 A starts " + why);
        const u16 pA = A->relay->listen_port();
        auto B = std::make_unique<TNode>("B", dir + "/B", H, G, opts(true, {pA}), bins, 100);
        C(B->relay->start(why), "R3-1 B starts " + why);
        const u16 pB = B->relay->listen_port();
        auto Cn = std::make_unique<TNode>("C", dir + "/C", H, G, opts(false, {pA, pB}), bins, 100);
        C(Cn->relay->start(why), "R3-1 C starts " + why);
        std::vector<TNode*> all{A.get(), B.get(), Cn.get()};
        auto up3 = [&] { return A->relay->ready_peers().size() == 2 && B->relay->ready_peers().size() == 2 && Cn->relay->ready_peers().size() == 2; };
        bool ok = wait_for(up3, all);
        C(ok, "R3-1 A-B-C mesh up");
        const ::v37::ScriptRef pay[3] = {payee_of("A"), payee_of("B"), payee_of("C")};
        auto tmpl = [&](u64 h) { for (auto* n : all) { n->template_height = h; n->chain.set_tip(h); } };
        auto same_pos = [&](u64 want) { return wait_for([&] { for (auto* n : all) if (n->next_pos() != want) return false; return true; }, all, 25000ms); };
        auto mint = [&](TNode& W, u64 h, u32 salt, u32 n, const ::v37::ScriptRef& who, u32 nonce0) {
            const SynthBlock b = make_block(h, bins[h - 100].first, salt, nullptr, 2, static_cast<u8>(salt % 200 + 10));
            for (u32 k = 0; k < n; ++k) W.relay->submit_own(own(b, nonce0 + k, who));
        };
        // common prefix: bin 100, 4 receipts of A
        tmpl(100);
        mint(*A, 100, 11, 4, pay[0], 1000);
        ok &= wait_for([&] { for (auto* n : all) if (n->relay->cache_size() < 4) return false; return true; }, all);
        tmpl(101);
        ok &= same_pos(4);
        // the divergence window: C is partitioned while A mints 4 in bin 101 and C
        // mints 1 of its own; after the heal each side appends the other's late
        // (A, B: [p4, A4, C1]; C: [p4, C1, A4]) -- the attempt-8 strike window
        Cn->relay->partition_for(std::chrono::seconds(3));
        ok &= wait_for([&] { return Cn->relay->ready_peers().empty(); }, all, 8000ms);
        mint(*A, 101, 20, 4, pay[0], 2000);
        mint(*Cn, 101, 40, 1, pay[2], 3000);
        tmpl(102);
        ok &= wait_for([&] { return A->next_pos() == 8 && Cn->next_pos() == 5; }, all, 8000ms);
        ok &= same_pos(9);
        C(ok, "R3-1 two lineages at lane 9: A and B = [p4, A4, C1], C = [p4, C1, A4]");
        const u64 b_div = 9;   // the divergence window ends here (positions [4, 9) differ)
        // more receipts before h1, so that P1 > a0 later
        u64 lane = 9;
        for (u64 h = 102; h < 104; ++h) {
            mint(*A, h, static_cast<u32>(50 + h), 10, pay[0], static_cast<u32>(10000 + 100 * h));
            tmpl(h + 1);
            lane += 10;
            ok &= same_pos(lane);
        }
        const u64 P1 = A->next_pos();
        const bytes32 spine1 = A->dig_at[P1];
        C(ok && P1 == 29 && P1 < H, "R3-1 A finds h1 at P1=" + std::to_string(P1) + " < H (" + std::to_string(H) + ")");
        // B: its order IS A's -> own (R3-4's precondition); C: FULL repair -> a shadow + record of A's lineage
        const Served sB1 = repair_served(*B, all, P1, spine1, 20000ms);
        C(sB1.own, "R3-4 B's own digest at P1 is A's spine (B shares A's whole order): src=own, no repair");
        const Served sC1 = repair_served(*Cn, all, P1, spine1, 20000ms);
        C(sC1.ready && !sC1.own && sC1.a0 == 0 && sC1.ids.size() == P1, "R3-1 C repairs h1 from the WHOLE order (a0=0, " + std::to_string(sC1.ids.size()) + " ids) [" + sC1.status + "]");
        std::string rw;
        const bool c1 = sC1.ready && run_replay(*Cn, sC1, spine1, true, rw);
        const std::string shadow_key1 = key_of(P1, spine1);
        C(c1 && Cn->rep->shadows() == 1 && Cn->records.count(shadow_key1) == 1,
          "R3-1 C's replay of h1 reproduces the spine: shadow of A's lineage ending at P1 + its DROPS record (" + shadow_key1.substr(0, 16) + "...) " + rw);
        // the lane grows past H: a0 = P2 - H lands inside (b_div, P1)
        for (u64 h = 104; h < 108; ++h) {
            mint(*A, h, static_cast<u32>(50 + h), 10, pay[0], static_cast<u32>(10000 + 100 * h));
            tmpl(h + 1);
            lane += 10;
            ok &= same_pos(lane);
        }
        const u64 P2 = A->next_pos();
        const bytes32 spine2 = A->dig_at[P2];
        C(ok && P2 == 69 && P2 > H && P2 - H > b_div && P2 - H < P1,
          "R3-1 A finds h2 at P2=" + std::to_string(P2) + " > H: a0 = P2 - H = " + std::to_string(P2 - H) + " lies in (" + std::to_string(b_div) + ", " + std::to_string(P1) + ")");
        // B: own again (R3-4). C: the SUFFIX, the probe matched through the shadow.
        const Served sB2 = repair_served(*B, all, P2, spine2, 20000ms);
        C(sB2.own, "R3-4 B at P2: own digest == spine (src=own)");
        const Served sC2 = repair_served(*Cn, all, P2, spine2, 30000ms);
        const auto ours_a0 = sC2.a0 ? digest_deep(*Cn->relay, sC2.a0) : std::nullopt;
        C(sC2.ready && !sC2.own && sC2.a0 > b_div && sC2.a0 < P1 && sC2.peer_a0 && sC2.ids.size() == P2 - sC2.a0,
          "R3-1 C's relay serves the SUFFIX [" + std::to_string(sC2.a0) + "," + std::to_string(P2) + ") with the peer's digest at a0 [" + sC2.status + "]");
        C(sC2.peer_a0 && ours_a0 && *ours_a0 != *sC2.peer_a0,
          "R3-1 C's OWN digest at a0 differs from the peer's (ours " + (ours_a0 ? hex12(*ours_a0) : "none") + " peer " +
              (sC2.peer_a0 ? hex12(*sC2.peer_a0) : "none") + "): our [0,a0) is not the base");
        C(sC2.peer_a0 && Cn->relay->alt_digest_is(sC2.a0, *sC2.peer_a0),
          "R3-1 the relay's prefix probe matched the peer's digest at a0 through C's SHADOW of A's lineage (alt_digest_is)");
#if defined(C2POOL_XMR_SHADOW_WITH_DIGEST)
        const auto named = sC2.peer_a0 ? Cn->rep->shadow_with_digest(sC2.a0, *sC2.peer_a0) : std::nullopt;
        C(named && named->first == P1 && named->second == spine1,
          "R3-1 the replayer NAMES the shadow the probe matched: P_end=" + std::to_string(named ? named->first : 0) + " (= P1) digest " +
              (named ? hex12(named->second) : "none") + " (= h1's spine)");
#else
        C(false, "R3-1 the base cannot name which shadow the probe matched (no shadow_with_digest)");
#endif
        // THE DECISION, in main's order: the DROPS prefix derivation runs BEFORE the
        // fold, so no settlement replay of this cut has run yet (replay_base empty).
        C(Cn->replay_base.count(key_of(P2, spine2)) == 0 && Cn->replays_run == 1,
          "R3-1 precondition: the WON frame is booked before any fold ran the replay of h2 (replay_base has no entry for P2)");
        const auto d1 = decide(*Cn, sC2, spine2, /*store_cut_record=*/true);
        C(d1.kind != 0,
          std::string("R3-1 ★ C's DROPS prefix base at a0 is DECIDED, not held: ") + kind_name(d1.kind) +
              " (8a7ed91b3: HOLD 'a0 digests differ; the settlement replay of this cut has not run', every retry, forever)");
        C(d1.replay_ran_now && Cn->replays_run == 2 && Cn->replay_base.count(key_of(P2, spine2)) == 1 &&
              Cn->replay_base[key_of(P2, spine2)].base == static_cast<int>(RepairReplayer::kShadow) &&
              Cn->replay_base[key_of(P2, spine2)].shadow_key == shadow_key1,
          "R3-1 the settlement replay was RUN NOW, once, and stood on the shadow of A's lineage (base=shadow " + shadow_key1.substr(0, 16) + "...)");
        C(d1.kind == 2 && d1.exact, "R3-1 the base is the record of the whole cut the replay just left (src=record), exact at a0");
        // the same decision again (the next retry): nothing re-run
        const auto d1b = decide(*Cn, sC2, spine2, true);
        C(d1b.kind == 2 && !d1b.replay_ran_now && Cn->replays_run == 2, "R3-1 a retry decides from the cached replay: no second replay (idempotent)");
        // variant: the replay ran (the pre-fold path: the WON frame after the fold's replay)
        // but drops_on_replay left no record of the whole cut (a record_miss) -> the base
        // is the SHADOW's DROPS record, accepted because a shadow (the one the replay just
        // adopted for this cut, superseding the h1 shadow it extended) holds EXACTLY the
        // peer's digest at a0; no second replay run
        {
            TNode& N = *Cn;
            N.records.erase(key_of(P2, spine2));
            const u64 runs = N.replays_run;
            const auto d2 = decide(N, sC2, spine2, /*store_cut_record=*/false);
            C(d2.kind == 3 && d2.exact && d2.shadow_key == shadow_key1 && !d2.replay_ran_now && N.replays_run == runs,
              std::string("R3-1 mirror (WON after the pre-fold replay, no cut record): the base is the SHADOW's DROPS record (src=shadow ") +
                  d2.shadow_key.substr(0, 16) + "...), exact at a0, no replay re-run (8a7ed91b3: the same path; pins the pre-fold route)");
            N.records.insert(key_of(P2, spine2));
        }
        // base-less: a node that never reconstructed A's lineage (no shadow) and whose own order differs: HOLD, the replay's reason named
        {
            auto fresh = std::make_unique<RepairReplayer>(2 * H);   // C's replayer without its shadows
            std::swap(Cn->rep, fresh);
            Cn->replay_base.erase(key_of(P2, spine2)); Cn->records.erase(key_of(P2, spine2));
            const auto d4 = decide(*Cn, sC2, spine2, true);
#if defined(C2POOL_XMR_SUFFIX_BASE_NOW)
            const std::string t = dx::suffix_hold_why(d4.cause);
            C(d4.kind == 0 && d4.replay_ran_now && t.rfind("cut-pending: ", 0) == 0 && t.find("run now and did not verify a base") != std::string::npos &&
                  t.find("[replay now: ") != std::string::npos && t.find("a0 digests differ") != std::string::npos,
              "R3-1 no shadow of the finder's lineage: HOLD, the cause names the replay run now and its reason -- " + t);
#else
            C(d4.kind == 0, "R3-1 no shadow: HOLD (base and fix agree a suffix is never composed without a verified [0,a0))");
#endif
            std::swap(Cn->rep, fresh);
        }
        // R3-7: the lane digest at P2 is the SAME on every path, and the composed order's pushes are the finder's
        {
            const auto sd = Cn->rep->shadow_digests();
            bool c_has = false;
            for (auto [p, d] : sd) if (p == P2 && d == spine2) c_has = true;
            const auto bd = B->dig_at.count(P2) ? B->dig_at[P2] : bytes32{};
            C(c_has && bd == spine2, "R3-7 lane_digest at P2 identical on every path: A own, B own, C via the shadow (" + hex12(spine2) + ")");
            // C's composed order = shadow[0, a0) + served [a0, P2): its push multiset == A's feed[0, P2)
            std::vector<std::pair<::v37::ScriptRef, u64>> composed;
            // the shadow's pushes are A's order [0, P1): use A's feed for [0, a0) (the shadow reproduced it) + the served suffix
            for (u64 i = 0; i < sC2.a0; ++i) composed.push_back(A->feed[i]);
            for (const auto& p : sC2.pushes) composed.push_back(p);
            C(payload_multiset(composed, P2) == payload_multiset(A->feed, P2) && composed.size() == P2,
              "R3-7 the composed order's push multiset over [0,P2) equals the finder's (the DROPS prefix is the same multiset on every node)");
        }
        for (auto* n : all) n->relay->set_dialing(false);
    }

    // ── R3-2: B's shape -- a side-block parent, a restart, the journalled bin ──
    {
        std::vector<std::pair<bytes32, u64>> bins;
        for (u64 h = 100; h < 110; ++h) bins.emplace_back(b32_of(static_cast<u8>(170 + h)), h);
        const bytes32 X = b32_of(0xE5);   // the side block at height 104 (same height as the kept bins[4])
        std::vector<std::pair<bytes32, u64>> bins_live = bins;
        bins_live.emplace_back(X, 105);   // a template built on X is at height 105 (prev X -> bin 105)
        std::string why;
        const std::string bdir = dir + "/B2";
        bytes32 id_x{}, id_m{};
        {
            auto B2 = std::make_unique<TNode>("B2", bdir, H, G, opts(true, {}), bins_live, 105);
            C(B2->relay->start(why), "R3-2 B2 starts (ChainView knows the side block X) " + why);
            std::vector<TNode*> one{B2.get()};
            B2->template_height = 104;
            const SynthBlock bm = make_block(104, bins[4].first, 71, nullptr, 2, 61);   // main-chain parent (ChainView: bin 104)
            const SynthBlock bx = make_block(105, X, 72, nullptr, 2, 62);               // the side block X as parent
            const Admitted am = own(bm, 500, payee_of("B")), ax = own(bx, 501, payee_of("B"));
            id_m = am.id; id_x = ax.id;
            B2->relay->submit_own(am);
            B2->relay->submit_own(ax);
            B2->template_height = 106; B2->chain.set_tip(106);
            wait_for([&] { return B2->next_pos() == 2; }, one, 8000ms);
            ::v37::ScriptRef py; u64 bn = 0; std::vector<u8> raw;
            const bool live_ok = B2->relay->cached_share(id_x, py, bn, raw) && bn == 105 && B2->journal.lookup(X) && *B2->journal.lookup(X) == 105;
            C(live_ok && B2->next_pos() == 2, "R3-2 live: both receipts pushed; the side-block receipt's bin 105 is in the cache and in the origin-bin journal");
            B2->relay->set_dialing(false);
        }
        // the restart: X is ORPHANED and gone from a ChainView rebuilt from main-chain headers
        auto B2 = std::make_unique<TNode>("B2", bdir, H, G, opts(true, {}), bins, 106);
        C(B2->relay->start(why), "R3-2 B2 restarts on its durable files; the ChainView lacks X " + why);
        ::v37::ScriptRef py; u64 bn_x = ~u64{0}, bn_m = ~u64{0}; std::vector<u8> raw;
        const bool cx = B2->relay->cached_share(id_x, py, bn_x, raw);
        const bool cm = B2->relay->cached_share(id_m, py, bn_m, raw);
        C(B2->reloaded == 2 && B2->journal_loaded >= 1 && !B2->chain.lookup(X) && cx && cm,
          "R3-2 reload: 2 receipts, the journal restored (" + std::to_string(B2->journal_loaded) + " bins), X unknown to the ChainView");
        C(bn_m == 104, "R3-2 the main-chain receipt's bin resolves from the ChainView after the reload (" + std::to_string(bn_m) + ")");
        C(bn_x == 105,
          "R3-2 ★ the side-block receipt's bin is 105 in the relay cache after the reload -- the journalled bin survived (8a7ed91b3: 0 -> "
          "'the origin bin of a repaired receipt is not resolvable yet', forever)");
        const auto ls = B2->ingest->lane_set(106);
        C(ls.unbinned == 0 && ls.n == 2, "R3-2 the lane set has no unbinned receipt after the reload (n=" + std::to_string(ls.n) + ")");
#if defined(C2POOL_XMR_RELOAD_BIN_RESOLVE)
        C(B2->ingest->stats().reload_binned == 2 && ls.unbinned_ids.empty(),
          "R3-2 the ingest resolved both bins AT reload (reload_binned=" + std::to_string(B2->ingest->stats().reload_binned) + "); the status line lists no unbinned id");
        {   // the listing itself: an unresolvable receipt is NAMED (4.10)
            XmrReceiptIngest::Options io; io.chain = kChain; io.order = XmrReceiptIngest::Order::Arrival;
            XmrReceiptIngest lone(io, [](const ::v37::ScriptRef&, u64, u64& na, bytes32&) { ++na; return true; }, {});
            lone.set_bin_of([](const FbReceipt&) -> std::optional<u64> { return std::nullopt; });
            const SynthBlock bz = make_block(107, b32_of(0xE6), 73, nullptr, 2, 63);
            Admitted az = own(bz, 502, payee_of("B")); az.bin = 0;
            lone.on_admitted(az);
            const auto l2 = lone.lane_set(107);
            C(l2.unbinned == 1 && l2.unbinned_ids.size() == 1 && l2.unbinned_ids[0] == az.id,
              "R3-2 an unresolved receipt is listed by id on the lane-set line (" + hex12(az.id) + ")");
        }
#else
        C(false, "R3-2 the base ingest does not resolve bins at reload and lists no unbinned ids");
#endif
        B2->relay->set_dialing(false);
    }

    // ── R3-8: the held-node cost -- one composition per cause, not per retry ──
    std::printf("R3-8: a held node's composition is served from the memo\n");
    {
#if defined(C2POOL_XMR_COMPOSE_MEMO)
        dx::ComposeMemo<int> memo(8);
        const std::string k1 = dx::ComposeMemo<int>::key_of("bid-1", 2451, b32_of(0x3c), "set-a", 600000000000ull, "1.0.0.0v", 77);
        u64 composed = 0;
        for (int retry = 0; retry < 100; ++retry) {
            int out = 0;
            if (memo.get(k1, out)) continue;   // the shell: `if (drops_compose_memo.get(memo_key, out)) return true;`
            ++composed; out = 42;
            memo.put(k1, out);
        }
        C(composed == 1 && memo.hits() == 99 && memo.puts() == 1, "R3-8 100 retries of one held block: composed=1, memo hits=99 (8a7ed91b3: composed=481 on node B, +1 per retry)");
        const std::string k2 = dx::ComposeMemo<int>::key_of("bid-1", 2451, b32_of(0x3c), "set-b", 600000000000ull, "1.0.0.0v", 77);
        const std::string k3 = dx::ComposeMemo<int>::key_of("bid-1", 2451, b32_of(0x3c), "set-a", 600000000000ull, "1.0.0.0v", 78);
        int o = 0;
        C(k2 != k1 && k3 != k1 && !memo.get(k2, o) && !memo.get(k3, o), "R3-8 a changed pinned set or booking-ledger state is a new key: composed again (<= 1 per cause change)");
        for (int i = 0; i < 20; ++i) memo.put("k" + std::to_string(i), i);
        C(memo.size() <= 8 && !memo.get(k1, o), "R3-8 the memo is bounded (8 entries, oldest out: size=" + std::to_string(memo.size()) + ")");
#else
        C(false, "R3-8 no composition memo on the base: the DROPS composition re-runs on every booking retry");
#endif
    }

    // ── R3-9: source pins (the shell wires F1 / F2 / R3-8) ────────────────────
    std::printf("R3-9: source pins (main_v37_xmr.cpp)\n");
    {
        const std::string sh = slurp(V37_XMR_SHELL_SRC);
        C(!sh.empty(), "R3-9 shell source readable");
        C(sh.find("const auto dec = c2pool::v37n::xmr::drops::decide_suffix_base(q);") != std::string::npos &&
              sh.find("return relay_view(P, cc.spine_digest, hint, w) != nullptr;") != std::string::npos &&
              sh.find("relay_replayer.shadow_with_digest(at, d)") != std::string::npos,
          "R3-9 F1: drops_lane_prefix decides the suffix base through decide_suffix_base, with relay_view as the replay run NOW and the replayer naming the shadow");
        C(sh.find("drops-prefix base: P=%llu") != std::string::npos && sh.find("exact_a0_match=%s replay_ran_now=%s") != std::string::npos &&
              sh.find("pushes of the SHADOW P_end=") != std::string::npos,
          "R3-9 4.10: the shell names which base the probe matched (own vs shadow P_end:digest), on the prefix line and the replay line");
        C(sh.find("auto bin_of_prev = [&](const ::v37::bytes32& prev_id)") != std::string::npos &&
              sh.find("return bin_of_prev(prev_id);   // F2: the journal fallback on the replay path too") != std::string::npos &&
              sh.find("return bin_of_prev(pb.prev_id);") != std::string::npos,
          "R3-9 F2: ONE origin-bin resolver (ChainView, then the journal) behind composed_bin_of_prev, drops_bin_of and the reload's set_bin_of");
        C(sh.find("unknown to the chain view and the origin-bin journal)") != std::string::npos && sh.find("ls.unbinned_ids") != std::string::npos,
          "R3-9 4.10: the origin-bin holds name the receipt and its parent; the lane-set line lists the unbinned ids");
        C(sh.find("if (drops_compose_memo.get(memo_key, out)) {") != std::string::npos &&
              sh.find("if (!memo_key.empty()) drops_compose_memo.put(memo_key, out);") != std::string::npos,
          "R3-9 R3-8: drops_compose_lane consults the composition memo before composing and stores the finished composition");
    }

    if (!std::getenv("HR3_KEEP")) std::filesystem::remove_all(dir);
    return C.done("v37_xmr_hold_round3_kat");
}
