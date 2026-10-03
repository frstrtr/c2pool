// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// v37_xmr_drops_harden_kat -- DROPS-HARDEN (adversarial verify of
// DROPS-SET-PIN, flip 1): the four residual defects d1-d4.
//
//   DH1  d1 BOUNDED ASKS: an unservable pinned set asked for every few ms for
//        3 s costs at most drops_fetch_max_asks fast asks per id plus one slow
//        re-ask per drops_fetch_slow_ms (base: one ask per retry, forever).
//        Once the members become servable they arrive, and the ask state of
//        a completed set is empty (base: kept for 10 minutes of silence);
//        drops_pin_forget() drops the ask state of a block that left the
//        pending set.
//   DH2  d3 FIRST SET WINS: a second, conflicting set-carrying FB_BLOCK_WON
//        for a bid never overwrites the held set (base: the LAST one did);
//        the block's first announcer's set replaces a non-announcer's once;
//        our own win never adopts a foreign set; every receiver keeps the
//        winner's set whatever the injection order after the winner's frame.
//   DH3  d4 PERSISTED STORE: a relay's raindrop store survives a restart
//        (lane<N>.drops, tmp+fsync+rename, sha256d trailer, versioned),
//        reloads into the harvest queue, and a restarted winner serves its
//        own members to a peer that never held them; a torn / foreign file
//        is ignored; the file is bounded by drops_retain_bins.
//        (DROPS-RETAIN: per-bin segments lane<N>.drops.d/<bin>.seg; a torn
//        record ends its own segment only; another lane's segments ignored.)
//   DH4  d2 + shell source pins: wire_cache is pruned (settled / orphaned
//        bids + a byte cap), relay_on_cut uses the first-set-wins verdict and
//        logs set-equivocation, own and journalled sets are final, the store
//        is persisted per lane next to lane<N>.shadow.
//
// RED on the base (d4d6d4b0), GREEN on the fix.
#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <map>
#include <optional>
#include <unistd.h>
#include <set>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include "xmr_relay_test_util.hpp"
#include <c2pool/v37/xmr/relay/xmr_relay_node.hpp>
#include <c2pool/v37/xmr/xmr_drops_wiring.hpp>

#ifndef V37_XMR_SHELL_SRC
#define V37_XMR_SHELL_SRC ""
#endif

using namespace gap2test;
using namespace std::chrono_literals;
namespace dx = ::c2pool::v37n::xmr::drops;

static constexpr u32 kChain = 7;
static constexpr u64 kRelayShareDiff = 1000;
static constexpr u64 kFloorDiff = 10;
static constexpr std::uint32_t kDropNonce = 0x40000000u;

static std::string slurp(const std::string& p) {
    std::ifstream f(p, std::ios::binary);
    std::stringstream ss; ss << f.rdbuf(); return ss.str();
}
struct RNode {
    ChainView chain;
    std::atomic<u64> rx_calls{0};
    std::unique_ptr<XmrRelayNode> relay;
    std::vector<bytes32> drained;
    explicit RNode(RelayOptions ro) {
        relay = std::make_unique<XmrRelayNode>(
            ro, chain,
            [this](const std::vector<u8>& blob, const bytes32&, bytes32& pow) {
                ++rx_calls;
                u32 nonce = 0;
                ::v37::xmr::HashingBlob hb; hb.bytes = blob;
                ::v37::xmr::verify::ParsedBlob pb;
                if (::v37::xmr::verify::parse_hashing_blob(hb, pb))
                    for (int i = 0; i < 4; ++i) nonce |= static_cast<u32>(blob[pb.header_len - 4 + i]) << (8 * i);
                pow.fill(0);
                if (nonce >= kDropNonce) pow[31] = 0x02;
                return true;
            },
            []() -> std::pair<u64, bytes32> { return {0, bytes32{}}; },
            [](const std::string&) {});
    }
    ~RNode() { relay->stop(); }
    void note_bin(const bytes32& prev, u64 height) { chain.note(prev, height, bytes32{}); chain.set_tip(height); }
    void pump() { for (auto& a : relay->drain_drops()) drained.push_back(a.id); }
};
static RelayOptions ropts(bool listen, std::vector<u16> dial) {
    RelayOptions o;
    o.network = 3; o.chain = kChain; o.share_diff = kRelayShareDiff; o.bind = BindMode::None;
    o.lane_params_digest = lane_params_digest(::v37::LaneParams{}, kRelayShareDiff, BindMode::None);
    o.listen = listen; o.listen_host = "127.0.0.1"; o.listen_port = 0;
    for (u16 p : dial) o.peers.emplace_back("127.0.0.1", p);
    o.hello_timeout_ms = 3000;
    o.drops_floor_diff = kFloorDiff;
    o.drops_hello_bins = 0;   // no inventory pull: only what a test asks for moves
    o.drops_fetch_retry_ms = 50;
    o.drops_fetch_max_asks = 8;
#if defined(C2POOL_XMR_DROPS_HARDEN)
    o.drops_fetch_slow_ms = 1000;
#endif
    return o;
}
template <class F>
static bool wait_for(F cond, std::vector<RNode*> pump, std::chrono::milliseconds limit = 15000ms) {
    const auto dl = std::chrono::steady_clock::now() + limit;
    while (std::chrono::steady_clock::now() < dl) {
        for (auto* n : pump) n->pump();
        if (cond()) return true;
        std::this_thread::sleep_for(10ms);
    }
    for (auto* n : pump) n->pump();
    return cond();
}
static Admitted drop_on(const SynthBlock& sb, std::uint32_t nonce, const ::v37::ScriptRef& payee) {
    Admitted a; std::string why;
    if (!mint_on(sb, nonce, payee, kChain, kRelayShareDiff, a.r, &why)) std::printf("    mint failed: %s\n", why.c_str());
    a.id = receipt_id(a.r); a.raw = encode_fb_receipt(a.r); a.bin = sb.height; a.own = true;
    a.pow.fill(0); a.pow[31] = 0x02;
    return a;
}
// 8 bins 100..107 on a chain view, and `n` raindrops per bin in bins [b0, b1)
struct Bins {
    std::vector<bytes32> prev;
    Bins() { for (int i = 0; i < 8; ++i) prev.push_back(b32_of(static_cast<u8>(100 + i))); }
    void note(RNode& n) const { for (int i = 0; i < 8; ++i) n.note_bin(prev[i], 100 + static_cast<u64>(i)); }
    std::vector<Admitted> drops(int b0, int b1, int n, const ::v37::ScriptRef& payee, std::uint32_t salt) const {
        std::vector<Admitted> v;
        for (int b = b0; b < b1; ++b) {
            const SynthBlock blk = make_block(100 + static_cast<u64>(b), prev[static_cast<std::size_t>(b)], 1 + static_cast<u32>(b), nullptr, 3, 10 + static_cast<u32>(b));
            for (int k = 0; k < n; ++k) v.push_back(drop_on(blk, kDropNonce + salt + 16 * static_cast<u32>(b) + static_cast<u32>(k), payee));
        }
        return v;
    }
};
static std::vector<bytes32> ids_of(const std::vector<Admitted>& v) {
    std::vector<bytes32> r; for (const auto& a : v) r.push_back(a.id); std::sort(r.begin(), r.end()); return r;
}

int main() {
    Checker C;
    std::printf("== v37_xmr_drops_harden_kat (%s) ==\n",
#if defined(C2POOL_XMR_DROPS_HARDEN)
                "fix tree: C2POOL_XMR_DROPS_HARDEN");
#else
                "BASE tree: unbounded pinned asks, last set wins, in-memory store (d4d6d4b0)");
#endif
    const Bins bins;
    std::string why;

    // ── DH1 d1: an unservable pinned set, asked for every 5 ms for 3 s ───────
    // M1 measurement mode: V37_DH1_SECS=120 V37_DH1_PROD=1 = the shipped retry (2000 ms) and slow (60000 ms)
    const long dh1_secs = std::getenv("V37_DH1_SECS") ? std::atol(std::getenv("V37_DH1_SECS")) : 3;
    const bool dh1_prod = std::getenv("V37_DH1_PROD") != nullptr;
    const u32 dh1_retry = dh1_prod ? 2000 : 50, dh1_slow = dh1_prod ? 60000 : 1000;
    std::printf("DH1: bounded asks for an unservable pinned set held %ld s (retry %u ms, max_asks 8, slow %u ms)\n", dh1_secs, dh1_retry, dh1_slow);
    {
        RNode A(ropts(true, {}));
        bins.note(A);
        C(A.relay->start(why), "DH1 A starts " + why);
        auto ob = ropts(true, {A.relay->listen_port()});
        ob.drops_fetch_retry_ms = dh1_retry;
#if defined(C2POOL_XMR_DROPS_HARDEN)
        ob.drops_fetch_slow_ms = dh1_slow;
#endif
        RNode B(ob);
        bins.note(B);
        C(B.relay->start(why), "DH1 B dials A " + why);
        C(wait_for([&] { return A.relay->ready_peers().size() == 1 && B.relay->ready_peers().size() == 1; }, {&A, &B}), "DH1 HELLO: A-B up");
        const auto held_back = bins.drops(0, 1, 5, payee_of("W"), 0);   // the winner's members: nobody serves them yet
        const auto pin = ids_of(held_back);
        const auto t0 = std::chrono::steady_clock::now();
        while (std::chrono::steady_clock::now() - t0 < std::chrono::seconds(dh1_secs)) {
            B.relay->drops_fetch_ids(pin, 0, 100, 101);
            B.pump();
            std::this_thread::sleep_for(5ms);
        }
        const u64 asked = B.relay->stats().drops_ids_asked.load();
        const u64 frames = B.relay->stats().drops_fetch_tx.load();
        const u64 rx = A.relay->stats().drops_fetchreq_rx.load();
        const std::size_t f0 = encode_getdrops(kChain, 100, 101, {}).size();   // a by-id GETDROPS = this + 32 B per id
        const u64 bytes = frames * f0 + asked * 32;
        std::printf("    M1 %ld s unservable (%zu ids, 1 peer): GETDROPS ids asked=%llu frames=%llu bytes=%llu (A received %llu) = %.1f asks per id per peer; pin_asked=%zu\n",
                    dh1_secs, pin.size(), (unsigned long long)asked, (unsigned long long)frames, (unsigned long long)bytes, (unsigned long long)rx,
                    static_cast<double>(asked) / static_cast<double>(pin.size()), B.relay->drops_pin_asked());
        // bound: 8 fast asks + one slow re-ask per slow period (+1 for the phase)
        const u64 bound = 8 + static_cast<u64>(dh1_secs) * 1000 / dh1_slow + 1;
        C(asked <= pin.size() * bound, "DH1 asks per id per peer <= drops_fetch_max_asks + slow re-asks (<= " + std::to_string(bound) +
          "; base: one per retry, " + std::to_string(dh1_secs * 1000 / dh1_retry) + ")");
#if defined(C2POOL_XMR_DROPS_HARDEN)
        C(B.relay->stats().drops_pin_capped.load() == pin.size() && B.relay->stats().drops_pin_slow_asks.load() >= pin.size(),
          "DH1 every id reached the cap, then was re-asked at the slow rate (counted)");
#else
        C(false, "DH1 no cap / slow re-ask counters on the base");
#endif
        // the members become servable: the slow re-ask fetches them; a complete set leaves no ask state
        for (auto a : held_back) A.relay->submit_own_drop(a);
        const bool got = wait_for([&] {
            std::set<bytes32> d(B.drained.begin(), B.drained.end());
            std::vector<bytes32> miss;
            for (const auto& x : pin) if (!d.count(x)) miss.push_back(x);
            B.relay->drops_fetch_ids(miss, 0, 100, 101);
            return miss.empty();
        }, {&A, &B}, std::chrono::milliseconds(dh1_slow + 4000));
        C(got, "DH1 once A holds the members all 5 arrive (flood or slow re-ask)");
        std::printf("    after completion: pin_asked=%zu\n", B.relay->drops_pin_asked());
        C(B.relay->drops_pin_asked() == 0, "DH1 the ask state of a completed set is empty (base: kept until 10 min of silence)");
#if defined(C2POOL_XMR_DROPS_HARDEN)
        const auto gone = ids_of(bins.drops(1, 2, 3, payee_of("Z"), 0));   // a block that leaves the pending set unserved
        B.relay->drops_fetch_ids(gone, 0, 101, 102);
        const std::size_t before = B.relay->drops_pin_asked();
        B.relay->drops_pin_forget(gone);
        C(before == 3 && B.relay->drops_pin_asked() == 0, "DH1 drops_pin_forget drops the ask state of a block that left the pending set");
#else
        C(false, "DH1 no drops_pin_forget on the base");
#endif
    }

    // ── DH2 d3: a second, conflicting set-carrying frame for the same bid ─────
    std::printf("DH2: first set wins (the winner's), a non-winner's conflicting set never overwrites it\n");
    {
        const auto W = ids_of(bins.drops(2, 3, 4, payee_of("W"), 0));   // the winner's pinned set
        std::vector<bytes32> X = W; X.pop_back();                          // injected: one member dropped
        const auto Xa = ids_of(bins.drops(2, 3, 1, payee_of("X"), 7));    // ... and one of the attacker's own added
        X.insert(X.end(), Xa.begin(), Xa.end()); std::sort(X.begin(), X.end());
        const std::uint64_t pW = 11, pX = 22, pY = 33;   // relay peer ids: W = the winner (announces first)
        struct Held { std::optional<std::vector<bytes32>> set; std::uint64_t from = 0; bool locked = false; std::size_t equiv = 0; };
        // the shell's relay_on_cut rule for a set-carrying frame
        auto rx = [&](Held& h, const std::vector<bytes32>& in, std::uint64_t from, std::uint64_t announcer, bool own) {
#if defined(C2POOL_XMR_DROPS_SET_FIRST_WINS)
            const auto v = dx::set_frame_verdict(h.set ? &*h.set : nullptr, h.from, h.locked, in, from, announcer, own);
            if (v == dx::SetFrameVerdict::Adopt || v == dx::SetFrameVerdict::AnnouncerReplaces) {
                h.set = in; h.from = from; h.locked = v == dx::SetFrameVerdict::AnnouncerReplaces;
            }
            if (v == dx::SetFrameVerdict::KeepFirst || v == dx::SetFrameVerdict::AnnouncerReplaces) ++h.equiv;
            return v;
#else
            (void)announcer; (void)own;   // BASE (d4d6d4b0): the LAST set-carrying frame overwrites (relay_on_cut)
            h.set = in; h.from = from;
            return 0;
#endif
        };
        // R1: the winner's frame (fresh flood), then the injected one (a solicited FB_GETWON answer)
        Held r1; rx(r1, W, pW, pW, false); rx(r1, X, pX, pW, false);
        C(r1.set && *r1.set == W, "DH2 R1 keeps the winner's FIRST set after an injected second set (base: books the injected set -> split)");
        C(r1.equiv == 1, "DH2 R1 counts the conflicting later frame as a set-equivocation");
        // R2: the injected set races ahead through a non-announcer; the announcer's set replaces it ONCE
        Held r2; rx(r2, X, pX, pW, false); rx(r2, W, pW, pW, false); rx(r2, X, pY, pW, false);
        C(r2.set && *r2.set == W, "DH2 R2: the block's first announcer's set replaces a non-announcer's, and is then final");
        C(r2.equiv == 2, "DH2 R2 logs both conflicts");
        // the same set again (a forward / re-offer) is not an equivocation
        Held r3; rx(r3, W, pW, pW, false); rx(r3, W, pY, pW, false);
        C(r3.set && *r3.set == W && r3.equiv == 0, "DH2 an identical set from another peer is no equivocation");
        // our own win: a foreign set is never adopted, ours is final
        Held own; rx(own, X, pX, pX, true);
        C(!own.set, "DH2 our own win never adopts a foreign set (we compose and pin it)");
        Held own2; own2.set = W; own2.locked = true; rx(own2, X, pX, pX, true);
        C(own2.set && *own2.set == W && own2.equiv == 1, "DH2 our own pinned set stands against a conflicting frame");
        // a booked / journalled set is final even against the announcer
        Held bk; bk.set = X; bk.from = pX; bk.locked = true; rx(bk, W, pW, pW, false);
        C(bk.set && *bk.set == X, "DH2 a locked (booked / journalled) set is never replaced");
        // every honest receiver ends on the winner's set whatever the injection order after the winner's frame
        bool all = true;
        for (int order = 0; order < 4; ++order) {
            Held h; rx(h, W, pW, pW, false);
            for (int k = 0; k < order; ++k) rx(h, (k % 2) ? W : X, (k % 2) ? pY : pX, pW, false);
            all = all && h.set && *h.set == W;
        }
        C(all, "DH2 every receiver books the winner's first set for every later injection order (owed digests equal)");
#if defined(C2POOL_XMR_DROPS_SET_FIRST_WINS)
        C(dx::XmrDropsWiring::set_digest(100, W[0], W) != dx::XmrDropsWiring::set_digest(100, W[0], X),
          "DH2 the two sets have different set digests (both logged by the shell)");
#else
        C(false, "DH2 no set_frame_verdict on the base");
#endif
    }

    // ── DH3 d4: the raindrop store survives a restart of the winner ──────────
    std::printf("DH3: persisted raindrop store (lane<N>.drops): a restarted winner serves its own pinned members\n");
#if defined(C2POOL_XMR_DROPS_HARDEN)
    {
        const std::string dir = std::filesystem::temp_directory_path().string() + "/v37_drops_harden_kat." + std::to_string(::getpid());
        std::filesystem::create_directories(dir);
        const std::string path = dir + "/lane7.drops";
        const auto mine = bins.drops(3, 5, 3, payee_of("W"), 0);   // the winner's 6 raindrops (bins 103, 104)
        const auto pin = ids_of(mine);
        {
            auto o = ropts(true, {}); o.drops_persist_path = path;
            RNode W(o); bins.note(W);
            C(W.relay->start(why), "DH3 W starts " + why);
            for (auto a : mine) W.relay->submit_own_drop(a);
            C(wait_for([&] { return W.relay->stats().drops_persist_writes.load() >= 1; }, {&W}, 5000ms),
              "DH3 the changed store is snapshotted by the maint thread (<= drops_persist_ms)");
        }   // W stops (a final snapshot) = the winner restarts
#if defined(C2POOL_XMR_DROPS_RETAIN)   // DROPS-RETAIN: per-bin append-only segments under lane<N>.drops.d
        C(std::filesystem::exists(path + ".d/103.seg") && std::filesystem::exists(path + ".d/104.seg") && !std::filesystem::exists(path),
          "DH3 lane<N>.drops.d/<bin>.seg written (one segment per bin; DROPS-RETAIN)");
#else
        C(std::filesystem::exists(path) && !std::filesystem::exists(path + ".tmp"), "DH3 lane<N>.drops written via tmp + rename");
#endif
        auto o = ropts(true, {}); o.drops_persist_path = path;
        RNode W2(o); bins.note(W2);
        const std::size_t n = W2.relay->drops_load(&why);
        C(n == 6 && W2.relay->drops_held(100, 108) == pin, "DH3 the restarted winner reloads exactly its 6 raindrops " + why);
        W2.pump();
        auto dr = W2.drained; std::sort(dr.begin(), dr.end());
        C(dr == pin,
          "DH3 the reloaded raindrops are queued for the harvest (drain_drops), as before the restart");
        C(W2.relay->start(why), "DH3 W2 starts " + why);
        RNode R(ropts(true, {W2.relay->listen_port()})); bins.note(R);   // a peer that never held them
        C(R.relay->start(why), "DH3 R dials the restarted winner " + why);
        C(wait_for([&] { return R.relay->ready_peers().size() == 1; }, {&R, &W2}), "DH3 HELLO: R-W2 up");
        const bool got = wait_for([&] {
            std::set<bytes32> d(R.drained.begin(), R.drained.end());
            std::vector<bytes32> miss;
            for (const auto& x : pin) if (!d.count(x)) miss.push_back(x);
            R.relay->drops_fetch_ids(miss, 0, 103, 105);
            return miss.empty();
        }, {&R, &W2}, 8000ms);
        C(got && W2.relay->stats().drops_served.load() >= pin.size(), "DH3 the restarted winner serves every pinned member by id (base: store=0 -> HOLD forever)");
        // the winner's OWN harvest asking for a member its store holds: served locally, no peer asked
        {
            auto o3 = ropts(true, {}); o3.drops_persist_path = path;
            RNode W3(o3); bins.note(W3);
            W3.relay->drops_load(&why);
            W3.drained.clear(); (void)W3.relay->drain_drops();
            W3.relay->drops_fetch_ids({pin[0]}, 0, 103, 105);
            W3.pump();
            C(W3.drained.size() == 1 && W3.drained[0] == pin[0] && W3.relay->stats().drops_pin_local.load() == 1 &&
              W3.relay->stats().drops_ids_asked.load() == 0, "DH3 a member in the node's own store is handed to its harvest locally (no peer asked)");
        }
        // torn / foreign files are ignored (an empty store, loud)
#if defined(C2POOL_XMR_DROPS_RETAIN)
        {   // DROPS-RETAIN: a torn record ends ITS segment only (the valid prefix + every other bin load)
            std::filesystem::copy(path + ".d", dir + "/torn.drops.d");
            const std::string seg = dir + "/torn.drops.d/103.seg";
            std::string b = slurp(seg); b[b.size() / 2] ^= 0x01;
            std::ofstream(seg, std::ios::binary | std::ios::trunc) << b;
            auto ot = ropts(true, {}); ot.drops_persist_path = dir + "/torn.drops";
            RNode T(ot);
            const std::size_t nt = T.relay->drops_load(&why);
            C(nt >= 3 && nt < 6 && T.relay->stats().drops_seg_torn.load() == 1 && T.relay->drops_held(104, 105).size() == 3,
              "DH3 a torn segment keeps its valid prefix, the other bin loads whole: loaded=" + std::to_string(nt) + " " + why);
            auto of = ropts(true, {}); of.drops_persist_path = path; of.chain = kChain + 1;
            RNode F(of);
            const std::size_t nf = F.relay->drops_load(&why);
            C(nf == 0 && why.find("ignored=2") != std::string::npos, "DH3 another lane's segments are ignored: " + why);
        }
#else
        {
            std::string b = slurp(path); b[b.size() / 2] ^= 0x01;
            std::ofstream(dir + "/torn.drops", std::ios::binary) << b;
            auto ot = ropts(true, {}); ot.drops_persist_path = dir + "/torn.drops";
            RNode T(ot);
            const std::size_t nt = T.relay->drops_load(&why);
            C(nt == 0 && why.find("trailer hash mismatch") != std::string::npos, "DH3 a torn file is ignored: " + why);
            auto of = ropts(true, {}); of.drops_persist_path = path; of.chain = kChain + 1;
            RNode F(of);
            const std::size_t nf = F.relay->drops_load(&why);
            C(nf == 0 && why.find("another lane") != std::string::npos, "DH3 another lane's file is ignored: " + why);
        }
#endif
        // bounded by drops_retain_bins: tip 107, retain 2 -> only bins >= 105 are kept (and persisted)
        {
            const std::string pb = dir + "/bounded.drops";
            auto ob = ropts(true, {}); ob.drops_persist_path = pb; ob.drops_retain_bins = 2;
            {
                RNode Bd(ob); bins.note(Bd);
                C(Bd.relay->start(why), "DH3 bounded node starts " + why);
                for (auto a : bins.drops(0, 3, 2, payee_of("B"), 0)) Bd.relay->submit_own_drop(a);   // bins 100-102: below the window
                for (auto a : bins.drops(6, 7, 2, payee_of("B"), 0)) Bd.relay->submit_own_drop(a);   // bin 106: inside
            }
            RNode Bl(ob);
            const std::size_t nb = Bl.relay->drops_load(&why);
            C(nb == 2 && Bl.relay->drops_held(100, 106).empty(), "DH3 the file holds only the retained window (bin 106: 2 raindrops) " + why);
        }
        std::error_code ec; std::filesystem::remove_all(dir, ec);
    }
#else
    C(false, "DH3 no persisted raindrop store on the base: a restarted winner holds store=0 and cannot serve its pinned members");
#endif

    // ── DH4 d2 + the shell's wiring (source pins) ─────────────────────────────
    std::printf("DH4: source pins -- wire_cache pruned, first set wins in relay_on_cut, the store persisted per lane\n");
    {
        const std::string sh = slurp(V37_XMR_SHELL_SRC);
        C(!sh.empty(), std::string("DH4 the shell source is readable: ") + V37_XMR_SHELL_SRC);
        auto has = [&](const char* s) { return sh.find(s) != std::string::npos; };
        C(has("auto wire_cache_prune = [&]()") && has("if (it->second.d.h_b + cfg.d_conf < cur) { ++wire_cache_evicted; it = forget(it); continue; }"),
          "DH4 d2: wire_cache evicts every bid the finalize cursor passed by D_conf (booked or orphaned)");
        C(has("kWireCacheMaxBytes") && has("if (total > kWireCacheMaxBytes)") && has("if (!own_won.count(b) && !drops_early.count(b)) byh.emplace_back(w.d.h_b, b);"),
          "DH4 d2: wire_cache is capped by bytes (highest heights first, never our own wins)");
        C(has("wire_cache_prune();   // ★ DROPS-HARDEN (d2)"), "DH4 d2: the prune runs on the relay tick");
        C(has("relay_node->drops_pin_forget(*it->second.drops_set)"), "DH4 d1: an evicted (settled / orphaned) set's ask state is dropped");
        C(has("if (relay_node && !ids.empty()) relay_node->drops_pin_forget(ids);"), "DH4 d1: a composed (complete) set's ask state is dropped");
        C(has("c2pool::v37n::xmr::drops::set_frame_verdict(") && has("drops-ALARM set-equivocation:"),
          "DH4 d3: relay_on_cut keeps the first set by set_frame_verdict and logs set-equivocation with both digests");
        C(has("wc.drops_from = 0; wc.drops_locked = true;   // ★ DROPS-HARDEN (d3): our own pin is final") &&
          has("wc.drops_locked = true;          // ★ DROPS-HARDEN (d3): journalled"),
          "DH4 d3: our own pinned set and journalled sets are final");
        C(has("\"/lane\" + std::to_string(cfg.lane_chain) + \".drops\"") && has("relay_node->drops_load(&dw)"),
          "DH4 d4: the relay store is persisted as <settle_db>/lane<N>.drops and reloaded before the relay starts");
        C(has("\"--drops-retain-bins\"") && has("\"--drops-store-persist\""), "DH4 d4: --drops-retain-bins / --drops-store-persist knobs");
    }
    return C.done("v37_xmr_drops_harden_kat");
}
