// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// v37_xmr_relay_repair_ctx_kat -- the GAP-2 relay-repair defect (rc4adv relay
// rig: node C stuck at cursor 15 on "relay repair of P=173 ... in flight",
// repair ready=0 while rx unresolved grew by exactly the missing-receipt count;
// rc4-gap2 rig: node A booking_stall_timeout -> REFUSED honest h=36,37,38 ->
// owed_digest mismatch at ledger_seq 67).
//
// ROOT CAUSE pinned here: the winner-side order holds receipts MINED ON A
// MONERO BLOCK THE REPAIRING NODE NEVER SAW (an orphaned sibling from a
// same-height race; Monero does not relay alternative blocks). Their prev_id
// resolves in no ChainView on the repairing node, so the verify worker parked
// and then dropped every fetched copy "unresolved" -- the repair re-asked the
// same frames forever and never became Ready.
//
// Three in-process XmrRelayNode instances over REAL loopback TCP, full mesh
// (B dials A; C dials A and B). A and B know the orphan X (they served
// templates on it); C does not. RandomX is a counting fake (PoW 0).
//
//   K1  FB_GETCTX / FB_CTX codec: round trip, bounds, total decoders
//   K2  verify_block_ctx: the served blob must hash to the id asked for (a
//       different block, a tampered tx hash, a wrong id are all refused); the
//       height is the coinbase txin_gen height, the parent is the header prev
//   K3  THE DEFECT, reproduced: with no peer able to serve X's context, C's
//       repair of A's cut is NEVER Ready, the fetched receipts are dropped
//       "unresolved", and repair_status names the stuck stage (the loud reason)
//   K4  bounded retries: an unservable context is asked of every ready peer
//       per round and GIVEN UP after ctx_max_rounds (then re-added by the
//       repair's refetch), never an unbounded loop; "unknown here" answers fail
//       over to the next peer at once
//   K5  reconnect: C drops off and redials while the repair is stuck; the
//       repair keeps its state and re-asks the new connections
//   K6  THE FIX: once A's monerod holds X, C's want is answered by A (B, the
//       frames' source, answers "unknown" first -> failover), the context is
//       verified + parent-linked, the dropped receipts are RE-FETCHED (repair
//       refetch, the order is kept), admitted, and the repair is Ready; a
//       scratch replay reproduces A's spine byte-for-byte
//   K7  a two-deep orphan chain (X2 on X1, both unknown to C): resolved
//       recursively (X2's proof waits for X1's), repair Ready
//   K8  a lying context: a block whose coinbase claims a height its (known)
//       parent does not have is REJECTED (ctx bad), never noted, and the repair
//       that needs it stays Pending with the reason
#include <atomic>
#include <chrono>
#include <cstdlib>
#include <map>
#include <thread>

#include "xmr_relay_test_util.hpp"
#include <c2pool/v37/xmr/relay/xmr_relay_node.hpp>
#include <c2pool/v37/xmr/relay/xmr_receipt_ingest.hpp>
#include <c2pool/v37/v37_engine.hpp>

using namespace gap2test;
using namespace std::chrono_literals;

static constexpr u32 kChain = 7;
static constexpr u64 kShareDiff = 1000;

static bytes32 block_id(const SynthBlock& sb) {   // keccak256(varint(len) | hashing_blob): monerod get_block_hash
    std::vector<u8> pre;
    put_varint(pre, sb.hashing_blob.size());
    pre.insert(pre.end(), sb.hashing_blob.begin(), sb.hashing_blob.end());
    const auto h = ::xmr::coin::keccak256(pre.data(), pre.size());
    bytes32 b; std::memcpy(b.data(), h.data(), 32); return b;
}

struct TNode {
    std::string name;
    ChainView chain;
    std::atomic<u64> rx_calls{0};
    std::unique_ptr<c2pool::v37n::V37Engine> engine;
    std::unique_ptr<XmrRelayNode> relay;
    std::unique_ptr<XmrReceiptIngest> ingest;
    u64 template_height = 0;
    std::map<bytes32, std::vector<u8>> monerod;   // what this node's monerod can serve by id (main blocks + alternatives)
    std::mutex dmtx;
    std::vector<std::string> logs;
    std::mutex log_mtx;

    TNode(std::string n, RelayOptions ro) : name(std::move(n)) {
        engine = std::make_unique<c2pool::v37n::V37Engine>(4096);
        engine->start();
        engine->submit_tracked(::v37::LaneRecord::add_lane(kChain, ::v37::LaneParams{})).get();
        relay = std::make_unique<XmrRelayNode>(
            ro, chain,
            [this](const std::vector<u8>&, const bytes32&, bytes32& pow) { ++rx_calls; pow.fill(0); return true; },
            [this]() -> std::pair<u64, bytes32> {
                auto s = engine->snapshot(kChain);
                if (!s) return {0, bytes32{}};
                return {s->next_pos, s->digest};
            },
            [this](const std::string& l) { std::lock_guard<std::mutex> lk(log_mtx); logs.push_back(l); });
        XmrReceiptIngest::Options io; io.chain = kChain; io.order = XmrReceiptIngest::Order::Canonical; io.bin_lag = 1; io.grace_ms = 0;
        ingest = std::make_unique<XmrReceiptIngest>(
            io,
            [this](const ::v37::ScriptRef& payee, u64 w, u64& next_after, bytes32& dig) {
                ::v37::PayoutDescriptor d; d.pay = payee;
                if (!engine->submit_tracked(::v37::LaneRecord::push(kChain, d, w, 0)).get().applied()) return false;
                auto s = engine->snapshot(kChain);
                next_after = s->next_pos; dig = s->digest;
                return true;
            },
            [this](const Admitted& a, u64 pos, u32 n_pushes, u64 next_after, const bytes32& dig) {
                relay->on_pushed(a.id, pos, n_pushes, a.raw, next_after, dig);
            });
    }
    ~TNode() { relay->stop(); engine->stop(); }
    void note_bin(const bytes32& prev, u64 height) { chain.note(prev, height, bytes32{}); chain.set_tip(height); }
    // the daemon's main-thread duties for the relay (main_v37_xmr.cpp relay_tick)
    void pump() {
        {
            std::lock_guard<std::mutex> lk(dmtx);
            for (const auto& id : relay->ctx_wants_local()) {
                auto it = monerod.find(id);
                if (it != monerod.end()) relay->offer_ctx(id, it->second, 0);
            }
            for (const auto& [pid, ids] : relay->drain_ctx_requests())
                for (const auto& id : ids) {
                    auto it = monerod.find(id);
                    relay->send_ctx(pid, id, it == monerod.end() ? std::vector<u8>{} : it->second);
                }
        }
        for (auto& a : relay->drain_admitted()) ingest->on_admitted(std::move(a));
        ingest->tick(template_height);
    }
    void monerod_add(const SynthBlock& sb) { std::lock_guard<std::mutex> lk(dmtx); monerod[block_id(sb)] = sb.full_blob; }
    u64 next_pos() { auto s = engine->snapshot(kChain); return s ? s->next_pos : 0; }
    bytes32 digest() { auto s = engine->snapshot(kChain); return s ? s->digest : bytes32{}; }
    std::string grep_logs(const std::string& needle) {
        std::lock_guard<std::mutex> lk(log_mtx);
        for (const auto& l : logs) if (l.find(needle) != std::string::npos) return l;
        return "";
    }
    void dump_logs() { std::lock_guard<std::mutex> lk(log_mtx); for (auto& l : logs) std::printf("    [%s] %s\n", name.c_str(), l.c_str()); logs.clear(); }
};

static RelayOptions opts(bool listen, std::vector<u16> dial) {
    RelayOptions o;
    o.network = 3; o.chain = kChain; o.share_diff = kShareDiff; o.bind = BindMode::None;
    o.lane_params_digest = lane_params_digest(::v37::LaneParams{}, kShareDiff, BindMode::None);
    o.listen = listen; o.listen_host = "127.0.0.1"; o.listen_port = 0;
    for (u16 p : dial) o.peers.emplace_back("127.0.0.1", p);
    o.hello_timeout_ms = 3000;
    // fast clocks for the KAT (the daemon keeps the production defaults)
    o.unresolved_patience_ms = 800;
    o.solicited_unresolved_patience_ms = 2500;
    o.ctx_retry_ms = 250;
    o.ctx_max_rounds = 4;
    o.repair_refetch_ms = 600;
    o.repair_state_timeout_ms = 4000;
    return o;
}

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

static Admitted own(const SynthBlock& sb, std::uint32_t nonce, const ::v37::ScriptRef& payee, u64 bin) {
    Admitted a; std::string why;
    if (!mint_on(sb, nonce, payee, kChain, kShareDiff, a.r, &why)) std::printf("    mint failed: %s\n", why.c_str());
    a.id = receipt_id(a.r); a.raw = encode_fb_receipt(a.r); a.bin = bin; a.own = true;
    return a;
}

static PeerId peer_by_port(XmrRelayNode& n, u16 port) {
    for (PeerId p : n.ready_peers()) { auto h = n.remote_hello(p); if (h && h->listen_port == port) return p; }
    return 0;
}

// Scratch-replay the Ready order and require the winner's digest at P.
static bool replay_matches(XmrRelayNode& n, const std::vector<bytes32>& ids, u64 P, const bytes32& spine) {
    c2pool::v37n::V37Engine scratch; scratch.start();
    scratch.submit_tracked(::v37::LaneRecord::add_lane(kChain, ::v37::LaneParams{})).get();
    for (const auto& id : ids) {
        ::v37::ScriptRef ref;
        if (!n.cached(id, &ref)) { scratch.stop(); return false; }
        ::v37::PayoutDescriptor d; d.pay = ref;
        scratch.submit_tracked(::v37::LaneRecord::push(kChain, d, kReceiptWeight, 0)).get();
    }
    bool mism = false;
    auto view = scratch.settlement_view_by_cut(kChain, P, spine, &mism);
    scratch.stop();
    return view != nullptr;
}

int main() {
    Checker C;
    std::printf("== v37_xmr_relay_repair_ctx_kat ==\n");
    const ::v37::ScriptRef pA = payee_of("A"), pB = payee_of("B");

    // ── the Monero chain ────────────────────────────────────────────────────
    // G (h=99) is a main block every node knows (children of G are at bin 100).
    // X (h=100, on G) is the ORPHAN: A's and B's monerods had it as their tip,
    // C's never saw it. Y (h=100, on G) is the sibling that won.
    const SynthBlock G  = make_block(99,  b32_of(5), 90, nullptr, 2, 60);
    const bytes32 idG = block_id(G);
    const SynthBlock X  = make_block(100, idG, 91, nullptr, 3, 61);
    const SynthBlock Y  = make_block(100, idG, 92, nullptr, 1, 62);
    const bytes32 idX = block_id(X), idY = block_id(Y);

    // ── K1 codec ────────────────────────────────────────────────────────────
    {
        std::vector<bytes32> ids{idX, idY};
        const auto f = encode_getctx(kChain, ids);
        u32 ch = 0; std::vector<bytes32> back; std::string why;
        C(f.size() == 7 + 64 && f[0] == FB_GETCTX && decode_getctx(f, ch, back, &why) && ch == kChain && back == ids,
          "K1 GETCTX round trip (0x43, 2 ids)");
        std::vector<bytes32> nine(9, idX);
        C(encode_getctx(kChain, nine).empty() && encode_getctx(kChain, {}).empty(), "K1 GETCTX refuses 0 or > 8 ids");
        auto g2 = f; g2.push_back(0);
        { const bool r = decode_getctx(g2, ch, back, &why); C(!r, "K1 GETCTX trailing byte refused: " + why); }
        const auto c = encode_ctx(kChain, idX, X.full_blob);
        bytes32 cid{}; std::vector<u8> blob;
        C(c[0] == FB_CTX && decode_ctx(c, ch, cid, blob, &why) && cid == idX && blob == X.full_blob, "K1 CTX round trip (0x44, one block blob)");
        const auto u = encode_ctx(kChain, idX, {});
        C(decode_ctx(u, ch, cid, blob, &why) && blob.empty(), "K1 CTX len 0 = unknown here");
        auto c2 = c; c2.pop_back();
        { const bool r = decode_ctx(c2, ch, cid, blob, &why); C(!r, "K1 CTX short body refused: " + why); }
        C(encode_ctx(kChain, idX, std::vector<u8>(kCtxMaxBlob + 1, 0)).empty(), "K1 CTX refuses a blob over 512 KiB");
        C(is_family_b_opcode(FB_GETCTX) && is_family_b_opcode(FB_CTX), "K1 0x43/0x44 are in the Family-B range (an older node counts + keeps the socket)");
    }

    // ── K2 verify_block_ctx ─────────────────────────────────────────────────
    {
        BlockCtx bc; std::string why;
        C(verify_block_ctx(idX, X.full_blob, bc, &why) && bc.id == idX && bc.parent == idG && bc.height == 100,
          "K2 X's blob verifies: id recomputed, parent = G, height 100 from the coinbase");
        { const bool r = verify_block_ctx(idX, Y.full_blob, bc, &why); C(!r, "K2 a DIFFERENT block for the id asked is refused: " + why); }
        auto t = X.full_blob; t[t.size() - 1] ^= 1;   // a tx hash
        { const bool r = verify_block_ctx(idX, t, bc, &why); C(!r, "K2 a tampered tx hash is refused (tree_root -> id): " + why); }
        auto t2 = X.full_blob; t2.resize(t2.size() - 5);
        { const bool r = verify_block_ctx(idX, t2, bc, &why); C(!r, "K2 a truncated blob is refused: " + why); }
        bytes32 wrong = idX; wrong[3] ^= 0x10;
        C(!verify_block_ctx(wrong, X.full_blob, bc, &why), "K2 the right blob for a WRONG id is refused");
    }

    // ── the network ─────────────────────────────────────────────────────────
    TNode A("A", opts(true, {}));
    std::string why;
    C(A.relay->start(why), "A starts " + why);
    const u16 portA = A.relay->listen_port();
    TNode B("B", opts(true, {portA}));
    C(B.relay->start(why), "B starts, dials A " + why);
    const u16 portB = B.relay->listen_port();
    TNode Cn("C", opts(true, {portA, portB}));
    C(Cn.relay->start(why), "C starts, dials A and B " + why);
    std::vector<TNode*> all{&A, &B, &Cn};
    C(wait_for([&] { return A.relay->ready_peers().size() == 2 && B.relay->ready_peers().size() == 2 && Cn.relay->ready_peers().size() == 2; }, all),
      "full mesh up");

    // chain views: everyone knows G (bin 100) and Y (bin 101); A and B also X (bin 101)
    for (auto* n : all) { n->note_bin(idG, 100); n->note_bin(idY, 101); n->template_height = 100; }
    A.note_bin(idX, 101); B.note_bin(idX, 101);

    // receipts: 3 on G (everyone verifies), 4 on X (only A and B can)
    const SynthBlock onG = make_block(100, idG, 11, nullptr, 2, 70);
    const SynthBlock onX = make_block(101, idX, 12, nullptr, 2, 71);
    for (std::uint32_t k = 0; k < 3; ++k) A.relay->submit_own(own(onG, 100 + k, pA, 100));
    for (std::uint32_t k = 0; k < 4; ++k) A.relay->submit_own(own(onX, 200 + k, pA, 101));
    C(wait_for([&] { return A.relay->cache_size() == 7 && B.relay->cache_size() == 7 && Cn.relay->cache_size() == 3; }, all),
      "flood: A and B admit all 7; C admits only the 3 on G (the 4 on X have an unknown prev_id)");
    C(wait_for([&] { return Cn.relay->stats().unresolved_dropped.load() >= 4; }, all, 5000ms),
      "C dropped the 4 X-receipts as unresolved (the rig's 'rx unresolved' counter)");
    for (auto* n : all) n->template_height = 103;
    C(wait_for([&] { return A.next_pos() == 7 && B.next_pos() == 7 && Cn.next_pos() == 3; }, all), "lanes: A=7 B=7 C=3");
    C(A.digest() == B.digest(), "A and B (canonical) agree on the spine");
    const u64 P = 7;
    const bytes32 spineA = A.digest();

    // ── K3 the defect: nobody can serve X's context ─────────────────────────
    const PeerId cB = peer_by_port(*Cn.relay, portB);
    std::vector<bytes32> ids;
    XmrRelayNode::RepairState st = XmrRelayNode::RepairState::Pending;
    const bool early = wait_for([&] { st = Cn.relay->repair_poll(P, spineA, cB, &ids); return st == XmrRelayNode::RepairState::Ready; }, all, 6000ms);
    C(!early && st != XmrRelayNode::RepairState::Ready, "K3 with X's context unservable the repair is NEVER Ready (the stuck node)");
    C(Cn.relay->stats().repair_order_ok.load() >= 1, "K3 the winner-side ORDER did arrive (the order was never the problem)");
    C(Cn.relay->stats().unresolved_solicited_dropped.load() >= 1, "K3 the fetched (solicited) X-receipts were dropped 'unresolved' too");
    const std::string st3 = Cn.relay->repair_status(P, spineA);
    std::printf("    repair_status: %s\n", st3.c_str());
    C(st3.find("fetching") != std::string::npos && st3.find("unresolved") != std::string::npos,
      "K3 repair_status names the stuck stage (fetching, receipts missing, Monero context unresolved)");

    // ── K4 bounded retries + failover ───────────────────────────────────────
    C(Cn.relay->stats().ctx_asked.load() >= 2 && Cn.relay->stats().ctx_unknown_rx.load() >= 2,
      "K4 C asked BOTH peers for X's context and both answered 'unknown here' (failover, not a wait)");
    C(wait_for([&] { Cn.relay->repair_poll(P, spineA, cB, nullptr); return Cn.relay->stats().ctx_gave_up.load() >= 1; }, all, 10000ms),
      "K4 the unservable want was GIVEN UP after ctx_max_rounds (bounded), with a log line");
    C(wait_for([&] { Cn.relay->repair_poll(P, spineA, cB, nullptr); return Cn.relay->stats().repair_refetch.load() >= 2 && Cn.relay->ctx_wants_open() >= 1; }, all, 10000ms),
      "K4 ...and re-added by the repair's REFETCH of the dropped frames (the order is kept)");

    // ── K5 reconnect while stuck ────────────────────────────────────────────
    const u64 hello0 = Cn.relay->stats().hello_ok.load();
    Cn.relay->set_dialing(false);
    C(wait_for([&] { return Cn.relay->ready_peers().empty(); }, all, 5000ms), "K5 C dropped off the network mid-repair");
    Cn.relay->set_dialing(true);
    C(wait_for([&] { return Cn.relay->ready_peers().size() == 2 && Cn.relay->stats().hello_ok.load() >= hello0 + 2; }, all, 15000ms),
      "K5 C redialed both peers");

    // ── K6 the fix: A's monerod holds X (as an alternative block) ───────────
    A.monerod_add(G); A.monerod_add(X); A.monerod_add(Y);
    B.monerod_add(G); B.monerod_add(Y);   // B's monerod reorged away from X: it serves "unknown"
    const u64 res0 = Cn.relay->stats().ctx_resolved.load();
    const bool ok6 = wait_for([&] { st = Cn.relay->repair_poll(P, spineA, cB, &ids); return st == XmrRelayNode::RepairState::Ready; }, all, 30000ms);
    C(ok6 && ids.size() == P, "K6 the repair of (P=7, A's spine) is Ready: " + std::to_string(ids.size()) + " ids");
    C(Cn.relay->stats().ctx_resolved.load() > res0 && Cn.relay->stats().ctx_bad.load() == 0,
      "K6 X's context was resolved from A's blob (verified + parent-linked), no bad proof");
    const auto rl = Cn.grep_logs("RESOLVED: block " + hex(idX).substr(0, 12));
    C(!rl.empty(), "K6 the resolution is logged: " + rl);
    C(A.relay->stats().ctx_served.load() >= 1, "K6 A served the block blob (its monerod had it)");
    C(Cn.chain.lookup(idX) && Cn.chain.lookup(idX)->height == 101, "K6 C's ChainView now holds X at bin 101 (the minter's bin)");
    C(replay_matches(*Cn.relay, ids, P, spineA), "K6 a scratch replay of the repaired order reproduces A's spine byte-for-byte");

    // ── K7 a two-deep orphan chain ──────────────────────────────────────────
    {
        const SynthBlock X1 = make_block(100, idG, 93, nullptr, 1, 63);
        const bytes32 idX1 = block_id(X1);
        const SynthBlock X2 = make_block(101, idX1, 94, nullptr, 2, 64);
        const bytes32 idX2 = block_id(X2);
        A.note_bin(idX1, 101); A.note_bin(idX2, 102); B.note_bin(idX1, 101); B.note_bin(idX2, 102);
        A.monerod_add(X1); A.monerod_add(X2);
        const SynthBlock onX2 = make_block(102, idX2, 13, nullptr, 1, 72);
        for (std::uint32_t k = 0; k < 3; ++k) A.relay->submit_own(own(onX2, 300 + k, pB, 102));
        for (auto* n : all) n->template_height = 104;
        C(wait_for([&] { return A.next_pos() == 10 && B.next_pos() == 10; }, all), "K7 A and B push 3 receipts mined on X2 (X2 on X1, both orphans)");
        const u64 P7 = 10; const bytes32 spine7 = A.digest();
        const u64 r0 = Cn.relay->stats().ctx_resolved.load();
        std::vector<bytes32> ids7;
        const bool ok7 = wait_for([&] { return Cn.relay->repair_poll(P7, spine7, 0, &ids7) == XmrRelayNode::RepairState::Ready; }, all, 30000ms);
        C(ok7 && ids7.size() == P7, "K7 repair of (P=10) Ready across a TWO-deep unknown ancestry");
        C(Cn.relay->stats().ctx_resolved.load() >= r0 + 2, "K7 both X2 and its parent X1 were resolved (recursive, parent first)");
        C(replay_matches(*Cn.relay, ids7, P7, spine7), "K7 replay reproduces A's spine at P=10");
    }

    // ── K8 a lying context ──────────────────────────────────────────────────
    {
        // Z's coinbase claims height 105 but its parent G is at bin 100 on every
        // node: a context that would re-bin receipts. A (the minter) believes it.
        const SynthBlock Z = make_block(105, idG, 95, nullptr, 1, 65);
        const bytes32 idZ = block_id(Z);
        A.note_bin(idZ, 106); B.note_bin(idZ, 106);
        A.monerod_add(Z);
        const SynthBlock onZ = make_block(106, idZ, 14, nullptr, 1, 73);
        A.relay->submit_own(own(onZ, 400, pA, 106));
        for (auto* n : all) n->template_height = 108;
        C(wait_for([&] { return A.next_pos() == 11 && B.next_pos() == 11; }, all), "K8 A and B push 1 receipt mined on Z");
        const u64 P8 = 11; const bytes32 spine8 = A.digest();
        const u64 bad0 = Cn.relay->stats().ctx_bad.load();
        const bool ok8 = wait_for([&] { return Cn.relay->repair_poll(P8, spine8, 0, nullptr) == XmrRelayNode::RepairState::Ready; }, all, 6000ms);
        C(!ok8 && Cn.relay->stats().ctx_bad.load() > bad0, "K8 Z's context is REJECTED (height 105 vs parent bin 100) and the repair stays Pending");
        C(!Cn.chain.lookup(idZ), "K8 Z never entered C's ChainView");
        const auto zl = Cn.grep_logs("REJECTED: block claims height 105");
        C(!zl.empty(), "K8 logged: " + zl);
    }

    for (auto* n : all) n->dump_logs();
    std::printf("    A %s\n    B %s\n    C %s\n", A.relay->describe().c_str(), B.relay->describe().c_str(), Cn.relay->describe().c_str());
    return C.done("v37_xmr_relay_repair_ctx_kat");
}
