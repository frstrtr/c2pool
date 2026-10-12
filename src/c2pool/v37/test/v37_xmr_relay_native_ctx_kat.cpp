// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// v37_xmr_relay_native_ctx_kat -- a Monero context (the block a template built
// on) is resolvable from the embedded native node on the Path B relay node:
// FB_GETCTX / FB_CTX served from and fed into the native index, judged by
// work.
//
// Three in-process Path B relay nodes over real loopback TCP, each with its own
// PathbNode; each has a FAKE native chain index (best-chain rows + retained
// bodies + held alternatives) bound as the relay's context source
// (PathbCtxSource: the bodies it serves, the chain index a served block is
// judged against, the follower a usable block goes into). RandomX of a context
// block is a counting model.
//
//   N1  C (best chain G, H1, H2 and an ALTERNATIVE body X) needs the contexts of
//       G, H1 and X: G and H1 are held by C's native index (used with no hash);
//       X resolves from C's OWN native body (verified + judged against its
//       parent G in C's index); no peer is asked; every want is cleared
//   N2  FB_GETCTX served NATIVELY: a block W only A's native node holds. C asks
//       its peers; A answers from its native body; C verifies it, judges its
//       work against its parent in C's own index, and feeds it into its
//       follower
//   N3  the context RandomX throws once at C (a node-internal failure): a
//       local alarm, no strike, no ban; the want kept and judged again:
//       resolved
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <map>
#include <mutex>
#include <set>
#include <stdexcept>
#include <thread>

#include "xmr_pathb_relay_test_util.hpp"

using namespace pathb_relay_test;
using namespace std::chrono_literals;

// A native chain index as the relay sees it: best-chain rows, retained bodies
// (connected blocks + held alternatives).
struct FakeIndex {
    std::mutex m;
    std::map<u64, bytes32> rows;
    std::map<bytes32, std::vector<u8>> bodies;
    std::atomic<u64> blob_calls{0};
    void main(const SynthBlock& sb) { std::lock_guard<std::mutex> lk(m); rows[sb.height] = block_id(sb); bodies[block_id(sb)] = sb.full_blob; }
    void alt(const SynthBlock& sb)  { std::lock_guard<std::mutex> lk(m); bodies[block_id(sb)] = sb.full_blob; }
};

struct TNode {
    FakeIndex idx;
    std::unique_ptr<RNode> n;
    std::mutex amtx;
    std::set<bytes32> accepted;                 // blocks fed into the follower
    std::map<std::vector<u8>, u64> hashed;      // context RandomX calls by hashing blob
    std::atomic<u64> ctx_rx{0};
    std::atomic<int> rx_throw{0};               // the next context RandomX calls that throw

    TNode(Rig& rig, std::string name, pb::PathbRelayOptions o) {
        n = rig.make(std::move(name), std::move(o));
        pb::PathbCtxSource s;
        s.block_blob = [this](const pb::Hash32& id, std::vector<u8>& out) {
            ++idx.blob_calls;
            std::lock_guard<std::mutex> lk(idx.m);
            const auto it = idx.bodies.find(id);
            if (it == idx.bodies.end()) return false;
            out = it->second;
            return true;
        };
        // The WORK behind a context is judged against this node's own (fake)
        // index: best-chain rows are held verified; a block above them needs
        // proof of work at a model difficulty of 2, which the zero-hash model
        // meets.
        s.chain.verified = [this](const bytes32& id) {
            std::lock_guard<std::mutex> lk(idx.m);
            for (const auto& [h, rid] : idx.rows) if (rid == id) return true;
            return false;
        };
        s.chain.target = [this](const bytes32& anchor, const std::vector<CtxStep>& above, std::uint64_t, CtxTarget& out, std::string& why) {
            std::lock_guard<std::mutex> lk(idx.m);
            for (const auto& [h, rid] : idx.rows)
                if (rid == anchor) { out.diff_lo = 2; out.diff_hi = 0; out.height = h + above.size() + 1; out.seed = bytes32{}; return true; }
            why = "anchor not held";
            return false;
        };
        s.rx = [this](const std::vector<u8>& blob, const bytes32&, bytes32& pow) {
            if (rx_throw.load() > 0 && rx_throw.fetch_sub(1) > 0) throw std::runtime_error("randomx: dataset");
            ++ctx_rx;
            { std::lock_guard<std::mutex> lk(amtx); hashed[blob]++; }
            pow.fill(0);
            return true;
        };
        s.accept = [this](const BlockCtx& b, const std::vector<u8>&) { std::lock_guard<std::mutex> lk(amtx); accepted.insert(b.id); };
        n->r().set_ctx_source(std::move(s));
    }
    ~TNode() { n.reset(); }   // the relay stops before the members its context source uses
    bool has(const bytes32& id) { std::lock_guard<std::mutex> lk(amtx); return accepted.count(id) != 0; }
    u64 hashed_count(const std::vector<u8>& blob) { std::lock_guard<std::mutex> lk(amtx); const auto it = hashed.find(blob); return it == hashed.end() ? 0 : it->second; }
};

static pb::PathbRelayOptions opts(bool listen, std::vector<u16> dial) {
    pb::PathbRelayOptions o = Rig::opts(listen, dial);
    o.ctx_retry_ms = 250;
    o.ctx_max_rounds = 4;
    return o;
}

int main() {
    Checker C;
    std::printf("== v37_xmr_relay_native_ctx_kat ==\n");

    // ── the Monero chain ────────────────────────────────────────────────────
    // best chain: G(99) <- H1(100) <- H2(101). X(100, on G) lost the race to H1:
    // C's native node HOLDS it as an alternative body. W(100, on G) is a sibling
    // only A's native node holds.
    const SynthBlock G  = make_block(99,  b32_of(5), 90, nullptr, 2, 60);
    const bytes32 idG = block_id(G);
    const SynthBlock H1 = make_block(100, idG, 91, nullptr, 1, 61);
    const bytes32 idH1 = block_id(H1);
    const SynthBlock H2 = make_block(101, idH1, 92, nullptr, 1, 62);
    const SynthBlock X  = make_block(100, idG, 93, nullptr, 3, 63);
    const bytes32 idX = block_id(X);
    const SynthBlock W  = make_block(100, idG, 94, nullptr, 2, 64);
    const bytes32 idW = block_id(W);

    // ── the network: A and B up first ───────────────────────────────────────
    Rig rig;
    TNode A(rig, "A", opts(true, {}));
    std::string why;
    C(A.n->start(why), "A starts " + why);
    const u16 portA = A.n->port();
    TNode B(rig, "B", opts(true, {portA}));
    C(B.n->start(why), "B starts, dials A " + why);
    const u16 portB = B.n->port();
    C(wait_until([&] { return A.n->r().ready_peers().size() == 1 && B.n->r().ready_peers().size() == 1; }, 15000ms), "A-B up");
    for (auto* t : {&A, &B}) { t->idx.main(G); t->idx.main(H1); t->idx.main(H2); }
    A.idx.alt(X); A.idx.alt(W);   // A mined on X and W: its native node holds both bodies

    // ── C: a native index that holds G/H1/H2 + X ────────────────────────────
    TNode Cn(rig, "C", opts(true, {portA, portB}));
    Cn.idx.main(G); Cn.idx.main(H1); Cn.idx.main(H2); Cn.idx.alt(X);   // W: never seen by C's native node
    C(Cn.n->start(why), "C starts, dials A and B " + why);
    C(wait_until([&] { return Cn.n->r().ready_peers().size() == 2; }, 15000ms), "C in the mesh");

    // ── N1 contexts from C's own native index and bodies ────────────────────
    const u64 rx0 = Cn.ctx_rx.load();
    const bool g_ok = Cn.n->fetch_context(idG, 5) && Cn.n->fetch_context(idH1, 5);
    C(g_ok && Cn.has(idG) && Cn.has(idH1) && Cn.ctx_rx.load() == rx0,
      "N1 the best-chain contexts (G, H1) came from C's native index (held there: no hash spent)");
    const bool x_ok = Cn.n->fetch_context(idX, 5);
    C(x_ok && Cn.has(idX) && Cn.hashed_count(X.hashing_blob) >= 1 && Cn.n->st().ctx_asked.load() == 0,
      "N1 X (an alternative C's native node holds) resolved from C's OWN native body (verified, its work judged "
      "against G in C's index; no peer asked)");

    // ── N2 FB_GETCTX served natively ────────────────────────────────────────
    const bool w_ok = Cn.n->fetch_context(idW, 10);
    C(w_ok && Cn.has(idW) && Cn.hashed_count(W.hashing_blob) >= 1,
      "N2 W (held only by A's native node) resolved at C: verified, its work judged against G in C's index, into C's follower");
    C(A.n->st().ctx_served.load() >= 1, "N2 A answered C's FB_GETCTX for W from its native body (" +
      std::to_string(A.n->st().ctx_served.load()) + " served natively)");
    C(wait_until([&] { return Cn.n->st().ctx_resolved.load() == Cn.n->st().ctx_wanted.load(); }, 5000ms) &&
      Cn.n->st().ctx_gave_up.load() == 0,
      "N1 every context want is cleared (" + std::to_string(Cn.n->st().ctx_resolved.load()) + " resolved of " +
      std::to_string(Cn.n->st().ctx_wanted.load()) + ")");

    // ── N3 a RandomX exception judging a context ────────────────────────────
    const SynthBlock Y = make_block(100, idG, 95, nullptr, 3, 65);
    const bytes32 idY = block_id(Y);
    Cn.idx.alt(Y);
    Cn.rx_throw = 1;
    const bool y_ok = Cn.n->fetch_context(idY, 10);
    C(y_ok && Cn.has(idY) && Cn.n->st().rx_failures.load() == 1 && Cn.rx_throw.load() <= 0 &&
      Cn.n->st().strikes.load() == 0 && Cn.n->st().bans.load() == 0,
      "N3 the context RandomX threw once at C (" + std::to_string(Cn.n->st().rx_failures.load()) +
      " failure): no strike, no ban; judged again and resolved");

    for (auto* t : {&A, &B, &Cn}) if (C.fail) t->n->dump_logs();
    std::printf("    C %s\n", Cn.n->r().describe().c_str());
    return C.done("v37_xmr_relay_native_ctx_kat");
}
