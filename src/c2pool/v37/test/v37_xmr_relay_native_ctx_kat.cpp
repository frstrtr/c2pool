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
//   N5  the join wants' cap (P-07) holds when a join raises an unsolicited
//       want's bound: up to the cap raised, the next kept unsolicited; with
//       the join wants full a relayed carrier takes the carrier class (P-07)
//   N4  a join's context (a carrier under verification) 5 blocks above C's
//       index, on a branch only A holds: the want climbs to the index (P-07,
//       not P-06), every block judged and fed into C's follower
//   N6  after a partition: a RELAYED carrier (a carrier under verification)
//       parked on its P_r, 5 blocks up a Monero branch only A holds (a losing
//       branch, reachable only through FB_GETCTX): the want climbs to C's
//       index (P-07), every block judged and fed into C's follower; a receipt
//       CARRIED by a relayed carrier (the carrier's DEFER names the receipt's
//       P_r) the same; an unsolicited relayed RECEIPT on such a branch climbs
//       P-06 (3 blocks) only
//   N7  P-13: a context block of ~600,000 B (above 512 KiB, within
//       blob_cap_ctx(16, zone(16)) = 600,051) only A holds is served by A and
//       resolved at C; a block of ~650,000 B: A serves it (its cap raised by
//       the policy), C drops the frame (over its cap at its view; no strike);
//       with C's view cap above it, C's judge drops it at the newest known
//       ancestor's cap (600,051) before hashing; with C's view answering 0
//       the frame cap stays at blob_cap_ctx(16, zone(16))
//   N8  N6's three cases as real frames from a peer of C's pool: a job of
//       C's with its Monero parent moved 5 blocks up a branch only A holds,
//       sent as an FC_CARRIER (the carrier's own P_r), as a receipt carried
//       by an FC_CARRIER (the carried P_r) and as an FB_RECEIPTS body: the
//       two carriers' contexts climb to C's index (P-07), every block judged
//       and fed into C's follower; the receipt's climbs P-06 only; a
//       malformed FB_CTX (its length field over the cap, the frame shorter)
//       is struck, not dropped as over the cap
//   N9  the classes of context wants: a peer fills the carrier class with
//       carriers whose P_r the node does not hold (the fifth held at P-06),
//       the receipt class is full; a join attempt's want is still taken at
//       the join's bound (P-07)
//   N10 a kept alternative block no native index holds, carried by A's kept
//       files (row_weights_kept and row_weights_kept_blobs, as a restarted
//       node loads them): A serves it from the kept blob, C resolves it
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <map>
#include <mutex>
#include <set>
#include <stdexcept>
#include <thread>

#include <unistd.h>

#include "xmr_pathb_relay_test_util.hpp"
#include "c2pool/v37/xmr/pathb/pathb_follower_rows.hpp"

using namespace pathb_relay_test;
using namespace std::chrono_literals;
using c2pool::v37n::CarrierPeerNode;

// A native chain index as the relay sees it: best-chain rows, retained bodies
// (connected blocks + held alternatives).
struct FakeIndex {
    std::mutex m;
    std::map<u64, bytes32> rows;
    std::map<bytes32, std::vector<u8>> bodies;
    std::atomic<u64> blob_calls{0};
    void main(const SynthBlock& sb) { std::lock_guard<std::mutex> lk(m); rows[sb.height] = block_id(sb); bodies[block_id(sb)] = sb.full_blob; }
    void alt(const SynthBlock& sb)  { std::lock_guard<std::mutex> lk(m); bodies[block_id(sb)] = sb.full_blob; }
    void drop(const bytes32& id)    { std::lock_guard<std::mutex> lk(m); bodies.erase(id); }
};

struct TNode {
    FakeIndex idx;
    std::unique_ptr<pb::PathbFollowerRows> kept;  // the kept rows and blobs (row_weights_kept_blobs), loaded on demand
    std::unique_ptr<RNode> n;
    std::mutex amtx;
    std::set<bytes32> accepted;                 // blocks fed into the follower
    std::map<std::vector<u8>, u64> hashed;      // context RandomX calls by hashing blob
    std::atomic<u64> ctx_rx{0};
    std::atomic<int> rx_throw{0};               // the next context RandomX calls that throw
    std::atomic<u64> anchor_cap{600051};        // P-13 at a judged block's newest known ancestor (the model index)
    std::atomic<u64> view_cap{600051};          // P-13 at the node's view

    TNode(Rig& rig, std::string name, pb::PathbRelayOptions o) {
        kept = std::make_unique<pb::PathbFollowerRows>(
                (std::filesystem::temp_directory_path() / ("ctxkat_" + name + "_" + std::to_string(::getpid())) / "row_weights")
                        .string());
        n = rig.make(std::move(name), std::move(o));
        pb::PathbCtxSource s;
        // the index first, then the kept blobs of before a restart (the daemon's composition)
        s.block_blob = pb::served_ctx_blob(
                [this](const pb::Hash32& id, std::vector<u8>& out) {
                    ++idx.blob_calls;
                    std::lock_guard<std::mutex> lk(idx.m);
                    const auto it = idx.bodies.find(id);
                    if (it == idx.bodies.end()) return false;
                    out = it->second;
                    return true;
                },
                kept.get());
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
                if (rid == anchor) {
                    out.diff_lo = 2; out.diff_hi = 0; out.height = h + above.size() + 1; out.seed = bytes32{};
                    out.blob_cap = anchor_cap.load();
                    return true;
                }
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
        s.view_cap = [this] { return view_cap.load(); };
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
    C(Cn.n->r().ctx_want_bytes() == 0 && Cn.n->r().ctx_want_bytes_peak() >= W.full_blob.size(),
      "N2 the wanted contexts' peak bytes hold W's block (" + std::to_string(Cn.n->r().ctx_want_bytes_peak()) + " B, W " +
      std::to_string(W.full_blob.size()) + " B) while none is held now");

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

    // ── N4 a join's context climbs a branch deeper than an unsolicited receipt's bound ─
    // Z1(100) <- Z2 <- ... <- Z5(104) on G: a branch A mined on its own; only A's native node holds the bodies. A
    // join's want for Z5 (a carrier under verification) climbs to G (P-07), past P-06 (3).
    std::vector<bytes32> zid;
    {
        bytes32 prev = idG;
        for (u64 k = 1; k <= 5; ++k) {
            const SynthBlock Z = make_block(99 + k, prev, 95 + k, nullptr, 1, 70 + k);
            zid.push_back(block_id(Z));
            A.idx.alt(Z);
            prev = zid.back();
        }
    }
    const bool z_ok = Cn.n->fetch_context(zid.back(), 30);
    bool z_all = z_ok;
    for (const bytes32& z : zid) z_all = z_all && Cn.has(z);
    C(z_all && Cn.n->r().options().ctx_max_depth == 3 && Cn.n->r().options().ctx_join_depth == 720,
      "N4 a join's context 5 blocks above C's index (a branch only A holds) climbs to it (P-07): every block of the "
      "branch verified, judged and fed into C's follower");

    // ── N6 after a partition: a relayed carrier's context climbs to P-07, a relayed receipt's P-06 ─
    {
        Cn.n->r().partition_for(std::chrono::seconds(2));
        std::vector<bytes32> qid, rid, sid;   // three branches on G only A mined while C was cut off
        bytes32 prev = idG;
        for (u64 k = 1; k <= 5; ++k) {
            const SynthBlock Q = make_block(99 + k, prev, 110 + k, nullptr, 1, 80 + k);
            qid.push_back(block_id(Q));
            A.idx.alt(Q);
            prev = qid.back();
        }
        prev = idG;
        for (u64 k = 1; k <= 5; ++k) {
            const SynthBlock R = make_block(99 + k, prev, 120 + k, nullptr, 2, 90 + k);
            rid.push_back(block_id(R));
            A.idx.alt(R);
            prev = rid.back();
        }
        std::this_thread::sleep_for(2500ms);
        prev = idG;
        for (u64 k = 1; k <= 5; ++k) {
            const SynthBlock S = make_block(99 + k, prev, 130 + k, nullptr, 3, 100 + k);
            sid.push_back(block_id(S));
            A.idx.alt(S);
            prev = sid.back();
        }
        C(wait_until([&] { return Cn.n->r().ready_peers().size() == 2; }, 20000ms), "N6 C back in the mesh after the partition");
        const std::vector<std::uint64_t> rp = Cn.n->r().ready_peers();
        const std::uint64_t sender = rp.empty() ? 0 : rp.front();
        const u64 res0 = Cn.n->st().ctx_resolved.load();
        Cn.n->r().test_parked(sender, pb::Missing::MoneroBlock, b32_of(230), qid.back(), /*relayed=*/true, /*carrier=*/true);
        bool q_all = wait_until([&] {
            for (const bytes32& q : qid)
                if (!Cn.has(q)) return false;
            return true;
        }, 30000ms);
        C(q_all && Cn.n->st().ctx_resolved.load() >= res0 + 5,
          "N6 a relayed carrier parked on its P_r 5 blocks up a branch only A holds: the context climbs to C's index "
          "(P-07): every block judged and fed into C's follower");
        // a receipt carried by a relayed carrier: the carrier's admission DEFER names the carried body's P_r
        Cn.n->r().test_parked(sender, pb::Missing::MoneroBlock, b32_of(232), sid.back(), /*relayed=*/true, /*carrier=*/true);
        bool s_all = wait_until([&] {
            for (const bytes32& x : sid)
                if (!Cn.has(x)) return false;
            return true;
        }, 30000ms);
        C(s_all, "N6 a receipt carried by a relayed carrier, its P_r 5 blocks up a branch only A holds: the context "
                 "climbs to C's index (P-07)");
        Cn.n->r().test_parked(sender, pb::Missing::MoneroBlock, b32_of(231), rid.back(), /*relayed=*/true, /*carrier=*/false);
        std::this_thread::sleep_for(3000ms);
        bool r_none = true;
        for (const bytes32& r : rid) r_none = r_none && !Cn.has(r);
        C(r_none && A.idx.blob_calls.load() > 0,
          "N6 an unsolicited relayed receipt on such a branch climbs P-06 only (3 blocks): it does not reach C's index");
    }

    // ── N7 P-13: a context block of ~600,000 B (above 512 KiB) is served and resolved ─
    {
        const std::uint64_t cap = pb::blob_cap_ctx(16, pb::zone(16)).value_or(0);
        const SynthBlock L = make_block(100, idG, 140, nullptr, 18742, 111);
        const bytes32 idL = block_id(L);
        A.idx.alt(L);
        const bool l_ok = Cn.n->fetch_context(idL, 30);
        C(cap == 600051 && L.full_blob.size() > 512 * 1024 && L.full_blob.size() <= cap && l_ok && Cn.has(idL),
          "N7 a context block of " + std::to_string(L.full_blob.size()) + " B (> 512 KiB, <= blob_cap_ctx(16, zone(16)) = " +
                  std::to_string(cap) + ") only A holds: served by A and resolved at C");
        // a block over the cap: A raised by its policy serves it; C drops the frame (its view's cap), no strike
        const SynthBlock M = make_block(100, idG, 141, nullptr, 20300, 112);
        const bytes32 idM = block_id(M);
        A.idx.alt(M);
        A.view_cap = 700000;
        const u64 over0 = Cn.n->st().ctx_over_cap.load(), strikes0 = A.n->st().strikes.load() + B.n->st().strikes.load();
        const bool m_ok = Cn.n->fetch_context(idM, 5);
        C(M.full_blob.size() > cap && M.full_blob.size() <= 700000 && !m_ok && !Cn.has(idM) &&
                  Cn.n->st().ctx_over_cap.load() > over0 && Cn.n->st().strikes.load() == 0,
          "N7 a context block of " + std::to_string(M.full_blob.size()) + " B over C's cap: served, dropped at C's frame (" +
                  std::to_string(Cn.n->st().ctx_over_cap.load() - over0) + " drops), no strike (" +
                  std::to_string(strikes0) + " before)");
        // C's view cap above the block, its newest known ancestor's cap below it: dropped by the judge before hashing
        Cn.view_cap = 700000;
        const u64 rxM0 = Cn.hashed_count(M.hashing_blob);
        const bool m2 = Cn.n->fetch_context(idM, 5);
        C(!m2 && !Cn.has(idM) && Cn.hashed_count(M.hashing_blob) == rxM0 && Cn.n->st().strikes.load() == 0,
          "N7 with C's view cap above the block and its newest known ancestor's P-13 below it: dropped before hashing");
        // C's view answering 0: the frame cap stays at blob_cap_ctx(16, zone(16))
        Cn.view_cap = 0;
        A.view_cap = 600051;
        const SynthBlock L2 = make_block(100, idG, 143, nullptr, 18742, 114);
        const bytes32 idL2 = block_id(L2);
        A.idx.alt(L2);
        const bool l2_ok = Cn.n->fetch_context(idL2, 30);
        C(L2.full_blob.size() > 512 * 1024 && L2.full_blob.size() <= cap && l2_ok && Cn.has(idL2),
          "N7 with C's view answering 0 the frame cap stays at blob_cap_ctx(16, zone(16)): a context block of " +
                  std::to_string(L2.full_blob.size()) + " B resolved");
        Cn.view_cap = 600051;
    }

    // ── N5 the join wants' count holds when an unsolicited want is raised to a join's bound ─
    // A node whose join wants are capped at 4 (the climb's bound, here 4 > P-06) holds five unsolicited wants; a join
    // wants all five: four are raised to the join's bound, the fifth stays an unsolicited want (the cap is checked at
    // the raise as at an insertion).
    {
        pb::PathbRelayOptions od = opts(false, {});
        od.ctx_join_depth = 4;
        TNode D(rig, "D", od);
        std::string w;
        C(D.n->start(w), "D starts " + w);
        std::vector<bytes32> ids;
        for (int k = 0; k < 5; ++k) ids.push_back(b32_of(static_cast<std::uint8_t>(201 + k)));
        for (const bytes32& x : ids) D.n->r().want_context(x, 0);
        const auto before = D.n->r().ctx_wants_held();
        for (const bytes32& x : ids) (void)D.n->fetch_context(x, 0);
        const auto after = D.n->r().ctx_wants_held();
        C(before.first == 5 && before.second == 0 && after.first == 5 && after.second == 4,
          "N5 five unsolicited wants, a join wants all five: four raised to the join's bound, the fifth kept unsolicited "
          "(join wants " + std::to_string(after.second) + " of a cap of 4)");
        // a relayed carrier's context with the join wants full: its own class (P-07), not a join place
        D.n->r().test_parked(0, pb::Missing::MoneroBlock, b32_of(240), b32_of(241), /*relayed=*/true, /*carrier=*/true);
        const auto byc = D.n->r().ctx_wants_by_class();
        C(byc[0] == 1 && byc[1] == 1 && byc[2] == 4 && D.n->r().ctx_want_bound(b32_of(241)) == std::optional<std::uint32_t>(4),
          "N5 with the join wants full a relayed carrier's context takes the carrier class at P-07 (receipt / carrier / "
          "join wants " + std::to_string(byc[0]) + " / " + std::to_string(byc[1]) + " / " + std::to_string(byc[2]) + ")");
    }

    // ── N9 relayed carriers cannot take a join attempt's places ─
    // A node with the carrier and join classes capped at 4 and the receipt class at 2. A peer fills the carrier class
    // with carriers whose P_r the node does not hold; a fifth carrier is held at P-06; the receipt class fills. A join
    // attempt's want is still taken, at the join's bound (P-07).
    {
        pb::PathbRelayOptions oe = opts(false, {});
        oe.ctx_join_depth = 4;
        oe.ctx_want_max = 2;
        TNode E(rig, "E", oe);
        std::string w;
        C(E.n->start(w), "E starts " + w);
        for (int k = 0; k < 5; ++k)
            E.n->r().test_parked(7, pb::Missing::MoneroBlock, b32_of(static_cast<std::uint8_t>(150 + k)),
                                 b32_of(static_cast<std::uint8_t>(160 + k)), /*relayed=*/true, /*carrier=*/true);
        const auto c1 = E.n->r().ctx_wants_by_class();
        C(c1[1] == 4 && c1[0] == 1 && E.n->r().ctx_want_bound(b32_of(164)) == std::optional<std::uint32_t>(3),
          "N9 four carriers with unknown P_r fill the carrier class; the fifth is held at P-06 (receipt / carrier "
          "wants " + std::to_string(c1[0]) + " / " + std::to_string(c1[1]) + ")");
        E.n->r().want_context(b32_of(170), 7);
        const auto c2 = E.n->r().ctx_wants_by_class();
        C(c2[0] == 2, "N9 the receipt class is full (2)");
        (void)E.n->fetch_context(b32_of(171), 0);
        const auto c3 = E.n->r().ctx_wants_by_class();
        C(c3[2] == 1 && E.n->r().ctx_want_bound(b32_of(171)) == std::optional<std::uint32_t>(4),
          "N9 a join attempt's want is taken at the join's bound (P-07), not pushed to P-06 nor refused (receipt / "
          "carrier / join wants " + std::to_string(c3[0]) + " / " + std::to_string(c3[1]) + " / " + std::to_string(c3[2]) + ")");
    }

    // ── N8 N6's three cases as real frames from a peer of C's pool ─
    // After each carrier case the branch's bodies leave A and A's serving goes quiet (C's follower here is the model
    // index, not its Path B node's Monero view), so the receipt case counts its own climb only.
    {
        CarrierPeerNode raw;
        const auto pid = raw.add_peer_id("127.0.0.1", Cn.n->port());
        if (pid != 0) raw.send_to(pid, Cn.n->hello_bytes(Cn.n->r().node_nonce() ^ 0x6a6a6a6aull, 0));
        C(pid != 0 && wait_until([&] { return Cn.n->r().ready_peers().size() == 3; }, 5000ms),
          "N8 a raw peer of C's pool is up at C");
        const pb::PathbNodeConfig cfg = rig.h.config(pk::kat_table(rig.net), false);
        std::optional<pb::PathbJob> j = rig.job(*Cn.n, 0);
        C(j.has_value(), "N8 a job of C's on its best tip");
        if (!j) j = pb::PathbJob{};
        auto branch = [&](u32 en, std::size_t ntx, u8 salt) {
            std::vector<bytes32> ids;
            bytes32 prev = idG;
            for (u64 k = 1; k <= 5; ++k) {
                const SynthBlock S = make_block(99 + k, prev, en + static_cast<u32>(k), nullptr, ntx, static_cast<u8>(salt + k));
                ids.push_back(block_id(S));
                A.idx.alt(S);
                prev = ids.back();
            }
            return ids;
        };
        auto moved = [&](std::uint32_t nonce, const bytes32& pr) {
            pb::ReceiptBodyV3 b = body_of(*j, nonce);
            b.blob.prev_id = pr;
            return b;
        };
        auto all_in = [&](const std::vector<bytes32>& ids) {
            for (const bytes32& x : ids)
                if (!Cn.has(x)) return false;
            return true;
        };
        auto settle = [&](const std::vector<bytes32>& ids) {
            for (const bytes32& x : ids) A.idx.drop(x);
            u64 last = A.n->st().ctx_served.load();
            auto since = std::chrono::steady_clock::now();
            const auto end = since + 30s;
            while (std::chrono::steady_clock::now() < end) {
                std::this_thread::sleep_for(250ms);
                const u64 now = A.n->st().ctx_served.load();
                if (now != last) {
                    last = now;
                    since = std::chrono::steady_clock::now();
                } else if (std::chrono::steady_clock::now() - since >= 1500ms) {
                    return;
                }
            }
        };
        const std::vector<bytes32> qid = branch(150, 4, 120), sid = branch(160, 5, 130), rid = branch(170, 6, 140);

        // a relayed carrier: its own P_r 5 blocks up the branch (row 5)
        pb::CarrierBodyV3 cq;
        cq.own = moved(0x601, qid.back());
        const std::optional<std::vector<u8>> fq = pb::encode_fc_carrier(cfg.identity.chain_id, cq, cfg.p.r_max);
        if (fq) raw.send_to(pid, *fq);
        C(fq.has_value() && wait_until([&] { return all_in(qid); }, 30000ms),
          "N8 an FC_CARRIER whose own P_r is 5 blocks up a branch only A holds: the context climbs to C's index (P-07): "
          "every block judged and fed into C's follower");
        settle(qid);

        // a receipt carried by a relayed carrier: the own body's P_r held, the carried one's 5 blocks up (row 19)
        pb::CarrierBodyV3 cs;
        cs.own = body_of(*j, 0x602);
        cs.carried.push_back(moved(0x603, sid.back()));
        const std::optional<std::vector<u8>> fs = pb::encode_fc_carrier(cfg.identity.chain_id, cs, cfg.p.r_max);
        if (fs) raw.send_to(pid, *fs);
        C(fs.has_value() && wait_until([&] { return all_in(sid); }, 30000ms),
          "N8 an FC_CARRIER carrying a receipt whose P_r is 5 blocks up such a branch: the context climbs to C's index "
          "(P-07)");
        settle(sid);

        // an unsolicited relayed receipt (FB_RECEIPTS): its P_r 5 blocks up such a branch (row 19)
        const u64 w0 = Cn.n->st().ctx_wanted.load(), s0 = A.n->st().ctx_served.load();
        const std::optional<std::vector<u8>> fr =
                pb::encode_fb_receipts(cfg.identity.chain_id, std::vector<pb::ReceiptBodyV3>{moved(0x604, rid.back())}, cfg.p);
        if (fr) raw.send_to(pid, *fr);
        const bool wanted = fr.has_value() && wait_until([&] { return Cn.n->st().ctx_wanted.load() > w0; }, 10000ms);
        std::this_thread::sleep_for(5000ms);   // P-06's climb and its rounds (4 x 3 peers at 250 ms)
        bool r_none = true;
        for (const bytes32& x : rid) r_none = r_none && !Cn.has(x);
        C(wanted && r_none && A.n->st().ctx_served.load() > s0,
          "N8 an FB_RECEIPTS body whose P_r is 5 blocks up such a branch: its context climbs P-06 only (A served " +
                  std::to_string(A.n->st().ctx_served.load() - s0) + "): it does not reach C's index");
        // an FB_CTX whose length field is over the cap and does not match the frame's bytes: malformed (a strike)
        {
            std::vector<u8> bad(kCtxHeader, 0);
            bad[0] = 0x44;
            bad[1] = 0x01;
            const std::uint32_t len = 700000;
            for (int i = 0; i < 4; ++i) bad[38 + i] = static_cast<u8>(len >> (8 * i));
            const u64 mal0 = Cn.n->st().malformed.load(), over0 = Cn.n->st().ctx_over_cap.load();
            raw.send_to(pid, bad);
            const bool struck = wait_until([&] { return Cn.n->st().malformed.load() > mal0; }, 5000ms);
            C(struck && Cn.n->st().ctx_over_cap.load() == over0,
              "N8 a malformed FB_CTX (its length field over the cap, the frame 42 B) is struck, not dropped as over the cap");
        }
        raw.stop();
    }

    // ── N10 a kept alternative block served after a restart (HP-2) ──────────
    // W2 (100, on G): no node's native index holds it. A's kept files (written as a save would, then loaded as a
    // restarted node does) carry W2's row and block: A serves it from the kept blob; C resolves it.
    {
        namespace fs = std::filesystem;
        const SynthBlock W2 = make_block(100, idG, 97, nullptr, 2, 67);
        const bytes32 idW2 = block_id(W2);
        const std::string table = A.kept->path();
        fs::create_directories(fs::path(table).parent_path());
        std::map<pb::Hash32, pb::KeptRow> rows;
        pb::KeptRow kr;
        kr.row.id = idW2;
        kr.row.prev_id = idG;
        kr.row.height = 100;
        kr.w = pb::RowWeights{1, 300000, 300000, 300000, 16};
        rows.emplace(idW2, kr);
        const auto put = [](const std::string& path, const std::vector<u8>& b) {
            std::ofstream(path, std::ios::binary | std::ios::trunc).write(reinterpret_cast<const char*>(b.data()),
                                                                          static_cast<std::streamsize>(b.size()));
        };
        put(table, pb::encode_row_weights_table({}));
        put(A.kept->kept_path(), pb::encode_kept_rows(rows));
        put(A.kept->blobs_path(), pb::encode_kept_blobs({{idW2, W2.full_blob}}));
        std::string lwhy;
        const bool loaded = A.kept->load(lwhy) && A.kept->kept_blobs_loaded() == 1;
        const u64 served0 = A.n->st().ctx_served.load();
        const bool w2_ok = loaded && Cn.n->fetch_context(idW2, 10);
        C(loaded && w2_ok && Cn.has(idW2) && A.n->st().ctx_served.load() > served0,
          "N10 a kept alternative block (W2: no index holds it; A's kept files carry its row and block) is served by A from "
          "its kept blob after a load, and resolves at C (" + lwhy + ")");
        fs::remove_all(fs::path(table).parent_path());
    }

    for (auto* t : {&A, &B, &Cn}) if (C.fail) t->n->dump_logs();
    std::printf("    C %s\n", Cn.n->r().describe().c_str());
    return C.done("v37_xmr_relay_native_ctx_kat");
}
