// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// v37_xmr_relay_native_ctx_kat -- RC-CTX: a receipt's Monero context (the block
// its template built on) must be resolvable on the P2P-FIRST arm.
//
// The defect (D2 verify D-3, D6a M3 restart, the D2 2-vs-1 lone node, the
// publish-arm verify's lag-suspended node C): on --arm-order p2p-first the
// relay's ChainView was fed ONLY the prev_id of the template being served, the
// relay's own context wants were never looked up, and every peer FB_GETCTX was
// answered "unknown". A restarted node (RAM-only ChainView) or one that
// followed another branch therefore could not verify the winner-side receipts
// of a cut -> "relay repair of P=.. N/M receipts missing, K Monero context(s)
// unresolved" -> relay_repair_stall_timeout REFUSES an honest cut.
//
// Three in-process XmrRelayNode instances over real loopback TCP; each has a
// FAKE native chain index (best-chain rows + retained bodies + held
// alternatives) wired exactly the way main_v37_xmr.cpp's relay_tick wires the
// real one (NativeCtxFeeder::feed + ::serve). RandomX is a counting fake.
//
//   N1  RESTART: C comes up with an EMPTY ChainView (only its current template
//       noted). A's cut holds receipts mined on best-chain blocks C's native
//       index holds (G, H1) and on a same-height sibling X that C's native node
//       holds as an ALTERNATIVE body. C's repair must be Ready and replay to
//       A's spine; every want cleared; repair_status names no unresolved context
//   N2  FB_GETCTX served NATIVELY: a block W only A's native node holds. C asks
//       its peers; A answers from its native body (no monerod: the fallback is
//       never called); C verifies + parent-links it; the repair is Ready
//   N3  the own-template journal: contexts noted, a duplicate suppressed, a
//       fresh ChainView reloads them; a torn tail / a corrupt record is
//       dropped; the file stays bounded (compaction)
//   N4  feed() is incremental and honest-path neutral: it notes best-chain rows
//       only (an alternative block never enters the ChainView unasked), and a
//       tip reorg re-notes the new block
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <map>
#include <thread>
#include <unistd.h>

#include "xmr_relay_test_util.hpp"
#include <c2pool/v37/xmr/relay/xmr_relay_node.hpp>
#include <c2pool/v37/xmr/relay/xmr_receipt_ingest.hpp>
#include <c2pool/v37/v37_engine.hpp>

#if __has_include(<c2pool/v37/xmr/relay/xmr_relay_native_ctx.hpp>)
#include <c2pool/v37/xmr/relay/xmr_relay_native_ctx.hpp>
static constexpr bool kFixTree = true;
#else
// BASE TREE (pre-RC-CTX): the P2P-first arm of main_v37_xmr.cpp relay_tick,
// verbatim in behaviour -- the ChainView is fed nothing from the native node,
// own wants are never looked up, every FB_GETCTX is answered "unknown", and no
// template context survives a restart. Same API so the scenarios compile.
static constexpr bool kFixTree = false;
namespace c2pool::v37n::xmr::relay {
struct NativeCtxSource {
    std::function<std::optional<u64>()> best_height;
    std::function<std::optional<bytes32>(u64)> id_at;
    std::function<std::optional<bytes32>(u64)> seed_for_bin;
    std::function<bool(const bytes32&, std::vector<u8>&)> block_blob;
    explicit operator bool() const noexcept { return best_height && id_at; }
};
class NativeCtxFeeder {
public:
    struct Stats { u64 rows_noted = 0, seedless = 0, wants_native = 0, wants_missing = 0, getctx_native = 0, getctx_unknown = 0, getctx_fallback = 0; };
    std::size_t feed(ChainView&, const NativeCtxSource&, u64 = 128) { return 0; }
    void serve(XmrRelayNode& rn, const NativeCtxSource&, const std::function<std::vector<u8>(const bytes32&)>& = {}) {
        for (const auto& [pid, ids] : rn.drain_ctx_requests())
            for (const auto& id : ids) { ++m_st.getctx_unknown; rn.send_ctx(pid, id, {}); }
    }
    const Stats& stats() const noexcept { return m_st; }
private:
    Stats m_st{};
};
class CtxJournal {
public:
    static constexpr std::size_t kRec = 80, kKeep = 4096;
    explicit CtxJournal(std::string p = {}) : m_path(std::move(p)) {}
    std::size_t load(ChainView&) { return 0; }
    bool note(const bytes32&, u64, const bytes32&) { return false; }
    std::size_t size() const { return 0; }
    u64 written() const { return 0; }
    u64 bad_tail() const { return 0; }
    const std::string& path() const { return m_path; }
private:
    std::string m_path;
};
}  // namespace c2pool::v37n::xmr::relay
#endif

using namespace gap2test;
using namespace std::chrono_literals;

static constexpr u32 kChain = 7;
static constexpr u64 kShareDiff = 1000;

static bytes32 block_id(const SynthBlock& sb) {
    std::vector<u8> pre;
    put_varint(pre, sb.hashing_blob.size());
    pre.insert(pre.end(), sb.hashing_blob.begin(), sb.hashing_blob.end());
    const auto h = ::xmr::coin::keccak256(pre.data(), pre.size());
    bytes32 b; std::memcpy(b.data(), h.data(), 32); return b;
}

// A native chain index as the relay sees it: best-chain rows, retained bodies
// (connected blocks + held alternatives). Seeds are all-zero (the RandomX fake
// ignores them), exactly like the repair-ctx KAT's note_bin().
struct FakeIndex {
    std::mutex m;
    std::map<u64, bytes32> rows;
    std::map<bytes32, std::vector<u8>> bodies;
    std::atomic<u64> blob_calls{0};
    void main(const SynthBlock& sb) { std::lock_guard<std::mutex> lk(m); rows[sb.height] = block_id(sb); bodies[block_id(sb)] = sb.full_blob; }
    void alt(const SynthBlock& sb)  { std::lock_guard<std::mutex> lk(m); bodies[block_id(sb)] = sb.full_blob; }
    NativeCtxSource source() {
        NativeCtxSource s;
        s.best_height = [this]() -> std::optional<u64> { std::lock_guard<std::mutex> lk(m); if (rows.empty()) return std::nullopt; return rows.rbegin()->first; };
        s.id_at = [this](u64 h) -> std::optional<bytes32> { std::lock_guard<std::mutex> lk(m); auto it = rows.find(h); if (it == rows.end()) return std::nullopt; return it->second; };
        s.seed_for_bin = [](u64) -> std::optional<bytes32> { return bytes32{}; };
        s.block_blob = [this](const bytes32& id, std::vector<u8>& out) {
            ++blob_calls;
            std::lock_guard<std::mutex> lk(m); auto it = bodies.find(id); if (it == bodies.end()) return false; out = it->second; return true;
        };
        return s;
    }
};

struct TNode {
    std::string name;
    ChainView chain;
    FakeIndex idx;
    NativeCtxSource native;
    NativeCtxFeeder feeder;
    std::atomic<u64> monerod_calls{0};   // the daemon-arm fallback: must stay 0 on the P2P-first arm
    std::unique_ptr<c2pool::v37n::V37Engine> engine;
    std::unique_ptr<XmrRelayNode> relay;
    std::unique_ptr<XmrReceiptIngest> ingest;
    u64 template_height = 0;
    std::vector<std::string> logs;
    std::mutex log_mtx;

    TNode(std::string n, RelayOptions ro) : name(std::move(n)) {
        native = idx.source();
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
    // the template this node is serving (main_v37_xmr.cpp relay_tick: note(prev, height, seed))
    void serve_template(const bytes32& prev, u64 height) { chain.note(prev, height, bytes32{}); chain.set_tip(height); template_height = height; }
    // the daemon's main-thread relay duties on the P2P-first arm (relay_tick)
    void pump() {
        feeder.feed(chain, native);
        feeder.serve(*relay, native);   // P2P-first: no monerod fallback
        for (auto& a : relay->drain_admitted()) ingest->on_admitted(std::move(a));
        ingest->tick(template_height);
    }
    u64 next_pos() { auto s = engine->snapshot(kChain); return s ? s->next_pos : 0; }
    bytes32 digest() { auto s = engine->snapshot(kChain); return s ? s->digest : bytes32{}; }
    void dump_logs() { std::lock_guard<std::mutex> lk(log_mtx); for (auto& l : logs) std::printf("    [%s] %s\n", name.c_str(), l.c_str()); logs.clear(); }
};

static RelayOptions opts(bool listen, std::vector<u16> dial) {
    RelayOptions o;
    o.network = 3; o.chain = kChain; o.share_diff = kShareDiff; o.bind = BindMode::None;
    o.lane_params_digest = lane_params_digest(::v37::LaneParams{}, kShareDiff, BindMode::None);
    o.listen = listen; o.listen_host = "127.0.0.1"; o.listen_port = 0;
    for (u16 p : dial) o.peers.emplace_back("127.0.0.1", p);
    o.hello_timeout_ms = 3000;
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
    std::printf("== v37_xmr_relay_native_ctx_kat (%s tree) ==\n", kFixTree ? "RC-CTX" : "BASE");
    const ::v37::ScriptRef pA = payee_of("A");

    // ── the Monero chain ────────────────────────────────────────────────────
    // best chain: G(99) <- H1(100) <- H2(101). X(100, on G) lost the race to H1:
    // C's native node HOLDS it as an alternative body. W(100, on G) is a sibling
    // only A's native node holds.
    const SynthBlock G  = make_block(99,  b32_of(5), 90, nullptr, 2, 60);
    const bytes32 idG = block_id(G);
    const SynthBlock H1 = make_block(100, idG, 91, nullptr, 1, 61);
    const bytes32 idH1 = block_id(H1);
    const SynthBlock H2 = make_block(101, idH1, 92, nullptr, 1, 62);
    const bytes32 idH2 = block_id(H2);
    const SynthBlock X  = make_block(100, idG, 93, nullptr, 3, 63);
    const bytes32 idX = block_id(X);
    const SynthBlock W  = make_block(100, idG, 94, nullptr, 2, 64);
    const bytes32 idW = block_id(W);

    // ── N4 feed(): incremental, best-chain rows only ────────────────────────
    {
        ChainView cv; FakeIndex fi; NativeCtxFeeder fd;
        fi.main(G); fi.main(H1); fi.alt(X);
        const auto src = fi.source();
        const std::size_t n1 = fd.feed(cv, src);
        C(n1 == 2 && cv.lookup(idG) && cv.lookup(idG)->height == 100 && cv.lookup(idH1) && cv.lookup(idH1)->height == 101,
          "N4 feed notes the best-chain rows: G -> bin 100, H1 -> bin 101 (" + std::to_string(n1) + " noted)");
        C(!cv.lookup(idX), "N4 an ALTERNATIVE block never enters the ChainView unasked (honest-path neutral: floods on it stay dropped)");
        C(fd.feed(cv, src) == 0, "N4 an unchanged native tip walks nothing");
        fi.main(H2);
        C(fd.feed(cv, src) == 1 && cv.lookup(idH2) && cv.lookup(idH2)->height == 102, "N4 a new tip notes only the new block (stops at the first known row)");
        const SynthBlock H2b = make_block(101, idH1, 95, nullptr, 1, 66);   // a tip reorg at h=101
        fi.main(H2b);
        C(fd.feed(cv, src) == 1 && cv.lookup(block_id(H2b)) && cv.lookup(block_id(H2b))->height == 102, "N4 a reorged tip block is noted");
    }

    // ── N3 the own-template journal ─────────────────────────────────────────
    {
        const auto dir = std::filesystem::temp_directory_path() / ("rcctx_kat_" + std::to_string(::getpid()));
        std::filesystem::create_directories(dir);
        const std::string path = (dir / "lane7.ctx").string();
        bytes32 s1{}; s1[0] = 0x11;
        {
            CtxJournal j(path);
            C(j.load(*std::make_unique<ChainView>()) == 0, "N3 a missing journal loads empty");
            C(j.note(idG, 100, s1) && j.note(idH1, 101, s1) && !j.note(idH1, 101, s1) && j.note(idX, 101, s1),
              "N3 three issued templates journaled, an unchanged template not rewritten");
        }
        {
            ChainView fresh; CtxJournal j(path);
            const std::size_t n = j.load(fresh);
            C(n == 3 && fresh.lookup(idX) && fresh.lookup(idX)->height == 101 && fresh.lookup(idX)->seed == s1 && fresh.lookup(idG),
              "N3 after a RESTART a fresh ChainView holds every issued template's context (" + std::to_string(n) + " reloaded) -- incl. X, a tip that later lost its race");
        }
        {
            std::FILE* f = std::fopen(path.c_str(), "ab"); const u8 junk[13] = {1, 2, 3}; std::fwrite(junk, 1, sizeof junk, f); std::fclose(f);
            ChainView v; CtxJournal j(path);
            C(j.load(v) == 3 && std::filesystem::file_size(path) == 3 * CtxJournal::kRec, "N3 a torn tail (crash mid-append) is ignored and compacted away");
        }
        {
            std::vector<u8> all; { std::FILE* f = std::fopen(path.c_str(), "rb"); all.resize(3 * CtxJournal::kRec); std::fread(all.data(), 1, all.size(), f); std::fclose(f); }
            all[CtxJournal::kRec + 5] ^= 0xff;   // corrupt record #2
            { std::FILE* f = std::fopen(path.c_str(), "wb"); std::fwrite(all.data(), 1, all.size(), f); std::fclose(f); }
            ChainView v; CtxJournal j(path);
            C(j.load(v) == 1 && j.bad_tail() == 1 && v.lookup(idG) && !v.lookup(idH1), "N3 a corrupt record ends the load (checksum), nothing after it is trusted");
        }
        {
            CtxJournal j(path); ChainView v; j.load(v);
            for (u64 k = 0; k < 2 * CtxJournal::kKeep + 5; ++k) { bytes32 p{}; std::memcpy(p.data(), &k, 8); p[31] = 0x77; j.note(p, 1000 + k, s1); }
            C(j.size() <= 2 * CtxJournal::kKeep && std::filesystem::file_size(path) <= 2 * CtxJournal::kKeep * CtxJournal::kRec,
              "N3 bounded: the journal compacts (" + std::to_string(std::filesystem::file_size(path)) + " B on disk)");
        }
        std::error_code ec; std::filesystem::remove_all(dir, ec);
    }

    // ── the network: A and B up first ───────────────────────────────────────
    TNode A("A", opts(true, {}));
    std::string why;
    C(A.relay->start(why), "A starts " + why);
    const u16 portA = A.relay->listen_port();
    TNode B("B", opts(true, {portA}));
    C(B.relay->start(why), "B starts, dials A " + why);
    const u16 portB = B.relay->listen_port();
    C(wait_for([&] { return A.relay->ready_peers().size() == 1 && B.relay->ready_peers().size() == 1; }, {&A, &B}), "A-B up");
    // A and B saw every template (G, H1, X, H2, W) before C's restart
    for (auto* n : {&A, &B}) {
        n->serve_template(idG, 100); n->serve_template(idX, 101); n->serve_template(idH1, 101);
        n->serve_template(idW, 101); n->serve_template(idH2, 102);
        n->idx.main(G); n->idx.main(H1); n->idx.main(H2);
    }
    A.idx.alt(X); A.idx.alt(W);   // A mined on X and W: its native node holds both bodies

    // A's receipts: 2 on G, 2 on H1, 2 on X, 2 on W, 1 on H2
    const SynthBlock onG  = make_block(100, idG, 11, nullptr, 2, 70);
    const SynthBlock onH1 = make_block(101, idH1, 12, nullptr, 1, 71);
    const SynthBlock onX  = make_block(101, idX, 13, nullptr, 2, 72);
    const SynthBlock onW  = make_block(101, idW, 14, nullptr, 1, 73);
    const SynthBlock onH2 = make_block(102, idH2, 15, nullptr, 1, 74);
    for (std::uint32_t k = 0; k < 2; ++k) A.relay->submit_own(own(onG, 100 + k, pA, 100));
    for (std::uint32_t k = 0; k < 2; ++k) A.relay->submit_own(own(onH1, 200 + k, pA, 101));
    for (std::uint32_t k = 0; k < 2; ++k) A.relay->submit_own(own(onX, 300 + k, pA, 101));
    for (std::uint32_t k = 0; k < 2; ++k) A.relay->submit_own(own(onW, 400 + k, pA, 101));
    A.relay->submit_own(own(onH2, 500, pA, 102));
    for (auto* n : {&A, &B}) n->template_height = 104;
    C(wait_for([&] { return A.next_pos() == 9 && B.next_pos() == 9; }, {&A, &B}), "A and B push all 9 receipts");
    C(A.digest() == B.digest(), "A and B agree on the spine");
    const u64 P = 9;
    const bytes32 spineA = A.digest();

    // ── N1 C RESTARTS: an empty ChainView, a native index that holds G/H1/H2 + X ─
    TNode Cn("C", opts(true, {portA, portB}));
    Cn.idx.main(G); Cn.idx.main(H1); Cn.idx.main(H2); Cn.idx.alt(X);   // W: never seen by C's native node
    Cn.serve_template(idH2, 102);                                        // the first template after the restart
    Cn.template_height = 104;
    C(Cn.relay->start(why), "C restarts, dials A and B " + why);
    std::vector<TNode*> all{&A, &B, &Cn};
    C(wait_for([&] { return Cn.relay->ready_peers().size() == 2; }, all), "C back in the mesh");
    const PeerId cA = peer_by_port(*Cn.relay, portA);
    std::vector<bytes32> ids;
    const auto t0 = std::chrono::steady_clock::now();
    const bool ok1 = wait_for([&] { return Cn.relay->repair_poll(P, spineA, cA, &ids) == XmrRelayNode::RepairState::Ready; }, all, 20000ms);
    const double secs = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
    std::printf("    C repair status: %s\n", Cn.relay->repair_status(P, spineA).c_str());
    C(ok1 && ids.size() == P, "N1 C's repair of A's cut (P=9) is Ready after the restart (" + std::to_string(secs).substr(0, 5) + " s)");
    C(Cn.chain.lookup(idG) && Cn.chain.lookup(idH1) && Cn.chain.lookup(idH1)->height == 101,
      "N1 the pre-restart best-chain contexts (G, H1) came from C's native index");
    C(Cn.chain.lookup(idX) && Cn.chain.lookup(idX)->height == 101 && Cn.feeder.stats().wants_native >= 1,
      "N1 X (an alternative C's native node holds) resolved from C's OWN native body (verified + parent-linked)");
    C(ok1 && replay_matches(*Cn.relay, ids, P, spineA), "N1 a scratch replay of the repaired order reproduces A's spine byte-for-byte");

    // ── N2 FB_GETCTX served natively ────────────────────────────────────────
    C(Cn.chain.lookup(idW) && Cn.chain.lookup(idW)->height == 101, "N2 W (held only by A's native node) resolved at C");
    C(A.feeder.stats().getctx_native >= 1, "N2 A answered C's FB_GETCTX for W from its native body (" +
      std::to_string(A.feeder.stats().getctx_native) + " served natively)");
    C(A.monerod_calls.load() + B.monerod_calls.load() + Cn.monerod_calls.load() == 0 &&
      A.feeder.stats().getctx_fallback + B.feeder.stats().getctx_fallback + Cn.feeder.stats().getctx_fallback == 0,
      "N2 zero monerod get_block calls on the context path");
    C(wait_for([&] { return Cn.relay->ctx_wants_open() == 0; }, all, 5000ms), "N1 every context want is cleared");
    const std::string st = Cn.relay->repair_status(P, spineA);
    C(st.find("unresolved") == std::string::npos, "N1 repair_status names no unresolved Monero context: " + st);

    for (auto* n : all) n->dump_logs();
    std::printf("    C %s\n", Cn.relay->describe().c_str());
    return C.done("v37_xmr_relay_native_ctx_kat");
}
