// v37_convergence_supply_kat.cpp — Track A2 / Stage 1 SUPPLY.
//
// THE GAP (confirmed on c2pool#1655 head 5636d8f1 before this change): no node
// retains carrier FRAME BYTES after admission, and nothing anywhere in the tree
// answers "which carrier sits at lane position P?".
//   * ::v37::L0Slot = {pos, w_raw, w_scaled, miner, flags, version, origin_bin}
//     — no hash. ::v37::LaneRecord::Push = {chain, desc, w_raw, flags} — no
//     hash. SettlementView / LaneSnapshot carry next_pos + digest — no hashes.
//   * RelaySeenSet is an UNORDERED set of hashes; MemShareTracker is
//     identity -> set<hash>. Neither is ordered by lane position.
//   * w6 CarrierRec is keyed by share hash and orders only by walking prev_hash
//     backwards from TipRec — and main_v37_btc_dash.cpp never instantiates W6.
//   * c2pool#1655's re-offer buffer keeps the exact broadcast frame, but keyed
//     only by hash, for ~60 s, fed only from do_broadcast().
// So a node that fell behind cannot even NAME the carriers it is missing.
//
// WHAT THIS SUITE PROVES:
//   CS-1  the unified FrameVault: one bounded store, indexed by lane POSITION
//         and by carrier HASH, retained to the WINDOW horizon, with the
//         c2pool#1655 re-offer riding it as a shallow recent SUB-VIEW (same
//         bytes, one copy). Order + bytes come back exactly.
//   CS-2  serve -> fetch -> verify over real sockets: GETORDER at a cut returns
//         the server's ordered carrier ids for [a, P); GETFRAMES returns the
//         retained bytes; every byte verifies against the id asked for.
//   CS-3  a LYING peer (correct id, wrong bytes) is FAIL-CLOSED: the whole
//         response is rejected, nothing is handed on, the failure is counted.
//   CS-4  a MISSING id is FAIL-CLOSED, and so is a peer that never answers
//         (bounded by request_timeout).
//   CS-5  the bounds: vault entry / byte / horizon caps, the per-peer token
//         bucket, one outstanding request per peer, and an unsolicited answer.
//   CS-6  FLAP SAFETY: a peer that connects and drops repeatedly exhausts its
//         own re-offers but CANNOT evict another peer's retained bytes — the
//         attempt cap now retires from the sub-view, not from the vault.
//   CS-7  BACKWARD TOLERANCE: an OLD peer (no demux at all — the exact
//         pre-Stage-1 reader loop, reproduced here over a raw socket) that
//         receives a >= 0x80 opcode answers REJECT_BAD_VERSION, KEEPS the
//         socket, and goes on to admit the very next carrier frame.
//   CS-9  THE TRANSPORT CEILING: the reply budget is DERIVED from
//         kMaxCarrierFrame, so no FRAMES or ORDER reply can be built over it; a
//         fetch whose frames do not fit in one reply COMPLETES by chunking with
//         the honest server KEPT (this is the case that used to take n_peers
//         1 -> 0); a frame that ALONE exceeds the ceiling comes back as an
//         explicit un-servable status, not as a missing id and not as a stall;
//         and a peer answering "truncated, served nothing" cannot make the
//         continuation loop.
//   CS-8  ZERO CONSENSUS MOVEMENT: the opcodes are not in kAcceptedVersions,
//         CarrierWire rejects every one of them, the frozen v0x01 / v0x02
//         goldens are byte-identical, and a full serve/fetch round-trip moves
//         neither the lane digest nor owed_digest by one byte.
//
// THIS STAGE SUPPLIES AND VERIFIES BYTES ONLY. Nothing here admits a fetched
// frame, calls settle::fold_eb, or touches btc_node.hpp — applying a verified
// prefix is Stage 2, deliberately absent.
//
// Stdlib + POSIX sockets + Threads, the same self-harness shape as the sibling
// A2 suites. CONSUMER TREE ONLY.

#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <iterator>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#include <c2pool/v37/carrier_ingest.hpp>
#include <c2pool/v37/carrier_net.hpp>
#include <c2pool/v37/carrier_supply.hpp>
#include <c2pool/v37/frame_vault.hpp>
#include <c2pool/v37/v37_engine.hpp>
#include <c2pool/v37/w2_admission.hpp>
#include <c2pool/v37/w2_receipt.hpp>
#include <c2pool/v37/w3_relay.hpp>
#include <c2pool/v37/w3_wire_freeze.hpp>
#include <c2pool/v37/w4_settlement.hpp>

using namespace c2pool::v37n;
using ::v37::ChainId;
using ::v37::LaneParams;
using ::v37::LaneRecord;
using ::v37::PayoutDescriptor;

static int g_failures = 0;
static int g_checks = 0;
#define CHECK(cond)                                                          \
    do {                                                                     \
        ++g_checks;                                                          \
        if (!(cond)) { ++g_failures;                                         \
            std::printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); }    \
    } while (0)

static const ChainId CHAIN = 1;

static LaneParams small_params() {
    LaneParams p;
    p.window = 256; p.c0 = 128; p.rollup = 8;
    p.level_caps = {16}; p.half_life = 64; p.journal_depth = 16;
    return p;
}
static PayoutDescriptor mk_desc(std::uint8_t fill) {
    std::vector<std::uint8_t> s = {0x76, 0xa9, 0x14};
    for (int i = 0; i < 20; ++i) s.push_back(fill);
    s.push_back(0x88); s.push_back(0xac);
    PayoutDescriptor d;
    d.pay = ::v37::canonicalize_script(s);
    return d;
}
static PayoutDescriptor ALICE_DESC() { return mk_desc(0x11); }

// A LARGE but entirely canon-valid descriptor: the F-2 aux slot takes up to
// 0xffff refs (u16 count), each encoding to 26 bytes on the W3 wire
// (u32 chain_id + kind + len + 20-byte P2PKH payload). It is the ordinary way a
// carrier frame gets big — no malformation, no oversize hack — and it is why a
// FRAMES reply can overrun the transport ceiling on perfectly honest traffic.
// The PoW preimage does NOT cover the descriptor (w2_receipt.hpp WorkEvent:
// chain_id, identity, prev_block_hash, prev_own_share, lz_bits, nonce only), so
// mining one of these costs exactly what mining a small one costs.
static PayoutDescriptor big_desc(std::size_t n_aux, std::uint8_t fill) {
    PayoutDescriptor d = mk_desc(fill);
    d.aux.clear();
    d.aux.reserve(n_aux);
    for (std::size_t i = 0; i < n_aux; ++i) {
        std::vector<std::uint8_t> s = {0x76, 0xa9, 0x14};
        for (int k = 0; k < 20; ++k)
            s.push_back(static_cast<std::uint8_t>((i >> (8 * (k % 4))) ^ (k * 7 + fill)));
        s.push_back(0x88);
        s.push_back(0xac);
        ::v37::AuxEntry e;
        e.chain_id = static_cast<std::uint32_t>(i + 1);   // strictly increasing
        e.ref = ::v37::canonicalize_script(s);
        d.aux.push_back(e);
    }
    return d;
}

// Real sha256d grind so the event clears its own bits (identity == the
// descriptor's key, so the W3-MUST binding holds).
static WorkEvent mine(ChainId chain_id, const PayoutDescriptor& desc,
                      u64 origin_bin, const bytes32& prev_own, const char* tag,
                      u64 salt = 0) {
    WorkEvent ev;
    ev.chain_id = chain_id;
    ev.identity = desc.identity_key();
    ev.descriptor = desc;
    ev.prev_block_hash = mainchain_hash(origin_bin);
    ev.prev_own_share = prev_own;
    ev.lz_bits = consensus_lz(origin_bin);
    ev.tag = tag;
    const u64 base = salt << 32;
    for (u64 nonce = base; nonce < base + (u64(1) << 22); ++nonce) {
        ev.nonce = nonce;
        if (ev.meets_own_target()) return ev;
    }
    std::printf("FATAL mine: nonce exhausted (%s)\n", tag);
    std::abort();
}

static CallbackMainchainIndex::Resolver synthetic_index(u64 tip, u64 horizon = 64) {
    auto by_hash = std::make_shared<std::map<bytes32, u64>>();
    const u64 lo = tip > horizon ? tip - horizon : 0;
    for (u64 x = lo; x <= tip; ++x) (*by_hash)[mainchain_hash(x)] = x;
    return [by_hash](const bytes32& h) -> std::optional<u64> {
        auto it = by_hash->find(h);
        return it == by_hash->end() ? std::nullopt : std::optional<u64>(it->second);
    };
}

template <class F>
static bool wait_until(F f, int timeout_ms = 5000) {
    const auto deadline = std::chrono::steady_clock::now() +
                          std::chrono::milliseconds(timeout_ms);
    while (std::chrono::steady_clock::now() < deadline) {
        if (f()) return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    return f();
}

// ── one node = engine + admission + relay + transport + the repair channel ──
struct Node {
    V37Engine engine;
    std::unique_ptr<CallbackMainchainIndex> index;
    MemShareTracker tracker;
    std::unique_ptr<CarrierIngest> ingest;
    std::unique_ptr<CarrierPeerNode> net;
    c2pool::v37n::wire_freeze::PolicyStats policy_stats;
    std::unique_ptr<CarrierRelay> relay;
    std::unique_ptr<SupplyService> serve;
    std::unique_ptr<SupplyRequester> fetch;

    // What the requester's verified-frames callback last delivered.
    std::mutex last_mtx;
    std::vector<VerifiedFrame> last_frames;
    // EVERY verified frame this node was handed, across all chunks of a fetch.
    // A fetch too big for one transport frame arrives as several verified
    // answers, so "did the whole fetch complete?" is a question about this, not
    // about the last callback.
    std::vector<VerifiedFrame> all_frames;
    std::vector<bytes32> unservable_ids;
    std::optional<CtrlOrder> last_order;
    std::vector<SupplyFailure> failures;

    explicit Node(u64 tip, bool with_control = true) {
        engine.start();
        engine.submit_tracked(LaneRecord::add_lane(CHAIN, small_params())).get();
        auto s = engine.snapshot(CHAIN);
        const u64 inc = s ? s->incarnation : 1;
        index  = std::make_unique<CallbackMainchainIndex>(synthetic_index(tip));
        ingest = std::make_unique<CarrierIngest>(engine, CHAIN, *index, tracker, inc);
        net    = std::make_unique<CarrierPeerNode>();
        relay  = std::make_unique<CarrierRelay>(ingest->fn(), *net);
        relay->set_frame_policy(c2pool::v37n::wire_freeze::make_relay_policy(&policy_stats));
        net->set_inbound([this](const std::vector<std::uint8_t>& f) {
            relay->handle_inbound(f);
        });
        net->set_on_peer_connect([this] { relay->note_peer_connected(); });

        auto send = [this](CarrierPeerNode::PeerId p,
                           const std::vector<std::uint8_t>& f) {
            return net->send_to(p, f);
        };
        serve = std::make_unique<SupplyService>(relay->vault(), send);
        fetch = std::make_unique<SupplyRequester>(send);
        // The server's claimed spine digest at a prefix. Under ruling A this is
        // an ASSERTION; Stage 2 replays to check it. Here it is our own
        // published projection when we have one.
        serve->set_spine_probe([this](std::uint32_t, std::uint64_t pos)
                                   -> std::optional<bytes32> {
            auto snap = engine.snapshot(CHAIN);
            if (snap && snap->next_pos == pos) return snap->digest;
            return std::nullopt;
        });
        fetch->set_on_order([this](CarrierPeerNode::PeerId, const CtrlOrder& o) {
            std::lock_guard<std::mutex> lk(last_mtx);
            last_order = o;
        });
        fetch->set_on_frames([this](CarrierPeerNode::PeerId,
                                    const std::vector<VerifiedFrame>& v) {
            std::lock_guard<std::mutex> lk(last_mtx);
            last_frames = v;
            all_frames.insert(all_frames.end(), v.begin(), v.end());
        });
        fetch->set_on_unservable([this](CarrierPeerNode::PeerId,
                                        const std::vector<bytes32>& ids) {
            std::lock_guard<std::mutex> lk(last_mtx);
            unservable_ids.insert(unservable_ids.end(), ids.begin(), ids.end());
        });
        fetch->set_on_fail([this](CarrierPeerNode::PeerId, SupplyFailure f) {
            std::lock_guard<std::mutex> lk(last_mtx);
            failures.push_back(f);
        });
        if (with_control) {
            // BOTH halves on the one demux point: requests -> the server,
            // responses -> the requester. Each ignores what is not its own.
            net->set_control([this](CarrierPeerNode::PeerId p,
                                    const std::vector<std::uint8_t>& f) {
                serve->on_control(p, f);
                fetch->on_control(p, f);
            });
        }
        net->set_on_peer_event([this](CarrierPeerNode::PeerId p, bool up) {
            if (!up) { serve->forget_peer(p); fetch->forget_peer(p); }
        });
    }
    ~Node() { if (net) net->stop(); engine.stop(); }

    u64 raw_total() { auto s = engine.snapshot(CHAIN); return s ? (u64)s->raw_total : 0; }
    u64 next_pos()  { auto s = engine.snapshot(CHAIN); return s ? s->next_pos : 0; }
    ::v37::bytes32 lane_digest() {
        auto s = engine.snapshot(CHAIN);
        return s ? s->digest : ::v37::bytes32{};
    }
    std::uint64_t pushes() const { return ingest->pushes_forwarded(); }

    std::size_t n_frames() { std::lock_guard<std::mutex> lk(last_mtx); return last_frames.size(); }
    std::size_t n_all_frames() { std::lock_guard<std::mutex> lk(last_mtx); return all_frames.size(); }
    std::size_t n_unservable() { std::lock_guard<std::mutex> lk(last_mtx); return unservable_ids.size(); }
    std::size_t n_failures() { std::lock_guard<std::mutex> lk(last_mtx); return failures.size(); }
    bool saw_failure(SupplyFailure f) {
        std::lock_guard<std::mutex> lk(last_mtx);
        for (SupplyFailure x : failures) if (x == f) return true;
        return false;
    }
};

// Mine + admit `n` carriers locally on `node` under `desc`, in lane order.
static std::vector<WorkEvent> fill_lane_desc(Node& node, int n, const char* tag,
                                             const PayoutDescriptor& desc) {
    std::vector<WorkEvent> out;
    bytes32 prev = W2_GENESIS_PREV_OWN;
    for (int i = 0; i < n; ++i) {
        const WorkEvent s = mine(CHAIN, desc, 100, prev, tag,
                                 static_cast<u64>(i + 1));
        prev = s.hash();
        Carrier c; c.carrier = s;
        const CarrierRelay::Outcome o = node.relay->handle_local(c);
        if (!o.admitted) { std::printf("FATAL fill_lane: not admitted\n"); std::abort(); }
        out.push_back(s);
    }
    (void)wait_until([&] { return node.next_pos() == static_cast<u64>(n); });
    return out;
}
static std::vector<WorkEvent> fill_lane(Node& node, int n, const char* tag) {
    return fill_lane_desc(node, n, tag, ALICE_DESC());
}

// ═══════════════════════════════════════════════════════════════════════════
// CS-1 — the unified FrameVault: position index + hash index + bounded
// retention, and the re-offer riding it as a shallow sub-view.
// ═══════════════════════════════════════════════════════════════════════════
static void test_cs1_vault_unified() {
    std::printf("-- CS-1 unified FrameVault: position index, hash index, one copy\n");
    Node A(110);
    const std::vector<WorkEvent> mined = fill_lane(A, 6, "cs1");

    // ★ the row that exists nowhere else in the tree: (chain, pos) -> carrier id.
    const VaultOrder vo = A.relay->vault().serve_order(CHAIN, 0, 6, 64);
    CHECK(vo.status == VaultOrderStatus::OK);
    CHECK(vo.p_served == 6);
    CHECK(vo.ids.size() == 6);
    for (std::size_t i = 0; i < vo.ids.size() && i < mined.size(); ++i) {
        CHECK(vo.ids[i].pos == i);                       // strictly increasing
        CHECK(vo.ids[i].id == mined[i].hash());          // in LANE ORDER
    }

    // A strict sub-range serves exactly that sub-range.
    const VaultOrder mid = A.relay->vault().serve_order(CHAIN, 2, 5, 64);
    CHECK(mid.status == VaultOrderStatus::OK);
    CHECK(mid.ids.size() == 3);
    CHECK(mid.ids.front().pos == 2);
    CHECK(mid.ids.back().pos == 4);

    // The asker's own bound truncates, and p_served tells the truth about it.
    const VaultOrder cut = A.relay->vault().serve_order(CHAIN, 0, 6, 2);
    CHECK(cut.ids.size() == 2);
    CHECK(cut.p_served == 2);                            // never claims coverage it did not serve

    // The hash index resolves the same carriers to their EXACT frame bytes.
    std::vector<bytes32> ids;
    for (const auto& x : vo.ids) ids.push_back(x.id);
    std::vector<std::pair<bytes32, std::vector<std::uint8_t>>> got;
    CHECK(A.relay->vault().serve_frames(ids, 64, 1u << 20, got) == 6);
    for (std::size_t i = 0; i < got.size() && i < mined.size(); ++i) {
        Carrier c; c.carrier = mined[i];
        CHECK(got[i].first == mined[i].hash());
        CHECK(got[i].second == CarrierWire::encode(c));  // verbatim, not re-derived
    }

    // The re-offer is a SUB-VIEW of the same store, not a second copy: it holds
    // slot references, and its own counters still work exactly as before.
    CHECK(A.relay->reoffer_pending() == 6);
    CHECK(A.relay->reoffer_stats().buffered == 6);
    CHECK(A.relay->vault().size() == 6);
    CHECK(A.relay->vault().stats().inserted == 6);
    // Each frame entered the vault ONCE (admission), then was REFRESHED by the
    // broadcast path — not stored a second time.
    CHECK(A.relay->vault().stats().refreshed >= 6);
}

// ═══════════════════════════════════════════════════════════════════════════
// CS-2 — serve -> fetch -> verify over real sockets. B learns A's order at a
// cut, fetches the bytes, and every byte verifies against the id it asked for.
// ═══════════════════════════════════════════════════════════════════════════
static void test_cs2_roundtrip() {
    std::printf("-- CS-2 GETORDER -> GETFRAMES -> verify round-trip\n");
    Node A(110), B(110);
    const std::vector<WorkEvent> mined = fill_lane(A, 5, "cs2");

    CHECK(A.net->listen("127.0.0.1", 0));
    CHECK(B.net->add_peer("127.0.0.1", A.net->listen_port()));
    CHECK(wait_until([&] { return B.net->n_peers() == 1 && A.net->n_peers() == 1; }));
    const auto bpeers = B.net->peer_ids();
    CHECK(bpeers.size() == 1);
    if (bpeers.empty()) return;
    const CarrierPeerNode::PeerId pa = bpeers.front();

    // ── GETORDER at the cut (chain, P=5). `a` is the last prefix B trusts.
    CHECK(B.fetch->request_order(pa, CHAIN, 0, 5, B.lane_digest(), 64));
    CHECK(wait_until([&] {
        std::lock_guard<std::mutex> lk(B.last_mtx);
        return B.last_order.has_value();
    }));
    std::vector<bytes32> want;
    {
        std::lock_guard<std::mutex> lk(B.last_mtx);
        CHECK(B.last_order.has_value());
        if (!B.last_order) return;
        CHECK(B.last_order->status == CtrlOrderStatus::OK);
        CHECK(B.last_order->a == 0);
        CHECK(B.last_order->p_served == 5);
        CHECK(B.last_order->ids.size() == 5);
        // ★ the served order is A's ORDER: the exact ids, at the exact positions.
        for (std::size_t i = 0; i < B.last_order->ids.size() && i < mined.size(); ++i) {
            CHECK(B.last_order->ids[i].pos == i);
            CHECK(B.last_order->ids[i].id == mined[i].hash());
        }
        // A asserts its spine digest at the prefix it served (ruling A: an
        // assertion; Stage 2 replays to check it).
        CHECK(B.last_order->have_spine);
        for (const auto& x : B.last_order->ids) want.push_back(x.id);
    }
    CHECK(B.fetch->stats().orders_ok == 1);
    CHECK(!B.fetch->busy(pa));                     // the slot was released

    // ── GETFRAMES for those ids.
    CHECK(B.fetch->request_frames(pa, CHAIN, want));
    CHECK(wait_until([&] { return B.n_frames() == 5; }));
    {
        std::lock_guard<std::mutex> lk(B.last_mtx);
        CHECK(B.last_frames.size() == 5);
        for (std::size_t i = 0; i < B.last_frames.size() && i < mined.size(); ++i) {
            Carrier c; c.carrier = mined[i];
            CHECK(B.last_frames[i].id == mined[i].hash());
            CHECK(B.last_frames[i].frame == CarrierWire::encode(c));  // EXACT bytes
            // ★ the verification the requester did, restated: the id IS the
            // carrier's WorkEvent::hash, recomputed from the bytes.
            CHECK(B.last_frames[i].carrier.carrier.hash() == B.last_frames[i].id);
        }
    }
    CHECK(B.fetch->stats().frames_ok == 1);
    CHECK(B.fetch->stats().frames_verified == 5);
    CHECK(B.fetch->stats().hash_mismatch == 0);
    CHECK(B.fetch->stats().missing_id == 0);
    CHECK(B.n_failures() == 0);

    // ★ NO APPLY. Stage 1 supplies bytes; it does not admit them. B's lane is
    // exactly where it was — this suite never calls handle_inbound on a fetched
    // frame, never folds, and never touches the ledger.
    CHECK(B.next_pos() == 0);
    CHECK(B.raw_total() == 0);
    CHECK(B.pushes() == 0);

    CHECK(A.serve->stats().order_served == 1);
    CHECK(A.serve->stats().frames_served == 1);
}

// ═══════════════════════════════════════════════════════════════════════════
// CS-3 — a LYING peer. The server is replaced by a hand-built FRAMES reply that
// answers with the RIGHT ids and the WRONG bytes. Fail-closed.
// ═══════════════════════════════════════════════════════════════════════════
static void test_cs3_lying_peer_fail_closed() {
    std::printf("-- CS-3 lying peer (wrong bytes for an id) is FAIL-CLOSED\n");
    Node B(110);

    // Two real carriers. B will ask for BOTH ids; the "peer" answers with
    // carrier #2's bytes under carrier #1's id.
    const WorkEvent s1 = mine(CHAIN, ALICE_DESC(), 100, W2_GENESIS_PREV_OWN, "cs3.a", 1);
    const WorkEvent s2 = mine(CHAIN, ALICE_DESC(), 100, s1.hash(), "cs3.b", 2);
    Carrier c1; c1.carrier = s1;
    Carrier c2; c2.carrier = s2;

    // A loopback "peer" that we drive by hand: B dials it, so B has a PeerId,
    // and we answer B's GETFRAMES from a raw socket with forged bytes.
    std::atomic<bool> done{false};
    std::atomic<std::uint16_t> port{0};
    std::thread liar([&] {
        const int ls = ::socket(AF_INET, SOCK_STREAM, 0);
        int one = 1;
        ::setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
        sockaddr_in a{};
        a.sin_family = AF_INET;
        a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        a.sin_port = 0;
        ::bind(ls, reinterpret_cast<sockaddr*>(&a), sizeof(a));
        socklen_t alen = sizeof(a);
        ::getsockname(ls, reinterpret_cast<sockaddr*>(&a), &alen);
        port.store(ntohs(a.sin_port));
        ::listen(ls, 4);
        const int cs = ::accept(ls, nullptr, nullptr);
        if (cs < 0) { ::close(ls); done.store(true); return; }
        // read one framed request
        std::uint8_t lb[4];
        std::size_t off = 0;
        while (off < 4) { ssize_t k = ::recv(cs, lb + off, 4 - off, 0); if (k <= 0) break; off += (std::size_t)k; }
        std::uint32_t len = 0;
        for (int i = 0; i < 4; ++i) len |= (std::uint32_t)lb[i] << (8 * i);
        std::vector<std::uint8_t> req(len);
        off = 0;
        while (off < len) { ssize_t k = ::recv(cs, req.data() + off, len - off, 0); if (k <= 0) break; off += (std::size_t)k; }
        CtrlGetFrames q;
        if (CtrlWire::decode(req, q) && q.ids.size() == 2) {
            CtrlFrames r;
            r.request_id = q.request_id;
            r.chain = q.chain;
            // A well-formed COMPLETE answer covering the whole ask — the lie is
            // in the BYTES, not in the framing, so the hash binding is what has
            // to catch it.
            r.status = CtrlFramesStatus::COMPLETE;
            r.cursor = static_cast<std::uint16_t>(q.ids.size());
            // ★ THE LIE: id[0] is s1's hash, the bytes are s2's frame.
            r.frames.emplace_back(q.ids[0], CarrierWire::encode(c2));
            r.frames.emplace_back(q.ids[1], CarrierWire::encode(c2));
            const std::vector<std::uint8_t> out = CtrlWire::encode(r);
            std::uint8_t ob[4];
            const std::uint32_t ol = (std::uint32_t)out.size();
            for (int i = 0; i < 4; ++i) ob[i] = (std::uint8_t)(ol >> (8 * i));
            ::send(cs, ob, 4, MSG_NOSIGNAL);
            ::send(cs, out.data(), out.size(), MSG_NOSIGNAL);
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(300));
        ::close(cs);
        ::close(ls);
        done.store(true);
    });
    CHECK(wait_until([&] { return port.load() != 0; }));
    CHECK(B.net->add_peer("127.0.0.1", port.load()));
    CHECK(wait_until([&] { return !B.net->peer_ids().empty(); }));
    const auto pl = B.net->peer_ids();
    if (pl.empty()) { done.store(true); liar.join(); return; }

    CHECK(B.fetch->request_frames(pl.front(), CHAIN, {s1.hash(), s2.hash()}));
    CHECK(wait_until([&] { return B.n_failures() > 0; }));

    // ★ FAIL-CLOSED: the hash mismatch is caught, the WHOLE response is
    // rejected, and NOTHING is handed on — not even the frame that was honest.
    CHECK(B.saw_failure(SupplyFailure::HASH_MISMATCH));
    CHECK(B.fetch->stats().hash_mismatch == 1);
    CHECK(B.fetch->stats().frames_ok == 0);
    CHECK(B.fetch->stats().frames_verified == 0);
    CHECK(B.n_frames() == 0);
    // And nothing was admitted anywhere: this layer does not apply.
    CHECK(B.next_pos() == 0);

    done.store(true);
    liar.join();
}

// ═══════════════════════════════════════════════════════════════════════════
// CS-4 — a MISSING id is fail-closed, and so is a peer that never answers.
// ═══════════════════════════════════════════════════════════════════════════
static void test_cs4_missing_and_timeout_fail_closed() {
    std::printf("-- CS-4 missing id + no answer are FAIL-CLOSED\n");

    // (a) MISSING ID: A holds only the first carrier; B asks for two.
    {
        Node A(110), B(110);
        const std::vector<WorkEvent> held = fill_lane(A, 1, "cs4a");
        const WorkEvent absent = mine(CHAIN, ALICE_DESC(), 100, held[0].hash(), "cs4a.x", 9);

        CHECK(A.net->listen("127.0.0.1", 0));
        CHECK(B.net->add_peer("127.0.0.1", A.net->listen_port()));
        CHECK(wait_until([&] { return !B.net->peer_ids().empty(); }));
        const auto pl = B.net->peer_ids();
        if (pl.empty()) return;

        CHECK(B.fetch->request_frames(pl.front(), CHAIN,
                                      {held[0].hash(), absent.hash()}));
        CHECK(wait_until([&] { return B.n_failures() > 0; }));
        CHECK(B.saw_failure(SupplyFailure::MISSING_ID));
        CHECK(B.fetch->stats().missing_id == 1);
        CHECK(B.fetch->stats().frames_ok == 0);
        CHECK(B.n_frames() == 0);                 // ★ the honest frame is NOT kept
        // The SERVER told the truth: it simply omitted what it does not hold.
        CHECK(A.relay->vault().stats().frames_missing >= 1);
    }

    // (b) NO ANSWER: a peer that accepts the connection and says nothing. The
    //     request expires at request_timeout; the peer is NOT dropped.
    {
        Node B(110);
        std::atomic<bool> done{false};
        std::atomic<std::uint16_t> port{0};
        std::thread mute([&] {
            const int ls = ::socket(AF_INET, SOCK_STREAM, 0);
            int one = 1;
            ::setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
            sockaddr_in a{};
            a.sin_family = AF_INET;
            a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            ::bind(ls, reinterpret_cast<sockaddr*>(&a), sizeof(a));
            socklen_t alen = sizeof(a);
            ::getsockname(ls, reinterpret_cast<sockaddr*>(&a), &alen);
            port.store(ntohs(a.sin_port));
            ::listen(ls, 4);
            const int cs = ::accept(ls, nullptr, nullptr);
            while (!done.load()) std::this_thread::sleep_for(std::chrono::milliseconds(10));
            if (cs >= 0) ::close(cs);
            ::close(ls);
        });
        CHECK(wait_until([&] { return port.load() != 0; }));
        SupplyFetchOptions fo;
        fo.request_timeout = std::chrono::milliseconds(50);
        B.fetch->set_options(fo);
        CHECK(B.net->add_peer("127.0.0.1", port.load()));
        CHECK(wait_until([&] { return !B.net->peer_ids().empty(); }));
        const auto pl = B.net->peer_ids();
        if (!pl.empty()) {
            CHECK(B.fetch->request_order(pl.front(), CHAIN, 0, 4, bytes32{}, 8));
            CHECK(B.fetch->busy(pl.front()));
            std::this_thread::sleep_for(std::chrono::milliseconds(120));
            CHECK(B.fetch->tick() == 1);                  // ★ bounded wait, not forever
            CHECK(B.fetch->stats().timeouts == 1);
            CHECK(B.saw_failure(SupplyFailure::TIMEOUT));
            CHECK(!B.fetch->busy(pl.front()));            // the slot is free again
            CHECK(B.net->n_peers() == 1);                 // ★ and the peer is NOT dropped
        }
        done.store(true);
        mute.join();
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// CS-5 — the bounds. Vault entry / byte / horizon caps; the per-peer token
// bucket; one outstanding request per peer; an unsolicited answer.
// ═══════════════════════════════════════════════════════════════════════════
static void test_cs5_bounds() {
    std::printf("-- CS-5 vault bounds + token bucket + one-outstanding + unsolicited\n");

    // (a) ENTRY CAP.
    {
        FrameVault v;
        FrameVaultOptions o;
        o.max_entries = 4;
        v.set_options(o);
        for (int i = 0; i < 10; ++i) {
            bytes32 h{};
            h[0] = static_cast<std::uint8_t>(i);
            v.insert(CHAIN, h, static_cast<std::uint64_t>(i), 1,
                     std::vector<std::uint8_t>(32, 0xaa));
        }
        CHECK(v.size() == 4);
        CHECK(v.stats().evicted_capacity == 6);
        CHECK(v.lowest_position() == 6);
    }
    // (b) BYTE CAP, and a frame bigger than the cap is never retained.
    {
        FrameVault v;
        FrameVaultOptions o;
        o.max_entries = 1000;
        o.max_bytes = 300;
        v.set_options(o);
        for (int i = 0; i < 10; ++i) {
            bytes32 h{};
            h[0] = static_cast<std::uint8_t>(i);
            v.insert(CHAIN, h, static_cast<std::uint64_t>(i), 1,
                     std::vector<std::uint8_t>(100, 0xbb));
        }
        CHECK(v.bytes() <= 300);
        CHECK(v.size() == 3);
        bytes32 big{};
        big[0] = 0xff;
        CHECK(!v.insert(CHAIN, big, 100, 1, std::vector<std::uint8_t>(1000, 0xcc)).has_value());
        CHECK(v.stats().rejected_oversize == 1);
    }
    // (c) WINDOW HORIZON: anything more than `horizon_positions` behind the
    //     highest retained position is evicted, and an `a` below the horizon is
    //     refused rather than answered with a gapped prefix.
    {
        FrameVault v;
        FrameVaultOptions o;
        o.max_entries = 1000;
        o.horizon_positions = 8;
        v.set_options(o);
        for (int i = 0; i < 20; ++i) {
            bytes32 h{};
            h[0] = static_cast<std::uint8_t>(i);
            v.insert(CHAIN, h, static_cast<std::uint64_t>(i), 1,
                     std::vector<std::uint8_t>(16, 0xdd));
        }
        CHECK(v.size() == 8);
        CHECK(v.lowest_position() == 12);
        CHECK(v.highest_position() == 19);
        CHECK(v.stats().evicted_horizon == 12);
        const VaultOrder below = v.serve_order(CHAIN, 0, 20, 64);
        CHECK(below.status == VaultOrderStatus::BELOW_HORIZON);   // ★ never a gapped lie
        CHECK(below.ids.empty());
        const VaultOrder inside = v.serve_order(CHAIN, 12, 20, 64);
        CHECK(inside.status == VaultOrderStatus::OK);
        CHECK(inside.ids.size() == 8);
    }

    // (d) PER-PEER TOKEN BUCKET on the serve side.
    {
        Node A(110), B(110);
        fill_lane(A, 2, "cs5d");
        SupplyServeOptions so;
        so.burst = 2.0;
        so.refill_per_sec = 0.0;                  // no refill inside the test
        A.serve->set_options(so);

        CHECK(A.net->listen("127.0.0.1", 0));
        CHECK(B.net->add_peer("127.0.0.1", A.net->listen_port()));
        CHECK(wait_until([&] { return !B.net->peer_ids().empty(); }));
        const auto pl = B.net->peer_ids();
        if (!pl.empty()) {
            SupplyFetchOptions fo;
            fo.request_timeout = std::chrono::milliseconds(50);
            B.fetch->set_options(fo);
            for (int i = 0; i < 5; ++i) {
                (void)B.fetch->request_order(pl.front(), CHAIN, 0, 2, bytes32{}, 8);
                std::this_thread::sleep_for(std::chrono::milliseconds(30));
                (void)B.fetch->tick();            // release the slot either way
            }
            CHECK(wait_until([&] { return A.serve->stats().throttled >= 1; }));
            CHECK(A.serve->stats().order_served <= 2);   // ★ the bucket held
            CHECK(A.serve->stats().throttled >= 1);
            // A throttled peer gets NOTHING back — zero amplification — and is
            // still connected.
            CHECK(A.net->n_peers() == 1);
        }
    }

    // (e) ONE OUTSTANDING REQUEST PER PEER, and an unsolicited answer.
    {
        Node A(110), B(110);
        fill_lane(A, 3, "cs5e");
        CHECK(A.net->listen("127.0.0.1", 0));
        CHECK(B.net->add_peer("127.0.0.1", A.net->listen_port()));
        CHECK(wait_until([&] { return !B.net->peer_ids().empty(); }));
        const auto pl = B.net->peer_ids();
        if (!pl.empty()) {
            const auto p = pl.front();
            CHECK(B.fetch->request_order(p, CHAIN, 0, 3, bytes32{}, 8));
            CHECK(!B.fetch->request_order(p, CHAIN, 0, 3, bytes32{}, 8));  // ★ refused
            CHECK(B.fetch->stats().refused_busy == 1);
            CHECK(B.fetch->outstanding() == 1);
            CHECK(wait_until([&] { return B.fetch->stats().orders_ok == 1; }));
            CHECK(B.fetch->outstanding() == 0);

            // An ORDER for a request_id nobody asked for is discarded.
            const std::uint64_t before = B.fetch->stats().unsolicited;
            CtrlOrder bogus;
            bogus.request_id = 0xdeadbeef;
            bogus.chain = CHAIN;
            B.fetch->on_control(p, CtrlWire::encode(bogus));
            CHECK(B.fetch->stats().unsolicited == before + 1);
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// CS-6 — FLAP SAFETY. Before Stage 1 the re-offer attempt cap ERASED the entry,
// so a peer that connected and dropped repeatedly (arming forced sweep after
// forced sweep) deleted the only retained copy of carriers a DIFFERENT peer
// still needed. Now the cap retires from the sub-view only.
// ═══════════════════════════════════════════════════════════════════════════
static void test_cs6_flap_cannot_evict() {
    std::printf("-- CS-6 a flapping peer cannot evict another peer's bytes\n");
    Node A(110);
    CarrierReofferOptions ro;
    ro.min_interval = std::chrono::milliseconds(0);
    ro.min_forced_interval = std::chrono::milliseconds(0);
    ro.max_attempts = 2;                          // exhausted quickly
    A.relay->set_reoffer_options(ro);

    const std::vector<WorkEvent> mined = fill_lane(A, 4, "cs6");
    CHECK(A.relay->reoffer_pending() == 4);
    CHECK(A.relay->vault().size() == 4);

    // A peer flaps: connect, drop, connect, drop — each connection arming a
    // forced sweep that burns one attempt on every buffered entry.
    for (int i = 0; i < 4; ++i) {
        Node F(110);
        CHECK(F.net->listen("127.0.0.1", 0));
        CHECK(A.net->add_peer("127.0.0.1", F.net->listen_port()));
        CHECK(wait_until([&] { return A.net->n_peers() >= 1; }));
        A.relay->note_peer_connected();
        (void)A.relay->reoffer_tick();
        F.net->stop();
        CHECK(wait_until([&] { return A.net->n_peers() == 0; }));
    }

    // ★ The re-offer sub-view is exhausted...
    CHECK(A.relay->reoffer_pending() == 0);
    CHECK(A.relay->reoffer_stats().exhausted == 4);
    // ...but the BYTES are still retained, and the ORDER is still servable.
    CHECK(A.relay->vault().size() == 4);
    const VaultOrder vo = A.relay->vault().serve_order(CHAIN, 0, 4, 64);
    CHECK(vo.status == VaultOrderStatus::OK);
    CHECK(vo.ids.size() == 4);
    std::vector<bytes32> ids;
    for (const auto& x : vo.ids) ids.push_back(x.id);
    std::vector<std::pair<bytes32, std::vector<std::uint8_t>>> got;
    CHECK(A.relay->vault().serve_frames(ids, 64, 1u << 20, got) == 4);
    for (std::size_t i = 0; i < got.size() && i < mined.size(); ++i) {
        Carrier c; c.carrier = mined[i];
        CHECK(got[i].second == CarrierWire::encode(c));
    }
    // A flapping peer inserts NOTHING: the vault is written only by our own
    // admissions and broadcasts, so it cannot push anything out by volume.
    CHECK(A.relay->vault().stats().inserted == 4);
    CHECK(A.relay->vault().stats().evicted_capacity == 0);
    CHECK(A.relay->vault().stats().evicted_horizon == 0);
}

// ═══════════════════════════════════════════════════════════════════════════
// CS-7 — BACKWARD TOLERANCE. An OLD peer has no demux: a >= 0x80 frame goes
// straight into CarrierWire::decode. Reproduce the EXACT pre-Stage-1 reader
// loop over a raw socket and prove it keeps the connection.
// ═══════════════════════════════════════════════════════════════════════════
static void test_cs7_old_peer_keeps_socket() {
    std::printf("-- CS-7 an OLD peer meets an opcode, keeps the socket, admits the next carrier\n");

    // The verdict every old peer reaches, stated directly.
    for (std::uint8_t op : {CTRL_GETORDER, CTRL_ORDER, CTRL_GETFRAMES, CTRL_FRAMES,
                            std::uint8_t{0x84}, std::uint8_t{0xff}}) {
        std::vector<std::uint8_t> f{op, kCtrlVersion, 0, 0, 0, 0};
        const DecodeResult dr = CarrierWire::decode(f);
        CHECK(dr.status == WireStatus::REJECT_BAD_VERSION);   // ★ a VERDICT, not a crash
        CHECK(!c2pool::v37n::wire_freeze::version_accepted(op));
    }

    // Now the live half: an old-style listener whose reader loop is verbatim
    // the pre-Stage-1 one (no control demux at all).
    Node old_node(110);
    std::atomic<bool> stop{false};
    std::atomic<std::uint16_t> port{0};
    std::atomic<int> opcode_frames{0};
    std::atomic<int> carrier_frames{0};
    std::atomic<bool> socket_broke{false};
    std::thread legacy([&] {
        const int ls = ::socket(AF_INET, SOCK_STREAM, 0);
        int one = 1;
        ::setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
        sockaddr_in a{};
        a.sin_family = AF_INET;
        a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        ::bind(ls, reinterpret_cast<sockaddr*>(&a), sizeof(a));
        socklen_t alen = sizeof(a);
        ::getsockname(ls, reinterpret_cast<sockaddr*>(&a), &alen);
        port.store(ntohs(a.sin_port));
        ::listen(ls, 4);
        const int cs = ::accept(ls, nullptr, nullptr);
        if (cs < 0) { ::close(ls); return; }
        // ── the EXACT pre-Stage-1 reader loop (carrier_net.hpp on master):
        //    read a frame, hand it to handle_inbound, break ONLY on a short
        //    read or an over-long length. No demux, no opcode awareness.
        for (;;) {
            std::uint8_t lb[4];
            std::size_t off = 0;
            bool ok = true;
            while (off < 4) {
                ssize_t k = ::recv(cs, lb + off, 4 - off, 0);
                if (k <= 0) { ok = false; break; }
                off += static_cast<std::size_t>(k);
            }
            if (!ok) break;
            std::uint32_t len = 0;
            for (int i = 0; i < 4; ++i) len |= static_cast<std::uint32_t>(lb[i]) << (8 * i);
            if (len > kMaxCarrierFrame) { socket_broke.store(true); break; }
            std::vector<std::uint8_t> frame(len);
            off = 0;
            while (off < len) {
                ssize_t k = ::recv(cs, frame.data() + off, len - off, 0);
                if (k <= 0) { ok = false; break; }
                off += static_cast<std::size_t>(k);
            }
            if (!ok) break;
            const CarrierRelay::Outcome o = old_node.relay->handle_inbound(frame);
            if (o.wire == WireStatus::REJECT_BAD_VERSION) opcode_frames.fetch_add(1);
            if (o.admitted) carrier_frames.fetch_add(1);
        }
        ::close(cs);
        ::close(ls);
    });
    CHECK(wait_until([&] { return port.load() != 0; }));

    // Dial it with a plain socket and push: opcode, opcode, then a REAL carrier
    // frame — all down the SAME connection.
    const int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in sa{};
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port.load());
    ::inet_pton(AF_INET, "127.0.0.1", &sa.sin_addr);
    CHECK(::connect(fd, reinterpret_cast<sockaddr*>(&sa), sizeof(sa)) == 0);
    auto send_framed = [&](const std::vector<std::uint8_t>& f) {
        std::uint8_t lb[4];
        const std::uint32_t l = static_cast<std::uint32_t>(f.size());
        for (int i = 0; i < 4; ++i) lb[i] = static_cast<std::uint8_t>(l >> (8 * i));
        return ::send(fd, lb, 4, MSG_NOSIGNAL) == 4 &&
               ::send(fd, f.data(), f.size(), MSG_NOSIGNAL) ==
                   static_cast<ssize_t>(f.size());
    };
    CtrlGetOrder q;
    q.request_id = 7;
    q.chain = CHAIN;
    q.a = 0;
    q.p = 4;
    CHECK(send_framed(CtrlWire::encode(q)));
    CtrlGetFrames q2;
    q2.request_id = 8;
    q2.chain = CHAIN;
    q2.ids.push_back(bytes32{});
    CHECK(send_framed(CtrlWire::encode(q2)));
    CHECK(wait_until([&] { return opcode_frames.load() == 2; }));

    // ★ THE POINT: the socket is still up, and the very next CARRIER frame is
    // admitted normally.
    const WorkEvent s = mine(CHAIN, ALICE_DESC(), 100, W2_GENESIS_PREV_OWN, "cs7");
    Carrier c; c.carrier = s;
    CHECK(send_framed(CarrierWire::encode(c)));
    CHECK(wait_until([&] { return carrier_frames.load() == 1; }));
    CHECK(!socket_broke.load());
    CHECK(old_node.next_pos() == 1);

    stop.store(true);
    ::shutdown(fd, SHUT_RDWR);
    ::close(fd);
    legacy.join();

    // The other direction: a repair-aware node meeting an opcode it does NOT
    // implement counts it and keeps the peer.
    {
        Node R(110);
        std::vector<std::uint8_t> future{0x9a, kCtrlVersion, 1, 0, 0, 0};
        R.serve->on_control(1, future);
        CHECK(R.serve->stats().unknown_opcode == 1);
        R.fetch->on_control(1, future);            // not a response: silently ignored
        CHECK(R.fetch->stats().malformed == 0);
    }
    // And a node with the demux but NO control handler bound ignores-and-counts
    // rather than dropping: that is CarrierPeerNode::ctrl_frames_ignored().
    {
        Node deaf(110, /*with_control=*/false);
        CHECK(deaf.net->listen("127.0.0.1", 0));
        const int dfd = ::socket(AF_INET, SOCK_STREAM, 0);
        sockaddr_in da{};
        da.sin_family = AF_INET;
        da.sin_port = htons(deaf.net->listen_port());
        ::inet_pton(AF_INET, "127.0.0.1", &da.sin_addr);
        CHECK(::connect(dfd, reinterpret_cast<sockaddr*>(&da), sizeof(da)) == 0);
        CHECK(wait_until([&] { return deaf.net->n_peers() == 1; }));
        const std::vector<std::uint8_t> f = CtrlWire::encode(q);
        std::uint8_t lb[4];
        const std::uint32_t l = static_cast<std::uint32_t>(f.size());
        for (int i = 0; i < 4; ++i) lb[i] = static_cast<std::uint8_t>(l >> (8 * i));
        CHECK(::send(dfd, lb, 4, MSG_NOSIGNAL) == 4);
        CHECK(::send(dfd, f.data(), f.size(), MSG_NOSIGNAL) ==
              static_cast<ssize_t>(f.size()));
        CHECK(wait_until([&] { return deaf.net->ctrl_frames_ignored() == 1; }));
        CHECK(deaf.net->n_peers() == 1);           // ★ never dropped
        ::shutdown(dfd, SHUT_RDWR);
        ::close(dfd);
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// CS-8 — ZERO CONSENSUS MOVEMENT.
// ═══════════════════════════════════════════════════════════════════════════
static void test_cs8_zero_consensus_movement() {
    std::printf("-- CS-8 no wire version, no golden move, no digest move\n");

    // (a) The opcodes are NOT wire versions. kAcceptedVersions is exactly
    //     {0x01, 0x02}, and every opcode is >= 0x80, so the two ranges cannot
    //     overlap by construction.
    CHECK(std::size(c2pool::v37n::wire_freeze::kAcceptedVersions) == 2);
    CHECK(c2pool::v37n::wire_freeze::version_accepted(W3_WIRE_VERSION_V1));
    CHECK(c2pool::v37n::wire_freeze::version_accepted(W3_WIRE_VERSION_V2));
    CHECK(W3_WIRE_VERSION_V1 < kCtrlOpcodeBase);
    CHECK(W3_WIRE_VERSION_V2 < kCtrlOpcodeBase);
    for (unsigned v = kCtrlOpcodeBase; v <= 0xff; ++v)
        CHECK(!c2pool::v37n::wire_freeze::version_accepted(static_cast<std::uint8_t>(v)));

    // (b) The FROZEN v0x01 / v0x02 encodings are byte-identical. The freeze KAT
    //     owns the full golden set; this re-runs the SAME encoder over a carrier
    //     built here so a regression in this branch shows up in this suite too.
    const WorkEvent s = mine(CHAIN, ALICE_DESC(), 100, W2_GENESIS_PREV_OWN, "cs8");
    Carrier c; c.carrier = s;
    const std::vector<std::uint8_t> v1 = CarrierWire::encode_version(c, W3_WIRE_VERSION_V1);
    const std::vector<std::uint8_t> v2 = CarrierWire::encode_version(c, W3_WIRE_VERSION_V2);
    CHECK(!v1.empty());
    CHECK(v1[0] == W3_WIRE_VERSION_V1);
    CHECK(v2[0] == W3_WIRE_VERSION_V2);
    // v0x02 is the v0x01 body VERBATIM plus a one-byte "no cut" trailer.
    CHECK(v2.size() == v1.size() + 1);
    CHECK(std::equal(v1.begin() + 1, v1.end(), v2.begin() + 1));
    CHECK(v2.back() == 0);
    CHECK(CarrierWire::decode(v1).ok());
    CHECK(CarrierWire::decode(v2).ok());

    // (c) A full serve/fetch round-trip moves NO consensus byte on either side.
    Node A(110), B(110);
    const std::vector<WorkEvent> mined = fill_lane(A, 3, "cs8r");

    c2pool::v37n::settle::OwedLedger ledger(CHAIN);
    c2pool::v37n::settle::OwedLedger::Amounts credit, payout;
    credit[ALICE_DESC().identity_key()] = 5000;
    ledger.on_block_found("cs8-block", credit, payout);
    ledger.on_block_finalized("cs8-block", 110);
    const ::v37::bytes32 owed_before = ledger.owed_digest();
    const u64 seq_before = ledger.ledger_seq();

    const u64 a_pos = A.next_pos(), b_pos = B.next_pos();
    const ::v37::bytes32 a_dig = A.lane_digest(), b_dig = B.lane_digest();
    const u64 a_raw = A.raw_total(), b_raw = B.raw_total();

    CHECK(A.net->listen("127.0.0.1", 0));
    CHECK(B.net->add_peer("127.0.0.1", A.net->listen_port()));
    CHECK(wait_until([&] { return !B.net->peer_ids().empty(); }));
    const auto pl = B.net->peer_ids();
    if (!pl.empty()) {
        CHECK(B.fetch->request_order(pl.front(), CHAIN, 0, 3, b_dig, 64));
        CHECK(wait_until([&] { return B.fetch->stats().orders_ok == 1; }));
        std::vector<bytes32> ids;
        {
            std::lock_guard<std::mutex> lk(B.last_mtx);
            if (B.last_order) for (const auto& x : B.last_order->ids) ids.push_back(x.id);
        }
        CHECK(ids.size() == 3);
        CHECK(B.fetch->request_frames(pl.front(), CHAIN, ids));
        CHECK(wait_until([&] { return B.n_frames() == 3; }));
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(150));

    // ★ Byte-identical on BOTH sides. Supplying is not applying: B holds three
    // verified carrier frames and has appended NOTHING.
    CHECK(A.next_pos() == a_pos);
    CHECK(A.lane_digest() == a_dig);
    CHECK(A.raw_total() == a_raw);
    CHECK(B.next_pos() == b_pos);
    CHECK(B.lane_digest() == b_dig);
    CHECK(B.raw_total() == b_raw);
    CHECK(B.pushes() == 0);
    CHECK(ledger.owed_digest() == owed_before);
    CHECK(ledger.ledger_seq() == seq_before);
    CHECK(B.n_frames() == 3);                     // the bytes ARE here, unapplied
}

// ═══════════════════════════════════════════════════════════════════════════
// CS-9 — THE TRANSPORT CEILING. Before this, kCtrlMaxReplyBytes was 4 MiB while
// carrier_net.hpp refuses anything over kMaxCarrierFrame = 1 MiB by BREAKING
// the socket. Measured on c2pool#1656 head f1286d18: a 20 x 64 KiB FRAMES reply
// encodes to 1,311,452 bytes, and sending it took the honest requester's
// n_peers from 1 to 0 — the honest server was hard-dropped for answering the
// question it was asked. A 10 x 64 KiB reply (655,732 B) was delivered fine, so
// the failure was purely the size.
//
// This pins the fix, in three parts:
//   (a) ARITHMETIC — the budget is DERIVED from the transport ceiling, and the
//       largest reply the encoder can build still fits under it.
//   (b) CONTINUATION — a fetch whose frames do not fit in one reply now
//       COMPLETES, by chunking, with the honest server KEPT.
//   (c) UN-SERVABLE — a single frame that ALONE exceeds the ceiling comes back
//       as an explicit status, distinct from a missing id, with no stall and no
//       peer drop.
// ═══════════════════════════════════════════════════════════════════════════
static void test_cs9_reply_ceiling_and_continuation() {
    std::printf("-- CS-9 reply ceiling + chunked continuation + un-servable id\n");

    // ── (a) THE ARITHMETIC. The budget is below the transport ceiling, and the
    //        WORST-CASE reply — every id un-servable AND a full payload — still
    //        encodes under it.
    CHECK(kCtrlMaxReplyBytes < static_cast<std::size_t>(kMaxCarrierFrame));
    CHECK(kCtrlFramesReserved + kCtrlMaxReplyBytes <= static_cast<std::size_t>(kMaxCarrierFrame));
    {
        CtrlFrames worst;
        worst.request_id = 1;
        worst.chain = CHAIN;
        worst.status = CtrlFramesStatus::TRUNCATED;
        worst.cursor = kCtrlMaxIdsPerFetch;
        const std::size_t each = kCtrlMaxReplyBytes / kCtrlMaxIdsPerFetch;
        for (std::size_t i = 0; i < kCtrlMaxIdsPerFetch; ++i) {
            bytes32 id{};
            id[0] = static_cast<std::uint8_t>(i);
            id[1] = 0x5a;
            worst.unservable.push_back(id);
            bytes32 fid{};
            fid[0] = static_cast<std::uint8_t>(i);
            fid[1] = 0xa5;
            worst.frames.emplace_back(fid, std::vector<std::uint8_t>(each, 0xcd));
        }
        const std::vector<std::uint8_t> enc = CtrlWire::encode(worst);
        CHECK(CtrlWire::encoded_size(worst) == enc.size());       // the prediction is exact
        CHECK(enc.size() <= static_cast<std::size_t>(kMaxCarrierFrame));   // ★ never over the ceiling
        CtrlFrames back;
        CHECK(CtrlWire::decode(enc, back));                        // and it round-trips
        CHECK(back.status == CtrlFramesStatus::TRUNCATED);
        CHECK(back.cursor == kCtrlMaxIdsPerFetch);
        CHECK(back.unservable.size() == kCtrlMaxIdsPerFetch);
        CHECK(back.frames.size() == kCtrlMaxIdsPerFetch);
    }
    {
        CtrlOrder worst;                                           // ORDER too
        worst.request_id = 2;
        worst.chain = CHAIN;
        worst.ids.resize(kCtrlMaxIdsPerOrder);
        for (std::size_t i = 0; i < worst.ids.size(); ++i) worst.ids[i].pos = i;
        const std::vector<std::uint8_t> enc = CtrlWire::encode(worst);
        CHECK(CtrlWire::encoded_size(worst) == enc.size());
        CHECK(enc.size() <= static_cast<std::size_t>(kMaxCarrierFrame));
    }
    {
        // An option set above the ceiling is CLAMPED, not honoured: the old
        // 4 MiB value cannot be restored through the options struct.
        SupplyServeOptions o;
        o.max_reply_bytes = 4u << 20;
        CHECK(clamped_reply_budget(o) == kCtrlMaxReplyBytes);
        o.max_ids_per_fetch = 4096;
        CHECK(clamped_frames_per_reply(o) == kCtrlMaxIdsPerFetch);
        o.max_ids_per_fetch = 0;                                   // and never zero
        CHECK(clamped_frames_per_reply(o) == 1);
    }

    // ── (b) THE CONTINUATION. 20 carriers whose frames are ~64 KiB each: their
    //        bytes total MORE than the whole transport ceiling, so they cannot
    //        be one reply. The fetch must still complete, and the server must
    //        still be there afterwards.
    {
        Node A(110), B(110);
        const PayoutDescriptor big = big_desc(2520, 0x33);
        const std::vector<WorkEvent> mined = fill_lane_desc(A, 20, "cs9b", big);
        CHECK(mined.size() == 20);

        std::size_t total_bytes = 0;
        std::vector<bytes32> ids;
        for (const WorkEvent& s : mined) {
            Carrier c; c.carrier = s;
            total_bytes += CarrierWire::encode(c).size();
            ids.push_back(s.hash());
        }
        // ★ THE PRECONDITION OF THE BUG: one reply carrying all of these would
        //   be over the ceiling, which is exactly what used to drop the peer.
        CHECK(total_bytes > static_cast<std::size_t>(kMaxCarrierFrame));
        CHECK(ids.size() <= kCtrlMaxIdsPerFetch);   // ONE ask, not pre-split by us

        CHECK(A.net->listen("127.0.0.1", 0));
        CHECK(B.net->add_peer("127.0.0.1", A.net->listen_port()));
        CHECK(wait_until([&] { return B.net->n_peers() == 1 && A.net->n_peers() == 1; }));
        const auto pl = B.net->peer_ids();
        CHECK(!pl.empty());
        if (!pl.empty()) {
            CHECK(B.fetch->request_frames(pl.front(), CHAIN, ids));
            // ★ IT COMPLETES. Not "the first chunk arrives" — all 20.
            CHECK(wait_until([&] { return B.n_all_frames() == 20; }, 20000));
            CHECK(B.n_all_frames() == 20);
            CHECK(B.fetch->stats().frames_verified == 20);
            CHECK(B.fetch->stats().fetches_completed == 1);
            CHECK(B.fetch->stats().truncated_replies >= 1);  // it really was split
            CHECK(B.fetch->stats().continuations >= 1);
            CHECK(B.fetch->stats().continuation_limit == 0);
            CHECK(B.fetch->stats().missing_id == 0);
            CHECK(B.fetch->stats().hash_mismatch == 0);
            CHECK(B.fetch->stats().unservable_id == 0);
            CHECK(B.n_failures() == 0);
            CHECK(!B.fetch->busy(pl.front()));               // no slot left pinned

            // Every byte is the exact retained frame, id-bound as always.
            {
                std::lock_guard<std::mutex> lk(B.last_mtx);
                std::size_t matched = 0;
                for (const WorkEvent& s : mined) {
                    Carrier c; c.carrier = s;
                    const std::vector<std::uint8_t> want = CarrierWire::encode(c);
                    for (const VerifiedFrame& v : B.all_frames)
                        if (v.id == s.hash() && v.frame == want &&
                            v.carrier.carrier.hash() == v.id) { ++matched; break; }
                }
                CHECK(matched == 20);
            }

            // ★ THE REGRESSION ASSERTION: the honest server is STILL CONNECTED.
            //   This is the check that fails on head f1286d18 (n_peers 1 -> 0).
            CHECK(B.net->n_peers() == 1);
            CHECK(A.net->n_peers() == 1);
            CHECK(A.serve->stats().frames_truncated >= 1);
            CHECK(A.serve->stats().reply_oversize == 0);     // never even built one
            CHECK(A.net->sends_refused_oversize() == 0);     // and never refused one
            CHECK(A.relay->vault().stats().frames_truncated >= 1);
        }
        // Supplying is still not applying.
        CHECK(B.next_pos() == 0);
        CHECK(B.raw_total() == 0);
        CHECK(B.pushes() == 0);
    }

    // ── (c) THE UN-SERVABLE FRAME. One retained frame is alone over the
    //        budget: no chunking can ever deliver it. It must be NAMED, not
    //        silently dropped (which would read as MISSING_ID and stall the
    //        caller forever) and not fatal to the peer.
    {
        Node A(110), B(110);
        const std::vector<WorkEvent> mined = fill_lane(A, 1, "cs9c");
        CHECK(mined.size() == 1);

        // A frame the vault will hold but the channel can never carry.
        bytes32 huge_id{};
        huge_id[0] = 0xde; huge_id[1] = 0xad; huge_id[31] = 0x01;
        const std::vector<std::uint8_t> huge(kCtrlMaxReplyBytes + 1, 0x7e);
        CHECK(A.relay->vault().insert(CHAIN, huge_id, FrameVault::kNoPos, 1, huge).has_value());
        CHECK(A.relay->vault().holds(huge_id));

        CHECK(A.net->listen("127.0.0.1", 0));
        CHECK(B.net->add_peer("127.0.0.1", A.net->listen_port()));
        CHECK(wait_until([&] { return B.net->n_peers() == 1 && A.net->n_peers() == 1; }));
        const auto pl = B.net->peer_ids();
        CHECK(!pl.empty());
        if (!pl.empty()) {
            CHECK(B.fetch->request_frames(pl.front(), CHAIN, {mined[0].hash(), huge_id}));
            CHECK(wait_until([&] { return B.n_unservable() == 1; }));
            // ★ EXPLICIT, and DISTINCT from a missing id.
            CHECK(B.saw_failure(SupplyFailure::UNSERVABLE_ID));
            CHECK(!B.saw_failure(SupplyFailure::MISSING_ID));
            CHECK(B.fetch->stats().unservable_id == 1);
            CHECK(B.fetch->stats().missing_id == 0);
            {
                std::lock_guard<std::mutex> lk(B.last_mtx);
                CHECK(B.unservable_ids.size() == 1);
                if (!B.unservable_ids.empty()) CHECK(B.unservable_ids[0] == huge_id);
            }
            // The servable half of the same ask still arrived, verified.
            CHECK(B.n_all_frames() == 1);
            CHECK(B.fetch->stats().frames_verified == 1);
            // Not a stall: the fetch is finished and the slot is free.
            CHECK(B.fetch->stats().fetches_completed == 1);
            CHECK(!B.fetch->busy(pl.front()));
            CHECK(B.saw_failure(SupplyFailure::TIMEOUT) == false);
            // ★ And not a drop, on either side.
            CHECK(B.net->n_peers() == 1);
            CHECK(A.net->n_peers() == 1);
            CHECK(A.serve->stats().frames_unservable == 1);
            CHECK(A.serve->stats().reply_oversize == 0);
            CHECK(A.relay->vault().stats().frames_unservable == 1);
        }
    }

    // ── (d) A PEER THAT ANSWERS NONSENSE cannot spin the continuation. The one
    //        answer that could loop forever is "TRUNCATED, and I consumed
    //        nothing": re-asking would repeat the same question for ever. It is
    //        refused as MALFORMED, so the fetch stops after exactly ONE request.
    {
        Node B(110);
        std::atomic<bool> done{false};
        std::atomic<std::uint16_t> port{0};
        std::atomic<int> requests{0};
        std::thread stuck([&] {
            const int ls = ::socket(AF_INET, SOCK_STREAM, 0);
            int one = 1;
            ::setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
            sockaddr_in a{};
            a.sin_family = AF_INET;
            a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            ::bind(ls, reinterpret_cast<sockaddr*>(&a), sizeof(a));
            socklen_t alen = sizeof(a);
            ::getsockname(ls, reinterpret_cast<sockaddr*>(&a), &alen);
            port.store(ntohs(a.sin_port));
            ::listen(ls, 4);
            const int cs = ::accept(ls, nullptr, nullptr);
            if (cs < 0) { ::close(ls); done.store(true); return; }
            while (!done.load()) {
                std::uint8_t lb[4];
                std::size_t off = 0;
                bool ok = true;
                while (off < 4) {
                    ssize_t k = ::recv(cs, lb + off, 4 - off, 0);
                    if (k <= 0) { ok = false; break; }
                    off += static_cast<std::size_t>(k);
                }
                if (!ok) break;
                std::uint32_t len = 0;
                for (int i = 0; i < 4; ++i) len |= static_cast<std::uint32_t>(lb[i]) << (8 * i);
                std::vector<std::uint8_t> req(len);
                off = 0;
                while (off < len) {
                    ssize_t k = ::recv(cs, req.data() + off, len - off, 0);
                    if (k <= 0) { ok = false; break; }
                    off += static_cast<std::size_t>(k);
                }
                if (!ok) break;
                CtrlGetFrames q;
                if (!CtrlWire::decode(req, q)) continue;
                requests.fetch_add(1);
                CtrlFrames r;
                r.request_id = q.request_id;
                r.chain = q.chain;
                r.status = CtrlFramesStatus::TRUNCATED;   // ★ "there is more"...
                r.cursor = 0;                             // ★ ...but I served none
                const std::vector<std::uint8_t> out = CtrlWire::encode(r);
                std::uint8_t ob[4];
                const std::uint32_t ol = static_cast<std::uint32_t>(out.size());
                for (int i = 0; i < 4; ++i) ob[i] = static_cast<std::uint8_t>(ol >> (8 * i));
                ::send(cs, ob, 4, MSG_NOSIGNAL);
                ::send(cs, out.data(), out.size(), MSG_NOSIGNAL);
            }
            ::close(cs);
            ::close(ls);
        });
        CHECK(wait_until([&] { return port.load() != 0; }));
        CHECK(B.net->add_peer("127.0.0.1", port.load()));
        CHECK(wait_until([&] { return !B.net->peer_ids().empty(); }));
        const auto pl = B.net->peer_ids();
        if (!pl.empty()) {
            std::vector<bytes32> ids;
            for (int i = 0; i < 3; ++i) {
                bytes32 h{};
                h[0] = static_cast<std::uint8_t>(i);
                ids.push_back(h);
            }
            CHECK(B.fetch->request_frames(pl.front(), CHAIN, ids));
            CHECK(wait_until([&] { return B.n_failures() > 0; }));
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
            CHECK(B.saw_failure(SupplyFailure::MALFORMED));
            CHECK(requests.load() == 1);                      // ★ asked ONCE, not forever
            CHECK(B.fetch->stats().continuations == 0);
            CHECK(!B.fetch->busy(pl.front()));
            CHECK(B.net->n_peers() == 1);                     // and still not a drop
        }
        done.store(true);
        B.net->stop();
        stuck.join();
    }
}

int main() {
    std::printf("== v37 convergence-supply KAT (Stage 1: FrameVault + serve/fetch/verify) ==\n");
    test_cs1_vault_unified();
    test_cs2_roundtrip();
    test_cs3_lying_peer_fail_closed();
    test_cs4_missing_and_timeout_fail_closed();
    test_cs5_bounds();
    test_cs6_flap_cannot_evict();
    test_cs7_old_peer_keeps_socket();
    test_cs8_zero_consensus_movement();
    test_cs9_reply_ceiling_and_continuation();
    std::printf("== checks=%d failures=%d ==\n", g_checks, g_failures);
    return g_failures == 0 ? 0 : 1;
}
