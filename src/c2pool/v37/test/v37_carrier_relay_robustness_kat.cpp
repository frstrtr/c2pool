// v37_carrier_relay_robustness_kat.cpp — Track A2 CONSUMER-tree relay
// robustness: the bounded carrier RE-OFFER (missed-record recovery) and the
// PER-DESCRIPTOR write lock (head-of-line stall), with the no-consensus-movement
// proof that must hold for both.
//
// THE TWO DEFECTS THIS PINS (both confirmed on master 22ef1a11 before the fix):
//
//   A. DROPPED FRAME, NEVER RE-OFFERED. CarrierRelay::handle_local marks the
//      carrier in RelaySeenSet and then broadcasts (w3_relay.hpp:723-724); if
//      the broadcast reached ZERO peers — nobody connected, or the one peer had
//      just dropped — the frame was gone. The send side only COUNTED it
//      (carrier_send.hpp CarrierSendStats::deferred_relay, bumped at :414), and
//      RelaySeenSet now says "seen", so nothing ever re-sent it. A peer that was
//      down for a second never learned that carrier existed.
//
//   B. ONE SHARED WRITE MUTEX FOR EVERY PEER. carrier_net.hpp guarded every
//      send_all with a single m_write_mtx (write_lock(int) returned &m_write_mtx
//      at :217, ignoring the fd), so one peer that stopped reading — holding
//      that mutex for the whole of a large blocking write — stalled the flood to
//      EVERY other peer, and with it the relay (which broadcasts under its own
//      mutex). A single slow reader was a whole-node send stall.
//
// WHAT IS PROVEN HERE:
//   RR-1  a carrier that reached no peer is re-offered to a peer that connects
//         afterwards, and is admitted there EXACTLY ONCE (lane advances by that
//         one carrier: +1 position, +work, 1 identity, 1 forwarded push).
//   RR-2  re-offering a carrier the receiver ALREADY holds is REJECT_DEDUP:
//         zero pushes, and next_pos / raw_total / lane digest / owed_digest all
//         byte-identical before and after. Repeat sweeps stay byte-identical.
//   RR-3  the horizon bound: an entry older than max_age is DROPPED, never
//         re-offered — the property that keeps a re-offer inside the receiver's
//         W2 dedup window (W2_DEDUP_RETENTION = W2_N_CTX + 2 bins) and therefore
//         keeps it a REJECT, not a second credit. Capacity bounds too.
//   RR-4  a peer that has stopped reading does not stall a send to a second
//         peer (the per-fd lock + the try-lock-first pass).
//   RR-5  concurrent writers never interleave a frame on ONE connection: every
//         frame arrives whole, self-consistent, and all of them arrive.
//
// Stdlib + POSIX sockets + Threads, the same self-harness shape as the sibling
// A2 suites (no gtest, no Boost, no coin backend). CONSUMER TREE ONLY: nothing
// under src/sharechain/v37 is touched by any code path exercised here.

#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#include <c2pool/v37/carrier_emit.hpp>
#include <c2pool/v37/carrier_ingest.hpp>
#include <c2pool/v37/carrier_net.hpp>
#include <c2pool/v37/carrier_send.hpp>
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

// ── one node = engine + admission + relay + peer transport ──────────────────
// Wired exactly as main_v37_btc_dash.cpp does, plus the two new bindings under
// test: the transport's peer-connect callback arms the relay's re-offer sweep,
// and the relay's dedup probe is the node's OWN W2 admission window.
struct Node {
    V37Engine engine;
    std::unique_ptr<CallbackMainchainIndex> index;
    MemShareTracker tracker;
    std::unique_ptr<CarrierIngest> ingest;
    std::unique_ptr<CarrierPeerNode> net;
    c2pool::v37n::wire_freeze::PolicyStats policy_stats;
    std::unique_ptr<CarrierRelay> relay;

    explicit Node(u64 tip) {
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
    }
    ~Node() { if (net) net->stop(); engine.stop(); }

    u64 raw_total() {
        auto s = engine.snapshot(CHAIN);
        return s ? static_cast<u64>(s->raw_total) : 0;
    }
    u64 next_pos() {
        auto s = engine.snapshot(CHAIN);
        return s ? s->next_pos : 0;
    }
    ::v37::bytes32 lane_digest() {
        auto s = engine.snapshot(CHAIN);
        return s ? s->digest : ::v37::bytes32{};
    }
    std::size_t identity_count() {
        auto s = engine.snapshot(CHAIN);
        return (s && s->identities) ? s->identities->size() : 0;
    }
    std::uint64_t pushes() const { return ingest->pushes_forwarded(); }
};

// A re-offer configuration with the rate limits opened up, so a sweep is
// deterministic in a test. The BOUNDS under test (entries / bytes / attempts /
// age) keep their meaning; only the "how often may I be asked" gates are 0.
static CarrierReofferOptions prompt_opts() {
    CarrierReofferOptions o;
    o.min_interval = std::chrono::milliseconds(0);
    o.min_forced_interval = std::chrono::milliseconds(0);
    return o;
}

// ═══════════════════════════════════════════════════════════════════════════
// RR-1 — the dropped carrier is re-offered to a peer that connects afterwards,
// and is admitted EXACTLY ONCE.
// ═══════════════════════════════════════════════════════════════════════════
static void test_rr1_reoffer_after_reconnect() {
    std::printf("-- RR-1 dropped carrier -> reconnect -> admitted exactly once\n");
    Node A(110);
    A.relay->set_reoffer_options(prompt_opts());

    // A peer existed and went away (the reconnect case, not the never-connected
    // one): B listens, A dials, B stops, A observes zero peers.
    {
        Node B(110);
        CHECK(B.net->listen("127.0.0.1", 0));
        CHECK(A.net->add_peer("127.0.0.1", B.net->listen_port()));
        CHECK(wait_until([&] { return A.net->n_peers() >= 1; }));
        B.net->stop();
    }
    CHECK(wait_until([&] { return A.net->n_peers() == 0; }));

    // A mines its own carrier with NO peer connected: admitted locally, relay
    // DEFERs (the #889/#903 guarantee), and — the fix — the frame is buffered.
    const WorkEvent share = mine(CHAIN, ALICE_DESC(), 100, W2_GENESIS_PREV_OWN, "A.c");
    Carrier c; c.carrier = share;
    const CarrierRelay::Outcome o = A.relay->handle_local(c);
    CHECK(o.admitted);
    CHECK(o.peers_reached == 0);
    CHECK(!o.relayed);                                   // DEFER: nobody to send to
    CHECK(A.relay->reoffer_pending() == 1);              // ★ the fix: kept, not lost
    CHECK(A.relay->reoffer_stats().buffered == 1);

    // A sweep with no peers does nothing and keeps the entry (nothing to offer to).
    CHECK(A.relay->reoffer_tick() == 0);
    CHECK(A.relay->reoffer_pending() == 1);

    // A NEW peer connects. The transport's connect callback arms the sweep.
    Node B2(110);
    CHECK(B2.net->listen("127.0.0.1", 0));
    CHECK(B2.raw_total() == 0);
    CHECK(A.net->add_peer("127.0.0.1", B2.net->listen_port()));
    CHECK(wait_until([&] { return A.net->n_peers() == 1; }));

    const std::size_t reoffered = A.relay->reoffer_tick();
    CHECK(reoffered == 1);
    CHECK(A.relay->reoffer_stats().frames_reoffered == 1);

    // B2 admits it — exactly once, and the lane advances by exactly one carrier.
    const u64 w = share.work();
    CHECK(wait_until([&] { return B2.raw_total() == w; }));
    CHECK(B2.raw_total() == w);
    CHECK(B2.next_pos() == 1);
    CHECK(B2.identity_count() == 1);
    CHECK(B2.pushes() == 1);

    // Sweep again and again: no double count anywhere.
    const ::v37::bytes32 d_after = B2.lane_digest();
    for (int i = 0; i < 3; ++i) (void)A.relay->reoffer_tick();
    std::this_thread::sleep_for(std::chrono::milliseconds(150));
    CHECK(B2.raw_total() == w);
    CHECK(B2.next_pos() == 1);
    CHECK(B2.pushes() == 1);
    CHECK(B2.lane_digest() == d_after);
    CHECK(A.raw_total() == w);                            // and A still counted it once
    CHECK(A.next_pos() == 1);
}

// ═══════════════════════════════════════════════════════════════════════════
// RR-2 — a re-offer of an already-held carrier is REJECT_DEDUP, and moves NO
// consensus byte: next_pos, raw_total, the lane digest and owed_digest are all
// identical before and after.
// ═══════════════════════════════════════════════════════════════════════════
static void test_rr2_reoffer_is_reject_dedup() {
    std::printf("-- RR-2 re-offer of a held carrier == REJECT_DEDUP, zero movement\n");
    Node B(110);

    // An owed ledger with REAL finalized state, so its digest is non-trivial and
    // an accidental mutation would show. The relay/re-offer path has no route
    // into it at all — that is the point being pinned.
    c2pool::v37n::settle::OwedLedger ledger(CHAIN);
    c2pool::v37n::settle::OwedLedger::Amounts credit, payout;
    credit[ALICE_DESC().identity_key()] = 5000;
    ledger.on_block_found("rr2-block", credit, payout);
    ledger.on_block_finalized("rr2-block", 110);
    const ::v37::bytes32 owed_before = ledger.owed_digest();
    const u64 seq_before = ledger.ledger_seq();

    const WorkEvent share = mine(CHAIN, ALICE_DESC(), 100, W2_GENESIS_PREV_OWN, "B.c");
    Carrier c; c.carrier = share;
    const std::vector<std::uint8_t> frame = CarrierWire::encode(c);

    // First arrival: admitted.
    const CarrierRelay::Outcome first = B.relay->handle_inbound(frame);
    CHECK(first.wire == WireStatus::OK);
    CHECK(first.admitted);
    CHECK(first.admission.carrier_status == CarrierStatus::OK);
    CHECK(wait_until([&] { return B.next_pos() == 1; }));

    const u64 raw_before = B.raw_total();
    const u64 pos_before = B.next_pos();
    const ::v37::bytes32 lane_before = B.lane_digest();
    const std::uint64_t pushes_before = B.pushes();
    CHECK(raw_before == share.work());
    CHECK(pushes_before == 1);

    // Every subsequent offer of the SAME bytes — which is exactly what a
    // re-offer puts on the wire — is refused by the W2 dedup window.
    for (int i = 0; i < 5; ++i) {
        const CarrierRelay::Outcome again = B.relay->handle_inbound(frame);
        CHECK(again.wire == WireStatus::OK);                       // bytes still valid
        CHECK(again.admission.carrier_status == CarrierStatus::REJECT_DEDUP);
        CHECK(!again.admitted);                                    // no append
        CHECK(again.admission.pushes.empty());                     // ★ zero pushes
        CHECK(!again.relayed);                                     // no amplification
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(150));

    // Byte-identical consensus state.
    CHECK(B.raw_total() == raw_before);
    CHECK(B.next_pos() == pos_before);
    CHECK(B.lane_digest() == lane_before);
    CHECK(B.pushes() == pushes_before);
    CHECK(B.identity_count() == 1);
    CHECK(ledger.owed_digest() == owed_before);
    CHECK(ledger.ledger_seq() == seq_before);
}

// ═══════════════════════════════════════════════════════════════════════════
// RR-3 — the bounds. An entry past max_age is DROPPED (never re-offered): that
// is what keeps a re-offer inside the receivers' W2 dedup horizon, and so keeps
// it a REJECT rather than a second credit. Capacity and attempt caps too.
// ═══════════════════════════════════════════════════════════════════════════
static void test_rr3_bounds_hold_the_horizon() {
    std::printf("-- RR-3 horizon + capacity + attempt bounds\n");

    // (a) age: an entry older than max_age is expired instead of re-offered.
    {
        Node A(110), B(110);
        CarrierReofferOptions o = prompt_opts();
        o.max_age = std::chrono::milliseconds(40);
        A.relay->set_reoffer_options(o);

        const WorkEvent share = mine(CHAIN, ALICE_DESC(), 100, W2_GENESIS_PREV_OWN, "age.c");
        Carrier c; c.carrier = share;
        CHECK(A.relay->handle_local(c).admitted);
        CHECK(A.relay->reoffer_pending() == 1);

        std::this_thread::sleep_for(std::chrono::milliseconds(120));   // past max_age

        CHECK(B.net->listen("127.0.0.1", 0));
        CHECK(A.net->add_peer("127.0.0.1", B.net->listen_port()));
        CHECK(wait_until([&] { return A.net->n_peers() == 1; }));

        CHECK(A.relay->reoffer_tick() == 0);                 // nothing survives to offer
        CHECK(A.relay->reoffer_pending() == 0);
        CHECK(A.relay->reoffer_stats().expired_age == 1);
        CHECK(A.relay->reoffer_stats().frames_reoffered == 0);
        std::this_thread::sleep_for(std::chrono::milliseconds(150));
        CHECK(B.raw_total() == 0);                           // B never saw it
        CHECK(B.next_pos() == 0);
    }

    // (b) capacity: the buffer is FIFO-bounded by entry count, and the bytes
    //     counter tracks it.
    {
        Node A(110);
        CarrierReofferOptions o = prompt_opts();
        o.max_entries = 3;
        A.relay->set_reoffer_options(o);
        bytes32 prev = W2_GENESIS_PREV_OWN;
        for (int i = 0; i < 6; ++i) {
            const WorkEvent s = mine(CHAIN, ALICE_DESC(), 100, prev, "cap.c",
                                     static_cast<u64>(i + 1));
            prev = s.hash();
            Carrier c; c.carrier = s;
            CHECK(A.relay->handle_local(c).admitted);
        }
        CHECK(A.relay->reoffer_pending() == 3);
        CHECK(A.relay->reoffer_stats().buffered == 6);
        CHECK(A.relay->reoffer_stats().evicted_capacity == 3);
        CHECK(A.relay->reoffer_bytes() > 0);
    }

    // (c) a frame larger than the byte cap is never buffered at all.
    {
        Node A(110);
        CarrierReofferOptions o = prompt_opts();
        o.max_bytes = 4;                                     // smaller than any frame
        A.relay->set_reoffer_options(o);
        const WorkEvent s = mine(CHAIN, ALICE_DESC(), 100, W2_GENESIS_PREV_OWN, "big.c");
        Carrier c; c.carrier = s;
        CHECK(A.relay->handle_local(c).admitted);            // the APPEND still stands
        CHECK(A.relay->reoffer_pending() == 0);
    }

    // (d) attempts: a peer that never fully takes delivery cannot make the
    //     buffer re-offer forever.
    {
        Node A(110), B(110);
        CarrierReofferOptions o = prompt_opts();
        o.max_attempts = 2;
        A.relay->set_reoffer_options(o);

        const WorkEvent s = mine(CHAIN, ALICE_DESC(), 100, W2_GENESIS_PREV_OWN, "att.c");
        Carrier c; c.carrier = s;
        CHECK(A.relay->handle_local(c).admitted);            // 0 peers -> under-delivered
        CHECK(A.relay->reoffer_pending() == 1);

        CHECK(B.net->listen("127.0.0.1", 0));
        CHECK(A.net->add_peer("127.0.0.1", B.net->listen_port()));
        CHECK(wait_until([&] { return A.net->n_peers() == 1; }));

        CHECK(A.relay->reoffer_tick() == 1);                 // delivered to the peer set
        CHECK(A.relay->reoffer_pending() == 1);              // kept for a future joiner
        A.relay->note_peer_connected();                      // another peer joins
        CHECK(A.relay->reoffer_tick() == 1);                 // forced sweeps re-offer all
        CHECK(A.relay->reoffer_pending() == 0);              // attempt cap reached
        CHECK(A.relay->reoffer_stats().exhausted == 1);

        // Two deliveries of one carrier, still ONE credit on B.
        CHECK(wait_until([&] { return B.next_pos() == 1; }));
        std::this_thread::sleep_for(std::chrono::milliseconds(150));
        CHECK(B.next_pos() == 1);
        CHECK(B.raw_total() == s.work());
        CHECK(B.pushes() == 1);
    }

    // (e) the rate limit is real: a second sweep inside min_interval is skipped.
    {
        Node A(110), B(110);
        CarrierReofferOptions o;                             // DEFAULT intervals
        o.min_forced_interval = std::chrono::milliseconds(30000);
        A.relay->set_reoffer_options(o);
        const WorkEvent s = mine(CHAIN, ALICE_DESC(), 100, W2_GENESIS_PREV_OWN, "rl.c");
        Carrier c; c.carrier = s;
        CHECK(A.relay->handle_local(c).admitted);
        CHECK(B.net->listen("127.0.0.1", 0));
        CHECK(A.net->add_peer("127.0.0.1", B.net->listen_port()));
        CHECK(wait_until([&] { return A.net->n_peers() == 1; }));
        CHECK(A.relay->reoffer_tick() == 1);                 // first sweep runs
        CHECK(A.relay->reoffer_tick() == 0);                 // second is rate-limited
        CHECK(A.relay->reoffer_stats().sweeps == 1);
        CHECK(A.relay->reoffer_stats().sweeps_skipped >= 1);
    }

    // (f) disabled means disabled: nothing is retained at all.
    {
        Node A(110);
        CarrierReofferOptions o;
        o.enabled = false;
        A.relay->set_reoffer_options(o);
        const WorkEvent s = mine(CHAIN, ALICE_DESC(), 100, W2_GENESIS_PREV_OWN, "off.c");
        Carrier c; c.carrier = s;
        CHECK(A.relay->handle_local(c).admitted);
        CHECK(A.relay->reoffer_pending() == 0);
        CHECK(A.relay->reoffer_tick() == 0);
    }
}

// ── a raw client socket that connects and NEVER reads ───────────────────────
static int connect_slow_reader(std::uint16_t port) {
    const int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    const int rcv = 2048;                       // tiny receive buffer, never drained
    ::setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcv, sizeof(rcv));
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_port = htons(port);
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (::connect(fd, reinterpret_cast<sockaddr*>(&a), sizeof(a)) != 0) { ::close(fd); return -1; }
    return fd;
}

// ═══════════════════════════════════════════════════════════════════════════
// RR-4 — a peer that stopped reading does not stall the send to a second peer.
// With the single shared write mutex this could not hold: the stalled writer
// held the ONE lock, so the second peer's frame never left the node.
// ═══════════════════════════════════════════════════════════════════════════
static void test_rr4_slow_peer_does_not_stall_others() {
    std::printf("-- RR-4 a slow reader does not stall the send to another peer\n");
    CarrierPeerNode S;                                   // the sender
    CHECK(S.listen("127.0.0.1", 0));
    const std::uint16_t port = S.listen_port();

    CarrierPeerNode R;                                   // the healthy peer
    std::atomic<int> r_small{0};
    std::atomic<int> r_any{0};
    R.set_inbound([&](const std::vector<std::uint8_t>& f) {
        ++r_any;
        if (f.size() == 64) ++r_small;
    });
    CHECK(R.add_peer("127.0.0.1", port));

    const int slow = connect_slow_reader(port);
    CHECK(slow >= 0);
    CHECK(wait_until([&] { return S.n_peers() == 2; }));

    // One writer wedges itself on the slow peer (1 MiB frames, nobody reading).
    const std::vector<std::uint8_t> big(1u << 20, 0x5a);
    const std::vector<std::uint8_t> small(64, 0x11);
    std::atomic<bool> stalling{true};
    std::thread wedger([&] { while (stalling.load()) (void)S.broadcast(big); });

    // Give it time to fill the slow peer's socket buffers and block there.
    std::this_thread::sleep_for(std::chrono::milliseconds(600));
    const int small_before = r_small.load();

    // ★ The claim: this send reaches the HEALTHY peer even though another
    // writer is wedged on the slow one. (This thread will itself end up waiting
    // on the wedged connection, by design — the assertion is about R.)
    std::thread sender([&] { (void)S.broadcast(small); });
    const bool reached_healthy =
        wait_until([&] { return r_small.load() > small_before; }, 4000);
    CHECK(reached_healthy);
    CHECK(r_any.load() > 0);

    // Release everyone: closing the dead peer fails its in-flight write, the
    // node drops it, and both writers return.
    stalling.store(false);
    ::shutdown(slow, SHUT_RDWR);
    ::close(slow);
    sender.join();
    wedger.join();
    S.stop();
    R.stop();
}

// ═══════════════════════════════════════════════════════════════════════════
// RR-5 — per-connection frame integrity: concurrent writers never interleave a
// frame's length prefix or body on ONE socket.
//
// TAG RANGE (Stage 1 supply): the synthetic frames below are identified by
// their repeated first byte, and that byte must stay INSIDE the CarrierWire
// body range 0x01..0x7f. carrier_net.hpp now demuxes frame[0] >= 0x80 to the
// repair-control channel BEFORE handle_inbound, so a synthetic tag of 0x80 or
// above would be routed to the control handler and never reach set_inbound at
// all. That is the namespace split working, not a transport regression; the
// property RR-5 pins (whole, un-interleaved frames on one connection) is
// unaffected and is exercised identically with a body-range tag.
// ═══════════════════════════════════════════════════════════════════════════
static void test_rr5_no_frame_interleaving() {
    std::printf("-- RR-5 concurrent writers never interleave a frame\n");
    CarrierPeerNode S;
    CHECK(S.listen("127.0.0.1", 0));

    constexpr int kThreads = 4;
    constexpr int kEach = 60;
    constexpr std::uint8_t kTagBase = 0x40;      // body range; see the note above
    static_assert(kTagBase + kThreads <= 0x80,
                  "RR-5 tags must stay below the control-opcode base (0x80)");
    std::atomic<int> received{0};
    std::atomic<int> corrupt{0};
    CarrierPeerNode R;
    R.set_inbound([&](const std::vector<std::uint8_t>& f) {
        ++received;
        if (f.empty()) { ++corrupt; return; }
        const std::uint8_t tag = f[0];
        if (tag < kTagBase || tag >= kTagBase + kThreads) { ++corrupt; return; }
        for (std::uint8_t b : f) if (b != tag) { ++corrupt; return; }
    });
    CHECK(R.add_peer("127.0.0.1", S.listen_port()));
    CHECK(wait_until([&] { return S.n_peers() == 1; }));

    std::vector<std::thread> ts;
    for (int t = 0; t < kThreads; ++t) {
        ts.emplace_back([&, t] {
            for (int i = 0; i < kEach; ++i) {
                const std::size_t len = 128 + static_cast<std::size_t>(t) * 4096 +
                                        static_cast<std::size_t>(i % 11) * 97;
                const std::vector<std::uint8_t> f(len, static_cast<std::uint8_t>(kTagBase + t));
                (void)S.broadcast(f);
            }
        });
    }
    for (auto& t : ts) t.join();

    CHECK(wait_until([&] { return received.load() == kThreads * kEach; }, 10000));
    CHECK(received.load() == kThreads * kEach);   // every frame arrived, none merged
    CHECK(corrupt.load() == 0);                   // and none of them was mixed
    S.stop();
    R.stop();
}

// ═══════════════════════════════════════════════════════════════════════════
// RR-6 — the send-side worker drives the sweep on its idle tick, and the exact
// dedup probe drops an entry our own admission window has already pruned.
// ═══════════════════════════════════════════════════════════════════════════
static void test_rr6_send_worker_tick_and_probe() {
    std::printf("-- RR-6 send-side tick driver + exact dedup probe\n");

    // (a) the worker's idle tick reaches the relay.
    {
        Node A(110), B(110);
        A.relay->set_reoffer_options(prompt_opts());
        const WorkEvent s = mine(CHAIN, ALICE_DESC(), 100, W2_GENESIS_PREV_OWN, "tick.c");
        Carrier c; c.carrier = s;
        CHECK(A.relay->handle_local(c).admitted);
        CHECK(A.relay->reoffer_pending() == 1);

        CHECK(B.net->listen("127.0.0.1", 0));
        CHECK(A.net->add_peer("127.0.0.1", B.net->listen_port()));
        CHECK(wait_until([&] { return A.net->n_peers() == 1; }));

        CarrierSendQueue::Options opt;
        opt.reoffer_tick_interval = std::chrono::milliseconds(20);
        CarrierSendQueue q(*A.relay, *A.index, static_cast<std::uint32_t>(CHAIN), opt);
        q.start();
        const bool got = wait_until([&] { return B.next_pos() == 1; }, 5000);
        CHECK(got);
        CHECK(q.stats().reoffered >= 1);
        q.stop();
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        CHECK(B.next_pos() == 1);                     // still exactly one credit
        CHECK(B.raw_total() == s.work());
        CHECK(B.pushes() == 1);
    }

    // (b) the exact probe: an entry the node's own dedup window no longer holds
    //     is dropped rather than re-offered (the double-credit hazard, closed
    //     exactly instead of only by the age bound).
    {
        Node A(110), B(110);
        A.relay->set_reoffer_options(prompt_opts());
        std::atomic<bool> in_window{true};
        A.relay->set_reoffer_dedup_probe(
            [&](const bytes32&) { return in_window.load(); });

        const WorkEvent s = mine(CHAIN, ALICE_DESC(), 100, W2_GENESIS_PREV_OWN, "probe.c");
        Carrier c; c.carrier = s;
        CHECK(A.relay->handle_local(c).admitted);
        CHECK(A.relay->reoffer_pending() == 1);

        in_window.store(false);                        // our window pruned it
        CHECK(B.net->listen("127.0.0.1", 0));
        CHECK(A.net->add_peer("127.0.0.1", B.net->listen_port()));
        CHECK(wait_until([&] { return A.net->n_peers() == 1; }));

        CHECK(A.relay->reoffer_tick() == 0);
        CHECK(A.relay->reoffer_pending() == 0);
        CHECK(A.relay->reoffer_stats().expired_window == 1);
        std::this_thread::sleep_for(std::chrono::milliseconds(150));
        CHECK(B.next_pos() == 0);                      // nothing offered, nothing credited
    }
}

int main() {
    std::printf("== v37 carrier-relay robustness KAT (re-offer + per-fd write lock) ==\n");
    test_rr1_reoffer_after_reconnect();
    test_rr2_reoffer_is_reject_dedup();
    test_rr3_bounds_hold_the_horizon();
    test_rr4_slow_peer_does_not_stall_others();
    test_rr5_no_frame_interleaving();
    test_rr6_send_worker_tick_and_probe();
    std::printf("%d checks, %d failures\n", g_checks, g_failures);
    return g_failures == 0 ? 0 : 1;
}
