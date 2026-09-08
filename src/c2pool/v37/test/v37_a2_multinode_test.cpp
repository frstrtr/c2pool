// V37 Track A2 — multi-node carrier accounting test (the CONSUMER-half proof).
//
// Proves the whole A2 consumer path end to end across TWO independent nodes
// connected by a REAL TCP socket: a carrier mined on node A is flooded over the
// wire, decoded + W2-admitted on node B, and appears as ACCOUNTED WEIGHT in node
// B's own V37Engine snapshot — i.e. "node B accounts node A's shares", the exact
// gap the Phase-B single-node daemon had (no --peer, owed empty by construction).
//
// Every piece here is the SAME production code the daemon wires:
//   * carrier_net.hpp     CarrierPeerNode  (ICarrierTransport over real sockets)
//   * w3_relay.hpp        CarrierRelay     (decode + relay + admission routing)
//   * carrier_ingest.hpp  CarrierIngest    (W2 admission -> V37Engine push)
//   * v37_engine.hpp      V37Engine        (the W0 seam; the executor accounts)
// Only the mainchain index is a synthetic map here (the daemon binds the LIVE
// LiveMainchainIndex, carrier_index.hpp; v37_a2_live_index_test proves that
// class). The carrier's PoW envelope stays the RDWR synthetic model (S-1).
// Every Node runs the W3-B5 frozen-wire policy gate, as the daemon does.
//
// stdlib-only + POSIX sockets, the same self-harness shape as the W3 KAT.

#include <netinet/in.h>

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#include <c2pool/v37/carrier_emit.hpp>
#include <c2pool/v37/carrier_ingest.hpp>
#include <c2pool/v37/carrier_net.hpp>
#include <c2pool/v37/v37_engine.hpp>
#include <c2pool/v37/w2_admission.hpp>
#include <c2pool/v37/w2_receipt.hpp>
#include <c2pool/v37/w3_relay.hpp>
#include <c2pool/v37/w3_wire_freeze.hpp>   // W3-B5 policy gate (make_relay_policy)

using namespace c2pool::v37n;
using ::v37::ChainId;
using ::v37::LaneParams;
using ::v37::LaneRecord;
using ::v37::MinerId;
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
static PayoutDescriptor BOB_DESC()   { return mk_desc(0x22); }

// Grind a real sha256d PoW so the event clears its own bits (well-bound:
// identity == descriptor.identity_key(), so W3-MUST holds).
static WorkEvent mine(ChainId chain_id, const PayoutDescriptor& desc,
                      u64 origin_bin, const bytes32& prev_own, unsigned lz_bits,
                      const char* tag, u64 salt = 0) {
    WorkEvent ev;
    ev.chain_id = chain_id;
    ev.identity = desc.identity_key();
    ev.descriptor = desc;
    ev.prev_block_hash = mainchain_hash(origin_bin);
    ev.prev_own_share = prev_own;
    ev.lz_bits = lz_bits ? lz_bits : consensus_lz(origin_bin);
    ev.tag = tag;
    u64 base = salt << 32;
    for (u64 nonce = base; nonce < base + (u64(1) << 22); ++nonce) {
        ev.nonce = nonce;
        if (ev.meets_own_target()) return ev;
    }
    std::printf("FATAL mine: nonce exhausted (%s)\n", tag);
    std::abort();
}

// Synthetic mainchain index: every carrier's prev_block_hash resolves to a bin
// within the horizon (the node's real index would resolve against the coin).
static CallbackMainchainIndex::Resolver synthetic_index(u64 tip, u64 horizon = 64) {
    auto by_hash = std::make_shared<std::map<bytes32, u64>>();
    u64 lo = tip > horizon ? tip - horizon : 0;
    for (u64 x = lo; x <= tip; ++x) (*by_hash)[mainchain_hash(x)] = x;
    return [by_hash](const bytes32& h) -> std::optional<u64> {
        auto it = by_hash->find(h);
        return it == by_hash->end() ? std::nullopt : std::optional<u64>(it->second);
    };
}

// ── one node = engine + admission + relay + peer transport ──────────────────
struct Node {
    V37Engine engine;
    std::unique_ptr<CallbackMainchainIndex> index;
    MemShareTracker tracker;
    std::unique_ptr<CarrierIngest> ingest;
    std::unique_ptr<CarrierPeerNode> net;
    c2pool::v37n::wire_freeze::PolicyStats policy_stats;   // W3-B5 policy gate counters
    std::unique_ptr<CarrierRelay> relay;

    explicit Node(u64 tip) {
        engine.start();
        engine.submit_tracked(LaneRecord::add_lane(CHAIN, small_params())).get();
        auto s = engine.snapshot(CHAIN);
        u64 inc = s ? s->incarnation : 1;
        index  = std::make_unique<CallbackMainchainIndex>(synthetic_index(tip));
        ingest = std::make_unique<CarrierIngest>(engine, CHAIN, *index, tracker, inc);
        net    = std::make_unique<CarrierPeerNode>();
        relay  = std::make_unique<CarrierRelay>(ingest->fn(), *net);
        // The production configuration: the W3-B5 frozen-wire policy gate (F-1
        // tag cap / F-2 descriptor validity) on every inbound frame, exactly as
        // main_v37_btc_dash.cpp binds it.
        relay->set_frame_policy(c2pool::v37n::wire_freeze::make_relay_policy(&policy_stats));
        net->set_inbound([this](const std::vector<std::uint8_t>& f) {
            relay->handle_inbound(f);
        });
    }
    ~Node() { if (net) net->stop(); engine.stop(); }

    u64 raw_total() {
        auto s = engine.snapshot(CHAIN);
        return s ? static_cast<u64>(s->raw_total) : 0;
    }
    // Does this node's OWN engine account a positive weight for `key`?
    bool accounts_identity(const bytes32& key) {
        auto s = engine.snapshot(CHAIN);
        if (!s || !s->identities) return false;
        for (const auto& [mid, ent] : s->identities->entries()) {
            if (ent.key == key) {
                auto it = s->payout.find(mid);
                return it != s->payout.end() && !(it->second == ::v37::U256{});
            }
        }
        return false;
    }
    std::size_t identity_count() {
        auto s = engine.snapshot(CHAIN);
        return (s && s->identities) ? s->identities->size() : 0;
    }
};

// Poll a predicate to a deadline (the engine executor + the socket reader are
// async). Returns true once it holds.
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

// ═══════════════════════════════════════════════════════════════════════════
// MN-1 — node B accounts node A's carrier (the core A2 proof).
// ═══════════════════════════════════════════════════════════════════════════
static void test_mn1_b_accounts_a() {
    Node A(110), B(110);

    CHECK(B.net->listen("127.0.0.1", 0));
    const std::uint16_t bport = B.net->listen_port();
    CHECK(bport != 0);
    CHECK(A.net->add_peer("127.0.0.1", bport));          // A dials B (--peer)
    CHECK(wait_until([&] { return B.net->n_peers() >= 1; }));

    // Precondition: B knows nothing yet.
    CHECK(B.raw_total() == 0);
    CHECK(!B.accounts_identity(ALICE_DESC().identity_key()));

    // A mines a real-PoW carrier under ALICE and floods it (local win path).
    WorkEvent a_share = mine(CHAIN, ALICE_DESC(), 100, W2_GENESIS_PREV_OWN, 0, "A.c");
    Carrier c; c.carrier = a_share;
    CarrierRelay::Outcome o = A.relay->handle_local(c);
    CHECK(o.admitted);                                   // A credited its own share
    CHECK(o.relayed);                                    // and it reached B (>=1 peer)
    CHECK(o.peers_reached >= 1);

    // B receives over the socket, admits, and ACCOUNTS it in B's own engine.
    const u64 w = a_share.work();                        // work_of_lz(8) = 256
    CHECK(wait_until([&] { return B.raw_total() == w; }));
    CHECK(B.raw_total() == w);
    CHECK(B.accounts_identity(ALICE_DESC().identity_key()));   // ALICE, by identity
    CHECK(B.identity_count() == 1);                            // only ALICE so far

    // A's own accounting is independent and equal (both nodes saw the share).
    CHECK(A.raw_total() == w);
    CHECK(A.accounts_identity(ALICE_DESC().identity_key()));
}

// ═══════════════════════════════════════════════════════════════════════════
// MN-2 — duplex: B's carrier reaches A over the same connection; a carrier with
// receipts is accounted whole (carrier + accepted receipts).
// ═══════════════════════════════════════════════════════════════════════════
static void test_mn2_duplex_and_receipts() {
    Node A(110), B(110);
    CHECK(B.net->listen("127.0.0.1", 0));
    CHECK(A.net->add_peer("127.0.0.1", B.net->listen_port()));
    CHECK(wait_until([&] { return B.net->n_peers() >= 1; }));

    // B mines a carrier carrying two self-bound receipts and floods to A.
    WorkEvent b_c = mine(CHAIN, BOB_DESC(), 100, W2_GENESIS_PREV_OWN, 0, "B.c");
    WorkEvent b_r0 = mine(CHAIN, BOB_DESC(), 100, b_c.hash(), 0, "B.r0", 1);
    WorkEvent b_r1 = mine(CHAIN, BOB_DESC(),  99, b_c.hash(), 0, "B.r1", 2);
    Carrier c; c.carrier = b_c; c.receipts = {b_r0, b_r1};
    CarrierRelay::Outcome o = B.relay->handle_local(c);
    CHECK(o.admitted);
    CHECK(o.admission.pushes.size() == 3);               // carrier + 2 receipts
    CHECK(o.relayed && o.peers_reached >= 1);

    // A accounts all three pushes' work (carrier + both receipts) for BOB.
    const u64 w_all = b_c.work() + b_r0.work() + b_r1.work();
    CHECK(wait_until([&] { return A.raw_total() == w_all; }));
    CHECK(A.raw_total() == w_all);
    CHECK(A.accounts_identity(BOB_DESC().identity_key()));
}

// ═══════════════════════════════════════════════════════════════════════════
// MN-3 — relay dedup: a re-flooded carrier is NOT double-accounted on B.
// (Consensus credit-once is the W2 window inside admit, independent of the
// relay-seen set — w3_relay.hpp §5.2. Here the observable is B's raw_total.)
// ═══════════════════════════════════════════════════════════════════════════
static void test_mn3_no_double_account() {
    Node A(110), B(110);
    CHECK(B.net->listen("127.0.0.1", 0));
    CHECK(A.net->add_peer("127.0.0.1", B.net->listen_port()));
    CHECK(wait_until([&] { return B.net->n_peers() >= 1; }));

    WorkEvent share = mine(CHAIN, ALICE_DESC(), 100, W2_GENESIS_PREV_OWN, 0, "d.c");
    Carrier c; c.carrier = share;
    const u64 w = share.work();

    A.relay->handle_local(c);
    CHECK(wait_until([&] { return B.raw_total() == w; }));

    // Flood the identical carrier again; B's dedup window rejects re-credit.
    A.relay->handle_local(c);
    // Give B time to (not) apply it, then assert it did NOT grow.
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    CHECK(B.raw_total() == w);                           // still single-counted
}

// ═══════════════════════════════════════════════════════════════════════════
// The real-index byte-order contract (Track A2 step (b)).
// A WorkEvent's prev_block_hash is header/INTERNAL byte order; dashd's
// getblockheader wants DISPLAY hex (reversed). The daemon's LiveMainchainIndex
// (carrier_index.hpp, bound with dash_rpc_coin_backend.hpp display_hex_of_bytes32)
// resolves by reversing then asking dashd. These two mirror that reversal so the
// KAT proves the contract WITHOUT a live daemon (the VM100 run proves it end to
// end against real dashd; v37_a2_live_index_test drives the index class itself).
// ═══════════════════════════════════════════════════════════════════════════
static std::string display_hex_of(const bytes32& internal) {
    static constexpr char kHex[] = "0123456789abcdef";
    std::string s(64, '0');
    for (int i = 0; i < 32; ++i) {
        const unsigned char b = internal[31 - i];
        s[2 * i] = kHex[b >> 4];
        s[2 * i + 1] = kHex[b & 0x0f];
    }
    return s;
}
static bytes32 internal_of_display(const std::string& disp) {
    bytes32 b{};
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        return 0;
    };
    for (int i = 0; i < 32; ++i)
        b[31 - i] = static_cast<std::uint8_t>((nib(disp[2 * i]) << 4) | nib(disp[2 * i + 1]));
    return b;
}

// ═══════════════════════════════════════════════════════════════════════════
// MN-4 — real IMainchainIndex binding: a carrier keyed to a REAL block hash
// (internal byte order) resolves through the internal->display reversal and is
// accounted; a carrier keyed to a block the chain does NOT know is rejected.
// Also drives the PRODUCTION send-side emitter (CarrierEmitter / carrier_emit.hpp).
// ═══════════════════════════════════════════════════════════════════════════
static void test_mn4_real_index_byteorder() {
    // A "real chain": the display-hex block ids dashd would answer -> height.
    auto chain = std::make_shared<std::map<std::string, u64>>();
    const std::string disp200 =
        "0000000fa1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c";
    (*chain)[disp200] = 200;

    // The REAL-index resolver: reverse internal->display, ask the chain (== what
    // LiveMainchainIndex's bound probe does with the live daemon).
    CallbackMainchainIndex::Resolver real_resolver =
        [chain](const bytes32& prev) -> std::optional<u64> {
            auto it = chain->find(display_hex_of(prev));
            return it == chain->end() ? std::nullopt : std::optional<u64>(it->second);
        };

    V37Engine eng;
    eng.start();
    eng.submit_tracked(LaneRecord::add_lane(CHAIN, small_params())).get();
    auto s0 = eng.snapshot(CHAIN);
    const u64 inc = s0 ? s0->incarnation : 1;
    CallbackMainchainIndex index(real_resolver);
    MemShareTracker tracker;
    CarrierIngest ingest(eng, CHAIN, index, tracker, inc);
    CarrierPeerNode net;                       // no peers: this is a local admit test
    CarrierRelay relay(ingest.fn(), net);
    CarrierEmitter emitter(relay, CHAIN, ALICE_DESC());

    // (a) carrier keyed to the REAL block (internal = reverse of disp200) resolves.
    const bytes32 prev_internal = internal_of_display(disp200);
    const auto er = emitter.emit_own_win(prev_internal, consensus_lz(200), "real.c");
    CHECK(er.minted);
    CHECK(er.outcome.admitted);                            // reversal resolved -> accounted
    const u64 w = work_of_lz(consensus_lz(200));
    // S-6: CarrierIngest submits fire-and-forget into the engine mailbox; the
    // snapshot is read through wait_until like every other MN check (a bare
    // read immediately after emit raced the executor deterministically).
    CHECK(wait_until([&] { auto s = eng.snapshot(CHAIN); return s && static_cast<u64>(s->raw_total) == w; }));
    CHECK(emitter.emitted() == 1);

    // (b) carrier keyed to a block the chain does NOT know is REJECTED (nullopt
    //     bin -> REJECT_POW), and never accounted.
    const bytes32 unknown = internal_of_display(
        "00000000000000000000000000000000000000000000000000000000deadbeef");
    const auto er2 = emitter.emit_own_win(unknown, consensus_lz(200), "unknown.c");
    CHECK(er2.minted);                                     // mint is local PoW, succeeds
    CHECK(!er2.outcome.admitted);                          // but admission rejects it
    {
        auto s = eng.snapshot(CHAIN);
        CHECK(s && static_cast<u64>(s->raw_total) == w);   // unchanged
    }
    CHECK(emitter.emitted() == 1);                         // own-chain did NOT advance
    eng.stop();
}

// ═══════════════════════════════════════════════════════════════════════════
// MN-5 — SEND-SIDE over the socket: node A ORIGINATES its own carriers through
// the production CarrierEmitter (not hand-mined + handle_local), and node B
// accounts them. Two chained own carriers => B accounts both. This is the
// formerly-deferred send half, now bidirectional with MN-1's receive half.
// ═══════════════════════════════════════════════════════════════════════════
static void test_mn5_sendside_emitter_over_socket() {
    Node A(110), B(110);
    CHECK(B.net->listen("127.0.0.1", 0));
    CHECK(A.net->add_peer("127.0.0.1", B.net->listen_port()));
    CHECK(wait_until([&] { return B.net->n_peers() >= 1; }));

    CarrierEmitter emitterA(*A.relay, CHAIN, ALICE_DESC());
    const u64 w = work_of_lz(consensus_lz(100));

    const auto er = emitterA.emit_own_win(mainchain_hash(100), consensus_lz(100), "A.emit");
    CHECK(er.minted);
    CHECK(er.outcome.admitted);                            // A accounts its own win
    CHECK(er.outcome.relayed && er.outcome.peers_reached >= 1);  // and it reached B
    CHECK(emitterA.emitted() == 1);
    CHECK(wait_until([&] { return B.raw_total() == w; }));
    CHECK(B.accounts_identity(ALICE_DESC().identity_key()));

    // A second, chained own carrier: B accounts both (2 × w).
    const auto er2 = emitterA.emit_own_win(mainchain_hash(101), consensus_lz(101), "A.emit2");
    CHECK(er2.minted && er2.outcome.admitted);
    CHECK(emitterA.emitted() == 2);
    CHECK(wait_until([&] { return B.raw_total() == 2 * w; }));
    CHECK(B.identity_count() == 1);                        // still only ALICE
}

int main() {
    test_mn1_b_accounts_a();
    test_mn2_duplex_and_receipts();
    test_mn3_no_double_account();
    test_mn4_real_index_byteorder();
    test_mn5_sendside_emitter_over_socket();
    std::printf("%d checks, %d failures\n", g_checks, g_failures);
    return g_failures == 0 ? 0 : 1;
}
