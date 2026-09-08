// V37 Track A2 step (b)(3) — SEND-SIDE queue test (the share-level own-win half).
//
// Proves carrier_send.hpp end to end over a REAL loopback socket: a stratum
// share solved on node A (per-miner payout script, header hashPrevBlock keyed
// to a block A's index resolves) is queued off the hot path, ground, admitted
// into A's own V37Engine, flooded as the FROZEN CarrierWire frame, and ACCOUNTED
// in node B's engine under the MINER's identity. Also pins: per-identity chains,
// the W3-G1 block-winner path, no-identity decline vs block-win fallback,
// unresolved parent (nothing ground), share backpressure (block winners never
// shed), the origin-side tag clamp, and the header byte-order helper.
//
// Same production pieces the daemon wires: carrier_net / w3_relay /
// carrier_ingest / v37_engine, with a synthetic CallbackMainchainIndex map in
// place of the daemon's LiveMainchainIndex (carrier_index.hpp; the index seam is
// identical). stdlib + POSIX sockets, self-harness shape of
// v37_a2_multinode_test.cpp.

#include <netinet/in.h>

#include <atomic>
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

#include <c2pool/v37/carrier_ingest.hpp>
#include <c2pool/v37/carrier_net.hpp>
#include <c2pool/v37/carrier_send.hpp>
#include <c2pool/v37/v37_engine.hpp>
#include <c2pool/v37/w2_admission.hpp>
#include <c2pool/v37/w2_receipt.hpp>
#include <c2pool/v37/w3_relay.hpp>

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

// A P2PKH output script for a 20-byte hash160 filled with `fill` — what
// classify_address_for_coin hands the mint seam for a valid DASH address.
static std::vector<std::uint8_t> p2pkh_script(std::uint8_t fill) {
    std::vector<std::uint8_t> s = {0x76, 0xa9, 0x14};
    for (int i = 0; i < 20; ++i) s.push_back(fill);
    s.push_back(0x88); s.push_back(0xac);
    return s;
}
static PayoutDescriptor desc_of(std::uint8_t fill) {
    PayoutDescriptor d;
    d.pay = ::v37::canonicalize_script(p2pkh_script(fill));
    return d;
}

// An 80-byte header whose hashPrevBlock [4..36) is `prev` (internal order).
static std::vector<unsigned char> header_with_prev(const bytes32& prev) {
    std::vector<unsigned char> h(80, 0x00);
    std::memcpy(h.data() + 4, prev.data(), 32);
    return h;
}

static CallbackMainchainIndex::Resolver synthetic_index(u64 tip, u64 horizon = 64) {
    auto by_hash = std::make_shared<std::map<bytes32, u64>>();
    u64 lo = tip > horizon ? tip - horizon : 0;
    for (u64 x = lo; x <= tip; ++x) (*by_hash)[mainchain_hash(x)] = x;
    return [by_hash](const bytes32& h) -> std::optional<u64> {
        auto it = by_hash->find(h);
        return it == by_hash->end() ? std::nullopt : std::optional<u64>(it->second);
    };
}

struct Node {
    V37Engine engine;
    std::unique_ptr<CallbackMainchainIndex> index;
    MemShareTracker tracker;
    std::unique_ptr<CarrierIngest> ingest;
    std::unique_ptr<CarrierPeerNode> net;
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
        net->set_inbound([this](const std::vector<std::uint8_t>& f) { relay->handle_inbound(f); });
    }
    ~Node() { if (net) net->stop(); engine.stop(); }

    u64 raw_total() {
        auto s = engine.snapshot(CHAIN);
        return s ? static_cast<u64>(s->raw_total) : 0;
    }
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

template <class F>
static bool wait_until(F f, int timeout_ms = 5000) {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    while (std::chrono::steady_clock::now() < deadline) {
        if (f()) return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    return f();
}

static OwnWinRequest req_of(u64 parent_bin, std::uint8_t miner_fill, bool won, const char* tag) {
    auto r = own_win_request_of_header(header_with_prev(mainchain_hash(parent_bin)),
                                       miner_fill ? p2pkh_script(miner_fill) : std::vector<std::uint8_t>{},
                                       won, tag);
    return *r;
}

// ═══════════════════════════════════════════════════════════════════════════
// SS-1 — a stratum SHARE on A, queued off the hot path, is accounted on A AND
// on B under the MINER's identity (not a pool placeholder).
// ═══════════════════════════════════════════════════════════════════════════
static void test_ss1_share_over_socket_per_miner_identity() {
    Node A(110), B(110);
    CHECK(B.net->listen("127.0.0.1", 0));
    CHECK(A.net->add_peer("127.0.0.1", B.net->listen_port()));
    CHECK(wait_until([&] { return B.net->n_peers() >= 1; }));

    CarrierSendQueue q(*A.relay, *A.index, CHAIN);
    q.start();
    const u64 w = work_of_lz(consensus_lz(100));

    CHECK(q.submit(req_of(100, 0x11, false, "share:0011")));   // returns at once
    CHECK(q.wait_idle());
    const auto st = q.stats();
    CHECK(st.submitted == 1 && st.processed == 1 && st.admitted == 1);
    CHECK(st.relayed == 1 && st.peers_reached_total >= 1 && st.block_winners == 0);
    CHECK(wait_until([&] { return A.raw_total() == w; }));         // A accounts its own share
    CHECK(wait_until([&] { return B.raw_total() == w; }));         // B accounts it too
    CHECK(B.accounts_identity(desc_of(0x11).identity_key()));       // under the MINER's identity
    CHECK(q.identities() == 1);
    CHECK(!(q.last_own(desc_of(0x11).identity_key()) == W2_GENESIS_PREV_OWN));  // chain advanced
    q.stop();
}

// ═══════════════════════════════════════════════════════════════════════════
// SS-2 — two miners on the same node: one chain PER IDENTITY, B sees both.
// ═══════════════════════════════════════════════════════════════════════════
static void test_ss2_per_identity_chains() {
    Node A(110), B(110);
    CHECK(B.net->listen("127.0.0.1", 0));
    CHECK(A.net->add_peer("127.0.0.1", B.net->listen_port()));
    CHECK(wait_until([&] { return B.net->n_peers() >= 1; }));

    // Exercise the relay-serialization hook the daemon uses while CarrierRelay
    // has no internal lock: the same mutex guards A's inbound dispatch.
    std::mutex relay_mtx;
    A.net->set_inbound([&](const std::vector<std::uint8_t>& f) {
        std::lock_guard<std::mutex> lk(relay_mtx);
        A.relay->handle_inbound(f);
    });
    CarrierSendQueue::Options opt;
    opt.relay_mutex = &relay_mtx;
    CarrierSendQueue q(*A.relay, *A.index, CHAIN, opt);
    q.start();
    const u64 w = work_of_lz(consensus_lz(100));
    CHECK(q.submit(req_of(100, 0x11, false, "m1.a")));
    CHECK(q.submit(req_of(101, 0x22, false, "m2.a")));
    CHECK(q.submit(req_of(102, 0x11, false, "m1.b")));
    CHECK(q.wait_idle());
    CHECK(q.stats().admitted == 3 && q.stats().rejected == 0);
    CHECK(q.identities() == 2);
    CHECK(wait_until([&] { return B.raw_total() == 3 * w; }));
    CHECK(B.identity_count() == 2);
    CHECK(B.accounts_identity(desc_of(0x11).identity_key()));
    CHECK(B.accounts_identity(desc_of(0x22).identity_key()));
    // The two chains are independent heads.
    CHECK(!(q.last_own(desc_of(0x11).identity_key()) == q.last_own(desc_of(0x22).identity_key())));
    q.stop();
}

// ═══════════════════════════════════════════════════════════════════════════
// SS-3 — block winner (won_block=true) takes the W3-G1 path and is counted as
// such; a share with NO identity is declined; a block win with NO identity
// falls back to the configured pool descriptor (never dropped).
// ═══════════════════════════════════════════════════════════════════════════
static void test_ss3_block_winner_and_identity_fallback() {
    Node A(110), B(110);
    CHECK(B.net->listen("127.0.0.1", 0));
    CHECK(A.net->add_peer("127.0.0.1", B.net->listen_port()));
    CHECK(wait_until([&] { return B.net->n_peers() >= 1; }));

    CarrierSendQueue::Options opt;
    opt.fallback_desc = desc_of(0xB0);
    CarrierSendQueue q(*A.relay, *A.index, CHAIN, opt);
    const u64 w = work_of_lz(consensus_lz(100));

    // synchronous path: deterministic outcomes
    const auto o1 = q.emit_now(req_of(100, 0x11, true, "win:m1"));
    CHECK(o1.status == CarrierSendQueue::EmitOutcome::Status::ADMITTED);
    CHECK(o1.parent_height && *o1.parent_height == 100 && o1.lz_bits == consensus_lz(100));
    CHECK(o1.relay.admitted && o1.relay.peers_reached >= 1 && !o1.used_fallback);
    CHECK(o1.identity == desc_of(0x11).identity_key());

    const auto o2 = q.emit_now(req_of(101, 0x00, false, "share:noid"));
    CHECK(o2.status == CarrierSendQueue::EmitOutcome::Status::NO_IDENTITY);

    const auto o3 = q.emit_now(req_of(101, 0x00, true, "win:noid"));
    CHECK(o3.status == CarrierSendQueue::EmitOutcome::Status::ADMITTED);
    CHECK(o3.used_fallback && o3.identity == desc_of(0xB0).identity_key());

    const auto st = q.stats();
    CHECK(st.admitted == 2 && st.block_winners == 2 && st.no_identity == 1 && st.fallback_identity == 1);
    CHECK(wait_until([&] { return B.raw_total() == 2 * w; }));
    CHECK(B.accounts_identity(desc_of(0x11).identity_key()));
    CHECK(B.accounts_identity(desc_of(0xB0).identity_key()));
}

// ═══════════════════════════════════════════════════════════════════════════
// SS-4 — a parent the index cannot place: nothing is ground, nothing accounted
// (the --carrier-synthetic-index / off-horizon / dashd-unknown case). A block
// winner retries a bounded number of times, a share once.
// ═══════════════════════════════════════════════════════════════════════════
static void test_ss4_unresolved_parent() {
    Node A(110);
    std::atomic<int> probes{0};
    CallbackMainchainIndex counting([&](const bytes32&) -> std::optional<u64> { ++probes; return std::nullopt; });
    CarrierSendQueue::Options opt;
    opt.block_resolve_attempts = 3;
    opt.block_resolve_backoff = std::chrono::milliseconds(1);
    CarrierSendQueue q(*A.relay, counting, CHAIN, opt);

    const auto o1 = q.emit_now(req_of(100, 0x11, false, "share:unres"));
    CHECK(o1.status == CarrierSendQueue::EmitOutcome::Status::UNRESOLVED_PARENT);
    CHECK(probes == 1);
    const auto o2 = q.emit_now(req_of(100, 0x11, true, "win:unres"));
    CHECK(o2.status == CarrierSendQueue::EmitOutcome::Status::UNRESOLVED_PARENT);
    CHECK(probes == 4);                                            // 1 + 3 attempts
    CHECK(q.stats().unresolved_parent == 2 && q.stats().admitted == 0);
    CHECK(A.raw_total() == 0);
    CHECK(q.identities() == 0);                                    // chain never touched
}

// ═══════════════════════════════════════════════════════════════════════════
// SS-5 — backpressure: shares beyond max_queued_shares are shed; a block
// winner is NEVER shed; the survivors are emitted once the worker runs; after
// stop() submit refuses.
// ═══════════════════════════════════════════════════════════════════════════
static void test_ss5_backpressure_never_sheds_block_winner() {
    Node A(110);
    CarrierSendQueue::Options opt;
    opt.max_queued_shares = 2;
    opt.fallback_desc = desc_of(0xB0);
    CarrierSendQueue q(*A.relay, *A.index, CHAIN, opt);   // NOT started: items pile up
    CHECK(q.submit(req_of(100, 0x11, false, "s1")));
    CHECK(q.submit(req_of(101, 0x11, false, "s2")));
    CHECK(!q.submit(req_of(102, 0x11, false, "s3")));      // shed
    CHECK(q.submit(req_of(103, 0x22, true, "win")));       // block winner always queued
    CHECK(q.queued() == 3 && q.stats().shed_shares == 1);
    q.start();
    CHECK(q.wait_idle());
    const auto st = q.stats();
    CHECK(st.processed == 3 && st.admitted == 3 && st.block_winners == 1 && st.deferred_relay == 3);  // no peers: DEFER, never dropped
    CHECK(wait_until([&] { return A.raw_total() == 3 * work_of_lz(consensus_lz(100)); }));
    q.stop();
    CHECK(!q.submit(req_of(104, 0x11, false, "late")));
    CHECK(q.stats().after_stop == 1);
}

// ═══════════════════════════════════════════════════════════════════════════
// SS-6 — origin-side tag clamp + header byte-order helper.
// ═══════════════════════════════════════════════════════════════════════════
static void test_ss6_tag_clamp_and_header_helper() {
    CHECK(clamp_carrier_tag(std::string(200, 'x')).size() == kCarrierSendTagMax);
    CHECK(clamp_carrier_tag("win:0123456789abcdef") == "win:0123456789abcdef");
    auto r = own_win_request_of_header(header_with_prev(mainchain_hash(7)), p2pkh_script(0x11), false,
                                       std::string(200, 't'));
    CHECK(r && r->prev_block_internal == mainchain_hash(7) && r->tag.size() == kCarrierSendTagMax);
    CHECK(!own_win_request_of_header(std::vector<unsigned char>(79, 0), {}, false, "short"));
    // descriptor: P2PKH canon, valid; RAW carries the script so the binding validates
    auto d1 = descriptor_of_payout_script(p2pkh_script(0x11));
    CHECK(d1 && d1->pay.kind == ::v37::ScriptKind::P2PKH && d1->raw_script.empty() && d1->valid());
    auto d2 = descriptor_of_payout_script(std::vector<std::uint8_t>{0x6a, 0x04, 1, 2, 3, 4});
    CHECK(d2 && d2->pay.kind == ::v37::ScriptKind::RAW && !d2->raw_script.empty() && d2->valid());
    CHECK(!descriptor_of_payout_script({}));
}

int main() {
    test_ss1_share_over_socket_per_miner_identity();
    test_ss2_per_identity_chains();
    test_ss3_block_winner_and_identity_fallback();
    test_ss4_unresolved_parent();
    test_ss5_backpressure_never_sheds_block_winner();
    test_ss6_tag_clamp_and_header_helper();
    std::printf("%d checks, %d failures\n", g_checks, g_failures);
    return g_failures == 0 ? 0 : 1;
}
