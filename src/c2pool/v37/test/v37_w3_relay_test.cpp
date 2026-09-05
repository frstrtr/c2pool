// V37 Track A2 / W3 — carrier-relay KAT suite. Standalone, stdlib-only
// (g++ -std=c++20 -pthread -I src), the same harness convention as
// v37_scaffold_test.cpp / v37_executor_test.cpp / v37_w2_ingestion_test.cpp:
// no gtest, no core/Boost link.
//
// WHAT THIS PINS (spec /home/ubuntu/v37-work/v37-a2-w3-relay-spec.md):
//   WR-1  carrier encode/decode round-trip (consensus fields preserved).
//   WR-2  R_MAX enforcement at decode — a carrier presenting > R_MAX receipts
//         is rejected WHOLE, before any push (§2.3, WT-1). No truncate-accept.
//   WR-3  the W3-MUST identity-binding KAT (spec close): a receipt whose carried
//         identity != descriptor.identity_key() is rejected at DECODE and the
//         carrier STANDS; a mis-bound CARRIER is a whole-carrier reject. This is
//         the anti-forgery seam W2's verify flagged (credit-misdirection hole).
//   WR-4  block-winning-carrier UNCONDITIONAL append (§4, the #889/#903 defect):
//         appended/credited regardless of relay dedup, no peers, or a re-inject
//         already in the relay-seen set (BW-2).
//   WR-5  relay dedup (§5.2): an echoed carrier is relayed ONCE; the second copy
//         is suppressed for relay AND credited once by the W2 window — the two
//         dedup mechanisms stay separate (no double-relay-credit). A mis-bound
//         receipt is NOT amplified onto the network (cleaned re-encode).
//   WR-6  a multi-process propagation smoke over REAL loopback sockets: >=8
//         child processes each receive the SAME carrier frame over 127.0.0.1,
//         decode it, and MUST agree bit-for-bit on the survivors (the DT-2
//         interleaving/transport-transparency property at smoke scale).
//   WR-7  the carrier-bloat measurement hook (§8.4) records the BM-2 inputs and
//         is off by default / never on the consensus path.
//
// LEG DISCIPLINE (spec §8): raw-work / identity / structure / ordering only. No
// decayed value is asserted (OI-7 / W3-B2 blocked). The engine append is driven
// END-TO-END through the W0 V37Engine::submit_tracked seam; the relay layer
// never touches Lane / LaneExecutor (O1, disjoint from the W4-unblock lane).

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <vector>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#include <c2pool/v37/v37_engine.hpp>
#include <c2pool/v37/w2_admission.hpp>
#include <c2pool/v37/w2_receipt.hpp>
#include <c2pool/v37/w3_relay.hpp>
#include <sharechain/v37/v37_roundabout.hpp>

using namespace c2pool::v37n;
using ::v37::bytes32;
using ::v37::ChainId;
using ::v37::LaneParams;
using ::v37::LaneRecord;
using ::v37::PayoutDescriptor;
using ::v37::SubmitResult;

static int g_failures = 0;
static int g_checks = 0;

#define CHECK(cond)                                                          \
    do {                                                                     \
        ++g_checks;                                                          \
        if (!(cond)) {                                                       \
            ++g_failures;                                                    \
            std::printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);      \
        }                                                                    \
    } while (0)

static const ChainId CHAIN = 1;
static const ChainId OTHER_CHAIN = 2;

static LaneParams small_params() {
    LaneParams p;
    p.window = 256; p.c0 = 128; p.rollup = 8;
    p.level_caps = {16}; p.half_life = 64; p.journal_depth = 16;
    return p;
}

// A valid V37.0 P2PKH descriptor, one distinct identity per fill byte.
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

// ── mine: grind a nonce so the event clears its own bits (real sha256d PoW) ──
// `identity` is set EXPLICITLY (not always = descriptor.identity_key()) so we
// can forge a mis-bound event: valid PoW binding one identity while the credit
// descriptor names another. A WELL-BOUND event uses identity = desc key.
static WorkEvent mine_bound(ChainId chain_id, const PayoutDescriptor& desc,
                            const bytes32& identity, u64 origin_bin,
                            const bytes32& prev_own, unsigned lz_bits,
                            const char* tag, u64 salt = 0) {
    WorkEvent ev;
    ev.chain_id = chain_id;
    ev.identity = identity;
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
    std::printf("FATAL mine: nonce space exhausted (%s)\n", tag);
    std::abort();
}
// Well-bound convenience: identity == descriptor.identity_key() (W3-MUST holds).
static WorkEvent mine(ChainId chain_id, const PayoutDescriptor& desc,
                      u64 origin_bin, const bytes32& prev_own, unsigned lz_bits,
                      const char* tag, u64 salt = 0) {
    return mine_bound(chain_id, desc, desc.identity_key(), origin_bin, prev_own,
                      lz_bits, tag, salt);
}

// ── injectable seams (mirror the W2 KAT fixtures) ───────────────────────────
struct KatMainchainIndex : IMainchainIndex {
    u64 tip, horizon;
    std::map<bytes32, u64> by_hash;
    explicit KatMainchainIndex(u64 t, u64 h = 64) : tip(t), horizon(h) {
        u64 lo = tip > horizon ? tip - horizon : 0;
        for (u64 x = lo; x <= tip; ++x) by_hash[mainchain_hash(x)] = x;
    }
    std::optional<u64> height_of(const bytes32& h) const override {
        auto it = by_hash.find(h);
        return it == by_hash.end() ? std::nullopt : std::optional<u64>(it->second);
    }
};
struct KatShareTracker : IShareTracker {
    std::map<bytes32, std::set<bytes32>> chained;
    bool has_prev_own(const bytes32& id, const bytes32& prev) const override {
        if (prev == W2_GENESIS_PREV_OWN) return true;
        auto it = chained.find(id);
        return it != chained.end() && it->second.count(prev) != 0;
    }
    void record_share(const bytes32& id, const bytes32& h) override {
        chained[id].insert(h);
    }
};

// ── an admission harness: W2 ReceiptAdmitter teed into a real V37Engine ─────
// Provides the CarrierRelay::AdmitFn. The engine is the W0 seam (submit_tracked
// into the private W1 executor); the relay never sees Lane/LaneExecutor.
struct AdmitHarness {
    KatMainchainIndex idx;
    KatShareTracker trk;
    V37Engine engine;
    std::unique_ptr<ReceiptAdmitter> adm;
    u64 total_engine_pushes = 0;

    explicit AdmitHarness(u64 tip) : idx(tip) {
        engine.start();
        u64 inc = add_lane();
        adm = std::make_unique<ReceiptAdmitter>(CHAIN, idx, trk, inc);
    }
    ~AdmitHarness() { engine.stop(); }

    u64 add_lane() {
        auto r = engine.submit_tracked(LaneRecord::add_lane(CHAIN, small_params())).get();
        auto s = engine.snapshot(CHAIN);
        return s ? s->incarnation : 0;
    }

    CarrierRelay::AdmitFn fn() {
        return [this](const WorkEvent& c, const std::vector<WorkEvent>& rs) {
            RecordSink sink = [this](const EmittedPush& p) {
                // fire-and-forget into the mailbox is the production path; the
                // KAT waits on the future so it can assert credit deterministically.
                auto res = engine.submit_tracked(
                    LaneRecord::push(CHAIN, p.descriptor, p.w_raw, p.flags)).get();
                if (res.applied()) ++total_engine_pushes;
            };
            return adm->admit(c, rs, sink);
        };
    }
    u64 raw_total() {
        auto s = engine.snapshot(CHAIN);
        return s ? (u64)s->raw_total : 0;
    }
};

// ── test transports (bindings of the ICarrierTransport seam) ────────────────
struct NullTransport : ICarrierTransport {           // no peers: relay defers
    std::size_t broadcast(const std::vector<std::uint8_t>&) override { return 0; }
    std::size_t n_peers() const override { return 0; }
};
struct CountingTransport : ICarrierTransport {
    std::size_t peers = 3;
    int sends = 0;
    std::vector<std::uint8_t> last_frame;
    std::size_t broadcast(const std::vector<std::uint8_t>& f) override {
        ++sends; last_frame = f; return peers;
    }
    std::size_t n_peers() const override { return peers; }
};

// ═══════════════════════════════════════════════════════════════════════════
// WR-1 — carrier encode/decode round-trip
// ═══════════════════════════════════════════════════════════════════════════
static bool same_event(const WorkEvent& a, const WorkEvent& b) {
    return a.preimage() == b.preimage() &&
           a.descriptor.identity_key() == b.descriptor.identity_key() &&
           a.descriptor.pay == b.descriptor.pay;
}
static void test_wr1_roundtrip() {
    KatMainchainIndex idx(110);
    WorkEvent c = mine(CHAIN, ALICE_DESC(), 100, W2_GENESIS_PREV_OWN, 0, "c");
    WorkEvent r0 = mine(CHAIN, ALICE_DESC(), 99, c.hash(), 0, "r0", 1);
    WorkEvent r1 = mine(CHAIN, ALICE_DESC(), 98, c.hash(), 0, "r1", 2);

    for (std::size_t n = 0; n <= W3_R_MAX; ++n) {
        Carrier in; in.carrier = c;
        std::vector<WorkEvent> pool = {r0, r1, r0, r1};   // reuse; identity-bound
        for (std::size_t k = 0; k < n; ++k) in.receipts.push_back(pool[k]);
        auto bytes = CarrierWire::encode(in);
        auto dr = CarrierWire::decode(bytes);
        CHECK(dr.ok());
        CHECK(dr.carrier.receipts.size() == n);            // exact count preserved
        CHECK(same_event(dr.carrier.carrier, c));          // carrier preserved
        for (std::size_t k = 0; k < n; ++k)
            CHECK(same_event(dr.carrier.receipts[k], pool[k]));
        // re-encode is byte-identical (transport transparency at the codec level)
        CHECK(CarrierWire::encode(dr.carrier) == bytes);
    }
    // truncated frame -> whole reject (never a partial decode)
    auto bytes = CarrierWire::encode([&] { Carrier x; x.carrier = c; x.receipts = {r0}; return x; }());
    bytes.pop_back();
    CHECK(CarrierWire::decode(bytes).status == WireStatus::REJECT_TRUNCATED);
    // bad version tag
    auto bad = CarrierWire::encode([&] { Carrier x; x.carrier = c; return x; }());
    bad[0] = 0x7f;
    CHECK(CarrierWire::decode(bad).status == WireStatus::REJECT_BAD_VERSION);
}

// ═══════════════════════════════════════════════════════════════════════════
// WR-2 — R_MAX enforcement (> R_MAX whole-carrier reject at decode)
// ═══════════════════════════════════════════════════════════════════════════
static void test_wr2_rmax() {
    WorkEvent c = mine(CHAIN, ALICE_DESC(), 100, W2_GENESIS_PREV_OWN, 0, "c");
    std::vector<WorkEvent> rs;
    for (int i = 0; i < 5; ++i)
        rs.push_back(mine(CHAIN, ALICE_DESC(), 99, c.hash(), 0, "r", 10 + i));

    // exactly R_MAX: accepted.
    Carrier ok; ok.carrier = c; ok.receipts.assign(rs.begin(), rs.begin() + W3_R_MAX);
    CHECK(CarrierWire::decode(CarrierWire::encode(ok)).ok());
    CHECK(CarrierWire::decode(CarrierWire::encode(ok)).carrier.receipts.size() == W3_R_MAX);

    // R_MAX + 1: whole carrier rejected, ZERO receipts survive (no truncate).
    Carrier over; over.carrier = c; over.receipts = rs;   // 5 > 4
    auto dr = CarrierWire::decode(CarrierWire::encode(over));
    CHECK(dr.status == WireStatus::REJECT_RMAX);
    CHECK(dr.carrier.receipts.empty());
    // Hand-set an oversize count byte directly (an adversarial frame) — same reject.
    auto raw = CarrierWire::encode(ok);
    // count byte sits right after version(1) + carrier-event bytes; recompute:
    Carrier bare; bare.carrier = c;
    std::size_t count_pos = CarrierWire::encode(bare).size() - /*count byte*/ 1;
    raw[count_pos] = (std::uint8_t)(W3_R_MAX + 1);
    CHECK(CarrierWire::decode(raw).status == WireStatus::REJECT_RMAX);
}

// ═══════════════════════════════════════════════════════════════════════════
// WR-3 — the W3-MUST identity-binding rejection KAT
// ═══════════════════════════════════════════════════════════════════════════
static void test_wr3_identity_binding() {
    // A well-bound carrier under ALICE.
    WorkEvent c = mine(CHAIN, ALICE_DESC(), 100, W2_GENESIS_PREV_OWN, 0, "c");
    CHECK(CarrierWire::identity_bound(c));

    // A well-bound receipt (identity == its descriptor key).
    WorkEvent good = mine(CHAIN, ALICE_DESC(), 99, c.hash(), 0, "good", 1);
    CHECK(CarrierWire::identity_bound(good));

    // A MIS-BOUND receipt: valid PoW binding ALICE's identity, but the credit
    // descriptor is BOB's — the exact credit-misdirection forgery. PoW is real
    // (identity is in the preimage), so this is not a PoW failure; it is the
    // binding W2 does not check and W3 MUST reject at decode.
    WorkEvent forged = mine_bound(CHAIN, /*credit->*/ BOB_DESC(),
                                  /*PoW-bound id*/ ALICE_DESC().identity_key(),
                                  99, c.hash(), 0, "forged", 2);
    CHECK(forged.meets_own_target());                 // PoW is genuinely valid
    CHECK(!CarrierWire::identity_bound(forged));       // ...but the binding breaks
    CHECK(forged.identity == ALICE_DESC().identity_key());
    CHECK(forged.descriptor.identity_key() == BOB_DESC().identity_key());

    // Decode a carrier bearing [good, forged]: the forged receipt is dropped at
    // decode, the carrier and the good receipt STAND (WT-2 / spec close).
    Carrier in; in.carrier = c; in.receipts = {good, forged};
    auto dr = CarrierWire::decode(CarrierWire::encode(in));
    CHECK(dr.ok());
    CHECK(dr.carrier.receipts.size() == 1);            // only `good` survives
    CHECK(same_event(dr.carrier.receipts[0], good));
    CHECK(dr.dropped.size() == 1);
    CHECK(dr.dropped[0].second == ReceiptWireDrop::MISBOUND_IDENTITY);
    CHECK(dr.dropped[0].first == "forged");

    // A MIS-BOUND CARRIER is fatal — whole-carrier reject (credit-misdirection
    // on the carrier itself must never stand).
    WorkEvent forged_carrier = mine_bound(CHAIN, BOB_DESC(),
                                          ALICE_DESC().identity_key(),
                                          100, W2_GENESIS_PREV_OWN, 0, "fc");
    Carrier bad; bad.carrier = forged_carrier; bad.receipts = {good};
    auto dr2 = CarrierWire::decode(CarrierWire::encode(bad));
    CHECK(dr2.status == WireStatus::REJECT_CARRIER_UNBOUND);
    CHECK(dr2.carrier.receipts.empty());

    // End-to-end through the relay: the forged receipt is never credited, and
    // never re-broadcast (the cleaned re-encode carries only `good`).
    AdmitHarness h(110);
    CountingTransport tx;
    CarrierRelay relay(h.fn(), tx);
    auto o = relay.handle_inbound(CarrierWire::encode(in));
    CHECK(o.wire == WireStatus::OK);
    CHECK(o.admitted);
    CHECK(o.wire_dropped.size() == 1);
    // admission saw carrier + 1 receipt (the good one); the forged one is gone.
    CHECK(o.admission.pushes.size() == 2);
    // the relayed frame decodes to a carrier with exactly the surviving receipt
    CHECK(tx.sends == 1);
    auto relayed = CarrierWire::decode(tx.last_frame);
    CHECK(relayed.ok() && relayed.carrier.receipts.size() == 1);
    CHECK(same_event(relayed.carrier.receipts[0], good));
}

// ═══════════════════════════════════════════════════════════════════════════
// WR-4 — block-winning-carrier UNCONDITIONAL append (§4)
// ═══════════════════════════════════════════════════════════════════════════
static void test_wr4_block_winner() {
    // BW-1 flavour: append with NO peers (relay defers). Append MUST still stand.
    {
        AdmitHarness h(110);
        NullTransport tx;
        CarrierRelay relay(h.fn(), tx);
        WorkEvent c = mine(CHAIN, ALICE_DESC(), 100, W2_GENESIS_PREV_OWN, 0, "bw.c");
        WorkEvent st = mine(CHAIN, ALICE_DESC(), 99, c.hash(), 0, "bw.st", 1);
        Carrier win; win.carrier = c; win.receipts = {st};
        auto o = relay.append_block_winner(win);
        CHECK(o.admitted);                              // credited despite 0 peers
        CHECK(!o.relayed);                              // relay legitimately deferred
        CHECK(o.admission.pushes.size() == 2);          // carrier + receipt appended
        CHECK(h.raw_total() == c.work() + st.work());   // PPLNS credit landed
    }
    // BW-2: a block-winner ALREADY in the relay-seen set still appends/credits
    // (relay drop != consensus keep — relay-seen never gates append, §5.2.1).
    {
        AdmitHarness h(110);
        CountingTransport tx;
        CarrierRelay relay(h.fn(), tx);
        WorkEvent c = mine(CHAIN, ALICE_DESC(), 100, W2_GENESIS_PREV_OWN, 0, "bw2.c");
        Carrier win; win.carrier = c;
        // Seed the relay-seen set with the winner's hash (as if we'd relayed it).
        relay.seen().mark_and_test(c.hash());
        CHECK(relay.seen().seen(c.hash()));
        auto o = relay.append_block_winner(win);
        CHECK(o.admitted);                              // STILL credited
        CHECK(h.raw_total() == c.work());
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// WR-5 — relay dedup: echo relayed ONCE, credited ONCE (no double-relay-credit)
// ═══════════════════════════════════════════════════════════════════════════
static void test_wr5_relay_dedup() {
    AdmitHarness h(110);
    CountingTransport tx;
    CarrierRelay relay(h.fn(), tx);
    relay.stats().enabled = true;

    WorkEvent c = mine(CHAIN, ALICE_DESC(), 100, W2_GENESIS_PREV_OWN, 0, "d.c");
    WorkEvent st = mine(CHAIN, ALICE_DESC(), 99, c.hash(), 0, "d.st", 1);
    Carrier car; car.carrier = c; car.receipts = {st};
    auto frame = CarrierWire::encode(car);

    // First arrival: admitted + relayed.
    auto o1 = relay.handle_inbound(frame);
    CHECK(o1.admitted);
    CHECK(o1.relayed);
    CHECK(tx.sends == 1);
    u64 raw_after_first = h.raw_total();
    CHECK(raw_after_first == c.work() + st.work());

    // Echo (same frame): relay SUPPRESSED (dedup), and the W2 consensus window
    // credits it ZERO more (carrier already accounted). No double-relay-credit.
    auto o2 = relay.handle_inbound(frame);
    CHECK(!o2.relayed);                                 // relay dedup fired
    CHECK(tx.sends == 1);                               // no second broadcast
    CHECK(o2.admission.carrier_status == CarrierStatus::REJECT_DEDUP);
    CHECK(h.raw_total() == raw_after_first);            // credit unchanged

    // The two dedup mechanisms are separate stores (§5.2.4): the relay-seen set
    // has 1 entry; the W2 window (inside the admitter) is unaffected by it.
    CHECK(relay.seen().size() == 1);
    CHECK(relay.stats().relay_received == 2);
    CHECK(relay.stats().relay_dedup_hits == 1);
}

// ═══════════════════════════════════════════════════════════════════════════
// WR-6 — multi-process propagation smoke over REAL loopback sockets
// ═══════════════════════════════════════════════════════════════════════════
// N child processes each connect to a 127.0.0.1 listener, receive the SAME
// length-prefixed carrier frame, decode it (real CarrierWire::decode in a
// separate address space), and MUST agree bit-for-bit on the outcome. This is
// the transport-transparency / interleaving-invariance property (DT-1/DT-2)
// exercised across process + socket boundaries at smoke scale.
static bool send_all(int fd, const std::uint8_t* p, std::size_t n) {
    std::size_t off = 0;
    while (off < n) {
        ssize_t k = ::send(fd, p + off, n - off, 0);
        if (k <= 0) { if (k < 0 && errno == EINTR) continue; return false; }
        off += (std::size_t)k;
    }
    return true;
}
static bool recv_all(int fd, std::uint8_t* p, std::size_t n) {
    std::size_t off = 0;
    while (off < n) {
        ssize_t k = ::recv(fd, p + off, n - off, 0);
        if (k <= 0) { if (k < 0 && errno == EINTR) continue; return false; }
        off += (std::size_t)k;
    }
    return true;
}
// The child return protocol (exit code): 42 == the exact expected decode
// (status OK, survivors == EXPECTED_SURVIVORS, dropped == EXPECTED_DROPPED, and
// the cleaned re-encode is byte-identical to the parent's cleaned frame). Any
// other value flags a divergence.
static constexpr int CHILD_OK = 42;
static constexpr std::size_t EXPECTED_SURVIVORS = 1;
static constexpr std::size_t EXPECTED_DROPPED   = 1;

static int child_peer(std::uint16_t port,
                      const std::vector<std::uint8_t>& expected_clean) {
    int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return 2;
    // Bound the wait so a stuck child never hangs CI.
    timeval tv{5, 0};
    ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    ::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (::connect(fd, (sockaddr*)&addr, sizeof(addr)) != 0) { ::close(fd); return 3; }

    std::uint8_t lenbuf[4];
    if (!recv_all(fd, lenbuf, 4)) { ::close(fd); return 4; }
    std::uint32_t len = 0;
    for (int i = 0; i < 4; ++i) len |= (std::uint32_t)lenbuf[i] << (8 * i);
    std::vector<std::uint8_t> frame(len);
    if (len && !recv_all(fd, frame.data(), len)) { ::close(fd); return 5; }

    auto dr = CarrierWire::decode(frame);
    std::uint8_t ack = 0;
    int code = CHILD_OK;
    if (!dr.ok()) code = 6;
    else if (dr.carrier.receipts.size() != EXPECTED_SURVIVORS) code = 7;
    else if (dr.dropped.size() != EXPECTED_DROPPED) code = 8;
    else if (CarrierWire::encode(dr.carrier) != expected_clean) code = 9;
    ack = (std::uint8_t)code;
    send_all(fd, &ack, 1);           // best-effort ack back to the parent
    ::close(fd);
    return code;
}

static void test_wr6_multiproc_loopback() {
    const int N = 8;
    // Build the propagated carrier: one well-bound receipt + one mis-bound
    // (forged) receipt, so every child MUST drop exactly one and keep exactly
    // one — a non-trivial, deterministic decode across the wire.
    WorkEvent c = mine(CHAIN, ALICE_DESC(), 100, W2_GENESIS_PREV_OWN, 0, "mp.c");
    WorkEvent good = mine(CHAIN, ALICE_DESC(), 99, c.hash(), 0, "mp.good", 1);
    WorkEvent forged = mine_bound(CHAIN, BOB_DESC(), ALICE_DESC().identity_key(),
                                  99, c.hash(), 0, "mp.forged", 2);
    Carrier car; car.carrier = c; car.receipts = {good, forged};
    std::vector<std::uint8_t> frame = CarrierWire::encode(car);
    // The parent's own reference for the cleaned survivor set.
    auto clean_dr = CarrierWire::decode(frame);
    std::vector<std::uint8_t> expected_clean = CarrierWire::encode(clean_dr.carrier);
    CHECK(clean_dr.carrier.receipts.size() == EXPECTED_SURVIVORS);
    CHECK(clean_dr.dropped.size() == EXPECTED_DROPPED);

    int lsock = ::socket(AF_INET, SOCK_STREAM, 0);
    if (lsock < 0) { std::printf("SKIP WR-6: socket() failed\n"); return; }
    int one = 1;
    ::setsockopt(lsock, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;   // ephemeral
    if (::bind(lsock, (sockaddr*)&addr, sizeof(addr)) != 0) {
        std::printf("SKIP WR-6: bind() failed\n"); ::close(lsock); return;
    }
    socklen_t alen = sizeof(addr);
    if (::getsockname(lsock, (sockaddr*)&addr, &alen) != 0) {
        std::printf("SKIP WR-6: getsockname() failed\n"); ::close(lsock); return;
    }
    std::uint16_t port = ntohs(addr.sin_port);
    if (::listen(lsock, N) != 0) {
        std::printf("SKIP WR-6: listen() failed\n"); ::close(lsock); return;
    }
    // Bound accept() so a lost child never hangs the suite.
    timeval tv{8, 0};
    ::setsockopt(lsock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    std::vector<pid_t> kids;
    for (int i = 0; i < N; ++i) {
        pid_t pid = ::fork();
        if (pid == 0) {                // child
            ::close(lsock);
            _exit(child_peer(port, expected_clean));
        }
        if (pid > 0) kids.push_back(pid);
    }
    CHECK((int)kids.size() == N);      // all forks succeeded

    // Parent: accept N connections, push the same frame to each.
    std::uint8_t lenbuf[4];
    std::uint32_t len = (std::uint32_t)frame.size();
    for (int i = 0; i < 4; ++i) lenbuf[i] = (std::uint8_t)(len >> (8 * i));
    int served = 0;
    for (int i = 0; i < N; ++i) {
        int cfd = ::accept(lsock, nullptr, nullptr);
        if (cfd < 0) break;
        ::setsockopt(cfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        bool ok = send_all(cfd, lenbuf, 4) && (len == 0 || send_all(cfd, frame.data(), len));
        std::uint8_t ack = 0; recv_all(cfd, &ack, 1);   // drain ack (best effort)
        ::close(cfd);
        if (ok) ++served;
    }
    ::close(lsock);
    CHECK(served == N);                // every child was served over the socket

    // Every child MUST have decoded IDENTICALLY (bit-for-bit survivor agreement).
    int agreed = 0;
    for (pid_t pid : kids) {
        int st = 0;
        ::waitpid(pid, &st, 0);
        if (WIFEXITED(st) && WEXITSTATUS(st) == CHILD_OK) ++agreed;
        else std::printf("WR-6 child %d diverged: exit=%d\n",
                         (int)pid, WIFEXITED(st) ? WEXITSTATUS(st) : -1);
    }
    CHECK(agreed == N);                // >=8-process cross-socket agreement
}

// ═══════════════════════════════════════════════════════════════════════════
// WR-7 — carrier-bloat measurement hook (spec §8.4)
// ═══════════════════════════════════════════════════════════════════════════
static void test_wr7_bloat_hook() {
    // Off by default: no accounting on the consensus path.
    {
        AdmitHarness h(110);
        CountingTransport tx;
        CarrierRelay relay(h.fn(), tx);
        WorkEvent c = mine(CHAIN, ALICE_DESC(), 100, W2_GENESIS_PREV_OWN, 0, "bh0.c");
        relay.handle_local([&] { Carrier x; x.carrier = c; return x; }());
        CHECK(relay.stats().enabled == false);
        CHECK(relay.stats().carriers_accepted == 0);   // hook silent when off
    }
    // On: records the BM-2 inputs. Two carriers, 0 and 2 receipts.
    AdmitHarness h(110);
    CountingTransport tx; tx.peers = 4;
    CarrierRelay relay(h.fn(), tx);
    relay.stats().enabled = true;

    WorkEvent c0 = mine(CHAIN, ALICE_DESC(), 100, W2_GENESIS_PREV_OWN, 0, "bh.c0");
    relay.handle_local([&] { Carrier x; x.carrier = c0; return x; }());
    WorkEvent c1 = mine(CHAIN, ALICE_DESC(), 101, c0.hash(), 0, "bh.c1", 1);
    WorkEvent s0 = mine(CHAIN, ALICE_DESC(), 100, c0.hash(), 0, "bh.s0", 2);
    WorkEvent s1 = mine(CHAIN, ALICE_DESC(), 99,  c0.hash(), 0, "bh.s1", 3);
    Carrier car1; car1.carrier = c1; car1.receipts = {s0, s1};
    relay.handle_local(car1);

    const auto& st = relay.stats();
    CHECK(st.carriers_accepted == 2);
    CHECK(st.receipt_count_hist[0] == 1);              // c0 had 0 receipts
    CHECK(st.receipt_count_hist[2] == 1);              // c1 had 2 receipts
    CHECK(st.carrier_body_bytes > 0);
    CHECK(st.receipt_payload_bytes > 0);               // c1 contributed payload
    CHECK(st.bloat_ratio() > 0.0 && st.bloat_ratio() < 1.0);
    CHECK(st.bytes_per_carrier() > 0.0);
    CHECK(st.bytes_per_receipt() > 0.0);
    CHECK(st.wire_bytes_sent > 0);                     // Σ over the send loop
    // Budget sanity (share-format §7 SF-OQ2: <= ~1 KB receipts/carrier).
    CHECK(st.receipt_payload_bytes <= 1024ull * st.carriers_accepted);
}

int main() {
    test_wr1_roundtrip();
    test_wr2_rmax();
    test_wr3_identity_binding();
    test_wr4_block_winner();
    test_wr5_relay_dedup();
    test_wr6_multiproc_loopback();
    test_wr7_bloat_hook();

    std::printf("%d checks, %d failures\n", g_checks, g_failures);
    return g_failures == 0 ? 0 : 1;
}
