// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ===========================================================================
// v37_convergence_apply_kat.cpp — Track A2 / Stage 2 APPLY.
//
// THE DEFECT THIS SUITE CLOSES (root cause 2 of the 09-13 sustained-convergence
// finding). S-1c made a peer credit the winner's E_b at the winner's lane cut,
// and that works exactly as long as the peer's own order at that cut IS the
// winner's. Drop ONE share anywhere before the cut and it is not:
//
//     B dropped a share  ->  B's lane is SHORTER  ->  prefix P was never
//                            published here            -> cut_miss   -> REFUSED
//     B got it out of order -> B publishes P with OTHER bytes
//                                                      -> cut_mismatch -> REFUSED
//
// and BOTH refusals were terminal: the peer's block was never credited, the two
// owed_digests stayed forked, and nothing in the tree could ever re-drive the
// one-shot descriptor (W2's dedup window suppresses the flood echo). One dropped
// share desynchronised the pool's settlement permanently.
//
// THE MECHANISM UNDER TEST (Stage 2, carrier_repair.hpp):
//   1. the refused arm ARMS a repair for exactly the cut the winner named;
//   2. the repair FETCHES the winner's ordered carrier ids over [0, P) and their
//      frame bytes over the Stage-1 supply channel (GETORDER / GETFRAMES, real
//      sockets, every frame hash-verified against the id that was asked for);
//   3. it REPLAYS that record stream into a SCRATCH V37Engine through the w6
//      slow path (ReplayDriver::canonical_records -> PrefixResolver::resolve),
//      admitting every frame through OUR OWN W2 over OUR OWN mainchain index;
//   4. it accepts the result ONLY IF the digest reached at P is byte-equal to
//      the winner's cut_spine_digest;
//   5. an S3 RE-DRIVE re-enters the same arm, which now reads the VERIFIED
//      projection and folds E_b there — same settle::fold_eb, same prefix, same
//      strictness. The repair changes WHICH view the fold reads. Nothing else.
//
// WHAT IS ASSERTED (fixed streams: no RNG; real sockets for the supply channel)
//   CA-1  ★ THE DEFECT, REPRODUCED: one dropped share -> cut_miss -> REFUSED ->
//         owed(A) != owed(B), B still at the empty anchor.
//   CA-2  ★ REPAIR over cut_miss: the replay reaches the winner's digest at P,
//         the S3 re-drive registers, and owed_digest(A) == owed_digest(B)
//         BYTE-EQUAL after the block settles, with the repaired credit equal to
//         the winner's credit key-for-key.
//   CA-3  ★ REPAIR over cut_digest_mismatch: the same share delivered LATE gives
//         B a DIFFERENT digest at the same P; the repair closes that too.
//   CA-4  ★ A REPAIR THAT CANNOT VERIFY STILL REFUSES: a winner naming a spine
//         no honest replay reaches is counted as a divergence and credited
//         NOTHING — owed(B) does not move by one byte.
//   CA-5  a server that cannot serve the order at all (vault off) -> refused,
//         counted, owed unchanged.
//   CA-6  the STRUCTURAL pre-check: an order whose position deltas disagree with
//         our own push derivation is rejected BEFORE any digest is computed.
//   CA-7  ZERO CONSENSUS MOVEMENT: the frozen wire selfcheck is green, the empty
//         anchor is unmoved, and a full repair round-trip changes neither the
//         winner's lane digest nor the winner's owed_digest.
//   CA-8  the first_eligible ARMING question, measured rather than assumed.
//   CA-9  ★ THE LIVENESS DEFECT: two DISTINCT refused peer wins while a repair
//         is in flight against the ONE peer that can serve them. The in-flight
//         job keeps its peer binding, the second cut is QUEUED (never coalesced
//         into the live job, never a silent zombie), it is re-armed the moment
//         the peer falls free, and BOTH blocks credit — owed(A) == owed(B).
//   CA-10 ★ THE CROSS-THREAD WINDOW: the ORDER reply is delivered while
//         request_order() is still on the stack — i.e. BEFORE the arm could
//         have bound the peer if it bound after dispatching. The reply is still
//         credited: the repair completes, the S3 re-drive registers the block,
//         and no job and no binding is left behind. (arm() binds m_by_peer
//         BEFORE the ask for exactly this reason; binding after left the reply
//         with nowhere to land and the job in m_jobs forever.)
//   CA-11 ★ THE UN-DRIVEN TIMEOUT: a repair whose reply NEVER arrives. Nothing
//         moves until SupplyRequester::tick() is driven — which is what the
//         daemon now does on the carrier_send idle cadence — and then the slot
//         expires, on_fail reaches finish(), the repair is REFUSED (never a
//         permanent zombie), and the cut queued behind that peer DRAINS. Both
//         nodes' owed_digest is unmoved: failing closed still fails closed.
//
// Stdlib + POSIX sockets + Threads, the self-harness shape of its siblings in
// this directory. CONSUMER TREE ONLY: no file under src/sharechain/v37 is
// touched, settle::fold_eb and OwedLedger::owed_digest() are unchanged, and no
// frozen golden moves.
// ===========================================================================
#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#include <c2pool/v37/btc/btc_node.hpp>
#include <c2pool/v37/btc/block_event_driver.hpp>
#include <c2pool/v37/carrier_ingest.hpp>
#include <c2pool/v37/carrier_net.hpp>
#include <c2pool/v37/carrier_repair.hpp>
#include <c2pool/v37/carrier_supply.hpp>
#include <c2pool/v37/w3_relay.hpp>
#include <c2pool/v37/w3_wire_freeze.hpp>

using namespace c2pool::v37n;
using namespace c2pool::v37n::btc;
namespace settle = ::c2pool::v37n::settle;
namespace wire_freeze = ::c2pool::v37n::wire_freeze;
using ::v37::bytes32;
using ::v37::ChainId;
using ::v37::LaneParams;
using ::v37::PayoutDescriptor;
using ::v37::u64;

static int g_checks = 0, g_fails = 0;
static void check(bool ok, const std::string& what) {
    ++g_checks;
    if (ok) std::printf("  ok: %s\n", what.c_str());
    else { ++g_fails; std::printf("  FAIL: %s\n", what.c_str()); }
}
static std::string hex32(const bytes32& d) {
    static const char* H = "0123456789abcdef";
    std::string s;
    for (auto b : d) { s += H[b >> 4]; s += H[b & 15]; }
    return s;
}

// The empty-fold anchor sha256d("V37O") — what owed_digest() returns before any
// block finalizes. The fingerprint of "this node credited nothing".
static const char* kEmptyAnchor =
    "b4db1ded95a73f939975a259f9b48a1d182109f44397ed77e35d624f1a5cf339";

static const ChainId CH      = 7;
static const u64     D_CONF  = 3;
static const int     N_SHARE = 9;     // the fixed stream length
static const int     DROP_AT = 4;     // the share B loses
static const char*   kWonBid =
    "00000000000000000a1b2c3d4e5f60718293a4b5c6d7e8f900112233445566aa";
// CA-9's SECOND win by the same peer, at a LATER prefix of the same lane.
static const char*   kWonBid2 =
    "00000000000000000b2c3d4e5f60718293a4b5c6d7e8f9001122334455667bb0";

// ── the fixed carrier stream ────────────────────────────────────────────────
static PayoutDescriptor mk_desc(std::uint8_t fill) {
    std::vector<std::uint8_t> s = {0x76, 0xa9, 0x14};
    for (int i = 0; i < 20; ++i) s.push_back(fill);
    s.push_back(0x88); s.push_back(0xac);
    PayoutDescriptor d;
    d.pay = ::v37::canonicalize_script(s);
    return d;
}
static WorkEvent mine(const PayoutDescriptor& desc, u64 origin_bin,
                      const bytes32& prev_own, const char* tag, u64 salt) {
    WorkEvent ev;
    ev.chain_id = static_cast<std::uint32_t>(CH);
    ev.identity = desc.identity_key();
    ev.descriptor = desc;
    ev.prev_block_hash = mainchain_hash(origin_bin);
    ev.prev_own_share = prev_own;
    ev.lz_bits = consensus_lz(origin_bin);
    ev.tag = tag;
    const u64 base = salt << 32;
    for (u64 n = base; n < base + (u64(1) << 22); ++n) {
        ev.nonce = n;
        if (ev.meets_own_target()) return ev;
    }
    std::printf("FATAL: nonce exhausted for %s\n", tag);
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

// The fixed stream, mined ONCE and reused by every case, so every case in this
// file is the same lane over the same bytes.
struct Stream {
    std::vector<WorkEvent>                  ev;
    std::vector<std::vector<std::uint8_t>>  frame;
};
static const Stream& stream() {
    static Stream s = [] {
        Stream out;
        bytes32 prev = W2_GENESIS_PREV_OWN;
        // Four distinct payees so the E_b split is a real multi-key map, not a
        // single-entry degenerate one.
        for (int i = 0; i < N_SHARE; ++i) {
            const PayoutDescriptor d = mk_desc(static_cast<std::uint8_t>(0xa0 + (i % 4)));
            const WorkEvent e = mine(d, 100, prev, "ca", static_cast<u64>(i + 1));
            prev = e.hash();
            Carrier c;
            c.carrier = e;
            out.ev.push_back(e);
            out.frame.push_back(CarrierWire::encode(c));
        }
        return out;
    }();
    return s;
}

template <class F>
static bool wait_until(F f, int timeout_ms = 8000) {
    const auto deadline =
        std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    while (std::chrono::steady_clock::now() < deadline) {
        if (f()) return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    return f();
}

// ═══════════════════════════════════════════════════════════════════════════
// A HAND-PUMPED CONTROL CHANNEL (CA-9 only).
//
// CA-2..CA-5 run the supply channel over real sockets, which is the right shape
// for "does the repair work". CA-9 asks a LIVENESS question instead — "what
// happens to a repair that is genuinely IN FLIGHT when a second cut is armed
// against the same peer" — and that needs the in-flight window held open on
// purpose. So CA-9 replaces ONLY the SendFn the supply halves were bound to:
// control frames go into a queue and are delivered when the test says so. Both
// nodes, both directions, the same real SupplyService / SupplyRequester /
// RepairDriver objects; nothing about the mechanism is stubbed, only the wire's
// timing is ours.
// ═══════════════════════════════════════════════════════════════════════════
struct ManualBus {
    std::mutex mtx;
    std::vector<std::vector<std::uint8_t>> to_a;   // frames B emitted, for A
    std::vector<std::vector<std::uint8_t>> to_b;   // frames A emitted, for B
    static const CarrierPeerNode::PeerId PID = 1;
};

// ═══════════════════════════════════════════════════════════════════════════
// ONE NODE — assembled exactly as main_v37_btc_dash.cpp assembles it: the
// XbtcNode lifecycle, the carrier relay over a real socket, the Stage-1 supply
// SERVE + FETCH halves on the one control demux, and (Stage 2) the repair
// driver bound BOTH as the node's repair source and as the S3 re-drive.
// ═══════════════════════════════════════════════════════════════════════════
struct Node {
    std::shared_ptr<MockCoinBackend>    coin;
    ISettleStore*                       store_ref = nullptr;
    std::unique_ptr<XbtcNode>           node;
    std::unique_ptr<BlockEventDriver>   bed;
    std::unique_ptr<CallbackMainchainIndex> index;
    MemShareTracker                     tracker;
    std::unique_ptr<CarrierIngest>      ingest;
    std::unique_ptr<CarrierPeerNode>    net;
    wire_freeze::PolicyStats            policy;
    std::unique_ptr<CarrierRelay>       relay;
    std::unique_ptr<SupplyService>      serve;
    std::unique_ptr<SupplyRequester>    fetch;
    std::unique_ptr<RepairDriver>       repair;
    LaneParams                          params;
    std::mutex                          redrive_mtx;
    std::vector<std::string>            redriven;     // bids the S3 path re-entered

    using CtlSend = std::function<bool(CarrierPeerNode::PeerId,
                                       const std::vector<std::uint8_t>&)>;
    Node(std::shared_ptr<MockCoinBackend> c, const LaneParams& p,
         ManualBus* bus = nullptr, bool is_a = false, CtlSend override_send = nullptr)
        : coin(std::move(c)), params(p) {
        BtcNodeConfig cfg;
        cfg.lane_chain  = CH;
        cfg.lane_params = p;
        cfg.d_conf      = D_CONF;
        auto st = std::make_unique<MemSettleStore>();
        store_ref = st.get();
        node = std::make_unique<XbtcNode>(cfg, std::move(st), coin, p2pkh_pay_of());
        if (!node->open() || !node->start()) { std::printf("FATAL: node open/start\n"); std::abort(); }
        bed = std::make_unique<BlockEventDriver>(*node, *store_ref, CH);

        auto snap = node->lane_snapshot();
        const u64 inc = snap ? snap->incarnation : 1;
        index  = std::make_unique<CallbackMainchainIndex>(synthetic_index(110));
        ingest = std::make_unique<CarrierIngest>(node->engine(), CH, *index, tracker, inc);
        net    = std::make_unique<CarrierPeerNode>();
        relay  = std::make_unique<CarrierRelay>(ingest->fn(), *net);
        relay->set_frame_policy(wire_freeze::make_relay_policy(&policy));
        net->set_inbound([this](const std::vector<std::uint8_t>& f) {
            (void)relay->handle_inbound(f);
        });
        // #1655: a (re)connecting peer arms the re-offer sweep.
        net->set_on_peer_connect([this] { relay->note_peer_connected(); });
        // #1655: the re-offer must not re-push what W2 already accounted.
        relay->set_reoffer_dedup_probe([this](const bytes32& h) { return relay->seen().seen(h); });

        // The ONE substitution CA-9 makes: where the control frames go. Every
        // other wire in this constructor is the production one.
        std::function<bool(CarrierPeerNode::PeerId, const std::vector<std::uint8_t>&)> send;
        if (override_send) {
            // CA-10 only: a SYNCHRONOUS loopback, so a reply is delivered from
            // inside the very request_order() call that asked for it.
            send = std::move(override_send);
        } else if (bus) {
            send = [bus, is_a](CarrierPeerNode::PeerId,
                               const std::vector<std::uint8_t>& f) {
                std::lock_guard<std::mutex> lk(bus->mtx);
                (is_a ? bus->to_b : bus->to_a).push_back(f);
                return true;
            };
        } else {
            send = [this](CarrierPeerNode::PeerId pid,
                          const std::vector<std::uint8_t>& f) { return net->send_to(pid, f); };
        }
        serve = std::make_unique<SupplyService>(relay->vault(), send);
        fetch = std::make_unique<SupplyRequester>(send);
        // The server's claimed commitment at a prefix. Under ruling A it is an
        // ASSERTION; Stage 2's replay is what checks it.
        serve->set_spine_probe([this](std::uint32_t, u64 pos) -> std::optional<bytes32> {
            auto s = node->engine().snapshot(CH);
            if (s && s->next_pos == pos) return s->digest;
            return std::nullopt;
        });
        repair = std::make_unique<RepairDriver>(*fetch, *index, static_cast<std::uint32_t>(CH), p);
        fetch->set_on_order([this](CarrierPeerNode::PeerId pid, const CtrlOrder& o) {
            repair->on_order(pid, o);
        });
        fetch->set_on_frames([this](CarrierPeerNode::PeerId pid,
                                    const std::vector<VerifiedFrame>& v) {
            repair->on_frames(pid, v);
        });
        fetch->set_on_unservable([this](CarrierPeerNode::PeerId pid,
                                        const std::vector<bytes32>& ids) {
            repair->on_unservable(pid, ids);
        });
        fetch->set_on_fail([this](CarrierPeerNode::PeerId pid, SupplyFailure f) {
            repair->on_fail(pid, f);
        });
        net->set_control([this](CarrierPeerNode::PeerId pid,
                                const std::vector<std::uint8_t>& f) {
            serve->on_control(pid, f);
            fetch->on_control(pid, f);
        });
        net->set_on_peer_event([this](CarrierPeerNode::PeerId pid, bool up) {
            if (!up) { serve->forget_peer(pid); fetch->forget_peer(pid); repair->forget_peer(pid); }
        });
        // ★ Stage 2: the node's cut-miss arm reads VERIFIED repaired views here.
        node->set_repair_source([this](ChainId c, u64 pos, const bytes32& spine) {
            return repair->verified_view(static_cast<std::uint32_t>(c), pos, spine);
        });
        // ★ Stage 2 / S3: a finished repair re-drives the one-shot refused win.
        repair->set_redrive([this](const std::string& bid, const RepairResult&) {
            { std::lock_guard<std::mutex> lk(redrive_mtx); redriven.push_back(bid); }
            (void)bed->redrive_peer_block_found(bid);
        });
    }
    ~Node() { if (net) net->stop(); if (node) node->stop(); }

    void feed(const std::vector<std::uint8_t>& f) { (void)relay->handle_inbound(f); }
    u64  next_pos() const { auto s = node->engine().snapshot(CH); return s ? s->next_pos : 0; }
    bytes32 lane() const { auto s = node->engine().snapshot(CH); return s ? s->digest : bytes32{}; }
    bytes32 owed() const { return node->ledger().owed_digest(); }
    std::size_t redrive_count() { std::lock_guard<std::mutex> lk(redrive_mtx); return redriven.size(); }
};

// Deliver whatever the two nodes have queued for each other, both directions,
// until the wire falls quiet. Everything the repair driver does downstream of a
// reply — the next GETFRAMES, the replay, the S3 re-drive, the release of a
// queued cut — happens INSIDE this call, on this thread, exactly as it happens
// inside the transport reader loop in production.
static void pump(ManualBus& bus, Node& A, Node& B, int rounds = 64) {
    for (int r = 0; r < rounds; ++r) {
        std::vector<std::vector<std::uint8_t>> ta, tb;
        {
            std::lock_guard<std::mutex> lk(bus.mtx);
            ta.swap(bus.to_a);
            tb.swap(bus.to_b);
        }
        if (ta.empty() && tb.empty()) return;
        for (const auto& f : ta) {
            A.serve->on_control(ManualBus::PID, f);
            A.fetch->on_control(ManualBus::PID, f);
        }
        for (const auto& f : tb) {
            B.serve->on_control(ManualBus::PID, f);
            B.fetch->on_control(ManualBus::PID, f);
        }
    }
}

// The v0x02 descriptor the WINNER puts on the wire, put through a REAL frame so
// every case exercises the codec, not a struct copy.
static PeerWin peer_win_of(const std::string& bid, u64 h_b, const EbCut& cut,
                           bool payout_emitted, const bytes32& owed_at_win) {
    CutDescriptor d;
    d.bid                = *cut_bid_bytes(bid);
    d.h_b                = h_b;
    d.cut_next_pos       = cut.next_pos;
    d.cut_spine_digest   = cut.lane_digest;
    d.reward             = cut.reward;
    d.payout_emitted     = payout_emitted;
    d.owed_digest_at_win = owed_at_win;
    Carrier c = wire_freeze::fixture_a();
    c.cut = d;
    const DecodeResult dr = CarrierWire::decode(CarrierWire::encode(c));
    if (!dr.ok() || !dr.carrier.cut) { std::printf("FATAL: descriptor wire round-trip\n"); std::abort(); }
    const CutDescriptor& g = *dr.carrier.cut;
    PeerWin w;
    w.bid                = cut_bid_hex(g.bid);
    w.h_b                = g.h_b;
    w.cut_next_pos       = g.cut_next_pos;
    w.cut_spine_digest   = g.cut_spine_digest;
    w.reward             = g.reward;
    w.payout_emitted     = g.payout_emitted;
    w.owed_digest_at_win = g.owed_digest_at_win;
    return w;
}

// ═══════════════════════════════════════════════════════════════════════════
// ONE PAIRED RUN. A gets the whole stream; B loses share DROP_AT (and, when
// `late` is set, receives it afterwards, out of order). A wins a block; B is
// handed the descriptor; if `do_repair` the refused arm is repaired over the
// real supply channel and the S3 re-drive retries it.
// ═══════════════════════════════════════════════════════════════════════════
struct RunOut {
    bytes32 owed_a{}, owed_b{}, lane_a{}, lane_b{};
    u64     pos_a = 0, pos_b = 0;
    EbCut   cut_a, cut_b;
    bool    first_registered = false;
    bool    first_cut_miss = false, first_cut_mismatch = false, first_repair_wanted = false;
    bool    final_registered = false, final_repaired = false;
    bool    a_final = false, b_final = false;
    u64     bin_a = 0, bin_b = 0;
    RepairStats rs;
    S1PeerStats ps;
    std::size_t redrives = 0;
    // the winner's lane/owed BEFORE and AFTER the repair round-trip (CA-7)
    bytes32 lane_a_before{}, owed_a_before{};
};

static RunOut run_pair(const LaneParams& params, bool late, bool do_repair,
                       bool corrupt_spine = false, bool server_vault_off = false) {
    RunOut r;
    auto coin = std::make_shared<MockCoinBackend>();
    Node A(coin, params), B(coin, params);
    const Stream& s = stream();

    for (int i = 0; i < N_SHARE; ++i) {
        A.feed(s.frame[i]);
        if (i != DROP_AT) B.feed(s.frame[i]);
    }
    (void)wait_until([&] { return A.next_pos() == static_cast<u64>(N_SHARE); });
    (void)wait_until([&] { return B.next_pos() == static_cast<u64>(N_SHARE - 1); });
    if (late) {
        // The dropped share arrives AFTER the rest: B reaches the same PREFIX
        // LENGTH as A with a DIFFERENT record order, hence a different digest.
        B.feed(s.frame[DROP_AT]);
        (void)wait_until([&] { return B.next_pos() == static_cast<u64>(N_SHARE); });
    }
    r.lane_a = A.lane(); r.lane_b = B.lane();
    r.pos_a  = A.next_pos(); r.pos_b = B.next_pos();

    // A wins.
    coin->append_block("g0");
    const u64 win_h = coin->append_block(kWonBid);
    const bytes32 owed_at_win = A.owed();
    const WonBlockOutcome won = A.node->on_block_won(kWonBid, win_h, /*confirmations=*/0);
    r.cut_a = won.cut;
    r.lane_a_before = A.lane();
    r.owed_a_before = A.owed();

    PeerWin w = peer_win_of(kWonBid, win_h, won.cut, won.emitted, owed_at_win);
    if (corrupt_spine) w.cut_spine_digest[0] ^= 0x01;   // a commitment no honest replay reaches

    // FIRST PASS through the arm: the one-shot descriptor.
    const BlockEventDriver::RegisterResult first = B.bed->on_peer_block_found(w);
    r.first_registered = first.registered;
    {
        const S1PeerStats p = B.node->s1c_stats();
        r.first_cut_miss      = p.cut_miss > 0;
        r.first_cut_mismatch  = p.cut_mismatch > 0;
        r.first_repair_wanted = p.repair_wanted > 0;
    }

    if (do_repair && !first.registered) {
        if (server_vault_off) {
            FrameVaultOptions vo;
            vo.enabled = false;
            A.relay->vault().set_options(vo);          // the server can serve nothing
        }
        // Connect the supply channel and arm the repair at exactly the cut the
        // winner named. Everything from here is asynchronous, over real sockets.
        A.net->listen("127.0.0.1", 0);
        B.net->add_peer("127.0.0.1", A.net->listen_port());
        (void)wait_until([&] { return !B.net->peer_ids().empty(); });
        const auto ids = B.net->peer_ids();
        if (!ids.empty())
            (void)B.repair->arm(ids.front(), w.bid, w.cut_next_pos, w.cut_spine_digest);
        (void)wait_until([&] {
            const RepairStats rs = B.repair->stats();
            return rs.repaired + rs.refused > 0;
        });
        (void)wait_until([&] { return B.repair->in_flight() == 0; });
    }
    r.rs = B.repair->stats();
    r.ps = B.node->s1c_stats();
    r.redrives = B.redrive_count();
    r.final_registered = B.node->ledger().is_pending(w.bid) || B.node->ledger().is_settled(w.bid);
    r.cut_b = B.node->last_peer_cut();
    r.final_repaired = r.ps.repair_hit > 0;

    // Bury D_conf deep on the SHARED coin chain; each node's own height-watch
    // finalizes at bin_height == H_b + d_conf.
    for (int i = 0; i <= static_cast<int>(D_CONF); ++i)
        coin->append_block("f" + std::to_string(i));
    for (const auto& st : A.bed->on_tip(coin->best_tip()))
        if (st.bid == kWonBid) { r.a_final = true; r.bin_a = st.bin_height; }
    for (const auto& st : B.bed->on_tip(coin->best_tip()))
        if (st.bid == kWonBid) { r.b_final = true; r.bin_b = st.bin_height; }

    r.owed_a = A.owed();
    r.owed_b = B.owed();
    return r;
}

int main() {
    std::printf("== v37 Stage 2 APPLY: repair at the cut-miss arm, 2-node convergence ==\n");
    LaneParams ratified{};    // the OQ-5 ratified default (gate-OFF V37.0)

    // ── CA-0 the seam is OPT-IN ─────────────────────────────────────────────
    {
        auto coin = std::make_shared<MockCoinBackend>();
        BtcNodeConfig cfg;
        cfg.lane_chain = CH; cfg.lane_params = ratified; cfg.d_conf = D_CONF;
        XbtcNode n(cfg, std::make_unique<MemSettleStore>(), coin, p2pkh_pay_of());
        check(!n.has_repair_source(),
              "CA-0 a node with no supply channel has NO repair source (the arm is unchanged)");
        n.stop();
    }

    // ── CA-1 the DEFECT, reproduced ─────────────────────────────────────────
    std::printf("-- CA-1 one dropped share -> cut_miss -> REFUSED (the defect)\n");
    {
        const RunOut d = run_pair(ratified, /*late=*/false, /*do_repair=*/false);
        std::printf("   A pos=%llu lane=%s\n   B pos=%llu lane=%s\n",
                    (unsigned long long)d.pos_a, hex32(d.lane_a).c_str(),
                    (unsigned long long)d.pos_b, hex32(d.lane_b).c_str());
        check(d.pos_a == N_SHARE && d.pos_b == N_SHARE - 1,
              "CA-1a B's lane is one push SHORT of A's");
        check(!d.first_registered && d.first_cut_miss && !d.first_cut_mismatch,
              "CA-1b B cut-MISSES the winner's prefix P and REFUSES");
        check(d.first_repair_wanted, "CA-1c ...and the refusal is flagged REPAIRABLE");
        check(hex32(d.owed_b) == kEmptyAnchor,
              "CA-1d B stays at the empty anchor: it credited nothing");
        check(hex32(d.owed_a) != kEmptyAnchor && d.owed_a != d.owed_b,
              "CA-1e ★ owed(A) != owed(B) — the settlement fork one dropped share causes");
        check(d.a_final && !d.b_final,
              "CA-1f only the winner ever finalizes the block");
    }

    // ── CA-2 ★ REPAIR over cut_miss ─────────────────────────────────────────
    std::printf("-- CA-2 the repair: fetch the winner's order, replay to P, fold there\n");
    RunOut c2 = run_pair(ratified, /*late=*/false, /*do_repair=*/true);
    {
        std::printf("   owed A = %s\n   owed B = %s\n",
                    hex32(c2.owed_a).c_str(), hex32(c2.owed_b).c_str());
        std::printf("   repair: armed=%llu replayed=%llu repaired=%llu refused=%llu frames=%llu\n",
                    (unsigned long long)c2.rs.armed, (unsigned long long)c2.rs.replayed,
                    (unsigned long long)c2.rs.repaired, (unsigned long long)c2.rs.refused,
                    (unsigned long long)c2.rs.frames_fetched);
        check(c2.rs.armed == 1 && c2.rs.replayed == 1,
              "CA-2a exactly one repair was armed and exactly one replay ran");
        check(c2.rs.frames_fetched == static_cast<u64>(N_SHARE),
              "CA-2b every carrier of the winner's prefix was fetched and hash-verified");
        check(c2.rs.repaired == 1 && c2.rs.refused == 0,
              "CA-2c ★ the replay reached the winner's commitment at P");
        check(c2.redrives == 1, "CA-2d the S3 re-drive retried the one-shot refused win exactly once");
        check(c2.final_registered && c2.final_repaired,
              "CA-2e ★ the re-driven arm folded over the REPAIRED view and registered");
        // The arm is entered TWICE (the one-shot pass, then the S3 re-drive) and
        // BOTH times our own ring still has no view at P — the repair never
        // rewrites our lane, it only supplies a verified projection for the fold.
        // So repair_wanted counts both passes and repair_hit counts the one that
        // found a verified view.
        check(c2.ps.repair_wanted == 2 && c2.ps.repair_hit == 1 && c2.ps.repair_missing == 1,
              "CA-2f the arm counted both repairable passes, one repair hit, one miss");
        check(c2.ps.credited == 1 && c2.ps.cut_miss == 1,
              "CA-2g0 exactly one cut_miss was ever counted, and exactly one credit followed");
        check(c2.cut_b.folded && c2.cut_b.next_pos == c2.cut_a.next_pos &&
              c2.cut_b.lane_digest == c2.cut_a.lane_digest,
              "CA-2g the fold ran at the SAME prefix P with the SAME lane commitment");
        check(c2.cut_b.credit == c2.cut_a.credit,
              "CA-2h ★ the repaired E_b is the winner's E_b, key for key");
        check(c2.a_final && c2.b_final && c2.bin_a == c2.bin_b && c2.bin_a == 1 + D_CONF,
              "CA-2i both height-watches FINALIZED at the SAME bin_height == H_b + d_conf");
        check(hex32(c2.owed_a) != kEmptyAnchor && hex32(c2.owed_b) != kEmptyAnchor,
              "CA-2j both owed_digests left the empty anchor");
        check(c2.owed_a == c2.owed_b,
              "CA-2k ★★ owed_digest(A) == owed_digest(B) BYTE-EQUAL after the repair");
        long long sum_a = 0, sum_b = 0;
        for (const auto& [k, v] : c2.cut_a.credit) { (void)k; sum_a += v; }
        for (const auto& [k, v] : c2.cut_b.credit) { (void)k; sum_b += v; }
        check(sum_a == static_cast<long long>(c2.cut_a.reward) && sum_b == sum_a,
              "CA-2l sum(E_b) == the block reward on BOTH sides (no lost satoshi)");
    }

    // ── CA-3 ★ REPAIR over cut_digest_mismatch ──────────────────────────────
    std::printf("-- CA-3 the same share, delivered LATE: same P, DIFFERENT digest\n");
    {
        const RunOut c3 = run_pair(ratified, /*late=*/true, /*do_repair=*/true);
        check(c3.pos_b == c3.pos_a && c3.lane_b != c3.lane_a,
              "CA-3a B reaches the same prefix LENGTH with a different commitment");
        check(c3.first_cut_mismatch && !c3.first_registered,
              "CA-3b the first pass is a cut_DIGEST_MISMATCH, REFUSED");
        check(c3.rs.repaired == 1 && c3.rs.refused == 0,
              "CA-3c ★ the repair verifies over the mismatch bit too");
        check(c3.final_registered && c3.final_repaired && c3.redrives == 1,
              "CA-3d the S3 re-drive registered the peer block");
        check(c3.owed_a == c3.owed_b && hex32(c3.owed_b) != kEmptyAnchor,
              "CA-3e ★★ owed_digest(A) == owed_digest(B) BYTE-EQUAL");
        check(c3.owed_b == c2.owed_b,
              "CA-3f ...and it is the SAME digest the cut_miss repair reached "
              "(the path to the cut does not change what is owed)");
    }

    // ── CA-4 a repair that cannot verify REFUSES ────────────────────────────
    std::printf("-- CA-4 a commitment no honest replay reaches: still REFUSED\n");
    {
        const RunOut c4 = run_pair(ratified, /*late=*/false, /*do_repair=*/true,
                                   /*corrupt_spine=*/true);
        // ★ With the candidate walk (F-2) this refusal happens EARLIER and more
        // cheaply. The server's ORDER answer asserts its own lane digest at P;
        // that assertion is not the commitment we asked it to stand behind, so
        // the repair refuses without fetching one frame or running a replay.
        // The property CA-4 exists for is unchanged and is asserted by the
        // lines below (nothing registered, owed unmoved, the S3 re-drive still
        // refuses); what changed is that the driver no longer pays for a whole
        // prefix fetch to learn what the server had already told it.
        check(c4.rs.replayed == 0 && c4.rs.repaired == 0 && c4.rs.refused == 1 &&
                  c4.rs.spine_refused == 1 && c4.rs.frames_fetched == 0,
              "CA-4a the serving peer asserted a DIFFERENT digest at P, so the "
              "repair refused before any fetch or replay");
        check(!c4.final_registered,
              "CA-4b ★ the peer block is NOT registered — no fold at a neighbouring prefix");
        check(c4.ps.repair_hit == 0 && c4.ps.repair_missing >= 1,
              "CA-4c the arm counted the refusal, and no repair hit");
        check(hex32(c4.owed_b) == kEmptyAnchor,
              "CA-4d ★ owed(B) did not move by one byte");
        check(c4.redrives == 1 && !c4.b_final,
              "CA-4e the S3 re-drive ran, refused again, and finalized nothing");
    }

    // ── CA-5 a server that cannot serve the order ───────────────────────────
    std::printf("-- CA-5 the server's vault is off: no order, no repair, no credit\n");
    {
        const RunOut c5 = run_pair(ratified, /*late=*/false, /*do_repair=*/true,
                                   /*corrupt_spine=*/false, /*server_vault_off=*/true);
        check(c5.rs.repaired == 0 && c5.rs.refused == 1 && c5.rs.replayed == 0,
              "CA-5a the repair failed before any replay (order_failed / fetch_failed)");
        check(!c5.final_registered && hex32(c5.owed_b) == kEmptyAnchor,
              "CA-5b ★ B credits nothing and stays at the anchor");
    }

    // ── CA-6 the STRUCTURAL pre-check ───────────────────────────────────────
    std::printf("-- CA-6 an order whose position deltas lie is caught before any digest\n");
    {
        const Stream& s = stream();
        CallbackMainchainIndex idx(synthetic_index(110));
        RepairInput in;
        in.chain = static_cast<std::uint32_t>(CH);
        in.target_pos = N_SHARE;
        in.params = ratified;
        for (int i = 0; i < N_SHARE; ++i) {
            in.order.push_back(VaultOrderId{static_cast<u64>(i), s.ev[i].hash()});
            in.frames[s.ev[i].hash()] = s.frame[i];
        }
        // (a) honest input, honest digest: prove the harness itself is sound by
        //     replaying to the digest a fresh engine reaches over the same stream.
        {
            V37Engine e;
            e.start();
            e.submit_tracked(::v37::LaneRecord::add_lane(CH, ratified)).get();
            for (int i = 0; i < N_SHARE; ++i)
                e.submit_tracked(::v37::LaneRecord::push(
                    CH, s.ev[i].descriptor, s.ev[i].work(), W2_CARRIER_FLAGS)).get();
            auto snap = e.snapshot(CH);
            in.spine_digest = snap ? snap->digest : bytes32{};
            e.stop();
        }
        const RepairResult good = replay_to_cut(in, idx);
        check(good.ok() && good.view && good.view->next_pos == N_SHARE,
              "CA-6a an honest order replays to the honest commitment");
        // (b) a position delta that does not match our own push derivation
        RepairInput bad = in;
        bad.order[3].pos += 1;                       // claims carrier 2 pushed twice
        const RepairResult r_bad = replay_to_cut(bad, idx);
        check(!r_bad.ok() && r_bad.outcome == RepairOutcome::PUSH_COUNT,
              "CA-6b a lying position delta is PUSH_COUNT, rejected before any digest");
        // (c) a missing frame
        RepairInput miss = in;
        miss.frames.erase(s.ev[2].hash());
        check(replay_to_cut(miss, idx).outcome == RepairOutcome::MISSING_FRAME,
              "CA-6c an ordered carrier with no bytes is MISSING_FRAME, fail-closed");
        // (d) an order that does not start at lane position 0 (a suffix)
        RepairInput suffix = in;
        suffix.order.erase(suffix.order.begin());
        check(replay_to_cut(suffix, idx).outcome == RepairOutcome::ORDER_GAP,
              "CA-6d a SUFFIX is never repaired: the digest at P covers [0, P)");
        // (e) the right records, the wrong commitment
        RepairInput wrong = in;
        wrong.spine_digest[5] ^= 0x01;
        check(replay_to_cut(wrong, idx).outcome == RepairOutcome::DIGEST_MISMATCH,
              "CA-6e reaching P with another digest is DIGEST_MISMATCH, never accepted");
    }

    // ── CA-7 ZERO CONSENSUS MOVEMENT ────────────────────────────────────────
    std::printf("-- CA-7 nothing consensus moved\n");
    {
        const wire_freeze::SelfCheck sc = wire_freeze::selfcheck();
        check(sc.ok(), "CA-7a the frozen v0x01 + v0x02 wire selfcheck is green");
        check(c2.lane_a == c2.lane_a_before,
              "CA-7b the winner's lane digest is untouched by serving a repair");
        check(c2.owed_a_before != bytes32{} && hex32(c2.owed_a_before) == kEmptyAnchor,
              "CA-7c the winner's owed_digest at the win is still the empty anchor "
              "(a fresh win withholds the coinbase; the credit rides FINALIZE)");
        settle::OwedLedger fresh(CH);
        check(hex32(fresh.owed_digest()) == kEmptyAnchor,
              "CA-7d the empty-fold anchor sha256d(\"V37O\") is unmoved");
        check(c2.cut_a.credit == c2.cut_b.credit,
              "CA-7e the repaired fold is the SAME fold: settle::fold_eb over the same view");
    }

    // ── CA-8 the first_eligible ARMING question, measured ───────────────────
    // rearm_first_eligible() arms a key on EffectiveOwed = finalW - Σ pending
    // payout, which is the UNSYNCHRONISED half; the S1B turnkey arms on the
    // FINALIZED half instead. owed_digest commits to first_eligible, so the two
    // rules can disagree whenever two nodes hold DIFFERENT pending payout maps
    // across a settling block. This measures whether that can happen on the
    // Stage-2 path rather than assuming it either way.
    std::printf("-- CA-8 first_eligible: does the arming rule bite on this path?\n");
    {
        check(c2.owed_a == c2.owed_b,
              "CA-8a across the SETTLING block the two owed_digests are byte-equal "
              "under the SHIPPED arming rule");
        // WHY it is byte-equal here, stated so the result is not mistaken for a
        // proof that the arming race is gone: btc_node.hpp mirrors the winner's
        // burial gate exactly on the receive side (gate.canonical = false,
        // confirmations = 0), so BOTH nodes register the FOUND with an EMPTY
        // payout map. EffectiveOwed therefore equals finalW on both sides and the
        // two arming rules coincide. The race needs a winner whose W5 assembly
        // EMITTED — which this path refuses outright (refused_payout_emitted) —
        // so the S1B arming turnkey is NOT required for the repair to converge,
        // and it is NOT applied here. It stays the operator's canon hand.
        check(c2.ps.refused_payout == 0,
              "CA-8b no descriptor on this path carried an emitted coinbase "
              "(payout maps are empty on both sides BY CONSTRUCTION)");
    }

    // ── CA-9 ★ TWO REFUSED WINS, ONE SERVING PEER ───────────────────────────
    // THE LIVENESS DEFECT. The supply channel allows ONE outstanding request per
    // peer, and on the 2-node shape the peer whose wins we refuse is the ONLY
    // peer that can serve the repair. So "a second distinct cut is armed while a
    // repair is in flight against that peer" is the ordinary case.
    //
    // It used to destroy the first repair. arm() wrote m_by_peer[peer] BEFORE
    // asking; the second ask came back refused_busy; the finish() that followed
    // erased m_by_peer BY BARE PEER ID. The live job's ORDER reply then had
    // nowhere to land, the job sat in m_jobs forever, and every later arm of
    // that cut COALESCED into the dead job — permanently unrepairable, with no
    // refusal logged and owed_digest forked for good. Fail-closed, and fatal to
    // convergence.
    //
    // Here: A commits to TWO prefixes and wins a block at each. B lost one share
    // and matches NEITHER (cut_mismatch at the first, cut_miss at the second),
    // so both wins are refused and both are armed back-to-back against the one
    // peer, with the first fetch deliberately held in flight.
    std::printf("-- CA-9 a second cut armed while a repair is in flight on the only peer\n");
    {
        ManualBus bus;
        auto coin = std::make_shared<MockCoinBackend>();
        Node A(coin, ratified, &bus, /*is_a=*/true);
        Node B(coin, ratified, &bus, /*is_a=*/false);
        const Stream& s = stream();
        {   // this case makes ~4 serve requests; the default burst is 8, and a
            // throttle here would be a harness artefact, not a finding.
            SupplyServeOptions so;
            so.burst = 64.0;
            A.serve->set_options(so);
        }

        // (a) A's FIRST prefix. B loses DROP_AT, so its prefix-P1 bytes differ.
        const int P1 = 6;
        static_assert(DROP_AT < 6 && 6 < N_SHARE, "P1 must split the stream after the drop");
        for (int i = 0; i < P1; ++i) { A.feed(s.frame[i]); if (i != DROP_AT) B.feed(s.frame[i]); }
        (void)wait_until([&] { return A.next_pos() == static_cast<u64>(P1); });
        coin->append_block("g0");
        const u64     h1    = coin->append_block(kWonBid);
        const bytes32 owed1 = A.owed();
        const WonBlockOutcome won1 = A.node->on_block_won(kWonBid, h1, /*confirmations=*/0);

        // (b) A's SECOND prefix, and a second win at it. Block 1 is still
        //     PENDING (unburied), so neither descriptor carries a coinbase.
        for (int i = P1; i < N_SHARE; ++i) { A.feed(s.frame[i]); if (i != DROP_AT) B.feed(s.frame[i]); }
        (void)wait_until([&] { return A.next_pos() == static_cast<u64>(N_SHARE); });
        (void)wait_until([&] { return B.next_pos() == static_cast<u64>(N_SHARE - 1); });
        const u64     h2    = coin->append_block(kWonBid2);
        const bytes32 owed2 = A.owed();
        const WonBlockOutcome won2 = A.node->on_block_won(kWonBid2, h2, /*confirmations=*/0);

        check(won1.cut.next_pos == static_cast<u64>(P1) &&
                  won2.cut.next_pos == static_cast<u64>(N_SHARE) &&
                  won1.cut.lane_digest != won2.cut.lane_digest,
              "CA-9a the two wins name two DISTINCT cuts of the same lane");
        check(!won1.emitted && !won2.emitted,
              "CA-9b neither win emitted a coinbase (both blocks are still unburied)");

        // (c) both descriptors refused on B — one of each refusal bit.
        const PeerWin w1 = peer_win_of(kWonBid,  h1, won1.cut, won1.emitted, owed1);
        const PeerWin w2 = peer_win_of(kWonBid2, h2, won2.cut, won2.emitted, owed2);
        const BlockEventDriver::RegisterResult g1 = B.bed->on_peer_block_found(w1);
        const BlockEventDriver::RegisterResult g2 = B.bed->on_peer_block_found(w2);
        const S1PeerStats ps0 = B.node->s1c_stats();
        check(!g1.registered && !g2.registered && ps0.repair_wanted >= 2,
              "CA-9c both peer wins are REFUSED here and both are flagged REPAIRABLE");
        check(ps0.cut_mismatch >= 1 && ps0.cut_miss >= 1,
              "CA-9d one refusal is cut_digest_mismatch, the other is cut_miss");

        // (d) ★ THE TRIGGER: arm both, back to back, against the one peer. The
        //     first fetch is sitting unread in the bus, so it is genuinely in
        //     flight when the second arm lands.
        const bool armed1 = B.repair->arm(ManualBus::PID, w1.bid, w1.cut_next_pos,
                                          w1.cut_spine_digest);
        const bool armed2 = B.repair->arm(ManualBus::PID, w2.bid, w2.cut_next_pos,
                                          w2.cut_spine_digest);
        const RepairStats mid = B.repair->stats();
        check(armed1 && !armed2,
              "CA-9e the first arm starts a fetch; the second does not start one");
        // in_flight() alone does NOT catch the defect — a zombie is still
        // counted in flight. What the invariant is about is the BINDING: the
        // live job must still be reachable from its peer when the reply lands.
        check(B.repair->in_flight() == 1 && B.repair->bindings() == 1,
              "CA-9f ★ THE INVARIANT: the in-flight honest job is still there AND still "
              "holds its peer binding after the second arm");
        check(mid.armed == 1 && mid.deferred == 1,
              "CA-9g ★ the second cut is QUEUED behind the busy peer, not started");
        check(mid.coalesced == 0 && mid.refused == 0 && mid.repaired == 0 &&
                  mid.fetch_failed == 0,
              "CA-9h ★ and it was NOT coalesced into the live job, and nothing was refused");
        check(B.repair->deferred() == 1,
              "CA-9i the queued cut is remembered by key, so it stays re-armable");

        // (e) release the wire. The first repair completes and re-drives; its
        //     completion frees the peer and releases the queued cut, which then
        //     fetches, replays and re-drives in turn — all inside this call.
        pump(bus, A, B);
        const RepairStats rs = B.repair->stats();
        check(rs.resumed == 1 && rs.armed == 2,
              "CA-9j the queued cut was re-armed exactly once, when the peer fell free");
        check(B.repair->in_flight() == 0 && B.repair->deferred() == 0,
              "CA-9k ★ NO ZOMBIE: no job and no queue entry survives the round");
        check(rs.repaired == 2 && rs.refused == 0 && rs.order_failed == 0 &&
                  rs.fetch_failed == 0,
              "CA-9l ★ BOTH cuts replayed to the winner's OWN digest and were accepted");
        check(B.repair->verified_view(CH, w1.cut_next_pos, w1.cut_spine_digest) != nullptr &&
                  B.repair->verified_view(CH, w2.cut_next_pos, w2.cut_spine_digest) != nullptr,
              "CA-9m a verified projection is cached for EACH cut (neither was orphaned)");
        check(B.redrive_count() == 2,
              "CA-9n both one-shot refused wins were re-driven by S3");
        check((B.node->ledger().is_pending(w1.bid) || B.node->ledger().is_settled(w1.bid)) &&
                  (B.node->ledger().is_pending(w2.bid) || B.node->ledger().is_settled(w2.bid)),
              "CA-9o both blocks are registered on B after the re-drive");
        const S1PeerStats ps1 = B.node->s1c_stats();
        check(ps1.repair_hit == 2 && ps1.credited == 2,
              "CA-9p the re-driven arms read the repaired views and CREDITED both");

        // (f) ★ CONVERGENCE. Bury both blocks and compare the commitments.
        for (int i = 0; i <= static_cast<int>(D_CONF); ++i)
            coin->append_block("f" + std::to_string(i));
        int a_fin = 0, b_fin = 0;
        for (const auto& st : A.bed->on_tip(coin->best_tip()))
            if (st.bid == kWonBid || st.bid == kWonBid2) ++a_fin;
        for (const auto& st : B.bed->on_tip(coin->best_tip()))
            if (st.bid == kWonBid || st.bid == kWonBid2) ++b_fin;
        check(a_fin == 2 && b_fin == 2,
              "CA-9q both blocks finalize on BOTH nodes at H_b + d_conf");
        check(A.owed() == B.owed() && hex32(B.owed()) != kEmptyAnchor,
              "CA-9r ★ owed_digest(A) == owed_digest(B), BYTE-EQUAL, over TWO settled blocks "
              "that were both armed against one busy peer");
        // The winner is the control: serving two repairs moved nothing of its own.
        check(A.lane() == won2.cut.lane_digest,
              "CA-9s the server's own lane digest is untouched by serving both repairs");
    }

    // ── CA-10 ★ THE REPLY BEATS THE BIND ────────────────────────────────────
    // arm() has to write m_by_peer[peer] at SOME point around the ask. Writing
    // it AFTER request_order() returned looks safe only if the reply can never
    // land first — and that argument depends on the answer arriving on the same
    // thread that armed, which is false: arm() is reached from the block-event
    // path, from drain_deferred() on a completing repair, and from the S3
    // re-drive, none of which is the transport reader thread.
    //
    // This case collapses that window to its extreme and makes it deterministic:
    // the control SendFn delivers each frame into the other node IMMEDIATELY, so
    // the whole ORDER / GETFRAMES round trip happens INSIDE B's request_order()
    // call, before arm() has returned. With the binding written after the ask,
    // on_order() finds NO binding for the peer, DROPS the reply, and the job
    // stays in m_jobs with nothing left to answer it: a silent zombie, and the
    // cut permanently unrepairable. With the binding written BEFORE the ask —
    // which is what ships — the reply lands on its job and the repair completes.
    std::printf("-- CA-10 the ORDER reply is delivered before arm() returns\n");
    {
        auto coin = std::make_shared<MockCoinBackend>();
        Node* pA = nullptr;
        Node* pB = nullptr;
        const CarrierPeerNode::PeerId PID = ManualBus::PID;
        // A's control frames go straight into B, and B's straight into A. No
        // queue, no second thread: delivery is a nested call.
        auto into_b = [&](CarrierPeerNode::PeerId,
                          const std::vector<std::uint8_t>& f) {
            if (!pB) return false;
            pB->serve->on_control(PID, f);
            pB->fetch->on_control(PID, f);
            return true;
        };
        auto into_a = [&](CarrierPeerNode::PeerId,
                          const std::vector<std::uint8_t>& f) {
            if (!pA) return false;
            pA->serve->on_control(PID, f);
            pA->fetch->on_control(PID, f);
            return true;
        };
        Node A(coin, ratified, nullptr, /*is_a=*/true,  into_b);
        Node B(coin, ratified, nullptr, /*is_a=*/false, into_a);
        pA = &A;
        pB = &B;
        {   // the serve side must not throttle: a throttle here would be a
            // harness artefact, not a finding.
            SupplyServeOptions so;
            so.burst = 64.0;
            A.serve->set_options(so);
        }

        const Stream& s = stream();
        for (int i = 0; i < N_SHARE; ++i) {
            A.feed(s.frame[i]);
            if (i != DROP_AT) B.feed(s.frame[i]);      // B loses one share
        }
        (void)wait_until([&] { return A.next_pos() == static_cast<u64>(N_SHARE); });
        (void)wait_until([&] { return B.next_pos() == static_cast<u64>(N_SHARE - 1); });

        coin->append_block("g0");
        const u64     win_h       = coin->append_block(kWonBid);
        const bytes32 owed_at_win = A.owed();
        const WonBlockOutcome won = A.node->on_block_won(kWonBid, win_h, /*confirmations=*/0);
        const bytes32 lane_a_before = A.lane();
        const bytes32 owed_a_before = A.owed();

        const PeerWin w = peer_win_of(kWonBid, win_h, won.cut, won.emitted, owed_at_win);
        const BlockEventDriver::RegisterResult g = B.bed->on_peer_block_found(w);
        check(!g.registered && B.node->s1c_stats().repair_wanted >= 1,
              "CA-10a the peer win is REFUSED at the cut and flagged REPAIRABLE");

        // ★ THE TRIGGER. Everything — ORDER, GETFRAMES, the replay, the S3
        //   re-drive — runs to completion inside this one call.
        const bool armed = B.repair->arm(PID, w.bid, w.cut_next_pos, w.cut_spine_digest);
        const RepairStats rs = B.repair->stats();
        check(armed, "CA-10b the arm dispatched a fetch");
        check(rs.armed == 1 && rs.repaired == 1 && rs.refused == 0 &&
                  rs.order_failed == 0 && rs.fetch_failed == 0,
              "CA-10c ★ the reply that landed INSIDE request_order() was CREDITED: the "
              "repair replayed to the winner's own digest");
        check(B.repair->in_flight() == 0 && B.repair->bindings() == 0 &&
                  B.repair->deferred() == 0,
              "CA-10d ★ NO ZOMBIE: no job, no binding and no queue entry survives the arm");
        check(B.repair->verified_view(CH, w.cut_next_pos, w.cut_spine_digest) != nullptr,
              "CA-10e a verified projection is cached for the cut");
        check(B.redrive_count() == 1,
              "CA-10f the S3 re-drive fired once, from inside the completing arm");
        check(B.node->ledger().is_pending(w.bid) || B.node->ledger().is_settled(w.bid),
              "CA-10g the block is registered on B after the re-drive");
        check(B.node->s1c_stats().repair_hit == 1 && B.node->s1c_stats().credited == 1,
              "CA-10h the re-driven arm read the repaired view and CREDITED");

        // Convergence, and the winner as the control.
        for (int i = 0; i <= static_cast<int>(D_CONF); ++i)
            coin->append_block("f" + std::to_string(i));
        bool a_fin = false, b_fin = false;
        for (const auto& st : A.bed->on_tip(coin->best_tip())) if (st.bid == kWonBid) a_fin = true;
        for (const auto& st : B.bed->on_tip(coin->best_tip())) if (st.bid == kWonBid) b_fin = true;
        check(a_fin && b_fin && A.owed() == B.owed() && hex32(B.owed()) != kEmptyAnchor,
              "CA-10i ★ owed_digest(A) == owed_digest(B), BYTE-EQUAL, over a reply that beat "
              "the bind");
        check(A.lane() == lane_a_before && owed_a_before == owed_at_win,
              "CA-10j serving the repair moved nothing of the winner's own");
    }

    // ── CA-11 ★ THE REPAIR NOBODY ANSWERS ───────────────────────────────────
    // A request that gets no reply at all. SupplyRequester stamps a deadline on
    // every outstanding slot, but a deadline nobody reads is not a timeout:
    // until tick() is DRIVEN the repair sits in flight forever, and the cut
    // queued behind that peer sits behind it forever. Fail-closed — owed never
    // moves — but permanently and silently, which is exactly the shape of a
    // zombie. The daemon now drives tick() on the carrier_send idle cadence;
    // this case drives it by hand, with the clock pushed past the deadline.
    std::printf("-- CA-11 a repair whose reply never arrives is timed out, not stranded\n");
    {
        ManualBus bus;                      // frames go in here and are NEVER pumped
        auto coin = std::make_shared<MockCoinBackend>();
        Node A(coin, ratified, &bus, /*is_a=*/true);
        Node B(coin, ratified, &bus, /*is_a=*/false);
        const Stream& s = stream();

        // Two distinct prefixes and a win at each, exactly as CA-9 builds them,
        // so there IS a second cut to strand behind the first.
        const int P1 = 6;
        for (int i = 0; i < P1; ++i) { A.feed(s.frame[i]); if (i != DROP_AT) B.feed(s.frame[i]); }
        (void)wait_until([&] { return A.next_pos() == static_cast<u64>(P1); });
        coin->append_block("g0");
        const u64     h1    = coin->append_block(kWonBid);
        const bytes32 owed1 = A.owed();
        const WonBlockOutcome won1 = A.node->on_block_won(kWonBid, h1, /*confirmations=*/0);
        for (int i = P1; i < N_SHARE; ++i) { A.feed(s.frame[i]); if (i != DROP_AT) B.feed(s.frame[i]); }
        (void)wait_until([&] { return A.next_pos() == static_cast<u64>(N_SHARE); });
        (void)wait_until([&] { return B.next_pos() == static_cast<u64>(N_SHARE - 1); });
        const u64     h2    = coin->append_block(kWonBid2);
        const bytes32 owed2 = A.owed();
        const WonBlockOutcome won2 = A.node->on_block_won(kWonBid2, h2, /*confirmations=*/0);

        const PeerWin w1 = peer_win_of(kWonBid,  h1, won1.cut, won1.emitted, owed1);
        const PeerWin w2 = peer_win_of(kWonBid2, h2, won2.cut, won2.emitted, owed2);
        (void)B.bed->on_peer_block_found(w1);
        (void)B.bed->on_peer_block_found(w2);
        const bytes32 owed_b_before = B.owed();

        const bool armed1 = B.repair->arm(ManualBus::PID, w1.bid, w1.cut_next_pos,
                                          w1.cut_spine_digest);
        const bool armed2 = B.repair->arm(ManualBus::PID, w2.bid, w2.cut_next_pos,
                                          w2.cut_spine_digest);
        check(armed1 && !armed2 && B.repair->in_flight() == 1 &&
                  B.repair->bindings() == 1 && B.repair->deferred() == 1,
              "CA-11a one repair is in flight and holds its binding; the second cut is QUEUED");

        // (a) NOTHING happens on its own. A tick BEFORE the deadline expires
        //     nothing, which is what makes the next step a timeout rather than
        //     an unconditional sweep.
        const std::size_t early = B.fetch->tick(std::chrono::steady_clock::now());
        check(early == 0 && B.repair->in_flight() == 1 && B.repair->deferred() == 1 &&
                  B.fetch->stats().timeouts == 0,
              "CA-11b before the deadline nothing expires — and with NOTHING driving tick() "
              "this is the state a stranded repair stays in forever");

        // (b) ★ THE DRIVE. Past the deadline the slot expires, on_fail reaches
        //     RepairDriver::finish(), and finish() drains the queue — so the
        //     SECOND cut is re-armed by the very failure of the first.
        const std::size_t late1 =
            B.fetch->tick(std::chrono::steady_clock::now() + std::chrono::hours(1));
        const RepairStats t1 = B.repair->stats();
        check(late1 == 1 && B.fetch->stats().timeouts == 1,
              "CA-11c tick() expired the outstanding request (the peer never answered)");
        check(t1.refused == 1 && t1.fetch_failed == 1,
              "CA-11d the stranded repair is counted REFUSED, not left in flight");
        check(t1.resumed == 1 && t1.armed == 2 && B.repair->deferred() == 0 &&
                  B.repair->in_flight() == 1,
              "CA-11e ★ the cut QUEUED behind the dead repair was released and re-armed");

        // (c) the resumed repair is asking the same silent peer. One more tick
        //     past its deadline and the driver is completely clean.
        const std::size_t late2 =
            B.fetch->tick(std::chrono::steady_clock::now() + std::chrono::hours(2));
        const RepairStats t2 = B.repair->stats();
        check(late2 == 1 && t2.refused == 2,
              "CA-11f the resumed repair times out in its turn");
        check(B.repair->in_flight() == 0 && B.repair->bindings() == 0 &&
                  B.repair->deferred() == 0,
              "CA-11g ★ NO PERMANENT ZOMBIE: no job, no binding and no queue entry is left");

        // (d) and the cut stays RE-ARMABLE: a timeout refuses, it does not
        //     poison the key the way a dead coalescing job did.
        const bool rearm = B.repair->arm(ManualBus::PID, w1.bid, w1.cut_next_pos,
                                         w1.cut_spine_digest);
        check(rearm && B.repair->stats().armed == 3,
              "CA-11h a timed-out cut is armed again cleanly by a later S3 re-offer");
        (void)B.fetch->tick(std::chrono::steady_clock::now() + std::chrono::hours(3));

        // (e) ZERO CONSENSUS: failing closed stays closed. Neither node credited
        //     anything, and B's owed_digest did not move by one byte.
        check(B.owed() == owed_b_before,
              "CA-11i owed_digest(B) is unmoved by three timed-out repairs (fail closed)");
        check(B.node->s1c_stats().credited == 0 &&
                  !B.node->ledger().is_pending(w1.bid) &&
                  !B.node->ledger().is_settled(w1.bid),
              "CA-11j nothing was credited on a repair that never verified");
        check(A.lane() == won2.cut.lane_digest,
              "CA-11k the winner's own lane digest is untouched throughout");
    }

    std::printf("== %d checks, %d failures ==\n", g_checks, g_fails);
    return g_fails == 0 ? 0 : 1;
}
