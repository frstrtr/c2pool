// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ===========================================================================
// v37_convergence_soak.cpp — the SUSTAINED-LOAD soak over the Stage-1 supply +
// Stage-2 apply repair machinery (the merged closer).
//
// WHY A SOAK AND NOT ANOTHER KAT. v37_convergence_apply_kat proves the repair
// MECHANISM on eleven short, fixed scenarios: nine carriers, one dropped share,
// one or two wins, hand-picked timings. Every one of them is inside the
// mechanism's operating envelope by construction. What a pool actually runs is
// the opposite shape — tens of thousands of carriers, a share lost here and
// there forever, peers coming and going, block after block after block — and
// the questions that shape asks are not "does the repair work once" but
//
//     * does owed_digest STAY byte-equal across nodes, block after block;
//     * is every cut-miss either repaired or failed CLOSED (never a fold at
//       a prefix that is not the winner's);
//     * does any repair job, binding or queue entry survive forever;
//     * do the retained-frame vault and the deferred queue stay BOUNDED;
//     * is any block ever credited twice.
//
// This file drives exactly that. It reuses the SAME rig objects the apply KAT
// assembles — XbtcNode + BlockEventDriver + CarrierIngest + CarrierRelay +
// FrameVault + SupplyService/SupplyRequester + RepairDriver, one set per node,
// the production wiring of main_v37_btc_dash.cpp — and replaces only the
// control-frame transport with an in-process mesh so the schedule is ours and
// the run is deterministic in its seed.
//
// WHAT IS ASSERTED, CONTINUOUSLY (the SAFETY half — these are hard failures)
//   SK-A  NEVER A WRONG-PREFIX FOLD: every peer win this node REGISTERS folded
//         at the winner's own (P, spine) and produced the winner's own E_b,
//         key for key. A refused win moves owed_digest by zero bytes.
//   SK-B  CONVERGENCE AT MATCHED CUTS: any two nodes holding the SAME settled
//         block set hold the SAME owed_digest, byte for byte.
//   SK-B2 AGREEMENT (a consistency check, NOT the convergence gate): for every
//         block a PAIR of nodes BOTH settled, the E_b map each put into its own
//         ledger is identical key for key — counted ONCE per (pair, block).
//         It is implied by SK-A (credit_map is only ever written on a path that
//         already asserted equality against the winner's map), which is why the
//         convergence GATE is SK-B's owed_digest comparison and not this.
//   SK-C  NO ZOMBIE: at every quiescence checkpoint — the wire drained and the
//         requester's tick() driven past its deadlines, which is what the
//         daemon does on the carrier_send idle cadence — no RepairDriver holds
//         a job, a peer binding or a queued cut.
//   SK-D  BOUNDED: FrameVault entries/bytes stay under their configured caps,
//         the deferred queue stays under kMaxDeferred, and the driver's held
//         peer-win map stays under kMaxRepairable.
//   SK-E  NO DOUBLE CREDIT: Σ finalW equals the sum of the credits actually
//         registered for the blocks this node has SETTLED — exactly once each.
//
// AND WHAT IS MEASURED (the LIVENESS half — reported, never guessed): the
// largest lane prefix at which a repair actually completed, the largest at
// which one was refused, and the cause histogram behind every refusal. A soak
// that cannot converge is only useful if it says WHY, at WHICH prefix, and
// with WHICH counter moving.
//
// CONSUMER TREE / TEST ONLY. Nothing under src/sharechain/v37 is touched, no
// production header is edited, settle::fold_eb and OwedLedger::owed_digest()
// are read and never changed, and every knob this file turns (SupplyServeOptions,
// FrameVaultOptions) is an ordinary runtime option the daemon already exposes.
//
// KNOBS (environment; the defaults are what the registered CTest runs)
//   SOAK_SEED          RNG seed                                   (default 20260918)
//   SOAK_NODES         nodes in the mesh                          (default 3)
//   SOAK_ROUNDS        max rounds                                 (default 1500)
//   SOAK_SECONDS       wall-clock budget, seconds                 (default 90)
//   SOAK_CARRIERS      carriers minted per round                  (default 2)
//   SOAK_WIN_EVERY     rounds per block win                       (default 6)
//   SOAK_PDROP         per-node per-carrier drop probability      (default 0.02)
//   SOAK_PDELAY        per-node per-carrier reorder probability   (default 0.06)
//   SOAK_PFLAP         per-round link flap probability            (default 0.004)
//   SOAK_BURST         SupplyServeOptions::burst, 0 = shipped     (default 0)
//   SOAK_REFILL        SupplyServeOptions::refill_per_sec, 0 = shipped
//   SOAK_VAULT_HORIZON FrameVaultOptions::horizon_positions, 0 = shipped
//   SOAK_VAULT_ENTRIES FrameVaultOptions::max_entries, 0 = shipped
//   SOAK_CHECK_EVERY   rounds per quiescence checkpoint           (default 20)
//   SOAK_STRICT        a divergence at a matched cut is FATAL     (default 1)
//   SOAK_MIN_REPAIR_PCT  % of REPAIRABLE pairs that must be repaired (default 90)
//   SOAK_QUIESCE_MS    virtual ms one quiescence may spend        (default 180000)
//   SOAK_ARM_WINNER    1 = name the winner FIRST in the candidate list (probe)
//   SOAK_VERBOSE       1 = per-win trace
//
// ── WHAT THE GATE IS, AND WHY IT IS ONE (the c2pool#1668 review, H-1..H-4) ──
// The first cut of this soak measured honestly and gated badly:
//   H-1 SK-3 was `credited_first_pass + repaired > 0` — satisfied by first-pass
//       credits alone, so deleting the repair arm left the soak green. It is
//       now SK-3a/b/c/d: cut-misses must exist, a repair must actually credit,
//       and the REPAIRABLE pairs must be covered to SOAK_MIN_REPAIR_PCT.
//   H-2 max_pos_repaired counted first-pass credits, so SK-A1 false-failed a
//       lossless run. It now counts only credits that appeared AFTER the repair
//       channel ran, and SK-A1 is the RETENTION pin (never a suffix repair)
//       rather than the token-budget pin the F-1 fix retired.
//   H-3 SK-B2 was cumulative (the same pair-block re-counted at every
//       checkpoint — that is where "79 753 samples" came from) and tautological
//       with SK-A. It is de-duplicated and demoted to a consistency check.
//   H-4 the owed_digest comparison was non-fatal unless SOAK_STRICT=1. It is
//       fatal by default, and SK-7a fails a run in which it was never sampled.
//
// Stdlib + Threads only, the self-harness shape of its siblings in this
// directory.
// ===========================================================================
#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <random>
#include <set>
#include <string>
#include <fcntl.h>
#include <thread>
#include <unistd.h>
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

// ── the scoreboard ─────────────────────────────────────────────────────────
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
static const char* kEmptyAnchor =
    "b4db1ded95a73f939975a259f9b48a1d182109f44397ed77e35d624f1a5cf339";

static const ChainId CH     = 7;
static const u64     D_CONF = 3;

// ═══════════════════════════════════════════════════════════════════════════
// THE VIRTUAL CLOCK — the second substitution this file makes, and the reason
// it can measure the serve-side budget at all.
//
// SupplyService's per-peer token bucket refills in REAL seconds, and
// SupplyRequester's timeouts and (since the F-1 fix) its throttle backoff run
// on the same clock. A soak compresses hours of block production into seconds
// of wall time, so on the real clock the bucket is permanently empty, every
// measured refusal is a harness artefact, and a backoff that waits 250 ms of
// real time would make the run take days.
//
// So both halves of the supply channel are driven from ONE monotone virtual
// clock that the harness advances explicitly — 50 ms at a time while a repair
// is waiting on a budget or a backoff. That is not a fudge: it is the honest
// model of the thing being measured, because the quantity that matters is
// exactly "how many virtual SECONDS of serve budget does one repair consume",
// and the report states it (REPAIR TIME below) so it can be compared against a
// real block interval rather than hidden.
static std::atomic<long long> g_vnanos{0};
static std::chrono::steady_clock::time_point vnow() {
    return std::chrono::steady_clock::time_point(std::chrono::nanoseconds(g_vnanos.load()));
}
static void vadvance(std::chrono::nanoseconds d) {
    g_vnanos.fetch_add(static_cast<long long>(d.count()));
}

// ── knobs ──────────────────────────────────────────────────────────────────
static long   env_long(const char* k, long d) {
    const char* v = std::getenv(k);
    if (!v || !*v) return d;
    return std::strtol(v, nullptr, 10);
}
static double env_dbl(const char* k, double d) {
    const char* v = std::getenv(k);
    if (!v || !*v) return d;
    return std::strtod(v, nullptr);
}

struct SoakCfg {
    std::uint64_t seed        = 20260918ULL;
    int           nodes       = 3;
    long          rounds      = 1500;
    double        seconds     = 90.0;
    int           carriers    = 2;
    int           win_every   = 6;
    double        p_drop      = 0.02;
    double        p_delay     = 0.06;
    double        p_flap      = 0.004;
    double        burst       = 0.0;     // 0 => shipped default
    double        refill      = 0.0;     // 0 => shipped default
    std::uint64_t vault_horizon = 0;     // 0 => shipped default
    std::size_t   vault_entries = 0;     // 0 => shipped default
    long          check_every = 20;
    bool          strict      = true;    // ★ a divergence at a matched cut is FATAL
    bool          verbose     = false;
    bool          arm_winner  = false;   // harness policy probe: name the WINNER first
    bool          bucket_reset = true;   // model the idle time BETWEEN real blocks
    long          progress    = 200;     // rounds between progress lines
    // ★ the gate: what share of the REPAIRABLE (peer, win) pairs must actually
    // be credited. A pair is repairable when, at arm time, some connected
    // candidate BOTH held the winner's cut and still retained lane position 0.
    long          min_repair_pct = 90;
    // How much VIRTUAL time one quiescence may spend letting the serve-side
    // budget refill and the backoff schedule run, before the request is
    // declared dead and expired. 180 s at the shipped burst/refill covers a
    // repair of ~8600 carriers, which is the vault horizon (F-3) anyway.
    long          quiesce_ms  = 180000;

    static SoakCfg from_env() {
        SoakCfg c;
        c.seed          = static_cast<std::uint64_t>(env_long("SOAK_SEED", (long)c.seed));
        c.nodes         = (int)env_long("SOAK_NODES", c.nodes);
        c.rounds        = env_long("SOAK_ROUNDS", c.rounds);
        c.seconds       = env_dbl("SOAK_SECONDS", c.seconds);
        c.carriers      = (int)env_long("SOAK_CARRIERS", c.carriers);
        c.win_every     = (int)env_long("SOAK_WIN_EVERY", c.win_every);
        c.p_drop        = env_dbl("SOAK_PDROP", c.p_drop);
        c.p_delay       = env_dbl("SOAK_PDELAY", c.p_delay);
        c.p_flap        = env_dbl("SOAK_PFLAP", c.p_flap);
        c.burst         = env_dbl("SOAK_BURST", c.burst);
        c.refill        = env_dbl("SOAK_REFILL", c.refill);
        c.vault_horizon = (std::uint64_t)env_long("SOAK_VAULT_HORIZON", 0);
        c.vault_entries = (std::size_t)env_long("SOAK_VAULT_ENTRIES", 0);
        c.check_every   = env_long("SOAK_CHECK_EVERY", c.check_every);
        c.strict        = env_long("SOAK_STRICT", 1) != 0;
        c.min_repair_pct= env_long("SOAK_MIN_REPAIR_PCT", c.min_repair_pct);
        c.quiesce_ms    = env_long("SOAK_QUIESCE_MS", c.quiesce_ms);
        c.verbose       = env_long("SOAK_VERBOSE", 0) != 0;
        c.arm_winner    = env_long("SOAK_ARM_WINNER", 0) != 0;
        c.bucket_reset  = env_long("SOAK_BUCKET_RESET", 1) != 0;
        c.progress      = env_long("SOAK_PROGRESS", c.progress);
        if (c.nodes < 2) c.nodes = 2;
        if (c.carriers < 1) c.carriers = 1;
        if (c.win_every < 1) c.win_every = 1;
        if (c.check_every < 1) c.check_every = 1;
        return c;
    }
};

// ── the miners ─────────────────────────────────────────────────────────────
static PayoutDescriptor mk_desc(std::uint8_t fill) {
    std::vector<std::uint8_t> s = {0x76, 0xa9, 0x14};
    for (int i = 0; i < 20; ++i) s.push_back(fill);
    s.push_back(0x88); s.push_back(0xac);
    PayoutDescriptor d;
    d.pay = ::v37::canonicalize_script(s);
    return d;
}
// The same nonce search the apply KAT mines with (lz = 8 below the retarget, so
// ~256 expected attempts per share — cheap enough for tens of thousands).
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
    const u64 base = salt << 30;
    for (u64 n = base; n < base + (u64(1) << 24); ++n) {
        ev.nonce = n;
        if (ev.meets_own_target()) return ev;
    }
    std::printf("FATAL: nonce exhausted (salt=%llu)\n", (unsigned long long)salt);
    std::abort();
}
static CallbackMainchainIndex::Resolver dense_index(u64 tip) {
    auto by_hash = std::make_shared<std::map<bytes32, u64>>();
    for (u64 x = 0; x <= tip; ++x) (*by_hash)[mainchain_hash(x)] = x;
    return [by_hash](const bytes32& h) -> std::optional<u64> {
        auto it = by_hash->find(h);
        return it == by_hash->end() ? std::nullopt : std::optional<u64>(it->second);
    };
}

template <class F>
static bool wait_until(F f, int timeout_ms = 4000) {
    const auto deadline =
        std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    while (std::chrono::steady_clock::now() < deadline) {
        if (f()) return true;
        std::this_thread::sleep_for(std::chrono::microseconds(200));
    }
    return f();
}

// ═══════════════════════════════════════════════════════════════════════════
// THE MESH — the ONE substitution this file makes, exactly the one CA-9 makes.
// Control frames are queued per destination instead of crossing a socket, and
// the harness delivers them. Every other wire in a Node is the production one.
// A link that is DOWN makes send() fail, which is what a dropped socket does.
// ═══════════════════════════════════════════════════════════════════════════
struct Mesh {
    struct Msg { CarrierPeerNode::PeerId from; std::vector<std::uint8_t> frame; };
    std::mutex mtx;
    std::vector<std::deque<Msg>> inbox;          // inbox[i] = frames for node i
    std::vector<std::vector<char>> up;           // up[i][j] = link i<->j alive
    std::uint64_t delivered = 0, send_failed = 0;

    void init(int n) {
        inbox.assign(n, {});
        up.assign(n, std::vector<char>(n, 1));
        for (int i = 0; i < n; ++i) up[i][i] = 0;
    }
    static CarrierPeerNode::PeerId pid_of(int node_index) {
        return static_cast<CarrierPeerNode::PeerId>(node_index + 1);
    }
    static int index_of(CarrierPeerNode::PeerId p) { return static_cast<int>(p) - 1; }

    bool send(int from, CarrierPeerNode::PeerId to_pid,
              const std::vector<std::uint8_t>& f) {
        const int to = index_of(to_pid);
        std::lock_guard<std::mutex> lk(mtx);
        if (to < 0 || to >= (int)inbox.size() || !up[from][to]) { ++send_failed; return false; }
        inbox[to].push_back(Msg{pid_of(from), f});
        return true;
    }
    bool link_up(int a, int b) {
        std::lock_guard<std::mutex> lk(mtx);
        return up[a][b] != 0;
    }
    void set_link(int a, int b, bool alive) {
        std::lock_guard<std::mutex> lk(mtx);
        up[a][b] = up[b][a] = alive ? 1 : 0;
        if (!alive) {
            // A dead socket loses whatever it was carrying.
            for (int side : {a, b}) {
                const int other = (side == a) ? b : a;
                auto& q = inbox[side];
                for (auto it = q.begin(); it != q.end();)
                    if (index_of(it->from) == other) it = q.erase(it); else ++it;
            }
        }
    }
    bool quiet() {
        std::lock_guard<std::mutex> lk(mtx);
        for (const auto& q : inbox) if (!q.empty()) return false;
        return true;
    }
};

// ═══════════════════════════════════════════════════════════════════════════
// ONE NODE — assembled exactly as main_v37_btc_dash.cpp assembles it, and as
// v37_convergence_apply_kat's `struct Node` does: the XbtcNode lifecycle, the
// carrier relay with its frame vault, the Stage-1 supply SERVE + FETCH halves,
// and the Stage-2 repair driver bound BOTH as the node's repair source and as
// the S3 re-drive.
// ═══════════════════════════════════════════════════════════════════════════
struct Node {
    int                                 idx = 0;
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
    std::mutex                          redrive_mtx;
    std::uint64_t                       redriven = 0;
    // harness bookkeeping
    std::uint64_t fed = 0;                       // carriers handed to this node
    std::map<std::string, long long> credit_of;  // bid -> Σ E_b we registered
    std::map<std::string, Amounts>   credit_map; // bid -> the E_b map we registered
    std::set<std::string> settled;               // bids this node FINALIZED

    Node(int i, std::shared_ptr<MockCoinBackend> c, const LaneParams& p,
         Mesh& mesh, const SoakCfg& cfg, u64 index_tip)
        : idx(i), coin(std::move(c)) {
        BtcNodeConfig bcfg;
        bcfg.lane_chain  = CH;
        bcfg.lane_params = p;
        bcfg.d_conf      = D_CONF;
        auto st = std::make_unique<MemSettleStore>();
        store_ref = st.get();
        node = std::make_unique<XbtcNode>(bcfg, std::move(st), coin, p2pkh_pay_of());
        if (!node->open() || !node->start()) { std::printf("FATAL: node open/start\n"); std::abort(); }
        bed = std::make_unique<BlockEventDriver>(*node, *store_ref, CH);

        auto snap = node->lane_snapshot();
        const u64 inc = snap ? snap->incarnation : 1;
        index  = std::make_unique<CallbackMainchainIndex>(dense_index(index_tip));
        ingest = std::make_unique<CarrierIngest>(node->engine(), CH, *index, tracker, inc);
        net    = std::make_unique<CarrierPeerNode>();
        relay  = std::make_unique<CarrierRelay>(ingest->fn(), *net);
        relay->set_frame_policy(wire_freeze::make_relay_policy(&policy));
        net->set_inbound([this](const std::vector<std::uint8_t>& f) {
            (void)relay->handle_inbound(f);
        });
        net->set_on_peer_connect([this] { relay->note_peer_connected(); });
        relay->set_reoffer_dedup_probe([this](const bytes32& h) { return relay->seen().seen(h); });

        if (cfg.vault_horizon || cfg.vault_entries) {
            FrameVaultOptions vo = relay->vault().options();
            if (cfg.vault_horizon) vo.horizon_positions = cfg.vault_horizon;
            if (cfg.vault_entries) vo.max_entries = cfg.vault_entries;
            relay->vault().set_options(vo);
        }

        auto send = [this, &mesh](CarrierPeerNode::PeerId pid,
                                  const std::vector<std::uint8_t>& f) {
            return mesh.send(idx, pid, f);
        };
        serve = std::make_unique<SupplyService>(relay->vault(), send);
        if (cfg.burst > 0.0 || cfg.refill > 0.0) {
            SupplyServeOptions so = serve->options();
            if (cfg.burst > 0.0)  so.burst = cfg.burst;
            if (cfg.refill > 0.0) so.refill_per_sec = cfg.refill;
            serve->set_options(so);
        }
        fetch = std::make_unique<SupplyRequester>(send);
        // Both halves on the harness's virtual clock (see vnow() above).
        serve->set_clock(&vnow);
        fetch->set_clock(&vnow);
        serve->set_spine_probe([this](std::uint32_t, u64 pos) -> std::optional<bytes32> {
            auto s = node->engine().snapshot(CH);
            if (s && s->next_pos == pos) return s->digest;
            return std::nullopt;
        });
        // ★ the cut probe the daemon binds: "did I publish exactly this cut?"
        serve->set_cut_probe([this](std::uint32_t, u64 pos, const bytes32& spine) {
            return node->engine().settlement_view_by_cut(CH, pos, spine) != nullptr;
        });
        repair = std::make_unique<RepairDriver>(*fetch, *index,
                                                static_cast<std::uint32_t>(CH), p);
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
        node->set_repair_source([this](ChainId c, u64 pos, const bytes32& spine) {
            return repair->verified_view(static_cast<std::uint32_t>(c), pos, spine);
        });
        repair->set_redrive([this](const std::string& bid, const RepairResult&) {
            { std::lock_guard<std::mutex> lk(redrive_mtx); ++redriven; }
            (void)bed->redrive_peer_block_found(bid);
        });
    }
    ~Node() { if (net) net->stop(); if (node) node->stop(); }

    void feed(const std::vector<std::uint8_t>& f) { (void)relay->handle_inbound(f); ++fed; }
    u64  next_pos() const { auto s = node->engine().snapshot(CH); return s ? s->next_pos : 0; }
    bytes32 lane() const { auto s = node->engine().snapshot(CH); return s ? s->digest : bytes32{}; }
    bytes32 owed() const { return node->ledger().owed_digest(); }
    long long final_total() const {
        long long t = 0;
        for (const auto& [k, v] : node->ledger().finalW()) { (void)k; t += v; }
        return t;
    }
};

// The v0x02 descriptor a winner puts on the wire, through a REAL frame so the
// codec is exercised on every single win of the soak.
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

static std::string bid_of(std::uint64_t n) {
    char buf[80];
    std::snprintf(buf, sizeof buf, "%032llx%032llx",
                  (unsigned long long)(n >> 32), (unsigned long long)(n & 0xffffffffULL));
    return std::string(buf);
}

// ── the running totals the report is made of ───────────────────────────────
struct Metrics {
    std::uint64_t rounds = 0, carriers_minted = 0, drops = 0, delays = 0, flaps = 0;
    std::uint64_t wins = 0, peer_offers = 0, credited_first_pass = 0;
    std::uint64_t refused_first_pass = 0, armed = 0, arm_failed = 0;
    std::uint64_t armed_at_winner = 0, armed_at_other = 0;
    std::uint64_t coverage_ok = 0, coverage_miss = 0;   // per (peer, win) pair
    // ── ★ the REPAIR gate's own numbers (H-1) ───────────────────────────────
    // repairable   : at arm time SOME connected candidate held the winner's cut
    //                AND still retained lane position 0 — i.e. a whole-prefix
    //                replay was physically possible for this pair.
    // repaired_pair: the block appeared in this node's ledger only AFTER the
    //                repair channel ran (never on the first pass).
    std::uint64_t repairable_pairs = 0, repairable_credited = 0;
    std::uint64_t repaired_pairs = 0;          // credited after quiesce, any pair
    std::uint64_t credited_unrepairable = 0;   // ★ must stay 0: a suffix repair
    // why a pair was NOT repairable — the honest decomposition of the misses
    std::uint64_t miss_winner_unreachable = 0; // the link to the winner was down
    std::uint64_t miss_no_holder = 0;          // reachable, but nobody held the cut
    std::uint64_t miss_horizon = 0;            // a holder, but its vault lost position 0
    std::uint64_t repaired = 0, repair_refused = 0, redrives = 0;
    std::uint64_t forced_ticks = 0, tick_timeouts = 0;
    std::uint64_t matched_cuts = 0, matched_equal = 0, divergences = 0;
    std::uint64_t unmatched_pairs = 0;
    // the finely-sampled half of SK-B: every block a PAIR of nodes both settled
    std::uint64_t common_blocks = 0, common_equal = 0, common_disagreed = 0;
    // liveness bounds, measured
    // ★ H-2: max_pos_repaired counts ONLY prefixes a REPLAY credited. It used
    // to be bumped on first-pass credits too, which made it a measure of how
    // far the lane got rather than of how far a repair reached — and made the
    // SK-A1 pin false-fail on a lossless run where no repair ever ran.
    u64 max_pos_repaired   = 0;
    u64 max_pos_first_pass = 0;
    u64 min_pos_refused  = ~u64(0);
    u64 max_pos_refused  = 0;
    // ★ the price of a repair, in the units the serve budget is denominated in
    long long max_repair_ms = 0, total_repair_ms = 0;
    // boundedness, measured
    std::size_t max_vault_entries = 0, max_vault_bytes = 0;
    std::size_t max_deferred = 0, max_held = 0, max_in_flight = 0, max_bindings = 0;
    std::size_t max_cached_views = 0;
    u64 max_lane_pos = 0;
    long rss_kb_start = 0, rss_kb_end = 0;
    // refusal cause histogram (server + client side)
    std::uint64_t serve_throttled = 0, order_failed = 0, fetch_failed = 0;
    std::uint64_t req_timeouts = 0, req_refused_busy = 0, deferred_drop = 0;
    std::uint64_t below_horizon_orders = 0;
    // ★ F-1 / F-2 / F-4, as counters
    std::uint64_t serve_throttled_replied = 0, throttle_retries = 0;
    std::uint64_t throttle_exhausted = 0, peer_retried = 0, spine_refused = 0;
    std::uint64_t candidates_out = 0;
    std::uint64_t by_outcome[kRepairOutcomeCount] = {};
    std::uint64_t coalesced = 0, deferred_total = 0, resumed = 0, unservable = 0;
    std::uint64_t refused_late = 0, refused_payout = 0, owed_diverged = 0;
    std::string   first_break;      // the first SAFETY break, verbatim
    long          first_break_round = -1;
};

// ── the daemon's own narration, muted ──────────────────────────────────────
// XbtcNode::say_s1c() and its siblings print a paragraph per peer win, by
// design — an operator wants to read them. Over tens of thousands of rounds
// that is tens of megabytes of log for a run whose interesting output is the
// report at the end, so the soak silences fd 1 for the body of each round and
// restores it for its own lines. SOAK_QUIET=0 keeps every word.
//
// fd 2 is NEVER touched: a sanitizer report, an assertion, a crash trace must
// always reach the log — muting stderr to keep a test quiet is how a green run
// hides a real one.
static int  g_out = -1;
static bool g_quiet = true;
static void mute() {
    if (!g_quiet) return;
    std::fflush(stdout);
    if (g_out < 0) g_out = dup(1);
    const int n = open("/dev/null", O_WRONLY);
    if (n >= 0) { dup2(n, 1); close(n); }
}
static void unmute() {
    if (!g_quiet || g_out < 0) return;
    std::fflush(stdout);
    dup2(g_out, 1);
}

static long rss_kb() {
    std::FILE* f = std::fopen("/proc/self/statm", "r");
    if (!f) return 0;
    long total = 0, resident = 0;
    if (std::fscanf(f, "%ld %ld", &total, &resident) != 2) resident = 0;
    std::fclose(f);
    return resident * (long)(sysconf(_SC_PAGESIZE) / 1024);
}

int main() {
    const SoakCfg cfg = SoakCfg::from_env();
    std::printf("== v37 CONVERGENCE SOAK — sustained multi-miner load over the merged "
                "Stage-1 supply + Stage-2 apply repair ==\n");
    std::printf("   seed=%llu nodes=%d rounds<=%ld wall<=%.0fs carriers/round=%d "
                "win_every=%d p_drop=%.3f p_delay=%.3f p_flap=%.4f\n",
                (unsigned long long)cfg.seed, cfg.nodes, cfg.rounds, cfg.seconds,
                cfg.carriers, cfg.win_every, cfg.p_drop, cfg.p_delay, cfg.p_flap);
    std::printf("   serve burst=%s refill=%s | vault horizon=%s entries=%s "
                "(0 = the SHIPPED default)\n",
                cfg.burst ? std::to_string(cfg.burst).c_str() : "shipped",
                cfg.refill ? std::to_string(cfg.refill).c_str() : "shipped",
                cfg.vault_horizon ? std::to_string(cfg.vault_horizon).c_str() : "shipped",
                cfg.vault_entries ? std::to_string(cfg.vault_entries).c_str() : "shipped");

    // The frozen wire is the control: it must be green before and after.
    check(wire_freeze::selfcheck().ok(),
          "SK-0a the frozen v0x01 + v0x02 wire selfcheck is green BEFORE the soak");
    {
        settle::OwedLedger fresh(CH);
        check(hex32(fresh.owed_digest()) == kEmptyAnchor,
              "SK-0b the empty-fold anchor sha256d(\"V37O\") is the shipped one");
    }

    Metrics M;
    M.rss_kb_start = rss_kb();
    g_vnanos.store(std::chrono::steady_clock::now().time_since_epoch().count());
    LaneParams ratified{};                       // the OQ-5 ratified default (gate-OFF)
    std::mt19937_64 rng(cfg.seed);
    auto chance = [&rng](double p) {
        return p > 0.0 && std::uniform_real_distribution<double>(0.0, 1.0)(rng) < p;
    };

    // Bins advance slowly so the W2 dedup window actually prunes (a real clock,
    // not a frozen one). Every bin in [0, tip] resolves in our index.
    const u64 BIN0 = 64;
    const int BIN_EVERY = 8;
    const u64 index_tip = BIN0 + static_cast<u64>(cfg.rounds / BIN_EVERY) + 8;

    auto coin = std::make_shared<MockCoinBackend>();
    // MockCoinBackend puts its first block at height 0, and H_b == 0 is refused
    // as "unknown height is not a height" — so the chain gets a genesis first,
    // exactly as the apply KAT's `coin->append_block("g0")` does.
    coin->append_block("g0");
    Mesh mesh;
    mesh.init(cfg.nodes);
    std::vector<std::unique_ptr<Node>> N;
    for (int i = 0; i < cfg.nodes; ++i)
        N.push_back(std::make_unique<Node>(i, coin, ratified, mesh, cfg, index_tip));

    // The miners: distinct payout descriptors, each with its OWN chained
    // prev_own_share, so the lane really is a multi-miner stream.
    const int NMINER = 4;
    std::vector<PayoutDescriptor> miner_desc;
    std::vector<bytes32>          miner_prev(NMINER, W2_GENESIS_PREV_OWN);
    for (int m = 0; m < NMINER; ++m)
        miner_desc.push_back(mk_desc(static_cast<std::uint8_t>(0xa0 + m)));

    // Per-node hold-back queues: a frame that arrives OUT OF ORDER.
    std::vector<std::vector<std::pair<long, std::vector<std::uint8_t>>>> held(cfg.nodes);

    // ── the mesh pump ───────────────────────────────────────────────────────
    // Delivers every queued control frame, both directions, until the wire
    // falls quiet. Everything downstream of a reply — the next GETFRAMES, the
    // replay, the S3 re-drive, the deferred drain — runs INSIDE this call, on
    // this thread, exactly as it runs inside the transport reader loop.
    auto pump = [&](int max_rounds = 4096) {
        for (int r = 0; r < max_rounds; ++r) {
            std::vector<std::vector<Mesh::Msg>> take(cfg.nodes);
            bool any = false;
            {
                std::lock_guard<std::mutex> lk(mesh.mtx);
                for (int i = 0; i < cfg.nodes; ++i) {
                    while (!mesh.inbox[i].empty()) {
                        take[i].push_back(std::move(mesh.inbox[i].front()));
                        mesh.inbox[i].pop_front();
                        any = true;
                    }
                }
            }
            if (!any) return;
            for (int i = 0; i < cfg.nodes; ++i)
                for (const auto& m : take[i]) {
                    ++mesh.delivered;
                    N[i]->serve->on_control(m.from, m.frame);
                    N[i]->fetch->on_control(m.from, m.frame);
                }
        }
    };

    // ── quiesce: drain the wire, then DRIVE tick() the way the daemon drives
    //    it on the carrier_send idle cadence. A request nobody answered (the
    //    server throttled it away, the peer went) only ever dies here.
    // ── quiesce: drain the wire, and ADVANCE VIRTUAL TIME in small steps while
    //    anything is still in flight, so the serve-side token bucket refills and
    //    the requester's bounded throttle backoff actually fires — which is what
    //    happens on a real node between two real blocks. Only when the virtual
    //    budget is spent is a still-outstanding request declared dead and
    //    expired, which is the harness's old behaviour and still the only way a
    //    genuinely unanswered request dies.
    //
    //    Returns the virtual milliseconds this quiescence consumed: the price of
    //    the repairs it ran, in the units the serve budget is denominated in.
    const auto kStep = std::chrono::milliseconds(50);
    auto quiesce = [&]() -> long long {
        long long spent_ms = 0;
        bool in_flight = false;
        for (;;) {
            pump();
            in_flight = false;
            for (auto& n : N) if (n->repair->in_flight() != 0) in_flight = true;
            if (!in_flight) break;
            if (spent_ms >= cfg.quiesce_ms) break;
            vadvance(kStep);
            spent_ms += kStep.count();
            for (auto& n : N) M.tick_timeouts += n->fetch->tick(vnow());
        }
        if (in_flight) {
            // The virtual budget is gone and something is STILL in flight: its
            // reply is not coming. Push every deadline past, twice, so both a
            // waiting request and the failure it turns into are drained.
            for (int spin = 0; spin < 4 && in_flight; ++spin) {
                vadvance(std::chrono::seconds(30));
                ++M.forced_ticks;
                for (auto& n : N) M.tick_timeouts += n->fetch->tick(vnow());
                pump();
                in_flight = false;
                for (auto& n : N) if (n->repair->in_flight() != 0) in_flight = true;
            }
        }
        pump();
        M.max_repair_ms = std::max(M.max_repair_ms, spent_ms);
        M.total_repair_ms += spent_ms;
        return spent_ms;
    };

    // ── the SAFETY assertions, evaluated inline so the first break is exact ──
    auto note_break = [&](long round, const std::string& what) {
        if (M.first_break.empty()) { M.first_break = what; M.first_break_round = round; }
    };

    // (pair of node indices, bid) already compared — H-3's de-duplication
    std::set<std::pair<std::pair<int, int>, std::string>> seen_pair;
    std::uint64_t bid_counter = 0x5000;
    std::uint64_t salt = 1;
    long filler = 0;
    bool safety_broken = false;
    const auto t0 = std::chrono::steady_clock::now();
    long round = 0;

    g_quiet = (env_long("SOAK_QUIET", 1) != 0) && !cfg.verbose;
    mute();
    for (; round < cfg.rounds; ++round) {
        M.rounds = static_cast<std::uint64_t>(round + 1);
        const double elapsed =
            std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
        if (elapsed > cfg.seconds) break;
        if (safety_broken) break;

        const u64 bin = BIN0 + static_cast<u64>(round / BIN_EVERY);

        // (1) LINK FLAP — a peer goes away, or comes back.
        if (cfg.nodes > 1 && chance(cfg.p_flap)) {
            const int a = (int)(rng() % cfg.nodes);
            int b = (int)(rng() % cfg.nodes);
            if (b == a) b = (a + 1) % cfg.nodes;
            const bool now_up = !mesh.link_up(a, b);
            mesh.set_link(a, b, now_up);
            ++M.flaps;
            if (!now_up) {
                // Exactly what carrier_net's peer-down callback does in main.
                N[a]->serve->forget_peer(Mesh::pid_of(b));
                N[a]->fetch->forget_peer(Mesh::pid_of(b));
                N[a]->repair->forget_peer(Mesh::pid_of(b));
                N[b]->serve->forget_peer(Mesh::pid_of(a));
                N[b]->fetch->forget_peer(Mesh::pid_of(a));
                N[b]->repair->forget_peer(Mesh::pid_of(a));
            }
        }

        // (2) MINT carriers and FLOOD them, with per-node loss and reordering.
        for (int c = 0; c < cfg.carriers; ++c) {
            const int m = (int)(rng() % NMINER);
            const WorkEvent ev = mine(miner_desc[m], bin, miner_prev[m], "soak", salt++);
            miner_prev[m] = ev.hash();
            Carrier car;
            car.carrier = ev;
            const std::vector<std::uint8_t> frame = CarrierWire::encode(car);
            ++M.carriers_minted;
            for (int i = 0; i < cfg.nodes; ++i) {
                if (chance(cfg.p_drop)) { ++M.drops; continue; }   // lost forever
                if (chance(cfg.p_delay)) {                          // out of order
                    ++M.delays;
                    held[i].emplace_back(round + 1 + (long)(rng() % 3), frame);
                    continue;
                }
                N[i]->feed(frame);
            }
        }
        // release whatever is due out of order
        for (int i = 0; i < cfg.nodes; ++i) {
            for (auto it = held[i].begin(); it != held[i].end();) {
                if (it->first <= round) { N[i]->feed(it->second); it = held[i].erase(it); }
                else ++it;
            }
        }
        // let every executor catch up with what it was handed
        for (int i = 0; i < cfg.nodes; ++i) {
            const u64 want = N[i]->fed;
            (void)wait_until([&] { return N[i]->next_pos() >= want; }, 4000);
        }

        // (3) A BLOCK WIN.
        if (round % cfg.win_every == 0) {
            // ★ TIME COMPRESSION, HONESTLY MODELLED. SupplyService's per-peer
            // token bucket refills in REAL seconds (shipped: burst 8, 2/s). A
            // soak compresses hours of block production into seconds, so without
            // this the bucket would be permanently empty and every measured
            // refusal would be a harness artefact rather than a property of the
            // code. Between two REAL blocks (~minutes) the bucket is always back
            // at `burst`, so that is the state each block's repair round starts
            // in: forget_peer() — the very call carrier_net makes on a peer-down
            // event — drops the bucket, and the next request re-creates it full.
            // What is then measured is the bound that actually binds: how many
            // requests ONE repair may make before its own burst runs out.
            if (cfg.bucket_reset)
                for (int i = 0; i < cfg.nodes; ++i)
                    for (int j = 0; j < cfg.nodes; ++j)
                        if (i != j) N[i]->serve->forget_peer(Mesh::pid_of(j));
            const int w = (int)(rng() % cfg.nodes);
            const std::string bid = bid_of(++bid_counter);
            const u64 h = coin->append_block(bid);
            const bytes32 owed_at_win = N[w]->owed();
            const BlockEventDriver::RegisterResult own = N[w]->bed->on_block_found(bid, h, 0);
            if (!own.registered) { note_break(round, "the winner could not register its OWN block: " + own.reason); safety_broken = true; break; }
            const WonBlockOutcome won = N[w]->node->last_won();
            ++M.wins;
            M.max_lane_pos = std::max<u64>(M.max_lane_pos, won.cut.next_pos);
            long long win_credit = 0;
            for (const auto& [k, v] : won.cut.credit) { (void)k; win_credit += v; }
            N[w]->credit_of[bid] = win_credit;
            N[w]->credit_map[bid] = won.cut.credit;

            const PeerWin pw = peer_win_of(bid, h, won.cut, won.emitted, owed_at_win);
            // node index -> was a whole-prefix repair PHYSICALLY possible for
            // this (peer, win) pair at the moment it was armed
            std::map<int, bool> repairable_by_node;
            if (cfg.verbose)
                std::printf("   [r%ld] win by n%d bid=%s P=%llu credit=%lld keys=%zu\n",
                            round, w, bid.substr(0, 12).c_str(),
                            (unsigned long long)pw.cut_next_pos, win_credit,
                            won.cut.credit.size());

            // (3a) offer it to every other node, exactly as the flood does.
            for (int i = 0; i < cfg.nodes; ++i) {
                if (i == w) continue;
                ++M.peer_offers;
                const bytes32 owed_before = N[i]->owed();
                const BlockEventDriver::RegisterResult r = N[i]->bed->on_peer_block_found(pw);
                if (r.registered) {
                    ++M.credited_first_pass;
                    M.max_pos_first_pass =
                        std::max<u64>(M.max_pos_first_pass, pw.cut_next_pos);
                    const EbCut& pc = N[i]->node->last_peer_cut();
                    // ★ SK-A: the fold ran at the WINNER'S prefix with the
                    //   WINNER'S commitment, and produced the WINNER'S E_b.
                    if (!(pc.next_pos == pw.cut_next_pos &&
                          pc.lane_digest == pw.cut_spine_digest &&
                          pc.credit == won.cut.credit)) {
                        note_break(round, "SK-A WRONG-PREFIX FOLD on first pass (node " +
                                              std::to_string(i) + ", bid " + bid + ")");
                        safety_broken = true;
                    }
                    long long s = 0;
                    for (const auto& [k, v] : pc.credit) { (void)k; s += v; }
                    N[i]->credit_of[bid] = s;
                    N[i]->credit_map[bid] = pc.credit;
                } else {
                    ++M.refused_first_pass;
                    // ★ SK-A (the other half): a refusal moves owed by ZERO.
                    if (N[i]->owed() != owed_before) {
                        note_break(round, "SK-A a REFUSED peer win moved owed_digest (node " +
                                              std::to_string(i) + ", bid " + bid + ")");
                        safety_broken = true;
                    }
                    // ★ F-2: arm the repair the way main_v37_btc_dash.cpp arms
                    // it NOW — hand the driver the whole connected set as an
                    // ORDERED CANDIDATE LIST and let it walk. The order is
                    // SHUFFLED so the measurement is not an artefact of this
                    // harness always naming the winner (or node 0) first: the
                    // daemon cannot identify the winner's peer id, so neither
                    // does the default run.
                    //
                    // SOAK_ARM_WINNER=1 puts the winner FIRST as a controlled
                    // probe of what perfect winner identification would buy.
                    std::vector<int> cand;
                    for (int j = 0; j < cfg.nodes; ++j)
                        if (j != i && mesh.link_up(i, j)) cand.push_back(j);
                    std::shuffle(cand.begin(), cand.end(), rng);
                    if (cfg.arm_winner) {
                        auto it = std::find(cand.begin(), cand.end(), w);
                        if (it != cand.end()) { cand.erase(it); cand.insert(cand.begin(), w); }
                    }
                    // ── ★ WAS THIS PAIR REPAIRABLE AT ALL (H-1's denominator)?
                    // A whole-prefix replay needs a candidate that BOTH holds
                    // the winner's own cut (its lane agrees at P, so its honest
                    // order replays to the winner's digest) AND still retains
                    // lane position 0 in its vault (F-3's horizon). Anything
                    // else is a refusal the repair machinery cannot be blamed
                    // for, and it does not belong in the gate's denominator.
                    bool repairable = false, any_holder = false;
                    for (int j : cand) {
                        const bool holds_cut =
                            N[j]->node->engine().settlement_view_by_cut(
                                CH, pw.cut_next_pos, pw.cut_spine_digest) != nullptr;
                        if (!holds_cut) continue;
                        any_holder = true;
                        if (N[j]->relay->vault().lowest_position() == 0) {
                            repairable = true;
                            break;
                        }
                    }
                    if (repairable) {
                        ++M.repairable_pairs;
                    } else if (any_holder) {
                        ++M.miss_horizon;          // ★ F-3, exactly
                    } else if (std::find(cand.begin(), cand.end(), w) == cand.end()) {
                        ++M.miss_winner_unreachable;
                    } else {
                        ++M.miss_no_holder;
                    }
                    repairable_by_node[i] = repairable;

                    std::vector<CarrierPeerNode::PeerId> pids;
                    for (int j : cand) pids.push_back(Mesh::pid_of(j));
                    bool armed = false;
                    if (!pids.empty() &&
                        N[i]->repair->arm_candidates(pids, pw.bid, pw.cut_next_pos,
                                                     pw.cut_spine_digest)) {
                        armed = true;
                        ++M.armed;
                        if (cand.front() == w) ++M.armed_at_winner; else ++M.armed_at_other;
                    }
                    if (!armed) ++M.arm_failed;
                }
                if (safety_broken) break;
            }
            if (safety_broken) break;

            // (3b) run the repair channel to completion.
            (void)quiesce();

            // (3c) whatever the repair produced, it is either the winner's own
            //      fold or nothing at all. Re-check every node.
            for (int i = 0; i < cfg.nodes && !safety_broken; ++i) {
                if (i == w) continue;
                const bool reg = N[i]->node->ledger().is_pending(bid) ||
                                 N[i]->node->ledger().is_settled(bid);
                if (!reg) {
                    if (N[i]->credit_of.count(bid)) {
                        note_break(round, "SK-A a credited block vanished from the ledger");
                        safety_broken = true;
                    }
                    continue;
                }
                if (!N[i]->credit_of.count(bid)) {
                    const EbCut& pc = N[i]->node->last_peer_cut();
                    if (!(pc.next_pos == pw.cut_next_pos &&
                          pc.lane_digest == pw.cut_spine_digest &&
                          pc.credit == won.cut.credit)) {
                        note_break(round, "SK-A WRONG-PREFIX FOLD after repair (node " +
                                              std::to_string(i) + ", bid " + bid + ")");
                        safety_broken = true;
                        break;
                    }
                    long long s = 0;
                    for (const auto& [k, v] : pc.credit) { (void)k; s += v; }
                    N[i]->credit_of[bid] = s;
                    N[i]->credit_map[bid] = pc.credit;
                    // ★ THIS is a repair credit: it did not exist before the
                    // channel ran. H-2: only these move max_pos_repaired.
                    ++M.repaired_pairs;
                    M.max_pos_repaired = std::max<u64>(M.max_pos_repaired, pw.cut_next_pos);
                    auto rit = repairable_by_node.find(i);
                    if (rit != repairable_by_node.end() && rit->second) {
                        ++M.repairable_credited;
                    } else {
                        // ★ SK-A1's replacement pin: a repair credited a cut
                        // that NO candidate could serve whole. Either the
                        // harness's repairable predicate is wrong or a SUFFIX
                        // was replayed — the second would be a safety bug.
                        ++M.credited_unrepairable;
                    }
                }
            }
            if (safety_broken) break;

            // measured liveness bound, per win
            for (int i = 0; i < cfg.nodes; ++i) {
                if (i == w) continue;
                const bool reg = N[i]->node->ledger().is_pending(bid) ||
                                 N[i]->node->ledger().is_settled(bid);
                if (reg) {
                    ++M.coverage_ok;
                } else {
                    ++M.coverage_miss;
                    M.min_pos_refused = std::min<u64>(M.min_pos_refused, pw.cut_next_pos);
                    M.max_pos_refused = std::max<u64>(M.max_pos_refused, pw.cut_next_pos);
                }
            }
        }

        // (4) BURY. One coin block a round; every node's own height-watch
        //     finalizes at bin_height == H_b + d_conf.
        coin->append_block("f" + std::to_string(filler++));
        for (int i = 0; i < cfg.nodes; ++i)
            for (const auto& st : N[i]->bed->on_tip(coin->best_tip()))
                N[i]->settled.insert(st.bid);

        // (5) the CONTINUOUS invariants.
        for (int i = 0; i < cfg.nodes; ++i) {
            // SK-E no double credit: Σ finalW is EXACTLY the sum of the credits
            // registered for the blocks this node has settled — once each.
            long long want = 0;
            for (const auto& b : N[i]->settled) {
                auto it = N[i]->credit_of.find(b);
                if (it != N[i]->credit_of.end()) want += it->second;
            }
            if (N[i]->final_total() != want) {
                note_break(round, "SK-E DOUBLE/LOST CREDIT on node " + std::to_string(i) +
                                      ": finalW total " + std::to_string(N[i]->final_total()) +
                                      " != registered credit sum " + std::to_string(want));
                safety_broken = true;
                break;
            }
            // SK-D bounded
            const FrameVaultOptions vo = N[i]->relay->vault().options();
            const std::size_t vs = N[i]->relay->vault().size();
            const std::size_t vb = N[i]->relay->vault().bytes();
            M.max_vault_entries = std::max(M.max_vault_entries, vs);
            M.max_vault_bytes   = std::max(M.max_vault_bytes, vb);
            M.max_deferred      = std::max(M.max_deferred, N[i]->repair->deferred());
            M.max_held          = std::max(M.max_held, N[i]->bed->repairable_held());
            M.max_in_flight     = std::max(M.max_in_flight, N[i]->repair->in_flight());
            M.max_bindings      = std::max(M.max_bindings, N[i]->repair->bindings());
            M.max_cached_views  = std::max(M.max_cached_views, N[i]->repair->cached());
            M.max_lane_pos      = std::max<u64>(M.max_lane_pos, N[i]->next_pos());
            if (vs > vo.max_entries || vb > vo.max_bytes) {
                note_break(round, "SK-D the frame vault exceeded its own caps");
                safety_broken = true; break;
            }
            if (N[i]->repair->deferred() > 64 || N[i]->bed->repairable_held() > 64) {
                note_break(round, "SK-D a bounded queue exceeded its bound");
                safety_broken = true; break;
            }
        }
        if (safety_broken) break;

        // (6) the CHECKPOINT: quiesce, then SK-B and SK-C.
        if (round % cfg.check_every == 0) {
            (void)quiesce();
            for (int i = 0; i < cfg.nodes; ++i) {
                // SK-C no zombie
                if (N[i]->repair->in_flight() != 0 || N[i]->repair->bindings() != 0 ||
                    N[i]->repair->deferred() != 0) {
                    note_break(round, "SK-C ZOMBIE on node " + std::to_string(i) +
                                          ": in_flight=" + std::to_string(N[i]->repair->in_flight()) +
                                          " bindings=" + std::to_string(N[i]->repair->bindings()) +
                                          " deferred=" + std::to_string(N[i]->repair->deferred()));
                    safety_broken = true;
                    break;
                }
            }
            if (safety_broken) break;
            // ── SK-B2, DEMOTED TO A REPORT LINE (H-3) ────────────────────────
            // This used to be a GATE, and it was tautological: credit_map is
            // written only on the paths where SK-A has ALREADY asserted
            // `pc.credit == won.cut.credit` against the winner's own map, so
            // every entry equals the winner's by construction and a pair can
            // only differ if SK-A already broke. It also re-walked the whole
            // cumulative settled set at every checkpoint, counting the same
            // pair-block thousands of times and calling each pass a "sample" —
            // which is where the 79 753 in the c2pool#1668 PR body came from.
            // It is kept as a CHEAP CONSISTENCY CHECK, counted ONCE per
            // (pair, block) and never again, and the real cross-node property
            // is SK-B below: owed_digest byte-equality, which is computed by
            // the LEDGER's own fold and is not implied by SK-A at all.
            for (int i = 0; i < cfg.nodes && !safety_broken; ++i)
                for (int j = i + 1; j < cfg.nodes && !safety_broken; ++j) {
                    const Node& a = *N[i];
                    const Node& b = *N[j];
                    const Node& small = a.settled.size() <= b.settled.size() ? a : b;
                    const Node& big   = a.settled.size() <= b.settled.size() ? b : a;
                    for (const auto& bid : small.settled) {
                        if (!big.settled.count(bid)) continue;
                        auto ia = small.credit_map.find(bid);
                        auto ib = big.credit_map.find(bid);
                        if (ia == small.credit_map.end() || ib == big.credit_map.end()) continue;
                        // ★ H-3: ONCE per (pair, block), ever.
                        if (!seen_pair.insert(std::make_pair(std::make_pair(i, j), bid)).second)
                            continue;
                        ++M.common_blocks;
                        if (ia->second == ib->second) ++M.common_equal;
                        else {
                            ++M.common_disagreed;
                            note_break(round,
                                       "SK-B2 two nodes SETTLED the same block with DIFFERENT "
                                       "E_b maps (bid " + bid + ")");
                            safety_broken = true;
                            break;
                        }
                    }
                }
            if (safety_broken) break;
            // SK-B convergence at MATCHED cuts
            for (int i = 0; i < cfg.nodes; ++i)
                for (int j = i + 1; j < cfg.nodes; ++j) {
                    if (N[i]->settled != N[j]->settled) { ++M.unmatched_pairs; continue; }
                    ++M.matched_cuts;
                    if (N[i]->owed() == N[j]->owed()) ++M.matched_equal;
                    else {
                        ++M.divergences;
                        if (cfg.strict) {
                            note_break(round, "SK-B DIVERGENCE at a matched cut: n" +
                                                  std::to_string(i) + " " + hex32(N[i]->owed()) +
                                                  " != n" + std::to_string(j) + " " +
                                                  hex32(N[j]->owed()));
                            safety_broken = true;
                        }
                    }
                }
            if (safety_broken) break;
        }

        // (7) progress, so a backgrounded run can be POLLED rather than waited on.
        if (cfg.progress > 0 && round % cfg.progress == 0) {
            unmute();
            std::printf("   [r%-6ld %6.1fs] lane=%llu wins=%llu credited=%llu/%llu "
                        "repaired=%llu armed=%llu vault=%zu cached=%zu rss=%ldkB\n",
                        round, elapsed, (unsigned long long)N[0]->next_pos(),
                        (unsigned long long)M.wins,
                        (unsigned long long)M.coverage_ok,
                        (unsigned long long)(M.coverage_ok + M.coverage_miss),
                        (unsigned long long)[&] {
                            std::uint64_t t = 0;
                            for (auto& n : N) t += n->repair->stats().repaired;
                            return t;
                        }(),
                        (unsigned long long)M.armed,
                        N[0]->relay->vault().size(), N[0]->repair->cached(), rss_kb());
            std::fflush(stdout);
            mute();
        }
    }
    unmute();

    // ── the final drain + the last checkpoint ────────────────────────────────
    mute();
    (void)quiesce();
    for (int k = 0; k <= (int)D_CONF + 2; ++k) coin->append_block("z" + std::to_string(k));
    for (int i = 0; i < cfg.nodes; ++i)
        for (const auto& st : N[i]->bed->on_tip(coin->best_tip()))
            N[i]->settled.insert(st.bid);
    (void)quiesce();
    unmute();

    // gather the cause histogram
    for (int i = 0; i < cfg.nodes; ++i) {
        const SupplyServeStats ss = N[i]->serve->stats();
        const SupplyFetchStats fs = N[i]->fetch->stats();
        const RepairStats      rs = N[i]->repair->stats();
        const S1PeerStats      ps = N[i]->node->s1c_stats();
        M.serve_throttled += ss.throttled;
        M.serve_throttled_replied += ss.throttled_replied;
        M.throttle_retries   += fs.throttle_retries;
        M.throttle_exhausted += fs.throttle_exhausted;
        M.peer_retried    += rs.peer_retried;
        M.spine_refused   += rs.spine_refused;
        M.candidates_out  += rs.candidates_out;
        M.below_horizon_orders += rs.order_below_horizon;
        for (std::size_t x = 0; x < kRepairOutcomeCount; ++x)
            M.by_outcome[x] += rs.by_outcome[x];
        M.req_timeouts    += fs.timeouts;
        M.req_refused_busy+= fs.refused_busy;
        M.repaired        += rs.repaired;
        M.repair_refused  += rs.refused;
        M.order_failed    += rs.order_failed;
        M.fetch_failed    += rs.fetch_failed;
        M.deferred_drop   += rs.deferred_drop;
        M.redrives        += rs.redriven;
        M.coalesced       += rs.coalesced;
        M.deferred_total  += rs.deferred;
        M.resumed         += rs.resumed;
        M.unservable      += rs.unservable;
        M.refused_late    += ps.refused_late;
        M.refused_payout  += ps.refused_payout;
        M.owed_diverged   += ps.owed_diverged;
    }
    M.rss_kb_end = rss_kb();

    // ── the report ───────────────────────────────────────────────────────────
    std::printf("\n-- SOAK REPORT (rounds run: %llu) ------------------------------\n",
                (unsigned long long)M.rounds);
    std::printf("   load      : carriers=%llu drops=%llu reorders=%llu flaps=%llu "
                "lane_pos_max=%llu\n",
                (unsigned long long)M.carriers_minted, (unsigned long long)M.drops,
                (unsigned long long)M.delays, (unsigned long long)M.flaps,
                (unsigned long long)M.max_lane_pos);
    std::printf("   blocks    : wins=%llu peer_offers=%llu credited_first_pass=%llu "
                "refused_first_pass=%llu\n",
                (unsigned long long)M.wins, (unsigned long long)M.peer_offers,
                (unsigned long long)M.credited_first_pass,
                (unsigned long long)M.refused_first_pass);
    std::printf("   repair    : armed=%llu (first candidate was the winner=%llu, "
                "another peer=%llu) "
                "arm_failed=%llu REPAIRED=%llu refused=%llu redrives=%llu\n",
                (unsigned long long)M.armed, (unsigned long long)M.armed_at_winner,
                (unsigned long long)M.armed_at_other, (unsigned long long)M.arm_failed,
                (unsigned long long)M.repaired, (unsigned long long)M.repair_refused,
                (unsigned long long)M.redrives);
    {
        // ★ from the OUTCOME HISTOGRAM, not from a subtraction. The old line
        // derived "replay-digest" as refused - fetch_failed - order_failed,
        // which went NEGATIVE the moment order_failed started counting (F-4):
        // order_failed counts per-CANDIDATE order refusals while `refused`
        // counts per-JOB finishes, and one job can now refuse several
        // candidates' orders before it gives up.
        const unsigned long long replay_refused =
            (unsigned long long)M.by_outcome[(std::size_t)RepairOutcome::DIGEST_MISMATCH];
        std::printf("   COVERAGE  : (peer,win) pairs credited=%llu of %llu (%.1f%%) | "
                    "refusals: transport=%llu order=%llu replay-digest=%llu\n",
                    (unsigned long long)M.coverage_ok,
                    (unsigned long long)(M.coverage_ok + M.coverage_miss),
                    (M.coverage_ok + M.coverage_miss)
                        ? 100.0 * (double)M.coverage_ok / (double)(M.coverage_ok + M.coverage_miss)
                        : 0.0,
                    (unsigned long long)M.fetch_failed, (unsigned long long)M.order_failed,
                    replay_refused);
    }
    std::printf("   causes    : serve_throttled=%llu (answered=%llu) req_timeouts=%llu "
                "order_failed=%llu (below_horizon=%llu) fetch_failed=%llu refused_busy=%llu "
                "deferred_drop=%llu\n",
                (unsigned long long)M.serve_throttled,
                (unsigned long long)M.serve_throttled_replied,
                (unsigned long long)M.req_timeouts,
                (unsigned long long)M.order_failed,
                (unsigned long long)M.below_horizon_orders,
                (unsigned long long)M.fetch_failed,
                (unsigned long long)M.req_refused_busy,
                (unsigned long long)M.deferred_drop);
    std::printf("   F-1 fix   : throttle retries=%llu exhausted=%llu  |  F-2 fix: "
                "candidate retries=%llu spine_refused=%llu exhausted=%llu\n",
                (unsigned long long)M.throttle_retries,
                (unsigned long long)M.throttle_exhausted,
                (unsigned long long)M.peer_retried,
                (unsigned long long)M.spine_refused,
                (unsigned long long)M.candidates_out);
    std::printf("   OUTCOMES  :");
    for (std::size_t x = 0; x < kRepairOutcomeCount; ++x)
        if (M.by_outcome[x])
            std::printf(" %s=%llu", repair_outcome_name(static_cast<RepairOutcome>(x)),
                        (unsigned long long)M.by_outcome[x]);
    std::printf("\n");
    std::printf("   queue     : coalesced=%llu deferred=%llu resumed=%llu deferred_drop=%llu "
                "unservable=%llu\n",
                (unsigned long long)M.coalesced, (unsigned long long)M.deferred_total,
                (unsigned long long)M.resumed, (unsigned long long)M.deferred_drop,
                (unsigned long long)M.unservable);
    std::printf("   arm       : refused_late=%llu refused_payout=%llu owed_diverged=%llu\n",
                (unsigned long long)M.refused_late, (unsigned long long)M.refused_payout,
                (unsigned long long)M.owed_diverged);
    const std::string min_ref =
        (M.min_pos_refused == ~u64(0))
            ? std::string("none")
            : std::to_string((unsigned long long)M.min_pos_refused);
    std::printf("   LIVENESS  : largest prefix P a REPAIR credited = %llu ; largest P "
                "credited on the FIRST pass = %llu ; smallest P refused = %s ; "
                "largest P refused = %llu\n",
                (unsigned long long)M.max_pos_repaired,
                (unsigned long long)M.max_pos_first_pass, min_ref.c_str(),
                (unsigned long long)M.max_pos_refused);
    std::printf("   REPAIR    : repairable (peer,win) pairs=%llu of which CREDITED=%llu "
                "(%.1f%%) ; repairs that credited=%llu ; credited-but-unrepairable=%llu\n",
                (unsigned long long)M.repairable_pairs,
                (unsigned long long)M.repairable_credited,
                M.repairable_pairs
                    ? 100.0 * (double)M.repairable_credited / (double)M.repairable_pairs
                    : 0.0,
                (unsigned long long)M.repaired_pairs,
                (unsigned long long)M.credited_unrepairable);
    std::printf("   NOT-REPAIRABLE: winner unreachable=%llu ; reachable but no peer held "
                "the winner's cut=%llu ; a holder, but its vault had evicted lane "
                "position 0 (F-3)=%llu\n",
                (unsigned long long)M.miss_winner_unreachable,
                (unsigned long long)M.miss_no_holder,
                (unsigned long long)M.miss_horizon);
    // ★ THE PRICE OF A REPAIR, in the units the serve budget is denominated in.
    // A repair over [0, P) costs ceil(P/4096) GETORDER + ceil(P/64) GETFRAMES
    // requests; the first `burst` are free and the rest arrive at
    // refill_per_sec, so the wall time one repair needs is roughly
    //     (ceil(P/4096) + ceil(P/64) - burst) / refill   seconds.
    // With the F-1 fix that is a DELAY, not a ceiling — the request is answered
    // THROTTLED and re-sent instead of dropped — so the number to watch is no
    // longer "the largest P a repair can afford" but "how long the largest one
    // took", against the chain's block interval.
    std::printf("   REPAIR TIME: virtual seconds one quiescence spent, max=%.1f s "
                "total=%.1f s (serve burst=%.0f refill=%.1f/s; a repair over P needs "
                "~(P/%u + P/%u - burst)/refill s)\n",
                (double)M.max_repair_ms / 1000.0, (double)M.total_repair_ms / 1000.0,
                cfg.burst > 0.0 ? cfg.burst : 8.0,
                cfg.refill > 0.0 ? cfg.refill : 2.0,
                (unsigned)kCtrlMaxIdsPerOrder, (unsigned)kCtrlMaxIdsPerFetch);
    // ── the OLD transport ceiling, kept only so a regression is legible. Before
    //    F-1 a request that ran out of tokens was DROPPED with no reply, so one
    //    repair could never cover more than
    //        ceil(P/4096) + ceil(P/64) <= burst   =>   P <= 448 at burst 8,
    //    and the measured max credited prefix sat right underneath it (441).
    //    With the throttle answered and the ask re-sent, that ceiling is gone:
    //    the same repair now costs TIME (see REPAIR TIME above), not coverage.
    const double burst_used = cfg.burst > 0.0 ? cfg.burst : 8.0;
    u64 p_bound = 0;
    for (u64 p = 64; p <= (u64)1 << 22; p += 64) {
        const double need = (double)((p + kCtrlMaxIdsPerOrder - 1) / kCtrlMaxIdsPerOrder) +
                            (double)((p + kCtrlMaxIdsPerFetch - 1) / kCtrlMaxIdsPerFetch);
        if (need > burst_used) break;
        p_bound = p;
    }
    std::printf("   TRANSPORT : the PRE-F-1 one-burst ceiling was P<=%llu (burst=%.0f, "
                "%u ids/ORDER, %u ids/GETFRAMES); measured max REPAIRED P=%llu %s\n",
                (unsigned long long)p_bound, burst_used,
                (unsigned)kCtrlMaxIdsPerOrder, (unsigned)kCtrlMaxIdsPerFetch,
                (unsigned long long)M.max_pos_repaired,
                M.max_pos_repaired > p_bound ? "(PAST the old ceiling: F-1 is live)"
                                             : "(at or under the old ceiling)");
    std::printf("   BOUNDS    : vault entries<=%zu bytes<=%zu | deferred<=%zu held<=%zu "
                "in_flight<=%zu bindings<=%zu | verified-view cache<=%zu\n",
                M.max_vault_entries, M.max_vault_bytes, M.max_deferred, M.max_held,
                M.max_in_flight, M.max_bindings, M.max_cached_views);
    std::printf("   MEMORY    : RSS %ld kB -> %ld kB (delta %ld kB)\n",
                M.rss_kb_start, M.rss_kb_end, M.rss_kb_end - M.rss_kb_start);
    std::printf("   AGREEMENT : blocks settled by BOTH nodes of a pair=%llu ; E_b identical "
                "key-for-key=%llu ; DISAGREED=%llu\n",
                (unsigned long long)M.common_blocks, (unsigned long long)M.common_equal,
                (unsigned long long)M.common_disagreed);
    std::printf("   CONVERGE  : matched cuts=%llu byte-equal=%llu DIVERGENT=%llu "
                "(pairs whose settled sets differed: %llu)\n",
                (unsigned long long)M.matched_cuts, (unsigned long long)M.matched_equal,
                (unsigned long long)M.divergences, (unsigned long long)M.unmatched_pairs);
    for (int i = 0; i < cfg.nodes; ++i) {
        std::printf("   node %d    : lane_pos=%llu settled=%zu owed=%s finalW=%lld "
                    "vault=%zu cached_views=%zu\n",
                    i, (unsigned long long)N[i]->next_pos(), N[i]->settled.size(),
                    hex32(N[i]->owed()).c_str(), N[i]->final_total(),
                    N[i]->relay->vault().size(), N[i]->repair->cached());
        const SupplyFetchStats f = N[i]->fetch->stats();
        const SupplyServeStats s = N[i]->serve->stats();
        const FrameVaultStats  v = N[i]->relay->vault().stats();
        std::printf("      fetch  : orders req=%llu ok=%llu | frames req=%llu ok=%llu "
                    "verified=%llu | MISSING_ID=%llu hash_mismatch=%llu dup=%llu "
                    "undecodable=%llu timeout=%llu busy=%llu unsolicited=%llu "
                    "malformed=%llu server_refused=%llu\n",
                    (unsigned long long)f.orders_requested, (unsigned long long)f.orders_ok,
                    (unsigned long long)f.frames_requested, (unsigned long long)f.frames_ok,
                    (unsigned long long)f.frames_verified, (unsigned long long)f.missing_id,
                    (unsigned long long)f.hash_mismatch, (unsigned long long)f.duplicate_id,
                    (unsigned long long)f.undecodable, (unsigned long long)f.timeouts,
                    (unsigned long long)f.refused_busy, (unsigned long long)f.unsolicited,
                    (unsigned long long)f.malformed, (unsigned long long)f.server_refused);
        std::printf("      serve  : req=%llu order_served=%llu ids=%llu frames_served=%llu "
                    "throttled=%llu truncated=%llu unservable=%llu send_failed=%llu\n",
                    (unsigned long long)s.requests, (unsigned long long)s.order_served,
                    (unsigned long long)s.order_ids, (unsigned long long)s.frames_served,
                    (unsigned long long)s.throttled, (unsigned long long)s.frames_truncated,
                    (unsigned long long)s.frames_unservable, (unsigned long long)s.send_failed);
        std::printf("      vault  : inserted=%llu refreshed=%llu evict_cap=%llu "
                    "evict_horizon=%llu order_q=%llu frame_q=%llu frames_served=%llu "
                    "frames_MISSING=%llu truncated=%llu | lowest_pos=%llu highest_pos=%llu\n",
                    (unsigned long long)v.inserted, (unsigned long long)v.refreshed,
                    (unsigned long long)v.evicted_capacity,
                    (unsigned long long)v.evicted_horizon,
                    (unsigned long long)v.order_queries, (unsigned long long)v.frame_queries,
                    (unsigned long long)v.frames_served, (unsigned long long)v.frames_missing,
                    (unsigned long long)v.frames_truncated,
                    (unsigned long long)N[i]->relay->vault().lowest_position(),
                    (unsigned long long)N[i]->relay->vault().highest_position());
    }
    std::printf("----------------------------------------------------------------\n\n");

    // ── the assertions ───────────────────────────────────────────────────────
    check(M.rounds > 0 && M.carriers_minted > 0 && M.wins > 0,
          "SK-1 the soak actually ran (rounds, carriers and block wins all non-zero)");
    check(M.first_break.empty(),
          std::string("SK-2 ★ NO SAFETY INVARIANT BROKE") +
              (M.first_break.empty() ? "" : (" — first break at round " +
                  std::to_string(M.first_break_round) + ": " + M.first_break)));
    if (!M.first_break.empty()) safety_broken = true;

    // SK-A/SK-B/SK-C/SK-D/SK-E, restated as end-state checks so a green run
    // says so in one line each.
    // ── ★ SK-3, THE REPAIR GATE (H-1) ───────────────────────────────────────
    // The old SK-3 was `credited_first_pass + repaired > 0`, which first-pass
    // credits satisfy on their own: `repair->arm()` could be deleted outright
    // and the soak stayed green. It proved nothing. These three do:
    //   3a the schedule really produced cut-misses (otherwise there was nothing
    //      for a repair to do and the rest of the gate is vacuous);
    //   3b the repair machinery actually ran and credited something — this is
    //      the one that FAILS the moment arm() is stubbed out;
    //   3c of the pairs a whole-prefix repair was PHYSICALLY possible for, at
    //      least SOAK_MIN_REPAIR_PCT% were credited.
    // A LOSSLESS schedule has no cut-miss to close, so the repair gate would be
    // vacuous — and demanding repairs of it is exactly the H-2 false-fail. It
    // gets the complementary property instead, which is just as strong for the
    // run it describes: with nothing dropped, every peer win must be credited on
    // the FIRST pass.
    const bool lossy = (cfg.p_drop > 0.0 || cfg.p_delay > 0.0 || cfg.p_flap > 0.0);
    if (!lossy) {
        check(M.refused_first_pass == 0 && M.coverage_miss == 0,
              "SK-3 (lossless schedule) every peer win was credited on the FIRST pass — "
              "there is no cut-miss for a repair to close");
    } else {
        check(M.refused_first_pass > 0,
              "SK-3a the schedule produced real cut-misses (there was work for the repair)");
        check(M.repaired > 0 && M.repaired_pairs > 0,
              "SK-3b ★ THE REPAIR RAN AND CREDITED: replays completed and blocks entered "
              "ledgers that had refused them on the first pass");
        const bool enough =
            M.repairable_pairs > 0 &&
            M.repairable_credited * 100 >=
                static_cast<std::uint64_t>(cfg.min_repair_pct) * M.repairable_pairs;
        check(enough,
              "SK-3c ★ COVERAGE: of the (peer, win) pairs some connected candidate could "
              "have served whole, at least SOAK_MIN_REPAIR_PCT% were repaired");
        check(M.spine_refused + M.peer_retried > 0 || cfg.nodes < 3,
              "SK-3d ★ the CANDIDATE WALK is exercised: at least one repair moved past a "
              "peer that could not serve the winner's cut");
    }
    {
        bool zombie = false;
        for (int i = 0; i < cfg.nodes; ++i)
            if (N[i]->repair->in_flight() || N[i]->repair->bindings() ||
                N[i]->repair->deferred()) zombie = true;
        check(!zombie,
              "SK-4 ★ NO ZOMBIE: after the final drain no node holds a repair job, "
              "a peer binding or a queued cut");
    }
    {
        bool bounded = true;
        for (int i = 0; i < cfg.nodes; ++i) {
            const FrameVaultOptions vo = N[i]->relay->vault().options();
            if (N[i]->relay->vault().size() > vo.max_entries ||
                N[i]->relay->vault().bytes() > vo.max_bytes) bounded = false;
        }
        check(bounded && M.max_deferred <= 64 && M.max_held <= 64,
              "SK-5 ★ BOUNDED: the frame vault stayed inside its caps and the "
              "deferred / held queues never passed their bounds");
    }
    {
        bool ok = true;
        for (int i = 0; i < cfg.nodes; ++i) {
            long long want = 0;
            for (const auto& b : N[i]->settled) {
                auto it = N[i]->credit_of.find(b);
                if (it != N[i]->credit_of.end()) want += it->second;
            }
            if (N[i]->final_total() != want) ok = false;
        }
        check(ok,
              "SK-6 ★ NO DOUBLE CREDIT: every node's Σ finalW is exactly the sum of "
              "the credits it registered for the blocks it settled");
    }
    // ★ SK-A1, RE-DERIVED (H-2). The old pin was `max_pos_repaired <= p_bound`,
    // the serve-side TOKEN bound — which (a) counted first-pass credits, so a
    // lossless run with P > 448 false-failed it although no repair had run, and
    // (b) stops being a law at all now that a throttled request is re-sent
    // rather than dropped. The honest pin in its place is the RETENTION one,
    // and it is the property that actually matters for safety: a repair must
    // never credit a cut that no candidate could serve WHOLE, because the lane
    // digest at P is a fold over [0, P) and a suffix replay would be a
    // wrong-prefix fold. It stays tight until F-3 lands.
    check(M.credited_unrepairable == 0,
          "SK-A1 ★ NEVER A SUFFIX REPAIR: every repair that credited had a candidate "
          "that held the winner's cut AND still retained lane position 0");
    check(M.common_disagreed == 0,
          "SK-B2 AGREEMENT (consistency, once per pair-block): no block two nodes both "
          "settled was settled with different E_b maps");
    // ★ SK-7 is now FATAL BY DEFAULT (H-4) and NON-VACUOUS. owed_digest equality
    // is the one cross-node property SK-A does not already imply: it is computed
    // by the LEDGER's own fold over its own entries, not by comparing harness
    // bookkeeping. `matched_cuts > 0` is the non-vacuity half — a run in which
    // no two nodes ever held the same settled set never sampled it at all.
    check(M.matched_cuts > 0,
          "SK-7a the owed_digest comparison was actually SAMPLED (some pair of nodes "
          "held the same settled set at a checkpoint)");
    check(M.divergences == 0 || !cfg.strict,
          "SK-7 ★★ CONVERGENCE: at every matched cut the two nodes' owed_digest was "
          "BYTE-EQUAL (fatal by default; SOAK_STRICT=0 downgrades it to a report)");
    if (M.divergences != 0)
        std::printf("  NOTE: %llu of %llu matched cuts DIVERGED — see the LIVENESS line "
                    "above for the prefix at which repairs stopped completing.\n",
                    (unsigned long long)M.divergences, (unsigned long long)M.matched_cuts);

    // ZERO CONSENSUS MOVEMENT, after all of it.
    check(wire_freeze::selfcheck().ok(),
          "SK-8 the frozen wire selfcheck is still green AFTER the soak");
    {
        settle::OwedLedger fresh(CH);
        check(hex32(fresh.owed_digest()) == kEmptyAnchor,
              "SK-9 the empty-fold anchor is unmoved by the whole run");
    }

    std::printf("== %d checks, %d failures ==\n", g_checks, g_fails);
    return g_fails == 0 ? 0 : 1;
}
