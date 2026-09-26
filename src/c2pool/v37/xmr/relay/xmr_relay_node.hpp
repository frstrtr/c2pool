// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ===========================================================================
// src/c2pool/v37/xmr/relay/xmr_relay_node.hpp   (GAP-2 stage 1)
//
// XmrRelayNode -- the c2pool-v37-xmr node-to-node RECEIPT RELAY over TCP.
// Replaces the --credit-feed shared file and the --wire-in/--wire-out
// directory drop (docs/xmr-lane/gap2-sharechain-relay-design.md).
//
// REUSED, unchanged in behaviour:
//   carrier_net.hpp   CarrierPeerNode  [u32 len][frame] TCP, one reader thread
//                     per peer, per-fd write locks, SO_SNDTIMEO hard drop.
//                     (GAP-2 adds pid-tagged inbound, add_peer_id, disconnect.)
//   frame_vault.hpp   FrameVault       bounded by-position + by-hash store; one
//                     entry per admitted receipt = its exact fb_receipt bytes.
//   carrier_supply.hpp SupplyService / SupplyRequester  GETORDER/ORDER/
//                     GETFRAMES/FRAMES (0x80..0x83); the requester's bytes-to-id
//                     check goes through the new IdOfFrameFn seam
//                     (fb_receipt -> keccak256(hashing_blob)).
//   impl/xmr/wire/xmr_carrier_dos_budget.hpp  CarrierDosBudget: per-peer and
//                     global RandomX token buckets, refund-on-valid, ban on a
//                     CONFIRMED invalid PoW (two agreeing hashes).
//
// PIPELINE for one inbound receipt (RandomX LAST, design §3.2):
//   reader thread : HELLO gate -> decode FB_RECEIPTS (total, bounded) -> dedup
//                   (known | in flight) -> bounded verify queue
//   verify worker : context (prev_id -> bin/seed via ChainView; unresolved ->
//                   parked, retried, then dropped without penalty) -> expiry
//                   (index horizon; solicited frames exempt) -> STRUCTURAL
//                   (xmr_receipt_mint.hpp check_structural) -> R-1 -> RandomX
//                   under a DoS token (none -> parked, never a penalty) ->
//                   valid: admit + refund / invalid: re-hash, confirm, BAN.
//   admit         : verified cache (the dedup set), recent ring (re-offer),
//                   FLOOD to every HELLO'd peer except the source, and the
//                   ADMITTED queue the daemon's main thread drains into the lane.
// The verify worker owns the ONLY call into RandomX (the injected RxFn): one
// LightVerifier on one thread, so a receipt flood can never sit in front of a
// miner's submit on the stratum listener thread.
//
// ORDER IS NODE-LOCAL (Ruling A). This class never decides lane order; the
// daemon's ingest (xmr_receipt_ingest.hpp) does, and the winner's on-chain cut
// (P, spine) stays the authority. When a node's own order at P does not
// reproduce the winner's spine, the REPAIR path here fetches the winner-side
// ORDER over [0, P) from a peer whose digest at P equals that spine (the
// SupplyService spine probe), fetches + fully admits any receipt it lacks, and
// hands the daemon the ordered id list to replay in a SCRATCH engine -- the
// same digest gate, the same fold (carrier_repair.hpp's argument, re-typed for
// Family-B).
//
// REPAIR CONTEXT (the fix for the stuck "relay repair ... in flight"): a
// winner-side order can hold receipts mined on a Monero block this node never
// saw -- a sibling that lost a same-height race on the winner's monerod. Our
// monerod never received it (Monero does not relay alternative blocks), so the
// receipt's prev_id resolves in no ChainView here, the verify worker parks it
// and drops it "unresolved", and before this fix the repair re-asked the same
// frames forever (and FinalizeConnect finally REFUSED an honest block at its
// retry bound). Now a SOLICITED receipt whose context is unresolved puts its
// prev_id on a bounded WANT list: the daemon asks its own monerod first (it may
// hold the block as an alternative), then the relay peers over FB_GETCTX with
// failover (each peer once per round, bounded rounds). A served block is
// verified from its bytes (verify_block_ctx: id recomputed, height from the
// coinbase) and linked to a parent this node already knows AT that height
// (recursively for a chain of up to ctx_max_depth unknown blocks); the seed is
// taken from our own chain. The repair then (a) keeps its order while it
// fetches, (b) re-asks idle missing frames with peer failover instead of
// discarding the order, (c) re-asks at once when the serving peer drops, and
// (d) reports WHICH stage is stuck (repair_status) so a stall that does reach
// the booking retry bound is refused with a loud, distinct reason.
//
// REPAIR HORIZON (REPAIR-HORIZON, capstone 09-26): a peer's frame vault keeps
// only the last horizon_positions (8640) lane positions and answers a GETORDER
// whose start predates that with BELOW_HORIZON. The repair used to ask [0, P)
// only and set such a peer aside, so once the lane was longer than the horizon
// EVERY peer refused and the repair was Exhausted forever (the non-winner side
// HELD every cross-side block). Now a BELOW_HORIZON answer raises the repair's
// start for THAT peer to its lowest_retained a0 (never lowered, never past P)
// and re-asks it instead of setting it aside: first a zero-length PREFIX PROBE
// GETORDER [a0, a0) whose spine answer is the peer's digest at a0, compared
// with ours -- equal (or unknown) -> GETORDER [a0, P) and the caller replays
// its OWN order over [0, a0) followed by the served [a0, P) (repair_a0()); the
// digest gate at P decides exactly as before. The caller may instead replay
// the last winner-side order it reconstructed (the SHADOW,
// xmr_repair_replay.hpp) as that prefix and registers its digests
// (note_alt_digests) so the probe accepts them too: lane orders never
// re-converge after a divergence, so the shadow CHAINS the winner-side order
// from repair to repair past the horizon. A peer whose digest at a0 DIFFERS
// from ours and the shadow's (or whose [a0, P) replay reaches the spine from
// neither) proves
// the divergence lies below its horizon: that peer is set aside as DEEP and,
// when every ready peer is, the repair reports a loud DEEP-DIVERGENCE status
// (repair_deep_divergence()) instead of a silent "none serves" -- still
// undecided (never a refusal on a timeout; the caller holds and alarms).
//
// RELAY-LIVENESS (capstone attempt 2): a WAN relay link went silent in BOTH
// directions for ~3.5 min while TCP kept both sessions established (conns=2
// ready=2): nothing read, nothing refused, no down event -- so both sides kept
// closing lane bins without the other side's receipts. Every ready link is now
// probed with FB_PING each keepalive_ms; any frame the peer sends refreshes the
// link's last-receive clock. A link whose peer has answered on it (it speaks
// keepalive) and then sends nothing for silence_timeout_ms is DROPPED with a
// loud "LINK SILENT" line; the dial target redials it at once (the down event
// path), and the reconnect's HELLO re-offer + GETORDER backfill deliver what the
// stall withheld. A peer that never answers a PING (a pre-0x45 build) is never
// timed out. keepalive_ms = 0 turns all of it off (no PING sent, none answered:
// the pre-liveness wire byte for byte). A maintenance gap (the process itself
// was stopped) re-arms every link's clock instead of blaming the peers.
//
// BACKFILL on (re)connect: the sender RE-OFFERS its last --relay-reoffer-seconds
// of admitted receipts PLUS every admitted receipt its lane has not pushed yet
// (the canonical ingest holds an OPEN bin's receipts unpushed, so neither the
// 60 s window nor the receiver's GETORDER backfill reached a bin that stayed
// open across a relay stall -- they arrived only as 'late' after a later
// reconnect); the receiver asks GETORDER over the peer's last
// --relay-backfill-positions lane positions and GETFRAMES for every id it has
// never seen (verified exactly like a flood, under the separate solicited
// RandomX credit).
// ===========================================================================
#pragma once

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <random>
#include <set>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include <c2pool/v37/carrier_net.hpp>
#include <c2pool/v37/carrier_supply.hpp>
#include <c2pool/v37/frame_vault.hpp>
#include "impl/xmr/wire/xmr_carrier_dos_budget.hpp"
#include "impl/xmr/coin/xmr_seedheight.hpp"
#include "xmr_relay_wire.hpp"
#include "xmr_receipt_mint.hpp"

// UP-GATE: a remote HELLO read before our own up event ran for that link waits
// for it (on_hello), and XmrRelayNode::set_test_up_delay_ms() exists.
#define C2POOL_XMR_RELAY_UP_GATE 1
// RELAY-LIVENESS: FB_PING/FB_PONG keepalive + silence timeout
// (RelayOptions::keepalive_ms / silence_timeout_ms, RelayStats::silent_drops).
#define C2POOL_XMR_RELAY_LIVENESS 1

namespace c2pool::v37n::xmr::relay {

using PeerId = ::c2pool::v37n::CarrierPeerNode::PeerId;
using Clock  = std::chrono::steady_clock;

struct Bytes32Hash {
    std::size_t operator()(const bytes32& b) const noexcept {
        std::size_t v = 0; std::memcpy(&v, b.data(), sizeof(v)); return v;
    }
};

// ── ChainView: prev_id -> (bin height, RandomX seed), fed by the main thread ──
// Thread-safe. The daemon notes every template it serves (prev_id, height,
// seed_hash) and, on the daemon arm, the recent blocks of its mainchain index,
// so a peer's receipt built on a tip we know resolves without touching the
// index from the verify thread.
class ChainView {
public:
    struct Ctx { u64 height = 0; bytes32 seed{}; };
    void note(const bytes32& prev_id, u64 height, const bytes32& seed) {
        std::lock_guard<std::mutex> lk(m_mtx);
        auto [it, fresh] = m_map.try_emplace(prev_id, Ctx{height, seed});
        if (!fresh) { it->second = Ctx{height, seed}; return; }
        m_order.push_back(prev_id);
        while (m_order.size() > kMax) { m_map.erase(m_order.front()); m_order.pop_front(); }
    }
    void set_tip(u64 template_height) {
        u64 cur = m_tip.load();
        while (template_height > cur && !m_tip.compare_exchange_weak(cur, template_height)) {}
    }
    std::optional<Ctx> lookup(const bytes32& prev_id) const {
        std::lock_guard<std::mutex> lk(m_mtx);
        auto it = m_map.find(prev_id);
        if (it == m_map.end()) return std::nullopt;
        return it->second;
    }
    u64 tip() const { return m_tip.load(); }
    std::size_t size() const { std::lock_guard<std::mutex> lk(m_mtx); return m_map.size(); }
    // RandomX seed blocks by SEED height (mainchain, >= 64 deep): what a
    // resolved foreign context takes its seed from when its bin crosses an
    // epoch edge (never from the peer that served the block).
    void note_seed(u64 seed_height, const bytes32& seed) {
        std::lock_guard<std::mutex> lk(m_mtx);
        m_seeds[seed_height] = seed;
        while (m_seeds.size() > 16) m_seeds.erase(m_seeds.begin());
    }
    std::optional<bytes32> seed_for(u64 height) const {
        std::lock_guard<std::mutex> lk(m_mtx);
        auto it = m_seeds.find(::xmr::coin::rx_seedheight(height));
        if (it == m_seeds.end()) return std::nullopt;
        return it->second;
    }
private:
    static constexpr std::size_t kMax = 8192;
    mutable std::mutex m_mtx;
    std::unordered_map<bytes32, Ctx, Bytes32Hash> m_map;
    std::map<u64, bytes32> m_seeds;
    std::deque<bytes32> m_order;
    std::atomic<u64> m_tip{0};
};

// One admitted receipt, as the main thread receives it.
struct Admitted {
    bytes32          id{};
    FbReceipt        r;
    std::vector<u8>  raw;     // its exact fb_receipt bytes (vault / durable log / GETFRAMES)
    u64              bin = 0; // origin bin = height of the block the share was mined on
    bool             own = false;
    // ★ DROPS (gate ON only): a RAINDROP — RandomX work that met the drops
    // floor but NOT share_diff. Never pushed to the lane, never cached, never
    // in a repair order; carried only to the node's DROPS harvester. `pow` is
    // the verified RandomX hash (little-endian, as meets_share_diff reads it).
    bool             drop = false;
    bytes32          pow{};
};

struct RelayOptions {
    u8          network = 3;
    u32         chain = 0;
    u64         share_diff = 0;
    bytes32     lane_params_digest{};
    BindMode    bind = BindMode::None;
    // POOL-ID: this node's roundabout lane_tag (pool_id_of()), sent in HELLO and
    // compared with every peer's. nullopt = a tagless (pre-POOL-ID) HELLO.
    std::optional<PoolId> pool_id;
    bool        listen = false;                   // false = dial-only
    std::string listen_host = "127.0.0.1";
    u16         listen_port = 0;                  // 0 = an ephemeral port (tests), read back via listen_port()
    std::vector<std::pair<std::string, u16>> peers;
    std::size_t max_peers = 8;
    u64         index_horizon = 64;               // blocks; older unsolicited receipts are dropped
    ::c2pool::xmr::DosPolicy dos{};
    u32         solicited_credits = 256;
    u64         backfill_positions = 2048;
    u32         reoffer_seconds = 60;
    bool        serve = true;
    ::c2pool::v37n::FrameVaultOptions vault{};
    u32         hello_timeout_ms = 10000;
    std::size_t verify_queue_max = 4096;
    u32         unresolved_patience_ms = 30000;
    std::size_t cache_max = 65536;                // verified receipts kept (= the dedup set)
    u32         repair_state_timeout_ms = 20000;
    // Lane positions one receipt may span (fee model S3: 2 = (payee, donation)
    // split; 1 = the gate-OFF / master rule). Bounds the repair density check.
    u32         max_pushes_per_receipt = 1;
    // repair context + refetch (see REPAIR CONTEXT above)
    u32         solicited_unresolved_patience_ms = 120000;   // a solicited receipt waits this long for its context
    u32         ctx_retry_ms = 2000;                         // re-ask an unanswered GETCTX (next peer) after this
    u32         ctx_max_rounds = 30;                         // rounds over every ready peer before a want is dropped
    u32         ctx_max_depth = 8;                           // unknown blocks chained above a known parent
    std::size_t ctx_want_max = 128;
    u32         repair_refetch_ms = 3000;                    // re-ask idle missing frames of a Fetching repair
    // ★ DROPS (gate ON only). 0 = OFF, the shipped default: a receipt below
    // share_diff is invalid PoW exactly as before (rx_invalid + DoS strike).
    // Non-zero: a receipt whose RandomX hash meets THIS difficulty but not
    // share_diff is a RAINDROP — admitted for measurement only (drain_drops),
    // flooded on like a share so every node harvests the same set.
    u64         drops_floor_diff = 0;
    std::size_t drops_seen_max = 65536;                      // raindrop dedup set bound
    // RELAY-LIVENESS: PING every ready link this often (0 = keepalive OFF: no
    // PING sent or answered, no silence timeout); drop + redial a link whose
    // keepalive-speaking peer sent nothing for silence_timeout_ms (0 = never).
    u32         keepalive_ms = 5000;
    u32         silence_timeout_ms = 25000;
};

struct RelayStats {
    std::atomic<u64> hello_sent{0}, hello_ok{0}, hello_rejected{0}, hello_timeout{0}, pre_hello_dropped{0};
    std::atomic<u64> hello_tag_mismatch{0};       // POOL-ID: HELLOs refused as TAG_MISMATCH (also in hello_rejected)
    std::atomic<u64> fa_ignored{0}, fb_unknown{0}, malformed{0}, wrong_chain{0};
    std::atomic<u64> rx_receipts{0}, dup{0}, queue_dropped{0}, unresolved_dropped{0}, expired{0};
    std::atomic<u64> structural{0}, rx_deferred{0}, rx_evals{0}, rx_valid{0}, rx_invalid{0}, rx_unavailable{0}, bans{0};
    std::atomic<u64> admitted_own{0}, admitted_foreign{0}, admitted_solicited{0};
    std::atomic<u64> flood_frames{0}, reoffer_frames{0};
    std::atomic<u64> backfill_orders{0}, backfill_ids_asked{0};
    std::atomic<u64> block_won_rx{0}, block_won_tx{0};
    std::atomic<u64> dials{0}, dial_fail{0}, over_cap{0};
    std::atomic<u64> repair_started{0}, repair_order_ok{0}, repair_spine_mismatch{0}, repair_peer_fail{0}, repair_ids_asked{0}, repair_ready{0}, repair_rejected{0};
    std::atomic<u64> repair_refetch{0}, repair_evicted{0}, upgraded_solicited{0}, unresolved_solicited_dropped{0};
    std::atomic<u64> ctx_wanted{0}, ctx_asked{0}, ctx_rx{0}, ctx_resolved{0}, ctx_bad{0}, ctx_unknown_rx{0},
                     ctx_gave_up{0}, ctx_served{0}, ctx_unknown_tx{0}, ctx_req_dropped{0};
    // ★ DROPS (gate ON only; all stay 0 with drops_floor_diff == 0)
    std::atomic<u64> drops_own{0}, drops_foreign{0}, drops_dup{0};
    std::atomic<u64> won_reoffered{0};   // ENROL-REPL: FB_BLOCK_WON frames re-offered on HELLO
    // REPAIR-HORIZON: BELOW_HORIZON answers that raised a repair's start and
    // re-asked (instead of setting the peer aside); prefix probes whose digest
    // at a0 matched ours / was unknown there; peers proven DEEP (divergence
    // below their horizon); receipts re-offered on HELLO because still unpushed.
    std::atomic<u64> repair_horizon_rearm{0}, repair_prefix_ok{0}, repair_prefix_unknown{0}, repair_deep{0};
    std::atomic<u64> reoffer_unpushed{0};
    // RELAY-LIVENESS: keepalive frames, links dropped as SILENT, peers that
    // never answered a PING (pre-0x45 builds: silence not enforced), and
    // maintenance gaps that re-armed every link's clock.
    std::atomic<u64> ping_tx{0}, ping_rx{0}, pong_tx{0}, pong_rx{0}, silent_drops{0}, ka_legacy{0}, ka_rearm{0};
};

class XmrRelayNode {
public:
    // RandomX on the verify worker: hash(blob) under `seed`. false = engine
    // unavailable / seed not resident (a local condition, never a penalty).
    using RxFn      = std::function<bool(const std::vector<u8>& blob, const bytes32& seed, bytes32& pow)>;
    using LaneTipFn = std::function<std::pair<u64, bytes32>()>;
    using LogFn     = std::function<void(const std::string&)>;

    enum class RepairState { Pending, Ready, Exhausted };

    XmrRelayNode(RelayOptions o, ChainView& chain, RxFn rx, LaneTipFn tip, LogFn log)
        : m_o(std::move(o)), m_chain(chain), m_rx(std::move(rx)), m_tip(std::move(tip)),
          m_log(std::move(log)), m_dos(m_o.dos), m_vault(m_o.vault) {
        std::random_device rd;
        m_nonce = (static_cast<u64>(rd()) << 32) ^ rd() ^
                  static_cast<u64>(Clock::now().time_since_epoch().count());
        m_solicited = static_cast<double>(m_o.solicited_credits);
    }
    ~XmrRelayNode() { stop(); }
    XmrRelayNode(const XmrRelayNode&) = delete;
    XmrRelayNode& operator=(const XmrRelayNode&) = delete;

    // ── lifecycle ───────────────────────────────────────────────────────────
    bool start(std::string& why) {
        m_serve = std::make_unique<SupplyService>(m_vault, [this](PeerId p, const std::vector<u8>& f) { return m_net.send_to(p, f); });
        m_fetch = std::make_unique<SupplyRequester>([this](PeerId p, const std::vector<u8>& f) { return m_net.send_to(p, f); });
        {
            SupplyServeOptions so = m_serve->options();
            so.enabled = m_o.serve;
            m_serve->set_options(so);
        }
        m_serve->set_spine_probe([this](std::uint32_t chain, std::uint64_t pos) -> std::optional<bytes32> {
            if (chain != m_o.chain) return std::nullopt;
            std::lock_guard<std::mutex> lk(m_dmtx);
            auto it = m_pos_digest.find(pos);
            if (it == m_pos_digest.end()) return std::nullopt;
            return it->second;
        });
        m_fetch->set_id_of_frame([](const std::vector<u8>& b) -> std::optional<bytes32> {
            FbReceipt r;
            if (!decode_fb_receipt(b, r)) return std::nullopt;
            return receipt_id(r);
        });
        m_fetch->set_on_order([this](PeerId p, const CtrlOrder& o) { on_order(p, o); });
        m_fetch->set_on_frames([this](PeerId p, const std::vector<VerifiedFrame>& v) { on_frames(p, v); });
        m_fetch->set_on_fail([this](PeerId p, SupplyFailure f) { on_fetch_fail(p, f); });
        m_fetch->set_on_unservable([this](PeerId p, const std::vector<bytes32>&) { on_fetch_fail(p, SupplyFailure::UNSERVABLE_ID); });

        m_net.set_inbound_from([this](PeerId p, const std::vector<u8>& f) { on_frame(p, f); });
        m_net.set_control([this](PeerId p, const std::vector<u8>& f) {
            note_rx(p);   // RELAY-LIVENESS: a supply frame proves the link alive too
            if (!hello_ok(p)) { m_st.pre_hello_dropped++; return; }
            m_serve->on_control(p, f);
            m_fetch->on_control(p, f);
        });
        m_net.set_on_peer_event([this](PeerId p, bool up) { on_peer_event(p, up); });
        m_net.set_log([this](const std::string& s) { log("relay: " + s); });

        if (m_o.listen) {
            if (!m_net.listen(m_o.listen_host, m_o.listen_port)) {
                why = "relay: cannot listen on " + m_o.listen_host + ":" + std::to_string(m_o.listen_port);
                return false;
            }
        }
        {
            std::lock_guard<std::mutex> lk(m_tmtx);
            for (const auto& [h, pt] : m_o.peers) m_targets.push_back(Target{h, pt, 0, Clock::now(), 1});
        }
        m_running = true;
        m_verify_thread = std::thread([this] { verify_loop(); });
        m_maint_thread  = std::thread([this] { maint_loop(); });
        return true;
    }

    void stop() {
        if (!m_running.exchange(false)) return;
        m_qcv.notify_all();
        if (m_verify_thread.joinable()) m_verify_thread.join();
        if (m_maint_thread.joinable()) m_maint_thread.join();
        m_net.stop();
    }

    u16 listen_port() const { return m_net.listen_port(); }
    u64 node_nonce() const { return m_nonce; }
    const RelayOptions& options() const { return m_o; }
    const RelayStats& stats() const { return m_st; }
    ::c2pool::v37n::FrameVault& vault() { return m_vault; }
    SupplyRequester* requester() { return m_fetch.get(); }

    // ── own receipts (any thread; the minter already ran check_structural) ──
    void submit_own(Admitted a) {
        a.own = true;
        {
            std::lock_guard<std::mutex> lk(m_mtx);
            if (m_cache.count(a.id)) { m_st.dup++; return; }
            cache_put_locked(a);
            unpushed_note_locked(a.id);
            m_inflight.erase(a.id);
        }
        m_st.admitted_own++;
        flood(a.raw, 0);
        std::lock_guard<std::mutex> lk(m_amtx);
        m_admitted.push_back(std::move(a));
    }

    // ── ★ DROPS: an own RAINDROP (any thread; the minter already ran
    // check_structural and knows the RandomX hash). Flooded like a share, queued
    // for drain_drops(), never cached / pushed / served in a repair order.
    void submit_own_drop(Admitted a) {
        if (!m_o.drops_floor_diff) return;               // gate OFF: unreachable
        a.own = true; a.drop = true;
        if (!drop_note_new(a.id)) { m_st.drops_dup++; return; }
        m_st.drops_own++;
        flood(a.raw, 0);
        std::lock_guard<std::mutex> lk(m_amtx);
        m_drops.push_back(std::move(a));
    }
    // ── main thread: the raindrops admitted since the last call ─────────────
    std::vector<Admitted> drain_drops() {
        std::lock_guard<std::mutex> lk(m_amtx);
        std::vector<Admitted> out;
        out.swap(m_drops);
        return out;
    }

    // ── main thread: drain what was admitted since the last call ────────────
    std::vector<Admitted> drain_admitted() {
        std::lock_guard<std::mutex> lk(m_amtx);
        std::vector<Admitted> out;
        out.swap(m_admitted);
        return out;
    }

    // ── main thread: a receipt reloaded from our own durable log (verified by
    // us before) re-enters the dedup set + cache without re-hashing.
    void note_reloaded(const Admitted& a) {
        std::lock_guard<std::mutex> lk(m_mtx);
        if (!m_cache.count(a.id)) cache_put_locked(a);
    }

    // ── main thread: after the ingest pushed a receipt into the live lane ───
    void on_pushed(const bytes32& id, u64 pos_first, u32 n_pushes, const std::vector<u8>& raw,
                   u64 next_after, const bytes32& digest_after) {
        (void)m_vault.insert(m_o.chain, id, pos_first, n_pushes, raw);
        {
            std::lock_guard<std::mutex> lk(m_mtx);
            m_unpushed.erase(id);   // REPAIR-HORIZON: in the lane now -> the GETORDER backfill covers it
        }
        std::lock_guard<std::mutex> lk(m_dmtx);
        m_pos_digest[next_after] = digest_after;
        const u64 horizon = m_o.vault.horizon_positions ? m_o.vault.horizon_positions : 8640;
        while (!m_pos_digest.empty() && m_pos_digest.begin()->first + horizon + 1 < next_after)
            m_pos_digest.erase(m_pos_digest.begin());
    }
    // REPAIR-HORIZON: the digests of the last winner-side order this node
    // reconstructed (RepairReplayer's SHADOW, xmr_repair_replay.hpp) -- a
    // prefix probe also accepts a peer whose digest at a0 equals one of these,
    // so the winner-side order chains from repair to repair past the horizon.
    void note_alt_digests(const std::multimap<u64, bytes32>& d) {
        std::lock_guard<std::mutex> lk(m_dmtx);
        m_alt_digest = d;
    }
    bool alt_digest_is(u64 pos, const bytes32& d) const {
        std::lock_guard<std::mutex> lk(m_dmtx);
        auto [b, e] = m_alt_digest.equal_range(pos);
        for (auto it = b; it != e; ++it) if (it->second == d) return true;
        return false;
    }
    bool alt_digest_known(u64 pos) const {
        std::lock_guard<std::mutex> lk(m_dmtx);
        return m_alt_digest.count(pos) != 0;
    }
    // Our recorded lane digest at position `pos` (the spine probe's answer).
    std::optional<bytes32> digest_at(u64 pos) const {
        std::lock_guard<std::mutex> lk(m_dmtx);
        auto it = m_pos_digest.find(pos);
        if (it == m_pos_digest.end()) return std::nullopt;
        return it->second;
    }

    // ── verified cache lookup (main thread, for a repair replay) ────────────
    // `give_author` = the u16 the receipt carries in its PoW-committed
    // side_data_v2 (fee model S3: the repair replay splits by it).
    bool cached(const bytes32& id, ::v37::ScriptRef* payee = nullptr, u16* give_author = nullptr) const {
        std::lock_guard<std::mutex> lk(m_mtx);
        auto it = m_cache.find(id);
        if (it == m_cache.end()) return false;
        if (payee) *payee = it->second.payee;
        if (give_author) *give_author = it->second.give_author;
        return true;
    }
    bool known(const bytes32& id) const {
        std::lock_guard<std::mutex> lk(m_mtx);
        return m_cache.count(id) != 0;
    }
    std::size_t cache_size() const { std::lock_guard<std::mutex> lk(m_mtx); return m_cache.size(); }

    // ── block-winner fast path ──────────────────────────────────────────────
    std::size_t broadcast_block_won(const BlockWon& b) {
        {
            std::lock_guard<std::mutex> lk(m_bmtx);
            m_seen_bids.insert(b.bid);
        }
        const auto f = encode_block_won(b);
        remember_won_frame(f);   // ENROL-REPL (DROPS only): re-offered to a peer that HELLOs later
        std::size_t n = 0;
        for (PeerId p : ready_peers()) if (m_net.send_to(p, f)) ++n;
        m_st.block_won_tx++;
        return n;
    }
    std::vector<std::pair<BlockWon, PeerId>> drain_block_won() {
        std::lock_guard<std::mutex> lk(m_bmtx);
        std::vector<std::pair<BlockWon, PeerId>> out;
        out.swap(m_won);
        return out;
    }
    PeerId peer_of_bid(const bytes32& bid) const {
        std::lock_guard<std::mutex> lk(m_bmtx);
        auto it = m_bid_peer.find(bid);
        return it == m_bid_peer.end() ? 0 : it->second;
    }

    // ── peers ───────────────────────────────────────────────────────────────
    std::vector<PeerId> ready_peers() const {
        std::lock_guard<std::mutex> lk(m_pmtx);
        std::vector<PeerId> v;
        for (const auto& [p, s] : m_peers) if (s.hello_ok) v.push_back(p);
        return v;
    }
    std::size_t n_connections() const { return m_net.n_peers(); }
    bool hello_ok(PeerId p) const {
        std::lock_guard<std::mutex> lk(m_pmtx);
        auto it = m_peers.find(p);
        return it != m_peers.end() && it->second.hello_ok;
    }
    std::optional<Hello> remote_hello(PeerId p) const {
        std::lock_guard<std::mutex> lk(m_pmtx);
        auto it = m_peers.find(p);
        if (it == m_peers.end() || !it->second.hello_ok) return std::nullopt;
        return it->second.remote;
    }
    Hello our_hello() const {
        Hello h;
        h.network = m_o.network; h.chain_id = m_o.chain; h.lane_params_digest = m_o.lane_params_digest;
        h.share_diff = m_o.share_diff; h.node_nonce = m_nonce; h.listen_port = m_net.listen_port();
        h.bind = m_o.bind; h.pool = m_o.pool_id;
        if (m_tip) { const auto t = m_tip(); h.lane_next_pos = t.first; h.lane_digest = t.second; }
        return h;
    }

    // ── REPAIR: the winner-side order over [0, P) whose digest at P is `spine`
    // Pending = in flight (the caller answers cut-pending and retries);
    // Ready = `ids` (the positions [repair_a0(), P), in the serving peer's lane
    // order; repair_a0() == 0 unless a peer's vault horizon forced a suffix) are
    // all in the verified cache; Exhausted = every connected peer was asked and none could
    // serve it (the caller keeps retrying; a new peer or a new tip may fix it).
    RepairState repair_poll(u64 P, const bytes32& spine, PeerId hint, std::vector<bytes32>* ids) {
        std::unique_lock<std::mutex> lk(m_rmtx);
        auto key = std::make_pair(P, spine);
        auto it = m_repairs.find(key);
        if (it == m_repairs.end()) {
            Repair r; r.P = P; r.spine = spine; r.hint = hint; r.since = Clock::now();
            it = m_repairs.emplace(key, std::move(r)).first;
            m_st.repair_started++;
            // bounded: evict the LEAST RECENTLY POLLED repair (the pre-fix code
            // evicted the smallest P -- the oldest, still-needed booking)
            while (m_repairs.size() > 64) {
                auto victim = m_repairs.end();
                for (auto vi = m_repairs.begin(); vi != m_repairs.end(); ++vi)
                    if (vi->first != key && (victim == m_repairs.end() || vi->second.polled < victim->second.polled)) victim = vi;
                if (victim == m_repairs.end()) break;
                m_repairs.erase(victim);
                m_st.repair_evicted++;
            }
            it = m_repairs.find(key);
            if (it == m_repairs.end()) return RepairState::Pending;
        }
        Repair& r = it->second;
        r.polled = Clock::now();
        if (hint && !r.hint) r.hint = hint;
        if (r.st == Repair::St::Fetching) {
            std::size_t missing = 0;
            {
                std::lock_guard<std::mutex> ck(m_mtx);
                for (const auto& id : r.ids) if (!m_cache.count(id)) ++missing;
            }
            if (!missing) { r.st = Repair::St::Ready; m_st.repair_ready++; }
        }
        if (r.st == Repair::St::Ready) { if (ids) *ids = r.ids; return RepairState::Ready; }
        const bool exhausted = (r.st == Repair::St::Idle && r.exhausted);
        lk.unlock();
        drive_repairs();
        return exhausted ? RepairState::Exhausted : RepairState::Pending;
    }
    // The replay of a Ready order did NOT reproduce `spine` (the serving peer
    // lied, or served a different lane): forget it and ask someone else.
    void repair_reject(u64 P, const bytes32& spine) {
        std::lock_guard<std::mutex> lk(m_rmtx);
        auto it = m_repairs.find(std::make_pair(P, spine));
        if (it == m_repairs.end()) return;
        Repair& r = it->second;
        if (r.served_by) {
            r.tried.insert(r.served_by);
            // REPAIR-HORIZON: a suffix order [a0, P) the peer asserted reaches the
            // spine, replayed after OUR [0, a0), did not: our prefix differs.
            if (r.a0) { r.deep[r.served_by] = r.a0; m_st.repair_deep++; }
        }
        r.reset();
        m_st.repair_rejected++;
    }
    std::size_t repairs_open() const { std::lock_guard<std::mutex> lk(m_rmtx); return m_repairs.size(); }
    // REPAIR-HORIZON: the first lane position the Ready order covers. 0 = the
    // whole order [0, P) (ids = P positions); a0 > 0 = the serving peer's vault
    // horizon: ids cover [a0, P) and the caller replays its OWN first a0 lane
    // pushes before them (the peer's digest at a0 matched ours, or was unknown;
    // the digest gate at P decides either way).
    u64 repair_a0(u64 P, const bytes32& spine, std::optional<bytes32>* peer_digest_at_a0 = nullptr) const {
        std::lock_guard<std::mutex> lk(m_rmtx);
        auto it = m_repairs.find(std::make_pair(P, spine));
        if (it == m_repairs.end() || it->second.st == Repair::St::Idle) return 0;
        if (peer_digest_at_a0 && it->second.has_a0_digest) *peer_digest_at_a0 = it->second.a0_digest;
        return it->second.a0;
    }
    // REPAIR-HORIZON: every ready peer was tried and at least one of them
    // proved (prefix probe or a failed [a0, P) replay) that our order diverges
    // from the winner's BELOW its vault horizon -- no connected peer can serve
    // the repair. `a0` = the lowest such horizon. Undecided (the caller HOLDS
    // and alarms); a peer with a longer vault, or a new peer, may still serve.
    bool repair_deep_divergence(u64 P, const bytes32& spine, u64* a0 = nullptr) const {
        std::lock_guard<std::mutex> lk(m_rmtx);
        auto it = m_repairs.find(std::make_pair(P, spine));
        if (it == m_repairs.end() || it->second.deep.empty() || !(it->second.st == Repair::St::Idle && it->second.exhausted)) return false;
        if (a0) { u64 lo = ~0ull; for (const auto& [p, v] : it->second.deep) { (void)p; lo = std::min(lo, v); } *a0 = lo; }
        return true;
    }

    // What a repair is waiting on, in words (the caller's cut-pending reason, so
    // a stall that reaches the booking retry bound names its stuck stage).
    std::string repair_status(u64 P, const bytes32& spine) const {
        std::string s;
        std::vector<bytes32> idle_ids;
        {
            std::lock_guard<std::mutex> lk(m_rmtx);
            auto it = m_repairs.find(std::make_pair(P, spine));
            if (it == m_repairs.end()) return "not started";
            const Repair& r = it->second;
            const auto age = [&](Clock::time_point t) { return std::to_string(std::chrono::duration_cast<std::chrono::seconds>(Clock::now() - t).count()) + "s"; };
            switch (r.st) {
                case Repair::St::Idle:
                    s = r.exhausted ? "idle: every ready peer tried (" + std::to_string(r.tried.size()) + "), none serves an order reaching this spine"
                                    : "idle: waiting for a ready peer";
                    if (!r.deep.empty()) {   // REPAIR-HORIZON: the loud, named outcome
                        s += "; DEEP-DIVERGENCE: our lane order differs from the winner's BELOW the vault horizon of " +
                             std::to_string(r.deep.size()) + " peer(s) (";
                        bool first = true;
                        for (const auto& [p, a] : r.deep) { s += (first ? "" : ", ") + std::string("peer ") + std::to_string(p) + " a0=" + std::to_string(a); first = false; }
                        s += ") -- no connected peer retains the divergent positions";
                    }
                    break;
                case Repair::St::Ordering:
                    s = std::string(r.probing ? "probing the prefix digest at a0=" + std::to_string(r.a0) + " of peer " : "ordering from peer ") +
                        std::to_string(r.cur) + " (" + std::to_string(r.cursor) + "/" + std::to_string(P) + " ids" +
                        (r.a0 ? ", from a0=" + std::to_string(r.a0) : std::string()) + ", " + age(r.since) + ")";
                    break;
                case Repair::St::Ready: s = "ready"; break;
                case Repair::St::Fetching: {
                    std::size_t missing = 0, verifying = 0;
                    std::lock_guard<std::mutex> ck(m_mtx);
                    for (const auto& id : r.ids) {
                        if (m_cache.count(id)) continue;
                        ++missing;
                        if (m_inflight.count(id)) ++verifying; else idle_ids.push_back(id);
                    }
                    s = "fetching: " + std::to_string(missing) + "/" + std::to_string(r.ids.size()) + " receipts missing" +
                        (r.a0 ? " of [" + std::to_string(r.a0) + "," + std::to_string(P) + ")" : std::string()) + " (" +
                        std::to_string(verifying) + " in verify, " + std::to_string(idle_ids.size()) + " to re-ask; order from peer " +
                        std::to_string(r.served_by) + ", refetches=" + std::to_string(r.refetches) + ", last progress " + age(r.last_progress) + " ago)";
                    break;
                }
            }
        }
        {
            std::lock_guard<std::mutex> lk(m_cmtx);
            std::size_t pending = 0; std::string first;
            for (const auto& [id, w] : m_ctx_want) {
                if (w.have_proof) continue;
                ++pending;
                if (first.empty()) first = hex_short(id) + " asked of " + std::to_string(w.asked_total) + " peer(s), round " + std::to_string(w.rounds);
            }
            if (pending)
                s += "; " + std::to_string(pending) + " Monero context(s) unresolved (prev_id " + first + ")";
        }
        const std::string lu = last_unresolved();
        if (!lu.empty()) s += "; last unresolved: " + lu;
        return s;
    }

    // ── receipt CONTEXT (FB_GETCTX / FB_CTX) ──────────────────────────────────
    // Main thread, the SERVING side: GETCTX requests peers sent us. The daemon
    // answers each id with send_ctx() (the block blob from its native node's
    // retained bodies -- xmr_relay_native_ctx.hpp -- or, on the daemon arm, its
    // monerod's get_block; empty = unknown here). Bounded; a daemon that never drains simply never serves.
    std::vector<std::pair<PeerId, std::vector<bytes32>>> drain_ctx_requests() {
        std::lock_guard<std::mutex> lk(m_cmtx);
        std::vector<std::pair<PeerId, std::vector<bytes32>>> out(m_ctx_serve.begin(), m_ctx_serve.end());
        m_ctx_serve.clear();
        return out;
    }
    bool send_ctx(PeerId p, const bytes32& id, const std::vector<u8>& blob) {
        const auto f = encode_ctx(m_o.chain, id, blob);
        if (f.empty() || !m_net.send_to(p, f)) return false;
        if (blob.empty()) m_st.ctx_unknown_tx++; else m_st.ctx_served++;
        return true;
    }
    // Main thread, the ASKING side: prev_ids we want that our OWN monerod has
    // not been asked for yet (it may hold the block as an alternative). Each id
    // is handed out once per 10 s.
    std::vector<bytes32> ctx_wants_local() {
        std::lock_guard<std::mutex> lk(m_cmtx);
        std::vector<bytes32> out;
        const auto now = Clock::now();
        for (auto& [id, w] : m_ctx_want) {
            if (w.have_proof) continue;
            if (w.local_tried != Clock::time_point{} && now - w.local_tried < std::chrono::seconds(10)) continue;
            w.local_tried = now;
            out.push_back(id);
        }
        return out;
    }
    // A block blob for a wanted id, from a peer (FB_CTX) or our own monerod
    // (from == 0). Verified here; never trusted.
    void offer_ctx(const bytes32& id, const std::vector<u8>& blob, PeerId from) {
        {
            std::lock_guard<std::mutex> lk(m_cmtx);
            auto it = m_ctx_want.find(id);
            if (it == m_ctx_want.end() || it->second.have_proof) return;   // not ours to resolve (or already have it)
            if (blob.empty()) {
                if (from) { m_st.ctx_unknown_rx++; it->second.last_ask = Clock::time_point{}; }   // "unknown here": ask the next peer now
                return;
            }
        }
        BlockCtx bc; std::string why;
        if (!verify_block_ctx(id, blob, bc, &why)) {
            m_st.ctx_bad++;
            log("relay: context for " + hex_short(id) + " from " + (from ? "peer " + std::to_string(from) : std::string("own monerod")) +
                " REJECTED: " + why);
            if (from) strike(from, why);
            return;
        }
        {
            std::lock_guard<std::mutex> lk(m_cmtx);
            auto it = m_ctx_want.find(id);
            if (it == m_ctx_want.end()) return;
            it->second.have_proof = true; it->second.proof = bc; it->second.proof_from = from;
        }
        resolve_ctx_chain(id);
    }
    std::size_t ctx_wants_open() const { std::lock_guard<std::mutex> lk(m_cmtx); return m_ctx_want.size(); }

    std::string describe() const {
        const auto& s = m_st;
        char b[2400];
        std::snprintf(b, sizeof b,
            "relay: conns=%zu ready=%zu hello ok=%llu rej=%llu tmo=%llu | rx recv=%llu dup=%llu struct=%llu "
            "rx_evals=%llu valid=%llu invalid=%llu deferred=%llu unavail=%llu bans=%llu unresolved=%llu expired=%llu qdrop=%llu | "
            "admitted own=%llu foreign=%llu solicited=%llu cache=%zu | flood=%llu reoffer=%llu backfill orders=%llu ids=%llu | "
            "won tx=%llu rx=%llu | repair start=%llu order_ok=%llu spine_mis=%llu peer_fail=%llu ids=%llu ready=%llu rejected=%llu open=%zu | "
            "fa_ignored=%llu fb_unknown=%llu malformed=%llu pre_hello=%llu | "
            "ctx want=%zu wanted=%llu asked=%llu rx=%llu resolved=%llu bad=%llu unknown_rx=%llu gave_up=%llu served=%llu unknown_tx=%llu | "
            "repair refetch=%llu evicted=%llu upgraded=%llu unresolved_solicited=%llu | pool-id tag_mismatch=%llu | "
            "repair-horizon rearm=%llu prefix_ok=%llu prefix_unknown=%llu deep=%llu reoffer_unpushed=%llu | "
            "liveness keepalive=%ums silence=%ums ping tx=%llu rx=%llu pong tx=%llu rx=%llu silent_drops=%llu legacy=%llu rearm=%llu",
            m_net.n_peers(), ready_peers().size(),
            (unsigned long long)s.hello_ok.load(), (unsigned long long)s.hello_rejected.load(), (unsigned long long)s.hello_timeout.load(),
            (unsigned long long)s.rx_receipts.load(), (unsigned long long)s.dup.load(), (unsigned long long)s.structural.load(),
            (unsigned long long)s.rx_evals.load(), (unsigned long long)s.rx_valid.load(), (unsigned long long)s.rx_invalid.load(),
            (unsigned long long)s.rx_deferred.load(), (unsigned long long)s.rx_unavailable.load(), (unsigned long long)s.bans.load(),
            (unsigned long long)s.unresolved_dropped.load(), (unsigned long long)s.expired.load(), (unsigned long long)s.queue_dropped.load(),
            (unsigned long long)s.admitted_own.load(), (unsigned long long)s.admitted_foreign.load(), (unsigned long long)s.admitted_solicited.load(),
            cache_size(),
            (unsigned long long)s.flood_frames.load(), (unsigned long long)s.reoffer_frames.load(),
            (unsigned long long)s.backfill_orders.load(), (unsigned long long)s.backfill_ids_asked.load(),
            (unsigned long long)s.block_won_tx.load(), (unsigned long long)s.block_won_rx.load(),
            (unsigned long long)s.repair_started.load(), (unsigned long long)s.repair_order_ok.load(),
            (unsigned long long)s.repair_spine_mismatch.load(), (unsigned long long)s.repair_peer_fail.load(),
            (unsigned long long)s.repair_ids_asked.load(), (unsigned long long)s.repair_ready.load(),
            (unsigned long long)s.repair_rejected.load(), repairs_open(),
            (unsigned long long)s.fa_ignored.load(), (unsigned long long)s.fb_unknown.load(),
            (unsigned long long)s.malformed.load(), (unsigned long long)s.pre_hello_dropped.load(),
            ctx_wants_open(), (unsigned long long)s.ctx_wanted.load(), (unsigned long long)s.ctx_asked.load(),
            (unsigned long long)s.ctx_rx.load(), (unsigned long long)s.ctx_resolved.load(), (unsigned long long)s.ctx_bad.load(),
            (unsigned long long)s.ctx_unknown_rx.load(), (unsigned long long)s.ctx_gave_up.load(),
            (unsigned long long)s.ctx_served.load(), (unsigned long long)s.ctx_unknown_tx.load(),
            (unsigned long long)s.repair_refetch.load(), (unsigned long long)s.repair_evicted.load(),
            (unsigned long long)s.upgraded_solicited.load(), (unsigned long long)s.unresolved_solicited_dropped.load(),
            (unsigned long long)s.hello_tag_mismatch.load(),
            (unsigned long long)s.repair_horizon_rearm.load(), (unsigned long long)s.repair_prefix_ok.load(),
            (unsigned long long)s.repair_prefix_unknown.load(), (unsigned long long)s.repair_deep.load(),
            (unsigned long long)s.reoffer_unpushed.load(),
            m_o.keepalive_ms, m_o.silence_timeout_ms,
            (unsigned long long)s.ping_tx.load(), (unsigned long long)s.ping_rx.load(),
            (unsigned long long)s.pong_tx.load(), (unsigned long long)s.pong_rx.load(),
            (unsigned long long)s.silent_drops.load(), (unsigned long long)s.ka_legacy.load(),
            (unsigned long long)s.ka_rearm.load());
        return b;
    }
    std::string last_reject() const { std::lock_guard<std::mutex> lk(m_mtx); return m_last_reject; }
    std::string last_unresolved() const { std::lock_guard<std::mutex> lk(m_mtx); return m_last_unresolved; }

    // Test hook: disconnect one peer (the KAT's "B drops off the network").
    void drop_peer(PeerId p) { m_net.disconnect(p); }
    // Test hook: stop redialing (and drop) every dial target.
    void set_dialing(bool on) { m_dialing = on; }
    // Test hook (UP-GATE KAT): hold every connection-up event of this node for
    // `ms` before it is handled (0 = off), so a remote HELLO reaches this
    // node's reader BEFORE its own HELLO goes out -- deterministically.
    void set_test_up_delay_ms(u32 ms) { m_test_up_delay_ms = ms; }
    // Rig hook (SIGUSR1 in the daemon): a NETWORK PARTITION of `secs` seconds --
    // every relay connection is dropped, inbound connections are refused and
    // nothing is dialed until it ends; then the node redials and backfills.
    // The node keeps mining/minting meanwhile, so its lane order diverges and
    // the reconnect exercises re-offer + GETORDER/GETFRAMES + the repair.
    void partition_for(std::chrono::seconds secs) {
        m_partition_until.store(Clock::now().time_since_epoch().count() +
                                std::chrono::duration_cast<Clock::duration>(secs).count());
        m_partitioned = true;
        m_dialing = false;
        for (PeerId p : m_net.peer_ids()) m_net.disconnect(p);
        log("relay: PARTITION for " + std::to_string(secs.count()) + " s (all relay links dropped)");
    }

private:
    // ── state ───────────────────────────────────────────────────────────────
    struct PeerSt {
        bool hello_ok = false;
        bool hello_sent = false;
        Clock::time_point connected = Clock::now();
        Hello remote{};
        // RELAY-LIVENESS
        Clock::time_point last_rx = Clock::now();   // any frame from this link
        Clock::time_point last_ping{};              // our last PING on it (epoch = ping at once)
        bool ka = false;                            // the peer answered / sent a PING on THIS link
        u32  unanswered = 0;                        // PINGs sent while !ka
        bool legacy_noted = false;
    };
    static constexpr u32 kLegacyProbes = 3;         // unanswered PINGs before a peer counts as pre-0x45
    struct Target {
        std::string host; u16 port = 0; PeerId pid = 0;
        Clock::time_point next_try; int backoff_s = 1;
        // SMOKE-NOISE: links of this target that ended BEFORE a HELLO was
        // accepted (refused at once by a partitioned peer, or a HELLO timeout
        // on a silent one). `backoff_s` above only covers connect(2) failing;
        // a connect that SUCCEEDS reset it to 1, so a refusing / silent peer
        // was redialed (and, if silent, re-timed-out) every ~1 s forever.
        u32  prehello_fails = 0;
        bool hello_seen = false;       // the current link reached HELLO ok
        bool hello_timed_out = false;  // the current link hit the HELLO timeout
    };
    static constexpr int kRefusedBackoffCapS = 16;
    static constexpr int kSilentBackoffCapS  = 60;
    // SMOKE-NOISE redial delay after the current link of `t` went down.
    //   HELLO ok on it     -> 1 s (the old behaviour; a healthy link that drops)
    //   refused pre-HELLO  -> 1, 1, 2, 4, 8, 16, 16 ... s   (heal within 16 s)
    //   HELLO timeout      -> counts twice, cap 60 s: 2, 8, 32, 60 ... s
    //                         (a silent peer costs <= ~1 HELLO timeout / min)
    static int prehello_delay_s(Target& t) {
        if (t.hello_seen) { t.prehello_fails = 0; return 1; }
        t.prehello_fails += t.hello_timed_out ? 2u : 1u;
        const int cap = t.hello_timed_out ? kSilentBackoffCapS : kRefusedBackoffCapS;
        if (t.prehello_fails <= 1) return 1;
        const u32 sh = std::min<u32>(t.prehello_fails - 1, 6);
        return std::min(cap, 1 << sh);
    }
    struct Item {
        PeerId from = 0;
        FbReceipt r;
        std::vector<u8> raw;
        bytes32 id{};
        bool solicited = false;
        Clock::time_point enq = Clock::now();
        Clock::time_point not_before = Clock::now();
    };
    struct CacheEntry { ::v37::ScriptRef payee; std::vector<u8> raw; u64 bin = 0; u16 give_author = 0; };
    struct Job {
        enum class Kind { Order, Frames } kind = Kind::Order;
        bool repair = false;
        std::pair<u64, bytes32> key{};
        u64 a = 0, p = 0;
        bytes32 spine{};
        std::vector<bytes32> ids;
        bool probe = false;   // REPAIR-HORIZON: the zero-length prefix probe GETORDER [a0, a0)
    };
    struct Repair {
        enum class St { Idle, Ordering, Fetching, Ready } st = St::Idle;
        u64 P = 0; bytes32 spine{};
        PeerId hint = 0, cur = 0, served_by = 0;
        std::set<PeerId> tried;
        std::vector<bytes32> ids;
        u64 cursor = 0;
        bool exhausted = false;
        // REPAIR-HORIZON: per-peer start (that peer's vault lowest_retained, 0 =
        // the whole order), the start of the order in flight / served, whether
        // the in-flight ask is the prefix probe, the peer whose BELOW_HORIZON
        // answer re-armed the repair (not set aside), and the peers proven DEEP.
        std::map<PeerId, u64> a0_of;
        u64 a0 = 0;
        bool probing = false;
        bytes32 a0_digest{}; bool has_a0_digest = false;   // the serving peer's digest at a0 (probe answer)
        PeerId rearm = 0, prefer = 0;
        std::map<PeerId, u64> deep;
        Clock::time_point since = Clock::now();
        // Fetching: progress + refetch bookkeeping
        Clock::time_point last_progress = Clock::now(), last_fetch = Clock::now(), polled = Clock::now();
        std::size_t cached_seen = 0;
        std::set<PeerId> fetch_tried;
        u32 refetches = 0;
        void reset() {
            st = St::Idle; ids.clear(); cursor = 0; cur = 0; served_by = 0; since = Clock::now();
            a0 = 0; probing = false; has_a0_digest = false;
            cached_seen = 0; fetch_tried.clear(); refetches = 0;
        }
    };
    struct CtxWant {
        PeerId from = 0;                   // the peer whose receipt needs it (asked first)
        u32 depth = 0;                     // 0 = a receipt's prev_id; n = n-th unknown ancestor
        std::set<PeerId> asked;            // this round
        u32 asked_total = 0, rounds = 0;
        Clock::time_point since = Clock::now(), last_ask{}, local_tried{};
        bool have_proof = false;
        BlockCtx proof{};
        PeerId proof_from = 0;
    };
    static std::string hex_short(const bytes32& b) {
        static const char* d = "0123456789abcdef";
        std::string s; for (int i = 0; i < 6; ++i) { s.push_back(d[b[i] >> 4]); s.push_back(d[b[i] & 15]); } return s + "…";
    }

    static ::c2pool::xmr::nanos_t now_ns() {
        return std::chrono::duration_cast<std::chrono::nanoseconds>(Clock::now().time_since_epoch()).count();
    }
    void log(const std::string& s) { if (m_log) m_log(s); }

    // REPAIR-HORIZON (open bin): admitted receipts not yet pushed into our lane
    // (bounded FIFO; on_pushed erases). Guarded by m_mtx.
    static constexpr std::size_t kUnpushedMax = 8192;
    void unpushed_note_locked(const bytes32& id) {
        if (!m_unpushed.insert(id).second) return;
        m_unpushed_order.push_back(id);
        while (m_unpushed_order.size() > kUnpushedMax ||
               (!m_unpushed_order.empty() && !m_unpushed.count(m_unpushed_order.front()))) {
            m_unpushed.erase(m_unpushed_order.front());
            m_unpushed_order.pop_front();
        }
    }

    void cache_put_locked(const Admitted& a) {
        CacheEntry e; e.payee = a.r.payee; e.raw = a.raw; e.bin = a.bin; e.give_author = a.r.side.give_author;
        m_cache.emplace(a.id, std::move(e));
        m_cache_order.push_back(a.id);
        while (m_cache_order.size() > m_o.cache_max) { m_cache.erase(m_cache_order.front()); m_cache_order.pop_front(); }
        m_recent.emplace_back(Clock::now(), a.id);
        const auto horizon = std::chrono::seconds(m_o.reoffer_seconds);
        while (!m_recent.empty() && (Clock::now() - m_recent.front().first > horizon || m_recent.size() > 4096))
            m_recent.pop_front();
    }

    // ── transport callbacks ─────────────────────────────────────────────────
    void on_peer_event(PeerId p, bool up) {
        if (up) {
            if (const u32 d = m_test_up_delay_ms.load()) std::this_thread::sleep_for(std::chrono::milliseconds(d));
            on_peer_up(p);
            open_up_gate(p);   // UP-GATE: whatever path the up event took, a waiting HELLO may go on
            return;
        }
        {
            std::lock_guard<std::mutex> lk(m_pmtx);
            m_peers.erase(p);
            m_up_done.erase(p);
        }
        on_peer_down(p);
    }

    // -- UP-GATE ---------------------------------------------------------------
    // The transport starts a connection's reader thread BEFORE it fires the up
    // event (carrier_net add_established), so the remote HELLO can be read and
    // handled before on_peer_up() registered the peer and sent OUR HELLO:
    //   same pool  -> on_hello found no peer entry and DROPPED the HELLO; the
    //                 link sat until the HELLO timeout and was redialed (a
    //                 second HELLO completed for the same neighbour)
    //   other pool -> we refused and dropped the link before our HELLO went
    //                 out: the remote never saw our tag and logged no
    //                 TAG_MISMATCH for that dial ("refused in BOTH directions"
    //                 held only when the up event won the race)
    // on_hello therefore waits, on the reader thread (bounded), until the up
    // event is done with the link or the link is gone. The reader handles its
    // frames in order, so nothing that follows the HELLO overtakes it.
    static constexpr int kUpGateWaitMs = 2000;
    void open_up_gate(PeerId p) {
        {
            std::lock_guard<std::mutex> lk(m_pmtx);
            m_up_done.insert(p);
        }
        m_up_cv.notify_all();
        // The link already ended (its down event may have run BEFORE this up
        // event): nothing would erase the mark later. A reader still waiting
        // on this link sees it gone within one wait slice.
        if (!m_net.has_peer(p)) {
            std::lock_guard<std::mutex> lk(m_pmtx);
            m_up_done.erase(p);
        }
    }
    void wait_up_gate(PeerId p) {
        const auto dl = Clock::now() + std::chrono::milliseconds(kUpGateWaitMs);
        std::unique_lock<std::mutex> lk(m_pmtx);
        while (!m_up_done.count(p) && Clock::now() < dl) {
            m_up_cv.wait_for(lk, std::chrono::milliseconds(20));
            if (m_up_done.count(p)) break;
            lk.unlock();
            const bool gone = !m_net.has_peer(p);   // the transport lock is never taken under m_pmtx
            lk.lock();
            if (gone) break;
        }
    }

    void on_peer_up(PeerId p) {
        if (m_partitioned.load()) { m_net.disconnect(p); return; }   // rig partition: refuse
        {
            bool over = false;
            {
                std::lock_guard<std::mutex> lk(m_pmtx);
                m_peers[p] = PeerSt{};
                over = m_peers.size() > m_o.max_peers;
            }
            // RELAY-FD: the up event runs on the dialing/accepting thread AFTER
            // the connection's reader started. A peer that closes at once (a
            // partitioned node refusing us) can unwind that reader and fire the
            // DOWN event before this line ran; no second down event follows, so
            // the entry just made would be a ghost: never HELLO'd, re-counted
            // as a HELLO timeout every tick, and counted against max_peers
            // forever -- enough of them and every new link is over_cap, so the
            // relay never heals. Re-check the transport after inserting: a down
            // event that lands after this check erases the entry itself.
            if (!m_net.has_peer(p)) {
                std::lock_guard<std::mutex> lk(m_pmtx);
                m_peers.erase(p);
                return;
            }
            if (over) { m_st.over_cap++; m_net.disconnect(p); return; }
            const auto f = encode_hello(our_hello());
            if (m_net.send_to(p, f)) {
                m_st.hello_sent++;
                std::lock_guard<std::mutex> lk(m_pmtx);
                auto it = m_peers.find(p);
                if (it != m_peers.end()) it->second.hello_sent = true;
            }
        }
    }

    void on_peer_down(PeerId p) {
        {
            std::lock_guard<std::mutex> lk(m_mtx);
            m_dos.forget(static_cast<::c2pool::xmr::u32>(p));
        }
        {
            std::lock_guard<std::mutex> lk(m_jmtx);
            m_jobs.erase(p);
            m_cur_job.erase(p);
        }
        if (m_fetch) m_fetch->forget_peer(p);
        if (m_serve) m_serve->forget_peer(p);
        {
            std::lock_guard<std::mutex> lk(m_rmtx);
            for (auto& [k, r] : m_repairs) {
                (void)k;
                if (r.st == Repair::St::Ordering && r.cur == p) { r.tried.insert(p); r.reset(); }
                // Fetching keeps its order; frames asked of the dropped peer are
                // re-asked of another peer on the next maintenance tick.
                if (r.st == Repair::St::Fetching) { r.fetch_tried.insert(p); r.last_fetch = Clock::time_point{}; }
            }
        }
        {
            std::lock_guard<std::mutex> lk(m_tmtx);
            for (auto& t : m_targets) if (t.pid == p) {
                t.pid = 0;
                t.next_try = Clock::now() + std::chrono::seconds(prehello_delay_s(t));   // SMOKE-NOISE
                t.hello_seen = false; t.hello_timed_out = false;
            }
        }
    }

    void on_frame(PeerId p, const std::vector<u8>& f) {
        note_rx(p);   // RELAY-LIVENESS: any frame proves the link alive
        if (f.empty()) { m_st.malformed++; return; }
        const u8 op = f[0];
        if (op == FB_HELLO) { on_hello(p, f); return; }
        if (!is_family_b_opcode(op)) { m_st.fa_ignored++; return; }   // Family-A CarrierWire: count, keep socket
        if (!hello_ok(p)) { m_st.pre_hello_dropped++; return; }
        if (op == FB_RECEIPTS) { on_receipts(p, f); return; }
        if (op == FB_BLOCK_WON) { on_block_won(p, f); return; }
        if (op == FB_GETCTX) { on_getctx(p, f); return; }
        if (op == FB_CTX) { on_ctx(p, f); return; }
        if ((op == FB_PING || op == FB_PONG) && m_o.keepalive_ms) { on_ping(p, f); return; }
        m_st.fb_unknown++;                                            // a future 0x45..0x4f: count, keep socket
    }

    // ── RELAY-LIVENESS ──────────────────────────────────────────────────────
    void note_rx(PeerId p) {
        std::lock_guard<std::mutex> lk(m_pmtx);
        auto it = m_peers.find(p);
        if (it != m_peers.end()) it->second.last_rx = Clock::now();
    }
    void on_ping(PeerId p, const std::vector<u8>& f) {
        u8 op = 0; u64 nonce = 0; std::string why;
        if (!decode_ping(f, op, nonce, &why)) { m_st.malformed++; return; }
        {
            std::lock_guard<std::mutex> lk(m_pmtx);
            auto it = m_peers.find(p);
            if (it != m_peers.end()) { it->second.ka = true; it->second.unanswered = 0; }
        }
        if (op == FB_PONG) { m_st.pong_rx++; return; }
        m_st.ping_rx++;
        if (m_net.send_to(p, encode_ping(FB_PONG, nonce))) m_st.pong_tx++;
    }
    static std::string peer_label(PeerId p, const PeerSt& s, const std::map<PeerId, std::string>& dialed) {
        const std::string l = "peer " + std::to_string(p);
        auto it = dialed.find(p);
        if (it != dialed.end()) return l + " (" + it->second + ")";
        return l + " (inbound, listen=" + std::to_string(s.remote.listen_port) + ")";
    }
    // Maintenance thread, every tick: PING due links, drop SILENT ones.
    void drive_liveness() {
        if (!m_o.keepalive_ms) return;
        const auto now = Clock::now();
        // A maintenance gap far over the 250 ms tick = THIS process was not
        // running (SIGSTOP, a suspended VM): the peers' frames wait unread in
        // our socket buffers, so re-arm every clock instead of dropping them.
        const auto gap = now - m_live_tick;
        m_live_tick = now;
        const bool rearm = gap > std::chrono::milliseconds(std::max<u32>(2000, m_o.keepalive_ms));
        std::vector<PeerId> ping, silent;
        std::vector<std::string> msgs;
        std::map<PeerId, std::string> dialed;   // labels only; never m_tmtx under m_pmtx
        {
            std::lock_guard<std::mutex> lk(m_tmtx);
            for (const auto& t : m_targets) if (t.pid) dialed[t.pid] = t.host + ":" + std::to_string(t.port);
        }
        {
            std::lock_guard<std::mutex> lk(m_pmtx);
            if (rearm && !m_peers.empty()) {
                m_st.ka_rearm++;
                msgs.push_back("relay: liveness: maintenance paused " +
                               std::to_string(std::chrono::duration_cast<std::chrono::milliseconds>(gap).count()) +
                               " ms (this process was stopped?) -- every link's silence clock re-armed");
                for (auto& [p, s] : m_peers) { (void)p; s.last_rx = now; }
            }
            for (auto& [p, s] : m_peers) {
                if (!s.hello_ok) continue;
                const auto quiet = std::chrono::duration_cast<std::chrono::milliseconds>(now - s.last_rx).count();
                if (s.ka && m_o.silence_timeout_ms && quiet > static_cast<long long>(m_o.silence_timeout_ms)) {
                    silent.push_back(p);
                    msgs.push_back("relay: LINK SILENT -- " + peer_label(p, s, dialed) + " sent NOTHING for " +
                                   std::to_string(quiet) + " ms (silence timeout " + std::to_string(m_o.silence_timeout_ms) +
                                   " ms, keepalive " + std::to_string(m_o.keepalive_ms) +
                                   " ms) while the TCP session is still up: DROPPING the link and redialing (RELAY-LIVENESS)");
                    continue;
                }
                if (!s.ka && s.unanswered >= kLegacyProbes) {
                    if (!s.legacy_noted) {
                        s.legacy_noted = true;
                        m_st.ka_legacy++;
                        msgs.push_back("relay: liveness: " + peer_label(p, s, dialed) + " answered none of " +
                                       std::to_string(kLegacyProbes) + " PINGs (a pre-keepalive build?): its silence is NOT timed out");
                    }
                    continue;
                }
                if (now - s.last_ping >= std::chrono::milliseconds(m_o.keepalive_ms)) {
                    s.last_ping = now;
                    if (!s.ka) ++s.unanswered;
                    ping.push_back(p);
                }
            }
        }
        for (const auto& m : msgs) log(m);
        for (PeerId p : silent) { m_st.silent_drops++; m_net.disconnect(p); }
        for (PeerId p : ping) if (m_net.send_to(p, encode_ping(FB_PING, ++m_ping_nonce))) m_st.ping_tx++;
    }

    void on_hello(PeerId p, const std::vector<u8>& f) {
        wait_up_gate(p);   // UP-GATE: our own HELLO goes out (and the peer is registered) first
        Hello h; std::string why;
        if (!decode_hello(f, h, &why)) {
            m_st.hello_rejected++;
            log("relay: peer " + std::to_string(p) + " HELLO undecodable (" + why + ") -> drop");
            m_net.disconnect(p);
            return;
        }
        const std::string mis = hello_mismatch(our_hello(), h);
        if (!mis.empty()) {
            m_st.hello_rejected++;
            if (is_tag_mismatch(mis)) m_st.hello_tag_mismatch++;   // POOL-ID: another pool's node
            {
                std::lock_guard<std::mutex> lk(m_mtx);
                m_last_reject = "hello: " + mis;
            }
            log("relay: peer " + std::to_string(p) + " HELLO REFUSED: " + mis + " -> drop");
            m_net.disconnect(p);
            return;
        }
        bool first = false, need_send = false;
        {
            std::lock_guard<std::mutex> lk(m_pmtx);
            auto it = m_peers.find(p);
            if (it == m_peers.end()) return;
            first = !it->second.hello_ok;
            it->second.hello_ok = true;
            it->second.remote = h;
            need_send = !it->second.hello_sent;
            it->second.hello_sent = true;
        }
        if (need_send && m_net.send_to(p, encode_hello(our_hello()))) m_st.hello_sent++;
        if (!first) return;
        m_st.hello_ok++;
        {   // SMOKE-NOISE: a dial target whose link reached HELLO is healthy again
            std::lock_guard<std::mutex> lk(m_tmtx);
            for (auto& t : m_targets) if (t.pid == p) { t.hello_seen = true; t.prehello_fails = 0; }
        }
        log("relay: peer " + std::to_string(p) + " HELLO ok (lane next_pos=" + std::to_string(h.lane_next_pos) +
            " listen=" + std::to_string(h.listen_port) + ")");
        reoffer_to(p);
        reoffer_won_to(p);   // ENROL-REPL (DROPS only; a no-op at flip 0)
        if (h.lane_next_pos > 0) {
            Job j; j.kind = Job::Kind::Order; j.repair = false;
            j.p = h.lane_next_pos;
            j.a = h.lane_next_pos > m_o.backfill_positions ? h.lane_next_pos - m_o.backfill_positions : 0;
            queue_job(p, std::move(j));
            m_st.backfill_orders++;
        }
    }

    void reoffer_to(PeerId p) {
        std::vector<std::vector<u8>> raws;
        {
            std::lock_guard<std::mutex> lk(m_mtx);
            const auto horizon = std::chrono::seconds(m_o.reoffer_seconds);
            std::unordered_set<bytes32, Bytes32Hash> sent;
            for (const auto& [t, id] : m_recent) {
                if (Clock::now() - t > horizon) continue;
                auto it = m_cache.find(id);
                if (it != m_cache.end() && sent.insert(id).second) raws.push_back(it->second.raw);
            }
            // REPAIR-HORIZON (open bin): every admitted receipt our lane has not
            // pushed yet -- an OPEN bin's receipts, however old -- is invisible to
            // the peer's GETORDER backfill (it covers pushed positions only) and,
            // past reoffer_seconds, to the window above: re-offer it too, so a bin
            // that stayed open across a relay stall closes with the same set on
            // both sides instead of recovering the missing receipts only 'late'.
            for (const auto& id : m_unpushed_order) {
                if (!m_unpushed.count(id) || sent.count(id)) continue;
                auto it = m_cache.find(id);
                if (it == m_cache.end()) continue;
                sent.insert(id);
                raws.push_back(it->second.raw);
                m_st.reoffer_unpushed++;
            }
        }
        for (std::size_t i = 0; i < raws.size(); i += kFbMaxReceiptsPerFrame) {
            std::vector<const std::vector<u8>*> v;
            for (std::size_t k = i; k < raws.size() && k < i + kFbMaxReceiptsPerFrame; ++k) v.push_back(&raws[k]);
            const auto f = encode_receipts_frame(m_o.chain, v);
            if (!f.empty() && m_net.send_to(p, f)) m_st.reoffer_frames++;
        }
    }

    void on_receipts(PeerId p, const std::vector<u8>& f) {
        ReceiptsFrame rf; std::string why;
        if (!decode_receipts_frame(f, rf, &why)) {
            m_st.malformed++;
            std::lock_guard<std::mutex> lk(m_mtx);
            m_last_reject = "frame: " + why;
            if (m_dos.on_cheap_reject(static_cast<::c2pool::xmr::u32>(p)) == ::c2pool::xmr::Action::Ban) {
                m_st.bans++;
                ban_later(p);
            }
            return;
        }
        if (rf.chain_id != m_o.chain) { m_st.wrong_chain++; return; }
        for (std::size_t i = 0; i < rf.receipts.size(); ++i) {
            m_st.rx_receipts++;
            Item it;
            it.from = p; it.r = std::move(rf.receipts[i]); it.raw = std::move(rf.raw[i]);
            it.id = receipt_id(it.r);
            enqueue(std::move(it));
        }
    }

    void on_block_won(PeerId p, const std::vector<u8>& f) {
        BlockWon b; std::string why;
        if (!decode_block_won(f, b, &why)) { m_st.malformed++; return; }
        if (b.chain_id != m_o.chain) { m_st.wrong_chain++; return; }
        bool fresh = false;
        {
            std::lock_guard<std::mutex> lk(m_bmtx);
            fresh = m_seen_bids.insert(b.bid).second;
            if (fresh) {
                m_bid_peer[b.bid] = p;
                m_won.emplace_back(b, p);
                if (m_won.size() > 256) m_won.erase(m_won.begin());
            }
        }
        if (!fresh) return;
        m_st.block_won_rx++;
        remember_won_frame(f);   // ENROL-REPL (DROPS only)
        for (PeerId q : ready_peers()) if (q != p) m_net.send_to(q, f);   // forward once (dedup by bid)
    }

    // ★ ENROL-REPL (DROPS, gate ON only): under the flip every node books a lane
    // block's DROPS credit from the winner's carried delta (FB_BLOCK_WON v0x02),
    // so a node that was not connected when the frame flooded (a late join, a
    // restart, a healed partition) must still receive it. The last
    // kWonReofferMax frames are re-offered on every HELLO, exactly like recent
    // receipts (reoffer_to). drops_floor_diff == 0 (flip 0): nothing is kept and
    // nothing is re-sent -- master's relay, byte for byte.
    static constexpr std::size_t kWonReofferMax = 64;
    void remember_won_frame(const std::vector<u8>& f) {
        if (m_o.drops_floor_diff == 0) return;
        std::lock_guard<std::mutex> lk(m_bmtx);
        m_won_raw.push_back(f);
        while (m_won_raw.size() > kWonReofferMax) m_won_raw.pop_front();
    }
    void reoffer_won_to(PeerId p) {
        if (m_o.drops_floor_diff == 0) return;
        std::vector<std::vector<u8>> raws;
        { std::lock_guard<std::mutex> lk(m_bmtx); raws.assign(m_won_raw.begin(), m_won_raw.end()); }
        for (const auto& f : raws) if (m_net.send_to(p, f)) m_st.won_reoffered++;
    }

    // ── receipt context: serve (queue for the daemon's monerod) / receive ────
    void on_getctx(PeerId p, const std::vector<u8>& f) {
        u32 chain = 0; std::vector<bytes32> ids; std::string why;
        if (!decode_getctx(f, chain, ids, &why)) { m_st.malformed++; strike(p, why); return; }
        if (chain != m_o.chain) { m_st.wrong_chain++; return; }
        std::lock_guard<std::mutex> lk(m_cmtx);
        std::size_t from_p = 0;
        for (const auto& [q, v] : m_ctx_serve) { (void)v; if (q == p) ++from_p; }
        if (from_p >= 4 || m_ctx_serve.size() >= 64) { m_st.ctx_req_dropped++; return; }   // bounded, per peer and total
        m_ctx_serve.emplace_back(p, std::move(ids));
    }
    void on_ctx(PeerId p, const std::vector<u8>& f) {
        u32 chain = 0; bytes32 id{}; std::vector<u8> blob; std::string why;
        if (!decode_ctx(f, chain, id, blob, &why)) { m_st.malformed++; strike(p, why); return; }
        if (chain != m_o.chain) { m_st.wrong_chain++; return; }
        m_st.ctx_rx++;
        offer_ctx(id, blob, p);
    }

    // A SOLICITED receipt's prev_id is unknown here: put it on the want list.
    void want_ctx(const bytes32& prev, PeerId from, u32 depth = 0) {
        std::lock_guard<std::mutex> lk(m_cmtx);
        auto it = m_ctx_want.find(prev);
        if (it != m_ctx_want.end()) { if (!it->second.from && from) it->second.from = from; return; }
        if (m_ctx_want.size() >= m_o.ctx_want_max) return;   // bounded; the repair's refetch re-adds it later
        CtxWant w; w.from = from; w.depth = depth;
        m_ctx_want.emplace(prev, std::move(w));
        m_st.ctx_wanted++;
    }

    // Link verified block proofs to our chain: a proof whose parent we know at
    // exactly its height becomes a ChainView entry (bin = height + 1, seed from
    // OUR chain), which may in turn resolve a child proof waiting on it.
    void resolve_ctx_chain(bytes32 id) {
        for (int guard = 0; guard < 64; ++guard) {
            CtxWant w;
            {
                std::lock_guard<std::mutex> lk(m_cmtx);
                auto it = m_ctx_want.find(id);
                if (it == m_ctx_want.end() || !it->second.have_proof) return;
                w = it->second;
            }
            const auto par = m_chain.lookup(w.proof.parent);
            if (!par) {
                if (w.depth + 1 >= m_o.ctx_max_depth) {
                    {
                        std::lock_guard<std::mutex> lk(m_cmtx);
                        m_ctx_want.erase(id);
                    }
                    m_st.ctx_gave_up++;
                    log("relay: context for " + hex_short(id) + " GIVEN UP: " + std::to_string(m_o.ctx_max_depth) +
                        " unknown ancestors above any block this node knows");
                    return;
                }
                want_ctx(w.proof.parent, w.proof_from ? w.proof_from : w.from, w.depth + 1);   // an unknown ancestor: fetch it too
                return;
            }
            if (par->height != w.proof.height) {
                m_st.ctx_bad++;
                log("relay: context for " + hex_short(id) + " REJECTED: block claims height " + std::to_string(w.proof.height) +
                    " but its parent " + hex_short(w.proof.parent) + " is at bin " + std::to_string(par->height) + " here");
                std::lock_guard<std::mutex> lk(m_cmtx);
                auto it = m_ctx_want.find(id);
                if (it != m_ctx_want.end()) { it->second.have_proof = false; it->second.last_ask = Clock::time_point{}; }
                return;
            }
            const u64 bin = w.proof.height + 1;
            bytes32 seed = par->seed;
            if (::xmr::coin::rx_seedheight(bin) != ::xmr::coin::rx_seedheight(w.proof.height)) {
                const auto s = m_chain.seed_for(bin);
                if (!s) {
                    log("relay: context for " + hex_short(id) + " waits for the RandomX seed of bin " + std::to_string(bin) + " (epoch edge)");
                    return;   // the proof is kept; retried by drive_ctx once the seed is noted
                }
                seed = *s;
            }
            m_chain.note(id, bin, seed);
            m_st.ctx_resolved++;
            log("relay: receipt context RESOLVED: block " + hex_short(id) + " h=" + std::to_string(w.proof.height) +
                " (parent " + hex_short(w.proof.parent) + " known here) via " +
                (w.proof_from ? "peer " + std::to_string(w.proof_from) : std::string("own monerod")) +
                " -> receipts mined on it verify at bin " + std::to_string(bin));
            // a child proof that waited for this block
            bytes32 child{}; bool has_child = false;
            {
                std::lock_guard<std::mutex> lk(m_cmtx);
                m_ctx_want.erase(id);
                for (const auto& [cid, cw] : m_ctx_want)
                    if (cw.have_proof && cw.proof.parent == id) { child = cid; has_child = true; break; }
            }
            if (!has_child) return;
            id = child;
        }
    }

    // Maintenance: ask for wanted contexts (source peer first, then every
    // other ready peer, each once per round; bounded rounds), retry kept proofs.
    void drive_ctx() {
        const auto ready = ready_peers();
        const auto now = Clock::now();
        std::map<PeerId, std::vector<bytes32>> ask;
        std::vector<bytes32> retry_proofs;
        std::vector<std::string> gave_up;
        {
            std::lock_guard<std::mutex> lk(m_cmtx);
            for (auto it = m_ctx_want.begin(); it != m_ctx_want.end();) {
                CtxWant& w = it->second;
                if (now - w.since > std::chrono::minutes(10)) {   // TTL (a repair that still needs it re-adds it)
                    m_st.ctx_gave_up++;
                    gave_up.push_back(hex_short(it->first) + " after 10 min");
                    it = m_ctx_want.erase(it);
                    continue;
                }
                if (w.have_proof) { retry_proofs.push_back(it->first); ++it; continue; }
                if (m_chain.lookup(it->first)) {   // RC-CTX: resolved meanwhile by the ChainView's feeder (native index / journal)
                    m_st.ctx_resolved++;
                    it = m_ctx_want.erase(it);
                    continue;
                }
                if (w.last_ask != Clock::time_point{} && now - w.last_ask < std::chrono::milliseconds(m_o.ctx_retry_ms)) { ++it; continue; }
                PeerId pick = 0;
                if (w.from && !w.asked.count(w.from) && std::find(ready.begin(), ready.end(), w.from) != ready.end()) pick = w.from;
                for (PeerId p : ready) if (!pick && !w.asked.count(p)) pick = p;
                if (!pick) {
                    if (!ready.empty() && !w.asked.empty()) { w.asked.clear(); ++w.rounds; w.last_ask = now; }
                    if (w.rounds >= m_o.ctx_max_rounds) {
                        m_st.ctx_gave_up++;
                        gave_up.push_back(hex_short(it->first) + " after " + std::to_string(w.rounds) + " rounds");
                        it = m_ctx_want.erase(it);
                        continue;
                    }
                    ++it; continue;
                }
                auto& v = ask[pick];
                if (v.size() >= kCtxMaxIds) { ++it; continue; }
                v.push_back(it->first);
                w.asked.insert(pick); ++w.asked_total; w.last_ask = now;
                ++it;
            }
        }
        for (const auto& g : gave_up)
            log("relay: context for " + g + " over every ready peer GIVEN UP (no peer's monerod holds that block)");
        for (const auto& [p, ids] : ask) {
            const auto f = encode_getctx(m_o.chain, ids);
            if (!f.empty() && m_net.send_to(p, f)) m_st.ctx_asked += ids.size();
        }
        for (const auto& id : retry_proofs) resolve_ctx_chain(id);
    }

    // ── the verify queue ────────────────────────────────────────────────────
    void enqueue(Item it) {
        std::lock_guard<std::mutex> lk(m_mtx);
        if (m_cache.count(it.id)) { m_st.dup++; return; }
        if (m_o.drops_floor_diff && drop_seen_locked(it.id)) { m_st.drops_dup++; return; }   // ★ DROPS
        if (m_inflight.count(it.id)) {
            // a SOLICITED copy (repair / backfill GETFRAMES) of a receipt that is
            // already queued or parked as an unsolicited flood: upgrade that item
            // (solicited credit, horizon-exempt, and -- if its context is unknown --
            // the context fetch + the longer patience). Pre-fix the solicited copy
            // was dropped as a dup and the flood copy was dropped "unresolved".
            if (it.solicited) {
                auto upg = [&](std::deque<Item>& q) {
                    for (auto& x : q) if (x.id == it.id && !x.solicited) {
                        x.solicited = true; x.from = it.from; x.enq = Clock::now(); x.not_before = Clock::now();
                        m_st.upgraded_solicited++;
                        return true;
                    }
                    return false;
                };
                if (!upg(m_q)) upg(m_parked);
            }
            m_st.dup++;
            return;
        }
        if (m_q.size() >= m_o.verify_queue_max) {
            m_inflight.erase(m_q.front().id);
            m_q.pop_front();
            m_st.queue_dropped++;
        }
        m_inflight.insert(it.id);
        m_q.push_back(std::move(it));
        m_qcv.notify_one();
    }

    void verify_loop() {
        while (m_running.load()) {
            Item it;
            {
                std::unique_lock<std::mutex> lk(m_mtx);
                m_qcv.wait_for(lk, std::chrono::milliseconds(200), [this] { return !m_q.empty() || !m_running.load(); });
                if (!m_running.load()) break;
                // parked items whose retry time came due go back in front
                const auto now = Clock::now();
                for (auto pit = m_parked.begin(); pit != m_parked.end();) {
                    if (pit->not_before <= now) { m_q.push_front(std::move(*pit)); pit = m_parked.erase(pit); }
                    else ++pit;
                }
                if (m_q.empty()) continue;
                it = std::move(m_q.front());
                m_q.pop_front();
            }
            process(std::move(it));
        }
    }

    void park(Item it, std::chrono::milliseconds delay) {
        std::lock_guard<std::mutex> lk(m_mtx);
        it.not_before = Clock::now() + delay;
        if (m_parked.size() >= 1024) {
            m_inflight.erase(m_parked.front().id);
            m_parked.pop_front();
            m_st.queue_dropped++;
        }
        m_parked.push_back(std::move(it));
    }
    void forget_inflight(const bytes32& id) {
        std::lock_guard<std::mutex> lk(m_mtx);
        m_inflight.erase(id);
    }

    void process(Item it) {
        const auto now = Clock::now();
        {
            std::lock_guard<std::mutex> lk(m_mtx);
            if (m_cache.count(it.id)) { m_inflight.erase(it.id); m_st.dup++; return; }
        }
        // context: prev_id -> (bin, seed)
        ::v37::xmr::verify::ParsedBlob pb;
        if (!::v37::xmr::verify::parse_hashing_blob(it.r.receipt.hashing_blob, pb)) {
            m_st.structural++; forget_inflight(it.id); strike(it.from, "hashing blob does not parse"); return;
        }
        const auto ctx = m_chain.lookup(pb.prev_id);
        if (!ctx) {
            // A SOLICITED receipt (a repair / backfill answer) mined on a block we
            // never saw: fetch that block's context (own monerod, then peers).
            // An unsolicited flood keeps the strict rule (known prev or dropped);
            // if a repair needs it, the solicited copy upgrades it (enqueue).
            if (it.solicited) want_ctx(pb.prev_id, it.from);
            const u32 patience = it.solicited ? m_o.solicited_unresolved_patience_ms : m_o.unresolved_patience_ms;
            if (now - it.enq < std::chrono::milliseconds(patience)) {
                park(std::move(it), std::chrono::milliseconds(1000));
            } else {
                m_st.unresolved_dropped++;
                const std::string why = "receipt " + hex_short(it.id) + " from peer " + std::to_string(it.from) +
                                        (it.solicited ? " (solicited)" : "") + ": Monero context prev_id " + hex_short(pb.prev_id) +
                                        " unknown here after " + std::to_string(patience / 1000) + " s";
                {
                    std::lock_guard<std::mutex> lk(m_mtx);
                    m_inflight.erase(it.id);
                    m_last_unresolved = why;
                }
                if (it.solicited) {
                    m_st.unresolved_solicited_dropped++;
                    log("relay: DROPPED " + why + " (the repair re-asks it; the context fetch continues)");
                }
            }
            return;
        }
        const u64 tip = m_chain.tip();
        if (!it.solicited && m_o.index_horizon && ctx->height + m_o.index_horizon < tip) {
            m_st.expired++; forget_inflight(it.id); return;
        }
        CheckCtx cc; cc.lane_chain = m_o.chain; cc.share_diff = m_o.share_diff; cc.bind = m_o.bind;
        const CheckResult cr = check_structural(it.r, cc);
        if (!cr.ok()) {
            m_st.structural++; forget_inflight(it.id);
            strike(it.from, std::string("structural ") + to_string(cr.stage) + ": " + cr.why);
            return;
        }
        // RandomX token
        const auto p32 = static_cast<::c2pool::xmr::u32>(it.from);
        bool granted = false;
        {
            std::lock_guard<std::mutex> lk(m_mtx);
            if (it.solicited) {
                refill_solicited_locked();
                if (m_solicited >= 1.0) { m_solicited -= 1.0; granted = true; }
            } else {
                granted = m_dos.grant_randomx(p32, now_ns());
            }
        }
        if (!granted) { m_st.rx_deferred++; park(std::move(it), std::chrono::milliseconds(500)); return; }
        bytes32 pow{};
        m_st.rx_evals++;
        if (!m_rx || !m_rx(it.r.receipt.hashing_blob.bytes, ctx->seed, pow)) {
            m_st.rx_unavailable++;
            std::lock_guard<std::mutex> lk(m_mtx);
            if (it.solicited) m_solicited += 1.0; else m_dos.on_valid_pow(p32, now_ns());   // our fault: give the token back
            m_inflight.erase(it.id);
            return;
        }
        if (meets_share_diff(pow, m_o.share_diff)) {
            m_st.rx_valid++;
            {
                std::lock_guard<std::mutex> lk(m_mtx);
                if (it.solicited) m_solicited += 1.0; else m_dos.on_valid_pow(p32, now_ns());
            }
            admit(std::move(it), ctx->height);
            return;
        }
        // ★ DROPS (gate ON only): real work below share_diff but at/above the
        // floor is a RAINDROP, not invalid PoW. With drops_floor_diff == 0 this
        // branch does not exist and the invalid path below is master's.
        if (m_o.drops_floor_diff && meets_share_diff(pow, m_o.drops_floor_diff)) {
            {
                std::lock_guard<std::mutex> lk(m_mtx);
                if (it.solicited) m_solicited += 1.0; else m_dos.on_valid_pow(p32, now_ns());
                m_inflight.erase(it.id);
            }
            admit_drop(std::move(it), ctx->height, pow);
            return;
        }
        // invalid: re-hash (the p2pool unstable-hardware guard) before any ban
        bytes32 pow2{};
        const bool again = m_rx(it.r.receipt.hashing_blob.bytes, ctx->seed, pow2);
        const bool confirmed = again && ::c2pool::xmr::confirm_invalid(pow.data(), pow2.data(), true,
                                                                        !meets_share_diff(pow2, m_o.share_diff));
        m_st.rx_invalid++;
        ::c2pool::xmr::Action a;
        {
            std::lock_guard<std::mutex> lk(m_mtx);
            a = m_dos.on_invalid_pow(p32, confirmed);
            m_inflight.erase(it.id);
            m_last_reject = "pow below share_diff from peer " + std::to_string(it.from) + (confirmed ? " (confirmed)" : " (unconfirmed)");
        }
        if (a == ::c2pool::xmr::Action::Ban) {
            m_st.bans++;
            log("relay: peer " + std::to_string(it.from) + " BANNED: confirmed invalid PoW (RandomX below the lane share difficulty)");
            ban_later(it.from);
        }
    }

    void strike(PeerId p, const std::string& why) {
        ::c2pool::xmr::Action a;
        {
            std::lock_guard<std::mutex> lk(m_mtx);
            m_last_reject = why;
            a = m_dos.on_cheap_reject(static_cast<::c2pool::xmr::u32>(p));
        }
        if (a == ::c2pool::xmr::Action::Ban) { m_st.bans++; ban_later(p); }
    }
    // Disconnect from the maintenance thread (never from inside a reader's own
    // callback stack while it holds our locks).
    void ban_later(PeerId p) {
        std::lock_guard<std::mutex> lk(m_tmtx);
        m_to_drop.push_back(p);
    }

    void refill_solicited_locked() {
        const auto now = Clock::now();
        const double dt = std::chrono::duration<double>(now - m_solicited_at).count();
        m_solicited_at = now;
        m_solicited = std::min<double>(m_o.solicited_credits, m_solicited + dt * 8.0);
    }

    void admit(Item it, u64 bin) {
        Admitted a;
        a.id = it.id; a.r = std::move(it.r); a.raw = std::move(it.raw); a.bin = bin; a.own = false;
        {
            std::lock_guard<std::mutex> lk(m_mtx);
            if (m_cache.count(a.id)) { m_inflight.erase(a.id); m_st.dup++; return; }
            cache_put_locked(a);
            unpushed_note_locked(a.id);
            m_inflight.erase(a.id);
        }
        if (it.solicited) m_st.admitted_solicited++; else m_st.admitted_foreign++;
        flood(a.raw, it.from);
        std::lock_guard<std::mutex> lk(m_amtx);
        m_admitted.push_back(std::move(a));
    }

    // ★ DROPS: raindrop dedup (a bounded FIFO set, separate from the receipt
    // cache so a raindrop can never enter a lane order or a repair answer).
    bool drop_seen_locked(const bytes32& id) const { return m_drop_seen.count(id) != 0; }
    bool drop_note_new(const bytes32& id) {
        std::lock_guard<std::mutex> lk(m_mtx);
        if (!m_drop_seen.insert(id).second) return false;
        m_drop_order.push_back(id);
        while (m_drop_order.size() > m_o.drops_seen_max) { m_drop_seen.erase(m_drop_order.front()); m_drop_order.pop_front(); }
        return true;
    }
    void admit_drop(Item it, u64 bin, const bytes32& pow) {
        if (!drop_note_new(it.id)) { m_st.drops_dup++; return; }
        Admitted a;
        a.id = it.id; a.r = std::move(it.r); a.raw = std::move(it.raw); a.bin = bin; a.own = false;
        a.drop = true; a.pow = pow;
        m_st.drops_foreign++;
        flood(a.raw, it.from);
        std::lock_guard<std::mutex> lk(m_amtx);
        m_drops.push_back(std::move(a));
    }

    void flood(const std::vector<u8>& raw, PeerId except) {
        const auto f = encode_receipts_frame(m_o.chain, {&raw});
        if (f.empty()) return;
        for (PeerId p : ready_peers()) {
            if (p == except) continue;
            if (m_net.send_to(p, f)) m_st.flood_frames++;
        }
    }

    // ── supply (backfill + repair) ──────────────────────────────────────────
    void queue_job(PeerId p, Job j) {
        std::lock_guard<std::mutex> lk(m_jmtx);
        m_jobs[p].push_back(std::move(j));
    }
    void pump_jobs() {
        std::vector<std::pair<PeerId, Job>> issue;
        {
            std::lock_guard<std::mutex> lk(m_jmtx);
            for (auto& [p, q] : m_jobs) {
                if (q.empty() || m_cur_job.count(p) || (m_fetch && m_fetch->busy(p))) continue;
                issue.emplace_back(p, q.front());
                m_cur_job[p] = q.front();
                q.pop_front();
            }
        }
        for (auto& [p, j] : issue) {
            bool ok = false;
            if (j.kind == Job::Kind::Order)
                ok = m_fetch->request_order(p, m_o.chain, j.a, j.p, j.spine);
            else
                ok = m_fetch->request_frames(p, m_o.chain, j.ids);
            if (!ok) {
                std::lock_guard<std::mutex> lk(m_jmtx);
                m_cur_job.erase(p);
            }
        }
    }
    std::optional<Job> take_cur_job(PeerId p) {
        std::lock_guard<std::mutex> lk(m_jmtx);
        auto it = m_cur_job.find(p);
        if (it == m_cur_job.end()) return std::nullopt;
        Job j = std::move(it->second);
        m_cur_job.erase(it);
        return j;
    }

    void on_order(PeerId p, const CtrlOrder& o) {
        // SupplyRequester now hands a NON-OK ORDER (BELOW_HORIZON, DISABLED,
        // BAD_RANGE) to the order callback too, so RepairDriver can name the
        // refusal, and reports it through on_fail right after. This relay
        // treats a refused order as a failed ask of this peer, exactly as
        // before: leave the job for on_fetch_fail and touch nothing here.
        //
        // REPAIR-HORIZON: except BELOW_HORIZON on a repair ask. The peer said
        // where its vault starts (lowest_retained); if that is past what we
        // asked and short of P, raise this peer's repair start to it and mark
        // the repair RE-ARMED, so on_fetch_fail (which follows) re-asks this
        // peer from there instead of setting it aside. No progress (the same
        // or a lower start, or one at/after P) keeps the old set-aside rule.
        if (o.status == CtrlOrderStatus::BELOW_HORIZON) {
            std::optional<Job> cj;
            {
                std::lock_guard<std::mutex> jl(m_jmtx);
                auto it = m_cur_job.find(p);
                if (it != m_cur_job.end()) cj = it->second;
            }
            if (cj && cj->repair && cj->kind == Job::Kind::Order) {
                std::lock_guard<std::mutex> lk(m_rmtx);
                auto it = m_repairs.find(cj->key);
                if (it != m_repairs.end() && it->second.st == Repair::St::Ordering && it->second.cur == p) {
                    Repair& r = it->second;
                    const u64 was = r.a0_of.count(p) ? r.a0_of[p] : 0;
                    if (o.lowest_retained > was && o.lowest_retained > cj->a && o.lowest_retained < r.P) {
                        r.a0_of[p] = o.lowest_retained;
                        r.rearm = p;
                        m_st.repair_horizon_rearm++;
                    }
                }
            }
        }
        if (o.status != CtrlOrderStatus::OK) return;
        auto j = take_cur_job(p);
        if (!j || j->kind != Job::Kind::Order) return;
        if (!j->repair) {                       // BACKFILL: ask for every id we never saw
            std::vector<bytes32> want;
            {
                std::lock_guard<std::mutex> lk(m_mtx);
                for (const auto& e : o.ids) if (!m_cache.count(e.id) && !m_inflight.count(e.id)) want.push_back(e.id);
            }
            for (std::size_t i = 0; i < want.size(); i += kCtrlMaxIdsPerFetch) {
                Job f; f.kind = Job::Kind::Frames; f.repair = false;
                f.ids.assign(want.begin() + static_cast<std::ptrdiff_t>(i),
                             want.begin() + static_cast<std::ptrdiff_t>(std::min(want.size(), i + kCtrlMaxIdsPerFetch)));
                m_st.backfill_ids_asked += f.ids.size();
                queue_job(p, std::move(f));
            }
            if (o.p_served < j->p && o.p_served > j->a) {   // paginate
                Job n = *j; n.a = o.p_served; queue_job(p, std::move(n));
            }
            pump_jobs();
            return;
        }
        // REPAIR
        if (j->probe) {   // REPAIR-HORIZON: the peer's digest at a0 vs ours
            const auto ours = digest_at(j->a);
            const bool alt_known = alt_digest_known(j->a);   // the shadows (reconstructed winner-side orders)
            const bool alt_eq = o.have_spine && alt_digest_is(j->a, o.spine_digest);
            bool go = false; std::string alarm;
            {
                std::lock_guard<std::mutex> lk(m_rmtx);
                auto it = m_repairs.find(j->key);
                if (it == m_repairs.end()) return;
                Repair& r = it->second;
                if (r.st != Repair::St::Ordering || r.cur != p || !r.probing || r.a0 != j->a) return;
                r.probing = false;
                if (o.p_served == j->a && o.have_spine && (ours || alt_known) && !(ours && o.spine_digest == *ours) && !alt_eq) {
                    const bool fresh = r.deep.emplace(p, j->a).second;   // log a peer's DEEP once per repair
                    r.deep[p] = j->a;
                    m_st.repair_deep++;
                    r.tried.insert(p); r.reset();
                    if (fresh) alarm = "relay: REPAIR-HORIZON repair of P=" + std::to_string(r.P) + ": peer " + std::to_string(p) +
                            " retains only positions >= " + std::to_string(j->a) + " and its lane digest there DIFFERS from ours -- "
                            "our order diverges from the winner's below that peer's vault horizon (peer set aside as DEEP)";
                } else {
                    if (o.have_spine && (ours || alt_known)) m_st.repair_prefix_ok++; else m_st.repair_prefix_unknown++;
                    if (o.p_served == j->a && o.have_spine) { r.a0_digest = o.spine_digest; r.has_a0_digest = true; }
                    r.since = Clock::now();
                    go = true;
                }
            }
            if (!alarm.empty()) log(alarm);
            if (go) {
                Job n = *j; n.probe = false; n.p = j->key.first; n.spine = j->key.second;   // the suffix order [a0, P)
                queue_job(p, std::move(n));
            }
            pump_jobs();
            return;
        }
        std::vector<bytes32> need;
        {
            std::lock_guard<std::mutex> lk(m_rmtx);
            auto it = m_repairs.find(j->key);
            if (it == m_repairs.end()) return;
            Repair& r = it->second;
            if (r.st != Repair::St::Ordering || r.cur != p) return;
            // Dense = every lane position in [cursor, p_served) is covered by
            // the served receipts. One receipt spans 1..max_pushes_per_receipt
            // positions (1 with the fee model OFF -- exactly the master rule --
            // 1 or 2 under it), so consecutive starts step by 1..max.
            const u64 mp = m_o.max_pushes_per_receipt ? m_o.max_pushes_per_receipt : 1;
            bool dense = (o.a == r.cursor);
            u64 prev = 0;
            for (std::size_t i = 0; dense && i < o.ids.size(); ++i) {
                const u64 pos = o.ids[i].pos;
                dense = (i == 0) ? (pos == r.cursor) : (pos >= prev + 1 && pos <= prev + mp);
                prev = pos;
            }
            dense = dense && (o.ids.empty() ? (o.p_served == r.cursor)
                                            : (o.p_served >= prev + 1 && o.p_served <= prev + mp));
            if (!dense) { m_st.repair_peer_fail++; r.tried.insert(p); r.reset(); return; }
            for (const auto& e : o.ids) r.ids.push_back(e.id);
            r.cursor = o.p_served;
            if (r.cursor < r.P) {
                Job n = *j; n.a = r.cursor; queue_job(p, std::move(n));
                pump_jobs();
                return;
            }
            if (!o.have_spine || o.spine_digest != r.spine) {
                // this peer's order does not reach the winner's digest at P
                m_st.repair_spine_mismatch++; r.tried.insert(p); r.reset(); return;
            }
            m_st.repair_order_ok++;
            r.served_by = p;
            r.st = Repair::St::Fetching;
            r.since = r.last_progress = r.last_fetch = Clock::now();
            r.fetch_tried.clear(); r.fetch_tried.insert(p);
            std::lock_guard<std::mutex> ck(m_mtx);
            // ids still in verify are asked too: the solicited copy upgrades a
            // parked unsolicited flood of the same receipt (context fetch,
            // longer patience) instead of letting it expire as "unresolved"
            for (const auto& id : r.ids) if (!m_cache.count(id)) need.push_back(id);
        }
        for (std::size_t i = 0; i < need.size(); i += kCtrlMaxIdsPerFetch) {
            Job f; f.kind = Job::Kind::Frames; f.repair = true; f.key = j->key;
            f.ids.assign(need.begin() + static_cast<std::ptrdiff_t>(i),
                         need.begin() + static_cast<std::ptrdiff_t>(std::min(need.size(), i + kCtrlMaxIdsPerFetch)));
            m_st.repair_ids_asked += f.ids.size();
            queue_job(p, std::move(f));
        }
        pump_jobs();
    }

    void on_frames(PeerId p, const std::vector<VerifiedFrame>& v) {
        for (const auto& vf : v) {
            Item it; it.from = p; it.solicited = true; it.raw = vf.frame;
            if (!decode_fb_receipt(vf.frame, it.r)) continue;   // unreachable: the id seam decoded it
            it.id = vf.id;
            enqueue(std::move(it));
        }
        // a multi-chunk fetch keeps its slot until the last chunk
        if (m_fetch && !m_fetch->busy(p)) take_cur_job(p);
        pump_jobs();
    }

    void on_fetch_fail(PeerId p, SupplyFailure) {
        auto j = take_cur_job(p);
        if (j && j->repair) {
            m_st.repair_peer_fail++;
            std::lock_guard<std::mutex> lk(m_rmtx);
            auto it = m_repairs.find(j->key);
            if (it != m_repairs.end()) {
                Repair& r = it->second;
                if (r.st == Repair::St::Fetching && j->kind == Job::Kind::Frames) {
                    // a frames fetch failed (unservable / timeout): keep the order,
                    // re-ask the missing frames of ANOTHER peer now
                    r.fetch_tried.insert(p); r.last_fetch = Clock::time_point{};
                } else if (r.st != Repair::St::Ready) {
                    // REPAIR-HORIZON: a BELOW_HORIZON answer that raised this peer's
                    // start re-arms the repair (re-ask it first) instead of setting it aside
                    if (r.rearm == p) { r.rearm = 0; r.prefer = p; } else r.tried.insert(p);
                    r.reset();
                }
            }
        }
        pump_jobs();
    }

    void drive_repairs() {
        const auto ready = ready_peers();
        std::vector<std::pair<PeerId, Job>> issue;
        {
            std::lock_guard<std::mutex> lk(m_rmtx);
            const auto now = Clock::now();
            const auto timeout = std::chrono::milliseconds(m_o.repair_state_timeout_ms);
            for (auto& [k, r] : m_repairs) {
                if (r.st == Repair::St::Ordering && now - r.since > timeout) {
                    if (r.cur) r.tried.insert(r.cur);
                    r.reset();
                }
                if (r.st == Repair::St::Fetching) {
                    // The order is known; only frames are missing. Pre-fix this
                    // state just waited for the 20 s timeout and then DISCARDED the
                    // order (re-asking the same frames, which failed the same way,
                    // forever). Now: progress resets the clock; idle missing frames
                    // (neither cached nor in verify) are re-asked with peer failover.
                    std::vector<bytes32> idle;
                    std::size_t cached = 0;
                    {
                        std::lock_guard<std::mutex> ck(m_mtx);
                        for (const auto& id : r.ids) {
                            if (m_cache.count(id)) { ++cached; continue; }
                            if (!m_inflight.count(id)) idle.push_back(id);
                        }
                    }
                    if (cached > r.cached_seen) { r.cached_seen = cached; r.last_progress = now; }
                    if (!idle.empty() && now - r.last_fetch >= std::chrono::milliseconds(m_o.repair_refetch_ms)) {
                        PeerId pick = 0;
                        const bool sb_ready = r.served_by && std::find(ready.begin(), ready.end(), r.served_by) != ready.end();
                        if (sb_ready && !r.fetch_tried.count(r.served_by)) pick = r.served_by;
                        for (PeerId p : ready) if (!pick && !r.fetch_tried.count(p)) pick = p;
                        if (!pick) {                       // every ready peer asked this round: start a new round
                            r.fetch_tried.clear();
                            pick = sb_ready ? r.served_by : (ready.empty() ? 0 : ready.front());
                        }
                        if (pick) {
                            r.fetch_tried.insert(pick);
                            r.last_fetch = now;
                            ++r.refetches;
                            m_st.repair_refetch++;
                            for (std::size_t i = 0; i < idle.size(); i += kCtrlMaxIdsPerFetch) {
                                Job f; f.kind = Job::Kind::Frames; f.repair = true; f.key = k;
                                f.ids.assign(idle.begin() + static_cast<std::ptrdiff_t>(i),
                                             idle.begin() + static_cast<std::ptrdiff_t>(std::min(idle.size(), i + kCtrlMaxIdsPerFetch)));
                                m_st.repair_ids_asked += f.ids.size();
                                issue.emplace_back(pick, std::move(f));
                            }
                        }
                    }
                    // no progress for a long time with frames nobody serves: the
                    // order itself may be unfetchable here -> ask another peer for it
                    if (!idle.empty() && now - r.last_progress > timeout * 6) {
                        if (r.served_by) r.tried.insert(r.served_by);
                        r.reset();
                    }
                }
                if (r.st != Repair::St::Idle) continue;
                PeerId pick = 0;
                if (r.prefer && !r.tried.count(r.prefer) &&
                    std::find(ready.begin(), ready.end(), r.prefer) != ready.end()) pick = r.prefer;   // REPAIR-HORIZON re-ask
                r.prefer = 0;
                if (!pick && r.hint && !r.tried.count(r.hint) &&
                    std::find(ready.begin(), ready.end(), r.hint) != ready.end()) pick = r.hint;
                for (PeerId p : ready) if (!pick && !r.tried.count(p)) pick = p;
                if (!pick) {
                    r.exhausted = !ready.empty();
                    if (r.exhausted && Clock::now() - r.since > std::chrono::seconds(5)) { r.tried.clear(); r.since = Clock::now(); }
                    continue;
                }
                r.exhausted = false;
                // REPAIR-HORIZON: from this peer's known vault start a0 (0 = the whole
                // order); a0 > 0 asks the zero-length prefix probe [a0, a0) first.
                const u64 a0 = r.a0_of.count(pick) ? r.a0_of[pick] : 0;
                r.st = Repair::St::Ordering; r.cur = pick; r.a0 = a0; r.cursor = a0; r.probing = a0 > 0; r.ids.clear(); r.since = Clock::now();
                Job j; j.kind = Job::Kind::Order; j.repair = true; j.key = k; j.a = a0; j.p = r.P; j.spine = r.spine;
                if (a0) { j.probe = true; j.p = a0; if (const auto d = digest_at(a0)) j.spine = *d; }
                issue.emplace_back(pick, std::move(j));
            }
        }
        for (auto& [p, j] : issue) queue_job(p, std::move(j));
        if (!issue.empty()) pump_jobs();
    }

    // ── maintenance: dial/redial, HELLO timeouts, fetch timeouts, drops ──────
    void maint_loop() {
        while (m_running.load()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(250));
            if (!m_running.load()) break;
            // deferred drops (bans)
            std::vector<PeerId> drops;
            {
                std::lock_guard<std::mutex> lk(m_tmtx);
                drops.swap(m_to_drop);
            }
            for (PeerId p : drops) m_net.disconnect(p);
            // HELLO timeouts
            std::vector<PeerId> stale;
            {
                std::lock_guard<std::mutex> lk(m_pmtx);
                for (const auto& [p, s] : m_peers)
                    if (!s.hello_ok && Clock::now() - s.connected > std::chrono::milliseconds(m_o.hello_timeout_ms))
                        stale.push_back(p);
            }
            for (PeerId p : stale) {
                m_st.hello_timeout++;
                {   // SMOKE-NOISE: a silent dial target backs off harder than a refusing one
                    std::lock_guard<std::mutex> lk(m_tmtx);
                    for (auto& t : m_targets) if (t.pid == p) t.hello_timed_out = true;
                }
                if (m_net.has_peer(p)) { m_net.disconnect(p); continue; }
                std::lock_guard<std::mutex> lk(m_pmtx);   // transport already dropped it: no down event will come
                m_peers.erase(p);
            }
            if (m_partitioned.load() && Clock::now().time_since_epoch().count() >= m_partition_until.load()) {
                m_partitioned = false;
                m_dialing = true;
                log("relay: partition over -- redialing");
            }
            // dial / redial with backoff
            if (m_dialing.load()) {
                std::vector<std::size_t> due;
                const auto live = m_net.peer_ids();
                {
                    std::lock_guard<std::mutex> lk(m_tmtx);
                    for (std::size_t i = 0; i < m_targets.size(); ++i) {
                        auto& t = m_targets[i];
                        if (t.pid && std::find(live.begin(), live.end(), t.pid) == live.end()) t.pid = 0;
                        if (!t.pid && Clock::now() >= t.next_try) due.push_back(i);
                    }
                }
                for (std::size_t i : due) {
                    std::string host; u16 port = 0;
                    {
                        std::lock_guard<std::mutex> lk(m_tmtx);
                        host = m_targets[i].host; port = m_targets[i].port;
                    }
                    m_st.dials++;
                    const PeerId pid = m_net.add_peer_id(host, port);
                    // the peer's HELLO may already have been accepted before t.pid is set
                    const bool hello_now = pid && hello_ok(pid);
                    std::lock_guard<std::mutex> lk(m_tmtx);
                    auto& t = m_targets[i];
                    if (pid) {
                        t.backoff_s = 1;   // connect(2) worked: the dial-failure backoff restarts (unchanged)
                        t.hello_seen = hello_now; t.hello_timed_out = false;
                        if (m_net.has_peer(pid)) {
                            t.pid = pid;
                            if (hello_now) t.prehello_fails = 0;
                        } else {
                            // SMOKE-NOISE: the link already ended and its down event ran
                            // before t.pid was set (it found no target), so the old code
                            // redialed on the very next tick (250 ms). Back off here.
                            t.next_try = Clock::now() + std::chrono::seconds(prehello_delay_s(t));
                            t.hello_seen = false;
                        }
                    } else {
                        m_st.dial_fail++;
                        t.next_try = Clock::now() + std::chrono::seconds(t.backoff_s);
                        t.backoff_s = std::min(60, t.backoff_s * 2);
                    }
                }
            } else {
                std::vector<PeerId> out;
                {
                    std::lock_guard<std::mutex> lk(m_tmtx);
                    for (auto& t : m_targets) if (t.pid) { out.push_back(t.pid); t.pid = 0; }
                }
                for (PeerId p : out) m_net.disconnect(p);
            }
            if (m_fetch) m_fetch->tick();
            // a job whose request timed out left no callback path in some shapes
            {
                std::vector<PeerId> done;
                {
                    std::lock_guard<std::mutex> lk(m_jmtx);
                    for (const auto& [p, j] : m_cur_job) { (void)j; if (!m_fetch->busy(p)) done.push_back(p); }
                }
                for (PeerId p : done) {
                    auto j = take_cur_job(p);
                    if (j && j->repair && j->kind == Job::Kind::Order) {
                        std::lock_guard<std::mutex> lk(m_rmtx);
                        auto it = m_repairs.find(j->key);
                        if (it != m_repairs.end() && it->second.st == Repair::St::Ordering && it->second.cur == p) {
                            Repair& r = it->second;   // REPAIR-HORIZON: a re-armed peer is re-asked, not set aside
                            if (r.rearm == p) { r.rearm = 0; r.prefer = p; } else r.tried.insert(p);
                            r.reset();
                        }
                    }
                }
            }
            pump_jobs();
            drive_repairs();
            drive_ctx();
            drive_liveness();   // RELAY-LIVENESS
        }
    }

    // ── members ─────────────────────────────────────────────────────────────
    RelayOptions m_o;
    ChainView&   m_chain;
    RxFn         m_rx;
    LaneTipFn    m_tip;
    LogFn        m_log;
    u64          m_nonce = 0;
    RelayStats   m_st;

    ::c2pool::v37n::CarrierPeerNode m_net;
    std::unique_ptr<SupplyService>   m_serve;
    std::unique_ptr<SupplyRequester> m_fetch;

    mutable std::mutex m_mtx;          // cache / inflight / queue / parked / dos / recent
    std::condition_variable m_qcv;
    ::c2pool::xmr::CarrierDosBudget m_dos;
    std::unordered_map<bytes32, CacheEntry, Bytes32Hash> m_cache;
    std::deque<bytes32> m_cache_order;
    std::unordered_set<bytes32, Bytes32Hash> m_inflight;
    std::deque<std::pair<Clock::time_point, bytes32>> m_recent;
    std::unordered_set<bytes32, Bytes32Hash> m_unpushed;   // REPAIR-HORIZON: admitted, not yet in our lane
    std::deque<bytes32> m_unpushed_order;
    std::deque<Item> m_q;
    std::deque<Item> m_parked;
    double m_solicited = 0;
    Clock::time_point m_solicited_at = Clock::now();
    std::string m_last_reject;
    std::string m_last_unresolved;

    mutable std::mutex m_cmtx;         // receipt-context wants + serve requests
    std::map<bytes32, CtxWant> m_ctx_want;
    std::deque<std::pair<PeerId, std::vector<bytes32>>> m_ctx_serve;

    std::mutex m_amtx;               // admitted queue
    std::vector<Admitted> m_admitted;
    std::vector<Admitted> m_drops;   // ★ DROPS: admitted raindrops (m_amtx)
    std::unordered_set<bytes32, Bytes32Hash> m_drop_seen;   // ★ DROPS dedup (m_mtx)
    std::deque<bytes32> m_drop_order;

    mutable std::mutex m_pmtx;         // peers
    std::map<PeerId, PeerSt> m_peers;
    std::set<PeerId> m_up_done;        // UP-GATE: links whose up event has been handled (m_pmtx)
    std::condition_variable m_up_cv;   // UP-GATE: signalled by open_up_gate
    std::atomic<u32> m_test_up_delay_ms{0};
    Clock::time_point m_live_tick = Clock::now();   // RELAY-LIVENESS (maintenance thread only)
    u64 m_ping_nonce = 0;                           // RELAY-LIVENESS (maintenance thread only)

    std::mutex m_tmtx;                 // dial targets + deferred drops
    std::vector<Target> m_targets;
    std::vector<PeerId> m_to_drop;
    std::atomic<bool> m_dialing{true};
    std::atomic<bool> m_partitioned{false};
    std::atomic<Clock::rep> m_partition_until{0};

    std::mutex m_jmtx;                 // supply jobs
    std::map<PeerId, std::deque<Job>> m_jobs;
    std::map<PeerId, Job> m_cur_job;

    mutable std::mutex m_rmtx;         // repairs
    std::map<std::pair<u64, bytes32>, Repair> m_repairs;

    mutable std::mutex m_bmtx;         // block-won
    std::set<bytes32> m_seen_bids;
    std::map<bytes32, PeerId> m_bid_peer;
    std::vector<std::pair<BlockWon, PeerId>> m_won;
    std::deque<std::vector<u8>> m_won_raw;   // ENROL-REPL: recent FB_BLOCK_WON frames (DROPS only)

    mutable std::mutex m_dmtx;         // pos -> lane digest (the spine probe)
    std::map<u64, bytes32> m_pos_digest;
    std::multimap<u64, bytes32> m_alt_digest;   // REPAIR-HORIZON: the shadows' digests (note_alt_digests)

    ::c2pool::v37n::FrameVault m_vault;

    std::atomic<bool> m_running{false};
    std::thread m_verify_thread, m_maint_thread;
};

} // namespace c2pool::v37n::xmr::relay
