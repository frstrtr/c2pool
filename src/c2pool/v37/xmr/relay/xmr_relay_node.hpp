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
// BACKFILL on (re)connect: the sender RE-OFFERS its last --relay-reoffer-seconds
// of admitted receipts; the receiver asks GETORDER over the peer's last
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
#include "xmr_relay_wire.hpp"
#include "xmr_receipt_mint.hpp"

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
private:
    static constexpr std::size_t kMax = 8192;
    mutable std::mutex m_mtx;
    std::unordered_map<bytes32, Ctx, Bytes32Hash> m_map;
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
};

struct RelayOptions {
    u8          network = 3;
    u32         chain = 0;
    u64         share_diff = 0;
    bytes32     lane_params_digest{};
    BindMode    bind = BindMode::None;
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
};

struct RelayStats {
    std::atomic<u64> hello_sent{0}, hello_ok{0}, hello_rejected{0}, hello_timeout{0}, pre_hello_dropped{0};
    std::atomic<u64> fa_ignored{0}, fb_unknown{0}, malformed{0}, wrong_chain{0};
    std::atomic<u64> rx_receipts{0}, dup{0}, queue_dropped{0}, unresolved_dropped{0}, expired{0};
    std::atomic<u64> structural{0}, rx_deferred{0}, rx_evals{0}, rx_valid{0}, rx_invalid{0}, rx_unavailable{0}, bans{0};
    std::atomic<u64> admitted_own{0}, admitted_foreign{0}, admitted_solicited{0};
    std::atomic<u64> flood_frames{0}, reoffer_frames{0};
    std::atomic<u64> backfill_orders{0}, backfill_ids_asked{0};
    std::atomic<u64> block_won_rx{0}, block_won_tx{0};
    std::atomic<u64> dials{0}, dial_fail{0}, over_cap{0};
    std::atomic<u64> repair_started{0}, repair_order_ok{0}, repair_spine_mismatch{0}, repair_peer_fail{0}, repair_ids_asked{0}, repair_ready{0}, repair_rejected{0};
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
            if (!hello_ok(p)) { m_st.pre_hello_dropped++; return; }
            m_serve->on_control(p, f);
            m_fetch->on_control(p, f);
        });
        m_net.set_on_peer_event([this](PeerId p, bool up) { on_peer_event(p, up); });

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
            m_inflight.erase(a.id);
        }
        m_st.admitted_own++;
        flood(a.raw, 0);
        std::lock_guard<std::mutex> lk(m_amtx);
        m_admitted.push_back(std::move(a));
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
        std::lock_guard<std::mutex> lk(m_dmtx);
        m_pos_digest[next_after] = digest_after;
        const u64 horizon = m_o.vault.horizon_positions ? m_o.vault.horizon_positions : 8640;
        while (!m_pos_digest.empty() && m_pos_digest.begin()->first + horizon + 1 < next_after)
            m_pos_digest.erase(m_pos_digest.begin());
    }
    // Our recorded lane digest at position `pos` (the spine probe's answer).
    std::optional<bytes32> digest_at(u64 pos) const {
        std::lock_guard<std::mutex> lk(m_dmtx);
        auto it = m_pos_digest.find(pos);
        if (it == m_pos_digest.end()) return std::nullopt;
        return it->second;
    }

    // ── verified cache lookup (main thread, for a repair replay) ────────────
    bool cached(const bytes32& id, ::v37::ScriptRef* payee = nullptr) const {
        std::lock_guard<std::mutex> lk(m_mtx);
        auto it = m_cache.find(id);
        if (it == m_cache.end()) return false;
        if (payee) *payee = it->second.payee;
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
        h.bind = m_o.bind;
        if (m_tip) { const auto t = m_tip(); h.lane_next_pos = t.first; h.lane_digest = t.second; }
        return h;
    }

    // ── REPAIR: the winner-side order over [0, P) whose digest at P is `spine`
    // Pending = in flight (the caller answers cut-pending and retries);
    // Ready = `ids` (P of them, in the serving peer's lane order) are all in the
    // verified cache; Exhausted = every connected peer was asked and none could
    // serve it (the caller keeps retrying; a new peer or a new tip may fix it).
    RepairState repair_poll(u64 P, const bytes32& spine, PeerId hint, std::vector<bytes32>* ids) {
        std::unique_lock<std::mutex> lk(m_rmtx);
        auto key = std::make_pair(P, spine);
        auto it = m_repairs.find(key);
        if (it == m_repairs.end()) {
            Repair r; r.P = P; r.spine = spine; r.hint = hint; r.since = Clock::now();
            it = m_repairs.emplace(key, std::move(r)).first;
            m_st.repair_started++;
            while (m_repairs.size() > 64) m_repairs.erase(m_repairs.begin());
            it = m_repairs.find(key);
            if (it == m_repairs.end()) return RepairState::Pending;
        }
        Repair& r = it->second;
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
        if (r.served_by) r.tried.insert(r.served_by);
        r.reset();
        m_st.repair_rejected++;
    }
    std::size_t repairs_open() const { std::lock_guard<std::mutex> lk(m_rmtx); return m_repairs.size(); }

    std::string describe() const {
        const auto& s = m_st;
        char b[1400];
        std::snprintf(b, sizeof b,
            "relay: conns=%zu ready=%zu hello ok=%llu rej=%llu tmo=%llu | rx recv=%llu dup=%llu struct=%llu "
            "rx_evals=%llu valid=%llu invalid=%llu deferred=%llu unavail=%llu bans=%llu unresolved=%llu expired=%llu qdrop=%llu | "
            "admitted own=%llu foreign=%llu solicited=%llu cache=%zu | flood=%llu reoffer=%llu backfill orders=%llu ids=%llu | "
            "won tx=%llu rx=%llu | repair start=%llu order_ok=%llu spine_mis=%llu peer_fail=%llu ids=%llu ready=%llu rejected=%llu open=%zu | "
            "fa_ignored=%llu fb_unknown=%llu malformed=%llu pre_hello=%llu",
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
            (unsigned long long)s.malformed.load(), (unsigned long long)s.pre_hello_dropped.load());
        return b;
    }
    std::string last_reject() const { std::lock_guard<std::mutex> lk(m_mtx); return m_last_reject; }

    // Test hook: disconnect one peer (the KAT's "B drops off the network").
    void drop_peer(PeerId p) { m_net.disconnect(p); }
    // Test hook: stop redialing (and drop) every dial target.
    void set_dialing(bool on) { m_dialing = on; }

private:
    // ── state ───────────────────────────────────────────────────────────────
    struct PeerSt {
        bool hello_ok = false;
        bool hello_sent = false;
        Clock::time_point connected = Clock::now();
        Hello remote{};
    };
    struct Target {
        std::string host; u16 port = 0; PeerId pid = 0;
        Clock::time_point next_try; int backoff_s = 1;
    };
    struct Item {
        PeerId from = 0;
        FbReceipt r;
        std::vector<u8> raw;
        bytes32 id{};
        bool solicited = false;
        Clock::time_point enq = Clock::now();
        Clock::time_point not_before = Clock::now();
    };
    struct CacheEntry { ::v37::ScriptRef payee; std::vector<u8> raw; u64 bin = 0; };
    struct Job {
        enum class Kind { Order, Frames } kind = Kind::Order;
        bool repair = false;
        std::pair<u64, bytes32> key{};
        u64 a = 0, p = 0;
        bytes32 spine{};
        std::vector<bytes32> ids;
    };
    struct Repair {
        enum class St { Idle, Ordering, Fetching, Ready } st = St::Idle;
        u64 P = 0; bytes32 spine{};
        PeerId hint = 0, cur = 0, served_by = 0;
        std::set<PeerId> tried;
        std::vector<bytes32> ids;
        u64 cursor = 0;
        bool exhausted = false;
        Clock::time_point since = Clock::now();
        void reset() { st = St::Idle; ids.clear(); cursor = 0; cur = 0; served_by = 0; since = Clock::now(); }
    };

    static ::c2pool::xmr::nanos_t now_ns() {
        return std::chrono::duration_cast<std::chrono::nanoseconds>(Clock::now().time_since_epoch()).count();
    }
    void log(const std::string& s) { if (m_log) m_log(s); }

    void cache_put_locked(const Admitted& a) {
        CacheEntry e; e.payee = a.r.payee; e.raw = a.raw; e.bin = a.bin;
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
            bool over = false;
            {
                std::lock_guard<std::mutex> lk(m_pmtx);
                m_peers[p] = PeerSt{};
                over = m_peers.size() > m_o.max_peers;
            }
            if (over) { m_st.over_cap++; m_net.disconnect(p); return; }
            const auto f = encode_hello(our_hello());
            if (m_net.send_to(p, f)) {
                m_st.hello_sent++;
                std::lock_guard<std::mutex> lk(m_pmtx);
                auto it = m_peers.find(p);
                if (it != m_peers.end()) it->second.hello_sent = true;
            }
            return;
        }
        {
            std::lock_guard<std::mutex> lk(m_pmtx);
            m_peers.erase(p);
        }
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
            for (auto& [k, r] : m_repairs)
                if (r.st == Repair::St::Ordering && r.cur == p) { r.tried.insert(p); r.reset(); }
        }
        {
            std::lock_guard<std::mutex> lk(m_tmtx);
            for (auto& t : m_targets) if (t.pid == p) { t.pid = 0; t.next_try = Clock::now() + std::chrono::seconds(t.backoff_s); }
        }
    }

    void on_frame(PeerId p, const std::vector<u8>& f) {
        if (f.empty()) { m_st.malformed++; return; }
        const u8 op = f[0];
        if (op == FB_HELLO) { on_hello(p, f); return; }
        if (!is_family_b_opcode(op)) { m_st.fa_ignored++; return; }   // Family-A CarrierWire: count, keep socket
        if (!hello_ok(p)) { m_st.pre_hello_dropped++; return; }
        if (op == FB_RECEIPTS) { on_receipts(p, f); return; }
        if (op == FB_BLOCK_WON) { on_block_won(p, f); return; }
        m_st.fb_unknown++;                                              // a future 0x43..0x4f: count, keep socket
    }

    void on_hello(PeerId p, const std::vector<u8>& f) {
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
        log("relay: peer " + std::to_string(p) + " HELLO ok (lane next_pos=" + std::to_string(h.lane_next_pos) +
            " listen=" + std::to_string(h.listen_port) + ")");
        reoffer_to(p);
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
            for (const auto& [t, id] : m_recent) {
                if (Clock::now() - t > horizon) continue;
                auto it = m_cache.find(id);
                if (it != m_cache.end()) raws.push_back(it->second.raw);
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
        for (PeerId q : ready_peers()) if (q != p) m_net.send_to(q, f);   // forward once (dedup by bid)
    }

    // ── the verify queue ────────────────────────────────────────────────────
    void enqueue(Item it) {
        std::lock_guard<std::mutex> lk(m_mtx);
        if (m_cache.count(it.id) || m_inflight.count(it.id)) { m_st.dup++; return; }
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
            if (now - it.enq < std::chrono::milliseconds(m_o.unresolved_patience_ms)) {
                park(std::move(it), std::chrono::milliseconds(1000));
            } else {
                m_st.unresolved_dropped++; forget_inflight(it.id);
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
            m_inflight.erase(a.id);
        }
        if (it.solicited) m_st.admitted_solicited++; else m_st.admitted_foreign++;
        flood(a.raw, it.from);
        std::lock_guard<std::mutex> lk(m_amtx);
        m_admitted.push_back(std::move(a));
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
        std::vector<bytes32> need;
        {
            std::lock_guard<std::mutex> lk(m_rmtx);
            auto it = m_repairs.find(j->key);
            if (it == m_repairs.end()) return;
            Repair& r = it->second;
            if (r.st != Repair::St::Ordering || r.cur != p) return;
            bool dense = (o.a == r.cursor);
            for (std::size_t i = 0; dense && i < o.ids.size(); ++i) dense = (o.ids[i].pos == r.cursor + i);
            dense = dense && (o.p_served == r.cursor + o.ids.size());
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
            r.since = Clock::now();
            std::lock_guard<std::mutex> ck(m_mtx);
            for (const auto& id : r.ids) if (!m_cache.count(id) && !m_inflight.count(id)) need.push_back(id);
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
                if (r.st != Repair::St::Ready) { r.tried.insert(p); r.reset(); }
            }
        }
        pump_jobs();
    }

    void drive_repairs() {
        const auto ready = ready_peers();
        std::vector<std::pair<PeerId, Job>> issue;
        {
            std::lock_guard<std::mutex> lk(m_rmtx);
            for (auto& [k, r] : m_repairs) {
                if (r.st != Repair::St::Idle &&
                    Clock::now() - r.since > std::chrono::milliseconds(m_o.repair_state_timeout_ms) &&
                    r.st != Repair::St::Ready) {
                    PeerId who = r.cur ? r.cur : r.served_by;
                    if (who) r.tried.insert(who);
                    r.reset();
                }
                if (r.st != Repair::St::Idle) continue;
                PeerId pick = 0;
                if (r.hint && !r.tried.count(r.hint) &&
                    std::find(ready.begin(), ready.end(), r.hint) != ready.end()) pick = r.hint;
                for (PeerId p : ready) if (!pick && !r.tried.count(p)) pick = p;
                if (!pick) {
                    r.exhausted = !ready.empty();
                    if (r.exhausted && Clock::now() - r.since > std::chrono::seconds(5)) { r.tried.clear(); r.since = Clock::now(); }
                    continue;
                }
                r.exhausted = false;
                r.st = Repair::St::Ordering; r.cur = pick; r.cursor = 0; r.ids.clear(); r.since = Clock::now();
                Job j; j.kind = Job::Kind::Order; j.repair = true; j.key = k; j.a = 0; j.p = r.P; j.spine = r.spine;
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
            for (PeerId p : stale) { m_st.hello_timeout++; m_net.disconnect(p); }
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
                    std::lock_guard<std::mutex> lk(m_tmtx);
                    auto& t = m_targets[i];
                    if (pid) { t.pid = pid; t.backoff_s = 1; }
                    else {
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
                            it->second.tried.insert(p); it->second.reset();
                        }
                    }
                }
            }
            pump_jobs();
            drive_repairs();
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
    std::deque<Item> m_q;
    std::deque<Item> m_parked;
    double m_solicited = 0;
    Clock::time_point m_solicited_at = Clock::now();
    std::string m_last_reject;

    std::mutex m_amtx;                 // admitted queue
    std::vector<Admitted> m_admitted;

    mutable std::mutex m_pmtx;         // peers
    std::map<PeerId, PeerSt> m_peers;

    std::mutex m_tmtx;                 // dial targets + deferred drops
    std::vector<Target> m_targets;
    std::vector<PeerId> m_to_drop;
    std::atomic<bool> m_dialing{true};

    std::mutex m_jmtx;                 // supply jobs
    std::map<PeerId, std::deque<Job>> m_jobs;
    std::map<PeerId, Job> m_cur_job;

    mutable std::mutex m_rmtx;         // repairs
    std::map<std::pair<u64, bytes32>, Repair> m_repairs;

    mutable std::mutex m_bmtx;         // block-won
    std::set<bytes32> m_seen_bids;
    std::map<bytes32, PeerId> m_bid_peer;
    std::vector<std::pair<BlockWon, PeerId>> m_won;

    mutable std::mutex m_dmtx;         // pos -> lane digest (the spine probe)
    std::map<u64, bytes32> m_pos_digest;

    ::c2pool::v37n::FrameVault m_vault;

    std::atomic<bool> m_running{false};
    std::thread m_verify_thread, m_maint_thread;
};

} // namespace c2pool::v37n::xmr::relay
