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
// The verify workers own the ONLY calls into RandomX (the injected RxFn), on the
// relay's OWN verifier, so a receipt flood can never sit in front of a miner's
// submit on the stratum listener thread.
//
// DROPS-VERIFY-SCALE (capstone attempt 5 false start): with raindrops ON every
// node RandomX-verifies every raindrop of the pool (64x the receipt load); one
// verify thread capped a node at one core, the FIFO dropped items and receipts
// verified after their bin closed went 'late' in arrival order (node-local lane
// orders diverged). RelayOptions::verify_threads = N workers now run the SAME
// process() on items popped from the one queue; the daemon's RxFn hashes on the
// worker's own light VM (verify_worker() -> O2RandomXVerifier::randomx_hash_on)
// over the SHARED seed caches (+~2.2 MiB per worker, no new 256 MiB cache).
// Every admission predicate is a pure function of (bytes, seed, share_diff,
// floor, chain), and the on-time lane order is (bin, id)-sorted by the ingest,
// so N changes only WHEN an item is verified, never what is accepted.
// verify_threads = 1 (the library default) is the pre-fix pipeline.
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
// ★ RAINDROP BACKFILL (RAIN-BACKFILL; gate ON only -- every piece below is
// unreachable with drops_floor_diff == 0, and a gate-OFF node counts the two
// new frames as an unknown Family-B opcode exactly as before). A raindrop is
// flooded once and never cached as a receipt, so a node that was partitioned,
// joined late or restarted never saw it and would harvest a different set. Now
// every admitted raindrop is also kept in a BOUNDED servable store (by interval,
// --drops-retain window); on HELLO each side pulls the other's inventory of its
// recent intervals (FB_GETDROPS n=0 -> FB_DROPINV) and fetches the ids it lacks
// (FB_GETDROPS n>0 -> FB_RECEIPTS, verified like a flood under the solicited
// credit); and drops_sync(lo, hi) -- called by the composition before it books
// a lane block -- asks every ready peer for its inventory of exactly [lo, hi),
// fetches what is missing and answers complete only when this node holds every
// raindrop every ready peer holds there (the composition HOLDs until then).
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
// stall withheld. A peer that never answers a PING (a pre-0x48 build) is never
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
#include <filesystem>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <random>
#include <set>
#include <string>
#include <thread>
#include <tuple>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <c2pool/v37/carrier_net.hpp>
#include <sharechain/v37/v37_hash.hpp>   // DROPS-HARDEN: the persisted store trailer (sha256d)
#include <c2pool/v37/carrier_supply.hpp>
#include <c2pool/v37/frame_vault.hpp>
#include "impl/xmr/wire/xmr_carrier_dos_budget.hpp"
#include "impl/xmr/coin/xmr_seedheight.hpp"
#include "xmr_relay_wire.hpp"
#include "xmr_relay_peerbook.hpp"   // RELAY-DISCOVERY
#include "xmr_receipt_mint.hpp"
#include "xmr_durable_order.hpp"   // REPAIR-CHAIN (F2-S)

// UP-GATE: a remote HELLO read before our own up event ran for that link waits
// for it (on_hello), and XmrRelayNode::set_test_up_delay_ms() exists.
#define C2POOL_XMR_RELAY_UP_GATE 1
// ★ RAIN-BACKFILL feature marker (drops_sync / drops_held / FB_GETDROPS + FB_DROPINV)
#define C2POOL_XMR_RAIN_BACKFILL 1
// RELAY-LIVENESS: FB_PING/FB_PONG keepalive + silence timeout
// (RelayOptions::keepalive_ms / silence_timeout_ms, RelayStats::silent_drops).
#define C2POOL_XMR_RELAY_LIVENESS 1

// Feature marker: NODE-NONCE (self-connection = SELF in the book, one link per node).
#define C2POOL_XMR_RELAY_NODE_NONCE 1
// DROPS-VERIFY-SCALE: RelayOptions::verify_threads workers, XmrRelayNode::verify_worker(),
// RelayStats::verify_threads / rx_unavail_parked (an rx-unavailable item is parked once).
#define C2POOL_XMR_RELAY_VERIFY_POOL 1
// DROPS-HARDEN: drops_fetch_ids bounded per id (drops_fetch_max_asks, then
// drops_fetch_slow_ms), drops_pin_forget(), the persisted raindrop store
// (drops_persist_path, drops_persist(), drops_load()).
#define C2POOL_XMR_DROPS_HARDEN 1
// DROPS-RETAIN (stagenet attempt 6, h=2220425): the servable raindrop store is
// sized by what this node still has to book, not by a count. L1: a floor
// (set_drops_floor_bin: frontier of the newest finalized lane block - 64) and a
// BYTE budget (RelayOptions::drops_store_bytes; drops_store_max is an optional
// count, 0 = none); L2: drops_pin_servable() (the winner pins only what it can
// serve) and drops_pin_retain()/drops_pin_release() (a pinned set is never
// evicted while its block is undecided here); the store persisted as per-bin
// append-only segments (<persist>.d/<bin>.seg), loaded newest-first up to the
// budget; drops_sync pages a truncated inventory per bin.
#define C2POOL_XMR_DROPS_RETAIN 1

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
    u64              bin = 0; // origin bin = the height of the block the share would become (the template / coinbase height; prev_id -> bin in the ChainView)
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
    // ★ DROPS-ENROL-TIDY (flip 1 only): the --drops-enrol set digest, sent in
    // HELLO (with a pool genesis) so a mismatch is refused by name. nullopt at flip 0.
    std::optional<bytes32> enrol_set_digest;
    // LANE-RULES (operator ruling R3): this node's lane-rules list, sent in HELLO
    // (with a pool genesis) and compared field by field with every peer's; the
    // same list's digest is folded into the on-chain pool_tag. nullopt = none.
    std::optional<::c2pool::v37n::xmr::lanerules::LaneRules> lane_rules;
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
    // DROPS-VERIFY-SCALE: verify worker threads (each runs process(); the RxFn
    // may read verify_worker() to hash on its own VM). 1 = the pre-fix single
    // worker (the library default, every KAT byte-identical); the daemon passes
    // --relay-verify-threads (auto = clamp(cores/2, 2, 8) minus --mine threads).
    // Clamped to [1, kMaxVerifyThreads] at start(): up to N DoS tokens may be
    // outstanding per peer, inside the per-peer burst (20).
    std::size_t verify_threads = 1;
    u32         unresolved_patience_ms = 30000;
    // ★ HOLD-ROUND-2 (B): shares the verdict classifies AHEAD (the sender booked
    // a lane block this node has not yet) wait for this node's share state to
    // advance (notify_share_state_advanced), not for a clock: bounded per peer
    // and in total, the oldest evicted first (dropped, never a strike).
    std::size_t share_ahead_per_peer = 512;   // per sender NODE (V4: inv_node, survives a reconnect)
    std::size_t share_ahead_max = 4096;
    std::size_t cache_max = 65536;                // verified receipts kept (= the dedup set)
    u32         repair_state_timeout_ms = 20000;
    // REPAIR-PAGE: ids per GETORDER page of a relay repair. Pre-fix every page
    // asked kCtrlMaxIdsPerOrder (4096 ids x 40 B = ~160 KiB) under the fixed
    // 5 s request timeout; on a slow winner->loser link (~64 kbit/s) that page
    // takes ~20 s, every answer came late, the repair never completed and the
    // re-asks piled up on the winner's socket until SO_SNDTIMEO dropped it.
    // A repair now asks repair_order_page_ids (~10 KiB) of a peer it has no
    // measure of, and grows the page, up to repair_order_page_max_ids, from
    // any ORDER answer of that peer (the HELLO backfill included) that came
    // back within a quarter of the request timeout: to what that round trip
    // fits in the quarter (x16 at most per answer). A fast link is at the cap
    // before the repair starts (the base page count, inside the server's
    // token burst); a slow one stays small. A page that times out halves it
    // (floor 16).
    // 0 = kCtrlMaxIdsPerOrder. No wire change: the server already clamps and
    // paginates (p_served), and the order is re-asked from the cursor.
    u32         repair_order_page_ids = 256;
    u32         repair_order_page_max_ids = kCtrlMaxIdsPerOrder;
    // Lane positions one receipt may span (fee model S3: 2 = (payee, donation)
    // split; 1 = the gate-OFF / master rule). Bounds the repair density check.
    u32         max_pushes_per_receipt = 1;
    // REPAIR-CHAIN (capstone attempt 4): serve GETORDER below the vault horizon
    // from this node's DURABLE lane order (xmr_durable_order.hpp sidecars at
    // deep_order_path + ".order"/".digest", frames read back from
    // receipts_log_path), and, as a requester, WALK a peer whose digest at a0
    // differs DOWN (q = a0 - step x 2^k, aligned to step, down to 0 = the whole
    // order) to the highest position where our own / a shadow's digest equals
    // the peer's, then ask [q, P). false (the struct default) = RC5 byte for
    // byte: vault-only serving, a differing peer is set aside as DEEP at once.
    bool        deep_order = false;
    std::string deep_order_path;                 // "" = no durable order (serving side off)
    std::string receipts_log_path;               // the ingest's durable log (deep frames)
    u64         deep_probe_step = 64;            // G: positions (and shadow checkpoint spacing)
    // ★ HOLD-ROUND-3 F3: the durable order serves the last deep_order_retain
    // positions only (0 = all; the daemon's mainnet default is 1,000,000) and a
    // WHOLE order [0, P) is served to a peer that asks it twice (the second ask
    // is deliberate), under a per-peer budget: ids_factor x P + one page ids
    // per (peer, P), cuts_per_hour distinct cuts per rolling hour (see
    // DeepServeBudget). No wire change.
    u64         deep_order_retain = 0;
    u64         deep_order_retain_slab = 0;      // appends between prunes (0 = max(1024, R/16); KAT knob)
    u64         deep_order_ids_factor = 2;
    u64         deep_order_budget_page_ids = kCtrlMaxIdsPerOrder;   // + one page of slack per cut (KAT knob)
    u32         deep_order_cuts_per_hour = 8;
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
    // ★ RAIN-BACKFILL (gate ON only; inert with drops_floor_diff == 0)
    // ★ DROPS-RETAIN: until the daemon sets a floor (set_drops_floor_bin) the
    // legacy window evicts intervals below tip - drops_retain_bins; once a
    // floor is set it alone decides (a slow pool's range is older than any
    // fixed tip window). Either way a RETAINED (pinned) raindrop stays.
    u64         drops_retain_bins = 512;                     // intervals below the tip kept servable (no floor set)
    // ★ DROPS-RETAIN (L1): the hard bound is BYTES (raw receipt + ~160 B of
    // index per raindrop). Over it the oldest unretained bins are evicted and
    // counted (drops_store_overflow_bins, loud): the winner then pins only what
    // it can serve, so an overflow costs raindrop credit, never a split.
    // drops_store_max: an optional COUNT bound on top (0 = none; it was 65536
    // = ~73 min at 15 raindrops/s, younger than any D_conf-60 range: attempt 6).
    std::size_t drops_store_max = 0;
    u64         drops_store_bytes = 512ull << 20;            // 512 MiB (--drops-store-bytes)
    u64         drops_hello_bins = 64;                     // HELLO: pull the peer's inventory of [tip - this, tip + 2)
    u32         drops_inv_retry_ms = 2000;                   // re-ask an unanswered inventory after this
    u32         drops_fetch_retry_ms = 2000;                 // re-ask still-missing ids after this
    u32         drops_fetch_max_asks = 8;                    // asks of one peer for its missing ids before it is set aside
    // ★ HOLD-ROUND-2 (C): cursor pages of one bin's inventory asked before an
    // unanswering (old) server's unpaged page is kept; and the bound of the set
    // of fetched-but-inadmissible raindrop ids (counted as held: never re-asked).
    u32         drops_inv_page_max_asks = 3;
    std::size_t drops_refused_max = 262144;
    // ★ DROPS-HARDEN (d1): a pinned id still missing after drops_fetch_max_asks
    // asks is re-asked no more often than this (never forever at the fast rate)
    u32         drops_fetch_slow_ms = 60000;
    // ★ DROPS-HARDEN (d4): the servable raindrop store survives a restart.
    // ★ DROPS-RETAIN: as per-bin append-only segments <path>.d/<bin>.seg (one
    // header + checksummed records; a changed bin appends, a partly evicted bin
    // is rewritten tmp + fsync + rename, an evicted bin is unlinked); a legacy
    // whole-store file at <path> is read once (newest bins first, up to the
    // budget) and migrated. "" = in-memory only (the library default).
    std::string drops_persist_path;
    u32         drops_persist_ms = 2000;                     // snapshot a changed store at most this often
    // RELAY-LIVENESS: PING every ready link this often (0 = keepalive OFF: no
    // PING sent or answered, no silence timeout); drop + redial a link whose
    // keepalive-speaking peer sent nothing for silence_timeout_ms (0 = never).
    u32         keepalive_ms = 5000;
    u32         silence_timeout_ms = 25000;
    // RELAY-SEND-QUEUE: every send is queued per connection and written by that
    // connection's own writer thread (carrier_net.hpp), so no reader, verify
    // worker, maintenance tick or stratum path ever blocks on a peer's socket.
    // A peer whose queue would exceed this many bytes is dropped (not the node
    // stalled). 0 = the legacy synchronous send path.
    std::size_t send_queue_bytes = 16u << 20;
    // RELAY-DISCOVERY (FB_GETADDR/FB_ADDR 0x4c/0x4d). OFF here (the library
    // default keeps every pre-discovery KAT byte-identical: 0x4c/0x4d are then
    // fb_unknown, nothing is asked or dialed beyond `peers`); the daemon turns
    // it ON (--relay-discovery on, the CLI default).
    bool        discovery = false;
    std::size_t max_outbound = 8;                 // dialed links (peers + learned) the node keeps up
    // The SEED seam: addresses dialed as CANDIDATES at start (the built-in
    // bootstrap list feeds this; --relay-peer stays a permanent dial target).
    std::vector<std::pair<std::string, u16>> seeds;
    // NODE-NONCE: this machine's addresses (numeric; the daemon gathers them).
    // With the listen port they are OUR relay address: never dialed, never
    // learned, never handed out (the listen host itself always counts).
    std::vector<std::string> self_hosts;
    std::vector<PeerRecord> book_load;            // persisted book (core::AddrStore) loaded at start
    std::function<void(const std::vector<PeerRecord>&)> book_save;   // persist hook (dirty book, every book_save_ms + stop)
    PeerBook::Limits book_limits{};
    u32         book_save_ms = 15000;
    u32         addr_reask_ms = 20000;            // re-ask GETADDR of a ready peer while below max_outbound
    u32         addr_answer_min_ms = 5000;        // answer at most one GETADDR per peer per this
    u16         addr_want = 64;                   // entries asked per GETADDR
    std::size_t addr_answer_max = 64;             // entries per FB_ADDR answer
    std::size_t addr_learn_per_answer = 64;       // entries taken from one FB_ADDR
    std::size_t addr_learn_per_peer = 256;        // entries taken from one connection in total
    u32         connect_timeout_ms = 3000;        // bound connect(2) (discovery ON only)
};

struct RelayStats {
    std::atomic<u64> hello_sent{0}, hello_ok{0}, hello_rejected{0}, hello_timeout{0}, pre_hello_dropped{0};
    std::atomic<u64> hello_tag_mismatch{0};       // POOL-ID: HELLOs refused as TAG_MISMATCH (also in hello_rejected)
    std::atomic<u64> hello_rules_mismatch{0};     // LANE-RULES: HELLOs refused as LANE_RULES_MISMATCH (also in hello_rejected)
    std::atomic<u64> fa_ignored{0}, fb_unknown{0}, malformed{0}, wrong_chain{0};
    std::atomic<u64> rx_receipts{0}, dup{0}, queue_dropped{0}, unresolved_dropped{0}, expired{0};
    std::atomic<u64> structural{0}, rx_deferred{0}, rx_evals{0}, rx_valid{0}, rx_invalid{0}, rx_unavailable{0}, bans{0};
    // DROPS-VERIFY-SCALE: verify workers running; items whose RandomX engine was
    // unavailable (seed being keyed during a switch) PARKED once for a retry
    // instead of forgotten (rx_unavailable counts only the ones finally dropped).
    std::atomic<u64> verify_threads{0}, rx_unavail_parked{0};
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
    // SHARE-LEVEL CANONICAL COINBASE: receipts refused / parked / undecided at the verdict
    std::atomic<u64> share_refused{0}, share_parked{0}, share_undecided_dropped{0}, share_undecided_trusted{0};
    // ★ HOLD-ROUND-2 (B): lane-prefix skew at the verdict (never a strike)
    std::atomic<u64> share_skew_ahead{0}, share_skew_behind{0}, share_late{0}, share_ahead_rejudged{0}, share_ahead_evicted{0};
    // ★ HOLD-ROUND-3 (F4): prefix-hash mismatches with no V37N base: parked (never struck), dropped after the re-judge bound
    std::atomic<u64> share_unbased_parked{0}, share_unbased_expired{0};
    std::atomic<u64> won_reoffer_skipped{0};   // RELAY-SEND-QUEUE: not re-offered, the peer node provably holds it
    std::atomic<u64> won_held_confirmed{0};    // RELAY-SEND-QUEUE: re-offered frames a later PONG proved read
    std::atomic<u64> won_asked{0}, won_served{0}, won_unknown{0}, won_solicited_rx{0};   // ★ DROPS-RESTART (FB_GETWON)
    // ★ RAIN-BACKFILL (gate ON only; all stay 0 with drops_floor_diff == 0)
    std::atomic<u64> drops_inv_tx{0}, drops_inv_rx{0}, drops_invreq_tx{0}, drops_invreq_rx{0};
    std::atomic<u64> drops_fetch_tx{0}, drops_ids_asked{0}, drops_fetchreq_rx{0}, drops_served{0}, drops_backfilled{0};
    std::atomic<u64> drops_sync_calls{0}, drops_sync_pending{0}, drops_sync_complete{0}, drops_peer_setaside{0};
    std::atomic<u64> drops_pin_fetch_ids{0};   // ★ DROPS-SET-PIN: set members asked for by id
    // ★ DROPS-HARDEN: pinned ids past drops_fetch_max_asks (slow re-ask), pruned
    // ask entries; the persisted store (snapshots written / failed, entries loaded)
    std::atomic<u64> drops_pin_capped{0}, drops_pin_slow_asks{0}, drops_pin_pruned{0};
    std::atomic<u64> drops_pin_local{0};   // members handed to the harvest from this node's own store
    std::atomic<u64> drops_persist_writes{0}, drops_persist_fail{0}, drops_persist_loaded{0};
    // ★ DROPS-RETAIN: bins evicted below the floor / the legacy window, bins
    // evicted over the budget (overflow: loud), raindrops kept by a pin past an
    // eviction, candidate set members skipped as unservable (L2a), segment
    // appends / rewrites / unlinks / torn tails, bins skipped at load (budget),
    // inventories paged per bin (K6)
    std::atomic<u64> drops_evict_floor_bins{0}, drops_store_overflow_bins{0}, drops_evict_kept_pinned{0};
    std::atomic<u64> drops_set_unservable_skipped{0};
    std::atomic<u64> drops_seg_appends{0}, drops_seg_rewrites{0}, drops_seg_unlinks{0}, drops_seg_torn{0};
    std::atomic<u64> drops_load_over_budget{0}, drops_inv_paged{0};
    // ★ HOLD-ROUND-2 (C): one-bin inventory pages by cursor (asked / served /
    // received / given up on an old server), fetched ids that were not
    // admissible here (refused: counted held), and inventories whose fetch-at-
    // once hit the per-peer ask budget (keyed by node, kept across reconnects)
    std::atomic<u64> drops_inv_pages_tx{0}, drops_inv_pages_served{0}, drops_inv_pages_rx{0}, drops_inv_page_gaveup{0};
    std::atomic<u64> drops_refused{0}, drops_refused_held{0}, drops_inv_budget_setaside{0};
    // REPAIR-HORIZON: BELOW_HORIZON answers that raised a repair's start and
    // re-asked (instead of setting the peer aside); prefix probes whose digest
    // at a0 matched ours / was unknown there; peers proven DEEP (divergence
    // below their horizon); receipts re-offered on HELLO because still unpushed.
    std::atomic<u64> repair_horizon_rearm{0}, repair_prefix_ok{0}, repair_prefix_unknown{0}, repair_deep{0};
    // REPAIR-CHAIN: walk probes asked, walks that found an equal point (q > 0)
    // or fell back to the whole order (q = 0), repairs made Ready through a
    // walk, and walks ended by an RC5 peer (BELOW_HORIZON on a walk probe) or
    // by a lineage that fails the gate (-> DEEP, loud, as before).
    std::atomic<u64> repair_deep_probe{0}, repair_deep_equal{0}, repair_deep_full{0}, repair_deep_ready{0};
    std::atomic<u64> repair_deep_rc5{0}, repair_deep_lineage{0};
    // ★ HOLD-ROUND-3 F3a (requester): repairs switched to the WHOLE-ORDER
    // fallback (no verified base for [0, a0): by the caller, or by a suffix
    // replay that reached the spine from no base), whole-order asks re-asked
    // once after a first refusal, refusals that set a peer aside, repairs made
    // Ready through the fallback, and fallbacks every peer refused (the loud
    // retention alarm; the block holds).
    std::atomic<u64> repair_full_required{0}, repair_full_reask{0}, repair_full_refused{0}, repair_full_ready{0}, repair_full_exhausted{0};
    // ★ HOLD-ROUND-3 F3b (server): whole orders served from the durable order,
    // and deep asks refused: the routine first [0, P) ask, over the per-peer
    // ids / cuts budget, or below our retention window (pruned here).
    std::atomic<u64> deep_serve_cuts{0}, deep_serve_first_ask{0}, deep_serve_over_budget{0}, deep_serve_below_retention{0};
    std::atomic<u64> reoffer_unpushed{0};
    // REPAIR-PAGE: repair GETORDER pages asked, the largest page asked (ids),
    // pages that timed out (the page was halved) and pages that grew it.
    std::atomic<u64> repair_order_pages{0}, repair_order_page_max{0}, repair_page_timeouts{0}, repair_page_grown{0};
    // REPAIR-PAGE liveness (#1808 review): non-final pages too thin to refresh
    // the Ordering clock, and serving peers set aside by the total Ordering cap.
    std::atomic<u64> repair_order_thin{0}, repair_order_capped{0};
    // RELAY-LIVENESS: keepalive frames, links dropped as SILENT, peers that
    // never answered a PING (pre-0x48 builds: silence not enforced), and
    // maintenance gaps that re-armed every link's clock.
    std::atomic<u64> ping_tx{0}, ping_rx{0}, pong_tx{0}, pong_rx{0}, silent_drops{0}, ka_legacy{0}, ka_rearm{0};
    // RELAY-DISCOVERY
    std::atomic<u64> getaddr_tx{0}, getaddr_rx{0}, getaddr_throttled{0}, addr_tx{0}, addr_rx{0}, addr_unsolicited{0};
    std::atomic<u64> addr_learned{0}, addr_ignored{0}, disc_dialed{0}, disc_dial_ok{0}, disc_dup_dropped{0};
    std::atomic<u64> disc_bad{0}, disc_self{0}, disc_saves{0}, disc_expired{0};
    // NODE-NONCE: HELLOs refused as our own nonce (both ends of a self-dial count),
    // dials / learns skipped as our own address, same-dialer duplicates left to the peer.
    std::atomic<u64> self_conn{0}, self_skipped{0}, dup_deferred{0};
};

// ★ RAIN-BACKFILL: the composition's view of one interval range.
struct DropsSync {
    bool        complete = true;
    std::size_t peers = 0, peers_ok = 0, missing = 0, set_aside = 0;
    std::string why;
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
        std::random_device rd;   // NODE-NONCE: a random 64-bit per-process nonce, never 0
        do {
            m_nonce = ((static_cast<u64>(rd()) << 32) | rd()) ^
                      static_cast<u64>(Clock::now().time_since_epoch().count());
        } while (m_nonce == 0);
        m_solicited = static_cast<double>(m_o.solicited_credits);
        // REPAIR-CHAIN (F2-S): open (truncate) the durable-order sidecars BEFORE
        // the boot reload re-pushes the receipts log through on_pushed, which
        // rebuilds them; then the vault serves below its horizon from them.
        if (m_o.deep_order && !m_o.deep_order_path.empty()) {
            std::string why;
            if (m_dorder.open(m_o.deep_order_path, m_o.receipts_log_path, &why)) {
                m_dorder.set_verify([](const std::vector<u8>& f, const bytes32& id) {
                    FbReceipt r; return decode_fb_receipt(f, r) && receipt_id(r) == id;
                });
                m_dorder.set_retain(m_o.deep_order_retain, m_o.deep_order_retain_slab);   // F3b retention (0 = everything)
                {
                    DeepServeBudget::Options bo;
                    bo.ids_factor = m_o.deep_order_ids_factor ? m_o.deep_order_ids_factor : 2;
                    bo.page_ids = m_o.deep_order_budget_page_ids;
                    bo.cuts_per_hour = m_o.deep_order_cuts_per_hour ? m_o.deep_order_cuts_per_hour : 8;
                    m_deep_budget.set_options(bo);
                }
                ::c2pool::v37n::FrameVaultDeep d;
                d.order = [this](std::uint32_t chain, std::uint64_t a, std::uint64_t p, std::size_t max_ids,
                                 ::c2pool::v37n::VaultOrder& out) -> bool {
                    if (chain != m_o.chain) return false;
                    out.ids.clear();
                    const u64 low = m_dorder.lowest_retained();
                    if (a == p) {   // a walk probe below our horizon: its answer is our digest at a (spine probe)
                        if (a > m_dorder.next_pos()) return false;
                        if (a < low) { m_st.deep_serve_below_retention++; return false; }   // F3b: pruned here -> BELOW_HORIZON
                        out.p_served = a; return true;
                    }
                    // ★ HOLD-ROUND-3 F3b: a deep page is served under the per-peer budget,
                    // not a 30-s walker mark. [0, P) is what EVERY repair asks first: that
                    // first ask stays BELOW_HORIZON (the requester re-arms to our horizon
                    // and asks a suffix, O(horizon) ids, exactly as before); the SECOND
                    // [0, P) ask of the same peer for the same P is deliberate (its walk
                    // reached q = 0, or its suffix replay found no base) and is served in
                    // pages while within our retention and its budget.
                    const PeerId peer = t_serving_peer;
                    if (a < low) {   // below our retention window: refused, loudly (never a silent hold on the asker's side either)
                        m_st.deep_serve_below_retention++;
                        // the same u64 the vault already states: what we retain from here = the durable order's floor
                        // (the asker re-arms its suffix to it and its alarm names it); no wire format change
                        out.lowest_retained = std::max(out.lowest_retained, low);
                        bool first = false;
                        {
                            std::lock_guard<std::mutex> lk(m_deep_log_mtx);
                            if (m_deep_retention_logged.size() > 4096) m_deep_retention_logged.clear();
                            first = m_deep_retention_logged.insert(std::make_pair(peer, p)).second;
                        }
                        if (first)
                            this->log("relay-deep-serve: ALARM peer " + std::to_string(peer) + " asked order positions [" + std::to_string(a) + "," +
                                std::to_string(p) + ") below our retention: lowest retained " + std::to_string(low) + " (--relay-order-retain " +
                                std::to_string(m_dorder.retain()) + " positions, lane at " + std::to_string(m_dorder.next_pos()) +
                                ") -- REFUSED (BELOW_HORIZON); that peer needs a longer-retaining peer or the cold-boot path");
                        return false;
                    }
                    const auto ask = m_deep_budget.ask(peer, a, p, max_ids);
                    if (ask.v != DeepServeBudget::Verdict::Serve) {
                        if (ask.v == DeepServeBudget::Verdict::FirstAsk) m_st.deep_serve_first_ask++;
                        else {
                            m_st.deep_serve_over_budget++;
                            if (m_deep_budget.note_logged(peer, p, ask.v))
                                this->log("relay-deep-serve: peer " + std::to_string(peer) + " asked deep order [" + std::to_string(a) + "," + std::to_string(p) +
                                    ") -- REFUSED, " + DeepServeBudget::name(ask.v) + " (ids served " + std::to_string(ask.ids_used) + " of " +
                                    std::to_string(ask.ids_max) + " for this cut; cuts this hour " + std::to_string(ask.cuts_hour) + " of " +
                                    std::to_string(m_deep_budget.options().cuts_per_hour) + ")");
                        }
                        return false;
                    }
                    std::vector<std::pair<u64, bytes32>> ids; u64 ps = a;
                    if (!m_dorder.order_page(a, p, max_ids, ids, ps)) return false;
                    for (const auto& [pos, id] : ids) out.ids.push_back(::c2pool::v37n::VaultOrderId{pos, id});
                    out.p_served = ps;
                    m_deep_budget.served(peer, p, ids.size());
                    if (ask.first_page && a == 0) {
                        m_st.deep_serve_cuts++;
                        this->log("relay-deep-serve: peer " + std::to_string(peer) + " asked the WHOLE order [0," + std::to_string(p) +
                            ") a second time -> serving it from the durable order in pages of <= " + std::to_string(max_ids) +
                            " ids (budget: cut " + std::to_string(ask.cuts_hour) + "/" + std::to_string(m_deep_budget.options().cuts_per_hour) +
                            " this hour, <= " + std::to_string(ask.ids_max) + " ids; retention lowest=" + std::to_string(low) + ")");
                    }
                    return true;
                };
                d.frame = [this](const bytes32& id, std::vector<std::uint8_t>& f) { return m_dorder.frame(id, f); };
                m_vault.set_deep(std::move(d));
            } else if (m_log) {
                m_log("relay: REPAIR-CHAIN durable order DISABLED (" + why + "): vault-only serving (RC5)");
            }
        }
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
            return digest_at_deep(pos);   // REPAIR-CHAIN: below one horizon from the durable order (off = memory only)
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
            t_serving_peer = p;   // REPAIR-CHAIN: the deep source knows who asks (reader thread, synchronous)
            m_serve->on_control(p, f);
            t_serving_peer = 0;
            m_fetch->on_control(p, f);
        });
        m_net.set_on_peer_event([this](PeerId p, bool up) { on_peer_event(p, up); });
        m_net.set_log([this](const std::string& s) { log("relay: " + s); });
        m_net.set_send_queue(m_o.send_queue_bytes);   // RELAY-SEND-QUEUE (0 = synchronous, legacy)

        if (m_o.listen) {
            if (!m_net.listen(m_o.listen_host, m_o.listen_port)) {
                why = "relay: cannot listen on " + m_o.listen_host + ":" + std::to_string(m_o.listen_port);
                return false;
            }
        }
        if (m_o.listen) {   // NODE-NONCE: our own relay addresses (listen host + this machine's)
            const u16 lp = m_net.listen_port();
            const bool wild = m_o.listen_host.empty() || m_o.listen_host == "0.0.0.0";
            if (!wild) m_self_keys.insert(peer_key(m_o.listen_host, lp));
            if (wild || m_o.listen_host == "127.0.0.1") m_self_keys.insert(peer_key("127.0.0.1", lp));
            if (wild) for (const auto& h : m_o.self_hosts) m_self_keys.insert(peer_key(h, lp));
        }
        {
            std::lock_guard<std::mutex> lk(m_tmtx);
            for (const auto& [h, pt] : m_o.peers) {
                if (m_self_keys.count(peer_key(h, pt))) {   // NODE-NONCE: --relay-peer = this node
                    m_st.self_skipped++;
                    log("relay: --relay-peer " + peer_key(h, pt) + " is THIS node (our listen address) -> never dialed");
                    continue;
                }
                m_targets.push_back(Target{h, pt, 0, Clock::now(), 1});
            }
        }
        if (m_o.discovery) {   // RELAY-DISCOVERY: seed = stored book + seed list (+ --relay-peer, marked good on HELLO)
            m_book.set_limits(m_o.book_limits);
            const u64 now = wall_s();
            for (const auto& k : m_self_keys) {   // NODE-NONCE: never learned / good / handed out
                const auto c = k.rfind(':');
                m_book.mark_self(k.substr(0, c), static_cast<u16>(std::stoul(k.substr(c + 1))));
            }
            m_book.load(m_o.book_load, now);
            for (const auto& [h, pt] : m_o.seeds) m_book.learn(h, pt, now, now);
            m_book.take_dirty();
            if (m_o.connect_timeout_ms) m_net.set_connect_timeout(std::chrono::milliseconds(m_o.connect_timeout_ms));
            log("relay-disc: discovery ON book=" + std::to_string(m_book.size()) + " (good=" + std::to_string(m_book.good()) +
                ", loaded=" + std::to_string(m_o.book_load.size()) + ") seeds=" + std::to_string(m_o.seeds.size()) +
                " relay-peers=" + std::to_string(m_o.peers.size()) + " max-outbound=" + std::to_string(m_o.max_outbound));
        }
        m_running = true;
        {   // DROPS-VERIFY-SCALE: N verify workers, each with its own index (verify_worker())
            const std::size_t n = std::clamp<std::size_t>(m_o.verify_threads, 1, kMaxVerifyThreads);
            m_st.verify_threads = n;
            for (std::size_t i = 0; i < n; ++i)
                m_verify_threads.emplace_back([this, i] { t_verify_worker = static_cast<int>(i); verify_loop(); });
        }
        m_maint_thread  = std::thread([this] { maint_loop(); });
        return true;
    }

    void stop() {
        if (!m_running.exchange(false)) return;
        m_qcv.notify_all();
        for (auto& t : m_verify_threads) if (t.joinable()) t.join();
        m_verify_threads.clear();
        if (m_maint_thread.joinable()) m_maint_thread.join();
        m_net.stop();
        if (m_o.discovery) save_book(true);   // RELAY-DISCOVERY: the book survives the restart
        drops_persist();                      // ★ DROPS-HARDEN (d4): the raindrop store too
    }

    // DROPS-VERIFY-SCALE: the calling verify worker's index in [0, verify_threads)
    // (-1 on any other thread). The daemon's RxFn hashes on that worker's VM.
    static constexpr std::size_t kMaxVerifyThreads = 16;
    static int verify_worker() noexcept { return t_verify_worker; }

    u16 listen_port() const { return m_net.listen_port(); }
    u64 node_nonce() const { return m_nonce; }
    const std::set<std::string>& self_keys() const { return m_self_keys; }   // NODE-NONCE (fixed after start)
    const RelayOptions& options() const { return m_o; }
    const RelayStats& stats() const { return m_st; }
    ::c2pool::v37n::FrameVault& vault() { return m_vault; }
    SupplyRequester* requester() { return m_fetch.get(); }
    SupplyService* supplier() { return m_serve.get(); }

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
        drop_store_put(a.id, a.bin, a.raw, a.pow);   // ★ RAIN-BACKFILL: servable
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

    // ── ★ RAIN-BACKFILL: is this node's raindrop set for [lo, hi) complete? ──
    // Main thread (the composition, before it books a lane block whose harvest
    // settles [lo, hi)). Asks every ready peer for its inventory of exactly this
    // range (once, re-asked if unanswered), fetches every id a peer holds that
    // this node does not, and answers complete ONLY when, for every ready peer,
    // every id of its inventory is held here (or that peer failed to serve its
    // own inventory drops_fetch_max_asks times: set aside, counted, logged). No
    // ready peer: complete only for a node that never had one and dials nobody
    // (a lone node); a partitioned node HOLDs. Gate OFF: always complete, no I/O.
    DropsSync drops_sync(u64 lo, u64 hi) {
        DropsSync out;
        if (!m_o.drops_floor_diff || hi <= lo) return out;
        if (hi - lo > kDropsMaxSpan) lo = hi - kDropsMaxSpan;
        m_st.drops_sync_calls++;
        const auto peers = ready_peers();
        out.peers = peers.size();
        if (peers.empty()) {
            if (m_drop_had_peer.load() || !m_o.peers.empty()) {
                out.complete = false; out.why = "no ready relay peer to confirm the raindrop set";
                m_st.drops_sync_pending++;
            } else m_st.drops_sync_complete++;
            return out;
        }
        const auto now = Clock::now();
        SyncWork work;
        std::vector<std::pair<PeerId, u64>> keyed;   // HOLD-ROUND-2 (C3): (connection, node key), outside m_dsmtx
        for (PeerId p : peers) keyed.emplace_back(p, inv_node(p));
        {
            std::lock_guard<std::mutex> lk(m_dsmtx);
            for (const auto& [p, node] : keyed)
                if (drops_sync_step_locked(p, node, lo, hi, now, out, work)) ++out.peers_ok;
        }
        for (const auto& [p, l, h] : work.ask_inv) send_drop_invreq(p, l, h);
        for (const auto& [p, l, after] : work.ask_page) send_drop_page(p, l, after);
        for (auto& [p, l, h, ids] : work.fetch) send_drop_fetch(p, l, h, ids);
        out.complete = (out.peers_ok == out.peers);
        if (!out.complete) {
            m_st.drops_sync_pending++;
            out.why = std::to_string(out.peers - out.peers_ok) + "/" + std::to_string(out.peers) + " peer(s) unconfirmed, " +
                      std::to_string(out.missing) + " raindrop(s) missing";
        } else m_st.drops_sync_complete++;
        return out;
    }
    // ── ★ DROPS-SET-PIN: fetch the named raindrops (a carried set's members this
    // node's harvest does not hold). Main thread. Asks `hint` (the peer the
    // frame came from: the winner holds every member by construction) first,
    // then every ready peer after drops_fetch_retry_ms; an id is re-asked no
    // more often than that. An id seen here (dedup set) but asked for anyway is
    // forgotten first, so the served copy is admitted (the caller's harvest
    // lacks it). Answers are admitted through admit_drop (PoW + ctx verified).
    // Returns the number of fetch frames sent. Gate OFF: nothing.
    // [lo, hi) = the block's range (FB_GETDROPS carries a non-empty range; a
    // by-id fetch is served by id whatever it says).
    std::size_t drops_fetch_ids(const std::vector<bytes32>& ids, PeerId hint, u64 lo, u64 hi) {
        if (!m_o.drops_floor_diff || ids.empty()) return 0;
        if (hi <= lo) hi = lo + 1;
        if (hi - lo > kDropsMaxSpan) lo = hi - kDropsMaxSpan;
        const auto now = Clock::now();
        const auto retry = std::chrono::milliseconds(m_o.drops_fetch_retry_ms);
        std::vector<bytes32> first, again;
        std::vector<Admitted> local;
        {
            std::lock_guard<std::mutex> lk(m_dsmtx);
            // ★ DROPS-HARDEN (d1): at most drops_fetch_max_asks fast asks per id
            // (each reaching every ready peer at most once), then one slow
            // re-ask per drops_fetch_slow_ms -- an unservable set never keeps
            // the fast rate forever. An entry leaves m_pin_asked when its id is
            // admitted (admit_drop) or the caller forgets it (drops_pin_forget).
            const auto slow = std::chrono::milliseconds(m_o.drops_fetch_slow_ms);
            for (const auto& id : ids) {
                auto it = m_pin_asked.find(id);
                if (it == m_pin_asked.end()) { m_pin_asked.emplace(id, std::make_pair(now, 1u)); first.push_back(id); continue; }
                const bool capped = it->second.second >= m_o.drops_fetch_max_asks;
                if (now - it->second.first < (capped ? slow : retry)) continue;
                if (capped) m_st.drops_pin_slow_asks++;
                else if (it->second.second + 1 == m_o.drops_fetch_max_asks) m_st.drops_pin_capped++;
                it->second.first = now; ++it->second.second;
                again.push_back(id);
            }
            for (const auto& id : ids) m_drop_want[id] = now;   // the answer is SOLICITED (a deferred ctx is waited for)
            // ★ DROPS-HARDEN (d4): a member this node's STORE holds (e.g. reloaded
            // from lane<N>.drops after a restart) but its harvest lacks is handed
            // to the harvest from the store (verified when first admitted), never
            // asked of a peer -- a restarted winner serves its own members.
            for (auto* v : {&first, &again}) {
                std::vector<bytes32> rest;
                for (const auto& id : *v) {
                    const auto bi = m_drop_store_id.find(id);
                    const auto pi = m_drop_pow.find(id);
                    const auto si = bi == m_drop_store_id.end() ? m_drop_store.end() : m_drop_store.find(bi->second);
                    Admitted a;
                    if (pi == m_drop_pow.end() || si == m_drop_store.end() || !si->second.count(id) ||
                        !decode_fb_receipt(si->second.at(id), a.r)) { rest.push_back(id); continue; }
                    a.id = id; a.raw = si->second.at(id); a.bin = bi->second; a.drop = true; a.pow = pi->second;
                    local.push_back(std::move(a));
                    m_pin_asked.erase(id);
                }
                v->swap(rest);
            }
        }
        if (!local.empty()) {
            m_st.drops_pin_local += local.size();
            std::lock_guard<std::mutex> lk(m_amtx);
            for (auto& a : local) m_drops.push_back(std::move(a));
        }
        if (first.empty() && again.empty()) return 0;
        {
            std::lock_guard<std::mutex> lk(m_mtx);   // forget the dedup entry: the caller does not hold its bytes
            for (const auto* v : {&first, &again})
                for (const auto& id : *v) m_drop_seen.erase(id);
        }
        const auto peers = ready_peers();
        const bool hint_ready = hint && std::find(peers.begin(), peers.end(), hint) != peers.end();
        std::size_t sent = 0;
        auto ask = [&](PeerId p, const std::vector<bytes32>& v) {
            const u64 before = m_st.drops_fetch_tx.load();
            send_drop_fetch(p, lo, hi, v);
            sent += m_st.drops_fetch_tx.load() - before;
        };
        if (!first.empty()) {
            if (hint_ready) ask(hint, first);
            else for (PeerId p : peers) ask(p, first);
        }
        if (!again.empty()) for (PeerId p : peers) ask(p, again);
        m_st.drops_pin_fetch_ids += first.size() + again.size();
        return sent;
    }
    // the ids a set fetch asked for that are not admitted yet (diagnostic)
    std::size_t drops_pin_asked() const { std::lock_guard<std::mutex> lk(m_dsmtx); return m_pin_asked.size(); }
    // ★ DROPS-HARDEN (d1): the caller no longer wants these ids (the set is
    // complete, or its block left the pending set): drop their ask state.
    std::size_t drops_pin_forget(const std::vector<bytes32>& ids) {
        std::lock_guard<std::mutex> lk(m_dsmtx);
        std::size_t n = 0;
        for (const auto& id : ids) n += m_pin_asked.erase(id);
        m_st.drops_pin_pruned += n;
        return n;
    }
    std::size_t drops_store_size() const { std::lock_guard<std::mutex> lk(m_dsmtx); return m_drop_store_id.size(); }
    // The raindrop ids this node holds (servable) for [lo, hi), sorted (diagnostic / KAT).
    std::vector<bytes32> drops_held(u64 lo, u64 hi) const {
        std::lock_guard<std::mutex> lk(m_dsmtx);
        std::vector<bytes32> v;
        for (auto it = m_drop_store.lower_bound(lo); it != m_drop_store.end() && it->first < hi; ++it)
            for (const auto& [id, raw] : it->second) { (void)raw; v.push_back(id); }
        std::sort(v.begin(), v.end());
        return v;
    }
    // ── ★ DROPS-RETAIN (L2a): the winner pins only what it can SERVE. Of the
    // candidate ids (its harvest over the range, ascending), keep those this
    // store holds, at most `cap` (the smallest: deterministic), and retain them
    // under `key` in the same critical section (no eviction can slip between
    // the check and the pin). `skipped` = candidates not servable here.
    std::vector<bytes32> drops_pin_servable(const std::string& key, std::vector<bytes32> candidates, std::size_t cap,
                                            std::size_t* skipped = nullptr, bool* capped = nullptr) {
        std::sort(candidates.begin(), candidates.end());
        candidates.erase(std::unique(candidates.begin(), candidates.end()), candidates.end());
        std::vector<bytes32> out;
        std::size_t skip = 0;
        bool over = false;
        std::lock_guard<std::mutex> lk(m_dsmtx);
        for (const auto& id : candidates) {
            if (!m_drop_store_id.count(id)) { ++skip; continue; }
            if (out.size() < cap) out.push_back(id); else over = true;
        }
        retain_locked(key, out);
        m_st.drops_set_unservable_skipped += skip;
        if (skipped) *skipped = skip;
        if (capped) *capped = over;
        return out;
    }
    // ── ★ DROPS-RETAIN (L2b): a pinned set is never evicted while its block is
    // undecided here. retain = union under `key` (a block id); the ids need not
    // be held yet (a member fetched later is retained on arrival). release at
    // the block's decision here (FINALIZE, decided refusal, wire_cache eviction).
    std::size_t drops_pin_retain(const std::string& key, const std::vector<bytes32>& ids) {
        std::lock_guard<std::mutex> lk(m_dsmtx);
        return retain_locked(key, ids);
    }
    std::size_t drops_pin_release(const std::string& key) {
        std::lock_guard<std::mutex> lk(m_dsmtx);
        auto it = m_drop_pins.find(key);
        if (it == m_drop_pins.end()) return 0;
        std::size_t n = 0;
        for (const auto& id : it->second) {
            auto r = m_drop_retained.find(id);
            if (r != m_drop_retained.end() && --r->second == 0) { m_drop_retained.erase(r); ++n; }
        }
        m_drop_pins.erase(it);
        drop_store_evict_locked(~u64{0});   // what the pin kept below the floor / over the budget goes now
        return n;
    }
    std::vector<std::string> drops_pin_keys() const {
        std::lock_guard<std::mutex> lk(m_dsmtx);
        std::vector<std::string> v;
        for (const auto& [k, ids] : m_drop_pins) { (void)ids; v.push_back(k); }
        return v;
    }
    bool drops_pin_has(const std::string& key) const { std::lock_guard<std::mutex> lk(m_dsmtx); return m_drop_pins.count(key) != 0; }
    std::size_t drops_retained_size() const { std::lock_guard<std::mutex> lk(m_dsmtx); return m_drop_retained.size(); }
    // ── ★ DROPS-RETAIN (L1): the servable floor (bins), pushed by the daemon on
    // every finalize step: frontier_of(newest finalized lane block) - 64. Every
    // block this node may still compose has its range at or above it. Monotone.
    void set_drops_floor_bin(u64 floor) {
        std::lock_guard<std::mutex> lk(m_dsmtx);
        if (m_drop_floor_set && floor <= m_drop_floor) return;
        m_drop_floor = floor; m_drop_floor_set = true;
        drop_store_evict_locked(~u64{0});
    }
    u64 drops_floor_bin() const { std::lock_guard<std::mutex> lk(m_dsmtx); return m_drop_floor; }
    bool drops_floor_set() const { std::lock_guard<std::mutex> lk(m_dsmtx); return m_drop_floor_set; }
    u64 drops_store_bytes() const { std::lock_guard<std::mutex> lk(m_dsmtx); return m_drop_store_bytes; }
    // oldest / newest bin held (0, 0 = empty)
    std::pair<u64, u64> drops_store_bins() const {
        std::lock_guard<std::mutex> lk(m_dsmtx);
        if (m_drop_store.empty()) return {0, 0};
        return {m_drop_store.begin()->first, m_drop_store.rbegin()->first};
    }
    std::string describe_retain() const {
        const auto& s = m_st;
        std::size_t n = 0, pins = 0, ret = 0; u64 bytes = 0, floor = 0, lo = 0, hi = 0; bool fset = false;
        {
            std::lock_guard<std::mutex> lk(m_dsmtx);
            n = m_drop_store_id.size(); bytes = m_drop_store_bytes; pins = m_drop_pins.size(); ret = m_drop_retained.size();
            floor = m_drop_floor; fset = m_drop_floor_set;
            if (!m_drop_store.empty()) { lo = m_drop_store.begin()->first; hi = m_drop_store.rbegin()->first; }
        }
        char b[700];
        std::snprintf(b, sizeof b,
            "drops-retain: store=%zu bytes=%llu budget=%llu bins=[%llu,%llu] floor=%s%llu pins=%zu retained=%zu | evict floor_bins=%llu "
            "overflow_bins=%llu kept_pinned=%llu | set_unservable_skipped=%llu | seg appends=%llu rewrites=%llu unlinks=%llu torn=%llu "
            "load_over_budget=%llu | inv_paged=%llu",
            n, (unsigned long long)bytes, (unsigned long long)m_o.drops_store_bytes, (unsigned long long)lo, (unsigned long long)hi,
            fset ? "" : "unset/", (unsigned long long)floor, pins, ret,
            (unsigned long long)s.drops_evict_floor_bins.load(), (unsigned long long)s.drops_store_overflow_bins.load(),
            (unsigned long long)s.drops_evict_kept_pinned.load(), (unsigned long long)s.drops_set_unservable_skipped.load(),
            (unsigned long long)s.drops_seg_appends.load(), (unsigned long long)s.drops_seg_rewrites.load(),
            (unsigned long long)s.drops_seg_unlinks.load(), (unsigned long long)s.drops_seg_torn.load(),
            (unsigned long long)s.drops_load_over_budget.load(), (unsigned long long)s.drops_inv_paged.load());
        return b;
    }
    // RELAY-SEND-QUEUE diagnostics (one line; the smoke greps it).
    std::string describe_sendq() const {
        char b[400];
        std::snprintf(b, sizeof b,
            "relay-sendq: bound=%zu hwm=%zu full_drops=%llu slow_drops=%llu frames=%llu max_wait_ms=%llu | won reoffered=%llu skipped=%llu confirmed=%llu",
            m_net.send_queue_limit(), m_net.queued_bytes_hwm(),
            (unsigned long long)m_net.peers_dropped_queue_full(), (unsigned long long)m_net.peers_dropped_slow(),
            (unsigned long long)m_net.async_frames_written(), (unsigned long long)m_net.async_max_wait_ms(),
            (unsigned long long)m_st.won_reoffered.load(), (unsigned long long)m_st.won_reoffer_skipped.load(),
            (unsigned long long)m_st.won_held_confirmed.load());
        return b;
    }
    std::string describe_drops() const {
        const auto& s = m_st;
        char b[1200];
        std::snprintf(b, sizeof b,
            "drops-backfill: store=%zu invreq tx=%llu rx=%llu inv tx=%llu rx=%llu | fetch tx=%llu ids_asked=%llu fetchreq_rx=%llu served=%llu "
            "backfilled=%llu | sync calls=%llu pending=%llu complete=%llu set_aside=%llu | getwon asked=%llu served=%llu unknown=%llu solicited_rx=%llu won_reoffered=%llu"
            " | pages tx=%llu served=%llu rx=%llu gaveup=%llu | refused=%llu refused_held=%llu budget_setaside=%llu",
            drops_store_size(),
            (unsigned long long)s.drops_invreq_tx.load(), (unsigned long long)s.drops_invreq_rx.load(),
            (unsigned long long)s.drops_inv_tx.load(), (unsigned long long)s.drops_inv_rx.load(),
            (unsigned long long)s.drops_fetch_tx.load(), (unsigned long long)s.drops_ids_asked.load(),
            (unsigned long long)s.drops_fetchreq_rx.load(), (unsigned long long)s.drops_served.load(),
            (unsigned long long)s.drops_backfilled.load(), (unsigned long long)s.drops_sync_calls.load(),
            (unsigned long long)s.drops_sync_pending.load(), (unsigned long long)s.drops_sync_complete.load(),
            (unsigned long long)s.drops_peer_setaside.load(),
            (unsigned long long)s.won_asked.load(), (unsigned long long)s.won_served.load(), (unsigned long long)s.won_unknown.load(),
            (unsigned long long)s.won_solicited_rx.load(), (unsigned long long)s.won_reoffered.load(),
            (unsigned long long)s.drops_inv_pages_tx.load(), (unsigned long long)s.drops_inv_pages_served.load(),
            (unsigned long long)s.drops_inv_pages_rx.load(), (unsigned long long)s.drops_inv_page_gaveup.load(),
            (unsigned long long)s.drops_refused.load(), (unsigned long long)s.drops_refused_held.load(),
            (unsigned long long)s.drops_inv_budget_setaside.load());
        return b;
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
        m_dorder.append(pos_first, n_pushes, id, raw.size(), next_after, digest_after);   // REPAIR-CHAIN (no-op when closed)
        if (const auto pr = m_dorder.take_prune())   // ★ HOLD-ROUND-3 F3b: one line per prune (range, bytes freed)
            log("relay-deep-order: pruned the durable order below position " + std::to_string(pr->to) + " (positions [" + std::to_string(pr->from) +
                "," + std::to_string(pr->to) + ") of a lane at " + std::to_string(next_after) + "; retention " + std::to_string(pr->retain) +
                " positions; .order " + std::to_string(pr->order_bytes) + " B + .digest " + std::to_string(pr->digest_bytes) + " B " +
                (pr->punched ? "freed" : "NOT freed: this filesystem cannot punch holes (logical retention only)") +
                "; the receipts log is kept whole: it is the lane's durability)");
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
    // Our recorded lane digest at position `pos` (the last horizon, in memory).
    std::optional<bytes32> digest_at(u64 pos) const {
        std::lock_guard<std::mutex> lk(m_dmtx);
        auto it = m_pos_digest.find(pos);
        if (it == m_pos_digest.end()) return std::nullopt;
        return it->second;
    }
    // REPAIR-CHAIN: the same, falling back to the durable order below the
    // in-memory horizon (the spine probe's answer; deep_order off = digest_at).
    std::optional<bytes32> digest_at_deep(u64 pos) const {
        if (auto d = digest_at(pos)) return d;
        if (!m_o.deep_order || !m_dorder.is_open()) return std::nullopt;
        return m_dorder.digest_at(pos);
    }
    // ★ HOLD-ROUND-3 F3b: the deep-serve budget (whole orders served from the
    // durable order; see DeepServeBudget) and the order's retention window.
    DeepServeBudget::Stats deep_serve_stats() const { return m_deep_budget.stats(); }
    u64 durable_order_lowest() const { return m_dorder.lowest_retained(); }
    u64 durable_order_retain() const { return m_dorder.retain(); }
    // ★ DROPS-CARRY-LIVE: our own lane order over [a, p) from the durable order
    // (pos_first, id); false = deep order off / not readable there.
    bool own_order_ids(u64 a, u64 p, std::vector<std::pair<u64, bytes32>>& ids) const {
        return m_dorder.ids_between(a, p, ids);
    }
    // REPAIR-CHAIN: the durable order's serving counters (deep pages / frames).
    DurableLaneOrder::Stats durable_order_stats() const { return m_dorder.stats(); }
    u64 durable_order_bytes() const { return m_dorder.disk_bytes(); }
    bool durable_order_open() const { return m_dorder.is_open(); }

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
    // ★ DROPS-ENROL-LANE (flip 1): a repaired prefix's receipt -> (payee, origin
    // bin, exact bytes); bin 0 = a reloaded receipt (the caller resolves it).
    bool cached_share(const bytes32& id, ::v37::ScriptRef& payee, u64& bin, std::vector<u8>& raw) const {
        std::lock_guard<std::mutex> lk(m_mtx);
        auto it = m_cache.find(id);
        if (it == m_cache.end()) return false;
        payee = it->second.payee; bin = it->second.bin; raw = it->second.raw;
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
        for (PeerId p : ready_peers()) if (m_net.send_to(p, f)) { ++n; if (m_o.drops_floor_diff) note_won_sent(p, b.bid); }
        m_st.block_won_tx++;
        return n;
    }
    // ★ DROPS-RESTART (gate ON only): a frame this node already holds (its own
    // journalled composition, or a peer's it booked) re-enters the re-offer ring
    // and the serve map after a restart; it is not re-flooded here.
    void adopt_won_frame(const std::vector<u8>& f) {
        if (m_o.drops_floor_diff == 0) return;
        BlockWon b; std::string why;
        if (!decode_block_won(f, b, &why) || !b.drops) return;
        { std::lock_guard<std::mutex> lk(m_bmtx); m_seen_bids.insert(b.bid); }
        remember_won_frame(f);
    }
    // ★ DROPS-RESTART (gate ON only): ask every ready peer for the carried frame
    // of `bid`. Any node that holds it answers (the winner need not be up); the
    // answer is handed to the shell via drain_block_won() even if the bid was
    // seen before. Returns the number of peers asked (0 at flip 0).
    std::size_t want_block_won(const bytes32& bid) {
        if (m_o.drops_floor_diff == 0) return 0;
        { std::lock_guard<std::mutex> lk(m_bmtx); m_won_wanted.insert(bid); }
        const auto f = encode_getwon(m_o.chain, bid);
        std::size_t n = 0;
        for (PeerId q : ready_peers()) if (m_net.send_to(q, f)) ++n;
        if (n) m_st.won_asked++;
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
        h.bind = m_o.bind; h.pool = m_o.pool_id; h.enrol_set = m_o.enrol_set_digest;
        h.rules = m_o.lane_rules;   // LANE-RULES
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
            if (!missing) {
                r.st = Repair::St::Ready; m_st.repair_ready++;
                if (r.walk_from.count(r.served_by)) m_st.repair_deep_ready++;   // REPAIR-CHAIN: Ready through a down-walk
                if (r.a0 == 0 && (r.full_only || r.walk_from.count(r.served_by))) {
                    // ★ HOLD-ROUND-3 F3a: one line per deep whole-order fetch (peer, pages, bytes, the committed digest it is verified against)
                    if (r.full_only) m_st.repair_full_ready++;
                    const std::string line = "relay-deep-order: fetched the WHOLE order [0," + std::to_string(r.P) + ") of spine " + hex_short(r.spine) +
                        " from peer " + std::to_string(r.served_by) + " in " + std::to_string(r.pages) + " page(s), " + std::to_string(r.ids.size()) +
                        " ids (" + std::to_string(r.ids.size() * 40) + " B on the wire)" + (r.full_only ? " via the whole-order fallback" : " at the end of a down-walk") +
                        "; the settlement replay verifies it against the committed digest at P next";
                    lk.unlock(); log(line); lk.lock();
                    it = m_repairs.find(key);
                    if (it == m_repairs.end()) return RepairState::Pending;
                }
            }
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
        std::unique_lock<std::mutex> lk(m_rmtx);
        auto it = m_repairs.find(std::make_pair(P, spine));
        if (it == m_repairs.end()) return;
        Repair& r = it->second;
        std::string note;
        if (r.served_by) {
            // REPAIR-HORIZON: a suffix order [a0, P) the peer asserted reaches the
            // spine, replayed after OUR [0, a0), did not: our prefix differs.
            if (r.walk_from.count(r.served_by)) { r.tried.insert(r.served_by); walk_failed_locked(r, r.served_by, /*rc5=*/false); }   // REPAIR-CHAIN
            else if (r.a0 && !r.full_only) {
                // ★ HOLD-ROUND-3 F3a: no base here reproduces the spine from [0, a0)
                // (own, every shadow): instead of naming the peer DEEP (attempt 8:
                // every peer DEEP -> Exhausted -> DEEP-DIVERGENCE, the block held for
                // ever), fall back to the WHOLE order [0, P) -- from this very peer first
                // (it holds the cut's lineage; it said so with its digest at P).
                r.full_only = true; r.prefer = r.served_by;
                m_st.repair_full_required++;
                note = "relay: REPAIR-DEEP repair of P=" + std::to_string(r.P) + ": the suffix [" + std::to_string(r.a0) + "," + std::to_string(r.P) +
                       ") from peer " + std::to_string(r.served_by) + " reached the spine from no base held here (own order, " +
                       "every shadow) -> WHOLE-ORDER fallback: asking [0," + std::to_string(r.P) + ") in pages (this peer first)";
            } else r.tried.insert(r.served_by);
        }
        r.reset();
        m_st.repair_rejected++;
        lk.unlock();
        if (!note.empty()) log(note);
    }
    // ★ HOLD-ROUND-3 F3a: the caller holds NO verified base for [0, a0) of this
    // cut (own digest at a0 differs, no shadow record / another a0 -- see
    // drops::decide_suffix_base): switch the repair to the WHOLE-ORDER fallback.
    // A Ready / in-flight suffix is discarded (its serving peer is re-asked
    // first: it holds the lineage); a Ready whole order stays Ready. Idempotent.
    void repair_require_full(u64 P, const bytes32& spine, const std::string& cause = std::string()) {
        std::unique_lock<std::mutex> lk(m_rmtx);
        auto it = m_repairs.find(std::make_pair(P, spine));
        if (it == m_repairs.end()) {
            Repair r; r.P = P; r.spine = spine; r.since = Clock::now();
            it = m_repairs.emplace(std::make_pair(P, spine), std::move(r)).first;
            m_st.repair_started++;
        }
        Repair& r = it->second;
        const bool was = r.full_only;
        r.full_only = true;
        bool restarted = false;
        if (r.st == Repair::St::Ready && r.a0 == 0) { /* a whole order: keep it */ }
        else if (r.st != Repair::St::Idle && r.a0 > 0) { r.prefer = r.served_by ? r.served_by : r.cur; r.reset(); restarted = true; }
        else if (r.st == Repair::St::Idle) { r.exhausted = false; r.tried.clear(); }
        if (!was) m_st.repair_full_required++;
        lk.unlock();
        if (!was)
            log("relay: REPAIR-DEEP repair of P=" + std::to_string(P) + " spine=" + hex_short(spine) + ": WHOLE-ORDER fallback armed" +
                (cause.empty() ? std::string() : " (" + cause + ")") + " -> asking every peer for [0," + std::to_string(P) + ") in pages" +
                (restarted ? "; the served suffix is discarded" : ""));
        drive_repairs();
    }
    // ★ HOLD-ROUND-3 F3a: the whole-order fallback was refused by EVERY ready
    // peer (twice each: below their retention, or RC5 peers with no durable
    // order). Undecided -- the caller HOLDS and alarms (never a silent hold);
    // `detail` names each refusing peer and what it said it retains.
    bool repair_full_exhausted(u64 P, const bytes32& spine, std::string* detail = nullptr) const {
        std::lock_guard<std::mutex> lk(m_rmtx);
        auto it = m_repairs.find(std::make_pair(P, spine));
        if (it == m_repairs.end()) return false;
        const Repair& r = it->second;
        if (!r.full_only || !(r.st == Repair::St::Idle && r.exhausted)) return false;
        if (detail) {
            std::string s;
            for (const auto& [p, n] : r.full_refused) {
                const auto lo = r.full_lowest.find(p);
                s += (s.empty() ? "" : ", ") + std::string("peer ") + std::to_string(p) + " refused x" + std::to_string(n) +
                     (lo != r.full_lowest.end() ? " (retains >= " + std::to_string(lo->second) + ")" : "");
            }
            *detail = s.empty() ? "no peer answered the whole-order ask" : s;
        }
        return true;
    }
    bool repair_full_only(u64 P, const bytes32& spine) const {
        std::lock_guard<std::mutex> lk(m_rmtx);
        auto it = m_repairs.find(std::make_pair(P, spine));
        return it != m_repairs.end() && it->second.full_only;
    }
#define C2POOL_XMR_DEEP_ORDER_FALLBACK 1
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
                    if (r.full_only) {   // ★ HOLD-ROUND-3 F3a: the whole-order fallback, named
                        s += "; WHOLE-ORDER fallback [0," + std::to_string(r.P) + ")";
                        if (r.exhausted) {
                            s += ": every ready peer refused it twice (";
                            bool first = true;
                            for (const auto& [p, n] : r.full_refused) {
                                const auto lo = r.full_lowest.find(p);
                                s += (first ? "" : ", ") + std::string("peer ") + std::to_string(p) + " x" + std::to_string(n) +
                                     (lo != r.full_lowest.end() ? " retains >= " + std::to_string(lo->second) : "");
                                first = false;
                            }
                            s += ") -- the cut's positions are below every serving peer's retention (--relay-order-retain) or the peers run "
                                 "without a durable order; this node needs a longer-retaining peer or the cold-boot path (ledger + lane snapshot)";
                        }
                    }
                    if (!r.deep.empty()) {   // REPAIR-HORIZON: the loud, named outcome
                        s += "; DEEP-DIVERGENCE: our lane order differs from the winner's BELOW the vault horizon of " +
                             std::to_string(r.deep.size()) + " peer(s) (";
                        bool first = true;
                        for (const auto& [p, a] : r.deep) { s += (first ? "" : ", ") + std::string("peer ") + std::to_string(p) + " a0=" + std::to_string(a); first = false; }
                        s += ") -- no connected peer retains the divergent positions";
                    }
                    break;
                case Repair::St::Ordering:
                    s = std::string(r.full_only ? "WHOLE-ORDER fallback (pages=" + std::to_string(r.pages) + "): " : std::string()) +
                        std::string(r.walk_from.count(r.cur) ? "REPAIR-CHAIN deep walk (step " + std::to_string(r.walk_k.count(r.cur) ? r.walk_k.at(r.cur) : 0) +
                                                               " below a0=" + std::to_string(r.walk_from.at(r.cur)) + "): " : std::string()) +
                        std::string(r.probing ? "probing the prefix digest at a0=" + std::to_string(r.a0) + " of peer " : "ordering from peer ") +
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
        // ORDER serving / asking (the "served=" above is ctx_served): late = an
        // answer that arrived after its request timed out (claim() drops it).
        const SupplyServeStats sv = m_serve ? m_serve->stats() : SupplyServeStats{};
        const SupplyFetchStats fs = m_fetch ? m_fetch->stats() : SupplyFetchStats{};
        char b[3072];
        std::snprintf(b, sizeof b,
            "relay: conns=%zu ready=%zu hello ok=%llu rej=%llu tmo=%llu | rx recv=%llu dup=%llu struct=%llu "
            "rx_evals=%llu valid=%llu invalid=%llu deferred=%llu unavail=%llu bans=%llu unresolved=%llu expired=%llu qdrop=%llu | "
            "admitted own=%llu foreign=%llu solicited=%llu cache=%zu | flood=%llu reoffer=%llu backfill orders=%llu ids=%llu | "
            "won tx=%llu rx=%llu | repair start=%llu order_ok=%llu spine_mis=%llu peer_fail=%llu ids=%llu ready=%llu rejected=%llu open=%zu | "
            "fa_ignored=%llu fb_unknown=%llu malformed=%llu pre_hello=%llu | "
            "ctx want=%zu wanted=%llu asked=%llu rx=%llu resolved=%llu bad=%llu unknown_rx=%llu gave_up=%llu served=%llu unknown_tx=%llu | "
            "repair refetch=%llu evicted=%llu upgraded=%llu unresolved_solicited=%llu | pool-id tag_mismatch=%llu rules_mismatch=%llu | "
            "repair-horizon rearm=%llu prefix_ok=%llu prefix_unknown=%llu deep=%llu reoffer_unpushed=%llu | "
            "deep-fallback required=%llu reask=%llu refused=%llu ready=%llu exhausted=%llu | "
            "deep-serve cuts=%llu first_ask=%llu over_budget=%llu below_retention=%llu retain=%llu lowest=%llu | "
            "liveness keepalive=%ums silence=%ums ping tx=%llu rx=%llu pong tx=%llu rx=%llu silent_drops=%llu legacy=%llu rearm=%llu | "
            "order serve=%llu ids=%llu throttled=%llu | order ask=%llu ok=%llu timeouts=%llu late=%llu | "
            "repair-page pages=%llu max=%llu timeouts=%llu grown=%llu | verify threads=%llu q=%zu parked=%zu unavail_parked=%llu",
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
            (unsigned long long)s.hello_tag_mismatch.load(), (unsigned long long)s.hello_rules_mismatch.load(),
            (unsigned long long)s.repair_horizon_rearm.load(), (unsigned long long)s.repair_prefix_ok.load(),
            (unsigned long long)s.repair_prefix_unknown.load(), (unsigned long long)s.repair_deep.load(),
            (unsigned long long)s.reoffer_unpushed.load(),
            (unsigned long long)s.repair_full_required.load(), (unsigned long long)s.repair_full_reask.load(),
            (unsigned long long)s.repair_full_refused.load(), (unsigned long long)s.repair_full_ready.load(),
            (unsigned long long)s.repair_full_exhausted.load(),
            (unsigned long long)s.deep_serve_cuts.load(), (unsigned long long)s.deep_serve_first_ask.load(),
            (unsigned long long)s.deep_serve_over_budget.load(), (unsigned long long)s.deep_serve_below_retention.load(),
            (unsigned long long)m_dorder.retain(), (unsigned long long)m_dorder.lowest_retained(),
            m_o.keepalive_ms, m_o.silence_timeout_ms,
            (unsigned long long)s.ping_tx.load(), (unsigned long long)s.ping_rx.load(),
            (unsigned long long)s.pong_tx.load(), (unsigned long long)s.pong_rx.load(),
            (unsigned long long)s.silent_drops.load(), (unsigned long long)s.ka_legacy.load(),
            (unsigned long long)s.ka_rearm.load(),
            (unsigned long long)sv.order_served, (unsigned long long)sv.order_ids, (unsigned long long)sv.throttled,
            (unsigned long long)fs.orders_requested, (unsigned long long)fs.orders_ok, (unsigned long long)fs.timeouts,
            (unsigned long long)fs.unsolicited,
            (unsigned long long)s.repair_order_pages.load(), (unsigned long long)s.repair_order_page_max.load(),
            (unsigned long long)s.repair_page_timeouts.load(), (unsigned long long)s.repair_page_grown.load(),
            (unsigned long long)s.verify_threads.load(), verify_queue_size(), verify_parked_size(),
            (unsigned long long)s.rx_unavail_parked.load());
        return b;
    }
    // DROPS-VERIFY-SCALE: verify queue depth (items waiting for a worker) and parked items.
    std::size_t verify_queue_size() const { std::lock_guard<std::mutex> lk(m_mtx); return m_q.size(); }
    std::size_t verify_parked_size() const { std::lock_guard<std::mutex> lk(m_mtx); return m_parked.size(); }
    std::size_t share_ahead_size() const { std::lock_guard<std::mutex> lk(m_mtx); return m_ahead.size(); }
    // ★ HOLD-ROUND-2 (B): the main thread published a new share state (a lane
    // block booked / a FOUND / a view readable): every AHEAD share is re-judged.
    void notify_share_state_advanced() {
        std::lock_guard<std::mutex> lk(m_mtx);
        if (m_ahead.empty()) return;
        const auto now = Clock::now();
        for (auto& x : m_ahead) { x.not_before = now; m_parked.push_back(std::move(x)); m_st.share_ahead_rejudged++; }
        m_ahead.clear(); m_ahead_n.clear();
        m_qcv.notify_one();
    }
    // The share-verdict counters (VERIFY S6: only the last refusal showed).
    std::string describe_shares() const {
        const auto& s = m_st;
        char b[560];
        // HOLD-ROUND-3 (4.10): `parked` / `ahead` are cumulative; `park_now` (the
        // undecided park) and `ahead_now` (the AHEAD/UNBASED park) are LIVE depths.
        std::snprintf(b, sizeof b,
            "relay-shares: refused=%llu parked=%llu undecided_dropped=%llu trusted=%llu | skew ahead=%llu behind=%llu late=%llu "
            "unbased=%llu unbased_expired=%llu | park_now=%zu ahead_now=%zu rejudged=%llu evicted=%llu",
            (unsigned long long)s.share_refused.load(), (unsigned long long)s.share_parked.load(),
            (unsigned long long)s.share_undecided_dropped.load(), (unsigned long long)s.share_undecided_trusted.load(),
            (unsigned long long)s.share_skew_ahead.load(), (unsigned long long)s.share_skew_behind.load(),
            (unsigned long long)s.share_late.load(),
            (unsigned long long)s.share_unbased_parked.load(), (unsigned long long)s.share_unbased_expired.load(),
            verify_parked_size(), share_ahead_size(),
            (unsigned long long)s.share_ahead_rejudged.load(), (unsigned long long)s.share_ahead_evicted.load());
        return b;
    }
    std::string last_reject() const { std::lock_guard<std::mutex> lk(m_mtx); return m_last_reject; }
    std::string last_unresolved() const { std::lock_guard<std::mutex> lk(m_mtx); return m_last_unresolved; }
    std::string last_share_refused() const { std::lock_guard<std::mutex> lk(m_mtx); return m_last_share_refused; }

    // SHARE-LEVEL CANONICAL COINBASE (P2Pool's share rule): a receipt earns lane
    // credit only if its coinbase is the canonical lane coinbase
    // (xmr_coinbase_recompute.hpp verify_share_coinbase). The daemon decides from
    // finalized state (the ledger + the view at its anchor, keyed by the ledger
    // state the receipt's 0x03 root commits). Called on a verify worker thread,
    // after the structural check, before RandomX: 1 canonical, -1 not canonical
    // (refused + strike), 0 not decidable here yet (parked like an unresolved
    // context; past the patience an unsolicited receipt is dropped, a solicited
    // one -- a repair of a winner's lane, Ruling A -- is admitted). Unset: no
    // check (test rigs). Set before start().
    using VerdictFn = std::function<int(const FbReceipt&, const ::v37::xmr::verify::ParsedBlob&, u64 coinbase_height, std::string& why)>;
    void set_share_verdict(VerdictFn f) { m_verdict = std::move(f); }

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

    // ── RELAY-DISCOVERY (read side) ─────────────────────────────────────────
    const PeerBook& book() const { return m_book; }
    // The relay address of every HELLO-ok link ("host:port"; "?" = an inbound
    // peer that announced no listen port) with its direction.
    std::vector<std::pair<std::string, bool /*outbound*/>> ready_links() const {
        std::lock_guard<std::mutex> lk(m_pmtx);
        std::vector<std::pair<std::string, bool>> v;
        for (const auto& [p, s] : m_peers) {
            (void)p;
            if (s.hello_ok) v.emplace_back(s.addr_key.empty() ? std::string("?") : s.addr_key, !s.out_host.empty());
        }
        return v;
    }
    // One status line: book size, good, dials, learned, the link graph.
    std::string disc_describe() const {
        std::size_t out = 0, in = 0;
        std::string links;
        for (const auto& [k, o] : ready_links()) {
            (o ? out : in)++;
            links += (links.empty() ? "" : ",") + k + (o ? ">" : "<");
        }
        const auto& s = m_st;
        char b[1024];
        std::snprintf(b, sizeof b,
            "relay-disc: %s known=%zu good=%zu bad=%zu | links out=%zu/%zu in=%zu | dialed=%llu dial_ok=%llu learned=%llu | "
            "getaddr tx=%llu rx=%llu throttled=%llu | addr tx=%llu rx=%llu unsolicited=%llu ignored=%llu | "
            "dup_dropped=%llu refused=%llu self=%llu saves=%llu expired=%llu | "
            "nonce=%016llx self_conn=%llu self_skipped=%llu self_book=%zu dup_deferred=%llu | peers=[",
            m_o.discovery ? "on" : "off", m_book.size(), m_book.good(), m_book.bad_size(), out, m_o.max_outbound, in,
            (unsigned long long)s.disc_dialed.load(), (unsigned long long)s.disc_dial_ok.load(), (unsigned long long)s.addr_learned.load(),
            (unsigned long long)s.getaddr_tx.load(), (unsigned long long)s.getaddr_rx.load(), (unsigned long long)s.getaddr_throttled.load(),
            (unsigned long long)s.addr_tx.load(), (unsigned long long)s.addr_rx.load(), (unsigned long long)s.addr_unsolicited.load(),
            (unsigned long long)s.addr_ignored.load(), (unsigned long long)s.disc_dup_dropped.load(), (unsigned long long)s.disc_bad.load(),
            (unsigned long long)s.disc_self.load(), (unsigned long long)s.disc_saves.load(), (unsigned long long)s.disc_expired.load(),
            (unsigned long long)m_nonce, (unsigned long long)s.self_conn.load(), (unsigned long long)s.self_skipped.load(),
            m_book.self_size(), (unsigned long long)s.dup_deferred.load());
        return std::string(b) + links + "]";
    }
    // Persist now (the daemon's shutdown path; the maintenance thread saves a dirty book on its own).
    void save_book(bool force) {
        if (!m_o.discovery || !m_o.book_save) return;
        if (!m_book.take_dirty() && !force) return;
        m_o.book_save(m_book.records());
        m_st.disc_saves++;
    }
    // Test hook: send one FB_GETADDR to every ready peer now.
    void ask_addrs_now() { for (PeerId p : ready_peers()) send_getaddr(p); }

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
        // RELAY-DISCOVERY
        std::string out_host; u16 out_port = 0;     // set iff WE dialed this link (the dialed address)
        std::string addr_key;                       // the peer's relay address (dialed, or remote ip:HELLO listen_port)
        std::string remote_ip;                      // inbound: the socket's remote address
        Clock::time_point getaddr_tx{}, getaddr_rx{};
        bool addr_pending = false;                  // a GETADDR of ours is unanswered on this link
        std::size_t addr_learned = 0;
    };
    static constexpr u32 kLegacyProbes = 3;         // unanswered PINGs before a peer counts as pre-0x48
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
        bool learned = false;          // RELAY-DISCOVERY: from the book (one link, then retired)
        bool used = false;             // RELAY-DISCOVERY: a learned target was dialed once
        bool self = false;             // NODE-NONCE: its HELLO carried OUR nonce -> never dialed again
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
        bool rx_retried = false;   // DROPS-VERIFY-SCALE: parked once already on rx-unavailable
        Clock::time_point enq = Clock::now();
        Clock::time_point not_before = Clock::now();
        u64 ahead_node = 0;        // HOLD-ROUND-2 V4: the sender NODE an AHEAD park is counted under (inv_node)
        unsigned unbased_rounds = 0;   // HOLD-ROUND-3 (F4): UNBASED re-judges so far (dropped past kShareUnbasedMaxRounds)
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
        u32 max_ids = 0;      // REPAIR-PAGE: ids this page asked (0 = the default kCtrlMaxIdsPerOrder)
        Clock::time_point issued{};   // REPAIR-PAGE: when an ORDER ask went out (its round trip)
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
        // REPAIR-CHAIN (F2-R): the DOWN-WALK of a peer whose digest at a0
        // differed -- the a0 it started from and the step count (this attempt),
        // the peers whose walk ended in a lineage that cannot reach the spine or
        // at an RC5 peer (never re-walked for this repair: DEEP as RC5 does), and
        // the equal point a finished walk found (a re-ask probes there first).
        std::map<PeerId, u64> walk_from;
        std::map<PeerId, u32> walk_k;
        std::set<PeerId> walk_checked;   // the peer's digest at P was probed == spine (its lineage reaches the cut)
        std::set<PeerId> walk_failed;
        std::map<PeerId, u64> walk_ok;
        // ★ HOLD-ROUND-3 F3a: the WHOLE-ORDER fallback. full_only = this repair
        // asks every peer [0, P) (never a suffix again: no verified base for
        // [0, a0) exists here); full_refused = whole-order refusals per peer
        // (the first is re-asked once: the server serves the SECOND ask; the
        // second sets the peer aside); full_lowest = what each refusing peer
        // said it retains (the alarm names it); full_next = peers whose next
        // ask starts at 0 (a refused walk step, re-asked); pages / page_ids =
        // the ORDER pages of the attempt in flight (the fetch line).
        bool full_only = false, full_alarmed = false;
        std::map<PeerId, u32> full_refused;
        std::map<PeerId, u64> full_lowest;
        std::set<PeerId> full_next;
        u64 pages = 0, page_ids = 0;
        Clock::time_point since = Clock::now();
        // REPAIR-PAGE liveness (#1808 review): when Ordering from `cur` began and
        // the first page it asked (0 = no page answered yet); they size the cap.
        Clock::time_point ordering_started = Clock::now();
        u64 ordering_page = 0;
        // Fetching: progress + refetch bookkeeping
        Clock::time_point last_progress = Clock::now(), last_fetch = Clock::now(), polled = Clock::now();
        std::size_t cached_seen = 0;
        std::set<PeerId> fetch_tried;
        u32 refetches = 0;
        void reset() {
            st = St::Idle; ids.clear(); cursor = 0; cur = 0; served_by = 0; since = Clock::now();
            a0 = 0; probing = false; has_a0_digest = false; ordering_page = 0;
            cached_seen = 0; fetch_tried.clear(); refetches = 0;
            walk_from.clear(); walk_k.clear(); walk_checked.clear();
            pages = 0; page_ids = 0;   // F3a: per attempt (full_only / full_refused / full_lowest / full_next persist)
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
    // ★ RAIN-BACKFILL: one peer's inventory of one interval range.
    // ★ HOLD-ROUND-2 (C3): keyed by the peer NODE (its HELLO node_nonce), not
    // the connection: the ask budget (drops_fetch_max_asks) and the set-aside
    // survive a reconnect. Stagenet attempt 7: the key was the connection and
    // was erased at every disconnect, so under a ~3 s ban loop the 8-ask
    // set-aside fired once in 3 h while 3.75M ids were asked.
    struct InvKey {
        u64 node = 0; u64 lo = 0, hi = 0;
        bool operator<(const InvKey& o) const { return std::tie(node, lo, hi) < std::tie(o.node, o.lo, o.hi); }
    };
    struct PeerInv {
        bool answered = false, set_aside = false;
        bool more = false;              // HOLD-ROUND-2 (C1): a one-bin inventory filled kDropsInvMaxIds: page on
        std::vector<bytes32> ids;
        u32 asks = 0, page_asks = 0;
        Clock::time_point asked{}, fetched{}, touched{}, page_asked{};
    };
    u64 inv_node(PeerId p) const {
        const u64 nn = peer_node_nonce(p);
        return nn ? nn : (static_cast<u64>(p) | (u64{1} << 63));   // before HELLO: the connection (tagged)
    }
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
                PeerSt st{};
                // RELAY-DISCOVERY: a dial's up event runs on the dialing (maintenance)
                // thread, before add_peer_id returns: this link is OUR dial of m_dial_*.
                if (std::this_thread::get_id() == m_maint_tid.load()) { st.out_host = m_dial_host; st.out_port = m_dial_port; }
                m_peers[p] = st;
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
            m_rpage.erase(p);
        }
        if (m_fetch) m_fetch->forget_peer(p);
        if (m_serve) m_serve->forget_peer(p);
        { std::lock_guard<std::mutex> lk(m_bmtx); m_won_offer.erase(p); }   // RELAY-SEND-QUEUE
        // ★ HOLD-ROUND-2 (C3): a dropped peer's inventories are KEPT (keyed by its
        // node, aged out after 10 min untouched): its ask budget and set-aside
        // survive the reconnect (pre-fix they were erased here, so a ban loop
        // re-asked the same inventory from zero every ~3 s).
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
                // RELAY-DISCOVERY: a learned address whose link ended before HELLO failed
                if (m_o.discovery && !t.hello_seen) m_book.mark_failed(t.host, t.port, wall_s());
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
        if (m_o.drops_floor_diff && op == FB_GETDROPS) { on_getdrops(p, f); return; }   // ★ RAIN-BACKFILL (gate ON only)
        if (m_o.drops_floor_diff && op == FB_DROPINV) { on_dropinv(p, f); return; }
        if (m_o.drops_floor_diff && op == FB_GETWON) { on_getwon(p, f); return; }     // ★ DROPS-RESTART (gate ON only)
        if ((op == FB_PING || op == FB_PONG) && m_o.keepalive_ms) { on_ping(p, f); return; }
        if (m_o.discovery && op == FB_GETADDR) { on_getaddr(p, f); return; }   // RELAY-DISCOVERY
        if (m_o.discovery && op == FB_ADDR) { on_addr(p, f); return; }
        m_st.fb_unknown++;                                            // a future 0x4a..0x4f: count, keep socket
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
        if (op == FB_PONG) { m_st.pong_rx++; on_pong_won(p, nonce); return; }
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
            if (is_lane_rules_mismatch(mis)) m_st.hello_rules_mismatch++;   // LANE-RULES: other lane rules = another pool
            {
                std::lock_guard<std::mutex> lk(m_mtx);
                m_last_reject = "hello: " + mis;
            }
            log("relay: peer " + std::to_string(p) + " HELLO REFUSED: " + mis + " -> drop");
            if (h.node_nonce == m_nonce) on_self_hello(p, h);   // NODE-NONCE: a self-connection
            if (m_o.discovery) disc_refused(p, mis, h);   // RELAY-DISCOVERY: never good, never re-learned
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
        if (m_o.discovery && !disc_hello_ok(p, h)) return;   // RELAY-DISCOVERY: a duplicate link was dropped
        reoffer_to(p);
        reoffer_won_to(p);   // ENROL-REPL (DROPS only; a no-op at flip 0)
        if (m_o.drops_floor_diff) {   // ★ RAIN-BACKFILL: pull the peer's recent raindrops (both sides do this)
            m_drop_had_peer = true;
            const u64 tip = m_chain.tip();
            if (tip) {
                u64 hi = tip + 2, lo = tip > m_o.drops_hello_bins ? tip - m_o.drops_hello_bins : 0;
                // HOLD-ROUND-2 (C): nothing below the index horizon is admissible
                // unsolicited -- never pull its inventory
                if (m_o.index_horizon && tip > m_o.index_horizon) lo = std::max(lo, tip - m_o.index_horizon);
                const u64 node = inv_node(p);
                {
                    std::lock_guard<std::mutex> lk(m_dsmtx);
                    PeerInv& inv = m_drop_inv[InvKey{node, lo, hi}];
                    inv.asked = Clock::now(); inv.touched = inv.asked;
                }
                send_drop_invreq(p, lo, hi);
            }
        }
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
            if (m_o.drops_floor_diff && drop_wanted(it.id)) it.solicited = true;   // ★ RAIN-BACKFILL: a fetched raindrop
            enqueue(std::move(it));
        }
    }

    void on_block_won(PeerId p, const std::vector<u8>& f) {
        BlockWon b; std::string why;
        if (!decode_block_won(f, b, &why)) { m_st.malformed++; return; }
        if (b.chain_id != m_o.chain) { m_st.wrong_chain++; return; }
        bool fresh = false;
        const u64 from_node = m_o.drops_floor_diff ? peer_node_nonce(p) : 0;   // RELAY-SEND-QUEUE
        {
            std::lock_guard<std::mutex> lk(m_bmtx);
            note_won_held(from_node, b.bid);   // that node holds this bid: never re-offer it back
            fresh = m_seen_bids.insert(b.bid).second;
            if (fresh) {
                m_bid_peer[b.bid] = p;
                m_won.emplace_back(b, p);
                if (m_won.size() > 256) m_won.erase(m_won.begin());
            }
        }
        if (!fresh) {
            // ★ DROPS-RESTART: a carried frame we ASKED for (FB_GETWON) is handed to
            // the shell again even though its bid was seen (the first copy was lost
            // or arrived before the shell could keep it). Never forwarded again.
            bool solicited = false;
            if (m_o.drops_floor_diff && b.drops) {
                std::lock_guard<std::mutex> lk(m_bmtx);
                solicited = m_won_wanted.erase(b.bid) != 0;
                if (solicited) { m_won.emplace_back(b, p); if (m_won.size() > 256) m_won.erase(m_won.begin()); }
            }
            if (solicited) { m_st.won_solicited_rx++; remember_won_frame(f); }
            return;
        }
        if (m_o.drops_floor_diff && b.drops) { std::lock_guard<std::mutex> lk(m_bmtx); m_won_wanted.erase(b.bid); }
        m_st.block_won_rx++;
        remember_won_frame(f);   // ENROL-REPL (DROPS only)
        for (PeerId q : ready_peers())   // forward once (dedup by bid)
            if (q != p && m_net.send_to(q, f) && m_o.drops_floor_diff) note_won_sent(q, b.bid);   // RELAY-SEND-QUEUE
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
        // ★ DROPS-RESTART: every carried (v0x02) frame this node holds is servable
        // by bid (FB_GETWON), bounded; the newest frame for a bid wins.
        if (f.size() >= kBlockWonDropsMinBytes && (f[1] == kFbBlockWonDropsVersion || f[1] == kFbBlockWonSetVersion)) {
            BlockWon b; std::string why;
            if (decode_block_won(f, b, &why)) {
                if (!m_won_by_bid.count(b.bid)) m_won_serve_order.push_back(b.bid);
                m_won_by_bid[b.bid] = f;
                while (m_won_serve_order.size() > kWonServeMax) { m_won_by_bid.erase(m_won_serve_order.front()); m_won_serve_order.pop_front(); }
            }
        }
    }
    void on_getwon(PeerId p, const std::vector<u8>& f) {
        u32 chain = 0; bytes32 bid{}; std::string why;
        if (!decode_getwon(f, chain, bid, &why)) { m_st.malformed++; strike(p, why); return; }
        if (chain != m_o.chain) { m_st.wrong_chain++; return; }
        std::vector<u8> frame;
        {
            std::lock_guard<std::mutex> lk(m_bmtx);
            auto it = m_won_by_bid.find(bid);
            if (it == m_won_by_bid.end()) { m_st.won_unknown++; return; }
            frame = it->second;
        }
        if (m_net.send_to(p, frame)) m_st.won_served++;
    }
    // ★ RELAY-SEND-QUEUE: the HELLO re-offer used to push EVERY kept frame (up to
    // 64 x ~512 KiB v0x03) synchronously from the reader thread, on both ends at
    // once -> the send-send deadlock of capstone attempt 6. Now it only builds a
    // per-peer TODO of the bids that peer's NODE is not known to hold, and
    // pump_won_offer() hands them to the transport's queue one frame at a time,
    // while that peer's queued bytes are under kWonPageBytes (the maintenance
    // tick keeps topping it up). "Known to hold" (m_won_held, by HELLO
    // node_nonce, so it survives the redial of the same process) is PROOF only:
    // that node sent us the frame, or a PONG for a PING queued AFTER our copy
    // came back (TCP order + its sequential reader). Nothing on the wire changes.
    static constexpr std::size_t kWonPageBytes = 1u << 20;
    static bool won_frame_bid(const std::vector<u8>& f, bytes32& bid) {
        if (f.size() < 6 + 32 || f[0] != FB_BLOCK_WON) return false;
        std::copy(f.begin() + 6, f.begin() + 6 + 32, bid.begin());
        return true;
    }
    u64 peer_node_nonce(PeerId p) const {
        std::lock_guard<std::mutex> lk(m_pmtx);
        auto it = m_peers.find(p);
        return (it != m_peers.end() && it->second.hello_ok) ? it->second.remote.node_nonce : 0;
    }
    void note_won_held(u64 nn, const bytes32& bid) {   // m_bmtx held by the caller
        if (!nn) return;
        auto& h = m_won_held[nn];
        if (h.size() >= 4 * kWonServeMax) h.clear();   // bound: forgetting only costs a re-offer
        h.insert(bid);
        if (m_won_held.size() > 256) { auto v = m_won_held.begin(); if (v->first == nn) ++v; m_won_held.erase(v); }
    }
    void reoffer_won_to(PeerId p) {
        if (m_o.drops_floor_diff == 0) return;
        const u64 nn = peer_node_nonce(p);
        std::vector<std::pair<std::vector<u8>, std::optional<bytes32>>> now;   // not servable by bid (v0x01): small, sent at once
        {
            std::lock_guard<std::mutex> lk(m_bmtx);
            auto& o = m_won_offer[p];
            o.todo.clear();
            auto hit = nn ? m_won_held.find(nn) : m_won_held.end();
            std::set<bytes32> queued;
            for (const auto& f : m_won_raw) {
                bytes32 bid{};
                if (!won_frame_bid(f, bid)) { now.emplace_back(f, std::nullopt); continue; }
                if (hit != m_won_held.end() && hit->second.count(bid)) { m_st.won_reoffer_skipped++; continue; }
                if (!m_won_by_bid.count(bid)) { now.emplace_back(f, bid); continue; }
                if (queued.insert(bid).second) o.todo.push_back(bid);
            }
        }
        for (const auto& [f, bid] : now) {
            if (!m_net.send_to(p, f)) continue;
            m_st.won_reoffered++;
            if (bid) note_won_sent(p, *bid);
        }
        pump_won_offer(p);
    }
    void pump_won_offer(PeerId p) {
        for (;;) {
            if (m_net.send_queue_limit() && m_net.queued_bytes(p) >= kWonPageBytes) return;
            std::vector<u8> f;
            bytes32 bid{};
            {
                std::lock_guard<std::mutex> lk(m_bmtx);
                auto it = m_won_offer.find(p);
                if (it == m_won_offer.end() || it->second.todo.empty()) return;
                bid = it->second.todo.front();
                it->second.todo.pop_front();
                auto w = m_won_by_bid.find(bid);
                if (w == m_won_by_bid.end()) continue;   // evicted since: nothing to offer
                f = w->second;
            }
            if (!m_net.send_to(p, f)) {   // gone (or dropped): never leave a TODO behind a link that ended
                if (!m_net.has_peer(p)) { std::lock_guard<std::mutex> lk(m_bmtx); m_won_offer.erase(p); }
                return;
            }
            m_st.won_reoffered++;
            note_won_sent(p, bid);
        }
    }
    void note_won_sent(PeerId p, const bytes32& bid) {
        const u64 at = m_ping_nonce.load();   // read AFTER the enqueue: a PING numbered > at is queued behind it
        std::lock_guard<std::mutex> lk(m_bmtx);
        auto it = m_won_offer.find(p);
        if (it != m_won_offer.end() && it->second.unconfirmed.size() < 4 * kWonReofferMax)
            it->second.unconfirmed.emplace_back(at, bid);
    }
    void on_pong_won(PeerId p, u64 nonce) {
        if (m_o.drops_floor_diff == 0) return;
        const u64 nn = peer_node_nonce(p);
        if (!nn) return;
        std::lock_guard<std::mutex> lk(m_bmtx);
        auto it = m_won_offer.find(p);
        if (it == m_won_offer.end()) return;
        auto& u = it->second.unconfirmed;
        for (auto e = u.begin(); e != u.end();) {
            if (nonce > e->first) { note_won_held(nn, e->second); m_st.won_held_confirmed++; e = u.erase(e); }
            else ++e;
        }
    }
    void pump_won_offers() {   // maintenance tick
        if (m_o.drops_floor_diff == 0) return;
        std::vector<PeerId> ps;
        {
            std::lock_guard<std::mutex> lk(m_bmtx);
            for (const auto& [p, o] : m_won_offer) if (!o.todo.empty()) ps.push_back(p);
        }
        for (PeerId p : ps) pump_won_offer(p);
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
    // The status line's "last unresolved" names a Monero context prev_id; once
    // that context resolves the line is stale -- clear it (cosmetic).
    void clear_unresolved_for(const bytes32& id) {
        std::lock_guard<std::mutex> lk(m_mtx);
        if (!m_last_unresolved.empty() && m_last_unresolved.find("prev_id " + hex_short(id)) != std::string::npos)
            m_last_unresolved.clear();
    }
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
            clear_unresolved_for(id);
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
        std::vector<bytes32> resolved_now;
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
                    resolved_now.push_back(it->first);
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
        for (const auto& id : resolved_now) clear_unresolved_for(id);
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
                if (!upg(m_q) && !upg(m_parked)) {
                    // HOLD-ROUND-2 (B): an AHEAD-parked flood copy -> back to the
                    // patience path as solicited (a repair answer, Ruling A)
                    for (auto ait = m_ahead.begin(); ait != m_ahead.end(); ++ait) {
                        if (ait->id != it.id || ait->solicited) continue;
                        auto n = m_ahead_n.find(ait->ahead_node);
                        if (n != m_ahead_n.end() && n->second && --n->second == 0) m_ahead_n.erase(n);
                        Item x = std::move(*ait); m_ahead.erase(ait);
                        x.solicited = true; x.from = it.from; x.enq = Clock::now(); x.not_before = Clock::now();
                        m_parked.push_back(std::move(x));
                        m_st.upgraded_solicited++;
                        break;
                    }
                }
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
    // HOLD-ROUND-2 (B): park an AHEAD share until the share state advances.
    // ★ V4: the per-sender bound is keyed by the sender NODE (its HELLO
    // node_nonce, inv_node), not the connection: a peer that reconnects (or is
    // re-dialed after every drop) keeps one share_ahead_per_peer budget. At
    // share_ahead_max the HEAVIEST node's oldest entry goes first (ties: the
    // oldest such entry), never the global oldest: N connections of fabricated
    // AHEAD takes cannot evict an honest finder's few parked shares.
    void park_ahead(Item it) {
        it.ahead_node = inv_node(it.from);   // takes m_pmtx: before m_mtx
        std::lock_guard<std::mutex> lk(m_mtx);
        auto evict = [&](std::deque<Item>::iterator victim) {
            auto n = m_ahead_n.find(victim->ahead_node);
            if (n != m_ahead_n.end() && n->second && --n->second == 0) m_ahead_n.erase(n);
            m_inflight.erase(victim->id);
            m_ahead.erase(victim);
            m_st.share_ahead_evicted++;
        };
        if (m_o.share_ahead_per_peer && m_ahead_n[it.ahead_node] >= m_o.share_ahead_per_peer) {
            for (auto v = m_ahead.begin(); v != m_ahead.end(); ++v) if (v->ahead_node == it.ahead_node) { evict(v); break; }
        }
        while (!m_ahead.empty() && m_ahead.size() >= std::max<std::size_t>(1, m_o.share_ahead_max)) {
            std::size_t top = 0;
            for (const auto& [node, c] : m_ahead_n) { (void)node; top = std::max(top, c); }
            auto v = m_ahead.begin();
            for (; v != m_ahead.end(); ++v) { const auto c = m_ahead_n.find(v->ahead_node); if (c != m_ahead_n.end() && c->second == top) break; }
            evict(v == m_ahead.end() ? m_ahead.begin() : v);
        }
        ++m_ahead_n[it.ahead_node];
        m_ahead.push_back(std::move(it));
    }
    // HOLD-ROUND-2 V4: AHEAD shares parked per sender node (inv_node keys)
    std::map<u64, std::size_t> share_ahead_by_node() const { std::lock_guard<std::mutex> lk(m_mtx); return m_ahead_n; }

    void process(Item it) {
        const auto now = Clock::now();
        {
            std::lock_guard<std::mutex> lk(m_mtx);
            if (m_cache.count(it.id)) { m_inflight.erase(it.id); m_st.dup++; return; }
        }
        // context: prev_id -> (bin, seed)
        ::v37::xmr::verify::ParsedBlob pb;
        if (!::v37::xmr::verify::parse_hashing_blob(it.r.receipt.hashing_blob, pb)) {
            m_st.structural++; forget_inflight(it.id); note_drop_refused(it.id); strike(it.from, "hashing blob does not parse"); return;
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
                note_drop_refused(it.id);   // HOLD-ROUND-2 (C2)
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
            m_st.expired++; forget_inflight(it.id); note_drop_refused(it.id); return;
        }
        CheckCtx cc; cc.lane_chain = m_o.chain; cc.share_diff = m_o.share_diff; cc.bind = m_o.bind;
        const CheckResult cr = check_structural(it.r, cc);
        if (!cr.ok()) {
            m_st.structural++; forget_inflight(it.id); note_drop_refused(it.id);
            strike(it.from, std::string("structural ") + to_string(cr.stage) + ": " + cr.why);
            return;
        }
        // SHARE-LEVEL CANONICAL COINBASE: before RandomX (cheap, and a refused
        // receipt never costs a hash). The coinbase height is ctx->height itself:
        // the ChainView maps prev_id to the height of the block built ON it (the
        // template's height, the chain feed's h + 1), which is the coinbase's
        // height. (It was passed + 1, so every honest share rebuilt one block
        // high, was refused as non-canonical and struck its sender;
        // v37_xmr_relay_multinode_kat M2 pins the height.)
        if (m_verdict) {
            std::string vw;
            int v = m_verdict(it.r, pb, ctx->height, vw);
            if (v >= kShareVerdictAhead) {
                // ★ HOLD-ROUND-2 (B): lane-prefix SKEW -- the sender is a lane block
                // ahead of (or behind) this node. Never a strike: the attempt-7 ban
                // loop (every finder share struck on the receivers' older prefix).
                if (it.solicited) {
                    v = 0;   // a repair answer: the patience path, then trusted (Ruling A)
                } else if (v == kShareVerdictAhead) {
                    m_st.share_skew_ahead++;
                    park_ahead(std::move(it));
                    return;
                } else if (v == kShareVerdictUnbased) {
                    // ★ HOLD-ROUND-3 (F4): no V37N base, the outputs differ: a lane
                    // block ahead / behind, or garbage -- parked like AHEAD (the same
                    // per-node / total bounds), re-judged on every share-state advance,
                    // dropped without a strike once kShareUnbasedMaxRounds re-judges
                    // never turned canonical. Never a strike, never a ban (attempt 8).
                    if (++it.unbased_rounds > kShareUnbasedMaxRounds) {
                        m_st.share_unbased_expired++;
                        forget_inflight(it.id); note_drop_refused(it.id);
                        return;
                    }
                    m_st.share_unbased_parked++;
                    park_ahead(std::move(it));
                    return;
                } else {
                    (v == kShareVerdictBehind ? m_st.share_skew_behind : m_st.share_late)++;
                    forget_inflight(it.id); note_drop_refused(it.id);
                    return;
                }
            }
            if (v < 0) {
                m_st.share_refused++; forget_inflight(it.id); note_drop_refused(it.id);
                { std::lock_guard<std::mutex> lk(m_mtx); m_last_share_refused = "receipt " + hex_short(it.id) + ": " + vw; }
                strike(it.from, "share coinbase not canonical: " + vw);
                return;
            }
            if (v == 0) {
                const u32 patience = it.solicited ? m_o.solicited_unresolved_patience_ms : m_o.unresolved_patience_ms;
                if (now - it.enq < std::chrono::milliseconds(patience)) {
                    m_st.share_parked++;
                    park(std::move(it), std::chrono::milliseconds(1000));
                    return;
                }
                if (!it.solicited) { m_st.share_undecided_dropped++; forget_inflight(it.id); return; }
                m_st.share_undecided_trusted++;   // a repair answer: the winner's lane holds it (Ruling A)
            }
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
            {
                std::lock_guard<std::mutex> lk(m_mtx);
                if (it.solicited) m_solicited += 1.0; else m_dos.on_valid_pow(p32, now_ns());   // our fault: give the token back
            }
            // DROPS-VERIFY-SCALE: the engine refuses while a switch keys the new
            // seed's cache (async_next_seed): park ONCE and retry instead of
            // silently forgetting the item (it was lost on this node only).
            if (m_rx && !it.rx_retried) {
                it.rx_retried = true;
                m_st.rx_unavail_parked++;
                park(std::move(it), std::chrono::milliseconds(500));
                return;
            }
            m_st.rx_unavailable++;
            forget_inflight(it.id);
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
        note_drop_refused(it.id);   // HOLD-ROUND-2 (C2): not a raindrop at all
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
        // ★ DROPS-RETAIN: the store outlives the dedup FIFO (drops_seen_max): a
        // raindrop it still holds is a duplicate, never re-admitted / re-flooded
        if (!it.solicited) { std::lock_guard<std::mutex> lk(m_dsmtx); if (m_drop_store_id.count(it.id)) { m_st.drops_dup++; return; } }
        if (!drop_note_new(it.id)) { m_st.drops_dup++; return; }
        Admitted a;
        a.id = it.id; a.r = std::move(it.r); a.raw = std::move(it.raw); a.bin = bin; a.own = false;
        a.drop = true; a.pow = pow;
        m_st.drops_foreign++;
        if (it.solicited && drop_unwant(a.id)) m_st.drops_backfilled++;   // ★ RAIN-BACKFILL
        drop_store_put(a.id, bin, a.raw, a.pow);
        flood(a.raw, it.from);
        std::lock_guard<std::mutex> lk(m_amtx);
        m_drops.push_back(std::move(a));
    }

    // ── ★ RAIN-BACKFILL: the servable raindrop store + the two frames ────────
    void drop_store_put(const bytes32& id, u64 bin, const std::vector<u8>& raw, const bytes32& pow) {
        std::lock_guard<std::mutex> lk(m_dsmtx);
        if (m_pin_asked.erase(id)) m_st.drops_pin_pruned++;   // ★ DROPS-HARDEN (d1): an asked id arrived
        if (!store_insert_locked(id, bin, raw, pow)) return;
        if (seg_on()) m_seg_append[bin].push_back(id);   // ★ DROPS-RETAIN: appended to <bin>.seg at the next persist
        drop_store_evict_locked(bin);
    }
    // ── ★ DROPS-RETAIN: the store's index + byte accounting (m_dsmtx held) ──
    static constexpr u64 kDropEntryOverhead = 160;   // id + bin + pow + map nodes, per raindrop
    bool seg_on() const { return !m_o.drops_persist_path.empty() && m_o.drops_floor_diff != 0; }   // segment work is tracked
    static u64 drop_entry_bytes(const std::vector<u8>& raw) { return static_cast<u64>(raw.size()) + kDropEntryOverhead; }
    bool store_insert_locked(const bytes32& id, u64 bin, const std::vector<u8>& raw, const bytes32& pow) {
        if (!m_drop_store_id.emplace(id, bin).second) return false;
        m_drop_store[bin].emplace(id, raw);
        m_drop_pow[id] = pow;   // ★ DROPS-HARDEN (d4): persisted with the bytes
        m_drop_store_bytes += drop_entry_bytes(raw);
        m_drop_dirty = true;
        return true;
    }
    std::size_t retain_locked(const std::string& key, const std::vector<bytes32>& ids) {
        auto& held = m_drop_pins[key];
        std::unordered_set<bytes32, Bytes32Hash> have(held.begin(), held.end());
        std::size_t n = 0;
        for (const auto& id : ids) {
            if (!have.insert(id).second) continue;
            held.push_back(id);
            ++m_drop_retained[id]; ++n;
        }
        return n;
    }
    bool drop_over_budget_locked() const {
        return m_drop_store_bytes > m_o.drops_store_bytes || (m_o.drops_store_max && m_drop_store_id.size() > m_o.drops_store_max);
    }
    // Evict the UNRETAINED raindrops of one bin; a bin left empty is erased
    // (its segment unlinked), a bin left with pinned raindrops only is kept
    // (its segment rewritten without the evicted records). Returns the next bin.
    using DropStoreIt = std::map<u64, std::map<bytes32, std::vector<u8>>>::iterator;
    DropStoreIt evict_bin_locked(DropStoreIt it, bool overflow) {
        const u64 bin = it->first;
        auto& m = it->second;
        std::size_t gone = 0, kept = 0;
        for (auto jt = m.begin(); jt != m.end();) {
            if (m_drop_retained.count(jt->first)) { ++kept; ++jt; continue; }
            m_drop_store_bytes -= drop_entry_bytes(jt->second);
            m_drop_store_id.erase(jt->first); m_drop_pow.erase(jt->first);
            jt = m.erase(jt); ++gone;
        }
        if (gone) {
            m_drop_dirty = true;
            if (overflow) m_st.drops_store_overflow_bins++; else m_st.drops_evict_floor_bins++;
        }
        if (kept) m_st.drops_evict_kept_pinned += kept;   // pinned raindrops an eviction pass had to step over
        if (m.empty()) {
            m_seg_append.erase(bin); m_seg_rewrite.erase(bin);
            if (seg_on()) m_seg_unlink.insert(bin);
            return m_drop_store.erase(it);
        }
        if (gone && seg_on()) { m_seg_append.erase(bin); m_seg_rewrite.insert(bin); }
        return std::next(it);
    }
    // L1: (1) every unretained raindrop below the floor (or, before the daemon
    // set one, below tip - drops_retain_bins); (2) over the byte budget / the
    // optional count, the oldest unretained bins (overflow: counted, loud).
    // `just` = the bin just stored (never evicted while it is the only bin).
    void drop_store_evict_locked(u64 just) {
        u64 keep_from = m_drop_floor;
        if (!m_drop_floor_set) {
            const u64 tip = m_chain.tip();
            keep_from = tip > m_o.drops_retain_bins ? tip - m_o.drops_retain_bins : 0;
        }
        for (auto it = m_drop_store.begin(); it != m_drop_store.end() && it->first < keep_from;) {
            if (it->first == just && m_drop_store.size() == 1) break;   // never evict the one just stored
            it = evict_bin_locked(it, false);
        }
        if (!drop_over_budget_locked()) return;
        for (auto it = m_drop_store.begin(); it != m_drop_store.end() && drop_over_budget_locked();) {
            if (it->first == just && std::next(it) == m_drop_store.end()) break;   // the newest bin, just stored
            it = evict_bin_locked(it, true);
        }
    }
    // ★ DROPS-RETAIN (K6): one inventory key of drops_sync; true = this peer's
    // inventory of [l, h) is held here (or the peer is set aside for it). An
    // inventory truncated at kDropsInvMaxIds over more than one bin is paged:
    // one key per bin, each asked and fetched on its own.
    struct SyncWork {
        std::vector<std::tuple<PeerId, u64, u64>> ask_inv;
        std::vector<std::tuple<PeerId, u64, bytes32>> ask_page;   // HOLD-ROUND-2 (C1): (peer, bin, cursor)
        std::vector<std::tuple<PeerId, u64, u64, std::vector<bytes32>>> fetch;
    };
    bool drops_sync_step_locked(PeerId p, u64 node, u64 l, u64 h, Clock::time_point now, DropsSync& out, SyncWork& work) {
        PeerInv& inv = m_drop_inv[InvKey{node, l, h}];
        inv.touched = now;
        if (!inv.answered) {
            if (inv.asked == Clock::time_point{} || now - inv.asked >= std::chrono::milliseconds(m_o.drops_inv_retry_ms)) {
                inv.asked = now; work.ask_inv.emplace_back(p, l, h);
            }
            return false;
        }
        if (inv.set_aside) { ++out.set_aside; return true; }
        if (inv.ids.size() >= kDropsInvMaxIds && h - l > 1) {   // truncated: page per bin
            if (!m_drop_inv.count(InvKey{node, l, l + 1})) m_st.drops_inv_paged++;
            bool ok = true;
            for (u64 b = l; b < h; ++b) ok = drops_sync_step_locked(p, node, b, b + 1, now, out, work) && ok;
            return ok;
        }
        // ★ HOLD-ROUND-2 (C1): ONE bin over kDropsInvMaxIds (VERIFY F3: a bin was
        // never paged, so "complete" held with the rest never asked): the next
        // page by cursor (GETDROPS [l, l+1) with the id twice = "ids > it"). An
        // old server answers that with the receipt, never a page: after
        // drops_inv_page_max_asks unanswered asks its unpaged page is kept.
        bool paging = false;
        if (h - l == 1 && inv.more && !inv.ids.empty()) {
            if (inv.page_asks >= m_o.drops_inv_page_max_asks) { inv.more = false; m_st.drops_inv_page_gaveup++; }
            else {
                paging = true;
                if (inv.page_asked == Clock::time_point{} || now - inv.page_asked >= std::chrono::milliseconds(m_o.drops_inv_retry_ms)) {
                    inv.page_asked = now; ++inv.page_asks; work.ask_page.emplace_back(p, l, inv.ids.back());
                }
            }
        }
        std::vector<bytes32> miss;
        for (const auto& id : inv.ids) if (!drop_held_locked(id)) miss.push_back(id);
        if (miss.empty()) return !paging;
        out.missing += miss.size();
        if (inv.fetched == Clock::time_point{} || now - inv.fetched >= std::chrono::milliseconds(m_o.drops_fetch_retry_ms)) {
            if (inv.asks >= m_o.drops_fetch_max_asks) {
                inv.set_aside = true; ++out.set_aside; m_st.drops_peer_setaside++;
                log("relay: drops backfill: peer " + std::to_string(p) + " did not serve " + std::to_string(miss.size()) +
                    " raindrop(s) of its own inventory of [" + std::to_string(l) + "," + std::to_string(h) + ") after " +
                    std::to_string(inv.asks) + " asks -> set aside for this range");
                return true;
            }
            ++inv.asks; inv.fetched = now;
            for (const auto& id : miss) m_drop_want[id] = now;
            work.fetch.emplace_back(p, l, h, std::move(miss));
        }
        return false;
    }
    // held = admitted here (servable) or at least seen (dedup set): nothing to fetch
    bool drop_held_locked(const bytes32& id) {
        if (m_drop_store_id.count(id)) return true;
        {
            std::lock_guard<std::mutex> lk(m_mtx);
            if (m_drop_seen.count(id) != 0) return true;
        }
        // ★ HOLD-ROUND-2 (C2): fetched here and not admissible (beyond the index
        // horizon, structurally bad, refused by the verdict, no context, not a
        // raindrop) -- "complete" = holds every raindrop it WOULD admit. Pre-fix
        // such an id was never "held", so it was asked again at every inventory
        // (B in attempt 7: the bin-2220689 page asked 3.75M times).
        if (drop_refused_has(id)) { m_st.drops_refused_held++; return true; }
        return false;
    }
    // m_drmtx is a LEAF lock (taken under m_mtx or m_dsmtx, never the reverse).
    bool drop_refused_has(const bytes32& id) const {
        std::lock_guard<std::mutex> lk(m_drmtx);
        return m_drop_refused.count(id) != 0;
    }
    void note_drop_refused(const bytes32& id) {
        if (!m_o.drops_floor_diff) return;
        std::lock_guard<std::mutex> lk(m_drmtx);
        if (!m_drop_refused.insert(id).second) return;
        m_drop_refused_order.push_back(id);
        m_st.drops_refused++;
        while (m_drop_refused_order.size() > std::max<std::size_t>(1, m_o.drops_refused_max)) {
            m_drop_refused.erase(m_drop_refused_order.front()); m_drop_refused_order.pop_front();
        }
    }
    bool drop_wanted(const bytes32& id) const { std::lock_guard<std::mutex> lk(m_dsmtx); return m_drop_want.count(id) != 0; }
    bool drop_unwant(const bytes32& id) { std::lock_guard<std::mutex> lk(m_dsmtx); return m_drop_want.erase(id) != 0; }
    void send_drop_invreq(PeerId p, u64 lo, u64 hi) {
        const auto f = encode_getdrops(m_o.chain, lo, hi, {});
        if (!f.empty() && m_net.send_to(p, f)) m_st.drops_invreq_tx++;
    }
    // HOLD-ROUND-2 (C1): the next inventory page of ONE bin (ids > after)
    void send_drop_page(PeerId p, u64 bin, const bytes32& after) {
        const auto f = encode_getdrops_page(m_o.chain, bin, after);
        if (!f.empty() && m_net.send_to(p, f)) m_st.drops_inv_pages_tx++;
    }
    void send_drop_fetch(PeerId p, u64 lo, u64 hi, const std::vector<bytes32>& ids) {
        for (std::size_t i = 0; i < ids.size(); i += kDropsGetMaxIds) {
            std::vector<bytes32> part(ids.begin() + static_cast<std::ptrdiff_t>(i),
                                      ids.begin() + static_cast<std::ptrdiff_t>(std::min(ids.size(), i + kDropsGetMaxIds)));
            const auto f = encode_getdrops(m_o.chain, lo, hi, part);
            if (!f.empty() && m_net.send_to(p, f)) { m_st.drops_fetch_tx++; m_st.drops_ids_asked += part.size(); }
        }
    }
    void on_getdrops(PeerId p, const std::vector<u8>& f) {
        u32 chain = 0; u64 lo = 0, hi = 0; std::vector<bytes32> ids; std::string why;
        if (!decode_getdrops(f, chain, lo, hi, ids, &why)) { m_st.malformed++; strike(p, why); return; }
        if (chain != m_o.chain) { m_st.wrong_chain++; return; }
        const bool page = is_getdrops_page(lo, hi, ids);   // HOLD-ROUND-2 (C1): "ids > ids[0] in bin lo"
        if (ids.empty() || page) {                           // inventory (or its next page)
            m_st.drops_invreq_rx++;
            std::vector<bytes32> inv;
            {
                std::lock_guard<std::mutex> lk(m_dsmtx);
                if (page) {
                    m_st.drops_inv_pages_served++;
                    auto bi = m_drop_store.find(lo);
                    if (bi != m_drop_store.end())
                        for (auto it = bi->second.upper_bound(ids[0]); it != bi->second.end() && inv.size() < kDropsInvMaxIds; ++it)
                            inv.push_back(it->first);
                } else
                for (auto it = m_drop_store.lower_bound(lo); it != m_drop_store.end() && it->first < hi; ++it)
                    for (const auto& [id, raw] : it->second) { (void)raw; if (inv.size() < kDropsInvMaxIds) inv.push_back(id); }
            }
            std::sort(inv.begin(), inv.end());
            const auto out = encode_dropinv(m_o.chain, lo, hi, inv);
            if (!out.empty() && m_net.send_to(p, out)) m_st.drops_inv_tx++;
            return;
        }
        m_st.drops_fetchreq_rx++;                            // fetch: answer with FB_RECEIPTS frames
        std::vector<std::vector<u8>> raws;
        {
            std::lock_guard<std::mutex> lk(m_dsmtx);
            for (const auto& id : ids) {
                auto bi = m_drop_store_id.find(id);
                if (bi == m_drop_store_id.end()) continue;
                auto si = m_drop_store.find(bi->second);
                if (si == m_drop_store.end()) continue;
                auto ri = si->second.find(id);
                if (ri != si->second.end()) raws.push_back(ri->second);
            }
        }
        for (std::size_t i = 0; i < raws.size(); i += kFbMaxReceiptsPerFrame) {
            std::vector<const std::vector<u8>*> v;
            for (std::size_t k = i; k < raws.size() && k < i + kFbMaxReceiptsPerFrame; ++k) v.push_back(&raws[k]);
            const auto fr = encode_receipts_frame(m_o.chain, v);
            if (!fr.empty() && m_net.send_to(p, fr)) m_st.drops_served += v.size();
        }
    }
    void on_dropinv(PeerId p, const std::vector<u8>& f) {
        u32 chain = 0; u64 lo = 0, hi = 0; std::vector<bytes32> ids; std::string why;
        if (!decode_dropinv(f, chain, lo, hi, ids, &why)) { m_st.malformed++; strike(p, why); return; }
        if (chain != m_o.chain) { m_st.wrong_chain++; return; }
        m_st.drops_inv_rx++;
        const u64 node = inv_node(p);   // HOLD-ROUND-2 (C3): outside m_dsmtx
        std::vector<bytes32> miss;
        bool set_aside_now = false;
        {
            std::lock_guard<std::mutex> lk(m_dsmtx);
            auto it = m_drop_inv.find(InvKey{node, lo, hi});
            if (it == m_drop_inv.end()) return;              // unsolicited: ignored
            PeerInv& inv = it->second;
            // HOLD-ROUND-2 (C1): the answer to a cursor page appends (every id above
            // the last one held); anything else is a fresh inventory
            const bool page = inv.answered && inv.more && hi == lo + 1 && !inv.ids.empty() &&
                              (ids.empty() || inv.ids.back() < ids.front());
            std::size_t from = 0;
            if (page) {
                from = inv.ids.size();
                inv.ids.insert(inv.ids.end(), ids.begin(), ids.end());
                inv.more = ids.size() >= kDropsInvMaxIds; inv.page_asks = 0; inv.page_asked = Clock::time_point{};
                m_st.drops_inv_pages_rx++;
            } else {
                inv.ids = std::move(ids);
                inv.more = (hi == lo + 1 && inv.ids.size() >= kDropsInvMaxIds);
            }
            inv.answered = true;
            const auto now = Clock::now();
            for (std::size_t i = from; i < inv.ids.size(); ++i) if (!drop_held_locked(inv.ids[i])) miss.push_back(inv.ids[i]);
            // HOLD-ROUND-2 (C3): the fetch-at-once goes through the per-node ask
            // budget (pre-fix it bypassed it, and each reconnect reset it)
            if (!miss.empty()) {
                if (inv.set_aside) miss.clear();
                else if (inv.asks >= m_o.drops_fetch_max_asks) {
                    inv.set_aside = true; set_aside_now = true; miss.clear();
                    m_st.drops_peer_setaside++; m_st.drops_inv_budget_setaside++;
                } else {
                    ++inv.asks; inv.fetched = now;
                    for (const auto& id : miss) m_drop_want[id] = now;
                }
            }
        }
        if (set_aside_now)
            log("relay: drops backfill: peer " + std::to_string(p) + " (node " + std::to_string(node) + ") inventory of [" +
                std::to_string(lo) + "," + std::to_string(hi) + ") still unfetched after " + std::to_string(m_o.drops_fetch_max_asks) +
                " asks across reconnects -> set aside");
        if (!miss.empty()) send_drop_fetch(p, lo, hi, miss);   // fetch at once (drops_sync re-asks)
    }
    // ── ★ DROPS-HARDEN (d4) + ★ DROPS-RETAIN: the persisted raindrop store ──
    // Per-bin append-only segments <drops_persist_path>.d/<bin>.seg:
    //   header  "V37DRS1\0" | chain u32 | lane_params_digest 32 | bin u64
    //   record  id 32 | pow 32 | len u32 | raw | chk 8 (sha256d of the record's bytes before it, first 8)
    // Written from the maint thread when the store changed (at most every
    // drops_persist_ms) and at stop(): new raindrops of a bin are APPENDED (+
    // fsync), a bin that lost raindrops to an eviction is REWRITTEN (tmp + fsync
    // + rename), an evicted bin is UNLINKED. The old design rewrote the WHOLE
    // store every ~2.4 s (56 MB at the 65536 cap: ~23 MB/s on every host, A6).
    // A torn record ends its segment (the valid prefix loads; the bin is
    // rewritten). The legacy whole-store file <drops_persist_path> = "V37DRP1\0"
    // | chain u32 | lane_params_digest 32 | n u32 | n x (id 32 | bin u64 | pow 32 |
    // len u32 | raw) | sha256d(all before) 32 is read when no segment exists.
    static constexpr u8 kDropsFileMagic[8] = {'V', '3', '7', 'D', 'R', 'P', '1', 0};
    static constexpr u8 kDropsSegMagic[8] = {'V', '3', '7', 'D', 'R', 'S', '1', 0};
    static constexpr std::size_t kDropsFileMaxRaw = 65536;
    static constexpr std::size_t kDropsSegHeader = 8 + 4 + 32 + 8;
    static void dput(std::vector<u8>& b, u64 v, int n) { for (int i = 0; i < n; ++i) b.push_back(static_cast<u8>(v >> (8 * i))); }
    std::string seg_dir() const { return m_o.drops_persist_path + ".d"; }
    std::string seg_path(u64 bin) const { return seg_dir() + "/" + std::to_string(bin) + ".seg"; }
    void seg_header(std::vector<u8>& b, u64 bin) const {
        b.insert(b.end(), kDropsSegMagic, kDropsSegMagic + 8);
        dput(b, m_o.chain, 4); b.insert(b.end(), m_o.lane_params_digest.begin(), m_o.lane_params_digest.end());
        dput(b, bin, 8);
    }
    static void seg_record(std::vector<u8>& b, const bytes32& id, const bytes32& pow, const std::vector<u8>& raw) {
        const std::size_t at = b.size();
        b.insert(b.end(), id.begin(), id.end()); b.insert(b.end(), pow.begin(), pow.end());
        dput(b, raw.size(), 4); b.insert(b.end(), raw.begin(), raw.end());
        const bytes32 h = ::v37::sha256d(b.data() + at, b.size() - at);
        b.insert(b.end(), h.begin(), h.begin() + 8);
    }
    static bool write_file_atomic(const std::string& path, const std::vector<u8>& b) {
        const std::string tmp = path + ".tmp";
        std::FILE* f = std::fopen(tmp.c_str(), "wb");
        bool ok = f && std::fwrite(b.data(), 1, b.size(), f) == b.size() && std::fflush(f) == 0 && ::fsync(::fileno(f)) == 0;
        if (f) ok = (std::fclose(f) == 0) && ok;
        return ok && std::rename(tmp.c_str(), path.c_str()) == 0;
    }
public:
    bool drops_persist() {
        if (m_o.drops_persist_path.empty() || !m_o.drops_floor_diff) return false;
        std::map<u64, std::vector<u8>> appends, rewrites;
        std::set<u64> unlinks;
        {
            std::lock_guard<std::mutex> lk(m_dsmtx);
            if (m_seg_append.empty() && m_seg_rewrite.empty() && m_seg_unlink.empty()) { m_drop_dirty = false; return false; }
            auto pow_of = [&](const bytes32& id) { const auto pi = m_drop_pow.find(id); return pi == m_drop_pow.end() ? bytes32{} : pi->second; };
            for (u64 bin : m_seg_rewrite) {
                const auto it = m_drop_store.find(bin);
                if (it == m_drop_store.end()) { unlinks.insert(bin); continue; }
                auto& b = rewrites[bin];
                seg_header(b, bin);
                for (const auto& [id, raw] : it->second) seg_record(b, id, pow_of(id), raw);
            }
            for (const auto& [bin, ids] : m_seg_append) {
                if (m_seg_rewrite.count(bin)) continue;
                const auto it = m_drop_store.find(bin);
                if (it == m_drop_store.end()) continue;
                auto& b = appends[bin];
                for (const auto& id : ids)
                    if (const auto r = it->second.find(id); r != it->second.end()) seg_record(b, id, pow_of(id), r->second);
            }
            unlinks.insert(m_seg_unlink.begin(), m_seg_unlink.end());
            m_seg_append.clear(); m_seg_rewrite.clear(); m_seg_unlink.clear();
            m_drop_dirty = false;
            m_drop_persisted_at = Clock::now();
        }
        std::error_code ec;
        std::filesystem::create_directories(seg_dir(), ec);
        std::set<u64> failed;
        for (u64 bin : unlinks)   // first: a bin evicted and re-created since the last persist starts afresh
            if (std::remove(seg_path(bin).c_str()) == 0) m_st.drops_seg_unlinks++;
        for (const auto& [bin, b] : rewrites) {
            if (write_file_atomic(seg_path(bin), b)) m_st.drops_seg_rewrites++;
            else failed.insert(bin);
        }
        for (const auto& [bin, b] : appends) {
            if (b.empty()) continue;
            std::FILE* f = std::fopen(seg_path(bin).c_str(), "ab");
            bool ok = f != nullptr;
            if (ok && std::fseek(f, 0, SEEK_END) == 0 && std::ftell(f) == 0) {   // a new segment: its header first
                std::vector<u8> h; seg_header(h, bin);
                ok = std::fwrite(h.data(), 1, h.size(), f) == h.size();
            }
            ok = ok && std::fwrite(b.data(), 1, b.size(), f) == b.size() && std::fflush(f) == 0 && ::fsync(::fileno(f)) == 0;
            if (f) ok = (std::fclose(f) == 0) && ok;
            if (ok) m_st.drops_seg_appends++; else failed.insert(bin);
        }
        if (!failed.empty()) {
            m_st.drops_persist_fail++;
            { std::lock_guard<std::mutex> lk(m_dsmtx); for (u64 bin : failed) m_seg_rewrite.insert(bin); m_drop_dirty = true; }
            log("relay: drops store persist FAILED for " + std::to_string(failed.size()) + " segment(s) under " + seg_dir() + ": " +
                std::strerror(errno));
            return false;
        }
        m_st.drops_persist_writes++;
        if (m_legacy_migrate.exchange(false))   // the legacy file is now segments: never read again
            (void)std::rename(m_o.drops_persist_path.c_str(), (m_o.drops_persist_path + ".migrated").c_str());
        return true;
    }
    // Boot (before start()): restore the store. The restored raindrops are
    // servable at once, count as seen, and are queued for drain_drops() so the
    // harvest holds exactly what the store holds (as before the restart).
    // ★ DROPS-RETAIN: segments are read NEWEST bin first while the store is
    // under its budget; an older bin past the budget keeps only its pinned
    // raindrops (drops_pin_retain before drops_load) and its segment is
    // dropped (drops_load_over_budget). A segment of another lane or with a bad
    // header is ignored; a torn tail ends that segment (the valid prefix loads).
    // No segment: the legacy whole-store file, read the same way (it used to be
    // ignored WHOLE when it held more than drops_store_max: a restart cliff);
    // any mismatch there (magic, chain, lane, trailer) = ignored, *why says so.
    struct LoadRec { bytes32 id; u64 bin; bytes32 pow; std::vector<u8> raw; };
    std::size_t drops_load(std::string* why = nullptr) {
        if (m_o.drops_persist_path.empty() || !m_o.drops_floor_diff) return 0;
        std::vector<std::pair<u64, std::string>> segs;
        std::error_code ec;
        if (std::filesystem::is_directory(seg_dir(), ec))
            for (const auto& e : std::filesystem::directory_iterator(seg_dir(), ec)) {
                const std::string n = e.path().filename().string();
                if (n.size() < 5 || n.compare(n.size() - 4, 4, ".seg") != 0) continue;
                const std::string num = n.substr(0, n.size() - 4);
                if (num.empty() || num.size() > 20 || num.find_first_not_of("0123456789") != std::string::npos) continue;
                segs.emplace_back(std::stoull(num), e.path().string());
            }
        if (segs.empty()) return drops_load_legacy(why);
        std::sort(segs.rbegin(), segs.rend());   // newest bin first
        std::size_t loaded = 0, torn = 0, bad = 0, over = 0;
        bool closed = false;   // once a bin does not fit, every older bin keeps its pinned raindrops only
        for (const auto& [bin, p] : segs) {
            std::vector<u8> b;
            if (!slurp_file(p, b)) { ++bad; continue; }
            std::vector<LoadRec> v;
            const int r = parse_segment(b, bin, v);
            if (r < 0) { ++bad; continue; }
            if (r > 0) { ++torn; m_st.drops_seg_torn++; std::lock_guard<std::mutex> lk(m_dsmtx); m_seg_rewrite.insert(bin); }
            if (!load_bin(bin, v, closed)) ++over;
            loaded += v.size();
        }
        m_st.drops_persist_loaded += loaded;
        if (why) {
            why->clear();
            if (torn || bad || over)
                *why = "segments=" + std::to_string(segs.size()) + " torn=" + std::to_string(torn) + " ignored=" + std::to_string(bad) +
                       " over_budget=" + std::to_string(over);
        }
        return loaded;
    }
private:
    static bool slurp_file(const std::string& p, std::vector<u8>& b) {
        std::FILE* f = std::fopen(p.c_str(), "rb");
        if (!f) return false;
        u8 buf[65536];
        for (std::size_t n; (n = std::fread(buf, 1, sizeof buf, f)) > 0;) b.insert(b.end(), buf, buf + n);
        std::fclose(f);
        return true;
    }
    static bool record_ok(const LoadRec& e) {
        FbReceipt r;
        return decode_fb_receipt(e.raw, r) && receipt_id(r) == e.id;
    }
    // -1 = not a segment of this lane / this bin; 0 = whole; 1 = torn tail (the valid prefix is in v)
    int parse_segment(const std::vector<u8>& b, u64 bin, std::vector<LoadRec>& v) const {
        if (b.size() < kDropsSegHeader || std::memcmp(b.data(), kDropsSegMagic, 8) != 0) return -1;
        auto rd = [&](std::size_t at, int n) { u64 x = 0; for (int i = n; i-- > 0;) x = (x << 8) | b[at + static_cast<std::size_t>(i)]; return x; };
        if (rd(8, 4) != m_o.chain || std::memcmp(b.data() + 12, m_o.lane_params_digest.data(), 32) != 0 || rd(44, 8) != bin) return -1;
        std::size_t o = kDropsSegHeader;
        while (o < b.size()) {
            if (o + 32 + 32 + 4 > b.size()) return 1;
            LoadRec e; e.bin = bin;
            std::memcpy(e.id.data(), b.data() + o, 32); std::memcpy(e.pow.data(), b.data() + o + 32, 32);
            const u64 len = rd(o + 64, 4);
            if (len > kDropsFileMaxRaw || o + 68 + len + 8 > b.size()) return 1;
            const bytes32 h = ::v37::sha256d(b.data() + o, 68 + static_cast<std::size_t>(len));
            if (std::memcmp(h.data(), b.data() + o + 68 + len, 8) != 0) return 1;
            e.raw.assign(b.begin() + static_cast<std::ptrdiff_t>(o + 68), b.begin() + static_cast<std::ptrdiff_t>(o + 68 + len));
            if (!record_ok(e)) return 1;
            v.push_back(std::move(e));
            o += 68 + static_cast<std::size_t>(len) + 8;
        }
        return 0;
    }
    // Insert one bin's records (newest-first loading). A bin that fits under the
    // budget (bytes, and the optional count) whole: all of them; else -- and for
    // every older bin after it (`closed`) -- the pinned ones only (the segment is
    // then rewritten or unlinked). false = the bin was (partly) dropped.
    bool load_bin(u64 bin, std::vector<LoadRec>& v, bool& closed) {
        bool full = true;
        {
            std::lock_guard<std::mutex> lk(m_dsmtx);
            if (!closed) {
                u64 add = 0;
                for (const auto& e : v) add += drop_entry_bytes(e.raw);
                closed = m_drop_store_bytes + add > m_o.drops_store_bytes ||
                         (m_o.drops_store_max && m_drop_store_id.size() + v.size() > m_o.drops_store_max);
            }
            full = !closed;
            if (!full) {
                v.erase(std::remove_if(v.begin(), v.end(), [&](const LoadRec& e) { return !m_drop_retained.count(e.id); }), v.end());
                m_st.drops_load_over_budget++;
                if (v.empty()) m_seg_unlink.insert(bin); else m_seg_rewrite.insert(bin);
                m_drop_dirty = true;
            }
        }
        std::vector<LoadRec> kept;
        for (auto& e : v) {
            if (!drop_note_new(e.id)) continue;
            { std::lock_guard<std::mutex> lk(m_dsmtx); if (!store_insert_locked(e.id, e.bin, e.raw, e.pow)) continue; }
            kept.push_back(std::move(e));
        }
        {
            std::lock_guard<std::mutex> lk(m_amtx);
            for (auto& e : kept) {
                Admitted a;
                decode_fb_receipt(e.raw, a.r);
                a.id = e.id; a.raw = std::move(e.raw); a.bin = e.bin; a.drop = true; a.pow = e.pow;
                m_drops.push_back(std::move(a));
            }
        }
        v.swap(kept);
        return full;
    }
    // the legacy whole-store file (pre-DROPS-RETAIN): newest bins first up to
    // the budget, then migrated (every loaded bin is written as a segment)
    std::size_t drops_load_legacy(std::string* why) {
        std::vector<u8> b;
        if (!slurp_file(m_o.drops_persist_path, b)) { if (why) *why = "absent"; return 0; }
        auto bad = [&](const char* w) { if (why) *why = std::string(w) + " (" + m_o.drops_persist_path + " ignored: empty store)"; return std::size_t{0}; };
        if (b.size() < 8 + 4 + 32 + 4 + 32 || std::memcmp(b.data(), kDropsFileMagic, 8) != 0) return bad("bad magic/size");
        const std::size_t body = b.size() - 32;
        if (::v37::sha256d(b.data(), body) != *reinterpret_cast<const bytes32*>(b.data() + body)) return bad("trailer hash mismatch (torn/corrupt)");
        std::size_t o = 8;
        auto get = [&](std::size_t n, u64& v) { if (o + n > body) return false; v = 0; for (std::size_t i = n; i-- > 0;) v = (v << 8) | b[o + i]; o += n; return true; };
        auto get32 = [&](bytes32& x) { if (o + 32 > body) return false; std::memcpy(x.data(), b.data() + o, 32); o += 32; return true; };
        u64 chain = 0, n = 0; bytes32 tag{};
        if (!get(4, chain) || !get32(tag) || !get(4, n)) return bad("truncated header");
        if (chain != m_o.chain || tag != m_o.lane_params_digest) return bad("another lane (chain / lane_params_digest differ)");
        std::map<u64, std::vector<LoadRec>, std::greater<u64>> by_bin;   // newest first
        for (u64 k = 0; k < n; ++k) {
            LoadRec e; u64 len = 0;
            if (!get32(e.id) || !get(8, e.bin) || !get32(e.pow) || !get(4, len) || len > kDropsFileMaxRaw || o + len > body) return bad("bad raindrop record");
            e.raw.assign(b.begin() + static_cast<std::ptrdiff_t>(o), b.begin() + static_cast<std::ptrdiff_t>(o + len)); o += len;
            if (!record_ok(e)) return bad("a record whose bytes are not its id");
            by_bin[e.bin].push_back(std::move(e));
        }
        if (o != body) return bad("trailing bytes");
        std::size_t loaded = 0, over = 0;
        bool closed = false;
        for (auto& [bin, v] : by_bin) {
            if (!load_bin(bin, v, closed)) ++over;
            loaded += v.size();
            std::lock_guard<std::mutex> lk(m_dsmtx);
            if (m_drop_store.count(bin)) { m_seg_rewrite.insert(bin); m_drop_dirty = true; }   // migrate to a segment
        }
        m_st.drops_persist_loaded += loaded;
        if (loaded) m_legacy_migrate = true;
        if (why) { why->clear(); if (over) *why = "legacy file: " + std::to_string(over) + " bin(s) past the budget dropped"; }
        return loaded;
    }
private:
    void drops_maint() {
        if (!m_o.drops_persist_path.empty()) {   // ★ DROPS-HARDEN (d4)
            bool due = false;
            {
                std::lock_guard<std::mutex> lk(m_dsmtx);
                due = m_drop_dirty && Clock::now() - m_drop_persisted_at >= std::chrono::milliseconds(m_o.drops_persist_ms);
            }
            if (due) drops_persist();
        }
        {   // ★ DROPS-RETAIN: an overflow evicts raindrops a pending block may still need: loud (at most once a minute)
            const u64 ov = m_st.drops_store_overflow_bins.load();
            if (ov != m_overflow_logged && Clock::now() - m_overflow_log_at >= std::chrono::minutes(1)) {
                m_overflow_logged = ov; m_overflow_log_at = Clock::now();
                log("relay: drops-ALARM store over budget (--drops-store-bytes " + std::to_string(m_o.drops_store_bytes) +
                    "): overflow_bins=" + std::to_string(ov) + " -- the oldest unretained raindrops were evicted; a winner pins only "
                    "what it can serve, so this costs raindrop credit, never a split");
            }
        }
        std::lock_guard<std::mutex> lk(m_dsmtx);
        const auto now = Clock::now();
        for (auto it = m_drop_inv.begin(); it != m_drop_inv.end();)
            it = (now - it->second.touched > std::chrono::minutes(10)) ? m_drop_inv.erase(it) : std::next(it);
        for (auto it = m_drop_want.begin(); it != m_drop_want.end();) {
            if (now - it->second > std::chrono::minutes(10)) {
                note_drop_refused(it->first);   // HOLD-ROUND-2 (C2): asked 10 min ago, never admitted
                it = m_drop_want.erase(it);
            } else ++it;
        }
        for (auto it = m_pin_asked.begin(); it != m_pin_asked.end();)   // ★ DROPS-SET-PIN
            it = (now - it->second.first > std::chrono::minutes(10)) ? m_pin_asked.erase(it) : std::next(it);
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
                Job j = q.front();
                q.pop_front();
                if (j.kind == Job::Kind::Order && !j.probe) j.issued = Clock::now();   // REPAIR-PAGE: its round trip sizes the repair page
                if (j.kind == Job::Kind::Order && j.repair && !j.probe) {   // REPAIR-PAGE
                    j.max_ids = repair_page_locked(p);
                    m_st.repair_order_pages++;
                    if (j.max_ids > m_st.repair_order_page_max.load()) m_st.repair_order_page_max = j.max_ids;
                }
                issue.emplace_back(p, j);
                m_cur_job[p] = std::move(j);
            }
        }
        for (auto& [p, j] : issue) {
            bool ok = false;
            if (j.kind == Job::Kind::Order)
                ok = j.max_ids ? m_fetch->request_order(p, m_o.chain, j.a, j.p, j.spine, j.max_ids)
                               : m_fetch->request_order(p, m_o.chain, j.a, j.p, j.spine);
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

    // REPAIR-PAGE liveness (#1808 review). A non-final page refreshes the
    // Ordering clock only when it carries >= min(ids asked, positions
    // remaining) / 2 ids; one peer's whole Ordering is capped at
    // timeout x (1 + ceil((P - a0) / first page asked)).
public:
    static bool repair_page_refreshes(u64 n_ids, u64 asked, u64 remaining, bool final_page) {
        return final_page || n_ids >= std::min<u64>(asked, remaining) / 2;
    }
    static std::chrono::milliseconds repair_order_cap(std::chrono::milliseconds timeout, u64 remaining0, u64 first_page) {
        const u64 pg = first_page ? first_page : 1;
        return timeout * static_cast<long long>(1 + (remaining0 + pg - 1) / pg);
    }
private:
    // REPAIR-PAGE: the page this peer's next repair GETORDER asks (m_jmtx held).
    u32 repair_page_max_locked() const {
        const u32 cap = m_o.repair_order_page_max_ids ? m_o.repair_order_page_max_ids : kCtrlMaxIdsPerOrder;
        return std::min<u32>(cap, kCtrlMaxIdsPerOrder);
    }
    u32 repair_page_locked(PeerId p) const {
        const u32 cap = repair_page_max_locked();
        auto it = m_rpage.find(p);
        const u32 first = m_o.repair_order_page_ids ? m_o.repair_order_page_ids : kCtrlMaxIdsPerOrder;
        return std::max<u32>(1, std::min<u32>(it != m_rpage.end() ? it->second : first, cap));
    }
    // An ORDER answer (a FULL repair page, or a backfill answer at least one
    // page long) that came back within a quarter of the request timeout grows
    // this peer's repair page to what that round trip fits in the quarter (x16
    // at most): a fast link reaches the cap, a slow one stays where its answers
    // arrive with a 4x margin to the timeout. A page that timed out halves
    // (floor 16). Never above the cap.
    void repair_page_answered(PeerId p, const Job& j, std::size_t n_ids) {
        if (j.issued == Clock::time_point{} || n_ids == 0 || (j.max_ids && n_ids < j.max_ids)) return;
        const auto rt = m_fetch ? m_fetch->options().request_timeout : std::chrono::milliseconds(5000);
        const auto budget = std::chrono::duration_cast<std::chrono::microseconds>(rt) / 4;
        const auto took = std::max<std::chrono::microseconds>(
            std::chrono::microseconds(1), std::chrono::duration_cast<std::chrono::microseconds>(Clock::now() - j.issued));
        if (took > budget) return;
        const u64 fit = static_cast<u64>(n_ids) * static_cast<u64>(budget.count()) / static_cast<u64>(took.count());
        std::lock_guard<std::mutex> lk(m_jmtx);
        const u32 cap = repair_page_max_locked();
        const u32 cur = repair_page_locked(p);
        if (n_ids < cur) return;   // a shorter answer says nothing about a page of cur ids
        const u32 next = static_cast<u32>(std::min<u64>({fit, static_cast<u64>(cur) * 16, static_cast<u64>(cap)}));
        if (next <= cur) return;
        m_rpage[p] = next;
        m_st.repair_page_grown++;
    }
    void repair_page_timed_out(PeerId p, const Job& j) {
        if (!j.max_ids) return;
        std::lock_guard<std::mutex> lk(m_jmtx);
        m_rpage[p] = std::max<u32>(std::min<u32>(16, j.max_ids), j.max_ids / 2);
        m_st.repair_page_timeouts++;
    }

    // REPAIR-CHAIN (F2-R): the next ask of peer p's down-walk (m_rmtx held):
    // q_k = a0 - G x 2^k aligned down to G (G = deep_probe_step), a zero-length
    // probe [q, q); at q = 0 the whole order [0, P) instead (the winner's order
    // itself -- always sufficient when this peer's lineage IS the winner's).
    Job walk_step_locked(Repair& r, PeerId p, const Job& j) {
        const u64 G = std::max<u64>(1, m_o.deep_probe_step);
        const u64 from = r.walk_from[p];
        const u32 k = r.walk_k[p]++;
        const u64 back = k >= 40 ? from : std::min<u64>(from, G << k);
        u64 q = from - back;
        q -= q % G;
        if (q == 0 && k == 0 && from > 1) q = from - 1;   // probe below the peer's horizon once before [0, P)
        Job n = j;
        n.max_ids = 0; n.ids.clear();
        r.since = Clock::now();
        r.has_a0_digest = false;
        if (q == 0) {
            m_st.repair_deep_full++;
            n.probe = false; n.a = 0; n.p = r.P; n.spine = r.spine;
            r.a0 = 0; r.cursor = 0; r.probing = false;
            return n;
        }
        m_st.repair_deep_probe++;
        n.probe = true; n.a = n.p = q; n.spine = bytes32{};
        if (const auto d = digest_at_deep(q)) n.spine = *d;
        r.a0 = q; r.cursor = q; r.probing = true;
        return n;
    }
    // REPAIR-CHAIN: a walked peer whose order cannot reach the spine (or an RC5
    // peer that refuses the walk) -> DEEP exactly as RC5 names it (m_rmtx held).
    void walk_failed_locked(Repair& r, PeerId p, bool rc5) {
        auto wf = r.walk_from.find(p);
        if (wf == r.walk_from.end()) return;
        r.deep[p] = wf->second;
        r.walk_failed.insert(p);
        r.walk_ok.erase(p);
        m_st.repair_deep++;
        if (rc5) m_st.repair_deep_rc5++; else m_st.repair_deep_lineage++;
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
                if (it != m_repairs.end() && it->second.st == Repair::St::Ordering && it->second.cur == p &&
                    (it->second.full_only || (!cj->probe && cj->a == 0 && it->second.walk_from.count(p)))) {
                    // ★ HOLD-ROUND-3 F3a: a refused WHOLE-ORDER ask [0, P) (the fallback, or a
                    // walk's last step). The server refuses the first [0, P) ask of a (peer, P)
                    // by design and serves the second: re-ask this peer ONCE from 0; a second
                    // refusal (below its retention, or no durable order) sets it aside.
                    Repair& r = it->second;
                    const u32 n = ++r.full_refused[p];
                    r.full_lowest[p] = o.lowest_retained;
                    if (n == 1) { r.rearm = p; r.full_next.insert(p); m_st.repair_full_reask++; }
                    else m_st.repair_full_refused++;
                } else if (it != m_repairs.end() && it->second.st == Repair::St::Ordering && it->second.cur == p &&
                    it->second.walk_from.count(p)) {
                    // REPAIR-CHAIN: a walk PROBE refused = an RC5 peer (no durable order):
                    // DEEP as RC5 names it.
                    if (cj->probe) walk_failed_locked(it->second, p, /*rc5=*/true);
                } else if (it != m_repairs.end() && it->second.st == Repair::St::Ordering && it->second.cur == p) {
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
            repair_page_answered(p, *j, o.ids.size());   // REPAIR-PAGE: its round trip measures this peer's link
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
            const auto ours = m_o.deep_order ? digest_at_deep(j->a) : digest_at(j->a);   // REPAIR-CHAIN: any position
            const bool alt_known = alt_digest_known(j->a);   // the shadows (reconstructed winner-side orders)
            const bool alt_eq = o.have_spine && alt_digest_is(j->a, o.spine_digest);
            bool go = false; std::string alarm;
            std::optional<Job> walk;   // REPAIR-CHAIN: the next step of a down-walk
            {
                std::lock_guard<std::mutex> lk(m_rmtx);
                auto it = m_repairs.find(j->key);
                if (it == m_repairs.end()) return;
                Repair& r = it->second;
                if (r.st != Repair::St::Ordering || r.cur != p || !r.probing || r.a0 != j->a) return;
                r.probing = false;
                const bool differs = o.p_served == j->a && o.have_spine && (ours || alt_known) &&
                                     !(ours && o.spine_digest == *ours) && !alt_eq;
                const bool equal = o.p_served == j->a && o.have_spine && ((ours && o.spine_digest == *ours) || alt_eq);
                if (r.walk_from.count(p) && !r.walk_checked.count(p)) {
                    // REPAIR-CHAIN: the walk's first probe is [P, P): a peer whose own
                    // digest at P is not the winner's spine cannot serve this cut from
                    // ANY start -- name it DEEP now instead of walking its whole order
                    if (o.p_served == j->a && o.have_spine && o.spine_digest == r.spine) {
                        r.walk_checked.insert(p);
                        walk = walk_step_locked(r, p, *j);
                    } else if (!o.have_spine || o.p_served != j->a) {
                        r.tried.insert(p); r.reset();   // the peer does not know P yet (lagging): retry later, not DEEP
                    } else {
                        walk_failed_locked(r, p, /*rc5=*/false);
                        r.tried.insert(p); r.reset();
                        alarm = "relay: REPAIR-CHAIN repair of P=" + std::to_string(r.P) + ": peer " + std::to_string(p) +
                                "'s lane digest at P is not the winner's spine -- its lineage cannot serve this cut (peer set aside as DEEP)";
                    }
                } else if (r.walk_from.count(p) && !equal) {
                    // REPAIR-CHAIN (F2-R): no equal state at this step (differs, or
                    // unknown on either side): step further down
                    walk = walk_step_locked(r, p, *j);
                } else if (r.walk_from.count(p)) {
                    m_st.repair_deep_equal++;
                    r.walk_ok[p] = j->a;
                    r.a0_digest = o.spine_digest; r.has_a0_digest = true;
                    r.since = Clock::now();
                    go = true;
                } else if (differs && m_o.deep_order && !r.walk_failed.count(p)) {
                    // REPAIR-CHAIN (F2-R): instead of setting the peer aside as DEEP,
                    // walk down to where our own / a shadow's state equals the peer's
                    r.walk_from[p] = j->a;
                    r.walk_k[p] = 0;
                    if (auto wo = r.walk_ok.find(p); wo != r.walk_ok.end() && wo->second < j->a) {
                        r.walk_checked.insert(p);   // a previous walk of this peer passed the [P, P) check
                        Job n = *j; n.a = n.p = wo->second; n.probe = true;   // the equal point a previous walk found
                        if (const auto d = digest_at_deep(n.a)) n.spine = *d;
                        r.a0 = r.cursor = n.a; r.probing = true; r.since = Clock::now();
                        m_st.repair_deep_probe++;
                        walk = std::move(n);
                    } else {   // first: the peer's digest at P ([P, P), inside its vault)
                        Job n = *j; n.a = n.p = r.P; n.probe = true; n.spine = r.spine; n.max_ids = 0;
                        r.a0 = r.cursor = r.P; r.probing = true; r.since = Clock::now();
                        m_st.repair_deep_probe++;
                        walk = std::move(n);
                    }
                } else if (differs) {
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
            if (walk) queue_job(p, std::move(*walk));
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
            ++r.pages; r.page_ids += o.ids.size();   // F3a: the fetch line's page count
            // REPAIR-PAGE: a page that ADVANCES the cursor is progress: restart
            // the Ordering clock, so a repair of many small pages is bounded per
            // page by repair_state_timeout_ms. #1808 review: only a SUBSTANTIAL
            // page is progress -- the final page, or one carrying at least
            // min(ids asked, positions remaining) / 2 ids. A peer answering 1 id
            // per page inside the request timeout no longer holds the repair for
            // (P - a0) x timeout; and the whole Ordering is capped per peer
            // (drive_repairs: timeout x (1 + ceil((P - a0) / first page))).
            {
                const u64 asked = j->max_ids ? j->max_ids : kCtrlMaxIdsPerOrder;
                if (!r.ordering_page) r.ordering_page = asked;
                const u64 remaining = r.P > r.cursor ? r.P - r.cursor : 0;
                const bool final_page = o.p_served >= r.P;
                if (o.p_served > r.cursor && repair_page_refreshes(o.ids.size(), asked, remaining, final_page))
                    r.since = Clock::now();
                else if (!final_page)
                    m_st.repair_order_thin++;
            }
            r.cursor = o.p_served;
            repair_page_answered(p, *j, o.ids.size());
            if (r.cursor < r.P) {
                Job n = *j; n.a = r.cursor; queue_job(p, std::move(n));
                pump_jobs();
                return;
            }
            if (!o.have_spine || o.spine_digest != r.spine) {
                // this peer's order does not reach the winner's digest at P
                if (o.have_spine) walk_failed_locked(r, p, /*rc5=*/false);   // REPAIR-CHAIN: a walked lineage -> DEEP (loud)
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

    void on_fetch_fail(PeerId p, SupplyFailure why) {
        auto j = take_cur_job(p);
        if (j && j->repair && j->kind == Job::Kind::Order && why == SupplyFailure::TIMEOUT) repair_page_timed_out(p, *j);
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
        std::vector<std::string> notes;   // logged after the repair lock is released
        {
            std::lock_guard<std::mutex> lk(m_rmtx);
            const auto now = Clock::now();
            const auto timeout = std::chrono::milliseconds(m_o.repair_state_timeout_ms);
            for (auto& [k, r] : m_repairs) {
                if (r.st == Repair::St::Ordering && now - r.since > timeout) {
                    if (r.cur) r.tried.insert(r.cur);
                    r.reset();
                }
                // REPAIR-PAGE liveness (#1808 review): the TOTAL Ordering of one
                // peer is capped at timeout x (1 + ceil((P - a0) / first page));
                // past it the peer is set aside however it paces its pages.
                if (r.st == Repair::St::Ordering && r.ordering_page) {
                    const u64 rem0 = r.P > r.a0 ? r.P - r.a0 : 0;
                    const auto cap = repair_order_cap(timeout, rem0, r.ordering_page);
                    if (now - r.ordering_started > cap) {
                        m_st.repair_order_capped++;
                        notes.push_back("relay: REPAIR-PAGE cap: repair of P=" + std::to_string(r.P) + " set peer " + std::to_string(r.cur) +
                                        " aside after " + std::to_string(std::chrono::duration_cast<std::chrono::milliseconds>(now - r.ordering_started).count()) +
                                        " ms ordering (cap " + std::to_string(std::chrono::duration_cast<std::chrono::milliseconds>(cap).count()) + " ms = " +
                                        std::to_string(m_o.repair_state_timeout_ms) + " ms x (1 + ceil(" + std::to_string(rem0) + " / " +
                                        std::to_string(r.ordering_page) + ")), cursor " + std::to_string(r.cursor) + "/" + std::to_string(r.P) + ")");
                        if (r.cur) r.tried.insert(r.cur);
                        r.reset();
                    }
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
                    if (r.exhausted && r.full_only && !r.full_alarmed) {   // ★ HOLD-ROUND-3 F3a: loud, once per repair
                        r.full_alarmed = true;
                        m_st.repair_full_exhausted++;
                        std::string who;
                        for (const auto& [p, n] : r.full_refused) {
                            const auto lo = r.full_lowest.find(p);
                            who += (who.empty() ? "" : ", ") + std::string("peer ") + std::to_string(p) + " x" + std::to_string(n) +
                                   (lo != r.full_lowest.end() ? " (retains >= " + std::to_string(lo->second) + ")" : "");
                        }
                        notes.push_back("relay-ALARM REPAIR-DEEP RETENTION: the WHOLE order [0," + std::to_string(r.P) + ") of the winner's cut spine=" +
                                        hex_short(r.spine) + " is served by NO connected peer: every ready peer refused it twice [" +
                                        (who.empty() ? "no answer" : who) + "] -- its positions are below every peer's --relay-order-retain window, or the "
                                        "peers run without a durable order. The block HOLDS (undecided); this node needs a peer retaining those positions "
                                        "or the cold-boot path (ledger + lane snapshot). Re-asking every 5 s.");
                    }
                    if (r.exhausted && Clock::now() - r.since > std::chrono::seconds(5)) { r.tried.clear(); r.since = Clock::now(); }
                    continue;
                }
                r.exhausted = false;
                // REPAIR-HORIZON: from this peer's known vault start a0 (0 = the whole
                // order); a0 > 0 asks the zero-length prefix probe [a0, a0) first.
                // ★ HOLD-ROUND-3 F3a: a whole-order fallback (or a re-asked whole-order
                // step) starts at 0 whatever the peer's horizon.
                const bool from_zero = r.full_only || r.full_next.erase(pick) > 0;
                const u64 a0 = from_zero ? 0 : (r.a0_of.count(pick) ? r.a0_of[pick] : 0);
                r.st = Repair::St::Ordering; r.cur = pick; r.a0 = a0; r.cursor = a0; r.probing = a0 > 0; r.ids.clear(); r.since = Clock::now();
                r.ordering_started = r.since; r.ordering_page = 0;   // REPAIR-PAGE liveness: the per-peer cap starts here
                Job j; j.kind = Job::Kind::Order; j.repair = true; j.key = k; j.a = a0; j.p = r.P; j.spine = r.spine;
                if (a0) { j.probe = true; j.p = a0; if (const auto d = digest_at(a0)) j.spine = *d; }
                issue.emplace_back(pick, std::move(j));
            }
        }
        for (const auto& n : notes) log(n);
        for (auto& [p, j] : issue) queue_job(p, std::move(j));
        if (!issue.empty()) pump_jobs();
    }

    // ── RELAY-DISCOVERY (FB_GETADDR 0x4c / FB_ADDR 0x4d) ────────────────────
    static u64 wall_s() {
        return static_cast<u64>(std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
    }
    static bool dialable_v4(const AddrEntry& e) {
        return e.family == kAddrFamV4 && e.ip[0] != 0 && e.port != 0;   // IPv4 transport; never 0.0.0.0/8
    }
    static bool is_public_host(const std::string& ip) {
        AddrEntry e; return addr_entry_of(ip, 1, 0, e) && addr_routable(e);
    }
    // Addresses we are linked to (dialed, or announced by an inbound peer).
    std::set<std::string> linked_keys() const {
        std::lock_guard<std::mutex> lk(m_pmtx);
        std::set<std::string> k;
        for (const auto& [p, s] : m_peers) {
            (void)p;
            if (!s.addr_key.empty()) k.insert(s.addr_key);
            if (!s.out_host.empty()) k.insert(peer_key(s.out_host, s.out_port));
        }
        return k;
    }
    void send_getaddr(PeerId p) {
        const auto f = encode_getaddr(m_o.chain, m_o.addr_want);
        {
            std::lock_guard<std::mutex> lk(m_pmtx);
            auto it = m_peers.find(p);
            if (it == m_peers.end() || !it->second.hello_ok) return;
            it->second.addr_pending = true;
            it->second.getaddr_tx = Clock::now();
        }
        if (m_net.send_to(p, f)) m_st.getaddr_tx++;
    }
    // A HELLO refused on a link WE dialed: that address is never good and never re-learned.
    void disc_refused(PeerId p, const std::string& mis, const Hello& hr) {
        std::string h; u16 port = 0;
        const bool self = hr.node_nonce == m_nonce;
        {
            std::lock_guard<std::mutex> lk(m_pmtx);
            auto it = m_peers.find(p);
            if (it == m_peers.end()) return;
            h = it->second.out_host; port = it->second.out_port;
        }
        if (h.empty()) {
            // NODE-NONCE: the accepting end of a self-dial: our announced address
            // (socket ip : HELLO listen port) is ours -- never learned or handed out.
            if (self && hr.listen_port) m_book.mark_self(m_net.remote_ip(p), hr.listen_port);
            return;
        }
        if (self) {
            m_st.disc_self++;
            m_book.mark_self(h, port);   // NODE-NONCE: never dialed, learned or handed out again
            log("relay-disc: " + peer_key(h, port) + " is THIS node (HELLO node nonce equal) -> marked self");
            return;
        }
        m_st.disc_bad++;
        m_book.mark_bad(h, port);
        log("relay-disc: " + peer_key(h, port) + " refused at HELLO -> never good, not re-learned (" + mis + ")");
    }
    // NODE-NONCE: a HELLO carrying OUR node nonce = this node talking to
    // itself. The link is closed by the caller; the dial target behind it is
    // retired for good (every mode, discovery ON or OFF). The target is found
    // by its pid OR by the dialed address: the self HELLO can be refused
    // before the dial loop has stored t.pid, and a pid-only match then missed
    // the target, which was dialed again after its backoff.
    void on_self_hello(PeerId p, const Hello&) {
        m_st.self_conn++;
        std::string oh; u16 op = 0;
        {
            std::lock_guard<std::mutex> lk(m_pmtx);
            auto it = m_peers.find(p);
            if (it != m_peers.end()) { oh = it->second.out_host; op = it->second.out_port; }
        }
        std::lock_guard<std::mutex> lk(m_tmtx);
        for (auto& t : m_targets) if (!t.self && (t.pid == p || (!oh.empty() && t.host == oh && t.port == op))) {
            t.self = true;
            if (t.learned) t.used = true;
            log("relay: dial target " + peer_key(t.host, t.port) + " is THIS node (HELLO node nonce equal) -> never dialed again");
        }
    }
    // NODE-NONCE: every address known to belong to a node we hold a HELLO-ok
    // link to (under that address or another one): dialing it again could only
    // make a duplicate link. A restarted node has a new nonce, so its old
    // addresses are dialable again at once.
    static constexpr std::size_t kAddrNonceMax = 4096;
    std::set<std::string> linked_node_keys() const {
        std::lock_guard<std::mutex> lk(m_pmtx);
        std::set<u64> live;
        for (const auto& [p, s] : m_peers) { (void)p; if (s.hello_ok) live.insert(s.remote.node_nonce); }
        std::set<std::string> v;
        for (const auto& [k, n] : m_addr_nonce) if (live.count(n)) v.insert(k);
        return v;
    }
    // HELLO ok: a dialed address becomes GOOD, so does an inbound peer's
    // announced address (it proved the pool id on this socket); a second link to the same node is dropped
    // (both ends keep the link dialed by the LOWER node nonce). false = this
    // link was the duplicate and is being dropped.
    bool disc_hello_ok(PeerId p, const Hello& h) {
        const u64 now = wall_s();
        std::string out_host; u16 out_port = 0;
        PeerId dup = 0; bool dup_out = false;
        {
            std::lock_guard<std::mutex> lk(m_pmtx);
            auto it = m_peers.find(p);
            if (it == m_peers.end()) return false;
            out_host = it->second.out_host; out_port = it->second.out_port;
            for (const auto& [q, s] : m_peers)
                if (q != p && s.hello_ok && s.remote.node_nonce == h.node_nonce) { dup = q; dup_out = !s.out_host.empty(); break; }
        }
        std::string key, rip;
        if (!out_host.empty()) {
            m_book.mark_good(out_host, out_port, now);
            key = peer_key(out_host, out_port);
            bool learned = false;
            {
                std::lock_guard<std::mutex> lk(m_tmtx);
                for (const auto& t : m_targets) if (t.learned && t.host == out_host && t.port == out_port) learned = true;
            }
            if (learned) m_st.disc_dial_ok++;
        } else {
            rip = m_net.remote_ip(p);
            if (!rip.empty() && h.listen_port) {
                // The peer proved the pool id at HELLO from this socket address: its
                // announced relay address (socket ip : HELLO listen port) is good. A
                // listen port that turns out unreachable is failed out by dialers.
                key = peer_key(rip, h.listen_port);
                m_book.mark_good(rip, h.listen_port, now);
            }
        }
        {
            std::lock_guard<std::mutex> lk(m_pmtx);
            auto it = m_peers.find(p);
            if (it == m_peers.end()) return false;
            it->second.addr_key = key; it->second.remote_ip = rip;
            if (!key.empty()) {   // NODE-NONCE: this address is that node (bounded, refreshed on every HELLO)
                if (m_addr_nonce.size() >= kAddrNonceMax && !m_addr_nonce.count(key)) m_addr_nonce.erase(m_addr_nonce.begin());
                m_addr_nonce[key] = h.node_nonce;
            }
        }
        if (dup) {
            // NODE-NONCE: one link per node, the same one on both ends (dup_link_rule).
            const DupPick pick = dup_link_rule(m_nonce, h.node_nonce, !out_host.empty(), dup_out);
            if (pick == DupPick::Defer) {
                m_st.dup_deferred++;
                log("relay-disc: duplicate link to node " + std::to_string(h.node_nonce & 0xffff) +
                    " dialed twice by the peer -> the peer closes one");
            } else {
                const bool drop_p = pick == DupPick::DropNew;
                const PeerId gone = drop_p ? p : dup;
                m_st.disc_dup_dropped++;
                log("relay-disc: duplicate link to node " + std::to_string(h.node_nonce & 0xffff) + " -> dropping peer " +
                    std::to_string(gone) + " (keep the link dialed by the lower node nonce; no penalty)");
                m_net.disconnect(gone);
                if (drop_p) return false;
            }
        }
        send_getaddr(p);
        return true;
    }
    void on_getaddr(PeerId p, const std::vector<u8>& f) {
        u32 chain = 0; u16 want = 0;
        if (!decode_getaddr(f, chain, want)) { m_st.malformed++; return; }
        if (chain != m_o.chain) { m_st.wrong_chain++; return; }
        m_st.getaddr_rx++;
        std::string asker_key, asker_ip;
        {
            std::lock_guard<std::mutex> lk(m_pmtx);
            auto it = m_peers.find(p);
            if (it == m_peers.end()) return;
            PeerSt& s = it->second;
            const auto now = Clock::now();
            if (s.getaddr_rx != Clock::time_point{} && now - s.getaddr_rx < std::chrono::milliseconds(m_o.addr_answer_min_ms)) {
                m_st.getaddr_throttled++;   // rate limit: one answer per peer per addr_answer_min_ms
                return;
            }
            s.getaddr_rx = now;
            asker_key = s.addr_key;
            asker_ip = s.out_host.empty() ? s.remote_ip : s.out_host;
        }
        // never hand a private / loopback address to a public peer; never the asker itself
        const bool asker_public = is_public_host(asker_ip);
        const auto sample = m_book.sample_good(std::min<std::size_t>(want, m_o.addr_answer_max), [&](const PeerRecord& r) {
            if (peer_key(r.host, r.port) == asker_key) return false;
            AddrEntry e;
            if (!addr_entry_of(r.host, r.port, r.last_seen, e)) return false;
            return !asker_public || addr_routable(e);
        });
        std::vector<AddrEntry> v;
        for (const auto& r : sample) { AddrEntry e; if (addr_entry_of(r.host, r.port, r.last_seen, e)) v.push_back(e); }
        if (m_net.send_to(p, encode_addr(m_o.chain, v))) m_st.addr_tx++;
    }
    void on_addr(PeerId p, const std::vector<u8>& f) {
        u32 chain = 0; std::vector<AddrEntry> v;
        if (!decode_addr(f, chain, v)) { m_st.malformed++; return; }
        if (chain != m_o.chain) { m_st.wrong_chain++; return; }
        std::string src_ip; std::size_t budget = 0;
        {
            std::lock_guard<std::mutex> lk(m_pmtx);
            auto it = m_peers.find(p);
            if (it == m_peers.end()) return;
            PeerSt& s = it->second;
            if (!s.addr_pending) { m_st.addr_unsolicited++; return; }   // an ADDR we did not ask for: ignored
            s.addr_pending = false;
            src_ip = s.out_host.empty() ? s.remote_ip : s.out_host;
            budget = s.addr_learned >= m_o.addr_learn_per_peer ? 0 : m_o.addr_learn_per_peer - s.addr_learned;
        }
        m_st.addr_rx++;
        const bool src_public = is_public_host(src_ip);
        const std::size_t take = std::min({v.size(), m_o.addr_learn_per_answer, budget});
        const u64 now = wall_s();
        std::size_t learned = 0;
        for (std::size_t i = 0; i < take; ++i) {
            const AddrEntry& e = v[i];
            if (!dialable_v4(e) || (src_public && !addr_routable(e))) { m_st.addr_ignored++; continue; }
            if (m_book.is_self(addr_host(e), e.port)) { m_st.self_skipped++; continue; }   // NODE-NONCE: our own address
            if (m_book.learn(addr_host(e), e.port, e.last_seen, now)) ++learned;
        }
        m_st.addr_ignored += v.size() - take;
        m_st.addr_learned += learned;
        std::lock_guard<std::mutex> lk(m_pmtx);
        auto it = m_peers.find(p);
        if (it != m_peers.end()) it->second.addr_learned += take;
    }
    // Maintenance thread, ~1 s: retire used learned targets, dial new
    // candidates up to max_outbound, re-ask addresses while below it, refresh
    // the connected good peers, expire stale entries, persist a dirty book.
    void disc_tick() {
        const auto nowc = Clock::now();
        if (nowc - m_disc_tick < std::chrono::seconds(1)) return;
        m_disc_tick = nowc;
        const u64 now = wall_s();
        {
            std::lock_guard<std::mutex> lk(m_tmtx);
            m_targets.erase(std::remove_if(m_targets.begin(), m_targets.end(),
                                           [](const Target& t) { return t.learned && t.used && !t.pid; }), m_targets.end());
        }
        std::size_t out = 0;
        std::vector<std::pair<PeerId, std::pair<std::string, u16>>> outs;
        std::vector<PeerId> reask;
        {
            std::lock_guard<std::mutex> lk(m_pmtx);
            for (const auto& [p, s] : m_peers) {
                if (s.hello_ok && s.out_host.empty() && !s.remote_ip.empty() && s.remote.listen_port)
                    outs.push_back({p, {s.remote_ip, s.remote.listen_port}});
                if (s.out_host.empty()) continue;
                ++out;
                if (s.hello_ok) outs.push_back({p, {s.out_host, s.out_port}});
            }
            for (const auto& [p, s] : m_peers)
                if (s.hello_ok && nowc - s.getaddr_tx >= std::chrono::milliseconds(m_o.addr_reask_ms)) reask.push_back(p);
        }
        std::set<std::string> skip = linked_keys();
        for (const auto& k : linked_node_keys()) skip.insert(k);   // NODE-NONCE: aliases of linked nodes
        {
            std::lock_guard<std::mutex> lk(m_tmtx);
            for (const auto& t : m_targets) {
                skip.insert(peer_key(t.host, t.port));
                if (t.learned && !t.used) ++out;   // queued dials count toward the target
            }
        }
        if (m_dialing.load() && !m_partitioned.load() && out < m_o.max_outbound && m_net.n_peers() < m_o.max_peers) {
            const auto c = m_book.dial_candidates(m_o.max_outbound - out, now, skip);
            std::lock_guard<std::mutex> lk(m_tmtx);
            for (const auto& r : c) {
                Target t{r.host, r.port, 0, Clock::now(), 1};
                t.learned = true;
                m_targets.push_back(t);
                m_st.disc_dialed++;
            }
        }
        if (out < m_o.max_outbound) for (PeerId p : reask) send_getaddr(p);
        if (nowc - m_disc_slow >= std::chrono::seconds(60)) {
            m_disc_slow = nowc;
            for (const auto& [p, a] : outs) { (void)p; m_book.mark_good(a.first, a.second, now); }   // connected: last_seen fresh
            m_st.disc_expired += m_book.expire(now);
        }
        if (nowc - m_disc_saved >= std::chrono::milliseconds(m_o.book_save_ms)) { m_disc_saved = nowc; save_book(false); }
    }
    // ── maintenance: dial/redial, HELLO timeouts, fetch timeouts, drops ──────
    void maint_loop() {
        m_maint_tid.store(std::this_thread::get_id());   // RELAY-DISCOVERY: marks our own dials in on_peer_up
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
                // RELAY-DISCOVERY: an address already linked (e.g. the peer dialed US) is not dialed again
                const std::set<std::string> linked = m_o.discovery ? linked_keys() : std::set<std::string>{};
                // NODE-NONCE: an address whose node (by HELLO nonce) is linked under ANOTHER address
                const std::set<std::string> aliased = m_o.discovery ? linked_node_keys() : std::set<std::string>{};
                {
                    std::lock_guard<std::mutex> lk(m_tmtx);
                    for (std::size_t i = 0; i < m_targets.size(); ++i) {
                        auto& t = m_targets[i];
                        if (t.pid && std::find(live.begin(), live.end(), t.pid) == live.end()) t.pid = 0;
                        if (t.self) continue;   // NODE-NONCE: this node itself, never dialed again
                        if (!t.pid && Clock::now() >= t.next_try) {
                            if (linked.count(peer_key(t.host, t.port)) || aliased.count(peer_key(t.host, t.port))) { t.next_try = Clock::now() + std::chrono::seconds(5); if (t.learned) t.used = true; continue; }
                            due.push_back(i);
                        }
                    }
                }
                for (std::size_t i : due) {
                    std::string host; u16 port = 0;
                    {
                        std::lock_guard<std::mutex> lk(m_tmtx);
                        host = m_targets[i].host; port = m_targets[i].port;
                    }
                    m_st.dials++;
                    m_dial_host = host; m_dial_port = port;   // RELAY-DISCOVERY (maintenance thread only)
                    const PeerId pid = m_net.add_peer_id(host, port);
                    m_dial_host.clear(); m_dial_port = 0;
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
                            if (m_o.discovery && !hello_now) m_book.mark_failed(host, port, wall_s());   // RELAY-DISCOVERY
                        }
                        if (t.learned) t.used = true;
                    } else {
                        m_st.dial_fail++;
                        if (m_o.discovery) m_book.mark_failed(t.host, t.port, wall_s());   // RELAY-DISCOVERY
                        if (t.learned) t.used = true;
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
            if (m_o.drops_floor_diff) drops_maint();   // ★ RAIN-BACKFILL
            drive_ctx();
            drive_liveness();   // RELAY-LIVENESS
            pump_won_offers();  // RELAY-SEND-QUEUE: page the won re-offer into each peer's queue
            if (m_o.discovery) disc_tick();   // RELAY-DISCOVERY
        }
    }

    // ── members ─────────────────────────────────────────────────────────────
    RelayOptions m_o;
    ChainView&   m_chain;
    RxFn         m_rx;
    VerdictFn    m_verdict;   // SHARE-LEVEL CANONICAL COINBASE
    LaneTipFn    m_tip;
    LogFn        m_log;
    u64          m_nonce = 0;
    std::set<std::string> m_self_keys;   // NODE-NONCE: our relay addresses (set in start())
    std::map<std::string, u64> m_addr_nonce;   // NODE-NONCE: relay address -> node nonce (under m_pmtx)
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
    std::deque<Item> m_ahead;                   // HOLD-ROUND-2 (B): AHEAD shares, re-judged on a share-state advance
    std::map<u64, std::size_t> m_ahead_n;       // ... per sending NODE (inv_node; bounded: share_ahead_per_peer) -- V4
    double m_solicited = 0;
    Clock::time_point m_solicited_at = Clock::now();
    std::string m_last_reject;
    std::string m_last_unresolved;
    std::string m_last_share_refused;

    mutable std::mutex m_cmtx;         // receipt-context wants + serve requests
    std::map<bytes32, CtxWant> m_ctx_want;
    std::deque<std::pair<PeerId, std::vector<bytes32>>> m_ctx_serve;

    std::mutex m_amtx;               // admitted queue
    std::vector<Admitted> m_admitted;
    std::vector<Admitted> m_drops;   // ★ DROPS: admitted raindrops (m_amtx)
    std::unordered_set<bytes32, Bytes32Hash> m_drop_seen;   // ★ DROPS dedup (m_mtx)
    mutable std::mutex m_drmtx;                                       // HOLD-ROUND-2 (C2): leaf lock
    std::unordered_set<bytes32, Bytes32Hash> m_drop_refused;         // fetched, not admissible here (bounded FIFO)
    std::deque<bytes32> m_drop_refused_order;
    std::deque<bytes32> m_drop_order;
    // ★ RAIN-BACKFILL (m_dsmtx; gate ON only)
    mutable std::mutex m_dsmtx;
    std::map<u64, std::map<bytes32, std::vector<u8>>> m_drop_store;        // bin -> id -> raw (servable)
    std::unordered_map<bytes32, u64, Bytes32Hash> m_drop_store_id;          // id -> bin
    std::unordered_map<bytes32, bytes32, Bytes32Hash> m_drop_pow;           // ★ DROPS-HARDEN: id -> verified RandomX hash
    // ★ DROPS-RETAIN: bytes held, the servable floor (L1), the pinned sets (L2b:
    // key -> ids, id -> number of keys), the segment work since the last persist
    u64 m_drop_store_bytes = 0;
    u64 m_drop_floor = 0;
    bool m_drop_floor_set = false;
    std::map<std::string, std::vector<bytes32>> m_drop_pins;
    std::unordered_map<bytes32, u32, Bytes32Hash> m_drop_retained;
    std::map<u64, std::vector<bytes32>> m_seg_append;   // bin -> ids to append to <bin>.seg
    std::set<u64> m_seg_rewrite, m_seg_unlink;          // bins to rewrite whole / to unlink
    u64 m_overflow_logged = 0;                          // ★ DROPS-RETAIN (maint thread only)
    Clock::time_point m_overflow_log_at{};
    std::atomic<bool> m_legacy_migrate{false};          // a legacy lane<N>.drops was loaded: renamed once segments exist
    bool m_drop_dirty = false;                                               // ★ DROPS-HARDEN: store changed since the last snapshot
    Clock::time_point m_drop_persisted_at{};
    std::map<InvKey, PeerInv> m_drop_inv;
    std::unordered_map<bytes32, Clock::time_point, Bytes32Hash> m_drop_want; // fetched ids in flight (solicited)
    std::unordered_map<bytes32, std::pair<Clock::time_point, u32>, Bytes32Hash> m_pin_asked;   // ★ DROPS-SET-PIN: id -> (last ask, asks)
    std::atomic<bool> m_drop_had_peer{false};

    mutable std::mutex m_pmtx;         // peers
    std::map<PeerId, PeerSt> m_peers;
    std::set<PeerId> m_up_done;        // UP-GATE: links whose up event has been handled (m_pmtx)
    std::condition_variable m_up_cv;   // UP-GATE: signalled by open_up_gate
    std::atomic<u32> m_test_up_delay_ms{0};
    Clock::time_point m_live_tick = Clock::now();   // RELAY-LIVENESS (maintenance thread only)
    std::atomic<u64> m_ping_nonce{0};               // RELAY-LIVENESS (bumped by maintenance only; read by the won re-offer)

    std::mutex m_tmtx;                 // dial targets + deferred drops
    std::vector<Target> m_targets;
    std::vector<PeerId> m_to_drop;
    std::atomic<bool> m_dialing{true};
    std::atomic<bool> m_partitioned{false};
    std::atomic<Clock::rep> m_partition_until{0};

    std::mutex m_jmtx;                 // supply jobs
    std::map<PeerId, std::deque<Job>> m_jobs;
    std::map<PeerId, Job> m_cur_job;
    std::map<PeerId, u32> m_rpage;     // REPAIR-PAGE: the repair order page size per peer (m_jmtx)

    mutable std::mutex m_rmtx;         // repairs
    std::map<std::pair<u64, bytes32>, Repair> m_repairs;

    mutable std::mutex m_bmtx;         // block-won
    std::set<bytes32> m_seen_bids;
    std::map<bytes32, PeerId> m_bid_peer;
    std::vector<std::pair<BlockWon, PeerId>> m_won;
    std::deque<std::vector<u8>> m_won_raw;   // ENROL-REPL: recent FB_BLOCK_WON frames (DROPS only)
    static constexpr std::size_t kWonServeMax = 1024;
    std::map<bytes32, std::vector<u8>> m_won_by_bid;   // ★ DROPS-RESTART: carried frames servable by bid (DROPS only)
    std::deque<bytes32> m_won_serve_order;
    // RELAY-SEND-QUEUE (guarded by m_bmtx): per-link paged won re-offer, and the
    // bids each remote NODE (HELLO node_nonce) provably holds.
    struct WonOffer { std::deque<bytes32> todo; std::vector<std::pair<u64, bytes32>> unconfirmed; };
    std::map<PeerId, WonOffer> m_won_offer;
    std::map<u64, std::set<bytes32>> m_won_held;
    std::set<bytes32> m_won_wanted;                    // ★ DROPS-RESTART: bids asked for with FB_GETWON

    mutable std::mutex m_dmtx;         // pos -> lane digest (the spine probe)
    std::map<u64, bytes32> m_pos_digest;
    std::multimap<u64, bytes32> m_alt_digest;   // REPAIR-HORIZON: the shadows' digests (note_alt_digests)

    ::c2pool::v37n::FrameVault m_vault;
    mutable DurableLaneOrder m_dorder;   // REPAIR-CHAIN (F2-S); declared after m_vault, destroyed before it
    // ★ HOLD-ROUND-3 F3b: the whole-order serve budget + once-per-(peer, P) retention alarms
    mutable DeepServeBudget m_deep_budget;
    mutable std::mutex m_deep_log_mtx;
    std::set<std::pair<PeerId, u64>> m_deep_retention_logged;
    static inline thread_local PeerId t_serving_peer = 0;
    static inline thread_local int t_verify_worker = -1;   // DROPS-VERIFY-SCALE

    // RELAY-DISCOVERY
    PeerBook m_book;                   // own lock
    std::atomic<std::thread::id> m_maint_tid{};   // the dialing thread (set once by maint_loop)
    std::string m_dial_host;           // the address being dialed (maintenance thread only)
    u16 m_dial_port = 0;
    Clock::time_point m_disc_tick{}, m_disc_slow = Clock::now(), m_disc_saved = Clock::now();   // maintenance thread only

    std::atomic<bool> m_running{false};
    std::vector<std::thread> m_verify_threads;   // DROPS-VERIFY-SCALE: verify_threads workers
    std::thread m_maint_thread;
};

} // namespace c2pool::v37n::xmr::relay
