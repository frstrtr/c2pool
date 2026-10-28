// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// src/c2pool/v37/xmr/pathb/pathb_relay_node.hpp
// PathbRelayNode: the Path B relay node of one PathbNode over a link layer
// (RelayLinks; the shared carrier transport is pathb_relay_links.hpp).
//
//   dispatch     FB_HELLO 0x40 (ours on link up and in reply; nothing but
//                HELLO before a HELLO is accepted; a HELLO the node refuses
//                or closes: the link closed, no strike), FB_RECEIPTS 0x41,
//                FC_CARRIER 0x50, FC_GETCARRIER 0x51 / FC_GETHEADERS 0x52 /
//                FC_GETBUCKETS 0x54 (the reply frames sent), FC_HEADERS 0x53,
//                FC_BUCKETS 0x55; kept: FB_GETCTX / FB_CTX 0x43 / 0x44,
//                FB_PING / FB_PONG 0x48 / 0x49, FB_GETADDR / FB_ADDR
//                0x4c / 0x4d; every other opcode is counted as unknown and the
//                link kept (0x4a / 0x4b are not used here)
//   tokens       STRIKE: one token of the sender's invalid-object budget (the
//                CarrierDosBudget of its source: its bucket and the global
//                one); BAN: the source address banned for ban_seconds (a
//                source with no address: the link dropped); DROP, DEFER and
//                the HELLO outcomes: no token
//   threading    one node lock serializes every PathbNode call. The owner
//                thread runs the posted events (HELLO, family C requests and
//                replies, complete_carrier, apply_join). The verify workers
//                take the sender's token, then run begin_carrier and the
//                FB_RECEIPTS admission under the node lock (no token: the
//                parked list, retried; never a penalty). The join worker runs
//                attempt_join holding the node lock and releases it at every
//                wait (FC_* replies, wait_until, FB_GETCTX), around each
//                RandomX hash of the attempt and between its replay steps, so
//                the attempt's reads of the adopted state run under the lock
//   joiner       JoinTransport over the links: the reply frames of a request
//                reach its ticket (FC_HEADERS in request order, FC_CARRIER by
//                the asked ids, FC_BUCKETS by (peer, at)); a ticket of a
//                disconnected peer gets no frame
//   after HELLO  headers first from the best tip when the peer's HELLO tip is
//                not held (the node's own header work at the reply fetches or
//                keeps; best_cum_work is not read), again while it is not held
//                and no reply ended it; the pending set re-offered (FB_RECEIPTS,
//                at most 1 + R_MAX bodies a frame); a store (not joined, not
//                load-failed) whose catch-up got a reply with no header to a
//                request from position 0 offers the peer's HELLO tip to the
//                joiner
//   buckets      a DEFER naming a missing bucket: FC_GETBUCKETS at the named
//                carrier, one peer at a time (one assembly per (peer, at)); the
//                parked frames run again when a bin arrives, when a request
//                ends unserved, refused or abandoned, and when the best tip
//                moves after every peer was closed for the named carrier
//   transport    liveness (FB_PING / FB_PONG, LINK SILENT), discovery and the
//                peer book, the node nonce (self-connection, one link per node
//                pair), address bans, inbound and outbound links counted apart,
//                the async send queue, the verify pool, the parked cap,
//                partition_for, the dial targets and the seeds
//
// Every clock read goes through RelayClock. Header-only.
// ---------------------------------------------------------------------------
#pragma once

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstdio>
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
#include <tuple>
#include <utility>
#include <vector>

#include "c2pool/v37/net_addr_ban.hpp"                  // is_addr_key
#include "c2pool/v37/xmr/relay/xmr_relay_native_ctx.hpp"  // verify_block_ctx, judge_block_ctx
#include "c2pool/v37/xmr/relay/xmr_relay_peerbook.hpp"  // PeerBook, dup_link_rule
#include "c2pool/v37/xmr/relay/xmr_relay_wire.hpp"      // FB_GETCTX / FB_CTX, FB_PING / FB_PONG, FB_GETADDR / FB_ADDR
#include "impl/xmr/wire/xmr_carrier_dos_budget.hpp"     // CarrierDosBudget

#include "c2pool/v37/xmr/pathb/pathb_join_link.hpp"
#include "c2pool/v37/xmr/pathb/pathb_node.hpp"

namespace c2pool::xmr::pathb {

namespace rly = ::c2pool::v37n::xmr::relay;

// ---------------------------------------------------------------------------
// The relay's clock: the transport timers only (keepalive, silence, HELLO
// timeout, bans, the parked retry, the join waits, the peer book's times).
// ---------------------------------------------------------------------------
struct RelayClock {
    std::function<std::uint64_t()> mono_ms;  // monotonic, milliseconds
    std::function<std::uint64_t()> wall_s;   // unix seconds (the peer book)
    static RelayClock system() {
        RelayClock c;
        c.mono_ms = [] {
            return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
                                                      std::chrono::steady_clock::now().time_since_epoch())
                                                      .count());
        };
        c.wall_s = [] {
            return static_cast<std::uint64_t>(
                    std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch())
                            .count());
        };
        return c;
    }
};

// P-40 (policy, ruling 23): the peers whose HELLO tails name the candidates before a join (two independent best-tip
// claims); flag --join-min-peers.
inline constexpr std::size_t kJoinMinPeersDefault = 2;

// ---------------------------------------------------------------------------
// Options (the generic transport values of the old relay node, kept)
// ---------------------------------------------------------------------------
// The class of a Monero context want: an unsolicited receipt's (P-06), a relayed carrier's (P-07) or a join
// attempt's (P-07); each class has its own cap (PathbRelayOptions).
enum class CtxClass : std::uint8_t { Receipt = 0, Carrier = 1, Join = 2 };

struct PathbRelayOptions {
    // links
    bool listen = false;
    std::string listen_host = "127.0.0.1";
    std::uint16_t listen_port = 0;                               // 0: an ephemeral port, read back by listen_port()
    std::vector<std::pair<std::string, std::uint16_t>> peers;    // permanent dial targets
    std::vector<std::pair<std::string, std::uint16_t>> seeds;    // discovery candidates (the caller's bootstrap list)
    std::size_t max_inbound = 101;                               // accepted links
    std::size_t max_inbound_per_addr = 1;
    std::size_t max_outbound = 12;                               // dialed links kept up
    std::size_t send_queue_bytes = 16u << 20;                    // per link (at least two FC_HEADERS frames + prefixes, P-14)
    std::uint32_t connect_timeout_ms = 3000;                     // discovery dials
    std::uint32_t hello_timeout_ms = 10000;
    // the invalid-object budget and the ban (unset: relay_budget_default at verify_threads and max_inbound +
    // max_outbound links)
    std::optional<::c2pool::xmr::DosPolicy> dos;
    std::optional<std::uint32_t> ban_seconds;
    // the frames that answer this node's own FC_GETCARRIER: verified under a credit of their own (P-21)
    std::uint32_t solicited_credits = 256;
    // P-15, the per-peer valid-object budget (unset: rate (1 + R_MAX) / T objects/s, capacity P-09 of the node)
    std::optional<double> peer_valid_rate;
    std::optional<double> peer_valid_capacity;
    // P-50, the claim-leaf alarm budget per peer (unset: (1 + R_MAX) / T alarms/s, burst 1 + R_MAX)
    std::optional<std::uint64_t> claim_alarm_rate_milli;  // P-50 refill, milli-alarms per second
    // P-40: the HELLO tails (connected peers past HELLO) a join attempt waits for
    std::size_t join_min_peers = kJoinMinPeersDefault;
    // the verify pool
    std::size_t verify_threads = 1;
    std::size_t verify_queue_max = 4096;
    std::size_t parked_max = kRuledLaneParams.open_bins * (1 + kRuledLaneParams.r_max);  // --relay-parked-max
    // liveness (0: no PING sent or answered, no silence timeout)
    std::uint32_t keepalive_ms = 5000;
    std::uint32_t silence_timeout_ms = 25000;
    // discovery
    bool discovery = false;
    std::vector<std::string> self_hosts;
    std::vector<rly::PeerRecord> book_load;
    std::function<void(const std::vector<rly::PeerRecord>&)> book_save;
    rly::PeerBook::Limits book_limits{};
    std::uint32_t book_save_ms = 15000;
    std::uint32_t addr_reask_ms = 20000;
    std::uint32_t addr_answer_min_ms = 5000;
    std::uint16_t addr_want = 64;
    std::size_t addr_answer_max = 64;
    std::size_t addr_learn_per_answer = 64;
    std::size_t addr_learn_per_peer = 256;
    // Monero contexts (FB_GETCTX / FB_CTX)
    std::uint32_t ctx_retry_ms = 2000;
    std::uint32_t ctx_max_rounds = 30;
    // context blocks climbed per want: P-06 (Fresh + 1) for an unsolicited receipt, P-07 (k_alt) for a carrier
    // under verification (a relayed carrier's admission, a join's FB_GETCTX). Three classes of wants, each with its
    // own cap: unsolicited receipts ctx_want_max, relayed carriers ctx_join_depth, join attempts ctx_join_depth.
    std::uint32_t ctx_max_depth = static_cast<std::uint32_t>(relay_horizons(kRuledLaneParams).ctx_max_depth);
    std::uint32_t ctx_join_depth = static_cast<std::uint32_t>(kAltDepth);
    std::size_t ctx_want_max = 128;  // wants of unsolicited receipts held at once
    // P-13 (--relay-ctx-block-cap, raise only): a context block's cap above blob_cap_ctx(hf, Z); 0: blob_cap_ctx alone.
    // The cap is max(this, blob_cap_ctx(hf, Z) of the block's newest known ancestor) when its work is judged; FB_CTX
    // frames are read and served up to max(this, blob_cap_ctx at the node's view).
    std::uint64_t ctx_block_cap = 0;
    // false: no thread; the caller runs pump(), tick() and join_step()
    bool threads = true;
};

// The invalid-object budget at its Appendix P defaults: P-16 refill G = (1 + R_MAX) / (2 T) tokens/s (before the
// first upgrade epoch), P-17 per-address burst C = N verify workers, P-18 global burst G_b = n x C over n links
// (P-23 + P-24), P-19 ban B = ceil(G_b / G) s; the per-address refill G / n.
struct RelayBudget {
    ::c2pool::xmr::DosPolicy dos;
    std::uint32_t ban_seconds = 0;
};
inline RelayBudget relay_budget_default(std::size_t verify_workers, std::size_t links, const LaneParams& p = kRuledLaneParams) {
    const std::uint64_t num = 1 + p.r_max;  // G = num / den tokens/s
    const std::uint64_t den = 2 * p.carrier_interval_s;
    const std::uint64_t n = std::max<std::size_t>(links, 1);
    const std::uint64_t c = std::max<std::size_t>(verify_workers, 1);
    const double g = static_cast<double>(num) / static_cast<double>(den);
    RelayBudget b;
    b.dos.per_peer_capacity = static_cast<double>(c);
    b.dos.per_peer_refill = g / static_cast<double>(n);
    b.dos.global_capacity = static_cast<double>(n * c);
    b.dos.global_refill = g;
    b.ban_seconds = static_cast<std::uint32_t>((n * c * den + num - 1) / num);
    return b;
}
// P-21: the solicited credit's refill.
inline constexpr std::uint32_t kSolicitedRefillPerS = 8;

struct PathbRelayStats {
    std::atomic<std::uint64_t> hello_sent{0}, hello_ok{0}, hello_rejected{0}, hello_closed{0}, hello_timeout{0};
    std::atomic<std::uint64_t> hello_tag_mismatch{0}, hello_rules_mismatch{0}, hello_old_version{0};
    std::atomic<std::uint64_t> pre_hello_dropped{0}, unknown_opcodes{0}, malformed{0}, wrong_chain{0};
    std::atomic<std::uint64_t> strikes{0}, bans{0}, drops{0}, addr_bans{0}, banned_src_dropped{0};
    std::atomic<std::uint64_t> queue_dropped{0}, rx_deferred{0}, verify_threads{0};
    std::atomic<std::uint64_t> flood_frames{0}, reoffer_frames{0}, catchup_requests{0}, empty_store_offers{0};
    std::atomic<std::uint64_t> bucket_requests{0}, parked_reruns{0}, rewalks{0}, solicited_jobs{0};
    std::atomic<std::uint64_t> owner_queue_hwm{0}, owner_waits{0};  // the owner's event queue: high-water mark; reader waits
    std::atomic<std::uint64_t> stale_events{0}, reoffer_paused{0}, p15_drops{0}, p15_counted{0}, rx_failures{0};
    std::atomic<std::uint64_t> tip_header_requests{0}, body_set_requests{0}, body_sets{0}, walk_placed{0};
    std::atomic<std::uint64_t> headers_ctx_deferred{0}, headers_ctx_reasks{0};  // header replies deferred on a P_r; asked again
    // replies to header requests retired at P-53, DROPped; header requests merged with an equal one in flight or waiting
    std::atomic<std::uint64_t> headers_retired_dropped{0}, header_wants_merged{0};
    // tip-header requests waiting or deferred that left at their peer's bound (P-47): their objects gone; the oldest
    std::atomic<std::uint64_t> header_wants_reclaimed{0}, header_wants_dropped{0};
    std::atomic<std::uint64_t> join_tickets{0}, join_attempts{0}, join_strikes{0}, join_waits{0};
    // join attempts that took a side branch's state from the server (a span on a side branch forking at a prefix node
    // below the root); of them: completed, not served
    std::atomic<std::uint64_t> join_side_attempts{0}, join_side_completed{0}, join_side_not_served{0};
    std::atomic<std::uint64_t> claim_alarms{0}, claim_alarm_drops{0};  // P-50: relayed frames' claim-leaf alarms; drops
    std::atomic<std::uint64_t> reoffer_done{0}, reoffer_last_ms{0}, reoffer_max_ms{0};  // re-offers finished; their time
    std::atomic<std::uint64_t> repend_offers{0}, repend_offered{0};  // switches whose re-pended receipts were relayed; receipts
    std::atomic<std::uint64_t> parked_receipts_sealed{0};  // parked receipts dropped (no strike) as their origin bin sealed
    std::atomic<std::uint64_t> parked_frames_sealed{0};    // parked carrier frames dropped (no strike) at their own bin's seal
    std::atomic<std::uint64_t> ctx_held{0};  // Monero-input DEFERs on a block the follower holds: no context asked
    // the catch-up's locator steps; a store not caught up: its peers' tips offered to the joiner after a catch-up step
    // stayed deferred on a P_r past kCtxTtlMs; join pairs released (their P_r resolved, a new peer, a want re-made);
    // when it caught up (ms; 0: not since start)
    std::atomic<std::uint64_t> catchup_steps{0}, catchup_join_offers{0}, join_releases{0}, caught_up_at_ms{0};
    std::atomic<std::uint64_t> receipts_parked{0}, parked_receipt_drops{0};  // DEFERred receipts parked; dropped over P-09
    // links dropped for a full send queue at a relay send: while the peer's re-offer pages; otherwise (live traffic)
    std::atomic<std::uint64_t> reoffer_queue_full{0}, live_queue_full{0};
    std::atomic<std::uint64_t> reoffer_cap_drops{0};  // re-offer ids dropped over a peer queue's cap (P-09), the oldest
    std::atomic<std::uint64_t> ping_tx{0}, ping_rx{0}, pong_tx{0}, pong_rx{0}, silent_drops{0}, ka_legacy{0}, ka_rearm{0};
    std::atomic<std::uint64_t> ctx_wanted{0}, ctx_asked{0}, ctx_rx{0}, ctx_resolved{0}, ctx_bad{0}, ctx_unknown_rx{0};
    std::atomic<std::uint64_t> ctx_over_cap{0};  // context blocks over P-13, dropped before hashing
    std::atomic<std::uint64_t> parked_index_pruned{0};  // prunes of the park index (frames that left the deferred store)
    std::atomic<std::uint64_t> ctx_gave_up{0}, ctx_served{0}, ctx_unknown_tx{0}, ctx_forged{0}, ctx_deferred{0}, ctx_unchecked{0};
    std::atomic<std::uint64_t> getaddr_tx{0}, getaddr_rx{0}, getaddr_throttled{0}, addr_tx{0}, addr_rx{0}, addr_unsolicited{0};
    std::atomic<std::uint64_t> addr_learned{0}, addr_ignored{0}, disc_dialed{0}, disc_dial_ok{0}, disc_dup_dropped{0};
    std::atomic<std::uint64_t> disc_bad{0}, disc_self{0}, disc_saves{0}, disc_expired{0};
    std::atomic<std::uint64_t> self_conn{0}, self_skipped{0}, dup_deferred{0};
    std::atomic<std::uint64_t> dials{0}, dial_fail{0}, over_cap{0};
};

// ---------------------------------------------------------------------------
// The link layer the relay node runs on (pathb_relay_links.hpp binds it to
// the shared carrier transport; a KAT binds a fake).
// ---------------------------------------------------------------------------
class RelayLinks {
public:
    using FrameFn = std::function<void(std::uint64_t peer, const std::vector<std::uint8_t>& frame)>;
    using EventFn = std::function<void(std::uint64_t peer, bool up)>;
    virtual ~RelayLinks() = default;
    // frame: a frame with frame[0] < 0x80; control: frame[0] >= 0x80; event: a link up / down
    virtual void bind(FrameFn frame, FrameFn control, EventFn event) = 0;
    virtual void configure(const PathbRelayOptions& o) = 0;
    virtual bool listen(const std::string& host, std::uint16_t port) = 0;
    virtual std::uint16_t listen_port() const = 0;
    virtual std::uint64_t dial(const std::string& host, std::uint16_t port) = 0;  // the new link; 0: failed
    virtual bool send_to(std::uint64_t peer, const std::vector<std::uint8_t>& frame) = 0;
    virtual void disconnect(std::uint64_t peer) = 0;
    virtual void ban_key(std::uint64_t key, std::uint32_t seconds) = 0;  // every link from key dropped
    virtual bool is_banned_key(std::uint64_t key) = 0;
    virtual std::uint64_t addr_key(std::uint64_t peer) const = 0;  // 0: none (127.0.0.1, ::1, gone)
    virtual bool is_inbound(std::uint64_t peer) const = 0;
    virtual bool has_peer(std::uint64_t peer) const = 0;
    virtual std::vector<std::uint64_t> peer_ids() const = 0;
    virtual std::size_t conns_from(std::uint64_t key) const = 0;
    virtual std::string remote_ip(std::uint64_t peer) const = 0;
    virtual std::size_t n_peers() const = 0;
    virtual void stop() = 0;
    // the bytes queued on a link and the per-link bound (0: not known)
    virtual std::size_t queued_bytes(std::uint64_t) const { return 0; }
    virtual std::size_t send_queue_limit() const { return 0; }
    // the links the transport dropped because a send would have passed the bound (cumulative)
    virtual std::uint64_t queue_full_drops() const { return 0; }
};

// The node's Monero contexts for FB_GETCTX / FB_CTX (the caller binds them to
// its native node and its follower).
struct PathbCtxSource {
    // a block body the node holds (served for FB_GETCTX; tried first for its own wants)
    std::function<bool(const Hash32& id, std::vector<std::uint8_t>& blob)> block_blob;
    // the node's own verified chain index (the work behind a served block)
    rly::CtxChainSource chain;
    // RandomX of a served block's hashing blob
    rly::CtxHashFn rx;
    // a served block judged usable: into the follower
    std::function<void(const rly::BlockCtx& b, const std::vector<std::uint8_t>& blob)> accept;
    // P-13 at the node's view (its index tip): blob_cap_ctx(hf, Z) of a child of the tip; unset or 0: hf 16, Z = zone(16)
    std::function<std::uint64_t()> view_cap;
};

// ---------------------------------------------------------------------------
// The node lock: FIFO order, so a waiting owner event runs as soon as the
// join worker or a verify worker lets the lock go.
// ---------------------------------------------------------------------------
class RelayNodeLock {
public:
    void lock() {
        std::unique_lock<std::mutex> l(m_);
        const std::uint64_t t = next_++;
        cv_.wait(l, [&] { return serving_ == t; });
    }
    void unlock() {
        {
            std::lock_guard<std::mutex> l(m_);
            ++serving_;
        }
        cv_.notify_all();
    }

private:
    std::mutex m_;
    std::condition_variable cv_;
    std::uint64_t next_ = 0;
    std::uint64_t serving_ = 0;
};

// ---------------------------------------------------------------------------
// PathbRelayNode
// ---------------------------------------------------------------------------
class PathbRelayNode {
public:
    using LogFn = std::function<void(const std::string&)>;
    static constexpr std::size_t kMaxVerifyThreads = 16;

    PathbRelayNode(PathbRelayOptions o, RelayLinks& links, RelayClock clock = RelayClock::system(), LogFn log = {})
        : o_(std::move(o)), links_(links), clock_(std::move(clock)), log_(std::move(log)), budget_(budget_of(o_)),
          dos_(budget_.dos), port_(*this) {
        solicited_ = static_cast<double>(o_.solicited_credits);
        std::random_device rd;
        do {
            nonce_ = ((static_cast<std::uint64_t>(rd()) << 32) | rd()) ^ clock_.mono_ms();
        } while (nonce_ == 0);
    }
    ~PathbRelayNode() { stop(); }
    PathbRelayNode(const PathbRelayNode&) = delete;
    PathbRelayNode& operator=(const PathbRelayNode&) = delete;

    // ---- binding ----
    // The node's I/O: send, flood and fetch_context go through this relay; the
    // join worker's RandomX runs with the node lock released.
    PathbNodeIo bind_io(PathbNodeIo io) {
        PathbNodeIo out = std::move(io);
        out.send = [this](std::uint64_t peer, const std::vector<std::uint8_t>& f) { node_send(peer, f); };
        out.flood = [this](const std::vector<std::uint8_t>& f, std::optional<std::uint64_t> except) { node_flood(f, except); };
        out.fetch_context = [this](const Hash32& id, std::uint64_t timeout_s) { return fetch_context(id, timeout_s); };
        auto rx = std::move(out.verify);
        out.verify = [this, rx = std::move(rx)](const HashingBlob& b, std::uint64_t d, const Hash32& seed) {
            if (!rx) return false;
            const JoinRelease r(*this);
            const bool ok = rx(b, d, seed);
            rx_ok_++;  // a hash computed (the RandomX alarm's recovery)
            return ok;
        };
        return out;
    }
    // The node this relay serves, built with bind_io's I/O. Before start().
    void attach(PathbNode& n) {
        node_ = &n;
        n.set_join_transport(&port_);
        n.set_join_step([this] { const JoinRelease r(*this); });
        const PathbNodeConfig& c = n.config();
        chain_id_ = c.identity.chain_id;
        p_ = c.p;
        buffers_ = c.buffers;
        headers_frame_ = n.frame_bytes_headers();
        bucket_frame_ = c.bucket_policy.frame_bytes;
        abandon_s_ = c.abandon_timeout_s;
        header_max_ = static_cast<std::uint16_t>(std::clamp<std::uint64_t>(c.journal_depth, 1, UINT16_MAX));
        valid_rate_ = o_.peer_valid_rate.value_or(static_cast<double>(1 + p_.r_max) / static_cast<double>(p_.carrier_interval_s));
        valid_cap_ = o_.peer_valid_capacity.value_or(
                static_cast<double>(c.pending_cap != 0 ? c.pending_cap : relay_horizons(c.p).pending_cap));
        claim_budget_ = ClaimAlarmBudget(p_, o_.claim_alarm_rate_milli.value_or(0));
    }
    // The context source; its RandomX call leaves every exception as RandomxFailure (node-internal).
    void set_ctx_source(PathbCtxSource s) {
        if (s.rx)
            s.rx = [this, rx = std::move(s.rx)](const std::vector<std::uint8_t>& blob, const Hash32& seed, Hash32& pow) {
                bool ok = false;
                try {
                    ok = rx(blob, seed, pow);
                } catch (const RandomxFailure&) {
                    throw;
                } catch (const std::exception& e) {
                    throw RandomxFailure(e.what());
                } catch (...) {
                    throw RandomxFailure("RandomX: unknown failure");
                }
                rx_ok_++;
                return ok;
            };
        ctx_ = std::move(s);
    }
    // Manual mode: called while a ticket or a wait has nothing to read (deliver one message; false: nothing moved).
    void set_drive(std::function<bool()> f) { drive_ = std::move(f); }

    // ---- lifecycle ----
    bool start(std::string& why) {
        if (node_ == nullptr) {
            why = "relay: no node attached";
            return false;
        }
        if (o_.send_queue_bytes < 2 * (headers_frame_ + 4)) {
            why = "relay: send queue " + std::to_string(o_.send_queue_bytes) + " B below two FC_HEADERS frames with their "
                  "length prefixes (2 x " + std::to_string(headers_frame_ + 4) + " B)";
            return false;
        }
        running_ = true;
        links_.configure(o_);
        links_.bind([this](std::uint64_t p, const std::vector<std::uint8_t>& f) { receive(p, f); },
                    [this](std::uint64_t p, const std::vector<std::uint8_t>& f) { on_control(p, f); },
                    [this](std::uint64_t p, bool up) { peer_event(p, up); });
        if (o_.listen) {
            if (!links_.listen(o_.listen_host, o_.listen_port)) {
                why = "relay: cannot listen on " + o_.listen_host + ":" + std::to_string(o_.listen_port);
                return false;
            }
            const std::uint16_t lp = links_.listen_port();
            const bool wild = o_.listen_host.empty() || o_.listen_host == "0.0.0.0";
            if (!wild) self_keys_.insert(rly::peer_key(o_.listen_host, lp));
            if (wild || o_.listen_host == "127.0.0.1") self_keys_.insert(rly::peer_key("127.0.0.1", lp));
            if (wild)
                for (const std::string& h : o_.self_hosts) self_keys_.insert(rly::peer_key(h, lp));
        }
        {
            std::lock_guard<std::mutex> lk(tmtx_);
            for (const auto& [h, pt] : o_.peers) {
                if (self_keys_.count(rly::peer_key(h, pt)) != 0) {
                    st_.self_skipped++;
                    log("relay: peer " + rly::peer_key(h, pt) + " is THIS node (our listen address) -> never dialed");
                    continue;
                }
                Target t;
                t.host = h;
                t.port = pt;
                targets_.push_back(t);
            }
        }
        if (o_.discovery) {
            book_.set_limits(o_.book_limits);
            const std::uint64_t now = clock_.wall_s();
            for (const std::string& k : self_keys_) {
                const auto c = k.rfind(':');
                book_.mark_self(k.substr(0, c), static_cast<std::uint16_t>(std::stoul(k.substr(c + 1))));
            }
            book_.load(o_.book_load, now);
            for (const auto& [h, pt] : o_.seeds) book_.learn(h, pt, now, now);
            book_.take_dirty();
        }
        disc_slow_ms_ = disc_saved_ms_ = live_tick_ms_ = now_ms();
        if (o_.threads) {
            const std::size_t n = std::clamp<std::size_t>(o_.verify_threads, 1, kMaxVerifyThreads);
            st_.verify_threads = n;
            owner_ = std::thread([this] { owner_loop(); });
            for (std::size_t i = 0; i < n; ++i) verify_.emplace_back([this] { verify_loop(); });
            join_ = std::thread([this] { join_loop(); });
            maint_ = std::thread([this] { maint_loop(); });
        } else {
            st_.verify_threads = 1;
        }
        return true;
    }

    void stop() {
        if (!running_.exchange(false)) return;
        { const std::lock_guard<std::mutex> lk(emtx_); }  // a waiter on ecv_ / fcv_ sees running_ false
        ecv_.notify_all();
        fcv_.notify_all();
        vcv_.notify_all();
        jcv_.notify_all();
        kcv_.notify_all();
        ccv_.notify_all();
        mcv_.notify_all();
        if (join_.joinable()) join_.join();
        for (std::thread& t : verify_)
            if (t.joinable()) t.join();
        verify_.clear();
        if (owner_.joinable()) owner_.join();
        if (maint_.joinable()) maint_.join();
        links_.stop();
        if (o_.discovery) save_book(true);
    }

    // Runs fn(node) under the node lock (the stratum, the miner, the template routine, a status line).
    template <class F>
    auto with_node(F&& fn) {
        const NodeGuard g(*this);
        return fn(*node_);
    }

    // ---- the link layer's handlers ----
    // A frame from `peer` (a reader thread, or the KAT).
    void receive(std::uint64_t p, const std::vector<std::uint8_t>& f) {
        note_rx(p);
        if (f.empty()) {
            st_.malformed++;
            return;
        }
        const std::uint8_t op = f[0];
        if (op == kOpFbHello) {
            wait_up_gate(p);
            HelloLink link;  // the link's addresses as the HELLO arrives (its down event may run before the owner)
            {
                std::lock_guard<std::mutex> lk(pmtx_);
                const auto it = peers_.find(p);
                if (it != peers_.end()) {
                    it->second.hello_posted = true;
                    link.out_host = it->second.out_host;
                    link.out_port = it->second.out_port;
                }
            }
            if (link.out_host.empty()) link.remote_ip = links_.remote_ip(p);
            post_from(p, [this, p, f, link] { handle_hello(p, f, link); }, [this, p, f, link] { hello_gone(p, f, link); });
            return;
        }
        bool ok = false, posted = false;
        {
            std::lock_guard<std::mutex> lk(pmtx_);
            const auto it = peers_.find(p);
            ok = it != peers_.end() && it->second.hello_ok;
            posted = it != peers_.end() && it->second.hello_posted;
        }
        if (!ok && posted) {  // its HELLO waits on the owner: the frame goes after it
            post_from(p, [this, p, f] {
                if (!hello_ok(p)) {
                    st_.pre_hello_dropped++;
                    return;
                }
                dispatch(p, f, true);
            });
            return;
        }
        if (!ok) {
            st_.pre_hello_dropped++;
            return;
        }
        dispatch(p, f, false);
    }
    // A frame from a HELLO-ok link (`owner`: run on the owner thread, after the link's HELLO).
    void dispatch(std::uint64_t p, const std::vector<std::uint8_t>& f, bool owner) {
        const auto run = [&](std::function<void()> fn) {
            if (owner)
                fn();
            else
                post_from(p, std::move(fn));
        };
        const std::uint8_t op = f[0];
        switch (op) {
            case kOpFbPing:
            case kOpFbPong:
                if (o_.keepalive_ms == 0) break;
                on_ping(p, f);
                return;
            case kOpFbGetAddr:
                if (!o_.discovery) break;
                on_getaddr(p, f);
                return;
            case kOpFbAddr:
                if (!o_.discovery) break;
                on_addr(p, f);
                return;
            case kOpFbGetCtx: run([this, p, f] { serve_getctx(p, f); }); return;
            case kOpFbCtx: run([this, p, f] { on_ctx(p, f); }); return;
            case kOpFbReceipts:
                if (f.size() > 1 && f[1] != kFrameVersion2) break;  // the old receipts v2 frame: unknown
                on_receipts_frame(p, f);
                return;
            case kOpFcCarrier: {
                if (route_reply(p, f)) return;
                if (f.size() > buffers_.frame) {  // above the frame buffer (P-11): DROP, before parsing
                    token(p, FrameToken::Drop);
                    return;
                }
                const CarrierReply k = carrier_reply(p, f);
                if (k == CarrierReply::BodySet) {
                    run([this, p, f] { handle_body_set(p, f); });
                    return;
                }
                enqueue_job(Job{Job::Kind::Carrier, p, src_of(p), f, 0, k == CarrierReply::Solicited});
                return;
            }
            case kOpFcHeaders: {
                bool node_reply = false;  // the frame answers this node's own request in link order
                if (route_reply(p, f, &node_reply)) return;
                run([this, p, f, node_reply] { handle_headers(p, f, node_reply); });
                return;
            }
            case kOpFcBuckets:
                if (route_reply(p, f)) return;
                run([this, p, f] { handle_buckets(p, f); });
                return;
            case kOpFcGetCarrier:
            case kOpFcGetHeaders:
            case kOpFcGetBuckets: run([this, p, f] { serve_request(p, f); }); return;
            default: break;
        }
        st_.unknown_opcodes++;  // FB_BLOCK_WON 0x42, 0x45-0x47, 0x4a / 0x4b, receipts v2, any other: counted, the link kept
    }
    // A frame with frame[0] >= 0x80: not handled here (counted, the link kept).
    void on_control(std::uint64_t p, const std::vector<std::uint8_t>&) {
        note_rx(p);
        st_.unknown_opcodes++;
    }
    // A link up (the accepting / dialing thread) or down (its reader thread).
    void peer_event(std::uint64_t p, bool up) {
        if (up) {
            on_peer_up(p);
            open_up_gate(p);
            return;
        }
        std::uint64_t src = 0;
        {
            std::lock_guard<std::mutex> lk(pmtx_);
            const auto it = peers_.find(p);
            if (it != peers_.end()) src = it->second.src;
            peers_.erase(p);
            up_done_.erase(p);
        }
        on_peer_down(p, src != 0 ? src : p);
    }

    // ---- manual mode (o_.threads false; the KATs) ----
    // Runs every queued net action, event and verify job until none is left; the count run.
    std::size_t pump() {
        std::size_t n = 0;
        for (;;) {
            bool any = false;
            n += run_net_actions();
            std::deque<std::function<void()>> ev;
            {
                std::lock_guard<std::mutex> lk(emtx_);
                ev.swap(events_);
            }
            for (std::function<void()>& e : ev) {
                e();
                ++n;
                any = true;
            }
            std::deque<Job> jobs;
            {
                std::lock_guard<std::mutex> lk(vmtx_);
                due_parked_locked();
                jobs.swap(vq_);
            }
            for (Job& j : jobs) {
                run_job(std::move(j));
                ++n;
                any = true;
            }
            if (!any) break;
        }
        return n;
    }
    // One join step: the next pair's attempt (the node lock held, released at its waits), then its outcome applied.
    std::optional<JoinStep> join_step() { return run_one_join(); }
    // The maintenance tick (the maintenance thread every 250 ms; manual mode: the caller).
    void tick() {
        run_net_actions();
        hello_timeouts();
        if (partitioned_ && now_ms() >= partition_until_ms_) {
            partitioned_ = false;
            dialing_ = true;
            log("relay: partition over -- redialing");
        }
        dial_targets();
        drive_liveness();
        if (o_.discovery) disc_tick();
        drive_ctx();
        node_tick();
        sweep_sealed_receipts();
        sweep_sealed_frames();
        rerun_due_receipts();
        reoffer_pump_all();
        rx_tick();
    }

    // ---- the rig and the status ----
    // A network partition of `secs` seconds: every link dropped, inbound links refused and nothing dialed until it ends.
    void partition_for(std::chrono::seconds secs) {
        partition_until_ms_ = now_ms() + static_cast<std::uint64_t>(secs.count()) * 1000;
        partitioned_ = true;
        dialing_ = false;
        for (std::uint64_t p : links_.peer_ids()) links_.disconnect(p);
        log("relay: PARTITION for " + std::to_string(secs.count()) + " s (all relay links dropped)");
    }
    void set_dialing(bool on) { dialing_ = on; }
    void drop_peer(std::uint64_t p) { links_.disconnect(p); }
    void ask_addrs_now() {
        for (std::uint64_t p : ready_peers()) send_getaddr(p);
    }
    void save_book(bool force) {
        if (!o_.discovery || !o_.book_save) return;
        if (!book_.take_dirty() && !force) return;
        o_.book_save(book_.records());
        st_.disc_saves++;
    }
    // Parks a carrier frame of `peer` in the verify parked list with no retry time (the parked-cap KAT).
    std::size_t test_park(std::uint64_t peer, const std::vector<std::uint8_t>& frame) {
        Job j{Job::Kind::Carrier, peer, peer, frame, 0};
        park_job(std::move(j), UINT64_MAX);
        return parked_size();
    }
    bool parked_has(const std::vector<std::uint8_t>& frame) const {
        std::lock_guard<std::mutex> lk(vmtx_);
        for (const Job& j : parked_)
            if (j.frame == frame) return true;
        return false;
    }

    const PathbRelayStats& stats() const noexcept { return st_; }
    // The budget in force (relay_budget_default, or the options' values).
    const RelayBudget& budget() const noexcept { return budget_; }
    static RelayBudget budget_of(const PathbRelayOptions& o) {
        RelayBudget b = relay_budget_default(std::clamp<std::size_t>(o.verify_threads, 1, kMaxVerifyThreads),
                                             o.max_inbound + o.max_outbound);
        if (o.dos) b.dos = *o.dos;
        if (o.ban_seconds) b.ban_seconds = *o.ban_seconds;
        return b;
    }
    const PathbRelayOptions& options() const noexcept { return o_; }
    // The context of an unsolicited receipt wanted (P-06), as a relayed frame's admission asks.
    void want_context(const Hash32& id, std::uint64_t from) { want_ctx(id, from, 0, CtxClass::Receipt); }
    // The context wants held now: all, and those of a join's climb (P-07).
    std::pair<std::size_t, std::size_t> ctx_wants_held() const {
        const std::array<std::size_t, 3> n = ctx_wants_by_class();
        return {n[0] + n[1] + n[2], n[2]};
    }
    // The context wants held now by class (Receipt, Carrier, Join).
    std::array<std::size_t, 3> ctx_wants_by_class() const {
        std::lock_guard<std::mutex> lk(cmtx_);
        std::array<std::size_t, 3> n{};
        for (const auto& kv : ctx_want_) ++n[static_cast<std::size_t>(kv.second.cls)];
        return n;
    }
    // A held want's climb bound (P-06 or P-07); none when not held.
    std::optional<std::uint32_t> ctx_want_bound(const Hash32& id) const {
        std::lock_guard<std::mutex> lk(cmtx_);
        const auto it = ctx_want_.find(id);
        if (it == ctx_want_.end()) return std::nullopt;
        return it->second.bound;
    }
    std::uint64_t node_nonce() const noexcept { return nonce_; }
    const std::set<std::string>& self_keys() const noexcept { return self_keys_; }
    RelayLinks& links() noexcept { return links_; }
    const rly::PeerBook& book() const noexcept { return book_; }
    std::uint64_t now_s() const { return now_ms() / 1000; }
    bool peer_known(std::uint64_t p) const {
        std::lock_guard<std::mutex> lk(pmtx_);
        return peers_.count(p) != 0;
    }
    bool hello_ok(std::uint64_t p) const {
        std::lock_guard<std::mutex> lk(pmtx_);
        const auto it = peers_.find(p);
        return it != peers_.end() && it->second.hello_ok;
    }
    std::vector<std::uint64_t> ready_peers() const {
        std::lock_guard<std::mutex> lk(pmtx_);
        std::vector<std::uint64_t> v;
        for (const auto& [p, s] : peers_)
            if (s.hello_ok) v.push_back(p);
        return v;
    }
    std::size_t peers_in() const {
        std::lock_guard<std::mutex> lk(pmtx_);
        std::size_t n = 0;
        for (const auto& [p, s] : peers_) n += s.inbound ? 1 : 0;
        return n;
    }
    std::size_t peers_out() const {
        std::lock_guard<std::mutex> lk(pmtx_);
        std::size_t n = 0;
        for (const auto& [p, s] : peers_) n += s.inbound ? 0 : 1;
        return n;
    }
    // The follower's main chain moved, or a RowWeights record was written: the frames parked on a Monero input (P_r,
    // its weights, its seed) whose input the follower holds now run again (each (cause, id) checked once).
    void on_monero_tip() {
        if (t_node_held == this) {  // the node lock is not re-entrant: run it after the holder lets go
            post([this] { on_monero_tip(); });
            return;
        }
        rerun_ready_ctx(std::nullopt);
    }
    // A peer's re-offer queue: the ids queued, and whether each is queued once.
    std::size_t reoffer_queued(std::uint64_t p) {
        std::lock_guard<std::mutex> lk(rmtx_);
        const auto it = reoffer_.find(p);
        return it == reoffer_.end() ? 0 : it->second.q.size();
    }
    bool reoffer_distinct(std::uint64_t p) {
        std::lock_guard<std::mutex> lk(rmtx_);
        const auto it = reoffer_.find(p);
        if (it == reoffer_.end()) return true;
        return std::set<Hash32>(it->second.q.begin(), it->second.q.end()).size() == it->second.q.size();
    }
    // The DEFERred receipts parked (P-09 at most).
    std::size_t parked_receipts() {
        const NodeGuard g(*this);
        return parked_receipts_.size();
    }
    // The asks recorded for parked receipts (they leave with their receipt), and the parked receipts due to run again.
    std::size_t parked_receipt_asks() {
        const NodeGuard g(*this);
        std::size_t n = 0;
        for (const auto& [key, e] : parked_receipts_) n += e.second.asked.size();
        return n;
    }
    std::size_t parked_receipts_due() {
        const NodeGuard g(*this);
        return receipt_due_.size();
    }
    // A receipt's one-body FB_RECEIPTS frame parked (by its key).
    bool receipt_parked(const std::vector<std::uint8_t>& frame) {
        const NodeGuard g(*this);
        return parked_receipts_.count(receipt_key(frame)) != 0;
    }
    // The digests indexed for a re-run, every cause.
    std::size_t parked_index_size() {
        const NodeGuard g(*this);
        std::size_t n = 0;
        for (const auto& [cause, ds] : parked_by_cause_) n += ds.size();
        for (const auto& [key, ds] : parked_ctx_) n += ds.size();
        return n;
    }
    // The digests indexed on a Monero input (cause, id).
    std::size_t parked_ctx_size(Missing m, const Hash32& id) { return parked_ctx_digests(m, id).size(); }
    std::set<Hash32> parked_ctx_digests(Missing m, const Hash32& id) {
        const NodeGuard g(*this);
        const auto it = parked_ctx_.find(std::make_pair(m, id));
        return it == parked_ctx_.end() ? std::set<Hash32>{} : it->second;
    }
    std::size_t strike_entries() const {
        std::lock_guard<std::mutex> lk(vmtx_);
        return strikes_by_peer_.size();
    }
    // KAT hooks: an admission outcome of `peer` parked on `m` (the relay's index and fetch), a strike on `peer`.
    void test_parked(std::uint64_t peer, Missing m, const Hash32& digest, const Hash32& fetch, bool relayed = true,
                     bool carrier = true) {
        NodeEventResult r;
        r.action = NodeAction::Parked;
        r.admit.missing = m;
        r.admit.digest = digest;
        r.admit.fetch = fetch;
        Effects fx;
        {
            const NodeGuard g(*this);
            after_result_locked(peer, r, digest, fx, relayed, carrier);
        }
        run_effects(fx);
    }
    // KAT hook: the frames parked for `m` run again, as when the cause resolves.
    void test_rerun(Missing m) { rerun_parked(m); }
    // KAT hooks: a tip-header request to `peer` as a TipUnknown admission asks it (from zero: the best chain at
    // pos(best) - J_0); the peers with a catch-up entry; the header requests waiting for `peer`'s slot.
    void test_tip_headers(std::uint64_t peer, const Hash32& from, const Hash32& stop) {
        const NodeGuard g(*this);
        request_tip_headers(peer, from, stop, std::nullopt);
    }
    std::size_t catchup_peers() const {
        std::lock_guard<std::mutex> lk(cumtx_);
        return catchup_.size();
    }
    std::size_t header_waiting(std::uint64_t peer) const {
        std::lock_guard<std::mutex> lk(cumtx_);
        const auto it = header_wants_.find(peer);
        return it == header_wants_.end() ? 0 : it->second.size();
    }
    // KAT hook: the parked objects the waiting header requests of `peer` carry.
    std::size_t header_waiting_objects(std::uint64_t peer) const {
        std::lock_guard<std::mutex> lk(cumtx_);
        const auto it = header_wants_.find(peer);
        std::size_t n = 0;
        if (it != header_wants_.end())
            for (const HdrWant& w : it->second) n += w.objs.ids.size();
        return n;
    }
    // KAT hooks: a header request of `peer` deferred on the P_r `fetch` (under `owner`, for `object`); the deferrals of
    // `peer` (of `owner`).
    void test_defer_headers(std::uint64_t peer, PathbNode::HeaderOwner owner, const Hash32& from, const Hash32& stop,
                            const Hash32& fetch, const std::optional<Hash32>& object = std::nullopt) {
        const NodeGuard g(*this);
        std::lock_guard<std::mutex> lk(cumtx_);
        HdrOnCtx w;
        w.owner = owner;
        w.from = from;
        w.stop = stop;
        w.fetch = fetch;
        if (object) w.objs.add(*object);
        note_ctx_locked(peer, w);
    }
    std::size_t header_deferred(std::uint64_t peer, PathbNode::HeaderOwner owner) const {
        std::lock_guard<std::mutex> lk(cumtx_);
        const auto it = headers_on_ctx_.find(peer);
        if (it == headers_on_ctx_.end()) return 0;
        return static_cast<std::size_t>(
                std::count_if(it->second.begin(), it->second.end(), [&](const HdrOnCtx& e) { return e.owner == owner; }));
    }
    // KAT hooks: the catch-up entry of `peer` (its page in flight and its last ask); the join attempts' transport.
    struct CatchupView {
        Hash32 fetch_tip{};
        std::uint64_t fetch_ms = 0;
        std::uint64_t asked_ms = 0;
        std::uint32_t step = 0;
    };
    std::optional<CatchupView> catchup_view(std::uint64_t peer) const {
        std::lock_guard<std::mutex> lk(cumtx_);
        const auto it = catchup_.find(peer);
        if (it == catchup_.end()) return std::nullopt;
        return CatchupView{it->second.fetch_tip, it->second.fetch_ms, it->second.asked_ms, it->second.step};
    }
    JoinTransport& test_join_transport() { return port_; }
    // P-50: the claim-leaf alarm buckets held.
    std::size_t claim_entries() const {
        std::lock_guard<std::mutex> lk(vmtx_);
        return claim_budget_.entries();
    }
    void test_strike(std::uint64_t peer) { strike(peer, 1, false); }
    // P-15: the objects left in `peer`'s valid-object budget; the per-peer buckets held.
    double peer_valid_left(std::uint64_t peer) { return valid_left(peer); }
    std::size_t valid_entries() const {
        std::lock_guard<std::mutex> lk(vmtx_);
        return valid_.size();
    }
    // The strike tokens applied to `peer` while its link is up.
    std::uint64_t strikes_of(std::uint64_t p) const {
        std::lock_guard<std::mutex> lk(vmtx_);
        const auto it = strikes_by_peer_.find(p);
        return it == strikes_by_peer_.end() ? 0 : it->second;
    }
    std::size_t parked_size() const {
        std::lock_guard<std::mutex> lk(vmtx_);
        return parked_.size();
    }
    std::size_t verify_queue_size() const {
        std::lock_guard<std::mutex> lk(vmtx_);
        return vq_.size();
    }
    std::size_t open_tickets() const {
        std::lock_guard<std::mutex> lk(kmtx_);
        return tickets_.size();
    }
    // The relay address of every HELLO-ok link ("?": an inbound peer that announced no listen port) and its direction.
    std::vector<std::pair<std::string, bool>> ready_links() const {
        std::lock_guard<std::mutex> lk(pmtx_);
        std::vector<std::pair<std::string, bool>> v;
        for (const auto& [p, s] : peers_)
            if (s.hello_ok) v.emplace_back(s.addr_key.empty() ? std::string("?") : s.addr_key, !s.out_host.empty());
        return v;
    }
    // The Monero contexts wanted now (FB_GETCTX).
    std::size_t ctx_wants() const {
        std::lock_guard<std::mutex> lk(cmtx_);
        return ctx_want_.size();
    }
    // The bytes of the context blocks the wanted contexts hold now (their verified blobs).
    std::size_t ctx_want_bytes() const {
        std::lock_guard<std::mutex> lk(cmtx_);
        std::size_t n = 0;
        for (const auto& kv : ctx_want_) n += kv.second.blob.size();
        return n;
    }
    // The per-peer omission log: link id -> the receipts its placed carriers left out that this node held pending (an
    // entry leaves at link down), and the total since start.
    std::map<std::uint64_t, std::uint64_t> omission_counts() const {
        std::lock_guard<std::mutex> lk(omtx_);
        return omissions_;
    }
    std::uint64_t omitted_total() const {
        std::lock_guard<std::mutex> lk(omtx_);
        return omitted_total_;
    }
    // The admission verdicts of peers' objects since start, by row (RowId, 0 = none) and verdict (AdmitVerdict).
    static constexpr std::size_t kRowKinds = static_cast<std::size_t>(RowId::R31) + 1;
    static constexpr std::size_t kVerdictKinds = static_cast<std::size_t>(AdmitVerdict::Drop) + 1;
    using VerdictCounts = std::array<std::array<std::uint64_t, kVerdictKinds>, kRowKinds>;
    VerdictCounts verdict_counts() const {
        std::lock_guard<std::mutex> lk(omtx_);
        return verdicts_;
    }
    // The most bytes the wanted contexts held at once (taken at every blob that enters a want).
    std::size_t ctx_want_bytes_peak() const {
        std::lock_guard<std::mutex> lk(cmtx_);
        return ctx_want_bytes_peak_;
    }
    std::string describe() const {
        char b[768];
        std::snprintf(b, sizeof b,
                      "relay: peers in=%zu out=%zu ready=%zu | hello ok=%llu rej=%llu old=%llu closed=%llu tmo=%llu | "
                      "strikes=%llu bans=%llu drops=%llu unknown=%llu pre_hello=%llu | parked=%zu dropped=%llu q=%zu | "
                      "silent_drops=%llu legacy=%llu | join tickets=%zu attempts=%llu strikes=%llu | "
                      "flood=%llu reoffer=%llu catchup=%llu buckets=%llu",
                      peers_in(), peers_out(), ready_peers().size(), ull(st_.hello_ok), ull(st_.hello_rejected),
                      ull(st_.hello_old_version), ull(st_.hello_closed), ull(st_.hello_timeout), ull(st_.strikes),
                      ull(st_.bans), ull(st_.drops), ull(st_.unknown_opcodes), ull(st_.pre_hello_dropped), parked_size(),
                      ull(st_.queue_dropped), verify_queue_size(), ull(st_.silent_drops), ull(st_.ka_legacy),
                      open_tickets(), ull(st_.join_attempts), ull(st_.join_strikes), ull(st_.flood_frames),
                      ull(st_.reoffer_frames), ull(st_.catchup_requests), ull(st_.bucket_requests));
        return b;
    }
    std::string disc_describe() const {
        std::size_t out = 0, in = 0;
        std::string links;
        for (const auto& [k, o] : ready_links()) {
            (o ? out : in)++;
            links += (links.empty() ? "" : ",") + k + (o ? ">" : "<");
        }
        char b[640];
        std::snprintf(b, sizeof b,
                      "relay-disc: %s known=%zu good=%zu bad=%zu | links out=%zu/%zu in=%zu/%zu | dialed=%llu "
                      "dial_ok=%llu learned=%llu | getaddr tx=%llu rx=%llu throttled=%llu | addr tx=%llu rx=%llu "
                      "unsolicited=%llu ignored=%llu | dup_dropped=%llu refused=%llu self=%llu saves=%llu "
                      "expired=%llu | nonce=%016llx self_conn=%llu self_skipped=%llu dup_deferred=%llu | peers=[",
                      o_.discovery ? "on" : "off", book_.size(), book_.good(), book_.bad_size(), out, o_.max_outbound, in,
                      o_.max_inbound, ull(st_.disc_dialed), ull(st_.disc_dial_ok), ull(st_.addr_learned),
                      ull(st_.getaddr_tx), ull(st_.getaddr_rx), ull(st_.getaddr_throttled), ull(st_.addr_tx),
                      ull(st_.addr_rx), ull(st_.addr_unsolicited), ull(st_.addr_ignored), ull(st_.disc_dup_dropped),
                      ull(st_.disc_bad), ull(st_.disc_self), ull(st_.disc_saves), ull(st_.disc_expired),
                      static_cast<unsigned long long>(nonce_), ull(st_.self_conn), ull(st_.self_skipped),
                      ull(st_.dup_deferred));
        return std::string(b) + links + "]";
    }

private:
    // ---- state ----
    struct PeerSt {
        bool hello_ok = false;
        bool hello_sent = false;
        bool hello_posted = false;       // a HELLO of the link waits on the owner
        std::uint64_t connected_ms = 0;
        std::uint64_t last_rx_ms = 0;
        std::uint64_t last_ping_ms = 0;  // 0: ping at once
        bool ka = false;                 // the peer answered or sent a PING on this link
        std::uint32_t unanswered = 0;    // PINGs sent while !ka
        bool legacy_noted = false;
        std::string out_host;            // set iff this node dialed the link
        std::uint16_t out_port = 0;
        std::string addr_key;            // the peer's relay address (dialed, or remote ip : HELLO listen port)
        std::string remote_ip;           // inbound: the socket's remote address
        std::uint64_t getaddr_tx_ms = 0;
        std::uint64_t getaddr_rx_ms = 0;
        bool addr_pending = false;
        std::size_t addr_learned = 0;
        std::uint64_t src = 0;           // the budget source: the address key, or the link id with none
        bool inbound = false;
        std::uint64_t remote_nonce = 0;
        std::uint16_t remote_listen = 0;
    };
    // A link's addresses as its HELLO arrives: the dialed address, or the socket's remote ip of an accepted link.
    struct HelloLink {
        std::string out_host;
        std::uint16_t out_port = 0;
        std::string remote_ip;
    };
    static constexpr std::uint32_t kLegacyProbes = 3;
    struct Target {
        std::string host;
        std::uint16_t port = 0;
        std::uint64_t pid = 0;
        std::uint64_t gone_ms = 0;  // its link left the link table before its down event ran (0: not seen)
        std::uint64_t next_try_ms = 0;
        int backoff_s = 1;
        std::uint32_t prehello_fails = 0;
        bool hello_seen = false;
        bool hello_timed_out = false;
        bool learned = false;  // from the book: one link, then retired
        bool used = false;
        bool self = false;     // its HELLO carried this node's nonce: never dialed again
    };
    static constexpr int kRefusedBackoffCapS = 16;
    static constexpr int kSilentBackoffCapS = 60;
    static int prehello_delay_s(Target& t) {
        if (t.hello_seen) {
            t.prehello_fails = 0;
            return 1;
        }
        t.prehello_fails += t.hello_timed_out ? 2u : 1u;
        const int cap = t.hello_timed_out ? kSilentBackoffCapS : kRefusedBackoffCapS;
        if (t.prehello_fails <= 1) return 1;
        const std::uint32_t sh = std::min<std::uint32_t>(t.prehello_fails - 1, 6);
        return std::min(cap, 1 << sh);
    }
    // A dial target whose link is gone: redialed after the pre-HELLO backoff (tmtx_ held).
    void release_target_locked(Target& t) {
        t.pid = 0;
        t.gone_ms = 0;
        if (o_.discovery && !t.hello_seen) book_.mark_failed(t.host, t.port, clock_.wall_s());
        t.next_try_ms = now_ms() + static_cast<std::uint64_t>(prehello_delay_s(t)) * 1000;
        t.hello_seen = false;
        t.hello_timed_out = false;
    }
    struct Job {
        enum class Kind : std::uint8_t { Carrier, Receipt } kind = Kind::Carrier;
        std::uint64_t peer = 0;
        std::uint64_t src = 0;
        std::vector<std::uint8_t> frame;
        std::uint64_t not_before_ms = 0;
        bool solicited = false;  // a reply to this node's own FC_GETCARRIER: the solicited credit (P-21)
        bool rerun = false;      // a frame run again (P-15 gated at its first arrival only; counted once, at its first placement)
        // a parked receipt's asks: (peer, cause, object), each made once while the receipt is parked or runs again
        std::set<std::tuple<std::uint64_t, Missing, Hash32>> asked;
        std::uint64_t origin_h = 0;  // a parked receipt's origin height h(r) (0: its P_r not held yet)
    };
    static constexpr std::uint64_t kParkRetryMs = 500;  // a job with no token waits this long before its next try
    static constexpr std::size_t kRependLogIds = 16;  // the re-pended ids named on one re-pend offer line
    static constexpr std::size_t kAskedMax = 256;       // asked carrier ids kept per peer
    struct Ticket {
        std::uint64_t peer = 0;
        std::uint8_t op = 0;             // the reply opcode
        std::set<Hash32> ids;            // FC_CARRIER: the asked ids not received yet
        std::size_t n = 0;               // FC_CARRIER: frames read at most
        Hash32 at{};                     // FC_BUCKETS
        std::vector<std::vector<std::uint8_t>> frames;
        std::uint64_t last_ms = 0;       // the send, then each frame
        bool closed = false;             // the peer disconnected
    };
    struct HdrWait {
        bool node = true;                // a request of the node (else a ticket's)
        std::uint64_t ticket = 0;
        bool dead = false;               // the ticket ended: its reply is dropped
    };
    struct Catchup {
        Hash32 tip{};
        bool from_pos0 = false;          // the last request asked from position 0
        bool from_root = false;          // ... from the lowest position the node holds (no step below it)
        std::uint32_t step = 0;          // the locator step of `from`: the best tip, then pos - 1, pos - 2, pos - 4, ...
        Hash32 asked_best{};
        std::uint64_t asked_ms = 0;
        Hash32 fetch_tip{};              // the last FetchBodies page's tip, while its bodies are in flight
        Hash32 fetch_best{};             // the best tip at the page's last progress
        std::uint64_t fetch_ms = 0;      // ... and its time
    };
    // A header request waiting for its peer's slot (one in flight per peer), served oldest first when the slot frees.
    // The parked objects (frame digests, receipt keys) waiting on a tip-header entry, in the order they came.
    struct TipObjects {
        std::set<Hash32> ids;
        std::deque<Hash32> order;
        bool tied = false;  // an object came (an entry made with none is not tied)
        void add(const Hash32& o) {
            tied = true;
            if (ids.insert(o).second) order.push_back(o);
        }
        void add(const TipObjects& t) {
            tied = tied || t.tied;
            for (const Hash32& o : t.order) add(o);
        }
    };
    struct HdrWant {
        PathbNode::HeaderOwner owner = PathbNode::HeaderOwner::Tip;
        Hash32 from{};
        Hash32 stop{};
        TipObjects objs;  // the parked objects waiting on it
    };
    // The tip-header request in flight to a peer and the objects it serves (its deferral takes them).
    struct HdrSent {
        Hash32 from{};
        Hash32 stop{};
        TipObjects objs;
    };
    // A catch-up or headers-first request deferred on a P_r: asked again once that P_r resolves, under its owner.
    struct HdrOnCtx {
        PathbNode::HeaderOwner owner = PathbNode::HeaderOwner::CatchUp;
        Hash32 from{};
        Hash32 stop{};
        Hash32 fetch{};               // the P_r
        Missing cause = Missing::MoneroBlock;  // its input: the block resolved, or (the floor reading) its weights
        std::uint64_t since_ms = 0;   // the first DEFER on this P_r
        bool offered = false;         // the peer's tip offered to the joiner for it (a store not caught up)
        TipObjects objs;              // a tip request's: the parked objects waiting on it
    };
    struct CtxWant {
        std::uint64_t from = 0;
        std::uint32_t depth = 0;
        std::uint32_t bound = 0;  // the climb's bound: ctx_max_depth (Receipt), ctx_join_depth (Carrier, Join)
        CtxClass cls = CtxClass::Receipt;
        std::set<std::uint64_t> asked;
        std::uint32_t rounds = 0;
        std::uint64_t since_ms = 0;
        std::uint64_t last_ask_ms = 0;
        bool have_proof = false;
        rly::BlockCtx proof{};
        std::vector<std::uint8_t> blob;
        std::uint64_t proof_from = 0;
        bool defer_noted = false;
    };
    static constexpr std::uint64_t kCtxTtlMs = 10 * 60 * 1000;  // a want is given up after this
    static constexpr std::uint64_t kCtxLocalMs = 10 * 1000;     // an own-source lookup per id at most this often
    static constexpr std::size_t kCtxPowKeep = 256;
    static constexpr int kUpGateWaitMs = 2000;

    // The node lock as a scope; join: the join worker's hold (released at its waits).
    struct NodeGuard {
        PathbRelayNode& r;
        const PathbRelayNode* prev;
        const PathbRelayNode* prev_held;
        explicit NodeGuard(PathbRelayNode& rr, bool join = false) : r(rr), prev(t_join_relay), prev_held(t_node_held) {
            r.lock_.lock();
            t_join_relay = join ? &r : nullptr;
            t_node_held = &r;
        }
        ~NodeGuard() {
            t_join_relay = prev;
            t_node_held = prev_held;
            r.lock_.unlock();
        }
        NodeGuard(const NodeGuard&) = delete;
        NodeGuard& operator=(const NodeGuard&) = delete;
    };
    // Lets the node lock go while the join worker waits or hashes; takes it again after.
    struct JoinRelease {
        PathbRelayNode& r;
        bool held;
        explicit JoinRelease(PathbRelayNode& rr) : r(rr), held(t_join_relay == &rr) {
            if (held) {
                t_node_held = nullptr;
                r.lock_.unlock();
            }
        }
        ~JoinRelease() {
            if (held) {
                r.lock_.lock();
                t_node_held = &r;
            }
        }
        JoinRelease(const JoinRelease&) = delete;
        JoinRelease& operator=(const JoinRelease&) = delete;
    };

    // The JoinTransport of the node's join attempts.
    class JoinPort final : public JoinTransport {
    public:
        explicit JoinPort(PathbRelayNode& r) : r_(r) {}
        std::uint64_t send(std::uint64_t peer, const std::vector<std::uint8_t>& request) override {
            return r_.ticket_send(peer, request);
        }
        std::vector<std::vector<std::uint8_t>> collect(std::uint64_t ticket, std::uint64_t timeout_s) override {
            return r_.ticket_collect(ticket, timeout_s);
        }
        void drop(std::uint64_t ticket) override { r_.ticket_drop(ticket); }
        std::uint64_t now_s() const override { return r_.now_s(); }
        void wait_until(std::uint64_t t_s) override { r_.wait_until_s(t_s); }

    private:
        PathbRelayNode& r_;
    };

    static unsigned long long ull(const std::atomic<std::uint64_t>& a) { return static_cast<unsigned long long>(a.load()); }
    std::uint64_t now_ms() const { return clock_.mono_ms(); }
    std::int64_t now_ns() const { return static_cast<std::int64_t>(now_ms()) * 1000000; }
    void log(const std::string& s) const {
        if (log_) log_(s);
    }
    static std::string hex_short(const Hash32& h) {
        static const char* d = "0123456789abcdef";
        std::string s;
        for (int i = 0; i < 6; ++i) {
            s.push_back(d[h[i] >> 4]);
            s.push_back(d[h[i] & 15]);
        }
        return s;
    }

    // ---- the executor ----
    void post(std::function<void()> fn) {
        {
            std::lock_guard<std::mutex> lk(emtx_);
            if (!running_) return;
            events_.push_back(std::move(fn));
            note_queue_locked();
        }
        ecv_.notify_one();
    }
    // A reader thread's event for peer `p`: one posted event per peer in flight; the reader waits until the
    // previous one has run (the link's TCP flow control engages). The readers' events are bounded by the link
    // count; the workers' posts (a carrier's completion, the join outcome, a link's down, our HELLO) are outside
    // this gate, bounded by the verify queue and the link count. An event whose peer is gone when it runs is
    // skipped (`gone` runs instead, when given).
    void post_from(std::uint64_t p, std::function<void()> fn, std::function<void()> gone = {}) {
        if (!o_.threads) {
            post([this, p, f = std::move(fn), g = std::move(gone)] {
                if (!peer_known(p)) {  // its link went down while the event waited
                    st_.stale_events++;
                    if (g) g();
                    return;
                }
                f();
            });
            return;
        }
        {
            std::unique_lock<std::mutex> lk(emtx_);
            if (inflight_.count(p) != 0) {
                st_.owner_waits++;
                fcv_.wait(lk, [&] { return !running_ || inflight_.count(p) == 0; });
            }
            if (!running_) return;
            inflight_.insert(p);
            events_.push_back([this, p, f = std::move(fn), g = std::move(gone)] {
                struct Done {
                    PathbRelayNode* r;
                    std::uint64_t p;
                    ~Done() {
                        {
                            std::lock_guard<std::mutex> l2(r->emtx_);
                            r->inflight_.erase(p);
                        }
                        r->fcv_.notify_all();
                    }
                } done{this, p};
                if (!peer_known(p)) {  // its link went down while the event waited
                    st_.stale_events++;
                    if (g) g();
                    return;
                }
                f();
            });
            note_queue_locked();
        }
        ecv_.notify_one();
    }
    void note_queue_locked() {
        const std::uint64_t n = events_.size();
        if (n > st_.owner_queue_hwm.load()) st_.owner_queue_hwm = n;
    }
    void owner_loop() {
        while (running_) {
            std::function<void()> fn;
            {
                std::unique_lock<std::mutex> lk(emtx_);
                ecv_.wait(lk, [&] { return !events_.empty() || !running_; });
                if (!running_) break;
                fn = std::move(events_.front());
                events_.pop_front();
            }
            fn();
        }
    }
    void maint_loop() {
        while (running_) {
            {
                std::unique_lock<std::mutex> lk(mmtx_);
                mcv_.wait_for(lk, std::chrono::milliseconds(250), [&] { return !running_ || maint_wake_; });
                maint_wake_ = false;
            }
            if (!running_) break;
            tick();
        }
    }
    void wake_maint() {
        {
            std::lock_guard<std::mutex> lk(mmtx_);
            maint_wake_ = true;
        }
        mcv_.notify_one();
    }

    // ---- links ----
    void note_rx(std::uint64_t p) {
        std::lock_guard<std::mutex> lk(pmtx_);
        const auto it = peers_.find(p);
        if (it != peers_.end()) it->second.last_rx_ms = now_ms();
    }
    std::uint64_t src_of(std::uint64_t p) const {
        std::lock_guard<std::mutex> lk(pmtx_);
        const auto it = peers_.find(p);
        return it != peers_.end() && it->second.src != 0 ? it->second.src : p;
    }
    bool src_banned(std::uint64_t src) {
        {
            std::lock_guard<std::mutex> lk(vmtx_);
            if (dos_.is_banned(src)) return true;
        }
        return ::c2pool::v37n::net::is_addr_key(src) && links_.is_banned_key(src);
    }
    void open_up_gate(std::uint64_t p) {
        {
            std::lock_guard<std::mutex> lk(pmtx_);
            up_done_.insert(p);
        }
        upcv_.notify_all();
        if (!links_.has_peer(p)) {
            std::lock_guard<std::mutex> lk(pmtx_);
            up_done_.erase(p);
        }
    }
    // A HELLO read before this node's up event ran for the link waits for it (bounded), so our HELLO goes out first.
    void wait_up_gate(std::uint64_t p) {
        if (!o_.threads) return;
        std::unique_lock<std::mutex> lk(pmtx_);
        for (int waited = 0; up_done_.count(p) == 0 && waited < kUpGateWaitMs; waited += 20) {
            upcv_.wait_for(lk, std::chrono::milliseconds(20));
            if (up_done_.count(p) != 0) break;
            lk.unlock();
            const bool gone = !links_.has_peer(p);
            lk.lock();
            if (gone) break;
        }
    }
    void on_peer_up(std::uint64_t p) {
        if (partitioned_) {
            links_.disconnect(p);
            return;
        }
        bool over = false;
        const std::uint64_t akey = links_.addr_key(p);
        const bool inbound = links_.is_inbound(p);
        {
            std::lock_guard<std::mutex> lk(pmtx_);
            PeerSt s;
            s.src = akey != 0 ? akey : p;
            s.inbound = inbound;
            s.connected_ms = s.last_rx_ms = now_ms();
            if (t_dialing_relay == this) {
                s.out_host = dial_host_;
                s.out_port = dial_port_;
            }
            peers_[p] = s;
            if (inbound) {
                std::size_t n_in = 0;
                for (const auto& [q, ps] : peers_) n_in += ps.inbound ? 1 : 0;
                over = n_in > o_.max_inbound;
            }
        }
        if (!links_.has_peer(p)) {  // the link ended before this ran: no down event follows
            std::lock_guard<std::mutex> lk(pmtx_);
            peers_.erase(p);
            return;
        }
        if (over) {
            st_.over_cap++;
            links_.disconnect(p);
            return;
        }
        post([this, p] { send_our_hello(p); });
    }
    void on_peer_down(std::uint64_t p, std::uint64_t src) {
        {
            const bool addr = ::c2pool::v37n::net::is_addr_key(src);
            const bool last = !addr || links_.conns_from(src) == 0;
            std::lock_guard<std::mutex> lk(vmtx_);
            if (!addr)
                dos_.forget(src);
            else if (last)
                dos_.release(src, now_ns());
            strikes_by_peer_.erase(p);
            valid_.erase(p);
            claim_budget_.forget(p);
        }
        tickets_peer_gone(p);
        {
            std::lock_guard<std::mutex> lk(rmtx_);
            reoffer_.erase(p);
            reoffer_t0_.erase(p);
        }
        {
            std::lock_guard<std::mutex> lk(cumtx_);
            catchup_.erase(p);
            header_wants_.erase(p);
            headers_on_ctx_.erase(p);
            hdr_sent_.erase(p);
        }
        {
            std::lock_guard<std::mutex> lk(tmtx_);
            for (Target& t : targets_)
                if (t.pid == p) release_target_locked(t);
        }
        post([this, p] {
            const NodeGuard g(*this);
            node_->disconnect(p);
            strip_gone_peer_asks_locked(p);
            std::lock_guard<std::mutex> lk(omtx_);
            omissions_.erase(p);
        });
    }
    // Under the node lock: a gone link's ask records leave every parked receipt (link ids are not reused, so they
    // gate nothing; one pass over the park, at most P-09 receipts).
    void strip_gone_peer_asks_locked(std::uint64_t p) {
        for (auto& [key, e] : parked_receipts_) {
            auto& asked = e.second.asked;
            const auto lo = asked.lower_bound(std::make_tuple(p, static_cast<Missing>(0), Hash32{}));
            auto hi = lo;
            while (hi != asked.end() && std::get<0>(*hi) == p) ++hi;
            asked.erase(lo, hi);
        }
    }
    // Disconnects and bans run on the maintenance thread (never under the node lock).
    void defer_drop(std::uint64_t p, std::uint64_t src, bool ban) {
        {
            std::lock_guard<std::mutex> lk(tmtx_);
            to_drop_.push_back(NetDrop{p, src, ban});
        }
        wake_maint();
    }
    std::size_t run_net_actions() {
        std::vector<NetDrop> drops;
        {
            std::lock_guard<std::mutex> lk(tmtx_);
            drops.swap(to_drop_);
        }
        for (const NetDrop& d : drops) {
            const bool addr = ::c2pool::v37n::net::is_addr_key(d.src);
            if (d.ban && addr && budget_.ban_seconds) {
                const bool fresh = !links_.is_banned_key(d.src);
                links_.ban_key(d.src, budget_.ban_seconds);  // every link from src dropped, p included
                if (fresh) {
                    st_.addr_bans++;
                    log("relay: address " + ::c2pool::v37n::net::addr_key_str(d.src) + " (peer " + std::to_string(d.peer) +
                        ") BANNED for " + std::to_string(budget_.ban_seconds) + " s");
                }
            } else {
                links_.disconnect(d.peer);
            }
            if (d.ban && addr) {
                std::lock_guard<std::mutex> lk(vmtx_);
                dos_.forget(d.src);
            }
        }
        return drops.size();
    }

    // ---- tokens ----
    void token(std::uint64_t p, FrameToken t, std::uint32_t n = 1) {
        if (t == FrameToken::Strike) strike(p, n, false);
        if (t == FrameToken::Drop) st_.drops++;
    }
    // STRIKE: `n` tokens of the sender's budget (`taken`: one of them was taken already, before RandomX).
    void strike(std::uint64_t p, std::uint32_t n, bool taken) {
        if (n == 0) return;
        st_.strikes += n;
        const std::uint64_t src = src_of(p);
        const bool known = peer_known(p);
        std::lock_guard<std::mutex> lk(vmtx_);
        if (known) strikes_by_peer_[p] += n;  // a peer whose link is gone keeps no entry
        for (std::uint32_t k = taken ? 1 : 0; k < n; ++k) (void)dos_.grant_randomx(src, now_ns());
    }
    // BAN: the sender's address banned for ban_seconds (no address: the link dropped); the line names the check.
    void ban(std::uint64_t p, const std::string& why) {
        st_.bans++;
        log("relay: peer " + std::to_string(p) + " BANNED: " + (why.empty() ? std::string("(no reason given)") : why));
        defer_drop(p, src_of(p), true);
    }
    // The job's token back: the solicited credit, or the source's token (a valid object, or no RandomX spent).
    void refund(const Job& j) {
        std::lock_guard<std::mutex> lk(vmtx_);
        if (j.solicited)
            solicited_ = std::min<double>(o_.solicited_credits, solicited_ + 1.0);
        else
            dos_.on_valid_pow(j.src, now_ns());
    }
    void refill_solicited_locked() {
        const std::uint64_t now = now_ms();
        if (solicited_ms_ != 0 && now > solicited_ms_)
            solicited_ = std::min<double>(o_.solicited_credits,
                                          solicited_ + static_cast<double>(now - solicited_ms_) * kSolicitedRefillPerS / 1000.0);
        solicited_ms_ = now;
    }

    // ---- the verify pool ----
    void enqueue_job(Job j) {
        // P-15 at arrival: above the peer's valid-object budget an unsolicited frame is DROPPED (counted; no token)
        if (!j.solicited && !j.rerun && !valid_has(j.peer)) {
            st_.p15_drops++;
            return;
        }
        {
            std::lock_guard<std::mutex> lk(vmtx_);
            if (vq_.size() >= o_.verify_queue_max) {
                vq_.pop_front();
                st_.queue_dropped++;
            }
            vq_.push_back(std::move(j));
        }
        vcv_.notify_one();
    }
    void park_job(Job j, std::uint64_t not_before_ms) {
        std::lock_guard<std::mutex> lk(vmtx_);
        j.not_before_ms = not_before_ms;
        if (parked_.size() >= o_.parked_max && !parked_.empty()) {
            parked_.pop_front();  // the oldest goes: no penalty
            st_.queue_dropped++;
        }
        if (o_.parked_max > 0) parked_.push_back(std::move(j));
    }
    void due_parked_locked() {
        const std::uint64_t t = now_ms();
        for (auto it = parked_.begin(); it != parked_.end();) {
            if (it->not_before_ms <= t) {
                vq_.push_front(std::move(*it));
                it = parked_.erase(it);
            } else {
                ++it;
            }
        }
    }
    void verify_loop() {
        while (running_) {
            Job j;
            {
                std::unique_lock<std::mutex> lk(vmtx_);
                vcv_.wait_for(lk, std::chrono::milliseconds(200), [&] { return !vq_.empty() || !running_; });
                if (!running_) break;
                due_parked_locked();
                if (vq_.empty()) continue;
                j = std::move(vq_.front());
                vq_.pop_front();
            }
            run_job(std::move(j));
        }
    }
    // One job: the sender's token, then the admission under the node lock; the token goes back unless the outcome
    // costs one (STRIKE) or bans.
    void run_job(Job j) {
        if (src_banned(j.src)) {
            st_.banned_src_dropped++;
            return;
        }
        bool granted = false;
        {
            std::lock_guard<std::mutex> lk(vmtx_);
            if (j.solicited) {
                refill_solicited_locked();
                if (solicited_ >= 1.0) {
                    solicited_ -= 1.0;
                    granted = true;
                }
            } else {
                granted = dos_.grant_randomx(j.src, now_ns());
            }
        }
        if (granted && j.solicited) st_.solicited_jobs++;
        if (!granted) {
            st_.rx_deferred++;
            park_job(std::move(j), now_ms() + kParkRetryMs);
            return;
        }
        if (j.kind == Job::Kind::Carrier) {
            PathbNode::CarrierTicket t;
            std::uint64_t fresh = 0;
            bool rx_fail = false;
            std::string rx_why;
            {
                const NodeGuard g(*this);
                if (!running_) {
                    refund(j);
                    return;
                }
                if (!j.solicited) fresh = new_carried(j.frame);
                try {
                    t = node_->begin_carrier(j.peer, j.frame, true, j.solicited);
                } catch (const RandomxFailure& e) {
                    rx_fail = true;
                    rx_why = e.what();
                }
            }
            if (rx_fail) {
                rx_failed(std::move(j), "carrier", rx_why);
                return;
            }
            // the token stays spent for a STRIKE or a BAN (begin_carrier's verdict is final for both); a solicited
            // frame's STRIKE takes its token from the source as well
            const bool kept = t.admit.verdict == AdmitVerdict::Strike || t.admit.verdict == AdmitVerdict::Ban;
            if (!kept) refund(j);
            const bool taken = kept && !j.solicited;
            const bool solicited = j.solicited;
            post([this, t = std::move(t), taken, solicited, fresh]() mutable { complete_job(std::move(t), taken, solicited, fresh); });
            return;
        }
        std::vector<NodeEventResult> rs;
        Effects fx;
        bool rx_fail = false;
        std::string rx_why;
        std::uint64_t fresh = 0;
        {
            const NodeGuard g(*this);
            if (!running_) {
                refund(j);
                return;
            }
            try {
                rs = node_->on_receipts(j.peer, j.frame);
            } catch (const RandomxFailure& e) {
                rx_fail = true;
                rx_why = e.what();
            }
            if (!rx_fail)
                for (const NodeEventResult& r : rs) {
                    const bool park = r.action == NodeAction::Parked && r.admit.missing && rerun_cause(*r.admit.missing);
                    const Hash32 key = park ? receipt_key(j.frame) : Hash32{};
                    if (park) park_receipt_locked(key, std::move(j.asked), j);
                    after_result_locked(j.peer, r, std::nullopt, fx, !j.solicited, /*carrier=*/false,
                                        park ? std::optional<Hash32>(key) : std::nullopt);
                    // a first-seen receipt (held now, or evicted at once by P-09; a copy held before is a duplicate),
                    // or a #7 refusal
                    if ((r.admit.verdict == AdmitVerdict::AdmitPending &&
                         (r.action == NodeAction::Pending || !node_->pending().holds(r.admit.id))) ||
                        (r.admit.verdict == AdmitVerdict::Refuse && r.admit.row == RowId::R21))
                        ++fresh;
                }
        }
        if (rx_fail) {
            rx_failed(std::move(j), "receipt", rx_why);
            return;
        }
        if (!j.solicited && fresh > 0) valid_count(j.peer, fresh);  // its first placement, a re-run or not
        bool kept = false;
        for (const NodeEventResult& r : rs) kept = apply_result(j.peer, r, !kept) || kept;
        if (!kept) refund(j);
        run_effects(fx);
    }
    // The placement on the owner. The carriers it releases whose admission fails with a RandomX failure come back
    // from the node (take_rx_failed) and are parked and run again; the placed carrier keeps its result and effects.
    // A RandomX failure of this frame's own re-admission parks this frame (its solicited state kept).
    void complete_job(PathbNode::CarrierTicket t, bool token_kept, bool solicited = false, std::uint64_t fresh = 0) {
        const std::uint64_t peer = t.peer;
        const Hash32 digest = ::v37::sha256d(t.frame);
        std::vector<std::uint8_t> frame = t.frame;
        NodeEventResult r;
        Effects fx;
        bool rx_fail = false;
        std::string rx_why;
        {
            const NodeGuard g(*this);
            try {
                r = node_->complete_carrier(std::move(t));
            } catch (const RandomxFailure& e) {
                rx_fail = true;
                rx_why = e.what();
            }
            if (!rx_fail) after_result_locked(peer, r, digest, fx, !solicited);
            take_rx_failed_locked(fx);
        }
        if (rx_fail) {
            rx_alarm("carrier placement", rx_why);
            park_job(Job{Job::Kind::Carrier, peer, src_of(peer), std::move(frame), 0, solicited, true}, now_ms() + kParkRetryMs);
            run_effects(fx);
            return;
        }
        if (!solicited && (r.action == NodeAction::Placed || r.action == NodeAction::SideBranch ||
                           r.action == NodeAction::Switched || r.action == NodeAction::JoinerPath))
            valid_count(peer, 1 + fresh);  // its first placement, a re-run or not: its own body and its new carried ones
        (void)apply_result(peer, r, token_kept);
        run_effects(fx);
    }
    // A RandomX failure (RandomxFailure from the hash) inside an admission: node-internal, a local alarm; the token
    // goes back and the frame is parked and run again; no strike, no ban.
    // P-50: a claim-leaf alarm on a frame `p` relayed (not a reply to this node's own request); the bucket empty:
    // the link dropped, no ban, no token, no verdict changed (the frame is DEFERred either way).
    void claim_charge(std::uint64_t p) {
        st_.claim_alarms++;
        bool ok = true;
        {
            std::lock_guard<std::mutex> lk(vmtx_);
            ok = claim_budget_.charge(p, now_ms() / 1000, true);
        }
        if (ok) return;
        st_.claim_alarm_drops++;
        log("relay: peer " + std::to_string(p) + ": claim-leaf alarm budget empty (P-50) -> link dropped, no ban");
        defer_drop(p, src_of(p), false);
    }
    void rx_failed(Job j, const char* where, const std::string& why) {
        rx_alarm(where, why);
        refund(j);
        j.rerun = true;  // run again (not gated again; counted at its first placement)
        park_job(std::move(j), now_ms() + kParkRetryMs);
    }
    // The alarm: every failure counted; a log line when RandomX starts failing (where, and the failure's reason) and
    // one when a hash is computed again (rx_tick).
    void rx_alarm(const std::string& where, const std::string& why = {}) {
        st_.rx_failures++;
        rx_mark_ = rx_ok_.load();
        if (!rx_failing_.exchange(true))
            log("relay: RandomX failing (" + where + (why.empty() ? "" : ": " + why) + "): frames parked and run again");
    }
    void rx_tick() {
        if (rx_failing_.load() && rx_ok_.load() > rx_mark_.load() && rx_failing_.exchange(false))
            log("relay: RandomX hashes again");
    }
    // Under the node lock: the carried bodies of a carrier frame this node holds no pending copy of.
    std::uint64_t new_carried(const std::vector<std::uint8_t>& f) {
        if (f.size() < kFrameHeaderBytes) return 0;
        CarrierBodyV3 c;
        if (decode_carrier_body_v3(f.data() + kFrameHeaderBytes, f.size() - kFrameHeaderBytes,
                                   CarrierLimits{buffers_.receipt, p_.r_max}, c) != WireError::None)
            return 0;
        std::uint64_t n = 0;
        for (const ReceiptBodyV3& b : c.carried) n += node_->pending().holds(receipt_id(b)) ? 0 : 1;
        return n;
    }
    // P-15: one bucket per peer, `valid_rate_` objects/s up to `valid_cap_`; a frame arrives only while one object is
    // left; the objects are counted after their verdict.
    bool valid_has(std::uint64_t p) {
        bool ok = false;
        {
            std::lock_guard<std::mutex> lk(vmtx_);
            ok = valid_bucket_locked(p).tokens >= 1.0;
        }
        valid_gone(p);
        return ok;
    }
    void valid_count(std::uint64_t p, std::uint64_t n) {
        {
            std::lock_guard<std::mutex> lk(vmtx_);
            valid_bucket_locked(p).tokens -= static_cast<double>(n);
            st_.p15_counted += n;
        }
        valid_gone(p);
    }
    // A bucket made for a peer whose link went down meanwhile does not stay (on_peer_down erases the others).
    void valid_gone(std::uint64_t p) {
        if (peer_known(p)) return;
        std::lock_guard<std::mutex> lk(vmtx_);
        valid_.erase(p);
    }
    // An omission entry made for a link that went down meanwhile does not stay (a carrier run again after its link's
    // down: a RandomX park, a parked frame's re-run, a queued verify job); the total keeps the count. The link-down
    // handler erases the others, so the log holds only links that are up.
    void omission_gone(std::uint64_t p) {
        if (peer_known(p)) return;
        std::lock_guard<std::mutex> lk(omtx_);
        omissions_.erase(p);
    }
    struct ValidBucket {
        double tokens = 0;
        std::uint64_t ms = 0;
    };
    ValidBucket& valid_bucket_locked(std::uint64_t p) {
        const std::uint64_t now = now_ms();
        const auto [it, fresh] = valid_.try_emplace(p);
        ValidBucket& b = it->second;
        if (fresh) {
            b.tokens = valid_cap_;
        } else if (now > b.ms) {
            b.tokens = std::min(valid_cap_, b.tokens + static_cast<double>(now - b.ms) * valid_rate_ / 1000.0);
        }
        b.ms = now;
        return b;
    }
    double valid_left(std::uint64_t p) {
        std::lock_guard<std::mutex> lk(vmtx_);
        return valid_bucket_locked(p).tokens;
    }

    // What follows an admission outcome outside the node lock.
    struct Effects {
        bool join = false;
        std::set<Missing> rerun;                            // causes whose parked frames run again
        // (a Monero block, the peer that sent the object, the want's class: Carrier for a carrier, Receipt for a receipt)
        std::vector<std::tuple<Hash32, std::uint64_t, CtxClass>> ctx;
        std::vector<std::uint64_t> bans;                    // servers of refuted walked variants or body sets
        std::vector<std::string> bans_why;                  // one per entry of bans
        std::vector<std::uint64_t> strikes;                 // servers of walked body sets struck once
        std::vector<ParkedFrame> rx_retry;                  // frames whose admission failed with a RandomX failure
        std::vector<ParkedFrame> rx_rerun;                  // frames to run again after a counted RandomX failure
        std::vector<std::pair<std::uint64_t, std::uint64_t>> p15;  // released carriers placed: (peer, objects)
        std::vector<std::string> lines;                     // the STRIKE / REFUSE lines of the drained carriers
        std::vector<PathbNode::DrainedResult> penalties;    // the STRIKE and BAN verdicts of the drained carriers
    };
    // Under the node lock: the released carriers whose admission failed with a RandomX failure, to park; the carriers
    // the node placed on its own (a drain's released carriers, a bind's walked carriers), counted as received frames are,
    // and their STRIKE and BAN verdicts charged to their senders as a received frame's are (run_effects).
    void take_rx_failed_locked(Effects& fx) {
        for (ParkedFrame& f : node_->take_rx_failed()) fx.rx_retry.push_back(std::move(f));
        for (const PathbNode::PlacedRelease& c : node_->take_placed_released()) fx.p15.emplace_back(c.peer, c.objects);
        for (const PathbNode::DrainedResult& d : node_->take_drained()) {
            account_locked(d.peer, d.action, d.row, d.verdict, d.omitted, d.repended, d.lost);
            if (d.verdict == AdmitVerdict::Strike || d.verdict == AdmitVerdict::Refuse)
                fx.lines.push_back("relay: peer " + std::to_string(d.peer) +
                                   (d.verdict == AdmitVerdict::Strike ? " STRIKE: " : " REFUSE: ") +
                                   admission_text(d.row, d.object));
            if (d.peer != 0 && d.peer != PathbNode::kOwnPeer &&
                (d.verdict == AdmitVerdict::Strike || d.verdict == AdmitVerdict::Ban))
                fx.penalties.push_back(d);
        }
    }
    // After the node lock: a drained carrier's STRIKE costs its sender the verdict's tokens and its BAN bans the sender
    // with its reason, as for a received frame (apply_result). A sender whose link is gone by then: one line, nothing
    // applied.
    void apply_drained(const PathbNode::DrainedResult& d) {
        const bool ban_v = d.verdict == AdmitVerdict::Ban;
        const std::string why = "admission row R" + std::to_string(static_cast<int>(d.row)) + " of " + hex_short(d.object != Hash32{} ? d.object : d.id);
        if (!peer_known(d.peer)) {
            log("relay: peer " + std::to_string(d.peer) + " gone: drained " + (ban_v ? "BAN" : "STRIKE") +
                " not applied: " + why);
            return;
        }
        if (ban_v)
            ban(d.peer, why);
        else
            strike(d.peer, std::max<std::uint32_t>(d.strike, 1), false);
    }
    // Under the node lock: the counts of one admission outcome of a peer's object, a received frame's or a carrier's the
    // node placed on its own (drained or walk-bound): the verdict by row, the per-peer omission log, the line of a switch
    // by the journal.
    void account_locked(std::uint64_t peer, NodeAction action, RowId row, AdmitVerdict verdict, std::uint64_t omitted,
                        std::uint64_t repended, std::uint64_t lost) {
        const bool from_peer = peer != 0 && peer != PathbNode::kOwnPeer;
        if (from_peer && action != NodeAction::None && action != NodeAction::NodeInternal) {  // verdicts by row
            std::lock_guard<std::mutex> lk(omtx_);
            ++verdicts_[static_cast<std::size_t>(row)][static_cast<std::size_t>(verdict)];
        }
        if (omitted != 0 && from_peer) {  // the per-peer omission log (relay policy; erased at link down)
            {
                std::lock_guard<std::mutex> lk(omtx_);
                omissions_[peer] += omitted;
                omitted_total_ += omitted;
            }
            omission_gone(peer);
        }
        if (action == NodeAction::Switched) {
            const PathbNode::SwitchCounts& sc = node_->switch_counts();
            log("relay: switch by the journal: re-pended " + std::to_string(repended) + ", lost " + std::to_string(lost) +
                " (re-pended since start " + std::to_string(sc.repended) + ", carried " + std::to_string(sc.carried) +
                ", sealed pending " + std::to_string(sc.sealed_pending) + ")");
        }
    }
    // Under the node lock: the requests a DEFER names, sent to the object's sender (FC_GETHEADERS of t's branch,
    // FC_GETCARRIER of a walked carrier's bodies or of a carrier, FB_GETCTX, FC_GETBUCKETS), the walked branch of a
    // TipBodies DEFER bound and placed, the joiner's signal.
    // carrier: the object is a carrier (its Monero context climbs to P-07), else a receipt (P-06).
    // receipt: a DEFERred receipt this node parked (park_receipt_locked): indexed under its cause by its key; each peer
    // is asked for one cause and object at most once per parked receipt; a TipBodies bind runs on every re-run.
    void after_result_locked(std::uint64_t peer, const NodeEventResult& r, std::optional<Hash32> digest, Effects& fx,
                             bool relayed = true, bool carrier = true, std::optional<Hash32> receipt = std::nullopt) {
        if (relayed && r.admit.missing == Missing::ClaimAlarm) claim_charge(peer);
        account_locked(peer, r.action, r.admit.row, r.admit.verdict, r.omitted, r.repended, r.lost);
        switch (r.action) {
            case NodeAction::JoinerPath: fx.join = true; break;
            case NodeAction::Placed:
            case NodeAction::Switched:
                if (r.action == NodeAction::Switched && node_->reask_pending()) {
                    reask_due_ = true;  // a joined store (its session or a restart): the claimed leaves asked again
                    fx.join = true;
                }
                if (bucket_stalled_) {  // every peer was closed for the named carrier: a later carrier of the chain
                    bucket_stalled_ = false;
                    fx.rerun.insert(Missing::MissingBucket);
                }
                // a placed carrier may be the tip, a walked carrier or a reference a parked frame waits on
                for (const Missing m : {Missing::TipUnknown, Missing::TipHeaders, Missing::TipBodies, Missing::ClosureBodies,
                                        Missing::Bodies, Missing::MissingRef})
                    if (!parked_by_cause_[m].empty()) fx.rerun.insert(m);
                break;
            default: break;
        }
        if (r.action != NodeAction::Parked || !r.admit.missing) return;
        const Missing m = *r.admit.missing;
        const std::optional<Hash32> d =
                digest ? std::optional<Hash32>(r.admit.digest != Hash32{} ? r.admit.digest : *digest) : std::nullopt;
        if (d && rerun_cause(m)) index_parked_locked(m, r.admit.fetch, *d);
        std::set<std::tuple<std::uint64_t, Missing, Hash32>>* asked = nullptr;
        bool kept = true;
        if (receipt) {
            const auto it = parked_receipts_.find(*receipt);
            kept = it != parked_receipts_.end();  // not kept (over the cap at once): nothing asked for it
            if (kept) {
                index_parked_locked(m, r.admit.fetch, *receipt);
                asked = &it->second.second.asked;
            }
        }
        // a parked receipt asks each peer for one cause and object at most once; its TipBodies bind runs every time;
        // a gone link (a re-run of a receipt it sent) is neither asked nor recorded
        const bool gone = asked != nullptr && !peer_known(peer);
        const auto may = [&](const Hash32& object) {
            return kept && !gone && (asked == nullptr || asked->emplace(peer, m, object).second);
        };
        switch (m) {
            case Missing::TipUnknown:
            case Missing::TipHeaders:
                if (may(r.admit.fetch)) request_tip_headers(peer, r.admit.fetch_from, r.admit.fetch, d, receipt ? receipt : d);
                break;
            case Missing::ClosureBodies:
                if (may(r.admit.fetch)) request_body_set(peer, r.admit.fetch, d);
                break;
            case Missing::Bodies:
                if (may(r.admit.fetch)) request_carrier(peer, r.admit.fetch);
                break;
            case Missing::TipBodies: {
                const PathbNode::WalkBind wb = node_->bind_walked_branch(r.admit.bind);
                if (wb.rx_failed) {
                    // node-internal (the walk stopped at a RandomX failure; what it found stays): the alarm; the
                    // parked frame runs again after kParkRetryMs (no token)
                    rx_alarm("walked carrier");
                    if (d) {
                        parked_by_cause_[m].erase(*d);
                        if (std::optional<ParkedFrame> f = node_->take_parked(*d)) fx.rx_rerun.push_back(std::move(*f));
                    }
                }
                st_.walk_placed += wb.placed.size();
                fx.bans.insert(fx.bans.end(), wb.banned.begin(), wb.banned.end());
                fx.bans_why.insert(fx.bans_why.end(), wb.banned_why.begin(), wb.banned_why.end());
                fx.bans_why.resize(fx.bans.size());
                fx.strikes.insert(fx.strikes.end(), wb.struck.begin(), wb.struck.end());
                if (!wb.need_bodies.empty() && (!d || node_->may_ask(*d, peer)))
                    for (const Hash32& id : wb.need_bodies)
                        if (may(id)) request_body_set(peer, id, std::nullopt);
                if (!wb.placed.empty()) fx.rerun.insert(Missing::TipBodies);
                break;
            }
            case Missing::MoneroBlock:
            case Missing::MissingBlock:
            case Missing::MissingWeights:
                if (r.admit.fetch == Hash32{}) break;
                if (m == Missing::MissingWeights && node_->monero_block_held(r.admit.fetch)) {
                    st_.ctx_held++;  // the block is held: a context brings no weights (the frame waits for its input)
                    break;
                }
                if (may(r.admit.fetch)) fx.ctx.emplace_back(r.admit.fetch, peer, carrier ? CtxClass::Carrier : CtxClass::Receipt);
                break;
            case Missing::MissingBucket:
                if (may(r.admit.fetch)) bucket_fetch(r.admit.fetch, r.admit.fetch_bin, peer);
                break;
            default: break;  // ParentUnknown: the node's own FC_GETCARRIER; MissingRef: a served bucket's references
        }
        take_rx_failed_locked(fx);
    }
    // A DEFER on a Monero input: indexed by (cause, id), run again when that input is held.
    static bool ctx_cause(Missing m) {
        return m == Missing::MoneroBlock || m == Missing::MissingBlock || m == Missing::MissingWeights || m == Missing::Seed;
    }
    // Under the node lock: a parked digest indexed for its re-run (a Monero input by (cause, id), else by cause). Past
    // the deferred store's cap (J_0) of digests indexed since the last prune, the index is pruned: it holds at most the
    // objects that wait (the frames the store holds, the parked receipts) and J_0 more.
    void index_parked_locked(Missing m, const Hash32& fetch, const Hash32& d) {
        if (ctx_cause(m) && fetch != Hash32{})
            parked_ctx_[std::make_pair(m, fetch)].insert(d);
        else
            parked_by_cause_[m].insert(d);
        if (++index_adds_ >= node_->deferred_cap()) prune_parked_index_locked();
    }
    // Under the node lock: a digest whose object no longer waits (its frame left the deferred store: an eviction past
    // J_0, a purge, a release or a take; not a parked receipt) leaves the index, and an emptied key with it. A peer's
    // disconnect drops no frame (forget_peer clears its ask records only).
    void prune_parked_index_locked() {
        index_adds_ = 0;
        const auto gone = [this](const Hash32& d) { return !node_->parked_held(d) && parked_receipts_.count(d) == 0; };
        for (auto it = parked_ctx_.begin(); it != parked_ctx_.end();) {
            for (auto d = it->second.begin(); d != it->second.end();) d = gone(*d) ? it->second.erase(d) : std::next(d);
            it = it->second.empty() ? parked_ctx_.erase(it) : std::next(it);
        }
        for (auto& [cause, ds] : parked_by_cause_)
            for (auto d = ds.begin(); d != ds.end();) d = gone(*d) ? ds.erase(d) : std::next(d);
        st_.parked_index_pruned++;
    }
    static bool rerun_cause(Missing m) {
        switch (m) {
            case Missing::TipUnknown:
            case Missing::TipHeaders:
            case Missing::ClosureBodies:
            case Missing::Bodies:
            case Missing::TipBodies:
            case Missing::MoneroBlock:
            case Missing::MissingBlock:
            case Missing::MissingWeights:
            case Missing::MissingBucket:
            case Missing::MissingRef:
            case Missing::Seed: return true;
            default: return false;
        }
    }
    // FC_GETHEADERS of t's branch to the sender (one in flight per peer: else it waits in the peer's queue): from c's
    // chain at pos(parent(c)) - J_0 (the admission's fetch_from; with none, the best chain at pos(best) - J_0) to t.
    // `object`: the parked frame (digest) or receipt (key) waiting on it.
    void request_tip_headers(std::uint64_t peer, Hash32 from, const Hash32& stop, const std::optional<Hash32>& digest,
                             const std::optional<Hash32>& object = std::nullopt) {
        if (peer == PathbNode::kOwnPeer || !hello_ok(peer)) return;
        if (digest && !node_->may_ask(*digest, peer)) return;
        if (from == Hash32{}) {
            const CarrierNode& b = node_->tree().best();
            const std::uint64_t j0 = admit_j0(p_);
            from = node_->store().best_at(b.pos > j0 ? b.pos - j0 : 0).value_or(b.id);
        }
        if (node_->tree().find(from) == nullptr) return;
        TipObjects objs;
        if (object) objs.add(*object);
        std::lock_guard<std::mutex> lk(cumtx_);
        want_headers_locked(peer, PathbNode::HeaderOwner::Tip, from, stop, objs);
    }
    // Under the node lock: a parked frame (digest) or receipt (key) still waits.
    bool object_waits_locked(const Hash32& o) const { return node_->parked_held(o) || parked_receipts_.count(o) != 0; }
    // Under the node lock: an entry tied to objects none of which still waits (an entry with none is not tied).
    template <class E>
    bool objects_gone_locked(const E& e) const {
        if (!e.objs.tied) return false;
        for (const Hash32& o : e.objs.order)
            if (object_waits_locked(o)) return false;
        return true;
    }
    // Under the node lock: the objects of `t` that no longer wait leave, the oldest first while they are gone, and all
    // of them when more remain than the node holds parked (its deferred frames and parked receipts).
    void prune_objects_locked(TipObjects& t) const {
        while (!t.order.empty() && !object_waits_locked(t.order.front())) {
            t.ids.erase(t.order.front());
            t.order.pop_front();
        }
        if (t.ids.size() <= node_->deferred().size() + parked_receipts_.size()) return;
        std::deque<Hash32> keep;
        for (const Hash32& o : t.order)
            if (object_waits_locked(o))
                keep.push_back(o);
            else
                t.ids.erase(o);
        t.order.swap(keep);
    }
    // Under the node lock and cumtx_: room for one more tip-header entry of a peer (its waiting requests or its
    // deferrals): at P-47 (the deferred store's cap) the tip entries whose objects no longer wait leave, then the
    // oldest tip entry; the catch-up's entry stays.
    template <class C>
    void tip_room_locked(C& v) {
        const auto tip = [](const auto& e) { return e.owner == PathbNode::HeaderOwner::Tip; };
        const std::size_t bound = static_cast<std::size_t>(std::max<std::uint64_t>(node_->deferred_cap(), 1));
        if (static_cast<std::size_t>(std::count_if(v.begin(), v.end(), tip)) < bound) return;
        const auto gone = std::remove_if(v.begin(), v.end(), [&](const auto& e) { return tip(e) && objects_gone_locked(e); });
        st_.header_wants_reclaimed += static_cast<std::uint64_t>(std::distance(gone, v.end()));
        v.erase(gone, v.end());
        while (static_cast<std::size_t>(std::count_if(v.begin(), v.end(), tip)) >= bound) {
            const auto oldest = std::find_if(v.begin(), v.end(), tip);
            if (oldest == v.end()) break;
            v.erase(oldest);
            st_.header_wants_dropped++;
        }
    }
    // Under the node lock and cumtx_: a header request of `owner` to `peer` for `objs`. An equal request (owner, from,
    // stop) open or waiting takes it (merged, its objects added); else it waits in the peer's queue (the catch-up keeps
    // only its latest; the tip requests within the peer's bound; no other request's entry replaced), served oldest
    // first while the peer's slot is free. True: sent now.
    bool want_headers_locked(std::uint64_t peer, PathbNode::HeaderOwner owner, const Hash32& from, const Hash32& stop) {
        return want_headers_locked(peer, owner, from, stop, TipObjects{});
    }
    bool want_headers_locked(std::uint64_t peer, PathbNode::HeaderOwner owner, const Hash32& from, const Hash32& stop,
                             const TipObjects& objs) {
        const std::optional<PathbNode::HeaderSlot> s = node_->header_slot(peer);
        if (s && !s->retired && s->owner == owner && s->from == from && s->stop == stop) {
            st_.header_wants_merged++;
            const auto sent = hdr_sent_.find(peer);
            if (sent != hdr_sent_.end() && sent->second.from == from && sent->second.stop == stop) {
                sent->second.objs.add(objs);
                prune_objects_locked(sent->second.objs);
            }
            return false;
        }
        std::deque<HdrWant>& q = header_wants_[peer];
        for (HdrWant& w : q)
            if (w.owner == owner && w.from == from && w.stop == stop) {
                st_.header_wants_merged++;
                w.objs.add(objs);
                prune_objects_locked(w.objs);
                return false;
            }
        if (owner == PathbNode::HeaderOwner::CatchUp)
            q.erase(std::remove_if(q.begin(), q.end(), [](const HdrWant& w) { return w.owner == PathbNode::HeaderOwner::CatchUp; }),
                    q.end());
        else
            tip_room_locked(q);
        q.push_back(HdrWant{owner, from, stop, objs});
        serve_header_wants_locked(peer);
        const auto it = header_wants_.find(peer);
        if (it == header_wants_.end()) return true;
        for (const HdrWant& w : it->second)
            if (w.owner == owner && w.from == from && w.stop == stop) return false;
        return true;
    }
    // Under the node lock and cumtx_: the waiting header requests of `peer` (every peer: 0), the oldest first, while
    // its slot is free (one in flight per peer).
    void serve_header_wants_locked(std::uint64_t only) {
        for (auto it = header_wants_.begin(); it != header_wants_.end();) {
            if (only != 0 && it->first != only) {
                ++it;
                continue;
            }
            std::deque<HdrWant>& q = it->second;
            while (!q.empty()) {
                const HdrWant& w = q.front();
                if (!hello_ok(it->first) || node_->tree().find(w.from) == nullptr) {
                    q.pop_front();
                    continue;
                }
                if (!node_->request_headers(it->first, w.from, w.stop, header_max_, now_s(), w.owner)) break;
                if (w.owner == PathbNode::HeaderOwner::Tip) {
                    st_.tip_header_requests++;
                    hdr_sent_[it->first] = HdrSent{w.from, w.stop, w.objs};
                } else {
                    hdr_sent_.erase(it->first);
                }
                q.pop_front();
                break;  // one in flight per peer
            }
            it = q.empty() ? header_wants_.erase(it) : std::next(it);
        }
    }
    // FC_GETCARRIER (want_bodies 1) of a walked carrier to the sender: its reply is that peer's body set.
    void request_body_set(std::uint64_t peer, const Hash32& id, const std::optional<Hash32>& digest) {
        if (peer == PathbNode::kOwnPeer || !hello_ok(peer)) return;
        if (digest && !node_->may_ask(*digest, peer)) return;
        GetCarrier q;
        q.chain_id = chain_id_;
        q.ids = {id};
        q.want_bodies = true;
        const std::optional<std::vector<std::uint8_t>> f = encode_fc_getcarrier(q, p_);
        if (!f) return;
        {
            std::lock_guard<std::mutex> lk(kmtx_);
            std::set<Hash32>& a = bodyset_asked_[peer];
            if (a.size() >= kAskedMax) a.clear();
            a.insert(id);
        }
        if (send_link(peer, *f)) st_.body_set_requests++;
    }
    // FC_GETCARRIER (want_bodies 1) of a carrier to the sender: its reply is admitted as a frame.
    void request_carrier(std::uint64_t peer, const Hash32& id) {
        if (peer == PathbNode::kOwnPeer || !hello_ok(peer)) return;
        GetCarrier q;
        q.chain_id = chain_id_;
        q.ids = {id};
        q.want_bodies = true;
        if (const std::optional<std::vector<std::uint8_t>> f = encode_fc_getcarrier(q, p_)) node_send(peer, *f);
    }
    // The text of an admission line: its row and the id of the body it names.
    static std::string admission_text(RowId row, const Hash32& id) {
        return "admission row R" + std::to_string(static_cast<int>(row)) + " of " + hex_short(id);
    }
    // The tokens of an outcome; true: the job's token is kept (STRIKE or BAN). A STRIKE, REFUSE or BAN logs its row and
    // the id of the body it names.
    bool apply_result(std::uint64_t peer, const NodeEventResult& r, bool token_taken) {
        for (const auto& [q, n] : r.admit.peer_tokens) strike(q, n, false);
        const auto named = [&]() { return admission_text(r.admit.row, r.admit.id != Hash32{} ? r.admit.id : r.object); };
        switch (r.admit.verdict) {
            case AdmitVerdict::Strike:
                log("relay: peer " + std::to_string(peer) + " STRIKE: " + named());
                strike(peer, std::max<std::uint32_t>(r.admit.strike, 1), token_taken);
                return true;
            case AdmitVerdict::Ban: ban(peer, named()); return true;
            case AdmitVerdict::Refuse: log("relay: peer " + std::to_string(peer) + " REFUSE: " + named()); return false;
            case AdmitVerdict::Drop: st_.drops++; return false;
            default: return false;
        }
    }
    void run_effects(Effects& fx) {
        for (const std::string& l : fx.lines) log(l);  // after the node lock
        fx.lines.clear();
        for (ParkedFrame& f : fx.rx_retry) {  // parked and run again (no token)
            rx_alarm("released carrier");
            park_job(Job{Job::Kind::Carrier, f.peer, src_of(f.peer), std::move(f.frame), 0, f.solicited, true},
                     now_ms() + kParkRetryMs);
        }
        for (ParkedFrame& f : fx.rx_rerun)
            park_job(Job{Job::Kind::Carrier, f.peer, src_of(f.peer), std::move(f.frame), 0, f.solicited, true},
                     now_ms() + kParkRetryMs);
        for (const auto& [peer, n] : fx.p15) valid_count(peer, n);  // a released carrier's first placement (P-15)
        fx.rx_retry.clear();
        fx.rx_rerun.clear();
        fx.p15.clear();
        for (const PathbNode::DrainedResult& d : fx.penalties) apply_drained(d);
        fx.penalties.clear();
        for (std::size_t i = 0; i < fx.bans.size(); ++i) ban(fx.bans[i], i < fx.bans_why.size() ? fx.bans_why[i] : std::string());
        for (std::uint64_t q : fx.strikes) strike(q, 1, false);
        for (const auto& [id, from, cls] : fx.ctx) want_ctx(id, from, 0, cls);
        if (!fx.rerun.empty()) rerun_parked(std::vector<Missing>(fx.rerun.begin(), fx.rerun.end()));
        if (fx.join) signal_join();
        repend_offer();
    }
    // FC_GETBUCKETS at the named carrier (one assembly per (peer, at)): the object's sender first, then every other
    // ready peer; none: a later carrier of the same chain (the parked frames run again when the best tip moves).
    void bucket_fetch(const Hash32& at, std::uint64_t bin, std::uint64_t prefer) {
        std::vector<std::uint64_t> order;
        const std::vector<std::uint64_t> ready = ready_peers();
        if (std::find(ready.begin(), ready.end(), prefer) != ready.end()) order.push_back(prefer);
        for (std::uint64_t q : ready)
            if (q != prefer) order.push_back(q);
        for (std::uint64_t q : order)
            if (node_->request_buckets(q, at, bin, bin, now_s())) {
                st_.bucket_requests++;
                return;
            }
        bucket_stalled_ = true;
    }
    // The frames parked for these causes, and those marked for a re-walk, run again (each a new job of its sender).
    // A parked receipt whose cause resolved is due; the due receipts run again, the oldest first, at most the verify
    // queue's free room at a time (no queued job dropped for them); the rest stay parked and due for the next tick.
    // A Monero input's cause: every (cause, id) key runs again whatever the input (the KAT hook; the follower's events
    // and a resolved context take rerun_ready_ctx).
    void rerun_parked(const std::vector<Missing>& causes) {
        std::vector<Hash32> ds;
        {
            const NodeGuard g(*this);
            for (const Missing cause : causes) {
                std::set<Hash32> s;
                s.swap(parked_by_cause_[cause]);
                ds.insert(ds.end(), s.begin(), s.end());
                if (!ctx_cause(cause)) continue;
                for (auto it = parked_ctx_.begin(); it != parked_ctx_.end();) {
                    if (it->first.first != cause) {
                        ++it;
                        continue;
                    }
                    ds.insert(ds.end(), it->second.begin(), it->second.end());
                    it = parked_ctx_.erase(it);
                }
            }
        }
        rerun_digests(ds, true);
        if (std::find(causes.begin(), causes.end(), Missing::MoneroBlock) != causes.end()) reask_headers_on_ctx(std::nullopt, false);
    }
    // The frames parked on a Monero input (cause, id) whose input the follower holds now run again: every key, or the
    // keys of `only` (a context of that id resolved). The header requests deferred on a P_r follow their input. A key
    // whose input is not held stays parked (no re-run, no new context).
    void rerun_ready_ctx(const std::optional<Hash32>& only) {
        std::vector<Hash32> ds;
        std::size_t released = 0;
        {
            const NodeGuard g(*this);
            for (auto it = parked_ctx_.begin(); it != parked_ctx_.end();) {
                const auto& [cause, id] = it->first;
                if ((only && id != *only) || !node_->monero_input_held(cause, id)) {
                    ++it;
                    continue;
                }
                ds.insert(ds.end(), it->second.begin(), it->second.end());
                it = parked_ctx_.erase(it);
            }
            // the join pairs waiting on a Monero input held now (a P_r resolved, a held block's weights recorded) are
            // tried again
            for (const auto& [cause, id] : node_->join_waits())
                if ((!only || id == *only) && node_->monero_input_held(cause, id))
                    released += node_->release_join_waits(id, cause);
        }
        rerun_digests(ds, false);
        reask_headers_on_ctx(only, true);
        if (released > 0) {
            st_.join_releases += released;
            signal_join();
        }
    }
    // The parked digests run again (each a new job of its sender; a parked receipt is due), with the frames marked for a
    // re-walk when `rewalk`.
    void rerun_digests(const std::vector<Hash32>& ds, bool rewalk) {
        std::vector<ParkedFrame> again;
        std::vector<Job> again_receipts;
        std::size_t rewalked = 0;
        std::size_t room = verify_room();
        {
            const NodeGuard g(*this);
            for (const Hash32& d : ds) {
                if (std::optional<ParkedFrame> f = node_->take_parked(d)) {
                    again.push_back(std::move(*f));
                } else {
                    const auto it = parked_receipts_.find(d);
                    if (it != parked_receipts_.end()) receipt_due_[it->second.first] = d;
                }
            }
            if (rewalk) {
                std::vector<ParkedFrame> rw = node_->take_rewalk_frames();
                rewalked = rw.size();
                for (ParkedFrame& f : rw) again.push_back(std::move(f));
            }
            room = room > again.size() ? room - again.size() : 0;
            take_due_receipts_locked(room, again_receipts);
        }
        st_.rewalks += rewalked;
        for (ParkedFrame& f : again) {
            st_.parked_reruns++;
            enqueue_job(Job{Job::Kind::Carrier, f.peer, src_of(f.peer), std::move(f.frame), 0, f.solicited, true});
        }
        for (Job& j : again_receipts) {
            st_.parked_reruns++;
            enqueue_job(std::move(j));
        }
    }
    // The due receipts left by a re-run (the tick): the next ones, at most the verify queue's free room.
    void rerun_due_receipts() {
        std::vector<Job> again_receipts;
        const std::size_t room = verify_room();
        {
            const NodeGuard g(*this);
            if (receipt_due_.empty()) return;
            take_due_receipts_locked(room, again_receipts);
        }
        for (Job& j : again_receipts) {
            st_.parked_reruns++;
            enqueue_job(std::move(j));
        }
    }
    std::size_t verify_room() const {
        std::lock_guard<std::mutex> lk(vmtx_);
        return vq_.size() < o_.verify_queue_max ? o_.verify_queue_max - vq_.size() : 0;
    }
    // ---- DEFERred receipts (SPEC DEFER: parked, run again when the missing data arrive) ----
    // A parked receipt's key: its one-body frame's digest (the park, its asks, its index and its due entry).
    static Hash32 receipt_key(const std::vector<std::uint8_t>& frame) { return ::v37::sha256d(frame); }
    // Under the node lock: the one-body FB_RECEIPTS job of a DEFERred receipt kept by its key with its asks (run again
    // as a re-run: the sender's RandomX token taken and given back like any job's, no P-15 gate at its arrival, P-15
    // counted at its first admission), at most the pending set's cap (P-09; a first-in-first-out store of its own,
    // not the pending set's overflow order): over it the oldest goes, with its asks. The same receipt parked again
    // keeps the asks made for it.
    void park_receipt_locked(const Hash32& key, std::set<std::tuple<std::uint64_t, Missing, Hash32>> asked, const Job& j) {
        const auto it = parked_receipts_.find(key);
        if (it != parked_receipts_.end()) {
            asked.insert(it->second.second.asked.begin(), it->second.second.asked.end());
            parked_receipt_order_.erase(it->second.first);
            receipt_due_.erase(it->second.first);
        }
        Job k{j.kind, j.peer, j.src, j.frame, 0, j.solicited, true, std::move(asked), receipt_origin_locked(j.frame)};
        const std::uint64_t seq = ++parked_receipt_seq_;
        parked_receipts_[key] = std::make_pair(seq, std::move(k));
        parked_receipt_order_[seq] = key;
        st_.receipts_parked++;
        const std::uint64_t cap = node_->pending_cap();
        while (parked_receipts_.size() > cap && !parked_receipt_order_.empty()) {
            const auto [old_seq, old] = *parked_receipt_order_.begin();
            parked_receipt_order_.erase(parked_receipt_order_.begin());
            receipt_due_.erase(old_seq);
            parked_receipts_.erase(old);
            unindex_receipt_locked(old);
            st_.parked_receipt_drops++;
        }
    }
    // Under the node lock: a parked receipt out of the park with its asks (they leave with the job).
    std::optional<Job> take_parked_receipt_locked(const Hash32& key) {
        const auto it = parked_receipts_.find(key);
        if (it == parked_receipts_.end()) return std::nullopt;
        Job j = std::move(it->second.second);
        parked_receipt_order_.erase(it->second.first);
        receipt_due_.erase(it->second.first);
        parked_receipts_.erase(it);
        unindex_receipt_locked(key);
        return j;
    }
    // Under the node lock: the origin height of a one-body FB_RECEIPTS frame's receipt by its own P_r, held with or
    // without its weights (0: not known).
    std::uint64_t receipt_origin_locked(const std::vector<std::uint8_t>& frame) const {
        const std::size_t at = kFrameHeaderBytes + 1;
        if (frame.size() <= at) return 0;
        ReceiptBodyV3 r;
        if (decode_receipt_body_v3(frame.data() + at, frame.size() - at, ReceiptLimits{buffers_.receipt}, r) != WireError::None)
            return 0;
        return node_->held_origin(r.blob.prev_id).value_or(0);
    }
    // SPEC DEFER: a parked receipt is dropped without strike when its origin bin seals on the best chain (with its asks
    // and index entries); once per move of the best chain's record H(L) (the tick).
    void sweep_sealed_receipts() {
        const NodeGuard g(*this);
        if (parked_receipts_.empty()) return;
        const std::optional<std::uint64_t> H = node_->best_record();
        if (!H || *H == swept_record_) return;
        swept_record_ = *H;
        std::vector<Hash32> sealed;
        for (const auto& [key, e] : parked_receipts_)
            if (e.second.origin_h != 0 && !open_at(*H, e.second.origin_h, p_.open_bins)) sealed.push_back(key);
        for (const Hash32& key : sealed) {
            (void)take_parked_receipt_locked(key);
            st_.parked_receipts_sealed++;
        }
    }
    void unindex_receipt_locked(const Hash32& key) {
        for (auto& [cause, ds] : parked_by_cause_) ds.erase(key);
        for (auto it = parked_ctx_.begin(); it != parked_ctx_.end();) {
            it->second.erase(key);
            it = it->second.empty() ? parked_ctx_.erase(it) : std::next(it);
        }
    }
    // SPEC DEFER for parked carrier frames: a frame indexed for a re-run is dropped without strike when the origin bin
    // of its OWN receipt (its body's own P_r, held with or without its weights: h = height + 1) seals on the best chain;
    // a frame whose own P_r is not held stays (the deferred store's cap bounds it). Once per move of H(L) (the tick).
    void sweep_sealed_frames() {
        const NodeGuard g(*this);
        const std::optional<std::uint64_t> H = node_->best_record();
        if (!H || *H == swept_frames_record_) return;
        swept_frames_record_ = *H;
        std::set<std::pair<Hash32, Hash32>> ds;  // (digest, the DEFER's id: zero for a cause with no Monero input)
        for (const auto& [key, s] : parked_ctx_)
            for (const Hash32& d : s) ds.emplace(d, key.second);
        for (const auto& [cause, s] : parked_by_cause_)
            for (const Hash32& d : s) ds.emplace(d, Hash32{});
        for (const auto& [d, id] : ds) {
            // the object's OWN P_r keys its bin; the DEFER's id (a carried receipt's or a walked body's P_r) does not
            const std::optional<Hash32> own = node_->parked_own_pr(d);
            if (!own) continue;
            const std::optional<std::uint64_t> h = node_->held_origin(*own);
            if (!h || open_at(*H, *h, p_.open_bins)) continue;
            if (node_->take_parked(d)) st_.parked_frames_sealed++;
            unindex_receipt_locked(d);
        }
    }
    void take_due_receipts_locked(std::size_t room, std::vector<Job>& out) {
        while (out.size() < room && !receipt_due_.empty()) {
            const auto [seq, key] = *receipt_due_.begin();
            receipt_due_.erase(receipt_due_.begin());
            const auto it = parked_receipts_.find(key);
            if (it == parked_receipts_.end() || it->second.first != seq) continue;
            if (std::optional<Job> j = take_parked_receipt_locked(key)) out.push_back(std::move(*j));
        }
    }
    void rerun_parked(Missing cause) { rerun_parked(std::vector<Missing>{cause}); }

    // ---- the node's sends ----
    void node_send(std::uint64_t peer, const std::vector<std::uint8_t>& f) {
        if (!f.empty() && f[0] == kOpFcGetHeaders) {
            std::lock_guard<std::mutex> lk(kmtx_);
            hdr_fifo_[peer].push_back(HdrWait{true, 0, false});
        }
        if (!f.empty() && f[0] == kOpFcGetCarrier) {  // its reply frames are solicited
            GetCarrier q;
            if (decode_fc_getcarrier(f, chain_id_, p_, q).ok()) {
                std::lock_guard<std::mutex> lk(kmtx_);
                std::set<Hash32>& a = asked_carriers_[peer];
                if (a.size() + q.ids.size() > kAskedMax) a.clear();  // a peer that does not answer: bounded
                a.insert(q.ids.begin(), q.ids.end());
            }
        }
        (void)send_link(peer, f);
    }
    // An FC_CARRIER of `peer` that answers this node's own request: a body set it asked for, or a carrier.
    enum class CarrierReply : std::uint8_t { None, Solicited, BodySet };
    CarrierReply carrier_reply(std::uint64_t peer, const std::vector<std::uint8_t>& f) {
        {
            std::lock_guard<std::mutex> lk(kmtx_);
            const auto a = asked_carriers_.find(peer);
            const auto b = bodyset_asked_.find(peer);
            if ((a == asked_carriers_.end() || a->second.empty()) && (b == bodyset_asked_.end() || b->second.empty()))
                return CarrierReply::None;
        }
        CarrierBodyV3 c;
        if (!check_fc_carrier(f, chain_id_, buffers_).ok()
            || decode_carrier_body_v3(f.data() + kFrameHeaderBytes, f.size() - kFrameHeaderBytes,
                                      CarrierLimits{buffers_.receipt, p_.r_max}, c)
                       != WireError::None)
            return CarrierReply::None;
        const Hash32 id = receipt_id(c.own);
        std::lock_guard<std::mutex> lk(kmtx_);
        if (const auto b = bodyset_asked_.find(peer); b != bodyset_asked_.end() && b->second.erase(id) != 0)
            return CarrierReply::BodySet;
        if (const auto a = asked_carriers_.find(peer); a != asked_carriers_.end() && a->second.erase(id) != 0)
            return CarrierReply::Solicited;
        return CarrierReply::None;
    }
    // A walked carrier's body set from `peer`: the parked frames that need it run again.
    void handle_body_set(std::uint64_t p, const std::vector<std::uint8_t>& f) {
        bool ok = false;
        {
            const NodeGuard g(*this);
            ok = node_->on_body_set(p, f);
        }
        if (!ok) return;
        st_.body_sets++;
        rerun_parked(std::vector<Missing>{Missing::ClosureBodies, Missing::TipBodies});
    }
    // Relay policy: every HELLO-ok link but the sender's.
    void node_flood(const std::vector<std::uint8_t>& f, std::optional<std::uint64_t> except) {
        for (std::uint64_t p : ready_peers()) {
            if (except && *except == p) continue;
            if (send_link(p, f)) st_.flood_frames++;
        }
    }

    // ---- HELLO ----
    void send_our_hello(std::uint64_t p) {
        PathbHello ours;
        {
            const NodeGuard g(*this);
            ours = node_->our_hello(nonce_, links_.listen_port());
        }
        send_hello(p, ours);
    }
    void send_hello(std::uint64_t p, const PathbHello& ours) {
        const std::optional<std::vector<std::uint8_t>> f = encode_pathb_hello(ours);
        if (!f || !send_link(p, *f)) return;
        st_.hello_sent++;
        std::lock_guard<std::mutex> lk(pmtx_);
        const auto it = peers_.find(p);
        if (it != peers_.end()) it->second.hello_sent = true;
    }
    void handle_hello(std::uint64_t p, const std::vector<std::uint8_t>& f, const HelloLink& link) {
        PathbHello ours;
        HelloCheck c;
        bool join = false;
        {
            const NodeGuard g(*this);
            ours = node_->our_hello(nonce_, links_.listen_port());
            c = node_->on_hello(p, f, ours);
            join = node_->joiner().queue().ready() > 0;
        }
        if (join) signal_join();
        const PathbHelloDecode d = decode_pathb_hello(f);
        if (c.verdict != HelloVerdict::Accept || d.error != HelloError::None) {
            hello_refused(p, f, c, d, link);
            return;
        }
        bool first = false, need_send = false;
        {
            std::lock_guard<std::mutex> lk(pmtx_);
            const auto it = peers_.find(p);
            if (it == peers_.end()) return;
            first = !it->second.hello_ok;
            it->second.hello_ok = true;
            it->second.remote_nonce = d.hello.node_nonce;
            it->second.remote_listen = d.hello.listen_port;
            need_send = !it->second.hello_sent;
            it->second.hello_sent = true;
        }
        if (need_send) send_hello(p, ours);
        if (!first) return;
        st_.hello_ok++;
        {
            std::lock_guard<std::mutex> lk(tmtx_);
            for (Target& t : targets_)
                if (t.pid == p) {
                    t.hello_seen = true;
                    t.prehello_fails = 0;
                }
        }
        log("relay: peer " + std::to_string(p) + " HELLO ok (listen=" + std::to_string(d.hello.listen_port) + ")");
        if (o_.discovery && !disc_hello_ok(p, d.hello.node_nonce, d.hello.listen_port)) return;
        after_hello(p, d.hello.tail);
    }
    // A HELLO the node refuses (TAG_MISMATCH, LANE_RULES_MISMATCH, K22 (frame version 0x01 or codec 1), malformed),
    // closes (mmr_leaf_count) or names this node: the link closed, no strike.
    void hello_refused(std::uint64_t p, const std::vector<std::uint8_t>& f, const HelloCheck& c, const PathbHelloDecode& d,
                       const HelloLink& link) {
        const bool self = c.verdict == HelloVerdict::SelfConnection;
        if (c.verdict == HelloVerdict::Close) {
            st_.hello_closed++;
        } else if (!self) {
            st_.hello_rejected++;
            if (c.reason == HelloReason::K22 && f.size() > 1 && f[1] != kHelloFrameVersion) st_.hello_old_version++;
            if (c.reason == HelloReason::Network || c.reason == HelloReason::ChainId || c.reason == HelloReason::PoolId)
                st_.hello_tag_mismatch++;
            if (c.reason == HelloReason::LaneRules) st_.hello_rules_mismatch++;
        }
        log("relay: peer " + std::to_string(p) + " HELLO REFUSED: " + c.text + " -> drop");
        if (self) {
            st_.self_conn++;
            on_self_hello(p, link);
        }
        if (o_.discovery) disc_refused(c.text, self, d.error == HelloError::None ? d.hello.listen_port : 0, link);
        defer_drop(p, src_of(p), false);
    }
    // A HELLO whose link went down before it ran: only a self-connection verdict is applied (the dial target behind
    // the link, the book); nothing of the gone link is kept.
    void hello_gone(std::uint64_t p, const std::vector<std::uint8_t>& f, const HelloLink& link) {
        PathbHello ours;
        {
            const NodeGuard g(*this);
            ours = node_->our_hello(nonce_, links_.listen_port());
        }
        PathbHello theirs;
        const HelloCheck c = pathb_hello_receive(
                ours, f, [](const Hash32&) -> std::optional<std::uint64_t> { return std::nullopt; }, 0, 0, &theirs);
        if (c.verdict != HelloVerdict::SelfConnection) return;
        st_.self_conn++;
        log("relay: peer " + std::to_string(p) + " HELLO REFUSED (link gone): " + c.text);
        on_self_hello(p, link);
        if (o_.discovery) disc_refused(c.text, true, theirs.listen_port, link);
    }
    // After an accepted HELLO: headers first when the peer's HELLO tip is not held, then the pending re-offer (the ids
    // taken under the node lock; the frames paged by reoffer_pump).
    void after_hello(std::uint64_t p, const HelloTail& tail) {
        std::vector<Hash32> ids;
        std::size_t cap = 0;
        {
            const NodeGuard g(*this);
            if (node_->rests_on_claims() || node_->poisoned()) return;
            catchup_start(p, tail);
            for (const PendingReceipt* r : node_->pending().all()) ids.push_back(r->id);
            cap = static_cast<std::size_t>(node_->pending_cap());
        }
        {
            std::lock_guard<std::mutex> lk(rmtx_);
            reoffer_[p] = ReofferQueue{};
            reoffer_append_locked(p, ids, cap);
            reoffer_t0_[p] = now_ms();
        }
        reoffer_pump(p);
    }
    // The re-offer of one peer, paged: a frame is queued only while the link's queued bytes with it (and its u32 length
    // prefix) stay within the link's bound less one FC_HEADERS frame with its prefix (P-14: room for a serve reply
    // and live traffic);
    // the rest waits for the queue to drain (the maintenance tick). Bodies no longer pending are skipped. One pump per
    // peer at a time (HELLO and the tick).
    void reoffer_pump(std::uint64_t p) {
        {
            std::lock_guard<std::mutex> lk(rmtx_);
            if (reoffer_.count(p) == 0 || !pumping_.insert(p).second) return;
        }
        struct Done {
            PathbRelayNode* r;
            std::uint64_t p;
            ~Done() {
                std::lock_guard<std::mutex> lk(r->rmtx_);
                r->pumping_.erase(p);
            }
        } done{this, p};
        const std::size_t per = static_cast<std::size_t>(fc_ids_max(p_));
        for (;;) {
            std::vector<Hash32> ids;
            {
                std::lock_guard<std::mutex> lk(rmtx_);
                const auto it = reoffer_.find(p);
                if (it == reoffer_.end()) return;
                if (it->second.q.empty()) {
                    reoffer_.erase(it);
                    reoffer_finished_locked(p);
                    return;
                }
                for (std::size_t i = 0; i < per && i < it->second.q.size(); ++i) ids.push_back(it->second.q[i]);
            }
            std::vector<ReceiptBodyV3> chunk;
            {
                const NodeGuard g(*this);
                for (const Hash32& id : ids)
                    if (const PendingReceipt* r = node_->pending().get(id)) chunk.push_back(r->body);
            }
            std::optional<std::vector<std::uint8_t>> fr;
            if (!chunk.empty()) fr = encode_fb_receipts(chain_id_, chunk, p_);
            if (fr) {
                const std::size_t bound = links_.send_queue_limit();
                if (bound != 0 && links_.queued_bytes(p) + fr->size() + 4 + headers_frame_ + 4 > bound) {
                    st_.reoffer_paused++;
                    return;
                }
                if (!send_link(p, *fr)) {
                    std::lock_guard<std::mutex> lk(rmtx_);
                    reoffer_.erase(p);
                    reoffer_t0_.erase(p);
                    return;
                }
                st_.reoffer_frames++;
            }
            std::lock_guard<std::mutex> lk(rmtx_);
            const auto it = reoffer_.find(p);
            if (it == reoffer_.end()) return;
            // the ids sent leave the front (by identity: the cap may have dropped the front meanwhile)
            for (const Hash32& id : ids)
                if (!it->second.q.empty() && it->second.q.front() == id) {
                    it->second.ids.erase(id);
                    it->second.q.pop_front();
                }
        }
    }
    // Under rmtx_: ids appended to a peer's re-offer queue, each id at most once (a duplicate of a queued id is not
    // appended), at most `cap` ids (the pending set's cap, P-09: no peer needs more distinct re-offers): over it the
    // oldest go.
    void reoffer_append_locked(std::uint64_t p, const std::vector<Hash32>& ids, std::size_t cap) {
        ReofferQueue& r = reoffer_[p];
        for (const Hash32& id : ids)
            if (r.ids.insert(id).second) r.q.push_back(id);
        while (r.q.size() > cap && !r.q.empty()) {
            r.ids.erase(r.q.front());
            r.q.pop_front();
            st_.reoffer_cap_drops++;
        }
    }
    // Under rmtx_: a re-offer sent to its end (soak: the time it took).
    void reoffer_finished_locked(std::uint64_t p) {
        const auto t = reoffer_t0_.find(p);
        if (t == reoffer_t0_.end()) return;
        const std::uint64_t now = now_ms();
        const std::uint64_t d = now > t->second ? now - t->second : 0;
        reoffer_t0_.erase(t);
        st_.reoffer_done++;
        st_.reoffer_last_ms = d;
        if (d > st_.reoffer_max_ms.load()) st_.reoffer_max_ms = d;
    }
    // Every relay send. A send at which the transport drops the link for a full queue (its count moved during the
    // send) is counted: a re-offer drop when the peer's re-offer was paging as the send began (the drop's link-down
    // ends it), else a live-traffic drop.
    bool send_link(std::uint64_t p, const std::vector<std::uint8_t>& f) {
        bool paging = false;
        {
            std::lock_guard<std::mutex> lk(rmtx_);
            paging = reoffer_.count(p) != 0;
        }
        const std::uint64_t q0 = links_.queue_full_drops();
        const bool ok = links_.send_to(p, f);
        if (!ok && links_.queue_full_drops() > q0) (paging ? st_.reoffer_queue_full : st_.live_queue_full)++;
        return ok;
    }
    void reoffer_pump_all() {
        std::vector<std::uint64_t> ps;
        {
            std::lock_guard<std::mutex> lk(rmtx_);
            for (const auto& [p, q] : reoffer_) ps.push_back(p);
        }
        for (const std::uint64_t p : ps) reoffer_pump(p);
    }
    // E11: the receipts a switch by the journal re-pended (either switch path: a placement or the drain of the
    // carriers it released) relayed as FB_RECEIPTS v3 to every ready peer, paged as the re-offer: appended to each
    // peer's re-offer queue, which reoffer_pump sends within the link's bound (P-67), skipping bodies no longer
    // pending. Run after each admission outcome's effects (run_effects; an own share extends the best tip and
    // never switches); never under the node lock (the ids then wait for the next call).
    void repend_offer() {
        if (t_node_held == this) return;
        std::vector<Hash32> ids;
        std::size_t cap = 0;
        {
            const NodeGuard g(*this);
            ids = node_->take_repended();
            if (ids.empty() || node_->rests_on_claims() || node_->poisoned()) return;
            cap = static_cast<std::size_t>(node_->pending_cap());
        }
        const std::vector<std::uint64_t> ready = ready_peers();
        st_.repend_offers++;
        st_.repend_offered += ids.size();
        std::string line = "relay: re-pend offer " + std::to_string(ids.size()) + " receipt(s) to " +
                           std::to_string(ready.size()) + " peer(s):";
        for (std::size_t i = 0; i < ids.size() && i < kRependLogIds; ++i) line += " " + hex_short(ids[i]);
        log(line);
        if (ready.empty()) return;  // a peer's HELLO re-offers the pending set
        {
            std::lock_guard<std::mutex> lk(rmtx_);
            for (const std::uint64_t p : ready) {
                if (reoffer_t0_.count(p) == 0) reoffer_t0_[p] = now_ms();
                reoffer_append_locked(p, ids, cap);
            }
        }
        for (const std::uint64_t p : ready) reoffer_pump(p);
    }

    // ---- headers first (the caller's catch-up loop) ----
    // Under the node lock. A catch-up starts when the peer's HELLO tip is not held; the node's own header work at the
    // reply decides fetch or keep (the tail's best_cum_work is not read).
    void catchup_start(std::uint64_t p, const HelloTail& tail) {
        std::lock_guard<std::mutex> lk(cumtx_);
        if (node_->holds_tip(tail.best_tip)) {
            caught_up_locked();  // nothing to catch up from this peer (the done test at the start)
            return;
        }
        Catchup& c = catchup_[p];
        c.tip = tail.best_tip;
        c.step = 0;
        catchup_ask_locked(p, c);
    }
    // Under the node lock and cumtx_: a store not caught up whose catch-ups all ended (each HELLO tip held, or a reply
    // that ended its catch-up by the node's own decision) is caught up (its record leaves the store).
    void caught_up_locked() {
        if (node_->caught_up() || !catchup_.empty() || !node_->has_pathb_peer()) return;
        node_->note_caught_up();
        st_.caught_up_at_ms = now_ms();
        log("relay: caught up (the catch-up from every HELLO peer ended by its done test)");
    }
    // Under the node lock and cumtx_: FC_GETHEADERS to the peer's tip (one in flight per peer), from the best tip,
    // then, after empty replies, a locator step down the best chain: pos - 1, pos - 2, pos - 4, ..., then the lowest
    // position held (position 0 on an unpruned store): at most floor(log2 pos) + 2 requests per round.
    void catchup_ask_locked(std::uint64_t p, Catchup& c) {
        const CarrierNode& b = node_->tree().best();
        const CarrierNode& root = node_->tree().genesis();
        Hash32 from = b.id;
        if (c.step > 0) {
            const std::uint64_t back = c.step - 1 < 63 ? std::uint64_t{1} << (c.step - 1) : UINT64_MAX;
            const std::uint64_t pos = b.pos > root.pos && b.pos - root.pos > back ? b.pos - back : root.pos;
            from = pos == root.pos ? root.id : node_->store().best_at(pos).value_or(root.id);
        }
        if (!node_->request_headers(p, from, c.tip, header_max_, now_s(), PathbNode::HeaderOwner::CatchUp)) return;
        hdr_sent_.erase(p);
        const auto q = header_wants_.find(p);  // the catch-up keeps only its latest request
        if (q != header_wants_.end()) {
            q->second.erase(std::remove_if(q->second.begin(), q->second.end(),
                                           [](const HdrWant& w) { return w.owner == PathbNode::HeaderOwner::CatchUp; }),
                            q->second.end());
            if (q->second.empty()) header_wants_.erase(q);
        }
        const CarrierNode* fn = node_->tree().find(from);
        c.from_root = fn == nullptr || fn->pos <= root.pos;
        c.from_pos0 = fn != nullptr && fn->pos == 0;
        c.asked_best = b.id;
        c.asked_ms = now_ms();
        st_.catchup_requests++;
        if (c.step > 0) st_.catchup_steps++;
    }
    // `node_reply`: the frame answered the node's own request in link order (its arrival was counted).
    void handle_headers(std::uint64_t p, const std::vector<std::uint8_t>& f, bool node_reply) {
        using K = PathbNode::HeadersOutcome::Kind;
        PathbNode::HeadersOutcome o;
        bool join = false;
        {
            const NodeGuard g(*this);
            if (node_reply) {  // handled now: no longer waiting for the owner
                std::lock_guard<std::mutex> lk(kmtx_);
                const auto a = hdr_arrived_.find(p);
                if (a != hdr_arrived_.end() && --a->second == 0) hdr_arrived_.erase(a);
            }
            try {
                o = node_->on_headers(p, f, now_s());
            } catch (const RandomxFailure& e) {  // node-internal, a local alarm; no token, no ban; the catch-up asks again
                rx_alarm("headers of peer " + std::to_string(p), e.what());
                log("relay: peer " + std::to_string(p) + " FC_HEADERS not judged: " + e.what() + " (no token, no ban)");
                return;
            }
            {
                std::lock_guard<std::mutex> lk(cumtx_);
                // the request this frame answered (a continuation page goes on): a tip request's objects go with its
                // deferral
                TipObjects objs;
                if (o.owner != PathbNode::HeaderOwner::None && o.kind != K::Continue) {
                    const auto sn = hdr_sent_.find(p);
                    if (sn != hdr_sent_.end()) {
                        if (o.owner == PathbNode::HeaderOwner::Tip && sn->second.from == o.from && sn->second.stop == o.stop)
                            objs = std::move(sn->second.objs);
                        hdr_sent_.erase(sn);
                    }
                }
                if (o.kind == K::Defer && o.fetch != Hash32{}) {  // asked again once its input is held
                    HdrOnCtx w;
                    w.owner = o.owner;
                    w.from = o.from;
                    w.stop = o.stop;
                    w.fetch = o.fetch;
                    w.cause = o.cause;
                    w.objs = std::move(objs);
                    note_ctx_locked(p, w);
                }
                // only the catch-up's own outcomes act on the catch-up (a tip request's outcome leaves it as it is)
                const auto it = o.owner == PathbNode::HeaderOwner::CatchUp ? catchup_.find(p) : catchup_.end();
                if (it != catchup_.end()) {
                    switch (o.kind) {
                        case K::Keep:
                            // an empty reply to a request from above the lowest position held: the server's chain does
                            // not hold that `from`; the next locator step down the best chain
                            if (o.ids.empty() && !it->second.from_root) {
                                ++it->second.step;
                                catchup_ask_locked(p, it->second);
                                break;
                            }
                            // the reply to a request from position 0 carried no header: the peer serves none of this
                            // node's chain (the joiner path: its tip a join candidate)
                            if (o.ids.empty() && it->second.from_pos0) {
                                if (node_->offer_empty_store_tip(p)) {
                                    st_.empty_store_offers++;
                                    join = true;
                                }
                                catchup_.erase(it);
                                break;
                            }
                            // the node's own header work kept its chain: this catch-up ended by its reply
                            catchup_.erase(it);
                            caught_up_locked();
                            break;
                        case K::JoinerPath: catchup_.erase(it); break;
                        case K::Ban:
                        case K::Strike:
                        case K::Undecodable:  // the catch-up ended by its reply
                            catchup_.erase(it);
                            caught_up_locked();
                            break;
                        case K::FetchBodies:  // one page in flight: no new ask until its last asked body is placed or
                                              // the page lapses
                            if (o.fetch_last != Hash32{}) {
                                it->second.fetch_tip = o.fetch_last;
                                it->second.fetch_best = node_->tree().best().id;
                                it->second.fetch_ms = now_ms();
                            }
                            break;
                        default: break;
                    }
                }
                serve_header_wants_locked(p);  // the peer's slot may be free: its waiting requests, the oldest first
            }
            if (o.kind == K::JoinerPath) join = true;
        }
        if ((o.kind == K::Unsolicited || o.kind == K::Retired) && !o.why.empty())
            log("relay: peer " + std::to_string(p) + " DROP: " + o.why);
        switch (o.kind) {
            case K::Retired: st_.headers_retired_dropped++; [[fallthrough]];
            case K::OverBuffer:   // above the FC_HEADERS buffer: DROP (the request ends)
            case K::Unsolicited: token(p, FrameToken::Drop); break;
            case K::Undecodable: token(p, FrameToken::Strike); break;
            case K::Ban: ban(p, o.why); break;
            case K::Strike:
                log("relay: peer " + std::to_string(p) + " STRIKE: " + o.why);
                token(p, FrameToken::Strike);
                break;
            default: break;
        }
        if (o.kind == K::Defer && o.fetch != Hash32{}) {
            // a header's P_r not resolved: fetched (FB_GETCTX, the carrier class); a header waiting for the weights of a
            // block the follower holds asks no context (the request was noted above)
            st_.headers_ctx_deferred++;
            bool held = false;
            {
                const NodeGuard g(*this);
                held = o.cause == Missing::MissingWeights && node_->monero_block_held(o.fetch);
            }
            if (o.cause == Missing::Seed) {
                // the seed cache: no context brings it; the request is asked again once the seed is held
            } else if (held) {
                st_.ctx_held++;
            } else {
                want_ctx(o.fetch, p, 0, CtxClass::Carrier);
            }
        }
        if (o.indexed > 0) rerun_parked(std::vector<Missing>{Missing::TipUnknown, Missing::TipHeaders});
        if (join) signal_join();
    }
    // Under the node lock and cumtx_: a header request of `p` deferred on a P_r. The catch-up keeps one deferral (its
    // latest request); a tip request's are kept per (from, stop) within the peer's bound (P-47; its objects added to an
    // equal one); an updated one's since restarts only for another P_r; nothing of another request replaced.
    void note_ctx_locked(std::uint64_t p, const HdrOnCtx& w) {
        std::vector<HdrOnCtx>& v = headers_on_ctx_[p];
        for (HdrOnCtx& e : v)
            if (e.owner == w.owner && (w.owner == PathbNode::HeaderOwner::CatchUp || (e.from == w.from && e.stop == w.stop))) {
                if (e.fetch != w.fetch || e.since_ms == 0) e.since_ms = w.since_ms != 0 ? w.since_ms : now_ms();
                e.from = w.from;
                e.stop = w.stop;
                e.fetch = w.fetch;
                e.cause = w.cause;
                e.objs.add(w.objs);
                prune_objects_locked(e.objs);
                return;
            }
        if (w.owner == PathbNode::HeaderOwner::Tip) tip_room_locked(v);
        v.push_back(w);
        if (v.back().since_ms == 0) v.back().since_ms = now_ms();
    }
    // Under cumtx_: the catch-up's own deferral of peer `p` (none: nullptr).
    HdrOnCtx* catchup_ctx_locked(std::uint64_t p) {
        const auto it = headers_on_ctx_.find(p);
        if (it == headers_on_ctx_.end()) return nullptr;
        for (HdrOnCtx& e : it->second)
            if (e.owner == PathbNode::HeaderOwner::CatchUp) return &e;
        return nullptr;
    }
    // The header requests deferred on a P_r (per peer and request), asked again under their owners once that P_r
    // resolves (gated: a context of that id resolved (`only`), or the follower's chain moved); ungated: the KAT hook's
    // re-run.
    void reask_headers_on_ctx(const std::optional<Hash32>& only, bool gated) {
        const NodeGuard g(*this);
        std::lock_guard<std::mutex> lk(cumtx_);
        for (auto it = headers_on_ctx_.begin(); it != headers_on_ctx_.end();) {
            const std::uint64_t p = it->first;
            std::vector<HdrOnCtx>& v = it->second;
            // the ones not due (another P_r, or its input not held yet) stay in place, in their order
            const auto due = std::stable_partition(v.begin(), v.end(), [&](const HdrOnCtx& e) {
                return (only && e.fetch != *only) || (gated && !node_->monero_input_held(e.cause, e.fetch));
            });
            std::vector<HdrOnCtx> asks(std::make_move_iterator(due), std::make_move_iterator(v.end()));
            v.erase(due, v.end());
            it = v.empty() ? headers_on_ctx_.erase(it) : std::next(it);
            for (const HdrOnCtx& w : asks) {
                if (!hello_ok(p) || node_->tree().find(w.from) == nullptr) continue;
                want_headers_locked(p, w.owner, w.from, w.stop, w.objs);
                st_.headers_ctx_reasks++;
            }
        }
    }
    // Under the node lock: the waiting header requests of `peer` (every peer: 0), while that peer has none in flight.
    void header_wants_locked(std::uint64_t only) {
        std::lock_guard<std::mutex> lk(cumtx_);
        serve_header_wants_locked(only);
    }

    // ---- FC_BUCKETS (the node's own requests) ----
    void handle_buckets(std::uint64_t p, const std::vector<std::uint8_t>& f) {
        BucketsEventResult r;
        {
            const NodeGuard g(*this);
            r = node_->on_buckets(p, f, now_s());
        }
        if (r.action == NodeAction::NodeInternal) return;
        switch (r.frame.verdict) {
            case BucketsFrameVerdict::Refused:
                token(p, FrameToken::Strike, std::max<std::uint32_t>(r.frame.strike, 1));
                rerun_parked(Missing::MissingBucket);  // another peer for that carrier
                break;
            case BucketsFrameVerdict::NotServed: rerun_parked(Missing::MissingBucket); break;
            case BucketsFrameVerdict::Drop: token(p, FrameToken::Drop); break;
            case BucketsFrameVerdict::Accepted:  // the bins and their references
                if (r.frame.bins_completed > 0) rerun_parked(std::vector<Missing>{Missing::MissingBucket, Missing::MissingRef});
                break;
            default: break;
        }
    }

    // ---- family C requests ----
    void serve_request(std::uint64_t p, const std::vector<std::uint8_t>& f) {
        ServeResult s;
        {
            const NodeGuard g(*this);
            switch (f[0]) {
                case kOpFcGetCarrier: s = node_->serve_getcarrier(p, f, now_s()); break;
                case kOpFcGetHeaders: s = node_->serve_getheaders(p, f, now_s()); break;
                case kOpFcGetBuckets: s = node_->serve_getbuckets(p, f, now_s()); break;
                default: return;
            }
        }
        token(p, s.token);
        for (const std::vector<std::uint8_t>& fr : s.frames) (void)send_link(p, fr);
    }

    // ---- FB_RECEIPTS ----
    // The frame checked as a whole (above the buffer: DROP; does not decode: refuse + 1 strike), then one job per body.
    void on_receipts_frame(std::uint64_t p, const std::vector<std::uint8_t>& f) {
        ReceiptsFrame rf;
        const FrameDecode d = decode_fb_receipts(f, chain_id_, buffers_, p_, rf);
        if (!d.ok()) {
            token(p, d.error == FrameWireError::OverBuffer ? FrameToken::Drop : FrameToken::Strike);
            return;
        }
        const std::uint64_t src = src_of(p);
        for (const std::vector<std::uint8_t>& body : rf.bodies) {
            std::vector<std::uint8_t> one;
            one.reserve(kFrameHeaderBytes + 1 + body.size());
            one.push_back(kOpFbReceipts);
            one.push_back(kFrameVersion2);
            for (int i = 0; i < 4; ++i) one.push_back(static_cast<std::uint8_t>(chain_id_ >> (8 * i)));
            one.push_back(1);
            one.insert(one.end(), body.begin(), body.end());
            enqueue_job(Job{Job::Kind::Receipt, p, src, std::move(one), 0});
        }
    }

    // ---- the join worker ----
    void signal_join() {
        {
            std::lock_guard<std::mutex> lk(jmtx_);
            join_due_ = true;
        }
        jcv_.notify_one();
    }
    void join_loop() {
        while (running_) {
            {
                std::unique_lock<std::mutex> lk(jmtx_);
                jcv_.wait(lk, [&] { return join_due_ || !running_; });
                if (!running_) break;
                join_due_ = false;
            }
            if (now_ms() < join_not_before_ms_) continue;  // the tick signals again
            (void)run_one_join();
        }
    }
    std::map<std::uint64_t, std::uint32_t> link_strikes_locked() const {
        std::map<std::uint64_t, std::uint32_t> m;
        for (std::uint64_t p : ready_peers())
            if (const PathbJoinLink* l = node_->join_link(p)) m[p] = l->strikes();
        return m;
    }
    std::optional<JoinStep> run_one_join() {
        JoinAttempted t;
        std::map<std::uint64_t, std::uint32_t> before, after;
        {
            const NodeGuard g(*this, true);
            if (!running_ || node_->poisoned()) return std::nullopt;
            const bool queued = node_->joiner().queue().ready() != 0;  // pairs waiting on a P_r are not attempted
            if (!queued && !reask_due_) return std::nullopt;
            // P-40: a queued pair is attempted once HELLO tails of at least join_min_peers peers name the candidates
            const bool tails = ready_peers().size() >= o_.join_min_peers;
            if (queued && !tails) st_.join_waits++;
            if (!reask_due_ && !tails) return std::nullopt;
            reask_due_ = false;
            before = link_strikes_locked();
            if (queued && tails) st_.join_attempts++;
            t = node_->attempt_join(tails);
            after = link_strikes_locked();
        }
        // an undecodable reply frame of the attempt's server: one strike each (the link counted it)
        for (const auto& [p, n] : after) {
            const auto b = before.find(p);
            const std::uint32_t was = b == before.end() ? 0 : b->second;
            if (n > was) {
                strike(p, n - was, false);
                st_.join_strikes += n - was;
            }
        }
        std::optional<JoinStep> s;
        if (o_.threads) {
            struct Shared {
                std::mutex m;
                std::condition_variable cv;
                bool done = false;
                JoinAttempted t;
                JoinStep s;
            };
            auto sh = std::make_shared<Shared>();
            sh->t = std::move(t);
            post([this, sh] {
                JoinStep r;
                {
                    const NodeGuard g(*this);
                    r = node_->apply_join(std::move(sh->t));
                }
                std::lock_guard<std::mutex> lk(sh->m);
                sh->s = std::move(r);
                sh->done = true;
                sh->cv.notify_all();
            });
            std::unique_lock<std::mutex> lk(sh->m);
            while (!sh->done && running_) sh->cv.wait_for(lk, std::chrono::milliseconds(200));
            if (!sh->done) return std::nullopt;
            s = std::move(sh->s);
        } else {
            const NodeGuard g(*this);
            s = node_->apply_join(std::move(t));
        }
        if (s->report) {
            const AttemptReport& rep = *s->report;
            log("relay: join attempt at peer " + std::to_string(rep.server) + ": " + attempt_end_name(rep.end) + " (L " +
                std::to_string(rep.L) + ", at " + std::to_string(rep.at) + ", row " + std::to_string(static_cast<int>(rep.row)) +
                ", tokens " + std::to_string(rep.strike) +
                (rep.side_needs > 0 ? ", side branches " + std::to_string(rep.side_needs) : std::string()) +
                (rep.what.empty() ? "" : ": " + rep.what) + ")" +
                (s->switched ? " -> adopted, lost " + std::to_string(s->sw.lost) : ""));
            if (s->caught_up) {
                st_.caught_up_at_ms = now_ms();
                log("relay: caught up (a join attempt completed; rule (4) kept the node's chain)");
            }
            if (rep.side_needs > 0) {
                st_.join_side_attempts++;
                if (rep.end == AttemptEnd::Completed) st_.join_side_completed++;
                if (rep.end == AttemptEnd::NotServed) st_.join_side_not_served++;
            }
            if (s->report->strike > 0) {
                strike(s->report->server, s->report->strike, false);
                st_.join_strikes += s->report->strike;
            }
            // a RandomX failure in the attempt: node-internal, the alarm; no token; the pair re-queued, tried again as
            // after a non-service
            if (s->report->end == AttemptEnd::NodeInternal) rx_alarm("join attempt", s->report->what);
            if (s->report->end == AttemptEnd::NotServed || s->report->end == AttemptEnd::NodeInternal)
                join_not_before_ms_ = now_ms() + abandon_s_ * 1000;
        }
        return s;
    }

    // ---- the tickets (JoinTransport) ----
    std::uint64_t ticket_send(std::uint64_t peer, const std::vector<std::uint8_t>& req) {
        Ticket t;
        t.peer = peer;
        t.last_ms = now_ms();
        const std::uint8_t op = req.empty() ? 0 : req[0];
        if (op == kOpFcGetHeaders) {
            t.op = kOpFcHeaders;
        } else if (op == kOpFcGetCarrier) {
            t.op = kOpFcCarrier;
            GetCarrier q;
            if (decode_fc_getcarrier(req, chain_id_, p_, q).ok()) {
                t.ids.insert(q.ids.begin(), q.ids.end());
                t.n = q.ids.size();
            }
        } else if (op == kOpFcGetBuckets) {
            t.op = kOpFcBuckets;
            GetBuckets q;
            if (decode_getbuckets(req, chain_id_, q) == BucketsWireError::None) t.at = q.at;
        }
        const bool live = links_.has_peer(peer);
        std::uint64_t id = 0;
        {
            std::lock_guard<std::mutex> lk(kmtx_);
            id = ++next_ticket_;
            t.closed = !live;
            if (t.op == kOpFcHeaders && live) hdr_fifo_[peer].push_back(HdrWait{false, id, false});
            tickets_.emplace(id, std::move(t));
        }
        st_.join_tickets++;
        if (live && !send_link(peer, req)) {
            std::lock_guard<std::mutex> lk(kmtx_);
            const auto it = tickets_.find(id);
            if (it != tickets_.end()) it->second.closed = true;
        }
        return id;
    }
    // The reply frames of a ticket: FC_HEADERS one frame; FC_CARRIER at most n frames; each within timeout_s of the
    // one before (the first of the send); FC_BUCKETS until timeout_s passes with no frame. A closed ticket: none.
    std::vector<std::vector<std::uint8_t>> ticket_collect(std::uint64_t id, std::uint64_t timeout_s) {
        const JoinRelease rel(*this);
        std::vector<std::vector<std::uint8_t>> out;
        std::unique_lock<std::mutex> lk(kmtx_);
        for (;;) {
            const auto it = tickets_.find(id);
            if (it == tickets_.end()) return out;
            Ticket& t = it->second;
            const bool full = (t.op == kOpFcHeaders && std::any_of(t.frames.begin(), t.frames.end(),
                                                                   [&](const auto& fr) { return fr.size() <= headers_frame_; }))
                              || (t.op == kOpFcCarrier && t.n > 0 && t.frames.size() >= t.n);
            const std::uint64_t now = now_ms();
            const std::uint64_t deadline = t.last_ms + timeout_s * 1000;
            if (t.closed || full || now >= deadline || !running_) {
                if (!t.closed) out = std::move(t.frames);
                finish_ticket_locked(it);
                return out;
            }
            if (!o_.threads) {
                lk.unlock();
                const bool moved = drive_ && drive_();
                lk.lock();
                if (moved) continue;
                const auto jt = tickets_.find(id);
                if (jt == tickets_.end()) return out;
                if (!jt->second.closed) out = std::move(jt->second.frames);
                finish_ticket_locked(jt);
                return out;
            }
            kcv_.wait_for(lk, std::chrono::milliseconds(deadline - now));
        }
    }
    void ticket_drop(std::uint64_t id) {
        std::lock_guard<std::mutex> lk(kmtx_);
        const auto it = tickets_.find(id);
        if (it != tickets_.end()) finish_ticket_locked(it);
    }
    void finish_ticket_locked(std::map<std::uint64_t, Ticket>::iterator it) {
        const auto q = hdr_fifo_.find(it->second.peer);
        if (q != hdr_fifo_.end())
            for (HdrWait& h : q->second)
                if (!h.node && h.ticket == it->first) h.dead = true;
        tickets_.erase(it);
    }
    void tickets_peer_gone(std::uint64_t p) {
        {
            std::lock_guard<std::mutex> lk(kmtx_);
            for (auto& [id, t] : tickets_)
                if (t.peer == p) t.closed = true;
            hdr_fifo_.erase(p);
            hdr_arrived_.erase(p);
            asked_carriers_.erase(p);
            bodyset_asked_.erase(p);
        }
        kcv_.notify_all();
    }
    void wait_until_s(std::uint64_t t_s) {
        const JoinRelease rel(*this);
        if (!o_.threads) {
            while (now_s() < t_s && drive_ && drive_()) {
            }
            return;
        }
        std::unique_lock<std::mutex> lk(kmtx_);
        for (;;) {
            const std::uint64_t now = now_ms();
            if (!running_ || now >= t_s * 1000) return;
            kcv_.wait_for(lk, std::chrono::milliseconds(t_s * 1000 - now));
        }
    }
    // A reply frame of an open ticket goes to it (true); any other frame to the node (false).
    bool open_ticket(std::uint64_t peer, std::uint8_t op) const {
        std::lock_guard<std::mutex> lk(kmtx_);
        for (const auto& [k, t] : tickets_)
            if (t.peer == peer && t.op == op && !t.closed) return true;
        return false;
    }
    // `node_reply`: an FC_HEADERS frame that answers the node's own request (its arrival recorded for its P-53 clock).
    bool route_reply(std::uint64_t peer, const std::vector<std::uint8_t>& f, bool* node_reply = nullptr) {
        const std::uint8_t op = f[0];
        if (op == kOpFcHeaders) {  // one FC_HEADERS frame answers one FC_GETHEADERS, in request order
            std::lock_guard<std::mutex> lk(kmtx_);
            const auto q = hdr_fifo_.find(peer);
            if (q == hdr_fifo_.end() || q->second.empty()) return false;
            const HdrWait h = q->second.front();
            q->second.pop_front();
            if (h.node) {
                ++hdr_arrived_[peer];  // node_tick stops the request's P-53 clock while the frame waits for the owner
                if (node_reply != nullptr) *node_reply = true;
                return false;
            }
            const auto it = tickets_.find(h.ticket);
            if (h.dead || it == tickets_.end()) {
                st_.drops++;  // the reply of an ended request: DROP
                return true;
            }
            it->second.frames.push_back(f);
            it->second.last_ms = now_ms();
            kcv_.notify_all();
            return true;
        }
        if (op == kOpFcCarrier) {
            if (f.size() > buffers_.frame || !open_ticket(peer, kOpFcCarrier)) return false;
            std::optional<Hash32> id;
            CarrierBodyV3 c;
            if (check_fc_carrier(f, chain_id_, buffers_).ok()
                && decode_carrier_body_v3(f.data() + kFrameHeaderBytes, f.size() - kFrameHeaderBytes,
                                          CarrierLimits{buffers_.receipt, p_.r_max}, c)
                           == WireError::None)
                id = receipt_id(c.own);
            std::lock_guard<std::mutex> lk(kmtx_);
            Ticket* oldest = nullptr;
            for (auto& [k, t] : tickets_) {
                if (t.peer != peer || t.op != kOpFcCarrier || t.closed || t.frames.size() >= t.n) continue;
                if (oldest == nullptr) oldest = &t;
                if (id && t.ids.erase(*id) != 0) {
                    t.frames.push_back(f);
                    t.last_ms = now_ms();
                    kcv_.notify_all();
                    return true;
                }
            }
            if (!id && oldest != nullptr) {  // does not decode: the asked server's reply (its link strikes it)
                oldest->frames.push_back(f);
                oldest->last_ms = now_ms();
                kcv_.notify_all();
                return true;
            }
            return false;
        }
        if (op == kOpFcBuckets) {
            if (f.size() > bucket_frame_ || !open_ticket(peer, kOpFcBuckets)) return false;
            BucketsFrameView v;
            const bool ok = decode_buckets_view(f, chain_id_, v) == BucketsWireError::None;
            std::lock_guard<std::mutex> lk(kmtx_);
            Ticket* oldest = nullptr;
            for (auto& [k, t] : tickets_) {
                if (t.peer != peer || t.op != kOpFcBuckets || t.closed) continue;
                if (oldest == nullptr) oldest = &t;
                if (ok && t.at == v.at) {
                    t.frames.push_back(f);
                    t.last_ms = now_ms();
                    kcv_.notify_all();
                    return true;
                }
            }
            if (!ok && oldest != nullptr) {
                oldest->frames.push_back(f);
                oldest->last_ms = now_ms();
                kcv_.notify_all();
                return true;
            }
            return false;
        }
        return false;
    }

    // ---- the maintenance work ----
    void hello_timeouts() {
        std::vector<std::uint64_t> stale;
        {
            std::lock_guard<std::mutex> lk(pmtx_);
            const std::uint64_t now = now_ms();
            for (const auto& [p, s] : peers_)
                if (!s.hello_ok && now - s.connected_ms > o_.hello_timeout_ms) stale.push_back(p);
        }
        for (std::uint64_t p : stale) {
            st_.hello_timeout++;
            {
                std::lock_guard<std::mutex> lk(tmtx_);
                for (Target& t : targets_)
                    if (t.pid == p) t.hello_timed_out = true;
            }
            if (links_.has_peer(p)) {
                links_.disconnect(p);
                continue;
            }
            std::lock_guard<std::mutex> lk(pmtx_);
            peers_.erase(p);
        }
    }
    std::set<std::string> linked_keys() const {
        std::lock_guard<std::mutex> lk(pmtx_);
        std::set<std::string> k;
        for (const auto& [p, s] : peers_) {
            if (!s.addr_key.empty()) k.insert(s.addr_key);
            if (!s.out_host.empty()) k.insert(rly::peer_key(s.out_host, s.out_port));
        }
        return k;
    }
    static constexpr std::size_t kAddrNonceMax = 4096;
    std::set<std::string> linked_node_keys() const {
        std::lock_guard<std::mutex> lk(pmtx_);
        std::set<std::uint64_t> live;
        for (const auto& [p, s] : peers_)
            if (s.hello_ok) live.insert(s.remote_nonce);
        std::set<std::string> v;
        for (const auto& [k, n] : addr_nonce_)
            if (live.count(n) != 0) v.insert(k);
        return v;
    }
    void dial_targets() {
        if (!dialing_) {
            std::vector<std::uint64_t> out;
            {
                std::lock_guard<std::mutex> lk(tmtx_);
                for (Target& t : targets_)
                    if (t.pid != 0) {
                        out.push_back(t.pid);
                        t.pid = 0;
                        t.gone_ms = 0;
                    }
            }
            for (std::uint64_t p : out) links_.disconnect(p);
            return;
        }
        std::vector<std::size_t> due;
        const std::vector<std::uint64_t> live = links_.peer_ids();
        const std::set<std::string> linked = o_.discovery ? linked_keys() : std::set<std::string>{};
        const std::set<std::string> aliased = o_.discovery ? linked_node_keys() : std::set<std::string>{};
        {
            std::lock_guard<std::mutex> lk(tmtx_);
            const std::uint64_t now = now_ms();
            for (std::size_t i = 0; i < targets_.size(); ++i) {
                Target& t = targets_[i];
                if (t.pid != 0 && std::find(live.begin(), live.end(), t.pid) == live.end()) {
                    // its down event releases it; one not run within hello_timeout_ms releases it here
                    if (t.gone_ms == 0) t.gone_ms = now;
                    if (now - t.gone_ms < o_.hello_timeout_ms) continue;
                    release_target_locked(t);
                }
                if (t.self) continue;
                if (t.pid == 0 && now >= t.next_try_ms) {
                    const std::string k = rly::peer_key(t.host, t.port);
                    if (linked.count(k) != 0 || aliased.count(k) != 0) {
                        t.next_try_ms = now + 5000;
                        if (t.learned) t.used = true;
                        continue;
                    }
                    due.push_back(i);
                }
            }
        }
        for (std::size_t i : due) {
            std::string host;
            std::uint16_t port = 0;
            {
                std::lock_guard<std::mutex> lk(tmtx_);
                if (i >= targets_.size()) continue;
                host = targets_[i].host;
                port = targets_[i].port;
            }
            st_.dials++;
            dial_host_ = host;
            dial_port_ = port;
            t_dialing_relay = this;
            const std::uint64_t pid = links_.dial(host, port);
            t_dialing_relay = nullptr;
            dial_host_.clear();
            dial_port_ = 0;
            const bool hello_now = pid != 0 && hello_ok(pid);
            std::lock_guard<std::mutex> lk(tmtx_);
            if (i >= targets_.size()) continue;
            Target& t = targets_[i];
            if (pid != 0) {
                t.backoff_s = 1;
                t.hello_seen = hello_now;
                t.hello_timed_out = false;
                if (links_.has_peer(pid)) {
                    t.pid = pid;
                    t.gone_ms = 0;
                    if (hello_now) t.prehello_fails = 0;
                } else {
                    t.next_try_ms = now_ms() + static_cast<std::uint64_t>(prehello_delay_s(t)) * 1000;
                    t.hello_seen = false;
                    if (o_.discovery && !hello_now) book_.mark_failed(host, port, clock_.wall_s());
                }
                if (t.learned) t.used = true;
            } else {
                st_.dial_fail++;
                if (o_.discovery) book_.mark_failed(t.host, t.port, clock_.wall_s());
                if (t.learned) t.used = true;
                t.next_try_ms = now_ms() + static_cast<std::uint64_t>(t.backoff_s) * 1000;
                t.backoff_s = std::min(60, t.backoff_s * 2);
            }
        }
    }
    void node_tick() {
        bool rerun = false, join = false;
        Effects rfx;  // released carriers whose admission failed with a RandomX failure (an own share's placement)
        {
            const NodeGuard g(*this);
            take_rx_failed_locked(rfx);
            {  // a header request whose reply frame arrived and waits for the owner is answered: its P-53 clock stops
                std::vector<std::uint64_t> arrived;
                {
                    std::lock_guard<std::mutex> lk(kmtx_);
                    for (const auto& [p, n] : hdr_arrived_)
                        if (n > 0) arrived.push_back(p);
                }
                for (const std::uint64_t p : arrived) node_->headers_arrived(p);
            }
            if (node_->tick(now_s()) > 0) rerun = true;  // a request abandoned (P-53): another peer
            {  // the wants re-made for an id a join pair waits on (it gave up before): the pairs are tried again
                std::vector<Hash32> again;
                {
                    std::lock_guard<std::mutex> lk(cmtx_);
                    again.swap(ctx_remade_);
                }
                for (const Hash32& id : again)
                    if (const std::size_t n = node_->release_join_waits(id, Missing::MoneroBlock); n > 0) st_.join_releases += n;
            }
            std::lock_guard<std::mutex> lk(cumtx_);
            bool done_any = false;
            for (auto it = catchup_.begin(); it != catchup_.end();) {
                const CarrierNode& b = node_->tree().best();
                const bool done = node_->holds_tip(it->second.tip) || node_->rests_on_claims();
                if (done) {
                    done_any = done_any || !node_->rests_on_claims();
                    it = catchup_.erase(it);
                    continue;
                }
                HdrOnCtx* const hd = catchup_ctx_locked(it->first);  // the catch-up's own deferral only
                const bool deferred = hd != nullptr;
                // a store not caught up whose catch-up step stays deferred on a P_r its context did not bring within
                // kCtxTtlMs: the peer's tip becomes a join candidate (the joiner path; paced on that P_r)
                if (deferred && !node_->caught_up() && !hd->offered && hd->since_ms != 0
                    && now_ms() >= hd->since_ms + kCtxTtlMs && !node_->monero_input_held(hd->cause, hd->fetch)) {
                    hd->offered = true;
                    if (node_->offer_empty_store_tip(it->first)) {
                        st_.catchup_join_offers++;
                        log("relay: catch-up from peer " + std::to_string(it->first) + " deferred on P_r " +
                            hex_short(hd->fetch) + " past its context's time: its tip offered to the joiner");
                    }
                }
                // a page whose bodies are in flight: no new ask until its tip is placed, or the best did not move within
                // P-53 (the page lapsed)
                Catchup& c = it->second;
                if (c.fetch_tip != Hash32{}) {
                    if (node_->tree().find(c.fetch_tip) != nullptr) {
                        c.fetch_tip = Hash32{};
                    } else if (b.id != c.fetch_best) {
                        c.fetch_best = b.id;
                        c.fetch_ms = now_ms();
                    } else if (now_ms() >= c.fetch_ms + abandon_s_ * 1000) {
                        c.fetch_tip = Hash32{};
                    }
                }
                // again from the new best tip (the locator from its step 0), or after a request that got no reply
                // within P-53 (a request deferred on a P_r is asked again when that P_r resolves)
                if (c.fetch_tip == Hash32{} && c.asked_best != b.id) {
                    c.step = 0;
                    catchup_ask_locked(it->first, c);
                } else if (c.fetch_tip == Hash32{} && !deferred && now_ms() >= c.asked_ms + abandon_s_ * 1000) {
                    catchup_ask_locked(it->first, c);
                }
                ++it;
            }
            if (done_any) caught_up_locked();
            join = (node_->joiner().queue().ready() > 0 || reask_due_) && now_ms() >= join_not_before_ms_;
        }
        {
            const NodeGuard g(*this);
            header_wants_locked(0);
        }
        if (rerun) rerun_parked(Missing::MissingBucket);
        if (join) signal_join();
        run_effects(rfx);
    }

    // ---- liveness (FB_PING / FB_PONG) ----
    void on_ping(std::uint64_t p, const std::vector<std::uint8_t>& f) {
        std::uint8_t op = 0;
        std::uint64_t n = 0;
        if (!rly::decode_ping(f, op, n)) {
            st_.malformed++;
            return;
        }
        {
            std::lock_guard<std::mutex> lk(pmtx_);
            const auto it = peers_.find(p);
            if (it != peers_.end()) {
                it->second.ka = true;
                it->second.unanswered = 0;
            }
        }
        if (op == kOpFbPong) {
            st_.pong_rx++;
            return;
        }
        st_.ping_rx++;
        if (send_link(p, rly::encode_ping(kOpFbPong, n))) st_.pong_tx++;
    }
    void drive_liveness() {
        if (o_.keepalive_ms == 0) return;
        const std::uint64_t now = now_ms();
        const std::uint64_t gap = now - live_tick_ms_;
        live_tick_ms_ = now;
        // a gap far over the tick: this process was not running; the peers' frames wait unread, so re-arm
        const bool rearm = gap > std::max<std::uint64_t>(2000, o_.keepalive_ms);
        std::vector<std::uint64_t> ping, silent;
        std::vector<std::string> msgs;
        {
            std::lock_guard<std::mutex> lk(pmtx_);
            if (rearm && !peers_.empty()) {
                st_.ka_rearm++;
                msgs.push_back("relay: liveness: maintenance paused " + std::to_string(gap) +
                               " ms -- every link's silence clock re-armed");
                for (auto& [p, s] : peers_) s.last_rx_ms = now;
            }
            for (auto& [p, s] : peers_) {
                if (!s.hello_ok) continue;
                const std::uint64_t quiet = now - s.last_rx_ms;
                if (s.ka && o_.silence_timeout_ms && quiet > o_.silence_timeout_ms) {
                    silent.push_back(p);
                    msgs.push_back("relay: LINK SILENT -- peer " + std::to_string(p) + " sent NOTHING for " +
                                   std::to_string(quiet) + " ms (silence timeout " + std::to_string(o_.silence_timeout_ms) +
                                   " ms) while the link is up: dropping the link and redialing");
                    continue;
                }
                if (!s.ka && s.unanswered >= kLegacyProbes) {
                    if (!s.legacy_noted) {
                        s.legacy_noted = true;
                        st_.ka_legacy++;
                        msgs.push_back("relay: liveness: peer " + std::to_string(p) + " answered none of " +
                                       std::to_string(kLegacyProbes) + " PINGs: its silence is not timed out");
                    }
                    continue;
                }
                if (s.last_ping_ms == 0 || now - s.last_ping_ms >= o_.keepalive_ms) {
                    s.last_ping_ms = now;
                    if (!s.ka) ++s.unanswered;
                    ping.push_back(p);
                }
            }
        }
        for (const std::string& m : msgs) log(m);
        for (std::uint64_t p : silent) {
            st_.silent_drops++;
            links_.disconnect(p);
        }
        for (std::uint64_t p : ping)
            if (send_link(p, rly::encode_ping(kOpFbPing, ++ping_nonce_))) st_.ping_tx++;
    }

    // ---- discovery (FB_GETADDR / FB_ADDR) and the node nonce ----
    static bool dialable_v4(const rly::AddrEntry& e) { return e.family == rly::kAddrFamV4 && e.ip[0] != 0 && e.port != 0; }
    static bool is_public_host(const std::string& ip) {
        rly::AddrEntry e;
        return rly::addr_entry_of(ip, 1, 0, e) && rly::addr_routable(e);
    }
    void send_getaddr(std::uint64_t p) {
        const std::vector<std::uint8_t> f = rly::encode_getaddr(chain_id_, o_.addr_want);
        {
            std::lock_guard<std::mutex> lk(pmtx_);
            const auto it = peers_.find(p);
            if (it == peers_.end() || !it->second.hello_ok) return;
            it->second.addr_pending = true;
            it->second.getaddr_tx_ms = now_ms();
        }
        if (send_link(p, f)) st_.getaddr_tx++;
    }
    // A HELLO refused on a link this node dialed: that address is never good and never learned again.
    void disc_refused(const std::string& why, bool self, std::uint16_t their_listen, const HelloLink& link) {
        const std::string& h = link.out_host;
        const std::uint16_t port = link.out_port;
        if (h.empty()) {
            // the accepting end of a self-dial: the announced address (socket ip : HELLO listen port) is ours
            if (self && their_listen != 0 && !link.remote_ip.empty()) book_.mark_self(link.remote_ip, their_listen);
            return;
        }
        if (self) {
            st_.disc_self++;
            book_.mark_self(h, port);
            log("relay-disc: " + rly::peer_key(h, port) + " is THIS node (HELLO node nonce equal) -> marked self");
            return;
        }
        st_.disc_bad++;
        book_.mark_bad(h, port);
        log("relay-disc: " + rly::peer_key(h, port) + " refused at HELLO -> never good, not learned again (" + why + ")");
    }
    // A HELLO carrying this node's nonce: the dial target behind the link is retired for good.
    void on_self_hello(std::uint64_t p, const HelloLink& link) {
        const std::string& oh = link.out_host;
        const std::uint16_t op = link.out_port;
        std::lock_guard<std::mutex> lk(tmtx_);
        for (Target& t : targets_)
            if (!t.self && (t.pid == p || (!oh.empty() && t.host == oh && t.port == op))) {
                t.self = true;
                if (t.learned) t.used = true;
                log("relay: dial target " + rly::peer_key(t.host, t.port) + " is THIS node -> never dialed again");
            }
    }
    // HELLO ok: a dialed address becomes good, so does an inbound peer's announced address; a second link to the
    // same node is dropped (both ends keep the link dialed by the lower node nonce). false: this link is dropped.
    bool disc_hello_ok(std::uint64_t p, std::uint64_t their_nonce, std::uint16_t their_listen) {
        const std::uint64_t now = clock_.wall_s();
        std::string out_host;
        std::uint16_t out_port = 0;
        std::uint64_t dup = 0;
        bool dup_out = false;
        {
            std::lock_guard<std::mutex> lk(pmtx_);
            const auto it = peers_.find(p);
            if (it == peers_.end()) return false;
            out_host = it->second.out_host;
            out_port = it->second.out_port;
            for (const auto& [q, s] : peers_)
                if (q != p && s.hello_ok && s.remote_nonce == their_nonce) {
                    dup = q;
                    dup_out = !s.out_host.empty();
                    break;
                }
        }
        std::string key, rip;
        if (!out_host.empty()) {
            book_.mark_good(out_host, out_port, now);
            key = rly::peer_key(out_host, out_port);
            bool learned = false;
            {
                std::lock_guard<std::mutex> lk(tmtx_);
                for (const Target& t : targets_)
                    if (t.learned && t.host == out_host && t.port == out_port) learned = true;
            }
            if (learned) st_.disc_dial_ok++;
        } else {
            rip = links_.remote_ip(p);
            if (!rip.empty() && their_listen != 0) {
                key = rly::peer_key(rip, their_listen);
                book_.mark_good(rip, their_listen, now);
            }
        }
        {
            std::lock_guard<std::mutex> lk(pmtx_);
            const auto it = peers_.find(p);
            if (it == peers_.end()) return false;
            it->second.addr_key = key;
            it->second.remote_ip = rip;
            if (!key.empty()) {
                if (addr_nonce_.size() >= kAddrNonceMax && addr_nonce_.count(key) == 0) addr_nonce_.erase(addr_nonce_.begin());
                addr_nonce_[key] = their_nonce;
            }
        }
        if (dup != 0) {
            const rly::DupPick pick = rly::dup_link_rule(nonce_, their_nonce, !out_host.empty(), dup_out);
            if (pick == rly::DupPick::Defer) {
                st_.dup_deferred++;
            } else {
                const bool drop_p = pick == rly::DupPick::DropNew;
                st_.disc_dup_dropped++;
                links_.disconnect(drop_p ? p : dup);
                if (drop_p) return false;
            }
        }
        send_getaddr(p);
        return true;
    }
    void on_getaddr(std::uint64_t p, const std::vector<std::uint8_t>& f) {
        std::uint32_t chain = 0;
        std::uint16_t want = 0;
        if (!rly::decode_getaddr(f, chain, want)) {
            st_.malformed++;
            return;
        }
        if (chain != chain_id_) {
            st_.wrong_chain++;
            return;
        }
        st_.getaddr_rx++;
        std::string asker_key, asker_ip;
        {
            std::lock_guard<std::mutex> lk(pmtx_);
            const auto it = peers_.find(p);
            if (it == peers_.end()) return;
            PeerSt& s = it->second;
            const std::uint64_t now = now_ms();
            if (s.getaddr_rx_ms != 0 && now - s.getaddr_rx_ms < o_.addr_answer_min_ms) {
                st_.getaddr_throttled++;
                return;
            }
            s.getaddr_rx_ms = now;
            asker_key = s.addr_key;
            asker_ip = s.out_host.empty() ? s.remote_ip : s.out_host;
        }
        const bool asker_public = is_public_host(asker_ip);
        const auto sample = book_.sample_good(std::min<std::size_t>(want, o_.addr_answer_max), [&](const rly::PeerRecord& r) {
            if (rly::peer_key(r.host, r.port) == asker_key) return false;
            rly::AddrEntry e;
            if (!rly::addr_entry_of(r.host, r.port, r.last_seen, e)) return false;
            return !asker_public || rly::addr_routable(e);
        });
        std::vector<rly::AddrEntry> v;
        for (const rly::PeerRecord& r : sample) {
            rly::AddrEntry e;
            if (rly::addr_entry_of(r.host, r.port, r.last_seen, e)) v.push_back(e);
        }
        if (send_link(p, rly::encode_addr(chain_id_, v))) st_.addr_tx++;
    }
    void on_addr(std::uint64_t p, const std::vector<std::uint8_t>& f) {
        std::uint32_t chain = 0;
        std::vector<rly::AddrEntry> v;
        if (!rly::decode_addr(f, chain, v)) {
            st_.malformed++;
            return;
        }
        if (chain != chain_id_) {
            st_.wrong_chain++;
            return;
        }
        std::string src_ip;
        std::size_t budget = 0;
        {
            std::lock_guard<std::mutex> lk(pmtx_);
            const auto it = peers_.find(p);
            if (it == peers_.end()) return;
            PeerSt& s = it->second;
            if (!s.addr_pending) {  // an FB_ADDR this node did not ask for: ignored
                st_.addr_unsolicited++;
                return;
            }
            s.addr_pending = false;
            src_ip = s.out_host.empty() ? s.remote_ip : s.out_host;
            budget = s.addr_learned >= o_.addr_learn_per_peer ? 0 : o_.addr_learn_per_peer - s.addr_learned;
        }
        st_.addr_rx++;
        const bool src_public = is_public_host(src_ip);
        const std::size_t take = std::min({v.size(), o_.addr_learn_per_answer, budget});
        const std::uint64_t now = clock_.wall_s();
        std::size_t learned = 0;
        for (std::size_t i = 0; i < take; ++i) {
            const rly::AddrEntry& e = v[i];
            if (!dialable_v4(e) || (src_public && !rly::addr_routable(e))) {
                st_.addr_ignored++;
                continue;
            }
            if (book_.is_self(rly::addr_host(e), e.port)) {
                st_.self_skipped++;
                continue;
            }
            if (book_.learn(rly::addr_host(e), e.port, e.last_seen, now)) ++learned;
        }
        st_.addr_ignored += v.size() - take;
        st_.addr_learned += learned;
        std::lock_guard<std::mutex> lk(pmtx_);
        const auto it = peers_.find(p);
        if (it != peers_.end()) it->second.addr_learned += take;
    }
    // About once a second: retire used learned targets, dial candidates up to max_outbound, ask addresses again while
    // below it, refresh the connected good peers, expire stale entries, save a dirty book.
    void disc_tick() {
        const std::uint64_t nowc = now_ms();
        if (nowc - disc_tick_ms_ < 1000) return;
        disc_tick_ms_ = nowc;
        const std::uint64_t now = clock_.wall_s();
        {
            std::lock_guard<std::mutex> lk(tmtx_);
            targets_.erase(std::remove_if(targets_.begin(), targets_.end(),
                                          [](const Target& t) { return t.learned && t.used && t.pid == 0; }),
                           targets_.end());
        }
        std::size_t out = 0;
        std::vector<std::pair<std::string, std::uint16_t>> outs;
        std::vector<std::uint64_t> reask;
        {
            std::lock_guard<std::mutex> lk(pmtx_);
            for (const auto& [p, s] : peers_) {
                if (s.hello_ok && s.out_host.empty() && !s.remote_ip.empty() && s.remote_listen != 0)
                    outs.emplace_back(s.remote_ip, s.remote_listen);
                if (s.out_host.empty()) continue;
                ++out;
                if (s.hello_ok) outs.emplace_back(s.out_host, s.out_port);
            }
            for (const auto& [p, s] : peers_)
                if (s.hello_ok && nowc - s.getaddr_tx_ms >= o_.addr_reask_ms) reask.push_back(p);
        }
        std::set<std::string> skip = linked_keys();
        for (const std::string& k : linked_node_keys()) skip.insert(k);
        {
            std::lock_guard<std::mutex> lk(tmtx_);
            for (const Target& t : targets_) {
                skip.insert(rly::peer_key(t.host, t.port));
                if (t.learned && !t.used) ++out;
            }
        }
        if (dialing_ && !partitioned_ && out < o_.max_outbound) {
            const auto c = book_.dial_candidates(o_.max_outbound - out, now, skip);
            std::lock_guard<std::mutex> lk(tmtx_);
            for (const rly::PeerRecord& r : c) {
                Target t;
                t.host = r.host;
                t.port = r.port;
                t.learned = true;
                targets_.push_back(t);
                st_.disc_dialed++;
            }
        }
        if (out < o_.max_outbound)
            for (std::uint64_t p : reask) send_getaddr(p);
        if (nowc - disc_slow_ms_ >= 60000) {
            disc_slow_ms_ = nowc;
            for (const auto& [h, pt] : outs) book_.mark_good(h, pt, now);
            st_.disc_expired += book_.expire(now);
        }
        if (nowc - disc_saved_ms_ >= o_.book_save_ms) {
            disc_saved_ms_ = nowc;
            save_book(false);
        }
    }

    // ---- Monero contexts (FB_GETCTX / FB_CTX) ----
    void serve_getctx(std::uint64_t p, const std::vector<std::uint8_t>& f) {
        std::uint32_t chain = 0;
        std::vector<Hash32> ids;
        std::string why;
        if (!rly::decode_getctx(f, chain, ids, &why)) {
            st_.malformed++;
            token(p, FrameToken::Strike);
            return;
        }
        if (chain != chain_id_) {
            st_.wrong_chain++;
            return;
        }
        std::vector<std::uint8_t> blob;
        for (const Hash32& id : ids) {
            blob.clear();
            const std::size_t cap = ctx_frame_cap();
            const bool have = ctx_.block_blob && ctx_.block_blob(id, blob) && !blob.empty() && blob.size() <= cap;
            if (!have) blob.clear();
            const std::vector<std::uint8_t> r = rly::encode_ctx(chain_id_, id, blob, cap);
            if (r.empty() || !send_link(p, r)) continue;
            if (have)
                st_.ctx_served++;
            else
                st_.ctx_unknown_tx++;
        }
    }
    void on_ctx(std::uint64_t p, const std::vector<std::uint8_t>& f) {
        std::uint32_t chain = 0;
        Hash32 id{};
        std::vector<std::uint8_t> blob;
        std::string why;
        const std::size_t cap = ctx_frame_cap();
        if (f.size() >= rly::kCtxHeader && f[0] == rly::FB_CTX && rly::le::get32(f.data() + 38) > cap &&
            f.size() == rly::kCtxHeader + rly::le::get32(f.data() + 38)) {
            st_.ctx_over_cap++;  // P-13: a well-formed frame of a block over the cap is dropped (no token)
            return;
        }
        if (!rly::decode_ctx(f, chain, id, blob, cap, &why)) {
            st_.malformed++;
            token(p, FrameToken::Strike);
            return;
        }
        if (chain != chain_id_) {
            st_.wrong_chain++;
            return;
        }
        st_.ctx_rx++;
        (void)offer_ctx(id, blob, p);
    }
    // P-13 for an FB_CTX frame read or served: max(the policy, blob_cap_ctx at the node's view), never below
    // blob_cap_ctx(16, zone(16)) (a view that answers 0, or none).
    std::size_t ctx_frame_cap() const {
        const std::uint64_t floor = blob_cap_ctx(kHf16, zone(kHf16)).value_or(0);
        const std::uint64_t view = ctx_.view_cap ? ctx_.view_cap() : 0;
        return static_cast<std::size_t>(std::max({view, floor, o_.ctx_block_cap}));
    }
    std::uint32_t ctx_bound_of(CtxClass c) const noexcept {
        return c == CtxClass::Receipt ? o_.ctx_max_depth : o_.ctx_join_depth;
    }
    std::size_t ctx_cap_of(CtxClass c) const noexcept {
        return c == CtxClass::Receipt ? o_.ctx_want_max : static_cast<std::size_t>(o_.ctx_join_depth);
    }
    // A want of class `cls`: counted in its own class only. A held want is raised to a higher class (and its bound)
    // within that class's cap; a new want past its class's cap is held as a receipt's (P-06) within that cap.
    void want_ctx(const Hash32& id, std::uint64_t from, std::uint32_t depth, CtxClass cls) {
        const bool by_object = cls != CtxClass::Join;  // a frame's or a catch-up's DEFER (not a join attempt's own)
        std::lock_guard<std::mutex> lk(cmtx_);
        std::array<std::size_t, 3> n{};
        for (const auto& kv : ctx_want_) ++n[static_cast<std::size_t>(kv.second.cls)];
        const auto ci = static_cast<std::size_t>(cls);
        const auto it = ctx_want_.find(id);
        if (it != ctx_want_.end()) {
            if (it->second.from == 0 && from != 0) it->second.from = from;
            if (cls > it->second.cls && n[ci] < ctx_cap_of(cls)) {
                it->second.cls = cls;
                it->second.bound = ctx_bound_of(cls);
            }
            return;
        }
        if (cls != CtxClass::Receipt && n[ci] >= ctx_cap_of(cls)) cls = CtxClass::Receipt;  // past its class's cap
        const std::uint32_t bound = ctx_bound_of(cls);
        if (depth >= bound) return;
        if (cls == CtxClass::Receipt && n[0] >= ctx_cap_of(CtxClass::Receipt)) return;
        CtxWant w;
        w.from = from;
        w.depth = depth;
        w.bound = bound;
        w.cls = cls;
        w.since_ms = now_ms();
        ctx_want_.emplace(id, std::move(w));
        st_.ctx_wanted++;
        if (const auto g = std::find(ctx_gave_up_ids_.begin(), ctx_gave_up_ids_.end(), id);
            by_object && g != ctx_gave_up_ids_.end()) {
            ctx_gave_up_ids_.erase(g);  // re-made by a DEFER after it gave up: a join pair waiting on it is tried again
            ctx_remade_.push_back(id);
        }
    }
    // Under cmtx_: a want that gave up, kept by id (at most the wants' bound, the oldest out first).
    void note_gave_up_locked(const Hash32& id) {
        if (std::find(ctx_gave_up_ids_.begin(), ctx_gave_up_ids_.end(), id) != ctx_gave_up_ids_.end()) return;
        ctx_gave_up_ids_.push_back(id);
        while (ctx_gave_up_ids_.size() > o_.ctx_want_max + 2 * std::size_t{o_.ctx_join_depth}) ctx_gave_up_ids_.pop_front();
    }
    bool ctx_resolved(const Hash32& id) const {
        std::lock_guard<std::mutex> lk(cmtx_);
        return std::find(ctx_done_.begin(), ctx_done_.end(), id) != ctx_done_.end();
    }
    // A block blob for a wanted id, from a peer or this node's own source (from 0): verified, its work judged, then
    // fed to the follower. True: resolved.
    bool offer_ctx(const Hash32& id, const std::vector<std::uint8_t>& blob, std::uint64_t from) {
        if (from != 0 && !ctx_.chain && !blob.empty()) {  // nothing to judge a peer's block against
            st_.ctx_unchecked++;
            return false;
        }
        {
            std::lock_guard<std::mutex> lk(cmtx_);
            const auto it = ctx_want_.find(id);
            if (it == ctx_want_.end() || it->second.have_proof) return false;
            if (blob.empty()) {
                if (from != 0) {
                    st_.ctx_unknown_rx++;
                    it->second.last_ask_ms = 0;  // "unknown here": the next peer is asked now
                }
                return false;
            }
        }
        rly::BlockCtx bc;
        std::string why;
        if (!rly::verify_block_ctx(id, blob, bc, &why)) {
            st_.ctx_bad++;
            log("relay: context " + hex_short(id) + " from peer " + std::to_string(from) + " REJECTED: " + why);
            if (from != 0) token(from, FrameToken::Strike);
            return false;
        }
        {
            std::lock_guard<std::mutex> lk(cmtx_);
            const auto it = ctx_want_.find(id);
            if (it == ctx_want_.end()) return false;
            it->second.have_proof = true;
            it->second.proof = bc;
            it->second.blob = blob;
            it->second.proof_from = from;
            std::size_t held = 0;
            for (const auto& kv : ctx_want_) held += kv.second.blob.size();
            if (held > ctx_want_bytes_peak_) ctx_want_bytes_peak_ = held;
        }
        return judge_ctx(id);
    }
    // The work behind a held proof (the node's own chain index); usable: accepted; forged: its sender banned; not
    // judgeable now: kept (its parent wanted while within ctx_max_depth).
    bool judge_ctx(Hash32 id) {
        for (std::size_t guard = 0; guard < o_.ctx_want_max + 2 * std::size_t{o_.ctx_join_depth}; ++guard) {
            CtxWant w;
            {
                std::lock_guard<std::mutex> lk(cmtx_);
                const auto it = ctx_want_.find(id);
                if (it == ctx_want_.end() || !it->second.have_proof) return false;
                w = it->second;
            }
            rly::CtxPowVerdict v;
            if (ctx_.chain) {
                try {
                    v = rly::judge_block_ctx(
                            w.proof, ctx_.chain,
                            [this](const Hash32& b) -> std::optional<rly::CtxPowRec> {
                                std::lock_guard<std::mutex> lk(cmtx_);
                                const auto it = ctx_pow_.find(b);
                                if (it == ctx_pow_.end()) return std::nullopt;
                                return it->second;
                            },
                            w.bound, ctx_.rx, o_.ctx_block_cap);
                } catch (const RandomxFailure& e) {  // node-internal, a local alarm; the context is judged again later
                    rx_alarm("context " + hex_short(id), e.what());
                    return false;
                }
            } else {
                v.kind = rly::CtxPow::Indexed;  // this node's own source, with no index wired
            }
            if (v.kind == rly::CtxPow::Forged) {
                st_.ctx_forged++;
                {
                    std::lock_guard<std::mutex> lk(cmtx_);
                    ctx_want_.erase(id);
                }
                log("relay: context " + hex_short(id) + " FORGED (" + v.why + ")");
                if (w.proof_from != 0) ban(w.proof_from, "context " + hex_short(id) + " FORGED (" + v.why + ")");
                return false;
            }
            if (v.kind == rly::CtxPow::OverCap) {  // P-13: dropped before hashing; no token; another peer may serve it
                st_.ctx_over_cap++;
                {
                    std::lock_guard<std::mutex> lk(cmtx_);
                    const auto it = ctx_want_.find(id);
                    if (it != ctx_want_.end()) {
                        it->second.have_proof = false;
                        it->second.proof = rly::BlockCtx{};
                        it->second.blob.clear();
                        it->second.last_ask_ms = 0;
                    }
                }
                log("relay: context " + hex_short(id) + " DROPPED (" + v.why + ")");
                return false;
            }
            if (v.kind == rly::CtxPow::Defer) {
                bool first = false;
                {
                    std::lock_guard<std::mutex> lk(cmtx_);
                    const auto it = ctx_want_.find(id);
                    if (it != ctx_want_.end() && !it->second.defer_noted) {
                        it->second.defer_noted = true;
                        first = true;
                    }
                }
                if (first) st_.ctx_deferred++;
                const bool parent_known = ctx_.chain && ctx_.chain.verified(w.proof.parent);
                bool parent_pow = false;
                {
                    std::lock_guard<std::mutex> lk(cmtx_);
                    parent_pow = ctx_pow_.count(w.proof.parent) != 0;
                }
                if (!parent_known && !parent_pow && w.depth + 1 < w.bound)
                    want_ctx(w.proof.parent, w.proof_from != 0 ? w.proof_from : w.from, w.depth + 1, w.cls);
                return false;
            }
            if (v.kind == rly::CtxPow::Accept) {
                std::lock_guard<std::mutex> lk(cmtx_);
                if (ctx_pow_.emplace(id, rly::CtxPowRec{w.proof.parent, v.step}).second) {
                    ctx_pow_order_.push_back(id);
                    while (ctx_pow_order_.size() > kCtxPowKeep) {
                        ctx_pow_.erase(ctx_pow_order_.front());
                        ctx_pow_order_.pop_front();
                    }
                }
            }
            if (ctx_.accept) {
                const NodeGuard g(*this);
                ctx_.accept(w.proof, w.blob);
            }
            st_.ctx_resolved++;
            Hash32 child{};
            bool has_child = false;
            {
                std::lock_guard<std::mutex> lk(cmtx_);
                ctx_want_.erase(id);
                ctx_done_.push_back(id);
                while (ctx_done_.size() > o_.ctx_want_max + 2 * std::size_t{o_.ctx_join_depth}) ctx_done_.pop_front();
                for (const auto& [cid, cw] : ctx_want_)
                    if (cw.have_proof && cw.proof.parent == id) {
                        child = cid;
                        has_child = true;
                        break;
                    }
            }
            ccv_.notify_all();
            rerun_ready_ctx(id);  // the frames parked on this id's inputs, those held now
            if (!has_child) return true;
            id = child;
        }
        return false;
    }
    // Maintenance: own source first, then the sender, then every other ready peer, each once per round (bounded
    // rounds); a kept proof judged again at the ask pace.
    void drive_ctx() {
        const std::vector<std::uint64_t> ready = ready_peers();
        const std::uint64_t now = now_ms();
        std::map<std::uint64_t, std::vector<Hash32>> ask;
        std::vector<Hash32> retry, local;
        {
            std::lock_guard<std::mutex> lk(cmtx_);
            for (auto it = ctx_local_ms_.begin(); it != ctx_local_ms_.end();)  // the looks older than the pace leave
                it = now - it->second >= kCtxLocalMs ? ctx_local_ms_.erase(it) : std::next(it);
            for (auto it = ctx_want_.begin(); it != ctx_want_.end();) {
                CtxWant& w = it->second;
                if (now - w.since_ms > kCtxTtlMs) {
                    st_.ctx_gave_up++;
                    note_gave_up_locked(it->first);
                    it = ctx_want_.erase(it);
                    continue;
                }
                if (w.have_proof) {
                    if (now - w.last_ask_ms >= o_.ctx_retry_ms) {
                        w.last_ask_ms = now;
                        retry.push_back(it->first);
                    }
                    ++it;
                    continue;
                }
                if (ctx_.block_blob) {  // the own source at most once per kCtxLocalMs per id, across wants
                    const auto [lm, fresh] = ctx_local_ms_.emplace(it->first, now);
                    if (fresh || now - lm->second >= kCtxLocalMs) {
                        lm->second = now;
                        local.push_back(it->first);
                    }
                }
                if (w.last_ask_ms != 0 && now - w.last_ask_ms < o_.ctx_retry_ms) {
                    ++it;
                    continue;
                }
                if (!ctx_.chain) {  // nothing to check a peer's block against: own sources only
                    ++it;
                    continue;
                }
                std::uint64_t pick = 0;
                if (w.from != 0 && w.asked.count(w.from) == 0 && std::find(ready.begin(), ready.end(), w.from) != ready.end())
                    pick = w.from;
                for (std::uint64_t q : ready)
                    if (pick == 0 && w.asked.count(q) == 0) pick = q;
                if (pick == 0) {
                    if (!ready.empty() && !w.asked.empty()) {
                        w.asked.clear();
                        ++w.rounds;
                        w.last_ask_ms = now;
                    }
                    if (w.rounds >= o_.ctx_max_rounds) {
                        st_.ctx_gave_up++;
                        note_gave_up_locked(it->first);
                        it = ctx_want_.erase(it);
                        continue;
                    }
                    ++it;
                    continue;
                }
                std::vector<Hash32>& v = ask[pick];
                if (v.size() >= rly::kCtxMaxIds) {
                    ++it;
                    continue;
                }
                v.push_back(it->first);
                w.asked.insert(pick);
                w.last_ask_ms = now;
                ++it;
            }
        }
        for (const Hash32& id : local) {
            std::vector<std::uint8_t> blob;
            if (ctx_.block_blob(id, blob) && !blob.empty()) (void)offer_ctx(id, blob, 0);
        }
        for (const auto& [p, ids] : ask) {
            const std::vector<std::uint8_t> f = rly::encode_getctx(chain_id_, ids);
            if (!f.empty() && send_link(p, f)) st_.ctx_asked += ids.size();
        }
        for (const Hash32& id : retry) (void)judge_ctx(id);
    }
    // PathbNodeIo::fetch_context (a join attempt's Monero context): the block from this node's own source or any
    // peer within timeout_s.
    bool fetch_context(const Hash32& id, std::uint64_t timeout_s) {
        const JoinRelease rel(*this);
        const std::uint64_t deadline = now_ms() + timeout_s * 1000;
        if (ctx_.block_blob) {
            std::vector<std::uint8_t> blob;
            want_ctx(id, 0, 0, CtxClass::Join);
            if (ctx_.block_blob(id, blob) && !blob.empty() && offer_ctx(id, blob, 0)) return true;
        }
        want_ctx(id, 0, 0, CtxClass::Join);
        drive_ctx();
        if (!o_.threads) {
            while (!ctx_resolved(id) && now_ms() < deadline && drive_ && drive_()) {
            }
            return ctx_resolved(id);
        }
        std::unique_lock<std::mutex> lk(ccv_m_);
        while (running_ && now_ms() < deadline) {
            if (ctx_resolved(id)) return true;
            ccv_.wait_for(lk, std::chrono::milliseconds(std::min<std::uint64_t>(deadline - now_ms(), o_.ctx_retry_ms)));
            lk.unlock();
            drive_ctx();
            lk.lock();
        }
        return ctx_resolved(id);
    }

    // ---- members ----
    struct NetDrop {
        std::uint64_t peer = 0;
        std::uint64_t src = 0;
        bool ban = false;
    };

    PathbRelayOptions o_;
    RelayLinks& links_;
    RelayClock clock_;
    LogFn log_;
    PathbNode* node_ = nullptr;
    PathbCtxSource ctx_;
    std::function<bool()> drive_;
    std::uint64_t nonce_ = 0;
    std::set<std::string> self_keys_;
    PathbRelayStats st_;
    RelayBudget budget_;

    // the node's values (attach)
    std::uint32_t chain_id_ = 0;
    LaneParams p_ = kRuledLaneParams;
    RelayBuffers buffers_{};
    std::uint64_t headers_frame_ = 0;
    std::uint64_t bucket_frame_ = 0;
    std::uint64_t abandon_s_ = kAbandonTimeoutDefault;
    std::uint16_t header_max_ = 1;

    RelayNodeLock lock_;  // the node lock
    // owned by the node lock
    std::map<Missing, std::set<Hash32>> parked_by_cause_;
    std::map<std::pair<Missing, Hash32>, std::set<Hash32>> parked_ctx_;  // Monero-input DEFERs by (cause, id)
    std::uint64_t swept_frames_record_ = 0;
    std::uint64_t index_adds_ = 0;  // digests indexed since the last prune of the park index  // the best chain's H(L) at the last seal sweep of the parked frames
    std::map<Hash32, std::pair<std::uint64_t, Job>> parked_receipts_;  // DEFERred receipts by key: (seq, job and asks)
    std::map<std::uint64_t, Hash32> parked_receipt_order_;             // by seq: the oldest first (P-09)
    std::uint64_t parked_receipt_seq_ = 0;
    std::map<std::uint64_t, Hash32> receipt_due_;  // parked receipts whose cause resolved, by seq: run again with room
    std::uint64_t swept_record_ = 0;               // the best chain's H(L) at the last seal sweep of the receipt park
    bool bucket_stalled_ = false;
    bool reask_due_ = false;

    std::mutex rmtx_;  // re-offer cursors
    struct ReofferQueue {
        std::deque<Hash32> q;  // the ids to offer, oldest first
        std::set<Hash32> ids;  // the ids in q (each queued once)
    };
    std::map<std::uint64_t, ReofferQueue> reoffer_;
    std::map<std::uint64_t, std::uint64_t> reoffer_t0_;  // a re-offer's start (ms), by peer
    std::set<std::uint64_t> pumping_;  // the peers whose re-offer a thread is pumping
    std::atomic<std::uint64_t> rx_ok_{0};    // RandomX hashes computed (node and context)
    std::atomic<std::uint64_t> rx_mark_{0};  // rx_ok_ at the last RandomX failure
    std::atomic<bool> rx_failing_{false};    // a RandomX failure since the last hash computed
    mutable std::mutex emtx_;  // events
    std::condition_variable ecv_;
    std::condition_variable fcv_;      // a reader waiting for its peer's event in flight
    std::set<std::uint64_t> inflight_;  // peers with a posted event in flight (emtx_)
    std::deque<std::function<void()>> events_;

    mutable std::mutex vmtx_;  // verify queue, parked list, the budget, the strikes
    std::condition_variable vcv_;
    std::deque<Job> vq_;
    std::deque<Job> parked_;
    ::c2pool::xmr::CarrierDosBudget dos_;
    std::map<std::uint64_t, std::uint64_t> strikes_by_peer_;
    std::map<std::uint64_t, ValidBucket> valid_;  // P-15 (vmtx_)
    ClaimAlarmBudget claim_budget_{kRuledLaneParams};  // P-50 (vmtx_)
    double valid_rate_ = 0;
    double valid_cap_ = 0;
    double solicited_ = 0;          // P-21 credits
    std::uint64_t solicited_ms_ = 0;

    mutable std::mutex pmtx_;  // peers
    std::map<std::uint64_t, PeerSt> peers_;
    std::set<std::uint64_t> up_done_;
    std::condition_variable upcv_;
    std::map<std::string, std::uint64_t> addr_nonce_;

    mutable std::mutex tmtx_;  // dial targets, deferred drops
    std::vector<Target> targets_;
    std::vector<NetDrop> to_drop_;

    mutable std::mutex kmtx_;  // tickets
    std::condition_variable kcv_;
    std::map<std::uint64_t, Ticket> tickets_;
    std::map<std::uint64_t, std::deque<HdrWait>> hdr_fifo_;
    std::map<std::uint64_t, std::uint64_t> hdr_arrived_;  // replies to node requests arrived, not handled yet (kmtx_)
    std::map<std::uint64_t, std::set<Hash32>> asked_carriers_;  // ids of the node's own FC_GETCARRIER, per peer
    std::map<std::uint64_t, std::set<Hash32>> bodyset_asked_;   // walked carriers whose body set is asked, per peer
    std::uint64_t next_ticket_ = 0;
    JoinPort port_;

    mutable std::mutex cumtx_;  // catch-up and t's branch headers waiting for a free request (under the node lock)
    std::map<std::uint64_t, Catchup> catchup_;
    std::map<std::uint64_t, std::deque<HdrWant>> header_wants_;  // peer -> its waiting header requests, oldest first
    std::map<std::uint64_t, std::vector<HdrOnCtx>> headers_on_ctx_;  // deferred on a P_r: peer -> per (owner, from, stop)
    std::map<std::uint64_t, HdrSent> hdr_sent_;  // the tip request in flight per peer and its objects (cumtx_)

    mutable std::mutex omtx_;                          // the omission log
    std::map<std::uint64_t, std::uint64_t> omissions_;  // link id -> receipts omitted (at most the links up)
    std::uint64_t omitted_total_ = 0;
    VerdictCounts verdicts_{};  // [row][verdict]
    mutable std::mutex cmtx_;  // contexts
    std::map<Hash32, CtxWant> ctx_want_;
    std::map<Hash32, std::uint64_t> ctx_local_ms_;  // the last own-source look per id (kept for kCtxLocalMs)
    std::deque<Hash32> ctx_gave_up_ids_;            // ids whose want gave up (the wants' bound)
    std::vector<Hash32> ctx_remade_;                // ... wanted again since (the join pairs on them released)
    std::size_t ctx_want_bytes_peak_ = 0;  // the most blob bytes ctx_want_ held at once
    std::deque<Hash32> ctx_done_;
    std::map<Hash32, rly::CtxPowRec> ctx_pow_;
    std::deque<Hash32> ctx_pow_order_;
    std::mutex ccv_m_;
    std::condition_variable ccv_;

    std::mutex jmtx_;  // the join worker
    std::condition_variable jcv_;
    bool join_due_ = false;
    std::atomic<std::uint64_t> join_not_before_ms_{0};

    std::mutex mmtx_;  // the maintenance thread
    std::condition_variable mcv_;
    bool maint_wake_ = false;

    rly::PeerBook book_;
    std::string dial_host_;  // the address being dialed (the maintenance thread)
    std::uint16_t dial_port_ = 0;
    std::uint64_t disc_tick_ms_ = 0;
    std::uint64_t disc_slow_ms_ = 0;
    std::uint64_t disc_saved_ms_ = 0;
    std::uint64_t live_tick_ms_ = 0;
    std::atomic<std::uint64_t> ping_nonce_{0};
    std::atomic<bool> dialing_{true};
    std::atomic<bool> partitioned_{false};
    std::atomic<std::uint64_t> partition_until_ms_{0};

    std::atomic<bool> running_{false};
    std::thread owner_;
    std::vector<std::thread> verify_;
    std::thread join_;
    std::thread maint_;

    static inline thread_local const PathbRelayNode* t_node_held = nullptr;  // the relay whose node lock this thread holds
    static inline thread_local const PathbRelayNode* t_join_relay = nullptr;     // the join worker's relay
    static inline thread_local const PathbRelayNode* t_dialing_relay = nullptr;  // the relay dialing on this thread
};

}  // namespace c2pool::xmr::pathb
