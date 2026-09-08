#pragma once
// V37 Track A2 step (b)(3) — carrier SEND-SIDE queue: THIS node's OWN stratum
// wins (share-level AND block-level) emitted as FROZEN CarrierWire (W3-B5)
// carriers to every connected peer, off the stratum hot path.
//
// CONSUMER-tree code (src/c2pool/v37/). NON-CONSENSUS: every append rides
// CarrierRelay -> CarrierIngest -> V37Engine (never src/sharechain/v37 canon).
//
// WHAT THIS ADDS over carrier_emit.hpp's CarrierEmitter (the H-BLOCK draft):
//   * SHARE-LEVEL wins. The pool's actual "stratum wins" are the solves that
//     clear the SHARE target (work_source.cpp:2891 share arm); the block arm is
//     a rare subset. The daemon binds DASHWorkSource::set_mint_share_fn (the
//     H-SHARE seam, work_source.hpp:188 MintShareFn) to submit(); that seam
//     fires on BOTH arms (won_block=false share arm, won_block=true block arm
//     AFTER the block dispatch, #887/#888), so this ONE binding covers every
//     own win. The H-BLOCK emission in the SubmitBlockFn is therefore removed
//     by the assemble step — never both, or a block win is minted+flooded twice.
//   * PER-MINER IDENTITY (S-2). The carrier's PayoutDescriptor is the MINER's
//     (MintShareInputs::payout_script, DASH-validated from the stratum
//     username, -> ::v37::canonicalize_script), not a fixed pool placeholder,
//     and the prev_own_share chain is kept PER IDENTITY (w2_admission.hpp:175
//     binds prev-own per identity). A win with NO payout identity (foreign /
//     malformed username -> empty script) is DECLINED for a share and falls
//     back to the configured pool descriptor for a BLOCK win (a block-winning
//     carrier is never dropped for want of an identity — W3-G1 spirit).
//   * OFF THE HOT PATH (S-3). submit() is O(1) under a tiny mutex and never
//     touches the RPC-backed index, the admit lock, or a socket: the stratum
//     io thread hands the win to ONE dedicated worker (MPSC queue) that does
//     resolve-parent (1 getblockheader RPC via IMainchainIndex) -> grind ->
//     admit -> flood. Arrival order into the engine is still exactly the order
//     admit() sees (carrier_ingest.hpp:21-25) — the queue only moves WHICH
//     thread calls admit, not the ordering rule.
//   * W3-G1 for block winners. won_block=true routes through
//     CarrierRelay::append_block_winner (unconditional append, never gated by
//     relay dedup / backpressure — the #889/#903 class); shares go through
//     handle_local. The queue itself never sheds a block winner: only shares
//     are subject to the bounded-queue cap.
//   * BOUNDED PATIENCE for a block winner's parent (I-2). IMainchainIndex
//     collapses Missing/Unknown into nullopt; a block winner retries the
//     resolve a few times with a short backoff before giving up (a share does
//     not — at share rates that would multiply RPC load for nothing).
//   * TAG CAP (S-4). Tags are bookkeeping only, NOT in the PoW preimage
//     (w2_receipt.hpp:214) yet relayed verbatim; this side clamps its own tags
//     to kCarrierSendTagMax so the daemon never originates a bloated tag.
//
// HONEST BOUNDARY (restate in every commit): the minted carrier still carries
// the SYNTHETIC RDWR sha256d envelope (prev_block_hash / prev_own / lz / nonce
// ground to consensus_lz(parent height) leading-zero bits), NOT the DASH X11
// share; a peer cannot verify the DASH share from it (S-1 / real share format).
// What is REAL after step (b): the WIRE (frozen), the INDEX (live dashd height
// of a real parent block), the payout IDENTITY (the miner's own script), and
// the cross-node FLOW (a carrier keyed to a real block, minted by the node
// whose stratum miner solved it, accounted by a peer through its own index).
// Under --carrier-synthetic-index the real parent hashes never resolve, so
// every own win ends as UNRESOLVED_PARENT here (counted, not ground) — expected
// under that debug flag (S-5).
//
// The share tracker behind the admitter stays in-memory (MemShareTracker):
// the prev-own chain here resets to W2_GENESIS_PREV_OWN on restart, which W2
// always accepts for a carrier (carriers are not prev-own-checked at all in
// ReceiptAdmitter::admit; only receipts are). The persisted store is W6's.
//
// stdlib + std::thread only (no Boost, no uint256, no coin backend): the
// stratum-specific glue (MintShareInputs -> OwnWinRequest, uint256 return) is
// a ten-line lambda in main_v37_btc_dash.cpp, so this header stays testable in
// the stdlib harness next to carrier_net.hpp / carrier_ingest.hpp.

#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstring>
#include <deque>
#include <functional>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "carrier_emit.hpp"     // mint_work_event
#include "w2_admission.hpp"     // IMainchainIndex
#include "w2_receipt.hpp"       // WorkEvent, bytes32, consensus_lz, W2_GENESIS_PREV_OWN
#include "w3_relay.hpp"         // Carrier, CarrierRelay

namespace c2pool::v37n {

// S-4: the longest tag this node ORIGINATES. "win:"+16 hex = 20 B, "share:"+16
// hex = 22 B; anything longer is clamped. Well under any decode-side cap the
// F-1 freeze decision may add (recommended <= 64) — this is the origin-side
// discipline, that is the network-side one.
constexpr std::size_t kCarrierSendTagMax = 32;

inline std::string clamp_carrier_tag(std::string tag) {
    if (tag.size() > kCarrierSendTagMax) tag.resize(kCarrierSendTagMax);
    return tag;
}

// ── one own win, as the send-side sees it ───────────────────────────────────
struct OwnWinRequest {
    bytes32 prev_block_internal{};              // header hashPrevBlock = header[4..36), INTERNAL order
    std::vector<std::uint8_t> payout_script;    // the miner's output script (empty = no identity)
    bool won_block = false;                     // #889: this solve was ALSO a coin block
    std::string tag;                            // bookkeeping only; clamped on submit
};

// Build a request from the raw stratum solve fields. `header` is the 80-byte
// solved header (MintShareInputs::header_bytes); hashPrevBlock sits at [4..36)
// in internal byte order — exactly what a WorkEvent.prev_block_hash carries
// (w2_receipt.hpp §mainchain bin) and what LiveMainchainIndex's bound probe
// (carrier_index.hpp + display_hex_of_bytes32) reverses to display hex before
// asking dashd. nullopt on a short header.
inline std::optional<OwnWinRequest>
own_win_request_of_header(const std::vector<unsigned char>& header,
                          std::vector<std::uint8_t> payout_script,
                          bool won_block, std::string tag) {
    if (header.size() < 80) return std::nullopt;
    OwnWinRequest r;
    std::memcpy(r.prev_block_internal.data(), header.data() + 4, 32);
    r.payout_script = std::move(payout_script);
    r.won_block     = won_block;
    r.tag           = clamp_carrier_tag(std::move(tag));
    return r;
}

// The carrier's payout identity from the miner's output script. Total via
// canonicalize_script (template kinds 0..4, else RAW=255 carrying the script so
// the RAW binding payload == sha256d(raw_script) validates). nullopt for an
// empty script (foreign-coin / malformed username: work_source.cpp:2637-2645
// leaves payout_script empty) or a descriptor the canon rejects.
inline std::optional<::v37::PayoutDescriptor>
descriptor_of_payout_script(const std::vector<std::uint8_t>& script) {
    if (script.empty()) return std::nullopt;
    ::v37::PayoutDescriptor d;
    d.pay = ::v37::canonicalize_script(script);
    if (d.pay.kind == ::v37::ScriptKind::RAW) d.raw_script = script;
    if (!d.valid()) return std::nullopt;
    return d;
}

// ── the per-identity own-share chain (S-2) ──────────────────────────────────
// prev_own_share is committed in the PoW preimage per IDENTITY; one chain per
// miner. Advances only on a locally-ADMITTED carrier, so a rejected mint never
// leaves a dangling prev_own. Not consensus, not persisted (see header note).
class OwnShareChains {
public:
    bytes32 last(const bytes32& identity) const {
        std::lock_guard<std::mutex> lk(m_mtx);
        auto it = m_last.find(identity);
        return it == m_last.end() ? W2_GENESIS_PREV_OWN : it->second;
    }
    void advance(const bytes32& identity, const bytes32& admitted_hash) {
        std::lock_guard<std::mutex> lk(m_mtx);
        m_last[identity] = admitted_hash;
    }
    std::size_t size() const {
        std::lock_guard<std::mutex> lk(m_mtx);
        return m_last.size();
    }
private:
    mutable std::mutex m_mtx;
    std::map<bytes32, bytes32> m_last;
};

// ── diagnostics (never consensus) ───────────────────────────────────────────
struct CarrierSendStats {
    std::uint64_t submitted = 0;          // submit() calls that were queued
    std::uint64_t shed_shares = 0;        // shares refused: queue at max_queued_shares
    std::uint64_t after_stop = 0;         // submit() after stop(): refused
    std::uint64_t abandoned_at_stop = 0;  // still queued when stop() ran (shares)
    std::uint64_t processed = 0;          // worker took the item off the queue
    std::uint64_t no_identity = 0;        // declined: empty/invalid payout script (share)
    std::uint64_t fallback_identity = 0;  // block win emitted under the fallback descriptor
    std::uint64_t unresolved_parent = 0;  // index could not place prev_block (no grind)
    std::uint64_t mint_exhausted = 0;     // nonce budget exhausted (never at lz 8..9)
    std::uint64_t admitted = 0;           // locally accounted own carriers
    std::uint64_t rejected = 0;           // minted but W2 rejected (dedup / target / chain)
    std::uint64_t block_winners = 0;      // of admitted: went through append_block_winner
    std::uint64_t relayed = 0;            // reached >= 1 peer
    std::uint64_t deferred_relay = 0;     // admitted but 0 peers (DEFER, never dropped)
    std::uint64_t peers_reached_total = 0;
};

// ═══════════════════════════════════════════════════════════════════════════
// CarrierSendQueue — the dedicated emit worker behind the stratum mint seam.
//
//   stratum io thread            worker thread                 relay / peers
//   ─────────────────            ─────────────                 ─────────────
//   submit(req) ─ O(1) ─►  [MPSC]  resolve parent (index)  ─► grind (2^lz)
//                                  admit (CarrierIngest)   ─► flood (net)
//
// One instance per node, bound to the node's CarrierRelay and the SAME
// IMainchainIndex the receive side admits against (so origin and peers agree
// on the parent height / horizon / byte order). Construct, start(), bind
// submit() into set_mint_share_fn, stop() BEFORE CarrierPeerNode::stop() and
// the engine drain (the worker may be mid-flood).
// ═══════════════════════════════════════════════════════════════════════════
class CarrierSendQueue {
public:
    struct Options {
        // Shares beyond this many queued are SHED (counted, logged). Block
        // winners are NEVER shed (W3-G1: no backpressure gate on a block win).
        std::size_t max_queued_shares = 4096;
        // I-2 bounded patience for a BLOCK winner's parent resolve (the index
        // returns nullopt for Missing AND Unknown; a transient dashd hiccup
        // must not lose the block-winning carrier). Shares try once.
        unsigned block_resolve_attempts = 5;
        std::chrono::milliseconds block_resolve_backoff{200};
        // Nonce budget per grind; 2^24 is a safety cap far above the 2^8..2^9
        // expected tries of the synthetic schedule.
        u64 max_grind_tries = u64(1) << 24;
        // Identity for a BLOCK win whose miner has no payout script (empty).
        // Shares without an identity are declined; a block win falls back here
        // so the block-winning carrier still enters the chain. nullopt = decline.
        std::optional<::v37::PayoutDescriptor> fallback_desc;
        // At stop(): finish queued BLOCK winners (bounded by the attempts above);
        // queued shares are abandoned (counted). false = abandon everything.
        bool drain_block_winners_on_stop = true;
        // CarrierRelay (w3_relay.hpp) has NO internal lock: its RelaySeenSet is
        // a bare std::set and CarrierPeerNode runs one reader thread PER PEER
        // into handle_inbound, so >= 2 peers already race on it, and this
        // worker adds handle_local / append_block_winner. Preferred fix is a
        // mutex INSIDE CarrierRelay (one lock_guard per public handler). Until
        // that lands, point this at a mutex the daemon ALSO takes in its
        // set_inbound lambda; the worker then holds it across the relay call
        // only (never across the resolve RPC or the grind). nullptr = none.
        std::mutex* relay_mutex = nullptr;
    };

    // (warn, line): the daemon binds LOG_WARNING / LOG_INFO; tests may print.
    using LogFn = std::function<void(bool warn, const std::string& line)>;

    CarrierSendQueue(CarrierRelay& relay, const IMainchainIndex& index,
                     std::uint32_t chain_id, Options opt)
        : m_relay(relay), m_index(index), m_chain(chain_id), m_opt(std::move(opt)) {}
    // Defaults. (A separate overload rather than `Options opt = {}`: GCC rejects
    // a braced default argument of a nested struct with default member
    // initializers inside the enclosing class body.)
    CarrierSendQueue(CarrierRelay& relay, const IMainchainIndex& index, std::uint32_t chain_id)
        : CarrierSendQueue(relay, index, chain_id, Options()) {}

    ~CarrierSendQueue() { stop(); }
    CarrierSendQueue(const CarrierSendQueue&) = delete;
    CarrierSendQueue& operator=(const CarrierSendQueue&) = delete;

    void set_log(LogFn f) {
        std::lock_guard<std::mutex> lk(m_log_mtx);
        m_log = std::move(f);
    }

    // Spawn the worker. Idempotent. Items submitted before start() stay queued.
    void start() {
        std::lock_guard<std::mutex> lk(m_q_mtx);
        if (m_worker.joinable() || m_stopped) return;
        m_worker = std::thread([this] { worker_loop(); });
    }

    // Signal, drain block winners (if configured), join. Idempotent. After
    // stop(), submit() refuses (counted as after_stop).
    void stop() {
        {
            std::lock_guard<std::mutex> lk(m_q_mtx);
            if (m_stopped) return;
            m_stopped = true;
        }
        m_q_cv.notify_all();
        if (m_worker.joinable()) m_worker.join();
        // Whatever the worker left (shares, or everything when not draining).
        std::deque<OwnWinRequest> left;
        {
            std::lock_guard<std::mutex> lk(m_q_mtx);
            left.swap(m_q);
        }
        if (!left.empty()) {
            std::lock_guard<std::mutex> lk(m_stats_mtx);
            m_stats.abandoned_at_stop += left.size();
        }
        for (const auto& r : left)
            log(true, std::string("[carrier-send] abandoned at stop: ") + (r.won_block ? "BLOCK WIN " : "share ") + r.tag);
    }

    // ── the stratum-thread entry (bind into MintShareFn) ─────────────────────
    // O(1); never blocks on RPC / admit lock / socket. true iff queued. A share
    // is refused when the queue is full; a block winner is always queued.
    bool submit(OwnWinRequest req) {
        req.tag = clamp_carrier_tag(std::move(req.tag));
        {
            std::lock_guard<std::mutex> lk(m_q_mtx);
            if (m_stopped) {
                std::lock_guard<std::mutex> sl(m_stats_mtx);
                ++m_stats.after_stop;
                return false;
            }
            if (!req.won_block && m_q.size() >= m_opt.max_queued_shares) {
                std::lock_guard<std::mutex> sl(m_stats_mtx);
                ++m_stats.shed_shares;
                return false;
            }
            m_q.push_back(std::move(req));
            {
                std::lock_guard<std::mutex> sl(m_stats_mtx);
                ++m_stats.submitted;
            }
        }
        m_q_cv.notify_one();
        return true;
    }

    // ── one emission, synchronously on the CALLING thread ────────────────────
    // What the worker runs per item. Public so a caller already off the hot
    // path (a KAT, a drill tool) can emit deterministically. Serialized under
    // m_emit_mtx with the worker so per-identity chaining stays consistent.
    struct EmitOutcome {
        enum class Status {
            ADMITTED,            // minted, W2-admitted, chain advanced (relay may still DEFER)
            REJECTED,            // minted but W2 rejected (dedup / target / chain)
            NO_IDENTITY,         // share with no payout identity: declined
            UNRESOLVED_PARENT,   // index cannot place prev_block: nothing ground
            MINT_EXHAUSTED,      // nonce budget exhausted
        };
        Status status = Status::NO_IDENTITY;
        bytes32 hash{};                      // the carrier's WorkEvent hash (ADMITTED/REJECTED)
        bytes32 identity{};                  // emitted-under identity (ADMITTED/REJECTED)
        std::optional<u64> parent_height;    // set whenever the resolve succeeded
        unsigned lz_bits = 0;
        bool used_fallback = false;
        CarrierRelay::Outcome relay;         // valid iff ADMITTED/REJECTED
    };

    EmitOutcome emit_now(const OwnWinRequest& req) {
        EmitOutcome o;

        // 1. identity: the miner's own script; a block win may fall back.
        std::optional<::v37::PayoutDescriptor> desc = descriptor_of_payout_script(req.payout_script);
        if (!desc && req.won_block && m_opt.fallback_desc) {
            desc = m_opt.fallback_desc;
            o.used_fallback = true;
        }
        if (!desc) {
            o.status = EmitOutcome::Status::NO_IDENTITY;
            bump([](CarrierSendStats& s) { ++s.no_identity; });
            log(true, "[carrier-send] DECLINED (no payout identity) " + req.tag);
            return o;
        }

        // 2. parent height via the node's index (the SAME index the receive
        //    side admits against: horizon / byte order / live dashd agree).
        o.parent_height = resolve_parent(req.prev_block_internal, req.won_block);
        if (!o.parent_height) {
            o.status = EmitOutcome::Status::UNRESOLVED_PARENT;
            bump([](CarrierSendStats& s) { ++s.unresolved_parent; });
            log(true, std::string("[carrier-send] no carrier for ") + req.tag +
                      ": parent block not in the index (unknown to dashd, off the "
                      "horizon, or --carrier-synthetic-index)");
            return o;
        }
        o.lz_bits = consensus_lz(*o.parent_height);   // R-1 pin: admitters recompute this

        // 3. grind + admit + flood, serialized so the per-identity chain is
        //    consistent between the worker and any emit_now caller.
        std::lock_guard<std::mutex> lk(m_emit_mtx);
        o.identity = desc->identity_key();
        const bytes32 prev_own = m_chains.last(o.identity);
        auto ev = mint_work_event(m_chain, *desc, req.prev_block_internal, prev_own,
                                  o.lz_bits, req.tag, (m_salt++) << 40,
                                  m_opt.max_grind_tries);
        if (!ev) {
            o.status = EmitOutcome::Status::MINT_EXHAUSTED;
            bump([](CarrierSendStats& s) { ++s.mint_exhausted; });
            log(true, "[carrier-send] mint exhausted nonce budget for " + req.tag);
            return o;
        }
        o.hash = ev->hash();
        Carrier c;
        c.carrier = std::move(*ev);
        // W3-G1: a block-winning carrier is appended UNCONDITIONALLY (no relay
        // dedup, no backpressure gate); an ordinary share takes the local path.
        {
            std::unique_lock<std::mutex> rl;
            if (m_opt.relay_mutex) rl = std::unique_lock<std::mutex>(*m_opt.relay_mutex);
            o.relay = req.won_block ? m_relay.append_block_winner(c)
                                    : m_relay.handle_local(c);
        }
        if (o.relay.admitted) {
            o.status = EmitOutcome::Status::ADMITTED;
            m_chains.advance(o.identity, o.hash);     // chain forward only on a real append
            const bool used_fb = o.used_fallback, won = req.won_block;
            const auto reached = o.relay.peers_reached;
            bump([&](CarrierSendStats& s) {
                ++s.admitted;
                if (won) ++s.block_winners;
                if (used_fb) ++s.fallback_identity;
                if (reached) { ++s.relayed; s.peers_reached_total += reached; }
                else ++s.deferred_relay;
            });
            log(false, std::string("[carrier-send] emitted ") + (req.won_block ? "BLOCK WIN " : "share ") +
                       req.tag + " parent@" + std::to_string(*o.parent_height) +
                       " lz=" + std::to_string(o.lz_bits) +
                       " peers_reached=" + std::to_string(o.relay.peers_reached) +
                       (o.relay.peers_reached ? "" : " (relay DEFERRED: no peer)") +
                       (o.used_fallback ? " [fallback identity]" : ""));
        } else {
            o.status = EmitOutcome::Status::REJECTED;
            bump([](CarrierSendStats& s) { ++s.rejected; });
            log(true, std::string("[carrier-send] own carrier REJECTED by W2 for ") + req.tag +
                      " (carrier_status=" + std::to_string(static_cast<int>(o.relay.admission.carrier_status)) + ")");
        }
        return o;
    }

    // Tests / drills: block until the queue is empty and the worker is idle.
    bool wait_idle(std::chrono::milliseconds timeout = std::chrono::milliseconds(5000)) {
        std::unique_lock<std::mutex> lk(m_q_mtx);
        return m_idle_cv.wait_for(lk, timeout, [&] { return m_q.empty() && !m_busy; });
    }

    CarrierSendStats stats() const {
        std::lock_guard<std::mutex> lk(m_stats_mtx);
        return m_stats;
    }
    std::size_t queued() const {
        std::lock_guard<std::mutex> lk(m_q_mtx);
        return m_q.size();
    }
    // The per-identity chain head (diagnostics; W2_GENESIS_PREV_OWN if unseen).
    bytes32 last_own(const bytes32& identity) const { return m_chains.last(identity); }
    std::size_t identities() const { return m_chains.size(); }
    const Options& options() const { return m_opt; }

private:
    std::optional<u64> resolve_parent(const bytes32& prev, bool won_block) {
        const unsigned attempts = won_block ? (m_opt.block_resolve_attempts ? m_opt.block_resolve_attempts : 1u) : 1u;
        for (unsigned i = 0; i < attempts; ++i) {
            if (auto h = m_index.height_of(prev)) return h;
            if (i + 1 < attempts) {
                // A block winner waits a little for dashd (I-2); a share does not.
                std::this_thread::sleep_for(m_opt.block_resolve_backoff);
                if (stopping()) break;
            }
        }
        return std::nullopt;
    }

    void worker_loop() {
        for (;;) {
            OwnWinRequest req;
            {
                std::unique_lock<std::mutex> lk(m_q_mtx);
                m_q_cv.wait(lk, [&] { return m_stopped || !m_q.empty(); });
                if (m_stopped) {
                    // Drain only block winners (bounded work, W3-G1-shaped);
                    // shares are abandoned by stop() and counted there.
                    if (!m_opt.drain_block_winners_on_stop) return;
                    auto it = m_q.begin();
                    while (it != m_q.end() && !it->won_block) ++it;
                    if (it == m_q.end()) return;
                    req = std::move(*it);
                    m_q.erase(it);
                } else {
                    req = std::move(m_q.front());
                    m_q.pop_front();
                }
                m_busy = true;
            }
            bump([](CarrierSendStats& s) { ++s.processed; });
            try {
                (void)emit_now(req);
            } catch (const std::exception& e) {
                log(true, std::string("[carrier-send] emit threw: ") + e.what() + " for " + req.tag);
            } catch (...) {
                log(true, "[carrier-send] emit threw (non-std) for " + req.tag);
            }
            {
                std::lock_guard<std::mutex> lk(m_q_mtx);
                m_busy = false;
            }
            m_idle_cv.notify_all();
        }
    }

    bool stopping() const {
        std::lock_guard<std::mutex> lk(m_q_mtx);
        return m_stopped;
    }
    template <class F>
    void bump(F f) {
        std::lock_guard<std::mutex> lk(m_stats_mtx);
        f(m_stats);
    }
    void log(bool warn, const std::string& line) {
        LogFn f;
        {
            std::lock_guard<std::mutex> lk(m_log_mtx);
            f = m_log;
        }
        if (f) f(warn, line);
    }

    CarrierRelay&            m_relay;
    const IMainchainIndex&   m_index;
    std::uint32_t            m_chain;
    Options                  m_opt;

    // queue
    mutable std::mutex       m_q_mtx;
    std::condition_variable  m_q_cv;
    std::condition_variable  m_idle_cv;
    std::deque<OwnWinRequest> m_q;
    bool                     m_stopped = false;
    bool                     m_busy = false;
    std::thread              m_worker;

    // emission
    std::mutex               m_emit_mtx;
    OwnShareChains           m_chains;
    u64                      m_salt = 0;

    // diagnostics
    mutable std::mutex       m_stats_mtx;
    CarrierSendStats         m_stats;
    std::mutex               m_log_mtx;
    LogFn                    m_log;
};

} // namespace c2pool::v37n
