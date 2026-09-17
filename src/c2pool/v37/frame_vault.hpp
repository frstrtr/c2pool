#pragma once
// V37 Track A2 / Stage 1 SUPPLY — the unified bounded FRAME VAULT.
// CONSUMER-tree code (src/c2pool/v37/). It retains carrier FRAME BYTES and the
// (chain, lane position) -> carrier-hash index that no other structure in this
// tree holds. It is NOT consensus code: it owns no lane, computes no digest,
// admits nothing, and every byte it hands out is a byte some peer already put
// on the wire (or that we already broadcast ourselves).
//
// ── THE GAP IT CLOSES (code-grounded, on c2pool#1655 head 5636d8f1) ─────────
// Nothing in this tree can answer "which carrier sits at lane position 1551937,
// and what were its bytes?":
//   * ::v37::L0Slot (src/sharechain/v37/v37_lane.hpp) = {pos, w_raw, w_scaled,
//     miner, flags, version, origin_bin} — NO carrier hash.
//   * ::v37::LaneRecord::Push = {chain, desc, w_raw, flags} — NO hash.
//   * SettlementView / LaneSnapshot carry next_pos + digest — NO hashes.
//   * RelaySeenSet is an unordered set of hashes; MemShareTracker is
//     identity -> set<hash>. Neither is ORDERED by lane position.
//   * w6 CarrierRec is keyed by share hash and orders only by walking prev_hash
//     backwards from TipRec — and the btc-dash daemon never instantiates W6.
// So a node that has fallen behind cannot even NAME the carriers it is missing,
// let alone fetch their bytes. c2pool#1655 added a small re-offer buffer that
// keeps the exact broadcast frame for redelivery, but it is keyed only by hash,
// holds ~60 s of history, and is fed only from do_broadcast().
//
// ── WHAT THIS IS ────────────────────────────────────────────────────────────
// ONE bounded store, written once per ADMITTED carrier, with two indices:
//   * BY POSITION — an ordered map pos_first -> slot. This is the (chain, pos)
//     -> carrier-hash index. It is what lets a serving node answer GETORDER at
//     a cut: "the ordered carrier ids for positions [a, P)".
//   * BY HASH     — hash -> slot, so GETFRAMES can serve a bounded id set, and
//     so the re-offer sweep can find the exact bytes it broadcast.
// Retention reaches back to the lane WINDOW horizon (W, default 8640 positions)
// instead of the re-offer's ~60 s, because a replay-supply request names a
// prefix that may be hours old. The c2pool#1655 re-offer keeps its own, much
// shallower RECENT SUB-VIEW over this store (w3_relay.hpp): same bytes, same
// entry, different retention policy — one copy of the frame, not two.
//
// ── MEMORY IS BOUNDED THREE WAYS, EXPLICITLY ────────────────────────────────
//   (1) max_entries      — hard FIFO cap on retained carriers  (default 16384)
//   (2) max_bytes        — hard FIFO cap on retained frame bytes (default 32 MiB)
//   (3) horizon_positions— anything more than W positions behind the highest
//                          retained position is evicted            (default 8640)
// Whichever binds first, binds. A single frame larger than max_bytes is never
// retained at all. The WORST CASE is therefore max_bytes + O(max_entries) index
// overhead: with the transport's 1 MiB kMaxCarrierFrame ceiling the byte cap
// binds at 32 frames; with realistic ~200-400 byte carriers the position
// horizon binds at W frames (~3 MiB). Both are stated, neither is unbounded.
//
// ── WHY THIS CANNOT MOVE A CONSENSUS BYTE ───────────────────────────────────
// The vault is written AFTER W2 admission has already returned its verdict, and
// it is read only to copy bytes onto a socket. It calls no admitter, no engine,
// no lane, no settlement fold. Serving a frame to a peer is byte-for-byte the
// same act as broadcasting it, and the receiver judges it exactly once through
// its own W2 DedupWindow (w2_admission.hpp "a replayed carrier is not
// re-credited"). Nothing here is in kAcceptedVersions and nothing here is a
// wire-version change.
//
// THREADING: self-synchronizing. Every public method takes m_mtx. It NEVER
// calls out (no callback, no transport, no admitter), so it is always a LEAF in
// the lock order — a caller may hold the relay mutex across a vault call, and
// the serve path may take the vault lock with no other lock held.

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <map>
#include <mutex>
#include <optional>
#include <utility>
#include <vector>

#include <sharechain/v37/v37_hash.hpp>   // ::v37::bytes32

namespace c2pool::v37n {

using ::v37::bytes32;

// ── configuration (all three bounds are hard) ───────────────────────────────
struct FrameVaultOptions {
    bool          enabled           = true;
    // (1) entry cap.
    std::size_t   max_entries       = 16384;
    // (2) byte cap. 32 MiB: comfortably above W=8640 realistic carriers
    //     (~3 MiB) and a hard ceiling when frames run large.
    std::size_t   max_bytes         = 32u << 20;
    // (3) the LANE WINDOW horizon, in lane positions. An entry more than this
    //     many positions behind the highest retained position is evicted: a
    //     replay-supply request can never usefully name a prefix older than the
    //     window, because the lane itself has already decayed past it.
    std::uint64_t horizon_positions = 8640;
};

struct FrameVaultStats {
    std::uint64_t inserted          = 0;   // fresh entries admitted into the vault
    std::uint64_t refreshed         = 0;   // an entry we already held, seen again
    std::uint64_t evicted_capacity  = 0;   // dropped: entry cap or byte cap
    std::uint64_t evicted_horizon   = 0;   // dropped: past the window horizon
    std::uint64_t rejected_oversize = 0;   // frame larger than max_bytes: never held
    std::uint64_t order_queries     = 0;
    std::uint64_t order_ids_served  = 0;
    std::uint64_t frame_queries     = 0;
    std::uint64_t frames_served     = 0;
    std::uint64_t frames_missing    = 0;   // an id asked for that we do not hold
};

// One ordered id the position index resolved: the lane position the carrier
// ARRIVED at (EmittedPush::pos of its first push) and the carrier's
// WorkEvent::hash. `pos` is strictly increasing across a served run.
struct VaultOrderId {
    std::uint64_t pos = 0;
    bytes32       id{};
    bool operator==(const VaultOrderId&) const = default;
};

// The answer to "your ordered carrier ids for [a, P)".
enum class VaultOrderStatus : std::uint8_t {
    OK          = 0,   // `a` is inside what we retain; `ids` is the exact prefix
    BELOW_HORIZON = 1, // `a` is older than anything we still hold: serve NOTHING
    DISABLED    = 2,   // the vault is off on this node
    BAD_RANGE   = 3,   // a > p
};

struct VaultOrder {
    VaultOrderStatus          status = VaultOrderStatus::OK;
    std::uint64_t             a = 0;
    // The exclusive end actually covered. Equals the requested P when the whole
    // range fitted; otherwise the position of the first entry we did NOT serve,
    // so the requester can ask again from there. Never claims coverage it did
    // not serve.
    std::uint64_t             p_served = 0;
    std::uint64_t             lowest_retained = 0;   // diagnostics for the requester
    std::vector<VaultOrderId> ids;
};

// ═══════════════════════════════════════════════════════════════════════════
// FrameVault
// ═══════════════════════════════════════════════════════════════════════════
class FrameVault {
public:
    using Clock = std::chrono::steady_clock;

    // A carrier we broadcast but whose admission gave us no position (the
    // append_block_winner path can broadcast an un-admitted frame) is stored
    // hash-only, so GETFRAMES can still serve it and the re-offer can still
    // find its bytes. It is deliberately absent from the position index.
    static constexpr std::uint64_t kNoPos = ~std::uint64_t{0};

    struct Entry {
        bytes32                   hash{};
        std::uint32_t             chain = 0;
        std::uint64_t             pos_first = kNoPos;  // EmittedPush::pos of push[0]
        std::uint32_t             n_pushes = 0;        // carrier + accepted receipts
        std::vector<std::uint8_t> frame;               // VERBATIM CarrierWire bytes
        Clock::time_point         at{};
    };

    FrameVault() = default;
    explicit FrameVault(const FrameVaultOptions& o) : m_opt(o) {}

    void set_options(const FrameVaultOptions& o) {
        std::lock_guard<std::mutex> lk(m_mtx);
        m_opt = o;
        if (!o.enabled) { clear_locked(); return; }
        enforce_capacity_locked(0);
        enforce_horizon_locked();
    }
    FrameVaultOptions options() const {
        std::lock_guard<std::mutex> lk(m_mtx); return m_opt;
    }
    FrameVaultStats stats() const {
        std::lock_guard<std::mutex> lk(m_mtx); return m_stats;
    }
    std::size_t size() const {
        std::lock_guard<std::mutex> lk(m_mtx); return m_q.size();
    }
    std::size_t bytes() const {
        std::lock_guard<std::mutex> lk(m_mtx); return m_bytes;
    }
    void clear() {
        std::lock_guard<std::mutex> lk(m_mtx); clear_locked();
    }

    // ── write side ──────────────────────────────────────────────────────────
    // Retain one carrier's EXACT frame bytes. `pos_first` is the lane position
    // its first push landed at (kNoPos when the carrier was not admitted here).
    // Returns the entry's SLOT (a monotone handle that survives other entries'
    // eviction), or nullopt when the frame was not retained at all.
    //
    // Idempotent by hash: a carrier we already hold is refreshed in place (the
    // bytes are not re-copied, and the position is filled in if we learn it
    // later), never stored twice.
    std::optional<std::uint64_t> insert(std::uint32_t chain, const bytes32& hash,
                                        std::uint64_t pos_first, std::uint32_t n_pushes,
                                        const std::vector<std::uint8_t>& frame,
                                        Clock::time_point now = Clock::now()) {
        std::lock_guard<std::mutex> lk(m_mtx);
        if (!m_opt.enabled) return std::nullopt;
        if (frame.size() > m_opt.max_bytes) { ++m_stats.rejected_oversize; return std::nullopt; }

        if (auto it = m_by_hash.find(hash); it != m_by_hash.end()) {
            Entry* e = entry_locked(it->second);
            if (e) {
                e->at = now;
                if (e->pos_first == kNoPos && pos_first != kNoPos) {
                    e->pos_first = pos_first;
                    e->n_pushes = n_pushes;
                    m_by_pos[pos_first] = it->second;
                    if (m_high_pos == kNoPos || pos_first > m_high_pos) m_high_pos = pos_first;
                }
                ++m_stats.refreshed;
                return it->second;
            }
            m_by_hash.erase(it);   // stale index row (already evicted): fall through
        }

        enforce_capacity_locked(frame.size());
        if (m_q.size() + 1 > m_opt.max_entries || m_bytes + frame.size() > m_opt.max_bytes)
            return std::nullopt;   // cannot fit even after eviction

        Entry e;
        e.hash = hash;
        e.chain = chain;
        e.pos_first = pos_first;
        e.n_pushes = n_pushes;
        e.frame = frame;
        e.at = now;
        const std::uint64_t slot = m_base + m_q.size();
        m_bytes += e.frame.size();
        m_q.push_back(std::move(e));
        m_by_hash.emplace(hash, slot);
        if (pos_first != kNoPos) {
            m_by_pos[pos_first] = slot;
            if (m_high_pos == kNoPos || pos_first > m_high_pos) m_high_pos = pos_first;
        }
        ++m_stats.inserted;
        enforce_horizon_locked();
        // The entry we just added can itself be evicted by the horizon sweep
        // (a very old position arriving late); report honestly.
        auto still = m_by_hash.find(hash);
        if (still == m_by_hash.end()) return std::nullopt;
        return still->second;
    }

    // ── read side: bytes ────────────────────────────────────────────────────
    // Copy out the frame held for `slot` (nullopt if it has been evicted, or if
    // the slot now holds a different carrier). Used by the re-offer sub-view,
    // which stores slots and re-validates the hash.
    std::optional<std::vector<std::uint8_t>> frame_at(std::uint64_t slot,
                                                      const bytes32& expect_hash) const {
        std::lock_guard<std::mutex> lk(m_mtx);
        const Entry* e = entry_locked(slot);
        if (!e || !(e->hash == expect_hash)) return std::nullopt;
        return e->frame;
    }

    bool holds(const bytes32& hash) const {
        std::lock_guard<std::mutex> lk(m_mtx);
        auto it = m_by_hash.find(hash);
        return it != m_by_hash.end() && entry_locked(it->second) != nullptr;
    }

    // Serve a BOUNDED id set: copies out (id, frame) for every id we hold, in
    // the order asked, stopping at `max_frames` or `max_bytes`. Ids we do not
    // hold are simply absent — the REQUESTER treats a missing id as a
    // fail-closed outcome (carrier_supply.hpp); the server never fabricates.
    std::size_t serve_frames(const std::vector<bytes32>& ids,
                             std::size_t max_frames, std::size_t max_bytes,
                             std::vector<std::pair<bytes32, std::vector<std::uint8_t>>>& out) const {
        std::lock_guard<std::mutex> lk(m_mtx);
        ++m_stats.frame_queries;
        out.clear();
        if (!m_opt.enabled) return 0;
        std::size_t acc = 0;
        for (const bytes32& id : ids) {
            if (out.size() >= max_frames) break;
            auto it = m_by_hash.find(id);
            const Entry* e = (it == m_by_hash.end()) ? nullptr : entry_locked(it->second);
            if (!e) { ++m_stats.frames_missing; continue; }
            if (acc + e->frame.size() > max_bytes) break;
            acc += e->frame.size();
            out.emplace_back(id, e->frame);
            ++m_stats.frames_served;
        }
        return out.size();
    }

    // ── read side: the ORDER at a cut ───────────────────────────────────────
    // "The ordered carrier ids you appended at positions [a, p), on `chain`."
    // This is the answer that does not exist anywhere else in the tree.
    VaultOrder serve_order(std::uint32_t chain, std::uint64_t a, std::uint64_t p,
                           std::size_t max_ids) const {
        std::lock_guard<std::mutex> lk(m_mtx);
        ++m_stats.order_queries;
        VaultOrder r;
        r.a = a;
        r.p_served = a;
        r.lowest_retained = lowest_pos_locked();
        if (!m_opt.enabled) { r.status = VaultOrderStatus::DISABLED; return r; }
        if (a > p)          { r.status = VaultOrderStatus::BAD_RANGE; return r; }
        // FAIL-CLOSED on the serve side too: if `a` predates everything we still
        // retain we cannot serve a CONTIGUOUS prefix, and a gapped answer would
        // be a lie about our own order. Say so instead.
        if (!m_q.empty() && a < r.lowest_retained) {
            r.status = VaultOrderStatus::BELOW_HORIZON;
            return r;
        }
        for (auto it = m_by_pos.lower_bound(a); it != m_by_pos.end(); ++it) {
            if (it->first >= p) break;
            const Entry* e = entry_locked(it->second);
            if (!e) continue;                       // stale index row
            if (e->chain != chain) continue;
            if (r.ids.size() >= max_ids) { r.p_served = it->first; return r; }
            r.ids.push_back(VaultOrderId{it->first, e->hash});
            ++m_stats.order_ids_served;
        }
        r.p_served = p;
        return r;
    }

    // Lowest / highest lane position still retained (0 / kNoPos when empty).
    std::uint64_t lowest_position() const {
        std::lock_guard<std::mutex> lk(m_mtx); return lowest_pos_locked();
    }
    std::uint64_t highest_position() const {
        std::lock_guard<std::mutex> lk(m_mtx); return m_high_pos;
    }

private:
    void clear_locked() {
        m_q.clear(); m_by_pos.clear(); m_by_hash.clear();
        m_bytes = 0; m_high_pos = kNoPos;
    }

    Entry* entry_locked(std::uint64_t slot) {
        if (slot < m_base) return nullptr;
        const std::uint64_t i = slot - m_base;
        if (i >= m_q.size()) return nullptr;
        return &m_q[static_cast<std::size_t>(i)];
    }
    const Entry* entry_locked(std::uint64_t slot) const {
        if (slot < m_base) return nullptr;
        const std::uint64_t i = slot - m_base;
        if (i >= m_q.size()) return nullptr;
        return &m_q[static_cast<std::size_t>(i)];
    }

    std::uint64_t lowest_pos_locked() const {
        return m_by_pos.empty() ? 0 : m_by_pos.begin()->first;
    }

    void evict_front_locked() {
        Entry& e = m_q.front();
        auto hit = m_by_hash.find(e.hash);
        if (hit != m_by_hash.end() && hit->second == m_base) m_by_hash.erase(hit);
        if (e.pos_first != kNoPos) {
            auto pit = m_by_pos.find(e.pos_first);
            if (pit != m_by_pos.end() && pit->second == m_base) m_by_pos.erase(pit);
        }
        m_bytes -= e.frame.size();
        m_q.pop_front();
        ++m_base;
    }

    void enforce_capacity_locked(std::size_t incoming) {
        while (!m_q.empty() &&
               (m_q.size() + 1 > m_opt.max_entries ||
                m_bytes + incoming > m_opt.max_bytes)) {
            ++m_stats.evicted_capacity;
            evict_front_locked();
        }
    }

    // Evict from the FRONT while the front entry is more than `horizon` lane
    // positions behind the highest position we hold. A hash-only entry (kNoPos)
    // at the front STOPS this sweep — it carries no position to compare — but it
    // is still bounded by the entry/byte caps above, so memory stays bounded.
    void enforce_horizon_locked() {
        if (m_opt.horizon_positions == 0 || m_high_pos == kNoPos) return;
        while (!m_q.empty()) {
            const Entry& f = m_q.front();
            if (f.pos_first == kNoPos) break;
            if (m_high_pos - f.pos_first < m_opt.horizon_positions) break;
            ++m_stats.evicted_horizon;
            evict_front_locked();
        }
    }

    mutable std::mutex      m_mtx;
    FrameVaultOptions       m_opt{};
    mutable FrameVaultStats m_stats{};
    std::deque<Entry>       m_q;
    std::uint64_t           m_base = 0;          // slot of m_q.front()
    std::size_t             m_bytes = 0;
    std::uint64_t           m_high_pos = kNoPos;
    std::map<std::uint64_t, std::uint64_t> m_by_pos;    // lane pos -> slot (ORDERED)
    std::map<bytes32, std::uint64_t>       m_by_hash;   // carrier hash -> slot
};

} // namespace c2pool::v37n
