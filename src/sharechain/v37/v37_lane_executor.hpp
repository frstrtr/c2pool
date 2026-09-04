#pragma once
// V37 lane executor — the O1 message-passing surface over Lane/Roundabout.
// Spec: the v37 concurrency-obligations addendum (WP1 normative O1–O5),
// clauses O1.1–O1.5 and O2.1. Track A2 bring-up step W1.
//
// The shipped Lane/Roundabout headers are the fold INTERNALS: plain mutable
// classes whose accessors (acc(), l0(), levels()) return const references
// into live state. Under O1 those types must never be exposed to the node —
// this executor owns them privately, and this surface is the only thing the
// node shell sees. Lane state is reachable ONLY as (a) value-carrying
// records submitted for in-order application, or (b) immutable published
// snapshots. Misuse is unrepresentable at this surface: there is no lock to
// hold wrong and no live reference to alias.
//
// O1 mapping (clause -> the construct that discharges it):
//   O1.1  submit(LaneRecord) is the only mutation entry; receive() returns
//         shared_ptr<const LaneSnapshot> — an immutable copy, atomically
//         published (pointer swap). Readers holding an older snapshot stay
//         valid: republication replaces the pointer, it never mutates a
//         snapshot that has been handed out.
//   O1.2  No lock exists anywhere in this type (single-writer core), so no
//         header can name one; no public member returns a reference into
//         lane state (static-asserted at the bottom of this header and
//         audited again by test/v37_executor_test.cpp's surface audit).
//   O1.3  The fold is Lane::push — pure over (committed prefix, record).
//         The executor performs no ambient reads while applying a record;
//         all context a record needs travels IN the record, by value.
//   O1.4  Shell/legacy context enters ONLY as value-carrying LaneRecords;
//         submit() never takes an external lock and never calls back out.
//   O1.5  Exactly one writer: the executor is non-copyable/non-movable and
//         every mutation flows through submit() in arrival order; committed
//         records form a total order (ops_committed() is its length). Lane
//         state == fold(genesis, records). The DURABLE record store is the
//         share tracker (feeds the W6 >D rebuild path); this object holds
//         only the fold state, exactly like Lane's own journal discipline.
//   O2.1  Every applied record bumps that lane's monotonic version and every
//         snapshot carries the version it was cut at — the per-lane
//         component of O2's future cut token (W4's settlement read).
//
// CONSENSUS-DETERMINISM / the threading seam: this core is single-threaded
// and deterministic — the ORDER in which records reach submit() IS the
// consensus input (the Lanes.tla §8.3 op-order pin, quoted in v37_lane.hpp:
// rebuild/fold/cascade/insert/evict at positionally defined points; nothing
// node-local enters the sequence). The seam where threads may exist lives
// OUTSIDE this type: a threaded shell funnels ALL records through one FIFO
// into one executor thread, and the queue's pop order is the committed
// order. The shell MUST NOT reorder, batch, defer, or parallelize records,
// and nothing in the consensus path may depend on thread scheduling.
// Snapshot CONTENT is a pure function of the committed record prefix, never
// of when receive() happens to be serviced.

#include <cstdint>
#include <map>
#include <memory>
#include <stdexcept>
#include <type_traits>
#include <utility>
#include <vector>

#include "v37_lane.hpp"
#include "v37_roundabout.hpp"

namespace v37 {

// ── the record vocabulary (O1.1/O1.4: context arrives as values) ──────────
struct LaneRecord {
    enum class Kind : std::uint8_t { AddLane, Push, Rewind, RemoveLane };
    Kind kind = Kind::Push;
    ChainId chain = 0;
    LaneParams params;          // AddLane
    PayoutDescriptor desc;      // Push (validated V37.0: attribution absent)
    u64 w_raw = 0;              // Push
    std::uint32_t flags = 0;    // Push (L0F_* annotation bits)
    u64 depth = 0;              // Rewind

    static LaneRecord add_lane(ChainId c, const LaneParams& p) {
        LaneRecord r; r.kind = Kind::AddLane; r.chain = c; r.params = p;
        return r;
    }
    static LaneRecord push(ChainId c, PayoutDescriptor d, u64 w,
                           std::uint32_t f) {
        LaneRecord r; r.kind = Kind::Push; r.chain = c;
        r.desc = std::move(d); r.w_raw = w; r.flags = f;
        return r;
    }
    static LaneRecord rewind(ChainId c, u64 d) {
        LaneRecord r; r.kind = Kind::Rewind; r.chain = c; r.depth = d;
        return r;
    }
    static LaneRecord remove_lane(ChainId c) {
        LaneRecord r; r.kind = Kind::RemoveLane; r.chain = c;
        return r;
    }
};

// Disposition of one record. Rejections are DETERMINISTIC functions of
// (committed prefix, record) — validation is part of the fold discipline,
// so two nodes applying the same stream reject the same records.
enum class SubmitStatus : std::uint8_t {
    Applied = 0,
    RejectedBadGeometry,        // AddLane: LaneParams validation failed
    RejectedDuplicateLane,      // AddLane: chain id already present
    RejectedUnknownChain,       // Push/Rewind/RemoveLane: no such lane
    RejectedInvalidDescriptor,  // Push: PayoutDescriptor fails V37.0 rules
    RejectedZeroWork,           // Push: w_raw == 0 (rewind bit-exactness)
    RefusedJournal,             // Rewind: journal cannot serve the depth
                                // (d > journaled pushes, or the span crosses
                                // an epoch rebuild). State untouched; the
                                // caller escalates to the full lane rebuild
                                // from the tracker — the W6 path, not W1.
};

struct SubmitResult {
    SubmitStatus status = SubmitStatus::Applied;
    MinerId miner = 0;              // Push+Applied: interned id (NODE-LOCAL;
                                    // never consensus bytes — C-1)
    std::uint64_t lane_version = 0; // that lane's version after this record
                                    // (unchanged when not applied)
    bool applied() const { return status == SubmitStatus::Applied; }
};

// ── the published view (O1.1: immutable; O2.1: versioned) ─────────────────
// Every field is a VALUE COPY cut at publication. Nothing here aliases live
// lane state; mutating the lane after publication cannot change a snapshot.
struct LaneSnapshot {
    std::uint64_t version = 0;   // per-lane, monotonic (O2.1)
    // F2 (W1 finding, folded in by the W0 consumer): a NODE-monotone lane
    // incarnation, minted by the executor on every AddLane and never reused
    // for any ChainId. `version` alone is ABA-unsafe across
    // RemoveLane(c)->AddLane(c) (version resets to 1), so a cut token keying
    // only on (chain, version) can confuse a stale snapshot for the fresh
    // incarnation. The executor is the SOLE minter (X-4); the snapshot merely
    // CARRIES the value so a reader/cut-token (W4) keys on
    // (chain, incarnation, version). 0 = never assigned.
    std::uint64_t incarnation = 0;
    ChainId chain = 0;
    LaneParams params;           // geometry (also digest-committed)
    u64 next_pos = 0;
    u64 epoch_base = 0;
    u64 cover = 0;
    U256 acc_total;              // epoch-frame accumulator total
    U256 decayed_total;          // head-decayed total
    u128 raw_total = 0;
    std::map<MinerId, U256> payout;  // decayed payout map, deep copy.
                                     // Keys are node-local intern ids —
                                     // display/local reads only; the
                                     // consensus quantity is `digest`.
    bytes32 digest{};            // canonical lane digest (MinerIntern::key
                                 // resolver — the consensus commitment)

    // Raw-work bands (L0 slots as single-position bands + closed buckets),
    // so settlement-grade span reads are answerable FROM the snapshot with
    // no live-state access (W4 reads these on versioned snapshots).
    struct Band { u64 pos_lo = 0, pos_hi = 0; u128 raw_work = 0; };
    std::vector<Band> bands;

    // Same containment semantics as Lane::raw_work_in_span (L0 slot counted
    // iff pos in [lo,hi]; bucket counted iff fully contained).
    u128 raw_work_in_span(u64 lo, u64 hi) const {
        u128 sum = 0;
        for (const auto& b : bands)
            if (b.pos_lo >= lo && b.pos_hi <= hi) sum += b.raw_work;
        return sum;
    }
};

// ── the executor: single writer, in-order apply, snapshot publication ─────
class LaneExecutor {
public:
    LaneExecutor() = default;
    // O1.5: exactly one writer per lane set — the object cannot be copied
    // (two writers) or moved out from under a shell holding it.
    LaneExecutor(const LaneExecutor&) = delete;
    LaneExecutor& operator=(const LaneExecutor&) = delete;
    LaneExecutor(LaneExecutor&&) = delete;
    LaneExecutor& operator=(LaneExecutor&&) = delete;

    // Apply one record, strictly in arrival order (O1.1/O1.5). Returns the
    // disposition BY VALUE. Never leaks a reference; never throws for data-
    // dependent rejections (they are dispositions, not exceptions — a
    // deterministic function of the committed prefix and the record).
    SubmitResult submit(const LaneRecord& r) {
        switch (r.kind) {
        case LaneRecord::Kind::AddLane: {
            if (m_rb.lane(r.chain))
                return {SubmitStatus::RejectedDuplicateLane, 0,
                        version(r.chain)};
            try {
                m_rb.add_lane(r.chain, r.params);
            } catch (const std::invalid_argument&) {
                return {SubmitStatus::RejectedBadGeometry, 0, 0};
            }
            auto& cell = m_cells[r.chain];
            cell.version = 1;
            cell.incarnation = ++m_next_incarnation;  // F2: sole minter (X-4)
            ++m_ops;
            return {SubmitStatus::Applied, 0, cell.version};
        }
        case LaneRecord::Kind::Push: {
            Lane* l = m_rb.lane(r.chain);
            if (!l)
                return {SubmitStatus::RejectedUnknownChain, 0, 0};
            if (r.w_raw == 0)
                return {SubmitStatus::RejectedZeroWork, 0, version(r.chain)};
            if (!r.desc.valid(false))
                return {SubmitStatus::RejectedInvalidDescriptor, 0,
                        version(r.chain)};
            MinerId id = m_rb.push(r.chain, r.desc, r.w_raw, r.flags);
            auto& cell = m_cells[r.chain];
            ++cell.version;
            ++m_ops;
            return {SubmitStatus::Applied, id, cell.version};
        }
        case LaneRecord::Kind::Rewind: {
            Lane* l = m_rb.lane(r.chain);
            if (!l)
                return {SubmitStatus::RejectedUnknownChain, 0, 0};
            if (r.depth == 0)   // no-op record: applied, nothing changed
                return {SubmitStatus::Applied, 0, version(r.chain)};
            if (!l->rewind(r.depth))
                return {SubmitStatus::RefusedJournal, 0, version(r.chain)};
            auto& cell = m_cells[r.chain];
            ++cell.version;
            ++m_ops;
            return {SubmitStatus::Applied, 0, cell.version};
        }
        case LaneRecord::Kind::RemoveLane: {
            if (!m_rb.lane(r.chain))
                return {SubmitStatus::RejectedUnknownChain, 0, 0};
            m_rb.remove_lane(r.chain);
            m_cells.erase(r.chain);
            ++m_ops;
            return {SubmitStatus::Applied, 0, 0};
        }
        }
        return {SubmitStatus::RejectedUnknownChain, 0, 0};  // unreachable
    }

    // Publish-and-return the immutable snapshot for one lane (O1.1). The
    // returned object is shared ownership of a VALUE COPY: the caller may
    // hold it across any number of later submits. Returns nullptr for an
    // unknown chain. Publication is cached per version — repeated receives
    // between mutations return the same published object; content is a pure
    // function of the committed record prefix either way.
    //
    // F1 (W1 finding): this call MUTATES the per-lane cache (m_cells) on a
    // version miss, so it is EXECUTOR-THREAD-ONLY — it is NOT a reader-safe
    // API despite returning a shared_ptr. Reader threads MUST consume the
    // published mailbox (the shell's per-lane atomic snapshot slot, stored by
    // the executor thread from this call), never call receive() themselves.
    std::shared_ptr<const LaneSnapshot> receive(ChainId chain) {
        const Lane* l = m_rb.lane(chain);
        if (!l) return nullptr;
        auto& cell = m_cells[chain];
        if (cell.published && cell.published->version == cell.version)
            return cell.published;
        cell.published = build_snapshot(chain, *l, cell.version,
                                        cell.incarnation);
        return cell.published;
    }

    // Current committed version of one lane (0 = unknown chain). O2.1.
    std::uint64_t version(ChainId chain) const {
        auto it = m_cells.find(chain);
        return it == m_cells.end() ? 0 : it->second.version;
    }

    // Length of the committed total order across all lanes (O1.5).
    std::uint64_t ops_committed() const { return m_ops; }

private:
    struct LaneCell {
        std::uint64_t version = 0;
        std::uint64_t incarnation = 0;   // F2: current incarnation of this lane
        std::shared_ptr<const LaneSnapshot> published;
    };

    // The ONLY place the Lane accessors' const references into live state
    // are touched (the F-2 allowance: fold executor, copying into an
    // immutable snapshot at publication). Everything is copied by value.
    std::shared_ptr<const LaneSnapshot> build_snapshot(
        ChainId chain, const Lane& l, std::uint64_t v,
        std::uint64_t incarnation) const {
        auto s = std::make_shared<LaneSnapshot>();
        s->version = v;
        s->incarnation = incarnation;   // F2: carry the executor-minted id
        s->chain = chain;
        s->params = l.params();
        s->next_pos = l.next_pos();
        s->epoch_base = l.epoch_base();
        s->cover = l.cover();
        s->acc_total = l.acc_total();
        s->decayed_total = l.decayed_total();
        s->raw_total = l.raw_total();
        s->payout = l.payout_map();
        s->digest = m_rb.lane_digest(chain);
        s->bands.reserve(l.l0().size() + 16);
        for (const auto& slot : l.l0())
            s->bands.push_back({slot.pos, slot.pos, slot.w_raw});
        for (const auto& lvl : l.levels())
            for (const auto& b : lvl)
                s->bands.push_back({b.pos_lo, b.pos_hi, b.raw_work});
        return s;
    }

    Roundabout m_rb;                     // owned; never escapes
    std::map<ChainId, LaneCell> m_cells;
    std::uint64_t m_ops = 0;
    // F2: the single node-monotone incarnation source (X-4: exactly one
    // minter). Bumped on every AddLane, never reset, never reused for any
    // ChainId across the node's life. A W0 mailbox/shell MUST NOT run its
    // own counter — it only carries this value out through the snapshot.
    std::uint64_t m_next_incarnation = 0;
};

// ── O1.2 surface audit, compile-time where expressible ────────────────────
// A C++ compiler cannot see caller-held locks; the achievable and
// sufficient standard (O1.2's own wording) is lock-gone-from-surface. The
// executor contains no lock AT ALL, so none can be named; the asserts below
// pin the rest — every public entry returns a value or shared-const, never
// a reference, and the writer cannot be duplicated. The F-D1 call-site grep
// (no acc()/l0()/levels()/push() outside this header) is the test suite's
// and CI's job (the FM-5/FM-6 static audit gates).
static_assert(std::is_same_v<decltype(std::declval<LaneExecutor&>().submit(
                                 std::declval<const LaneRecord&>())),
                             SubmitResult>,
              "O1.2: submit must return its disposition by value");
static_assert(std::is_same_v<decltype(std::declval<LaneExecutor&>().receive(
                                 ChainId{})),
                             std::shared_ptr<const LaneSnapshot>>,
              "O1.1/O1.2: receive must return a shared immutable snapshot");
static_assert(!std::is_reference_v<decltype(std::declval<const LaneExecutor&>()
                                                .version(ChainId{}))>,
              "O1.2: version is a value");
static_assert(!std::is_reference_v<decltype(std::declval<const LaneExecutor&>()
                                                .ops_committed())>,
              "O1.2: ops_committed is a value");
static_assert(!std::is_copy_constructible_v<LaneExecutor> &&
                  !std::is_copy_assignable_v<LaneExecutor> &&
                  !std::is_move_constructible_v<LaneExecutor> &&
                  !std::is_move_assignable_v<LaneExecutor>,
              "O1.5: exactly one writer — the executor cannot be duplicated");

} // namespace v37
