#pragma once
// V37 Track A2 / W2 — RDWR receipt-admission pipeline + push emitter.
// CONSUMER-tree code (src/c2pool/v37/). Spec: v37-a2-w2-ingestion-spec.md §3
// (admission — where it runs and the stateless pipeline) and §4 (from an
// accepted receipt to a Roundabout::push). Reference: rdwr_ref.py (golden
// 7ac46235); this reproduces its dispositions / ordered push tuples / dedup /
// expiry / R_MAX bit-for-bit.
//
// WHERE IT RUNS (spec §3): admission is the v36 share-check position, strictly
// BEFORE any push. The C++ Lane never sees a receipt — by design it sees only
// (descriptor, w_raw, flags). All receipt semantics (PoW recompute, binding
// checks, N_CTX expiry, dedup) live here, ahead of the push; only the
// accept/reject decision and the resulting flagged push cross into the engine.
//
// W2-F-A RULING (operator, 2026-09-04): OPTION (a) — carrier-position credit
// for V37.0. Each accepted receipt's work is credited at the carrier/arrival
// position (what Lane::push does natively — it always appends at next_pos; it
// has NO bin/position argument). There is NO origin-bin positioned insert. So
// the receipt push is an ORDINARY push of work(T_origin) at the carrier's
// position, distinguished only by the annotation-only L0F_RECEIPT bit.
//
// THE PUSH SEQUENCE (spec §4.2, a fixed consensus rule): for an accepted
// carrier and its accepted receipts, in wire order —
//   1. carrier : push(chain, carrier_descriptor, work(T_carrier), carrier_flags)
//   2. receipts: for each accepted receipt i, push(chain, carrier_descriptor,
//                work(T_origin_i), carrier_flags | L0F_RECEIPT)
// Every push — carrier and receipt alike — advances the lane position by 1
// (W2-F-E: "receipts never advance the clock" is the BIN clock, not next_pos).
// The emitter MUST NOT reorder, batch, defer, or parallelize any of it.

#include <cstdint>
#include <functional>
#include <map>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "w2_receipt.hpp"

namespace c2pool::v37n {

// ── injectable seams (KAT plan §2; spec §5.1 architecture) ─────────────────
// The node's mainchain index: height_of(hashPrevBlock) with a context horizon;
// unresolvable within the horizon -> nullopt (share-format §2).
struct IMainchainIndex {
    virtual ~IMainchainIndex() = default;
    virtual std::optional<u64> height_of(const bytes32& prev_block_hash) const = 0;
};

// The durable share tracker (NOT lane state): the prev-own-share source, and
// the store the carrier (a chained share) is recorded into on admission. W2
// reads has_prev_own for the binding check; the carrier's own recording is the
// share-admission step the carrier goes through (spec §3.1 step 3).
struct IShareTracker {
    virtual ~IShareTracker() = default;
    virtual bool has_prev_own(const bytes32& identity,
                              const bytes32& prev_own_share) const = 0;
    virtual void record_share(const bytes32& identity,
                              const bytes32& share_hash) = 0;
};

// ── dispositions (consensus order of spec §3.1) ────────────────────────────
// A receipt failing several checks reports the FIRST in this order:
//   PoW -> R-1 -> identity -> prev-own -> chain -> expiry -> dedup.
enum class Disposition {
    OK,
    REJECT_POW,           // step 1: header.hash does not meet its own target
    REJECT_R1_TARGET,     // step 2: T_origin != consensus target for bin(receipt)
    REJECT_IDENTITY,      // step 3a: payout identity != carrier's (self-carriage)
    REJECT_PREV_OWN,      // step 3b: prev_own_share not on the miner's chain
    REJECT_CHAIN,         // step 3c: chain_id mismatch
    REJECT_EXPIRED,       // step 4: unresolvable / future / older than N_CTX
    REJECT_DEDUP,         // step 5: header.hash already in the window
};

enum class CarrierStatus {
    OK,
    REJECT_RMAX,          // > R_MAX receipts: whole carrier rejected at decode
    REJECT_POW,           // carrier PoW / target / chain / unresolvable bin
    REJECT_DEDUP,         // a replayed carrier is not re-credited
};

// ── the dedup / window store (share-format §5) ─────────────────────────────
// A hash set of accounted work events (chained shares AND receipts), retained
// for N_CTX+2 bins, pruned on clock advance. Derivable, NOT a digest leaf.
// W2-F-D / F2: keyed on lane INCARNATION, never on (chain, version) alone
// (version ABAs across RemoveLane->AddLane) — reset it on a lane re-creation.
class DedupWindow {
public:
    DedupWindow(std::uint32_t chain, u64 incarnation)
        : m_chain(chain), m_incarnation(incarnation) {}

    bool contains(const bytes32& h) const { return m_events.count(h) != 0; }
    void add(const bytes32& h, u64 at_bin) { m_events[h] = at_bin; }
    void prune(u64 now_bin) {
        // retained for DEDUP_RETENTION bins; drop entries older than the horizon
        u64 cutoff = now_bin >= W2_DEDUP_RETENTION ? now_bin - W2_DEDUP_RETENTION : 0;
        for (auto it = m_events.begin(); it != m_events.end();) {
            if (it->second < cutoff) it = m_events.erase(it);
            else ++it;
        }
    }
    std::size_t size() const { return m_events.size(); }
    std::uint32_t chain() const { return m_chain; }
    u64 incarnation() const { return m_incarnation; }

private:
    std::uint32_t m_chain;
    u64 m_incarnation;
    std::map<bytes32, u64> m_events;   // event hash -> bin it was accounted in
};

// ── one emitted weight-credit push ─────────────────────────────────────────
// `identity` (the reference identity key, committed in the preimage) drives the
// binding and the push-sequence commitment; `descriptor` is the real
// PayoutDescriptor the push is applied under (self-carriage). Meta fields carry
// the credit-placement data (KR-1) but do NOT affect the push itself under
// ruling (a) — the position is always the carrier arrival position.
struct EmittedPush {
    bytes32 identity{};
    ::v37::PayoutDescriptor descriptor;
    u64 w_raw = 0;
    std::uint32_t flags = 0;
    // credit-placement / determinism data (spec §4.4, KR-1):
    u64 pos = 0;           // carrier arrival position (ruling (a): the credit pos)
    u64 origin_bin = 0;    // bin(event) — the (demoted) T-OQ1 credit-intent datum
    u64 carrier_bin = 0;
    std::string tag;
    u64 age_delta() const { return carrier_bin - origin_bin; }
};

// A sink for accepted pushes. Production sink forwards each to
// V37Engine::submit_tracked (a LaneRecord::push); the KAT sink tees (records the
// tuple AND forwards to a real engine).
using RecordSink = std::function<void(const EmittedPush&)>;

// ── the admitter / emitter (spec §3-§4) ────────────────────────────────────
class ReceiptAdmitter {
public:
    ReceiptAdmitter(std::uint32_t chain_id, const IMainchainIndex& index,
                    IShareTracker& tracker, u64 incarnation = 1)
        : m_chain(chain_id), m_index(index), m_tracker(tracker),
          m_window(chain_id, incarnation), m_incarnation(incarnation) {}

    // F2 / W2-F-D: RemoveLane -> AddLane resets the lane-scoped admission state.
    // The durable tracker (share store) is NOT reset — only the window / the
    // node-local position counter, keyed on the new incarnation.
    void reset_incarnation(u64 new_incarnation) {
        m_incarnation = new_incarnation;
        m_window = DedupWindow(m_chain, new_incarnation);
        m_next_pos = 0;
        m_raw_total = 0;
    }

    struct Result {
        CarrierStatus carrier_status = CarrierStatus::OK;
        std::vector<std::pair<std::string, Disposition>> receipts;  // (tag, disp)
        std::vector<EmittedPush> pushes;   // in emission order (also -> sink)
    };

    // Per-receipt stateless validation, in the fixed consensus order (spec §3.1).
    Disposition validate_receipt(const WorkEvent& r, const WorkEvent& carrier,
                                 u64 carrier_bin) const {
        // 1. PoW against the receipt's OWN bits.
        if (!r.meets_own_target()) return Disposition::REJECT_POW;
        // 2. R-1 pinning: T_origin == consensus target for bin(receipt). Only
        //    when the bin resolves (an unresolvable bin is caught at step 4).
        std::optional<u64> rb = m_index.height_of(r.prev_block_hash);
        if (rb.has_value() && r.lz_bits != consensus_lz(*rb))
            return Disposition::REJECT_R1_TARGET;
        // 3a. self-carriage: payout identity == the carrier's.
        if (!(r.identity == carrier.identity)) return Disposition::REJECT_IDENTITY;
        // 3b. prev-own-share on the miner's chain (durable tracker, not lane).
        if (!m_tracker.has_prev_own(r.identity, r.prev_own_share))
            return Disposition::REJECT_PREV_OWN;
        // 3c. chain id.
        if (r.chain_id != m_chain) return Disposition::REJECT_CHAIN;
        // 4. context window: unresolvable, future, or older than N_CTX.
        if (!rb.has_value() || *rb > carrier_bin || carrier_bin - *rb > W2_N_CTX)
            return Disposition::REJECT_EXPIRED;
        // 5. dedup (the single window dedup).
        if (m_window.contains(r.hash())) return Disposition::REJECT_DEDUP;
        return Disposition::OK;
    }

    // Whole-carrier admission (W2 owns steps 4-6 of share-format §8). Emits the
    // deterministic push sequence (§4.2) through `sink` and returns it.
    Result admit(const WorkEvent& carrier, const std::vector<WorkEvent>& receipts,
                 const RecordSink& sink = {}) {
        Result out;
        // R_MAX: whole-carrier reject at decode, ZERO pushes (W3 WT-1 owns the
        // wire decode; W2's emitter must never fire on an over-R_MAX carrier).
        if (receipts.size() > W2_R_MAX) {
            out.carrier_status = CarrierStatus::REJECT_RMAX;
            return out;
        }
        std::optional<u64> carrier_bin = m_index.height_of(carrier.prev_block_hash);
        if (!carrier_bin.has_value() || !carrier.meets_own_target() ||
            carrier.lz_bits != consensus_lz(*carrier_bin) ||
            carrier.chain_id != m_chain) {
            out.carrier_status = CarrierStatus::REJECT_POW;
            return out;
        }
        // The carrier is a chained share: prune the window on clock advance, then
        // account it (share-format §5: the accounted-event set holds chained
        // shares AND receipts). A replayed carrier is not re-credited.
        m_window.prune(*carrier_bin);
        if (m_window.contains(carrier.hash())) {
            out.carrier_status = CarrierStatus::REJECT_DEDUP;
            return out;
        }
        // §4.2 step 1: the carrier push (carrier position, no receipt flag).
        emit(out, sink, carrier.identity, carrier.descriptor, carrier.work(),
             W2_CARRIER_FLAGS, *carrier_bin, *carrier_bin, carrier.tag);
        m_window.add(carrier.hash(), *carrier_bin);
        m_tracker.record_share(carrier.identity, carrier.hash());

        // §4.2 step 2: receipts in WIRE order; invalid entries ignored in place,
        // the carrier still stands (OQ-M1 — an invalid receipt is never a fork
        // tool). Accepted receipts self-carry under the carrier's descriptor.
        for (const WorkEvent& r : receipts) {
            Disposition disp = validate_receipt(r, carrier, *carrier_bin);
            out.receipts.emplace_back(r.tag, disp);
            if (disp != Disposition::OK) continue;
            u64 origin_bin = *m_index.height_of(r.prev_block_hash);
            emit(out, sink, carrier.identity, carrier.descriptor, r.work(),
                 W2_CARRIER_FLAGS | W2_L0F_RECEIPT, origin_bin, *carrier_bin,
                 r.tag);
            m_window.add(r.hash(), *carrier_bin);
        }
        return out;
    }

    const DedupWindow& window() const { return m_window; }
    u64 next_pos() const { return m_next_pos; }
    ::v37::u128 raw_total() const { return m_raw_total; }
    u64 incarnation() const { return m_incarnation; }
    std::uint32_t chain() const { return m_chain; }

private:
    void emit(Result& out, const RecordSink& sink, const bytes32& identity,
              const ::v37::PayoutDescriptor& desc, u64 w_raw,
              std::uint32_t flags, u64 origin_bin, u64 carrier_bin,
              const std::string& tag) {
        EmittedPush p;
        p.identity = identity;         // self-carriage: carrier identity always
        p.descriptor = desc;           // self-carriage: carrier descriptor always
        p.w_raw = w_raw;
        p.flags = flags;
        p.pos = m_next_pos;            // ruling (a): carrier arrival position
        p.origin_bin = origin_bin;
        p.carrier_bin = carrier_bin;
        p.tag = tag;
        ++m_next_pos;
        m_raw_total += w_raw;
        out.pushes.push_back(p);
        if (sink) sink(p);
    }

    std::uint32_t m_chain;
    const IMainchainIndex& m_index;
    IShareTracker& m_tracker;
    DedupWindow m_window;
    u64 m_incarnation;
    u64 m_next_pos = 0;
    ::v37::u128 m_raw_total = 0;
};

} // namespace c2pool::v37n
