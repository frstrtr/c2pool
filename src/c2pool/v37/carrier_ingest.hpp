#pragma once
// V37 Track A2 — carrier-ingest bridge: the W2->W0 admission sink for the relay.
// CONSUMER-tree code (src/c2pool/v37/). This is the production binding of the
// W3 CarrierRelay::AdmitFn: it owns a W2 ReceiptAdmitter and forwards every
// EmittedPush into the W0 V37Engine as a LaneRecord::push. It NEVER touches
// src/sharechain/v37 consensus canon and NEVER calls Lane::push directly — the
// only append is through V37Engine's MPSC producer seam (O1.4), exactly as the
// W3 header (w3_relay.hpp §"the transport seam") and the W2 admission header
// (w2_admission.hpp, RecordSink comment) require.
//
// Why this class exists: w3_relay.hpp defines the relay orchestration and the
// codec, and w2_admission.hpp defines admission + the EmittedPush stream, but
// nothing in the merged tree bound the two to a live V37Engine — the W3 KAT
// wired it inline in its AdmitHarness. A daemon needs a REUSABLE binding that
// can be constructed once and handed to CarrierRelay. That is this file.
//
// Threading: CarrierRelay::handle_inbound (the peer-reader thread) and
// handle_local (the stratum-win thread) both drive the AdmitFn, so admit() runs
// on more than one thread. ReceiptAdmitter is single-writer state (its dedup
// window + next_pos), so admit() is serialized here under m_mtx. The engine
// submit() past that lock is itself the thread-safe MPSC enqueue, and the
// arrival ORDER into the engine is the arrival order into admit() (the consensus
// input; v37_engine.hpp §"the ONE hard rule"): the lock makes admit->submit one
// atomic step so two threads never interleave a receipt push between another
// carrier's carrier-push and its receipt-pushes.

#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <set>

#include "v37_engine.hpp"       // V37Engine, LaneRecord
#include "w2_admission.hpp"     // ReceiptAdmitter, IMainchainIndex, IShareTracker
#include "w2_receipt.hpp"       // WorkEvent, bytes32
#include "w3_relay.hpp"         // CarrierRelay::AdmitFn

namespace c2pool::v37n {

// ── IMainchainIndex bound to a caller-supplied height resolver ──────────────
// The daemon supplies the node's real mainchain index (a resolver that maps a
// carrier's prev_block_hash to a coin height within the context horizon, or
// nullopt); a test supplies a synthetic map. Kept behind a std::function so the
// heavy coin backend never leaks into this stdlib-only header.
class CallbackMainchainIndex final : public IMainchainIndex {
public:
    using Resolver = std::function<std::optional<u64>(const bytes32&)>;
    explicit CallbackMainchainIndex(Resolver r) : m_resolve(std::move(r)) {}
    std::optional<u64> height_of(const bytes32& prev_block_hash) const override {
        return m_resolve ? m_resolve(prev_block_hash) : std::nullopt;
    }
private:
    Resolver m_resolve;
};

// ── an in-memory durable share tracker (thread-safe) ────────────────────────
// The W2 prev-own-share source + carrier recording. This is NOT lane state and
// NOT a digest leaf (w2_admission.hpp IShareTracker). A production node backs
// this with the persisted share store; the in-memory form is correct for a
// single node lifetime and for the multi-node bring-up. Guarded because the
// admitter records a carrier from whichever thread admitted it.
class MemShareTracker final : public IShareTracker {
public:
    bool has_prev_own(const bytes32& id, const bytes32& prev) const override {
        if (prev == W2_GENESIS_PREV_OWN) return true;
        std::lock_guard<std::mutex> lk(m_mtx);
        auto it = m_chained.find(id);
        return it != m_chained.end() && it->second.count(prev) != 0;
    }
    void record_share(const bytes32& id, const bytes32& h) override {
        std::lock_guard<std::mutex> lk(m_mtx);
        m_chained[id].insert(h);
    }
private:
    mutable std::mutex m_mtx;
    std::map<bytes32, std::set<bytes32>> m_chained;
};

// ═══════════════════════════════════════════════════════════════════════════
// CarrierIngest — the reusable CarrierRelay::AdmitFn bound to a live V37Engine.
//
// admit(carrier, receipts):
//   1. W2 ReceiptAdmitter::admit — the full RDWR pipeline (PoW recompute, R-1
//      target pinning, identity/prev-own/chain/expiry/dedup, R_MAX), emitting
//      the deterministic push sequence (carrier, then accepted receipts).
//   2. Each EmittedPush -> V37Engine::submit(LaneRecord::push(...)) — fire-and-
//      forget into the MPSC mailbox (the production path, O1.4). The engine's
//      single executor thread applies them in arrival order; the resulting
//      LaneSnapshot (readable via engine.snapshot(chain)) is where a REMOTE
//      node's admitted work becomes accounted weight.
//
// The whole admit->submit is one locked step (see threading note at top).
// ═══════════════════════════════════════════════════════════════════════════
class CarrierIngest {
public:
    CarrierIngest(V37Engine& engine, ::v37::ChainId chain,
                  const IMainchainIndex& index, IShareTracker& tracker,
                  u64 incarnation)
        : m_engine(engine), m_chain(chain),
          m_adm(std::make_unique<ReceiptAdmitter>(
              static_cast<std::uint32_t>(chain), index, tracker, incarnation)) {}

    // The callback CarrierRelay is constructed with. Bound to `this`; the
    // CarrierIngest must outlive the CarrierRelay (the daemon owns both for the
    // node lifetime).
    CarrierRelay::AdmitFn fn() {
        return [this](const WorkEvent& carrier,
                      const std::vector<WorkEvent>& receipts) {
            std::lock_guard<std::mutex> lk(m_mtx);
            RecordSink sink = [this](const EmittedPush& p) {
                // Fire-and-forget: O1.4 no callback out, no wait on the executor.
                m_engine.submit(::v37::LaneRecord::push(
                    m_chain, p.descriptor, p.w_raw, p.flags));
                ++m_pushes_forwarded;
            };
            return m_adm->admit(carrier, receipts, sink);
        };
    }

    // F2 / W2-F-D: RemoveLane -> AddLane resets the lane-scoped admission state.
    void reset_incarnation(u64 new_incarnation) {
        std::lock_guard<std::mutex> lk(m_mtx);
        m_adm->reset_incarnation(new_incarnation);
    }

    // Diagnostics (never consensus): how many pushes this bridge has forwarded
    // into the engine mailbox. A monotone counter for the multi-node acceptance
    // assertions and the daemon's boot/stop log lines.
    std::uint64_t pushes_forwarded() const {
        std::lock_guard<std::mutex> lk(m_mtx);
        return m_pushes_forwarded;
    }

private:
    V37Engine&                       m_engine;
    ::v37::ChainId                   m_chain;
    std::unique_ptr<ReceiptAdmitter> m_adm;
    mutable std::mutex               m_mtx;
    std::uint64_t                    m_pushes_forwarded = 0;
};

} // namespace c2pool::v37n
