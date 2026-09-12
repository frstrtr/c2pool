#pragma once
// ============================================================================
// V37 DROPS — THE LIVE-SHELL WIRING BUNDLE (Step 2).
//
// WHAT THIS FIXES. The DROPS package shipped four consumer seams and a verified
// gate-ON mint, and NOTHING IN ANY LIVE SHELL CALLED THEM. main_v37_btc_dash.cpp
// never constructed a DropHarvester, an EnrollmentBook or a ShareCountBook, and
// never called set_drop_harvest / set_drop_harvester / set_pre_harvest /
// set_enrollment_book. So after the operator flip every node would have been
// gate-ON and DORMANT: it converges with its peers and credits nobody, because
// no raindrop is ever harvested, no share count is ever declared, and every
// harvested interval is withheld by the fail-closed rule. This header is the
// four calls, in one object, with the one property the seams cannot enforce for
// themselves.
//
// ★★ THE PROPERTY: now_interval COMES FROM THE TIP, AND ONLY FROM THE TIP.
//
// EnrollmentBook::commit(payee, now_interval, effective_from) enforces the
// ex-ante rule — effective_from MUST be strictly greater than now_interval — but
// `now_interval` is SUPPLIED BY THE CALLER. The rule is therefore only as strong
// as the caller's clock. A caller that passes a STALE now (the obvious mistake
// being the BURIAL FRONTIER, which is the other interval number this wiring
// handles, and which lags the tip by D_conf) re-opens the whole selective-
// enrolment attack: "enrol me, effective from frontier+1" is an enrolment that
// covers intervals the payee has ALREADY DRAWN AND SEEN. Measured over the same
// draws as the R-SYBIL ruling, that seam is worth 1.32x at a 2000-way identity
// split — the same door, one argument further in.
//
// So this bundle does not take `now_interval` from anybody. It owns a TipBin
// that is fed from the chain tip in the shell's height-watch, it keeps the
// EnrollmentBook PRIVATE, and the ONLY enrolment entry point it publishes —
// enroll_at_tip(payee) — HAS NO INTERVAL PARAMETER AT ALL. The stale-now call is
// not refused at runtime; it is not expressible. The burial frontier enters
// through a different door entirely (declare_at_frontier), which reaches
// ShareCountBook::declare_into and can never reach commit().
//
// THE TWO INTERVAL CLOCKS, NAMED ONCE SO THEY ARE NEVER CONFUSED AGAIN:
//   now_interval   THE TIP. The ex-ante clock. Enrolment is decided against it
//                  and takes effect at now+1, which is strictly in the future of
//                  every draw any payee has seen. Also the ShareCountBook arm
//                  point: everything before it is UNKNOWN and stays withheld.
//   bury_before    THE BURIAL FRONTIER (won_height - D_conf). The F1 release
//                  clock. Only intervals strictly below it may be shown to the
//                  estimator, because only they are complete. NEVER an enrolment
//                  clock.
//
// THREADING. A live node touches these objects from three threads: the carrier
// reader threads (raindrops + emitted pushes, through the W2 admitter), the
// stratum submit thread (our own win), and the carrier reader thread again (a
// peer's win). DropHarvester / ShareCountBook / EnrollmentBook are plain stdlib
// containers with no internal locking, so the bundle carries the lock. Every
// entry point here takes it. The two calls that are made by code BETWEEN the
// hooks — DropHarvester::take_buried() on an own win and discard_buried() on a
// peer win, both invoked by XbtcNode after it has called the pre-harvest hook —
// are covered by the shell holding win_lock() across the whole registration. The
// mutex is RECURSIVE for exactly that reason: the pre-harvest hook re-enters it
// on the same thread that already holds the win lock.
//
// NOT CONSENSUS STATE. Everything here is a node-local measurement buffer plus a
// node-local enrolment book. What crosses the wire is the winner's COMPOSED
// credit map and the book digest that witnesses it (DROPS-R3 / R-SYBIL); nothing
// in this header is re-derived by a receiver.
//
// Stdlib-only, header-only, C++20.
// ============================================================================
#include <cstdint>
#include <functional>
#include <mutex>
#include <optional>
#include <utility>

#include <c2pool/v37/v37_drop_harvest.hpp>          // DropHarvester
#include <c2pool/v37/v37_drops_enrollment.hpp>      // EnrollmentBook
#include <c2pool/v37/v37_node_lane_activation.hpp>  // kActivateConsensusV1
#include <c2pool/v37/v37_share_counter.hpp>         // ShareCountBook
#include <c2pool/v37/w2_admission.hpp>              // DropSink, RecordSink, EmittedPush
#include <c2pool/v37/w2_receipt.hpp>                // consensus_lz

namespace c2pool::v37n {

// ── THE TIP BIN — the one source of `now_interval` ──────────────────────────
//
// W2 keys a work event's interval on its ORIGIN BIN, which is the mainchain
// height of the block the event was mined against (w2_admission.hpp
// HarvestedDrop::interval, EmittedPush::origin_bin). So the interval space IS
// the coin-height space, and "the current interval" is the height of the chain
// tip. That is what observe_tip() is fed, from the same height-watch poll that
// feeds the carrier index.
//
// MONOTONE ON PURPOSE. A reorg that lowers the tip must not lower the ex-ante
// clock: doing so would make an enrolment made before the reorg cover intervals
// after it that the payee has already drawn. Going back in time is precisely
// the stale-now shape, so the clock refuses to.
class TipBin {
public:
    void observe_tip(std::uint64_t coin_height) {
        std::lock_guard<std::mutex> lk(m_mtx);
        if (!m_known || coin_height > m_bin) m_bin = coin_height;
        m_known = true;
    }
    bool known() const {
        std::lock_guard<std::mutex> lk(m_mtx);
        return m_known;
    }
    // The ex-ante clock. UNKNOWN until the first tip is observed; a caller that
    // needs it before then is told so rather than handed a 0 that would make
    // every enrolment look like it was committed at genesis.
    std::optional<std::uint64_t> now_interval() const {
        std::lock_guard<std::mutex> lk(m_mtx);
        if (!m_known) return std::nullopt;
        return m_bin;
    }

private:
    mutable std::mutex   m_mtx;
    std::uint64_t        m_bin = 0;
    bool                 m_known = false;
};

// What an enrolment attempt did. There is no "refused because the interval was
// wrong" outcome, because the interval is not the caller's to supply.
enum class EnrollOutcome {
    Enrolled,        // a new ex-ante commitment was recorded at tip -> tip+1
    AlreadyEnrolled, // this payee had already committed; the first one stands
    TipUnknown,      // no chain tip observed yet: REFUSED, nothing recorded
};

// ── THE BUNDLE ──────────────────────────────────────────────────────────────
// ONE per lane. Owns the three node-local DROPS objects and publishes exactly
// the values a shell needs to attach them:
//   drop_sink()    -> ReceiptAdmitter::set_drop_harvest(true, sink)
//   sink_filter()  -> the W2 emit-stream tee that feeds the share-count producer
//   pre_harvest()  -> XbtcNode::set_pre_harvest(fn)
//   harvester()    -> XbtcNode::set_drop_harvester(&...)
//   enrollment()   -> XbtcNode::set_enrollment_book(&...)   [CONST — see below]
//
// enrollment() is deliberately CONST-ONLY. The node wants a
// `const EnrollmentBook*` and nothing else does; handing out a mutable reference
// would hand out commit(payee, now, effective_from) and put the stale-now
// argument back in a caller's hands. It is the one accessor whose constness is
// load-bearing rather than stylistic.
class DropsWiring {
public:
    // K must be the lane's SubthresholdGate::K so the collectors retain exactly
    // the K the fold will later ask for.
    explicit DropsWiring(std::uint32_t K) : m_harvester(K) {}

    DropsWiring(const DropsWiring&) = delete;
    DropsWiring& operator=(const DropsWiring&) = delete;

    // ── the tip clock ───────────────────────────────────────────────────────
    void observe_tip(std::uint64_t coin_height) { m_tip.observe_tip(coin_height); }
    const TipBin& tip() const { return m_tip; }
    std::optional<std::uint64_t> now_interval() const { return m_tip.now_interval(); }

    // ── ★ THE ONLY ENROLMENT ENTRY POINT. NO INTERVAL PARAMETER. ───────────
    // now_interval is THE TIP; effective_from is TIP + 1, strictly later, so the
    // commitment covers no interval whose draws the payee can already have seen.
    // A shell cannot express anything else through this bundle.
    EnrollOutcome enroll_at_tip(const ::v37::bytes32& payee) {
        std::lock_guard<std::recursive_mutex> lk(m_mtx);
        const auto now = m_tip.now_interval();
        if (!now) return EnrollOutcome::TipUnknown;
        const bool had = (m_enroll.find(payee) != nullptr);
        // commit() refuses effective_from <= now; *now + 1 can never be <= *now,
        // so this call is refused only for a reason that is not the caller's.
        m_enroll.commit(payee, *now, *now + 1);
        return had ? EnrollOutcome::AlreadyEnrolled : EnrollOutcome::Enrolled;
    }

    // Arm the share-count producer at the TIP. Everything strictly earlier stays
    // UNKNOWN for ever and is therefore WITHHELD by the harvester — which is the
    // fail-closed error, not a bug: for those intervals the book genuinely does
    // not know whether the payee landed shares.
    bool arm_at_tip() {
        std::lock_guard<std::recursive_mutex> lk(m_mtx);
        const auto now = m_tip.now_interval();
        if (!now) return false;
        m_shares.arm(*now);
        return true;
    }
    bool armed() const {
        std::lock_guard<std::recursive_mutex> lk(m_mtx);
        return m_shares.armed();
    }

    // ── the four attachment values ─────────────────────────────────────────

    // W2 DropSink: every raindrop the admitter harvests lands in the harvester.
    DropSink drop_sink() {
        return [this](const HarvestedDrop& d) {
            std::lock_guard<std::recursive_mutex> lk(m_mtx);
            m_harvester.observe(d);
        };
    }

    // The W2 emit-stream TEE. Wraps the engine sink so the share-count producer
    // sees every EmittedPush the admitter emits and the engine still gets it, in
    // order, unchanged. This is the producer that turns DropHarvester's
    // fail-closed declare_shares() rule from an API into a live path.
    std::function<RecordSink(RecordSink)> sink_filter() {
        return [this](RecordSink downstream) -> RecordSink {
            RecordSink inner = m_shares.tee(std::move(downstream));
            return [this, inner = std::move(inner)](const EmittedPush& p) {
                std::lock_guard<std::recursive_mutex> lk(m_mtx);
                inner(p);
            };
        };
    }

    // XbtcNode::PreHarvestFn. Called with the BURIAL FRONTIER immediately before
    // the harvest is taken (own win) or discarded (peer win). `bury_before` is
    // the F1 release clock and NOTHING ELSE: it reaches declare_into and can
    // never reach commit().
    std::function<void(std::uint64_t)> pre_harvest() {
        return [this](std::uint64_t bury_before) { declare_at_frontier(bury_before); };
    }

    // The pre-harvest body, exposed so a KAT drives exactly what the shell wires.
    std::size_t declare_at_frontier(std::uint64_t bury_before) {
        std::lock_guard<std::recursive_mutex> lk(m_mtx);
        const std::size_t n = m_shares.declare_into(
            m_harvester, bury_before,
            [](u64 bin) { return consensus_lz(bin); },
            &m_enroll);
        m_declared += n;
        return n;
    }

    // The harvester the node folds from. Mutable because XbtcNode takes a
    // DropHarvester* and calls take_buried()/discard_buried() on it — which is
    // why the shell must hold win_lock() across the registration.
    DropHarvester& harvester() { return m_harvester; }
    const DropHarvester& harvester() const { return m_harvester; }

    // ★ CONST ONLY. See the class comment: this is what makes the stale-now call
    // unreachable rather than merely discouraged.
    const EnrollmentBook& enrollment() const { return m_enroll; }

    const ShareCountBook& shares() const { return m_shares; }

    // Held by the shell across bed.on_block_found() / bed.on_peer_block_found(),
    // because XbtcNode calls take_buried()/discard_buried() itself, after the
    // pre-harvest hook has returned. Recursive: the hook re-enters on the same
    // thread.
    std::unique_lock<std::recursive_mutex> win_lock() {
        return std::unique_lock<std::recursive_mutex>(m_mtx);
    }

    // ── diagnostics (never consensus) ──────────────────────────────────────
    struct Stats {
        std::uint64_t harvested = 0;    // raindrops observed
        std::uint64_t late = 0;         // raindrops for an already-released interval
        std::uint64_t withheld = 0;     // intervals released with no declared S
        std::uint64_t discarded = 0;    // intervals dropped on a peer win
        std::uint64_t shares_seen = 0;  // EmittedPush rows the producer counted
        std::uint64_t declared = 0;     // (payee, interval) rows declared
        std::size_t   open = 0;         // intervals still accumulating
        std::size_t   enrolled = 0;     // ex-ante commitments held
    };
    Stats stats() const {
        std::lock_guard<std::recursive_mutex> lk(m_mtx);
        Stats s;
        s.harvested   = m_harvester.observed();
        s.late        = m_harvester.late_discarded();
        s.withheld    = m_harvester.undeclared_withheld();
        s.discarded   = m_harvester.discarded();
        s.shares_seen = m_shares.observed();
        s.declared    = m_declared;
        s.open        = m_harvester.open_intervals();
        s.enrolled    = m_enroll.size();
        return s;
    }

private:
    mutable std::recursive_mutex m_mtx;
    TipBin          m_tip;
    DropHarvester   m_harvester;
    EnrollmentBook  m_enroll;
    ShareCountBook  m_shares;
    std::uint64_t   m_declared = 0;
};

// Is the live wiring ARMED in this build? Exactly the consensus-activation flag
// — the flip is what makes DROPS reachable, and nothing else does.
inline constexpr bool kDropsWiringArmed = kActivateConsensusV1;

// ★ THE DORMANCY GATE. A default build gets std::nullopt, so the shell
// constructs nothing, attaches nothing, arms no harvest and installs no tee: the
// W2 admitter, the fold and the OWED ledger are the ones master ships. A build
// that has taken the consensus activation AND whose lane geometry actually
// carries the gate gets the bundle.
//
// The second condition is not redundant belt-and-braces. At kActivationArity 1
// the flip opens DROPS alone, and a lane whose geometry somehow did not carry
// the gate would harvest raindrops that compose to nothing — memory spent to
// credit zero. Refusing to build the bundle there is the honest answer.
inline std::optional<DropsWiring> make_drops_wiring(const ::v37::LaneParams& p) {
    if constexpr (!kDropsWiringArmed) {
        (void)p;
        return std::nullopt;
    } else {
        if (!p.subthreshold.enabled) return std::nullopt;
        return std::optional<DropsWiring>(std::in_place, p.subthreshold.K);
    }
}

}  // namespace c2pool::v37n
