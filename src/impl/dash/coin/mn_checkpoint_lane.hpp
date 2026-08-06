// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// E2d (#738): the daemonless MN-set BRIDGE — pinned checkpoint, then forward
/// replay through the existing block-connect ingest.
///
/// ─────────────────────────────────────────────────────────────────────────
/// WHAT PROBLEM THIS SOLVES
/// ─────────────────────────────────────────────────────────────────────────
/// NodeCoinState::populated() needs BOTH a header tip AND a payout-bearing
/// masternode set. E2a gave the tip half daemonlessly. The MN half had
/// exactly one source — dashd RPC `protx list registered true` (E2c,
/// mn_seed.hpp)
/// — because the P2P Simplified MN List omits scriptPayout/nLastPaidHeight.
/// With no RPC the arm printed "seed UNAVAILABLE" and every template kept
/// routing to the dashd fallback. That was the last structurally
/// daemon-dependent input on the daemonless path.
///
/// This lane replaces the RPC with a release-pinned checkpoint
/// (mn_checkpoint.hpp) plus a forward replay of the blocks between the
/// checkpoint height and the current tip.
///
/// ─────────────────────────────────────────────────────────────────────────
/// WHY A PRIVATE MnStateMachine AND NOT "SEED THEN LET THE MAINTAINER RUN"
/// ─────────────────────────────────────────────────────────────────────────
/// The obvious wiring — publish the checkpoint straight into
/// Node::mn_list_update at h=CKPT and let CoinStateMaintainer fold blocks
/// forward — is WRONG, and dangerously so.
///
/// MnStateMachine::apply_block is forward-CONTIGUOUS: after loading a
/// snapshot at h, the only block it may fold is h+1. During a cold start the
/// live feed is simultaneously delivering blocks at the CURRENT TIP (the
/// new_block inv -> request_block leg). Publishing at h=CKPT would arm
/// MN-readiness immediately, and the first live tip block (h >> CKPT+1) would
/// trip gap_detected -> wipe + demote + request an authoritative re-seed. On
/// the daemonless arm there IS no authoritative re-seed, so the arm would
/// latch dead. Worse, between the publish and that gap the bundle is
/// populated() with a payment queue that is thousands of blocks stale —
/// a served bad-cb-payee window.
///
/// So the bridge runs OFF to the side, on a private MnStateMachine this lane
/// owns. It applies ONLY the exact next height it is waiting for; live tip
/// blocks that arrive mid-bridge are ignored (they will be requested in
/// sequence later). The maintainer sees nothing until the private machine has
/// caught up to the header tip, at which point the lane publishes the
/// finished set through the SAME leg-4 event (Node::mn_list_update) that the
/// E2c RPC seed uses — so the maintainer takes it exactly like any other
/// authoritative resync, with as_of_height = the height it actually bridged
/// to, and its snapshot fence set correctly for the next live block.
///
/// ─────────────────────────────────────────────────────────────────────────
/// THE BRIDGE IS ALSO THE ANCHOR'S VERIFICATION
/// ─────────────────────────────────────────────────────────────────────────
/// Each replayed block is a live cross-check of the pinned data:
/// apply_block projects the DIP-3 payee from the anchored set and compares it
/// with that block's ACTUAL coinbase. An accepted block by definition pays
/// dashd's projected masternode, so a mismatch proves the anchor (or our
/// replay) is wrong. Any payee_desync or gap_detected during the bridge is
/// TERMINAL here: the lane fails closed permanently and never publishes.
/// A wrong checkpoint therefore cannot reach a template — it can only stop
/// the embedded arm from arming.
///
/// This does NOT make the anchor trustless. It makes it progressively
/// falsifiable: the further the bridge runs, the more payment slots have been
/// confirmed against real coinbases. The set membership AT the checkpoint
/// height is still trusted. See mn_checkpoint.hpp's header and
/// src/impl/dash/coin/checkpoints/README.md.
///
/// ─────────────────────────────────────────────────────────────────────────
/// THREADING / LOCK POSTURE (see the #878/#881 caller-side-lock defect class)
/// ─────────────────────────────────────────────────────────────────────────
/// This lane holds NO lock of its own and is NOT thread-safe. It is confined
/// to the single io_context thread that main_dash runs, exactly like UtxoLane
/// and CoinStateMaintainer's reception paths. Its two entry points are:
///
///   • on_block_connected(): driven from the block-connect ingest, which
///     fires from the coin-P2P read handler on the io thread.
///   • pump(): driven from HeaderChain's on_tip_changed callback and from
///     on_block_connected itself.
///
/// pump() calls back into HeaderChain (height() / get_header_by_height()),
/// which are SELF-LOCKING on HeaderChain::m_mutex. That is safe — and,
/// critically, REACHABLE — because HeaderChain dispatches m_on_tip_changed
/// with m_mutex RELEASED: add_header() and add_headers() both copy the
/// pending tip-change out inside the lock scope, close the scope, and only
/// then invoke the callback (header_chain.hpp: the callback calls at the end
/// of add_header/add_headers sit outside every lock_guard block). The
/// pre-existing tip-changed lambda in main_dash already relies on this — it
/// calls tip_advance_from_chain(*hc, ...), which takes the same lock — and
/// that path is proven live. There is no exclusive lock held across any call
/// into this lane.
///
/// ─────────────────────────────────────────────────────────────────────────
/// POST-ANCHOR PoSe BANS — THE REPLAY APPLIES REMOVALS, NOT ONLY ADDITIONS
/// ─────────────────────────────────────────────────────────────────────────
/// A PoSe ban is applied by dashd from CONSENSUS (accumulated
/// MAX_PoSe_PENALTY), never as a special transaction. MnStateMachine::
/// apply_block walks special txs, so a block replay is STRUCTURALLY incapable
/// of observing one: it can only ever ADD.
///
/// MEASURED, mainnet, hotel dashd 23.1.7, 2026-08-02, anchor 2513000 -> tip
/// 2514874:
///
///     protx list valid false 2513000   -> 2068 entries
///     protx list valid false 2514874   -> 2059 entries   the chain FELL by 9
///     this bridge's replayed set        2067 -> 2070      we CLIMBED by 3
///
/// The bridge fail-closed at h=2514874 having projected a masternode that the
/// chain had PoSe-banned inside the window (still `registered`, no longer
/// `valid`). Correct refusal, wrong set.
///
/// The Simplified Masternode List is the only carrier of that ban, and we
/// already receive and persist it. There are now THREE seams onto it, and they
/// do different jobs:
///
///   • set_request_snapshot_fn() + set_merkle_root_at_fn() — the PER-HEIGHT
///     WHOLESALE REMOVAL fold, and the reason this lane no longer reads the
///     tip SML for a past height at all. At a fold point the lane issues
///     getmnlistd(ZERO, hash_at(H)) — the same primitive
///     quorum_member_source.hpp uses — and folds the list AS OF H with the
///     cursor standing exactly on H. Every masternode that list attests
///     not-valid leaves the payee-eligible set in a SINGLE pass, which is the
///     whole point: it makes a BURST of bans indistinguishable from one ban.
///     Because the list is requested for the cursor's own height rather than
///     read off the moving tip, `cursor == H_sml` holds BY CONSTRUCTION and
///     the dangerous EARLY case is unreachable rather than merely unlikely.
///     The full argument, the sequencing, and the one-outstanding-request rule
///     are written out at the PER-HEIGHT PoSe FOLD block below.
///
///   • set_sml_snapshot_fn() — the TIP SML, still wired, but no longer the
///     fold's input. It supplies only the FRESHNESS HEIGHT that gates the
///     reactive walk's attestations (a stale list must not license a permanent
///     demotion of a since-revived masternode).
///
///     A fold point is COARSE (kDefaultFoldInterval blocks), so a ban landing
///     strictly BETWEEN two of them is invisible to it. That gap is closed by
///     the ON-DEMAND fold below, not by shrinking the interval.
///
///   • THE ON-DEMAND FOLD — the same request machinery, fired BY A PAYEE
///     MISMATCH rather than by a fold point. Measured on mainnet: the bridge
///     fail-closed at h=2513489 having projected a masternode PoSe-banned at
///     h<=2513488, with the next scheduled fold point ELEVEN BLOCKS LATER at
///     2513500. The mismatch itself is the perfect trigger — it fires exactly
///     when, and only when, the queue is wrong. See the ON-DEMAND PoSe FOLD
///     block below for the cap and the safety argument.
///
///   • set_sml_validity_fn() — the per-hash attestation used by the REACTIVE
///     per-mismatch demotion walk, which remains the second line of defence
///     for a ban the fold could not cover (no verified SML, or an SML whose
///     height the cursor never lands on). It may walk down the ranked queue,
///     but ONLY while each demoted candidate is ATTESTED INVALID by an SML
///     FRESH ENOUGH to speak about that height and the accepted candidate's
///     scriptPayout EXACTLY matches an output this block pays. The walk is
///     capped per bridge (see pump()) and adjudicates ONE exclusion per
///     height, which is exactly why it cannot carry a burst.
///
/// MEASURED CAUSE OF THE h=2514874 FAIL-CLOSE — it was a BURST, not missing
/// machinery. The walk RAN AND WORKED five times during that replay (bridge
/// total 1/6 … 5/6). The chain then shows three masternodes
/// (824da5790b93de99…, 91c8c62b1245a1f5…, a459ade702cbe47a…) leaving `protx
/// list valid` together inside 73 blocks: valid 2062 at h=2514800, 2059 at
/// h=2514873, and still absent at h=2515025 (never revived, so the SML held
/// isValid=false correctly). Three consecutive banned queue-head candidates
/// defeat a walk that must land an exact coinbase script match at each step.
///
/// Every count is surfaced on status(), on the publish line, and on every
/// fail-closed message (divergence_report()): a count that lives only in
/// scrollback is half-silent, and this file exists to prevent silent
/// degradation.
///
/// ONE RESIDUAL, stated honestly:
///
///   A post-anchor ban INSIDE a shared-payoutAddress group can escape the
///   coinbase cross-check, because it is SCRIPT-granular: if the banned MN
///   and the MN dashd actually paid share one payout address, the coinbase
///   output still matches our projected script, the mismatch never fires, and
///   the payment is attributed to the wrong member of the group. That is a
///   PRE-EXISTING blind spot in the projection cross-check (the same
///   granularity the gap_detected note in mn_state_machine.hpp calls out).
///   The removal pass narrows it — a banned member is now dropped from the
///   group before it can be projected — but does not close it.
///
/// ANCHOR SELECTION ON REPEAT DESYNC — PARTLY DONE, AND THE REST IS SCOPED
/// RATHER THAN HALF-BUILT. rearm() (below) now answers the maintainer's
/// authoritative-re-seed ask on the daemonless arm, capped and backed off, and
/// it enforces the half of the policy this build CAN enforce: never an anchor
/// newer than the one in use, never one at or after the earliest observed
/// divergence, always the release-pinned floor. Picking the NEWEST anchor is
/// wrong — an anchor cut AFTER a divergence began replays cleanly over a
/// shorter window and re-arms a queue that is already wrong, which mints a
/// rejected coinbase — and that case is now REFUSED terminally rather than
/// merely warned about.
///
/// STILL MISSING, and required before a genuine oldest-first LADDER exists:
/// this build carries exactly ONE anchor per network
/// (src/impl/dash/coin/checkpoints/dash_mn_checkpoint_{mainnet,testnet}.inc,
/// referenced once from main_dash.cpp), so there is no anchor LIST to order and
/// no persisted desync history to count re-arms against ACROSS RESTARTS (the
/// cap here is per-process). Prerequisites, unchanged: (1) a multi-anchor
/// checkpoint store keyed by height, (2) a persisted per-anchor desync counter,
/// (3) an arm()/re-arm API that takes a candidate list rather than a single
/// MnCheckpoint. Until (1) exists, "oldest-first" and "the compiled-in anchor"
/// are the same choice, which is why re-arming from it is legitimate today.
///
/// FENCED: src/impl/dash only. Constructed exclusively by the opt-in embedded
/// path in main_dash.cpp; the dashd-RPC fallback never touches this file.

#include <impl/dash/coin/block.hpp>
#include <impl/dash/coin/mn_checkpoint.hpp>
#include <impl/dash/coin/mn_state_machine.hpp>
#include <impl/dash/coin/historical_sml.hpp>   // authenticate_historical_snapshot
#include <impl/dash/coin/lane_diag.hpp>        // ProgressReporter / StallWatchdog / MnSource
#include <impl/dash/coin/vendor/simplifiedmns.hpp>
#include <impl/dash/coin/vendor/smldiff.hpp>    // CSimplifiedMNListDiff
#include <impl/dash/coin/vendor/cbtx.hpp>       // CCbTx

#include <core/log.hpp>
#include <core/uint256.hpp>

#include <algorithm>
#include <cstdint>
#include <functional>
#include <optional>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

namespace dash {
namespace coin {

class MnCheckpointLane {
public:
    /// Request the full block body at `height` from the coin-P2P peer. Wired
    /// by main_dash to the same header-chain-hash lookup + request_block seam
    /// UtxoLane uses.
    using RequestBlockFn = std::function<void(uint32_t height)>;
    /// Publish the bridged, payout-bearing set as an authoritative MN-list
    /// resync. Wired by main_dash to Node::mn_list_update.happened().
    using PublishFn =
        std::function<void(std::vector<std::pair<uint256, MNState>>, uint32_t)>;
    /// Current best header height (0 = header chain empty).
    using TipHeightFn = std::function<uint32_t()>;
    /// Block hash our header chain holds at `height`, if known.
    using HeaderHashAtFn = std::function<std::optional<uint256>(uint32_t)>;
    /// Three-state SML validity attestation for a proTxHash — nullopt when the
    /// masternode is absent from the SML (no opinion), false when the SML
    /// attests it PoSe-banned, true when it attests it live. See
    /// MnStateMachine::SmlValidityFn and the residuals note in this file's
    /// header. Wired by main_dash to NodeCoinState::sml() + have_sml().
    using SmlValidityFn = MnStateMachine::SmlValidityFn;
    /// The WHOLE persisted Simplified Masternode List TOGETHER WITH THE
    /// HEIGHT IT IS CURRENT AT. Both halves are mandatory: the list carries
    /// the PoSe REMOVALS, and the height is what makes them safe to apply
    /// (see the PER-HEIGHT PoSe FOLD block — a fold is only valid at ONE cursor
    /// position) and what gates the reactive walk's attestations for
    /// staleness. `list == nullptr` means this node has no verified SML yet.
    ///
    /// Returns a pointer, not a copy: the list is ~3000 entries and is read on
    /// the same io thread that updates it (mnlistdiff ingest). No lock is
    /// taken or needed; the pointer is used and discarded inside one call.
    struct SmlSnapshot {
        const vendor::CSimplifiedMNList* list{nullptr};
        uint32_t                         height{0};
    };
    using SmlSnapshotFn = std::function<SmlSnapshot()>;

    /// Request the FULL Simplified Masternode List as of a specific historical
    /// block: getmnlistd(ZERO, block_hash). Wired by main_dash to the same
    /// coin-P2P primitive quorum_member_source.hpp already uses, and the reply
    /// is routed back through the SAME historical demux — a historical reply
    /// must never reach the tip-SML maintainer.
    using RequestSnapshotFn = std::function<void(const uint256& block_hash)>;
    /// The PoW-verified header's hashMerkleRoot for a held block hash — the
    /// DIP-4 trust anchor for authenticating a snapshot.
    using MerkleRootAtFn = MerkleRootOfHashFn;

    enum class State {
        Unarmed,      ///< no checkpoint loaded — the lane does nothing
        Waiting,      ///< armed; header chain has not reached the anchor yet
        Bridging,     ///< replaying blocks anchor+1 .. tip
        Published,    ///< set handed to the maintainer; lane is done
        FailedClosed, ///< terminal refusal — the arm must NOT serve templates
    };

    /// What rearm() did. Every value is a NAMED outcome an operator can grep;
    /// there is no "returned false, good luck" case.
    enum class RearmOutcome {
        Armed,        ///< the bridge is re-armed and will replay from the anchor
        Deferred,     ///< backoff not satisfied yet — try again on a later trigger
        CapExhausted, ///< TERMINAL: the re-arm budget is spent, the arm stays down
        Refused,      ///< TERMINAL: this anchor may not be used (see the log)
    };

    static const char* rearm_outcome_name(RearmOutcome o)
    {
        switch (o) {
            case RearmOutcome::Armed:        return "ARMED";
            case RearmOutcome::Deferred:     return "DEFERRED";
            case RearmOutcome::CapExhausted: return "CAP-EXHAUSTED";
            case RearmOutcome::Refused:      return "REFUSED";
        }
        return "UNKNOWN";
    }

    /// ~34 days of DASH blocks at 2.5 min spacing. Chosen so a release cut
    /// within the last month bridges in minutes over the coin-P2P feed, and
    /// anything older is refused loudly instead of grinding.
    static constexpr uint32_t kDefaultMaxBridgeBlocks = 20000;

    /// How many block bodies to keep requested ahead of the apply cursor.
    /// Responses to getdata come back in request order on the single ordered
    /// TCP stream, so a window preserves the contiguity apply_block demands
    /// while avoiding a per-block round trip. Matches the order of magnitude
    /// of UtxoLane's 288-block bootstrap window without competing with it.
    static constexpr uint32_t kWindow = 64;

    MnCheckpointLane() = default;
    MnCheckpointLane(const MnCheckpointLane&) = delete;
    MnCheckpointLane& operator=(const MnCheckpointLane&) = delete;

    void set_request_block_fn(RequestBlockFn fn) { m_request = std::move(fn); }
    void set_publish_fn(PublishFn fn)            { m_publish = std::move(fn); }
    void set_tip_height_fn(TipHeightFn fn)       { m_tip_height = std::move(fn); }
    void set_header_hash_at_fn(HeaderHashAtFn fn){ m_header_hash_at = std::move(fn); }
    /// OPTIONAL. Unwired, the bridge behaves exactly as it did before this
    /// seam existed: any payee mismatch during replay is terminal.
    void set_sml_validity_fn(SmlValidityFn fn)
    {
        m_has_sml_fn = static_cast<bool>(fn);
        m_machine.set_sml_validity_fn(std::move(fn));
    }
    /// OPTIONAL, but this is the seam that fixes the measured 2068->2059 vs
    /// 2067->2070 divergence. Unwired, the replay can still only ADD, and the
    /// reactive walk runs with no freshness gate (its pre-existing behaviour).
    void set_sml_snapshot_fn(SmlSnapshotFn fn) { m_sml_snapshot = std::move(fn); }
    bool has_sml_snapshot_fn() const { return static_cast<bool>(m_sml_snapshot); }
    /// Both are REQUIRED for per-height folding. Unwired, the lane degrades to
    /// the additions-only replay plus the per-mismatch walk, and says so.
    void set_request_snapshot_fn(RequestSnapshotFn fn)
    {
        m_request_snapshot = std::move(fn);
    }
    void set_merkle_root_at_fn(MerkleRootAtFn fn)
    {
        m_merkle_root_at = std::move(fn);
    }
    /// How many blocks between fold points. Coarse on purpose: a fold is a
    /// network round trip, and a ban that lands BETWEEN two fold points is
    /// caught by the ON-DEMAND fold at the mismatch it causes (see the
    /// ON-DEMAND PoSe FOLD block below), not by shrinking this.
    void set_fold_interval(uint32_t n) { m_fold_interval = n ? n : 1; }

    /// Override the per-bridge on-demand fold cap. Unset, the cap is sized
    /// against the replay distance at bridge start (see pump()). ZERO disables
    /// the on-demand path entirely, which restores the pre-change behaviour
    /// exactly: a payee mismatch between fold points is terminal.
    void set_ondemand_fold_cap(size_t n)
    {
        m_ondemand_cap       = n;
        m_ondemand_cap_forced = true;
    }

    /// Override the per-bridge ban-state probe cap. Unset, it is sized against
    /// the replay distance at bridge start (see pump()). ZERO disables the
    /// probe entirely, which restores the pre-change behaviour exactly: a
    /// ProUpServTx whose revive turns on an unmeasured ban is applied as a
    /// plain service update — and, unlike before, COUNTED as unmeasured.
    void set_revive_probe_cap(size_t n)
    {
        m_revive_probe_cap        = n;
        m_revive_probe_cap_forced = true;
    }

    /// Maximum number of blocks the bridge is willing to replay. A checkpoint
    /// further behind the tip than this is treated as STALE and refused: the
    /// replay would take longer than an operator would tolerate, and a
    /// silently-crawling bridge that never arms is exactly the "quiet
    /// degradation" failure this lane exists to avoid. Refusing loudly points
    /// the operator at the real fix (upgrade to a release with a fresher
    /// anchor, or run with a coin RPC).
    void set_max_bridge_blocks(uint32_t n) { m_max_bridge = n; }
    uint32_t max_bridge_blocks() const     { return m_max_bridge; }

    // ─────────────────────────────────────────────────────────────────────
    // DIAGNOSTIC SEAMS (telemetry only — no serve/arm/consensus effect)
    // ─────────────────────────────────────────────────────────────────────

    /// Monotonic clock. Injectable so a KAT can drive the progress throttle and
    /// the stall watchdog deterministically instead of sleeping.
    void set_clock_fn(std::function<int64_t()> fn) { m_now = std::move(fn); }

    /// Wire size of a replayed block, for the `fetched=` field of the progress
    /// line. OPTIONAL: unwired, the line prints `fetched=n/a` rather than a
    /// fabricated number. Kept as a seam rather than serialising inline so the
    /// lane stays free of a codec dependency it does not otherwise need.
    void set_wire_size_fn(std::function<size_t(const BlockType&)> fn)
    {
        m_wire_size = std::move(fn);
    }

    /// Emit at most one progress line per `blocks` of replay OR per `ms` of
    /// wall clock, whichever comes first. Defaults are sized so a full
    /// 20000-block bridge costs ~40 lines, not 20000.
    void set_progress_throttle(uint64_t blocks, int64_t ms)
    {
        m_progress = diag::ProgressReporter(blocks, ms);
    }

    /// Silence after which watchdog_tick() calls this lane FROZEN, and how
    /// often it repeats while the freeze lasts.
    void set_watchdog(int64_t stall_ms, int64_t repeat_ms)
    {
        m_watchdog = diag::StallWatchdog(stall_ms, repeat_ms);
    }

    /// ── THE WATCHDOG. Call from a WALL-CLOCK TIMER, never from pump() ─────
    ///
    /// 2026-08-04, mainnet, BOTH .211 and contabo: the bridge froze right
    /// after a COMPLETED on-demand PoSe fold (cursors h=2514874 and h=2516862)
    /// and stayed frozen 11-12 minutes with NO warning of any kind. The only
    /// symptom available to an operator was "the arm never arms".
    ///
    /// The reason is structural, and it is the reason this function exists
    /// SEPARATELY from pump(): the old stall probe lived INSIDE pump(), below
    /// several early returns — including the pending-snapshot return — so the
    /// detector could be skipped by the very condition it was meant to detect.
    /// And pump() is driven by tip changes (~2.5 min on mainnet) while the
    /// probe needed FIVE consecutive stalled pumps before it said anything:
    /// ~12 minutes of guaranteed silence even when it did run.
    ///
    /// watchdog_tick() has neither property. It is driven by a timer that the
    /// lane cannot influence, it reads a last-progress TIMESTAMP rather than
    /// counting drives, and "the lane stopped being driven entirely" is
    /// therefore the case it reports FASTEST instead of the case it misses.
    /// It emits nothing but a log line.
    void watchdog_tick()
    {
        const int64_t now = m_now();
        auto due = m_watchdog.due(now);
        if (!due) return;
        LOG_WARNING << "[LANE-WATCHDOG] lane=mn-ckpt state=" << state_name()
                    << " cursor=" << m_next
                    << " target=" << m_replay_target
                    << " frozen_for=" << (*due / 1000) << "s"
                    << " waiting_for=" << waiting_for()
                    << " snapshot_pending=" << (m_snapshot_pending ? 1 : 0)
                    << " ondemand_pending=" << (m_ondemand_pending ? 1 : 0)
                    << " requested_through=" << m_requested_through
                    << " applied=" << m_applied
                    << " folds=" << m_folds
                    << " warn=" << m_watchdog.warnings()
                    << " — the payee queue is NOT advancing; the embedded arm"
                       " cannot arm until it does";
    }

    /// What the lane is blocked on, as ONE greppable token. This is the field
    /// that was missing: a frozen lane published a cursor but never said what
    /// it was waiting for, so "peer dropped our getdata" and "peer never
    /// answered the fold" looked identical from outside.
    std::string waiting_for() const
    {
        if (m_state == State::FailedClosed) return "nothing(failed-closed)";
        if (m_state == State::Published)    return "nothing(published)";
        if (m_snapshot_pending)
            return std::string(m_ondemand_pending ? "ondemand-mnlist-reply@h="
                                                  : "fold-mnlist-reply@h=")
                   + std::to_string(m_snapshot_height);
        if (!m_position_verified)
            return "header-tip-to-reach-anchor@h="
                   + std::to_string(m_anchor_height);
        if (m_requested_through >= m_next)
            return "block-bodies@h=" + std::to_string(m_next) + ".."
                   + std::to_string(m_requested_through);
        return "tip-advance";
    }

    static const char* state_name(State s)
    {
        switch (s) {
            case State::Unarmed:      return "unarmed";
            case State::Waiting:      return "waiting";
            case State::Bridging:     return "bridging";
            case State::Published:    return "published";
            case State::FailedClosed: return "failed-closed";
        }
        return "unknown";
    }
    const char* state_name() const { return state_name(m_state); }

    /// Whether this lane's replay cursor was RESTORED from persisted work or is
    /// starting COLD. Today it is ALWAYS cold — there is no cursor persistence
    /// — and the point of surfacing it is that the log said nothing at all
    /// about discarding a completed 3913-block replay on every process start.
    bool cursor_restored() const { return m_cursor_restored; }

    /// Load a parsed checkpoint. A !ok checkpoint arms the lane in the
    /// terminal FailedClosed state so the refusal is visible in status()
    /// rather than looking like "not configured".
    void arm(const MnCheckpoint& cp)
    {
        if (!cp.ok) {
            m_state  = State::FailedClosed;
            m_status = cp.unpinned
                ? ("no MN-set anchor in this build: " + cp.error)
                : ("checkpoint REJECTED: " + cp.error);
            LOG_ERROR << "[MN-CKPT] " << m_status;
            return;
        }
        reset_for_arm(cp);
        m_status = "armed at h=" + std::to_string(cp.height) + " ("
                   + std::to_string(m_anchor_count) + " masternodes), waiting"
                     " for headers to reach the anchor";
        LOG_INFO << "[MN-CKPT] armed: anchor h=" << cp.height << " "
                 << cp.blockhash.GetHex().substr(0, 16) << " count="
                 << m_anchor_count << " source='" << cp.source << "'";
    }

    // ─────────────────────────────────────────────────────────────────────
    // RE-ARM — the answer to CoinStateMaintainer's authoritative-re-seed ask
    // ─────────────────────────────────────────────────────────────────────
    //
    // WHAT WAS BROKEN. CoinStateMaintainer::on_block_connected, on a payee
    // DESYNC or an apply GAP, wipes the payee set, latches m_mn_needs_reseed,
    // demotes to the dashd fallback and calls m_on_mn_reseed(). On the
    // dashd-RPC arm that callback re-runs `protx list valid`. On the DAEMONLESS
    // arm main_dash set NO callback at all, so the ask went into a void: MEASURED
    // on the contabo daemonless soak, three times in one run (h=2513168,
    // 2513261, 2515266 — the last ABOVE the bridge's own failure height, i.e.
    // on a LIVE tip advance, not a bridge-replay artefact). The payee set stayed
    // wiped for the rest of the run and only a restart recovered it.
    //
    // WHAT ANSWERS IT NOW. A bridge RE-ARM: reload the anchor, replay forward to
    // the current tip, publish through the same leg-4 event. arm() alone cannot
    // do this — it assumes a VIRGIN lane and both terminal states are one-way —
    // so the reset is factored into reset_for_arm(), which arm() and rearm()
    // BOTH call. That is deliberate: two hand-maintained reset lists drift, and
    // a field the second list forgets is a silent wrong-set bug, not a crash.
    //
    // ANCHOR SELECTION — THE TRAP THIS MUST NOT FALL INTO. On a REPEAT desync,
    // picking the NEWEST anchor is WRONG: an anchor cut AFTER a divergence began
    // replays perfectly cleanly over a shorter window and re-arms a queue that
    // is ALREADY wrong, which mints a coinbase the network rejects — the exact
    // failure this whole lane exists to prevent. The correct policy is
    // OLDEST-FIRST. This build carries exactly ONE anchor per network, so:
    //
    //   • re-arming from the SAME compiled-in anchor is legitimate — it is the
    //     release-pinned trust root, it is by construction not newer than any
    //     divergence this process has observed, and it is the floor of any
    //     future ladder.
    //   • an anchor NEWER than the one in use, or at/after the earliest
    //     divergence we have evidence of, is REFUSED TERMINALLY. It is a wiring
    //     error, it is deterministic, and retrying it forever would be a
    //     fail-loop dressed as recovery.
    //
    // A genuine oldest-first LADDER still needs what the TODO at the top of this
    // file lists and this change does NOT half-build: a multi-anchor store keyed
    // by height, a persisted per-anchor desync counter, and an arm() that takes
    // a candidate list. Scoped, not started.
    //
    // CAP + BACKOFF. An unbounded re-arm against a deterministic failure is a
    // fail-loop with extra steps — worse than staying down, because it hides the
    // problem. Cap: kMaxRearms. Backoff: measured in BLOCKS observed at the tip
    // seam (the lane owns no timer and must not grow one), doubling per attempt.
    // Neither counter is reset by a successful publish: a bridge that publishes
    // and then desyncs AGAIN is precisely the loop being bounded.

    /// How many re-arms one process will attempt. THREE, because three is what
    /// the measurement showed: the soak's live path asked three times in one
    /// run. A fourth ask inside one process is no longer "a transient desync",
    /// it is a standing disagreement between our replayed queue and the chain,
    /// and the honest response is to stay down loudly.
    static constexpr uint32_t kMaxRearms = 3;
    /// Blocks that must pass at the tip before the SECOND re-arm; doubled for
    /// each one after that (64, then 128). Sized off the same measurement: the
    /// observed repeat gaps were 93 and 2005 blocks, so 64 admits both real
    /// repeats while refusing the pathological back-to-back retry that would
    /// replay the identical window and fail identically.
    static constexpr uint32_t kRearmBackoffBlocks = 64;

    /// Re-arm the bridge after the maintainer wiped a desynced payee queue.
    /// `why` is the operator-facing trigger text and appears in every line.
    RearmOutcome rearm(const MnCheckpoint& cp, const std::string& why)
    {
        ++m_rearm_asks;
        // A field never evaluated prints "n/a", never "0" — 0 is a height.
        const bool     have_tip = static_cast<bool>(m_tip_height);
        const uint32_t at       = have_tip ? m_tip_height() : 0;
        const std::string at_s  = have_tip ? std::to_string(at)
                                           : std::string("n/a");
        const std::string attempt_s = std::to_string(m_rearms + 1) + "/"
                                      + std::to_string(kMaxRearms);
        auto say = [&](RearmOutcome o, const std::string& detail) {
            m_last_rearm_reason = std::string(rearm_outcome_name(o)) + ": "
                                  + detail;
            // WHO pulled the trigger, kept separately from WHAT happened. With
            // two callers (the maintainer's ask and the lane's own tip-seam
            // poll) "a re-arm occurred" no longer identifies the path, and the
            // path is the thing this file got wrong.
            m_last_rearm_trigger = why;
            std::ostringstream ln;
            ln << "[MN-CKPT] RE-ARM " << rearm_outcome_name(o)
               << " (ask #" << m_rearm_asks << ", attempt " << attempt_s
               << ", " << m_rearms << " already used)"
               << " trigger='" << why << "'"
               << " anchor h=" << (cp.ok ? std::to_string(cp.height)
                                         : std::string("n/a"))
               << " source='" << (cp.ok ? cp.source : std::string("n/a")) << "'"
               << " observed tip h=" << at_s
               << " last re-arm at h="
               << (m_rearms == 0 ? std::string("n/a")
                                 : (m_last_rearm_at_known
                                        ? std::to_string(m_last_rearm_at)
                                        : std::string("n/a")))
               << " — " << detail;
            if (o == RearmOutcome::Armed) LOG_INFO << ln.str();
            else if (o == RearmOutcome::Deferred) LOG_WARNING << ln.str();
            else LOG_ERROR << ln.str();
            return o;
        };

        if (m_rearm_blocked) {
            return say(RearmOutcome::Refused,
                       "re-arming is TERMINALLY BLOCKED for this process: "
                       + m_rearm_block_reason
                       + ". The embedded DASH arm stays demoted to the dashd"
                         " fallback until the operator restarts with a fixed"
                         " anchor or a coin RPC (--coin-rpc-*).");
        }
        if (m_rearms >= kMaxRearms) {
            m_rearm_blocked = true;
            m_rearm_block_reason =
                "the re-arm cap of " + std::to_string(kMaxRearms)
                + " is EXHAUSTED";
            return say(RearmOutcome::CapExhausted,
                       "the re-arm cap of " + std::to_string(kMaxRearms)
                       + " is EXHAUSTED. Our replayed payee queue keeps"
                         " diverging from the chain, so re-replaying the SAME"
                         " release-pinned anchor will keep producing the SAME"
                         " wrong queue. STAYING DOWN ON PURPOSE — a fourth"
                         " re-arm would be a fail-loop that hides this. The"
                         " embedded DASH arm will NOT serve templates;"
                         " templates keep routing to the dashd fallback arm (if"
                         " configured). Fix: upgrade to a release carrying a"
                         " fresher masternode-set anchor, or run with a coin"
                         " RPC (--coin-rpc-*) so the authoritative protx seed"
                         " is used.");
        }
        if (!cp.ok) {
            m_rearm_blocked      = true;
            m_rearm_block_reason = "the candidate anchor does not parse ("
                                   + cp.error + ")";
            return say(RearmOutcome::Refused,
                       "the candidate anchor does not parse: " + cp.error
                       + ". Nothing to re-arm from.");
        }

        // ── THE ANCHOR-SELECTION GUARD (never newest-first) ───────────────
        // Record the earliest height at which we have evidence of divergence.
        // Every re-seed ask IS such evidence: the maintainer only calls back
        // after apply_block reported a payee desync or an apply gap.
        if (have_tip && (m_first_divergence == 0 || at < m_first_divergence))
            m_first_divergence = at;

        if (m_anchor_height != 0 && cp.height > m_anchor_height) {
            m_rearm_blocked = true;
            m_rearm_block_reason =
                "the candidate anchor h=" + std::to_string(cp.height)
                + " is NEWER than the anchor already in use h="
                + std::to_string(m_anchor_height);
            return say(RearmOutcome::Refused,
                       "REFUSING A NEWER ANCHOR. Candidate h="
                       + std::to_string(cp.height) + " is newer than the anchor"
                         " already in use h=" + std::to_string(m_anchor_height)
                       + ". On a REPEAT desync an anchor cut AFTER the"
                         " divergence began replays cleanly over a shorter"
                         " window and re-arms a queue that is ALREADY wrong —"
                         " which mints a coinbase the network rejects. Policy"
                         " is oldest-first with the compiled-in checkpoint as"
                         " the floor; this build carries one anchor per network"
                         " and there is no older one to fall back to.");
        }
        if (m_first_divergence != 0 && cp.height >= m_first_divergence) {
            m_rearm_blocked = true;
            m_rearm_block_reason =
                "the candidate anchor h=" + std::to_string(cp.height)
                + " is at or after the earliest observed divergence h="
                + std::to_string(m_first_divergence);
            return say(RearmOutcome::Refused,
                       "REFUSING AN ANCHOR AT OR AFTER THE DIVERGENCE."
                       " Candidate h=" + std::to_string(cp.height)
                       + " is not strictly older than the earliest divergence"
                         " we have evidence of (h="
                       + std::to_string(m_first_divergence)
                       + "). Such an anchor replays cleanly BECAUSE it already"
                         " contains the divergence — it would re-arm a wrong"
                         " queue and mint a rejected coinbase.");
        }

        // ── BACKOFF ──────────────────────────────────────────────────────
        if (m_rearms > 0) {
            const uint32_t need = kRearmBackoffBlocks << (m_rearms - 1);
            if (!have_tip || !m_last_rearm_at_known) {
                return say(RearmOutcome::Deferred,
                           "cannot evaluate the " + std::to_string(need)
                           + "-block backoff: no tip-height seam is wired, so"
                             " the lane cannot tell how far the chain has moved"
                             " since the last re-arm. Deferring rather than"
                             " guessing.");
            }
            if (at < m_last_rearm_at + need) {
                return say(RearmOutcome::Deferred,
                           "BACKOFF: only "
                           + std::to_string(at - m_last_rearm_at)
                           + " blocks since the last re-arm at h="
                           + std::to_string(m_last_rearm_at) + ", need "
                           + std::to_string(need)
                           + ". Re-replaying the same window immediately would"
                             " fail identically. The arm stays down until the"
                             " chain has moved on; this attempt is NOT counted"
                             " against the cap.");
            }
        }

        ++m_rearms;
        m_last_rearm_at       = at;
        m_last_rearm_at_known = have_tip;
        reset_for_arm(cp);
        m_status = "RE-ARMED " + std::to_string(m_rearms) + "/"
                   + std::to_string(kMaxRearms) + " at h="
                   + std::to_string(cp.height) + " ("
                   + std::to_string(m_anchor_count) + " masternodes) after "
                   + why + "; replaying forward to the tip";
        return say(RearmOutcome::Armed,
                   "re-armed from the release-pinned anchor (the trust root, and"
                   " by construction not newer than any observed divergence);"
                   " replaying anchor+1..tip. Until this bridge PUBLISHES the"
                   " embedded arm stays demoted and templates keep routing to"
                   " the dashd fallback.");
    }

    // ─────────────────────────────────────────────────────────────────────
    // SELF RE-ARM — the trigger path that SURVIVES the failure it recovers
    // ─────────────────────────────────────────────────────────────────────
    //
    // WHAT WAS BROKEN (measured, contabo daemonless soak0803c/d, 2026-08-03).
    // rearm() had exactly ONE caller: main_dash's
    // maintainer->set_on_mn_reseed callback. That callback has exactly ONE
    // invoker: CoinStateMaintainer::on_block_connected's payee-desync /
    // apply-gap branch. That branch can only fire when apply_block resolves a
    // PROJECTED payee — i.e. on a NON-EMPTY payee queue — and its own first act
    // is to WIPE that queue (mnstates().load({}), which also zeroes the apply
    // cursor, so gap_detected cannot fire either). Only a lane PUBLISH refills
    // it. So the ask chain is a closed cycle:
    //
    //     ask -> rearm() -> bridge -> PUBLISH -> queue refilled -> next ask
    //
    // and a bridge that FAILS CLOSED never publishes, so a second ask is
    // arithmetically impossible. The re-arm ladder was triggerable only by an
    // event that its own failure had already made unreachable.
    //
    // THE MEASUREMENT, verbatim. soak0803c failed closed at 06:13:50 with
    // "re-arms remaining: 2 — a further payee desync from the maintainer will
    // trigger one". 2h39m later the process was alive, the tip had advanced 69
    // blocks (2515479 -> 2515548, i.e. 68 blocks PAST the 64-block backoff
    // gate at h=2515543), 90 templates had been served, the EMBED-GATE
    // heartbeat was still printing "cause=mn-needs-reseed value=latched" every
    // five minutes — and there were ZERO further asks and ZERO MN-CKPT lines of
    // any kind. Those two remaining rungs were never available capacity; they
    // were UNREACHABLE capacity, and the log said the opposite.
    //
    // WHY THE FIX IS THE TRIGGER AND NOT THE POLICY. pump() is already invoked
    // on EVERY tip change (main_dash's header_chain->set_on_tip_changed) and is
    // the one lane seam that keeps running after a fail-close — it simply
    // returned at its state guard. It now re-evaluates the ladder FIRST. The
    // attempt still goes through rearm(), so everything that bounded the ladder
    // still bounds it: the kMaxRearms cap, the doubling block backoff, the
    // never-a-newer-anchor guards and every terminal block are unchanged. What
    // changed is only WHO may pull the trigger — a caller that is still alive
    // when the payee queue is wiped.
    //
    // AND IT MUST NOT REPLAY A WINDOW THAT WOULD FAIL IDENTICALLY. Two bounds,
    // both named in the log:
    //   1. the gate (rearm_gate_height): the chain must advance
    //      kRearmBackoffBlocks past the tip AT WHICH THE LANE FAILED CLOSED, on
    //      top of the existing per-re-arm ladder backoff. Without the first
    //      half, the ORIGINAL arm's fail-close (m_rearms == 0, so no ladder
    //      backoff applies yet) would self re-arm on the very next block over
    //      the identical window.
    //   2. the deterministic-repeat block (fail_closed): if a RE-ARMED replay
    //      dies at the same cursor height as the previous one, that is measured
    //      proof the failure is deterministic — the ladder is blocked
    //      TERMINALLY and says so, instead of spending its remaining rungs on
    //      the same block.

    /// The tip height at or after which the NEXT re-arm is admissible.
    /// 0 means NO height admits one (cap spent, terminally blocked, or the tip
    /// at the fail-close was never observed) — 0 is never a real gate height,
    /// so it is safe as the sentinel.
    uint32_t rearm_gate_height() const
    {
        if (m_rearm_blocked || m_rearms >= kMaxRearms) return 0;
        if (!m_failed_at_tip_known)                    return 0;
        uint32_t gate = m_failed_at_tip + kRearmBackoffBlocks;
        if (m_rearms > 0 && m_last_rearm_at_known) {
            const uint32_t ladder =
                m_last_rearm_at + (kRearmBackoffBlocks << (m_rearms - 1));
            if (ladder > gate) gate = ladder;
        }
        return gate;
    }

    /// Is there a LIVE path that can still spend the remaining ladder? This is
    /// the question "re-arms remaining: 2" used to answer wrongly.
    bool rearm_self_reachable() const
    {
        return m_state == State::FailedClosed && m_rearm_pending
               && !m_rearm_blocked && m_rearms < kMaxRearms
               && static_cast<bool>(m_tip_height) && rearm_gate_height() != 0;
    }

    /// The ladder's posture as ONE greppable sentence that distinguishes
    /// exhausted / terminally blocked / structurally unreachable / waiting on
    /// backoff / ready. A remaining-count on its own is not an answer: the
    /// defect this replaces printed "re-arms remaining: 2" for 2h39m about
    /// capacity nothing could spend.
    std::string rearm_posture() const
    {
        std::ostringstream o;
        o << "RE-ARM POSTURE: "
          << (m_rearms == 0
                  ? std::string("the ORIGINAL arm is down")
                  : ("RE-ARM " + std::to_string(m_rearms) + "/"
                     + std::to_string(kMaxRearms) + " is down"))
          << "; re-seed asks so far: " << m_rearm_asks << "; ";
        if (m_rearm_blocked) {
            o << "further re-arms are TERMINALLY BLOCKED ("
              << m_rearm_block_reason << ") — remaining capacity: NONE";
        } else if (m_rearms >= kMaxRearms) {
            o << "the re-arm cap of " << kMaxRearms
              << " is EXHAUSTED — remaining capacity: NONE";
        } else if (m_state != State::FailedClosed || !m_rearm_pending) {
            o << "re-arms remaining: " << (kMaxRearms - m_rearms)
              << ", none wanted — the lane is not in a failed-closed state that"
                 " asks for one";
        } else if (!m_tip_height || !m_failed_at_tip_known) {
            o << "re-arms remaining: " << (kMaxRearms - m_rearms)
              << " but STRUCTURALLY UNREACHABLE: no tip-height seam is wired, so"
                 " the lane has no live trigger and no way to measure the"
                 " backoff. This capacity CANNOT be spent by this process";
        } else {
            const uint32_t gate = rearm_gate_height();
            const uint32_t now  = m_tip_height();
            o << "re-arms remaining: " << (kMaxRearms - m_rearms)
              << " and REACHABLE: the lane re-arms ITSELF on a tip advance at"
                 " h>=" << gate << " (tip h=" << now << " — "
              << (now >= gate
                      ? std::string("gate CLEARED, the next tip advance re-arms")
                      : ("waiting on " + std::to_string(gate - now)
                         + " more block(s)"))
              << "). No further maintainer desync ask is needed, and none is"
                 " possible: the wiped payee queue cannot project a payee, so it"
                 " cannot desync again until this bridge publishes.";
        }
        return o.str();
    }

    /// The TICK. Called from pump() — which main_dash drives on every tip
    /// change — and therefore from a path that is still alive after the
    /// fail-close it recovers from. Returns true when a re-arm was ARMED.
    ///
    /// Cheap by construction: on the overwhelmingly common path it does two
    /// bool tests and returns. The anchor is only COPIED when the gate has
    /// actually cleared, so a per-block tick never copies ~2000 entries, and
    /// rearm() is never called with a request it would only DEFER — which is
    /// what keeps the log free of a per-block DEFERRED storm.
    ///
    /// HONEST NOTE ON COVERAGE. Deleting the `m_rearms >= kMaxRearms` half of
    /// the guard below produces NO red on its own: rearm_gate_height() carries
    /// the same check and returns 0, and rearm() itself would refuse. It is
    /// stated rather than papered over — three layers say the same thing, and
    /// only removing the cap from BOTH this guard AND rearm_gate_height() reds
    /// AnExhaustedLadderIsNotReAskedOncePerBlock. Kept anyway: the guard is
    /// what makes "poll_rearm never asks past the cap" true by reading rather
    /// than by tracing a callee.
    bool poll_rearm()
    {
        if (m_state != State::FailedClosed) return false;
        if (!m_rearm_pending)               return false;
        if (m_rearm_blocked || m_rearms >= kMaxRearms) return false;
        if (!m_tip_height || !m_failed_at_tip_known)   return false;

        const uint32_t now  = m_tip_height();
        const uint32_t gate = rearm_gate_height();
        if (gate == 0 || now < gate) {
            // A lane waiting hours on a gate must not be SILENT about it —
            // silence is what made the original defect invisible for 2h39m.
            // Rate-limited in BLOCKS (the lane owns no timer and must not grow
            // one), so it costs one line per ~kPendingLogEvery blocks.
            if (now >= m_last_pending_log + kPendingLogEvery) {
                m_last_pending_log = now;
                LOG_WARNING << "[MN-CKPT] " << rearm_posture();
            }
            return false;
        }
        // Copy: rearm() -> reset_for_arm() writes m_anchor_cp, and passing it
        // its own member would be a self-referential read during the write.
        const MnCheckpoint cp = m_anchor_cp;
        const auto out = rearm(
            cp,
            "the bridge FAILED CLOSED and the chain has advanced past the"
            " backoff gate — SELF RE-ARM from the tip seam (the maintainer"
            " cannot ask: its payee queue is wiped, so it cannot desync)");
        return out == RearmOutcome::Armed;
    }

    /// How many re-arms have actually been spent against the cap.
    uint32_t rearms() const           { return m_rearms; }
    /// How many times a re-seed was ASKED for, including deferrals and
    /// refusals. Deliberately distinct from rearms(): "asked 9 times, re-armed
    /// 3" and "asked 3 times, re-armed 3" are different diagnoses.
    uint32_t rearm_asks() const       { return m_rearm_asks; }
    uint32_t rearm_cap() const        { return kMaxRearms; }
    bool     rearm_blocked() const    { return m_rearm_blocked; }
    /// The last named outcome, verbatim. Empty until the first ask — which is
    /// itself the answer to "was a re-seed ever asked for".
    const std::string& last_rearm_reason() const { return m_last_rearm_reason; }
    /// The trigger text of the last ask, verbatim — which PATH asked. Empty
    /// until the first ask.
    const std::string& last_rearm_trigger() const { return m_last_rearm_trigger; }
    /// The earliest height at which a re-seed ask gave us evidence of
    /// divergence; 0 = no such evidence (never a valid height here).
    uint32_t first_divergence_height() const { return m_first_divergence; }

    State              state()  const { return m_state; }
    const std::string& status() const { return m_status; }
    uint32_t anchor_height() const { return m_anchor_height; }
    uint32_t cursor_height() const { return m_next == 0 ? 0 : m_next - 1; }
    size_t   set_size()      const { return m_machine.size(); }
    /// Masternodes PERMANENTLY excluded during this bridge on SML-attested
    /// PoSe bans. Non-zero is not a failure — it is the repair working — but
    /// it IS a degradation of how much of the published set the replay
    /// verified, so it is surfaced here, in status(), and in the publish log.
    size_t   sml_recovered() const { return m_sml_recovered; }
    /// ── The self-describing divergence counters ───────────────────────────
    /// A bridge that fails closed used to say "the anchor is wrong, the replay
    /// is incomplete, or a post-anchor PoSe ban could not be attested" — three
    /// hypotheses and no measurement. These are the measurement: an operator
    /// can tell the three apart from the log alone, and can compare
    /// eligible_size() directly against `protx list valid <h>` on any dashd.
    size_t   eligible_size()      const { return m_machine.eligible_size(); }
    size_t   anchor_eligible()    const { return m_anchor_eligible; }
    size_t   pose_removed()       const { return m_pose_removed; }
    size_t   pose_reinstated()    const { return m_pose_reinstated; }
    /// Present-but-ineligible (PoSe-banned) masternodes carried BY the anchor.
    /// Zero on a `valid`-filtered anchor, which is exactly the state in which
    /// no reinstatement can happen at all — see reinstatement_report().
    size_t   anchor_ineligible()  const { return m_anchor_ineligible; }
    /// ProUpServTx PoSe revives the replay APPLIED.
    size_t   tx_revived()         const { return m_tx_revived; }
    /// ProUpServTx revives the replay DROPPED because the named proTxHash was
    /// not in the set. NON-ZERO IS A DEFECT: dashd has put a masternode back
    /// in the DIP-3 payment queue and this replay could not, so every later
    /// projection is one queue slot ahead of the chain's.
    size_t   revive_dropped()     const { return m_revive_dropped; }

    /// ── BAN-STATE PROBE accounting ────────────────────────────────────────
    /// A ProUpServTx revives only a masternode that IS PoSe-banned, and a PoSe
    /// ban is consensus-computed — never a transaction. A replay therefore
    /// cannot decide the revive from the block; it decides it from whatever
    /// masternode list it last folded. These count the times the replay had to
    /// go and MEASURE that, and the times it could not.
    ///
    ///   probes            — folds fired by an ambiguous ProUpServTx, dated at
    ///                       the block BEFORE it (the list dashcore reads).
    ///   revive_unmeasured — ProUpServTx applied with the ban state at their
    ///                       own height still unknown. NON-ZERO IS A BLIND
    ///                       SPOT: if the chain had those banned, dashd set a
    ///                       revive height and this replay did not.
    ///   revive_declined_measured — ProUpServTx a dated list proved were NOT
    ///                       revives. This is the zero that IS a measurement.
    size_t   revive_probes()      const { return m_revive_probes; }
    size_t   revive_unmeasured()  const { return m_revive_unmeasured; }
    size_t   revive_declined()    const { return m_revive_declined; }
    size_t   revive_probe_cap()   const { return m_revive_probe_cap; }
    bool     revive_probe_cap_hit() const { return m_revive_probe_cap_hit; }

    /// The ban-state probe's own line, in every report and on the published
    /// status. Same discipline as ondemand_report(): a field that was never
    /// evaluated prints n/a, never 0.
    std::string revive_probe_report() const
    {
        if (m_revive_unmeasured != 0) {
            return "BAN-STATE PROBE: " + std::to_string(m_revive_unmeasured)
                 + " ProUpServTx were applied WITHOUT a masternode list dated"
                   " at their own pre-block height, so their revive outcome is"
                   " UNKNOWN. A PoSe ban that starts AND ends between two folds"
                   " never appears in any fold's input, so for these heights"
                   " 'no reinstatement' is an ABSENCE OF MEASUREMENT. If the"
                   " chain had them banned it set nPoSeRevivedHeight and this"
                   " replay did not, and each one puts that masternode ~one"
                   " queue length ahead of the chain in every later projection."
                 + (m_revive_probe_cap_hit
                        ? " THE PROBE CAP IS EXHAUSTED ("
                          + std::to_string(m_revive_probes) + "/"
                          + std::to_string(m_revive_probe_cap)
                          + "): further ambiguity was left unmeasured rather"
                            " than asking a peer for another list."
                        : " The per-height snapshot seam was unavailable, so"
                          " no probe could be issued at all.");
        }
        if (m_revive_probes == 0 && m_revive_declined == 0) {
            return "BAN-STATE PROBE: n/a — no ProUpServTx in this replay"
                   " landed on a masternode whose ban state was both"
                   " undecided and load-bearing, so the probe path was never"
                   " exercised.";
        }
        return "BAN-STATE PROBE: " + std::to_string(m_revive_probes)
             + "/" + std::to_string(m_revive_probe_cap)
             + " used; every ProUpServTx whose revive turned on an unmeasured"
               " ban was adjudicated against a list dated EXACTLY at the block"
               " before it. " + std::to_string(m_revive_declined)
             + " were attested NOT banned (dashcore revives nothing there"
               " either, so that zero is a measurement); the rest became"
               " ordinary revives counted above. 0 left unmeasured.";
    }

    /// Why "REINSTATED: 0" is not automatically good news.
    ///
    /// Reinstatement has two sources — the wholesale SML fold flipping an
    /// entry back to valid, and an explicit ProUpServTx revive — and BOTH
    /// require the masternode to be IN the set. An anchor built from
    /// `protx list valid` filters every PoSe-banned masternode out, so it
    /// carries no revivable entry at all and its zero means "impossible
    /// here", not "none needed". This sentence says which one it is.
    std::string reinstatement_report() const
    {
        if (m_anchor_ineligible == 0) {
            std::string s =
                "REINSTATEMENT: NOT MEASURABLE on this anchor — it carries "
                + std::to_string(m_anchor_count)
                + " masternodes and ZERO of them PoSe-banned. A real DIP-3 set"
                  " at any mainnet height has banned members, so a zero here"
                  " is the fingerprint of a `protx list valid`-filtered"
                  " source: a banned masternode is ABSENT rather than present-"
                  "and-ineligible, and a ProUpServTx revive has no entry to"
                  " revive. Any 'reinstated 0' below is an absence of"
                  " measurement, NOT a measurement.";
            if (m_revive_dropped != 0) {
                s += " CONFIRMED: " + std::to_string(m_revive_dropped)
                   + " ProUpServTx revive(s) were DROPPED as unknown"
                     " masternodes during this replay.";
            }
            s += " " + revive_probe_report();
            return s;
        }
        std::string s =
            "REINSTATEMENT: measurable — the anchor carries "
            + std::to_string(m_anchor_ineligible)
            + " present-but-INELIGIBLE (PoSe-banned) masternode(s) out of "
            + std::to_string(m_anchor_count) + ". Reinstated so far: "
            + std::to_string(m_pose_reinstated) + " by the wholesale SML fold, "
            + std::to_string(m_tx_revived) + " by explicit ProUpServTx revive.";
        if (m_revive_dropped != 0) {
            s += " " + std::to_string(m_revive_dropped)
               + " ProUpServTx revive(s) were still DROPPED as unknown"
                 " masternodes — the set is INCOMPLETE beyond the PoSe-ban"
                 " axis and every later projection is that many queue slots"
                 " ahead of the chain's.";
        }
        // The second way "reinstated 0" lies. The first (above) is a
        // `valid`-filtered anchor with nothing revivable in it. This one is a
        // COMPLETE anchor whose fold sampling cannot see a ban that begins and
        // ends inside one interval — the wholesale fold's own "+0 revived"
        // then reports an interval it structurally could not observe.
        s += " " + revive_probe_report();
        return s;
    }
    bool     sml_folded()         const { return m_sml_folded; }
    uint32_t sml_folded_at()      const { return m_sml_folded_at; }
    /// The FIRST fold's height. Distinct from sml_folded_at(), which tracks the
    /// most recent — a bridge folds at the anchor, at intervals, and at the
    /// tip, so "did we fold before the first block" is a different question
    /// from "where did we fold last".
    uint32_t first_fold_height()  const { return m_first_fold_height; }
    /// ── On-demand fold accounting ─────────────────────────────────────────
    /// How many folds were triggered BY A PAYEE MISMATCH rather than by a
    /// fold point, how many queue heads they retired, the per-bridge cap, and
    /// whether that cap was ever hit. `ondemand_evaluated()` is false when no
    /// mismatch ever occurred — in which case every other number here is
    /// "never evaluated", NOT "evaluated and zero", and the reports say n/a.
    size_t   ondemand_folds()     const { return m_ondemand_folds; }
    size_t   ondemand_excluded()  const { return m_ondemand_excluded; }
    size_t   ondemand_cap()       const { return m_ondemand_cap; }
    bool     ondemand_cap_hit()   const { return m_ondemand_cap_hit; }
    bool     ondemand_evaluated() const { return m_ondemand_evaluated; }
    /// On-demand asks that were never answered. #1033 kept this SEPARATE from
    /// m_abandoned_folds on purpose (reusing that one made the report claim
    /// "the replay carried on degraded" when it had not); it is surfaced here
    /// for the same reason the fold counters are — and so a re-arm can be
    /// proven to clear it.
    size_t   ondemand_abandoned() const { return m_ondemand_abandoned; }
    /// #1033's preserved mismatch context, read through the lane. A re-arm
    /// reloads the anchor via MnStateMachine::load(), which already drops
    /// this — exposing it is how that path is PROVEN to be reached rather
    /// than assumed.
    const MnStateMachine::PendingPayeeAdjudication&
    pending_payee_adjudication() const
    {
        return m_machine.pending_payee_adjudication();
    }
    size_t   replay_registered()  const { return m_registered; }
    size_t   replay_spent()       const { return m_spent; }
    bool     failed_closed() const { return m_state == State::FailedClosed; }
    bool     published()     const { return m_state == State::Published; }
    /// ── The RE-ARM RESET witnesses ────────────────────────────────────────
    /// Exposed so a test can assert that rearm() actually cleared them, not
    /// merely that the lane "looked armed". Each of these was set by a
    /// COMPLETED bridge and, before reset_for_arm() existed, survived arm():
    /// m_requested_through is the load-bearing one — left stale it makes
    /// request_window() compute `from > end` and issue NO getdata at all, so a
    /// re-armed bridge would sit at its cursor forever with no symptom.
    bool     position_verified()  const { return m_position_verified; }
    uint32_t requested_through()  const { return m_requested_through; }
    uint32_t stalled_pumps()      const { return m_stalled_pumps; }
    size_t   sml_recovery_cap()   const { return m_sml_recovery_cap; }
    /// The machine's SPENT per-bridge demotion-walk budget. MnStateMachine::
    /// load() does not zero it, so a re-armed bridge would otherwise inherit
    /// the previous bridge's spend and fail closed on its first PoSe ban.
    size_t   sml_recovery_spent() const { return m_machine.sml_recovered_total(); }
    uint32_t last_fold_height()   const { return m_last_fold_height; }
    bool     anchor_fold_done()   const { return m_anchor_fold_done; }
    size_t   replay_applied()     const { return m_applied; }

    /// Drive the bridge: verify the anchor's chain position once the header
    /// chain reaches it, enforce the staleness bound, request the next window
    /// of block bodies, and publish when the cursor catches the tip.
    ///
    /// Safe to call as often as convenient (every tip change is ideal); it is
    /// idempotent and cheap when there is nothing to do.
    void pump()
    {
        // THE RE-ARM TICK, and it must come BEFORE the state guard. This is
        // the whole fix: pump() is driven by the tip-changed callback, which
        // keeps firing after a fail-close (the soak proves it — the tip
        // advanced 69 blocks while the lane sat terminal), and it was the guard
        // below that dropped every one of those ticks on the floor. poll_rearm
        // is a no-op unless the lane is failed-closed with a cleared gate; when
        // it does arm, the state is Waiting and the ordinary body below picks
        // the bridge straight up on this same call.
        if (m_state == State::FailedClosed) {
            poll_rearm();
            if (m_state == State::FailedClosed) return;
        }
        if (m_state != State::Waiting && m_state != State::Bridging) return;
        if (!m_tip_height) return;

        const uint32_t tip = m_tip_height();
        if (tip == 0 || tip < m_anchor_height) {
            // Headers still syncing towards the anchor. Not an error — but say
            // so periodically, because "silently waiting forever" and "working"
            // look identical from outside.
            if (tip / 10000 != m_last_wait_log / 10000) {
                m_last_wait_log = tip;
                LOG_INFO << "[MN-CKPT] waiting: header tip h=" << tip
                         << " has not reached the anchor h=" << m_anchor_height;
            }
            return;
        }

        // ── Chain-position verification (locally verified, no trust) ──────
        // Do this the moment the header chain covers the anchor height, and
        // only once. If our PoW-validated header chain says a different block
        // occupies that height, the checkpoint is for a different chain or a
        // different fork; nothing built on it can be right.
        if (!m_position_verified) {
            if (!m_header_hash_at) {
                return fail_closed("no header-hash lookup wired — cannot verify"
                                   " the checkpoint's chain position");
            }
            auto have = m_header_hash_at(m_anchor_height);
            if (!have) {
                // Height is covered but the entry is not retrievable (pruned
                // index / still loading). Retry on the next pump.
                return;
            }
            if (*have != m_anchor_hash) {
                return fail_closed(
                    "CHAIN-POSITION MISMATCH at h="
                    + std::to_string(m_anchor_height) + ": checkpoint pins "
                    + m_anchor_hash.GetHex()
                    + " but our PoW-validated header chain holds "
                    + have->GetHex()
                    + " — this anchor is for a different chain/fork");
            }
            m_position_verified = true;
            LOG_INFO << "[MN-CKPT] chain position VERIFIED: anchor h="
                     << m_anchor_height << " matches our header chain";
        }

        // ── Staleness bound ──────────────────────────────────────────────
        const uint32_t distance = tip - m_anchor_height;
        if (distance > m_max_bridge) {
            return fail_closed(
                "checkpoint is STALE: anchor h=" + std::to_string(m_anchor_height)
                + " is " + std::to_string(distance) + " blocks behind the tip h="
                + std::to_string(tip) + ", over the "
                + std::to_string(m_max_bridge) + "-block bridge limit."
                  " Upgrade to a release with a fresher masternode-set anchor,"
                  " raise --embedded-mn-bridge-max, or run with a coin RPC"
                  " (--coin-rpc-*) so the authoritative protx seed is used");
        }

        if (m_state == State::Waiting) {
            m_state = State::Bridging;
            // Size the per-mismatch demotion-walk budget against the replay
            // distance. A PoSe ban is a rare per-masternode event, so the
            // count inside a window scales with the window, not with the set
            // size: 4 covers a short bridge, +1 per 1000 blocks covers a long
            // one. Past that, "recovery" stops being a repair of a few
            // known-banned nodes and becomes a wholesale override of the
            // projection, which is precisely what this walk must never do.
            //
            // MEASURED SHAPE MISMATCH — this cap is sized for ISOLATED bans
            // and a legitimate ban BURST can exhaust it. On mainnet
            // 2026-08-02 the walk reached 5/6 legitimately, and the chain put
            // THREE masternodes out inside 73 blocks; two such bursts in one
            // ~2000-block window is 6 exclusions, i.e. the whole budget, and a
            // third masternode in either burst overruns it. Exhaustion is
            // TERMINAL. That is a real limitation of the walk, and it is a
            // second reason the per-height wholesale fold is the right
            // mechanism: a fold is ONE pass over the list and spends NO budget
            // at all, so a burst costs it nothing. The cap is deliberately
            // left as-is rather than widened — widening it would license
            // exactly the wholesale-override-by-inference this walk exists to
            // refuse, and the fold already removes the need.
            m_sml_recovery_cap = 4 + (tip - m_anchor_height) / 1000;
            m_machine.set_sml_recovery_cap(m_sml_recovery_cap);
            // ── THE ON-DEMAND FOLD CAP ───────────────────────────────────
            // Bounds ROUND TRIPS, not trust: every on-demand fold is DIP-4
            // client-verified against the coinbase of the very block it
            // judges, so an extra one costs correctness nothing. What it
            // costs is one getmnlistd and one paused replay, and a bridge
            // that mismatches on EVERY block is not experiencing bans — it
            // has a wrong anchor or a broken replay, and must stop rather
            // than hammer a peer for thousands of lists.
            //
            // SIZING, from the measurement. One on-demand fold repairs an
            // entire BURST at once (the wholesale pass retires every
            // masternode the list attests banned, not just the queue head),
            // so the cost is one round trip per DISTINCT ban EVENT that
            // reaches the queue head between two fold points. Mainnet
            // 2026-08-02: 9 masternodes left `protx list valid` across 1874
            // blocks — about one ban event per 200 blocks, and only a
            // fraction of those hit the queue head before the next scheduled
            // fold. kOnDemandFoldPerBlocks = 250 tracks that rate with
            // headroom; kOnDemandFoldBase = 8 covers a SHORT bridge, where
            // the ratio term contributes nothing but a burst can still land.
            //
            // At the default 20000-block bridge bound that is 8 + 80 = 88
            // round trips worst case, which is negligible against the 20000
            // getdata the same bridge already issues — while a runaway
            // stops after 88 instead of after 20000.
            if (!m_ondemand_cap_forced) {
                m_ondemand_cap = kOnDemandFoldBase
                               + (tip - m_anchor_height) / kOnDemandFoldPerBlocks;
            }
            if (!m_revive_probe_cap_forced) {
                m_revive_probe_cap =
                    kReviveProbeBase
                    + (tip - m_anchor_height) / kReviveProbePerBlocks;
            }
            LOG_INFO << "[MN-CKPT] bridge START: replaying h=" << m_next
                     << ".." << tip << " (" << (tip - m_next + 1)
                     << " blocks) onto the anchored set";
            // ── PERSISTENCE VISIBILITY ────────────────────────────────────
            // This lane has NO cursor persistence: every process start throws
            // away the previous run's completed replay and re-walks the whole
            // window from the pinned anchor. That is a real cost (3913 blocks
            // on 2026-08-04) and the log said NOTHING about it — "bridge
            // START: replaying h=2513001..2516913" reads exactly the same
            // whether prior work was resumed or discarded. Name it.
            m_replay_target = tip;
            m_replay_base   = m_next;
            m_replay_bytes  = 0;
            LOG_INFO << "[MN-CKPT] cursor "
                     << (m_cursor_restored ? "RESTORED" : "COLD")
                     << " lane=mn-ckpt from="
                     << (m_cursor_restored ? "persisted-cursor"
                                           : "pinned-anchor@h="
                                                 + std::to_string(m_anchor_height))
                     << " cursor=" << m_next << " target=" << tip
                     << " to_replay=" << (tip - m_next + 1)
                     << " rearms=" << m_rearms
                     << (m_cursor_restored
                             ? ""
                             : " — there is no replay-cursor persistence in"
                               " this build, so ANY replay work done by a"
                               " previous process was DISCARDED and this window"
                               " is being walked from scratch");
            m_progress.start(0, m_now());
            m_watchdog.arm(m_now());
        }

        // ── ANCHOR FOLD (F4). Two separate fixes meet on this line and BOTH
        // are kept:
        //
        //   • WHERE the fold is dispatched from. Bridge start is the only
        //     dispatch site that can ever observe cursor == anchor: the
        //     post-apply site in on_block_connected first runs at cursor ==
        //     anchor+1, and publish() runs at the final cursor, so the anchor
        //     position — the canonical NON-early one, because the loaded
        //     snapshot IS the state after connecting the anchor — was silently
        //     forfeited and the first replayed blocks went unprotected. That
        //     is the fix in "fold at the anchor cursor, not only post-apply",
        //     and this call site is it.
        //
        //   • WHICH list the fold consumes. Dispatching here was necessary but
        //     not sufficient: the old dispatch folded the TIP SML and was a
        //     no-op unless H_sml happened to equal the anchor, which during a
        //     catch-up it does not. So the dispatch now REQUESTS the list as of
        //     the anchor rather than hoping the tip one is dated there, and the
        //     anchor fold fires every time instead of by coincidence.
        if (!m_snapshot_pending && !m_anchor_fold_done
            && m_next == m_anchor_height + 1 && m_request_snapshot) {
            m_anchor_fold_done = true;
            if (begin_fold(m_anchor_height)) return;   // paused; reply resumes
        }
        // A PAUSED replay is a stopped replay. If the reply never comes (peer
        // dropped it, swapped, or does not serve that height) the bridge would
        // wait forever with no symptom other than "the arm never armed" — the
        // silent-refusal defect class. Re-ask, then give up on THAT fold point
        // and carry on degraded rather than wedge.
        if (m_snapshot_pending && !tick_pending_fold()) return;

        // Cursor already at (or past) the tip: the bridge is complete.
        if (m_next > tip) { publish(tip); return; }

        // Stall detection. pump() is driven by tip changes (~2.5 min apart on
        // mainnet), so "the cursor has not moved since the last pump" means a
        // getdata response was dropped. Re-request from the cursor rather than
        // waiting forever with no symptom other than "the arm never armed".
        if (m_next == m_last_pump_next) {
            ++m_stalled_pumps;
            m_rerequest_from_cursor = true;
            if ((m_stalled_pumps % 5) == 0)
                LOG_WARNING << "[MN-CKPT] bridge stalled at h=" << m_next
                            << " across " << m_stalled_pumps
                            << " drive attempts — re-requesting from the cursor";
        } else {
            m_stalled_pumps = 0;
        }
        m_last_pump_next = m_next;

        request_window(tip);
    }

    /// Fold the next bridge block. Wired to the SAME block-connect ingest the
    /// maintainer uses; blocks that are not the exact next height are ignored
    /// (a live tip block arriving mid-bridge must not be folded onto a stale
    /// cursor — that is the E4-soak bad-cb-payee shape).
    void on_block_connected(const BlockType& block, uint32_t height)
    {
        if (m_state != State::Bridging) return;
        // PAUSED: a fold request is outstanding for the current cursor. The
        // cursor must not advance past the height the pending list describes,
        // or the fold would land EARLY. Blocks arriving now are dropped; they
        // are re-requested when the fold completes.
        if (m_snapshot_pending) return;
        if (height != m_next) return;

        // Publish the SML's own height into the machine BEFORE it adjudicates
        // anything, so the reactive demotion walk's attestations are gated on
        // freshness (MnStateMachine::sml_attest). A stale SML attesting a
        // since-revived masternode "invalid" would otherwise license a
        // PERMANENT demotion.
        refresh_sml_height();

        // ── BAN-STATE PROBE. Fire BEFORE the apply, because the question is
        // about the PRE-block list and the cursor is standing exactly on
        // height-1 right now — the one position at which a fold for height-1
        // is valid by the same construction every other fold here relies on.
        // Returns true when a request is outstanding (replay PAUSED; the reply
        // resumes it and re-delivers this very block).
        if (begin_revive_probe(block, height)) return;

        const auto r = m_machine.apply_block(block, height);

        // The anchor's own falsification test. apply_block already logs the
        // detail; here it is TERMINAL (unlike the maintainer's path, which can
        // ask for an RPC re-seed — daemonless has nothing to re-seed from, and
        // guessing is exactly what must never happen).
        if (r.payee_desync && !r.gap_detected) {
            // ── ON-DEMAND FOLD. The mismatch IS the trigger: ask for the
            // masternode list dated exactly at this height and re-adjudicate.
            // Returns true when the request was issued (the replay is now
            // PAUSED and the reply resumes it) or when the reply arrived
            // inline and has already resolved or failed the bridge. False
            // means the path was unavailable, and the ONLY other answer is
            // the one this lane has always given.
            if (begin_ondemand_fold(block, height, r)) return;
        }
        if (r.gap_detected || r.payee_desync) {
            return fail_closed(
                std::string("bridge replay ")
                + (r.gap_detected ? "GAP" : "PAYEE DESYNC") + " at h="
                + std::to_string(height) + ". " + divergence_report(r));
        }
        if (r.total_after == 0) {
            return fail_closed(
                "bridge replay emptied the masternode set at h="
                + std::to_string(height) + " — cannot back a payee");
        }

        m_next = height + 1;
        ++m_applied;
        note_replay_advance(block);
        // ── PER-HEIGHT PoSe fold. The cursor is now exactly `height`; if
        // this is a fold point, request the list AS OF it and pause.
        if (m_tip_height) {
            const uint32_t tip_now = m_tip_height();
            auto target = fold_target(height, tip_now);
            if (target && *target == height && begin_fold(height)) {
                // Paused. Do not fall through to request_window(): the reply
                // resumes the replay.
                m_sml_recovered += r.sml_recovered;
                m_registered    += r.registered;
                m_spent         += r.spent;
                m_tx_revived    += r.revived;
                m_revive_dropped += r.revive_dropped_unknown;
                return;
            }
        }
        m_sml_recovered += r.sml_recovered;
        m_registered    += r.registered;
        m_spent         += r.spent;
        m_tx_revived    += r.revived;
        m_revive_dropped += r.revive_dropped_unknown;
        m_revive_unmeasured += r.revive_unmeasured;
        m_revive_declined   += r.revive_declined_measured;
        m_stalled_pumps = 0;

        if ((m_applied % 500) == 0) {
            LOG_INFO << "[MN-CKPT] bridge progress: applied " << m_applied
                     << " blocks, cursor h=" << height << " registered="
                     << r.total_after << " eligible=" << m_machine.eligible_size()
                     << " (anchor " << m_anchor_eligible << "; +"
                     << m_registered << " reg, -" << m_spent << " spent, -"
                     << m_pose_removed << " PoSe-removed, +"
                     << (m_pose_reinstated + m_tx_revived) << " reinstated ["
                     << m_pose_reinstated << " SML-fold, " << m_tx_revived
                     << " ProUpServTx], " << m_revive_dropped
                     << " revive(s) DROPPED unknown)"
                     << " anchor-ineligible=" << m_anchor_ineligible
                     << " sml-recovered=" << m_sml_recovered
                     << " sml-folded=" << (m_sml_folded ? "yes" : "no");
        }

        if (!m_tip_height) return;
        const uint32_t tip = m_tip_height();
        if (m_next > tip) { publish(tip); return; }
        request_window(tip);
    }

private:
    /// Push the SML's current height into the machine so the reactive
    /// demotion walk can refuse a STALE attestation. Cheap; called on every
    /// folded block because the mnlistdiff feed advances underneath us.
    void refresh_sml_height()
    {
        if (!m_sml_snapshot) return;
        const SmlSnapshot snap = m_sml_snapshot();
        m_machine.set_sml_current_height(snap.list ? snap.height : 0);
    }

    // ─────────────────────────────────────────────────────────────────────
    // PER-HEIGHT PoSe FOLD — cursor == H_sml BY CONSTRUCTION
    // ─────────────────────────────────────────────────────────────────────
    //
    // WHY THE TIP SML COULD NEVER DO THIS. A fold is only valid at one cursor
    // position: apply cursor == the height the list describes. The embedded
    // SML tracks the TIP (main_dash issues getmnlistd on every tip change), so
    // during catch-up H_sml sits at or ahead of the tip while the replay
    // cursor is behind it. Waiting for the two to coincide is a race between
    // replay rate and mnlistdiff cadence, and it loses: every failing height
    // during catch-up is a height the tip fold cannot reach. That is pinned by
    // FoldMissesTheWindowWhenTheSmlTracksTheMovingTip.
    //
    // THE FIX IS TO STOP GUESSING AND ASK. getmnlistd(ZERO, hash_at(H)) yields
    // the FULL list as of H — the same primitive quorum_member_source.hpp
    // already uses to source a historical member set. So the lane requests the
    // list for the height it is standing on, and folds THAT.
    //
    // ── WHY "EARLY" IS NOW UNREACHABLE, FROM THE CODE ────────────────────
    //
    // EARLY meant: applying validity from a list dated LATER than the cursor,
    // so a masternode banned between the cursor and the list's date is removed
    // at heights the chain still paid it. That required the list's date and
    // the cursor to differ. Here they cannot:
    //
    //   1. fold_target() picks H, and we request hash_at(H) from our OWN
    //      PoW-validated header chain. The request names a block, not a range.
    //   2. on_historical_snapshot() consumes a reply ONLY if
    //      diff.blockHash == m_snapshot_hash (the exact block we asked for)
    //      AND diff.baseBlockHash.IsNull() (a full snapshot, not a delta).
    //   3. authenticate_historical_snapshot() then REFUSES the reply unless
    //      the embedded cbTx's nHeight == H. A peer cannot substitute another
    //      block's genuine snapshot.
    //   4. The fold is applied only while m_paused_at == H == cursor_height().
    //
    // So the list is consensus-committed AT H (its root is proven into the
    // coinbase of block H, whose header we PoW-validated) and it is applied
    // with the cursor exactly at H. "Dated later than the cursor" has no
    // representable state. EARLY is not unlikely here; it is unreachable.
    //
    // ── SEQUENCING, AND THE ONE-OUTSTANDING-REQUEST CONSTRAINT ───────────
    //
    // Only one getmnlistd may be outstanding: replies are matched by block
    // hash and a second in-flight request draws a reply that matches no await
    // and leaks past the demux. The lane therefore has at most ONE request in
    // flight, enforced structurally rather than by bookkeeping:
    //
    //   • On reaching a fold height the lane sets m_snapshot_pending. pump()
    //     then returns before it can request another window, so the replay
    //     stops pulling blocks and cannot run ahead of its own fold. (There is
    //     a second check inside request_window(); mutation testing shows
    //     nothing reaches it today, so read that one as a backstop.)
    //   • It issues exactly one request and will not issue another until that
    //     one is consumed, refused, or the lane fails closed.
    //   • on_block_connected() ignores blocks while paused (the cursor cannot
    //     advance past the fold height), so no second fold height can be
    //     reached while one is in flight.
    //
    // Coarse-grained on purpose: kDefaultFoldInterval blocks between folds,
    // plus the anchor and the final height. The per-mismatch walk covers the
    // gaps, which is the split that was already right — it was just being fed
    // the wrong SML.
    //
    // ── WHAT THE FOLD IS WORTH NOW ───────────────────────────────────────
    //
    // The tip-SML fold trusted a list that on_mnlistdiff never checks against
    // cbTx.merkleRootMNList. This one is DIP-4 client-verified before it is
    // believed (historical_sml.hpp), so the F5 size bound below is now
    // defence-in-depth rather than the only defence.

public:
    /// Blocks between fold points.
    static constexpr uint32_t kDefaultFoldInterval = 500;

    /// ── The ON-DEMAND fold cap, per bridge ────────────────────────────────
    /// cap = kOnDemandFoldBase + replay_blocks / kOnDemandFoldPerBlocks.
    /// The reasoning is written out at the sizing site in pump(); the short
    /// version is that this bounds ROUND TRIPS (each fold is DIP-4 verified,
    /// so more of them costs correctness nothing) and that one fold repairs a
    /// whole burst, so the rate that matters is DISTINCT BAN EVENTS — measured
    /// at roughly one per 200 blocks on mainnet 2026-08-02.
    static constexpr size_t   kOnDemandFoldBase      = 8;
    static constexpr uint32_t kOnDemandFoldPerBlocks = 250;

    /// ── The BAN-STATE PROBE cap, per bridge ───────────────────────────────
    /// cap = kReviveProbeBase + replay_blocks / kReviveProbePerBlocks.
    /// Sized from the SAME mainnet window the defect was traced in: 22
    /// ProUpServTx across 2530 blocks (~1 per 115), of which 7 landed on a
    /// masternode the replay believed valid and therefore needed a probe
    /// (~1 per 360). kReviveProbePerBlocks = 100 tracks that with better than
    /// 3x headroom; the base covers a short bridge where the ratio term is 0
    /// but a ProUpServTx can still land. Exhausting it does NOT fail the
    /// bridge — it leaves the ambiguity UNMEASURED and says so, because a
    /// bridge that has run out of probe budget is still more useful than one
    /// that hammers a peer, and the blind spot is now nameable either way.
    static constexpr size_t   kReviveProbeBase      = 8;
    static constexpr uint32_t kReviveProbePerBlocks = 100;

    /// The next height at or after `cursor` at which we want a snapshot, or
    /// nullopt when none remains before `tip`. Always includes the tip so the
    /// published set is current, and the anchor so the first replayed block is
    /// already projected from a correct eligible set.
    std::optional<uint32_t> fold_target(uint32_t cursor, uint32_t tip) const
    {
        if (cursor > tip) return std::nullopt;
        if (cursor == m_anchor_height) return cursor;          // anchor
        if (cursor == tip) return cursor;                      // final
        if (m_last_fold_height == 0) return cursor;
        if (cursor - m_last_fold_height >= m_fold_interval) return cursor;
        return std::nullopt;
    }

    // ─────────────────────────────────────────────────────────────────────
    // THE BAN-STATE PROBE — measure the gate, never guess it
    // ─────────────────────────────────────────────────────────────────────
    //
    // dashcore revives on a ProUpServTx if and only if the masternode
    // IsBanned() in the PRE-BLOCK list (specialtxman.cpp:361-370). We mirror
    // that gate against OUR belief about who is banned — and that belief is a
    // sample, taken at fold points. A ban that starts and ends between two
    // samples never enters our belief at all, so the gate reads false, the
    // revive is dropped on the floor, and nPoSeRevivedHeight stays at the
    // masternode's stale last payment. From there payee_score() sorts it ~one
    // full queue length ahead of where dashd sorts it.
    //
    // MEASURED (mainnet, anchor 2513000, fold interval 500, replay to 2515511;
    // dashd 23.1.7 asked directly for the pre-block state of every ProUpServTx
    // in the window):
    //
    //   22 ProUpServTx in 2513001..2515530
    //   20 of them landed on a masternode dashd HAD banned  -> dashd revived
    //   15 of those 20 this replay also believed banned      -> applied
    //    5 it did not (banned AND revived between two folds) -> MISSED
    //    2 landed on a masternode that was NOT banned        -> no revive,
    //      and dashd set no revive height either
    //
    // The 5 missed ones, scored our way, reach the head of our queue at
    // 2515511 / ~2516175 / ~2516176 / ~2516332 / ~2517466. The replay
    // fail-closed at 2515511 projecting the first of them, 80b4892b…, which
    // dashd will not pay until ~2516627.
    //
    // WHY NOT JUST SET revivedHeight ON EVERY ProUpServTx. Because of the 2.
    // d07e1f49… sent a service update at 2515068 with ban height -1 and PoSe
    // penalty 0; dashd left its revive height at 2501164 and its score at its
    // last payment, 2513500. Setting 2515068 there moves it 1568 blocks DOWN
    // the queue and fails at ~2515558 instead — a guess that trades one
    // divergence for another 47 blocks later. 3da232a3… shows the same shape
    // one block wide: two ProUpServTx in consecutive blocks, only the FIRST a
    // revive. The transaction does not carry the answer.
    //
    // WHY NOT SHRINK THE FOLD INTERVAL. It cannot work, at any interval. A
    // ban+revive pair fits between any two fixed samples — 80b4892b…'s was
    // FOUR blocks wide — so a finer cadence only shrinks the window while
    // paying a round trip continuously, ban or no ban. At interval 1 it is no
    // longer a replay, it is a list fetch per block, which is the daemon
    // dependency this whole lane exists to remove.
    //
    // WHY EVENT-TRIGGERED SAMPLING IS EXACTLY ENOUGH. The set of heights at
    // which an unobserved ban can permanently move a masternode's queue
    // position is EXACTLY the set of heights carrying a ProUpServTx for a
    // masternode we hold and believe valid: nowhere else does the ban state
    // feed a field that outlives the ban. So the replay fires a fold at those
    // heights and only those. On the measured window that is 7 probes across
    // 2530 blocks — ~0.3% — against 5 permanent divergences removed. An
    // unobserved ban still costs eligibility WHILE it lasts, but that is
    // transient and already carried by the on-demand fold at the mismatch it
    // causes.
    //
    // The probe is the ORDINARY fold: same request, same DIP-4 client
    // verification, same one-in-flight pause, same cursor==H-by-construction
    // invariant (the cursor sits on height-1 when the probe is issued). It
    // needs no new trust and no new reply route.
    bool begin_revive_probe(const BlockType& block, uint32_t height)
    {
        if (height == 0) return false;
        // LATCH. A probe that was abandoned, or answered by a list that did
        // not move the gate, must not re-fire when the block is re-delivered:
        // that is a livelock, not a retry.
        if (m_revive_probe_at == height - 1) return false;
        const auto cands = m_machine.unmeasured_revive_candidates(block, height);
        if (cands.empty()) return false;

        if (m_revive_probes >= m_revive_probe_cap) {
            m_revive_probe_cap_hit = true;
            LOG_WARNING
                << "[MN-CKPT] BAN-STATE PROBE REFUSED at h=" << height
                << ": " << m_revive_probes << "/" << m_revive_probe_cap
                << " probes already spent. " << cands.size()
                << " ProUpServTx here will be applied with the pre-block ban"
                   " state UNMEASURED. This is reported, not swallowed — see"
                   " the BAN-STATE PROBE line.";
            return false;
        }
        // THE LATCH IS SET BEFORE THE REQUEST, and that ordering is
        // load-bearing rather than tidy. m_request_snapshot may be answered
        // INLINE — an ordered stream, or a same-thread demux — in which case
        // on_historical_snapshot() clears m_snapshot_pending, folds, and
        // resumes the replay, re-delivering THIS block into
        // on_block_connected() before begin_fold() has even returned. With the
        // latch set afterwards that re-entry sees an unlatched lane and asks
        // again, recursively: mutation-tested, and it does not terminate on
        // its own. Setting it first makes the re-entry a no-op.
        const uint32_t probe_at      = height - 1;
        const uint32_t latch_before  = m_revive_probe_at;
        const size_t   probes_before = m_revive_probes;
        m_revive_probe_at = probe_at;
        ++m_revive_probes;
        // THIS block was already requested and has just been dropped on the
        // floor. request_window() asks only for heights above
        // m_requested_through, so without this the resume would ask for
        // height+1 — which on_block_connected ignores (height != m_next) — and
        // the bridge would sit on the stall probe until the next tip change.
        // The probe is the one path that pauses on a block it has ALREADY
        // consumed, so it is the one path that has to say so.
        m_rerequest_from_cursor = true;
        if (!begin_fold(probe_at, /*on_demand=*/false,
                        "BAN-STATE PROBE (a ProUpServTx at h="
                        + std::to_string(height)
                        + " whose revive turns on a ban this set never"
                          " measured)")) {
            // No snapshot seam, or the header for height-1 is not held.
            // Nothing was asked, so nothing was spent: put the budget and the
            // latch back exactly as they were. The ambiguity survives and
            // apply_block will COUNT it.
            m_revive_probe_at = latch_before;
            m_revive_probes   = probes_before;
            return false;
        }
        return true;
    }

    /// Ask for the list as of `height`, and pause the replay until it lands.
    /// Returns true when a request was issued (caller must stop pulling).
    bool begin_fold(uint32_t height, bool on_demand = false,
                    const std::string& why = std::string())
    {
        if (!m_request_snapshot || !m_merkle_root_at || !m_header_hash_at)
            return false;
        auto hash = m_header_hash_at(height);
        if (!hash) return false;              // header not held yet; retry later
        m_snapshot_pending = true;
        m_snapshot_hash    = *hash;
        m_snapshot_height  = height;
        m_snapshot_waits   = 0;
        // ── EVERY pause drops its in-flight bodies, so EVERY resume must
        // re-request from the cursor (task #103; found measuring #1151's
        // baseline). on_block_connected() returns early while
        // m_snapshot_pending is set, so whatever getdata was outstanding when
        // this fold paused is answered into the void. The resume paths call
        // request_window(), but with this flag clear that computes
        // from = m_requested_through + 1 — PAST the end of the already-
        // requested window — and issues ZERO getdata. The bridge then sits
        // idle until the next tip change (~2.5 min mainnet), once per fold:
        // measured 4m16s, 5m34s, then 16m25s of dead gap on a cold bridge —
        // 26 of its first 28 minutes doing nothing, against a fetch lane that
        // moves at ~190 blk/s.
        //
        // The BAN-STATE PROBE path already sets this flag for itself, with a
        // comment naming this exact failure ("the bridge would sit on the
        // stall probe until the next tip change"); it was the ONE pause path
        // that did, because it uniquely re-consumes a block it already folded.
        // But the dropped-getdata half applies to ALL pauses, so the flag
        // belongs to the pause itself, not to one caller. One flag set per
        // pause, consumed once by the next request_window() (which resets it),
        // and re-requesting a body we already hold is harmless — apply_block
        // skips heights != m_next. No storm: a pause re-arms exactly once.
        //
        // SET BEFORE m_request_snapshot below, for the same reason the probe
        // sets its latch first: the request may be answered INLINE (ordered
        // stream / same-thread demux), in which case on_historical_snapshot()
        // resumes and calls request_window() before begin_fold() returns —
        // and that resume must already see the flag.
        m_rerequest_from_cursor = true;
        LOG_INFO << "[MN-CKPT] "
                 << (!why.empty()
                         ? why
                         : (on_demand
                                ? std::string("ON-DEMAND PoSe fold (triggered"
                                              " by the payee mismatch itself,"
                                              " not by a fold point)")
                                : std::string("PoSe fold")))
                 << ": requesting the masternode list AS OF"
                    " h=" << height << " (" << hash->GetHex().substr(0, 16)
                 << ") — replay PAUSED until it lands, so the cursor cannot"
                    " run past the height the list describes";
        m_request_snapshot(*hash);
        return true;
    }

    // ─────────────────────────────────────────────────────────────────────
    // ON-DEMAND PoSe FOLD — fire AT the mismatch, not at a fold point
    // ─────────────────────────────────────────────────────────────────────
    //
    // MEASURED (contabo daemonless soak vs hotel dashd, mainnet, anchor
    // 2513000, fold interval 500):
    //
    //     h=2513000  protx list valid 2068  projected payee PRESENT  <- folded
    //     h=2513400                   2068  PRESENT
    //     h=2513488                   2066  ABSENT  <- PoSe-banned in this range
    //     h=2513489                   2066  ABSENT  <- projected anyway -> DEAD
    //     next fold point   h=2513500                <- ELEVEN BLOCKS TOO LATE
    //
    // The chain paid 4cad8728bb473c80…; we projected e8626fcd57f6394d…, which
    // the chain had already banned. THREE separate builds fail-closed at that
    // identical height — one of them carrying no fold code at all. So the fold
    // MECHANISM is right and only its GRANULARITY was wrong: a ban landing
    // strictly inside a fold interval is invisible to fold points.
    //
    // WHY NOT JUST SHRINK THE INTERVAL. A finer interval pays a network round
    // trip CONTINUOUSLY (every interval, ban or no ban) and STILL leaves a
    // window — it only makes the window smaller. Firing at the mismatch pays a
    // round trip only when a mismatch actually occurs, and leaves NO window at
    // all, because the list we ask for is dated at the very height that failed.
    //
    // SAFETY IS THE #1028 ARGUMENT, UNCHANGED:
    //   * the list is DIP-4 client-verified against the block's own coinbase
    //     commitment (historical_sml.hpp), before it is believed;
    //   * cursor == H holds BY CONSTRUCTION — we name the height being
    //     adjudicated, ask for hash_at(H) from our OWN PoW-validated header
    //     chain, and authenticate that the reply's cbTx nHeight IS H;
    //   * the replay PAUSES while the request is outstanding, because exactly
    //     one getmnlistd may be in flight (a duplicate reply is
    //     indistinguishable from the first). Same m_snapshot_pending latch as
    //     the interval fold, so there is one pause mechanism, not two;
    //   * the reply comes back through the SAME HistoricalMnListDiffDemux —
    //     no second filter slot, no second route to the live tip SML;
    //   * every failure lands on TODAY'S behaviour: fail closed, never a
    //     guessed payee.
    //
    // Returns TRUE when the mismatch has been TAKEN OVER by this path — either
    // a request is outstanding (replay paused) or an inline reply has already
    // resolved or failed the bridge. FALSE means the caller must fail closed
    // exactly as it did before this path existed.
    bool begin_ondemand_fold(const BlockType& block, uint32_t height,
                             const MnStateMachine::ApplyResult& r)
    {
        // Nothing to re-adjudicate: the machine refused for a reason a better
        // list cannot change (e.g. the pre-block queue was empty).
        if (!m_machine.pending_payee_adjudication().present) return false;
        if (m_machine.pending_payee_adjudication().height != height) return false;
        // The seams are wired as a pair or not at all (main_dash), but a lane
        // driven without them must degrade, not wedge.
        if (!m_request_snapshot || !m_merkle_root_at || !m_header_hash_at)
            return false;
        // ONE outstanding getmnlistd. UNREACHABLE today and mutation testing
        // says so — deleting it produces no red, because on_block_connected
        // returns early while paused, so no block can be applied to mismatch
        // while a request is in flight. Kept as a backstop: the constraint is
        // hard (a second in-flight ask draws a reply that matches no await and
        // leaks past the demux), and it is checked where it would be spent.
        if (m_snapshot_pending) return false;

        // From here on the cap has been EVALUATED, so its counters mean
        // "measured", not "never looked".
        m_ondemand_evaluated = true;
        if (m_ondemand_folds >= m_ondemand_cap) {
            m_ondemand_cap_hit = true;
            LOG_WARNING << "[MN-CKPT] ON-DEMAND PoSe FOLD REFUSED at h="
                        << height << ": " << m_ondemand_folds
                        << " on-demand folds already used of a per-bridge cap of "
                        << m_ondemand_cap << " (cap = " << kOnDemandFoldBase
                        << " + replay_blocks/" << kOnDemandFoldPerBlocks
                        << "). A bridge that needs more than this is not"
                           " experiencing PoSe bans — it has a wrong anchor or a"
                           " broken replay — so it stops here rather than asking"
                           " a peer for a masternode list per block.";
            return false;
        }

        // Stash everything the re-adjudication needs. The block is copied
        // because the reply is asynchronous in production and the caller's
        // buffer will be long gone; this costs one block copy per MISMATCH,
        // not per block.
        m_ondemand_block  = block;
        m_ondemand_height = height;
        m_ondemand_r      = r;
        m_ondemand_pending = true;
        if (!begin_fold(height, /*on_demand=*/true)) {
            m_ondemand_pending = false;
            return false;
        }
        return true;
    }

    /// Called once per pump() while a fold request is outstanding. Returns
    /// TRUE when the fold has been ABANDONED and the caller may resume the
    /// replay; FALSE while it is still worth waiting.
    bool tick_pending_fold()
    {
        ++m_snapshot_waits;
        if (m_snapshot_waits == kFoldRetryPumps && m_request_snapshot) {
            LOG_WARNING << "[MN-CKPT] no reply to the h=" << m_snapshot_height
                        << " masternode-list request after " << m_snapshot_waits
                        << " drives — re-asking (same block, so still ONE"
                           " outstanding request: a reply to either ask is"
                           " indistinguishable and both are ours)";
            m_request_snapshot(m_snapshot_hash);
            return false;
        }
        if (m_snapshot_waits < kFoldGiveUpPumps) return false;

        // An ON-DEMAND fold cannot be abandoned "degraded": the replay is
        // parked on an UNRESOLVED payee mismatch, so resuming would mean
        // carrying on with a queue we already know disagrees with the chain.
        // The honest end is the one this lane always had.
        if (m_ondemand_pending) {
            remember_abandoned(m_snapshot_hash);
            m_snapshot_pending = false;
            m_ondemand_pending = false;
            // Counted SEPARATELY from m_abandoned_folds on purpose: that
            // counter's whole meaning is "the replay carried on degraded over
            // that interval", and this replay did not carry on at all.
            ++m_ondemand_abandoned;
            fail_closed(
                "bridge replay PAYEE DESYNC at h="
                + std::to_string(m_ondemand_height)
                + ": the ON-DEMAND masternode-list request for that exact"
                  " height went unanswered across "
                + std::to_string(m_snapshot_waits)
                + " drives, so the mismatch was never adjudicated. "
                + divergence_report(m_ondemand_r));
            return false;   // the caller must NOT resume
        }

        // GIVE UP on this fold point rather than wedge the whole bridge. The
        // cursor is still exactly at m_snapshot_height, so nothing is
        // mis-dated; we simply do not get this fold, and the per-mismatch walk
        // carries the interval as it did before the fold existed.
        LOG_WARNING << "[MN-CKPT] ABANDONING the PoSe fold at h="
                    << m_snapshot_height << " after " << m_snapshot_waits
                    << " drives with no usable reply. The replay RESUMES"
                       " degraded: this interval is carried by the"
                       " per-mismatch walk alone, whose budget a ban BURST can"
                       " exhaust. This is reported in status(), not swallowed.";
        // The claim is NOT released. A late reply to an abandoned request is
        // still a base=ZERO snapshot at an OLD block, and letting it fall
        // through to the tip feed would rewrite the LIVE tip SML to a past
        // state — the reward-critical corruption. We keep claiming it and drop
        // it on the floor.
        remember_abandoned(m_snapshot_hash);
        m_snapshot_pending = false;
        m_abandoned_folds++;
        m_last_fold_height = m_snapshot_height;   // do not re-ask immediately
        return true;
    }

    /// Consume a historical snapshot reply. Returns TRUE iff it answered a
    /// request THIS lane made — in which case the caller must NOT also feed
    /// the tip-SML maintainer, even if the lane then refuses the content or
    /// had already given up waiting for it.
    bool on_historical_snapshot(const vendor::CSimplifiedMNListDiff& diff)
    {
        if (!diff.baseBlockHash.IsNull()) return false;   // not a full snapshot
        if (!m_snapshot_pending || diff.blockHash != m_snapshot_hash) {
            // A LATE reply to a request we abandoned. Claim it (so it cannot
            // reach the live tip SML) and drop it: the cursor has moved on, so
            // applying it now would be a fold dated BEFORE the cursor.
            if (is_abandoned(diff.blockHash)) {
                LOG_WARNING << "[MN-CKPT] late masternode-list reply for an"
                               " ABANDONED fold ("
                            << diff.blockHash.GetHex().substr(0, 16)
                            << ") — claimed and DROPPED. It must not reach the"
                               " live tip SML, and it is too late to fold.";
                return true;
            }
            return false;
        }

        m_snapshot_pending = false;
        const uint32_t h = m_snapshot_height;
        const bool on_demand = m_ondemand_pending;

        vendor::CCbTx cbtx;
        auto sml = authenticate_historical_snapshot(
            diff, h, m_merkle_root_at, cbtx, "MN-CKPT");
        if (!sml) {
            m_ondemand_pending = false;
            fail_closed(
                "the masternode list served for h=" + std::to_string(h)
                + " failed DIP-4 client verification (see the AUTH FAILED line"
                  " above). Refusing to fold an unauthenticated list into the"
                  " payee set — that list decides who gets paid."
                + (on_demand
                       ? " This was an ON-DEMAND fold, so the payee mismatch"
                         " at that height also stands unresolved."
                       : ""));
            return true;   // consumed: it matched our await
        }

        if (on_demand) { finish_ondemand_fold(*sml, h); return true; }

        apply_fold(*sml, h);
        if (m_state != State::Bridging) return true;

        // Resume: the cursor is exactly at h, so the next block is h+1.
        if (m_tip_height) {
            const uint32_t tip = m_tip_height();
            if (m_next > tip) { publish(tip); return true; }
            request_window(tip);
        }
        return true;
    }

    bool snapshot_pending() const { return m_snapshot_pending; }
    uint32_t folds_applied() const { return m_folds; }
    uint32_t abandoned_folds() const { return m_abandoned_folds; }

    /// Pumps to wait before re-asking, and before giving up on a fold point.
    /// pump() is driven by tip changes (~2.5 min on mainnet), so these are
    /// generous in wall-clock terms and deliberately so: abandoning a fold
    /// costs the bridge its burst-proof mechanism for that interval.
    static constexpr uint32_t kFoldRetryPumps  = 3;
    static constexpr uint32_t kFoldGiveUpPumps = 12;

private:
    /// Keep claiming a small ring of abandoned request hashes. Bounded: this
    /// is a leak-proof guard, not a history.
    static constexpr size_t kAbandonedRing = 16;
    void remember_abandoned(const uint256& h)
    {
        if (m_abandoned.size() >= kAbandonedRing) m_abandoned.erase(m_abandoned.begin());
        m_abandoned.push_back(h);
    }
    bool is_abandoned(const uint256& h) const
    {
        return std::find(m_abandoned.begin(), m_abandoned.end(), h)
               != m_abandoned.end();
    }

    /// Resolve an ON-DEMAND fold: an AUTHENTICATED list dated exactly at the
    /// height whose payee mismatched. Two steps, in this order and for two
    /// different reasons:
    ///
    ///   1. WHOLESALE FOLD. Every masternode the list attests banned leaves
    ///      the payee-eligible set in one pass, so a ban BURST inside the fold
    ///      interval costs the same as a single ban. Same apply_fold() the
    ///      interval folds use — same F5 sanity bound, same counters, same log
    ///      line — and legitimate here for the same reason: the cursor is
    ///      exactly at the height the list describes.
    ///
    ///   2. RE-ADJUDICATE THIS BLOCK'S PAYEE. The fold repairs the queue for
    ///      every LATER block, but block `height` itself still has an
    ///      unattributed payment; leaving it unattributed would desync the
    ///      very next block. The re-adjudication demands the same unrelaxed
    ///      evidence the walk always did — the accepted candidate's
    ///      scriptPayout must EXACTLY equal an output this block pays.
    ///
    /// Any refusal at either step is TERMINAL, exactly as a payee mismatch has
    /// always been on this lane.
    void finish_ondemand_fold(const vendor::CSimplifiedMNList& sml,
                              uint32_t height)
    {
        m_ondemand_pending = false;
        ++m_ondemand_folds;

        apply_fold(sml, height);
        if (m_state != State::Bridging) return;   // F5 refused; already closed

        const auto rr =
            m_machine.readjudicate_payee(m_ondemand_block, height, sml);
        if (!rr.recovered) {
            return fail_closed(
                "bridge replay PAYEE DESYNC at h=" + std::to_string(height)
                + " SURVIVED the ON-DEMAND PoSe fold: " + rr.refusal
                + ". The masternode list dated EXACTLY at that height was"
                  " fetched and DIP-4 client-verified, so staleness is ruled"
                  " out — this is a real divergence, not a missed ban. "
                + divergence_report(m_ondemand_r));
        }
        m_ondemand_excluded += rr.excluded;
        // The one post-apply check the desync branch jumped over. Structurally
        // unreachable — a payee mismatch requires a non-empty projection — but
        // "publishing a set that cannot back a payee" is exactly what this lane
        // exists to prevent, so it is not left to an argument.
        if (m_ondemand_r.total_after == 0) {
            return fail_closed(
                "bridge replay emptied the masternode set at h="
                + std::to_string(height) + " — cannot back a payee");
        }

        // The bookkeeping the ordinary post-apply path would have done. It was
        // skipped when apply_block reported the mismatch, and the block IS
        // applied — only its attribution was withheld until now.
        m_next = height + 1;
        ++m_applied;
        // The on-demand path is where BOTH nodes froze on 2026-08-04, right
        // after this line. Recording progress here is what gives the watchdog a
        // truthful last-progress timestamp to measure that freeze from.
        note_replay_advance(m_ondemand_block);
        m_sml_recovered += m_ondemand_r.sml_recovered;
        m_registered    += m_ondemand_r.registered;
        m_spent         += m_ondemand_r.spent;
        m_tx_revived    += m_ondemand_r.revived;
        m_revive_dropped += m_ondemand_r.revive_dropped_unknown;
        m_stalled_pumps = 0;
        m_ondemand_r    = MnStateMachine::ApplyResult{};
        m_ondemand_block = BlockType{};

        // Resume: the cursor is exactly at `height`, so the next block is +1.
        if (!m_tip_height) return;
        const uint32_t tip = m_tip_height();
        if (m_next > tip) { publish(tip); return; }
        request_window(tip);
    }

    /// Apply an AUTHENTICATED list dated exactly at `height`, with the cursor
    /// at `height`. Every caller must have established that equality.
    void apply_fold(const vendor::CSimplifiedMNList& sml, uint32_t height)
    {
        const size_t before = m_machine.eligible_size();

        // F5 SANITY BOUND, now defence-in-depth. The list is DIP-4 verified
        // above, so this no longer stands alone — but a fold is still a
        // wholesale rewrite of who may be paid, and a bound that costs nothing
        // is worth keeping against a future path that forgets to verify.
        const size_t would_remove = count_fold_removals(sml);
        const size_t bound = std::max<size_t>(kMinFoldRemovals,
                                             before / kMaxFoldRemovalDivisor);
        if (before != 0 && would_remove > bound) {
            return fail_closed(
                "SML PoSe FOLD REFUSED at h=" + std::to_string(height)
                + ": the list would retire " + std::to_string(would_remove)
                + " of " + std::to_string(before)
                + " payee-eligible masternodes in one pass, over the 1/"
                + std::to_string(kMaxFoldRemovalDivisor) + " sanity bound of "
                + std::to_string(bound) + ". A PoSe ban is a rare per-node"
                  " event; a fold this large is not a ban wave. (The list WAS"
                  " DIP-4 client-verified, so this is defence-in-depth, not"
                  " the only defence — treat it as a signal that the anchor or"
                  " the replay is wrong rather than that the peer lied.)");
        }

        const auto vr = m_machine.sync_validity_from_sml(sml, height);
        const size_t after = m_machine.eligible_size();
        if (!m_sml_folded) m_first_fold_height = height;
        m_sml_folded       = true;
        m_sml_folded_at    = height;
        m_last_fold_height = height;
        m_folds            += 1;
        m_pose_removed     += vr.flipped_to_invalid;
        m_pose_reinstated  += vr.flipped_to_valid;
        // DELIBERATELY NOT set_sml_current_height(height) here. That looks
        // right and is wrong. The freshness gate dates the list the WALK
        // consults, and the walk consults set_sml_validity_fn() — the LIVE TIP
        // list, not this historical snapshot. Declaring the fold's (past)
        // height would UNDERSTATE the tip list's freshness and silently
        // downgrade every walk attestation to "no opinion" until the next
        // block's refresh_sml_height() undid it. The two lists are dated
        // independently because they ARE independent.
        // WHICH ZERO. "+0 revived" here means one specific thing: no
        // masternode this set was holding as banned is attested VALID by THIS
        // list. It does NOT mean no reinstatement happened since the last
        // fold, and it never could — a PoSe ban that starts AND ends inside a
        // fold interval is absent from BOTH folds' inputs, so no cadence of
        // folds can observe it. Those heights are covered by the ban-state
        // probe instead, and the count of ones it could not reach is the only
        // honest answer to "did we miss a reinstatement". Saying so at the
        // fold is the point: this is the line an operator reads as
        // reassurance.
        const std::string zero_note =
            vr.flipped_to_valid != 0
                ? std::string()
                : (" The +0 revived is scoped to THIS list: it says no"
                   " masternode this set held as banned is attested valid at h="
                   + std::to_string(height) + ", NOT that no reinstatement"
                     " happened since the last fold — a ban that starts and"
                     " ends inside a fold interval appears in no fold's input."
                     " Those are measured by the ban-state probe: "
                   + std::to_string(m_revive_probes) + " taken, "
                   + std::to_string(m_revive_unmeasured) + " left unmeasured.");
        LOG_INFO << "[MN-CKPT] PoSe FOLD at h=" << height
                 << " (cursor == the height the list describes, by"
                    " construction): payee-eligible " << before << " -> "
                 << after << " (-" << vr.flipped_to_invalid << " banned, +"
                 << vr.flipped_to_valid << " revived; scanned " << vr.scanned
                 << " entries, " << vr.matched << " ours). List was DIP-4"
                    " client-verified against the block's own coinbase"
                    " commitment." << zero_note;
    }

public:
    /// How much of the payee-eligible set a single fold may retire: at most
    /// 1/N of it. Deliberately blunt — the point is to bound the blast radius
    /// of an unverified list, not to model ban rates.
    static constexpr size_t kMaxFoldRemovalDivisor = 8;
    /// Absolute floor, so the bound is never zero on a small set (which would
    /// refuse every legitimate fold) and a handful of genuine bans always fits.
    static constexpr size_t kMinFoldRemovals = 4;

    /// Dry-run the fold's removal count without mutating anything, so the
    /// sanity bound can refuse BEFORE any state changes.
    size_t count_fold_removals(const vendor::CSimplifiedMNList& sml) const
    {
        size_t n = 0;
        for (const auto& e : sml.mnList) {
            if (e.isValid) continue;
            auto it = m_machine.entries().find(e.proRegTxHash);
            if (it == m_machine.entries().end()) continue;
            if (it->second.isValid) ++n;
        }
        return n;
    }

    /// The ON-DEMAND fold's own line, in every report and on the published
    /// status. It NAMES ITS CAP: measured value, threshold, and the formula
    /// that produced the threshold.
    ///
    /// A field that was never evaluated prints `n/a`, never `0` — "no mismatch
    /// ever happened" and "mismatches happened and no fold was needed" are
    /// different facts, and a bare 0 says the second while meaning the first.
    std::string ondemand_report() const
    {
        if (!m_request_snapshot || !m_merkle_root_at || !m_header_hash_at) {
            return "ON-DEMAND PoSe folds: n/a (the per-height snapshot seam is"
                   " not wired, so a mismatch can never be re-adjudicated"
                   " against a list dated at its own height).";
        }
        const std::string cap_source =
            m_ondemand_cap_forced
                ? std::string("cap set explicitly")
                : ("cap = " + std::to_string(kOnDemandFoldBase)
                   + " + replay_blocks/"
                   + std::to_string(kOnDemandFoldPerBlocks));
        if (m_ondemand_cap == 0) {
            return "ON-DEMAND PoSe folds: DISABLED (cap 0, " + cap_source
                 + ") — a payee mismatch between fold points is terminal, which"
                   " is the pre-on-demand behaviour."
                 + (m_ondemand_evaluated
                        ? " One was refused on that basis."
                        : " None was ever attempted.");
        }
        if (!m_ondemand_evaluated) {
            return "ON-DEMAND PoSe folds: n/a — no payee mismatch ever reached"
                   " the on-demand path, so its cap ("
                   + std::to_string(m_ondemand_cap) + ", " + cap_source
                   + ") was never tested.";
        }
        std::string s = "ON-DEMAND PoSe folds: " + std::to_string(m_ondemand_folds)
            + "/" + std::to_string(m_ondemand_cap) + " used (" + cap_source
            + "), " + std::to_string(m_ondemand_excluded)
            + " queue-head exclusion(s) licensed by a list dated EXACTLY at the"
              " height it judged.";
        if (m_ondemand_cap_hit) {
            s += " THE CAP IS EXHAUSTED: " + std::to_string(m_ondemand_folds)
                 + " of " + std::to_string(m_ondemand_cap)
                 + " — a further mismatch was REFUSED rather than asking a peer"
                   " for another list. A bridge that needs more than this is not"
                   " experiencing PoSe bans; suspect the anchor or the replay.";
        }
        if (m_ondemand_abandoned != 0) {
            s += " " + std::to_string(m_ondemand_abandoned)
                 + " on-demand request(s) went UNANSWERED — the replay did NOT"
                   " carry on degraded, it failed closed, because it was parked"
                   " on a payee mismatch it had not adjudicated.";
        }
        return s;
    }

    /// The measurement that replaces three hypotheses. Every fail-closed on
    /// the replay path carries it, so an operator can separate "the anchor is
    /// wrong" from "the replay is incomplete" from "a PoSe ban could not be
    /// attested" WITHOUT attaching a debugger.
    std::string divergence_report(const MnStateMachine::ApplyResult& r) const
    {
        const size_t elig = m_machine.eligible_size();
        std::string s =
            "SET DELTA: payee-eligible " + std::to_string(m_anchor_eligible)
            + " at the anchor -> " + std::to_string(elig) + " now"
            + " (registered total " + std::to_string(m_machine.size()) + ")."
            + " ADDS: " + std::to_string(m_registered) + " registrations."
            + " REMOVALS: " + std::to_string(m_pose_removed)
            + " PoSe (SML-attested), " + std::to_string(m_spent)
            + " collateral spends, "
            + std::to_string(m_sml_recovered) + " demotion-walk exclusions."
            + " REINSTATED: " + std::to_string(m_pose_reinstated)
            + " by SML fold, " + std::to_string(m_tx_revived)
            + " by ProUpServTx revive, " + std::to_string(m_revive_dropped)
            + " revive(s) DROPPED as unknown masternodes."
            + " " + reinstatement_report();

        if (!m_request_snapshot || !m_merkle_root_at) {
            s += " NO PER-HEIGHT SNAPSHOT SEAM IS WIRED (getmnlistd + header"
                 " merkle-root lookup) — this replay could only ADD"
                 " masternodes, so ANY post-anchor PoSe ban lands here.";
        } else if (!m_sml_folded) {
            s += " NO per-height PoSe fold has been applied yet, so every ban"
                 " in this window is being carried by the per-mismatch walk"
                 " alone — and the walk's per-bridge budget is sized for"
                 " ISOLATED bans, so a BURST can exhaust it.";
        } else {
            s += " Per-height PoSe folds applied: " + std::to_string(m_folds)
                 + " (first at h=" + std::to_string(m_first_fold_height)
                 + ", latest at h=" + std::to_string(m_sml_folded_at)
                 + "); each was DIP-4 client-verified and applied with the"
                   " cursor exactly at the height the list describes.";
        }
        if (m_abandoned_folds != 0) {
            s += " " + std::to_string(m_abandoned_folds)
                 + " fold point(s) were ABANDONED after no usable reply — the"
                   " replay carried on degraded over those intervals, with the"
                   " per-mismatch walk alone.";
        }
        s += " " + ondemand_report();
        s += " " + revive_probe_report();
        if (m_snapshot_pending) {
            s += " A masternode-list request for h="
                 + std::to_string(m_snapshot_height) + " is OUTSTANDING and the"
                   " replay is PAUSED on it (" + std::to_string(m_snapshot_waits)
                 + " drives waited).";
        }
        if (m_sml_recovered >= m_sml_recovery_cap && m_sml_recovery_cap != 0) {
            s += " The per-bridge demotion-walk BUDGET is EXHAUSTED ("
                 + std::to_string(m_sml_recovered) + "/"
                 + std::to_string(m_sml_recovery_cap)
                 + "): further exclusions are refused by design.";
        }

        if (r.projected_payee) {
            s += " PROJECTED PAYEE: " + r.projected_payee->GetHex() + ";";
            if (!m_has_sml_fn) {
                s += " no SML validity seam is wired, so nothing can attest it.";
            } else {
                const auto op = m_machine.sml_opinion(*r.projected_payee);
                s += !op ? std::string(" the SML has NO ENTRY for it (absent is"
                                       " never treated as evidence of a ban).")
                     : (*op ? std::string(" the SML attests it VALID — so this"
                                          " is NOT an unobserved PoSe ban;"
                                          " suspect the anchor or a missed"
                                          " block (or a ban+revive entirely"
                                          " inside the window).")
                            : std::string(" the SML attests it INVALID, yet no"
                                          " candidate below it matched this"
                                          " coinbase exactly — the queue has"
                                          " diverged by more than one ban."));
            }
        } else {
            s += " No payee was projected (the pre-block eligible set was"
                 " empty).";
        }
        s += " Refusing to publish a masternode set that would mint a rejected"
             " coinbase.";
        return s;
    }

    /// ── THE PROGRESS/RATE TICK ────────────────────────────────────────────
    /// Called on EVERY cursor advance; emits at most one line per throttle
    /// window. Two jobs, and they must not be separated: it stamps the
    /// watchdog's last-progress timestamp (so a freeze is measured from the
    /// last real advance, not from the last time anything called us) and it
    /// feeds the throttled progress line.
    ///
    /// Before this existed, rate and ETA for a 3913-block replay had to be
    /// reconstructed by diffing log timestamps by hand.
    void note_replay_advance(const BlockType& block)
    {
        const int64_t now = m_now();
        m_watchdog.progress(now);
        if (m_wire_size) {
            m_replay_bytes += static_cast<uint64_t>(m_wire_size(block));
            m_have_bytes = true;
        }
        auto s = m_progress.sample(m_applied, now);
        if (s) emit_progress(*s);
    }

    void emit_progress(const diag::ProgressReporter::Sample& s)
    {
        const uint64_t total =
            m_replay_target >= m_replay_base
                ? (m_replay_target - m_replay_base + 1)
                : 0;
        const uint64_t remaining = total > s.units ? total - s.units : 0;
        LOG_INFO << "[REPLAY-PROGRESS] lane=mn-ckpt"
                 // cursor_height() (the LAST APPLIED height), not m_next: a
                 // cursor printed one past the target reads like an overrun.
                 << " cursor=" << cursor_height()
                 << " target=" << m_replay_target
                 << " done=" << diag::fmt1(diag::ProgressReporter::done_pct(
                                    s.units, total))
                 << "%"
                 << " rate=" << diag::fmt1(s.rate_per_s) << "blk/s"
                 << " eta=" << diag::fmt_eta(
                                    diag::ProgressReporter::eta_s(s, remaining))
                 << " fetched=" << (m_have_bytes ? diag::fmt_bytes(m_replay_bytes)
                                                 : std::string("n/a"))
                 << " applied=" << m_applied
                 << " payee_ok=" << m_applied
                 << " diverged=" << m_ondemand_abandoned
                 << " folds=" << m_folds
                 << " ondemand=" << m_ondemand_folds
                 << " eligible=" << m_machine.eligible_size()
                 << " elapsed=" << (s.total_ms / 1000) << "s";
    }

    void request_window(uint32_t tip)
    {
        // Keep the progress line's denominator honest: the tip moves under a
        // long replay, so a target captured only at bridge START would make
        // `done=` drift upward past 100%.
        if (tip > m_replay_target) m_replay_target = tip;
        // Never rewrite the status of a lane that has already finished or
        // refused — that status is the only record of WHY.
        if (m_state != State::Bridging) return;
        // Belt-and-braces on the one-outstanding-getmnlistd rule. TODAY THIS
        // IS UNREACHABLE and mutation-testing says so: deleting it produces no
        // red, because pump() already returns before request_window() while a
        // fold is pending and on_historical_snapshot() clears the flag before
        // resuming. It is kept because the load-bearing guards are two
        // early-returns in two other functions, and a future caller that
        // reaches request_window() by a third route must not start pulling
        // blocks past the height the pending list describes. Read it as a
        // backstop, not as the enforcement.
        if (m_snapshot_pending) return;
        if (!m_request) {
            return fail_closed("no block-request seam wired — the bridge cannot"
                               " fetch the blocks it must replay");
        }
        const uint32_t end = std::min<uint32_t>(m_next + kWindow - 1, tip);
        // Ask only for heights not already asked for, so a 20k-block bridge
        // issues ~20k getdata rather than 20k x kWindow. A detected stall
        // (pump()) forces one re-request pass from the cursor; getdata for a
        // block we already hold is harmless — apply_block skips it.
        uint32_t from = m_next;
        if (!m_rerequest_from_cursor && m_requested_through >= m_next)
            from = m_requested_through + 1;
        m_rerequest_from_cursor = false;
        // Status BEFORE the requests: a request may be answered synchronously
        // (an ordered stream, or a test harness), and the answer can publish or
        // fail the bridge — whose status must not then be overwritten by ours.
        m_status = "bridging: cursor h=" + std::to_string(m_next) + " target h="
                   + std::to_string(tip) + " ("
                   + std::to_string(m_sml_recovered)
                   + " SML-recovered exclusions)";
        for (uint32_t h = from; h <= end; ++h) {
            // Same reason: a synchronous answer may have finished or failed the
            // bridge mid-loop. Never keep pulling history for a lane that is no
            // longer bridging.
            if (m_state != State::Bridging) return;
            m_request(h);
            if (h > m_requested_through) m_requested_through = h;
        }
    }

    void publish(uint32_t bridged_to)
    {
        if (!m_publish) {
            return fail_closed("no publish seam wired — the bridged masternode"
                               " set has nowhere to go");
        }
        // Last chance for the wholesale PoSe fold: this is the cursor ==
        // H_sml case when the SML is current at the bridge target (and the
        // only chance at all for a zero-block bridge). Same one-shot equality
        // gate as the mid-replay call — it cannot double-apply and it cannot
        // fire early.
        const uint32_t as_of = m_next - 1;
        std::vector<std::pair<uint256, MNState>> out;
        out.reserve(m_machine.entries().size());
        for (const auto& [h, st] : m_machine.entries()) out.emplace_back(h, st);
        if (out.empty()) {
            return fail_closed("bridged masternode set is empty — refusing to"
                               " publish");
        }
        m_state  = State::Published;
        m_watchdog.disarm();
        // FINAL, unthrottled progress line. The last window of a replay is the
        // one an operator most wants (it carries the achieved rate for the
        // whole run in `elapsed=`), and the throttle would usually eat it.
        if (m_replay_base != 0)
            if (auto s = m_progress.flush(m_applied, m_now())) emit_progress(*s);
        // The full delta rides on BOTH the status string and the log line. A
        // degradation that is only visible in scrollback is half-silent, and
        // this lane exists to make degradation loud. `eligible` is directly
        // comparable to dashd's `protx list valid <as_of>` — which is how the
        // 2068->2059 vs 2067->2070 divergence was measured in the first place.
        const std::string delta =
            "eligible " + std::to_string(m_anchor_eligible) + " -> "
            + std::to_string(m_machine.eligible_size()) + " (+"
            + std::to_string(m_registered) + " reg, -" + std::to_string(m_spent)
            + " spent, -" + std::to_string(m_pose_removed)
            + " PoSe-removed, +"
            + std::to_string(m_pose_reinstated + m_tx_revived)
            + " reinstated, -" + std::to_string(m_sml_recovered)
            + " SML-recovered exclusions) " + reinstatement_report();
        m_status = "published " + std::to_string(out.size())
                   + " masternodes (" + std::to_string(m_sml_recovered)
                   + " SML-recovered exclusions) as-of h=" + std::to_string(as_of)
                   + " (anchor h=" + std::to_string(m_anchor_height)
                   + " + " + std::to_string(m_applied) + " replayed blocks) "
                   + delta
                   + " PoSe folds: " + std::to_string(m_folds)
                   + " (" + ondemand_report() + " "
                   + revive_probe_report() + ")";
        // A DEGRADED publish must say so. Publishing a set that was assembled
        // without the fold points it asked for looks identical, from outside,
        // to a clean bridge — and that silence is the defect: the operator has
        // no way to tell that a ban BURST in an unfolded interval was carried
        // by the walk alone, or not carried at all.
        if (m_abandoned_folds != 0) {
            m_status += " (DEGRADED: " + std::to_string(m_abandoned_folds)
                        + " fold point(s) ABANDONED — no usable masternode-list"
                          " reply, so those intervals were carried by the"
                          " per-mismatch walk alone)";
        }
        if (m_folds == 0) {
            m_status += " — NO per-height fold was ever applied; this set is"
                        " the additions-only replay plus the walk";
        }
        // A publish that is the OUTPUT OF A RE-ARM must not read like a clean
        // cold start. It is a recovery from a payee desync, and how much of the
        // per-process budget it consumed is the operator's warning that the
        // next desync may be the last one this process can answer.
        if (m_rearms != 0) {
            m_status += " [RE-ARM " + std::to_string(m_rearms) + "/"
                        + std::to_string(kMaxRearms) + " — this set is a"
                          " recovery from a payee desync, not a cold start]";
        }
        LOG_INFO << "[MN-CKPT] bridge COMPLETE: published " << out.size()
                 << " masternodes (" << m_sml_recovered
                 << " SML-recovered exclusions) as-of h=" << as_of
                 << " (anchor h=" << m_anchor_height << ", replayed "
                 << m_applied << " blocks, tip h=" << bridged_to
                 << ") " << delta << " -> publishing to the maintainer";
        m_publish(std::move(out), as_of);
    }

    void fail_closed(const std::string& why)
    {
        if (m_state == State::FailedClosed) return;
        // The height the replay DIED ON, captured before anything resets it.
        // Two fail-closes at the identical cursor are the measurement that says
        // "this failure is deterministic" — see the block below.
        const uint32_t cursor = m_next;
        m_state  = State::FailedClosed;
        m_status = why;
        // A failed-closed lane is DONE, not frozen. Saying "stalled" about it
        // would be the noise that trains an operator to ignore the tag.
        m_watchdog.disarm();
        // Only if the bridge ever STARTED. A lane that fails closed before the
        // Waiting->Bridging edge has no target and no baseline, and a
        // `target=0 done=0.0%` line would be a measurement of nothing.
        if (m_replay_base != 0)
            if (auto s = m_progress.flush(m_applied, m_now())) emit_progress(*s);
        // Deliberately ERROR, not WARNING: the operator's embedded arm will
        // not arm, and the only thing worse than saying so is not saying so.
        LOG_ERROR << "[MN-CKPT] FAIL-CLOSED: " << why;
        LOG_ERROR << "[MN-CKPT] the embedded DASH template arm will NOT serve;"
                     " templates keep routing to the dashd fallback arm (if"
                     " configured). No masternode payee will be guessed.";
        // DETERMINISTIC REPEAT. A re-armed replay that dies at the SAME cursor
        // as the previous one is not a transient: the window between the anchor
        // and that height produces the same wrong queue every time, and burning
        // the rest of the ladder on it is the fail-loop the cap exists to
        // prevent. Requires m_rearms > 0 — the ORIGINAL arm has nothing to
        // repeat yet — so a single fail-close never blocks the first recovery.
        if (m_rearms > 0 && m_have_last_fail_cursor
            && cursor == m_last_fail_cursor && !m_rearm_blocked) {
            m_rearm_blocked      = true;
            m_rearm_block_reason =
                "the re-armed replay failed closed at the IDENTICAL height h="
                + std::to_string(cursor) + " as the previous attempt, so"
                  " replaying this anchor is DETERMINISTIC — a further re-arm"
                  " would reproduce it";
        }
        m_last_fail_cursor      = cursor;
        m_have_last_fail_cursor = true;

        // ARM THE SELF RE-ARM. The tip AT THE FAIL-CLOSE is what the gate is
        // measured from: without it the ORIGINAL arm's failure (m_rearms == 0,
        // so the ladder backoff does not apply yet) would be retried over the
        // identical window on the very next block.
        m_rearm_pending    = true;
        m_last_pending_log = 0;
        if (m_tip_height) {
            m_failed_at_tip       = m_tip_height();
            m_failed_at_tip_known = true;
        } else {
            m_failed_at_tip_known = false;
        }

        // Say which generation of the bridge this was, whether any budget to
        // try again remains AND — the half that used to be missing — whether
        // anything can still spend it. "re-arms remaining: 2" was printed for
        // 2h39m about capacity no live path could reach.
        LOG_ERROR << "[MN-CKPT] " << rearm_posture()
                  << " Last re-arm outcome: "
                  << (m_last_rearm_reason.empty()
                          ? std::string("n/a (no re-seed has ever been asked"
                                        " for)")
                          : m_last_rearm_reason);
        // The STATE says its own name too, not just the scrollback: status() is
        // what the operator surfaces read, and a posture that lives only in a
        // log line is half-silent.
        m_status += " — " + rearm_posture();
    }

    /// EVERY field an arm starts from, in ONE place.
    ///
    /// arm() and rearm() both call this. That is the whole point: a second,
    /// hand-maintained reset list inside rearm() would drift from this one, and
    /// a field it forgot would not crash — it would publish a WRONG masternode
    /// set. "rearm() resets everything arm() sets" is therefore true by
    /// construction rather than by review.
    ///
    /// It also resets seven fields the old arm() did NOT, all of which are
    /// harmless on a virgin lane (they are zero-initialised, so this is a no-op
    /// at startup) and all of which are bugs on a re-arm:
    ///
    ///   m_requested_through     — stale => request_window() computes from>end
    ///                             and issues NO getdata; the bridge wedges.
    ///   m_last_pump_next        — stale => the stall probe fires (or fails to)
    ///                             against the PREVIOUS bridge's cursor.
    ///   m_stalled_pumps         — stale => a fresh bridge inherits a stall
    ///                             count it did not earn.
    ///   m_rerequest_from_cursor — stale => one spurious full-window re-request.
    ///   m_position_verified     — stale => a DIFFERENT anchor would skip the
    ///                             chain-position check entirely.
    ///   m_last_wait_log         — stale => the "waiting for headers" line is
    ///                             suppressed for the whole next decade of
    ///                             heights.
    ///   m_sml_recovery_cap      — stale => status()/divergence_report() quote
    ///                             the previous bridge's budget.
    ///
    /// The machine's SPENT walk budget is zeroed too (see
    /// MnStateMachine::reset_sml_recovery_budget) — load() deliberately does
    /// not, and a re-arm is a new bridge.
    ///
    /// HONEST NOTE ON COVERAGE. Mutation testing kills the deletion of every
    /// line in this function EXCEPT two, and they are stated rather than
    /// papered over: m_rerequest_from_cursor (unreset: at most one spurious
    /// duplicate getdata pass, which apply_block skips) and m_last_wait_log
    /// (unreset: one INFO line's rate limiter is off for the next 10000
    /// heights). Neither has a reward-path or diagnostic effect worth a test;
    /// both are reset anyway, because leaving a field dirty on purpose is how
    /// the next one gets missed.
    ///
    /// NOT reset here, on purpose: the re-arm bookkeeping (m_rearms,
    /// m_rearm_asks, m_last_rearm_at, m_first_divergence, m_rearm_blocked,
    /// m_last_rearm_reason). It MUST survive a re-arm or the cap can never
    /// fire. Nor the configured seams / m_max_bridge / m_fold_interval /
    /// m_has_sml_fn, which are wiring, not bridge state.
    void reset_for_arm(const MnCheckpoint& cp)
    {
        // The lane KEEPS its own anchor. poll_rearm() has no caller to hand it
        // one — that is the point of it — and a self re-arm that depended on an
        // extra seam being wired in main_dash would be one more thing that can
        // be forgotten, i.e. the same defect class again. Guarded because
        // poll_rearm() passes a copy of this very member.
        if (&cp != &m_anchor_cp) m_anchor_cp = cp;
        // A fresh arm is not a lane WAITING to re-arm.
        m_rearm_pending = false;
        m_anchor_height = cp.height;
        m_anchor_hash   = cp.blockhash;
        m_anchor_source = cp.source;
        m_anchor_count  = cp.entries.size();
        m_machine.load(cp.entries, cp.height);
        m_machine.reset_sml_recovery_budget();
        // F6: reset the one-shot fold latch and its counters. The latch is the
        // dangerous one — a second bridge on a re-armed lane would run
        // additions-only while sml_folded() still reported true, i.e. it would
        // LIE about having applied removals.
        m_sml_folded       = false;
        m_sml_folded_at    = 0;
        m_folds            = 0;
        m_first_fold_height = 0;
        m_last_fold_height = 0;
        m_anchor_fold_done = false;
        m_snapshot_pending = false;
        m_snapshot_hash    = uint256();
        m_snapshot_height  = 0;
        m_snapshot_waits   = 0;
        m_abandoned_folds  = 0;
        m_abandoned.clear();
        // ── #1033 ON-DEMAND fold state. Every field the on-demand arm carries
        // across a bridge, reset for the next one. The one-shot-ish latches
        // are the dangerous half again: m_ondemand_cap_hit unreset makes a
        // fresh bridge report a budget it never spent, and m_ondemand_evaluated
        // unreset makes ondemand_report() claim a mismatch reached the arm on a
        // bridge where none did — a report that lies in the SAFE-looking
        // direction is still a report an operator will act on.
        m_ondemand_pending   = false;
        m_ondemand_height    = 0;
        m_ondemand_folds     = 0;
        m_ondemand_excluded  = 0;
        m_ondemand_cap_hit   = false;
        m_ondemand_evaluated = false;
        m_ondemand_abandoned = 0;
        m_ondemand_block     = BlockType{};
        m_ondemand_r         = MnStateMachine::ApplyResult{};
        // The SIZED cap, which #1033's arm() did not reset. pump() recomputes
        // it at the Waiting->Bridging edge (kOnDemandFoldBase + replay/250),
        // exactly like m_sml_recovery_cap — so between a re-arm and the first
        // pump, status() and ondemand_report() would otherwise quote the
        // PREVIOUS bridge's budget. Restored to the declared default, never to
        // 0: a 0 cap has its own meaning ("the on-demand arm is disabled"),
        // and manufacturing that state here would be a different lie.
        // m_ondemand_cap_forced is CONFIG (set_ondemand_fold_cap) and survives,
        // which is why the reset is guarded the same way pump()'s sizing is.
        if (!m_ondemand_cap_forced) m_ondemand_cap = kOnDemandFoldBase;
        // Same argument for the probe budget, plus one more: the latch. A
        // re-armed bridge replays the SAME heights from the SAME anchor, so a
        // latch left standing would suppress the very probe the second attempt
        // exists to take.
        m_revive_probes        = 0;
        m_revive_probe_at      = 0;
        m_revive_unmeasured    = 0;
        m_revive_declined      = 0;
        m_revive_probe_cap_hit = false;
        if (!m_revive_probe_cap_forced) m_revive_probe_cap = kReviveProbeBase;
        m_pose_removed    = 0;
        m_pose_reinstated = 0;
        m_tx_revived      = 0;
        m_revive_dropped  = 0;
        m_sml_recovered   = 0;
        m_registered      = 0;
        m_spent           = 0;
        m_applied         = 0;
        m_warned_no_sml   = false;
        // The seven arm() used to forget.
        m_sml_recovery_cap      = 0;
        m_stalled_pumps         = 0;
        m_last_pump_next        = 0;
        m_requested_through     = 0;
        m_rerequest_from_cursor = false;
        m_last_wait_log         = 0;
        m_position_verified     = false;
        // Diagnostics, reset for the same reason every other counter here is:
        // a re-armed bridge that inherited the previous run's progress baseline
        // would report a negative delta and an absurd rate, and one that
        // inherited its watchdog timestamp would either cry stall immediately
        // or sit silent through a fresh freeze.
        m_replay_base    = 0;
        m_replay_target  = 0;
        m_replay_bytes   = 0;
        m_have_bytes     = false;
        m_cursor_restored = false;   // no cursor persistence exists to restore
        m_progress.start(0, m_now());
        m_watchdog.disarm();         // re-armed at the Waiting->Bridging edge
        m_anchor_eligible   = m_machine.eligible_size();
        m_anchor_ineligible = m_machine.ineligible_size();
        m_next  = cp.height + 1;
        m_state = State::Waiting;
    }

    MnStateMachine m_machine;

    RequestBlockFn m_request;
    PublishFn      m_publish;
    TipHeightFn    m_tip_height;
    HeaderHashAtFn m_header_hash_at;
    SmlSnapshotFn  m_sml_snapshot;

    State       m_state{State::Unarmed};
    std::string m_status{"unarmed"};

    uint32_t m_anchor_height{0};
    uint256  m_anchor_hash;
    std::string m_anchor_source;
    size_t   m_anchor_count{0};

    uint32_t m_next{0};             // the ONLY height apply_block may fold next
    uint32_t m_applied{0};
    size_t   m_sml_recovered{0};    // masternodes excluded on SML-attested bans
    size_t   m_anchor_eligible{0};  // payee-eligible count AT the anchor
    // Present-but-INELIGIBLE (PoSe-banned) count AT the anchor. ZERO means
    // the anchor was built from a `valid`-filtered source and therefore
    // CANNOT reinstate anything — which is what makes a "REINSTATED: 0" on
    // such an anchor an absence of measurement rather than a measurement.
    size_t   m_anchor_ineligible{0};
    size_t   m_pose_removed{0};     // masternodes the wholesale fold banned
    size_t   m_pose_reinstated{0};  // masternodes the wholesale fold revived
    size_t   m_tx_revived{0};       // ProUpServTx PoSe revives APPLIED
    size_t   m_revive_dropped{0};   // ProUpServTx revives DROPPED: unknown MN
    bool     m_sml_folded{false};   // at least one per-height fold has run
    uint32_t m_sml_folded_at{0};    // ...most recently at this height
    uint32_t m_folds{0};            // how many per-height folds were applied
    uint32_t m_first_fold_height{0};
    uint32_t m_last_fold_height{0};
    uint32_t m_fold_interval{kDefaultFoldInterval};
    bool     m_anchor_fold_done{false};
    // At most ONE outstanding getmnlistd, enforced structurally (request_window
    // and on_block_connected both bail while this is set).
    bool     m_snapshot_pending{false};
    uint256  m_snapshot_hash;
    uint32_t m_snapshot_height{0};
    uint32_t m_snapshot_waits{0};     // pumps spent waiting on the current one
    uint32_t m_abandoned_folds{0};
    std::vector<uint256> m_abandoned; // requests we gave up on but still claim
    // ── ON-DEMAND fold state. m_ondemand_pending rides ALONGSIDE
    // m_snapshot_pending rather than replacing it: there is one pause
    // mechanism and one outstanding request, and this only says which of the
    // two dispatch reasons owns the reply.
    bool      m_ondemand_pending{false};
    BlockType m_ondemand_block;         // the mismatching block, kept to re-judge
    uint32_t  m_ondemand_height{0};
    MnStateMachine::ApplyResult m_ondemand_r;  // its counters + projected payee
    size_t    m_ondemand_folds{0};
    size_t    m_ondemand_excluded{0};
    size_t    m_ondemand_cap{kOnDemandFoldBase};
    bool      m_ondemand_cap_forced{false};    // set_ondemand_fold_cap() wins
    bool      m_ondemand_cap_hit{false};
    bool      m_ondemand_evaluated{false};     // a mismatch ever reached it
    size_t    m_ondemand_abandoned{0};         // on-demand asks never answered
    // ── BAN-STATE PROBE state. Rides the SAME m_snapshot_pending pause and
    // the SAME reply route as a scheduled fold — it IS a scheduled fold, just
    // scheduled by a ProUpServTx instead of by a counter. m_revive_probe_at is
    // the anti-livelock latch: the probed height, so a re-delivered block
    // cannot re-ask for a list that has already been asked for and consumed,
    // refused or abandoned.
    size_t    m_revive_probes{0};
    uint32_t  m_revive_probe_at{0};
    size_t    m_revive_unmeasured{0};
    size_t    m_revive_declined{0};
    size_t    m_revive_probe_cap{kReviveProbeBase};
    bool      m_revive_probe_cap_forced{false};
    bool      m_revive_probe_cap_hit{false};
    RequestSnapshotFn m_request_snapshot;
    MerkleRootAtFn    m_merkle_root_at;
    size_t   m_sml_recovery_cap{0}; // budget handed to the machine, mirrored
    size_t   m_registered{0};       // ADDS observed across the replay
    size_t   m_spent{0};            // collateral-spend removals across the replay
    bool     m_warned_no_sml{false};
    bool     m_has_sml_fn{false};   // an SML validity seam was wired
    uint32_t m_max_bridge{kDefaultMaxBridgeBlocks};
    uint32_t m_stalled_pumps{0};
    uint32_t m_last_pump_next{0};        // cursor at the previous pump (stall probe)
    uint32_t m_requested_through{0};     // highest height already asked for
    bool     m_rerequest_from_cursor{false};
    uint32_t m_last_wait_log{0};
    bool     m_position_verified{false};

    // ── DIAGNOSTICS (telemetry only; nothing below is read by a gate) ──────
    /// Injectable monotonic clock — a KAT drives the throttle and the watchdog
    /// deterministically instead of sleeping.
    std::function<int64_t()> m_now{&diag::steady_now_ms};
    std::function<size_t(const BlockType&)> m_wire_size;
    /// 500 blocks OR 15 s, whichever first. A 20000-block bridge therefore
    /// costs ~40 lines, and a bridge crawling at 1 blk/s still reports every
    /// 15 s instead of going quiet for an hour.
    diag::ProgressReporter m_progress{500, 15000};
    /// 90 s of NO cursor movement is a freeze worth naming, repeated every
    /// 120 s. Sized against the 2026-08-04 incident (11-12 min of silence) and
    /// against DASH's ~150 s block spacing: a bridge mid-replay should advance
    /// far faster than one block per 90 s, and a bridge that has caught the tip
    /// is Published (disarmed), so this cannot fire on a healthy idle lane.
    diag::StallWatchdog m_watchdog{90000, 120000};
    uint32_t m_replay_base{0};      // cursor at bridge START (progress denominator)
    uint32_t m_replay_target{0};    // tip the replay is chasing
    uint64_t m_replay_bytes{0};     // wire bytes of replayed block bodies
    bool     m_have_bytes{false};   // ...only when set_wire_size_fn is wired
    /// Whether the replay cursor came from persisted work. ALWAYS false today:
    /// this build has no cursor persistence, and the field exists so the log
    /// says so out loud rather than leaving the discard invisible.
    bool     m_cursor_restored{false};

    // ── RE-ARM bookkeeping. Survives reset_for_arm() by design: if a re-arm
    // cleared its own counters the cap could never fire and the "recovery"
    // would be an unbounded fail-loop.
    uint32_t    m_rearms{0};              // spent against kMaxRearms
    uint32_t    m_rearm_asks{0};          // asks, including deferred/refused
    uint32_t    m_last_rearm_at{0};       // tip height at the last re-arm
    bool        m_last_rearm_at_known{false};
    uint32_t    m_first_divergence{0};    // earliest divergence evidence
    bool        m_rearm_blocked{false};   // terminal: no further re-arms
    std::string m_rearm_block_reason;
    std::string m_last_rearm_reason;
    std::string m_last_rearm_trigger;

    // ── SELF RE-ARM state. Also survives reset_for_arm() (except the pending
    // flag, which a fresh arm clears): the gate is measured across bridges.
    /// The anchor this lane is armed from, kept so poll_rearm() needs no
    /// caller and no extra seam. One copy, overwritten per arm.
    MnCheckpoint m_anchor_cp;
    bool     m_rearm_pending{false};        // failed closed, wants a re-arm
    uint32_t m_failed_at_tip{0};            // tip observed AT the fail-close
    bool     m_failed_at_tip_known{false};  // ...if a tip seam was wired then
    uint32_t m_last_fail_cursor{0};         // cursor the previous replay died on
    bool     m_have_last_fail_cursor{false};
    uint32_t m_last_pending_log{0};         // tip at the last pending line
    /// Blocks between two "waiting on the gate" lines. ~8 DASH blocks is ~20
    /// minutes: loud enough that a wedged ladder cannot hide for 2h39m again,
    /// quiet enough that it is not a per-block storm.
    static constexpr uint32_t kPendingLogEvery = 8;
};

} // namespace coin
} // namespace dash
