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
/// exactly one source — dashd RPC `protx list valid true` (E2c, mn_seed.hpp)
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
/// already receive and persist it. There are now TWO seams onto it, and they
/// do different jobs:
///
///   • set_sml_snapshot_fn() — the WHOLESALE REMOVAL fold. Supplies the whole
///     list PLUS the height it is current at. At exactly ONE cursor position
///     — apply cursor == that height — the lane folds
///     MnStateMachine::sync_validity_from_sml() over the working set, so every
///     masternode the SML attests not-valid leaves the payee-eligible set in a
///     single pass. That single-pass property is the point: it makes a BURST
///     of bans indistinguishable from one ban. The ordering rule, and why
///     violating it EARLY is dangerous while LATE is benign, is written out in
///     full at maybe_fold_sml(). The same seam supplies the freshness height
///     that gates the walk below.
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
/// TODO (separate change, deliberately NOT half-done here): ANCHOR SELECTION
/// ON REPEAT DESYNC. When a bridge fails closed and the operator re-arms,
/// picking the NEWEST anchor is wrong: an anchor cut AFTER a divergence began
/// replays cleanly over a shorter window and re-arms a queue that is already
/// wrong, which mints a rejected coinbase. The correct policy is oldest-first
/// on a repeat desync, with capped re-arms + backoff and the compiled-in
/// checkpoint as the floor. It is not implementable in this file today: this
/// build carries exactly ONE anchor per network
/// (src/impl/dash/coin/checkpoints/dash_mn_checkpoint_{mainnet,testnet}.inc,
/// referenced once from main_dash.cpp), there is no anchor LIST to order and
/// no persisted desync history to count re-arms against across restarts.
/// Prerequisites: (1) a multi-anchor checkpoint store keyed by height,
/// (2) a persisted per-anchor desync counter, (3) an arm()/re-arm API that
/// takes a candidate list rather than a single MnCheckpoint.
///
/// FENCED: src/impl/dash only. Constructed exclusively by the opt-in embedded
/// path in main_dash.cpp; the dashd-RPC fallback never touches this file.

#include <impl/dash/coin/block.hpp>
#include <impl/dash/coin/mn_checkpoint.hpp>
#include <impl/dash/coin/mn_state_machine.hpp>
#include <impl/dash/coin/vendor/simplifiedmns.hpp>

#include <core/log.hpp>
#include <core/uint256.hpp>

#include <algorithm>
#include <cstdint>
#include <functional>
#include <optional>
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
    /// (see maybe_fold_sml() — a wholesale fold is only valid at ONE cursor
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

    enum class State {
        Unarmed,      ///< no checkpoint loaded — the lane does nothing
        Waiting,      ///< armed; header chain has not reached the anchor yet
        Bridging,     ///< replaying blocks anchor+1 .. tip
        Published,    ///< set handed to the maintainer; lane is done
        FailedClosed, ///< terminal refusal — the arm must NOT serve templates
    };

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

    /// Maximum number of blocks the bridge is willing to replay. A checkpoint
    /// further behind the tip than this is treated as STALE and refused: the
    /// replay would take longer than an operator would tolerate, and a
    /// silently-crawling bridge that never arms is exactly the "quiet
    /// degradation" failure this lane exists to avoid. Refusing loudly points
    /// the operator at the real fix (upgrade to a release with a fresher
    /// anchor, or run with a coin RPC).
    void set_max_bridge_blocks(uint32_t n) { m_max_bridge = n; }
    uint32_t max_bridge_blocks() const     { return m_max_bridge; }

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
        m_anchor_height = cp.height;
        m_anchor_hash   = cp.blockhash;
        m_anchor_source = cp.source;
        m_anchor_count  = cp.entries.size();
        m_machine.load(cp.entries, cp.height);
        // F6: reset the one-shot fold latch and its counters. The latch is the
        // dangerous one — a second bridge on a re-armed lane would run
        // additions-only while sml_folded() still reported true, i.e. it would
        // LIE about having applied removals.
        m_sml_folded      = false;
        m_sml_folded_at   = 0;
        m_pose_removed    = 0;
        m_pose_reinstated = 0;
        m_sml_recovered   = 0;
        m_registered      = 0;
        m_spent           = 0;
        m_applied         = 0;
        m_warned_no_sml   = false;
        m_anchor_eligible = m_machine.eligible_size();
        m_next  = cp.height + 1;
        m_state = State::Waiting;
        m_status = "armed at h=" + std::to_string(cp.height) + " ("
                   + std::to_string(m_anchor_count) + " masternodes), waiting"
                     " for headers to reach the anchor";
        LOG_INFO << "[MN-CKPT] armed: anchor h=" << cp.height << " "
                 << cp.blockhash.GetHex().substr(0, 16) << " count="
                 << m_anchor_count << " source='" << cp.source << "'";
    }

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
    bool     sml_folded()         const { return m_sml_folded; }
    uint32_t sml_folded_at()      const { return m_sml_folded_at; }
    size_t   replay_registered()  const { return m_registered; }
    size_t   replay_spent()       const { return m_spent; }
    bool     failed_closed() const { return m_state == State::FailedClosed; }
    bool     published()     const { return m_state == State::Published; }

    /// Drive the bridge: verify the anchor's chain position once the header
    /// chain reaches it, enforce the staleness bound, request the next window
    /// of block bodies, and publish when the cursor catches the tip.
    ///
    /// Safe to call as often as convenient (every tip change is ideal); it is
    /// idempotent and cheap when there is nothing to do.
    void pump()
    {
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
            // second reason the wholesale fold (maybe_fold_sml) is the right
            // mechanism: a fold is ONE pass over the list and spends NO budget
            // at all, so a burst costs it nothing. The cap is deliberately
            // left as-is rather than widened — widening it would license
            // exactly the wholesale-override-by-inference this walk exists to
            // refuse, and the fold already removes the need.
            m_sml_recovery_cap = 4 + (tip - m_anchor_height) / 1000;
            m_machine.set_sml_recovery_cap(m_sml_recovery_cap);
            LOG_INFO << "[MN-CKPT] bridge START: replaying h=" << m_next
                     << ".." << tip << " (" << (tip - m_next + 1)
                     << " blocks) onto the anchored set";
        }

        // F4: the anchor height is itself a valid fold cursor -- and the ONLY
        // dispatch that can ever observe it. The post-apply fold in
        // on_block_connected first runs at cursor == anchor+1, and the publish()
        // fold runs at the final cursor, so an SML current EXACTLY at the anchor
        // (cursor == H_sml == anchor -- the canonical NON-early position: the
        // loaded snapshot IS the state after connecting H_sml) is otherwise
        // silently forfeited, leaving the first replayed blocks unprotected.
        // Dispatch once here at bridge start; maybe_fold_sml()'s own
        // cursor == snap.height guard makes this a no-op unless H_sml == anchor,
        // so it can never fold early. (One-shot latch: it will not re-run once
        // the post-apply site takes over for cursor > anchor.)
        maybe_fold_sml();
        if (m_state != State::Bridging) return;   // the fold can fail closed

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
        if (height != m_next) return;

        // Publish the SML's own height into the machine BEFORE it adjudicates
        // anything, so the reactive demotion walk's attestations are gated on
        // freshness (MnStateMachine::sml_attest). A stale SML attesting a
        // since-revived masternode "invalid" would otherwise license a
        // PERMANENT demotion.
        refresh_sml_height();

        const auto r = m_machine.apply_block(block, height);

        // The anchor's own falsification test. apply_block already logs the
        // detail; here it is TERMINAL (unlike the maintainer's path, which can
        // ask for an RPC re-seed — daemonless has nothing to re-seed from, and
        // guessing is exactly what must never happen).
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
        // ── WHOLESALE PoSe fold, at the ONE cursor position where it is safe.
        // Sequenced by HEIGHT, never by arrival order: see maybe_fold_sml().
        maybe_fold_sml();
        // The fold can fail closed (oversized list). Return immediately: the
        // tail of this function calls request_window(), which unconditionally
        // rewrites m_status and would erase the refusal reason the operator
        // needs.
        if (m_state != State::Bridging) return;
        m_sml_recovered += r.sml_recovered;
        m_registered    += r.registered;
        m_spent         += r.spent;
        m_stalled_pumps = 0;

        if ((m_applied % 500) == 0) {
            LOG_INFO << "[MN-CKPT] bridge progress: applied " << m_applied
                     << " blocks, cursor h=" << height << " registered="
                     << r.total_after << " eligible=" << m_machine.eligible_size()
                     << " (anchor " << m_anchor_eligible << "; +"
                     << m_registered << " reg, -" << m_spent << " spent, -"
                     << m_pose_removed << " PoSe-removed, +"
                     << m_pose_reinstated << " reinstated)"
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
    // maybe_fold_sml — the WHOLESALE PoSe removal, at the ONE safe cursor
    // ─────────────────────────────────────────────────────────────────────
    //
    // WHY IT IS NEEDED. The reactive walk (recover_from_sml_ban) adjudicates
    // ONE queue-head exclusion per height, and each success must re-attribute
    // the payment to the next candidate "whose scriptPayout matches this
    // coinbase exactly". That works for ISOLATED bans and is proven to: on
    // mainnet 2026-08-02 it ran and succeeded five times during the replay
    // (bridge total 1/6 … 5/6). It cannot work for a BURST. The chain shows
    // what actually broke:
    //
    //     h=2514800   valid 2062, our projected MN PRESENT
    //     h=2514873   valid 2059, our projected MN ABSENT
    //                 -> THREE masternodes banned inside 73 blocks
    //     h=2515025   valid 2063, still ABSENT (never revived)
    //
    // Three consecutive banned queue-head candidates defeat a walk that has
    // to land an exact coinbase script match at every step. The wholesale
    // fold fixes it precisely BECAUSE it makes a burst indistinguishable from
    // a single ban: all three leave the eligible set in one pass, before any
    // of them is ever projected.
    //
    // ── THE ORDERING RULE, AND WHY VIOLATING IT IS ASYMMETRIC ────────────
    //
    // The SML is a snapshot of the state AFTER connecting H_sml. A wholesale
    // fold is valid at EXACTLY ONE cursor position: apply cursor == H_sml —
    // after apply_block(H_sml), before apply_block(H_sml+1). Sequenced by
    // HEIGHT, never by arrival order.
    //
    //   EARLY (cursor < H_sml) is DANGEROUS, and this is the whole reason the
    //   fold is gated rather than run per-height. A masternode banned at
    //   h_ban <= H_sml would be removed at heights where the chain still held
    //   it valid and actually paid it. The mild outcome is a spurious terminal
    //   fail-close. The severe one is silent: inside a shared-payoutAddress
    //   group the divergence is SCRIPT-INVISIBLE (see the residual note in
    //   this file's header), the coinbase cross-check still passes, and the
    //   bridge PUBLISHES A WRONG QUEUE — the exact bad-cb-payee this lane
    //   exists to prevent. An early fold also perturbs queue POSITION for
    //   nodes it touches, because sync_validity_from_sml bumps
    //   nPoSeRevivedHeight, which is a CompareByLastPaid sort key.
    //
    //   LATE (cursor > H_sml) is BENIGN: it is today's behaviour, and the
    //   reactive walk still catches a ban when it reaches the queue head.
    //
    // So the fold NEVER runs early. If the cursor passes H_sml without an SML
    // present, it simply does not happen and the walk carries the window
    // alone — degraded, and said so out loud.
    //
    // TWO DISPATCH POINTS, ONE RULE. This is called after each successful
    // apply_block (catching cursor == H_sml mid-replay, which is what lets a
    // burst at H_sml+1 be survived) and once more from publish() (catching
    // H_sml == tip, and the zero-block bridge). Both test the same equality
    // and the fold is one-shot, so they cannot double-apply.
    void maybe_fold_sml()
    {
        if (m_sml_folded) return;
        if (!m_sml_snapshot) return;
        const SmlSnapshot snap = m_sml_snapshot();
        if (!snap.list || snap.list->size() == 0) {
            if (!m_warned_no_sml) {
                m_warned_no_sml = true;
                LOG_WARNING << "[MN-CKPT] no verified SML available at cursor h="
                            << cursor_height()
                            << " — the replay can only ADD masternodes until"
                               " one arrives, and a PoSe ban inside the window"
                               " must then be carried by the per-mismatch walk"
                               " alone (which a multi-masternode ban BURST can"
                               " defeat).";
            }
            return;
        }
        const uint32_t cursor = cursor_height();
        if (cursor != snap.height) return;   // never early; late is benign

        const size_t before = m_machine.eligible_size();

        // F5 SANITY BOUND. The per-mismatch walk is capped AND cross-checked
        // against the real coinbase at every step precisely so that "recovery"
        // can never become a wholesale override of the projection. This fold IS
        // a wholesale override — it rewrites validity for the entire set from
        // one message, and on_mnlistdiff does not currently re-derive
        // sml.CalcMerkleRoot() against diff.cbTx.merkleRootMNList, so the list
        // is trusted rather than verified. A PoSe ban is a rare per-masternode
        // event: a diff that would retire a large fraction of the set at once
        // is not a ban wave, it is a corrupt or hostile list. Refuse it and say
        // so, rather than publish a set with a hole in it.
        const size_t would_remove = count_fold_removals(*snap.list);
        const size_t bound = std::max<size_t>(kMinFoldRemovals,
                                             before / kMaxFoldRemovalDivisor);
        if (before != 0 && would_remove > bound) {
            return fail_closed(
                "SML PoSe FOLD REFUSED at cursor h=" + std::to_string(cursor)
                + ": the list would retire " + std::to_string(would_remove)
                + " of " + std::to_string(before)
                + " payee-eligible masternodes in one pass, over the 1/"
                + std::to_string(kMaxFoldRemovalDivisor) + " sanity bound of "
                + std::to_string(bound) + ". A PoSe ban is a rare per-node"
                  " event; a fold this large is a corrupt or hostile SML, not a"
                  " ban wave. NOTE: the SML is NOT root-verified against"
                  " cbTx.merkleRootMNList on the diff ingest path, so this"
                  " bound is the only thing standing between a bad list and a"
                  " wholesale rewrite of the payee set.");
        }

        const auto vr = m_machine.sync_validity_from_sml(*snap.list, snap.height);
        const size_t after = m_machine.eligible_size();
        m_sml_folded    = true;
        m_sml_folded_at = snap.height;
        m_pose_removed    = vr.flipped_to_invalid;
        m_pose_reinstated = vr.flipped_to_valid;
        LOG_INFO << "[MN-CKPT] SML PoSe FOLD at cursor h=" << cursor
                 << " (== the height the SML is current at): payee-eligible "
                 << before << " -> " << after << " (-" << vr.flipped_to_invalid
                 << " banned, +" << vr.flipped_to_valid << " revived; scanned "
                 << vr.scanned << " SML entries, " << vr.matched << " ours)."
                 << " A ban BURST leaves in one pass here, which the"
                    " per-mismatch walk cannot do.";
    }

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
            + ".";

        if (!m_sml_snapshot) {
            s += " NO SML SNAPSHOT SEAM IS WIRED — this replay could only ADD"
                 " masternodes, so ANY post-anchor PoSe ban lands here.";
        } else if (!m_sml_folded) {
            s += " The WHOLESALE SML fold has NOT run (it applies only at"
                 " cursor == the height the SML is current at, and never"
                 " earlier — an early fold can publish a wrong queue"
                 " silently). Every ban in this window is therefore being"
                 " carried by the per-mismatch walk alone, which a BURST of"
                 " masternodes banned close together defeats: it adjudicates"
                 " one exclusion per height and must land an exact coinbase"
                 " script match at each step.";
        } else {
            s += " The wholesale SML fold ran at h="
                 + std::to_string(m_sml_folded_at) + ".";
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

    void request_window(uint32_t tip)
    {
        // Never rewrite the status of a lane that has already finished or
        // refused — that status is the only record of WHY.
        if (m_state != State::Bridging) return;
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
        maybe_fold_sml();

        const uint32_t as_of = m_next - 1;
        std::vector<std::pair<uint256, MNState>> out;
        out.reserve(m_machine.entries().size());
        for (const auto& [h, st] : m_machine.entries()) out.emplace_back(h, st);
        if (out.empty()) {
            return fail_closed("bridged masternode set is empty — refusing to"
                               " publish");
        }
        m_state  = State::Published;
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
            + std::to_string(m_pose_reinstated)
            + " reinstated, -" + std::to_string(m_sml_recovered)
            + " SML-recovered exclusions)";
        m_status = "published " + std::to_string(out.size())
                   + " masternodes (" + std::to_string(m_sml_recovered)
                   + " SML-recovered exclusions) as-of h=" + std::to_string(as_of)
                   + " (anchor h=" + std::to_string(m_anchor_height)
                   + " + " + std::to_string(m_applied) + " replayed blocks) "
                   + delta;
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
        m_state  = State::FailedClosed;
        m_status = why;
        // Deliberately ERROR, not WARNING: the operator's embedded arm will
        // not arm, and the only thing worse than saying so is not saying so.
        LOG_ERROR << "[MN-CKPT] FAIL-CLOSED: " << why;
        LOG_ERROR << "[MN-CKPT] the embedded DASH template arm will NOT serve;"
                     " templates keep routing to the dashd fallback arm (if"
                     " configured). No masternode payee will be guessed.";
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
    size_t   m_pose_removed{0};     // masternodes the wholesale fold banned
    size_t   m_pose_reinstated{0};  // masternodes the wholesale fold revived
    bool     m_sml_folded{false};   // the one-shot wholesale fold has run
    uint32_t m_sml_folded_at{0};    // ...at this height (== the SML's height)
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
};

} // namespace coin
} // namespace dash
