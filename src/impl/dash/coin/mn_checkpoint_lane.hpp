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
#include <impl/dash/coin/historical_sml.hpp>   // authenticate_historical_snapshot
#include <impl/dash/coin/vendor/simplifiedmns.hpp>
#include <impl/dash/coin/vendor/smldiff.hpp>    // CSimplifiedMNListDiff
#include <impl/dash/coin/vendor/cbtx.hpp>       // CCbTx

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
    /// network round trip and the per-mismatch walk covers the gaps.
    void set_fold_interval(uint32_t n) { m_fold_interval = n ? n : 1; }

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
    /// The FIRST fold's height. Distinct from sml_folded_at(), which tracks the
    /// most recent — a bridge folds at the anchor, at intervals, and at the
    /// tip, so "did we fold before the first block" is a different question
    /// from "where did we fold last".
    uint32_t first_fold_height()  const { return m_first_fold_height; }
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
            // second reason the per-height wholesale fold is the right
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
                return;
            }
        }
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
    //   • On reaching a fold height the lane sets m_snapshot_pending and
    //     STOPS pulling blocks (request_window() returns immediately while
    //     paused). The replay cannot run ahead of its own fold.
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

    /// Ask for the list as of `height`, and pause the replay until it lands.
    /// Returns true when a request was issued (caller must stop pulling).
    bool begin_fold(uint32_t height)
    {
        if (!m_request_snapshot || !m_merkle_root_at || !m_header_hash_at)
            return false;
        auto hash = m_header_hash_at(height);
        if (!hash) return false;              // header not held yet; retry later
        m_snapshot_pending = true;
        m_snapshot_hash    = *hash;
        m_snapshot_height  = height;
        m_snapshot_waits   = 0;
        LOG_INFO << "[MN-CKPT] PoSe fold: requesting the masternode list AS OF"
                    " h=" << height << " (" << hash->GetHex().substr(0, 16)
                 << ") — replay PAUSED until it lands, so the cursor cannot"
                    " run past the height the list describes";
        m_request_snapshot(*hash);
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

        vendor::CCbTx cbtx;
        auto sml = authenticate_historical_snapshot(
            diff, h, m_merkle_root_at, cbtx, "MN-CKPT");
        if (!sml) {
            fail_closed(
                "the masternode list served for h=" + std::to_string(h)
                + " failed DIP-4 client verification (see the AUTH FAILED line"
                  " above). Refusing to fold an unauthenticated list into the"
                  " payee set — that list decides who gets paid.");
            return true;   // consumed: it matched our await
        }

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
        LOG_INFO << "[MN-CKPT] PoSe FOLD at h=" << height
                 << " (cursor == the height the list describes, by"
                    " construction): payee-eligible " << before << " -> "
                 << after << " (-" << vr.flipped_to_invalid << " banned, +"
                 << vr.flipped_to_valid << " revived; scanned " << vr.scanned
                 << " entries, " << vr.matched << " ours). List was DIP-4"
                    " client-verified against the block's own coinbase"
                    " commitment.";
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

    void request_window(uint32_t tip)
    {
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
                   + delta
                   + " PoSe folds: " + std::to_string(m_folds);
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
};

} // namespace coin
} // namespace dash
