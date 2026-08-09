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
/// POST-ANCHOR PoSe BANS, AND THE TWO RESIDUALS THAT REMAIN
/// ─────────────────────────────────────────────────────────────────────────
/// The falsification test above has one structural blind spot. A PoSe ban is
/// applied by dashd from CONSENSUS (accumulated MAX_PoSe_PENALTY), never as a
/// special transaction. MnStateMachine::apply_block walks special txs, so it
/// cannot observe one at any price. A masternode banned AFTER the anchor
/// height therefore stays isValid=true in the replay, keeps its place at the
/// head of our payment queue, and is projected as the payee for a block dashd
/// paid to somebody else — payee_desync, which here is TERMINAL. One such ban
/// anywhere in the replay window permanently prevents the daemonless arm from
/// publishing a masternode set at all.
///
/// The Simplified Masternode List is the only carrier of that ban, so the lane
/// exposes set_sml_validity_fn() and hands it to its private machine. On a
/// payee mismatch the machine may walk down the ranked queue, but ONLY while
/// each demoted candidate is ATTESTED INVALID by the SML and the accepted
/// candidate's scriptPayout EXACTLY matches an output this block pays. Any
/// step that cannot satisfy both reports payee_desync exactly as before. The
/// walk is capped per bridge (see pump()), every event logs at WARNING, and
/// the running count is surfaced in status() and in the publish line — a
/// count that lives only in scrollback is half-silent, and this file exists
/// to prevent silent degradation.
///
/// TWO RESIDUALS, stated honestly:
///
///  (a) A masternode banned AND revived entirely inside the replay window,
///      whose CURRENT SML entry therefore reads isValid==true, still fails
///      closed. The SML is a snapshot of NOW; it cannot attest a historical
///      ban, and an attested-valid answer is treated as counter-evidence (it
///      must be — that is what stops the walk from excusing a real desync).
///      This is exactly today's behaviour for that case, not worse.
///
///  (b) A post-anchor ban INSIDE a shared-payoutAddress group can escape both
///      the cross-check and this recovery, because both are SCRIPT-granular:
///      if the banned MN and the MN dashd actually paid share one payout
///      address, the coinbase output still matches our projected script, the
///      mismatch never fires, and the payment is attributed to the wrong
///      member of the group. That is a PRE-EXISTING blind spot in the
///      projection cross-check (the same granularity the gap_detected note in
///      mn_state_machine.hpp calls out), not something this recovery
///      introduces — the recovery only ever runs when the cross-check already
///      failed.
///
/// FENCED: src/impl/dash only. Constructed exclusively by the opt-in embedded
/// path in main_dash.cpp; the dashd-RPC fallback never touches this file.

#include <impl/dash/coin/block.hpp>
#include <impl/dash/coin/mn_checkpoint.hpp>
#include <impl/dash/coin/mn_state_machine.hpp>

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
            // Size the SML ban-recovery budget against the replay distance.
            // A PoSe ban is a rare per-masternode event, so the count of them
            // inside a window scales with the window, not with the set size:
            // 4 covers a short bridge, +1 per 1000 blocks covers a long one.
            // Past that, "recovery" stops being a repair of a few known-banned
            // nodes and becomes a wholesale override of the projection, which
            // is precisely what this lane must never do.
            m_machine.set_sml_recovery_cap(4 + (tip - m_anchor_height) / 1000);
            LOG_INFO << "[MN-CKPT] bridge START: replaying h=" << m_next
                     << ".." << tip << " (" << (tip - m_next + 1)
                     << " blocks) onto the anchored set";
        }

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

        const auto r = m_machine.apply_block(block, height);

        // The anchor's own falsification test. apply_block already logs the
        // detail; here it is TERMINAL (unlike the maintainer's path, which can
        // ask for an RPC re-seed — daemonless has nothing to re-seed from, and
        // guessing is exactly what must never happen).
        if (r.gap_detected || r.payee_desync) {
            return fail_closed(
                std::string("bridge replay ")
                + (r.gap_detected ? "GAP" : "PAYEE DESYNC") + " at h="
                + std::to_string(height)
                + " — the pinned masternode-set anchor does not reproduce this"
                  " block's actual coinbase payee. The anchor is wrong, the"
                  " replay is incomplete, or a post-anchor PoSe ban could not"
                  " be attested"
                + (m_has_sml_fn
                       ? std::string(" by the SML (absent entry, or attested"
                                     " VALID because the masternode was banned"
                                     " AND revived inside the replay window)")
                       : std::string(" — no SML validity seam is wired"))
                + ". Refusing to publish a masternode set that would mint a"
                  " rejected coinbase");
        }
        if (r.total_after == 0) {
            return fail_closed(
                "bridge replay emptied the masternode set at h="
                + std::to_string(height) + " — cannot back a payee");
        }

        m_next = height + 1;
        ++m_applied;
        m_sml_recovered += r.sml_recovered;
        m_stalled_pumps = 0;

        if ((m_applied % 500) == 0) {
            LOG_INFO << "[MN-CKPT] bridge progress: applied " << m_applied
                     << " blocks, cursor h=" << height << " set="
                     << r.total_after << " sml-recovered=" << m_sml_recovered;
        }

        if (!m_tip_height) return;
        const uint32_t tip = m_tip_height();
        if (m_next > tip) { publish(tip); return; }
        // #1103 chase-log. The cursor is advancing but has not yet reached the
        // LIVE tip: this is a CHASE across the header/body-availability gap
        // (the header tip leads what block bodies are locally available), NOT a
        // wedge. The lane watchdog resets on every cursor move, so a healthy
        // tail-chase and a genuine stall are indistinguishable from outside —
        // "33 min no publish" on contabo 2026-08-09 was in fact this chase
        // creeping the last handful of bodies to the tip. Emit the lag
        // explicitly for the tail (lag<=8), where the coarse 500-block progress
        // line does not fire, so the silent window becomes greppable.
        if ((tip - m_next + 1) <= 8) {
            LOG_INFO << "[MN-CKPT] chase: cursor h=" << (m_next - 1)
                     << " live-tip h=" << tip << " lag=" << (tip - m_next + 1)
                     << " block(s) — chasing block-bodies to tip, not wedged";
        }
        request_window(tip);
    }

private:
    void request_window(uint32_t tip)
    {
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
        const uint32_t as_of = m_next - 1;
        std::vector<std::pair<uint256, MNState>> out;
        out.reserve(m_machine.entries().size());
        for (const auto& [h, st] : m_machine.entries()) out.emplace_back(h, st);
        if (out.empty()) {
            return fail_closed("bridged masternode set is empty — refusing to"
                               " publish");
        }
        m_state  = State::Published;
        // The recovery count rides on BOTH the status string and the log
        // line. A degradation that is only visible in scrollback is
        // half-silent, and this lane exists to make degradation loud.
        m_status = "published " + std::to_string(out.size())
                   + " masternodes (" + std::to_string(m_sml_recovered)
                   + " SML-recovered exclusions) as-of h=" + std::to_string(as_of)
                   + " (anchor h=" + std::to_string(m_anchor_height)
                   + " + " + std::to_string(m_applied) + " replayed blocks)";
        LOG_INFO << "[MN-CKPT] bridge COMPLETE: published " << out.size()
                 << " masternodes (" << m_sml_recovered
                 << " SML-recovered exclusions) as-of h=" << as_of
                 << " (anchor h=" << m_anchor_height << ", replayed "
                 << m_applied << " blocks, tip h=" << bridged_to
                 << ") -> publishing to the maintainer";
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

    State       m_state{State::Unarmed};
    std::string m_status{"unarmed"};

    uint32_t m_anchor_height{0};
    uint256  m_anchor_hash;
    std::string m_anchor_source;
    size_t   m_anchor_count{0};

    uint32_t m_next{0};             // the ONLY height apply_block may fold next
    uint32_t m_applied{0};
    size_t   m_sml_recovered{0};    // masternodes excluded on SML-attested bans
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
