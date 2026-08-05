// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// ── THE LAST DAEMONLESS SEAM: the replay fold FEEDS the payee queue ────────
//
// W1's DML fold (replay_fold_engine.hpp), driven by W2's bulk lane through
// W5's consumer (replay_fold_consumer.hpp) with W4's derived membership
// (replay_quorum_bridge.hpp), reconstructs the deterministic masternode list
// and self-checks it, per block, against that block's own committed cbTx
// merkleRootMNList. On contabo (pure daemonless, no dashd at all) it folded
// 4690/4690 byte-exact roots to tip in 264 s.
//
// The SERVE gate did not consume any of it. `populated()` needs the PAYEE
// axis — CoinStateMaintainer's MnStateMachine, the queue GetMNPayee orders —
// and that axis had exactly two sources:
//
//   * `dashd-seed`  (E2c, mn_seed.hpp): one shot at startup from
//                   `protx list registered true`. FAST — .211 served in 7
//                   minutes — but it is an RPC call to dashd. A run that
//                   uses it has not proven a daemonless serve, it has proven
//                   a daemonless FOLD next to a dashd-seeded serve.
//   * `mn-ckpt`     (E2d, mn_checkpoint_lane.hpp): a second, INDEPENDENT
//                   reconstruction from the compiled-in checkpoint forward,
//                   at ~0.8-1 blk/s with an on-demand PoSe fold (an
//                   mnlistdiff round trip) at every payee mismatch. 40-60
//                   min to tip against the fold's 264 s, and until it lands
//                   the gate says
//                       [EMBED-GATE] DECLINED cause=not-populated
//                                    value=have_tip=1,have_mn=0
//                   and a node with no dashd creds pushes ZERO mining.notify.
//
// This file adds a THIRD source, `replay-fold`, PREFERRED when — and only
// when — it is PROVEN CURRENT. It removes neither of the other two: with the
// replay flags absent nothing here is constructed and the node behaves
// exactly as before.
//
// ── THE FAIL-CLOSED GUARD (non-negotiable) ────────────────────────────────
//
// A masternode list that is wrong by one entry mints a coinbase the network
// deterministically rejects (bad-cb-payee) — a WON block, lost. So the
// replay-derived list may be published as authoritative ONLY when every one
// of these holds, and the refusal NAMES which one did not:
//
//   G1  the fold engine is not POISONED (W1's sticky divergence latch)
//   G2  the consumer reports DIVERGED=none
//   G3  blocks_folded > 0 — a fold that folded nothing proves nothing
//   G4  roots_matched == blocks_folded — every folded block was root-checked;
//       an unchecked fold is indistinguishable from a wrong one
//   G5  the engine's cursor equals the last root-checked height (the state we
//       are about to publish is the state that passed, not a later mutation)
//   G6  the folded list re-hashes, RIGHT NOW, to the merkleRootMNList that
//       block committed. This is the guard that cannot be faked by a counter:
//       it recomputes the root over the exact entries being converted.
//   G7  the fold cursor is AT the header-chain tip. A list that is behind the
//       tip is a list that has not seen the registrations, bans and payments
//       of the blocks in between — the queue front would be stale.
//   G8  the list is non-empty and every entry carries a payout script.
//
// G1..G6 are the fold's own proof; G7 is currency; G8 is usability. Anything
// short of all eight WITHHOLDS, the two existing lanes keep their jobs, and
// the log says which condition blocked.

#include <impl/dash/coin/mn_state_db.hpp>            // dash::coin::MNState
#include <impl/dash/coin/replay_fold_engine.hpp>
#include <impl/dash/coin/replay_fold_consumer.hpp>

#include <core/log.hpp>

#include <cstdint>
#include <functional>
#include <string>
#include <utility>
#include <vector>

namespace dash {
namespace coin {
namespace replay {

/// The name this source answers to everywhere it touches the payee axis.
/// "state says its own name": the populate log line carries it verbatim so
/// the next reader can tell which of the three lanes won, instantly.
inline constexpr const char* kPayeeSourceReplayFold = "replay-fold";
inline constexpr const char* kPayeeSourceDashdSeed  = "dashd-seed";
inline constexpr const char* kPayeeSourceMnCkpt     = "mn-ckpt";

/// ReplayMNState (fold state, dashd's CDeterministicMNState field-for-field,
/// -1 == NEVER) -> MNState (payee state, 0 == never, isValid derived).
///
/// The two structs are the same information in two dialects; the ONLY
/// non-mechanical decisions are documented inline. Anything that cannot be
/// mapped faithfully must fail the guard, never be defaulted quietly.
inline MNState to_payee_state(const ReplayMNState& st)
{
    MNState mn;

    // Registration facets — immutable after ProRegTx unless a ProUpRegTx
    // rewrote them, which the fold applied.
    mn.nVersion           = st.nVersion;
    mn.nType              = static_cast<uint8_t>(st.nType);
    mn.collateralOutpoint = st.collateralOutpoint;
    mn.keyIDOwner         = st.keyIDOwner;
    mn.pubKeyOperator     = st.pubKeyOperator;
    mn.keyIDVoting        = st.keyIDVoting;
    mn.nOperatorReward    = st.nOperatorReward;
    mn.scriptPayout       = st.scriptPayout;

    // ProUpServTx facets.
    mn.netInfo              = st.netInfo;
    mn.scriptOperatorPayout = st.scriptOperatorPayout;

    // Per-block state-machine outputs. NEVER (-1) is the fold's "unset";
    // MNState encodes the same absence as 0 (mn_state_machine.hpp reads
    // `nPoSeBanHeight != 0` as "banned" and `nPoSeRevivedHeight` through
    // sane()). Negative values are impossible from a fold that root-checked,
    // but clamp rather than wrap: a silent 4-billion height would sort the
    // queue catastrophically.
    auto h32 = [](int32_t v) -> uint32_t {
        return v <= 0 ? 0u : static_cast<uint32_t>(v);
    };
    mn.nRegisteredHeight    = h32(st.nRegisteredHeight);
    mn.nLastPaidHeight      = h32(st.nLastPaidHeight);
    mn.nPoSeRevivedHeight   = h32(st.nPoSeRevivedHeight);
    mn.nPoSeBanHeight       = h32(st.nPoSeBanHeight);
    mn.nConsecutivePayments = h32(st.nConsecutivePayments);
    mn.nRevocationReason    = st.nRevocationReason;

    // ELIGIBILITY IS COMPUTED, exactly as the SML entry the root is taken
    // over computes it: isValid ≡ !IsBanned(). Keeping the pair consistent
    // is load-bearing — mn_state_machine's Bug-14 guard refuses to pay an
    // entry whose isValid=true sits next to a live ban height.
    mn.isValid = !st.IsBanned();

    // Evo platform facets.
    mn.platformNodeID   = st.platformNodeID;
    mn.platformP2PPort  = st.platformP2PPort;
    mn.platformHTTPPort = st.platformHTTPPort;

    // ── PAYOUT-SPLIT PROVENANCE (incident h=2516595) ──────────────────────
    // SPLIT_KNOWN is asserted here, and it is EARNED, not assumed:
    //   * nOperatorReward is immutable after registration and the fold parsed
    //     it from the ProRegTx payload in a block body it verified;
    //   * scriptOperatorPayout is only ever set by a ProUpServTx, which the
    //     fold also parses from block bodies;
    //   * pre-anchor entries come from the prestate, whose format carries
    //     BOTH fields as mandatory columns (replay_prestate.hpp fields 13 and
    //     15) and which is refused unless it reproduces the anchor block's
    //     committed root.
    // There is no path into a folded entry that leaves the split unproven —
    // which is exactly the condition mn_state_machine.hpp names for
    // SPLIT_KNOWN ("a ProRegTx we parsed from a block body ... the operator
    // script may only be set later by a ProUpServTx, which we also parse").
    mn.payoutSplitProvenance = MNState::SPLIT_KNOWN;

    return mn;
}

/// The verdict of the fail-closed guard. `blocker` is empty iff `ok`.
struct ReplayPayeeGuard
{
    bool        ok{false};
    std::string blocker;        // the ONE named condition that refused

    uint32_t    fold_height{0};
    uint32_t    tip_height{0};
    uint64_t    folded{0};
    uint64_t    roots_matched{0};
    size_t      mns{0};
    std::string root;           // display hex of the re-derived root
};

/// THE FAIL-CLOSED GUARD, as a pure function of (folded state, proof
/// counters, tip). Free-standing on purpose: every one of G1..G8 is then
/// directly pinnable by a KAT that synthesises the exact failure — a fold
/// that diverged, one that is behind the tip, one whose list no longer
/// re-hashes to the root it matched — without having to reproduce that
/// failure over live chain bytes.
inline ReplayPayeeGuard evaluate_payee_guard(const DmlFoldEngine&     engine,
                                             const FoldConsumerStats& s,
                                             uint32_t                 tip_height)
{
    ReplayPayeeGuard g;
    g.fold_height   = engine.height();
    g.folded        = s.blocks_folded;
    g.roots_matched = s.roots_matched;
    g.mns           = engine.size();
    g.tip_height    = tip_height;

    // G1 — W1's own sticky latch. Poisoned means a fold already failed; the
    // state behind it is not consensus and never becomes consensus.
    if (engine.poisoned()) {
        g.blocker = "G1 fold is POISONED: " + engine.poison_reason();
        return g;
    }
    // G2 — the consumer's divergence finding, reported verbatim.
    if (s.diverged) {
        g.blocker = "G2 fold DIVERGED at h=" + std::to_string(s.divergence_height)
                  + " (computed " + s.computed_root
                  + " != committed " + s.committed_root + ")";
        return g;
    }
    // G3 — a fold that has folded nothing has proven nothing, however
    // healthy its counters look.
    if (s.blocks_folded == 0) {
        g.blocker = "G3 fold has not folded a single block yet";
        return g;
    }
    // G4 — THE proof counter must cover every fold. A block folded but not
    // root-checked is indistinguishable from a block folded wrong.
    if (s.roots_matched != s.blocks_folded) {
        g.blocker = "G4 roots_matched=" + std::to_string(s.roots_matched)
                  + " != folded=" + std::to_string(s.blocks_folded)
                  + " (an unchecked fold may not be authoritative)";
        return g;
    }
    // G5 — the engine cursor must BE the last checked height. If the engine
    // advanced past it by any path other than a checked fold, the state we
    // are about to publish is not the state that passed.
    if (engine.height() != s.last_height) {
        g.blocker = "G5 engine cursor h=" + std::to_string(engine.height())
                  + " != last root-checked h=" + std::to_string(s.last_height);
        return g;
    }
    // G6 — the one guard a counter cannot fake: re-derive the root over the
    // entries as they stand and compare to the chain's answer key.
    const uint256 now_root = engine.compute_sml_root();
    g.root = now_root.GetHex();
    if (s.last_matched_root.IsNull() || now_root != s.last_matched_root) {
        g.blocker = "G6 folded list re-hashes to " + now_root.GetHex()
                  + " but block h=" + std::to_string(s.last_height)
                  + " committed " + s.last_matched_root.GetHex();
        return g;
    }
    // G7 — CURRENCY. A proven-correct list AS OF a height below the tip has
    // not seen the registrations, bans and payments in between; its queue
    // front is stale and the coinbase it projects is wrong.
    if (tip_height == 0) {
        g.blocker = "G7 header-chain tip height unknown (0)";
        return g;
    }
    if (g.fold_height < tip_height) {
        g.blocker = "G7 fold is BEHIND the tip: fold h="
                  + std::to_string(g.fold_height) + ", tip h="
                  + std::to_string(tip_height) + " ("
                  + std::to_string(tip_height - g.fold_height)
                  + " blocks to go)";
        return g;
    }
    // G8 — usability. An empty set is a set-gap (the maintainer demotes on it
    // anyway); an entry with no payout script would occupy a queue slot it
    // cannot be paid at.
    if (engine.size() == 0) {
        g.blocker = "G8 folded masternode list is EMPTY";
        return g;
    }
    for (const auto& e : engine.entries()) {
        if (e.second.scriptPayout.m_data.empty()) {
            g.blocker = "G8 folded entry " + e.first.GetHex().substr(0, 16)
                      + " carries an EMPTY scriptPayout";
            return g;
        }
    }

    g.ok = true;
    return g;
}

/// Publishes the replay fold's masternode list into the payee queue — the
/// SAME sink (`Node::mn_list_update` -> CoinStateMaintainer::on_mn_list_update)
/// the dashd seed and the checkpoint bridge feed.
class ReplayPayeePublisher
{
public:
    /// (mnstates, as_of_height, source) -> the leg-4 event.
    using PublishFn   = std::function<void(
        std::vector<std::pair<uint256, MNState>>, uint32_t, const char*)>;
    /// The PoW-validated header chain's tip height. 0 = unknown, which
    /// WITHHOLDS (an unknown tip cannot prove currency).
    using TipHeightFn = std::function<uint32_t()>;

    ReplayPayeePublisher(const DmlFoldEngine&      engine,
                         const FoldReplayConsumer& consumer,
                         TipHeightFn               tip_fn,
                         PublishFn                 publish)
        : m_engine(engine)
        , m_consumer(consumer)
        , m_tip_fn(std::move(tip_fn))
        , m_publish(std::move(publish))
    {}

    /// Run the guard WITHOUT publishing. Pure; safe to call every tick.
    ReplayPayeeGuard evaluate() const
    {
        return evaluate_payee_guard(m_engine, m_consumer.stats(),
                                    m_tip_fn ? m_tip_fn() : 0u);
    }

    /// Publish if — and only if — the guard passes. Returns true when a
    /// publish happened on THIS call.
    ///
    /// ONE-SHOT, exactly like the dashd seed and the checkpoint bridge. The
    /// payee queue is a snapshot PLUS a forward apply cursor: re-loading a
    /// snapshot as-of h after the maintainer has already applied live blocks
    /// h+1.. would rewind that cursor and make the next live block report a
    /// gap. From here on the maintainer owns the queue and folds live blocks
    /// into it; the only thing that may republish is an explicit re-seed ask
    /// (which fires only AFTER the maintainer has wiped the queue itself).
    bool maybe_publish(const char* why = "fold reached the header-chain tip")
    {
        if (m_publishes != 0) return false;
        const auto g = evaluate();
        if (!g.ok) {
            note_withheld(g);
            return false;
        }
        do_publish(g, why);
        return true;
    }

    /// The maintainer wiped a desynced/gapped payee queue and asked for an
    /// authoritative re-seed. Answer it from the replay fold when the fold is
    /// STILL proven current; otherwise return false and let the caller fall
    /// through to whichever lane it had before (mn-ckpt re-arm / dashd
    /// re-seed). Bypasses the per-height latch — the queue was wiped, so
    /// republishing the same height is precisely the repair.
    bool republish_for_reseed()
    {
        const auto g = evaluate();
        if (!g.ok) {
            LOG_WARNING << "[REPLAY-PAYEE] re-seed ask NOT answered from the"
                           " replay fold — " << g.blocker
                        << "; falling through to the pre-existing lane";
            return false;
        }
        ++m_reseeds;
        do_publish(g, "maintainer re-seed ask");
        return true;
    }

    uint32_t published_height() const { return m_published_height; }
    uint64_t publishes()        const { return m_publishes; }
    uint64_t reseeds()          const { return m_reseeds; }
    bool     has_published()    const { return m_publishes != 0; }

    /// The last refusal, for status surfaces. Empty once a publish landed.
    const std::string& last_blocker() const { return m_last_blocker; }

private:
    void do_publish(const ReplayPayeeGuard& g, const char* why)
    {
        std::vector<std::pair<uint256, MNState>> out;
        out.reserve(m_engine.size());
        size_t eligible = 0, banned = 0, with_split = 0;
        for (const auto& e : m_engine.entries()) {
            MNState mn = to_payee_state(e.second);
            if (mn.isValid) ++eligible; else ++banned;
            if (mn.nOperatorReward > 0
                && !mn.scriptOperatorPayout.m_data.empty()) ++with_split;
            out.emplace_back(e.first, std::move(mn));
        }

        LOG_INFO << "[REPLAY-PAYEE] PUBLISHED source=" << kPayeeSourceReplayFold
                 << " as_of_h=" << g.fold_height
                 << " tip_h=" << g.tip_height
                 << " mns=" << out.size()
                 << " eligible=" << eligible
                 << " pose_banned=" << banned
                 << " operator_split=" << with_split
                 << " root=" << g.root
                 << " (" << why << ")";
        LOG_INFO << "[REPLAY-PAYEE]   PROOF: " << g.roots_matched << "/"
                 << g.folded << " byte-exact merkleRootMNList self-checks,"
                    " DIVERGED=none, list re-hashes to the root block h="
                 << g.fold_height << " commits, fold cursor == header tip"
                    " — G1..G8 all passed";

        m_publish(std::move(out), g.fold_height, kPayeeSourceReplayFold);
        m_published_height = g.fold_height;
        ++m_publishes;
        m_last_blocker.clear();
        m_last_blocker_code.clear();
    }

    /// Say WHY we are still withholding, but do not flood. Dedup on the GUARD
    /// CODE (G1..G8), not on the whole sentence: the G7 text carries the live
    /// fold height, so a full-text compare would log every single tick while
    /// the fold catches up — thousands of near-identical lines that bury the
    /// one transition a reader is looking for. The code changes when the
    /// SITUATION changes; a 30-ask heartbeat keeps a run parked on one
    /// condition (and the catch-up progress) visible.
    void note_withheld(const ReplayPayeeGuard& g)
    {
        const std::string code = g.blocker.substr(0, 2);
        const bool changed = (code != m_last_blocker_code);
        m_last_blocker      = g.blocker;
        m_last_blocker_code = code;
        if (changed || ++m_withheld_since_log >= 30) {
            m_withheld_since_log = 0;
            LOG_INFO << "[REPLAY-PAYEE] WITHHELD source="
                     << kPayeeSourceReplayFold << ": " << g.blocker
                     << " — the payee queue keeps whatever source it has"
                        " (dashd-seed / mn-ckpt); nothing is guessed";
        }
    }

    const DmlFoldEngine&      m_engine;
    const FoldReplayConsumer& m_consumer;
    TipHeightFn               m_tip_fn;
    PublishFn                 m_publish;

    uint32_t    m_published_height{0};
    uint64_t    m_publishes{0};
    uint64_t    m_reseeds{0};
    std::string m_last_blocker;
    std::string m_last_blocker_code;   // "G1".."G8" — the dedup key
    uint32_t    m_withheld_since_log{0};
};

} // namespace replay
} // namespace coin
} // namespace dash
