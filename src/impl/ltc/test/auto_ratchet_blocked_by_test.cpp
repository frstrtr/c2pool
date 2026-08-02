// SPDX-License-Identifier: AGPL-3.0-or-later
// ltc_auto_ratchet_blocked_by_test: KATs for the VOTING explain-line — the
// OBSERVABILITY-ONLY change that makes a stuck v36 AutoRatchet name the ONE
// condition that is holding it, with the measurement that justifies the name.
//
// WHY. A live LTC prod node logged nothing but
//     [AutoRatchet] share_version=35 desired=36 state=VOTING
// for >10h while the dashboard showed a 95.31% vote. The two pre-existing
// refusal lines sat INSIDE the `full_window && vote_pct >= 95` branch, so the
// two most common blockers — an under-filled window and an under-voted one —
// produced TOTAL SILENCE. Silence is the defect; a state name that never says
// which of its four gates is shut is not observability.
//
// WHAT IS PINNED. VOTING -> ACTIVATED has FOUR conditions:
//   1  window-fill     total >= chain_length
//   2  vote-pct        vote_pct >= ACTIVATION_THRESHOLD (95)
//   3  tail-work       oldest 10% of the window carries >= SWITCH_THRESHOLD (60)
//                      percent of WORK signalling the target (WEIGHT, not count)
//   4  self-vote-only  distinct_nonself_authors >= MIN_DISTINCT_NONSELF_AUTHORS
//
// Two layers, both driving REAL production code — no lifted oracle, no replica:
//
//   A) AutoRatchet::first_unmet — the pure ordering predicate the live path
//      calls. One KAT per blocked-by value plus the all-pass NONE case, and a
//      precedence KAT pinning that a MULTIPLY-blocked window names the FIRST
//      unmet condition, never a list.
//
//   B) End-to-end through AutoRatchet::get_share_version over a REAL populated
//      ltc::ShareTracker (the chain_walk_window_test construction precedent),
//      with a Boost.Log sink capturing what the node would actually print. Each
//      of the four blockers is provoked by CHAIN SHAPE alone and the emitted
//      line is asserted verbatim on its blocked-by name, its numbers, and the
//      `n/a` vs measured discipline for the tail field. The NEGATIVE TWIN asserts
//      an all-conditions-pass window logs NO blocked line and DOES activate.
//
// CONSENSUS SURFACE IS NOT TOUCHED. Every assertion here is about what the
// ratchet SAYS. The activation decision itself is asserted only via
// ar.state(), so a drift in behaviour (not just wording) also reddens these.
//
// Folded into the EXISTING allowlisted `share_test` target rather than a new
// add_executable — a standalone target is absent from build.yml's --target list
// and would become a #143 NOT_BUILT CTest sentinel.

#include <gtest/gtest.h>

#include <impl/ltc/auto_ratchet.hpp>
#include <impl/ltc/share.hpp>
#include <impl/ltc/share_tracker.hpp>
#include <core/uint256.hpp>

#include <boost/log/core.hpp>
#include <boost/log/sinks/sync_frontend.hpp>
#include <boost/log/sinks/text_ostream_backend.hpp>
#include <boost/make_shared.hpp>
#include <boost/shared_ptr.hpp>

#include <cstdint>
#include <cstdio>
#include <sstream>
#include <string>

using ltc::AutoRatchet;
using ltc::RatchetBlocker;
using ltc::RatchetState;
using ltc::RatchetTail;

namespace {

constexpr int64_t TARGET_VERSION = 36;

// ---------------------------------------------------------------------------
// A) Pure ordering predicate — AutoRatchet::first_unmet, the REAL function the
//    live VOTING path calls to name its blocker.
// ---------------------------------------------------------------------------

TEST(LTC_RatchetBlockedBy, A_WindowFillIsNamedWhenWindowIsShort)
{
    // Under-filled window. Every LATER condition is satisfied, and the tail was
    // deliberately never measured — the live path short-circuits before it.
    EXPECT_EQ(AutoRatchet::first_unmet(/*full_window*/ false, /*vote*/ 100,
                                       RatchetTail::NOT_MEASURED, /*nonself*/ 9),
              RatchetBlocker::WINDOW_FILL);
    EXPECT_STREQ(ltc::ratchet_blocker_str(RatchetBlocker::WINDOW_FILL), "window-fill");
}

TEST(LTC_RatchetBlockedBy, A_VotePctIsNamedWhenVoteIsShort)
{
    EXPECT_EQ(AutoRatchet::first_unmet(true, AutoRatchet::ACTIVATION_THRESHOLD - 1,
                                       RatchetTail::NOT_MEASURED, 9),
              RatchetBlocker::VOTE_PCT);
    // Exactly AT the threshold is NOT a vote-pct block (>=, not >).
    EXPECT_NE(AutoRatchet::first_unmet(true, AutoRatchet::ACTIVATION_THRESHOLD,
                                       RatchetTail::PASS, 9),
              RatchetBlocker::VOTE_PCT);
    EXPECT_STREQ(ltc::ratchet_blocker_str(RatchetBlocker::VOTE_PCT), "vote-pct");
}

TEST(LTC_RatchetBlockedBy, A_TailWorkIsNamedWhenTailGuardFails)
{
    EXPECT_EQ(AutoRatchet::first_unmet(true, 100, RatchetTail::FAIL, 9),
              RatchetBlocker::TAIL_WORK);
    EXPECT_STREQ(ltc::ratchet_blocker_str(RatchetBlocker::TAIL_WORK), "tail-work");

    // Totality: an UNMEASURED tail can never be reported as activate-ready. If
    // it were treated as a pass, an unmeasured zero would silently green-light.
    EXPECT_EQ(AutoRatchet::first_unmet(true, 100, RatchetTail::NOT_MEASURED, 9),
              RatchetBlocker::TAIL_WORK);
}

TEST(LTC_RatchetBlockedBy, A_SelfVoteOnlyIsNamedWhenWindowIsSelfAuthored)
{
    EXPECT_EQ(AutoRatchet::first_unmet(true, 100, RatchetTail::PASS,
                                       AutoRatchet::MIN_DISTINCT_NONSELF_AUTHORS - 1),
              RatchetBlocker::SELF_VOTE_ONLY);
    EXPECT_STREQ(ltc::ratchet_blocker_str(RatchetBlocker::SELF_VOTE_ONLY), "self-vote-only");
}

TEST(LTC_RatchetBlockedBy, A_NoneWhenAllFourConditionsHold)
{
    EXPECT_EQ(AutoRatchet::first_unmet(true, AutoRatchet::ACTIVATION_THRESHOLD,
                                       RatchetTail::PASS,
                                       AutoRatchet::MIN_DISTINCT_NONSELF_AUTHORS),
              RatchetBlocker::NONE);
}

TEST(LTC_RatchetBlockedBy, A_PrecedenceNamesTheFirstUnmetNotAList)
{
    // ALL FOUR unmet at once: the report must be the FIRST in evaluation order
    // so the log stays greppable and unambiguous.
    EXPECT_EQ(AutoRatchet::first_unmet(false, 0, RatchetTail::FAIL, 0),
              RatchetBlocker::WINDOW_FILL);
    // Window fills -> the next one surfaces, and so on down the chain.
    EXPECT_EQ(AutoRatchet::first_unmet(true, 0, RatchetTail::FAIL, 0),
              RatchetBlocker::VOTE_PCT);
    EXPECT_EQ(AutoRatchet::first_unmet(true, 100, RatchetTail::FAIL, 0),
              RatchetBlocker::TAIL_WORK);
    EXPECT_EQ(AutoRatchet::first_unmet(true, 100, RatchetTail::PASS, 0),
              RatchetBlocker::SELF_VOTE_ONLY);
    EXPECT_EQ(AutoRatchet::first_unmet(true, 100, RatchetTail::PASS, 1),
              RatchetBlocker::NONE);
}

// ---------------------------------------------------------------------------
// B) End-to-end: drive the REAL AutoRatchet over a REAL populated ShareTracker
//    and read back what the node actually logged.
// ---------------------------------------------------------------------------

// Boost.Log sink capture. LOG_INFO is BOOST_LOG_TRIVIAL(info); attaching an
// ostream sink to the core records every formatted line for inspection.
class LogCapture
{
public:
    LogCapture()
        : stream_(boost::make_shared<std::ostringstream>())
    {
        auto backend = boost::make_shared<boost::log::sinks::text_ostream_backend>();
        backend->add_stream(stream_);
        backend->auto_flush(true);
        sink_ = boost::make_shared<sink_t>(backend);
        boost::log::core::get()->add_sink(sink_);
    }
    ~LogCapture() { boost::log::core::get()->remove_sink(sink_); }

    std::string str() const { return stream_->str(); }
    void clear() { stream_->str(std::string()); }

private:
    using sink_t = boost::log::sinks::synchronous_sink<boost::log::sinks::text_ostream_backend>;
    boost::shared_ptr<std::ostringstream> stream_;
    boost::shared_ptr<sink_t> sink_;
};

// Short hex tail -> uint256, the LTC test-tree hx() convention.
uint256 hx(const std::string& tail)
{
    uint256 v;
    v.SetHex(std::string(64 - tail.size(), '0') + tail);
    return v;
}

// Chain shape knobs. Share i (0 = oldest) signals `TARGET_VERSION` iff
// i >= old_prefix, i.e. the OLDEST `old_prefix` shares are the non-signalling
// ones — which is exactly where the [9/10*CL, CL] tail guard looks.
struct ChainSpec
{
    int32_t count       = 0;
    int32_t old_prefix  = 0;    // number of oldest shares voting TARGET-1
    bool    external    = true; // give YES-voters a non-local peer_addr
};

// Build a resolved ltc::ShareTracker of uniform-work V36-format shares.
// Uniform m_bits => uniform work weight, so the work-weighted tail guard
// reduces to a head-count over the tail and the spec is exactly predictive.
uint256 build_chain(ltc::ShareTracker& tracker, const ChainSpec& spec, size_t salt)
{
    uint256 prev;
    prev.SetNull();
    uint256 tip;
    tip.SetNull();
    for (int32_t i = 0; i < spec.count; ++i) {
        char buf[24];
        std::snprintf(buf, sizeof(buf), "%zx",
                      static_cast<size_t>((salt << 20) + 0x5100 + static_cast<size_t>(i)));
        uint256 h = hx(buf);
        auto* sh = new ltc::MergedMiningShare();
        sh->m_hash = h;
        if (i == 0) sh->m_prev_hash.SetNull(); else sh->m_prev_hash = prev;
        const bool signals = (i >= spec.old_prefix);
        sh->m_desired_version = signals ? static_cast<uint64_t>(TARGET_VERSION)
                                        : static_cast<uint64_t>(TARGET_VERSION - 1);
        sh->m_bits     = 0x1e0ffff0;
        sh->m_max_bits = 0x1e0ffff0;
        if (signals && spec.external)
            sh->peer_addr = NetService{"203.0.113.7", 9333};
        ltc::ShareType st;
        st = sh;
        tracker.add(st);
        prev = h;
        tip = h;
    }
    return tip;
}

// Testnet params give CHAIN_LENGTH = 400 (vs mainnet 8640), so a full window is
// cheap to build. The flag is process-global; the fixture restores it.
class RatchetExplainLine : public ::testing::Test
{
protected:
    void SetUp() override
    {
        saved_testnet_ = ltc::PoolConfig::is_testnet;
        ltc::PoolConfig::is_testnet = true;
    }
    void TearDown() override { ltc::PoolConfig::is_testnet = saved_testnet_; }

    // Drive one evaluation and return everything the node logged during it.
    static std::string evaluate(AutoRatchet& ar, ltc::ShareTracker& tracker,
                                const uint256& tip)
    {
        LogCapture cap;
        ar.get_share_version(tracker, tip);
        return cap.str();
    }

    bool saved_testnet_ = false;
};

TEST_F(RatchetExplainLine, B_WindowFill_ShortWindowIsNoLongerSilent)
{
    // THE SILENT CASE. Pre-change this branch logged absolutely nothing.
    const uint32_t CL = ltc::PoolConfig::chain_length();
    ASSERT_EQ(CL, 400u);

    ltc::ShareTracker tracker;
    ChainSpec spec; spec.count = 120; spec.old_prefix = 0;   // 100% YES, short window
    auto tip = build_chain(tracker, spec, 1);

    AutoRatchet ar("", TARGET_VERSION);
    const std::string out = evaluate(ar, tracker, tip);

    EXPECT_NE(out.find("blocked-by=window-fill"), std::string::npos) << out;
    EXPECT_NE(out.find("window=120/400"), std::string::npos) << out;
    // The measurement AND the threshold, both present.
    EXPECT_NE(out.find("vote=100% (need 95)"), std::string::npos) << out;
    // Tail was never evaluated -> `n/a`, NEVER a zero that means "not measured".
    EXPECT_NE(out.find("tail10%work=n/a (need 60)"), std::string::npos) << out;
    EXPECT_EQ(out.find("tail10%work=0%"), std::string::npos) << out;
    // ETA is tail-guard-only.
    EXPECT_EQ(out.find("eta_shares"), std::string::npos) << out;
    EXPECT_EQ(ar.state(), RatchetState::VOTING);
}

TEST_F(RatchetExplainLine, B_VotePct_UnderVotedWindowIsNoLongerSilent)
{
    // THE OTHER SILENT CASE: window is full, vote is short.
    ltc::ShareTracker tracker;
    ChainSpec spec; spec.count = 400; spec.old_prefix = 80;  // 320/400 = 80%
    auto tip = build_chain(tracker, spec, 2);

    AutoRatchet ar("", TARGET_VERSION);
    const std::string out = evaluate(ar, tracker, tip);

    EXPECT_NE(out.find("blocked-by=vote-pct"), std::string::npos) << out;
    EXPECT_NE(out.find("window=400/400"), std::string::npos) << out;
    EXPECT_NE(out.find("vote=80% (need 95)"), std::string::npos) << out;
    EXPECT_NE(out.find("tail10%work=n/a (need 60)"), std::string::npos) << out;
    EXPECT_EQ(out.find("eta_shares"), std::string::npos) << out;
    EXPECT_EQ(ar.state(), RatchetState::VOTING);
}

TEST_F(RatchetExplainLine, B_TailWork_NamedWithMeasuredTailAndEta)
{
    // Window full, vote EXACTLY at 95% (380/400) — so conditions 1 and 2 hold —
    // but the oldest 20 of the 40-share tail still vote V35, so the tail carries
    // only 50% of the work signalling: below the 60% switch gate.
    ltc::ShareTracker tracker;
    ChainSpec spec; spec.count = 400; spec.old_prefix = 20;
    auto tip = build_chain(tracker, spec, 3);

    AutoRatchet ar("", TARGET_VERSION);
    const std::string out = evaluate(ar, tracker, tip);

    EXPECT_NE(out.find("blocked-by=tail-work"), std::string::npos) << out;
    EXPECT_NE(out.find("window=400/400"), std::string::npos) << out;
    EXPECT_NE(out.find("vote=95% (need 95)"), std::string::npos) << out;
    // The tail WAS measured here, so a real number must appear — not `n/a`.
    EXPECT_NE(out.find("tail10%work=50% (need 60)"), std::string::npos) << out;
    EXPECT_EQ(out.find("tail10%work=n/a"), std::string::npos) << out;
    // ETA, and ONLY for this blocker. Shallowest non-signalling share sits at
    // depth 380 (share index 19 of 400), tail end = 400, so 20 more shares; at
    // the 4s testnet share period that is 80s = 0.0h to one decimal.
    EXPECT_NE(out.find("eta_shares<=20"), std::string::npos) << out;
    EXPECT_NE(out.find("eta<=0.0h"), std::string::npos) << out;
    EXPECT_EQ(ar.state(), RatchetState::VOTING);
}

TEST_F(RatchetExplainLine, B_SelfVoteOnly_NamedOnAFullySelfAuthoredWindow)
{
    // 100% YES by count AND by tail work, but every YES-vote is locally minted
    // (default peer_addr), so the mode-2 guard holds. The tail WAS measured and
    // passed, so it must report 100%, not `n/a`.
    ltc::ShareTracker tracker;
    ChainSpec spec; spec.count = 400; spec.old_prefix = 0; spec.external = false;
    auto tip = build_chain(tracker, spec, 4);

    AutoRatchet ar("", TARGET_VERSION);
    const std::string out = evaluate(ar, tracker, tip);

    EXPECT_NE(out.find("blocked-by=self-vote-only"), std::string::npos) << out;
    EXPECT_NE(out.find("vote=100% (need 95)"), std::string::npos) << out;
    EXPECT_NE(out.find("tail10%work=100% (need 60)"), std::string::npos) << out;
    EXPECT_NE(out.find("nonself_authors=0 (need 1)"), std::string::npos) << out;
    EXPECT_EQ(out.find("eta_shares"), std::string::npos) << out;
    EXPECT_EQ(ar.state(), RatchetState::VOTING);
}

// --- NEGATIVE TWIN ---------------------------------------------------------
TEST_F(RatchetExplainLine, B_AllFourPass_NoBlockedLineAndItActivates)
{
    // Same 400-share window, 100% YES, tail 100% by work, and the YES-votes
    // carry an EXTERNAL peer_addr. All four conditions hold.
    ltc::ShareTracker tracker;
    ChainSpec spec; spec.count = 400; spec.old_prefix = 0; spec.external = true;
    auto tip = build_chain(tracker, spec, 5);

    AutoRatchet ar("", TARGET_VERSION);
    const std::string out = evaluate(ar, tracker, tip);

    // It must NOT claim to be blocked...
    EXPECT_EQ(out.find("blocked-by="), std::string::npos) << out;
    // ...and it must actually cross, not merely stay quiet.
    EXPECT_NE(ar.state(), RatchetState::VOTING) << out;
    EXPECT_NE(out.find("VOTING -> "), std::string::npos) << out;
}

// --- RATE LIMIT ------------------------------------------------------------
TEST_F(RatchetExplainLine, B_RateLimitedToChangePlusHeartbeat)
{
    // This runs once per share; an unthrottled line would flood the log. The
    // rule is: emit on CHANGE of blocked-by, plus a heartbeat every
    // VOTING_EXPLAIN_HEARTBEAT evaluations.
    ltc::ShareTracker tracker;
    ChainSpec spec; spec.count = 120; spec.old_prefix = 0;
    auto tip = build_chain(tracker, spec, 6);

    AutoRatchet ar("", TARGET_VERSION);

    // First evaluation: change (nothing logged before) -> one line.
    EXPECT_NE(evaluate(ar, tracker, tip).find("blocked-by=window-fill"),
              std::string::npos);

    // Next HEARTBEAT-1 evaluations: same blocker, suppressed.
    for (int i = 0; i < AutoRatchet::VOTING_EXPLAIN_HEARTBEAT - 1; ++i) {
        const std::string quiet = evaluate(ar, tracker, tip);
        EXPECT_EQ(quiet.find("blocked-by="), std::string::npos)
            << "flooded at i=" << i << ": " << quiet;
    }
    // The heartbeat evaluation speaks again.
    EXPECT_NE(evaluate(ar, tracker, tip).find("blocked-by=window-fill"),
              std::string::npos);

    // A CHANGE of blocker breaks the silence immediately, without waiting for
    // the next heartbeat: same ratchet, a chain that now blocks on vote-pct.
    ltc::ShareTracker tracker2;
    ChainSpec spec2; spec2.count = 400; spec2.old_prefix = 80;
    auto tip2 = build_chain(tracker2, spec2, 7);
    const std::string changed = evaluate(ar, tracker2, tip2);
    EXPECT_NE(changed.find("blocked-by=vote-pct"), std::string::npos) << changed;
}

} // namespace
