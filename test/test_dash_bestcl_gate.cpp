// SPDX-License-Identifier: AGPL-3.0-or-later
/// bestCL template gate — the CONSENSUS-EXACT rule vs the freshness proxy.
///
/// WHAT THIS SUITE PINS. The #780 BLOCKER-2 gate refuses to serve the embedded
/// arm unless our best observed ChainLock is within one block of the tip. Its
/// own rationale calls that "a sufficient condition" — and it is only that.
/// dashcore's actual rule, CheckCbTxBestChainlock (dash v23.1.7
/// src/evo/specialtxman.cpp:102-177), never mentions the tip or freshness:
///
///     prevCL = GetNonNullCoinbaseChainlock(pindex->pprev)              // :129
///     if (prevCL) {
///         if (!cbTx.bestCLSignature.IsValid())   -> bad-cbtx-null-clsig    // :134
///         if (cbTx.bestCLHeightDiff > prevCL.diff + 1)
///                                                -> bad-cbtx-older-clsig   // :138
///     }
///     if (cbTx.bestCLSignature.IsValid()) {
///         if (bestCLHeightDiff >= pindex->nHeight) -> bad-cbtx-cldiff       // :146
///         VerifyChainLock(...)                     -> bad-cbtx-invalid-clsig// :164
///     } else if (bestCLHeightDiff != 0)            -> bad-cbtx-cldiff       // :172
///
/// Restated on the absolute-height axis (committed CL height of a block at H is
/// H - bestCLHeightDiff - 1), `bestCLHeightDiff > prevDiff + 1` is EXACTLY
/// "our committed ChainLock height is LOWER than the previous block's". The
/// rule is monotonicity, not recency. dashd's own miner exploits precisely
/// that: holding nothing fresher, it RE-COMMITS the previous block's signature
/// with heightDiff = prevDiff + 1 and mines on (src/node/miner.cpp:143-146,
/// :153-156). It never refuses.
///
/// So the tests below are written against the real rule:
///   * a ChainLock far older than the tip, but equal to what the previous block
///     committed, is SERVABLE (the freshness proxy refused it — measured as the
///     single largest decline cause on the daemonless soak);
///   * an ADVANCE past the previous block's committed ChainLock is refused
///     unless it passed local BLS verification (dashcore re-verifies it, so we
///     must be able to justify it);
///   * a null/absent ChainLock where the previous block committed a real one is
///     refused (bad-cbtx-null-clsig);
///   * WITHOUT the previous block's own committed ChainLock in hand we cannot
///     evaluate the rule at all, so we refuse — the gate is never weakened into
///     a no-op, including on a BLS-dark build.
///
/// No fabricated dashcore behaviour: every expectation is a restatement of a
/// cited line of specialtxman.cpp / miner.cpp above.

#include <gtest/gtest.h>

#include <impl/dash/coin/node_coin_state.hpp>
#include <impl/dash/coin/mn_state_machine.hpp>
#include <impl/dash/coin/vendor/simplifiedmns.hpp>

#include <core/param_catalog.hpp>
#include <core/uint256.hpp>

#include <array>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

using dash::coin::NodeCoinState;
using dash::coin::BestClPolicy;
using dash::coin::ClProvenance;
using dash::coin::MNState;
using dash::coin::vendor::CSimplifiedMNListEntry;

namespace {

constexpr uint8_t  DASH_PUBKEY_VER = 76;
constexpr uint8_t  DASH_P2SH_VER   = 16;

// A realistic mainnet tip from the measured soak window (soak0803g probe).
constexpr uint32_t TIP = 2'515'889;

uint256 raw256(uint8_t base) {
    uint256 h;
    std::array<uint8_t, 32> p{};
    for (size_t i = 0; i < 32; ++i) p[i] = static_cast<uint8_t>(base + i);
    std::memcpy(h.data(), p.data(), 32);
    return h;
}

std::vector<unsigned char> p2pkh_script(uint8_t hashseed) {
    std::vector<unsigned char> s{0x76, 0xa9, 0x14};
    for (int i = 0; i < 20; ++i) s.push_back(static_cast<unsigned char>(hashseed + i));
    s.push_back(0x88); s.push_back(0xac);
    return s;
}

CSimplifiedMNListEntry sml_entry(uint8_t seed) {
    CSimplifiedMNListEntry e;
    e.proRegTxHash  = raw256(seed);
    e.confirmedHash = raw256(seed + 1);
    e.isValid = true;
    return e;
}

std::array<uint8_t, 96> some_sig(uint8_t seed) {
    std::array<uint8_t, 96> s{};
    for (size_t i = 0; i < s.size(); ++i) s[i] = static_cast<uint8_t>(seed + i);
    return s;
}

/// A NodeCoinState in which EVERY axis other than bestCL is viable, tipped at
/// `tip`. Any refusal a test sees is therefore attributable to the bestCL gate.
void make_state(NodeCoinState& st, uint32_t tip = TIP) {
    MNState s;
    s.isValid = true;
    s.nRegisteredHeight = 2'300'000;
    s.nLastPaidHeight   = 0;
    s.scriptPayout.m_data = p2pkh_script(0x30);
    s.payoutSplitProvenance = MNState::SPLIT_KNOWN;   // fixture: proven zero split (h=2516595 gate)
    st.mnstates().load(std::vector<std::pair<uint256, MNState>>{{raw256(0x01), s}});

    st.sml().mnList = {sml_entry(0x40), sml_entry(0x60)};
    st.sml().sort();
    st.set_have_sml(true);
    st.set_sml_current_hash(raw256(0xAB));
    st.set_tip(tip, raw256(0xAB), 0x1b104be3u, 1'700'000'000u,
               DASH_PUBKEY_VER, DASH_P2SH_VER);
}

// The greppable token only (classify_decline() decorates it for the log).
std::string cause_of(const NodeCoinState& st) {
    return st.describe_decline().cause;
}

}  // namespace

// ════════════════════════════════════════════════════════════════════════
// 1. THE HEADLINE: a verified-but-OLD ChainLock is servable under the real
//    rule, where the freshness proxy refused it.
//
//    MEASURED context (soak0803g probe, 2026-08-03): 23 of 39 decline alerts
//    were cause=bestcl-stale, e.g. "value=2515889 threshold=>=2515893" — a
//    genuine mainnet ChainLock stall with the CL height frozen while blocks
//    kept coming. dashd built through every one of those blocks; only our
//    stricter gate refused.
// ════════════════════════════════════════════════════════════════════════
TEST(DashBestClGate, StaleButMonotonicChainLockServesUnderConsensusExact) {
    NodeCoinState st;
    make_state(st);

    // Ground truth: the previous block (TIP) committed a ChainLock 4 blocks
    // back. Under dashcore that means our block at TIP+1 need only commit a
    // ChainLock at height >= 2515885. Nothing about the tip enters into it.
    const int32_t prev_committed_cl = 2'515'885;

    // (a) The freshness proxy refuses it — this is the behaviour on master.
    st.set_bestcl_policy(BestClPolicy::Freshness);
    st.set_best_cl(prev_committed_cl, some_sig(0x11), ClProvenance::ChainCommitted);
    EXPECT_FALSE(st.make_embedded_work_inputs().viable())
        << "the freshness proxy is expected to refuse here — that is the cost "
           "this change removes";
    EXPECT_EQ("bestcl-stale", cause_of(st));

    // (b) Consensus-exact, given the previous block's OWN committed ChainLock,
    //     serves: equal to prev's committed CL => bestCLHeightDiff == prevDiff+1
    //     exactly, which dashcore's `> prevDiff + 1` test admits (:138).
    st.set_bestcl_policy(BestClPolicy::ConsensusExact);
    st.set_tip_cbtx_chainlock(static_cast<int32_t>(TIP), /*has_sig=*/true,
                              prev_committed_cl);
    EXPECT_TRUE(st.make_embedded_work_inputs().viable())
        << "decline was: " << cause_of(st);

    // And the pre-emit gate must agree — one decision, two surfaces.
    EXPECT_FALSE(st.bestcl_decline().has_value());
}

// ════════════════════════════════════════════════════════════════════════
// 2. An ADVANCE past the previous block's committed ChainLock is the one case
//    dashcore makes us prove with BLS (specialtxman.cpp:164 VerifyChainLock =>
//    bad-cbtx-invalid-clsig). Unverified provenance must NOT be committed.
// ════════════════════════════════════════════════════════════════════════
TEST(DashBestClGate, UnverifiedAdvanceRefused) {
    NodeCoinState st;
    make_state(st);
    st.set_bestcl_policy(BestClPolicy::ConsensusExact);
    st.set_tip_cbtx_chainlock(static_cast<int32_t>(TIP), true, 2'515'885);

    // A ChainLock NEWER than what the previous block committed, with no
    // recorded justification at all. Freshness would have loved it — it is at
    // the tip. The consensus-exact gate refuses it.
    st.set_best_cl(static_cast<int32_t>(TIP), some_sig(0x22),
                   ClProvenance::Unknown);
    EXPECT_FALSE(st.make_embedded_work_inputs().viable());
    EXPECT_EQ("bestcl-unverified-advance", cause_of(st));

    // Chain-committed provenance does not license an advance either: a value we
    // read out of some block's coinbase is only self-evidently good AS the
    // previous block's committed value, and this one is past it.
    st.set_best_cl(static_cast<int32_t>(TIP), some_sig(0x22),
                   ClProvenance::ChainCommitted);
    EXPECT_FALSE(st.make_embedded_work_inputs().viable());
    EXPECT_EQ("bestcl-unverified-advance", cause_of(st));

    // Locally BLS-verified => servable, and strictly better than re-committing
    // the previous block's (dashcore admits any diff <= prevDiff+1).
    st.set_best_cl(static_cast<int32_t>(TIP), some_sig(0x22),
                   ClProvenance::BlsVerified);
    EXPECT_TRUE(st.make_embedded_work_inputs().viable())
        << "decline was: " << cause_of(st);
}

// ════════════════════════════════════════════════════════════════════════
// 3. Null / absent ChainLock where the previous block committed a real one =>
//    bad-cbtx-null-clsig (specialtxman.cpp:134-137). Refuse.
// ════════════════════════════════════════════════════════════════════════
TEST(DashBestClGate, AbsentChainLockRefusedWhenPrevCommittedOne) {
    NodeCoinState st;
    make_state(st);
    st.set_bestcl_policy(BestClPolicy::ConsensusExact);
    st.set_tip_cbtx_chainlock(static_cast<int32_t>(TIP), true, 2'515'885);

    // best_cl_height 0 is "no clsig ever observed" (post-restart / relay gap).
    EXPECT_FALSE(st.make_embedded_work_inputs().viable());
    EXPECT_EQ("bestcl-absent", cause_of(st));
}

// ════════════════════════════════════════════════════════════════════════
// 4. A ChainLock OLDER than the previous block's committed one is exactly
//    bad-cbtx-older-clsig. Refuse. (This is the failure the freshness proxy
//    was standing in for — and the only one it actually needed to catch.)
// ════════════════════════════════════════════════════════════════════════
TEST(DashBestClGate, OlderThanPrevCommittedRefused) {
    NodeCoinState st;
    make_state(st);
    st.set_bestcl_policy(BestClPolicy::ConsensusExact);
    st.set_tip_cbtx_chainlock(static_cast<int32_t>(TIP), true, 2'515'885);

    st.set_best_cl(2'515'884, some_sig(0x33), ClProvenance::ChainCommitted);
    EXPECT_FALSE(st.make_embedded_work_inputs().viable());
    EXPECT_EQ("bestcl-older-than-prev", cause_of(st));
}

// ════════════════════════════════════════════════════════════════════════
// 5. FAIL-CLOSED WITHOUT THE CONSTRAINT'S OWN INPUT. dashcore's rule is stated
//    relative to the previous block's committed ChainLock; without it we cannot
//    evaluate the rule, so we must not serve. This is what stops the relaxation
//    from degenerating into "commit whatever we have".
// ════════════════════════════════════════════════════════════════════════
TEST(DashBestClGate, MissingPrevBlockCommittedChainLockFailsClosed) {
    NodeCoinState st;
    make_state(st);
    st.set_bestcl_policy(BestClPolicy::ConsensusExact);

    // Never fed => refuse even with a ChainLock AT the tip (which the freshness
    // proxy would have accepted).
    st.set_best_cl(static_cast<int32_t>(TIP), some_sig(0x44),
                   ClProvenance::BlsVerified);
    EXPECT_FALSE(st.make_embedded_work_inputs().viable());
    EXPECT_EQ("bestcl-tip-cbtx-stale", cause_of(st));

    // Fed, but for a block BEHIND the tip we are building on — the previous
    // block may have committed something newer than what we hold, and
    // committing ours would then be bad-cbtx-older-clsig. Refuse.
    st.set_tip_cbtx_chainlock(static_cast<int32_t>(TIP) - 1, true, 2'515'880);
    EXPECT_FALSE(st.make_embedded_work_inputs().viable());
    EXPECT_EQ("bestcl-tip-cbtx-stale", cause_of(st));

    // Current with the tip => servable.
    st.set_tip_cbtx_chainlock(static_cast<int32_t>(TIP), true, 2'515'880);
    EXPECT_TRUE(st.make_embedded_work_inputs().viable())
        << "decline was: " << cause_of(st);
}

// ════════════════════════════════════════════════════════════════════════
// 6. BLS-DARK BUILD MUST NOT BECOME PERMISSIVE. A stub build never produces
//    ClProvenance::BlsVerified (CoinStateMaintainer::on_new_chainlock returns
//    early with no verifier installed), so the ONLY values it can hold are
//    chain-committed ones — and those can never advance past the previous
//    block's committed ChainLock, which is the one case requiring BLS.
//
//    This test states the invariant directly: with only chain-committed
//    provenance available, consensus-exact serves EXACTLY the set of states
//    where our committed value equals the previous block's — i.e. dashd's own
//    no-ChainLock behaviour, never anything the network has not already
//    accepted.
// ════════════════════════════════════════════════════════════════════════
TEST(DashBestClGate, BlsDarkBuildNeverServesAnUnprovenChainLock) {
    NodeCoinState st;
    make_state(st);
    st.set_bestcl_policy(BestClPolicy::ConsensusExact);
    st.set_tip_cbtx_chainlock(static_cast<int32_t>(TIP), true, 2'515'885);

    // Every non-BlsVerified height ABOVE the previous block's committed CL is
    // refused; only the equal-or-below-and-not-older case serves.
    for (int32_t h : {2'515'886, 2'515'887, 2'515'888, static_cast<int32_t>(TIP)}) {
        st.set_best_cl(h, some_sig(0x55), ClProvenance::ChainCommitted);
        EXPECT_FALSE(st.make_embedded_work_inputs().viable())
            << "h=" << h << " must not be servable without BLS proof";
    }
    st.set_best_cl(2'515'885, some_sig(0x55), ClProvenance::ChainCommitted);
    EXPECT_TRUE(st.make_embedded_work_inputs().viable())
        << "decline was: " << cause_of(st);

    // Provenance Unknown is refused at every height, including the equal one —
    // an unaudited future writer cannot open the gate by omission.
    st.set_best_cl(2'515'885, some_sig(0x55), ClProvenance::Unknown);
    EXPECT_FALSE(st.make_embedded_work_inputs().viable());
    EXPECT_EQ("bestcl-unjustified", cause_of(st));
}

// ════════════════════════════════════════════════════════════════════════
// 7. The previous block committed a NULL ChainLock =>
//    GetNonNullCoinbaseChainlock returns nullopt and specialtxman.cpp:130-141
//    is skipped entirely: dashcore imposes NO constraint. dashd commits null in
//    that state when it holds nothing (miner.cpp:167-171). Refusing there would
//    be pure loss.
// ════════════════════════════════════════════════════════════════════════
TEST(DashBestClGate, PrevCommittedNullImposesNoConstraint) {
    NodeCoinState st;
    make_state(st);
    st.set_bestcl_policy(BestClPolicy::ConsensusExact);
    st.set_tip_cbtx_chainlock(static_cast<int32_t>(TIP), /*has_sig=*/false, -1);

    // Holding nothing: commit null, exactly as dashd does. Servable.
    EXPECT_TRUE(st.make_embedded_work_inputs().viable())
        << "decline was: " << cause_of(st);

    // Holding a chain-committed ChainLock: also servable (dashcore only
    // BLS-verifies it, and the network already accepted this signature in a
    // block). No `advancing` comparison applies — there is no prev value.
    st.set_best_cl(2'515'800, some_sig(0x66), ClProvenance::ChainCommitted);
    EXPECT_TRUE(st.make_embedded_work_inputs().viable())
        << "decline was: " << cause_of(st);

    // Holding an UNJUSTIFIED one is still refused: we would commit a signature
    // we cannot defend, and dashcore verifies it (:164).
    st.set_best_cl(2'515'800, some_sig(0x66), ClProvenance::Unknown);
    EXPECT_FALSE(st.make_embedded_work_inputs().viable());
    EXPECT_EQ("bestcl-unjustified", cause_of(st));
}

// ════════════════════════════════════════════════════════════════════════
// 8. REGRESSION FENCE: the legacy setter is byte-unchanged.
//    set_require_fresh_bestcl(true) must still mean the freshness proxy, and a
//    bare NodeCoinState runs no gate. (The NODE default is ConsensusExact —
//    case 10 — installed through resolve_bestcl_policy(), not this setter.)
// ════════════════════════════════════════════════════════════════════════
TEST(DashBestClGate, LegacySetterStillSelectsFreshnessAndOffIsOff) {
    NodeCoinState st;
    make_state(st);

    EXPECT_EQ(BestClPolicy::Off, st.bestcl_policy())
        << "default must be Off — no gate unless armed";

    st.set_require_fresh_bestcl(true);
    EXPECT_EQ(BestClPolicy::Freshness, st.bestcl_policy());

    // The exact pre-change refusals, reproduced.
    EXPECT_FALSE(st.make_embedded_work_inputs().viable());
    EXPECT_EQ("bestcl-stale", cause_of(st));
    st.set_best_cl(static_cast<int32_t>(TIP) - 2, some_sig(0x77),
                   ClProvenance::ChainCommitted);
    EXPECT_FALSE(st.make_embedded_work_inputs().viable());
    st.set_best_cl(static_cast<int32_t>(TIP) - 1, some_sig(0x77),
                   ClProvenance::ChainCommitted);
    EXPECT_TRUE(st.make_embedded_work_inputs().viable());

    // ...and the freshness proxy ignores the tip-cbtx datum entirely, so
    // feeding it cannot change a Freshness verdict in either direction.
    st.set_best_cl(static_cast<int32_t>(TIP) - 5, some_sig(0x77),
                   ClProvenance::ChainCommitted);
    st.set_tip_cbtx_chainlock(static_cast<int32_t>(TIP), true,
                              static_cast<int32_t>(TIP) - 5);
    EXPECT_FALSE(st.make_embedded_work_inputs().viable());
    EXPECT_EQ("bestcl-stale", cause_of(st));

    st.set_require_fresh_bestcl(false);
    EXPECT_EQ(BestClPolicy::Off, st.bestcl_policy());
    EXPECT_TRUE(st.make_embedded_work_inputs().viable());
}

// ════════════════════════════════════════════════════════════════════════
// 9. set_tip_cbtx_chainlock is MONOTONIC on the block axis: a late or
//    duplicate OLD block must not roll the provenance height backwards (the
//    same discipline the credit-pool seed's Nit-C guard applies). Without this
//    a replayed historical body would silently un-arm the gate.
// ════════════════════════════════════════════════════════════════════════
TEST(DashBestClGate, TipCbtxChainLockIsMonotonic) {
    NodeCoinState st;
    make_state(st);
    st.set_bestcl_policy(BestClPolicy::ConsensusExact);

    st.set_tip_cbtx_chainlock(static_cast<int32_t>(TIP), true, 2'515'885);
    EXPECT_EQ(static_cast<int32_t>(TIP), st.tip_cbtx_at_height());

    // A replayed older block is ignored on both fields.
    st.set_tip_cbtx_chainlock(2'515'000, true, 2'514'000);
    EXPECT_EQ(static_cast<int32_t>(TIP), st.tip_cbtx_at_height());
    EXPECT_EQ(2'515'885, st.tip_cbtx_cl_height());
    EXPECT_FALSE(st.tip_cbtx_cl_null());

    st.set_best_cl(2'515'885, some_sig(0x88), ClProvenance::ChainCommitted);
    EXPECT_TRUE(st.make_embedded_work_inputs().viable())
        << "decline was: " << cause_of(st);
}

// ════════════════════════════════════════════════════════════════════════
// 10. THE NODE DEFAULT IS CONSENSUS-EXACT, and freshness stays selectable as
//     the rollback. Pinned on every surface that names a default: the policy
//     constant, the CLI parser, the resolver main_dash installs, the param
//     catalog row, and main_dash's own initializers.
// ════════════════════════════════════════════════════════════════════════
TEST(DashBestClGate, DefaultPolicyIsConsensusExact) {
    using dash::coin::kDefaultBestClPolicy;
    using dash::coin::bestcl_policy_name;
    using dash::coin::parse_bestcl_policy;
    using dash::coin::resolve_bestcl_policy;

    EXPECT_EQ(BestClPolicy::ConsensusExact, kDefaultBestClPolicy);
    const std::string def = bestcl_policy_name(kDefaultBestClPolicy);
    EXPECT_EQ("consensus-exact", def);

    // What main_dash installs for a node launched without --bestcl-policy.
    EXPECT_EQ(BestClPolicy::ConsensusExact, resolve_bestcl_policy(true, def));
    // No embedded arm => no gate, whatever the flag says.
    EXPECT_EQ(BestClPolicy::Off, resolve_bestcl_policy(false, def));
    EXPECT_EQ(BestClPolicy::Off, resolve_bestcl_policy(false, "freshness"));

    // The rollback is one flag away and means exactly the old proxy.
    ASSERT_TRUE(parse_bestcl_policy("freshness").has_value());
    EXPECT_EQ(BestClPolicy::Freshness, *parse_bestcl_policy("freshness"));
    EXPECT_EQ(BestClPolicy::Freshness, resolve_bestcl_policy(true, "freshness"));
    ASSERT_TRUE(parse_bestcl_policy("consensus-exact").has_value());
    EXPECT_EQ(BestClPolicy::ConsensusExact,
              *parse_bestcl_policy("consensus-exact"));

    // Nothing else parses: the CLI refuses these instead of guessing a gate.
    for (const char* bad : {"", "off", "Freshness", "consensus_exact", "exact",
                            "freshness ", "none"})
        EXPECT_FALSE(parse_bestcl_policy(bad).has_value()) << "'" << bad << "'";

    // The param catalog states the same default (the settings / config
    // surfaces publish this literal).
    const auto* row = c2pool::catalog::find_by_canon("embedded.bestcl_policy");
    ASSERT_NE(nullptr, row);
    EXPECT_EQ(def, row->default_literal);
    EXPECT_EQ(row, c2pool::catalog::find_by_alias(c2pool::catalog::Bin::BIN_DASH,
                                                  "--bestcl-policy"));

    // main_dash.cpp initialises both of its defaults (the CLI local and
    // run_node's parameter) from the constant, never from a literal that could
    // drift from it.
    std::ifstream in(DASH_MAIN_SRC);
    ASSERT_TRUE(in.good()) << "cannot open " << DASH_MAIN_SRC;
    std::stringstream buf;
    buf << in.rdbuf();
    std::string code;
    std::istringstream lines(buf.str());
    for (std::string line; std::getline(lines, line);) {
        const auto c = line.find("//");
        code += (c == std::string::npos ? line : line.substr(0, c)) + "\n";
    }
    std::size_t sites = 0;
    for (const char* decl : {"std::string& bestcl_policy =",
                             "std::string bestcl_policy ="}) {
        for (std::size_t at = code.find(decl); at != std::string::npos;
             at = code.find(decl, at + 1)) {
            const std::string init = code.substr(at, 160);
            EXPECT_NE(std::string::npos,
                      init.find("bestcl_policy_name(dash::coin::kDefaultBestClPolicy)"))
                << "default initializer does not use kDefaultBestClPolicy: " << init;
            ++sites;
        }
    }
    EXPECT_EQ(2u, sites) << "the CLI local and run_node's parameter";
    EXPECT_EQ(std::string::npos, code.find("bestcl_policy = \"freshness\""));
}

// ════════════════════════════════════════════════════════════════════════
// 11. THE 2026-10-25 INCIDENT, replayed against the default policy.
//
//     Blocks 2561315..2561318 carried no ChainLock. The last ChainLock was at
//     2561314, and every block after it re-committed that signature in its
//     coinbase (dashd's miner: "Our best CL isn't newer: inserting CL from
//     previous block"). Building on 2561316 the node held best CL 2561314,
//     prev_h - best_cl = 2: the freshness proxy declined, the daemonless node
//     had no fallback, no template went out for 376 s, and the block the
//     miners found on the old job (2561316) was orphaned.
//
//     Under the default, with block H-1's committed ChainLock in hand, every
//     one of those templates is viable — and is exactly what dashd built.
// ════════════════════════════════════════════════════════════════════════
TEST(DashBestClGate, IncidentStaleChainLockIsViableUnderTheDefault) {
    constexpr int32_t LAST_CL = 2'561'314;

    for (uint32_t prev : {2'561'316u, 2'561'317u, 2'561'318u}) {
        NodeCoinState st;
        make_state(st, prev);
        // Block `prev` committed the ChainLock at LAST_CL, and that very
        // signature is what we hold (read out of its coinbase).
        st.set_tip_cbtx_chainlock(static_cast<int32_t>(prev), /*has_sig=*/true,
                                  LAST_CL);
        st.set_best_cl(LAST_CL, some_sig(0x99), ClProvenance::ChainCommitted);
        ASSERT_GE(static_cast<int32_t>(prev) - LAST_CL, 2) << "a stale best CL";

        // The node's default, installed the way main_dash installs it.
        st.set_bestcl_policy(dash::coin::resolve_bestcl_policy(
            true, dash::coin::bestcl_policy_name(dash::coin::kDefaultBestClPolicy)));
        EXPECT_EQ(BestClPolicy::ConsensusExact, st.bestcl_policy());
        EXPECT_TRUE(st.make_embedded_work_inputs().viable())
            << "prev=" << prev << " decline was: " << cause_of(st);
        EXPECT_FALSE(st.bestcl_decline().has_value()) << "prev=" << prev;

        // The rollback still declines it, exactly as on the incident day.
        st.set_bestcl_policy(dash::coin::resolve_bestcl_policy(true, "freshness"));
        EXPECT_FALSE(st.make_embedded_work_inputs().viable()) << "prev=" << prev;
        EXPECT_EQ("bestcl-stale", cause_of(st)) << "prev=" << prev;
    }
}
