// SPDX-License-Identifier: AGPL-3.0-or-later
//
// KAT for the daemonless good-citizen serving defaults
// (impl/dash/coin/good_citizen_defaults.hpp).
//
// The contract under test:
//   * dashd-ARMED posture (any of --coin-rpc/--coin-rpc-auth/--submit-block):
//     resolution is byte-identical to the requested flags — the default never
//     flips anything, existing deployments keep their served bytes.
//   * DAEMONLESS posture: every lever the operator did not spell out resolves
//     ON (serve the full mempool + special txs + funded superblocks by
//     default); an explicit --<flag>=false opt-out wins; an explicit ON is
//     honoured.
//   * The unsafe corner (fee-carrying serve with the serve-time referee
//     disarmed) is impossible via defaults and is NAMED when an explicit
//     opt-out creates it.
//   * REGRESSION WITNESS: the resolved daemonless default resolves the embedded
//     ARM (embedded_mainnet ON ⇒ resolve_embedded_arm → EmbeddedEligible with
//     discovery implied), whereas the pre-flip default (embedded_mainnet OFF)
//     resolved DashdFallback/NoOptIn — i.e. a bare `--run` served NOTHING.

#include <gtest/gtest.h>

#include <impl/dash/coin/good_citizen_defaults.hpp>
#include <impl/dash/coin/arm_resolution.hpp>

using dash::coin::TxServeLever;
using dash::coin::TxServeLevers;
using dash::coin::TxServeResolution;
using dash::coin::resolve_good_citizen_tx_serve;

namespace {

TxServeLever off()          { return TxServeLever{false, false}; }
TxServeLever on()           { return TxServeLever{true,  false}; }
TxServeLever forced_off()   { return TxServeLever{false, true};  }

// All twelve levers unset ("operator said nothing").
TxServeLevers all_default()
{
    return TxServeLevers{off(), off(), off(), off(), off(), off(),
                         off(), off(), off(), off(), off(), off()};
}

// All twelve levers explicitly requested ON.
TxServeLevers all_on()
{
    return TxServeLevers{on(), on(), on(), on(), on(), on(),
                         on(), on(), on(), on(), on(), on()};
}

// All twelve levers explicitly opted out (--<flag>=false).
TxServeLevers all_forced_off()
{
    return TxServeLevers{forced_off(), forced_off(), forced_off(), forced_off(),
                         forced_off(), forced_off(), forced_off(), forced_off(),
                         forced_off(), forced_off(), forced_off(), forced_off()};
}

// Assert every one of the twelve resolved bools equals `v`.
void expect_all(const TxServeResolution& r, bool v)
{
    EXPECT_EQ(r.serve_mempool_txs,      v);
    EXPECT_EQ(r.tx_serve_own_set,       v);
    EXPECT_EQ(r.mempool_ingest,         v);
    EXPECT_EQ(r.ingest_isdlock,         v);
    EXPECT_EQ(r.ingest_dstx,            v);
    EXPECT_EQ(r.embedded_mainnet,       v);
    EXPECT_EQ(r.embedded_utxo,          v);
    EXPECT_EQ(r.null_arm,               v);
    EXPECT_EQ(r.superblock,             v);
    EXPECT_EQ(r.include_mn_special_txs, v);
    EXPECT_EQ(r.accrue_asset_locks,     v);
    EXPECT_EQ(r.accrue_asset_unlocks,   v);
}

} // namespace

// ── dashd-armed posture: the resolver is an identity on the requested set ──

TEST(DashGoodCitizenDefaults, DashdArmedAllDefaultStaysAllOff)
{
    const TxServeResolution r =
        resolve_good_citizen_tx_serve(/*daemonless=*/false, all_default());
    expect_all(r, false);
    EXPECT_FALSE(r.defaulted_any);
    EXPECT_FALSE(r.unsafe_serve_without_referee);
}

// The 7 new levers, dashd-armed, must stay byte-identical to what was asked.
TEST(DashGoodCitizenDefaults, DashdArmedStaysByteIdenticalForNewLevers)
{
    const TxServeResolution r =
        resolve_good_citizen_tx_serve(/*daemonless=*/false, all_default());
    EXPECT_FALSE(r.embedded_mainnet);        // no arm ⇒ dashd fallback, unchanged
    EXPECT_FALSE(r.embedded_utxo);
    EXPECT_FALSE(r.null_arm);
    EXPECT_FALSE(r.superblock);
    EXPECT_FALSE(r.include_mn_special_txs);
    EXPECT_FALSE(r.accrue_asset_locks);
    EXPECT_FALSE(r.accrue_asset_unlocks);
    EXPECT_FALSE(r.defaulted_any);
}

TEST(DashGoodCitizenDefaults, DashdArmedExplicitOnIsHonoured)
{
    TxServeLevers req = all_default();
    req.serve_mempool_txs = on();
    req.tx_serve_own_set  = on();
    req.include_mn_special_txs = on();
    const TxServeResolution r =
        resolve_good_citizen_tx_serve(/*daemonless=*/false, req);
    EXPECT_TRUE(r.serve_mempool_txs);
    EXPECT_TRUE(r.tx_serve_own_set);
    EXPECT_TRUE(r.include_mn_special_txs);
    EXPECT_FALSE(r.mempool_ingest);   // not requested, not defaulted
    EXPECT_FALSE(r.superblock);
    EXPECT_FALSE(r.defaulted_any);
    EXPECT_FALSE(r.unsafe_serve_without_referee);
}

TEST(DashGoodCitizenDefaults, DashdArmedExplicitOffStaysOff)
{
    TxServeLevers req = all_default();
    req.mempool_ingest = forced_off();
    const TxServeResolution r =
        resolve_good_citizen_tx_serve(/*daemonless=*/false, req);
    EXPECT_FALSE(r.mempool_ingest);
    EXPECT_FALSE(r.defaulted_any);
}

// ── daemonless posture: FULL serving is the default ────────────────────────

TEST(DashGoodCitizenDefaults, DaemonlessAllDefaultArmsEverythingDashdWouldServe)
{
    const TxServeResolution r =
        resolve_good_citizen_tx_serve(/*daemonless=*/true, all_default());
    expect_all(r, true);               // all TWELVE levers arm
    EXPECT_TRUE(r.defaulted_any);
    EXPECT_FALSE(r.unsafe_serve_without_referee);
}

// REGRESSION WITNESS (the point of the whole change): the resolved daemonless
// default arms the embedded ARM and implies discovery — a bare `--run` serves.
TEST(DashGoodCitizenDefaults, DaemonlessBareRunResolvesEmbeddedEligibleWithDiscovery)
{
    const TxServeResolution r =
        resolve_good_citizen_tx_serve(/*daemonless=*/true, all_default());
    ASSERT_TRUE(r.embedded_mainnet);

    // Bare `--run`: no --testnet, no pinned peer, no explicit discovery.
    const dash::coin::ArmResolution arm =
        dash::coin::resolve_embedded_arm(dash::coin::ArmInputs{
            /*testnet=*/false, /*embedded_mainnet=*/r.embedded_mainnet,
            /*coin_p2p_connect=*/false, /*coin_p2p_discover=*/false});
    EXPECT_EQ(arm.arm, dash::coin::WorkArm::EmbeddedEligible);
    EXPECT_EQ(arm.reason, dash::coin::ArmReason::Armed);
    EXPECT_TRUE(arm.embedded_arm_enabled);
    EXPECT_TRUE(arm.coin_feed_armed);
    EXPECT_TRUE(arm.discover_implied);   // daemonless syncs itself
}

// The "before" this witness pins: the pre-flip default (embedded_mainnet OFF)
// produced NO WORK on a bare `--run` — DashdFallback with no opt-in.
TEST(DashGoodCitizenDefaults, BeforeWitness_LegacyDefaultsProducedNoWork)
{
    const dash::coin::ArmResolution arm =
        dash::coin::resolve_embedded_arm(dash::coin::ArmInputs{
            /*testnet=*/false, /*embedded_mainnet=*/false,
            /*coin_p2p_connect=*/false, /*coin_p2p_discover=*/false});
    EXPECT_EQ(arm.arm, dash::coin::WorkArm::DashdFallback);
    EXPECT_EQ(arm.reason, dash::coin::ArmReason::NoOptIn);
    EXPECT_FALSE(arm.embedded_arm_enabled);
    EXPECT_FALSE(arm.coin_feed_armed);
}

TEST(DashGoodCitizenDefaults, DaemonlessExplicitOnIsNotCountedAsDefaulted)
{
    const TxServeResolution r =
        resolve_good_citizen_tx_serve(/*daemonless=*/true, all_on());
    expect_all(r, true);
    EXPECT_FALSE(r.defaulted_any);     // nothing was defaulted — all explicit
    EXPECT_FALSE(r.unsafe_serve_without_referee);
}

TEST(DashGoodCitizenDefaults, DaemonlessSingleOptOutKeepsTheRestOn)
{
    TxServeLevers req = all_default();
    req.ingest_dstx = forced_off();
    const TxServeResolution r =
        resolve_good_citizen_tx_serve(/*daemonless=*/true, req);
    EXPECT_TRUE(r.serve_mempool_txs);
    EXPECT_TRUE(r.tx_serve_own_set);
    EXPECT_TRUE(r.mempool_ingest);
    EXPECT_TRUE(r.ingest_isdlock);
    EXPECT_FALSE(r.ingest_dstx);       // the one opt-out
    EXPECT_TRUE(r.embedded_mainnet);   // the rest still arm
    EXPECT_TRUE(r.include_mn_special_txs);
    EXPECT_TRUE(r.superblock);
    EXPECT_TRUE(r.defaulted_any);
    EXPECT_FALSE(r.unsafe_serve_without_referee);
}

// Opting OUT of superblock serving must not disarm the mempool lane.
TEST(DashGoodCitizenDefaults, SuperblockOptOutStillLeavesMempoolOn)
{
    TxServeLevers req = all_default();
    req.superblock = forced_off();
    const TxServeResolution r =
        resolve_good_citizen_tx_serve(/*daemonless=*/true, req);
    EXPECT_FALSE(r.superblock);
    EXPECT_TRUE(r.serve_mempool_txs);
    EXPECT_TRUE(r.mempool_ingest);
    EXPECT_TRUE(r.embedded_mainnet);   // still arms — superblock heights just
                                       // refuse as they do today
    EXPECT_TRUE(r.defaulted_any);
}

// Per-lever opt-out for each of the 7 new levers.
TEST(DashGoodCitizenDefaults, EachNewLeverOptsOutIndependently)
{
    {
        TxServeLevers req = all_default();
        req.embedded_mainnet = forced_off();
        const auto r = resolve_good_citizen_tx_serve(true, req);
        EXPECT_FALSE(r.embedded_mainnet);
        EXPECT_TRUE(r.embedded_utxo);
    }
    {
        TxServeLevers req = all_default();
        req.embedded_utxo = forced_off();
        const auto r = resolve_good_citizen_tx_serve(true, req);
        EXPECT_FALSE(r.embedded_utxo);
        EXPECT_TRUE(r.embedded_mainnet);
    }
    {
        TxServeLevers req = all_default();
        req.null_arm = forced_off();
        const auto r = resolve_good_citizen_tx_serve(true, req);
        EXPECT_FALSE(r.null_arm);
        EXPECT_TRUE(r.serve_mempool_txs);
    }
    {
        TxServeLevers req = all_default();
        req.include_mn_special_txs = forced_off();
        const auto r = resolve_good_citizen_tx_serve(true, req);
        EXPECT_FALSE(r.include_mn_special_txs);
        EXPECT_TRUE(r.serve_mempool_txs);
    }
    {
        TxServeLevers req = all_default();
        req.accrue_asset_locks = forced_off();
        const auto r = resolve_good_citizen_tx_serve(true, req);
        EXPECT_FALSE(r.accrue_asset_locks);
        EXPECT_TRUE(r.accrue_asset_unlocks);
    }
    {
        TxServeLevers req = all_default();
        req.accrue_asset_unlocks = forced_off();
        const auto r = resolve_good_citizen_tx_serve(true, req);
        EXPECT_FALSE(r.accrue_asset_unlocks);
        EXPECT_TRUE(r.accrue_asset_locks);
    }
}

TEST(DashGoodCitizenDefaults, DaemonlessFullOptOutRestoresCoinbaseOnly)
{
    const TxServeResolution r =
        resolve_good_citizen_tx_serve(/*daemonless=*/true, all_forced_off());
    expect_all(r, false);
    EXPECT_FALSE(r.defaulted_any);
    EXPECT_FALSE(r.unsafe_serve_without_referee);  // no fee-carrying serve

    // And with embedded_mainnet forced off, the arm falls back to dashd — the
    // operator asked for the legacy posture and got it.
    const dash::coin::ArmResolution arm =
        dash::coin::resolve_embedded_arm(dash::coin::ArmInputs{
            false, r.embedded_mainnet, false, false});
    EXPECT_EQ(arm.arm, dash::coin::WorkArm::DashdFallback);
}

// ── the unsafe corner is named, and unreachable via defaults ───────────────

TEST(DashGoodCitizenDefaults, DaemonlessRefereeOptOutWithServingOnIsNamedUnsafe)
{
    TxServeLevers req = all_default();
    req.tx_serve_own_set = forced_off();   // operator disarms the referee...
    const TxServeResolution r =
        resolve_good_citizen_tx_serve(/*daemonless=*/true, req);
    EXPECT_TRUE(r.serve_mempool_txs);      // ...while serving still defaults ON
    EXPECT_FALSE(r.tx_serve_own_set);
    EXPECT_TRUE(r.unsafe_serve_without_referee);
}

TEST(DashGoodCitizenDefaults, DaemonlessServeOptOutIsNotUnsafe)
{
    TxServeLevers req = all_default();
    req.serve_mempool_txs = forced_off();
    const TxServeResolution r =
        resolve_good_citizen_tx_serve(/*daemonless=*/true, req);
    EXPECT_FALSE(r.serve_mempool_txs);
    EXPECT_TRUE(r.tx_serve_own_set);       // referee stays armed (harmless)
    EXPECT_FALSE(r.unsafe_serve_without_referee);
}

TEST(DashGoodCitizenDefaults, ExplicitOffBeatsExplicitOn)
{
    // Both spellings on one command line: the opt-out wins (fail-safe).
    TxServeLevers req = all_default();
    req.serve_mempool_txs = TxServeLever{true, true};
    const TxServeResolution r =
        resolve_good_citizen_tx_serve(/*daemonless=*/true, req);
    EXPECT_FALSE(r.serve_mempool_txs);
}
