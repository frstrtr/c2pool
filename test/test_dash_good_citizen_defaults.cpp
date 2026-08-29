// SPDX-License-Identifier: AGPL-3.0-or-later
//
// KAT for the daemonless good-citizen mempool-serving defaults
// (impl/dash/coin/good_citizen_defaults.hpp).
//
// The contract under test:
//   * dashd-ARMED posture (any of --coin-rpc/--coin-rpc-auth/--submit-block):
//     resolution is byte-identical to the requested flags — the default never
//     flips anything, existing deployments keep their served bytes.
//   * DAEMONLESS posture: every lever the operator did not spell out resolves
//     ON (serve the full mempool by default); an explicit --<flag>=false
//     opt-out wins; an explicit ON is honoured.
//   * The unsafe corner (fee-carrying serve with the serve-time referee
//     disarmed) is impossible via defaults and is NAMED when an explicit
//     opt-out creates it.

#include <gtest/gtest.h>

#include <impl/dash/coin/good_citizen_defaults.hpp>

using dash::coin::TxServeLever;
using dash::coin::TxServeLevers;
using dash::coin::TxServeResolution;
using dash::coin::resolve_good_citizen_tx_serve;

namespace {

TxServeLever off()          { return TxServeLever{false, false}; }
TxServeLever on()           { return TxServeLever{true,  false}; }
TxServeLever forced_off()   { return TxServeLever{false, true};  }

TxServeLevers all_default() { return TxServeLevers{off(), off(), off(), off(), off()}; }

} // namespace

// ── dashd-armed posture: the resolver is an identity on the requested set ──

TEST(DashGoodCitizenDefaults, DashdArmedAllDefaultStaysAllOff)
{
    const TxServeResolution r =
        resolve_good_citizen_tx_serve(/*daemonless=*/false, all_default());
    EXPECT_FALSE(r.serve_mempool_txs);
    EXPECT_FALSE(r.tx_serve_own_set);
    EXPECT_FALSE(r.mempool_ingest);
    EXPECT_FALSE(r.ingest_isdlock);
    EXPECT_FALSE(r.ingest_dstx);
    EXPECT_FALSE(r.defaulted_any);
    EXPECT_FALSE(r.unsafe_serve_without_referee);
}

TEST(DashGoodCitizenDefaults, DashdArmedExplicitOnIsHonoured)
{
    TxServeLevers req = all_default();
    req.serve_mempool_txs = on();
    req.tx_serve_own_set  = on();
    const TxServeResolution r =
        resolve_good_citizen_tx_serve(/*daemonless=*/false, req);
    EXPECT_TRUE(r.serve_mempool_txs);
    EXPECT_TRUE(r.tx_serve_own_set);
    EXPECT_FALSE(r.mempool_ingest);   // not requested, not defaulted
    EXPECT_FALSE(r.defaulted_any);
    EXPECT_FALSE(r.unsafe_serve_without_referee);  // referee concern is the
                                                   // daemonless posture's
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

// ── daemonless posture: full-mempool serving is the default ────────────────

TEST(DashGoodCitizenDefaults, DaemonlessAllDefaultArmsFullMempoolServing)
{
    const TxServeResolution r =
        resolve_good_citizen_tx_serve(/*daemonless=*/true, all_default());
    EXPECT_TRUE(r.serve_mempool_txs);
    EXPECT_TRUE(r.tx_serve_own_set);   // referee armed WITH serving, always
    EXPECT_TRUE(r.mempool_ingest);
    EXPECT_TRUE(r.ingest_isdlock);
    EXPECT_TRUE(r.ingest_dstx);
    EXPECT_TRUE(r.defaulted_any);
    EXPECT_FALSE(r.unsafe_serve_without_referee);
}

TEST(DashGoodCitizenDefaults, DaemonlessExplicitOnIsNotCountedAsDefaulted)
{
    TxServeLevers req{on(), on(), on(), on(), on()};
    const TxServeResolution r =
        resolve_good_citizen_tx_serve(/*daemonless=*/true, req);
    EXPECT_TRUE(r.serve_mempool_txs);
    EXPECT_TRUE(r.tx_serve_own_set);
    EXPECT_TRUE(r.mempool_ingest);
    EXPECT_TRUE(r.ingest_isdlock);
    EXPECT_TRUE(r.ingest_dstx);
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
    EXPECT_TRUE(r.defaulted_any);
    EXPECT_FALSE(r.unsafe_serve_without_referee);
}

TEST(DashGoodCitizenDefaults, DaemonlessFullOptOutRestoresCoinbaseOnly)
{
    const TxServeLevers req{forced_off(), forced_off(), forced_off(),
                            forced_off(), forced_off()};
    const TxServeResolution r =
        resolve_good_citizen_tx_serve(/*daemonless=*/true, req);
    EXPECT_FALSE(r.serve_mempool_txs);
    EXPECT_FALSE(r.tx_serve_own_set);
    EXPECT_FALSE(r.mempool_ingest);
    EXPECT_FALSE(r.ingest_isdlock);
    EXPECT_FALSE(r.ingest_dstx);
    EXPECT_FALSE(r.defaulted_any);
    EXPECT_FALSE(r.unsafe_serve_without_referee);  // no fee-carrying serve
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
