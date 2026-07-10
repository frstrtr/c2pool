// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// DGB+DOGE (phase DC) — broadcast-path single-fire proof KAT.
//
// Fenced / test-only. Positively PROVES the integrator's HARD precondition for
// any DC live-wire (UID2478): the submitauxblock RPC fallback cannot double-
// fire the same DOGE block hash alongside the embedded submit path. Proven two
// ways that together cover the race:
//   (A) ELECTION returns exactly one carrier per won block (never both), with
//       embedded primary / RPC fallback ordering (mirrors aux_chain_embedded
//       .hpp submit_block-primary / submit_aux_block-fallback roles).
//   (B) the idempotent LEDGER suppresses any second broadcast of an already-
//       fired hash, regardless of path — so a retry or both-paths-attempted
//       race yields exactly ONE network broadcast.
//
// Non-circular: every golden is restated by value here. Pure helpers; links
// only core (uint256). Consumes nothing in src/impl/doge, touches no node seam.
// MUST appear in BOTH test/CMakeLists.txt AND the build.yml --target allowlist
// (#143 NOT_BUILT sentinel trap).
// ---------------------------------------------------------------------------

#include <gtest/gtest.h>

#include <impl/dgb/coin/aux_broadcast_path_election.hpp>
#include <core/uint256.hpp>

using dgb::coin::AuxBroadcastPath;
using dgb::coin::AuxBroadcastLedger;
using dgb::coin::elect_aux_broadcast_path;
using dgb::coin::elect_and_claim;

namespace {
uint256 H(uint64_t n) { uint256 h; h.SetNull(); *h.begin() = static_cast<uint8_t>(n & 0xff); *(h.begin() + 1) = static_cast<uint8_t>((n >> 8) & 0xff); return h; }
}

// ---- (A) ELECTION truth table: exactly one carrier per won block -----------

// No win -> no carrier on EITHER path, whatever the carrier availability.
TEST(DGB_AuxBroadcastElection, NoWinNeverFires) {
    for (int e = 0; e < 2; ++e)
        for (int r = 0; r < 2; ++r)
            EXPECT_EQ(elect_aux_broadcast_path(/*win*/false, e, r),
                      AuxBroadcastPath::None);
}

// Win + embedded relay available -> ALWAYS embedded (primary), even if RPC is
// also available. This is the core mutual-exclusion: RPC is never co-selected.
TEST(DGB_AuxBroadcastElection, EmbeddedIsPrimaryWhenAvailable) {
    EXPECT_EQ(elect_aux_broadcast_path(true, /*emb*/true, /*rpc*/true),
              AuxBroadcastPath::EmbeddedSubmitBlock);
    EXPECT_EQ(elect_aux_broadcast_path(true, /*emb*/true, /*rpc*/false),
              AuxBroadcastPath::EmbeddedSubmitBlock);
}

// Win + no embedded relay + RPC available -> RPC fallback (and ONLY then).
TEST(DGB_AuxBroadcastElection, RpcOnlyAsFallback) {
    EXPECT_EQ(elect_aux_broadcast_path(true, /*emb*/false, /*rpc*/true),
              AuxBroadcastPath::RpcSubmitAuxBlock);
}

// Win + no carrier at all -> None (cannot fabricate a broadcast).
TEST(DGB_AuxBroadcastElection, NoCarrierNoFire) {
    EXPECT_EQ(elect_aux_broadcast_path(true, /*emb*/false, /*rpc*/false),
              AuxBroadcastPath::None);
}

// Exhaustive: across the full 2x2x2 input cube the result is a single enum
// value — there is structurally no input that yields "both paths".
TEST(DGB_AuxBroadcastElection, ResultIsAlwaysSinglePath) {
    for (int w = 0; w < 2; ++w)
      for (int e = 0; e < 2; ++e)
        for (int r = 0; r < 2; ++r) {
            AuxBroadcastPath p = elect_aux_broadcast_path(w, e, r);
            const bool is_embedded = (p == AuxBroadcastPath::EmbeddedSubmitBlock);
            const bool is_rpc      = (p == AuxBroadcastPath::RpcSubmitAuxBlock);
            EXPECT_FALSE(is_embedded && is_rpc);  // never both
            if (!w) EXPECT_FALSE(is_embedded || is_rpc);
        }
}

// ---- (B) idempotent LEDGER: one broadcast per distinct hash ----------------

TEST(DGB_AuxBroadcastLedger, FirstFireFreshSecondSuppressed) {
    AuxBroadcastLedger ledger;
    const uint256 h = H(0xABCD);
    EXPECT_FALSE(ledger.already_fired(h));
    EXPECT_TRUE (ledger.try_fire(h));   // first authorization
    EXPECT_TRUE (ledger.already_fired(h));
    EXPECT_FALSE(ledger.try_fire(h));   // double-fire suppressed
    EXPECT_FALSE(ledger.try_fire(h));   // and stays suppressed
}

TEST(DGB_AuxBroadcastLedger, DistinctHashesAreIndependent) {
    AuxBroadcastLedger ledger;
    EXPECT_TRUE(ledger.try_fire(H(1)));
    EXPECT_TRUE(ledger.try_fire(H(2)));
    EXPECT_FALSE(ledger.try_fire(H(1)));  // h1 already fired
    EXPECT_TRUE(ledger.try_fire(H(3)));
}

// ---- (A)+(B) end-to-end single-fire: both paths race the SAME hash ---------

// The integrator's exact scenario: the same won DOGE block is attempted via the
// embedded path AND the RPC fallback. elect_and_claim authorizes exactly ONE;
// the second attempt (different carrier availability, same hash) yields None.
TEST(DGB_AuxBroadcastSingleFire, EmbeddedThenRpcSameHashFiresOnce) {
    AuxBroadcastLedger ledger;
    const uint256 won = H(0x5151);

    // Embedded path wins the election and claims the hash.
    EXPECT_EQ(elect_and_claim(ledger, won, /*win*/true, /*emb*/true, /*rpc*/true),
              AuxBroadcastPath::EmbeddedSubmitBlock);

    // RPC fallback later attempts the SAME hash (e.g. daemon retry) — suppressed.
    EXPECT_EQ(elect_and_claim(ledger, won, /*win*/true, /*emb*/false, /*rpc*/true),
              AuxBroadcastPath::None);
}

// Symmetric: RPC fires first, embedded retry suppressed — order-independent.
TEST(DGB_AuxBroadcastSingleFire, RpcThenEmbeddedSameHashFiresOnce) {
    AuxBroadcastLedger ledger;
    const uint256 won = H(0x6262);

    EXPECT_EQ(elect_and_claim(ledger, won, /*win*/true, /*emb*/false, /*rpc*/true),
              AuxBroadcastPath::RpcSubmitAuxBlock);
    EXPECT_EQ(elect_and_claim(ledger, won, /*win*/true, /*emb*/true, /*rpc*/true),
              AuxBroadcastPath::None);
}

// A no-win claim never consumes the ledger, so a later genuine win still fires.
TEST(DGB_AuxBroadcastSingleFire, NoWinDoesNotBurnTheHash) {
    AuxBroadcastLedger ledger;
    const uint256 h = H(0x7777);
    EXPECT_EQ(elect_and_claim(ledger, h, /*win*/false, true, true),
              AuxBroadcastPath::None);
    EXPECT_FALSE(ledger.already_fired(h));               // not recorded
    EXPECT_EQ(elect_and_claim(ledger, h, /*win*/true, true, true),
              AuxBroadcastPath::EmbeddedSubmitBlock);     // genuine win still fires
}