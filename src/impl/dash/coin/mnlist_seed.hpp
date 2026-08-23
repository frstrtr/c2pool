// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// ── OPTIONAL, DEFAULT-OFF V20 getmnlistdiff SEED for the replay fold ───────
// (path-ii escape hatch for #154 — the pre-V20 rotated-quorum derivation)
//
// WHAT THIS IS, AND WHAT IT IS NOT
// ---------------------------------
// The #154 self-derive fold is from-DIP3 (h=1028160) forward: every block's
// computed merkleRootMNList is self-checked byte-exact against that block's
// own committed cbTx root, fail-closed on any mismatch. That pure from-DIP3
// path is THE DEFAULT and is fixed separately (a pre-v19 rotated-quorum
// ordering bug). NOTHING in this header runs unless the operator explicitly
// arms it, and when the flags are absent the from-DIP3 path is byte-identical
// to master.
//
// This header adds an ALTERNATIVE the operator may opt into for the
// checkpoint-GENERATION use case: instead of DERIVING the pre-V20 state, SEED
// the fold's DML from a dashd getmnlistdiff snapshot AT/AFTER the V20
// activation height (mainnet h=1'987'776) and walk V20+ only — sidestepping
// the pre-v19 rotated-derivation problem entirely. The tradeoff (a build-time
// dashd dependency for the generated .inc) is understood and accepted by the
// operator SPECIFICALLY BECAUSE this is optional and off by default.
//
// REWARD-SAFETY (the whole point)
// -------------------------------
// A seed is TRUSTED at exactly ONE height and PROGRESSIVELY FALSIFIABLE after
// it. Before a single block is folded forward, the seeded state must reproduce
// the chain's OWN committed merkleRootMNList at the seed height — that check is
// replay::seed_engine_from_prestate() (replay_prestate.hpp), reused verbatim
// here. A seed whose computed root != the committed root is not an anchor, it
// is a guess, and it is REJECTED. From H+1 onward the normal per-block
// byte-exact self-check continues unchanged, so the generated .inc remains
// oracle-verifiable at 2522504 exactly as a from-DIP3 fold's would be.
//
// WHY getmnlistdiff CAN verify the root (but a payee axis is separate)
// -------------------------------------------------------------------
// merkleRootMNList is CalcMerkleRoot over the DIP-4 SML entries
// (ReplayMNState::to_sml_entry): proRegTxHash, confirmedHash, service,
// pubKeyOperator, keyIDVoting, isValid, nType, platform*. Every one of those
// is carried by getmnlistdiff. scriptPayout / nLastPaidHeight are NOT in the
// SML leaf and NOT committed in merkleRootMNList — so for the merkleRootMNList
// proof the getmnlistdiff SML is sufficient and self-verifying. (The payee
// axis, which getmnlistdiff omits, is a SEPARATE concern handled by the
// protx-list prestate path and is not what the .inc is oracle-checked on.)
//
// FORMAT REUSE (do NOT reinvent)
// ------------------------------
// The materialized seed is the SAME text the W5 anchor prestate uses
// (replay_prestate.hpp's `c2pool-dash-replay-prestate/1`), so the SAME
// fail-closed 26-field parser and the SAME root-verification gate apply with
// no second parser to drift. The getmnlistdiff SML columns fill the SML
// fields; the payout columns are filled by the accompanying `protx list` (the
// accepted build-time dashd dependency). What THIS header adds over the plain
// prestate arm is purely the ARMING + GATING policy of the escape hatch:
//   * the source must be "getmnlistdiff" (an explicit, named provenance),
//   * the seed height must be >= the V20 activation floor (this is what makes
//     it a V20-only sidestep and not a general re-anchor), and
//   * the operator's declared --replay-mnlist-seed-height must match the
//     height the snapshot actually carries (no silent height drift).
//
// LIVE vs OFFLINE
// ---------------
// The live leg — fetch getmnlistdiff from the configured coin-p2p peer (e.g.
// the archival .165) at runtime — is SEQUENCED LATER on the operator's call
// (#154). For the CODE + KAT deliverable the snapshot is materialized to a
// FILE (--replay-mnlist-seed-file), which is the byte-for-byte offline twin of
// exactly what the peer's getmnlistdiff returns. The file path and the live
// path converge on the identical Prestate + identical root gate; only the
// transport differs.

#include <impl/dash/coin/replay_prestate.hpp>
#include <impl/dash/coin/vendor/quorum_members.hpp>   // kV20FloorMainnet/Testnet

#include <cstdint>
#include <string>

namespace dash {
namespace coin {
namespace replay {

/// The only accepted --replay-mnlist-seed-source value. An enum-of-one on
/// purpose: an unknown source is fail-closed, and a future source (e.g. a
/// signed checkpoint) is a NEW named token rather than a silent widening.
inline constexpr const char* kMnListSeedSourceGetMnListDiff = "getmnlistdiff";

/// The operator's arming request, straight off the CLI. DEFAULT = DISARMED:
/// a value-initialized request is inert and mnlist_seed_armed() is false, so
/// the from-DIP3 path is what runs.
struct MnListSeedRequest
{
    uint32_t    seed_height{0};   // --replay-mnlist-seed-height  (0 => disarmed)
    std::string source;           // --replay-mnlist-seed-source  ("getmnlistdiff")
    std::string file;             // --replay-mnlist-seed-file     (materialized snapshot)
    bool        testnet{false};   // mirrors the run's network
};

/// True iff the operator touched ANY of the escape-hatch flags. When false the
/// caller must NOT enter the seed path — the from-DIP3 default is unchanged.
inline bool mnlist_seed_armed(const MnListSeedRequest& r)
{
    return r.seed_height != 0 || !r.source.empty() || !r.file.empty();
}

/// The V20 activation floor for the request's network — the escape hatch may
/// only seed at or after it.
inline uint32_t mnlist_seed_v20_floor(bool testnet)
{
    return testnet ? vendor::kV20FloorTestnet : vendor::kV20FloorMainnet;
}

/// Validate the arming request and load the seed into a Prestate the EXISTING
/// wiring consumes. Every failure is fail-closed and NAMED via Prestate.ok /
/// Prestate.error. On success the returned Prestate is handed to the SAME
/// seed_engine_from_prestate() root gate the plain prestate arm uses — this
/// function does NOT seed anything itself, it only enforces the escape-hatch
/// policy and reuses the shared parser.
inline Prestate load_and_validate_mnlist_seed(const MnListSeedRequest& r)
{
    Prestate ps;
    auto fail = [&](const std::string& why) -> Prestate& {
        ps.ok = false;
        ps.error = why;
        return ps;
    };

    // (1) SOURCE — an unknown/blank provenance is never guessed.
    if (r.source != kMnListSeedSourceGetMnListDiff)
        return fail("--replay-mnlist-seed-source must be '"
                    + std::string(kMnListSeedSourceGetMnListDiff)
                    + "' (got '" + r.source + "')");

    // (2) HEIGHT — the escape hatch is height-driven by definition.
    if (r.seed_height == 0)
        return fail("--replay-mnlist-seed-height is required and must be > 0");

    // (3) THE V20 FLOOR — this is what makes the hatch a V20-only sidestep of
    //     the pre-v19 rotated derivation and NOT a general re-anchor. Seeding
    //     below it would silently re-introduce exactly the pre-V20 state this
    //     mode exists to avoid deriving.
    const uint32_t floor = mnlist_seed_v20_floor(r.testnet);
    if (r.seed_height < floor)
        return fail("--replay-mnlist-seed-height "
                    + std::to_string(r.seed_height)
                    + " is below the V20 activation floor "
                    + std::to_string(floor)
                    + " for this network — the getmnlistdiff escape hatch may"
                      " only seed at or after V20 (seed from DIP3 instead, the"
                      " default, for any earlier height)");

    // (4) TRANSPORT — the live coin-p2p getmnlistdiff fetch is sequenced later
    //     on the operator's call (#154); for now the snapshot is a file, the
    //     offline twin of the peer's reply. Absent a file we fail closed
    //     rather than silently do nothing.
    if (r.file.empty())
        return fail("--replay-mnlist-seed-file is required: the live coin-p2p"
                    " getmnlistdiff fetch is sequenced later (#154); supply the"
                    " materialized snapshot file for now");

    // (5) PARSE — reuse the shared, fail-closed prestate parser. No second
    //     parser exists to drift from consensus.
    ps = load_prestate_file(r.file);
    if (!ps.ok)
        return ps;   // error already NAMED by the shared parser

    // (6) HEIGHT MATCH — the operator's declared height must equal the height
    //     the snapshot actually carries. A mismatch means the peer/file
    //     answered for a different height than the operator asked to seed at,
    //     and pinning the forward lane to the wrong anchor+1 would fold the
    //     wrong first block. Fail closed.
    if (ps.height != r.seed_height)
        return fail("--replay-mnlist-seed-height " + std::to_string(r.seed_height)
                    + " does not match the snapshot's height "
                    + std::to_string(ps.height)
                    + " — the getmnlistdiff answered for a different height");

    // (7) NETWORK MATCH — a mainnet snapshot must not seed a testnet run or
    //     vice-versa (the floor in (3) is per-network).
    const std::string want = r.testnet ? "testnet" : "mainnet";
    if (ps.network != want)
        return fail("--replay-mnlist-seed source is network '" + ps.network
                    + "' but the run is '" + want + "'");

    // The committed-root gate itself is seed_engine_from_prestate(), run by the
    // caller exactly as the plain prestate arm does. ps.ok is true here only
    // in the sense that it PARSED and passed the arming policy; it is NOT yet
    // proven against the chain's committed root — that is the caller's next,
    // reused, fail-closed step.
    return ps;
}

} // namespace replay
} // namespace coin
} // namespace dash
