// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// #738 — which template arm a `--run` invocation resolves to, as ONE pure,
/// testable function.
///
/// THE DEFECT THIS CLOSES
/// ---------------------
/// Taking the embedded (daemonless) template arm needs TWO independent
/// conditions, and before this header NO SINGLE FLAG satisfied both:
///
///   (1) the work-source arm gate — DASHWorkSource only consults the embedded
///       bundle when `is_testnet_ || embedded_mainnet_` (work_source.cpp
///       get_work / resource_template_now). On mainnet that means
///       `--embedded-mainnet`.
///   (2) a live coin-state FEED — NodeCoinState::populated() only flips once
///       CoinStateMaintainer publishes a tip, and the maintainer + header chain
///       + ingest legs are constructed ONLY inside main_dash's `if (coin_p2p)`
///       block, i.e. only when `--coin-p2p-connect` / `--coin-p2p-discover`
///       built a CoinClient.
///
/// `--embedded-mainnet` satisfied (1) but not (2): with no coin-P2P flag the
/// bundle was never fed, populated() stayed false forever, and every template
/// came off the dashd fallback. `--coin-p2p-connect` satisfied (2) but not (1).
/// So the whole daemonless stack was unreachable from any documented
/// invocation. This resolver makes the EMBEDDED OPT-IN imply its own feed, so
/// one flag arms both halves end to end.
///
/// ★ REWARD-SAFETY INVARIANT (hotel incident: `--coin-p2p-connect` once
/// activated an unguarded embedded arm on a live production node) ★
/// The implication is ONE-WAY and runs only in the safe direction:
///
///     embedded opt-in  =>  coin-state feed        (NEW — this is the wiring)
///     coin-state feed  =>  embedded opt-in        (NEVER — explicitly not)
///
/// A transport flag can therefore never flip the arm. `--coin-p2p-connect`
/// alone on mainnet still resolves DashdFallback, exactly as today, and a bare
/// `--run` touches none of this. Both are pinned by tests.
///
/// STRICTLY single-coin (src/impl/dash only) and dependency-free: no I/O, no
/// core reach, no allocation. main_dash.cpp is the sole production caller.

namespace dash {
namespace coin {

/// Which arm a `--run` invocation resolves to. "EmbeddedEligible" means the
/// arm is ARMED, not that it will serve: every per-template viability gate
/// (SML fresh at tip, non-superblock height, credit-pool seed height, bestCL,
/// MN-payee cursor, DKG plan completeness) still fails closed to the dashd
/// fallback on the hot path. This is the outer, invocation-level decision only.
enum class WorkArm {
    DashdFallback,      ///< retained dashd getblocktemplate RPC arm (reward-safe default)
    EmbeddedEligible,   ///< daemonless embedded arm armed AND fed
};

/// Why the resolution came out the way it did — the operator-facing diagnosis
/// for the startup banner, and the assertion handle for the tests.
enum class ArmReason {
    NoOptIn,           ///< mainnet, no --embedded-mainnet: the default posture
    MainnetGateOff,    ///< a coin-P2P feed was requested but the arm was NOT opted in
    NoCoinStateFeed,   ///< the arm is enabled but nothing feeds NodeCoinState
    Armed,             ///< arm enabled AND fed
};

/// The invocation-level inputs, straight off argv.
struct ArmInputs {
    bool testnet           = false;  ///< --testnet / --regtest
    bool embedded_mainnet  = false;  ///< --embedded-mainnet (the embedded opt-in)
    bool coin_p2p_connect  = false;  ///< at least one --coin-p2p-connect HOST:PORT
    bool coin_p2p_discover = false;  ///< --coin-p2p-discover
};

struct ArmResolution {
    WorkArm   arm    = WorkArm::DashdFallback;
    ArmReason reason = ArmReason::NoOptIn;

    /// Construct the CoinClient + HeaderChain + CoinStateMaintainer + ingest
    /// legs? (main_dash's `if (coin_p2p)` block.)
    bool coin_feed_armed = false;

    /// Turn on seed-based peer discovery because the embedded opt-in was given
    /// with no pinned peer — the daemonless posture needs somewhere to sync
    /// from. False whenever the operator named peers or asked for discovery
    /// themselves.
    bool discover_implied = false;

    /// The work-source gate: DASHWorkSource::set_embedded_mainnet / is_testnet.
    bool embedded_arm_enabled = false;
};

/// Pure resolution. No hidden state, no ordering dependence.
inline ArmResolution resolve_embedded_arm(const ArmInputs& in)
{
    ArmResolution r;

    // Half (1): the arm gate. Byte-identical to the predicate DASHWorkSource
    // applies internally (`is_testnet_ || embedded_mainnet_`), so the two
    // halves cannot drift.
    r.embedded_arm_enabled = in.testnet || in.embedded_mainnet;

    // Half (2): the feed. An operator-named transport (pinned peers or explicit
    // discovery) arms it, exactly as before.
    const bool explicit_feed = in.coin_p2p_connect || in.coin_p2p_discover;

    // ★ The one-way implication. ONLY the embedded opt-in may imply a feed, and
    // only when the operator named no transport of their own. The converse is
    // deliberately absent: no transport flag ever sets embedded_arm_enabled.
    r.discover_implied = in.embedded_mainnet && !explicit_feed;
    r.coin_feed_armed  = explicit_feed || r.discover_implied;

    if (!r.embedded_arm_enabled) {
        // Mainnet with no opt-in. A requested feed still runs (block relay,
        // witness) but cannot move the arm — the hotel-incident invariant.
        r.arm    = WorkArm::DashdFallback;
        r.reason = explicit_feed ? ArmReason::MainnetGateOff : ArmReason::NoOptIn;
    } else if (!r.coin_feed_armed) {
        // Reachable for a bare `--testnet` (arm enabled by network, no feed
        // requested and none implied, because --embedded-mainnet is what
        // implies one). Unchanged behaviour.
        r.arm    = WorkArm::DashdFallback;
        r.reason = ArmReason::NoCoinStateFeed;
    } else {
        r.arm    = WorkArm::EmbeddedEligible;
        r.reason = ArmReason::Armed;
    }
    return r;
}

inline const char* arm_name(WorkArm a)
{
    switch (a) {
        case WorkArm::EmbeddedEligible: return "embedded";
        case WorkArm::DashdFallback:    break;
    }
    return "dashd-fallback";
}

inline const char* arm_reason_text(ArmReason r)
{
    switch (r) {
        case ArmReason::NoOptIn:
            return "no --embedded-mainnet (default reward-safe posture)";
        case ArmReason::MainnetGateOff:
            return "coin-P2P feed requested but --embedded-mainnet absent "
                   "(transport only; the arm never follows the transport)";
        case ArmReason::NoCoinStateFeed:
            return "embedded arm enabled but no coin-state feed "
                   "(--coin-p2p-connect / --coin-p2p-discover / --embedded-mainnet)";
        case ArmReason::Armed:
            break;
    }
    return "embedded opt-in + coin-state feed both present "
           "(per-template viability gates still fail closed to dashd)";
}

}  // namespace coin
}  // namespace dash
