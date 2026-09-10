// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/native/contracts/parity.hpp
//
// C6: the monerod-parity oracle interface. The native node may only be trusted
// to serve on its own after the oracle has GRADUATED it against a real monerod,
// and graduation is revocable at any time by a single disagreeing sample.
//
// Two rules carried over from the DASH shadow-compare incident and kept here as
// part of the contract, not as advice:
//   * coverage is a MEASUREMENT, never a gate -- a probe that produced no
//     samples must report NoSamples and must never be read as agreement;
//   * every probe runs off the hot path, coalesced, and a probe failure can
//     never affect what is served.
// ---------------------------------------------------------------------------
#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "types.hpp"
#include "miner_data.hpp"

namespace c2pool::xmr::native {

// Which probe produced a sample.
enum class ProbeKind : std::uint8_t { Tip = 0, Template = 1, Submit = 2 };

// What kind of height the sample was taken at; a diff at an epoch edge or a
// reorg means something different from a diff in the steady state.
enum class HeightClass : std::uint8_t {
    Steady = 0,
    EpochEdge,     // RandomX seed rollover within the 64-block lag
    Reorg,
    HardForkEdge,
    PenaltyZone,   // block weight above the effective median
};

// One field that differed between the served arm and the shadow arm.
struct FieldDiff {
    std::string field;
    std::string served;   // rendered value from the arm that served
    std::string shadow;   // rendered value from the arm that shadowed
};

enum class ParityVerdict : std::uint8_t {
    // The sample could not be judged (one arm had no data, or the alignment key
    // did not match). NOT agreement.
    Void = 0,
    Clean,
    Fail,
    // The arms agreed on the comparable fields but what we actually SERVED did
    // not match either -- the worst case, and it is its own verdict.
    ServedMismatch,
};

struct ParitySample {
    ProbeKind                kind = ProbeKind::Tip;
    std::uint64_t            height = 0;
    Hash                     prev_id{};
    std::vector<FieldDiff>   fields;
    ParityVerdict            verdict = ParityVerdict::Void;
    std::vector<HeightClass> classes;
    std::string              note;
};

// Graduation is keyed so that changing ANY of the four keys drops the node back
// to ungraduated: a new c2pool commit, a new comparator version, a different
// monerod version, or a different network is a different experiment.
struct GraduationKey {
    std::string c2pool_commit;
    std::uint32_t comparator_version = 1;
    std::string monerod_version;
    std::string net;   // "mainnet" / "stagenet" / "testnet" / "regtest"
};

enum class GraduationState : std::uint8_t {
    Ungraduated = 0,
    Observing,
    Graduated,
    Revoked,
};

inline const char* to_string(GraduationState g) noexcept {
    switch (g) {
        case GraduationState::Ungraduated: return "Ungraduated";
        case GraduationState::Observing:   return "Observing";
        case GraduationState::Graduated:   return "Graduated";
        case GraduationState::Revoked:     return "Revoked";
    }
    return "?";
}

// Coverage counters. `no_samples_streak` is the heartbeat: a probe that has
// produced nothing for a long time is an alarm, not a pass.
struct ParityCoverage {
    std::uint64_t samples           = 0;
    std::uint64_t clean             = 0;
    std::uint64_t fail              = 0;
    std::uint64_t served_mismatch   = 0;
    std::uint64_t voided            = 0;
    std::uint64_t epoch_edges_seen  = 0;
    std::uint64_t reorgs_seen       = 0;
    std::uint64_t no_samples_streak = 0;
};

class IParityOracle {
public:
    virtual ~IParityOracle() = default;

    // P-TIP: a tip moved on one of the two arms. `side` names the arm.
    virtual void on_tip(const node::MainchainEvent&, const char* side) = 0;

    // P-TPL: a template was served. Enqueue-only; the comparison itself runs
    // off the serving thread so a slow oracle can never slow a share.
    virtual void on_serve(const MinerDataEpoch&, const char* served_arm) = 0;

    // P-SUB: a found block was relayed and its arms reported back.
    virtual void on_submit(const Hash& block_id, bool daemon_accepted,
                           std::size_t p2p_peers_sent) = 0;

    virtual GraduationState state() const = 0;
    virtual ParityCoverage  coverage() const = 0;

    // Drop out of Graduated immediately and permanently for this key.
    virtual void revoke(const std::string& why) = 0;
};

} // namespace c2pool::xmr::native
