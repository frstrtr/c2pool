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
#include "relay.hpp"

namespace c2pool::xmr::native {

// Which probe produced a sample.
//
// CONTRACT AMENDMENT (M1). `Pool` is added to the three probes plan section
// 4.10 pinned. It is an addition, not a redefinition -- the three existing
// values keep their numbers, their seams and their field tables -- but it is a
// change to the FROZEN TABLE SET the comparator is keyed on, so
// parity::COMPARATOR_VERSION is bumped alongside it. That bump is the point: a
// node graduated under a comparator that never looked at the transaction pool
// must not inherit that clean streak into one that does.
//
// P-POOL is KEYED DIFFERENTLY from P-TIP and P-TPL, and the difference belongs
// here rather than in the implementation. A tip sample is one question at one
// height. A pool sample is a SET comparison: both arms are asked what their
// pool holds at the same tip, the per-transaction comparison runs over the
// INTERSECTION, and the two set differences are carried as MEASUREMENTS. The
// intersection is what can be judged; a difference is a fact about propagation
// timing, and scoring it as failure would make the seam fail on nothing worse
// than a transaction that had not reached us yet. What stops that from becoming
// the blind spot the DASH incident was is a separate, cumulative claim the
// probe keeps and the milestone is judged on: every id ever seen in the
// daemon's pool must eventually have been compared field by field. A set
// difference that never closes is therefore visible as an uncompared id, not as
// a clean sample.
enum class ProbeKind : std::uint8_t { Tip = 0, Template = 1, Submit = 2, Pool = 3 };

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
    //
    // CONTRACT NOTE (widened after the Wave 0 verify pass; plan section 4.10
    // writes on_serve(const SettlementSnapshot&)). SettlementSnapshot stays out
    // of contracts/ for the same reason BlockCandidate does -- it belongs to the
    // settlement layer above this family. But an epoch TAG alone is not enough,
    // and that projection would have cost C6 a rework:
    //
    //   P-TPL's claim is "the full_blob is byte-identical given the same
    //   backlog". With only an epoch, the oracle has to go back to the served
    //   arm and pull a fresh snapshot, which differs from the one that was
    //   actually served whenever the backlog moved in between. The
    //   ServedMismatch verdict -- the worst case, and the only one that catches
    //   us serving something neither arm would have produced -- then becomes
    //   unprovable, and P-TPL quietly degrades into a shadow-versus-shadow
    //   compare that can never fail for the reason it exists.
    //
    // So the served ARTEFACT is carried, in the value type both arms already
    // speak: node::MinerData. `served` must be exactly what went out, not a
    // re-read. The epoch stays as the alignment key.
    virtual void on_serve(const MinerDataEpoch&        epoch,
                          const node::MinerData&       served,
                          const char*                  served_arm) = 0;

    // P-SUB: a found block was relayed and its arms reported back.
    //
    // CONTRACT NOTE (same pass, same reason): the whole BlockRelayVerdict is
    // carried rather than three fields of it. Without daemon_armed the oracle
    // cannot tell "the daemon REJECTED our block", which is a real parity
    // failure, from "there was no daemon arm at all", which is a VOID sample --
    // and scoring the second as the first would revoke graduation on nothing.
    // landed_first and why are what makes a sample readable afterwards.
    virtual void on_submit(const BlockRelayVerdict&) = 0;

    virtual GraduationState state() const = 0;
    virtual ParityCoverage  coverage() const = 0;

    // Drop out of Graduated immediately and permanently for this key.
    virtual void revoke(const std::string& why) = 0;
};

} // namespace c2pool::xmr::native
