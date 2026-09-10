// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/native/contracts/miner_data.hpp
//
// C4: the ONE seam the settlement template provider is rebound through. Two
// implementations land behind it -- one wrapping the existing monerod
// get_miner_data path, one built from IChainView + ITxpoolSnapshot -- and the
// option-B assembler above the seam is not modified at all.
//
// Readiness is FAIL-CLOSED and per-input: a source that cannot name every
// window it has must not serve a template. "Last good" is servable only while
// its prev_id still equals the tip.
// ---------------------------------------------------------------------------
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "types.hpp"

namespace c2pool::xmr::native {

// Identifies which template a snapshot belongs to, without copying it.
struct MinerDataEpoch {
    std::uint64_t height      = 0;
    Hash          prev_id{};
    std::uint64_t backlog_seq = 0;   // ITxpoolSnapshot::backlog_version()

    friend bool operator==(const MinerDataEpoch& a, const MinerDataEpoch& b) noexcept {
        return a.height == b.height && a.prev_id == b.prev_id && a.backlog_seq == b.backlog_seq;
    }
    friend bool operator!=(const MinerDataEpoch& a, const MinerDataEpoch& b) noexcept {
        return !(a == b);
    }
};

// One flag per chain-state input the template needs. ok() is the gate.
struct MinerDataReadiness {
    bool tip_known         = false;
    bool seed_reach        = false;  // seed (and next seed inside the lag) resolvable
    bool difficulty_window = false;  // full 735-row window available
    bool weight_window     = false;  // short + long-term weight windows available
    bool coins_known       = false;  // already_generated_coins carried forward
    bool hf_known          = false;  // major/minor version resolved and not fenced
    std::string why;                 // first missing input, for the log line

    bool ok() const noexcept {
        return tip_known && seed_reach && difficulty_window
            && weight_window && coins_known && hf_known;
    }
};

class IMinerDataSource {
public:
    virtual ~IMinerDataSource() = default;

    // "monerod" or "native"; appears in the settlement snapshot and in parity
    // samples so a diff can always be attributed to an arm.
    virtual const char* name() const = 0;

    virtual MinerDataReadiness readiness() const = 0;

    // Lock-free. The provider polls this and rebuilds only when it changes.
    virtual MinerDataEpoch epoch() const = 0;

    // nullopt when !readiness().ok(); `why` receives the reason when non-null.
    virtual std::optional<node::MinerData> snapshot(std::string* why) const = 0;

    // Body for a transaction the last snapshot selected, or nullptr. The
    // pointer stays valid until the next snapshot() on the same source.
    virtual const std::vector<std::uint8_t>* tx_body(const Hash&) const = 0;
};

// Which arm serves and which one shadows. The resolver falls back to the daemon
// arm when the native arm loses readiness, and says so loudly.
enum class TemplateArm : std::uint8_t { Monerod = 0, Native = 1 };

inline const char* to_string(TemplateArm a) noexcept {
    return a == TemplateArm::Native ? "native" : "monerod";
}

} // namespace c2pool::xmr::native
