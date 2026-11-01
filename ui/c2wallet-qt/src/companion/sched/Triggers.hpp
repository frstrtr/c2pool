// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// Inject scheduler — trigger evaluation (design §4). Pure: the caller passes
// the tip it read, the current time and a parent lookup; nothing here talks
// to the node.
//
// An item is ready when EVERY enabled condition holds (all-of):
//   maturity           tip >= safe_from_height - 1 + slack (the next template
//                      is tip + 1; a coinbase created at h0 is spendable in
//                      block h0 + 100)
//   not_before_height  tip >= H
//   not_before_time    now >= T (the online host's UTC clock)
//   after_parent       each parent mined with tip - H + 1 >= N confirmations
// A height-based condition with the tip unknown (node not synced) waits.
// The `why` text lists the unmet conditions in the order maturity -> height ->
// time -> parents, each with an ETA (blocks at 2.6 min per block).

#include "InjectQueue.hpp"

#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <vector>

namespace c2w::companion::sched {

inline constexpr int64_t kSecondsPerBlock = 156; // 2.6 min, the DASH target spacing

struct ChainSnapshot {
    bool tip_known = false;
    int64_t tip = 0;
    std::string tip_unknown_why; // e.g. "tip unknown: node not synced (sync_blocked_by=...)"
};

struct ParentStatus {
    bool known = false;                 // a queue item or a tracked foreign txid
    bool mined = false;
    std::optional<int64_t> mined_height;
    bool height_unknown = false;        // mined, block outside the body window
    std::string state_text;             // e.g. "riding", "in the mempool", "not seen in a block yet"
};

using ParentLookup = std::function<ParentStatus(const std::string& txid)>;

enum class TriggerKind : uint8_t { Maturity, Height, Time, Parent };

struct Unmet {
    TriggerKind kind = TriggerKind::Maturity;
    std::string why;
    std::optional<int64_t> eta_blocks;
    std::optional<int64_t> eta_time; // unix seconds
};

struct Verdict {
    bool ready = false;
    std::vector<Unmet> unmet;
    std::string why() const; // "; "-joined unmet reasons (empty when ready)
};

Verdict evaluate(const Item& it, const ChainSnapshot& chain, int64_t now, const ParentLookup& parents);

// The lowest tip at which the maturity condition holds.
int64_t maturity_fire_tip(const MaturityTrigger& m);

// "~6 h 14 m" for 144 blocks; "~8 m" below an hour.
std::string format_eta_blocks(int64_t blocks);
std::string format_eta_seconds(int64_t seconds);

} // namespace c2w::companion::sched
