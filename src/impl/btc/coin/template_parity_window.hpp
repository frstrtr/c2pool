// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once
//
// §4.7 B6.2/B6.3 rolling-parity gate — bookkeeping SSOT.
//
// The live template-parity soak walks contiguous block heights and, for
// each, compares c2pool-btc's locally computed consensus fields (block
// subsidy, nBits) against the bitcoind oracle (getblock / getblocktemplate).
// This class holds the *oracle-independent* half of that gate: it decides
// WHEN the soak is GREEN given a stream of per-height match/mismatch
// verdicts. The RPC-fed driver (which needs the bitcoind snapshot rig,
// reference_btc_snapshot.md) reuses this exact predicate so the soak driver
// and its unit KAT share one definition of "green" — same SSOT shape as
// tip_reconcile_gate.hpp (merged PR #1291).
//
// GREEN semantics: the gate is green ONLY when a FULL window of `capacity`
// CONTIGUOUS heights have every one matched. A single divergence anywhere
// in the window holds the gate RED until that sample rolls out the back and
// `capacity` clean samples re-accumulate. A height gap (a skipped block)
// breaks the soak: you cannot claim N consecutive green having skipped one,
// so a non-contiguous height resets the window.

#include <cstddef>
#include <cstdint>
#include <deque>
#include <optional>

namespace btc::coin {

class RollingParityWindow {
public:
    static constexpr std::size_t kDefaultCapacity = 1000;  // §4.7 rolling-1000

    explicit RollingParityWindow(std::size_t capacity = kDefaultCapacity)
        : capacity_(capacity == 0 ? 1 : capacity) {}

    // Record one height's parity verdict. Heights are expected to arrive
    // monotonically and contiguously (height == prev + 1). A gap resets the
    // window — an unbroken run is the whole point of a soak gate.
    void record(uint32_t height, bool matched) {
        if (last_height_ && height != *last_height_ + 1) {
            window_.clear();
            mismatches_ = 0;
        }
        last_height_ = height;
        window_.push_back(Sample{height, matched});
        if (!matched) {
            ++mismatches_;
            last_mismatch_height_ = height;
        }
        while (window_.size() > capacity_) {
            if (!window_.front().matched) --mismatches_;
            window_.pop_front();
        }
    }

    // Green iff the window is full AND contains zero mismatches.
    bool is_green() const {
        return window_.size() >= capacity_ && mismatches_ == 0;
    }

    std::size_t capacity()   const { return capacity_; }
    std::size_t size()       const { return window_.size(); }
    std::size_t mismatches() const { return mismatches_; }
    std::optional<uint32_t> last_mismatch_height() const { return last_mismatch_height_; }

private:
    struct Sample { uint32_t height; bool matched; };
    std::size_t             capacity_;
    std::deque<Sample>      window_;
    std::size_t             mismatches_ = 0;
    std::optional<uint32_t> last_height_;
    std::optional<uint32_t> last_mismatch_height_;
};

}  // namespace btc::coin
