// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// src/impl/xmr/pathb/test/pathb_kat_branch_view.hpp
// An in-memory IBranchView for the S3 KATs: Monero blocks by id on every
// branch, and the weight inputs a follower holds after a block, with the base
// reward B = base_reward_at(already_generated_coins after the block, hf).
// ---------------------------------------------------------------------------
#pragma once

#include <cstdint>
#include <map>
#include <optional>

#include "impl/xmr/pathb/pathb_branch.hpp"
#include "impl/xmr/pathb/pathb_emission.hpp"

namespace pathb_kat {

namespace pbv = ::c2pool::xmr::pathb;

// Block id: branch tag, height (LE64), fixed tail byte.
inline pbv::Hash32 block_id(std::uint8_t tag, std::uint64_t h) {
    pbv::Hash32 id{};
    id[0] = tag;
    for (int i = 0; i < 8; ++i) id[1 + i] = static_cast<std::uint8_t>(h >> (8 * i));
    id[31] = 0xB7;
    return id;
}

class KatBranchView final : public pbv::IBranchView {
public:
    std::map<pbv::Hash32, pbv::BranchBlock> blocks;
    std::map<pbv::Hash32, pbv::WeightInputs> weights;

    std::optional<pbv::BranchBlock> block(const pbv::Hash32& id) const override {
        auto it = blocks.find(id);
        if (it == blocks.end()) return std::nullopt;
        return it->second;
    }
    std::optional<pbv::WeightInputs> weights_at(const pbv::Hash32& id) const override {
        auto it = weights.find(id);
        if (it == weights.end()) return std::nullopt;
        return it->second;
    }

    // Append block (tag, h) on `parent` with difficulty `diff`, timestamp `ts`,
    // and the follower's weight inputs after it: B from `agc`, fee median `m`,
    // zone `z`.
    pbv::Hash32 add(std::uint8_t tag, std::uint64_t h, const pbv::Hash32& parent, std::uint64_t ts,
                    std::uint64_t diff, std::uint64_t agc, std::uint64_t m, std::uint64_t z) {
        pbv::BranchBlock b;
        b.id = block_id(tag, h);
        b.prev_id = parent;
        b.height = h;
        b.timestamp = ts;
        pbv::U128 prev_cum{};
        if (h > 0) prev_cum = blocks.at(parent).cumulative_difficulty;
        b.cumulative_difficulty = ::c2pool::xmr::native::u128_add(prev_cum, pbv::U128{diff, 0});
        blocks[b.id] = b;
        weights[b.id] = pbv::WeightInputs{pbv::base_reward_at(agc, 16), m, z, z / 2};
        return b.id;
    }
};

}  // namespace pathb_kat
