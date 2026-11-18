// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// v37_xmr_ring_partition_kat (pathb_ring.hpp): the partition at every depth.
// Keys and rows are scripted or generated under the TEST tags (pathb_kat_ring.hpp).
//   P1 every value of key byte 0 (bytes 1..31 fixed): at each depth 0..7 every key
//      is in exactly one ring, every ring is hit, each ring is the disjoint
//      union of its two children (child()), and child(r, bit) holds the keys
//      whose bit d is that bit.
//   P2 a fixed set of sealed rows (generated miners, each on two rows with two
//      generated owners): at each depth 0..7 every row is in exactly one ring,
//      rows of one miner share it, each ring is the disjoint union of its two
//      children; ring_of_entry on the same entries gives the same rings.
// Output: PASS / FAIL and case counts.
// ---------------------------------------------------------------------------
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <iterator>
#include <limits>
#include <optional>
#include <string>
#include <vector>

#include "impl/xmr/pathb/pathb_ring.hpp"
#include "pathb_kat_check.hpp"
#include "pathb_kat_ring.hpp"

using namespace pathb_kat;
using namespace pathb_kat::ring;

namespace {

constexpr std::uint32_t kChainA = 0x04030201u;  // four distinct bytes
constexpr std::uint8_t kBound = pb::kRingDepthBound;
// one key per value of a byte
constexpr std::size_t kByteValues = std::size_t{std::numeric_limits<std::uint8_t>::max()} + 1;

using Members = std::vector<std::vector<std::size_t>>;  // ring index -> member positions, ascending

// Places items 0..n-1 by ring_at(i) at depth d. Checks: each item gets a ring at depth d with
// index < 2^d, and lies in exactly one of the 2^d rings.
template <class RingAt>
Members place(std::size_t n, std::uint8_t d, RingAt ring_at, const std::string& what) {
    const std::size_t rings = std::size_t{1} << d;
    Members m(rings);
    std::vector<std::optional<pb::RingId>> got(n);
    for (std::size_t i = 0; i < n; ++i) {
        got[i] = ring_at(i);
        check(got[i] && got[i]->depth == d && got[i]->index < rings,
              what + ": item " + std::to_string(i) + " has a ring at depth " + std::to_string(d));
        if (got[i] && got[i]->index < rings) m[got[i]->index].push_back(i);
    }
    for (std::size_t i = 0; i < n; ++i) {
        std::size_t in = 0;
        for (std::size_t j = 0; j < rings; ++j)
            if (got[i] && *got[i] == pb::RingId{d, static_cast<std::uint8_t>(j)}) ++in;
        check(in == 1, what + ": item " + std::to_string(i) + " is in exactly one ring at depth " + std::to_string(d));
    }
    return m;
}

// Each ring at depth d is the disjoint union of its children's members at d + 1.
void children_partition(const Members& at_d, const Members& at_next, std::uint8_t d, const std::string& what) {
    for (std::size_t j = 0; j < at_d.size(); ++j) {
        const pb::RingId r{d, static_cast<std::uint8_t>(j)};
        const auto c0 = pb::child(r, false);
        const auto c1 = pb::child(r, true);
        check(c0 && c1 && c0->depth == d + 1 && c1->depth == d + 1 && c0->index < at_next.size() &&
                      c1->index < at_next.size(),
              what + ": ring {" + std::to_string(d) + "," + std::to_string(j) + "} has two children");
        if (!(c0 && c1 && c0->index < at_next.size() && c1->index < at_next.size())) continue;
        const std::vector<std::size_t>& a = at_next[c0->index];
        const std::vector<std::size_t>& b = at_next[c1->index];
        std::vector<std::size_t> both;
        std::set_intersection(a.begin(), a.end(), b.begin(), b.end(), std::back_inserter(both));
        std::vector<std::size_t> uni;
        std::set_union(a.begin(), a.end(), b.begin(), b.end(), std::back_inserter(uni));
        check(both.empty(), what + ": the children of {" + std::to_string(d) + "," + std::to_string(j) + "} are disjoint");
        check(uni == at_d[j], what + ": the children of {" + std::to_string(d) + "," + std::to_string(j) +
                                      "} hold exactly its members");
    }
}

void p1() {
    std::vector<pb::Hash32> keys(kByteValues);
    for (std::size_t b = 0; b < kByteValues; ++b) {
        keys[b] = seq32(0x11);
        keys[b][0] = static_cast<std::uint8_t>(b);
    }
    std::vector<Members> by_depth;
    for (std::uint8_t d = 0; d <= kBound; ++d) {
        by_depth.push_back(place(keys.size(), d, [&](std::size_t i) { return pb::ring_of(keys[i], d); }, "P1"));
        for (std::size_t j = 0; j < by_depth.back().size(); ++j)
            check(!by_depth.back()[j].empty(), "P1: ring {" + std::to_string(d) + "," + std::to_string(j) + "} is hit");
    }
    for (std::uint8_t d = 0; d < kBound; ++d) {
        children_partition(by_depth[d], by_depth[d + 1], d, "P1");
        // child(r, bit) holds the keys whose bit d (byte 0, most significant first) is that bit
        const std::size_t shift = pb::kRingBitsPerByte - 1 - d;
        for (std::size_t j = 0; j < by_depth[d].size(); ++j) {
            for (const bool one : {false, true}) {
                const auto c = pb::child(pb::RingId{d, static_cast<std::uint8_t>(j)}, one);
                if (!c || c->index >= by_depth[d + 1].size()) continue;
                for (const std::size_t i : by_depth[d + 1][c->index])
                    check(((keys[i][0] >> shift) & 1u) == (one ? 1u : 0u),
                          "P1: child({" + std::to_string(d) + "," + std::to_string(j) + "}, " + (one ? "1" : "0") +
                                  ") holds key " + std::to_string(i) + " by its bit " + std::to_string(d));
            }
        }
    }
    std::printf("  P1: %zu keys x %d depths\n", keys.size(), kBound + 1);
}

void p2() {
    // row c: miner X(c / 2), owner X(kByteValues + c): each miner on two rows
    const std::size_t n = kByteValues;
    std::vector<pb::BucketRow> rows(n);
    std::vector<pb::WinEntry> entries(n);
    for (std::size_t c = 0; c < n; ++c) {
        rows[c].miner = gen_id(c / 2);
        rows[c].owner = gen_id(n + c);
        entries[c].miner = rows[c].miner;
        entries[c].owner = rows[c].owner;
        entries[c].position = c;
    }
    const pb::RingKeyRule rule = test_rule();
    const pb::RingBindingValue v = chain(kChainA);
    std::vector<Members> by_depth;
    for (std::uint8_t d = 0; d <= kBound; ++d) {
        by_depth.push_back(place(n, d, [&](std::size_t i) { return ring_row(rule, v, rows[i], d); }, "P2 rows"));
        for (std::size_t c = 0; c + 1 < n; c += 2) {
            const auto a = ring_row(rule, v, rows[c], d);
            const auto b = ring_row(rule, v, rows[c + 1], d);
            check(a && b && *a == *b, "P2: the two rows of miner " + std::to_string(c / 2) + " share a ring at depth " +
                                              std::to_string(d));
        }
        for (std::size_t c = 0; c < n; ++c) {
            const auto e = ring_entry(rule, v, entries[c], d);
            const auto r = ring_row(rule, v, rows[c], d);
            check(e && r && *e == *r, "P2: ring_of_entry = ring_of_row, item " + std::to_string(c) + ", depth " +
                                              std::to_string(d));
        }
        const Members by_entry =
                place(n, d, [&](std::size_t i) { return ring_entry(rule, v, entries[i], d); }, "P2 entries");
        check(by_entry == by_depth.back(), "P2: entries and rows fall into the same rings at depth " + std::to_string(d));
    }
    for (std::uint8_t d = 0; d < kBound; ++d) children_partition(by_depth[d], by_depth[d + 1], d, "P2");
    std::printf("  P2: %zu rows (%zu miners) x %d depths\n", n, n / 2, kBound + 1);
}

}  // namespace

int main() {
    p1();
    p2();
    return finish("v37_xmr_ring_partition_kat");
}
