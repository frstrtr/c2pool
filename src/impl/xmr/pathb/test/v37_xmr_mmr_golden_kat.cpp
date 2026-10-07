// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// v37_xmr_mmr_golden_kat (pathb_buckets.hpp, S3.2 / S3.6; C25, C33):
//   the PINNED golden vectors (row_leaf, comp_root, mmr_leaf) byte-for-byte; the
//   append-only MMR leaf / root for 1, 2, 3, 7, 8 sealed bins; n_peaks ==
//   popcount(leaf_count); the proof of bin 3 of 8 verifies; a forged composition
//   and forged peaks fail; a rebuild reproduces the root (restart / reorg / joiner).
// ---------------------------------------------------------------------------
#include <cstdint>
#include <vector>

#include "impl/xmr/pathb/pathb_buckets.hpp"
#include "pathb_kat_check.hpp"

using namespace pathb_kat;
namespace pb = ::c2pool::xmr::pathb;

static pb::Hash32 rep(std::uint8_t b) { pb::Hash32 h{}; h.fill(b); return h; }
static std::string hx(const pb::Hash32& h) { return hex(h.data(), h.size()); }

static pb::L1Bucket mkbin(std::uint64_t i) {
    pb::BucketRow r;
    r.miner = rep(static_cast<std::uint8_t>(0x10 + i));
    r.w_miner = pb::Work(1000 + i);
    return pb::seal_bucket(3000000 + i, {r}, pb::Work(1000 + i), 1, 18180 + i);
}

int main() {
    // ---- the pinned golden vectors (S3.2) ----
    pb::BucketRow A;
    A.miner = rep(0xAA); A.owner = pb::Hash32{};
    A.w_miner = pb::Work(119880); A.w_owner = pb::Work(0); A.w_author = pb::Work(120);
    pb::BucketRow B;
    B.miner = rep(0xBB); B.owner = rep(0xCC);
    B.w_miner = pb::Work(89900); B.w_owner = pb::Work(10000); B.w_author = pb::Work(100);

    check(hx(pb::row_leaf(A)) == "755d2087bd8287525f3c39d9335cf9e3af92578f6d2af0a57c9a3f937466f7b7",
          "golden row_leaf(A)");
    check(hx(pb::row_leaf(B)) == "6e8ec210ff6274b11ddb64f075575486ed53e2638b0d8b037074dbb9d0fea8be",
          "golden row_leaf(B)");
    check(hx(pb::comp_root({A, B})) == "8577c505690b7058e986ec25f9a427a182a26b306e3c733269581ecb0b07ca62",
          "golden comp_root");
    // sort-independence: rows in the other order give the same comp_root.
    check(pb::comp_root({B, A}) == pb::comp_root({A, B}), "comp_root sorts by miner||owner");

    pb::L1Bucket golden = pb::seal_bucket(3000000, {A, B}, pb::Work(220000), 2, 18180);
    check(golden.comp_root_v == pb::comp_root({A, B}), "seal fills comp_root");
    check(hx(pb::mmr_leaf_of(golden)) == "7161ee83858544e9dce3ea4ea449840b92a3a31e28897703ad9fb59cb81dddc9",
          "golden mmr_leaf (0x00 || LeafPayload v1)");

    // one row -> comp_root is that row leaf; empty -> 32 zero bytes.
    check(pb::comp_root({A}) == pb::row_leaf(A), "one row -> row_leaf");
    check(pb::comp_root({}) == pb::Hash32{}, "empty bin -> zero comp_root");

    // ---- the MMR: leaf / root for 1, 2, 3, 7, 8 bins; n_peaks == popcount ----
    pb::BinMmr m;
    const char* roots[9] = {"", "684057b52a748b910d7badb43e80ead6803b3ebaff38ab19beec7b869c8d7de3",
                            "e4b3aa3d83d52422bdb92e7cbde00f223fa0c23a8d3297fff3b025d625465cef",
                            "6a094b8ae1cdef2701ed8fe21f5f001e051e87bb23dbfda25f6b3aa0f8386b42", "", "", "",
                            "4523e78de9f5a87792fb53cd605f65b2649da046cc37ddf30bb81874fb04ca9e",
                            "b0f5ea549446a62fa69bfb0be12c38815c73f44ee7337834ad8f3aaeb4d699d5"};
    for (std::uint64_t n = 1; n <= 8; ++n) {
        m.append(pb::mmr_leaf_of(mkbin(n - 1)));
        check(m.n_peaks() == pb::popcount64(n), "n_peaks == popcount(leaf_count)");
        if (roots[n][0]) check(hx(m.root()) == roots[n], "MMR root golden");
    }

    // ---- proof of bin 3 (index 2) of 8 verifies; forgeries refused ----
    pb::MmrProof pr = pb::mmr_proof(m, 2);
    const pb::Hash32 leaf2 = pb::mmr_leaf_of(mkbin(2));
    check(pb::mmr_verify(m.root(), leaf2, pr), "proof of bin 3 of 8 verifies");
    pb::Hash32 forged = leaf2; forged[0] ^= 1;
    check(!pb::mmr_verify(m.root(), forged, pr), "forged composition refused");
    pb::MmrProof bad_peaks = pr; bad_peaks.peaks.front()[0] ^= 1;
    check(!pb::mmr_verify(m.root(), leaf2, bad_peaks), "forged peaks refused");

    // ---- a rebuild reproduces the root (restart / reorg / joiner) ----
    pb::BinMmr rebuilt;
    for (std::uint64_t n = 0; n < 8; ++n) rebuilt.append(pb::mmr_leaf_of(mkbin(n)));
    check(rebuilt.root() == m.root(), "rebuild reproduces the MMR root");

    return finish("v37_xmr_mmr_golden_kat");
}
