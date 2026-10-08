// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// v37_xmr_joiner_kat (pathb_joiner.hpp, ruling 15 Q8, 20 Q-E; V-10, C43): the
// recent-window joiner reaches the byte-equal lane digest from the span +
// N_rt headers + sealed-bin buckets with MMR proofs; span == 1,176, N_rt ==
// 2,160; the first span carrier's peaks bag to its mmr_root; a forged bucket
// (composition changed) and forged peaks are refused by the MMR proof.
// ---------------------------------------------------------------------------
#include <cstdint>
#include <vector>

#include "impl/xmr/pathb/pathb_joiner.hpp"
#include "pathb_kat_check.hpp"

using namespace pathb_kat;
namespace pb = ::c2pool::xmr::pathb;

static pb::Hash32 rep(std::uint8_t b) { pb::Hash32 h{}; h.fill(b); return h; }
static pb::L1Bucket mkbin(std::uint64_t i) {
    pb::BucketRow r; r.miner = rep(static_cast<std::uint8_t>(0x30 + i)); r.w_miner = pb::Work(5000 + i);
    return pb::seal_bucket(2000000 + i, {r}, pb::Work(5000 + i), 1, 18180 + i);
}

int main() {
    // span = max(J_0, ceil((F+Fresh) x 120 / T) + D_fin) = 1,176 at D_fin 0;
    // N_rt = 2,160.
    check(pb::journal_j0(pb::kRuledLaneParams, 0) == 1152, "J_0 == 1152 (default journal)");
    check(pb::join_span(pb::kRuledLaneParams, 0) == 1176, "joiner span == 1176 positions");
    check(pb::join_n_rt(pb::kRuledLaneParams) == 2160, "N_rt == 2160 retarget-prefix headers");

    // the first span carrier commits c0_mmr_root over 11 sealed bins; its peaks +
    // leaf_count must bag to that root (n_peaks == popcount).
    pb::BinMmr mmr;
    for (std::uint64_t i = 0; i < 11; ++i) mmr.append(pb::mmr_leaf_of(mkbin(i)));
    const pb::Hash32 c0_root = mmr.root();
    const auto peaks = mmr.peaks();
    check(pb::peaks_match_root(peaks, mmr.leaf_count(), c0_root), "span-start peaks bag to mmr_root");
    check(peaks.size() == pb::popcount64(11), "n_peaks == popcount(11) == 3");

    // forged peaks (bag != mmr_root(c_0)) refused.
    auto bad_peaks = peaks; bad_peaks.front()[0] ^= 1;
    check(!pb::peaks_match_root(bad_peaks, mmr.leaf_count(), c0_root), "forged peaks refused");

    // sealed-bin buckets served with MMR proofs (FC_GETBUCKETS): each verifies.
    std::vector<pb::ServedBucket> served;
    for (std::uint64_t i = 0; i < 11; ++i) served.push_back({mkbin(i), pb::mmr_proof(mmr, i)});
    check(pb::joiner_bucket_pass(peaks, mmr.leaf_count(), c0_root, served),
          "joiner accepts span-start peaks + all served buckets with proofs");

    // a forged bucket (composition changed) is refused by its MMR proof.
    pb::ServedBucket forged = served[4];
    forged.bucket.rows.front().w_miner = pb::Work(999999);  // changed composition
    forged.bucket.comp_root_v = pb::comp_root(forged.bucket.rows);  // recompute to hide it
    check(!pb::verify_served_bucket(c0_root, forged), "forged bucket refused by its MMR proof");

    // a bucket served without a valid proof (wrong proof) is refused.
    pb::ServedBucket wrong_proof = {mkbin(4), pb::mmr_proof(mmr, 7)};  // bin 4 body, bin 7 proof
    check(!pb::verify_served_bucket(c0_root, wrong_proof), "bucket without a matching proof refused");

    return finish("v37_xmr_joiner_kat");
}
