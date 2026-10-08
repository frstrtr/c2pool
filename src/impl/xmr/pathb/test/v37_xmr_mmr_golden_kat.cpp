// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// v37_xmr_mmr_golden_kat (pathb_buckets.hpp, pathb_bin_store.hpp, S3.2 / S3.6;
// C25, C33, E-8, E-9):
//   the PINNED golden vectors (row_leaf, comp_root, mmr_leaf) byte-for-byte; the
//   append-only MMR leaf / root for 1, 2, 3, 7, 8 sealed bins; n_peaks ==
//   popcount(leaf_count); the proof of bin 3 of 8 verifies; a forged composition
//   and forged peaks fail; a valid path under another leaf_index fails; the
//   empty-bin leaf goldens (E-8); a rebuild reproduces the root (restart / reorg /
//   joiner).
//   S3b-1a: the O(log n) BinMmr against master's O(n) fold (every size 1..2^12
//   and 2^20; root / prefix_root / proof costs <= log2(n) + popcount(n) hashes);
//   prefix_proof(i, n) against the root at n; from_peaks prefix MMRs; truncate;
//   the dense FR-B1 vector; the K_BMMR / K_BLHASH / K_BLEAF codecs; restart and
//   crash vectors of the lane records.
//   S3b-3: FC_BUCKETS with MMR proofs accepted by a joiner (8 sealed bins, the
//   proof of bin 3 of 8 from the wire), without a proof not.
// ---------------------------------------------------------------------------
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <map>
#include <optional>
#include <string>
#include <vector>

#include "impl/xmr/pathb/pathb_bin_store.hpp"
#include "impl/xmr/pathb/pathb_bucket_wire.hpp"
#include "impl/xmr/pathb/pathb_buckets.hpp"
#include "pathb_kat_bodies.hpp"
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

static void master_goldens() {
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

    // ---- leaf_index is bound to the path directions and own_peak ----
    // the valid co-path of index 2 of 8 presented under another leaf_index.
    for (std::uint64_t wrong : {std::uint64_t{3}, std::uint64_t{6}, std::uint64_t{8}}) {
        pb::MmrProof moved = pr; moved.leaf_index = wrong;
        check(!pb::mmr_verify(m.root(), leaf2, moved),
              "valid path of index 2 of 8 under leaf_index " + std::to_string(wrong) + " refused");
    }
    {
        // 11 bins: peaks 8, 2, 1. Every leaf verifies under its own index; the
        // valid co-path of index 9 (peak 1) is refused under index 8 (same peak,
        // other side), 10 (peak 2) and 1 (peak 0).
        pb::BinMmr m11;
        for (std::uint64_t n = 0; n < 11; ++n) m11.append(pb::mmr_leaf_of(mkbin(n)));
        bool all_ok = true;
        for (std::uint64_t i = 0; i < 11; ++i)
            all_ok = all_ok && pb::mmr_verify(m11.root(), pb::mmr_leaf_of(mkbin(i)), pb::mmr_proof(m11, i));
        check(all_ok, "every leaf of 11 verifies under its own leaf_index");
        const pb::MmrProof pr9 = pb::mmr_proof(m11, 9);
        const pb::Hash32 leaf9 = pb::mmr_leaf_of(mkbin(9));
        for (std::uint64_t wrong : {std::uint64_t{8}, std::uint64_t{10}, std::uint64_t{1}}) {
            pb::MmrProof moved = pr9; moved.leaf_index = wrong;
            check(!pb::mmr_verify(m11.root(), leaf9, moved),
                  "valid path of index 9 of 11 under leaf_index " + std::to_string(wrong) + " refused");
        }
    }

    // ---- E-8: the empty-bin leaf (a bin with no live receipt at its fold) ----
    // LeafPayload v1: bin_lo = bin_hi = b, raw_sum 0, miner_count 0, d_min 0,
    // comp_root = 32 zero bytes; mmr_leaf = sha256d(0x00 || LeafPayload v1).
    {
        struct EmptyLeaf { std::uint64_t b; const char* leaf; };
        const EmptyLeaf empty[] = {
            {0, "493bbf476c3f201466248d191eb35a0ce00b917fa97768ae64b65f5e1cc8a507"},
            {1, "c64b418f478ff0214bd15f86f5f898a3d62420258cf521e1ddb758a0f111f5cb"},
            {3500000, "5f1c87aacdf5c93e759200e347878dea6d70016dd22cbeeaf4e3ec2727100be4"},
        };
        for (const EmptyLeaf& e : empty) {
            const pb::L1Bucket eb = pb::seal_bucket(e.b, {}, pb::Work(0), 0, 0);
            check(eb.comp_root_v == pb::Hash32{}, "empty bin " + std::to_string(e.b) + ": comp_root zero");
            check(hx(pb::mmr_leaf_of(eb)) == e.leaf, "golden empty-bin mmr_leaf b = " + std::to_string(e.b));
        }
    }

    // ---- a rebuild reproduces the root (restart / reorg / joiner) ----
    pb::BinMmr rebuilt;
    for (std::uint64_t n = 0; n < 8; ++n) rebuilt.append(pb::mmr_leaf_of(mkbin(n)));
    check(rebuilt.root() == m.root(), "rebuild reproduces the MMR root");
}

// ===========================================================================
// S3b-1a: the O(log n) MMR, prefix roots / proofs, truncate, the lane records
// ===========================================================================
namespace s3b {

// master's O(n) fold (pathb_buckets.hpp before S3b), kept as the reference.
pb::Hash32 ref_fold_range(const std::vector<pb::Hash32>& leaves, std::uint64_t lo, std::uint64_t sz) {
    std::vector<pb::Hash32> level(leaves.begin() + static_cast<std::ptrdiff_t>(lo),
                                  leaves.begin() + static_cast<std::ptrdiff_t>(lo + sz));
    while (level.size() > 1) {
        std::vector<pb::Hash32> next;
        next.reserve(level.size() / 2);
        for (std::size_t i = 0; i < level.size(); i += 2)
            next.push_back(pb::sha256d_tag_pair(pb::kDomMmrNode, level[i], level[i + 1]));
        level.swap(next);
    }
    return level.front();
}

pb::Hash32 ref_root(const std::vector<pb::Hash32>& leaves, std::uint64_t n) {
    if (n == 0) return pb::Hash32{};
    std::vector<pb::Hash32> peaks;
    std::uint64_t start = 0;
    for (int bit = 63; bit >= 0; --bit) {
        const std::uint64_t sz = std::uint64_t{1} << bit;
        if (n & sz) {
            peaks.push_back(ref_fold_range(leaves, start, sz));
            start += sz;
        }
    }
    pb::Hash32 bag = peaks.back();
    for (std::size_t i = peaks.size() - 1; i-- > 0;) bag = pb::sha256d_tag_pair(pb::kDomMmrNode, peaks[i], bag);
    std::vector<std::uint8_t> pre;
    pre.push_back(pb::kDomMmrRoot);
    for (std::size_t i = 0; i < 8; ++i) pre.push_back(static_cast<std::uint8_t>(n >> (8 * i)));
    pre.insert(pre.end(), bag.begin(), bag.end());
    return ::v37::sha256d(pre);
}

// deterministic 32-byte leaves (the MMR does not read inside a leaf).
pb::Hash32 lf(std::uint64_t i) {
    Rng r(0x5EED0000ull + i);
    pb::Hash32 h{};
    for (std::size_t k = 0; k < h.size(); k += 8) {
        const std::uint64_t v = r.next();
        for (std::size_t j = 0; j < 8; ++j) h[k + j] = static_cast<std::uint8_t>(v >> (8 * j));
    }
    return h;
}

// the cost bound: log2(n) + popcount(n) hashes.
std::uint64_t bound(std::uint64_t n) { return pb::floor_log2(n) + pb::popcount64(n); }

void sizes_1_to_4096() {
    pb::BinMmr m;
    std::vector<pb::Hash32> leaves;
    std::vector<pb::Hash32> ref(4097);
    bool root_ok = true, root_cost = true;
    for (std::uint64_t n = 1; n <= 4096; ++n) {
        leaves.push_back(lf(n - 1));
        m.append(leaves.back());
        ref[n] = ref_root(leaves, n);
        const std::uint64_t h0 = m.hash_count();
        const pb::Hash32 r = m.root();
        root_ok = root_ok && r == ref[n];
        root_cost = root_cost && m.hash_count() - h0 <= bound(n);
    }
    check(root_ok, "root == master's O(n) fold at every append size 1..4096");
    check(root_cost, "root costs <= log2(n) + popcount(n) hashes, sizes 1..4096");
    bool pre_ok = true, pre_cost = true;
    for (std::uint64_t n = 1; n <= 4096; ++n) {
        const std::uint64_t h0 = m.hash_count();
        const std::optional<pb::Hash32> r = m.prefix_root(n);
        pre_ok = pre_ok && r && *r == ref[n];
        pre_cost = pre_cost && m.hash_count() - h0 <= bound(n);
    }
    check(pre_ok, "prefix_root(n) == master's O(n) fold over the first n leaves, n 1..4096");
    check(pre_cost, "prefix_root(n) costs <= log2(n) + popcount(n) hashes");
    check(m.prefix_root(0) == pb::Hash32{} && !m.prefix_root(4097), "prefix_root(0) zero; n > leaf_count refused");

    bool proof_ok = true, proof_cost = true, stale_refused = true;
    std::uint64_t n_proofs = 0;
    const auto one = [&](std::uint64_t i, std::uint64_t n) {
        const std::uint64_t h0 = m.hash_count();
        const std::optional<pb::MmrProof> p = m.prefix_proof(i, n);
        proof_cost = proof_cost && m.hash_count() - h0 <= bound(n);
        proof_ok = proof_ok && p && p->leaf_count == n && pb::mmr_verify(ref[n], leaves[i], *p);
        if (n != 4096) stale_refused = stale_refused && p && !pb::mmr_verify(m.root(), leaves[i], *p);
        ++n_proofs;
    };
    for (std::uint64_t n : {1u, 2u, 3u, 5u, 8u, 13u, 100u, 1023u, 1024u, 1025u, 4095u, 4096u})
        for (std::uint64_t i = 0; i < n; ++i) one(i, n);
    Rng r(77);
    for (int k = 0; k < 4000; ++k) {
        const std::uint64_t n = 1 + r.below(4096);
        one(r.below(n), n);
    }
    check(proof_ok, "prefix_proof(i, n) verifies against the root committed at leaf_count n (" +
                            std::to_string(n_proofs) + " proofs)");
    check(stale_refused, "prefix_proof(i, n < leaf_count) fails against the current root");
    check(proof_cost, "a proof costs <= log2(n) + popcount(n) hashes");
    check(!m.prefix_proof(5, 5) && !m.prefix_proof(0, 4097), "no proof for i >= n or n > leaf_count");
    const pb::MmrProof cur = pb::mmr_proof(m, 4095);
    check(cur.leaf_count == 4096 && pb::mmr_verify(m.root(), leaves[4095], cur), "mmr_proof = prefix_proof at leaf_count");
}

void size_2_pow_20() {
    const std::uint64_t N = std::uint64_t{1} << 20;
    std::vector<pb::Hash32> leaves(N);
    for (std::uint64_t i = 0; i < N; ++i) leaves[i] = lf(i);
    pb::BinMmr m;
    for (std::uint64_t i = 0; i < N; ++i) m.append(leaves[i]);
    check(m.hash_count() == N - pb::popcount64(N), "2^20 appends: n - popcount(n) node hashes in total");
    std::uint64_t h0 = m.hash_count();
    const pb::Hash32 root = m.root();
    check(m.hash_count() - h0 <= bound(N), "2^20: the root costs <= log2(n) + popcount(n) hashes");
    check(root == ref_root(leaves, N), "2^20: root == master's O(n) fold");
    const std::uint64_t n2 = N - 1;  // popcount 20
    h0 = m.hash_count();
    const std::optional<pb::Hash32> r2 = m.prefix_root(n2);
    check(m.hash_count() - h0 <= bound(n2), "2^20 - 1: prefix_root costs <= log2(n) + popcount(n)");
    const pb::Hash32 ref2 = ref_root(leaves, n2);
    check(r2 && *r2 == ref2, "2^20 - 1: prefix_root == master's O(n) fold");
    const std::optional<pb::MmrProof> p = m.prefix_proof(777777, n2);
    check(p && pb::mmr_verify(ref2, leaves[777777], *p) && !pb::mmr_verify(root, leaves[777777], *p),
          "2^20: a proof against the root at n verifies, against the current root fails");
    check(p && p->path.size() <= pb::floor_log2(n2), "2^20: proof path <= log2(n)");
}

void prefix_mmrs() {
    std::vector<pb::Hash32> leaves;
    for (std::uint64_t i = 0; i < 200; ++i) leaves.push_back(lf(1000 + i));
    pb::BinMmr full;
    for (const pb::Hash32& l : leaves) full.append(l);
    bool ok = true;
    for (std::uint64_t c0 : {0u, 1u, 2u, 5u, 37u, 64u, 99u, 128u, 199u, 200u}) {
        std::optional<pb::BinMmr> pm = pb::BinMmr::from_peaks(c0, *full.prefix_peaks(c0));
        ok = ok && pm && pm->leaf_count() == c0 && pm->first_provable() == c0 && pm->root() == *full.prefix_root(c0);
        if (!pm) continue;
        for (std::uint64_t i = c0; i < leaves.size(); ++i) pm->append(leaves[i]);
        for (std::uint64_t n = c0; n <= leaves.size(); ++n) ok = ok && pm->prefix_root(n) == full.prefix_root(n);
        for (std::uint64_t i = c0; i < leaves.size(); ++i) {
            const std::optional<pb::MmrProof> p = pm->prefix_proof(i, 200);
            ok = ok && p && pb::mmr_verify(full.root(), leaves[i], *p);
        }
        if (c0 > 0) ok = ok && !pm->prefix_proof(c0 - 1, 200) && !pm->truncate(c0 - 1);
        ok = ok && pm->truncate(c0) && pm->root() == *full.prefix_root(c0);
        for (std::uint64_t i = c0; i < leaves.size(); ++i) pm->append(leaves[i]);
        ok = ok && pm->root() == full.root();
    }
    check(ok, "from_peaks(c0): roots for every n >= c0, proofs for leaves >= c0 only, truncate / re-append");
    check(!pb::BinMmr::from_peaks(5, {lf(1), lf(2), lf(3)}), "from_peaks refuses n_peaks != popcount(leaf_count)");
}

void truncate_vectors() {
    std::vector<pb::Hash32> leaves, other;
    for (std::uint64_t i = 0; i < 300; ++i) {
        leaves.push_back(lf(5000 + i));
        other.push_back(lf(9000 + i));
    }
    pb::BinMmr full;
    for (const pb::Hash32& l : leaves) full.append(l);
    bool same = true, branch = true;
    for (std::uint64_t n : {0u, 1u, 2u, 3u, 4u, 7u, 8u, 100u, 255u, 256u, 257u, 299u, 300u}) {
        pb::BinMmr t = full;
        same = same && t.truncate(n) && t.leaf_count() == n && t.root() == ref_root(leaves, n);
        for (std::uint64_t i = n; i < leaves.size(); ++i) t.append(leaves[i]);
        same = same && t.root() == full.root();
        // a rewind followed by another branch's leaves
        pb::BinMmr u = full;
        std::vector<pb::Hash32> mixed(leaves.begin(), leaves.begin() + static_cast<std::ptrdiff_t>(n));
        branch = branch && u.truncate(n);
        for (std::uint64_t i = n; i < 300; ++i) {
            u.append(other[i]);
            mixed.push_back(other[i]);
        }
        branch = branch && u.root() == ref_root(mixed, mixed.size());
        for (std::uint64_t i = 0; i < mixed.size(); i += 37) {
            const std::optional<pb::MmrProof> p = u.prefix_proof(i, mixed.size());
            branch = branch && p && pb::mmr_verify(u.root(), mixed[i], *p);
        }
    }
    check(same, "truncate(n) then re-append reproduces the root");
    check(branch, "truncate(n) then another branch's leaves == the fold of the new leaf list");
    pb::BinMmr t = full;
    check(!t.truncate(301) && t.leaf_count() == 300, "truncate beyond leaf_count refused");
}

pb::WinEntry entry(const pb::Hash32& miner, std::uint64_t work) {
    pb::WinEntry e;
    e.miner = miner;
    e.work = work;
    return e;
}

void fr_b1_dense() {
    const pb::Hash32 aa = rep(0xAA);
    const pb::L1Bucket a0 = pb::seal_from_entries(3500000, {entry(aa, 18180)});
    const pb::L1Bucket e1 = pb::seal_from_entries(3500001, {});
    const pb::L1Bucket a2 = pb::seal_from_entries(3500002, {entry(aa, 18180)});
    pb::BinMmr dense, sparse;
    for (const pb::L1Bucket* b : {&a0, &e1, &a2}) dense.append(pb::mmr_leaf_of(*b));
    for (const pb::L1Bucket* b : {&a0, &a2}) sparse.append(pb::mmr_leaf_of(*b));
    check(hx(pb::mmr_leaf_of(a0)) == "2236549787e6f158bfe596d94b96457abc7e6c822c2c9793f6e073e50485a201" &&
                  hx(pb::mmr_leaf_of(e1)) == "dcd7becdd422d3ff25c6477a1f9f26de4c109baf2930b1361bc7d09d46dc8417" &&
                  hx(pb::mmr_leaf_of(a2)) == "891c80d0569ee5b875f2d4f3c53b011845a9086cd940074d7821644ef76ff239",
          "FR-B1 gap: the three leaves (golden)");
    check(hx(dense.root()) == "dc6ff5da350b6e8e7b21fd6e75332e3d5acb872e3637378a5c476486ed9dd49c",
          "FR-B1 gap: dense mmr_root golden");
    check(hx(sparse.root()) == "fc3c8bd1c504726dc626436ae725d1c7a62007142e006a1e4bf5950fcaf5fdff" &&
                  sparse.root() != dense.root(),
          "FR-B1 gap: the sparse form fc3c8bd1... is not the root");
}

void bmmr_codec() {
    pb::BinMmr m;
    for (std::uint64_t i = 0; i < 5; ++i) m.append(lf(i));
    pb::BmmrHead h;
    h.b0 = 3500000;
    h.leaf_count = 5;
    h.root = m.root();
    h.peaks = m.peaks();
    h.tip_pos = 1234;
    h.tip_id = seq32(0x31);
    const std::string enc = pb::encode_bmmr(h);
    check(enc.size() == 2 + 8 + 8 + 32 + 4 + 2 * 32 + 8 + 32, "K_BMMR length");
    const std::optional<pb::BmmrHead> d = pb::decode_bmmr(enc);
    check(d && *d == h, "K_BMMR encode -> decode -> identical head");
    pb::BmmrHead bad = h;
    bad.peaks = {lf(10), lf(11), lf(12)};
    bad.root = pb::mmr_root_of(5, bad.peaks);
    check(!pb::decode_bmmr(pb::encode_bmmr(bad)), "K_BMMR with n_peaks != popcount(leaf_count) refused");
    std::string flip = enc;
    flip[18] = static_cast<char>(flip[18] ^ 1);  // root
    check(!pb::decode_bmmr(flip), "K_BMMR byte-flipped root refused");
    flip = enc;
    flip[60] = static_cast<char>(flip[60] ^ 1);  // a peak
    check(!pb::decode_bmmr(flip), "K_BMMR byte-flipped peak refused");
    check(!pb::decode_bmmr(enc.substr(0, enc.size() - 1)) && !pb::decode_bmmr(enc + std::string(1, '\0')),
          "K_BMMR truncated / trailing bytes refused");
    flip = enc;
    flip[0] = 2;
    check(!pb::decode_bmmr(flip), "K_BMMR newer schema refused");
    flip = enc;
    flip[1] = static_cast<char>(pb::K_BLEAF);
    check(!pb::decode_bmmr(flip), "K_BMMR wrong kind refused");
    flip = enc;
    for (int i = 0; i < 4; ++i) flip[50 + i] = static_cast<char>(0xff);
    check(!pb::decode_bmmr(flip), "K_BMMR n_peaks 2^32 - 1 refused before allocating");
    pb::BmmrHead empty;
    check(pb::decode_bmmr(pb::encode_bmmr(empty)) == empty, "K_BMMR of an empty MMR (root zero)");
    check(pb::decode_blhash(pb::encode_blhash(lf(3))) == lf(3) && !pb::decode_blhash(pb::encode_blhash(lf(3)) + "x"),
          "K_BLHASH encode / decode; trailing refused");
}

void bleaf_codec() {
    const pb::XmrKeyRef k1 = key_ref(0x10), k2 = key_ref(0x30), k3 = key_ref(0x50);
    const pb::Hash32 i1 = pb::key_ref_identity(k1), i2 = pb::key_ref_identity(k2), i3 = pb::key_ref_identity(k3);
    pb::WinEntry e1 = entry(i1, 30000), e2 = entry(i2, 20000);
    e2.owner = i3;
    e2.p = 100;
    pb::SealedBin sb;
    sb.bucket = pb::seal_from_entries(3500007, {e1, e2});
    sb.leaf = pb::mmr_leaf_of(sb.bucket);
    sb.refs = {k1, k2, k3};
    std::sort(sb.refs.begin(), sb.refs.end(), [](const pb::XmrKeyRef& a, const pb::XmrKeyRef& b) {
        return pb::key_ref_identity(a) < pb::key_ref_identity(b);
    });
    const std::string enc = pb::encode_bleaf(sb);
    check(enc.size() == 2 + 96 + 4 + 2 * 160 + 4 + 3 * 66, "K_BLEAF length");
    const std::optional<pb::SealedBin> d = pb::decode_bleaf(enc, 7, 3500000);
    check(d && pb::encode_bleaf(*d) == enc && d->leaf == sb.leaf, "K_BLEAF encode -> decode -> same bytes and leaf");
    check(!pb::decode_bleaf(enc, 8, 3500000), "K_BLEAF leaf_index != bin_lo - b0 refused");
    pb::SealedBin swapped = sb;
    std::swap(swapped.refs[0], swapped.refs[1]);
    check(!pb::decode_bleaf(pb::encode_bleaf(swapped), 7, 3500000), "K_BLEAF references out of identity order refused");
    pb::SealedBin dup = sb;
    dup.refs[1] = dup.refs[0];
    check(!pb::decode_bleaf(pb::encode_bleaf(dup), 7, 3500000), "K_BLEAF duplicate reference refused");
    pb::SealedBin stranger = sb;
    stranger.refs = {key_ref(0x70)};
    check(!pb::decode_bleaf(pb::encode_bleaf(stranger), 7, 3500000),
          "K_BLEAF reference of an identity outside the rows refused");
    std::string t = enc;
    t[2 + 16] = static_cast<char>(t[2 + 16] ^ 1);  // raw_sum
    check(!pb::decode_bleaf(t, 7, 3500000), "K_BLEAF raw_sum not from the rows refused");
    t = enc;
    for (int i = 0; i < 4; ++i) t[2 + 96 + i] = static_cast<char>(0xff);
    check(!pb::decode_bleaf(t, 7, 3500000), "K_BLEAF n_rows 2^32 - 1 refused before allocating");
    pb::SealedBin e;
    e.bucket = pb::seal_from_entries(3500001, {});
    e.leaf = pb::mmr_leaf_of(e.bucket);
    const std::optional<pb::SealedBin> de = pb::decode_bleaf(pb::encode_bleaf(e), 1, 3500000);
    check(de && de->leaf == e.leaf && de->bucket.rows.empty(), "K_BLEAF of an empty bin");
}

}  // namespace s3b

static void s3b_mmr_vectors() {
    s3b::sizes_1_to_4096();
    s3b::size_2_pow_20();
    s3b::prefix_mmrs();
    s3b::truncate_vectors();
    s3b::fr_b1_dense();
    s3b::bmmr_codec();
    s3b::bleaf_codec();
}

// ---------------------------------------------------------------------------
// Lane records: restart, crash consistency (one batch per best-chain change).
// ---------------------------------------------------------------------------
namespace s3b {

constexpr std::uint64_t kB0 = 3500000;
constexpr std::uint32_t kChain = 7;

pb::Hash32 cid(std::uint8_t tag, std::uint64_t n) {
    pb::Hash32 h{};
    h[0] = tag;
    for (int i = 0; i < 8; ++i) h[1 + i] = static_cast<std::uint8_t>(n >> (8 * i));
    return h;
}

pb::Placement rc(std::uint64_t n, std::uint64_t bin, std::uint64_t p_own, const pb::XmrKeyRef& ref,
                 std::uint64_t work) {
    pb::Placement x;
    x.id = cid(0xEE, n);
    x.bin = bin;
    x.p_own = p_own;
    x.payee = pb::key_ref_identity(ref);
    x.payee_ref = ref;
    x.work = work;
    return x;
}

struct Built {
    bool ok = true;
    std::vector<pb::LaneBatch> batches;  // one per best-chain change
};

// add + ingest + seal + switch_best, the switch's batch kept.
void step(pb::BinStore& s, Built& b, const pb::Hash32& id, const pb::Hash32& parent, std::uint64_t h,
          const std::vector<pb::Placement>& pls, bool best = true) {
    b.ok = b.ok && s.add_carrier(id, parent, h) == pb::AddVerdict::Added;
    for (const pb::Placement& x : pls) b.ok = b.ok && s.ingest(id, x) == pb::Ingest::Accepted;
    b.ok = b.ok && s.seal(id).has_value();
    if (!best) return;
    pb::LaneBatch batch;
    b.ok = b.ok && s.switch_best(id, &batch) == pb::SwitchVerdict::Switched;
    b.batches.push_back(std::move(batch));
}

pb::LaneLoad load(const pb::LaneKv& kv, const pb::BinStore& s) {
    const pb::LaneView v = s.view_at(s.best_tip());
    return pb::load_lane(kv, kChain, kB0, pb::kRuledLaneParams.open_bins, s.best_tip(), s.tip_pos(),
                         v.record(v.pos()));
}

}  // namespace s3b

static void s3b_lane_record_vectors() {
    using namespace s3b;
    const pb::LaneParams P = pb::kRuledLaneParams;
    const pb::XmrKeyRef ka = key_ref(0x10), kb = key_ref(0x30), kc = key_ref(0x50);

    // Branch A: bins b0 and b0 + 1 carry receipts; the record reaches b0 + 99 (4 leaves).
    pb::BinStore s(P, 64, cid(0x40, 0), kB0, kChain);
    Built a;
    pb::LaneKv kv;
    {
        pb::LaneBatch first;
        s.write_all(first);
        pb::apply_batch(kv, first);
    }
    step(s, a, cid(0x40, 1), cid(0x40, 0), kB0, {rc(1, kB0, 1, ka, 30000), rc(2, kB0, 1, kb, 20000)});
    step(s, a, cid(0x40, 2), cid(0x40, 1), kB0 + 1, {rc(3, kB0 + 1, 2, kc, 25000)});
    step(s, a, cid(0x40, 3), cid(0x40, 2), kB0 + 97, {});
    step(s, a, cid(0x40, 4), cid(0x40, 3), kB0 + 98, {});
    step(s, a, cid(0x40, 5), cid(0x40, 4), kB0 + 99, {});
    for (const pb::LaneBatch& b : a.batches) pb::apply_batch(kv, b);
    check(a.ok && s.head().leaf_count == 4, "records: branch A built, 4 leaves");

    // restart from the records equals the live root.
    const pb::LaneLoad l = load(kv, s);
    check(l.fault == pb::LoadFault::None && l.mmr.root() == s.head().root && l.mmr.leaf_count() == 4 &&
                  l.head == s.head(),
          "restart from the records equals the live root and head");
    bool bodies = l.bodies.size() == 4;
    for (std::uint64_t i = 0; bodies && i < 4; ++i)
        bodies = l.bodies[i] && pb::encode_bleaf(*l.bodies[i]) ==
                                        pb::encode_bleaf(*s.view_at(s.best_tip()).bucket(kB0 + i));
    check(bodies, "restart: every K_BLEAF decodes to the live bucket bytes (key references kept)");
    check(l.bodies.size() == 4 && l.bodies[0] && l.bodies[0]->refs.size() == 2 && l.bodies[1]->refs.size() == 1 &&
                  l.bodies[2]->refs.empty(),
          "restart: the key-reference tables (2, 1, 0 references)");
    {
        pb::LaneKv all;
        pb::LaneBatch b;
        s.write_all(b);
        pb::apply_batch(all, b);
        check(all == kv, "the incremental batches leave exactly the records of write_all");
    }

    // crash: the second of two batches is missing (the carrier store is at the newer tip).
    {
        pb::LaneKv partial;
        pb::LaneBatch first;
        pb::BinStore g(P, 64, cid(0x40, 0), kB0, kChain);
        g.write_all(first);
        pb::apply_batch(partial, first);
        for (std::size_t i = 0; i + 1 < a.batches.size(); ++i) pb::apply_batch(partial, a.batches[i]);
        const pb::LaneLoad lp = load(partial, s);
        check(lp.fault == pb::LoadFault::Tip, "crash: a store missing the second of two batches -> load refuses");
        // the rebuild path: a fresh store fed the chain reproduces the lane state.
        pb::BinStore r(P, 64, cid(0x40, 0), kB0, kChain);
        Built rb;
        step(r, rb, cid(0x40, 1), cid(0x40, 0), kB0, {rc(1, kB0, 1, ka, 30000), rc(2, kB0, 1, kb, 20000)});
        step(r, rb, cid(0x40, 2), cid(0x40, 1), kB0 + 1, {rc(3, kB0 + 1, 2, kc, 25000)});
        step(r, rb, cid(0x40, 3), cid(0x40, 2), kB0 + 97, {});
        step(r, rb, cid(0x40, 4), cid(0x40, 3), kB0 + 98, {});
        step(r, rb, cid(0x40, 5), cid(0x40, 4), kB0 + 99, {});
        pb::LaneKv rebuilt;
        pb::LaneBatch all;
        r.write_all(all);
        pb::apply_batch(rebuilt, all);
        check(rb.ok && r.head() == s.head() && load(rebuilt, r).fault == pb::LoadFault::None,
              "crash: the rebuild reproduces the head and loads");
        // control: a carrier store at the older tip loads the older state.
        const pb::LaneView v4 = s.view_at(cid(0x40, 4));
        const pb::LaneLoad lo = pb::load_lane(partial, kChain, kB0, P.open_bins, cid(0x40, 4), 4, v4.record(4));
        check(lo.fault == pb::LoadFault::None && lo.mmr.root() == v4.mmr_root(),
              "crash control: records and carrier store at the same older tip load");
    }

    // the other load refusals
    {
        const pb::LaneView v = s.view_at(s.best_tip());
        check(pb::load_lane(kv, kChain, kB0 + 1, P.open_bins, s.best_tip(), s.tip_pos(), v.record(v.pos())).fault ==
                      pb::LoadFault::B0,
              "load: another b0 refused");
        check(pb::load_lane(kv, kChain, kB0, P.open_bins, s.best_tip(), s.tip_pos(), v.record(v.pos()) + 1).fault ==
                      pb::LoadFault::LeafCount,
              "load: leaf_count != lc(H(tip_pos)) refused");
        check(pb::load_lane(kv, kChain + 1, kB0, P.open_bins, s.best_tip(), s.tip_pos(), v.record(v.pos())).fault ==
                      pb::LoadFault::NoHead,
              "load: no head");
        pb::LaneKv k2 = kv;
        k2.erase(pb::lane_keys::blhash(kChain, 2));
        check(load(k2, s).fault == pb::LoadFault::LeafHash, "load: a missing K_BLHASH refused");
        k2 = kv;
        k2.erase(pb::lane_keys::bleaf(kChain, 2));
        const pb::LaneLoad lpr = load(k2, s);
        check(lpr.fault == pb::LoadFault::None && !lpr.bodies[2] && lpr.bodies[1],
              "load: a pruned K_BLEAF loads (the leaf hash stays)");
        k2 = kv;
        k2[pb::lane_keys::blhash(kChain, 9)] = pb::encode_blhash(lf(9));
        k2[pb::lane_keys::bleaf(kChain, 4)] = kv.at(pb::lane_keys::bleaf(kChain, 3));
        const pb::LaneLoad lx = load(k2, s);
        check(lx.fault == pb::LoadFault::None && lx.cleanup.ops.size() == 2, "load: records beyond leaf_count ignored");
        pb::apply_batch(k2, lx.cleanup);
        check(k2 == kv, "load: ... and deleted by the cleanup batch");
    }

    // reorg across the folds: branch B forks at 1; its fold re-seals bin b0 with one receipt more.
    std::map<std::string, std::string> stale_a;
    for (std::uint64_t i = 0; i < 2; ++i) {
        stale_a[pb::lane_keys::blhash(kChain, i)] = kv.at(pb::lane_keys::blhash(kChain, i));
        stale_a[pb::lane_keys::bleaf(kChain, i)] = kv.at(pb::lane_keys::bleaf(kChain, i));
    }
    Built bb;
    step(s, bb, cid(0x4B, 2), cid(0x40, 1), kB0 + 1, {rc(4, kB0, 1, kc, 21000)}, false);
    step(s, bb, cid(0x4B, 3), cid(0x4B, 2), kB0 + 97, {});
    for (const pb::LaneBatch& b : bb.batches) pb::apply_batch(kv, b);
    const pb::LaneLoad lb = load(kv, s);
    check(bb.ok && s.head().leaf_count == 2 && lb.fault == pb::LoadFault::None && lb.mmr.root() == s.head().root,
          "reorg: one batch rewrites the records; the load equals the live root");
    check(kv.count(pb::lane_keys::blhash(kChain, 2)) == 0 && kv.count(pb::lane_keys::bleaf(kChain, 3)) == 0,
          "reorg: the abandoned branch's records from lc(fork) on are deleted");
    check(stale_a.at(pb::lane_keys::blhash(kChain, 0)) != kv.at(pb::lane_keys::blhash(kChain, 0)),
          "reorg: leaf 0 differs between the branches");
    {
        // a stale leaf of the abandoned branch (hash and body agree with each other).
        pb::LaneKv k3 = kv;
        k3[pb::lane_keys::blhash(kChain, 0)] = stale_a.at(pb::lane_keys::blhash(kChain, 0));
        k3[pb::lane_keys::bleaf(kChain, 0)] = stale_a.at(pb::lane_keys::bleaf(kChain, 0));
        check(load(k3, s).fault == pb::LoadFault::Root, "crash: a stale K_BLHASH / K_BLEAF(0) -> load refuses (root)");
        pb::LaneKv k4 = kv;
        k4[pb::lane_keys::bleaf(kChain, 0)] = stale_a.at(pb::lane_keys::bleaf(kChain, 0));
        check(load(k4, s).fault == pb::LoadFault::Body, "crash: a stale K_BLEAF(0) alone -> load refuses (body)");
        pb::LaneKv k5 = kv;
        k5[pb::lane_keys::bmmr(kChain)][20] ^= 1;
        check(load(k5, s).fault == pb::LoadFault::BadHead, "crash: a byte-flipped K_BMMR root -> load refuses");
    }
}

// ---------------------------------------------------------------------------
// FC_BUCKETS (S3b-3): a joiner accepts buckets with MMR proofs, never without.
// ---------------------------------------------------------------------------
static void s3b_fc_buckets_vectors() {
    constexpr std::uint64_t b0 = 3500000;
    constexpr std::uint32_t chain = 7;
    const std::uint64_t F = pb::kRuledLaneParams.open_bins;
    std::map<std::uint64_t, pb::SealedBin> held;
    pb::BinMmr m;
    for (std::uint64_t i = 0; i < 8; ++i) {
        const pb::XmrKeyRef k = key_ref(static_cast<std::uint8_t>(0x10 + 0x11 * i));
        pb::WinEntry e;
        e.miner = pb::key_ref_identity(k);
        e.work = 18180 + 1000 * i;
        pb::SealedBin sb;
        sb.bucket = pb::seal_from_entries(b0 + i, {e});
        sb.leaf = pb::mmr_leaf_of(sb.bucket);
        sb.refs = {k};
        m.append(sb.leaf);
        held.emplace(b0 + i, sb);
    }
    pb::BucketServeSource src;
    src.b0 = b0;
    src.leaf_count = 8;
    src.mmr = &m;
    src.bucket = [&held](std::uint64_t bin) -> const pb::SealedBin* {
        const auto it = held.find(bin);
        return it == held.end() ? nullptr : &it->second;
    };
    const pb::GetBuckets req{chain, rep(0x31), b0, b0 + 7};
    const std::uint64_t frame = pb::bucket_wire_policy_default(16, pb::zone(16))->frame_bytes;
    const std::vector<std::vector<std::uint8_t>> fr = pb::serve_buckets_from(src, req, frame);
    pb::BucketsAnchor a;
    a.header_held = true;
    a.record = b0 + F - 1 + 8;
    a.mmr_root = m.root();
    pb::BucketsAssembly as(req, b0, F, frame);
    const pb::FrameOutcome o = as.add_frame(1, fr.at(0), a);
    bool same = as.bins().size() == 8;
    for (std::uint64_t i = 0; same && i < 8; ++i) same = as.bins().at(b0 + i).leaf == *m.leaf(i);
    check(fr.size() == 1 && o.verdict == pb::FrameVerdict::Accepted && as.complete() && same,
          "FC_BUCKETS: 8 sealed bins with MMR proofs accepted by a joiner, leaves reproduced");
    pb::BucketsReply r;
    check(pb::decode_buckets(fr.at(0), chain, r) == pb::BucketsWireError::None && r.entries.size() == 8 &&
                  pb::mmr_verify(m.root(), pb::mmr_leaf_of(r.entries[3].payload),
                                 pb::wire_proof(3, 8, r.entries[3].path, r.peaks)) &&
                  r.entries[3].path.size() == 3,
          "FC_BUCKETS: the proof of bin 3 of 8 from the wire (3 siblings) verifies");
    if (r.entries.size() == 8) r.entries[3].path.clear();
    pb::BucketsAssembly bs(req, b0, F, frame);
    const pb::FrameOutcome no = bs.add_frame(1, *pb::encode_buckets(r), a);
    check(no.verdict == pb::FrameVerdict::Refused && no.fault == pb::BucketsFault::Proof && no.strike == 1 &&
                  bs.bins().empty(),
          "FC_BUCKETS: a bucket without its proof refused, the server struck");
}

// A part that throws (a broken invariant) fails by name instead of aborting the KAT.
template <class Body>
static void run_part(const char* name, Body&& body) {
    try {
        body();
    } catch (const std::exception& e) {
        check(false, std::string(name) + ": exception " + e.what());
    }
}

int main() {
    master_goldens();
    run_part("MMR vectors", s3b_mmr_vectors);
    run_part("lane record vectors", s3b_lane_record_vectors);
    run_part("FC_BUCKETS vectors", s3b_fc_buckets_vectors);
    return finish("v37_xmr_mmr_golden_kat");
}
