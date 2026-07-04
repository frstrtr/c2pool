// DASH S8 STRATUM-BINDING contract KAT -- job-notify ROUND-TRIP leaf.
//
// The final leaf of the S8 stratum-binding suite. Where test_dash_stratum_binding
// pins the coinbase NONCE slot geometry (the get_work()->job half) and
// test_dash_work_job_targets pins the job TARGET arithmetic, THIS pins the
// notify->submit seam: the merkle_branch the pool sends ONCE per job must fold
// the miner's reassembled coinbase back to the SAME canonical merkle root the
// pool computes over the full tx list. That equality is the whole reason a
// miner can iterate extranonce2 locally without re-fetching the job -- if the
// branch did not bind, every submit would carry a root the pool rejects.
//
// ORACLE: frstrtr/p2pool-dash @9a0a609
//   dash/stratum.py  -- mining.notify packs merkle branch as
//        [pack.IntType(256).pack(s).encode('hex') for s in link.branch]
//        i.e. LE internal bytes as hex (NOT the reversed display form).
//   p2pool/work.py   -- coinb1/coinb2 split at the nonce64 slot (:421,:436-437).
// Every expected value below is derived from an INDEPENDENT Python sha256d
// merkle walk (see the golden block), NOT from the SUT: a true byte-parity pin.
//
// Pure / socket-free / node-free: synthetic coinbase + synthetic sibling tx
// hashes, no dashd, no live sharechain, no template build. The round-trip
// invariant stands alone from generate_transaction / the stratum server.

#include <gtest/gtest.h>

#include <cstddef>
#include <cstring>
#include <numeric>
#include <span>
#include <string>
#include <vector>

#include <impl/dash/coinbase_builder.hpp>  // split_coinb, merkle_branches_raw/hex, sha256d, EXTRANONCE2_SIZE
#include <btclibs/util/strencodings.h>     // HexStr
#include <core/uint256.hpp>

using dash::coinbase::CoinbaseLayout;
using dash::coinbase::CoinbSplit;
using dash::coinbase::split_coinb;
using dash::coinbase::sha256d;
using dash::coinbase::merkle_branches_raw;
using dash::coinbase::merkle_branches_hex;
using dash::coinbase::EXTRANONCE2_SIZE;

namespace {

// Synthetic 40-byte coinbase identical to test_dash_stratum_binding: bytes[i]=i
// with the 8-byte nonce64 slot at [28,36) zeroed. (Leaf0 goldens below MATCH
// that sibling test, confirming a shared layout.)
constexpr size_t kTotal  = 40;
constexpr size_t kOffset = 28;   // = kTotal - 4 - 8

CoinbaseLayout make_layout()
{
    CoinbaseLayout lay;
    lay.bytes.resize(kTotal);
    std::iota(lay.bytes.begin(), lay.bytes.end(), static_cast<unsigned char>(0));
    for (size_t i = kOffset; i < kOffset + EXTRANONCE2_SIZE; ++i)
        lay.bytes[i] = 0x00;
    lay.nonce64_offset  = kOffset;
    lay.ref_hash_offset = kOffset - 32;
    return lay;
}

std::vector<unsigned char> reassemble(const CoinbaseLayout& lay,
                                      std::span<const unsigned char> e2)
{
    std::vector<unsigned char> cb;
    cb.reserve(lay.bytes.size());
    cb.insert(cb.end(), lay.bytes.begin(), lay.bytes.begin() + lay.nonce64_offset);
    cb.insert(cb.end(), e2.begin(), e2.end());
    cb.insert(cb.end(), lay.bytes.begin() + lay.nonce64_offset + EXTRANONCE2_SIZE,
              lay.bytes.end());
    return cb;
}

uint256 hash_of(const std::vector<unsigned char>& b)
{
    return sha256d(std::span<const unsigned char>(b.data(), b.size()));
}

// Synthetic sibling tx hashes (indices 1..3 of the merkle tree). Values are
// arbitrary but fixed; the Python oracle uses the same sha256d(bytes([v]*4)).
uint256 mk_tx(unsigned char v)
{
    std::vector<unsigned char> b(4, v);
    return sha256d(std::span<const unsigned char>(b.data(), b.size()));
}

// Pool-side canonical merkle root over [coinbase_leaf, h1, h2, h3] -- computed
// in-test, independent of merkle_branches_raw, so the round-trip check is not a
// tautology against the SUT branch.
uint256 canonical_root(uint256 leaf0, uint256 h1, uint256 h2, uint256 h3)
{
    std::vector<uint256> layer{leaf0, h1, h2, h3};
    while (layer.size() > 1) {
        if (layer.size() % 2 == 1) layer.push_back(layer.back());
        std::vector<uint256> next;
        for (size_t i = 0; i + 1 < layer.size(); i += 2) {
            std::vector<unsigned char> buf(64);
            std::memcpy(buf.data(),      layer[i].data(),     32);
            std::memcpy(buf.data() + 32, layer[i + 1].data(), 32);
            next.push_back(sha256d(std::span<const unsigned char>(buf.data(), buf.size())));
        }
        layer.swap(next);
    }
    return layer[0];
}

// Miner-side walk: fold the coinbase leaf through the branch siblings, exactly
// as cpuminer does with the mining.notify merkle_branch. root = leaf; for each
// sibling s: root = sha256d(root || s).
uint256 miner_root(uint256 leaf0, const std::vector<uint256>& branch)
{
    uint256 r = leaf0;
    for (const auto& s : branch) {
        std::vector<unsigned char> buf(64);
        std::memcpy(buf.data(),      r.data(), 32);
        std::memcpy(buf.data() + 32, s.data(), 32);
        r = sha256d(std::span<const unsigned char>(buf.data(), buf.size()));
    }
    return r;
}

const unsigned char E2_A[8]    = {1, 2, 3, 4, 5, 6, 7, 8};
const unsigned char E2_B[8]    = {0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xf0, 0x0d};
const unsigned char E2_ZERO[8] = {0, 0, 0, 0, 0, 0, 0, 0};

// The branch the pool computes ONCE per job, from the placeholder coinbase
// (slot 0 == zero-hash) plus the three sibling tx hashes. Siblings are
// independent of leaf 0, which is exactly what makes the branch reusable.
std::vector<uint256> job_branch()
{
    std::vector<uint256> leaves{uint256::ZERO, mk_tx(0xa1), mk_tx(0xb2), mk_tx(0xc3)};
    return merkle_branches_raw(leaves);
}

}  // namespace

// (1) The notify branch has the expected depth for a 4-leaf tree: two siblings
//     (one per merkle level). A wrong-depth branch silently mis-binds.
TEST(DashJobNotifyRoundTrip, BranchDepth)
{
    EXPECT_EQ(job_branch().size(), static_cast<size_t>(2));
}

// (2) ROUND-TRIP core: for the zero extranonce2 (identity), the miner walk over
//     the notify branch reproduces the pool canonical root byte-for-byte.
TEST(DashJobNotifyRoundTrip, ZeroNonceRootMatches)
{
    CoinbaseLayout lay = make_layout();
    uint256 h1 = mk_tx(0xa1), h2 = mk_tx(0xb2), h3 = mk_tx(0xc3);
    uint256 leaf0 = hash_of(reassemble(lay, std::span<const unsigned char>(E2_ZERO, 8)));
    EXPECT_EQ(miner_root(leaf0, job_branch()), canonical_root(leaf0, h1, h2, h3));
}

// (3) ROUND-TRIP under extranonce2 iteration: the SAME job branch binds every
//     distinct extranonce2 back to the matching canonical root -- the miner
//     iterates the slot without re-fetching the job.
TEST(DashJobNotifyRoundTrip, IteratedNonceRootMatches)
{
    CoinbaseLayout lay = make_layout();
    uint256 h1 = mk_tx(0xa1), h2 = mk_tx(0xb2), h3 = mk_tx(0xc3);
    const std::vector<uint256> br = job_branch();
    for (const auto* e2 : {E2_A, E2_B}) {
        uint256 leaf0 = hash_of(reassemble(lay, std::span<const unsigned char>(e2, 8)));
        EXPECT_EQ(miner_root(leaf0, br), canonical_root(leaf0, h1, h2, h3));
    }
}

// (4) Distinct extranonce2 -> distinct block merkle root: the notify branch
//     PARTITIONS the search space rather than collapsing it (overlapping roots
//     would let two miners claim one solution).
TEST(DashJobNotifyRoundTrip, RootInjectivity)
{
    CoinbaseLayout lay = make_layout();
    const std::vector<uint256> br = job_branch();
    uint256 r0 = miner_root(hash_of(reassemble(lay, std::span<const unsigned char>(E2_ZERO, 8))), br);
    uint256 rA = miner_root(hash_of(reassemble(lay, std::span<const unsigned char>(E2_A, 8))), br);
    uint256 rB = miner_root(hash_of(reassemble(lay, std::span<const unsigned char>(E2_B, 8))), br);
    EXPECT_NE(rA, rB);
    EXPECT_NE(rA, r0);
    EXPECT_NE(rB, r0);
}

// (5) Wire form of the merkle branch is LE internal-bytes hex (stratum.py
//     convention), NOT the reversed display form. Golden hex from independent
//     Python (pack.IntType(256).pack(s).encode(hex)).
TEST(DashJobNotifyRoundTrip, BranchWireHexGolden)
{
    std::vector<std::string> hex = merkle_branches_hex(job_branch());
    ASSERT_EQ(hex.size(), static_cast<size_t>(2));
    EXPECT_EQ(hex[0], "f8401cfffc19b3a56c2de52278297152d9028b4efbc30f8d2096f780ceb0b2b6");
    EXPECT_EQ(hex[1], "6f43268501a527c6adc37e7d6a293168c42f9aae863ab15628ab78ddf9ec836c");
}

// (6) Golden merkle-root byte-parity anchors (GetHex display form), computed
//     independently in Python over [sha256d(coinbase_e2), h1, h2, h3]:
//       h_i   = sha256d(bytes([0xa1/0xb2/0xc3]*4))
//       leaf0 = sha256d(base[:28] + e2 + base[36:]),  base = bytes(range(40)) w/ [28:36]=0
TEST(DashJobNotifyRoundTrip, CanonicalRootGolden)
{
    CoinbaseLayout lay = make_layout();
    uint256 h1 = mk_tx(0xa1), h2 = mk_tx(0xb2), h3 = mk_tx(0xc3);
    auto root_for = [&](const unsigned char* e2) {
        return canonical_root(
            hash_of(reassemble(lay, std::span<const unsigned char>(e2, 8))), h1, h2, h3);
    };
    EXPECT_EQ(root_for(E2_ZERO).GetHex(),
              "b4bfbae433a5f984c30f4bead3cfe650a0e770bd8126b5c16a15b4b5b9243189");
    EXPECT_EQ(root_for(E2_A).GetHex(),
              "d445471556d06a5b2722c27f92498bf030117d756fd8fe7997d3732cf4df5e93");
    EXPECT_EQ(root_for(E2_B).GetHex(),
              "7c81c0a061417d008d0ada06bfe98d69d82ea6561ec1c327f7fb34d63259772c");
}
