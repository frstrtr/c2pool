// DASH S8 STRATUM-BINDING contract KAT.
//
// Pins the get_work() -> stratum job binding contract: the extranonce2
// (nonce64) coinbase slot geometry and the coinb1/coinb2 split/reassembly
// that partitions the miner search space. Where test_dash_work_job_targets
// pins the job-TARGET arithmetic (work.py:368-426), this pins the coinbase
// NONCE-BINDING half of the same get_work() path (work.py:21,421,436-438).
//
// ORACLE: frstrtr/p2pool-dash @9a0a609 p2pool/work.py
//   :21   COINBASE_NONCE_LENGTH = 8
//   :421  coinb1 = packed_gentx[:-payload - COINBASE_NONCE_LENGTH - 4]
//   :436  assert len(coinbase_nonce) == COINBASE_NONCE_LENGTH
//   :437  new_gentx = coinb1 + coinbase_nonce + packed_gentx[-payload-4:]
//                     ... == packed_gentx  iff coinbase_nonce == '\0'*8
// Every expected value below is derived from the oracle contract (or an
// independent Python sha256d, see each golden), NOT from the SUT: a true
// byte-parity pin, not a tautology.
//
// Pure / socket-free / node-free: no VM200/201 dashd, no live sharechain,
// no template build -- the contract is exercised on a synthetic CoinbaseLayout
// so the geometry/binding invariants stand alone from generate_transaction.

#include <gtest/gtest.h>

#include <cstddef>
#include <numeric>
#include <span>
#include <string>
#include <vector>

#include <impl/dash/coinbase_builder.hpp>  // CoinbaseLayout, split_coinb, sha256d, EXTRANONCE2_SIZE
#include <btclibs/util/strencodings.h>     // HexStr
#include <core/uint256.hpp>

using dash::coinbase::CoinbaseLayout;
using dash::coinbase::CoinbSplit;
using dash::coinbase::split_coinb;
using dash::coinbase::sha256d;
using dash::coinbase::EXTRANONCE2_SIZE;

namespace {

// Synthetic 40-byte coinbase: bytes[i] = i, with the 8-byte nonce64 slot at
// [28,36) zeroed (nonce64_offset = 40 - locktime(4) - nonce64(8) = 28), mirroring
// the real coinbase tail [... nonce64 8B][locktime 4B] for a type-0 tx.
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
    lay.ref_hash_offset = kOffset - 32;   // not exercised here; kept consistent
    return lay;
}

// Reassemble coinb1 || extranonce2 || coinb2 as a stratum miner does, then
// sha256d it -- the coinbase-hash leaf the miner feeds the merkle root.
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

const unsigned char E2_A[8] = {1, 2, 3, 4, 5, 6, 7, 8};
const unsigned char E2_B[8] = {0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xf0, 0x0d};
const unsigned char E2_ZERO[8] = {0, 0, 0, 0, 0, 0, 0, 0};

}  // namespace

// (1) Extranonce2 width == oracle COINBASE_NONCE_LENGTH (work.py:21). A width
//     mismatch silently corrupts every miner submission, so pin it hard.
TEST(DashStratumBinding, Extranonce2WidthOraclePin)
{
    EXPECT_EQ(EXTRANONCE2_SIZE, static_cast<size_t>(8));
}

// (2) Split boundary geometry (work.py:421). coinb1 is exactly bytes[:offset]
//     and coinb2 is exactly bytes[offset+8:]. Lengths pinned from the layout,
//     independent of the SUT's own hex.
TEST(DashStratumBinding, SplitBoundaryGeometry)
{
    CoinbaseLayout lay = make_layout();
    CoinbSplit s = split_coinb(lay);
    EXPECT_EQ(s.coinb1_hex.size(), kOffset * 2);                       // hex chars
    EXPECT_EQ(s.coinb2_hex.size(), (kTotal - kOffset - EXTRANONCE2_SIZE) * 2);
    // coinb1 == HexStr(bytes[:offset]); coinb2 == HexStr(bytes[offset+8:]).
    std::span<const unsigned char> b1(lay.bytes.data(), kOffset);
    std::span<const unsigned char> b2(lay.bytes.data() + kOffset + EXTRANONCE2_SIZE,
                                      kTotal - kOffset - EXTRANONCE2_SIZE);
    EXPECT_EQ(s.coinb1_hex, HexStr(b1));
    EXPECT_EQ(s.coinb2_hex, HexStr(b2));
}

// (3) Identity: reassembling coinb1 || '\0'*8 || coinb2 reproduces the coinbase
//     bytes EXACTLY (work.py:437 -- coinbase_nonce == '\0'*8 => new_gentx == gentx).
//     The zero nonce is the identity element of the binding.
TEST(DashStratumBinding, ZeroNonceIsIdentity)
{
    CoinbaseLayout lay = make_layout();
    CoinbSplit s = split_coinb(lay);
    std::span<const unsigned char> z(E2_ZERO, EXTRANONCE2_SIZE);
    EXPECT_EQ(s.coinb1_hex + HexStr(z) + s.coinb2_hex, HexStr(lay.bytes));
    // ...and the reassembled bytes equal the original coinbase byte-for-byte.
    EXPECT_EQ(reassemble(lay, z), lay.bytes);
}

// (4) Slot isolation: across distinct extranonce2 values, coinb1 and coinb2 are
//     invariant and ONLY the 8 slot bytes move -- the reason a miner fetches
//     coinb1/coinb2 once per job and iterates just the slot.
TEST(DashStratumBinding, SlotIsolation)
{
    CoinbaseLayout lay = make_layout();
    auto a = reassemble(lay, std::span<const unsigned char>(E2_A, 8));
    auto b = reassemble(lay, std::span<const unsigned char>(E2_B, 8));
    ASSERT_EQ(a.size(), lay.bytes.size());
    ASSERT_EQ(b.size(), lay.bytes.size());
    for (size_t i = 0; i < a.size(); ++i) {
        if (i >= kOffset && i < kOffset + EXTRANONCE2_SIZE) continue;  // slot: may differ
        EXPECT_EQ(a[i], b[i]) << "byte " << i << " outside slot must be invariant";
    }
    // slot region carries the supplied extranonce2 verbatim.
    for (size_t i = 0; i < EXTRANONCE2_SIZE; ++i) {
        EXPECT_EQ(a[kOffset + i], E2_A[i]);
        EXPECT_EQ(b[kOffset + i], E2_B[i]);
    }
}

// (5) Binding injectivity: distinct extranonce2 -> distinct coinbase hash, and
//     each differs from the zero-slot leaf. This is the search-space PARTITION
//     guarantee -- overlapping leaves would let two miners claim one solution.
TEST(DashStratumBinding, BindingInjectivity)
{
    CoinbaseLayout lay = make_layout();
    uint256 h0 = hash_of(reassemble(lay, std::span<const unsigned char>(E2_ZERO, 8)));
    uint256 hA = hash_of(reassemble(lay, std::span<const unsigned char>(E2_A, 8)));
    uint256 hB = hash_of(reassemble(lay, std::span<const unsigned char>(E2_B, 8)));
    EXPECT_NE(hA, hB);
    EXPECT_NE(hA, h0);
    EXPECT_NE(hB, h0);
}

// (6) Golden sha256d byte-parity anchors. Expected values computed independently
//     in Python (hashlib sha256d, big-endian display), NOT from the SUT:
//       base = bytes(range(40)); base[28:36] = 0
//       zero/A/B insert '\0'*8 / 01..08 / deadbeefcafef00d at [28:36)
TEST(DashStratumBinding, GoldenLeafHashes)
{
    CoinbaseLayout lay = make_layout();
    EXPECT_EQ(hash_of(reassemble(lay, std::span<const unsigned char>(E2_ZERO, 8))).GetHex(),
              "b0d22de8e7f6765f9d8c289ecd77ad8e0ab6a88c2a4ccf594c509d7775bb54ab");
    EXPECT_EQ(hash_of(reassemble(lay, std::span<const unsigned char>(E2_A, 8))).GetHex(),
              "9bdc1a3b7b8600535e99c5298b6cb50fde48bd1b20a1ad6883abfbb2799b1b0e");
    EXPECT_EQ(hash_of(reassemble(lay, std::span<const unsigned char>(E2_B, 8))).GetHex(),
              "a0acea5d125dd3452a24dd84c0d1245450dd237cfe0bc0170d4381195e5f8061");
}
