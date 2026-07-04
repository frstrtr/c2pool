// DASH S8 STRATUM-BINDING contract KAT -- mining.submit REASSEMBLY leaf.
//
// Closes the subscribe -> notify -> SUBMIT triangle. The sibling leaves pin the
// pool->miner half: test_dash_stratum_binding (get_work nonce slot geometry),
// test_dash_stratum_extranonce_split (coinb1/coinb2 split the server ships), and
// test_dash_job_notify_roundtrip (the once-per-job merkle_branch folds back to
// the canonical root). THIS pins the miner->pool half: given a submit
// (extranonce2, ntime, nonce), the pool must reconstruct the EXACT 80-byte block
// header whose sha256d IS the share/block identity -- and the coinbase it
// reassembles under that extranonce2 must match the notify goldens byte-for-byte.
// If reassembly diverged by one byte or one field-endianness, the pool would
// hash a header the miner never solved and reject every valid submit.
//
// Landed producers bound (NOT reimplemented):
//   * dash::coinbase::split_coinb   (src/impl/dash/coinbase_builder.hpp) --
//     the coinb1/coinb2 the miner reassembles across its extranonce2.
//   * dash::coinbase::merkle_branches_raw -- the once-per-job branch the miner
//     folds its reassembled coinbase leaf through to the block merkle root.
// Header field order + endianness mirror the landed submit verifier
// share_check.hpp:306-321 exactly: PackStream serializes uint256 as its 32 raw
// internal bytes (uint256::Serialize) and each uint32 little-endian, i.e. the
// canonical 80B header  version_LE || prevhash || merkle_root || ntime_LE ||
// nbits_LE || nonce_LE. The share identity pinned here is sha256d(header) -- the
// value the Stratum submit path exposes; the X11 PoW *check* is node-plumbed
// (params.pow_func) and deliberately out of scope for this pure KAT.
//
// ORACLE: frstrtr/p2pool-dash @9a0a609 (dash/stratum.py mining.submit path;
// work.py coinb1/coinb2 split at the nonce64 slot). Every expected value below
// is from an INDEPENDENT Python hashlib sha256d walk (NOT the SUT): the coinbase
// goldens are byte-for-byte identical to the split/notify leaves (cross-bind),
// and the ROOT for extranonce2==0 equals the notify leaf`s canonical-root golden.
//
// Fenced: test/ + test/CMakeLists.txt only. Pure / socket-free / node-free --
// synthetic coinbase + synthetic sibling tx hashes, no dashd, no live sharechain.

#include <gtest/gtest.h>

#include <cstddef>
#include <cstring>
#include <numeric>
#include <span>
#include <string>
#include <vector>

#include <impl/dash/coinbase_builder.hpp>  // split_coinb, merkle_branches_raw, sha256d, EXTRANONCE2_SIZE
#include <btclibs/util/strencodings.h>     // ParseHex
#include <core/uint256.hpp>

using dash::coinbase::CoinbaseLayout;
using dash::coinbase::CoinbSplit;
using dash::coinbase::split_coinb;
using dash::coinbase::sha256d;
using dash::coinbase::merkle_branches_raw;
using dash::coinbase::EXTRANONCE2_SIZE;

namespace {

// Synthetic 40-byte coinbase identical to the sibling S8 leaves: bytes[i]=i with
// the 8-byte nonce64 (extranonce2) slot at [28,36) zeroed.
constexpr size_t kTotal  = 40;
constexpr size_t kOffset = 28;   // = kTotal - locktime(4) - nonce64(8)

// Fixed block-header scalars. version = the #625 injectable-version baseline.
constexpr uint32_t kVersion = 0x20000000u;
constexpr uint32_t kNbits   = 0x1e0ffff0u;
constexpr uint32_t T0 = 0x60506070u, T1 = 0x60506071u;      // ntime + neighbour
constexpr uint32_t N0 = 0x00000000u, N1 = 0x12345678u, N2 = 0x9abcdef0u;  // nonces

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

// Reassemble the coinbase the way a miner does: coinb1 || extranonce2 || coinb2,
// with coinb1/coinb2 taken from the LANDED split_coinb producer.
std::vector<unsigned char> reassemble_coinbase(const CoinbaseLayout& lay,
                                               std::span<const unsigned char> e2)
{
    CoinbSplit s = split_coinb(lay);
    std::vector<unsigned char> b1 = ParseHex(s.coinb1_hex);
    std::vector<unsigned char> b2 = ParseHex(s.coinb2_hex);
    std::vector<unsigned char> cb;
    cb.reserve(b1.size() + e2.size() + b2.size());
    cb.insert(cb.end(), b1.begin(), b1.end());
    cb.insert(cb.end(), e2.begin(), e2.end());
    cb.insert(cb.end(), b2.begin(), b2.end());
    return cb;
}

uint256 sd(std::span<const unsigned char> b) { return sha256d(b); }
uint256 sd(const std::vector<unsigned char>& b)
{
    return sha256d(std::span<const unsigned char>(b.data(), b.size()));
}

// Synthetic sibling tx hashes (leaves 1..3): sha256d(bytes([v]*4)).
uint256 mk_tx(unsigned char v)
{
    std::vector<unsigned char> b(4, v);
    return sd(b);
}

// The once-per-job notify branch over [coinbase_placeholder=0, h1, h2, h3], from
// the LANDED merkle_branches_raw. Siblings are independent of leaf 0, which is
// what lets the branch bind every extranonce2.
std::vector<uint256> job_branch()
{
    std::vector<uint256> leaves{uint256::ZERO, mk_tx(0xa1), mk_tx(0xb2), mk_tx(0xc3)};
    return merkle_branches_raw(leaves);
}

// Miner-side fold: root = leaf0; for each sibling s: root = sha256d(root || s).
uint256 fold_root(uint256 leaf0, const std::vector<uint256>& branch)
{
    uint256 r = leaf0;
    for (const auto& s : branch) {
        std::vector<unsigned char> buf(64);
        std::memcpy(buf.data(),      r.data(), 32);
        std::memcpy(buf.data() + 32, s.data(), 32);
        r = sd(buf);
    }
    return r;
}

void put_le32(std::vector<unsigned char>& out, uint32_t v)
{
    out.push_back(static_cast<unsigned char>(v         & 0xff));
    out.push_back(static_cast<unsigned char>((v >>  8) & 0xff));
    out.push_back(static_cast<unsigned char>((v >> 16) & 0xff));
    out.push_back(static_cast<unsigned char>((v >> 24) & 0xff));
}

// Assemble the canonical 80-byte header, mirroring share_check.hpp:306-321.
std::vector<unsigned char> assemble_header(const uint256& prev, const uint256& root,
                                           uint32_t ntime, uint32_t nonce)
{
    std::vector<unsigned char> h;
    h.reserve(80);
    put_le32(h, kVersion);
    h.insert(h.end(), prev.data(), prev.data() + 32);
    h.insert(h.end(), root.data(), root.data() + 32);
    put_le32(h, ntime);
    put_le32(h, kNbits);
    put_le32(h, nonce);
    return h;
}

// prevhash fixture: a real uint256 = sha256d(bytes([0x77]*4)) so it is
// reproducible by the independent Python oracle.
uint256 prev_block()
{
    std::vector<unsigned char> b(4, 0x77);
    return sd(b);
}

// Full submit reconstruction: (extranonce2, ntime, nonce) -> sha256d(header).
uint256 submit_share_hash(std::span<const unsigned char> e2, uint32_t ntime, uint32_t nonce)
{
    CoinbaseLayout lay = make_layout();
    uint256 leaf0 = sd(reassemble_coinbase(lay, e2));
    uint256 root  = fold_root(leaf0, job_branch());
    return sd(assemble_header(prev_block(), root, ntime, nonce));
}

uint256 reassembled_cbhash(std::span<const unsigned char> e2)
{
    return sd(reassemble_coinbase(make_layout(), e2));
}

const unsigned char E2_ZERO[8] = {0, 0, 0, 0, 0, 0, 0, 0};
const unsigned char E2_A[8]    = {0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8};
const unsigned char E2_B[8]    = {0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8};
std::span<const unsigned char> sp(const unsigned char* p) { return {p, 8}; }

// Independent Python hashlib goldens (GetHex display form).
// Coinbase hashes -- IDENTICAL to the split/notify leaves (byte-for-byte cross-bind).
const char* GOLD_CBHASH_Z = "b0d22de8e7f6765f9d8c289ecd77ad8e0ab6a88c2a4ccf594c509d7775bb54ab";
const char* GOLD_CBHASH_A = "22a146527ac0731341d026480042a55cee0bdb804043b570af24feb9e76f2c8b";
const char* GOLD_CBHASH_B = "04c8f4793537be307eaa2166642accc8265add0a59ccf4d01525f0ec54c6237a";
// Merkle roots -- ROOT_Z equals test_dash_job_notify_roundtrip`s canonical golden.
const char* GOLD_ROOT_Z = "b4bfbae433a5f984c30f4bead3cfe650a0e770bd8126b5c16a15b4b5b9243189";
const char* GOLD_ROOT_A = "c786028b55a1b786c4129907e1b98a2c51af7657b96da41e06f3ade68b16360c";
const char* GOLD_ROOT_B = "7b19224ce6a77db6300ba36228fcec66d5836376e29c3a19e37ee38c0e069748";
// prevhash fixture golden.
const char* GOLD_PREV = "d091f0df392e993ba3fa7d5651a73abdb2b4e726c17d7b282e38f434470776c7";
// Full 80B header for (e2=0, ntime=T0, nonce=N0).
const char* GOLD_HDR_Z_T0_N0 =
    "00000020c776074734f4382e287b7dc126e7b4b2bd3aa751567dfaa33b992e39dff091d0"
    "893124b9b5b4156ac1b52681bd70e7a050e6cfd3ea4b0fc384f9a533e4babfb4"
    "70605060f0ff0f1e00000000";
// Reconstructed share hashes sha256d(header).
const char* GOLD_SHARE_Z_T0_N0 = "80d1e297b7ed60eef357ccb4245b52b7ffe713db1582855c81c45223eeeb9037";
const char* GOLD_SHARE_A_T0_N0 = "65654070d81c526a0f611ecbfd753a8bd0dba5c1060ffeb8b42d6fd55b27f063";
const char* GOLD_SHARE_B_T0_N0 = "8e612179e3475079257edc72ed06791a9f300774b85333415eb7bfe173faa117";
const char* GOLD_SHARE_Z_T0_N1 = "9b6b5edfa16e550b02a629b1bdeefa66356fadef6985bcae35a9b88152696b96";
const char* GOLD_SHARE_Z_T0_N2 = "d2252fbc5dee017caa8bfca8945368827381439a7e7ccb72ebbe72fb04a26553";
const char* GOLD_SHARE_Z_T1_N0 = "60bf11e6fbb621e91dc9e0af806420bf2da3c8c297848b3f49e52f86911db8d8";

}  // namespace

// (1) Header geometry: exactly 80 bytes, with the miner-folded merkle root at
//     [36,68) -- the offset the PoW hash reads. Version/ntime/nbits/nonce are the
//     little-endian scalars share_check serializes; prevhash at [4,36).
TEST(DashStratumSubmitReassembly, HeaderGeometryAndFieldPlacement)
{
    uint256 root = fold_root(sd(reassemble_coinbase(make_layout(), sp(E2_ZERO))), job_branch());
    std::vector<unsigned char> h = assemble_header(prev_block(), root, T0, N0);
    ASSERT_EQ(h.size(), static_cast<size_t>(80));
    EXPECT_TRUE(std::equal(h.begin() + 4,  h.begin() + 36, prev_block().data()));  // prevhash
    EXPECT_TRUE(std::equal(h.begin() + 36, h.begin() + 68, root.data()));          // merkle root
    const unsigned char ver_le[4] = {0x00, 0x00, 0x00, 0x20};                      // kVersion LE
    EXPECT_TRUE(std::equal(h.begin(), h.begin() + 4, ver_le));
    const unsigned char nbits_le[4] = {0xf0, 0xff, 0x0f, 0x1e};                    // kNbits LE
    EXPECT_TRUE(std::equal(h.begin() + 72, h.begin() + 76, nbits_le));
}

// (2) The coinbase the submit path reassembles under each extranonce2 is
//     byte-for-byte the split/notify leaves` coinbase (cross-bind, non-circular).
TEST(DashStratumSubmitReassembly, ReassembledCoinbaseMatchesNotifyGolden)
{
    EXPECT_EQ(reassembled_cbhash(sp(E2_ZERO)).GetHex(), GOLD_CBHASH_Z);
    EXPECT_EQ(reassembled_cbhash(sp(E2_A)).GetHex(),    GOLD_CBHASH_A);
    EXPECT_EQ(reassembled_cbhash(sp(E2_B)).GetHex(),    GOLD_CBHASH_B);
}

// (3) The miner`s fold of the reassembled coinbase through the notify branch
//     reproduces the block merkle root; ROOT for extranonce2==0 is identical to
//     the notify-roundtrip leaf`s canonical-root golden.
TEST(DashStratumSubmitReassembly, MerkleRootFoldMatchesNotifyGolden)
{
    const std::vector<uint256> br = job_branch();
    EXPECT_EQ(fold_root(reassembled_cbhash(sp(E2_ZERO)), br).GetHex(), GOLD_ROOT_Z);
    EXPECT_EQ(fold_root(reassembled_cbhash(sp(E2_A)),    br).GetHex(), GOLD_ROOT_A);
    EXPECT_EQ(fold_root(reassembled_cbhash(sp(E2_B)),    br).GetHex(), GOLD_ROOT_B);
}

// (4) prevhash fixture reproduces the independent oracle value.
TEST(DashStratumSubmitReassembly, PrevBlockFixtureGolden)
{
    EXPECT_EQ(prev_block().GetHex(), GOLD_PREV);
}

// (5) Full submit reconstruction: the assembled 80B header is byte-exact and its
//     sha256d is the share identity -- for three distinct extranonce2 values.
TEST(DashStratumSubmitReassembly, ReconstructsHeaderAndShareHashGolden)
{
    uint256 root = fold_root(reassembled_cbhash(sp(E2_ZERO)), job_branch());
    EXPECT_EQ(HexStr(assemble_header(prev_block(), root, T0, N0)), GOLD_HDR_Z_T0_N0);
    EXPECT_EQ(submit_share_hash(sp(E2_ZERO), T0, N0).GetHex(), GOLD_SHARE_Z_T0_N0);
    EXPECT_EQ(submit_share_hash(sp(E2_A),    T0, N0).GetHex(), GOLD_SHARE_A_T0_N0);
    EXPECT_EQ(submit_share_hash(sp(E2_B),    T0, N0).GetHex(), GOLD_SHARE_B_T0_N0);
}

// (6) nonce is load-bearing in the header: iterating it yields distinct share
//     hashes (matching goldens) though coinbase and merkle root are unchanged.
TEST(DashStratumSubmitReassembly, NonceIteratesShareHashInjectively)
{
    uint256 s0 = submit_share_hash(sp(E2_ZERO), T0, N0);
    uint256 s1 = submit_share_hash(sp(E2_ZERO), T0, N1);
    uint256 s2 = submit_share_hash(sp(E2_ZERO), T0, N2);
    EXPECT_EQ(s1.GetHex(), GOLD_SHARE_Z_T0_N1);
    EXPECT_EQ(s2.GetHex(), GOLD_SHARE_Z_T0_N2);
    EXPECT_NE(s0, s1);
    EXPECT_NE(s0, s2);
    EXPECT_NE(s1, s2);
}

// (7) ntime is load-bearing: a neighbouring ntime yields a distinct share hash.
TEST(DashStratumSubmitReassembly, NtimeIteratesShareHash)
{
    uint256 s0 = submit_share_hash(sp(E2_ZERO), T0, N0);
    uint256 s1 = submit_share_hash(sp(E2_ZERO), T1, N0);
    EXPECT_EQ(s1.GetHex(), GOLD_SHARE_Z_T1_N0);
    EXPECT_NE(s0, s1);
}

// (8) extranonce2 propagates all the way through: coinbase -> merkle root ->
//     header -> share hash, so distinct submits are distinct block candidates.
TEST(DashStratumSubmitReassembly, Extranonce2PropagatesToShareHash)
{
    uint256 z = submit_share_hash(sp(E2_ZERO), T0, N0);
    uint256 a = submit_share_hash(sp(E2_A),    T0, N0);
    uint256 b = submit_share_hash(sp(E2_B),    T0, N0);
    EXPECT_NE(z, a);
    EXPECT_NE(z, b);
    EXPECT_NE(a, b);
}
