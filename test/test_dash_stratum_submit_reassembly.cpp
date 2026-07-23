// SPDX-License-Identifier: MIT
//
// DASH S8 stratum mining.submit reassembly contract KAT.
//
// Closes the subscribe -> notify -> submit triangle. The prior leaves pinned
// two of the three sides:
//   * #630 test_dash_stratum_binding          -- get_work extranonce2 slot geometry
//   * #631 test_dash_stratum_notify_roundtrip  -- notify merkle_branch fold -> merkle_root
//   * #633 test_dash_stratum_extranonce_split  -- subscribe coinb1/coinb2 split
// The OPEN side is submit: given a miner's (extranonce2, ntime, nonce), the
// server must reconstruct the EXACT block header whose sha256d IS the share
// hash. This leaf proves that reconstruction end-to-end:
//
//     mining.submit [extranonce2, ntime, nonce]
//        -> reassemble coinb1 || extranonce2 || coinb2   (REAL split_coinb)
//        -> sha256d -> coinbase txid                     (== #631/#633 golden)
//        -> fold notify merkle_branch (index 0)          (REAL merkle_branches_raw)
//        -> header merkle_root
//        -> assemble 80B header [version|prev|root|ntime|nbits|nonce]
//        -> sha256d -> the share/header hash
//
// It binds the REAL landed producers dash::coinbase::split_coinb() and
// dash::coinbase::merkle_branches_raw() (src/impl/dash/coinbase_builder.hpp) --
// the exact code mining.subscribe/mining.notify ship -- and mirrors the
// miner-side reassembly + fold + header assembly locally (the miner is
// cpuminer, not our code; handle_submit's compute_share_difficulty walks the
// identical reconstruction, src/core/stratum_server.cpp:877).
//
// The reconstructed coinbase is cross-checked byte-for-byte against the #631 /
// #633 golden coinbase hashes, and the header hash is pinned to independent
// Python hashlib sha256d anchors (NOT the oracle code, NOT this code) -- so the
// submit reconstruction agrees with the subscribe/notify producers on the
// coinbase, and the header hash is non-circular. extranonce2, ntime, and nonce
// are each shown to bind injectively into the header hash -- i.e. all three
// miner-supplied submit fields are load-bearing in the share the pool verifies.
//
// Oracle (frstrtr/p2pool-dash @9a0a609):
//   p2pool/work.py:474   header['merkle_root'] == check_merkle_link(hash256(gentx), link)
//   p2pool/dash/data.py block_header_type: version|prev|merkle_root|timestamp|bits|nonce
//   p2pool/dash/stratum.py rpc_submit [worker, job_id, extranonce2, ntime, nonce]
//
// Fenced: test/ + build.yml allowlist only. Non-consensus, socket-free,
// node-free -- pure synthetic CoinbaseLayout, no live node / RPC / P2P.

#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>
#include <string>
#include <vector>

#include <impl/dash/coinbase_builder.hpp>  // CoinbaseLayout, split_coinb, merkle_branches_raw, sha256d, EXTRANONCE2_SIZE
#include <btclibs/util/strencodings.h>     // HexStr, ParseHex
#include <core/uint256.hpp>

using dash::coinbase::CoinbaseLayout;
using dash::coinbase::CoinbSplit;
using dash::coinbase::split_coinb;
using dash::coinbase::merkle_branches_raw;
using dash::coinbase::sha256d;
using dash::coinbase::EXTRANONCE2_SIZE;

namespace {

// ── Coinbase fixture (identical to #630/#631/#633) ───────────────────────────
// 40-byte synthetic coinbase: bytes[i] = i, with the 8-byte nonce64
// (extranonce2) slot at [28,36). nonce64_offset = 40 - locktime(4) - nonce64(8).
constexpr size_t kTotal       = 40;
constexpr size_t kNonceOffset = 28;

CoinbaseLayout make_layout() {
    CoinbaseLayout lay;
    lay.bytes.resize(kTotal);
    for (size_t i = 0; i < kTotal; ++i) lay.bytes[i] = static_cast<unsigned char>(i);
    for (size_t i = kNonceOffset; i < kNonceOffset + EXTRANONCE2_SIZE; ++i) lay.bytes[i] = 0;
    lay.ref_hash_offset = kNonceOffset - 32;
    lay.nonce64_offset  = kNonceOffset;
    return lay;
}

// Miner-side reassembly: coinb1 || extranonce2 || coinb2 (mirror of cpuminer).
std::vector<unsigned char> reassemble(const CoinbSplit& s, std::span<const unsigned char> e2) {
    std::vector<unsigned char> b1 = ParseHex(s.coinb1_hex);
    std::vector<unsigned char> b2 = ParseHex(s.coinb2_hex);
    std::vector<unsigned char> out;
    out.reserve(b1.size() + e2.size() + b2.size());
    out.insert(out.end(), b1.begin(), b1.end());
    out.insert(out.end(), e2.begin(), e2.end());
    out.insert(out.end(), b2.begin(), b2.end());
    return out;
}

uint256 coinbase_hash(const CoinbSplit& s, std::span<const unsigned char> e2) {
    auto cb = reassemble(s, e2);
    return sha256d(std::span<const unsigned char>(cb.data(), cb.size()));
}

uint256 fill_hash(unsigned char b) { return uint256(std::vector<unsigned char>(32, b)); }

// Four-leaf tx set: coinbase placeholder at [0] + three sibling tx hashes
// (identical to #631, so the merkle_branch is the exact one mining.notify ships).
std::vector<uint256> leaves_with(const uint256& cb) {
    return { cb, fill_hash(0x11), fill_hash(0x22), fill_hash(0x33) };
}

// sha256d(left || right), 32B internal LE each -- mirrors merkle_record_type.pack.
uint256 node_hash(const uint256& l, const uint256& r) {
    std::vector<unsigned char> buf(64);
    auto lc = l.GetChars();
    auto rc = r.GetChars();
    std::memcpy(buf.data(),      lc.data(), 32);
    std::memcpy(buf.data() + 32, rc.data(), 32);
    return sha256d(std::span<const unsigned char>(buf.data(), buf.size()));
}

// Miner-side fold for coinbase leaf index 0: running hash always on the LEFT.
uint256 fold_index0(const uint256& tip, const std::vector<uint256>& branch) {
    uint256 cur = tip;
    for (const auto& sib : branch) cur = node_hash(cur, sib);
    return cur;
}

// ── 80-byte block-header fields (synthetic) ──────────────────────────────────
constexpr uint32_t VERSION = 0x20000000u;
constexpr uint32_t NBITS   = 0x1a0ffff0u;
constexpr uint32_t NTIME   = 0x6512a3f4u;
constexpr uint32_t NTIME2  = 0x6512a400u;   // distinct ntime (binding guard)
constexpr uint32_t NONCE   = 0x0000abcdu;
constexpr uint32_t NONCE2  = 0x0000abceu;   // distinct nonce (binding guard)
const char* PREV_DISPLAY =
    "00000000000000000000000000000000000000000000000000000000deadbeef";

void put_le32(std::vector<unsigned char>& b, uint32_t v) {
    b.push_back(static_cast<unsigned char>( v        & 0xff));
    b.push_back(static_cast<unsigned char>((v >>  8) & 0xff));
    b.push_back(static_cast<unsigned char>((v >> 16) & 0xff));
    b.push_back(static_cast<unsigned char>((v >> 24) & 0xff));
}

// Assemble the canonical 80-byte header and return its sha256d (the share hash).
// Layout: version(4 LE) | prev(32 internal LE) | merkle_root(32 internal LE) |
//         ntime(4 LE) | nbits(4 LE) | nonce(4 LE).
uint256 header_hash(const uint256& merkle_root, uint32_t ntime, uint32_t nonce) {
    std::vector<unsigned char> h;
    h.reserve(80);
    put_le32(h, VERSION);
    auto prev = uint256S(PREV_DISPLAY).GetChars();   // display -> internal LE
    h.insert(h.end(), prev.begin(), prev.end());
    auto root = merkle_root.GetChars();
    h.insert(h.end(), root.begin(), root.end());
    put_le32(h, ntime);
    put_le32(h, NBITS);
    put_le32(h, nonce);
    EXPECT_EQ(h.size(), 80u);
    return sha256d(std::span<const unsigned char>(h.data(), h.size()));
}

// Full reconstruction from a miner submit: (extranonce2, ntime, nonce) -> share.
uint256 reconstruct_share(const CoinbSplit& s, std::span<const unsigned char> e2,
                          uint32_t ntime, uint32_t nonce) {
    uint256 cb     = coinbase_hash(s, e2);
    auto    branch = merkle_branches_raw(leaves_with(cb));
    uint256 root   = fold_index0(cb, branch);
    return header_hash(root, ntime, nonce);
}

const std::vector<unsigned char> E2_ZERO(8, 0x00);
const std::vector<unsigned char> E2_A{0xA1,0xA2,0xA3,0xA4,0xA5,0xA6,0xA7,0xA8};
const std::vector<unsigned char> E2_B{0xB1,0xB2,0xB3,0xB4,0xB5,0xB6,0xB7,0xB8};

// Cross-bind anchors: coinbase hashes identical to #631/#633 (independent Python).
const char* GOLD_CBHASH_Z = "b0d22de8e7f6765f9d8c289ecd77ad8e0ab6a88c2a4ccf594c509d7775bb54ab";
const char* GOLD_CBHASH_A = "22a146527ac0731341d026480042a55cee0bdb804043b570af24feb9e76f2c8b";
const char* GOLD_CBHASH_B = "04c8f4793537be307eaa2166642accc8265add0a59ccf4d01525f0ec54c6237a";

// Merkle roots identical to #631 GOLD_ROOT_* (the notify leaf ships this branch).
const char* GOLD_ROOT_Z = "26f79b540fe6f2ac6fc52f37e5af5b33a61f33216bc4ec394635b24235850ea0";
const char* GOLD_ROOT_A = "4b2d0948edb39954294fd28ca3926a78f0e56990c69d4fd7530a80a40491198e";
const char* GOLD_ROOT_B = "72f7c45d5d6c65fd77053fec86d20d918681b92aba88c87f5aaa5bf7ab3a8230";

// 80-byte header-hash anchors (independent Python hashlib sha256d; display form).
const char* GOLD_HDR_Z      = "fee1d073bb4d6329a1dcc557806bde0856353ed9cc564278fb64e7c786174fe8";
const char* GOLD_HDR_A      = "6549fd53a623d482003f58bd9b309b97b86f749c6b0480eb3c74ab29fbc7058b";
const char* GOLD_HDR_B      = "1652fb9178ae66f2edb802bf9b7c3c316e2f80b1dc4bcd21cfc07386bde33742";
const char* GOLD_HDR_NTIME2 = "8dcaed61b0b47c637316436355030b3927f98042d35bc31784e5fd81a15d2495";
const char* GOLD_HDR_NONCE2 = "ebc6423bb7454bd964bd07e06fab55c4dad5af62be9f26949d3c39edcd5f0563";

} // namespace

// (1) Submit reconstructs the golden coinbase: reassembling coinb1 (from the
//     REAL split_coinb producer) || extranonce2 || coinb2 and sha256d'ing it
//     reproduces the EXACT coinbase hash the notify/split leaves golden-anchor
//     -- the submit path agrees with subscribe/notify byte-for-byte.
TEST(DashStratumSubmitReassembly, SubmitReconstructsGoldenCoinbase) {
    CoinbSplit s = split_coinb(make_layout());
    EXPECT_EQ(coinbase_hash(s, E2_ZERO).GetHex(), GOLD_CBHASH_Z);
    EXPECT_EQ(coinbase_hash(s, E2_A).GetHex(),    GOLD_CBHASH_A);
    EXPECT_EQ(coinbase_hash(s, E2_B).GetHex(),    GOLD_CBHASH_B);
}

// (2) Reconstructed merkle_root matches the #631 notify leaf: folding the REAL
//     mining.notify branch over the reassembled coinbase reproduces the exact
//     header merkle_root the notify round-trip pins.
TEST(DashStratumSubmitReassembly, ReconstructedRootMatchesNotifyLeaf) {
    CoinbSplit s = split_coinb(make_layout());
    for (auto [e2, gold] : std::vector<std::pair<std::span<const unsigned char>, const char*>>{
             {E2_ZERO, GOLD_ROOT_Z}, {E2_A, GOLD_ROOT_A}, {E2_B, GOLD_ROOT_B}}) {
        uint256 cb   = coinbase_hash(s, e2);
        auto    br   = merkle_branches_raw(leaves_with(cb));
        EXPECT_EQ(fold_index0(cb, br).GetHex(), gold);
    }
}

// (3) THE closing assertion: the full submit reconstruction -- (extranonce2,
//     ntime, nonce) -> reassembled coinbase -> folded merkle_root -> 80B header
//     -> sha256d -- yields the exact share hash pinned by an independent Python
//     golden. The subscribe->notify->submit triangle is closed.
TEST(DashStratumSubmitReassembly, ReconstructedHeaderHashesToShare) {
    CoinbSplit s = split_coinb(make_layout());
    EXPECT_EQ(reconstruct_share(s, E2_ZERO, NTIME, NONCE).GetHex(), GOLD_HDR_Z);
}

// (4) extranonce2 binds into the share: distinct extranonce2 -> distinct header
//     hash, each equal to its independent golden. The miner's nonce64 slot
//     propagates all the way into the share the pool verifies.
TEST(DashStratumSubmitReassembly, Extranonce2BindsIntoShareHash) {
    CoinbSplit s = split_coinb(make_layout());
    uint256 z = reconstruct_share(s, E2_ZERO, NTIME, NONCE);
    uint256 a = reconstruct_share(s, E2_A,    NTIME, NONCE);
    uint256 b = reconstruct_share(s, E2_B,    NTIME, NONCE);
    EXPECT_EQ(a.GetHex(), GOLD_HDR_A);
    EXPECT_EQ(b.GetHex(), GOLD_HDR_B);
    EXPECT_NE(z, a);
    EXPECT_NE(z, b);
    EXPECT_NE(a, b);
}

// (5) ntime binds into the share: same extranonce2/nonce, distinct ntime ->
//     distinct header hash. ntime is a load-bearing submit field, not decor.
TEST(DashStratumSubmitReassembly, NtimeBindsIntoShareHash) {
    CoinbSplit s = split_coinb(make_layout());
    uint256 base = reconstruct_share(s, E2_ZERO, NTIME,  NONCE);
    uint256 alt  = reconstruct_share(s, E2_ZERO, NTIME2, NONCE);
    EXPECT_EQ(base.GetHex(), GOLD_HDR_Z);
    EXPECT_EQ(alt.GetHex(),  GOLD_HDR_NTIME2);
    EXPECT_NE(base, alt);
}

// (6) nonce binds into the share: same extranonce2/ntime, distinct nonce ->
//     distinct header hash. The header nonce field is placed correctly.
TEST(DashStratumSubmitReassembly, NonceBindsIntoShareHash) {
    CoinbSplit s = split_coinb(make_layout());
    uint256 base = reconstruct_share(s, E2_ZERO, NTIME, NONCE);
    uint256 alt  = reconstruct_share(s, E2_ZERO, NTIME, NONCE2);
    EXPECT_EQ(base.GetHex(), GOLD_HDR_Z);
    EXPECT_EQ(alt.GetHex(),  GOLD_HDR_NONCE2);
    EXPECT_NE(base, alt);
}

// (7) Golden byte-parity anchors (independent Python sha256d, computed outside
//     both the oracle and this code) for coinbase, merkle_root, and header hash.
TEST(DashStratumSubmitReassembly, GoldenAnchors) {
    CoinbSplit s = split_coinb(make_layout());
    // coinbase (cross-bind to #631/#633)
    EXPECT_EQ(coinbase_hash(s, E2_ZERO).GetHex(), GOLD_CBHASH_Z);
    EXPECT_EQ(coinbase_hash(s, E2_A).GetHex(),    GOLD_CBHASH_A);
    EXPECT_EQ(coinbase_hash(s, E2_B).GetHex(),    GOLD_CBHASH_B);
    // header shares
    EXPECT_EQ(reconstruct_share(s, E2_ZERO, NTIME,  NONCE ).GetHex(), GOLD_HDR_Z);
    EXPECT_EQ(reconstruct_share(s, E2_A,    NTIME,  NONCE ).GetHex(), GOLD_HDR_A);
    EXPECT_EQ(reconstruct_share(s, E2_B,    NTIME,  NONCE ).GetHex(), GOLD_HDR_B);
    EXPECT_EQ(reconstruct_share(s, E2_ZERO, NTIME2, NONCE ).GetHex(), GOLD_HDR_NTIME2);
    EXPECT_EQ(reconstruct_share(s, E2_ZERO, NTIME,  NONCE2).GetHex(), GOLD_HDR_NONCE2);
}
