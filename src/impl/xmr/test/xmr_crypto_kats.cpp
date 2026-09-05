// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/test/xmr_crypto_kats.cpp  --  X1 KAT: vendored Monero hash prims
//
// Known-Answer Tests for the *light* vendored Monero-crypto primitives that the
// XMR settlement lane depends on and that build WITHOUT libsodium / RandomX /
// boost: Keccak-256 (cn_fast_hash), the CryptoNote transaction/tree hash
// (tree-hash.c), and the CryptoNote varint (LEB128) codec. This is its own
// harness -- nonzero exit on any failure -- mirroring src/sharechain/v37/test.
//
// VECTOR PROVENANCE (all official / real-chain, cited inline):
//   * Keccak-256("") is the published original-Keccak (pre-SHA3) empty digest,
//     the same constant Ethereum's keccak256 emits.
//   * The single-byte, 96-byte tx-hash, and tree-branch vectors are lifted from
//     REAL Monero mainnet block 3,000,000 (monerod get_block ground truth),
//     already pinned in test/x0-kat-3000000.json by X0. Reproduced here as
//     literals so the KAT has no file/JSON dependency.
//   * The varint vectors are the canonical CryptoNote LEB128 encodings.
// ---------------------------------------------------------------------------
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "xmr_crypto_types.hpp"      // Hash256
#include "xmr_keccak_midstate.hpp"   // keccak256() == cn_fast_hash
#include "xmr_blob.hpp"              // tree_root / TreeBranch / verify_branch
#include "vendor/varint.h"          // tools::write_varint / read_varint

using xmr::coin::Hash256;

namespace {

int g_fail = 0;
#define CHECK(cond, ...) do { \
    bool _ok = (cond); \
    std::printf("  [%s] ", _ok ? "PASS" : "FAIL"); \
    std::printf(__VA_ARGS__); std::printf("\n"); \
    if (!_ok) ++g_fail; \
} while (0)

std::vector<unsigned char> unhex(const std::string& h) {
    std::vector<unsigned char> o;
    o.reserve(h.size() / 2);
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    for (std::size_t i = 0; i + 1 < h.size(); i += 2)
        o.push_back(static_cast<unsigned char>((nib(h[i]) << 4) | nib(h[i + 1])));
    return o;
}
std::string hex(const unsigned char* b, std::size_t n) {
    static const char* d = "0123456789abcdef";
    std::string s; s.reserve(n * 2);
    for (std::size_t i = 0; i < n; ++i) { s.push_back(d[b[i] >> 4]); s.push_back(d[b[i] & 0xf]); }
    return s;
}
Hash256 h256(const std::string& hexstr) {
    Hash256 h{};
    auto v = unhex(hexstr);
    std::memcpy(h.data(), v.data(), v.size() < 32 ? v.size() : 32);
    return h;
}
std::string hx(const Hash256& h) { return hex(h.data(), 32); }

// ---- real Monero mainnet block 3,000,000 (x0-kat-3000000.json ground truth) --
const char* kBlkH_prefix    = "18b7efb2ab347082fc161ff480b0554dbf94de87251e676d8b67d7f5d9173b24";
const char* kBlkH_rct_base  = "bc36789e7a1e281436464229828f817d6612f7b477d66591ff96a9e064bcc98a";
const char* kBlkH_prunable  = "0000000000000000000000000000000000000000000000000000000000000000";
const char* kBlkMinerTxHash = "7f88a52afdab303ddb9d444cb5b53adb5a12c63a82e898a9d2db9f76dd1127f6";
const char* kBlkTreeRoot    = "3cc88694451e92299e5283b2c51985e5c0d31b8d910f53d9a8b167a24e7bdf06";
// tree_branch for leaf 0 (the coinbase): depth 5, path bits 00000, 38 txs.
const char* kBlkBranch[5] = {
    "e4516854a5984eaf5f8750ac7af41d1e0b2c602a2297a673001e8c0af88eba11",
    "160b280159f52461dcb661e49f30cae2a7f235acbdd68a8d002183b2358ed144",
    "03330ad5f7bee104763d8c19b207d52d4323d86a888229790801934c177629d3",
    "2244a793730a85480efc9301dde5045088ee4d8b61e4849ccf757ab8a99d5f44",
    "3d5a1ba12f721187cf632d75f220ee7c412420572fe6aca17cce1eecb569e93d",
};

// =====================================================================
void kats_keccak_cn_fast_hash() {
    std::printf("== Keccak-256 / cn_fast_hash ==\n");

    // (1) Empty-input original-Keccak-256 (published constant, == Ethereum keccak256("")).
    Hash256 e = xmr::coin::keccak256(nullptr, 0);
    CHECK(hx(e) == "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
          "keccak256(\"\") = %s", hx(e).c_str());

    // (2) Single 0x00 byte == the RCTTypeNull base hash of the real coinbase tx.
    unsigned char zero = 0x00;
    Hash256 rct = xmr::coin::keccak256(&zero, 1);
    CHECK(hx(rct) == kBlkH_rct_base, "keccak256(0x00) = %s (real blk3000000 H_rct_base)", hx(rct).c_str());

    // (3) 96-byte tx-hash triple: miner_tx_hash == cn_fast_hash(H_prefix||H_rct_base||H_prunable).
    std::vector<unsigned char> triple;
    for (const char* p : {kBlkH_prefix, kBlkH_rct_base, kBlkH_prunable}) {
        auto v = unhex(p); triple.insert(triple.end(), v.begin(), v.end());
    }
    Hash256 txh = xmr::coin::keccak256(triple.data(), triple.size());
    CHECK(hx(txh) == kBlkMinerTxHash, "cn_fast_hash(96B triple) = %s (real miner_tx_hash)", hx(txh).c_str());
}

// =====================================================================
void kats_tree_hash() {
    std::printf("== CryptoNote tree-hash (tree-hash.c) ==\n");

    // (4) tree_root of a single leaf is the leaf itself.
    Hash256 leaf = h256(kBlkMinerTxHash);
    Hash256 solo = xmr::coin::tree_root({leaf});
    CHECK(solo == leaf, "tree_root([leaf]) == leaf");

    // (5) tree_root of two leaves == cn_fast_hash(l0||l1).
    Hash256 l1 = h256(kBlkBranch[0]);
    std::vector<unsigned char> cat(leaf.data(), leaf.data() + 32);
    cat.insert(cat.end(), l1.data(), l1.data() + 32);
    Hash256 pair = xmr::coin::tree_root({leaf, l1});
    CHECK(pair == xmr::coin::keccak256(cat.data(), cat.size()),
          "tree_root([l0,l1]) == cn_fast_hash(l0||l1)");

    // (6) REAL block 3,000,000 coinbase branch: verify_branch(leaf0, branch, root) == true.
    xmr::coin::TreeBranch tb;
    tb.depth = 5;
    tb.path  = 0;  // path bits "00000"
    for (const char* b : kBlkBranch) tb.branch.push_back(h256(b));
    Hash256 root = h256(kBlkTreeRoot);
    CHECK(xmr::coin::verify_branch(leaf, tb, root), "verify_branch(coinbase, blk3000000) == true");

    // (7) Negative: a flipped leaf must NOT verify (guards a silent-accept bug).
    Hash256 bad = leaf; bad.bytes[0] ^= 0x01;
    CHECK(!xmr::coin::verify_branch(bad, tb, root), "verify_branch(tampered leaf) == false");
}

// =====================================================================
void kats_varint() {
    std::printf("== CryptoNote varint (LEB128) codec (varint.h) ==\n");

    struct V { std::uint64_t value; const char* enc; };
    // Canonical CryptoNote LEB128: 7 bits/byte, little-endian, MSB = continue.
    const V vs[] = {
        { 0ULL,          "00" },
        { 127ULL,        "7f" },
        { 128ULL,        "8001" },
        { 300ULL,        "ac02" },
        { 16384ULL,      "808001" },
        { 0xFFFFFFFFULL, "ffffffff0f" },
        { 0x80000000000ULL, "80808080808002" },
    };
    for (const V& v : vs) {
        std::string enc;
        tools::write_varint(std::back_inserter(enc), v.value);
        std::string got = hex(reinterpret_cast<const unsigned char*>(enc.data()), enc.size());
        bool enc_ok = (got == v.enc);

        std::uint64_t back = 0;
        int n = tools::read_varint(enc.begin(), enc.end(), back);
        bool rt_ok = (n == static_cast<int>(enc.size())) && (back == v.value);

        CHECK(enc_ok && rt_ok, "varint(%llu) = %s  round-trip=%llu",
              (unsigned long long)v.value, got.c_str(), (unsigned long long)back);
    }
}

} // namespace

int main() {
    std::printf("=== xmr_crypto_kats (keccak / cn_fast_hash / tree-hash / varint) ===\n");
    kats_keccak_cn_fast_hash();
    kats_tree_hash();
    kats_varint();
    std::printf("%s (%d failure%s)\n", g_fail ? "KAT FAILED" : "KAT OK",
                g_fail, g_fail == 1 ? "" : "s");
    return g_fail ? 1 : 0;
}
