// SPDX-License-Identifier: AGPL-3.0-or-later
/// Phase C-SML step 1 — Dash SimplifiedMNList (DIP-0004) unit tests
///
/// Exercises the vendored CSimplifiedMNListEntry / CSimplifiedMNList
/// (src/impl/dash/coin/vendor/simplifiedmns.hpp), the base leaf of the
/// embedded_gbt dependency chain (S7). These KATs pin the wire + hash
/// semantics that the CCbTx merkleRootMNList cross-check depends on:
///
///   - SERIALIZE_METHODS version/type field gating (v1 legacy / v2 basic /
///     v2 EVO) round-trips byte-for-byte and matches the expected length.
///   - CalcHash() builds the SER_GETHASH preimage bit-exactly: nVersion is
///     OMITTED, fields are emitted in the documented order, isValid is a
///     single byte. We rebuild the preimage by hand and double-SHA256 it
///     independently, then assert equality with CalcHash().
///   - CSimplifiedMNList::sort() uses dashcore memcmp (little-endian memory)
///     ordering, NOT c2pool uint256 integer ordering. This is the live
///     "Bug A" regression (2026-04-24 Dash-mainnet CBTX-root mismatch):
///     the two orderings disagree and the wrong one breaks every block.
///   - CalcMerkleRoot() is the standard SHA256d-pairwise / duplicate-last-
///     on-odd tree over the SORTED leaves, and is invariant to input order.
///
/// SCOPE NOTE (honest): these are structural + bit-exact-preimage +
/// regression KATs that are fully self-contained. The end-to-end
/// "CalcMerkleRoot() == the CCbTx merkleRootMNList parsed from a real Dash
/// block" cross-check (oracle: a live mnlistdiff from a Dash node) is
/// deferred to the embedded_gbt integration leaf where a real block is
/// parsed — it is NOT claimed here.

#include <gtest/gtest.h>

#include <impl/dash/coin/vendor/simplifiedmns.hpp>

#include <core/uint256.hpp>
#include <core/pack.hpp>
#include <core/hash.hpp>

#include <array>
#include <cstdint>
#include <cstring>
#include <vector>

using dash::coin::vendor::CSimplifiedMNListEntry;
using dash::coin::vendor::CSimplifiedMNList;

// ─── helpers ────────────────────────────────────────────────────────────────

// uint256 whose raw memory bytes are exactly `pattern` (memcmp order).
static uint256 raw256(const std::array<uint8_t, 32>& pattern) {
    uint256 h;
    std::memcpy(h.data(), pattern.data(), 32);
    return h;
}

// uint256 with a single nonzero byte at memory index `idx`.
static uint256 raw256_byte(size_t idx, uint8_t val) {
    std::array<uint8_t, 32> p{};
    p[idx] = val;
    return raw256(p);
}

static uint160 raw160_seq(uint8_t base) {
    uint160 h;
    std::array<uint8_t, 20> p{};
    for (size_t i = 0; i < 20; ++i) p[i] = static_cast<uint8_t>(base + i);
    std::memcpy(h.data(), p.data(), 20);
    return h;
}

// A deterministic v2-regular entry with fully-populated raw fields.
static CSimplifiedMNListEntry make_entry(uint16_t nVersion, uint16_t nType) {
    CSimplifiedMNListEntry e;
    e.nVersion = nVersion;
    std::array<uint8_t, 32> pr{}, cf{};
    for (size_t i = 0; i < 32; ++i) { pr[i] = static_cast<uint8_t>(i);
                                      cf[i] = static_cast<uint8_t>(0x40 + i); }
    e.proRegTxHash  = raw256(pr);
    e.confirmedHash = raw256(cf);
    for (size_t i = 0; i < e.netAddress.size(); ++i)
        e.netAddress[i] = static_cast<uint8_t>(i);
    e.netPort = 0x1234;
    for (size_t i = 0; i < e.pubKeyOperator.size(); ++i)
        e.pubKeyOperator[i] = static_cast<uint8_t>(0xA0 + i);
    e.keyIDVoting = raw160_seq(0x10);
    e.isValid = true;
    e.nType = nType;
    // Platform fields are serialized (and so survive a round-trip) ONLY for
    // v2+ EVO entries; for v1/regular they are wire-absent, so leave them at
    // defaults — otherwise EXPECT_EQ(e, roundtrip(e)) compares phantom data
    // the wire never carried. (Matches the nVersion/nType gating above.)
    if (nVersion >= CSimplifiedMNListEntry::VER_BASIC_BLS &&
        nType == CSimplifiedMNListEntry::TYPE_EVO) {
        e.platformHTTPPort = 0x1F90;            // 8080
        e.platformNodeID = raw160_seq(0x60);
    }
    return e;
}

template <typename T>
static CSimplifiedMNListEntry roundtrip(const T& e, size_t* wire_len) {
    auto ps = ::pack(e);
    if (wire_len) *wire_len = ps.size();
    CSimplifiedMNListEntry out;
    ps >> out;
    return out;
}

// ─── KAT 1: version/type field gating round-trips + length ──────────────────

TEST(DashSimplifiedMNS, RoundTripV1Legacy) {
    // nVersion < VER_BASIC_BLS → nType NOT serialized, no platform fields.
    // base = nVersion(2) + proReg(32) + confirmed(32) + netAddr(16) +
    //        port(2) + pubkey(48) + keyID(20) + isValid(1) = 153
    auto e = make_entry(CSimplifiedMNListEntry::VER_LEGACY_BLS,
                        CSimplifiedMNListEntry::TYPE_REGULAR);
    size_t len = 0;
    auto out = roundtrip(e, &len);
    EXPECT_EQ(len, 153u);
    EXPECT_EQ(e, out);
}

TEST(DashSimplifiedMNS, RoundTripV2Regular) {
    // nVersion >= VER_BASIC_BLS, nType == REGULAR → +nType(2), no platform.
    auto e = make_entry(CSimplifiedMNListEntry::VER_BASIC_BLS,
                        CSimplifiedMNListEntry::TYPE_REGULAR);
    size_t len = 0;
    auto out = roundtrip(e, &len);
    EXPECT_EQ(len, 155u);
    EXPECT_EQ(e, out);
}

TEST(DashSimplifiedMNS, RoundTripV2Evo) {
    // nVersion (2) < VER_EXT_ADDR and nType == EVO → +platformHTTPPort(2)
    // +platformNodeID(20). 155 + 2 + 20 = 177.
    auto e = make_entry(CSimplifiedMNListEntry::VER_BASIC_BLS,
                        CSimplifiedMNListEntry::TYPE_EVO);
    size_t len = 0;
    auto out = roundtrip(e, &len);
    EXPECT_EQ(len, 177u);
    EXPECT_EQ(e, out);
    EXPECT_EQ(out.platformHTTPPort, 0x1F90);
    EXPECT_EQ(out.platformNodeID, e.platformNodeID);
}

// ─── KAT 2: CalcHash() preimage is bit-exact (SER_GETHASH) ──────────────────

TEST(DashSimplifiedMNS, CalcHashPreimageBitExact) {
    // Build a v2-regular entry, reconstruct the SER_GETHASH preimage by
    // hand, double-SHA256 it independently, and assert == CalcHash().
    // nType is set to 0 so its two LE/BE-ambiguous bytes are both 0x00,
    // keeping the preimage byte-order unambiguous.
    auto e = make_entry(CSimplifiedMNListEntry::VER_BASIC_BLS,
                        CSimplifiedMNListEntry::TYPE_REGULAR);

    std::vector<unsigned char> pre;
    auto push = [&](const unsigned char* p, size_t n) {
        pre.insert(pre.end(), p, p + n);
    };
    // OMIT nVersion (SER_GETHASH), then documented order:
    push(e.proRegTxHash.data(), 32);
    push(e.confirmedHash.data(), 32);
    push(e.netAddress.data(), 16);
    pre.push_back(0x12); pre.push_back(0x34);           // netPort big-endian
    push(e.pubKeyOperator.data(), 48);
    push(e.keyIDVoting.data(), 20);
    pre.push_back(0x01);                                // isValid == true
    // nVersion >= VER_BASIC_BLS → nType (==0) two bytes; nType != EVO so
    // no platform fields.
    pre.push_back(0x00); pre.push_back(0x00);

    uint256 expected;
    CHash256()
        .Write(std::span<const unsigned char>(pre.data(), pre.size()))
        .Finalize(std::span<unsigned char>(expected.data(), 32));

    EXPECT_EQ(e.CalcHash(), expected);
    // determinism
    EXPECT_EQ(e.CalcHash(), e.CalcHash());
}

TEST(DashSimplifiedMNS, CalcHashOmitsVersion) {
    // Two entries identical in every HASHED field but with different
    // nVersion (both >= VER_BASIC_BLS so the conditional branches match)
    // must hash identically, proving nVersion is excluded from the preimage.
    auto a = make_entry(CSimplifiedMNListEntry::VER_BASIC_BLS,
                        CSimplifiedMNListEntry::TYPE_REGULAR);
    auto b = a;
    b.nVersion = CSimplifiedMNListEntry::VER_EXT_ADDR;   // 3, still regular
    EXPECT_EQ(a.CalcHash(), b.CalcHash());
}

// ─── KAT 3: sort uses memcmp order, NOT integer order (Bug A guard) ─────────

TEST(DashSimplifiedMNS, SortIsMemcmpNotIntegerOrder) {
    // hashLo: memory byte[0] = 0x01  → integer value 1 (byte 0 is LSB)
    //         memcmp first byte 0x01
    // hashHi: memory byte[31] = 0x01 → integer value 2^248
    //         memcmp first byte 0x00
    // memcmp order:  hashHi (0x00...) < hashLo (0x01...)
    // integer order: hashLo (1)      < hashHi (2^248)   — OPPOSITE
    uint256 hashLo = raw256_byte(0, 0x01);
    uint256 hashHi = raw256_byte(31, 0x01);

    auto eLo = make_entry(CSimplifiedMNListEntry::VER_BASIC_BLS,
                          CSimplifiedMNListEntry::TYPE_REGULAR);
    auto eHi = eLo;
    eLo.proRegTxHash = hashLo;
    eHi.proRegTxHash = hashHi;

    // Insert integer-ascending (eLo first); a correct memcmp sort must
    // REORDER so eHi (memcmp-smaller) comes first.
    std::vector<CSimplifiedMNListEntry> v{eLo, eHi};
    CSimplifiedMNList sml(std::move(v));

    ASSERT_EQ(sml.size(), 2u);
    // memcmp-smallest first:
    EXPECT_LT(std::memcmp(sml.mnList[0].proRegTxHash.data(),
                          sml.mnList[1].proRegTxHash.data(), 32), 0);
    EXPECT_EQ(sml.mnList[0].proRegTxHash, hashHi);   // 0x00...01 sorts first
    EXPECT_EQ(sml.mnList[1].proRegTxHash, hashLo);
}

// ─── KAT 4: merkle root — empty / single / pair / duplicate-last ────────────

static uint256 dsha_pair(const uint256& a, const uint256& b) {
    uint256 out;
    CHash256()
        .Write(std::span<const unsigned char>(a.data(), 32))
        .Write(std::span<const unsigned char>(b.data(), 32))
        .Finalize(std::span<unsigned char>(out.data(), 32));
    return out;
}

TEST(DashSimplifiedMNS, MerkleRootEmptyIsZero) {
    CSimplifiedMNList sml;
    EXPECT_EQ(sml.CalcMerkleRoot(), uint256::ZERO);
}

TEST(DashSimplifiedMNS, MerkleRootSingleIsLeafHash) {
    auto e = make_entry(CSimplifiedMNListEntry::VER_BASIC_BLS,
                        CSimplifiedMNListEntry::TYPE_REGULAR);
    std::vector<CSimplifiedMNListEntry> v{e};
    CSimplifiedMNList sml(std::move(v));
    EXPECT_EQ(sml.CalcMerkleRoot(), e.CalcHash());
}

TEST(DashSimplifiedMNS, MerkleRootPairAndDuplicateLastOnOdd) {
    // three distinct entries; sort is by proRegTxHash memcmp order.
    auto e0 = make_entry(CSimplifiedMNListEntry::VER_BASIC_BLS,
                         CSimplifiedMNListEntry::TYPE_REGULAR);
    auto e1 = e0; auto e2 = e0;
    e0.proRegTxHash = raw256_byte(0, 0x01);
    e1.proRegTxHash = raw256_byte(0, 0x02);
    e2.proRegTxHash = raw256_byte(0, 0x03);

    std::vector<CSimplifiedMNListEntry> v{e2, e0, e1};   // shuffled input
    CSimplifiedMNList sml(std::move(v));

    // sorted leaves (memcmp ascending → e0,e1,e2)
    uint256 l0 = e0.CalcHash(), l1 = e1.CalcHash(), l2 = e2.CalcHash();
    // odd count → duplicate last (l2,l2)
    uint256 h01 = dsha_pair(l0, l1);
    uint256 h22 = dsha_pair(l2, l2);
    uint256 expected = dsha_pair(h01, h22);

    EXPECT_EQ(sml.CalcMerkleRoot(), expected);
}

TEST(DashSimplifiedMNS, MerkleRootInvariantToInputOrder) {
    auto e0 = make_entry(CSimplifiedMNListEntry::VER_BASIC_BLS,
                         CSimplifiedMNListEntry::TYPE_REGULAR);
    auto e1 = e0; auto e2 = e0; auto e3 = e0;
    e0.proRegTxHash = raw256_byte(0, 0x0A);
    e1.proRegTxHash = raw256_byte(0, 0x0B);
    e2.proRegTxHash = raw256_byte(5, 0x01);
    e3.proRegTxHash = raw256_byte(31, 0x07);

    CSimplifiedMNList a(std::vector<CSimplifiedMNListEntry>{e0, e1, e2, e3});
    CSimplifiedMNList b(std::vector<CSimplifiedMNListEntry>{e3, e2, e1, e0});
    EXPECT_EQ(a.CalcMerkleRoot(), b.CalcMerkleRoot());
}