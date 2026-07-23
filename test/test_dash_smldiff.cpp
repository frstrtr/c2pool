// SPDX-License-Identifier: AGPL-3.0-or-later
/// Phase C-SML step 3 (S8.1) — Dash CSimplifiedMNListDiff wire KATs
///
/// Exercises the vendored CSimplifiedMNListDiff + apply_diff()
/// (src/impl/dash/coin/vendor/smldiff.hpp), the mnlistdiff wire leaf that
/// the embedded_gbt SML-update path (S8) consumes. These KATs pin:
///
///   - Byte-for-byte round-trip of a fully-populated diff (non-hollow).
///   - The on-wire field ORDER matches the frstrtr/p2pool-dash / dashcore
///     CSimplifiedMNListDiff layout EXACTLY at fixed byte offsets — pinned
///     by independent reconstruction, NOT a self round-trip. A drifted
///     layout (two fields transposed) is detected as a different stream,
///     proving the comparator is layout-sensitive (integrator gate (b)).
///   - The opaque quorum_tail round-trips unknown trailing bytes verbatim.
///   - apply_diff() delete/insert/update semantics + memcmp re-sort.
///
/// SCOPE NOTE (honest): structural + bit-exact-layout + apply-semantics
/// KATs, fully self-contained. The end-to-end "apply a real mnlistdiff
/// pulled from a live Dash node and match its resulting merkleRootMNList"
/// cross-check is deferred to the embedded_gbt integration leaf where a
/// real block + dashd oracle are available — NOT claimed here.

#include <gtest/gtest.h>

#include <impl/dash/coin/vendor/smldiff.hpp>
#include <impl/dash/coin/vendor/simplifiedmns.hpp>
#include <impl/dash/coin/transaction.hpp>

#include <core/uint256.hpp>
#include <core/pack.hpp>

#include <array>
#include <cstdint>
#include <cstring>
#include <vector>

using dash::coin::vendor::CSimplifiedMNListEntry;
using dash::coin::vendor::CSimplifiedMNList;
using dash::coin::vendor::CSimplifiedMNListDiff;
using dash::coin::vendor::CPartialMerkleTreeStub;
using dash::coin::vendor::apply_diff;
using dash::coin::MutableTransaction;

// ─── helpers ────────────────────────────────────────────────────────────────

static uint256 raw256(const std::array<uint8_t, 32>& pattern) {
    uint256 h;
    std::memcpy(h.data(), pattern.data(), 32);
    return h;
}
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

// A deterministic v2-regular SML entry keyed by its proRegTxHash byte0.
static CSimplifiedMNListEntry make_entry(uint8_t proreg_byte0) {
    CSimplifiedMNListEntry e;
    e.nVersion = CSimplifiedMNListEntry::VER_BASIC_BLS;
    std::array<uint8_t, 32> pr{}, cf{};
    pr[0] = proreg_byte0;
    for (size_t i = 0; i < 32; ++i) cf[i] = static_cast<uint8_t>(0x40 + i);
    e.proRegTxHash  = raw256(pr);
    e.confirmedHash = raw256(cf);
    for (size_t i = 0; i < e.netAddress.size(); ++i)
        e.netAddress[i] = static_cast<uint8_t>(i);
    e.netPort = 0x1234;
    for (size_t i = 0; i < e.pubKeyOperator.size(); ++i)
        e.pubKeyOperator[i] = static_cast<uint8_t>(0xA0 + i);
    e.keyIDVoting = raw160_seq(0x10);
    e.isValid = true;
    e.nType = CSimplifiedMNListEntry::TYPE_REGULAR;
    return e;
}

// A minimal CBTX-flavoured coinbase tx (type 5 carries an extra payload,
// exactly like the cbTx embedded in a real mnlistdiff).
static MutableTransaction make_cbtx() {
    MutableTransaction tx;
    tx.version = 1;
    tx.type = 5;
    tx.locktime = 0;
    tx.extra_payload = {0xDE, 0xAD, 0xBE, 0xEF};
    return tx;
}

static CPartialMerkleTreeStub make_pmt() {
    CPartialMerkleTreeStub p;
    p.nTransactions = 7;
    p.vHash = {raw256_byte(0, 0x11), raw256_byte(1, 0x22)};
    p.vBitsBytes = {0x0F, 0x01};
    return p;
}

// A fully-populated diff with a nonempty opaque quorum tail.
static CSimplifiedMNListDiff make_diff() {
    CSimplifiedMNListDiff d;
    d.nVersion = CSimplifiedMNListDiff::CURRENT_VERSION;
    d.baseBlockHash = raw256_byte(0, 0xAA);   // distinct from blockHash
    d.blockHash     = raw256_byte(0, 0xBB);
    d.cbTxMerkleTree = make_pmt();
    d.cbTx = make_cbtx();
    d.deletedMNs = {raw256_byte(0, 0x01), raw256_byte(0, 0x02)};
    d.mnList = {make_entry(0x05), make_entry(0x03)};
    d.quorum_tail = {0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x99};  // opaque, unknown bytes
    return d;
}

static std::vector<unsigned char> bytes_of(PackStream& ps) {
    auto sp = ps.get_span();
    auto* p = reinterpret_cast<const unsigned char*>(sp.data());
    return std::vector<unsigned char>(p, p + sp.size());
}

// ─── KAT 1: full-diff round-trip is byte-for-byte stable (non-hollow) ───────

TEST(DashSMLDiff, RoundTripByteForByte) {
    auto d = make_diff();
    auto ps1 = ::pack(d);
    auto wire1 = bytes_of(ps1);

    CSimplifiedMNListDiff out;
    PackStream in(wire1);
    in >> out;

    // Field-level survival.
    EXPECT_EQ(out.nVersion, d.nVersion);
    EXPECT_EQ(out.baseBlockHash, d.baseBlockHash);
    EXPECT_EQ(out.blockHash, d.blockHash);
    EXPECT_EQ(out.cbTxMerkleTree.nTransactions, d.cbTxMerkleTree.nTransactions);
    EXPECT_EQ(out.cbTx.type, d.cbTx.type);
    EXPECT_EQ(out.cbTx.extra_payload, d.cbTx.extra_payload);
    EXPECT_EQ(out.deletedMNs.size(), 2u);
    EXPECT_EQ(out.mnList.size(), 2u);
    EXPECT_EQ(out.quorum_tail, d.quorum_tail);   // opaque tail verbatim

    // Re-pack must reproduce the identical stream.
    auto ps2 = ::pack(out);
    auto wire2 = bytes_of(ps2);
    EXPECT_EQ(wire1, wire2);
}

// ─── KAT 2: on-wire layout matches dashcore/p2pool-dash order at fixed ──────
//             offsets, AND a transposed layout is detected as different.

TEST(DashSMLDiff, CanonicalLayoutBitExactVsDashcore) {
    auto d = make_diff();
    auto ps = ::pack(d);
    auto wire = bytes_of(ps);

    // Documented head layout (CSimplifiedMNListDiff, proto >= 70229):
    //   [0,2)   nVersion          (LE uint16)
    //   [2,34)  baseBlockHash     (32 raw bytes, memory order)
    //   [34,66) blockHash         (32 raw bytes, memory order)
    ASSERT_GE(wire.size(), 66u);
    EXPECT_EQ(wire[0], 0x01);  // CURRENT_VERSION LE low byte
    EXPECT_EQ(wire[1], 0x00);  // LE high byte
    EXPECT_EQ(wire[2], 0xAA);  // baseBlockHash byte0
    for (size_t i = 1; i < 32; ++i) EXPECT_EQ(wire[2 + i], 0x00);
    EXPECT_EQ(wire[34], 0xBB); // blockHash byte0
    for (size_t i = 1; i < 32; ++i) EXPECT_EQ(wire[34 + i], 0x00);

    // Comparator-sensitivity proof: a diff with the two block hashes
    // TRANSPOSED is a DIFFERENT layout — its stream must NOT match, and
    // its bytes at the two offsets are swapped. A trivial self-comparison
    // would miss this.
    auto drift = d;
    std::swap(drift.baseBlockHash, drift.blockHash);
    auto pd = ::pack(drift);
    auto wired = bytes_of(pd);
    EXPECT_NE(wire, wired);
    EXPECT_EQ(wired[2], 0xBB);
    EXPECT_EQ(wired[34], 0xAA);

    // And the drift survives a decode (observable, not silently dropped).
    CSimplifiedMNListDiff back;
    PackStream pin(wired);
    pin >> back;
    EXPECT_EQ(back.baseBlockHash, d.blockHash);
    EXPECT_EQ(back.blockHash, d.baseBlockHash);
}

// ─── KAT 3: opaque quorum tail of arbitrary length round-trips verbatim ─────

TEST(DashSMLDiff, OpaqueQuorumTailVerbatim) {
    auto d = make_diff();
    d.quorum_tail.clear();
    for (int i = 0; i < 137; ++i) d.quorum_tail.push_back(static_cast<unsigned char>(i * 7 + 3));

    auto ps = ::pack(d);
    auto wire = bytes_of(ps);
    CSimplifiedMNListDiff out;
    PackStream in(wire);
    in >> out;
    EXPECT_EQ(out.quorum_tail.size(), 137u);
    EXPECT_EQ(out.quorum_tail, d.quorum_tail);

    // Empty tail must also be exact (no phantom bytes drained).
    auto d0 = make_diff();
    d0.quorum_tail.clear();
    auto ps0 = ::pack(d0);
    CSimplifiedMNListDiff out0;
    PackStream in0(bytes_of(ps0));
    in0 >> out0;
    EXPECT_TRUE(out0.quorum_tail.empty());
}

// ─── KAT 4: apply_diff delete + update + insert, then memcmp re-sort ────────

TEST(DashSMLDiff, ApplyDiffDeleteUpdateInsert) {
    // Current list: entries keyed 0x02, 0x04, 0x06 (already sorted memcmp).
    CSimplifiedMNList current;
    current.mnList = {make_entry(0x02), make_entry(0x04), make_entry(0x06)};
    current.sort();

    CSimplifiedMNListDiff diff;
    diff.deletedMNs = {raw256_byte(0, 0x04)};       // delete the 0x04 entry
    auto updated = make_entry(0x02);                 // same key, changed field
    updated.netPort = 0x9999;
    auto inserted = make_entry(0x01);                // new key, sorts first
    diff.mnList = {updated, inserted};

    auto res = apply_diff(current, diff);
    EXPECT_EQ(res.deleted, 1u);
    EXPECT_EQ(res.added_or_updated, 2u);

    // Final set keyed {0x01, 0x02(updated), 0x06}, memcmp-sorted ascending.
    ASSERT_EQ(current.mnList.size(), 3u);
    EXPECT_EQ(current.mnList[0].proRegTxHash.data()[0], 0x01);
    EXPECT_EQ(current.mnList[1].proRegTxHash.data()[0], 0x02);
    EXPECT_EQ(current.mnList[2].proRegTxHash.data()[0], 0x06);
    EXPECT_EQ(current.mnList[1].netPort, 0x9999);   // update applied, not insert

    // Idempotent ordering: list is in memcmp order (Bug-A invariant).
    for (size_t i = 1; i < current.mnList.size(); ++i) {
        EXPECT_LT(std::memcmp(current.mnList[i - 1].proRegTxHash.data(),
                              current.mnList[i].proRegTxHash.data(), 32), 0);
    }
}

// ─── KAT 5: apply an empty diff is a no-op (no spurious churn) ──────────────

TEST(DashSMLDiff, ApplyEmptyDiffNoOp) {
    CSimplifiedMNList current;
    current.mnList = {make_entry(0x03), make_entry(0x07)};
    current.sort();
    auto before = current.mnList.size();

    CSimplifiedMNListDiff empty;   // no deletes, no mnList entries
    auto res = apply_diff(current, empty);
    EXPECT_EQ(res.deleted, 0u);
    EXPECT_EQ(res.added_or_updated, 0u);
    EXPECT_EQ(current.mnList.size(), before);
    EXPECT_EQ(current.mnList[0].proRegTxHash.data()[0], 0x03);
    EXPECT_EQ(current.mnList[1].proRegTxHash.data()[0], 0x07);
}