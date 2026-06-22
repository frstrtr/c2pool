/// Phase C-QUO — Dash LLMQ quorum-tail verification leaf unit tests
///
/// Exercises the vendored CFinalCommitment / QuorumTail parser and the
/// in-memory QuorumManager active-set tracker:
///
///   - src/impl/dash/coin/vendor/llmq_commitment.hpp
///   - src/impl/dash/coin/vendor/quorum_tail.hpp
///   - src/impl/dash/coin/quorum_manager.hpp
///
/// This is the quorum/LLMQ verification leaf that sits between the
/// SimplifiedMNList leaf (#309) and the embedded_gbt main: it pins the
/// wire semantics of the mnlistdiff "quorum tail" (deletedQuorums +
/// newQuorums + quorumsCLSigs) that Phase L's ChainLock verifier and
/// Phase C-TEMPLATE's merkleRootQuorums computation both reach into.
///
/// KATs pinned here:
///   - CFinalCommitment round-trips byte-for-byte against a hand-built
///     wire vector (non-indexed v1) — nVersion(LE16), llmqType, quorumHash,
///     DYNBITSET signers/validMembers, raw 48/32/96/96 trailers.
///   - The INDEXED version gate (v2/v4) emits quorumIndex(int16) right
///     after quorumHash; non-indexed (v1/v3) omits it — length differs
///     by exactly 2 and quorumIndex round-trips.
///   - DYNBITSET is LSB-first within each byte and REJECTS out-of-range
///     trailing pad bits (dashcore malleation guard) on read.
///   - parse_quorum_tail decodes deletedQuorums + newQuorums +
///     quorumsCLSigs bit-exactly, treats empty input as clean success,
///     and rejects trailing garbage (wire-drift smell).
///   - parse_qfcommit_payload (type-6 special tx) round-trips and
///     enforces the strict-tail policy.
///   - QuorumManager.apply() insert/replace/delete semantics, find /
///     find_mutable / active_by_type / replace_state / CL-sig caching.
///
/// SCOPE NOTE (honest): these are structural + bit-exact wire KATs that
/// are fully self-contained. BLS signature verification and the
/// end-to-end "active set matches a live mnlistdiff from a Dash node"
/// cross-check are explicitly NOT vendored yet (Phase L) and NOT claimed
/// here.

#include <gtest/gtest.h>

#include <impl/dash/coin/vendor/llmq_commitment.hpp>
#include <impl/dash/coin/vendor/quorum_tail.hpp>
#include <impl/dash/coin/quorum_manager.hpp>

#include <core/uint256.hpp>
#include <core/pack.hpp>

#include <array>
#include <cstdint>
#include <cstring>
#include <optional>
#include <vector>

using dash::coin::vendor::CFinalCommitment;
using dash::coin::vendor::CFinalCommitmentTxPayload;
using dash::coin::vendor::QuorumTail;
using dash::coin::vendor::parse_quorum_tail;
using dash::coin::vendor::parse_qfcommit_payload;
using dash::coin::QuorumManager;

// ─── helpers ────────────────────────────────────────────────────────────────

// uint256 with a single nonzero byte at memory index 0.
static uint256 raw256_b0(uint8_t val) {
    uint256 h;
    std::array<uint8_t, 32> p{};
    p[0] = val;
    std::memcpy(h.data(), p.data(), 32);
    return h;
}

template <typename T>
static std::vector<unsigned char> ser(const T& obj) {
    auto ps = ::pack(obj);
    std::vector<unsigned char> out(ps.size());
    if (!out.empty())
        std::memcpy(out.data(), ps.data(), ps.size());
    return out;
}

template <typename T>
static T deser(const std::vector<unsigned char>& bytes) {
    ::PackStream s(bytes);
    T out;
    s >> out;
    return out;
}

static void push(std::vector<unsigned char>& v, std::initializer_list<uint8_t> bs) {
    for (auto b : bs) v.push_back(b);
}
static void push_n(std::vector<unsigned char>& v, uint8_t first, size_t n) {
    if (n == 0) return;
    v.push_back(first);
    for (size_t i = 1; i < n; ++i) v.push_back(0);
}

static void expect_commitment_eq(const CFinalCommitment& a,
                                 const CFinalCommitment& b) {
    EXPECT_EQ(a.nVersion, b.nVersion);
    EXPECT_EQ(a.llmqType, b.llmqType);
    EXPECT_EQ(a.quorumHash, b.quorumHash);
    EXPECT_EQ(a.quorumIndex, b.quorumIndex);
    EXPECT_EQ(a.signers, b.signers);
    EXPECT_EQ(a.validMembers, b.validMembers);
    EXPECT_EQ(a.quorumPublicKey, b.quorumPublicKey);
    EXPECT_EQ(a.quorumVvecHash, b.quorumVvecHash);
    EXPECT_EQ(a.quorumSig, b.quorumSig);
    EXPECT_EQ(a.membersSig, b.membersSig);
}

// A deterministic commitment with fully-populated raw trailers.
static CFinalCommitment make_commitment(uint16_t nVersion, uint8_t llmqType,
                                        uint8_t quorumHashByte0) {
    CFinalCommitment c;
    c.nVersion = nVersion;
    c.llmqType = llmqType;
    c.quorumHash = raw256_b0(quorumHashByte0);
    c.quorumIndex = c.is_indexed_version() ? static_cast<int16_t>(0x0102) : 0;
    c.signers      = {true, false, true};        // 3 bits → 0x05
    c.validMembers = {true, true,  false};        // 3 bits → 0x03
    c.quorumPublicKey.fill(0); c.quorumPublicKey[0] = 0xBB;
    c.quorumVvecHash = raw256_b0(0xCC);
    c.quorumSig.fill(0);   c.quorumSig[0]   = 0xDD;
    c.membersSig.fill(0);  c.membersSig[0]  = 0xEE;
    return c;
}

// ─── KAT 1: CFinalCommitment byte-exact wire (non-indexed v1) ───────────────

TEST(DashQuorum, FinalCommitmentByteExactNonIndexed) {
    auto c = make_commitment(
        CFinalCommitment::LEGACY_BLS_NON_INDEXED_QUORUM_VERSION,
        CFinalCommitment::LLMQ_50_60, 0xAA);

    std::vector<unsigned char> expected;
    push(expected, {0x01, 0x00});          // nVersion = 1 (LE16)
    push(expected, {0x01});                // llmqType = 1
    push_n(expected, 0xAA, 32);            // quorumHash
    // NO quorumIndex (non-indexed)
    push(expected, {0x03, 0x05});          // signers: CompactSize(3), LSB byte 0x05
    push(expected, {0x03, 0x03});          // validMembers: CompactSize(3), 0x03
    push_n(expected, 0xBB, 48);            // quorumPublicKey
    push_n(expected, 0xCC, 32);            // quorumVvecHash
    push_n(expected, 0xDD, 96);            // quorumSig
    push_n(expected, 0xEE, 96);            // membersSig

    EXPECT_EQ(ser(c), expected);

    auto back = deser<CFinalCommitment>(expected);
    expect_commitment_eq(back, c);
}

// ─── KAT 2: indexed version gate emits quorumIndex(int16) ───────────────────

TEST(DashQuorum, IndexedVersionGateAddsTwoBytes) {
    auto base = make_commitment(
        CFinalCommitment::LEGACY_BLS_NON_INDEXED_QUORUM_VERSION,
        CFinalCommitment::LLMQ_400_60, 0x11);
    auto indexed = make_commitment(
        CFinalCommitment::BASIC_BLS_INDEXED_QUORUM_VERSION,
        CFinalCommitment::LLMQ_400_60, 0x11);

    auto base_wire    = ser(base);
    auto indexed_wire = ser(indexed);

    // Indexed payload is exactly 2 bytes longer (the int16 quorumIndex).
    EXPECT_EQ(indexed_wire.size(), base_wire.size() + 2);

    // quorumIndex sits immediately after quorumHash:
    // nVersion(2) + llmqType(1) + quorumHash(32) = offset 35, LE16 0x0102.
    EXPECT_EQ(indexed_wire[35], 0x02);
    EXPECT_EQ(indexed_wire[36], 0x01);

    auto back = deser<CFinalCommitment>(indexed_wire);
    EXPECT_TRUE(back.is_indexed_version());
    EXPECT_EQ(back.quorumIndex, 0x0102);
    expect_commitment_eq(back, indexed);
}

// ─── KAT 3: DYNBITSET LSB-first + 9-bit two-byte packing ────────────────────

TEST(DashQuorum, DynBitSetLsbFirstNineBits) {
    auto c = make_commitment(
        CFinalCommitment::LEGACY_BLS_NON_INDEXED_QUORUM_VERSION,
        CFinalCommitment::LLMQ_50_60, 0x01);
    // 9 bits: positions 0 and 2 set in byte 0, position 8 set in byte 1.
    c.signers = {true, false, true, false, false, false, false, false, true};
    auto wire = ser(c);

    // signers section starts after nVersion(2)+llmqType(1)+quorumHash(32) = 35.
    EXPECT_EQ(wire[35], 0x09);   // CompactSize(9)
    EXPECT_EQ(wire[36], 0x05);   // byte 0: bits 0,2
    EXPECT_EQ(wire[37], 0x01);   // byte 1: bit 8

    auto back = deser<CFinalCommitment>(wire);
    EXPECT_EQ(back.signers, c.signers);
    EXPECT_EQ(back.CountSigners(), 3);
}

// ─── KAT 4: DYNBITSET rejects out-of-range trailing pad bits ────────────────

TEST(DashQuorum, DynBitSetRejectsMalleatedPadBits) {
    auto c = make_commitment(
        CFinalCommitment::LEGACY_BLS_NON_INDEXED_QUORUM_VERSION,
        CFinalCommitment::LLMQ_50_60, 0x01);
    c.signers = {true, false, true};   // 3 bits, byte = 0x05; bits 3..7 are pad
    auto wire = ser(c);
    ASSERT_EQ(wire[35], 0x03);
    ASSERT_EQ(wire[36], 0x05);

    // Flip an out-of-range pad bit (bit 3) → must be rejected on read.
    wire[36] = 0x0D;   // 0x05 | (1<<3)
    EXPECT_THROW(deser<CFinalCommitment>(wire), std::exception);
}

// ─── KAT 5: parse_quorum_tail decodes all three sections ────────────────────

static std::vector<unsigned char> build_tail_bytes(
    const std::vector<std::pair<uint8_t, uint256>>& deleted,
    const std::vector<CFinalCommitment>& newq,
    const std::vector<std::pair<std::array<uint8_t, 96>, std::vector<uint16_t>>>& clsigs) {
    std::vector<unsigned char> v;
    // deletedQuorums
    v.push_back(static_cast<uint8_t>(deleted.size()));   // small CompactSize
    for (auto& [t, h] : deleted) {
        v.push_back(t);
        const auto* p = reinterpret_cast<const unsigned char*>(h.data());
        v.insert(v.end(), p, p + 32);
    }
    // newQuorums
    v.push_back(static_cast<uint8_t>(newq.size()));
    for (auto& c : newq) {
        auto w = ser(c);
        v.insert(v.end(), w.begin(), w.end());
    }
    // quorumsCLSigs
    v.push_back(static_cast<uint8_t>(clsigs.size()));
    for (auto& [sig, idxs] : clsigs) {
        v.insert(v.end(), sig.begin(), sig.end());
        v.push_back(static_cast<uint8_t>(idxs.size()));
        for (auto idx : idxs) {
            v.push_back(static_cast<uint8_t>(idx & 0xff));
            v.push_back(static_cast<uint8_t>((idx >> 8) & 0xff));
        }
    }
    return v;
}

TEST(DashQuorum, ParseQuorumTailAllSections) {
    auto c0 = make_commitment(
        CFinalCommitment::LEGACY_BLS_NON_INDEXED_QUORUM_VERSION,
        CFinalCommitment::LLMQ_50_60, 0x21);
    auto c1 = make_commitment(
        CFinalCommitment::BASIC_BLS_INDEXED_QUORUM_VERSION,
        CFinalCommitment::LLMQ_400_60, 0x22);

    std::array<uint8_t, 96> sig{}; sig[0] = 0x7F;
    auto bytes = build_tail_bytes(
        {{CFinalCommitment::LLMQ_50_60, raw256_b0(0x33)}},
        {c0, c1},
        {{sig, {0, 1, 2}}});

    QuorumTail tail;
    ASSERT_TRUE(parse_quorum_tail(bytes, tail));

    ASSERT_EQ(tail.deletedQuorums.size(), 1u);
    EXPECT_EQ(tail.deletedQuorums[0].first, CFinalCommitment::LLMQ_50_60);
    EXPECT_EQ(tail.deletedQuorums[0].second, raw256_b0(0x33));

    ASSERT_EQ(tail.newQuorums.size(), 2u);
    expect_commitment_eq(tail.newQuorums[0], c0);
    expect_commitment_eq(tail.newQuorums[1], c1);

    ASSERT_EQ(tail.quorumsCLSigs.size(), 1u);
    EXPECT_EQ(tail.quorumsCLSigs[0].first, sig);
    EXPECT_EQ(tail.quorumsCLSigs[0].second, (std::vector<uint16_t>{0, 1, 2}));
}

TEST(DashQuorum, ParseQuorumTailEmptyIsCleanSuccess) {
    QuorumTail tail;
    EXPECT_TRUE(parse_quorum_tail({}, tail));
    EXPECT_TRUE(tail.deletedQuorums.empty());
    EXPECT_TRUE(tail.newQuorums.empty());
    EXPECT_TRUE(tail.quorumsCLSigs.empty());
}

TEST(DashQuorum, ParseQuorumTailRejectsTrailingGarbage) {
    auto bytes = build_tail_bytes({}, {}, {});   // 3 zero CompactSizes
    bytes.push_back(0xFF);                        // wire-drift smell
    QuorumTail tail;
    EXPECT_FALSE(parse_quorum_tail(bytes, tail));
}

// ─── KAT 6: parse_qfcommit_payload (type-6 special tx) ──────────────────────

TEST(DashQuorum, ParseQfcommitPayloadRoundTripAndStrictTail) {
    CFinalCommitmentTxPayload pl;
    pl.nVersion = CFinalCommitmentTxPayload::CURRENT_VERSION;
    pl.nHeight  = 0x00BEEF12;
    pl.commitment = make_commitment(
        CFinalCommitment::BASIC_BLS_NON_INDEXED_QUORUM_VERSION,
        CFinalCommitment::LLMQ_100_67, 0x44);

    auto wire = ser(pl);
    CFinalCommitmentTxPayload out;
    ASSERT_TRUE(parse_qfcommit_payload(wire, out));
    EXPECT_EQ(out.nVersion, pl.nVersion);
    EXPECT_EQ(out.nHeight, pl.nHeight);
    expect_commitment_eq(out.commitment, pl.commitment);

    // Strict-tail policy: any trailing byte is rejected.
    wire.push_back(0x00);
    CFinalCommitmentTxPayload out2;
    EXPECT_FALSE(parse_qfcommit_payload(wire, out2));

    // Empty input is rejected (not a valid payload).
    CFinalCommitmentTxPayload out3;
    EXPECT_FALSE(parse_qfcommit_payload({}, out3));
}

// ─── KAT 7: QuorumManager apply / find / delete / replace ───────────────────

static CFinalCommitment quorum_at(uint8_t llmqType, uint8_t hashByte) {
    auto c = make_commitment(
        CFinalCommitment::BASIC_BLS_NON_INDEXED_QUORUM_VERSION,
        llmqType, hashByte);
    return c;
}

TEST(DashQuorum, ManagerApplyInsertReplaceDelete) {
    QuorumManager mgr;
    EXPECT_EQ(mgr.active_count(), 0u);

    QuorumTail t1;
    t1.newQuorums = {quorum_at(CFinalCommitment::LLMQ_50_60, 0x01),
                     quorum_at(CFinalCommitment::LLMQ_400_60, 0x02)};
    std::array<uint8_t, 96> sig{}; sig[0] = 0x09;
    t1.quorumsCLSigs = {{sig, {0, 1}}};

    auto r1 = mgr.apply(t1);
    EXPECT_EQ(r1.added_or_updated, 2u);
    EXPECT_EQ(r1.deleted, 0u);
    EXPECT_EQ(r1.cl_sigs_cached, 1u);
    EXPECT_EQ(r1.active_after, 2u);
    EXPECT_EQ(mgr.active_count(), 2u);

    // find existing / missing
    auto found = mgr.find(CFinalCommitment::LLMQ_50_60, raw256_b0(0x01));
    ASSERT_TRUE(found.has_value());
    EXPECT_EQ(found->llmqType, CFinalCommitment::LLMQ_50_60);
    EXPECT_FALSE(mgr.find(CFinalCommitment::LLMQ_50_60, raw256_b0(0x09)).has_value());

    // replace one (same key) + delete the other in one diff
    QuorumTail t2;
    auto replacement = quorum_at(CFinalCommitment::LLMQ_50_60, 0x01);
    replacement.quorumSig[0] = 0x77;   // mutated payload, same key
    t2.newQuorums = {replacement};
    t2.deletedQuorums = {{CFinalCommitment::LLMQ_400_60, raw256_b0(0x02)}};

    auto r2 = mgr.apply(t2);
    EXPECT_EQ(r2.added_or_updated, 1u);
    EXPECT_EQ(r2.deleted, 1u);
    EXPECT_EQ(r2.active_after, 1u);
    EXPECT_EQ(mgr.active_count(), 1u);

    auto reborn = mgr.find(CFinalCommitment::LLMQ_50_60, raw256_b0(0x01));
    ASSERT_TRUE(reborn.has_value());
    EXPECT_EQ(reborn->quorumSig[0], 0x77);   // replaced in place

    // Latest CL sigs replaced (t2 carried none).
    EXPECT_TRUE(mgr.latest_cl_sigs().empty());
}

TEST(DashQuorum, ManagerFindMutableAndActiveByType) {
    QuorumManager mgr;
    QuorumTail t;
    t.newQuorums = {quorum_at(CFinalCommitment::LLMQ_50_60, 0x01),
                    quorum_at(CFinalCommitment::LLMQ_50_60, 0x02),
                    quorum_at(CFinalCommitment::LLMQ_400_60, 0x03)};
    mgr.apply(t);

    auto by_type = mgr.active_by_type();
    EXPECT_EQ(by_type[CFinalCommitment::LLMQ_50_60], 2u);
    EXPECT_EQ(by_type[CFinalCommitment::LLMQ_400_60], 1u);

    // find_mutable populates mining_height in place.
    auto* e = mgr.find_mutable(CFinalCommitment::LLMQ_400_60, raw256_b0(0x03));
    ASSERT_NE(e, nullptr);
    EXPECT_EQ(e->mining_height, 0u);
    e->mining_height = 2128896;
    EXPECT_EQ(mgr.find_mutable(CFinalCommitment::LLMQ_400_60, raw256_b0(0x03))->mining_height,
              2128896u);
    EXPECT_EQ(mgr.find_mutable(CFinalCommitment::LLMQ_400_60, raw256_b0(0x99)), nullptr);
}

TEST(DashQuorum, ManagerReplaceStateWarmsActiveSet) {
    QuorumManager mgr;
    std::vector<QuorumManager::Entry> warm;
    QuorumManager::Entry e;
    e.key = {CFinalCommitment::LLMQ_100_67, raw256_b0(0x05)};
    e.commitment = quorum_at(CFinalCommitment::LLMQ_100_67, 0x05);
    e.mining_height = 42;
    warm.push_back(e);

    std::array<uint8_t, 96> sig{}; sig[0] = 0xAB;
    std::vector<QuorumManager::CLSig> sigs{{sig, {7}}};

    mgr.replace_state(std::move(warm), std::move(sigs));
    EXPECT_EQ(mgr.active_count(), 1u);
    ASSERT_TRUE(mgr.find(CFinalCommitment::LLMQ_100_67, raw256_b0(0x05)).has_value());
    ASSERT_EQ(mgr.latest_cl_sigs().size(), 1u);
    EXPECT_EQ(mgr.latest_cl_sigs()[0].second, (std::vector<uint16_t>{7}));

    mgr.clear();
    EXPECT_EQ(mgr.active_count(), 0u);
    EXPECT_TRUE(mgr.latest_cl_sigs().empty());
}
