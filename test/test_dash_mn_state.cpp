// SPDX-License-Identifier: AGPL-3.0-or-later
/// Phase C-PAY (S7 mn_state_machine leaf) — Dash masternode state-machine
/// unit tests.
///
/// Exercises the three vendored / derived components that turn the
/// SimplifiedMNList leaf (#309) into a live, auto-maintained DMN list the
/// embedded_gbt payee projection consumes:
///
///   - vendor/providertx.hpp : CProRegTx / CProUpServTx / CProUpRegTx /
///     CProUpRevTx wire (de)serialization + nVersion/nType field gating +
///     parse_protx_payload full-consume / trailing-garbage rejection.
///   - mn_state_db.hpp : MNState internal persistence wire round-trip.
///   - mn_state_machine.hpp : apply_block RebuildListFromBlock semantics
///     (register / update-service / update-registrar / revoke / collateral
///     spend / payee resolution), find_expected_payee +
///     pick_paid_mn memcmp tiebreak, and sync_validity_from_sml.
///
/// KAT philosophy (mirrors test_dash_simplifiedmns.cpp): every assertion is
/// either a structural round-trip (serialize -> deserialize -> EQ), a
/// bit-exact preimage rebuilt independently and double-SHA256d, or a
/// self-consistency property of the algorithm. No "expected" hashes are
/// fabricated.
///
/// SCOPE NOTE (honest): the end-to-end cross-check — "apply_block over a
/// REAL Dash mainnet block produces the SAME per-MN nLastPaidHeight /
/// find_expected_payee as dashd protx list" — requires a live Dash node
/// oracle (mnlistdiff + a real special-tx-bearing block) and is deferred to
/// the embedded_gbt integration leaf. It is NOT claimed here. The
/// compute_tx_hash KAT below asserts the SHA256d-of-serialized-tx property
/// is self-consistent and stable, not equality with a dashd-reported txid
/// (which would need the node oracle).

#include <gtest/gtest.h>

#include <impl/dash/coin/mn_state_machine.hpp>
#include <impl/dash/coin/mn_state_db.hpp>
#include <impl/dash/coin/vendor/providertx.hpp>
#include <impl/dash/coin/vendor/simplifiedmns.hpp>
#include <impl/dash/coin/transaction.hpp>
#include <impl/dash/coin/block.hpp>

#include <core/uint256.hpp>
#include <core/pack.hpp>
#include <core/hash.hpp>

#include <array>
#include <cstdint>
#include <cstring>
#include <vector>

using dash::coin::MNState;
using dash::coin::MnStateMachine;
using dash::coin::BlockType;
using dash::coin::MutableTransaction;
using dash::coin::vendor::CProRegTx;
using dash::coin::vendor::CProUpServTx;
using dash::coin::vendor::CProUpRegTx;
using dash::coin::vendor::CProUpRevTx;
using dash::coin::vendor::CSimplifiedMNList;
using dash::coin::vendor::CSimplifiedMNListEntry;
namespace ProTxVersion = dash::coin::vendor::ProTxVersion;
namespace MnType = dash::coin::vendor::MnType;
using dash::coin::vendor::parse_protx_payload;
using bitcoin_family::coin::TxPrevOut;
using bitcoin_family::coin::TxIn;
using bitcoin_family::coin::TxOut;

// ─── helpers ────────────────────────────────────────────────────────────────

static uint256 raw256(uint8_t base) {
    uint256 h;
    std::array<uint8_t, 32> p{};
    for (size_t i = 0; i < 32; ++i) p[i] = static_cast<uint8_t>(base + i);
    std::memcpy(h.data(), p.data(), 32);
    return h;
}

static uint256 raw256_byte(size_t idx, uint8_t val) {
    uint256 h;
    std::array<uint8_t, 32> p{};
    p[idx] = val;
    std::memcpy(h.data(), p.data(), 32);
    return h;
}

static uint160 raw160(uint8_t base) {
    uint160 h;
    std::array<uint8_t, 20> p{};
    for (size_t i = 0; i < 20; ++i) p[i] = static_cast<uint8_t>(base + i);
    std::memcpy(h.data(), p.data(), 20);
    return h;
}

template <size_t N>
static std::array<uint8_t, N> seq_array(uint8_t base) {
    std::array<uint8_t, N> a{};
    for (size_t i = 0; i < N; ++i) a[i] = static_cast<uint8_t>(base + i);
    return a;
}

// generic round-trip: pack(in) then >> into a fresh out; reports wire len.
template <typename T>
static T roundtrip(const T& in, size_t* wire_len) {
    auto ps = ::pack(in);
    if (wire_len) *wire_len = ps.size();
    T out;
    ps >> out;
    return out;
}

// a 33-output coinbase-style script pattern (opaque bytes; the machine only
// memcmp-compares m_data, never interprets it).
static std::vector<unsigned char> script_bytes(uint8_t tag, size_t n = 25) {
    std::vector<unsigned char> v(n);
    for (size_t i = 0; i < n; ++i) v[i] = static_cast<unsigned char>(tag + i);
    return v;
}


// A real, valid canonical-BASIC mainnet operator key (from the h=2522504
// checkpoint, proTxHash 0019bb2a...; first byte 0xae >= 0x80). Used by the
// #154 E2d apply-path regression lock below to derive a genuine LEGACY wire
// re-encoding of the SAME G1 point via opkey_for_leaf().
static std::array<uint8_t, 48> opkey_from_hex(const char* hex) {
    std::array<uint8_t, 48> a{};
    for (size_t i = 0; i < 48; ++i) {
        auto nyb = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return 0;
        };
        a[i] = static_cast<uint8_t>((nyb(hex[2 * i]) << 4) | nyb(hex[2 * i + 1]));
    }
    return a;
}

// ════════════════════════════════════════════════════════════════════════
// ProTx wire round-trips + field gating
// ════════════════════════════════════════════════════════════════════════

static CProRegTx make_proreg(uint16_t nVersion, uint16_t nType) {
    CProRegTx p;
    p.nVersion = nVersion;
    p.nType = nType;
    p.nMode = 0;
    p.collateralOutpoint.hash = raw256(0x10);
    p.collateralOutpoint.index = 7;
    p.netInfo.ip = seq_array<16>(0x20);
    p.netInfo.port_be = 0x2334;            // 9011
    p.keyIDOwner = raw160(0x30);
    p.pubKeyOperator = seq_array<48>(0x40);
    p.keyIDVoting = raw160(0x50);
    p.nOperatorReward = 250;
    p.scriptPayout.m_data = script_bytes(0x76, 25);
    p.inputsHash = raw256(0x60);
    p.vchSig = {0xde, 0xad, 0xbe, 0xef};
    if (nType == MnType::EVO) {
        p.platformNodeID = raw160(0x70);
        p.platformP2PPort = 0x6f4c;        // 28492
        p.platformHTTPPort = 0x6f4d;
    }
    return p;
}

TEST(DashMnState, ProRegTxRoundTripRegular) {
    auto p = make_proreg(ProTxVersion::BASIC_BLS, MnType::REGULAR);
    size_t len = 0;
    auto out = roundtrip(p, &len);
    EXPECT_EQ(out.nVersion, p.nVersion);
    EXPECT_EQ(out.nType, p.nType);
    EXPECT_EQ(out.collateralOutpoint.hash, p.collateralOutpoint.hash);
    EXPECT_EQ(out.collateralOutpoint.index, p.collateralOutpoint.index);
    EXPECT_EQ(out.netInfo.ip, p.netInfo.ip);
    EXPECT_EQ(out.netInfo.port_be, p.netInfo.port_be);
    EXPECT_EQ(out.keyIDOwner, p.keyIDOwner);
    EXPECT_EQ(out.pubKeyOperator, p.pubKeyOperator);
    EXPECT_EQ(out.keyIDVoting, p.keyIDVoting);
    EXPECT_EQ(out.nOperatorReward, p.nOperatorReward);
    EXPECT_EQ(out.scriptPayout.m_data, p.scriptPayout.m_data);
    EXPECT_EQ(out.inputsHash, p.inputsHash);
    EXPECT_EQ(out.vchSig, p.vchSig);
}

TEST(DashMnState, ProRegTxRoundTripEvoCarriesPlatformFields) {
    auto p = make_proreg(ProTxVersion::BASIC_BLS, MnType::EVO);
    size_t len_evo = 0, len_reg = 0;
    auto out = roundtrip(p, &len_evo);
    EXPECT_EQ(out.platformNodeID, p.platformNodeID);
    EXPECT_EQ(out.platformP2PPort, p.platformP2PPort);
    EXPECT_EQ(out.platformHTTPPort, p.platformHTTPPort);
    // EVO wire is strictly longer than REGULAR (platformNodeID(20) +
    // 2 BE ports(4) = +24 bytes); proves the nType==EVO gate fired.
    auto preg = make_proreg(ProTxVersion::BASIC_BLS, MnType::REGULAR);
    (void)roundtrip(preg, &len_reg);
    EXPECT_EQ(len_evo, len_reg + 24u);
}

TEST(DashMnState, ProRegTxEmptyScriptAndSigKnownLength) {
    // Deterministic wire length with empty scriptPayout + empty vchSig
    // (each a single 0x00 CompactSize byte), REGULAR (no platform fields):
    //   nVersion(2) nType(2) nMode(2) collateral(36) netInfo(18)
    //   keyIDOwner(20) pubKeyOperator(48) keyIDVoting(20)
    //   nOperatorReward(2) scriptPayout(1) inputsHash(32) vchSig(1) = 184
    auto p = make_proreg(ProTxVersion::BASIC_BLS, MnType::REGULAR);
    p.scriptPayout.m_data.clear();
    p.vchSig.clear();
    size_t len = 0;
    auto out = roundtrip(p, &len);
    EXPECT_EQ(len, 184u);
    EXPECT_TRUE(out.scriptPayout.m_data.empty());
    EXPECT_TRUE(out.vchSig.empty());
}

TEST(DashMnState, ProUpServTxRoundTrip) {
    CProUpServTx p;
    p.nVersion = ProTxVersion::BASIC_BLS;
    p.nType = MnType::REGULAR;
    p.proTxHash = raw256(0x11);
    p.netInfo.ip = seq_array<16>(0x22);
    p.netInfo.port_be = 0x2334;
    p.scriptOperatorPayout.m_data = script_bytes(0x88, 22);
    p.inputsHash = raw256(0x33);
    p.sig = seq_array<96>(0x44);
    size_t len = 0;
    auto out = roundtrip(p, &len);
    EXPECT_EQ(out.nVersion, p.nVersion);
    EXPECT_EQ(out.proTxHash, p.proTxHash);
    EXPECT_EQ(out.netInfo.port_be, p.netInfo.port_be);
    EXPECT_EQ(out.scriptOperatorPayout.m_data, p.scriptOperatorPayout.m_data);
    EXPECT_EQ(out.inputsHash, p.inputsHash);
    EXPECT_EQ(out.sig, p.sig);
}

TEST(DashMnState, ProUpRegTxRoundTrip) {
    CProUpRegTx p;
    p.nVersion = ProTxVersion::BASIC_BLS;
    p.proTxHash = raw256(0x12);
    p.nMode = 0;
    p.pubKeyOperator = seq_array<48>(0x55);
    p.keyIDVoting = raw160(0x66);
    p.scriptPayout.m_data = script_bytes(0x99, 25);
    p.inputsHash = raw256(0x34);
    p.vchSig = {0x01, 0x02, 0x03};
    size_t len = 0;
    auto out = roundtrip(p, &len);
    EXPECT_EQ(out.proTxHash, p.proTxHash);
    EXPECT_EQ(out.pubKeyOperator, p.pubKeyOperator);
    EXPECT_EQ(out.keyIDVoting, p.keyIDVoting);
    EXPECT_EQ(out.scriptPayout.m_data, p.scriptPayout.m_data);
    EXPECT_EQ(out.inputsHash, p.inputsHash);
    EXPECT_EQ(out.vchSig, p.vchSig);
}

TEST(DashMnState, ProUpRevTxRoundTripAndKnownLength) {
    CProUpRevTx p;
    p.nVersion = ProTxVersion::BASIC_BLS;
    p.proTxHash = raw256(0x13);
    p.nReason = CProUpRevTx::REASON_COMPROMISED_KEYS;
    p.inputsHash = raw256(0x35);
    p.sig = seq_array<96>(0x77);
    // nVersion(2) proTxHash(32) nReason(2) inputsHash(32) sig(96) = 164
    size_t len = 0;
    auto out = roundtrip(p, &len);
    EXPECT_EQ(len, 164u);
    EXPECT_EQ(out.proTxHash, p.proTxHash);
    EXPECT_EQ(out.nReason, CProUpRevTx::REASON_COMPROMISED_KEYS);
    EXPECT_EQ(out.inputsHash, p.inputsHash);
    EXPECT_EQ(out.sig, p.sig);
}

// ─── parse_protx_payload: full-consume + trailing-garbage rejection ─────────

TEST(DashMnState, ParseProtxPayloadFullConsume) {
    auto p = make_proreg(ProTxVersion::BASIC_BLS, MnType::EVO);
    auto ps = ::pack(p);
    auto sp = ps.get_span();
    std::vector<uint8_t> payload(
        reinterpret_cast<const uint8_t*>(sp.data()),
        reinterpret_cast<const uint8_t*>(sp.data()) + sp.size());

    CProRegTx out;
    EXPECT_TRUE(parse_protx_payload(payload, out));
    EXPECT_EQ(out.platformNodeID, p.platformNodeID);
    EXPECT_EQ(out.scriptPayout.m_data, p.scriptPayout.m_data);
}

TEST(DashMnState, ParseProtxPayloadRejectsTrailingGarbage) {
    auto p = make_proreg(ProTxVersion::BASIC_BLS, MnType::REGULAR);
    auto ps = ::pack(p);
    auto sp = ps.get_span();
    std::vector<uint8_t> payload(
        reinterpret_cast<const uint8_t*>(sp.data()),
        reinterpret_cast<const uint8_t*>(sp.data()) + sp.size());
    payload.push_back(0xAB);   // one trailing byte -> not fully consumed
    CProRegTx out;
    EXPECT_FALSE(parse_protx_payload(payload, out));
}

TEST(DashMnState, ParseProtxPayloadRejectsEmpty) {
    std::vector<uint8_t> empty;
    CProRegTx out;
    EXPECT_FALSE(parse_protx_payload(empty, out));
}

// ════════════════════════════════════════════════════════════════════════
// MNState internal persistence wire round-trip
// ════════════════════════════════════════════════════════════════════════

TEST(DashMnState, MNStatePersistenceRoundTrip) {
    MNState s;
    s.nVersion = ProTxVersion::BASIC_BLS;
    s.nType = MnType::EVO;
    s.collateralOutpoint.hash = raw256(0x01);
    s.collateralOutpoint.index = 3;
    s.keyIDOwner = raw160(0x02);
    s.pubKeyOperator = seq_array<48>(0x03);
    s.keyIDVoting = raw160(0x04);
    s.nOperatorReward = 500;
    s.scriptPayout.m_data = script_bytes(0x05, 25);
    s.netInfo.ip = seq_array<16>(0x06);
    s.netInfo.port_be = 0x2334;
    s.scriptOperatorPayout.m_data = script_bytes(0x07, 22);
    s.nRegisteredHeight = 2400000;
    s.nLastPaidHeight = 2450123;
    s.nPoSeRevivedHeight = 2440000;
    s.nPoSeBanHeight = 0;
    s.nConsecutivePayments = 4;
    s.nRevocationReason = CProUpRevTx::REASON_NOT_SPECIFIED;
    s.isValid = true;
    s.platformNodeID = raw160(0x08);
    s.platformP2PPort = 0x6f4c;
    s.platformHTTPPort = 0x6f4d;

    size_t len = 0;
    auto out = roundtrip(s, &len);
    EXPECT_TRUE(s == out) << "MNState persistence round-trip mismatch";
    // operator== already covers every persisted field; double-check a few
    // that are easy to silently drop.
    EXPECT_EQ(out.nLastPaidHeight, 2450123u);
    EXPECT_EQ(out.nConsecutivePayments, 4u);
    EXPECT_EQ(out.platformHTTPPort, 0x6f4d);
}

// ════════════════════════════════════════════════════════════════════════
// MnStateMachine::apply_block — RebuildListFromBlock semantics
// ════════════════════════════════════════════════════════════════════════

// Serialize a ProTx variant into the wire payload bytes the machine parses.
template <typename T>
static std::vector<unsigned char> protx_payload(const T& p) {
    auto ps = ::pack(p);
    auto sp = ps.get_span();
    return std::vector<unsigned char>(
        reinterpret_cast<const unsigned char*>(sp.data()),
        reinterpret_cast<const unsigned char*>(sp.data()) + sp.size());
}

// Build a special tx carrying `type` + the given payload. extra_payload
// must be non-empty AND type != 0 for the machine to look at it.
static MutableTransaction special_tx(uint16_t type,
                                     const std::vector<unsigned char>& payload) {
    MutableTransaction tx;
    // DIP2 special txs (ProReg/ProUpReg/ProUpRev/ProUpServ/CbTx) are nVersion==3;
    // dashd (primitives/transaction.h) only (de)serializes vExtraPayload when
    // nVersion==3 && nType!=0, so the extra_payload only affects the tx hash for
    // a nVersion==3 tx. Build the fixture the way the chain actually carries it.
    tx.version = 3;
    tx.type = type;
    tx.extra_payload = payload;
    // one dummy input (collateral spends test uses real prevouts instead)
    TxIn in; in.prevout.hash = uint256{}; in.prevout.index = 0xFFFFFFFF;
    in.sequence = 0xFFFFFFFF;
    tx.vin.push_back(in);
    return tx;
}

// A coinbase tx (index 0) with the given output scripts.
static MutableTransaction coinbase_tx(
    const std::vector<std::vector<unsigned char>>& out_scripts) {
    MutableTransaction cb;
    cb.type = 0;
    TxIn in; in.prevout.hash = uint256{}; in.prevout.index = 0xFFFFFFFF;
    in.sequence = 0xFFFFFFFF;
    cb.vin.push_back(in);
    for (const auto& s : out_scripts) {
        TxOut o; o.value = 100000; o.scriptPubKey.m_data = s;
        cb.vout.push_back(o);
    }
    return cb;
}

// Reproduce MnStateMachine::compute_tx_hash independently (SHA256d of the
// MutableTransaction serialization) so the test can predict the
// proRegTxHash the machine will assign.
static uint256 tx_hash(const MutableTransaction& tx) {
    ::PackStream s;
    s << tx;
    auto sp = s.get_span();
    uint256 h;
    CHash256()
        .Write(std::span<const unsigned char>(
            reinterpret_cast<const unsigned char*>(sp.data()), sp.size()))
        .Finalize(std::span<unsigned char>(h.data(), 32));
    return h;
}

TEST(DashMnState, ComputeTxHashSelfConsistentAndStable) {
    // SCOPE NOTE: asserts SHA256d-of-serialized-tx is deterministic and
    // changes with the payload — NOT equality with a dashd-reported txid
    // (that needs the node oracle). Registering this tx in apply_block must
    // key the MN under exactly this hash (verified in RegisterAddsMN).
    auto reg = make_proreg(ProTxVersion::BASIC_BLS, MnType::REGULAR);
    auto tx = special_tx(CProRegTx::SPECIALTX_TYPE, protx_payload(reg));
    uint256 h1 = tx_hash(tx);
    uint256 h2 = tx_hash(tx);
    EXPECT_EQ(h1, h2);
    EXPECT_FALSE(h1.IsNull());
    // mutate the payload -> different hash
    reg.nOperatorReward = 999;
    auto tx2 = special_tx(CProRegTx::SPECIALTX_TYPE, protx_payload(reg));
    EXPECT_NE(tx_hash(tx2), h1);
}

TEST(DashMnState, RegisterAddsMNKeyedByTxHash) {
    auto reg = make_proreg(ProTxVersion::BASIC_BLS, MnType::REGULAR);
    auto regtx = special_tx(CProRegTx::SPECIALTX_TYPE, protx_payload(reg));
    uint256 expected_hash = tx_hash(regtx);

    BlockType blk;
    blk.m_txs.push_back(coinbase_tx({script_bytes(0xC0)}));  // cb at index 0
    blk.m_txs.push_back(regtx);

    MnStateMachine m;
    auto r = m.apply_block(blk, 2400000);
    EXPECT_EQ(r.registered, 1u);
    EXPECT_EQ(m.size(), 1u);
    auto it = m.entries().find(expected_hash);
    ASSERT_NE(it, m.entries().end()) << "MN must be keyed by compute_tx_hash";
    EXPECT_EQ(it->second.nRegisteredHeight, 2400000u);
    EXPECT_EQ(it->second.scriptPayout.m_data, reg.scriptPayout.m_data);
    EXPECT_TRUE(it->second.isValid);
    // null collateral hash -> resolved to the tx own hash.
    EXPECT_EQ(it->second.collateralOutpoint.hash, reg.collateralOutpoint.hash);
}

TEST(DashMnState, RegisterNullCollateralResolvesToOwnHash) {
    auto reg = make_proreg(ProTxVersion::BASIC_BLS, MnType::REGULAR);
    reg.collateralOutpoint.hash = uint256{};   // null -> own tx output
    reg.collateralOutpoint.index = 1;
    auto regtx = special_tx(CProRegTx::SPECIALTX_TYPE, protx_payload(reg));
    uint256 own = tx_hash(regtx);

    BlockType blk;
    blk.m_txs.push_back(coinbase_tx({script_bytes(0xC1)}));
    blk.m_txs.push_back(regtx);
    MnStateMachine m;
    m.apply_block(blk, 2400001);
    auto it = m.entries().find(own);
    ASSERT_NE(it, m.entries().end());
    EXPECT_EQ(it->second.collateralOutpoint.hash, own);
    EXPECT_EQ(it->second.collateralOutpoint.index, 1u);
    // collateral index must resolve back to the MN.
    auto by_coll = m.find_by_collateral(it->second.collateralOutpoint);
    ASSERT_TRUE(by_coll.has_value());
    EXPECT_EQ(*by_coll, own);
}

TEST(DashMnState, UpdateRegistrarKeyChangeBansMN) {
    auto reg = make_proreg(ProTxVersion::BASIC_BLS, MnType::REGULAR);
    auto regtx = special_tx(CProRegTx::SPECIALTX_TYPE, protx_payload(reg));
    uint256 h = tx_hash(regtx);

    BlockType b1;
    b1.m_txs.push_back(coinbase_tx({script_bytes(0xC2)}));
    b1.m_txs.push_back(regtx);
    MnStateMachine m;
    m.apply_block(b1, 2400010);
    ASSERT_TRUE(m.entries().at(h).isValid);

    // ProUpReg with a DIFFERENT operator key -> ResetOperatorFields + ban.
    CProUpRegTx upreg;
    upreg.nVersion = ProTxVersion::BASIC_BLS;
    upreg.proTxHash = h;
    upreg.pubKeyOperator = seq_array<48>(0xEE);   // changed
    upreg.keyIDVoting = raw160(0x66);
    upreg.scriptPayout.m_data = script_bytes(0x9A, 25);
    upreg.inputsHash = raw256(0x34);
    upreg.vchSig = {0x01};
    BlockType b2;
    b2.m_txs.push_back(coinbase_tx({script_bytes(0xC3)}));
    b2.m_txs.push_back(special_tx(CProUpRegTx::SPECIALTX_TYPE, protx_payload(upreg)));
    auto r = m.apply_block(b2, 2400011);
    EXPECT_EQ(r.updated, 1u);
    EXPECT_FALSE(m.entries().at(h).isValid);
    EXPECT_EQ(m.entries().at(h).nPoSeBanHeight, 2400011u);
    EXPECT_EQ(m.entries().at(h).scriptPayout.m_data, upreg.scriptPayout.m_data);
}

#ifdef C2POOL_DASH_BLS
// ════════════════════════════════════════════════════════════════════════
// #154 legacy<->basic opkey — E2d MN-CKPT apply-path regression lock
// ════════════════════════════════════════════════════════════════════════
// mn_state_machine case-3 (PROVIDER_UPDATE_REGISTRAR) stores the operator key
// canonical-BASIC and compares canonical-vs-canonical. A v1 (LEGACY_BLS)
// ProUpReg payload carries the SAME G1 point in the legacy wire encoding
// (mainnet h=2525069: 04c4.. wire vs the 84c4.. basic store). Byte-comparing
// the raw wire against a basic-stored key manufactures a phantom operator
// change -> spurious dashd-semantics PoSe-ban (dashd compares deserialized
// points via CBLSLazyPublicKey and never bans) -> the SML fold revives the MN
// and re-orders the payment queue -> payee desync one cycle later (first
// observable mainnet slot h=2526494). Guarded on C2POOL_DASH_BLS because
// opkey_to_basic / opkey_for_leaf are identity no-ops without a BLS backend,
// so the legacy re-encoding cannot be produced and the defect is untestable —
// the exact reason it stayed invisible to the BLS-OFF CI jobs.
TEST(DashMnState, LegacyProUpRegSamePointDoesNotBan) {
    const std::array<uint8_t, 48> basic = opkey_from_hex(
        "aef878fcb417bd993366d8bf42e8aa079bd93ebc207072e7b5c9f973b232091e"
        "3001416816b7f06750daa2274a57981d");

    // The LEGACY (pre-v19) wire encoding of the SAME underlying G1 point.
    const std::array<uint8_t, 48> legacy =
        dash::coin::vendor::opkey_for_leaf(basic, /*want_legacy=*/true);
    ASSERT_NE(legacy, basic)
        << "legacy re-encoding must differ byte-wise from basic (else this "
           "point cannot exercise the scheme-mismatch defect)";
    // Canonicalizing the legacy wire recovers the basic store form (injective).
    ASSERT_EQ(dash::coin::vendor::opkey_to_basic(legacy, /*wire_legacy=*/true),
              basic);

    // Register the MN with the BASIC key (a v2 ProReg stores canonical basic).
    auto reg = make_proreg(ProTxVersion::BASIC_BLS, MnType::REGULAR);
    reg.pubKeyOperator = basic;
    auto regtx = special_tx(CProRegTx::SPECIALTX_TYPE, protx_payload(reg));
    uint256 h = tx_hash(regtx);
    BlockType b1;
    b1.m_txs.push_back(coinbase_tx({script_bytes(0xC2)}));
    b1.m_txs.push_back(regtx);
    MnStateMachine m;
    m.apply_block(b1, 2400010);
    ASSERT_TRUE(m.entries().at(h).isValid);
    ASSERT_EQ(m.entries().at(h).pubKeyOperator, basic);

    // v1 (LEGACY_BLS) ProUpReg carrying the SAME point in legacy encoding,
    // changing only the payout script — dashd does NOT ban (same point).
    CProUpRegTx upreg;
    upreg.nVersion = ProTxVersion::LEGACY_BLS;   // == 1
    upreg.proTxHash = h;
    upreg.pubKeyOperator = legacy;               // legacy wire of the same point
    upreg.keyIDVoting = raw160(0x66);
    upreg.scriptPayout.m_data = script_bytes(0x9A, 25);
    upreg.inputsHash = raw256(0x34);
    upreg.vchSig = {0x01};
    BlockType b2;
    b2.m_txs.push_back(coinbase_tx({script_bytes(0xC3)}));
    b2.m_txs.push_back(
        special_tx(CProUpRegTx::SPECIALTX_TYPE, protx_payload(upreg)));
    auto r = m.apply_block(b2, 2400011);
    EXPECT_EQ(r.updated, 1u);

    // THE LOCK: same G1 point => key_changed=false => NO ban, entry stays valid
    // (pre-fix: raw byte-compare sees 2e.. != ae.. -> spurious ban).
    EXPECT_TRUE(m.entries().at(h).isValid)
        << "legacy-encoded same-point ProUpReg spuriously banned the MN "
           "(raw byte-compare regression #154, h=2526494 payee-desync class)";
    EXPECT_EQ(m.entries().at(h).nPoSeBanHeight, 0u);
    // Store stays canonical BASIC; the payout update still applies.
    EXPECT_EQ(m.entries().at(h).pubKeyOperator, basic);
    EXPECT_EQ(m.entries().at(h).scriptPayout.m_data, upreg.scriptPayout.m_data);
}
#endif // C2POOL_DASH_BLS

TEST(DashMnState, UpdateServiceRevivesBannedMN) {
    auto reg = make_proreg(ProTxVersion::BASIC_BLS, MnType::REGULAR);
    auto regtx = special_tx(CProRegTx::SPECIALTX_TYPE, protx_payload(reg));
    uint256 h = tx_hash(regtx);
    BlockType b1;
    b1.m_txs.push_back(coinbase_tx({script_bytes(0xD0)}));
    b1.m_txs.push_back(regtx);
    MnStateMachine m;
    m.apply_block(b1, 2400020);

    // Revoke -> ban.
    CProUpRevTx rev;
    rev.nVersion = ProTxVersion::BASIC_BLS;
    rev.proTxHash = h;
    rev.nReason = CProUpRevTx::REASON_COMPROMISED_KEYS;
    rev.inputsHash = raw256(0x35);
    rev.sig = seq_array<96>(0x77);
    BlockType b2;
    b2.m_txs.push_back(coinbase_tx({script_bytes(0xD1)}));
    b2.m_txs.push_back(special_tx(CProUpRevTx::SPECIALTX_TYPE, protx_payload(rev)));
    auto rr = m.apply_block(b2, 2400021);
    EXPECT_EQ(rr.revoked, 1u);
    ASSERT_FALSE(m.entries().at(h).isValid);
    EXPECT_EQ(m.entries().at(h).nPoSeBanHeight, 2400021u);

    // ProUpServ -> revive.
    CProUpServTx ups;
    ups.nVersion = ProTxVersion::BASIC_BLS;
    ups.nType = MnType::REGULAR;
    ups.proTxHash = h;
    ups.netInfo.ip = seq_array<16>(0x22);
    ups.netInfo.port_be = 0x2334;
    ups.inputsHash = raw256(0x36);
    ups.sig = seq_array<96>(0x44);
    BlockType b3;
    b3.m_txs.push_back(coinbase_tx({script_bytes(0xD2)}));
    b3.m_txs.push_back(special_tx(CProUpServTx::SPECIALTX_TYPE, protx_payload(ups)));
    auto r3 = m.apply_block(b3, 2400022);
    EXPECT_EQ(r3.updated, 1u);
    EXPECT_TRUE(m.entries().at(h).isValid);
    EXPECT_EQ(m.entries().at(h).nPoSeBanHeight, 0u);
    EXPECT_EQ(m.entries().at(h).nPoSeRevivedHeight, 2400022u);
}

TEST(DashMnState, CollateralSpendRemovesMN) {
    auto reg = make_proreg(ProTxVersion::BASIC_BLS, MnType::REGULAR);
    // external collateral (non-null hash) so we can spend it precisely.
    reg.collateralOutpoint.hash = raw256(0xAA);
    reg.collateralOutpoint.index = 2;
    auto regtx = special_tx(CProRegTx::SPECIALTX_TYPE, protx_payload(reg));
    uint256 h = tx_hash(regtx);
    BlockType b1;
    b1.m_txs.push_back(coinbase_tx({script_bytes(0xE0)}));
    b1.m_txs.push_back(regtx);
    MnStateMachine m;
    m.apply_block(b1, 2400030);
    ASSERT_EQ(m.size(), 1u);

    // a tx that spends the collateral outpoint.
    MutableTransaction spend;
    spend.type = 0;
    TxIn in; in.prevout.hash = raw256(0xAA); in.prevout.index = 2;
    in.sequence = 0xFFFFFFFF;
    spend.vin.push_back(in);
    BlockType b2;
    b2.m_txs.push_back(coinbase_tx({script_bytes(0xE1)}));
    b2.m_txs.push_back(spend);
    auto r = m.apply_block(b2, 2400031);
    EXPECT_EQ(r.spent, 1u);
    EXPECT_EQ(m.size(), 0u);
    EXPECT_FALSE(m.find_by_collateral(reg.collateralOutpoint).has_value());
}

// ─── payee resolution + selection tiebreak ──────────────────────────────────

TEST(DashMnState, PayeeResolutionSetsLastPaidHeight) {
    auto reg = make_proreg(ProTxVersion::BASIC_BLS, MnType::REGULAR);
    auto payout = reg.scriptPayout.m_data;     // the script the coinbase pays
    auto regtx = special_tx(CProRegTx::SPECIALTX_TYPE, protx_payload(reg));
    uint256 h = tx_hash(regtx);

    BlockType b1;
    b1.m_txs.push_back(coinbase_tx({script_bytes(0xF0)}));
    b1.m_txs.push_back(regtx);
    MnStateMachine m;
    m.apply_block(b1, 2400040);
    EXPECT_EQ(m.entries().at(h).nLastPaidHeight, 0u);

    // next block: coinbase pays the MN payout script.
    BlockType b2;
    b2.m_txs.push_back(coinbase_tx(std::vector<std::vector<unsigned char>>{payout}));
    auto r = m.apply_block(b2, 2400041);
    EXPECT_EQ(r.paid, 1u);
    EXPECT_EQ(m.entries().at(h).nLastPaidHeight, 2400041u);
}

TEST(DashMnState, PayeeResolutionNeverRollsBackward) {
    auto reg = make_proreg(ProTxVersion::BASIC_BLS, MnType::REGULAR);
    auto payout = reg.scriptPayout.m_data;
    auto regtx = special_tx(CProRegTx::SPECIALTX_TYPE, protx_payload(reg));
    uint256 h = tx_hash(regtx);
    BlockType b1;
    b1.m_txs.push_back(coinbase_tx({script_bytes(0xF1)}));
    b1.m_txs.push_back(regtx);
    MnStateMachine m;
    m.apply_block(b1, 2400050);

    // (contiguity-cursor fix: folds must be sequential — a gapped fold is
    // now REFUSED outright, which is even stronger no-rollback protection.)
    BlockType bhi;
    bhi.m_txs.push_back(coinbase_tx(std::vector<std::vector<unsigned char>>{payout}));
    m.apply_block(bhi, 2400051);
    EXPECT_EQ(m.entries().at(h).nLastPaidHeight, 2400051u);

    // out-of-order lower height must NOT roll lastPaid backwards (the
    // whole apply is skipped by the forward-only guard).
    BlockType blo;
    blo.m_txs.push_back(coinbase_tx(std::vector<std::vector<unsigned char>>{payout}));
    auto rlo = m.apply_block(blo, 2400050);
    EXPECT_TRUE(rlo.skipped_out_of_order);
    EXPECT_EQ(m.entries().at(h).nLastPaidHeight, 2400051u);

    // and a GAPPED higher fold is refused too (never mutate on a
    // non-contiguous delivery — E4 re-soak contiguity fix).
    auto rg = m.apply_block(bhi, 2400060);
    EXPECT_TRUE(rg.gap_detected);
    EXPECT_EQ(m.entries().at(h).nLastPaidHeight, 2400051u);
}

// pick_paid_mn / find_expected_payee tiebreak: when two MNs share a payout
// script with equal scoring height, the memcmp-smaller proRegTxHash wins.
// We seed two MNState entries directly via load() to control the hashes.
TEST(DashMnState, PickPaidMnMemcmpTiebreak) {
    MnStateMachine m;
    auto shared = script_bytes(0x42, 25);

    MNState a;
    a.scriptPayout.m_data = shared;
    a.isValid = true;
    a.nRegisteredHeight = 2400000;
    a.nLastPaidHeight = 0;     // scores to nRegisteredHeight
    MNState b = a;             // identical scoring

    // hashA memcmp-smaller than hashB.
    uint256 hashA = raw256_byte(0, 0x01);
    uint256 hashB = raw256_byte(0, 0x02);
    ASSERT_LT(std::memcmp(hashA.data(), hashB.data(), 32), 0);

    std::vector<std::pair<uint256, MNState>> entries{{hashB, b}, {hashA, a}};
    m.load(entries);

    auto picked = m.pick_paid_mn(shared);
    ASSERT_TRUE(picked.has_value());
    EXPECT_EQ(*picked, hashA) << "memcmp-smaller proRegTxHash must win tiebreak";

    // find_expected_payee uses the same CompareByLastPaid scan.
    auto exp = m.find_expected_payee();
    ASSERT_TRUE(exp.has_value());
    EXPECT_EQ(*exp, hashA);
}

TEST(DashMnState, FindExpectedPayeeNormalizesSentinelLastPaid) {
    // UINT32_MAX (dashd protx -1 sentinel) must NOT beat real heights.
    MnStateMachine m;
    MNState sentinel;
    sentinel.isValid = true;
    sentinel.nRegisteredHeight = 2400000;
    sentinel.nLastPaidHeight = std::numeric_limits<uint32_t>::max(); // bug sentinel
    MNState real;
    real.isValid = true;
    real.nRegisteredHeight = 2400000;
    real.nLastPaidHeight = 10;     // genuinely oldest-paid -> should win

    uint256 hSent = raw256_byte(0, 0x01);   // memcmp-smaller
    uint256 hReal = raw256_byte(0, 0x02);
    std::vector<std::pair<uint256, MNState>> e{{hSent, sentinel}, {hReal, real}};
    m.load(e);
    auto exp = m.find_expected_payee();
    ASSERT_TRUE(exp.has_value());
    // sentinel normalized to 0 -> scores to nRegisteredHeight(2400000);
    // real scores to 10 -> real is oldest-unpaid -> real wins despite
    // being memcmp-larger.
    EXPECT_EQ(*exp, hReal) << "UINT32_MAX sentinel must not win payee selection";
}

TEST(DashMnState, FindExpectedPayeeSkipsInvalid) {
    MnStateMachine m;
    MNState valid, invalid;
    valid.isValid = true;   valid.nRegisteredHeight = 100; valid.nLastPaidHeight = 50;
    invalid.isValid = false; invalid.nRegisteredHeight = 1; invalid.nLastPaidHeight = 1; // would win if counted
    std::vector<std::pair<uint256, MNState>> e{
        {raw256_byte(0, 0x05), valid}, {raw256_byte(0, 0x06), invalid}};
    m.load(e);
    auto exp = m.find_expected_payee();
    ASSERT_TRUE(exp.has_value());
    EXPECT_EQ(*exp, raw256_byte(0, 0x05));
}

// ─── projection attribution (soak-found bad-cb-payee class, 2026-07-22) ────
//
// E4 re-soak evidence (run/e4-e1e2b, binary 0b6cd2bb): 13/124 embedded serves
// REJECTED by dashd with bad-cb-payee. Root cause: the old OBSERVATION
// attribution (scan coinbase outputs -> pick_paid_mn per match) is not
// idempotent — ONE duplicated attribution pass over an already-applied block
// re-picks inside a shared-payoutAddress group (53 testnet MNs share one
// address) and marks the NEXT MN of the group. The group's payment cursor
// then runs one slot ahead of dashd's DIP-3 schedule FOREVER, emitting the
// wrong coinbase payee at every height where the shifted cursor changes the
// projected address (~10% of serves). Exhaustive replay of the soak's 129
// embedded emissions reproduced ALL of them (129/129, incl. all 13 fails)
// from exactly two such duplicated attributions.
//
// Fix under test: dashd-exact PROJECTION attribution
// (evo/deterministicmns.cpp BuildNewListFromBlock: mark
// GetMNPayee(pindexPrev), never an output-scan inference) + whole-apply
// forward-only guard + payee-desync fail-closed.

// THE regression KAT (fails on the pre-fix machine, passes post-fix): a
// duplicated apply of one block must NOT advance a shared-payoutAddress
// group's payment cursor. Uses only the pre-fix API surface so it compiles
// against both implementations.
TEST(DashMnState, SharedPayoutGroupCursorSurvivesDuplicateApply) {
    MnStateMachine m;
    auto shared = script_bytes(0x42, 25);   // A and B share this payout
    auto other  = script_bytes(0x43, 25);   // C pays elsewhere

    MNState a; a.isValid = true; a.scriptPayout.m_data = shared;
    a.nRegisteredHeight = 1'000'000; a.nLastPaidHeight = 1'519'100;
    MNState b = a; b.nLastPaidHeight = 1'519'200;
    MNState c = a; c.scriptPayout.m_data = other; c.nLastPaidHeight = 1'519'300;
    // Distinct collaterals (load() keys a collateral index).
    a.collateralOutpoint.hash = raw256_byte(0, 0xA1);
    b.collateralOutpoint.hash = raw256_byte(0, 0xB1);
    c.collateralOutpoint.hash = raw256_byte(0, 0xC1);

    uint256 hA = raw256_byte(0, 0x01);
    uint256 hB = raw256_byte(0, 0x02);
    uint256 hC = raw256_byte(0, 0x03);
    m.load(std::vector<std::pair<uint256, MNState>>{{hA, a}, {hB, b}, {hC, c}});

    // dashd schedule: A (oldest) is the payee at H; the block pays `shared`.
    BlockType blk;
    blk.m_txs.push_back(coinbase_tx(std::vector<std::vector<unsigned char>>{shared}));
    auto r1 = m.apply_block(blk, 1'520'000);
    EXPECT_EQ(r1.paid, 1u);
    EXPECT_EQ(m.entries().at(hA).nLastPaidHeight, 1'520'000u);

    // DUPLICATE delivery of the same block. Pre-fix: pick_paid_mn skips the
    // just-marked A and spuriously marks B (the soak corruption). Post-fix:
    // the whole apply is skipped (forward-only) — no mutation.
    m.apply_block(blk, 1'520'000);
    EXPECT_EQ(m.entries().at(hB).nLastPaidHeight, 1'519'200u)
        << "duplicate apply must not mark the next MN of the shared group";

    // The projected next payee must still be B (dashd's schedule), not C.
    auto exp = m.find_expected_payee();
    ASSERT_TRUE(exp.has_value());
    EXPECT_EQ(*exp, hB)
        << "group cursor ran one slot ahead after a duplicate apply";
}

// Projection attribution marks exactly the projected MN and reports it —
// and an out-of-order (height <=) delivery is skipped whole.
TEST(DashMnState, ApplyBlockIsForwardOnlyAndReportsSkip) {
    MnStateMachine m;
    auto shared = script_bytes(0x44, 25);
    MNState a; a.isValid = true; a.scriptPayout.m_data = shared;
    a.nRegisteredHeight = 1'000'000; a.nLastPaidHeight = 1'519'100;
    a.collateralOutpoint.hash = raw256_byte(0, 0xA2);
    uint256 hA = raw256_byte(0, 0x01);
    m.load(std::vector<std::pair<uint256, MNState>>{{hA, a}});
    EXPECT_EQ(m.last_applied_height(), 0u);

    BlockType blk;
    blk.m_txs.push_back(coinbase_tx(std::vector<std::vector<unsigned char>>{shared}));
    auto r1 = m.apply_block(blk, 1'520'000);
    EXPECT_FALSE(r1.skipped_out_of_order);
    EXPECT_EQ(r1.paid, 1u);
    EXPECT_EQ(m.last_applied_height(), 1'520'000u);

    auto r2 = m.apply_block(blk, 1'520'000);     // duplicate
    EXPECT_TRUE(r2.skipped_out_of_order);
    EXPECT_EQ(r2.paid, 0u);
    auto r3 = m.apply_block(blk, 1'519'999);     // out-of-order
    EXPECT_TRUE(r3.skipped_out_of_order);
    EXPECT_EQ(m.last_applied_height(), 1'520'000u);
}

// A coinbase that does NOT pay the projected MN is a payee DESYNC: nothing is
// attributed (never guess) and the apply reports payee_desync so the caller
// fails closed. The old code silently marked whatever MN matched any output.
TEST(DashMnState, CoinbaseNotPayingProjectedMnReportsDesyncNoGuess) {
    MnStateMachine m;
    auto sA = script_bytes(0x45, 25);
    auto sB = script_bytes(0x46, 25);
    MNState a; a.isValid = true; a.scriptPayout.m_data = sA;
    a.nRegisteredHeight = 1'000'000; a.nLastPaidHeight = 1'519'100;  // projected
    MNState b = a; b.scriptPayout.m_data = sB; b.nLastPaidHeight = 1'519'200;
    a.collateralOutpoint.hash = raw256_byte(0, 0xA3);
    b.collateralOutpoint.hash = raw256_byte(0, 0xB3);
    uint256 hA = raw256_byte(0, 0x01);
    uint256 hB = raw256_byte(0, 0x02);
    m.load(std::vector<std::pair<uint256, MNState>>{{hA, a}, {hB, b}});

    // Block pays B's script while the projection says A -> desync, no mark.
    BlockType blk;
    blk.m_txs.push_back(coinbase_tx(std::vector<std::vector<unsigned char>>{sB}));
    auto r = m.apply_block(blk, 1'520'000);
    EXPECT_TRUE(r.payee_desync);
    EXPECT_EQ(r.paid, 0u);
    EXPECT_EQ(m.entries().at(hA).nLastPaidHeight, 1'519'100u);
    EXPECT_EQ(m.entries().at(hB).nLastPaidHeight, 1'519'200u)
        << "desync must not attribute the payment to the observed-match MN";
}


// ─── seed-gap contiguity (soak-found bad-cb-payee class #2, 2026-07-23) ────
//
// E4 re-soak evidence (run/e4-e1e2c, binary 7daa4d61, testnet dashd
// @192.168.86.52): the E2c seed was fetched as-of h=1519820; blocks 1519821
// and 1519822 were mined during header sync and NEVER folded; the first live
// full-block fold was 1519823. dashd advanced its DIP-3 payment cursor at
// the two skipped blocks (both paid yeRZB…-group MNs: 6d1b185b…, 8e11eb78…);
// c2pool's queue did not, so every subsequent fold marked a 2-slots-behind
// MN of the SAME shared payout address (invisible to the pass-3 script
// cross-check). At 1519827 dashd's head crossed into the yVXDA… group
// (617d72f6…) while our lagged head was still yeRZB…-member 05b68797… —
// bad-cb-payee served for the whole 1519826→1519827 window; the desync net
// only fired at 1519827-connect, one block too late by construction.
//
// Fix under test: load(entries, as_of) seeds the forward-contiguous apply
// cursor; apply_block REFUSES a non-contiguous fold (gap_detected, no
// mutation) so the caller fails closed + re-seeds instead of silently
// advancing a stale queue.

// The seed's as-of height IS the cursor: duplicate/old folds are skipped,
// a gapped fold is refused, only as_of+1 advances.
TEST(DashMnState, SeedAsOfHeightSeedsContiguityCursor) {
    MnStateMachine m;
    auto shared = script_bytes(0x47, 25);
    MNState a; a.isValid = true; a.scriptPayout.m_data = shared;
    a.nRegisteredHeight = 1'000'000; a.nLastPaidHeight = 1'519'100;
    a.collateralOutpoint.hash = raw256_byte(0, 0xA4);
    uint256 hA = raw256_byte(0, 0x01);
    m.load(std::vector<std::pair<uint256, MNState>>{{hA, a}}, 1'519'820);
    EXPECT_EQ(m.last_applied_height(), 1'519'820u);

    BlockType blk;
    blk.m_txs.push_back(coinbase_tx(std::vector<std::vector<unsigned char>>{shared}));

    // At/below the seed: duplicate/out-of-order, skipped whole.
    auto r0 = m.apply_block(blk, 1'519'820);
    EXPECT_TRUE(r0.skipped_out_of_order);

    // Beyond as_of+1: a gap — blocks 1'519'821..822 would be skipped and the
    // cursor would go stale. PRE-FIX the machine folded this silently (the
    // incident); POST-FIX it refuses with gap_detected and no mutation.
    auto r2 = m.apply_block(blk, 1'519'823);
    EXPECT_TRUE(r2.gap_detected);
    EXPECT_EQ(r2.paid, 0u);
    EXPECT_EQ(m.last_applied_height(), 1'519'820u);
    EXPECT_EQ(m.entries().at(hA).nLastPaidHeight, 1'519'100u)
        << "a gapped apply must not attribute anything";

    // Exactly as_of+1: contiguous, folds normally.
    auto r1 = m.apply_block(blk, 1'519'821);
    EXPECT_FALSE(r1.gap_detected);
    EXPECT_EQ(r1.paid, 1u);
    EXPECT_EQ(m.last_applied_height(), 1'519'821u);
}

// ─── FROM-WIRE vector: testnet 1519826 → 1519827 (E4 re-soak incident) ─────
//
// Real data captured from dashd testnet @192.168.86.52:
//   - kMnSetAsOf1519825: `protx list valid true 1519825` (85 valid MNs;
//     payout-address groups: 53x yVXDAM73…, 28x yeRZBWYf…, 4 singles);
//   - the two coinbase payout scripts from `getblock <hash> 2` at 1519826
//     (block 0000004c14c66f9f…, MN output 1.11618884 → yeRZBWYf…) and
//     1519827 (block 0000001cb3001858…, MN output 1.11611384 → yVXDAM73…);
//   - ground truth specific payees: `protx list valid true <h>` shows
//     lastPaidHeight==1519826 for ff261d2c… (yeRZB group) and
//     lastPaidHeight==1519827 for 617d72f6… (yVXDA group).

#include "dash_mn_set_1519825.inc"

static std::vector<unsigned char> hexscript(const char* h) {
    std::vector<unsigned char> v;
    auto nib = [](char c) -> unsigned {
        return (c >= '0' && c <= '9') ? unsigned(c - '0') : unsigned(c - 'a' + 10);
    };
    for (const char* p = h; p[0] && p[1]; p += 2)
        v.push_back(static_cast<unsigned char>((nib(p[0]) << 4) | nib(p[1])));
    return v;
}

static std::vector<std::pair<uint256, MNState>> mn_set_as_of_1519825() {
    std::vector<std::pair<uint256, MNState>> v;
    for (const auto& e : kMnSetAsOf1519825) {
        MNState s;
        s.isValid            = true;
        s.scriptPayout.m_data = hexscript(e.script);
        s.nLastPaidHeight    = e.last_paid;
        s.nRegisteredHeight  = e.registered;
        s.nPoSeRevivedHeight = e.revived;
        // distinct collaterals (load() keys a collateral index); the proTx
        // hash itself is unique per MN so reuse it.
        s.collateralOutpoint.hash  = uint256S(e.protx);
        s.collateralOutpoint.index = 0;
        v.emplace_back(uint256S(e.protx), s);
    }
    return v;
}

// The specific proTxHashes dashd paid (ground truth, see header above).
static const char* kPaidAt1519826 =
    "ff261d2c1c76907a2ad8aeb6c5611796f03b5cbd88ae92452a4727e13f4f4ac9";
static const char* kPaidAt1519827 =
    "617d72f6941af02ef5f2ceaa2ac0315ed5db0979c45391398f74b0fadc100ca6";
// The two shared MN payout scripts (P2PKH of yeRZBWYf… / yVXDAM73…).
static const char* kScriptYeRZB =
    "76a914c69a0bda7daaae481be8def95e5f347a1d00a4b488ac";
static const char* kScriptYVXDA =
    "76a91464f2b2b84f62d68a2cd7f7f5fb2b5aa75ef716d788ac";

// The real coinbase payout scripts (all outputs, in order, from the wire).
static MutableTransaction coinbase_1519826() {
    return coinbase_tx(std::vector<std::vector<unsigned char>>{
        hexscript("76a9142629e1bbb4960da4c86226c876019e55c7c0346288ac"),
        hexscript("6a"),
        hexscript(kScriptYeRZB),
        hexscript("76a91420cb5c22b1e4d5947e5c112c7696b51ad9af3c6188ac"),
        hexscript("6a28de5d37566ad5bab938ddbe82c123bd051d3ec7c47fbaa641f9"
                  "0fc9032a5acadf0000000000000000")});
}
static MutableTransaction coinbase_1519827() {
    return coinbase_tx(std::vector<std::vector<unsigned char>>{
        hexscript("76a914b489115851ca07a26a5ad8bac3cec3c7dbebd83188ac"),
        hexscript("6a"),
        hexscript(kScriptYVXDA)});
}

// (i) After the REAL 1519826 block folds on the REAL 1519825 list, the
// projection must advance to the SPECIFIC proTxHash dashd pays at 1519827 —
// 617d72f6… across the shared-address-group boundary into the yVXDA group —
// exactly mirroring dashd BuildNewListFromBlock + GetMNPayee(pindexPrev).
TEST(DashMnState, FromWire1519826To1519827AdvancesSpecificProTxAcrossGroupBoundary) {
    MnStateMachine m;
    m.load(mn_set_as_of_1519825(), 1'519'825);

    // Projection for 1519826 from the as-of-1519825 list: dashd paid
    // ff261d2c… (yeRZB group) there.
    auto p26 = m.find_expected_payee();
    ASSERT_TRUE(p26.has_value());
    EXPECT_EQ(p26->GetHex(), kPaidAt1519826);

    BlockType b26;
    b26.m_txs.push_back(coinbase_1519826());
    auto r26 = m.apply_block(b26, 1'519'826);
    EXPECT_FALSE(r26.gap_detected);
    EXPECT_FALSE(r26.payee_desync);
    EXPECT_EQ(r26.paid, 1u);
    EXPECT_EQ(m.entries().at(uint256S(kPaidAt1519826)).nLastPaidHeight,
              1'519'826u)
        << "the SPECIFIC projected MN (not just any yeRZB-address MN) must "
           "carry the payment mark";

    // THE incident assertion: the projection for 1519827 is 617d72f6…
    // (yVXDA), NOT a yeRZB-group member (the soak binary projected
    // 05b68797… / yeRZB and served bad-cb-payee).
    auto p27 = m.find_expected_payee();
    ASSERT_TRUE(p27.has_value());
    EXPECT_EQ(p27->GetHex(), kPaidAt1519827);
    EXPECT_EQ(m.entries().at(*p27).scriptPayout.m_data, hexscript(kScriptYVXDA));
}

// The incident mechanism itself, from-wire: folding the real 1519826 block
// over a cursor that missed blocks (the soak missed 1519821+1519822) is
// REFUSED. PRE-FIX this folded silently — the coinbase pays yeRZB, our
// (stale) projection is also a yeRZB-group member, so the script cross-check
// passed and the WRONG specific MN was marked (paid=1, no desync): the
// silent cursor lag that surfaced as bad-cb-payee at 1519827.
TEST(DashMnState, FromWireGappedFoldIsRefusedNotSilentlyMisattributed) {
    MnStateMachine m;
    m.load(mn_set_as_of_1519825(), 1'519'823);   // cursor claims two blocks behind

    BlockType b26;
    b26.m_txs.push_back(coinbase_1519826());
    auto r = m.apply_block(b26, 1'519'826);
    EXPECT_TRUE(r.gap_detected);
    EXPECT_FALSE(r.payee_desync);
    EXPECT_EQ(r.paid, 0u)
        << "a gapped fold must never attribute the payment (pre-fix it "
           "marked a wrong same-address MN here)";
    EXPECT_EQ(m.last_applied_height(), 1'519'823u);
    EXPECT_EQ(m.entries().at(uint256S(kPaidAt1519826)).nLastPaidHeight,
              1'519'741u)
        << "no mutation on a refused apply (1519741 = ff261d2c…'s from-wire "
           "lastPaidHeight in the 1519825 snapshot)";
}

// (ii) If the queue is nonetheless wrong (any residual divergence source),
// the desync net MUST fire the moment the network shows a coinbase that does
// not pay our projected MN: at 1519827 the projection (617d72f6…/yVXDA after
// a correct 1519826 fold) vs a coinbase paying yeRZB (what the incident
// binary emitted) is a DESYNC — nothing attributed, caller fails closed.
TEST(DashMnState, FromWireWrongGroupCoinbaseFiresDesyncNoAttribution) {
    MnStateMachine m;
    m.load(mn_set_as_of_1519825(), 1'519'825);
    BlockType b26;
    b26.m_txs.push_back(coinbase_1519826());
    ASSERT_EQ(m.apply_block(b26, 1'519'826).paid, 1u);

    BlockType bad27;   // the incident binary's wrong-group coinbase
    bad27.m_txs.push_back(coinbase_tx(std::vector<std::vector<unsigned char>>{
        hexscript("76a914b489115851ca07a26a5ad8bac3cec3c7dbebd83188ac"),
        hexscript("6a"),
        hexscript(kScriptYeRZB)}));
    auto r = m.apply_block(bad27, 1'519'827);
    EXPECT_TRUE(r.payee_desync);
    EXPECT_EQ(r.paid, 0u);
    EXPECT_EQ(m.entries().at(uint256S(kPaidAt1519827)).nLastPaidHeight,
              1'519'742u)
        << "desync must not attribute (1519742 = 617d72f6…'s from-wire "
           "lastPaidHeight in the 1519825 snapshot)";
}

// ─── sync_validity_from_sml (Bug 12/14 triple-field reconciliation) ─────────

TEST(DashMnState, SyncValidityFromSmlBansAndRevives) {
    MnStateMachine m;
    uint256 h = raw256_byte(0, 0x09);
    MNState s;
    s.isValid = true;
    s.nRegisteredHeight = 2400000;
    s.nPoSeBanHeight = 0;
    s.nPoSeRevivedHeight = 0;
    std::vector<std::pair<uint256, MNState>> e{{h, s}};
    m.load(e);

    // SML says this MN is now invalid (implicit PoSe ban, no tx observed).
    CSimplifiedMNListEntry sml_e;
    sml_e.proRegTxHash = h;
    sml_e.isValid = false;
    CSimplifiedMNList sml_ban(std::vector<CSimplifiedMNListEntry>{sml_e});
    auto r1 = m.sync_validity_from_sml(sml_ban, 2450000);
    EXPECT_EQ(r1.matched, 1u);
    EXPECT_EQ(r1.flipped_to_invalid, 1u);
    EXPECT_EQ(r1.ban_height_set, 1u);
    EXPECT_FALSE(m.entries().at(h).isValid);
    EXPECT_EQ(m.entries().at(h).nPoSeBanHeight, 2450000u);

    // SML later says valid again (revive).
    CSimplifiedMNListEntry sml_e2;
    sml_e2.proRegTxHash = h;
    sml_e2.isValid = true;
    CSimplifiedMNList sml_rev(std::vector<CSimplifiedMNListEntry>{sml_e2});
    auto r2 = m.sync_validity_from_sml(sml_rev, 2460000);
    EXPECT_EQ(r2.flipped_to_valid, 1u);
    EXPECT_EQ(r2.revived_height_set, 1u);
    EXPECT_TRUE(m.entries().at(h).isValid);
    EXPECT_EQ(m.entries().at(h).nPoSeBanHeight, 0u);
    EXPECT_EQ(m.entries().at(h).nPoSeRevivedHeight, 2460000u);
}

TEST(DashMnState, SyncValidityFromSmlIdempotentAndSmlOnly) {
    MnStateMachine m;
    uint256 h = raw256_byte(0, 0x0A);
    MNState s; s.isValid = true; s.nRegisteredHeight = 2400000;
    m.load(std::vector<std::pair<uint256, MNState>>{{h, s}});

    // matching validity -> no flips (idempotent).
    CSimplifiedMNListEntry same; same.proRegTxHash = h; same.isValid = true;
    auto r = m.sync_validity_from_sml(
        CSimplifiedMNList(std::vector<CSimplifiedMNListEntry>{same}), 2450000);
    EXPECT_EQ(r.matched, 1u);
    EXPECT_EQ(r.flipped_to_invalid, 0u);
    EXPECT_EQ(r.flipped_to_valid, 0u);

    // SML entry not in our set -> sml_only, no crash.
    CSimplifiedMNListEntry only; only.proRegTxHash = raw256_byte(0, 0x0B);
    only.isValid = true;
    auto r2 = m.sync_validity_from_sml(
        CSimplifiedMNList(std::vector<CSimplifiedMNListEntry>{only}), 2450001);
    EXPECT_EQ(r2.sml_only, 1u);
    EXPECT_EQ(r2.matched, 0u);
}


// --------------------------------------------------------------------------
// Bug 14 selection-path guard. nPoSeBanHeight is write-only when picking a
// payee, so a divergent persisted snapshot (isValid==true alongside a live
// ban height -- reachable after a consensus PoSe ban that never appears as a
// special tx) must be fail-closed OUT of BOTH selection scans, never paid on
// the boolean alone. Pairs with the maintainer caller-guard tests
// (MnlistdiffBanReconcilesOntoPayeeAxis / SeedReconcileAppliesAlreadyPresentSmlBan)
// that prove sync_validity_from_sml() keeps a production caller.
// --------------------------------------------------------------------------
TEST(DashMnState, SelectionGuardExcludesValidButBannedSnapshot) {
    MnStateMachine m;
    uint256 banned = raw256_byte(0, 0x0A);
    uint256 clean  = raw256_byte(0, 0x0B);

    MNState sb; sb.isValid = true; sb.nRegisteredHeight = 2400000;
    sb.nPoSeBanHeight = 2513418;               // live ban, yet bool left true
    sb.scriptPayout.m_data = script_bytes(0x76, 25);

    MNState sc; sc.isValid = true; sc.nRegisteredHeight = 2400001;
    sc.nPoSeBanHeight = 0;                      // genuinely valid
    sc.scriptPayout.m_data = script_bytes(0x77, 25);

    m.load(std::vector<std::pair<uint256, MNState>>{{banned, sb}, {clean, sc}});

    // find_expected_payee must skip the banned snapshot and pick the clean MN.
    auto exp = m.find_expected_payee();
    ASSERT_TRUE(exp.has_value());
    EXPECT_EQ(*exp, clean);

    // pick_paid_mn on the banned MN's own script must refuse it outright...
    EXPECT_FALSE(m.pick_paid_mn(sb.scriptPayout.m_data).has_value());
    // ...but still serve the clean MN on its script.
    auto pk = m.pick_paid_mn(sc.scriptPayout.m_data);
    ASSERT_TRUE(pk.has_value());
    EXPECT_EQ(*pk, clean);
}

// The -1 / UINT32_MAX "never banned" sentinel must NOT read as a live ban --
// the guard normalizes it exactly as the height scoring does.
TEST(DashMnState, SelectionGuardTreatsSentinelBanHeightAsNeverBanned) {
    MnStateMachine m;
    uint256 h = raw256_byte(0, 0x0C);
    MNState s; s.isValid = true; s.nRegisteredHeight = 2400000;
    s.nPoSeBanHeight = 0xFFFFFFFFu;            // dashd protx -1 sentinel
    s.scriptPayout.m_data = script_bytes(0x78, 25);
    m.load(std::vector<std::pair<uint256, MNState>>{{h, s}});

    auto exp = m.find_expected_payee();
    ASSERT_TRUE(exp.has_value());
    EXPECT_EQ(*exp, h);
    auto pk = m.pick_paid_mn(s.scriptPayout.m_data);
    ASSERT_TRUE(pk.has_value());
    EXPECT_EQ(*pk, h);
}

// ════════════════════════════════════════════════════════════════════════
// Ranked payee candidates + the SML-attested PoSe-ban recovery walk.
//
// PoSe bans are consensus-driven and never appear as a special tx, so
// apply_block cannot observe one at any price. A masternode banned after a
// snapshot/anchor was taken keeps the head of our payment queue forever; the
// block pays the NEXT eligible node and pass 3 reports payee_desync. The SML
// is the only carrier of that ban, so it is the only thing that may license a
// repair. These pin the mechanism at the unit boundary; the production-seam
// coverage (a real MnCheckpointLane driven through pump()/on_block_connected)
// lives in test_dash_mn_checkpoint.cpp.
// ════════════════════════════════════════════════════════════════════════

static MNState payee_mn(uint32_t last_paid,
                        const std::vector<unsigned char>& script) {
    MNState s;
    s.isValid             = true;
    s.nRegisteredHeight   = 2400000;
    s.nLastPaidHeight     = last_paid;
    s.scriptPayout.m_data = script;
    return s;
}

// A hook answering from an explicit table; anything absent answers nullopt,
// which is the "no opinion" state the walk must refuse to act on.
static MnStateMachine::SmlValidityFn attest(
    std::vector<std::pair<uint256, bool>> table) {
    return [table](const uint256& h) -> std::optional<bool> {
        for (const auto& [k, v] : table)
            if (k == h) return v;
        return std::nullopt;
    };
}

TEST(DashMnState, RankPayeeCandidatesMirrorsCompareByLastPaid) {
    MnStateMachine m;
    // Two ties at 1000 to exercise the proTxHash memcmp tiebreak, then two
    // distinct heights above them.
    uint256 a = raw256_byte(0, 0x01), b = raw256_byte(0, 0x02);
    uint256 c = raw256_byte(0, 0x03), d = raw256_byte(0, 0x04);
    m.load(std::vector<std::pair<uint256, MNState>>{
        {d, payee_mn(1002, script_bytes(0x40, 25))},
        {b, payee_mn(1000, script_bytes(0x41, 25))},
        {c, payee_mn(1001, script_bytes(0x42, 25))},
        {a, payee_mn(1000, script_bytes(0x43, 25))}});

    auto ranked = m.rank_payee_candidates(4);
    ASSERT_EQ(ranked.size(), 4u);
    EXPECT_EQ(ranked[0], a) << "tie at 1000 breaks on proTxHash memcmp ascending";
    EXPECT_EQ(ranked[1], b);
    EXPECT_EQ(ranked[2], c);
    EXPECT_EQ(ranked[3], d);

    // The winner is find_expected_payee() BY CONSTRUCTION -- the two share one
    // scan, so they can never drift apart.
    auto exp = m.find_expected_payee();
    ASSERT_TRUE(exp.has_value());
    EXPECT_EQ(*exp, ranked.front());

    // Truncation keeps the FRONT of the queue, not an arbitrary subset.
    auto top2 = m.rank_payee_candidates(2);
    ASSERT_EQ(top2.size(), 2u);
    EXPECT_EQ(top2[0], a);
    EXPECT_EQ(top2[1], b);
    EXPECT_TRUE(m.rank_payee_candidates(0).empty());
}

TEST(DashMnState, RankPayeeCandidatesExcludesInvalidAndBanned) {
    MnStateMachine m;
    uint256 a = raw256_byte(0, 0x01), b = raw256_byte(0, 0x02),
            c = raw256_byte(0, 0x03);
    MNState sa = payee_mn(1000, script_bytes(0x50, 25)); sa.isValid = false;
    MNState sb = payee_mn(1001, script_bytes(0x51, 25)); sb.nPoSeBanHeight = 2500000;
    MNState sc = payee_mn(1002, script_bytes(0x52, 25));
    m.load(std::vector<std::pair<uint256, MNState>>{{a, sa}, {b, sb}, {c, sc}});

    auto ranked = m.rank_payee_candidates(MnStateMachine::kPayeeCandidates);
    ASSERT_EQ(ranked.size(), 1u) << "neither an invalid nor a live-banned"
                                    " masternode may be a payee candidate";
    EXPECT_EQ(ranked[0], c);
}

// The default posture: no hook, so a mismatch is a desync and nothing else.
// This is the guarantee that every pre-existing caller and KAT is untouched.
TEST(DashMnState, NullSmlHookLeavesPayeeDesyncExactlyAsBefore) {
    MnStateMachine m;
    uint256 a = raw256_byte(0, 0x01), b = raw256_byte(0, 0x02);
    auto s1 = script_bytes(0x60, 25);
    auto s2 = script_bytes(0x61, 25);
    m.load(std::vector<std::pair<uint256, MNState>>{
               {a, payee_mn(1000, s1)}, {b, payee_mn(1001, s2)}},
           2400000);
    EXPECT_FALSE(m.has_sml_validity_fn());

    BlockType blk;
    blk.m_txs.push_back(coinbase_tx({s2}));      // pays queue slot 2
    auto r = m.apply_block(blk, 2400001);

    EXPECT_TRUE(r.payee_desync);
    EXPECT_EQ(r.paid, 0u);
    EXPECT_EQ(r.sml_recovered, 0u);
    ASSERT_TRUE(r.projected_payee.has_value());
    EXPECT_EQ(*r.projected_payee, a);
    EXPECT_TRUE(m.entries().at(a).isValid) << "no hook, no exclusion";
    EXPECT_EQ(m.entries().at(a).nPoSeBanHeight, 0u);
    EXPECT_EQ(m.entries().at(b).nLastPaidHeight, 1001u)
        << "a desync attributes NOTHING";
}

TEST(DashMnState, SmlAttestedBanDemotesPermanentlyAndAttributesToTheNext) {
    MnStateMachine m;
    uint256 a = raw256_byte(0, 0x01), b = raw256_byte(0, 0x02);
    auto s1 = script_bytes(0x62, 25);
    auto s2 = script_bytes(0x63, 25);
    m.load(std::vector<std::pair<uint256, MNState>>{
               {a, payee_mn(1000, s1)}, {b, payee_mn(1001, s2)}},
           2400000);
    m.set_sml_validity_fn(attest({{a, false}, {b, true}}));
    m.set_sml_recovery_cap(4);

    BlockType blk;
    blk.m_txs.push_back(coinbase_tx({s2}));
    auto r = m.apply_block(blk, 2400001);

    EXPECT_FALSE(r.payee_desync);
    EXPECT_EQ(r.paid, 1u);
    EXPECT_EQ(r.sml_recovered, 1u);
    EXPECT_EQ(m.sml_recovered_total(), 1u);
    EXPECT_FALSE(m.entries().at(a).isValid);
    EXPECT_EQ(m.entries().at(a).nPoSeBanHeight, 2400001u);
    EXPECT_EQ(m.entries().at(a).nLastPaidHeight, 1000u);
    EXPECT_EQ(m.entries().at(b).nLastPaidHeight, 2400001u);
}

// The acceptance side is EXACT script equality, never "the only unexplained
// output". A coinbase that pays nobody in the set must not be attributed to
// whichever candidate happens to be next, no matter how many bans are attested.
TEST(DashMnState, SmlAttestedBanStillNeedsAnExactCoinbaseScriptMatch) {
    MnStateMachine m;
    uint256 a = raw256_byte(0, 0x01), b = raw256_byte(0, 0x02);
    auto s1 = script_bytes(0x64, 25);
    auto s2 = script_bytes(0x65, 25);
    m.load(std::vector<std::pair<uint256, MNState>>{
               {a, payee_mn(1000, s1)}, {b, payee_mn(1001, s2)}},
           2400000);
    m.set_sml_validity_fn(attest({{a, false}, {b, false}}));
    m.set_sml_recovery_cap(4);

    BlockType blk;
    blk.m_txs.push_back(coinbase_tx({script_bytes(0x66, 25)}));  // nobody's
    auto r = m.apply_block(blk, 2400001);

    EXPECT_TRUE(r.payee_desync);
    EXPECT_EQ(r.sml_recovered, 0u);
    EXPECT_TRUE(m.entries().at(a).isValid)
        << "a refused walk must leave NO partial exclusion behind";
    EXPECT_TRUE(m.entries().at(b).isValid);
}

// The cap discriminator. IDENTICAL input either side; the only difference is
// the budget, so a pass/fail split here can only be the cap.
TEST(DashMnState, SmlRecoveryCapIsTheOnlyDifferenceAtTheBoundary) {
    uint256 a = raw256_byte(0, 0x01), b = raw256_byte(0, 0x02),
            c = raw256_byte(0, 0x03), d = raw256_byte(0, 0x04);
    auto shared = script_bytes(0x70, 25);   // a, b, c all pay this
    auto lone   = script_bytes(0x71, 25);   // d alone

    auto build = [&](MnStateMachine& m, size_t cap) {
        m.load(std::vector<std::pair<uint256, MNState>>{
                   {a, payee_mn(1000, shared)}, {b, payee_mn(1001, shared)},
                   {c, payee_mn(1002, shared)}, {d, payee_mn(1003, lone)}},
               2400000);
        m.set_sml_validity_fn(attest({{a, false}, {b, false}, {c, false},
                                      {d, true}}));
        m.set_sml_recovery_cap(cap);
    };
    BlockType blk;
    blk.m_txs.push_back(coinbase_tx({lone}));   // dashd paid queue slot 4

    // Budget 2 < the 3 exclusions the walk needs: refuse, mutate nothing.
    MnStateMachine tight;
    build(tight, 2);
    auto r_tight = tight.apply_block(blk, 2400001);
    EXPECT_TRUE(r_tight.payee_desync);
    EXPECT_EQ(r_tight.sml_recovered, 0u);
    EXPECT_TRUE(tight.entries().at(a).isValid);
    EXPECT_EQ(tight.entries().at(d).nLastPaidHeight, 1003u);

    // Budget 3 == what it needs: accept.
    MnStateMachine roomy;
    build(roomy, 3);
    auto r_roomy = roomy.apply_block(blk, 2400001);
    EXPECT_FALSE(r_roomy.payee_desync);
    EXPECT_EQ(r_roomy.sml_recovered, 3u);
    EXPECT_EQ(roomy.sml_recovered_total(), 3u);
    for (const auto& h : {a, b, c}) {
        EXPECT_FALSE(roomy.entries().at(h).isValid) << h.GetHex();
        EXPECT_EQ(roomy.entries().at(h).nPoSeBanHeight, 2400001u);
    }
    EXPECT_EQ(roomy.entries().at(d).nLastPaidHeight, 2400001u);
}

// The walk stops at the FIRST candidate the SML does not attest invalid. An
// attested-valid runner-up is counter-evidence: the mismatch is a genuine
// desync and must be reported as one even though a deeper candidate would
// have matched the coinbase.
TEST(DashMnState, SmlRecoveryStopsAtTheFirstUnattestedCandidate) {
    MnStateMachine m;
    uint256 a = raw256_byte(0, 0x01), b = raw256_byte(0, 0x02),
            c = raw256_byte(0, 0x03);
    auto s1 = script_bytes(0x72, 25);
    auto s2 = script_bytes(0x73, 25);
    auto s3 = script_bytes(0x74, 25);
    m.load(std::vector<std::pair<uint256, MNState>>{
               {a, payee_mn(1000, s1)}, {b, payee_mn(1001, s2)},
               {c, payee_mn(1002, s3)}},
           2400000);
    // a is banned, b is LIVE, and the coinbase pays c.
    m.set_sml_validity_fn(attest({{a, false}, {b, true}, {c, false}}));
    m.set_sml_recovery_cap(8);

    BlockType blk;
    blk.m_txs.push_back(coinbase_tx({s3}));
    auto r = m.apply_block(blk, 2400001);

    EXPECT_TRUE(r.payee_desync);
    EXPECT_EQ(r.sml_recovered, 0u);
    EXPECT_TRUE(m.entries().at(a).isValid);
    EXPECT_EQ(m.entries().at(c).nLastPaidHeight, 1002u);
}

// Permanence is the whole point: a one-shot skip would put the banned node
// back at the head of the queue at its next turn and desync the replay again.
TEST(DashMnState, SmlRecoveryExclusionSurvivesTheNextQueueTurn) {
    MnStateMachine m;
    uint256 a = raw256_byte(0, 0x01), b = raw256_byte(0, 0x02);
    auto s1 = script_bytes(0x75, 25);
    auto s2 = script_bytes(0x76, 25);
    m.load(std::vector<std::pair<uint256, MNState>>{
               {a, payee_mn(1000, s1)}, {b, payee_mn(1001, s2)}},
           2400000);
    m.set_sml_validity_fn(attest({{a, false}, {b, true}}));
    m.set_sml_recovery_cap(4);

    BlockType blk;
    blk.m_txs.push_back(coinbase_tx({s2}));
    ASSERT_FALSE(m.apply_block(blk, 2400001).payee_desync);

    // b now has the newest lastPaidHeight, so an un-excluded `a` would be back
    // at the head of the queue. It must not be a candidate at all.
    EXPECT_TRUE(m.rank_payee_candidates(8).empty()
                || m.rank_payee_candidates(8).front() != a);
    auto r2 = m.apply_block(blk, 2400002);
    EXPECT_EQ(r2.sml_recovered, 0u) << "no SECOND exclusion should be needed";
    EXPECT_FALSE(r2.payee_desync);
    EXPECT_EQ(m.sml_recovered_total(), 1u);
    EXPECT_EQ(m.entries().at(b).nLastPaidHeight, 2400002u);
}

// ═══════════════════════════════════════════════════════════════════════════
// THE BAN WE NEVER MEASURED — ProUpServTx revive gate vs fold sampling
// ═══════════════════════════════════════════════════════════════════════════
//
// dashcore revives on a ProUpServTx iff the masternode IsBanned() in the
// PRE-BLOCK list. This machine mirrors that gate against ITS OWN belief about
// who is banned — and that belief only ever changes at a fold. A PoSe ban is
// consensus-computed, never a transaction, so a ban that starts AND ends
// between two folds never enters the belief, the gate reads false, and
// nPoSeRevivedHeight is left at the masternode's stale last payment while
// dashd moves it to the revive height.
//
// TRACED ON MAINNET (2026-08-03, anchor 2513000, fold interval 500): proTx
// 80b4892b… banned at 2514570, revived by a ProUpServTx at 2514574 — four
// blocks, entirely inside the 2514150..2514650 fold interval. We scored it
// 2513453 (its last payment); dashd scored it 2514574. That put it at the head
// of OUR queue at 2515511 and at rank 1116 of dashd's.
//
// The obvious repair — set nPoSeRevivedHeight on EVERY ProUpServTx — is
// refuted by the same window: 2 of its 22 ProUpServTx came from masternodes
// that were NOT banned (d07e1f49… at 2515068, ban height -1, PoSe penalty 0)
// and dashd set no revive height for them. So the machine must MEASURE the
// gate, and where it cannot, say so.

namespace {

// A masternode set holding one entry that is valid and unbanned — the state in
// which a ProUpServTx's outcome depends entirely on a ban we may not have seen.
struct ReviveFixture {
    MnStateMachine m;
    uint256        mn;
    BlockType      blk;      // coinbase pays `mn`, plus a ProUpServTx for it

    explicit ReviveFixture(uint32_t last_paid = 2513453)
    {
        mn = raw256_byte(0, 0x5A);
        MNState s;
        s.isValid             = true;
        s.nRegisteredHeight   = 2400000;
        s.nLastPaidHeight     = last_paid;
        s.nPoSeBanHeight      = 0;
        s.nPoSeRevivedHeight  = 0;
        s.scriptPayout.m_data = script_bytes(0xE1);
        m.load(std::vector<std::pair<uint256, MNState>>{{mn, s}}, 2514573);

        CProUpServTx ups;
        ups.nVersion  = ProTxVersion::BASIC_BLS;
        ups.nType     = MnType::REGULAR;
        ups.proTxHash = mn;
        ups.netInfo.ip = seq_array<16>(0x22);
        ups.netInfo.port_be = 0x2334;
        ups.inputsHash = raw256(0x41);
        ups.sig        = seq_array<96>(0x42);
        blk.m_txs.push_back(coinbase_tx({script_bytes(0xE1)}));
        blk.m_txs.push_back(
            special_tx(CProUpServTx::SPECIALTX_TYPE, protx_payload(ups)));
    }

    // Fold a list dated at `height` attesting `mn` valid/invalid.
    void fold(uint32_t height, bool valid)
    {
        CSimplifiedMNListEntry e;
        e.proRegTxHash = mn;
        e.isValid      = valid;
        m.sync_validity_from_sml(
            CSimplifiedMNList(std::vector<CSimplifiedMNListEntry>{e}), height);
    }
};

} // namespace

// ── CASE A. No fold dated at the pre-block height: the revive outcome is
// UNKNOWN and must be counted as such. Nothing is guessed in either direction.
TEST(DashMnReviveBanState, UnmeasuredBanIsCountedNotGuessed) {
    ReviveFixture f;
    ASSERT_EQ(f.m.ban_state_measured_at(), 0u);
    ASSERT_FALSE(f.m.ban_state_measured_for(2514574));

    const auto r = f.m.apply_block(f.blk, 2514574);
    EXPECT_EQ(r.revive_unmeasured, 1u)
        << "a ProUpServTx whose revive turns on a ban state this set never"
           " measured is a BLIND SPOT and has to be counted as one";
    ASSERT_EQ(r.revive_unmeasured_protx.size(), 1u);
    EXPECT_EQ(r.revive_unmeasured_protx.front(), f.mn)
        << "the report must NAME the masternode, not just count it";
    EXPECT_EQ(r.revived, 0u);
    EXPECT_EQ(r.revive_declined_measured, 0u);
    EXPECT_EQ(r.updated, 1u) << "the service update itself still applies";
    // The refuted repair, pinned: nothing is written to the revive height on a
    // ban we did not measure. Mutating the else-branch into
    // `nPoSeRevivedHeight = height` reds exactly here.
    EXPECT_EQ(f.m.entries().at(f.mn).nPoSeRevivedHeight, 0u)
        << "mainnet d07e1f49… sent a ProUpServTx at 2515068 while NOT banned"
           " (ban height -1, PoSe penalty 0) and dashd set no revive height."
           " Guessing one there moves the masternode 1568 blocks DOWN the"
           " queue — a divergence in the other direction, not a fix.";
}

// ── CASE B. A list dated EXACTLY at the pre-block height attesting the
// masternode NOT banned. dashcore revives nothing here and neither do we — but
// this zero is a MEASUREMENT and gets its own counter.
TEST(DashMnReviveBanState, MeasuredNotBannedIsADifferentZero) {
    ReviveFixture f;
    f.fold(2514573, /*valid=*/true);
    ASSERT_EQ(f.m.ban_state_measured_at(), 2514573u);
    ASSERT_TRUE(f.m.ban_state_measured_for(2514574));

    const auto r = f.m.apply_block(f.blk, 2514574);
    EXPECT_EQ(r.revive_declined_measured, 1u);
    EXPECT_EQ(r.revive_unmeasured, 0u)
        << "'the list at h-1 says not banned' and 'we never looked' are"
           " different facts and must not share a counter";
    EXPECT_TRUE(r.revive_unmeasured_protx.empty());
    EXPECT_EQ(r.revived, 0u);
    EXPECT_EQ(f.m.entries().at(f.mn).nPoSeRevivedHeight, 0u);
}

// ── CASE C. The same list dated at the same height, attesting the masternode
// BANNED. That is the mainnet 80b4892b… shape, and the revive must land with
// dashd's height.
TEST(DashMnReviveBanState, MeasuredBanAtThePreBlockHeightLandsTheRevive) {
    ReviveFixture f;
    f.fold(2514573, /*valid=*/false);
    ASSERT_FALSE(f.m.entries().at(f.mn).isValid);
    ASSERT_EQ(f.m.entries().at(f.mn).nPoSeBanHeight, 2514573u);

    const auto r = f.m.apply_block(f.blk, 2514574);
    EXPECT_EQ(r.revived, 1u);
    EXPECT_EQ(r.revive_unmeasured, 0u);
    EXPECT_EQ(r.revive_declined_measured, 0u);
    const MNState& back = f.m.entries().at(f.mn);
    EXPECT_TRUE(back.isValid);
    EXPECT_EQ(back.nPoSeBanHeight, 0u);
    EXPECT_EQ(back.nPoSeRevivedHeight, 2514574u)
        << "dashd scores this masternode by its revive height from here on;"
           " scoring it by its last payment (2513453) puts it at the head of"
           " our queue ~1100 blocks before dashd will pay it";
    EXPECT_EQ(MnStateMachine::payee_score(back), 2514574);
}

// ── CASE D. A list dated at the WRONG height is not a measurement of this
// block's gate. h-2 cannot speak for h-1: the ban we are looking for is
// exactly the kind that lasts four blocks.
TEST(DashMnReviveBanState, AListDatedOffByOneIsNotAMeasurement) {
    ReviveFixture f;
    f.fold(2514572, /*valid=*/true);          // one block too early
    EXPECT_FALSE(f.m.ban_state_measured_for(2514574));
    const auto r = f.m.apply_block(f.blk, 2514574);
    EXPECT_EQ(r.revive_unmeasured, 1u);
    EXPECT_EQ(r.revive_declined_measured, 0u);
}

// ── CASE E. The pre-scan and the apply must agree about what a block contains,
// because the whole repair is "ask BEFORE applying". They share the predicate;
// this pins that they cannot drift.
TEST(DashMnReviveBanState, PreScanAgreesWithTheApply) {
    {
        ReviveFixture f;
        const auto cands = f.m.unmeasured_revive_candidates(f.blk, 2514574);
        ASSERT_EQ(cands.size(), 1u);
        EXPECT_EQ(cands.front(), f.mn);
        EXPECT_EQ(f.m.apply_block(f.blk, 2514574).revive_unmeasured,
                  cands.size());
    }
    {   // measured at h-1: nothing to ask about
        ReviveFixture f;
        f.fold(2514573, true);
        EXPECT_TRUE(f.m.unmeasured_revive_candidates(f.blk, 2514574).empty());
        EXPECT_EQ(f.m.apply_block(f.blk, 2514574).revive_unmeasured, 0u);
    }
    {   // already believed banned: the gate is decided, no ambiguity
        ReviveFixture f;
        f.fold(2514573, false);
        EXPECT_TRUE(f.m.unmeasured_revive_candidates(f.blk, 2514574).empty());
        const auto r = f.m.apply_block(f.blk, 2514574);
        EXPECT_EQ(r.revive_unmeasured, 0u);
        EXPECT_EQ(r.revived, 1u);
    }
    {   // proTxHash we do not hold at all: that is revive_dropped_unknown, a
        // DIFFERENT defect (seed completeness) with its own counter. A probe
        // would tell us nothing, so it must not be requested.
        ReviveFixture f;
        f.m.load(std::vector<std::pair<uint256, MNState>>{}, 2514573);
        EXPECT_TRUE(f.m.unmeasured_revive_candidates(f.blk, 2514574).empty());
        const auto r = f.m.apply_block(f.blk, 2514574);
        EXPECT_EQ(r.revive_unmeasured, 0u);
        EXPECT_EQ(r.revive_dropped_unknown, 1u);
    }
}

// ── CASE F. A measurement describes the ENTRIES it was folded into. Replacing
// them (a re-seed / re-arm) retires it — otherwise a re-armed bridge would
// believe it had measured a set it has never looked at.
TEST(DashMnReviveBanState, LoadRetiresTheMeasurement) {
    ReviveFixture f;
    f.fold(2514573, true);
    ASSERT_TRUE(f.m.ban_state_measured_for(2514574));

    MNState s;
    s.isValid             = true;
    s.nRegisteredHeight   = 2400000;
    s.nLastPaidHeight     = 2513453;
    s.scriptPayout.m_data = script_bytes(0xE1);
    f.m.load(std::vector<std::pair<uint256, MNState>>{{f.mn, s}}, 2514573);
    EXPECT_EQ(f.m.ban_state_measured_at(), 0u);
    EXPECT_FALSE(f.m.ban_state_measured_for(2514574));
    EXPECT_EQ(f.m.apply_block(f.blk, 2514574).revive_unmeasured, 1u);
}

// --- same-block self-ProUpReg: pay the PRE-block script (dashd ordering) ----
// Mainnet h=2525714 (proTx f5a49888ec1d00db...): the projected payee's OWN
// ProUpRegTx rides the very block it is paid in, moving its payout script
// a7f7252d -> Xv4Ys1mi. dashd pays block H's masternode from the list AS OF H-1
// (payments.cpp GetBlockTxOuts reads oldList.GetMNPayee(pindexPrev)->pdmnState->
// scriptPayout BEFORE the block's special txs fold in BuildNewListFromBlock), so
// the coinbase correctly pays the PRE-block a7f7252d. Cross-checking the entry
// pass 1 just rewrote (Xv4Ys1mi) is a FALSE payee_desync that fail-closes the
// daemonless bridge. RED before the pass-0 snapshot fix, GREEN after.
TEST(DashMnState, ProjectedPayeePaidByPreBlockScriptWhenSelfProUpRegSameBlock) {
    MnStateMachine m;
    auto s_old  = script_bytes(0xA7, 25);   // pre-block payout, paid by coinbase
    auto s_new  = script_bytes(0x54, 25);   // in-block ProUpReg's new payout
    auto op_key = seq_array<48>(0x55);       // UNCHANGED operator key -> no ban

    MNState a;
    a.isValid                 = true;
    a.scriptPayout.m_data     = s_old;
    a.pubKeyOperator          = op_key;
    a.nRegisteredHeight       = 2'500'940;
    a.nLastPaidHeight         = 2'521'534;   // oldest paid -> projected winner
    a.collateralOutpoint.hash = raw256_byte(0, 0xA7);
    uint256 hA = raw256_byte(0, 0x01);

    // A more-recently-paid MN so the ranked queue has a runner-up and the
    // projection is unambiguous (A is the sole eligible winner this block).
    MNState b = a;
    b.scriptPayout.m_data     = script_bytes(0xB0, 25);
    b.nLastPaidHeight         = 2'525'000;
    b.collateralOutpoint.hash = raw256_byte(0, 0xB0);
    uint256 hB = raw256_byte(0, 0x02);

    m.load(std::vector<std::pair<uint256, MNState>>{{hA, a}, {hB, b}});

    // Block H=2525714: coinbase pays A's PRE-block script (s_old); A's OWN
    // ProUpRegTx (same operator key -> no ResetOperatorFields/ban) rewrites its
    // payout to s_new within the same block.
    CProUpRegTx upreg;
    upreg.nVersion            = ProTxVersion::BASIC_BLS;
    upreg.proTxHash           = hA;
    upreg.pubKeyOperator      = op_key;      // unchanged -> stays valid, stays payee
    upreg.keyIDVoting         = raw160(0x66);
    upreg.scriptPayout.m_data = s_new;
    upreg.inputsHash          = raw256(0x34);
    upreg.vchSig              = {0x01};

    BlockType blk;
    blk.m_txs.push_back(coinbase_tx(std::vector<std::vector<unsigned char>>{s_old}));
    blk.m_txs.push_back(special_tx(CProUpRegTx::SPECIALTX_TYPE, protx_payload(upreg)));

    auto r = m.apply_block(blk, 2'525'714);

    // The ProUpReg applied: post-block state carries the new payout...
    EXPECT_EQ(r.updated, 1u);
    EXPECT_EQ(m.entries().at(hA).scriptPayout.m_data, s_new)
        << "post-block state must carry the in-block ProUpReg's new payout";

    // ...but the payment is attributed to A on its PRE-block script -- no desync.
    EXPECT_FALSE(r.payee_desync)
        << "coinbase pays the script dashd pays from the H-1 list; cross-checking "
           "the mutated post-block script is a false payee_desync (h=2525714 class)";
    EXPECT_EQ(r.paid, 1u);
    ASSERT_TRUE(r.projected_payee.has_value());
    EXPECT_EQ(*r.projected_payee, hA);
    EXPECT_EQ(m.entries().at(hA).nLastPaidHeight, 2'525'714u)
        << "the projected payee must be marked paid at this height";
}
