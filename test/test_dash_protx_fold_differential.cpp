// SPDX-License-Identifier: AGPL-3.0-or-later
/// Differential KAT: the template fold (sml_special_fold.hpp, MnFoldContext)
/// must commit the merkleRootMNList the chain-side DML engine
/// (replay_fold_engine.hpp — root-checked against every mainnet block since
/// DIP3) computes for the same pre-block list and the same provider tx, and
/// must refuse exactly what it refuses.
///
/// M1 (VERIFY): a ProUpRevTx, and a ProUpRegTx that changes the operator key,
/// run dashd's ResetOperatorFields (evo/dmnstate.h:112-120): nVersion back to
/// LegacyBLS (then the payload's nVersion for ProUpRegTx), platformNodeID
/// cleared — and the SML leaf drops nType / platform fields below BasicBLS.
/// "Changes" is the CBLSLazyPublicKey compare: bytes under one scheme, points
/// across schemes.
/// M2 (VERIFY): operator-key uniqueness is dashd's unique-property map —
/// BYTES under the holder's scheme, never points: a basic encoding of a
/// legacy holder's point is a different property (accepted), and wire bytes
/// equal to a basic holder's key are the same property even when they decode
/// to another point under the legacy scheme (refused).
///
/// Real dashbls keys: the cross-scheme cases need valid G1 points.

#include <gtest/gtest.h>

#include <impl/dash/coin/block.hpp>
#include <impl/dash/coin/mn_state_db.hpp>
#include <impl/dash/coin/mn_state_machine.hpp>
#include <impl/dash/coin/replay_fold_engine.hpp>
#include <impl/dash/coin/sml_special_fold.hpp>
#include <impl/dash/coin/transaction.hpp>
#include <impl/dash/coin/utxo_adapter.hpp>
#include <impl/dash/coin/vendor/bls_verify.hpp>
#include <impl/dash/coin/vendor/cbtx.hpp>
#include <impl/dash/coin/vendor/providertx.hpp>
#include <impl/dash/coin/vendor/simplifiedmns.hpp>

#ifdef C2POOL_DASH_BLS
#include <dashbls/bls.hpp>
#include <dashbls/schemes.hpp>
#include <dashbls/elements.hpp>
#endif

#include <core/pack.hpp>
#include <core/uint256.hpp>

#include <array>
#include <cstdint>
#include <string>
#include <vector>

#ifdef C2POOL_DASH_BLS
namespace {

namespace v = dash::coin::vendor;
using dash::coin::BlockType;
using dash::coin::MnFoldContext;
using dash::coin::MNState;
using dash::coin::MnStateMachine;
using dash::coin::MutableTransaction;
using dash::coin::dash_txid;
using dash::coin::replay::DmlFoldEngine;
using dash::coin::replay::FoldConfig;
using dash::coin::replay::ReplayMNState;
using Key48 = std::array<uint8_t, 48>;

uint256 h256(uint8_t tag)
{
    uint256 h;
    for (int i = 0; i < 32; ++i) h.data()[i] = static_cast<uint8_t>(tag ^ (i * 29));
    return h;
}
uint160 h160(uint8_t tag)
{
    uint160 h;
    for (int i = 0; i < 20; ++i) h.data()[i] = static_cast<uint8_t>(tag + 7 * i);
    return h;
}
std::vector<unsigned char> p2pkh(uint8_t tag)
{
    std::vector<unsigned char> s = {0x76, 0xa9, 0x14};
    for (int i = 0; i < 20; ++i) s.push_back(static_cast<uint8_t>(tag + i));
    s.push_back(0x88); s.push_back(0xac);
    return s;
}

/// One operator key: the point P with both of its encodings.
struct OpKey {
    Key48 basic{};    // B(P)
    Key48 legacy{};   // L(P)
};
OpKey op_key(std::vector<uint8_t> seed)
{
    const bls::G1Element pk = bls::BasicSchemeMPL().KeyGen(seed).GetG1Element();
    return {pk.SerializeToArray(false), pk.SerializeToArray(true)};
}
OpKey op_key(uint8_t seed_byte) { return op_key(std::vector<uint8_t>(32, seed_byte)); }

/// A key whose two encodings differ (L(P) != B(P)) — the M2 direction-1 case.
OpKey op_key_with_distinct_encodings(uint8_t start)
{
    for (int s = start; s < start + 64; ++s) {
        const OpKey k = op_key(static_cast<uint8_t>(s));
        if (k.basic != k.legacy) return k;
    }
    ADD_FAILURE() << "no key with distinct encodings";
    return {};
}

/// A key P whose BASIC bytes are also the canonical LEGACY encoding of a
/// DIFFERENT point Q (the h=1874081 class) — the M2 direction-2 case.
OpKey op_key_whose_basic_bytes_are_another_legacy_point(uint8_t start)
{
    for (int s = start; s < start + 128; ++s) {
        const OpKey k = op_key(static_cast<uint8_t>(s));
        try {
            const bls::G1Element q = bls::G1Element::FromBytes(
                bls::Bytes(k.basic.data(), k.basic.size()), /*fLegacy=*/true);
            if (!q.IsValid()) continue;
            if (q.SerializeToArray(true) != k.basic) continue;          // canonical
            if (q.SerializeToArray(false) == k.basic) continue;         // a different point
            return k;
        } catch (...) {
        }
    }
    ADD_FAILURE() << "no such key";
    return {};
}

struct Mn {
    uint256 pro;
    ReplayMNState st;
};
Mn mn(uint8_t tag, const OpKey& k, uint16_t version, uint16_t type = v::MnType::REGULAR)
{
    Mn m;
    m.pro = h256(static_cast<uint8_t>(0xC0 + tag));
    auto& st = m.st;
    st.nVersion = version;
    st.nType = type;
    st.keyIDOwner = h160(static_cast<uint8_t>(0x20 + tag));
    st.keyIDVoting = h160(static_cast<uint8_t>(0x50 + tag));
    st.pubKeyOperator = k.basic;                  // the store is canonical basic
    st.collateralOutpoint.hash = h256(static_cast<uint8_t>(0x40 + tag));
    st.collateralOutpoint.index = 1;
    st.netInfo.ip[10] = 0xff; st.netInfo.ip[11] = 0xff;
    st.netInfo.ip[12] = 10; st.netInfo.ip[15] = tag;
    st.netInfo.port_be = 9999;
    st.scriptPayout.m_data = p2pkh(static_cast<uint8_t>(0x60 + tag));
    st.nRegisteredHeight = 50;
    st.confirmedHash = h256(0x77);
    if (type == v::MnType::EVO) {
        st.platformNodeID = h160(static_cast<uint8_t>(0x90 + tag));
        st.platformP2PPort = 26656;
        st.platformHTTPPort = 443;
    }
    return m;
}

template <typename Payload>
MutableTransaction special(uint16_t type, const Payload& p)
{
    MutableTransaction tx;
    tx.version = 3;
    tx.type = type;
    bitcoin_family::coin::TxIn in;
    in.prevout.hash = h256(0xA5);
    in.prevout.index = type;
    in.sequence = 0xffffffffu;
    tx.vin.push_back(in);
    bitcoin_family::coin::TxOut out;
    out.value = 1000;
    out.scriptPubKey.m_data = p2pkh(0x33);
    tx.vout.push_back(out);
    auto ps = ::pack(p);
    auto sp = ps.get_span();
    tx.extra_payload.assign(reinterpret_cast<const unsigned char*>(sp.data()),
                            reinterpret_cast<const unsigned char*>(sp.data()) + sp.size());
    return tx;
}

v::CProUpRevTx revoke(const uint256& pro)
{
    v::CProUpRevTx p;
    p.nVersion = v::ProTxVersion::BASIC_BLS;
    p.proTxHash = pro;
    p.nReason = v::CProUpRevTx::REASON_CHANGE_OF_KEYS;
    p.inputsHash = h256(0x11);
    return p;
}
v::CProUpRegTx update_registrar(const uint256& pro, uint16_t version, const Key48& wire_key)
{
    v::CProUpRegTx p;
    p.nVersion = version;
    p.proTxHash = pro;
    p.pubKeyOperator = wire_key;
    p.keyIDVoting = h160(0xEE);                   // a new voting key
    p.scriptPayout.m_data = p2pkh(0x44);
    p.inputsHash = h256(0x12);
    return p;
}
v::CProRegTx register_mn(uint16_t version, const Key48& wire_key)
{
    v::CProRegTx p;
    p.nVersion = version;
    p.nType = v::MnType::REGULAR;
    p.collateralOutpoint.hash = h256(0x99);
    p.collateralOutpoint.index = 1;
    p.netInfo.ip[10] = 0xff; p.netInfo.ip[11] = 0xff;
    p.netInfo.ip[12] = 10; p.netInfo.ip[15] = 200;
    p.netInfo.port_be = 9999;
    p.keyIDOwner = h160(0xD1);
    p.pubKeyOperator = wire_key;
    p.keyIDVoting = h160(0xD2);
    p.scriptPayout.m_data = p2pkh(0x55);
    p.inputsHash = h256(0x13);
    return p;
}

struct Outcome {
    bool        refused{false};
    std::string why;
    uint256     root;
};

FoldConfig cfg()
{
    FoldConfig c;
    c.enabled = true;
    c.gates.dip0003_height = 1;
    c.gates.dip0003_enforcement_height = 1;
    c.gates.v19_height = 1;
    c.gates.mn_rr_height = 1;
    return c;
}

BlockType block(const DmlFoldEngine& e, const uint256& committed, const MutableTransaction& tx)
{
    BlockType b;
    b.m_version = 0x20000000;
    b.m_previous_block = h256(0x09);
    b.m_timestamp = 1700000101;
    b.m_bits = 0x1e0fffff;
    b.m_nonce = 101;
    v::CCbTx cb;
    cb.nVersion = v::CCbTx::VERSION_MERKLE_ROOT_QUORUMS;
    cb.nHeight = 101;
    cb.merkleRootMNList = committed;
    MutableTransaction coinbase;
    coinbase.version = 3;
    coinbase.type = 5;
    bitcoin_family::coin::TxIn in;
    in.prevout.hash.SetNull(); in.prevout.index = 0xffffffffu; in.sequence = 0xffffffffu;
    coinbase.vin.push_back(in);
    if (auto payee = e.project_payee(101)) {
        if (const ReplayMNState* st = e.find(*payee)) {
            bitcoin_family::coin::TxOut o;
            o.value = 1;
            o.scriptPubKey.m_data = st->first_payout_script();
            coinbase.vout.push_back(o);
        }
    }
    auto ps = ::pack(cb);
    auto sp = ps.get_span();
    coinbase.extra_payload.assign(reinterpret_cast<const unsigned char*>(sp.data()),
                                  reinterpret_cast<const unsigned char*>(sp.data()) + sp.size());
    b.m_txs = {coinbase, tx};
    return b;
}

/// The chain side: the DML engine folds the block. A refusal comes back
/// before the root; otherwise the root it computed is re-committed and the
/// block must then fold cleanly (proof the engine accepts it).
Outcome dml(const std::vector<Mn>& mns, const MutableTransaction& tx)
{
    auto seeded = [&] {
        DmlFoldEngine e(cfg());
        std::vector<std::pair<uint256, ReplayMNState>> rows;
        for (const auto& m : mns) rows.emplace_back(m.pro, m.st);
        e.seed(rows, mns.size(), 100, h256(0x09));
        return e;
    };
    DmlFoldEngine probe = seeded();
    const auto r = probe.fold_block(block(probe, uint256{}, tx), 101);
    Outcome o;
    if (r.computed_root.IsNull()) {
        o.refused = true;
        o.why = r.error;
        return o;
    }
    o.root = r.computed_root;
    DmlFoldEngine e = seeded();
    const auto ok = e.fold_block(block(e, o.root, tx), 101);
    EXPECT_TRUE(ok.ok) << ok.error;
    return o;
}

/// The template side: the serving-path fold over the same pre-block list.
Outcome tmpl(const std::vector<Mn>& mns, const MutableTransaction& tx)
{
    MnStateMachine sm;
    std::vector<std::pair<uint256, MNState>> rows;
    std::vector<v::CSimplifiedMNListEntry> leaves;
    for (const auto& m : mns) {
        MNState s;
        s.nVersion = m.st.nVersion;
        s.nType = static_cast<uint8_t>(m.st.nType);
        s.collateralOutpoint = m.st.collateralOutpoint;
        s.keyIDOwner = m.st.keyIDOwner;
        s.pubKeyOperator = m.st.pubKeyOperator;
        s.keyIDVoting = m.st.keyIDVoting;
        s.netInfo = m.st.netInfo;
        s.scriptPayout = m.st.scriptPayout;
        s.platformNodeID = m.st.platformNodeID;
        s.platformP2PPort = m.st.platformP2PPort;
        s.platformHTTPPort = m.st.platformHTTPPort;
        s.isValid = !m.st.IsBanned();
        s.nRegisteredHeight = static_cast<uint32_t>(m.st.nRegisteredHeight);
        rows.emplace_back(m.pro, s);
        leaves.push_back(m.st.to_sml_entry(m.pro));
    }
    sm.load(rows, 100);
    const v::CSimplifiedMNList base(std::move(leaves));
    const auto ctx = MnFoldContext::from(
        sm, {}, [](const MnFoldContext::OpKey&, bool, const uint256&,
                   const MnFoldContext::Sig&, bool) { return true; });
    const auto f = dash::coin::fold_mn_special_txs(
        base, std::vector<MutableTransaction>{tx},
        [](const MutableTransaction& t) { return dash_txid(t); }, ctx);
    Outcome o;
    o.refused = f.refused > 0;
    if (!f.refused_reasons.empty()) o.why = f.refused_reasons.front();
    o.root = f.sml.CalcMerkleRoot();
    return o;
}

void expect_same_root(const std::vector<Mn>& mns, const MutableTransaction& tx)
{
    const Outcome chain = dml(mns, tx);
    const Outcome serve = tmpl(mns, tx);
    ASSERT_FALSE(chain.refused) << chain.why;
    ASSERT_FALSE(serve.refused) << serve.why;
    EXPECT_EQ(serve.root, chain.root)
        << "the template commits a merkleRootMNList the chain does not compute";
}

} // namespace

// ── M1: ResetOperatorFields in the template leaf ──────────────────────────

TEST(DashProTxFoldDifferential, ProUpRevTxOnABasicMn)
{
    const auto a = mn(1, op_key(0x01), v::ProTxVersion::BASIC_BLS);
    const auto b = mn(2, op_key(0x02), v::ProTxVersion::BASIC_BLS);
    expect_same_root({a, b}, special(4, revoke(a.pro)));
}

TEST(DashProTxFoldDifferential, ProUpRevTxOnAnEvoMn)
{
    const auto e = mn(3, op_key(0x03), v::ProTxVersion::BASIC_BLS, v::MnType::EVO);
    const auto b = mn(2, op_key(0x02), v::ProTxVersion::BASIC_BLS);
    expect_same_root({e, b}, special(4, revoke(e.pro)));
}

TEST(DashProTxFoldDifferential, LegacyMnV2ProUpRegTxWithTheSamePointIsNotAKeyChange)
{
    const OpKey kl = op_key_with_distinct_encodings(0x10);
    const auto l = mn(4, kl, v::ProTxVersion::LEGACY_BLS);
    const auto b = mn(2, op_key(0x02), v::ProTxVersion::BASIC_BLS);
    // `protx update_registrar` on a pre-V19 MN: same operator point, now
    // basic-encoded (the #154 / h=2525069 shape).
    expect_same_root({l, b}, special(3, update_registrar(l.pro, v::ProTxVersion::BASIC_BLS, kl.basic)));
}

TEST(DashProTxFoldDifferential, LegacyMnV2ProUpRegTxWithANewKeyMovesTheLeafToBasic)
{
    const auto l = mn(4, op_key_with_distinct_encodings(0x10), v::ProTxVersion::LEGACY_BLS);
    const auto b = mn(2, op_key(0x02), v::ProTxVersion::BASIC_BLS);
    const OpKey fresh = op_key(0x31);
    expect_same_root({l, b}, special(3, update_registrar(l.pro, v::ProTxVersion::BASIC_BLS, fresh.basic)));
}

TEST(DashProTxFoldDifferential, BasicMnV1ProUpRegTxWithANewKeyMovesTheLeafToLegacy)
{
    const auto a = mn(1, op_key(0x01), v::ProTxVersion::BASIC_BLS);
    const auto b = mn(2, op_key(0x02), v::ProTxVersion::BASIC_BLS);
    const OpKey fresh = op_key(0x32);
    expect_same_root({a, b}, special(3, update_registrar(a.pro, v::ProTxVersion::LEGACY_BLS, fresh.legacy)));
}

TEST(DashProTxFoldDifferential, EvoMnKeyChangeClearsThePlatformNodeId)
{
    const auto e = mn(3, op_key(0x03), v::ProTxVersion::BASIC_BLS, v::MnType::EVO);
    const auto b = mn(2, op_key(0x02), v::ProTxVersion::BASIC_BLS);
    const OpKey fresh = op_key(0x33);
    expect_same_root({e, b}, special(3, update_registrar(e.pro, v::ProTxVersion::BASIC_BLS, fresh.basic)));
}

// ── M2: operator-key uniqueness is bytes under the holder's scheme ────────

// Direction 1: a legacy holder's point, re-sent basic-encoded by a new
// registration, is a DIFFERENT unique property in dashd — accepted, mined.
// Refusing it would latch the DML lane on a valid block.
TEST(DashProTxFoldDifferential, ProRegTxWithTheBasicBytesOfALegacyHoldersPointIsAccepted)
{
    const OpKey kl = op_key_with_distinct_encodings(0x10);
    const auto l = mn(4, kl, v::ProTxVersion::LEGACY_BLS);
    const auto b = mn(2, op_key(0x02), v::ProTxVersion::BASIC_BLS);
    expect_same_root({l, b}, special(1, register_mn(v::ProTxVersion::BASIC_BLS, kl.basic)));
}

// Direction 2: wire bytes equal to a basic holder's key are the SAME
// property even though, read under the legacy scheme, they are another point
// — dashd refuses (bad-protx-dup-key), so both folds must.
TEST(DashProTxFoldDifferential, ProRegTxWhoseBytesEqualABasicHoldersKeyIsRefused)
{
    const OpKey ka = op_key_whose_basic_bytes_are_another_legacy_point(0x40);
    const auto a = mn(1, ka, v::ProTxVersion::BASIC_BLS);
    const auto b = mn(2, op_key(0x02), v::ProTxVersion::BASIC_BLS);
    const auto tx = special(1, register_mn(v::ProTxVersion::LEGACY_BLS, ka.basic));
    const Outcome chain = dml({a, b}, tx);
    const Outcome serve = tmpl({a, b}, tx);
    EXPECT_TRUE(chain.refused) << "the chain fold must refuse bad-protx-dup-key";
    EXPECT_NE(chain.why.find("bad-protx-dup-key"), std::string::npos) << chain.why;
    EXPECT_TRUE(serve.refused) << "the template fold must drop it";
}

// The legacy-wire helper both engines rely on.
TEST(DashProTxFoldDifferential, LegacyWireToBasicFindsOnlyCanonicalLegacyEncodings)
{
    const OpKey k = op_key_with_distinct_encodings(0x10);
    const auto from_legacy = v::opkey_legacy_wire_to_basic(k.legacy);
    ASSERT_TRUE(from_legacy.has_value());
    EXPECT_EQ(*from_legacy, k.basic) << "L(P) must map to B(P)";
    const OpKey odd = op_key_whose_basic_bytes_are_another_legacy_point(0x40);
    const auto other = v::opkey_legacy_wire_to_basic(odd.basic);
    ASSERT_TRUE(other.has_value());
    EXPECT_NE(*other, odd.basic) << "B(P) read as legacy is another point";
}
#endif // C2POOL_DASH_BLS
