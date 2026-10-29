// SPDX-License-Identifier: AGPL-3.0-or-later
/// Dash Core v23.1.9 port, item B (+ the v23.1.8 delta's B.9) — the template
/// side of the provider-tx rules.
///
/// dashd v23.1.9 closed three cases where its MEMPOOL admitted a provider tx
/// that its own CreateNewBlock could not mine (#7488 ProUpServTx nType, #7489
/// collateral reuse vs a pending update, #7846 owner key / platformNodeID
/// namespace). c2pool serves types 1-4 from its own fold
/// (sml_special_fold.hpp), so every such case is a found block dashd rejects.
/// These KATs pin the context fold (MnFoldContext) the template builder and
/// the emit gate share: each case is REFUSED (the builder drops the tx and
/// its fee) or, where dashd's own list rebuild removes a masternode, the
/// folded root is the one dashd computes.
///
/// The operator-signature checks here run against a stub verifier (the fold's
/// plumbing: which key, which preimage, what happens on false); the real BLS
/// crypto is pinned in test_dash_protx_sig_bls.cpp (BLS-backend target).

#include <gtest/gtest.h>

#include <impl/dash/coin/embedded_gbt.hpp>
#include <impl/dash/coin/mempool.hpp>
#include <impl/dash/coin/mn_state_machine.hpp>
#include <impl/dash/coin/quorum_manager.hpp>
#include <impl/dash/coin/sml_special_fold.hpp>
#include <impl/dash/coin/transaction.hpp>
#include <impl/dash/coin/utxo_adapter.hpp>
#include <impl/dash/coin/vendor/cbtx.hpp>
#include <impl/dash/coin/vendor/providertx.hpp>
#include <impl/dash/coin/vendor/simplifiedmns.hpp>

#include <core/coin/utxo_view_cache.hpp>
#include <core/pack.hpp>
#include <core/uint256.hpp>

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace {

namespace v = dash::coin::vendor;
using dash::coin::MnFoldContext;
using dash::coin::MNState;
using dash::coin::MnStateMachine;
using dash::coin::Mempool;
using dash::coin::MutableTransaction;
using dash::coin::SmlSpecialFold;
using dash::coin::dash_txid;
using v::CSimplifiedMNList;
using v::CSimplifiedMNListEntry;
using bitcoin_family::coin::TxPrevOut;

uint256 h256(uint8_t tag)
{
    uint256 h;
    for (int i = 0; i < 32; ++i) h.data()[i] = static_cast<uint8_t>(tag ^ (i * 13));
    return h;
}
uint160 h160(uint8_t tag)
{
    uint160 h;
    for (int i = 0; i < 20; ++i) h.data()[i] = static_cast<uint8_t>(tag + 3 * i);
    return h;
}
template <size_t N>
std::array<uint8_t, N> seq(uint8_t base)
{
    std::array<uint8_t, N> a{};
    for (size_t i = 0; i < N; ++i) a[i] = static_cast<uint8_t>(base + i);
    return a;
}
TxPrevOut outpoint(uint8_t tag, uint32_t n = 1)
{
    TxPrevOut o;
    o.hash = h256(tag);
    o.index = n;
    return o;
}

/// A registered masternode: the MnStateMachine row and its SML leaf.
struct Mn {
    uint256 pro;
    MNState st;
    CSimplifiedMNListEntry leaf;
};

Mn make_mn(uint8_t tag, uint8_t type = v::MnType::REGULAR)
{
    Mn m;
    m.pro = h256(static_cast<uint8_t>(0xB0 + tag));
    m.st.nVersion = v::ProTxVersion::BASIC_BLS;
    m.st.nType = type;
    m.st.collateralOutpoint = outpoint(static_cast<uint8_t>(0x40 + tag));
    m.st.keyIDOwner = h160(static_cast<uint8_t>(0x20 + tag));
    m.st.pubKeyOperator = seq<48>(static_cast<uint8_t>(0x30 + tag));
    m.st.keyIDVoting = h160(static_cast<uint8_t>(0x50 + tag));
    m.st.netInfo.ip = seq<16>(static_cast<uint8_t>(0x10 + tag));
    m.st.netInfo.port_be = 9999;
    m.st.scriptPayout.m_data = {0x76, 0xa9, 0x14, tag, 0x88, 0xac};
    m.st.isValid = true;
    m.st.nRegisteredHeight = 2'000'000;
    if (type == v::MnType::EVO) {
        m.st.platformNodeID = h160(static_cast<uint8_t>(0x60 + tag));
        m.st.platformP2PPort = 26656;
        m.st.platformHTTPPort = 443;
    }
    m.leaf.nVersion = CSimplifiedMNListEntry::VER_BASIC_BLS;
    m.leaf.proRegTxHash = m.pro;
    m.leaf.confirmedHash = h256(0x77);
    m.leaf.netAddress = m.st.netInfo.ip;
    m.leaf.netPort = m.st.netInfo.port_be;
    m.leaf.pubKeyOperator = m.st.pubKeyOperator;
    m.leaf.keyIDVoting = m.st.keyIDVoting;
    m.leaf.isValid = true;
    m.leaf.nType = type;
    m.leaf.platformHTTPPort = m.st.platformHTTPPort;
    m.leaf.platformNodeID = m.st.platformNodeID;
    return m;
}

struct World {
    std::vector<Mn> mns;
    MnStateMachine sm;
    CSimplifiedMNList base;
    explicit World(std::vector<Mn> in) : mns(std::move(in))
    {
        std::vector<std::pair<uint256, MNState>> rows;
        std::vector<CSimplifiedMNListEntry> leaves;
        for (const auto& m : mns) { rows.emplace_back(m.pro, m.st); leaves.push_back(m.leaf); }
        sm.load(rows, 2'500'000);
        base = CSimplifiedMNList(std::move(leaves));
        base.sort();
    }
};

/// Every signature verifies — the plumbing KATs below are not about crypto.
MnFoldContext::OperatorSigFn accept_all()
{
    return [](const MnFoldContext::OpKey&, bool, const uint256&,
              const MnFoldContext::Sig&, bool) { return true; };
}

template <typename Payload>
MutableTransaction special(uint16_t type, const Payload& p, uint8_t funding_tag)
{
    MutableTransaction tx;
    tx.version = 3;
    tx.type    = type;
    bitcoin_family::coin::TxIn in;
    in.prevout = outpoint(funding_tag, 0);
    in.sequence = 0xFFFFFFFFu;
    tx.vin.push_back(in);
    bitcoin_family::coin::TxOut out;
    out.value = 1000;
    out.scriptPubKey.m_data = {0x51};
    tx.vout.push_back(out);
    auto ps = ::pack(p);
    auto sp = ps.get_span();
    tx.extra_payload.assign(reinterpret_cast<const unsigned char*>(sp.data()),
                            reinterpret_cast<const unsigned char*>(sp.data()) + sp.size());
    return tx;
}

v::CProRegTx proreg(uint8_t tag)
{
    v::CProRegTx p;
    p.nVersion = v::ProTxVersion::BASIC_BLS;
    p.nType    = v::MnType::REGULAR;
    p.collateralOutpoint = outpoint(static_cast<uint8_t>(0x80 + tag));
    p.netInfo.ip = seq<16>(static_cast<uint8_t>(0xC0 + tag));
    p.netInfo.port_be = 9999;
    p.keyIDOwner = h160(static_cast<uint8_t>(0xA0 + tag));
    p.pubKeyOperator = seq<48>(static_cast<uint8_t>(0x90 + tag));
    p.keyIDVoting = h160(static_cast<uint8_t>(0xD0 + tag));
    p.scriptPayout.m_data = {0x76, 0xa9, 0x14, tag, 0x88, 0xac};
    p.inputsHash = h256(static_cast<uint8_t>(0xE0 + tag));
    return p;
}
v::CProUpServTx proupserv(const Mn& m, uint8_t tag)
{
    v::CProUpServTx p;
    p.nVersion = v::ProTxVersion::BASIC_BLS;
    p.nType    = m.st.nType;
    p.proTxHash = m.pro;
    p.netInfo.ip = seq<16>(static_cast<uint8_t>(0xF0 - tag));
    p.netInfo.port_be = 9999;
    p.inputsHash = h256(static_cast<uint8_t>(0x0F + tag));
    if (m.st.nType == v::MnType::EVO) {
        p.platformNodeID = m.st.platformNodeID;
        p.platformP2PPort = 26656;
        p.platformHTTPPort = 443;
    }
    p.sig = seq<96>(tag);
    return p;
}

SmlSpecialFold fold(const World& w, const std::vector<MutableTransaction>& body,
                    const MnFoldContext& ctx)
{
    return dash::coin::fold_mn_special_txs(
        w.base, body, [](const MutableTransaction& t) { return dash_txid(t); }, ctx);
}

bool refused(const SmlSpecialFold& f, const MutableTransaction& tx)
{
    for (const auto& id : f.refused_ids) if (id == dash_txid(tx)) return true;
    return false;
}

/// The leaf a ProRegTx folds to (independent hand-build).
CSimplifiedMNListEntry leaf_of(const v::CProRegTx& p, const uint256& pro)
{
    CSimplifiedMNListEntry e;
    e.nVersion = p.nVersion;
    e.proRegTxHash = pro;
    e.netAddress = p.netInfo.ip;
    e.netPort = p.netInfo.port_be;
    e.pubKeyOperator = p.pubKeyOperator;
    e.keyIDVoting = p.keyIDVoting;
    e.isValid = true;
    e.nType = p.nType;
    e.platformHTTPPort = p.platformHTTPPort;
    e.platformNodeID = p.platformNodeID;
    return e;
}

uint256 root_of(std::vector<CSimplifiedMNListEntry> leaves)
{
    CSimplifiedMNList l(std::move(leaves));
    l.sort();
    return l.CalcMerkleRoot();
}

} // namespace

// B1 (#7488): a ProUpServTx whose nType is not a valid MnType is refused.
TEST(DashSupersetSpecialTx, ProUpServTxWithInvalidNTypeIsRefused)
{
    World w({make_mn(1)});
    const auto ctx = MnFoldContext::from(w.sm, {}, accept_all());
    auto pl = proupserv(w.mns[0], 1);
    pl.nType = 2;
    auto tx = special(2, pl, 0x01);
    const auto f = fold(w, {tx}, ctx);
    EXPECT_EQ(f.applied, 0u);
    EXPECT_TRUE(refused(f, tx)) << "dashd: bad-protx-type";
    EXPECT_EQ(f.sml.CalcMerkleRoot(), w.base.CalcMerkleRoot());
}

// B2 (#7488): nType must equal the registered MN's nType, both ways.
TEST(DashSupersetSpecialTx, ProUpServTxNTypeMismatchIsRefused)
{
    World w({make_mn(1), make_mn(2, v::MnType::EVO)});
    const auto ctx = MnFoldContext::from(w.sm, {}, accept_all());
    auto to_regular_as_evo = proupserv(w.mns[0], 1);
    to_regular_as_evo.nType = v::MnType::EVO;
    to_regular_as_evo.platformNodeID = h160(0x99);
    to_regular_as_evo.platformP2PPort = 26656;
    to_regular_as_evo.platformHTTPPort = 443;
    auto to_evo_as_regular = proupserv(w.mns[1], 2);
    to_evo_as_regular.nType = v::MnType::REGULAR;
    auto a = special(2, to_regular_as_evo, 0x01);
    auto b = special(2, to_evo_as_regular, 0x02);
    const auto f = fold(w, {a, b}, ctx);
    EXPECT_TRUE(refused(f, a)) << "dashd: bad-protx-type-mismatch";
    EXPECT_TRUE(refused(f, b)) << "dashd: bad-protx-type-mismatch";
    EXPECT_EQ(f.sml.CalcMerkleRoot(), w.base.CalcMerkleRoot());
}

// B3 (#7489): a ProRegTx reusing MN X's (external) collateral REMOVES X, and a
// later update to X in the same body is refused (bad-protx-hash). The folded
// root is the hand-built dashd list.
TEST(DashSupersetSpecialTx, ProRegTxReusingLiveCollateralReplacesMnAndRefusesPendingUpdate)
{
    World w({make_mn(1), make_mn(2)});
    const Mn& x = w.mns[0];
    const auto ctx = MnFoldContext::from(w.sm, {}, accept_all());
    auto reg = proreg(1);
    reg.collateralOutpoint = x.st.collateralOutpoint;
    auto regtx = special(1, reg, 0x01);
    auto upd = special(2, proupserv(x, 1), 0x02);
    const auto f = fold(w, {regtx, upd}, ctx);
    EXPECT_FALSE(refused(f, regtx));
    EXPECT_TRUE(refused(f, upd)) << "X was replaced: its update can never be mined";
    EXPECT_EQ(f.replaced, 1u);
    bool x_present = false;
    for (const auto& e : f.sml.mnList) if (e.proRegTxHash == x.pro) x_present = true;
    EXPECT_FALSE(x_present);
    EXPECT_EQ(f.sml.CalcMerkleRoot(),
              root_of({w.mns[1].leaf, leaf_of(reg, dash_txid(regtx))}));
}

// B4 (#7846): keyIDOwner and platformNodeID are one namespace.
TEST(DashSupersetSpecialTx, OwnerKeyCollidingWithPlatformNodeIdIsRefused)
{
    World w({make_mn(1), make_mn(2, v::MnType::EVO), make_mn(3, v::MnType::EVO)});
    const auto ctx = MnFoldContext::from(w.sm, {}, accept_all());
    auto reg = proreg(1);
    reg.keyIDOwner = w.mns[1].st.platformNodeID;     // an Evo MN's platform id
    auto regtx = special(1, reg, 0x01);
    auto serv = proupserv(w.mns[2], 2);
    serv.platformNodeID = w.mns[0].st.keyIDOwner;    // a regular MN's owner key
    auto servtx = special(2, serv, 0x02);
    const auto f = fold(w, {regtx, servtx}, ctx);
    EXPECT_TRUE(refused(f, regtx)) << "owner key == an existing platformNodeID";
    EXPECT_TRUE(refused(f, servtx)) << "platformNodeID == an existing owner key";
    EXPECT_EQ(f.sml.CalcMerkleRoot(), w.base.CalcMerkleRoot());
}

// B5: the owner-key and service siblings (bad-protx-dup-key /
// bad-protx-dup-netinfo-entry).
TEST(DashSupersetSpecialTx, DupOwnerKeyAndDupServiceAreRefused)
{
    World w({make_mn(1), make_mn(2)});
    const auto ctx = MnFoldContext::from(w.sm, {}, accept_all());
    auto dup_owner = proreg(1);
    dup_owner.keyIDOwner = w.mns[0].st.keyIDOwner;
    auto dup_svc = proreg(2);
    dup_svc.netInfo = w.mns[0].st.netInfo;
    auto serv = proupserv(w.mns[1], 3);
    serv.netInfo = w.mns[0].st.netInfo;              // another MN's service
    auto a = special(1, dup_owner, 0x01);
    auto b = special(1, dup_svc, 0x02);
    auto c = special(2, serv, 0x03);
    const auto f = fold(w, {a, b, c}, ctx);
    EXPECT_TRUE(refused(f, a)) << "bad-protx-dup-key";
    EXPECT_TRUE(refused(f, b)) << "bad-protx-dup-netinfo-entry";
    EXPECT_TRUE(refused(f, c)) << "bad-protx-dup-netinfo-entry";
    EXPECT_EQ(f.sml.CalcMerkleRoot(), w.base.CalcMerkleRoot());
}

// B6: a body tx spending a masternode's collateral removes that MN — dashd's
// collateral loop runs AFTER the special-tx loop, so both orders of
// [spend(C_X), ProUpServTx(X)] are valid blocks and both end without X. Same
// for an MN registered earlier in the body whose collateral a later tx spends.
TEST(DashSupersetSpecialTx, CollateralSpentInBodyRemovesTheMnLikeDashd)
{
    World w({make_mn(1), make_mn(2)});
    const Mn& x = w.mns[0];
    const auto ctx = MnFoldContext::from(w.sm, {}, accept_all());
    MutableTransaction spend;
    spend.version = 2;
    bitcoin_family::coin::TxIn in;
    in.prevout = x.st.collateralOutpoint; in.sequence = 0xFFFFFFFFu;
    spend.vin.push_back(in);
    bitcoin_family::coin::TxOut o; o.value = 5; o.scriptPubKey.m_data = {0x51};
    spend.vout.push_back(o);
    auto upd = special(2, proupserv(x, 1), 0x02);
    const uint256 without_x = root_of({w.mns[1].leaf});
    for (bool spend_first : {true, false}) {
        const auto f = spend_first ? fold(w, {spend, upd}, ctx) : fold(w, {upd, spend}, ctx);
        EXPECT_TRUE(f.clean()) << "spend_first=" << spend_first;
        EXPECT_EQ(f.collateral_removed, 1u) << "spend_first=" << spend_first;
        EXPECT_EQ(f.sml.CalcMerkleRoot(), without_x) << "spend_first=" << spend_first;
    }

    // Registered in this body (internal collateral = own output 0), spent by
    // a later body tx: dashd adds it, then removes it.
    auto reg = proreg(4);
    reg.collateralOutpoint.hash.SetNull();
    reg.collateralOutpoint.index = 0;
    auto regtx = special(1, reg, 0x05);
    MutableTransaction child;
    child.version = 2;
    bitcoin_family::coin::TxIn cin;
    cin.prevout.hash = dash_txid(regtx); cin.prevout.index = 0; cin.sequence = 0xFFFFFFFFu;
    child.vin.push_back(cin);
    child.vout.push_back(o);
    const auto g = fold(w, {regtx, child}, ctx);
    EXPECT_EQ(g.applied, 1u);
    EXPECT_EQ(g.collateral_removed, 1u);
    EXPECT_EQ(g.sml.CalcMerkleRoot(), w.base.CalcMerkleRoot());
}

// B7: the external collateral must be an unspent coin of collat_amount(nType)
// — refused on PROOF only (Absent / wrong amount); Unknown keeps today's
// behaviour (see Mempool::prove_chain_coin).
TEST(DashSupersetSpecialTx, ExternalCollateralNotInUtxoViewIsRefused)
{
    World w({make_mn(1)});
    auto reg = proreg(1);
    auto regtx = special(1, reg, 0x01);
    auto with = [&](MnFoldContext::CollateralProof proof, int64_t value) {
        const auto ctx = MnFoldContext::from(
            w.sm,
            [proof, value](const TxPrevOut&, int64_t& out) { out = value; return proof; },
            accept_all());
        return fold(w, {regtx}, ctx);
    };
    using P = MnFoldContext::CollateralProof;
    EXPECT_TRUE(refused(with(P::Absent, 0), regtx)) << "bad-protx-collateral";
    EXPECT_TRUE(refused(with(P::Unspent, 999LL * 100'000'000LL), regtx))
        << "bad-protx-collateral (amount)";
    EXPECT_EQ(with(P::Unspent, 1000LL * 100'000'000LL).applied, 1u);
    EXPECT_EQ(with(P::Unknown, 0).applied, 1u) << "no proof, no refusal";
}

// B8: an ExtAddr (nVersion 3, DEPLOYMENT_V24) payload is refused by name even
// when the fixed-layout parse happens to succeed.
TEST(DashSupersetSpecialTx, ExtAddrPayloadIsRefusedByName)
{
    World w({make_mn(1)});
    const auto ctx = MnFoldContext::from(w.sm, {}, accept_all());
    auto reg = proreg(1);
    reg.nVersion = v::ProTxVersion::EXT_ADDR;
    auto regtx = special(1, reg, 0x01);
    auto serv = proupserv(w.mns[0], 2);
    serv.nVersion = v::ProTxVersion::EXT_ADDR;
    auto servtx = special(2, serv, 0x02);
    const auto f = fold(w, {regtx, servtx}, ctx);
    ASSERT_EQ(f.refused, 2u);
    ASSERT_EQ(f.refused_reasons.size(), 2u);
    for (const auto& why : f.refused_reasons)
        EXPECT_NE(why.find("ExtAddr"), std::string::npos) << why;
    EXPECT_EQ(f.sml.CalcMerkleRoot(), w.base.CalcMerkleRoot());
}

// B.9 plumbing: ProUpServTx / ProUpRevTx are verified against the PRE-block
// operator key, over the payload minus its trailing signature, with the
// payload's scheme; a false verdict refuses, and no verifier at all refuses.
TEST(DashSupersetSpecialTx, OperatorSignatureIsCheckedAgainstThePreBlockKey)
{
    World w({make_mn(1)});
    const Mn& x = w.mns[0];
    auto servtx = special(2, proupserv(x, 1), 0x01);
    v::CProUpRevTx rev;
    rev.nVersion = v::ProTxVersion::BASIC_BLS;
    rev.proTxHash = x.pro;
    rev.sig = seq<96>(0x44);
    auto revtx = special(4, rev, 0x02);

    int calls = 0;
    bool key_ok = true, hash_ok = true;
    const auto expect_hash_serv = v::protx_operator_sign_hash(servtx.extra_payload);
    const auto expect_hash_rev  = v::protx_operator_sign_hash(revtx.extra_payload);
    ASSERT_TRUE(expect_hash_serv && expect_hash_rev);
    auto spy = [&](bool verdict) {
        return [&, verdict](const MnFoldContext::OpKey& key, bool key_legacy,
                            const uint256& h, const MnFoldContext::Sig&, bool sig_legacy) {
            ++calls;
            key_ok  = key_ok && key == x.leaf.pubKeyOperator && !key_legacy && !sig_legacy;
            hash_ok = hash_ok && (h == *expect_hash_serv || h == *expect_hash_rev);
            return verdict;
        };
    };
    const auto bad = fold(w, {servtx, revtx}, MnFoldContext::from(w.sm, {}, spy(false)));
    EXPECT_EQ(calls, 2);
    EXPECT_TRUE(key_ok);
    EXPECT_TRUE(hash_ok);
    EXPECT_TRUE(refused(bad, servtx)) << "bad-protx-sig";
    EXPECT_TRUE(refused(bad, revtx)) << "bad-protx-sig";
    EXPECT_EQ(bad.sml.CalcMerkleRoot(), w.base.CalcMerkleRoot());

    const auto unwired = fold(w, {servtx, revtx}, MnFoldContext::from(w.sm));
    EXPECT_EQ(unwired.refused, 2u) << "no verifier wired => fail closed";

    const auto good = fold(w, {servtx}, MnFoldContext::from(w.sm, {}, spy(true)));
    EXPECT_EQ(good.applied, 1u);

    // The preimage really is the payload minus the 96-byte sig.
    ASSERT_GE(servtx.extra_payload.size(), 96u);
    std::vector<uint8_t> head(servtx.extra_payload.begin(), servtx.extra_payload.end() - 96);
    uint256 want;
    CHash256().Write(std::span<const unsigned char>(head.data(), head.size()))
              .Finalize(std::span<unsigned char>(want.data(), 32));
    EXPECT_EQ(*expect_hash_serv, want);
}

// The production verifier is memoized: one BLS pairing per distinct
// (key, preimage, sig, schemes), however often the body is re-folded.
TEST(DashSupersetSpecialTx, OperatorSignatureVerdictIsMemoized)
{
    int calls = 0;
    auto memo = dash::coin::memoize_operator_sig_fn(
        [&calls](const MnFoldContext::OpKey&, bool, const uint256& h,
                 const MnFoldContext::Sig&, bool) { ++calls; return h == h256(1); });
    const auto key = seq<48>(1);
    const auto sig = seq<96>(2);
    EXPECT_TRUE(memo(key, false, h256(1), sig, false));
    EXPECT_TRUE(memo(key, false, h256(1), sig, false));
    EXPECT_EQ(calls, 1) << "the same verify is answered from the memo";
    EXPECT_FALSE(memo(key, false, h256(2), sig, false));
    EXPECT_FALSE(memo(key, false, h256(2), sig, false));
    EXPECT_EQ(calls, 2);
    EXPECT_TRUE(memo(key, false, h256(1), sig, false));
    EXPECT_EQ(calls, 2);
    EXPECT_TRUE(memo(key, true, h256(1), sig, false));
    EXPECT_EQ(calls, 3) << "a different scheme flag is a different verify";
}

// An update naming an MN registered earlier in the same body is refused:
// dashd's CheckProUp*Tx reads the PRE-block list (bad-protx-hash).
TEST(DashSupersetSpecialTx, UpdateOfAnMnRegisteredInTheSameBodyIsRefused)
{
    World w({make_mn(1)});
    const auto ctx = MnFoldContext::from(w.sm, {}, accept_all());
    auto reg = proreg(1);
    auto regtx = special(1, reg, 0x01);
    Mn fresh;
    fresh.pro = dash_txid(regtx);
    fresh.st.nType = v::MnType::REGULAR;
    auto upd = special(2, proupserv(fresh, 2), 0x02);
    const auto f = fold(w, {regtx, upd}, ctx);
    EXPECT_EQ(f.applied, 1u);
    EXPECT_TRUE(refused(f, upd));
}

// A7: the GBT builder never packs a negative-nVersion mempool entry, even one
// that reached the pool before the admission gate (test seam).
TEST(DashEmbeddedGbt, NegativeVersionMempoolTxNeverRidesTemplate)
{
    ::core::coin::UTXOViewCache utxo(nullptr);
    Mempool mp;
    mp.set_utxo(&utxo);
    auto mk = [&](uint8_t tag, int32_t version) {
        const uint256 prev = h256(tag);
        utxo.add_coin(::core::coin::Outpoint(prev, 0),
                      ::core::coin::Coin(100'000, {}, 1, false));
        MutableTransaction tx;
        tx.version = version;
        bitcoin_family::coin::TxIn in;
        in.prevout.hash = prev; in.prevout.index = 0; in.sequence = 0xFFFFFFFFu;
        tx.vin.push_back(in);
        bitcoin_family::coin::TxOut out;
        out.value = 90'000;
        out.scriptPubKey.m_data = {0x76, 0xa9, 0x14, tag, 0x88, 0xac};
        tx.vout.push_back(out);
        return tx;
    };
    auto neg = mk(0x61, 0xFFFF);
    auto ok  = mk(0x62, 1);
    ASSERT_TRUE(mp.add_tx_skipping_contextual_check_for_test(neg));
    ASSERT_TRUE(mp.add_tx(ok));

    World w({make_mn(1)});
    auto wd = dash::coin::build_embedded_workdata(
        2'500'000, h256(0xAB), w.sm, mp, 0x1b104be3u, 1'700'000'000u,
        76, 16, 1'700'000'123u, 0x20000000u);
    bool neg_rides = false, ok_rides = false;
    for (const auto& h : wd.m_tx_hashes) {
        if (h == dash_txid(neg)) neg_rides = true;
        if (h == dash_txid(ok))  ok_rides  = true;
    }
    EXPECT_FALSE(neg_rides) << "bad-txns-version on every upgraded node";
    EXPECT_TRUE(ok_rides);
}
