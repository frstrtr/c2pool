// SPDX-License-Identifier: AGPL-3.0-or-later
/// Dash Core v23.1.8 delta, item B.9 — the operator signature of ProUpServTx /
/// ProUpRevTx in the template fold, with the REAL BLS backend.
///
/// The most plausible persistent lost-block path the delta revealed: an
/// operator rotates its key (ProUpRegTx(X, K2) mined) while a ProUpServTx(X)
/// signed with the OLD key K1 sits in our pool. Every dashd evicts and rejects
/// it (CheckProUpServTx -> CheckHashSig -> bad-protx-sig); the fold applied it
/// on every template until pool expiry. The fold now verifies the signature
/// against the pre-block operator key (vendor::verify_protx_operator_sig).
///
/// Folded into the test_dash_govvote_bls target: the KAT signs with dashbls,
/// so it needs the BLS backend (C2POOL_DASH_BLS) that target links.

#include <gtest/gtest.h>

#include <impl/dash/coin/mn_state_machine.hpp>
#include <impl/dash/coin/sml_special_fold.hpp>
#include <impl/dash/coin/transaction.hpp>
#include <impl/dash/coin/utxo_adapter.hpp>
#include <impl/dash/coin/vendor/bls_verify.hpp>
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
#include <vector>

#ifdef C2POOL_DASH_BLS
namespace {

namespace v = dash::coin::vendor;
using dash::coin::MnFoldContext;
using dash::coin::MNState;
using dash::coin::MnStateMachine;
using dash::coin::MutableTransaction;
using dash::coin::dash_txid;
using v::CSimplifiedMNList;
using v::CSimplifiedMNListEntry;

struct Key {
    bls::PrivateKey sk;
    std::array<uint8_t, 48> pub{};
};
Key key(uint8_t seed_byte)
{
    Key k{bls::BasicSchemeMPL().KeyGen(std::vector<uint8_t>(32, seed_byte)), {}};
    k.pub = k.sk.GetG1Element().SerializeToArray(/*legacy=*/false);
    return k;
}

uint256 h256(uint8_t tag)
{
    uint256 h;
    for (int i = 0; i < 32; ++i) h.data()[i] = static_cast<uint8_t>(tag + i);
    return h;
}

/// One registered masternode X whose CURRENT operator key is `op`.
struct World {
    uint256 x = h256(0x51);
    MnStateMachine sm;
    CSimplifiedMNList base;
    explicit World(const std::array<uint8_t, 48>& op)
    {
        MNState st;
        st.nVersion = v::ProTxVersion::BASIC_BLS;
        st.collateralOutpoint.hash = h256(0x61);
        st.collateralOutpoint.index = 1;
        st.pubKeyOperator = op;
        st.netInfo.ip[15] = 7; st.netInfo.port_be = 9999;
        st.isValid = true;
        sm.load({{x, st}}, 2'500'000);
        CSimplifiedMNListEntry e;
        e.nVersion = CSimplifiedMNListEntry::VER_BASIC_BLS;
        e.proRegTxHash = x;
        e.confirmedHash = h256(0x77);
        e.netAddress = st.netInfo.ip;
        e.netPort = st.netInfo.port_be;
        e.pubKeyOperator = op;
        e.isValid = true;
        base = CSimplifiedMNList(std::vector<CSimplifiedMNListEntry>{e});
    }
    MnFoldContext ctx() const
    {
        return MnFoldContext::from(sm, {}, &v::verify_protx_operator_sig);
    }
};

template <typename Payload>
MutableTransaction signed_tx(uint16_t type, Payload p, const bls::PrivateKey& signer)
{
    auto pack_payload = [](const Payload& q) {
        auto ps = ::pack(q);
        auto sp = ps.get_span();
        return std::vector<uint8_t>(reinterpret_cast<const uint8_t*>(sp.data()),
                                    reinterpret_cast<const uint8_t*>(sp.data()) + sp.size());
    };
    // The preimage excludes the trailing sig, so signing a zero-sig payload
    // signs exactly what the final payload hashes to.
    p.sig = {};
    const auto h = v::protx_operator_sign_hash(pack_payload(p));
    EXPECT_TRUE(h.has_value());
    const auto sig = bls::BasicSchemeMPL().Sign(signer, bls::Bytes(h->data(), 32));
    p.sig = sig.SerializeToArray(/*legacy=*/false);
    MutableTransaction tx;
    tx.version = 3;
    tx.type = type;
    bitcoin_family::coin::TxIn in;
    in.prevout.hash = h256(0x91); in.prevout.index = type; in.sequence = 0xFFFFFFFFu;
    tx.vin.push_back(in);
    tx.extra_payload = pack_payload(p);
    return tx;
}

v::CProUpServTx serv_of(const uint256& x)
{
    v::CProUpServTx p;
    p.nVersion = v::ProTxVersion::BASIC_BLS;
    p.nType = v::MnType::REGULAR;
    p.proTxHash = x;
    p.netInfo.ip[15] = 8; p.netInfo.port_be = 9999;
    p.inputsHash = h256(0x33);
    return p;
}

v::CProUpRevTx rev_of(const uint256& x)
{
    v::CProUpRevTx p;
    p.nVersion = v::ProTxVersion::BASIC_BLS;
    p.proTxHash = x;
    p.nReason = v::CProUpRevTx::REASON_CHANGE_OF_KEYS;
    p.inputsHash = h256(0x34);
    return p;
}

dash::coin::SmlSpecialFold fold(const World& w, const MutableTransaction& tx)
{
    return dash::coin::fold_mn_special_txs(
        w.base, std::vector<MutableTransaction>{tx},
        [](const MutableTransaction& t) { return dash_txid(t); }, w.ctx());
}

} // namespace

// The entry's operator is K2 (the rotation is mined). A ProUpServTx signed by
// the old key K1 is refused; the same update signed by K2 is applied.
TEST(DashSupersetSpecialTx, ProUpServTxWithStaleOperatorKeyIsRefused)
{
    if (!v::bls_backend_available()) GTEST_SKIP();
    const Key k1 = key(0x11), k2 = key(0x22);
    World w(k2.pub);
    const auto stale = fold(w, signed_tx(2, serv_of(w.x), k1.sk));
    EXPECT_EQ(stale.applied, 0u);
    EXPECT_EQ(stale.refused, 1u) << "dashd: bad-protx-sig";
    EXPECT_EQ(stale.sml.CalcMerkleRoot(), w.base.CalcMerkleRoot());
    const auto fresh = fold(w, signed_tx(2, serv_of(w.x), k2.sk));
    EXPECT_EQ(fresh.applied, 1u);
    EXPECT_EQ(fresh.refused, 0u);
}

// ProUpRevTx is signed by the operator too (CheckProUpRevTx -> CheckHashSig).
TEST(DashSupersetSpecialTx, ProUpRevTxWithWrongOperatorKeyIsRefused)
{
    if (!v::bls_backend_available()) GTEST_SKIP();
    const Key k1 = key(0x31), k2 = key(0x42);
    World w(k2.pub);
    EXPECT_EQ(fold(w, signed_tx(4, rev_of(w.x), k1.sk)).refused, 1u);
    EXPECT_EQ(fold(w, signed_tx(4, rev_of(w.x), k2.sk)).applied, 1u);
}

// The verifier itself: basic-scheme verify of the 32-byte preimage; a sig is
// decoded ONLY under the payload's scheme, the null key never verifies, and a
// legacy-scheme SIGNATURE is rejected post-V19 like dashd's VerifyInsecure.
TEST(DashProTxSigBls, VerifierMatchesDashdCheckHashSig)
{
    if (!v::bls_backend_available()) GTEST_SKIP();
    const Key k = key(0x55);
    const uint256 h = h256(0x66);
    const auto sig = bls::BasicSchemeMPL().Sign(k.sk, bls::Bytes(h.data(), 32));
    const auto sig_basic = sig.SerializeToArray(false);
    EXPECT_TRUE(v::verify_protx_operator_sig(k.pub, false, h, sig_basic, false));
    // The key's encoding is a fallback axis (a LegacyBLS-registered entry).
    EXPECT_TRUE(v::verify_protx_operator_sig(
        k.sk.GetG1Element().SerializeToArray(true), true, h, sig_basic, false));
    EXPECT_FALSE(v::verify_protx_operator_sig(k.pub, false, h256(0x67), sig_basic, false));
    EXPECT_FALSE(v::verify_protx_operator_sig({}, false, h, sig_basic, false))
        << "a revoked (null) operator key verifies nothing";
    const auto legacy_signed = bls::LegacySchemeMPL().Sign(k.sk, bls::Bytes(h.data(), 32));
    EXPECT_FALSE(v::verify_protx_operator_sig(
        k.pub, false, h, legacy_signed.SerializeToArray(false), false));
}
#endif // C2POOL_DASH_BLS
