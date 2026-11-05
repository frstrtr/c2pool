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

#include <algorithm>
#include <array>
#include <cstdint>
#include <string>
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

// ── S4: REAL mainnet vectors (Dash Core 23.1.7 archival node, read-only) ──
// Two mined ProUpServTx and the operator key `protx info <proTx> <block h-1>`
// reported for the PRE-block list. Mainnet has no post-V19 ProUpServTx with
// payload nVersion 1 (a legacy-scheme signature does not verify under the
// network's basic scheme since V19), so the legacy axis covered here is the
// KEY's: vector 1's masternode state is LegacyBLS (legacy-encoded key) while
// its update is signed in the basic scheme.
namespace {
struct RealVector {
    const char* height;
    const char* txid;          // display hex
    const char* raw;           // getrawtransaction <txid> 0
    const char* op_key;        // state.pubKeyOperator at h-1 (the state's scheme)
    bool        key_legacy;    // state.version == 1
    uint16_t    mn_type;
};
const RealVector kVectors[] = {
    {"2555756", "415dc3539c6836583497879301d491d204dde68caf692dfbca46e69e2badd6ad",
     "0300020001eb08ccbdc43d4ca93696eb8685a4dd2505a94c69cdd164a92ca5fb7330015508000000006a473044022012f3185adcc699d2dbe4039db6e64d5913ffbf190580e85b9dbc7aff8247356c02201d8db0ba520034137cd56d2c4c475c9d24afc2f762a5aaf3a2265c48d1776d370121035ffbab73725c430b2904c10563007c5047257aae6caefcda4b47ed70c03b2f6efeffffff01286e7000000000001976a914b734da3d63094c95589fcf9252cd8d9c46eebafa88ac00000000b70200000009c40d4664fa991af5c89e9d5322f7137204c55f5bb8464a1f7d9f60dd46a11f00000000000000000000ffff5fd835c1270f00482f3ea24239aa948b99e100553cbd9b43e93a2d1532b3406c98f3100c4399178ccc794803d0efac7b301eb377c8ef9f8e15f1ecc9723b074ae27404dfcde2889c809e08705ebe2bb98ef564f3a0a45c0abcd94e01867bb54d71d4a81f84785a7ec13340c724d0e0a360121485e0cde3c4a339eb5afc75847be14d13b7b84370",
     "824fb68c3d8268c335884368934dfef6969f79ee93bbf7d575a37812c9e5a014f02513f9e9bbae3fee5283e9363d0e38",
     true, v::MnType::REGULAR},
    {"2561949", "3e090864ef14260d12d7b4fa37cadd8ac9cd0f45721536ae0d426403f8ef6ab2",
     "030002000102e0315717164e0ab9333d10ff4cbb108f7702531eabbc8fd3e5caf593262ebd0a0000006a473044022019acbf538e8fee546a28a62f8b44a8ae2c1c78778069ed32f8326fb42645c2590220717f53e4a37d557dd64bc057a2c96bc8f9903df38ca80be47f452827b5e2ad660121038fe4e6ce652bd57dc0a9061d7e516b85750f0372c29b5b9064170b3a0d010c17feffffff0108850100000000001976a914e7ea00a9693de82bf24bcf0a2760c59994fd134188ac00000000cf020001000c3b617d6c3cc7086840b700d6496d60edc5bf0599af45bea2e4ca90a8b094c000000000000000000000ffff54f7b4c6270f00b8084100a353bc9d0fa63ba3c5bdb9461965126495edc724dae2a647708ef1d3bc3b17ac533e74321ead59434f9bfddd5a4196012068bb01ad7681f826f14056887b4261c15d8924fd4c99b8a43c14d1f7e7ecfef1eb60a53d54e7b2a99100631a858c8f295dbdcb041c87e7f5247f61ab42897bc35eab182cb3da0646b3b2a9974be13f1bdcf658f1ca9affc3c95b458f901a0a7e6b6069",
     "afd9ffe0b5eaabd5fb18c1a76edfb67ea0b42d67069a1ea81f2e67a4fc495ccca31db79b9e1b159dc16330495d038e55",
     false, v::MnType::EVO},
};

std::vector<uint8_t> unhex(const char* h)
{
    std::vector<uint8_t> out;
    for (size_t i = 0; h[i] && h[i + 1]; i += 2)
        out.push_back(static_cast<uint8_t>(std::stoul(std::string(h + i, 2), nullptr, 16)));
    return out;
}
std::array<uint8_t, 48> key48(const char* h)
{
    const auto b = unhex(h);
    std::array<uint8_t, 48> k{};
    std::copy(b.begin(), b.begin() + 48, k.begin());
    return k;
}
MutableTransaction parse_raw(const char* raw)
{
    ::PackStream ps(unhex(raw));
    MutableTransaction tx;
    ps >> tx;
    return tx;
}
} // namespace

// The verifier accepts each real signature under the real pre-block operator
// key, and only under that key.
TEST(DashProTxSigBls, RealMainnetProUpServTxSignaturesVerify)
{
    if (!v::bls_backend_available()) GTEST_SKIP();
    for (size_t i = 0; i < 2; ++i) {
        const auto& rv = kVectors[i];
        const auto tx = parse_raw(rv.raw);
        ASSERT_EQ(dash_txid(tx).GetHex(), rv.txid) << "h=" << rv.height << ": byte-exact parse";
        ASSERT_EQ(tx.type, v::CProUpServTx::SPECIALTX_TYPE);
        v::CProUpServTx pl;
        ASSERT_TRUE(v::parse_protx_payload(tx.extra_payload, pl)) << rv.height;
        EXPECT_EQ(pl.nVersion, v::ProTxVersion::BASIC_BLS);
        EXPECT_EQ(pl.nType, rv.mn_type);
        const auto h = v::protx_operator_sign_hash(tx.extra_payload);
        ASSERT_TRUE(h.has_value());
        EXPECT_TRUE(v::verify_protx_operator_sig(key48(rv.op_key), rv.key_legacy, *h, pl.sig,
                                                  pl.nVersion == v::ProTxVersion::LEGACY_BLS))
            << "h=" << rv.height << ": the mined signature must verify";
        const auto& other = kVectors[1 - i];
        EXPECT_FALSE(v::verify_protx_operator_sig(key48(other.op_key), other.key_legacy, *h,
                                                   pl.sig, false))
            << "h=" << rv.height << ": another operator's key must not verify it";
    }
}

// And through the serving fold with the production (memoized) verifier: each
// real ProUpServTx is Applied on its own pre-block leaf, Refused when the leaf
// holds another operator's key (the stale-key case B.9 exists for).
TEST(DashSupersetSpecialTx, RealMainnetProUpServTxRidesOnlyUnderItsOperatorKey)
{
    if (!v::bls_backend_available()) GTEST_SKIP();
    const auto verifier = dash::coin::memoize_operator_sig_fn(&v::verify_protx_operator_sig);
    MnStateMachine sm;
    for (size_t i = 0; i < 2; ++i) {
        const auto& rv = kVectors[i];
        const auto tx = parse_raw(rv.raw);
        v::CProUpServTx pl;
        ASSERT_TRUE(v::parse_protx_payload(tx.extra_payload, pl));
        auto leaf_with = [&](const RealVector& kv) {
            CSimplifiedMNListEntry e;
            e.nVersion = kv.key_legacy ? CSimplifiedMNListEntry::VER_LEGACY_BLS
                                       : CSimplifiedMNListEntry::VER_BASIC_BLS;
            e.proRegTxHash = pl.proTxHash;
            e.confirmedHash = h256(0x77);
            e.pubKeyOperator = key48(kv.op_key);
            e.isValid = true;
            e.nType = rv.mn_type;
            return CSimplifiedMNList(std::vector<CSimplifiedMNListEntry>{e});
        };
        const auto fold_on = [&](const CSimplifiedMNList& base) {
            return dash::coin::fold_mn_special_txs(
                base, std::vector<MutableTransaction>{tx},
                [](const MutableTransaction& t) { return dash_txid(t); },
                MnFoldContext::from(sm, {}, verifier));
        };
        const auto good = fold_on(leaf_with(rv));
        EXPECT_EQ(good.applied, 1u) << "h=" << rv.height << " "
                                    << (good.refused_reasons.empty() ? "" : good.refused_reasons.front());
        const auto stale = fold_on(leaf_with(kVectors[1 - i]));
        EXPECT_EQ(stale.refused, 1u) << "h=" << rv.height;
    }
}
#endif // C2POOL_DASH_BLS
