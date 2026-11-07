// SPDX-License-Identifier: AGPL-3.0-or-later
//
// S6 (VERIFY-S2 P-2): Dash Core's full CheckPro*Tx before a provider tx rides
// a template (protx_check.hpp), and its wiring into the template fold
// (sml_special_fold.hpp require_core_check / core_check) and the builder.
//
// Every case is cryptographically real: operator keys and signatures come from
// dashbls, collateral and owner signatures from secp256k1, so a positive case
// passes only when the hashes, the sign string and the key IDs are exactly
// Core's. Negative cases flip one field each and assert Core's reject code.
// This TU rides test_dash_govvote_bls (the BLS-backend target).

#include <gtest/gtest.h>

#include <impl/dash/coin/embedded_gbt.hpp>
#include <impl/dash/coin/mempool.hpp>
#include <impl/dash/coin/mn_state_machine.hpp>
#include <impl/dash/coin/protx_check.hpp>
#include <impl/dash/coin/protx_ecdsa.hpp>
#include <impl/dash/coin/quorum_manager.hpp>
#include <impl/dash/coin/sml_projection.hpp>
#include <impl/dash/coin/sml_special_fold.hpp>
#include <impl/dash/coin/vendor/bls_verify.hpp>
#include <impl/dash/coin/vendor/cbtx.hpp>
#include <impl/dash/coin/vendor/providertx.hpp>
#include <impl/dash/coin/vendor/simplifiedmns.hpp>

#include <core/coin/utxo_view_cache.hpp>
#include <core/hash.hpp>
#include <core/pack.hpp>
#include <core/uint256.hpp>

#ifdef C2POOL_DASH_BLS
#include <dashbls/bls.hpp>
#include <dashbls/schemes.hpp>
#endif

#include <secp256k1.h>
#include <secp256k1_recovery.h>

#include <cctype>
#include <map>
#include <optional>
#include <string>
#include <vector>

#ifdef C2POOL_DASH_BLS
namespace {

namespace v = dash::coin::vendor;
using dash::coin::MNState;
using dash::coin::MnStateMachine;
using dash::coin::MutableTransaction;
using dash::coin::ProTxCheckRules;
using dash::coin::ProTxCoinProof;
using dash::coin::protx_core_refusal;
using Outpoint = bitcoin_family::coin::TxPrevOut;

// ── keys ────────────────────────────────────────────────────────────────────

struct BlsKey {
    bls::PrivateKey sk;
    std::array<uint8_t, 48> pub{};   // basic scheme
};
BlsKey bls_key(uint8_t seed)
{
    BlsKey k{bls::BasicSchemeMPL().KeyGen(std::vector<uint8_t>(32, seed)), {}};
    k.pub = k.sk.GetG1Element().SerializeToArray(/*legacy=*/false);
    return k;
}

const secp256k1_context* sign_ctx()
{
    static secp256k1_context* c = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    return c;
}

struct EcKey {
    std::array<uint8_t, 32> sk{};
    uint160 id;
};
EcKey ec_key(uint8_t seed)
{
    EcKey k;
    for (size_t i = 0; i < 32; ++i) k.sk[i] = static_cast<uint8_t>(seed + i);
    secp256k1_pubkey pk;
    EXPECT_EQ(secp256k1_ec_pubkey_create(sign_ctx(), &pk, k.sk.data()), 1);
    unsigned char ser[33];
    size_t len = sizeof(ser);
    secp256k1_ec_pubkey_serialize(sign_ctx(), ser, &len, &pk, SECP256K1_EC_COMPRESSED);
    CHash160().Write(std::span<const unsigned char>(ser, len)).Finalize(std::span<unsigned char>(k.id.data(), 20));
    return k;
}

/// CKey::SignCompact: [27 + recid + 4 (compressed)] || r || s.
std::vector<uint8_t> sign_compact(const EcKey& k, const uint256& hash)
{
    secp256k1_ecdsa_recoverable_signature sig;
    EXPECT_EQ(secp256k1_ecdsa_sign_recoverable(sign_ctx(), &sig, hash.data(), k.sk.data(), nullptr, nullptr), 1);
    std::vector<uint8_t> out(65);
    int recid = 0;
    secp256k1_ecdsa_recoverable_signature_serialize_compact(sign_ctx(), out.data() + 1, &recid, &sig);
    out[0] = static_cast<uint8_t>(27 + recid + 4);
    return out;
}

std::vector<uint8_t> p2pkh(const uint160& id)
{
    std::vector<uint8_t> s = {0x76, 0xa9, 0x14};
    s.insert(s.end(), id.data(), id.data() + 20);
    s.push_back(0x88);
    s.push_back(0xac);
    return s;
}
std::vector<uint8_t> p2sh(uint8_t tag)
{
    std::vector<uint8_t> s = {0xa9, 0x14};
    for (int i = 0; i < 20; ++i) s.push_back(static_cast<uint8_t>(tag + i));
    s.push_back(0x87);
    return s;
}

uint256 h256(uint8_t tag)
{
    uint256 h;
    for (int i = 0; i < 32; ++i) h.data()[i] = static_cast<uint8_t>(tag + i);
    return h;
}

v::LegacyNetService ipv4(uint8_t a, uint8_t b, uint8_t c, uint8_t d, uint16_t port)
{
    v::LegacyNetService n;
    n.ip[10] = 0xff; n.ip[11] = 0xff;
    n.ip[12] = a; n.ip[13] = b; n.ip[14] = c; n.ip[15] = d;
    n.port_be = port;
    return n;
}

template <typename P>
std::vector<uint8_t> pack_payload(const P& p)
{
    auto ps = ::pack(p);
    auto sp = ps.get_span();
    return std::vector<uint8_t>(reinterpret_cast<const uint8_t*>(sp.data()),
                                reinterpret_cast<const uint8_t*>(sp.data()) + sp.size());
}

constexpr int64_t kColl = 1000LL * 100'000'000LL;

// ── the world: one registered masternode M and a UTXO view ──────────────────

struct World {
    EcKey owner = ec_key(0x11);
    EcKey collat = ec_key(0x22);
    EcKey voting = ec_key(0x33);
    EcKey newcollat = ec_key(0x44);
    BlsKey op = bls_key(0x55);
    BlsKey op2 = bls_key(0x56);
    uint256 m = h256(0xA0);
    Outpoint m_collateral;
    MnStateMachine sm;
    std::map<std::pair<uint256, uint32_t>, std::pair<int64_t, std::vector<uint8_t>>> coins;
    ProTxCheckRules rules;   // mainnet, v19 on, v24 off

    World()
    {
        m_collateral.hash = h256(0xB0);
        m_collateral.index = 1;
        MNState st;
        st.nVersion = v::ProTxVersion::BASIC_BLS;
        st.collateralOutpoint = m_collateral;
        st.keyIDOwner = owner.id;
        st.keyIDVoting = voting.id;
        st.pubKeyOperator = op.pub;
        st.nOperatorReward = 1000;
        st.scriptPayout.m_data = p2pkh(ec_key(0x66).id);
        st.netInfo = ipv4(1, 2, 3, 4, 9999);
        st.isValid = true;
        sm.load({{m, st}}, 2'500'000);
        coins[{m_collateral.hash, m_collateral.index}] = {kColl, p2pkh(collat.id)};
    }

    dash::coin::ProTxCoinFn coin_fn() const
    {
        return [this](const Outpoint& o, int64_t& value, std::vector<uint8_t>& script) {
            auto it = coins.find({o.hash, o.index});
            if (it == coins.end()) return ProTxCoinProof::Absent;
            value = it->second.first;
            script = it->second.second;
            return ProTxCoinProof::Unspent;
        };
    }
    std::optional<std::string> check(const MutableTransaction& tx, bool with_ecdsa = true) const
    {
        dash::coin::ProTxEcdsaVerifyFn ec;
        if (with_ecdsa) ec = &dash::coin::protx_ecdsa_verify_hash;
        return protx_core_refusal(tx, sm, rules, coin_fn(), ec);
    }
};

MutableTransaction tx_with_inputs(uint16_t type, std::vector<std::pair<uint256, uint32_t>> ins)
{
    MutableTransaction tx;
    tx.version = 3;
    tx.type = type;
    for (auto& [h, n] : ins) {
        bitcoin_family::coin::TxIn in;
        in.prevout.hash = h;
        in.prevout.index = n;
        in.sequence = 0xffffffffu;
        tx.vin.push_back(in);
    }
    return tx;
}

/// A ProRegTx with an INTERNAL collateral (vout[0], 1000 DASH): no signature.
struct RegInternal {
    v::CProRegTx p;
    MutableTransaction tx;
};
RegInternal reg_internal(const World& w)
{
    RegInternal r;
    r.tx = tx_with_inputs(1, {{h256(0xC0), 0}});
    bitcoin_family::coin::TxOut out;
    out.value = kColl;
    out.scriptPubKey.m_data = p2pkh(w.newcollat.id);
    r.tx.vout.push_back(out);
    r.p.nVersion = v::ProTxVersion::BASIC_BLS;
    r.p.nType = v::MnType::REGULAR;
    r.p.collateralOutpoint.index = 0;   // null hash: internal
    r.p.netInfo = ipv4(5, 6, 7, 8, 9999);
    r.p.keyIDOwner = ec_key(0x71).id;
    r.p.pubKeyOperator = bls_key(0x72).pub;
    r.p.keyIDVoting = ec_key(0x73).id;
    r.p.nOperatorReward = 0;
    r.p.scriptPayout.m_data = p2pkh(ec_key(0x74).id);
    r.p.inputsHash = dash::coin::protx_check_detail::inputs_hash(r.tx);
    r.tx.extra_payload = pack_payload(r.p);
    return r;
}
MutableTransaction rewrap(MutableTransaction tx, const v::CProRegTx& p)
{
    tx.extra_payload = pack_payload(p);
    return tx;
}

/// A ProRegTx with an EXTERNAL collateral, signed by the collateral key over
/// MakeSignString.
MutableTransaction reg_external(const World& w, v::CProRegTx p, const EcKey& signer, bool fix_inputs = true)
{
    MutableTransaction tx = tx_with_inputs(1, {{h256(0xC1), 0}});
    if (fix_inputs) p.inputsHash = dash::coin::protx_check_detail::inputs_hash(tx);
    p.vchSig.clear();
    tx.extra_payload = pack_payload(p);
    const auto h = dash::coin::protx_check_detail::hash_without_trailing_vchsig(tx.extra_payload, 0);
    const std::string s =
        core::script_to_address(p.scriptPayout.m_data, "", 76, 16) + "|" + std::to_string(p.nOperatorReward)
        + "|" + dash::coin::protx_check_detail::encode_pkh(p.keyIDOwner, 76)
        + "|" + dash::coin::protx_check_detail::encode_pkh(p.keyIDVoting, 76) + "|" + h->GetHex();
    p.vchSig = sign_compact(signer, dash::coin::protx_check_detail::message_hash(s));
    tx.extra_payload = pack_payload(p);
    (void)w;
    return tx;
}
v::CProRegTx external_payload(World& w)
{
    v::CProRegTx p;
    p.nVersion = v::ProTxVersion::BASIC_BLS;
    p.nType = v::MnType::REGULAR;
    p.collateralOutpoint.hash = h256(0xD0);
    p.collateralOutpoint.index = 2;
    w.coins[{p.collateralOutpoint.hash, 2}] = {kColl, p2pkh(w.newcollat.id)};
    p.netInfo = ipv4(9, 9, 9, 9, 9999);
    p.keyIDOwner = ec_key(0x81).id;
    p.pubKeyOperator = bls_key(0x82).pub;
    p.keyIDVoting = ec_key(0x83).id;
    p.nOperatorReward = 250;
    p.scriptPayout.m_data = p2sh(0x84);
    return p;
}

MutableTransaction serv_tx(const World& w, v::CProUpServTx p, const bls::PrivateKey& signer, bool fix_inputs = true)
{
    MutableTransaction tx = tx_with_inputs(2, {{h256(0xE0), 3}});
    if (fix_inputs) p.inputsHash = dash::coin::protx_check_detail::inputs_hash(tx);
    p.sig = {};
    const auto h = v::protx_operator_sign_hash(pack_payload(p));
    // The signature is encoded in the payload version's scheme.
    p.sig = bls::BasicSchemeMPL().Sign(signer, bls::Bytes(h->data(), 32))
                .SerializeToArray(/*legacy=*/p.nVersion == v::ProTxVersion::LEGACY_BLS);
    tx.extra_payload = pack_payload(p);
    (void)w;
    return tx;
}
v::CProUpServTx serv_payload(const World& w)
{
    v::CProUpServTx p;
    p.nVersion = v::ProTxVersion::BASIC_BLS;
    p.nType = v::MnType::REGULAR;
    p.proTxHash = w.m;
    p.netInfo = ipv4(1, 2, 3, 5, 9999);
    return p;
}

MutableTransaction upreg_tx(const World& w, v::CProUpRegTx p, const EcKey& signer, bool fix_inputs = true)
{
    MutableTransaction tx = tx_with_inputs(3, {{h256(0xE1), 0}});
    if (fix_inputs) p.inputsHash = dash::coin::protx_check_detail::inputs_hash(tx);
    p.vchSig.clear();
    tx.extra_payload = pack_payload(p);
    const auto h = dash::coin::protx_check_detail::hash_without_trailing_vchsig(tx.extra_payload, 0);
    p.vchSig = sign_compact(signer, *h);
    tx.extra_payload = pack_payload(p);
    (void)w;
    return tx;
}
v::CProUpRegTx upreg_payload(const World& w)
{
    v::CProUpRegTx p;
    p.nVersion = v::ProTxVersion::BASIC_BLS;
    p.proTxHash = w.m;
    p.pubKeyOperator = w.op2.pub;
    p.keyIDVoting = w.voting.id;
    p.scriptPayout.m_data = p2pkh(ec_key(0x91).id);
    return p;
}

MutableTransaction rev_tx(const World& w, v::CProUpRevTx p, const bls::PrivateKey& signer, bool fix_inputs = true)
{
    MutableTransaction tx = tx_with_inputs(4, {{h256(0xE2), 1}});
    if (fix_inputs) p.inputsHash = dash::coin::protx_check_detail::inputs_hash(tx);
    p.sig = {};
    const auto h = v::protx_operator_sign_hash(pack_payload(p));
    p.sig = bls::BasicSchemeMPL().Sign(signer, bls::Bytes(h->data(), 32))
                .SerializeToArray(/*legacy=*/p.nVersion == v::ProTxVersion::LEGACY_BLS);
    tx.extra_payload = pack_payload(p);
    (void)w;
    return tx;
}
v::CProUpRevTx rev_payload(const World& w)
{
    v::CProUpRevTx p;
    p.nVersion = v::ProTxVersion::BASIC_BLS;
    p.proTxHash = w.m;
    p.nReason = v::CProUpRevTx::REASON_TERMINATION_OF_SERVICE;
    return p;
}

/// Core's reject code exactly: the reason is the code, or the code followed by
/// a " (detail)".
::testing::AssertionResult HasCode(const std::optional<std::string>& r, const std::string& code)
{
    if (!r) return ::testing::AssertionFailure() << "expected " << code << ", got a pass";
    if (*r == code || r->rfind(code + " ", 0) == 0) return ::testing::AssertionSuccess();
    return ::testing::AssertionFailure() << "expected " << code << ", got " << *r;
}
#define EXPECT_CODE(expr, code) EXPECT_TRUE(HasCode((expr), (code)))

} // namespace

// ── positive cases (every rule passes, signatures real) ─────────────────────

TEST(DashV24ProTxCheck, ValidTxsOfEveryTypePass)
{
    World w;
    EXPECT_EQ(w.check(reg_internal(w).tx), std::nullopt);
    EXPECT_EQ(w.check(reg_external(w, external_payload(w), w.newcollat)), std::nullopt);
    EXPECT_EQ(w.check(serv_tx(w, serv_payload(w), w.op.sk)), std::nullopt);
    EXPECT_EQ(w.check(upreg_tx(w, upreg_payload(w), w.owner)), std::nullopt);
    EXPECT_EQ(w.check(rev_tx(w, rev_payload(w), w.op.sk)), std::nullopt);
    // Non-provider txs are not this check's business.
    MutableTransaction plain;
    plain.version = 2;
    EXPECT_EQ(w.check(plain), std::nullopt);
}

// ── ProRegTx ────────────────────────────────────────────────────────────────

TEST(DashV24ProTxCheck, ProRegTxPayloadRules)
{
    World w;
    auto base = reg_internal(w);
    auto mut = [&](auto f) { auto p = base.p; f(p); return rewrap(base.tx, p); };
    EXPECT_CODE(w.check(mut([](auto& p) { p.nVersion = 0; })), "bad-protx-version");
    EXPECT_CODE(w.check(mut([](auto& p) { p.nVersion = 3; })), "bad-protx-version");
    EXPECT_CODE(w.check(mut([](auto& p) { p.nVersion = 1; p.nType = v::MnType::EVO; })), "bad-protx-evo-version");
    EXPECT_CODE(w.check(mut([](auto& p) { p.nType = 2; })), "bad-protx-type");
    EXPECT_CODE(w.check(mut([](auto& p) { p.nMode = 1; })), "bad-protx-mode");
    EXPECT_CODE(w.check(mut([](auto& p) { p.keyIDOwner = uint160(); })), "bad-protx-key-null");
    EXPECT_CODE(w.check(mut([](auto& p) { p.keyIDVoting = uint160(); })), "bad-protx-key-null");
    EXPECT_CODE(w.check(mut([](auto& p) { p.pubKeyOperator = {}; })), "bad-protx-key-null");
    EXPECT_CODE(w.check(mut([](auto& p) { p.pubKeyOperator[0] ^= 0x01; })), "bad-protx-key-null")
        << "not a canonical point";
    // A v1 (LegacyBLS) payload carries the key in the legacy encoding.
    {
        auto p = base.p;
        p.nVersion = 1;
        p.pubKeyOperator = bls_key(0x72).sk.GetG1Element().SerializeToArray(/*legacy=*/true);
        EXPECT_EQ(w.check(rewrap(base.tx, p)), std::nullopt) << "a v1 legacy registration passes before v24";
        p.pubKeyOperator = {};
        EXPECT_CODE(w.check(rewrap(base.tx, p)), "bad-protx-key-null");
    }
    EXPECT_CODE(w.check(mut([](auto& p) { p.scriptPayout.m_data = {0x51}; })), "bad-protx-payee");
    EXPECT_CODE(w.check(mut([](auto& p) { p.scriptPayout.m_data = p2pkh(p.keyIDOwner); })), "bad-protx-payee-reuse");
    EXPECT_CODE(w.check(mut([](auto& p) { p.scriptPayout.m_data = p2pkh(p.keyIDVoting); })), "bad-protx-payee-reuse");
    EXPECT_CODE(w.check(mut([](auto& p) { p.nOperatorReward = 10001; })), "bad-protx-operator-reward");
}

TEST(DashV24ProTxCheck, ProRegTxNetworkFields)
{
    World w;
    auto base = reg_internal(w);
    auto with_net = [&](v::LegacyNetService n) { auto p = base.p; p.netInfo = n; return rewrap(base.tx, p); };
    EXPECT_EQ(w.check(with_net(v::LegacyNetService{})), std::nullopt) << "empty is allowed (MN starts banned)";
    EXPECT_CODE(w.check(with_net(ipv4(10, 0, 0, 1, 9999))), "bad-protx-netinfo-addr-unroutable");
    EXPECT_CODE(w.check(with_net(ipv4(192, 168, 1, 1, 9999))), "bad-protx-netinfo-addr-unroutable");
    EXPECT_CODE(w.check(with_net(ipv4(127, 0, 0, 1, 9999))), "bad-protx-netinfo-addr-unroutable");
    EXPECT_CODE(w.check(with_net(ipv4(100, 64, 0, 1, 9999))), "bad-protx-netinfo-addr-unroutable");
    EXPECT_CODE(w.check(with_net(ipv4(5, 6, 7, 8, 19999))), "bad-protx-netinfo-port") << "mainnet needs 9999";
    // 0.0.0.0:9999 is "empty" to Core but not to the fold: refused.
    EXPECT_CODE(w.check(with_net(ipv4(0, 0, 0, 0, 9999))), "bad-protx-netinfo-addr");
    v::LegacyNetService v6;
    v6.ip[0] = 0x20; v6.ip[1] = 0x01; v6.ip[15] = 1; v6.port_be = 9999;
    EXPECT_CODE(w.check(with_net(v6)), "bad-protx-netinfo-addr");
    // Testnet: port 9999 is forbidden, private addresses still are.
    w.rules.net = dash::coin::DashNetwork::TESTNET;
    EXPECT_CODE(w.check(with_net(ipv4(5, 6, 7, 8, 9999))), "bad-protx-netinfo-port");
    EXPECT_EQ(w.check(with_net(ipv4(5, 6, 7, 8, 19999))), std::nullopt);
    // Evo platform fields (mainnet defaults 26656 / 443).
    w.rules.net = dash::coin::DashNetwork::MAINNET;
    auto evo = [&](uint160 node, uint16_t p2p, uint16_t http) {
        auto p = base.p;
        p.nType = v::MnType::EVO;
        p.platformNodeID = node;
        p.platformP2PPort = p2p;
        p.platformHTTPPort = http;
        auto tx = base.tx;
        tx.vout[0].value = 4000LL * 100'000'000LL;
        return rewrap(tx, p);
    };
    uint160 node = ec_key(0x99).id;
    EXPECT_EQ(w.check(evo(node, 26656, 443)), std::nullopt);
    EXPECT_CODE(w.check(evo(uint160(), 26656, 443)), "bad-protx-platform-nodeid");
    EXPECT_CODE(w.check(evo(node, 26657, 443)), "bad-protx-platform-p2p-port");
    EXPECT_CODE(w.check(evo(node, 26656, 444)), "bad-protx-platform-http-port");
}

TEST(DashV24ProTxCheck, ProRegTxCollateralInputsAndSignature)
{
    World w;
    // Internal collateral.
    {
        auto base = reg_internal(w);
        auto tx = base.tx;
        auto p = base.p;
        p.collateralOutpoint.index = 5;
        EXPECT_CODE(w.check(rewrap(tx, p)), "bad-protx-collateral-index");
        tx.vout[0].value -= 1;
        EXPECT_CODE(w.check(rewrap(tx, base.p)), "bad-protx-collateral");
        tx = base.tx;
        tx.vout[0].scriptPubKey.m_data = {0x6a};
        EXPECT_CODE(w.check(rewrap(tx, base.p)), "bad-protx-collateral-dest");
        tx = base.tx;
        tx.vout[0].scriptPubKey.m_data = p2pkh(base.p.keyIDOwner);
        EXPECT_CODE(w.check(rewrap(tx, base.p)), "bad-protx-collateral-reuse");
        p = base.p;
        p.inputsHash = h256(0x01);
        EXPECT_CODE(w.check(rewrap(base.tx, p)), "bad-protx-inputs-hash");
        p = base.p;
        p.vchSig = {1, 2, 3};
        EXPECT_CODE(w.check(rewrap(base.tx, p)), "bad-protx-sig") << "internal collateral carries no sig";
        // A valid payload re-wrapped in a tx with other inputs (P-2).
        auto rew = base.tx;
        rew.vin[0].prevout.index = 7;
        EXPECT_CODE(w.check(rew), "bad-protx-inputs-hash");
    }
    // External collateral.
    {
        auto p = external_payload(w);
        EXPECT_CODE(w.check(reg_external(w, p, w.owner)), "bad-protx-sig") << "signed by a non-collateral key";
        EXPECT_CODE(w.check(reg_external(w, p, w.newcollat), /*with_ecdsa=*/false), "bad-protx-sig");
        auto tx = reg_external(w, p, w.newcollat);
        tx.extra_payload.back() ^= 0x01;   // flip a sig byte
        EXPECT_CODE(w.check(tx), "bad-protx-sig");
        // The coin: absent, wrong amount, P2SH, unprovable.
        auto q = p; q.collateralOutpoint.index = 9;
        EXPECT_CODE(w.check(reg_external(w, q, w.newcollat)), "bad-protx-collateral");
        w.coins[{p.collateralOutpoint.hash, 2}].first = kColl + 1;
        EXPECT_CODE(w.check(reg_external(w, p, w.newcollat)), "bad-protx-collateral");
        w.coins[{p.collateralOutpoint.hash, 2}] = {kColl, p2sh(0x01)};
        EXPECT_CODE(w.check(reg_external(w, p, w.newcollat)), "bad-protx-collateral-pkh");
        w.coins[{p.collateralOutpoint.hash, 2}] = {kColl, p2pkh(w.newcollat.id)};
        auto unknown = [](const Outpoint&, int64_t&, std::vector<uint8_t>&) { return ProTxCoinProof::Unknown; };
        EXPECT_CODE(protx_core_refusal(reg_external(w, p, w.newcollat), w.sm, w.rules, unknown,
                                       &dash::coin::protx_ecdsa_verify_hash),
                    "bad-protx-collateral");
        EXPECT_CODE(protx_core_refusal(reg_external(w, p, w.newcollat), w.sm, w.rules, {},
                                       &dash::coin::protx_ecdsa_verify_hash),
                    "bad-protx-collateral");
        // The signed string covers the payload hash: any payload change after
        // signing breaks it.
        auto tx2 = reg_external(w, p, w.newcollat);
        v::CProRegTx back;
        ASSERT_TRUE(v::parse_protx_payload(tx2.extra_payload, back));
        back.nOperatorReward = 251;
        EXPECT_CODE(w.check(rewrap(tx2, back)), "bad-protx-sig");
    }
}

TEST(DashV24ProTxCheck, ProRegTxUnderV24)
{
    World w;
    w.rules.v24_active = true;
    auto base = reg_internal(w);
    EXPECT_EQ(w.check(base.tx), std::nullopt);
    auto p = base.p;
    p.nVersion = 1;
    p.pubKeyOperator = bls_key(0x72).sk.GetG1Element().SerializeToArray(/*legacy=*/true);
    EXPECT_CODE(w.check(rewrap(base.tx, p)), "bad-protx-version-disallowed")
        << "no legacy-scheme registrations after v24";
    // The operator key of M under any scheme is taken.
    p = base.p;
    p.pubKeyOperator = w.op.pub;
    EXPECT_CODE(w.check(rewrap(base.tx, p)), "bad-protx-dup-key");
}

// ── ProUpServTx ─────────────────────────────────────────────────────────────

TEST(DashV24ProTxCheck, ProUpServTxRules)
{
    World w;
    auto p = serv_payload(w);
    auto t = [&](v::CProUpServTx q, bool fix = true) { return serv_tx(w, q, w.op.sk, fix); };
    { auto q = p; q.netInfo = v::LegacyNetService{}; EXPECT_CODE(w.check(t(q)), "bad-protx-netinfo-empty"); }
    { auto q = p; q.netInfo = ipv4(10, 1, 1, 1, 9999); EXPECT_CODE(w.check(t(q)), "bad-protx-netinfo-addr-unroutable"); }
    { auto q = p; q.proTxHash = h256(0x01); EXPECT_CODE(w.check(t(q)), "bad-protx-hash"); }
    { auto q = p; q.nType = v::MnType::EVO; q.platformNodeID = ec_key(0x9a).id;
      q.platformP2PPort = 26656; q.platformHTTPPort = 443;
      EXPECT_CODE(w.check(t(q)), "bad-protx-type-mismatch"); }
    { auto q = p; q.nType = 5; EXPECT_CODE(w.check(t(q)), "bad-protx-type"); }
    { auto q = p; q.scriptOperatorPayout.m_data = {0x51}; EXPECT_CODE(w.check(t(q)), "bad-protx-operator-payee"); }
    { auto q = p; q.scriptOperatorPayout.m_data = p2sh(0x10); EXPECT_EQ(w.check(t(q)), std::nullopt); }
    { auto q = p; q.inputsHash = h256(0x02); EXPECT_CODE(w.check(t(q, false)), "bad-protx-inputs-hash"); }
    // Operator reward 0: no operator payee may be set.
    {
        World w0;
        MNState st = w0.sm.entries().at(w0.m);
        st.nOperatorReward = 0;
        w0.sm.load({{w0.m, st}}, 2'500'000);
        auto q = serv_payload(w0);
        q.scriptOperatorPayout.m_data = p2pkh(ec_key(0x12).id);
        EXPECT_CODE(w0.check(serv_tx(w0, q, w0.op.sk)), "bad-protx-operator-payee");
    }
    // A signature that is not a canonical BLS encoding: Core cannot even parse.
    {
        auto tx = t(p);
        v::CProUpServTx back;
        ASSERT_TRUE(v::parse_protx_payload(tx.extra_payload, back));
        back.sig.fill(0xff);   // x >= p: no point decodes
        back.sig[0] = 0x9f;
        tx.extra_payload = pack_payload(back);
        EXPECT_CODE(w.check(tx), "bad-protx-payload");
    }
    // v24: downgrading a basic-scheme state with a legacy payload.
    {
        World w2;
        w2.rules.v24_active = true;
        auto q = serv_payload(w2);
        q.nVersion = 1;
        EXPECT_CODE(w2.check(serv_tx(w2, q, w2.op.sk)), "bad-protx-version-downgrade");
    }
}

// ── ProUpRegTx ──────────────────────────────────────────────────────────────

TEST(DashV24ProTxCheck, ProUpRegTxRules)
{
    World w;
    auto p = upreg_payload(w);
    auto t = [&](v::CProUpRegTx q, const EcKey& k, bool fix = true) { return upreg_tx(w, q, k, fix); };
    { auto q = p; q.nMode = 1; EXPECT_CODE(w.check(t(q, w.owner)), "bad-protx-mode"); }
    { auto q = p; q.pubKeyOperator = {}; EXPECT_CODE(w.check(t(q, w.owner)), "bad-protx-key-null"); }
    { auto q = p; q.keyIDVoting = uint160(); EXPECT_CODE(w.check(t(q, w.owner)), "bad-protx-key-null"); }
    { auto q = p; q.scriptPayout.m_data = {0x00, 0x14}; EXPECT_CODE(w.check(t(q, w.owner)), "bad-protx-payee"); }
    { auto q = p; q.scriptPayout.m_data = p2pkh(q.keyIDVoting); EXPECT_CODE(w.check(t(q, w.owner)), "bad-protx-payee-reuse"); }
    { auto q = p; q.scriptPayout.m_data = p2pkh(w.owner.id); EXPECT_CODE(w.check(t(q, w.owner)), "bad-protx-payee-reuse")
        << "the registered owner key"; }
    { auto q = p; q.proTxHash = h256(0x03); EXPECT_CODE(w.check(t(q, w.owner)), "bad-protx-hash"); }
    { auto q = p; q.keyIDVoting = w.collat.id; EXPECT_CODE(w.check(t(q, w.owner)), "bad-protx-collateral-reuse"); }
    { auto q = p; q.inputsHash = h256(0x04); EXPECT_CODE(w.check(t(q, w.owner, false)), "bad-protx-inputs-hash"); }
    EXPECT_CODE(w.check(t(p, w.collat)), "bad-protx-sig") << "signed by the collateral key, not the owner";
    EXPECT_CODE(w.check(t(p, w.owner), /*with_ecdsa=*/false), "bad-protx-sig");
    // The collateral coin is gone / unprovable.
    {
        World w2;
        w2.coins.clear();
        EXPECT_CODE(w2.check(upreg_tx(w2, upreg_payload(w2), w2.owner)), "bad-protx-collateral");
    }
    // v24: the new key is another masternode's under any scheme.
    {
        World w3;
        w3.rules.v24_active = true;
        MNState other = w3.sm.entries().at(w3.m);
        other.pubKeyOperator = w3.op2.pub;
        other.keyIDOwner = ec_key(0x13).id;
        other.collateralOutpoint.hash = h256(0x14);
        std::vector<std::pair<uint256, MNState>> all(w3.sm.entries().begin(), w3.sm.entries().end());
        all.push_back({h256(0x15), other});
        w3.sm.load(all, 2'500'000);
        EXPECT_CODE(w3.check(upreg_tx(w3, upreg_payload(w3), w3.owner)), "bad-protx-dup-key");
    }
    // v24 (VERIFY-S6 G1): a legacy -> basic migration without a key change
    // carries the STORED core service into the basic netInfo, which
    // re-validates it (SetStateVersion -> AddNetInfoEntries -> ValidateService).
    {
        World w5;
        w5.rules.v24_active = true;
        auto with_state = [&w5](const v::LegacyNetService& stored, bool legacy) {
            MNState st = w5.sm.entries().at(w5.m);
            st.nVersion = legacy ? v::ProTxVersion::LEGACY_BLS : v::ProTxVersion::BASIC_BLS;
            st.netInfo = stored;
            w5.sm.load({{w5.m, st}}, 2'500'000);
        };
        auto same_key = upreg_payload(w5);
        same_key.pubKeyOperator = w5.op.pub;
        with_state(ipv4(10, 0, 0, 1, 9999), /*legacy=*/true);
        EXPECT_CODE(w5.check(upreg_tx(w5, same_key, w5.owner)), "bad-protx-netinfo-addr-unroutable");
        with_state(ipv4(1, 2, 3, 4, 19999), true);
        EXPECT_CODE(w5.check(upreg_tx(w5, same_key, w5.owner)), "bad-protx-netinfo-port")
            << "mainnet port rule on the stored service";
        with_state(ipv4(1, 2, 3, 4, 9999), true);
        EXPECT_EQ(w5.check(upreg_tx(w5, same_key, w5.owner)), std::nullopt) << "a valid stored service";
        with_state(v::LegacyNetService{}, true);
        EXPECT_EQ(w5.check(upreg_tx(w5, same_key, w5.owner)), std::nullopt) << "empty: no entry to add";
        // A key change clears the stored addresses: nothing is re-validated.
        with_state(ipv4(10, 0, 0, 1, 9999), true);
        EXPECT_EQ(w5.check(upreg_tx(w5, upreg_payload(w5), w5.owner)), std::nullopt);
        // No migration (basic state), and before v24, nothing is re-validated.
        with_state(ipv4(10, 0, 0, 1, 9999), /*legacy=*/false);
        EXPECT_EQ(w5.check(upreg_tx(w5, same_key, w5.owner)), std::nullopt);
        with_state(ipv4(10, 0, 0, 1, 9999), true);
        w5.rules.v24_active = false;
        EXPECT_EQ(w5.check(upreg_tx(w5, same_key, w5.owner)), std::nullopt);
    }
}

// ── ProUpRevTx ──────────────────────────────────────────────────────────────

TEST(DashV24ProTxCheck, ProUpRevTxRules)
{
    World w;
    auto p = rev_payload(w);
    { auto q = p; q.nReason = 4; EXPECT_CODE(w.check(rev_tx(w, q, w.op.sk)), "bad-protx-reason"); }
    { auto q = p; q.proTxHash = h256(0x05); EXPECT_CODE(w.check(rev_tx(w, q, w.op.sk)), "bad-protx-hash"); }
    { auto q = p; q.inputsHash = h256(0x06); EXPECT_CODE(w.check(rev_tx(w, q, w.op.sk, false)), "bad-protx-inputs-hash"); }
    { auto q = p; q.nVersion = 3; EXPECT_CODE(w.check(rev_tx(w, q, w.op.sk)), "bad-protx-version"); }
    World w2;
    w2.rules.v24_active = true;
    auto q = rev_payload(w2);
    q.nVersion = 1;
    EXPECT_CODE(w2.check(rev_tx(w2, q, w2.op.sk)), "bad-protx-version-downgrade");
}

// ── wiring: the serving fold ────────────────────────────────────────────────

namespace {
v::CSimplifiedMNList sml_of(const World& w)
{
    v::CSimplifiedMNListEntry e;
    e.nVersion = v::CSimplifiedMNListEntry::VER_BASIC_BLS;
    e.proRegTxHash = w.m;
    e.confirmedHash = h256(0x77);
    const auto& st = w.sm.entries().at(w.m);
    e.netAddress = st.netInfo.ip;
    e.netPort = st.netInfo.port_be;
    e.pubKeyOperator = st.pubKeyOperator;
    e.keyIDVoting = st.keyIDVoting;
    e.isValid = true;
    return v::CSimplifiedMNList(std::vector<v::CSimplifiedMNListEntry>{e});
}
dash::coin::MnFoldContext serving_ctx(const World& w, bool wire_check = true)
{
    auto ctx = dash::coin::MnFoldContext::from(w.sm, {}, &v::verify_protx_operator_sig);
    ctx.require_core_check = true;
    if (wire_check)
        ctx.core_check = [&w](const MutableTransaction& tx) { return w.check(tx); };
    return ctx;
}
dash::coin::SmlSpecialFold fold(const World& w, std::vector<MutableTransaction> body,
                                const dash::coin::MnFoldContext& ctx)
{
    return dash::coin::fold_mn_special_txs(
        sml_of(w), body, [](const MutableTransaction& t) { return dash::coin::dash_txid(t); }, ctx);
}
} // namespace

TEST(DashV24ProTxCheck, ServingFoldAppliesValidRefusesInvalid)
{
    World w;
    const auto good = reg_internal(w).tx;
    auto bad = good;
    bad.vin[0].prevout.index = 9;   // inputsHash no longer matches
    const auto f = fold(w, {good, bad}, serving_ctx(w));
    EXPECT_EQ(f.applied, 1u);
    ASSERT_EQ(f.refused, 1u);
    EXPECT_EQ(f.refused_reasons[0].rfind("bad-protx-inputs-hash", 0), 0u) << f.refused_reasons[0];
    // Without a wired check, nothing rides (fail closed).
    const auto f2 = fold(w, {good}, serving_ctx(w, /*wire_check=*/false));
    EXPECT_EQ(f2.applied, 0u);
    EXPECT_EQ(f2.refused, 1u);
    // The plain context fold (no require) keeps its old behaviour.
    auto plain = dash::coin::MnFoldContext::from(w.sm, {}, &v::verify_protx_operator_sig);
    EXPECT_EQ(fold(w, {bad}, plain).applied, 1u);
}

TEST(DashV24ProTxCheck, ServiceUpdateAfterKeyChangeIsLeftOut)
{
    World w;
    const auto upreg = upreg_tx(w, upreg_payload(w), w.owner);   // rotates M's operator key
    const auto serv = serv_tx(w, serv_payload(w), w.op.sk);       // signed by the OLD key
    {
        const auto f = fold(w, {upreg, serv}, serving_ctx(w));
        EXPECT_EQ(f.applied, 1u);
        ASSERT_EQ(f.refused, 1u);
        EXPECT_EQ(f.refused_ids[0], dash::coin::dash_txid(serv));
        EXPECT_NE(f.refused_reasons[0].find("follows a key change"), std::string::npos) << f.refused_reasons[0];
    }
    {   // The service update first, then the key change: both are fine.
        const auto f = fold(w, {serv, upreg}, serving_ctx(w));
        EXPECT_EQ(f.applied, 2u);
        EXPECT_EQ(f.refused, 0u);
    }
    {   // A revocation is a key change too.
        const auto rev = rev_tx(w, rev_payload(w), w.op.sk);
        const auto f = fold(w, {rev, serv}, serving_ctx(w));
        EXPECT_EQ(f.applied, 1u);
        EXPECT_EQ(f.refused, 1u);
    }
}

TEST(DashV24ProTxCheck, BuilderCarriesAValidProRegTxAndFoldsIt)
{
    // The positive end-to-end case of embedded_gbt's
    // Type1FailingCoreChecksIsExcludedRootUnchanged: a ProRegTx passing every
    // check rides the template, and the committed root is the folded one.
    World w;
    ::core::coin::UTXOViewCache utxo(nullptr);
    dash::coin::Mempool mp;
    mp.set_utxo(&utxo);
    auto r = reg_internal(w);
    utxo.add_coin(::core::coin::Outpoint(h256(0xC0), 0),
                  ::core::coin::Coin(kColl + 10'000, {}, 1, false));
    ASSERT_TRUE(mp.add_tx(r.tx));
    const auto sml = sml_of(w);
    dash::coin::QuorumManager qmgr;
    dash::coin::ProTxCheckEnv env;
    env.net = dash::coin::DashNetwork::MAINNET;
    env.ecdsa = &dash::coin::protx_ecdsa_verify_hash;
    const uint32_t H = 2'500'001;
    const dash::coin::MnFoldContext::OperatorSigFn sigfn = &v::verify_protx_operator_sig;
    auto build = [&](const dash::coin::ProTxCheckEnv* e) {
        return dash::coin::build_embedded_workdata(
            H - 1, h256(0xAB), w.sm, mp, 0x1b104be3u, 1'800'000'000u, 76, 16, 1'800'000'100u, 0x20000000u,
            nullptr, &sml, &qmgr, 0, dash::coin::k_zero_cl_sig, 0, nullptr, nullptr,
            dash::coin::DASH_MN_RR_HEIGHT_MAINNET, nullptr, dash::coin::DASH_MN_MIN_CONFIRMATIONS_MAINNET,
            /*suppress=*/false, "utxo-immature-serving", nullptr, false, nullptr,
            /*include_mn_special_txs=*/true, nullptr, nullptr, &sigfn, /*v24_active=*/false, e);
    };
    auto rides = [&](const dash::coin::DashWorkData& wd) {
        for (const auto& h : wd.m_tx_hashes)
            if (h == dash::coin::dash_txid(r.tx)) return true;
        return false;
    };
    const auto with = build(&env);
    EXPECT_TRUE(rides(with)) << "a ProRegTx passing Dash Core's checks rides";
    v::CCbTx cb;
    ASSERT_TRUE(v::parse_cbtx(with.m_coinbase_payload, cb));
    auto proj = dash::coin::project_sml_confirmations(sml, H - 1, h256(0xAB), w.sm,
                                                      dash::coin::DASH_MN_MIN_CONFIRMATIONS_MAINNET);
    ASSERT_TRUE(proj.ok);
    const auto folded = dash::coin::fold_mn_special_txs(
        proj.sml, std::vector<MutableTransaction>{r.tx},
        [](const MutableTransaction& t) { return dash::coin::dash_txid(t); });
    EXPECT_EQ(cb.merkleRootMNList, folded.sml.CalcMerkleRoot());
    // Without the environment it does not ride.
    EXPECT_FALSE(rides(build(nullptr)));
}

// ── real testnet provider txs (LAN testnet dashd 24.0.0, VM504) ───────────────
// ProRegTx v2 99b70013... (height 1,576,258): external collateral 6793d701...:0,
// 1000 tDASH to yQPW... (76a9142ca5...), signed over MakeSignString by the
// collateral key. Its payout script equals the collateral script, which only
// version 3 forbids. ProUpServTx v2 417bd56e... (height 1,576,008) for
// masternode a356adb8..., whose state at 1,576,007 is version 2, Regular,
// operatorReward 0, operator key adad41e1... (protx info at that block).
namespace {
const char* kTnProRegTx99b7 =
    "03000100016ae16a091cdcd992423d02be4313e2044457df56faa4b373d3b3cbe9354064c9620000006a473044022064"
    "dcc8e37b766e7b00a066293354ce99162989e34981969507a911380e5cba0002201a7c10c6bee749b0ba0a3b324c1f12"
    "c0da39305add74f83b06b0067dbbaefd1c012102bbd242bd2e6dd55edcace54866730725155ec62eb9bb52da443d5934"
    "d91dbe9dfeffffff01dd590d00000000001976a914fc1052729c217f5f5017ca392f9c5e2ca0a740bd88ac00000000fd"
    "12010200000000008066c530b426e0d45824cdff0cc963a59c691238d0fb4ca16eeedc3f01d793670000000000000000"
    "000000000000ffff97f455604e1f400d33b0c9735c4ec53457758ed77a21455d4deb8762ab6cda7a38827e39e8dffcea"
    "30aea015ac78895cdf9a64c650f5ba71b36c25d29211bfee08619267d71971371d86400d33b0c9735c4ec53457758ed7"
    "7a21455d4deb00001976a9142ca51900528857bec830330acd9391a57e80496e88acce312fd401be207427b779b1803f"
    "552bedf3d20c9c1a35f03e791b0859292e1c411fc8204d3d16b4104a221d1bc6db3e3ea625c1902b9adfd8db267b9968"
    "cc8ac7774a4d6b5eb636a07007f1f38d2d10e223a7f39451f7186753eb964f03a3356377";
const char* kTnProUpServ417b =
    "030002000198fb3400615cae8817e6939361a85f64a0666c65c90901dc35f4f1cdfd411991000000006a47304402206d"
    "8041715089285d8d90eec24b296c9b42a6980ca6bd9b29adb74a5963ccb098022043eec9636a59ae625dc03b3fffc3f1"
    "2420b629c170b197ad8982a3f23d8ec904012102325e83cb1285c92eee0ab95a95e51ec81431bf8311384fbbb3bc2fd5"
    "ff63424afeffffff01c73d0f00000000001976a914dbe0812a19d7e3e8e168fd060e8680fc6a05d2f288ac00000000b7"
    "02000000b27541f9766ea980fa9df7c3b41808530509cdba5f2d52238628df32b8ad56a300000000000000000000ffff"
    "4e1146af4dbb00b98b7a1f56beef6fabe5a5838d7244a9f60d92efe60796c9d17ca09657c97d76ab1e9e3ee8f3730211"
    "7994b5156f2a19b4f4286bde8b1fa8d558174c8b81f3469d45a6561c44f38fa7d1b309a8042e8909bbcfc316865533a7"
    "4cd372cb85149e53847603deaf101b2c00cd8e029cf07aa2b4cd03d8d5e9af460be89744114ed0";

std::vector<uint8_t> unhex_tn(const std::string& text)
{
    std::string h;   // the replay fixtures embed line breaks
    for (char c : text)
        if (std::isxdigit(static_cast<unsigned char>(c))) h.push_back(c);
    std::vector<uint8_t> out;
    for (size_t i = 0; i + 1 < h.size(); i += 2)
        out.push_back(static_cast<uint8_t>(std::stoul(h.substr(i, 2), nullptr, 16)));
    return out;
}
MutableTransaction tx_from_hex(const char* hex)
{
    const auto raw = unhex_tn(hex);
    MutableTransaction tx;
    ::PackStream s(raw);
    s >> tx;
    EXPECT_TRUE(s.empty());
    return tx;
}
template <size_t N>
std::array<uint8_t, N> arr_hex(const std::string& h)
{
    std::array<uint8_t, N> a{};
    const auto v = unhex_tn(h);
    EXPECT_EQ(v.size(), N);
    std::copy_n(v.begin(), std::min(N, v.size()), a.begin());
    return a;
}
} // namespace

TEST(DashV24ProTxCheck, RealTestnetProRegTxPassesCoreChecks)
{
    const auto tx = tx_from_hex(kTnProRegTx99b7);
    uint256 want;
    want.SetHex("99b70013e2464247d122f0cecf73203f3480b4126fb0f9b14a32c6fc500a6d90");
    ASSERT_EQ(dash::coin::dash_txid(tx), want);
    MnStateMachine empty;
    ProTxCheckRules rules;
    rules.net = dash::coin::DashNetwork::TESTNET;
    uint256 coll;
    coll.SetHex("6793d7013fdcee6ea14cfbd03812699ca563c90cffcd2458d4e026b430c56680");
    const auto coll_script = unhex_tn("76a9142ca51900528857bec830330acd9391a57e80496e88ac");
    auto coin = [&](const Outpoint& o, int64_t& value, std::vector<uint8_t>& script) {
        if (o.hash != coll || o.index != 0) return ProTxCoinProof::Absent;
        value = kColl;
        script = coll_script;
        return ProTxCoinProof::Unspent;
    };
    EXPECT_EQ(protx_core_refusal(tx, empty, rules, coin, &dash::coin::protx_ecdsa_verify_hash), std::nullopt)
        << "MakeSignString, the message hash and the collateral key ID are Core's";
    // Mainnet rules reject its testnet port; a different collateral key fails the sig.
    ProTxCheckRules main_rules;
    EXPECT_CODE(protx_core_refusal(tx, empty, main_rules, coin, &dash::coin::protx_ecdsa_verify_hash),
                "bad-protx-netinfo-port");
    auto other = [&](const Outpoint& o, int64_t& value, std::vector<uint8_t>& script) {
        auto r = coin(o, value, script);
        script[5] ^= 0x01;
        return r;
    };
    EXPECT_CODE(protx_core_refusal(tx, empty, rules, other, &dash::coin::protx_ecdsa_verify_hash), "bad-protx-sig");
    // The same tx under v24 rules still passes (a version-2 registration).
    rules.v24_active = true;
    EXPECT_EQ(protx_core_refusal(tx, empty, rules, coin, &dash::coin::protx_ecdsa_verify_hash), std::nullopt);
}

TEST(DashV24ProTxCheck, RealTestnetProUpServTxPassesCoreChecksAndBlsSig)
{
    const auto tx = tx_from_hex(kTnProUpServ417b);
    uint256 want;
    want.SetHex("417bd56e8a28f17406a03110333c5af309d9579e328994a1189e1c39c0c74503");
    ASSERT_EQ(dash::coin::dash_txid(tx), want);
    uint256 mn;
    mn.SetHex("a356adb832df288623522d5fbacd0905530818b4c3f79dfa80a96e76f94175b2");
    MNState st;
    st.nVersion = v::ProTxVersion::BASIC_BLS;
    st.nType = v::MnType::REGULAR;
    st.nOperatorReward = 0;
    st.pubKeyOperator = arr_hex<48>(
        "adad41e17d64581f58fcbc8dff2845a9a10c2e57db782dc5fd41a175729e59048dc3fb82d9f0620eeaac3eacadced01a");
    MnStateMachine sm;
    sm.load({{mn, st}}, 1'576'007);
    ProTxCheckRules rules;
    rules.net = dash::coin::DashNetwork::TESTNET;
    EXPECT_EQ(protx_core_refusal(tx, sm, rules, {}, {}), std::nullopt);
    // The operator signature (verified by the template fold) is the real one.
    v::CProUpServTx p;
    ASSERT_TRUE(v::parse_protx_payload(tx.extra_payload, p));
    const auto h = v::protx_operator_sign_hash(tx.extra_payload);
    ASSERT_TRUE(h.has_value());
    EXPECT_TRUE(v::verify_protx_operator_sig(st.pubKeyOperator, false, *h, p.sig, false));
    // Re-wrapped with another input (P-2): the inputsHash no longer matches.
    auto rew = tx;
    rew.vin[0].prevout.index = 1;
    EXPECT_CODE(protx_core_refusal(rew, sm, rules, {}, {}), "bad-protx-inputs-hash");
}

// A LegacyBLS (version 1) ProUpServTx: tx 2842fdbf... at height 1,566,129 for
// masternode b9fab136..., whose state at 1,566,128 is version 1 with operator
// key 0fa5377e... (legacy encoding). Its signature is a canonical legacy-scheme
// encoding and verifies; the store keeps the key in the basic scheme.
namespace {
const char* kTnProUpServV1_2842 =
    "0300020001f8aa39a770f52916eb864aa73df680b46976cacf902304cd15dc46eb5b420379010000006a473044022049"
    "cb210b13de3c376dd91889de4626d107a95ab8c4eed7d14722396c9cb7910502200f585e5093d9851716c23b66679488"
    "24df078beb53d69dd6e810a0725a5e062b0121024cc4973b7f20a9282deb930af896892be43b2b462a30c98b9ff9f8a2"
    "622d88fefeffffff0181dff505000000001976a91454331ff5356c8a834bc40ec241aacfae8bf5c54e88ac00000000b5"
    "0100c1b4efa5fe55cfac7b9841af3161d7b27a208f29e5eecf6cd8059b1236b1fab900000000000000000000ffff4443"
    "7a424e1f00d59a174acdd68386a66de19f1a4e6885fc3731a91beda5d6498e715c1fbf97e510ebe74493508a93235862"
    "2513d3f187df3777566f27e58644bd4c525db8d8842a0ac219f829228f1af4349332676a60168e8b003446470a9c46cc"
    "33f00d0326866f815386fd013690f170647784a38b1591136b5630b9903d36d6607cb8ec2e";
} // namespace

TEST(DashV24ProTxCheck, RealTestnetLegacyProUpServTxPasses)
{
    const auto tx = tx_from_hex(kTnProUpServV1_2842);
    uint256 want;
    want.SetHex("2842fdbf516002bf6888283a56def5636e4dcc4caa4c1388da7083790e64d19c");
    ASSERT_EQ(dash::coin::dash_txid(tx), want);
    uint256 mn;
    mn.SetHex("b9fab136129b05d86ccfeee5298f207ab2d76131af41987baccf55fea5efb4c1");
    const auto legacy_key = arr_hex<48>(
        "0fa5377eb256323aace31b45c3e48ea110404b053cb80e8043bd1e44de1705130548e4ab28738816251ea57a7fc10324");
    MNState st;
    st.nVersion = v::ProTxVersion::LEGACY_BLS;
    st.nType = v::MnType::REGULAR;
    st.pubKeyOperator = v::opkey_to_basic(legacy_key, /*wire_legacy=*/true);
    MnStateMachine sm;
    sm.load({{mn, st}}, 1'566'128);
    ProTxCheckRules rules;
    rules.net = dash::coin::DashNetwork::TESTNET;
    EXPECT_EQ(protx_core_refusal(tx, sm, rules, {}, {}), std::nullopt);
    v::CProUpServTx p;
    ASSERT_TRUE(v::parse_protx_payload(tx.extra_payload, p));
    EXPECT_EQ(p.nVersion, 1);
    EXPECT_TRUE(v::blssig_parses_canonical(p.sig, /*legacy=*/true));
    const auto h = v::protx_operator_sign_hash(tx.extra_payload);
    ASSERT_TRUE(h.has_value());
    EXPECT_TRUE(v::verify_protx_operator_sig(legacy_key, true, *h, p.sig, true));
    // v24: a legacy payload for this (legacy) state is no downgrade.
    rules.v24_active = true;
    EXPECT_EQ(protx_core_refusal(tx, sm, rules, {}, {}), std::nullopt);
}

// ── byte identity where no provider tx is involved ──────────────────────────
// Real mainnet block bodies (dashd getblock <hash> 0 captures): the serving
// fold with the Core check wired applies nothing, refuses nothing and leaves
// the list root unchanged, no tx touches the shared-collateral template, and
// the core check passes every tx.
#include "data/dash_replay_block_2516412.inc"
#include "data/dash_replay_block_2516757.inc"
#include "data/dash_replay_block_2516758.inc"
#include "data/dash_replay_block_2516759.inc"
#include "data/dash_replay_block_2516760.inc"

TEST(DashV24ProTxCheck, MainnetBlocksWithoutProviderTxsAreUntouched)
{
    World w;
    const auto base = sml_of(w);
    const uint256 root = base.CalcMerkleRoot();
    size_t checked_blocks = 0;
    for (const char* hex : {kDashReplayBlock2516412, kDashReplayBlock2516757, kDashReplayBlock2516758,
                            kDashReplayBlock2516759, kDashReplayBlock2516760}) {
        const auto raw = unhex_tn(hex);
        dash::coin::BlockType blk;
        ::PackStream ps(raw);
        ps >> blk;
        ASSERT_TRUE(ps.empty());
        std::vector<MutableTransaction> body(blk.m_txs.begin() + 1, blk.m_txs.end());
        size_t provider = 0;
        for (const auto& tx : body) {
            if (tx.type >= 1 && tx.type <= 4) ++provider;
            EXPECT_EQ(w.check(tx), std::nullopt);
            for (const auto& o : tx.vout) EXPECT_FALSE(dash::coin::is_shared_collateral_script(o.scriptPubKey.m_data));
        }
        if (provider != 0) continue;
        const auto f = fold(w, body, serving_ctx(w));
        EXPECT_EQ(f.applied, 0u);
        EXPECT_EQ(f.refused, 0u);
        EXPECT_EQ(f.sml.CalcMerkleRoot(), root);
        ++checked_blocks;
    }
    EXPECT_GE(checked_blocks, 3u);
}

TEST(DashV24ProTxCheck, TemplateWithoutProviderTxsIsByteIdentical)
{
    // The same plain mempool, the special-tx superset on and off, with and
    // without the Core-check environment: identical templates.
    World w;
    ::core::coin::UTXOViewCache utxo(nullptr);
    dash::coin::Mempool mp;
    mp.set_utxo(&utxo);
    for (uint8_t i = 0; i < 5; ++i) {
        const uint256 prev = h256(static_cast<uint8_t>(0x30 + i));
        OPScript spk; spk.m_data = p2pkh(ec_key(static_cast<uint8_t>(0x40 + i)).id);
        utxo.add_coin(::core::coin::Outpoint(prev, 0), ::core::coin::Coin(1'000'000, spk, 1, false));
        MutableTransaction tx = tx_with_inputs(0, {{prev, 0}});
        tx.version = 2;
        bitcoin_family::coin::TxOut o;
        o.value = 990'000 - i;
        o.scriptPubKey.m_data = p2pkh(ec_key(static_cast<uint8_t>(0x50 + i)).id);
        tx.vout.push_back(o);
        ASSERT_TRUE(mp.add_tx(tx));
    }
    const auto sml = sml_of(w);
    dash::coin::QuorumManager qmgr;
    dash::coin::ProTxCheckEnv env;
    env.ecdsa = &dash::coin::protx_ecdsa_verify_hash;
    const dash::coin::MnFoldContext::OperatorSigFn sigfn = &v::verify_protx_operator_sig;
    auto build = [&](bool include, const dash::coin::ProTxCheckEnv* e) {
        return dash::coin::build_embedded_workdata(
            2'500'000, h256(0xAB), w.sm, mp, 0x1b104be3u, 1'800'000'000u, 76, 16, 1'800'000'100u, 0x20000000u,
            nullptr, &sml, &qmgr, 0, dash::coin::k_zero_cl_sig, 0, nullptr, nullptr,
            dash::coin::DASH_MN_RR_HEIGHT_MAINNET, nullptr, dash::coin::DASH_MN_MIN_CONFIRMATIONS_MAINNET,
            false, "utxo-immature-serving", nullptr, false, nullptr, include, nullptr, nullptr, &sigfn,
            false, e);
    };
    const auto off = build(false, nullptr);
    const auto on_env = build(true, &env);
    const auto on_none = build(true, nullptr);
    ASSERT_EQ(off.m_tx_hashes.size(), 5u);
    for (const auto* x : {&on_env, &on_none}) {
        EXPECT_EQ(x->m_tx_hashes, off.m_tx_hashes);
        EXPECT_EQ(x->m_tx_fees, off.m_tx_fees);
        EXPECT_EQ(x->m_coinbase_payload, off.m_coinbase_payload);
        EXPECT_EQ(x->m_coinbase_value, off.m_coinbase_value);
        EXPECT_EQ(x->m_payment_amount, off.m_payment_amount);
    }
}

#endif // C2POOL_DASH_BLS
