// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Every transaction type Dash Core v24.0.0's miner puts in a block, in the
// templates the embedded DASH node builds:
//
//   * type 7, MNHF signal: Dash Core's CheckMNHFTx and the miner's duplicate
//     rule (mnhf_check.hpp), against a REAL testnet signal (the v24 bit-13
//     signal mined at 1,565,132, quorum llmq_50_60 000000036fa2...);
//   * types 10-12 (ProDisTx, ProUpShareTx, ProUpSharedRegTx): Dash Core's
//     CheckProDisTx / CheckProUpShareTx / CheckProUpSharedRegTx
//     (protx_check.hpp) against a REAL testnet ProDisTx (1,583,318) and
//     codec-built txs signed with real secp256k1 / dashbls keys; the v24
//     template fold (sml_special_fold.hpp) whose merkleRootMNList must equal
//     the root the S3 block-connect path (the root-checked replay fold,
//     replay_fold_engine.hpp) computes for the same block;
//   * types 1-4 under v24: the template fold now runs the v24 transitions
//     (a revocation keeps a basic state's version).
//
// This TU rides test_dash_govvote_bls (the BLS-backend target).

#include <gtest/gtest.h>

#include <impl/dash/coin/embedded_gbt.hpp>
#include <impl/dash/coin/mempool.hpp>
#include <impl/dash/coin/mn_state_machine.hpp>
#include <impl/dash/coin/mnhf_check.hpp>
#include <impl/dash/coin/mnhf_node_env.hpp>
#include <impl/dash/coin/node_coin_state.hpp>
#include <impl/dash/coin/protx_check.hpp>
#include <impl/dash/coin/protx_ecdsa.hpp>
#include <impl/dash/coin/quorum_manager.hpp>
#include <impl/dash/coin/replay_fold_engine.hpp>
#include <impl/dash/coin/service_update_order.hpp>
#include <impl/dash/coin/sml_projection.hpp>
#include <impl/dash/coin/sml_special_fold.hpp>
#include <impl/dash/coin/v24_sml_leaf.hpp>
#include <impl/dash/coin/vendor/bls_verify.hpp>
#include <impl/dash/coin/vendor/cbtx.hpp>
#include <impl/dash/coin/vendor/mnhftx.hpp>
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
#include <functional>
#include <limits>
#include <map>
#include <optional>
#include <set>
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
using dash::coin::replay::DmlFoldEngine;
using dash::coin::replay::FoldConfig;
using dash::coin::replay::ReplayMNState;
using Outpoint = bitcoin_family::coin::TxPrevOut;

// ── keys and small builders ──────────────────────────────────────────────────

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

/// CKey::SignCompact: [27 + recid + 4 (compressed)] || r || s (low S).
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
v::CompactSignature compact(const std::vector<uint8_t>& s)
{
    v::CompactSignature c{};
    std::copy_n(s.begin(), c.size(), c.begin());
    return c;
}

/// The same signature with S replaced by n - S (and the recovery id flipped):
/// it recovers the same key, so only Core's low-S rule refuses it.
template <typename Sig>
Sig high_s(Sig sig)
{
    static constexpr uint8_t kN[32] = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
        0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
    };
    int borrow = 0;
    for (int i = 31; i >= 0; --i) {
        int d = int(kN[i]) - int(sig[33 + i]) - borrow;
        borrow = d < 0;
        sig[33 + i] = static_cast<uint8_t>(d + (borrow ? 256 : 0));
    }
    sig[0] = static_cast<uint8_t>(((sig[0] - 27) ^ 1) + 27);
    return sig;
}

std::vector<uint8_t> p2pkh(const uint160& id)
{
    std::vector<uint8_t> s = {0x76, 0xa9, 0x14};
    s.insert(s.end(), id.data(), id.data() + 20);
    s.push_back(0x88);
    s.push_back(0xac);
    return s;
}
OPScript script_of(std::vector<uint8_t> b)
{
    OPScript s;
    s.m_data = std::move(b);
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

v::ExtNetInfo core4(uint8_t a, uint8_t b, uint8_t c, uint8_t d, uint16_t port)
{
    v::ExtNetInfo e;
    e.set(v::NetInfoPurpose::CORE_P2P, {v::NetInfoEntry{v::NetService::ipv4(a, b, c, d, port)}});
    return e;
}

template <typename P>
std::vector<uint8_t> pack_payload(const P& p)
{
    auto ps = ::pack(p);
    auto sp = ps.get_span();
    return std::vector<uint8_t>(reinterpret_cast<const uint8_t*>(sp.data()),
                                reinterpret_cast<const uint8_t*>(sp.data()) + sp.size());
}

std::vector<uint8_t> unhex(const std::string& text)
{
    std::string h;
    for (char c : text)
        if (std::isxdigit(static_cast<unsigned char>(c))) h.push_back(c);
    std::vector<uint8_t> out;
    for (size_t i = 0; i + 1 < h.size(); i += 2)
        out.push_back(static_cast<uint8_t>(std::stoul(h.substr(i, 2), nullptr, 16)));
    return out;
}
template <size_t N>
std::array<uint8_t, N> arr_hex(const std::string& h)
{
    std::array<uint8_t, N> a{};
    const auto b = unhex(h);
    EXPECT_EQ(b.size(), N);
    std::copy_n(b.begin(), std::min(N, b.size()), a.begin());
    return a;
}
MutableTransaction tx_from_hex(const std::string& hex)
{
    const auto raw = unhex(hex);
    MutableTransaction tx;
    ::PackStream s(raw);
    s >> tx;
    EXPECT_TRUE(s.empty());
    return tx;
}
uint256 u256(const char* hex)
{
    uint256 h;
    h.SetHex(hex);
    return h;
}
uint160 u160_from_p2pkh(const std::string& script_hex)
{
    const auto s = unhex(script_hex);
    uint160 id;
    std::copy(s.begin() + 3, s.begin() + 23, id.data());
    return id;
}

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
bitcoin_family::coin::TxOut txout(int64_t value, std::vector<uint8_t> script)
{
    bitcoin_family::coin::TxOut o;
    o.value = value;
    o.scriptPubKey.m_data = std::move(script);
    return o;
}

::testing::AssertionResult HasCode(const std::optional<std::string>& r, const std::string& code)
{
    if (!r) return ::testing::AssertionFailure() << "expected " << code << ", got a pass";
    if (*r == code || r->rfind(code + " ", 0) == 0) return ::testing::AssertionSuccess();
    return ::testing::AssertionFailure() << "expected " << code << ", got " << *r;
}
#define EXPECT_CODE(expr, code) EXPECT_TRUE(HasCode((expr), (code)))

constexpr int64_t kCoin = 100'000'000LL;
constexpr int64_t kColl = 1000 * kCoin;

/// The same masternode as the replay fold holds it (the S3 block-connect
/// path), confirmed at `confirmed`.
ReplayMNState to_replay(const uint256& pro, const MNState& st, const uint256& confirmed)
{
    ReplayMNState r;
    r.nType = st.nType;
    r.collateralOutpoint = st.collateralOutpoint;
    r.nOperatorReward = st.nOperatorReward;
    r.nVersion = st.nVersion;
    r.nRegisteredHeight = static_cast<int32_t>(st.nRegisteredHeight);
    r.keyIDOwner = st.keyIDOwner;
    r.pubKeyOperator = st.pubKeyOperator;
    r.keyIDVoting = st.keyIDVoting;
    r.netInfo = st.netInfo;
    r.scriptPayout = st.scriptPayout;
    r.scriptOperatorPayout = st.scriptOperatorPayout;
    r.platformNodeID = st.platformNodeID;
    r.platformP2PPort = st.platformP2PPort;
    r.platformHTTPPort = st.platformHTTPPort;
    r.v24 = st.v24;
    if (!st.isValid) r.nPoSeBanHeight = static_cast<int32_t>(st.nPoSeBanHeight ? st.nPoSeBanHeight : 1);
    r.UpdateConfirmedHash(pro, confirmed);
    return r;
}

/// A DIP-3 coinbase carrying `root` as merkleRootMNList.
MutableTransaction coinbase(uint32_t height, const uint256& root)
{
    v::CCbTx cb;
    cb.nVersion = v::CCbTx::VERSION_MERKLE_ROOT_QUORUMS;
    cb.nHeight = static_cast<int32_t>(height);
    cb.merkleRootMNList = root;
    MutableTransaction tx;
    tx.version = 3;
    tx.type = 5;
    bitcoin_family::coin::TxIn in;
    in.prevout.hash.SetNull();
    in.prevout.index = 0xffffffff;
    in.sequence = 0xffffffff;
    tx.vin.push_back(in);
    tx.extra_payload = pack_payload(cb);
    return tx;
}

dash::coin::BlockType block_of(uint32_t height, const uint256& prev, const uint256& root,
                               const std::vector<MutableTransaction>& body)
{
    dash::coin::BlockType b;
    b.m_version = 536870912;
    b.m_previous_block = prev;
    b.m_timestamp = 1800000000 + height;
    b.m_bits = 0x1e0fffff;
    b.m_nonce = height;
    b.m_txs.push_back(coinbase(height, root));
    for (const auto& t : body) b.m_txs.push_back(t);
    return b;
}

// ── the world: a shared masternode S, a regular v2 masternode R ──────────────

struct V24World {
    static constexpr uint32_t H = 2'600'001;   // the block being built
    EcKey s0 = ec_key(0x31), s1 = ec_key(0x32);   // share owners
    EcKey svoting = ec_key(0x33);
    EcKey refund0 = ec_key(0x34), refund1 = ec_key(0x35);
    EcKey rowner = ec_key(0x36), rvoting = ec_key(0x37), rcollat = ec_key(0x38);
    BlsKey sop = bls_key(0x41), sop2 = bls_key(0x42), rop = bls_key(0x43), rop2 = bls_key(0x44);
    uint256 S = h256(0x10), R = h256(0x20);
    MNState shared, regular;
    MnStateMachine sm;
    std::map<std::pair<uint256, uint32_t>, std::pair<int64_t, std::vector<uint8_t>>> coins;

    V24World()
    {
        shared.nVersion = v::ProTxVersion::EXT_ADDR;
        shared.nType = v::MnType::REGULAR;
        shared.collateralOutpoint.hash = S;    // internal collateral
        shared.collateralOutpoint.index = 0;
        shared.pubKeyOperator = sop.pub;
        shared.keyIDVoting = svoting.id;
        shared.v24.extNetInfo = core4(1, 2, 3, 4, 9999);
        v::CCollateralShare a, b;
        a.amount = 600 * kCoin;
        a.scriptRefund = script_of(p2pkh(refund0.id));
        a.keyIDOwner = s0.id;
        b.amount = 400 * kCoin;
        b.scriptRefund = script_of(p2pkh(refund1.id));
        b.keyIDOwner = s1.id;
        shared.v24.shares = {a, b};
        shared.v24.nEarlyPeriodBlocks = 1000;
        shared.v24.nEarlyPenalty = 5 * kCoin;
        shared.nRegisteredHeight = H - 500;
        shared.isValid = true;

        regular.nVersion = v::ProTxVersion::BASIC_BLS;
        regular.nType = v::MnType::REGULAR;
        regular.collateralOutpoint.hash = h256(0x50);
        regular.collateralOutpoint.index = 1;
        regular.keyIDOwner = rowner.id;
        regular.keyIDVoting = rvoting.id;
        regular.pubKeyOperator = rop.pub;
        regular.netInfo = ipv4(5, 6, 7, 8, 9999);
        regular.scriptPayout = script_of(p2pkh(ec_key(0x39).id));
        regular.nRegisteredHeight = H - 900;
        regular.isValid = true;
        coins[{regular.collateralOutpoint.hash, 1}] = {kColl, p2pkh(rcollat.id)};
        reload();
    }
    void reload() { sm.load({{S, shared}, {R, regular}}, H - 1); }

    uint256 confirmed_of(const uint256& pro) const { return pro == S ? h256(0x60) : h256(0x61); }

    std::vector<std::pair<uint256, ReplayMNState>> replay_states() const
    {
        return {{S, to_replay(S, shared, confirmed_of(S))}, {R, to_replay(R, regular, confirmed_of(R))}};
    }
    /// The projected SML the template folds over: the replay states' leaves.
    v::CSimplifiedMNList base_sml() const
    {
        std::vector<v::CSimplifiedMNListEntry> leaves;
        for (const auto& [pro, st] : replay_states()) leaves.push_back(st.to_sml_entry(pro));
        v::CSimplifiedMNList l(std::move(leaves));
        l.sort();
        return l;
    }

    ProTxCheckRules rules(bool v24 = true) const
    {
        dash::coin::ProTxCheckEnv env;
        env.net = dash::coin::DashNetwork::MAINNET;
        return dash::coin::protx_rules_for(env, H, v24);
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
    std::optional<std::string> check(const MutableTransaction& tx, bool v24 = true) const
    {
        return protx_core_refusal(tx, sm, rules(v24), coin_fn(), &dash::coin::protx_ecdsa_verify_hash);
    }
    dash::coin::MnFoldContext ctx(bool v24 = true) const
    {
        auto c = dash::coin::MnFoldContext::from(sm, {}, &v::verify_protx_operator_sig);
        c.require_core_check = true;
        c.core_check = [this, v24](const MutableTransaction& tx) { return check(tx, v24); };
        c.v24_rules = v24;
        c.height = H;
        c.netinfo_rules = v::NetInfoRules::mainnet();
        return c;
    }
    dash::coin::SmlSpecialFold fold(const std::vector<MutableTransaction>& body, bool v24 = true) const
    {
        return dash::coin::fold_mn_special_txs(
            base_sml(), body, [](const MutableTransaction& t) { return dash::coin::dash_txid(t); }, ctx(v24));
    }
    /// The S3 block-connect path: the root-checked replay fold, seeded with
    /// the same pre-block list at H - 1. It folds the block only if its own
    /// list hashes to the committed root.
    dash::coin::replay::FoldResult connect(const std::vector<MutableTransaction>& body, const uint256& root,
                                           const std::function<void(const DmlFoldEngine&)>& inspect = {}) const
    {
        FoldConfig cfg;
        cfg.enabled = true;
        cfg.gates.dip0003_height = 1;
        cfg.gates.dip0003_enforcement_height = std::numeric_limits<int32_t>::max();   // no payee axis here
        cfg.gates.v19_height = 1;
        cfg.gates.mn_rr_height = 1;
        cfg.gates.v24_height = 1;
        DmlFoldEngine eng(cfg);
        eng.seed(replay_states(), 2, H - 1, h256(0x70));
        auto r = eng.fold_block(block_of(H, eng.block_hash(), root, body), H);
        if (inspect) inspect(eng);
        return r;
    }

    // ── the shared-masternode txs ──
    MutableTransaction share_tx(uint16_t index, const uint160& reward_key, const EcKey& signer,
                                uint8_t vin_tag = 0x80) const
    {
        MutableTransaction tx = tx_with_inputs(11, {{h256(vin_tag), 0}});
        v::CProUpShareTx p;
        p.proTxHash = S;
        p.shareIndex = index;
        p.scriptReward = script_of(p2pkh(reward_key));
        p.inputsHash = dash::coin::protx_check_detail::inputs_hash(tx);
        tx.extra_payload = pack_payload(p);
        const auto h = dash::coin::protx_check_detail::hash_without_trailing_vchsig(tx.extra_payload, 0);
        p.vchSig = sign_compact(signer, *h);
        tx.extra_payload = pack_payload(p);
        return tx;
    }
    MutableTransaction sharedreg_tx(const std::array<uint8_t, 48>& opkey, const uint160& voting,
                                    std::vector<const EcKey*> signers, uint8_t vin_tag = 0x81) const
    {
        MutableTransaction tx = tx_with_inputs(12, {{h256(vin_tag), 0}});
        v::CProUpSharedRegTx p;
        p.proTxHash = S;
        p.pubKeyOperator = opkey;
        p.keyIDVoting = voting;
        p.inputsHash = dash::coin::protx_check_detail::inputs_hash(tx);
        const auto h = dash::coin::protx_check_detail::hash_without_trailing_sig_list(pack_payload(p), 0);
        for (const EcKey* k : signers) p.vchSigs.push_back(compact(sign_compact(*k, *h)));
        tx.extra_payload = pack_payload(p);
        return tx;
    }
    /// Unanimous dissolution: share 1's refund, then the actor's (share 0).
    MutableTransaction dissolve_tx(int64_t fee = 1000, bool unanimous = true) const
    {
        MutableTransaction tx = tx_with_inputs(10, {{S, 0}});
        tx.vout.push_back(txout(400 * kCoin, p2pkh(refund1.id)));
        tx.vout.push_back(txout(600 * kCoin - fee, p2pkh(refund0.id)));
        v::CProDisTx p;
        p.proTxHash = S;
        p.actorIndex = 0;
        const uint8_t n = unanimous ? 2 : 1;
        const uint256 h = dash::coin::protx_check_detail::prodis_sign_hash(tx, p, n);
        p.vchSigs.push_back(compact(sign_compact(s0, h)));
        if (unanimous) p.vchSigs.push_back(compact(sign_compact(s1, h)));
        tx.extra_payload = pack_payload(p);
        return tx;
    }
    /// ProUpRegTx for R (owner-signed), rotating its operator key.
    MutableTransaction upreg_r(const std::array<uint8_t, 48>& opkey) const
    {
        MutableTransaction tx = tx_with_inputs(3, {{h256(0x82), 0}});
        v::CProUpRegTx p;
        p.nVersion = v::ProTxVersion::BASIC_BLS;
        p.proTxHash = R;
        p.pubKeyOperator = opkey;
        p.keyIDVoting = rvoting.id;
        p.scriptPayout = regular.scriptPayout;
        p.inputsHash = dash::coin::protx_check_detail::inputs_hash(tx);
        tx.extra_payload = pack_payload(p);
        const auto h = dash::coin::protx_check_detail::hash_without_trailing_vchsig(tx.extra_payload, 0);
        p.vchSig = sign_compact(rowner, *h);
        tx.extra_payload = pack_payload(p);
        return tx;
    }
    /// ProUpRevTx v2 for R, signed by its operator.
    MutableTransaction rev_r() const
    {
        MutableTransaction tx = tx_with_inputs(4, {{h256(0x83), 1}});
        v::CProUpRevTx p;
        p.nVersion = v::ProTxVersion::BASIC_BLS;
        p.proTxHash = R;
        p.nReason = v::CProUpRevTx::REASON_TERMINATION_OF_SERVICE;
        p.inputsHash = dash::coin::protx_check_detail::inputs_hash(tx);
        p.sig = {};
        const auto h = v::protx_operator_sign_hash(pack_payload(p));
        p.sig = bls::BasicSchemeMPL().Sign(rop.sk, bls::Bytes(h->data(), 32)).SerializeToArray(false);
        tx.extra_payload = pack_payload(p);
        return tx;
    }
};

uint256 txid(const MutableTransaction& t) { return dash::coin::dash_txid(t); }

// ── real testnet fixtures (LAN testnet dashd 24.0.0) ────────────────────────
// MNHF signal 46a47fe6... mined at 1,565,132: v24 (bit 13), quorum
// 000000036fa2... (llmq_50_60, height 1,565,112), quorumPublicKey a1620ca2...
const char* kTnMnhf =
    "0300070000000000000082010dfab03beecae3ec79691a966f8a37a836dab21a409f1ee39bfe98a26f03000000a3520c90ae1a"
    "3aa2b750be245cb9eaa1c4be78f0ee43f46b56a0d319cae9e76a87c5ce23d93e24b7484b93288bdbc7e70610d04c7d9ba4f30dc3"
    "b71b58baf6436752ffbace4c79da3e4d6de87646610a8cff9001b51d768c4b6d8a4ddda6f01c";
const char* kTnMnhfQuorum = "000000036fa298fe9be31e9f401ab2da36a8378a6f961a6979ece3caee3bb0fa";
const char* kTnMnhfQuorumKey =
    "a1620ca2f42b36c8ef6c248f22153b0a68589c969841971f2e46208c562b8d9c1882efecac7ca6848ee2810497ee9732";

// ProDisTx 1,583,318 dissolving shared masternode 8699ef5a... (registered at
// 1,583,312: 600 + 400 tDASH shares, early period 52,560 blocks, penalty
// 5 tDASH), unanimous, actor 0. State from `protx info` at 1,583,317.
const char* kTnProDis =
    "03000a0001405fa63b6380023e9f88c6846c2fce8a4675484fdb70f1027b1f14fd5aef99860200000000ffffffff0200902f50"
    "090000001976a9149b46ddc488343060485292c1ef17c92fbe0462c188ac60d145f80d0000001976a914370f5835c82007e823"
    "39b42ccfd7767ae6220ad288ac00000000a70100405fa63b6380023e9f88c6846c2fce8a4675484fdb70f1027b1f14fd5aef99"
    "86000002207468f204e6e698fca4766f4229e595b979c5ac866c7fb772c8cd6c554289fea420ed8884f4258faa78e83ada5d03"
    "1d764b1c1827b28389b54feedc1f13f982f21faadc59d99905d22389096db2a12ec24e75148383f004a86350c7553b1c0edb115"
    "a3912a51f6ad8ac23202b585d9ddb65653022c0e4a5cc1a00e4d719f78e5bba";
const char* kTnSharedPro = "8699ef5afd141f7b02f170db4f4875468ace2f6c84c6889f3e0280633ba65f40";

MNState tn_shared_state()
{
    MNState st;
    st.nVersion = v::ProTxVersion::EXT_ADDR;
    st.nType = v::MnType::REGULAR;
    st.collateralOutpoint.hash = u256(kTnSharedPro);
    st.collateralOutpoint.index = 2;
    st.nOperatorReward = 4;
    st.nRegisteredHeight = 1'583'312;
    st.nPoSeBanHeight = 1'583'312;   // registered with no address: banned
    st.isValid = false;
    st.keyIDVoting = u160_from_p2pkh("76a9148217be2c828470a8d4d5ebbb7435a8f47c16106f88ac");
    st.pubKeyOperator = arr_hex<48>(
        "940c2f91e087567fa1ca3eb22a52ac374a0fc32f103e4bb31a8b1aaf3daf60085968adb4e0cf64033a8d0645393c97cc");
    v::CCollateralShare a, b;
    a.amount = 60'000'000'000LL;
    a.scriptRefund = script_of(unhex("76a914370f5835c82007e82339b42ccfd7767ae6220ad288ac"));
    a.keyIDOwner = u160_from_p2pkh("76a9145c122f49bca30a387c8b851642482eb247ddca3788ac");
    b.amount = 40'000'000'000LL;
    b.scriptRefund = script_of(unhex("76a9149b46ddc488343060485292c1ef17c92fbe0462c188ac"));
    b.keyIDOwner = u160_from_p2pkh("76a9145043a17f22496a934848fe6d93c679c3c85fc0dc88ac");
    st.v24.shares = {a, b};
    st.v24.nEarlyPeriodBlocks = 52'560;
    st.v24.nEarlyPenalty = 500'000'000;
    return st;
}

// ProUpRevTx v3 1,578,068 (eight blocks after testnet v24 activation)
// revoking EvoNode 044d20aa..., whose state at 1,578,067 is version 2 (protx
// info): Core v24 keeps max(2, 3) = 3, so the revoked state is version 3
// with an empty ExtNetInfo, a null operator key, platformNodeID cleared and
// the payout script migrated into the payout list (protx info at 1,578,068).
const char* kTnRevV3 =
    "03000400015e1fc0bfae7beed6df5a36b7c21d8984202ecd22763a9e475c14e4c3aa204d04000000006a47304402203c0e4d07c2"
    "74180ed64b71ff03ca7ee465d55fcc5bec2cd063554c1b76bdcbee02205097f29c81a4dc764bd003c3fab56911f4feb2fc5a6cd4"
    "96b16e04f18dd8107a01210368037eedf9974ae19dbf7afad02f781ebf59b6e1ab07e9d27375604e0ae55e70feffffff0195f10d"
    "00000000001976a9140f85adbdfdf6f484f433e3c756430b85297a97ab88ac00000000a403005e1fc0bfae7beed6df5a36b7c21d"
    "8984202ecd22763a9e475c14e4c3aa204d04010036f1ba69a89f35bdec658106cd8d11e58ae48c2d1274f2c6ba14a343ddf828a7"
    "978ee11937eb3534414217b54301ac823fda0964f8ba67ab1c3a7171271c184226673a8cadef01ee7dc1bad302d5008c0a771abe"
    "16417a6077d0615118f4e4471ada150fe4fd4cc464cbf7c3f58b13b06a921e1199cbbe61adfe097f1c8447be";
const char* kTnRevPro = "044d20aac3e4145c479e3a7622cd2e2084891dc2b7365adfd6ee7baebfc01f5e";

MNState tn_evo_state()
{
    MNState st;
    st.nVersion = v::ProTxVersion::BASIC_BLS;
    st.nType = v::MnType::EVO;
    st.collateralOutpoint.hash = u256("3f59630f28d5e1e5d1d40c64558d860a0821ca11840be5fdfad512e56ee22a37");
    st.collateralOutpoint.index = 1;
    st.nOperatorReward = 0;
    st.nRegisteredHeight = 1'576'918;
    st.isValid = true;
    st.keyIDOwner = u160_from_p2pkh("76a9142f4994deef0702c2c368301f92e11d0bcaec5daf88ac");
    st.keyIDVoting = u160_from_p2pkh("76a9143755a14e2aab8750b9f853e0b9b07fd15a38c97488ac");
    st.pubKeyOperator = arr_hex<48>(
        "b03a69e21639859a0448d9ad97ee33d9c7807adc1aba1791c759b87aa81b99d79c19ba8778cdda6533ce9f0534a8392f");
    st.netInfo = ipv4(85, 209, 243, 10, 19999);
    st.platformNodeID.SetHex("e3c638c489d26fbfc76eabe40448551c47474f0f");
    st.platformP2PPort = 36656;
    st.platformHTTPPort = 1443;
    st.scriptPayout = script_of(unhex("76a914cd6bf562acba01f16fd0bd5ace0730faf18ac05a88ac"));
    return st;
}

// ProUpServTx v3 1,579,049 of Regular masternode a356adb8... (state at
// 1,579,048: version 2, banned) and ProUpServTx v3 1,578,496 of EvoNode
// 763ca29f... (version 2, banned, Platform ports): Core raises both to
// version 3 with the payload's ExtNetInfo, migrates the payout script into
// the payout list and revives them (protx info at the next block).
const char* kTnServA356 =
    "03000200018e8b4dea67509df4c39c4697f6bfb8e68bbb460d3d8b32c9cab16543a82fd720000000006a4730440220349f96398d"
    "556fbaec3ed9e0b37eb0a6a202bcbf012354034062b11d503bca7402205e6ff7820151321953ceffb95256cd4086b75328e5b5c1"
    "90f3fd42683de5d13f012102325e83cb1285c92eee0ab95a95e51ec81431bf8311384fbbb3bc2fd5ff63424afeffffff014aa10e"
    "00000000001976a914dbe0812a19d7e3e8e168fd060e8680fc6a05d2f288ac00000000b203000000b27541f9766ea980fa9df7c3"
    "b41808530509cdba5f2d52238628df32b8ad56a3010100010101044e1146af4dbb0098b86264de16a59ad62d848a7e953c5a6a68"
    "a523e4d1eadbd68a42745ab60dcfa0e0459b98edb459d9431da6e8f84b7eefa4ee6736d97f2ff0708f3d0800b036ad27cdab33bb"
    "031762a9fb09a433d68b13d713d8f0e0f0a046bdeba3831c8228c549614374d5bc78ffd74973b923e3848883a5feee3f4ced04d6"
    "0471ea207b7f";
const char* kTnServA356Pro = "a356adb832df288623522d5fbacd0905530818b4c3f79dfa80a96e76f94175b2";
const char* kTnServEvo =
    "0300020001164941f480ccf7c14794cd957f724ceae4ef7f0fb0b18a7fb9814abf6285e3c6000000006a47304402205e379d1294"
    "5f77970d713bf7169fa1527216f0982ad4c0a05fea1e9a012b7b5502204dd4971f7ffe6e5c3d3ba95c63c24e00b090237f17f598"
    "8cc1b2a1d3585d54eb01210216a3c19bb2333bc4c3addaa1f1118c42fd060d3e47fe6fd4932b437363f54f2cfeffffff015eea0e"
    "00000000001976a914000888b285fe4aba88b8bed38e9ce5a4a856ad2488ac00000000dc03000100800b5c82dde5ef1694b17d0a"
    "93dfd03ca8a49c1c31512457e78396f79fa23c7601030001010104a223f3554e1d0101010104a223f3558f300201010104a223f3"
    "5505a300e1e72e7b664391a00b68f6dfc6a9e20ee49cdb3f353c360e94027e74c21e25dfc92e0ebc2cf6df05de73b3a9821e9c59"
    "0420d033997ab3a46cdcaf52d48e9eb601e05430f11f678d04678dc0790fdb8702d7ddf8834c786178264e6e90d07df8e3bbddc3"
    "1212a0eb020103e35c60edce0aeeb8bb214a05fad022df5dd267d280043a8ef02810d0a9267a95aae2df21a3a754b056";
const char* kTnServEvoPro = "763ca29ff79683e7572451311c9ca4a83cd0df930a7db19416efe5dd825c0b80";

MNState tn_a356_state()
{
    MNState st;
    st.nVersion = v::ProTxVersion::BASIC_BLS;
    st.nType = v::MnType::REGULAR;
    st.collateralOutpoint.hash = u256("5c20c6b1cde0dc0517d799a482edf51359662cc2f06e120739e08ccefa233beb");
    st.collateralOutpoint.index = 0;
    st.nRegisteredHeight = 1'573'098;
    st.nPoSeBanHeight = 1'578'755;
    st.isValid = false;
    st.keyIDOwner = u160_from_p2pkh("76a914441af17f3a9019dcc1a9052ec9f04d35229c27e088ac");
    st.keyIDVoting = u160_from_p2pkh("76a91456ae25b378bfedb83c9ec80d560df5ca475f898488ac");
    st.pubKeyOperator = arr_hex<48>(
        "adad41e17d64581f58fcbc8dff2845a9a10c2e57db782dc5fd41a175729e59048dc3fb82d9f0620eeaac3eacadced01a");
    st.netInfo = ipv4(78, 17, 70, 175, 19899);
    st.scriptPayout = script_of(unhex("76a9140dcd5182b7ec23f747af4113adf39404934f7b8788ac"));
    return st;
}
MNState tn_evo763c_state()
{
    MNState st;
    st.nVersion = v::ProTxVersion::BASIC_BLS;
    st.nType = v::MnType::EVO;
    st.collateralOutpoint.hash = u256(kTnServEvoPro);
    st.collateralOutpoint.index = 1;
    st.nRegisteredHeight = 1'545'893;
    st.nPoSeBanHeight = 1'573'164;
    st.isValid = false;
    st.keyIDOwner = u160_from_p2pkh("76a914d2f68ed8684606fe777711f469fa91d1be8a040e88ac");
    st.keyIDVoting = u160_from_p2pkh("76a9146fc8eacf785fce62cb493c3ce335a12ff0596ff188ac");
    st.pubKeyOperator = arr_hex<48>(
        "ad99da4a07542b221fa6f2335ab2a1071cad6f2dbae230fe82a619b07d039b6270632272ea7269dc5c8241eef139f57c");
    st.netInfo = ipv4(162, 35, 243, 85, 19997);
    st.platformNodeID.SetHex("33d02004599c1e82a9b373de05dff62cbc0e2ec9");
    st.platformP2PPort = 36656;
    st.platformHTTPPort = 1443;
    st.scriptPayout = script_of(unhex("76a91418d05f474a776383ac3aebbfb978ae29da144ed088ac"));
    return st;
}

/// Fold one real testnet provider tx over a list holding only `pro` (its
/// state at `height - 1`), with Core's checks for that height, and connect
/// the same block through the replay fold on testnet gates.
struct RealFold {
    dash::coin::SmlSpecialFold fold;
    v::CSimplifiedMNList base;
    dash::coin::replay::FoldResult connect;
    std::optional<std::string> core_check;
};
RealFold real_fold(const uint256& pro, const MNState& pre, const MutableTransaction& tx, uint32_t height,
                   const std::function<void(const DmlFoldEngine&)>& inspect = {})
{
    RealFold out;
    MnStateMachine sm;
    sm.load({{pro, pre}}, height - 1);
    const std::vector<std::pair<uint256, ReplayMNState>> states = {{pro, to_replay(pro, pre, h256(0x63))}};
    out.base = v::CSimplifiedMNList(std::vector<v::CSimplifiedMNListEntry>{states[0].second.to_sml_entry(pro)});
    dash::coin::ProTxCheckEnv env;
    env.net = dash::coin::DashNetwork::TESTNET;
    const auto rules = dash::coin::protx_rules_for(env, height, true);
    const auto check = [&sm, rules](const MutableTransaction& t) {
        return protx_core_refusal(t, sm, rules, {}, &dash::coin::protx_ecdsa_verify_hash);
    };
    out.core_check = check(tx);
    auto ctx = dash::coin::MnFoldContext::from(sm, {}, &v::verify_protx_operator_sig);
    ctx.require_core_check = true;
    ctx.core_check = check;
    ctx.v24_rules = true;
    ctx.height = height;
    ctx.netinfo_rules = v::NetInfoRules::testnet();
    out.fold = dash::coin::fold_mn_special_txs(out.base, std::vector<MutableTransaction>{tx}, &txid, ctx);
    FoldConfig cfg;
    cfg.enabled = true;
    cfg.gates = dash::coin::replay::FoldGates::testnet();
    cfg.gates.dip0003_enforcement_height = std::numeric_limits<int32_t>::max();
    DmlFoldEngine eng(cfg);
    eng.seed(states, 1, height - 1, h256(0x70), "testnet");
    out.connect = eng.fold_block(block_of(height, eng.block_hash(), out.fold.sml.CalcMerkleRoot(), {tx}), height);
    if (inspect) inspect(eng);
    return out;
}

dash::coin::MnhfCheckEnv tn_mnhf_env(std::optional<bool> staged = false)
{
    dash::coin::MnhfCheckEnv env;
    env.net = dash::coin::DashNetwork::TESTNET;
    env.chain_height_of = [](const uint256& h, uint32_t prev) -> std::optional<uint32_t> {
        if (h == u256(kTnMnhfQuorum) && prev >= 1'565'112) return 1'565'112u;
        return std::nullopt;
    };
    env.quorum_public_key = [](uint8_t type, const uint256& q) -> std::optional<std::array<uint8_t, 48>> {
        if (type == 1 && q == u256(kTnMnhfQuorum)) return arr_hex<48>(kTnMnhfQuorumKey);
        return std::nullopt;
    };
    env.verify_sig = [](const std::array<uint8_t, 48>& pk, const uint256& h, const std::array<uint8_t, 96>& sig) {
        return v::verify_chainlock_sig(pk, h, sig);
    };
    env.bit_staged = [staged](uint8_t, uint32_t) { return staged; };
    return env;
}
constexpr uint32_t kTnMnhfPrev = 1'565'131;
constexpr int64_t  kTnMnhfMtp  = 1'790'987'000;   // after the v24 start time (1,790,208,000)

MutableTransaction with_payload(MutableTransaction tx, const v::MNHFTxPayload& p)
{
    tx.extra_payload = pack_payload(p);
    return tx;
}
v::MNHFTxPayload mnhf_payload_of(const MutableTransaction& tx)
{
    v::MNHFTxPayload p;
    EXPECT_TRUE(v::parse_mnhf_payload(tx.extra_payload, p));
    return p;
}

} // namespace

// ════════════════════════════════════════════════════════════════════════════
// TYPE 7: MNHF SIGNAL
// ════════════════════════════════════════════════════════════════════════════

TEST(DashV24AllTx, RealTestnetMnhfSignalPassesCheckMnhfTx)
{
    const auto tx = tx_from_hex(kTnMnhf);
    ASSERT_EQ(txid(tx), u256("46a47fe65c9fd29e9379f3f74020df33dabb1d4095c8da6b1fa05e508b74a491"));
    const auto env = tn_mnhf_env();
    EXPECT_EQ(dash::coin::mnhf_tx_refusal(tx, &env, kTnMnhfPrev, kTnMnhfMtp), std::nullopt)
        << *dash::coin::mnhf_tx_refusal(tx, &env, kTnMnhfPrev, kTnMnhfMtp);
    // The signed hash is the txid with the signature zeroed, the request id
    // SerializeHash("mnhf", int64 13): a real quorum signature verifies only
    // if both are Core's.
    const auto p = mnhf_payload_of(tx);
    EXPECT_EQ(p.signal.versionBit, 13);
    EXPECT_TRUE(v::verify_chainlock_sig(
        arr_hex<48>(kTnMnhfQuorumKey),
        dash::coin::mnhf_sign_hash(1, p.signal.quorumHash, dash::coin::mnhf_request_id(13),
                                   dash::coin::mnhf_msg_hash(tx, p)),
        p.signal.sig));
}

TEST(DashV24AllTx, MnhfSignalRefusalsAreCoresCodes)
{
    const auto tx = tx_from_hex(kTnMnhf);
    const auto env = tn_mnhf_env();
    auto refusal = [&](const MutableTransaction& t, const dash::coin::MnhfCheckEnv* e = nullptr) {
        return dash::coin::mnhf_tx_refusal(t, e ? e : &env, kTnMnhfPrev, kTnMnhfMtp);
    };
    {   // a flipped signature byte
        auto p = mnhf_payload_of(tx);
        p.signal.sig[5] ^= 0x01;
        EXPECT_CODE(refusal(with_payload(tx, p)), "bad-mnhf-invalid");
    }
    {   // a valid signature over another bit is not a signature over this one
        auto p = mnhf_payload_of(tx);
        p.signal.versionBit = 14;
        EXPECT_CODE(refusal(with_payload(tx, p)), "bad-mnhf-invalid");
    }
    {
        auto p = mnhf_payload_of(tx);
        p.nVersion = 2;
        EXPECT_CODE(refusal(with_payload(tx, p)), "bad-mnhf-version");
        p.nVersion = 1;
        p.signal.versionBit = 29;
        EXPECT_CODE(refusal(with_payload(tx, p)), "bad-mnhf-nbit-out-of-bounds");
        p.signal.versionBit = 28;   // TESTDUMMY: not an EHF deployment
        EXPECT_CODE(refusal(with_payload(tx, p)), "bad-mnhf-non-ehf");
    }
    {   // a truncated payload; a non-special version
        auto t = tx;
        t.extra_payload.pop_back();
        EXPECT_CODE(refusal(t), "bad-mnhf-payload");
        t = tx;
        t.version = 2;
        EXPECT_CODE(refusal(t), "bad-mnhf-type");
    }
    {   // the quorum block is not on our chain at or below the parent
        EXPECT_CODE(dash::coin::mnhf_tx_refusal(tx, &env, 1'565'100, kTnMnhfMtp), "bad-mnhf-quorum-hash");
        auto e = env;
        e.chain_height_of = [](const uint256&, uint32_t) { return std::optional<uint32_t>{}; };
        EXPECT_CODE(refusal(tx, &e), "bad-mnhf-quorum-hash");
    }
    {   // a quorum we do not hold
        auto e = env;
        e.quorum_public_key = [](uint8_t, const uint256&) { return std::optional<std::array<uint8_t, 48>>{}; };
        EXPECT_CODE(refusal(tx, &e), "bad-mnhf-missing-quorum");
    }
    {   // already staged (a second signal for a mined bit): Core's ProcessBlock
        const auto e = tn_mnhf_env(true);
        EXPECT_CODE(refusal(tx, &e), "bad-mnhf-duplicate");
    }
    {   // fail closed: no environment, no staged-signal knowledge
        EXPECT_TRUE(dash::coin::mnhf_tx_refusal(tx, nullptr, kTnMnhfPrev, kTnMnhfMtp).has_value());
        const auto e = tn_mnhf_env(std::nullopt);
        EXPECT_TRUE(refusal(tx, &e).has_value());
        auto e2 = env;
        e2.verify_sig = {};
        EXPECT_TRUE(refusal(tx, &e2).has_value());
    }
    // A non-MNHF tx passes untouched.
    EXPECT_EQ(refusal(tx_with_inputs(0, {{h256(1), 0}})), std::nullopt);
}

TEST(DashV24AllTx, MnhfActivationRuleIsTimeIndependentForTheV24Table)
{
    const auto& p = dash::coin::dash_deployment_params(dash::coin::DashNetwork::MAINNET);
    for (int64_t t : {int64_t{0}, int64_t{1794182399}, int64_t{1794182400}, int64_t{1857340800},
                      int64_t{1857340801}, std::numeric_limits<int64_t>::max() - 1}) {
        EXPECT_TRUE(dash::coin::mnhf_is_valid_activation(p, 13, t));
        EXPECT_TRUE(dash::coin::mnhf_is_valid_activation(p, 14, t));
        EXPECT_TRUE(dash::coin::mnhf_is_valid_activation(p, 7, t));     // unknown bit: valid in Core
        EXPECT_FALSE(dash::coin::mnhf_is_valid_activation(p, 28, t));   // TESTDUMMY, never EHF
    }
    EXPECT_TRUE(dash::coin::mnhf_is_valid_activation_from(p, 13, 0));
    EXPECT_FALSE(dash::coin::mnhf_is_valid_activation_from(p, 28, 0));
}

TEST(DashV24AllTx, MnhfDuplicateInOneBlockKeepsTheFirst)
{
    const auto tx = tx_from_hex(kTnMnhf);
    const auto env = tn_mnhf_env();
    auto other = tx;
    other.locktime = 1;   // another tx for the same bit (its signature no longer verifies)
    const auto why = dash::coin::mnhf_select({tx, tx_with_inputs(0, {{h256(1), 0}}), tx}, &env, kTnMnhfPrev,
                                             kTnMnhfMtp);
    ASSERT_EQ(why.size(), 3u);
    EXPECT_TRUE(why[0].empty()) << why[0];
    EXPECT_TRUE(why[1].empty());
    EXPECT_EQ(why[2].rfind("bad-mnhf-duplicates-in-block", 0), 0u) << why[2];
    const auto why2 = dash::coin::mnhf_select({other, tx}, &env, kTnMnhfPrev, kTnMnhfMtp);
    EXPECT_FALSE(why2[0].empty());
    EXPECT_TRUE(why2[1].empty()) << why2[1];
}

TEST(DashV24AllTx, BuilderCarriesAValidMnhfSignalFirstAndLeavesTheRootAlone)
{
    V24World w;
    ::core::coin::UTXOViewCache utxo(nullptr);
    dash::coin::Mempool mp;
    mp.set_utxo(&utxo);
    const auto sig = tx_from_hex(kTnMnhf);
    ASSERT_TRUE(mp.add_tx(sig));
    // An ordinary fee-paying tx alongside.
    auto plain = tx_with_inputs(0, {{h256(0x90), 0}});
    plain.vout.push_back(txout(5 * kCoin, p2pkh(ec_key(0x91).id)));
    utxo.add_coin(::core::coin::Outpoint(h256(0x90), 0), ::core::coin::Coin(5 * kCoin + 10'000, {}, 1, false));
    ASSERT_TRUE(mp.add_tx(plain));
    const auto sml = w.base_sml();
    dash::coin::QuorumManager qmgr;
    const auto env = tn_mnhf_env();
    dash::coin::ProTxCheckEnv penv;
    penv.net = dash::coin::DashNetwork::MAINNET;
    penv.ecdsa = &dash::coin::protx_ecdsa_verify_hash;
    const dash::coin::MnFoldContext::OperatorSigFn sigfn = &v::verify_protx_operator_sig;
    auto build = [&](bool lever, const dash::coin::MnhfCheckEnv* e) {
        return dash::coin::build_embedded_workdata(
            kTnMnhfPrev, h256(0xAB), w.sm, mp, 0x1b104be3u, static_cast<uint32_t>(kTnMnhfMtp), 140, 19,
            static_cast<uint32_t>(kTnMnhfMtp + 100), 0x20000000u, nullptr, &sml, &qmgr, 0,
            dash::coin::k_zero_cl_sig, 0, nullptr, nullptr, dash::coin::DASH_MN_RR_HEIGHT_MAINNET, nullptr,
            dash::coin::DASH_MN_MIN_CONFIRMATIONS_MAINNET, /*suppress=*/false, "utxo-immature-serving", nullptr,
            false, nullptr, /*include_mn_special_txs=*/lever, nullptr, nullptr, &sigfn, /*v24_active=*/false,
            &penv, e);
    };
    auto position = [&](const dash::coin::DashWorkData& wd) -> int {
        for (size_t i = 0; i < wd.m_tx_hashes.size(); ++i)
            if (wd.m_tx_hashes[i] == txid(sig)) return static_cast<int>(i);
        return -1;
    };
    const auto with = build(true, &env);
    EXPECT_EQ(position(with), 0) << "a valid signal rides, first (its +0.1 DASH priority)";
    const auto without_env = build(true, nullptr);
    const auto lever_off = build(false, &env);
    EXPECT_EQ(position(without_env), -1) << "no checks wired: no signal rides";
    EXPECT_EQ(position(lever_off), -1) << "the special-tx lever off: no signal rides";
    // A signal changes no CbTx root and pays no fee.
    v::CCbTx a, b;
    ASSERT_TRUE(v::parse_cbtx(with.m_coinbase_payload, a));
    ASSERT_TRUE(v::parse_cbtx(without_env.m_coinbase_payload, b));
    EXPECT_EQ(a.merkleRootMNList, b.merkleRootMNList);
    EXPECT_EQ(with.m_coinbase_value, without_env.m_coinbase_value);
    // Already staged: left out.
    const auto staged = tn_mnhf_env(true);
    EXPECT_EQ(position(build(true, &staged)), -1);
}

// ════════════════════════════════════════════════════════════════════════════
// TYPES 10-12: CORE CHECKS
// ════════════════════════════════════════════════════════════════════════════

TEST(DashV24AllTx, RealTestnetProDisTxPassesCheckProDisTx)
{
    const auto tx = tx_from_hex(kTnProDis);
    MnStateMachine sm;
    sm.load({{u256(kTnSharedPro), tn_shared_state()}}, 1'583'317);
    dash::coin::ProTxCheckEnv env;
    env.net = dash::coin::DashNetwork::TESTNET;
    const auto rules = dash::coin::protx_rules_for(env, 1'583'318, /*v24=*/true);
    const auto check = [&](const MutableTransaction& t, const ProTxCheckRules& r) {
        return protx_core_refusal(t, sm, r, {}, &dash::coin::protx_ecdsa_verify_hash);
    };
    // Both share owners' real signatures over Core's MakeSignHash.
    EXPECT_EQ(check(tx, rules), std::nullopt) << *check(tx, rules);
    // Pre-activation; no verifier; a tampered output (the signatures commit to it).
    EXPECT_CODE(check(tx, dash::coin::protx_rules_for(env, 1'583'318, false)), "bad-prodis-too-early");
    EXPECT_TRUE(protx_core_refusal(tx, sm, rules, {}, {}).has_value());
    auto t2 = tx;
    t2.vout[1].value -= 1;
    EXPECT_CODE(check(t2, rules), "bad-prodis-sig");
    // The masternode must be in the pre-block list.
    MnStateMachine empty;
    EXPECT_CODE(protx_core_refusal(tx, empty, rules, {}, &dash::coin::protx_ecdsa_verify_hash), "bad-prodis-hash");
}

TEST(DashV24AllTx, SharedMasternodeTxsPassCoreChecks)
{
    V24World w;
    EXPECT_EQ(w.check(w.share_tx(1, ec_key(0x51).id, w.s1)), std::nullopt);
    EXPECT_EQ(w.check(w.sharedreg_tx(w.sop2.pub, ec_key(0x52).id, {&w.s0, &w.s1})), std::nullopt);
    EXPECT_EQ(w.check(w.dissolve_tx()), std::nullopt);
    // Unilateral inside the early period: the actor must pay the 5 DASH
    // penalty to the other share (here it does not).
    EXPECT_CODE(w.check(w.dissolve_tx(1000, /*unanimous=*/false)), "bad-prodis-penalty-floor");
}

TEST(DashV24AllTx, SharedMasternodeTxRefusalsAreCoresCodes)
{
    V24World w;
    // ── type 11 ──
    EXPECT_CODE(w.check(w.share_tx(1, ec_key(0x51).id, w.s1), /*v24=*/false), "bad-proupshare-too-early");
    EXPECT_CODE(w.check(w.share_tx(1, ec_key(0x51).id, w.s0)), "bad-proupshare-sig");       // wrong owner
    EXPECT_CODE(w.check(w.share_tx(2, ec_key(0x51).id, w.s1)), "bad-proupshare-index");
    EXPECT_CODE(w.check(w.share_tx(1, w.svoting.id, w.s1)), "bad-proupshare-payee-reuse");  // voting key
    EXPECT_CODE(w.check(w.share_tx(1, w.s0.id, w.s1)), "bad-proupshare-payee-reuse");       // an owner key
    {
        auto t = w.share_tx(1, ec_key(0x51).id, w.s1);
        t.vin[0].prevout.index = 7;
        EXPECT_CODE(w.check(t), "bad-protx-inputs-hash");
    }
    {   // a high-S copy of a valid signature recovers the same key: only the
        // canonical rule (VerifyHashCanonical) refuses it
        auto t = w.share_tx(1, ec_key(0x51).id, w.s1);
        v::CProUpShareTx p;
        ASSERT_TRUE(v::parse_protx_payload(t.extra_payload, p));
        p.vchSig = high_s(p.vchSig);
        t.extra_payload = pack_payload(p);
        EXPECT_CODE(w.check(t), "bad-proupshare-sig");
    }
    {   // a regular masternode
        auto t = w.share_tx(0, ec_key(0x51).id, w.s1);
        v::CProUpShareTx p;
        ASSERT_TRUE(v::parse_protx_payload(t.extra_payload, p));
        p.proTxHash = w.R;
        t.extra_payload = pack_payload(p);
        EXPECT_CODE(w.check(t), "bad-proupshare-not-shared");
        p.proTxHash = h256(0x99);
        t.extra_payload = pack_payload(p);
        EXPECT_CODE(w.check(t), "bad-proupshare-hash");
    }
    // ── type 12 ──
    EXPECT_CODE(w.check(w.sharedreg_tx(w.sop2.pub, ec_key(0x52).id, {&w.s0, &w.s1}), false),
                "bad-proupsharedreg-too-early");
    EXPECT_CODE(w.check(w.sharedreg_tx(w.sop2.pub, ec_key(0x52).id, {&w.s0})), "bad-proupsharedreg-sig-count");
    EXPECT_CODE(w.check(w.sharedreg_tx(w.sop2.pub, ec_key(0x52).id, {&w.s1, &w.s0})), "bad-proupsharedreg-sig");
    EXPECT_CODE(w.check(w.sharedreg_tx(w.rop.pub, ec_key(0x52).id, {&w.s0, &w.s1})), "bad-protx-dup-key");
    EXPECT_CODE(w.check(w.sharedreg_tx(w.sop2.pub, w.refund0.id, {&w.s0, &w.s1})),
                "bad-proupsharedreg-payee-reuse");
    {
        std::array<uint8_t, 48> junk{};
        junk.fill(0x01);
        EXPECT_CODE(w.check(w.sharedreg_tx(junk, ec_key(0x52).id, {&w.s0, &w.s1})), "bad-protx-key-null");
    }
    // ── type 10 ──
    EXPECT_CODE(w.check(w.dissolve_tx(), false), "bad-prodis-too-early");
    EXPECT_CODE(w.check(w.dissolve_tx(/*fee=*/1'000'001)), "bad-prodis-fee");
    {
        auto t = w.dissolve_tx();
        std::swap(t.vout[0], t.vout[1]);   // refunds in the wrong order
        EXPECT_CODE(w.check(t), "bad-prodis-payee");
        t = w.dissolve_tx();
        t.vin[0].prevout.index = 1;
        EXPECT_CODE(w.check(t), "bad-prodis-input");
        t = w.dissolve_tx();
        v::CProDisTx p;
        ASSERT_TRUE(v::parse_protx_payload(t.extra_payload, p));
        p.vchSigs[1] = high_s(p.vchSigs[1]);
        t.extra_payload = pack_payload(p);
        EXPECT_CODE(w.check(t), "bad-prodis-sig");
    }
}

// ════════════════════════════════════════════════════════════════════════════
// TYPES 10-12: THE TEMPLATE FOLD AGAINST THE S3 BLOCK-CONNECT PATH
// ════════════════════════════════════════════════════════════════════════════

TEST(DashV24AllTx, ProUpShareTxFoldsAndTheRootMatchesBlockConnect)
{
    V24World w;
    const auto tx = w.share_tx(1, ec_key(0x51).id, w.s1);
    const auto f = w.fold({tx});
    ASSERT_EQ(f.refused, 0u) << f.refused_reasons.front();
    EXPECT_EQ(f.applied, 1u);
    // The share table is not hashed: the root does not move...
    EXPECT_EQ(f.sml.CalcMerkleRoot(), w.base_sml().CalcMerkleRoot());
    // ...and the block-connect fold agrees, and applied the share.
    const auto r = w.connect({tx}, f.sml.CalcMerkleRoot(), [&](const DmlFoldEngine& eng) {
        ASSERT_NE(eng.find(w.S), nullptr);
        EXPECT_EQ(eng.find(w.S)->v24.shares[1].scriptReward.m_data, p2pkh(ec_key(0x51).id));
    });
    ASSERT_TRUE(r.ok) << r.error;
}

TEST(DashV24AllTx, ProUpSharedRegTxFoldsAndTheRootMatchesBlockConnect)
{
    V24World w;
    const auto tx = w.sharedreg_tx(w.sop2.pub, ec_key(0x52).id, {&w.s0, &w.s1});
    const auto f = w.fold({tx});
    ASSERT_EQ(f.refused, 0u) << f.refused_reasons.front();
    EXPECT_EQ(f.applied, 1u);
    EXPECT_NE(f.sml.CalcMerkleRoot(), w.base_sml().CalcMerkleRoot()) << "operator change: reset + ban";
    const auto r = w.connect({tx}, f.sml.CalcMerkleRoot(), [&](const DmlFoldEngine& eng) {
        const auto* st = eng.find(w.S);
        ASSERT_NE(st, nullptr);
        EXPECT_EQ(st->nVersion, 3);
        EXPECT_TRUE(st->IsBanned());
        EXPECT_EQ(st->keyIDVoting, ec_key(0x52).id);
    });
    ASSERT_TRUE(r.ok) << r.error;
    // The same key again only moves the voting key (no reset, no ban).
    const auto same = w.sharedreg_tx(w.sop.pub, ec_key(0x53).id, {&w.s0, &w.s1});
    const auto f2 = w.fold({same});
    ASSERT_EQ(f2.refused, 0u) << f2.refused_reasons.front();
    const auto r2 = w.connect({same}, f2.sml.CalcMerkleRoot());
    EXPECT_TRUE(r2.ok) << r2.error;
}

TEST(DashV24AllTx, ProDisTxRemovesTheMasternodeAndTheRootMatchesBlockConnect)
{
    V24World w;
    const auto tx = w.dissolve_tx();
    const auto f = w.fold({tx});
    ASSERT_EQ(f.refused, 0u) << f.refused_reasons.front();
    EXPECT_EQ(f.applied, 1u);
    EXPECT_EQ(f.collateral_removed, 1u);
    EXPECT_EQ(f.sml.mnList.size(), 1u);
    const auto r = w.connect({tx}, f.sml.CalcMerkleRoot(),
                             [&](const DmlFoldEngine& eng) { EXPECT_EQ(eng.find(w.S), nullptr); });
    ASSERT_TRUE(r.ok) << r.error;
    EXPECT_FALSE(w.connect({tx}, w.base_sml().CalcMerkleRoot()).ok) << "the removal changes the root";
}

TEST(DashV24AllTx, RealTestnetProDisTxFoldsAndTheRootMatchesBlockConnect)
{
    // The real dissolution over a list holding the real shared masternode
    // (banned: it never announced a service) and a regular one.
    V24World w;
    const auto tx = tx_from_hex(kTnProDis);
    const uint256 pro = u256(kTnSharedPro);
    MNState shared = tn_shared_state();
    MnStateMachine sm;
    sm.load({{pro, shared}, {w.R, w.regular}}, 1'583'317);
    std::vector<std::pair<uint256, ReplayMNState>> states = {
        {pro, to_replay(pro, shared, h256(0x60))}, {w.R, to_replay(w.R, w.regular, h256(0x61))}};
    std::vector<v::CSimplifiedMNListEntry> leaves;
    for (const auto& [p, st] : states) leaves.push_back(st.to_sml_entry(p));
    v::CSimplifiedMNList base(std::move(leaves));
    base.sort();
    dash::coin::ProTxCheckEnv env;
    env.net = dash::coin::DashNetwork::TESTNET;
    auto ctx = dash::coin::MnFoldContext::from(sm, {}, &v::verify_protx_operator_sig);
    ctx.require_core_check = true;
    ctx.core_check = [&](const MutableTransaction& t) {
        return protx_core_refusal(t, sm, dash::coin::protx_rules_for(env, 1'583'318, true), {},
                                  &dash::coin::protx_ecdsa_verify_hash);
    };
    ctx.v24_rules = true;
    ctx.height = 1'583'318;
    ctx.netinfo_rules = v::NetInfoRules::testnet();
    const auto f = dash::coin::fold_mn_special_txs(base, std::vector<MutableTransaction>{tx}, &txid, ctx);
    ASSERT_EQ(f.refused, 0u) << f.refused_reasons.front();
    EXPECT_EQ(f.collateral_removed, 1u);
    FoldConfig cfg;
    cfg.enabled = true;
    cfg.gates = dash::coin::replay::FoldGates::testnet();
    cfg.gates.dip0003_enforcement_height = std::numeric_limits<int32_t>::max();
    DmlFoldEngine eng(cfg);
    eng.seed(states, 2, 1'583'317, h256(0x70), "testnet");
    const auto r = eng.fold_block(block_of(1'583'318, eng.block_hash(), f.sml.CalcMerkleRoot(), {tx}), 1'583'318);
    ASSERT_TRUE(r.ok) << r.error;
    EXPECT_EQ(eng.find(pro), nullptr);
}

TEST(DashV24AllTx, AllThreeSharedTypesInOneBlockMatchBlockConnect)
{
    V24World w;
    const std::vector<MutableTransaction> body = {
        w.share_tx(0, ec_key(0x51).id, w.s0),
        w.sharedreg_tx(w.sop2.pub, ec_key(0x52).id, {&w.s0, &w.s1}),
        w.dissolve_tx(),
    };
    const auto f = w.fold(body);
    ASSERT_EQ(f.refused, 0u) << f.refused_reasons.front();
    EXPECT_EQ(f.applied, 3u);
    const auto r = w.connect(body, f.sml.CalcMerkleRoot());
    EXPECT_TRUE(r.ok) << r.error;
    // The block-connect fold is a real check: the unfolded root is refused.
    EXPECT_FALSE(w.connect(body, w.base_sml().CalcMerkleRoot()).ok);
}

TEST(DashV24AllTx, InBodyConflictsAreRefusedNotFolded)
{
    V24World w;
    {   // R takes S's new operator key earlier in the block: the shared
        // registrar update would duplicate it (ApplyTxToList bad-protx-dup-key)
        const std::vector<MutableTransaction> body = {
            w.upreg_r(w.sop2.pub), w.sharedreg_tx(w.sop2.pub, ec_key(0x52).id, {&w.s0, &w.s1})};
        ASSERT_EQ(w.check(body[0]), std::nullopt) << *w.check(body[0]);
        ASSERT_EQ(w.check(body[1]), std::nullopt) << *w.check(body[1]);
        const auto f = w.fold(body);
        EXPECT_EQ(f.applied, 1u);
        ASSERT_EQ(f.refused, 1u);
        EXPECT_EQ(f.refused_ids[0], txid(body[1]));
        EXPECT_EQ(f.refused_reasons[0].rfind("bad-protx-dup-key", 0), 0u) << f.refused_reasons[0];
        // What remains folds to the block-connect root.
        const auto r = w.connect({body[0]}, f.sml.CalcMerkleRoot());
        EXPECT_TRUE(r.ok) << r.error;
    }
    {   // a share reward moved onto the voting key a registrar update set
        // earlier in the block (ApplyTxToList bad-proupshare-payee-reuse)
        const auto newvoting = ec_key(0x54);
        const std::vector<MutableTransaction> body = {
            w.sharedreg_tx(w.sop.pub, newvoting.id, {&w.s0, &w.s1}), w.share_tx(1, newvoting.id, w.s1)};
        const auto f = w.fold(body);
        EXPECT_EQ(f.applied, 1u);
        ASSERT_EQ(f.refused, 1u);
        EXPECT_EQ(f.refused_reasons[0].rfind("bad-proupshare-payee-reuse", 0), 0u) << f.refused_reasons[0];
    }
    {   // a plain tx spending the shared collateral (only a ProDisTx may)
        auto spend = tx_with_inputs(0, {{w.S, 0}});
        spend.vout.push_back(txout(999 * kCoin, p2pkh(ec_key(0x55).id)));
        const auto f = w.fold({spend});
        ASSERT_EQ(f.refused, 1u);
        EXPECT_EQ(f.refused_reasons[0].rfind("bad-shared-collateral-spend", 0), 0u) << f.refused_reasons[0];
        EXPECT_EQ(f.sml.CalcMerkleRoot(), w.base_sml().CalcMerkleRoot());
    }
}

TEST(DashV24AllTx, StateDriftFromTheSmlLeafFailsClosed)
{
    // The projection's pre-block state must reproduce the SML leaf; if it
    // does not (here: the projection lost the voting key), every tx touching
    // that masternode is refused and the root is the unfolded one.
    V24World w;
    const auto base = w.base_sml();
    w.shared.keyIDVoting = ec_key(0x56).id;
    w.reload();
    const auto f = dash::coin::fold_mn_special_txs(
        base, std::vector<MutableTransaction>{w.share_tx(1, ec_key(0x51).id, w.s1)}, &txid, w.ctx());
    ASSERT_EQ(f.refused, 1u);
    EXPECT_NE(f.refused_reasons[0].find("state drift"), std::string::npos) << f.refused_reasons[0];
    EXPECT_EQ(f.sml.CalcMerkleRoot(), base.CalcMerkleRoot());
}

TEST(DashV24AllTx, ProviderTxsUnderV24FollowTheV24Transitions)
{
    // Before this branch the template fold applied the pre-v24 rules at v24
    // heights too: a revocation reset a basic (v2) state to version 1, so the
    // committed leaf (legacy key encoding, no nType) differed from Core's.
    V24World w;
    const auto rev = w.rev_r();
    ASSERT_EQ(w.check(rev), std::nullopt) << *w.check(rev);
    const auto f = w.fold({rev});
    ASSERT_EQ(f.refused, 0u) << f.refused_reasons.front();
    const auto r = w.connect({rev}, f.sml.CalcMerkleRoot());
    EXPECT_TRUE(r.ok) << r.error;
    auto folded = f.sml;
    const auto* leaf = dash::coin::detail::find_entry(folded.mnList, w.R);
    ASSERT_NE(leaf, nullptr);
    EXPECT_EQ(leaf->nVersion, v::ProTxVersion::BASIC_BLS) << "Core v24 keeps the version on a revocation";
    EXPECT_FALSE(leaf->isValid);
    // The pre-v24 fold of the same tx gives a different (pre-v24) root, one a
    // v24 block cannot commit: the block-connect fold refuses it.
    const auto old = w.fold({rev}, /*v24=*/false);
    EXPECT_NE(old.sml.CalcMerkleRoot(), f.sml.CalcMerkleRoot());
    EXPECT_FALSE(w.connect({rev}, old.sml.CalcMerkleRoot()).ok);
}

TEST(DashV24AllTx, RealTestnetProUpRevTxV3OfAnEvoNodeFoldsToCoresState)
{
    // Ground truth is Dash Core's own post-state (protx info at 1,578,068),
    // turned into the SML leaf by hand here; the fold must commit exactly that
    // leaf, and the block-connect fold must agree on the root.
    const auto tx = tx_from_hex(kTnRevV3);
    const uint256 pro = u256(kTnRevPro);
    const MNState evo = tn_evo_state();
    MnStateMachine sm;
    sm.load({{pro, evo}}, 1'578'067);
    const std::vector<std::pair<uint256, ReplayMNState>> states = {{pro, to_replay(pro, evo, h256(0x62))}};
    v::CSimplifiedMNList base(std::vector<v::CSimplifiedMNListEntry>{states[0].second.to_sml_entry(pro)});
    dash::coin::ProTxCheckEnv env;
    env.net = dash::coin::DashNetwork::TESTNET;
    const auto rules = dash::coin::protx_rules_for(env, 1'578'068, true);
    const auto check = [&](const MutableTransaction& t) {
        return protx_core_refusal(t, sm, rules, {}, &dash::coin::protx_ecdsa_verify_hash);
    };
    ASSERT_EQ(check(tx), std::nullopt) << *check(tx);
    // Before v24 a version-3 payload is out of range.
    EXPECT_CODE(protx_core_refusal(tx, sm, dash::coin::protx_rules_for(env, 1'578'068, false), {},
                                   &dash::coin::protx_ecdsa_verify_hash),
                "bad-protx-version");
    auto ctx = dash::coin::MnFoldContext::from(sm, {}, &v::verify_protx_operator_sig);
    ctx.require_core_check = true;
    ctx.core_check = check;
    ctx.v24_rules = true;
    ctx.height = 1'578'068;
    ctx.netinfo_rules = v::NetInfoRules::testnet();
    const auto f = dash::coin::fold_mn_special_txs(base, std::vector<MutableTransaction>{tx}, &txid, ctx);
    ASSERT_EQ(f.refused, 0u) << f.refused_reasons.front();
    ASSERT_EQ(f.sml.mnList.size(), 1u);
    v::CSimplifiedMNListEntry want;
    want.nVersion = v::CSimplifiedMNListEntry::VER_EXT_ADDR;
    want.proRegTxHash = pro;
    want.confirmedHash = base.mnList[0].confirmedHash;
    want.extNetInfo = v::ExtNetInfo{};
    want.pubKeyOperator = {};
    want.keyIDVoting = evo.keyIDVoting;
    want.isValid = false;
    want.nType = v::CSimplifiedMNListEntry::TYPE_EVO;
    want.platformNodeID = uint160{};
    EXPECT_EQ(f.sml.mnList[0].CalcHash(), want.CalcHash());
    EXPECT_EQ(f.sml.mnList[0].nVersion, 3);
    FoldConfig cfg;
    cfg.enabled = true;
    cfg.gates = dash::coin::replay::FoldGates::testnet();
    cfg.gates.dip0003_enforcement_height = std::numeric_limits<int32_t>::max();
    DmlFoldEngine eng(cfg);
    eng.seed(states, 1, 1'578'067, h256(0x70), "testnet");
    const auto r = eng.fold_block(block_of(1'578'068, eng.block_hash(), f.sml.CalcMerkleRoot(), {tx}), 1'578'068);
    ASSERT_TRUE(r.ok) << r.error;
    const auto* st = eng.find(pro);
    ASSERT_NE(st, nullptr);
    ASSERT_EQ(st->v24.payouts.size(), 1u);
    EXPECT_EQ(st->v24.payouts[0].scriptPayout.m_data, evo.scriptPayout.m_data);
    EXPECT_EQ(st->v24.payouts[0].reward, 10000);
    EXPECT_EQ(st->nRevocationReason, 1);
}

TEST(DashV24AllTx, RealTestnetProUpServTxV3RaisesAndRevivesLikeCore)
{
    for (const bool evo : {false, true}) {
        SCOPED_TRACE(evo ? "EvoNode 763ca29f at 1,578,496" : "Regular a356adb8 at 1,579,049");
        const auto tx = tx_from_hex(evo ? kTnServEvo : kTnServA356);
        const uint256 pro = u256(evo ? kTnServEvoPro : kTnServA356Pro);
        const MNState pre = evo ? tn_evo763c_state() : tn_a356_state();
        const uint32_t height = evo ? 1'578'496 : 1'579'049;
        v::CProUpServTx p;
        ASSERT_TRUE(v::parse_protx_payload(tx.extra_payload, p));
        ASSERT_EQ(p.nVersion, 3);
        const auto r = real_fold(pro, pre, tx, height, [&](const DmlFoldEngine& eng) {
            const auto* st = eng.find(pro);
            ASSERT_NE(st, nullptr);
            EXPECT_EQ(st->nVersion, 3);
            EXPECT_FALSE(st->IsBanned());
            ASSERT_EQ(st->v24.payouts.size(), 1u);
            EXPECT_EQ(st->v24.payouts[0].scriptPayout.m_data, pre.scriptPayout.m_data);
        });
        ASSERT_EQ(r.core_check, std::nullopt) << *r.core_check;
        ASSERT_EQ(r.fold.refused, 0u) << r.fold.refused_reasons.front();
        // Dash Core's post-state as a leaf, built by hand: version 3, the
        // payload's ExtNetInfo, the operator key in the basic scheme, revived.
        v::CSimplifiedMNListEntry want;
        want.nVersion = v::CSimplifiedMNListEntry::VER_EXT_ADDR;
        want.proRegTxHash = pro;
        want.confirmedHash = r.base.mnList[0].confirmedHash;
        want.extNetInfo = p.extNetInfo;
        want.pubKeyOperator = pre.pubKeyOperator;
        want.keyIDVoting = pre.keyIDVoting;
        want.isValid = true;
        want.nType = pre.nType;
        want.platformNodeID = evo ? p.platformNodeID : uint160{};
        ASSERT_EQ(r.fold.sml.mnList.size(), 1u);
        EXPECT_EQ(r.fold.sml.mnList[0].CalcHash(), want.CalcHash());
        EXPECT_TRUE(r.connect.ok) << r.connect.error;
    }
    // An EvoNode must spell its Platform entries out at version 3: the same
    // masternode's v2-shaped update is refused under v24.
    {
        MnStateMachine sm;
        sm.load({{u256(kTnServEvoPro), tn_evo763c_state()}}, 1'578'495);
        auto tx = tx_from_hex(kTnServEvo);
        v::CProUpServTx p;
        ASSERT_TRUE(v::parse_protx_payload(tx.extra_payload, p));
        dash::coin::ProTxCheckEnv env;
        env.net = dash::coin::DashNetwork::TESTNET;
        // Before v24 a version-3 payload is out of range.
        EXPECT_CODE(protx_core_refusal(tx, sm, dash::coin::protx_rules_for(env, 1'578'496, false), {},
                                       &dash::coin::protx_ecdsa_verify_hash),
                    "bad-protx-version");
    }
}

TEST(DashV24AllTx, ProUpRegTxV3PayoutListFoldsAndMatchesBlockConnect)
{
    V24World w;
    auto make = [&](std::vector<std::pair<uint160, uint16_t>> payouts, const std::array<uint8_t, 48>& key) {
        MutableTransaction tx = tx_with_inputs(3, {{h256(0x84), 0}});
        v::CProUpRegTx p;
        p.nVersion = v::ProTxVersion::EXT_ADDR;
        p.proTxHash = w.R;
        p.pubKeyOperator = key;
        p.keyIDVoting = w.rvoting.id;
        for (const auto& [id, reward] : payouts) {
            v::MasternodePayoutShare s;
            s.scriptPayout = script_of(p2pkh(id));
            s.reward = reward;
            p.payouts.push_back(s);
        }
        p.inputsHash = dash::coin::protx_check_detail::inputs_hash(tx);
        tx.extra_payload = pack_payload(p);
        const auto h = dash::coin::protx_check_detail::hash_without_trailing_vchsig(tx.extra_payload, 0);
        p.vchSig = sign_compact(w.rowner, *h);
        tx.extra_payload = pack_payload(p);
        return tx;
    };
    const auto a = ec_key(0x5a).id, b = ec_key(0x5b).id;
    const auto tx = make({{a, 6000}, {b, 4000}}, w.rop.pub);   // no key change: raised to 3
    ASSERT_EQ(w.check(tx), std::nullopt) << *w.check(tx);
    const auto f = w.fold({tx});
    ASSERT_EQ(f.refused, 0u) << f.refused_reasons.front();
    auto folded = f.sml;
    const auto* leaf = dash::coin::detail::find_entry(folded.mnList, w.R);
    ASSERT_NE(leaf, nullptr);
    EXPECT_EQ(leaf->nVersion, 3) << "max(state 2, tx 3): the legacy service becomes an ExtNetInfo entry";
    EXPECT_TRUE(leaf->isValid);
    const auto r = w.connect({tx}, f.sml.CalcMerkleRoot(), [&](const DmlFoldEngine& eng) {
        const auto* st = eng.find(w.R);
        ASSERT_NE(st, nullptr);
        ASSERT_EQ(st->v24.payouts.size(), 2u);
        EXPECT_EQ(st->v24.payouts[1].reward, 4000);
    });
    EXPECT_TRUE(r.ok) << r.error;
    // Core's codes for the version-3 rules.
    EXPECT_CODE(w.check(make({{a, 6000}, {b, 3000}}, w.rop.pub)), "bad-protx-payout-reward-sum");
    EXPECT_CODE(w.check(make({{a, 5000}, {w.rcollat.id, 5000}}, w.rop.pub)), "bad-protx-payee-reuse");
    EXPECT_CODE(w.check(make({{a, 5000}, {w.rvoting.id, 5000}}, w.rop.pub)), "bad-protx-payee-reuse");
    EXPECT_CODE(w.check(make({{a, 10000}}, w.rop.pub), /*v24=*/false), "bad-protx-version");
    {   // a shared masternode is never updated by a ProUpRegTx
        auto t = make({{a, 10000}}, w.rop.pub);
        v::CProUpRegTx p;
        ASSERT_TRUE(v::parse_protx_payload(t.extra_payload, p));
        p.proTxHash = w.S;
        t.extra_payload = pack_payload(p);
        EXPECT_CODE(w.check(t), "bad-protx-shared-mn");
    }
}

TEST(DashV24AllTx, PreActivationTheV24TypesNeverReachATemplate)
{
    V24World w;
    const auto share = w.share_tx(1, ec_key(0x51).id, w.s1);
    // Mempool admission follows the v24 type list only once v24 is active
    // for the next block.
    dash::coin::Mempool mp;
    EXPECT_FALSE(mp.add_tx(share)) << "bad-txns-type before v24";
    mp.set_v24_admission(true);
    EXPECT_TRUE(mp.add_tx(share));
    // The pre-v24 fold has no transition for 10-12; selection must keep them
    // out (the mask admits them only under v24 rules).
    dash::coin::Mempool::SpecialTxSelectMask m;
    m.allow_all_special = false;
    m.allow_mn_types = true;
    m.allow_v24_provider = true;
    EXPECT_FALSE(m.admits(11));
    m.v24_rules = true;
    EXPECT_TRUE(m.admits(10));
    EXPECT_TRUE(m.admits(11));
    EXPECT_TRUE(m.admits(12));
    EXPECT_FALSE(m.admits(9));
    EXPECT_FALSE(m.admits(6));
}

TEST(DashV24AllTx, BuilderCarriesSharedTypesAtV24AndCommitsTheBlockConnectRoot)
{
    V24World w;
    ::core::coin::UTXOViewCache utxo(nullptr);
    dash::coin::Mempool mp;
    mp.set_utxo(&utxo);
    mp.set_v24_admission(true);
    const auto share = w.share_tx(0, ec_key(0x51).id, w.s0);
    const auto reg = w.sharedreg_tx(w.sop2.pub, ec_key(0x52).id, {&w.s0, &w.s1});
    const auto dis = w.dissolve_tx();
    auto add_input = [&](const MutableTransaction& t, int64_t value, std::vector<uint8_t> script) {
        utxo.add_coin(::core::coin::Outpoint(t.vin[0].prevout.hash, t.vin[0].prevout.index),
                      ::core::coin::Coin(value, script_of(std::move(script)), 1, false));
    };
    add_input(share, 10'000, p2pkh(ec_key(0x57).id));
    add_input(reg, 10'000, p2pkh(ec_key(0x58).id));
    add_input(dis, kColl, dash::coin::v24::shared_collateral_script());
    ASSERT_TRUE(mp.add_tx(share));
    ASSERT_TRUE(mp.add_tx(reg));
    ASSERT_TRUE(mp.add_tx(dis));
    const auto sml = w.base_sml();
    dash::coin::QuorumManager qmgr;
    dash::coin::ProTxCheckEnv env;
    env.net = dash::coin::DashNetwork::MAINNET;
    env.ecdsa = &dash::coin::protx_ecdsa_verify_hash;
    const dash::coin::MnFoldContext::OperatorSigFn sigfn = &v::verify_protx_operator_sig;
    auto build = [&](bool v24) {
        return dash::coin::build_embedded_workdata(
            V24World::H - 1, h256(0xAB), w.sm, mp, 0x1b104be3u, 1'800'000'000u, 76, 16, 1'800'000'100u,
            0x20000000u, nullptr, &sml, &qmgr, 0, dash::coin::k_zero_cl_sig, 0, nullptr, nullptr,
            dash::coin::DASH_MN_RR_HEIGHT_MAINNET, nullptr, dash::coin::DASH_MN_MIN_CONFIRMATIONS_MAINNET,
            /*suppress=*/false, "utxo-immature-serving", nullptr, false, nullptr,
            /*include_mn_special_txs=*/true, nullptr, nullptr, &sigfn, v24, &env, nullptr);
    };
    auto rides = [&](const dash::coin::DashWorkData& wd, const MutableTransaction& t) {
        for (const auto& h : wd.m_tx_hashes)
            if (h == txid(t)) return true;
        return false;
    };
    const auto at = build(true);
    EXPECT_TRUE(rides(at, share));
    EXPECT_TRUE(rides(at, reg));
    EXPECT_TRUE(rides(at, dis));
    v::CCbTx cb;
    ASSERT_TRUE(v::parse_cbtx(at.m_coinbase_payload, cb));
    EXPECT_EQ(cb.nVersion, v::CCbTx::VERSION_MERKLE_ROOT_ASSETUNLOCKS);
    std::vector<MutableTransaction> body;
    for (const auto& t : at.m_txs) body.emplace_back(t);
    const auto r = w.connect(body, cb.merkleRootMNList);
    EXPECT_TRUE(r.ok) << r.error;
    // Before v24 none of them rides, and the root is the unfolded one.
    const auto before = build(false);
    EXPECT_FALSE(rides(before, share));
    EXPECT_FALSE(rides(before, reg));
    EXPECT_FALSE(rides(before, dis));
    v::CCbTx cb0;
    ASSERT_TRUE(v::parse_cbtx(before.m_coinbase_payload, cb0));
    EXPECT_EQ(cb0.merkleRootMNList, sml.CalcMerkleRoot());
}

TEST(DashV24AllTx, BuilderLeavesOutAnInvalidOrDuplicateDissolution)
{
    V24World w;
    ::core::coin::UTXOViewCache utxo(nullptr);
    dash::coin::Mempool mp;
    mp.set_utxo(&utxo);
    mp.set_v24_admission(true);
    const auto good = w.dissolve_tx(1000);
    const auto rival = w.dissolve_tx(2000);   // a second dissolution of the same collateral
    utxo.add_coin(::core::coin::Outpoint(w.S, 0),
                  ::core::coin::Coin(kColl, script_of(dash::coin::v24::shared_collateral_script()), 1, false));
    ASSERT_TRUE(mp.add_tx(good));
    mp.add_tx(rival);   // the pool may refuse the double spend outright
    const auto sml = w.base_sml();
    dash::coin::QuorumManager qmgr;
    dash::coin::ProTxCheckEnv env;
    env.net = dash::coin::DashNetwork::MAINNET;
    env.ecdsa = &dash::coin::protx_ecdsa_verify_hash;
    const dash::coin::MnFoldContext::OperatorSigFn sigfn = &v::verify_protx_operator_sig;
    const auto wd = dash::coin::build_embedded_workdata(
        V24World::H - 1, h256(0xAB), w.sm, mp, 0x1b104be3u, 1'800'000'000u, 76, 16, 1'800'000'100u,
        0x20000000u, nullptr, &sml, &qmgr, 0, dash::coin::k_zero_cl_sig, 0, nullptr, nullptr,
        dash::coin::DASH_MN_RR_HEIGHT_MAINNET, nullptr, dash::coin::DASH_MN_MIN_CONFIRMATIONS_MAINNET,
        /*suppress=*/false, "utxo-immature-serving", nullptr, false, nullptr,
        /*include_mn_special_txs=*/true, nullptr, nullptr, &sigfn, /*v24_active=*/true, &env, nullptr);
    size_t dissolutions = 0;
    for (const auto& h : wd.m_tx_hashes)
        if (h == txid(good) || h == txid(rival)) ++dissolutions;
    EXPECT_EQ(dissolutions, 1u) << "one spend of the collateral at most";
    v::CCbTx cb;
    ASSERT_TRUE(v::parse_cbtx(wd.m_coinbase_payload, cb));
    std::vector<MutableTransaction> body;
    for (const auto& t : wd.m_txs) body.emplace_back(t);
    const auto r = w.connect(body, cb.merkleRootMNList);
    EXPECT_TRUE(r.ok) << r.error;
    // Without the Dash Core checks wired, no dissolution rides (fail closed).
    const auto none = dash::coin::build_embedded_workdata(
        V24World::H - 1, h256(0xAB), w.sm, mp, 0x1b104be3u, 1'800'000'000u, 76, 16, 1'800'000'100u,
        0x20000000u, nullptr, &sml, &qmgr, 0, dash::coin::k_zero_cl_sig, 0, nullptr, nullptr,
        dash::coin::DASH_MN_RR_HEIGHT_MAINNET, nullptr, dash::coin::DASH_MN_MIN_CONFIRMATIONS_MAINNET,
        /*suppress=*/false, "utxo-immature-serving", nullptr, false, nullptr,
        /*include_mn_special_txs=*/true, nullptr, nullptr, &sigfn, /*v24_active=*/true, nullptr, nullptr);
    for (const auto& h : none.m_tx_hashes) {
        EXPECT_NE(h, txid(good));
        EXPECT_NE(h, txid(rival));
    }
}

// ── Dash Core v24 mempool rules for the shared-masternode types ─────────────
// (txmempool.cpp existsProviderTxConflict / existsProviderTxCrossSchemeConflict
// at admission, removeProTxConflicts at block connect): the pool keeps a
// pairwise-safe set, so the template never has to pick between two txs that
// cannot share a block.

namespace {
MutableTransaction with_out(MutableTransaction tx)
{
    tx.vout.push_back(txout(1000, {0x51}));
    return tx;
}
/// The tip list of V24World, as NodeCoinState answers it.
dash::coin::Mempool::TipOperatorKeyFn tip_of(const V24World& w,
                                              dash::coin::Mempool::TipMn other = dash::coin::Mempool::TipMn::Absent)
{
    return [&w, other](const uint256& pro) {
        dash::coin::Mempool::TipOperatorKey k;
        k.state = other;
        if (pro == w.S || pro == w.R) {
            k.state = dash::coin::Mempool::TipMn::Listed;
            k.key = pro == w.S ? w.shared.pubKeyOperator : w.regular.pubKeyOperator;
        }
        return k;
    };
}
bool in_pool(const dash::coin::Mempool& mp, const MutableTransaction& tx)
{
    return mp.get_entry(txid(tx)).has_value();
}
}  // namespace

TEST(DashV24AllTx, MempoolRefusesAShareRewardThatAPendingSharedRegistrarMakesTheVotingKey)
{
    V24World w;
    const EcKey nv = ec_key(0x51);
    {
        dash::coin::Mempool mp;
        mp.set_v24_admission(true);
        mp.set_tip_operator_key_fn(tip_of(w));
        const auto reg = with_out(w.sharedreg_tx(w.sop.pub, nv.id, {&w.s0, &w.s1}, 0x81));
        ASSERT_TRUE(mp.add_tx(reg));
        const auto share = with_out(w.share_tx(0, nv.id, w.s0, 0x80));
        EXPECT_FALSE(mp.add_tx(share)) << "its reward would pay the pending new voting key";
        const auto other = with_out(w.share_tx(0, ec_key(0x52).id, w.s0, 0x84));
        EXPECT_TRUE(mp.add_tx(other)) << "a reward to any other key is no conflict";
    }
    {   // the mirror order
        dash::coin::Mempool mp;
        mp.set_v24_admission(true);
        mp.set_tip_operator_key_fn(tip_of(w));
        const auto share = with_out(w.share_tx(0, nv.id, w.s0, 0x80));
        ASSERT_TRUE(mp.add_tx(share));
        const auto reg = with_out(w.sharedreg_tx(w.sop.pub, nv.id, {&w.s0, &w.s1}, 0x81));
        EXPECT_FALSE(mp.add_tx(reg)) << "a pending share reward already pays the new voting key";
        const auto reg2 = with_out(w.sharedreg_tx(w.sop.pub, ec_key(0x53).id, {&w.s0, &w.s1}, 0x85));
        EXPECT_TRUE(mp.add_tx(reg2));
    }
}

TEST(DashV24AllTx, MempoolAllowsOneOperatorKeyChangePerMasternode)
{
    V24World w;
    dash::coin::Mempool mp;
    mp.set_v24_admission(true);
    mp.set_tip_operator_key_fn(tip_of(w));
    // S: one key change, then a second one is refused; keeping the key is no change.
    const auto change = with_out(w.sharedreg_tx(w.sop2.pub, w.svoting.id, {&w.s0, &w.s1}, 0x81));
    ASSERT_TRUE(mp.add_tx(change));
    const auto change2 = with_out(w.sharedreg_tx(bls_key(0x45).pub, w.svoting.id, {&w.s0, &w.s1}, 0x86));
    EXPECT_FALSE(mp.add_tx(change2)) << "only one operator key change in the mempool";
    const auto keep = with_out(w.sharedreg_tx(w.sop.pub, ec_key(0x54).id, {&w.s0, &w.s1}, 0x87));
    EXPECT_TRUE(mp.add_tx(keep)) << "a registrar update keeping the key is not a key change";
    // R: a key-changing ProUpRegTx, then a revocation (also a key change) is refused.
    const auto upreg = with_out(w.upreg_r(w.rop2.pub));
    ASSERT_TRUE(mp.add_tx(upreg));
    EXPECT_FALSE(mp.add_tx(with_out(w.rev_r())));
}

TEST(DashV24AllTx, MempoolRefusesASecondClaimOfAnOperatorKeyAcrossTypes)
{
    V24World w;
    const auto K = bls_key(0x46).pub;
    {
        dash::coin::Mempool mp;
        mp.set_v24_admission(true);
        mp.set_tip_operator_key_fn(tip_of(w));
        ASSERT_TRUE(mp.add_tx(with_out(w.sharedreg_tx(K, w.svoting.id, {&w.s0, &w.s1}, 0x81))));
        EXPECT_FALSE(mp.add_tx(with_out(w.upreg_r(K)))) << "a pending shared registrar update claims K";
    }
    {
        dash::coin::Mempool mp;
        mp.set_v24_admission(true);
        mp.set_tip_operator_key_fn(tip_of(w));
        ASSERT_TRUE(mp.add_tx(with_out(w.upreg_r(K))));
        EXPECT_FALSE(mp.add_tx(with_out(w.sharedreg_tx(K, w.svoting.id, {&w.s0, &w.s1}, 0x81))))
            << "a pending ProUpRegTx claims K";
    }
}

TEST(DashV24AllTx, MempoolRefusesUpdatesOfAMasternodeNotInTheTipList)
{
    V24World w;
    dash::coin::Mempool::TipOperatorKeyFn none = [](const uint256&) {
        dash::coin::Mempool::TipOperatorKey k;
        k.state = dash::coin::Mempool::TipMn::Absent;
        return k;
    };
    dash::coin::Mempool mp;
    mp.set_v24_admission(true);
    mp.set_tip_operator_key_fn(none);
    EXPECT_FALSE(mp.add_tx(with_out(w.share_tx(0, ec_key(0x52).id, w.s0, 0x80))));
    EXPECT_FALSE(mp.add_tx(with_out(w.sharedreg_tx(w.sop.pub, w.svoting.id, {&w.s0, &w.s1}, 0x81))));
    // A list that is not at the tip decides nothing: admitted, the template
    // checks decide.
    mp.set_tip_operator_key_fn([](const uint256&) { return dash::coin::Mempool::TipOperatorKey{}; });
    EXPECT_TRUE(mp.add_tx(with_out(w.share_tx(0, ec_key(0x52).id, w.s0, 0x80))));
}

TEST(DashV24AllTx, BlockConnectEvictsThePendingSharedTypesCoreEvicts)
{
    V24World w;
    const EcKey nv = ec_key(0x51), nr = ec_key(0x55);
    dash::coin::Mempool mp;
    mp.set_v24_admission(true);
    // Admitted without the tip rules: a pool fed before the list reached the tip.
    const auto share_pays_nv = with_out(w.share_tx(0, nv.id, w.s0, 0x80));
    const auto reg_votes_nr = with_out(w.sharedreg_tx(w.sop2.pub, nr.id, {&w.s0, &w.s1}, 0x81));
    const auto share_other = with_out(w.share_tx(1, ec_key(0x56).id, w.s1, 0x84));
    const auto r_upreg = with_out(w.upreg_r(w.rop.pub));   // keeps R's key
    ASSERT_TRUE(mp.add_tx(share_pays_nv));
    ASSERT_TRUE(mp.add_tx(reg_votes_nr));
    ASSERT_TRUE(mp.add_tx(share_other));
    ASSERT_TRUE(mp.add_tx(r_upreg));
    auto owner = [&w](const bitcoin_family::coin::TxPrevOut& op) -> std::optional<uint256> {
        if (op.hash == w.S && op.index == 0) return w.S;
        return std::nullopt;
    };
    auto held = [&w](const uint256& pro) -> std::optional<std::array<uint8_t, 48>> {
        if (pro == w.S) return w.shared.pubKeyOperator;
        if (pro == w.R) return w.regular.pubKeyOperator;
        return std::nullopt;
    };
    // A mined ProUpSharedRegTx making nv the voting key evicts the pending
    // share update paying nv (removeProTxVotingPayeeConflicts, UPDATE_SHARE);
    // it keeps the key, so nothing keyed on the operator goes, and the
    // pending update claiming another key stays.
    const auto mined_reg = with_out(w.sharedreg_tx(w.sop.pub, nv.id, {&w.s0, &w.s1}, 0x88));
    mp.remove_protx_conflicts_for_block(block_of(V24World::H, h256(0xAB), uint256(), {mined_reg}), owner, held);
    EXPECT_FALSE(in_pool(mp, share_pays_nv));
    EXPECT_TRUE(in_pool(mp, reg_votes_nr));
    EXPECT_TRUE(in_pool(mp, share_other));
    EXPECT_TRUE(in_pool(mp, r_upreg)) << "another masternode";
    // A mined ProUpShareTx paying nr evicts the pending shared registrar
    // update voting nr (UPDATE_SHARED_REGISTRAR).
    const auto mined_share = with_out(w.share_tx(1, nr.id, w.s1, 0x89));
    mp.remove_protx_conflicts_for_block(block_of(V24World::H, h256(0xAB), uint256(), {mined_share}), owner, held);
    EXPECT_FALSE(in_pool(mp, reg_votes_nr));
    EXPECT_TRUE(in_pool(mp, share_other));
    // A mined ProDisTx spends the collateral: every pending tx naming S goes
    // (removeProTxSpentCollateralConflicts -> removeProTxReferences).
    mp.remove_protx_conflicts_for_block(block_of(V24World::H, h256(0xAB), uint256(), {w.dissolve_tx()}), owner,
                                        held);
    EXPECT_FALSE(in_pool(mp, share_other));
    EXPECT_TRUE(in_pool(mp, r_upreg));
}

TEST(DashV24AllTx, BlockConnectOperatorKeyChangeSkipsTheSharedTypes)
{
    V24World w;
    dash::coin::Mempool mp;
    mp.set_v24_admission(true);
    const auto share = with_out(w.share_tx(0, ec_key(0x52).id, w.s0, 0x80));
    const auto reg = with_out(w.sharedreg_tx(w.sop.pub, ec_key(0x57).id, {&w.s0, &w.s1}, 0x81));
    ASSERT_TRUE(mp.add_tx(share));
    ASSERT_TRUE(mp.add_tx(reg));
    auto held = [&w](const uint256& pro) -> std::optional<std::array<uint8_t, 48>> {
        if (pro == w.S) return w.shared.pubKeyOperator;
        return std::nullopt;
    };
    // A mined key change of S: share owner keys sign the shared types, so the
    // pending share update stays (removeProTxKeyChangedConflicts skips types
    // 10-12); the pending registrar update claiming the OLD key stays too (a
    // different key from the mined one).
    const auto mined = with_out(w.sharedreg_tx(w.sop2.pub, w.svoting.id, {&w.s0, &w.s1}, 0x88));
    mp.remove_protx_conflicts_for_block(block_of(V24World::H, h256(0xAB), uint256(), {mined}),
                                        [](const bitcoin_family::coin::TxPrevOut&) { return std::optional<uint256>{}; },
                                        held);
    EXPECT_TRUE(in_pool(mp, share));
    EXPECT_TRUE(in_pool(mp, reg));
    // A pending shared registrar update claiming the key a mined one takes
    // is evicted (removeProTxPubKeyConflicts).
    const auto claim = with_out(w.sharedreg_tx(bls_key(0x47).pub, w.svoting.id, {&w.s0, &w.s1}, 0x8a));
    ASSERT_TRUE(mp.add_tx(claim));
    const auto mined2 = with_out(w.upreg_r(bls_key(0x47).pub));
    mp.remove_protx_conflicts_for_block(block_of(V24World::H, h256(0xAB), uint256(), {mined2}),
                                        [](const bitcoin_family::coin::TxPrevOut&) { return std::optional<uint256>{}; },
                                        held);
    EXPECT_FALSE(in_pool(mp, claim));
}

// ── Dash Core's service-update order (node/miner.cpp keyChangedMNs,
// GetServiceUpdatesBeforeKeyChange, IsUnorderableServiceUpdate) ─────────────

namespace {
dash::coin::ServiceOrderTx so(uint8_t tag, std::vector<uint8_t> parents = {})
{
    dash::coin::ServiceOrderTx t;
    t.txid = h256(tag);
    for (uint8_t p : parents) t.spends.push_back(h256(p));
    t.spends.push_back(h256(0xF0));   // a confirmed coin
    return t;
}
std::vector<uint256> ids_in(const std::vector<dash::coin::ServiceOrderTx>& body, const dash::coin::ServiceOrderResult& r)
{
    std::vector<uint256> out;
    for (size_t i : r.order) out.push_back(body[i].txid);
    return out;
}
MutableTransaction servtx_r(const V24World& w, uint8_t vin_tag = 0x8b,
                            std::optional<std::pair<uint256, uint32_t>> spend = std::nullopt)
{
    MutableTransaction tx = tx_with_inputs(2, {spend ? *spend : std::make_pair(h256(vin_tag), 0u)});
    v::CProUpServTx p;
    p.nVersion = v::ProTxVersion::BASIC_BLS;
    p.nType = v::MnType::REGULAR;
    p.proTxHash = w.R;
    p.netInfo = ipv4(5, 6, 7, 9, 9999);
    p.inputsHash = dash::coin::protx_check_detail::inputs_hash(tx);
    p.sig = {};
    const auto h = v::protx_operator_sign_hash(pack_payload(p));
    p.sig = bls::BasicSchemeMPL().Sign(w.rop.sk, bls::Bytes(h->data(), 32)).SerializeToArray(false);
    tx.extra_payload = pack_payload(p);
    return tx;
}
}  // namespace

TEST(DashV24AllTx, ServiceUpdateMovesInFrontOfTheKeyChangeWithItsAncestors)
{
    const uint256 X = h256(0xC1);
    auto k = so(0x01);
    k.key_change_of = X;
    auto a = so(0x02);                  // unrelated
    auto parent = so(0x03);             // the update's unconfirmed parent
    auto u = so(0x04, {0x03});
    u.service_update_of = X;
    const std::vector<dash::coin::ServiceOrderTx> body{k, a, parent, u};
    const auto r = dash::coin::order_service_updates(body);
    EXPECT_TRUE(r.dropped.empty());
    EXPECT_EQ(r.moved, 2u);
    EXPECT_EQ(ids_in(body, r), (std::vector<uint256>{h256(0x03), h256(0x04), h256(0x01), h256(0x02)}));
}

TEST(DashV24AllTx, ServiceUpdateThatCannotGoFirstIsLeftOutWithItsDescendants)
{
    const uint256 X = h256(0xC1);
    {   // a descendant of the key change
        auto k = so(0x01);
        k.key_change_of = X;
        auto u = so(0x02, {0x01});
        u.service_update_of = X;
        auto child = so(0x03, {0x02});
        const std::vector<dash::coin::ServiceOrderTx> body{k, u, child};
        const auto r = dash::coin::order_service_updates(body);
        EXPECT_EQ(ids_in(body, r), (std::vector<uint256>{h256(0x01)}));
        EXPECT_EQ(r.dropped.size(), 2u);
    }
    {   // an ancestor of an unorderable kind (asset lock / unlock / MNHF)
        auto k = so(0x01);
        k.key_change_of = X;
        auto lock = so(0x02);
        lock.unorderable_kind = true;
        auto u = so(0x03, {0x02});
        u.service_update_of = X;
        const std::vector<dash::coin::ServiceOrderTx> body{k, lock, u};
        const auto r = dash::coin::order_service_updates(body);
        EXPECT_EQ(ids_in(body, r), (std::vector<uint256>{h256(0x01), h256(0x02)}));
        ASSERT_EQ(r.dropped.size(), 1u);
        EXPECT_EQ(r.dropped[0].first, 2u);
    }
    {   // an update already before the key change stays; another MN's is untouched
        auto u = so(0x01);
        u.service_update_of = X;
        auto k = so(0x02);
        k.key_change_of = X;
        auto other = so(0x03);
        other.service_update_of = h256(0xC2);
        const std::vector<dash::coin::ServiceOrderTx> body{u, k, other};
        const auto r = dash::coin::order_service_updates(body);
        EXPECT_EQ(r.moved, 0u);
        EXPECT_TRUE(r.dropped.empty());
        EXPECT_EQ(ids_in(body, r), (std::vector<uint256>{h256(0x01), h256(0x02), h256(0x03)}));
    }
}

TEST(DashV24AllTx, MempoolRefusesAServiceUpdateThatCannotBeOrderedBeforeItsAncestors)
{
    V24World w;
    dash::coin::Mempool mp;
    mp.set_v24_admission(true);
    mp.set_tip_operator_key_fn(tip_of(w));
    // An unconfirmed key change of R, and a service update of R spending its output.
    const auto key_change = with_out(w.upreg_r(w.rop2.pub));
    ASSERT_TRUE(mp.add_tx(key_change));
    EXPECT_FALSE(mp.add_tx(with_out(servtx_r(w, 0, std::make_pair(txid(key_change), 0u)))))
        << "IsUnorderableServiceUpdate: an ancestor changes the operator key";
    // An unconfirmed MNHF signal has no outputs; an asset lock does.
    auto lock = tx_with_inputs(8, {{h256(0x8c), 0}});
    lock.vout.push_back(txout(5000, p2pkh(ec_key(0x5b).id)));
    ASSERT_TRUE(mp.add_tx_skipping_contextual_check_for_test(lock));
    EXPECT_FALSE(mp.add_tx(with_out(servtx_r(w, 0, std::make_pair(txid(lock), 0u)))))
        << "IsUnorderableServiceUpdate: an asset lock ancestor";
    // A service update with no unconfirmed ancestor is admitted.
    EXPECT_TRUE(mp.add_tx(with_out(servtx_r(w, 0x8d))));
}

TEST(DashV24AllTx, BuilderPutsAServiceUpdateBeforeTheKeyChangeAndMatchesBlockConnect)
{
    V24World w;
    ::core::coin::UTXOViewCache utxo(nullptr);
    dash::coin::Mempool mp;
    mp.set_utxo(&utxo);
    const auto key_change = w.upreg_r(w.rop2.pub);
    const auto serv = servtx_r(w);
    utxo.add_coin(::core::coin::Outpoint(key_change.vin[0].prevout.hash, key_change.vin[0].prevout.index),
                  ::core::coin::Coin(1'000'000, script_of(p2pkh(ec_key(0x58).id)), 1, false));
    utxo.add_coin(::core::coin::Outpoint(serv.vin[0].prevout.hash, serv.vin[0].prevout.index),
                  ::core::coin::Coin(10'000, script_of(p2pkh(ec_key(0x59).id)), 1, false));
    // R's collateral (CheckProUpRegTx reads its coin).
    utxo.add_coin(::core::coin::Outpoint(w.regular.collateralOutpoint.hash, w.regular.collateralOutpoint.index),
                  ::core::coin::Coin(kColl, script_of(p2pkh(w.rcollat.id)), 1, false));
    ASSERT_TRUE(mp.add_tx(key_change));
    ASSERT_TRUE(mp.add_tx(serv));
    const auto sml = w.base_sml();
    dash::coin::QuorumManager qmgr;
    dash::coin::ProTxCheckEnv env;
    env.net = dash::coin::DashNetwork::MAINNET;
    env.ecdsa = &dash::coin::protx_ecdsa_verify_hash;
    const dash::coin::MnFoldContext::OperatorSigFn sigfn = &v::verify_protx_operator_sig;
    const auto wd = dash::coin::build_embedded_workdata(
        V24World::H - 1, h256(0xAB), w.sm, mp, 0x1b104be3u, 1'800'000'000u, 76, 16, 1'800'000'100u,
        0x20000000u, nullptr, &sml, &qmgr, 0, dash::coin::k_zero_cl_sig, 0, nullptr, nullptr,
        dash::coin::DASH_MN_RR_HEIGHT_MAINNET, nullptr, dash::coin::DASH_MN_MIN_CONFIRMATIONS_MAINNET,
        /*suppress=*/false, "utxo-immature-serving", nullptr, false, nullptr,
        /*include_mn_special_txs=*/true, nullptr, nullptr, &sigfn, /*v24_active=*/true, &env, nullptr);
    std::optional<size_t> at_serv, at_change;
    for (size_t i = 0; i < wd.m_tx_hashes.size(); ++i) {
        if (wd.m_tx_hashes[i] == txid(serv)) at_serv = i;
        if (wd.m_tx_hashes[i] == txid(key_change)) at_change = i;
    }
    ASSERT_TRUE(at_serv && at_change) << "both ride";
    EXPECT_LT(*at_serv, *at_change) << "the lower-fee service update goes first (Dash Core)";
    v::CCbTx cb;
    ASSERT_TRUE(v::parse_cbtx(wd.m_coinbase_payload, cb));
    std::vector<MutableTransaction> body;
    for (const auto& t : wd.m_txs) body.emplace_back(t);
    const auto r = w.connect(body, cb.merkleRootMNList, [&](const DmlFoldEngine& eng) {
        // The key change came last: the masternode is banned with its service
        // fields reset, not revived on the old operator's address.
        const auto* st = eng.find(w.R);
        ASSERT_NE(st, nullptr);
        EXPECT_NE(st->nPoSeBanHeight, -1);
    });
    EXPECT_TRUE(r.ok) << r.error;
}

// ── The node's wiring: the MNHF environment c2pool-dash builds
// (mnhf_node_env.hpp, called from main_dash) and the emit gate's MNHF and
// ProDisTx paths (NodeCoinState::embedded_template_emit_ok) ─────────────────

namespace {
struct FakeHeader {
    uint32_t height;
    uint256 hash;
};
struct FakeChain {
    std::map<uint256, uint32_t> heights;   // every header we know
    std::map<uint32_t, uint256> main;      // our main chain
    std::optional<FakeHeader> get_header(const uint256& h) const
    {
        const auto it = heights.find(h);
        if (it == heights.end()) return std::nullopt;
        return FakeHeader{it->second, h};
    }
    std::optional<FakeHeader> get_header_by_height(uint32_t height) const
    {
        const auto it = main.find(height);
        if (it == main.end()) return std::nullopt;
        return FakeHeader{height, it->second};
    }
};
struct FakeTracker {
    int64_t covered_to{0};
    int64_t verified{0};
    std::map<uint8_t, int64_t> signals;
    bool covers(int64_t prev) const { return prev <= covered_to; }
    int64_t verified_coverage() const { return verified; }
    int64_t signal_height(uint8_t bit, int64_t prev) const
    {
        const auto it = signals.find(bit);
        return it != signals.end() && it->second <= prev ? it->second : dash::coin::kNoSignalHeight;
    }
};
dash::coin::MnhfQuorumKeyFn tn_quorum_keys()
{
    return [](uint8_t type, const uint256& q) -> std::optional<std::array<uint8_t, 48>> {
        if (type == 1 && q == u256(kTnMnhfQuorum)) return arr_hex<48>(kTnMnhfQuorumKey);
        return std::nullopt;
    };
}
struct NodeMnhf {
    FakeChain chain;
    std::shared_ptr<FakeTracker> tracker = std::make_shared<FakeTracker>();
    std::shared_ptr<std::atomic<bool>> alive = std::make_shared<std::atomic<bool>>(true);
    NodeMnhf()
    {
        chain.heights[u256(kTnMnhfQuorum)] = 1'565'112;
        chain.main[1'565'112] = u256(kTnMnhfQuorum);
        tracker->covered_to = kTnMnhfPrev;
        tracker->verified = kTnMnhfPrev;
    }
    dash::coin::MnhfCheckEnv env() const
    {
        return dash::coin::make_node_mnhf_check_env(dash::coin::DashNetwork::TESTNET, &chain,
                                                    std::shared_ptr<const FakeTracker>(tracker),
                                                    std::shared_ptr<const std::atomic<bool>>(alive), tn_quorum_keys());
    }
};
}  // namespace

TEST(DashV24AllTx, NodeMnhfEnvironmentAcceptsTheRealSignalAndFailsClosed)
{
    const auto sig = tx_from_hex(kTnMnhf);
    {
        NodeMnhf n;
        const auto env = n.env();
        EXPECT_EQ(dash::coin::mnhf_tx_refusal(sig, &env, kTnMnhfPrev, kTnMnhfMtp), std::nullopt);
    }
    {   // the quorum block is on a fork of our chain
        NodeMnhf n;
        n.chain.main[1'565'112] = h256(0x99);
        const auto env = n.env();
        EXPECT_TRUE(dash::coin::mnhf_tx_refusal(sig, &env, kTnMnhfPrev, kTnMnhfMtp).has_value());
    }
    {   // the quorum block is above the parent
        NodeMnhf n;
        const auto env = n.env();
        EXPECT_TRUE(dash::coin::mnhf_tx_refusal(sig, &env, 1'565'100, kTnMnhfMtp).has_value());
    }
    {   // the header chain is torn down
        NodeMnhf n;
        const auto env = n.env();
        n.alive->store(false);
        EXPECT_TRUE(dash::coin::mnhf_tx_refusal(sig, &env, kTnMnhfPrev, kTnMnhfMtp).has_value());
    }
    {   // the tracker does not cover the parent with verified bodies
        NodeMnhf n;
        n.tracker->verified = kTnMnhfPrev - 1;
        const auto env = n.env();
        EXPECT_TRUE(dash::coin::mnhf_tx_refusal(sig, &env, kTnMnhfPrev, kTnMnhfMtp).has_value());
    }
    {   // the bit is already signalled at the parent
        NodeMnhf n;
        n.tracker->signals[13] = 1'565'000;
        const auto env = n.env();
        EXPECT_TRUE(dash::coin::mnhf_tx_refusal(sig, &env, kTnMnhfPrev, kTnMnhfMtp).has_value());
    }
    {   // an unknown quorum
        NodeMnhf n;
        const auto env = dash::coin::make_node_mnhf_check_env(
            dash::coin::DashNetwork::TESTNET, &n.chain, std::shared_ptr<const FakeTracker>(n.tracker),
            std::shared_ptr<const std::atomic<bool>>(n.alive),
            [](uint8_t, const uint256&) { return std::optional<std::array<uint8_t, 48>>{}; });
        EXPECT_TRUE(dash::coin::mnhf_tx_refusal(sig, &env, kTnMnhfPrev, kTnMnhfMtp).has_value());
    }
}

TEST(DashV24AllTx, EmitGateRechecksEveryMnhfSignalWithTheNodeEnvironment)
{
    const uint256 prev = h256(0xAB);
    std::vector<v::CSimplifiedMNListEntry> entries;
    for (uint8_t b : {0x01, 0x02}) {
        v::CSimplifiedMNListEntry e;
        e.nVersion = v::CSimplifiedMNListEntry::VER_BASIC_BLS;
        e.proRegTxHash = h256(b);
        e.confirmedHash = h256(0x77);
        e.isValid = true;
        entries.push_back(e);
    }
    const v::CSimplifiedMNList sml(std::move(entries));
    dash::coin::NodeCoinState st;
    st.set_require_sml(true);
    st.sml() = sml;
    st.set_have_sml(true);
    st.set_sml_current_hash(prev);
    st.set_tip(kTnMnhfPrev, prev, 0x1b104be3u, static_cast<uint32_t>(kTnMnhfMtp), 140, 19);
    dash::coin::DashWorkData w;
    w.m_coinbase_payload = dash::coin::encode_cbtx(dash::coin::build_embedded_cbtx(
        kTnMnhfPrev, sml, std::as_const(st).qmgr(), 0, std::array<uint8_t, 96>{}, 0, nullptr));
    dash::coin::DeclineReport plain_why;
    const bool plain_ok = st.embedded_template_emit_ok(w, &plain_why);

    const auto sig = tx_from_hex(kTnMnhf);
    auto with = w;
    with.m_txs.emplace_back(sig);
    dash::coin::DeclineReport why;
    EXPECT_FALSE(st.embedded_template_emit_ok(with, &why)) << "no environment wired: refused";
    EXPECT_EQ(why.cause, "emit-mnhf-refused");

    NodeMnhf n;
    st.set_mnhf_check_env(n.env());
    EXPECT_EQ(st.embedded_template_emit_ok(with, &why), plain_ok) << why.cause << " " << why.value;
    EXPECT_EQ(why.cause, plain_why.cause) << "a valid signal changes no verdict";

    auto twice = with;
    twice.m_txs.emplace_back(sig);
    EXPECT_FALSE(st.embedded_template_emit_ok(twice, &why));
    EXPECT_EQ(why.cause, "emit-mnhf-refused") << "a duplicate signal for the bit";

    auto forged = w;
    auto p = mnhf_payload_of(sig);
    p.signal.sig[5] ^= 0x01;
    forged.m_txs.emplace_back(with_payload(sig, p));
    EXPECT_FALSE(st.embedded_template_emit_ok(forged, &why));
    EXPECT_EQ(why.cause, "emit-mnhf-refused");

    n.tracker->signals[13] = 1'565'000;   // the node's tracker: already staged
    EXPECT_FALSE(st.embedded_template_emit_ok(with, &why));
    EXPECT_EQ(why.cause, "emit-mnhf-refused");
}

TEST(DashV24AllTx, EmitGateFoldsAProDisTxInsteadOfRefusingItsCollateralSpend)
{
    V24World w;
    const uint256 prev = h256(0xAB);
    ::core::coin::UTXOViewCache utxo(nullptr);
    dash::coin::NodeCoinState st;
    dash::coin::V24State v24 = dash::coin::V24State::ACTIVE;
    st.set_v24_state_fn([&v24](uint32_t) { return v24; });
    st.set_require_sml(true);
    st.sml() = w.base_sml();
    st.set_have_sml(true);
    st.set_sml_current_hash(prev);
    {
        // The operator-reward split of every listed masternode is known (the
        // emit gate proves the scheduled payee's split first).
        MNState shared = w.shared, regular = w.regular;
        shared.payoutSplitProvenance = MNState::SPLIT_KNOWN;
        regular.payoutSplitProvenance = MNState::SPLIT_KNOWN;
        st.mnstates().load({{w.S, shared}, {w.R, regular}}, V24World::H - 1);
    }
    st.set_include_mn_special_txs(true);
    dash::coin::ProTxCheckEnv env;
    env.net = dash::coin::DashNetwork::MAINNET;
    env.ecdsa = &dash::coin::protx_ecdsa_verify_hash;
    st.set_protx_check_env(env);
    const dash::coin::MnFoldContext::OperatorSigFn sigfn = &v::verify_protx_operator_sig;
    st.set_protx_operator_sig_verifier(sigfn);
    st.mempool().set_utxo(&utxo);
    st.set_tip(V24World::H - 1, prev, 0x1b104be3u, 1'800'000'000u, 76, 16, 1'800'000'100u, 0x20000000u);
    utxo.add_coin(::core::coin::Outpoint(w.S, 0),
                  ::core::coin::Coin(kColl, script_of(dash::coin::v24::shared_collateral_script()), 1, false));
    const auto dis = w.dissolve_tx();
    ASSERT_TRUE(st.mempool().add_tx(dis));
    const auto wd = dash::coin::build_embedded_workdata(
        V24World::H - 1, prev, std::as_const(st).mnstates(), st.mempool(), 0x1b104be3u,
        1'800'000'000u, 76, 16, 1'800'000'100u, 0x20000000u, nullptr, &std::as_const(st).sml(),
        &std::as_const(st).qmgr(), 0, dash::coin::k_zero_cl_sig, 0, nullptr, nullptr,
        dash::coin::DASH_MN_RR_HEIGHT_MAINNET, nullptr, dash::coin::DASH_MN_MIN_CONFIRMATIONS_MAINNET,
        /*suppress=*/false, "utxo-immature-serving", nullptr, false, nullptr,
        /*include_mn_special_txs=*/true, nullptr, nullptr, &sigfn, /*v24_active=*/true, &env, nullptr);
    bool rides = false;
    for (const auto& h : wd.m_tx_hashes) rides = rides || h == txid(dis);
    ASSERT_TRUE(rides);
    dash::coin::DeclineReport why;
    const bool ok = st.embedded_template_emit_ok(wd, &why);
    EXPECT_NE(why.cause, "emit-collateral-spend-in-template");
    EXPECT_TRUE(ok) << why.cause << " " << why.value << " / " << why.threshold;

    // Under the v24 fold a plain spend of the same collateral is still refused.
    auto spend = wd;
    auto plain = tx_with_inputs(0, {{w.S, 0}});
    plain.vout.push_back(txout(kColl - 1000, p2pkh(ec_key(0x5a).id)));
    spend.m_txs.emplace_back(plain);
    EXPECT_FALSE(st.embedded_template_emit_ok(spend, &why));
    EXPECT_EQ(why.cause, "emit-collateral-spend-in-template");

    // Without the v24 fold (lever off, or v24 not active) the ProDisTx is a
    // collateral spend like any other.
    st.set_include_mn_special_txs(false);
    EXPECT_FALSE(st.embedded_template_emit_ok(wd, &why));
    EXPECT_EQ(why.cause, "emit-collateral-spend-in-template");
    st.set_include_mn_special_txs(true);
    v24 = dash::coin::V24State::INACTIVE;
    EXPECT_FALSE(st.embedded_template_emit_ok(wd, &why));
    EXPECT_EQ(why.cause, "emit-collateral-spend-in-template");
}

// ════════════════════════════════════════════════════════════════════════════
// TYPE 1 VERSION 3: ProRegTx with ExtNetInfo, payout lists and shared
// collateral (CheckProRegTx, MakeSignString, MakeSharedRegConsentHash)
// ════════════════════════════════════════════════════════════════════════════

namespace {
struct RealProReg {
    uint32_t height;
    const char* txid;
    const char* hex;
    int64_t coll_value;        ///< the external collateral (0: internal)
    const char* coll_script;
};
// 14 version-3 ProRegTx mined on Dash testnet (Dash Core v24.0.0 accepted every one)
const RealProReg kTnProRegV3[] = {
    {1578168, "2770d2493755b59b3426474b2a18eb5c34df636530ae8059aa1fe4b22ce47c3c",
     "030001000106ad96cfe67c0fac8f4a54be91fe086c9da510bcf6456ee2554cf45018210f4e000000006a4730440220445ce1"
     "f55571ce9b924cb68f7857464bbc918c000c425de9f1ac49c43c470162022056c5481adf9282d90ff01398ffa7d0990e4f21"
     "b536195c538651c13fe8fa5a9a01210368037eedf9974ae19dbf7afad02f781ebf59b6e1ab07e9d27375604e0ae55e70feff"
     "ffff017fef0d00000000001976a9140f85adbdfdf6f484f433e3c756430b85297a97ab88ac00000000fd4701030001000000"
     "372ae26ee512d5fafde50b8411ca21080a868d55640cd4d1e5e1d5280f63593f010000000103000101010455d1f30a4e1f01"
     "0101010455d1f30a8f30020101010455d1f30a05a32351d825841fe0b86f5d5e9b4de6e50dfe831f9ab03a69e21639859a04"
     "48d9ad97ee33d9c7807adc1aba1791c759b87aa81b99d79c19ba8778cdda6533ce9f0534a8392f0c51904ec5f4eeeb8d54b4"
     "f7b43c67a9d7a202ff0000011976a914482551fcc51ba10000202e7d6a7938cba1cd28ef88ac102700000000000000000000"
     "00000029b0ac1ebdd8472b5d4dc4f628e4cb3e70167440e098871bec569eed8658abee0f4f47471c554804e4ab6ec7bf6fd2"
     "89c438c6e3411f95a5abeadb2a012c78337172a41c8315b5e9a9e38e458338689ce4edc4a6a12a79330d2ee5298a899a80d4"
     "ecf42e3501229a81e7f04592f43bccd8ce11b52fde"
     , 400000000000, "76a914cd6bf562acba01f16fd0bd5ace0730faf18ac05a88ac"},
    {1578185, "13ccca675ed8a8a788693f46191e7237e2896701ede3058c20263e1b2343923d",
     "03000100013c7ce42cb2e41faa5980ae306563df345ceb182a4b4726349bb5553749d27027000000006a47304402204f239b"
     "22bb793a2ad1f0da13269484b1f7644e8ac39dc8a71043e990215517f802202686ddde448a508ca41a032de1f05974b27440"
     "a2712a6039173c4d76422cffda01210368037eedf9974ae19dbf7afad02f781ebf59b6e1ab07e9d27375604e0ae55e70feff"
     "ffff0192ed0d00000000001976a9140f85adbdfdf6f484f433e3c756430b85297a97ab88ac00000000fd1d01030000000000"
     "f02bdee9b0c994f184b1e83a731b1c0b0afcecf3aa1dd5376be21ce535292199000000000101000101010455d1f32a4e1f50"
     "c455d6408cbe0ff9223ea627d7c1330587ec1e9321b7d8d72b12d10b413673a65b81d375bd0cc1b7f05f027d974d30209452"
     "167e577eddad6a76ac737d1563c659d1e1804d680fe032b74dd93132e8ffcfc10dcea976b00000011976a914482551fcc51b"
     "a10000202e7d6a7938cba1cd28ef88ac1027000000000000000000000000000e306067b2a7ea73fd4fa6cf4263241d7d7e2e"
     "ec1f9a3f74f6584b057eac8078411f760624efb2010edff7624e8e13ad95ab27d77e9b28cfd3a7e024cc6cfc6cf95b093c2a"
     "a7a91b2678cd7013028c434bd42efe0caf45bdd01c156b385501deea1e"
     , 100000000000, "76a914311f538ddddabc9c8240cf94448ebf9d4983d90888ac"},
    {1578200, "d39aaa53bcc166fbc21ffc0ffcd1bcf5c2474d160ec17dfb5e47a518138f2e95",
     "0300010001a02023fc7b98b6e01dd7cd0024734ec73abef4a2fa588dd3c50bf26820fa4b9f000000006a4730440220082cf0"
     "0d918e15454caf78f17bd91acef657c3610954d26a6422fc1bc6b5487b0220524a867b05f9faf578965c695221df77f04e41"
     "ffa564e8fdbf2f744a7ec0f47801210368037eedf9974ae19dbf7afad02f781ebf59b6e1ab07e9d27375604e0ae55e70feff"
     "ffff0130ea0d00000000001976a9140f85adbdfdf6f484f433e3c756430b85297a97ab88ac00000000fd1d01030000000000"
     "f02bdee9b0c994f184b1e83a731b1c0b0afcecf3aa1dd5376be21ce535292199000000000101000101010455d1f32a4e1fbd"
     "25254f6267904362b60b0a65705524ee303e489321b7d8d72b12d10b413673a65b81d375bd0cc1b7f05f027d974d30209452"
     "167e577eddad6a76ac737d1563c659d1e1a5f8e9b87827f988a28e63b164c52034b8ceef820000011976a914482551fcc51b"
     "a10000202e7d6a7938cba1cd28ef88ac102700000000000000000000000000f40540028448dae1d22e28d447889366dbc335"
     "3c6faf84b9f2ee0ae47522fd89411fb0af1ac43d2e854cd2107d125a27e7c9d9bf1a75043528ac81d817c49610205027f819"
     "650d6510c7c6af6eca407b2bccd2d8f521e24c511d200e10fd971b751b"
     , 100000000000, "76a914311f538ddddabc9c8240cf94448ebf9d4983d90888ac"},
    {1578200, "cc78a04fa5f9b8479f58f293994e3fc98423fa150c14a8e41d85f2bc104e0857",
     "0300010001952e8f1318a5475efb7dc10e164d47c2f5bcd1fc0ffc1fc2fb66c1bc53aa9ad3000000006a4730440220380800"
     "cc6ffcb5327d7e7a489b8a32fe2bd4c0efdf58eb53c7197acd08e9a2b402205fd4f41a0371e8c16fa0ae238b3633ebc48ab5"
     "afb3538d485e5ea605e782370401210368037eedf9974ae19dbf7afad02f781ebf59b6e1ab07e9d27375604e0ae55e70feff"
     "ffff012b860d00000000001976a9140f85adbdfdf6f484f433e3c756430b85297a97ab88ac00000000fd1d01030000000000"
     "0caea4ee528d83f58a941bc57fc7603a1a886b836753649130593f8f8759929d000000000101000101010455d1f32b4e1f25"
     "9485b40b1c57d5f94fb8fcf350c10e66c58c7aae6dba4a6b6c1fe9fb23ba8b22ff570bde267c0ad0542b1df45f64f931fcc0"
     "83850c95fae1f7bfd478f6ff3dbc87385cfa7a0d39c7aa1d2f8e7141b1dc37bcd149cde1a90000011976a914482551fcc51b"
     "a10000202e7d6a7938cba1cd28ef88ac10270000000000000000000000000001144a677157de4bbd04210c02398abcc7fb9f"
     "6e7f89fd7756bf02a2bce6324c411f99516ed7b26c257cb560bf757ba76a1d282088a39e7674a0f7b7345734eed9e8296e7e"
     "0edfe6cc0174be9048002cba4e8f205e1ec96753166da6bc69de0ff56f"
     , 100000000000, "76a91412ddfdbd796f3a26ec3e7e8f26a7d54d5b24264a88ac"},
    {1578200, "2c234e919880ba725a077b53deb939e8c9779978e032bfca00fc37e12141f1bf",
     "030001000157084e10bcf2851de4a8140c15fa2384c93f4e9993f2589f47b8f9a54fa078cc000000006a47304402207e34db"
     "a861ffd92f7b230dc07e83e57f472bfafb77c91e2a91657c051fbd3da102200a5d9fd28f48434a34b109e069de6592f32532"
     "02433425788dda34693ea2cb5901210368037eedf9974ae19dbf7afad02f781ebf59b6e1ab07e9d27375604e0ae55e70feff"
     "ffff0126220d00000000001976a9140f85adbdfdf6f484f433e3c756430b85297a97ab88ac00000000fd1d01030000000000"
     "69f8a23dd0fbbb7f6de42e93f3028c22067881df3e270adc9ef054bb4dd7a484010000000101000101010455d1f32c4e1fae"
     "4a31f86fde3e24b0b688d8656efd6e0b46553cb2b6553f221b16a34b996ae93343f1a0a085a106845f089c2d2258176b218a"
     "b6f5fe50acde73fbaf0f28039394bef24787e98c408cd1c718a9c4d0e37f826bf4bc4e90460000011976a914482551fcc51b"
     "a10000202e7d6a7938cba1cd28ef88ac102700000000000000000000000000b231738e4047b331162e5d80e57974a694ebb6"
     "e891a139889947f70a851f299941209ea72f7f30d6521beed7e79e3466b669b3ac48fc6dd26d56cc0bc95a5f4318e5484799"
     "38721781aa3606d6d2b8150dd15efcd912e594644d8372da3ca9f9434d"
     , 100000000000, "76a91456788e2d3fa8557fdbe6082edc6e632b0a61f1dd88ac"},
    {1578200, "5796b1c1325dbbd82754026a197ff08591ba993a61cb721ee2cc5dddfaea2a76",
     "0300010001bff14121e137fc00cabf32e0789977c9e839b9de537b075a72ba8098914e232c000000006a47304402203c1752"
     "5a6250191fb33bf862fa7e97c204ecdc363b9fb0a56f877a275eb40c0e0220770215fed5bcaf77a981321e0a83dcdf4d17c1"
     "cbdbd462662cfbd97cf42d169001210368037eedf9974ae19dbf7afad02f781ebf59b6e1ab07e9d27375604e0ae55e70feff"
     "ffff0136200d00000000001976a9140f85adbdfdf6f484f433e3c756430b85297a97ab88ac00000000fd1d01030000000000"
     "018f84918a63b06835bd5c7dd861f3aa37d304a7047c963d2aad8abbdec18557010000000101000101010455d1f32d4e1f93"
     "35adbd16fe044c6eb69bcc35a8908921d3c2bba98f8ca3644fe1055e2604556fcc8edb9d5191116fe2dac57d12a4afa3f2ce"
     "23b1aca5bcecd726e271987b86dca91581a0699323fe85451f4e0f6fc1335515a196f4e9230000011976a914482551fcc51b"
     "a10000202e7d6a7938cba1cd28ef88ac102700000000000000000000000000a69bbbfe22917beae9acaa4b4aaae352d49e3c"
     "12db9624cae733a7fc9d7cef2d411f39e1ce4de2ae12f94d4dffd1295d2e3c3e699f69ca6ca09cd5377f9103db664c63fd5b"
     "a03996ae4fdbb4d92728759d44aafb5f3ba8f5ecf0ed7e167c5d1feeb1"
     , 100000000000, "76a914f7a269ac33ca7b4600f46a4da29f0f99c4327c0088ac"},
    {1578200, "deededf9f0e219f4e29c49e5fc755f744a96de581f06702afd1141a9d3da888d",
     "0300010001762aeafadd5dcce21e72cb613a99ba9185f07f196a025427d8bb5d32c1b19657000000006a47304402207b5658"
     "c05425ce9fd0ee0a5f179118471f6bdf7dd4d3877bb22aed1f4b4b4dbc0220556ea0a9e326d55c94c0a38f8f459177026368"
     "7131e700d421c8c11bb786836801210368037eedf9974ae19dbf7afad02f781ebf59b6e1ab07e9d27375604e0ae55e70feff"
     "ffff01461e0d00000000001976a9140f85adbdfdf6f484f433e3c756430b85297a97ab88ac00000000fd1d01030000000000"
     "ba90abed762ded59448b1d09aa73e6fe08df6ccae2018c29c1db6bb6b61df6ba010000000101000101010455d1f32e4e1f1c"
     "f74738c6ee61981813a50e303e030c098f8aa79940ce35274814495ed1855e09650c016fde1dae932ec081c6a4c4e34910a3"
     "8cfda65cb4eeecfcb0129158a49d1cc081ca0f2acd4e483922b1bd27de9a25cc94b7cd70630000011976a914482551fcc51b"
     "a10000202e7d6a7938cba1cd28ef88ac1027000000000000000000000000009295c180078cd80287f728cf71ae6a61cbb81a"
     "dd9f668fb59b5fc9816ebb6a4241204a032f5e57cd84ae1abec59141ccabc3bfdda13c302ec338c96430b40d0ec7be586f9f"
     "773bd9159669c03e03e318b9401e3e7e11b77909f81ec8169e74469dba"
     , 100000000000, "76a914bbf8b0378966c0a3841bf71e34cea9f33269d36688ac"},
    {1580478, "e6a15d2538eaf448a585242846b2395160590516dfb66dec91405f9066746082",
     "0300010001d73d8f2aa62b70faafa1bec5b4a2c4bdd229e73951e67b35a68ed45909703a40010000006a473044022008470b"
     "eb3388effe1dd2c203bdce6f77ce2a31c24953864cdfb2f038b1410cb7022064b12897c06d2ea5257b88390a68f3be170629"
     "42e41ea341da126813a38bce1f012103373b1a2246e5c28ce99c49a927fa3f8823bb5e26d9b037ff1069dcae3ba4cf4afeff"
     "ffff01b683c35f000000001976a91418d05f474a776383ac3aebbfb978ae29da144ed088ac00000000fd1d01030000000000"
     "d73d8f2aa62b70faafa1bec5b4a2c4bdd229e73951e67b35a68ed45909703a4000000000010100010101044e1146af4dbb6e"
     "b549415b14aeec6f7cccb1105fc70a7fc91df4adad41e17d64581f58fcbc8dff2845a9a10c2e57db782dc5fd41a175729e59"
     "048dc3fb82d9f0620eeaac3eacadced01a4d29551a50fabceb0c248be984667982c4b7525d0000011976a9143c72c1973a46"
     "191e397a516d78d1532bc7641c3388ac102700000000000000000000000000835d813849142f78458d77771d56069e360761"
     "b2074d60954faf3b35737477484120447324ab63323f38783907e00a3838b2518a99213c4582c4d2da71fb2fc54245745ab1"
     "b4aed2af0284b11cd714bd89325f00772543ffb08483978c4dce22774d"
     , 100000000000, "76a9140dcd5182b7ec23f747af4113adf39404934f7b8788ac"},
    {1583312, "8699ef5afd141f7b02f170db4f4875468ace2f6c84c6889f3e0280633ba65f40",
     "03000100030e0caf8673c3e49b6d68085e300c4ad3ec5862772a2e3de20b1cc6d979282dbe010000006a473044022010975c"
     "2d0dfec5dd7b1c9ebcf4e19be30352c448bcdcfb24e70f8a2e5745d2890220406fd55e15b39e8b8dad2e5a3bdbe56461c1a8"
     "a6f907b94b396e32e62b8548e4012102d3cc14fbf267f63cbdd37e3d7c84f1dab6d6a798c5eceb76937f565570f585acffff"
     "ffffa56857866c0cee555fdee0506e8552ea3d3e4ad117641bab2c1212f2beecb387010000006a473044022060b0594b9845"
     "4a7458db667126a87f84f0f4288286a1fc71a91e7433734b126002203df71baf97923c050a8ca490912ea77fe12f51b0eb7d"
     "4a172cd913a643d0fd5c012102a664bd6871aa3371abfc32249f12816a44eb98c8ec668d7dcb47eec9627adb0dffffffff0e"
     "0caf8673c3e49b6d68085e300c4ad3ec5862772a2e3de20b1cc6d979282dbe000000006a47304402200165f5a76ae3c0cbc9"
     "5a85119ba9d21d1d8c9f6d627e8d74df6c52c67a40e3500220720916c462279af79c56a474f37ad1bd183c734c037774a878"
     "5b2c5483622fcd012103a35be6563f7004612c609478bc4be06b6d861893345b8fa1e2ed0942e3c39ca4ffffffff03ff68f9"
     "02000000001976a9142c876aed13e14bc54b3e83eae7d9847c5c04070f88ac80f0fa02000000001976a9147acd5755371a01"
     "4306bb5772ba738a56268782b788ac00e8764817000000070444534843755100000000fda501030000000000000000000000"
     "0000000000000000000000000000000000000000000000000000020000000100000000000000000000000000000000000000"
     "0000940c2f91e087567fa1ca3eb22a52ac374a0fc32f103e4bb31a8b1aaf3daf60085968adb4e0cf64033a8d0645393c97cc"
     "8217be2c828470a8d4d5ebbb7435a8f47c16106f90010002005847f80d0000001976a914370f5835c82007e82339b42ccfd7"
     "767ae6220ad288ac005c122f49bca30a387c8b851642482eb247ddca3700902f50090000001976a9149b46ddc48834306048"
     "5292c1ef17c92fbe0462c188ac005043a17f22496a934848fe6d93c679c3c85fc0dc20507720e8779ca1044e4df6c1b9f532"
     "ab9610c6fdb179d37fd42bd7ad36a9981e0f5c13cdcc739ef9bbe27d9e02b8d0e544240fbc89db2f33caba4dcbf1b86dd61f"
     "4ca65370c8ca51b8312582b3250bc65f501c3562d23702dd744f4eaa173ccb661a1572c7b0e157640dd5b351acbaeda417f1"
     "b9e12c79db56f3c2230d5169d18b50cd00000065cd1d000000008bb69fc51d1e6a923f701a10138e433109071435c9923695"
     "a5611cd141326a9300"
     , 0, ""},
    {1583318, "d400c12078251aa1320315a683291667beb3b585a5e0c2609919df27aab674e6",
     "0300010003d59915d74bfc1311cbb5208103efbc9fdcaf96211e88ab839147ad242cdef04f010000006a473044022072e815"
     "d3e8af27227e4daa26263f63b367cd38c299d7b246be89fdcbfd88800502206357510e053cb41c4e14ce168baab159f2784b"
     "10917641b11f3574c38aca82180121020f3d1e78c43f89e257cbbbed8340189a0645a4d50c2cd5b50aa0ae713952570bffff"
     "ffffd7e86481dd1292c15f21129b4f4e8efe0632002500d8398132c8d0e069d529c0000000006a47304402201bcd7bccfcb8"
     "61e905048a939f9300198968ae4fb60df06aaa3561b975fe75b7022066e7fff55f1af28c722c62e020f9c83d492aee8f45b1"
     "bb2136c3e7d02e4a2749012103744c5b210472ebac227f0102734d8b32cf28443ddaddebc1439b26c3229fa378ffffffffd5"
     "9915d74bfc1311cbb5208103efbc9fdcaf96211e88ab839147ad242cdef04f000000006a4730440220401e8dc002648c16ff"
     "9cd0f8d006aef0ff8784f2fa2a19ae5ee7c48e480a2a9e02207ecb5dc635ad4c779166fdc284f4f26190bc3291216a699510"
     "03fb78624b207a012102c6c36e455f2dc3dd1b0d961826a9a2b165e2595e18bb251c7b969c0011378b57ffffffff049efbd5"
     "17000000001976a9143ddbfe646ae560916b97090bd6ec87e64b31cbc988ac80f0fa02000000001976a914a30752ba4a5554"
     "d8df9af600b3ea6cb43173cdaf88ac80f0fa02000000001976a91475967a3560c6c59496f2c9a3f83757723712e25888ac00"
     "e8764817000000070444534843755100000000fd360203000000000000000000000000000000000000000000000000000000"
     "0000000000000000000003000000010000000000000000000000000000000000000000008ca1de0998a6d21724322b77bbe0"
     "adcb524c0aa276a6554a1fc66993b63aff8a327b5ebef76e83a6ccaeac3d9ff5f1c6e1b04c5aa15cf6e8b99fad36432e797e"
     "88a53f7b2c01000300743ba40b0000001976a91445510306394113374cd237d4836597e663093a1c88ac1976a91409a70500"
     "fb7388215fa644e1a3e9e6dba5fc104088ac4412220e39d5a7032c3b2de372c1ac102dbf21c300ac23fc060000001976a914"
     "44d7479df28a249959233f6bdf82c326eab52c3288ac002918436b02b5f0bb882525be98c4b95d16d4776100c817a8040000"
     "001976a914e40980a704c25b7f3f50cf9cde29aa59bf797d3e88ac00ddf7b3b70818bff7ceeaf36a9b5cc0821701403220b2"
     "eb13046d042ccbd7268c820dd792ae54ae0fe565c0b191298fb4f16f994c3128545104d2690f85db4b6a18c59afe54d0250e"
     "d19a31f08b727667f68e84aae820841b5fe4df2f50ed21c40780d5405b64a185109a8ce9611d705f906d33469cc717bd0ec5"
     "8760190ea800c44c6d71a593f4a329aba5bbc4e64ce59bd6bf250b171f86cc000e8fb8e8d218145b50dfe3ee486151326846"
     "c6e494e6990899044de0475534e7829f494bf82a250b485b768da6052aabb5922aa8d72f81574a12d5bc5650cd00000065cd"
     "1d00000000aae5c8bc130a76c2a3fc5bdcbe95ea8825456287b1e6449ae552682cb419132a00"
     , 0, ""},
    {1583595, "38c3acb9c3fb86efc51133ae2021167fb27f33e3021d1fe2771e83af009d8aa4",
     "03000100038a0460c967504640568ce4296e4b4808d74b68a48de8ec9ac447ae82218e03ae000000006a4730440220017742"
     "602349f39821c19df92f1659a03df0977823ea4cbb4a98ffe0a0aba24b0220543ac974133a92bedae803bbd838af8c157ed2"
     "9b4daab1247034e1858e7717b9012102516098f890254ff92a688f11436a9ef87d27eb9c73c5e02f89423c3bb5fb5088ffff"
     "ffffc49801ae6020cd711741382166f4d4faadb5bcd3f3683a904523bf3967abd4ab000000006a47304402201f4b8f21ddf2"
     "8e913d7a636c0d706d8dae80e91b70ef06e5f56d7288bab7360d0220483613dfda920fad3f2a95e8cf2eb9b0a7990622183a"
     "379d54acfaf535cdb0e70121020aaa32736c30906c919668c11c01bef2a00a9f29659142e92e1f80f465e8b0aaffffffffdb"
     "a275420c87fe99ebdba6d571d552bd8dd1a8a0b3ca0edd6fc440a91872e7d8000000006a47304402205854d480f6f94918a0"
     "99d230956e5ade2b90a97093b9e71a05a1c2f87c1977a4022053902c75cdc29278754a6c9eb4cdda4d7db42584eec71688b2"
     "cec03f8d4b9956012102113b590b512c4454c638ee25bba73a5308b2ee76628641980419ebc0bf5707ffffffffff0460331c"
     "d2050000001976a91446d25774d93ee47561b6f6fea535e8f9d17da8f188ac41d5117e030000001976a9145811b6a67b7b9a"
     "c28ba084d7faa3cfb130f1d9a688ac00f2052a010000001976a914833d8f904af19380b4d0bedf47c725d659bc533c88ac00"
     "e8764817000000070444534843755100000000fd1d0203000000000000000000000000000000000000000000000000000000"
     "0000000000000000000003000000010000000000000000000000000000000000000000008ff3e99f732d192b816f9d60e55d"
     "0d2631785a68da834d146627af6f098e452600e9da2c402b6e03667265c16b067f1151385c42acee7551d6713d1b99e12ba3"
     "31c195ec0000000300902f50090000001976a91459fc2f806811df7f532237302f31a8cf64f0f95488ac002c427cf9967fed"
     "4bcd2722f9c79e2af1dc9b7cea00ac23fc060000001976a914e4eddbdf18252c4daf075eac03d27430ba9cf65588ac00e13f"
     "9f592049230543ccc783113e58f5255d537700ac23fc060000001976a914a4bc8fc8828e3a7bc5b9438fb025b50d6f698eca"
     "88ac0027ebe0077a76112845d0e5de9d26b5b62a8a61f1201c1a3121118ae7252d2bc934ea967a5d724286eb4cb9fd614d9d"
     "72bf051756430db861b79dbbbbfc84d5ec780a1bb3d642b086663967809cf8414301a150caaf202d67d6db5eca69e9e05d22"
     "5758e87eda1d11c04eac7c0b3247bb898a5e4a2eb473feb71acf2e555b6d529497555627e5d781f0af25a58cc3a864fb8ecc"
     "49703d20f2d84ef88cb1685b20ec86aa735a3fea1316a965a70ed74d5b88edaf6895bec95da95918dc831b665050f1e339b4"
     "8c7f09909e819f285a7b599d30c88f445ee3000000000000000000000000497f4443078b89bfdf2ad706508c3cb8e803ccd8"
     "5143e3a32b10336cd247d54b00"
     , 0, ""},
    {1584322, "cebef3e9af512f18719a4aa1c2bcc4c1cf5da7fb7eaae17c24d72d3cadad1fe3",
     "0300010001cddf0b7d8512a8b1eddb39002e85d49b561f3f510fdbee48b5ef1bf2a9c84159010000006a47304402204c4a77"
     "1aed83336c09a0348103c73cc1f3f63c7a0e7d5c871857a0dcb8b4ea870220144792901084c847aeefe48d4139fff3189090"
     "c71aa36a0bec816f871eb8f13e01210389c2bc8088d56da1f940db47a0c25ba3fb53ffb540a7e347bd6b6275d4ab4bcffeff"
     "ffff015e2f023b000000001976a9144e0c37c67b0bf8d9cd52da576437a92379dfb40488ac00000000fd7c01030000000000"
     "cddf0b7d8512a8b1eddb39002e85d49b561f3f510fdbee48b5ef1bf2a9c841590200000001010004010104ae8a04a44e1f01"
     "02102a03b0c0000200f00000000239fe00014e1f010420b15cd27e875a564b870851f9ce38b3b6e511328c1fef72a0d3ada5"
     "f2ccd55e094e1f010520fe5410b0633359d63d4904d3206dcbb3d5e70f5cab66a17e764b27d39ec1f8ab0000b50a00d93b13"
     "b7d013093649f3a859f50d5ff41899c825dac0553e4ab11a441f9ceae265254303d9c8ad50c4cfc36211449613d7269307c7"
     "d94a6903e0818a25e6a5607f0f91f84ae1810a080a7f98db171a3c2ab2cb6fbb0000011976a914b8f54de7b6cfcece349aa8"
     "05a419e2fe0995222d88ac10270000000000000000000000000020264486082ff65f2f98161bdb416df35476eaa79968533e"
     "b0f30b4cc5fdd8d1411f311b95d46c37cecfb3354c95d3ddb408ea5671350cfcf3812644afd46896fa4351149901c5cc7327"
     "2b920a4967f4c0c328dffdc38041627b162135cedf5f2ccc"
     , 100000000000, "76a91461a82a9727542882bc1c9df8f37e66028b08689688ac"},
    {1584322, "144b9bce85bd4a31d119d885181c99ecbec80bebea851a7b60361bc68d21a6e2",
     "0300010001e31fadad3c2dd7247ce1aa7efba75dcfc1c4bcc2a14a9a71182f51afe9f3bece000000006a4730440220375550"
     "d818b6b98f2b21d141f92922f816e4e9c44d65fa80cb44f1d5446d39d302206541f6df74c9460474c5f3bc398dc7df9b1ac6"
     "cc1ad46bd6c85d61586996df7401210389c2bc8088d56da1f940db47a0c25ba3fb53ffb540a7e347bd6b6275d4ab4bcffeff"
     "ffff01602d023b000000001976a9144e0c37c67b0bf8d9cd52da576437a92379dfb40488ac00000000fd3201030000000000"
     "cddf0b7d8512a8b1eddb39002e85d49b561f3f510fdbee48b5ef1bf2a9c8415903000000010100020102102a03b0c0000200"
     "f00000000239fdf0014e1f0101049fdf0f2b4e1fca3dd1004050d6f229817d792a0751a0c5024a4c87216859888c548ce252"
     "013d67d7149ccd24a450afe1d08e12939da9c81d7c06bf6b0d1636358011badd715748db90e9369733a0b2ecea5d6dbae110"
     "3c77737a13fbb25b0000011976a914e82d5526fb89e1ceb924501878ae6e626179820a88ac10270000000000000000000000"
     "0000a802b31435682ac2c58b5e3c2a42f7495c1aa33752afffd110980dbc2bec74a7411f8640b6a35e3eacaad67fd28e9a4e"
     "23e2426537116e43cc698274f5784bf206f33f4f527df7db1bf6f73755066ab8ea6e32587827c055cf181940591055e7bdd9"
     , 100000000000, "76a91469fb0620c4d89b2598566ca8cf5a21337da9866b88ac"},
    {1584322, "5aeb3cad17caebd8f1392e4778eed3224808b691e9980c779974e8c36e139f49",
     "0300010001e2a6218dc61b36607b1a85eaeb0bc8beec991c1885d819d1314abd85ce9b4b14000000006a473044022036ef9c"
     "02e7045a0a0505b015e86ed2b564d416a18319b6ccee468c17407b1cf30220071c35f560c6b3721551426dbff42a1eca816b"
     "5899ddb6f30cf51d6e38421b5601210389c2bc8088d56da1f940db47a0c25ba3fb53ffb540a7e347bd6b6275d4ab4bcffeff"
     "ffff01f12a023b000000001976a9144e0c37c67b0bf8d9cd52da576437a92379dfb40488ac00000000fda301030001000000"
     "cddf0b7d8512a8b1eddb39002e85d49b561f3f510fdbee48b5ef1bf2a9c8415904000000010300020101049df54a294e1f01"
     "02102a03b0c0000200f00000000239fde0014e1f01020101049df54a298f300102102a03b0c0000200f00000000239fde001"
     "8f3002030101049df54a2905a30219657874616464722d746573742e74686570617374612e6f726701bb0102102a03b0c000"
     "0200f00000000239fde00101bbfcb919129c94cb91430f6d9423681a72ccd3327e8699a2bd842a175191e534503bd9732d28"
     "f8d3580a1d3f802c6e45ec33976942f5a5753d9cff216e4ca8e490b69abe0cd986a0d56669aeea96eb7b79ce798a0703a6a2"
     "9d0000011976a9149b339503e754f531b6a480721fcab361a9a8154688ac1027000000000000000000000000002490d47be1"
     "bf655e3f47692af5fa333bd0d2754316b99bde1705726e22bc27638fe66fc79f983de89e248b484cbf668169c40984412094"
     "aa779f87a7e9d8bd8ed6c856e0477739a33547f3cf46833eb7f02cfe9f21d22aea69ba931e8314cbc467381aa1fec1818967"
     "b18dc7ae4e41e50079da2fe5dd"
     , 400000000000, "76a914966aa4943c10bf59dafa1fe5b1a861d409d612ca88ac"},
};

dash::coin::ProTxCoinFn real_coin(const RealProReg& r, const MutableTransaction& tx)
{
    v::CProRegTx p;
    EXPECT_TRUE(v::parse_protx_payload(tx.extra_payload, p));
    const auto want = p.collateralOutpoint;
    const int64_t value = r.coll_value;
    const auto script = unhex(r.coll_script);
    return [want, value, script](const Outpoint& o, int64_t& v_out, std::vector<uint8_t>& s_out) {
        if (value == 0 || o.hash != want.hash || o.index != want.index) return ProTxCoinProof::Absent;
        v_out = value;
        s_out = script;
        return ProTxCoinProof::Unspent;
    };
}
std::optional<std::string> real_reg_check(const RealProReg& r, const MutableTransaction& tx, bool v24 = true,
                                          dash::coin::ProTxCoinFn coin = {})
{
    MnStateMachine pre;
    dash::coin::ProTxCheckEnv env;
    env.net = dash::coin::DashNetwork::TESTNET;
    return dash::coin::protx_core_refusal(tx, pre, dash::coin::protx_rules_for(env, r.height, v24),
                                          coin ? coin : real_coin(r, tx), &dash::coin::protx_ecdsa_verify_hash);
}
/// A testnet masternode no registration here touches.
MNState unrelated_testnet_mn()
{
    MNState st;
    st.nVersion = v::ProTxVersion::BASIC_BLS;
    st.nType = v::MnType::REGULAR;
    st.collateralOutpoint.hash = h256(0x5e);
    st.collateralOutpoint.index = 1;
    st.keyIDOwner = ec_key(0x6a).id;
    st.keyIDVoting = ec_key(0x6b).id;
    st.pubKeyOperator = bls_key(0x6c).pub;
    st.netInfo = ipv4(9, 9, 9, 9, 19999);
    st.scriptPayout = script_of(p2pkh(ec_key(0x6d).id));
    st.nRegisteredHeight = 1'500'000;
    st.isValid = true;
    return st;
}
}  // namespace

TEST(DashV24AllTx, RealTestnetProRegTxV3PassCheckProRegTx)
{
    size_t shared = 0, external = 0, evo = 0;
    for (const auto& r : kTnProRegV3) {
        const auto tx = tx_from_hex(r.hex);
        ASSERT_EQ(txid(tx), u256(r.txid));
        const auto why = real_reg_check(r, tx);
        EXPECT_FALSE(why.has_value()) << r.txid << " at " << r.height << ": " << *why;
        EXPECT_TRUE(real_reg_check(r, tx, /*v24=*/false).has_value()) << r.txid << ": version 3 before v24";
        v::CProRegTx p;
        ASSERT_TRUE(v::parse_protx_payload(tx.extra_payload, p));
        EXPECT_EQ(p.nVersion, v::ProTxVersion::EXT_ADDR);
        if (p.IsShared()) ++shared;
        if (!p.collateralOutpoint.hash.IsNull()) ++external;
        if (p.nType == v::MnType::EVO) ++evo;
    }
    EXPECT_EQ(std::size(kTnProRegV3), 14u);
    EXPECT_EQ(shared, 3u);
    EXPECT_EQ(external, 11u);
    EXPECT_EQ(evo, 2u);
}

TEST(DashV24AllTx, SharedRegistrationNeedsEveryShareOwnersConsent)
{
    size_t checked = 0;
    for (const auto& r : kTnProRegV3) {
        const auto tx = tx_from_hex(r.hex);
        v::CProRegTx p;
        ASSERT_TRUE(v::parse_protx_payload(tx.extra_payload, p));
        if (!p.IsShared()) continue;
        ++checked;
        ASSERT_EQ(p.vchJoinSigs.size(), p.shares.size());
        ASSERT_GE(p.shares.size(), 2u);
        // One share owner's signature altered.
        auto q = p;
        q.vchJoinSigs.back()[10] ^= 0x01;
        auto bad = tx;
        bad.extra_payload = pack_payload(q);
        EXPECT_CODE(real_reg_check(r, bad), "bad-protx-shares-sig");
        // The re-serialized payload is the mined one (the codec round-trips).
        EXPECT_EQ(pack_payload(p), tx.extra_payload);
        // An output the owners did not consent to (not the collateral).
        auto moved = tx;
        for (size_t i = 0; i < moved.vout.size(); ++i)
            if (i != p.collateralOutpoint.index) {
                moved.vout[i].value -= 1;
                break;
            }
        EXPECT_CODE(real_reg_check(r, moved), "bad-protx-shares-sig");
        // A sequence rewrite (BIP68 relative lock): also covered by the consent.
        auto seq = tx;
        seq.vin[0].sequence ^= 0x01;
        EXPECT_CODE(real_reg_check(r, seq), "bad-protx-shares-sig");
        // The collateral must be the template script.
        auto wrong = tx;
        wrong.vout[p.collateralOutpoint.index].scriptPubKey.m_data = p2pkh(ec_key(0x6e).id);
        EXPECT_CODE(real_reg_check(r, wrong), "bad-protx-shares-collateral-script");
        // An external signature is never allowed on internal collateral.
        auto signed_too = p;
        signed_too.vchSig = std::vector<uint8_t>(65, 0x1b);
        auto st = tx;
        st.extra_payload = pack_payload(signed_too);
        EXPECT_CODE(real_reg_check(r, st), "bad-protx-sig");
    }
    EXPECT_EQ(checked, 3u);
}

TEST(DashV24AllTx, ExternalCollateralV3SignsThePayoutList)
{
    size_t checked = 0;
    for (const auto& r : kTnProRegV3) {
        const auto tx = tx_from_hex(r.hex);
        v::CProRegTx p;
        ASSERT_TRUE(v::parse_protx_payload(tx.extra_payload, p));
        if (p.collateralOutpoint.hash.IsNull()) continue;
        ++checked;
        // The collateral key's message signature altered.
        auto q = p;
        q.vchSig[20] ^= 0x01;
        auto bad = tx;
        bad.extra_payload = pack_payload(q);
        EXPECT_CODE(real_reg_check(r, bad), "bad-protx-sig");
        // A collateral held by another key.
        const auto other_key = [&](const Outpoint& o, int64_t& v_out, std::vector<uint8_t>& s_out) {
            if (o.hash != p.collateralOutpoint.hash || o.index != p.collateralOutpoint.index)
                return ProTxCoinProof::Absent;
            v_out = r.coll_value;
            s_out = p2pkh(ec_key(0x6f).id);
            return ProTxCoinProof::Unspent;
        };
        EXPECT_CODE(real_reg_check(r, tx, true, other_key), "bad-protx-sig");
        // A collateral the UTXO view cannot prove: refused (fail closed).
        const auto unknown = [](const Outpoint&, int64_t&, std::vector<uint8_t>&) { return ProTxCoinProof::Unknown; };
        EXPECT_TRUE(real_reg_check(r, tx, true, unknown).has_value());
        // A payout paying the collateral key (IsPayoutListKeySafe, version 3).
        const auto pays_collateral = [&](const Outpoint& o, int64_t& v_out, std::vector<uint8_t>& s_out) {
            if (o.hash != p.collateralOutpoint.hash || o.index != p.collateralOutpoint.index)
                return ProTxCoinProof::Absent;
            v_out = r.coll_value;
            s_out = p.payouts[0].scriptPayout.m_data;
            return ProTxCoinProof::Unspent;
        };
        EXPECT_CODE(real_reg_check(r, tx, true, pays_collateral), "bad-protx-payee-reuse");
    }
    EXPECT_EQ(checked, 11u);
}

TEST(DashV24AllTx, RealTestnetProRegTxV3FoldsAndTheRootMatchesBlockConnect)
{
    const uint256 other = h256(0x5f);
    const MNState other_st = unrelated_testnet_mn();
    for (const auto& r : kTnProRegV3) {
        const auto tx = tx_from_hex(r.hex);
        const uint256 pro = txid(tx);
        MnStateMachine sm;
        sm.load({{other, other_st}}, r.height - 1);
        const std::vector<std::pair<uint256, ReplayMNState>> states = {{other, to_replay(other, other_st, h256(0x63))}};
        const v::CSimplifiedMNList base(std::vector<v::CSimplifiedMNListEntry>{states[0].second.to_sml_entry(other)});
        auto ctx = dash::coin::MnFoldContext::from(sm, {}, &v::verify_protx_operator_sig);
        ctx.require_core_check = true;
        ctx.core_check = [&r](const MutableTransaction& t) { return real_reg_check(r, t); };
        ctx.v24_rules = true;
        ctx.height = r.height;
        ctx.netinfo_rules = v::NetInfoRules::testnet();
        const auto fold = dash::coin::fold_mn_special_txs(base, std::vector<MutableTransaction>{tx}, &txid, ctx);
        EXPECT_EQ(fold.applied, 1u) << r.txid << ": "
                                    << (fold.refused_reasons.empty() ? std::string() : fold.refused_reasons[0]);
        FoldConfig cfg;
        cfg.enabled = true;
        cfg.gates = dash::coin::replay::FoldGates::testnet();
        cfg.gates.dip0003_enforcement_height = std::numeric_limits<int32_t>::max();
        DmlFoldEngine eng(cfg);
        eng.seed(states, 1, r.height - 1, h256(0x70), "testnet");
        const auto connect = eng.fold_block(block_of(r.height, eng.block_hash(), fold.sml.CalcMerkleRoot(), {tx}),
                                            r.height);
        EXPECT_TRUE(connect.ok) << r.txid << ": " << connect.error;
        const auto* st = eng.find(pro);
        ASSERT_NE(st, nullptr) << r.txid;
        EXPECT_EQ(st->nVersion, v::ProTxVersion::EXT_ADDR);
        // The same registration a second time in one body is a duplicate.
        const auto twice = dash::coin::fold_mn_special_txs(base, std::vector<MutableTransaction>{tx, tx}, &txid, ctx);
        EXPECT_EQ(twice.applied, 1u);
        EXPECT_EQ(twice.refused, 1u);
    }
}

TEST(DashV24AllTx, BuilderCarriesARealSharedRegistrationOnlyAtV24)
{
    V24World w;
    const RealProReg* r = nullptr;
    for (const auto& f : kTnProRegV3)
        if (std::string(f.txid) == "8699ef5afd141f7b02f170db4f4875468ace2f6c84c6889f3e0280633ba65f40") r = &f;
    ASSERT_NE(r, nullptr);
    const auto tx = tx_from_hex(r->hex);
    ::core::coin::UTXOViewCache utxo(nullptr);
    // Its funding coins, from testnet blocks 1,583,287-1,583,288.
    utxo.add_coin(::core::coin::Outpoint(u256("be2d2879d9c61c0be23d2e2a776258ecd34a0c305e08686d9be4c37386af0c0e"), 1),
                  ::core::coin::Coin(59'949'999'775, script_of(unhex("76a9147e043aa93e5160be7d0a9051af26727304fbbbc988ac")),
                                     1'583'288, false));
    utxo.add_coin(::core::coin::Outpoint(u256("87b3ecbef212122cab1b6417d14a3e3dea52856e50e0de5f55ee0c6c865768a5"), 1),
                  ::core::coin::Coin(100'000'000, script_of(unhex("76a91461c8a7a076a563357c2668c73a0f0f64882e607388ac")),
                                     1'583'287, false));
    utxo.add_coin(::core::coin::Outpoint(u256("be2d2879d9c61c0be23d2e2a776258ecd34a0c305e08686d9be4c37386af0c0e"), 0),
                  ::core::coin::Coin(40'050'000'000, script_of(unhex("76a914837502f9d1483f4a19b153da729c4e2e49691d3488ac")),
                                     1'583'288, false));
    dash::coin::Mempool mp;
    mp.set_utxo(&utxo);
    ASSERT_TRUE(mp.add_tx(tx));
    const auto sml = w.base_sml();
    dash::coin::QuorumManager qmgr;
    dash::coin::ProTxCheckEnv env;
    env.net = dash::coin::DashNetwork::TESTNET;
    env.ecdsa = &dash::coin::protx_ecdsa_verify_hash;
    const dash::coin::MnFoldContext::OperatorSigFn sigfn = &v::verify_protx_operator_sig;
    auto build = [&](bool v24) {
        return dash::coin::build_embedded_workdata(
            r->height - 1, h256(0xAB), w.sm, mp, 0x1b104be3u, 1'790'987'000u, 140, 19, 1'790'987'100u, 0x20000000u,
            nullptr, &sml, &qmgr, 0, dash::coin::k_zero_cl_sig, 0, nullptr, nullptr,
            dash::coin::DASH_MN_RR_HEIGHT_MAINNET, nullptr, dash::coin::DASH_MN_MIN_CONFIRMATIONS_MAINNET,
            /*suppress=*/false, "utxo-immature-serving", nullptr, false, nullptr,
            /*include_mn_special_txs=*/true, nullptr, nullptr, &sigfn, v24, &env, nullptr);
    };
    auto rides = [&](const dash::coin::DashWorkData& wd) {
        for (const auto& h : wd.m_tx_hashes)
            if (h == txid(tx)) return true;
        return false;
    };
    const auto at = build(true);
    ASSERT_TRUE(rides(at)) << "the shared registration (its template-script collateral output) rides under v24";
    v::CCbTx cb;
    ASSERT_TRUE(v::parse_cbtx(at.m_coinbase_payload, cb));
    EXPECT_NE(cb.merkleRootMNList, sml.CalcMerkleRoot()) << "the new masternode is in the committed root";
    std::vector<MutableTransaction> body;
    for (const auto& t : at.m_txs) body.emplace_back(t);
    const auto c = w.connect(body, cb.merkleRootMNList);
    EXPECT_TRUE(c.ok) << c.error;
    EXPECT_FALSE(rides(build(false))) << "before v24 a tx paying the template never rides";
}

#endif  // C2POOL_DASH_BLS
