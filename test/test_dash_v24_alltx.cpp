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
#include <impl/dash/coin/protx_check.hpp>
#include <impl/dash/coin/protx_ecdsa.hpp>
#include <impl/dash/coin/quorum_manager.hpp>
#include <impl/dash/coin/replay_fold_engine.hpp>
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

#endif  // C2POOL_DASH_BLS
