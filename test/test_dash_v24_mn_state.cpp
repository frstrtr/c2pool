// SPDX-License-Identifier: AGPL-3.0-or-later
/// Dash Core v24 masternode state (slice S3): state transitions, the
/// shared-collateral and ProDisTx rules, and the persistence formats.
///
///   DashV24StateVersion*  SetStateVersion (payout migration, MnNetInfo <->
///                         ExtNetInfo conversion, the EvoNode refusal) and
///                         the per-type transitions on a bare state.
///   DashV24Covenant*      the shared-collateral template script 04445348437551
///                         (create and spend rules) with Core's codes.
///   DashV24ProDis*        CheckProDisTxForList: every reject code, the
///                         early-exit penalty floors, and monotone validity.
///   DashV24Formats*       MnStateDb format 3 (reads format 2 in place), the
///                         ReplayMNState / MNState row codecs (byte-identical
///                         below v3), MnStateDiff v24 fields and the diff
///                         store format, checkpoint /2 (and /1), the dashd v24
///                         seed JSON.
/// The fold-level KATs (root self-checked replay, the payee projection) are
/// in test_dash_replay_fold.cpp and test_dash_mn_state.cpp.

#include <gtest/gtest.h>

#include <impl/dash/coin/mn_checkpoint.hpp>
#include <impl/dash/coin/mn_checkpoint_dump.hpp>
#include <impl/dash/coin/mn_diff_store.hpp>
#include <impl/dash/coin/mn_seed.hpp>
#include <impl/dash/coin/mn_state_db.hpp>
#include <impl/dash/coin/replay_fold_engine.hpp>
#include <impl/dash/coin/replay_prestate.hpp>
#include <impl/dash/coin/v24_state.hpp>

#include <core/address_utils.hpp>

#include <core/leveldb_store.hpp>
#include <core/pack.hpp>

#include <nlohmann/json.hpp>

#include <cstring>
#include <filesystem>
#include <string>
#include <unistd.h>
#include <vector>

namespace {

namespace v = dash::coin::vendor;
namespace v24 = dash::coin::v24;
using dash::coin::MNState;
using dash::coin::MnStateV24Ext;
using dash::coin::replay::ReplayMNState;
using Bytes = std::vector<uint8_t>;
using Code = std::optional<std::string>;
Code C(const char* s) { return std::string(s); }

uint160 h160(uint8_t b) { uint160 h; for (int i = 0; i < 20; ++i) h.data()[i] = static_cast<uint8_t>(b + i); return h; }
uint256 h256(uint8_t b) { uint256 h; for (int i = 0; i < 32; ++i) h.data()[i] = static_cast<uint8_t>(b + i); return h; }
template <size_t N> std::array<uint8_t, N> seq(uint8_t b)
{
    std::array<uint8_t, N> a{};
    for (size_t i = 0; i < N; ++i) a[i] = static_cast<uint8_t>(b + i);
    return a;
}
OPScript p2pkh(const uint160& h)
{
    OPScript s;
    s.m_data = {0x76, 0xa9, 0x14};
    s.m_data.insert(s.m_data.end(), h.data(), h.data() + 20);
    s.m_data.push_back(0x88);
    s.m_data.push_back(0xac);
    return s;
}
v::LegacyNetService legacy4(uint8_t a, uint8_t b, uint8_t c, uint8_t d, uint16_t port)
{
    v::LegacyNetService l;
    l.ip[10] = 0xff; l.ip[11] = 0xff;
    l.ip[12] = a; l.ip[13] = b; l.ip[14] = c; l.ip[15] = d;
    l.port_be = port;
    return l;
}
v::ExtNetInfo ext_core(uint8_t a, uint8_t b, uint8_t c, uint8_t d, uint16_t port)
{
    v::ExtNetInfo e;
    e.set(v::NetInfoPurpose::CORE_P2P, {v::NetInfoEntry{v::NetService::ipv4(a, b, c, d, port)}});
    return e;
}
template <typename T> Bytes pack_bytes(const T& x)
{
    auto ps = ::pack(x);
    auto sp = ps.get_span();
    return Bytes(reinterpret_cast<const uint8_t*>(sp.data()), reinterpret_cast<const uint8_t*>(sp.data()) + sp.size());
}
const auto kMain = v::NetInfoRules::mainnet();

ReplayMNState v2_state()
{
    ReplayMNState st;
    st.nVersion = v::ProTxVersion::BASIC_BLS;
    st.keyIDOwner = h160(0x10);
    st.keyIDVoting = h160(0x20);
    st.pubKeyOperator = seq<48>(0x30);
    st.netInfo = legacy4(1, 2, 3, 4, 9999);
    st.scriptPayout = p2pkh(h160(0x40));
    st.collateralOutpoint.hash = h256(0x50);
    st.collateralOutpoint.index = 1;
    st.nRegisteredHeight = 100;
    return st;
}

v::CollateralShares two_shares()
{
    v::CCollateralShare a, b;
    a.amount = 600 * v::CCollateralShare::COIN;
    a.scriptRefund = p2pkh(h160(0x61));
    a.keyIDOwner = h160(0x71);
    b.amount = 400 * v::CCollateralShare::COIN;
    b.scriptRefund = p2pkh(h160(0x62));
    b.keyIDOwner = h160(0x72);
    return {a, b};
}

std::string fresh_dir(const char* name)
{
    const auto dir = std::filesystem::temp_directory_path()
                   / ("c2pool_v24_mn_state_" + std::string(name) + "_" + std::to_string(::getpid()));
    std::filesystem::remove_all(dir);
    std::filesystem::create_directories(dir);
    return (dir / "db").string();
}

} // namespace

// ═══════════════════════════════════════════════════════════════════════════
// SetStateVersion and the per-type transitions
// ═══════════════════════════════════════════════════════════════════════════

TEST(DashV24StateVersion, RaiseToThreeMigratesPayoutAndConvertsNetInfo)
{
    auto st = v2_state();
    const auto payout = st.scriptPayout;
    ASSERT_EQ(v24::set_state_version(st, 3, v::MnType::REGULAR, /*ext=*/false, kMain), std::nullopt);
    EXPECT_EQ(st.nVersion, 3);
    ASSERT_EQ(st.v24.payouts.size(), 1u);
    EXPECT_EQ(st.v24.payouts[0].scriptPayout, payout);
    EXPECT_EQ(st.v24.payouts[0].reward, 10000);
    EXPECT_TRUE(st.scriptPayout.m_data.empty());
    EXPECT_EQ(st.v24.extNetInfo, ext_core(1, 2, 3, 4, 9999));
    EXPECT_EQ(st.netInfo, v::LegacyNetService{});
    // An empty MnNetInfo converts to an empty ExtNetInfo ("01 00").
    auto e = v2_state();
    e.netInfo = {};
    ASSERT_EQ(v24::set_state_version(e, 3, v::MnType::REGULAR, false, kMain), std::nullopt);
    EXPECT_TRUE(e.v24.extNetInfo.IsEmpty());
    // Same version and kind: only the payout migration runs (Core's early return).
    auto same = v2_state();
    ASSERT_EQ(v24::set_state_version(same, 2, v::MnType::REGULAR, false, kMain), std::nullopt);
    EXPECT_EQ(same.netInfo, legacy4(1, 2, 3, 4, 9999));
    EXPECT_TRUE(same.v24.payouts.empty());
}

TEST(DashV24StateVersion, ConversionRefusals)
{
    // An EvoNode with a non-empty MnNetInfo cannot be raised (its Platform
    // ports would be lost): Core's bad-protx-netinfo-version.
    auto evo = v2_state();
    evo.platformP2PPort = 26656;
    EXPECT_EQ(v24::set_state_version(evo, 3, v::MnType::EVO, false, kMain), C("bad-protx-netinfo-version"));
    // A legacy address that is not a valid ExtNetInfo primary on mainnet.
    auto bad = v2_state();
    bad.netInfo = legacy4(1, 2, 3, 4, 19999);
    EXPECT_EQ(v24::set_state_version(bad, 3, v::MnType::REGULAR, false, kMain), C("bad-protx-netinfo-version"));
    auto priv = v2_state();
    priv.netInfo = legacy4(10, 0, 0, 1, 9999);
    EXPECT_EQ(v24::set_state_version(priv, 3, v::MnType::REGULAR, false, kMain), C("bad-protx-netinfo-version"));
    EXPECT_EQ(v24::set_state_version(priv, 3, v::MnType::REGULAR, false, v::NetInfoRules::regtest()), std::nullopt);
    // ExtNetInfo -> MnNetInfo carries one IPv4 entry, never two.
    auto two = v2_state();
    two.v24.extNetInfo = ext_core(1, 2, 3, 4, 9999);
    two.v24.extNetInfo.purposes[0].second.push_back(v::NetInfoEntry{v::NetService::ipv4(1, 2, 3, 5, 9999)});
    EXPECT_EQ(v24::set_state_version(two, 2, v::MnType::REGULAR, true, kMain), C("bad-protx-netinfo-version"));
    auto one = v2_state();
    one.v24.extNetInfo = ext_core(1, 2, 3, 4, 9999);
    ASSERT_EQ(v24::set_state_version(one, 2, v::MnType::REGULAR, true, kMain), std::nullopt);
    EXPECT_EQ(one.netInfo, legacy4(1, 2, 3, 4, 9999));
}

TEST(DashV24StateVersion, ProUpServTxTargetVersions)
{
    // v2 state + v3 ProUpServTx: raised to 3, payouts migrated, the payload's
    // ExtNetInfo kept; an EvoNode's scalar ports cleared.
    auto st = v2_state();
    v::CProUpServTx p3;
    p3.nVersion = 3;
    p3.extNetInfo = ext_core(5, 6, 7, 8, 9999);
    ASSERT_EQ(v24::apply_proupserv(st, p3, v::MnType::REGULAR, kMain).error, std::nullopt);
    EXPECT_EQ(st.nVersion, 3);
    EXPECT_EQ(st.v24.extNetInfo, ext_core(5, 6, 7, 8, 9999));
    EXPECT_EQ(st.v24.payouts.size(), 1u);
    // v3 state + v2 ProUpServTx: target stays 3, the legacy service is converted back.
    v::CProUpServTx p2;
    p2.nVersion = 2;
    p2.netInfo = legacy4(9, 9, 9, 9, 9999);
    ASSERT_EQ(v24::apply_proupserv(st, p2, v::MnType::REGULAR, kMain).error, std::nullopt);
    EXPECT_EQ(st.nVersion, 3);
    EXPECT_EQ(st.v24.extNetInfo, ext_core(9, 9, 9, 9, 9999));
    // Revive needs every key; a shared masternode counts as having an owner key.
    ReplayMNState shared;
    shared.pubKeyOperator = seq<48>(1);
    shared.keyIDVoting = h160(2);
    EXPECT_FALSE(v24::revive_allowed(shared));
    shared.v24.shares = two_shares();
    EXPECT_TRUE(v24::revive_allowed(shared));
}

TEST(DashV24StateVersion, RegistrarRevokeAndSharedTransitions)
{
    // ProUpRegTx v3 without a key change: payout list from the payload.
    auto st = v2_state();
    v::CProUpRegTx up;
    up.nVersion = 3;
    up.keyIDVoting = h160(0x21);
    v::MasternodePayoutShare a, b;
    a.scriptPayout = p2pkh(h160(0x81)); a.reward = 7000;
    b.scriptPayout = p2pkh(h160(0x82)); b.reward = 3000;
    up.payouts = {a, b};
    auto t = v24::apply_proupreg(st, up, v::MnType::REGULAR, /*changed=*/false, st.pubKeyOperator, kMain);
    ASSERT_EQ(t.error, std::nullopt);
    EXPECT_FALSE(t.ban);
    EXPECT_EQ(st.nVersion, 3);
    EXPECT_EQ(st.v24.payouts, up.payouts);
    EXPECT_EQ(st.keyIDVoting, h160(0x21));
    // ... with a key change: reset (empty ExtNetInfo), ban, new key, version kept.
    const auto newkey = seq<48>(0x90);
    t = v24::apply_proupreg(st, up, v::MnType::REGULAR, /*changed=*/true, newkey, kMain);
    ASSERT_EQ(t.error, std::nullopt);
    EXPECT_TRUE(t.ban);
    EXPECT_EQ(st.nVersion, 3);
    EXPECT_TRUE(st.v24.extNetInfo.IsEmpty());
    EXPECT_EQ(st.pubKeyOperator, newkey);
    // v2 state + v2 ProUpRegTx: stays a single script (target 2).
    auto s2 = v2_state();
    v::CProUpRegTx u2;
    u2.nVersion = 2;
    u2.keyIDVoting = h160(0x22);
    u2.scriptPayout = p2pkh(h160(0x83));
    ASSERT_EQ(v24::apply_proupreg(s2, u2, 0, false, s2.pubKeyOperator, kMain).error, std::nullopt);
    EXPECT_EQ(s2.nVersion, 2);
    EXPECT_EQ(s2.scriptPayout, p2pkh(h160(0x83)));
    EXPECT_TRUE(s2.v24.payouts.empty());
    // ProUpRegTx is refused for a shared masternode.
    auto sh = v2_state();
    sh.v24.shares = two_shares();
    EXPECT_EQ(v24::apply_proupreg(sh, up, 0, false, sh.pubKeyOperator, kMain).error, C("bad-protx-shared-mn"));

    // ProUpRevTx after v24 keeps the version (pre-v24 dropped it to 1).
    auto r2 = v2_state();
    v::CProUpRevTx rv;
    rv.nVersion = 2;
    rv.nReason = 2;
    t = v24::apply_prouprev(r2, rv, 0, kMain);
    ASSERT_EQ(t.error, std::nullopt);
    EXPECT_TRUE(t.ban);
    EXPECT_EQ(r2.nVersion, 2);
    EXPECT_EQ(r2.netInfo, v::LegacyNetService{});
    EXPECT_EQ(r2.nRevocationReason, 2);
    auto r1 = v2_state();
    r1.nVersion = 1;
    rv.nVersion = 1;
    ASSERT_EQ(v24::apply_prouprev(r1, rv, 0, kMain).error, std::nullopt);
    EXPECT_EQ(r1.nVersion, 1) << "a legacy state revoked by a legacy tx stays at 1";

    // ProUpShareTx / ProUpSharedRegTx.
    auto s = v2_state();
    s.nVersion = 3;
    s.netInfo = {};
    s.v24.extNetInfo = ext_core(1, 2, 3, 4, 9999);
    s.keyIDOwner = uint160{};
    s.v24.shares = two_shares();
    v::CProUpShareTx us;
    us.shareIndex = 1;
    us.scriptReward = p2pkh(h160(0x93));
    ASSERT_EQ(v24::apply_proupshare(s, us).error, std::nullopt);
    EXPECT_EQ(s.v24.shares[1].scriptReward, p2pkh(h160(0x93)));
    us.shareIndex = 2;
    EXPECT_EQ(v24::apply_proupshare(s, us).error, C("bad-proupshare-index"));
    us.shareIndex = 0;
    us.scriptReward = p2pkh(s.keyIDVoting);
    EXPECT_EQ(v24::apply_proupshare(s, us).error, C("bad-proupshare-payee-reuse"));
    auto ns = v2_state();
    EXPECT_EQ(v24::apply_proupshare(ns, us).error, C("bad-proupshare-index")) << "not shared";

    auto s3 = v2_state();
    s3.nVersion = 3;
    s3.netInfo = {};
    s3.v24.extNetInfo = ext_core(1, 2, 3, 4, 9999);
    s3.v24.shares = two_shares();
    v::CProUpSharedRegTx sr;
    sr.keyIDVoting = h160(0x23);
    t = v24::apply_proupsharedreg(s3, sr, 0, /*changed=*/true, seq<48>(0xa0), kMain);
    ASSERT_EQ(t.error, std::nullopt);
    EXPECT_TRUE(t.ban);
    EXPECT_EQ(s3.nVersion, 3) << "the shared state version is restored after the reset";
    EXPECT_TRUE(s3.v24.extNetInfo.IsEmpty());
    EXPECT_EQ(s3.pubKeyOperator, seq<48>(0xa0));
    sr.keyIDVoting = s3.v24.shares[0].keyIDOwner;   // fine: owner keys are not voting-checked
    sr.keyIDVoting = h160(0x61);                     // == share 0's refund destination
    auto s4 = s3;
    EXPECT_EQ(v24::apply_proupsharedreg(s4, sr, 0, false, s4.pubKeyOperator, kMain).error,
              C("bad-proupsharedreg-payee-reuse"));
    auto plain = v2_state();
    EXPECT_EQ(v24::apply_proupsharedreg(plain, sr, 0, false, plain.pubKeyOperator, kMain).error,
              C("bad-proupsharedreg-not-shared"));
}

// ═══════════════════════════════════════════════════════════════════════════
// Shared-collateral covenant
// ═══════════════════════════════════════════════════════════════════════════

TEST(DashV24Covenant, TemplateScriptCreateAndSpendRules)
{
    using dash::coin::MutableTransaction;
    EXPECT_EQ(v24::shared_collateral_script(), (std::vector<uint8_t>{0x04, 0x44, 0x53, 0x48, 0x43, 0x75, 0x51}));
    bitcoin_family::coin::TxOut tmpl;
    tmpl.value = 1000 * v::CCollateralShare::COIN;
    tmpl.scriptPubKey.m_data = v24::shared_collateral_script();

    // A plain tx paying the template: bad-shared-collateral-create.
    MutableTransaction plain;
    plain.vout.push_back(tmpl);
    EXPECT_EQ(v24::shared_collateral_create_refusal(plain), C("bad-shared-collateral-create"));
    // A shared ProRegTx naming that output as its internal collateral: valid.
    MutableTransaction reg;
    reg.version = 3;
    reg.type = 1;
    bitcoin_family::coin::TxOut change;
    change.value = 5;
    change.scriptPubKey = p2pkh(h160(1));
    reg.vout = {change, tmpl};
    v::CProRegTx p;
    p.nVersion = 3;
    p.collateralOutpoint.index = 1;
    p.shares = two_shares();
    p.vchJoinSigs.resize(2);
    reg.extra_payload = v::serialize_special_payload(p);
    EXPECT_EQ(v24::shared_collateral_create_refusal(reg), std::nullopt);
    // ... at another index, external, or not shared: refused.
    p.collateralOutpoint.index = 0;
    reg.extra_payload = v::serialize_special_payload(p);
    EXPECT_EQ(v24::shared_collateral_create_refusal(reg), C("bad-shared-collateral-create"));
    p.collateralOutpoint.index = 1;
    p.collateralOutpoint.hash = h256(9);
    reg.extra_payload = v::serialize_special_payload(p);
    EXPECT_EQ(v24::shared_collateral_create_refusal(reg), C("bad-shared-collateral-create"));
    p.collateralOutpoint.hash = uint256{};
    p.shares.clear();
    p.vchJoinSigs.clear();
    reg.extra_payload = v::serialize_special_payload(p);
    EXPECT_EQ(v24::shared_collateral_create_refusal(reg), C("bad-shared-collateral-create"));
    // The coinbase too (the rule covers every tx).
    MutableTransaction cb;
    cb.version = 3;
    cb.type = 5;
    cb.vout.push_back(tmpl);
    EXPECT_EQ(v24::shared_collateral_create_refusal(cb), C("bad-shared-collateral-create"));

    // Spends: only a ProDisTx may spend a template output.
    bitcoin_family::coin::TxIn in;
    in.prevout.hash = h256(0x33);
    in.prevout.index = 0;
    MutableTransaction spend;
    spend.vin.push_back(in);
    auto lookup = [](const bitcoin_family::coin::TxPrevOut& o) -> std::optional<std::vector<uint8_t>> {
        if (o.index == 0) return v24::shared_collateral_script();
        return std::nullopt;
    };
    EXPECT_EQ(v24::shared_collateral_spend_refusal(spend, false, lookup), C("bad-shared-collateral-spend"));
    spend.version = 3;
    spend.type = 10;
    EXPECT_EQ(v24::shared_collateral_spend_refusal(spend, false, lookup), std::nullopt);
    MutableTransaction other;
    in.prevout.index = 1;
    other.vin.push_back(in);
    EXPECT_EQ(v24::shared_collateral_spend_refusal(other, false, lookup), std::nullopt);
}

// ═══════════════════════════════════════════════════════════════════════════
// ProDisTx (CheckProDisTxForList) and the early-exit penalty
// ═══════════════════════════════════════════════════════════════════════════

namespace {
struct Dis {
    v::CollateralShares shares;
    v24::ProDisTarget mn;
    dash::coin::MutableTransaction tx;
    v::CProDisTx p;
    Dis()
    {
        const int64_t COIN = v::CCollateralShare::COIN;
        v::CCollateralShare a, b, c;
        a.amount = 500 * COIN; a.scriptRefund = p2pkh(h160(0x11)); a.keyIDOwner = h160(0x21);
        b.amount = 300 * COIN; b.scriptRefund = p2pkh(h160(0x12)); b.keyIDOwner = h160(0x22);
        c.amount = 200 * COIN; c.scriptRefund = p2pkh(h160(0x13)); c.keyIDOwner = h160(0x23);
        shares = {a, b, c};
        mn.exists = true;
        mn.shared = true;
        mn.collateral.hash = h256(0x44);
        mn.collateral.index = 1;
        mn.shares = &shares;
        mn.registered_height = 1000;
        mn.early_period_blocks = 100;
        mn.early_penalty = 10 * COIN;
        bitcoin_family::coin::TxIn in;
        in.prevout = mn.collateral;
        tx.version = 3;
        tx.type = 10;
        tx.vin = {in};
        p.actorIndex = 0;   // unilateral by share 0
        p.vchSigs.resize(1);
    }
    void outputs(int64_t bonus_b, int64_t bonus_c, int64_t actor)
    {
        tx.vout.clear();
        bitcoin_family::coin::TxOut ob, oc, oa;
        ob.value = shares[1].amount + bonus_b; ob.scriptPubKey = shares[1].scriptRefund;
        oc.value = shares[2].amount + bonus_c; oc.scriptPubKey = shares[2].scriptRefund;
        tx.vout = {ob, oc};
        if (actor >= 0) {
            oa.value = actor;
            oa.scriptPubKey = shares[0].scriptRefund;
            tx.vout.push_back(oa);
        }
    }
    Code check(int64_t h) const
    {
        auto target = mn;
        target.shares = &shares;   // this object's own table (copies keep their own)
        return v24::prodis_list_refusal(tx, p, target, h);
    }
};
} // namespace

TEST(DashV24ProDis, EarlyPenaltyFloorsAndMonotoneValidity)
{
    const int64_t COIN = v::CCollateralShare::COIN;
    Dis d;
    // Inside the early period a unilateral exit owes 10 DASH, split
    // pro rata over the other shares: 300:200 -> 6 and 4 DASH.
    d.outputs(6 * COIN, 4 * COIN, 500 * COIN - 10 * COIN - 1000);
    EXPECT_EQ(d.check(1050), std::nullopt);
    d.outputs(6 * COIN - 1, 4 * COIN + 1, 500 * COIN - 10 * COIN - 1000);
    EXPECT_EQ(d.check(1050), C("bad-prodis-penalty-floor"));
    // After the early period no penalty is owed.
    d.outputs(0, 0, 500 * COIN - 1000);
    EXPECT_EQ(d.check(1050), C("bad-prodis-penalty-floor"));
    EXPECT_EQ(d.check(1100), std::nullopt);
    // Monotone: valid at h stays valid at every later height.
    d.outputs(6 * COIN, 4 * COIN, 500 * COIN - 10 * COIN - 1000);
    for (int64_t h = 1001; h <= 1300; ++h)
        ASSERT_EQ(d.check(h), std::nullopt) << h;
    // Unanimous: no penalty owed even early, and no bonus ceiling.
    d.p.vchSigs.resize(3);
    d.outputs(0, 0, 500 * COIN - 1000);
    EXPECT_EQ(d.check(1001), std::nullopt);
    d.outputs(20 * COIN, 0, 480 * COIN - 1000);
    EXPECT_EQ(d.check(1001), std::nullopt) << "unanimous bonuses are consented";
    // ProRataFloor uses a 128-bit intermediate.
    EXPECT_EQ(v24::pro_rata_floor(4'000 * COIN, 3'999 * COIN, 4'000 * COIN), 3'999 * COIN);
    EXPECT_EQ(v24::pro_rata_floor(10, 1, 3), 3);
}

TEST(DashV24ProDis, RejectCodes)
{
    const int64_t COIN = v::CCollateralShare::COIN;
    auto valid = [&] { Dis d; d.outputs(6 * COIN, 4 * COIN, 500 * COIN - 10 * COIN - 1000); return d; };
    {
        Dis d = valid();
        d.mn.exists = false;
        EXPECT_EQ(d.check(1050), C("bad-prodis-hash"));
    }
    {
        Dis d = valid();
        d.mn.shared = false;
        EXPECT_EQ(d.check(1050), C("bad-prodis-not-shared"));
    }
    {
        Dis d = valid();
        d.tx.vin[0].prevout.index = 2;
        EXPECT_EQ(d.check(1050), C("bad-prodis-input"));
        d = valid();
        d.tx.vin[0].scriptSig.m_data = {0x51};
        EXPECT_EQ(d.check(1050), C("bad-prodis-input")) << "non-empty scriptSig";
        d = valid();
        d.tx.vin.push_back(d.tx.vin[0]);
        EXPECT_EQ(d.check(1050), C("bad-prodis-input"));
    }
    {
        Dis d = valid();
        d.p.actorIndex = 3;
        EXPECT_EQ(d.check(1050), C("bad-prodis-actor"));
    }
    {
        Dis d = valid();
        d.p.vchSigs.resize(2);
        EXPECT_EQ(d.check(1050), C("bad-prodis-sig-count"));
    }
    {
        Dis d = valid();
        d.tx.vout.pop_back();
        d.tx.vout.pop_back();
        EXPECT_EQ(d.check(1050), C("bad-prodis-payee-count"));
    }
    {
        Dis d = valid();
        d.tx.vout[0].scriptPubKey = p2pkh(h160(0x99));
        EXPECT_EQ(d.check(1050), C("bad-prodis-payee"));
        d = valid();
        d.tx.vout[2].scriptPubKey = p2pkh(h160(0x99));
        EXPECT_EQ(d.check(1050), C("bad-prodis-payee")) << "actor output";
    }
    {
        Dis d;
        d.outputs(6 * COIN, 4 * COIN, 0);
        EXPECT_EQ(d.check(1050), C("bad-prodis-actor-output-zero"));
    }
    {
        // Floors met but the sum short: 10 DASH over 3:1 shares with duff
        // remainders; force the sum below the penalty with exact floors.
        Dis d;
        d.shares[1].amount = 1;
        d.shares[2].amount = 2;
        d.mn.early_penalty = 10;
        // floors: floor(10*1/3)=3, floor(10*2/3)=6, sum 9 < 10.
        d.outputs(3, 6, 500 * COIN - 1000);
        EXPECT_EQ(d.check(1050), C("bad-prodis-penalty-sum"));
        d.outputs(4, 6, 500 * COIN - 1000);
        EXPECT_EQ(d.check(1050), std::nullopt);
    }
    {
        Dis d;
        d.outputs(6 * COIN, 4 * COIN, 500 * COIN - 10 * COIN - v::CProDisTx::MAX_FEE - 1);
        EXPECT_EQ(d.check(1050), C("bad-prodis-fee"));
    }
    {
        Dis d;
        d.outputs(7 * COIN, 4 * COIN, 500 * COIN - 11 * COIN - 1000);
        EXPECT_EQ(d.check(1050), C("bad-prodis-bonus")) << "unilateral bonus above the penalty";
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Formats
// ═══════════════════════════════════════════════════════════════════════════

TEST(DashV24Formats, StateCodecsAreUnchangedBelowV3)
{
    // ReplayMNState: a v1/v2 state encodes exactly as the pre-v24 layout
    // (the diff store rows and v3/v4 snapshots), a v3 state appends its block.
    auto st = v2_state();
    st.v24.payouts.push_back({});   // ignored below v3: not on the wire
    Bytes base;
    {
        ::PackStream ps;
        ReplayMNState::Base::Write(ps, st);
        auto sp = ps.get_span();
        base.assign(reinterpret_cast<const uint8_t*>(sp.data()), reinterpret_cast<const uint8_t*>(sp.data()) + sp.size());
    }
    EXPECT_EQ(pack_bytes(st), base);
    auto s3 = v2_state();
    s3.nVersion = 3;
    s3.netInfo = {};
    s3.v24.extNetInfo = ext_core(1, 2, 3, 4, 9999);
    s3.v24.shares = two_shares();
    s3.v24.nEarlyPeriodBlocks = 50;
    s3.v24.nEarlyPenalty = 7;
    const Bytes b3 = pack_bytes(s3);
    EXPECT_EQ(b3.size(), pack_bytes(s3.v24).size()
                         + [&] { ::PackStream ps; ReplayMNState::Base::Write(ps, s3); return ps.size(); }());
    ::PackStream in(b3);
    ReplayMNState back;
    in >> back;
    EXPECT_TRUE(in.empty());
    EXPECT_EQ(back, s3);
    // MNState: same rule; a pre-v24 (format 3) row reads with unserialize_pre_v24.
    MNState m;
    m.nVersion = 2;
    m.scriptPayout = p2pkh(h160(5));
    const Bytes m2 = pack_bytes(m);
    ::PackStream pm(m2);
    MNState mb;
    mb.unserialize_pre_v24(pm);
    EXPECT_TRUE(pm.empty());
    EXPECT_EQ(mb, m);
    m.nVersion = 3;
    m.v24.payouts.push_back({});
    ::PackStream pm3(pack_bytes(m));
    MNState mb3;
    pm3 >> mb3;
    EXPECT_EQ(mb3, m);
}

TEST(DashV24Formats, MnStateDbReadsFormat3InPlaceAndClearsFormat2)
{
    const std::string dir = fresh_dir("statedb");
    MNState m;
    m.nVersion = 2;
    m.scriptPayout = p2pkh(h160(5));
    {
        dash::coin::MnStateDb db(dir);
        ASSERT_TRUE(db.open());
        ASSERT_TRUE(db.write_all({{h256(1), m}}, h256(9), 100));
    }
    {   // rewrite the format key to 3, as a pre-v24 binary (P-3) left it
        ::core::LevelDBStore raw(dir, {});
        ASSERT_TRUE(raw.open());
        raw.put("F", {0x03, 0x00, 0x00, 0x00});
        raw.close();
    }
    {
        dash::coin::MnStateDb db(dir);
        ASSERT_TRUE(db.open());
        std::vector<std::pair<uint256, MNState>> out;
        ASSERT_TRUE(db.load_all(out));
        ASSERT_EQ(out.size(), 1u) << "format-3 rows survive the upgrade";
        EXPECT_EQ(out[0].second, m);
        EXPECT_EQ(db.get_best_height(), 100u);
    }
    {   // a format-3 store holding a v3 row it could not complete: cleared
        ::core::LevelDBStore raw(dir, {});
        ASSERT_TRUE(raw.open());
        MNState v3 = m;
        v3.nVersion = 3;
        ::PackStream ps;
        MNState::Base::Write(ps, v3);
        auto sp = ps.get_span();
        std::string key(1, 'M');
        key.append(reinterpret_cast<const char*>(h256(2).data()), 32);
        raw.put(key, std::vector<uint8_t>(reinterpret_cast<const uint8_t*>(sp.data()),
                                          reinterpret_cast<const uint8_t*>(sp.data()) + sp.size()));
        raw.put("F", {0x03, 0x00, 0x00, 0x00});
        raw.close();
    }
    {
        dash::coin::MnStateDb db(dir);
        ASSERT_TRUE(db.open());
        std::vector<std::pair<uint256, MNState>> out;
        db.load_all(out);
        EXPECT_TRUE(out.empty()) << "cleared for a reseed";
    }
    {   // a format-2 store (mixed operator-key encodings, P-3): cleared
        dash::coin::MnStateDb db(dir);
        ASSERT_TRUE(db.open());
        ASSERT_TRUE(db.write_all({{h256(1), m}}, h256(9), 100));
    }
    {
        ::core::LevelDBStore raw(dir, {});
        ASSERT_TRUE(raw.open());
        raw.put("F", {0x02, 0x00, 0x00, 0x00});
        raw.close();
    }
    {
        dash::coin::MnStateDb db(dir);
        ASSERT_TRUE(db.open());
        std::vector<std::pair<uint256, MNState>> out;
        db.load_all(out);
        EXPECT_TRUE(out.empty()) << "a format-2 store is cleared for a reseed";
    }
}

TEST(DashV24Formats, StateDiffV24FieldsAndStoreFormat)
{
    using dash::coin::replay::MnStateDiff;
    auto a = v2_state();
    auto b = a;
    ASSERT_EQ(v24::set_state_version(b, 3, 0, false, kMain), std::nullopt);
    b.v24.payouts[0].reward = 10000;
    const MnStateDiff d(a, b);
    EXPECT_TRUE(d.fields & MnStateDiff::Field_nVersion);
    EXPECT_TRUE(d.fields & MnStateDiff::Field_netInfo);
    EXPECT_TRUE(d.fields & MnStateDiff::Field_payouts);
    EXPECT_TRUE(d.fields & MnStateDiff::Field_scriptPayout);
    ::PackStream ps;
    d.write_to(ps);
    MnStateDiff back;
    back.read_from(ps);
    auto t = a;
    back.apply_to(t);
    EXPECT_EQ(t, b) << "a v2 -> v3 raise round-trips through a diff record";
    // Share-table and early-term bits.
    auto c = b;
    c.v24.shares = two_shares();
    c.v24.nEarlyPeriodBlocks = 9;
    c.v24.nEarlyPenalty = 3;
    const MnStateDiff d2(b, c);
    EXPECT_EQ(d2.fields, MnStateDiff::Field_shares | MnStateDiff::Field_nEarlyPeriodBlocks
                         | MnStateDiff::Field_nEarlyPenalty);
    // A pre-v24 record (no v24 bits, v2 netInfo) is unchanged.
    auto e = a;
    e.netInfo = legacy4(4, 3, 2, 1, 9999);
    const MnStateDiff d3(a, e);
    EXPECT_EQ(d3.fields, MnStateDiff::Field_nVersion | MnStateDiff::Field_netInfo);
    ::PackStream p3;
    d3.write_to(p3);
    EXPECT_EQ(p3.size(), 3u + 2 + 18) << "CompactSize(0x1001) + nVersion + 18-byte service";

    // The store reads a format-1 store in place.
    const std::string dir = fresh_dir("diffstore");
    {
        dash::coin::replay::MnDiffStore store(dir);
        ASSERT_TRUE(store.open());
    }
    {
        ::core::LevelDBStore raw(dir, {});
        ASSERT_TRUE(raw.open());
        raw.put("F", {0x01, 0x00, 0x00, 0x00});
        raw.put("Sxyz", {0x01});   // any row: a mismatching format would clear it
        raw.close();
    }
    {
        dash::coin::replay::MnDiffStore store(dir);
        ASSERT_TRUE(store.open());
    }
    {
        ::core::LevelDBStore raw(dir, {});
        ASSERT_TRUE(raw.open());
        std::vector<uint8_t> f, srow;
        ASSERT_TRUE(raw.get("F", f));
        EXPECT_EQ(f, (std::vector<uint8_t>{0x02, 0x00, 0x00, 0x00}));
        EXPECT_TRUE(raw.get("Sxyz", srow)) << "format 1 -> 2 keeps the rows";
        raw.close();
    }
}

TEST(DashV24Formats, CheckpointFormat2AndFormat1)
{
    // Build a set holding one v2 and one v3 masternode and dump it.
    std::map<uint256, MNState> set;
    MNState a;
    a.nVersion = 2;
    a.collateralOutpoint.hash = h256(0x50);
    a.collateralOutpoint.index = 1;
    a.scriptPayout = p2pkh(h160(5));
    a.keyIDOwner = h160(6);
    a.keyIDVoting = h160(7);
    a.pubKeyOperator = seq<48>(8);
    a.nRegisteredHeight = 10;
    MNState b = a;
    b.nVersion = 3;
    b.collateralOutpoint.hash = h256(0x51);
    b.scriptPayout = OPScript{};
    v::MasternodePayoutShare po;
    po.scriptPayout = p2pkh(h160(9));
    b.v24.payouts = {po};
    b.v24.extNetInfo = ext_core(1, 2, 3, 4, 9999);
    set[h256(1)] = a;
    set[h256(2)] = b;
    const auto dump = dash::coin::emit_mn_checkpoint_dump(set, 2'600'000, h256(0x77), "mainnet", "kat", "2026-11-06T00:00:00Z");
    ASSERT_TRUE(dump.ok) << dump.error;
    EXPECT_EQ(dump.payload.rfind("c2pool-dash-mn-checkpoint/2\n", 0), 0u);
    const auto cp = dash::coin::parse_mn_checkpoint(dump.payload, "mainnet");
    ASSERT_TRUE(cp.ok) << cp.error;
    ASSERT_EQ(cp.entries.size(), 2u);
    for (const auto& [pro, mn] : cp.entries) {
        EXPECT_EQ(mn.nVersion, set.at(pro).nVersion);
        EXPECT_EQ(mn.scriptPayout, set.at(pro).scriptPayout);
        EXPECT_EQ(mn.v24, set.at(pro).v24);
    }
    // A set with no v3 state is still written as /1 (and parses as before).
    set.erase(h256(2));
    const auto d1 = dash::coin::emit_mn_checkpoint_dump(set, 2'600'000, h256(0x77), "mainnet", "kat", "2026-11-06T00:00:00Z");
    ASSERT_TRUE(d1.ok) << d1.error;
    EXPECT_EQ(d1.payload.rfind("c2pool-dash-mn-checkpoint/1\n", 0), 0u);
    EXPECT_TRUE(dash::coin::parse_mn_checkpoint(d1.payload, "mainnet").ok);
}

TEST(DashV24Formats, SeedReadsDashCoreV24StateJson)
{
    // dashd v24 `protx list registered true` rows: a v3 state with payouts,
    // a shared one with shares, and a v2 one with payoutAddress.
    const std::string payout_hex = "76a914" + std::string(40, 'a') + "88ac";
    const std::string refund_hex = "76a914" + std::string(40, 'b') + "88ac";
    auto addr = [](uint8_t fill) {
        uint160 h;
        std::memset(h.data(), fill, 20);
        return core::script_to_address(p2pkh(h).m_data, "", 0x8c, 0x13);   // testnet P2PKH
    };
    nlohmann::json list = nlohmann::json::array();
    list.push_back({{"proTxHash", std::string(64, '1')}, {"collateralHash", std::string(64, 'c')},
                    {"collateralIndex", 0}, {"operatorReward", 0}, {"type", "Regular"},
                    {"state", {{"version", 3}, {"registeredHeight", 5}, {"lastPaidHeight", 0},
                               {"PoSeRevivedHeight", -1}, {"PoSeBanHeight", -1}, {"consecutivePayments", 0},
                               {"revocationReason", 0},
                               {"payouts", nlohmann::json::array({{{"address", "x"}, {"script", payout_hex}, {"reward", 10000}}})}}}});
    list.push_back({{"proTxHash", std::string(64, '2')}, {"collateralHash", std::string(64, 'd')},
                    {"collateralIndex", 1}, {"operatorReward", 0}, {"type", "Regular"},
                    {"state", {{"version", 3}, {"registeredHeight", 6}, {"lastPaidHeight", 0},
                               {"PoSeRevivedHeight", -1}, {"PoSeBanHeight", -1}, {"consecutivePayments", 0},
                               {"revocationReason", 0}, {"earlyPeriodBlocks", 100}, {"earlyPenalty", 5},
                               {"shares", nlohmann::json::array({
                                   {{"amount", 60000000000LL}, {"refundScript", refund_hex}, {"rewardScript", refund_hex}, {"ownerAddress", addr(0x11)}},
                                   {{"amount", 40000000000LL}, {"refundScript", payout_hex}, {"rewardScript", payout_hex}, {"ownerAddress", addr(0x22)}}})}}}});
    list.push_back({{"proTxHash", std::string(64, '3')}, {"collateralHash", std::string(64, 'e')},
                    {"collateralIndex", 2}, {"operatorReward", 0}, {"type", "Regular"},
                    {"state", {{"version", 2}, {"registeredHeight", 7}, {"lastPaidHeight", 0},
                               {"PoSeRevivedHeight", -1}, {"PoSeBanHeight", -1}, {"consecutivePayments", 0},
                               {"revocationReason", 0}, {"payoutAddress", addr(0x33)}}}});
    dash::coin::MnSeedStats st;
    const auto rows = dash::coin::parse_protx_list_seed(list, 0x8c, 0x13, &st);
    ASSERT_EQ(rows.size(), 3u) << "payout_decode_failed=" << st.payout_decode_failed;
    std::map<std::string, MNState> by;
    for (const auto& [h, mn] : rows) by[h.GetHex()] = mn;
    const auto& p = by.at(std::string(64, '1'));
    ASSERT_EQ(p.v24.payouts.size(), 1u);
    EXPECT_EQ(p.v24.payouts[0].reward, 10000);
    EXPECT_TRUE(p.scriptPayout.m_data.empty());
    const auto& s = by.at(std::string(64, '2'));
    ASSERT_EQ(s.v24.shares.size(), 2u);
    EXPECT_EQ(s.v24.shares[1].amount, 40000000000LL);
    EXPECT_EQ(s.v24.shares[0].keyIDOwner, [] { uint160 h; std::memset(h.data(), 0x11, 20); return h; }());
    EXPECT_EQ(s.v24.nEarlyPeriodBlocks, 100u);
    EXPECT_EQ(s.v24.nEarlyPenalty, 5);
    EXPECT_EQ(by.at(std::string(64, '3')).scriptPayout.m_data.size(), 25u);
    // A v3 state without payouts/shares aborts the seed (fail closed).
    list[0]["state"].erase("payouts");
    EXPECT_TRUE(dash::coin::parse_protx_list_seed(list, 0x8c, 0x13).empty());
}

TEST(DashV24Formats, ReplayPrestateFormat2CarriesAV3State)
{
    // One v3 masternode in prestate /2; seeding must reproduce the root the
    // header commits (the seed self-check).
    auto st = v2_state();
    st.nVersion = 3;
    st.netInfo = {};
    st.v24.extNetInfo = ext_core(1, 2, 3, 4, 9999);
    st.v24.payouts = v::legacy_payout_as_list(st.scriptPayout);
    st.scriptPayout = OPScript{};
    st.confirmedHash = h256(0x66);
    const uint256 pro = h256(0x77);
    auto whex = [](const uint8_t* p, size_t n) {
        static const char* d = "0123456789abcdef";
        std::string s;
        for (size_t i = 0; i < n; ++i) { s += d[p[i] >> 4]; s += d[p[i] & 15]; }
        return s;
    };
    const Bytes blob = pack_bytes(st.v24);
    std::vector<v::CSimplifiedMNListEntry> leaf{st.to_sml_entry(pro)};
    const uint256 root = v::CSimplifiedMNList(std::move(leaf)).CalcMerkleRoot();
    std::string row = "mn " + whex(pro.data(), 32) + " " + whex(st.confirmedHash.data(), 32) + " "
                    + std::string(32, '0') + " 0 " + whex(st.pubKeyOperator.data(), 48) + " "
                    + whex(st.keyIDVoting.data(), 20) + " " + whex(st.keyIDOwner.data(), 20)
                    + " 3 0 - 0 0 0 - - 100 0 0 0 -1 -1 0 " + whex(st.collateralOutpoint.hash.data(), 32)
                    + " 1 0 " + whex(blob.data(), blob.size());
    const std::string text = std::string("c2pool-dash-replay-prestate/2\n") + "network mainnet\nheight 100\n"
                           + "blockhash " + h256(9).GetHex() + "\nmnroot " + root.GetHex() + "\ncount 1\n" + row + "\n";
    const auto ps = dash::coin::replay::parse_prestate_text(text);
    ASSERT_TRUE(ps.ok) << ps.error;
    ASSERT_EQ(ps.entries.size(), 1u);
    EXPECT_EQ(ps.entries[0].second.v24, st.v24);
    dash::coin::replay::FoldConfig cfg;
    cfg.enabled = true;
    dash::coin::replay::DmlFoldEngine eng(cfg);
    EXPECT_EQ(dash::coin::replay::seed_engine_from_prestate(eng, ps), "");
    // The same row under /1 is refused (a /1 row cannot hold the payout list).
    std::string t1 = text;
    t1.replace(0, std::string("c2pool-dash-replay-prestate/2").size(), "c2pool-dash-replay-prestate/1");
    t1.erase(t1.rfind(' '), std::string::npos);
    t1 += "\n";
    EXPECT_FALSE(dash::coin::replay::parse_prestate_text(t1).ok);
}
