// SPDX-License-Identifier: AGPL-3.0-or-later
/// Dash Core v23.1.8 delta, item B.8 — block-connect ProTx eviction.
///
/// dashd CTxMemPool::removeForBlock → removeProTxConflicts
/// (txmempool.cpp:985-1110 @ v23.1.9) drops the pending provider txs a
/// connected block invalidates. Without it a ProUpServTx signed with an
/// operator key that a mined ProUpRegTx/ProUpRevTx just replaced stays in our
/// pool (no dashd will ever mine it, so it never confirms) and every template
/// that carries it is bad-protx-sig. Mempool::remove_protx_conflicts_for_block
/// is that phase; the CoinStateMaintainer calls it with the PRE-block
/// collateral index before apply_block.

#include <gtest/gtest.h>

#include <impl/dash/coin/block.hpp>
#include <impl/dash/coin/mempool.hpp>
#include <impl/dash/coin/transaction.hpp>
#include <impl/dash/coin/utxo_adapter.hpp>
#include <impl/dash/coin/vendor/providertx.hpp>

#include <core/pack.hpp>
#include <core/uint256.hpp>

#include <array>
#include <cstdint>
#include <map>
#include <optional>
#include <vector>

namespace {

namespace v = dash::coin::vendor;
using dash::coin::BlockType;
using dash::coin::Mempool;
using dash::coin::MutableTransaction;
using dash::coin::dash_txid;
using bitcoin_family::coin::TxPrevOut;

uint256 h256(uint8_t tag)
{
    uint256 h;
    for (int i = 0; i < 32; ++i) h.data()[i] = static_cast<uint8_t>(tag ^ (i * 7));
    return h;
}
uint160 h160(uint8_t tag)
{
    uint160 h;
    for (int i = 0; i < 20; ++i) h.data()[i] = static_cast<uint8_t>(tag + i);
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
    p.collateralOutpoint = outpoint(static_cast<uint8_t>(0x40 + tag));
    p.netInfo.ip = seq<16>(static_cast<uint8_t>(0x10 + tag));
    p.netInfo.port_be = 9999;
    p.keyIDOwner = h160(static_cast<uint8_t>(0x20 + tag));
    p.pubKeyOperator = seq<48>(static_cast<uint8_t>(0x30 + tag));
    p.keyIDVoting = h160(static_cast<uint8_t>(0x50 + tag));
    p.scriptPayout.m_data = {0x76, 0xa9, 0x14, tag, 0x88, 0xac};
    p.inputsHash = h256(static_cast<uint8_t>(0x70 + tag));
    return p;
}
v::CProUpServTx proupserv(const uint256& mn, uint8_t tag)
{
    v::CProUpServTx p;
    p.nVersion = v::ProTxVersion::BASIC_BLS;
    p.nType    = v::MnType::REGULAR;
    p.proTxHash = mn;
    p.netInfo.ip = seq<16>(static_cast<uint8_t>(0x90 + tag));
    p.netInfo.port_be = 9999;
    p.inputsHash = h256(static_cast<uint8_t>(0xA0 + tag));
    return p;
}
v::CProUpRegTx proupreg(const uint256& mn, uint8_t key_tag)
{
    v::CProUpRegTx p;
    p.nVersion = v::ProTxVersion::BASIC_BLS;
    p.proTxHash = mn;
    p.pubKeyOperator = seq<48>(key_tag);
    p.keyIDVoting = h160(key_tag);
    p.scriptPayout.m_data = {0x76, 0xa9, 0x14, key_tag, 0x88, 0xac};
    p.inputsHash = h256(key_tag);
    return p;
}
v::CProUpRevTx prouprev(const uint256& mn)
{
    v::CProUpRevTx p;
    p.nVersion = v::ProTxVersion::BASIC_BLS;
    p.proTxHash = mn;
    p.nReason = v::CProUpRevTx::REASON_CHANGE_OF_KEYS;
    return p;
}

BlockType block_of(std::vector<MutableTransaction> txs)
{
    BlockType b;
    MutableTransaction cb;
    cb.version = 3; cb.type = 5;
    bitcoin_family::coin::TxIn in;
    in.prevout.hash.SetNull(); in.prevout.index = 0xFFFFFFFFu; in.sequence = 0xFFFFFFFFu;
    cb.vin.push_back(in);
    b.m_txs.push_back(cb);
    for (auto& t : txs) b.m_txs.push_back(std::move(t));
    return b;
}

/// The pre-block collateral index the maintainer hands over.
Mempool::CollateralOwnerFn owners(std::map<std::pair<uint256, uint32_t>, uint256> m)
{
    return [m](const TxPrevOut& op) -> std::optional<uint256> {
        auto it = m.find({op.hash, op.index});
        if (it == m.end()) return std::nullopt;
        return it->second;
    };
}

bool pooled(const Mempool& mp, const MutableTransaction& tx)
{
    return mp.get_entry(dash_txid(tx)).has_value();
}

const uint256 kX = h256(0xC1);   // a registered masternode
const uint256 kY = h256(0xC2);   // another one

} // namespace

// Rule 4: the mined ProUpRegTx replaces X's operator key, so a pending
// ProUpServTx(X) signed with the old key can never be mined again.
TEST(DashMempool, BlockWithProUpRegEvictsPendingUpdatesForThatMn)
{
    Mempool mp;
    auto pending = special(2, proupserv(kX, 1), 0x01);
    auto pending_rev = special(4, prouprev(kX), 0x02);
    ASSERT_TRUE(mp.add_tx(pending));
    ASSERT_TRUE(mp.add_tx(pending_rev));
    ASSERT_EQ(mp.size(), 2u);

    auto mined = special(3, proupreg(kX, 0xE0), 0x03);
    const size_t n = mp.remove_protx_conflicts_for_block(block_of({mined}), owners({}));
    EXPECT_EQ(n, 2u);
    EXPECT_EQ(mp.size(), 0u) << "pending updates of X must leave with the key change";
}

// Rule 5: a mined ProUpRevTx(X) clears X's operator key.
TEST(DashMempool, BlockWithProUpRevEvictsPendingUpdates)
{
    Mempool mp;
    auto serv = special(2, proupserv(kX, 2), 0x04);
    auto reg  = special(3, proupreg(kX, 0xE1), 0x05);
    ASSERT_TRUE(mp.add_tx(serv));
    ASSERT_TRUE(mp.add_tx(reg));
    auto mined = special(4, prouprev(kX), 0x06);
    mp.remove_protx_conflicts_for_block(block_of({mined}), owners({}));
    EXPECT_EQ(mp.size(), 0u);
}

// Rule 1: a mined tx spending X's collateral removes X, so pending updates of
// X go; a pending ProRegTx whose (external) collateral the block spends goes
// too (it is not an input of the ProRegTx, so the outpoint-conflict phase
// never sees it).
TEST(DashMempool, BlockSpendingTrackedCollateralEvictsPendingUpdatesAndRegistration)
{
    Mempool mp;
    const TxPrevOut x_coll = outpoint(0xD1);
    auto serv = special(2, proupserv(kX, 3), 0x07);
    auto reg  = proreg(1);                       // external collateral outpoint(0x41)
    auto regtx = special(1, reg, 0x08);
    ASSERT_TRUE(mp.add_tx(serv));
    ASSERT_TRUE(mp.add_tx(regtx));

    MutableTransaction spend;
    spend.version = 2;
    for (const auto& op : {x_coll, reg.collateralOutpoint}) {
        bitcoin_family::coin::TxIn in;
        in.prevout = op; in.sequence = 0xFFFFFFFFu;
        spend.vin.push_back(in);
    }
    bitcoin_family::coin::TxOut out; out.value = 5; out.scriptPubKey.m_data = {0x51};
    spend.vout.push_back(out);

    mp.remove_protx_conflicts_for_block(
        block_of({spend}), owners({{{x_coll.hash, x_coll.index}, kX}}));
    EXPECT_FALSE(pooled(mp, serv)) << "X's collateral is spent: X leaves the list";
    EXPECT_FALSE(pooled(mp, regtx)) << "the registration's collateral is spent";
    EXPECT_EQ(mp.size(), 0u);
}

// Rule 2: a mined ProRegTx takes its owner key, operator key, collateral,
// service and (Evo) platformNodeID — and owner keys and platformNodeIDs are
// ONE namespace (#7846).
TEST(DashMempool, BlockProRegTxEvictsDupOwnerOperatorCollateralPlatform)
{
    Mempool mp;
    auto mined_pl = proreg(2);
    mined_pl.nType = v::MnType::EVO;
    mined_pl.platformNodeID = h160(0x77);
    mined_pl.platformP2PPort = 26656;
    mined_pl.platformHTTPPort = 443;

    auto dup_owner = proreg(3);    dup_owner.keyIDOwner = mined_pl.keyIDOwner;
    auto dup_op    = proreg(4);    dup_op.pubKeyOperator = mined_pl.pubKeyOperator;
    auto dup_coll  = proreg(5);    dup_coll.collateralOutpoint = mined_pl.collateralOutpoint;
    auto dup_svc   = proreg(6);    dup_svc.netInfo = mined_pl.netInfo;
    auto owner_is_platform = proreg(7);
    owner_is_platform.keyIDOwner = mined_pl.platformNodeID;          // #7846
    auto evo_serv = proupserv(kY, 4);
    evo_serv.nType = v::MnType::EVO;
    evo_serv.platformNodeID = mined_pl.keyIDOwner;                    // #7846
    evo_serv.platformP2PPort = 26656;
    evo_serv.platformHTTPPort = 443;
    auto clean = proreg(8);                                          // shares nothing

    std::vector<MutableTransaction> pool = {
        special(1, dup_owner, 0x11), special(1, dup_op, 0x12),
        special(1, dup_coll, 0x13),  special(1, dup_svc, 0x14),
        special(1, owner_is_platform, 0x15), special(2, evo_serv, 0x16)};
    for (const auto& t : pool) ASSERT_TRUE(mp.add_tx(t));
    auto clean_tx = special(1, clean, 0x17);
    ASSERT_TRUE(mp.add_tx(clean_tx));

    mp.remove_protx_conflicts_for_block(block_of({special(1, mined_pl, 0x18)}), owners({}));
    for (size_t i = 0; i < pool.size(); ++i)
        EXPECT_FALSE(pooled(mp, pool[i])) << "conflict #" << i << " must be evicted";
    EXPECT_TRUE(pooled(mp, clean_tx)) << "an unrelated registration stays";
    EXPECT_EQ(mp.size(), 1u);
}

// Rule 2, #7489 block half: a mined ProRegTx re-registering the external
// collateral of MN X replaces X, so every pending update of X goes.
TEST(DashMempool, BlockProRegTxReusingCollateralEvictsUpdatesOfReplacedMn)
{
    Mempool mp;
    const TxPrevOut x_coll = outpoint(0xD2);
    auto serv = special(2, proupserv(kX, 5), 0x21);
    auto reg  = special(3, proupreg(kX, 0xE2), 0x22);
    ASSERT_TRUE(mp.add_tx(serv));
    ASSERT_TRUE(mp.add_tx(reg));

    auto mined = proreg(9);
    mined.collateralOutpoint = x_coll;
    mp.remove_protx_conflicts_for_block(
        block_of({special(1, mined, 0x23)}),
        owners({{{x_coll.hash, x_coll.index}, kX}}));
    EXPECT_EQ(mp.size(), 0u) << "X no longer exists after the re-registration";
}

// Control: provider txs the block does not touch stay.
TEST(DashMempool, UnrelatedProTxSurvivesBlock)
{
    Mempool mp;
    auto serv_y = special(2, proupserv(kY, 6), 0x31);
    auto reg_other = special(1, proreg(10), 0x32);
    ASSERT_TRUE(mp.add_tx(serv_y));
    ASSERT_TRUE(mp.add_tx(reg_other));
    auto mined = special(3, proupreg(kX, 0xE3), 0x33);
    EXPECT_EQ(mp.remove_protx_conflicts_for_block(
                  block_of({mined}), owners({{{h256(0xD3), 1}, kX}})),
              0u);
    EXPECT_TRUE(pooled(mp, serv_y));
    EXPECT_TRUE(pooled(mp, reg_other));
    EXPECT_EQ(mp.size(), 2u);
}

// S2 — the connected blocks' spent outpoints prove a coin spent: an external
// collateral spent by one of the last kRecentSpentBlocks blocks is Absent
// (the template fold then refuses a ProRegTx naming it, bad-protx-collateral),
// an untouched outpoint stays Unknown, and the proof ages out.
TEST(DashMempool, RecentlySpentOutpointsAreProvenAbsent)
{
    Mempool mp;
    const TxPrevOut c = outpoint(0xD7);
    MutableTransaction spend;
    spend.version = 2;
    bitcoin_family::coin::TxIn in;
    in.prevout = c; in.sequence = 0xFFFFFFFFu;
    spend.vin.push_back(in);
    bitcoin_family::coin::TxOut out; out.value = 5; out.scriptPubKey.m_data = {0x51};
    spend.vout.push_back(out);
    mp.remove_protx_conflicts_for_block(block_of({spend}), owners({}));

    ::core::coin::Coin coin;
    EXPECT_EQ(mp.prove_chain_coin(::core::coin::Outpoint(c.hash, c.index), coin),
              Mempool::CoinProof::Absent);
    const TxPrevOut other = outpoint(0xD8);
    EXPECT_EQ(mp.prove_chain_coin(::core::coin::Outpoint(other.hash, other.index), coin),
              Mempool::CoinProof::Unknown);

    for (size_t i = 0; i < Mempool::kRecentSpentBlocks; ++i)
        mp.remove_protx_conflicts_for_block(block_of({}), owners({}));
    EXPECT_EQ(mp.prove_chain_coin(::core::coin::Outpoint(c.hash, c.index), coin),
              Mempool::CoinProof::Unknown) << "the proof covers the last kRecentSpentBlocks blocks";
}
