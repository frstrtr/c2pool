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

// S3 — rule 4 is dashd's removeProTxKeyChangedConflicts(X, hash(newKey)):
// a pending ProUpServTx carries the NULL validForProTxKey (txmempool.cpp sets
// it only for ProUpRegTx / ProUpRevTx, :686/:694; txmempool.h:178) and is
// evicted by any mined ProUpRegTx(X); a pending ProUpRegTx / ProUpRevTx(X)
// survives a mined ProUpRegTx that leaves the key's bytes unchanged, and is
// evicted when they change.
TEST(DashMempool, BlockProUpRegTxKeepsUpdatesValidForAnUnchangedOperatorKey)
{
    const std::array<uint8_t, 48> key = seq<48>(0xE5);
    auto run = [&](const std::array<uint8_t, 48>& held_bytes) {
        Mempool mp;
        auto serv = special(2, proupserv(kX, 7), 0x41);
        auto reg  = special(3, proupreg(kX, 0xE6), 0x42);   // payout/voting change pending
        auto rev  = special(4, prouprev(kX), 0x43);
        EXPECT_TRUE(mp.add_tx(serv));
        EXPECT_TRUE(mp.add_tx(reg));
        EXPECT_TRUE(mp.add_tx(rev));
        auto mined_pl = proupreg(kX, 0xE5);                 // carries `key`
        mp.remove_protx_conflicts_for_block(
            block_of({special(3, mined_pl, 0x44)}), owners({}),
            [held_bytes](const uint256& pro) -> std::optional<std::array<uint8_t, 48>> {
                if (pro == kX) return held_bytes;
                return std::nullopt;
            });
        return std::array<bool, 3>{pooled(mp, serv), pooled(mp, reg), pooled(mp, rev)};
    };
    const auto same = run(key);
    EXPECT_FALSE(same[0]) << "a pending ProUpServTx is evicted by any mined ProUpRegTx (dashd)";
    EXPECT_TRUE(same[1]) << "the operator key did not change: the pending ProUpRegTx stays";
    EXPECT_TRUE(same[2]) << "the operator key did not change: the pending ProUpRevTx stays";
    const auto changed = run(seq<48>(0x70));
    EXPECT_FALSE(changed[0]);
    EXPECT_FALSE(changed[1]) << "the key changed: validForProTxKey no longer matches";
    EXPECT_FALSE(changed[2]);
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

// A reorg takes back the spends of the blocks it disconnected: a ProRegTx
// naming such an outpoint as external collateral is dashd-valid on the new
// chain and must not be refused on the old chain's word. An outpoint the
// surviving chain spends as well stays proven.
TEST(DashMempool, ReorgForgetsTheSpendsOfDisconnectedBlocks)
{
    auto spend_of = [](const TxPrevOut& op, uint32_t salt) {
        MutableTransaction tx;
        tx.version = 2;
        tx.locktime = salt;
        bitcoin_family::coin::TxIn in;
        in.prevout = op; in.sequence = 0xFFFFFFFFu;
        tx.vin.push_back(in);
        bitcoin_family::coin::TxOut out; out.value = 5; out.scriptPubKey.m_data = {0x51};
        tx.vout.push_back(out);
        return tx;
    };
    auto proof = [](const Mempool& mp, const TxPrevOut& op) {
        ::core::coin::Coin coin;
        return mp.prove_chain_coin(::core::coin::Outpoint(op.hash, op.index), coin);
    };
    using Proof = Mempool::CoinProof;
    const TxPrevOut kept = outpoint(0xD1), orphaned = outpoint(0xD2), both = outpoint(0xD3);
    const uint256 h100 = h256(0x60), a101 = h256(0x61), b101 = h256(0x62);

    Mempool mp;
    mp.remove_protx_conflicts_for_block(block_of({spend_of(kept, 1)}), owners({}), {},
                                        Mempool::ChainPos{100, h100});
    mp.remove_protx_conflicts_for_block(
        block_of({spend_of(orphaned, 2), spend_of(both, 3)}), owners({}), {},
        Mempool::ChainPos{101, a101});
    mp.remove_protx_conflicts_for_block(block_of({spend_of(both, 4)}), owners({}), {},
                                        Mempool::ChainPos{101, b101});
    EXPECT_EQ(proof(mp, kept), Proof::Absent);
    EXPECT_EQ(proof(mp, orphaned), Proof::Absent);
    EXPECT_EQ(proof(mp, both), Proof::Absent);

    // The active chain after the reorg: 100 -> h100, 101 -> b101, nothing above.
    auto active = [&](uint32_t h) -> std::optional<uint256> {
        if (h == 100) return h100;
        if (h == 101) return b101;
        return std::nullopt;
    };
    EXPECT_EQ(mp.forget_chain_spends_off_chain(active), 1u);
    EXPECT_EQ(mp.recent_chain_spend_blocks(), 2u);
    EXPECT_EQ(proof(mp, kept), Proof::Absent);
    EXPECT_EQ(proof(mp, orphaned), Proof::Unknown) << "spent only by the disconnected block";
    EXPECT_EQ(proof(mp, both), Proof::Absent) << "the surviving chain spends it too";

    // A block recorded without a position is forgotten on any reorg, and
    // with no chain lookup the whole ring goes (proof given up, never a
    // false refusal).
    mp.remove_protx_conflicts_for_block(block_of({spend_of(orphaned, 5)}), owners({}));
    EXPECT_EQ(mp.forget_chain_spends_off_chain(active), 1u);
    EXPECT_EQ(proof(mp, orphaned), Proof::Unknown);
    EXPECT_EQ(mp.forget_chain_spends_off_chain({}), 2u);
    EXPECT_EQ(proof(mp, kept), Proof::Unknown);
    EXPECT_EQ(proof(mp, both), Proof::Unknown);

    // A block the live lane refused is forgotten by hash.
    mp.remove_protx_conflicts_for_block(block_of({spend_of(kept, 6)}), owners({}), {},
                                        Mempool::ChainPos{102, h256(0x63)});
    EXPECT_FALSE(mp.forget_chain_spends_of_block(h256(0x64)));
    EXPECT_TRUE(mp.forget_chain_spends_of_block(h256(0x63)));
    EXPECT_EQ(proof(mp, kept), Proof::Unknown);
}
