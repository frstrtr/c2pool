// SPDX-License-Identifier: AGPL-3.0-or-later
//
// S2 KATs: the DASH full UTXO set from a pinned dumptxoutset snapshot
// (utxo_snapshot_import.hpp, UtxoLane full mode, utxo_status.hpp), and the
// mempool's view lookups that must not read a (value 0, empty script) coin as
// absent (VERIFY-S1 S2-3). Every full set here is built the way the node
// builds it: a snapshot file, a digest-gated pin, the real import, the S2-2
// open rule (dash_utxo_full_fixture.hpp).

#include "dash_utxo_full_fixture.hpp"

#include <impl/dash/coin/mempool.hpp>
#include <impl/dash/coin/utxo_status.hpp>

#include <core/leveldb_store.hpp>

#include <gtest/gtest.h>

#include <atomic>
#include <fstream>
#include <map>
#include <string>
#include <thread>
#include <vector>

using namespace dash_utxo_full;
using dash::coin::UtxoLane;
namespace R = dash::coin::utxo_snapshot_refusal;

namespace {

constexpr uint32_t kBase = 1000;

struct Rig {
    TempDir tmp{"lane"};
    UtxoLane lane;
    Chain chain;
    std::vector<uint32_t> requested;
    std::vector<std::pair<std::string, std::string>> alerts;
    BlockType base_block = block(fake_hash(999), {coinbase(50, 999)}, 999);
    uint256 base_hash = hash_of(base_block);

    /// The full set, opened; the header chain holds the base, the seams are
    /// wired, nothing verified yet.
    bool open(std::vector<SnapCoin> coins)
    {
        if (!open_full_set(lane, tmp, std::move(coins), kBase, base_hash)) return false;
        chain.hashes[kBase] = base_hash;
        lane.set_hash_at_fn(chain.fn());
        lane.set_request_block_fn([this](uint32_t h) {
            requested.push_back(h);
            return true;
        });
        lane.set_alert_fn([this](const std::string& e, const std::string& d) { alerts.push_back({e, d}); });
        return true;
    }
    /// Put `b` on the header chain at `h` and hand it to the lane.
    void deliver(const BlockType& b, uint32_t h)
    {
        chain.hashes[h] = hash_of(b);
        lane.on_block_connected(b, h);
    }
    bool has(const Outpoint& op)
    {
        Coin c;
        return lane.cache()->get_coin(op, c);
    }
    bool get(const Outpoint& op, Coin& c) { return lane.cache()->get_coin(op, c); }
};

/// Import only (the open-rule cases open the directory themselves).
void import_only(const TempDir& tmp, const std::string& dir, const uint256& base_hash)
{
    const auto pin = make_pinned_snapshot(tmp.sub(dir + ".dat"), {snap_coin(fake_hash(3), 0, 10, 3)}, kBase,
                                          base_hash);
    dash::coin::DashUtxoImportConfig cfg;
    cfg.network = "regtest";
    const auto r = dash::coin::import_dash_utxo_snapshot({tmp.sub(dir + ".dat")}, tmp.sub(dir), pin, cfg);
    ASSERT_TRUE(r.ok) << r.refusal << " " << r.detail;
}

} // namespace

TEST(DashUtxoLane, OpensFullDbWhenTracked)
{
    Rig r;
    const uint256 t = fake_hash(1);
    ASSERT_TRUE(r.open({snap_coin(t, 0, 1000, 1), snap_coin(t, 1, 2000, 2), snap_coin(fake_hash(2), 0, 3000, 3)}));
    EXPECT_TRUE(r.lane.full());
    EXPECT_EQ(r.lane.cache()->get_best_height(), kBase);
    EXPECT_EQ(r.lane.cache()->get_best_block(), r.base_hash);
    EXPECT_EQ(r.lane.cache()->sync_state().coins, 3u);
    EXPECT_EQ(r.lane.cache()->sync_state().anchor_height, 0u);
    // Not placed on the header chain yet: not current, not ready.
    EXPECT_EQ(r.lane.full_status().state, "verifying-base");
    EXPECT_FALSE(r.lane.mining_utxo_ready());
    EXPECT_FALSE(r.lane.utxo_current_at(r.base_hash));
    r.lane.on_header_tip(kBase);
    EXPECT_TRUE(r.lane.base_verified());
    EXPECT_EQ(r.lane.full_status().state, "serving");
    EXPECT_TRUE(r.lane.mining_utxo_ready());
    EXPECT_TRUE(r.lane.utxo_current_at(r.base_hash));
    EXPECT_TRUE(r.requested.empty()) << "at the tip: nothing to fill";
    Coin c;
    ASSERT_TRUE(r.get(Outpoint(t, 1), c));
    EXPECT_EQ(c.value, 2000);
    EXPECT_EQ(c.height, 500u);
}

TEST(DashUtxoLane, FullDbOpenRuleRefusesByName)
{
    TempDir tmp("openrule");
    // Absent: nothing to open, not an error.
    auto absent = dash::coin::open_dash_full_utxo_set(tmp.sub("none"), "regtest", 0);
    EXPECT_TRUE(absent.absent);
    EXPECT_FALSE(absent.ok());

    // 'C' records without 'B' / 'S': an import cut short.
    {
        ::core::LevelDBStore s(tmp.sub("cut"), ::core::LevelDBOptions{});
        ASSERT_TRUE(s.open());
        ASSERT_TRUE(s.put(::core::coin::view_db_coin_key(Outpoint(fake_hash(7), 0)),
                          ::core::coin::serialize_coin(Coin(5, script(p2pkh(7)), 1, false))));
        s.close();
    }
    auto cut = dash::coin::open_dash_full_utxo_set(tmp.sub("cut"), "regtest", 0);
    EXPECT_EQ(cut.refusal, R::kFullDbIncomplete) << cut.detail;

    // An accrual view (coins + 'B', no 'S') is not a full set.
    {
        dash::coin::UtxoViewDB db(tmp.sub("accrual"));
        ASSERT_TRUE(db.open());
        dash::coin::UtxoViewDB::ChangeMap ch;
        ch[Outpoint(fake_hash(8), 0)] = Coin(5, script(p2pkh(8)), 1, false);
        ASSERT_TRUE(db.write_batch(ch, fake_hash(80), 80));
        db.close();
    }
    auto accrual = dash::coin::open_dash_full_utxo_set(tmp.sub("accrual"), "regtest", 0);
    EXPECT_EQ(accrual.refusal, R::kFullDbIncomplete) << accrual.detail;

    // A real full set, opened against the wrong network / a higher checkpoint.
    import_only(tmp, "full", fake_hash(1000));
    auto wrong_net = dash::coin::open_dash_full_utxo_set(tmp.sub("full"), "mainnet", 0);
    EXPECT_EQ(wrong_net.refusal, R::kFullDbWrongNet) << wrong_net.detail;
    auto below = dash::coin::open_dash_full_utxo_set(tmp.sub("full"), "regtest", kBase + 1);
    EXPECT_EQ(below.refusal, R::kFullDbBelowCkpt) << below.detail;
    auto ok = dash::coin::open_dash_full_utxo_set(tmp.sub("full"), "regtest", kBase);
    ASSERT_TRUE(ok.ok()) << ok.refusal << " " << ok.detail;
    EXPECT_EQ(ok.assumed.base_height, kBase);
    EXPECT_EQ(ok.assumed.base_hash, fake_hash(1000));
    EXPECT_EQ(ok.assumed.coin, "dash");
    EXPECT_EQ(ok.assumed.network, "regtest");
    EXPECT_EQ(ok.assumed.validated, 0);
    EXPECT_EQ(ok.assumed.coins, 1u);
    EXPECT_EQ(ok.assumed.pin_digest.size(), 64u);
}

TEST(DashUtxoLane, FullSetNeverJumps)
{
    // Best B; the first block the lane sees is B+1000. It asks for B+1 ..
    // B+64 (the full window, one request per height), never B+1000-288.
    Rig r;
    ASSERT_TRUE(r.open({snap_coin(fake_hash(1), 0, 1000, 1)}));
    const uint32_t far = kBase + 1000;
    const BlockType x = block(fake_hash(far - 1), {coinbase(50, far)}, far);
    r.deliver(x, far);
    ASSERT_EQ(r.requested.size(), UtxoLane::FULL_WINDOW);
    for (size_t i = 0; i < r.requested.size(); ++i) EXPECT_EQ(r.requested[i], kBase + 1 + i);
    EXPECT_EQ(std::count(r.requested.begin(), r.requested.end(), far - 288), 0);
    EXPECT_EQ(r.lane.cache()->get_best_height(), kBase) << "nothing connected across the gap";
    const auto st = r.lane.full_status();
    EXPECT_EQ(st.state, "catching-up");
    EXPECT_EQ(st.fill_next, kBase + 1);
    EXPECT_EQ(st.fill_end, far);
    EXPECT_FALSE(r.lane.utxo_current_at(hash_of(x)));
}

TEST(DashUtxoLane, OneRequestPerHeightOnRefill)
{
    // The header tip is 100 blocks past the base: the fill asks each height
    // exactly once while the bodies arrive in order, and ends at the tip.
    Rig r;
    ASSERT_TRUE(r.open({snap_coin(fake_hash(1), 0, 1000, 1)}));
    std::map<uint32_t, BlockType> chain_blocks;
    uint256 prev = r.base_hash;
    for (uint32_t h = kBase + 1; h <= kBase + 100; ++h) {
        chain_blocks[h] = block(prev, {coinbase(50 + h, h)}, h);
        prev = hash_of(chain_blocks[h]);
        r.chain.hashes[h] = prev;
    }
    r.lane.on_header_tip(kBase + 100);
    size_t served = 0;
    while (served < r.requested.size()) {
        const uint32_t h = r.requested[served++];
        r.lane.on_block_connected(chain_blocks.at(h), h);
    }
    std::map<uint32_t, int> asked;
    for (uint32_t h : r.requested) ++asked[h];
    EXPECT_EQ(asked.size(), 100u);
    for (const auto& [h, n] : asked) EXPECT_EQ(n, 1) << "height " << h << " asked " << n << " times";
    EXPECT_EQ(r.lane.cache()->get_best_height(), kBase + 100);
    EXPECT_EQ(r.lane.cache()->get_best_block(), prev);
    EXPECT_EQ(r.lane.full_status().state, "serving");
    EXPECT_EQ(r.lane.full_status().connected, 100u);
    EXPECT_TRUE(r.lane.utxo_current_at(prev));
    EXPECT_EQ(r.lane.cache()->sync_state().coins, 101u);
    EXPECT_EQ(r.lane.cache()->sync_state().best_height, kBase + 100);
}

TEST(DashUtxoLane, StrictRefusalWithholdsByName)
{
    Rig r;
    ASSERT_TRUE(r.open({snap_coin(fake_hash(1), 0, 1000, 1)}));
    // B+1 spends a coin the set does not hold.
    const BlockType b1 = block(r.base_hash,
                               {coinbase(50, 1), spend({Outpoint(fake_hash(66), 0)}, {out(10, p2pkh(9))}, 1)}, 1);
    r.deliver(b1, kBase + 1);
    EXPECT_FALSE(r.lane.withheld()) << "a first refusal asks the body again";
    EXPECT_EQ(std::count(r.requested.begin(), r.requested.end(), kBase + 1), 1);
    EXPECT_EQ(r.lane.full_status().strict_refusals, 1u);
    r.deliver(b1, kBase + 1);   // the same body again: the set is wrong
    EXPECT_TRUE(r.lane.withheld());
    const auto st = r.lane.full_status();
    EXPECT_EQ(st.state, "withheld");
    EXPECT_NE(st.withheld_reason.find("utxo-strict-refusal"), std::string::npos) << st.withheld_reason;
    EXPECT_NE(st.withheld_reason.find("bad-txns-inputs-missingorspent"), std::string::npos) << st.withheld_reason;
    EXPECT_NE(st.withheld_reason.find(fake_hash(66).GetHex()), std::string::npos) << st.withheld_reason;
    ASSERT_EQ(r.alerts.size(), 1u);
    EXPECT_EQ(r.alerts[0].first, "utxo-strict-refusal");
    EXPECT_EQ(r.lane.cache()->get_best_height(), kBase);
    EXPECT_FALSE(r.lane.utxo_current_at(r.base_hash)) << "withheld: no mempool tx is served";
    // It never heals by itself: a later valid block is not connected.
    const BlockType b1ok = block(r.base_hash, {coinbase(51, 2)}, 2);
    r.deliver(b1ok, kBase + 1);
    EXPECT_EQ(r.lane.cache()->get_best_height(), kBase);
}

TEST(FullLane, DashConnectsSpecialTxs)
{
    Rig r;
    const Outpoint c_lock(fake_hash(11), 0), c_reg(fake_hash(12), 0), c_plain(fake_hash(13), 0);
    ASSERT_TRUE(r.open({snap_coin(c_lock.txid, 0, 5000, 11), snap_coin(c_reg.txid, 0, 7000, 12),
                        snap_coin(c_plain.txid, 0, 3000, 13)}));
    r.lane.on_header_tip(kBase);

    MutableTransaction cbtx = coinbase(1000, 1);   // CbTx: version 3, type 5, a payload
    cbtx.version = 3;
    cbtx.type = 5;
    cbtx.extra_payload = {0x02, 0x00, 0xe9, 0x03};
    MutableTransaction qc;                          // QcTx: no inputs, no outputs
    qc.version = 3;
    qc.type = 6;
    qc.extra_payload = {0x01, 0x02};
    MutableTransaction mnhf;                        // MnHfTx: no inputs, no outputs
    mnhf.version = 3;
    mnhf.type = 7;
    mnhf.extra_payload = {0x01, 0x03};
    MutableTransaction unlock;                      // AssetUnlock: no inputs, adds its outputs
    unlock.version = 3;
    unlock.type = 9;
    unlock.extra_payload = {0x01, 0x04};
    unlock.vout.push_back(out(2000, p2pkh(20)));
    MutableTransaction lock = spend({c_lock}, {out(4000, {0x6a}), out(900, p2pkh(21))}, 3);  // AssetLock
    lock.version = 3;
    lock.type = 8;
    lock.extra_payload = {0x01, 0x05};
    MutableTransaction reg = spend({c_reg}, {out(6900, p2pkh(22))}, 4);   // ProRegTx (internal collateral)
    reg.version = 3;
    reg.type = 1;
    reg.extra_payload = {0x01, 0x06};
    const BlockType b1 = block(r.base_hash, {cbtx, qc, mnhf, unlock, lock, reg}, 1);
    r.deliver(b1, kBase + 1);
    ASSERT_FALSE(r.lane.withheld()) << r.lane.full_status().withheld_reason;
    ASSERT_EQ(r.lane.cache()->get_best_height(), kBase + 1);

    Coin c;
    ASSERT_TRUE(r.get(Outpoint(dash_txid(cbtx), 0), c));
    EXPECT_TRUE(c.coinbase);
    EXPECT_EQ(c.height, kBase + 1);
    EXPECT_FALSE(r.has(Outpoint(dash_txid(qc), 0)));
    EXPECT_FALSE(r.has(Outpoint(dash_txid(mnhf), 0)));
    ASSERT_TRUE(r.get(Outpoint(dash_txid(unlock), 0), c));
    EXPECT_EQ(c.value, 2000);
    EXPECT_FALSE(c.coinbase);
    EXPECT_FALSE(r.has(Outpoint(dash_txid(lock), 0))) << "the AssetLock OP_RETURN is unspendable";
    EXPECT_TRUE(r.has(Outpoint(dash_txid(lock), 1)));
    EXPECT_FALSE(r.has(c_lock));
    EXPECT_FALSE(r.has(c_reg));
    EXPECT_TRUE(r.has(Outpoint(dash_txid(reg), 0)));
    EXPECT_TRUE(r.has(c_plain));
    // 3 - 2 spent + coinbase + unlock + lock change + reg = 5.
    EXPECT_EQ(r.lane.cache()->sync_state().coins, 5u);
}

TEST(FullLane, Bip30DuplicateRefused)
{
    // The set already holds (T, 0); a block carrying T would add it again.
    const Outpoint c_plain(fake_hash(13), 0);
    const MutableTransaction t = spend({c_plain}, {out(2500, p2pkh(30))}, 7);
    Rig r;
    ASSERT_TRUE(r.open({snap_coin(c_plain.txid, 0, 3000, 13), snap_coin(dash_txid(t), 0, 2500, 30)}));
    r.lane.on_header_tip(kBase);
    const BlockType b1 = block(r.base_hash, {coinbase(50, 1), t}, 1);
    r.deliver(b1, kBase + 1);
    r.deliver(b1, kBase + 1);
    EXPECT_TRUE(r.lane.withheld());
    EXPECT_NE(r.lane.full_status().withheld_reason.find("bad-txns-BIP30"), std::string::npos)
        << r.lane.full_status().withheld_reason;
    EXPECT_TRUE(r.has(c_plain)) << "nothing of the refused block was applied";
}

TEST(FullLane, SpentShapedOutputRefused)
{
    // An output Coin::is_spent() would read as absent never enters the set.
    Rig r;
    ASSERT_TRUE(r.open({snap_coin(fake_hash(13), 0, 3000, 13)}));
    r.lane.on_header_tip(kBase);
    MutableTransaction cb = coinbase(50, 1);
    cb.vout.push_back(out(0, {}));
    const BlockType b1 = block(r.base_hash, {cb}, 1);
    r.deliver(b1, kBase + 1);
    r.deliver(b1, kBase + 1);
    EXPECT_TRUE(r.lane.withheld());
    EXPECT_NE(r.lane.full_status().withheld_reason.find("utxo-spent-shaped-output"), std::string::npos)
        << r.lane.full_status().withheld_reason;
}

TEST(DashUtxoLane, FullSetRewindsAReorgFromUndo)
{
    Rig r;
    const Outpoint c1(fake_hash(41), 0);
    ASSERT_TRUE(r.open({snap_coin(c1.txid, 0, 1000, 41)}));
    r.lane.on_header_tip(kBase);
    const MutableTransaction sA = spend({c1}, {out(990, p2pkh(42))}, 42);
    const BlockType a1 = block(r.base_hash, {coinbase(50, 101), sA}, 101);
    r.deliver(a1, kBase + 1);
    const MutableTransaction cbA2 = coinbase(50, 102);
    const BlockType a2 = block(hash_of(a1), {cbA2}, 102);
    r.deliver(a2, kBase + 2);
    ASSERT_EQ(r.lane.cache()->get_best_block(), hash_of(a2));

    // A sibling of a2 becomes the header chain's block at B+2.
    const MutableTransaction cbB2 = coinbase(50, 202);
    const BlockType b2 = block(hash_of(a1), {cbB2}, 202);
    r.chain.hashes[kBase + 2] = hash_of(b2);
    r.lane.on_header_tip(kBase + 2);
    EXPECT_EQ(r.lane.full_status().rewinds, 1u);
    EXPECT_EQ(r.lane.cache()->get_best_block(), hash_of(a1));
    EXPECT_FALSE(r.has(Outpoint(dash_txid(cbA2), 0))) << "the orphaned block's outputs are gone";
    EXPECT_EQ(r.requested.back(), kBase + 2) << "the new branch's body is asked for";
    r.lane.on_block_connected(b2, kBase + 2);
    EXPECT_EQ(r.lane.cache()->get_best_block(), hash_of(b2));
    EXPECT_TRUE(r.has(Outpoint(dash_txid(cbB2), 0)));
    EXPECT_TRUE(r.has(Outpoint(dash_txid(sA), 0)));

    // Two deep: back to the base, the spent snapshot coin restored.
    r.chain.hashes[kBase + 1] = fake_hash(5001);
    r.chain.hashes[kBase + 2] = fake_hash(5002);
    r.lane.on_header_tip(kBase + 2);
    EXPECT_EQ(r.lane.full_status().rewinds, 3u);
    EXPECT_EQ(r.lane.cache()->get_best_block(), r.base_hash);
    EXPECT_EQ(r.lane.cache()->get_best_height(), kBase);
    EXPECT_TRUE(r.has(c1)) << "undo puts the spent coin back";
    EXPECT_FALSE(r.has(Outpoint(dash_txid(sA), 0)));
    EXPECT_EQ(r.lane.cache()->sync_state().coins, 1u);
    EXPECT_FALSE(r.lane.withheld());

    // Below the base there is no undo: withhold, never guess.
    r.chain.hashes[kBase] = fake_hash(5000);
    r.lane.on_header_tip(kBase + 2);
    EXPECT_TRUE(r.lane.withheld());
    EXPECT_NE(r.lane.full_status().withheld_reason.find("utxo-reorg-below-snapshot-base"), std::string::npos)
        << r.lane.full_status().withheld_reason;
}

TEST(DashSnapshot, RefusesBaseBelowCheckpointOrAbsent)
{
    TempDir tmp("ckpt");
    const auto pin = make_pinned_snapshot(tmp.sub("s.dat"), {snap_coin(fake_hash(3), 0, 10, 3)}, kBase,
                                          fake_hash(1000));
    dash::coin::DashUtxoImportConfig cfg;
    cfg.network = "regtest";
    cfg.min_base_height = kBase + 1;
    const auto r = dash::coin::import_dash_utxo_snapshot({tmp.sub("s.dat")}, tmp.sub("db"), pin, cfg);
    EXPECT_EQ(r.refusal, R::kBelowCheckpoint) << r.detail;
    EXPECT_FALSE(std::filesystem::exists(tmp.sub("db") + "/CURRENT")) << "refused before any DB is created";

    // The base is not the header chain's block at its height: withheld.
    {
        Rig w;
        ASSERT_TRUE(w.open({snap_coin(fake_hash(3), 0, 10, 3)}));
        w.chain.hashes[kBase] = fake_hash(7777);
        w.lane.on_header_tip(kBase + 5);
        EXPECT_TRUE(w.lane.withheld());
        EXPECT_NE(w.lane.full_status().withheld_reason.find("utxo-full-base-not-in-header-chain"),
                  std::string::npos);
        EXPECT_TRUE(w.requested.empty());
        ASSERT_EQ(w.alerts.size(), 1u);
    }
    // The header chain does not hold the base yet: wait, serve nothing.
    {
        Rig a;
        ASSERT_TRUE(a.open({snap_coin(fake_hash(3), 0, 10, 3)}));
        a.chain.hashes.clear();
        a.lane.on_header_tip(kBase + 5);
        EXPECT_FALSE(a.lane.withheld());
        EXPECT_EQ(a.lane.full_status().state, "verifying-base");
        EXPECT_FALSE(a.lane.mining_utxo_ready());
        EXPECT_FALSE(a.lane.utxo_current_at(a.base_hash));
        EXPECT_TRUE(a.requested.empty());
    }
}

TEST(DashSnapshot, ImportRefusesSpentShapedCoin)
{
    TempDir tmp("spentshape");
    SnapCoin zero;
    zero.op = Outpoint(fake_hash(9), 0);
    zero.coin = Coin(0, OPScript(), 400, false);
    const auto pin = make_pinned_snapshot(tmp.sub("s.dat"), {snap_coin(fake_hash(3), 0, 10, 3), zero}, kBase,
                                          fake_hash(1000));
    ASSERT_TRUE(pin.pin) << pin.refusal;
    dash::coin::DashUtxoImportConfig cfg;
    cfg.network = "regtest";
    const auto r = dash::coin::import_dash_utxo_snapshot({tmp.sub("s.dat")}, tmp.sub("db"), pin, cfg);
    EXPECT_EQ(r.refusal, ::core::coin::snapshot_refusal::kSpentShapedCoin) << r.detail;
    auto o = dash::coin::open_dash_full_utxo_set(tmp.sub("db"), "regtest", 0);
    EXPECT_FALSE(o.ok());
    EXPECT_EQ(o.refusal, R::kFullDbEmpty) << "the refused import left no record";
}

TEST(DashSnapshotPin, DigestGatedLoad)
{
    // The built-in mainnet pin: the 2564044 trial snapshot.
    const auto main = dash::coin::load_dash_utxo_pin("", "mainnet");
    ASSERT_TRUE(main.pin) << main.refusal << " " << main.detail;
    EXPECT_EQ(main.source, "built-in mainnet");
    EXPECT_EQ(main.pin->height, 2564044u);
    EXPECT_EQ(main.pin->coins, 4531254u);
    EXPECT_EQ(main.pin->blockhash.GetHex(), "000000000000000e2fb6aafce51366a10a8ec7db1d7a69640e3ba5d340a58a88");
    EXPECT_EQ(main.pin->muhash.GetHex(), "c00ab2e7ba53e9981a8c560002bb2229cc855820db6c4434ad2081bd267e32b5");
    ASSERT_TRUE(main.pin->hash_serialized_2);
    EXPECT_EQ(main.pin->hash_serialized_2->GetHex(),
              "eedc6501ea8cbc171199a1c26eaaa812d12f6d34ba7cec91b40d74b72ac4a355");
    ASSERT_EQ(main.pin->parts.size(), 1u);
    EXPECT_EQ(main.pin->parts[0].sha256, "50f2579cb842a64bcf04a0934d2367264ddf38e99a2b815c5161a1035cc78160");
    EXPECT_EQ(main.digest, "2887531c74be30ad1b7f6c9398e77e9f8e437ebe909ad787bd8e7e3979435982");

    EXPECT_EQ(dash::coin::load_dash_utxo_pin("", "testnet").refusal, R::kNoPin);
    EXPECT_EQ(dash::coin::check_dash_utxo_pin(dash::coin::builtin_dash_utxo_pin_text("mainnet"), "testnet", "t")
                  .refusal,
              R::kPinWrongNetwork);

    TempDir tmp("pin");
    std::string text = dash::coin::builtin_dash_utxo_pin_text("mainnet");
    text.replace(text.find("coins 4531254"), 13, "coins 4531255");
    {
        std::ofstream f(tmp.sub("tampered.txt"));
        f << text;
    }
    const auto tampered = dash::coin::load_dash_utxo_pin(tmp.sub("tampered.txt"), "mainnet");
    EXPECT_EQ(tampered.refusal, R::kPinInvalid) << tampered.detail;
    EXPECT_NE(tampered.detail.find("digest mismatch"), std::string::npos) << tampered.detail;
    EXPECT_EQ(dash::coin::load_dash_utxo_pin(tmp.sub("absent.txt"), "mainnet").refusal, R::kPinUnreadable);

    const auto doge = make_pinned_snapshot(tmp.sub("d.dat"), {snap_coin(fake_hash(3), 0, 10, 3)}, kBase,
                                           fake_hash(1000), "regtest", "doge");
    EXPECT_EQ(doge.refusal, R::kPinWrongCoin);
}

TEST(DashStatus, ReportsUtxoFullState)
{
    Rig r;
    ASSERT_TRUE(r.open({snap_coin(fake_hash(1), 0, 1000, 1), snap_coin(fake_hash(1), 1, 1000, 2)}));
    r.lane.on_header_tip(kBase);
    const auto j = dash::coin::utxo_status_json(r.lane, "", 12.7);
    EXPECT_EQ(j["mode"], "full");
    EXPECT_EQ(j["state"], "serving");
    EXPECT_EQ(j["best_height"], kBase);
    EXPECT_EQ(j["best_block"], r.base_hash.GetHex());
    EXPECT_EQ(j["coins"], 2);
    EXPECT_EQ(j["strict_refusals"], 0);
    EXPECT_EQ(j["import_seconds"], 12);
    EXPECT_EQ(j["assumeutxo"]["assumed"], true);
    EXPECT_EQ(j["assumeutxo"]["base_height"], kBase);
    EXPECT_EQ(j["assumeutxo"]["base_hash"], r.base_hash.GetHex());
    EXPECT_EQ(j["assumeutxo"]["validated"], false);
    EXPECT_EQ(j["assumeutxo"]["base_verified"], true);
    EXPECT_EQ(j["assumeutxo"]["validation"]["status"], "idle");
    EXPECT_EQ(dash::coin::utxo_status_line(r.lane), "utxo=full/serving best=1000 refusals=0");

    UtxoLane accrual;
    ASSERT_TRUE(accrual.open(""));
    const auto a = dash::coin::utxo_status_json(accrual, "utxo-full-db-wrong-network: x");
    EXPECT_EQ(a["mode"], "accrual");
    EXPECT_EQ(a["full_refused"], "utxo-full-db-wrong-network: x");
    EXPECT_FALSE(a.contains("assumeutxo"));
    UtxoLane off;
    EXPECT_EQ(dash::coin::utxo_status_json(off)["mode"], "off");
}

TEST(DashMempool, ZeroValueEmptyScriptCoinIsPresent)
{
    // VERIFY-S1 S2-3: a coin with value 0 and an empty script is a coin
    // (Core stores it); the mempool's view lookups must not read it as absent.
    ::core::coin::UTXOViewCache view(nullptr);
    const Outpoint op(fake_hash(51), 0);
    view.add_coin(op, Coin(0, OPScript(), 5, false));
    dash::coin::Mempool mp;
    mp.set_utxo(&view);
    Coin c;
    EXPECT_EQ(mp.prove_chain_coin(op, c), dash::coin::Mempool::CoinProof::Unspent);
    EXPECT_EQ(c.value, 0);
}

TEST(DashUtxoLane, StatusReadFromAnotherThreadWhileTheLaneMoves)
{
    // VERIFY-S2 S-1: /local_stats reads the lane's status on the HTTP thread
    // while the io thread connects, re-asks and withholds. The read must be a
    // published copy, never the live members (a torn withheld_reason string
    // could crash the node). Run under TSan this is the race detector's pin;
    // without it, a crash-or-garbage smoke.
    Rig r;
    ASSERT_TRUE(r.open({snap_coin(fake_hash(71), 0, 1000, 71)}));
    std::atomic<bool> stop{false};
    std::atomic<uint64_t> reads{0};
    std::atomic<bool> garbage{false};
    std::thread http([&] {
        while (!stop.load(std::memory_order_relaxed)) {
            const auto j = dash::coin::utxo_status_json(r.lane);
            const auto st = r.lane.full_status();
            const auto line = dash::coin::utxo_status_line(r.lane);
            if (st.state != "verifying-base" && st.state != "catching-up" && st.state != "serving" &&
                st.state != "withheld")
                garbage = true;
            if (!st.withheld_reason.empty() && st.withheld_reason.rfind("utxo-strict-refusal", 0) != 0)
                garbage = true;
            if (j.is_null() || line.empty()) garbage = true;
            reads.fetch_add(1, std::memory_order_relaxed);
        }
    });
    r.lane.on_header_tip(kBase);
    uint256 prev = r.base_hash;
    for (uint32_t i = 1; i <= 150; ++i) {
        const BlockType b = block(prev, {coinbase(50, 7000 + i)}, 7000 + i);
        r.deliver(b, kBase + i);
        prev = hash_of(b);
    }
    // A body spending a coin the set does not hold, twice: the second refusal
    // withholds, writing the reason while the reader runs.
    const BlockType bad = block(prev, {coinbase(50, 7999), spend({Outpoint(fake_hash(72), 0)},
                                                                 {out(5, p2pkh(72))}, 7999)}, 7999);
    r.deliver(bad, kBase + 151);
    r.lane.on_block_connected(bad, kBase + 151);
    while (reads.load() < 1000) std::this_thread::yield();
    stop = true;
    http.join();
    EXPECT_FALSE(garbage.load());
    EXPECT_TRUE(r.lane.withheld());
    const auto st = r.lane.full_status();
    EXPECT_EQ(st.state, "withheld");
    EXPECT_EQ(st.best_height, kBase + 150);
    EXPECT_EQ(st.connected, 150u);
    EXPECT_EQ(st.strict_refusals, 2u);
    EXPECT_EQ(st.withheld_reason.rfind("utxo-strict-refusal", 0), 0u) << st.withheld_reason;
}

TEST(DashUtxoLane, FailedFlushDropsTheUnflushedChanges)
{
    // VERIFY-S2 S-4: a flush that fails withholds AND drops the block's
    // unflushed changes, so the view the mempool prices from is the DB's
    // again (not coins the DB does not have).
    Rig r;
    ASSERT_TRUE(r.open({snap_coin(fake_hash(61), 0, 1000, 61)}));
    r.lane.on_header_tip(kBase);
    ASSERT_EQ(r.lane.full_status().state, "serving");
    ASSERT_EQ(r.lane.cache()->cache_size(), 0u);
    r.lane.db()->close();   // every write fails from here on
    const BlockType a1 = block(r.base_hash, {coinbase(50, 601)}, 601);
    r.deliver(a1, kBase + 1);
    EXPECT_TRUE(r.lane.withheld());
    EXPECT_NE(r.lane.full_status().withheld_reason.find("utxo-flush-failed"), std::string::npos)
        << r.lane.full_status().withheld_reason;
    EXPECT_EQ(r.lane.cache()->cache_size(), 0u)
        << "the failed block's changes are dropped: the view is the DB's again";
    ASSERT_EQ(r.alerts.size(), 1u);
}
