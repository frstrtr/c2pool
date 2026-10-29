// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// The merged (DOGE) work miners get is always buildable (rides share_test).
//
// After a refresh the current work carries the backend's block hash, which
// for the embedded DOGE backend is the PARENT's hash, until a rebuild builds
// and freezes a block. A rebuild that got no payouts (the sharechain
// tracker's lock busy, no best share yet) skipped the chain and still built
// the LTC commitment from that hash: a DOGE-target share then committed to a
// block no snapshot matches ("No matching snapshot ... skipping submission")
// and the find was lost. On the sg-ltc canary 15 % of a 38-minute window.
//   - a rebuild without payouts never commits to the parent's hash: it keeps
//     the last block frozen on the same parent, else takes the chain out of
//     the commitment until a block is built;
//   - a rebuild whose template was replaced while the payouts were computed
//     does not freeze its block under the new template;
//   - MergedPayoutSource: the payouts are produced while the tracker lock is
//     busy (a short wait on the RPC thread, or the result already computed
//     for the same best share, chain and value).
// Folded into the allowlisted share_test target (no new executable: #769).
// ---------------------------------------------------------------------------

#include <gtest/gtest.h>

#include <chrono>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <boost/asio/io_context.hpp>
#include <nlohmann/json.hpp>

#include <core/uint256.hpp>
#include <btclibs/util/strencodings.h>
#include <c2pool/merged/merged_mining.hpp>
#include <c2pool/merged/payout_source.hpp>

namespace {

using c2pool::merged::MergedMiningManager;
using c2pool::merged::MergedPayoutSource;
using Payouts = MergedPayoutSource::Payouts;

/// The embedded DOGE backend's shape: the work's block hash is its tip (the
/// parent of the block being built).
struct EmbeddedLike : c2pool::merged::IAuxChainBackend {
    c2pool::merged::AuxChainConfig cfg;
    std::string tip_id = std::string(62, '0') + "a1";   // what get_best_block_hash reports
    std::string parent = std::string(62, '0') + "a1";   // the template's previousblockhash
    int curtime = 1793210000;
    int submits = 0;
    std::function<void()> on_fetch;
    EmbeddedLike()
    {
        cfg.symbol = "DOGE";
        cfg.chain_id = 98;
        cfg.multiaddress = true;
    }
    c2pool::merged::AuxWork get_work_template() override
    {
        if (on_fetch)
            on_fetch();
        c2pool::merged::AuxWork w;
        w.chain_id = 98;
        w.height = 5'000'001;
        w.coinbase_value = 1000000000000ULL;
        w.block_hash.SetHex(parent);   // embedded: tip->block_hash
        w.target.SetHex(std::string(8, '0') + std::string(56, 'f'));
        w.prev_block_hash = parent;
        w.block_template = {
            {"previousblockhash", parent}, {"height", 5'000'001}, {"bits", "1a01d2c3"},
            {"curtime", curtime}, {"version", 0x620004}, {"coinbasevalue", 1000000000000LL},
            {"transactions", nlohmann::json::array()},
        };
        return w;
    }
    c2pool::merged::AuxWork create_aux_block(const std::string&) override
    {
        auto w = get_work_template();
        return w;
    }
    bool connect() override { return true; }
    bool submit_block(const std::string&) override { ++submits; return true; }
    bool submit_aux_block(const uint256&, const std::string&) override { return true; }
    std::string get_block_hex(const std::string&) override { return {}; }
    std::string get_best_block_hash() override { return tip_id; }
    std::vector<NetService> getpeerinfo() override { return {}; }
    const c2pool::merged::AuxChainConfig& config() const override { return cfg; }
};

Payouts one_payee(uint64_t value)
{
    std::vector<unsigned char> s{0x76, 0xa9, 0x14};
    s.insert(s.end(), 20, 0x5c);
    s.push_back(0x88);
    s.push_back(0xac);
    return {{s, value}};
}

/// The root the LTC coinbase commits to (null when there is no commitment).
uint256 committed_root(MergedMiningManager& mm)
{
    const auto c = mm.get_auxpow_commitment();
    uint256 r;
    if (c.size() < 36)
        return r;
    for (int i = 0; i < 32; ++i)
        r.data()[i] = c[4 + 31 - i];
    return r;
}

/// A share whose LTC coinbase carries the current commitment meets the DOGE
/// target: try_submit_merged_blocks.
void submit_current_job(MergedMiningManager& mm)
{
    const auto c = mm.get_auxpow_commitment();
    const std::string cb = std::string(20, 'a') + HexStr(std::span<const unsigned char>(c.data(), c.size()))
                         + std::string(20, 'b');
    uint256 parent_hash;
    parent_hash.SetHex("01");
    mm.try_submit_merged_blocks(std::string(160, 'd'), cb, {}, 0, parent_hash);
}

struct Rig {
    boost::asio::io_context ioc;
    MergedMiningManager mm{ioc};
    EmbeddedLike* b{nullptr};
    bool payouts{true};
    Rig()
    {
        auto backend = std::make_unique<EmbeddedLike>();
        b = backend.get();
        mm.add_chain(b->cfg, std::move(backend));
        mm.set_payout_provider([this](uint32_t, uint64_t value) -> Payouts {
            if (!payouts) {
                MergedMiningManager::note_payout_miss("tracker_busy");
                return {};
            }
            return one_payee(value);
        });
    }
};

} // namespace

// A tip change whose rebuild gets no payouts: the work must not commit to
// the parent's hash (no snapshot is ever built for it).
TEST(MergedMining, RebuildWithoutPayoutsNeverCommitsTheParentHash)
{
    Rig r;
    r.payouts = false;
    r.mm.refresh_aux_work();
    uint256 parent;
    parent.SetHex(r.b->parent);
    const auto work = r.mm.get_current_work().at(98);
    EXPECT_NE(work.block_hash, parent) << "the current block is the parent's hash";
    EXPECT_NE(committed_root(r.mm), parent) << "the LTC coinbase commits to the parent's hash";
    EXPECT_TRUE(r.mm.get_auxpow_commitment().empty()) << "no buildable block: no commitment";
    const auto j = r.mm.get_rebuild_stats_json();
    EXPECT_EQ(j["no_payouts"]["tracker_busy"], 1u);
    EXPECT_EQ(j["dropped_commitment"], 1u);

    // Payouts back: the next poll builds and commits a real block.
    r.payouts = true;
    r.mm.refresh_aux_work();
    const uint256 built = r.mm.get_current_work().at(98).block_hash;
    EXPECT_FALSE(built.IsNull());
    EXPECT_NE(built, parent);
    EXPECT_EQ(committed_root(r.mm), built);
    submit_current_job(r.mm);
    EXPECT_EQ(r.b->submits, 1);
}

// The template fetched again on the same parent (the tip's body cleaned the
// pool) while the payouts are unavailable: keep committing to the last block
// frozen on this parent; a DOGE-target share on that work finds its snapshot.
TEST(MergedMining, NoPayoutsOnTheSameParentKeepsTheLastBlock)
{
    Rig r;
    r.mm.refresh_aux_work();
    const uint256 a = r.mm.get_current_work().at(98).block_hash;
    ASSERT_EQ(committed_root(r.mm), a);

    r.payouts = false;
    r.b->tip_id = std::string(62, '0') + "a2";   // re-fetched, same parent
    r.b->curtime += 7;
    r.mm.refresh_aux_work();
    EXPECT_EQ(r.mm.get_current_work().at(98).block_hash, a) << "the last block on this parent";
    EXPECT_EQ(committed_root(r.mm), a);
    submit_current_job(r.mm);
    EXPECT_EQ(r.b->submits, 1) << "the share's block is built from its snapshot";
    EXPECT_EQ(r.mm.get_rebuild_stats_json()["kept_last_block"], 1u);
}

// The payouts take a while; meanwhile a refresh replaces the template (here:
// from inside the provider). The older rebuild's block must not be frozen
// under the new template: its snapshot would not hash to its key and a find
// on it would be skipped at submit.
TEST(MergedMining, StaleRebuildResultIsNotFrozenUnderANewTemplate)
{
    Rig r;
    bool nested = false;
    r.mm.set_payout_provider([&](uint32_t, uint64_t value) -> Payouts {
        if (!nested) {
            nested = true;
            r.b->tip_id = std::string(62, '0') + "b1";
            r.b->parent = std::string(62, '0') + "b1";
            r.mm.refresh_aux_work();   // the newer template, rebuilt meanwhile
        }
        return one_payee(value);
    });
    r.mm.refresh_aux_work();
    const auto work = r.mm.get_current_work().at(98);
    EXPECT_EQ(work.block_template["previousblockhash"], r.b->parent);
    EXPECT_EQ(committed_root(r.mm), work.block_hash);
    submit_current_job(r.mm);
    EXPECT_EQ(r.b->submits, 1) << "the committed block rebuilds from its snapshot";
    EXPECT_GE(r.mm.get_rebuild_stats_json()["stale_results"].get<uint64_t>(), 1u);
}

// ── MergedPayoutSource ──────────────────────────────────────────────────────

TEST(MergedPayoutSource, BusyLockIsWaitedFor)
{
    MergedPayoutSource src(std::chrono::milliseconds(200), std::chrono::milliseconds(1));
    uint256 best;
    best.SetHex("77");
    int tries = 0;
    std::string miss;
    const auto p = src.get(best, 98, 1000, /*may_wait=*/true, [&]() -> std::optional<Payouts> {
        if (++tries < 4)
            return std::nullopt;   // busy three times
        return one_payee(1000);
    }, miss);
    EXPECT_EQ(p, one_payee(1000));
    EXPECT_TRUE(miss.empty());
    EXPECT_EQ(tries, 4);
}

TEST(MergedPayoutSource, StillBusyReusesTheSameKey)
{
    MergedPayoutSource src(std::chrono::milliseconds(5), std::chrono::milliseconds(1));
    uint256 best;
    best.SetHex("78");
    std::string miss;
    auto free_lock = [&]() -> std::optional<Payouts> { return one_payee(1000); };
    auto busy_lock = []() -> std::optional<Payouts> { return std::nullopt; };
    ASSERT_EQ(src.get(best, 98, 1000, false, free_lock, miss), one_payee(1000));
    EXPECT_EQ(src.get(best, 98, 1000, false, busy_lock, miss), one_payee(1000)) << "same key: reused";
    EXPECT_TRUE(miss.empty());
    EXPECT_EQ(src.reused(), 1u);
    EXPECT_TRUE(src.get(best, 98, 2000, false, busy_lock, miss).empty()) << "another value: not reused";
    EXPECT_EQ(miss, "tracker_busy");
    uint256 other;
    other.SetHex("79");
    EXPECT_TRUE(src.get(other, 98, 1000, false, busy_lock, miss).empty()) << "another best share";
}

TEST(MergedPayoutSource, NetworkThreadDoesNotWait)
{
    MergedPayoutSource src(std::chrono::milliseconds(2000), std::chrono::milliseconds(1));
    uint256 best;
    best.SetHex("7a");
    std::string miss;
    const auto t0 = std::chrono::steady_clock::now();
    EXPECT_TRUE(src.get(best, 98, 1000, /*may_wait=*/false,
                        []() -> std::optional<Payouts> { return std::nullopt; }, miss).empty());
    EXPECT_LT(std::chrono::steady_clock::now() - t0, std::chrono::milliseconds(500));
    EXPECT_EQ(miss, "tracker_busy");
}
