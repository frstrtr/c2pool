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
//     busy: from the PPLNS weights the compute thread published for the best
//     share, re-derived exactly for any coinbase value (a 30 s busy stretch
//     with the fees changing every second still pays every rebuild), else a
//     short wait for the lock on the RPC thread; never from another best
//     share's weights (V36 peers re-derive them from the share's prev share),
//     and a kept block is dropped once the best share moves;
//   - a retry that leaves the work as it was does not push it to the miners
//     again; a kept block ages from when it was last kept; a find from an
//     older job is submitted only if it meets the bits of its own block.
// Folded into the allowlisted share_test target (no new executable: #769).
// ---------------------------------------------------------------------------

#include <gtest/gtest.h>

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <functional>
#include <map>
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
#include <impl/ltc/share.hpp>
#include <impl/ltc/share_tracker.hpp>

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
    std::string bits = "1a01d2c3";
    std::string target_hex = std::string(8, '0') + std::string(56, 'f');
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
        w.target.SetHex(target_hex);
        w.prev_block_hash = parent;
        w.block_template = {
            {"previousblockhash", parent}, {"height", 5'000'001}, {"bits", bits},
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

Payouts one_payee(uint64_t value, unsigned char who = 0x5c)
{
    std::vector<unsigned char> s{0x76, 0xa9, 0x14};
    s.insert(s.end(), 20, who);
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

/// A share whose LTC coinbase carries commitment `c` and whose parent PoW is
/// `pow`: try_submit_merged_blocks.
void submit_job(MergedMiningManager& mm, const std::vector<uint8_t>& c, const std::string& pow = "01")
{
    const std::string cb = std::string(20, 'a') + HexStr(std::span<const unsigned char>(c.data(), c.size()))
                         + std::string(20, 'b');
    uint256 parent_hash;
    parent_hash.SetHex(pow);
    mm.try_submit_merged_blocks(std::string(160, 'd'), cb, {}, 0, parent_hash);
}

/// A share on the current job (its coinbase carries the current commitment).
void submit_current_job(MergedMiningManager& mm)
{
    submit_job(mm, mm.get_auxpow_commitment());
}

struct Rig {
    boost::asio::io_context ioc;
    MergedMiningManager mm{ioc};
    EmbeddedLike* b{nullptr};
    bool payouts{true};
    unsigned char payee{0x5c};
    uint256 best;   // the sharechain best share the payouts are split at
    int64_t clock{1000};
    int work_pushes{0};
    Rig()
    {
        auto backend = std::make_unique<EmbeddedLike>();
        b = backend.get();
        mm.add_chain(b->cfg, std::move(backend));
        mm.set_payout_provider([this](uint32_t, uint64_t value) -> Payouts {
            MergedMiningManager::note_payout_basis(best);
            if (!payouts) {
                MergedMiningManager::note_payout_miss("tracker_busy");
                return {};
            }
            return one_payee(value, payee);
        });
        mm.set_clock_for_test([this] { return clock; });
        mm.set_on_work_changed([this] { ++work_pushes; });
    }
    /// Work pushes to the miners so far (the manager posts them to the io_context).
    int pushes()
    {
        ioc.restart();
        ioc.poll();
        return work_pushes;
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

// A chain without payouts is fetched again on every poll (block hash null)
// and dropped again: the miners' work does not change, so it is not pushed
// again (the canary pushed the same work every second of an episode).
TEST(MergedMining, RetriesWithoutPayoutsDoNotPushTheSameWork)
{
    Rig r;
    r.mm.refresh_aux_work();
    EXPECT_EQ(r.pushes(), 1) << "a block built: pushed";

    r.payouts = false;
    r.b->tip_id = std::string(62, '0') + "a3";
    r.b->parent = r.b->tip_id;
    r.mm.refresh_aux_work();
    EXPECT_EQ(r.pushes(), 2) << "the commitment dropped: pushed";
    for (int i = 0; i < 30; ++i)
        r.mm.refresh_aux_work();
    EXPECT_EQ(r.pushes(), 2) << "retries without payouts pushed the same work again";
    const auto j = r.mm.get_rebuild_stats_json();
    EXPECT_EQ(j["work_unchanged"], 30u);
    EXPECT_EQ(j["no_payouts"]["tracker_busy"], 31u) << "every poll still retried the rebuild";

    r.payouts = true;
    r.mm.refresh_aux_work();
    EXPECT_EQ(r.pushes(), 3) << "payouts back: the new block is pushed";
    EXPECT_FALSE(r.mm.get_auxpow_commitment().empty());
}

// The last block on the parent is kept while the payouts are unavailable and
// the miners keep committing to it. When a newer block on the same parent is
// frozen later, snapshots older than FROZEN_EXPIRY_SEC are pruned: the kept
// one must count its age from when it was last kept, or a find on a job still
// carrying it is skipped ("No matching snapshot").
TEST(MergedMining, KeptBlockDoesNotExpireUnderItsJobs)
{
    Rig r;
    r.mm.refresh_aux_work();   // block A, frozen at t=1000
    const uint256 a = r.mm.get_current_work().at(98).block_hash;

    r.payouts = false;
    r.clock = 1290;
    r.b->tip_id = std::string(62, '0') + "a2";   // fetched again, same parent
    r.b->curtime += 7;
    r.mm.refresh_aux_work();
    ASSERT_EQ(committed_root(r.mm), a) << "kept";
    const auto job_a = r.mm.get_auxpow_commitment();   // a job issued now

    r.clock = 1490;                                     // 490 s after A was frozen
    r.payouts = true;
    r.payee = 0x5d;                                     // new PPLNS split
    r.mm.mark_pplns_dirty();
    r.mm.refresh_aux_work();                            // block B frozen, prune runs
    ASSERT_NE(committed_root(r.mm), a);

    submit_job(r.mm, job_a);
    EXPECT_EQ(r.b->submits, 1) << "the kept block's snapshot expired under its jobs";
}

// The last block on the parent is kept while the payouts are unavailable,
// but only while its payouts are for the current best share: once the best
// moves (a new share), a job's LTC share carries the new best as prev share
// and a V36 peer would re-derive other payouts. The block is dropped, and
// the next one is built at the new best.
TEST(MergedMining, KeptBlockIsDroppedWhenTheBestMoves)
{
    Rig r;
    r.best.SetHex("b1");
    r.mm.refresh_aux_work();   // block A, payouts at b1
    const uint256 a = r.mm.get_current_work().at(98).block_hash;
    ASSERT_EQ(r.mm.get_cached_header_infos_and_commitment().first.at(0).payout_basis, r.best);

    r.payouts = false;
    r.b->tip_id = std::string(62, '0') + "a2";   // fetched again, same parent, same best
    r.b->curtime += 7;
    r.mm.refresh_aux_work();
    ASSERT_EQ(committed_root(r.mm), a) << "kept while the best is unchanged";

    r.best.SetHex("b2");                         // a new share; the tracker still busy
    r.mm.mark_pplns_dirty();
    r.mm.refresh_aux_work();
    EXPECT_TRUE(r.mm.get_auxpow_commitment().empty()) << "a block paying the previous best stays committed";
    EXPECT_TRUE(r.mm.get_cached_header_infos_and_commitment().first.empty());
    const auto j = r.mm.get_rebuild_stats_json();
    EXPECT_EQ(j["dropped_best_moved"], 1u);
    EXPECT_EQ(j["kept_last_block"], 1u);

    r.payouts = true;                            // weights for b2 published
    r.mm.refresh_aux_work();
    const auto [infos, commitment] = r.mm.get_cached_header_infos_and_commitment();
    ASSERT_EQ(infos.size(), 1u);
    EXPECT_EQ(infos[0].payout_basis, r.best);
    EXPECT_FALSE(commitment.empty());
    EXPECT_NE(committed_root(r.mm), a);
}

// A share from an older job whose block is on another parent, with harder
// bits than the current work: its PoW meets the current target but not the
// bits the block is built with. It must not be submitted (nor relayed).
TEST(MergedMining, OldJobMustMeetItsSnapshotsBits)
{
    Rig r;
    r.b->bits = "1a01d2c3";                                    // target ~2^201
    r.b->target_hex = std::string(12, '0') + "01d2c3" + std::string(46, '0');
    r.mm.refresh_aux_work();                                   // block A on parent a1
    const auto job_a = r.mm.get_auxpow_commitment();

    r.b->tip_id = std::string(62, '0') + "b2";                 // DOGE moves on, easier bits
    r.b->parent = r.b->tip_id;
    r.b->bits = "1d00ffff";                                    // target ~2^224
    r.b->target_hex = std::string(8, '0') + "ffff" + std::string(52, '0');
    r.mm.refresh_aux_work();                                   // block B on parent b2
    const auto job_b = r.mm.get_auxpow_commitment();
    ASSERT_NE(job_a, job_b);

    const std::string pow = std::string(11, '0') + "4" + std::string(52, '0');   // 2^210
    submit_job(r.mm, job_a, pow);
    EXPECT_EQ(r.b->submits, 0) << "a PoW-invalid block was submitted";
    EXPECT_EQ(r.mm.get_rebuild_stats_json()["snapshot_target_refusals"], 1u);

    submit_job(r.mm, job_b, pow);                              // control: B's bits are met
    EXPECT_EQ(r.b->submits, 1);
}

// ── MergedPayoutSource ──────────────────────────────────────────────────────

namespace {

/// Weights whose amounts are one payee taking the whole value.
MergedPayoutSource::Weights one_payee_weights(const uint256& best, int32_t chain_len = 10)
{
    MergedPayoutSource::Weights w;
    w.best = best;
    w.chain_id = 98;
    w.chain_len = chain_len;
    w.derive = [](uint64_t value) { return one_payee(value); };
    return w;
}

uint256 hx(const std::string& tail)
{
    uint256 v;
    v.SetHex(std::string(64 - tail.size(), '0') + tail);
    return v;
}

constexpr uint32_t kShareBits = 0x1e0fffff;
constexpr uint16_t kDonation = 50;   // per 65535

/// A run of V36 shares on top of `prev`, mined by `miners` in turn
/// (pubkey hash byte, pubkey type). Returns the tip.
uint256 add_shares(ltc::ShareTracker& t, uint256 prev, size_t salt,
                   const std::vector<std::pair<unsigned char, uint8_t>>& miners)
{
    for (size_t i = 0; i < miners.size(); ++i) {
        char buf[32];
        std::snprintf(buf, sizeof(buf), "%zx", (salt << 20) + 0x9d00 + i);
        auto* sh = new ltc::MergedMiningShare();
        sh->m_hash = hx(buf);
        sh->m_prev_hash = prev;
        sh->m_desired_version = 36;
        sh->m_bits = kShareBits;
        sh->m_max_bits = kShareBits;
        sh->m_donation = kDonation;
        sh->m_pubkey_hash.SetHex(std::string(40, "0123456789abcdef"[miners[i].first & 0xf]));
        sh->m_pubkey_type = miners[i].second;
        ltc::ShareType st;
        st = sh;
        t.add(st);
        prev = sh->m_hash;
    }
    return prev;
}

std::vector<unsigned char> combined_donation()
{
    return {ltc::PoolConfig::COMBINED_DONATION_SCRIPT.begin(), ltc::PoolConfig::COMBINED_DONATION_SCRIPT.end()};
}

/// The weights of `best`, as main_ltc publishes them.
MergedPayoutSource::Weights tracker_weights(ltc::ShareTracker& t, const uint256& best)
{
    auto w = std::make_shared<const ltc::MergedPayoutWeights>(t.get_merged_payout_weights(best, 98));
    MergedPayoutSource::Weights out;
    out.best = best;
    out.chain_id = 98;
    out.chain_len = w->chain_len;
    out.derive = [w](uint64_t value) {
        return ltc::ShareTracker::merged_payout_outputs(*w, value, combined_donation());
    };
    return out;
}

/// What the payout provider produced with the tracker lock taken for this
/// value (get_merged_expected_payouts, outputs >= 1, sorted).
Payouts with_the_lock(ltc::ShareTracker& t, const uint256& best, uint64_t value)
{
    Payouts out;
    for (auto& [script, amount] : t.get_merged_expected_payouts(best, uint256(), value, 98, combined_donation()))
        if (amount >= 1)
            out.emplace_back(script, amount);
    std::sort(out.begin(), out.end());
    return out;
}

uint64_t total(const Payouts& p)
{
    uint64_t s = 0;
    for (const auto& [script, amount] : p)
        s += amount;
    return s;
}

const auto kBusy = []() -> std::optional<MergedPayoutSource::Weights> { return std::nullopt; };

} // namespace

TEST(MergedPayoutSource, BusyLockIsWaitedFor)
{
    MergedPayoutSource src(std::chrono::milliseconds(200), std::chrono::milliseconds(1));
    const uint256 best = hx("77");
    int tries = 0;
    std::string miss;
    const auto p = src.get(best, 98, 1000, /*may_wait=*/true, [&]() -> std::optional<MergedPayoutSource::Weights> {
        if (++tries < 4)
            return std::nullopt;   // busy three times
        return one_payee_weights(best);
    }, miss);
    EXPECT_EQ(p, one_payee(1000));
    EXPECT_TRUE(miss.empty());
    EXPECT_EQ(tries, 4);
    EXPECT_EQ(src.stats().computed, 1u);
}

TEST(MergedPayoutSource, NetworkThreadDoesNotWait)
{
    MergedPayoutSource src(std::chrono::milliseconds(2000), std::chrono::milliseconds(1));
    std::string miss;
    const auto t0 = std::chrono::steady_clock::now();
    EXPECT_TRUE(src.get(hx("7a"), 98, 1000, /*may_wait=*/false, kBusy, miss).empty());
    EXPECT_LT(std::chrono::steady_clock::now() - t0, std::chrono::milliseconds(500));
    EXPECT_EQ(miss, "tracker_busy");
    EXPECT_EQ(src.stats().busy, 1u);
}

// The amounts for a new coinbase value (the fees changed) come from the
// weights alone, exactly as get_merged_expected_payouts computes them with
// the tracker lock, and by p2pool's arithmetic.
TEST(MergedPayoutSource, ValueChangeIsDerivedExactlyWithoutTheLock)
{
    ltc::ShareTracker t;
    // Five shares from miner 1 (P2PKH), three from miner 2 (P2WPKH, paid
    // P2PKH on DOGE), two from miner 3 (P2SH).
    const uint256 best = add_shares(t, uint256(), 1,
        {{1, 0}, {2, 1}, {1, 0}, {3, 2}, {1, 0}, {2, 1}, {1, 0}, {3, 2}, {2, 1}, {1, 0}});
    MergedPayoutSource src;
    src.publish(tracker_weights(t, best));

    for (uint64_t value : {1000000000000ULL, 1000000012345ULL, 999999999999ULL, 7ULL, 1ULL, 0ULL,
                           12345678901234ULL}) {
        std::string miss;
        const Payouts p = src.get(best, 98, value, false, kBusy, miss);   // lock busy throughout
        EXPECT_EQ(p, with_the_lock(t, best, value)) << "value " << value;
        if (value == 0) {
            EXPECT_TRUE(p.empty());
            continue;
        }
        EXPECT_EQ(total(p), value) << "value " << value;
        // p2pool: donation = v*Dw//Tw; miners = v - donation, split by weight
        // (5:3:2) with integer division; the remainder to the donation.
        const uint64_t donation = static_cast<uint64_t>(
            (static_cast<unsigned __int128>(value) * kDonation) / 65535);
        const uint64_t miners = value - donation;
        const uint64_t m1 = miners * 5 / 10, m2 = miners * 3 / 10, m3 = miners * 2 / 10;
        uint64_t don = donation + (miners - m1 - m2 - m3);
        std::map<std::vector<unsigned char>, uint64_t> want;
        const auto key = [](unsigned char b, uint8_t type) {
            uint160 h;
            h.SetHex(std::string(40, "0123456789abcdef"[b & 0xf]));
            return ltc::resolve_merged_payout_script(ltc::pubkey_hash_to_script(h, type));
        };
        if (m1) want[key(1, 0)] += m1;
        if (m2) want[key(2, 1)] += m2;
        if (m3) want[key(3, 2)] += m3;
        if (don < 1 && !want.empty()) {
            auto largest = std::max_element(want.begin(), want.end(), [](const auto& a, const auto& b) {
                return a.second != b.second ? a.second < b.second : a.first < b.first;
            });
            largest->second -= 1;
            don += 1;
        }
        want[combined_donation()] += don;
        Payouts w;
        for (auto& [script, amount] : want)
            if (amount >= 1)
                w.emplace_back(script, amount);
        std::sort(w.begin(), w.end());
        EXPECT_EQ(p, w) << "value " << value;
    }
    EXPECT_EQ(src.stats().from_weights, 7u);
    EXPECT_EQ(src.stats().busy, 0u);
}

// Two weight keys resolving to the same DOGE script (a miner's P2PKH and
// P2WPKH shares of one pubkey hash) are one output, split once on their
// summed weight, as p2pool's build_canonical_merged_coinbase does
// (script_weights). Summing two per-key floors gives a satoshi less to that
// output (and one more to the donation) whenever the split is not exact; a
// V36 peer re-derives the coinbase and would reject the share.
TEST(MergedPayoutSource, SameScriptFromTwoKeysIsSplitOnceLikeP2pool)
{
    ltc::ShareTracker t;
    const uint256 best = add_shares(t, uint256(), 4, {{1, 0}, {1, 1}, {2, 0}});   // h (P2PKH), h (P2WPKH), g
    const auto w = t.get_merged_payout_weights(best, 98);
    // The miners' reward m = v - floor(v*50/65535); pick v with m = 2 (mod 3).
    uint64_t value = 1000000000000ULL;
    while ((value - static_cast<uint64_t>((static_cast<unsigned __int128>(value) * kDonation) / 65535)) % 3 != 2)
        ++value;
    const uint64_t donation = static_cast<uint64_t>((static_cast<unsigned __int128>(value) * kDonation) / 65535);
    const uint64_t miners = value - donation;
    const auto script_of = [](unsigned char b) {
        uint160 h;
        h.SetHex(std::string(40, "0123456789abcdef"[b & 0xf]));
        return ltc::pubkey_hash_to_script(h, 0);
    };
    const uint64_t h_amount = miners * 2 / 3;   // p2pool: one floor on the summed weight
    const uint64_t g_amount = miners / 3;
    Payouts want{{script_of(1), h_amount}, {script_of(2), g_amount},
                 {combined_donation(), donation + (miners - h_amount - g_amount)}};
    std::sort(want.begin(), want.end());
    EXPECT_EQ(ltc::ShareTracker::merged_payout_outputs(w, value, combined_donation()), want);
    EXPECT_EQ(with_the_lock(t, best, value), want);
    EXPECT_NE(h_amount, 2 * (miners / 3)) << "the case where per-key floors differ";
}

// The tracker lock stays busy for 30 s (one rebuild a second, the fees
// changing every time): every rebuild on the best share whose weights the
// compute thread published gets payouts, re-derived exactly. The best share
// moves at 15 s and its weights are published at 20 s: in between there are
// NO payouts. The previous best's weights would build a coinbase no V36
// peer accepts on a share whose prev share is the new best (they re-derive
// it from previous_share_hash).
TEST(MergedPayoutSource, BusyLockPaysOnlyForThePublishedBest)
{
    ltc::ShareTracker t;
    const uint256 b1 = add_shares(t, uint256(), 2, {{1, 0}, {2, 0}, {1, 0}, {3, 0}});
    MergedPayoutSource src(std::chrono::milliseconds(0), std::chrono::milliseconds(1));
    src.publish(tracker_weights(t, b1));
    uint256 best = b1;
    uint256 b2;
    for (int sec = 0; sec < 30; ++sec) {
        const uint64_t value = 1000000000000ULL + 1000ULL * sec * sec;   // fees
        if (sec == 15) {
            b2 = add_shares(t, b1, 3, {{2, 0}});   // a new share: the best moves
            best = b2;
        }
        if (sec == 20)
            src.publish(tracker_weights(t, b2));   // the compute thread got there
        std::string miss;
        const Payouts p = src.get(best, 98, value, /*may_wait=*/true, kBusy, miss);
        if (sec >= 15 && sec < 20) {
            EXPECT_TRUE(p.empty()) << sec << " s: payouts for another best share";
            EXPECT_EQ(miss, "tracker_busy") << sec << " s";
            continue;
        }
        ASSERT_FALSE(p.empty()) << "no payouts at " << sec << " s (" << miss << ")";
        EXPECT_EQ(total(p), value) << sec << " s";
        EXPECT_EQ(p, with_the_lock(t, best, value)) << sec << " s";
    }
    const auto st = src.stats();
    EXPECT_EQ(st.from_weights, 25u);
    EXPECT_EQ(st.busy, 5u);
}

// One entry per best share: what the compute thread publishes for it (a
// deeper window while the tracker syncs below the same best share) replaces
// what was computed on request before.
TEST(MergedPayoutSource, DeeperWindowReplacesTheSameBest)
{
    MergedPayoutSource src;
    const uint256 best = hx("5e");
    auto at_depth = [&](int32_t chain_len, unsigned char who) {
        MergedPayoutSource::Weights w = one_payee_weights(best, chain_len);
        w.derive = [who](uint64_t v) { return one_payee(v, who); };
        return std::optional<MergedPayoutSource::Weights>(w);
    };
    std::string miss;
    EXPECT_EQ(src.get(best, 98, 10, false, [&] { return at_depth(100, 0x01); }, miss), one_payee(10, 0x01));
    EXPECT_EQ(src.get(best, 98, 10, false, kBusy, miss), one_payee(10, 0x01));
    src.publish(*at_depth(200, 0x02));
    EXPECT_EQ(src.get(best, 98, 10, false, kBusy, miss), one_payee(10, 0x02)) << "deeper";
    src.publish(*at_depth(150, 0x03));
    EXPECT_EQ(src.get(best, 98, 10, false, kBusy, miss), one_payee(10, 0x03)) << "published wins";
}

// Through the manager: with the tracker busy for 30 polls, each on a new
// DOGE tip with a new coinbase value, every rebuild builds a block and the
// chain never leaves the commitment.
TEST(MergedMining, BusyTrackerKeepsTheChainCommitted)
{
    Rig r;
    auto src = r.mm.payout_source();
    const uint256 best = hx("ab");
    src->publish(one_payee_weights(best));
    r.mm.set_payout_provider([&](uint32_t chain_id, uint64_t value) -> Payouts {
        std::string miss;
        auto p = src->get(best, chain_id, value, MergedMiningManager::on_rpc_thread(), kBusy, miss);
        if (p.empty())
            MergedMiningManager::note_payout_miss(miss);
        return p;
    });
    for (int i = 0; i < 30; ++i) {
        char tip[8];
        std::snprintf(tip, sizeof(tip), "%02x", 0x40 + i);
        r.b->tip_id = std::string(62, '0') + tip;
        r.b->parent = r.b->tip_id;
        r.mm.refresh_aux_work();
        ASSERT_FALSE(r.mm.get_auxpow_commitment().empty()) << "poll " << i;
        EXPECT_EQ(committed_root(r.mm), r.mm.get_current_work().at(98).block_hash);
    }
    const auto j = r.mm.get_rebuild_stats_json();
    EXPECT_EQ(j["dropped_commitment"], 0u);
    EXPECT_TRUE(j["no_payouts"].empty());
    EXPECT_EQ(j["no_payout_seconds"], 0);
    EXPECT_EQ(j["payout_source"]["from_weights"], 30u);
    EXPECT_EQ(j["payout_source"]["busy"], 0u);
    submit_current_job(r.mm);
    EXPECT_EQ(r.b->submits, 1);
}
