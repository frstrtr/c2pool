// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// No work is ever built on a burn output (rides core_test).
//
// refresh_work used to record the best share as the one the cached PPLNS was
// computed for BEFORE calling pplns_fn, and when pplns_fn returned nothing
// (the tracker try-lock failed) it cached a single output to the zero key
// (P2PKH 76a914 00..00 88ac) as that share's PPLNS: build_connection_coinbase
// then saw prev == cached best, skipped the recompute and built every job of
// that share on the burn output — a found block paid the whole subsidy to
// the zero key. The same fallback paid every --solo / --custodial block to the
// zero key (their best share is null, so pplns_fn was never called).
// Pinned on the real MiningInterface over a mock coin node, in the
// verifier's sequence:
//   - a busy tracker at a NEW best share: no burn output in any coinbase
//     (global or job), the cached pair is not poisoned, jobs on that share
//     are held until the split is computed;
//   - busy again at the SAME best share: the last valid split is reused;
//   - an empty sharechain: p2pool's genesis rule (the whole subsidy to the
//     donation script), never the zero key;
//   - solo / custodial (pplns_fn ignores the null best share): the global
//     coinbase pays their split.
// A cached split is also keyed by the template's coinbase value, bits and the
// donation script (its amounts depend on them): busy at the same best share
// after a new block or a fee change must not pay the old amounts (blocks
// rejected bad-cb-amount, or underpaid); jobs recompute or are held. Checked
// sequentially and with a refresher racing four job builders.
// ---------------------------------------------------------------------------

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <map>
#include <mutex>
#include <random>
#include <string>
#include <thread>
#include <vector>

#include <nlohmann/json.hpp>

#include <core/coin/node_iface.hpp>
#include <core/coin/work_view.hpp>
#include <core/uint256.hpp>
#include <core/web_server.hpp>

namespace {

using core::MiningInterface;
using Split = std::map<std::vector<unsigned char>, double>;

const std::string kBurn = "76a914" + std::string(40, '0') + "88ac";

struct LtcNode : public core::coin::ICoinNode {
    nlohmann::json work_data = {
        {"previousblockhash", std::string(62, '0') + "ab"}, {"version", 0x20000000},
        {"height", 100}, {"bits", "207fffff"}, {"curtime", 1600000000},
        {"coinbasevalue", 5000000000LL}, {"transactions", nlohmann::json::array()},
        {"rules", nlohmann::json::array({"csv", "!segwit", "taproot"})},
    };
    core::coin::WorkView get_work_view() override
    {
        core::coin::WorkView v;
        v.m_data = work_data;
        return v;
    }
    bool submit_block_hex(const std::string&, bool) override { return true; }
    bool is_embedded() const override { return false; }
    bool has_rpc() const override { return true; }
};

std::vector<unsigned char> p2pkh(unsigned char b)
{
    std::vector<unsigned char> s{0x76, 0xa9, 0x14};
    s.insert(s.end(), 20, b);
    s.push_back(0x88);
    s.push_back(0xac);
    return s;
}

std::string hex(const std::vector<unsigned char>& v)
{
    static const char* H = "0123456789abcdef";
    std::string r;
    for (auto b : v) { r += H[b >> 4]; r += H[b & 15]; }
    return r;
}

// The amount (LE64) right before "<len><script>" in a coinbase hex; -1 if the
// output is absent.
int64_t amount_of(const std::string& cb, const std::vector<unsigned char>& script)
{
    char lenhex[3];
    std::snprintf(lenhex, sizeof(lenhex), "%02x", static_cast<unsigned>(script.size()));
    const std::string needle = std::string(lenhex) + hex(script);
    auto p = cb.find(needle);
    if (p == std::string::npos || p < 16) return -1;
    const std::string le = cb.substr(p - 16, 16);
    uint64_t v = 0;
    for (int i = 7; i >= 0; --i) v = (v << 8) | std::stoul(le.substr(i * 2, 2), nullptr, 16);
    return static_cast<int64_t>(v);
}

// The BIP34 height in coinb1 (a 1..3-byte push right after the scriptSig length).
int height_of(const std::string& cb1)
{
    // 8 version + 2 vin + 64 prevhash + 8 index + 2 scriptlen = 84
    if (cb1.size() < 92) return -1;
    const int n = std::stoi(cb1.substr(84, 2), nullptr, 16);
    if (n < 1 || n > 3) return -1;
    int v = 0;
    for (int i = n - 1; i >= 0; --i) v = (v << 8) | std::stoi(cb1.substr(86 + i * 2, 2), nullptr, 16);
    return v;
}

struct Rig {
    LtcNode ltc;
    MiningInterface mi{/*testnet=*/true};
    uint256 best;
    bool busy{false};
    int pplns_calls{0};
    std::vector<unsigned char> don{0xa9, 0x14, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 0x87};
    Rig()
    {
        mi.set_coin_node(&ltc);
        mi.set_donation_script(don);
        mi.set_best_share_hash_fn([this] { return best; });
        // The LTC pool hook's shape: nothing for a null best share, nothing
        // while the tracker is busy, else a split that names the best share.
        mi.set_pplns_fn([this](const uint256& b, const uint256&, uint64_t subsidy,
                               const std::vector<unsigned char>& d) -> Split {
            ++pplns_calls;
            if (b.IsNull() || busy)
                return {};
            const unsigned char who = static_cast<unsigned char>(b.GetLow64() & 0xff);
            return {{p2pkh(who), static_cast<double>(subsidy - 1000)}, {d, 1000.0}};
        });
        mi.set_ref_hash_fn([](const uint256&, const std::vector<unsigned char>&, const std::vector<unsigned char>&,
                              uint64_t, uint32_t, uint32_t, bool, const std::string&, const uint256&,
                              const std::vector<std::pair<uint32_t, std::vector<unsigned char>>>&,
                              const std::vector<uint256>&) {
            MiningInterface::RefHashResult r;
            r.ref_hash.SetHex(std::string(64, '5'));
            r.bits = 0x207fffff;
            return r;
        });
    }
    std::string global()
    {
        auto [c1, c2] = mi.get_coinbase_parts();
        return c1 + c2;
    }
    MiningInterface::CoinbaseResult job(const uint256& prev)
    {
        const std::vector<unsigned char> payout = p2pkh(0x77);
        return mi.build_connection_coinbase(prev, "aabbccdd", payout, {});
    }
};

uint256 h(uint64_t n)
{
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%llx", static_cast<unsigned long long>(n));
    uint256 v;
    v.SetHex(buf);
    return v;
}

} // namespace

TEST(PplnsNoBurn, BusyTrackerAtANewBestShareNeverBurns)
{
    Rig r;
    r.best = h(0xa1);
    r.mi.refresh_work();
    ASSERT_TRUE(r.mi.cached_pplns_valid());
    EXPECT_NE(r.global().find(hex(p2pkh(0xa1))), std::string::npos) << "share A's split";
    auto ja = r.job(h(0xa1));
    ASSERT_FALSE(ja.held);
    EXPECT_NE((ja.coinb1 + ja.coinb2).find(hex(p2pkh(0xa1))), std::string::npos);

    // A new best share B while the tracker is busy (the verifier's sequence)
    r.best = h(0xb2);
    r.busy = true;
    r.mi.refresh_work();
    EXPECT_EQ(r.global().find(kBurn), std::string::npos) << "no burn in the global coinbase";
    EXPECT_TRUE(r.global().empty()) << "no global coinbase without a valid split";
    EXPECT_FALSE(r.mi.cached_pplns_valid()) << "the cache is not poisoned with B";
    EXPECT_EQ(r.mi.refreshes_without_pplns(), 1u);
    auto jb = r.job(h(0xb2));
    EXPECT_TRUE(jb.held) << "a job on B is held, not built on A's split or a burn";
    EXPECT_TRUE(jb.coinb1.empty());
    auto ja2 = r.job(h(0xa1));
    EXPECT_TRUE(ja2.held) << "the cached pair is not valid now: recomputed, and the tracker is busy";
    EXPECT_GE(r.mi.jobs_held(), 2u);

    // The tracker free again: a job on B computes B's split and caches it
    r.busy = false;
    auto jb2 = r.job(h(0xb2));
    ASSERT_FALSE(jb2.held);
    EXPECT_NE((jb2.coinb1 + jb2.coinb2).find(hex(p2pkh(0xb2))), std::string::npos);
    EXPECT_EQ((jb2.coinb1 + jb2.coinb2).find(kBurn), std::string::npos);
    EXPECT_TRUE(r.mi.cached_pplns_valid());

    // Busy again at the SAME best share: the last valid split is reused
    r.busy = true;
    r.mi.refresh_work();
    EXPECT_NE(r.global().find(hex(p2pkh(0xb2))), std::string::npos);
    EXPECT_TRUE(r.mi.cached_pplns_valid());
    auto jb3 = r.job(h(0xb2));
    EXPECT_FALSE(jb3.held) << "B's split is cached: no recompute needed";
    EXPECT_EQ((jb3.coinb1 + jb3.coinb2).find(kBurn), std::string::npos);
}

TEST(PplnsNoBurn, EmptySharechainPaysTheDonationNotTheZeroKey)
{
    Rig r;
    r.best = uint256();
    r.mi.refresh_work();
    EXPECT_EQ(r.global().find(kBurn), std::string::npos);
    EXPECT_NE(r.global().find(hex(r.don)), std::string::npos) << "p2pool's genesis rule";
    auto j = r.job(uint256());
    ASSERT_FALSE(j.held);
    EXPECT_NE((j.coinb1 + j.coinb2).find(hex(r.don)), std::string::npos);
    EXPECT_EQ((j.coinb1 + j.coinb2).find(kBurn), std::string::npos);
}

TEST(PplnsNoBurn, SoloAndCustodialPayTheirSplit)
{
    // --solo / --custodial: the best share is always null and pplns_fn
    // ignores it; no ref_hash_fn (the global coinbase is the job's).
    LtcNode ltc;
    MiningInterface mi{/*testnet=*/true};
    mi.set_coin_node(&ltc);
    const std::vector<unsigned char> don{0xa9, 0x14, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 0x87};
    mi.set_donation_script(don);
    mi.set_best_share_hash_fn([] { return uint256::ZERO; });
    const auto owner = p2pkh(0x0e);
    mi.set_pplns_fn([&owner](const uint256&, const uint256&, uint64_t subsidy, const std::vector<unsigned char>& d)
                        -> Split { return {{d, 1.0}, {owner, static_cast<double>(subsidy - 1)}}; });
    mi.refresh_work();
    auto [c1, c2] = mi.get_coinbase_parts();
    const std::string cb = c1 + c2;
    EXPECT_NE(cb.find(hex(owner)), std::string::npos) << "the owner is paid";
    EXPECT_EQ(cb.find(kBurn), std::string::npos) << "never the zero key";
}

TEST(PplnsNoBurn, ASplitIsOnlyReusedAtTheTemplateValueItWasComputedFor)
{
    Rig r;
    r.best = h(0xb2);
    r.mi.refresh_work();
    ASSERT_TRUE(r.mi.cached_pplns_valid());
    EXPECT_EQ(amount_of(r.global(), p2pkh(0xb2)), 5000000000LL - 1000);

    // A new block at the same best share (the value halves, or the fees
    // drop), and the tracker is busy at this refresh
    r.ltc.work_data["height"] = 101;
    r.ltc.work_data["coinbasevalue"] = 2500000000LL;
    r.busy = true;
    r.mi.refresh_work();
    EXPECT_TRUE(r.global().empty()) << "no global coinbase from a split of another coinbase value";
    EXPECT_FALSE(r.mi.cached_pplns_valid());
    auto held = r.job(h(0xb2));
    EXPECT_TRUE(held.held) << "the split at this value cannot be read: held";

    // The tracker free: the job recomputes at this template's value
    r.busy = false;
    auto j = r.job(h(0xb2));
    ASSERT_FALSE(j.held);
    EXPECT_EQ(amount_of(j.coinb1 + j.coinb2, p2pkh(0xb2)), 2500000000LL - 1000)
        << "the outputs add up to this template's value";
    EXPECT_TRUE(r.mi.cached_pplns_valid());

    // A fee change at the same best share and height: recomputed too
    r.ltc.work_data["coinbasevalue"] = 2500004350LL;
    r.mi.refresh_work();
    EXPECT_EQ(amount_of(r.global(), p2pkh(0xb2)), 2500004350LL - 1000);
    const int calls = r.pplns_calls;
    r.busy = true;
    r.ltc.work_data["coinbasevalue"] = 2500001440LL;
    r.mi.refresh_work();
    auto j2 = r.job(h(0xb2));
    EXPECT_TRUE(j2.held) << "never the amounts of 2500004350";
    EXPECT_GT(r.pplns_calls, calls);
}

TEST(PplnsNoBurn, ANewDonationScriptAtTheSameBestShareRecomputes)
{
    Rig r;
    r.best = h(0xc3);
    r.mi.refresh_work();
    ASSERT_FALSE(r.job(h(0xc3)).held);
    const int calls = r.pplns_calls;
    ASSERT_FALSE(r.job(h(0xc3)).held);
    EXPECT_EQ(r.pplns_calls, calls) << "same share, value, bits, donation: the cached split";

    const std::vector<unsigned char> don2{0xa9, 0x14, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 0x87};
    r.mi.set_donation_script(don2);
    auto j = r.job(h(0xc3));
    ASSERT_FALSE(j.held);
    EXPECT_EQ(r.pplns_calls, calls + 1) << "another donation script: recomputed";
    EXPECT_EQ(amount_of(j.coinb1 + j.coinb2, don2), 1000);
}

TEST(PplnsNoBurn, AJobRecomputedBeforeAnyValidRefreshPaysRealScripts)
{
    // A restart onto an existing sharechain with the tracker busy at the
    // first refresh: nothing was cached yet, and the job's recomputed outputs
    // are scripts (they were read as hash160s and wrapped into P2PKH garbage).
    Rig r;
    r.best = h(0xd4);
    r.busy = true;
    r.mi.refresh_work();
    ASSERT_FALSE(r.mi.cached_pplns_valid());
    r.busy = false;
    auto j = r.job(h(0xd4));
    ASSERT_FALSE(j.held);
    const std::string cb = j.coinb1 + j.coinb2;
    EXPECT_EQ(amount_of(cb, p2pkh(0xd4)), 5000000000LL - 1000);
    EXPECT_EQ(amount_of(cb, r.don), 1000);
}

namespace {

uint64_t value_for_height(int ht) { return 1000000000ULL + static_cast<uint64_t>(ht) * 1000ULL; }

// A template source a refresher thread changes while jobs are built.
struct RacingNode : public core::coin::ICoinNode {
    std::mutex mu;
    int height = 1000;
    core::coin::WorkView get_work_view() override
    {
        std::lock_guard<std::mutex> l(mu);
        core::coin::WorkView v;
        v.m_data = {
            {"previousblockhash", std::string(62, '0') + "ab"}, {"version", 0x20000000},
            {"height", height}, {"bits", "207fffff"}, {"curtime", 1600000000},
            {"coinbasevalue", value_for_height(height)}, {"transactions", nlohmann::json::array()},
            {"rules", nlohmann::json::array({"csv", "!segwit", "taproot"})},
        };
        return v;
    }
    void next_block()
    {
        std::lock_guard<std::mutex> l(mu);
        ++height;
    }
    bool submit_block_hex(const std::string&, bool) override { return true; }
    bool is_embedded() const override { return false; }
    bool has_rpc() const override { return true; }
};

} // namespace

TEST(PplnsNoBurn, ConcurrentJobsPayTheirOwnShareAtTheirOwnTemplateValue)
{
    RacingNode node;
    MiningInterface mi{/*testnet=*/true};
    std::mutex best_mu;
    uint256 best = h(0xa1);
    std::atomic<bool> busy{false};
    const std::vector<unsigned char> don{0xa9, 0x14, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 0x87};
    mi.set_coin_node(&node);
    mi.set_donation_script(don);
    mi.set_best_share_hash_fn([&] { std::lock_guard<std::mutex> l(best_mu); return best; });
    mi.set_pplns_fn([&](const uint256& b, const uint256&, uint64_t subsidy, const std::vector<unsigned char>& d) -> Split {
        if (b.IsNull() || busy.load())
            return {};
        const unsigned char who = static_cast<unsigned char>(b.GetLow64() & 0xff);
        return {{p2pkh(who), static_cast<double>(subsidy - 1000)}, {d, 1000.0}};
    });
    mi.set_ref_hash_fn([&](const uint256&, const std::vector<unsigned char>&, const std::vector<unsigned char>&,
                           uint64_t, uint32_t, uint32_t, bool, const std::string&, const uint256&,
                           const std::vector<std::pair<uint32_t, std::vector<unsigned char>>>&,
                           const std::vector<uint256>&) {
        MiningInterface::RefHashResult r;
        if (busy.load())
            return r;   // the LTC hook: null while the tracker is busy
        r.ref_hash.SetHex(std::string(64, '5'));
        r.bits = 0x207fffff;
        return r;
    });
    mi.refresh_work();

    std::atomic<bool> stop{false};
    std::atomic<uint64_t> jobs{0}, held{0}, burns{0}, wrong_share{0}, wrong_value{0}, global_burns{0};
    const uint64_t shares[] = {0xa1, 0xb2, 0xc3, 0xd4};
    std::thread refresher([&] {
        std::mt19937 rng(1);
        while (!stop.load()) {
            const unsigned k = rng() % 8;
            if (k == 0) {
                std::lock_guard<std::mutex> l(best_mu);
                best = h(shares[rng() % 4]);
            }
            if (k == 1)
                node.next_block();
            busy = (rng() % 3) == 0;
            mi.refresh_work();
            auto [c1, c2] = mi.get_coinbase_parts();
            if ((c1 + c2).find(kBurn) != std::string::npos)
                ++global_burns;
        }
    });
    std::vector<std::thread> builders;
    for (int t = 0; t < 4; ++t) {
        builders.emplace_back([&, t] {
            std::mt19937 rng(100 + t);
            const std::vector<unsigned char> payout = p2pkh(0x77);
            while (!stop.load()) {
                const uint64_t s = shares[rng() % 4];
                auto j = mi.build_connection_coinbase(h(s), "aabbccdd", payout, {});
                ++jobs;
                if (j.held) { ++held; continue; }
                if (j.coinb1.empty()) continue;
                const std::string cb = j.coinb1 + j.coinb2;
                if (cb.find(kBurn) != std::string::npos) ++burns;
                const int64_t amt = amount_of(cb, p2pkh(static_cast<unsigned char>(s & 0xff)));
                if (amt < 0) { ++wrong_share; continue; }
                if (amt != static_cast<int64_t>(value_for_height(height_of(j.coinb1))) - 1000) ++wrong_value;
            }
        });
    }
    std::this_thread::sleep_for(std::chrono::seconds(4));
    stop = true;
    refresher.join();
    for (auto& b : builders) b.join();
    std::printf("[no-burn race] jobs=%llu held=%llu\n", static_cast<unsigned long long>(jobs.load()),
                static_cast<unsigned long long>(held.load()));
    EXPECT_GT(jobs.load() - held.load(), 0u) << "some jobs were built";
    EXPECT_EQ(burns.load(), 0u);
    EXPECT_EQ(global_burns.load(), 0u);
    EXPECT_EQ(wrong_share.load(), 0u) << "a job paid a split that is not its prev share's";
    EXPECT_EQ(wrong_value.load(), 0u) << "a job paid amounts computed for another template value";
}

TEST(PplnsNoBurn, ARefreshWithoutAGlobalCoinbaseKeepsTheLastReserve)
{
    // The template's block budget reserves room for the coinbase (weight,
    // sigops) from the last coinbase built. A refresh that builds no global
    // coinbase (no valid split) used to note an empty one and reset the
    // reserve to nothing while the jobs' coinbases stay full size.
    Rig r;
    r.best = h(0xa1);
    r.mi.refresh_work();
    ASSERT_FALSE(r.global().empty());
    const uint32_t weight = r.mi.coinbase_weight_reserve();
    const uint32_t sigops = r.mi.coinbase_sigop_reserve();
    ASSERT_GT(weight, 0u);

    r.best = h(0xb2);
    r.busy = true;
    r.mi.refresh_work();
    ASSERT_TRUE(r.global().empty());
    EXPECT_EQ(r.mi.coinbase_weight_reserve(), weight) << "the last real coinbase's weight is kept";
    EXPECT_EQ(r.mi.coinbase_sigop_reserve(), sigops);
}
