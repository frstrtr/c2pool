// SPDX-License-Identifier: AGPL-3.0-or-later
// P2': the frozen-job registry's byte cap, age eviction and count backstop
// (dash::mint::FrozenJobRegistry), the cap rule read from the cgroup
// (frozen_registry_cap_from_cgroup), and the producer job cache's age sweep
// (dash::mint::ProducerJobCache).
//
// Every registry here runs on an injected clock: no real sleeps. A "full-size"
// template is 3,976,000 hex characters (4,970 txs of 400 bytes), the size the
// mainnet peak puts on one vector.

#include <impl/dash/mint_runloop.hpp>
#include <impl/dash/coin/rpc_data.hpp>   // TemplateTxHex, live_template_hex_chars

#include <core/uint256.hpp>

#include <gtest/gtest.h>

#include <algorithm>
#include <chrono>
#include <iostream>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <vector>

namespace {

using dash::mint::FrozenEvictCause;
using dash::mint::FrozenJobRegistry;
using dash::mint::FrozenRegistryConfig;
using dash::mint::kMiB;
using dash::stratum::FrozenMintJob;
using namespace std::chrono_literals;

using HexVec = std::shared_ptr<const std::vector<std::string>>;

struct FakeClock {
    std::chrono::steady_clock::time_point t =
        std::chrono::steady_clock::time_point{} + std::chrono::hours(1);
    FrozenJobRegistry::Clock fn()
    {
        return [this] { return t; };
    }
    template <typename D>
    void advance(D d) { t += std::chrono::duration_cast<std::chrono::steady_clock::duration>(d); }
};

uint256 key(uint64_t i, unsigned char tag = 0x01)
{
    std::vector<unsigned char> b(32, 0x00);
    b[0] = tag;
    for (int k = 0; k < 8; ++k) b[1 + k] = static_cast<unsigned char>(i >> (8 * k));
    b[31] = 0x5a;
    return uint256(b);
}
uint256 tip(unsigned char n) { return key(n, 0xb0); }
uint256 share(unsigned char n) { return key(n, 0x5c); }

HexVec hex_vec(size_t txs, size_t chars, char fill = 'a')
{
    auto v = std::make_shared<std::vector<std::string>>();
    v->reserve(txs);
    for (size_t i = 0; i < txs; ++i) v->emplace_back(chars, fill);
    return v;
}

FrozenMintJob job_with(HexVec v, size_t hashes, uint32_t nonce = 0)
{
    FrozenMintJob j;
    j.tx_data_hex = std::move(v);
    j.desired_tx_hashes.assign(hashes, uint256());
    j.share_nonce = nonce;
    return j;
}

FrozenRegistryConfig cfg_cap(uint64_t cap_bytes, size_t backstop = dash::mint::kFrozenJobBackstop)
{
    FrozenRegistryConfig c;
    c.cap_bytes = cap_bytes;
    c.backstop  = backstop;
    return c;
}

// The bytes one entry (with its own vector) adds: the vector once + the entry.
uint64_t one_entry_bytes(const FrozenMintJob& j)
{
    return (j.tx_data_hex ? dash::mint::frozen_vector_bytes(*j.tx_data_hex) : 0) +
           dash::mint::frozen_entry_bytes(j);
}

}  // namespace

// A sustained stream of full-size templates, far over the cap: 1 and 8 payouts
// per template, a new best share every 5 templates, a new tip every 25, 8 s
// apart (so the current context plus the ones inside the 45 s grace hold at
// most 11 templates, about 57 MiB, under the 64 MiB cap). After EVERY put the registry is at or under its cap, its bytes equal
// an independent count (each live vector once, every live entry's own bytes),
// the brake never engages, and every job on the current tip and best share is
// still held (so the newest job of every payout hits).
TEST(DashFrozenJobRegistryCap, FloodFullTemplatesStaysUnderCap)
{
    for (const size_t payouts : {size_t{1}, size_t{8}}) {
        SCOPED_TRACE("payouts=" + std::to_string(payouts));
        FakeClock clk;
        const uint64_t cap = 64 * kMiB;
        FrozenJobRegistry reg(cfg_cap(cap), clk.fn());

        struct Put { const void* vec; uint64_t vec_bytes; uint64_t entry_bytes; };
        std::map<uint256, Put> maybe_held;     // refs the test has not seen evicted
        std::vector<uint256> current_ctx;      // refs put on the current tip + share
        unsigned char t = 1, sh = 1;
        uint64_t n = 0;
        for (int step = 0; step < 180; ++step) {
            clk.advance(8s);
            if (step > 0 && step % 25 == 0) { ++t; ++sh; current_ctx.clear(); }
            else if (step > 0 && step % 5 == 0) { ++sh; current_ctx.clear(); }
            HexVec v = hex_vec(4970, 800);   // 3,976,000 hex chars
            const uint64_t vb = dash::mint::frozen_vector_bytes(*v);
            for (size_t p = 0; p < payouts; ++p) {
                const FrozenMintJob j = job_with(v, 4970, static_cast<uint32_t>(n));
                const uint256 r = key(++n);
                reg.put(r, j, tip(t), share(sh));
                maybe_held[r] = Put{v.get(), vb, dash::mint::frozen_entry_bytes(j)};
                current_ctx.push_back(r);

                uint64_t expect = 0;
                std::set<const void*> vecs;
                for (auto it = maybe_held.begin(); it != maybe_held.end();) {
                    if (!reg.contains(it->first)) { it = maybe_held.erase(it); continue; }
                    if (vecs.insert(it->second.vec).second) expect += it->second.vec_bytes;
                    expect += it->second.entry_bytes;
                    ++it;
                }
                ASSERT_EQ(reg.bytes(), expect) << "step " << step << " payout " << p;
                ASSERT_LE(reg.bytes(), cap) << "step " << step << " payout " << p;
                ASSERT_FALSE(reg.brake_on()) << "step " << step;
                for (const auto& c : current_ctx)
                    ASSERT_TRUE(reg.contains(c)) << "a current-tip, current-share job was evicted"
                                                 << " at step " << step;
            }
        }
        const auto s = reg.stats();
        EXPECT_GT(s.evict_cap_oldtip, 0u);
        EXPECT_GT(s.evict_cap_oldshare, 0u);
        EXPECT_EQ(s.evict_age, 0u);
        EXPECT_EQ(s.evict_backstop, 0u);
        EXPECT_EQ(s.brake_episodes, 0u);
        EXPECT_LE(s.peak_bytes, cap);
    }
}

// Every put on ONE tip and ONE best share: nothing unexpired is evicted, the
// registry admits past its cap and raises the brake. Once the best share moves
// and the grace has passed, the superseded entries are trimmed to below 80% of
// the cap (the brake's trim level, not just the cap) and the brake is released.
TEST(DashFrozenJobRegistryCap, FloodOneTipAdmitsAndFlagsBackpressure)
{
    FakeClock clk;
    const uint64_t cap = 16 * kMiB;
    FrozenJobRegistry reg(cfg_cap(cap), clk.fn());
    std::vector<uint256> refs;
    for (uint64_t i = 1; i <= 30; ++i) {
        clk.advance(5s);
        const uint256 r = key(i);
        reg.put(r, job_with(hex_vec(256, 4096), 256), tip(1), share(1));
        refs.push_back(r);
        for (const auto& x : refs) ASSERT_TRUE(reg.contains(x)) << "put " << i;
        ASSERT_EQ(reg.size(), refs.size());
        if (reg.bytes() > cap) ASSERT_TRUE(reg.brake_on()) << "put " << i;
    }
    EXPECT_GT(reg.bytes(), cap);
    EXPECT_TRUE(reg.brake_on());
    EXPECT_EQ(reg.stats().brake_episodes, 1u);
    EXPECT_EQ(reg.stats().evict_cap_oldshare + reg.stats().evict_cap_oldtip, 0u);

    // A new best share: the old entries are superseded, inside the grace.
    clk.advance(5s);
    reg.put(key(100), job_with(hex_vec(256, 4096), 256), tip(1), share(2));
    EXPECT_EQ(reg.size(), 31u);
    EXPECT_TRUE(reg.brake_on());

    // Still inside the grace: nothing goes, the brake holds.
    clk.advance(dash::mint::kFrozenJobGrace - 1s);
    reg.put(key(101), job_with(hex_vec(256, 4096), 256), tip(1), share(2));
    EXPECT_EQ(reg.size(), 32u);
    EXPECT_TRUE(reg.brake_on());

    // Past the grace: old-share entries go, oldest first, to below 80%.
    clk.advance(2s);
    reg.put(key(102), job_with(hex_vec(256, 4096), 256), tip(1), share(2));
    EXPECT_LT(reg.bytes() * 5, cap * 4);
    EXPECT_FALSE(reg.brake_on()) << "the brake must be released once the kept entries fit";
    EXPECT_TRUE(reg.contains(key(100)));
    EXPECT_TRUE(reg.contains(key(101)));
    EXPECT_TRUE(reg.contains(key(102)));
    EXPECT_FALSE(reg.contains(key(1))) << "oldest first";
    EXPECT_TRUE(reg.contains(key(30))) << "only down to the trim level";
    EXPECT_GT(reg.stats().evict_cap_oldshare, 0u);
    EXPECT_EQ(reg.stats().brake_episodes, 1u);
}

// Strictly more than 420 s after the last put, and only on the next put.
TEST(DashFrozenJobRegistryCap, AgeEvictsAfterTAgeOnNextPut)
{
    FakeClock clk;
    FrozenJobRegistry reg(FrozenRegistryConfig{}, clk.fn());
    reg.put(key(1), job_with(nullptr, 3), tip(1), share(1));
    clk.advance(420s);
    reg.put(key(2), job_with(nullptr, 3), tip(1), share(1));
    EXPECT_TRUE(reg.contains(key(1))) << "evicted at exactly 420.000 s";
    clk.advance(1ms);
    reg.put(key(3), job_with(nullptr, 3), tip(1), share(1));
    EXPECT_FALSE(reg.contains(key(1))) << "held at 420.001 s after a put";
    EXPECT_TRUE(reg.contains(key(2)));
    const auto miss = reg.lookup_for_mint(key(1));
    ASSERT_FALSE(miss.job.has_value());
    EXPECT_TRUE(miss.evicted);
    EXPECT_EQ(miss.cause, FrozenEvictCause::age);
    EXPECT_EQ(reg.stats().evict_age, 1u);
}

// A re-put at +300 s keeps the entry to +720 s.
TEST(DashFrozenJobRegistryCap, ReputRefreshesAge)
{
    FakeClock clk;
    FrozenJobRegistry reg(FrozenRegistryConfig{}, clk.fn());
    const FrozenMintJob j = job_with(hex_vec(4, 64), 4);
    reg.put(key(1), j, tip(1), share(1));
    clk.advance(300s);
    reg.put(key(1), j, tip(1), share(1));   // the job cache hit's re-put
    EXPECT_EQ(reg.stats().reputs, 1u);
    clk.advance(420s);                        // +720.000
    reg.put(key(2), job_with(nullptr, 0), tip(1), share(1));
    EXPECT_TRUE(reg.contains(key(1))) << "the re-put did not refresh the age";
    clk.advance(1ms);                         // +720.001
    reg.put(key(3), job_with(nullptr, 0), tip(1), share(1));
    EXPECT_FALSE(reg.contains(key(1)));
}

// With no puts nothing is swept: an hour later a get and a mint lookup hit.
TEST(DashFrozenJobRegistryCap, NoSweepWithoutPuts)
{
    FakeClock clk;
    FrozenJobRegistry reg(FrozenRegistryConfig{}, clk.fn());
    reg.put(key(1), job_with(hex_vec(4, 64), 4, 7), tip(1), share(1));
    clk.advance(1h);
    ASSERT_TRUE(reg.get(key(1)).has_value());
    const auto hit = reg.lookup_for_mint(key(1));
    ASSERT_TRUE(hit.job.has_value());
    EXPECT_EQ(hit.job->share_nonce, 7u);
    EXPECT_EQ(reg.size(), 1u);
    EXPECT_EQ(reg.stats().evict_age, 0u);
    reg.put(key(2), job_with(nullptr, 0), tip(1), share(1));
    EXPECT_FALSE(reg.contains(key(1))) << "the next put evicts it";
}

// Over the cap: old-tip entries go first, oldest first, then old-share
// entries, never the current tip and share. The old-tip entries here are
// NEWER than the old-share ones (a put on another tip came in between), so
// last-put order alone would pick the wrong ones.
TEST(DashFrozenJobRegistryCap, EvictionOrderOldTipThenOldShare)
{
    FakeClock clk;
    const FrozenMintJob probe = job_with(hex_vec(64, 1024), 64);
    const uint64_t one = one_entry_bytes(probe);
    // 5 entries raise the brake; its trim level (80% of 4.4) then keeps 3.
    const uint64_t cap = one * 22 / 5;
    FrozenJobRegistry reg(cfg_cap(cap), clk.fn());

    auto put = [&](uint64_t i, unsigned char t, unsigned char s) {
        reg.put(key(i), job_with(hex_vec(64, 1024), 64), tip(t), share(s));
    };
    put(1, 2, 1); put(2, 2, 1);           // tip B, share S1: become old-share (T2)
    clk.advance(1s);
    put(3, 1, 0); put(4, 1, 0);           // tip A: becomes old-tip (T1)
    clk.advance(1s);
    put(5, 2, 2);                         // tip B, share S2: current
    EXPECT_EQ(reg.size(), 5u) << "inside the grace nothing is evictable";
    EXPECT_TRUE(reg.brake_on());
    clk.advance(dash::mint::kFrozenJobGrace + 1s);
    put(6, 2, 2);

    EXPECT_FALSE(reg.contains(key(3)));
    EXPECT_FALSE(reg.contains(key(4)));
    EXPECT_FALSE(reg.contains(key(1)));
    EXPECT_TRUE(reg.contains(key(2))) << "an old-share entry went before an old-tip one";
    EXPECT_TRUE(reg.contains(key(5)));
    EXPECT_TRUE(reg.contains(key(6)));
    EXPECT_LE(reg.bytes(), cap);
    const auto s = reg.stats();
    EXPECT_EQ(s.evict_cap_oldtip, 2u);
    EXPECT_EQ(s.evict_cap_oldshare, 1u);
    EXPECT_EQ(reg.lookup_for_mint(key(3)).cause, FrozenEvictCause::cap_oldtip);
    EXPECT_EQ(reg.lookup_for_mint(key(1)).cause, FrozenEvictCause::cap_oldshare);
}

// An entry superseded less than the grace (45 s) ago survives cap pressure, by
// old share and by old tip; just past the grace it goes.
TEST(DashFrozenJobRegistryCap, GraceKeepsJustSupersededEntries)
{
    for (const bool by_tip : {false, true}) {
        SCOPED_TRACE(by_tip ? "old tip" : "old share");
        FakeClock clk;
        const uint64_t one = one_entry_bytes(job_with(hex_vec(64, 1024), 64));
        FrozenJobRegistry reg(cfg_cap(2 * one + one / 2), clk.fn());
        auto put = [&](uint64_t i, unsigned char t, unsigned char s) {
            reg.put(key(i), job_with(hex_vec(64, 1024), 64), tip(t), share(s));
        };
        put(1, 1, 1);
        clk.advance(1s);
        put(2, 1, 1);
        clk.advance(1s);
        put(3, by_tip ? 2 : 1, 2);        // supersedes (1, 1) now
        clk.advance(dash::mint::kFrozenJobGrace - 1s);
        put(4, by_tip ? 2 : 1, 2);        // 44 s after: over the cap, nothing evictable
        EXPECT_TRUE(reg.contains(key(1)));
        EXPECT_TRUE(reg.contains(key(2)));
        EXPECT_TRUE(reg.brake_on());
        clk.advance(1001ms);              // 45.001 s after
        put(5, by_tip ? 2 : 1, 2);
        EXPECT_FALSE(reg.contains(key(1)));
        EXPECT_FALSE(reg.contains(key(2)));
        EXPECT_TRUE(reg.contains(key(3)));
        EXPECT_TRUE(reg.contains(key(4)));
        EXPECT_TRUE(reg.contains(key(5)));
    }
}

// 64 entries on one vector count its bytes once. With 63 of them evicted the
// vector is still held and counted; the last one takes it out.
TEST(DashFrozenJobRegistryCap, SharedVectorCountedOnce)
{
    FakeClock clk;
    FrozenJobRegistry reg(FrozenRegistryConfig{}, clk.fn());
    HexVec v = hex_vec(1000, 400);
    const uint64_t vb = dash::mint::frozen_vector_bytes(*v);
    const uint64_t eb = dash::mint::frozen_entry_bytes(job_with(v, 10));
    for (uint64_t i = 1; i <= 63; ++i) reg.put(key(i), job_with(v, 10), tip(1), share(1));
    clk.advance(100s);
    reg.put(key(64), job_with(v, 10), tip(1), share(1));
    v.reset();
    auto s = reg.stats();
    EXPECT_EQ(s.vectors, 1u);
    EXPECT_EQ(s.hex_bytes, vb);
    EXPECT_EQ(s.bytes, vb + 64 * eb);

    clk.advance(320500ms);   // 420.5 s after the first 63, 320.5 s after the 64th
    reg.put(key(65), job_with(nullptr, 0), tip(1), share(1));
    s = reg.stats();
    EXPECT_EQ(s.evict_age, 63u);
    EXPECT_EQ(s.vectors, 1u);
    EXPECT_EQ(s.hex_bytes, vb);

    clk.advance(100s);
    reg.put(key(66), job_with(nullptr, 0), tip(1), share(1));
    s = reg.stats();
    EXPECT_EQ(s.evict_age, 64u);
    EXPECT_EQ(s.vectors, 0u);
    EXPECT_EQ(s.hex_bytes, 0u);
}

// Every entry's own tx hash list is counted, even when the entries share one
// vector: 8,800 hashes add 281,600 bytes per entry.
TEST(DashFrozenJobRegistryCap, HashListBytesCounted)
{
    FakeClock clk;
    FrozenJobRegistry reg(FrozenRegistryConfig{}, clk.fn());
    HexVec v = hex_vec(8800, 452);
    reg.put(key(1), job_with(v, 8800), tip(1), share(1));
    uint64_t before = reg.bytes();
    for (uint64_t i = 2; i <= 9; ++i) {
        reg.put(key(i), job_with(v, 8800), tip(1), share(1));
        const uint64_t delta = reg.bytes() - before;
        EXPECT_GE(delta, 8800u * 32u) << "entry " << i;
        EXPECT_EQ(delta, dash::mint::kFrozenEntryFixedBytes + 8800u * 32u) << "entry " << i;
        before = reg.bytes();
    }
    EXPECT_EQ(reg.stats().vectors, 1u);
}

// Vectors encoded the way the template store encodes them (TemplateTxHex), held
// by the registry and the producer job cache. After a flood, an age-out and the
// job cache's sweep, the process-wide hex gauge is back at its baseline: no
// eviction record keeps a vector alive.
TEST(DashFrozenJobRegistryCap, GaugeReturnsToBaseline)
{
    const int64_t baseline = dash::coin::live_template_hex_chars();
    FakeClock clk;
    FrozenJobRegistry reg(cfg_cap(1 * kMiB), clk.fn());
    dash::mint::ProducerJobCache cache;
    dash::coin::DashWorkData wd;
    wd.m_previous_block = tip(1);
    wd.m_height         = 100;
    {
        std::vector<std::string> bodies(100, std::string(2000, 'c'));
        for (uint64_t i = 1; i <= 20; ++i) {
            clk.advance(5s);
            bodies[0][0] = static_cast<char>('a' + (i % 20));
            const auto tx = dash::coin::TemplateTxHex::encode(bodies, i);
            auto build = std::make_shared<dash::mint::ProducerJobBuild>();
            build->frozen   = job_with(tx.hex(), 100);
            build->job.ref_hash = key(i);
            reg.put(key(i), build->frozen, tip(1), share(static_cast<unsigned char>(1 + i / 5)));
            cache.store({share(static_cast<unsigned char>(i)), {0x76}}, build, tip(1), 100, clk.t);
        }
    }
    EXPECT_GT(dash::coin::live_template_hex_chars(), baseline);
    EXPECT_GT(reg.stats().evict_cap_oldshare, 0u);

    clk.advance(421s);
    reg.put(key(1000), job_with(nullptr, 0), tip(1), share(9));
    const auto s = reg.stats();
    EXPECT_EQ(s.vectors, 0u);
    EXPECT_EQ(s.hex_bytes, 0u);
    EXPECT_EQ(s.bytes, dash::mint::frozen_entry_bytes(job_with(nullptr, 0)));
    EXPECT_GT(dash::coin::live_template_hex_chars(), baseline) << "the job cache still holds them";

    (void)cache.find({uint256(), {}}, wd, clk.t);   // any call sweeps
    EXPECT_EQ(cache.size(), 0u);
    EXPECT_EQ(dash::coin::live_template_hex_chars(), baseline);
}

// cap = min(256 MiB, memory.max / 8), floor 64 MiB, 256 MiB without a limit;
// the smallest limit over the cgroup and its ancestors; v1 as a fallback.
TEST(DashFrozenJobRegistryCap, CapFromCgroupMemoryMax)
{
    using dash::mint::frozen_registry_cap_from_cgroup;
    auto reader = [](std::map<std::string, std::string> files) {
        return dash::mint::TextFileReader([files](const std::string& p) -> std::optional<std::string> {
            auto it = files.find(p);
            if (it == files.end()) return std::nullopt;
            return it->second;
        });
    };
    const std::string self = "0::/system.slice/c2pool-dash.service\n";
    const std::string svc  = "/sys/fs/cgroup/system.slice/c2pool-dash.service/memory.max";
    const std::string sl   = "/sys/fs/cgroup/system.slice/memory.max";

    {   // no limit anywhere
        auto c = frozen_registry_cap_from_cgroup(reader({{"/proc/self/cgroup", self}, {svc, "max\n"}, {sl, "max\n"}}));
        EXPECT_EQ(c.cap_bytes, 256 * kMiB);
        EXPECT_EQ(c.source, "cgroup2");
        EXPECT_FALSE(c.memory_max.has_value());
    }
    {   // 5 GiB (the hotel primary): /8 = 640 MiB -> 256 MiB
        auto c = frozen_registry_cap_from_cgroup(reader({{"/proc/self/cgroup", self}, {svc, "5368709120\n"}}));
        EXPECT_EQ(c.cap_bytes, 256 * kMiB);
        EXPECT_EQ(c.memory_max, std::optional<uint64_t>(5368709120ull));
        EXPECT_EQ(c.cgroup, "/system.slice/c2pool-dash.service");
    }
    {   // 2,621,440,000 B (the smallest MemoryMax in the fleet): /8 > 256 MiB
        auto c = frozen_registry_cap_from_cgroup(reader({{"/proc/self/cgroup", self}, {svc, "2621440000"}}));
        EXPECT_EQ(c.cap_bytes, 256 * kMiB);
    }
    {   // 1 GiB: /8 = 128 MiB
        auto c = frozen_registry_cap_from_cgroup(reader({{"/proc/self/cgroup", self}, {svc, "1073741824\n"}}));
        EXPECT_EQ(c.cap_bytes, 128 * kMiB);
    }
    {   // 256 MiB: /8 = 32 MiB -> the 64 MiB floor
        auto c = frozen_registry_cap_from_cgroup(reader({{"/proc/self/cgroup", self}, {svc, "268435456\n"}}));
        EXPECT_EQ(c.cap_bytes, 64 * kMiB);
    }
    {   // the parent slice's limit is the smaller one
        auto c = frozen_registry_cap_from_cgroup(
            reader({{"/proc/self/cgroup", self}, {svc, "max"}, {sl, "805306368"}}));
        EXPECT_EQ(c.cap_bytes, 96 * kMiB);
        EXPECT_EQ(c.cgroup, "/system.slice");
    }
    {   // cgroup v1 memory controller
        auto c = frozen_registry_cap_from_cgroup(reader(
            {{"/proc/self/cgroup", "5:cpu,cpuacct:/docker/x\n4:memory:/docker/x\n"},
             {"/sys/fs/cgroup/memory/docker/x/memory.limit_in_bytes", "1073741824\n"}}));
        EXPECT_EQ(c.source, "cgroup1");
        EXPECT_EQ(c.cap_bytes, 128 * kMiB);
    }
    {   // v1 "unlimited"
        auto c = frozen_registry_cap_from_cgroup(reader(
            {{"/proc/self/cgroup", "4:memory:/\n"},
             {"/sys/fs/cgroup/memory/memory.limit_in_bytes", "9223372036854771712\n"}}));
        EXPECT_EQ(c.source, "cgroup1");
        EXPECT_EQ(c.cap_bytes, 256 * kMiB);
        EXPECT_FALSE(c.memory_max.has_value());
    }
    {   // nothing readable
        auto c = frozen_registry_cap_from_cgroup(reader({}));
        EXPECT_EQ(c.source, "no-limit");
        EXPECT_EQ(c.cap_bytes, 256 * kMiB);
        const auto line = dash::mint::format_frozen_registry_config_line(c, FrozenRegistryConfig{});
        EXPECT_NE(line.find("[MINT-REG] config cap_mib=256.0 cap_bytes=268435456 source=no-limit"
                            " cgroup=- memory_max=none"), std::string::npos) << line;
        EXPECT_NE(line.find(" age_s=420 grace_s=45 backstop=16384 "), std::string::npos) << line;
    }
}

// The count backstop: expired entries first, then old-tip entries oldest
// first, then old-share entries, never the current tip and share.
TEST(DashFrozenJobRegistryCap, BackstopUsesTierOrder)
{
    FakeClock clk;
    FrozenJobRegistry reg(cfg_cap(dash::mint::kFrozenRegistryCapMax, /*backstop=*/3), clk.fn());
    auto put = [&](uint64_t i, unsigned char t, unsigned char s) {
        reg.put(key(i), job_with(nullptr, 0), tip(t), share(s));
    };
    put(1, 9, 9);                          // expires before the backstop runs
    clk.advance(380s);
    put(2, 2, 1); put(3, 2, 1);            // tip B, share S1: old share (T2)
    clk.advance(1s);
    put(4, 1, 0); put(5, 1, 0);            // tip A: old tip (T1), newer than T2
    clk.advance(1s);
    put(6, 2, 2);                          // current
    EXPECT_EQ(reg.size(), 6u) << "inside the grace the backstop admits";
    clk.advance(dash::mint::kFrozenJobGrace + 1s);
    put(7, 2, 2);

    EXPECT_FALSE(reg.contains(key(1)));
    EXPECT_FALSE(reg.contains(key(4)));
    EXPECT_FALSE(reg.contains(key(5)));
    EXPECT_FALSE(reg.contains(key(2)));
    EXPECT_TRUE(reg.contains(key(3)));
    EXPECT_TRUE(reg.contains(key(6)));
    EXPECT_TRUE(reg.contains(key(7)));
    EXPECT_EQ(reg.size(), 3u);
    const auto s = reg.stats();
    EXPECT_EQ(s.evict_age, 1u);
    EXPECT_EQ(s.evict_backstop, 3u);
    EXPECT_EQ(reg.lookup_for_mint(key(1)).cause, FrozenEvictCause::age);
    EXPECT_EQ(reg.lookup_for_mint(key(4)).cause, FrozenEvictCause::backstop);
    EXPECT_EQ(reg.lookup_for_mint(key(2)).cause, FrozenEvictCause::backstop);
}

// The producer job cache sweeps entries older than 60 s on every call, at any
// size (it swept only above 128 entries). Its hit rule is unchanged.
TEST(DashProducerJobCache, SweepsByAgeAtAnySize)
{
    using dash::mint::ProducerJobCache;
    ProducerJobCache cache;
    const auto t0 = std::chrono::steady_clock::time_point{} + std::chrono::hours(1);
    dash::coin::DashWorkData wd;
    wd.m_previous_block = tip(1);
    wd.m_height         = 50;
    wd.m_payment_amount = 7;
    wd.m_tx_hashes      = {key(77)};
    auto build = std::make_shared<dash::mint::ProducerJobBuild>();
    build->frozen.payment_amount    = 7;
    build->frozen.desired_tx_hashes = {key(77)};
    const ProducerJobCache::Key a{share(1), {0x01}}, b{share(2), {0x02}};
    cache.store(a, build, tip(1), 50, t0);
    cache.store(b, build, tip(1), 50, t0);

    EXPECT_EQ(cache.find(a, wd, t0 + 29s).outcome, ProducerJobCache::Outcome::hit);
    auto moved = wd;
    moved.m_tx_hashes = {key(78)};
    EXPECT_EQ(cache.find(a, moved, t0 + 29s).outcome, ProducerJobCache::Outcome::drift);
    EXPECT_EQ(cache.size(), 1u) << "a drift drops its entry";
    EXPECT_EQ(cache.find(b, wd, t0 + 30s).outcome, ProducerJobCache::Outcome::miss)
        << "30 s old is no longer a hit";

    cache.store(a, build, tip(1), 50, t0);
    cache.store(b, build, tip(1), 50, t0 + 1s);
    (void)cache.find({share(3), {}}, wd, t0 + 60s);
    EXPECT_EQ(cache.size(), 2u) << "60 s old is kept";
    (void)cache.find({share(3), {}}, wd, t0 + 61s);
    EXPECT_EQ(cache.size(), 1u) << "older than 60 s is swept at size 2";
    (void)cache.find({share(3), {}}, wd, t0 + 62s);
    EXPECT_EQ(cache.size(), 0u);
}

// ── Second pass: brake release, interleaving, reorg back, late session,
//    bounded eviction pass, soft backstop ───────────────────────────────────

// Under a sustained load the brake is released once the kept entries fit:
// while it is on, the tiers trim to below 80% of the cap, not just to the cap
// (bytes parked just under the cap would keep it on for the whole load and
// freeze every block's tx set).
TEST(DashFrozenJobRegistryCap, BrakeReleasesUnderSustainedLoad)
{
    FakeClock clk;
    const uint64_t cap = 16 * kMiB;
    FrozenJobRegistry reg(cfg_cap(cap), clk.fn());
    uint64_t n = 0;
    for (int i = 0; i < 20; ++i) {   // one context over the cap: the brake engages
        clk.advance(5s);
        reg.put(key(++n), job_with(hex_vec(256, 4096), 256), tip(1), share(1));
    }
    ASSERT_TRUE(reg.brake_on());
    // Sustained load: a new 1 MiB job every 5 s, a new best share every 10 s.
    int released_at = -1;
    for (int i = 0; i < 60; ++i) {
        clk.advance(5s);
        reg.put(key(++n), job_with(hex_vec(256, 4096), 256), tip(1),
                share(static_cast<unsigned char>(2 + i / 2)));
        if (released_at < 0 && !reg.brake_on()) released_at = i;
        if (released_at >= 0) {
            EXPECT_FALSE(reg.brake_on()) << "re-engaged at put " << i;
            EXPECT_LE(reg.bytes(), cap) << "put " << i;
        }
    }
    ASSERT_GE(released_at, 0) << "the brake stayed on for the whole load";
    EXPECT_LE(released_at, 10) << "released one put after the grace";
    EXPECT_EQ(reg.stats().brake_episodes, 1u);
}

// Two producers interleave their puts on two contexts (a tip change racing
// the sessions): each put makes its context current and supersedes the other
// for a few seconds only, so neither producer's jobs are taken while both
// keep putting. Once one stops, its jobs go after the grace.
TEST(DashFrozenJobRegistryCap, InterleavedProducersKeepBothContextsLive)
{
    FakeClock clk;
    const uint64_t one = one_entry_bytes(job_with(hex_vec(64, 1024), 64));
    FrozenJobRegistry reg(cfg_cap(4 * one), clk.fn());
    std::vector<uint256> a, b;
    uint64_t n = 0;
    for (int i = 0; i < 24; ++i) {   // 120 s, 5 s apart, alternating
        clk.advance(5s);
        const bool is_a = (i % 2) == 0;
        const uint256 r = key(++n);
        reg.put(r, job_with(hex_vec(64, 1024), 64), is_a ? tip(2) : tip(1),
                is_a ? share(2) : share(1));
        (is_a ? a : b).push_back(r);
        for (const auto& x : a) ASSERT_TRUE(reg.contains(x)) << "producer A lost a job at put " << i;
        for (const auto& x : b) ASSERT_TRUE(reg.contains(x)) << "producer B lost a job at put " << i;
    }
    EXPECT_EQ(reg.stats().evict_cap_oldtip + reg.stats().evict_cap_oldshare, 0u);
    // B stops; A goes on. Past the grace (45 s after A's first lone put) B's
    // jobs go, A's stay.
    for (int i = 0; i < 12; ++i) {
        clk.advance(5s);
        const uint256 r = key(++n);
        reg.put(r, job_with(hex_vec(64, 1024), 64), tip(2), share(2));
        a.push_back(r);
    }
    for (const auto& x : b) EXPECT_FALSE(reg.contains(x));
    for (const auto& x : a) EXPECT_TRUE(reg.contains(x));
    EXPECT_EQ(reg.stats().evict_cap_oldtip, b.size());
}

// A reorg back to an earlier tip: the tip seen before becomes current again
// with its old context, so its jobs are kept; the orphaned tip's jobs go
// after the grace.
TEST(DashFrozenJobRegistryCap, ReorgBackToEarlierTipRevivesIt)
{
    FakeClock clk;
    const uint64_t one = one_entry_bytes(job_with(hex_vec(64, 1024), 64));
    FrozenJobRegistry reg(cfg_cap(3 * one), clk.fn());
    auto put = [&](uint64_t i, unsigned char t, unsigned char s) {
        reg.put(key(i), job_with(hex_vec(64, 1024), 64), tip(t), share(s));
    };
    put(1, 1, 1);             // tip A
    clk.advance(5s);
    put(2, 1, 1);
    clk.advance(5s);
    put(3, 2, 2);             // tip B
    clk.advance(5s);
    put(4, 2, 2);
    clk.advance(5s);
    put(5, 1, 1);             // B orphaned: back on tip A, same context
    clk.advance(dash::mint::kFrozenJobGrace + 1s);
    put(6, 1, 1);
    EXPECT_TRUE(reg.contains(key(1))) << "the revived tip's old job was taken";
    EXPECT_TRUE(reg.contains(key(2)));
    EXPECT_TRUE(reg.contains(key(5)));
    EXPECT_TRUE(reg.contains(key(6)));
    EXPECT_FALSE(reg.contains(key(3))) << "the orphaned tip's job is kept";
    EXPECT_FALSE(reg.contains(key(4)));
    EXPECT_EQ(reg.lookup_for_mint(key(3)).cause, FrozenEvictCause::cap_oldtip);
}

// A late session: the best share moves, one session is served on it at once,
// another only at its next notify, up to the session lag (37.5 s) later, and
// meanwhile still submits on its old job. Under cap pressure that job is
// still held 44 s after the supersession (the grace covers the lag), so the
// submit mints.
TEST(DashFrozenJobRegistryCap, LateSessionInsideTheGraceStillMints)
{
    FakeClock clk;
    const uint64_t one = one_entry_bytes(job_with(hex_vec(64, 1024), 64));
    FrozenJobRegistry reg(cfg_cap(3 * one), clk.fn());
    const uint256 late = key(1);
    reg.put(late, job_with(hex_vec(64, 1024), 64, 77), tip(1), share(1));
    reg.put(key(2), job_with(hex_vec(64, 1024), 64), tip(1), share(1));
    clk.advance(10s);
    uint64_t n = 100;
    reg.put(key(++n), job_with(hex_vec(64, 1024), 64), tip(1), share(2));   // supersedes share 1
    for (int i = 0; i < 7; ++i) {                                            // others, under pressure
        clk.advance(5s);
        reg.put(key(++n), job_with(hex_vec(64, 1024), 64), tip(1), share(2));
    }
    clk.advance(4s);   // 39 s after the supersession: the late session's result arrives
    const auto hit = reg.lookup_for_mint(late);
    ASSERT_TRUE(hit.job.has_value()) << "a job a late session still submits on was taken";
    EXPECT_EQ(hit.job->share_nonce, 77u);
    clk.advance(5s);   // 44 s: one more put, still inside the grace
    reg.put(key(++n), job_with(hex_vec(64, 1024), 64), tip(1), share(2));
    EXPECT_TRUE(reg.contains(late));
    clk.advance(dash::mint::kFrozenJobGrace - 44s + 1s);
    reg.put(key(++n), job_with(hex_vec(64, 1024), 64), tip(1), share(2));
    EXPECT_FALSE(reg.contains(late)) << "past the grace it goes";
}

// The eviction pass visits only the contexts past the grace, never the
// entries one by one: at 16,384 entries in the current context (the brake on,
// nothing evictable) a put examines no context; with the entries spread over
// 1,024 superseded contexts it examines at most the candidate contexts. The
// put hold times are printed ([P2-HOLD]) for the record.
TEST(DashFrozenJobRegistryCap, EvictionPassVisitsOnlyContextsPastTheGrace)
{
    using wall = std::chrono::steady_clock;
    auto us = [](wall::duration d) {
        return static_cast<int64_t>(std::chrono::duration_cast<std::chrono::microseconds>(d).count());
    };
    const FrozenMintJob small = job_with(nullptr, 8);
    {   // (a) 16,384 entries, all current: over the cap and at the backstop.
        FakeClock clk;
        FrozenJobRegistry reg(cfg_cap(1 * kMiB), clk.fn());
        for (uint64_t i = 1; i <= 16384; ++i) reg.put(key(i), small, tip(1), share(1));
        ASSERT_TRUE(reg.brake_on());
        const uint64_t steps0 = reg.stats().scan_steps;
        int64_t worst = 0, total = 0;
        for (uint64_t i = 0; i < 200; ++i) {
            clk.advance(1ms);
            const auto t0 = wall::now();
            reg.put(key(100000 + i), small, tip(1), share(1));
            const int64_t d = us(wall::now() - t0);
            worst = std::max(worst, d);
            total += d;
        }
        EXPECT_EQ(reg.stats().scan_steps, steps0) << "a put scanned with nothing evictable";
        std::cout << "[P2-HOLD] 16384+ current entries, brake on: put max_us=" << worst
                  << " avg_us=" << total / 200 << "\n";
    }
    {   // (b) 16,384 entries over 1,024 superseded contexts, then puts that evict.
        FakeClock clk;
        const uint64_t one = one_entry_bytes(job_with(hex_vec(1, 64), 8));
        FrozenJobRegistry reg(cfg_cap(16000 * one), clk.fn());
        uint64_t n = 0;
        for (unsigned c = 0; c < 1024; ++c) {
            clk.advance(100ms);
            for (int j = 0; j < 16; ++j)
                reg.put(key(++n), job_with(hex_vec(1, 64), 8), tip(1), key(c, 0x77));
        }
        clk.advance(dash::mint::kFrozenJobGrace + 1s);
        int64_t worst = 0, total = 0;
        uint64_t worst_steps = 0;
        for (int i = 0; i < 200; ++i) {
            clk.advance(1ms);
            const uint64_t s0 = reg.stats().scan_steps;
            const auto t0 = wall::now();
            reg.put(key(++n), job_with(hex_vec(1, 64), 8), tip(1), key(5000, 0x77));
            const int64_t d = us(wall::now() - t0);
            worst = std::max(worst, d);
            total += d;
            worst_steps = std::max(worst_steps, reg.stats().scan_steps - s0);
        }
        EXPECT_LE(reg.bytes(), 16000 * one);
        EXPECT_GT(reg.stats().evict_cap_oldshare, 0u);
        EXPECT_LE(worst_steps, 1024u + 1u) << "a put examined more than the candidate contexts";
        std::cout << "[P2-HOLD] 16384 entries over 1024 superseded contexts, evicting: put max_us="
                  << worst << " avg_us=" << total / 200 << " max_contexts_examined="
                  << worst_steps << "\n";
        {
            const auto t0 = wall::now();
            (void)reg.lookup_for_mint(key(999999999));   // a miss walks the full eviction ring
            std::cout << "[P2-HOLD] mint lookup miss over a full eviction ring (4096): us="
                      << us(wall::now() - t0) << "\n";
        }
        // (c) everything expired at once (a put after an idle period): each put
        // evicts at most kEvictBudget, the next puts go on.
        clk.advance(dash::mint::kFrozenJobAge + 1s);
        const size_t before = reg.size();
        const uint64_t aged0 = reg.stats().evict_age;
        const auto t0 = wall::now();
        reg.put(key(++n), small, tip(1), key(5000, 0x77));
        std::cout << "[P2-HOLD] first put after " << before << " entries expired: us="
                  << us(wall::now() - t0) << " (evicts at most "
                  << FrozenJobRegistry::kEvictBudget << ")\n";
        EXPECT_EQ(reg.size(), before + 1 - FrozenJobRegistry::kEvictBudget);
        for (int i = 0; i < 20; ++i) reg.put(key(++n), small, tip(1), key(5000, 0x77));
        EXPECT_EQ(reg.size(), 21u);
        EXPECT_EQ(reg.stats().evict_age - aged0, before);
    }
}

// The count backstop is soft: above it the registry admits, counts the puts
// and warns once per episode.
TEST(DashFrozenJobRegistryCap, SoftBackstopWarnsOncePerEpisode)
{
    FakeClock clk;
    FrozenJobRegistry reg(cfg_cap(dash::mint::kFrozenRegistryCapMax, /*backstop=*/4), clk.fn());
    for (uint64_t i = 1; i <= 6; ++i) reg.put(key(i), job_with(nullptr, 0), tip(1), share(1));
    auto s = reg.stats();
    EXPECT_EQ(s.entries, 6u) << "the backstop never takes the current context";
    EXPECT_EQ(s.over_backstop_puts, 2u);
    EXPECT_EQ(s.backstop_episodes, 1u);
    const std::string line = FrozenJobRegistry::format_backstop_line(s);
    EXPECT_NE(line.find("[MINT-REG] COUNT BACKSTOP exceeded with no evictable entry left: entries=6"
                        " backstop=4"), std::string::npos) << line;
    clk.advance(dash::mint::kFrozenJobAge + 1s);
    reg.put(key(7), job_with(nullptr, 0), tip(1), share(1));   // back within
    for (uint64_t i = 8; i <= 11; ++i) reg.put(key(i), job_with(nullptr, 0), tip(1), share(1));
    s = reg.stats();
    EXPECT_EQ(s.entries, 5u);
    EXPECT_EQ(s.backstop_episodes, 2u);
    EXPECT_EQ(s.over_backstop_puts, 1u + 2u);
    EXPECT_NE(FrozenJobRegistry::format_stats_line(s).find(" over_backstop_puts=3 backstop_episodes=2"),
              std::string::npos);
}
