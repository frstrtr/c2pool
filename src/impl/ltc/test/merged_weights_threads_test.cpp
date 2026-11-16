// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// The PPLNS weight caches are safe for concurrent readers (rides share_test).
//
// LTC+DOGE canary, 2026-11-06 08:24:20: SIGSEGV in deque::emplace_back under
// WeightsSkipList::query, from ShareTracker::get_merged_payout_weights on the
// merged-mining RPC thread (refresh_aux_work -> rebuild_cached_blocks -> the
// payout provider), 25 s after a start, the moment the embedded DOGE chain
// turned synced (before that the DOGE work had no coinbase value and the
// rebuild never asked for payouts). No weights were published yet for the best
// share, so the provider computed them under the SHARED tracker lock; in the
// same IO phase the IO thread's tip-payout cache (cache_pplns_at_tip ->
// get_payouts -> the same provider) did too. query() fills the skip list it
// walks: two readers in it at once insert into one unordered_map and append to
// one deque. The compute thread (think / share add / prune) holds the lock
// exclusively and is ordered with both; the readers are not ordered with each
// other.
//   - WeightsSkipList / StatsSkipList: two queries never run at once. The
//     first thread waits inside its first callback for the second to get into
//     one; it must not (RED before the fix: both were inside);
//   - the DOGE-sync reproducer: the merged chain turns synced, refresh_aux_work
//     -> rebuild_cached_blocks -> get_merged_payout_weights runs on the
//     manager's own RPC thread while the IO thread rebuilds and caches the tip
//     payouts, a stratum thread derives the ref_hash data and the compute
//     thread adds and prunes shares under the exclusive lock. The results then
//     equal a single-threaded replay of the same rounds. Under ThreadSanitizer
//     (setarch -R, gcc 13) it reports the reader/reader race before the fix
//     and none after;
//   - identity: the merged payout weights, the merged coinbase bytes, the
//     merged payout hash and the parent PPLNS weights for a fixed tracker are
//     pinned to the values the code computed before the fix, cold, warm and
//     from four threads at once;
//   - every ShareTracker copy (ltc, dash, btc, dgb, bip110, bch) takes the
//     same cache lock in the same places.
// ---------------------------------------------------------------------------

#include <gtest/gtest.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <fstream>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include <boost/asio/io_context.hpp>
#include <boost/log/core.hpp>
#include <nlohmann/json.hpp>

#include <btclibs/util/strencodings.h>
#include <c2pool/merged/merged_mining.hpp>
#include <c2pool/merged/payout_source.hpp>
#include <core/uint256.hpp>
#include <impl/ltc/share.hpp>
#include <impl/ltc/share_tracker.hpp>
#include <sharechain/stats_skiplist.hpp>
#include <sharechain/weights_skiplist.hpp>

#ifndef C2POOL_IMPL_DIR
#error "C2POOL_IMPL_DIR must be defined by CMake to the path of src/impl"
#endif

namespace {

using c2pool::merged::MergedMiningManager;
using c2pool::merged::MergedPayoutSource;
using Payouts = MergedPayoutSource::Payouts;
using namespace std::chrono_literals;

constexpr uint32_t kDoge = 98;
constexpr uint32_t kNmc = 1;

uint256 num_hash(uint64_t prefix, uint64_t n)
{
    char buf[40];
    std::snprintf(buf, sizeof(buf), "%08llx%016llx", static_cast<unsigned long long>(prefix),
                  static_cast<unsigned long long>(n));
    uint256 h;
    h.SetHex(buf);
    return h;
}

uint288 unlimited()
{
    uint288 u;
    u.SetHex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    return u;
}

/// Logging off for a scope (the stress loops would print every rebuild).
struct QuietLog {
    bool was;
    QuietLog() : was(boost::log::core::get()->get_logging_enabled())
    {
        boost::log::core::get()->set_logging_enabled(false);
    }
    ~QuietLog() { boost::log::core::get()->set_logging_enabled(was); }
};

// ─────────────────────────────────────────────────────────────────────────
// 1. The skip lists themselves: one query at a time.
// ─────────────────────────────────────────────────────────────────────────

/// Two branches of `len` shares each over a shared tail of `len` shares.
struct Forked {
    std::map<uint256, uint256> prev;
    uint256 head_a, head_b;
    explicit Forked(int len)
    {
        uint256 tail;
        for (int i = 1; i <= len; ++i) {
            const uint256 h = num_hash(0x7a11, i);
            prev[h] = tail;
            tail = h;
        }
        uint256 a = tail, b = tail;
        for (int i = 1; i <= len; ++i) {
            const uint256 ha = num_hash(0xaaaa, i), hb = num_hash(0xbbbb, i);
            prev[ha] = a;
            prev[hb] = b;
            a = ha;
            b = hb;
        }
        head_a = a;
        head_b = b;
    }
    uint256 previous(const uint256& h) const
    {
        auto it = prev.find(h);
        return it == prev.end() ? uint256() : it->second;
    }
};

/// Counts the threads inside the skip list's callbacks. Thread A, in its
/// first callback, lets thread B start and waits (up to 1 s) for B to get
/// into a callback too. With the skip list serialized B cannot: it waits for
/// A's query to finish, so at most one thread is ever inside.
struct OneAtATime {
    std::atomic<int> inside{0};
    std::atomic<int> peak{0};
    std::atomic<bool> a_started{false};
    std::atomic<bool> b_inside{false};
    static inline thread_local bool t_is_a = false;

    void enter()
    {
        const int now = ++inside;
        int p = peak.load();
        while (now > p && !peak.compare_exchange_weak(p, now)) {}
        if (t_is_a) {
            if (!a_started.exchange(true)) {
                const auto until = std::chrono::steady_clock::now() + 1s;
                while (!b_inside.load() && std::chrono::steady_clock::now() < until)
                    std::this_thread::yield();
            }
        } else {
            b_inside.store(true);
        }
        --inside;
    }

    template <typename QueryA, typename QueryB>
    void run(QueryA&& qa, QueryB&& qb)
    {
        std::thread a([&] {
            t_is_a = true;
            qa();
        });
        std::thread b([&] {
            while (!a_started.load())
                std::this_thread::yield();
            qb();
        });
        a.join();
        b.join();
    }
};

TEST(WeightsSkipListThreads, TwoQueriesNeverRunAtOnce)
{
    const Forked f(300);
    OneAtATime gate;
    std::atomic<int> deltas{0};
    chain::WeightsSkipList sl(
        [&](const uint256& h) {
            gate.enter();
            ++deltas;
            chain::WeightsDelta d;
            if (!f.prev.contains(h))
                return d;
            d.share_count = 1;
            d.total_weight = uint288(1000);
            d.weights[{static_cast<unsigned char>(h.GetLow64() % 7)}] = uint288(1000);
            return d;
        },
        [&](const uint256& h) { return f.previous(h); });

    chain::CumulativeWeightsResult ra, rb;
    gate.run([&] { ra = sl.query(f.head_a, 600, unlimited()); },
             [&] { rb = sl.query(f.head_b, 600, unlimited()); });

    EXPECT_EQ(gate.peak.load(), 1)
        << "two threads were inside WeightsSkipList::query at once (it fills m_skips as it walks)";
    EXPECT_EQ(ra.total_weight, uint288(600 * 1000));
    EXPECT_EQ(rb.total_weight, uint288(600 * 1000));
    EXPECT_EQ(deltas.load(), 900) << "every share's delta once: the shared tail is reused";
}

TEST(StatsSkipListThreads, TwoQueriesNeverRunAtOnce)
{
    const Forked f(300);
    OneAtATime gate;
    chain::StatsSkipList sl(
        [&](const uint256& h) {
            gate.enter();
            chain::StatsDelta d;
            if (!f.prev.contains(h))
                return d;
            d.share_count = 1;
            d.difficulty_sum = 1.0;
            return d;
        },
        [&](const uint256& h) { return f.previous(h); });

    chain::StatsResult ra, rb;
    gate.run([&] { ra = sl.query(f.head_a, 600); },
             [&] { rb = sl.query(f.head_b, 600); });

    EXPECT_EQ(gate.peak.load(), 1)
        << "two threads were inside StatsSkipList::query at once (it fills m_nodes as it walks)";
    EXPECT_EQ(ra.share_count, 600);
    EXPECT_EQ(rb.share_count, 600);
}

// ─────────────────────────────────────────────────────────────────────────
// Sharechain fixtures.
// ─────────────────────────────────────────────────────────────────────────

std::vector<unsigned char> p2pkh_script(unsigned char fill)
{
    std::vector<unsigned char> s{0x76, 0xa9, 0x14};
    s.insert(s.end(), 20, fill);
    s.push_back(0x88);
    s.push_back(0xac);
    return s;
}

std::vector<unsigned char> combined_donation()
{
    return {ltc::PoolConfig::COMBINED_DONATION_SCRIPT.begin(), ltc::PoolConfig::COMBINED_DONATION_SCRIPT.end()};
}

/// One share of a deterministic sharechain: share `n` of a run keyed by
/// `salt`, mined by miner m (pubkey hash m, type m % 3), with varied bits and
/// donation. Every `explicit_every`-th share of a miner carries an explicit
/// DOGE address for that miner (its other shares resolve it by Tier 1.5).
struct ShareSpec {
    uint64_t salt;
    uint64_t n;
    unsigned miner;
    int desired_version{36};
    bool explicit_doge{false};
    bool explicit_nmc{false};
};

uint256 add_share(ltc::ShareTracker& t, const uint256& prev, const ShareSpec& sp)
{
    auto* sh = new ltc::MergedMiningShare();
    sh->m_hash = num_hash(0x5000 + sp.salt, sp.n);
    sh->m_prev_hash = prev;
    sh->m_desired_version = sp.desired_version;
    static constexpr uint32_t kBits[] = {0x1e0fffff, 0x1e07ffff, 0x1e03ffff, 0x1d7fffff};
    sh->m_bits = kBits[(sp.n * 7 + sp.miner) % 4];
    sh->m_max_bits = sh->m_bits;
    sh->m_donation = static_cast<uint16_t>(50 + (sp.n % 5) * 25);
    char hex[48];
    std::snprintf(hex, sizeof(hex), "%02x%038x", sp.miner & 0xff, sp.miner * 2654435761u);
    sh->m_pubkey_hash.SetHex(hex);
    sh->m_pubkey_type = static_cast<uint8_t>(sp.miner % 3);
    if (sp.explicit_doge) {
        ltc::MergedAddressEntry e;
        e.m_chain_id = kDoge;
        e.m_script.m_data = p2pkh_script(static_cast<unsigned char>(0x40 + sp.miner));
        sh->m_merged_addresses.push_back(e);
    }
    if (sp.explicit_nmc) {
        ltc::MergedAddressEntry e;
        e.m_chain_id = kNmc;
        e.m_script.m_data = p2pkh_script(static_cast<unsigned char>(0x90 + sp.miner));
        sh->m_merged_addresses.push_back(e);
    }
    ltc::ShareType st;
    st = sh;
    t.add(st);
    return sh->m_hash;
}

std::string hex_of(const std::vector<unsigned char>& v)
{
    return HexStr(std::span<const unsigned char>(v.data(), v.size()));
}

std::string ser(const ltc::CumulativeWeights& w)
{
    std::ostringstream o;
    for (const auto& [k, v] : w.weights)
        o << hex_of(k) << ':' << v.GetHex() << '|';
    o << "T:" << w.total_weight.GetHex() << "|D:" << w.total_donation_weight.GetHex();
    return o.str();
}

// The weights with each MERGED: key as it was before the key carried the
// parent script ("MERGED:" <merged script>), keys that differ only by parent
// summed: the per-merged-script weights the payouts are split by. The golden
// digest below was taken before that change, so it equal => the weights are.
ltc::CumulativeWeights fold_merged_parents(ltc::CumulativeWeights w)
{
    std::map<std::vector<unsigned char>, uint288> folded;
    for (const auto& [k, v] : w.weights) {
        std::vector<unsigned char> key = k;
        if (ltc::is_merged_key(k)) {
            const auto merged = ltc::strip_merged_key(k);
            key.assign(ltc::MERGED_KEY_PREFIX.begin(), ltc::MERGED_KEY_PREFIX.end());
            key.insert(key.end(), merged.begin(), merged.end());
        }
        folded[key] = folded[key] + v;
    }
    w.weights = std::move(folded);
    return w;
}

std::string ser(const ltc::MergedPayoutWeights& w)
{
    std::ostringstream o;
    o << w.best.GetHex() << '/' << w.chain_id << '/' << w.chain_len << '/' << w.total_weight.GetHex() << '/'
      << w.donation_weight.GetHex() << '/' << w.accepted_total.GetHex();
    for (const auto& [script, weight] : w.resolved)
        o << '|' << hex_of(script) << ':' << weight.GetHex();
    return o.str();
}

std::string ser(const Payouts& p)
{
    std::ostringstream o;
    for (const auto& [script, amount] : p)
        o << hex_of(script) << ':' << amount << '|';
    return o.str();
}

std::string digest(const std::string& s)
{
    return Hash(std::span<const unsigned char>(reinterpret_cast<const unsigned char*>(s.data()), s.size())).GetHex();
}

/// Everything the merged and parent payouts of `best` are made of.
struct Snapshot {
    std::string merged_weights;    // get_merged_payout_weights(best, DOGE)
    std::string merged_payouts;    // merged_payout_outputs at a fixed value
    std::string merged_coinbase;   // the DOGE coinbase those payouts build
    std::string nmc_weights;       // get_merged_cumulative_weights(best, NMC)
    std::string v36_weights;       // get_v36_merged_weights
    std::string merged_hash;       // compute_merged_payout_hash
    std::string decayed;           // get_v36_decayed_cumulative_weights
    std::string capped;            // get_cumulative_weights, desired weight hit inside a share
    bool operator==(const Snapshot&) const = default;
};

constexpr uint64_t kDogeValue = 1000000012345ULL;
constexpr int kDogeHeight = 6445872;

Snapshot snapshot(ltc::ShareTracker& t, const uint256& best)
{
    Snapshot s;
    const int32_t len = std::min(t.chain.get_height(best),
                                 static_cast<int32_t>(ltc::PoolConfig::real_chain_length()));
    const auto w = t.get_merged_payout_weights(best, kDoge);
    s.merged_weights = ser(w);
    const auto payouts = ltc::ShareTracker::merged_payout_outputs(w, kDogeValue, combined_donation());
    s.merged_payouts = ser(payouts);
    s.merged_coinbase = MergedMiningManager::build_pplns_coinbase_hex(kDogeHeight, payouts, uint256());
    s.nmc_weights = ser(fold_merged_parents(t.get_merged_cumulative_weights(best, len, unlimited(), kNmc)));
    s.v36_weights = ser(t.get_v36_merged_weights(best, len, unlimited()));
    uint256 block_target;
    block_target.SetHex("00000000000000000000ffff00000000000000000000000000000000000000ff");
    s.merged_hash = t.compute_merged_payout_hash(best, block_target).GetHex();
    s.decayed = ser(t.get_v36_decayed_cumulative_weights(best, len, unlimited()));
    const auto full = t.get_cumulative_weights(best, len, unlimited());
    // A desired weight that ends inside a share: the boundary share is scaled.
    const uint288 desired = full.total_weight / 3 + uint288(12345);
    s.capped = ser(t.get_cumulative_weights(best, len, desired));
    return s;
}

/// The identity fixture: 640 shares, 23 miners (P2PKH / P2WPKH / P2SH),
/// some pre-V36, explicit DOGE addresses on some shares of some miners (Tier
/// 1 and Tier 1.5), explicit NMC addresses on others.
uint256 build_identity_chain(ltc::ShareTracker& t)
{
    uint256 tip;
    for (uint64_t n = 0; n < 640; ++n) {
        ShareSpec sp;
        sp.salt = 1;
        sp.n = n;
        sp.miner = static_cast<unsigned>((n * 11 + n / 7) % 23);
        sp.desired_version = (n % 53 == 5) ? 35 : 36;
        sp.explicit_doge = (sp.miner % 4 == 1) && (n % 3 == 0);
        sp.explicit_nmc = (sp.miner % 5 == 2) && (n % 4 == 1);
        tip = add_share(t, tip, sp);
    }
    return tip;
}

// The values the code computed for the identity fixture before the
// concurrency fix (origin/master 59b781cdf, single-threaded, cold caches; the
// fix only adds locking: same tracker state, same bytes). SHA256d of the
// serializations above; the merged payout hash as is.
constexpr const char* kGoldenMergedWeights  = "4d8780506af83ff1c96497c9b88bba155d8558378abb2af50f3d4f97dc44fedd";
constexpr const char* kGoldenMergedPayouts  = "a7ffc1a32947214379fa824087514157eb95833c3aeef5784565c1cb26848b41";
constexpr const char* kGoldenMergedCoinbase = "91a414acc373601061b4428c7bfbebf99ae5892bd10ffea9cebfd2c63a90da30";
constexpr const char* kGoldenNmcWeights     = "bffe002a13939284ccf1e765dfc61380c36a099c262ca94a59ef3ebc782c5cb1";
constexpr const char* kGoldenV36Weights     = "2ce521a1ddccf1b82fbcc33e6e1c76455b19bcfdd47c38b6eae71c25fefbb10c";
constexpr const char* kGoldenMergedHash     = "e7e341bd0a19f02e3d9bf374e8831faed5958a7b2c23d5cbfe86bfe3473ce510";
constexpr const char* kGoldenDecayed        = "b443412ec48549fe1762a0c2d390d8a3dd41bce206656a6d8bf85a73d3159145";
constexpr const char* kGoldenCapped         = "c8f0744b6d299b8191fbed4c7995c1862bb4153fe48369b6e7e3bd0bbde44f90";

void expect_golden(const Snapshot& s, const std::string& when)
{
    EXPECT_EQ(digest(s.merged_weights), kGoldenMergedWeights) << when << ": merged payout weights";
    EXPECT_EQ(digest(s.merged_payouts), kGoldenMergedPayouts) << when << ": merged payouts";
    EXPECT_EQ(digest(s.merged_coinbase), kGoldenMergedCoinbase) << when << ": merged coinbase bytes";
    EXPECT_EQ(digest(s.nmc_weights), kGoldenNmcWeights) << when << ": NMC weights";
    EXPECT_EQ(digest(s.v36_weights), kGoldenV36Weights) << when << ": v36 merged weights";
    EXPECT_EQ(s.merged_hash, kGoldenMergedHash) << when << ": merged payout hash";
    EXPECT_EQ(digest(s.decayed), kGoldenDecayed) << when << ": decayed weights";
    EXPECT_EQ(digest(s.capped), kGoldenCapped) << when << ": capped weights";
}

} // namespace

// ─────────────────────────────────────────────────────────────────────────
// 2. Identity: the same bytes as before the fix.
// ─────────────────────────────────────────────────────────────────────────

TEST(MergedWeightsIdentity, WeightsAndCoinbaseAreThoseBeforeTheFix)
{
    QuietLog quiet;
    ltc::ShareTracker t;
    const uint256 best = build_identity_chain(t);
    ASSERT_EQ(t.chain.get_height(best), 640);

    const Snapshot cold = snapshot(t, best);
    std::printf("[identity] merged_weights=%s\n[identity] merged_payouts=%s\n"
                "[identity] merged_coinbase=%s\n[identity] nmc_weights=%s\n"
                "[identity] v36_weights=%s\n[identity] merged_hash=%s\n"
                "[identity] decayed=%s\n[identity] capped=%s\n",
                digest(cold.merged_weights).c_str(), digest(cold.merged_payouts).c_str(),
                digest(cold.merged_coinbase).c_str(), digest(cold.nmc_weights).c_str(),
                digest(cold.v36_weights).c_str(), cold.merged_hash.c_str(),
                digest(cold.decayed).c_str(), digest(cold.capped).c_str());
    std::fflush(stdout);
    expect_golden(cold, "cold caches");
    EXPECT_FALSE(cold.merged_coinbase.empty());
    EXPECT_NE(cold.merged_payouts.find(hex_of(p2pkh_script(0x41))), std::string::npos)
        << "an explicit DOGE address is paid";

    // Warm caches: the same.
    EXPECT_EQ(snapshot(t, best), cold);

    // Four threads at once on another tracker's cold caches: the same.
    ltc::ShareTracker shared;
    ASSERT_EQ(build_identity_chain(shared), best);
    std::vector<Snapshot> got(4);
    std::vector<std::thread> threads;
    for (int i = 0; i < 4; ++i)
        threads.emplace_back([&, i] { got[i] = snapshot(shared, best); });
    for (auto& th : threads)
        th.join();
    for (int i = 0; i < 4; ++i)
        EXPECT_EQ(got[i], cold) << "thread " << i;
}

// ─────────────────────────────────────────────────────────────────────────
// 3. The DOGE-sync reproducer.
// ─────────────────────────────────────────────────────────────────────────

namespace {

/// The embedded DOGE backend across its sync: no work (null hash, height 0)
/// until it is synced, then a new tip on every poll.
struct SyncingDoge : c2pool::merged::IAuxChainBackend {
    c2pool::merged::AuxChainConfig cfg;
    std::atomic<bool> synced{false};
    std::atomic<int> polls_synced{0};
    uint64_t tip{0};
    SyncingDoge()
    {
        cfg.symbol = "DOGE";
        cfg.chain_id = kDoge;
        cfg.multiaddress = true;
    }
    std::string tip_hex() const { return num_hash(0xd09e, tip).GetHex(); }
    c2pool::merged::AuxWork work()
    {
        c2pool::merged::AuxWork w;
        if (!synced.load())
            return w;   // "chain not synced": the manager waits
        w.chain_id = kDoge;
        w.height = kDogeHeight;
        w.coinbase_value = 1000000000000ULL;
        w.block_hash.SetHex(tip_hex());
        w.target.SetHex("000000000000005c909700000000000000000000000000000000000000000000");
        w.prev_block_hash = tip_hex();
        w.block_template = {
            {"previousblockhash", tip_hex()}, {"height", kDogeHeight}, {"bits", "195c9097"},
            {"curtime", 1793939060}, {"version", 0x620004}, {"coinbasevalue", 1000000000000LL},
            {"transactions", nlohmann::json::array()},
        };
        return w;
    }
    c2pool::merged::AuxWork get_work_template() override { return work(); }
    c2pool::merged::AuxWork create_aux_block(const std::string&) override { return work(); }
    bool connect() override { return true; }
    bool submit_block(const std::string&) override { return true; }
    bool submit_aux_block(const uint256&, const std::string&) override { return true; }
    std::string get_block_hex(const std::string&) override { return {}; }
    std::string get_best_block_hash() override
    {
        if (!synced.load())
            return {};
        ++polls_synced;
        ++tip;   // a new DOGE tip each poll: every poll rebuilds
        return tip_hex();
    }
    std::vector<NetService> getpeerinfo() override { return {}; }
    const c2pool::merged::AuxChainConfig& config() const override { return cfg; }
};

/// What the compute thread does in round r (think / share add / clean): the
/// same in the threaded run and in the single-threaded replay.
struct Rounds {
    static constexpr int kInitial = 360;
    static constexpr int kRounds = 120;
    static constexpr int kPerRound = 5;

    std::vector<uint256> order;   // the chain, oldest first (prunes pop the front)
    size_t pruned{0};

    uint256 tip() const { return order.empty() ? uint256() : order.back(); }

    void initial(ltc::ShareTracker& t)
    {
        for (uint64_t n = 0; n < kInitial; ++n) {
            ShareSpec sp{2, n, static_cast<unsigned>(n % 17)};
            sp.explicit_doge = (sp.miner % 4 == 1) && (n % 5 == 0);
            order.push_back(add_share(t, tip(), sp));
        }
    }

    void round(ltc::ShareTracker& t, int r)
    {
        for (int i = 0; i < kPerRound; ++i) {
            const uint64_t n = 100000 + static_cast<uint64_t>(r) * kPerRound + i;
            // Every 6th round a new miner arrives with an explicit DOGE address:
            // a new Tier 1.5 mapping, so the DOGE skip list is dropped and the
            // next reader rebuilds it from scratch (the longest walk).
            const bool newcomer = (r % 6 == 0) && i == 0;
            ShareSpec sp{3, n, newcomer ? static_cast<unsigned>(40 + r / 6)
                                        : static_cast<unsigned>((n * 5) % 17)};
            sp.explicit_doge = newcomer || ((sp.miner % 4 == 1) && (n % 5 == 0));
            order.push_back(add_share(t, tip(), sp));
        }
        // clean_tracker: drop the oldest shares now and then.
        if (r % 4 == 3) {
            for (int i = 0; i < 3; ++i) {
                ASSERT_TRUE(t.chain.remove(order[pruned])) << "prune " << pruned;
                ++pruned;
            }
        }
    }
};

/// The node's tracker lock and best share (NodeImpl::m_tracker_mutex,
/// m_best_share_hash published by the compute thread).
struct Node {
    ltc::ShareTracker tracker;
    std::shared_mutex mtx;
    // A std::shared_mutex lets new readers in while a writer waits; the
    // readers here never pause, so they back off while the compute thread
    // waits (the node's readers are rarer than these loops).
    std::atomic<bool> writer_waiting{false};
    // Reads that got the lock since the compute thread last released it: two
    // readers race only within one such window (the exclusive lock orders
    // everything before it with everything after it).
    std::atomic<int> reads_in_window{0};
    bool try_read(std::shared_lock<std::shared_mutex>& lk)
    {
        if (writer_waiting.load())
            return false;
        lk = std::shared_lock<std::shared_mutex>(mtx, std::try_to_lock);
        if (!lk.owns_lock())
            return false;
        ++reads_in_window;
        return true;
    }
    mutable std::mutex best_mtx;
    uint256 best_hash;
    uint256 best() const
    {
        std::lock_guard<std::mutex> lk(best_mtx);
        return best_hash;
    }
    void set_best(const uint256& h)
    {
        std::lock_guard<std::mutex> lk(best_mtx);
        best_hash = h;
    }
};

/// main_ltc's merged_weights lambda: the weights of `best` as a payout
/// source entry.
MergedPayoutSource::Weights merged_weights(ltc::ShareTracker& tracker, const uint256& best, uint32_t chain_id)
{
    MergedPayoutSource::Weights out;
    out.best = best;
    out.chain_id = chain_id;
    if (best.IsNull() || !tracker.chain.contains(best))
        return out;
    auto w = std::make_shared<const ltc::MergedPayoutWeights>(tracker.get_merged_payout_weights(best, chain_id));
    out.chain_len = w->chain_len;
    out.derive = [w](uint64_t value) {
        return ltc::ShareTracker::merged_payout_outputs(*w, value, combined_donation());
    };
    return out;
}

} // namespace

TEST(MergedWeightsThreads, DogeSyncFlipRebuildRacesTipCacheAndThink)
{
    QuietLog quiet;
    Node node;
    Rounds rounds;
    rounds.initial(node.tracker);
    node.set_best(rounds.tip());

    boost::asio::io_context ioc;
    MergedMiningManager mm(ioc);
    auto backend = std::make_unique<SyncingDoge>();
    SyncingDoge* doge = backend.get();
    mm.add_chain(doge->cfg, std::move(backend));
    auto src = mm.payout_source();

    std::atomic<int> computed_mm{0}, computed_io{0};
    // main_ltc's P2P payout provider: the published weights of the best
    // share, else computed under a shared try-lock (read_tracker).
    mm.set_payout_provider([&](uint32_t chain_id, uint64_t value) -> Payouts {
        const uint256 best = node.best();
        if (best.IsNull()) {
            MergedMiningManager::note_payout_miss("no_best_share");
            return {};
        }
        MergedMiningManager::note_payout_basis(best);
        std::string miss;
        Payouts p = src->get(best, chain_id, value, MergedMiningManager::on_rpc_thread(),
            [&]() -> std::optional<MergedPayoutSource::Weights> {
                std::shared_lock<std::shared_mutex> lk;
                if (!node.try_read(lk))
                    return std::nullopt;
                ++(MergedMiningManager::on_rpc_thread() ? computed_mm : computed_io);
                return merged_weights(node.tracker, best, chain_id);
            },
            miss);
        if (p.empty())
            MergedMiningManager::note_payout_miss(miss.empty() ? "empty" : miss);
        return p;
    });

    std::atomic<bool> done{false};
    std::atomic<int> stratum_reads{0}, io_reads{0};

    // The compute thread: think / share add / prune, exclusive lock; the
    // locked best-share hook publishes the weights of every other best (the
    // others are left to the readers, as before the hook is installed).
    std::thread compute([&] {
        for (int r = 0; r < Rounds::kRounds; ++r) {
            {
                node.writer_waiting.store(true);
                std::unique_lock<std::shared_mutex> lk(node.mtx);
                node.writer_waiting.store(false);
                rounds.round(node.tracker, r);
                node.set_best(rounds.tip());
                if (r % 2 == 1)
                    src->publish(merged_weights(node.tracker, rounds.tip(), kDoge));
            }
            if (r == 2)
                doge->synced.store(true);   // [EMB-DOGE] Sync state changed: synced=true
            // Between two rounds (the IO phase, the next share batch) the
            // readers get the tracker: leave the window open until three
            // reads are in (or 30 ms).
            const auto until = std::chrono::steady_clock::now() + 30ms;
            while (node.reads_in_window.load() < 3 && std::chrono::steady_clock::now() < until)
                std::this_thread::yield();
            node.reads_in_window.store(0);
        }
        done.store(true);
    });

    // The merged-mining RPC thread: poll_loop -> refresh_aux_work ->
    // rebuild_cached_blocks -> the provider (the crashed stack). Driven by
    // request_refresh, which posts to the manager's own RPC pool thread.
    std::thread poller([&] {
        while (!done.load()) {
            mm.request_refresh();
            std::this_thread::yield();
        }
    });

    // The IO thread's work refresh: refresh_work -> rebuild_cached_blocks
    // (PPLNS dirty) and cache_pplns_at_tip -> compute_current_merged_payouts
    // -> get_payouts -> the same provider.
    std::thread io([&] {
        while (!done.load()) {
            if (!doge->synced.load()) {
                std::this_thread::yield();
                continue;
            }
            mm.mark_pplns_dirty();
            mm.rebuild_cached_blocks();
            (void)mm.get_payouts(kDoge, 1000000000000ULL + io_reads.load());
            ++io_reads;
        }
    });

    // A stratum thread: ref_hash_fn (compute_merged_payout_hash, whose
    // per-height log reads the DOGE and NMC skip lists) and the PPLNS hook
    // (the decayed walk and its cache), under the shared try-lock.
    std::thread stratum([&] {
        uint256 block_target;
        block_target.SetHex("00000000000000000000ffff00000000000000000000000000000000000000ff");
        while (!done.load()) {
            std::shared_lock<std::shared_mutex> lk;
            if (!node.try_read(lk)) {
                std::this_thread::yield();
                continue;
            }
            auto& t = node.tracker;
            const uint256 best = node.best();
            const int32_t len = std::min(t.chain.get_height(best),
                                         static_cast<int32_t>(ltc::PoolConfig::real_chain_length()));
            (void)t.compute_merged_payout_hash(best, block_target);
            (void)t.get_v36_decayed_cumulative_weights(best, len, unlimited());
            (void)t.get_cumulative_weights(best, len, unlimited());
            (void)t.get_merged_cumulative_weights(best, len, unlimited(), kDoge);
            ++stratum_reads;
            lk.unlock();
            std::this_thread::yield();
        }
    });

    compute.join();
    poller.join();
    io.join();
    stratum.join();
    mm.stop();   // joins the RPC pool thread

    EXPECT_GT(doge->polls_synced.load(), 0) << "the DOGE chain never turned synced on the RPC thread";
    EXPECT_GT(computed_mm.load(), 0) << "the RPC thread never computed weights under the shared lock";
    EXPECT_GT(computed_io.load(), 0) << "the IO thread never computed weights under the shared lock";
    EXPECT_GT(stratum_reads.load(), 0);
    std::printf("[doge-sync] rpc computes=%d io computes=%d io reads=%d stratum reads=%d synced polls=%d\n",
                computed_mm.load(), computed_io.load(), io_reads.load(), stratum_reads.load(),
                doge->polls_synced.load());

    // The caches the readers filled give what a single-threaded replay of the
    // same rounds gives on fresh caches.
    Rounds replay_rounds;
    ltc::ShareTracker replay;
    replay_rounds.initial(replay);
    for (int r = 0; r < Rounds::kRounds; ++r)
        replay_rounds.round(replay, r);
    const uint256 best = rounds.tip();
    ASSERT_EQ(replay_rounds.tip(), best);
    ASSERT_EQ(replay.chain.size(), node.tracker.chain.size());
    EXPECT_EQ(snapshot(node.tracker, best), snapshot(replay, best));
    // And so do the weights the payout source holds for the last best share
    // (published by the compute thread or computed by a reader).
    std::string miss;
    const Payouts held = src->get(best, kDoge, kDogeValue, /*may_wait=*/false,
        [&] { return std::optional<MergedPayoutSource::Weights>(merged_weights(replay, best, kDoge)); }, miss);
    EXPECT_EQ(held, ltc::ShareTracker::merged_payout_outputs(replay.get_merged_payout_weights(best, kDoge),
                                                             kDogeValue, combined_donation()));
}

// ─────────────────────────────────────────────────────────────────────────
// 4. The same lock in every ShareTracker copy.
// ─────────────────────────────────────────────────────────────────────────

namespace {

std::string read_text(const std::string& path)
{
    std::ifstream f(path);
    std::stringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

/// The body ({...}) of the first function whose signature starts with `sig`.
std::string body_of(const std::string& src, const std::string& sig)
{
    const auto at = src.find(sig);
    if (at == std::string::npos)
        return {};
    const auto open = src.find('{', at);
    int depth = 0;
    for (size_t i = open; i < src.size(); ++i) {
        if (src[i] == '{')
            ++depth;
        else if (src[i] == '}' && --depth == 0)
            return src.substr(open, i - open + 1);
    }
    return {};
}

} // namespace

TEST(MergedWeightsThreads, EveryTrackerCopyTakesTheCacheLock)
{
    const std::string impl = C2POOL_IMPL_DIR;
    const std::vector<std::pair<std::string, std::string>> trackers = {
        {"ltc", impl + "/ltc/share_tracker.hpp"},   {"dash", impl + "/dash/share_tracker.hpp"},
        {"btc", impl + "/btc/share_tracker.hpp"},   {"dgb", impl + "/dgb/share_tracker.hpp"},
        {"bip110", impl + "/bip110/pool/share_tracker.hpp"}, {"bch", impl + "/bch/share_tracker.hpp"},
    };
    const std::string lock = "std::lock_guard<std::mutex> cache_lock(m_weights_cache_mutex)";
    for (const auto& [lane, path] : trackers) {
        const std::string src = read_text(path);
        ASSERT_FALSE(src.empty()) << path;
        EXPECT_NE(src.find("std::mutex m_weights_cache_mutex;"), std::string::npos) << lane;
        std::vector<std::string> sigs = {
            "CumulativeWeights get_cumulative_weights(",
            "CumulativeWeights get_v36_decayed_cumulative_weights(",
            "CumulativeWeights get_merged_cumulative_weights(",
            "void invalidate_weight_caches(",
            "void prime_pplns_cache(",
        };
        if (lane != "bch") {
            sigs.push_back("CumulativeWeights get_v36_merged_weights(");
            sigs.push_back("void try_register_merged_addr(");
        }
        for (const auto& sig : sigs) {
            const std::string b = body_of(src, sig);
            ASSERT_FALSE(b.empty()) << lane << ": " << sig;
            EXPECT_NE(b.find(lock), std::string::npos) << lane << ": " << sig << " does not take the cache lock";
        }
        // The skip lists are only reached through those functions.
        for (const auto& reach : {"ensure_weights_skiplist();", "ensure_merged_skiplist(target_chain_id)"}) {
            size_t n = 0;
            for (auto p = src.find(reach); p != std::string::npos; p = src.find(reach, p + 1))
                ++n;
            EXPECT_EQ(n, 1u) << lane << ": " << reach;
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────
// The merged rule by share version. V36 shares keep Tier 1 / Tier 1.5 / the
// parent script (P2SH as P2SH) — the shares in the window at the flag day
// keep their payouts. 3601 shares (FLAG_DAY_SHARE_VERSION) are resolved from
// themselves only: their own merged address, else their own parent key
// (P2PKH / P2WPKH as P2PKH, P2SH as P2SH). A 3601 share neither feeds nor
// uses Tier 1.5. The scenarios:
// S5 (one share registers another miner's parent script with the attacker's
// DOGE address) and S3 (nodes that received the same shares in different
// orders).
// ─────────────────────────────────────────────────────────────────────────

namespace {

using Entries = std::vector<std::pair<uint32_t, std::vector<unsigned char>>>;

uint256 add_rule_share(ltc::ShareTracker& t, const uint256& prev, uint64_t n, unsigned miner, uint8_t type,
                       const Entries& entries, bool v3601)
{
    auto* sh = new ltc::MergedMiningShare();
    sh->m_hash = num_hash(0x0e37, n);
    sh->m_prev_hash = prev;
    sh->m_desired_version = 36;
    sh->m_bits = 0x1e0fffff;
    sh->m_max_bits = sh->m_bits;
    sh->m_donation = 50;
    char hex[48];
    std::snprintf(hex, sizeof(hex), "%02x%038x", miner & 0xff, miner * 2654435761u);
    sh->m_pubkey_hash.SetHex(hex);
    sh->m_pubkey_type = type;
    for (const auto& [id, script] : entries) {
        ltc::MergedAddressEntry e;
        e.m_chain_id = id;
        e.m_script.m_data = script;
        sh->m_merged_addresses.push_back(e);
    }
    const uint256 h = sh->m_hash;
    ltc::ShareType st;
    if (v3601) {
        st = new ltc::MergedMiningShareV3601(*sh);
        delete sh;
    } else {
        st = sh;
    }
    t.add(st);
    return h;
}

std::vector<unsigned char> miner_p2pkh(unsigned miner)
{
    char hex[48];
    std::snprintf(hex, sizeof(hex), "%02x%038x", miner & 0xff, miner * 2654435761u);
    uint160 h;
    h.SetHex(hex);
    return ltc::pubkey_hash_to_script(h, 0);
}

std::vector<unsigned char> miner_p2sh(unsigned miner)
{
    char hex[48];
    std::snprintf(hex, sizeof(hex), "%02x%038x", miner & 0xff, miner * 2654435761u);
    uint160 h;
    h.SetHex(hex);
    return ltc::pubkey_hash_to_script(h, 2);
}

struct RuleShare {
    uint64_t n;
    uint64_t prev;   // 0: none
    unsigned miner;
    Entries entries;
    uint8_t type = 0;      // the parent script: 0 P2PKH, 1 P2WPKH, 2 P2SH
    bool v3601 = true;     // the share version: 3601, else 36
};

using WMap = std::map<std::vector<unsigned char>, uint288>;

// The DOGE payout weights of `tip` for shares added in `order`.
WMap doge_weights(const std::vector<RuleShare>& shares, const std::vector<uint64_t>& order, uint64_t tip,
                  uint288* accepted = nullptr)
{
    ltc::ShareTracker t;
    std::map<uint64_t, const RuleShare*> by_n;
    for (const auto& s : shares) by_n[s.n] = &s;
    for (auto n : order) {
        const auto* s = by_n.at(n);
        add_rule_share(t, s->prev ? num_hash(0x0e37, s->prev) : uint256(), s->n, s->miner, s->type, s->entries,
                       s->v3601);
    }
    const auto w = t.get_merged_payout_weights(num_hash(0x0e37, tip), kDoge);
    if (accepted) *accepted = w.accepted_total;
    return {w.resolved.begin(), w.resolved.end()};
}

std::vector<RuleShare> as_version(std::vector<RuleShare> v, bool v3601)
{
    for (auto& s : v) s.v3601 = v3601;
    return v;
}

} // namespace

// S5: miner 7's parent script with the attacker's DOGE address in one share,
// then miner 7's address-less shares. 3601: the attacker is paid for its one
// share only, miner 7 for the rest. V36 (Tier 1.5): the attacker takes them.
TEST(MergedPerShareRule, NoShareTakesAnothersPayout)
{
    const auto attacker = p2pkh_script(0xbb);
    const std::vector<RuleShare> chain = {
        {1, 0, 7, {{kDoge, attacker}}},
        {2, 1, 2, {{kDoge, miner_p2pkh(2)}}},
        {3, 2, 7, {}},
        {4, 3, 7, {}},
        {5, 4, 7, {{kDoge, miner_p2pkh(7)}}},
        {6, 5, 7, {}},
    };
    const auto w = doge_weights(chain, {1, 2, 3, 4, 5, 6}, 6);
    ASSERT_TRUE(w.count(attacker));
    ASSERT_TRUE(w.count(miner_p2pkh(7)));
    const uint288 one = w.at(attacker);
    EXPECT_EQ(w.at(miner_p2pkh(7)), one + one + one + one);
    EXPECT_EQ(w.at(miner_p2pkh(2)), one);
    const auto old_rule = doge_weights(as_version(chain, false), {1, 2, 3, 4, 5, 6}, 6);
    EXPECT_EQ(old_rule.at(attacker), one + one + one + one) << "V36: Tier 1.5, unchanged";
}

// A 3601 share registers nothing: one naming miner 7's parent script with the
// attacker's address does not take miner 7's address-less V36 shares (which
// keep Tier 1.5 from V36 shares only).
TEST(MergedPerShareRule, A3601ShareCannotTakeV36Shares)
{
    const auto attacker = p2pkh_script(0xbb);
    std::vector<RuleShare> chain = {
        {1, 0, 7, {}, 0, false},
        {2, 1, 7, {}, 0, false},
        {3, 2, 7, {{kDoge, attacker}}, 0, true},   // past the flag day
        {4, 3, 7, {}, 0, true},
    };
    for (const auto& order : std::vector<std::vector<uint64_t>>{{1, 2, 3, 4}, {3, 4, 1, 2}, {4, 3, 2, 1}}) {
        const auto w = doge_weights(chain, order, 4);
        const uint288 one = w.at(attacker);
        EXPECT_EQ(w.at(miner_p2pkh(7)), one + one + one) << "shares 1, 2, 4 pay miner 7's own key";
    }
}

// S3: the same main chain; node X added it in order, node Y first saw a fork
// share naming miner 1's script with another address, node Z downloaded the
// chain newest first: with 3601 shares all three derive the same payouts;
// with V36 shares (Tier 1.5, first seen) X and Y differ.
TEST(MergedPerShareRule, AddOrderDoesNotChangeThePayouts)
{
    const auto owner = p2pkh_script(0xd1);
    const std::vector<RuleShare> chain = {
        {1, 0, 1, {{kDoge, owner}}},
        {2, 1, 2, {{kDoge, miner_p2pkh(2)}}},
        {3, 2, 1, {}},
        {4, 3, 3, {{kDoge, miner_p2pkh(3)}}},
        {5, 4, 2, {}},
        {6, 5, 1, {}},
        {7, 6, 3, {}},
        {8, 7, 1, {}},
        {100, 1, 1, {{kDoge, miner_p2pkh(1)}}},   // a fork share off share 1
    };
    const auto px = doge_weights(chain, {1, 2, 3, 4, 5, 6, 7, 8}, 8);
    EXPECT_EQ(px, doge_weights(chain, {100, 1, 2, 3, 4, 5, 6, 7, 8}, 8));   // the fork share first
    EXPECT_EQ(px, doge_weights(chain, {8, 7, 6, 5, 4, 3, 2, 1}, 8));        // newest first
    // entry-less shares 3, 6, 8 pay miner 1's own key; the owner address only share 1
    const uint288 one = px.at(owner);
    EXPECT_EQ(px.at(miner_p2pkh(1)), one + one + one);
    EXPECT_EQ(px.at(miner_p2pkh(2)), one + one);
    const auto v36 = as_version(chain, false);
    EXPECT_NE(doge_weights(v36, {1, 2, 3, 4, 5, 6, 7, 8}, 8), doge_weights(v36, {100, 1, 2, 3, 4, 5, 6, 7, 8}, 8));
}

// A window across the flag day: the V36 shares keep their rule (Tier 1.5 from
// V36 shares), the 3601 shares pay themselves; the merged payout hash (over
// the parent scripts) is the same whatever the rule.
TEST(MergedPerShareRule, V36SharesKeepTheirRuleAcrossTheFlagDay)
{
    const auto attacker = p2pkh_script(0xbb);
    ltc::ShareTracker a, b;
    uint256 ta, tb;
    // a: shares 1-4 V36, 5-6 3601; b: the same with every share's resolution
    // written out (explicit entries), all V36.
    struct S { unsigned miner; bool v3601; Entries minted; Entries resolved; };
    const std::vector<S> seq = {
        {7, false, {{kDoge, attacker}}, {{kDoge, attacker}}},
        {2, false, {{kDoge, miner_p2pkh(2)}}, {{kDoge, miner_p2pkh(2)}}},
        {7, false, {}, {{kDoge, attacker}}},          // V36: Tier 1.5
        {3, false, {{kDoge, miner_p2pkh(3)}}, {{kDoge, miner_p2pkh(3)}}},
        {7, true, {}, {{kDoge, miner_p2pkh(7)}}},     // 3601: its own key
        {2, true, {}, {{kDoge, miner_p2pkh(2)}}},
    };
    for (size_t i = 0; i < seq.size(); ++i) {
        ta = add_rule_share(a, ta, i + 1, seq[i].miner, 0, seq[i].minted, seq[i].v3601);
        tb = add_rule_share(b, tb, i + 1, seq[i].miner, 0, seq[i].resolved, false);
    }
    const auto wa = a.get_merged_payout_weights(ta, kDoge);
    const auto wb = b.get_merged_payout_weights(tb, kDoge);
    EXPECT_EQ(WMap(wa.resolved.begin(), wa.resolved.end()), WMap(wb.resolved.begin(), wb.resolved.end()));
    EXPECT_EQ(wa.total_weight, wb.total_weight);
    uint256 block_target;
    block_target.SetHex("00000000000000000000ffff00000000000000000000000000000000000000ff");
    EXPECT_EQ(a.compute_merged_payout_hash(ta, block_target), b.compute_merged_payout_hash(tb, block_target));
}

// A P2SH parent script with no merged address of its own is paid as the
// merged chain's P2SH of the same hash160 by both versions (a legacy P2SH,
// the pool's 1-of-2 multisig donation script among them, spends there). The
// difference is Tier 1.5: a V36 share takes the address another V36 share of
// the same parent script named; a 3601 share pays its own P2SH.
TEST(MergedPerShareRule, A3601P2shParentIsPaidAsP2shWithoutTier15)
{
    const std::vector<RuleShare> chain = {
        {1, 0, 1, {}, 0},
        {2, 1, 9, {}, 2},                              // P2SH, no merged address
        {3, 2, 2, {{kDoge, miner_p2pkh(2)}}, 0},
        {4, 3, 9, {{kDoge, p2pkh_script(0x99)}}, 2},   // the same P2SH with a DOGE address
    };
    uint288 accepted;
    const auto w = doge_weights(chain, {1, 2, 3, 4}, 4, &accepted);
    const uint288 one = w.at(miner_p2pkh(1));
    EXPECT_EQ(w.at(miner_p2sh(9)), one) << "3601: share 2 pays its own P2SH";
    EXPECT_EQ(w.at(p2pkh_script(0x99)), one) << "share 4: its own DOGE address";
    EXPECT_EQ(w.at(miner_p2pkh(2)), one);
    EXPECT_EQ(accepted, one + one + one + one) << "every share has a payee";
    // V36 (unchanged): share 2 takes miner 9's DOGE address from share 4 (Tier 1.5)
    const auto w36 = doge_weights(as_version(chain, false), {1, 2, 3, 4}, 4);
    EXPECT_EQ(w36.at(p2pkh_script(0x99)), one + one);
    EXPECT_EQ(w36.count(miner_p2sh(9)), 0u);
    // without share 4 both versions pay the P2SH key as a DOGE P2SH
    const auto w36b = doge_weights(as_version({chain[0], chain[1], chain[2]}, false), {1, 2, 3}, 3);
    EXPECT_EQ(w36b.at(miner_p2sh(9)), one);
    const auto wb = doge_weights({chain[0], chain[1], chain[2]}, {1, 2, 3}, 3);
    EXPECT_EQ(wb, w36b);
    const std::vector<unsigned char> don(ltc::PoolConfig::COMBINED_DONATION_SCRIPT.begin(),
                                         ltc::PoolConfig::COMBINED_DONATION_SCRIPT.end());
    EXPECT_EQ(ltc::resolve_merged_payout_script(don), don);
    EXPECT_EQ(ltc::resolve_merged_payout_script(miner_p2sh(9)), miner_p2sh(9));
}

// ─────────────────────────────────────────────────────────────────────────
// Where each merged payout comes from (merged_payout_origins), for the web
// payouts view: the parent script of the shares and whether they gave the
// merged address (explicit) or it is their parent key's (auto-convert), from
// the same weights the amounts are split by.
// ─────────────────────────────────────────────────────────────────────────

TEST(MergedPayoutOrigins, MergedKeyCarriesTheParentAndResolvesAsBefore)
{
    const auto doge = p2pkh_script(0xd0);
    const auto parent = miner_p2pkh(2);
    const auto k = ltc::make_merged_key(doge, parent);
    ASSERT_TRUE(ltc::is_merged_key(k));
    EXPECT_EQ(ltc::strip_merged_key(k), doge);
    EXPECT_EQ(ltc::merged_key_parent(k), parent);
    EXPECT_EQ(ltc::resolve_merged_payout_script(k), doge);
    const auto bare = ltc::make_merged_key(doge);
    EXPECT_EQ(ltc::strip_merged_key(bare), doge);
    EXPECT_TRUE(ltc::merged_key_parent(bare).empty());
    EXPECT_NE(k, ltc::make_merged_key(doge, miner_p2pkh(3))) << "one key per (merged, parent)";
    // an empty merged script stays unconvertible (skipped), as before
    EXPECT_TRUE(ltc::resolve_merged_payout_script(ltc::make_merged_key({}, parent)).empty());
}

TEST(MergedPayoutOrigins, ExplicitAutoP2shAndSharedExplicitAddress)
{
    const auto doge = p2pkh_script(0xd0);   // one DOGE address given by miners 2 and 3
    const std::vector<RuleShare> chain = {
        {1, 0, 1, {}, 0},                    // miner 1: P2PKH, no DOGE address
        {2, 1, 9, {}, 2},                    // miner 9: P2SH, no DOGE address
        {3, 2, 2, {{kDoge, doge}}, 0},       // miner 2: explicit
        {4, 3, 3, {{kDoge, doge}}, 0},       // miner 3: the same explicit address
        {5, 4, 3, {{kDoge, doge}}, 0},
        {6, 5, 4, {{kDoge, p2pkh_script(0xd4)}}, 1},   // miner 4: P2WPKH, explicit
    };
    for (bool v3601 : {true, false}) {
        ltc::ShareTracker t;
        for (const auto& s : as_version(chain, v3601))
            add_rule_share(t, s.prev ? num_hash(0x0e37, s.prev) : uint256(), s.n, s.miner, s.type, s.entries,
                           s.v3601);
        const auto w = t.get_merged_payout_weights(num_hash(0x0e37, 6), kDoge);
        const WMap resolved(w.resolved.begin(), w.resolved.end());
        const uint288 one = resolved.at(miner_p2pkh(1));
        EXPECT_EQ(resolved.at(doge), one + one + one) << "the shared address: one output, summed before the split";

        // sources sum to the resolved weights
        WMap from_sources;
        for (const auto& src : w.sources)
            from_sources[src.script] = from_sources[src.script] + src.weight;
        EXPECT_EQ(from_sources, resolved) << v3601;

        struct O { bool expl; double fraction; };
        std::map<std::pair<std::vector<unsigned char>, std::vector<unsigned char>>, O> by;
        for (const auto& o : ltc::ShareTracker::merged_payout_origins(w))
            by[{o.script, o.parent_script}] = {o.explicit_address, o.fraction};
        ASSERT_EQ(by.size(), 5u) << v3601;
        const auto at = [&](const std::vector<unsigned char>& sc, const std::vector<unsigned char>& p) {
            const auto it = by.find({sc, p});
            EXPECT_NE(it, by.end());
            return it == by.end() ? O{false, -1} : it->second;
        };
        EXPECT_FALSE(at(miner_p2pkh(1), miner_p2pkh(1)).expl) << "auto-convert, P2PKH parent";
        EXPECT_DOUBLE_EQ(at(miner_p2pkh(1), miner_p2pkh(1)).fraction, 1.0);
        EXPECT_FALSE(at(miner_p2sh(9), miner_p2sh(9)).expl) << "auto-convert, P2SH parent";
        EXPECT_TRUE(at(doge, miner_p2pkh(2)).expl);
        EXPECT_TRUE(at(doge, miner_p2pkh(3)).expl);
        EXPECT_NEAR(at(doge, miner_p2pkh(2)).fraction, 1.0 / 3, 1e-9);
        EXPECT_NEAR(at(doge, miner_p2pkh(3)).fraction, 2.0 / 3, 1e-9);
        // miner 4's parent script is its P2WPKH script, not the P2PKH form
        std::vector<unsigned char> p2wpkh = {0x00, 0x14};
        const auto p4 = miner_p2pkh(4);
        p2wpkh.insert(p2wpkh.end(), p4.begin() + 3, p4.begin() + 23);
        EXPECT_TRUE(at(p2pkh_script(0xd4), p2wpkh).expl);

        // the amounts are those of the resolved weights alone
        MergedPayoutSource::Weights pw;
        auto shared = std::make_shared<const ltc::MergedPayoutWeights>(w);
        pw.best = w.best;
        pw.chain_id = kDoge;
        pw.chain_len = w.chain_len;
        pw.derive = [shared](uint64_t v) {
            return ltc::ShareTracker::merged_payout_outputs(*shared, v, combined_donation());
        };
        pw.origins = [shared] { return ltc::ShareTracker::merged_payout_origins(*shared); };
        MergedPayoutSource src;
        src.publish(pw);
        std::string miss;
        const auto none = [] { return std::optional<MergedPayoutSource::Weights>{}; };
        const auto d = src.get_detail(w.best, kDoge, kDogeValue, false, none, miss);
        EXPECT_EQ(d.payouts, src.get(w.best, kDoge, kDogeValue, false, none, miss));
        EXPECT_EQ(d.payouts, ltc::ShareTracker::merged_payout_outputs(w, kDogeValue, combined_donation()));
        EXPECT_EQ(d.origins.size(), 5u);
    }
}
