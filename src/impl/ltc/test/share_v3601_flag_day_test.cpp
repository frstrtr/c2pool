// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Share version 3601: the flag day (no ratchet vote) and what it changes.
//
//   - the version of a share follows from its own timestamp against
//     PoolConfig::v3601_activation_time() (share_check.hpp flag_day_problem):
//     3601 at or after it, an earlier version before it, and nothing but a
//     3601 share after a 3601 share; the boundary into 3601 does not go
//     through the 60% switch gate, the V35 -> V36 gate is unchanged;
//   - our own jobs build the version their clipped timestamp calls for
//     (job_share_version), whatever the ratchet says;
//   - a 3601 share has the V36 wire bytes and reloads (restart) as a 3601
//     share; a node without the type (c2pool before v0.2.12) cannot load it;
//   - peers below protocol 3601 are not served 3601 shares and are dropped
//     from the flag day on (node.hpp peer_takes_3601 ...);
//   - the multi-chain AuxPoW commitment rule is enforced for 3601 shares and
//     only counted for V36 shares (share_check.hpp merged_aux_commitment_problem).
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <map>
#include <memory>
#include <span>
#include <optional>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include <c2pool/merged/aux_commitment_rule.hpp>
#include <core/coin_params.hpp>
#include <core/hash.hpp>
#include <core/pack.hpp>
#include <core/uint256.hpp>
#include <impl/ltc/config_pool.hpp>
#include <impl/ltc/node.hpp>
#include <impl/ltc/params.hpp>
#include <impl/ltc/share.hpp>
#include <impl/ltc/share_check.hpp>
#include <impl/ltc/share_tracker.hpp>

namespace {

constexpr uint32_t kT = 1700000000;   // the flag day the tests use (in the past: step 1 accepts it)
constexpr uint32_t kBits = 0x1e0fffff;
constexpr uint32_t kDoge = 98, kPep = 63;

uint256 hx(uint64_t n)
{
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%llx", static_cast<unsigned long long>(n));
    std::string t(buf);
    uint256 v;
    v.SetHex(std::string(64 - t.size(), '0') + t);
    return v;
}

template <class S>
S* make(uint64_t id, const uint256& prev, uint32_t ts, uint64_t dv = 36)
{
    auto* sh = new S();
    sh->m_hash = hx(id);
    sh->m_prev_hash = prev;
    sh->m_desired_version = dv;
    sh->m_bits = kBits;
    sh->m_max_bits = kBits;
    sh->m_timestamp = ts;
    sh->m_donation = 50;
    if constexpr (requires { sh->m_pubkey_hash; })
        sh->m_pubkey_hash.SetHex(std::string(38, '0') + std::to_string(id % 7 + 1) + "1");
    // A hash link as every real share has: the 32-byte state (a fixed-size
    // field: an empty one packs to nothing and does not reload).
    sh->m_hash_link.m_state.m_data.assign(32, 0x4c);
    sh->m_hash_link.m_length = 64;
    return sh;
}

template <class S>
uint256 add(ltc::ShareTracker& tr, uint64_t id, const uint256& prev, uint32_t ts, uint64_t dv = 36)
{
    auto* sh = make<S>(id, prev, ts, dv);
    const uint256 h = sh->m_hash;
    ltc::ShareType st;
    st = sh;
    tr.add(st);
    return h;
}

// A chain of n shares of type S, timestamps ts0, ts0 + 1, ...
template <class S>
uint256 build_chain(ltc::ShareTracker& tr, uint64_t id0, int n, uint32_t ts0, uint64_t dv = 36,
              uint256 prev = uint256())
{
    for (int i = 0; i < n; ++i)
        prev = add<S>(tr, id0 + i, prev, ts0 + i, dv);
    return prev;
}

bool version_step(const std::string& m)
{
    return m.find("flag day") != std::string::npos || m.find("3601") != std::string::npos
           || m.find("switch without") != std::string::npos || m.find("version jump") != std::string::npos;
}

// share_check steps 1b (flag day) and 2 (switch gate) on a child of type S:
// "" when both passed (a later step on these synthetic shares may still
// throw), else their message.
template <class S>
std::string version_verdict(ltc::ShareTracker& tr, const uint256& parent, uint32_t ts, uint64_t id = 0xa000)
{
    std::unique_ptr<S> x(make<S>(id, parent, ts));
    const auto params = ltc::make_coin_params(true);
    try {
        ltc::share_check(*x, x->m_hash, uint256(), tr, params);
        return "";
    } catch (const std::exception& e) {
        const std::string m = e.what();
        return version_step(m) ? m : "";
    }
}

class FlagDay : public ::testing::Test {
protected:
    void SetUp() override
    {
        was_testnet_ = ltc::PoolConfig::is_testnet;
        ltc::PoolConfig::is_testnet = true;   // CHAIN_LENGTH 400
        ltc::PoolConfig::v3601_activation_time_override = kT;
    }
    void TearDown() override
    {
        ltc::PoolConfig::v3601_activation_time_override.reset();
        ltc::PoolConfig::is_testnet = was_testnet_;
    }
    bool was_testnet_{false};
};

} // namespace

TEST(FlagDayDefault, MainnetScheduledTestnetNot)
{
    ASSERT_FALSE(ltc::PoolConfig::v3601_activation_time_override.has_value());
    // mainnet: 2026-11-11 12:00:00 UTC; testnet stays unscheduled.
    EXPECT_EQ(ltc::PoolConfig::V3601_ACTIVATION_TIME, 1794398400u);
    EXPECT_EQ(ltc::PoolConfig::TESTNET_V3601_ACTIVATION_TIME, 0xFFFFFFFFu);
    const bool was_testnet = ltc::PoolConfig::is_testnet;
    ltc::PoolConfig::is_testnet = false;
    const uint32_t t = ltc::PoolConfig::V3601_ACTIVATION_TIME;
    EXPECT_EQ(ltc::PoolConfig::v3601_activation_time(), t);
    EXPECT_EQ(ltc::flag_day_share_version(36, t - 1), 36);
    EXPECT_EQ(ltc::flag_day_share_version(36, t), 3601);
    EXPECT_EQ(ltc::flag_day_problem(36, t - 1, 36), "");
    EXPECT_NE(ltc::flag_day_problem(3601, t - 1, 36), "") << "no 3601 share before the flag day";
    EXPECT_NE(ltc::flag_day_problem(36, t, 36), "") << "no V36 share at or after the flag day";
    ltc::PoolConfig::is_testnet = true;
    EXPECT_EQ(ltc::flag_day_share_version(36, 2000000000u), 36) << "testnet: not scheduled";
    EXPECT_NE(ltc::flag_day_problem(3601, 2000000000u, 36), "");
    ltc::PoolConfig::is_testnet = was_testnet;
    EXPECT_EQ(ltc::PoolConfig::ADVERTISED_PROTOCOL_VERSION, 3601u);
    EXPECT_EQ(ltc::make_coin_params(false).advertised_protocol_version, 3601u);
    EXPECT_EQ(ltc::make_coin_params(false).minimum_protocol_version, 3301u) << "V36 peers still connect before it";
}

TEST_F(FlagDay, VersionFollowsTheTimestamp)
{
    EXPECT_EQ(ltc::flag_day_share_version(36, kT - 1), 36);
    EXPECT_EQ(ltc::flag_day_share_version(35, kT - 1), 35);
    EXPECT_EQ(ltc::flag_day_share_version(36, kT), 3601);
    EXPECT_EQ(ltc::flag_day_share_version(35, kT), 3601) << "the ratchet is not consulted after the flag day";
    EXPECT_EQ(ltc::flag_day_share_version(36, kT + 86400), 3601);
}

TEST_F(FlagDay, JobsBuildTheVersionTheirClippedTimestampCallsFor)
{
    EXPECT_EQ(ltc::job_share_version(36, kT - 10, std::nullopt), 36);
    EXPECT_EQ(ltc::job_share_version(36, kT - 10, kT - 20), 36);
    // ntime before the flag day on a parent at kT - 1: clipped to kT
    EXPECT_EQ(ltc::job_share_version(36, kT - 10, kT - 1), 3601);
    // a job on a 3601 parent builds a 3601 share whatever its ntime
    EXPECT_EQ(ltc::job_share_version(36, kT - 1000, kT + 3), 3601);
    EXPECT_EQ(ltc::job_share_version(35, kT, std::nullopt), 3601);
}

TEST_F(FlagDay, ProblemVerdicts)
{
    EXPECT_EQ(ltc::flag_day_problem(36, kT - 1, std::nullopt), "");
    EXPECT_EQ(ltc::flag_day_problem(35, kT - 1, 36), "");
    EXPECT_EQ(ltc::flag_day_problem(3601, kT, 36), "");
    EXPECT_EQ(ltc::flag_day_problem(3601, kT, 35), "") << "a chain still on V35 at the flag day cannot stall";
    EXPECT_EQ(ltc::flag_day_problem(3601, kT + 5, 3601), "");
    EXPECT_EQ(ltc::flag_day_problem(3601, kT, std::nullopt), "") << "a genesis share";
    const auto late = ltc::flag_day_problem(36, kT, 36);
    EXPECT_NE(late.find("peer too old, upgrade to c2pool v0.2.12"), std::string::npos) << late;
    EXPECT_NE(ltc::flag_day_problem(35, kT + 1, 36), "");
    EXPECT_NE(ltc::flag_day_problem(3601, kT - 1, 36), "");
    EXPECT_NE(ltc::flag_day_problem(36, kT - 1, 3601), "") << "no way back from 3601, whatever the timestamps";
}

// share_check on real trackers: the flag-day rule (step 1b) and the switch
// gate (step 2), before / at / after the flag day.
TEST_F(FlagDay, ShareCheckAcrossTheFlagDay)
{
    ltc::ShareTracker tr;
    const uint256 v36 = build_chain<ltc::MergedMiningShare>(tr, 0x1000, 410, kT - 1000);   // deeper than CHAIN_LENGTH
    EXPECT_EQ(version_verdict<ltc::MergedMiningShare>(tr, v36, kT - 1), "") << "V36 before the flag day";
    EXPECT_NE(version_verdict<ltc::MergedMiningShare>(tr, v36, kT), "") << "V36 at the flag day";
    EXPECT_NE(version_verdict<ltc::MergedMiningShare>(tr, v36, kT + 100), "") << "V36 after it";
    EXPECT_EQ(version_verdict<ltc::MergedMiningShareV3601>(tr, v36, kT), "") << "3601 at the flag day";
    EXPECT_NE(version_verdict<ltc::MergedMiningShareV3601>(tr, v36, kT - 1), "") << "3601 before it";

    // straddling: a 3601 share, then a V36 child timestamped before it
    const uint256 first = add<ltc::MergedMiningShareV3601>(tr, 0x5000, v36, kT + 2);
    const auto back = version_verdict<ltc::MergedMiningShare>(tr, first, kT - 5);
    EXPECT_NE(back.find("after a share version 3601 parent"), std::string::npos) << back;
    EXPECT_EQ(version_verdict<ltc::MergedMiningShareV3601>(tr, first, kT + 3), "");
    EXPECT_EQ(version_verdict<ltc::PaddingBugfixShare>(tr, first, kT + 3).empty(), false) << "nor a V35 one";
}

// The boundary into 3601 is not the 60% switch: a window in which nothing
// desires 36 or 3601 still crosses; the V35 -> V36 switch keeps its gate.
TEST_F(FlagDay, BoundaryDoesNotGoThroughTheSwitchGate)
{
    ltc::ShareTracker tr;
    const uint256 v35 = build_chain<ltc::PaddingBugfixShare>(tr, 0x2000, 410, kT - 1000, 35);
    EXPECT_EQ(version_verdict<ltc::MergedMiningShareV3601>(tr, v35, kT), "") << "V35 -> 3601 at the flag day";
    const auto gate = version_verdict<ltc::MergedMiningShare>(tr, v35, kT - 1);
    EXPECT_NE(gate.find("switch without enough hash power upgraded"), std::string::npos) << gate;

    ltc::ShareTracker shallow;
    const uint256 s36 = build_chain<ltc::MergedMiningShare>(shallow, 0x3000, 5, kT - 100);
    EXPECT_EQ(version_verdict<ltc::MergedMiningShareV3601>(shallow, s36, kT), "") << "no history needed";
    const uint256 s35 = build_chain<ltc::PaddingBugfixShare>(shallow, 0x3100, 5, kT - 100, 35);
    const auto hist = version_verdict<ltc::MergedMiningShare>(shallow, s35, kT - 1);
    EXPECT_NE(hist.find("switch without enough history"), std::string::npos) << hist;
}

// Two branches off a V36 share before the flag day: A crosses at once, B
// carries V36 shares up to just before it, then crosses. Every share of both
// is valid by its own timestamp, a V36 share past the flag day on either is
// not, and the 3601 shares' merged payouts do not depend on the other branch
// or the order the shares arrived in.
TEST_F(FlagDay, ReorgAcrossTheFlagDay)
{
    const auto entries = [](uint64_t id) {
        std::vector<ltc::MergedAddressEntry> v(1);
        v[0].m_chain_id = kDoge;
        v[0].m_script.m_data = ltc::pubkey_hash_to_script(uint160(), 0);
        v[0].m_script.m_data[3] = static_cast<unsigned char>(id);
        return v;
    };
    struct S { uint64_t id, prev; uint32_t ts; bool v3601; };
    const std::vector<S> base = {{1, 0, kT - 50, false}, {2, 1, kT - 40, false}, {3, 2, kT - 30, false}};
    const std::vector<S> a = {{10, 3, kT, true}, {11, 10, kT + 1, true}, {12, 11, kT + 2, true}};
    const std::vector<S> b = {{20, 3, kT - 10, false}, {21, 20, kT - 5, false}, {22, 21, kT + 2, true},
                              {23, 22, kT + 4, true}};
    const auto build = [&](ltc::ShareTracker& tr, const std::vector<std::vector<S>>& parts) {
        for (const auto& part : parts)
            for (const auto& s : part) {
                const uint256 prev = s.prev ? hx(s.prev) : uint256();
                if (s.v3601) {
                    auto* sh = make<ltc::MergedMiningShareV3601>(s.id, prev, s.ts);
                    ltc::ShareType st;
                    st = sh;
                    tr.add(st);
                } else {
                    auto* sh = make<ltc::MergedMiningShare>(s.id, prev, s.ts);
                    sh->m_merged_addresses = entries(s.id);
                    ltc::ShareType st;
                    st = sh;
                    tr.add(st);
                }
            }
    };
    ltc::ShareTracker ab, ba, a_only;
    build(ab, {base, a, b});
    build(ba, {b, base, a});
    build(a_only, {base, a});
    for (const auto& part : {a, b})
        for (const auto& s : part) {
            const auto verdict = s.v3601 ? version_verdict<ltc::MergedMiningShareV3601>(ab, hx(s.prev), s.ts, s.id + 0x100)
                                         : version_verdict<ltc::MergedMiningShare>(ab, hx(s.prev), s.ts, s.id + 0x100);
            EXPECT_EQ(verdict, "") << s.id;
        }
    EXPECT_NE(version_verdict<ltc::MergedMiningShare>(ab, hx(21), kT, 0x9999), "") << "B's next V36 share at the flag day";
    using W = std::map<std::vector<unsigned char>, uint288>;
    const auto w = [](ltc::ShareTracker& tr, uint64_t tip) {
        const auto r = tr.get_merged_payout_weights(hx(tip), kDoge);
        return W(r.resolved.begin(), r.resolved.end());
    };
    EXPECT_EQ(w(ab, 12), w(ba, 12));
    EXPECT_EQ(w(ab, 12), w(a_only, 12));
    EXPECT_EQ(w(ab, 23), w(ba, 23));
}

// A 3601 share is the V36 share's bytes under type number 3601: it reloads
// (a restart reads the stored type) as a 3601 share with every field; the
// share list a node without the type was built with cannot load it.
TEST_F(FlagDay, RestartReloadsA3601ShareAndAnOldNodeCannotLoadIt)
{
    std::unique_ptr<ltc::MergedMiningShare> v36(make<ltc::MergedMiningShare>(0x77, hx(0x76), kT + 9));
    v36->m_coinbase.m_data = {0x03, 0x11, 0x22, 0x33};
    v36->m_nonce = 0x01020304;
    v36->m_subsidy = 1250000000;
    v36->m_stale_info = ltc::StaleInfo::orphan;
    v36->m_far_share_hash = hx(0x10);
    v36->m_absheight = 1234;
    v36->m_abswork = uint128(987654321);
    v36->m_last_txout_nonce = 0xfeedbeef;
    v36->m_pubkey_type = 1;
    v36->m_merged_payout_hash = hx(0x99);
    v36->m_message_data.m_data = {0x01, 0x02};
    v36->m_ref_merkle_link.m_branch = {hx(1), hx(2)};
    v36->m_merkle_link.m_branch = {hx(3)};
    ltc::MergedAddressEntry e;
    e.m_chain_id = kDoge;
    e.m_script.m_data = {0x76, 0xa9, 0x14};
    v36->m_merged_addresses.push_back(e);
    ltc::MergedCoinbaseEntry ci;
    ci.m_chain_id = kDoge;
    ci.m_coinbase_value = 1000;
    ci.m_block_height = 7;
    ci.m_block_header.m_data.assign(80, 0x5a);
    v36->m_merged_coinbase_info.push_back(ci);
    v36->m_pow_hash = hx(0x1234);

    ltc::ShareType s36, s3601;
    s36 = new ltc::MergedMiningShare(*v36);
    s3601 = new ltc::MergedMiningShareV3601(*v36);
    EXPECT_EQ(s3601.version(), 3601);
    EXPECT_EQ(s3601.hash(), v36->m_hash);
    const auto bytes = [](const ltc::ShareType& s) {
        auto p = pack(s);
        auto sp = p.get_span();
        return std::vector<unsigned char>(reinterpret_cast<const unsigned char*>(sp.data()),
                                          reinterpret_cast<const unsigned char*>(sp.data()) + sp.size());
    };
    EXPECT_EQ(bytes(s36), bytes(s3601)) << "the same wire bytes";

    chain::RawShare raw(s3601.version(), pack(s3601));
    auto loaded = ltc::load_share(raw, NetService{});
    EXPECT_EQ(loaded.version(), 3601);
    EXPECT_EQ(loaded.prev_hash(), v36->m_prev_hash);   // (the hash is the header's, computed on verify)
    EXPECT_EQ(bytes(loaded), bytes(s36));
    // back to 36: every field, transient ones included
    loaded.invoke([&](auto* obj) {
        if constexpr (std::remove_pointer_t<decltype(obj)>::version == 3601) {
            ltc::MergedMiningShare again(*obj);
            ltc::ShareType sa;
            sa = new ltc::MergedMiningShare(again);
            EXPECT_EQ(bytes(sa), bytes(s36));
            EXPECT_EQ(again.m_prev_hash, v36->m_prev_hash);
            sa.destroy();
        }
    });
    ltc::MergedMiningShareV3601 conv(*v36);
    EXPECT_EQ(conv.m_pow_hash, v36->m_pow_hash);
    EXPECT_EQ(conv.m_timestamp, v36->m_timestamp);

    // c2pool before v0.2.12: the share list without 3601
    using OldShareType = chain::ShareVariants<ltc::Formatter, ltc::Share, ltc::NewShare, ltc::SegwitMiningShare,
                                              ltc::PaddingBugfixShare, ltc::MergedMiningShare>;
    auto stream = raw.contents.as_stream();
    EXPECT_THROW(OldShareType::load(3601, stream), std::invalid_argument);

    loaded.destroy();
    s36.destroy();
    s3601.destroy();
}

TEST_F(FlagDay, PeersBelow3601)
{
    EXPECT_FALSE(ltc::peer_takes_3601(std::nullopt));
    EXPECT_FALSE(ltc::peer_takes_3601(3600u)) << "p2pool and c2pool before v0.2.12";
    EXPECT_FALSE(ltc::peer_takes_3601(3502u));
    EXPECT_TRUE(ltc::peer_takes_3601(3601u));
    EXPECT_FALSE(ltc::v3601_flag_day_passed(kT - 1));
    EXPECT_TRUE(ltc::v3601_flag_day_passed(kT));
    const auto line = ltc::pre_3601_peer_line("10.0.0.1:9326", 3600u, "c2pool/0.2.11");
    EXPECT_NE(line.find("peer too old, upgrade to c2pool v0.2.12"), std::string::npos) << line;
    EXPECT_NE(line.find("protocol 3600"), std::string::npos) << line;

    ltc::ShareType late, early, ok;
    late = make<ltc::MergedMiningShare>(1, uint256(), kT);
    early = make<ltc::MergedMiningShare>(2, uint256(), kT - 1);
    ok = make<ltc::MergedMiningShareV3601>(3, uint256(), kT);
    EXPECT_TRUE(ltc::pre_3601_share_past_flag_day(late));
    EXPECT_FALSE(ltc::pre_3601_share_past_flag_day(early));
    EXPECT_FALSE(ltc::pre_3601_share_past_flag_day(ok));
    late.destroy();
    early.destroy();
    ok.destroy();
}

// The "too old" WARNING once an hour per IP, whatever port the old peer
// redials from; another IP is warned about on its own.
TEST(FlagDayPeers, TooOldWarningOncePerHourPerIp)
{
    ltc::Pre3601WarnLimiter lim;
    const auto t0 = ltc::Pre3601WarnLimiter::clock::now();
    EXPECT_TRUE(lim.should_warn("10.0.0.1", t0));
    EXPECT_FALSE(lim.should_warn("10.0.0.1", t0 + std::chrono::seconds(30))) << "a redial from a new port";
    EXPECT_FALSE(lim.should_warn("10.0.0.1", t0 + std::chrono::minutes(59)));
    EXPECT_TRUE(lim.should_warn("10.0.0.2", t0 + std::chrono::seconds(30))) << "another IP";
    EXPECT_TRUE(lim.should_warn("10.0.0.1", t0 + std::chrono::hours(1)));
    EXPECT_FALSE(lim.should_warn("10.0.0.1", t0 + std::chrono::hours(1) + std::chrono::seconds(1)));
    // bounded: once the map passes 4096, the expired entries go
    ltc::Pre3601WarnLimiter big;
    for (int i = 0; i < 5000; ++i)
        EXPECT_TRUE(big.should_warn("ip" + std::to_string(i), t0));
    EXPECT_EQ(big.size(), 5000u) << "all within their hour";
    const auto later = t0 + std::chrono::hours(2);
    EXPECT_TRUE(big.should_warn("ip0", later));
    EXPECT_EQ(big.size(), 1u) << "the expired 4999 dropped";
}

// ---- the AuxPoW commitment: enforced for 3601 shares, counted for V36 ------

namespace {

std::vector<unsigned char> header_of(uint32_t cid)
{
    std::vector<unsigned char> h(80);
    for (size_t i = 0; i < 80; ++i) h[i] = static_cast<unsigned char>((cid * 7 + i) & 0xff);
    return h;
}

// The coinbase scriptSig of a share committing (root, size) and its
// merged_coinbase_info for `carried`.
template <class S>
void commit(S& s, const uint256& root, uint32_t size, const std::vector<uint32_t>& carried)
{
    s.m_coinbase.m_data = {0x03, 0x01, 0x02, 0x03, 0xfa, 0xbe, 0x6d, 0x6d};
    for (int i = 31; i >= 0; --i) s.m_coinbase.m_data.push_back(root.data()[i]);
    for (int i = 0; i < 4; ++i) s.m_coinbase.m_data.push_back(static_cast<unsigned char>(size >> (8 * i)));
    for (int i = 0; i < 4; ++i) s.m_coinbase.m_data.push_back(0);
    s.m_merged_coinbase_info.clear();
    for (auto cid : carried) {
        ltc::MergedCoinbaseEntry e;
        e.m_chain_id = cid;
        e.m_coinbase_value = 1000;
        e.m_block_height = 1;
        e.m_block_header.m_data = header_of(cid);
        s.m_merged_coinbase_info.push_back(e);
    }
}

// The p2pool tree root over `ids` (aux_commitment_rule.hpp p2pool_aux_tree).
uint256 tree_root(const std::vector<uint32_t>& ids, uint32_t& size)
{
    std::map<uint32_t, uint32_t> slots;
    size = c2pool::merged::p2pool_aux_tree(ids, &slots);
    std::vector<uint256> layer(size);
    for (auto id : ids) layer[slots.at(id)] = Hash(std::span<const unsigned char>(header_of(id).data(), 80));
    while (layer.size() > 1) {
        std::vector<uint256> next(layer.size() / 2);
        for (size_t k = 0; k < next.size(); ++k) next[k] = Hash(layer[2 * k], layer[2 * k + 1]);
        layer = std::move(next);
    }
    return layer[0];
}

} // namespace

TEST_F(FlagDay, AuxCommitmentIsEnforcedFor3601SharesOnly)
{
    uint32_t size = 0;
    const uint256 root = tree_root({kDoge, kPep}, size);
    ASSERT_EQ(size, 2u);
    ltc::MergedMiningShareV3601 good;
    commit(good, root, size, {kDoge, kPep});
    EXPECT_EQ(ltc::merged_aux_commitment_problem(good), "");

    struct Defect { const char* what; uint256 root; uint32_t size; std::vector<uint32_t> carried; };
    uint256 flipped = root;
    flipped.data()[0] ^= 1;
    const std::vector<Defect> defects = {
        {"size", root, size * 2, {kDoge, kPep}},
        {"root", flipped, size, {kDoge, kPep}},
        {"a chain committed but not carried", root, size, {kDoge}},
        {"one chain at size 1, another block", root, 1, {kDoge}},
    };
    ltc::ShareTracker shallow;
    const auto params = ltc::make_coin_params(true);
    for (const auto& d : defects) {
        ltc::MergedMiningShareV3601 s;
        commit(s, d.root, d.size, d.carried);
        EXPECT_NE(ltc::merged_aux_commitment_problem(s), "") << d.what;
        // rejected by the share check at any depth (no share chain needed)
        const auto why = ltc::verify_merged_coinbase_commitment(s, shallow, params);
        EXPECT_NE(why.find("merged aux commitment"), std::string::npos) << d.what << ": " << why;
    }

    // A V36 share with the same multi-chain defect: counted, not rejected
    // (with the chain depth the check needs; without it nothing is checked).
    ltc::ShareTracker deep;
    const uint256 tip = build_chain<ltc::MergedMiningShare>(deep, 0x4000, 410, kT - 1000);
    auto& st = c2pool::merged::merged_rule_stats();
    for (const auto& d : {defects[0], defects[1], defects[2]}) {
        ltc::MergedMiningShare s36;
        commit(s36, d.root, d.size, d.carried);
        s36.m_prev_hash = tip;
        s36.m_bits = kBits;
        const auto w0 = st.would_reject.load();
        EXPECT_EQ(ltc::verify_merged_coinbase_commitment(s36, deep, params), "") << d.what;
        EXPECT_EQ(st.would_reject.load(), w0 + 1) << d.what;
        ltc::MergedMiningShareV3601 s3601(s36);
        EXPECT_NE(ltc::verify_merged_coinbase_commitment(s3601, deep, params), "") << d.what;
    }
    // compliant shares pass at any depth
    ltc::MergedMiningShareV3601 deep_good(good);
    deep_good.m_prev_hash = tip;
    deep_good.m_bits = kBits;
    EXPECT_EQ(ltc::verify_merged_coinbase_commitment(deep_good, deep, params), "");
    EXPECT_EQ(ltc::verify_merged_coinbase_commitment(good, shallow, params), "");
}
