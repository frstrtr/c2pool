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
// ---------------------------------------------------------------------------

#include <gtest/gtest.h>

#include <cstdio>
#include <map>
#include <string>
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
