// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// DGB is held at V35 until a flag day (rides dgb_work_source_test).
//
// Operator decision (2026-11-27): the live DGB network is python V35 only
// (SUCCESSOR None: a V36 share "can't follow" a V35 one there), so c2pool-dgb
// must never switch to V36 by itself once its shares fill the ratchet's 95%
// window. dgb::DgbVersionPolicy: without --v36-ratchet the node mints V35 and
// votes 35 (as python does) and reads/writes no ratchet state; a persisted
// state file is ignored. With it, today's AutoRatchet.
// ---------------------------------------------------------------------------

#include <impl/dgb/auto_ratchet_wire.hpp>
#include <impl/dgb/config_pool.hpp>
#include <impl/dgb/share.hpp>
#include <impl/dgb/share_tracker.hpp>

#include <core/uint256.hpp>

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>

#include <cstdio>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <unistd.h>
#include <vector>

#ifndef DGB_MAIN_SRC
#error "DGB_MAIN_SRC (path of src/c2pool/main_dgb.cpp) is not defined"
#endif

namespace {

// A genesis-rooted chain of `n` V35 shares, every one voting 36: c2pool-only
// mining after python left, the state the ratchet would activate on.
struct VotingChain {
    dgb::ShareTracker tracker;
    uint256 tip;
    explicit VotingChain(int n)
    {
        uint256 prev;
        for (int i = 0; i < n; ++i) {
            auto* s = new dgb::PaddingBugfixShare();
            uint256 h;
            h.SetHex(std::to_string(1000000 + i));
            s->m_hash = h;
            s->m_prev_hash = prev;
            s->m_desired_version = 36;
            s->m_bits = 0x1e0fffff;
            s->m_max_bits = 0x1e0fffff;
            s->m_timestamp = 1790000000u + 15u * static_cast<uint32_t>(i);
            s->m_absheight = static_cast<uint32_t>(i + 1);
            prev = h;
            tip = h;
            dgb::ShareType st;
            st = s;
            tracker.add(st);
        }
    }
};

std::string tmp_path(const char* tag)
{
    return std::string("/tmp/dgb_v35_hold_") + tag + "_" + std::to_string(::getpid()) + ".json";
}

std::string read_all(const std::string& p)
{
    std::ifstream f(p);
    std::stringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

void write_confirmed(const std::string& path)
{
    nlohmann::json j;
    j["state"] = "confirmed";
    j["activated_at"] = 1;
    j["activated_height"] = 2;
    j["confirmed_at"] = 3;
    j["confirm_count"] = 4;
    std::ofstream(path) << j.dump(2);
}

} // namespace

TEST(DgbV35Hold, FullWindowOfV36VotesStaysV35WhileTheRatchetIsOff)
{
    const int n = static_cast<int>(dgb::PoolConfig::chain_length()) + 20;
    VotingChain c(n);
    ASSERT_GE(c.tracker.chain.get_height(c.tip), static_cast<int32_t>(dgb::PoolConfig::chain_length()));

    const std::string path = tmp_path("off");
    std::remove(path.c_str());
    dgb::DgbVersionPolicy held(/*v36_ratchet=*/false, path);
    EXPECT_FALSE(held.ratchet_enabled());
    for (int i = 0; i < 3; ++i) {
        const auto [mint, vote] = held.select(c.tracker, c.tip);
        EXPECT_EQ(mint, 35) << "c2pool-dgb switched to V36 by itself";
        EXPECT_EQ(vote, 35) << "a held node votes as python does";
    }
    EXPECT_FALSE(std::filesystem::exists(path)) << "a held node wrote ratchet state";

    // Opt-in: today's behaviour, the same window activates V36.
    const std::string on_path = tmp_path("on");
    std::remove(on_path.c_str());
    dgb::DgbVersionPolicy on(/*v36_ratchet=*/true, on_path);
    ASSERT_TRUE(on.ratchet_enabled());
    const auto [mint, vote] = on.select(c.tracker, c.tip);
    EXPECT_EQ(mint, 36);
    EXPECT_EQ(vote, 36);
    std::remove(on_path.c_str());
}

TEST(DgbV35Hold, PersistedRatchetStateIsIgnoredWhileOff)
{
    VotingChain c(10);
    const std::string path = tmp_path("persisted");
    write_confirmed(path);
    const std::string before = read_all(path);

    dgb::DgbVersionPolicy held(false, path);
    EXPECT_TRUE(held.stale_state_file_ignored());
    const auto [mint, vote] = held.select(c.tracker, c.tip);
    EXPECT_EQ(mint, 35) << "a persisted CONFIRMED state was honoured while the ratchet is off";
    EXPECT_EQ(vote, 35);
    EXPECT_EQ(read_all(path), before) << "the persisted state was rewritten";

    // Opt-in honours it, as before.
    dgb::DgbVersionPolicy on(true, path);
    EXPECT_FALSE(on.stale_state_file_ignored());
    const auto [m2, v2] = on.select(c.tracker, c.tip);
    EXPECT_EQ(m2, 36);
    EXPECT_EQ(v2, 36);
    std::remove(path.c_str());
}

// main_dgb asks the policy (not the ratchet) and builds it from the opt-in.
TEST(DgbV35Hold, MainDgbUsesThePolicy)
{
    std::ifstream f(DGB_MAIN_SRC);
    ASSERT_TRUE(f.good()) << DGB_MAIN_SRC;
    std::stringstream ss;
    ss << f.rdbuf();
    const std::string src = ss.str();
    EXPECT_NE(src.find("std::make_shared<dgb::DgbVersionPolicy>(v36_ratchet, ratchet_path)"), std::string::npos);
    EXPECT_NE(src.find("dgb_versions->select(pplns_tracker, prev_share_hash)"), std::string::npos);
    EXPECT_EQ(src.find("std::make_shared<dgb::AutoRatchet>("), std::string::npos)
        << "main_dgb builds a ratchet outside the policy";
    EXPECT_NE(src.find("\"--v36-ratchet\""), std::string::npos);
}
