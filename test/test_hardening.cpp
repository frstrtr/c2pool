/**
 * Regression tests for the hardening changes introduced in
 * "Harden coin RPC/P2P safety checks" (commit 2e7fadba).
 *
 * Covers:
 *   1. collect_softfork_names() — pure JSON-to-set parsing; all daemon formats
 *   2. Softfork gate logic — missing / present / superset
 *   3. Matcher timeout configuration — default and custom; response path
 *   4. Matcher timeout integration — entry expires after configured seconds
 */

#include <gtest/gtest.h>

#include <impl/ltc/coin/softfork_check.hpp>
#include <core/reply_matcher.hpp>

#include <boost/asio.hpp>
#include <nlohmann/json.hpp>

#include <atomic>
#include <chrono>
#include <set>
#include <string>
#include <vector>

// ============================================================================
// Helpers
// ============================================================================

namespace {

std::set<std::string> collect(const nlohmann::json& j)
{
    std::set<std::string> out;
    ltc::coin::collect_softfork_names(j, out);
    return out;
}

} // anonymous namespace

// ============================================================================
// Suite 1: collect_softfork_names — pure data transformation
// ============================================================================

TEST(CollectSoftforkNames, ArrayOfObjectsWithId)
{
    // Modern litecoind: [{"id":"segwit","type":"buried"}, ...]
    auto j = nlohmann::json::array();
    j.push_back({{"id", "segwit"}, {"type", "buried"}});
    j.push_back({{"id", "taproot"}, {"type", "buried"}});
    j.push_back({{"id", "mweb"}, {"type", "buried"}});

    auto names = collect(j);
    EXPECT_EQ(names.size(), 3u);
    EXPECT_TRUE(names.count("segwit"));
    EXPECT_TRUE(names.count("taproot"));
    EXPECT_TRUE(names.count("mweb"));
}

TEST(CollectSoftforkNames, ArrayOfStrings)
{
    // Compact array form: ["bip65", "csv", "segwit"]
    nlohmann::json j = {"bip65", "csv", "segwit"};

    auto names = collect(j);
    EXPECT_EQ(names.size(), 3u);
    EXPECT_TRUE(names.count("bip65"));
    EXPECT_TRUE(names.count("csv"));
    EXPECT_TRUE(names.count("segwit"));
}

TEST(CollectSoftforkNames, ObjectKeys)
{
    // BIP9 style: {"segwit": {...}, "taproot": {...}}
    nlohmann::json j = {
        {"segwit",  {{"status", "active"}}},
        {"taproot", {{"status", "active"}}},
    };

    auto names = collect(j);
    EXPECT_EQ(names.size(), 2u);
    EXPECT_TRUE(names.count("segwit"));
    EXPECT_TRUE(names.count("taproot"));
}

TEST(CollectSoftforkNames, SkipsObjectsWithoutIdField)
{
    // Objects missing the "id" key must be silently skipped
    auto j = nlohmann::json::array();
    j.push_back({{"type", "buried"}});                     // no "id"
    j.push_back({{"id", "csv"}, {"type", "buried"}});      // has "id"

    auto names = collect(j);
    EXPECT_EQ(names.size(), 1u);
    EXPECT_TRUE(names.count("csv"));
}

TEST(CollectSoftforkNames, EmptyArrayProducesNoNames)
{
    nlohmann::json j = nlohmann::json::array();
    EXPECT_TRUE(collect(j).empty());
}

TEST(CollectSoftforkNames, MixedTypesInArrayDoNotCrash)
{
    // Non-string, non-object items must be silently ignored
    auto j = nlohmann::json::array();
    j.push_back(nullptr);
    j.push_back(42);
    j.push_back(true);
    j.push_back({{"id", "taproot"}});

    auto names = collect(j);
    EXPECT_EQ(names.size(), 1u);
    EXPECT_TRUE(names.count("taproot"));
}

TEST(CollectSoftforkNames, AccumulatesAcrossMultipleCalls)
{
    // Simulates the rpc.cpp pattern: call once for "softforks",
    // once for "bip9_softforks", both accumulate into the same set.
    std::set<std::string> out;

    nlohmann::json softforks = {"bip65", "csv"};
    ltc::coin::collect_softfork_names(softforks, out);

    nlohmann::json bip9 = {{"segwit", {{"status", "active"}}},
                           {"taproot", {{"status", "active"}}}};
    ltc::coin::collect_softfork_names(bip9, out);

    EXPECT_EQ(out.size(), 4u);
    EXPECT_TRUE(out.count("bip65"));
    EXPECT_TRUE(out.count("csv"));
    EXPECT_TRUE(out.count("segwit"));
    EXPECT_TRUE(out.count("taproot"));
}

// ============================================================================
// Suite 2: Softfork gate logic (mirrors NodeRPC::check() decision)
// ============================================================================

namespace {

// Returns missing fork names given a supported set and a required set.
std::vector<std::string> missing_forks(
    const std::set<std::string>& supported,
    const std::set<std::string>& required)
{
    std::vector<std::string> missing;
    for (const auto& req : required)
        if (!supported.count(req))
            missing.push_back(req);
    return missing;
}

const std::set<std::string> REQUIRED = {
    "bip65", "csv", "segwit", "taproot", "mweb"
};

} // anonymous namespace

TEST(SoftforkGate, AllRequiredPresent)
{
    std::set<std::string> supported = {"bip65", "csv", "segwit", "taproot", "mweb"};
    EXPECT_TRUE(missing_forks(supported, REQUIRED).empty());
}

TEST(SoftforkGate, MissingTaprootDetected)
{
    std::set<std::string> supported = {"bip65", "csv", "segwit", "mweb"};
    auto missing = missing_forks(supported, REQUIRED);
    ASSERT_EQ(missing.size(), 1u);
    EXPECT_EQ(missing[0], "taproot");
}

TEST(SoftforkGate, MissingMwebDetected)
{
    std::set<std::string> supported = {"bip65", "csv", "segwit", "taproot"};
    auto missing = missing_forks(supported, REQUIRED);
    ASSERT_EQ(missing.size(), 1u);
    EXPECT_EQ(missing[0], "mweb");
}

TEST(SoftforkGate, MultipleMissingForksAllReported)
{
    std::set<std::string> supported = {"bip65"};
    auto missing = missing_forks(supported, REQUIRED);
    EXPECT_EQ(missing.size(), 4u);
}

TEST(SoftforkGate, SupersetPassesGate)
{
    // Daemon reporting extra forks beyond what we require must still pass
    std::set<std::string> supported = {
        "bip65", "csv", "segwit", "taproot", "mweb", "bip68", "bip112"
    };
    EXPECT_TRUE(missing_forks(supported, REQUIRED).empty());
}

TEST(SoftforkGate, EmptySupportedSetFailsAll)
{
    std::set<std::string> supported;
    auto missing = missing_forks(supported, REQUIRED);
    EXPECT_EQ(missing.size(), REQUIRED.size());
}

// ============================================================================
// Suite 3: Matcher — timeout configuration
// ============================================================================

TEST(ReplyMatcherConfig, DefaultTimeoutIsFiveSec)
{
    boost::asio::io_context ioc;
    auto req = [](int) {};
    core::deffered::Matcher<int, std::string, int> m(&ioc, req);
    EXPECT_EQ(m.m_timeout, 5);
}

TEST(ReplyMatcherConfig, CustomTimeoutIsStored)
{
    boost::asio::io_context ioc;
    auto req = [](int) {};
    core::deffered::Matcher<int, std::string, int> m(&ioc, req, 15);
    EXPECT_EQ(m.m_timeout, 15);
}

TEST(ReplyMatcherConfig, LargeTimeoutStoredCorrectly)
{
    boost::asio::io_context ioc;
    auto req = [](int) {};
    core::deffered::Matcher<int, std::string, int> m(&ioc, req, 300);
    EXPECT_EQ(m.m_timeout, 300);
}

TEST(ReplyMatcherResponse, EntryRemovedOnSuccessfulResponse)
{
    boost::asio::io_context ioc;
    auto req = [](int) {};
    core::deffered::Matcher<int, std::string, int> m(&ioc, req, 5);

    std::string received;
    m.request(42, [&received](std::string s) { received = std::move(s); }, 0);

    EXPECT_EQ(m.m_watchers.size(), 1u);

    m.got_response(42, "hello");

    EXPECT_EQ(received, "hello");
    EXPECT_EQ(m.m_watchers.size(), 0u);
}

TEST(ReplyMatcherResponse, DuplicateRequestIsIgnored)
{
    // Requesting the same id twice: second call should be silently dropped
    boost::asio::io_context ioc;
    int send_count = 0;
    auto req = [&send_count](int) { ++send_count; };
    core::deffered::Matcher<int, std::string, int> m(&ioc, req, 5);

    m.request(1, [](std::string) {}, 0);
    m.request(1, [](std::string) {}, 0);  // duplicate — should be dropped

    EXPECT_EQ(m.m_watchers.size(), 1u);
    EXPECT_EQ(send_count, 1);
}

// ============================================================================
// Suite 4: Matcher timeout integration (1-second timer)
// ============================================================================

TEST(ReplyMatcherTimeout, EntryExpiredAfterOneSec)
{
    boost::asio::io_context ioc;
    auto req = [](int) {};
    core::deffered::Matcher<int, std::string, int> m(&ioc, req, 1);

    m.request(99, [](std::string) {}, 0);
    EXPECT_EQ(m.m_watchers.size(), 1u);

    // run_for returns as soon as the timer fires (≈1s) and there is no more work
    ioc.run_for(std::chrono::milliseconds(1500));

    EXPECT_EQ(m.m_watchers.size(), 0u);
}

TEST(ReplyMatcherTimeout, ResponseBeforeTimeoutCancelsTimer)
{
    // Sending a response before the timer fires must leave nothing in watchers.
    boost::asio::io_context ioc;
    auto req = [](int) {};
    core::deffered::Matcher<int, std::string, int> m(&ioc, req, 5);

    std::string received;
    m.request(7, [&received](std::string s) { received = std::move(s); }, 0);

    m.got_response(7, "ok");

    EXPECT_EQ(received, "ok");
    EXPECT_EQ(m.m_watchers.size(), 0u);

    // Running the io_context should find nothing queued for the 5-second timeout
    // (the timer was stopped when the response arrived)
    ioc.run_for(std::chrono::milliseconds(100));

    EXPECT_EQ(m.m_watchers.size(), 0u);
}
