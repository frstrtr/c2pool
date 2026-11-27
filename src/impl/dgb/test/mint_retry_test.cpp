// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// The DGB mint retries while the tracker is busy (rides dgb_work_source_test).
//
// Review 713dc77a0 #11: main_dgb's mint seam took the tracker lock with
// try_to_lock and dropped the share when it was busy ("deferred" meant lost).
// dgb::mint_with_retry runs the attempt now, and while it reports busy retries
// it on the IO context, bounded; a declined share is not retried.
// ---------------------------------------------------------------------------

#include <impl/dgb/mint_retry.hpp>

#include <core/uint256.hpp>

#include <boost/asio/io_context.hpp>
#include <gtest/gtest.h>

#include <fstream>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

#ifndef DGB_MAIN_SRC
#error "DGB_MAIN_SRC (path of src/c2pool/main_dgb.cpp) is not defined"
#endif

namespace {

const uint256 kShare(std::vector<unsigned char>(32, 0x42));

} // namespace

TEST(DgbMintRetry, NotBusyMintsAtOnce)
{
    boost::asio::io_context ioc;
    int attempts = 0;
    bool queued = true;
    const uint256 h = dgb::mint_with_retry(ioc, [&]() -> std::optional<uint256> {
        ++attempts;
        return kShare;
    }, {}, &queued);
    EXPECT_EQ(h, kShare);
    EXPECT_FALSE(queued);
    EXPECT_EQ(ioc.run(), 0u) << "no retry was needed";
    EXPECT_EQ(attempts, 1);
}

TEST(DgbMintRetry, BusyTrackerIsRetriedUntilTheMint)
{
    boost::asio::io_context ioc;
    int attempts = 0;
    bool queued = false;
    uint256 done;
    int done_tries = 0;
    const uint256 h = dgb::mint_with_retry(
        ioc,
        [&]() -> std::optional<uint256> {
            ++attempts;
            if (attempts <= 3)
                return std::nullopt;   // busy
            return kShare;
        },
        [&](const uint256& r, int tries) {
            done = r;
            done_tries = tries;
        },
        &queued);
    EXPECT_TRUE(h.IsNull()) << "a busy mint returns no hash now";
    EXPECT_TRUE(queued);
    ioc.run();
    EXPECT_EQ(attempts, 4);
    EXPECT_EQ(done, kShare) << "the share was dropped on a busy tracker";
    EXPECT_EQ(done_tries, 4);
}

TEST(DgbMintRetry, RetriesAreBounded)
{
    boost::asio::io_context ioc;
    int attempts = 0;
    bool gave_up = false;
    dgb::mint_with_retry(
        ioc, [&]() -> std::optional<uint256> {
            ++attempts;
            return std::nullopt;
        },
        [&](const uint256& r, int tries) {
            gave_up = r.IsNull() && tries == dgb::kMintRetryTries;
        });
    ioc.run();
    EXPECT_EQ(attempts, dgb::kMintRetryTries);
    EXPECT_TRUE(gave_up);
}

TEST(DgbMintRetry, DeclinedShareIsNotRetried)
{
    boost::asio::io_context ioc;
    int attempts = 0;
    bool queued = true;
    const uint256 h = dgb::mint_with_retry(ioc, [&]() -> std::optional<uint256> {
        ++attempts;
        return uint256();   // declined (not busy)
    }, {}, &queued);
    EXPECT_TRUE(h.IsNull());
    EXPECT_FALSE(queued);
    EXPECT_EQ(ioc.run(), 0u);
    EXPECT_EQ(attempts, 1);
}

// main_dgb's mint seam goes through mint_with_retry and no longer drops a
// share on a busy tracker.
TEST(DgbMintRetry, MainDgbMintSeamRetries)
{
    std::ifstream f(DGB_MAIN_SRC);
    ASSERT_TRUE(f.good()) << DGB_MAIN_SRC;
    std::stringstream ss;
    ss << f.rdbuf();
    const std::string src = ss.str();
    const auto seam = src.find("work_source->set_mint_share_fn(");
    ASSERT_NE(seam, std::string::npos);
    const auto end = src.find("sharechain mint seam BOUND", seam);
    ASSERT_NE(end, std::string::npos);
    const std::string body = src.substr(seam, end - seam);
    EXPECT_NE(body.find("dgb::mint_with_retry("), std::string::npos);
    EXPECT_EQ(body.find("share deferred"), std::string::npos) << "the mint still drops a share on a busy tracker";
}
