#include <gtest/gtest.h>
#include <memory>
#include <vector>
#include <string>

//#include <sharechains/tracker.h>
//#include <networks/network.h>
//
//#include <sharechains/share.h>
//#include <sharechains/share_builder.h>
#include <sharechains/data.h>
#include <libdevcore/random.h>

TEST(SharechainDataTest, TestCheckHashLink)
{
    for (int i = 0; i < 100; i++)
    {
        auto d = c2pool::random::random_bytes(2048);
        auto x = shares::prefix_to_hash_link(d);
        ASSERT_EQ(shares::check_hash_link(x, std::vector<unsigned char>{}), coind::data::hash256(PackStream(d)));
    }
}