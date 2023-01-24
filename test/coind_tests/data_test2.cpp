#include <gtest/gtest.h>
#include <tuple>
#include <string>
#include <sstream>
#include <iostream>

#include <btclibs/uint256.h>
#include <btclibs/arith_uint256.h>
#include <libcoind/types.h>
#include <libcoind/data.h>

#include <boost/range/combine.hpp>
#include <boost/foreach.hpp>
using namespace std;

TEST(CoindData, calculate_merkle_link_test)
{
    std::vector<uint256> arr{uint256::ZERO, uint256S("f57657b1b38a9766c736c9195d1df87f7053fcbbcc7540da12fb6afee7a2c58d")};
    auto res = coind::data::calculate_merkle_link(arr, 0);

    ASSERT_EQ(res.branch.size(), 1);
    ASSERT_EQ(res.branch.back(), uint256S("f57657b1b38a9766c736c9195d1df87f7053fcbbcc7540da12fb6afee7a2c58d"));
    ASSERT_EQ(res.index, 0);

    std::vector<uint256> arr2 = {uint256::ZERO, uint256S("f57657b1b38a9766c736c9195d1df87f7053fcbbcc7540da12fb6afee7a2c58d"), uint256S("d85c2a7eefa6bf21ad0457ccbbcf3507f78fd1d5919c637c6679a83b1b75675f")};
    auto res2 = coind::data::calculate_merkle_link(arr2, 1);

    ASSERT_EQ(res2.branch.size(), 2);
    std::vector<uint256> assert_arr{uint256S("f57657b1b38a9766c736c9195d1df87f7053fcbbcc7540da12fb6afee7a2c58d"), uint256S("4e982e45bfc83686d1c881cda6c753f12286f0659c646cb4fa4959bfea568176")};
    ASSERT_EQ(res2.branch, assert_arr);
    ASSERT_EQ(res2.index, 0);
}