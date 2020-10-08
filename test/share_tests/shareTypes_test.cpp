#include <gtest/gtest.h>
#include <iostream>
#include <memory>
#include <shareTypes.h>
#include <sstream>


//TODO: create CMakeList.txt
TEST(Shares, HashLinkTypeTest)
{
    c2pool::shares::HashLinkType hashLinkType1("1", "2");
    c2pool::shares::HashLinkType hashLinkType2;
    std::stringstream ss;
    ss << "1" << " " << "2";
    ss >> hashLinkType2;
    ASSERT_EQ(hashLinkType1, hashLinkType2);
    c2pool::shares::HashLinkType hashLinkType3;
    std::stringstream ss2;
    ss2 << hashLinkType1;
    ss2 >> hashLinkType3;
    ASSERT_EQ(hashLinkType1, hashLinkType3);
}