#include <gtest/gtest.h>
#include <libdevcore/common.h>
#include <iostream>
#include <boost/date_time.hpp>

TEST(Devcore_common, simple_string)
{
    auto t1 = boost::posix_time::seconds(86401*30);
//    std::cout << to_iso_string(t1) << std::endl;
    auto r = boost::posix_time::to_simple_string(t1);

    std::cout << "R=" << r << std::endl;
}

//todo
TEST(Devcore_common, date_format)
{
    auto f = [](boost::posix_time::seconds t){
//        if (t.)
    };

    auto t1 = boost::posix_time::seconds(86401);
//    std::cout << to_iso_string(t1) << std::endl;
    auto r = boost::posix_time::to_simple_string(t1);

    std::cout << "R=" << r << std::endl;
}