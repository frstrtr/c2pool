#include <gtest/gtest.h>
#include <tuple>
#include <string>
#include <sstream>
#include <iostream>

#include "bitcoind.h"

TEST(BitcoindJSON_RPC, getblockchaininfo){
    auto first = CreateUINT256("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    uint256 first_res = bitcoind::data::target_to_average_attempts(first);
    cout << first_res.GetHex() << endl;
    ASSERT_EQ(first_res.GetHex(), "0000000000000000000000000000000000000000000000000000000000000001");
    
    auto second = CreateUINT256("1");
    uint256 second_res = bitcoind::data::target_to_average_attempts(second);
    cout << second_res.GetHex() << endl;
    //Note: in Python: '0x8000000000000000000000000000000000000000000000000000000000000000'
    ASSERT_EQ(second_res.GetHex(), "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");

    auto third = CreateUINT256("100000000000000000000000000000000");
    uint256 third_res = bitcoind::data::target_to_average_attempts(third);
    cout << third_res.GetHex() << endl;
    ASSERT_EQ(third_res.GetHex(), "00000000000000000000000000000000ffffffffffffffffffffffffffffffff");

    auto fourth = CreateUINT256("ffffffffffffffffffffffffffffffff");
    uint256 fourth_res = bitcoind::data::target_to_average_attempts(fourth);
    cout << fourth_res.GetHex() << endl;
    ASSERT_EQ(fourth_res.GetHex(), "00000000000000000000000000000000ffffffffffffffffffffffffffffffff");
}