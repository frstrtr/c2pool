#include <gtest/gtest.h>
#include <tuple>
#include <string>
#include <sstream>
#include <iostream>

#include <btclibs/uint256.h>
#include <btclibs/arith_uint256.h>
#include <libcoind/data.h>

using namespace std;

uint256 CreateUINT256(string _hex){
    uint256 result;
    result.SetHex(_hex);
    return result;
}

TEST(BitcoindDataTest, target_to_averate_attempts_test){
    auto first = CreateUINT256("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    uint256 first_res = coind::data::target_to_average_attempts(first);
    cout << first_res.GetHex() << endl;
    ASSERT_EQ(first_res.GetHex(), "0000000000000000000000000000000000000000000000000000000000000001");
    
    auto second = CreateUINT256("1");
    uint256 second_res = coind::data::target_to_average_attempts(second);
    cout << second_res.GetHex() << endl;
    //Note: in Python: '0x8000000000000000000000000000000000000000000000000000000000000000'
    ASSERT_EQ(second_res.GetHex(), "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");

    auto third = CreateUINT256("100000000000000000000000000000000");
    uint256 third_res = coind::data::target_to_average_attempts(third);
    cout << third_res.GetHex() << endl;
    ASSERT_EQ(third_res.GetHex(), "00000000000000000000000000000000ffffffffffffffffffffffffffffffff");

    auto fourth = CreateUINT256("ffffffffffffffffffffffffffffffff");
    uint256 fourth_res = coind::data::target_to_average_attempts(fourth);
    cout << fourth_res.GetHex() << endl;
    ASSERT_EQ(fourth_res.GetHex(), "00000000000000000000000000000000ffffffffffffffffffffffffffffffff");
}

TEST(BitcoindDataTest, average_attempts_to_target_test){
    auto first = CreateUINT256("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    uint256 first_res = coind::data::average_attempts_to_target(first);
    cout << first_res.GetHex() << endl;
    ASSERT_EQ(first_res.GetHex(), "0000000000000000000000000000000000000000000000000000000000000000");
    
    auto second = CreateUINT256("100000000000000000000000000000000");
    uint256 second_res = coind::data::target_to_average_attempts(second);
    cout << second_res.GetHex() << endl;
    //Note: in Python: '0x8000000000000000000000000000000000000000000000000000000000000000'
    ASSERT_EQ(second_res.GetHex(), "0000000000000000000000000000000100000000000000000000000000000000");

    auto third = CreateUINT256("100000000000000000000000000000000");
    uint256 third_res = coind::data::target_to_average_attempts(third);
    cout << third_res.GetHex() << endl;
    ASSERT_EQ(third_res.GetHex(), "00000000000000000000000000000000ffffffffffffffffffffffffffffffff");

    auto fourth = CreateUINT256("ffffffffffffffffffffffffffffffff");
    uint256 fourth_res = coind::data::target_to_average_attempts(fourth);
    cout << fourth_res.GetHex() << endl;
    ASSERT_EQ(fourth_res.GetHex(), "00000000000000000000000000000000ffffffffffffffffffffffffffffffff");
}

TEST(CoindDataTest, hash256_from_hash_link_test)
{
    uint32_t _init[8] {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05644c, 0x1f83d9ab, 0x5be0cd12};
    auto result = coind::data::hash256_from_hash_link(_init, (unsigned char*)"12345678901234ac", (unsigned char*) "12345678901234ac", 128/8);
    std::cout << result.GetHex() << std::endl;
    ASSERT_EQ(result.GetHex(), "209c335d5b5d3f5735d44b33ec1706091969060fddbdb26a080eb3569717fb9e");
}