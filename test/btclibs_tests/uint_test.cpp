#include <gtest/gtest.h>
#include <iostream>
#include <memory>
#include <string>
#include <sstream>
#include "uint256.h"
#include "arith_uint256.h"
using namespace std;

TEST(Btclibs, UINT256_INIT)
{
    string s = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    uint256 first;
    first.SetHex(s);

    ASSERT_EQ(first.ToString(), s);
}

TEST(Btclibs, A_UINT256_SUB){
    uint256 first;
    first.SetHex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");

    arith_uint256 a_first;

    a_first = UintToArith256(first);
    ASSERT_EQ(first.ToString(), a_first.ToString());

    arith_uint256 a_second("8000000000000000000000000000001230000000000000003220000000000000");

    a_first -= a_second;

    ASSERT_EQ(a_first.ToString(), "7fffffffffffffffffffffffffffffedcfffffffffffffffcddfffffffffffff");
}

TEST(Btclibs, A_UINT256_ADD){
    uint256 first;
    first.SetHex("7fffffffffffffffffffffffffffffedcfffffffffffffffcddfffffffffffff");

    arith_uint256 a_first;

    a_first = UintToArith256(first);
    ASSERT_EQ(first.ToString(), a_first.ToString());

    arith_uint256 a_second("8000000000000000000000000000001230000000000000003220000000000000");

    a_first += a_second;

    ASSERT_EQ(a_first.ToString(), "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
}

TEST(Btclibs, UINT256_COMPARE){
    uint256 first;
    first.SetHex("0");
    uint256 second;
    second.SetHex("1");

    ASSERT_EQ(first.Compare(second), -1);
    ASSERT_EQ(second.Compare(first), 1);



    first.SetHex("8000000000000000000000000000001230000000000000003220000000000000");
    second.SetHex("8000000000000000000000000000001230000000000000003220000000000000");

    ASSERT_EQ(first.Compare(second), 0);
    ASSERT_EQ(second.Compare(first), 0);
}

TEST(Btclibs, UINT256_SERIALIZE)
{
    string s = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    uint256 first;
    first.SetHex(s);

    stringstream ss;
    ss << first;


    uint256 second;
    ss >> second;

    ASSERT_EQ(first.ToString(), second.ToString());
}

//---
TEST(Btclibs, UINT128_INIT)
{
    string s = "ffffffffffffffffffffffffffffffff";
    uint128 first;
    first.SetHex(s);

    ASSERT_EQ(first.ToString(), s);
}


TEST(Btclibs, UINT128_COMPARE){
    uint128 first;
    first.SetHex("0");
    uint128 second;
    second.SetHex("1");

    ASSERT_EQ(first.Compare(second), -1);
    ASSERT_EQ(second.Compare(first), 1);



    first.SetHex("80000000000322000000000000000000");
    second.SetHex("80000000000322000000000000000000");

    ASSERT_EQ(first.Compare(second), 0);
    ASSERT_EQ(second.Compare(first), 0);
}

TEST(Btclibs, UINT128_SERIALIZE)
{
    string s = "ffffffffffffffffffffffffffffffff";
    uint128 first;
    first.SetHex(s);

    stringstream ss;
    ss << first;


    uint128 second;
    ss >> second;

    ASSERT_EQ(first.ToString(), second.ToString());
}