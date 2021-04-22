#include <gtest/gtest.h>
#include <iostream>
#include <memory>
#include <string>
#include <sstream>
#include <btclibs/uint256.h>
using namespace std;

TEST(secp256k1TEST, UINT256_INIT)
{
    string s = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    uint256 first;
    first.SetHex(s);

    ASSERT_EQ(first.ToString(), s);
}