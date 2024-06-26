#include <gtest/gtest.h>
#include <iostream>
#include <memory>
#include <string>
#include <sstream>
#include <btclibs/uint256.h>
#include <btclibs/util/strencodings.h>
#include <libdevcore/random.h>
#include "common.h"

using namespace std;

TEST(Btclibs, UINT256_INIT)
{
    string s = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    uint256 first;
    first.SetHex(s);
    ASSERT_EQ(first.ToString(), s);

    string s2 = "0000000000000000000000000000000000000000000000000000000ffcffcffc";
    uint256 second(s2);
    ASSERT_EQ(second.ToString(), s2);

    auto vec = second.GetChars();
//    std::cout << "vec.size = " << vec.size() << "; sizeof(pn) = " << sizeof(second.pn) << std::endl;
    uint256 third(vec);
    ASSERT_EQ(third, second);
}

TEST(Btclibs, A_UINT256_ADD)
{
    uint256 first;
    first.SetHex("7fffffffffffffffffffffffffffffedcfffffffffffffffcddfffffffffffff");

    uint256 a_first;
    a_first = first;
    ASSERT_EQ(first.ToString(), a_first.ToString());

    uint256 a_second("8000000000000000000000000000001230000000000000003220000000000000");

    a_first += a_second;

    ASSERT_EQ(a_first.ToString(), "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
}

TEST(Btclibs, UINT256_COMPARE)
{
    uint256 first;
    first.SetHex("0");
    uint256 second;
    second.SetHex("1");

    ASSERT_EQ(first.CompareTo(second), -1);
    ASSERT_EQ(second.CompareTo(first), 1);

    first.SetHex("8000000000000000000000000000001230000000000000003220000000000000");
    second.SetHex("8000000000000000000000000000001230000000000000003220000000000000");

    ASSERT_EQ(first.CompareTo(second), 0);
    ASSERT_EQ(second.CompareTo(first), 0);
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
    ASSERT_EQ(first.ToString(), s);
    ASSERT_EQ(second.ToString(), s);
}

//---
TEST(Btclibs, UINT128_INIT)
{
    string s = "ffffffffffffffffffffffffffffffff";
    uint128 first;
    first.SetHex(s);

    ASSERT_EQ(first.ToString(), s);
}

TEST(Btclibs, UINT128_COMPARE)
{
    uint128 first;
    first.SetHex("0");
    uint128 second;
    second.SetHex("1");

    ASSERT_EQ(first.CompareTo(second), -1);
    ASSERT_EQ(second.CompareTo(first), 1);

    first.SetHex("80000000000322000000000000000000");
    second.SetHex("80000000000322000000000000000000");

    ASSERT_EQ(first.CompareTo(second), 0);
    ASSERT_EQ(second.CompareTo(first), 0);
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

TEST(Btclibs, UINT256_SERIALIZE_BYTES)
{
    string s = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
    uint256 first;
    first.SetHex(s);

    stringstream ss;
    ss << first;

    std::cout << ss.str().c_str() << std::endl;
    for (auto c : first.GetChars())
    {
        std::cout << (unsigned int)c << " ";
    }
    std::cout << std::endl;
//    std::cout << "max:" << UINT32_MAX << std::endl;

//    unsigned char *T = reinterpret_cast<unsigned char *>(&first);
//    for (int i = 0; i < sizeof(T) / sizeof(*T); i++)
//    {
//        cout << (unsigned int)T[i] << " ";
//    }
//    cout << endl;
}

TEST(Btclibs, UINT256_TO_UINT64)
{
    auto first = uint256S("10000000000000000");
    auto first64 = first.GetLow64();
    std::cout << first64 << std::endl;
    ASSERT_EQ(0, first64);

    auto second = uint256S("ffffffffffffffff");
    auto second64 = second.GetLow64();
    std::cout << second64 << std::endl;
    ASSERT_EQ(18446744073709551615, second64);

    auto third = uint256S("100000000fffffffe");
    auto third64 = third.GetLow64();
    std::cout << third64 << std::endl;
    ASSERT_EQ(4294967294, third64);
}

TEST(Btclibs, UINT256_SET_NULL)
{
    auto second = uint256S("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    std::cout << second.GetHex() << std::endl;
    ASSERT_EQ(second.GetHex(), "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    second.SetNull();
    ASSERT_TRUE(second.IsNull());
}

TEST(Btclibs, UINT256_CONVERT_TEST)
{
    uint288 s("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc");

    // old version
    std::vector<unsigned char> b;
    b.resize(32);

    for(int x=0; x<uint256::WIDTH_BYTES/4; ++x)
        WriteLE32(&b[0] + x*4, s.pn[x]);

    uint256 res1(b);

    std::cout << res1.GetHex() << std::endl;
    ASSERT_EQ(res1.GetHex(), "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc");

    // convert (new version)
    auto res2 = convert_uint<uint256>(s);
    std::cout << res2.GetHex() << std::endl;
    ASSERT_EQ(res2.GetHex(), "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc");
    ASSERT_EQ(res1, res2);
}

TEST(Btclibs, UINT256_CONVERT_TEST2)
{
    uint256 s("fffffffffffffffffffffffffffffffffffffffffffffffffffffffc");
    uint288 ss = s;
}

class segf_data
{
public:
    std::map<uint256, bool> data;

    ~segf_data()
    {
        std::cout << "deleted" << std::endl;
    }
};

TEST(Btclibs, UINT256_Compare_Segf)
{
    segf_data* d = new segf_data();
    d->data[uint256S("ff")];

    auto f = [&d](uint256 v){
        auto vv = std::move(v);
        if (d->data.find(v) != d->data.end())
        {
            std::cout << "ok" << std::endl;
        } 
    ;};
    delete d;
    auto v = uint256S("ff");
    f(v);
}

//int COMPARE(const uint256& a, const uint256& b)
//{
//    for (int i = a.WIDTH - 1; i >= 0; i--)
//    {
//        if (a.m_data[i] < b.m_data[i])
//            return -1;
//        if (a.m_data[i] > b.m_data[i])
//            return 1;
//    }
//    return 0;
//}
//
//TEST(Btclibst, SortUINT256)
//{
//    std::vector<int> _nums = {2,4,1,3,5,7,6};
//    std::sort(_nums.begin(), _nums.end());
//    for (auto v : _nums)
//    {
//        std::cout << v << " ";
//    }
//    std::cout << std::endl << std::endl;
//
//    std::vector<uint256> nums;
//    std::vector<arith_uint256> nums2;
//    std::vector<uint256> nums3;
//    const int test_size = 7;
//
//    for (int i = 0; i < test_size; i++)
//    {
//        auto num = uint256S(HexStr(c2pool::random::random_bytes(32)));
//        auto num2 = UintToArith256(num);
//
//        nums.push_back(num);
//        nums2.push_back(num2);
//        nums3.push_back(num);
//    }
//
//    std::sort(nums.begin(), nums.end());
//    std::sort(nums2.begin(), nums2.end());
//    std::sort(nums3.begin(), nums3.end(), [&](const auto& a, const auto& b){
//        return COMPARE(a, b) < 0;
//    });
//
//    for (int i = 0; i < test_size; i++)
//    {
//        std::cout << nums[i].GetHex() << "\t" << ArithToUint256(nums2[i]).GetHex() << std::endl;
//    }
//
//    std::cout << "nums3:\n";
//    for (int i = 0; i < test_size; i++)
//    {
//        std::cout << nums3[i].GetHex() << "\t" << ArithToUint256(nums2[i]).GetHex() << std::endl;
//    }
//}