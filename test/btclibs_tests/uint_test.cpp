#include <gtest/gtest.h>
#include <iostream>
#include <memory>
#include <string>
#include <sstream>
#include <btclibs/uint256.h>
#include <btclibs/arith_uint256.h>
#include <util/pystruct.h>
using namespace std;

TEST(Btclibs, UINT256_INIT)
{
    string s = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    uint256 first;
    first.SetHex(s);

    ASSERT_EQ(first.ToString(), s);
}

TEST(Btclibs, A_UINT256_SUB)
{
    uint256 first;
    first.SetHex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");

    arith_uint256 a_first;

    a_first = UintToArith256(first);
    ASSERT_EQ(first.ToString(), a_first.ToString());

    arith_uint256 a_second("8000000000000000000000000000001230000000000000003220000000000000");

    a_first -= a_second;

    ASSERT_EQ(a_first.ToString(), "7fffffffffffffffffffffffffffffedcfffffffffffffffcddfffffffffffff");
}

TEST(Btclibs, A_UINT256_ADD)
{
    uint256 first;
    first.SetHex("7fffffffffffffffffffffffffffffedcfffffffffffffffcddfffffffffffff");

    arith_uint256 a_first;

    a_first = UintToArith256(first);
    ASSERT_EQ(first.ToString(), a_first.ToString());

    arith_uint256 a_second("8000000000000000000000000000001230000000000000003220000000000000");

    a_first += a_second;

    ASSERT_EQ(a_first.ToString(), "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
}

TEST(Btclibs, UINT256_COMPARE)
{
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

TEST(Btclibs, UINT128_COMPARE)
{
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

TEST(Btclibs, UINT256_SERIALIZE_BYTES)
{
    string s = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
    uint256 first;
    first.SetHex(s);

    stringstream ss;
    ss << first;

    std::cout << ss.str().c_str() << std::endl;
    for (auto c = first.begin(); c != first.end(); c++)
    {
        std::cout << (unsigned int)*c << " ";
    }
    std::cout << std::endl;
    std::cout << "max:" << UINT32_MAX << std::endl;

    unsigned char *T = reinterpret_cast<unsigned char *>(&first);
    for (int i = 0; i < sizeof(T) / sizeof(*T); i++)
    {
        cout << (unsigned int)T[i] << " ";
    }
    cout << endl;
}

// TEST(Btclibs, UINT256_SERIALIZE_BYTES_COMPARE_PYTHON)
// {
//     string s = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
//     uint256 first;
//     first.SetHex(s);

//     auto second = c2pool::python::for_test::PyType::IntType256_test(s);
//     unsigned char *second_unsig = (unsigned char *)second;
//     cout << "second: " << endl;
//     for (int c = 0; c <= strlen(second); c++)
//     {
//         std::cout << (unsigned int)second_unsig[c] << " ";
//     }
//     cout << endl;

//     cout << "first: " << endl;
//     for (auto c = first.begin(); c != first.end(); c++)
//     {
//         std::cout << (unsigned int)*c << " ";
//     }
//     std::cout << std::endl;

//     unsigned char *T = reinterpret_cast<unsigned char *>(&first);
//     for (int i = 0; i < std::distance(first.begin(), first.end()); i++)
//     {
//         cout << (unsigned int)T[i] << " ";
//     }
//     cout << endl;

//     auto packed_first = c2pool::SerializedData::pack(first);
//     for (int i = 0; i < packed_first.length; i++)
//     {
//         cout << (unsigned int)packed_first.data[i] << " ";
//     }
//     cout << endl;

//     auto unpacked_first = c2pool::SerializedData::unpack<uint256>(packed_first);
//     cout << unpacked_first->GetHex() << endl;
//     ASSERT_EQ(first, *unpacked_first);
// }

// #pragma pack(push, 1)
// struct TestUINT256Struct
// {
//     uint256 first;
//     uint256 second;
// };
// #pragma pack(pop)

// TEST(Btclibs, UINT256_SERIALIZE_STRUCT)
// {
//     unsigned char* python_packed = new unsigned char[64]{255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 15, 0, 0, 0, 0, 0, 0, 0, 252, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 0};

//     string f = "fffffffffffffffffffffffffffffffffffffffffffffffff";
//     uint256 first;
//     first.SetHex(f);

//     string s = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
//     uint256 second;
//     second.SetHex(s);

//     TestUINT256Struct _struct = {first, second};

//     auto packed_struct = c2pool::SerializedData::pack(_struct);

//     for (int i = 0; i < packed_struct.length; i++)
//     {
//         cout << (unsigned int)packed_struct.data[i] << " ";
//     }
//     cout << endl;

//     ASSERT_EQ(memcmp(packed_struct.data, python_packed, packed_struct.length), 0);
// }
