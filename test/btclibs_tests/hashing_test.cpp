#include <gtest/gtest.h>
#include <iostream>
#include <memory>
#include <string>
#include <sstream>
#include <vector>
#include <btclibs/uint256.h>
#include <btclibs/hash.h>
#include <btclibs/crypto/sha256.h>
#include <btclibs/crypto/ripemd160.h>
#include <btclibs/util/strencodings.h>
#include <btclibs/base58.h>
#include <btclibs/span.h>
using namespace std;

//method from bitcoin core
template <typename Hasher, typename In, typename Out>
static Out TestVector(const Hasher &h, const In &in, const Out &out)
{
    Out hash;
    GTEST_CHECK_(out.size() == h.OUTPUT_SIZE);
    hash.resize(out.size());
    {
        // Test that writing the whole input string at once works.
        Hasher(h).Write((unsigned char *)&in[0], in.size()).Finalize(&hash[0]);
        GTEST_CHECK_(hash == out);
    }

    return hash;
    // for (int i=0; i<32; i++) {
    //     // Test that writing the string broken up in random pieces works.
    //     Hasher hasher(h);
    //     size_t pos = 0;
    //     while (pos < in.size()) {
    //         size_t len = InsecureRandRange((in.size() - pos + 1) / 2 + 1);
    //         hasher.Write((unsigned char*)&in[pos], len);
    //         pos += len;
    //         if (pos > 0 && pos + 2 * out.size() > in.size() && pos < in.size()) {
    //             // Test that writing the rest at once to a copy of a hasher works.
    //             Hasher(hasher).Write((unsigned char*)&in[pos], in.size() - pos).Finalize(&hash[0]);
    //             GTEST_CHECK_(hash == out);
    //         }
    //     }
    //     hasher.Finalize(&hash[0]);
    //     GTEST_CHECK_(hash == out);
    // }
}

static vector<unsigned char> TestSHA256(const std::string &in, const std::string &hexout) { return TestVector(CSHA256(), in, ParseHex(hexout)); }

TEST(secp256k1TEST, HashTest)
{
    auto res = TestSHA256("abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    // uint256 uint_res(res);
    // cout << uint_res.GetHex() << endl;

    uint256 uint_res;
    // cout << HexStr(res) << endl;

    uint_res.SetHex(HexStr(res));
    // cout << uint_res.GetHex() << endl;

    ASSERT_EQ(uint_res.GetHex(), HexStr(res));
}

TEST(secp256k1TEST, Hash256Test)
{
    auto res = TestSHA256("abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    // uint256 uint_res(res);
    // cout << uint_res.GetHex() << endl;

    vector<unsigned char> out;
    uint256 out_res;
    out.resize(CSHA256::OUTPUT_SIZE);
    uint256 in;
    in.SetHex(HexStr(res));
    string in2 = in.GetHex(); //= "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    CSHA256().Write((unsigned char *)&in2[0], in2.size()).Finalize(&out[0]);
    out_res.SetHex(HexStr(out));

    uint256 uint_res;
    // cout << HexStr(res) << endl;

    uint_res.SetHex(HexStr(res));
    // cout << uint_res.GetHex() << endl;

    ASSERT_EQ(out_res.GetHex(), "dfe7a23fefeea519e9bbfdd1a6be94c4b2e4529dd6b7cbea83f9959c2621b13c");
}

#define print_decode_data(vch) \
    cout << "decoded data: ";  \
    for (auto v : vch)         \
    {                          \
        cout << v;             \
    }                          \
    cout << endl;

TEST(Base58TEST, Base58Encode_Decode)
{
    unsigned char *_data = new unsigned char[6];
    _data = (unsigned char *)"asd123";
    auto _span1 = Span<unsigned char>(_data, 6);
    auto encoded_span1 = EncodeBase58(_span1);
    // cout << encoded_span1 << endl;
    ASSERT_EQ(encoded_span1, "qXbwBTDc");

    vector<unsigned char> decode_data1;
    if (!DecodeBase58(encoded_span1, decode_data1, 64))
    {
        throw("error in decode1");
    }
    // print_decode_data(decode_data1);
    ASSERT_EQ(memcmp(_data, decode_data1.data(), 6), 0);
    //=============

    unsigned char *_data2 = new unsigned char[8];
    _data2 = (unsigned char *)"G0OD P1E";
    auto _span2 = Span<unsigned char>(_data2, 8);
    auto encoded_span2 = EncodeBase58(_span2);
    // cout << encoded_span2 << endl;
    ASSERT_EQ(encoded_span2, "CucwXUgr14Y");

    vector<unsigned char> decode_data2;
    if (!DecodeBase58(encoded_span2, decode_data2, 64))
    {
        throw("error in decode2");
    }
    // print_decode_data(decode_data2);
    ASSERT_EQ(memcmp(_data2, decode_data2.data(), 8), 0);
}

TEST(secp256k1TEST, Ripemd160Test)
{
    string data = "Hello world!";

    vector<unsigned char> out;
    out.resize(CRIPEMD160::OUTPUT_SIZE);

    CRIPEMD160().Write((unsigned char *)&data[0], data.length()).Finalize(&out[0]);

    uint160 result;
    result.SetHex(HexStr(out));
    cout << result.ToString() << endl;

    ASSERT_EQ("7f772647d88750add82d8e1a7a3e5c0902a346a3", result.ToString());
}

#undef print_decode_data