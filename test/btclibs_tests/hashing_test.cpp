#include <gtest/gtest.h>
#include <iostream>
#include <memory>
#include <string>
#include <sstream>
#include <vector>
#include <btclibs/uint256.h>
#include <btclibs/hash.h>
#include <btclibs/crypto/sha256.h>
#include <btclibs/util/strencodings.h>
using namespace std;

//method from bitcoin core
template<typename Hasher, typename In, typename Out>
static Out TestVector(const Hasher &h, const In &in, const Out &out) {
    Out hash;
    GTEST_CHECK_(out.size() == h.OUTPUT_SIZE);
    hash.resize(out.size());
    {
        // Test that writing the whole input string at once works.
        Hasher(h).Write((unsigned char*)&in[0], in.size()).Finalize(&hash[0]);
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

static vector<unsigned char> TestSHA256(const std::string &in, const std::string &hexout) { return TestVector(CSHA256(), in, ParseHex(hexout));}

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
    CSHA256().Write((unsigned char*)&in2[0], in2.size()).Finalize(&out[0]);
    out_res.SetHex(HexStr(out));

    uint256 uint_res;
    // cout << HexStr(res) << endl;

    uint_res.SetHex(HexStr(res));
    // cout << uint_res.GetHex() << endl;

    ASSERT_EQ(out_res.GetHex(), "dfe7a23fefeea519e9bbfdd1a6be94c4b2e4529dd6b7cbea83f9959c2621b13c");


}