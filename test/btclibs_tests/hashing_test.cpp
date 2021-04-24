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

TEST(secp256k1TEST, HashTest)
{
    //string s = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    //string s = "fffffffffffffffffffffffffffffffffff22fffffffffffffffffffffffffff";
    string s = "1";
    uint256 first;
    first.SetHex(s);
    cout << first.GetHex() << endl;
    std::vector<unsigned char> vch(first.begin(), first.end());
    //std::vector<unsigned char> vch {1, 2, 3, 4};

    cout << "vch: ";
    for (auto &item : vch)
    {
        cout << (int)item << " ";
    }
    cout << "\n";

    auto _span = MakeUCharSpan(vch);

    cout << "_span: ";
    for (auto &item : _span)
    {
        cout << (int)item << " ";
    }
    cout << "\n";

    auto res = Hash(_span);

    cout << res.GetHex() << endl;

    //ASSERT_EQ(first.ToString(), s);
}

TEST(secp256k1TEST, Sha256Test)
{
    //string s = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    string s = "fffffffffffffffffffffffffffffffffff22fffffffffffffffffffffffffff";
    //string s = "1";
    uint256 first;
    first.SetHex("0x7b");
    //first.SetHex(s);
    cout << first.GetHex() << endl;
    for (auto &item : first)
    {
        cout << (int)item << " ";
    }
    cout << "\n";
    // std::vector<unsigned char> vch(first.begin(), first.end());
    // //std::vector<unsigned char> vch {1, 2, 3, 4};

    // cout <<"vch: ";
    // for (auto& item : vch){
    //     cout << (int)item << " ";
    // }
    // cout << "\n";

    // auto _span = MakeUCharSpan(vch);

    // cout <<"_span: ";
    // for (auto& item : _span){
    //     cout << (int)item << " ";
    // }
    // cout << "\n";

    unsigned char *data = new unsigned char[32]{123, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

    uint256 result;
    CSHA256().Write(data, 32).Finalize(result.begin());
    cout << "result " << result.GetHex() << endl;
    //CSHA256().Write(input.begin(), 32).Finalize(result.begin());

    auto res = SHA256Uint256(first);

    // auto res = Hash(_span);

    cout << res.GetHex() << endl;

    //ASSERT_EQ(first.ToString(), s);
}

TEST(secp256k1TEST, HashTest3)
{
    //string s = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    string s = "abc";
    //string s = "1";
    uint256 first;
    first.SetHex(s);
    cout << first.GetHex() << endl;
    std::vector<unsigned char> vch(first.begin(), first.end());
    //std::vector<unsigned char> vch {1, 2, 3, 4};

    cout << "vch: ";
    for (auto &item : vch)
    {
        cout << (int)item << " ";
    }
    cout << "\n";

    auto _span = MakeUCharSpan(vch);

    cout << "_span: ";
    for (auto &item : _span)
    {
        cout << (int)item << " ";
    }
    cout << "\n";

    //auto res = Hash(_span);
    std::vector<unsigned char> hash_result;
    hash_result.resize(_span.size());

    CHash256().Write(_span).Finalize(hash_result);

    uint256 res(hash_result);

    cout << res.GetHex() << endl;

    //ASSERT_EQ(first.ToString(), s);
}

TEST(secp256k1TEST, HashTest4)
{
    string s = "abc";

    vector<unsigned char> res;
    res.resize(32);
            //   Write((unsigned char*)&in[0], in.size())
    CSHA256().Write((unsigned char*)&s[0], s.size()).Finalize(&res[0]);

    uint256 result(res);
    
    cout << result.GetHex() << endl;
    for (auto r : res){
        cout << (int)r << " ";
    }
    cout << endl;
    //ASSERT_EQ(first.ToString(), s);
}

//------------------------

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

TEST(secp256k1TEST, HashTest5)
{
    auto res = TestSHA256("abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    uint256 uint_res(res);
    cout << uint_res.GetHex() << endl;
    cout << HexStr(res) << endl;

    uint256 uint_res2;
    uint_res.SetHex(HexStr(res));
    cout << uint_res.GetHex() << endl;
}