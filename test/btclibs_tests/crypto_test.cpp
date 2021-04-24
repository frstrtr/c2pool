// Copyright (c) 2014-2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <btclibs/crypto/hkdf_sha256_32.h>
#include <btclibs/crypto/hmac_sha256.h>
#include <btclibs/crypto/hmac_sha512.h>
#include <btclibs/crypto/poly1305.h>
#include <btclibs/crypto/ripemd160.h>
#include <btclibs/crypto/sha1.h>
#include <btclibs/crypto/sha256.h>
#include <btclibs/crypto/sha512.h>
//#include <random.h>
//#include <test/util/setup_common.h>
#include <btclibs/util/strencodings.h>

#include <vector>

#include <gtest/gtest.h>

//BOOST_FIXTURE_TEST_SUITE(crypto_tests, BasicTestingSetup)

template<typename Hasher, typename In, typename Out>
static void TestVector(const Hasher &h, const In &in, const Out &out) {
    Out hash;
    GTEST_CHECK_(out.size() == h.OUTPUT_SIZE);
    hash.resize(out.size());
    {
        // Test that writing the whole input string at once works.
        Hasher(h).Write((unsigned char*)&in[0], in.size()).Finalize(&hash[0]);
        GTEST_CHECK_(hash == out);
    }
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

static void TestSHA256(const std::string &in, const std::string &hexout) { TestVector(CSHA256(), in, ParseHex(hexout));}


static std::string LongTestString()
{
    std::string ret;
    for (int i = 0; i < 200000; i++) {
        ret += (char)(i);
        ret += (char)(i >> 4);
        ret += (char)(i >> 8);
        ret += (char)(i >> 12);
        ret += (char)(i >> 16);
    }
    return ret;
}

const std::string test1 = LongTestString();

TEST(sha256, testvectors) {
    TestSHA256("", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    TestSHA256("abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    TestSHA256("message digest",
               "f7846f55cf23e14eebeab5b4e1550cad5b509e3348fbc4efa3a1413d393cb650");
    TestSHA256("secure hash algorithm",
               "f30ceb2bb2829e79e4ca9753d35a8ecc00262d164cc077080295381cbd643f0d");
    TestSHA256("SHA256 is considered to be safe",
               "6819d915c73f4d1e77e4e1b52d1fa0f9cf9beaead3939f15874bd988e2a23630");
    TestSHA256("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
               "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
    TestSHA256("For this sample, this 63-byte string will be used as input data",
               "f08a78cbbaee082b052ae0708f32fa1e50c5c421aa772ba5dbb406a2ea6be342");
    TestSHA256("This is exactly 64 bytes long, not counting the terminating byte",
               "ab64eff7e88e2e46165e29f2bce41826bd4c7b3552f6b382a9e7d3af47c245f8");
    TestSHA256("As Bitcoin relies on 80 byte header hashes, we want to have an example for that.",
               "7406e8de7d6e4fffc573daef05aefb8806e7790f55eab5576f31349743cca743");
    TestSHA256(std::string(1000000, 'a'),
               "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
    TestSHA256(test1, "a316d55510b49662420f49d145d42fb83f31ef8dc016aa4e32df049991a91e26");
}
