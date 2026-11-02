// KATs for the Dash Core v23.1.7 MuHash3072 / ChaCha20 port
// (src/core/crypto/{muhash,chacha20}.{hpp,cpp}). Every vector below is
// Core's own: src/test/crypto_tests.cpp chacha20_testvector,
// chacha20_midblock and muhash_tests, at the tag recorded in
// src/core/crypto/VENDOR.md. Core's InsecureRand draws are replaced by a
// fixed-seed mt19937 (the properties checked do not depend on the draws).

#include <core/crypto/chacha20.hpp>
#include <core/crypto/muhash.hpp>

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstring>
#include <random>
#include <string>
#include <vector>

using core::crypto::ChaCha20;
using core::crypto::ChaCha20Aligned;
using core::crypto::MuHash3072;

namespace {

std::string hex_of(const unsigned char* p, size_t n)
{
    static const char* kHex = "0123456789abcdef";
    std::string out;
    for (size_t i = 0; i < n; ++i) {
        out.push_back(kHex[p[i] >> 4]);
        out.push_back(kHex[p[i] & 0x0f]);
    }
    return out;
}

std::vector<std::byte> hex_bytes(const std::string& hex)
{
    std::vector<std::byte> out;
    for (size_t i = 0; i + 1 < hex.size(); i += 2)
        out.push_back(static_cast<std::byte>(std::stoi(hex.substr(i, 2), nullptr, 16)));
    return out;
}

std::string to_hex(const std::vector<std::byte>& v)
{
    return hex_of(reinterpret_cast<const unsigned char*>(v.data()), v.size());
}

std::string hash_bytes_hex(const uint256& h)
{
    return hex_of(h.data(), 32);
}

struct ChaChaVector {
    const char* message;
    const char* key;
    ChaCha20::Nonce96 nonce;
    uint32_t seek;
    const char* out;
};

// crypto_tests.cpp chacha20_testvector, every TestChaCha20() call in order.
const ChaChaVector kChaChaVectors[] = {
    {"",
     "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
     {0x09000000, 0x4a000000}, 1,
     "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4ed2826446079faa0914c2d705d98b02a2"
         "b5129cd1de164eb9cbd083e8a2503c4e"},
    {"4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a20496620492063"
         "6f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73"
         "637265656e20776f756c642062652069742e",
     "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
     {0, 0x4a000000}, 1,
     "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0bf91b65c5524733ab8f593dabcd62b357"
         "1639d624e65152ab8f530c359f0861d807ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab7793736"
         "5af90bbf74a35be6b40b8eedf2785e42874d"},
    {"",
     "0000000000000000000000000000000000000000000000000000000000000000",
     {0, 0}, 0,
     "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7da41597c5157488d7724e03fb8d84a37"
         "6a43b8f41518a11cc387b669b2ee6586"},
    {"",
     "0000000000000000000000000000000000000000000000000000000000000000",
     {0, 0}, 1,
     "9f07e7be5551387a98ba977c732d080dcb0f29a048e3656912c6533e32ee7aed29b721769ce64e43d57133b074d839d5"
         "31ed1f28510afb45ace10a1f4b794d6f"},
    {"",
     "0000000000000000000000000000000000000000000000000000000000000001",
     {0, 0}, 1,
     "3aeb5224ecf849929b9d828db1ced4dd832025e8018b8160b82284f3c949aa5a8eca00bbb4a73bdad192b5c42f73f2fd"
         "4e273644c8b36125a64addeb006c13a0"},
    {"",
     "00ff000000000000000000000000000000000000000000000000000000000000",
     {0, 0}, 2,
     "72d54dfbf12ec44b362692df94137f328fea8da73990265ec1bbbea1ae9af0ca13b25aa26cb4a648cb9b9d1be65b2c09"
         "24a66c54d545ec1b7374f4872e99f096"},
    {"",
     "0000000000000000000000000000000000000000000000000000000000000000",
     {0, 0x200000000000000}, 0,
     "c2c64d378cd536374ae204b9ef933fcd1a8b2288b3dfa49672ab765b54ee27c78a970e0e955c14f3a88e741b97c286f7"
         "5f8fc299e8148362fa198a39531bed6d"},
    {"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
         "00000000000000000000000000000000",
     "0000000000000000000000000000000000000000000000000000000000000000",
     {0, 0}, 0,
     "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7da41597c5157488d7724e03fb8d84a37"
         "6a43b8f41518a11cc387b669b2ee6586"},
    {"416e79207375626d697373696f6e20746f20746865204945544620696e74656e6465642062792074686520436f6e7472"
         "696275746f7220666f72207075626c69636174696f6e20617320616c6c206f722070617274206f6620616e2049455446"
         "20496e7465726e65742d4472616674206f722052464320616e6420616e792073746174656d656e74206d616465207769"
         "7468696e2074686520636f6e74657874206f6620616e204945544620616374697669747920697320636f6e7369646572"
         "656420616e20224945544620436f6e747269627574696f6e222e20537563682073746174656d656e747320696e636c75"
         "6465206f72616c2073746174656d656e747320696e20494554462073657373696f6e732c2061732077656c6c20617320"
         "7772697474656e20616e6420656c656374726f6e696320636f6d6d756e69636174696f6e73206d61646520617420616e"
         "792074696d65206f7220706c6163652c207768696368206172652061646472657373656420746f",
     "0000000000000000000000000000000000000000000000000000000000000001",
     {0, 0x200000000000000}, 1,
     "a3fbf07df3fa2fde4f376ca23e82737041605d9f4f4f57bd8cff2c1d4b7955ec2a97948bd3722915c8f3d337f7d37005"
         "0e9e96d647b7c39f56e031ca5eb6250d4042e02785ececfa4b4bb5e8ead0440e20b6e8db09d881a7c6132f420e527950"
         "42bdfa7773d8a9051447b3291ce1411c680465552aa6c405b7764d5e87bea85ad00f8449ed8f72d0d662ab052691ca66"
         "424bc86d2df80ea41f43abf937d3259dc4b2d0dfb48a6c9139ddd7f76966e928e635553ba76c5c879d7b35d49eb2e62b"
         "0871cdac638939e25e8a1e0ef9d5280fa8ca328b351c3c765989cbcf3daa8b6ccc3aaf9f3979c92b3720fc88dc95ed84"
         "a1be059c6499b9fda236e7e818b04b0bc39c1e876b193bfe5569753f88128cc08aaa9b63d1a16f80ef2554d7189c411f"
         "5869ca52c5b83fa36ff216b9c1d30062bebcfd2dc5bce0911934fda79a86f6e698ced759c3ff9b6477338f3da4f9cd85"
         "14ea9982ccafb341b2384dd902f3d1ab7ac61dd29c6f21ba5b862f3730e37cfdc4fd806c22f221"},
    {"2754776173206272696c6c69672c20616e642074686520736c6974687920746f7665730a446964206779726520616e64"
         "2067696d626c6520696e2074686520776162653a0a416c6c206d696d737920776572652074686520626f726f676f7665"
         "732c0a416e6420746865206d6f6d65207261746873206f757467726162652e",
     "1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0",
     {0, 0x200000000000000}, 42,
     "62e6347f95ed87a45ffae7426f27a1df5fb69110044c0d73118effa95b01e5cf166d3df2d721caf9b21e5fb14c616871"
         "fd84c54f9d65b283196c7fe4f60553ebf39c6402c42234e32a356b3e764312a61a5532055716ead6962568f87d3f3f77"
         "04c6a8d1bcd1bf4d50d6154b6da731b187b58dfd728afa36757a797ac188d1"},
    {"",
     "0000000000000000000000000000000000000000000000000000000000000000",
     {0, 0}, 0,
     "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7"},
    {"",
     "0000000000000000000000000000000000000000000000000000000000000001",
     {0, 0x200000000000000}, 0,
     "ecfa254f845f647473d3cb140da9e87606cb33066c447b87bc2666dde3fbb739"},
    {"",
     "1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0",
     {0, 0x200000000000000}, 0,
     "965e3bc6f9ec7ed9560808f4d229f94b137ff275ca9b3fcbdd59deaad23310ae"},
    {"4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a20496620492063"
         "6f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73"
         "637265656e20776f756c642062652069742e",
     "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
     {0, 0x4a000000UL}, 1,
     "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0bf91b65c5524733ab8f593dabcd62b357"
         "1639d624e65152ab8f530c359f0861d807ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab7793736"
         "5af90bbf74a35be6b40b8eedf2785e42874d"},
    {"",
     "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
     {0, 0x4a000000UL}, 1,
     "224f51f3401bd9e12fde276fb8631ded8c131f823d2c06e27e4fcaec9ef3cf788a3b0aa372600a92b57974cded2b9334"
         "794cba40c63e34cdea212c4cf07d41b769a6749f3f630f4122cafe28ec4dc47e26d4346d70b98c73f3e9c53ac40c5945"
         "398b6eda1a832c89c167eacd901d7e2bf363"},
    {"",
     "0000000000000000000000000000000000000000000000000000000000000000",
     {0, 0}, 0,
     "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7da41597c5157488d7724e03fb8d84a37"
         "6a43b8f41518a11cc387b669b2ee6586"},
    {"",
     "0000000000000000000000000000000000000000000000000000000000000001",
     {0, 0}, 0,
     "4540f05a9f1fb296d7736e7b208e3c96eb4fe1834688d2604f450952ed432d41bbe2a0b6ea7566d2a5d1e7e20d42af2c"
         "53d792b1c43fea817e9ad275ae546963"},
    {"",
     "0000000000000000000000000000000000000000000000000000000000000000",
     {0, 0x0100000000000000ULL}, 0,
     "de9cba7bf3d69ef5e786dc63973f653a0b49e015adbff7134fcb7df137821031e85a050278a7084527214f73efc7fa5b"
         "5277062eb7a0433e445f41e3"},
    {"",
     "0000000000000000000000000000000000000000000000000000000000000000",
     {0, 1}, 0,
     "ef3fdfd6c61578fbf5cf35bd3dd33b8009631634d21e42ac33960bd138e50d32111e4caf237ee53ca8ad6426194a8854"
         "5ddc497a0b466e7d6bbdb0041b2f586b"},
    {"",
     "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
     {0, 0x0706050403020100ULL}, 0,
     "f798a189f195e66982105ffb640bb7757f579da31602fc93ec01ac56f85ac3c134a4547b733b46413042c94400491769"
         "05d3be59ea1c53f15916155c2be8241a38008b9a26bc35941e2444177c8ade6689de95264986d95889fb60e84629c9bd"
         "9a5acb1cc118be563eb9b3a4a472f82e09a7e778492b562ef7130e88dfe031c79db9d4f7c7a899151b9a475032b63fc3"
         "85245fe054e3dd5a97a5f576fe064025d3ce042c566ab2c507b138db853e3d6959660996546cc9c4a6eafdc777c040d7"
         "0eaf46f76dad3979e5c5360c3317166a1c894c94a371876a94df7628fe4eaaf2ccb27d5aaae0ad7ad0f9d4b6ad3b5409"
         "8746d4524d38407a6deb3ab78fab78c9"},
    {"",
     "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
     {0, 0xdeadbeef12345678}, 0xffffffff,
     "2d292c880513397b91221c3a647cfb0765a4815894715f411e3df5e0dd0ba9dffd565dea5addbdb914208fde7950f23e"
         "0385f9a727143f6a6ac51d84b1c0fb3e2e3b00b63d6841a1cc6d1538b1d3a74bef1eb2f54c7b7281e36e484dba89b351"
         "c8f572617e61e342879f211b0e4c515df50ea9d0771518fad96cd0baee62deb6"},
// ser_exp len 1536
// ss_max len 1536
};

// TestChaCha20(): one-shot, keystream XOR check, then 10 fragmented runs.
void run_chacha_vector(const ChaChaVector& v, std::mt19937& rng)
{
    const std::string hex_message = v.message;
    const std::string hexout = v.out;
    auto key = hex_bytes(v.key);
    ASSERT_EQ(key.size(), 32u);
    auto m = hex_bytes(hex_message);
    ChaCha20 c{key};
    c.Seek(v.nonce, v.seek);
    std::vector<std::byte> outres(hexout.size() / 2);
    ASSERT_TRUE(hex_message.empty() || m.size() * 2 == hexout.size());
    if (!hex_message.empty()) {
        c.Crypt(m, outres);
    } else {
        c.Keystream(outres);
    }
    EXPECT_EQ(hexout, to_hex(outres));
    if (!hex_message.empty()) {
        c.Seek(v.nonce, v.seek);
        std::vector<std::byte> only_keystream(outres.size());
        c.Keystream(only_keystream);
        for (size_t i = 0; i != m.size(); i++) outres[i] = m[i] ^ only_keystream[i];
        EXPECT_EQ(hexout, to_hex(outres));
    }
    // Repeat 10x, fragmented into 3 chunks, to exercise the ChaCha20 class's caching.
    for (int i = 0; i < 10; ++i) {
        const size_t total = hexout.size() / 2;
        size_t lens[3];
        lens[0] = std::uniform_int_distribution<size_t>(0, total)(rng);
        lens[1] = std::uniform_int_distribution<size_t>(0, total - lens[0])(rng);
        lens[2] = total - lens[0] - lens[1];
        c.Seek(v.nonce, v.seek);
        outres.assign(total, std::byte{0});
        size_t pos = 0;
        for (int j = 0; j < 3; ++j) {
            if (!hex_message.empty()) {
                c.Crypt(std::span<const std::byte>(m).subspan(pos, lens[j]),
                        std::span<std::byte>(outres).subspan(pos, lens[j]));
            } else {
                c.Keystream(std::span<std::byte>(outres).subspan(pos, lens[j]));
            }
            pos += lens[j];
        }
        EXPECT_EQ(hexout, to_hex(outres));
    }
}

MuHash3072 FromInt(unsigned char i)
{
    unsigned char tmp[32] = {i, 0};
    return MuHash3072(tmp);
}

} // namespace

TEST(ChaCha20, RFC7539Vectors)
{
    std::mt19937 rng(20261030);
    ASSERT_EQ(std::size(kChaChaVectors), 21u);
    for (const auto& v : kChaChaVectors) {
        SCOPED_TRACE(v.out);
        run_chacha_vector(v, rng);
    }
}

TEST(ChaCha20, MidBlock)
{
    // crypto_tests.cpp chacha20_midblock
    auto key = hex_bytes("0000000000000000000000000000000000000000000000000000000000000000");
    ChaCha20 c20{key};
    std::byte block[64];
    c20.Keystream(block);
    std::byte b1[5], b2[7], b3[52];
    c20 = ChaCha20{key};
    c20.Keystream(b1);
    c20.Keystream(b2);
    c20.Keystream(b3);
    EXPECT_TRUE(std::equal(b1, b1 + 5, block));
    EXPECT_TRUE(std::equal(b2, b2 + 7, block + 5));
    EXPECT_TRUE(std::equal(b3, b3 + 52, block + 12));
}

TEST(MuHash3072, CoreVectors)
{
    // crypto_tests.cpp muhash_tests
    std::mt19937 rng(2564044);
    uint256 out;
    for (int iter = 0; iter < 10; ++iter) {
        uint256 res;
        int table[4];
        for (int i = 0; i < 4; ++i) table[i] = static_cast<int>(rng() & 7);
        for (int order = 0; order < 4; ++order) {
            MuHash3072 acc;
            for (int i = 0; i < 4; ++i) {
                int t = table[i ^ order];
                if (t & 4) {
                    acc /= FromInt(t & 3);
                } else {
                    acc *= FromInt(t & 3);
                }
            }
            acc.Finalize(out);
            if (order == 0) {
                res = out;
            } else {
                EXPECT_EQ(res, out);
            }
        }

        MuHash3072 x = FromInt(static_cast<unsigned char>(rng() & 15)); // x=X
        MuHash3072 y = FromInt(static_cast<unsigned char>(rng() & 15)); // x=X, y=Y
        MuHash3072 z; // x=X, y=Y, z=1
        z *= x; // x=X, y=Y, z=X
        z *= y; // x=X, y=Y, z=X*Y
        y *= x; // x=X, y=Y*X, z=X*Y
        z /= y; // x=X, y=Y*X, z=1
        z.Finalize(out);

        uint256 out2;
        MuHash3072 a;
        a.Finalize(out2);
        EXPECT_EQ(out, out2);
    }

    MuHash3072 acc = FromInt(0);
    acc *= FromInt(1);
    acc /= FromInt(2);
    acc.Finalize(out);
    EXPECT_EQ(out.GetHex(), "10d312b100cbd32ada024a6646e40d3482fcff103668d2625f10002a607d5863");

    MuHash3072 acc2 = FromInt(0);
    unsigned char tmp[32] = {1, 0};
    acc2.Insert(tmp);
    unsigned char tmp2[32] = {2, 0};
    acc2.Remove(tmp2);
    acc2.Finalize(out);
    EXPECT_EQ(out.GetHex(), "10d312b100cbd32ada024a6646e40d3482fcff103668d2625f10002a607d5863");

    // Test MuHash3072 serialization
    MuHash3072 serchk = FromInt(1);
    serchk *= FromInt(2);
    const std::string ser_exp =
    "1fa093295ea30a6a3acdc7b3f770fa538eff537528e990e2910e40bbcfd7f6696b1256901929094694b56316de342f59"
        "3303dd12ac43e06dce1be1ff8301c845beb15468fff0ef002dbf80c29f26e6452bccc91b5cb9437ad410d2a67ea84788"
        "7fa3c6a6553309946880fe20db2c73fe0641adbd4e86edfee0d9f8cd0ee1230898873dc13ed8ddcaf045c80faa082774"
        "279007a2253f8922ee3ef361d378a6af3ddaf180b190ac97e556888c36b3d1fb1c85aab9ccd46e3deaeb7b7cf5db067a"
        "7e9ff86b658cf3acd6662bbcce37232daa753c48b794356c020090c831a8304416e2aa7ad633c0ddb2f11be1be316a81"
        "be7f7e472071c042cb68faef549c221ebff209273638b741aba5a81675c45a5fa92fea4ca821d7a324cb1e1a2ccd3b76"
        "c4228ec8066dad2a5df6e1bd0de45c7dd5de8070bdb46db6c554cf9aefc9b7b2bbf9f75b1864d9f95005314593905c01"
        "09b71f703d49944ae94477b51dac10a816bb6d1c700bafabc8bd86fac8df24be519a2f2836b16392e18036cb13e48c5c"
        "010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
    const auto ser = serchk.Serialize();
    EXPECT_EQ(ser_exp, hex_of(ser.data(), ser.size()));

    // Test MuHash3072 deserialization
    MuHash3072 deserchk = MuHash3072::Deserialize(ser);
    uint256 out3;
    serchk.Finalize(out);
    deserchk.Finalize(out3);
    EXPECT_EQ(hash_bytes_hex(out), hash_bytes_hex(out3));

    // Test MuHash3072 overflow, meaning the internal data is larger than the modulus.
    const std::string max_hex =
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        "010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
    const auto max_bytes = hex_bytes(max_hex);
    ASSERT_EQ(max_bytes.size(), MuHash3072::SERIALIZED_SIZE);
    std::array<unsigned char, MuHash3072::SERIALIZED_SIZE> max_arr{};
    std::memcpy(max_arr.data(), max_bytes.data(), max_arr.size());
    MuHash3072 overflowchk = MuHash3072::Deserialize(max_arr);
    uint256 out4;
    overflowchk.Finalize(out4);
    EXPECT_EQ(hash_bytes_hex(out4), "3a31e6903aff0de9f62f9a9f7f8b861de76ce2cda09822b90014319ae5dc2271");
}

TEST(MuHash3072, EmptySetAndIndependentReference)
{
    // The empty set finalizes to SHA256 of the 384-byte encoding of 1, and an
    // independent big-integer reference (Python: ChaCha20 per RFC 8439,
    // product mod 2^3072 - 1103717) agrees on a three-element set built in
    // two different orders.
    uint256 empty;
    MuHash3072().Finalize(empty);
    EXPECT_EQ(empty.GetHex(), "dd5ad2a105c2d29495f577245c357409002329b9f4d6182c0af3dc2f462555c8");

    MuHash3072 a, b;
    unsigned char e0[32] = {0}, e1[32] = {1}, e2[32] = {2};
    a.Insert(e0).Insert(e1);
    a.Remove(e2);
    b.Remove(e2);
    b.Insert(e1).Insert(e0);
    uint256 ha, hb;
    a.Finalize(ha);
    b.Finalize(hb);
    EXPECT_EQ(ha.GetHex(), "10d312b100cbd32ada024a6646e40d3482fcff103668d2625f10002a607d5863");
    EXPECT_EQ(ha, hb);
}
