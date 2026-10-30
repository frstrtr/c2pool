// KATs for the Dash Core v23.1.7 compressor / Coin codec port
// (src/core/coin/coin_compressor.{hpp,cpp}). The amount vectors are Core's
// src/test/compress_tests.cpp; the script cases cover all six special forms
// (Core's tests use random keys, here the generator G and -G stand in so
// both parities of an uncompressed key are pinned); the coin bytes are the
// first coin of a real dashd 23.1.7 `dumptxoutset` file (mainnet, base
// 000000000000000e2fb6aafce51366a10a8ec7db1d7a69640e3ba5d340a58a88).

#include <core/coin/coin_compressor.hpp>

#include <gtest/gtest.h>

#include <string>
#include <vector>

using namespace core::coin;

namespace {

constexpr uint64_t CENT = 1000000;
constexpr uint64_t COIN = 100000000;

std::vector<unsigned char> H(const std::string& hex)
{
    std::vector<unsigned char> out;
    for (size_t i = 0; i + 1 < hex.size(); i += 2)
        out.push_back(static_cast<unsigned char>(std::stoi(hex.substr(i, 2), nullptr, 16)));
    return out;
}

std::string X(const std::vector<unsigned char>& v)
{
    static const char* kHex = "0123456789abcdef";
    std::string out;
    for (unsigned char c : v) {
        out.push_back(kHex[c >> 4]);
        out.push_back(kHex[c & 0x0f]);
    }
    return out;
}

bool TestEncode(uint64_t in) { return in == DecompressAmount(CompressAmount(in)); }
bool TestDecode(uint64_t in) { return in == CompressAmount(DecompressAmount(in)); }
bool TestPair(uint64_t dec, uint64_t enc) { return CompressAmount(dec) == enc && DecompressAmount(enc) == dec; }

const std::string Gx = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const std::string Gy = "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8";   // even
const std::string nGy = "b7c52588d95c3b9aa25b0403f1eef75702e84bb7597aabe663b82f6f04ef2777";  // odd (-G)

/// Ser then Unser through ScriptCompression; returns the bytes Ser wrote.
std::vector<unsigned char> roundtrip_script(const std::vector<unsigned char>& script,
                                            std::vector<unsigned char>& back, CodecStatus& st)
{
    std::vector<unsigned char> ser;
    SerializeCompressedScript(ser, script);
    SpanStream s{ser.data(), ser.size()};
    back.clear();
    st = UnserializeCompressedScript(s, back);
    EXPECT_TRUE(s.eof());
    return ser;
}

} // namespace

TEST(CoinCompressor, AmountRoundTripCoreVectors)
{
    // compress_tests.cpp compress_amounts
    EXPECT_TRUE(TestPair(            0,       0x0));
    EXPECT_TRUE(TestPair(            1,       0x1));
    EXPECT_TRUE(TestPair(         CENT,       0x7));
    EXPECT_TRUE(TestPair(         COIN,       0x9));
    EXPECT_TRUE(TestPair(      50*COIN,      0x32));
    EXPECT_TRUE(TestPair(21000000*COIN, 0x1406f40));

    uint64_t bad = 0;
    for (uint64_t i = 1; i <= 100000; i++) bad += !TestEncode(i);
    for (uint64_t i = 1; i <= 10000; i++) bad += !TestEncode(i * CENT);
    for (uint64_t i = 1; i <= 10000; i++) bad += !TestEncode(i * COIN);
    for (uint64_t i = 1; i <= 420000; i++) bad += !TestEncode(i * 50 * COIN);
    for (uint64_t i = 0; i < 100000; i++) bad += !TestDecode(i);
    EXPECT_EQ(bad, 0u);
}

TEST(CoinCompressor, SixSpecialScriptsAndRaw)
{
    CompressedScript out;
    std::vector<unsigned char> back;
    CodecStatus st;

    // 0x00 P2PKH: 21 bytes, the hash160 copied.
    const auto p2pkh = H("76a914" "3a3b7b6c89a099c64fbc24b2c1d9ceddcbffec54" "88ac");
    ASSERT_TRUE(CompressScript(p2pkh, out));
    EXPECT_EQ(X(out), "00" "3a3b7b6c89a099c64fbc24b2c1d9ceddcbffec54");
    roundtrip_script(p2pkh, back, st);
    EXPECT_EQ(st, CodecStatus::ok);
    EXPECT_EQ(back, p2pkh);

    // 0x01 P2SH.
    const auto p2sh = H("a914" "b472a266d0bd89c13706a4132ccfb16f7c3b9fcb" "87");
    ASSERT_TRUE(CompressScript(p2sh, out));
    EXPECT_EQ(X(out), "01" "b472a266d0bd89c13706a4132ccfb16f7c3b9fcb");
    roundtrip_script(p2sh, back, st);
    EXPECT_EQ(back, p2sh);

    // 0x02 / 0x03 P2PK compressed: prefix kept, x copied, no curve check.
    const auto p2pk02 = H("21" "02" + Gx + "ac");
    ASSERT_TRUE(CompressScript(p2pk02, out));
    EXPECT_EQ(X(out), "02" + Gx);
    roundtrip_script(p2pk02, back, st);
    EXPECT_EQ(back, p2pk02);
    const auto p2pk03 = H("21" "03" + Gx + "ac");
    ASSERT_TRUE(CompressScript(p2pk03, out));
    EXPECT_EQ(X(out), "03" + Gx);
    roundtrip_script(p2pk03, back, st);
    EXPECT_EQ(back, p2pk03);

    // 0x04 / 0x05 P2PK uncompressed: 0x04 | parity of y, x copied; the
    // decompression recovers y through libsecp256k1.
    const auto p2pk_even = H("41" "04" + Gx + Gy + "ac");
    ASSERT_TRUE(CompressScript(p2pk_even, out));
    EXPECT_EQ(X(out), "04" + Gx);
    roundtrip_script(p2pk_even, back, st);
    EXPECT_EQ(st, CodecStatus::ok);
    EXPECT_EQ(back, p2pk_even);
    const auto p2pk_odd = H("41" "04" + Gx + nGy + "ac");
    ASSERT_TRUE(CompressScript(p2pk_odd, out));
    EXPECT_EQ(X(out), "05" + Gx);
    roundtrip_script(p2pk_odd, back, st);
    EXPECT_EQ(st, CodecStatus::ok);
    EXPECT_EQ(back, p2pk_odd);

    // An uncompressed key that is not on the curve is not compressible (IsFullyValid).
    auto off_curve = p2pk_even;
    off_curve[65] ^= 0x01;
    EXPECT_FALSE(CompressScript(off_curve, out));
    auto ser = roundtrip_script(off_curve, back, st);
    EXPECT_EQ(ser[0], 67 + nSpecialScripts);
    EXPECT_EQ(back, off_curve);

    // 0x04/0x05 whose x has no y (x = 5: 5^3+7 is a non-residue) fails as Core's
    // DecompressScript does; the reader reports it.
    for (unsigned char code : {0x04, 0x05}) {
        std::vector<unsigned char> bytes = {code};
        auto x5 = H("0000000000000000000000000000000000000000000000000000000000000005");
        bytes.insert(bytes.end(), x5.begin(), x5.end());
        SpanStream s{bytes.data(), bytes.size()};
        back.clear();
        EXPECT_EQ(UnserializeCompressedScript(s, back), CodecStatus::bad_pubkey);
    }

    // Raw scripts: VARINT(size + 6) then the bytes, up to MAX_SCRIPT_SIZE.
    const std::vector<unsigned char> empty;
    ser = roundtrip_script(empty, back, st);
    EXPECT_EQ(X(ser), "06");
    EXPECT_EQ(st, CodecStatus::ok);
    EXPECT_TRUE(back.empty());
    std::vector<unsigned char> big(MAX_SCRIPT_SIZE, 0x51);
    ser = roundtrip_script(big, back, st);
    EXPECT_EQ(X(std::vector<unsigned char>(ser.begin(), ser.begin() + 2)), "cd16");  // VARINT(10006)
    EXPECT_EQ(st, CodecStatus::ok);
    EXPECT_EQ(back, big);
    std::vector<unsigned char> too_big(MAX_SCRIPT_SIZE + 1, 0x51);
    ser = roundtrip_script(too_big, back, st);
    EXPECT_EQ(st, CodecStatus::oversized_script);
    EXPECT_EQ(X(back), "6a");
    EXPECT_TRUE(IsUnspendableScript(too_big));
    EXPECT_TRUE(IsUnspendableScript(H("6a0401020304")));
    EXPECT_FALSE(IsUnspendableScript(big));
    EXPECT_FALSE(IsUnspendableScript(empty));

    // Special sizes.
    EXPECT_EQ(GetSpecialScriptSize(0), 20u);
    EXPECT_EQ(GetSpecialScriptSize(1), 20u);
    for (unsigned n = 2; n <= 5; ++n) EXPECT_EQ(GetSpecialScriptSize(n), 32u);
    EXPECT_EQ(GetSpecialScriptSize(6), 0u);
}

TEST(CoinCompressor, VarIntMatchesCoreEncoding)
{
    // serialize.h WriteVarInt: the encodings the snapshot coin carries.
    struct V { uint64_t n; const char* hex; };
    const V vs[] = {{0, "00"}, {1, "01"}, {127, "7f"}, {128, "8000"}, {255, "807f"}, {256, "8100"},
                    {16383, "fe7f"}, {16384, "ff00"}, {16511, "ff7f"}, {65535, "82fe7f"},
                    {5085036, "81b5ad6c"}, {900004, "b5f624"}};
    for (const auto& v : vs) {
        std::vector<unsigned char> b;
        WriteVarInt(b, v.n);
        EXPECT_EQ(X(b), v.hex) << v.n;
        SpanStream s{b.data(), b.size()};
        uint64_t back = 0;
        EXPECT_EQ(ReadVarInt(s, back), CodecStatus::ok);
        EXPECT_EQ(back, v.n);
    }
    // Truncation and overflow (Core: "ReadVarInt(): size too large").
    {
        const auto b = H("80");
        SpanStream s{b.data(), b.size()};
        uint32_t v;
        EXPECT_EQ(ReadVarInt(s, v), CodecStatus::truncated);
    }
    {
        const auto b = H("8fffffff7f");  // > uint32 max
        SpanStream s{b.data(), b.size()};
        uint32_t v;
        EXPECT_EQ(ReadVarInt(s, v), CodecStatus::varint_overflow);
    }
}

TEST(CoinCompressor, CoinCodecCoreBytes)
{
    // Coin 0 of dash-utxo-2564044.dat (offset 40, after txid + vout):
    // code 81b5ad6c = 5085036 -> height 2542518, not coinbase;
    // amount b5f624 = 900004 -> 100001000 sat; script 00 + hash160 (P2PKH).
    const auto bytes = H("81b5ad6c" "b5f624" "00" "3a3b7b6c89a099c64fbc24b2c1d9ceddcbffec54");
    SpanStream s{bytes.data(), bytes.size()};
    Coin c;
    ASSERT_EQ(UnserializeCoreCoin(s, c), CodecStatus::ok);
    EXPECT_TRUE(s.eof());
    EXPECT_EQ(c.height, 2542518u);
    EXPECT_FALSE(c.coinbase);
    EXPECT_FALSE(c.pegout);
    EXPECT_EQ(c.value, 100001000);
    EXPECT_EQ(X(c.scriptPubKey.m_data), "76a9143a3b7b6c89a099c64fbc24b2c1d9ceddcbffec5488ac");

    std::vector<unsigned char> re;
    SerializeCoreCoin(re, c);
    EXPECT_EQ(re, bytes);

    // A coinbase coin with a raw script and a zero value.
    Coin cb(0, OPScript(), 1, true);
    cb.scriptPubKey.m_data = H("51");
    re.clear();
    SerializeCoreCoin(re, cb);
    EXPECT_EQ(X(re), "03" "00" "07" "51");
    SpanStream s2{re.data(), re.size()};
    Coin back;
    ASSERT_EQ(UnserializeCoreCoin(s2, back), CodecStatus::ok);
    EXPECT_TRUE(back.coinbase);
    EXPECT_EQ(back.height, 1u);
    EXPECT_EQ(back.value, 0);
    EXPECT_EQ(X(back.scriptPubKey.m_data), "51");

    // Every strict prefix is a truncation.
    for (size_t n = 0; n < bytes.size(); ++n) {
        SpanStream t{bytes.data(), n};
        Coin tc;
        EXPECT_EQ(UnserializeCoreCoin(t, tc), CodecStatus::truncated) << n;
    }
}
