#pragma once

// Shared data for the UTXO snapshot / set-hash KATs.
//
// The expected hashes were computed by an independent reference, not by the
// code under test: a Python big-integer MuHash3072 (ChaCha20 written from RFC
// 8439, product mod 2^3072 - 1103717, checked against Core's crypto_tests
// vector 10d312b1...5863) and a straight transcription of
// kernel/coinstats.cpp ApplyHash for hash_serialized_2.

#include <core/coin/utxo.hpp>
#include <core/uint256.hpp>

#include <btclibs/crypto/sha256.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

#if !defined(_WIN32)
#include <unistd.h>
#endif

namespace utxo_kat {

using core::coin::Coin;
using core::coin::Outpoint;

inline std::vector<unsigned char> hex(const std::string& h)
{
    std::vector<unsigned char> out;
    for (size_t i = 0; i + 1 < h.size(); i += 2)
        out.push_back(static_cast<unsigned char>(std::stoi(h.substr(i, 2), nullptr, 16)));
    return out;
}

inline std::string to_hex(const unsigned char* p, size_t n)
{
    static const char* kHex = "0123456789abcdef";
    std::string out;
    for (size_t i = 0; i < n; ++i) {
        out.push_back(kHex[p[i] >> 4]);
        out.push_back(kHex[p[i] & 0x0f]);
    }
    return out;
}

inline std::string to_hex(const std::vector<unsigned char>& v) { return to_hex(v.data(), v.size()); }

inline std::array<unsigned char, 32> sha256_of(const std::string& s)
{
    std::array<unsigned char, 32> out{};
    CSHA256().Write(reinterpret_cast<const unsigned char*>(s.data()), s.size()).Finalize(out.data());
    return out;
}

inline uint256 hash_from_bytes(const unsigned char* p)
{
    uint256 h;
    std::memcpy(h.data(), p, 32);
    return h;
}

inline uint256 display_hash(const std::string& hex64)
{
    uint256 h;
    h.SetHex(hex64);
    return h;
}

struct KatCoin {
    Outpoint op;
    Coin coin;
};

// ── The synthetic set (mirrored in the Python reference) ────────────────────
// Five txids sha256("s1-kat-tx-<t>") with 1, 3, 300, 2, 1 outputs: a
// coinbase group, a 300-output group (vout > 255: UTXOViewDB's LE vout key
// does not sort numerically), a 300-byte raw script (CompactSize fd prefix),
// a zero-value coin and an empty script.
inline constexpr const char* kSynBestHex = "8a860e94f3d6b6e0b71824b1d32d91a798265bfc8ba5f9cf37653e0f2bc206ae";
inline constexpr const char* kSynMuhash = "8e6f6fd2666c16cc4c219d4b30f9ab67a44a07c2bfe2009b8164b6ce3efb6f30";
inline constexpr const char* kSynHashSer2 = "8a501bd6250e3975facb15f609d366a013e16553e81bcedbe0fb52289f26f7ee";
// Same set with every height + 1: hash_serialized_2 unchanged (the v23
// ApplyHash ternary folds the literal 1), muhash changes.
inline constexpr const char* kSynMuhashHeightsPlus1 = "b64822c0fad8b7b1fda1f9dd8f10c0f7c0ed3682aa921d31bc45697b660d7c67";
// Empty set at the same best block: SHA256d(best) and MuHash of the empty set.
inline constexpr const char* kEmptyHashSer2 = "a980537b626e2c2c66481892d8cf3186e9e7d5895ddf6dae76e5eb79f902d7c7";
inline constexpr const char* kEmptyMuhash = "dd5ad2a105c2d29495f577245c357409002329b9f4d6182c0af3dc2f462555c8";

inline uint256 syn_best()
{
    const auto b = sha256_of("s1-kat-best");
    return hash_from_bytes(b.data());
}

/// The set in key order (txid bytes, then vout ascending).
inline std::vector<KatCoin> synthetic_set(uint32_t height_delta = 0)
{
    const int counts[5] = {1, 3, 300, 2, 1};
    std::vector<KatCoin> out;
    for (int t = 0; t < 5; ++t) {
        const auto txid = sha256_of("s1-kat-tx-" + std::to_string(t));
        for (int n = 0; n < counts[t]; ++n) {
            KatCoin k;
            k.op = Outpoint(hash_from_bytes(txid.data()), static_cast<uint32_t>(n));
            k.coin.height = 1000 + t * 7 + n + height_delta;
            k.coin.coinbase = (t == 0);
            k.coin.value = (t == 3 && n == 1) ? 0 : n * 1000 + t + 1;
            if (t == 4) {
                // empty script
            } else if (t == 3 && n == 0) {
                k.coin.scriptPubKey.m_data.push_back(0x51);
                for (int i = 1; i < 300; ++i) k.coin.scriptPubKey.m_data.push_back(static_cast<unsigned char>(i % 251));
            } else {
                const auto h = sha256_of("s1-kat-spk-" + std::to_string(t) + "-" + std::to_string(n));
                auto& s = k.coin.scriptPubKey.m_data;
                s = {0x76, 0xa9, 0x14};
                s.insert(s.end(), h.begin(), h.begin() + 20);
                s.push_back(0x88);
                s.push_back(0xac);
            }
            out.push_back(std::move(k));
        }
    }
    std::sort(out.begin(), out.end(), [](const KatCoin& a, const KatCoin& b) {
        const int c = std::memcmp(a.op.txid.data(), b.op.txid.data(), 32);
        return c != 0 ? c < 0 : a.op.index < b.op.index;
    });
    return out;
}

// ── Three real coins: the first coins of dash-utxo-2564044.dat ──────────────
inline constexpr const char* kRealBaseHex = "000000000000000e2fb6aafce51366a10a8ec7db1d7a69640e3ba5d340a58a88";
inline constexpr const char* kRealCoinBytes[3] = {
    "000008879aa1eb4c85423c7e1939d8726721c147485858b891813803f647de270100000081b5ad6cb5f624003a3b7b6c89a099c64fbc24b2c1d9ceddcbffec54",
    "00000da7fd985ae002f4ac4246e2cf38fa177b1737420f164c3d1a2b3339246e01000000d8ba4cf7a7bb0100349678549f2d4c15196e72ddff587d0da93e8b61",
    "00001092c683c1e2d9819c34812b1d2af55796783c10eb143f5c07166d4528af00000000eacc50951b0065bc8282cf566e7c17caf069ecbfb414eba30429",
};
inline constexpr const char* kReal3Muhash = "433a169468303007efea47fe4b2ce5c36a80aa09fc792d804ef304207d61b007";
inline constexpr const char* kReal3HashSer2 = "12edbcad62b9598a8383e5854539844a63200a3c66d98998d07d5c6802c04bca";

/// metadata(base, count) followed by raw coin bytes.
inline std::vector<unsigned char> snapshot_bytes(const uint256& base, uint64_t count,
                                                 const std::vector<std::vector<unsigned char>>& coins)
{
    std::vector<unsigned char> out(base.data(), base.data() + 32);
    for (int i = 0; i < 8; ++i) out.push_back(static_cast<unsigned char>(count >> (8 * i)));
    for (const auto& c : coins) out.insert(out.end(), c.begin(), c.end());
    return out;
}

inline std::vector<unsigned char> real3_file_bytes()
{
    std::vector<std::vector<unsigned char>> coins;
    for (const char* c : kRealCoinBytes) coins.push_back(hex(c));
    return snapshot_bytes(display_hash(kRealBaseHex), 3, coins);
}

inline void write_file(const std::string& path, const std::vector<unsigned char>& bytes)
{
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    f.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
}

inline std::vector<unsigned char> read_file(const std::string& path)
{
    std::ifstream f(path, std::ios::binary);
    return std::vector<unsigned char>((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
}

inline std::string sha256_hex(const std::vector<unsigned char>& bytes)
{
    unsigned char out[32];
    CSHA256().Write(bytes.data(), bytes.size()).Finalize(out);
    return to_hex(out, 32);
}

/// A fresh directory under the temp dir, removed on destruction.
class TempDir {
public:
    explicit TempDir(const std::string& tag)
    {
        static std::atomic<int> counter{0};
#if defined(_WIN32)
        const long pid = 0;
#else
        const long pid = static_cast<long>(::getpid());
#endif
        m_path = (std::filesystem::temp_directory_path() /
                  ("c2pool-s1-" + tag + "-" + std::to_string(pid) + "-" + std::to_string(counter++)))
                     .string();
        std::filesystem::remove_all(m_path);
        std::filesystem::create_directories(m_path);
    }
    ~TempDir()
    {
        std::error_code ec;
        std::filesystem::remove_all(m_path, ec);
    }
    const std::string& path() const { return m_path; }
    std::string sub(const std::string& name) const { return (std::filesystem::path(m_path) / name).string(); }

private:
    std::string m_path;
};

} // namespace utxo_kat
