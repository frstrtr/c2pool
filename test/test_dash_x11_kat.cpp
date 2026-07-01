// Known-answer test for the DASH X11 PoW primitive (PR-0 foundation, S2 slice).
//
// Vector: the DASH mainnet genesis block. Hashing its 80-byte header with X11
// must reproduce the published genesis block hash. This pins the full
// BLAKE->BMW->...->ECHO pipeline (sph reference, dashcore v0.16.1.1) end to end.
//
// Header serialization is little-endian; the KAT targets Linux x86_64 CI, so the
// uint32 fields are memcpy-d directly (host is LE). uint256::data() already holds
// the internal (reversed-from-display) byte order, matching consensus header bytes.

#include <gtest/gtest.h>

#include <impl/dash/crypto/hash_x11.hpp>
#include <core/uint256.hpp>

#include <cstdint>
#include <cstring>
#include <cstdio>

#include <array>

namespace {

// DASH mainnet genesis constants (chainparams.cpp, CreateGenesisBlock).
constexpr uint32_t kVersion = 1;
constexpr uint32_t kTime    = 1390095618;     // 2014-01-19
constexpr uint32_t kBits    = 0x1e0ffff0;
constexpr uint32_t kNonce   = 28917698;
constexpr char     kMerkle[] =
    "e0028eb9648db56b1ac77cf090b99048a8007e2bb64b68f092c03c7f56a662c7";
constexpr char     kGenesisHash[] =
    "00000ffd590b1485b3caadc19b22e6379c733355108f107a430458cdf3407ab6";

void serialize_genesis_header(unsigned char out[80]) {
    uint256 prev_block;                 // genesis prevhash = 0
    std::memset(prev_block.data(), 0, 32);
    uint256 merkle_root;
    merkle_root.SetHex(kMerkle);

    size_t off = 0;
    std::memcpy(out + off, &kVersion, 4);            off += 4;
    std::memcpy(out + off, prev_block.data(), 32);   off += 32;
    std::memcpy(out + off, merkle_root.data(), 32);  off += 32;
    std::memcpy(out + off, &kTime, 4);               off += 4;
    std::memcpy(out + off, &kBits, 4);               off += 4;
    std::memcpy(out + off, &kNonce, 4);              off += 4;
}

} // namespace

TEST(DashX11Kat, GenesisHeaderReproducesGenesisHash) {
    unsigned char header[80];
    serialize_genesis_header(header);

    uint256 pow = dash::crypto::hash_x11(header, sizeof(header));
    EXPECT_EQ(pow.GetHex(), kGenesisHash);
}

TEST(DashX11Kat, Deterministic) {
    unsigned char header[80];
    serialize_genesis_header(header);
    EXPECT_EQ(dash::crypto::hash_x11(header, 80).GetHex(),
              dash::crypto::hash_x11(header, 80).GetHex());
}

// ── Real-node KAT: DASH testnet3 block #1497944 ─────────────────────────────
// Captured from a fully-synced testnet3 dashd (getblockheader RPC; blocks==
// headers, initialblockdownload=false). Hashing the real 80-byte header with
// X11 must reproduce the block hash the node reports. Unlike the static mainnet
// genesis above, this pins the pipeline against live-mined consensus data.
TEST(DashX11Kat, Testnet3Block1497944ReproducesBlockHash) {
    constexpr uint32_t version = 536870912u;
    constexpr uint32_t time    = 1781737170u;
    constexpr uint32_t bits    = 0x1e00f256u;
    constexpr uint32_t nonce   = 721236u;
    const char* prev_hex   = "000000dbbc08ee519459b38b02bb7754b455dd00cd74069a1352f08f0dd986db";
    const char* merkle_hex = "0464a4ac5f058a742f6aa42b2b3c7489abde7609b529612bcfa5da34b10bdb1b";
    const char* expected   = "000000b6a4e5ea1a0854ef83f0028dde5b96cdaacc604decd8b064d0cea38234";

    uint256 prev_block;  prev_block.SetHex(prev_hex);
    uint256 merkle_root; merkle_root.SetHex(merkle_hex);

    unsigned char header[80];
    size_t off = 0;
    std::memcpy(header + off, &version, 4);            off += 4;
    std::memcpy(header + off, prev_block.data(), 32);  off += 32;
    std::memcpy(header + off, merkle_root.data(), 32); off += 32;
    std::memcpy(header + off, &time, 4);               off += 4;
    std::memcpy(header + off, &bits, 4);               off += 4;
    std::memcpy(header + off, &nonce, 4);              off += 4;

    uint256 pow = dash::crypto::hash_x11(header, sizeof(header));
    EXPECT_EQ(pow.GetHex(), expected);
}


// -- Real-node byte-parity KATs: DASH testnet3 raw on-wire headers -----------
// Captured 2026-06-26 from a fully-synced testnet3 dashd (Dash Core 22.1.3;
// blocks==headers==1503386, initialblockdownload=false) on the testbed node
// (VMID 200) via:  dash-cli getblockheader <hash> false  -- the raw 80-byte
// serialized header hex exactly as it crosses the wire. Hashing each header with
// X11 must reproduce the block hash the node reports. Unlike the field-
// reconstructed vector above, these pin the pipeline against the precise
// consensus bytes the node relays (no host-side serialization assumptions).
namespace {

std::array<unsigned char, 80> header_from_hex(const char* hex) {
    std::array<unsigned char, 80> out{};
    for (size_t i = 0; i < out.size(); ++i) {
        unsigned int byte = 0;
        std::sscanf(hex + 2 * i, "%2x", &byte);
        out[i] = static_cast<unsigned char>(byte);
    }
    return out;
}

struct RealHeaderVector {
    int         height;
    const char* raw_header_hex;   // 160 hex chars == 80 serialized header bytes
    const char* expected_hash;    // node-reported block hash (display order)
};

// Dash Core 22.1.3, testnet3, captured 2026-06-26 @ tip 1503386.
constexpr RealHeaderVector kRealVectors[] = {
    {1503380,
     "00000020ed80a6115db295cfce0267973b57c99559ef153c8ee6d637230708b262000000"
     "d57690645314f8e6c928b0bb009e26b250599ec71049926aa6811e237e5a4aed818c3e6a"
     "f4c3001e38a10000",
     "000000b30a96f693930510ea6e0fde107ebe25816ad8caf2b4eb78593e193225"},
    {1502000,
     "00000020e2f154277cac71c02d220aac3a8270f79fb948c9c46b2311c13693888b000000"
     "69941a5ab8c7b4fea50ea0d7f9cf998a57a31ef3b6ea164eb226091364a72c6392913b6a"
     "9926011e95e70c00",
     "0000005a8905c97234e4fef4fc42b70bf0bdb9ccf80d1c00ade9269af39b82a6"},
    {1500000,
     "00000020f0f499182b0f199a5ed575408449f3da1daa5d05d8694a68f56da86f37000000"
     "45293808cc9d4b6be7de310c88ac5cd40fe1bbaee4425fce5459d68e1df1d07a9096376a"
     "28ca001ec60b0700",
     "000000b625f73fab6cb338c31cb656680ccfb3b574b9225022c8e90e293a0c12"},
    // Refresh captured 2026-06-28 from the same testnet3 dashd (Dash Core
    // 22.1.3) @ tip 1504350; extends coverage past the 2026-06-26 set.
    {1504350,
     "00000020b33f17f5247631f56f2360b85b5f4372c8cf9eab39030fe3f7f83890a9000000"
     "c3ad0d1ac042c96a9831e5a45311d0f65f50a188299acb8f1a05987baf1745fedc97406a"
     "f3c6001e02120000",
     "000000a2abf612a4a2f52576db68b0ce8b8922a74f6724e741816f4d9db481c3"},
    {1504000,
     "000000206ee35350ca86a16ab8b2f29bbc55f59681c7d4e31f921a889288faa612000000"
     "50e1a0fa17ae233cd327b771282632018539e59ab1729ef75d1e7ff38f068231c4db3f6a"
     "1bee001e629c0200",
     "00000031658286158413b93924acc273555520528b12ffce07849590ce72bbf0"},
    {1503000,
     "00000020e7ca3d0bfba302f7c0575b0b403a7390f8c7ecf56e6eab3029125b0485000000"
     "ef14eb268fe763717da40470f658d5944db22dd33004ac4c68cd1a4b8801c6c8fcbc3d6a"
     "58ed001e89b40800",
     "00000031a2ea207437d6c55b970371db3131bb4bdfdd18e62c12c1a2d26186df"},
};

} // namespace

TEST(DashX11Kat, Testnet3RawHeadersReproduceBlockHash) {
    for (const auto& v : kRealVectors) {
        const auto header = header_from_hex(v.raw_header_hex);
        const uint256 pow = dash::crypto::hash_x11(header.data(), header.size());
        EXPECT_EQ(pow.GetHex(), v.expected_hash)
            << "X11 byte-parity mismatch at testnet3 height " << v.height;
    }
}
