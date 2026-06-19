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
