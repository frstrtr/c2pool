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
