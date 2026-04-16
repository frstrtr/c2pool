#pragma once

// PoW function types and built-in algorithm implementations.
// Each coin binds its CoinParams::pow_func to one of these.

#include "uint256.hpp"
#include "hash.hpp"
#include <btclibs/crypto/scrypt.h>

#include <cstring>
#include <functional>
#include <span>

namespace core
{

// PoW function: takes an 80-byte block header, returns the PoW hash.
// For most coins, this differs from the block identity hash (SHA256d).
using PowFunc = std::function<uint256(std::span<const unsigned char>)>;

// Block hash function: computes the block's identity hash (used for prev_block references).
// For Bitcoin-family coins this is always SHA256d, but kept separate for generality.
using BlockHashFunc = std::function<uint256(std::span<const unsigned char>)>;

// Subsidy function: given a block height, returns the block reward in satoshis.
using SubsidyFunc = std::function<uint64_t(uint32_t height)>;

// Donation script function: given a share version, returns the donation script bytes.
using DonationScriptFunc = std::function<std::vector<unsigned char>(int64_t share_version)>;

namespace pow
{

// SHA256d (Bitcoin): double SHA-256 of 80-byte header.
inline uint256 sha256d(std::span<const unsigned char> header)
{
    return Hash(header);
}

// Scrypt(1024,1,1,256) (Litecoin, Dogecoin): scrypt hash of 80-byte header.
inline uint256 scrypt(std::span<const unsigned char> header)
{
    char pow_hash_bytes[32];
    scrypt_1024_1_1_256(reinterpret_cast<const char*>(header.data()),
                        pow_hash_bytes);
    uint256 result;
    std::memcpy(result.begin(), pow_hash_bytes, 32);
    return result;
}

} // namespace pow
} // namespace core
