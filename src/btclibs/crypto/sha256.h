// Copyright (c) 2014-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CRYPTO_SHA256_H
#define BITCOIN_CRYPTO_SHA256_H

#include <stdint.h>
#include <stdlib.h>
#include <string>
#include <vector>

/** A hasher class for SHA-256. */
class CSHA256
{
public:
    uint32_t s[8];
    unsigned char buf[64];
    uint64_t bytes;

public:
    static const size_t OUTPUT_SIZE = 32;

    CSHA256();
    CSHA256(uint32_t* custom_init, std::vector<unsigned char> _buf = {}, uint64_t _length = 0);
    CSHA256& Write(const unsigned char* data, size_t len);
    void Finalize(unsigned char hash[OUTPUT_SIZE]);
    // NOT the digest: copies the eight internal state words in host byte
    // order (each 4-byte group reversed on little-endian), without the
    // big-endian write Finalize(unsigned char*) does. A c2pool core uint256's
    // begin() is a uint32_t*, so Finalize(x.begin()) silently lands here; use
    // Finalize(x.data()) for a digest (the #968a BIP 152 short-id bug).
    void Finalize(uint32_t hash[OUTPUT_SIZE / 4]);
    CSHA256& Reset();
};

/** Which optimized implementations SHA256AutoDetect may select (Bitcoin
 *  Core's sha256_implementation mask). AVX2 and SHA-NI are probed only when
 *  USE_SSE4 is set too, as in Core.
 */
namespace sha256_implementation {
enum UseImplementation : uint8_t {
    STANDARD = 0,
    USE_SSE4 = 1 << 0,
    USE_AVX2 = 1 << 1,
    USE_SHANI = 1 << 2,
    USE_SSE4_AND_AVX2 = USE_SSE4 | USE_AVX2,
    USE_SSE4_AND_SHANI = USE_SSE4 | USE_SHANI,
    USE_ALL = USE_SSE4 | USE_AVX2 | USE_SHANI,
};
}

/** Autodetect the best available SHA256 implementation among those
 *  use_implementation allows, and install it. Each call starts from the
 *  scalar implementation, so SHA256AutoDetect(sha256_implementation::STANDARD)
 *  puts the scalar implementation back.
 *  Returns the name of the implementation.
 *  Writes plain global function pointers: call it before any thread hashes.
 *  It does not self-test; run SHA256SelfTest() after it (core::init_sha256).
 */
std::string SHA256AutoDetect(sha256_implementation::UseImplementation use_implementation = sha256_implementation::USE_ALL);

/** Known-answer test of the implementation installed now: Transform for 0..8
 *  blocks, TransformD64 and every D64 width that is installed. Not compiled
 *  out under NDEBUG. */
bool SHA256SelfTest();

/** Compute multiple double-SHA256's of 64-byte blobs.
 *  output:  pointer to a blocks*32 byte output buffer
 *  input:   pointer to a blocks*64 byte input buffer
 *  blocks:  the number of hashes to compute.
 */
void SHA256D64(unsigned char* output, const unsigned char* input, size_t blocks);

#endif // BITCOIN_CRYPTO_SHA256_H
