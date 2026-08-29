// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once
// ---------------------------------------------------------------------------
// DGB-Scrypt proof-of-work digest CALL  (M3 §7b / Stage 4b-4c work-gen).
//
// The satisfaction gate in coin/header_chain.hpp compares HeaderSample::pow_hash
// (a coin/dgb_arith256.hpp u256) against the SetCompact target -- hash <= target.
// dgb_arith256.hpp::u256::from_le_bytes already documents the decode convention
// (the scrypt output is read little-endian, mirroring bitcoin UintToArith256),
// and ends: "the scrypt CALL itself lands at the ingest boundary in a following
// slice." THIS header is that call: the single place the DGB-Scrypt algo hash is
// computed, so the embedded work-gen (nonce grinder) and the ingest boundary
// share ONE digest SSOT and can never disagree on byte order.
//
// V36 is Scrypt-ONLY (project_v36_dgb_scrypt_only): this is the ONLY PoW digest
// DGB validates. The other four DGB algos (SHA256d/Skein/Qubit/Odocrypt) are
// accept-by-continuity and never reach this function.
//
// scrypt_1024_1_1_256 is the canonical pooler/ArtForz Scrypt(N=1024,r=1,p=1)
// from btclibs (src/btclibs/crypto/scrypt.*), the SAME routine DigiByte Core /
// Litecoin Core use for the Scrypt algo. It links transitively here via
// core -> btclibs (target_link_libraries(core PUBLIC ... btclibs)).
// ---------------------------------------------------------------------------

#include <array>
#include <cstdint>

#include <btclibs/crypto/scrypt.h>   // scrypt_1024_1_1_256
#include <impl/dgb/coin/dgb_arith256.hpp>  // dgb::coin::u256

namespace dgb::coin {

// scrypt_1024_1_1_256 over the 80-byte serialized block header -> pow_hash u256.
// The 32-byte digest is decoded little-endian (from_le_bytes) so the result
// drops straight into the header_chain satisfaction gate with no reshape.
inline u256 scrypt_pow_hash(const unsigned char header80[80]) {
    char digest[32];
    scrypt_1024_1_1_256(reinterpret_cast<const char*>(header80), digest);
    return u256::from_le_bytes(reinterpret_cast<const unsigned char*>(digest));
}

// std::array convenience overload (the form the reconstructed-header builder and
// the nonce grinder carry the 80 header bytes in).
inline u256 scrypt_pow_hash(const std::array<unsigned char, 80>& header80) {
    return scrypt_pow_hash(header80.data());
}

}  // namespace dgb::coin