#pragma once
// ---------------------------------------------------------------------------
// DGB+DOGE merged-mining (phase DB) — DGB-side AuxPoW coinbase-commitment
// builder.  Fenced / header-only — NOT yet wired into the live work-source /
// mint path (that is the follow-on DB slice).
//
// PURPOSE.  When DGB acts as the PARENT chain in a DGB+DOGE merged-mining
// arrangement, the DGB coinbase scriptSig must carry the canonical AuxPoW
// merged-mining commitment that binds the auxiliary (DOGE) blockchain merkle
// root.  This header is the single, fenced producer of that commitment blob.
//
// CANONICAL LAYOUT (mirrors the neutral c2pool producer
// c2pool/merged/merged_mining.cpp build_auxpow_commitment, and is consumed by
// the LTC verify path src/impl/ltc/share_check.hpp
// verify_merged_coinbase_commitment):
//
//     [4]   MM_MAGIC          = fa be 6d 6d   ("\xfa\xbe" + "mm")
//     [32]  aux_merkle_root   — the aux blockchain merkle root, serialized
//                               BIG-ENDIAN (reversed from the internal little-
//                               endian uint256 word order, byte 31 first)
//     [4]   merkle_size       — aux merkle-tree size, 4 bytes LITTLE-ENDIAN
//     [4]   merkle_nonce      — aux merkle nonce, 4 bytes LITTLE-ENDIAN
//     Total: 44 bytes.
//
// The big-endian root + LE size/nonce ordering is byte-identical to LTC: the
// LTC verifier reads the 32-byte root back big-endian (i = 31..0) and decodes
// size as p[0] | p[1]<<8 | p[2]<<16 | p[3]<<24 (little-endian).  Emitting in
// this exact order is what makes a DGB-as-parent coinbase verifiable by the
// existing aux/verify machinery without a single byte of divergence.
//
// ISOLATION.  Lives entirely under src/impl/dgb/.  Consumes only shared dgb/
// core types (core/uint256.hpp).  It includes NOTHING from the doge tree and
// modifies nothing in doge/ltc/core/bitcoin_family.  It is a pure value
// transform (root,size,nonce) -> bytes with no chain/tracker/run-loop deps and
// no AUX_DOGE-only dependency, so it compiles flag-agnostically in BOTH the
// default and the -DAUX_DOGE build arms.
//
// FENCED — NOT REWIRED.  No live caller invokes this yet; the mint/work-source
// path is untouched.  Wiring it into coinbase construction is the next DB
// slice, gated on operator/integrator tap.
// ---------------------------------------------------------------------------

#include <cstdint>
#include <vector>

#include <core/uint256.hpp>

namespace dgb {
namespace coin {

// MM merged-mining magic marker: 0xfa 0xbe 'm' 'm'  ("\xfa\xbe6d6d").
inline constexpr unsigned char AUX_MM_MAGIC[4] = {0xfa, 0xbe, 0x6d, 0x6d};

// Size in bytes of the canonical AuxPoW merged-mining commitment blob:
//   magic(4) + aux_merkle_root(32) + merkle_size(4) + merkle_nonce(4).
inline constexpr std::size_t AUX_MM_COMMITMENT_SIZE = 44;

// Build the canonical merged-mining coinbase commitment blob for a DGB-as-
// parent coinbase.  Byte-identical to the neutral producer
// build_auxpow_commitment and to the layout the LTC verifier decodes.
//
//   aux_merkle_root — auxiliary (DOGE) blockchain merkle root, emitted
//                     big-endian (byte 31 first).
//   merkle_size     — aux merkle-tree size, emitted 4 bytes little-endian.
//   merkle_nonce    — aux merkle nonce, emitted 4 bytes little-endian.
//
// Returns exactly AUX_MM_COMMITMENT_SIZE (44) bytes.
inline std::vector<unsigned char> build_aux_mm_commitment(
    const uint256& aux_merkle_root,
    uint32_t merkle_size,
    uint32_t merkle_nonce)
{
    std::vector<unsigned char> out;
    out.reserve(AUX_MM_COMMITMENT_SIZE);

    // [4] MM magic.
    out.push_back(AUX_MM_MAGIC[0]);
    out.push_back(AUX_MM_MAGIC[1]);
    out.push_back(AUX_MM_MAGIC[2]);
    out.push_back(AUX_MM_MAGIC[3]);

    // [32] aux merkle root — big-endian (reversed from internal LE byte order).
    const unsigned char* root =
        reinterpret_cast<const unsigned char*>(aux_merkle_root.pn);
    for (int i = 31; i >= 0; --i)
        out.push_back(root[i]);

    // [4] merkle size — little-endian.
    out.push_back(static_cast<unsigned char>(merkle_size & 0xFF));
    out.push_back(static_cast<unsigned char>((merkle_size >> 8) & 0xFF));
    out.push_back(static_cast<unsigned char>((merkle_size >> 16) & 0xFF));
    out.push_back(static_cast<unsigned char>((merkle_size >> 24) & 0xFF));

    // [4] merkle nonce — little-endian.
    out.push_back(static_cast<unsigned char>(merkle_nonce & 0xFF));
    out.push_back(static_cast<unsigned char>((merkle_nonce >> 8) & 0xFF));
    out.push_back(static_cast<unsigned char>((merkle_nonce >> 16) & 0xFF));
    out.push_back(static_cast<unsigned char>((merkle_nonce >> 24) & 0xFF));

    return out;
}

} // namespace coin
} // namespace dgb
