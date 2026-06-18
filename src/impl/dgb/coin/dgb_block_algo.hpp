#pragma once
// ---------------------------------------------------------------------------
// DGB multi-algo block-version classifier  (M3 §7b — SCRYPT-ONLY VALIDATION).
//
// DigiByte is a multi-algo chain (Scrypt, SHA256d, Skein, Qubit, Odocrypt;
// legacy Groestl). The mining algorithm is encoded in 4 bits of the block
// nVersion field. c2pool-dgb (V36) validates the SCRYPT path ONLY:
//   - Scrypt header        -> full PoW validate          (DgbAlgo::SCRYPT)
//   - known non-Scrypt     -> accept-by-continuity        (work-neutral: it
//                             extends the header chain but contributes ZERO
//                             cumulative work / best-chain weight; see the
//                             THIRD INVARIANT note in coin/header_chain.hpp)
//   - unknown algo bits    -> reject                      (DgbAlgo::UNKNOWN)
// Full 5-algo PoW validation is V37 scope — do NOT add the other PoW lanes.
//
// SSOT: DigiByte Core src/primitives/block.h (ALGO_* + BLOCK_VERSION_* enums)
// and block.cpp CBlockHeader::GetAlgo(). The constants below are independent
// literals so this header is the single consensus pin for the algo decode;
// the standalone guard test (test/algo_select_test.cpp) asserts them against
// the upstream values and fails loudly on drift.
//
// CRITICAL: Scrypt == (0 << 8) — the masked algo bits are ZERO for a Scrypt
// block. A header is Scrypt iff (nVersion & DGB_BLOCK_VERSION_ALGO) == 0.
//
// Header-only: no OBJECT-lib / transport deps, so it links into the standalone
// CI guard (no dgb OBJECT lib, GTest-only) exactly like rpc_request.hpp.
// ---------------------------------------------------------------------------

#include <cstdint>

namespace dgb::coin {

// Algo id space — mirrors DigiByte Core's ALGO_* enum (block.h) verbatim,
// including ALGO_ODO == 7 (NOT 5) and ALGO_UNKNOWN == -1.
enum class DgbAlgo : int {
    UNKNOWN = -1,
    SHA256D = 0,
    SCRYPT  = 1,
    GROESTL = 2,
    SKEIN   = 3,
    QUBIT   = 4,
    ODO     = 7,
};

// Block-version algo field — DigiByte Core BLOCK_VERSION_* (block.h).
// Mask is the 4 bits at <<8; Scrypt is the all-zero codepoint.
static constexpr int32_t DGB_BLOCK_VERSION_ALGO    = (15 << 8); // 0x0F00 mask
static constexpr int32_t DGB_BLOCK_VERSION_SCRYPT  = ( 0 << 8); // 0x0000
static constexpr int32_t DGB_BLOCK_VERSION_SHA256D = ( 2 << 8); // 0x0200
static constexpr int32_t DGB_BLOCK_VERSION_GROESTL = ( 4 << 8); // 0x0400
static constexpr int32_t DGB_BLOCK_VERSION_SKEIN   = ( 6 << 8); // 0x0600
static constexpr int32_t DGB_BLOCK_VERSION_QUBIT   = ( 8 << 8); // 0x0800
static constexpr int32_t DGB_BLOCK_VERSION_ODO     = (14 << 8); // 0x0E00

// Decode the mining algo from a block nVersion field. Mirrors
// CBlockHeader::GetAlgo(): switch on the masked algo bits, default UNKNOWN.
inline DgbAlgo dgb_block_algo(int32_t n_version) noexcept
{
    switch (n_version & DGB_BLOCK_VERSION_ALGO)
    {
        case DGB_BLOCK_VERSION_SCRYPT:  return DgbAlgo::SCRYPT;
        case DGB_BLOCK_VERSION_SHA256D: return DgbAlgo::SHA256D;
        case DGB_BLOCK_VERSION_GROESTL: return DgbAlgo::GROESTL;
        case DGB_BLOCK_VERSION_SKEIN:   return DgbAlgo::SKEIN;
        case DGB_BLOCK_VERSION_QUBIT:   return DgbAlgo::QUBIT;
        case DGB_BLOCK_VERSION_ODO:     return DgbAlgo::ODO;
        default:                        return DgbAlgo::UNKNOWN;
    }
}

// V36 validation gate: is this header on the Scrypt PoW path?
inline bool is_scrypt_header(int32_t n_version) noexcept
{
    return (n_version & DGB_BLOCK_VERSION_ALGO) == DGB_BLOCK_VERSION_SCRYPT;
}

// Three-way V36 disposition of an incoming parent header by its algo bits.
enum class HeaderDisposition {
    VALIDATE_SCRYPT,        // Scrypt -> full PoW validate
    ACCEPT_BY_CONTINUITY,   // known non-Scrypt -> extend, work-neutral
    REJECT,                 // unknown algo bits -> reject
};

inline HeaderDisposition dgb_header_disposition(int32_t n_version) noexcept
{
    switch (dgb_block_algo(n_version))
    {
        case DgbAlgo::SCRYPT:  return HeaderDisposition::VALIDATE_SCRYPT;
        case DgbAlgo::UNKNOWN: return HeaderDisposition::REJECT;
        default:               return HeaderDisposition::ACCEPT_BY_CONTINUITY;
    }
}

} // namespace dgb::coin
