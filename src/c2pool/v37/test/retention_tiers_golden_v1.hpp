#pragma once
// Goldens for v37_retention_tiers_kat.cpp — v1.
//
// These are ABSOLUTE pins on the retention record log's ENCODING and on the
// root of a fixed promotion schedule. They are minted from this build and
// exist so that a later change to the leaf bytes, the domain tag, the field
// order or the MMR discipline cannot pass silently.
//
// A golden still carrying its @PLACEHOLDER@ is REPORTED AS A FAILURE by the
// KAT's pin() helper, never silently skipped.

#include <cstdint>

namespace rtg_v1 {

// ret_leaf_payload(RET_PIN, sender = b32_of(0x11,1), record_hash = b32_of(0x31,1),
//                  anchor_bin = 4096, bytes = 1024, price_mwu = 8192)
// == "V37R" || 0x01 || sender || record_hash || u64 LE || u32 LE || u64 LE
inline constexpr const char* PIN_LEAF_PAYLOAD_HEX =
    "56333752011112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f01"
    "3132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f01"
    "0010000000000000" "00040000" "0020000000000000";
inline constexpr const char* PIN_LEAF_HASH =
    "ae0374027bcb191764b09ff83740a7a36c2962669706430a7228aae073bf7cf2";

// The MMR root after the fixed five-promotion schedule in section A7:
//   PIN   (ALICE, RH1, 4096, 1024,  8192)
//   RENEW (ALICE, RH1, 4160, 1024,  8192)
//   HASH  (BOB,   RH2, 4224, 60000, 24576)
//   PIN   (BOB,   RH3, 4288, 2048,  16384)
//   HASH  (ALICE, RH4, 4352, 1,     24576)
inline constexpr const char* SCHEDULE_ROOT =
    "377269d5f32270ecab31276dd1372ed6146075d49534fbe63db08175e3302159";

} // namespace rtg_v1
