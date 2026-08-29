// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// bch G2-ratchet C3 KAT -- donation script BYTE-CORRECTNESS across the
// pre-V36 (P2PK) <-> V36 (P2SH) flip. The only G2-ratchet failure mode that is
// SILENT and REWARD-LOSING: a wrong donation script pays the wrong destination
// with no gate error, so it is guarded by a pinned byte KAT here rather than by
// runtime checks.
//
// FENCED, additive, rig-free. Header-only over <core/donation.hpp>; touches NO
// gate logic and NO consensus surface (STOP+flag if this ever needs to edit
// bitcoin_family/ or src/core/*.hpp beyond reading the donation SSOT).
//
// WHAT IT PINS (SSOT = core::donation::get_donation_script):
//   * v<36 (BCH CURRENT MAINNET leg): 67-byte P2PK -- OP_PUSHBYTES_65
//     <uncompressed forrestv pubkey> OP_CHECKSIG. This is the script BCH pays
//     on real net today; it is NOT a copied LTC/DASH vector. A silent swap to a
//     different key/script fails the pubkey-identity check below.
//   * v>=36: 23-byte P2SH -- OP_HASH160 <hash160(1-of-2 redeem)> OP_EQUAL.
//   * The flip boundary is EXACTLY at version 36 (35->P2PK, 36->P2SH), no
//     off-by-one -- an off-by-one is the byte-offset-104 GENTX divergence class.
//   * GENTX=0 posture: at any single share version there is exactly ONE donation
//     script; author and verify both delegate to this SSOT, so a coinbase built
//     at version V and reconstructed at version V cannot diverge on the donation
//     output.
//
// MUST appear in BOTH src/impl/bch/test/CMakeLists.txt (BCH_ABLA_TESTS) AND the
// two build.yml COIN_BCH --target lists, or it becomes a #143-style NOT_BUILT
// sentinel that silently never runs.
// ---------------------------------------------------------------------------

#include <cstdint>
#include <iostream>
#include <vector>

#include <core/donation.hpp>

namespace {

using Bytes = std::vector<unsigned char>;

// KAT expected legs -- hard-coded, INDEPENDENT of the SSOT header, so an edit to
// core::donation that changes either script byte-for-byte fails here.

// v<36 -- BCH current-mainnet P2PK (forrestv uncompressed key).
const Bytes EXPECT_P2PK = {
    0x41,
    0x04, 0xff, 0xd0, 0x3d, 0xe4, 0x4a, 0x6e, 0x11,
    0xb9, 0x91, 0x7f, 0x3a, 0x29, 0xf9, 0x44, 0x32,
    0x83, 0xd9, 0x87, 0x1c, 0x9d, 0x74, 0x3e, 0xf3,
    0x0d, 0x5e, 0xdd, 0xcd, 0x37, 0x09, 0x4b, 0x64,
    0xd1, 0xb3, 0xd8, 0x09, 0x04, 0x96, 0xb5, 0x32,
    0x56, 0x78, 0x6b, 0xf5, 0xc8, 0x29, 0x32, 0xec,
    0x23, 0xc3, 0xb7, 0x4d, 0x9f, 0x05, 0xa6, 0xf9,
    0x5a, 0x8b, 0x55, 0x29, 0x35, 0x26, 0x56, 0x66,
    0x4b,
    0xac
};

// v>=36 -- combined 1-of-2 P2SH.
const Bytes EXPECT_P2SH = {
    0xa9,
    0x14,
    0x8c, 0x62, 0x72, 0x62, 0x1d, 0x89, 0xe8, 0xfa,
    0x52, 0x6d, 0xd8, 0x6a, 0xcf, 0xf6, 0x0c, 0x71,
    0x36, 0xbe, 0x8e, 0x85,
    0x87
};

int failures = 0;
void check(bool cond, const char* label)
{
    std::cout << (cond ? "  PASS  " : "  FAIL  ") << label << "\n";
    if (!cond) ++failures;
}

Bytes leg(int64_t v) { return core::donation::get_donation_script(v); }

} // namespace

int main()
{
    std::cout << "bch donation-flip C3 KAT (P2PK<->P2SH byte-correctness)\n";

    // --- leg shapes ---------------------------------------------------------
    check(leg(35) == EXPECT_P2PK, "v35 leg == 67-byte BCH current-mainnet P2PK (byte-exact)");
    check(leg(36) == EXPECT_P2SH, "v36 leg == 23-byte combined P2SH (byte-exact)");
    check(leg(35).size() == 67, "v35 P2PK length == 67");
    check(leg(36).size() == 23, "v36 P2SH length == 23");

    // --- opcode framing -----------------------------------------------------
    check(leg(35).front() == 0x41 && leg(35).back() == 0xac,
          "v35: OP_PUSHBYTES_65 ... OP_CHECKSIG framing");
    check(leg(36).front() == 0xa9 && leg(36)[1] == 0x14 && leg(36).back() == 0x87,
          "v36: OP_HASH160 PUSH20 ... OP_EQUAL framing");

    // --- BCH current-mainnet identity: guard against a silent LTC/DASH copy --
    // The forrestv pubkey prefix (0x04 0xff 0xd0 0x3d) is load-bearing: a
    // different donation key would pass all shape checks but pay the wrong dest.
    check(leg(35)[1] == 0x04 && leg(35)[2] == 0xff &&
          leg(35)[3] == 0xd0 && leg(35)[4] == 0x3d,
          "v35 pubkey is the BCH live forrestv key (not a copied LTC/DASH vector)");

    // --- flip boundary EXACTLY at 36 (no off-by-one) ------------------------
    check(leg(1)  == EXPECT_P2PK, "v1 -> P2PK");
    check(leg(34) == EXPECT_P2PK, "v34 -> P2PK");
    check(leg(35) == EXPECT_P2PK, "v35 -> P2PK (last pre-flip)");
    check(leg(36) == EXPECT_P2SH, "v36 -> P2SH (flip)");
    check(leg(37) == EXPECT_P2SH, "v37 -> P2SH");

    // --- GENTX=0: exactly one script per version, P2PK != P2SH --------------
    check(EXPECT_P2PK != EXPECT_P2SH, "the two legs are byte-distinct");
    check(leg(35) != leg(36), "author-at-v and verify-at-v share ONE donation script per version");

    if (failures == 0) {
        std::cout << "ALL PASS\n";
        return 0;
    }
    std::cout << failures << " FAIL\n";
    return 1;
}
