// ---------------------------------------------------------------------------
// dgb M3 §7b multi-algo version classifier regression guard.
//
// Pins the DigiByte block-version -> algo decode that the Scrypt-only header
// validation path relies on (coin/dgb_block_algo.hpp). The decode is
// consensus-critical: misclassifying a non-Scrypt header as Scrypt would feed
// it into the Scrypt PoW lane (a divergence), and misclassifying a Scrypt
// header as continuity would silently drop real parent work. The CRITICAL
// trap is that Scrypt == (0 << 8): the masked algo bits are ZERO, so a naive
// "nonzero == has-algo" check is wrong.
//
// Independent literals (taken from DigiByte Core src/primitives/block.h) so
// this fails loudly if the SSOT header is ever edited. Links ONLY the
// header-only classifier + gtest -- no dgb OBJECT lib / transport.
// ---------------------------------------------------------------------------

#include <cstdint>

#include <gtest/gtest.h>

#include <impl/dgb/coin/dgb_block_algo.hpp>

using namespace dgb::coin;

// Real DGB chain uses low primary versions OR'd with the algo bits. Build the
// nVersion the way a miner does: primary (e.g. 2) | algo codepoint.
static constexpr int32_t PRIMARY = 2; // BLOCK_VERSION_DEFAULT

TEST(DgbAlgoSelect, ScryptIsZeroAlgoBits)
{
    // Scrypt block: algo bits all zero.
    EXPECT_EQ(dgb_block_algo(PRIMARY | DGB_BLOCK_VERSION_SCRYPT), DgbAlgo::SCRYPT);
    EXPECT_TRUE(is_scrypt_header(PRIMARY | DGB_BLOCK_VERSION_SCRYPT));
    // A bare primary version (no algo bits) is therefore Scrypt too.
    EXPECT_TRUE(is_scrypt_header(PRIMARY));
}

TEST(DgbAlgoSelect, KnownNonScryptDecodes)
{
    EXPECT_EQ(dgb_block_algo(PRIMARY | DGB_BLOCK_VERSION_SHA256D), DgbAlgo::SHA256D);
    EXPECT_EQ(dgb_block_algo(PRIMARY | DGB_BLOCK_VERSION_GROESTL), DgbAlgo::GROESTL);
    EXPECT_EQ(dgb_block_algo(PRIMARY | DGB_BLOCK_VERSION_SKEIN),   DgbAlgo::SKEIN);
    EXPECT_EQ(dgb_block_algo(PRIMARY | DGB_BLOCK_VERSION_QUBIT),   DgbAlgo::QUBIT);
    EXPECT_EQ(dgb_block_algo(PRIMARY | DGB_BLOCK_VERSION_ODO),     DgbAlgo::ODO);
    // None of them are on the Scrypt path.
    EXPECT_FALSE(is_scrypt_header(PRIMARY | DGB_BLOCK_VERSION_SHA256D));
    EXPECT_FALSE(is_scrypt_header(PRIMARY | DGB_BLOCK_VERSION_ODO));
}

TEST(DgbAlgoSelect, OdoIdIsSevenNotFive)
{
    // Guard the upstream quirk: ALGO_ODO == 7, not a dense 5.
    EXPECT_EQ(static_cast<int>(DgbAlgo::ODO), 7);
}

TEST(DgbAlgoSelect, UnknownAlgoBitsReject)
{
    // 10<<8 and 12<<8 are reserved/commented-out (Equihash/Ethash) in Core:
    // they must decode to UNKNOWN and be rejected, not silently continued.
    EXPECT_EQ(dgb_block_algo(PRIMARY | (10 << 8)), DgbAlgo::UNKNOWN);
    EXPECT_EQ(dgb_block_algo(PRIMARY | (12 << 8)), DgbAlgo::UNKNOWN);
    EXPECT_EQ(dgb_header_disposition(PRIMARY | (10 << 8)), HeaderDisposition::REJECT);
}

TEST(DgbAlgoSelect, MaskIgnoresHighAndLowBits)
{
    // Algo decode must mask exactly the 4 bits at <<8 -- high version bits
    // (BIP9 signalling, e.g. 0x20000000) and low primary bits must not leak.
    const int32_t bip9 = 0x20000000;
    EXPECT_EQ(dgb_block_algo(bip9 | DGB_BLOCK_VERSION_SCRYPT), DgbAlgo::SCRYPT);
    EXPECT_EQ(dgb_block_algo(bip9 | DGB_BLOCK_VERSION_QUBIT),  DgbAlgo::QUBIT);
    EXPECT_TRUE(is_scrypt_header(bip9 | 0x000000FF)); // low byte set, algo still 0
}

TEST(DgbAlgoSelect, DispositionThreeWay)
{
    EXPECT_EQ(dgb_header_disposition(PRIMARY | DGB_BLOCK_VERSION_SCRYPT),
              HeaderDisposition::VALIDATE_SCRYPT);
    EXPECT_EQ(dgb_header_disposition(PRIMARY | DGB_BLOCK_VERSION_SKEIN),
              HeaderDisposition::ACCEPT_BY_CONTINUITY);
    EXPECT_EQ(dgb_header_disposition(PRIMARY | (10 << 8)),
              HeaderDisposition::REJECT);
}

// V36 multi-algo posture: the FOUR known non-Scrypt PoW lanes (SHA256d, Skein,
// Qubit, Odo) and the legacy Groestl lane are all ACCEPT_BY_CONTINUITY -- never
// validated (would feed a non-Scrypt header into the Scrypt PoW lane) and never
// rejected (would drop real parent work and fork off the DGB chain). The
// classifier reaches this via the switch `default:`, so a future explicit
// `case DgbAlgo::QUBIT: return REJECT;` style regression must fail HERE.
// Full 5-algo PoW validation is V37 scope; in V36 every non-Scrypt known algo
// extends the chain work-neutrally. (DigiByte Core src/primitives/block.h.)
TEST(DgbAlgoSelect, AllKnownNonScryptAlgosAreContinuity)
{
    EXPECT_EQ(dgb_header_disposition(PRIMARY | DGB_BLOCK_VERSION_SHA256D),
              HeaderDisposition::ACCEPT_BY_CONTINUITY);
    EXPECT_EQ(dgb_header_disposition(PRIMARY | DGB_BLOCK_VERSION_GROESTL),
              HeaderDisposition::ACCEPT_BY_CONTINUITY);
    EXPECT_EQ(dgb_header_disposition(PRIMARY | DGB_BLOCK_VERSION_SKEIN),
              HeaderDisposition::ACCEPT_BY_CONTINUITY);
    EXPECT_EQ(dgb_header_disposition(PRIMARY | DGB_BLOCK_VERSION_QUBIT),
              HeaderDisposition::ACCEPT_BY_CONTINUITY);
    EXPECT_EQ(dgb_header_disposition(PRIMARY | DGB_BLOCK_VERSION_ODO),
              HeaderDisposition::ACCEPT_BY_CONTINUITY);
}
