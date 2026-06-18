// ---------------------------------------------------------------------------
// dgb M3 §7b DigiShield Scrypt-only ancestor-walk regression guard.
//
// Pins the consensus quirk flagged at coin/header_chain.hpp's DIGISHIELD
// INSERTION POINT: on a mixed-algo DGB chain the Scrypt difficulty window must
// walk SCRYPT ancestors ONLY and SKIP continuity (non-Scrypt) headers. Folding
// a continuity header into the window corrupts the Scrypt retarget and breaks
// work-neutrality (THIRD INVARIANT). Also pins header_credits_work() == the
// Scrypt predicate, so the validate() work-accounting and the retarget walk
// share one SSOT and cannot drift apart.
//
// Links ONLY the header-only helpers + gtest -- no dgb OBJECT lib / transport.
// ---------------------------------------------------------------------------

#include <cstdint>
#include <vector>

#include <gtest/gtest.h>

#include <impl/dgb/coin/dgb_digishield.hpp>

using namespace dgb::coin;

static constexpr int32_t PRIMARY = 2; // BLOCK_VERSION_DEFAULT
static constexpr int32_t SCRYPT   = PRIMARY | DGB_BLOCK_VERSION_SCRYPT;
static constexpr int32_t SHA256D  = PRIMARY | DGB_BLOCK_VERSION_SHA256D;
static constexpr int32_t SKEIN    = PRIMARY | DGB_BLOCK_VERSION_SKEIN;
static constexpr int32_t ODO      = PRIMARY | DGB_BLOCK_VERSION_ODO;

// Build a version_at() over a fixed nearest-first chain.
static std::function<int32_t(std::size_t)> chain(const std::vector<int32_t>& c)
{
    return [c](std::size_t k) { return c.at(k); };
}

TEST(DigishieldWalk, WorkCreditPredicateIsScryptOnly)
{
    EXPECT_TRUE (header_credits_work(SCRYPT));
    EXPECT_TRUE (header_credits_work(PRIMARY));        // bare primary == Scrypt
    EXPECT_FALSE(header_credits_work(SHA256D));
    EXPECT_FALSE(header_credits_work(SKEIN));
    EXPECT_FALSE(header_credits_work(ODO));
}

TEST(DigishieldWalk, AllScryptChainTakesContiguousWindow)
{
    std::vector<int32_t> c(10, SCRYPT);
    auto w = scrypt_window_ancestors(chain(c), c.size(), 4);
    ASSERT_EQ(w.size(), 4u);
    EXPECT_EQ(w, (std::vector<std::size_t>{0, 1, 2, 3}));
}

TEST(DigishieldWalk, SkipsInterleavedContinuityHeaders)
{
    // Mixed: S, sha, S, skein, S, odo, S  -> Scrypt at k = 0,2,4,6.
    std::vector<int32_t> c{SCRYPT, SHA256D, SCRYPT, SKEIN, SCRYPT, ODO, SCRYPT};
    auto w = scrypt_window_ancestors(chain(c), c.size(), 3);
    ASSERT_EQ(w.size(), 3u);
    EXPECT_EQ(w, (std::vector<std::size_t>{0, 2, 4}));  // continuity skipped
}

TEST(DigishieldWalk, LeadingContinuityRunIsSkipped)
{
    // Nearest headers are all non-Scrypt; first Scrypt sample is deep.
    std::vector<int32_t> c{SHA256D, SKEIN, ODO, SCRYPT, SCRYPT};
    auto w = scrypt_window_ancestors(chain(c), c.size(), 2);
    ASSERT_EQ(w.size(), 2u);
    EXPECT_EQ(w, (std::vector<std::size_t>{3, 4}));
}

TEST(DigishieldWalk, ExhaustedChainReturnsFewerThanWindow)
{
    // Only 2 Scrypt headers exist but the window wants 4 (early-chain region).
    std::vector<int32_t> c{SCRYPT, SHA256D, SCRYPT, SHA256D};
    auto w = scrypt_window_ancestors(chain(c), c.size(), 4);
    ASSERT_EQ(w.size(), 2u);
    EXPECT_EQ(w, (std::vector<std::size_t>{0, 2}));
}

TEST(DigishieldWalk, ZeroWindowIsEmpty)
{
    std::vector<int32_t> c(4, SCRYPT);
    EXPECT_TRUE(scrypt_window_ancestors(chain(c), c.size(), 0).empty());
}
