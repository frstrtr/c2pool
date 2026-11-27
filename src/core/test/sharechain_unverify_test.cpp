// SPDX-License-Identifier: AGPL-3.0-or-later
//
// core::SharechainLevelDBStore::mark_shares_unverified: the verified flag of
// the named shares is cleared in one batch; each share, its metadata and its
// cached pow_hash are kept (a coin whose share rules changed verifies its
// stored shares again instead of deleting them). Shares not named, unknown
// hashes and already-unverified shares are left alone.

#include <gtest/gtest.h>

#include <core/leveldb_store.hpp>
#include <core/uint256.hpp>

#include <filesystem>
#include <random>
#include <string>
#include <vector>

namespace {

struct TempDir {
    std::filesystem::path dir;
    TempDir()
    {
        std::mt19937_64 rng(std::random_device{}());
        dir = std::filesystem::temp_directory_path() / ("sharechain_unverify_" + std::to_string(rng()));
        std::filesystem::create_directories(dir);
    }
    ~TempDir()
    {
        std::error_code ec;
        std::filesystem::remove_all(dir, ec);
    }
};

uint256 h(int n)
{
    uint256 x;
    x.SetHex(std::to_string(9100 + n));
    return x;
}

} // namespace

TEST(SharechainStoreUnverify, ClearsTheFlagAndKeepsTheShare)
{
    TempDir t;
    core::SharechainLevelDBStore st(t.dir.string(), "kat");
    ASSERT_TRUE(st.open());
    uint256 pow;
    pow.SetHex("abcdef0123");
    for (int i = 1; i <= 3; ++i) {
        core::ShareMetadata m;
        m.prev_hash = i > 1 ? h(i - 1) : uint256();
        m.height = static_cast<uint64_t>(i);
        m.timestamp = 1790000000u + static_cast<uint64_t>(i);
        m.is_verified = (i != 3);
        m.pow_hash = pow;
        ASSERT_TRUE(st.store_share(h(i), std::vector<uint8_t>(16, static_cast<uint8_t>(i)), m));
    }
    uint256 unknown;
    unknown.SetHex("777");
    ASSERT_TRUE(st.mark_shares_unverified({h(1), h(3), unknown}));

    std::vector<core::SharechainLevelDBStore::IndexEntry> idx;
    ASSERT_TRUE(st.scan_share_index(idx));
    ASSERT_EQ(idx.size(), 3u);
    for (const auto& e : idx)
        EXPECT_EQ(e.is_verified, e.hash == h(2)) << e.hash.GetHex();

    std::vector<uint8_t> data;
    core::ShareMetadata m;
    ASSERT_TRUE(st.load_share(h(1), data, m));
    EXPECT_EQ(data, std::vector<uint8_t>(16, 1));
    EXPECT_FALSE(m.is_verified);
    EXPECT_EQ(m.pow_hash, pow) << "the cached pow_hash is kept";
    EXPECT_EQ(m.height, 1u);
    EXPECT_EQ(m.timestamp, 1790000001u);

    // An empty list changes nothing and is not a failure.
    EXPECT_TRUE(st.mark_shares_unverified({}));
    st.close();
    EXPECT_FALSE(st.mark_shares_unverified({h(2)})) << "a closed store";
}
