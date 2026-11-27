// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// The DGB sharechain store is wiped once on a share-rules change (rides
// dgb_work_source_test). Review 906a0e5e3 #5.
// ---------------------------------------------------------------------------

#include <impl/dgb/store_rules_epoch.hpp>

#include <core/uint256.hpp>

#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>
#include <string>
#include <unistd.h>
#include <vector>

namespace {

struct FakeStore {
    std::vector<uint256> shares;
    std::vector<uint256> get_shares_by_height_range(uint64_t, uint64_t) const { return shares; }
    bool remove_shares_batch(const std::vector<uint256>& h)
    {
        for (const auto& x : h)
            std::erase(shares, x);
        return true;
    }
};

} // namespace

TEST(DgbStoreRulesEpoch, OlderStoreIsWipedOnceThenKept)
{
    const auto dir = std::filesystem::temp_directory_path() / ("dgb_rules_epoch_" + std::to_string(::getpid()));
    std::filesystem::remove_all(dir);
    const auto marker = dir / "digibyte" / "dgb_share_rules_epoch";
    FakeStore st;
    for (int i = 1; i <= 5; ++i)
        st.shares.push_back(uint256(std::vector<unsigned char>(32, static_cast<unsigned char>(i))));

    // A store with no epoch (an older build): emptied, the epoch written.
    EXPECT_EQ(dgb::wipe_store_if_rules_changed(st, marker), 5u);
    EXPECT_TRUE(st.shares.empty());
    std::ifstream in(marker);
    std::string e;
    std::getline(in, e);
    EXPECT_EQ(e, dgb::kDgbShareRulesEpoch);

    // Written under these rules: kept.
    st.shares.push_back(uint256(std::vector<unsigned char>(32, 0x42)));
    EXPECT_EQ(dgb::wipe_store_if_rules_changed(st, marker), 0u);
    EXPECT_EQ(st.shares.size(), 1u);

    // Another epoch: emptied again.
    std::ofstream(marker, std::ios::trunc) << "dgb-older\n";
    EXPECT_EQ(dgb::wipe_store_if_rules_changed(st, marker), 1u);
    EXPECT_TRUE(st.shares.empty());
    std::filesystem::remove_all(dir);
}
