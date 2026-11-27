// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// The DGB sharechain store is verified again once on a share-rules change
// (rides dgb_work_source_test). Reviews 906a0e5e3 #5, dd1248abd REQUIRED 1-2
// and #7/#8: the shares are KEPT and their verified flags cleared; the marker
// is written only after a re-scan confirms no flag is left; on a failure no
// stored flag is trusted and the clear runs again on the next start.
// ---------------------------------------------------------------------------

#include <impl/dgb/store_rules_epoch.hpp>

#include <core/leveldb_store.hpp>
#include <core/uint256.hpp>

#include <gtest/gtest.h>

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <unistd.h>
#include <vector>

#ifndef DGB_MAIN_SRC
#error "DGB_MAIN_SRC must name src/c2pool/main_dgb.cpp"
#endif

namespace {

using Entry = core::SharechainLevelDBStore::IndexEntry;

struct FakeStore {
    std::vector<Entry> idx;
    bool scan_fails = false;
    bool mark_fails = false;
    bool mark_is_noop = false;   // reports success, clears nothing
    int marks = 0;
    bool scan_share_index(std::vector<Entry>& out) const
    {
        out.clear();
        if (scan_fails)
            return false;
        out = idx;
        return true;
    }
    bool mark_shares_unverified(const std::vector<uint256>& hs)
    {
        ++marks;
        if (mark_fails)
            return false;
        if (!mark_is_noop)
            for (auto& e : idx)
                if (std::find(hs.begin(), hs.end(), e.hash) != hs.end())
                    e.is_verified = false;
        return true;
    }
    size_t verified() const
    {
        return static_cast<size_t>(std::count_if(idx.begin(), idx.end(), [](const Entry& e) { return e.is_verified; }));
    }
};

FakeStore store_with(int n, int verified)
{
    FakeStore st;
    for (int i = 1; i <= n; ++i) {
        Entry e;
        e.hash = uint256(std::vector<unsigned char>(32, static_cast<unsigned char>(i)));
        e.height = static_cast<uint64_t>(i);
        e.is_verified = i <= verified;
        st.idx.push_back(e);
    }
    return st;
}

struct Dir {
    std::filesystem::path p;
    explicit Dir(const char* tag)
        : p(std::filesystem::temp_directory_path() / (std::string(tag) + std::to_string(::getpid())))
    {
        std::filesystem::remove_all(p);
    }
    ~Dir() { std::filesystem::remove_all(p); }
    std::filesystem::path marker() const { return p / "digibyte" / "dgb_share_rules_epoch"; }
};

std::string slurp(const std::filesystem::path& f)
{
    std::ifstream in(f);
    std::stringstream ss;
    ss << in.rdbuf();
    return ss.str();
}

} // namespace

TEST(DgbStoreRulesEpoch, OlderStoreKeepsItsSharesAndVerifiesThemAgain)
{
    Dir d("dgb_rules_epoch_a_");
    FakeStore st = store_with(5, 3);

    // A store with no epoch (an older build): every flag cleared, every share kept.
    EXPECT_TRUE(dgb::reverify_store_if_rules_changed(st, d.marker()));
    EXPECT_EQ(st.idx.size(), 5u) << "a share was dropped";
    EXPECT_EQ(st.verified(), 0u);
    EXPECT_EQ(dgb::read_rules_epoch(d.marker()), dgb::kDgbShareRulesEpoch);

    // Written under these rules: the flags are trusted and left alone.
    st.idx[0].is_verified = true;
    const int marks = st.marks;
    EXPECT_TRUE(dgb::reverify_store_if_rules_changed(st, d.marker()));
    EXPECT_EQ(st.marks, marks);
    EXPECT_EQ(st.verified(), 1u);

    // Another epoch: cleared again.
    std::ofstream(d.marker(), std::ios::trunc) << "dgb-older\n";
    EXPECT_TRUE(dgb::reverify_store_if_rules_changed(st, d.marker()));
    EXPECT_EQ(st.verified(), 0u);
    EXPECT_EQ(dgb::read_rules_epoch(d.marker()), dgb::kDgbShareRulesEpoch);

    // An empty store: nothing to clear, the marker is written.
    Dir e("dgb_rules_epoch_b_");
    FakeStore empty;
    EXPECT_TRUE(dgb::reverify_store_if_rules_changed(empty, e.marker()));
    EXPECT_EQ(empty.marks, 0);
    EXPECT_EQ(dgb::read_rules_epoch(e.marker()), dgb::kDgbShareRulesEpoch);
}

TEST(DgbStoreRulesEpoch, AFailedClearTrustsNoFlagAndWritesNoMarker)
{
    {
        Dir d("dgb_rules_epoch_c_");
        FakeStore st = store_with(4, 4);
        st.scan_fails = true;
        EXPECT_FALSE(dgb::reverify_store_if_rules_changed(st, d.marker()));
        EXPECT_FALSE(std::filesystem::exists(d.marker()));
    }
    {
        Dir d("dgb_rules_epoch_d_");
        FakeStore st = store_with(4, 4);
        st.mark_fails = true;
        EXPECT_FALSE(dgb::reverify_store_if_rules_changed(st, d.marker()));
        EXPECT_FALSE(std::filesystem::exists(d.marker()));
    }
    {
        // The write reports success, the re-scan still sees flags.
        Dir d("dgb_rules_epoch_e_");
        FakeStore st = store_with(4, 2);
        st.mark_is_noop = true;
        EXPECT_FALSE(dgb::reverify_store_if_rules_changed(st, d.marker()));
        EXPECT_FALSE(std::filesystem::exists(d.marker()));
        // The next start retries.
        st.mark_is_noop = false;
        EXPECT_TRUE(dgb::reverify_store_if_rules_changed(st, d.marker()));
        EXPECT_EQ(st.verified(), 0u);
    }
    {
        // An unwritable marker: the flags are cleared, so they can be trusted;
        // the clear runs again on the next start.
        Dir d("dgb_rules_epoch_f_");
        std::filesystem::create_directories(d.marker());   // a directory where the file goes
        FakeStore st = store_with(3, 3);
        EXPECT_TRUE(dgb::reverify_store_if_rules_changed(st, d.marker()));
        EXPECT_EQ(st.verified(), 0u);
        EXPECT_NE(dgb::read_rules_epoch(d.marker()), dgb::kDgbShareRulesEpoch);
    }
}

TEST(DgbStoreRulesEpoch, TheNodeRunsItBeforeTheLoadAndHonoursIt)
{
    const auto dgb_dir = std::filesystem::path(DGB_MAIN_SRC).parent_path().parent_path() / "impl" / "dgb";
    const std::string hpp = slurp(dgb_dir / "node.hpp");
    const std::string cpp = slurp(dgb_dir / "node.cpp");
    ASSERT_FALSE(hpp.empty());
    ASSERT_FALSE(cpp.empty());
    const auto call = hpp.find("m_trust_stored_verified = reverify_store_if_rules_changed(");
    ASSERT_NE(call, std::string::npos);
    EXPECT_NE(hpp.find("core::filesystem::config_path() / net_name / \"dgb_share_rules_epoch\"", call),
              std::string::npos);
    EXPECT_LT(call, hpp.find("load_persisted_shares();", call));
    EXPECT_EQ(hpp.find("wipe_store_if_rules_changed"), std::string::npos);
    EXPECT_NE(cpp.find("if (meta.is_verified && m_trust_stored_verified) {"), std::string::npos);
    // Review dd1248abd #7: stored V36 shares are not loaded while held.
    EXPECT_NE(cpp.find("if (ver >= 36 && !dgb::v36_shares_accepted()) {"), std::string::npos);
}
